//! Vault token authentication middleware.
use crate::db::ApiKey;
use axum::{
    extract::{Request, State},
    http::{header::SET_COOKIE, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Claims extracted from a valid Vault token
#[derive(Clone, Debug)]
pub struct VaultClaims {
    pub token: String,
    pub org_id: Uuid,
    pub user_id: Option<Uuid>,
    pub api_key: Option<ApiKey>,
    /// Namespace the token was issued in ("" = root); limits where it may be used.
    pub token_ns: String,
    /// Namespace this request resolved to ("" = root). Set by `resolve_namespace`.
    pub namespace: String,
    /// Policies this token carries, used for per-path capability checks.
    pub policies: Vec<String>,
}

/// Shared state available to vault handlers
#[derive(Clone)]
pub struct VaultState {
    pub store: Arc<crate::core::SecretStore>,
    pub db: Arc<dyn crate::db::SecretBackend>,
    /// Root token for dev mode (if set, bypasses DB lookup)
    pub dev_root_token: Option<String>,
    pub default_org_id: Uuid,
    pub default_env_id: Uuid,
    /// Postgres pool for API key lookups (None in SQLite/dev mode)
    pub pg_pool: Option<sqlx::PgPool>,
    /// JWT session service for issuing/validating child tokens
    pub sessions: Arc<crate::auth::SessionService>,
}

/// Name of the httpOnly session cookie set by the web UI login.
pub const SESSION_COOKIE: &str = "secretd_token";

pub fn extract_vault_token(headers: &HeaderMap) -> Option<String> {
    // Header-based clients (SDKs, CLI) first.
    if let Some(v) = headers
        .get("X-Vault-Token")
        .or_else(|| headers.get("Authorization"))
        .and_then(|v| v.to_str().ok())
    {
        let t = v.trim_start_matches("Bearer ").trim();
        if !t.is_empty() {
            return Some(t.to_string());
        }
    }
    // Browser clients: the httpOnly session cookie.
    cookie_value(headers, SESSION_COOKIE)
}

/// Read a single cookie value out of the `Cookie` request header.
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            if k == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Validate a raw token and, if accepted, return the claims it grants.
/// Shared by the auth middleware and the cookie-login endpoint.
pub async fn authenticate_token(state: &VaultState, token: &str) -> Option<VaultClaims> {
    if token.is_empty() {
        return None;
    }
    // Dev root token — full access.
    if let Some(ref root) = state.dev_root_token {
        if token == root {
            return Some(VaultClaims {
                token: token.to_string(),
                org_id: state.default_org_id,
                user_id: None,
                api_key: None,
                token_ns: String::new(),
                namespace: String::new(),
                policies: vec!["root".to_string()],
            });
        }
    }
    // JWT child token (issued by /auth/token/create or human login) — the token's
    // roles/policies claim governs what it can do.
    if let Ok(jwt) = state.sessions.validate(token) {
        if let Ok(org_id) = Uuid::parse_str(&jwt.org) {
            let policies = if jwt.roles.is_empty() {
                vec!["default".to_string()]
            } else {
                jwt.roles.clone()
            };
            return Some(VaultClaims {
                token: token.to_string(),
                org_id,
                user_id: Uuid::parse_str(&jwt.sub).ok(),
                api_key: None,
                token_ns: jwt.ns.clone(),
                namespace: String::new(),
                policies,
            });
        }
    }
    // API key (Postgres only) — the key's role becomes its policy.
    if let Some(ref pool) = state.pg_pool {
        if let Ok(resolved) = crate::api::native::keys::resolve_api_key(pool, token).await {
            let policies = vec![resolved
                .role
                .clone()
                .unwrap_or_else(|| "default".to_string())];
            return Some(VaultClaims {
                token: token.to_string(),
                org_id: resolved.org_id,
                user_id: Some(resolved.key_id),
                api_key: None,
                token_ns: String::new(),
                namespace: String::new(),
                policies,
            });
        }
    }
    None
}

/// Middleware: require a valid token (header or session cookie).
pub async fn require_vault_token(
    State(state): State<VaultState>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = match extract_vault_token(req.headers()) {
        Some(t) if !t.is_empty() => t,
        _ => {
            return crate::api::vault::error::VaultError::resp(
                StatusCode::FORBIDDEN,
                "missing client token",
            )
        }
    };

    match authenticate_token(&state, &token).await {
        Some(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        None => crate::api::vault::error::VaultError::resp(StatusCode::FORBIDDEN, "invalid token"),
    }
}

// ── Cookie session (web UI) ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CookieLoginBody {
    pub token: String,
}

/// True when the original request reached us over HTTPS (directly or via a
/// TLS-terminating proxy that sets `X-Forwarded-Proto`).
fn request_is_https(headers: &HeaderMap) -> bool {
    headers
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

fn session_cookie(token: &str, max_age: u32, secure: bool) -> Option<HeaderValue> {
    // HttpOnly: unreadable by JS (defeats XSS token theft).
    // SameSite=Strict: never sent on cross-site requests (CSRF defence).
    let mut c =
        format!("{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}");
    if secure {
        c.push_str("; Secure");
    }
    HeaderValue::from_str(&c).ok()
}

/// POST /v1/auth/cookie/login — exchange a token for an httpOnly session cookie.
/// The browser then authenticates by cookie, so the token never touches JS
/// storage. The token is validated here before any cookie is set.
pub async fn cookie_login(
    State(state): State<VaultState>,
    headers: HeaderMap,
    Json(body): Json<CookieLoginBody>,
) -> Response {
    let token = body.token.trim();
    if authenticate_token(&state, token).await.is_none() {
        return crate::api::vault::error::VaultError::resp(
            StatusCode::UNAUTHORIZED,
            "invalid token",
        );
    }
    let Some(cookie) = session_cookie(token, 604800, request_is_https(&headers)) else {
        return crate::api::vault::error::VaultError::resp(
            StatusCode::BAD_REQUEST,
            "token not storable in a cookie",
        );
    };
    let mut resp = Json(json!({ "ok": true })).into_response();
    resp.headers_mut().insert(SET_COOKIE, cookie);
    resp
}

/// POST /v1/auth/cookie/logout — clear the session cookie.
pub async fn cookie_logout(headers: HeaderMap) -> Response {
    let mut resp = Json(json!({ "ok": true })).into_response();
    if let Some(cookie) = session_cookie("", 0, request_is_https(&headers)) {
        resp.headers_mut().insert(SET_COOKIE, cookie);
    }
    resp
}

// ── Policy enforcement ────────────────────────────────────────────────────────

/// Middleware (runs after auth + namespace resolution): enforce the token's
/// policies for the KV operation implied by the method and path. `sys/*` and
/// `auth/*` routes are not path-gated (authentication already being required),
/// and `token/create` separately restricts delegated policies to a subset.
pub async fn enforce_policy(req: Request, next: Next) -> Response {
    use crate::auth::policy::{allows, Capability};

    let Some(claims) = req.extensions().get::<VaultClaims>().cloned() else {
        return crate::api::vault::error::VaultError::resp(StatusCode::FORBIDDEN, "invalid token");
    };

    let method = req.method().as_str().to_string();
    let path = req.uri().path().to_string();
    let is_list = req
        .uri()
        .query()
        .map(|q| q.contains("list=true"))
        .unwrap_or(false);
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    if segs.len() >= 2 {
        let mount = segs[0];
        let op = segs[1];
        let rest = segs.get(2..).map(|s| s.join("/")).unwrap_or_default();
        let target = format!("{mount}/{rest}");

        let cap = match (op, method.as_str()) {
            ("data", "GET") => Some(Capability::Read),
            ("data", "POST") | ("data", "PUT") => Some(Capability::Update),
            ("data", "DELETE") => Some(Capability::Delete),
            ("delete", "POST") => Some(Capability::Delete),
            ("undelete", "POST") => Some(Capability::Update),
            ("destroy", "PUT") | ("destroy", "POST") => Some(Capability::Destroy),
            ("metadata", "GET") => {
                if is_list || rest.is_empty() {
                    Some(Capability::List)
                } else {
                    Some(Capability::Read)
                }
            }
            ("metadata", "POST") | ("metadata", "PUT") => Some(Capability::Read),
            ("metadata", "DELETE") => Some(Capability::Delete),
            _ => None, // sys/*, auth/*, unknown → no path gate
        };

        if let Some(cap) = cap {
            if !allows(&claims.policies, &target, cap) {
                return crate::api::vault::error::VaultError::resp(
                    StatusCode::FORBIDDEN,
                    "permission denied: token policy does not allow this operation",
                );
            }
        }
    }

    next.run(req).await
}

// ── Namespaces ───────────────────────────────────────────────────────────────

/// Names that cannot be namespaces because they are Vault system path prefixes.
pub const RESERVED_NS_NAMES: &[&str] = &["sys", "auth", "identity", "cubbyhole"];

/// Normalise a namespace path: trim slashes, collapse empty segments.
pub fn normalize_ns(raw: &str) -> String {
    raw.split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn join_ns(base: &str, child: &str) -> String {
    if base.is_empty() {
        child.to_string()
    } else {
        format!("{base}/{child}")
    }
}

/// True if `token_ns` is `ns` itself or one of its ancestors.
pub fn ns_allows(token_ns: &str, ns: &str) -> bool {
    token_ns.is_empty() || ns == token_ns || ns.starts_with(&format!("{token_ns}/"))
}

/// Middleware (runs after auth): resolve the request's namespace from the
/// `X-Vault-Namespace` header plus any leading namespace path segments in the URL
/// (`/team-a/secret/data/x`), rewrite the URI to the namespace-relative path, and
/// reject tokens that don't cover the namespace.
pub async fn resolve_namespace(
    State(state): State<VaultState>,
    mut req: Request,
    next: Next,
) -> Response {
    let Some(mut claims) = req.extensions().get::<VaultClaims>().cloned() else {
        return crate::api::vault::error::VaultError::resp(StatusCode::FORBIDDEN, "invalid token");
    };

    let mut ns = req
        .headers()
        .get("X-Vault-Namespace")
        .and_then(|v| v.to_str().ok())
        .map(normalize_ns)
        .unwrap_or_default();
    if !ns.is_empty() && state.db.get_namespace(claims.org_id, &ns).await.is_err() {
        return crate::api::vault::error::VaultError::resp(
            StatusCode::NOT_FOUND,
            "namespace not found",
        );
    }

    // Descend through leading path segments that name existing child namespaces,
    // always leaving at least one segment (the mount / sys path) behind.
    let path = req.uri().path().to_string();
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    let mut consumed = 0;
    while consumed + 1 < segs.len() && !RESERVED_NS_NAMES.contains(&segs[consumed]) {
        let cand = join_ns(&ns, segs[consumed]);
        if state.db.get_namespace(claims.org_id, &cand).await.is_err() {
            break;
        }
        ns = cand;
        consumed += 1;
    }

    if consumed > 0 {
        let mut new_path = format!("/{}", segs[consumed..].join("/"));
        if path.ends_with('/') {
            new_path.push('/');
        }
        if let Some(q) = req.uri().query() {
            new_path.push('?');
            new_path.push_str(q);
        }
        let mut parts = req.uri().clone().into_parts();
        match new_path.parse() {
            Ok(pq) => parts.path_and_query = Some(pq),
            Err(_) => return crate::api::vault::error::VaultError::bad_request("invalid path"),
        }
        match axum::http::Uri::from_parts(parts) {
            Ok(u) => *req.uri_mut() = u,
            Err(_) => return crate::api::vault::error::VaultError::bad_request("invalid path"),
        }
    }

    if !ns_allows(&claims.token_ns, &ns) {
        return crate::api::vault::error::VaultError::resp(
            StatusCode::FORBIDDEN,
            "permission denied",
        );
    }
    claims.namespace = ns;
    req.extensions_mut().insert(claims);
    next.run(req).await
}
