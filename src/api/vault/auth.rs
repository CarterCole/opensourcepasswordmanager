//! Vault token authentication middleware.
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use std::sync::Arc;
use uuid::Uuid;
use crate::db::ApiKey;

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

pub fn extract_vault_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-Vault-Token")
        .or_else(|| headers.get("Authorization"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").to_string())
}

/// Middleware: require a valid X-Vault-Token or Bearer token
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

    // Dev root token — always accepted
    if let Some(ref root) = state.dev_root_token {
        if &token == root {
            req.extensions_mut().insert(VaultClaims {
                token,
                org_id: state.default_org_id,
                user_id: None,
                api_key: None,
                token_ns: String::new(),
                namespace: String::new(),
            });
            return next.run(req).await;
        }
    }

    // JWT child token (issued by /auth/token/create)
    if let Ok(jwt) = state.sessions.validate(&token) {
        if let Ok(org_id) = Uuid::parse_str(&jwt.org) {
            req.extensions_mut().insert(VaultClaims {
                token,
                org_id,
                user_id: Uuid::parse_str(&jwt.sub).ok(),
                api_key: None,
                token_ns: jwt.ns.clone(),
                namespace: String::new(),
            });
            return next.run(req).await;
        }
    }

    // API key (Postgres only)
    if let Some(ref pool) = state.pg_pool {
        if let Ok(resolved) = crate::api::native::keys::resolve_api_key(pool, &token).await {
            req.extensions_mut().insert(VaultClaims {
                token,
                org_id: resolved.org_id,
                user_id: Some(resolved.key_id),
                api_key: None,
                token_ns: String::new(),
                namespace: String::new(),
            });
            return next.run(req).await;
        }
    }

    crate::api::vault::error::VaultError::resp(StatusCode::FORBIDDEN, "invalid token")
}

// ── Namespaces ───────────────────────────────────────────────────────────────

/// Names that cannot be namespaces because they are Vault system path prefixes.
pub const RESERVED_NS_NAMES: &[&str] = &["sys", "auth", "identity", "cubbyhole"];

/// Normalise a namespace path: trim slashes, collapse empty segments.
pub fn normalize_ns(raw: &str) -> String {
    raw.split('/').filter(|s| !s.is_empty()).collect::<Vec<_>>().join("/")
}

pub fn join_ns(base: &str, child: &str) -> String {
    if base.is_empty() { child.to_string() } else { format!("{base}/{child}") }
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
        return crate::api::vault::error::VaultError::resp(StatusCode::NOT_FOUND, "namespace not found");
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
        return crate::api::vault::error::VaultError::resp(StatusCode::FORBIDDEN, "permission denied");
    }
    claims.namespace = ns;
    req.extensions_mut().insert(claims);
    next.run(req).await
}
