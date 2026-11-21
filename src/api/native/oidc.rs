//! /api/v1/auth/oidc/{id}/… — "Sign in with Kith" (and other OIDC providers).
//!
//! `start` redirects the browser to the provider; `callback` is where the provider
//! sends it back. The browser ends up on the web UI's login page, either signed in
//! (`?oidc=ok`, session cookie set) or with `?oidc_error=<code>`.
//!
//! The provider has already authenticated the user (for Kith: a passkey, with an
//! `acr` saying how strong), so there is no second TOTP prompt here. An account
//! whose TOTP is enabled can still demand it on the password route.
use axum::{
    extract::{Path, Query, State},
    http::{
        header::{CACHE_CONTROL, LOCATION, SET_COOKIE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sqlx::Row;
use uuid::Uuid;

use super::router::NativeState;
use crate::api::vault::auth::{cookie_value, request_is_https, session_cookie};
use crate::auth::oidc::{random_token, OidcIdentity, OidcProvider};

/// Binds a login to the browser that started it (defeats login CSRF: an attacker
/// cannot make a victim's browser finish the attacker's flow).
const FLOW_COOKIE: &str = "secretd_oidc";
const FLOW_COOKIE_PATH: &str = "/api/v1/auth/oidc";

fn flow_cookie(state: &str, max_age: u32, secure: bool) -> HeaderValue {
    // Lax, not Strict: the provider redirects back with a cross-site navigation.
    let mut c = format!(
        "{FLOW_COOKIE}={state}; HttpOnly; SameSite=Lax; Path={FLOW_COOKIE_PATH}; Max-Age={max_age}"
    );
    if secure {
        c.push_str("; Secure");
    }
    HeaderValue::from_str(&c).expect("state is base64url")
}

fn redirect(to: &str) -> Response {
    let mut r = StatusCode::FOUND.into_response();
    r.headers_mut()
        .insert(LOCATION, HeaderValue::from_str(to).expect("static path"));
    r.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r
}

fn fail(code: &str, secure: bool) -> Response {
    let mut r = redirect(&format!("/ui/login?oidc_error={code}"));
    r.headers_mut()
        .append(SET_COOKIE, flow_cookie("", 0, secure));
    r
}

// ── GET /api/v1/auth/oidc/:id/start ───────────────────────────────────────────

pub async fn start(State(s): State<NativeState>, Path(id): Path<String>) -> Response {
    let Some(p) = s.oidc.get(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let (state, nonce, verifier) = (random_token(), random_token(), random_token());
    let url = match p.authorization_url(&state, &nonce, &verifier).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("oidc[{id}]: cannot start login: {e:#}");
            return fail("unavailable", p.secure());
        }
    };
    s.oidc.flows.insert(state.clone(), &id, verifier, nonce);
    let mut r = redirect(&url);
    r.headers_mut()
        .append(SET_COOKIE, flow_cookie(&state, 600, p.secure()));
    r
}

// ── GET /api/v1/auth/oidc/:id/callback ────────────────────────────────────────

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub async fn callback(
    State(s): State<NativeState>,
    Path(id): Path<String>,
    Query(q): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Response {
    let Some(p) = s.oidc.get(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let secure = p.secure();

    // `state` must be one we issued, for this provider, and the same browser must
    // have started it. Taking it removes it: a callback URL cannot be replayed.
    let Some(state) = q.state.as_deref() else {
        return fail("failed", secure);
    };
    let flow = s.oidc.flows.take(state);
    let bound = cookie_value(&headers, FLOW_COOKIE).is_some_and(|c| c == state);
    let Some(flow) = flow.filter(|f| bound && f.provider == id) else {
        return fail("expired", secure);
    };
    if let Some(e) = &q.error {
        // access_denied, login_required, ...; never echo the provider's text.
        tracing::info!("oidc[{id}]: provider returned error={e}");
        return fail("denied", secure);
    }
    let Some(code) = q.code.as_deref() else {
        return fail("failed", secure);
    };

    let identity = match p.complete(code, &flow.verifier, &flow.nonce).await {
        Ok(i) => i,
        Err(e) => {
            tracing::warn!("oidc[{id}]: login rejected: {e:#}");
            return fail("failed", secure);
        }
    };

    let (user_id, org_id, email) = match resolve_user(&s.pool, &p, &identity).await {
        Ok(u) => u,
        Err(Resolve::Refused(code)) => {
            tracing::info!("oidc[{id}]: {} refused: {code}", identity.subject);
            return fail(code, secure);
        }
        Err(Resolve::Db(e)) => {
            tracing::error!("oidc[{id}]: database error: {e}");
            return fail("failed", secure);
        }
    };

    let roles = super::auth::fetch_roles(&s.pool, user_id, org_id)
        .await
        .unwrap_or_default();
    let token = match s
        .sessions
        .issue(user_id, org_id, &email, roles, true, 86400 * 7)
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("oidc[{id}]: cannot issue session: {e}");
            return fail("failed", secure);
        }
    };
    let Some(cookie) = session_cookie(&token, 604800, secure || request_is_https(&headers)) else {
        return fail("failed", secure);
    };
    let mut r = redirect("/ui/login?oidc=ok");
    r.headers_mut().append(SET_COOKIE, cookie);
    r.headers_mut()
        .append(SET_COOKIE, flow_cookie("", 0, secure));
    r
}

// ── identity → local user ─────────────────────────────────────────────────────

enum Resolve {
    /// The login is fine but not allowed in; the code goes to the login page.
    Refused(&'static str),
    Db(sqlx::Error),
}

impl From<sqlx::Error> for Resolve {
    fn from(e: sqlx::Error) -> Self {
        Resolve::Db(e)
    }
}

/// Find (or, if allowed, create) the local user for a verified identity.
///
/// 1. `(issuer, sub)` already linked: that user. A deactivated user stays out.
/// 2. Otherwise a **verified** email that matches an active user links the
///    identity to them. From then on the provider's `sub` is what counts, so a
///    later email change at the provider cannot move the login to someone else.
/// 3. Otherwise, with `auto_provision`, a verified email creates a user with no
///    roles. Without it, the login is refused: users are invited by an admin.
async fn resolve_user(
    pool: &sqlx::PgPool,
    p: &OidcProvider,
    id: &OidcIdentity,
) -> Result<(Uuid, Uuid, String), Resolve> {
    let linked = sqlx::query(
        "SELECT u.id, u.org_id, u.email, u.is_active
         FROM external_identities e JOIN users u ON u.id = e.user_id
         WHERE e.issuer = $1 AND e.subject = $2",
    )
    .bind(&id.issuer)
    .bind(&id.subject)
    .fetch_optional(pool)
    .await?;
    if let Some(r) = linked {
        if !r.get::<bool, _>("is_active") {
            return Err(Resolve::Refused("denied"));
        }
        return finish(
            pool,
            r.get("id"),
            r.get("org_id"),
            r.get("email"),
            id,
            false,
        )
        .await;
    }

    let Some(email) = id.email.as_deref() else {
        return Err(Resolve::Refused("no_account"));
    };
    if !id.email_verified {
        return Err(Resolve::Refused("unverified_email"));
    }

    let existing =
        sqlx::query("SELECT id, org_id, email, is_active FROM users WHERE lower(email) = $1")
            .bind(email)
            .fetch_optional(pool)
            .await?;
    if let Some(r) = existing {
        if !r.get::<bool, _>("is_active") {
            return Err(Resolve::Refused("denied"));
        }
        return finish(pool, r.get("id"), r.get("org_id"), r.get("email"), id, true).await;
    }

    if !p.config().auto_provision {
        return Err(Resolve::Refused("no_account"));
    }
    let org_id: Uuid =
        sqlx::query_scalar("SELECT id FROM organizations ORDER BY created_at LIMIT 1")
            .fetch_one(pool)
            .await?;
    let row = sqlx::query(
        "INSERT INTO users (org_id, email, display_name) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(org_id)
    .bind(email)
    .bind(&id.name)
    .fetch_one(pool)
    .await?;
    finish(pool, row.get("id"), org_id, email.to_string(), id, true).await
}

/// Record the link (when new) and the login time.
async fn finish(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    org_id: Uuid,
    email: String,
    id: &OidcIdentity,
    link: bool,
) -> Result<(Uuid, Uuid, String), Resolve> {
    if link {
        // A concurrent first login for the same identity is harmless.
        sqlx::query(
            "INSERT INTO external_identities (user_id, issuer, subject) VALUES ($1, $2, $3)
             ON CONFLICT (issuer, subject) DO NOTHING",
        )
        .bind(user_id)
        .bind(&id.issuer)
        .bind(&id.subject)
        .execute(pool)
        .await?;
    }
    sqlx::query(
        "UPDATE external_identities SET last_login_at = NOW() WHERE issuer = $1 AND subject = $2",
    )
    .bind(&id.issuer)
    .bind(&id.subject)
    .execute(pool)
    .await?;
    sqlx::query("UPDATE users SET last_login_at = NOW() WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok((user_id, org_id, email))
}
