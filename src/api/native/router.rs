//! Native REST API router — /api/v1/
//! Handles API key management, user management, and optional human login.
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde_json::json;
use std::sync::Arc;

use super::{auth, keys, passkey, totp, users};
use crate::auth::{manager::AuthManager, session::SessionService};
use crate::config::Config;

#[derive(Clone)]
pub struct NativeState {
    pub pool: sqlx::PgPool,
    pub sessions: Arc<SessionService>,
    pub auth_manager: Arc<AuthManager>,
    pub config: Arc<Config>,
    /// Crypto engine — used to seal/open the TOTP secret at rest.
    pub crypto: Arc<crate::core::CryptoEngine>,
    /// WebAuthn/passkey service (disabled unless RP id/origin configured).
    pub passkey: Arc<crate::auth::PasskeyService>,
}

pub fn native_router(state: NativeState) -> Router {
    // Admin-only routes: key & user management. Requires a valid bearer token
    // AND an admin-tier role. `require_auth` is the outer layer so it runs first
    // and injects Claims; `require_admin` then checks the role (fail closed).
    let admin = Router::new()
        .route("/keys", get(keys::list_keys))
        .route("/keys", post(keys::create_key))
        .route("/keys/:id", delete(keys::revoke_key))
        .route("/users", get(users::list_users))
        .route("/users/:id", delete(users::deactivate_user))
        .route("/users/:id/roles/:role", put(users::assign_role))
        .layer(middleware::from_fn(require_admin))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Authenticated routes available to any valid token (no admin role required).
    // Includes self-service 2FA management for the calling user.
    let authed = Router::new()
        .route("/auth/me", get(auth::me))
        .route("/auth/totp/status", get(totp::status))
        .route("/auth/totp/enroll", post(totp::enroll))
        .route("/auth/totp/verify", post(totp::verify))
        .route("/auth/totp", delete(totp::disable))
        .route(
            "/auth/passkey/register/start",
            post(passkey::register_start),
        )
        .route(
            "/auth/passkey/register/finish",
            post(passkey::register_finish),
        )
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Public routes — no auth needed
    let public = Router::new()
        .route("/auth/providers", get(auth::list_providers))
        .route("/auth/login", post(auth::login))
        .route("/auth/register", post(auth::register))
        .route("/auth/passkey/login/start", post(passkey::login_start))
        .route("/auth/passkey/login/finish", post(passkey::login_finish));

    Router::new()
        .nest("/api/v1", public.merge(authed).merge(admin))
        .with_state(state)
}

/// Middleware (runs after `require_auth`): require an admin-tier role.
/// Denies with 403 if the authenticated principal is not an org admin/owner.
async fn require_admin(req: Request, next: Next) -> Response {
    let is_admin = req
        .extensions()
        .get::<crate::auth::Claims>()
        .map(|c| crate::auth::rbac::RbacService::is_admin(&c.roles))
        .unwrap_or(false);
    if !is_admin {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "insufficient privileges: admin role required"})),
        )
            .into_response();
    }
    next.run(req).await
}

/// Middleware: accept `Authorization: Bearer <token>` where token is either:
///   - An API key (sk_live_...) — validated against DB
///   - A JWT session token — validated with JWT secret
///
/// Injects `crate::auth::Claims` into request extensions for downstream handlers.
async fn require_auth(State(s): State<NativeState>, mut req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string)
        // Browser clients authenticate via the httpOnly session cookie.
        .or_else(|| {
            crate::api::vault::auth::cookie_value(
                req.headers(),
                crate::api::vault::auth::SESSION_COOKIE,
            )
        });

    let Some(token) = token else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "missing credentials"})),
        )
            .into_response();
    };

    // API key path
    if token.starts_with("sk_live_") {
        match keys::resolve_api_key(&s.pool, &token).await {
            Ok(resolved) => {
                let claims = crate::auth::Claims {
                    sub: resolved.key_id.to_string(),
                    org: resolved.org_id.to_string(),
                    email: String::new(),
                    roles: resolved.role.into_iter().collect(),
                    exp: usize::MAX,
                    iat: 0,
                    two_fa_verified: true,
                    ns: String::new(),
                };
                req.extensions_mut().insert(claims);
                return next.run(req).await;
            }
            Err(_) => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "invalid API key"})),
                )
                    .into_response()
            }
        }
    }

    // JWT path
    match s.sessions.validate(&token) {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid token"})),
        )
            .into_response(),
    }
}
