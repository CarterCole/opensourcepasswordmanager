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

use crate::auth::{manager::AuthManager, session::SessionService};
use crate::config::Config;
use super::{auth, keys, users};

#[derive(Clone)]
pub struct NativeState {
    pub pool: sqlx::PgPool,
    pub sessions: Arc<SessionService>,
    pub auth_manager: Arc<AuthManager>,
    pub config: Arc<Config>,
}

pub fn native_router(state: NativeState) -> Router {
    // Routes that require a valid bearer token (API key or JWT)
    let protected = Router::new()
        .route("/auth/me",              get(auth::me))
        .route("/keys",                 get(keys::list_keys))
        .route("/keys",                 post(keys::create_key))
        .route("/keys/:id",             delete(keys::revoke_key))
        .route("/users",                get(users::list_users))
        .route("/users/:id",            delete(users::deactivate_user))
        .route("/users/:id/roles/:role", put(users::assign_role))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    // Public routes — no auth needed
    let public = Router::new()
        .route("/auth/providers", get(auth::list_providers))
        .route("/auth/login",     post(auth::login))
        .route("/auth/register",  post(auth::register));

    Router::new()
        .nest("/api/v1", public.merge(protected))
        .with_state(state)
}

/// Middleware: accept `Authorization: Bearer <token>` where token is either:
///   - An API key (sk_live_...) — validated against DB
///   - A JWT session token — validated with JWT secret
///
/// Injects `crate::auth::Claims` into request extensions for downstream handlers.
async fn require_auth(
    State(s): State<NativeState>,
    mut req: Request,
    next: Next,
) -> Response {
    let bearer = req.headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_string);

    let Some(token) = bearer else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "missing Authorization header"}))).into_response();
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
                };
                req.extensions_mut().insert(claims);
                return next.run(req).await;
            }
            Err(_) => return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid API key"}))).into_response(),
        }
    }

    // JWT path
    match s.sessions.validate(&token) {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            next.run(req).await
        }
        Err(_) => (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid token"}))).into_response(),
    }
}
