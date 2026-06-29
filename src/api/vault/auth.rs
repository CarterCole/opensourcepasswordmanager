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
            });
            return next.run(req).await;
        }
    }

    crate::api::vault::error::VaultError::resp(StatusCode::FORBIDDEN, "invalid token")
}
