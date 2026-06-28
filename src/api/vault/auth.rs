//! Vault token authentication middleware.
//! Extracts X-Vault-Token header and validates against the DB.
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use crate::db::ApiKey;

/// Claims extracted from a valid Vault token
#[derive(Clone, Debug)]
pub struct VaultClaims {
    pub token: String,
    pub org_id: uuid::Uuid,
    pub user_id: Option<uuid::Uuid>,
    pub api_key: Option<ApiKey>,
}

/// Shared state available to vault handlers
#[derive(Clone)]
pub struct VaultState {
    pub store: std::sync::Arc<crate::core::SecretStore>,
    pub db: std::sync::Arc<dyn crate::db::SecretBackend>,
    /// Root token for dev mode (if set, bypasses DB lookup)
    pub dev_root_token: Option<String>,
    /// Default org to use when single-tenant
    pub default_org_id: uuid::Uuid,
    /// Default environment id for the default mount
    pub default_env_id: uuid::Uuid,
}

pub fn extract_vault_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-Vault-Token")
        .or_else(|| headers.get("Authorization"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").to_string())
}

/// Middleware: require a valid X-Vault-Token
pub async fn require_vault_token(
    State(state): State<VaultState>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = match extract_vault_token(req.headers()) {
        Some(t) => t,
        None => {
            return crate::api::vault::error::VaultError::resp(
                StatusCode::FORBIDDEN,
                "missing client token",
            )
        }
    };

    // Dev mode: accept root token without DB lookup
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

    // TODO: look up token in api_keys table (Phase 2)
    crate::api::vault::error::VaultError::resp(StatusCode::FORBIDDEN, "invalid token")
}
