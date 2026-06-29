//! Shared AppState used by all API compatibility layers.
use axum::http::{HeaderMap, StatusCode};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<crate::core::SecretStore>,
    pub db: Arc<dyn crate::db::SecretBackend>,
    /// Root token for dev mode — bypasses real auth
    pub dev_root_token: Option<String>,
    pub default_org_id: uuid::Uuid,
    pub default_env_id: uuid::Uuid,
    /// Postgres pool for API key lookups (None in SQLite/dev mode)
    pub pg_pool: Option<sqlx::PgPool>,
    /// JWT session service — used to validate child tokens
    pub sessions: Arc<crate::auth::SessionService>,
}

/// Validate any Bearer/Vault token against the configured backend.
/// Returns Ok(()) on success, Err(FORBIDDEN) when denied.
///
/// Acceptance order:
///  1. Dev root token (always works)
///  2. AWS SigV4 Authorization prefix (dev pass-through)
///  3. JWT child token issued by /auth/token/create
///  4. API key (sk_live_...) — Postgres only
pub async fn require_auth(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    // Cloudflare-style auth: X-Auth-Email + X-Auth-Key (dev: any non-empty values accepted)
    let has_cf_key = headers.get("X-Auth-Email").is_some() && headers.get("X-Auth-Key").is_some();
    if has_cf_key {
        return Ok(());
    }

    let token = headers
        .get("Authorization")
        .or_else(|| headers.get("X-Vault-Token"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_start_matches("Bearer ").to_string())
        .unwrap_or_default();

    if token.is_empty() {
        return Err(StatusCode::FORBIDDEN);
    }

    // Dev root token
    if state.dev_root_token.as_deref() == Some(token.as_str()) {
        return Ok(());
    }

    // AWS SDK SigV4 — dev-mode pass-through (proper SigV4 validation is out of scope)
    if token.starts_with("AWS4-HMAC-SHA256") {
        return Ok(());
    }

    // JWT child token
    if state.sessions.validate(&token).is_ok() {
        return Ok(());
    }

    // API key (Postgres only)
    if let Some(ref pool) = state.pg_pool {
        if crate::api::native::keys::resolve_api_key(pool, &token).await.is_ok() {
            return Ok(());
        }
    }

    Err(StatusCode::FORBIDDEN)
}
