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

/// Validate a request against the configured backend. Returns Ok(()) only when
/// the caller presents a credential we can actually verify; Err(FORBIDDEN)
/// otherwise. Fails closed — there are no "header is present" shortcuts.
///
/// A candidate credential is collected from any of:
///  - `Authorization: Bearer <token>` / `X-Vault-Token` (JWT or `sk_live_` key)
///  - `X-Auth-Key` (Cloudflare-style clients send the API key here)
///  - the `Credential=<access-key-id>/...` field of an AWS SigV4 `Authorization`
///    header — since the SigV4 signature itself cannot be verified without the
///    shared secret, the access-key-id must itself be a valid API key / dev token
///
/// Each candidate is checked against: the dev root token, a valid JWT session,
/// or a valid API key (Postgres). If none verifies, access is denied.
pub async fn require_auth(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let mut candidates: Vec<String> = Vec::new();

    if let Some(v) = headers.get("Authorization").and_then(|v| v.to_str().ok()) {
        if let Some(akid) = sigv4_access_key_id(v) {
            // AWS SigV4: the signature can't be checked here, so the access-key-id
            // must itself be a credential we recognise.
            candidates.push(akid);
        } else {
            candidates.push(v.trim_start_matches("Bearer ").trim().to_string());
        }
    }
    if let Some(v) = headers.get("X-Vault-Token").and_then(|v| v.to_str().ok()) {
        candidates.push(v.trim_start_matches("Bearer ").trim().to_string());
    }
    if let Some(v) = headers.get("X-Auth-Key").and_then(|v| v.to_str().ok()) {
        candidates.push(v.trim().to_string());
    }
    // Browser clients authenticate via the httpOnly session cookie.
    if let Some(c) = crate::api::vault::auth::cookie_value(headers, crate::api::vault::auth::SESSION_COOKIE) {
        candidates.push(c);
    }

    candidates.retain(|c| !c.is_empty());
    if candidates.is_empty() {
        return Err(StatusCode::FORBIDDEN);
    }

    // The cloud-compat shims all operate on the default organization's default
    // environment, so a credential is only accepted when it belongs to that org.
    // This stops a token issued for another org from reaching these secrets.
    for token in &candidates {
        // Dev root token (only set when explicitly configured) — the default-org root.
        if state.dev_root_token.as_deref() == Some(token.as_str()) {
            return Ok(());
        }
        // JWT session token — must be scoped to the default org.
        if let Ok(claims) = state.sessions.validate(token) {
            if uuid::Uuid::parse_str(&claims.org) == Ok(state.default_org_id) {
                return Ok(());
            }
            continue;
        }
        // API key (Postgres only) — must belong to the default org.
        if let Some(ref pool) = state.pg_pool {
            if let Ok(resolved) = crate::api::native::keys::resolve_api_key(pool, token).await {
                if resolved.org_id == state.default_org_id {
                    return Ok(());
                }
            }
        }
    }

    Err(StatusCode::FORBIDDEN)
}

/// Extract the access-key-id from an AWS SigV4 `Authorization` header value,
/// i.e. the `<id>` in `AWS4-HMAC-SHA256 Credential=<id>/<date>/<region>/...`.
/// Returns None if this is not a SigV4 header.
fn sigv4_access_key_id(auth: &str) -> Option<String> {
    if !auth.starts_with("AWS4-HMAC-SHA256") {
        return None;
    }
    let cred = auth.split("Credential=").nth(1)?;
    let akid = cred.split('/').next()?.trim();
    if akid.is_empty() {
        None
    } else {
        Some(akid.to_string())
    }
}
