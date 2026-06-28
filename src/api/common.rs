//! Shared AppState used by all API compatibility layers.
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<crate::core::SecretStore>,
    pub db: Arc<dyn crate::db::SecretBackend>,
    /// Root token for dev mode — bypasses real auth
    pub dev_root_token: Option<String>,
    pub default_org_id: uuid::Uuid,
    pub default_env_id: uuid::Uuid,
}
