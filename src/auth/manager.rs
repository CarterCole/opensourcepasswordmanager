//! AuthManager — registry of enabled human login providers.
//!
//! Populated at startup from config. Providers are opt-in:
//!   - No providers registered → only API key (bearer token) auth works.
//!   - Email provider registered → email+password login enabled.
//!   - LDAP/OIDC registered → those login buttons appear in the UI.
//!
//! The cloud tier injects its own providers (SAML, org-scoped OIDC)
//! via register_boxed before calling serve().
use super::provider::{AuthProvider, AuthUser, Credentials, ProviderInfo};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Default)]
pub struct AuthManager {
    providers: HashMap<String, Arc<dyn AuthProvider>>,
}

impl AuthManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, p: impl AuthProvider + 'static) {
        self.providers.insert(p.id().to_string(), Arc::new(p));
    }

    /// Hook for cloud tier / plugins to inject providers at runtime.
    pub fn register_boxed(&mut self, p: Arc<dyn AuthProvider>) {
        self.providers.insert(p.id().to_string(), p);
    }

    pub fn providers(&self) -> Vec<ProviderInfo> {
        self.providers.values().map(|p| p.info()).collect()
    }

    pub fn has_any(&self) -> bool {
        !self.providers.is_empty()
    }

    pub async fn authenticate(
        &self,
        provider_id: &str,
        creds: &Credentials,
        pool: &sqlx::PgPool,
    ) -> anyhow::Result<AuthUser> {
        self.providers
            .get(provider_id)
            .ok_or_else(|| anyhow::anyhow!("unknown provider: {provider_id}"))?
            .authenticate(creds, pool)
            .await
    }
}
