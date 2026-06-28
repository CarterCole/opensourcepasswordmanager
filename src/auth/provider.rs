//! AuthProvider trait — implement to add a login method.
//!
//! Built-in providers are registered at startup based on config.
//! The cloud tier or third-party plugins register additional providers
//! by calling AuthManager::register_boxed at startup before serving.
//!
//! Core bearer-token (API key) auth is always active and does NOT go
//! through this trait — it's enforced at the middleware layer directly.
//! This trait is for *human* login methods (email/password, LDAP, OIDC).
use async_trait::async_trait;
use serde::Serialize;
use uuid::Uuid;

/// Identity returned after a successful human login.
#[derive(Debug, Clone)]
pub struct AuthUser {
    /// DB user id (or None if the provider saw a new user that should be auto-provisioned)
    pub user_id: Option<Uuid>,
    pub org_id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    /// Roles to attach. Empty = let DB decide from existing role_assignments.
    pub roles: Vec<String>,
}

pub type Credentials = serde_json::Value;

/// Describes the login widget the UI should render for this provider.
#[derive(Debug, Clone, Serialize)]
pub struct ProviderField {
    pub name: String,
    pub label: String,
    #[serde(rename = "type")]
    pub kind: String, // "text" | "password"
    pub required: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ProviderKind {
    /// Shows a form with fields (email/password, LDAP username/password)
    Form { fields: Vec<ProviderField> },
    /// Redirects to an external URL (OAuth2 / OIDC / SAML)
    Redirect { url: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderInfo {
    pub id: String,
    pub display_name: String,
    #[serde(flatten)]
    pub kind: ProviderKind,
}

#[async_trait]
pub trait AuthProvider: Send + Sync {
    fn id(&self) -> &str;
    fn info(&self) -> ProviderInfo;
    async fn authenticate(&self, creds: &Credentials, pool: &sqlx::PgPool) -> anyhow::Result<AuthUser>;
}
