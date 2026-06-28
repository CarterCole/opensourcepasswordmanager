//! Server configuration — 12-factor env vars + optional TOML file.
use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: String,
    pub database_url: String,
    pub dev_root_token: String,
    pub jwt_secret: String,
    pub auth: AuthConfig,
}

/// Which human login methods are enabled. All default to disabled.
/// API key bearer tokens are always active regardless of these settings.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthConfig {
    /// Enable email+password login. Default: false.
    #[serde(default)]
    pub email: bool,

    /// LDAP provider, if configured.
    pub ldap: Option<LdapConfig>,

    /// OIDC providers (Okta, GitHub, Google, etc.), zero or more.
    #[serde(default)]
    pub oidc: Vec<OidcConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LdapConfig {
    pub url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub base_dn: String,
    /// Template with `{username}` placeholder. Example: `(uid={username})`
    pub user_filter: String,
    pub email_attr: Option<String>,
    pub display_name_attr: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfig {
    /// Unique id shown in the UI, e.g. "okta", "github", "google"
    pub id: String,
    pub display_name: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            listen_addr: std::env::var("SECRETD_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:8200".into()),
            database_url: std::env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?,
            dev_root_token: std::env::var("SECRETD_DEV_ROOT_TOKEN")
                .unwrap_or_else(|_| "dev-root-token".into()),
            jwt_secret: std::env::var("SECRETD_JWT_SECRET")
                .unwrap_or_else(|_| "change-me-in-production".into()),
            auth: AuthConfig {
                // SECRETD_AUTH_EMAIL=true enables email login
                email: std::env::var("SECRETD_AUTH_EMAIL")
                    .map(|v| v == "true" || v == "1")
                    .unwrap_or(false),
                ldap: None,  // configured via TOML only (too many fields for env)
                oidc: vec![], // configured via TOML only
            },
        })
    }
}
