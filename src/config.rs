//! Server configuration — 12-factor env vars + optional TOML file.
//!
//! Security posture: the server **fails closed**. Secrets that would be
//! catastrophic to default (the JWT signing key, the dev root token) have no
//! built-in fallback value. A missing or weak value aborts startup rather than
//! silently booting with a publicly-known credential.
use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// Minimum length for the JWT signing secret (HS256). 32 bytes of entropy.
const MIN_JWT_SECRET_LEN: usize = 32;
/// Minimum length for an explicitly-configured dev root token.
const MIN_DEV_TOKEN_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct Config {
    pub listen_addr: String,
    pub database_url: String,
    /// Dev-only master token. `None` unless `SECRETD_DEV_ROOT_TOKEN` is set to a
    /// strong value — there is deliberately no default, so production never ships
    /// with a known backdoor token.
    pub dev_root_token: Option<String>,
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

    /// WebAuthn relying-party id (the site's registrable domain, e.g.
    /// "secretd.example.com" or "localhost"). Passkeys are disabled unless set.
    #[serde(default)]
    pub rp_id: Option<String>,

    /// WebAuthn origin, the full URL the UI is served from
    /// (e.g. "https://secretd.example.com"). Required for passkeys.
    #[serde(default)]
    pub rp_origin: Option<String>,
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
        // JWT signing secret — required, no default. A weak or guessable secret
        // lets anyone forge session tokens, so refuse to start without a strong one.
        let jwt_secret = std::env::var("SECRETD_JWT_SECRET").context(
            "SECRETD_JWT_SECRET is not set — refusing to start without an explicit JWT signing secret \
             (generate one with `openssl rand -base64 48`)",
        )?;
        if jwt_secret.len() < MIN_JWT_SECRET_LEN {
            bail!(
                "SECRETD_JWT_SECRET is too short ({} chars) — use at least {} characters of entropy",
                jwt_secret.len(),
                MIN_JWT_SECRET_LEN
            );
        }
        if jwt_secret == "change-me-in-production" {
            bail!("SECRETD_JWT_SECRET is still the example value — set a unique random secret");
        }

        // Dev root token — opt-in only. There is intentionally NO default: in
        // production the field stays `None` so there is no publicly-known master
        // token. When set, it must still be strong and must not be the docs value.
        let dev_root_token = match std::env::var("SECRETD_DEV_ROOT_TOKEN") {
            Ok(t) if !t.is_empty() => {
                if t == "dev-root-token" {
                    bail!(
                        "SECRETD_DEV_ROOT_TOKEN is set to the example value 'dev-root-token' — \
                         use a long random token, or unset it to disable the dev root token entirely"
                    );
                }
                if t.len() < MIN_DEV_TOKEN_LEN {
                    bail!(
                        "SECRETD_DEV_ROOT_TOKEN is too short ({} chars) — use at least {} random \
                         characters, or unset it to disable the dev root token",
                        t.len(),
                        MIN_DEV_TOKEN_LEN
                    );
                }
                Some(t)
            }
            // Unset or empty → disabled. Fail closed: no backdoor token.
            _ => None,
        };

        Ok(Self {
            listen_addr: std::env::var("SECRETD_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:8200".into()),
            database_url: std::env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?,
            dev_root_token,
            jwt_secret,
            auth: AuthConfig {
                // SECRETD_AUTH_EMAIL=true enables email login
                email: std::env::var("SECRETD_AUTH_EMAIL")
                    .map(|v| v == "true" || v == "1")
                    .unwrap_or(false),
                ldap: None,  // configured via TOML only (too many fields for env)
                oidc: vec![], // configured via TOML only
                rp_id: std::env::var("SECRETD_RP_ID").ok(),
                rp_origin: std::env::var("SECRETD_RP_ORIGIN").ok(),
            },
        })
    }
}
