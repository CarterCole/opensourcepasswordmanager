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

    /// OpenID Connect providers (Kith, Okta, Google, ...), zero or more. Kith is
    /// configured from `SECRETD_KITH_*` env vars.
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
    /// Omit for a public client (PKCE is always used, so none is needed).
    #[serde(default)]
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    /// Defaults to `openid email profile`; `openid` is always added.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Create a user on first login when none matches. Off by default: new users
    /// are otherwise invited by an administrator. Needs a verified email.
    #[serde(default)]
    pub auto_provision: bool,
    /// Sent as `acr_values` (e.g. `urn:kith:acr:aal2` to demand a strong login).
    #[serde(default)]
    pub acr_values: Option<String>,
}

/// Path the OIDC callback is served on; the provider's redirect URI must end in it.
pub fn oidc_callback_path(id: &str) -> String {
    format!("/api/v1/auth/oidc/{id}/callback")
}

/// "Sign in with Kith" (https://github.com/CarterCole/kith) from the environment.
/// Enabled by setting `SECRETD_KITH_ISSUER`; returns `None` when it is unset.
fn kith_from_env(rp_origin: Option<&str>) -> Result<Option<OidcConfig>> {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.trim().is_empty());
    let Some(issuer) = var("SECRETD_KITH_ISSUER") else {
        return Ok(None);
    };
    let client_id = var("SECRETD_KITH_CLIENT_ID")
        .context("SECRETD_KITH_CLIENT_ID is required when SECRETD_KITH_ISSUER is set")?;
    let redirect_uri = match var("SECRETD_KITH_REDIRECT_URI") {
        Some(u) => u,
        None => match rp_origin {
            Some(o) => format!("{}{}", o.trim_end_matches('/'), oidc_callback_path("kith")),
            None => bail!(
                "set SECRETD_KITH_REDIRECT_URI (or SECRETD_RP_ORIGIN) so the Kith hub \
                 knows where to send the user back"
            ),
        },
    };
    let flag = |k: &str| matches!(std::env::var(k).as_deref(), Ok("true") | Ok("1"));
    Ok(Some(OidcConfig {
        id: "kith".into(),
        display_name: "Kith".into(),
        issuer,
        client_id,
        client_secret: var("SECRETD_KITH_CLIENT_SECRET"),
        redirect_uri,
        scopes: var("SECRETD_KITH_SCOPES")
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default(),
        auto_provision: flag("SECRETD_KITH_AUTO_PROVISION"),
        acr_values: var("SECRETD_KITH_ACR_VALUES"),
    }))
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

        let rp_origin = std::env::var("SECRETD_RP_ORIGIN").ok();
        let oidc: Vec<OidcConfig> = kith_from_env(rp_origin.as_deref())?.into_iter().collect();

        Ok(Self {
            listen_addr: std::env::var("SECRETD_LISTEN").unwrap_or_else(|_| "0.0.0.0:8200".into()),
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL not set")?,
            dev_root_token,
            jwt_secret,
            auth: AuthConfig {
                // SECRETD_AUTH_EMAIL=true enables email login
                email: std::env::var("SECRETD_AUTH_EMAIL")
                    .map(|v| v == "true" || v == "1")
                    .unwrap_or(false),
                ldap: None, // configured via TOML only (too many fields for env)
                oidc,
                rp_id: std::env::var("SECRETD_RP_ID").ok(),
                rp_origin,
            },
        })
    }
}
