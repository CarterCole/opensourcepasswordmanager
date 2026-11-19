//! WebAuthn passkeys (FIDO2) via `webauthn-rs`.
//!
//! Passkeys are **opt-in**: the service is only active when `SECRETD_RP_ID` and
//! `SECRETD_RP_ORIGIN` are configured. When disabled, all operations return an
//! error and the HTTP endpoints report 501.
//!
//! The in-progress registration / authentication ceremony state is held in a
//! short-lived in-memory store (single-instance). Completed credentials are
//! serialized as JSON and persisted in `users.webauthn_credentials`.
//!
//! NOTE: the registration/authentication ceremonies require a real browser
//! authenticator and must be validated end-to-end in a browser; they cannot be
//! exercised by the server-side unit tests, which cover only configuration
//! gating and credential (de)serialization.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// How long an in-flight ceremony challenge remains valid.
const CEREMONY_TTL: Duration = Duration::from_secs(300);

pub struct PasskeyService {
    webauthn: Option<Webauthn>,
}

struct Pending<T> {
    state: T,
    created: Instant,
}

fn reg_store() -> &'static Mutex<HashMap<Uuid, Pending<PasskeyRegistration>>> {
    static S: OnceLock<Mutex<HashMap<Uuid, Pending<PasskeyRegistration>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn auth_store() -> &'static Mutex<HashMap<String, Pending<PasskeyAuthentication>>> {
    static S: OnceLock<Mutex<HashMap<String, Pending<PasskeyAuthentication>>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

impl PasskeyService {
    /// Build from config. Returns a disabled service if RP id/origin are unset.
    pub fn from_config(rp_id: Option<&str>, rp_origin: Option<&str>) -> Self {
        let webauthn = match (rp_id, rp_origin) {
            (Some(id), Some(origin)) => match Url::parse(origin) {
                // `url` must outlive the builder (which borrows it) up to build().
                Ok(url) => WebauthnBuilder::new(id, &url)
                    .and_then(|b| b.rp_name("secretd").build())
                    .ok(),
                Err(_) => None,
            },
            _ => None,
        };
        Self { webauthn }
    }

    pub fn enabled(&self) -> bool {
        self.webauthn.is_some()
    }

    fn engine(&self) -> Result<&Webauthn> {
        self.webauthn
            .as_ref()
            .ok_or_else(|| anyhow!("passkeys are not configured"))
    }

    /// Begin registration for a user. Persist nothing yet; the returned
    /// challenge goes to the browser, the ceremony state is stashed server-side.
    pub fn start_registration(
        &self,
        user_id: Uuid,
        user_name: &str,
        display_name: &str,
        existing: &[Passkey],
    ) -> Result<CreationChallengeResponse> {
        let webauthn = self.engine()?;
        let exclude = existing
            .iter()
            .map(|p| p.cred_id().clone())
            .collect::<Vec<_>>();
        let (ccr, state) = webauthn
            .start_passkey_registration(user_id, user_name, display_name, Some(exclude))
            .map_err(|e| anyhow!("start registration: {e}"))?;
        gc(reg_store());
        reg_store()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                user_id,
                Pending {
                    state,
                    created: Instant::now(),
                },
            );
        Ok(ccr)
    }

    /// Complete registration, returning the new credential to persist.
    pub fn finish_registration(
        &self,
        user_id: Uuid,
        reg: &RegisterPublicKeyCredential,
    ) -> Result<Passkey> {
        let webauthn = self.engine()?;
        let pending = reg_store()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&user_id)
            .ok_or_else(|| anyhow!("no registration in progress"))?;
        if pending.created.elapsed() > CEREMONY_TTL {
            return Err(anyhow!("registration challenge expired"));
        }
        webauthn
            .finish_passkey_registration(reg, &pending.state)
            .map_err(|e| anyhow!("finish registration: {e}"))
    }

    /// Begin authentication for a set of the user's credentials.
    pub fn start_authentication(
        &self,
        key: &str,
        credentials: &[Passkey],
    ) -> Result<RequestChallengeResponse> {
        let webauthn = self.engine()?;
        if credentials.is_empty() {
            return Err(anyhow!("no passkeys registered"));
        }
        let (rcr, state) = webauthn
            .start_passkey_authentication(credentials)
            .map_err(|e| anyhow!("start authentication: {e}"))?;
        gc(auth_store());
        auth_store()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(
                key.to_string(),
                Pending {
                    state,
                    created: Instant::now(),
                },
            );
        Ok(rcr)
    }

    /// Complete authentication. Returns the credential id that was used and
    /// whether its signature counter advanced (for optional persistence).
    pub fn finish_authentication(
        &self,
        key: &str,
        assertion: &PublicKeyCredential,
    ) -> Result<AuthenticationResult> {
        let webauthn = self.engine()?;
        let pending = auth_store()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key)
            .ok_or_else(|| anyhow!("no authentication in progress"))?;
        if pending.created.elapsed() > CEREMONY_TTL {
            return Err(anyhow!("authentication challenge expired"));
        }
        webauthn
            .finish_passkey_authentication(assertion, &pending.state)
            .map_err(|e| anyhow!("finish authentication: {e}"))
    }
}

/// Parse the stored JSON array of passkeys.
pub fn parse_credentials(json: &serde_json::Value) -> Vec<Passkey> {
    serde_json::from_value(json.clone()).unwrap_or_default()
}

/// Serialize passkeys for storage.
pub fn serialize_credentials(creds: &[Passkey]) -> serde_json::Value {
    serde_json::to_value(creds).unwrap_or_else(|_| serde_json::json!([]))
}

/// Drop expired ceremony entries so the stores stay bounded.
fn gc<T>(store: &'static Mutex<HashMap<impl std::hash::Hash + Eq, Pending<T>>>) {
    if let Ok(mut map) = store.lock() {
        map.retain(|_, p| p.created.elapsed() <= CEREMONY_TTL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_without_config() {
        let svc = PasskeyService::from_config(None, None);
        assert!(!svc.enabled());
        assert!(svc
            .start_registration(Uuid::new_v4(), "a", "a", &[])
            .is_err());
    }

    #[test]
    fn enabled_with_valid_config() {
        let svc = PasskeyService::from_config(Some("localhost"), Some("http://localhost:8200"));
        assert!(svc.enabled());
    }

    #[test]
    fn invalid_origin_stays_disabled() {
        let svc = PasskeyService::from_config(Some("localhost"), Some("not a url"));
        assert!(!svc.enabled());
    }

    #[test]
    fn credentials_roundtrip_empty() {
        let creds: Vec<Passkey> = vec![];
        let json = serialize_credentials(&creds);
        assert_eq!(parse_credentials(&json).len(), 0);
    }
}
