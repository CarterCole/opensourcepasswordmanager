//! OpenID Connect relying party — "Sign in with Kith" (or any standards-compliant
//! OIDC provider: Okta, Keycloak, Google, ...).
//!
//! Authorization-code flow with PKCE (S256, always — Kith requires it for every
//! client), a per-login `state` bound to the browser by a cookie, and a `nonce`
//! checked in the ID token. ID tokens are verified against the provider's JWKS
//! (RS256 or EdDSA only), with `iss`, `aud`, `exp` and `nonce` all required.
//!
//! This module only talks to the provider. Mapping the verified identity to a
//! local user lives in `api::native::oidc`.
use super::provider::{AuthProvider, AuthUser, Credentials, ProviderInfo, ProviderKind};
use crate::config::{oidc_callback_path, OidcConfig};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode, decode_header, jwk::Jwk, Algorithm, DecodingKey, Validation};
use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// How long a started login may take before its `state` expires.
const FLOW_TTL: Duration = Duration::from_secs(600);
/// Cap on logins in flight, so unauthenticated `/start` calls cannot grow memory.
const MAX_FLOWS: usize = 10_000;
/// How long a discovery document is trusted.
const DISCOVERY_TTL: Duration = Duration::from_secs(3600);

/// Verified identity from the provider's ID token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcIdentity {
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub acr: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    #[serde(default)]
    code_challenge_methods_supported: Option<Vec<String>>,
}

/// One configured provider.
pub struct OidcProvider {
    cfg: OidcConfig,
    http: reqwest::Client,
    discovery: RwLock<Option<(Instant, Discovery)>>,
}

impl OidcProvider {
    pub fn new(mut cfg: OidcConfig) -> Result<Self> {
        if cfg.id.is_empty()
            || !cfg
                .id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            bail!(
                "OIDC provider id must be alphanumeric/dashes, got {:?}",
                cfg.id
            );
        }
        cfg.issuer = cfg.issuer.trim_end_matches('/').to_string();
        require_secure_url("issuer", &cfg.issuer)?;
        require_secure_url("redirect_uri", &cfg.redirect_uri)?;
        if !cfg.redirect_uri.ends_with(&oidc_callback_path(&cfg.id)) {
            bail!(
                "OIDC redirect_uri for {:?} must end in {} (register exactly that URL with the provider)",
                cfg.id,
                oidc_callback_path(&cfg.id)
            );
        }
        if cfg.scopes.is_empty() {
            cfg.scopes = ["openid", "email", "profile"].map(String::from).into();
        } else if !cfg.scopes.iter().any(|s| s == "openid") {
            cfg.scopes.insert(0, "openid".into());
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            // Discovery and token endpoints must answer directly.
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            cfg,
            http,
            discovery: RwLock::new(None),
        })
    }

    pub fn config(&self) -> &OidcConfig {
        &self.cfg
    }

    pub fn issuer(&self) -> &str {
        &self.cfg.issuer
    }

    /// Whether the session cookie and flow cookie should be marked `Secure`.
    pub fn secure(&self) -> bool {
        self.cfg.redirect_uri.starts_with("https://")
    }

    async fn discover(&self) -> Result<Discovery> {
        if let Some((at, d)) = &*self.discovery.read().await {
            if at.elapsed() < DISCOVERY_TTL {
                return Ok(d.clone());
            }
        }
        let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer);
        let d: Discovery = self
            .http
            .get(&url)
            .send()
            .await
            .context("fetching OIDC discovery document")?
            .error_for_status()?
            .json()
            .await
            .context("parsing OIDC discovery document")?;
        // OIDC Discovery §4.3: the issuer in the document must be the one we asked.
        if d.issuer.trim_end_matches('/') != self.cfg.issuer {
            bail!(
                "discovery issuer {:?} does not match {:?}",
                d.issuer,
                self.cfg.issuer
            );
        }
        for (n, u) in [
            ("authorization_endpoint", &d.authorization_endpoint),
            ("token_endpoint", &d.token_endpoint),
            ("jwks_uri", &d.jwks_uri),
        ] {
            require_secure_url(n, u)?;
        }
        if let Some(m) = &d.code_challenge_methods_supported {
            if !m.iter().any(|m| m == "S256") {
                bail!("provider does not support PKCE S256");
            }
        }
        *self.discovery.write().await = Some((Instant::now(), d.clone()));
        Ok(d)
    }

    /// Where to send the browser to sign in.
    pub async fn authorization_url(
        &self,
        state: &str,
        nonce: &str,
        verifier: &str,
    ) -> Result<String> {
        let d = self.discover().await?;
        build_authorization_url(&d.authorization_endpoint, &self.cfg, state, nonce, verifier)
    }

    /// Exchange the authorization `code` and return the verified identity.
    pub async fn complete(&self, code: &str, verifier: &str, nonce: &str) -> Result<OidcIdentity> {
        let d = self.discover().await?;
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.cfg.redirect_uri.as_str()),
            ("client_id", self.cfg.client_id.as_str()),
            ("code_verifier", verifier),
        ];
        let mut req = self.http.post(&d.token_endpoint);
        if let Some(secret) = &self.cfg.client_secret {
            // client_secret_basic, the method every provider must support.
            req = req.basic_auth(form_encode(&self.cfg.client_id), Some(form_encode(secret)));
            form.retain(|(k, _)| *k != "client_id");
        }
        let resp = req.form(&form).send().await.context("token request")?;
        if !resp.status().is_success() {
            bail!("token endpoint answered {}", resp.status());
        }
        #[derive(Deserialize)]
        struct Tokens {
            id_token: String,
        }
        let tokens: Tokens = resp
            .json()
            .await
            .context("token response has no id_token")?;

        let jwks: serde_json::Value = self
            .http
            .get(&d.jwks_uri)
            .send()
            .await
            .context("fetching JWKS")?
            .error_for_status()?
            .json()
            .await?;
        verify_id_token(
            &tokens.id_token,
            &jwks,
            &self.cfg.issuer,
            &self.cfg.client_id,
            nonce,
        )
    }
}

/// `application/x-www-form-urlencoded` escaping, for RFC 6749 §2.3.1 basic auth.
fn form_encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

/// Issuers and endpoints must be https; plain http is allowed only for loopback
/// (local development against `kith hub serve`).
fn require_secure_url(what: &str, u: &str) -> Result<()> {
    let url = url::Url::parse(u).with_context(|| format!("{what} is not a URL: {u:?}"))?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!("{what} must not contain credentials or a fragment");
    }
    let ok = match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(url::Host::Domain(d)) => d == "localhost",
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            None => false,
        },
        _ => false,
    };
    if !ok {
        bail!("{what} must be https (or http on loopback): {u}");
    }
    Ok(())
}

pub fn build_authorization_url(
    endpoint: &str,
    cfg: &OidcConfig,
    state: &str,
    nonce: &str,
    verifier: &str,
) -> Result<String> {
    let mut url = url::Url::parse(endpoint)?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code")
            .append_pair("client_id", &cfg.client_id)
            .append_pair("redirect_uri", &cfg.redirect_uri)
            .append_pair("scope", &cfg.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", &pkce_challenge(verifier))
            .append_pair("code_challenge_method", "S256");
        if let Some(acr) = &cfg.acr_values {
            q.append_pair("acr_values", acr);
        }
    }
    Ok(url.into())
}

/// RFC 7636 S256: `BASE64URL(SHA256(verifier))`.
pub fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// 256 bits of randomness, base64url (43 chars: a valid PKCE verifier too).
pub fn random_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

/// Verify an ID token against a JWKS document. Pure, so it is testable offline.
pub fn verify_id_token(
    token: &str,
    jwks: &serde_json::Value,
    issuer: &str,
    client_id: &str,
    nonce: &str,
) -> Result<OidcIdentity> {
    let header = decode_header(token).context("malformed ID token")?;
    // Never let the token pick a weak algorithm (`none`, HS256 keyed with a public key).
    let (alg, kty) = match header.alg {
        Algorithm::RS256 => (Algorithm::RS256, "RSA"),
        Algorithm::EdDSA => (Algorithm::EdDSA, "OKP"),
        other => bail!("ID token algorithm {other:?} is not accepted"),
    };

    // Tolerate JWKS entries we do not understand (other kty, curves): skip them
    // rather than failing the whole set.
    let keys: Vec<Jwk> = jwks
        .get("keys")
        .and_then(|k| k.as_array())
        .ok_or_else(|| anyhow!("JWKS has no keys"))?
        .iter()
        .filter(|k| k.get("kty").and_then(|v| v.as_str()) == Some(kty))
        .filter(|k| {
            k.get("use")
                .and_then(|v| v.as_str())
                .is_none_or(|u| u == "sig")
        })
        .filter_map(|k| serde_json::from_value::<Jwk>(k.clone()).ok())
        .collect();
    let jwk = match &header.kid {
        Some(kid) => keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid)),
        None if keys.len() == 1 => keys.first(),
        None => None,
    }
    .ok_or_else(|| anyhow!("no matching signing key in the provider's JWKS"))?;
    let key = DecodingKey::from_jwk(jwk).context("unusable signing key")?;

    let mut v = Validation::new(alg);
    v.set_issuer(&[issuer]);
    v.set_audience(&[client_id]);
    v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    v.validate_nbf = true;
    let claims = decode::<serde_json::Value>(token, &key, &v)
        .context("ID token rejected")?
        .claims;

    // Replay / mix-up defence: the nonce we sent must come back unchanged.
    if claims.get("nonce").and_then(|n| n.as_str()) != Some(nonce) {
        bail!("ID token nonce does not match");
    }
    // OIDC Core §3.1.3.7: with several audiences, azp must be us.
    if let Some(azp) = claims.get("azp").and_then(|a| a.as_str()) {
        if azp != client_id {
            bail!("ID token authorized party is not this client");
        }
    }
    let subject = claims
        .get("sub")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("ID token has no sub"))?
        .to_string();
    let s = |k: &str| {
        claims
            .get(k)
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .filter(|v| !v.is_empty())
    };
    // Some providers send "true" as a string.
    let email_verified = match claims.get("email_verified") {
        Some(serde_json::Value::Bool(b)) => *b,
        Some(serde_json::Value::String(t)) => t == "true",
        _ => false,
    };
    Ok(OidcIdentity {
        issuer: issuer.to_string(),
        subject,
        email: s("email").map(|e| e.to_lowercase()),
        email_verified,
        name: s("name").or_else(|| s("preferred_username")),
        acr: s("acr"),
    })
}

// ── logins in flight ───────────────────────────────────────────────────────────

/// What we remember between redirecting out and the callback.
#[derive(Debug, Clone)]
pub struct PendingFlow {
    pub provider: String,
    pub verifier: String,
    pub nonce: String,
    started: Instant,
}

/// `state` → pending login. In memory, single use, expiring; a restart only
/// abandons logins in flight (the user clicks "Sign in" again).
#[derive(Default)]
pub struct FlowStore {
    flows: Mutex<HashMap<String, PendingFlow>>,
}

impl FlowStore {
    pub fn insert(&self, state: String, provider: &str, verifier: String, nonce: String) {
        let mut m = self.flows.lock().unwrap_or_else(|e| e.into_inner());
        if m.len() >= MAX_FLOWS {
            m.retain(|_, f| f.started.elapsed() < FLOW_TTL);
            if m.len() >= MAX_FLOWS {
                // Under flood, shed the oldest rather than refuse a real user.
                if let Some(k) = m
                    .iter()
                    .min_by_key(|(_, f)| f.started)
                    .map(|(k, _)| k.clone())
                {
                    m.remove(&k);
                }
            }
        }
        m.insert(
            state,
            PendingFlow {
                provider: provider.to_string(),
                verifier,
                nonce,
                started: Instant::now(),
            },
        );
    }

    /// Remove and return the flow: a `state` can be used once.
    pub fn take(&self, state: &str) -> Option<PendingFlow> {
        let f = self
            .flows
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(state)?;
        (f.started.elapsed() < FLOW_TTL).then_some(f)
    }
}

/// All configured providers plus the logins in flight.
#[derive(Default)]
pub struct OidcService {
    providers: HashMap<String, Arc<OidcProvider>>,
    pub flows: FlowStore,
}

impl OidcService {
    pub fn new(configs: Vec<OidcConfig>) -> Result<Self> {
        let mut providers = HashMap::new();
        for c in configs {
            let p = Arc::new(OidcProvider::new(c)?);
            if providers.insert(p.cfg.id.clone(), p).is_some() {
                bail!("duplicate OIDC provider id");
            }
        }
        Ok(Self {
            providers,
            flows: FlowStore::default(),
        })
    }

    pub fn get(&self, id: &str) -> Option<Arc<OidcProvider>> {
        self.providers.get(id).cloned()
    }

    pub fn all(&self) -> impl Iterator<Item = &Arc<OidcProvider>> {
        self.providers.values()
    }
}

/// Lists the provider on the login screen. The login itself is the redirect flow
/// (`/api/v1/auth/oidc/{id}/start`), so `authenticate` is never the way in.
#[async_trait]
impl AuthProvider for OidcProvider {
    fn id(&self) -> &str {
        &self.cfg.id
    }

    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: self.cfg.id.clone(),
            display_name: self.cfg.display_name.clone(),
            kind: ProviderKind::Redirect {
                url: format!("/api/v1/auth/oidc/{}/start", self.cfg.id),
            },
        }
    }

    async fn authenticate(&self, _: &Credentials, _: &sqlx::PgPool) -> Result<AuthUser> {
        Err(anyhow!("use the redirect flow for this provider"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use openssl::{bn::BigNumRef, rsa::Rsa};
    use serde_json::json;

    const ISS: &str = "https://id.example.com";
    const CID: &str = "secretd";

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    struct TestKey {
        enc: EncodingKey,
        jwks: serde_json::Value,
    }

    fn test_key(kid: &str) -> TestKey {
        let rsa = Rsa::generate(2048).unwrap();
        let b64 = |n: &BigNumRef| URL_SAFE_NO_PAD.encode(n.to_vec());
        TestKey {
            enc: EncodingKey::from_rsa_pem(&rsa.private_key_to_pem().unwrap()).unwrap(),
            jwks: json!({"keys": [{
                "kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
                "n": b64(rsa.n()), "e": b64(rsa.e()),
            }]}),
        }
    }

    fn sign(k: &TestKey, kid: &str, claims: serde_json::Value) -> String {
        let mut h = Header::new(Algorithm::RS256);
        h.kid = Some(kid.into());
        jsonwebtoken::encode(&h, &claims, &k.enc).unwrap()
    }

    fn good() -> serde_json::Value {
        json!({
            "iss": ISS, "aud": CID, "sub": "did:kith:abc", "exp": now() + 300, "iat": now(),
            "nonce": "n1", "email": "Ada@Example.com", "email_verified": true, "name": "Ada",
            "acr": "urn:kith:acr:aal2",
        })
    }

    #[test]
    fn pkce_matches_rfc7636_vector() {
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(random_token().len(), 43);
        assert_ne!(random_token(), random_token());
    }

    #[test]
    fn valid_token_is_accepted_and_normalised() {
        let k = test_key("k1");
        let id = verify_id_token(&sign(&k, "k1", good()), &k.jwks, ISS, CID, "n1").unwrap();
        assert_eq!(id.subject, "did:kith:abc");
        assert_eq!(id.email.as_deref(), Some("ada@example.com"));
        assert!(id.email_verified);
        assert_eq!(id.name.as_deref(), Some("Ada"));
        assert_eq!(id.acr.as_deref(), Some("urn:kith:acr:aal2"));
    }

    #[test]
    fn rejects_wrong_nonce_audience_issuer_and_expiry() {
        let k = test_key("k1");
        let check =
            |c: serde_json::Value| verify_id_token(&sign(&k, "k1", c), &k.jwks, ISS, CID, "n1");
        let mut c = good();
        c["nonce"] = json!("other");
        assert!(check(c).is_err());
        let mut c = good();
        c.as_object_mut().unwrap().remove("nonce");
        assert!(check(c).is_err());
        let mut c = good();
        c["aud"] = json!("someone-else");
        assert!(check(c).is_err());
        let mut c = good();
        c["iss"] = json!("https://evil.example");
        assert!(check(c).is_err());
        let mut c = good();
        c["exp"] = json!(now() - 3600);
        assert!(check(c).is_err());
        let mut c = good();
        c["aud"] = json!([CID, "other"]);
        c["azp"] = json!("other");
        assert!(check(c).is_err());
        let mut c = good();
        c["sub"] = json!("");
        assert!(check(c).is_err());
    }

    #[test]
    fn rejects_forged_signature_and_unknown_kid() {
        let (k, attacker) = (test_key("k1"), test_key("k1"));
        // Signed with a different key but claiming the right kid.
        let forged = sign(&attacker, "k1", good());
        assert!(verify_id_token(&forged, &k.jwks, ISS, CID, "n1").is_err());
        // Right key, kid the provider does not publish.
        let t = sign(&k, "nope", good());
        assert!(verify_id_token(&t, &k.jwks, ISS, CID, "n1").is_err());
    }

    #[test]
    fn rejects_hmac_and_none_algorithms() {
        let k = test_key("k1");
        // Classic confusion attack: HS256 keyed with the (public) modulus.
        let n = k.jwks["keys"][0]["n"].as_str().unwrap();
        let mut h = Header::new(Algorithm::HS256);
        h.kid = Some("k1".into());
        let t = jsonwebtoken::encode(&h, &good(), &EncodingKey::from_secret(n.as_bytes())).unwrap();
        assert!(verify_id_token(&t, &k.jwks, ISS, CID, "n1").is_err());
        let none = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(good().to_string())
        );
        assert!(verify_id_token(&none, &k.jwks, ISS, CID, "n1").is_err());
    }

    #[test]
    fn unverified_email_is_reported_as_such() {
        let k = test_key("k1");
        for v in [json!(false), json!("false"), json!(null)] {
            let mut c = good();
            c["email_verified"] = v;
            let id = verify_id_token(&sign(&k, "k1", c), &k.jwks, ISS, CID, "n1").unwrap();
            assert!(!id.email_verified);
        }
        let mut c = good();
        c["email_verified"] = json!("true");
        assert!(
            verify_id_token(&sign(&k, "k1", c), &k.jwks, ISS, CID, "n1")
                .unwrap()
                .email_verified
        );
    }

    #[test]
    fn jwks_with_unknown_key_types_is_tolerated() {
        let k = test_key("k1");
        let mut jwks = k.jwks.clone();
        jwks["keys"].as_array_mut().unwrap().insert(
            0,
            json!({"kty": "EC", "crv": "P-999", "kid": "weird", "x": "a", "y": "b"}),
        );
        assert!(verify_id_token(&sign(&k, "k1", good()), &jwks, ISS, CID, "n1").is_ok());
    }

    fn cfg() -> OidcConfig {
        OidcConfig {
            id: "kith".into(),
            display_name: "Kith".into(),
            issuer: ISS.into(),
            client_id: CID.into(),
            client_secret: None,
            redirect_uri: "https://vault.example.com/api/v1/auth/oidc/kith/callback".into(),
            scopes: vec![],
            auto_provision: false,
            acr_values: Some("urn:kith:acr:aal2".into()),
        }
    }

    #[test]
    fn authorization_url_carries_pkce_state_and_nonce() {
        let p = OidcProvider::new(cfg()).unwrap();
        let u = build_authorization_url(
            &format!("{ISS}/oauth/authorize"),
            p.config(),
            "st",
            "no",
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        )
        .unwrap();
        let url = url::Url::parse(&u).unwrap();
        let q: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], CID);
        assert_eq!(q["scope"], "openid email profile");
        assert_eq!(q["state"], "st");
        assert_eq!(q["nonce"], "no");
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(
            q["code_challenge"],
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert_eq!(q["acr_values"], "urn:kith:acr:aal2");
        assert!(!q.contains_key("code_verifier"));
    }

    #[test]
    fn provider_config_is_validated() {
        let mut c = cfg();
        c.issuer = "http://id.example.com".into();
        assert!(OidcProvider::new(c).is_err(), "plain http issuer");
        let mut c = cfg();
        c.issuer = "http://localhost:7788/".into();
        c.redirect_uri = "http://localhost:8200/api/v1/auth/oidc/kith/callback".into();
        assert_eq!(
            OidcProvider::new(c).unwrap().issuer(),
            "http://localhost:7788"
        );
        let mut c = cfg();
        c.redirect_uri = "https://vault.example.com/cb".into();
        assert!(OidcProvider::new(c).is_err(), "callback path");
        let mut c = cfg();
        c.issuer = "https://good.example@evil.example".into();
        assert!(OidcProvider::new(c).is_err(), "userinfo in issuer");
        let mut c = cfg();
        c.id = "a/b".into();
        assert!(OidcProvider::new(c).is_err());
        let mut c = cfg();
        c.scopes = vec!["email".into()];
        assert_eq!(
            OidcProvider::new(c).unwrap().config().scopes,
            ["openid", "email"]
        );
    }

    #[test]
    fn flows_are_single_use() {
        let f = FlowStore::default();
        f.insert("s".into(), "kith".into(), "v".into(), "n".into());
        let got = f.take("s").unwrap();
        assert_eq!(
            (got.provider.as_str(), got.verifier.as_str()),
            ("kith", "v")
        );
        assert!(f.take("s").is_none());
        assert!(f.take("never-started").is_none());
    }
}
