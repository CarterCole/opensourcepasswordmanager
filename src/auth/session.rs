//! JWT session tokens.
use anyhow::Result;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,       // user UUID
    pub org: String,       // org UUID
    pub email: String,
    pub roles: Vec<String>,
    pub exp: usize,
    pub iat: usize,
    /// true if 2FA has been satisfied (or not enrolled)
    pub two_fa_verified: bool,
}

pub struct SessionService {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl SessionService {
    pub fn from_secret(secret: &str) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret.as_bytes()),
            decoding: DecodingKey::from_secret(secret.as_bytes()),
        }
    }

    pub fn issue(
        &self,
        user_id: Uuid,
        org_id: Uuid,
        email: &str,
        roles: Vec<String>,
        two_fa_verified: bool,
        ttl_seconds: i64,
    ) -> Result<String> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id.to_string(),
            org: org_id.to_string(),
            email: email.to_string(),
            roles,
            iat: now.timestamp() as usize,
            exp: (now + Duration::seconds(ttl_seconds)).timestamp() as usize,
            two_fa_verified,
        };
        let token = encode(&Header::default(), &claims, &self.encoding)?;
        Ok(token)
    }

    pub fn validate(&self, token: &str) -> Result<Claims> {
        let data = decode::<Claims>(token, &self.decoding, &Validation::default())?;
        Ok(data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_service() -> SessionService {
        SessionService::from_secret("super-secret-test-key")
    }

    fn sample_claims(ttl: i64) -> (Uuid, Uuid, String, Vec<String>, bool, i64) {
        let user_id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let org_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
        (user_id, org_id, "test@example.com".into(), vec!["admin".into()], true, ttl)
    }

    #[test]
    fn issue_and_validate_roundtrip() {
        let svc = test_service();
        let (uid, oid, email, roles, tfa, ttl) = sample_claims(3600);
        let token = svc.issue(uid, oid, &email, roles.clone(), tfa, ttl).unwrap();
        let claims = svc.validate(&token).unwrap();
        assert_eq!(claims.sub, uid.to_string());
        assert_eq!(claims.org, oid.to_string());
        assert_eq!(claims.email, email);
        assert_eq!(claims.roles, roles);
        assert!(claims.two_fa_verified);
    }

    #[test]
    fn tampered_token_fails_validate() {
        let svc = test_service();
        let (uid, oid, email, roles, tfa, ttl) = sample_claims(3600);
        let mut token = svc.issue(uid, oid, &email, roles, tfa, ttl).unwrap();
        // Corrupt the signature portion (last segment)
        token.push_str("TAMPERED");
        assert!(svc.validate(&token).is_err(), "tampered token should fail");
    }

    #[test]
    fn expired_token_fails_validate() {
        let svc = test_service();
        let (uid, oid, email, roles, tfa, _) = sample_claims(0);
        // Use a large negative TTL (well past the 60-second leeway jsonwebtoken applies)
        let token = svc.issue(uid, oid, &email, roles, tfa, -7200).unwrap();
        assert!(svc.validate(&token).is_err(), "expired token should fail");
    }

    #[test]
    fn wrong_secret_fails_validate() {
        let svc1 = test_service();
        let svc2 = SessionService::from_secret("completely-different-secret");
        let (uid, oid, email, roles, tfa, ttl) = sample_claims(3600);
        let token = svc1.issue(uid, oid, &email, roles, tfa, ttl).unwrap();
        assert!(svc2.validate(&token).is_err(), "token signed with different secret should fail");
    }
}
