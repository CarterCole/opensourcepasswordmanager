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
