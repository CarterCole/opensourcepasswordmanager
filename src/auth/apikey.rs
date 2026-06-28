//! API key generation and validation.
//! Keys are formatted as `sk_live_{random_base64}` and stored as Argon2 hashes.
use anyhow::{Context, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use rand::RngCore;
use uuid::Uuid;

pub struct ApiKeyService;

impl ApiKeyService {
    /// Generate a new raw API key and its hash.
    /// Returns `(raw_key, prefix, hash)`.
    pub fn generate() -> Result<(String, String, String)> {
        let mut bytes = [0u8; 40];
        rand::thread_rng().fill_bytes(&mut bytes);
        let raw = format!("sk_live_{}", B64.encode(bytes));
        let prefix = raw[..12].to_string();
        let hash = Self::hash(&raw)?;
        Ok((raw, prefix, hash))
    }

    pub fn hash(key: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(key.as_bytes(), &salt)
            .map_err(|e| anyhow::anyhow!("hash failed: {e}"))?
            .to_string();
        Ok(hash)
    }

    pub fn verify(key: &str, hash: &str) -> bool {
        let parsed = match PasswordHash::new(hash) {
            Ok(h) => h,
            Err(_) => return false,
        };
        Argon2::default()
            .verify_password(key.as_bytes(), &parsed)
            .is_ok()
    }
}
