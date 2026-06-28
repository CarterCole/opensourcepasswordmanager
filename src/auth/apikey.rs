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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_starts_with_sk_live() {
        let (raw, _prefix, _hash) = ApiKeyService::generate().unwrap();
        assert!(raw.starts_with("sk_live_"), "key should start with sk_live_: {raw}");
    }

    #[test]
    fn prefix_is_first_12_chars() {
        let (raw, prefix, _hash) = ApiKeyService::generate().unwrap();
        assert_eq!(&raw[..12], prefix, "prefix should be first 12 chars of raw key");
    }

    #[test]
    fn verify_correct_key_returns_true() {
        let (raw, _prefix, hash) = ApiKeyService::generate().unwrap();
        assert!(ApiKeyService::verify(&raw, &hash), "verify should return true for correct key");
    }

    #[test]
    fn verify_wrong_key_returns_false() {
        let (_raw, _prefix, hash) = ApiKeyService::generate().unwrap();
        assert!(
            !ApiKeyService::verify("sk_live_totally_wrong_key", &hash),
            "verify should return false for wrong key"
        );
    }

    #[test]
    fn two_generated_keys_differ() {
        let (raw1, _p1, _h1) = ApiKeyService::generate().unwrap();
        let (raw2, _p2, _h2) = ApiKeyService::generate().unwrap();
        assert_ne!(raw1, raw2, "two generated keys should differ");
    }

    #[test]
    fn verify_malformed_hash_returns_false() {
        let (raw, _prefix, _hash) = ApiKeyService::generate().unwrap();
        assert!(!ApiKeyService::verify(&raw, "not-a-valid-hash"));
    }
}
