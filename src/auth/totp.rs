//! TOTP (RFC 6238) two-factor authentication and single-use backup codes.
//!
//! The TOTP seed is generated server-side, shown to the user once as an
//! `otpauth://` provisioning URI (and QR), and stored only in encrypted form
//! (see [`crate::core::CryptoEngine::seal`]). Enrollment is confirmed by a
//! verify step so a mistyped seed can never lock a user out.

use anyhow::{anyhow, Result};
use rand::RngCore;
use totp_rs::{Algorithm, Secret, TOTP};

/// Period (seconds) and allowed skew (steps) for verification.
const STEP: u64 = 30;
const SKEW: u8 = 1; // accept the adjacent window on each side
const DIGITS: usize = 6;
const ISSUER: &str = "secretd";

pub struct TotpService;

impl TotpService {
    /// Generate a fresh random base32 TOTP secret (160 bits).
    pub fn generate_secret() -> String {
        let mut bytes = [0u8; 20];
        rand::thread_rng().fill_bytes(&mut bytes);
        Secret::Raw(bytes.to_vec()).to_encoded().to_string()
    }

    fn totp(secret_b32: &str, account: &str) -> Result<TOTP> {
        let secret = Secret::Encoded(secret_b32.to_string())
            .to_bytes()
            .map_err(|e| anyhow!("invalid TOTP secret: {e:?}"))?;
        TOTP::new(Algorithm::SHA1, DIGITS, SKEW, STEP, secret, Some(ISSUER.to_string()), account.to_string())
            .map_err(|e| anyhow!("totp init: {e}"))
    }

    /// `otpauth://` provisioning URI for authenticator apps.
    pub fn provisioning_uri(secret_b32: &str, account: &str) -> Result<String> {
        Ok(Self::totp(secret_b32, account)?.get_url())
    }

    /// Base64-encoded PNG QR code for the provisioning URI.
    pub fn qr_base64(secret_b32: &str, account: &str) -> Result<String> {
        Self::totp(secret_b32, account)?
            .get_qr_base64()
            .map_err(|e| anyhow!("qr: {e}"))
    }

    /// Verify a 6-digit code against the secret, allowing ±1 time step of skew.
    pub fn verify(secret_b32: &str, code: &str, account: &str) -> bool {
        let code = code.trim();
        match Self::totp(secret_b32, account) {
            Ok(t) => t.check_current(code).unwrap_or(false),
            Err(_) => false,
        }
    }
}

/// Single-use recovery codes, used if the authenticator device is lost.
pub struct BackupCodes;

impl BackupCodes {
    /// Number of codes issued per enrollment.
    pub const COUNT: usize = 10;

    /// Generate `COUNT` human-friendly codes (shown once) paired with their
    /// Argon2 hashes (stored). Returns `(plaintext_codes, hashes)`.
    pub fn generate() -> Result<(Vec<String>, Vec<String>)> {
        let mut plain = Vec::with_capacity(Self::COUNT);
        let mut hashes = Vec::with_capacity(Self::COUNT);
        for _ in 0..Self::COUNT {
            let mut raw = [0u8; 6];
            rand::thread_rng().fill_bytes(&mut raw);
            // 12 hex chars, grouped for readability: "abcd-ef12-3456"
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            let code = format!("{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12]);
            let hash = crate::auth::ApiKeyService::hash(&code)?;
            plain.push(code);
            hashes.push(hash);
        }
        Ok((plain, hashes))
    }

    /// If `code` matches one of `hashes`, return the index of the consumed code
    /// so the caller can remove it. `None` if no match.
    pub fn consume(code: &str, hashes: &[String]) -> Option<usize> {
        let code = code.trim();
        hashes.iter().position(|h| crate::auth::ApiKeyService::verify(code, h))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use totp_rs::{Algorithm, Secret, TOTP};

    #[test]
    fn verify_accepts_current_code() {
        let secret = TotpService::generate_secret();
        let bytes = Secret::Encoded(secret.clone()).to_bytes().unwrap();
        let t = TOTP::new(Algorithm::SHA1, DIGITS, SKEW, STEP, bytes, None, "me".into()).unwrap();
        let code = t.generate_current().unwrap();
        assert!(TotpService::verify(&secret, &code, "me"));
    }

    #[test]
    fn verify_rejects_wrong_code() {
        let secret = TotpService::generate_secret();
        assert!(!TotpService::verify(&secret, "000000", "me"));
        assert!(!TotpService::verify(&secret, "not-a-code", "me"));
    }

    #[test]
    fn provisioning_uri_has_issuer_and_secret() {
        let secret = TotpService::generate_secret();
        let uri = TotpService::provisioning_uri(&secret, "me@example.com").unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("issuer=secretd"));
        assert!(uri.contains(&format!("secret={secret}")));
    }

    #[test]
    fn backup_codes_roundtrip_and_single_use() {
        let (plain, hashes) = BackupCodes::generate().unwrap();
        assert_eq!(plain.len(), BackupCodes::COUNT);
        let idx = BackupCodes::consume(&plain[3], &hashes).expect("code should match");
        assert_eq!(idx, 3);
        assert!(BackupCodes::consume("wrong-code-000", &hashes).is_none());
    }
}
