//! Envelope encryption: AES-256-GCM per-secret DEK wrapped by a master KEK.
//!
//! `encrypted_dek` blob layout: [12-byte kek_nonce][AES-GCM(kek, dek)]
//! `encrypted_value` is raw AES-GCM ciphertext; nonce lives in the `nonce` column.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use crate::db::EncryptResult;
use uuid::Uuid;

pub struct CryptoEngine {
    kek_id: Uuid,
    kek: [u8; 32],
}

impl CryptoEngine {
    /// Load from environment: `SECRETD_KEK_ID` (UUID) and `SECRETD_KEK` (base64, 32 bytes).
    pub fn from_env() -> Result<Self> {
        let kek_id = Uuid::parse_str(
            &std::env::var("SECRETD_KEK_ID").context("SECRETD_KEK_ID not set")?,
        )
        .context("invalid SECRETD_KEK_ID")?;

        let kek_bytes = B64
            .decode(std::env::var("SECRETD_KEK").context("SECRETD_KEK not set")?)
            .context("invalid base64 SECRETD_KEK")?;

        if kek_bytes.len() != 32 {
            bail!("SECRETD_KEK must decode to exactly 32 bytes");
        }
        let mut kek = [0u8; 32];
        kek.copy_from_slice(&kek_bytes);
        Ok(Self { kek_id, kek })
    }

    /// Generate a random KEK. Used by `secretd generate-kek`.
    pub fn generate_kek() -> (Uuid, [u8; 32]) {
        use rand::RngCore;
        let id = Uuid::new_v4();
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        (id, key)
    }

    pub fn kek_id(&self) -> Uuid {
        self.kek_id
    }

    /// Encrypt `plaintext`. Returns everything the DB layer needs to persist atomically.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptResult> {
        // Fresh DEK
        let dek_raw = Aes256Gcm::generate_key(OsRng);
        let data_nonce = Aes256Gcm::generate_nonce(OsRng);
        let ciphertext = Aes256Gcm::new(&dek_raw)
            .encrypt(&data_nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;

        // Wrap DEK with KEK
        let kek_nonce = Aes256Gcm::generate_nonce(OsRng);
        let wrapped_dek = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.kek))
            .encrypt(&kek_nonce, dek_raw.as_slice())
            .map_err(|e| anyhow::anyhow!("wrap dek: {e}"))?;

        // encrypted_dek blob = kek_nonce || wrapped_dek
        let mut encrypted_dek = kek_nonce.to_vec();
        encrypted_dek.extend_from_slice(&wrapped_dek);

        Ok(EncryptResult {
            ciphertext,
            nonce: data_nonce.to_vec(),
            dek_id: Uuid::new_v4(),
            kek_version_id: self.kek_id,
            encrypted_dek,
        })
    }

    /// Decrypt using the stored DEK blob.
    /// `encrypted_dek_blob` = the `encrypted_dek` column value from `data_encryption_keys`.
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        data_nonce: &[u8],
        encrypted_dek_blob: &[u8],
    ) -> Result<Vec<u8>> {
        if encrypted_dek_blob.len() < 12 {
            bail!("encrypted_dek_blob too short");
        }
        let (kek_nonce_bytes, wrapped_dek) = encrypted_dek_blob.split_at(12);

        let dek_bytes = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.kek))
            .decrypt(Nonce::from_slice(kek_nonce_bytes), wrapped_dek)
            .map_err(|_| anyhow::anyhow!("failed to unwrap DEK — wrong key or corrupted data"))?;

        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&dek_bytes))
            .decrypt(Nonce::from_slice(data_nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("failed to decrypt value"))
    }

    /// Directly encrypt a small value under the KEK (no per-value DEK). Returns a
    /// self-contained blob `[12-byte nonce][AES-256-GCM ciphertext]`, suitable for
    /// single-column storage of config-sized secrets such as a TOTP seed.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        let ciphertext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.kek))
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("seal: {e}"))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Inverse of [`seal`]. Input is `[12-byte nonce][ciphertext]`.
    pub fn open(&self, blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < 12 {
            bail!("sealed blob too short");
        }
        let (nonce, ciphertext) = blob.split_at(12);
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.kek))
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("failed to open sealed blob — wrong key or corrupted data"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    fn test_engine() -> CryptoEngine {
        std::env::set_var("SECRETD_KEK_ID", "00000000-0000-0000-0000-000000000099");
        std::env::set_var("SECRETD_KEK", B64.encode([42u8; 32]));
        CryptoEngine::from_env().unwrap()
    }

    #[test]
    fn roundtrip_short() {
        let e = test_engine();
        let ct = e.encrypt(b"hello world").unwrap();
        let pt = e.decrypt(&ct.ciphertext, &ct.nonce, &ct.encrypted_dek).unwrap();
        assert_eq!(pt, b"hello world");
    }

    #[test]
    fn roundtrip_empty() {
        let e = test_engine();
        let ct = e.encrypt(b"").unwrap();
        let pt = e.decrypt(&ct.ciphertext, &ct.nonce, &ct.encrypted_dek).unwrap();
        assert_eq!(pt, b"");
    }

    #[test]
    fn roundtrip_large() {
        let e = test_engine();
        let plaintext = vec![0xABu8; 1024 * 1024]; // 1 MB
        let ct = e.encrypt(&plaintext).unwrap();
        let pt = e.decrypt(&ct.ciphertext, &ct.nonce, &ct.encrypted_dek).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn different_plaintext_gives_different_ciphertext() {
        let e = test_engine();
        let ct1 = e.encrypt(b"hello world").unwrap();
        let ct2 = e.encrypt(b"hello world").unwrap();
        // Each encryption uses a fresh nonce, so ciphertexts must differ
        assert_ne!(ct1.ciphertext, ct2.ciphertext);
        assert_ne!(ct1.nonce, ct2.nonce);
    }

    #[test]
    fn tampered_ciphertext_fails_decrypt() {
        let e = test_engine();
        let ct = e.encrypt(b"hello world").unwrap();
        let mut tampered = ct.ciphertext.clone();
        tampered[0] ^= 0xFF; // flip bits in the first byte
        let result = e.decrypt(&tampered, &ct.nonce, &ct.encrypted_dek);
        assert!(result.is_err(), "tampered ciphertext should fail to decrypt");
    }

    #[test]
    fn seal_open_roundtrip() {
        let e = test_engine();
        let blob = e.seal(b"JBSWY3DPEHPK3PXP").unwrap();
        assert_ne!(blob, b"JBSWY3DPEHPK3PXP");
        let out = e.open(&blob).unwrap();
        assert_eq!(out, b"JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn open_rejects_tampered_blob() {
        let e = test_engine();
        let mut blob = e.seal(b"totp-seed").unwrap();
        let n = blob.len() - 1;
        blob[n] ^= 0xFF;
        assert!(e.open(&blob).is_err());
    }

    #[test]
    fn wrong_kek_fails_decrypt() {
        let e = test_engine();
        let ct = e.encrypt(b"secret").unwrap();

        // Build a second engine with a different KEK
        std::env::set_var("SECRETD_KEK", B64.encode([99u8; 32]));
        let e2 = CryptoEngine::from_env().unwrap();
        // Restore correct KEK
        std::env::set_var("SECRETD_KEK", B64.encode([42u8; 32]));

        let result = e2.decrypt(&ct.ciphertext, &ct.nonce, &ct.encrypted_dek);
        assert!(result.is_err(), "wrong KEK should fail to decrypt");
    }
}
