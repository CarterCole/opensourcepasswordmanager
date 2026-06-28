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
}
