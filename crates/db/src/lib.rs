pub mod models;
pub mod backend;
pub mod postgres;
pub mod sqlite;

pub use backend::SecretBackend;
pub use models::*;

use sqlx::{Pool, Postgres, Sqlite};

#[derive(Clone)]
pub enum DbPool {
    Postgres(Pool<Postgres>),
    Sqlite(Pool<Sqlite>),
}

/// Everything the DB layer needs from a single encrypt call.
/// Returned by the encrypt closure injected into backends.
pub struct EncryptResult {
    /// AES-GCM ciphertext
    pub ciphertext: Vec<u8>,
    /// 12-byte GCM nonce for the data
    pub nonce: Vec<u8>,
    /// UUID to use as the new DEK row's primary key
    pub dek_id: uuid::Uuid,
    /// UUID of the KEK version that wrapped this DEK
    pub kek_version_id: uuid::Uuid,
    /// The wrapped DEK blob to store in data_encryption_keys
    pub encrypted_dek: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    #[error("database error: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("not found")]
    NotFound,
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("invalid: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, DbError>;
