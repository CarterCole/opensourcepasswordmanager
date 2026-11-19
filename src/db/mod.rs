pub mod backend;
pub mod models;
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
pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub dek_id: uuid::Uuid,
    pub kek_version_id: uuid::Uuid,
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
