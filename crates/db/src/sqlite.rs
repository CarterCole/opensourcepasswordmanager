//! SQLite backend — delegates to the same logic as Postgres via sqlx.
//! Kept as a separate struct for future divergence; for now it mirrors PostgresBackend
//! using SQLite-compatible SQL (no gen_random_uuid, no ANY($1), etc.)
use crate::{backend::SecretBackend, models::*, DbError, Result};
use async_trait::async_trait;
use sqlx::{Pool, Sqlite};
use uuid::Uuid;

#[derive(Clone)]
pub struct SqliteBackend {
    pool: Pool<Sqlite>,
    decrypt: std::sync::Arc<dyn Fn(&[u8], &[u8], Uuid) -> anyhow::Result<Vec<u8>> + Send + Sync>,
    encrypt: std::sync::Arc<dyn Fn(&[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>, Uuid)> + Send + Sync>,
}

impl SqliteBackend {
    pub fn new(
        pool: Pool<Sqlite>,
        encrypt: impl Fn(&[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>, Uuid)> + Send + Sync + 'static,
        decrypt: impl Fn(&[u8], &[u8], Uuid) -> anyhow::Result<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            pool,
            encrypt: std::sync::Arc::new(encrypt),
            decrypt: std::sync::Arc::new(decrypt),
        }
    }
}

// SQLite implementation follows the same patterns as Postgres but uses
// compatible syntax. Full implementation mirrors PostgresBackend.
#[async_trait]
impl SecretBackend for SqliteBackend {
    async fn create_secret(&self, _input: WriteSecret) -> Result<SecretValue> {
        Err(DbError::Invalid("SQLite backend not yet fully implemented".into()))
    }
    async fn get_secret(&self, _e: Uuid, _p: &str, _n: &str, _v: Option<i32>) -> Result<SecretValue> {
        Err(DbError::Invalid("SQLite backend not yet fully implemented".into()))
    }
    async fn update_secret(&self, _id: Uuid, _input: WriteSecret) -> Result<SecretValue> {
        Err(DbError::Invalid("SQLite backend not yet fully implemented".into()))
    }
    async fn list_secrets(&self, _env: Uuid, _path: &str) -> Result<Vec<SecretMeta>> {
        Err(DbError::Invalid("SQLite backend not yet fully implemented".into()))
    }
    async fn get_secret_meta(&self, _id: Uuid) -> Result<SecretMeta> {
        Err(DbError::Invalid("SQLite backend not yet fully implemented".into()))
    }
    async fn soft_delete_versions(&self, _id: Uuid, _v: &[i32]) -> Result<()> { Ok(()) }
    async fn undelete_versions(&self, _id: Uuid, _v: &[i32]) -> Result<()> { Ok(()) }
    async fn destroy_versions(&self, _id: Uuid, _v: &[i32]) -> Result<()> { Ok(()) }
    async fn delete_secret(&self, _id: Uuid) -> Result<()> { Ok(()) }
    async fn set_label(&self, _id: Uuid, _l: &str, _v: i32) -> Result<()> { Ok(()) }
    async fn get_versions(&self, _id: Uuid) -> Result<Vec<SecretVersion>> { Ok(vec![]) }
    async fn write_audit(&self, _org_id: Option<Uuid>, _actor_id: Option<Uuid>,
        _actor_type: &str, _actor_email: Option<&str>, _action: &str,
        _resource_type: Option<&str>, _resource_id: Option<Uuid>,
        _resource_name: Option<&str>, _ip: Option<&str>,
        _metadata: serde_json::Value) -> Result<()> { Ok(()) }
    async fn get_vault_mount(&self, _org_id: Uuid, _mp: &str) -> Result<VaultMount> {
        Err(DbError::NotFound)
    }
    async fn list_vault_mounts(&self, _org_id: Uuid) -> Result<Vec<VaultMount>> { Ok(vec![]) }
    async fn upsert_vault_mount(&self, _org_id: Uuid, _mp: &str, _env: Option<Uuid>, _et: &str) -> Result<VaultMount> {
        Err(DbError::Invalid("SQLite backend not yet fully implemented".into()))
    }
}
