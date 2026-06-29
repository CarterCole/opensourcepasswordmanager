use crate::db::{models::*, Result};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait SecretBackend: Send + Sync {
    // ── Secrets ──────────────────────────────────────────────────────────────

    async fn create_secret(&self, input: WriteSecret) -> Result<SecretValue>;

    async fn get_secret(
        &self,
        environment_id: Uuid,
        path: &str,
        name: &str,
        version: Option<i32>,
    ) -> Result<SecretValue>;

    async fn update_secret(&self, secret_id: Uuid, input: WriteSecret) -> Result<SecretValue>;

    async fn list_secrets(
        &self,
        environment_id: Uuid,
        path: &str,
    ) -> Result<Vec<SecretMeta>>;

    async fn get_secret_meta(&self, secret_id: Uuid) -> Result<SecretMeta>;

    async fn soft_delete_versions(
        &self,
        secret_id: Uuid,
        versions: &[i32],
    ) -> Result<()>;

    async fn undelete_versions(&self, secret_id: Uuid, versions: &[i32]) -> Result<()>;

    async fn destroy_versions(&self, secret_id: Uuid, versions: &[i32]) -> Result<()>;

    async fn delete_secret(&self, secret_id: Uuid) -> Result<()>;

    // ── Labels ───────────────────────────────────────────────────────────────

    async fn set_label(
        &self,
        secret_id: Uuid,
        label: &str,
        version_num: i32,
    ) -> Result<()>;

    async fn get_versions(&self, secret_id: Uuid) -> Result<Vec<SecretVersion>>;

    // ── Audit ────────────────────────────────────────────────────────────────

    async fn write_audit(
        &self,
        org_id: Option<Uuid>,
        actor_id: Option<Uuid>,
        actor_type: &str,
        actor_email: Option<&str>,
        action: &str,
        resource_type: Option<&str>,
        resource_id: Option<Uuid>,
        resource_name: Option<&str>,
        ip: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<()>;

    // ── Vault mounts ─────────────────────────────────────────────────────────

    async fn get_vault_mount(&self, org_id: Uuid, mount_path: &str) -> Result<VaultMount>;

    async fn list_vault_mounts(&self, org_id: Uuid) -> Result<Vec<VaultMount>>;

    async fn upsert_vault_mount(
        &self,
        org_id: Uuid,
        mount_path: &str,
        environment_id: Option<Uuid>,
        engine_type: &str,
    ) -> Result<VaultMount>;

    // ── Tags ─────────────────────────────────────────────────────────────────

    /// Merge/replace the tags JSON on a secret without creating a new version.
    async fn update_secret_tags(&self, secret_id: Uuid, tags: serde_json::Value) -> Result<()>;
}
