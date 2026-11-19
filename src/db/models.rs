use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Uuid,
    pub org_id: Uuid,
    pub name: String,
    pub slug: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub id: Uuid,
    pub project_id: Uuid,
    pub name: String,
    pub slug: String,
    pub position: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KekVersion {
    pub id: Uuid,
    pub provider: String,
    pub encrypted_kek: Option<Vec<u8>>,
    pub provider_key_id: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataEncryptionKey {
    pub id: Uuid,
    pub kek_version_id: Uuid,
    pub encrypted_dek: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: Uuid,
    pub environment_id: Uuid,
    pub name: String,
    pub path: String,
    pub description: Option<String>,
    pub tags: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub id: Uuid,
    pub secret_id: Uuid,
    pub version_num: i32,
    pub dek_id: Uuid,
    pub encrypted_value: Vec<u8>,
    pub nonce: Vec<u8>,
    pub value_type: String,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub destroyed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretLabel {
    pub secret_id: Uuid,
    pub label: String,
    pub version_num: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub org_id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub password_hash: Option<String>,
    pub totp_secret_encrypted: Option<Vec<u8>>,
    pub totp_enrolled_at: Option<DateTime<Utc>>,
    pub backup_codes_hash: Option<serde_json::Value>,
    pub webauthn_credentials: serde_json::Value,
    pub is_active: bool,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub org_id: Option<Uuid>,
    pub name: String,
    pub permissions: serde_json::Value,
    pub is_builtin: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub id: Uuid,
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub scope_type: String,
    pub scope_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub created_by: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub org_id: Uuid,
    pub owner_id: Uuid,
    pub owner_type: String,
    pub name: String,
    pub key_prefix: String,
    pub key_hash: String,
    pub scopes: serde_json::Value,
    pub role_id: Option<Uuid>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: i64,
    pub org_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub actor_type: Option<String>,
    pub actor_email: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub resource_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub metadata: serde_json::Value,
    pub ts: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMount {
    pub id: Uuid,
    pub org_id: Uuid,
    /// Owning namespace path ("" = root).
    pub namespace: String,
    pub mount_path: String,
    pub environment_id: Option<Uuid>,
    pub engine_type: String,
    pub config: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// An isolated sub-tree (OpenBao/Vault-style). `path` is absolute, e.g. "team-a/prod".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    pub id: Uuid,
    pub org_id: Uuid,
    pub path: String,
    pub created_at: DateTime<Utc>,
}

/// Resolved secret value (decrypted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretValue {
    pub secret: Secret,
    pub version: SecretVersion,
    pub plaintext: Vec<u8>,
    pub value_type: String,
}

/// Lightweight metadata returned by list operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMeta {
    pub id: Uuid,
    pub name: String,
    pub path: String,
    pub current_version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub tags: serde_json::Value,
}

/// Input for creating/updating a secret
#[derive(Debug, Clone)]
pub struct WriteSecret {
    pub environment_id: Uuid,
    pub name: String,
    pub path: String,
    pub plaintext: Vec<u8>,
    pub value_type: String,
    pub description: Option<String>,
    pub tags: Option<serde_json::Value>,
    pub actor_id: Option<Uuid>,
}
