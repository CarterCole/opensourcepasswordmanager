//! Vault KV v2 wire types (exact JSON shapes the Vault API uses).
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Read response ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct VaultResponse<T: Serialize> {
    pub request_id: String,
    pub lease_id: String,
    pub renewable: bool,
    pub lease_duration: u64,
    pub data: T,
    pub wrap_info: Option<()>,
    pub warnings: Option<Vec<String>>,
    pub auth: Option<()>,
    pub mount_type: String,
}

impl<T: Serialize> VaultResponse<T> {
    pub fn kv(data: T) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            lease_id: String::new(),
            renewable: false,
            lease_duration: 0,
            data,
            wrap_info: None,
            warnings: None,
            auth: None,
            mount_type: "kv".into(),
        }
    }
}

// ── KV v2 data read ──────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct KvData {
    pub data: HashMap<String, serde_json::Value>,
    pub metadata: KvVersionMeta,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct KvVersionMeta {
    pub created_time: DateTime<Utc>,
    pub custom_metadata: Option<HashMap<String, String>>,
    pub deletion_time: String,
    pub destroyed: bool,
    pub version: i32,
}

// ── KV v2 write ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct KvWriteRequest {
    #[serde(default)]
    pub options: KvWriteOptions,
    pub data: HashMap<String, serde_json::Value>,
}

#[derive(Deserialize, Default)]
pub struct KvWriteOptions {
    /// check-and-set: if set, write only succeeds if current version == cas
    pub cas: Option<i32>,
}

#[derive(Serialize)]
pub struct KvWriteResponse {
    pub created_time: DateTime<Utc>,
    pub custom_metadata: Option<HashMap<String, String>>,
    pub deletion_time: String,
    pub destroyed: bool,
    pub version: i32,
}

// ── Metadata read ────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct KvMetadataResponse {
    pub cas_required: bool,
    pub created_time: DateTime<Utc>,
    pub current_version: i32,
    pub custom_metadata: Option<HashMap<String, String>>,
    pub delete_version_after: String,
    pub max_versions: i32,
    pub oldest_version: i32,
    pub updated_time: DateTime<Utc>,
    pub versions: HashMap<String, KvVersionMeta>,
}

// ── Metadata write ───────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
pub struct KvMetadataWriteRequest {
    pub cas_required: Option<bool>,
    pub delete_version_after: Option<String>,
    pub max_versions: Option<i32>,
    pub custom_metadata: Option<HashMap<String, String>>,
}

// ── Version actions ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VersionsRequest {
    pub versions: Vec<i32>,
}

// ── List ─────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ListData {
    pub keys: Vec<String>,
}

// ── Auth ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UserpassLoginRequest {
    pub password: String,
}

#[derive(Deserialize)]
pub struct TokenCreateRequest {
    #[serde(default)]
    pub policies: Vec<String>,
    pub ttl: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub request_id: String,
    pub auth: AuthData,
}

#[derive(Serialize)]
pub struct AuthData {
    pub client_token: String,
    pub accessor: String,
    pub policies: Vec<String>,
    pub token_policies: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub lease_duration: u64,
    pub renewable: bool,
    pub entity_id: String,
    pub token_type: String,
    pub orphan: bool,
    pub num_uses: u32,
}

// ── sys/health ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct HealthResponse {
    pub initialized: bool,
    pub sealed: bool,
    pub standby: bool,
    pub performance_standby: bool,
    pub replication_performance_mode: String,
    pub replication_dr_mode: String,
    pub server_time_utc: i64,
    pub version: String,
    pub cluster_name: String,
    pub cluster_id: String,
}

// ── sys/mounts ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct MountsResponse {
    pub request_id: String,
    pub data: HashMap<String, MountInfo>,
}

#[derive(Serialize)]
pub struct MountInfo {
    pub accessor: String,
    #[serde(rename = "type")]
    pub engine_type: String,
    pub description: String,
    pub local: bool,
    pub seal_wrap: bool,
    pub options: HashMap<String, String>,
}
