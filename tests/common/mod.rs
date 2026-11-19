//! Shared test helpers: in-memory backend, app-state factory, HTTP call helpers.
#![allow(dead_code)]

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use opensourcepasswordmanager::{
    core::{CryptoEngine, SecretStore},
    db::{
        backend::SecretBackend,
        models::{
            AuditLog, Namespace, Secret, SecretLabel, SecretMeta, SecretValue, SecretVersion, VaultMount,
            WriteSecret,
        },
        DbError, Result as DbResult,
    },
};

// ── In-memory secret store ──────────────────────────────────────────────────

#[derive(Default)]
struct MemStore {
    /// primary index: (environment_id, path, name) → list of versions in order
    secrets: HashMap<(Uuid, String, String), (Secret, Vec<SecretVersion>)>,
    /// secondary index: secret_id → (environment_id, path, name)
    by_id: HashMap<Uuid, (Uuid, String, String)>,
    /// vault mounts
    mounts: Vec<VaultMount>,
    namespaces: Vec<Namespace>,
}

#[derive(Clone, Default)]
pub struct MemBackend {
    inner: Arc<Mutex<MemStore>>,
}

impl MemBackend {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SecretBackend for MemBackend {
    async fn create_secret(&self, input: WriteSecret) -> DbResult<SecretValue> {
        let mut store = self.inner.lock().unwrap();
        let key = (input.environment_id, input.path.clone(), input.name.clone());

        // If already exists (by path/name), treat as conflict
        if store.secrets.contains_key(&key) {
            return Err(DbError::Conflict("secret already exists".into()));
        }

        let secret_id = Uuid::new_v4();
        let now = Utc::now();
        let secret = Secret {
            id: secret_id,
            environment_id: input.environment_id,
            name: input.name.clone(),
            path: input.path.clone(),
            description: input.description.clone(),
            tags: input.tags.clone().unwrap_or(serde_json::Value::Object(Default::default())),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let version = SecretVersion {
            id: Uuid::new_v4(),
            secret_id,
            version_num: 1,
            dek_id: Uuid::new_v4(),
            encrypted_value: input.plaintext.clone(),
            nonce: vec![],
            value_type: input.value_type.clone(),
            created_at: now,
            created_by: input.actor_id,
            deleted_at: None,
            destroyed_at: None,
        };

        let sv = SecretValue {
            secret: secret.clone(),
            version: version.clone(),
            plaintext: input.plaintext.clone(),
            value_type: input.value_type.clone(),
        };

        store.by_id.insert(secret_id, key.clone());
        store.secrets.insert(key, (secret, vec![version]));
        Ok(sv)
    }

    async fn get_secret(
        &self,
        environment_id: Uuid,
        path: &str,
        name: &str,
        version: Option<i32>,
    ) -> DbResult<SecretValue> {
        let store = self.inner.lock().unwrap();
        let key = (environment_id, path.to_string(), name.to_string());
        let (secret, versions) = store.secrets.get(&key).ok_or(DbError::NotFound)?;
        // A secret that has been hard-deleted (secret-level delete) is not found
        if secret.deleted_at.is_some() {
            return Err(DbError::NotFound);
        }

        let ver = match version {
            Some(v) => versions
                .iter()
                .find(|sv| sv.version_num == v)
                .ok_or(DbError::NotFound)?,
            None => versions.last().ok_or(DbError::NotFound)?,
        };

        Ok(SecretValue {
            secret: secret.clone(),
            version: ver.clone(),
            plaintext: ver.encrypted_value.clone(), // stored as plaintext in mock
            value_type: ver.value_type.clone(),
        })
    }

    async fn update_secret(&self, secret_id: Uuid, input: WriteSecret) -> DbResult<SecretValue> {
        let mut store = self.inner.lock().unwrap();
        let key = store.by_id.get(&secret_id).cloned().ok_or(DbError::NotFound)?;

        let (secret, versions) = store.secrets.get_mut(&key).ok_or(DbError::NotFound)?;

        let now = Utc::now();
        let next_version = versions.iter().map(|v| v.version_num).max().unwrap_or(0) + 1;

        let version = SecretVersion {
            id: Uuid::new_v4(),
            secret_id,
            version_num: next_version,
            dek_id: Uuid::new_v4(),
            encrypted_value: input.plaintext.clone(),
            nonce: vec![],
            value_type: input.value_type.clone(),
            created_at: now,
            created_by: input.actor_id,
            deleted_at: None,
            destroyed_at: None,
        };

        secret.updated_at = now;
        versions.push(version.clone());

        Ok(SecretValue {
            secret: secret.clone(),
            version,
            plaintext: input.plaintext,
            value_type: input.value_type,
        })
    }

    async fn list_secrets(&self, environment_id: Uuid, path: &str) -> DbResult<Vec<SecretMeta>> {
        let store = self.inner.lock().unwrap();
        let metas: Vec<SecretMeta> = store
            .secrets
            .iter()
            .filter(|((eid, spath, _), (secret, _))| {
                *eid == environment_id
                    && (path == "/" || spath == path)
                    && secret.deleted_at.is_none()
            })
            .map(|(_, (secret, versions))| {
                let current = versions.iter().map(|v| v.version_num).max().unwrap_or(0);
                SecretMeta {
                    id: secret.id,
                    name: secret.name.clone(),
                    path: secret.path.clone(),
                    current_version: current,
                    created_at: secret.created_at,
                    updated_at: secret.updated_at,
                    deleted_at: secret.deleted_at,
                    tags: secret.tags.clone(),
                }
            })
            .collect();
        Ok(metas)
    }

    async fn get_secret_meta(&self, secret_id: Uuid) -> DbResult<SecretMeta> {
        let store = self.inner.lock().unwrap();
        let key = store.by_id.get(&secret_id).cloned().ok_or(DbError::NotFound)?;
        let (secret, versions) = store.secrets.get(&key).ok_or(DbError::NotFound)?;
        let current = versions.iter().map(|v| v.version_num).max().unwrap_or(0);
        Ok(SecretMeta {
            id: secret.id,
            name: secret.name.clone(),
            path: secret.path.clone(),
            current_version: current,
            created_at: secret.created_at,
            updated_at: secret.updated_at,
            deleted_at: secret.deleted_at,
            tags: secret.tags.clone(),
        })
    }

    async fn soft_delete_versions(&self, secret_id: Uuid, versions: &[i32]) -> DbResult<()> {
        let mut store = self.inner.lock().unwrap();
        let key = store.by_id.get(&secret_id).cloned().ok_or(DbError::NotFound)?;
        let (_, vers) = store.secrets.get_mut(&key).ok_or(DbError::NotFound)?;
        let now = Utc::now();
        for v in vers.iter_mut() {
            if versions.contains(&v.version_num) {
                v.deleted_at = Some(now);
            }
        }
        Ok(())
    }

    async fn undelete_versions(&self, secret_id: Uuid, versions: &[i32]) -> DbResult<()> {
        let mut store = self.inner.lock().unwrap();
        let key = store.by_id.get(&secret_id).cloned().ok_or(DbError::NotFound)?;
        let (_, vers) = store.secrets.get_mut(&key).ok_or(DbError::NotFound)?;
        for v in vers.iter_mut() {
            if versions.contains(&v.version_num) {
                v.deleted_at = None;
            }
        }
        Ok(())
    }

    async fn destroy_versions(&self, secret_id: Uuid, versions: &[i32]) -> DbResult<()> {
        let mut store = self.inner.lock().unwrap();
        let key = store.by_id.get(&secret_id).cloned().ok_or(DbError::NotFound)?;
        let (_, vers) = store.secrets.get_mut(&key).ok_or(DbError::NotFound)?;
        let now = Utc::now();
        for v in vers.iter_mut() {
            if versions.contains(&v.version_num) {
                v.destroyed_at = Some(now);
                v.encrypted_value = vec![];
            }
        }
        Ok(())
    }

    async fn delete_secret(&self, secret_id: Uuid) -> DbResult<()> {
        let mut store = self.inner.lock().unwrap();
        let key = store.by_id.get(&secret_id).cloned().ok_or(DbError::NotFound)?;
        let (secret, _) = store.secrets.get_mut(&key).ok_or(DbError::NotFound)?;
        secret.deleted_at = Some(Utc::now());
        Ok(())
    }

    async fn update_secret_tags(&self, secret_id: Uuid, tags: serde_json::Value) -> DbResult<()> {
        let mut store = self.inner.lock().unwrap();
        let key = store.by_id.get(&secret_id).cloned().ok_or(DbError::NotFound)?;
        let (secret, _) = store.secrets.get_mut(&key).ok_or(DbError::NotFound)?;
        secret.tags = tags;
        Ok(())
    }

    async fn update_secret_description(&self, secret_id: Uuid, description: String) -> DbResult<()> {
        let mut store = self.inner.lock().unwrap();
        let key = store.by_id.get(&secret_id).cloned().ok_or(DbError::NotFound)?;
        let (secret, _) = store.secrets.get_mut(&key).ok_or(DbError::NotFound)?;
        secret.description = Some(description);
        secret.updated_at = Utc::now();
        Ok(())
    }

    async fn restore_secret(&self, environment_id: Uuid, path: &str, name: &str) -> DbResult<SecretMeta> {
        let mut store = self.inner.lock().unwrap();
        let key = (environment_id, path.to_string(), name.to_string());
        let (secret, versions) = store.secrets.get_mut(&key).ok_or(DbError::NotFound)?;
        if secret.deleted_at.is_none() {
            return Err(DbError::NotFound);
        }
        secret.deleted_at = None;
        secret.updated_at = Utc::now();
        let current = versions.iter().map(|v| v.version_num).max().unwrap_or(0);
        Ok(SecretMeta {
            id: secret.id,
            name: secret.name.clone(),
            path: secret.path.clone(),
            current_version: current,
            created_at: secret.created_at,
            updated_at: secret.updated_at,
            deleted_at: None,
            tags: secret.tags.clone(),
        })
    }

    async fn set_label(&self, _secret_id: Uuid, _label: &str, _version_num: i32) -> DbResult<()> {
        Ok(())
    }

    async fn get_versions(&self, secret_id: Uuid) -> DbResult<Vec<SecretVersion>> {
        let store = self.inner.lock().unwrap();
        let key = store.by_id.get(&secret_id).cloned().ok_or(DbError::NotFound)?;
        let (_, versions) = store.secrets.get(&key).ok_or(DbError::NotFound)?;
        Ok(versions.clone())
    }

    async fn write_audit(
        &self,
        _org_id: Option<Uuid>,
        _actor_id: Option<Uuid>,
        _actor_type: &str,
        _actor_email: Option<&str>,
        _action: &str,
        _resource_type: Option<&str>,
        _resource_id: Option<Uuid>,
        _resource_name: Option<&str>,
        _ip: Option<&str>,
        _metadata: serde_json::Value,
    ) -> DbResult<()> {
        Ok(())
    }

    async fn get_vault_mount(&self, org_id: Uuid, namespace: &str, mount_path: &str) -> DbResult<VaultMount> {
        let store = self.inner.lock().unwrap();
        store.mounts.iter()
            .find(|m| m.org_id == org_id && m.namespace == namespace && m.mount_path == mount_path)
            .cloned()
            .ok_or(DbError::NotFound)
    }

    async fn list_vault_mounts(&self, org_id: Uuid, namespace: &str) -> DbResult<Vec<VaultMount>> {
        let store = self.inner.lock().unwrap();
        Ok(store.mounts.iter()
            .filter(|m| m.org_id == org_id && m.namespace == namespace)
            .cloned().collect())
    }

    async fn upsert_vault_mount(
        &self,
        org_id: Uuid,
        namespace: &str,
        mount_path: &str,
        environment_id: Option<Uuid>,
        engine_type: &str,
    ) -> DbResult<VaultMount> {
        let mut store = self.inner.lock().unwrap();
        store.mounts.retain(|m| !(m.org_id == org_id && m.namespace == namespace && m.mount_path == mount_path));
        let m = VaultMount {
            id: Uuid::new_v4(),
            org_id,
            namespace: namespace.to_string(),
            mount_path: mount_path.to_string(),
            environment_id,
            engine_type: engine_type.to_string(),
            config: serde_json::Value::Object(Default::default()),
            created_at: Utc::now(),
        };
        store.mounts.push(m.clone());
        Ok(m)
    }

    async fn create_namespace(&self, org_id: Uuid, path: &str) -> DbResult<Namespace> {
        let mut store = self.inner.lock().unwrap();
        if let Some((parent, _)) = path.rsplit_once('/') {
            if !store.namespaces.iter().any(|n| n.org_id == org_id && n.path == parent) {
                return Err(DbError::NotFound);
            }
        }
        if store.namespaces.iter().any(|n| n.org_id == org_id && n.path == path) {
            return Err(DbError::Conflict("namespace already exists".into()));
        }
        let ns = Namespace { id: Uuid::new_v4(), org_id, path: path.to_string(), created_at: Utc::now() };
        store.namespaces.push(ns.clone());
        store.mounts.push(VaultMount {
            id: Uuid::new_v4(),
            org_id,
            namespace: path.to_string(),
            mount_path: "secret".into(),
            environment_id: Some(Uuid::new_v4()),
            engine_type: "kv-v2".into(),
            config: serde_json::Value::Object(Default::default()),
            created_at: Utc::now(),
        });
        Ok(ns)
    }

    async fn get_namespace(&self, org_id: Uuid, path: &str) -> DbResult<Namespace> {
        let store = self.inner.lock().unwrap();
        store.namespaces.iter().find(|n| n.org_id == org_id && n.path == path)
            .cloned().ok_or(DbError::NotFound)
    }

    async fn list_namespaces(&self, org_id: Uuid) -> DbResult<Vec<Namespace>> {
        let store = self.inner.lock().unwrap();
        let mut v: Vec<_> = store.namespaces.iter().filter(|n| n.org_id == org_id).cloned().collect();
        v.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(v)
    }

    async fn delete_namespace(&self, org_id: Uuid, path: &str) -> DbResult<()> {
        let mut store = self.inner.lock().unwrap();
        let prefix = format!("{path}/");
        if store.namespaces.iter().any(|n| n.org_id == org_id && n.path.starts_with(&prefix)) {
            return Err(DbError::Conflict("namespace has child namespaces".into()));
        }
        let env_ids: Vec<Uuid> = store.mounts.iter()
            .filter(|m| m.org_id == org_id && m.namespace == path)
            .filter_map(|m| m.environment_id).collect();
        let has_secrets = store.secrets.iter()
            .any(|((env, _, _), (s, _))| env_ids.contains(env) && s.deleted_at.is_none());
        if has_secrets {
            return Err(DbError::Conflict("namespace is not empty".into()));
        }
        let before = store.namespaces.len();
        store.namespaces.retain(|n| !(n.org_id == org_id && n.path == path));
        if store.namespaces.len() == before {
            return Err(DbError::NotFound);
        }
        store.mounts.retain(|m| !(m.org_id == org_id && m.namespace == path));
        Ok(())
    }
}

// ── AppState factory ────────────────────────────────────────────────────────

pub fn test_kek_env() {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    std::env::set_var("SECRETD_KEK_ID", "00000000-0000-0000-0000-000000000099");
    std::env::set_var("SECRETD_KEK", B64.encode([1u8; 32]));
}

pub fn make_app_state() -> opensourcepasswordmanager::api::common::AppState {
    test_kek_env();
    let backend: Arc<dyn SecretBackend> = Arc::new(MemBackend::new());
    let crypto = Arc::new(CryptoEngine::from_env().unwrap());
    let store = Arc::new(SecretStore::new(backend.clone(), crypto));
    let sessions = Arc::new(opensourcepasswordmanager::auth::SessionService::from_secret("test-jwt-secret"));
    opensourcepasswordmanager::api::common::AppState {
        store,
        db: backend,
        dev_root_token: Some("test-token".into()),
        default_org_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        default_env_id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
        pg_pool: None,
        sessions,
    }
}

pub fn make_vault_state() -> opensourcepasswordmanager::api::vault::auth::VaultState {
    test_kek_env();
    let backend: Arc<dyn SecretBackend> = Arc::new(MemBackend::new());
    let crypto = Arc::new(CryptoEngine::from_env().unwrap());
    let store = Arc::new(SecretStore::new(backend.clone(), crypto));
    let sessions = Arc::new(opensourcepasswordmanager::auth::SessionService::from_secret("test-jwt-secret"));
    opensourcepasswordmanager::api::vault::auth::VaultState {
        store,
        db: backend,
        dev_root_token: Some("test-token".into()),
        default_org_id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
        default_env_id: Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
        pg_pool: None,
        sessions,
    }
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

pub async fn call(
    app: axum::Router,
    req: axum::http::Request<axum::body::Body>,
) -> (axum::http::StatusCode, serde_json::Value) {
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body: serde_json::Value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, body)
}

pub fn json_req(
    method: &str,
    uri: &str,
    body: serde_json::Value,
) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .header("X-Vault-Token", "test-token")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

pub fn authed_req(
    method: &str,
    uri: &str,
    body: serde_json::Value,
) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .header("Authorization", "AWS4-HMAC-SHA256 Credential=test-token/20240101/us-east-1/secretsmanager/aws4_request")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}
