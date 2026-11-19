//! Vault KV v2 handlers — exact wire format per Vault/OpenBao spec.
use crate::api::vault::{
    auth::{VaultClaims, VaultState},
    error::VaultError,
    types::*,
};
use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

// Helper: map secret path from Vault convention ("/mount/data/foo/bar") to DB (env, path, name)
fn split_kv_path(raw: &str) -> (String, String) {
    // raw = "foo/bar/baz" → folder = "/foo/bar/", name = "baz"
    let parts: Vec<&str> = raw.splitn(100, '/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return ("/".into(), String::new());
    }
    if parts.len() == 1 {
        return ("/".into(), parts[0].to_string());
    }
    let name = parts.last().unwrap().to_string();
    let folder = format!("/{}/", parts[..parts.len() - 1].join("/"));
    (folder, name)
}

// ── sys/health ───────────────────────────────────────────────────────────────

pub async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        initialized: true,
        sealed: false,
        standby: false,
        performance_standby: false,
        replication_performance_mode: "disabled".into(),
        replication_dr_mode: "disabled".into(),
        server_time_utc: Utc::now().timestamp(),
        version: "1.15.0+secretd".into(),
        cluster_name: "secretd".into(),
        cluster_id: Uuid::new_v4().to_string(),
    })
}

// ── sys/mounts ───────────────────────────────────────────────────────────────

pub async fn list_mounts(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
) -> Response {
    let mounts = match state.db.list_vault_mounts(claims.org_id, &claims.namespace).await {
        Ok(m) => m,
        Err(e) => return VaultError::internal(e.to_string()),
    };

    let mut data: HashMap<String, MountInfo> = HashMap::new();
    for m in mounts {
        let path = format!("{}/", m.mount_path);
        data.insert(
            path.clone(),
            MountInfo {
                accessor: format!("kv_{}", &m.id.to_string()[..8]),
                engine_type: m.engine_type,
                description: String::new(),
                local: false,
                seal_wrap: false,
                options: {
                    let mut o = HashMap::new();
                    o.insert("version".into(), "2".into());
                    o
                },
            },
        );
    }

    Json(MountsResponse {
        request_id: Uuid::new_v4().to_string(),
        data,
    })
    .into_response()
}

// ── sys/namespaces ───────────────────────────────────────────────────────────

fn ns_json(ns: &crate::db::Namespace) -> Value {
    serde_json::json!({
        "id": ns.id.to_string().replace('-', "")[..5].to_string(),
        "path": format!("{}/", ns.path),
        "custom_metadata": {},
    })
}

/// Validate a namespace path relative to the request namespace; returns the absolute path.
fn abs_ns_path(claims: &VaultClaims, rel: &str) -> Result<String, Response> {
    let rel = crate::api::vault::auth::normalize_ns(rel);
    if rel.is_empty() {
        return Err(VaultError::bad_request("missing namespace path"));
    }
    for seg in rel.split('/') {
        let ok = seg.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            && seg != "."
            && seg != "..";
        if !ok {
            return Err(VaultError::bad_request(format!("invalid namespace name \"{seg}\"")));
        }
        if crate::api::vault::auth::RESERVED_NS_NAMES.contains(&seg) {
            return Err(VaultError::bad_request(format!("\"{seg}\" is a reserved name")));
        }
    }
    Ok(crate::api::vault::auth::join_ns(&claims.namespace, &rel))
}

fn is_direct_child(parent: &str, path: &str) -> bool {
    let rest = if parent.is_empty() {
        path
    } else {
        match path.strip_prefix(parent).and_then(|r| r.strip_prefix('/')) {
            Some(r) => r,
            None => return false,
        }
    };
    !rest.is_empty() && !rest.contains('/')
}

pub async fn ns_list(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
) -> Response {
    let all = match state.db.list_namespaces(claims.org_id).await {
        Ok(v) => v,
        Err(e) => return VaultError::internal(e.to_string()),
    };
    let children: Vec<_> = all.iter().filter(|n| is_direct_child(&claims.namespace, &n.path)).collect();
    if children.is_empty() {
        return VaultError::not_found();
    }
    let prefix_len = if claims.namespace.is_empty() { 0 } else { claims.namespace.len() + 1 };
    let mut keys = Vec::new();
    let mut key_info = serde_json::Map::new();
    for n in children {
        let key = format!("{}/", &n.path[prefix_len..]);
        key_info.insert(key.clone(), ns_json(n));
        keys.push(key);
    }
    Json(VaultResponse::kv(serde_json::json!({ "keys": keys, "key_info": key_info }))).into_response()
}

pub async fn ns_read(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path(rel): Path<String>,
) -> Response {
    let path = match abs_ns_path(&claims, &rel) {
        Ok(p) => p,
        Err(r) => return r,
    };
    match state.db.get_namespace(claims.org_id, &path).await {
        Ok(ns) => Json(VaultResponse::kv(ns_json(&ns))).into_response(),
        Err(crate::db::DbError::NotFound) => VaultError::not_found(),
        Err(e) => VaultError::internal(e.to_string()),
    }
}

pub async fn ns_create(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path(rel): Path<String>,
) -> Response {
    let path = match abs_ns_path(&claims, &rel) {
        Ok(p) => p,
        Err(r) => return r,
    };
    // Nested creation is relative to the request namespace; intermediate
    // namespaces must already exist (create_namespace checks the parent).
    match state.db.create_namespace(claims.org_id, &path).await {
        Ok(ns) => {
            let _ = state.db.write_audit(
                Some(claims.org_id), claims.user_id, "vault_token", None,
                "namespace.create", Some("namespace"), Some(ns.id), Some(&ns.path),
                None, serde_json::json!({}),
            ).await;
            Json(VaultResponse::kv(ns_json(&ns))).into_response()
        }
        Err(crate::db::DbError::Conflict(m)) => VaultError::bad_request(m),
        Err(crate::db::DbError::NotFound) => VaultError::resp(StatusCode::NOT_FOUND, "parent namespace not found"),
        Err(e) => VaultError::internal(e.to_string()),
    }
}

pub async fn ns_delete(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path(rel): Path<String>,
) -> Response {
    let path = match abs_ns_path(&claims, &rel) {
        Ok(p) => p,
        Err(r) => return r,
    };
    match state.db.delete_namespace(claims.org_id, &path).await {
        Ok(()) => {
            let _ = state.db.write_audit(
                Some(claims.org_id), claims.user_id, "vault_token", None,
                "namespace.delete", Some("namespace"), None, Some(&path),
                None, serde_json::json!({}),
            ).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(crate::db::DbError::Conflict(m)) => VaultError::bad_request(m),
        Err(crate::db::DbError::NotFound) => VaultError::not_found(),
        Err(e) => VaultError::internal(e.to_string()),
    }
}

// ── auth/token/create ────────────────────────────────────────────────────────

pub async fn token_create(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Json(req): Json<TokenCreateRequest>,
) -> Response {
    let ttl_seconds: i64 = req
        .ttl
        .as_deref()
        .and_then(|s| s.trim_end_matches('s').parse::<i64>().ok())
        .unwrap_or(3600);

    let requested = if req.policies.is_empty() {
        vec!["default".to_string()]
    } else {
        req.policies.clone()
    };

    // Prevent privilege escalation: a non-root token may only delegate policies
    // it already holds. Root tokens (dev token, owner/admin) may delegate freely.
    let policies = if crate::auth::policy::is_root(&claims.policies) {
        requested
    } else {
        let subset: Vec<String> = requested
            .into_iter()
            .filter(|p| claims.policies.contains(p))
            .collect();
        if subset.is_empty() {
            vec!["default".to_string()]
        } else {
            subset
        }
    };

    let user_id = claims.user_id.unwrap_or_else(Uuid::new_v4);
    let child_token = state
        .sessions
        .issue_in_namespace(user_id, claims.org_id, "", policies.clone(), true, ttl_seconds, &claims.namespace)
        .unwrap_or_else(|_| claims.token.clone());

    Json(AuthResponse {
        request_id: Uuid::new_v4().to_string(),
        auth: AuthData {
            client_token: child_token,
            accessor: Uuid::new_v4().to_string(),
            policies: policies.clone(),
            token_policies: policies,
            metadata: HashMap::new(),
            lease_duration: ttl_seconds as u64,
            renewable: false,
            entity_id: String::new(),
            token_type: "service".into(),
            orphan: false,
            num_uses: 0,
        },
    })
    .into_response()
}

// ── KV v2 data: GET /v1/{mount}/data/{path} ──────────────────────────────────

#[derive(serde::Deserialize)]
pub struct VersionQuery {
    pub version: Option<i32>,
}

pub async fn kv_read(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path((mount, secret_path)): Path<(String, String)>,
    Query(q): Query<VersionQuery>,
) -> Response {
    let env_id = match resolve_env(&state, &claims, &mount).await {
        Ok(id) => id,
        Err(r) => return r,
    };

    let (folder, name) = split_kv_path(&secret_path);
    let sv = match state.store.get(env_id, &folder, &name, q.version).await {
        Ok(v) => v,
        Err(e) if is_not_found(&e) => return VaultError::not_found(),
        Err(e) => return VaultError::internal(e.to_string()),
    };

    // Parse stored value as JSON key-value map (Vault KV v2 stores arbitrary JSON)
    let data: HashMap<String, Value> = match serde_json::from_slice(&sv.plaintext) {
        Ok(v) => v,
        Err(_) => {
            // If not JSON, wrap as single "value" key
            let mut m = HashMap::new();
            m.insert(
                "value".into(),
                Value::String(String::from_utf8_lossy(&sv.plaintext).into_owned()),
            );
            m
        }
    };

    let deleted = sv.version.deleted_at.is_some();
    let destroyed = sv.version.destroyed_at.is_some();

    Json(VaultResponse::kv(KvData {
        data,
        metadata: KvVersionMeta {
            created_time: sv.version.created_at,
            custom_metadata: None,
            deletion_time: sv.version.deleted_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
            destroyed,
            version: sv.version.version_num,
        },
    }))
    .into_response()
}

// ── KV v2 data: POST /v1/{mount}/data/{path} ─────────────────────────────────

pub async fn kv_write(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path((mount, secret_path)): Path<(String, String)>,
    Json(req): Json<KvWriteRequest>,
) -> Response {
    let env_id = match resolve_env(&state, &claims, &mount).await {
        Ok(id) => id,
        Err(r) => return r,
    };

    let (folder, name) = split_kv_path(&secret_path);
    let plaintext = match serde_json::to_vec(&req.data) {
        Ok(b) => b,
        Err(e) => return VaultError::bad_request(e.to_string()),
    };

    let sv = match state
        .store
        .put(env_id, &folder, &name, &plaintext, "string", claims.user_id)
        .await
    {
        Ok(v) => v,
        Err(e) => return VaultError::internal(e.to_string()),
    };

    // Audit
    let _ = state
        .db
        .write_audit(
            Some(claims.org_id),
            claims.user_id,
            "user",
            None,
            "secret.write",
            Some("secret"),
            Some(sv.secret.id),
            Some(&format!("{}{}", folder, name)),
            None,
            serde_json::json!({"mount": mount, "version": sv.version.version_num}),
        )
        .await;

    Json(VaultResponse::kv(KvWriteResponse {
        created_time: sv.version.created_at,
        custom_metadata: None,
        deletion_time: String::new(),
        destroyed: false,
        version: sv.version.version_num,
    }))
    .into_response()
}

// ── KV v2 data: DELETE /v1/{mount}/data/{path} (soft-delete latest) ──────────

pub async fn kv_delete_latest(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path((mount, secret_path)): Path<(String, String)>,
) -> Response {
    let env_id = match resolve_env(&state, &claims, &mount).await {
        Ok(id) => id,
        Err(r) => return r,
    };
    let (folder, name) = split_kv_path(&secret_path);
    let sv = match state.store.get(env_id, &folder, &name, None).await {
        Ok(v) => v,
        Err(e) if is_not_found(&e) => return VaultError::not_found(),
        Err(e) => return VaultError::internal(e.to_string()),
    };
    if let Err(e) = state
        .db
        .soft_delete_versions(sv.secret.id, &[sv.version.version_num])
        .await
    {
        return VaultError::internal(e.to_string());
    }
    StatusCode::NO_CONTENT.into_response()
}

// ── KV v2: POST /v1/{mount}/delete/{path} (soft-delete specific versions) ────

pub async fn kv_delete_versions(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path((mount, secret_path)): Path<(String, String)>,
    Json(req): Json<VersionsRequest>,
) -> Response {
    let env_id = match resolve_env(&state, &claims, &mount).await {
        Ok(id) => id,
        Err(r) => return r,
    };
    let (folder, name) = split_kv_path(&secret_path);
    let sv = match state.store.get(env_id, &folder, &name, None).await {
        Ok(v) => v,
        Err(e) if is_not_found(&e) => return VaultError::not_found(),
        Err(e) => return VaultError::internal(e.to_string()),
    };
    if let Err(e) = state.db.soft_delete_versions(sv.secret.id, &req.versions).await {
        return VaultError::internal(e.to_string());
    }
    StatusCode::NO_CONTENT.into_response()
}

// ── KV v2: POST /v1/{mount}/undelete/{path} ──────────────────────────────────

pub async fn kv_undelete_versions(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path((mount, secret_path)): Path<(String, String)>,
    Json(req): Json<VersionsRequest>,
) -> Response {
    let env_id = match resolve_env(&state, &claims, &mount).await {
        Ok(id) => id,
        Err(r) => return r,
    };
    let (folder, name) = split_kv_path(&secret_path);
    let sv = match state.store.get(env_id, &folder, &name, None).await {
        Ok(v) => v,
        Err(e) if is_not_found(&e) => return VaultError::not_found(),
        Err(e) => return VaultError::internal(e.to_string()),
    };
    if let Err(e) = state.db.undelete_versions(sv.secret.id, &req.versions).await {
        return VaultError::internal(e.to_string());
    }
    StatusCode::NO_CONTENT.into_response()
}

// ── KV v2: PUT /v1/{mount}/destroy/{path} ────────────────────────────────────

pub async fn kv_destroy_versions(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path((mount, secret_path)): Path<(String, String)>,
    Json(req): Json<VersionsRequest>,
) -> Response {
    let env_id = match resolve_env(&state, &claims, &mount).await {
        Ok(id) => id,
        Err(r) => return r,
    };
    let (folder, name) = split_kv_path(&secret_path);
    let sv = match state.store.get(env_id, &folder, &name, None).await {
        Ok(v) => v,
        Err(e) if is_not_found(&e) => return VaultError::not_found(),
        Err(e) => return VaultError::internal(e.to_string()),
    };
    if let Err(e) = state.db.destroy_versions(sv.secret.id, &req.versions).await {
        return VaultError::internal(e.to_string());
    }
    StatusCode::NO_CONTENT.into_response()
}

// ── KV v2: GET /v1/{mount}/metadata/{path} ───────────────────────────────────

pub async fn kv_read_metadata(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path((mount, secret_path)): Path<(String, String)>,
) -> Response {
    let env_id = match resolve_env(&state, &claims, &mount).await {
        Ok(id) => id,
        Err(r) => return r,
    };
    let (folder, name) = split_kv_path(&secret_path);
    let sv = match state.store.get(env_id, &folder, &name, None).await {
        Ok(v) => v,
        Err(e) if is_not_found(&e) => return VaultError::not_found(),
        Err(e) => return VaultError::internal(e.to_string()),
    };

    let all_versions = match state.db.get_versions(sv.secret.id).await {
        Ok(v) => v,
        Err(e) => return VaultError::internal(e.to_string()),
    };

    let mut versions_map = HashMap::new();
    for v in &all_versions {
        versions_map.insert(
            v.version_num.to_string(),
            KvVersionMeta {
                created_time: v.created_at,
                custom_metadata: None,
                deletion_time: v.deleted_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
                destroyed: v.destroyed_at.is_some(),
                version: v.version_num,
            },
        );
    }

    let current = all_versions.iter().map(|v| v.version_num).max().unwrap_or(0);
    let oldest = all_versions.iter().map(|v| v.version_num).min().unwrap_or(0);

    Json(VaultResponse::kv(KvMetadataResponse {
        cas_required: false,
        created_time: sv.secret.created_at,
        current_version: current,
        custom_metadata: None,
        delete_version_after: "0s".into(),
        max_versions: 0,
        oldest_version: oldest,
        updated_time: sv.secret.updated_at,
        versions: versions_map,
    }))
    .into_response()
}

// ── KV v2: LIST /v1/{mount}/metadata/{path} ──────────────────────────────────

#[derive(serde::Deserialize)]
pub struct ListQuery {
    pub list: Option<String>,
}

pub async fn kv_list(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path((mount, secret_path)): Path<(String, String)>,
    Query(q): Query<ListQuery>,
) -> Response {
    let env_id = match resolve_env(&state, &claims, &mount).await {
        Ok(id) => id,
        Err(r) => return r,
    };

    // GET ?list=true → folder listing; GET without list param → version metadata for a secret
    if q.list.as_deref() != Some("true") {
        let (folder, name) = split_kv_path(&secret_path);
        let sv = match state.store.get(env_id, &folder, &name, None).await {
            Ok(v) => v,
            Err(e) if is_not_found(&e) => return VaultError::not_found(),
            Err(e) => return VaultError::internal(e.to_string()),
        };
        let all_versions = match state.db.get_versions(sv.secret.id).await {
            Ok(v) => v,
            Err(e) => return VaultError::internal(e.to_string()),
        };
        let mut versions_map = HashMap::new();
        for v in &all_versions {
            versions_map.insert(
                v.version_num.to_string(),
                KvVersionMeta {
                    created_time: v.created_at,
                    custom_metadata: None,
                    deletion_time: v.deleted_at.map(|t| t.to_rfc3339()).unwrap_or_default(),
                    destroyed: v.destroyed_at.is_some(),
                    version: v.version_num,
                },
            );
        }
        let current = all_versions.iter().map(|v| v.version_num).max().unwrap_or(0);
        let oldest = all_versions.iter().map(|v| v.version_num).min().unwrap_or(0);
        return Json(VaultResponse::kv(KvMetadataResponse {
            cas_required: false,
            created_time: sv.secret.created_at,
            current_version: current,
            custom_metadata: None,
            delete_version_after: "0s".into(),
            max_versions: 0,
            oldest_version: oldest,
            updated_time: sv.secret.updated_at,
            versions: versions_map,
        }))
        .into_response();
    }

    let base_path = if secret_path.is_empty() {
        "/".into()
    } else {
        format!("/{}/", secret_path.trim_matches('/'))
    };

    let items = match state.store.list(env_id, &base_path).await {
        Ok(v) => v,
        Err(e) => return VaultError::internal(e.to_string()),
    };

    let keys: Vec<String> = items.iter().map(|m| m.name.clone()).collect();

    Json(VaultResponse::kv(ListData { keys })).into_response()
}

// ── KV v2: GET /v1/{mount}/metadata (list at root, no path segment) ──────────

pub async fn kv_list_root(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path(mount): Path<String>,
    Query(_q): Query<ListQuery>,
) -> Response {
    let env_id = match resolve_env(&state, &claims, &mount).await {
        Ok(id) => id,
        Err(r) => return r,
    };

    let items = match state.store.list(env_id, "/").await {
        Ok(v) => v,
        Err(e) => return VaultError::internal(e.to_string()),
    };

    let keys: Vec<String> = items.iter().map(|m| m.name.clone()).collect();
    Json(VaultResponse::kv(ListData { keys })).into_response()
}

// ── DELETE /v1/{mount}/metadata/{path} (delete all versions permanently) ─────

pub async fn kv_delete_all(
    State(state): State<VaultState>,
    Extension(claims): Extension<VaultClaims>,
    Path((mount, secret_path)): Path<(String, String)>,
) -> Response {
    let env_id = match resolve_env(&state, &claims, &mount).await {
        Ok(id) => id,
        Err(r) => return r,
    };
    let (folder, name) = split_kv_path(&secret_path);
    let sv = match state.store.get(env_id, &folder, &name, None).await {
        Ok(v) => v,
        Err(e) if is_not_found(&e) => return VaultError::not_found(),
        Err(e) => return VaultError::internal(e.to_string()),
    };
    if let Err(e) = state.store.delete(sv.secret.id).await {
        return VaultError::internal(e.to_string());
    }
    StatusCode::NO_CONTENT.into_response()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn resolve_env(
    state: &VaultState,
    claims: &VaultClaims,
    mount: &str,
) -> Result<Uuid, Response> {
    match state.db.get_vault_mount(claims.org_id, &claims.namespace, mount).await {
        Ok(m) => {
            if let Some(env_id) = m.environment_id {
                return Ok(env_id);
            }
        }
        Err(crate::db::DbError::NotFound) => {}
        Err(e) => return Err(VaultError::internal(e.to_string())),
    }
    // Only the root namespace falls back to the default env; a namespace must
    // never see root data through an unmounted path.
    if !claims.namespace.is_empty() {
        return Err(VaultError::resp(
            StatusCode::NOT_FOUND,
            format!("no handler for route \"{mount}\""),
        ));
    }
    Ok(state.default_env_id)
}

fn is_not_found(e: &anyhow::Error) -> bool {
    e.downcast_ref::<crate::db::DbError>()
        .map(|de| matches!(de, crate::db::DbError::NotFound))
        .unwrap_or(false)
}
