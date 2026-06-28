//! GCP Secret Manager wire-compat handlers.
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::common::AppState;

// ── helpers ──────────────────────────────────────────────────────────────────

fn gcp_error(code: u16, message: &str, status: &str) -> Response {
    let http_status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        http_status,
        Json(json!({
            "error": {
                "code": code,
                "message": message,
                "status": status,
            }
        })),
    )
        .into_response()
}

fn not_found(name: &str) -> Response {
    gcp_error(404, &format!("Secret [{name}] not found."), "NOT_FOUND")
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn secret_resource(project: &str, name: &str) -> String {
    format!("projects/{project}/secrets/{name}")
}

fn version_resource(project: &str, secret: &str, n: i32) -> String {
    format!("projects/{project}/secrets/{secret}/versions/{n}")
}

// ── list secrets ──────────────────────────────────────────────────────────────

pub async fn list_secrets(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
) -> Response {
    require_bearer(&headers);

    match state.store.list(state.default_env_id, "/").await {
        Ok(secrets) => {
            let list: Vec<Value> = secrets
                .iter()
                .map(|s| {
                    json!({
                        "name": secret_resource(&project, &s.name),
                        "replication": {"automatic": {}},
                        "createTime": s.created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "secrets": list, "nextPageToken": "" })),
            )
                .into_response()
        }
        Err(e) => gcp_error(500, &e.to_string(), "INTERNAL"),
    }
}

// ── create secret (container, no value) ──────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateSecretQuery {
    #[serde(rename = "secretId")]
    pub secret_id: Option<String>,
}

pub async fn create_secret(
    State(state): State<AppState>,
    Path(project): Path<String>,
    headers: HeaderMap,
    Query(q): Query<CreateSecretQuery>,
    Json(_body): Json<Value>,
) -> Response {
    require_bearer(&headers);

    let name = match q.secret_id {
        Some(s) => s,
        None => return gcp_error(400, "secretId query parameter required", "INVALID_ARGUMENT"),
    };

    // Create with empty value as placeholder
    match state
        .store
        .put(state.default_env_id, "/", &name, b"", "string", None)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "name": secret_resource(&project, &name),
                "replication": {"automatic": {}},
                "createTime": rfc3339_now(),
            })),
        )
            .into_response(),
        Err(e) => gcp_error(500, &e.to_string(), "INTERNAL"),
    }
}

// ── POST /v1/projects/:project/secrets/*action ────────────────────────────────
// Handles both:  /secrets/NAME:addVersion  and  /secrets/NAME  (plain POST)

pub async fn post_action(
    State(state): State<AppState>,
    Path((project, action)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    require_bearer(&headers);

    if action.ends_with(":addVersion") {
        let secret = action.trim_end_matches(":addVersion").to_string();
        add_version(state, project, secret, body).await
    } else {
        gcp_error(400, "Unknown action", "INVALID_ARGUMENT")
    }
}

async fn add_version(state: AppState, project: String, secret: String, body: Value) -> Response {
    let data_b64 = body
        .get("payload")
        .and_then(|p| p.get("data"))
        .and_then(|d| d.as_str())
        .unwrap_or("");

    let plaintext = match B64.decode(data_b64) {
        Ok(bytes) => bytes,
        Err(_) => return gcp_error(400, "Invalid base64 in payload.data", "INVALID_ARGUMENT"),
    };

    match state
        .store
        .put(state.default_env_id, "/", &secret, &plaintext, "bytes", None)
        .await
    {
        Ok(sv) => (
            StatusCode::OK,
            Json(json!({
                "name": version_resource(&project, &secret, sv.version.version_num),
                "state": "ENABLED",
                "createTime": rfc3339_now(),
            })),
        )
            .into_response(),
        Err(e) => gcp_error(500, &e.to_string(), "INTERNAL"),
    }
}

// ── GET /v1/projects/:project/secrets/*action ─────────────────────────────────
// Handles:
//   /secrets/NAME                          — metadata
//   /secrets/NAME/versions/latest:access   — access latest version
//   /secrets/NAME/versions/N:access        — access specific version

pub async fn get_action(
    State(state): State<AppState>,
    Path((project, action)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    require_bearer(&headers);

    // Try to parse versions access pattern
    // action patterns:
    //   "NAME"
    //   "NAME/versions/latest:access"
    //   "NAME/versions/N:access"
    if let Some((secret, version_part)) = action.split_once("/versions/") {
        let version_str = version_part.trim_end_matches(":access");
        let version: Option<i32> = if version_str == "latest" {
            None
        } else {
            version_str.parse().ok()
        };

        return match state
            .store
            .get(state.default_env_id, "/", secret, version)
            .await
        {
            Ok(sv) => {
                let encoded = B64.encode(&sv.plaintext);
                let ver_num = sv.version.version_num;
                (
                    StatusCode::OK,
                    Json(json!({
                        "name": version_resource(&project, secret, ver_num),
                        "payload": {
                            "data": encoded,
                            "dataCrc32c": "0",
                        },
                    })),
                )
                    .into_response()
            }
            Err(_) => not_found(secret),
        };
    }

    // Plain metadata request: action = "NAME"
    let secret = &action;
    match state.store.get(state.default_env_id, "/", secret, None).await {
        Ok(sv) => (
            StatusCode::OK,
            Json(json!({
                "name": secret_resource(&project, secret),
                "replication": {"automatic": {}},
                "createTime": sv.secret.created_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            })),
        )
            .into_response(),
        Err(_) => not_found(secret),
    }
}

// ── DELETE /v1/projects/:project/secrets/*action ──────────────────────────────

pub async fn delete_action(
    State(state): State<AppState>,
    Path((_project, action)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    require_bearer(&headers);

    let secret = &action;
    match state.store.get(state.default_env_id, "/", secret, None).await {
        Ok(sv) => {
            let _ = state.store.delete(sv.secret.id).await;
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        Err(_) => not_found(secret),
    }
}

// ── auth helper ───────────────────────────────────────────────────────────────

fn require_bearer(_headers: &HeaderMap) {
    // Dev mode: accept any Authorization header; silently pass if missing
}
