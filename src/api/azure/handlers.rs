//! Azure Key Vault wire-compat handlers.
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::common::{require_auth, AppState};

// ── helpers ──────────────────────────────────────────────────────────────────

fn azure_error(code: &str, message: &str) -> Response {
    let status = match code {
        "SecretNotFound" | "Unauthorized" => StatusCode::NOT_FOUND,
        "BadParameter" => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(json!({ "error": { "code": code, "message": message } })),
    )
        .into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": { "code": "Unauthorized", "message": "Not authorized" } })),
    )
        .into_response()
}

fn not_found(name: &str) -> Response {
    azure_error(
        "SecretNotFound",
        &format!("A secret with (name/id) {name} was not found in this key vault."),
    )
}

fn ts_now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn secret_id_url(vault: &str, name: &str, version: &str) -> String {
    format!("http://localhost/azure/{vault}/secrets/{name}/{version}")
}

fn build_bundle(vault: &str, name: &str, value: &str, version_id: &str, ts: i64) -> Value {
    json!({
        "id": secret_id_url(vault, name, version_id),
        "value": value,
        "attributes": {
            "enabled": true,
            "created": ts,
            "updated": ts,
            "recoveryLevel": "Purgeable",
        },
    })
}

// ── set secret (PUT) ──────────────────────────────────────────────────────────

pub async fn set_secret(
    State(state): State<AppState>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized();
    }

    let value = body.get("value").and_then(|v| v.as_str()).unwrap_or("");

    match state
        .store
        .put(
            state.default_env_id,
            "/",
            &name,
            value.as_bytes(),
            "string",
            None,
        )
        .await
    {
        Ok(sv) => {
            let ts = sv.secret.updated_at.timestamp();
            let vid = sv.version.id.to_string();
            (
                StatusCode::OK,
                Json(build_bundle(&vault, &name, value, &vid, ts)),
            )
                .into_response()
        }
        Err(e) => azure_error("InternalError", &e.to_string()),
    }
}

// ── get secret (GET latest) ───────────────────────────────────────────────────

pub async fn get_secret(
    State(state): State<AppState>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized();
    }

    match state
        .store
        .get(state.default_env_id, "/", &name, None)
        .await
    {
        Ok(sv) => {
            let value = String::from_utf8_lossy(&sv.plaintext).to_string();
            let ts = sv.secret.updated_at.timestamp();
            let vid = sv.version.id.to_string();
            (
                StatusCode::OK,
                Json(build_bundle(&vault, &name, &value, &vid, ts)),
            )
                .into_response()
        }
        Err(_) => not_found(&name),
    }
}

// ── get specific version ──────────────────────────────────────────────────────

pub async fn get_secret_version(
    State(state): State<AppState>,
    Path((vault, name, version)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized();
    }

    match state
        .store
        .get(state.default_env_id, "/", &name, None)
        .await
    {
        Ok(sv) => {
            let value = String::from_utf8_lossy(&sv.plaintext).to_string();
            let ts = sv.secret.updated_at.timestamp();
            (
                StatusCode::OK,
                Json(build_bundle(&vault, &name, &value, &version, ts)),
            )
                .into_response()
        }
        Err(_) => not_found(&name),
    }
}

// ── delete secret ─────────────────────────────────────────────────────────────

pub async fn delete_secret(
    State(state): State<AppState>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized();
    }

    match state
        .store
        .get(state.default_env_id, "/", &name, None)
        .await
    {
        Ok(sv) => {
            let ts = sv.secret.updated_at.timestamp();
            let vid = sv.version.id.to_string();
            let _ = state.store.delete(sv.secret.id).await;
            let bundle = json!({
                "id": secret_id_url(&vault, &name, &vid),
                "attributes": {
                    "enabled": false,
                    "created": ts,
                    "updated": ts_now(),
                    "recoveryLevel": "Purgeable",
                },
                "deletedDate": ts_now(),
                "scheduledPurgeDate": ts_now() + 30 * 86400,
            });
            (StatusCode::OK, Json(bundle)).into_response()
        }
        Err(_) => not_found(&name),
    }
}

// ── list secrets ──────────────────────────────────────────────────────────────

pub async fn list_secrets(
    State(state): State<AppState>,
    Path(vault): Path<String>,
    headers: HeaderMap,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized();
    }

    match state.store.list(state.default_env_id, "/").await {
        Ok(secrets) => {
            let items: Vec<Value> = secrets
                .iter()
                .map(|s| {
                    json!({
                        "id": format!("http://localhost/azure/{}/secrets/{}", vault, s.name),
                        "attributes": {
                            "enabled": s.deleted_at.is_none(),
                            "created": s.created_at.timestamp(),
                            "updated": s.updated_at.timestamp(),
                            "recoveryLevel": "Purgeable",
                        },
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "value": items, "nextLink": null })),
            )
                .into_response()
        }
        Err(e) => azure_error("InternalError", &e.to_string()),
    }
}

// ── list versions ─────────────────────────────────────────────────────────────

pub async fn list_versions(
    State(state): State<AppState>,
    Path((vault, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return unauthorized();
    }

    match state
        .store
        .get(state.default_env_id, "/", &name, None)
        .await
    {
        Ok(sv) => {
            let vid = sv.version.id.to_string();
            let ts = sv.secret.updated_at.timestamp();
            let items = vec![json!({
                "id": secret_id_url(&vault, &name, &vid),
                "attributes": {
                    "enabled": true, "created": ts, "updated": ts, "recoveryLevel": "Purgeable",
                },
            })];
            (
                StatusCode::OK,
                Json(json!({ "value": items, "nextLink": null })),
            )
                .into_response()
        }
        Err(_) => not_found(&name),
    }
}

// ── deleted secret endpoints ──────────────────────────────────────────────────

pub async fn get_deleted(Path((_vault, name)): Path<(String, String)>) -> Response {
    azure_error(
        "SecretNotFound",
        &format!("Deleted secret {name} was not found."),
    )
}

pub async fn recover_secret(Path((_vault, name)): Path<(String, String)>) -> Response {
    azure_error(
        "SecretNotFound",
        &format!("Deleted secret {name} was not found."),
    )
}

pub async fn purge_secret(Path((_vault, _name)): Path<(String, String)>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}
