//! Bitwarden Public API wire-compat handlers.
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Form, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::common::AppState;

// ── OAuth2 token ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
}

pub async fn token(Form(form): Form<TokenRequest>) -> Response {
    // Dev mode: accept any non-empty client_id/secret
    let client_id = form.client_id.as_deref().unwrap_or("").trim();
    let client_secret = form.client_secret.as_deref().unwrap_or("").trim();

    if client_id.is_empty() || client_secret.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "invalid_client",
                "error_description": "client_id and client_secret are required",
            })),
        )
            .into_response();
    }

    let token = Uuid::new_v4().to_string();
    (
        StatusCode::OK,
        Json(json!({
            "access_token": token,
            "expires_in": 3600,
            "token_type": "Bearer",
            "scope": form.scope.as_deref().unwrap_or("api.organization"),
        })),
    )
        .into_response()
}

// ── collections ───────────────────────────────────────────────────────────────

pub async fn list_collections(State(state): State<AppState>) -> Response {
    match state.store.list(state.default_env_id, "/").await {
        Ok(secrets) => {
            // Group unique paths as "collections"
            let mut paths: Vec<String> = secrets.iter().map(|s| s.path.clone()).collect();
            paths.sort();
            paths.dedup();

            let data: Vec<Value> = paths
                .iter()
                .map(|p| {
                    json!({
                        "object": "collection",
                        "id": Uuid::new_v4().to_string(),
                        "organizationId": state.default_org_id.to_string(),
                        "name": p,
                        "externalId": null,
                        "groups": [],
                    })
                })
                .collect();

            (
                StatusCode::OK,
                Json(json!({
                    "object": "list",
                    "data": data,
                    "continuationToken": null,
                })),
            )
                .into_response()
        }
        Err(e) => bw_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn create_collection(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Response {
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed");
    let id = Uuid::new_v4().to_string();
    (
        StatusCode::OK,
        Json(json!({
            "object": "collection",
            "id": id,
            "organizationId": state.default_org_id.to_string(),
            "name": name,
            "externalId": null,
            "groups": [],
        })),
    )
        .into_response()
}

pub async fn get_collection(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "object": "collection",
            "id": id,
            "organizationId": state.default_org_id.to_string(),
            "name": "default",
            "externalId": null,
            "groups": [],
        })),
    )
        .into_response()
}

pub async fn update_collection(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("default");
    (
        StatusCode::OK,
        Json(json!({
            "object": "collection",
            "id": id,
            "organizationId": state.default_org_id.to_string(),
            "name": name,
            "externalId": null,
            "groups": [],
        })),
    )
        .into_response()
}

pub async fn delete_collection(Path(_id): Path<String>) -> Response {
    StatusCode::NO_CONTENT.into_response()
}

// ── members ───────────────────────────────────────────────────────────────────

pub async fn list_members() -> Response {
    (
        StatusCode::OK,
        Json(json!({ "object": "list", "data": [], "continuationToken": null })),
    )
        .into_response()
}

// ── events ────────────────────────────────────────────────────────────────────

pub async fn list_events() -> Response {
    (
        StatusCode::OK,
        Json(json!({ "object": "list", "data": [], "continuationToken": null })),
    )
        .into_response()
}

// ── policies ──────────────────────────────────────────────────────────────────

pub async fn list_policies() -> Response {
    (
        StatusCode::OK,
        Json(json!({ "object": "list", "data": [], "continuationToken": null })),
    )
        .into_response()
}

pub async fn get_policy(Path(policy_type): Path<String>) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "object": "policy",
            "id": Uuid::new_v4().to_string(),
            "organizationId": null,
            "type": policy_type,
            "data": null,
            "enabled": false,
        })),
    )
        .into_response()
}

// ── error helper ──────────────────────────────────────────────────────────────

fn bw_error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(json!({
            "object": "error",
            "code": status.as_u16(),
            "message": message,
        })),
    )
        .into_response()
}
