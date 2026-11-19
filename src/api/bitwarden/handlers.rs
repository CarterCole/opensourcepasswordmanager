//! Bitwarden Public API wire-compat handlers.
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Form, Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::common::{require_auth, AppState};

// ── OAuth2 token ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
}

pub async fn token(State(state): State<AppState>, Form(form): Form<TokenRequest>) -> Response {
    let client_id = form.client_id.as_deref().unwrap_or("").trim().to_string();
    let client_secret = form.client_secret.as_deref().unwrap_or("").trim();

    if client_id.is_empty() || client_secret.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(json!({
            "error": "invalid_client",
            "error_description": "client_id and client_secret are required",
        }))).into_response();
    }

    // Validate the client_secret as a real credential before issuing any token.
    // Production (Postgres): the client_secret must be a valid API key; the
    // resulting session inherits that key's org and role. Dev (SQLite): the
    // client_secret must equal the configured dev root token. Anything else is
    // rejected — we never mint a session for an unverified caller.
    let invalid = || (StatusCode::UNAUTHORIZED, Json(json!({
        "error": "invalid_client",
        "error_description": "client authentication failed",
    }))).into_response();

    let (org_id, roles): (Uuid, Vec<String>) = if let Some(ref pool) = state.pg_pool {
        match crate::api::native::keys::resolve_api_key(pool, client_secret).await {
            Ok(resolved) => (resolved.org_id, resolved.role.into_iter().collect()),
            Err(_) => return invalid(),
        }
    } else if state.dev_root_token.as_deref() == Some(client_secret) {
        (state.default_org_id, vec!["owner".into()])
    } else {
        return invalid();
    };

    // Issue a real JWT so protected routes can validate it
    let access_token = state
        .sessions
        .issue(Uuid::new_v4(), org_id, &client_id, roles, true, 3600)
        .unwrap_or_else(|_| Uuid::new_v4().to_string());

    (StatusCode::OK, Json(json!({
        "access_token": access_token,
        "expires_in": 3600,
        "token_type": "Bearer",
        "scope": form.scope.as_deref().unwrap_or("api.organization"),
    }))).into_response()
}

// ── collections ───────────────────────────────────────────────────────────────

pub async fn list_collections(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if require_auth(&state, &headers).await.is_err() { return bw_error(StatusCode::UNAUTHORIZED, "Not authorized"); }

    match state.store.list(state.default_env_id, "/").await {
        Ok(secrets) => {
            let mut paths: Vec<String> = secrets.iter().map(|s| s.path.clone()).collect();
            paths.sort();
            paths.dedup();
            let data: Vec<Value> = paths.iter().map(|p| json!({
                "object": "collection",
                "id": Uuid::new_v4().to_string(),
                "organizationId": state.default_org_id.to_string(),
                "name": p,
                "externalId": null,
                "groups": [],
            })).collect();
            (StatusCode::OK, Json(json!({ "object": "list", "data": data, "continuationToken": null }))).into_response()
        }
        Err(e) => bw_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn create_collection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if require_auth(&state, &headers).await.is_err() { return bw_error(StatusCode::UNAUTHORIZED, "Not authorized"); }

    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed");
    let id = Uuid::new_v4().to_string();
    (StatusCode::OK, Json(json!({
        "object": "collection",
        "id": id,
        "organizationId": state.default_org_id.to_string(),
        "name": name,
        "externalId": null,
        "groups": [],
    }))).into_response()
}

pub async fn get_collection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    if require_auth(&state, &headers).await.is_err() { return bw_error(StatusCode::UNAUTHORIZED, "Not authorized"); }

    (StatusCode::OK, Json(json!({
        "object": "collection",
        "id": id,
        "organizationId": state.default_org_id.to_string(),
        "name": "default",
        "externalId": null,
        "groups": [],
    }))).into_response()
}

pub async fn update_collection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    if require_auth(&state, &headers).await.is_err() { return bw_error(StatusCode::UNAUTHORIZED, "Not authorized"); }

    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("default");
    (StatusCode::OK, Json(json!({
        "object": "collection",
        "id": id,
        "organizationId": state.default_org_id.to_string(),
        "name": name,
        "externalId": null,
        "groups": [],
    }))).into_response()
}

pub async fn delete_collection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(_id): Path<String>,
) -> Response {
    if require_auth(&state, &headers).await.is_err() { return bw_error(StatusCode::UNAUTHORIZED, "Not authorized"); }
    StatusCode::NO_CONTENT.into_response()
}

// ── members ───────────────────────────────────────────────────────────────────

pub async fn list_members(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if require_auth(&state, &headers).await.is_err() { return bw_error(StatusCode::UNAUTHORIZED, "Not authorized"); }

    // In SQLite/dev mode there's no pg_pool — return empty list
    let pool = match &state.pg_pool {
        Some(p) => p.clone(),
        None => return (StatusCode::OK, Json(json!({
            "object": "list", "data": [], "continuationToken": null
        }))).into_response(),
    };

    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT id, email, display_name, is_active FROM users WHERE org_id = $1 ORDER BY created_at",
    )
    .bind(state.default_org_id)
    .fetch_all(&pool)
    .await;

    match rows {
        Ok(rows) => {
            let data: Vec<Value> = rows.iter().map(|r| json!({
                "object": "member",
                "id": r.get::<uuid::Uuid, _>("id"),
                "userId": r.get::<uuid::Uuid, _>("id"),
                "organizationId": state.default_org_id,
                "email": r.get::<String, _>("email"),
                "name": r.try_get::<Option<String>, _>("display_name").ok().flatten().unwrap_or_default(),
                "status": 2,
                "type": 2,
                "accessAll": false,
                "twoFactorEnabled": false,
            })).collect();
            (StatusCode::OK, Json(json!({ "object": "list", "data": data, "continuationToken": null }))).into_response()
        }
        Err(e) => bw_error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

// ── events ────────────────────────────────────────────────────────────────────

pub async fn list_events(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if require_auth(&state, &headers).await.is_err() { return bw_error(StatusCode::UNAUTHORIZED, "Not authorized"); }
    (StatusCode::OK, Json(json!({ "object": "list", "data": [], "continuationToken": null }))).into_response()
}

// ── policies ──────────────────────────────────────────────────────────────────

pub async fn list_policies(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if require_auth(&state, &headers).await.is_err() { return bw_error(StatusCode::UNAUTHORIZED, "Not authorized"); }
    (StatusCode::OK, Json(json!({ "object": "list", "data": [], "continuationToken": null }))).into_response()
}

pub async fn get_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(policy_type): Path<String>,
) -> Response {
    if require_auth(&state, &headers).await.is_err() { return bw_error(StatusCode::UNAUTHORIZED, "Not authorized"); }
    (StatusCode::OK, Json(json!({
        "object": "policy",
        "id": Uuid::new_v4().to_string(),
        "organizationId": state.default_org_id,
        "type": policy_type,
        "data": null,
        "enabled": false,
    }))).into_response()
}

// ── error helper ──────────────────────────────────────────────────────────────

fn bw_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({ "object": "error", "code": status.as_u16(), "message": message }))).into_response()
}
