//! Cloudflare Secrets Store wire-compat handlers.
//! Values are write-only — never returned after creation.
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::common::{require_auth, AppState};

// ── response wrapper ──────────────────────────────────────────────────────────

fn cf_ok(result: Value) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "success": true, "errors": [], "messages": [], "result": result,
        })),
    )
        .into_response()
}

fn cf_ok_with_info(result: Value, count: usize) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "success": true, "errors": [], "messages": [], "result": result,
            "result_info": { "count": count, "page": 1, "per_page": 25, "total_count": count },
        })),
    )
        .into_response()
}

fn cf_error(status: StatusCode, code: u32, message: &str) -> Response {
    (
        status,
        Json(json!({
            "success": false,
            "errors": [{"code": code, "message": message}],
            "messages": [], "result": null,
        })),
    )
        .into_response()
}

fn cf_forbidden() -> Response {
    cf_error(StatusCode::FORBIDDEN, 9109, "Not authorized")
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn store_object(store_id: &str, name: &str) -> Value {
    json!({ "id": store_id, "name": name, "created_on": rfc3339_now(), "modified_on": rfc3339_now() })
}

fn secret_meta_object(secret_id: &str, name: &str, store_id: &str) -> Value {
    json!({
        "id": secret_id, "name": name, "store_id": store_id,
        "status": "active", "created_on": rfc3339_now(), "modified_on": rfc3339_now(),
    })
}

fn cf_path(store: &str) -> String {
    format!("/cf/{store}")
}

// ── quota ─────────────────────────────────────────────────────────────────────

pub async fn get_quota(
    State(state): State<AppState>,
    Path((_account,)): Path<(String,)>,
    headers: HeaderMap,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return cf_forbidden();
    }
    let count = state
        .store
        .list(state.default_env_id, "/")
        .await
        .map(|l| l.len())
        .unwrap_or(0);
    cf_ok(json!({ "count": count, "limit": 10000 }))
}

// ── stores ────────────────────────────────────────────────────────────────────

pub async fn list_stores(
    State(state): State<AppState>,
    Path((_account,)): Path<(String,)>,
    headers: HeaderMap,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return cf_forbidden();
    }
    let store_id = Uuid::new_v4().to_string();
    cf_ok(json!([store_object(&store_id, "default")]))
}

pub async fn create_store(
    State(state): State<AppState>,
    Path((_account,)): Path<(String,)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return cf_forbidden();
    }
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let store_id = Uuid::new_v4().to_string();
    cf_ok(store_object(&store_id, name))
}

pub async fn get_store(
    State(state): State<AppState>,
    Path((_account, store)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return cf_forbidden();
    }
    cf_ok(store_object(&store, "default"))
}

pub async fn delete_store(
    State(state): State<AppState>,
    Path((_account, _store)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return cf_forbidden();
    }
    cf_ok(Value::Null)
}

// ── secrets ───────────────────────────────────────────────────────────────────

pub async fn list_store_secrets(
    State(state): State<AppState>,
    Path((_account, store)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return cf_forbidden();
    }
    let path = cf_path(&store);
    match state.store.list(state.default_env_id, &path).await {
        Ok(secrets) => {
            let items: Vec<Value> = secrets
                .iter()
                .map(|s| secret_meta_object(&s.id.to_string(), &s.name, &store))
                .collect();
            let n = items.len();
            cf_ok_with_info(json!(items), n)
        }
        Err(e) => cf_error(StatusCode::INTERNAL_SERVER_ERROR, 7000, &e.to_string()),
    }
}

pub async fn batch_create_secrets(
    State(state): State<AppState>,
    Path((_account, store)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return cf_forbidden();
    }
    let path = cf_path(&store);

    let items = match body.as_array() {
        Some(a) => a.clone(),
        None => return cf_error(StatusCode::BAD_REQUEST, 7001, "body must be an array"),
    };

    let mut results = Vec::new();
    for item in &items {
        let name = match item.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => continue,
        };
        let value = item.get("text").and_then(|v| v.as_str()).unwrap_or("");
        if let Ok(sv) = state
            .store
            .put(
                state.default_env_id,
                &path,
                name,
                value.as_bytes(),
                "string",
                None,
            )
            .await
        {
            results.push(secret_meta_object(&sv.secret.id.to_string(), name, &store));
        }
    }

    cf_ok(json!(results))
}

pub async fn get_store_secret(
    State(state): State<AppState>,
    Path((_account, store, secret)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return cf_forbidden();
    }
    let path = cf_path(&store);
    match state
        .store
        .get(state.default_env_id, &path, &secret, None)
        .await
    {
        Ok(sv) => cf_ok(secret_meta_object(
            &sv.secret.id.to_string(),
            &secret,
            &store,
        )),
        Err(_) => cf_error(StatusCode::NOT_FOUND, 7003, "Secret not found"),
    }
}

pub async fn update_store_secret(
    State(state): State<AppState>,
    Path((_account, store, secret)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return cf_forbidden();
    }
    let path = cf_path(&store);
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(&secret)
        .to_string();
    let value = body.get("text").and_then(|v| v.as_str()).unwrap_or("");

    match state
        .store
        .put(
            state.default_env_id,
            &path,
            &name,
            value.as_bytes(),
            "string",
            None,
        )
        .await
    {
        Ok(sv) => cf_ok(secret_meta_object(&sv.secret.id.to_string(), &name, &store)),
        Err(e) => cf_error(StatusCode::INTERNAL_SERVER_ERROR, 7000, &e.to_string()),
    }
}

pub async fn delete_store_secret(
    State(state): State<AppState>,
    Path((_account, store, secret)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return cf_forbidden();
    }
    let path = cf_path(&store);
    match state
        .store
        .get(state.default_env_id, &path, &secret, None)
        .await
    {
        Ok(sv) => {
            let _ = state.store.delete(sv.secret.id).await;
            cf_ok(json!({ "id": sv.secret.id.to_string() }))
        }
        Err(_) => cf_error(StatusCode::NOT_FOUND, 7003, "Secret not found"),
    }
}
