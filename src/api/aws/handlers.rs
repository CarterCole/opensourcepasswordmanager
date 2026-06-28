//! AWS Secrets Manager wire-compat handlers.
//! All requests come as POST / with X-Amz-Target header.
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::common::AppState;

// ── helpers ──────────────────────────────────────────────────────────────────

fn arn(name: &str) -> String {
    format!("arn:aws:secretsmanager:us-east-1:123456789012:secret:{name}")
}

fn ts_now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Strip ARN prefix, returning just the secret name.
fn strip_arn(id: &str) -> &str {
    if id.starts_with("arn:") {
        // arn:aws:secretsmanager:REGION:ACCOUNT:secret:NAME
        if let Some(pos) = id.rfind(':') {
            return &id[pos + 1..];
        }
    }
    id
}

/// Split a secret name like "foo/bar/baz" into path "/" and name "baz",
/// or "foo/bar" into path "/foo" and name "bar", etc.
fn name_to_path_name(full_name: &str) -> (String, String) {
    match full_name.rfind('/') {
        None => ("/".to_string(), full_name.to_string()),
        Some(pos) => {
            let path = format!("/{}", &full_name[..pos]);
            let name = full_name[pos + 1..].to_string();
            (path, name)
        }
    }
}

fn aws_error(status: StatusCode, type_name: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "__type": type_name,
            "message": message,
        })),
    )
        .into_response()
}

fn not_found(name: &str) -> Response {
    aws_error(
        StatusCode::NOT_FOUND,
        "ResourceNotFoundException",
        &format!("Secrets Manager can't find the specified secret: {name}"),
    )
}

// ── dispatcher ───────────────────────────────────────────────────────────────

pub async fn dispatch(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // Basic auth check: Authorization header must be present
    if headers.get("Authorization").is_none() {
        return aws_error(
            StatusCode::FORBIDDEN,
            "AccessDeniedException",
            "No authorization header provided",
        );
    }

    let target = headers
        .get("X-Amz-Target")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let body: Value = serde_json::from_slice(&body).unwrap_or(Value::Object(Default::default()));

    match target {
        "secretsmanager.GetSecretValue" => get_secret_value(state, body).await,
        "secretsmanager.CreateSecret" => create_secret(state, body).await,
        "secretsmanager.PutSecretValue" => put_secret_value(state, body).await,
        "secretsmanager.UpdateSecret" => put_secret_value(state, body).await,
        "secretsmanager.DeleteSecret" => delete_secret(state, body).await,
        "secretsmanager.ListSecrets" => list_secrets(state).await,
        "secretsmanager.DescribeSecret" => describe_secret(state, body).await,
        "secretsmanager.GetRandomPassword" => get_random_password(body).await,
        "secretsmanager.TagResource" | "secretsmanager.UntagResource" => {
            (StatusCode::OK, Json(json!({}))).into_response()
        }
        "secretsmanager.RotateSecret" => rotate_secret(state, body).await,
        _ => aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequestException",
            "Unknown operation",
        ),
    }
}

// ── handlers ─────────────────────────────────────────────────────────────────

async fn get_secret_value(state: AppState, body: Value) -> Response {
    let secret_id = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(StatusCode::BAD_REQUEST, "InvalidRequestException", "SecretId required")
        }
    };
    let name = strip_arn(&secret_id).to_string();
    let (path, sname) = name_to_path_name(&name);

    match state.store.get(state.default_env_id, &path, &sname, None).await {
        Ok(sv) => {
            let version_id = sv.version.id.to_string();
            let plaintext = String::from_utf8_lossy(&sv.plaintext).to_string();
            let ts = sv.secret.updated_at.timestamp();
            (
                StatusCode::OK,
                Json(json!({
                    "ARN": arn(&name),
                    "Name": name,
                    "VersionId": version_id,
                    "SecretString": plaintext,
                    "VersionStages": ["AWSCURRENT"],
                    "CreatedDate": ts,
                })),
            )
                .into_response()
        }
        Err(_) => not_found(&name),
    }
}

async fn create_secret(state: AppState, body: Value) -> Response {
    let name = match body.get("Name").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => return aws_error(StatusCode::BAD_REQUEST, "InvalidRequestException", "Name required"),
    };
    let (path, sname) = name_to_path_name(&name);

    let plaintext = extract_secret_value(&body);

    match state
        .store
        .put(state.default_env_id, &path, &sname, plaintext.as_bytes(), "string", None)
        .await
    {
        Ok(sv) => (
            StatusCode::OK,
            Json(json!({
                "ARN": arn(&name),
                "Name": name,
                "VersionId": sv.version.id.to_string(),
            })),
        )
            .into_response(),
        Err(e) => aws_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServiceError",
            &e.to_string(),
        ),
    }
}

async fn put_secret_value(state: AppState, body: Value) -> Response {
    let secret_id = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(StatusCode::BAD_REQUEST, "InvalidRequestException", "SecretId required")
        }
    };
    let name = strip_arn(&secret_id).to_string();
    let (path, sname) = name_to_path_name(&name);

    let plaintext = extract_secret_value(&body);

    match state
        .store
        .put(state.default_env_id, &path, &sname, plaintext.as_bytes(), "string", None)
        .await
    {
        Ok(sv) => (
            StatusCode::OK,
            Json(json!({
                "ARN": arn(&name),
                "Name": name,
                "VersionId": sv.version.id.to_string(),
            })),
        )
            .into_response(),
        Err(e) => aws_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServiceError",
            &e.to_string(),
        ),
    }
}

async fn delete_secret(state: AppState, body: Value) -> Response {
    let secret_id = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(StatusCode::BAD_REQUEST, "InvalidRequestException", "SecretId required")
        }
    };
    let name = strip_arn(&secret_id).to_string();
    let (path, sname) = name_to_path_name(&name);

    // Get the secret first to get its ID
    match state.store.get(state.default_env_id, &path, &sname, None).await {
        Ok(sv) => {
            let secret_id_uuid = sv.secret.id;
            let _ = state.store.delete(secret_id_uuid).await;
            (
                StatusCode::OK,
                Json(json!({
                    "ARN": arn(&name),
                    "Name": name,
                    "DeletionDate": ts_now() + 30 * 86400,
                })),
            )
                .into_response()
        }
        Err(_) => not_found(&name),
    }
}

async fn list_secrets(state: AppState) -> Response {
    match state.store.list(state.default_env_id, "/").await {
        Ok(secrets) => {
            let list: Vec<Value> = secrets
                .iter()
                .map(|s| {
                    let full_name = if s.path == "/" {
                        s.name.clone()
                    } else {
                        format!("{}/{}", s.path.trim_start_matches('/'), s.name)
                    };
                    json!({
                        "ARN": arn(&full_name),
                        "Name": full_name,
                        "LastChangedDate": s.updated_at.timestamp(),
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({ "SecretList": list, "NextToken": null }))).into_response()
        }
        Err(e) => aws_error(StatusCode::INTERNAL_SERVER_ERROR, "InternalServiceError", &e.to_string()),
    }
}

async fn describe_secret(state: AppState, body: Value) -> Response {
    let secret_id = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(StatusCode::BAD_REQUEST, "InvalidRequestException", "SecretId required")
        }
    };
    let name = strip_arn(&secret_id).to_string();
    let (path, sname) = name_to_path_name(&name);

    match state.store.get(state.default_env_id, &path, &sname, None).await {
        Ok(sv) => {
            let version_id = sv.version.id.to_string();
            (
                StatusCode::OK,
                Json(json!({
                    "ARN": arn(&name),
                    "Name": name,
                    "VersionIdsToStages": {
                        version_id: ["AWSCURRENT"],
                    },
                })),
            )
                .into_response()
        }
        Err(_) => not_found(&name),
    }
}

async fn get_random_password(body: Value) -> Response {
    let length = body
        .get("PasswordLength")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize)
        .unwrap_or(32);

    let exclude_chars = body
        .get("ExcludeCharacters")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let opts = crate::core::password::PasswordOptions {
        length,
        exclude_uppercase: body.get("ExcludeUppercase").and_then(|v| v.as_bool()).unwrap_or(false),
        exclude_lowercase: body.get("ExcludeLowercase").and_then(|v| v.as_bool()).unwrap_or(false),
        exclude_numbers: body.get("ExcludeNumbers").and_then(|v| v.as_bool()).unwrap_or(false),
        exclude_punctuation: body
            .get("ExcludePunctuation")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        include_space: body.get("IncludeSpace").and_then(|v| v.as_bool()).unwrap_or(false),
        exclude_characters: exclude_chars,
        require_each_included_type: body
            .get("RequireEachIncludedType")
            .and_then(|v| v.as_bool())
            .unwrap_or(true),
    };

    match crate::core::password::generate_password(&opts) {
        Ok(pw) => (StatusCode::OK, Json(json!({ "RandomPassword": pw }))).into_response(),
        Err(e) => aws_error(StatusCode::BAD_REQUEST, "InvalidRequestException", e),
    }
}

async fn rotate_secret(state: AppState, body: Value) -> Response {
    let secret_id = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(StatusCode::BAD_REQUEST, "InvalidRequestException", "SecretId required")
        }
    };
    let name = strip_arn(&secret_id).to_string();
    let (path, sname) = name_to_path_name(&name);

    match state.store.get(state.default_env_id, &path, &sname, None).await {
        Ok(sv) => (
            StatusCode::OK,
            Json(json!({
                "ARN": arn(&name),
                "Name": name,
                "VersionId": sv.version.id.to_string(),
            })),
        )
            .into_response(),
        Err(_) => not_found(&name),
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

/// Extract plaintext from SecretString or SecretBinary (base64-decoded).
fn extract_secret_value(body: &Value) -> String {
    if let Some(s) = body.get("SecretString").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    if let Some(b) = body.get("SecretBinary").and_then(|v| v.as_str()) {
        if let Ok(decoded) = B64.decode(b) {
            return String::from_utf8_lossy(&decoded).to_string();
        }
    }
    String::new()
}
