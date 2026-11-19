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

use crate::api::common::{require_auth, AppState};

// ── helpers ───────────────────────────────────────────────────────────────────

fn aws_region() -> String {
    std::env::var("SECRETD_AWS_REGION").unwrap_or_else(|_| "us-east-1".into())
}

fn aws_account_id() -> String {
    std::env::var("SECRETD_AWS_ACCOUNT_ID").unwrap_or_else(|_| "123456789012".into())
}

fn arn(name: &str) -> String {
    format!(
        "arn:aws:secretsmanager:{}:{}:secret:{name}",
        aws_region(),
        aws_account_id()
    )
}

fn ts_now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn strip_arn(id: &str) -> &str {
    if id.starts_with("arn:") {
        if let Some(pos) = id.rfind(':') {
            return &id[pos + 1..];
        }
    }
    id
}

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
        Json(json!({ "__type": type_name, "message": message })),
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

fn tags_to_aws(tags: &Value) -> Vec<Value> {
    tags.as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| json!({"Key": k, "Value": v.as_str().unwrap_or("")}))
                .collect()
        })
        .unwrap_or_default()
}

/// Returns `(bytes, value_type)` from SecretString or SecretBinary.
/// value_type is "binary" when SecretBinary is used, "string" otherwise.
fn extract_secret_value(body: &Value) -> (Vec<u8>, &'static str) {
    if let Some(s) = body.get("SecretString").and_then(|v| v.as_str()) {
        return (s.as_bytes().to_vec(), "string");
    }
    if let Some(b) = body.get("SecretBinary").and_then(|v| v.as_str()) {
        if let Ok(decoded) = B64.decode(b) {
            return (decoded, "binary");
        }
    }
    (Vec::new(), "string")
}

fn tags_from_aws_array(body: &Value) -> Option<Value> {
    let arr = body.get("Tags")?.as_array()?;
    let map: serde_json::Map<String, Value> = arr
        .iter()
        .filter_map(|t| {
            let k = t.get("Key")?.as_str()?;
            let v = t.get("Value")?.as_str()?;
            Some((k.to_string(), Value::String(v.to_string())))
        })
        .collect();
    Some(Value::Object(map))
}

// ── dispatcher ────────────────────────────────────────────────────────────────

pub async fn dispatch(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if require_auth(&state, &headers).await.is_err() {
        return aws_error(
            StatusCode::FORBIDDEN,
            "AccessDeniedException",
            "Not authorized",
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
        "secretsmanager.UpdateSecret" => update_secret(state, body).await,
        "secretsmanager.DeleteSecret" => delete_secret(state, body).await,
        "secretsmanager.RestoreSecret" => restore_secret_handler(state, body).await,
        "secretsmanager.ListSecrets" => list_secrets(state, body).await,
        "secretsmanager.ListSecretVersionIds" => list_secret_version_ids(state, body).await,
        "secretsmanager.DescribeSecret" => describe_secret(state, body).await,
        "secretsmanager.BatchGetSecretValue" => batch_get_secret_value(state, body).await,
        "secretsmanager.GetRandomPassword" => get_random_password(body).await,
        "secretsmanager.TagResource" => tag_resource(state, body, true).await,
        "secretsmanager.UntagResource" => tag_resource(state, body, false).await,
        "secretsmanager.RotateSecret" => rotate_secret(state, body).await,
        _ => aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidRequestException",
            "Unknown operation",
        ),
    }
}

// ── helpers that need async state access ─────────────────────────────────────

/// Derive stage labels for a version_num based on its position among all versions.
async fn stages_for_version(
    state: &AppState,
    secret_id: Uuid,
    version_num: i32,
) -> Vec<&'static str> {
    let Ok(all) = state.db.get_versions(secret_id).await else {
        return vec!["AWSCURRENT"];
    };
    let mut nums: Vec<i32> = all.iter().map(|v| v.version_num).collect();
    nums.sort_unstable();
    let max = nums.last().copied().unwrap_or(0);
    let prev = if nums.len() >= 2 {
        nums[nums.len() - 2]
    } else {
        -1
    };
    if version_num == max {
        vec!["AWSCURRENT"]
    } else if version_num == prev {
        vec!["AWSPREVIOUS"]
    } else {
        vec![]
    }
}

// ── handlers ──────────────────────────────────────────────────────────────────

async fn get_secret_value(state: AppState, body: Value) -> Response {
    let secret_id_str = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequestException",
                "SecretId required",
            )
        }
    };
    let name = strip_arn(&secret_id_str).to_string();
    let (path, sname) = name_to_path_name(&name);

    let version_id_req = body
        .get("VersionId")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let version_stage_req = body
        .get("VersionStage")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Always fetch current version first to get secret_id
    let current = match state
        .store
        .get(state.default_env_id, &path, &sname, None)
        .await
    {
        Ok(sv) => sv,
        Err(_) => return not_found(&name),
    };

    let sv = if version_id_req.is_some() || version_stage_req.as_deref() == Some("AWSPREVIOUS") {
        let all_versions = match state.db.get_versions(current.secret.id).await {
            Ok(v) => v,
            Err(e) => {
                return aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServiceError",
                    &e.to_string(),
                )
            }
        };

        let target_num = if let Some(vid) = &version_id_req {
            all_versions
                .iter()
                .find(|v| v.id.to_string() == *vid)
                .map(|v| v.version_num)
        } else {
            // AWSPREVIOUS = second-largest version_num
            let mut nums: Vec<i32> = all_versions.iter().map(|v| v.version_num).collect();
            nums.sort_unstable();
            let len = nums.len();
            if len >= 2 {
                Some(nums[len - 2])
            } else {
                None
            }
        };

        match target_num {
            Some(vnum) => {
                match state
                    .store
                    .get(state.default_env_id, &path, &sname, Some(vnum))
                    .await
                {
                    Ok(sv) => sv,
                    Err(_) => {
                        return aws_error(
                            StatusCode::NOT_FOUND,
                            "ResourceNotFoundException",
                            "Version not found",
                        )
                    }
                }
            }
            None => {
                return aws_error(
                    StatusCode::NOT_FOUND,
                    "ResourceNotFoundException",
                    "Version not found",
                )
            }
        }
    } else {
        current
    };

    let version_id = sv.version.id.to_string();
    let ts = sv.secret.updated_at.timestamp();
    let stages = stages_for_version(&state, sv.secret.id, sv.version.version_num).await;

    let mut resp = json!({
        "ARN": arn(&name),
        "Name": name,
        "VersionId": version_id,
        "VersionStages": stages,
        "CreatedDate": ts,
    });

    if sv.value_type == "binary" {
        resp["SecretBinary"] = Value::String(B64.encode(&sv.plaintext));
    } else {
        resp["SecretString"] = Value::String(String::from_utf8_lossy(&sv.plaintext).into_owned());
    }

    (StatusCode::OK, Json(resp)).into_response()
}

async fn create_secret(state: AppState, body: Value) -> Response {
    let name = match body.get("Name").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequestException",
                "Name required",
            )
        }
    };
    let (path, sname) = name_to_path_name(&name);
    let (plaintext, value_type) = extract_secret_value(&body);
    let description = body
        .get("Description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    use crate::db::WriteSecret;
    match state
        .db
        .create_secret(WriteSecret {
            environment_id: state.default_env_id,
            name: sname,
            path,
            plaintext,
            value_type: value_type.to_string(),
            description,
            tags: tags_from_aws_array(&body),
            actor_id: None,
        })
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
        Err(crate::db::DbError::Conflict(_)) => aws_error(
            StatusCode::BAD_REQUEST,
            "ResourceExistsException",
            &format!("The operation failed because the secret {name} already exists."),
        ),
        Err(e) => aws_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServiceError",
            &e.to_string(),
        ),
    }
}

async fn put_secret_value(state: AppState, body: Value) -> Response {
    let secret_id_str = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequestException",
                "SecretId required",
            )
        }
    };
    let name = strip_arn(&secret_id_str).to_string();
    let (path, sname) = name_to_path_name(&name);
    let (plaintext, value_type) = extract_secret_value(&body);

    match state
        .store
        .put(
            state.default_env_id,
            &path,
            &sname,
            &plaintext,
            value_type,
            None,
        )
        .await
    {
        Ok(sv) => (
            StatusCode::OK,
            Json(json!({
                "ARN": arn(&name),
                "Name": name,
                "VersionId": sv.version.id.to_string(),
                "VersionStages": ["AWSCURRENT"],
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

async fn update_secret(state: AppState, body: Value) -> Response {
    let secret_id_str = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequestException",
                "SecretId required",
            )
        }
    };
    let name = strip_arn(&secret_id_str).to_string();
    let (path, sname) = name_to_path_name(&name);

    let existing = match state
        .store
        .get(state.default_env_id, &path, &sname, None)
        .await
    {
        Ok(sv) => sv,
        Err(_) => return not_found(&name),
    };

    let has_value = body.get("SecretString").is_some() || body.get("SecretBinary").is_some();
    let description = body
        .get("Description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut version_id = existing.version.id.to_string();

    if has_value {
        let (plaintext, value_type) = extract_secret_value(&body);
        match state
            .store
            .put(
                state.default_env_id,
                &path,
                &sname,
                &plaintext,
                value_type,
                None,
            )
            .await
        {
            Ok(new_sv) => version_id = new_sv.version.id.to_string(),
            Err(e) => {
                return aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalServiceError",
                    &e.to_string(),
                )
            }
        }
    }

    if let Some(desc) = description {
        if let Err(e) = state
            .db
            .update_secret_description(existing.secret.id, desc)
            .await
        {
            return aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServiceError",
                &e.to_string(),
            );
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "ARN": arn(&name),
            "Name": name,
            "VersionId": version_id,
        })),
    )
        .into_response()
}

async fn delete_secret(state: AppState, body: Value) -> Response {
    let secret_id_str = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequestException",
                "SecretId required",
            )
        }
    };
    let name = strip_arn(&secret_id_str).to_string();
    let (path, sname) = name_to_path_name(&name);

    match state
        .store
        .get(state.default_env_id, &path, &sname, None)
        .await
    {
        Ok(sv) => {
            let _ = state.store.delete(sv.secret.id).await;
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

async fn restore_secret_handler(state: AppState, body: Value) -> Response {
    let secret_id_str = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequestException",
                "SecretId required",
            )
        }
    };
    let name = strip_arn(&secret_id_str).to_string();
    let (path, sname) = name_to_path_name(&name);

    match state
        .db
        .restore_secret(state.default_env_id, &path, &sname)
        .await
    {
        Ok(_meta) => (
            StatusCode::OK,
            Json(json!({
                "ARN": arn(&name),
                "Name": name,
            })),
        )
            .into_response(),
        Err(crate::db::DbError::NotFound) => not_found(&name),
        Err(e) => aws_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServiceError",
            &e.to_string(),
        ),
    }
}

async fn list_secrets(state: AppState, body: Value) -> Response {
    let max_results = body
        .get("MaxResults")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize);
    let offset = body
        .get("NextToken")
        .and_then(|v| v.as_str())
        .and_then(|t| B64.decode(t).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);

    match state.store.list(state.default_env_id, "/").await {
        Ok(secrets) => {
            let mut all: Vec<Value> = secrets
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
                        "Tags": tags_to_aws(&s.tags),
                    })
                })
                .collect();

            // Apply cursor offset
            if offset > 0 {
                all = all.into_iter().skip(offset).collect();
            }

            let next_token = if let Some(max) = max_results {
                if all.len() > max {
                    let new_offset = offset + max;
                    all.truncate(max);
                    Some(B64.encode(new_offset.to_string().as_bytes()))
                } else {
                    None
                }
            } else {
                None
            };

            (
                StatusCode::OK,
                Json(json!({
                    "SecretList": all,
                    "NextToken": next_token,
                })),
            )
                .into_response()
        }
        Err(e) => aws_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServiceError",
            &e.to_string(),
        ),
    }
}

async fn list_secret_version_ids(state: AppState, body: Value) -> Response {
    let secret_id_str = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequestException",
                "SecretId required",
            )
        }
    };
    let name = strip_arn(&secret_id_str).to_string();
    let (path, sname) = name_to_path_name(&name);

    let sv = match state
        .store
        .get(state.default_env_id, &path, &sname, None)
        .await
    {
        Ok(sv) => sv,
        Err(_) => return not_found(&name),
    };

    let all_versions = match state.db.get_versions(sv.secret.id).await {
        Ok(v) => v,
        Err(e) => {
            return aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServiceError",
                &e.to_string(),
            )
        }
    };

    let mut nums: Vec<i32> = all_versions.iter().map(|v| v.version_num).collect();
    nums.sort_unstable();
    let max_num = nums.last().copied().unwrap_or(0);
    let prev_num = if nums.len() >= 2 {
        nums[nums.len() - 2]
    } else {
        -1
    };

    let versions: Vec<Value> = all_versions
        .iter()
        .map(|v| {
            let stages: Vec<&str> = if v.version_num == max_num {
                vec!["AWSCURRENT"]
            } else if v.version_num == prev_num {
                vec!["AWSPREVIOUS"]
            } else {
                vec![]
            };
            json!({
                "VersionId": v.id.to_string(),
                "VersionStages": stages,
                "CreatedDate": v.created_at.timestamp(),
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "ARN": arn(&name),
            "Name": name,
            "Versions": versions,
        })),
    )
        .into_response()
}

async fn describe_secret(state: AppState, body: Value) -> Response {
    let secret_id_str = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequestException",
                "SecretId required",
            )
        }
    };
    let name = strip_arn(&secret_id_str).to_string();
    let (path, sname) = name_to_path_name(&name);

    match state
        .store
        .get(state.default_env_id, &path, &sname, None)
        .await
    {
        Ok(sv) => {
            let version_id = sv.version.id.to_string();
            (
                StatusCode::OK,
                Json(json!({
                    "ARN": arn(&name),
                    "Name": name,
                    "Description": sv.secret.description,
                    "VersionIdsToStages": { version_id: ["AWSCURRENT"] },
                    "Tags": tags_to_aws(&sv.secret.tags),
                    "CreatedDate": sv.secret.created_at.timestamp(),
                    "LastChangedDate": sv.secret.updated_at.timestamp(),
                })),
            )
                .into_response()
        }
        Err(_) => not_found(&name),
    }
}

async fn batch_get_secret_value(state: AppState, body: Value) -> Response {
    let ids = match body.get("SecretIdList").and_then(|v| v.as_array()) {
        Some(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>(),
        None => {
            return aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequestException",
                "SecretIdList required",
            )
        }
    };

    let mut secret_values: Vec<Value> = Vec::new();
    let mut errors: Vec<Value> = Vec::new();

    for id_str in ids {
        let name = strip_arn(&id_str).to_string();
        let (path, sname) = name_to_path_name(&name);
        match state
            .store
            .get(state.default_env_id, &path, &sname, None)
            .await
        {
            Ok(sv) => {
                let version_id = sv.version.id.to_string();
                let ts = sv.secret.updated_at.timestamp();
                let mut entry = json!({
                    "ARN": arn(&name),
                    "Name": name,
                    "VersionId": version_id,
                    "VersionStages": ["AWSCURRENT"],
                    "CreatedDate": ts,
                });
                if sv.value_type == "binary" {
                    entry["SecretBinary"] = Value::String(B64.encode(&sv.plaintext));
                } else {
                    entry["SecretString"] =
                        Value::String(String::from_utf8_lossy(&sv.plaintext).into_owned());
                }
                secret_values.push(entry);
            }
            Err(_) => {
                errors.push(json!({
                    "SecretId": id_str,
                    "ErrorCode": "ResourceNotFoundException",
                    "Message": format!("Secrets Manager can't find the specified secret: {name}"),
                }));
            }
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "SecretValues": secret_values,
            "Errors": errors,
        })),
    )
        .into_response()
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
        exclude_uppercase: body
            .get("ExcludeUppercase")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        exclude_lowercase: body
            .get("ExcludeLowercase")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        exclude_numbers: body
            .get("ExcludeNumbers")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        exclude_punctuation: body
            .get("ExcludePunctuation")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        include_space: body
            .get("IncludeSpace")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
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

async fn tag_resource(state: AppState, body: Value, adding: bool) -> Response {
    let secret_id_str = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequestException",
                "SecretId required",
            )
        }
    };
    let name = strip_arn(&secret_id_str).to_string();
    let (path, sname) = name_to_path_name(&name);

    let sv = match state
        .store
        .get(state.default_env_id, &path, &sname, None)
        .await
    {
        Ok(sv) => sv,
        Err(_) => return not_found(&name),
    };

    let mut current = sv.secret.tags.as_object().cloned().unwrap_or_default();

    if adding {
        if let Some(arr) = body.get("Tags").and_then(|v| v.as_array()) {
            for t in arr {
                if let (Some(k), Some(v)) = (
                    t.get("Key").and_then(|v| v.as_str()),
                    t.get("Value").and_then(|v| v.as_str()),
                ) {
                    current.insert(k.to_string(), Value::String(v.to_string()));
                }
            }
        }
    } else if let Some(arr) = body.get("TagKeys").and_then(|v| v.as_array()) {
        for k in arr {
            if let Some(key) = k.as_str() {
                current.remove(key);
            }
        }
    }

    match state
        .db
        .update_secret_tags(sv.secret.id, Value::Object(current))
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({}))).into_response(),
        Err(e) => aws_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalServiceError",
            &e.to_string(),
        ),
    }
}

async fn rotate_secret(state: AppState, body: Value) -> Response {
    let secret_id_str = match body.get("SecretId").and_then(|v| v.as_str()) {
        Some(s) => s.to_string(),
        None => {
            return aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequestException",
                "SecretId required",
            )
        }
    };
    let name = strip_arn(&secret_id_str).to_string();
    let (path, sname) = name_to_path_name(&name);

    let sv = match state
        .store
        .get(state.default_env_id, &path, &sname, None)
        .await
    {
        Ok(sv) => sv,
        Err(_) => return not_found(&name),
    };

    // Create a new version with the same plaintext.
    // Real rotation would invoke a Lambda to generate a new value.
    match state
        .store
        .put(
            state.default_env_id,
            &path,
            &sname,
            &sv.plaintext,
            &sv.value_type,
            None,
        )
        .await
    {
        Ok(new_sv) => (
            StatusCode::OK,
            Json(json!({
                "ARN": arn(&name),
                "Name": name,
                "VersionId": new_sv.version.id.to_string(),
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
