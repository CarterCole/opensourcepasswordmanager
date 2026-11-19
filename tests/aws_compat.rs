//! AWS Secrets Manager wire-compatibility integration tests.
mod common;

use axum::http::StatusCode;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use opensourcepasswordmanager::api::aws::router::aws_router;
use serde_json::json;

fn app() -> axum::Router {
    aws_router(common::make_app_state())
}

fn amz_req(target: &str, body: serde_json::Value) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method("POST")
        .uri("/")
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Target", target)
        .header(
            "Authorization",
            "AWS4-HMAC-SHA256 Credential=test-token/20240101/us-east-1/secretsmanager/aws4_request",
        )
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

// ── CreateSecret ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_secret() {
    let req = amz_req(
        "secretsmanager.CreateSecret",
        json!({ "Name": "prod/db", "SecretString": "mypassword" }),
    );
    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["ARN"].as_str().unwrap().contains("arn:aws:secretsmanager"));
    assert_eq!(body["Name"], "prod/db");
    assert!(body["VersionId"].is_string());
}

#[tokio::test]
async fn create_secret_with_description_and_tags() {
    let req = amz_req(
        "secretsmanager.CreateSecret",
        json!({
            "Name": "tagged/secret",
            "SecretString": "value",
            "Description": "A test secret",
            "Tags": [{"Key": "env", "Value": "prod"}, {"Key": "team", "Value": "infra"}]
        }),
    );
    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["Name"], "tagged/secret");

    // DescribeSecret should reflect description and tags
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "tagcheck", "SecretString": "x", "Description": "desc", "Tags": [{"Key": "k", "Value": "v"}] }))).await;
    let (_, d) = common::call(app, amz_req("secretsmanager.DescribeSecret", json!({ "SecretId": "tagcheck" }))).await;
    assert_eq!(d["Description"], "desc");
    let tags = d["Tags"].as_array().unwrap();
    assert!(tags.iter().any(|t| t["Key"] == "k" && t["Value"] == "v"));
}

#[tokio::test]
async fn create_duplicate_returns_resource_exists() {
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "dupe", "SecretString": "v1" }))).await;
    let (status, body) = common::call(app, amz_req("secretsmanager.CreateSecret", json!({ "Name": "dupe", "SecretString": "v2" }))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "ResourceExistsException");
}

// ── GetSecretValue ────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_secret_value() {
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "getsecret", "SecretString": "topsecret" }))).await;

    let (status, body) = common::call(app, amz_req("secretsmanager.GetSecretValue", json!({ "SecretId": "getsecret" }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["SecretString"], "topsecret");
    assert_eq!(body["Name"], "getsecret");
    assert!(body["ARN"].as_str().unwrap().contains("arn:aws:secretsmanager"));
    assert!(body["VersionId"].is_string());
    let stages = body["VersionStages"].as_array().unwrap();
    assert!(stages.iter().any(|s| s == "AWSCURRENT"));
    assert!(body.get("SecretBinary").is_none());
}

#[tokio::test]
async fn get_secret_value_by_version_id() {
    let app = app();
    let (_, c1) = common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "vertest", "SecretString": "v1" }))).await;
    let v1_id = c1["VersionId"].as_str().unwrap().to_string();

    common::call(app.clone(), amz_req("secretsmanager.PutSecretValue", json!({ "SecretId": "vertest", "SecretString": "v2" }))).await;

    // Request the first version by its UUID
    let (status, body) = common::call(app, amz_req("secretsmanager.GetSecretValue", json!({ "SecretId": "vertest", "VersionId": v1_id }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["SecretString"], "v1");
    let stages = body["VersionStages"].as_array().unwrap();
    assert!(stages.iter().any(|s| s == "AWSPREVIOUS"));
}

#[tokio::test]
async fn get_secret_value_awsprevious_stage() {
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "stagetest", "SecretString": "v1" }))).await;
    common::call(app.clone(), amz_req("secretsmanager.PutSecretValue", json!({ "SecretId": "stagetest", "SecretString": "v2" }))).await;

    let (status, body) = common::call(app, amz_req("secretsmanager.GetSecretValue", json!({ "SecretId": "stagetest", "VersionStage": "AWSPREVIOUS" }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["SecretString"], "v1");
    let stages = body["VersionStages"].as_array().unwrap();
    assert!(stages.iter().any(|s| s == "AWSPREVIOUS"));
}

#[tokio::test]
async fn get_secret_value_awsprevious_no_previous_version() {
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "onlyone", "SecretString": "v1" }))).await;

    let (status, _) = common::call(app, amz_req("secretsmanager.GetSecretValue", json!({ "SecretId": "onlyone", "VersionStage": "AWSPREVIOUS" }))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── SecretBinary roundtrip ────────────────────────────────────────────────────

#[tokio::test]
async fn get_secret_created_with_binary_roundtrip() {
    let app = app();
    let raw = b"binary\x00data\xFF";
    let b64 = B64.encode(raw);

    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "binsecret", "SecretBinary": b64 }))).await;

    let (status, body) = common::call(app, amz_req("secretsmanager.GetSecretValue", json!({ "SecretId": "binsecret" }))).await;
    assert_eq!(status, StatusCode::OK);
    // Binary secrets must return SecretBinary, not SecretString
    assert!(body.get("SecretString").is_none(), "binary secrets must not return SecretString");
    let returned_b64 = body["SecretBinary"].as_str().expect("SecretBinary must be present");
    let returned_bytes = B64.decode(returned_b64).unwrap();
    assert_eq!(returned_bytes, raw);
}

#[tokio::test]
async fn put_secret_binary_roundtrip() {
    let app = app();
    let raw = b"\x00\x01\x02\xFF";
    let b64 = B64.encode(raw);

    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "binput", "SecretString": "initial" }))).await;
    common::call(app.clone(), amz_req("secretsmanager.PutSecretValue", json!({ "SecretId": "binput", "SecretBinary": b64 }))).await;

    let (status, body) = common::call(app, amz_req("secretsmanager.GetSecretValue", json!({ "SecretId": "binput" }))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.get("SecretString").is_none());
    let back = B64.decode(body["SecretBinary"].as_str().unwrap()).unwrap();
    assert_eq!(back, raw);
}

// ── missing secret → ResourceNotFoundException ────────────────────────────────

#[tokio::test]
async fn missing_secret_returns_resource_not_found() {
    let (status, body) = common::call(app(), amz_req("secretsmanager.GetSecretValue", json!({ "SecretId": "does-not-exist" }))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["__type"], "ResourceNotFoundException");
}

// ── ListSecrets ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_secrets() {
    let app = app();
    for name in &["listme1", "listme2"] {
        common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": name, "SecretString": "value" }))).await;
    }

    let (status, body) = common::call(app, amz_req("secretsmanager.ListSecrets", json!({}))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["SecretList"].is_array());
    assert!(body["NextToken"].is_null());
}

#[tokio::test]
async fn list_secrets_pagination() {
    let app = app();
    for i in 0..5u8 {
        common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": format!("page{i}"), "SecretString": "v" }))).await;
    }

    // First page: 3 items
    let (status, body) = common::call(app.clone(), amz_req("secretsmanager.ListSecrets", json!({ "MaxResults": 3 }))).await;
    assert_eq!(status, StatusCode::OK);
    let page1 = body["SecretList"].as_array().unwrap();
    assert_eq!(page1.len(), 3);
    let token = body["NextToken"].as_str().expect("NextToken must be set after partial page");

    // Second page using the token
    let (status2, body2) = common::call(app, amz_req("secretsmanager.ListSecrets", json!({ "MaxResults": 3, "NextToken": token }))).await;
    assert_eq!(status2, StatusCode::OK);
    let page2 = body2["SecretList"].as_array().unwrap();
    assert_eq!(page2.len(), 2, "remaining 2 items on second page");
    assert!(body2["NextToken"].is_null(), "no more pages");
}

// ── ListSecretVersionIds ──────────────────────────────────────────────────────

#[tokio::test]
async fn list_secret_version_ids() {
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "versioned", "SecretString": "v1" }))).await;
    common::call(app.clone(), amz_req("secretsmanager.PutSecretValue", json!({ "SecretId": "versioned", "SecretString": "v2" }))).await;
    common::call(app.clone(), amz_req("secretsmanager.PutSecretValue", json!({ "SecretId": "versioned", "SecretString": "v3" }))).await;

    let (status, body) = common::call(app, amz_req("secretsmanager.ListSecretVersionIds", json!({ "SecretId": "versioned" }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["Name"], "versioned");
    assert!(body["ARN"].is_string());

    let versions = body["Versions"].as_array().unwrap();
    assert_eq!(versions.len(), 3);

    let current_count = versions.iter().filter(|v| {
        v["VersionStages"].as_array().unwrap().iter().any(|s| s == "AWSCURRENT")
    }).count();
    assert_eq!(current_count, 1);

    let prev_count = versions.iter().filter(|v| {
        v["VersionStages"].as_array().unwrap().iter().any(|s| s == "AWSPREVIOUS")
    }).count();
    assert_eq!(prev_count, 1);
}

// ── DescribeSecret ────────────────────────────────────────────────────────────

#[tokio::test]
async fn describe_secret_no_value() {
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "describeme", "SecretString": "secret" }))).await;

    let (status, body) = common::call(app, amz_req("secretsmanager.DescribeSecret", json!({ "SecretId": "describeme" }))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["ARN"].is_string());
    assert_eq!(body["Name"], "describeme");
    assert!(body.get("SecretString").is_none(), "DescribeSecret must not return SecretString");
    assert!(body["VersionIdsToStages"].is_object());
    assert!(body["CreatedDate"].is_number());
    assert!(body["LastChangedDate"].is_number());
}

// ── PutSecretValue ────────────────────────────────────────────────────────────

#[tokio::test]
async fn put_secret_value_creates_new_version() {
    let app = app();
    let (_, c_body) = common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "putme", "SecretString": "v1" }))).await;
    let v1_id = c_body["VersionId"].as_str().unwrap().to_string();

    let (status, p_body) = common::call(app.clone(), amz_req("secretsmanager.PutSecretValue", json!({ "SecretId": "putme", "SecretString": "v2" }))).await;
    assert_eq!(status, StatusCode::OK);
    let v2_id = p_body["VersionId"].as_str().unwrap().to_string();
    assert_ne!(v1_id, v2_id, "PutSecretValue must produce a new VersionId");

    let (_, g_body) = common::call(app, amz_req("secretsmanager.GetSecretValue", json!({ "SecretId": "putme" }))).await;
    assert_eq!(g_body["SecretString"], "v2");
}

// ── UpdateSecret ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn update_secret_description_only_no_new_version() {
    let app = app();
    let (_, c_body) = common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "updesc", "SecretString": "val" }))).await;
    let original_version_id = c_body["VersionId"].as_str().unwrap().to_string();

    let (status, u_body) = common::call(app.clone(), amz_req("secretsmanager.UpdateSecret", json!({ "SecretId": "updesc", "Description": "my desc" }))).await;
    assert_eq!(status, StatusCode::OK);
    // No value update → same VersionId
    assert_eq!(u_body["VersionId"].as_str().unwrap(), original_version_id);

    let (_, d_body) = common::call(app, amz_req("secretsmanager.DescribeSecret", json!({ "SecretId": "updesc" }))).await;
    assert_eq!(d_body["Description"], "my desc");
}

#[tokio::test]
async fn update_secret_value_creates_new_version() {
    let app = app();
    let (_, c_body) = common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "upval", "SecretString": "old" }))).await;
    let original_version_id = c_body["VersionId"].as_str().unwrap().to_string();

    let (status, u_body) = common::call(app.clone(), amz_req("secretsmanager.UpdateSecret", json!({ "SecretId": "upval", "SecretString": "new" }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(u_body["VersionId"].as_str().unwrap(), original_version_id);

    let (_, g_body) = common::call(app, amz_req("secretsmanager.GetSecretValue", json!({ "SecretId": "upval" }))).await;
    assert_eq!(g_body["SecretString"], "new");
}

// ── DeleteSecret + RestoreSecret ─────────────────────────────────────────────

#[tokio::test]
async fn delete_secret_then_not_found() {
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "delme", "SecretString": "bye" }))).await;

    let (status, body) = common::call(app.clone(), amz_req("secretsmanager.DeleteSecret", json!({ "SecretId": "delme" }))).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["DeletionDate"].is_number());

    let (status2, body2) = common::call(app, amz_req("secretsmanager.GetSecretValue", json!({ "SecretId": "delme" }))).await;
    assert_eq!(status2, StatusCode::NOT_FOUND);
    assert_eq!(body2["__type"], "ResourceNotFoundException");
}

#[tokio::test]
async fn restore_secret_after_delete() {
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "restore_me", "SecretString": "alive" }))).await;
    common::call(app.clone(), amz_req("secretsmanager.DeleteSecret", json!({ "SecretId": "restore_me" }))).await;

    let (status, body) = common::call(app.clone(), amz_req("secretsmanager.RestoreSecret", json!({ "SecretId": "restore_me" }))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["Name"], "restore_me");

    // Secret should be retrievable again
    let (status2, body2) = common::call(app, amz_req("secretsmanager.GetSecretValue", json!({ "SecretId": "restore_me" }))).await;
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(body2["SecretString"], "alive");
}

#[tokio::test]
async fn restore_non_deleted_secret_returns_not_found() {
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "notdel", "SecretString": "v" }))).await;

    let (status, _) = common::call(app, amz_req("secretsmanager.RestoreSecret", json!({ "SecretId": "notdel" }))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ── BatchGetSecretValue ───────────────────────────────────────────────────────

#[tokio::test]
async fn batch_get_secret_value_mixed() {
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "batch1", "SecretString": "s1" }))).await;
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "batch2", "SecretString": "s2" }))).await;

    let (status, body) = common::call(app, amz_req("secretsmanager.BatchGetSecretValue", json!({
        "SecretIdList": ["batch1", "batch2", "missing"]
    }))).await;
    assert_eq!(status, StatusCode::OK);

    let values = body["SecretValues"].as_array().unwrap();
    assert_eq!(values.len(), 2);
    assert!(values.iter().any(|v| v["Name"] == "batch1" && v["SecretString"] == "s1"));
    assert!(values.iter().any(|v| v["Name"] == "batch2" && v["SecretString"] == "s2"));

    let errors = body["Errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["ErrorCode"], "ResourceNotFoundException");
}

#[tokio::test]
async fn batch_get_secret_value_binary() {
    let app = app();
    let raw = b"\xDE\xAD\xBE\xEF";
    let b64 = B64.encode(raw);
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "batchbin", "SecretBinary": b64 }))).await;

    let (status, body) = common::call(app, amz_req("secretsmanager.BatchGetSecretValue", json!({ "SecretIdList": ["batchbin"] }))).await;
    assert_eq!(status, StatusCode::OK);
    let values = body["SecretValues"].as_array().unwrap();
    assert!(values[0].get("SecretString").is_none());
    let back = B64.decode(values[0]["SecretBinary"].as_str().unwrap()).unwrap();
    assert_eq!(back, raw);
}

// ── RotateSecret ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn rotate_secret_increments_version() {
    let app = app();
    let (_, c_body) = common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "rotateme", "SecretString": "original" }))).await;
    let v1_id = c_body["VersionId"].as_str().unwrap().to_string();

    let (status, r_body) = common::call(app.clone(), amz_req("secretsmanager.RotateSecret", json!({ "SecretId": "rotateme" }))).await;
    assert_eq!(status, StatusCode::OK);
    let new_version_id = r_body["VersionId"].as_str().unwrap();
    assert_ne!(new_version_id, v1_id, "RotateSecret must produce a new VersionId");

    // Value is still readable
    let (_, g_body) = common::call(app, amz_req("secretsmanager.GetSecretValue", json!({ "SecretId": "rotateme" }))).await;
    assert_eq!(g_body["SecretString"], "original");
}

// ── TagResource / UntagResource ───────────────────────────────────────────────

#[tokio::test]
async fn tag_and_untag_resource() {
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "tagme", "SecretString": "v" }))).await;

    common::call(app.clone(), amz_req("secretsmanager.TagResource", json!({
        "SecretId": "tagme",
        "Tags": [{"Key": "env", "Value": "staging"}]
    }))).await;

    let (_, d) = common::call(app.clone(), amz_req("secretsmanager.DescribeSecret", json!({ "SecretId": "tagme" }))).await;
    let tags = d["Tags"].as_array().unwrap();
    assert!(tags.iter().any(|t| t["Key"] == "env" && t["Value"] == "staging"));

    common::call(app.clone(), amz_req("secretsmanager.UntagResource", json!({
        "SecretId": "tagme",
        "TagKeys": ["env"]
    }))).await;

    let (_, d2) = common::call(app, amz_req("secretsmanager.DescribeSecret", json!({ "SecretId": "tagme" }))).await;
    let tags2 = d2["Tags"].as_array().unwrap();
    assert!(!tags2.iter().any(|t| t["Key"] == "env"));
}

// ── GetRandomPassword ─────────────────────────────────────────────────────────

#[tokio::test]
async fn get_random_password() {
    let (status, body) = common::call(app(), amz_req("secretsmanager.GetRandomPassword", json!({ "PasswordLength": 20 }))).await;
    assert_eq!(status, StatusCode::OK);
    let pw = body["RandomPassword"].as_str().expect("RandomPassword should be a string");
    assert_eq!(pw.len(), 20);
}

// ── ARN region/account env override ──────────────────────────────────────────

#[tokio::test]
async fn arn_uses_env_var_region_and_account() {
    std::env::set_var("SECRETD_AWS_REGION", "eu-west-1");
    std::env::set_var("SECRETD_AWS_ACCOUNT_ID", "999999999999");
    let app = app();
    common::call(app.clone(), amz_req("secretsmanager.CreateSecret", json!({ "Name": "arntest", "SecretString": "v" }))).await;
    let (_, body) = common::call(app, amz_req("secretsmanager.DescribeSecret", json!({ "SecretId": "arntest" }))).await;
    let arn = body["ARN"].as_str().unwrap();
    assert!(arn.contains("eu-west-1"), "ARN should reflect SECRETD_AWS_REGION");
    assert!(arn.contains("999999999999"), "ARN should reflect SECRETD_AWS_ACCOUNT_ID");
    std::env::remove_var("SECRETD_AWS_REGION");
    std::env::remove_var("SECRETD_AWS_ACCOUNT_ID");
}

// ── Error cases ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn unknown_target_returns_invalid_request() {
    let (status, body) = common::call(app(), amz_req("secretsmanager.FakeAction", json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "InvalidRequestException");
}

#[tokio::test]
async fn missing_auth_header_rejected() {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/")
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Target", "secretsmanager.ListSecrets")
        .body(axum::body::Body::from(b"{}".to_vec()))
        .unwrap();
    let (status, _) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn batch_get_requires_secret_id_list() {
    let (status, body) = common::call(app(), amz_req("secretsmanager.BatchGetSecretValue", json!({}))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["__type"], "InvalidRequestException");
}

// ── auth: must present a verifiable credential (no SigV4 pass-through) ──────────

#[tokio::test]
async fn rejects_sigv4_with_unknown_access_key_id() {
    // A well-formed SigV4 header whose access-key-id is NOT a valid credential
    // must be rejected — the old prefix-only pass-through is gone.
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/")
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Target", "secretsmanager.ListSecrets")
        .header(
            "Authorization",
            "AWS4-HMAC-SHA256 Credential=boguskey/20240101/us-east-1/secretsmanager/aws4_request",
        )
        .body(axum::body::Body::from(serde_json::to_vec(&json!({})).unwrap()))
        .unwrap();
    let (status, _body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rejects_missing_credentials() {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/")
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("X-Amz-Target", "secretsmanager.ListSecrets")
        .body(axum::body::Body::from(serde_json::to_vec(&json!({})).unwrap()))
        .unwrap();
    let (status, _body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
