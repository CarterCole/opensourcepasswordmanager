//! GCP Secret Manager wire-compatibility integration tests.
mod common;

use axum::http::StatusCode;
use opensourcepasswordmanager::api::gcp::router::gcp_router;
use serde_json::json;

fn app() -> axum::Router {
    gcp_router(common::make_app_state())
}

fn bearer_req(
    method: &str,
    uri: &str,
    body: serde_json::Value,
) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer test-token")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

// ── create secret container ───────────────────────────────────────────────────

#[tokio::test]
async fn create_secret_container() {
    let req = bearer_req(
        "POST",
        "/v1/projects/myproject/secrets?secretId=mysecret",
        json!({ "replication": { "automatic": {} } }),
    );
    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "projects/myproject/secrets/mysecret");
    assert!(body["createTime"].is_string());
}

// ── add version and access ────────────────────────────────────────────────────

#[tokio::test]
async fn add_version_and_access_latest() {
    let app = app();
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let hello_b64 = B64.encode(b"hello");

    // Create container
    let create = bearer_req(
        "POST",
        "/v1/projects/myproject/secrets?secretId=versionsecret",
        json!({ "replication": { "automatic": {} } }),
    );
    common::call(app.clone(), create).await;

    // Add version
    let add = bearer_req(
        "POST",
        "/v1/projects/myproject/secrets/versionsecret:addVersion",
        json!({ "payload": { "data": hello_b64 } }),
    );
    let (status, body) = common::call(app.clone(), add).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["name"].as_str().unwrap().contains("/versions/"));
    assert_eq!(body["state"], "ENABLED");

    // Access latest
    let access = bearer_req(
        "GET",
        "/v1/projects/myproject/secrets/versionsecret/versions/latest:access",
        json!(null),
    );
    let (astatus, abody) = common::call(app, access).await;
    assert_eq!(astatus, StatusCode::OK);
    let returned_b64 = abody["payload"]["data"]
        .as_str()
        .expect("payload.data should be string");
    assert_eq!(
        returned_b64, hello_b64,
        "base64 roundtrip should be lossless"
    );
}

// ── access version by number ──────────────────────────────────────────────────

#[tokio::test]
async fn access_version_by_number() {
    let app = app();
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let payload_b64 = B64.encode(b"version-data");

    // Create container
    let create = bearer_req(
        "POST",
        "/v1/projects/myproject/secrets?secretId=numversiontest",
        json!({ "replication": { "automatic": {} } }),
    );
    common::call(app.clone(), create).await;

    // Add a version — capture the version number from the response
    let add = bearer_req(
        "POST",
        "/v1/projects/myproject/secrets/numversiontest:addVersion",
        json!({ "payload": { "data": payload_b64 } }),
    );
    let (_, add_body) = common::call(app.clone(), add).await;

    // Extract version number from response name like "projects/p/secrets/s/versions/N"
    let ver_name = add_body["name"]
        .as_str()
        .expect("name should be in addVersion response");
    let version_num = ver_name
        .split('/')
        .last()
        .expect("version number should be last segment");

    // Access by the returned version number
    let uri =
        format!("/v1/projects/myproject/secrets/numversiontest/versions/{version_num}:access");
    let access = bearer_req("GET", &uri, json!(null));
    let (status, body) = common::call(app, access).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["payload"]["data"], payload_b64);
}

// ── list secrets ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_secrets() {
    let app = app();

    // Create two secrets
    for name in &["listsecret1", "listsecret2"] {
        let create = bearer_req(
            "POST",
            &format!("/v1/projects/myproject/secrets?secretId={name}"),
            json!({ "replication": { "automatic": {} } }),
        );
        common::call(app.clone(), create).await;
    }

    let list = bearer_req("GET", "/v1/projects/myproject/secrets", json!(null));
    let (status, body) = common::call(app, list).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["secrets"].is_array(), "secrets should be array");
    assert!(body["nextPageToken"].is_string());
}

// ── missing secret → GCP error shape ─────────────────────────────────────────

#[tokio::test]
async fn missing_secret_returns_gcp_error_shape() {
    let req = bearer_req(
        "GET",
        "/v1/projects/myproject/secrets/no-such-secret",
        json!(null),
    );
    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].is_object(), "should have error object");
    assert_eq!(body["error"]["code"], 404);
    assert_eq!(body["error"]["status"], "NOT_FOUND");
    assert!(body["error"]["message"].is_string());
}

// ── binary value roundtrip ────────────────────────────────────────────────────

#[tokio::test]
async fn binary_value_roundtrip() {
    let app = app();
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    // Arbitrary binary data including null bytes
    let raw = vec![0x00u8, 0xFF, 0x42, 0x00, 0xDE, 0xAD, 0xBE, 0xEF];
    let b64 = B64.encode(&raw);

    let create = bearer_req(
        "POST",
        "/v1/projects/myproject/secrets?secretId=binarysecret",
        json!({ "replication": { "automatic": {} } }),
    );
    common::call(app.clone(), create).await;

    let add = bearer_req(
        "POST",
        "/v1/projects/myproject/secrets/binarysecret:addVersion",
        json!({ "payload": { "data": b64 } }),
    );
    common::call(app.clone(), add).await;

    let access = bearer_req(
        "GET",
        "/v1/projects/myproject/secrets/binarysecret/versions/latest:access",
        json!(null),
    );
    let (status, body) = common::call(app, access).await;
    assert_eq!(status, StatusCode::OK);
    let got = body["payload"]["data"]
        .as_str()
        .expect("data should be base64 string");
    let decoded = B64.decode(got).expect("should decode to valid bytes");
    assert_eq!(decoded, raw, "binary roundtrip should be lossless");
}
