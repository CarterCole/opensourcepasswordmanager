//! Cloudflare Secrets Store wire-compatibility integration tests.
mod common;

use axum::http::StatusCode;
use opensourcepasswordmanager::api::cloudflare::router::cf_router;
use serde_json::json;

fn app() -> axum::Router {
    cf_router(common::make_app_state())
}

fn cf_req(
    method: &str,
    uri: &str,
    body: serde_json::Value,
) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .header("X-Auth-Email", "test@example.com")
        .header("X-Auth-Key", "test-token")
        .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

/// Verify Cloudflare envelope shape: {success, errors, messages, result}
fn assert_cf_envelope(body: &serde_json::Value) {
    assert_eq!(body["success"], true, "success should be true: {body}");
    assert!(body["errors"].is_array(), "errors should be array: {body}");
    assert!(body["messages"].is_array(), "messages should be array: {body}");
}

// ── envelope shape ────────────────────────────────────────────────────────────

#[tokio::test]
async fn all_responses_wrapped_in_cf_envelope() {
    let req = cf_req(
        "GET",
        "/v4/accounts/acct123/secrets_store/stores",
        json!(null),
    );
    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_cf_envelope(&body);
}

// ── create store and list ─────────────────────────────────────────────────────

#[tokio::test]
async fn create_store_and_list() {
    let app = app();

    // Create store
    let create = cf_req(
        "POST",
        "/v4/accounts/acct123/secrets_store/stores",
        json!({ "name": "mystore" }),
    );
    let (cs, cbody) = common::call(app.clone(), create).await;
    assert_eq!(cs, StatusCode::OK);
    assert_cf_envelope(&cbody);
    let result = &cbody["result"];
    assert!(result["id"].is_string());
    assert_eq!(result["name"], "mystore");

    // List stores
    let list = cf_req("GET", "/v4/accounts/acct123/secrets_store/stores", json!(null));
    let (ls, lbody) = common::call(app, list).await;
    assert_eq!(ls, StatusCode::OK);
    assert_cf_envelope(&lbody);
    assert!(lbody["result"].is_array(), "result should be array of stores");
}

// ── batch create secrets ──────────────────────────────────────────────────────

#[tokio::test]
async fn batch_create_secrets() {
    let app = app();

    let batch = cf_req(
        "POST",
        "/v4/accounts/acct123/secrets_store/stores/mystore/secrets",
        json!([
            { "name": "KEY1", "text": "VALUE1" },
            { "name": "KEY2", "text": "VALUE2" }
        ]),
    );
    let (status, body) = common::call(app, batch).await;
    assert_eq!(status, StatusCode::OK);
    assert_cf_envelope(&body);
    let results = body["result"].as_array().expect("result should be array");
    assert_eq!(results.len(), 2, "should have 2 results");
    for r in results {
        assert!(r["id"].is_string());
        assert!(r["name"].is_string());
        assert!(r["status"].is_string());
    }
}

// ── get secret metadata — no value ───────────────────────────────────────────

#[tokio::test]
async fn get_secret_metadata_no_value() {
    let app = app();

    // Create a secret
    let create = cf_req(
        "POST",
        "/v4/accounts/acct123/secrets_store/stores/secretstore/secrets",
        json!([{ "name": "MYKEY", "text": "MYVALUE" }]),
    );
    common::call(app.clone(), create).await;

    // Get metadata
    let get = cf_req(
        "GET",
        "/v4/accounts/acct123/secrets_store/stores/secretstore/secrets/MYKEY",
        json!(null),
    );
    let (status, body) = common::call(app, get).await;
    assert_eq!(status, StatusCode::OK);
    assert_cf_envelope(&body);
    let result = &body["result"];
    assert!(result["id"].is_string());
    assert!(result["name"].is_string());
    assert!(result["status"].is_string());
    // Value should NOT be exposed
    assert!(result.get("text").is_none(), "text should not be in metadata response");
    assert!(result.get("value").is_none(), "value should not be in metadata response");
}

// ── quota endpoint ────────────────────────────────────────────────────────────

#[tokio::test]
async fn quota_endpoint() {
    let req = cf_req("GET", "/v4/accounts/acct123/secrets_store/quota", json!(null));
    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_cf_envelope(&body);
    let result = &body["result"];
    assert!(result["count"].is_number(), "count should be a number");
    assert!(result["limit"].is_number(), "limit should be a number");
}

// ── get non-existent secret → CF error ───────────────────────────────────────

#[tokio::test]
async fn missing_secret_cf_error() {
    let req = cf_req(
        "GET",
        "/v4/accounts/acct123/secrets_store/stores/emptystore/secrets/NOSUCHKEY",
        json!(null),
    );
    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["success"], false, "success should be false for errors");
    assert!(body["errors"].as_array().map(|a| !a.is_empty()).unwrap_or(false));
}

// ── auth: X-Auth-Key must be a verifiable credential ──────────────────────────

#[tokio::test]
async fn rejects_unknown_auth_key() {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v4/accounts/acct123/secrets_store/stores")
        .header("X-Auth-Email", "test@example.com")
        .header("X-Auth-Key", "not-a-real-key")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, _body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rejects_missing_credentials() {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/v4/accounts/acct123/secrets_store/stores")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, _body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
