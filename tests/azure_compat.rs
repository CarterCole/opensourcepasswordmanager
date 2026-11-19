//! Azure Key Vault wire-compatibility integration tests.
mod common;

use axum::http::StatusCode;
use opensourcepasswordmanager::api::azure::router::azure_router;
use serde_json::json;

fn app() -> axum::Router {
    azure_router(common::make_app_state())
}

fn az_req(
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

// ── set and get secret ────────────────────────────────────────────────────────

#[tokio::test]
async fn set_and_get_secret() {
    let app = app();

    let put = az_req(
        "PUT",
        "/myvault/secrets/mykey?api-version=7.4",
        json!({ "value": "supersecret", "attributes": {} }),
    );
    let (put_status, put_body) = common::call(app.clone(), put).await;
    assert_eq!(put_status, StatusCode::OK);
    assert_eq!(put_body["value"], "supersecret");
    assert!(put_body["id"].is_string());
    assert!(put_body["attributes"]["enabled"].as_bool().unwrap_or(false));
    assert!(put_body["attributes"]["created"].is_number());
    assert!(put_body["attributes"]["updated"].is_number());

    // GET
    let get = az_req("GET", "/myvault/secrets/mykey?api-version=7.4", json!(null));
    let (get_status, get_body) = common::call(app, get).await;
    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(get_body["value"], "supersecret");
    assert!(get_body["id"].is_string());
}

// ── secret ID is a URL ────────────────────────────────────────────────────────

#[tokio::test]
async fn secret_id_is_url_format() {
    let app = app();

    let put = az_req(
        "PUT",
        "/myvault/secrets/urltest",
        json!({ "value": "hello" }),
    );
    let (_, body) = common::call(app, put).await;
    let id = body["id"].as_str().expect("id should be a string");
    assert!(
        id.starts_with("http://"),
        "id should be a full URL, got: {id}"
    );
    assert!(
        id.contains("/myvault/secrets/urltest/"),
        "id should contain vault path"
    );
}

// ── list secrets — no values ──────────────────────────────────────────────────

#[tokio::test]
async fn list_secrets_no_values() {
    let app = app();

    // Write a secret
    let put = az_req(
        "PUT",
        "/myvault/secrets/listablekey",
        json!({ "value": "hidden" }),
    );
    common::call(app.clone(), put).await;

    // List
    let list = az_req("GET", "/myvault/secrets?api-version=7.4", json!(null));
    let (status, body) = common::call(app, list).await;
    assert_eq!(status, StatusCode::OK);
    let items = body["value"].as_array().expect("value should be array");
    assert!(!items.is_empty(), "list should contain at least one item");

    // Items must NOT have a "value" field
    for item in items {
        assert!(
            item.get("value").is_none(),
            "list items should not expose value: {item}"
        );
        assert!(item["id"].is_string(), "list items should have id");
        assert!(
            item["attributes"].is_object(),
            "list items should have attributes"
        );
    }
    assert_eq!(body["nextLink"], serde_json::Value::Null);
}

// ── missing secret → SecretNotFound ──────────────────────────────────────────

#[tokio::test]
async fn missing_secret_returns_azure_error_shape() {
    let req = az_req("GET", "/myvault/secrets/nope?api-version=7.4", json!(null));
    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "SecretNotFound");
    assert!(body["error"]["message"].is_string());
}

// ── api-version parameter is ignored (works without it) ──────────────────────

#[tokio::test]
async fn api_version_param_is_optional() {
    let app = app();

    let put = az_req(
        "PUT",
        "/myvault/secrets/noversiontest",
        json!({ "value": "test" }),
    );
    let (status, _) = common::call(app, put).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "should work without api-version param"
    );
}

// ── delete secret ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn delete_then_get_returns_not_found() {
    let app = app();

    // Create
    let put = az_req(
        "PUT",
        "/myvault/secrets/deletablekey",
        json!({ "value": "temporary" }),
    );
    common::call(app.clone(), put).await;

    // Delete
    let del = az_req("DELETE", "/myvault/secrets/deletablekey", json!(null));
    let (del_status, _) = common::call(app.clone(), del).await;
    assert_eq!(del_status, StatusCode::OK);

    // Get should return 404
    let get = az_req("GET", "/myvault/secrets/deletablekey", json!(null));
    let (get_status, _) = common::call(app, get).await;
    assert_eq!(get_status, StatusCode::NOT_FOUND);
}

// ── list secret versions ──────────────────────────────────────────────────────

#[tokio::test]
async fn list_secret_versions() {
    let app = app();

    // Write 3 times to create 3 versions
    for v in 1..=3 {
        let put = az_req(
            "PUT",
            "/myvault/secrets/multiver",
            json!({ "value": format!("version{v}") }),
        );
        common::call(app.clone(), put).await;
    }

    // List versions
    let list = az_req("GET", "/myvault/secrets/multiver/versions", json!(null));
    let (status, body) = common::call(app, list).await;
    assert_eq!(status, StatusCode::OK);
    let versions = body["value"].as_array().expect("value should be array");
    // Versions list should have items without value field
    for ver in versions {
        assert!(
            ver.get("value").is_none(),
            "version items should not expose value"
        );
        assert!(ver["id"].is_string(), "version items should have id");
    }
}
