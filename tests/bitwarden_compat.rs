//! Bitwarden Public API wire-compatibility integration tests.
mod common;

use axum::http::StatusCode;
use opensourcepasswordmanager::api::bitwarden::router::bitwarden_router;
use serde_json::json;

fn app() -> axum::Router {
    bitwarden_router(common::make_app_state())
}

// ── OAuth2 token ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn token_endpoint_accepts_form_encoded() {
    let body = "grant_type=client_credentials&client_id=org.00000000-0000-0000-0000-000000000001&client_secret=test-secret&scope=api.organization";
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/identity/connect/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body.as_bytes().to_vec()))
        .unwrap();

    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["access_token"].is_string(), "access_token should be present");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 3600);
}

#[tokio::test]
async fn token_endpoint_rejects_empty_client_id() {
    let body = "grant_type=client_credentials&client_id=&client_secret=test-secret&scope=api.organization";
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/identity/connect/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body.as_bytes().to_vec()))
        .unwrap();

    let (status, _) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn token_endpoint_rejects_empty_client_secret() {
    let body = "grant_type=client_credentials&client_id=org.test&client_secret=&scope=api.organization";
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/identity/connect/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(axum::body::Body::from(body.as_bytes().to_vec()))
        .unwrap();

    let (status, _) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ── collections list ──────────────────────────────────────────────────────────

#[tokio::test]
async fn collections_list_shape() {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/api/public/collections")
        .header("Authorization", "Bearer test-token")
        .body(axum::body::Body::empty())
        .unwrap();

    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object"], "list");
    assert!(body["data"].is_array(), "data should be array");
    assert_eq!(body["continuationToken"], serde_json::Value::Null);
}

// ── events list ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn events_list_shape() {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/api/public/events")
        .header("Authorization", "Bearer test-token")
        .body(axum::body::Body::empty())
        .unwrap();

    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object"], "list");
    assert!(body["data"].is_array(), "data should be array");
    assert_eq!(body["continuationToken"], serde_json::Value::Null);
}

// ── create collection ─────────────────────────────────────────────────────────

#[tokio::test]
async fn create_collection_returns_collection_object() {
    let req = axum::http::Request::builder()
        .method("POST")
        .uri("/api/public/collections")
        .header("Content-Type", "application/json")
        .header("Authorization", "Bearer test-token")
        .body(axum::body::Body::from(
            serde_json::to_vec(&json!({ "name": "MyCollection", "groups": [] })).unwrap(),
        ))
        .unwrap();

    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object"], "collection");
    assert_eq!(body["name"], "MyCollection");
    assert!(body["id"].is_string());
}

// ── policies list ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn policies_list_shape() {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/api/public/policies")
        .header("Authorization", "Bearer test-token")
        .body(axum::body::Body::empty())
        .unwrap();

    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object"], "list");
    assert!(body["data"].is_array());
}

// ── members list ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn members_list_shape() {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/api/public/members")
        .header("Authorization", "Bearer test-token")
        .body(axum::body::Body::empty())
        .unwrap();

    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["object"], "list");
    assert!(body["data"].is_array());
}
