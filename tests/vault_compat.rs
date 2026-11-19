//! Vault / OpenBao KV v2 wire-compatibility integration tests.
mod common;

use axum::http::StatusCode;
use opensourcepasswordmanager::api::vault::router::vault_router;
use serde_json::json;

fn app() -> axum::Router {
    vault_router(common::make_vault_state())
}

// ── sys/health ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_check_no_auth() {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/sys/health")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["initialized"], true);
    assert_eq!(body["sealed"], false);
    assert_eq!(body["standby"], false);
}

// ── write then read ───────────────────────────────────────────────────────────

#[tokio::test]
async fn write_then_read() {
    let app = app();

    // Write
    let write_req = common::json_req(
        "POST",
        "/secret/data/myapp",
        json!({ "data": { "db_pass": "hunter2" } }),
    );
    let (ws, _) = common::call(app.clone(), write_req).await;
    assert_eq!(ws, StatusCode::OK);

    // Read
    let read_req = common::json_req("GET", "/secret/data/myapp", json!(null));
    let (rs, body) = common::call(app, read_req).await;
    assert_eq!(rs, StatusCode::OK);
    assert_eq!(body["data"]["data"]["db_pass"], "hunter2");
}

// ── response envelope shape ───────────────────────────────────────────────────

#[tokio::test]
async fn response_envelope_shape() {
    let app = app();

    let write_req = common::json_req(
        "POST",
        "/secret/data/envelopetest",
        json!({ "data": { "key": "value" } }),
    );
    common::call(app.clone(), write_req).await;

    let read_req = common::json_req("GET", "/secret/data/envelopetest", json!(null));
    let (status, body) = common::call(app, read_req).await;
    assert_eq!(status, StatusCode::OK);

    // Top-level envelope fields
    assert!(body["lease_id"].is_string());
    assert!(body["renewable"].is_boolean());
    assert!(body["lease_duration"].is_number());

    // data.data contains the KV map
    assert!(body["data"]["data"].is_object());

    // data.metadata
    let meta = &body["data"]["metadata"];
    assert!(meta["version"].is_number());
    assert!(meta["created_time"].is_string());
    assert!(meta["destroyed"].is_boolean());
}

// ── 404 for missing secret ────────────────────────────────────────────────────

#[tokio::test]
async fn read_missing_returns_404_with_errors_array() {
    let req = common::json_req("GET", "/secret/data/does-not-exist", json!(null));
    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // Vault error shape: {"errors": [...]}
    assert!(body["errors"].is_array(), "errors should be an array, got: {body}");
}

// ── list secrets ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_secrets() {
    let app = app();

    // Write two secrets under the same folder
    for key in &["foo/a", "foo/b"] {
        let req = common::json_req(
            "POST",
            &format!("/secret/data/{key}"),
            json!({ "data": { "val": key } }),
        );
        common::call(app.clone(), req).await;
    }

    let list_req = common::json_req("GET", "/secret/metadata/foo?list=true", json!(null));
    let (status, body) = common::call(app, list_req).await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["data"]["keys"].as_array().expect("keys should be array");
    let names: Vec<&str> = keys.iter().filter_map(|v| v.as_str()).collect();
    assert!(names.contains(&"a"), "expected 'a' in keys: {names:?}");
    assert!(names.contains(&"b"), "expected 'b' in keys: {names:?}");
}

// ── missing token → 403 ───────────────────────────────────────────────────────

#[tokio::test]
async fn missing_token_returns_403() {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/secret/data/anything")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, _) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── wrong token → 403 ────────────────────────────────────────────────────────

#[tokio::test]
async fn wrong_token_returns_403() {
    let req = axum::http::Request::builder()
        .method("GET")
        .uri("/secret/data/anything")
        .header("X-Vault-Token", "wrong-token")
        .body(axum::body::Body::empty())
        .unwrap();
    let (status, _) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ── multiple versions ─────────────────────────────────────────────────────────

#[tokio::test]
async fn write_multiple_versions() {
    let app = app();

    // Write v1
    let r1 = common::json_req(
        "POST",
        "/secret/data/versioned",
        json!({ "data": { "val": "v1" } }),
    );
    common::call(app.clone(), r1).await;

    // Write v2
    let r2 = common::json_req(
        "POST",
        "/secret/data/versioned",
        json!({ "data": { "val": "v2" } }),
    );
    common::call(app.clone(), r2).await;

    // Read latest → v2
    let latest = common::json_req("GET", "/secret/data/versioned", json!(null));
    let (_, body) = common::call(app.clone(), latest).await;
    assert_eq!(body["data"]["data"]["val"], "v2");
    assert_eq!(body["data"]["metadata"]["version"], 2);

    // Read version 1 explicitly
    let v1_req = common::json_req("GET", "/secret/data/versioned?version=1", json!(null));
    let (_, v1_body) = common::call(app, v1_req).await;
    assert_eq!(v1_body["data"]["data"]["val"], "v1");
    assert_eq!(v1_body["data"]["metadata"]["version"], 1);
}

// ── soft delete and undelete ──────────────────────────────────────────────────

#[tokio::test]
async fn soft_delete_marks_deletion_time() {
    let app = app();

    // Write
    let write = common::json_req(
        "POST",
        "/secret/data/deleteme",
        json!({ "data": { "val": "secret" } }),
    );
    common::call(app.clone(), write).await;

    // Soft-delete latest
    let del = axum::http::Request::builder()
        .method("DELETE")
        .uri("/secret/data/deleteme")
        .header("X-Vault-Token", "test-token")
        .body(axum::body::Body::empty())
        .unwrap();
    let (del_status, _) = common::call(app.clone(), del).await;
    assert_eq!(del_status, StatusCode::NO_CONTENT);

    // Read → version still accessible but deletion_time set
    let read = common::json_req("GET", "/secret/data/deleteme", json!(null));
    let (_, body) = common::call(app.clone(), read).await;
    let deletion_time = body["data"]["metadata"]["deletion_time"]
        .as_str()
        .unwrap_or("");
    assert!(!deletion_time.is_empty(), "deletion_time should be set after delete");

    // Undelete version 1
    let undelete = common::json_req(
        "POST",
        "/secret/undelete/deleteme",
        json!({ "versions": [1] }),
    );
    let (ud_status, _) = common::call(app.clone(), undelete).await;
    assert_eq!(ud_status, StatusCode::NO_CONTENT);

    // Read → deletion_time cleared
    let read2 = common::json_req("GET", "/secret/data/deleteme", json!(null));
    let (_, body2) = common::call(app, read2).await;
    let dt2 = body2["data"]["metadata"]["deletion_time"]
        .as_str()
        .unwrap_or("");
    assert!(dt2.is_empty(), "deletion_time should be empty after undelete, got: {dt2}");
}

// ── sys/mounts ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sys_mounts_returns_data_object() {
    let req = common::json_req("GET", "/sys/mounts", json!(null));
    let (status, body) = common::call(app(), req).await;
    assert_eq!(status, StatusCode::OK);
    // data should be an object (may be empty if no mounts configured)
    assert!(body["data"].is_object(), "data should be an object");
}

// ── namespaces ────────────────────────────────────────────────────────────────

fn ns_req(method: &str, uri: &str, ns: Option<&str>, body: serde_json::Value) -> axum::http::Request<axum::body::Body> {
    let mut b = axum::http::Request::builder()
        .method(method)
        .uri(uri)
        .header("Content-Type", "application/json")
        .header("X-Vault-Token", "test-token");
    if let Some(ns) = ns {
        b = b.header("X-Vault-Namespace", ns);
    }
    b.body(axum::body::Body::from(serde_json::to_vec(&body).unwrap())).unwrap()
}

async fn create_ns(app: &axum::Router, path: &str, ns: Option<&str>) -> StatusCode {
    let (s, _) = common::call(app.clone(), ns_req("POST", &format!("/sys/namespaces/{path}"), ns, json!({}))).await;
    s
}

#[tokio::test]
async fn namespace_create_read_list_delete() {
    let app = app();
    assert_eq!(create_ns(&app, "team-a", None).await, StatusCode::OK);

    let (s, body) = common::call(app.clone(), ns_req("GET", "/sys/namespaces/team-a", None, json!(null))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["data"]["path"], "team-a/");

    let (s, body) = common::call(app.clone(), ns_req("GET", "/sys/namespaces?list=true", None, json!(null))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["data"]["keys"], json!(["team-a/"]));

    let (s, _) = common::call(app.clone(), ns_req("DELETE", "/sys/namespaces/team-a", None, json!(null))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = common::call(app.clone(), ns_req("GET", "/sys/namespaces/team-a", None, json!(null))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn namespace_rejects_reserved_and_duplicate_and_orphan() {
    let app = app();
    assert_eq!(create_ns(&app, "sys", None).await, StatusCode::BAD_REQUEST);
    assert_eq!(create_ns(&app, "bad%20name", None).await, StatusCode::BAD_REQUEST);
    assert_eq!(create_ns(&app, "a", None).await, StatusCode::OK);
    assert_eq!(create_ns(&app, "a", None).await, StatusCode::BAD_REQUEST);
    // parent "x" doesn't exist
    assert_eq!(create_ns(&app, "x/y", None).await, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn namespace_secrets_are_isolated_via_header() {
    let app = app();
    create_ns(&app, "team-a", None).await;
    create_ns(&app, "team-b", None).await;

    let w = ns_req("POST", "/secret/data/db", Some("team-a"), json!({"data": {"pw": "a-secret"}}));
    assert_eq!(common::call(app.clone(), w).await.0, StatusCode::OK);

    let (s, body) = common::call(app.clone(), ns_req("GET", "/secret/data/db", Some("team-a"), json!(null))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["data"]["data"]["pw"], "a-secret");

    // Not visible from a sibling namespace or from root.
    let (s, _) = common::call(app.clone(), ns_req("GET", "/secret/data/db", Some("team-b"), json!(null))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = common::call(app.clone(), ns_req("GET", "/secret/data/db", None, json!(null))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn namespace_via_path_prefix_matches_header() {
    let app = app();
    create_ns(&app, "team-a", None).await;
    let w = ns_req("POST", "/team-a/secret/data/db", None, json!({"data": {"pw": "x"}}));
    assert_eq!(common::call(app.clone(), w).await.0, StatusCode::OK);
    let (s, body) = common::call(app.clone(), ns_req("GET", "/secret/data/db", Some("team-a"), json!(null))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["data"]["data"]["pw"], "x");
}

#[tokio::test]
async fn nested_namespaces_and_relative_creation() {
    let app = app();
    create_ns(&app, "team-a", None).await;
    // created relative to the header namespace
    assert_eq!(create_ns(&app, "prod", Some("team-a")).await, StatusCode::OK);
    // and via path prefix
    let (s, _) = common::call(app.clone(), ns_req("POST", "/team-a/sys/namespaces/staging", None, json!({}))).await;
    assert_eq!(s, StatusCode::OK);

    let w = ns_req("POST", "/team-a/prod/secret/data/k", None, json!({"data": {"v": "1"}}));
    assert_eq!(common::call(app.clone(), w).await.0, StatusCode::OK);
    let (s, _) = common::call(app.clone(), ns_req("GET", "/secret/data/k", Some("team-a/prod"), json!(null))).await;
    assert_eq!(s, StatusCode::OK);

    // parent can't be deleted while it has children; child can
    let (s, _) = common::call(app.clone(), ns_req("DELETE", "/sys/namespaces/team-a", None, json!(null))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, body) = common::call(app.clone(), ns_req("GET", "/sys/namespaces?list=true", Some("team-a"), json!(null))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body["data"]["keys"], json!(["prod/", "staging/"]));
}

#[tokio::test]
async fn nonempty_namespace_cannot_be_deleted() {
    let app = app();
    create_ns(&app, "team-a", None).await;
    common::call(app.clone(), ns_req("POST", "/secret/data/k", Some("team-a"), json!({"data": {"v": "1"}}))).await;
    let (s, _) = common::call(app.clone(), ns_req("DELETE", "/sys/namespaces/team-a", None, json!(null))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_namespace_header_is_404() {
    let (s, _) = common::call(app(), ns_req("GET", "/secret/data/x", Some("nope"), json!(null))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn child_token_is_confined_to_its_namespace() {
    let app = app();
    create_ns(&app, "team-a", None).await;
    create_ns(&app, "team-b", None).await;

    let (s, body) = common::call(app.clone(), ns_req("POST", "/auth/token/create", Some("team-a"), json!({}))).await;
    assert_eq!(s, StatusCode::OK);
    let tok = body["auth"]["client_token"].as_str().unwrap().to_string();

    let with_tok = |ns: &str| {
        axum::http::Request::builder()
            .method("GET").uri("/secret/data/none")
            .header("X-Vault-Token", &tok).header("X-Vault-Namespace", ns)
            .body(axum::body::Body::empty()).unwrap()
    };
    // allowed in own namespace (404 = secret absent, not forbidden)
    assert_eq!(common::call(app.clone(), with_tok("team-a")).await.0, StatusCode::NOT_FOUND);
    // forbidden in sibling and in root
    assert_eq!(common::call(app.clone(), with_tok("team-b")).await.0, StatusCode::FORBIDDEN);
    assert_eq!(common::call(app.clone(), with_tok("")).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn namespace_works_when_nested_under_v1() {
    let app = axum::Router::new().nest("/v1", app());
    create_ns_at(&app, "/v1/sys/namespaces/team-a").await;
    let w = ns_req("POST", "/v1/team-a/secret/data/db", None, json!({"data": {"pw": "x"}}));
    assert_eq!(common::call(app.clone(), w).await.0, StatusCode::OK);
    let (s, _) = common::call(app.clone(), ns_req("GET", "/v1/secret/data/db", Some("team-a"), json!(null))).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = common::call(app, ns_req("GET", "/v1/secret/data/db", None, json!(null))).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

async fn create_ns_at(app: &axum::Router, uri: &str) {
    let (s, _) = common::call(app.clone(), ns_req("POST", uri, None, json!({}))).await;
    assert_eq!(s, StatusCode::OK);
}
