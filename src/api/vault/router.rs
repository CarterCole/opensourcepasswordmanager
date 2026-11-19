//! Mounts the Vault KV v2 compatible router at /v1/
use super::{
    auth::{require_vault_token, resolve_namespace, VaultState},
    handlers,
};
use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower::Layer;

/// Build the Vault-compatible router.
/// Mount this at `/v1` in the main server.
pub fn vault_router(state: VaultState) -> Router {
    let protected = Router::new()
        // sys
        .route("/sys/mounts", get(handlers::list_mounts))
        // sys/namespaces (OpenBao): list/create/read/delete, relative to the request namespace
        .route("/sys/namespaces", get(handlers::ns_list))
        .route("/sys/namespaces/*path", get(handlers::ns_read))
        .route("/sys/namespaces/*path", post(handlers::ns_create).put(handlers::ns_create))
        .route("/sys/namespaces/*path", delete(handlers::ns_delete))
        // auth
        .route("/auth/token/create", post(handlers::token_create))
        // KV v2 data
        .route("/:mount/data/*path", get(handlers::kv_read))
        .route("/:mount/data/*path", post(handlers::kv_write))
        .route("/:mount/data/*path", delete(handlers::kv_delete_latest))
        // KV v2 version management
        .route("/:mount/delete/*path", post(handlers::kv_delete_versions))
        .route("/:mount/undelete/*path", post(handlers::kv_undelete_versions))
        .route("/:mount/destroy/*path", put(handlers::kv_destroy_versions))
        // KV v2 metadata (GET/LIST) — root listing (no path) and deep listing
        .route("/:mount/metadata", get(handlers::kv_list_root))
        .route("/:mount/metadata/*path", get(handlers::kv_list))
        // KV v2 metadata write (create/update config)
        .route("/:mount/metadata/*path", post(handlers::kv_read_metadata))
        // KV v2 metadata delete (delete all)
        .route("/:mount/metadata/*path", delete(handlers::kv_delete_all))
        .with_state(state.clone());

    // Namespace resolution rewrites the URI, so it must wrap the whole router
    // (route-level layers run after matching). Auth runs first: namespaces are per-org.
    let ns_layer = middleware::from_fn_with_state(state.clone(), resolve_namespace);
    let auth_layer = middleware::from_fn_with_state(state, require_vault_token);
    let protected = auth_layer.layer(ns_layer.layer(protected));

    // Health check does not require auth (standard Vault behaviour)
    Router::new()
        .route("/sys/health", get(handlers::health))
        .fallback_service(protected)
}
