//! Mounts the Vault KV v2 compatible router at /v1/
use super::{
    auth::{require_vault_token, VaultState},
    handlers,
};
use axum::{
    middleware,
    routing::{delete, get, post, put},
    Router,
};

/// Build the Vault-compatible router.
/// Mount this at `/v1` in the main server.
pub fn vault_router(state: VaultState) -> Router {
    let protected = Router::new()
        // sys
        .route("/sys/mounts", get(handlers::list_mounts))
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
        // KV v2 metadata (GET/LIST)
        .route("/:mount/metadata/*path", get(handlers::kv_list))
        // KV v2 metadata write (create/update config)
        .route("/:mount/metadata/*path", post(handlers::kv_read_metadata))
        // KV v2 metadata delete (delete all)
        .route("/:mount/metadata/*path", delete(handlers::kv_delete_all))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_vault_token,
        ))
        .with_state(state);

    // Health check does not require auth (standard Vault behaviour)
    Router::new()
        .route("/sys/health", get(handlers::health))
        .merge(protected)
}
