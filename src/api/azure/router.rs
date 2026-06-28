use axum::{
    routing::{delete, get, post, put},
    Router,
};
use crate::api::common::AppState;
use super::handlers;

pub fn azure_router(state: AppState) -> Router {
    Router::new()
        // Secrets
        .route("/:vault/secrets/:name", put(handlers::set_secret).get(handlers::get_secret))
        .route("/:vault/secrets/:name/:version", get(handlers::get_secret_version))
        .route("/:vault/secrets/:name", delete(handlers::delete_secret))
        .route("/:vault/secrets", get(handlers::list_secrets))
        .route("/:vault/secrets/:name/versions", get(handlers::list_versions))
        // Deleted secrets
        .route("/:vault/deletedsecrets/:name", get(handlers::get_deleted).delete(handlers::purge_secret))
        .route("/:vault/deletedsecrets/:name/recover", post(handlers::recover_secret))
        .with_state(state)
}
