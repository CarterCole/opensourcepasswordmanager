use super::handlers;
use crate::api::common::AppState;
use axum::{
    routing::{delete, get, post},
    Router,
};

pub fn gcp_router(state: AppState) -> Router {
    Router::new()
        // Secret CRUD via wildcard — we dispatch on action suffix in handler
        .route(
            "/v1/projects/:project/secrets",
            get(handlers::list_secrets).post(handlers::create_secret),
        )
        .route(
            "/v1/projects/:project/secrets/*action",
            post(handlers::post_action)
                .get(handlers::get_action)
                .delete(handlers::delete_action),
        )
        .with_state(state)
}
