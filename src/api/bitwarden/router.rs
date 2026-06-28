use axum::{
    routing::{delete, get, post, put},
    Router,
};
use crate::api::common::AppState;
use super::handlers;

pub fn bitwarden_router(state: AppState) -> Router {
    Router::new()
        // OAuth2 token endpoint (no auth required)
        .route("/identity/connect/token", post(handlers::token))
        // Public API
        .route(
            "/api/public/collections",
            get(handlers::list_collections).post(handlers::create_collection),
        )
        .route(
            "/api/public/collections/:id",
            get(handlers::get_collection)
                .put(handlers::update_collection)
                .delete(handlers::delete_collection),
        )
        .route("/api/public/members", get(handlers::list_members))
        .route("/api/public/events", get(handlers::list_events))
        .route("/api/public/policies", get(handlers::list_policies))
        .route("/api/public/policies/:policy_type", get(handlers::get_policy))
        .with_state(state)
}
