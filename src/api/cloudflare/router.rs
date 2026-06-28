use axum::{
    routing::{delete, get, patch, post},
    Router,
};
use crate::api::common::AppState;
use super::handlers;

pub fn cf_router(state: AppState) -> Router {
    Router::new()
        // Quota
        .route("/v4/accounts/:account/secrets_store/quota", get(handlers::get_quota))
        // Stores
        .route(
            "/v4/accounts/:account/secrets_store/stores",
            get(handlers::list_stores).post(handlers::create_store),
        )
        .route(
            "/v4/accounts/:account/secrets_store/stores/:store",
            get(handlers::get_store).delete(handlers::delete_store),
        )
        // Secrets in store
        .route(
            "/v4/accounts/:account/secrets_store/stores/:store/secrets",
            get(handlers::list_store_secrets).post(handlers::batch_create_secrets),
        )
        .route(
            "/v4/accounts/:account/secrets_store/stores/:store/secrets/:secret",
            get(handlers::get_store_secret)
                .patch(handlers::update_store_secret)
                .delete(handlers::delete_store_secret),
        )
        .with_state(state)
}
