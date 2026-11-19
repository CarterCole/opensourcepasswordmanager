use crate::api::common::AppState;
use axum::{routing::post, Router};

pub fn aws_router(state: AppState) -> Router {
    Router::new()
        .route("/", post(super::handlers::dispatch))
        .with_state(state)
}
