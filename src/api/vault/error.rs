//! Vault wire error format: {"errors": ["msg1"]}
use axum::{http::StatusCode, response::IntoResponse, Json};
use serde::Serialize;

#[derive(Serialize)]
pub struct VaultError {
    pub errors: Vec<String>,
}

impl VaultError {
    pub fn new(msg: impl Into<String>) -> Self {
        Self {
            errors: vec![msg.into()],
        }
    }
    pub fn resp(status: StatusCode, msg: impl Into<String>) -> axum::response::Response {
        (status, Json(Self::new(msg))).into_response()
    }
    pub fn not_found() -> axum::response::Response {
        Self::resp(StatusCode::NOT_FOUND, "secret not found")
    }
    pub fn unauthorized() -> axum::response::Response {
        Self::resp(StatusCode::FORBIDDEN, "permission denied")
    }
    pub fn bad_request(msg: impl Into<String>) -> axum::response::Response {
        Self::resp(StatusCode::BAD_REQUEST, msg)
    }
    pub fn internal(msg: impl Into<String>) -> axum::response::Response {
        Self::resp(StatusCode::INTERNAL_SERVER_ERROR, msg)
    }
}
