//! /api/v1/users — list, invite, remove users.
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::api::native::router::NativeState;

pub async fn list_users(State(s): State<NativeState>) -> impl IntoResponse {
    let rows = sqlx::query(
        "SELECT u.id, u.email, u.display_name, u.is_active, u.last_login_at, u.created_at,
                array_agg(r.name) FILTER (WHERE r.name IS NOT NULL) as roles
         FROM users u
         LEFT JOIN role_assignments ra ON ra.user_id = u.id AND ra.scope_type = 'org'
         LEFT JOIN roles r ON r.id = ra.role_id
         GROUP BY u.id ORDER BY u.created_at",
    )
    .fetch_all(&s.pool)
    .await;

    match rows {
        Ok(rows) => {
            let users: Vec<_> = rows.iter().map(|r| json!({
                "id": r.get::<Uuid, _>("id"),
                "email": r.get::<String, _>("email"),
                "display_name": r.try_get::<Option<String>, _>("display_name").ok().flatten(),
                "is_active": r.get::<bool, _>("is_active"),
                "last_login_at": r.try_get::<Option<DateTime<Utc>>, _>("last_login_at").ok().flatten(),
                "created_at": r.get::<DateTime<Utc>, _>("created_at"),
                "roles": r.try_get::<Vec<String>, _>("roles").unwrap_or_default(),
            })).collect();
            Json(json!({ "users": users })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn deactivate_user(
    State(s): State<NativeState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query("UPDATE users SET is_active = FALSE WHERE id = $1")
        .bind(id)
        .execute(&s.pool)
        .await;

    match result {
        Ok(r) if r.rows_affected() == 1 => StatusCode::NO_CONTENT.into_response(),
        Ok(_) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "user not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

pub async fn assign_role(
    State(s): State<NativeState>,
    Path((user_id, role_name)): Path<(Uuid, String)>,
) -> impl IntoResponse {
    let role_row = sqlx::query("SELECT id FROM roles WHERE name = $1 AND is_builtin = TRUE")
        .bind(&role_name)
        .fetch_optional(&s.pool)
        .await;

    let role_id: Uuid = match role_row {
        Ok(Some(r)) => r.get("id"),
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown role"})),
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    // Scope to the first org for now
    let org_row = sqlx::query("SELECT id FROM organizations ORDER BY created_at LIMIT 1")
        .fetch_optional(&s.pool)
        .await;
    let org_id: Uuid = match org_row {
        Ok(Some(r)) => r.get("id"),
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "no org"})),
            )
                .into_response()
        }
    };

    let result = sqlx::query(
        "INSERT INTO role_assignments (user_id, role_id, scope_type, scope_id)
         VALUES ($1, $2, 'org', $3)
         ON CONFLICT (user_id, role_id, scope_type, scope_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(role_id)
    .bind(org_id)
    .execute(&s.pool)
    .await;

    match result {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}
