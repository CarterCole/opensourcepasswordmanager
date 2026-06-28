//! /api/v1/keys — API key (bearer token) management.
//! This is the primary auth mechanism. Keys are always enabled.
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::api::native::router::NativeState;
use crate::auth::ApiKeyService;

#[derive(Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    /// Built-in role name: owner | admin | developer | reader
    pub role: Option<String>,
    /// Array of "resource:action" strings, e.g. ["secrets:read"]
    pub scopes: Option<Vec<String>>,
    /// ISO 8601 expiry. None = never expires.
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct CreatedKey {
    pub id: Uuid,
    pub name: String,
    pub key: String,  // shown ONCE
    pub prefix: String,
    pub role: Option<String>,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct KeyMeta {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub role: Option<String>,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Resolve a role name to its UUID from the seed data.
fn builtin_role_id(role: &str) -> Option<Uuid> {
    match role {
        "owner"     => Some(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()),
        "admin"     => Some(Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap()),
        "developer" => Some(Uuid::parse_str("00000000-0000-0000-0000-000000000003").unwrap()),
        "reader"    => Some(Uuid::parse_str("00000000-0000-0000-0000-000000000004").unwrap()),
        _ => None,
    }
}

// ── POST /api/v1/keys ─────────────────────────────────────────────────────

pub async fn create_key(
    State(s): State<NativeState>,
    Json(body): Json<CreateKeyRequest>,
) -> impl IntoResponse {
    let (raw, prefix, hash) = match ApiKeyService::generate() {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    // Use first org for now; multi-org comes with full RBAC
    let org_row = sqlx::query("SELECT id FROM organizations ORDER BY created_at LIMIT 1")
        .fetch_optional(&s.pool).await;
    let org_id: Uuid = match org_row {
        Ok(Some(r)) => r.get("id"),
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "no org"}))).into_response(),
    };

    let role_id = body.role.as_deref().and_then(builtin_role_id);
    let scopes: Vec<String> = body.scopes.clone().unwrap_or_default();
    let scopes_json = serde_json::to_value(&scopes).unwrap();

    let row = sqlx::query(
        "INSERT INTO api_keys (org_id, owner_id, owner_type, name, key_prefix, key_hash, scopes, role_id, expires_at)
         VALUES ($1, $1, 'system', $2, $3, $4, $5, $6, $7)
         RETURNING id, created_at",
    )
    .bind(org_id)
    .bind(&body.name)
    .bind(&prefix)
    .bind(&hash)
    .bind(&scopes_json)
    .bind(role_id)
    .bind(body.expires_at)
    .fetch_one(&s.pool)
    .await;

    match row {
        Ok(r) => {
            let id: Uuid = r.get("id");
            let created_at: DateTime<Utc> = r.get("created_at");
            (StatusCode::CREATED, Json(json!({
                "id": id,
                "name": body.name,
                "key": raw,
                "prefix": prefix,
                "role": body.role,
                "scopes": scopes,
                "expires_at": body.expires_at,
                "created_at": created_at,
            }))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

// ── GET /api/v1/keys ──────────────────────────────────────────────────────

pub async fn list_keys(State(s): State<NativeState>) -> impl IntoResponse {
    let rows = sqlx::query(
        "SELECT ak.id, ak.name, ak.key_prefix, ak.scopes, ak.expires_at, ak.last_used_at, ak.created_at,
                r.name as role_name
         FROM api_keys ak
         LEFT JOIN roles r ON r.id = ak.role_id
         WHERE ak.revoked_at IS NULL
         ORDER BY ak.created_at DESC",
    )
    .fetch_all(&s.pool)
    .await;

    match rows {
        Ok(rows) => {
            let keys: Vec<_> = rows.iter().map(|r| {
                let scopes: Vec<String> = r.get::<serde_json::Value, _>("scopes")
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default();
                json!({
                    "id": r.get::<Uuid, _>("id"),
                    "name": r.get::<String, _>("name"),
                    "prefix": r.get::<String, _>("key_prefix"),
                    "role": r.try_get::<String, _>("role_name").ok(),
                    "scopes": scopes,
                    "expires_at": r.try_get::<Option<DateTime<Utc>>, _>("expires_at").ok().flatten(),
                    "last_used_at": r.try_get::<Option<DateTime<Utc>>, _>("last_used_at").ok().flatten(),
                    "created_at": r.get::<DateTime<Utc>, _>("created_at"),
                })
            }).collect();
            Json(json!({ "keys": keys })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

// ── DELETE /api/v1/keys/:id ───────────────────────────────────────────────

pub async fn revoke_key(
    State(s): State<NativeState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let result = sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&s.pool)
    .await;

    match result {
        Ok(r) if r.rows_affected() == 1 => StatusCode::NO_CONTENT.into_response(),
        Ok(_) => (StatusCode::NOT_FOUND, Json(json!({"error": "key not found"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

// ── API key middleware ─────────────────────────────────────────────────────

/// Resolve a raw `sk_live_...` bearer token against the DB.
/// Returns the role name if valid.
pub async fn resolve_api_key(
    pool: &sqlx::PgPool,
    raw_key: &str,
) -> anyhow::Result<ResolvedKey> {
    // Fetch candidates by prefix for efficient lookup
    let prefix = &raw_key[..raw_key.len().min(12)];

    let rows = sqlx::query(
        "SELECT ak.id, ak.key_hash, ak.scopes, ak.org_id, ak.expires_at, r.name as role_name
         FROM api_keys ak
         LEFT JOIN roles r ON r.id = ak.role_id
         WHERE ak.key_prefix = $1 AND ak.revoked_at IS NULL
           AND (ak.expires_at IS NULL OR ak.expires_at > NOW())",
    )
    .bind(prefix)
    .fetch_all(pool)
    .await?;

    for row in &rows {
        let hash: String = row.get("key_hash");
        if ApiKeyService::verify(raw_key, &hash) {
            // Update last_used_at asynchronously (fire and forget)
            let id: Uuid = row.get("id");
            let pool2 = pool.clone();
            tokio::spawn(async move {
                let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
                    .bind(id).execute(&pool2).await;
            });

            let scopes: Vec<String> = row.get::<serde_json::Value, _>("scopes")
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();

            return Ok(ResolvedKey {
                key_id: id,
                org_id: row.get("org_id"),
                role: row.try_get("role_name").ok().flatten(),
                scopes,
            });
        }
    }

    Err(anyhow::anyhow!("invalid API key"))
}

#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub key_id: Uuid,
    pub org_id: Uuid,
    pub role: Option<String>,
    pub scopes: Vec<String>,
}
