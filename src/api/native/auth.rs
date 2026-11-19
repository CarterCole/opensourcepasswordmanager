//! /api/v1/auth — login + provider discovery.
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::api::native::router::NativeState;
use crate::auth::ApiKeyService;

// ── GET /api/v1/auth/providers ─────────────────────────────────────────────

pub async fn list_providers(State(s): State<NativeState>) -> impl IntoResponse {
    let providers = s.auth_manager.providers();
    Json(json!({ "providers": providers }))
}

// ── POST /api/v1/auth/login ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginRequest {
    pub provider: String,
    #[serde(flatten)]
    pub credentials: serde_json::Value,
}

pub async fn login(
    State(s): State<NativeState>,
    Json(body): Json<LoginRequest>,
) -> impl IntoResponse {
    // Throttle online guessing, keyed by provider + login identifier.
    let identifier = body.credentials.get("email").and_then(|v| v.as_str()).unwrap_or("");
    let rl_key = format!("login:{}:{}", body.provider, identifier);
    if let Err(retry) = super::ratelimit::check_and_record(&rl_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", retry.to_string())],
            Json(json!({"error": "too many attempts; try again later"})),
        )
            .into_response();
    }

    let user = match s.auth_manager.authenticate(&body.provider, &body.credentials, &s.pool).await {
        Ok(u) => u,
        Err(e) => {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": e.to_string()}))).into_response();
        }
    };
    // Successful auth — clear the throttle for this identifier.
    super::ratelimit::reset(&rl_key);

    let org_id = user.org_id;
    let user_id = match user.user_id {
        Some(id) => id,
        None => {
            // Auto-provision: insert or upsert the user
            match upsert_user(&s.pool, &user).await {
                Ok(id) => id,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
            }
        }
    };

    // Second factor: if the account has TOTP enabled, require a valid TOTP code
    // or a single-use backup code before issuing a session.
    match enforce_totp(&s, user_id, &user.email, &body.credentials).await {
        TotpOutcome::Ok => {}
        TotpOutcome::Required => {
            return (StatusCode::UNAUTHORIZED, Json(json!({
                "error": "totp_required",
                "mfa_required": true,
                "detail": "resubmit with a 'totp' field containing your 6-digit code or a backup code",
            }))).into_response();
        }
        TotpOutcome::Invalid => {
            return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid_totp"}))).into_response();
        }
        TotpOutcome::Error(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response();
        }
    }

    let roles = fetch_roles(&s.pool, user_id, org_id).await.unwrap_or_default();
    let token = s.sessions.issue(user_id, org_id, &user.email, roles, true, 86400 * 7);

    match token {
        Ok(t) => Json(json!({ "token": t, "token_type": "Bearer" })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

enum TotpOutcome {
    Ok,
    Required,
    Invalid,
    Error(String),
}

/// Verify the second factor for `user_id`. Returns `Ok` when 2FA is not enabled
/// or the supplied code is valid; consumes a backup code if one is used.
async fn enforce_totp(
    s: &NativeState,
    user_id: Uuid,
    email: &str,
    credentials: &serde_json::Value,
) -> TotpOutcome {
    let row = match sqlx::query(
        "SELECT totp_enrolled_at, totp_secret_encrypted, backup_codes_hash FROM users WHERE id = $1",
    ).bind(user_id).fetch_optional(&s.pool).await {
        Ok(Some(r)) => r,
        Ok(None) => return TotpOutcome::Ok,
        Err(e) => return TotpOutcome::Error(e.to_string()),
    };

    let enrolled = row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("totp_enrolled_at")
        .ok().flatten().is_some();
    if !enrolled {
        return TotpOutcome::Ok;
    }

    let code = credentials.get("totp").or_else(|| credentials.get("code"))
        .and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if code.is_empty() {
        return TotpOutcome::Required;
    }

    let sealed: Option<Vec<u8>> = row.try_get("totp_secret_encrypted").ok().flatten();
    let secret = sealed
        .and_then(|b| s.crypto.open(&b).ok())
        .and_then(|b| String::from_utf8(b).ok());
    if let Some(secret) = secret {
        if crate::auth::TotpService::verify(&secret, &code, email) {
            return TotpOutcome::Ok;
        }
    }

    // Fall back to a one-time backup code.
    let hashes: Vec<String> = row
        .try_get::<Option<serde_json::Value>, _>("backup_codes_hash").ok().flatten()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    if let Some(idx) = crate::auth::BackupCodes::consume(&code, &hashes) {
        let mut remaining = hashes;
        remaining.remove(idx);
        let json = serde_json::to_value(&remaining).unwrap_or(json!([]));
        let _ = sqlx::query("UPDATE users SET backup_codes_hash = $1 WHERE id = $2")
            .bind(json).bind(user_id).execute(&s.pool).await;
        return TotpOutcome::Ok;
    }

    TotpOutcome::Invalid
}

async fn upsert_user(pool: &sqlx::PgPool, user: &crate::auth::provider::AuthUser) -> anyhow::Result<Uuid> {
    let row = sqlx::query(
        "INSERT INTO users (org_id, email, display_name) VALUES ($1, $2, $3)
         ON CONFLICT (email) DO UPDATE SET display_name = EXCLUDED.display_name, updated_at = NOW()
         RETURNING id",
    )
    .bind(user.org_id)
    .bind(&user.email)
    .bind(&user.display_name)
    .fetch_one(pool)
    .await?;
    Ok(row.get("id"))
}

async fn fetch_roles(pool: &sqlx::PgPool, user_id: Uuid, org_id: Uuid) -> anyhow::Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT r.name FROM roles r
         JOIN role_assignments ra ON ra.role_id = r.id
         WHERE ra.user_id = $1 AND ra.scope_type = 'org' AND ra.scope_id = $2",
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.iter().map(|r| r.get::<String, _>("name")).collect())
}

// ── GET /api/v1/auth/me ────────────────────────────────────────────────────

pub async fn me(
    State(_s): State<NativeState>,
    axum::Extension(claims): axum::Extension<crate::auth::Claims>,
) -> impl IntoResponse {
    Json(json!({
        "user_id": claims.sub,
        "email":   claims.email,
        "org_id":  claims.org,
        "roles":   claims.roles,
    }))
}

// ── POST /api/v1/auth/register (first-user bootstrap) ─────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub display_name: Option<String>,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: Uuid,
    pub email: String,
}

pub async fn register(
    State(s): State<NativeState>,
    Json(body): Json<RegisterRequest>,
) -> impl IntoResponse {
    // Only allow if email auth is enabled in config
    if !s.config.auth.email {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "email auth not enabled"}))).into_response();
    }

    // Throttle registration attempts by email to limit abuse of the endpoint.
    let rl_key = format!("register:{}", body.email);
    if let Err(retry) = super::ratelimit::check_and_record(&rl_key) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", retry.to_string())],
            Json(json!({"error": "too many attempts; try again later"})),
        )
            .into_response();
    }

    let hash = match crate::auth::apikey::ApiKeyService::hash(&body.password) {
        Ok(h) => h,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };

    // Use the first org as default
    let org_row = sqlx::query("SELECT id FROM organizations ORDER BY created_at LIMIT 1")
        .fetch_optional(&s.pool).await;

    let org_id: Uuid = match org_row {
        Ok(Some(r)) => r.get("id"),
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "no org found"}))).into_response(),
    };

    // Open registration is a first-user bootstrap ONLY. Once any user exists, the
    // endpoint is closed — additional users must be invited by an admin — so a
    // stranger can never self-register (and never be granted the owner role).
    let user_count: i64 = match sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE org_id = $1")
        .bind(org_id)
        .fetch_one(&s.pool)
        .await
    {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    };
    if user_count > 0 {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "registration is closed; an administrator must invite additional users"})),
        )
            .into_response();
    }

    let row = sqlx::query(
        "INSERT INTO users (org_id, email, display_name, password_hash)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (email) DO NOTHING
         RETURNING id",
    )
    .bind(org_id)
    .bind(&body.email)
    .bind(&body.display_name)
    .bind(&hash)
    .fetch_optional(&s.pool).await;

    match row {
        Ok(Some(r)) => {
            let user_id: Uuid = r.get("id");
            // First user bootstraps as owner.
            let _ = sqlx::query(
                "INSERT INTO role_assignments (user_id, role_id, scope_type, scope_id)
                 VALUES ($1, '00000000-0000-0000-0000-000000000001', 'org', $2)
                 ON CONFLICT DO NOTHING",
            )
            .bind(user_id).bind(org_id).execute(&s.pool).await;

            (StatusCode::CREATED, Json(json!({ "user_id": user_id, "email": body.email }))).into_response()
        }
        Ok(None) => (StatusCode::CONFLICT, Json(json!({"error": "email already registered"}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}
