//! /api/v1/auth/totp — self-service TOTP 2FA enrollment & management.
//!
//! Flow: `enroll` returns a provisioning URI (store the sealed secret, not yet
//! active) → the user scans it and calls `verify` with a current code, which
//! activates 2FA and returns one-time backup codes → thereafter `login`
//! requires a TOTP (or backup) code.
use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::api::native::router::NativeState;
use crate::auth::{BackupCodes, Claims, TotpService};

#[derive(Deserialize)]
pub struct CodeBody {
    pub code: String,
}

fn user_id(claims: &Claims) -> Result<Uuid, axum::response::Response> {
    Uuid::parse_str(&claims.sub).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid subject"})),
        )
            .into_response()
    })
}

// ── GET /api/v1/auth/totp/status ──────────────────────────────────────────────

pub async fn status(
    State(s): State<NativeState>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    let uid = match user_id(&claims) {
        Ok(u) => u,
        Err(r) => return r,
    };
    let row = sqlx::query("SELECT totp_enrolled_at FROM users WHERE id = $1")
        .bind(uid)
        .fetch_optional(&s.pool)
        .await;
    match row {
        Ok(Some(r)) => {
            let enrolled = r
                .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("totp_enrolled_at")
                .ok()
                .flatten()
                .is_some();
            Json(json!({ "enrolled": enrolled })).into_response()
        }
        Ok(None) => (
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

// ── POST /api/v1/auth/totp/enroll ─────────────────────────────────────────────

pub async fn enroll(
    State(s): State<NativeState>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    let uid = match user_id(&claims) {
        Ok(u) => u,
        Err(r) => return r,
    };

    let row = match sqlx::query("SELECT email, totp_enrolled_at FROM users WHERE id = $1")
        .bind(uid)
        .fetch_optional(&s.pool)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "user not found"})),
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
    let email: String = row.get("email");
    if row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("totp_enrolled_at")
        .ok()
        .flatten()
        .is_some()
    {
        return (
            StatusCode::CONFLICT,
            Json(json!({"error": "TOTP is already enabled; disable it first"})),
        )
            .into_response();
    }

    let secret = TotpService::generate_secret();
    let sealed = match s.crypto.seal(secret.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };

    // Store the (not-yet-active) sealed secret.
    if let Err(e) = sqlx::query(
        "UPDATE users SET totp_secret_encrypted = $1, totp_enrolled_at = NULL WHERE id = $2",
    )
    .bind(&sealed)
    .bind(uid)
    .execute(&s.pool)
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }

    let uri = match TotpService::provisioning_uri(&secret, &email) {
        Ok(u) => u,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let qr = TotpService::qr_base64(&secret, &email).ok();

    Json(json!({
        "secret": secret,
        "otpauth_uri": uri,
        "qr_png_base64": qr,
        "next": "POST /api/v1/auth/totp/verify with a current 6-digit code to activate",
    }))
    .into_response()
}

// ── POST /api/v1/auth/totp/verify ─────────────────────────────────────────────

pub async fn verify(
    State(s): State<NativeState>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<CodeBody>,
) -> impl IntoResponse {
    let uid = match user_id(&claims) {
        Ok(u) => u,
        Err(r) => return r,
    };

    let row = match sqlx::query("SELECT email, totp_secret_encrypted FROM users WHERE id = $1")
        .bind(uid)
        .fetch_optional(&s.pool)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "user not found"})),
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
    let email: String = row.get("email");
    let sealed: Option<Vec<u8>> = row.try_get("totp_secret_encrypted").ok().flatten();
    let Some(sealed) = sealed else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "no pending TOTP enrollment; call enroll first"})),
        )
            .into_response();
    };

    let secret = match s
        .crypto
        .open(&sealed)
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
    {
        Some(sec) => sec,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "could not read TOTP secret"})),
            )
                .into_response()
        }
    };
    if !TotpService::verify(&secret, &body.code, &email) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid code"})),
        )
            .into_response();
    }

    let (plain, hashes) = match BackupCodes::generate() {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let hashes_json = serde_json::to_value(&hashes).unwrap_or(json!([]));

    if let Err(e) = sqlx::query(
        "UPDATE users SET totp_enrolled_at = NOW(), backup_codes_hash = $1 WHERE id = $2",
    )
    .bind(&hashes_json)
    .bind(uid)
    .execute(&s.pool)
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(json!({
            "enrolled": true,
            "backup_codes": plain,
            "warning": "store these backup codes now — they are shown only once",
        })),
    )
        .into_response()
}

// ── DELETE /api/v1/auth/totp ──────────────────────────────────────────────────

pub async fn disable(
    State(s): State<NativeState>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<CodeBody>,
) -> impl IntoResponse {
    let uid = match user_id(&claims) {
        Ok(u) => u,
        Err(r) => return r,
    };

    let row = match sqlx::query(
        "SELECT email, totp_secret_encrypted, totp_enrolled_at FROM users WHERE id = $1",
    )
    .bind(uid)
    .fetch_optional(&s.pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "user not found"})),
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
    if row
        .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>("totp_enrolled_at")
        .ok()
        .flatten()
        .is_none()
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "TOTP is not enabled"})),
        )
            .into_response();
    }
    let email: String = row.get("email");
    let sealed: Option<Vec<u8>> = row.try_get("totp_secret_encrypted").ok().flatten();

    // Require a valid current code to disable, so a hijacked session can't drop 2FA.
    let valid = sealed
        .and_then(|b| s.crypto.open(&b).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .map(|secret| TotpService::verify(&secret, &body.code, &email))
        .unwrap_or(false);
    if !valid {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "a valid TOTP code is required to disable 2FA"})),
        )
            .into_response();
    }

    if let Err(e) = sqlx::query(
        "UPDATE users SET totp_secret_encrypted = NULL, totp_enrolled_at = NULL, backup_codes_hash = NULL WHERE id = $1",
    ).bind(uid).execute(&s.pool).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}
