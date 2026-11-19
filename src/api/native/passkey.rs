//! /api/v1/auth/passkey — WebAuthn registration & passwordless login.
//!
//! Registration requires an authenticated session (a user adds a passkey to
//! their own account). Login is a two-step public ceremony: `login/start`
//! returns a challenge, `login/finish` verifies the assertion and issues a
//! session token.
//!
//! Disabled unless SECRETD_RP_ID and SECRETD_RP_ORIGIN are configured, in which
//! case every endpoint returns 501 Not Implemented.
use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use serde::Deserialize;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

use crate::api::native::router::NativeState;
use crate::auth::passkey::{parse_credentials, serialize_credentials};
use crate::auth::Claims;

fn disabled() -> axum::response::Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({"error": "passkeys are not configured on this server"})),
    )
        .into_response()
}

fn err(status: StatusCode, msg: impl ToString) -> axum::response::Response {
    (status, Json(json!({"error": msg.to_string()}))).into_response()
}

// ── registration (authenticated) ──────────────────────────────────────────────

pub async fn register_start(
    State(s): State<NativeState>,
    Extension(claims): Extension<Claims>,
) -> impl IntoResponse {
    if !s.passkey.enabled() {
        return disabled();
    }
    let uid = match Uuid::parse_str(&claims.sub) {
        Ok(u) => u,
        Err(_) => return err(StatusCode::UNAUTHORIZED, "invalid subject"),
    };

    let row = match sqlx::query(
        "SELECT email, display_name, webauthn_credentials FROM users WHERE id = $1",
    )
    .bind(uid)
    .fetch_optional(&s.pool)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return err(StatusCode::NOT_FOUND, "user not found"),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let email: String = row.get("email");
    let display: String = row
        .try_get::<Option<String>, _>("display_name")
        .ok()
        .flatten()
        .unwrap_or_else(|| email.clone());
    let existing = parse_credentials(
        &row.try_get::<serde_json::Value, _>("webauthn_credentials")
            .unwrap_or(json!([])),
    );

    match s
        .passkey
        .start_registration(uid, &email, &display, &existing)
    {
        Ok(ccr) => Json(ccr).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

pub async fn register_finish(
    State(s): State<NativeState>,
    Extension(claims): Extension<Claims>,
    Json(reg): Json<RegisterPublicKeyCredential>,
) -> impl IntoResponse {
    if !s.passkey.enabled() {
        return disabled();
    }
    let uid = match Uuid::parse_str(&claims.sub) {
        Ok(u) => u,
        Err(_) => return err(StatusCode::UNAUTHORIZED, "invalid subject"),
    };

    let passkey = match s.passkey.finish_registration(uid, &reg) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };

    // Append to the user's stored credentials.
    let row = match sqlx::query("SELECT webauthn_credentials FROM users WHERE id = $1")
        .bind(uid)
        .fetch_optional(&s.pool)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return err(StatusCode::NOT_FOUND, "user not found"),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
    };
    let mut creds = parse_credentials(
        &row.try_get::<serde_json::Value, _>("webauthn_credentials")
            .unwrap_or(json!([])),
    );
    creds.push(passkey);
    let json = serialize_credentials(&creds);

    if let Err(e) = sqlx::query("UPDATE users SET webauthn_credentials = $1 WHERE id = $2")
        .bind(&json)
        .bind(uid)
        .execute(&s.pool)
        .await
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    (
        StatusCode::CREATED,
        Json(json!({"registered": true, "passkeys": creds.len()})),
    )
        .into_response()
}

// ── login (public, passwordless) ──────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LoginStartBody {
    pub email: String,
}

async fn load_user_creds(
    pool: &sqlx::PgPool,
    email: &str,
) -> Option<(Uuid, Uuid, Vec<webauthn_rs::prelude::Passkey>)> {
    let row = sqlx::query(
        "SELECT id, org_id, webauthn_credentials FROM users WHERE email = $1 AND is_active = TRUE",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .ok()??;
    let creds = parse_credentials(
        &row.try_get::<serde_json::Value, _>("webauthn_credentials")
            .unwrap_or(json!([])),
    );
    Some((row.get("id"), row.get("org_id"), creds))
}

pub async fn login_start(
    State(s): State<NativeState>,
    Json(body): Json<LoginStartBody>,
) -> impl IntoResponse {
    if !s.passkey.enabled() {
        return disabled();
    }

    let Some((_uid, _org, creds)) = load_user_creds(&s.pool, &body.email).await else {
        return err(StatusCode::NOT_FOUND, "no passkeys for this account");
    };
    match s.passkey.start_authentication(&body.email, &creds) {
        Ok(rcr) => Json(rcr).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

#[derive(Deserialize)]
pub struct LoginFinishBody {
    pub email: String,
    pub assertion: PublicKeyCredential,
}

pub async fn login_finish(
    State(s): State<NativeState>,
    Json(body): Json<LoginFinishBody>,
) -> impl IntoResponse {
    if !s.passkey.enabled() {
        return disabled();
    }

    if s.passkey
        .finish_authentication(&body.email, &body.assertion)
        .is_err()
    {
        return err(StatusCode::UNAUTHORIZED, "passkey authentication failed");
    }
    let Some((uid, org, _creds)) = load_user_creds(&s.pool, &body.email).await else {
        return err(StatusCode::UNAUTHORIZED, "passkey authentication failed");
    };

    let roles = fetch_roles(&s.pool, uid, org).await;
    match s
        .sessions
        .issue(uid, org, &body.email, roles, true, 86400 * 7)
    {
        Ok(t) => Json(json!({"token": t, "token_type": "Bearer"})).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

async fn fetch_roles(pool: &sqlx::PgPool, user_id: Uuid, org_id: Uuid) -> Vec<String> {
    let rows = sqlx::query(
        "SELECT r.name FROM roles r
         JOIN role_assignments ra ON ra.role_id = r.id
         WHERE ra.user_id = $1 AND ra.scope_type = 'org' AND ra.scope_id = $2",
    )
    .bind(user_id)
    .bind(org_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    rows.iter().map(|r| r.get::<String, _>("name")).collect()
}
