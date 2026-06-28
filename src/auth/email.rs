//! Email + password auth provider. Disabled by default.
//! Enable with SECRETD_AUTH_EMAIL=true (or auth.email = true in config).
use super::provider::{AuthProvider, AuthUser, Credentials, ProviderField, ProviderInfo, ProviderKind};
use argon2::{password_hash::{PasswordHash, PasswordVerifier}, Argon2};
use async_trait::async_trait;
use sqlx::Row;

pub struct EmailPasswordProvider;

#[async_trait]
impl AuthProvider for EmailPasswordProvider {
    fn id(&self) -> &str { "email" }

    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "email".into(),
            display_name: "Email & Password".into(),
            kind: ProviderKind::Form {
                fields: vec![
                    ProviderField { name: "email".into(), label: "Email".into(), kind: "text".into(), required: true },
                    ProviderField { name: "password".into(), label: "Password".into(), kind: "password".into(), required: true },
                ],
            },
        }
    }

    async fn authenticate(&self, creds: &Credentials, pool: &sqlx::PgPool) -> anyhow::Result<AuthUser> {
        let email = creds["email"].as_str().ok_or_else(|| anyhow::anyhow!("email required"))?;
        let password = creds["password"].as_str().ok_or_else(|| anyhow::anyhow!("password required"))?;

        let row = sqlx::query(
            "SELECT id, org_id, email, display_name, password_hash FROM users
             WHERE email = $1 AND is_active = TRUE",
        )
        .bind(email)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| anyhow::anyhow!("invalid credentials"))?;

        let hash: Option<String> = row.try_get("password_hash")?;
        let hash = hash.ok_or_else(|| anyhow::anyhow!("password login not configured for this account"))?;

        let parsed = PasswordHash::new(&hash).map_err(|_| anyhow::anyhow!("invalid credentials"))?;
        let ok = Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok();
        if !ok { return Err(anyhow::anyhow!("invalid credentials")); }

        Ok(AuthUser {
            user_id: Some(row.get("id")),
            org_id: row.get("org_id"),
            email: row.get("email"),
            display_name: row.try_get("display_name").ok().flatten(),
            roles: vec![],
        })
    }
}
