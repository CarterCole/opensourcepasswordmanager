use anyhow::{Context, Result};
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

mod config;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = config::Config::from_env()?;
    tracing::info!("secretd starting on {}", cfg.listen_addr);

    let pool = sqlx::PgPool::connect(&cfg.database_url)
        .await
        .context("failed to connect to database")?;

    // Run migrations embedded from the db crate's migrations directory
    let migrations_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/db/migrations");
    sqlx::migrate::Migrator::new(migrations_path)
        .await
        .context("failed to load migrations")?
        .run(&pool)
        .await
        .context("migrations failed")?;

    tracing::info!("migrations applied");

    let crypto = Arc::new(secretd_core::CryptoEngine::from_env()?);

    // Encrypt: plaintext → EncryptResult (ciphertext + wrapped DEK blob, all in one call)
    let crypto_enc = {
        let c = crypto.clone();
        move |plaintext: &[u8]| -> anyhow::Result<db::EncryptResult> { c.encrypt(plaintext) }
    };
    // Decrypt: (ciphertext, data_nonce, encrypted_dek_blob) → plaintext
    let crypto_dec = {
        let c = crypto.clone();
        move |ct: &[u8], nonce: &[u8], dek_blob: &[u8]| -> anyhow::Result<Vec<u8>> {
            c.decrypt(ct, nonce, dek_blob)
        }
    };

    let db_backend = Arc::new(db::postgres::PostgresBackend::new(
        pool.clone(),
        crypto_enc,
        crypto_dec,
    ));

    let store = Arc::new(secretd_core::SecretStore::new(
        db_backend.clone() as Arc<dyn db::SecretBackend>,
        crypto.clone(),
    ));

    // Ensure default org / project / env exist
    let (default_org_id, default_env_id) =
        bootstrap_dev_data(&pool, &cfg).await.context("bootstrap failed")?;

    let vault_state = api_vault::auth::VaultState {
        store: store.clone(),
        db: db_backend.clone() as Arc<dyn db::SecretBackend>,
        dev_root_token: Some(cfg.dev_root_token.clone()),
        default_org_id,
        default_env_id,
    };

    let app = Router::new()
        .nest("/v1", api_vault::vault_router(vault_state))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    let addr: SocketAddr = cfg.listen_addr.parse().context("invalid listen addr")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Create seed org/project/environment rows for dev mode.
async fn bootstrap_dev_data(
    pool: &sqlx::PgPool,
    _cfg: &config::Config,
) -> Result<(uuid::Uuid, uuid::Uuid)> {
    use sqlx::Row;

    let org_row = sqlx::query(
        "INSERT INTO organizations (name, slug) VALUES ('default', 'default')
         ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .fetch_one(pool)
    .await?;
    let org_id: uuid::Uuid = org_row.get("id");

    let proj_row = sqlx::query(
        "INSERT INTO projects (org_id, name, slug) VALUES ($1, 'default', 'default')
         ON CONFLICT (org_id, slug) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(org_id)
    .fetch_one(pool)
    .await?;
    let proj_id: uuid::Uuid = proj_row.get("id");

    let env_row = sqlx::query(
        "INSERT INTO environments (project_id, name, slug) VALUES ($1, 'default', 'default')
         ON CONFLICT (project_id, slug) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    )
    .bind(proj_id)
    .fetch_one(pool)
    .await?;
    let env_id: uuid::Uuid = env_row.get("id");

    sqlx::query(
        "INSERT INTO vault_mounts (org_id, mount_path, environment_id, engine_type)
         VALUES ($1, 'secret', $2, 'kv-v2')
         ON CONFLICT (org_id, mount_path) DO NOTHING",
    )
    .bind(org_id)
    .bind(env_id)
    .execute(pool)
    .await?;

    Ok((org_id, env_id))
}
