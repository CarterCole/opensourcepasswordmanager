mod config;
mod db;
mod core;
mod auth;
mod api;
mod sync;
mod ui;

use anyhow::{Context, Result};
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cfg = config::Config::from_env()?;
    let listen_addr = cfg.listen_addr.clone();
    tracing::info!("secretd starting on {}", listen_addr);

    let crypto = Arc::new(core::CryptoEngine::from_env()?);

    // ── Database setup ────────────────────────────────────────────────────────
    // DATABASE_URL prefix determines which backend is used:
    //   sqlite:./secretd.db  →  SQLite (no Docker, great for demo/dev)
    //   postgres://...       →  PostgreSQL (production)

    enum Pools { Sqlite(sqlx::SqlitePool), Postgres(sqlx::PgPool) }

    let (backend, pools, (default_org_id, default_env_id)) = if cfg.database_url.starts_with("sqlite:") {
        tracing::info!("SQLite mode — {}", cfg.database_url);
        let pool = sqlx::SqlitePool::connect(&cfg.database_url)
            .await.context("failed to open SQLite database")?;
        sqlx::migrate::Migrator::new(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations/sqlite")
        ).await?.run(&pool).await.context("SQLite migrations failed")?;
        let ids = bootstrap_sqlite(&pool).await?;
        let c1 = crypto.clone(); let c2 = crypto.clone();
        let b: Arc<dyn db::SecretBackend> = Arc::new(db::sqlite::SqliteBackend::new(
            pool.clone(),
            move |pt: &[u8]| c1.encrypt(pt),
            move |ct, n, d| c2.decrypt(ct, n, d),
        ));
        (b, Pools::Sqlite(pool), ids)
    } else {
        tracing::info!("PostgreSQL mode");
        let pool = sqlx::PgPool::connect(&cfg.database_url)
            .await.context("failed to connect to PostgreSQL")?;
        sqlx::migrate::Migrator::new(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations")
        ).await?.run(&pool).await.context("PostgreSQL migrations failed")?;
        let ids = bootstrap_postgres(&pool).await?;
        let c1 = crypto.clone(); let c2 = crypto.clone();
        let b: Arc<dyn db::SecretBackend> = Arc::new(db::postgres::PostgresBackend::new(
            pool.clone(),
            move |pt: &[u8]| c1.encrypt(pt),
            move |ct, n, d| c2.decrypt(ct, n, d),
        ));
        (b, Pools::Postgres(pool), ids)
    };

    tracing::info!("migrations applied — org={default_org_id} env={default_env_id}");

    let store = Arc::new(core::SecretStore::new(backend.clone(), crypto.clone()));

    let vault_state = api::vault::auth::VaultState {
        store: store.clone(),
        db: backend.clone(),
        dev_root_token: Some(cfg.dev_root_token.clone()),
        default_org_id,
        default_env_id,
    };
    let app_state = api::common::AppState {
        store: store.clone(),
        db: backend.clone(),
        dev_root_token: Some(cfg.dev_root_token.clone()),
        default_org_id,
        default_env_id,
    };

    let mut app = Router::new()
        .nest("/v1",       api::vault::vault_router(vault_state))
        .nest("/",         api::aws::aws_router(app_state.clone()))
        .nest("/gcp",      api::gcp::gcp_router(app_state.clone()))
        .nest("/azure",    api::azure::azure_router(app_state.clone()))
        .nest("/client",   api::cloudflare::cf_router(app_state.clone()))
        .nest("/bitwarden",api::bitwarden::bitwarden_router(app_state.clone()))
        .nest("/ui",       ui::serve_ui());

    // Native API (key management + human auth) — Postgres only for now.
    // SQLite demo: use the dev root token directly.
    if let Pools::Postgres(ref pool) = pools {
        let mut auth_mgr = auth::AuthManager::new();
        if cfg.auth.email {
            tracing::info!("email+password login enabled");
            auth_mgr.register(auth::email::EmailPasswordProvider);
        }
        let cfg = Arc::new(cfg);
        let native_state = api::native::router::NativeState {
            pool: pool.clone(),
            sessions: Arc::new(auth::SessionService::from_secret(&cfg.jwt_secret)),
            auth_manager: Arc::new(auth_mgr),
            config: cfg,
        };
        app = app.merge(api::native::native_router(native_state));
        tracing::info!("native API mounted at /api/v1/");
    } else {
        tracing::warn!("SQLite mode: /api/v1/ not mounted — use dev token '{}'", cfg.dev_root_token);
    }

    let app = app
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    let addr: SocketAddr = listen_addr.parse().context("invalid listen addr")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on {addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

async fn bootstrap_postgres(pool: &sqlx::PgPool) -> Result<(Uuid, Uuid)> {
    use sqlx::Row;
    let org = sqlx::query(
        "INSERT INTO organizations (name, slug) VALUES ('default', 'default')
         ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    ).fetch_one(pool).await?;
    let org_id: Uuid = org.get("id");

    let proj = sqlx::query(
        "INSERT INTO projects (org_id, name, slug) VALUES ($1, 'default', 'default')
         ON CONFLICT (org_id, slug) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    ).bind(org_id).fetch_one(pool).await?;
    let proj_id: Uuid = proj.get("id");

    let env = sqlx::query(
        "INSERT INTO environments (project_id, name, slug) VALUES ($1, 'default', 'default')
         ON CONFLICT (project_id, slug) DO UPDATE SET name = EXCLUDED.name RETURNING id",
    ).bind(proj_id).fetch_one(pool).await?;
    let env_id: Uuid = env.get("id");

    sqlx::query(
        "INSERT INTO vault_mounts (org_id, mount_path, environment_id, engine_type)
         VALUES ($1, 'secret', $2, 'kv-v2') ON CONFLICT (org_id, mount_path) DO NOTHING",
    ).bind(org_id).bind(env_id).execute(pool).await?;

    Ok((org_id, env_id))
}

async fn bootstrap_sqlite(pool: &sqlx::SqlitePool) -> Result<(Uuid, Uuid)> {
    use sqlx::Row;

    // Insert OR IGNORE so re-runs are idempotent; read back the real IDs.
    let org_id = Uuid::new_v4();
    sqlx::query("INSERT OR IGNORE INTO organizations (id, name, slug) VALUES (?, 'default', 'default')")
        .bind(org_id.to_string()).execute(pool).await?;
    let org_id: Uuid = sqlx::query("SELECT id FROM organizations WHERE slug = 'default'")
        .fetch_one(pool).await?.try_get::<String, _>("id")
        .map(|s| Uuid::parse_str(&s).unwrap_or(org_id))?;

    let proj_id = Uuid::new_v4();
    sqlx::query("INSERT OR IGNORE INTO projects (id, org_id, name, slug) VALUES (?, ?, 'default', 'default')")
        .bind(proj_id.to_string()).bind(org_id.to_string()).execute(pool).await?;
    let proj_id: Uuid = sqlx::query("SELECT id FROM projects WHERE slug = 'default' AND org_id = ?")
        .bind(org_id.to_string()).fetch_one(pool).await?
        .try_get::<String, _>("id").map(|s| Uuid::parse_str(&s).unwrap_or(proj_id))?;

    let env_id = Uuid::new_v4();
    sqlx::query("INSERT OR IGNORE INTO environments (id, project_id, name, slug) VALUES (?, ?, 'default', 'default')")
        .bind(env_id.to_string()).bind(proj_id.to_string()).execute(pool).await?;
    let env_id: Uuid = sqlx::query("SELECT id FROM environments WHERE slug = 'default' AND project_id = ?")
        .bind(proj_id.to_string()).fetch_one(pool).await?
        .try_get::<String, _>("id").map(|s| Uuid::parse_str(&s).unwrap_or(env_id))?;

    let mount_id = Uuid::new_v4();
    sqlx::query(
        "INSERT OR IGNORE INTO vault_mounts (id, org_id, mount_path, environment_id, engine_type)
         VALUES (?, ?, 'secret', ?, 'kv-v2')",
    ).bind(mount_id.to_string()).bind(org_id.to_string()).bind(env_id.to_string())
     .execute(pool).await?;

    Ok((org_id, env_id))
}
