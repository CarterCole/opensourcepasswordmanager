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
        let opts = cfg.database_url.parse::<sqlx::sqlite::SqliteConnectOptions>()
            .context("invalid SQLite URL")?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);
        let pool = sqlx::SqlitePool::connect_with(opts)
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

    let pg_pool: Option<sqlx::PgPool> = match &pools {
        Pools::Postgres(p) => Some(p.clone()),
        Pools::Sqlite(_) => None,
    };
    let sessions = Arc::new(auth::SessionService::from_secret(&cfg.jwt_secret));

    if cfg.dev_root_token.is_some() {
        tracing::warn!(
            "SECRETD_DEV_ROOT_TOKEN is set — a master bypass token is active. \
             Do not use this in production; rely on the native API / issued tokens instead."
        );
    }

    let vault_state = api::vault::auth::VaultState {
        store: store.clone(),
        db: backend.clone(),
        dev_root_token: cfg.dev_root_token.clone(),
        default_org_id,
        default_env_id,
        pg_pool: pg_pool.clone(),
        sessions: sessions.clone(),
    };
    let app_state = api::common::AppState {
        store: store.clone(),
        db: backend.clone(),
        dev_root_token: cfg.dev_root_token.clone(),
        default_org_id,
        default_env_id,
        pg_pool: pg_pool.clone(),
        sessions: sessions.clone(),
    };

    let mut app = Router::new()
        .nest("/v1",       api::vault::vault_router(vault_state))
        .nest("/",         api::aws::aws_router(app_state.clone()))
        .nest("/gcp",      api::gcp::gcp_router(app_state.clone()))
        .nest("/azure",    api::azure::azure_router(app_state.clone()))
        .nest("/client",   api::cloudflare::cf_router(app_state.clone()))
        .nest("/bitwarden",api::bitwarden::bitwarden_router(app_state.clone()))
        .nest("/ui",       ui::serve_ui())
        .route("/", axum::routing::get(home))
        .fallback(not_found);

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
            sessions: sessions.clone(),
            auth_manager: Arc::new(auth_mgr),
            config: cfg,
        };
        app = app.merge(api::native::native_router(native_state));
        tracing::info!("native API mounted at /api/v1/");
    } else if cfg.dev_root_token.is_some() {
        tracing::warn!("SQLite mode: /api/v1/ not mounted — authenticate with the configured SECRETD_DEV_ROOT_TOKEN");
    } else {
        tracing::error!(
            "SQLite mode: /api/v1/ not mounted and no SECRETD_DEV_ROOT_TOKEN set — \
             the server has no usable authentication and every request will be rejected. \
             Set SECRETD_DEV_ROOT_TOKEN to a strong random value for local use."
        );
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
        "INSERT INTO vault_mounts (org_id, namespace, mount_path, environment_id, engine_type)
         VALUES ($1, '', 'secret', $2, 'kv-v2') ON CONFLICT (org_id, namespace, mount_path) DO NOTHING",
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
        "INSERT OR IGNORE INTO vault_mounts (id, org_id, namespace, mount_path, environment_id, engine_type)
         VALUES (?, ?, '', 'secret', ?, 'kv-v2')",
    ).bind(mount_id.to_string()).bind(org_id.to_string()).bind(env_id.to_string())
     .execute(pool).await?;

    Ok((org_id, env_id))
}

async fn not_found(uri: axum::http::Uri, headers: axum::http::HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    let path = uri.path();
    let wants_json = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.contains("application/json"))
        .unwrap_or(false);

    if wants_json {
        (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({ "error": "not_found", "path": path })),
        ).into_response()
    } else {
        let body = format!(r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>404 — secretd</title>
  <style>
    body {{ font-family: monospace; max-width: 640px; margin: 80px auto; padding: 0 24px; color: #cdd6f4; background: #1e1e2e; }}
    h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}
    p  {{ color: #a6adc8; font-size: 0.875rem; margin: 0 0 2rem; }}
    .path {{ color: #f38ba8; }}
    a {{ color: #cba6f7; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <h1>404 Not Found</h1>
  <p>No route for <span class="path">{path}</span></p>
  <a href="/">← back to index</a>
</body>
</html>"#);
        (axum::http::StatusCode::NOT_FOUND, axum::response::Html(body)).into_response()
    }
}

async fn home() -> axum::response::Html<&'static str> {
    axum::response::Html(r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>secretd</title>
  <style>
    body { font-family: monospace; max-width: 640px; margin: 80px auto; padding: 0 24px; color: #cdd6f4; background: #1e1e2e; }
    h1 { font-size: 1.4rem; margin-bottom: 0.25rem; }
    p  { color: #a6adc8; margin: 0 0 2rem; font-size: 0.875rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
    th { text-align: left; color: #6c7086; font-weight: normal; padding: 4px 0; border-bottom: 1px solid #313244; }
    td { padding: 6px 0; border-bottom: 1px solid #181825; vertical-align: top; }
    td:first-child { color: #89b4fa; width: 120px; }
    td:nth-child(2) { color: #a6e3a1; padding-right: 16px; white-space: nowrap; }
    a { color: #cba6f7; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <h1>secretd</h1>
  <p>Open-source secrets manager</p>
  <table>
    <thead><tr><th>Interface</th><th>Mount</th><th>Description</th></tr></thead>
    <tbody>
      <tr><td>Dashboard</td><td><a href="/ui/">/ui/</a></td><td>Web UI</td></tr>
      <tr><td>Vault KV v2</td><td>/v1/</td><td>HashiCorp Vault-compatible API</td></tr>
      <tr><td>AWS Secrets</td><td>/</td><td>AWS SecretsManager shim (POST)</td></tr>
      <tr><td>GCP</td><td>/gcp/</td><td>GCP Secret Manager shim</td></tr>
      <tr><td>Azure</td><td>/azure/</td><td>Azure Key Vault shim</td></tr>
      <tr><td>Bitwarden</td><td>/bitwarden/</td><td>Bitwarden Secrets Manager shim</td></tr>
      <tr><td>Cloudflare</td><td>/client/</td><td>Cloudflare Workers secrets shim</td></tr>
      <tr><td>Health</td><td><a href="/v1/sys/health">/v1/sys/health</a></td><td>Liveness check</td></tr>
    </tbody>
  </table>
</body>
</html>"#)
}
