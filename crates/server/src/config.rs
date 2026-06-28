//! Server configuration loaded from environment variables (12-factor style).
use anyhow::{Context, Result};

pub struct Config {
    pub listen_addr: String,
    pub database_url: String,
    pub dev_root_token: String,
    pub jwt_secret: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            listen_addr: std::env::var("SECRETD_LISTEN")
                .unwrap_or_else(|_| "0.0.0.0:8200".into()),
            database_url: std::env::var("DATABASE_URL")
                .context("DATABASE_URL not set")?,
            dev_root_token: std::env::var("SECRETD_DEV_ROOT_TOKEN")
                .unwrap_or_else(|_| "dev-root-token".into()),
            jwt_secret: std::env::var("SECRETD_JWT_SECRET")
                .unwrap_or_else(|_| "change-me-in-production".into()),
        })
    }
}
