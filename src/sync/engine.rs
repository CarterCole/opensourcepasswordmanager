//! Sync engine: push/pull/bidirectional between local store and cloud providers.
use std::sync::Arc;

use crate::core::SecretStore;
use crate::db::SecretBackend;

// ── config types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Deserialize)]
pub struct SyncConfig {
    pub provider: String,
    pub direction: SyncDirection,
    pub environment_id: uuid::Uuid,
    pub path_filter: Option<String>,
    pub schedule_cron: Option<String>,
    pub credentials: SyncCredentials,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SyncDirection {
    Push,
    Pull,
    Bidirectional,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "provider", rename_all = "lowercase")]
pub enum SyncCredentials {
    Aws {
        endpoint_url: Option<String>,
        access_key_id: String,
        secret_access_key: String,
        region: String,
    },
    Gcp {
        endpoint_url: Option<String>,
        project_id: String,
        token: String,
    },
    Azure {
        vault_url: String,
        client_id: String,
        client_secret: String,
        tenant_id: String,
    },
    Vault {
        address: String,
        token: String,
        mount: String,
    },
}

// ── report ────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct SyncReport {
    pub pushed: usize,
    pub pulled: usize,
    pub conflicts: usize,
    pub errors: Vec<String>,
}

// ── remote secret ─────────────────────────────────────────────────────────────

pub struct RemoteSecret {
    pub name: String,
    pub version_id: String,
    pub last_changed: chrono::DateTime<chrono::Utc>,
}

// ── engine ────────────────────────────────────────────────────────────────────

pub struct SyncEngine {
    store: Arc<SecretStore>,
    db: Arc<dyn SecretBackend>,
    client: reqwest::Client,
}

impl SyncEngine {
    pub fn new(store: Arc<SecretStore>, db: Arc<dyn SecretBackend>) -> Self {
        Self {
            store,
            db,
            client: reqwest::Client::new(),
        }
    }

    pub async fn sync(&self, config: &SyncConfig) -> anyhow::Result<SyncReport> {
        match config.direction {
            SyncDirection::Push => self.push(config).await,
            SyncDirection::Pull => self.pull(config).await,
            SyncDirection::Bidirectional => {
                let mut report = self.push(config).await?;
                let pull_report = self.pull(config).await?;
                report.pulled += pull_report.pulled;
                report.conflicts += pull_report.conflicts;
                report.errors.extend(pull_report.errors);
                Ok(report)
            }
        }
    }

    pub async fn push(&self, config: &SyncConfig) -> anyhow::Result<SyncReport> {
        let mut report = SyncReport::default();
        let path = config.path_filter.as_deref().unwrap_or("/");

        let locals = self.store.list(config.environment_id, path).await?;

        for meta in &locals {
            let sv = match self
                .store
                .get(config.environment_id, &meta.path, &meta.name, None)
                .await
            {
                Ok(v) => v,
                Err(e) => {
                    report.errors.push(format!("read {}: {e}", meta.name));
                    continue;
                }
            };
            let value = String::from_utf8_lossy(&sv.plaintext).to_string();

            let result = match &config.credentials {
                SyncCredentials::Aws {
                    endpoint_url,
                    access_key_id,
                    secret_access_key,
                    region,
                } => {
                    use crate::sync::providers::aws::{AwsCredentials, AwsProvider};
                    let creds = AwsCredentials {
                        endpoint_url: endpoint_url.clone(),
                        access_key_id: access_key_id.clone(),
                        secret_access_key: secret_access_key.clone(),
                        region: region.clone(),
                    };
                    let provider = AwsProvider::new(self.client.clone(), creds);
                    provider.put_secret(&meta.name, &value).await
                }
                SyncCredentials::Gcp {
                    endpoint_url,
                    project_id,
                    token,
                } => {
                    use crate::sync::providers::gcp::{GcpCredentials, GcpProvider};
                    let creds = GcpCredentials {
                        endpoint_url: endpoint_url.clone(),
                        project_id: project_id.clone(),
                        token: token.clone(),
                    };
                    let provider = GcpProvider::new(self.client.clone(), creds);
                    provider.put_secret(&meta.name, &value).await
                }
                SyncCredentials::Azure {
                    vault_url,
                    client_id,
                    client_secret,
                    tenant_id,
                } => {
                    use crate::sync::providers::azure::{AzureCredentials, AzureProvider};
                    let creds = AzureCredentials {
                        vault_url: vault_url.clone(),
                        client_id: client_id.clone(),
                        client_secret: client_secret.clone(),
                        tenant_id: tenant_id.clone(),
                    };
                    let provider = AzureProvider::new(self.client.clone(), creds);
                    provider.put_secret(&meta.name, &value).await
                }
                SyncCredentials::Vault {
                    address,
                    token,
                    mount,
                } => {
                    use crate::sync::providers::vault::{VaultCredentials, VaultProvider};
                    let creds = VaultCredentials {
                        address: address.clone(),
                        token: token.clone(),
                        mount: mount.clone(),
                    };
                    let provider = VaultProvider::new(self.client.clone(), creds);
                    provider.put_secret(&meta.name, &value).await
                }
            };

            match result {
                Ok(()) => report.pushed += 1,
                Err(e) => report.errors.push(format!("push {}: {e}", meta.name)),
            }
        }

        Ok(report)
    }

    pub async fn pull(&self, config: &SyncConfig) -> anyhow::Result<SyncReport> {
        let mut report = SyncReport::default();

        let remote_secrets: anyhow::Result<Vec<RemoteSecret>> = match &config.credentials {
            SyncCredentials::Aws {
                endpoint_url,
                access_key_id,
                secret_access_key,
                region,
            } => {
                use crate::sync::providers::aws::{AwsCredentials, AwsProvider};
                let creds = AwsCredentials {
                    endpoint_url: endpoint_url.clone(),
                    access_key_id: access_key_id.clone(),
                    secret_access_key: secret_access_key.clone(),
                    region: region.clone(),
                };
                AwsProvider::new(self.client.clone(), creds)
                    .list_secrets()
                    .await
            }
            SyncCredentials::Gcp {
                endpoint_url,
                project_id,
                token,
            } => {
                use crate::sync::providers::gcp::{GcpCredentials, GcpProvider};
                let creds = GcpCredentials {
                    endpoint_url: endpoint_url.clone(),
                    project_id: project_id.clone(),
                    token: token.clone(),
                };
                GcpProvider::new(self.client.clone(), creds)
                    .list_secrets()
                    .await
            }
            SyncCredentials::Azure {
                vault_url,
                client_id,
                client_secret,
                tenant_id,
            } => {
                use crate::sync::providers::azure::{AzureCredentials, AzureProvider};
                let creds = AzureCredentials {
                    vault_url: vault_url.clone(),
                    client_id: client_id.clone(),
                    client_secret: client_secret.clone(),
                    tenant_id: tenant_id.clone(),
                };
                AzureProvider::new(self.client.clone(), creds)
                    .list_secrets()
                    .await
            }
            SyncCredentials::Vault {
                address,
                token,
                mount,
            } => {
                use crate::sync::providers::vault::{VaultCredentials, VaultProvider};
                let creds = VaultCredentials {
                    address: address.clone(),
                    token: token.clone(),
                    mount: mount.clone(),
                };
                VaultProvider::new(self.client.clone(), creds)
                    .list_secrets()
                    .await
            }
        };

        let remote_secrets = match remote_secrets {
            Ok(v) => v,
            Err(e) => {
                report.errors.push(format!("list remote: {e}"));
                return Ok(report);
            }
        };

        let path = config.path_filter.as_deref().unwrap_or("/");

        for remote in &remote_secrets {
            // Fetch remote value
            let value_result: anyhow::Result<String> = match &config.credentials {
                SyncCredentials::Aws {
                    endpoint_url,
                    access_key_id,
                    secret_access_key,
                    region,
                } => {
                    use crate::sync::providers::aws::{AwsCredentials, AwsProvider};
                    let creds = AwsCredentials {
                        endpoint_url: endpoint_url.clone(),
                        access_key_id: access_key_id.clone(),
                        secret_access_key: secret_access_key.clone(),
                        region: region.clone(),
                    };
                    AwsProvider::new(self.client.clone(), creds)
                        .get_secret(&remote.name)
                        .await
                }
                SyncCredentials::Gcp {
                    endpoint_url,
                    project_id,
                    token,
                } => {
                    use crate::sync::providers::gcp::{GcpCredentials, GcpProvider};
                    let creds = GcpCredentials {
                        endpoint_url: endpoint_url.clone(),
                        project_id: project_id.clone(),
                        token: token.clone(),
                    };
                    GcpProvider::new(self.client.clone(), creds)
                        .get_secret(&remote.name)
                        .await
                }
                SyncCredentials::Azure {
                    vault_url,
                    client_id,
                    client_secret,
                    tenant_id,
                } => {
                    use crate::sync::providers::azure::{AzureCredentials, AzureProvider};
                    let creds = AzureCredentials {
                        vault_url: vault_url.clone(),
                        client_id: client_id.clone(),
                        client_secret: client_secret.clone(),
                        tenant_id: tenant_id.clone(),
                    };
                    AzureProvider::new(self.client.clone(), creds)
                        .get_secret(&remote.name)
                        .await
                }
                SyncCredentials::Vault {
                    address,
                    token,
                    mount,
                } => {
                    use crate::sync::providers::vault::{VaultCredentials, VaultProvider};
                    let creds = VaultCredentials {
                        address: address.clone(),
                        token: token.clone(),
                        mount: mount.clone(),
                    };
                    VaultProvider::new(self.client.clone(), creds)
                        .get_secret(&remote.name)
                        .await
                }
            };

            match value_result {
                Ok(value) => {
                    match self
                        .store
                        .put(
                            config.environment_id,
                            path,
                            &remote.name,
                            value.as_bytes(),
                            "string",
                            None,
                        )
                        .await
                    {
                        Ok(_) => report.pulled += 1,
                        Err(e) => report.errors.push(format!("store {}: {e}", remote.name)),
                    }
                }
                Err(e) => report.errors.push(format!("fetch {}: {e}", remote.name)),
            }
        }

        Ok(report)
    }
}
