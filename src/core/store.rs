//! High-level SecretStore wraps the DB backend + crypto engine.
use crate::core::crypto::CryptoEngine;
use crate::db::{SecretBackend, SecretMeta, SecretValue, WriteSecret};
use std::sync::Arc;
use uuid::Uuid;

pub struct SecretStore {
    backend: Arc<dyn SecretBackend>,
    crypto: Arc<CryptoEngine>,
}

impl SecretStore {
    pub fn new(backend: Arc<dyn SecretBackend>, crypto: Arc<CryptoEngine>) -> Self {
        Self { backend, crypto }
    }

    pub fn backend(&self) -> Arc<dyn SecretBackend> {
        self.backend.clone()
    }

    pub fn crypto(&self) -> Arc<CryptoEngine> {
        self.crypto.clone()
    }

    pub async fn put(
        &self,
        environment_id: Uuid,
        path: &str,
        name: &str,
        plaintext: &[u8],
        value_type: &str,
        actor_id: Option<Uuid>,
    ) -> anyhow::Result<SecretValue> {
        // Check if secret already exists — if so, update
        match self
            .backend
            .get_secret(environment_id, path, name, None)
            .await
        {
            Ok(existing) => {
                let result = self
                    .backend
                    .update_secret(
                        existing.secret.id,
                        WriteSecret {
                            environment_id,
                            name: name.to_string(),
                            path: path.to_string(),
                            plaintext: plaintext.to_vec(),
                            value_type: value_type.to_string(),
                            description: None,
                            tags: None,
                            actor_id,
                        },
                    )
                    .await?;
                Ok(result)
            }
            Err(crate::db::DbError::NotFound) => {
                let result = self
                    .backend
                    .create_secret(WriteSecret {
                        environment_id,
                        name: name.to_string(),
                        path: path.to_string(),
                        plaintext: plaintext.to_vec(),
                        value_type: value_type.to_string(),
                        description: None,
                        tags: None,
                        actor_id,
                    })
                    .await?;
                Ok(result)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub async fn get(
        &self,
        environment_id: Uuid,
        path: &str,
        name: &str,
        version: Option<i32>,
    ) -> anyhow::Result<SecretValue> {
        Ok(self
            .backend
            .get_secret(environment_id, path, name, version)
            .await?)
    }

    pub async fn list(
        &self,
        environment_id: Uuid,
        path: &str,
    ) -> anyhow::Result<Vec<SecretMeta>> {
        Ok(self.backend.list_secrets(environment_id, path).await?)
    }

    pub async fn delete(&self, secret_id: Uuid) -> anyhow::Result<()> {
        Ok(self.backend.delete_secret(secret_id).await?)
    }
}
