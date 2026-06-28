//! HashiCorp Vault / OpenBao sync provider.
use crate::sync::engine::RemoteSecret;

pub struct VaultCredentials {
    pub address: String,
    pub token: String,
    pub mount: String,
}

pub struct VaultProvider {
    client: reqwest::Client,
    creds: VaultCredentials,
}

impl VaultProvider {
    pub fn new(client: reqwest::Client, creds: VaultCredentials) -> Self {
        Self { client, creds }
    }

    fn base(&self) -> String {
        format!("{}/v1/{}", self.creds.address, self.creds.mount)
    }

    pub async fn list_secrets(&self) -> anyhow::Result<Vec<RemoteSecret>> {
        let url = format!("{}/metadata?list=true", self.base());
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.creds.token)
            .send()
            .await?
            .json()
            .await?;

        let keys = resp
            .get("data")
            .and_then(|d| d.get("keys"))
            .and_then(|k| k.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(keys
            .iter()
            .filter_map(|k| {
                let name = k.as_str()?.trim_end_matches('/').to_string();
                Some(RemoteSecret {
                    name,
                    version_id: String::new(),
                    last_changed: chrono::Utc::now(),
                })
            })
            .collect())
    }

    pub async fn get_secret(&self, name: &str) -> anyhow::Result<String> {
        let url = format!("{}/data/{}", self.base(), name);
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.creds.token)
            .send()
            .await?
            .json()
            .await?;

        // KV v2 format: data.data.VALUE (first value in the map)
        let data = resp
            .get("data")
            .and_then(|d| d.get("data"))
            .and_then(|d| d.as_object());

        if let Some(map) = data {
            if let Some(val) = map.values().next().and_then(|v| v.as_str()) {
                return Ok(val.to_string());
            }
        }

        Ok(String::new())
    }

    pub async fn put_secret(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let url = format!("{}/data/{}", self.base(), name);
        self.client
            .post(&url)
            .header("X-Vault-Token", &self.creds.token)
            .json(&serde_json::json!({ "data": { "value": value } }))
            .send()
            .await?;
        Ok(())
    }

    pub async fn delete_secret(&self, name: &str) -> anyhow::Result<()> {
        let url = format!("{}/metadata/{}", self.base(), name);
        self.client
            .delete(&url)
            .header("X-Vault-Token", &self.creds.token)
            .send()
            .await?;
        Ok(())
    }
}
