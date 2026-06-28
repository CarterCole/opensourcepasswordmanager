//! Azure Key Vault sync provider.
use crate::sync::engine::RemoteSecret;

pub struct AzureCredentials {
    pub vault_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub tenant_id: String,
}

pub struct AzureProvider {
    client: reqwest::Client,
    creds: AzureCredentials,
}

impl AzureProvider {
    pub fn new(client: reqwest::Client, creds: AzureCredentials) -> Self {
        Self { client, creds }
    }

    fn vault_url(&self) -> &str {
        &self.creds.vault_url
    }

    /// Get a bearer token via OAuth2 client_credentials (or return a stub for dev).
    async fn get_token(&self) -> anyhow::Result<String> {
        let token_url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.creds.tenant_id
        );
        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", &self.creds.client_id),
            ("client_secret", &self.creds.client_secret),
            ("scope", "https://vault.azure.net/.default"),
        ];
        let resp: serde_json::Value = self
            .client
            .post(&token_url)
            .form(&params)
            .send()
            .await?
            .json()
            .await?;

        Ok(resp
            .get("access_token")
            .and_then(|v| v.as_str())
            .unwrap_or("dev-token")
            .to_string())
    }

    pub async fn list_secrets(&self) -> anyhow::Result<Vec<RemoteSecret>> {
        let token = self.get_token().await.unwrap_or_else(|_| "dev".to_string());
        let url = format!("{}/secrets?api-version=7.4", self.vault_url());
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await?
            .json()
            .await?;

        let items = resp
            .get("value")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(items
            .iter()
            .filter_map(|item| {
                let id = item.get("id")?.as_str()?;
                // https://VAULT.vault.azure.net/secrets/NAME/VERSION → NAME
                let name = id.split('/').rev().nth(1)?.to_string();
                let ts = item
                    .get("attributes")
                    .and_then(|a| a.get("updated"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let last_changed =
                    chrono::DateTime::from_timestamp(ts, 0).unwrap_or_else(chrono::Utc::now);
                Some(RemoteSecret {
                    name,
                    version_id: String::new(),
                    last_changed,
                })
            })
            .collect())
    }

    pub async fn get_secret(&self, name: &str) -> anyhow::Result<String> {
        let token = self.get_token().await.unwrap_or_else(|_| "dev".to_string());
        let url = format!("{}/secrets/{}?api-version=7.4", self.vault_url(), name);
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await?
            .json()
            .await?;

        Ok(resp
            .get("value")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }

    pub async fn put_secret(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let token = self.get_token().await.unwrap_or_else(|_| "dev".to_string());
        let url = format!("{}/secrets/{}?api-version=7.4", self.vault_url(), name);
        self.client
            .put(&url)
            .bearer_auth(&token)
            .json(&serde_json::json!({ "value": value }))
            .send()
            .await?;
        Ok(())
    }

    pub async fn delete_secret(&self, name: &str) -> anyhow::Result<()> {
        let token = self.get_token().await.unwrap_or_else(|_| "dev".to_string());
        let url = format!("{}/secrets/{}?api-version=7.4", self.vault_url(), name);
        self.client
            .delete(&url)
            .bearer_auth(&token)
            .send()
            .await?;
        Ok(())
    }
}
