//! GCP Secret Manager sync provider.
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use crate::sync::engine::RemoteSecret;

pub struct GcpCredentials {
    pub endpoint_url: Option<String>,
    pub project_id: String,
    pub token: String,
}

pub struct GcpProvider {
    client: reqwest::Client,
    creds: GcpCredentials,
}

impl GcpProvider {
    pub fn new(client: reqwest::Client, creds: GcpCredentials) -> Self {
        Self { client, creds }
    }

    fn base_url(&self) -> String {
        self.creds
            .endpoint_url
            .clone()
            .unwrap_or_else(|| "https://secretmanager.googleapis.com".to_string())
    }

    fn project_url(&self) -> String {
        format!(
            "{}/v1/projects/{}",
            self.base_url(),
            self.creds.project_id
        )
    }

    pub async fn list_secrets(&self) -> anyhow::Result<Vec<RemoteSecret>> {
        let url = format!("{}/secrets", self.project_url());
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .bearer_auth(&self.creds.token)
            .send()
            .await?
            .json()
            .await?;

        let secrets = resp
            .get("secrets")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(secrets
            .iter()
            .filter_map(|s| {
                let resource = s.get("name")?.as_str()?;
                // projects/PROJECT/secrets/NAME → NAME
                let name = resource.rsplit('/').next()?.to_string();
                Some(RemoteSecret {
                    name,
                    version_id: "latest".to_string(),
                    last_changed: chrono::Utc::now(),
                })
            })
            .collect())
    }

    pub async fn get_secret(&self, name: &str) -> anyhow::Result<String> {
        let url = format!(
            "{}/secrets/{}/versions/latest:access",
            self.project_url(),
            name
        );
        let resp: serde_json::Value = self
            .client
            .get(&url)
            .bearer_auth(&self.creds.token)
            .send()
            .await?
            .json()
            .await?;

        let data_b64 = resp
            .get("payload")
            .and_then(|p| p.get("data"))
            .and_then(|d| d.as_str())
            .unwrap_or("");

        let bytes = B64.decode(data_b64)?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    pub async fn put_secret(&self, name: &str, value: &str) -> anyhow::Result<()> {
        // Ensure secret container exists
        let create_url = format!("{}/secrets?secretId={}", self.project_url(), name);
        self.client
            .post(&create_url)
            .bearer_auth(&self.creds.token)
            .json(&serde_json::json!({ "replication": { "automatic": {} } }))
            .send()
            .await
            .ok(); // ignore error if already exists

        // Add version
        let add_url = format!("{}/secrets/{}:addVersion", self.project_url(), name);
        let encoded = B64.encode(value.as_bytes());
        self.client
            .post(&add_url)
            .bearer_auth(&self.creds.token)
            .json(&serde_json::json!({ "payload": { "data": encoded } }))
            .send()
            .await?;

        Ok(())
    }

    pub async fn delete_secret(&self, name: &str) -> anyhow::Result<()> {
        let url = format!("{}/secrets/{}", self.project_url(), name);
        self.client
            .delete(&url)
            .bearer_auth(&self.creds.token)
            .send()
            .await?;
        Ok(())
    }
}
