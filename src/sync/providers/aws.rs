//! AWS Secrets Manager sync provider.
use crate::sync::engine::RemoteSecret;

pub struct AwsCredentials {
    pub endpoint_url: Option<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub region: String,
}

pub struct AwsProvider {
    client: reqwest::Client,
    creds: AwsCredentials,
}

impl AwsProvider {
    pub fn new(client: reqwest::Client, creds: AwsCredentials) -> Self {
        Self { client, creds }
    }

    fn endpoint(&self) -> String {
        self.creds.endpoint_url.clone().unwrap_or_else(|| {
            format!("https://secretsmanager.{}.amazonaws.com", self.creds.region)
        })
    }

    fn auth_header(&self) -> String {
        format!(
            "AWS4-HMAC-SHA256 Credential={}/dev-date/{}/secretsmanager/aws4_request",
            self.creds.access_key_id, self.creds.region
        )
    }

    pub async fn list_secrets(&self) -> anyhow::Result<Vec<RemoteSecret>> {
        let resp: serde_json::Value = self
            .client
            .post(self.endpoint())
            .header("X-Amz-Target", "secretsmanager.ListSecrets")
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("Authorization", self.auth_header())
            .json(&serde_json::json!({}))
            .send()
            .await?
            .json()
            .await?;

        let secrets = resp
            .get("SecretList")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        Ok(secrets
            .iter()
            .filter_map(|s| {
                let name = s.get("Name")?.as_str()?.to_string();
                let version_id = s
                    .get("VersionId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let ts = s
                    .get("LastChangedDate")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let last_changed =
                    chrono::DateTime::from_timestamp(ts, 0).unwrap_or_else(chrono::Utc::now);
                Some(RemoteSecret {
                    name,
                    version_id,
                    last_changed,
                })
            })
            .collect())
    }

    pub async fn get_secret(&self, name: &str) -> anyhow::Result<String> {
        let resp: serde_json::Value = self
            .client
            .post(self.endpoint())
            .header("X-Amz-Target", "secretsmanager.GetSecretValue")
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("Authorization", self.auth_header())
            .json(&serde_json::json!({ "SecretId": name }))
            .send()
            .await?
            .json()
            .await?;

        Ok(resp
            .get("SecretString")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }

    pub async fn put_secret(&self, name: &str, value: &str) -> anyhow::Result<()> {
        // Try PutSecretValue first; if 404 fall back to CreateSecret
        let resp = self
            .client
            .post(self.endpoint())
            .header("X-Amz-Target", "secretsmanager.PutSecretValue")
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("Authorization", self.auth_header())
            .json(&serde_json::json!({ "SecretId": name, "SecretString": value }))
            .send()
            .await?;

        if resp.status().as_u16() == 404 {
            self.client
                .post(self.endpoint())
                .header("X-Amz-Target", "secretsmanager.CreateSecret")
                .header("Content-Type", "application/x-amz-json-1.1")
                .header("Authorization", self.auth_header())
                .json(&serde_json::json!({ "Name": name, "SecretString": value }))
                .send()
                .await?;
        }

        Ok(())
    }

    pub async fn delete_secret(&self, name: &str) -> anyhow::Result<()> {
        self.client
            .post(self.endpoint())
            .header("X-Amz-Target", "secretsmanager.DeleteSecret")
            .header("Content-Type", "application/x-amz-json-1.1")
            .header("Authorization", self.auth_header())
            .json(&serde_json::json!({
                "SecretId": name,
                "ForceDeleteWithoutRecovery": true,
            }))
            .send()
            .await?;
        Ok(())
    }
}
