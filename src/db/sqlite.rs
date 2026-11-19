//! SQLite backend — full implementation for zero-dependency local/demo use.
use crate::db::{DbError, EncryptResult, Result, SecretBackend, models::*};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::{Pool, Row, Sqlite};
use uuid::Uuid;

#[derive(Clone)]
pub struct SqliteBackend {
    pool: Pool<Sqlite>,
    encrypt: std::sync::Arc<dyn Fn(&[u8]) -> anyhow::Result<EncryptResult> + Send + Sync>,
    decrypt: std::sync::Arc<dyn Fn(&[u8], &[u8], &[u8]) -> anyhow::Result<Vec<u8>> + Send + Sync>,
}

impl SqliteBackend {
    pub fn new(
        pool: Pool<Sqlite>,
        encrypt: impl Fn(&[u8]) -> anyhow::Result<EncryptResult> + Send + Sync + 'static,
        decrypt: impl Fn(&[u8], &[u8], &[u8]) -> anyhow::Result<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            pool,
            encrypt: std::sync::Arc::new(encrypt),
            decrypt: std::sync::Arc::new(decrypt),
        }
    }

    async fn ensure_kek(&self) -> Result<Uuid> {
        let id = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO kek_versions (id, provider, is_active) VALUES (?, 'local', 1)",
        )
        .bind(id.to_string())
        .execute(&self.pool)
        .await
        .map_err(DbError::Sqlx)?;
        Ok(id)
    }
}

fn ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .or_else(|_| DateTime::parse_from_str(&format!("{s}+00:00"), "%Y-%m-%d %H:%M:%S%z"))
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

fn now() -> String { Utc::now().to_rfc3339() }

fn get_ts(row: &sqlx::sqlite::SqliteRow, col: &str) -> DateTime<Utc> {
    row.try_get::<String, _>(col).map(|s| ts(&s)).unwrap_or_else(|_| Utc::now())
}

fn get_opt_ts(row: &sqlx::sqlite::SqliteRow, col: &str) -> Option<DateTime<Utc>> {
    row.try_get::<Option<String>, _>(col).ok().flatten().map(|s| ts(&s))
}

fn parse_uuid(row: &sqlx::sqlite::SqliteRow, col: &str) -> Result<Uuid> {
    let s: String = row.try_get(col).map_err(DbError::Sqlx)?;
    Uuid::parse_str(&s).map_err(|e| DbError::Invalid(e.to_string()))
}

#[async_trait]
impl SecretBackend for SqliteBackend {
    async fn create_secret(&self, input: WriteSecret) -> Result<SecretValue> {
        let kek_id = self.ensure_kek().await?;
        let enc = (self.encrypt)(&input.plaintext).map_err(|e| DbError::Invalid(e.to_string()))?;

        let secret_id = Uuid::new_v4();
        let version_id = Uuid::new_v4();
        let n = now();

        sqlx::query(
            "INSERT OR IGNORE INTO data_encryption_keys (id, kek_version_id, encrypted_dek) VALUES (?, ?, ?)",
        )
        .bind(enc.dek_id.to_string()).bind(kek_id.to_string()).bind(&enc.encrypted_dek)
        .execute(&self.pool).await.map_err(DbError::Sqlx)?;

        sqlx::query(
            "INSERT INTO secrets (id, environment_id, name, path, description, tags, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, '{}', ?, ?)",
        )
        .bind(secret_id.to_string()).bind(input.environment_id.to_string())
        .bind(&input.name).bind(&input.path).bind(&input.description)
        .bind(&n).bind(&n)
        .execute(&self.pool).await.map_err(|e| match e {
            sqlx::Error::Database(d) if d.message().contains("UNIQUE") =>
                DbError::Conflict(format!("'{}' already exists at '{}'", input.name, input.path)),
            e => DbError::Sqlx(e),
        })?;

        sqlx::query(
            "INSERT INTO secret_versions
             (id, secret_id, version_num, dek_id, encrypted_value, nonce, value_type, created_at)
             VALUES (?, ?, 1, ?, ?, ?, ?, ?)",
        )
        .bind(version_id.to_string()).bind(secret_id.to_string())
        .bind(enc.dek_id.to_string()).bind(&enc.ciphertext).bind(&enc.nonce)
        .bind(&input.value_type).bind(&n)
        .execute(&self.pool).await.map_err(DbError::Sqlx)?;

        sqlx::query(
            "INSERT OR REPLACE INTO secret_labels (secret_id, label, version_num) VALUES (?, 'AWSCURRENT', 1)",
        )
        .bind(secret_id.to_string()).execute(&self.pool).await.map_err(DbError::Sqlx)?;

        let now_dt = Utc::now();
        Ok(SecretValue {
            secret: Secret {
                id: secret_id,
                environment_id: input.environment_id,
                name: input.name,
                path: input.path,
                description: input.description,
                tags: serde_json::Value::Object(Default::default()),
                created_at: now_dt,
                updated_at: now_dt,
                deleted_at: None,
            },
            version: SecretVersion {
                id: version_id,
                secret_id,
                version_num: 1,
                dek_id: enc.dek_id,
                encrypted_value: enc.ciphertext,
                nonce: enc.nonce,
                value_type: input.value_type.clone(),
                created_at: now_dt,
                created_by: input.actor_id,
                deleted_at: None,
                destroyed_at: None,
            },
            plaintext: input.plaintext,
            value_type: input.value_type,
        })
    }

    async fn get_secret(&self, environment_id: Uuid, path: &str, name: &str, version: Option<i32>) -> Result<SecretValue> {
        let row = if let Some(v) = version {
            sqlx::query(
                "SELECT s.id as s_id, s.environment_id, s.name, s.path, s.description, s.tags,
                        s.created_at as s_ca, s.updated_at as s_ua, s.deleted_at as s_da,
                        sv.id as v_id, sv.secret_id, sv.version_num, sv.dek_id,
                        sv.encrypted_value, sv.nonce, sv.value_type,
                        sv.created_at as v_ca, sv.created_by, sv.deleted_at as v_da, sv.destroyed_at,
                        dk.encrypted_dek
                 FROM secrets s
                 JOIN secret_versions sv ON sv.secret_id = s.id AND sv.version_num = ?
                      AND sv.deleted_at IS NULL AND sv.destroyed_at IS NULL
                 JOIN data_encryption_keys dk ON dk.id = sv.dek_id
                 WHERE s.environment_id = ? AND s.path = ? AND s.name = ? AND s.deleted_at IS NULL",
            )
            .bind(v).bind(environment_id.to_string()).bind(path).bind(name)
            .fetch_optional(&self.pool).await.map_err(DbError::Sqlx)?
        } else {
            sqlx::query(
                "SELECT s.id as s_id, s.environment_id, s.name, s.path, s.description, s.tags,
                        s.created_at as s_ca, s.updated_at as s_ua, s.deleted_at as s_da,
                        sv.id as v_id, sv.secret_id, sv.version_num, sv.dek_id,
                        sv.encrypted_value, sv.nonce, sv.value_type,
                        sv.created_at as v_ca, sv.created_by, sv.deleted_at as v_da, sv.destroyed_at,
                        dk.encrypted_dek
                 FROM secrets s
                 JOIN secret_versions sv ON sv.secret_id = s.id AND sv.deleted_at IS NULL AND sv.destroyed_at IS NULL
                 JOIN data_encryption_keys dk ON dk.id = sv.dek_id
                 WHERE s.environment_id = ? AND s.path = ? AND s.name = ? AND s.deleted_at IS NULL
                 ORDER BY sv.version_num DESC LIMIT 1",
            )
            .bind(environment_id.to_string()).bind(path).bind(name)
            .fetch_optional(&self.pool).await.map_err(DbError::Sqlx)?
        };

        let row = row.ok_or(DbError::NotFound)?;

        let ct: Vec<u8> = row.try_get("encrypted_value").map_err(DbError::Sqlx)?;
        let nonce: Vec<u8> = row.try_get("nonce").map_err(DbError::Sqlx)?;
        let dek: Vec<u8> = row.try_get("encrypted_dek").map_err(DbError::Sqlx)?;
        let plaintext = (self.decrypt)(&ct, &nonce, &dek).map_err(|e| DbError::Invalid(e.to_string()))?;

        let value_type: String = row.try_get("value_type").unwrap_or_else(|_| "string".into());

        Ok(SecretValue {
            secret: Secret {
                id: parse_uuid(&row, "s_id")?,
                environment_id: parse_uuid(&row, "environment_id")?,
                name: row.try_get("name").map_err(DbError::Sqlx)?,
                path: row.try_get("path").map_err(DbError::Sqlx)?,
                description: row.try_get("description").ok().flatten(),
                tags: row.try_get::<Option<String>, _>("tags").ok().flatten()
                    .and_then(|s| serde_json::from_str(&s).ok())
                    .unwrap_or_default(),
                created_at: get_ts(&row, "s_ca"),
                updated_at: get_ts(&row, "s_ua"),
                deleted_at: get_opt_ts(&row, "s_da"),
            },
            version: SecretVersion {
                id: parse_uuid(&row, "v_id")?,
                secret_id: parse_uuid(&row, "secret_id")?,
                version_num: row.try_get("version_num").map_err(DbError::Sqlx)?,
                dek_id: parse_uuid(&row, "dek_id")?,
                encrypted_value: ct,
                nonce,
                value_type: value_type.clone(),
                created_at: get_ts(&row, "v_ca"),
                created_by: row.try_get::<Option<String>, _>("created_by").ok().flatten()
                    .and_then(|s| Uuid::parse_str(&s).ok()),
                deleted_at: get_opt_ts(&row, "v_da"),
                destroyed_at: get_opt_ts(&row, "destroyed_at"),
            },
            plaintext,
            value_type,
        })
    }

    async fn update_secret(&self, secret_id: Uuid, input: WriteSecret) -> Result<SecretValue> {
        let kek_id = self.ensure_kek().await?;
        let enc = (self.encrypt)(&input.plaintext).map_err(|e| DbError::Invalid(e.to_string()))?;
        let n = now();

        let max_v: i32 = sqlx::query(
            "SELECT COALESCE(MAX(version_num), 0) FROM secret_versions WHERE secret_id = ?",
        )
        .bind(secret_id.to_string()).fetch_one(&self.pool).await.map_err(DbError::Sqlx)?
        .try_get(0).unwrap_or(0);

        let new_v = max_v + 1;
        let version_id = Uuid::new_v4();

        sqlx::query(
            "INSERT OR IGNORE INTO data_encryption_keys (id, kek_version_id, encrypted_dek) VALUES (?, ?, ?)",
        )
        .bind(enc.dek_id.to_string()).bind(kek_id.to_string()).bind(&enc.encrypted_dek)
        .execute(&self.pool).await.map_err(DbError::Sqlx)?;

        sqlx::query(
            "INSERT INTO secret_versions (id, secret_id, version_num, dek_id, encrypted_value, nonce, value_type, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(version_id.to_string()).bind(secret_id.to_string()).bind(new_v)
        .bind(enc.dek_id.to_string()).bind(&enc.ciphertext).bind(&enc.nonce)
        .bind(&input.value_type).bind(&n)
        .execute(&self.pool).await.map_err(DbError::Sqlx)?;

        sqlx::query(
            "INSERT OR REPLACE INTO secret_labels (secret_id, label, version_num) VALUES (?, 'AWSPREVIOUS', ?)",
        ).bind(secret_id.to_string()).bind(max_v).execute(&self.pool).await.map_err(DbError::Sqlx)?;
        sqlx::query(
            "INSERT OR REPLACE INTO secret_labels (secret_id, label, version_num) VALUES (?, 'AWSCURRENT', ?)",
        ).bind(secret_id.to_string()).bind(new_v).execute(&self.pool).await.map_err(DbError::Sqlx)?;

        sqlx::query("UPDATE secrets SET updated_at = ? WHERE id = ?")
            .bind(&n).bind(secret_id.to_string()).execute(&self.pool).await.map_err(DbError::Sqlx)?;

        let now_dt = Utc::now();
        Ok(SecretValue {
            secret: Secret {
                id: secret_id,
                environment_id: input.environment_id,
                name: input.name,
                path: input.path,
                description: input.description,
                tags: Default::default(),
                created_at: now_dt,
                updated_at: now_dt,
                deleted_at: None,
            },
            version: SecretVersion {
                id: version_id,
                secret_id,
                version_num: new_v,
                dek_id: enc.dek_id,
                encrypted_value: enc.ciphertext,
                nonce: enc.nonce,
                value_type: input.value_type.clone(),
                created_at: now_dt,
                created_by: input.actor_id,
                deleted_at: None,
                destroyed_at: None,
            },
            plaintext: input.plaintext,
            value_type: input.value_type,
        })
    }

    async fn list_secrets(&self, environment_id: Uuid, path: &str) -> Result<Vec<SecretMeta>> {
        let rows = sqlx::query(
            "SELECT s.id, s.name, s.path, s.tags, s.created_at, s.updated_at, s.deleted_at,
                    COALESCE(MAX(sv.version_num), 0) as cur_ver
             FROM secrets s
             LEFT JOIN secret_versions sv ON sv.secret_id = s.id AND sv.deleted_at IS NULL
             WHERE s.environment_id = ? AND s.path = ? AND s.deleted_at IS NULL
             GROUP BY s.id ORDER BY s.name",
        )
        .bind(environment_id.to_string()).bind(path)
        .fetch_all(&self.pool).await.map_err(DbError::Sqlx)?;

        rows.iter().map(|r| Ok(SecretMeta {
            id: parse_uuid(r, "id")?,
            name: r.try_get("name").map_err(DbError::Sqlx)?,
            path: r.try_get("path").map_err(DbError::Sqlx)?,
            current_version: r.try_get("cur_ver").unwrap_or(0),
            created_at: get_ts(r, "created_at"),
            updated_at: get_ts(r, "updated_at"),
            deleted_at: get_opt_ts(r, "deleted_at"),
            tags: r.try_get::<Option<String>, _>("tags").ok().flatten()
                .and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
        })).collect()
    }

    async fn get_secret_meta(&self, id: Uuid) -> Result<SecretMeta> {
        let r = sqlx::query(
            "SELECT s.id, s.name, s.path, s.tags, s.created_at, s.updated_at, s.deleted_at,
                    COALESCE(MAX(sv.version_num), 0) as cur_ver
             FROM secrets s
             LEFT JOIN secret_versions sv ON sv.secret_id = s.id AND sv.deleted_at IS NULL
             WHERE s.id = ? GROUP BY s.id",
        )
        .bind(id.to_string()).fetch_optional(&self.pool).await.map_err(DbError::Sqlx)?
        .ok_or(DbError::NotFound)?;

        Ok(SecretMeta {
            id,
            name: r.try_get("name").map_err(DbError::Sqlx)?,
            path: r.try_get("path").map_err(DbError::Sqlx)?,
            current_version: r.try_get("cur_ver").unwrap_or(0),
            created_at: get_ts(&r, "created_at"),
            updated_at: get_ts(&r, "updated_at"),
            deleted_at: get_opt_ts(&r, "deleted_at"),
            tags: r.try_get::<Option<String>, _>("tags").ok().flatten()
                .and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
        })
    }

    async fn soft_delete_versions(&self, secret_id: Uuid, versions: &[i32]) -> Result<()> {
        let n = now();
        for v in versions {
            sqlx::query(
                "UPDATE secret_versions SET deleted_at = ? WHERE secret_id = ? AND version_num = ? AND deleted_at IS NULL",
            ).bind(&n).bind(secret_id.to_string()).bind(v).execute(&self.pool).await.map_err(DbError::Sqlx)?;
        }
        Ok(())
    }

    async fn undelete_versions(&self, secret_id: Uuid, versions: &[i32]) -> Result<()> {
        for v in versions {
            sqlx::query(
                "UPDATE secret_versions SET deleted_at = NULL WHERE secret_id = ? AND version_num = ?",
            ).bind(secret_id.to_string()).bind(v).execute(&self.pool).await.map_err(DbError::Sqlx)?;
        }
        Ok(())
    }

    async fn destroy_versions(&self, secret_id: Uuid, versions: &[i32]) -> Result<()> {
        let n = now();
        for v in versions {
            sqlx::query(
                "UPDATE secret_versions SET destroyed_at = ?, encrypted_value = X'', nonce = X''
                 WHERE secret_id = ? AND version_num = ?",
            ).bind(&n).bind(secret_id.to_string()).bind(v).execute(&self.pool).await.map_err(DbError::Sqlx)?;
        }
        Ok(())
    }

    async fn delete_secret(&self, secret_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE secrets SET deleted_at = ? WHERE id = ?")
            .bind(now()).bind(secret_id.to_string())
            .execute(&self.pool).await.map_err(DbError::Sqlx)?;
        Ok(())
    }

    async fn set_label(&self, secret_id: Uuid, label: &str, version_num: i32) -> Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO secret_labels (secret_id, label, version_num) VALUES (?, ?, ?)",
        ).bind(secret_id.to_string()).bind(label).bind(version_num)
        .execute(&self.pool).await.map_err(DbError::Sqlx)?;
        Ok(())
    }

    async fn get_versions(&self, secret_id: Uuid) -> Result<Vec<SecretVersion>> {
        let rows = sqlx::query(
            "SELECT sv.id as v_id, sv.secret_id, sv.version_num, sv.dek_id,
                    sv.encrypted_value, sv.nonce, sv.value_type,
                    sv.created_at as v_ca, sv.created_by, sv.deleted_at as v_da, sv.destroyed_at
             FROM secret_versions sv WHERE sv.secret_id = ? ORDER BY sv.version_num",
        )
        .bind(secret_id.to_string()).fetch_all(&self.pool).await.map_err(DbError::Sqlx)?;

        rows.iter().map(|r| Ok(SecretVersion {
            id: parse_uuid(r, "v_id")?,
            secret_id,
            version_num: r.try_get("version_num").map_err(DbError::Sqlx)?,
            dek_id: parse_uuid(r, "dek_id")?,
            encrypted_value: r.try_get("encrypted_value").map_err(DbError::Sqlx)?,
            nonce: r.try_get("nonce").map_err(DbError::Sqlx)?,
            value_type: r.try_get("value_type").unwrap_or_else(|_| "string".into()),
            created_at: get_ts(r, "v_ca"),
            created_by: r.try_get::<Option<String>, _>("created_by").ok().flatten()
                .and_then(|s| Uuid::parse_str(&s).ok()),
            deleted_at: get_opt_ts(r, "v_da"),
            destroyed_at: get_opt_ts(r, "destroyed_at"),
        })).collect()
    }

    async fn write_audit(&self, org_id: Option<Uuid>, actor_id: Option<Uuid>,
        actor_type: &str, actor_email: Option<&str>, action: &str,
        resource_type: Option<&str>, resource_id: Option<Uuid>,
        resource_name: Option<&str>, ip: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_logs
             (org_id, actor_id, actor_type, actor_email, action, resource_type, resource_id, resource_name, ip_address, metadata, ts)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(org_id.map(|u| u.to_string()))
        .bind(actor_id.map(|u| u.to_string()))
        .bind(actor_type).bind(actor_email).bind(action)
        .bind(resource_type).bind(resource_id.map(|u| u.to_string()))
        .bind(resource_name).bind(ip)
        .bind(serde_json::to_string(&metadata).unwrap_or_else(|_| "{}".into()))
        .bind(now())
        .execute(&self.pool).await.map_err(DbError::Sqlx)?;
        Ok(())
    }

    async fn get_vault_mount(&self, org_id: Uuid, namespace: &str, mount_path: &str) -> Result<VaultMount> {
        let r = sqlx::query(
            "SELECT id, org_id, namespace, mount_path, environment_id, engine_type, config, created_at
             FROM vault_mounts WHERE org_id = ? AND namespace = ? AND mount_path = ?",
        )
        .bind(org_id.to_string()).bind(namespace).bind(mount_path)
        .fetch_optional(&self.pool).await.map_err(DbError::Sqlx)?
        .ok_or(DbError::NotFound)?;
        mount_from_row(&r, org_id)
    }

    async fn list_vault_mounts(&self, org_id: Uuid, namespace: &str) -> Result<Vec<VaultMount>> {
        let rows = sqlx::query(
            "SELECT id, org_id, namespace, mount_path, environment_id, engine_type, config, created_at
             FROM vault_mounts WHERE org_id = ? AND namespace = ? ORDER BY mount_path",
        )
        .bind(org_id.to_string()).bind(namespace)
        .fetch_all(&self.pool).await.map_err(DbError::Sqlx)?;
        rows.iter().map(|r| mount_from_row(r, org_id)).collect()
    }

    async fn create_namespace(&self, org_id: Uuid, path: &str) -> Result<Namespace> {
        if let Some((parent, _)) = path.rsplit_once('/') {
            self.get_namespace(org_id, parent).await?;
        }
        let mut tx = self.pool.begin().await.map_err(DbError::Sqlx)?;

        let project_id: String = sqlx::query_scalar(
            "SELECT id FROM projects WHERE org_id = ? ORDER BY created_at LIMIT 1",
        ).bind(org_id.to_string()).fetch_optional(&mut *tx).await.map_err(DbError::Sqlx)?
            .ok_or(DbError::NotFound)?;

        let ns_id = Uuid::new_v4();
        let ins = sqlx::query(
            "INSERT OR IGNORE INTO namespaces (id, org_id, path, created_at) VALUES (?, ?, ?, ?)",
        ).bind(ns_id.to_string()).bind(org_id.to_string()).bind(path).bind(now())
            .execute(&mut *tx).await.map_err(DbError::Sqlx)?;
        if ins.rows_affected() == 0 {
            return Err(DbError::Conflict("namespace already exists".into()));
        }

        let env_id = Uuid::new_v4();
        sqlx::query("INSERT INTO environments (id, project_id, name, slug) VALUES (?, ?, ?, ?)")
            .bind(env_id.to_string()).bind(&project_id)
            .bind(format!("ns:{path}")).bind(format!("ns-{ns_id}"))
            .execute(&mut *tx).await.map_err(DbError::Sqlx)?;

        sqlx::query(
            "INSERT INTO vault_mounts (id, org_id, namespace, mount_path, environment_id, engine_type)
             VALUES (?, ?, ?, 'secret', ?, 'kv-v2')",
        ).bind(Uuid::new_v4().to_string()).bind(org_id.to_string()).bind(path).bind(env_id.to_string())
            .execute(&mut *tx).await.map_err(DbError::Sqlx)?;

        tx.commit().await.map_err(DbError::Sqlx)?;
        self.get_namespace(org_id, path).await
    }

    async fn get_namespace(&self, org_id: Uuid, path: &str) -> Result<Namespace> {
        let r = sqlx::query("SELECT id, path, created_at FROM namespaces WHERE org_id = ? AND path = ?")
            .bind(org_id.to_string()).bind(path)
            .fetch_optional(&self.pool).await.map_err(DbError::Sqlx)?
            .ok_or(DbError::NotFound)?;
        ns_from_row(&r, org_id)
    }

    async fn list_namespaces(&self, org_id: Uuid) -> Result<Vec<Namespace>> {
        let rows = sqlx::query("SELECT id, path, created_at FROM namespaces WHERE org_id = ? ORDER BY path")
            .bind(org_id.to_string()).fetch_all(&self.pool).await.map_err(DbError::Sqlx)?;
        rows.iter().map(|r| ns_from_row(r, org_id)).collect()
    }

    async fn delete_namespace(&self, org_id: Uuid, path: &str) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(DbError::Sqlx)?;
        let child_like = format!("{}/%", path.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_"));
        let has_children: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM namespaces WHERE org_id = ? AND path LIKE ? ESCAPE '\\')",
        ).bind(org_id.to_string()).bind(&child_like).fetch_one(&mut *tx).await.map_err(DbError::Sqlx)?;
        if has_children {
            return Err(DbError::Conflict("namespace has child namespaces".into()));
        }
        let has_secrets: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM secrets s JOIN vault_mounts m ON m.environment_id = s.environment_id
                WHERE m.org_id = ? AND m.namespace = ? AND s.deleted_at IS NULL)",
        ).bind(org_id.to_string()).bind(path).fetch_one(&mut *tx).await.map_err(DbError::Sqlx)?;
        if has_secrets {
            return Err(DbError::Conflict("namespace is not empty".into()));
        }
        let env_ids: Vec<String> = sqlx::query_scalar(
            "SELECT environment_id FROM vault_mounts WHERE org_id = ? AND namespace = ? AND environment_id IS NOT NULL",
        ).bind(org_id.to_string()).bind(path).fetch_all(&mut *tx).await.map_err(DbError::Sqlx)?;
        sqlx::query("DELETE FROM vault_mounts WHERE org_id = ? AND namespace = ?")
            .bind(org_id.to_string()).bind(path).execute(&mut *tx).await.map_err(DbError::Sqlx)?;
        let gone = sqlx::query("DELETE FROM namespaces WHERE org_id = ? AND path = ?")
            .bind(org_id.to_string()).bind(path).execute(&mut *tx).await.map_err(DbError::Sqlx)?;
        if gone.rows_affected() == 0 {
            return Err(DbError::NotFound);
        }
        for env_id in env_ids {
            sqlx::query("DELETE FROM environments WHERE id = ?")
                .bind(env_id).execute(&mut *tx).await.map_err(DbError::Sqlx)?;
        }
        tx.commit().await.map_err(DbError::Sqlx)?;
        Ok(())
    }

    async fn update_secret_tags(&self, secret_id: Uuid, tags: serde_json::Value) -> Result<()> {
        sqlx::query(
            "UPDATE secrets SET tags = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(serde_json::to_string(&tags).unwrap_or_else(|_| "{}".into()))
        .bind(now())
        .bind(secret_id.to_string())
        .execute(&self.pool).await.map_err(DbError::Sqlx)?;
        Ok(())
    }

    async fn update_secret_description(&self, secret_id: Uuid, description: String) -> Result<()> {
        sqlx::query(
            "UPDATE secrets SET description = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL",
        )
        .bind(description)
        .bind(now())
        .bind(secret_id.to_string())
        .execute(&self.pool).await.map_err(DbError::Sqlx)?;
        Ok(())
    }

    async fn restore_secret(&self, environment_id: Uuid, path: &str, name: &str) -> Result<SecretMeta> {
        let rows_affected = sqlx::query(
            "UPDATE secrets SET deleted_at = NULL, updated_at = ?
             WHERE environment_id = ? AND path = ? AND name = ? AND deleted_at IS NOT NULL",
        )
        .bind(now())
        .bind(environment_id.to_string())
        .bind(path)
        .bind(name)
        .execute(&self.pool).await.map_err(DbError::Sqlx)?
        .rows_affected();

        if rows_affected == 0 {
            return Err(DbError::NotFound);
        }

        let r = sqlx::query(
            "SELECT s.id, s.name, s.path, s.tags, s.created_at, s.updated_at, s.deleted_at,
                    COALESCE(MAX(sv.version_num), 0) as cur_ver
             FROM secrets s
             LEFT JOIN secret_versions sv ON sv.secret_id = s.id AND sv.deleted_at IS NULL
             WHERE s.environment_id = ? AND s.path = ? AND s.name = ? AND s.deleted_at IS NULL
             GROUP BY s.id",
        )
        .bind(environment_id.to_string())
        .bind(path)
        .bind(name)
        .fetch_optional(&self.pool).await.map_err(DbError::Sqlx)?
        .ok_or(DbError::NotFound)?;

        Ok(SecretMeta {
            id: parse_uuid(&r, "id")?,
            name: r.try_get("name").map_err(DbError::Sqlx)?,
            path: r.try_get("path").map_err(DbError::Sqlx)?,
            current_version: r.try_get("cur_ver").unwrap_or(0),
            created_at: get_ts(&r, "created_at"),
            updated_at: get_ts(&r, "updated_at"),
            deleted_at: None,
            tags: r.try_get::<Option<String>, _>("tags").ok().flatten()
                .and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
        })
    }

    async fn upsert_vault_mount(&self, org_id: Uuid, namespace: &str, mount_path: &str, env_id: Option<Uuid>, engine_type: &str) -> Result<VaultMount> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO vault_mounts (id, org_id, namespace, mount_path, environment_id, engine_type)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT (org_id, namespace, mount_path) DO UPDATE SET environment_id = excluded.environment_id",
        )
        .bind(id.to_string()).bind(org_id.to_string()).bind(namespace).bind(mount_path)
        .bind(env_id.map(|u| u.to_string())).bind(engine_type)
        .execute(&self.pool).await.map_err(DbError::Sqlx)?;
        self.get_vault_mount(org_id, namespace, mount_path).await
    }
}

fn mount_from_row(r: &sqlx::sqlite::SqliteRow, org_id: Uuid) -> Result<VaultMount> {
    Ok(VaultMount {
        id: parse_uuid(r, "id")?,
        org_id,
        namespace: r.try_get("namespace").map_err(DbError::Sqlx)?,
        mount_path: r.try_get("mount_path").map_err(DbError::Sqlx)?,
        environment_id: r.try_get::<Option<String>, _>("environment_id").ok().flatten()
            .and_then(|s| Uuid::parse_str(&s).ok()),
        engine_type: r.try_get("engine_type").map_err(DbError::Sqlx)?,
        config: r.try_get::<Option<String>, _>("config").ok().flatten()
            .and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default(),
        created_at: get_ts(r, "created_at"),
    })
}

fn ns_from_row(r: &sqlx::sqlite::SqliteRow, org_id: Uuid) -> Result<Namespace> {
    Ok(Namespace {
        id: parse_uuid(r, "id")?,
        org_id,
        path: r.try_get("path").map_err(DbError::Sqlx)?,
        created_at: get_ts(r, "created_at"),
    })
}
