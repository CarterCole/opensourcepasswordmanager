//! PostgreSQL backend implementation.
use crate::db::{models::*, DbError, EncryptResult, Result, SecretBackend};
use async_trait::async_trait;
use sqlx::{Pool, Postgres, Row};
use uuid::Uuid;

type EncryptFn = dyn Fn(&[u8]) -> anyhow::Result<EncryptResult> + Send + Sync;
type DecryptFn = dyn Fn(&[u8], &[u8], &[u8]) -> anyhow::Result<Vec<u8>> + Send + Sync;

#[derive(Clone)]
pub struct PostgresBackend {
    pool: Pool<Postgres>,
    /// encrypt(plaintext) → EncryptResult
    encrypt: std::sync::Arc<EncryptFn>,
    /// decrypt(ciphertext, data_nonce, encrypted_dek_blob) → plaintext
    decrypt: std::sync::Arc<DecryptFn>,
}

impl PostgresBackend {
    pub fn new(
        pool: Pool<Postgres>,
        encrypt: impl Fn(&[u8]) -> anyhow::Result<EncryptResult> + Send + Sync + 'static,
        decrypt: impl Fn(&[u8], &[u8], &[u8]) -> anyhow::Result<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            pool,
            encrypt: std::sync::Arc::new(encrypt),
            decrypt: std::sync::Arc::new(decrypt),
        }
    }

    async fn max_version_num(&self, secret_id: Uuid) -> Result<i32> {
        let row = sqlx::query(
            "SELECT COALESCE(MAX(version_num), 0) FROM secret_versions WHERE secret_id = $1",
        )
        .bind(secret_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.try_get::<i32, _>(0).unwrap_or(0))
    }

    fn row_to_secret(row: &sqlx::postgres::PgRow) -> Secret {
        Secret {
            id: row.get("id"),
            environment_id: row.get("environment_id"),
            name: row.get("name"),
            path: row.get("path"),
            description: row.get("description"),
            tags: row.get("tags"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            deleted_at: row.get("deleted_at"),
        }
    }

    fn row_to_version(row: &sqlx::postgres::PgRow) -> SecretVersion {
        SecretVersion {
            id: row.get("id"),
            secret_id: row.get("secret_id"),
            version_num: row.get("version_num"),
            dek_id: row.get("dek_id"),
            encrypted_value: row.get("encrypted_value"),
            nonce: row.get("nonce"),
            value_type: row.get("value_type"),
            created_at: row.get("created_at"),
            created_by: row.get("created_by"),
            deleted_at: row.get("deleted_at"),
            destroyed_at: row.get("destroyed_at"),
        }
    }

    fn row_to_mount(row: &sqlx::postgres::PgRow) -> VaultMount {
        VaultMount {
            id: row.get("id"),
            org_id: row.get("org_id"),
            namespace: row.get("namespace"),
            mount_path: row.get("mount_path"),
            environment_id: row.get("environment_id"),
            engine_type: row.get("engine_type"),
            config: row.get("config"),
            created_at: row.get("created_at"),
        }
    }
}

#[async_trait]
impl SecretBackend for PostgresBackend {
    async fn create_secret(&self, input: WriteSecret) -> Result<SecretValue> {
        let mut tx = self.pool.begin().await?;
        let tags = input.tags.unwrap_or_else(|| serde_json::json!({}));

        let secret_row = sqlx::query(
            "INSERT INTO secrets (environment_id, name, path, description, tags)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, environment_id, name, path, description, tags,
                       created_at, updated_at, deleted_at",
        )
        .bind(input.environment_id)
        .bind(&input.name)
        .bind(&input.path)
        .bind(&input.description)
        .bind(&tags)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref de) = e {
                if de.constraint().is_some() {
                    return DbError::Conflict(format!(
                        "secret '{}/{}' already exists",
                        input.path, input.name
                    ));
                }
            }
            DbError::Sqlx(e)
        })?;
        let secret = Self::row_to_secret(&secret_row);

        let enc = (self.encrypt)(&input.plaintext).map_err(|e| DbError::Invalid(e.to_string()))?;

        sqlx::query(
            "INSERT INTO data_encryption_keys (id, kek_version_id, encrypted_dek)
             VALUES ($1, $2, $3)",
        )
        .bind(enc.dek_id)
        .bind(enc.kek_version_id)
        .bind(&enc.encrypted_dek)
        .execute(&mut *tx)
        .await?;

        let version_row = sqlx::query(
            "INSERT INTO secret_versions
             (secret_id, version_num, dek_id, encrypted_value, nonce, value_type, created_by)
             VALUES ($1, 1, $2, $3, $4, $5, $6)
             RETURNING id, secret_id, version_num, dek_id, encrypted_value, nonce,
                       value_type, created_at, created_by, deleted_at, destroyed_at",
        )
        .bind(secret.id)
        .bind(enc.dek_id)
        .bind(&enc.ciphertext)
        .bind(&enc.nonce)
        .bind(&input.value_type)
        .bind(input.actor_id)
        .fetch_one(&mut *tx)
        .await?;
        let version = Self::row_to_version(&version_row);

        sqlx::query(
            "INSERT INTO secret_labels (secret_id, label, version_num) VALUES ($1, 'AWSCURRENT', 1)
             ON CONFLICT (secret_id, label) DO UPDATE SET version_num = EXCLUDED.version_num",
        )
        .bind(secret.id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        let value_type = version.value_type.clone();
        Ok(SecretValue {
            plaintext: input.plaintext,
            value_type,
            secret,
            version,
        })
    }

    async fn get_secret(
        &self,
        environment_id: Uuid,
        path: &str,
        name: &str,
        version: Option<i32>,
    ) -> Result<SecretValue> {
        let secret_row = sqlx::query(
            "SELECT id, environment_id, name, path, description, tags,
                    created_at, updated_at, deleted_at
             FROM secrets
             WHERE environment_id = $1 AND path = $2 AND name = $3 AND deleted_at IS NULL",
        )
        .bind(environment_id)
        .bind(path)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)?;
        let secret = Self::row_to_secret(&secret_row);

        let version_row = if let Some(v) = version {
            sqlx::query(
                "SELECT id, secret_id, version_num, dek_id, encrypted_value, nonce,
                        value_type, created_at, created_by, deleted_at, destroyed_at
                 FROM secret_versions
                 WHERE secret_id = $1 AND version_num = $2 AND destroyed_at IS NULL",
            )
            .bind(secret.id)
            .bind(v)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DbError::NotFound)?
        } else {
            sqlx::query(
                "SELECT id, secret_id, version_num, dek_id, encrypted_value, nonce,
                        value_type, created_at, created_by, deleted_at, destroyed_at
                 FROM secret_versions
                 WHERE secret_id = $1 AND destroyed_at IS NULL
                 ORDER BY version_num DESC LIMIT 1",
            )
            .bind(secret.id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(DbError::NotFound)?
        };

        let sv = Self::row_to_version(&version_row);
        if sv.deleted_at.is_some() {
            return Err(DbError::NotFound);
        }

        let dek_row = sqlx::query("SELECT encrypted_dek FROM data_encryption_keys WHERE id = $1")
            .bind(sv.dek_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| DbError::Invalid("DEK not found".into()))?;

        let encrypted_dek: Vec<u8> = dek_row.get("encrypted_dek");
        let plaintext = (self.decrypt)(&sv.encrypted_value, &sv.nonce, &encrypted_dek)
            .map_err(|e| DbError::Invalid(e.to_string()))?;

        let value_type = sv.value_type.clone();
        Ok(SecretValue {
            secret,
            version: sv,
            plaintext,
            value_type,
        })
    }

    async fn update_secret(&self, secret_id: Uuid, input: WriteSecret) -> Result<SecretValue> {
        let mut tx = self.pool.begin().await?;

        let secret_row = sqlx::query(
            "SELECT id, environment_id, name, path, description, tags,
                    created_at, updated_at, deleted_at
             FROM secrets WHERE id = $1 AND deleted_at IS NULL FOR UPDATE",
        )
        .bind(secret_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(DbError::NotFound)?;
        let secret = Self::row_to_secret(&secret_row);

        let cur_ver = self.max_version_num(secret_id).await?;
        if cur_ver > 0 {
            sqlx::query(
                "INSERT INTO secret_labels (secret_id, label, version_num) VALUES ($1, 'AWSPREVIOUS', $2)
                 ON CONFLICT (secret_id, label) DO UPDATE SET version_num = EXCLUDED.version_num",
            )
            .bind(secret_id).bind(cur_ver)
            .execute(&mut *tx).await?;
        }

        let enc = (self.encrypt)(&input.plaintext).map_err(|e| DbError::Invalid(e.to_string()))?;

        sqlx::query(
            "INSERT INTO data_encryption_keys (id, kek_version_id, encrypted_dek)
             VALUES ($1, $2, $3)",
        )
        .bind(enc.dek_id)
        .bind(enc.kek_version_id)
        .bind(&enc.encrypted_dek)
        .execute(&mut *tx)
        .await?;

        let new_ver = cur_ver + 1;
        let version_row = sqlx::query(
            "INSERT INTO secret_versions
             (secret_id, version_num, dek_id, encrypted_value, nonce, value_type, created_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, secret_id, version_num, dek_id, encrypted_value, nonce,
                       value_type, created_at, created_by, deleted_at, destroyed_at",
        )
        .bind(secret_id)
        .bind(new_ver)
        .bind(enc.dek_id)
        .bind(&enc.ciphertext)
        .bind(&enc.nonce)
        .bind(&input.value_type)
        .bind(input.actor_id)
        .fetch_one(&mut *tx)
        .await?;
        let version = Self::row_to_version(&version_row);

        sqlx::query(
            "INSERT INTO secret_labels (secret_id, label, version_num) VALUES ($1, 'AWSCURRENT', $2)
             ON CONFLICT (secret_id, label) DO UPDATE SET version_num = EXCLUDED.version_num",
        )
        .bind(secret_id).bind(new_ver)
        .execute(&mut *tx).await?;

        sqlx::query(
            "UPDATE secrets SET updated_at = NOW(),
             description = COALESCE($2, description),
             tags = COALESCE($3, tags) WHERE id = $1",
        )
        .bind(secret_id)
        .bind(&input.description)
        .bind(&input.tags)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        let value_type = version.value_type.clone();
        Ok(SecretValue {
            secret,
            version,
            plaintext: input.plaintext,
            value_type,
        })
    }

    async fn list_secrets(&self, environment_id: Uuid, path: &str) -> Result<Vec<SecretMeta>> {
        let rows = sqlx::query(
            "SELECT s.id, s.name, s.path, s.created_at, s.updated_at, s.deleted_at,
                    s.tags, COALESCE(MAX(sv.version_num), 0)::int AS current_version
             FROM secrets s
             LEFT JOIN secret_versions sv
               ON sv.secret_id = s.id AND sv.destroyed_at IS NULL
             WHERE s.environment_id = $1 AND s.path LIKE $2 AND s.deleted_at IS NULL
             GROUP BY s.id ORDER BY s.path, s.name",
        )
        .bind(environment_id)
        .bind(format!("{}%", path))
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|r| SecretMeta {
                id: r.get("id"),
                name: r.get("name"),
                path: r.get("path"),
                current_version: r.get("current_version"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
                deleted_at: r.get("deleted_at"),
                tags: r.get("tags"),
            })
            .collect())
    }

    async fn get_secret_meta(&self, secret_id: Uuid) -> Result<SecretMeta> {
        let r = sqlx::query(
            "SELECT s.id, s.name, s.path, s.created_at, s.updated_at, s.deleted_at,
                    s.tags, COALESCE(MAX(sv.version_num), 0)::int AS current_version
             FROM secrets s
             LEFT JOIN secret_versions sv
               ON sv.secret_id = s.id AND sv.destroyed_at IS NULL
             WHERE s.id = $1 GROUP BY s.id",
        )
        .bind(secret_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)?;

        Ok(SecretMeta {
            id: r.get("id"),
            name: r.get("name"),
            path: r.get("path"),
            current_version: r.get("current_version"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
            deleted_at: r.get("deleted_at"),
            tags: r.get("tags"),
        })
    }

    async fn soft_delete_versions(&self, secret_id: Uuid, versions: &[i32]) -> Result<()> {
        for v in versions {
            sqlx::query(
                "UPDATE secret_versions SET deleted_at = NOW()
                 WHERE secret_id = $1 AND version_num = $2 AND destroyed_at IS NULL",
            )
            .bind(secret_id)
            .bind(v)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn undelete_versions(&self, secret_id: Uuid, versions: &[i32]) -> Result<()> {
        for v in versions {
            sqlx::query(
                "UPDATE secret_versions SET deleted_at = NULL
                 WHERE secret_id = $1 AND version_num = $2 AND destroyed_at IS NULL",
            )
            .bind(secret_id)
            .bind(v)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn destroy_versions(&self, secret_id: Uuid, versions: &[i32]) -> Result<()> {
        for v in versions {
            sqlx::query(
                "UPDATE secret_versions
                 SET destroyed_at = NOW(), encrypted_value = ''::bytea, nonce = ''::bytea
                 WHERE secret_id = $1 AND version_num = $2",
            )
            .bind(secret_id)
            .bind(v)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn delete_secret(&self, secret_id: Uuid) -> Result<()> {
        sqlx::query("UPDATE secrets SET deleted_at = NOW() WHERE id = $1 AND deleted_at IS NULL")
            .bind(secret_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_label(&self, secret_id: Uuid, label: &str, version_num: i32) -> Result<()> {
        sqlx::query(
            "INSERT INTO secret_labels (secret_id, label, version_num) VALUES ($1, $2, $3)
             ON CONFLICT (secret_id, label) DO UPDATE SET version_num = EXCLUDED.version_num",
        )
        .bind(secret_id)
        .bind(label)
        .bind(version_num)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_versions(&self, secret_id: Uuid) -> Result<Vec<SecretVersion>> {
        let rows = sqlx::query(
            "SELECT id, secret_id, version_num, dek_id, encrypted_value, nonce,
                    value_type, created_at, created_by, deleted_at, destroyed_at
             FROM secret_versions WHERE secret_id = $1 ORDER BY version_num DESC",
        )
        .bind(secret_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(|r| Self::row_to_version(r)).collect())
    }

    async fn write_audit(
        &self,
        org_id: Option<Uuid>,
        actor_id: Option<Uuid>,
        actor_type: &str,
        actor_email: Option<&str>,
        action: &str,
        resource_type: Option<&str>,
        resource_id: Option<Uuid>,
        resource_name: Option<&str>,
        ip: Option<&str>,
        metadata: serde_json::Value,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO audit_logs
             (org_id, actor_id, actor_type, actor_email, action,
              resource_type, resource_id, resource_name, ip_address, metadata)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(org_id)
        .bind(actor_id)
        .bind(actor_type)
        .bind(actor_email)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(resource_name)
        .bind(ip)
        .bind(metadata)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_vault_mount(
        &self,
        org_id: Uuid,
        namespace: &str,
        mount_path: &str,
    ) -> Result<VaultMount> {
        sqlx::query(
            "SELECT id, org_id, namespace, mount_path, environment_id, engine_type, config, created_at
             FROM vault_mounts WHERE org_id = $1 AND namespace = $2 AND mount_path = $3",
        )
        .bind(org_id).bind(namespace).bind(mount_path)
        .fetch_optional(&self.pool).await?
        .map(|r| Self::row_to_mount(&r))
        .ok_or(DbError::NotFound)
    }

    async fn list_vault_mounts(&self, org_id: Uuid, namespace: &str) -> Result<Vec<VaultMount>> {
        let rows = sqlx::query(
            "SELECT id, org_id, namespace, mount_path, environment_id, engine_type, config, created_at
             FROM vault_mounts WHERE org_id = $1 AND namespace = $2 ORDER BY mount_path",
        )
        .bind(org_id).bind(namespace)
        .fetch_all(&self.pool).await?;
        Ok(rows.iter().map(|r| Self::row_to_mount(r)).collect())
    }

    async fn upsert_vault_mount(
        &self,
        org_id: Uuid,
        namespace: &str,
        mount_path: &str,
        environment_id: Option<Uuid>,
        engine_type: &str,
    ) -> Result<VaultMount> {
        let row = sqlx::query(
            "INSERT INTO vault_mounts (org_id, namespace, mount_path, environment_id, engine_type)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (org_id, namespace, mount_path) DO UPDATE
               SET environment_id = EXCLUDED.environment_id,
                   engine_type    = EXCLUDED.engine_type
             RETURNING id, org_id, namespace, mount_path, environment_id, engine_type, config, created_at",
        )
        .bind(org_id).bind(namespace).bind(mount_path).bind(environment_id).bind(engine_type)
        .fetch_one(&self.pool).await?;
        Ok(Self::row_to_mount(&row))
    }

    async fn create_namespace(&self, org_id: Uuid, path: &str) -> Result<Namespace> {
        if let Some((parent, _)) = path.rsplit_once('/') {
            self.get_namespace(org_id, parent).await?;
        }
        let mut tx = self.pool.begin().await?;

        let proj: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM projects WHERE org_id = $1 ORDER BY created_at LIMIT 1",
        )
        .bind(org_id)
        .fetch_optional(&mut *tx)
        .await?;
        let project_id = proj.ok_or(DbError::NotFound)?;

        let ns_id = Uuid::new_v4();
        let inserted = sqlx::query(
            "INSERT INTO namespaces (id, org_id, path) VALUES ($1, $2, $3)
             ON CONFLICT (org_id, path) DO NOTHING
             RETURNING id, org_id, path, created_at",
        )
        .bind(ns_id)
        .bind(org_id)
        .bind(path)
        .fetch_optional(&mut *tx)
        .await?;
        let row = inserted.ok_or_else(|| DbError::Conflict("namespace already exists".into()))?;

        let env_id: Uuid = sqlx::query_scalar(
            "INSERT INTO environments (project_id, name, slug) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(project_id)
        .bind(format!("ns:{path}"))
        .bind(format!("ns-{ns_id}"))
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO vault_mounts (org_id, namespace, mount_path, environment_id, engine_type)
             VALUES ($1, $2, 'secret', $3, 'kv-v2')",
        )
        .bind(org_id)
        .bind(path)
        .bind(env_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(Namespace {
            id: row.get("id"),
            org_id: row.get("org_id"),
            path: row.get("path"),
            created_at: row.get("created_at"),
        })
    }

    async fn get_namespace(&self, org_id: Uuid, path: &str) -> Result<Namespace> {
        sqlx::query(
            "SELECT id, org_id, path, created_at FROM namespaces WHERE org_id = $1 AND path = $2",
        )
        .bind(org_id)
        .bind(path)
        .fetch_optional(&self.pool)
        .await?
        .map(|r| Namespace {
            id: r.get("id"),
            org_id: r.get("org_id"),
            path: r.get("path"),
            created_at: r.get("created_at"),
        })
        .ok_or(DbError::NotFound)
    }

    async fn list_namespaces(&self, org_id: Uuid) -> Result<Vec<Namespace>> {
        let rows = sqlx::query(
            "SELECT id, org_id, path, created_at FROM namespaces WHERE org_id = $1 ORDER BY path",
        )
        .bind(org_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| Namespace {
                id: r.get("id"),
                org_id: r.get("org_id"),
                path: r.get("path"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    async fn delete_namespace(&self, org_id: Uuid, path: &str) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let child_like = format!(
            "{}/%",
            path.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        let has_children: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM namespaces WHERE org_id = $1 AND path LIKE $2)",
        )
        .bind(org_id)
        .bind(&child_like)
        .fetch_one(&mut *tx)
        .await?;
        if has_children {
            return Err(DbError::Conflict("namespace has child namespaces".into()));
        }
        let has_secrets: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM secrets s JOIN vault_mounts m ON m.environment_id = s.environment_id
                WHERE m.org_id = $1 AND m.namespace = $2 AND s.deleted_at IS NULL)",
        )
        .bind(org_id)
        .bind(path)
        .fetch_one(&mut *tx)
        .await?;
        if has_secrets {
            return Err(DbError::Conflict("namespace is not empty".into()));
        }
        let env_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT environment_id FROM vault_mounts WHERE org_id = $1 AND namespace = $2 AND environment_id IS NOT NULL",
        ).bind(org_id).bind(path).fetch_all(&mut *tx).await?;
        sqlx::query("DELETE FROM vault_mounts WHERE org_id = $1 AND namespace = $2")
            .bind(org_id)
            .bind(path)
            .execute(&mut *tx)
            .await?;
        let gone = sqlx::query("DELETE FROM namespaces WHERE org_id = $1 AND path = $2")
            .bind(org_id)
            .bind(path)
            .execute(&mut *tx)
            .await?;
        if gone.rows_affected() == 0 {
            return Err(DbError::NotFound);
        }
        // Environments cascade-delete their (all soft-deleted) secrets.
        sqlx::query("DELETE FROM environments WHERE id = ANY($1)")
            .bind(&env_ids)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    async fn update_secret_tags(&self, secret_id: Uuid, tags: serde_json::Value) -> Result<()> {
        sqlx::query(
            "UPDATE secrets SET tags = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(secret_id)
        .bind(&tags)
        .execute(&self.pool)
        .await
        .map_err(DbError::Sqlx)?;
        Ok(())
    }

    async fn update_secret_description(&self, secret_id: Uuid, description: String) -> Result<()> {
        sqlx::query(
            "UPDATE secrets SET description = $2, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(secret_id).bind(description)
        .execute(&self.pool).await.map_err(DbError::Sqlx)?;
        Ok(())
    }

    async fn restore_secret(
        &self,
        environment_id: Uuid,
        path: &str,
        name: &str,
    ) -> Result<SecretMeta> {
        let rows_affected = sqlx::query(
            "UPDATE secrets SET deleted_at = NULL, updated_at = NOW()
             WHERE environment_id = $1 AND path = $2 AND name = $3 AND deleted_at IS NOT NULL",
        )
        .bind(environment_id)
        .bind(path)
        .bind(name)
        .execute(&self.pool)
        .await?
        .rows_affected();

        if rows_affected == 0 {
            return Err(DbError::NotFound);
        }

        let r = sqlx::query(
            "SELECT s.id, s.name, s.path, s.tags, s.created_at, s.updated_at, s.deleted_at,
                    COALESCE(MAX(sv.version_num), 0)::int AS current_version
             FROM secrets s
             LEFT JOIN secret_versions sv ON sv.secret_id = s.id AND sv.destroyed_at IS NULL
             WHERE s.environment_id = $1 AND s.path = $2 AND s.name = $3 AND s.deleted_at IS NULL
             GROUP BY s.id",
        )
        .bind(environment_id)
        .bind(path)
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DbError::NotFound)?;

        Ok(SecretMeta {
            id: r.get("id"),
            name: r.get("name"),
            path: r.get("path"),
            current_version: r.get("current_version"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
            deleted_at: None,
            tags: r.get("tags"),
        })
    }
}
