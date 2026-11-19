-- SQLite-compatible schema (no gen_random_uuid, BLOB not BYTEA, TEXT not JSONB/TIMESTAMPTZ)
PRAGMA foreign_keys = ON;

CREATE TABLE organizations (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE projects (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (org_id, slug)
);

CREATE TABLE environments (
    id          TEXT PRIMARY KEY,
    project_id  TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL,
    position    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (project_id, slug)
);

CREATE TABLE kek_versions (
    id              TEXT PRIMARY KEY,
    provider        TEXT NOT NULL DEFAULT 'local',
    encrypted_kek   BLOB,
    provider_key_id TEXT,
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE data_encryption_keys (
    id              TEXT PRIMARY KEY,
    kek_version_id  TEXT NOT NULL REFERENCES kek_versions(id),
    encrypted_dek   BLOB NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE secrets (
    id              TEXT PRIMARY KEY,
    environment_id  TEXT NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    path            TEXT NOT NULL DEFAULT '/',
    description     TEXT,
    tags            TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    deleted_at      TEXT,
    UNIQUE (environment_id, path, name)
);

CREATE INDEX idx_secrets_env  ON secrets(environment_id);
CREATE INDEX idx_secrets_path ON secrets(environment_id, path);

CREATE TABLE secret_versions (
    id              TEXT PRIMARY KEY,
    secret_id       TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version_num     INTEGER NOT NULL,
    dek_id          TEXT NOT NULL REFERENCES data_encryption_keys(id),
    encrypted_value BLOB NOT NULL,
    nonce           BLOB NOT NULL,
    value_type      TEXT NOT NULL DEFAULT 'string',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    created_by      TEXT,
    deleted_at      TEXT,
    destroyed_at    TEXT,
    UNIQUE (secret_id, version_num)
);

CREATE INDEX idx_versions_secret ON secret_versions(secret_id);

CREATE TABLE secret_labels (
    secret_id   TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    label       TEXT NOT NULL,
    version_num INTEGER NOT NULL,
    PRIMARY KEY (secret_id, label)
);

CREATE TABLE users (
    id                      TEXT PRIMARY KEY,
    org_id                  TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email                   TEXT NOT NULL UNIQUE,
    display_name            TEXT,
    password_hash           TEXT,
    totp_secret_encrypted   BLOB,
    totp_enrolled_at        TEXT,
    backup_codes_hash       TEXT,
    webauthn_credentials    TEXT NOT NULL DEFAULT '[]',
    is_active               INTEGER NOT NULL DEFAULT 1,
    last_login_at           TEXT,
    created_at              TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at              TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_users_org   ON users(org_id);
CREATE INDEX idx_users_email ON users(email);

CREATE TABLE roles (
    id          TEXT PRIMARY KEY,
    org_id      TEXT REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    permissions TEXT NOT NULL DEFAULT '[]',
    is_builtin  INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO roles (id, name, permissions, is_builtin) VALUES
    ('00000000-0000-0000-0000-000000000001', 'owner',     '["*:*"]', 1),
    ('00000000-0000-0000-0000-000000000002', 'admin',     '["secrets:*","members:*","projects:*","environments:*"]', 1),
    ('00000000-0000-0000-0000-000000000003', 'developer', '["secrets:read","secrets:write"]', 1),
    ('00000000-0000-0000-0000-000000000004', 'reader',    '["secrets:read"]', 1);

CREATE TABLE role_assignments (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_type  TEXT NOT NULL,
    scope_id    TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    created_by  TEXT,
    UNIQUE (user_id, role_id, scope_type, scope_id)
);

CREATE TABLE api_keys (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_id     TEXT NOT NULL,
    owner_type   TEXT NOT NULL DEFAULT 'user',
    name         TEXT NOT NULL,
    key_prefix   TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    scopes       TEXT NOT NULL DEFAULT '[]',
    role_id      TEXT REFERENCES roles(id),
    expires_at   TEXT,
    last_used_at TEXT,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at   TEXT
);

CREATE INDEX idx_api_keys_org    ON api_keys(org_id);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);

CREATE TABLE audit_logs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id        TEXT REFERENCES organizations(id) ON DELETE SET NULL,
    actor_id      TEXT,
    actor_type    TEXT,
    actor_email   TEXT,
    action        TEXT NOT NULL,
    resource_type TEXT,
    resource_id   TEXT,
    resource_name TEXT,
    ip_address    TEXT,
    user_agent    TEXT,
    metadata      TEXT NOT NULL DEFAULT '{}',
    ts            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_audit_org_ts   ON audit_logs(org_id, ts);
CREATE INDEX idx_audit_actor    ON audit_logs(actor_id, ts);

CREATE TABLE sync_configs (
    id                    TEXT PRIMARY KEY,
    project_id            TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    provider              TEXT NOT NULL,
    direction             TEXT NOT NULL DEFAULT 'bidirectional',
    path_filter           TEXT,
    credentials_dek_id    TEXT REFERENCES data_encryption_keys(id),
    credentials_encrypted BLOB,
    credentials_nonce     BLOB,
    schedule_cron         TEXT,
    is_active             INTEGER NOT NULL DEFAULT 1,
    last_synced_at        TEXT,
    last_sync_status      TEXT,
    state                 TEXT NOT NULL DEFAULT '{}',
    created_at            TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE cf_stores (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    comment    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (org_id, name)
);

CREATE TABLE vault_mounts (
    id             TEXT PRIMARY KEY,
    org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    mount_path     TEXT NOT NULL,
    environment_id TEXT REFERENCES environments(id),
    engine_type    TEXT NOT NULL DEFAULT 'kv-v2',
    config         TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (org_id, mount_path)
);
