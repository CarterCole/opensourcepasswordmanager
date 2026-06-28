-- Organizations
CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Projects
CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, slug)
);

-- Environments
CREATE TABLE environments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL,
    position    INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (project_id, slug)
);

-- Key encryption keys (master keys; value may be local or KMS-wrapped)
CREATE TABLE kek_versions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider            TEXT NOT NULL DEFAULT 'local', -- local | aws-kms | gcp-kms | azure-kv
    encrypted_kek       BYTEA,                         -- NULL for local (stored in env/config)
    provider_key_id     TEXT,                          -- KMS key ARN/resource for unwrapping
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-secret data encryption keys (DEKs), wrapped by a KEK
CREATE TABLE data_encryption_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kek_version_id  UUID NOT NULL REFERENCES kek_versions(id),
    encrypted_dek   BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Secrets (the named container; value lives in versions)
CREATE TABLE secrets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    environment_id  UUID NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    path            TEXT NOT NULL DEFAULT '/',     -- folder path, e.g. "/database/"
    description     TEXT,
    tags            JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at      TIMESTAMPTZ,
    UNIQUE (environment_id, path, name)
);

CREATE INDEX idx_secrets_env ON secrets(environment_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_secrets_path ON secrets(environment_id, path) WHERE deleted_at IS NULL;

-- Secret versions (immutable; new write = new version)
CREATE TABLE secret_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version_num     INTEGER NOT NULL,
    dek_id          UUID NOT NULL REFERENCES data_encryption_keys(id),
    encrypted_value BYTEA NOT NULL,          -- AES-256-GCM ciphertext
    nonce           BYTEA NOT NULL,          -- 12-byte GCM nonce
    value_type      TEXT NOT NULL DEFAULT 'string', -- string | binary
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      UUID,                    -- user or machine id
    deleted_at      TIMESTAMPTZ,             -- soft delete
    destroyed_at    TIMESTAMPTZ,             -- hard destroy (value wiped)
    UNIQUE (secret_id, version_num)
);

CREATE INDEX idx_versions_secret ON secret_versions(secret_id);

-- Labels on secret versions (AWSCURRENT, AWSPREVIOUS, custom)
CREATE TABLE secret_labels (
    secret_id   UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    label       TEXT NOT NULL,
    version_num INTEGER NOT NULL,
    PRIMARY KEY (secret_id, label)
);

-- Users
CREATE TABLE users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email                   TEXT NOT NULL UNIQUE,
    display_name            TEXT,
    password_hash           TEXT,                    -- NULL if passkey-only
    totp_secret_encrypted   BYTEA,                   -- NULL if not enrolled
    totp_enrolled_at        TIMESTAMPTZ,
    backup_codes_hash       JSONB,                   -- array of hashed one-time codes
    webauthn_credentials    JSONB NOT NULL DEFAULT '[]',
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at           TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_org ON users(org_id);
CREATE INDEX idx_users_email ON users(email);

-- Roles
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID REFERENCES organizations(id) ON DELETE CASCADE, -- NULL = built-in
    name        TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]',  -- array of "resource:action" strings
    is_builtin  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed built-in roles
INSERT INTO roles (id, name, permissions, is_builtin) VALUES
    ('00000000-0000-0000-0000-000000000001', 'owner',     '["*:*"]', TRUE),
    ('00000000-0000-0000-0000-000000000002', 'admin',     '["secrets:*","members:*","projects:*","environments:*"]', TRUE),
    ('00000000-0000-0000-0000-000000000003', 'developer', '["secrets:read","secrets:write"]', TRUE),
    ('00000000-0000-0000-0000-000000000004', 'reader',    '["secrets:read"]', TRUE);

-- Role assignments (user → role scoped to org/project/environment)
CREATE TABLE role_assignments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_type  TEXT NOT NULL,   -- org | project | environment
    scope_id    UUID NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by  UUID,
    UNIQUE (user_id, role_id, scope_type, scope_id)
);

-- API Keys (for machine identities)
CREATE TABLE api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_id    UUID NOT NULL,           -- user_id or a machine identity UUID
    owner_type  TEXT NOT NULL DEFAULT 'user',  -- user | machine
    name        TEXT NOT NULL,
    key_prefix  TEXT NOT NULL,           -- first 8 chars, for display
    key_hash    TEXT NOT NULL UNIQUE,    -- Argon2 hash of full key
    scopes      JSONB NOT NULL DEFAULT '[]',
    role_id     UUID REFERENCES roles(id),
    expires_at  TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_org ON api_keys(org_id) WHERE revoked_at IS NULL;

-- Audit log
CREATE TABLE audit_logs (
    id              BIGSERIAL PRIMARY KEY,
    org_id          UUID REFERENCES organizations(id) ON DELETE SET NULL,
    actor_id        UUID,
    actor_type      TEXT,           -- user | api_key | system
    actor_email     TEXT,
    action          TEXT NOT NULL,  -- secret.read, secret.write, secret.delete, etc.
    resource_type   TEXT,
    resource_id     UUID,
    resource_name   TEXT,
    ip_address      TEXT,
    user_agent      TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}',
    ts              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_org_ts ON audit_logs(org_id, ts DESC);
CREATE INDEX idx_audit_actor ON audit_logs(actor_id, ts DESC);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id, ts DESC);

-- Sync configurations
CREATE TABLE sync_configs (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id              UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name                    TEXT NOT NULL,
    provider                TEXT NOT NULL,  -- aws | gcp | azure | vault | cloudflare
    direction               TEXT NOT NULL DEFAULT 'bidirectional',
    env_filter              TEXT[],         -- environment slugs to sync; NULL = all
    path_filter             TEXT,           -- path prefix filter
    credentials_dek_id      UUID REFERENCES data_encryption_keys(id),
    credentials_encrypted   BYTEA,          -- provider credentials (encrypted)
    credentials_nonce       BYTEA,
    schedule_cron           TEXT,
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    last_synced_at          TIMESTAMPTZ,
    last_sync_status        TEXT,
    state                   JSONB NOT NULL DEFAULT '{}',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Cloudflare Secrets Store compatibility: stores (namespaces)
CREATE TABLE cf_stores (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    comment         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

-- Vault mounts (for Vault API compat: each mount maps to a project+environment)
CREATE TABLE vault_mounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    mount_path      TEXT NOT NULL,   -- e.g. "secret"
    environment_id  UUID REFERENCES environments(id),
    engine_type     TEXT NOT NULL DEFAULT 'kv-v2',
    config          JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, mount_path)
);
