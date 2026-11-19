CREATE TABLE namespaces (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (org_id, path)
);

-- Rebuild vault_mounts to add `namespace` and widen the unique key.
CREATE TABLE vault_mounts_new (
    id             TEXT PRIMARY KEY,
    org_id         TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    namespace      TEXT NOT NULL DEFAULT '',
    mount_path     TEXT NOT NULL,
    environment_id TEXT REFERENCES environments(id),
    engine_type    TEXT NOT NULL DEFAULT 'kv-v2',
    config         TEXT NOT NULL DEFAULT '{}',
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (org_id, namespace, mount_path)
);
INSERT INTO vault_mounts_new (id, org_id, mount_path, environment_id, engine_type, config, created_at)
    SELECT id, org_id, mount_path, environment_id, engine_type, config, created_at FROM vault_mounts;
DROP TABLE vault_mounts;
ALTER TABLE vault_mounts_new RENAME TO vault_mounts;
