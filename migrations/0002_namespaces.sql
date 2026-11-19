-- Namespaces (OpenBao/Vault Enterprise-style isolated sub-trees).
-- path is absolute and slash-separated without leading/trailing slash, e.g. "team-a/prod".
-- The root namespace is the empty string and has no row.
CREATE TABLE namespaces (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    path        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, path)
);

-- Mounts now live inside a namespace ('' = root).
ALTER TABLE vault_mounts ADD COLUMN namespace TEXT NOT NULL DEFAULT '';
ALTER TABLE vault_mounts DROP CONSTRAINT vault_mounts_org_id_mount_path_key;
ALTER TABLE vault_mounts ADD CONSTRAINT vault_mounts_org_ns_mount_key UNIQUE (org_id, namespace, mount_path);
