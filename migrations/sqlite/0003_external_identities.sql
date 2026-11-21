-- Identities from external OpenID Connect providers ("Sign in with Kith", Okta, ...).
CREATE TABLE external_identities (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer        TEXT NOT NULL,
    subject       TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at TEXT,
    UNIQUE (issuer, subject)
);

CREATE INDEX idx_external_identities_user ON external_identities(user_id);
