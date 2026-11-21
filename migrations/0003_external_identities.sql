-- Identities from external OpenID Connect providers ("Sign in with Kith", Okta, ...).
-- A login is matched on (issuer, subject), never on email alone after the first
-- sign-in: the first login may bind by a verified email, and from then on the
-- provider's stable `sub` is what identifies the user.
CREATE TABLE external_identities (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer        TEXT NOT NULL,
    subject       TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at TIMESTAMPTZ,
    UNIQUE (issuer, subject)
);

CREATE INDEX idx_external_identities_user ON external_identities(user_id);
