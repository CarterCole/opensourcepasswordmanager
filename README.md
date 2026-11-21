# secretd

An open-source secrets manager written in Rust. One server speaks several
cloud-secret wire protocols at once, so existing tooling (the Vault CLI, the AWS
SDK, etc.) can talk to it unmodified while your secrets stay on infrastructure
you control.

> **Status: alpha.** The crypto and auth core are implemented and tested, but
> some authorization features are still in progress. Read
> [SECURITY.md](SECURITY.md) before deploying anything that matters.

## Features

- **Envelope encryption** — AES-256-GCM with a fresh per-secret data key (DEK)
  wrapped by a master key (KEK). The KEK is supplied via env/KMS and never
  stored with the data.
- **Multi-protocol compatibility shims** — one backend, many front doors:
  - HashiCorp Vault **KV v2** (`/v1/`) — namespaces, versioning, soft-delete
  - AWS **Secrets Manager** (`/`)
  - GCP **Secret Manager** (`/gcp/`)
  - Azure **Key Vault** (`/azure/`)
  - Bitwarden **Secrets Manager** (`/bitwarden/`)
  - Cloudflare **Secrets Store** (`/client/`)
- **Pluggable storage** — PostgreSQL for production, SQLite for zero-Docker
  local use.
- **Auth** — `sk_live_` API keys and HS256 JWT sessions, Argon2-hashed; optional
  email+password with **TOTP 2FA** (backup codes), **WebAuthn passkeys**, and
  **Sign in with [Kith](https://github.com/CarterCole/kith)** (OpenID Connect);
  role-based access for admin actions and **per-path token policies** on the KV
  API. The web UI uses an httpOnly, `SameSite=Strict` session cookie.
- **Web UI** — a small React dashboard for browsing and editing secrets.

## Quick start (no Docker)

```bash
./demo.sh
```

This builds the UI, compiles the server, generates fresh random secrets, starts
it against a local SQLite database, and prints the dev token and UI URL. The
demo database is wiped on exit.

## Running it yourself

The server is configured entirely through environment variables and **fails
closed** — it will refuse to start without a strong signing secret.

```bash
# Required
export SECRETD_JWT_SECRET="$(openssl rand -base64 48)"   # >= 32 chars
export SECRETD_KEK="$(openssl rand -base64 32)"           # 32-byte master key
export SECRETD_KEK_ID="$(secretd generate-kek | ...)"     # see `secretd generate-kek`
export DATABASE_URL="postgres://secretd:secretd@localhost/secretd"

# Optional
export SECRETD_LISTEN="0.0.0.0:8200"     # default
# export SECRETD_DEV_ROOT_TOKEN=...      # dev only — leave UNSET in production

cargo run --release --features embed-ui
```

See [`config.example.toml`](config.example.toml) for the full list. Run behind
TLS (a reverse proxy is fine).

### Sign in with Kith

secretd can be an OpenID Connect client of a [Kith](https://github.com/CarterCole/kith)
hub (or any OIDC provider), so people sign in with their Kith passkey instead of a
password. It uses the authorization-code flow with PKCE (S256), a `state` bound to the
browser, a `nonce`, and RS256/EdDSA ID tokens checked against the hub's JWKS.

Register secretd with the hub as a client (`clients.json` for `kith hub serve`):

```json
{ "client_id": "secretd", "name": "secretd", "consent": "implied",
  "redirect_uris": ["https://secretd.example.com/api/v1/auth/oidc/kith/callback"] }
```

Then point secretd at the hub (needs the native API, i.e. PostgreSQL):

```bash
export SECRETD_KITH_ISSUER="https://id.example.com"
export SECRETD_KITH_CLIENT_ID="secretd"
export SECRETD_RP_ORIGIN="https://secretd.example.com"   # redirect URI = <origin>/api/v1/auth/oidc/kith/callback
# export SECRETD_KITH_REDIRECT_URI=...         # or give the full URL
# export SECRETD_KITH_CLIENT_SECRET=...        # only if the client is confidential
# export SECRETD_KITH_ACR_VALUES=urn:kith:acr:aal2   # demand a strong login
# export SECRETD_KITH_AUTO_PROVISION=true      # create users on first login (default: off)
```

The login page then shows **Sign in with Kith**. Who gets in:

- A user already linked to that Kith identity (`sub`) signs in. The link is kept in
  `external_identities`, so a later email change at the hub cannot hand the account to
  someone else.
- The first time, a **verified** email (`email_verified: true`) that matches an active
  user links the identity to them. An unverified email never matches.
- With no matching user, the login is refused, unless `SECRETD_KITH_AUTO_PROVISION` is
  on. Then a user with no roles is created, again only from a verified email.
- Deactivated users cannot sign in this way.

The hub has already checked the passkey, so secretd does not ask for TOTP after it. Issuers
and endpoints must be `https` (plain `http` only on loopback, for local testing).

### Example: use it as Vault

```bash
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=<your token>
vault kv put secret/myapp/db password=s3cr3t
vault kv get secret/myapp/db
```

### Example: use it as AWS Secrets Manager

```bash
AWS_ENDPOINT_URL=http://localhost:8200 \
  aws secretsmanager get-secret-value --secret-id myapp/db
```

## Architecture

```
          ┌────────── wire-compat shims ──────────┐
 Vault ─▶ /v1    AWS ─▶ /    GCP ─▶ /gcp    Azure ─▶ /azure   …
          └───────────────────┬───────────────────┘
                              ▼
                    SecretStore (core)
                 envelope encryption (KEK/DEK)
                              ▼
               SecretBackend  →  PostgreSQL | SQLite
```

- `src/core/` — crypto engine and the storage-agnostic secret store
- `src/db/` — the `SecretBackend` trait and its Postgres/SQLite implementations
- `src/api/` — the per-protocol HTTP shims and the native `/api/v1` management API
- `src/auth/` — API keys, JWT sessions, password hashing, RBAC
- `web/` — the React dashboard

## Development

```bash
cargo test          # unit + wire-compat integration tests
cargo run           # start the server (set env vars first)
cd web && npm run dev
```

## Security

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md), which
also documents the secure-configuration requirements and current known
limitations.

## License

[MIT](LICENSE) © Carter Cole
