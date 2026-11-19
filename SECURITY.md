# Security Policy

`secretd` is early-stage software. It handles secrets, so please read this
before deploying it anywhere that matters.

## Project status

**Alpha — not yet recommended for production.** The cryptographic core
(AES-256-GCM envelope encryption with per-secret data keys wrapped by a master
KEK) and the authentication primitives (Argon2 password/key hashing, HS256 JWT
sessions) are implemented and tested, but several authorization features are
still in progress (see "Known limitations").

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab) rather than opening
a public issue. We aim to acknowledge reports within a few days.

## Secure configuration (required)

The server **fails closed** and will refuse to start without a strong secret:

| Variable | Requirement |
|----------|-------------|
| `SECRETD_JWT_SECRET` | **Required.** ≥ 32 chars, not the example value. Generate with `openssl rand -base64 48`. Anyone who knows this can forge sessions. |
| `SECRETD_KEK` / `SECRETD_KEK_ID` | **Required.** 32-byte base64 master key. Generate with `secretd generate-kek`. Loss of the KEK means loss of all secrets. |
| `SECRETD_DEV_ROOT_TOKEN` | **Optional, dev only.** A master bypass token. Leave **unset** in production — there is no default. |

Run the server behind TLS (a reverse proxy is fine); it does not terminate TLS
itself.

## Known limitations (tracked, not yet fixed)

These are documented so operators can make informed decisions:

- **Passkey / WebAuthn 2FA is a stub.** TOTP 2FA is implemented; WebAuthn is not
  wired up yet.
- **Rate limiting is per-instance and in-memory.** The built-in auth throttle
  does not coordinate across replicas; for multi-instance deployments add a
  shared limiter or a WAF / reverse proxy.

## Recently hardened

- **Per-path token policies** are now enforced on the KV API. A token carries
  policies (built-ins `root`/`owner`/`admin`, `developer`, `reader`/`default`,
  or inline `"read,list,update secret/app/*"` rules), and every KV read/write/
  delete/destroy/list is checked against them. `token/create` restricts a child
  token's policies to a subset of the parent's, preventing privilege escalation.
- **TOTP 2FA** (RFC 6238) with single-use backup codes; login enforces the
  second factor for enrolled accounts. The TOTP seed is stored encrypted.
- **Web session uses an httpOnly, `SameSite=Strict` cookie** set by the server
  at login, instead of `localStorage`. The token is no longer readable by JS, so
  an XSS cannot exfiltrate it, and `SameSite=Strict` defends against CSRF. Set
  `X-Forwarded-Proto: https` (any TLS proxy does) to get the `Secure` attribute.
- Cloud-compat shims (AWS/GCP/Azure/Bitwarden/Cloudflare) now reject credentials
  that do not belong to the shim's organization, closing a cross-tenant access
  path.
- Online password guessing is throttled on `/api/v1/auth/login` and
  `/api/v1/auth/register` (fixed-window attempt counter with lockout).
- The SQLite backend no longer serves soft-deleted secret versions, matching the
  PostgreSQL backend.

## Supported versions

Pre-1.0: only the latest `main` receives fixes.
