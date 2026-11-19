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

- **Cross-tenant isolation on the cloud-compat shims is incomplete.** The
  AWS/GCP/Azure/Bitwarden/Cloudflare compatibility endpoints currently operate
  against the default environment and do not yet scope by the caller's
  organization. Treat a single deployment as single-tenant for now.
- **No login rate-limiting / lockout.** Brute-force protection on
  `/api/v1/auth/login` is not yet implemented; put it behind a rate-limiting
  proxy.
- **Least-privilege within a tenant is coarse.** Any valid vault token can
  read/write within its org + namespace; fine-grained per-path policies are not
  enforced yet. Admin-tier actions (key/user management) *are* gated by role.
- **Web UI stores its session token in `localStorage`**, which is exfiltratable
  by any XSS on the origin. Serve the UI from a trusted origin with a strict CSP.
- **TOTP / passkey 2FA are stubs.** `two_fa_verified` is asserted but no second
  factor is actually verified yet.
- **SQLite backend** is intended for demo/zero-Docker use and has had less
  hardening than the PostgreSQL backend (e.g. soft-delete visibility differs).

## Supported versions

Pre-1.0: only the latest `main` receives fixes.
