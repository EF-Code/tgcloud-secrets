# Changelog

All notable changes to this project are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## 0.1.0-beta.1 - 2026-09-09

First public beta.

### Included

- Capability-scoped outbound secret injection with a vendorable runtime helper.
- Encrypted local development storage and PostgreSQL storage with forced RLS.
- KMS envelope encryption, secret versioning, rollback, and key rotation.
- Capability expiry, revocation, rotation, and tenant kill switches.
- Authenticated administrative API boundaries and transactional audit outbox.
- SSRF controls, DNS pinning, bounded requests, rate limiting, and resilience
  controls.
- Database migrations, deployment templates, operational guidance, and CI for
  Node.js 22 and 24.

### Beta limitations

- Production deployments must supply authentication, a managed KMS, a
  distributed limiter adapter, durable audit export, TLS ingress, backups, and
  operational ownership.
- The Telegram Serverless runtime integration still requires validation against
  the target hosted environment.
