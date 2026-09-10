# Changelog

All notable changes to this project are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## Unreleased

### Security

- Replaced DSNs and private storage paths in CLI and pool diagnostics with
  stable redacted placeholders while preserving existing JSON field names.
- Redacted environment- and option-derived connection details from CLI errors.
- Removed the unbounded DSN-redaction regular expression flagged by CodeQL.
- Ensured migration JSON mode emits one valid JSON document without progress
  text.

## 0.1.0-beta.2 - 2026-09-10

Telegram Serverless compatibility update. The adapter follows the documented
V8 SDK architecture and has been build-tested, but still awaits execution in a
live Telegram Serverless project.

### Added

- A first-class `createTelegramSecretFetch` adapter that requires Telegram's
  injected `sdk.fetch` explicitly.
- A fail-closed, non-sensitive `tgcloud run` compatibility probe fixture.

### Changed

- The vendorable runtime helper now sends a string URL and limits its default
  request options to Telegram Serverless's documented fetch-compatible surface.
- Abort signals are forwarded only when callers explicitly provide one; the
  adapter does not require undocumented cancellation globals.

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
