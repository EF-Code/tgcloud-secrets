# tgcloud-secrets

Capability-scoped secret injection for Telegram Serverless bots.

Telegram Serverless supplies handlers, project modules, and outbound `fetch`,
but no secret store. `tgcloud-secrets` adds a companion broker: vendor secrets
remain encrypted at rest, while a revocable bearer capability authorizes one
origin, path prefix, method set, and injection header. The broker injects the
secret only on the matching upstream request.

## Status

The repository contains the application controls and provider-neutral
production artifacts, but it is not a claim of turnkey production readiness.
The remaining gates that require infrastructure or organizational decisions are
listed in [the readiness status matrix](docs/PRODUCTION_READINESS_STATUS.md).
The two local planning prompts are intentionally not part of the package or
release workflow.

Use the file store for local development. Shared or multi-tenant operation
requires Postgres with forced RLS, a non-owner runtime role, managed KMS,
authenticated admin access, distributed limiting, durable audit delivery,
backups, and exercised runbooks.

## Quick start (local file store)

Requires Node.js 22 or newer.

```sh
npm test

node src/cli.js init --data-dir .tgcloud-secrets
printf %s "$OPENAI_API_KEY" | node src/cli.js set openai --data-dir .tgcloud-secrets

node src/cli.js grant openai \
  --data-dir .tgcloud-secrets \
  --base-url https://api.openai.com \
  --path-prefix /v1/ \
  --method POST \
  --inject-header authorization \
  --inject-prefix 'Bearer '

node src/cli.js serve --data-dir .tgcloud-secrets --host 127.0.0.1 --port 8787
```

`grant` prints the capability once. It stores only a hash, so a lost token
cannot be recovered: revoke it and grant a replacement. A capability is a
bearer credential; do not commit it or put it in a URL.

The file store creates `0700` directories and `0600` files, uses atomic synced
writes, validates the store before parsing it, and rejects symlink/ownership
and prototype-pollution hazards. Keep its data directory outside source
control.

## Use from a Serverless module

Telegram Serverless does not install packages at runtime. Vendor
`runtime/secret-fetch.js` into the bot's `lib/` directory:

```js
import { fetch } from 'sdk';
import { createSecretFetch } from 'lib/secret-fetch';

const openaiFetch = createSecretFetch({
  endpoint: 'https://secrets.example.internal',
  capability: 'tgscap_REPLACE_WITH_REVOCABLE_CAPABILITY',
  fetchImpl: fetch,
});

export function createCompletion(body) {
  return openaiFetch('/v1/chat/completions', { method: 'POST', body });
}
```

The helper uses the platform `fetch`, sends the capability in
`X-Tgcloud-Capability`, strips URL fragments, rejects remote HTTP broker
endpoints, bounds the serialized client request to 1 MiB, and returns the
upstream `Response`.

## CLI reference

```text
tgcloud-secrets init [--data-dir PATH] [--dsn URL] [--org ID] [--project ID] [--kms-key-id ID]
tgcloud-secrets set NAME [--data-dir PATH] [--dsn URL] [--org ID] [--project ID]
tgcloud-secrets list [--json] [--data-dir PATH] [--dsn URL] [--org ID] [--project ID]
tgcloud-secrets grant NAME --base-url URL [options] [--dsn URL] [--org ID] [--project ID]
tgcloud-secrets capabilities [--json] [--data-dir PATH] [--dsn URL] [--org ID] [--project ID]
tgcloud-secrets revoke CAPABILITY_ID [--data-dir PATH] [--dsn URL] [--org ID] [--project ID]
tgcloud-secrets serve [--host HOST] [--port PORT] [--data-dir PATH] [--dsn URL] [--trusted-proxy IP[,IP...]] [--rate-limiter-module PATH]
tgcloud-secrets healthcheck [--dsn URL] [--kms-key-id ID]
tgcloud-secrets migrate --from PATH --to URL [--org ID] [--project ID] [--dry-run]
tgcloud-secrets migrate-db [--dsn URL] [--dry-run]
tgcloud-secrets migration-status [--dsn URL]
tgcloud-secrets config-check
```

`--dsn` or `DATABASE_URL`/`TGCLOUD_SECRETS_DSN` selects Postgres; otherwise
the file store is used. Postgres tenant IDs default to `default` but should be
explicit in shared deployments. `--kms-key-id` or `TGCLOUD_KMS_KEY_ID`
selects the KMS provider. `local` uses a 32-byte `TGCLOUD_MASTER_KEY` and is
for development or a tightly controlled single team only.

`grant` accepts `--path-prefix`, comma-separated `--method`,
`--inject-header`, `--inject-prefix`, `--allow-http` for loopback development,
and Postgres-only `--expires-at`. Postgres also exposes versioned secret
rollback, KMS re-encryption, capability rotation with bounded overlap,
tenant/project revocation, audit, and the ordered offboarding API through the
library and authenticated admin module.

`migrate-db --dry-run` is read-only. File-to-Postgres `migrate --dry-run` also
reads an existing source store without creating or repairing source files and
does not write the target database.

For a multi-replica production broker, `serve` accepts
`--rate-limiter-module PATH` or `TGCLOUD_RATE_LIMITER_MODULE`. The local module
must export `createRateLimiterBackend()`, `rateLimiterBackend`, or `default`
and provide a Redis-compatible client with `eval(script, options)`. A factory
may return `{ backend, close }` so the CLI can close the client during graceful
shutdown. The module is intentionally provider-neutral and must be supplied as
an immutable, operator-reviewed deployment artifact; the repository does not
choose a Redis vendor or receive its credentials.

## HTTP API

The broker exposes:

- `GET`/`HEAD /healthz` — process health without dependency claims.
- `GET /readyz` — Postgres/KMS or file-store readiness, with a short bounded cache.
- `GET /metrics` — bounded Prometheus counters and latency/event-loop gauges,
  restricted to loopback or an explicitly trusted proxy.
- `POST /v1/fetch` — JSON `{path, method, headers, body}` with
  `X-Tgcloud-Capability`.

Requests use strict bounded UTF-8 JSON parsing, reject duplicate/unsafe keys,
and apply body, field, depth, array, header, timeout, and concurrency limits.
The broker rejects absolute/cross-origin paths, encoded traversal, redirects,
hop-by-hop headers, private or link-local upstream addresses, mixed DNS
answers, and attempts to override the injected header. It pins the verified
upstream address while preserving HTTPS host/SNI behavior.

The optional `src/admin.js` module provides authenticated, idempotent routes
for secret writes/deletes/rollback, capability issue/revoke/rotation,
tenant/project emergency revocation, lifecycle transitions, and audit reads. It deliberately requires
an external authentication adapter and does not accept a caller-supplied
approval identity. The CLI does not invent OIDC, MFA, workload identity, or an
admin deployment; those are integration and organizational gates.

## Security model

- Postgres tenant tables use forced RLS plus composite organization/project
  foreign keys. Startup verifies an immutable contiguous migration history,
  exact checksums, required tables, and forced RLS; startup does not run DDL.
- Postgres records use per-secret KMS data keys and AES-256-GCM envelope `v3`
  encryption with organization, project, and secret-name associated data.
  AWS KMS decrypt caching is bounded by TTL and entry count, can be disabled
  with `TGCLOUD_KMS_CACHE_TTL_MS=0`, and fingerprints the encryption context.
  The local provider is an explicit development fallback, not a
  managed-production substitute.
- Capabilities store only token hashes and HMAC-authenticated policy metadata.
  Expiry, not-before, revocation, scheduled revocation, optimistic mutation
  versions, tenant kill switches, and bounded rotation overlap are enforced.
- Audit events are written transactionally to a Postgres outbox. Proxy use,
  administrative mutations, KMS rotation, revocation, and lifecycle changes
  are represented without storing secret values or bearer tokens. The outbox
  worker requires an explicit tenant scope and bounded publisher timeout; an
  external append-only destination and retention policy are still required.
- Rate limiting supports an injected Redis-compatible backend with an atomic
  script and bounded local fallback. The application does not silently claim
  that a local in-memory limiter is distributed; production wiring and Redis
  capacity are external deployment gates.
- Logs redact secret/token/credential/DSN material. Metrics labels do not carry
  secret names, capability tokens, URLs, or unbounded tenant identifiers.

Never disable TLS, RLS, audit, authentication, or limiter failure-closed
behavior to work around an incident. See [SECURITY.md](SECURITY.md),
`ops/`, `deploy/`, and the readiness matrix for operating requirements.

## Managed deployment outline

For a managed deployment, pre-provision the database schema and tenant with a
migration identity, then run the broker with a non-owner runtime role and
managed KMS/HMAC key delivery:

```sh
export TGCLOUD_ENV=production
export DATABASE_URL='postgresql://runtime@db.internal:5432/tgcloud?sslmode=verify-full'
export TGCLOUD_ORG_ID=myorg
export TGCLOUD_PROJECT_ID=mybot
export TGCLOUD_KMS_KEY_ID='arn:aws:kms:region:account:key/key-id'
export TGCLOUD_HMAC_KEY='REPLACE_WITH_32_BYTE_BASE64URL'
export TGCLOUD_HMAC_KEY_ID='hmac-2026'
export TGCLOUD_DISTRIBUTED_LIMITER=true
export TGCLOUD_AUDIT_REQUIRED=true
# Path inside the runtime image or mounted read-only adapter volume. The module
# must export the provider-neutral limiter contract described above.
export TGCLOUD_RATE_LIMITER_MODULE=/app/config/rate-limiter-adapter.mjs
# Optional bounded policy; defaults to 90 days and cannot exceed 365 days.
export TGCLOUD_MAX_CAPABILITY_LIFETIME_MS=7776000000

node src/cli.js config-check
node src/cli.js migration-status --dsn "$DATABASE_URL"
node src/cli.js healthcheck --dsn "$DATABASE_URL" --kms-key-id "$TGCLOUD_KMS_KEY_ID"
```

Use the deployment templates only after filling their immutable image,
secret-manager, ingress, Redis, resource, network-policy, backup, and owner
values. The repository deliberately cannot choose those consequential
provider or organizational decisions.

## Development verification

```sh
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:5432/tgcloud npm test
npm run fuzz
npm run check
npm run secret-scan
npm run license-check
node scripts/generate-sbom.mjs > sbom.cdx.json
npm audit --omit=dev
npm pack --dry-run
```

Postgres tests use the configured `DATABASE_URL`; if it is unset they default
to port 5433 so an accidental local test cannot mutate an unrelated database.

The broker returns upstream response bytes and selected representation
metadata. Some upstreams echo injected authentication headers or request data;
the broker cannot reliably remove such application-level echoes, so use a
vendor endpoint/adapter that does not reflect credentials and test the actual
upstream behavior before issuing a capability.
