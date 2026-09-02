# tgcloud-secrets

Capability-scoped secret injection for Telegram Serverless bots.

Telegram Serverless runs handlers with the Telegram SDK, project modules, and outbound `fetch`. It does not provide `npm` packages, filesystem access, or a secret store. `tgcloud-secrets` adds that boundary as a companion broker.

The broker holds vendor secrets encrypted at rest. A handler receives a revocable capability token scoped to one HTTPS origin, one path prefix, one or more HTTP methods, and one header for injection. The broker injects the secret on egress. It never returns the secret through the capability API, logs, or capability metadata.

## Status

`0.1.0` — single-host file store is ready for local development and a tightly controlled companion deployment behind HTTPS. For shared or multi-tenant use, use Postgres + KMS mode (same CLI, `Postgres` replaces the file lock, `KMS` envelope `v3` replaces `master.key`). See Production.

File store (`--data-dir`) remains for local work. For any shared deployment, use Postgres (`--dsn` or `DATABASE_URL`) with `TGCLOUD_KMS_KEY_ID` or `TGCLOUD_MASTER_KEY` for local KMS.

## Quick start (file store)

Requires Node.js 22 or newer.

```sh
npm test

# Create a private store. The key is written 0600.
node src/cli.js init --data-dir .tgcloud-secrets

# Do not put the secret in an argument or source file.
printf %s "$OPENAI_API_KEY" | node src/cli.js set openai --data-dir .tgcloud-secrets

# Allow only the endpoint and method the bot needs.
node src/cli.js grant openai \
  --data-dir .tgcloud-secrets \
  --base-url https://api.openai.com \
  --path-prefix /v1/ \
  --method POST \
  --inject-header authorization \
  --inject-prefix 'Bearer '

node src/cli.js serve --data-dir .tgcloud-secrets --host 127.0.0.1 --port 8787
```

`grant` prints the capability once. The broker stores only its hash, so a lost token cannot be recovered — revoke it and grant again. The capability is not the vendor secret, but it is a bearer credential. Do not commit it.

If `--data-dir` is omitted, the CLI uses the OS per-user data directory (`TGCLOUD_SECRETS_DATA_DIR` overrides). The examples use an explicit directory to make the files visible. Add that directory to `.gitignore` and do not commit `master.key` or `store.json`.

## Use in a Serverless module

Telegram Serverless does not install `npm` packages at runtime. Vendor `runtime/secret-fetch.js` into `lib/`:

```js
// lib/openai.js — vendored from runtime/secret-fetch.js
import { fetch } from 'sdk';
import { createSecretFetch } from 'lib/secret-fetch';

const openaiFetch = createSecretFetch({
  endpoint: 'https://secrets.example.internal',
  capability: 'tgscap_REPLACE_WITH_REVOCABLE_CAPABILITY',
  fetchImpl: fetch,
});

export function createCompletion(body) {
  return openaiFetch('/v1/chat/completions', {
    method: 'POST',
    body,
  });
}
```

The helper uses the platform's `fetch` and returns a standard `Response`. It sends the capability as `X-Tgcloud-Capability`, which the broker strips before forwarding.

## CLI reference

```text
tgcloud-secrets init [--data-dir PATH] [--dsn URL] [--org ID] [--project ID] [--kms-key-id ID]
tgcloud-secrets set NAME [--data-dir PATH] [--dsn URL] [--org ID] [--project ID]
tgcloud-secrets list [--json] [--data-dir PATH] [--dsn URL] [--org ID] [--project ID]
tgcloud-secrets grant NAME --base-url URL [options] [--dsn URL] [--org ID] [--project ID] [--expires-at ISO8601]
tgcloud-secrets capabilities [--json] [--data-dir PATH] [--dsn URL] [--org ID] [--project ID]
tgcloud-secrets revoke CAPABILITY_ID [--data-dir PATH] [--dsn URL] [--org ID] [--project ID]
tgcloud-secrets serve [--host HOST] [--port PORT] [--data-dir PATH] [--dsn URL] [--trusted-proxy IP[,IP...]]
tgcloud-secrets healthcheck [--dsn URL] [--kms-key-id ID]
tgcloud-secrets migrate --from <path> --to <dsn> [--org ID] [--project ID]
```

`--dsn` or `DATABASE_URL`/`TGCLOUD_SECRETS_DSN` selects Postgres; otherwise the file store is used. `--org` and `--project` default to `default`. `--kms-key-id` or `TGCLOUD_KMS_KEY_ID` selects the KMS key (`local` uses `TGCLOUD_MASTER_KEY`, a 32-byte base64url value).

`grant` options: `--path-prefix`, `--method` (comma-separated), `--inject-header`, `--inject-prefix`, `--allow-http` (local development only), `--expires-at` (Postgres only, ISO 8601).

`serve` binds to `127.0.0.1` by default. A non-loopback bind requires `--allow-public`; put TLS termination, authentication, and network filtering in front. If a trusted proxy overwrites `X-Forwarded-For`, pass its immediate IP to `--trusted-proxy` so rate limits distinguish clients. Use this only when direct access is blocked and the proxy controls the header.

## HTTP API

- `GET /healthz` — health check, `HEAD` also, `?query` ignored.
- `GET /readyz` — readiness, checks Postgres and KMS (or file store), `200 {ok:true}` or `503`.
- `GET /metrics` — Prometheus `tgcloud_proxy_requests_in_flight` and per-capability count.
- `POST /v1/fetch` — JSON `{path, method, headers, body}` with `X-Tgcloud-Capability`.

The broker rejects out-of-policy paths, methods, absolute URLs, redirects, hop-by-hop headers, attempts to override the injected header, oversized bodies, private or link-local targets, and malformed requests. It applies per-capability and invalid-attempt rate limits. Upstream bodies are returned as-is; an upstream that echoes `Authorization` would expose the secret, so choose integrations accordingly.

## Security model

- **File store:** `AES-256-GCM` with a local 32-byte key, `AAD` bound to `secretName`. The `v3` Postgres envelope binds to `org/project` and uses a per-secret `DEK` (`keyId` in record). Re-enter secrets from older unbound builds.
- **Postgres + KMS:** `orgs`, `projects`, `secrets`, and `capabilities` persist encrypted envelopes and metadata MACs bound to `org/project/keyId/expiresAt`. `LocalKMSProvider` wraps DEKs with `TGCLOUD_MASTER_KEY`; `AwsKMSProvider` uses `GenerateDataKey`/`Decrypt` with a bounded five-minute in-process cache.
- File mode uses `0600`/`0700` and `fstat`/`fchmod` symlink checks `src/store.js:44-96`. Postgres mode isolates by `WHERE org_id/project_id` (no `RLS` yet).
- The broker stores only the `SHA-256` hash `src/crypto.js:98` and `HMAC-SHA256` `src/crypto.js:123` now covering `orgId/projectId/keyId/expiresAt`.
- Logs contain `capabilityId`, `path` (pathname only), `method`, `status` `src/broker.js:542-547`, never secrets or tokens. `expiresAt` is enforced `src/pg-store.js:358`.
- Hostnames are resolved, private/link-local rejected, and the verified IP is pinned with `Host`/`SNI` preserved `src/broker.js:237-284`.
- Limits: `1 MiB` request, `30 MiB` response, `15s` timeout, `16k` header, `8` per-capability and `32` global concurrency `src/broker.js:8-11`, graceful drain `src/broker.js:593-605`.
- Rate limits are per `peer` or `client:<XFF>` when `--trusted-proxy` trusts the immediate proxy `src/broker.js:107-117,477-499`; valid `tgscap_` tokens bypass the invalid bucket.
- File `master.key` beside `store.json` means host compromise can expose secrets. For production, use Postgres + KMS (`TGCLOUD_MASTER_KEY` for local AES-GCM key wrapping, or `TGCLOUD_KMS_KEY_ID=arn:...` plus a 32-byte base64url `TGCLOUD_HMAC_KEY` for AWS). AWS DEKs are cached for at most five minutes; `healthCheck` performs a database query and KMS roundtrip.
- File mode has no `expiresAt` beyond `HMAC`; Postgres enforces `expires_at` and `org`/`project` isolation.
- No hosted identity, rotation, or quota yet — `grant --expires-at` is a per-capability TTL, `revoke` is immediate.

## Production (Postgres + KMS)

Local, no AWS — for a single team:

```sh
docker compose up -d postgres
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/tgcloud
export TGCLOUD_MASTER_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")
# keep TGCLOUD_MASTER_KEY in systemd-creds or OS keyring, 0600, not in repo
node src/cli.js healthcheck --dsn $DATABASE_URL
printf %s "$OPENAI_API_KEY" | node src/cli.js set openai --org myorg --project mybot
node src/cli.js grant openai --org myorg --project mybot --base-url https://api.openai.com --path-prefix /v1/ --method POST --expires-at 2027-01-01T00:00:00Z
DATABASE_URL=... TGCLOUD_MASTER_KEY=... node src/cli.js serve --host 127.0.0.1 --port 8787
# migrate from file
node src/cli.js migrate --from .tgcloud-secrets --to $DATABASE_URL --org myorg --project mybot
```

Managed, for multiple orgs at Serverless GA:

```sh
# Postgres: Neon/Supabase/RDS, KMS: AWS KMS
export DATABASE_URL=postgres://...@neon...
export TGCLOUD_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/abc
export AWS_REGION=us-east-1
node src/cli.js healthcheck
# same set/grant/serve as above, DEKs are KMS-wrapped, per-org kms_key_id in orgs
```

## Development

```sh
npm test                          # file store
DATABASE_URL=postgres://postgres:postgres@localhost:5432/tgcloud TGCLOUD_MASTER_KEY=... npm test  # + postgres
npm run check                     # node --check src/*.js + runtime
docker compose up -d && npm test  # local Postgres
```

Tests cover file store `v2`, envelope `v3` with `org/project` binding `tests/kms.test.js`, `PgStore` isolation `tests/pg-store.test.js`, broker injection with `PgStore` and `/readyz`/`/metrics`, and security regressions without network.
