# tgcloud-secrets

Capability-scoped secret injection for Telegram Serverless bots.

Telegram Serverless documents a deliberately small runtime: handlers can use the Telegram SDK, project modules, and outbound `fetch`, but not npm packages, the filesystem, or a documented runtime secret store. This project is an MVP companion broker for the missing secret boundary.

The broker stores vendor secrets encrypted at rest. A Serverless module receives only a revocable capability token. The token is scoped to:

- one upstream HTTPS origin;
- one path prefix;
- one or more HTTP methods; and
- one header into which the broker injects the secret.

The vendor secret is used only inside the broker's outbound request. It is never returned through the capability API, written to logs, or stored in the capability metadata.

## Status

MVP `0.1.0` is production-hardened for **single-host** local dev + controlled companion behind HTTPS. For multi-tenant/org use (as planned for Telegram Serverless GA), use **Postgres + KMS** mode below — same CLI, `Postgres` replaces file lock store, `KMS` envelope (`v3` with `keyId`) replaces `master.key` beside `store.json`. See `Production` section.

> File store (`--data-dir`) remains for local dev. Postgres (`--dsn`/`DATABASE_URL`) + `TGCLOUD_KMS_KEY_ID` (or `TGCLOUD_MASTER_KEY` for `local` KMS) is recommended for any shared/org deployment.

## Quick start

Requires a supported Node.js LTS release (22 or newer) for the CLI and broker.

```sh
npm test

# Create a private store. The generated master key is stored with mode 0600.
node src/cli.js init --data-dir .tgcloud-secrets

# Never put the vendor secret in a command argument or source file.
printf %s "$OPENAI_API_KEY" | node src/cli.js set openai --data-dir .tgcloud-secrets

# Grant only the endpoint and method the bot needs.
node src/cli.js grant openai \
  --data-dir .tgcloud-secrets \
  --base-url https://api.openai.com \
  --path-prefix /v1/ \
  --method POST \
  --inject-header authorization \
  --inject-prefix 'Bearer '

node src/cli.js serve --data-dir .tgcloud-secrets --host 127.0.0.1 --port 8787
```

`grant` prints a capability token once. The broker stores only its hash, so a lost token cannot be recovered; revoke it and create a new capability instead. The capability is not the vendor secret, but it is still a bearer credential and should not be committed to a public repository.

If `--data-dir` is omitted, the CLI uses the platform's per-user data directory (or `TGCLOUD_SECRETS_DATA_DIR`). The quick-start examples use an explicit project-local directory only to make the files visible; add that directory to `.gitignore` and never commit `master.key` or `store.json`.

## Using it from a Telegram Serverless module

Telegram Serverless does not load npm packages at runtime. Copy or vendor [`runtime/secret-fetch.js`](runtime/secret-fetch.js) into the bot's `lib/` directory, then configure it with the broker endpoint and the capability created above:

```js
// lib/openai.js — vendored from runtime/secret-fetch.js
import { fetch } from 'sdk';
import { createSecretFetch } from 'lib/secret-fetch';

const openaiFetch = createSecretFetch({
  endpoint: 'https://secrets.example.internal',
  capability: 'tgscap_REPLACE_WITH_THE_REVOCABLE_CAPABILITY',
  fetchImpl: fetch,
});

export function createCompletion(body) {
  return openaiFetch('/v1/chat/completions', {
    method: 'POST',
    body,
  });
}
```

The helper uses the platform's fetch-compatible implementation and returns the broker's normal `Response`. It sends the capability in `X-Tgcloud-Capability`; that header is stripped before the upstream request.

## CLI reference

```text
tgcloud-secrets init [--data-dir PATH] [--dsn URL] [--org ID] [--project ID] [--kms-key-id ID]
tgcloud-secrets set NAME [--data-dir PATH] [--dsn URL] [--org ID] [--project ID]  # reads from stdin
tgcloud-secrets list [--json] [--data-dir PATH] [--dsn URL] [--org ID] [--project ID]
tgcloud-secrets grant NAME --base-url URL [options] [--dsn URL] [--org ID] [--project ID] [--expires-at ISO8601]
tgcloud-secrets capabilities [--json] [--data-dir PATH] [--dsn URL] [--org ID] [--project ID]
tgcloud-secrets revoke CAPABILITY_ID [--data-dir PATH] [--dsn URL] [--org ID] [--project ID]
tgcloud-secrets serve [--host HOST] [--port PORT] [--data-dir PATH] [--dsn URL] [--trusted-proxy IP[,IP...]]
tgcloud-secrets healthcheck [--dsn URL] [--kms-key-id ID]
tgcloud-secrets migrate --from <path> --to <dsn> [--org ID] [--project ID]
```

Global: `--dsn` or `DATABASE_URL`/`TGCLOUD_SECRETS_DSN` selects Postgres (file store otherwise); `--org`/`--project` default `default`; `--kms-key-id` or `TGCLOUD_KMS_KEY_ID` (`local` uses `TGCLOUD_MASTER_KEY` 32-byte base64url, or ephemeral dev key).

`grant` options are `--path-prefix`, `--method` (comma-separated), `--inject-header`, `--inject-prefix`, and `--allow-http`. HTTP is rejected by default for upstreams; `--allow-http` is intended only for local development. The runtime helper likewise requires HTTPS for remote broker endpoints and permits HTTP only for loopback development endpoints.

`serve` binds to loopback by default. A non-loopback bind requires the explicit `--allow-public` acknowledgement; put TLS termination, authentication/access control, and network filtering in front of that deployment. If a trusted proxy overwrites `X-Forwarded-For`, pass its immediate IP with `--trusted-proxy` so invalid-attempt rate limits can distinguish clients; never use this option unless direct access is blocked and the proxy controls that header.

## HTTP API

The companion broker exposes:

- `GET /healthz` — non-sensitive health response (`HEAD` also, `?query` ignored).
- `GET /readyz` — checks Postgres + KMS (or file store) readiness, returns `200 {ok:true}` or `503`.
- `GET /metrics` — Prometheus `tgcloud_proxy_requests_in_flight`, per-capability `tgcloud_proxy_capability_in_flight`.
- `POST /v1/fetch` — accepts JSON `{path, method, headers, body}`. Capability via `X-Tgcloud-Capability`.

The broker rejects out-of-policy paths, methods, absolute URLs, redirects, hop-by-hop/forwarding headers, caller attempts to override the injected header, oversized request/response bodies, private or link-local literal/DNS targets, and malformed requests. It also applies instance-local per-capability and invalid-attempt rate limits. Upstream response bodies are returned as-is, so an upstream service that intentionally echoes its authorization header could still expose it to the caller; integrations should be chosen with that in mind.

## Security model and current limits

- **File store:** AES-256-GCM encrypts each secret with a local 32-byte master key and binds ciphertext to `secretName`; records from older unbound builds must be re-entered. `v3` envelope (`src/crypto.js:11`) now binds to `org/project` and uses `KMS` `DEK` per secret (`keyId` in record) when `--dsn` is used.
- **Postgres+KMS:** `orgs(id,kms_key_id)`, `projects(id,org_id)`, `secrets(id,project_id,name,encrypted_blob,dek_ciphertext,keyId)` `src/pg-store.js:67-77`, `capabilities` with `token_hash` + `metadata_mac` bound to `org/project/keyId/expiresAt` `src/crypto.js:123`. `LocalKMSProvider` `src/kms.js:9` encrypts `DEK` with `TGCLOUD_MASTER_KEY`; `AwsKMSProvider` `src/kms.js:40` uses `GenerateDataKey`/`Decrypt` cached `5m`.
- Store and key files (file mode) are `0600`/`0700` with symlink refusal `src/store.js:44-96` (`fstat`/`fchmod`). Postgres mode uses application-level `org_id`/`project_id` isolation via `WHERE` (no `RLS` yet — `RLS` is roadmap, not enabled), no file lock.
- Broker keeps only `SHA-256` of capability token `src/crypto.js:98`, `metadataMac` `HMAC-SHA256` `src/crypto.js:123` now includes `orgId/projectId/keyId/expiresAt`.
- Logs contain `capabilityId`, `path` (pathname only), `method`, `status` `src/broker.js:542-547`, never secret/`tgscap_` values. `capabilities` with `expiresAt` auto-rejected `src/pg-store.js:358`.
- Broker resolves public hostnames, rejects private/link-local, pins verified IP via custom `lookup` preserving `Host`/`SNI` `src/broker.js:237-284`.
- Bounded `1MiB` request / `30MiB` response, `15s` timeout, `maxHeaderSize 16k`, per-capability `8` + global `32` concurrency `src/broker.js:8-11`, graceful drain `src/broker.js:593-605`.
- Invalid-attempt limiting per `peer` or `client:<XFF>` when `--trusted-proxy` trusts immediate proxy `src/broker.js:107-117,477-499`; valid `tgscap_` tokens bypass invalid bucket (no DoS).
- File store `0600` key beside `store.json` is still host-compromise = decrypt. **Use Postgres+KMS (`local` `age` via `TGCLOUD_MASTER_KEY` or `AWS KMS` `TGCLOUD_KMS_KEY_ID=arn:...` + `TGCLOUD_HMAC_KEY` 32B base64url) for production** — key never on same disk unencrypted, `DEK` cached `5m` `src/kms.js:9,64`, `healthCheck` `src/pg-store.js:444` does `SELECT 1` + `KMS` roundtrip (`TGCLOUD_HMAC_KEY` required for `AwsKMS` `src/pg-store.js:17-32`).
- File mode has no `expiresAt` enforcement beyond `HMAC`; Postgres mode enforces `expires_at` and `org`/`project` isolation.
- No hosted identity provider/rotation scheduler/quota yet — `grant --expires-at` is per-capability TTL, `revoke` is immediate.

## Production (Postgres + KMS)

Local (no AWS) — single-team prod without dashboard:
```sh
docker compose up -d postgres # uses docker-compose.yml postgres:15
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/tgcloud
export TGCLOUD_MASTER_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")
# keep TGCLOUD_MASTER_KEY in systemd-creds/OS keyring, 0600, not in repo
node src/cli.js healthcheck --dsn $DATABASE_URL # -> {ok:true, store:'postgres'}
printf %s "$OPENAI_API_KEY" | node src/cli.js set openai --org myorg --project mybot
node src/cli.js grant openai --org myorg --project mybot --base-url https://api.openai.com --path-prefix /v1/ --method POST --expires-at 2027-01-01T00:00:00Z
DATABASE_URL=... TGCLOUD_MASTER_KEY=... node src/cli.js serve --host 127.0.0.1 --port 8787
# migrate from file store
node src/cli.js migrate --from .tgcloud-secrets --to $DATABASE_URL --org myorg --project mybot
```

Managed (org-ready, when Serverless GA):
```sh
# Postgres: Neon/Supabase/RDS, KMS: AWS KMS
export DATABASE_URL=postgres://...@neon...
export TGCLOUD_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/abc
export AWS_REGION=us-east-1 # + AWS credentials via env/IRSA
node src/cli.js healthcheck # checks SELECT 1 + KMS GenerateDataKey/Decrypt
# same set/grant/serve as above, but DEKs are KMS-wrapped, per-org kms_key_id in orgs table
```

## Development

```sh
npm test                          # file store + swarm-audit (49 tests)
DATABASE_URL=postgres://postgres:postgres@localhost:5432/tgcloud TGCLOUD_MASTER_KEY=... npm test  # + 5 pg-store tests
npm run check                     # node --check src/*.js + runtime
docker compose up -d && npm test  # local Postgres via 5432
```

Tests cover `v2` file store, `v3` envelope `org/project` binding `tests/kms.test.js`, `PgStore` isolation `tests/pg-store.test.js`, `broker` `PgStore` injection + `/readyz`/`/metrics`, and `swarm-audit` regressions without third-party network.
