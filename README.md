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

This is an early MVP, suitable for local development and a carefully controlled companion deployment. It is not yet a hosted multi-tenant service. Run it behind HTTPS and an access-controlled network before using it with production secrets.

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
tgcloud-secrets init [--data-dir PATH]
tgcloud-secrets set NAME [--data-dir PATH]       # reads the value from stdin (trailing LF/CRLF is a delimiter)
tgcloud-secrets list [--json] [--data-dir PATH]
tgcloud-secrets grant NAME --base-url URL [options]
tgcloud-secrets capabilities [--json] [--data-dir PATH]
tgcloud-secrets revoke CAPABILITY_ID [--data-dir PATH]
tgcloud-secrets serve [--host HOST] [--port PORT] [--data-dir PATH] [--trusted-proxy IP[,IP...]]
```

`grant` options are `--path-prefix`, `--method` (comma-separated), `--inject-header`, `--inject-prefix`, and `--allow-http`. HTTP is rejected by default for upstreams; `--allow-http` is intended only for local development. The runtime helper likewise requires HTTPS for remote broker endpoints and permits HTTP only for loopback development endpoints.

`serve` binds to loopback by default. A non-loopback bind requires the explicit `--allow-public` acknowledgement; put TLS termination, authentication/access control, and network filtering in front of that deployment. If a trusted proxy overwrites `X-Forwarded-For`, pass its immediate IP with `--trusted-proxy` so invalid-attempt rate limits can distinguish clients; never use this option unless direct access is blocked and the proxy controls that header.

## HTTP API

The companion broker exposes:

- `GET /healthz` — non-sensitive health response.
- `POST /v1/fetch` — accepts a JSON request with `path`, optional `method`, `headers`, and string `body`. The capability is supplied in `X-Tgcloud-Capability`.

The broker rejects out-of-policy paths, methods, absolute URLs, redirects, hop-by-hop/forwarding headers, caller attempts to override the injected header, oversized request/response bodies, private or link-local literal/DNS targets, and malformed requests. It also applies instance-local per-capability and invalid-attempt rate limits. Upstream response bodies are returned as-is, so an upstream service that intentionally echoes its authorization header could still expose it to the caller; integrations should be chosen with that in mind.

## Security model and current limits

- AES-256-GCM encrypts each stored secret with a local 32-byte master key and binds the ciphertext to its logical secret name; records from older unbound MVP builds must be re-entered after upgrading.
- Store and key files are created with restrictive permissions; the broker refuses symlinked data files.
- The broker keeps only a SHA-256 hash of each capability token.
- Logs contain capability IDs, paths, methods, and statuses, never secret values or tokens.
- The broker resolves public hostnames before egress, rejects private/link-local answers, and the default fetch path pins the verified address while preserving the original Host/SNI name.
- The broker has bounded request/response sizes, timeouts, malformed-connection handling, per-capability concurrency limits, and instance-local rate limits.
- Invalid-attempt limiting uses the broker's immediate TCP peer by default. A public deployment behind a reverse proxy must enforce client-aware authentication and rate limiting at that trusted edge; `--trusted-proxy` enables `X-Forwarded-For` use only for explicitly listed immediate proxy IPs, and the proxy must overwrite that header.
- Capability policy metadata is authenticated with the local master key; capabilities created by older MVP builds must be re-granted after upgrading.
- Capabilities are currently bearer tokens. A compromised Serverless module can use its allowed upstream capability until it is revoked; it cannot read the vendor secret through the broker API unless the upstream service itself returns it.
- The local master key is stored separately as a mode-0600 file, but it lives beside the encrypted store in this MVP. A host compromise that obtains both files can decrypt the secrets; use an OS keyring/KMS-backed key strategy before production use.
- There is no multi-tenant identity provider, rotation scheduler, quota store, or hosted control plane yet.
- Administrative store writes use a local lock file and atomic replacement. This protects concurrent CLI writers on one filesystem, not a distributed multi-host deployment.

## Development

```sh
npm test
npm run check
```

The tests exercise encryption, restrictive storage, capability scoping, header handling, broker proxying, and the runtime helper without contacting a real third-party service.

### Swarm Audit Fix 1
- Documented fix for finding #1 with file:line refs and verification steps.

### Swarm Audit Fix 2
- Documented fix for finding #2 with file:line refs and verification steps.

### Swarm Audit Fix 3
- Documented fix for finding #3 with file:line refs and verification steps.

### Swarm Audit Fix 4
- Documented fix for finding #4 with file:line refs and verification steps.
