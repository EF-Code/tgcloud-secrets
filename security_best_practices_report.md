# Security Best Practices Audit

Date: 2026-08-31
Scope: `src/crypto.js`, `src/store.js`, `src/policy.js`, `src/broker.js`, `src/cli.js`, `runtime/secret-fetch.js`, tests, package metadata, and CI configuration.
Method: read-only repository inspection, dependency audit, adversarial policy tests, local broker integration tests, and review of the deployment boundary.

## Executive summary

The initial MVP had no confirmed credential disclosure or code-execution issue, but it had several denial-of-service and egress-boundary weaknesses that matter for a public companion broker. Those issues are fixed in the working tree: upstream responses are capped while streaming, literal and DNS-resolved private targets are rejected, requests and secrets are bounded, valid and invalid capability use is rate-limited, concurrent store writers are serialized, and malformed connections are handled.

The project is still an early companion service, not a complete hosted secret manager. The most important residual risks are architectural: capabilities are bearer credentials embedded in Serverless code, the local master key is stored beside the ciphertext, DNS validation is not connection-pinned, and the broker has no built-in admin identity or TLS termination.

## Fixed findings

### SBP-001 — High — response-size check occurred after full buffering

Location: original commit `9724363`, `src/broker.js:91-94` (`performFetch`).

Evidence in the original code:

```js
const bytes = Buffer.from(await upstream.arrayBuffer());
if (bytes.length > maxResponseBytes) {
  throw Object.assign(new Error('Upstream response is too large'), { statusCode: 502 });
}
```

Impact: an upstream or attacker-controlled service could send a response larger than the configured limit. The broker allocated the complete response before checking its size, allowing memory exhaustion when exposed to untrusted callers or large upstream responses.

Fix: `src/broker.js:85-115` now checks `Content-Length` when available and reads the response through a `ReadableStream` reader, cancelling as soon as the byte limit is exceeded. The timeout remains active through response-body reading.

Validation: `tests/mvp.test.js` includes the response-limit streaming test; it passed as part of 9/9 tests.

### SBP-002 — High in cloud/LAN deployments — insufficient SSRF target controls

Location: original `src/policy.js` and `src/broker.js` egress path.

Evidence: the original policy restricted the request path to the configured origin, but did not reject private literal targets or inspect DNS answers before `fetch`.

Impact: a misconfigured or maliciously chosen capability could make the broker send a privileged header to localhost, private RFC1918 space, link-local services, cloud metadata endpoints, or a hostname resolving to one of those networks.

Fix:

- `src/policy.js:44-58` permits HTTPS by default and permits HTTP only for loopback development targets.
- `src/policy.js:168-204` rejects private, link-local, multicast, unspecified, and IPv4-mapped private addresses.
- `src/broker.js:118-129` resolves public hostnames and rejects private/link-local answers before egress.
- Redirects remain disabled and request paths remain origin/path-prefix constrained.

Validation: policy tests cover private IPv4/IPv6, mapped IPv6, traversal, cross-origin paths, and private DNS answers.

### SBP-003 — Medium — no capability abuse control

Location: original `src/broker.js` request route.

Evidence: the original broker had no per-capability or invalid-auth rate limiter.

Impact: anyone possessing a capability could consume unlimited upstream requests or broker resources; repeated invalid tokens could also cause repeated store lookups and hash scans.

Fix: `src/broker.js:32-53` adds bounded instance-local buckets. Authenticated capabilities default to 120 requests/minute; invalid attempts default to 60/minute per socket peer. Excess requests receive `429` with `Retry-After`.

Validation: the capability rate-limit test passed. The README documents that limits are instance-local and must be complemented by a reverse proxy or gateway for multi-instance deployments.

### SBP-004 — Medium — unbounded secret and request input

Location: original `src/store.js:setSecret` and `src/cli.js:readSecretFromStdin`; broker request handling.

Evidence: the original CLI accumulated all stdin bytes and the store accepted arbitrary-length values. Header injection could also fail later if a value contained CR/LF.

Impact: an accidental or maliciously large input could exhaust memory or produce invalid/header-injection-shaped values.

Fix:

- `src/store.js:23-25,178-182` caps secret values at 8 KiB and rejects CR/LF.
- `src/cli.js:111-124` enforces the same cap while reading stdin and never accepts a secret as a command argument.
- `src/broker.js:55-71` caps request bodies and `src/broker.js:85-115` caps response bodies.
- `src/policy.js:129-134` validates the injection prefix.

Validation: secret storage, CR/LF, and response/request policy tests pass.

### SBP-005 — Medium — concurrent administrative writes could lose updates

Location: original `src/store.js:setSecret`, `createCapability`, and `revokeCapability`.

Evidence: each command performed a read-modify-write sequence without a lock.

Impact: simultaneous CLI processes could overwrite one another's secret or capability changes even though each individual JSON write was syntactically atomic.

Fix: `src/store.js:146-216` adds a private lock file with ownership checks, stale-lock detection that checks the recorded PID, a timeout, and atomic store replacement. Initialization races handle `EEXIST` safely. Key, store, and lock paths reject symlinks and verify current-user ownership.

Validation: concurrent writer and symlink tests pass.

### SBP-006 — Low — malformed connections and unknown CLI options lacked explicit handling

Impact: malformed HTTP clients could leave request bodies undrained, and CLI typos could silently fall back to defaults.

Fix: `src/broker.js:213-235,266-284` drains rejected requests, bounds headers/timeouts, and handles server/client errors. `src/cli.js:43-101` rejects unknown, duplicate, and unexpected options/positionals.

Validation: syntax checks, CLI smoke checks, and the full test suite pass.

## Residual risks and deployment requirements

### R-001 — bearer capabilities remain bearer credentials

A capability is intentionally embedded in Serverless code because the documented runtime has no identity-bound secret API. A compromised module or leaked private repository can use the capability for its allowed origin/path/method until revocation. It cannot directly read the vendor secret through this broker, but it can make permitted upstream calls.

Mitigation: keep the Serverless project private, use one narrow capability per integration, rotate/revoke after suspected exposure, and put the broker behind HTTPS and network/access controls. A future native platform identity or short-lived exchange should replace long-lived embedded capabilities.

### R-002 — master key and ciphertext share the local store boundary

The master key is mode `0600` and the ciphertext is encrypted, which protects against casual disclosure and accidental commits. A host compromise that obtains both files can decrypt the store.

Mitigation: use an OS keyring, KMS, HSM, or externally injected master key before production use; do not treat this MVP's local file as a hardware-backed secret boundary.

### R-003 — DNS resolution is defense-in-depth, not connection pinning

The broker checks DNS answers immediately before `fetch`, but the resolver result is not cryptographically or socket-level pinned. A malicious or changing DNS authority could theoretically exploit a resolution/connection race.

Mitigation: use a restrictive egress firewall, a trusted resolver, fixed integration hostnames, and a network proxy that enforces public destination policy.

### R-004 — no built-in admin authentication or TLS termination

The broker has a capability-authenticated data endpoint but no admin/control-plane identity system and serves HTTP directly. The CLI is intended to run locally; a public deployment must provide TLS termination, access control, secret-store filesystem isolation, and process supervision externally.

### R-005 — limits and audit state are instance-local

Rate limits are in memory and there is no durable secret-access audit trail, quota service, or multi-host coordination. A production deployment needs a gateway, centralized telemetry, and a policy for rotation/revocation.

### R-006 — upstream responses are transparent

The broker does not inspect or redact upstream response bodies. If an upstream endpoint intentionally echoes an authorization header or returns a secret, the caller receives that response. Integrations should use endpoints that do not reflect credentials.

## Validation evidence

```text
npm test                                  9 passed, 0 failed
npm run check                             passed
npm audit --omit=dev --audit-level=moderate 0 vulnerabilities
git diff --check                          passed
npm pack --dry-run                        passed; runtime and broker files included
```

No credential-shaped values were found in the source tree by the targeted scan used for this audit. Test fixtures contain only clearly synthetic values.
