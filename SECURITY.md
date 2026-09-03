# Security policy

## Supported versions

Only the latest published `0.1.x` release receives security fixes until a
different support window is approved and published. Operators should pin the
exact package or container digest and keep the Node.js runtime within the
supported engine range.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the repository's
private security contact or the GitHub Security Advisories workflow after an
owner has configured it. If no private channel is configured, contact the
maintainer privately through the address in the repository profile and do not
include live credentials, capability tokens, customer data, or production
topology in the first report.

Include the affected version/commit, deployment mode, a minimal reproducible
description, impact, and a safe test case using synthetic values. Redact
secrets from logs and attachments. The maintainer will acknowledge receipt,
coordinate a severity assessment, and agree on disclosure timing with the
reporter; response and patch SLAs must be set by the operating organization
before making a public guarantee.

## Security boundaries

The file store is for local development or a tightly controlled single-host
deployment. Hosted multi-tenant operation requires Postgres with forced RLS,
a non-owner runtime role, managed KMS, the authenticated admin control plane,
an approved ingress, distributed limiting, durable audit delivery, backups,
and exercised operational runbooks. See `ops/` and `docs/` for implementation
artifacts and unresolved external gates.

Capability tokens are bearer credentials. Revoke and reissue a token if it may
have been disclosed. Never put a token or secret value in source control,
URLs, logs, request bodies sent to an upstream, metrics labels, or issue
reports.
