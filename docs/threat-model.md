# Threat model

## Assets

- Vendor secret plaintext and encrypted secret history.
- KMS-wrapped DEKs and HMAC capability metadata keys.
- Capability bearer tokens and the policy they authorize.
- Tenant/project identity, revocation state, idempotency responses, and audit
  evidence.
- Availability and integrity of the broker, Postgres, KMS, Redis limiter,
  ingress, and audit destination.

## Trust boundaries

1. Telegram Serverless bot code crosses into the broker with a bearer
   capability.
2. The broker crosses into an arbitrary approved HTTPS vendor origin.
3. The application runtime role crosses into Postgres protected by transaction
   context and forced RLS.
4. KMS protects DEKs outside the database; HMAC key material authenticates
   capability policy metadata.
5. The authenticated admin adapter crosses from an external identity/approval
   system into the control plane.
6. The audit worker crosses from a scoped Postgres outbox into an external
   append-only destination.

## Main abuse cases and controls

| Abuse case | Repository controls | Residual/external control |
| --- | --- | --- |
| Stolen capability used outside its policy | Hash-only storage, HMAC metadata, origin/path/method/header checks, expiry, not-before, revoke, kill switch, rotation | Bot secret distribution, short TTL, detection, incident revoke SLA |
| Cross-tenant read/write | Composite FKs, transaction-local context, forced RLS, non-owner role, exact org/project predicates | Correct role ownership/grants and managed DB verification |
| Database dump exposes plaintext | KMS-wrapped per-record DEKs, context-bound AES-GCM, encrypted idempotency replay, legacy scrub migration | Managed KMS IAM, backup encryption/retention, key recovery, memory/core dump policy |
| SSRF or DNS rebinding reaches private service | URL policy, private/link-local/mixed-answer rejection, verified-address pinning, redirect denial, egress template | Actual DNS/egress firewall and vendor allowlist |
| Header/path smuggling leaks or changes scope | Strict JSON, duplicate/unsafe-key rejection, hop-by-hop/original-path header filtering, no caller override of injected header | Edge normalization and vendor integration review |
| Brute-force or abuse overloads service | Invalid-attempt, capability, tenant, source, global and concurrency limits; circuit breaker; bounded buffers | Redis availability/capacity, WAF/edge quotas, load evidence |
| Admin caller forges approval | External authentication adapter boundary, default-deny roles, MFA/independent approver requirement, body approval rejected | OIDC/workload identity, MFA, approval ledger and access review |
| Audit evidence is rewritten or lost | Transactional outbox, redaction, scoped worker, runtime no update/delete privilege, retry/backoff | Append-only sink, publisher identity, retention, delivery monitoring |
| Malicious or broken release | Immutable migration checksums, CI checks, SBOM, non-root image, package lock | SAST, image scan, signing/provenance, branch protection and independent review |

## Residual risks requiring explicit acceptance

The repository cannot prevent a compromised host from reading plaintext while a
request is being forwarded, a compromised KMS/IAM authority from decrypting
data, an authorized administrator from misusing a permitted scope, data retained
in external backups/logs, or an upstream vendor from echoing an injected header.
It also cannot prove HA, failover, SLO, egress, Redis, identity, compliance, or
penetration-test outcomes without the actual deployment.

Threat-model review must be repeated after choosing the cloud topology,
identity provider, KMS/Redis/DB services, ingress, data residency, and customer
use cases. Record accepted residual risks and compensating controls with named
owners.
