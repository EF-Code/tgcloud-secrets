# Production-readiness status

This matrix is the implementation record for the repository. It is deliberately
honest: code and templates can be complete while a service is still not ready
for production because its cloud resources, identity system, operating owners,
or release controls have not been selected and exercised.

Status meanings:

- **Implemented** — the repository contains the control and a repeatable local
  test or static check covers it.
- **Partial** — the repository contains a bounded interface, template, or
  fail-closed behavior, but an integration or acceptance gate remains.
- **External gate** — this cannot be completed by source changes alone and must
  be owned, configured, and evidenced outside the repository.

The application must not be described as 100% production-ready until every
external gate below has an owner, an evidence location, and a successful
staging or recovery exercise.

## Phase traceability

| Phase | Repository result | Verification | Exit gate still required |
| --- | --- | --- | --- |
| A — storage and tenant isolation | Versioned migrations 001–018, including project-level KMS authority, leased audit-outbox claims, exact checksums, composite tenant foreign keys, forced RLS, lifecycle columns, and read-only migration status/dry run | `npm run migrate:db`, `npm run migration:status`, Postgres integration and RLS tests | Run upgrade/rollback-compatibility rehearsals on a production-like copy, size/lock migrations, and approve the migration identity and maintenance window |
| B — key/configuration controls | KMS envelope v3, context binding, bounded cache, HMAC key ring, typed production checks, KMS rotation, optimistic secret versions | crypto/KMS/config/lifecycle tests and `npm run check` | Provision managed KMS, IAM, key policy, HMAC secret delivery, rotation schedule, and recovery evidence |
| C — control plane and audit | External-auth adapter boundary, role matrix, MFA/independent approval checks, transactional outbox, encrypted idempotency replay, offboarding state machine | admin, auth, lifecycle, idempotency, and Postgres tests | Integrate OIDC/workload identity/MFA and an append-only audit destination; approve retention and break-glass authority |
| D — broker resilience | Strict bounded input, SSRF/DNS pinning, HTTPS policy, provider-neutral rate-limit adapter/fallback, circuit breaker, cancellation, concurrency, metrics, and graceful drain including active audit-worker delivery | broker/policy/resilience/fuzz tests | Supply the reviewed limiter module, wire Redis and ingress/egress policy, then run load, soak, failover, and cancellation tests through the real topology |
| E — delivery and operations | Non-root image, deployment templates, role SQL, CI checks, SBOM, secret/license checks, runbooks, threat/data-governance docs | `npm run check`, tests, `npm run secret-scan`, `npm run license-check`, SBOM, package dry run | Pin/sign/promote the exact release, configure branch/repository controls, assign on-call owners, and complete an independent review |

## Requirement-by-requirement audit

| # | Requirement | Repository evidence | Status and remaining action |
| ---: | --- | --- | --- |
| 1 | Safe schema migration and upgrade path | `migrations/001_initial.sql` through `migrations/018_audit_outbox_leases.sql`; `src/migrations.js` uses contiguous versions, checksums, an advisory lock, bounded timeouts, and no startup DDL | **Implemented/partial.** Test all supported historical versions and real data volumes in an isolated staging database before release. Do not edit an applied migration; add a forward migration. |
| 2 | Tenant isolation at the database boundary | `src/pg-store.js` sets transaction-local tenant context; migration 013 adds composite organization/project/secret relationships; migration 002/003/004/006 force RLS; `ops/postgres-roles.sql` keeps runtime non-owner and migration metadata read-only | **Implemented.** Production must execute the role script, verify `rolbypassrls=false`, verify ownership, and run the RLS test against the real managed PostgreSQL service. |
| 3 | Authenticated control plane and least privilege | `src/auth.js` has default-deny role permissions, tenant checks, and destructive MFA/independent-approval requirements; `src/admin.js` requires an authentication adapter and rejects body-supplied approval | **Partial.** Select and integrate an OIDC/workload identity provider, validate claims and tenant mapping, provide MFA/step-up and independent approval, and test token expiry, clock skew, rotation, and outage behavior. |
| 4 | KMS-backed envelope encryption and key rotation | `src/kms.js`, `src/crypto.js`, and `src/pg-store.js` bind records to org/project/name context, bound cache plaintext DEKs, zero transient buffers, and rotate current/history records transactionally | **Partial.** Create the managed key, restrictive IAM/key policy, regional/residency choice, deny disabled/deleted key states, KMS quotas/alerts, and a tested key recovery/rotation exercise. Local KMS is not the managed-production control. |
| 5 | Capability scoping, expiry, revocation, and rotation | `src/pg-store.js` validates origin/path/method/header policy, stores token hashes and HMAC metadata, enforces expiry/not-before/revocation/kill switches, optimistic versions, and bounded overlap | **Implemented/partial.** Decide the approved maximum TTL, source restrictions, quota policy, and emergency revocation SLA; test them through the ingress and all replicas. |
| 6 | Distributed rate limiting and abuse controls | `src/rate-limit.js` provides atomic Redis scripting, bounded keys, fail-closed decisions, and bounded local fallback; `src/rate-limiter-adapter.js` and the CLI load a local operator-supplied adapter; broker applies capability, tenant, source, global, and invalid-attempt buckets | **Partial.** Supply a TLS-authenticated Redis-compatible service and reviewed adapter module, set capacity/eviction/availability policy, and prove behavior during Redis loss and multi-replica bursts. The local fallback is not distributed. |
| 7 | Network, TLS, and SSRF boundary | `src/policy.js` and `src/broker.js` reject private/link-local/mixed DNS answers, redirects, unsafe paths/headers, and remote HTTP; deployment templates require an authenticated TLS edge and network policy | **Partial.** Configure actual ingress TLS, mTLS if required, trusted proxy addresses, egress allowlists/DNS, Postgres/KMS/Redis private paths, firewall rules, certificate renewal, and network-policy selectors. |
| 8 | Durable, redacted, tamper-resistant audit | Mutations and proxy use append to `audit_outbox`; idempotency responses are encrypted; `src/audit-outbox.js` uses tenant-scoped short claim leases, retry/backoff, bounded database/publisher waits, active-delivery tracking for graceful stop, and redacted errors; runtime SQL cannot update/delete the outbox | **Partial.** Choose an append-only destination, publisher identity, delivery semantics, retention/legal hold, clock source, alert threshold, and replay procedure. Make the publisher idempotent because a lease expiry or database/network boundary can produce duplicates. |
| 9 | Observability and SLOs | `src/observability.js` redacts sensitive fields; broker emits bounded metrics for traffic, limits, errors, latency, and event-loop delay; `ops/slo-template.md` defines candidate SLIs and alert classes | **Partial.** Approve target SLOs/error budgets, dashboards, traces, sampling, cardinality limits, alert owners, paging routes, and log/metric retention. No target or owner is invented here. |
| 10 | HA database, backup, PITR, and restore | `ops/production-operations.md` gives restore, migration, KMS, and failover procedures; deployment template uses two replicas and readiness/liveness probes | **External gate.** Select managed PostgreSQL HA/failover, encrypted backup/PITR retention, RPO/RTO, replica/connection budgets, and complete a restore exercise that decrypts current/history data and verifies revocation/audit state. |
| 11 | Secret/configuration delivery | `src/config.js` rejects insecure production combinations, conflicting modes/keys, default DB credentials, local KMS, disabled audit, unsafe HMAC state, and public binds without edge controls | **Partial.** Use workload identity/secret manager delivery, prohibit shell history and image-layer secrets, configure tenant IDs, Redis/edge settings, KMS/HMAC rotation, and verify no secret appears in process arguments or diagnostics. |
| 12 | API/version compatibility and graceful failure | CLI has explicit migration/config/health commands and a provider-neutral limiter loader; broker/admin/runtime helper use bounded strict JSON, stable public error codes, request IDs, timeouts, client cancellation, and graceful drain | **Implemented/partial.** Publish a compatibility matrix for Node/SDK/proxy versions, exercise oversized/malformed/disconnected traffic through the real edge, and define deprecation/versioning policy. |
| 13 | Offboarding, deletion, and data governance | `src/pg-store.js` enforces ordered project lifecycle transitions, explicit erasure confirmation, capability kill switch, secret/idempotency deletion, retained audit, and prevents organization erasure from bypassing project workflow; `docs/data-governance.md` records the policy decisions needed | **Partial.** Approve retention, legal hold, residency, export/delete response, KMS disablement, backup expiry, and evidence destruction. Database deletion alone does not erase backups or KMS audit records. |
| 14 | Supply-chain and release integrity | CI pins action commits, runs tests/checks/scans/license/audit/SBOM/package checks; CodeQL and dependency-review workflows are pinned; `Dockerfile` uses non-root runtime; `ops/release-checklist.md` requires immutable image, signing, and provenance | **Partial.** Configure repository-host branch protection, dependency update ownership, container scanning, signed artifacts, provenance verification, vulnerability exceptions, and release approvals; hosted CodeQL/dependency-review results still need review. |
| 15 | Test depth and independent assurance | Unit, file-store, Postgres, RLS, crypto, admin, lifecycle, broker, resilience, strict-parser, deterministic fuzz, and migration tests run with the regular suite | **Partial.** Run production-like load/soak/concurrency, chaos/dependency outage, HA/failover, ingress E2E, restore, and penetration tests. Record findings and remediation; regular local tests are not proof of those external behaviors. |
| 16 | Operations, incident response, and break glass | `ops/production-operations.md`, `ops/release-checklist.md`, `ops/slo-template.md`, and `docs/incident-response.md` provide commands, failure behavior, alert classes, and evidence fields | **Partial.** Assign service/database/KMS/security owners, on-call and escalation paths, communications, break-glass approval, access review cadence, and exercise the runbooks with synthetic data. |
| 17 | Documentation and customer/operator expectations | README, SECURITY policy, deployment examples, threat model, governance, incident, operations, and readiness matrix describe implemented boundaries and limitations | **Implemented/partial.** Review docs with operators and customers; only publish guarantees backed by approved SLO, support, retention, and disclosure commitments. |
| 18 | Legal, privacy, and compliance | Repository avoids making legal claims and documents data categories and unresolved decisions | **External gate.** Complete privacy/security review, DPA/subprocessor assessment, residency/export controls, breach-notification obligations, license review, regulatory mapping, and formal risk acceptance where applicable. |

## Release evidence required before production

1. A reviewed commit and immutable package/container digest are promoted from
   staging; the SBOM, vulnerability result, signature, provenance, and review
   records refer to that same digest.
2. `config-check`, migration status, health/readiness, role/RLS verification,
   and synthetic admin/proxy traffic pass with production-like identities and
   no live secret values in logs.
3. A managed-KMS rotation, capability revoke/restore, limiter outage, database
   failover, backup restore, audit-delivery retry, and graceful-drain exercise
   have timestamps, owners, expected/observed results, and retained evidence.
4. The approved SLO/alert dashboard is paging the named on-call, and the
   incident/break-glass workflow has been exercised by the people who will use
   it.
5. Independent security review, privacy/compliance review, and risk acceptance
   are complete for the deployment's actual topology and data classification.

Until these records exist, safe repository work can continue, but a production
deployment choice should stop at the external gate rather than silently using
local KMS, in-memory limiting, unauthenticated administration, public HTTP, or
unverified backups.
