# Data governance and deletion

This document defines the repository's data boundaries. It is a control
template, not a legal retention policy. The operating organization must approve
the values marked for decision before production.

## Data inventory and classification

| Data | Location | Classification | Repository behavior | Required owner decision |
| --- | --- | --- | --- | --- |
| Secret plaintext | Process memory only during set/get/forwarding | Restricted credential | Never returned by capability metadata, logs, metrics, or audit payloads; transient DEK buffers are zeroed | Memory/core-dump policy, host debugging policy, and vendor data handling |
| Encrypted secret envelope and DEK ciphertext | Postgres `secrets` and `secret_versions` | Restricted encrypted data | AES-256-GCM v3 binds org/project/name; KMS context is required for managed records | KMS region, key policy, backup encryption, rotation and recovery |
| Capability token | Issued once to an operator/bot; hash in Postgres | Restricted bearer credential | Only token hash and authenticated policy metadata are stored; token is not logged or placed in URLs | TTL, distribution, rotation, incident revocation and bot secret delivery |
| Capability policy and identifiers | Postgres `capabilities` | Confidential tenant metadata | Forced RLS and HMAC metadata authentication | Tenant visibility, export permissions and support access |
| Audit events | Postgres `capability_audit`/`audit_outbox`, external sink | Confidential security record | Transactional append path, redacted fields, scoped outbox worker | Retention, append-only storage, legal hold, access and regional residency |
| Idempotency metadata | Postgres `idempotency_keys` | Confidential operational data | New responses are encrypted; migrations 015 and 016 scrub and forbid plaintext response values | TTL, purge cadence, incident replay and support access |
| Network/request metadata | Audit rows and bounded metrics/logs | Operational/security metadata | Pathname, method, status, peer and request ID are bounded; no full URL/query or secret value | IP retention, privacy notice, aggregation and regional handling |
| KMS/DB/Redis/ingress logs | Managed external services | Security-sensitive operational data | Not controlled by this package | Provider retention, access review, export and deletion |

## Retention and legal hold decisions

Record approved values before launch:

```text
Secret current-version retention: <approve>
Secret historical-version retention: <approve>
Capability/audit retention: <approve>
Idempotency retention and purge cadence: <approve>
Database backup/PITR retention: <approve>
KMS audit-log retention: <approve>
Legal-hold authority and release process: <assign/approve>
Data residency regions: <approve>
Privacy/compliance owner: <assign>
```

Legal hold overrides ordinary deletion only when the authorized policy says so.
The hold must identify scope, authority, start time, review time, and release
conditions. Do not remove KMS keys or backups solely because a database row was
deleted.

## Export and deletion semantics

- Secret values are never exported by `list`, audit, metrics, or capability
  APIs. Any approved export must use a separately authenticated, audited,
  short-lived workflow with an explicit destination and legal basis.
- Project offboarding proceeds `active → disabling → revoking → erasing →
  completed`. Erasing requires explicit confirmation and removes project
  secrets, historical secret versions, capabilities through cascade, and
  idempotency rows while retaining the lifecycle/audit record.
- Organization-wide erasure is intentionally not a single database shortcut;
  execute and verify every project through the approved workflow. This prevents
  a partial tenant deletion from being mistaken for complete erasure.
- Database deletion does not prove deletion from managed backups, PITR archives,
  provider audit logs, caches, replicas, KMS records, or operator copies. The
  backup/KMS owners must execute the approved expiry and destruction policy and
  attach evidence.
- A deletion request must record requester, scope, authorization/approval,
  legal hold result, database transaction, external systems, completion time,
  exceptions, and reviewer. Failed or partial deletion remains an incident.

## Access and review

Use the non-owner runtime role for application traffic, a separately scoped
audit worker for outbox publication, and a migration identity only for schema
changes. Review grants, KMS key policy, secret-manager access, break-glass
members, and audit-reader access at the organization-approved cadence.
