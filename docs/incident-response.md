# Incident response playbook

This playbook is provider-neutral. Replace placeholders with the actual paging,
communications, identity, database, KMS, Redis, ingress, and audit owners before
production. Use synthetic data in exercises and preserve a timeline.

## First response

1. Declare the incident, assign an incident commander and evidence owner, and
   record time, affected tenant/project, release digest, replicas, and current
   dependency health.
2. Do not paste secrets, capability tokens, DSNs, request bodies, or customer
   payloads into the incident channel. Preserve immutable logs and audit records
   through the approved security process.
3. If authorization or tenant isolation is uncertain, remove public traffic or
   isolate the affected replica, then use the authenticated control plane to
   revoke the smallest affected organization/project scope.
4. Keep RLS, MFA, TLS, audit-required, and limiter fail-closed settings enabled.
   A temporary bypass requires the external break-glass approval and a written
   risk decision.

## Repository actions

Run from a reviewed artifact with the correct non-owner/migration identity. Do
not run destructive commands against production until the incident authority
has confirmed the exact tenant and scope.

| Situation | Repository action | Verify |
| --- | --- | --- |
| Configuration or schema concern | `node src/cli.js config-check`; `node src/cli.js migration-status --dsn "$DATABASE_URL"` | Exact approved environment, contiguous checksums, current schema, no secret output |
| Postgres/KMS readiness concern | `node src/cli.js healthcheck --dsn "$DATABASE_URL" --kms-key-id "$TGCLOUD_KMS_KEY_ID"` | Provider IAM/key state, context errors, pool saturation and readiness |
| Leaked capability | Identify the ID from controlled audit data, call the authenticated admin revoke route or `store.revokeCapability`, then issue a new bounded capability | Old token resolves to null; replacement resolves only for the approved policy |
| Tenant emergency stop | Authenticated admin tenant/project revoke or `store.setTenantRevocation` | Every replica denies the old capability; audit event exists and propagates |
| Offboarding request | Progress the scoped state machine through admin control plane with `eraseConfirmed` only at erasure | Secrets/capabilities/idempotency rows are gone; audit/lifecycle evidence remains |
| Redis outage | Keep the bounded local fallback and fail-closed limiter decision; restore the approved Redis service | Multi-replica burst tests and limiter error metrics return to baseline |
| KMS issue/rotation | Stop grants if required, inspect key state/IAM, and use the approved `rotateSecrets` workflow | Current and historical records decrypt; old key is disabled only after recovery evidence |
| Suspected tenant escape | Stop traffic, preserve DB/audit/KMS evidence, revoke scope, and invoke independent security review | RLS/role checks and a clean-room reproduction are complete |

## Evidence checklist

```text
Incident ID and commander: <record>
Detection and containment timestamps: <record>
Release/package/container digest: <record>
Affected organizations/projects: <record>
Identity/approval references: <record, no credentials>
Database/KMS/Redis/ingress evidence IDs: <record>
Audit delivery and backup/PITR evidence: <record>
Customer/regulatory notification decision: <owner/record>
Root cause and contributing controls: <record>
Remediation owner and due date: <record>
Post-incident reviewer: <assign>
```

## Exercises

At the approved cadence, exercise synthetic capability leakage, KMS denial,
Postgres failover, Redis outage, malformed/oversized requests, audit publisher
failure, deployment rollback, backup restore, and graceful drain. Measure
revocation propagation, recovery time, audit lag, data loss, and operator
decision points. Record failures as work items rather than treating a tabletop
as proof of runtime readiness.
