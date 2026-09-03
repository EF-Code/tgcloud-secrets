# Production operations template

This is a provider-neutral operating template. It records repository behavior
and commands, but does not choose a cloud, identity provider, retention
period, RPO/RTO, or SLO. Those values require an accountable operator and
security review before launch.

## Deployment preflight

1. Build from a reviewed commit and an immutable base-image digest. Generate
   and retain the SBOM and package checksum.
2. Apply `ops/postgres-roles.sql` with a database administrator before the first
   migration on a new database. The script grants schema `CREATE` only to the
   non-login schema-owner role so the migration identity can create and evolve
   the schema; the application runtime never receives that privilege. Run the
   migration job with the migration identity, then run:

   ```sh
   node src/cli.js migration-status --dsn "$DATABASE_URL"
   node src/cli.js config-check
   node src/cli.js healthcheck --dsn "$DATABASE_URL" --kms-key-id "$TGCLOUD_KMS_KEY_ID"
   ```

3. Verify migrations 015 and 016 have scrubbed and forbidden legacy plaintext
   idempotency responses, migration 017 has populated the project-level KMS
   authority, and migration 018 has added the audit-outbox claim lease
   columns, then apply the database role policy from
   `ops/postgres-roles.sql`. The broker must
   use `tgcloud_runtime`, never the schema owner, audit worker, or a superuser.
4. Verify the ingress overwrites forwarded security headers, provides verified
   TLS, and is the only network path to the broker. Set the exact immediate
   proxy addresses in `TGCLOUD_TRUSTED_PROXY_ADDRESSES`.
5. Start the broker only after readiness succeeds. Keep the admin listener on
   a separate private endpoint and provide an external authentication adapter.
6. For a multi-replica deployment, mount the reviewed limiter adapter as a
   read-only application artifact and set `TGCLOUD_RATE_LIMITER_MODULE` to its
   in-container path. The module must satisfy the contract documented in the
   README and must not obtain credentials from command-line arguments or log
   them. A production `serve` without this adapter fails closed at startup.

## Migration and forward recovery

Migrations are immutable and ordered. Startup only checks the exact current
schema version; it never creates or alters tables. If a migration fails, keep
the database available only to the migration operator, preserve the error and
transaction evidence, correct the migration or restore an isolated copy, and
resume with the same migration identity. Do not invent a destructive
down-migration in an incident. Deploy a forward migration and a compatible
application after validating both representations.

For a fresh or isolated restore:

```sh
pg_restore --no-owner --exit-on-error --dbname "$RESTORE_DATABASE_URL" "$BACKUP_FILE"
node src/cli.js migration-status --dsn "$RESTORE_DATABASE_URL"
node src/cli.js healthcheck --dsn "$RESTORE_DATABASE_URL" --kms-key-id "$TGCLOUD_KMS_KEY_ID"
```

Use a secret manager/workload identity for all DSNs and KMS credentials. Do
not put them in shell history. Restore tests must use synthetic secrets and a
separately approved KMS decrypt identity; KMS keys are not recoverable by
exporting a Postgres dump.

## Backup, PITR, and failover

The database operator must enable encrypted automated backups and point-in-time
recovery, define the backup retention/legal-hold policy, and record the
approved RPO/RTO here before launch:

```text
Database owner: <assign>
KMS owner: <assign>
Backup retention: <approve>
RPO: <approve>
RTO: <approve>
Restore exercise cadence: <approve>
```

At each restore exercise, verify schema status, KMS decryptability of current
and historical envelopes, capability revocation state, audit outbox ordering,
and that the restored service is isolated from production traffic. Record
timestamps, backup identifiers, key versions, observed RPO/RTO, and
remediation owners.

The audit outbox worker must run as a separately provisioned login identity that
can assume `tgcloud_audit_worker`, with one worker scope per logical
organization/project. Construct it with the exact `orgId` and `projectId`, set
the transaction-local context, and use an idempotent append-only publisher. Do
not grant the worker `BYPASSRLS`, table ownership, or access to secret tables.
The worker claims each row with a short lease, publishes outside the database
transaction, and conditionally completes or retries only while holding that
claim. A lease expiry, timeout, or database/network boundary can produce a
duplicate publish; the destination must deduplicate by `eventId`.

On `SIGTERM`, stop accepting new traffic, wait for active proxy requests up to
the configured drain deadline, stop the audit worker, and close the limiter
adapter and database pool. The worker's `stop()` waits for its bounded active
publisher attempt, so deployment termination grace must exceed the configured
publisher timeout plus normal cleanup overhead. If the deadline is reached,
preserve the outbox row for retry and investigate the resulting delivery lag.

## Dependency failure behavior

| Dependency | Repository behavior | Operator action |
| --- | --- | --- |
| Postgres | readiness fails; data-plane authorization cannot resolve | fail over/restore the approved HA database; investigate audit and pool errors |
| KMS | readiness or secret resolution fails closed | verify IAM, key state, context, throttling, and key recovery evidence |
| Redis limiter | local bounded emergency limiter is used; configured secret routes fail closed if the limiter cannot establish a decision | restore the limiter or reduce traffic; do not disable authorization controls |
| DNS/upstream | verified addresses, private ranges, redirects, and excessive responses are rejected | verify the vendor/egress policy; no blanket SSRF bypass |
| ingress certificate | readiness/edge health should remove traffic | renew through the approved certificate process and canary before promotion |
| bad release | drain and stop the affected replica; roll back the same signed artifact | preserve evidence and verify schema compatibility before rollback |

## Emergency response

- Leaked capability: identify the capability ID from controlled audit data,
  revoke it, issue a replacement with a bounded expiry, and verify both old
  and new resolution behavior.
- Suspected tenant escape: stop public traffic, preserve database/audit logs,
  revoke the affected organization/project, rotate relevant keys only under
  approved incident authority, and begin the independent investigation.
- KMS/HMAC compromise: disable or quarantine affected key versions, block
  grants, preserve ciphertext/key inventory, and use the tested re-encryption
  workflow. Do not delete a key until backup references and recovery evidence
  are approved.
- Break-glass access: require the external MFA/approval system, record actor,
  reason, scope, start/end time, and automatic revocation. The repository
  exposes audit fields but cannot create the external approval workflow.
