# SLO and alert ownership template

These are measurement definitions, not approved targets. Fill the target,
owner, paging route, and evidence location before production use.

| SLI | Measurement | Target | Owner/runbook |
| --- | --- | --- | --- |
| Availability | successful health/readiness window over eligible minutes | `<approve>` | `<assign>` |
| Authorized proxy success | authorized requests without broker/dependency error | `<approve>` | `<assign>` |
| Proxy latency | p50/p95/p99 from request acceptance to response completion | `<approve>` | `<assign>` |
| Revocation propagation | time from committed revoke/kill switch to all replicas denying | `<approve>` | `<assign>` |
| Audit delivery lag | event creation to append-only destination | `<approve>` | `<assign>` |
| Database saturation | pool wait, active connections, and transaction failures | `<approve>` | `<assign>` |
| KMS health | latency, denial/throttling, and readiness failures | `<approve>` | `<assign>` |

Required alerts include error-budget burn, auth-failure spikes, unusual
capability use, KMS denial/throttling, database saturation, limiter outage,
audit lag, certificate expiry, backup failure, and secret-marker detection.
Every alert needs a severity, owner, diagnosis, mitigation, escalation path,
and a tested runbook. Metric labels must remain bounded; do not add tenant,
capability, secret, URL, or path identifiers.
