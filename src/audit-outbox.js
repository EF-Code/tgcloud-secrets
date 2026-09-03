const DEFAULT_BATCH_SIZE = 100;
const DEFAULT_POLL_MS = 1_000;
const DEFAULT_PUBLISH_TIMEOUT_MS = 30_000;
const MAX_BACKOFF_MS = 5 * 60 * 1_000;
const MAX_PUBLISHED_EVENT_BYTES = 96 * 1024;
const MIN_CLAIM_LEASE_MS = 10 * 1_000;
const MAX_CLAIM_LEASE_MS = 5 * 60 * 1_000;
import { createRedactingLogger } from './observability.js';
import { parseStrictJson } from './json.js';
import { sanitizeAuditPayload } from './audit.js';
import { randomUUID } from 'node:crypto';

const TENANT_ID = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;

function validateTenantId(value, label) {
  if (typeof value !== 'string' || !TENANT_ID.test(value)) throw new Error(`${label} must be a valid tenant identifier`);
  return value;
}

function assertBatch(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 1_000) throw new Error('audit batch size must be between 1 and 1000');
  return value;
}

/**
 * Run a bounded outbox delivery loop with an injected publisher. The database
 * role used by `pool` must be a separate audit-worker identity; the broker
 * runtime identity should not be able to claim or publish every tenant's rows.
 */
export function createAuditOutboxWorker({
  pool,
  publish,
  orgId,
  projectId,
  batchSize = DEFAULT_BATCH_SIZE,
  pollMs = DEFAULT_POLL_MS,
  publishTimeoutMs = DEFAULT_PUBLISH_TIMEOUT_MS,
  logger = console,
} = {}) {
  if (!pool || typeof pool.connect !== 'function') throw new Error('Audit outbox worker requires a pg-compatible pool');
  if (typeof publish !== 'function') throw new Error('Audit outbox worker requires a publisher');
  validateTenantId(orgId, 'orgId');
  validateTenantId(projectId, 'projectId');
  assertBatch(batchSize);
  if (!Number.isSafeInteger(pollMs) || pollMs < 100 || pollMs > 60_000) throw new Error('audit pollMs must be between 100 and 60000');
  if (!Number.isSafeInteger(publishTimeoutMs) || publishTimeoutMs < 100 || publishTimeoutMs > 120_000) throw new Error('audit publishTimeoutMs must be between 100 and 120000');
  let stopped = false;
  let started = false;
  let timer;
  let activeDelivery;
  const safeLogger = createRedactingLogger(logger);
  const scopedProjectId = `${orgId}:${projectId}`;
  const claimLeaseMs = Math.min(MAX_CLAIM_LEASE_MS, Math.max(MIN_CLAIM_LEASE_MS, publishTimeoutMs * 2));

  async function publishWithTimeout(event) {
    const operation = Promise.resolve().then(() => publish(event));
    operation.catch(() => {});
    let timeout;
    try {
      return await Promise.race([
        operation,
        new Promise((_, reject) => {
          timeout = setTimeout(() => reject(new Error('audit publisher timed out')), publishTimeoutMs);
        }),
      ]);
    } finally {
      clearTimeout(timeout);
    }
  }

  async function withWorkerTransaction(callback) {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL statement_timeout = '10000ms'");
      // The worker identity is intentionally separate from the broker runtime
      // role. SET LOCAL keeps the elevated table privileges inside this
      // transaction only; the database role must be provisioned as NOLOGIN.
      await client.query('SET LOCAL ROLE tgcloud_audit_worker');
      await client.query(
        `SELECT set_config('app.org_id', $1, true), set_config('app.project_id', $2, true)`,
        [orgId, scopedProjectId],
      );
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async function claimEvent() {
    const claimToken = randomUUID();
    const result = await withWorkerTransaction((client) => client.query(
      `WITH candidate AS (
         SELECT id
         FROM audit_outbox
         WHERE org_id=$1 AND project_id=$2
           AND published_at IS NULL AND next_attempt_at <= now()
           AND (claim_expires_at IS NULL OR claim_expires_at <= now())
         ORDER BY next_attempt_at, id
         FOR UPDATE SKIP LOCKED
         LIMIT 1
       )
       UPDATE audit_outbox AS outbox
       SET claim_token=$3, claim_expires_at=now() + ($4 * interval '1 millisecond')
       FROM candidate
       WHERE outbox.id=candidate.id AND outbox.org_id=$1 AND outbox.project_id=$2
       RETURNING outbox.id, outbox.event_id, outbox.event_type, outbox.org_id,
                 outbox.project_id, outbox.payload, outbox.attempts, outbox.claim_token`,
      [orgId, scopedProjectId, claimToken, claimLeaseMs],
    ));
    return result.rows[0] || null;
  }

  async function completeEvent(event) {
    return withWorkerTransaction((client) => client.query(
      `UPDATE audit_outbox
       SET published_at=now(), attempts=attempts+1, claim_token=NULL, claim_expires_at=NULL
       WHERE id=$1 AND org_id=$2 AND project_id=$3 AND claim_token=$4 AND published_at IS NULL`,
      [event.id, orgId, scopedProjectId, event.claim_token],
    ));
  }

  async function failEvent(event, attempts, delay) {
    return withWorkerTransaction((client) => client.query(
      `UPDATE audit_outbox
       SET attempts=$2, next_attempt_at=now() + ($3 * interval '1 millisecond'),
           claim_token=NULL, claim_expires_at=NULL
       WHERE id=$1 AND org_id=$4 AND project_id=$5 AND claim_token=$6 AND published_at IS NULL`,
      [event.id, attempts, delay, orgId, scopedProjectId, event.claim_token],
    ));
  }

  async function deliverBatch() {
    let processed = 0;
    for (let index = 0; index < batchSize; index += 1) {
      const event = await claimEvent();
      if (!event) break;
      try {
        if (event.org_id !== orgId || event.project_id !== scopedProjectId
          || typeof event.event_id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(event.event_id)
          || typeof event.event_type !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(event.event_type)) {
          throw new Error('Audit outbox row has invalid tenant or event metadata');
        }
        const payload = sanitizeAuditPayload(typeof event.payload === 'string'
          ? parseStrictJson(event.payload, { maxBytes: 96 * 1024, maxDepth: 10, maxFields: 128, maxArrayItems: 128, maxStringBytes: 64 * 1024 })
          : event.payload);
        const publishedEvent = Object.freeze({
          eventId: event.event_id,
          eventType: event.event_type,
          orgId: event.org_id,
          projectId: event.project_id,
          payload,
        });
        if (Buffer.byteLength(JSON.stringify(publishedEvent), 'utf8') > MAX_PUBLISHED_EVENT_BYTES) {
          throw new Error('Audit outbox payload is too large');
        }
        await publishWithTimeout(publishedEvent);
        await completeEvent(event);
      } catch (error) {
        const attempts = Number(event.attempts || 0) + 1;
        const delay = Math.min(MAX_BACKOFF_MS, 1_000 * (2 ** Math.min(attempts, 9)));
        safeLogger.error('audit outbox delivery failed', { eventType: event.event_type, attempts, message: error.message });
        try {
          await failEvent(event, attempts, delay);
        } catch (claimError) {
          safeLogger.error('audit outbox claim release failed', { eventType: event.event_type, message: claimError.message });
          throw claimError;
        }
      }
      processed += 1;
    }
    return processed;
  }

  async function deliverOnce() {
    // A caller may invoke a manual delivery while the poll loop is already
    // running. Share the in-flight operation so two workers cannot overlap
    // their claim/update cycles through this instance, and so stop() can
    // provide a real graceful-drain guarantee.
    if (activeDelivery) return activeDelivery;
    const operation = deliverBatch();
    activeDelivery = operation;
    try {
      return await operation;
    } finally {
      if (activeDelivery === operation) activeDelivery = undefined;
    }
  }

  async function loop() {
    if (stopped) return;
    try {
      await deliverOnce();
    } catch (error) {
      safeLogger.error('audit outbox worker unavailable', { message: error.message });
    }
    if (!stopped) {
      timer = setTimeout(loop, pollMs);
      timer.unref?.();
    }
  }

  return {
    deliverOnce,
    start() {
      if (!stopped && !started) {
        started = true;
        void loop();
      }
    },
    async stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
      timer = undefined;
      // Publish happens outside the claim transaction. Wait for the current
      // delivery to finish its bounded publish and conditional release before
      // the caller closes the pool or process. The operation itself has
      // bounded publisher and database waits; stop never hides its result from
      // the delivery loop, but shutdown should remain best-effort.
      await activeDelivery?.catch(() => {});
    },
  };
}

export { DEFAULT_BATCH_SIZE, DEFAULT_PUBLISH_TIMEOUT_MS, MAX_BACKOFF_MS, MAX_PUBLISHED_EVENT_BYTES, MIN_CLAIM_LEASE_MS, MAX_CLAIM_LEASE_MS };
