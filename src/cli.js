#!/usr/bin/env node

import { MAX_SECRET_BYTES, SecretStore } from './store.js';
import { PgStore } from './pg-store.js';
import { createBrokerServer } from './broker.js';
import { isLoopbackHost } from './policy.js';
import { join } from 'node:path';
import { TextDecoder } from 'node:util';
import { LocalKMSProvider } from './kms.js';
import { generateMasterKey, encodeMasterKey } from './crypto.js';
import { migrationStatus, runMigrations } from './migrations.js';
import { assertDatabaseConfig, assertProductionConfig, readConfig } from './config.js';
import { loadRateLimiterBackend } from './rate-limiter-adapter.js';

const VERSION = '0.1.0';

function usage() {
  console.log(`tgcloud-secrets ${VERSION}

Capability-scoped secret injection for Telegram Serverless bots.

Commands:
  init                                      Create a private local store (or Postgres when --dsn set)
  set <name>                                Read a secret from stdin and store it encrypted
  list                                      List secret names (never values)
  grant <secret> --base-url <url>           Create a scoped capability
  capabilities                              List capability metadata (never tokens)
  revoke <capability-id>                   Revoke a capability
  serve                                     Run the local/companion broker
  migrate --from <path> --to <dsn>          Migrate file store to Postgres
  migrate-db [--dsn URL]                    Apply versioned Postgres migrations
  migration-status [--dsn URL]              Show Postgres migration status
  config-check                               Validate production configuration
  healthcheck                               Check Postgres + KMS connectivity

Global options:
  --data-dir <path>                         Store directory (default: OS user-data directory, ignored with --dsn)
  --dsn <postgres://...>                    Postgres DSN (or DATABASE_URL env)
  --org <id>                                Organization ID (default: default)
  --project <id>                            Project ID (default: default)
  --kms-key-id <id>                         KMS key ID (or TGCLOUD_KMS_KEY_ID env, default: local)

Grant options:
  --path-prefix <path>                      Allowed upstream path (default: /)
  --method <methods>                        Comma-separated methods (default: GET)
  --inject-header <name>                   Header that receives the secret (default: authorization)
  --inject-prefix <text>                   Prefix such as "Bearer " (default: empty)
  --allow-http                              Allow HTTP; use only for local development
  --expires-at <ISO8601>                   Expiry time for capability (e.g., 2027-01-01T00:00:00Z)

Serve options:
  --host <host>                             Bind host (default: 127.0.0.1)
  --port <port>                             Bind port (default: 8787)
  --trusted-proxy <ips>                     Trust X-Forwarded-For from these proxy IPs for rate limiting
  --rate-limiter-module <path>              Local module exporting the distributed limiter adapter
  --allow-public                            Acknowledge that a non-loopback bind needs external TLS/access controls

Examples:
  printf %s "$OPENAI_API_KEY" | tgcloud-secrets set openai
  tgcloud-secrets grant openai --base-url https://api.openai.com --path-prefix /v1/ --method POST --inject-prefix "Bearer "
  tgcloud-secrets serve --host 127.0.0.1 --port 8787
  DATABASE_URL=postgres://... tgcloud-secrets set openai --org myorg --project mybot
`);
}

function parseArgs(args) {
  const positional = [];
  const options = Object.create(null);
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--__proto__' || arg === '--constructor' || arg === '--prototype' || arg.startsWith('--__proto__=') || arg.startsWith('--constructor=') || arg.startsWith('--prototype=')) throw new Error(`Option ${arg} is reserved`);
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const withoutPrefix = arg.slice(2);
    if (withoutPrefix === 'help' || withoutPrefix === 'version') {
      options[withoutPrefix] = true;
      continue;
    }
    if (withoutPrefix === 'allow-http' || withoutPrefix === 'allow-public' || withoutPrefix === 'json' || withoutPrefix === 'dry-run') {
      if (Object.hasOwn(options, withoutPrefix)) throw new Error(`Option --${withoutPrefix} was provided more than once`);
      options[withoutPrefix] = true;
      continue;
    }
    const equals = withoutPrefix.indexOf('=');
    if (equals !== -1) {
      const name = withoutPrefix.slice(0, equals);
      if (Object.hasOwn(options, name)) throw new Error(`Option --${name} was provided more than once`);
      options[name] = withoutPrefix.slice(equals + 1);
      continue;
    }
    const next = args[index + 1];
    if (next === undefined || next.startsWith('--')) throw new Error(`Option --${withoutPrefix} requires a value`);
    if (Object.hasOwn(options, withoutPrefix)) throw new Error(`Option --${withoutPrefix} was provided more than once`);
    options[withoutPrefix] = next;
    index += 1;
  }
  return { positional, options };
}

const ALLOWED_OPTIONS = {
  init: new Set(['data-dir', 'dsn', 'org', 'project', 'kms-key-id', 'json']),
  set: new Set(['data-dir', 'dsn', 'org', 'project', 'kms-key-id', 'json']),
  list: new Set(['data-dir', 'dsn', 'org', 'project', 'kms-key-id', 'json']),
  grant: new Set(['data-dir', 'dsn', 'org', 'project', 'kms-key-id', 'json', 'base-url', 'path-prefix', 'method', 'inject-header', 'inject-prefix', 'allow-http', 'expires-at']),
  capabilities: new Set(['data-dir', 'dsn', 'org', 'project', 'kms-key-id', 'json']),
  caps: new Set(['data-dir', 'dsn', 'org', 'project', 'kms-key-id', 'json']),
  revoke: new Set(['data-dir', 'dsn', 'org', 'project', 'kms-key-id', 'json']),
  serve: new Set(['data-dir', 'dsn', 'org', 'project', 'kms-key-id', 'host', 'port', 'trusted-proxy', 'rate-limiter-module', 'allow-public']),
  migrate: new Set(['from', 'to', 'org', 'project', 'kms-key-id', 'json', 'dry-run']),
  'migrate-db': new Set(['dsn', 'json', 'dry-run']),
  'migration-status': new Set(['dsn', 'json']),
  'config-check': new Set(['json']),
  healthcheck: new Set(['dsn', 'kms-key-id', 'json']),
};

function validateCommandArgs(command, positional, options) {
  if (!ALLOWED_OPTIONS[command]) throw new Error(`Unknown command: ${command}`);
  for (const name of Object.keys(options)) {
    if (!ALLOWED_OPTIONS[command].has(name)) throw new Error(`Unknown option for ${command}: --${name}`);
  }
  for (const name of ['json', 'allow-http', 'allow-public', 'dry-run']) {
    if (options[name] !== undefined && options[name] !== true) throw new Error(`--${name} is a flag and does not take a value`);
  }
  const valueOptions = new Set([
    'data-dir', 'dsn', 'org', 'project', 'kms-key-id', 'from', 'to', 'base-url',
    'path-prefix', 'method', 'inject-header', 'expires-at', 'host', 'port',
    'trusted-proxy', 'rate-limiter-module',
  ]);
  for (const name of valueOptions) {
    if (options[name] !== undefined && options[name] === '') throw new Error(`--${name} must not be empty`);
  }

  const expectedPositionals = { init: 0, set: 1, list: 0, grant: 1, capabilities: 0, caps: 0, revoke: 1, serve: 0, migrate: 0, 'migrate-db': 0, 'migration-status': 0, 'config-check': 0, healthcheck: 0 }[command];
  if (positional.length !== expectedPositionals) throw new Error(`Unexpected positional arguments for ${command}`);
}

function valueOption(options, name, fallback) {
  return options[name] === undefined ? fallback : options[name];
}

function dataDirOption(options) {
  if (options['data-dir'] !== undefined) return options['data-dir'];
  if (process.env.TGCLOUD_SECRETS_DATA_DIR !== undefined) {
    if (process.env.TGCLOUD_SECRETS_DATA_DIR.length === 0) throw new Error('TGCLOUD_SECRETS_DATA_DIR must not be empty');
    return process.env.TGCLOUD_SECRETS_DATA_DIR;
  }
  if (process.platform === 'win32') return join(process.env.APPDATA || process.env.LOCALAPPDATA || '.', 'tgcloud-secrets');
  if (process.env.XDG_DATA_HOME) return join(process.env.XDG_DATA_HOME, 'tgcloud-secrets');
  if (process.env.HOME) return join(process.env.HOME, '.local', 'share', 'tgcloud-secrets');
  return '.tgcloud-secrets';
}

function dsnOption(options) {
  if (options['dsn'] !== undefined) return options['dsn'];
  if (process.env.DATABASE_URL !== undefined) return process.env.DATABASE_URL;
  if (process.env.TGCLOUD_SECRETS_DSN !== undefined) return process.env.TGCLOUD_SECRETS_DSN;
  return null;
}

function orgOption(options) {
  if (options['org'] !== undefined) return options['org'];
  if (process.env.TGCLOUD_ORG_ID !== undefined) return process.env.TGCLOUD_ORG_ID;
  return 'default';
}

function projectOption(options) {
  if (options['project'] !== undefined) return options['project'];
  if (process.env.TGCLOUD_PROJECT_ID !== undefined) return process.env.TGCLOUD_PROJECT_ID;
  return 'default';
}

function kmsKeyIdOption(options) {
  if (options['kms-key-id'] !== undefined) return options['kms-key-id'];
  if (process.env.TGCLOUD_KMS_KEY_ID !== undefined) return process.env.TGCLOUD_KMS_KEY_ID;
  if (process.env.AWS_KMS_KEY_ID !== undefined) return process.env.AWS_KMS_KEY_ID;
  return 'local';
}

function createStore(options, { host } = {}) {
  const hasExplicitDsn = options['dsn'] !== undefined;
  const hasExplicitDataDir = options['data-dir'] !== undefined;
  const dsn = dsnOption(options);
  const orgId = orgOption(options);
  const projectId = projectOption(options);
  const kmsKeyId = kmsKeyIdOption(options);
  const effectiveEnv = {
    ...process.env,
    DATABASE_URL: dsn === null ? undefined : dsn,
    TGCLOUD_ORG_ID: orgId,
    TGCLOUD_PROJECT_ID: projectId,
    TGCLOUD_KMS_KEY_ID: kmsKeyId,
    ...(host ? { TGCLOUD_HOST: host } : {}),
  };
  if (hasExplicitDataDir && !hasExplicitDsn) {
    // The file-store override intentionally ignores database selectors, but
    // still validates the environment mode and all controls that apply to
    // the selected local store.
    effectiveEnv.DATABASE_URL = undefined;
    effectiveEnv.TGCLOUD_SECRETS_DSN = undefined;
  }
  const config = assertProductionConfig(readConfig(effectiveEnv));
  // Explicit --data-dir takes precedence over env DATABASE_URL to avoid surprise
  if (hasExplicitDataDir && !hasExplicitDsn) {
    return new SecretStore({ dataDir: dataDirOption(options) });
  }
  if (dsn) {
    const masterKeyEnv = process.env.TGCLOUD_MASTER_KEY;
    let kmsProvider = null;
    if (kmsKeyId === 'local' && masterKeyEnv) {
      kmsProvider = new LocalKMSProvider({ masterKey: masterKeyEnv, keyId: 'local' });
    } else if (kmsKeyId !== 'local') {
      kmsProvider = null;
    }
    return new PgStore({ dsn, orgId, projectId, kmsProvider, kmsKeyId, masterKey: masterKeyEnv || undefined, maxCapabilityLifetimeMs: config.maxCapabilityLifetimeMs });
  }
  return new SecretStore({ dataDir: dataDirOption(options) });
}

function validateServeOptions(options) {
  const host = valueOption(options, 'host', process.env.TGCLOUD_HOST !== undefined ? process.env.TGCLOUD_HOST : '127.0.0.1');
  if (typeof host !== 'string' || host.length === 0) throw new Error('--host/TGCLOUD_HOST must not be empty');
  const port = Number(valueOption(options, 'port', process.env.TGCLOUD_PORT !== undefined ? process.env.TGCLOUD_PORT : '8787'));
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error('Port must be an integer from 1 to 65535');
  const rateLimiterModule = rateLimiterModuleOption(options);
  const effectiveEnv = {
    ...process.env,
    TGCLOUD_HOST: host,
    TGCLOUD_ORG_ID: orgOption(options),
    TGCLOUD_PROJECT_ID: projectOption(options),
    TGCLOUD_KMS_KEY_ID: kmsKeyIdOption(options),
    ...(rateLimiterModule !== undefined ? { TGCLOUD_RATE_LIMITER_MODULE: rateLimiterModule } : {}),
  };
  if (options['data-dir'] !== undefined && options['dsn'] === undefined) {
    effectiveEnv.DATABASE_URL = undefined;
    effectiveEnv.TGCLOUD_SECRETS_DSN = undefined;
  } else if (dsnOption(options)) {
    effectiveEnv.DATABASE_URL = dsnOption(options);
  }
  assertProductionConfig(readConfig(effectiveEnv));
  if (!isLoopbackHost(host) && options['allow-public'] !== true) {
    throw new Error('Refusing a non-loopback bind without --allow-public; put TLS and access controls in front of a public broker');
  }
  return { host, port, rateLimiterModule };
}

function trustedProxyOption(options) {
  const raw = options['trusted-proxy'] ?? process.env.TGCLOUD_TRUSTED_PROXY_ADDRESSES;
  if (raw === undefined) return [];
  const addresses = raw.split(',').map((value) => value.trim()).filter(Boolean);
  if (addresses.length === 0) throw new Error('--trusted-proxy must contain one or more IP addresses');
  return addresses;
}

function rateLimiterModuleOption(options) {
  const value = options['rate-limiter-module'] !== undefined
    ? options['rate-limiter-module']
    : process.env.TGCLOUD_RATE_LIMITER_MODULE;
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0) throw new Error('--rate-limiter-module/TGCLOUD_RATE_LIMITER_MODULE must not be empty');
  return value;
}

async function readSecretFromStdin() {
  if (process.stdin.isTTY) {
    throw new Error('Refusing to read a secret from an interactive terminal; pipe it on stdin (for example, printf %s "$KEY" | tgcloud-secrets set name)');
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    total += chunk.length;
    if (total > MAX_SECRET_BYTES + 2) throw new Error(`Secret value must be at most ${MAX_SECRET_BYTES} bytes`);
    chunks.push(chunk);
  }
  let value;
  try {
    value = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
  } catch {
    throw new Error('Secret value from stdin must contain valid UTF-8');
  }
  value = value.replace(/\r?\n$/, '');
  if (value.length === 0) throw new Error('Secret value from stdin is empty');
  if (Buffer.byteLength(value, 'utf8') > MAX_SECRET_BYTES) throw new Error(`Secret value must be at most ${MAX_SECRET_BYTES} bytes`);
  return value;
}

function printJsonOrText(options, value, text) {
  if (options.json) console.log(JSON.stringify(value, null, 2));
  else console.log(text);
}

async function run(argv) {
  if (argv.length === 0 || argv.includes('--help')) {
    usage();
    return;
  }
  if (argv.includes('--version')) {
    console.log(VERSION);
    return;
  }

  const command = argv[0];
  const { positional, options } = parseArgs(argv.slice(1));
  validateCommandArgs(command, positional, options);
  if (command === 'config-check') {
    try {
      const config = readConfig();
      assertProductionConfig(config);
      printJsonOrText(options, { ok: true, environment: config.environment, production: config.production }, 'Configuration is valid');
    } catch (error) {
      if (options.json) console.log(JSON.stringify({ ok: false, error: error.message }, null, 2));
      else console.error(error.message);
      process.exitCode = 1;
    }
    return;
  }
  if (command === 'migrate-db' || command === 'migration-status') {
    const dsn = options.dsn !== undefined ? options.dsn : dsnOption(options);
    if (dsn === null || dsn === undefined || dsn === '') throw new Error(`${command} requires --dsn or DATABASE_URL/TGCLOUD_SECRETS_DSN`);
    assertDatabaseConfig(readConfig({
      ...process.env,
      DATABASE_URL: dsn,
      TGCLOUD_SECRETS_DSN: undefined,
    }));
    const status = command === 'migrate-db'
      ? await runMigrations({ dsn, dryRun: options['dry-run'] === true })
      : await migrationStatus({ dsn });
    printJsonOrText(options, status, status.map((item) => `${item.version} ${item.name}: ${item.applied ? 'applied' : 'pending'}`).join('\n'));
    return;
  }
  const serveSettings = command === 'serve' ? validateServeOptions(options) : null;
  const store = command === 'migrate' ? null : createStore(options, serveSettings || {});
  const isPgStore = store instanceof PgStore;

  try {
    const orgId = orgOption(options);
    const projectId = projectOption(options);

  if (command === 'init') {
    await store.init();
    if (isPgStore) {
      const maskedDsn = dsnOption(options) ? String(dsnOption(options)).replace(/:\/\/[^@]+@/, '://***@') : 'postgres://***';
      printJsonOrText(options, { dsn: maskedDsn, orgId, projectId }, `Initialized Postgres store for org ${orgId} project ${projectId}`);
    } else {
      printJsonOrText(options, { dataDir: dataDirOption(options) }, `Initialized private secret store in ${dataDirOption(options)}`);
    }
    return;
  }
  if (command === 'set') {
    const name = positional[0];
    if (!name) throw new Error('Usage: tgcloud-secrets set <name>');
    const value = await readSecretFromStdin();
    if (isPgStore) await store.setSecret(name, value, { orgId, projectId });
    else await store.setSecret(name, value);
    printJsonOrText(options, { name, orgId, projectId }, `Stored encrypted secret ${name} for ${orgId}/${projectId}`);
    return;
  }
  if (command === 'list') {
    const secrets = isPgStore ? await store.listSecrets({ orgId, projectId }) : await store.listSecrets();
    if (options.json) console.log(JSON.stringify(secrets, null, 2));
    else if (secrets.length === 0) console.log('No secrets stored.');
    else for (const secret of secrets) console.log(`${secret.name}\t${secret.updatedAt}`);
    return;
  }
  if (command === 'grant') {
    const secretName = positional[0];
    const baseUrl = options['base-url'];
    if (!secretName || !baseUrl) throw new Error('Usage: tgcloud-secrets grant <secret> --base-url <url>');
    let expiresAt = null;
    if (options['expires-at']) {
      if (!isPgStore) throw new Error('--expires-at requires Postgres store (--dsn or DATABASE_URL)');
      const d = new Date(options['expires-at']);
      if (Number.isNaN(d.getTime())) throw new Error('--expires-at must be valid ISO8601');
      expiresAt = d.toISOString();
    }
    const capability = isPgStore ? await store.createCapability({
      secretName,
      baseUrl,
      pathPrefix: valueOption(options, 'path-prefix', '/'),
      methods: valueOption(options, 'method', 'GET'),
      injectHeader: valueOption(options, 'inject-header', 'authorization'),
      injectPrefix: valueOption(options, 'inject-prefix', ''),
      allowHttp: Boolean(options['allow-http']),
      expiresAt,
      orgId,
      projectId,
    }) : await store.createCapability({
      secretName,
      baseUrl,
      pathPrefix: valueOption(options, 'path-prefix', '/'),
      methods: valueOption(options, 'method', 'GET'),
      injectHeader: valueOption(options, 'inject-header', 'authorization'),
      injectPrefix: valueOption(options, 'inject-prefix', ''),
      allowHttp: Boolean(options['allow-http']),
    });
    const output = {
      id: capability.id,
      endpoint: '/v1/fetch',
      capability: capability.token,
      secretName: capability.secretName,
      baseUrl: capability.baseUrl,
      pathPrefix: capability.pathPrefix,
      methods: capability.methods,
      injectHeader: capability.injectHeader,
      injectPrefix: capability.injectPrefix,
      expiresAt: capability.expiresAt || null,
      orgId: capability.orgId || orgId,
      projectId: capability.projectId || projectId,
    };
    if (options.json) console.log(JSON.stringify(output, null, 2));
    else {
      console.log(`Capability ${capability.id} created.`);
      console.log('The capability token is shown once and is revocable; do not commit it to a public repository.');
      console.log(JSON.stringify(output, null, 2));
    }
    return;
  }
  if (command === 'capabilities' || command === 'caps') {
    const capabilities = isPgStore ? await store.listCapabilities({ orgId, projectId }) : await store.listCapabilities();
    if (options.json) console.log(JSON.stringify(capabilities, null, 2));
    else if (capabilities.length === 0) console.log('No capabilities created.');
    else for (const capability of capabilities) console.log(`${capability.id}\t${capability.secretName}\t${capability.methods.join(',')}\t${capability.baseUrl.replace(/\/$/, '')}${capability.pathPrefix}${capability.expiresAt ? '\t' + capability.expiresAt : ''}`);
    return;
  }
  if (command === 'revoke') {
    const id = positional[0];
    if (!id) throw new Error('Usage: tgcloud-secrets revoke <capability-id>');
    const revoked = isPgStore ? await store.revokeCapability(id, { orgId, projectId }) : await store.revokeCapability(id);
    if (!revoked) throw new Error(`Capability not found: ${id}`);
    printJsonOrText(options, { id, revoked: true }, `Revoked capability ${id}`);
    return;
  }
  if (command === 'healthcheck') {
    await store.init();
    if (isPgStore && typeof store.healthCheck === 'function') {
      await store.healthCheck();
      printJsonOrText(options, { ok: true, store: 'postgres', kms: kmsKeyIdOption(options) }, 'Health check passed: Postgres + KMS reachable');
    } else {
      printJsonOrText(options, { ok: true, store: 'file' }, 'Health check passed: file store reachable');
    }
    return;
  }
  if (command === 'migrate') {
    const from = options['from'] !== undefined ? options['from'] : dataDirOption(options);
    const to = options['to'] !== undefined ? options['to'] : dsnOption(options);
    if (!to) throw new Error('migrate requires --to <dsn> (or DATABASE_URL env)');
    const migrationConfig = assertProductionConfig(readConfig({
      ...process.env,
      DATABASE_URL: to,
      TGCLOUD_ORG_ID: orgId,
      TGCLOUD_PROJECT_ID: projectId,
      TGCLOUD_KMS_KEY_ID: kmsKeyIdOption(options),
    }));
    const isDryRun = options['dry-run'] === true || options['dry-run'] === 'true';
    const fileStore = new SecretStore({ dataDir: from });
    const sourceSnapshot = isDryRun ? await fileStore.readExisting() : null;
    if (!isDryRun) await fileStore.init();
    const pgStore = new PgStore({ dsn: to, orgId, projectId, kmsKeyId: kmsKeyIdOption(options), masterKey: process.env.TGCLOUD_MASTER_KEY, maxCapabilityLifetimeMs: migrationConfig.maxCapabilityLifetimeMs });
    try {
      if (!isDryRun) await pgStore.init();
      const existing = await (async () => {
        const client = await pgStore.pool.connect();
        try {
          await client.query('BEGIN READ ONLY');
          await pgStore._setTenantContext(client, orgId, `${orgId}:${projectId}`);
          const result = await client.query(`SELECT name FROM secrets WHERE org_id=$1 AND project_id=$2`, [orgId, `${orgId}:${projectId}`]);
          await client.query('ROLLBACK');
          return new Set(result.rows.map((row) => row.name));
        } catch (error) {
          await client.query('ROLLBACK').catch(() => {});
          throw error;
        } finally {
          client.release();
        }
      })();
      const secrets = sourceSnapshot
        ? Object.entries(sourceSnapshot.secrets).map(([name, value]) => ({ name, updatedAt: value.updatedAt }))
        : await fileStore.listSecrets();
      let migrated = 0;
      let skipped = 0;
      for (const { name } of secrets) {
        if (existing.has(name)) {
          console.log(`Skipped existing secret ${name} (already in Postgres)`);
          skipped++;
          continue;
        }
        if (isDryRun) {
          console.log(`[dry-run] Would migrate secret ${name}`);
          migrated++;
          continue;
        }
        const value = await fileStore.getSecret(name);
        await pgStore.setSecret(name, value, { orgId, projectId });
        console.log(`Migrated secret ${name}`);
        migrated++;
      }
      const caps = sourceSnapshot
        ? Object.values(sourceSnapshot.capabilities)
        : await fileStore.listCapabilities();
      console.log(`Note: capabilities must be re-granted after migration (tokens are hashed, cannot be migrated). Found ${caps.length} capabilities in file store.`);
      if (isDryRun) console.log(`[dry-run] Would migrate ${migrated} secrets, skipped ${skipped}`);
      printJsonOrText(options, { migratedSecrets: migrated, skipped, capabilitiesFound: caps.length, dryRun: isDryRun }, `${isDryRun ? '[dry-run] ' : ''}Migrated ${migrated} secrets to Postgres (skipped ${skipped})`);
    } finally {
      await pgStore.close().catch(() => {});
    }
    return;
  }
  if (command === 'serve') {
    const { host, port } = serveSettings;
    const effectiveEnv = { ...process.env, TGCLOUD_HOST: host };
    const selectedDsn = dsnOption(options);
    if (selectedDsn !== null && selectedDsn !== undefined) effectiveEnv.DATABASE_URL = selectedDsn;
    if (options.org !== undefined) effectiveEnv.TGCLOUD_ORG_ID = orgOption(options);
    if (options.project !== undefined) effectiveEnv.TGCLOUD_PROJECT_ID = projectOption(options);
    if (options['kms-key-id'] !== undefined) effectiveEnv.TGCLOUD_KMS_KEY_ID = kmsKeyIdOption(options);
    assertProductionConfig(readConfig(effectiveEnv));
    if (!isLoopbackHost(host) && options['allow-public'] !== true) throw new Error('Refusing a non-loopback bind without --allow-public; put TLS and access controls in front of a public broker');
    let broker;
    let limiterAdapter;
    const closeLimiter = async () => {
      if (typeof limiterAdapter?.close === 'function') await Promise.resolve(limiterAdapter.close()).catch(() => {});
    };
    try {
      limiterAdapter = await loadRateLimiterBackend(serveSettings.rateLimiterModule);
      broker = createBrokerServer({
        store,
        host,
        port,
        trustedProxyAddresses: trustedProxyOption(options),
        rateLimiterBackend: limiterAdapter?.backend,
      });
      await store.init();
      const address = await broker.listen();
      console.log(`tgcloud-secrets broker listening on http://${address.address === '::' ? '[::]' : address.address}:${address.port} (${isPgStore ? 'postgres' : 'file'} store)`);
      let shuttingDown = false;
      const shutdown = async () => {
        if (shuttingDown) return;
        shuttingDown = true;
        await broker.close().catch(() => {});
        if (isPgStore) await store.close().catch(() => {});
        await closeLimiter();
        process.exit(0);
      };
      process.once('SIGINT', shutdown);
      process.once('SIGTERM', shutdown);
      return new Promise(() => {});
    } catch (error) {
      if (broker) await broker.close().catch(() => {});
      if (isPgStore) await store.close().catch(() => {});
      await closeLimiter();
      throw error;
    }
  }

  throw new Error(`Unknown command: ${command}`);
  } finally {
    // One-shot Postgres commands must release their pool before returning;
    // otherwise idle sockets keep the CLI alive until the pool timeout.
    if (isPgStore && command !== 'serve') await store.close().catch(() => {});
  }
}

run(process.argv.slice(2)).catch((error) => {
  console.error(`error: ${error.message}`);
  process.exitCode = 1;
});
