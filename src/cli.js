#!/usr/bin/env node

import { MAX_SECRET_BYTES, SecretStore } from './store.js';
import { createBrokerServer } from './broker.js';
import { isLoopbackHost } from './policy.js';
import { join } from 'node:path';

const VERSION = '0.1.0';

function usage() {
  console.log(`tgcloud-secrets ${VERSION}

Capability-scoped secret injection for Telegram Serverless bots.

Commands:
  init                                      Create a private local store
  set <name>                                Read a secret from stdin and store it encrypted
  list                                      List secret names (never values)
  grant <secret> --base-url <url>           Create a scoped capability
  capabilities                              List capability metadata (never tokens)
  revoke <capability-id>                   Revoke a capability
  serve                                     Run the local/companion broker

Global options:
  --data-dir <path>                         Store directory (default: OS user-data directory)

Grant options:
  --path-prefix <path>                      Allowed upstream path (default: /)
  --method <methods>                        Comma-separated methods (default: GET)
  --inject-header <name>                   Header that receives the secret (default: authorization)
  --inject-prefix <text>                   Prefix such as "Bearer " (default: empty)
  --allow-http                              Allow HTTP; use only for local development

Serve options:
  --host <host>                             Bind host (default: 127.0.0.1)
  --port <port>                             Bind port (default: 8787)
  --trusted-proxy <ips>                     Trust X-Forwarded-For from these proxy IPs for rate limiting
  --allow-public                            Acknowledge that a non-loopback bind needs external TLS/access controls

Examples:
  printf %s "$OPENAI_API_KEY" | tgcloud-secrets set openai
  tgcloud-secrets grant openai --base-url https://api.openai.com --path-prefix /v1/ --method POST --inject-prefix "Bearer "
  tgcloud-secrets serve --host 127.0.0.1 --port 8787
`);
}

function parseArgs(args) {
  const positional = [];
  const options = {};
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    const withoutPrefix = arg.slice(2);
    if (withoutPrefix === 'help' || withoutPrefix === 'version') {
      options[withoutPrefix] = true;
      continue;
    }
    if (withoutPrefix === 'allow-http' || withoutPrefix === 'allow-public' || withoutPrefix === 'json') {
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
    if (!next || next.startsWith('--')) throw new Error(`Option --${withoutPrefix} requires a value`);
    if (Object.hasOwn(options, withoutPrefix)) throw new Error(`Option --${withoutPrefix} was provided more than once`);
    options[withoutPrefix] = next;
    index += 1;
  }
  return { positional, options };
}

const ALLOWED_OPTIONS = {
  init: new Set(['data-dir', 'json']),
  set: new Set(['data-dir', 'json']),
  list: new Set(['data-dir', 'json']),
  grant: new Set(['data-dir', 'json', 'base-url', 'path-prefix', 'method', 'inject-header', 'inject-prefix', 'allow-http']),
  capabilities: new Set(['data-dir', 'json']),
  caps: new Set(['data-dir', 'json']),
  revoke: new Set(['data-dir', 'json']),
  serve: new Set(['data-dir', 'host', 'port', 'trusted-proxy', 'allow-public']),
};

function validateCommandArgs(command, positional, options) {
  if (!ALLOWED_OPTIONS[command]) throw new Error(`Unknown command: ${command}`);
  for (const name of Object.keys(options)) {
    if (!ALLOWED_OPTIONS[command].has(name)) throw new Error(`Unknown option for ${command}: --${name}`);
  }
  for (const name of ['json', 'allow-http', 'allow-public']) {
    if (options[name] !== undefined && options[name] !== true) throw new Error(`--${name} is a flag and does not take a value`);
  }
  if (options['data-dir'] !== undefined && options['data-dir'].length === 0) throw new Error('--data-dir must not be empty');

  const expectedPositionals = { init: 0, set: 1, list: 0, grant: 1, capabilities: 0, caps: 0, revoke: 1, serve: 0 }[command];
  if (positional.length !== expectedPositionals) throw new Error(`Unexpected positional arguments for ${command}`);
}

function valueOption(options, name, fallback) {
  return options[name] === undefined ? fallback : options[name];
}

function dataDirOption(options) {
  if (options['data-dir'] !== undefined) return options['data-dir'];
  if (process.env.TGCLOUD_SECRETS_DATA_DIR) return process.env.TGCLOUD_SECRETS_DATA_DIR;
  if (process.platform === 'win32') return join(process.env.APPDATA || process.env.LOCALAPPDATA || '.', 'tgcloud-secrets');
  if (process.env.XDG_DATA_HOME) return join(process.env.XDG_DATA_HOME, 'tgcloud-secrets');
  if (process.env.HOME) return join(process.env.HOME, '.local', 'share', 'tgcloud-secrets');
  return '.tgcloud-secrets';
}

function trustedProxyOption(options) {
  if (options['trusted-proxy'] === undefined) return [];
  const addresses = options['trusted-proxy'].split(',').map((value) => value.trim()).filter(Boolean);
  if (addresses.length === 0) throw new Error('--trusted-proxy must contain one or more IP addresses');
  return addresses;
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
  const value = Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
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
  const store = new SecretStore({ dataDir: dataDirOption(options) });

  if (command === 'init') {
    await store.init();
    printJsonOrText(options, { dataDir: dataDirOption(options) }, `Initialized private secret store in ${dataDirOption(options)}`);
    return;
  }
  if (command === 'set') {
    const name = positional[0];
    if (!name) throw new Error('Usage: tgcloud-secrets set <name>');
    const value = await readSecretFromStdin();
    await store.setSecret(name, value);
    printJsonOrText(options, { name }, `Stored encrypted secret ${name}`);
    return;
  }
  if (command === 'list') {
    const secrets = await store.listSecrets();
    if (options.json) console.log(JSON.stringify(secrets, null, 2));
    else if (secrets.length === 0) console.log('No secrets stored.');
    else for (const secret of secrets) console.log(`${secret.name}\t${secret.updatedAt}`);
    return;
  }
  if (command === 'grant') {
    const secretName = positional[0];
    const baseUrl = options['base-url'];
    if (!secretName || !baseUrl) throw new Error('Usage: tgcloud-secrets grant <secret> --base-url <url>');
    const capability = await store.createCapability({
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
    const capabilities = await store.listCapabilities();
    if (options.json) console.log(JSON.stringify(capabilities, null, 2));
    else if (capabilities.length === 0) console.log('No capabilities created.');
    else for (const capability of capabilities) console.log(`${capability.id}\t${capability.secretName}\t${capability.methods.join(',')}\t${capability.baseUrl.replace(/\/$/, '')}${capability.pathPrefix}`);
    return;
  }
  if (command === 'revoke') {
    const id = positional[0];
    if (!id) throw new Error('Usage: tgcloud-secrets revoke <capability-id>');
    const revoked = await store.revokeCapability(id);
    if (!revoked) throw new Error(`Capability not found: ${id}`);
    printJsonOrText(options, { id, revoked: true }, `Revoked capability ${id}`);
    return;
  }
  if (command === 'serve') {
    await store.init();
    const host = valueOption(options, 'host', '127.0.0.1');
    const port = Number(valueOption(options, 'port', '8787'));
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Port must be an integer from 1 to 65535');
    if (!isLoopbackHost(host) && options['allow-public'] !== true) throw new Error('Refusing a non-loopback bind without --allow-public; put TLS and access controls in front of a public broker');
    const broker = createBrokerServer({ store, host, port, trustedProxyAddresses: trustedProxyOption(options) });
    const address = await broker.listen();
    console.log(`tgcloud-secrets broker listening on http://${address.address === '::' ? '[::]' : address.address}:${address.port}`);
    const shutdown = async () => {
      await broker.close();
      process.exit(0);
    };
    process.once('SIGINT', shutdown);
    process.once('SIGTERM', shutdown);
    return new Promise(() => {});
  }

  throw new Error(`Unknown command: ${command}`);
}

run(process.argv.slice(2)).catch((error) => {
  console.error(`error: ${error.message}`);
  process.exitCode = 1;
});
