import { chmod, mkdir, readFile, rename, writeFile, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  capabilityMatches,
  decryptSecret,
  encryptSecret,
  encodeMasterKey,
  generateMasterKey,
  hashCapability,
  parseMasterKey,
} from './crypto.js';
import {
  normalizeBaseUrl,
  normalizeInjectHeader,
  normalizeMethods,
  normalizePathPrefix,
} from './policy.js';

const STORE_VERSION = 1;
const SECRET_NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;

async function pathExists(path) {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

async function ensurePrivateDirectory(path) {
  if (await pathExists(path)) {
    const info = await lstat(path);
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error(`Refusing to use a non-directory data path: ${path}`);
    }
    if ((info.mode & 0o077) !== 0) await chmod(path, 0o700);
  } else {
    await mkdir(path, { recursive: true, mode: 0o700 });
  }
}

async function writePrivateFile(path, contents) {
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  await writeFile(temporary, contents, { mode: 0o600, flag: 'wx' });
  await chmod(temporary, 0o600);
  await rename(temporary, path);
}

async function ensurePrivateFile(path) {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`Refusing to use a non-regular secret file: ${path}`);
  }
  if ((info.mode & 0o077) !== 0) await chmod(path, 0o600);
}

function validateSecretName(name) {
  if (typeof name !== 'string' || !SECRET_NAME.test(name)) {
    throw new Error('Secret name must start with a letter and contain only letters, numbers, ., _, or -');
  }
  return name;
}

function emptyStore() {
  return { version: STORE_VERSION, secrets: {}, capabilities: {} };
}

export class SecretStore {
  constructor({ dataDir = '.tgcloud-secrets', masterKey } = {}) {
    this.dataDir = dataDir;
    this.masterKeyPath = join(dataDir, 'master.key');
    this.storePath = join(dataDir, 'store.json');
    this.suppliedMasterKey = masterKey;
  }

  async init() {
    await ensurePrivateDirectory(this.dataDir);
    if (!(await pathExists(this.masterKeyPath))) {
      if (this.suppliedMasterKey) {
        await writePrivateFile(this.masterKeyPath, `${encodeMasterKey(this.suppliedMasterKey)}\n`);
      } else {
        await writePrivateFile(this.masterKeyPath, `${encodeMasterKey(generateMasterKey())}\n`);
      }
    }
    await ensurePrivateFile(this.masterKeyPath);
    await this._masterKey();
    if (!(await pathExists(this.storePath))) {
      await writePrivateFile(this.storePath, `${JSON.stringify(emptyStore(), null, 2)}\n`);
    }
    await ensurePrivateFile(this.storePath);
    return this;
  }

  async _masterKey() {
    if (this.suppliedMasterKey) return parseMasterKey(this.suppliedMasterKey);
    const raw = (await readFile(this.masterKeyPath, 'utf8')).trim();
    return parseMasterKey(raw);
  }

  async _readStore() {
    await this.init();
    const raw = await readFile(this.storePath, 'utf8');
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`Secret store is not valid JSON: ${this.storePath}`);
    }
    if (parsed.version !== STORE_VERSION || !parsed.secrets || !parsed.capabilities) {
      throw new Error('Unsupported secret store format');
    }
    return parsed;
  }

  async _writeStore(store) {
    await writePrivateFile(this.storePath, `${JSON.stringify(store, null, 2)}\n`);
  }

  async setSecret(name, value) {
    validateSecretName(name);
    if (typeof value !== 'string' || value.length === 0) throw new Error('Secret value must be a non-empty string');
    const store = await this._readStore();
    store.secrets[name] = {
      encrypted: encryptSecret(value, await this._masterKey()),
      updatedAt: new Date().toISOString(),
    };
    await this._writeStore(store);
  }

  async listSecrets() {
    const store = await this._readStore();
    return Object.entries(store.secrets).map(([name, value]) => ({
      name,
      updatedAt: value.updatedAt,
    }));
  }

  async getSecret(name) {
    validateSecretName(name);
    const store = await this._readStore();
    const record = store.secrets[name];
    if (!record) throw new Error(`Secret not found: ${name}`);
    return decryptSecret(record.encrypted, await this._masterKey());
  }

  async createCapability({
    secretName,
    baseUrl,
    pathPrefix = '/',
    methods = ['GET'],
    injectHeader = 'authorization',
    injectPrefix = '',
    allowHttp = false,
  }) {
    validateSecretName(secretName);
    const store = await this._readStore();
    if (!store.secrets[secretName]) throw new Error(`Secret not found: ${secretName}`);
    const normalizedBaseUrl = normalizeBaseUrl(baseUrl, { allowHttp });
    const normalizedPathPrefix = normalizePathPrefix(pathPrefix);
    const normalizedMethods = normalizeMethods(methods);
    const normalizedHeader = normalizeInjectHeader(injectHeader);
    if (typeof injectPrefix !== 'string' || injectPrefix.length > 128) {
      throw new Error('Injection prefix must be a string of at most 128 characters');
    }

    const id = `cap_${randomBytes(10).toString('hex')}`;
    const token = `tgscap_${randomBytes(32).toString('base64url')}`;
    store.capabilities[id] = {
      id,
      tokenHash: hashCapability(token),
      secretName,
      baseUrl: normalizedBaseUrl,
      pathPrefix: normalizedPathPrefix,
      methods: normalizedMethods,
      injectHeader: normalizedHeader,
      injectPrefix,
      allowHttp: Boolean(allowHttp),
      createdAt: new Date().toISOString(),
    };
    await this._writeStore(store);
    return {
      id,
      token,
      secretName,
      baseUrl: normalizedBaseUrl,
      pathPrefix: normalizedPathPrefix,
      methods: normalizedMethods,
      injectHeader: normalizedHeader,
      injectPrefix,
      allowHttp: Boolean(allowHttp),
    };
  }

  async listCapabilities() {
    const store = await this._readStore();
    return Object.values(store.capabilities).map(({ tokenHash, ...capability }) => capability);
  }

  async revokeCapability(id) {
    const store = await this._readStore();
    if (!store.capabilities[id]) return false;
    delete store.capabilities[id];
    await this._writeStore(store);
    return true;
  }

  async resolveCapability(token) {
    if (typeof token !== 'string' || token.length < 16 || token.length > 256) return null;
    const store = await this._readStore();
    const entry = Object.values(store.capabilities).find((candidate) => capabilityMatches(token, candidate.tokenHash));
    if (!entry) return null;
    const secret = store.secrets[entry.secretName];
    if (!secret) return null;
    return {
      ...entry,
      secretValue: decryptSecret(secret.encrypted, await this._masterKey()),
    };
  }
}

export { validateSecretName, emptyStore };
