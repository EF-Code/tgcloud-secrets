import { chmod, link, mkdir, open, readFile, rename, writeFile, lstat, unlink, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import {
  capabilityMatches,
  decryptSecret,
  encryptSecret,
  encodeMasterKey,
  generateMasterKey,
  hashCapability,
  hashCapabilityMetadata,
  capabilityMetadataMatches,
  parseMasterKey,
} from './crypto.js';
import {
  normalizeBaseUrl,
  normalizeInjectHeader,
  normalizeInjectPrefix,
  normalizeMethods,
  normalizePathPrefix,
  isSafeHeaderValue,
} from './policy.js';

const STORE_VERSION = 1;
const SECRET_NAME = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const CAPABILITY_ID = /^cap_[a-f0-9]{20}$/;
// Keep injected values below common HTTP header-size limits while allowing
// ordinary API keys, JWTs, and service credentials.
const MAX_SECRET_BYTES = 8 * 1024;
const LOCK_TIMEOUT_MS = 5_000;
const STALE_LOCK_MS = 5 * 60 * 1_000;
const LOCK_QUARANTINE_PREFIX = '.lock.stale-';

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
    assertCurrentUserOwnership(info, path);
    if ((info.mode & 0o077) !== 0) await chmod(path, 0o700);
  } else {
    await mkdir(path, { recursive: true, mode: 0o700 });
  }
}

async function writePrivateFile(path, contents) {
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  let renamed = false;
  try {
    await writeFile(temporary, contents, { mode: 0o600, flag: 'wx' });
    await chmod(temporary, 0o600);
    await rename(temporary, path);
    renamed = true;
  } finally {
    if (!renamed) await unlink(temporary).catch(() => {});
  }
}

async function createPrivateFile(path, contents) {
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(contents);
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = undefined;
    // link() installs the fully-written file without rename's overwrite
    // semantics. A competing initializer gets EEXIST and keeps its file.
    await link(temporary, path);
  } finally {
    if (handle) await handle.close().catch(() => {});
    await unlink(temporary).catch(() => {});
  }
}

async function ensurePrivateFile(path) {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error(`Refusing to use a non-regular secret file: ${path}`);
  }
  assertCurrentUserOwnership(info, path);
  if ((info.mode & 0o077) !== 0) await chmod(path, 0o600);
}

function assertCurrentUserOwnership(info, path) {
  const currentUid = process.getuid?.();
  if (currentUid !== undefined && info.uid !== currentUid) {
    throw new Error(`Refusing to use a secret path not owned by the current user: ${path}`);
  }
}

function sameFileIdentity(left, right) {
  return left.isFile()
    && !left.isSymbolicLink()
    && left.dev === right.dev
    && left.ino === right.ino;
}

function assertLockFile(info, path) {
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Refusing to use an unsafe lock path: ${path}`);
  assertCurrentUserOwnership(info, path);
}

function isProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code === 'EPERM';
  }
}

async function restoreQuarantinedLock(lockPath, quarantinePath) {
  try {
    // link() never overwrites an existing pathname, unlike rename(). If a
    // waiter installed a newer lock in the meantime, preserve both inodes.
    await link(quarantinePath, lockPath);
    await unlink(quarantinePath);
    return true;
  } catch (error) {
    if (error.code === 'EEXIST') return false;
    throw error;
  }
}

async function reclaimStaleLock(lockPath, expectedIdentity) {
  const quarantinePath = `${lockPath}.stale-${process.pid}-${randomBytes(6).toString('hex')}`;
  try {
    // Moving the observed pathname removes it atomically; only the private
    // quarantine pathname is ever deleted during reclamation.
    await rename(lockPath, quarantinePath);
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }

  try {
    const current = await lstat(quarantinePath);
    let owner;
    try {
      owner = JSON.parse(await readFile(quarantinePath, 'utf8')).pid;
    } catch {
      owner = undefined;
    }
    const stillStale = Date.now() - current.mtimeMs > STALE_LOCK_MS;
    if (sameFileIdentity(current, expectedIdentity) && stillStale && !isProcessAlive(owner)) {
      await unlink(quarantinePath);
      return true;
    }
    await restoreQuarantinedLock(lockPath, quarantinePath);
    return false;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

async function listLockQuarantines(dataDir) {
  try {
    const entries = await readdir(dataDir);
    return entries
      .filter((entry) => entry.startsWith(LOCK_QUARANTINE_PREFIX))
      .map((entry) => join(dataDir, entry));
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
}

async function reapDeadLockQuarantines(dataDir) {
  for (const quarantinePath of await listLockQuarantines(dataDir)) {
    try {
      const info = await lstat(quarantinePath);
      assertLockFile(info, quarantinePath);
      if (Date.now() - info.mtimeMs <= STALE_LOCK_MS) continue;
      let owner;
      try {
        owner = JSON.parse(await readFile(quarantinePath, 'utf8')).pid;
      } catch {
        owner = undefined;
      }
      if (!isProcessAlive(owner)) await reclaimStaleLock(quarantinePath, info);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return listLockQuarantines(dataDir);
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function validateSecretName(name) {
  if (typeof name !== 'string' || !SECRET_NAME.test(name)) {
    throw new Error('Secret name must start with a letter and contain only letters, numbers, ., _, or -');
  }
  return name;
}

function validateCapabilityId(id) {
  if (typeof id !== 'string' || !CAPABILITY_ID.test(id)) throw new Error('Capability ID is invalid');
  return id;
}

function emptyStore() {
  return { version: STORE_VERSION, secrets: {}, capabilities: {} };
}

function validateStoredCapability(candidate) {
  if (typeof candidate.id !== 'string' || !CAPABILITY_ID.test(candidate.id)) return false;
  if (typeof candidate.secretName !== 'string' || !SECRET_NAME.test(candidate.secretName)) return false;
  if (typeof candidate.allowHttp !== 'boolean') return false;
  if (typeof candidate.tokenHash !== 'string') return false;
  try {
    if (normalizeBaseUrl(candidate.baseUrl, { allowHttp: candidate.allowHttp }) !== candidate.baseUrl) return false;
    if (normalizePathPrefix(candidate.pathPrefix) !== candidate.pathPrefix) return false;
    if (JSON.stringify(normalizeMethods(candidate.methods)) !== JSON.stringify(candidate.methods)) return false;
    if (normalizeInjectHeader(candidate.injectHeader) !== candidate.injectHeader) return false;
    if (normalizeInjectPrefix(candidate.injectPrefix) !== candidate.injectPrefix) return false;
  } catch {
    return false;
  }
  return true;
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
      try {
        const encoded = this.suppliedMasterKey !== undefined ? encodeMasterKey(this.suppliedMasterKey) : encodeMasterKey(generateMasterKey());
        await createPrivateFile(this.masterKeyPath, `${encoded}\n`);
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
      }
    }
    await ensurePrivateFile(this.masterKeyPath);
    await this._masterKey();
    if (!(await pathExists(this.storePath))) {
      try {
        await createPrivateFile(this.storePath, `${JSON.stringify(emptyStore(), null, 2)}\n`);
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
      }
    }
    await ensurePrivateFile(this.storePath);
    return this;
  }

  async _masterKey() {
    const raw = (await readFile(this.masterKeyPath, 'utf8')).trim();
    const diskKey = parseMasterKey(raw);
    if (this.suppliedMasterKey !== undefined) {
      const suppliedKey = parseMasterKey(this.suppliedMasterKey);
      if (!timingSafeEqual(diskKey, suppliedKey)) throw new Error('Supplied master key does not match the existing store key');
    }
    return diskKey;
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
    if (
      !parsed || typeof parsed !== 'object' || Array.isArray(parsed)
      || parsed.version !== STORE_VERSION
      || !parsed.secrets || typeof parsed.secrets !== 'object' || Array.isArray(parsed.secrets)
      || !parsed.capabilities || typeof parsed.capabilities !== 'object' || Array.isArray(parsed.capabilities)
    ) {
      throw new Error('Unsupported secret store format');
    }
    return parsed;
  }

  async _writeStore(store) {
    await writePrivateFile(this.storePath, `${JSON.stringify(store, null, 2)}\n`);
  }

  async _acquireWriteLock() {
    const lockPath = join(this.dataDir, '.lock');
    const startedAt = Date.now();
    while (true) {
      // A stale-lock reaper temporarily moves the observed inode into a
      // quarantine pathname. Treat that pathname as the lock still being
      // held; otherwise a contender could enter during the move/restore
      // window and violate mutual exclusion.
      const quarantines = await reapDeadLockQuarantines(this.dataDir);
      if (quarantines.length > 0) {
        if (Date.now() - startedAt >= LOCK_TIMEOUT_MS) throw new Error('Timed out waiting for the secret store lock');
        await wait(25);
        continue;
      }
      let handle;
      try {
        handle = await open(lockPath, 'wx', 0o600);
        await handle.writeFile(`${JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() })}\n`);
        const identity = await handle.stat();
        // A reaper may have moved another inode after the open succeeded.
        // Abandon this candidate if its quarantine marker is visible so no
        // writer proceeds while reclamation is in flight.
        if ((await listLockQuarantines(this.dataDir)).length > 0) {
          const candidate = { handle, lockPath, identity };
          handle = undefined;
          await this._releaseWriteLock(candidate);
          if (Date.now() - startedAt >= LOCK_TIMEOUT_MS) throw new Error('Timed out waiting for the secret store lock');
          await wait(25);
          continue;
        }
        return { handle, lockPath, identity };
      } catch (error) {
        if (handle) await handle.close().catch(() => {});
        if (error.code !== 'EEXIST') throw error;
        try {
          const info = await lstat(lockPath);
          assertLockFile(info, lockPath);
          if (Date.now() - info.mtimeMs > STALE_LOCK_MS) {
            let lockOwner;
            try {
              lockOwner = JSON.parse(await readFile(lockPath, 'utf8')).pid;
            } catch {
              lockOwner = undefined;
            }
            if (!isProcessAlive(lockOwner)) await reclaimStaleLock(lockPath, info);
          }
        } catch (lockError) {
          if (lockError.code !== 'ENOENT') throw lockError;
        }
        if (Date.now() - startedAt >= LOCK_TIMEOUT_MS) throw new Error('Timed out waiting for the secret store lock');
        await wait(25);
      }
    }
  }

  async _releaseWriteLock(lock) {
    await lock.handle.close();
    const lockPaths = [lock.lockPath];
    try {
      const entries = await readdir(this.dataDir);
      for (const entry of entries) {
        if (entry.startsWith('.lock.stale-')) lockPaths.push(join(this.dataDir, entry));
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
    for (const lockPath of lockPaths) {
      try {
        const current = await lstat(lockPath);
        if (sameFileIdentity(current, lock.identity)) await unlink(lockPath);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
    }
  }

  async _withWriteLock(callback) {
    await this.init();
    const lock = await this._acquireWriteLock();
    try {
      return await callback();
    } finally {
      await this._releaseWriteLock(lock);
    }
  }

  async setSecret(name, value) {
    validateSecretName(name);
    if (typeof value !== 'string' || value.length === 0) throw new Error('Secret value must be a non-empty string');
    if (Buffer.byteLength(value, 'utf8') > MAX_SECRET_BYTES) throw new Error(`Secret value must be at most ${MAX_SECRET_BYTES} bytes`);
    if (!isSafeHeaderValue(value)) throw new Error('Secret value must be an HTTP-safe string without unsafe control characters');
    await this._withWriteLock(async () => {
      const store = await this._readStore();
      store.secrets[name] = {
        encrypted: encryptSecret(value, await this._masterKey(), name),
        updatedAt: new Date().toISOString(),
      };
      await this._writeStore(store);
    });
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
    if (!Object.hasOwn(store.secrets, name) || !record) throw new Error(`Secret not found: ${name}`);
    return decryptSecret(record.encrypted, await this._masterKey(), name);
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
    return this._withWriteLock(async () => {
      const store = await this._readStore();
      if (!Object.hasOwn(store.secrets, secretName)) throw new Error(`Secret not found: ${secretName}`);
      const normalizedBaseUrl = normalizeBaseUrl(baseUrl, { allowHttp });
      const normalizedPathPrefix = normalizePathPrefix(pathPrefix);
      const normalizedMethods = normalizeMethods(methods);
      const normalizedHeader = normalizeInjectHeader(injectHeader);
      const normalizedInjectPrefix = normalizeInjectPrefix(injectPrefix);
      if (typeof allowHttp !== 'boolean') throw new Error('allowHttp must be a boolean');
      const key = await this._masterKey();

      const id = `cap_${randomBytes(10).toString('hex')}`;
      const token = `tgscap_${randomBytes(32).toString('base64url')}`;
      const capability = {
        id,
        tokenHash: hashCapability(token),
        secretName,
        baseUrl: normalizedBaseUrl,
        pathPrefix: normalizedPathPrefix,
        methods: normalizedMethods,
        injectHeader: normalizedHeader,
        injectPrefix: normalizedInjectPrefix,
        allowHttp,
        createdAt: new Date().toISOString(),
      };
      capability.metadataMac = hashCapabilityMetadata(capability, key);
      store.capabilities[id] = capability;
      await this._writeStore(store);
      return {
        id,
        token,
        secretName,
        baseUrl: normalizedBaseUrl,
        pathPrefix: normalizedPathPrefix,
        methods: normalizedMethods,
        injectHeader: normalizedHeader,
        injectPrefix: normalizedInjectPrefix,
        allowHttp: Boolean(allowHttp),
      };
    });
  }

  async listCapabilities() {
    const store = await this._readStore();
    return Object.values(store.capabilities).map(({ tokenHash, metadataMac, ...capability }) => capability);
  }

  async revokeCapability(id) {
    validateCapabilityId(id);
    return this._withWriteLock(async () => {
      const store = await this._readStore();
      if (!store.capabilities[id]) return false;
      delete store.capabilities[id];
      await this._writeStore(store);
      return true;
    });
  }

  async resolveCapability(token) {
    if (typeof token !== 'string' || token.length < 16 || token.length > 256) return null;
    const store = await this._readStore();
    let entry;
    const key = await this._masterKey();
    for (const [storedId, candidate] of Object.entries(store.capabilities)) {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) continue;
      if (candidate.id !== storedId) continue;
      if (!validateStoredCapability(candidate)) continue;
      if (!capabilityMatches(token, candidate.tokenHash)) continue;
      if (!capabilityMetadataMatches(candidate, key, candidate.metadataMac)) continue;
      entry = candidate;
      break;
    }
    if (!entry) return null;
    const secret = store.secrets[entry.secretName];
    if (!Object.hasOwn(store.secrets, entry.secretName) || !secret) return null;
    return {
      ...entry,
      secretValue: decryptSecret(secret.encrypted, await this._masterKey(), entry.secretName),
    };
  }
}

export { MAX_SECRET_BYTES, validateSecretName, validateCapabilityId, emptyStore };
