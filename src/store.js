import { constants } from 'node:fs';
import { link, mkdir, open, rename, lstat, unlink, readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { parseStrictJson } from './json.js';
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
const MAX_STORE_BYTES = 16 * 1024 * 1024;
const PRIVATE_READ_FLAGS = process.platform === 'win32'
  ? 'r'
  : constants.O_RDONLY | (constants.O_NOFOLLOW || 0);

function openPrivateRead(path) {
  return open(path, PRIVATE_READ_FLAGS);
}

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
    const linfo = await lstat(path);
    if (!linfo.isDirectory() || linfo.isSymbolicLink()) {
      throw new Error(`Refusing to use a non-directory data path: ${path}`);
    }
    const handle = await openPrivateRead(path);
    try {
      const info = await handle.stat();
      // TOCTOU: verify fd and path are same inode (O_NOFOLLOW equivalent) — for dirs check dev/ino
      const same = linfo.dev === info.dev && linfo.ino === info.ino && !linfo.isSymbolicLink() && !info.isSymbolicLink();
      if (!same) throw new Error(`Refusing to use a non-regular secret file (race): ${path}`);
      assertCurrentUserOwnership(info, path);
      if ((info.mode & 0o077) !== 0) {
        await handle.chmod(0o700);
        await handle.sync();
        await syncDirectory(path);
      }
    } finally {
      await handle.close().catch(() => {});
    }
  } else {
    await mkdir(path, { recursive: true, mode: 0o700 });
    await assertExistingPrivateDirectory(path);
  }
}

async function writePrivateFile(path, contents) {
  const temporary = `${path}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  let handle;
  let renamed = false;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(contents);
    await handle.chmod(0o600);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, path);
    await syncDirectory(dirname(path));
    renamed = true;
  } finally {
    if (handle) await handle.close().catch(() => {});
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
    await syncDirectory(dirname(path));
  } finally {
    if (handle) await handle.close().catch(() => {});
    await unlink(temporary).catch(() => {});
  }
}

async function syncDirectory(path) {
  // Windows does not support opening a directory for fsync in the same way as
  // POSIX filesystems. The normal file sync still provides the useful local
  // guarantee there; production durable stores are expected to run on POSIX.
  if (process.platform === 'win32') return;
  const handle = await openPrivateRead(path);
  try {
    await handle.sync();
  } finally {
    await handle.close().catch(() => {});
  }
}

async function ensurePrivateFile(path) {
  const linfo = await lstat(path);
  if (!linfo.isFile() || linfo.isSymbolicLink()) {
    throw new Error(`Refusing to use a non-regular secret file: ${path}`);
  }
  const handle = await openPrivateRead(path);
  try {
    const info = await handle.stat();
    if (!sameFileIdentity(linfo, info)) throw new Error(`Refusing to use a non-regular secret file (race): ${path}`);
    assertCurrentUserOwnership(info, path);
    if ((info.mode & 0o077) !== 0) {
      await handle.chmod(0o600);
      await handle.sync();
      await syncDirectory(dirname(path));
    }
  } finally {
    await handle.close().catch(() => {});
  }
}

async function assertExistingPrivateDirectory(path) {
  const info = await lstat(path);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`Refusing to use a non-directory data path: ${path}`);
  assertCurrentUserOwnership(info, path);
  if ((info.mode & 0o077) !== 0) throw new Error(`Secret data directory must be private: ${path}`);
}

async function assertExistingPrivateFile(path) {
  const info = await lstat(path);
  if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Refusing to use a non-regular secret file: ${path}`);
  assertCurrentUserOwnership(info, path);
  if ((info.mode & 0o077) !== 0) throw new Error(`Secret file must be private: ${path}`);
}

async function readPrivateFile(path, maximumBytes) {
  const observed = await lstat(path);
  if (!observed.isFile() || observed.isSymbolicLink()) throw new Error(`Refusing to use a non-regular secret file: ${path}`);
  assertCurrentUserOwnership(observed, path);
  if ((observed.mode & 0o077) !== 0) throw new Error(`Secret file must be private: ${path}`);
  if (maximumBytes !== undefined && observed.size > maximumBytes) throw new Error(`Secret file is too large: ${path}`);
  const handle = await openPrivateRead(path);
  try {
    const actual = await handle.stat();
    if (!sameFileIdentity(observed, actual)) throw new Error(`Refusing to use a replaced secret file: ${path}`);
    assertCurrentUserOwnership(actual, path);
    if ((actual.mode & 0o077) !== 0) throw new Error(`Secret file must be private: ${path}`);
    if (maximumBytes !== undefined && actual.size > maximumBytes) throw new Error(`Secret file is too large: ${path}`);
    const readLimit = maximumBytes === undefined ? MAX_STORE_BYTES : maximumBytes;
    if (actual.size > readLimit) throw new Error(`Secret file is too large: ${path}`);
    const buffer = Buffer.alloc(readLimit);
    let bytesRead = 0;
    while (bytesRead < buffer.length) {
      const result = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
    }
    const final = await handle.stat();
    if (!sameFileIdentity(observed, final)) throw new Error(`Refusing to use a replaced secret file: ${path}`);
    assertCurrentUserOwnership(final, path);
    if ((final.mode & 0o077) !== 0) throw new Error(`Secret file must be private: ${path}`);
    if (final.size > readLimit || final.size !== bytesRead) throw new Error(`Secret file changed while being read: ${path}`);
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close().catch(() => {});
  }
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
  if ((info.mode & 0o077) !== 0) throw new Error(`Secret lock must be private: ${path}`);
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

async function readLockOwner(path) {
  try {
    const parsed = parseStrictJson(await readPrivateFile(path, 1_024), {
      maxBytes: 1_024,
      maxDepth: 3,
      maxFields: 8,
      maxArrayItems: 4,
      maxStringBytes: 256,
    });
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) && Number.isSafeInteger(parsed.pid)
      ? parsed.pid
      : undefined;
  } catch {
    return undefined;
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
    const owner = await readLockOwner(quarantinePath);
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
      const owner = await readLockOwner(quarantinePath);
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
  if (name === '__proto__' || name === 'constructor' || name === 'prototype') {
    throw new Error('Secret name is reserved');
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

function validateStoredSecret(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)
    || typeof candidate.updatedAt !== 'string') return false;
  const keys = Object.keys(candidate);
  if (keys.length !== 2 || !keys.includes('encrypted') || !keys.includes('updatedAt')
    || Number.isNaN(new Date(candidate.updatedAt).getTime())) return false;
  const record = candidate.encrypted;
  return Boolean(record && typeof record === 'object' && !Array.isArray(record)
    && record.version === 2
    && record.algorithm === 'aes-256-gcm'
    && typeof record.iv === 'string'
    && typeof record.tag === 'string'
    && typeof record.ciphertext === 'string');
}

function validateStoredCapability(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return false;
  if (typeof candidate.id !== 'string' || !CAPABILITY_ID.test(candidate.id)) return false;
  if (typeof candidate.secretName !== 'string' || !SECRET_NAME.test(candidate.secretName)
    || ['__proto__', 'constructor', 'prototype'].includes(candidate.secretName)) return false;
  if (typeof candidate.allowHttp !== 'boolean') return false;
  if (typeof candidate.tokenHash !== 'string' || !/^[a-f0-9]{64}$/.test(candidate.tokenHash)) return false;
  if (typeof candidate.metadataMac !== 'string' || !/^[a-f0-9]{64}$/.test(candidate.metadataMac)) return false;
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
    const raw = (await readPrivateFile(this.masterKeyPath, 1_024)).toString('utf8').trim();
    const diskKey = parseMasterKey(raw);
    if (this.suppliedMasterKey !== undefined) {
      const suppliedKey = parseMasterKey(this.suppliedMasterKey);
      if (!timingSafeEqual(diskKey, suppliedKey)) throw new Error('Supplied master key does not match the existing store key');
    }
    return diskKey;
  }

  async _readStore({ initialize = true } = {}) {
    if (initialize) await this.init();
    else {
      // Dry-run callers must not create directories, keys, stores, or repair
      // permissions. Read-only validation still rejects symlinks and foreign
      // ownership before any data is parsed.
      await assertExistingPrivateDirectory(this.dataDir);
      await assertExistingPrivateFile(this.masterKeyPath);
      await assertExistingPrivateFile(this.storePath);
      await this._masterKey();
    }
    const raw = await readPrivateFile(this.storePath, MAX_STORE_BYTES);
    if (raw.byteLength > MAX_STORE_BYTES) throw new Error(`Secret store is too large: ${this.storePath}`);
    let parsed;
    try {
      parsed = parseStrictJson(raw, { maxBytes: MAX_STORE_BYTES, maxDepth: 20, maxFields: 100_000, maxArrayItems: 10_000, maxStringBytes: MAX_STORE_BYTES });
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
    // Reject proto-pollution keys on read (including prototype pollution via __proto__)
    const secretsProto = Object.getPrototypeOf(parsed.secrets);
    const capsProto = Object.getPrototypeOf(parsed.capabilities);
    if (secretsProto !== Object.prototype || capsProto !== Object.prototype) {
      throw new Error('Unsupported secret store format: prototype pollution');
    }
    for (const [key, value] of Object.entries(parsed.secrets)) {
      if (!SECRET_NAME.test(key) || key === '__proto__' || key === 'constructor' || key === 'prototype' || !validateStoredSecret(value)) {
        throw new Error(`Unsupported secret store format: invalid secret ${key}`);
      }
    }
    for (const [key, value] of Object.entries(parsed.capabilities)) {
      if (!CAPABILITY_ID.test(key) || !validateStoredCapability(value) || value.id !== key) {
        throw new Error(`Unsupported secret store format: invalid capability ${key}`);
      }
    }
    return parsed;
  }

  async readExisting() {
    return this._readStore({ initialize: false });
  }

  async _writeStore(store) {
    await writePrivateFile(this.storePath, `${JSON.stringify(store, null, 2)}\n`);
  }

  async _acquireWriteLock() {
    const lockPath = join(this.dataDir, '.lock');
    const startedAt = Date.now();
    while (true) {
      const quarantines = await reapDeadLockQuarantines(this.dataDir);
      // Only stale quarantines indicate a reclamation that is still in flight;
      // fresh quarantines (e.g., an attacker-created file) must not block
      // writers for the full stale window.
      const staleQuarantines = [];
      for (const qp of quarantines) {
        try {
          const info = await lstat(qp);
          if (Date.now() - info.mtimeMs > STALE_LOCK_MS) staleQuarantines.push(qp);
        } catch {
          // Quarantine disappeared between list and stat — treat as gone.
        }
      }
      if (staleQuarantines.length > 0) {
        if (Date.now() - startedAt >= LOCK_TIMEOUT_MS) throw new Error('Timed out waiting for the secret store lock');
        await wait(25);
        continue;
      }
      if (quarantines.length > 100) throw new Error('Too many stale lock quarantines; data directory may be under attack or need cleanup');
      let handle;
      try {
        handle = await open(lockPath, 'wx', 0o600);
        await handle.writeFile(`${JSON.stringify({ pid: process.pid, createdAt: new Date().toISOString() })}\n`);
        const identity = await handle.stat();
        const postQuarantines = await listLockQuarantines(this.dataDir);
        const postStale = [];
        for (const qp of postQuarantines) {
          try {
            const info = await lstat(qp);
            if (Date.now() - info.mtimeMs > STALE_LOCK_MS) postStale.push(qp);
          } catch {}
        }
        if (postStale.length > 0) {
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
            const lockOwner = await readLockOwner(lockPath);
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

// lock quarantine now counts stale only
