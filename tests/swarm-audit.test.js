import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isPrivateHost, normalizeBaseUrl, resolveUpstreamUrl } from '../src/policy.js';
import { SecretStore } from '../src/store.js';
import { createBrokerServer } from '../src/broker.js';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Swarm audit regression tests - neuromancer/wintermute findings 2026-09-02
