import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AUTHORIZATION_MATRIX, AuthenticationError, AuthorizationError, authorize, createAuthorizationBoundary, normalizePrincipal } from '../src/auth.js';

const resource = { orgId: 'org1', projectId: 'project1' };

test('authorization matrix has default-deny role boundaries', () => {
  for (const [role, permissions] of Object.entries(AUTHORIZATION_MATRIX)) {
    const principal = normalizePrincipal({ authenticated: true, subject: `${role}@example.test`, roles: [role], ...resource, mfaSatisfied: true });
    for (const permission of new Set(Object.values(AUTHORIZATION_MATRIX).flat())) {
      const allowed = permissions.includes(permission);
      if (allowed) assert.doesNotThrow(() => authorize(principal, permission, resource));
      else assert.throws(() => authorize(principal, permission, resource), AuthorizationError);
    }
  }
});

test('authorization rejects unauthenticated, cross-tenant, and unsafe principals', () => {
  assert.throws(() => normalizePrincipal({ authenticated: false, subject: 'alice', roles: ['auditor'], ...resource }), AuthenticationError);
  const principal = { authenticated: true, subject: 'alice@example.test', roles: ['auditor'], ...resource, mfaSatisfied: true };
  assert.throws(() => authorize(principal, 'audit:read', { orgId: 'other', projectId: 'project1' }), AuthorizationError);
  assert.throws(() => authorize(principal, 'audit:read', { orgId: 'org1', projectId: 'other' }), AuthorizationError);
  assert.throws(() => normalizePrincipal({ authenticated: true, subject: 'alice', roles: ['unknown'], ...resource }), AuthenticationError);
});

test('destructive authorization requires MFA or independent approval', () => {
  const principal = { authenticated: true, subject: 'alice@example.test', roles: ['organization_owner'], ...resource };
  assert.throws(() => authorize(principal, 'tenant:revoke', { ...resource, destructive: true }), AuthorizationError);
  assert.doesNotThrow(() => authorize(principal, 'tenant:revoke', { ...resource, destructive: true, approvedBy: 'security@example.test' }));
  assert.throws(() => authorize({ ...principal, mfaSatisfied: true }, 'tenant:revoke', { ...resource, destructive: true, approvedBy: 'alice@example.test' }), AuthorizationError);
});

test('authorization boundary preserves the authenticated principal with custom authorizers', async () => {
  const principal = { authenticated: true, subject: 'alice@example.test', roles: ['auditor'], ...resource };
  const boundary = createAuthorizationBoundary({
    authenticate: async () => principal,
    authorize: async () => true,
  });
  assert.deepEqual(await boundary({}, 'audit:read', resource), normalizePrincipal(principal));
});

test('authorization boundary awaits and enforces an asynchronous denial', async () => {
  const principal = { authenticated: true, subject: 'alice@example.test', roles: ['auditor'], ...resource };
  let checked = false;
  const boundary = createAuthorizationBoundary({
    authenticate: async () => principal,
    authorize: async () => {
      await new Promise((resolve) => setImmediate(resolve));
      checked = true;
      return false;
    },
  });
  await assert.rejects(() => boundary({}, 'audit:read', resource), AuthorizationError);
  assert.equal(checked, true);
});
