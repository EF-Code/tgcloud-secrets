const ROLE_PERMISSIONS = Object.freeze({
  organization_owner: Object.freeze([
    'tenant:read', 'tenant:revoke', 'secret:read', 'secret:write', 'secret:delete',
    'capability:issue', 'capability:revoke', 'capability:rotate', 'audit:read',
    'kms:rotate', 'breakglass:use', 'tenant:offboard',
  ]),
  secret_administrator: Object.freeze(['secret:read', 'secret:write', 'secret:delete']),
  capability_issuer: Object.freeze(['capability:issue', 'capability:rotate']),
  capability_revoker: Object.freeze(['capability:revoke']),
  auditor: Object.freeze(['tenant:read', 'audit:read']),
  service_workload: Object.freeze(['proxy:use']),
});

const ID = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
const SUBJECT = /^[A-Za-z0-9][A-Za-z0-9@._:/-]{0,255}$/;

function normalizeStepUpAt(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== 'string' || value.length === 0 || value.length > 64) throw new AuthenticationError();
  const timestamp = new Date(value);
  if (Number.isNaN(timestamp.getTime())) throw new AuthenticationError();
  return timestamp.toISOString();
}

function validateId(value, label) {
  if (typeof value !== 'string' || !ID.test(value) || value.includes(':')) throw new Error(`${label} is invalid`);
  return value;
}

export const AUTHORIZATION_MATRIX = ROLE_PERMISSIONS;

export class AuthorizationError extends Error {
  constructor(message = 'Forbidden') {
    super(message);
    this.name = 'AuthorizationError';
    this.statusCode = 403;
    this.publicCode = 'forbidden';
  }
}

export class AuthenticationError extends Error {
  constructor(message = 'Unauthenticated') {
    super(message);
    this.name = 'AuthenticationError';
    this.statusCode = 401;
    this.publicCode = 'unauthenticated';
  }
}

export function normalizePrincipal(principal) {
  if (!principal || typeof principal !== 'object' || Array.isArray(principal)) throw new AuthenticationError();
  if (principal.authenticated !== true) throw new AuthenticationError();
  if (typeof principal.subject !== 'string' || !SUBJECT.test(principal.subject)) throw new AuthenticationError();
  if (!Array.isArray(principal.roles) || principal.roles.length === 0) throw new AuthenticationError();
  const roles = [...new Set(principal.roles)];
  if (roles.some((role) => !Object.hasOwn(ROLE_PERMISSIONS, role))) throw new AuthenticationError();
  let orgId = null;
  let projectId = null;
  try {
    orgId = principal.orgId === undefined || principal.orgId === null ? null : validateId(principal.orgId, 'principal.orgId');
    projectId = principal.projectId === undefined || principal.projectId === null ? null : validateId(principal.projectId, 'principal.projectId');
  } catch {
    throw new AuthenticationError();
  }
  if (projectId !== null && orgId === null) throw new AuthenticationError();
  const approvedBy = principal.approvedBy === undefined || principal.approvedBy === null ? null : principal.approvedBy;
  if (approvedBy !== null && (typeof approvedBy !== 'string' || !SUBJECT.test(approvedBy))) throw new AuthenticationError();
  return Object.freeze({
    subject: principal.subject,
    roles: Object.freeze(roles),
    orgId,
    projectId,
    authenticated: true,
    mfaSatisfied: principal.mfaSatisfied === true,
    stepUpAt: normalizeStepUpAt(principal.stepUpAt),
    // This value may only be supplied by the trusted authentication/approval
    // adapter. Public request fields must never be treated as approval.
    approvedBy,
    workload: principal.workload === true,
  });
}

export function hasPermission(principal, permission) {
  const normalized = normalizePrincipal(principal);
  return normalized.roles.some((role) => ROLE_PERMISSIONS[role].includes(permission));
}

export function authorize(principal, permission, { orgId, projectId, destructive = false, approvedBy } = {}) {
  const normalized = normalizePrincipal(principal);
  if (typeof permission !== 'string' || !/^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$/.test(permission)) throw new AuthorizationError();
  if (!hasPermission(normalized, permission)) throw new AuthorizationError();
  if (orgId !== undefined && orgId !== null) {
    validateId(orgId, 'resource.orgId');
    if (normalized.orgId !== orgId) throw new AuthorizationError();
  }
  if (projectId !== undefined && projectId !== null) {
    if (orgId === undefined || orgId === null) throw new AuthorizationError();
    validateId(projectId, 'resource.projectId');
    if (normalized.projectId !== null && normalized.projectId !== projectId) throw new AuthorizationError();
    if (normalized.orgId === null || (orgId !== undefined && normalized.orgId !== orgId)) throw new AuthorizationError();
  }
  const effectiveApproval = approvedBy ?? normalized.approvedBy;
  if (destructive && !normalized.mfaSatisfied && !effectiveApproval) throw new AuthorizationError('Step-up authentication or independent approval is required');
  if (effectiveApproval !== undefined && effectiveApproval !== null
    && (typeof effectiveApproval !== 'string' || !SUBJECT.test(effectiveApproval) || effectiveApproval === normalized.subject)) {
    throw new AuthorizationError('Independent approval is invalid');
  }
  return normalized;
}

export function createAuthorizationBoundary({ authenticate, authorize: authorizeFn = authorize } = {}) {
  if (typeof authenticate !== 'function') throw new Error('An external authentication adapter is required');
  if (typeof authorizeFn !== 'function') throw new Error('An authorization function is required');
  return async function authenticateAndAuthorize(request, permission, resource) {
    const principal = normalizePrincipal(await authenticate(request));
    // Authorization is a side-effecting decision, not an identity transform.
    // Always return the authenticated principal so a custom authorizer cannot
    // accidentally replace the trusted identity with a boolean or user input.
    const decision = await authorizeFn(principal, permission, resource);
    if (decision === false) throw new AuthorizationError();
    return principal;
  };
}

export { validateId };
