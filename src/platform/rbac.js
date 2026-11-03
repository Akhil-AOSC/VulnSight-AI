'use strict';

// Roles -> permissions. Checked in the service layer on every call, so authorization does not
// depend on the HTTP layer.
const PERMISSIONS = {
  viewer: ['repos:read', 'findings:read', 'reports:read', 'scans:read'],
  developer: ['repos:read', 'findings:read', 'reports:read', 'scans:read', 'scans:run', 'findings:write', 'ai:use', 'teams:read'],
  admin: [
    'repos:read', 'findings:read', 'reports:read', 'scans:read', 'scans:run', 'findings:write', 'ai:use', 'teams:read',
    'repos:write', 'providers:manage', 'members:manage', 'teams:manage', 'audit:read', 'org:settings',
  ],
};
PERMISSIONS.owner = [...PERMISSIONS.admin, 'org:delete'];

const ROLES = Object.keys(PERMISSIONS);

class ForbiddenError extends Error {
  constructor(message = 'You do not have permission to do that') { super(message); this.status = 403; }
}
class NotFoundError extends Error {
  constructor(message = 'Not found') { super(message); this.status = 404; }
}
class ValidationError extends Error {
  constructor(message) { super(message); this.status = 400; }
}
class AuthError extends Error {
  constructor(message = 'Authentication required') { super(message); this.status = 401; }
}

function can(role, permission) {
  return !!PERMISSIONS[role] && PERMISSIONS[role].includes(permission);
}

function assertCan(role, permission) {
  if (!can(role, permission)) throw new ForbiddenError();
}

module.exports = { PERMISSIONS, ROLES, can, assertCan, ForbiddenError, NotFoundError, ValidationError, AuthError };
