export const PROTOCOL_VERSION = 3;
export const SCHEMA_VERSION = 3;
export const PERMISSIONS = Object.freeze([
  'view_status',
  'view_metrics',
  'view_logs',
  'restart',
  'start',
  'suspend',
]);

export function validateLinkPolicy(value) {
  if (!value || typeof value !== 'object') throw new Error('Policy is required');
  const requiredStrings = ['id', 'installationId', 'targetStackRef', 'expectedProjectName', 'clientLabel', 'tokenHash'];
  for (const key of requiredStrings) {
    if (typeof value[key] !== 'string' || !value[key].trim()) throw new Error(`Invalid ${key}`);
  }
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(value.id)) throw new Error('Invalid id');
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(value.installationId)) throw new Error('Invalid installationId');
  if (value.targetStackRef.length > 256 || /[\0\r\n]/.test(value.targetStackRef)) throw new Error('Invalid targetStackRef');
  if (value.expectedProjectName.length > 256 || /[\0\r\n]/.test(value.expectedProjectName)) throw new Error('Invalid expectedProjectName');
  if (value.clientLabel.length > 200 || /[\0\r\n]/.test(value.clientLabel)) throw new Error('Invalid clientLabel');
  if (!/^[a-f0-9]{64}$/.test(value.tokenHash)) throw new Error('Invalid tokenHash');
  if (value.passcodeHash != null && !/^scrypt\$v1\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{43}$/.test(value.passcodeHash)) {
    throw new Error('Invalid passcodeHash');
  }
  if (!Number.isInteger(value.tokenVersion) || value.tokenVersion < 1) throw new Error('Invalid tokenVersion');
  if (!Number.isInteger(value.expiresAt) || value.expiresAt <= Date.now()) throw new Error('Invalid expiresAt');
  if (!Array.isArray(value.permissions)) throw new Error('Invalid permissions');
  const permissions = [...new Set(value.permissions)];
  if (permissions.some((permission) => !PERMISSIONS.includes(permission))) throw new Error('Unknown permission');
  if (!permissions.includes('view_status') || !permissions.includes('view_metrics')) {
    throw new Error('Status and metrics permissions are required');
  }
  return { ...value, permissions };
}
