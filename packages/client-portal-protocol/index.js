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

export const DEFAULT_BRANDING = Object.freeze({
  name: 'Application status',
  logoDataUrl: null,
  primaryColor: '#2563EB',
});

const LOGO_DATA_URL = /^data:image\/(?:png|jpeg|webp);base64,[A-Za-z0-9+/]+={0,2}$/;
const MAX_LOGO_DATA_URL_LENGTH = 48 * 1024;

export function validateBranding(value, fallbackName = DEFAULT_BRANDING.name) {
  if (value == null) return { ...DEFAULT_BRANDING, name: fallbackName };
  if (typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid branding');
  const allowedKeys = new Set(['name', 'logoDataUrl', 'primaryColor']);
  if (Object.keys(value).some((key) => !allowedKeys.has(key))) throw new Error('Unknown branding field');

  const name = typeof value.name === 'string' ? value.name.trim() : fallbackName;
  if (!name || name.length > 60 || /[\0\r\n]/.test(name)) throw new Error('Invalid branding name');

  const primaryColor = value.primaryColor ?? DEFAULT_BRANDING.primaryColor;
  if (typeof primaryColor !== 'string' || !/^#[0-9A-Fa-f]{6}$/.test(primaryColor)) {
    throw new Error('Invalid branding color');
  }

  const logoDataUrl = value.logoDataUrl ?? null;
  if (
    logoDataUrl !== null &&
    (typeof logoDataUrl !== 'string' ||
      logoDataUrl.length > MAX_LOGO_DATA_URL_LENGTH ||
      !LOGO_DATA_URL.test(logoDataUrl))
  ) {
    throw new Error('Invalid branding logo');
  }

  return { name, logoDataUrl, primaryColor: primaryColor.toUpperCase() };
}

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
  return {
    ...value,
    permissions,
    branding: validateBranding(value.branding, value.clientLabel.trim()),
  };
}
