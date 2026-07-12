const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

function hostUrl(rawHost) {
  if (typeof rawHost !== 'string' || rawHost.length === 0 || rawHost.length > 512) return null;
  try {
    const parsed = new URL(`http://${rawHost}`);
    if (parsed.username || parsed.password || parsed.pathname !== '/' || parsed.search || parsed.hash) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function validateBrowserRequest({ host, origin, method }, publicOrigin) {
  let configured;
  try {
    configured = new URL(publicOrigin);
  } catch {
    return { valid: false, reason: 'invalid_configuration' };
  }
  if (configured.protocol !== 'https:' || configured.pathname !== '/' || configured.search || configured.hash) {
    return { valid: false, reason: 'invalid_configuration' };
  }

  const requestedHost = hostUrl(host);
  if (!requestedHost) return { valid: false, reason: 'invalid_host' };
  const hostname = requestedHost.hostname.toLowerCase();
  const loopback = LOOPBACK_HOSTS.has(hostname);
  const publicHost = hostname === configured.hostname.toLowerCase()
    && (!requestedHost.port || requestedHost.port === '443');
  if (!loopback && !publicHost) return { valid: false, reason: 'invalid_host' };

  const requestOrigin = publicHost
    ? configured.origin
    : `http://${host}`;
  let normalizedOrigin = null;
  if (origin) {
    try {
      normalizedOrigin = new URL(origin).origin;
    } catch {
      return { valid: false, reason: 'invalid_origin' };
    }
    if (normalizedOrigin !== requestOrigin) return { valid: false, reason: 'invalid_origin' };
  }
  if (MUTATING_METHODS.has(String(method).toUpperCase()) && !normalizedOrigin) {
    return { valid: false, reason: 'missing_origin' };
  }

  return {
    valid: true,
    requestOrigin,
    forwardedProto: loopback ? 'http' : 'https',
  };
}
