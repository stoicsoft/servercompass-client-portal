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

export function parsePublicOrigins(publicOrigins) {
  const raw = Array.isArray(publicOrigins) ? publicOrigins : [publicOrigins];
  const configured = [];
  const seen = new Set();
  for (const value of raw) {
    if (typeof value !== 'string' || !value.trim()) continue;
    let url;
    try {
      url = new URL(value.trim());
    } catch {
      return null;
    }
    if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || url.port) return null;
    const hostname = url.hostname.toLowerCase();
    if (seen.has(hostname)) continue;
    seen.add(hostname);
    configured.push(url);
  }
  return configured.length ? configured : null;
}

export function validateBrowserRequest({ host, origin, method }, publicOrigins) {
  const configured = parsePublicOrigins(publicOrigins);
  if (!configured) return { valid: false, reason: 'invalid_configuration' };

  const requestedHost = hostUrl(host);
  if (!requestedHost) return { valid: false, reason: 'invalid_host' };
  const hostname = requestedHost.hostname.toLowerCase();
  const loopback = LOOPBACK_HOSTS.has(hostname);
  const matched = requestedHost.port && requestedHost.port !== '443'
    ? undefined
    : configured.find((url) => url.hostname.toLowerCase() === hostname);
  if (!loopback && !matched) return { valid: false, reason: 'invalid_host' };

  const requestOrigin = matched
    ? matched.origin
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
