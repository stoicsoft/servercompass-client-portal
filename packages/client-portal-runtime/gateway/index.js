import http from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Transform } from 'node:stream';
import { MAX_BODY_BYTES, resolveClientAddress } from '../shared/http.js';
import { validateBrowserRequest, parsePublicOrigins } from './security.js';

const port = Number(process.env.PORT ?? 4100);
const brokerUrl = new URL(process.env.PORTAL_BROKER_URL ?? 'http://broker:4101');
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be a valid TCP port');
if (
  brokerUrl.protocol !== 'http:' ||
  brokerUrl.username ||
  brokerUrl.password ||
  (brokerUrl.pathname !== '' && brokerUrl.pathname !== '/') ||
  brokerUrl.search ||
  brokerUrl.hash
) {
  throw new Error('PORTAL_BROKER_URL must be an unauthenticated HTTP URL');
}
const gatewayToken = process.env.PORTAL_GATEWAY_TOKEN ?? (
  process.env.PORTAL_GATEWAY_TOKEN_FILE
    ? readFileSync(process.env.PORTAL_GATEWAY_TOKEN_FILE, 'utf8').trim()
    : ''
);
if (gatewayToken.length < 32) throw new Error('PORTAL_GATEWAY_TOKEN must be at least 32 characters');
const publicOrigin = process.env.PORTAL_PUBLIC_ORIGIN ?? '';
if (!publicOrigin) throw new Error('PORTAL_PUBLIC_ORIGIN is required');
// Additional client-portal hostnames served by this one gateway. Each entry must
// be an HTTPS origin (scheme + host, no port/path/query/fragment). This lets a
// single server front several branded portal hostnames (e.g. one per client);
// leaving it unset keeps the single-hostname behavior. PORTAL_PUBLIC_ORIGIN is
// always the primary origin and is included automatically.
const additionalOrigins = (process.env.PORTAL_PUBLIC_ORIGINS ?? '')
  .split(/[\s,]+/)
  .map((value) => value.trim())
  .filter(Boolean);
const publicOrigins = [publicOrigin, ...additionalOrigins];
if (!parsePublicOrigins(publicOrigins)) throw new Error('PORTAL_PUBLIC_ORIGIN / PORTAL_PUBLIC_ORIGINS must all be HTTPS origins without a port, path, query, or fragment');
const protocolVersion = Number(process.env.PORTAL_PROTOCOL_VERSION ?? 0);
if (!Number.isInteger(protocolVersion) || protocolVersion < 1) throw new Error('PORTAL_PROTOCOL_VERSION is required');
// Number of trusted reverse-proxy hops in front of the gateway. Every supported
// topology (managed Traefik, external nginx/Caddy/CloudPanel, or a host-local
// proxy in front of the loopback port) places exactly one proxy ahead of the
// gateway, so the default is 1. The fronting proxy MUST set or append
// X-Forwarded-For; only the entry that proxy inserts is treated as the client
// address, defeating client-supplied X-Forwarded-For spoofing of rate-limit and
// audit source attribution.
const trustedProxyHops = (() => {
  const raw = process.env.PORTAL_TRUSTED_PROXY_HOPS;
  if (raw === undefined || raw === '') return 1;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 0 || value > 8) throw new Error('PORTAL_TRUSTED_PROXY_HOPS must be an integer between 0 and 8');
  return value;
})();
const html = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'portal.html'));
const javascript = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'portal.js'));
const stylesheet = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'portal.css'));

const securityHeaders = {
  'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'cross-origin-opener-policy': 'same-origin',
  'cache-control': 'no-store',
};

function proxy(request, response) {
  const browserRequest = validateBrowserRequest(
    { host: request.headers.host, origin: request.headers.origin, method: request.method },
    publicOrigins
  );
  if (!browserRequest.valid) {
    response.writeHead(403, { ...securityHeaders, 'content-type': 'application/json' });
    response.end(JSON.stringify({ error: 'Invalid request origin' }));
    return;
  }
  const declaredLength = Number(request.headers['content-length'] ?? 0);
  if (!Number.isFinite(declaredLength) || declaredLength < 0 || declaredLength > MAX_BODY_BYTES) {
    response.writeHead(413, { ...securityHeaders, 'content-type': 'application/json' });
    response.end(JSON.stringify({ error: 'Request body too large' }));
    return;
  }

  const forwardedFor = resolveClientAddress(request.headers['x-forwarded-for'], request.socket.remoteAddress, trustedProxyHops);
  const headers = {
    'content-type': request.headers['content-type'] ?? 'application/json',
    'x-portal-gateway-token': gatewayToken,
    'x-forwarded-for': forwardedFor,
    'x-forwarded-proto': browserRequest.forwardedProto,
    'x-forwarded-host': request.headers.host,
    'x-portal-request-origin': browserRequest.requestOrigin,
    'x-portal-origin-valid': '1',
    'x-csrf-token': request.headers['x-csrf-token'],
    'x-idempotency-key': request.headers['x-idempotency-key'],
    cookie: request.headers.cookie,
  };
  for (const key of Object.keys(headers)) if (headers[key] === undefined) delete headers[key];
  const upstream = http.request({
    hostname: brokerUrl.hostname,
    port: brokerUrl.port,
    path: request.url,
    method: request.method,
    headers,
  }, (upstreamResponse) => {
    response.writeHead(upstreamResponse.statusCode ?? 502, {
      ...securityHeaders,
      'content-type': upstreamResponse.headers['content-type'] ?? 'application/json',
      ...(upstreamResponse.headers['set-cookie'] ? { 'set-cookie': upstreamResponse.headers['set-cookie'] } : {}),
      ...(upstreamResponse.headers['retry-after'] ? { 'retry-after': upstreamResponse.headers['retry-after'] } : {}),
    });
    upstreamResponse.pipe(response);
  });
  upstream.on('error', () => {
    if (response.writableEnded) return;
    response.writeHead(502, { ...securityHeaders, 'content-type': 'application/json' });
    response.end(JSON.stringify({ error: 'Portal temporarily unavailable' }));
  });

  let receivedBytes = 0;
  const limiter = new Transform({
    transform(chunk, _encoding, callback) {
      receivedBytes += chunk.length;
      if (receivedBytes > MAX_BODY_BYTES) {
        callback(new Error('Request body too large'));
      } else {
        callback(null, chunk);
      }
    },
  });
  limiter.on('error', () => {
    upstream.destroy();
    if (!response.headersSent) {
      response.writeHead(413, { ...securityHeaders, 'content-type': 'application/json' });
      response.end(JSON.stringify({ error: 'Request body too large' }));
    }
  });
  request.pipe(limiter).pipe(upstream);
}

const server = http.createServer((request, response) => {
  const url = new URL(request.url ?? '/', 'http://gateway');
  if (url.pathname.startsWith('/api/')) return proxy(request, response);
  if (url.pathname === '/portal.js') {
    response.writeHead(200, { ...securityHeaders, 'content-type': 'text/javascript; charset=utf-8' });
    return response.end(javascript);
  }
  if (url.pathname === '/portal.css') {
    response.writeHead(200, { ...securityHeaders, 'content-type': 'text/css; charset=utf-8' });
    return response.end(stylesheet);
  }
  if (url.pathname === '/healthz') {
    response.writeHead(200, { ...securityHeaders, 'content-type': 'application/json' });
    return response.end(JSON.stringify({ healthy: true, protocolVersion, buildDigest: process.env.PORTAL_BUILD_DIGEST ?? null }));
  }
  response.writeHead(200, { ...securityHeaders, 'content-type': 'text/html; charset=utf-8' });
  return response.end(html);
});
server.headersTimeout = 15_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 64;
server.listen(port, '0.0.0.0', () => console.log(`[portal-gateway] listening on ${port}`));
