import { timingSafeEqual } from 'node:crypto';

export const MAX_BODY_BYTES = 64 * 1024;

export function json(response, status, body, headers = {}) {
  const data = Buffer.from(JSON.stringify(body));
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': data.length,
    'cache-control': 'no-store',
    ...headers,
  });
  response.end(data);
}

export async function readJson(request) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) throw new Error('Request body too large');
    chunks.push(chunk);
  }
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

export function safeEqual(left, right) {
  const leftBuffer = Buffer.from(String(left));
  const rightBuffer = Buffer.from(String(right));
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

export function resolveClientAddress(forwardedFor, peerAddress, trustedHops = 1) {
  const peer = typeof peerAddress === 'string' && peerAddress.trim() ? peerAddress.trim() : 'unknown';
  const hops = Number.isInteger(trustedHops) && trustedHops >= 0 ? trustedHops : 1;
  // hops === 0 means no proxy is trusted to set X-Forwarded-For, so only the
  // real TCP peer is authoritative.
  if (hops === 0) return peer;
  const entries = String(forwardedFor ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  // Standard "trust proxy = N" semantics: the client address is the entry the
  // outermost trusted proxy inserted (the hops-th value from the right).
  // Anything further left is caller-supplied and must never be trusted. A chain
  // shorter than the trusted hop count means the request arrived from closer
  // than the deployment expects, so fall back to the authoritative TCP peer.
  const index = entries.length - hops;
  return index >= 0 ? entries[index] : peer;
}

export function cookies(request) {
  const result = Object.create(null);
  const header = String(request.headers.cookie ?? '').slice(0, 8 * 1024);
  for (const rawPart of header.split(';')) {
    const part = rawPart.trim();
    const separator = part.indexOf('=');
    if (!part || separator <= 0) continue;
    try {
      const key = decodeURIComponent(part.slice(0, separator));
      const value = decodeURIComponent(part.slice(separator + 1));
      if (key) result[key] = value;
    } catch {
      // Ignore malformed percent-encoding in individual cookies.
    }
  }
  return result;
}
