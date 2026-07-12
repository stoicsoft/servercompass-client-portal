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
