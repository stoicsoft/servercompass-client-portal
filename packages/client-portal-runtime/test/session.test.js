import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import vm from 'node:vm';
import test from 'node:test';
import { openBrokerDatabase } from '../broker/schema.js';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const pause = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

async function reservePort() {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  const port = typeof address === 'object' && address ? address.port : 0;
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function waitForBroker(url, adminToken, child, output) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Broker exited before startup:\n${output()}`);
    try {
      const response = await fetch(`${url}/admin/health`, {
        headers: { authorization: `Bearer ${adminToken}` },
      });
      if (response.ok) return;
    } catch {
      // The listener may not be ready yet.
    }
    await pause(50);
  }
  throw new Error(`Broker did not become ready:\n${output()}`);
}

test('broker restores an HttpOnly-cookie session and rotates its CSRF secret', { timeout: 15_000 }, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'servercompass-portal-session-'));
  const databasePath = join(directory, 'portal.db');
  const port = await reservePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const adminToken = 'admin-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  const gatewayToken = 'gateway-token-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
  const sessionSecret = 'session-secret-cccccccccccccccccccccccccccccccc';
  const sessionId = 'd'.repeat(43);
  const oldCsrf = 'old-csrf-token';
  const expiresAt = Date.now() + 60 * 60_000;

  const database = openBrokerDatabase(databasePath);
  database.prepare(`INSERT INTO links (
    id, installation_id, target_stack_ref, target_project_name, client_label,
    token_hash, token_version, passcode_hash, permissions, expires_at,
    revoked_at, revision, created_at, updated_at
  ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, ?, ?, ?)`).run(
    'link', 'installation', 'stack', 'project', 'Client', 'e'.repeat(64), 1,
    JSON.stringify(['view_status', 'view_metrics', 'restart']), expiresAt, 1, Date.now(), Date.now()
  );
  database.prepare(`INSERT INTO sessions (
    id_hash, link_id, token_version, csrf_hash, permission_ceiling, expires_at, revoked_at
  ) VALUES (?, ?, ?, ?, NULL, ?, NULL)`).run(sha256(sessionId), 'link', 1, sha256(oldCsrf), expiresAt);
  database.close();

  const runtimeDirectory = fileURLToPath(new URL('../', import.meta.url));
  const child = spawn(process.execPath, ['broker/index.js'], {
    cwd: runtimeDirectory,
    env: {
      ...process.env,
      PORT: String(port),
      PORTAL_ADMIN_TOKEN: adminToken,
      PORTAL_GATEWAY_TOKEN: gatewayToken,
      PORTAL_SESSION_SECRET: sessionSecret,
      PORTAL_DB_PATH: databasePath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let childOutput = '';
  const capture = (chunk) => { childOutput = `${childOutput}${chunk}`.slice(-8_192); };
  child.stdout.on('data', capture);
  child.stderr.on('data', capture);
  t.after(async () => {
    if (child.exitCode === null) {
      const exited = once(child, 'exit');
      child.kill('SIGTERM');
      await Promise.race([exited, pause(1_000)]);
      if (child.exitCode === null) child.kill('SIGKILL');
    }
    await rm(directory, { recursive: true, force: true });
  });

  await waitForBroker(baseUrl, adminToken, child, () => childOutput);
  const signature = createHmac('sha256', sessionSecret).update(sessionId).digest('hex');
  const headers = {
    'content-type': 'application/json',
    'x-portal-gateway-token': gatewayToken,
    'x-portal-origin-valid': '1',
    'x-forwarded-for': '203.0.113.7',
    cookie: `__Host-scp_session=${sessionId}.${signature}`,
  };
  const restored = await fetch(`${baseUrl}/api/session/restore`, {
    method: 'POST',
    headers,
    body: '{}',
  });
  assert.equal(restored.status, 200);
  const restoredBody = await restored.json();
  assert.equal(restoredBody.authenticated, true);
  assert.equal(restoredBody.expiresAt, expiresAt);
  assert.match(restoredBody.csrf, /^[A-Za-z0-9_-]{32}$/);
  assert.notEqual(restoredBody.csrf, oldCsrf);

  const verificationDatabase = openBrokerDatabase(databasePath);
  const storedSession = verificationDatabase.prepare('SELECT csrf_hash FROM sessions WHERE id_hash=?').get(sha256(sessionId));
  verificationDatabase.close();
  assert.equal(storedSession.csrf_hash, sha256(restoredBody.csrf));
  assert.notEqual(storedSession.csrf_hash, sha256(oldCsrf));

  const malformed = await fetch(`${baseUrl}/api/session/restore`, {
    method: 'POST',
    headers: { ...headers, cookie: '__Host-scp_session=malformed' },
    body: '{}',
  });
  assert.equal(malformed.status, 401);
  assert.deepEqual(await malformed.json(), { error: 'Link invalid or unavailable' });

  for (let attempt = 1; attempt < 30; attempt += 1) {
    const repeated = await fetch(`${baseUrl}/api/session/restore`, {
      method: 'POST',
      headers,
      body: '{}',
    });
    assert.equal(repeated.status, 200);
  }
  const rateLimited = await fetch(`${baseUrl}/api/session/restore`, {
    method: 'POST',
    headers,
    body: '{}',
  });
  assert.equal(rateLimited.status, 429);
  assert.equal(rateLimited.headers.get('retry-after'), '60');
});

function fakeNode() {
  return {
    attributes: {},
    dataset: {},
    disabled: false,
    hidden: false,
    listeners: new Map(),
    textContent: '',
    value: '',
    addEventListener(type, listener) { this.listeners.set(type, listener); },
    append() {},
    replaceChildren() {},
    setAttribute(name, value) { this.attributes[name] = value; },
  };
}

test('browser restores the cookie session and uses its rotated CSRF without storing capabilities', async () => {
  const source = await readFile(new URL('../gateway/portal.js', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\b(?:localStorage|sessionStorage)\b/);

  const nodes = new Map();
  const nodeFor = (selector) => {
    if (!nodes.has(selector)) nodes.set(selector, fakeNode());
    return nodes.get(selector);
  };
  const requests = [];
  const dashboard = {
    clientLabel: 'Client',
    permissions: ['view_status', 'view_metrics', 'restart'],
    snapshot: {
      health: 'healthy', running: 1, total: 1, uptimeSeconds: 60,
      updatedAt: Date.now(), services: [],
    },
    metrics: {
      cpuPercent: 1, memoryBytes: 1, memoryLimit: 2, rxBytes: 3, txBytes: 4,
      rxBytesPerSecond: 0, txBytesPerSecond: 0, storageBytes: 5,
      blockReadBytes: 6, blockWriteBytes: 7,
    },
    history: [],
    source: { stale: false, lastSuccessfulAt: Date.now(), errorCode: null },
    backup: { status: 'owner_managed', reason: 'Owner managed' },
    httpMetrics: { reason: 'Unavailable' },
  };
  const response = (body) => ({ ok: true, status: 200, json: async () => body });
  const context = {
    AbortSignal,
    URLSearchParams,
    console,
    crypto: { randomUUID: () => 'restored-action-id' },
    document: {
      querySelector: nodeFor,
      createElement: () => fakeNode(),
    },
    fetch: async (path, options = {}) => {
      requests.push({ path, options });
      if (path === '/api/session/restore') return response({ authenticated: true, csrf: 'rotated-csrf', expiresAt: Date.now() + 60_000 });
      if (path === '/api/dashboard') return response(dashboard);
      if (path === '/api/restart') return response({ outcomes: [] });
      throw new Error(`Unexpected request: ${path}`);
    },
    history: { replaceState() {} },
    location: { hash: '', pathname: '/', search: '' },
    window: {
      clearInterval() {},
      confirm: () => true,
      setInterval: () => 1,
    },
  };
  vm.runInNewContext(source, context, { filename: 'portal.js' });

  for (let attempt = 0; attempt < 20 && !requests.some(({ path }) => path === '/api/dashboard'); attempt += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.deepEqual(requests.slice(0, 2).map(({ path }) => path), ['/api/session/restore', '/api/dashboard']);
  assert.equal(requests.some(({ path }) => path === '/api/session/exchange'), false);

  const restart = nodeFor('#restart').listeners.get('click');
  assert.equal(typeof restart, 'function');
  await restart();
  const actionRequest = requests.find(({ path }) => path === '/api/restart');
  assert.equal(actionRequest.options.headers['x-csrf-token'], 'rotated-csrf');
  assert.equal(actionRequest.options.headers['x-idempotency-key'], 'restored-action-id');
});
