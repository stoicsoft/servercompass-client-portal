import assert from 'node:assert/strict';
import test from 'node:test';
import { PROTOCOL_VERSION, SCHEMA_VERSION, validateLinkPolicy } from '../../client-portal-protocol/index.js';
import { openBrokerDatabase } from '../broker/schema.js';
import { addCounterRates, orderedPowerContainers, redactLogText, scopedContainers } from '../broker/docker.js';
import { Readable } from 'node:stream';
import { cookies, readJson, MAX_BODY_BYTES } from '../shared/http.js';
import { validateBrowserRequest } from '../gateway/security.js';

test('protocol rejects unknown permissions and accepts the scoped baseline', () => {
  const policy = { id: 'link', installationId: 'install', targetStackRef: 'stack', expectedProjectName: 'project', clientLabel: 'Client', tokenHash: 'a'.repeat(64), tokenVersion: 1, expiresAt: Date.now() + 1000, permissions: ['view_status', 'view_metrics'] };
  assert.equal(PROTOCOL_VERSION, 3);
  assert.equal(SCHEMA_VERSION, 3);
  assert.deepEqual(validateLinkPolicy(policy).permissions, ['view_status', 'view_metrics']);
  assert.deepEqual(validateLinkPolicy({ ...policy, permissions: [...policy.permissions, 'start', 'suspend'] }).permissions, ['view_status', 'view_metrics', 'start', 'suspend']);
  assert.throws(() => validateLinkPolicy({ ...policy, permissions: [...policy.permissions, 'shell'] }));
  assert.throws(() => validateLinkPolicy({ ...policy, clientLabel: 'client\nforged' }));
  assert.throws(() => validateLinkPolicy({ ...policy, passcodeHash: 'scrypt$v1$bad$bad' }));
});

test('HTTP helpers cap JSON bodies and ignore malformed cookies', async () => {
  const request = Readable.from([Buffer.alloc(MAX_BODY_BYTES + 1)]);
  await assert.rejects(() => readJson(request), /too large/);
  assert.deepEqual(
    { ...cookies({ headers: { cookie: 'valid=value; malformed=%ZZ; second=ok' } }) },
    { valid: 'value', second: 'ok' }
  );
});

test('broker schema persists operation, link, session, audit, metrics, and rate-limit state', () => {
  const db = openBrokerDatabase(':memory:');
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all().map((row) => row.name);
  assert.deepEqual(['runtime_metadata', 'applied_operations', 'links', 'link_revisions', 'sessions', 'audit_events', 'resource_points_1m', 'resource_points_5m', 'stack_snapshots', 'rate_limit_checkpoints', 'action_operations'].every((name) => tables.includes(name)), true);
  assert.equal(db.prepare("SELECT value FROM runtime_metadata WHERE key='actions_enabled'").get().value, 'false');
  assert.equal(db.prepare("SELECT value FROM runtime_metadata WHERE key='lifecycle_enabled'").get().value, 'false');
  assert.equal(db.prepare("SELECT value FROM runtime_metadata WHERE key='schema_version'").get().value, '3');
  assert.deepEqual(['storage_bytes', 'block_read_bytes', 'block_write_bytes'].every((name) => db.prepare('PRAGMA table_info(resource_points_1m)').all().some((column) => column.name === name)), true);
  assert.equal(db.prepare('PRAGMA table_info(action_operations)').all().some((column) => column.name === 'action_kind'), true);
  db.close();
});

test('network rates handle first samples, elapsed time, and Docker counter resets', () => {
  const points = addCounterRates([
    { at: 1_000, rxBytes: 100, txBytes: 200 },
    { at: 3_000, rxBytes: 500, txBytes: 800 },
    { at: 5_000, rxBytes: 10, txBytes: 20 },
  ]);
  assert.equal(points[0].rxBytesPerSecond, null);
  assert.equal(points[1].rxBytesPerSecond, 200);
  assert.equal(points[1].txBytesPerSecond, 300);
  assert.equal(points[2].rxBytesPerSecond, null);
  assert.equal(points[2].txBytesPerSecond, null);
});

test('whole-stack power ordering starts dependencies first and suspends apps first', () => {
  const app = { Id: 'app', Labels: { 'servercompass.role': 'app' } };
  const dependency = { Id: 'database', Labels: { 'servercompass.role': 'database' } };
  assert.deepEqual(orderedPowerContainers([app, dependency], 'start').map((item) => item.Id), ['database', 'app']);
  assert.deepEqual(orderedPowerContainers([dependency, app], 'stop').map((item) => item.Id), ['app', 'database']);
});

test('Docker scope requires both immutable stack and Compose project labels', () => {
  const containers = [
    { Id: 'a', Labels: { 'servercompass.stack_id': 'stack-a', 'com.docker.compose.project': 'project-a' } },
    { Id: 'b', Labels: { 'servercompass.stack_id': 'stack-b', 'com.docker.compose.project': 'project-b' } },
    { Id: 'job', Labels: { 'servercompass.stack_id': 'stack-a', 'com.docker.compose.project': 'project-a', 'com.docker.compose.oneoff': 'True' } },
  ];
  assert.deepEqual(scopedContainers(containers, 'stack-a', 'project-a').map((item) => item.Id), ['a']);
  assert.throws(() => scopedContainers(containers, 'stack-a', 'project-b'), /Compose project/);
  assert.throws(() => scopedContainers(containers, 'missing', 'project-a'), /No containers/);
});

test('gateway enforces configured Host and same-origin mutations while allowing loopback preview', () => {
  const publicOrigin = 'https://clients.example.com';
  assert.equal(validateBrowserRequest({ host: 'clients.example.com', origin: publicOrigin, method: 'POST' }, publicOrigin).valid, true);
  assert.equal(validateBrowserRequest({ host: 'clients.example.com', method: 'GET' }, publicOrigin).valid, true);
  assert.equal(validateBrowserRequest({ host: 'localhost:41800', origin: 'http://localhost:41800', method: 'POST' }, publicOrigin).valid, true);
  assert.equal(validateBrowserRequest({ host: 'evil.example', origin: 'https://evil.example', method: 'POST' }, publicOrigin).valid, false);
  assert.equal(validateBrowserRequest({ host: 'clients.example.com', origin: 'https://evil.example', method: 'POST' }, publicOrigin).valid, false);
  assert.equal(validateBrowserRequest({ host: 'clients.example.com', method: 'POST' }, publicOrigin).valid, false);
});

test('log redaction removes known secrets, token patterns, ANSI, control bytes, and oversized lines', () => {
  const secret = 'super-secret-value';
  const output = redactLogText(`\u001b[31merror\u001b[0m\nTOKEN=abc123\npassword: hunter2\npostgres://admin:db-password@example.test/app\n${secret}\u0000\n${'x'.repeat(5000)}`, [secret]);
  assert.equal(output.includes(secret), false);
  assert.equal(output.includes('abc123'), false);
  assert.equal(output.includes('hunter2'), false);
  assert.equal(output.includes('db-password'), false);
  assert.equal(output.includes('\u001b'), false);
  assert.equal(output.includes('\u0000'), false);
  assert.equal(output.split('\n').at(-1).length, 4096);
});
