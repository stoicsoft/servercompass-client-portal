import http from 'node:http';
import { createHash, createHmac, randomBytes, randomUUID, scrypt, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { promisify } from 'node:util';
import { PROTOCOL_VERSION, SCHEMA_VERSION, validateLinkPolicy } from '@servercompass/client-portal-protocol';
import { openBrokerDatabase } from './schema.js';
import {
  getStackLogs,
  getStackMetrics,
  getStackSnapshot,
  addCounterRates,
  restartStack,
  startStack,
  suspendStack,
} from './docker.js';
import { cookies, json, readJson, safeEqual } from '../shared/http.js';

const port = Number(process.env.PORT ?? 4101);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT must be a valid TCP port');
const secret = (name) => process.env[name] ?? (process.env[`${name}_FILE`] ? readFileSync(process.env[`${name}_FILE`], 'utf8').trim() : '');
const adminToken = secret('PORTAL_ADMIN_TOKEN');
const gatewayToken = secret('PORTAL_GATEWAY_TOKEN');
const sessionSecret = secret('PORTAL_SESSION_SECRET');
if ([adminToken, gatewayToken, sessionSecret].some((value) => value.length < 32)) {
  throw new Error('Portal runtime secrets must each be at least 32 characters');
}
const db = openBrokerDatabase(process.env.PORTAL_DB_PATH ?? '/data/portal.db');
const scryptAsync = promisify(scrypt);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const sourceDigest = (value) => createHmac('sha256', sessionSecret).update(value).digest('hex');
const sessionSignature = (sessionId) => createHmac('sha256', sessionSecret).update(sessionId).digest('hex');
const genericAuthError = (response) => json(response, 401, { error: 'Link invalid or unavailable' });

async function collectStack(stackRef, expectedProjectName) {
  const attemptedAt = Date.now();
  try {
    const [snapshot, metrics] = await Promise.all([
      getStackSnapshot(stackRef, expectedProjectName),
      getStackMetrics(stackRef, expectedProjectName),
    ]);
    const bucketAt = Math.floor(attemptedAt / 60_000) * 60_000;
    db.transaction(() => {
      db.prepare(`INSERT OR REPLACE INTO resource_points_1m (stack_ref,bucket_at,cpu_percent,memory_bytes,memory_limit,rx_bytes,tx_bytes,storage_bytes,block_read_bytes,block_write_bytes,running,total) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`)
        .run(stackRef, bucketAt, metrics.cpuPercent, metrics.memoryBytes, metrics.memoryLimit, metrics.rxBytes, metrics.txBytes, metrics.storageBytes, metrics.blockReadBytes, metrics.blockWriteBytes, snapshot.running, snapshot.total);
      db.prepare(`INSERT INTO stack_snapshots (stack_ref,snapshot_json,metrics_json,last_success_at,last_attempt_at,last_error_code)
        VALUES (?,?,?,?,?,NULL)
        ON CONFLICT(stack_ref) DO UPDATE SET snapshot_json=excluded.snapshot_json,metrics_json=excluded.metrics_json,last_success_at=excluded.last_success_at,last_attempt_at=excluded.last_attempt_at,last_error_code=NULL`)
        .run(stackRef, JSON.stringify(snapshot), JSON.stringify(metrics), attemptedAt, attemptedAt);
    })();
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    const errorCode = message.includes('authorized stack') || message.includes('Compose project')
      ? 'PORTAL_SCOPE_MISMATCH'
      : 'PORTAL_METRICS_UNAVAILABLE';
    db.prepare(`INSERT INTO stack_snapshots (stack_ref,snapshot_json,metrics_json,last_success_at,last_attempt_at,last_error_code)
      VALUES (?,NULL,NULL,NULL,?,?)
      ON CONFLICT(stack_ref) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,last_error_code=excluded.last_error_code`)
      .run(stackRef, attemptedAt, errorCode);
    throw error;
  }
}

let collectionRunning = false;
async function runCollector() {
  const stacks = db.prepare('SELECT DISTINCT target_stack_ref AS stack_ref,target_project_name AS project_name FROM links WHERE revoked_at IS NULL AND expires_at>?').all(Date.now());
  for (const { stack_ref: stackRef, project_name: projectName } of stacks) {
    try { await collectStack(stackRef, projectName); } catch { /* cached health carries the named failure */ }
  }
  const fiveMinuteFloor = Math.floor(Date.now() / 300_000) * 300_000;
  db.exec(`
    INSERT OR REPLACE INTO resource_points_5m (
      stack_ref,bucket_at,cpu_percent,memory_bytes,memory_limit,rx_bytes,tx_bytes,storage_bytes,block_read_bytes,block_write_bytes,running,total,sample_count
    )
    SELECT stack_ref,(bucket_at / 300000) * 300000,AVG(cpu_percent),AVG(memory_bytes),AVG(memory_limit),
      MAX(rx_bytes),MAX(tx_bytes),AVG(storage_bytes),MAX(block_read_bytes),MAX(block_write_bytes),MIN(running),MAX(total),COUNT(*)
    FROM resource_points_1m
    WHERE bucket_at >= ${fiveMinuteFloor - 10 * 60_000}
    GROUP BY stack_ref,(bucket_at / 300000) * 300000;
  `);
  db.prepare('DELETE FROM resource_points_1m WHERE bucket_at<?').run(Date.now() - 24 * 60 * 60_000);
  db.prepare('DELETE FROM resource_points_5m WHERE bucket_at<?').run(Date.now() - 7 * 24 * 60 * 60_000);
  db.prepare('DELETE FROM sessions WHERE expires_at<?').run(Date.now() - 24 * 60 * 60_000);
  db.prepare('DELETE FROM preview_grants WHERE expires_at<?').run(Date.now());
  db.prepare('DELETE FROM rate_limit_checkpoints WHERE resets_at<?').run(Date.now());
  db.prepare('DELETE FROM audit_events WHERE created_at<?').run(Date.now() - 90 * 24 * 60 * 60_000);
  db.prepare('DELETE FROM action_operations WHERE created_at<?').run(Date.now() - 90 * 24 * 60 * 60_000);
  db.prepare('DELETE FROM applied_operations WHERE applied_at<?').run(Date.now() - 90 * 24 * 60 * 60_000);
}
const collector = setInterval(() => {
  if (collectionRunning) return;
  collectionRunning = true;
  void runCollector()
    .catch(() => { /* the health endpoint reports collection failures */ })
    .finally(() => { collectionRunning = false; });
}, 60_000);
collector.unref();
void runCollector().catch(() => { /* per-stack cache records the failure */ });

function audit(linkId, eventType, outcome, detail = {}, request) {
  const source = String(request?.headers['x-forwarded-for'] ?? request?.socket.remoteAddress ?? '').split(',')[0].trim();
  db.prepare(`INSERT INTO audit_events (id, link_id, event_type, outcome, detail_json, source_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(randomUUID(), linkId ?? null, eventType, outcome, JSON.stringify(detail), source ? sourceDigest(source) : null, Date.now());
}

function activeLinkByCapability(capability) {
  const tokenHash = sha256(capability);
  const row = db.prepare('SELECT * FROM links WHERE token_hash = ?').get(tokenHash);
  if (!row || row.revoked_at || row.expires_at <= Date.now()) return null;
  return row;
}

function sessionFor(request) {
  const raw = cookies(request)['__Host-scp_session'];
  if (!raw) return null;
  const [sessionId, signature] = raw.split('.');
  const expected = sessionSignature(sessionId);
  if (!signature || !safeEqual(signature, expected)) return null;
  const row = db.prepare(`SELECT id_hash, link_id, token_version AS session_token_version, csrf_hash, permission_ceiling, expires_at AS session_expires_at, revoked_at AS session_revoked_at FROM sessions WHERE id_hash = ?`).get(sha256(sessionId));
  if (!row || row.session_revoked_at || row.session_expires_at <= Date.now()) return null;
  const current = db.prepare('SELECT * FROM links WHERE id = ?').get(row.link_id);
  if (!current || current.revoked_at || current.expires_at <= Date.now() || current.token_version !== row.session_token_version) return null;
  return { session: row, link: current, sessionId };
}

async function verifyPasscode(passcode, encoded) {
  const [algorithm, version, saltValue, hashValue] = String(encoded).split('$');
  if (algorithm !== 'scrypt' || version !== 'v1' || !saltValue || !hashValue) return false;
  if (typeof passcode !== 'string' || passcode.length > 1024) return false;
  const salt = Buffer.from(saltValue, 'base64url');
  const expected = Buffer.from(hashValue, 'base64url');
  if (salt.length !== 16 || expected.length !== 32) return false;
  const derived = await scryptAsync(passcode, salt, expected.length);
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

function requirePermission(request, response, permission) {
  const auth = sessionFor(request);
  if (!auth) {
    genericAuthError(response);
    return null;
  }
  const ceiling = auth.session.permission_ceiling ? JSON.parse(auth.session.permission_ceiling) : null;
  if (!JSON.parse(auth.link.permissions).includes(permission) || (ceiling && !ceiling.includes(permission))) {
    audit(auth.link.id, 'permission', 'denied', { permission }, request);
    json(response, 403, { error: 'The owner did not grant this action' });
    return null;
  }
  return auth;
}

function rateLimit(bucket, limit, windowMs) {
  return db.transaction(() => {
    const now = Date.now();
    const row = db.prepare('SELECT * FROM rate_limit_checkpoints WHERE bucket = ?').get(bucket);
    if (!row || row.resets_at <= now) {
      db.prepare('INSERT OR REPLACE INTO rate_limit_checkpoints (bucket, count, resets_at) VALUES (?, 1, ?)').run(bucket, now + windowMs);
      return false;
    }
    if (row.count >= limit) return true;
    db.prepare('UPDATE rate_limit_checkpoints SET count = count + 1 WHERE bucket = ?').run(bucket);
    return false;
  })();
}

function acquireLease(stackRef, owner, ttlMs = 120_000) {
  const now = Date.now();
  return db.transaction(() => {
    db.prepare('DELETE FROM stack_mutation_leases WHERE expires_at<=?').run(now);
    const existing = db.prepare('SELECT owner FROM stack_mutation_leases WHERE stack_ref=?').get(stackRef);
    if (existing && existing.owner !== owner) return false;
    db.prepare('INSERT OR REPLACE INTO stack_mutation_leases (stack_ref,owner,expires_at) VALUES (?,?,?)').run(stackRef, owner, now + ttlMs);
    return true;
  })();
}

function releaseLease(stackRef, owner) {
  db.prepare('DELETE FROM stack_mutation_leases WHERE stack_ref=? AND owner=?').run(stackRef, owner);
}

const stackActions = {
  restart: { execute: restartStack, failure: 'Restart could not be completed' },
  start: { execute: startStack, failure: 'Start could not be completed' },
  suspend: { execute: suspendStack, failure: 'Suspend could not be completed' },
};

async function runStackAction(request, response, auth, action) {
  const capabilityKey = action === 'restart' ? 'actions_enabled' : 'lifecycle_enabled';
  const capabilityEnabled = db.prepare('SELECT value FROM runtime_metadata WHERE key=?').get(capabilityKey)?.value === 'true';
  if (!capabilityEnabled) return json(response, 403, { error: 'This remote action is disabled by the owner' });
  const csrf = String(request.headers['x-csrf-token'] ?? '');
  if (!csrf || !safeEqual(sha256(csrf), auth.session.csrf_hash)) {
    return json(response, 403, { error: 'Invalid request' });
  }
  const idempotencyKey = String(request.headers['x-idempotency-key'] ?? '');
  if (!/^[A-Za-z0-9._:-]{8,128}$/.test(idempotencyKey)) {
    return json(response, 400, { error: 'A valid idempotency key is required' });
  }
  const existingAction = db.prepare('SELECT action_kind,state,status_code,result_json FROM action_operations WHERE link_id=? AND idempotency_key=?').get(auth.link.id, idempotencyKey);
  if (existingAction) {
    if (existingAction.action_kind !== action) {
      return json(response, 409, { error: 'This idempotency key was already used for another action' });
    }
    if (existingAction.result_json && existingAction.status_code) {
      return json(response, existingAction.status_code, JSON.parse(existingAction.result_json));
    }
    return json(response, 409, { error: `This ${action} request is already running`, operationId: idempotencyKey });
  }
  const sourceKey = sourceDigest(String(request.headers['x-forwarded-for'] ?? request.socket.remoteAddress ?? 'unknown').split(',')[0].trim());
  if (rateLimit(`${action}-link:${auth.link.id}`, 1, 60_000) || rateLimit(`${action}-source:${sourceKey}`, 5, 60_000)) {
    return json(response, 429, { error: 'Try again later' }, { 'retry-after': '60' });
  }
  try {
    db.prepare(`INSERT INTO action_operations (link_id,idempotency_key,stack_ref,action_kind,state,status_code,result_json,created_at,updated_at)
      VALUES (?,?,?,?,'running',NULL,NULL,?,?)`).run(auth.link.id, idempotencyKey, auth.link.target_stack_ref, action, Date.now(), Date.now());
  } catch {
    return json(response, 409, { error: `This ${action} request is already running`, operationId: idempotencyKey });
  }
  const leaseOwner = `public:${auth.link.id}:${randomUUID()}`;
  if (!acquireLease(auth.link.target_stack_ref, leaseOwner)) {
    const body = { error: 'Another application operation is running', operationId: idempotencyKey };
    db.prepare("UPDATE action_operations SET state='failed',status_code=409,result_json=?,updated_at=? WHERE link_id=? AND idempotency_key=?")
      .run(JSON.stringify(body), Date.now(), auth.link.id, idempotencyKey);
    return json(response, 409, body);
  }
  try {
    // Audit intent must be durable before crossing the Docker mutation boundary.
    audit(auth.link.id, `${action}_intent`, 'allowed', { operationId: idempotencyKey }, request);
    const outcomes = await stackActions[action].execute(auth.link.target_stack_ref, auth.link.target_project_name);
    const outcome = outcomes.every((item) => item.success) ? 'succeeded' : 'failed';
    const statusCode = outcome === 'succeeded' ? 200 : 207;
    const body = { action, operationId: idempotencyKey, outcomes };
    audit(auth.link.id, `${action}_outcome`, outcome, { operationId: idempotencyKey, succeeded: outcomes.filter((item) => item.success).length, failed: outcomes.filter((item) => !item.success).length }, request);
    db.prepare("UPDATE action_operations SET state='completed',status_code=?,result_json=?,updated_at=? WHERE link_id=? AND idempotency_key=?")
      .run(statusCode, JSON.stringify(body), Date.now(), auth.link.id, idempotencyKey);
    return json(response, statusCode, body);
  } catch (error) {
    const body = { error: stackActions[action].failure, operationId: idempotencyKey };
    db.prepare("UPDATE action_operations SET state='failed',status_code=500,result_json=?,updated_at=? WHERE link_id=? AND idempotency_key=?")
      .run(JSON.stringify(body), Date.now(), auth.link.id, idempotencyKey);
    try { audit(auth.link.id, `${action}_outcome`, 'failed', { operationId: idempotencyKey }, request); } catch { /* original audit or Docker failure remains authoritative */ }
    throw error;
  } finally {
    releaseLease(auth.link.target_stack_ref, leaseOwner);
  }
}

async function admin(request, response, url) {
  if (!safeEqual(request.headers.authorization ?? '', `Bearer ${adminToken}`)) return genericAuthError(response);
  if (url.pathname === '/admin/health') {
    return json(response, 200, { healthy: true, protocolVersion: PROTOCOL_VERSION, schemaVersion: SCHEMA_VERSION, buildDigest: process.env.PORTAL_BUILD_DIGEST ?? null });
  }
  if (url.pathname === '/admin/backup' && request.method === 'POST') {
    await db.backup('/data/portal.db.preupdate');
    return json(response, 200, { backedUp: true });
  }
  if (url.pathname === '/admin/links/apply' && request.method === 'POST') {
    const body = await readJson(request);
    if (!/^[A-Za-z0-9._:-]{8,128}$/.test(String(body.operationId ?? '')) || !Number.isInteger(body.expectedRevision) || body.expectedRevision < 0) {
      return json(response, 400, { error: 'Invalid apply request' });
    }
    const existingOperation = db.prepare('SELECT result_json FROM applied_operations WHERE operation_id = ?').get(body.operationId);
    if (existingOperation) return json(response, 200, JSON.parse(existingOperation.result_json));
    const policy = validateLinkPolicy(body.policy);
    const existing = db.prepare('SELECT revision, created_at FROM links WHERE id = ?').get(policy.id);
    if (existing && existing.revision !== body.expectedRevision) return json(response, 409, { error: 'Revision conflict', revision: existing.revision });
    const revision = (existing?.revision ?? 0) + 1;
    const now = Date.now();
    const result = { linkId: policy.id, revision, appliedAt: now };
    // Validate both immutable scope labels and seed the read cache before the
    // policy can become remotely active.
    await collectStack(policy.targetStackRef, policy.expectedProjectName);
    db.transaction(() => {
      db.prepare(`INSERT INTO links (id, installation_id, target_stack_ref, target_project_name, client_label, token_hash, token_version, passcode_hash, permissions, expires_at, revoked_at, revision, created_at, updated_at)
        VALUES (@id, @installationId, @targetStackRef, @expectedProjectName, @clientLabel, @tokenHash, @tokenVersion, @passcodeHash, @permissions, @expiresAt, NULL, @revision, @createdAt, @updatedAt)
        ON CONFLICT(id) DO UPDATE SET target_project_name=excluded.target_project_name,client_label=excluded.client_label, token_hash=excluded.token_hash, token_version=excluded.token_version, passcode_hash=excluded.passcode_hash, permissions=excluded.permissions, expires_at=excluded.expires_at, revoked_at=NULL, revision=excluded.revision, updated_at=excluded.updated_at`)
        .run({ ...policy, passcodeHash: policy.passcodeHash ?? null, permissions: JSON.stringify(policy.permissions), revision, createdAt: existing?.created_at ?? now, updatedAt: now });
      db.prepare('INSERT INTO link_revisions (link_id, revision, policy_json, created_at) VALUES (?, ?, ?, ?)').run(policy.id, revision, JSON.stringify({ ...policy, tokenHash: '[REDACTED]', passcodeHash: policy.passcodeHash ? '[REDACTED]' : null }), now);
      db.prepare('INSERT INTO applied_operations (operation_id, kind, result_json, applied_at) VALUES (?, ?, ?, ?)').run(body.operationId, 'apply_link', JSON.stringify(result), now);
    })();
    audit(policy.id, 'policy_applied', 'succeeded', { revision });
    return json(response, 200, result);
  }
  if (url.pathname === '/admin/actions' && request.method === 'POST') {
    const body = await readJson(request);
    if (typeof body.enabled !== 'boolean') return json(response, 400, { error: 'Invalid action state' });
    db.prepare("INSERT OR REPLACE INTO runtime_metadata (key, value) VALUES ('actions_enabled', ?)").run(body.enabled ? 'true' : 'false');
    if (typeof body.lifecycleEnabled === 'boolean') {
      db.prepare("INSERT OR REPLACE INTO runtime_metadata (key, value) VALUES ('lifecycle_enabled', ?)").run(body.lifecycleEnabled ? 'true' : 'false');
    }
    if (typeof body.logsEnabled === 'boolean') {
      db.prepare("INSERT OR REPLACE INTO runtime_metadata (key, value) VALUES ('logs_enabled', ?)").run(body.logsEnabled ? 'true' : 'false');
    }
    audit(null, 'actions_changed', 'succeeded', { enabled: body.enabled, lifecycleEnabled: body.lifecycleEnabled === true, logsEnabled: body.logsEnabled === true });
    return json(response, 200, { enabled: body.enabled, lifecycleEnabled: body.lifecycleEnabled === true, logsEnabled: body.logsEnabled === true });
  }
  if (url.pathname === '/admin/leases/acquire' && request.method === 'POST') {
    const body = await readJson(request);
    if (typeof body.stackRef !== 'string' || typeof body.owner !== 'string') return json(response, 400, { error: 'Invalid lease' });
    const acquired = acquireLease(body.stackRef, body.owner, Math.min(Number(body.ttlMs) || 120_000, 30 * 60_000));
    return json(response, acquired ? 200 : 409, { acquired });
  }
  if (url.pathname === '/admin/leases/release' && request.method === 'POST') {
    const body = await readJson(request);
    releaseLease(String(body.stackRef ?? ''), String(body.owner ?? ''));
    return json(response, 200, { released: true });
  }
  const previewMatch = url.pathname.match(/^\/admin\/links\/([^/]+)\/preview$/);
  if (previewMatch && request.method === 'POST') {
    const link = db.prepare('SELECT id FROM links WHERE id=? AND revoked_at IS NULL AND expires_at>?').get(previewMatch[1], Date.now());
    if (!link) return genericAuthError(response);
    const grant = randomBytes(32).toString('base64url');
    const expiresAt = Date.now() + 5 * 60_000;
    db.prepare('INSERT INTO preview_grants (grant_hash, link_id, expires_at, used_at) VALUES (?, ?, ?, NULL)').run(sha256(grant), previewMatch[1], expiresAt);
    return json(response, 200, { grant, expiresAt });
  }
  const revokeMatch = url.pathname.match(/^\/admin\/links\/([^/]+)\/revoke$/);
  if (revokeMatch && request.method === 'POST') {
    const body = await readJson(request);
    if (!/^[A-Za-z0-9._:-]{8,128}$/.test(String(body.operationId ?? '')) || !Number.isInteger(body.expectedRevision) || body.expectedRevision < 0) {
      return json(response, 400, { error: 'Invalid revoke request' });
    }
    const existingOperation = db.prepare('SELECT result_json FROM applied_operations WHERE operation_id=?').get(body.operationId);
    if (existingOperation) return json(response, 200, JSON.parse(existingOperation.result_json));
    const link = db.prepare('SELECT revision,revoked_at FROM links WHERE id=?').get(revokeMatch[1]);
    if (!link) return genericAuthError(response);
    if (link.revision !== body.expectedRevision) return json(response, 409, { error: 'Revision conflict', revision: link.revision });
    const now = Date.now();
    const result = { revoked: true, changed: !link.revoked_at, revokedAt: link.revoked_at ?? now, revision: link.revision + (link.revoked_at ? 0 : 1) };
    db.transaction(() => {
      if (!link.revoked_at) {
        db.prepare('UPDATE links SET revoked_at=?, token_version=token_version+1, revision=revision+1, updated_at=? WHERE id=?').run(now, now, revokeMatch[1]);
        db.prepare('UPDATE sessions SET revoked_at=? WHERE link_id=? AND revoked_at IS NULL').run(now, revokeMatch[1]);
      }
      db.prepare('INSERT INTO applied_operations (operation_id,kind,result_json,applied_at) VALUES (?,?,?,?)')
        .run(body.operationId, 'revoke_link', JSON.stringify(result), now);
    })();
    audit(revokeMatch[1], 'revoke', 'succeeded', { operationId: body.operationId });
    return json(response, 200, result);
  }
  const removeMatch = url.pathname.match(/^\/admin\/links\/([^/]+)$/);
  if (removeMatch && request.method === 'DELETE') {
    db.prepare('DELETE FROM links WHERE id = ? AND revoked_at IS NOT NULL').run(removeMatch[1]);
    return json(response, 200, { removed: true });
  }
  const activityMatch = url.pathname.match(/^\/admin\/links\/([^/]+)\/activity$/);
  if (activityMatch) {
    const rows = db.prepare('SELECT id, event_type, outcome, detail_json, created_at FROM audit_events WHERE link_id = ? ORDER BY created_at DESC LIMIT 100').all(activityMatch[1]);
    return json(response, 200, { events: rows });
  }
  return json(response, 404, { error: 'Not found' });
}

async function publicApi(request, response, url) {
  if (!safeEqual(request.headers['x-portal-gateway-token'] ?? '', gatewayToken)) return genericAuthError(response);
  if (request.headers['x-portal-origin-valid'] !== '1') return json(response, 403, { error: 'Invalid request origin' });
  if (url.pathname === '/api/session/exchange' && request.method === 'POST') {
    const source = sourceDigest(String(request.headers['x-forwarded-for'] ?? request.socket.remoteAddress ?? 'unknown'));
    if (rateLimit(`exchange:${source}`, 10, 60_000)) return json(response, 429, { error: 'Try again later' }, { 'retry-after': '60' });
    const body = await readJson(request);
    const link = typeof body.capability === 'string' ? activeLinkByCapability(body.capability) : null;
    if (!link) return genericAuthError(response);
    if (rateLimit(`exchange-link:${link.id}`, 10, 60_000)) return json(response, 429, { error: 'Try again later' }, { 'retry-after': '60' });
    if (link.passcode_hash && !(await verifyPasscode(body.passcode ?? '', link.passcode_hash))) return genericAuthError(response);
    const sessionId = randomBytes(32).toString('base64url');
    const csrf = randomBytes(24).toString('base64url');
    const expiresAt = Math.min(link.expires_at, Date.now() + 12 * 60 * 60 * 1000);
    db.prepare('INSERT INTO sessions (id_hash, link_id, token_version, csrf_hash, permission_ceiling, expires_at, revoked_at) VALUES (?, ?, ?, ?, NULL, ?, NULL)')
      .run(sha256(sessionId), link.id, link.token_version, sha256(csrf), expiresAt);
    audit(link.id, 'session_exchange', 'allowed', {}, request);
    return json(response, 200, { authenticated: true, csrf, expiresAt }, {
      'set-cookie': `__Host-scp_session=${sessionId}.${sessionSignature(sessionId)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.max(1, Math.floor((expiresAt - Date.now()) / 1000))}`,
    });
  }
  if (url.pathname === '/api/session/preview' && request.method === 'POST') {
    const body = await readJson(request);
    const grantHash = sha256(String(body.grant ?? ''));
    const grant = db.prepare('SELECT * FROM preview_grants WHERE grant_hash=? AND used_at IS NULL AND expires_at>?').get(grantHash, Date.now());
    if (!grant) return genericAuthError(response);
    const link = db.prepare('SELECT * FROM links WHERE id=? AND revoked_at IS NULL AND expires_at>?').get(grant.link_id, Date.now());
    if (!link) return genericAuthError(response);
    const sessionId = randomBytes(32).toString('base64url');
    const csrf = randomBytes(24).toString('base64url');
    const expiresAt = Math.min(grant.expires_at, Date.now() + 5 * 60_000);
    const claimed = db.transaction(() => {
      const update = db.prepare('UPDATE preview_grants SET used_at=? WHERE grant_hash=? AND used_at IS NULL').run(Date.now(), grantHash);
      if (update.changes !== 1) return false;
      db.prepare('INSERT INTO sessions (id_hash, link_id, token_version, csrf_hash, permission_ceiling, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, NULL)')
        .run(sha256(sessionId), link.id, link.token_version, sha256(csrf), JSON.stringify(['view_status', 'view_metrics']), expiresAt);
      return true;
    })();
    if (!claimed) return genericAuthError(response);
    audit(link.id, 'owner_preview', 'allowed', {}, request);
    return json(response, 200, { authenticated: true, csrf, expiresAt }, {
      'set-cookie': `__Host-scp_session=${sessionId}.${sessionSignature(sessionId)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=300`,
    });
  }
  if (url.pathname === '/api/dashboard' && request.method === 'GET') {
    const auth = requirePermission(request, response, 'view_status');
    if (!auth) return;
    if (rateLimit(`read:${auth.link.id}`, 120, 60_000)) return json(response, 429, { error: 'Try again later' }, { 'retry-after': '60' });
    const cached = db.prepare('SELECT * FROM stack_snapshots WHERE stack_ref=?').get(auth.link.target_stack_ref);
    if (!cached?.snapshot_json || !cached?.metrics_json || !cached.last_success_at) {
      return json(response, 503, { error: 'Metrics are not available yet', code: cached?.last_error_code ?? 'PORTAL_METRICS_UNAVAILABLE' });
    }
    const snapshot = JSON.parse(cached.snapshot_json);
    const storedMetrics = JSON.parse(cached.metrics_json);
    const history = addCounterRates(db.prepare('SELECT bucket_at AS at,cpu_percent AS cpuPercent,memory_bytes AS memoryBytes,memory_limit AS memoryLimit,rx_bytes AS rxBytes,tx_bytes AS txBytes,storage_bytes AS storageBytes,block_read_bytes AS blockReadBytes,block_write_bytes AS blockWriteBytes,running,total FROM resource_points_1m WHERE stack_ref=? ORDER BY bucket_at DESC LIMIT 60').all(auth.link.target_stack_ref).reverse());
    const latestRates = history.at(-1);
    const metrics = {
      ...storedMetrics,
      rxBytesPerSecond: latestRates?.rxBytesPerSecond ?? null,
      txBytesPerSecond: latestRates?.txBytesPerSecond ?? null,
    };
    const stale = cached.last_success_at < Date.now() - 150_000 || Boolean(cached.last_error_code);
    audit(auth.link.id, 'dashboard_view', 'allowed', { stale }, request);
    return json(response, 200, {
      clientLabel: auth.link.client_label,
      permissions: JSON.parse(auth.link.permissions),
      expiresAt: auth.link.expires_at,
      snapshot,
      metrics,
      history,
      source: {
        stale,
        lastSuccessfulAt: cached.last_success_at,
        errorCode: cached.last_error_code ?? null,
      },
      httpMetrics: {
        available: false,
        reason: 'HTTP request metrics are unavailable. Resource metrics continue to update.',
      },
      backup: {
        status: 'owner_managed',
        lastRunAt: null,
        runAvailable: false,
        reason: 'Backups remain owner-managed until a safe always-on backup destination and executor are configured.',
      },
    });
  }
  if (url.pathname === '/api/logs' && request.method === 'GET') {
    const auth = requirePermission(request, response, 'view_logs');
    if (!auth) return;
    const logsEnabled = db.prepare("SELECT value FROM runtime_metadata WHERE key='logs_enabled'").get()?.value === 'true';
    if (!logsEnabled) return json(response, 403, { error: 'Recent logs are disabled by the owner' });
    if (rateLimit(`logs:${auth.link.id}`, 10, 60_000)) return json(response, 429, { error: 'Try again later' }, { 'retry-after': '60' });
    const logs = await getStackLogs(auth.link.target_stack_ref, auth.link.target_project_name);
    audit(auth.link.id, 'logs_view', 'allowed', {}, request);
    return json(response, 200, { logs });
  }
  const actionMatch = url.pathname.match(/^\/api\/(restart|start|suspend)$/);
  if (actionMatch && request.method === 'POST') {
    const action = actionMatch[1];
    const auth = requirePermission(request, response, action);
    if (!auth) return;
    return runStackAction(request, response, auth, action);
  }
  return json(response, 404, { error: 'Not found' });
}

const server = http.createServer(async (request, response) => {
  try {
    const url = new URL(request.url ?? '/', 'http://broker');
    if (url.pathname.startsWith('/admin/')) return await admin(request, response, url);
    if (url.pathname.startsWith('/api/')) return await publicApi(request, response, url);
    return json(response, 404, { error: 'Not found' });
  } catch (error) {
    console.error('[portal-broker] request failed', error instanceof Error ? error.message : 'unknown');
    const message = error instanceof Error ? error.message : '';
    const status = message === 'Request body too large' ? 413 : message.includes('JSON') ? 400 : 500;
    return json(response, status, { error: status === 500 ? 'Portal temporarily unavailable' : 'Invalid request' });
  }
});
server.headersTimeout = 15_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 64;
server.listen(port, '0.0.0.0', () => console.log(`[portal-broker] listening on ${port}`));
