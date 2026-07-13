import Database from 'better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export function openBrokerDatabase(filename) {
  mkdirSync(dirname(filename), { recursive: true });
  const db = new Database(filename);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  const hasRuntimeMetadata = Boolean(
    db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='runtime_metadata'").get()
  );
  const previousSchemaVersion = hasRuntimeMetadata
    ? Number(db.prepare("SELECT value FROM runtime_metadata WHERE key='schema_version'").get()?.value ?? 0)
    : 0;
  db.exec(`
    CREATE TABLE IF NOT EXISTS runtime_metadata (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS applied_operations (
      operation_id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      result_json TEXT NOT NULL,
      applied_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS links (
      id TEXT PRIMARY KEY,
      installation_id TEXT NOT NULL,
      target_stack_ref TEXT NOT NULL,
      target_project_name TEXT NOT NULL,
      client_label TEXT NOT NULL,
      token_hash TEXT NOT NULL UNIQUE,
      token_version INTEGER NOT NULL,
      passcode_hash TEXT,
      permissions TEXT NOT NULL,
      branding TEXT NOT NULL DEFAULT '{}',
      expires_at INTEGER NOT NULL,
      revoked_at INTEGER,
      revision INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS link_revisions (
      link_id TEXT NOT NULL,
      revision INTEGER NOT NULL,
      policy_json TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (link_id, revision)
    );
    CREATE TABLE IF NOT EXISTS sessions (
      id_hash TEXT PRIMARY KEY,
      link_id TEXT NOT NULL REFERENCES links(id) ON DELETE CASCADE,
      token_version INTEGER NOT NULL,
      csrf_hash TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      revoked_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS preview_grants (
      grant_hash TEXT PRIMARY KEY,
      link_id TEXT NOT NULL REFERENCES links(id) ON DELETE CASCADE,
      expires_at INTEGER NOT NULL,
      used_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS audit_events (
      id TEXT PRIMARY KEY,
      link_id TEXT,
      event_type TEXT NOT NULL,
      outcome TEXT NOT NULL,
      detail_json TEXT NOT NULL DEFAULT '{}',
      source_hash TEXT,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS resource_points_1m (
      stack_ref TEXT NOT NULL,
      bucket_at INTEGER NOT NULL,
      cpu_percent REAL NOT NULL,
      memory_bytes INTEGER NOT NULL,
      memory_limit INTEGER NOT NULL,
      rx_bytes INTEGER NOT NULL,
      tx_bytes INTEGER NOT NULL,
      storage_bytes INTEGER NOT NULL DEFAULT 0,
      block_read_bytes INTEGER NOT NULL DEFAULT 0,
      block_write_bytes INTEGER NOT NULL DEFAULT 0,
      running INTEGER NOT NULL,
      total INTEGER NOT NULL,
      PRIMARY KEY (stack_ref, bucket_at)
    );
    CREATE TABLE IF NOT EXISTS resource_points_5m (
      stack_ref TEXT NOT NULL,
      bucket_at INTEGER NOT NULL,
      cpu_percent REAL NOT NULL,
      memory_bytes INTEGER NOT NULL,
      memory_limit INTEGER NOT NULL,
      rx_bytes INTEGER NOT NULL,
      tx_bytes INTEGER NOT NULL,
      storage_bytes INTEGER NOT NULL DEFAULT 0,
      block_read_bytes INTEGER NOT NULL DEFAULT 0,
      block_write_bytes INTEGER NOT NULL DEFAULT 0,
      running INTEGER NOT NULL,
      total INTEGER NOT NULL,
      sample_count INTEGER NOT NULL,
      PRIMARY KEY (stack_ref, bucket_at)
    );
    CREATE TABLE IF NOT EXISTS stack_snapshots (
      stack_ref TEXT PRIMARY KEY,
      snapshot_json TEXT,
      metrics_json TEXT,
      last_success_at INTEGER,
      last_attempt_at INTEGER NOT NULL,
      last_error_code TEXT
    );
    CREATE TABLE IF NOT EXISTS rate_limit_checkpoints (
      bucket TEXT PRIMARY KEY,
      count INTEGER NOT NULL,
      resets_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS stack_mutation_leases (
      stack_ref TEXT PRIMARY KEY,
      owner TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS action_operations (
      link_id TEXT NOT NULL REFERENCES links(id) ON DELETE CASCADE,
      idempotency_key TEXT NOT NULL,
      stack_ref TEXT NOT NULL,
      action_kind TEXT NOT NULL DEFAULT 'restart',
      state TEXT NOT NULL CHECK (state IN ('running', 'completed', 'failed')),
      status_code INTEGER,
      result_json TEXT,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (link_id, idempotency_key)
    );
    CREATE INDEX IF NOT EXISTS idx_links_stack ON links(target_stack_ref);
    CREATE INDEX IF NOT EXISTS idx_audit_link_time ON audit_events(link_id, created_at DESC);
  `);
  const sessionColumns = db.prepare('PRAGMA table_info(sessions)').all();
  if (!sessionColumns.some((column) => column.name === 'permission_ceiling')) {
    db.exec('ALTER TABLE sessions ADD COLUMN permission_ceiling TEXT;');
  }
  const linkColumns = db.prepare('PRAGMA table_info(links)').all();
  if (!linkColumns.some((column) => column.name === 'target_project_name')) {
    db.exec("ALTER TABLE links ADD COLUMN target_project_name TEXT NOT NULL DEFAULT '';");
  }
  if (!linkColumns.some((column) => column.name === 'branding')) {
    db.exec("ALTER TABLE links ADD COLUMN branding TEXT NOT NULL DEFAULT '{}';");
  }
  for (const table of ['resource_points_1m', 'resource_points_5m']) {
    const columns = db.prepare(`PRAGMA table_info(${table})`).all();
    for (const column of ['storage_bytes', 'block_read_bytes', 'block_write_bytes']) {
      if (!columns.some((item) => item.name === column)) {
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} INTEGER NOT NULL DEFAULT 0;`);
      }
    }
  }
  const actionColumns = db.prepare('PRAGMA table_info(action_operations)').all();
  if (!actionColumns.some((column) => column.name === 'action_kind')) {
    db.exec("ALTER TABLE action_operations ADD COLUMN action_kind TEXT NOT NULL DEFAULT 'restart';");
  }
  db.prepare(`INSERT OR REPLACE INTO runtime_metadata (key, value) VALUES ('schema_version', '3')`).run();
  db.prepare(`INSERT OR IGNORE INTO runtime_metadata (key, value) VALUES ('actions_enabled', 'false')`).run();
  db.prepare(`INSERT OR IGNORE INTO runtime_metadata (key, value) VALUES ('lifecycle_enabled', 'false')`).run();
  db.prepare(`INSERT OR IGNORE INTO runtime_metadata (key, value) VALUES ('logs_enabled', 'false')`).run();
  if (previousSchemaVersion > 0 && previousSchemaVersion < 3) {
    // Runtime upgrades fail safe until the desktop explicitly re-enables the
    // gated capabilities supported by the new protocol.
    db.prepare("UPDATE runtime_metadata SET value='false' WHERE key IN ('actions_enabled', 'lifecycle_enabled', 'logs_enabled')").run();
  }
  return db;
}
