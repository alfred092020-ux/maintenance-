import { existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

function ensureColumn(
  db: DatabaseSync,
  table: string,
  column: string,
  definition: string
): void {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as unknown as Array<{
    name: string;
  }>;
  if (!rows.some((row) => row.name === column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${definition}`);
  }
}

export function openReadOnlyDatabase(filename: string): DatabaseSync | undefined {
  if (!existsSync(filename)) return undefined;
  const db = new DatabaseSync(filename, { readOnly: true });
  db.exec('PRAGMA query_only=ON; PRAGMA busy_timeout=5000;');
  return db;
}

export function openDatabase(filename: string): DatabaseSync {
  if (filename !== ':memory:') mkdirSync(path.dirname(filename), { recursive: true });
  const db = new DatabaseSync(filename);
  db.exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;');
  db.exec(`
    CREATE TABLE IF NOT EXISTS jobs (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL,
      owner TEXT,
      result_json TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      execution_scope TEXT NOT NULL DEFAULT 'local',
      target_machine_id TEXT,
      required_capability TEXT,
      lease_owner TEXT,
      lease_expires_at INTEGER,
      priority INTEGER NOT NULL DEFAULT 100,
      reassignable INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS leases (
      resource TEXT PRIMARY KEY,
      owner TEXT NOT NULL,
      expires_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      subject TEXT NOT NULL,
      data_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      action TEXT NOT NULL,
      actor TEXT NOT NULL,
      target TEXT NOT NULL,
      detail_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS machines (
      id TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      certificate_fingerprint TEXT NOT NULL UNIQUE,
      status TEXT NOT NULL,
      last_seen_at TEXT,
      enrolled_at TEXT NOT NULL,
      revoked_at TEXT,
      metadata_json TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS machine_capabilities (
      machine_id TEXT NOT NULL REFERENCES machines(id) ON DELETE CASCADE,
      capability TEXT NOT NULL,
      PRIMARY KEY(machine_id, capability)
    );
    CREATE TABLE IF NOT EXISTS privileged_nonces (
      nonce TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL
    );
  `);

  ensureColumn(db, 'jobs', 'execution_scope',
    "execution_scope TEXT NOT NULL DEFAULT 'local'");
  ensureColumn(db, 'jobs', 'target_machine_id', 'target_machine_id TEXT');
  ensureColumn(db, 'jobs', 'required_capability', 'required_capability TEXT');
  ensureColumn(db, 'jobs', 'lease_owner', 'lease_owner TEXT');
  ensureColumn(db, 'jobs', 'lease_expires_at', 'lease_expires_at INTEGER');
  ensureColumn(db, 'jobs', 'priority',
    'priority INTEGER NOT NULL DEFAULT 100');
  ensureColumn(db, 'jobs', 'reassignable',
    'reassignable INTEGER NOT NULL DEFAULT 1');

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_jobs_remote_queue
      ON jobs(execution_scope, status, priority, created_at);
    CREATE INDEX IF NOT EXISTS idx_jobs_remote_lease_expiry
      ON jobs(execution_scope, status, lease_expires_at);
  `);

  return db;
}
