import { randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { redactText, redactValue } from '../security/redact.js';
import {
  MACHINE_CAPABILITIES,
  type EnrollMachineInput,
  type MachineCapability,
  type MachineRecord,
  type MachineStatus
} from '../machines/types.js';
import type {
  CreateRemoteJobInput,
  RemoteRequeueResult
} from '../remote/types.js';

export type JobStatus =
  | 'QUEUED'
  | 'LEASED'
  | 'RUNNING'
  | 'WAITING'
  | 'VERIFYING'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'CANCELLED'
  | 'ROLLED_BACK';

export interface JobRecord {
  id: string;
  kind: string;
  payload: Record<string, unknown>;
  status: JobStatus;
  owner: string | null;
  result: unknown;
  createdAt: string;
  updatedAt: string;
  executionScope: 'local' | 'remote';
  targetMachineId: string | null;
  requiredCapability: MachineCapability | null;
  leaseOwner: string | null;
  leaseExpiresAt: number | null;
  priority: number;
  reassignable: boolean;
}

export interface CreateJobInput {
  kind: string;
  payload: Record<string, unknown>;
}

export interface EventInput {
  type: string;
  subject: string;
  data?: Record<string, unknown>;
}

export interface AuditInput {
  action: string;
  actor: string;
  target: string;
  detail?: Record<string, unknown>;
}

export interface EventRecord {
  id: number;
  type: string;
  subject: string;
  data: Record<string, unknown>;
  createdAt: string;
}

export interface AuditRecord {
  id: number;
  action: string;
  actor: string;
  target: string;
  detail: Record<string, unknown>;
  createdAt: string;
}

interface JobRow {
  id: string;
  kind: string;
  payload_json: string;
  status: JobStatus;
  owner: string | null;
  result_json: string | null;
  created_at: string;
  updated_at: string;
  execution_scope: 'local' | 'remote';
  target_machine_id: string | null;
  required_capability: MachineCapability | null;
  lease_owner: string | null;
  lease_expires_at: number | null;
  priority: number;
  reassignable: number;
}

interface MachineRow {
  id: string;
  display_name: string;
  certificate_fingerprint: string;
  status: MachineStatus;
  last_seen_at: string | null;
  enrolled_at: string;
  revoked_at: string | null;
  metadata_json: string;
}

export class BrainStore {
  constructor(private readonly db: DatabaseSync) {}

  close(): void {
    this.db.close();
  }

  createJob(input: CreateJobInput, actor = 'system'): string {
    const id = randomUUID();
    const now = new Date().toISOString();
    this.db.prepare(
      'INSERT INTO jobs(id, kind, payload_json, status, owner, result_json, created_at, updated_at) VALUES(?,?,?,\'QUEUED\',NULL,NULL,?,?)'
    ).run(id, input.kind, JSON.stringify(input.payload), now, now);
    this.appendAudit({
      action: 'job.create',
      actor,
      target: id,
      detail: { kind: input.kind }
    });
    return id;
  }

  getJob(id: string): JobRecord | undefined {
    const row = this.db.prepare('SELECT * FROM jobs WHERE id=?').get(id) as unknown as JobRow | undefined;
    return row ? this.mapJob(row) : undefined;
  }

  claimJob(id: string, owner: string): boolean {
    const now = new Date().toISOString();
    const result = this.db.prepare(
      "UPDATE jobs SET status='RUNNING', owner=?, updated_at=? WHERE id=? AND status='QUEUED' AND execution_scope='local'"
    ).run(owner, now, id);
    if (result.changes === 1) {
      this.appendAudit({
        action: 'job.claim',
        actor: owner,
        target: id,
        detail: { status: 'RUNNING' }
      });
      return true;
    }
    return false;
  }

  claimNextJob(owner: string): JobRecord | undefined {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.db.prepare(
        "SELECT * FROM jobs WHERE status='QUEUED' AND execution_scope='local' ORDER BY created_at, id LIMIT 1"
      ).get() as unknown as JobRow | undefined;
      if (!row) {
        this.db.exec('COMMIT');
        return undefined;
      }
      const now = new Date().toISOString();
      const changed = this.db.prepare(
        "UPDATE jobs SET status='RUNNING', owner=?, updated_at=? WHERE id=? AND status='QUEUED' AND execution_scope='local'"
      ).run(owner, now, row.id);
      if (changed.changes !== 1) {
        this.db.exec('COMMIT');
        return undefined;
      }
      this.appendAudit({
        action: 'job.claim',
        actor: owner,
        target: row.id,
        detail: { status: 'RUNNING' }
      });
      this.db.exec('COMMIT');
      return this.getJob(row.id);
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  listJobsByStatus(status: JobStatus): JobRecord[] {
    const rows = this.db.prepare(
      'SELECT * FROM jobs WHERE status=? ORDER BY created_at, id'
    ).all(status) as unknown as JobRow[];
    return rows.map((row) => this.mapJob(row));
  }

  listLocalJobsByStatus(status: JobStatus): JobRecord[] {
    const rows = this.db.prepare(
      "SELECT * FROM jobs WHERE status=? AND execution_scope='local' ORDER BY created_at, id"
    ).all(status) as unknown as JobRow[];
    return rows.map((row) => this.mapJob(row));
  }

  countJobsByStatus(status: JobStatus): number {
    const row = this.db.prepare(
      'SELECT COUNT(*) AS count FROM jobs WHERE status=?'
    ).get(status) as unknown as { count: number };
    return Number(row.count);
  }

  createRemoteJob(
    input: CreateRemoteJobInput,
    actor = 'system'
  ): string {
    if (input.targetMachineId !== undefined) {
      this.requireMachine(input.targetMachineId);
    }
    if (
      input.requiredCapability !== undefined &&
      !(MACHINE_CAPABILITIES as readonly string[]).includes(
        input.requiredCapability
      )
    ) {
      throw new Error('invalid required capability');
    }

    const priority = input.priority ?? 100;
    if (!Number.isInteger(priority) || priority < 0 || priority > 1_000_000) {
      throw new Error('invalid remote job priority');
    }

    const id = randomUUID();
    const now = new Date().toISOString();
    this.db.prepare(
      `INSERT INTO jobs(
        id, kind, payload_json, status, owner, result_json,
        created_at, updated_at, execution_scope,
        target_machine_id, required_capability,
        lease_owner, lease_expires_at, priority, reassignable
      ) VALUES(?,?,?,'QUEUED',NULL,NULL,?,?,'remote',?,?,NULL,NULL,?,?)`
    ).run(
      id,
      input.kind,
      JSON.stringify(input.payload),
      now,
      now,
      input.targetMachineId ?? null,
      input.requiredCapability ?? null,
      priority,
      input.reassignable === false ? 0 : 1
    );

    this.appendEvent({
      type: 'JOB_CREATED',
      subject: id,
      data: {
        executionScope: 'remote',
        targetMachineId: input.targetMachineId ?? null
      }
    });
    this.appendAudit({
      action: 'remote_job.create',
      actor,
      target: id,
      detail: {
        kind: input.kind,
        targetMachineId: input.targetMachineId ?? null,
        requiredCapability: input.requiredCapability ?? null,
        priority,
        reassignable: input.reassignable !== false
      }
    });
    return id;
  }

  listRemoteJobs(status?: JobStatus): JobRecord[] {
    const rows = status === undefined
      ? this.db.prepare(
          "SELECT * FROM jobs WHERE execution_scope='remote' ORDER BY priority, created_at, id"
        ).all()
      : this.db.prepare(
          "SELECT * FROM jobs WHERE execution_scope='remote' AND status=? ORDER BY priority, created_at, id"
        ).all(status);
    return (rows as unknown as JobRow[]).map((row) => this.mapJob(row));
  }

  finishJob(id: string, status: Extract<JobStatus, 'SUCCEEDED' | 'FAILED'>, result: unknown): boolean {
    const current = this.getJob(id);
    const now = new Date().toISOString();
    const changed = this.db.prepare(
      "UPDATE jobs SET status=?, result_json=?, updated_at=? WHERE id=? AND status='RUNNING' AND execution_scope='local'"
    ).run(status, JSON.stringify(result), now, id);
    if (changed.changes === 1) {
      this.appendAudit({
        action: 'job.finish',
        actor: current?.owner ?? 'system',
        target: id,
        detail: { status }
      });
      return true;
    }
    return false;
  }

  leaseRemoteJob(
    machineId: string,
    leaseMs: number,
    now = Date.now()
  ): JobRecord | undefined {
    if (!Number.isInteger(leaseMs) || leaseMs < 100 || leaseMs > 3_600_000) {
      throw new Error('invalid remote lease duration');
    }

    const machine = this.requireMachine(machineId);
    if (machine.status !== 'ONLINE') return undefined;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const row = this.db.prepare(
        `SELECT j.*
         FROM jobs j
         WHERE j.execution_scope='remote'
           AND j.status='QUEUED'
           AND (j.target_machine_id IS NULL OR j.target_machine_id=?)
           AND (
             j.required_capability IS NULL
             OR EXISTS (
               SELECT 1
               FROM machine_capabilities c
               WHERE c.machine_id=?
                 AND c.capability=j.required_capability
             )
           )
         ORDER BY j.priority, j.created_at, j.id
         LIMIT 1`
      ).get(machineId, machineId) as unknown as JobRow | undefined;

      if (!row) {
        this.db.exec('COMMIT');
        return undefined;
      }

      const updatedAt = new Date(now).toISOString();
      const expiresAt = now + leaseMs;
      const changed = this.db.prepare(
        `UPDATE jobs
         SET status='RUNNING',
             owner=?,
             lease_owner=?,
             lease_expires_at=?,
             updated_at=?
         WHERE id=?
           AND status='QUEUED'
           AND execution_scope='remote'`
      ).run(
        `machine:${machineId}`,
        machineId,
        expiresAt,
        updatedAt,
        row.id
      );

      if (changed.changes !== 1) {
        this.db.exec('COMMIT');
        return undefined;
      }

      this.appendEvent({
        type: 'JOB_STARTED',
        subject: row.id,
        data: {
          machineId,
          leaseExpiresAt: expiresAt
        }
      });
      this.appendAudit({
        action: 'remote_job.lease',
        actor: machineId,
        target: row.id,
        detail: { leaseExpiresAt: expiresAt }
      });
      this.db.exec('COMMIT');
      return this.getJob(row.id);
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  heartbeatRemoteLease(
    jobId: string,
    machineId: string,
    leaseMs: number,
    now = Date.now()
  ): boolean {
    if (!Number.isInteger(leaseMs) || leaseMs < 100 || leaseMs > 3_600_000) {
      throw new Error('invalid remote lease duration');
    }

    const job = this.getJob(jobId);
    if (!job || job.executionScope !== 'remote') {
      throw new Error('remote job not found');
    }
    if (job.status !== 'RUNNING') throw new Error('remote job is not running');
    if (job.leaseOwner !== machineId) {
      throw new Error('remote job lease owner mismatch');
    }
    if (job.leaseExpiresAt === null || job.leaseExpiresAt <= now) {
      throw new Error('remote job lease expired');
    }

    const expiresAt = now + leaseMs;
    const changed = this.db.prepare(
      `UPDATE jobs
       SET lease_expires_at=?, updated_at=?
       WHERE id=?
         AND execution_scope='remote'
         AND status='RUNNING'
         AND lease_owner=?`
    ).run(expiresAt, new Date(now).toISOString(), jobId, machineId);

    if (changed.changes === 1) {
      this.appendEvent({
        type: 'JOB_PROGRESS',
        subject: jobId,
        data: { machineId, leaseExpiresAt: expiresAt }
      });
      this.appendAudit({
        action: 'remote_job.heartbeat',
        actor: machineId,
        target: jobId,
        detail: { leaseExpiresAt: expiresAt }
      });
      return true;
    }
    return false;
  }

  finishRemoteJob(
    jobId: string,
    machineId: string,
    result: unknown,
    now = Date.now(),
    status: Extract<JobStatus, 'SUCCEEDED' | 'FAILED'> = 'SUCCEEDED'
  ): boolean {
    const job = this.getJob(jobId);
    if (!job || job.executionScope !== 'remote') {
      throw new Error('remote job not found');
    }
    if (job.status !== 'RUNNING') throw new Error('remote job is not running');
    if (job.leaseOwner !== machineId) {
      throw new Error('remote job lease owner mismatch');
    }
    if (job.leaseExpiresAt === null || job.leaseExpiresAt <= now) {
      throw new Error('remote job lease expired');
    }

    const safeResult = redactValue(result);
    const encoded = JSON.stringify(safeResult);
    if (Buffer.byteLength(encoded, 'utf8') > 1024 * 1024) {
      throw new Error('remote job result too large');
    }

    const changed = this.db.prepare(
      `UPDATE jobs
       SET status=?,
           result_json=?,
           lease_expires_at=NULL,
           updated_at=?
       WHERE id=?
         AND execution_scope='remote'
         AND status='RUNNING'
         AND lease_owner=?`
    ).run(
      status,
      encoded,
      new Date(now).toISOString(),
      jobId,
      machineId
    );

    if (changed.changes !== 1) return false;

    this.appendEvent({
      type: status === 'SUCCEEDED' ? 'JOB_SUCCEEDED' : 'JOB_FAILED',
      subject: jobId,
      data: { machineId }
    });
    this.appendAudit({
      action: 'remote_job.finish',
      actor: machineId,
      target: jobId,
      detail: { status }
    });
    return true;
  }

  requeueExpiredRemoteJobs(now = Date.now()): RemoteRequeueResult {
    const expired = this.db.prepare(
      `SELECT *
       FROM jobs
       WHERE execution_scope='remote'
         AND status='RUNNING'
         AND lease_expires_at IS NOT NULL
         AND lease_expires_at<=?
       ORDER BY priority, created_at, id`
    ).all(now) as unknown as JobRow[];

    let requeued = 0;
    let failed = 0;

    this.db.exec('BEGIN IMMEDIATE');
    try {
      for (const row of expired) {
        if (row.reassignable === 1) {
          const changed = this.db.prepare(
            `UPDATE jobs
             SET status='QUEUED',
                 owner=NULL,
                 target_machine_id=NULL,
                 lease_owner=NULL,
                 lease_expires_at=NULL,
                 updated_at=?
             WHERE id=?
               AND status='RUNNING'
               AND lease_expires_at<=?`
          ).run(new Date(now).toISOString(), row.id, now);
          if (changed.changes !== 1) continue;
          requeued += 1;
          this.appendEvent({
            type: 'JOB_PROGRESS',
            subject: row.id,
            data: { reason: 'remote_lease_expired', action: 'requeued' }
          });
          this.appendAudit({
            action: 'remote_job.requeue',
            actor: 'lease-reconciler',
            target: row.id,
            detail: { reason: 'remote_lease_expired' }
          });
        } else {
          const result = JSON.stringify({ reason: 'remote_lease_expired' });
          const changed = this.db.prepare(
            `UPDATE jobs
             SET status='FAILED',
                 result_json=?,
                 lease_expires_at=NULL,
                 updated_at=?
             WHERE id=?
               AND status='RUNNING'
               AND lease_expires_at<=?`
          ).run(result, new Date(now).toISOString(), row.id, now);
          if (changed.changes !== 1) continue;
          failed += 1;
          this.appendEvent({
            type: 'JOB_FAILED',
            subject: row.id,
            data: { reason: 'remote_lease_expired' }
          });
          this.appendAudit({
            action: 'remote_job.fail_expired',
            actor: 'lease-reconciler',
            target: row.id,
            detail: { reason: 'remote_lease_expired' }
          });
        }
      }
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }

    return { requeued, failed };
  }

  appendEvent(event: EventInput): number {
    const result = this.db.prepare(
      'INSERT INTO events(type, subject, data_json, created_at) VALUES(?,?,?,?)'
    ).run(event.type, event.subject, JSON.stringify(event.data ?? {}), new Date().toISOString());
    return Number(result.lastInsertRowid);
  }

  appendAudit(audit: AuditInput): number {
    const result = this.db.prepare(
      'INSERT INTO audits(action, actor, target, detail_json, created_at) VALUES(?,?,?,?,?)'
    ).run(
      redactText(audit.action),
      redactText(audit.actor),
      redactText(audit.target),
      JSON.stringify(redactValue(audit.detail ?? {})),
      new Date().toISOString()
    );
    return Number(result.lastInsertRowid);
  }

  listEvents(): EventRecord[] {
    const rows = this.db.prepare(
      'SELECT id, type, subject, data_json, created_at FROM events ORDER BY id'
    ).all() as unknown as Array<{
      id: number;
      type: string;
      subject: string;
      data_json: string;
      created_at: string;
    }>;
    return rows.map((row) => ({
      id: row.id,
      type: row.type,
      subject: row.subject,
      data: JSON.parse(row.data_json) as Record<string, unknown>,
      createdAt: row.created_at
    }));
  }

  listEventsAfter(
    afterEventId = 0,
    limit = 100
  ): EventRecord[] {
    if (!Number.isInteger(afterEventId) || afterEventId < 0) {
      throw new Error('invalid event cursor');
    }
    if (!Number.isInteger(limit) || limit < 1 || limit > 10_000) {
      throw new Error('invalid event limit');
    }

    const rows = this.db.prepare(
      `SELECT id, type, subject, data_json, created_at
       FROM events
       WHERE id>?
       ORDER BY id
       LIMIT ?`
    ).all(afterEventId, limit) as unknown as Array<{
      id: number;
      type: string;
      subject: string;
      data_json: string;
      created_at: string;
    }>;
    return rows.map((row) => ({
      id: row.id,
      type: row.type,
      subject: row.subject,
      data: JSON.parse(row.data_json) as Record<string, unknown>,
      createdAt: row.created_at
    }));
  }

  listAudits(): AuditRecord[] {
    const rows = this.db.prepare(
      'SELECT id, action, actor, target, detail_json, created_at FROM audits ORDER BY id'
    ).all() as unknown as Array<{
      id: number;
      action: string;
      actor: string;
      target: string;
      detail_json: string;
      created_at: string;
    }>;
    return rows.map((row) => ({
      id: row.id,
      action: row.action,
      actor: row.actor,
      target: row.target,
      detail: JSON.parse(row.detail_json) as Record<string, unknown>,
      createdAt: row.created_at
    }));
  }

  enrollMachine(input: EnrollMachineInput, actor: string): MachineRecord {
    if (!/^[A-Za-z0-9._-]+$/.test(input.id)) throw new Error('invalid machine id');
    const fingerprint = input.certificateFingerprint.toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw new Error('invalid certificate fingerprint');
    const now = new Date().toISOString();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare(
        `INSERT INTO machines(
          id, display_name, certificate_fingerprint, status,
          last_seen_at, enrolled_at, revoked_at, metadata_json
        ) VALUES(?,?,?,'ENROLLED',NULL,?,NULL,?)`
      ).run(input.id, input.displayName, fingerprint, now, JSON.stringify(input.metadata ?? {}));
      this.appendAudit({
        action: 'machine.enroll',
        actor,
        target: input.id,
        detail: { certificateFingerprint: fingerprint, displayName: input.displayName }
      });
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
    return this.requireMachine(input.id);
  }

  getMachine(id: string): MachineRecord | undefined {
    const row = this.db.prepare('SELECT * FROM machines WHERE id=?').get(id) as unknown as MachineRow | undefined;
    return row ? this.mapMachine(row) : undefined;
  }

  findMachineByFingerprint(fingerprint: string): MachineRecord | undefined {
    const row = this.db.prepare(
      'SELECT * FROM machines WHERE certificate_fingerprint=?'
    ).get(fingerprint.toLowerCase()) as unknown as MachineRow | undefined;
    return row ? this.mapMachine(row) : undefined;
  }

  listMachines(): MachineRecord[] {
    const rows = this.db.prepare('SELECT * FROM machines ORDER BY id').all() as unknown as MachineRow[];
    return rows.map((row) => this.mapMachine(row));
  }

  heartbeatMachine(id: string, metadata: Record<string, unknown> = {}): MachineRecord {
    const current = this.requireMachine(id);
    if (current.status === 'REVOKED') throw new Error('machine is revoked');
    const now = new Date().toISOString();
    this.db.prepare(
      "UPDATE machines SET status='ONLINE', last_seen_at=?, metadata_json=? WHERE id=?"
    ).run(now, JSON.stringify(metadata), id);
    this.appendAudit({
      action: 'machine.heartbeat',
      actor: id,
      target: id,
      detail: { status: 'ONLINE' }
    });
    return this.requireMachine(id);
  }

  revokeMachine(id: string, actor: string): boolean {
    const now = new Date().toISOString();
    const changed = this.db.prepare(
      "UPDATE machines SET status='REVOKED', revoked_at=? WHERE id=? AND status!='REVOKED'"
    ).run(now, id);
    if (changed.changes !== 1) return false;
    this.appendAudit({ action: 'machine.revoke', actor, target: id });
    return true;
  }

  setMachineCapabilities(id: string, capabilities: MachineCapability[], actor: string): void {
    this.requireMachine(id);
    const unique = [...new Set(capabilities)].sort();
    for (const capability of unique) {
      if (!(MACHINE_CAPABILITIES as readonly string[]).includes(capability)) {
        throw new Error(`invalid machine capability: ${capability}`);
      }
    }

    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare('DELETE FROM machine_capabilities WHERE machine_id=?').run(id);
      const insertCapability = this.db.prepare(
        'INSERT INTO machine_capabilities(machine_id, capability) VALUES(?,?)'
      );
      for (const capability of unique) insertCapability.run(id, capability);
      this.appendAudit({
        action: 'machine.capabilities',
        actor,
        target: id,
        detail: { capabilities: unique }
      });
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  machineHasCapability(id: string, capability: MachineCapability): boolean {
    const row = this.db.prepare(
      `SELECT 1 AS allowed
       FROM machine_capabilities c
       JOIN machines m ON m.id=c.machine_id
       WHERE c.machine_id=? AND c.capability=? AND m.status!='REVOKED'`
    ).get(id, capability) as unknown as { allowed: number } | undefined;
    return row !== undefined;
  }

  consumePrivilegedNonce(
    nonce: string,
    now = Date.now(),
    ttlMs = 120_000
  ): boolean {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare(
        'DELETE FROM privileged_nonces WHERE expires_at<=?'
      ).run(now);
      const result = this.db.prepare(
        'INSERT OR IGNORE INTO privileged_nonces(nonce, expires_at) VALUES(?,?)'
      ).run(nonce, now + ttlMs);
      this.db.exec('COMMIT');
      return result.changes === 1;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  acquireLease(resource: string, owner: string, ttlMs: number): boolean {
    const now = Date.now();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare('DELETE FROM leases WHERE resource=? AND expires_at<=?').run(resource, now);
      const result = this.db.prepare(
        'INSERT OR IGNORE INTO leases(resource, owner, expires_at) VALUES(?,?,?)'
      ).run(resource, owner, now + ttlMs);
      if (result.changes === 1) {
        this.appendAudit({
          action: 'lease.acquire',
          actor: owner,
          target: resource,
          detail: { expiresAt: now + ttlMs }
        });
      }
      this.db.exec('COMMIT');
      return result.changes === 1;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  private requireMachine(id: string): MachineRecord {
    const machine = this.getMachine(id);
    if (!machine) throw new Error('machine not found');
    return machine;
  }

  private mapMachine(row: MachineRow): MachineRecord {
    const capabilityRows = this.db.prepare(
      'SELECT capability FROM machine_capabilities WHERE machine_id=? ORDER BY capability'
    ).all(row.id) as unknown as Array<{ capability: MachineCapability }>;
    return {
      id: row.id,
      displayName: row.display_name,
      certificateFingerprint: row.certificate_fingerprint,
      status: row.status,
      lastSeenAt: row.last_seen_at,
      enrolledAt: row.enrolled_at,
      revokedAt: row.revoked_at,
      metadata: JSON.parse(row.metadata_json) as Record<string, unknown>,
      capabilities: capabilityRows.map((item) => item.capability)
    };
  }

  private mapJob(row: JobRow): JobRecord {
    return {
      id: row.id,
      kind: row.kind,
      payload: JSON.parse(row.payload_json) as Record<string, unknown>,
      status: row.status,
      owner: row.owner,
      result: row.result_json === null ? null : JSON.parse(row.result_json),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      executionScope: row.execution_scope,
      targetMachineId: row.target_machine_id,
      requiredCapability: row.required_capability,
      leaseOwner: row.lease_owner,
      leaseExpiresAt: row.lease_expires_at,
      priority: row.priority,
      reassignable: row.reassignable === 1
    };
  }
}
