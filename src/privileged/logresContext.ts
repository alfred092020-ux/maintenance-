import { openReadOnlyDatabase } from '../brain/db.js';

export interface LogresLeaseContext {
  taskId: string;
  workerId: string;
  branch: string;
  expiresAt: number;
}

export class LogresPrivilegeContextResolver {
  constructor(
    private readonly dbPath: string,
    private readonly now: () => number = Date.now
  ) {}

  resolve(taskId: string, workerId: string, branch: string): LogresLeaseContext | null {
    let db: ReturnType<typeof openReadOnlyDatabase>;
    try {
      db = openReadOnlyDatabase(this.dbPath);
    } catch {
      return null;
    }
    if (!db) return null;
    try {
      const row = db.prepare(`
        SELECT task_id, chat_id, COALESCE(branch, '') AS branch, lease_until_epoch
        FROM brain_task_leases
        WHERE task_id=?
        LIMIT 1
      `).get(taskId) as unknown as {
        task_id: string;
        chat_id: string;
        branch: string;
        lease_until_epoch: number;
      } | undefined;
      if (!row) return null;
      const expiresAt = Math.floor(Number(row.lease_until_epoch) * 1000);
      if (!Number.isFinite(expiresAt) || expiresAt <= this.now()) return null;
      if (row.chat_id !== workerId || row.branch !== branch) return null;
      return {
        taskId: row.task_id,
        workerId: row.chat_id,
        branch: row.branch,
        expiresAt
      };
    } catch {
      return null;
    } finally {
      db.close();
    }
  }
}
