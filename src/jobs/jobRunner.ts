import type { BrainStore, JobRecord } from '../brain/store.js';
import type { LocalExecutor } from '../executor/localExecutor.js';

export interface JobRunnerOptions {
  timeoutMs: number;
  maxOutputBytes: number;
}

export class JobRunner {
  constructor(
    private readonly store: BrainStore,
    private readonly executor: Pick<LocalExecutor, 'exec'>,
    private readonly options: JobRunnerOptions
  ) {}

  async runOnce(workerId: string): Promise<boolean> {
    const job = this.store.claimNextJob(workerId);
    if (!job) return false;
    await this.executeClaimed(job, workerId);
    return true;
  }

  async runJob(id: string, workerId: string): Promise<boolean> {
    if (!this.store.claimJob(id, workerId)) return false;
    const job = this.store.getJob(id);
    if (!job) return false;
    await this.executeClaimed(job, workerId);
    return true;
  }

  reconcileOnStartup(): number {
    const running = this.store.listLocalJobsByStatus('RUNNING');
    let reconciled = 0;
    for (const job of running) {
      if (this.isLiveLocalOwner(job.owner)) continue;
      if (this.store.finishJob(job.id, 'FAILED', { reason: 'orphaned_after_restart' })) {
        this.store.appendEvent({
          type: 'JOB_FAILED',
          subject: job.id,
          data: { reason: 'orphaned_after_restart' }
        });
        reconciled += 1;
      }
    }
    return reconciled;
  }

  private isLiveLocalOwner(owner: string | null): boolean {
    const match = /^pid:(\d+)$/.exec(owner ?? '');
    if (!match) return false;
    const pid = Number(match[1]);
    if (!Number.isSafeInteger(pid) || pid <= 0) return false;
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  }

  private async executeClaimed(job: JobRecord, workerId: string): Promise<void> {
    this.store.appendEvent({
      type: 'JOB_STARTED',
      subject: job.id,
      data: { workerId, kind: job.kind }
    });

    try {
      const result = await this.execute(job);
      const status = result.exitCode === 0 && !result.timedOut ? 'SUCCEEDED' : 'FAILED';
      this.store.finishJob(job.id, status, result);
      this.store.appendEvent({
        type: status === 'SUCCEEDED' ? 'JOB_SUCCEEDED' : 'JOB_FAILED',
        subject: job.id,
        data: {
          workerId,
          exitCode: result.exitCode,
          timedOut: result.timedOut,
          truncated: result.truncated
        }
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.store.finishJob(job.id, 'FAILED', {
        reason: 'executor_error',
        message
      });
      this.store.appendEvent({
        type: 'JOB_FAILED',
        subject: job.id,
        data: { workerId, reason: 'executor_error' }
      });
    }
  }

  private execute(job: JobRecord) {
    if (job.kind !== 'exec') {
      throw new Error(`unsupported job kind: ${job.kind}`);
    }
    const command = job.payload.command;
    if (typeof command !== 'string' || command.length === 0) {
      throw new Error('exec job requires a non-empty command');
    }
    return this.executor.exec({
      command,
      timeoutMs: this.options.timeoutMs,
      maxOutputBytes: this.options.maxOutputBytes
    });
  }
}
