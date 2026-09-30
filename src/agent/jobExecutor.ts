import type { AgentClient } from './client.js';
import { LocalExecutor, type ExecResult } from '../executor/localExecutor.js';
import { redactText } from '../security/redact.js';

export interface AgentRemoteJob {
  id: string;
  kind: string;
  payload: Record<string, unknown>;
}

export interface RemoteJobExecution {
  status: 'SUCCEEDED' | 'FAILED';
  result: ExecResult;
}

export interface RemoteJobExecutorOptions {
  defaultTimeoutMs: number;
  maxTimeoutMs: number;
  defaultMaxOutputBytes: number;
  maxOutputBytes: number;
}

const DEFAULT_OPTIONS: RemoteJobExecutorOptions = {
  defaultTimeoutMs: 120_000,
  maxTimeoutMs: 900_000,
  defaultMaxOutputBytes: 1024 * 1024,
  maxOutputBytes: 1024 * 1024
};

const nullAuditSink = {
  appendAudit() {
    return 0;
  }
};

export class RemoteJobExecutor {
  private readonly options: RemoteJobExecutorOptions;
  private readonly executor: LocalExecutor;

  constructor(options: Partial<RemoteJobExecutorOptions> = {}) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.executor = new LocalExecutor(nullAuditSink, 'remote-agent');
  }

  async execute(job: AgentRemoteJob): Promise<RemoteJobExecution> {
    if (job.kind !== 'remote.exec') {
      throw new Error('unsupported remote job kind');
    }

    const command = job.payload.command;
    if (
      typeof command !== 'string' ||
      command.length === 0 ||
      command.length > 64 * 1024
    ) {
      throw new Error('invalid remote job command');
    }

    const timeoutMs =
      job.payload.timeoutMs === undefined
        ? this.options.defaultTimeoutMs
        : Number(job.payload.timeoutMs);
    if (
      !Number.isInteger(timeoutMs) ||
      timeoutMs < 1 ||
      timeoutMs > this.options.maxTimeoutMs
    ) {
      throw new Error('invalid remote job timeout');
    }

    const maxOutputBytes =
      job.payload.maxOutputBytes === undefined
        ? this.options.defaultMaxOutputBytes
        : Number(job.payload.maxOutputBytes);
    if (
      !Number.isInteger(maxOutputBytes) ||
      maxOutputBytes < 1 ||
      maxOutputBytes > this.options.maxOutputBytes
    ) {
      throw new Error('invalid remote job output limit');
    }

    const result = await this.executor.exec({
      command,
      timeoutMs,
      maxOutputBytes
    });

    return {
      status:
        result.exitCode === 0 && !result.timedOut
          ? 'SUCCEEDED'
          : 'FAILED',
      result
    };
  }
}

export interface AgentJobClient {
  leaseJob(
    leaseMs?: number,
    capabilities?: string[]
  ): Promise<Record<string, unknown>>;
  heartbeatJob(
    jobId: string,
    leaseMs?: number
  ): Promise<Record<string, unknown>>;
  finishJob(
    jobId: string,
    input: {
      status: 'SUCCEEDED' | 'FAILED';
      result: unknown;
    }
  ): Promise<Record<string, unknown>>;
}

export interface AgentJobCycleOptions {
  leaseMs: number;
  heartbeatEveryMs: number;
}

const DEFAULT_CYCLE: AgentJobCycleOptions = {
  leaseMs: 30_000,
  heartbeatEveryMs: 10_000
};

export async function runAgentJobCycle(
  client: AgentJobClient | Pick<AgentClient, 'leaseJob' | 'heartbeatJob' | 'finishJob'>,
  executor: RemoteJobExecutor,
  options: Partial<AgentJobCycleOptions> = {}
): Promise<boolean> {
  const settings = { ...DEFAULT_CYCLE, ...options };
  const leased = await client.leaseJob(
    settings.leaseMs,
    ['AUTONOMOUS_EXEC']
  );
  const candidate = leased.job;

  if (candidate === null || candidate === undefined) return false;
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
    throw new Error('invalid leased job response');
  }

  const record = candidate as Record<string, unknown>;
  if (
    typeof record.id !== 'string' ||
    typeof record.kind !== 'string' ||
    !record.payload ||
    typeof record.payload !== 'object' ||
    Array.isArray(record.payload)
  ) {
    throw new Error('invalid leased job payload');
  }

  const job: AgentRemoteJob = {
    id: record.id,
    kind: record.kind,
    payload: record.payload as Record<string, unknown>
  };

  const heartbeatTimer = setInterval(() => {
    void client
      .heartbeatJob(job.id, settings.leaseMs)
      .catch(() => undefined);
  }, settings.heartbeatEveryMs);

  try {
    let execution: {
      status: 'SUCCEEDED' | 'FAILED';
      result: unknown;
    };
    try {
      execution = await executor.execute(job);
    } catch (error) {
      execution = {
        status: 'FAILED',
        result: {
          error: redactText(
            error instanceof Error ? error.message : String(error)
          )
        }
      };
    }

    await client.finishJob(job.id, execution);
    return true;
  } finally {
    clearInterval(heartbeatTimer);
  }
}
