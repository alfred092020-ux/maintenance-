import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdir, open, rename, stat } from 'node:fs/promises';
import path from 'node:path';
import type { AuditInput, BrainStore } from '../brain/store.js';
import { redactText } from '../security/redact.js';

export interface ExecInput {
  command: string;
  timeoutMs: number;
  maxOutputBytes: number;
}

export interface ExecResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
  durationMs: number;
}

export interface FileReadResult {
  content: string;
  bytes: number;
  totalBytes: number;
  truncated: boolean;
}

type AuditSink = Pick<BrainStore, 'appendAudit'> | { appendAudit(audit: AuditInput): number };

export class LocalExecutor {
  constructor(
    private readonly auditSink: AuditSink,
    private readonly actor = 'nexus'
  ) {}

  async execReadOnly(input: ExecInput): Promise<ExecResult> {
    return this.execInternal(input, false);
  }

  async exec(input: ExecInput): Promise<ExecResult> {
    return this.execInternal(input, true);
  }

  private async execInternal(input: ExecInput, audit: boolean): Promise<ExecResult> {
    const started = Date.now();
    const child = spawn('/bin/bash', ['-lc', input.command], {
      detached: true,
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let stdout: Buffer = Buffer.alloc(0);
    let stderr: Buffer = Buffer.alloc(0);
    let truncated = false;
    let timedOut = false;
    let killTimer: NodeJS.Timeout | undefined;

    const capture = (current: Buffer, chunk: Buffer): Buffer => {
      const used = stdout.length + stderr.length;
      const remaining = Math.max(0, input.maxOutputBytes - used);
      if (chunk.length > remaining) truncated = true;
      if (remaining === 0) return current;
      return Buffer.concat([current, chunk.subarray(0, remaining)]);
    };

    child.stdout.on('data', (chunk: Buffer) => {
      stdout = capture(stdout, chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr = capture(stderr, chunk);
    });

    const timeout = setTimeout(() => {
      timedOut = true;
      if (child.pid === undefined) return;
      try {
        process.kill(-child.pid, 'SIGTERM');
      } catch {
        return;
      }
      killTimer = setTimeout(() => {
        if (child.pid === undefined) return;
        try {
          process.kill(-child.pid, 'SIGKILL');
        } catch {
          // Process group already exited.
        }
      }, 750);
    }, input.timeoutMs);

    const result = await new Promise<ExecResult>((resolve, reject) => {
      child.once('error', reject);
      child.once('close', (exitCode, signal) => {
        clearTimeout(timeout);
        if (killTimer) clearTimeout(killTimer);
        resolve({
          exitCode,
          signal,
          stdout: redactText(stdout.toString('utf8')),
          stderr: redactText(stderr.toString('utf8')),
          truncated,
          timedOut,
          durationMs: Date.now() - started
        });
      });
    });

    if (audit) this.auditSink.appendAudit({
      action: 'command.exec',
      actor: this.actor,
      target: 'local-shell',
      detail: {
        command: redactText(input.command),
        exitCode: result.exitCode,
        signal: result.signal,
        truncated: result.truncated,
        timedOut: result.timedOut,
        durationMs: result.durationMs
      }
    });
    return result;
  }

  async readFile(filePath: string, maxBytes: number): Promise<FileReadResult> {
    const info = await stat(filePath);
    const handle = await open(filePath, 'r');
    try {
      const bytesToRead = Math.min(info.size, maxBytes);
      const buffer = Buffer.alloc(bytesToRead);
      const { bytesRead } = await handle.read(buffer, 0, bytesToRead, 0);
      return {
        content: buffer.subarray(0, bytesRead).toString('utf8'),
        bytes: bytesRead,
        totalBytes: info.size,
        truncated: info.size > bytesRead
      };
    } finally {
      await handle.close();
    }
  }

  async writeFile(filePath: string, content: string): Promise<void> {
    await mkdir(path.dirname(filePath), { recursive: true });
    const tempPath = path.join(
      path.dirname(filePath),
      `.${path.basename(filePath)}.nexus-${randomUUID()}.tmp`
    );
    const data = Buffer.from(content, 'utf8');
    const handle = await open(tempPath, 'w');
    try {
      await handle.writeFile(data);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(tempPath, filePath);

    this.auditSink.appendAudit({
      action: 'file.write',
      actor: this.actor,
      target: filePath,
      detail: {
        bytes: data.length,
        sha256: createHash('sha256').update(data).digest('hex')
      }
    });
  }
}
