import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import path from 'node:path';
import type { NexusConfig } from '../config.js';

function findProjectRoot(start: string): string {
  let current = start;
  for (let depth = 0; depth < 6; depth += 1) {
    if (existsSync(path.join(current, 'package.json'))) return current;
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  throw new Error('unable to locate Nexus Commander project root');
}

export function spawnDetachedJobWorker(config: NexusConfig, jobId: string): number {
  const root = findProjectRoot(import.meta.dirname);
  const tsx = path.join(root, 'node_modules', '.bin', 'tsx');
  const worker = path.join(root, 'src', 'jobs', 'worker.ts');
  if (!existsSync(tsx)) throw new Error(`tsx executable not found: ${tsx}`);
  if (!existsSync(worker)) throw new Error(`job worker not found: ${worker}`);

  const child = spawn(tsx, [worker, jobId], {
    cwd: root,
    detached: true,
    stdio: 'ignore',
    env: {
      ...process.env,
      NEXUS_STATE_DIR: config.stateDir,
      NEXUS_DB_PATH: config.dbPath,
      NEXUS_LOG_DIR: config.logDir,
      NEXUS_COMMAND_TIMEOUT_MS: String(config.commandTimeoutMs),
      NEXUS_MAX_OUTPUT_BYTES: String(config.maxOutputBytes),
      NEXUS_LOGRES_ROOT: config.logresRoot
    }
  });

  child.unref();
  if (child.pid === undefined) throw new Error('failed to start detached job worker');
  return child.pid;
}
