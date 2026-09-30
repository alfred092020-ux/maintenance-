import {
  freemem,
  hostname,
  loadavg,
  platform,
  release,
  totalmem,
  uptime
} from 'node:os';
import { readFileSync } from 'node:fs';
import { AgentClient } from './client.js';
import { RemoteJobExecutor, runAgentJobCycle } from './jobExecutor.js';

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`missing required environment variable: ${name}`);
  return value;
}

function numberSetting(
  name: string,
  fallback: number,
  min: number,
  max: number
): number {
  const value = Number(process.env[name] ?? fallback);
  if (!Number.isFinite(value) || value < min || value > max) {
    throw new Error(`invalid ${name}`);
  }
  return value;
}

function telemetry(): Record<string, unknown> {
  const total = totalmem();
  const free = freemem();
  return {
    hostname: hostname(),
    platform: platform(),
    release: release(),
    uptimeSeconds: Math.floor(uptime()),
    loadAverage: loadavg(),
    memoryTotalBytes: total,
    memoryFreeBytes: free,
    memoryUsedPercent: Math.round(((total - free) / total) * 100)
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function main(): Promise<void> {
  const host = required('NEXUS_CONTROL_HOST');
  const port = Number(required('NEXUS_CONTROL_PORT'));
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error('invalid NEXUS_CONTROL_PORT');
  }

  const client = new AgentClient({
    host,
    port,
    ca: readFileSync(required('NEXUS_AGENT_CA_PATH')),
    cert: readFileSync(required('NEXUS_AGENT_CERT_PATH')),
    key: readFileSync(required('NEXUS_AGENT_KEY_PATH')),
    ...(process.env.NEXUS_CONTROL_SERVERNAME
      ? { servername: process.env.NEXUS_CONTROL_SERVERNAME }
      : {}),
    timeoutMs: 30_000
  });

  const pollMs = numberSetting(
    'NEXUS_AGENT_POLL_MS',
    Number(process.env.NEXUS_AGENT_HEARTBEAT_MS ?? 5_000),
    500,
    60_000
  );
  const leaseMs = numberSetting(
    'NEXUS_AGENT_JOB_LEASE_MS',
    30_000,
    1_000,
    900_000
  );
  const heartbeatEveryMs = Math.max(
    250,
    Math.min(Math.floor(leaseMs / 3), leaseMs - 100)
  );
  const maxTimeoutMs = numberSetting(
    'NEXUS_AGENT_MAX_JOB_TIMEOUT_MS',
    900_000,
    1_000,
    3_600_000
  );
  const maxOutputBytes = numberSetting(
    'NEXUS_AGENT_MAX_OUTPUT_BYTES',
    1024 * 1024,
    1024,
    16 * 1024 * 1024
  );

  const executor = new RemoteJobExecutor({
    defaultTimeoutMs: Math.min(120_000, maxTimeoutMs),
    maxTimeoutMs,
    defaultMaxOutputBytes: maxOutputBytes,
    maxOutputBytes
  });

  let stopping = false;
  const stop = () => {
    stopping = true;
  };
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);

  await client.identity();

  let backoffMs = 1_000;
  while (!stopping) {
    try {
      await client.heartbeat(telemetry());
      const worked = await runAgentJobCycle(client, executor, {
        leaseMs,
        heartbeatEveryMs
      });
      backoffMs = 1_000;
      if (!worked && !stopping) await sleep(pollMs);
    } catch (error) {
      console.error(error instanceof Error ? error.message : String(error));
      if (!stopping) {
        await sleep(backoffMs);
        backoffMs = Math.min(backoffMs * 2, 30_000);
      }
    }
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
