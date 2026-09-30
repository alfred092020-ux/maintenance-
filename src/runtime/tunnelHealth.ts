import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface TunnelHealth {
  running: boolean;
  healthy: boolean;
  ready: boolean;
  state: string;
  profile: string;
  tunnelId?: string;
  diagnostic?: string;
}

export function parseTunnelStatus(raw: string): TunnelHealth {
  if (!raw.trim()) return { running: false, healthy: false, ready: false, state: 'unavailable', profile: 'nexus-commander' };
  try {
    const value = JSON.parse(raw) as Record<string, unknown>;
    return {
      running: value.process_running === true,
      healthy: value.healthy === true,
      ready: value.ready === true,
      state: typeof value.runtime_state === 'string' ? value.runtime_state : 'unknown',
      profile: typeof value.profile === 'string' ? value.profile : 'nexus-commander',
      ...(typeof value.tunnel_id === 'string' ? { tunnelId: value.tunnel_id } : {})
    };
  } catch {
    return { running: false, healthy: false, ready: false, state: 'invalid-status', profile: 'nexus-commander', diagnostic: 'tunnel status was not valid JSON' };
  }
}

export function tunnelStatusArgs(): string[] { return ['runtimes', 'status', 'nexus-commander', '--json']; }

export async function readTunnelHealth(): Promise<TunnelHealth> {
  const binary = process.env.NEXUS_TUNNEL_CLIENT ?? '/home/ubuntu/.local/bin/tunnel-client';
  try {
    const { stdout } = await execFileAsync(binary, tunnelStatusArgs(), { timeout: 10_000, maxBuffer: 256 * 1024 });
    return parseTunnelStatus(stdout);
  } catch (error) {
    return { running: false, healthy: false, ready: false, state: 'unavailable', profile: 'nexus-commander', diagnostic: error instanceof Error ? error.message.slice(0, 512) : 'status failed' };
  }
}
