import { chmod, chown, lstat, readFile, realpath, rename, unlink, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { redactText } from '../security/redact.js';
import type { PrivilegedOperation } from './protocol.js';

export interface PrivilegedExecResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
  durationMs: number;
}

export type PrivilegedOperationResult =
  | PrivilegedExecResult
  | { ok: true }
  | { taskId: string; branch: string; sha: string; changedPaths: string[] };

export interface PrivilegedOperationExecutor {
  execute(
    operation: PrivilegedOperation,
    payload: unknown
  ): Promise<PrivilegedOperationResult>;
}

interface RunArgvInput {
  executable: string;
  argv: string[];
  cwd?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

export interface VerifiedInstallBoundary {
  sourceRoots: readonly string[];
  destinationRoots: readonly string[];
}

const DEFAULT_VERIFIED_INSTALL_BOUNDARY: VerifiedInstallBoundary = {
  sourceRoots: ['/home/ubuntu/logres/staging'],
  destinationRoots: ['/etc/systemd/system', '/etc/apparmor.d']
};

const LOGRES_MANAGED_SERVICE_RE = /^logres-[A-Za-z0-9@_.:-]+\.service$/;
const NEXUS_MANAGED_SERVICE_RE = /^nexus-(?:tunnel@ubuntu|privileged-executor|agent|control-plane@ubuntu)\.service$/;
const MANAGED_PROFILE_RE = /^logres-[A-Za-z0-9._-]+$/;
const SERVICE_ACTIONS = new Set(['status', 'start', 'stop', 'restart']);
const MAX_VERIFIED_INSTALL_BYTES = 1024 * 1024;

function exactKeys(payload: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('invalid structured payload');
  const value = payload as Record<string, unknown>;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error('unexpected privileged payload field');
  }
  return value;
}


interface LogresWorkerLifecyclePayload { action: 'start' | 'release'; chatId: string; taskId: string; branch?: string; note?: string; }
function requireLogresWorkerLifecyclePayload(payload: unknown): LogresWorkerLifecyclePayload {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('invalid Logres worker lifecycle payload');
  const value = payload as Record<string, unknown>;
  const id = /^[A-Za-z0-9._:-]+$/;
  const branch = /^worker\/[A-Za-z0-9._\/-]+$/;
  if (value.action === 'start') {
    exactKeys(payload, value.branch === undefined ? ['action','chatId','taskId'] : ['action','branch','chatId','taskId']);
    if (typeof value.chatId !== 'string' || !id.test(value.chatId) || typeof value.taskId !== 'string' || !id.test(value.taskId)) throw new Error('invalid Logres worker identity');
    if (value.branch !== undefined && (typeof value.branch !== 'string' || !branch.test(value.branch))) throw new Error('invalid Logres worker branch');
    return { action: 'start', chatId: value.chatId, taskId: value.taskId, ...(value.branch === undefined ? {} : { branch: value.branch as string }) };
  }
  if (value.action === 'release') {
    exactKeys(payload, ['action','chatId','note','taskId']);
    if (typeof value.chatId !== 'string' || !id.test(value.chatId) || typeof value.taskId !== 'string' || !id.test(value.taskId) || typeof value.note !== 'string' || value.note.length < 1 || value.note.length > 2048) throw new Error('invalid Logres worker release');
    return { action: 'release', chatId: value.chatId, taskId: value.taskId, note: value.note };
  }
  throw new Error('invalid Logres worker lifecycle action');
}

interface LogresPreflightPayload { action: 'status' | 'run' | 'apply'; max?: number; id?: number; }

function requireLogresPreflightPayload(payload: unknown): LogresPreflightPayload {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) throw new Error('invalid Logres preflight payload');
  const value = payload as Record<string, unknown>;
  if (value.action === 'status') {
    exactKeys(payload, ['action']);
    return { action: 'status' };
  }
  if (value.action === 'run') {
    exactKeys(payload, ['action', 'max']);
    if (!Number.isInteger(value.max) || (value.max as number) < 1 || (value.max as number) > 8) throw new Error('invalid Logres preflight max');
    return { action: 'run', max: value.max as number };
  }
  if (value.action === 'apply') {
    exactKeys(payload, ['action', 'id']);
    if (!Number.isInteger(value.id) || (value.id as number) < 1) throw new Error('invalid Logres preflight id');
    return { action: 'apply', id: value.id as number };
  }
  throw new Error('invalid Logres preflight action');
}

function insideRoot(candidate: string, root: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === '' || (!relative.startsWith('..' + path.sep) && relative !== '..' && !path.isAbsolute(relative));
}



const ISOLATION_NAME_RE = /^[A-Za-z0-9._-]{1,48}$/;

function requireIsolationName(payload: unknown): string {
  const value = (payload as { isolationName?: unknown })?.isolationName;
  if (typeof value !== 'string' || !ISOLATION_NAME_RE.test(value)) {
    throw new Error('invalid Logres Devin isolation name');
  }
  return value;
}

function safeUnitComponent(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 48) || 'worker';
}

function safeNftComponent(value: string): string {
  return value.replace(/[^A-Za-z0-9_]+/g, '_').replace(/^_+|_+$/g, '') || 'worker';
}

function ipv4(value: number): string {
  const n = value >>> 0;
  return [24, 16, 8, 0].map((shift) => (n >>> shift) & 255).join('.');
}

function logresDevinNetworkIdentity(isolationName: string) {
  const name = safeUnitComponent(isolationName);
  const digest = createHash('sha256').update(name).digest('hex');
  const index = Number.parseInt(digest.slice(0, 8), 16) % 16384;
  const suffix = index.toString(16).padStart(4, '0');
  const base = (10 * 2 ** 24) + (210 * 2 ** 16) + (index * 4);
  return {
    netns: `logres-devin-${name.slice(0, 15)}-${digest.slice(0, 8)}`,
    table: `logres_devin_${safeNftComponent(name).slice(0, 23)}_${digest.slice(0, 8)}`,
    vethHost: `ldv${suffix}h`,
    vethGuest: `ldv${suffix}n`,
    hostIp: ipv4(base + 1),
    guestIp: ipv4(base + 2)
  };
}

function logresDevinProvisionPlan(isolationName: string): RunArgvInput[] {
  const id = logresDevinNetworkIdentity(isolationName);
  const plan: RunArgvInput[] = [
    { executable: '/usr/sbin/ip', argv: ['netns', 'add', id.netns] },
    { executable: '/usr/sbin/ip', argv: ['link', 'add', id.vethHost, 'type', 'veth', 'peer', 'name', id.vethGuest] },
    { executable: '/usr/sbin/ip', argv: ['link', 'set', id.vethGuest, 'netns', id.netns] },
    { executable: '/usr/sbin/ip', argv: ['addr', 'add', `${id.hostIp}/30`, 'dev', id.vethHost] },
    { executable: '/usr/sbin/ip', argv: ['link', 'set', id.vethHost, 'up'] },
    { executable: '/usr/sbin/ip', argv: ['-n', id.netns, 'addr', 'add', `${id.guestIp}/30`, 'dev', id.vethGuest] },
    { executable: '/usr/sbin/ip', argv: ['-n', id.netns, 'link', 'set', id.vethGuest, 'up'] },
    { executable: '/usr/sbin/ip', argv: ['-n', id.netns, 'link', 'set', 'lo', 'up'] },
    { executable: '/usr/sbin/ip', argv: ['-n', id.netns, 'route', 'add', 'default', 'via', id.hostIp] },
    { executable: '/usr/sbin/nft', argv: ['add', 'table', 'inet', id.table] },
    { executable: '/usr/sbin/nft', argv: ['add', 'chain', 'inet', id.table, 'worker_in', '{', 'type', 'filter', 'hook', 'input', 'priority', '-10', ';', '}'] },
    { executable: '/usr/sbin/nft', argv: ['add', 'chain', 'inet', id.table, 'worker_fwd', '{', 'type', 'filter', 'hook', 'forward', 'priority', '-10', ';', '}'] },
    { executable: '/usr/sbin/nft', argv: ['add', 'chain', 'inet', id.table, 'worker_nat', '{', 'type', 'nat', 'hook', 'postrouting', 'priority', '100', ';', '}'] }
  ];
  const deny4 = ['169.254.169.254/32', '169.254.0.0/16', '127.0.0.0/8'];
  const deny6 = ['fd00:ec2::254/128', '::1/128', 'fe80::/10'];
  for (const chain of ['worker_in', 'worker_fwd']) {
    plan.push({ executable: '/usr/sbin/nft', argv: ['add', 'rule', 'inet', id.table, chain, 'iifname', id.vethHost, 'ip', 'daddr', '169.254.169.254', 'udp', 'dport', '53', 'accept'] });
    plan.push({ executable: '/usr/sbin/nft', argv: ['add', 'rule', 'inet', id.table, chain, 'iifname', id.vethHost, 'ip', 'daddr', '169.254.169.254', 'tcp', 'dport', '53', 'accept'] });
    for (const cidr of deny4) {
      plan.push({ executable: '/usr/sbin/nft', argv: ['add', 'rule', 'inet', id.table, chain, 'iifname', id.vethHost, 'ip', 'daddr', cidr, 'drop'] });
    }
    for (const cidr of deny6) {
      plan.push({ executable: '/usr/sbin/nft', argv: ['add', 'rule', 'inet', id.table, chain, 'iifname', id.vethHost, 'ip6', 'daddr', cidr, 'drop'] });
    }
  }
  plan.push({ executable: '/usr/sbin/nft', argv: ['add', 'rule', 'inet', id.table, 'worker_nat', 'oifname', '!=', id.vethHost, 'ip', 'saddr', id.guestIp, 'masquerade'] });
  plan.push({ executable: '/usr/sbin/iptables', argv: ['-w', '5', '-I', 'FORWARD', '1', '-i', id.vethHost, '-j', 'ACCEPT'] });
  plan.push({ executable: '/usr/sbin/iptables', argv: ['-w', '5', '-I', 'FORWARD', '1', '-o', id.vethHost, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'] });
  plan.push({ executable: '/usr/sbin/sysctl', argv: ['-w', 'net.ipv4.ip_forward=1'] });
  return plan;
}

function logresDevinTeardownPlan(isolationName: string): RunArgvInput[] {
  const id = logresDevinNetworkIdentity(isolationName);
  return [
    { executable: '/usr/sbin/iptables', argv: ['-w', '5', '-D', 'FORWARD', '-i', id.vethHost, '-j', 'ACCEPT'] },
    { executable: '/usr/sbin/iptables', argv: ['-w', '5', '-D', 'FORWARD', '-o', id.vethHost, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-j', 'ACCEPT'] },
    { executable: '/usr/sbin/nft', argv: ['delete', 'table', 'inet', id.table] },
    { executable: '/usr/sbin/ip', argv: ['link', 'delete', id.vethHost] },
    { executable: '/usr/sbin/ip', argv: ['netns', 'delete', id.netns] }
  ];
}


interface LogresDevinStartPayload {
  taskId: string;
  workerId: string;
  branch: string;
  worktree: string;
  jobId: number;
  model: 'swe-2-max' | 'swe-2-high' | 'swe-2-medium';
  permissionMode: 'smart' | 'autonomous';
}

const LOGRES_ID_RE = /^[A-Za-z0-9._:-]+$/;
const LOGRES_BRANCH_RE = /^worker\/[A-Za-z0-9._\/-]+$/;
const LOGRES_WORKTREE_RE = /^\/home\/ubuntu\/logres\/work\/[A-Za-z0-9._-]+$/;
const FREE_DEVIN_MODELS = new Set(['swe-2-max', 'swe-2-high', 'swe-2-medium']);

function requireLogresDevinStartPayload(payload: unknown): LogresDevinStartPayload {
  const p = payload as Partial<LogresDevinStartPayload>;
  if (!p || typeof p !== 'object') throw new Error('invalid Logres Devin start payload');
  if (typeof p.taskId !== 'string' || !LOGRES_ID_RE.test(p.taskId)) throw new Error('invalid Logres Devin task id');
  if (typeof p.workerId !== 'string' || !LOGRES_ID_RE.test(p.workerId)) throw new Error('invalid Logres Devin worker id');
  if (typeof p.branch !== 'string' || !LOGRES_BRANCH_RE.test(p.branch)) throw new Error('invalid Logres Devin branch');
  if (typeof p.worktree !== 'string' || !LOGRES_WORKTREE_RE.test(p.worktree)) throw new Error('invalid Logres Devin worktree');
  if (!Number.isInteger(p.jobId) || Number(p.jobId) <= 0) throw new Error('invalid Logres Devin job id');
  if (typeof p.model !== 'string' || !FREE_DEVIN_MODELS.has(p.model)) throw new Error('invalid or paid Devin model');
  if (p.permissionMode !== 'smart' && p.permissionMode !== 'autonomous') {
    throw new Error('unsafe Devin permission mode');
  }
  return p as LogresDevinStartPayload;
}

function logresDevinUnit(isolationName: string): string {
  return `logres-devin-${safeUnitComponent(isolationName)}.service`;
}

function logresDevinSystemdRunPlan(payload: LogresDevinStartPayload): RunArgvInput {
  const worktreeName = payload.worktree.split('/').at(-1) || '';
  const isolationName = safeUnitComponent(worktreeName);
  const unit = logresDevinUnit(isolationName);
  const id = logresDevinNetworkIdentity(isolationName);
  const scratch = `/home/ubuntu/logres/scratch/devin-workers/${isolationName}`;
  const logs = `/home/ubuntu/logres/logs/devin-workers/${isolationName}`;
  const marker = `systemd-run/system:${unit}`;
  const inaccessible = [
    '-/etc/cloud', '-/etc/ssh', '-/home/ubuntu/.aws', '-/home/ubuntu/.azure',
    '-/home/ubuntu/.config/gh', '-/home/ubuntu/.docker', '-/home/ubuntu/.gitconfig',
    '-/home/ubuntu/.gnupg', '-/home/ubuntu/.kube', '-/home/ubuntu/.oci',
    '-/home/ubuntu/.ssh', '-/home/ubuntu/logres/private', '-/root', '-/run/secrets', '-/var/lib/cloud'
  ];
  const properties = [
    `Description=Logres isolated Devin worker ${payload.taskId} (${payload.workerId})`,
    'User=ubuntu',
    `WorkingDirectory=${payload.worktree}`,
    'NoNewPrivileges=yes',
    'PrivateTmp=yes',
    'PrivateDevices=yes',
    'ProtectSystem=strict',
    'ProtectHome=read-only',
    'ProtectKernelTunables=yes',
    'ProtectKernelModules=yes',
    'ProtectKernelLogs=yes',
    'ProtectControlGroups=yes',
    'ProtectClock=yes',
    'ProtectHostname=yes',
    'RestrictSUIDSGID=yes',
    'LockPersonality=yes',
    'RestrictRealtime=yes',
    'RemoveIPC=yes',
    'KeyringMode=private',
    'DevicePolicy=closed',
    'RestrictNamespaces=~cgroup',
    'CapabilityBoundingSet=',
    'AmbientCapabilities=',
    'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK',
    'SystemCallArchitectures=native',
    'SocketBindDeny=any',
    'UMask=0077',
    'MemoryMax=4G',
    'MemoryHigh=3G',
    'CPUQuota=300%',
    'TasksMax=512',
    'RuntimeMaxSec=7200',
    'TimeoutStopSec=30',
    'KillMode=control-group',
    'KillSignal=SIGTERM',
    'FinalKillSignal=SIGKILL',
    'SendSIGKILL=yes',
    `NetworkNamespacePath=/run/netns/${id.netns}`,
    `StandardOutput=append:${logs}/devin.log`,
    `StandardError=append:${logs}/devin.log`,
    `SyslogIdentifier=logres-devin-${isolationName.slice(0, 32)}`,
    'IPAddressDeny=fd00:ec2::254/128 127.0.0.0/8 ::1/128 fe80::/10',
    `BindPaths=${logs}`,
    `BindPaths=${scratch}`,
    `BindPaths=${payload.worktree}`,
    'BindPaths=/home/ubuntu/logres/control',
    'BindPaths=/home/ubuntu/logres/artifacts',
    'BindPaths=/home/ubuntu/logres/logs',
    'BindPaths=/home/ubuntu/logres/src/awakened-realms/.git',
    'BindPaths=/home/ubuntu/.config/devin',
    'BindPaths=/home/ubuntu/.local/share/devin',
    `InaccessiblePaths=${inaccessible.join(' ')}`,
    `Environment=HOME=${scratch}/home`,
    'Environment=PATH=/home/ubuntu/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'Environment=XDG_CONFIG_HOME=/home/ubuntu/.config',
    'Environment=XDG_DATA_HOME=/home/ubuntu/.local/share',
    'BindReadOnlyPaths=/run/systemd/resolve/resolv.conf:/etc/resolv.conf',
    'Environment=TMPDIR=/tmp',
    `Environment=GIT_CONFIG_GLOBAL=${scratch}/home/.gitconfig`,
    `Environment=LOGRES_TASK_ID=${payload.taskId}`,
    `Environment=LOGRES_WORKER_ID=${payload.workerId}`,
    `Environment=LOGRES_BRANCH=${payload.branch}`,
    `Environment=LOGRES_WORKTREE=${payload.worktree}`,
    `Environment=LOGRES_DEVIN_ISOLATION_UNIT=${unit}`,
    `Environment=LOGRES_DEVIN_EXECUTION_ISOLATION=${marker}`,
    `Environment=NPM_CONFIG_CACHE=${scratch}/npm-cache`,
    `Environment=XDG_CACHE_HOME=${scratch}/home/.cache`,
    'Environment=GIT_CONFIG_NOSYSTEM=1'
  ];
  const child = [
    '/home/ubuntu/logres/bin/logres-devin-agent',
    '--task', payload.taskId,
    '--worker', payload.workerId,
    '--job-id', String(payload.jobId),
    '--branch', payload.branch,
    '--worktree', payload.worktree,
    '--model', payload.model,
    '--permission-mode', payload.permissionMode,
    '--execution-mode', 'unattended',
    '--sandbox',
    '--isolation', marker
  ];
  const argv = ['--system', `--unit=${unit}`, '--service-type=exec', '--collect', '--quiet'];
  for (const property of properties) argv.push('--property', property);
  argv.push('--', ...child);
  return { executable: '/usr/bin/systemd-run', argv, timeoutMs: 120_000 };
}


function requireManagedServicePayload(payload: unknown, serviceRe: RegExp): { name: string; action: string } {
  const p = exactKeys(payload, ['name', 'action']);
  if (typeof p.name !== 'string' || !serviceRe.test(p.name)) throw new Error('invalid managed service name');
  if (typeof p.action !== 'string' || !SERVICE_ACTIONS.has(p.action)) throw new Error('invalid managed service action');
  return { name: p.name, action: p.action };
}

function requireManagedProfile(payload: unknown): string {
  const p = exactKeys(payload, ['profile']);
  if (typeof p.profile !== 'string' || !MANAGED_PROFILE_RE.test(p.profile)) throw new Error('invalid managed security profile');
  return p.profile;
}

function requireSysctlPayload(payload: unknown): { key: 'net.ipv4.ip_forward'; value: 0 | 1 } {
  const p = exactKeys(payload, ['key', 'value']);
  if (p.key !== 'net.ipv4.ip_forward') throw new Error('unsupported sysctl key');
  if (p.value !== 0 && p.value !== 1) throw new Error('invalid sysctl value');
  return { key: p.key, value: p.value };
}

interface NexusPromotePayload { sourcePath: string; sha256: string }
const NEXUS_RUNTIME_ARCHIVE_RE = /^(?:\/home\/ubuntu\/logres\/(?:staging|control)|\/var\/tmp\/nexus-maintenance\/staging)\/nexus-runtime-[A-Za-z0-9._:-]+\/runtime\.tar\.gz$/;
function requireNexusPromotePayload(payload: unknown): NexusPromotePayload {
  const p = exactKeys(payload, ['sourcePath', 'sha256']);
  if (typeof p.sourcePath !== 'string' || !NEXUS_RUNTIME_ARCHIVE_RE.test(p.sourcePath)) {
    throw new Error('invalid Nexus runtime archive path');
  }
  if (typeof p.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(p.sha256)) {
    throw new Error('invalid artifact digest');
  }
  return { sourcePath: p.sourcePath, sha256: p.sha256.toLowerCase() };
}

interface VerifiedInstallPayload { sourcePath: string; destinationPath: string; sha256: string }
function requireVerifiedInstallPayload(payload: unknown): VerifiedInstallPayload {
  const p = exactKeys(payload, ['sourcePath', 'destinationPath', 'sha256']);
  if (typeof p.sourcePath !== 'string' || !path.isAbsolute(p.sourcePath)) throw new Error('invalid source path');
  if (typeof p.destinationPath !== 'string' || !path.isAbsolute(p.destinationPath)) throw new Error('invalid destination path');
  if (typeof p.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(p.sha256)) throw new Error('invalid artifact digest');
  return { sourcePath: p.sourcePath, destinationPath: p.destinationPath, sha256: p.sha256.toLowerCase() };
}

export class SystemPrivilegedOperations implements PrivilegedOperationExecutor {
  constructor(
    private readonly defaultTimeoutMs = 120_000,
    private readonly maxOutputBytes = 1024 * 1024,
    private readonly execAllowlist: ReadonlySet<string> = new Set(),
    private readonly verifiedInstallBoundary: VerifiedInstallBoundary = DEFAULT_VERIFIED_INSTALL_BOUNDARY
  ) {}

  private async ensureLogresWritableSurfaces(): Promise<void> {
    const targets = [
      '/home/ubuntu/logres/work',
      '/home/ubuntu/logres/src/awakened-realms/.git'
    ];
    const inspect = async (target: string) => this.runArgv({
      executable: '/usr/bin/findmnt',
      argv: ['--target', target, '--noheadings', '--output', 'TARGET,OPTIONS'],
      timeoutMs: 10_000,
      maxOutputBytes: 64 * 1024
    });
    const parse = (stdout: string) => {
      const line = stdout.trim().split(/\r?\n/)[0] ?? '';
      const match = line.match(/^(\S+)\s+(.+)$/);
      return { mountTarget: match?.[1] ?? '', options: match?.[2] ?? '' };
    };
    for (const target of targets) {
      const mounted = await inspect(target);
      const before = mounted.exitCode === 0 ? parse(mounted.stdout) : { mountTarget: '', options: '' };
      const dedicated = mounted.exitCode === 0 && before.mountTarget === target;
      if (!dedicated) {
        const bind = await this.runArgv({
          executable: '/usr/bin/mount',
          argv: ['--bind', target, target],
          timeoutMs: 10_000,
          maxOutputBytes: 64 * 1024
        });
        if (bind.exitCode !== 0) throw new Error(`unable to bind writable Logres surface ${target}: ${bind.stderr.trim()}`);
      }
      if (!dedicated || !/(^|,)rw(,|$)/.test(before.options)) {
        const remount = await this.runArgv({
          executable: '/usr/bin/mount',
          argv: ['-o', 'remount,bind,rw', target, target],
          timeoutMs: 10_000,
          maxOutputBytes: 64 * 1024
        });
        if (remount.exitCode !== 0) throw new Error(`unable to remount writable Logres surface ${target}: ${remount.stderr.trim()}`);
      }
      const verified = await inspect(target);
      const after = verified.exitCode === 0 ? parse(verified.stdout) : { mountTarget: '', options: '' };
      if (verified.exitCode !== 0 || after.mountTarget !== target || !/(^|,)rw(,|$)/.test(after.options)) {
        throw new Error(`writable Logres surface verification failed for ${target}`);
      }
    }
  }

  async execute(
    operation: PrivilegedOperation,
    payload: unknown
  ): Promise<PrivilegedOperationResult> {
    switch (operation) {
      case 'process.execArgv': {
        const p = payload as {
          executable: string;
          argv: string[];
          timeoutMs?: number;
        };
        if (!this.execAllowlist.has(p.executable)) {
          throw new Error('executable not allowed by privileged policy');
        }
        return this.runArgv({
          executable: p.executable,
          argv: p.argv,
          timeoutMs: p.timeoutMs
        });
      }
      case 'service.status':
      case 'service.start':
      case 'service.stop':
      case 'service.restart':
      case 'service.enable':
      case 'service.disable': {
        const p = payload as { name: string };
        const action = operation.slice('service.'.length);
        return this.runArgv({
          executable: '/usr/bin/systemctl',
          argv: [action, p.name]
        });
      }
      case 'package.install': {
        const p = payload as { packages: string[] };
        return this.runArgv({
          executable: '/usr/bin/apt-get',
          argv: ['install', '-y', '--', ...p.packages],
          timeoutMs: 900_000
        });
      }
      case 'filesystem.chmod': {
        const p = payload as { path: string; mode: string };
        await chmod(p.path, Number.parseInt(p.mode, 8));
        return { ok: true };
      }
      case 'filesystem.chown': {
        const p = payload as { path: string; uid: number; gid: number };
        await chown(p.path, p.uid, p.gid);
        return { ok: true };
      }
      case 'network.logresDevinProvision': {
        const isolationName = requireIsolationName(payload);
        const cleanup = async () => {
          for (const input of logresDevinTeardownPlan(isolationName)) {
            await this.runArgv(input);
          }
        };
        // A prior worker bootstrap can fail after creating only part of the
        // namespace. Reconcile this exact deterministic identity before
        // provisioning so retries do not fail on stale netns/veth/nft state.
        await cleanup();
        for (const input of logresDevinProvisionPlan(isolationName)) {
          const result = await this.runArgv(input);
          if (result.exitCode !== 0 || result.timedOut) {
            await cleanup();
            const argv = [input.executable, ...input.argv].join(' ');
            const detail = (result.stderr || result.stdout || '').trim().slice(0, 800);
            throw new Error(
              `Logres Devin network provision failed: ${argv}; ` +
              `exit=${result.exitCode}${result.timedOut ? ' timeout=true' : ''}` +
              (detail ? `; detail=${detail}` : '')
            );
          }
        }
        return { ok: true };
      }
      case 'network.logresDevinTeardown': {
        const isolationName = requireIsolationName(payload);
        const failures: string[] = [];
        for (const input of logresDevinTeardownPlan(isolationName)) {
          const result = await this.runArgv(input);
          if (result.exitCode !== 0 || result.timedOut) failures.push(input.executable);
        }
        if (failures.length > 0) {
          throw new Error(`Logres Devin network teardown failed: ${failures.join(', ')}`);
        }
        return { ok: true };
      }
      case 'systemd.logresDevinStart': {
        const p = requireLogresDevinStartPayload(payload);
        const input = logresDevinSystemdRunPlan(p);
        const launch = await this.runArgv(input);
        if (launch.exitCode !== 0 || launch.timedOut) {
          throw new Error('Logres Devin transient launch failed');
        }
        const isolationName = safeUnitComponent(p.worktree.split('/').at(-1) || 'worker');
        const unit = logresDevinUnit(isolationName);
        const status = await this.runArgv({
          executable: '/usr/bin/systemctl',
          argv: ['show', unit, '--property=ActiveState,SubState,MainPID,ExecMainStatus']
        });
        if (status.exitCode !== 0 || status.timedOut) {
          throw new Error('Logres Devin transient status failed');
        }
        const active = /(?:^|\n)ActiveState=active(?:\n|$)/.test(status.stdout);
        const pid = Number(status.stdout.match(/(?:^|\n)MainPID=(\d+)(?:\n|$)/)?.[1] ?? 0);
        if (!active || pid <= 0) {
          throw new Error('Logres Devin transient unit did not become active');
        }
        return status;
      }
      case 'systemd.logresDevinStop': {
        const isolationName = requireIsolationName(payload);
        const unit = logresDevinUnit(isolationName);
        const stop = await this.runArgv({
          executable: '/usr/bin/systemctl',
          argv: ['stop', unit]
        });
        const reset = await this.runArgv({
          executable: '/usr/bin/systemctl',
          argv: ['reset-failed', unit]
        });
        if (stop.timedOut || reset.timedOut || stop.exitCode !== 0 || reset.exitCode !== 0) {
          throw new Error('Logres Devin transient stop failed');
        }
        return { ok: true };
      }
      case 'service.nexusManage':
      case 'service.nexusMaintenanceManage': {
        const p = requireManagedServicePayload(payload, NEXUS_MANAGED_SERVICE_RE);
        return this.runArgv({ executable: '/usr/bin/systemctl', argv: [p.action, p.name] });
      }
      case 'service.logresManage': {
        const p = requireManagedServicePayload(payload, LOGRES_MANAGED_SERVICE_RE);
        return this.runArgv({ executable: '/usr/bin/systemctl', argv: [p.action, p.name] });
      }
      case 'security.logresProfileReload': {
        const profile = requireManagedProfile(payload);
        return this.runArgv({ executable: '/usr/sbin/apparmor_parser', argv: ['-r', `/etc/apparmor.d/${profile}`] });
      }
      case 'systemd.logresDaemonReload':
        exactKeys(payload, []);
        return this.runArgv({ executable: '/usr/bin/systemctl', argv: ['daemon-reload'] });
      case 'sysctl.logresSet': {
        const p = requireSysctlPayload(payload);
        return this.runArgv({ executable: '/usr/sbin/sysctl', argv: ['-w', `${p.key}=${p.value}`] });
      }
      case 'deployment.nexusInstallVerified':
      case 'deployment.nexusMaintenanceInstallVerified':
      case 'deployment.logresInstallVerified':
        return this.installVerified(requireVerifiedInstallPayload(payload));
      case 'deployment.logresRuntimePromote': {
        const p = exactKeys(payload, ['sha']);
        if (typeof p.sha !== 'string' || !/^[a-f0-9]{40}$/.test(p.sha)) {
          throw new Error('invalid integration sha');
        }
        return this.runArgv({
          executable: '/opt/nexus-commander/scripts/logres-runtime-promote-root.sh',
          argv: ['--sha', p.sha],
          timeoutMs: 900_000,
          maxOutputBytes: 2 * 1024 * 1024
        });
      }
      case 'deployment.nexusPromoteVerified':
      case 'deployment.nexusMaintenancePromoteVerified': {
        const p = requireNexusPromotePayload(payload);
        return this.runArgv({
          executable: '/opt/nexus-commander/scripts/nexus-runtime-promote.sh',
          argv: ['--source', p.sourcePath, '--sha256', p.sha256],
          timeoutMs: 900_000,
          maxOutputBytes: 2 * 1024 * 1024
        });
      }
      case 'integration.logresVerify': {
        await this.ensureLogresWritableSurfaces();
        const p = exactKeys(payload, ['ref']);
        if (typeof p.ref !== 'string' || !/^[A-Za-z0-9._\/-]+$/.test(p.ref)) throw new Error('invalid Logres verify ref');
        return this.runArgv({ executable: '/usr/sbin/runuser', argv: ['-u','ubuntu','--','/home/ubuntu/logres/bin/logres-verify-ref',p.ref], timeoutMs: 900_000, maxOutputBytes: 2 * 1024 * 1024 });
      }
      case 'integration.logresDevice': {
        const p = payload as Record<string, unknown>;
        const argv = ['-u','ubuntu','--','/home/ubuntu/logres/bin/logres-phone-qa'];
        if (p.action === 'screenshot') argv.push('screenshot', String(p.outputPath));
        else if (p.action === 'logcat') argv.push('logcat', String(p.outputPath));
        else if (p.action === 'certify') return this.runArgv({ executable: '/usr/sbin/runuser', argv: ['-u','ubuntu','--','/home/ubuntu/logres/bin/logres-hardware-qa','--sha',String(p.sha)], timeoutMs: 900_000, maxOutputBytes: 2 * 1024 * 1024 });
        else throw new Error('invalid Logres device action');
        return this.runArgv({ executable: '/usr/sbin/runuser', argv, timeoutMs: 120_000, maxOutputBytes: 2 * 1024 * 1024 });
      }
      case 'integration.logresBrain': {
        const p = payload as Record<string, unknown>;
        const argv = ['-u', 'ubuntu', '--'];
        if (p.action === 'createTask') argv.push('/home/ubuntu/logres/bin/logres-control', 'new-task', String(p.taskId), String(p.priority), String(p.workType), String(p.title));
        else if (p.action === 'lease') argv.push('/home/ubuntu/logres/bin/logres-brain', 'lease', String(p.chatId), String(p.taskId), '--minutes', String(p.minutes), '--branch', String(p.branch));
        else if (p.action === 'progress') argv.push('/home/ubuntu/logres/bin/logres-brain', 'progress', String(p.chatId), String(p.taskId), String(p.percent), '--note', String(p.note));
        else if (p.action === 'evidence') { argv.push('/home/ubuntu/logres/bin/logres-brain', 'evidence', String(p.chatId), String(p.confidence), String(p.subject), String(p.summary)); if (p.taskId) argv.push('--task', String(p.taskId)); }
        else if (p.action === 'block') argv.push('/home/ubuntu/logres/bin/logres-brain', 'release', String(p.chatId), String(p.taskId), '--status', 'BLOCKED_DEP', '--note', String(p.note));
        else throw new Error('invalid Logres Brain action');
        return this.runArgv({ executable: '/usr/sbin/runuser', argv, timeoutMs: 180_000, maxOutputBytes: 1024 * 1024 });
      }
      case 'integration.logresCoordinator': {
        const p = payload as Record<string, unknown>;
        const argv = ['-u', 'ubuntu', '--'];
        if (p.action === 'devinDispatch') argv.push('/home/ubuntu/logres/bin/logres-swarm', 'tick');
        else if (p.action === 'baton') {
          argv.push('/home/ubuntu/logres/bin/logres-supervisor', 'baton', '--state', String(p.state));
          if (p.objective) argv.push('--objective', String(p.objective));
          if (p.task) argv.push('--task', String(p.task));
          if (p.note) argv.push('--note', String(p.note));
          if (p.newGeneration === true) argv.push('--new-generation');
        } else throw new Error('invalid Logres coordinator action');
        return this.runArgv({ executable: '/usr/sbin/runuser', argv, timeoutMs: 300_000, maxOutputBytes: 1024 * 1024 });
      }
      case 'integration.logresVmExec': {
        const p = payload as { chatId: string; taskId: string; branch: string; executable: 'git'|'npm'|'node'|'python3'|'bash'|'adb'; argv: string[]; cwd: string; timeoutMs: number };
        const repo = '/home/ubuntu/logres/src/awakened-realms';
        const tree = await this.runArgv({ executable: '/usr/sbin/runuser', argv: ['-u','ubuntu','--','/usr/bin/git','-C',repo,'worktree','list','--porcelain'] });
        if (tree.exitCode !== 0) throw new Error('unable to resolve worker worktree');
        const target = tree.stdout.split(/\n\n+/).find((b) => b.split(/\r?\n/).includes('branch refs/heads/' + p.branch));
        const worktree = target?.split(/\r?\n/).find((line) => line.startsWith('worktree '))?.slice(9).trim();
        if (!worktree || !worktree.startsWith('/home/ubuntu/logres/work/')) throw new Error('no managed worker worktree for branch');
        if (path.isAbsolute(p.cwd)) throw new Error('worker cwd must be relative');
        const cwd = path.resolve(worktree, p.cwd);
        if (cwd !== worktree && !cwd.startsWith(worktree + path.sep)) throw new Error('worker cwd escapes worktree');
        const executable = { git:'/usr/bin/git', npm:'/usr/bin/npm', node:'/usr/bin/node', python3:'/usr/bin/python3', bash:'/usr/bin/bash', adb:'/usr/bin/adb' }[p.executable];
        if ((p.executable === 'node' && p.argv.some((a) => a === '-e' || a === '--eval')) || (p.executable === 'python3' && p.argv.includes('-c')) || (p.executable === 'bash' && p.argv.includes('-c'))) throw new Error('inline code execution is not approved for VM commands');
        const command = p.executable === 'git' ? ['/usr/bin/env','GIT_CONFIG_NOSYSTEM=1','GIT_CONFIG_GLOBAL=/dev/null',executable,...p.argv] : [executable,...p.argv];
        return this.runArgv({ executable: '/usr/sbin/runuser', argv: ['-u','ubuntu','--',...command], cwd, timeoutMs: p.timeoutMs, maxOutputBytes: 1024 * 1024 });
      }
      case 'integration.logresCandidateCommit': {
        const p = payload as { chatId: string; taskId: string; branch: string };
        const run = (argv: string[], timeoutMs = 120_000) => this.runArgv({ executable: '/usr/sbin/runuser', argv: ['-u','ubuntu','--',...argv], timeoutMs, maxOutputBytes: 1024 * 1024 });
        const db = '/home/ubuntu/logres/control/control.sqlite';
        const scopeSql = "select path_prefix from task_scopes where task_id='" + p.taskId + "' union select path_prefix from claims where task_id='" + p.taskId + "' order by 1;";
        const scopeResult = await run(['/usr/bin/sqlite3','-readonly',db,scopeSql]);
        if (scopeResult.exitCode !== 0) throw new Error('unable to read task scopes');
        const scopes = scopeResult.stdout.split(/\r?\n/).map((v) => v.trim()).filter(Boolean);
        if (scopes.length === 0) throw new Error('task has no declared or claimed scopes');
        const repo = '/home/ubuntu/logres/src/awakened-realms';
        const trees = await run(['/usr/bin/git','-C',repo,'worktree','list','--porcelain']);
        if (trees.exitCode !== 0) throw new Error('unable to resolve worker worktree');
        const target = trees.stdout.split(/\n\n+/).find((b) => b.split(/\r?\n/).includes('branch refs/heads/' + p.branch));
        const worktree = target?.split(/\r?\n/).find((line) => line.startsWith('worktree '))?.slice(9).trim();
        if (!worktree || !worktree.startsWith('/home/ubuntu/logres/work/')) throw new Error('no managed worker worktree for branch');
        const git = async (args: string[]) => { const r = await run(['/usr/bin/env','GIT_CONFIG_NOSYSTEM=1','GIT_CONFIG_GLOBAL=/dev/null','/usr/bin/git','-C',worktree,...args]); if (r.exitCode !== 0) throw new Error(r.stderr.trim() || 'git command failed'); return r; };
        const dirty = new Set<string>();
        for (const args of [['diff','--name-only'],['diff','--cached','--name-only'],['ls-files','--others','--exclude-standard']]) for (const name of (await git(args)).stdout.split(/\r?\n/).map((v) => v.trim()).filter(Boolean)) dirty.add(name);
        if (dirty.size === 0) throw new Error('no candidate changes');
        const covered = (file: string, prefix: string) => { const a=file.replace(/^\/+|\/+$/g,''); const b=prefix.replace(/^\/+|\/+$/g,''); return a===b || a.startsWith(b + '/') || b.startsWith(a + '/'); };
        const violations = [...dirty].filter((file) => !scopes.some((scope) => covered(file, scope)));
        if (violations.length) throw new Error('candidate changes outside task scope: ' + violations.join(', '));
        await git(['diff','--check']); await git(['diff','--cached','--check']); await git(['add','-A']);
        const staged = (await git(['diff','--cached','--name-only'])).stdout.split(/\r?\n/).map((v) => v.trim()).filter(Boolean);
        if (staged.length === 0) throw new Error('no staged candidate changes');
        const stagedViolations = staged.filter((file) => !scopes.some((scope) => covered(file, scope)));
        if (stagedViolations.length) throw new Error('staged changes outside task scope: ' + stagedViolations.join(', '));
        await git(['-c','user.name=Nexus Typed Bridge','-c','user.email=nexus-typed-bridge@local.invalid','commit','-m','worker: ' + p.taskId + ' typed candidate']);
        if ((await git(['status','--porcelain'])).stdout.trim()) throw new Error('worktree changed during candidate commit');
        const sha = (await git(['rev-parse','HEAD'])).stdout.trim();
        return { taskId: p.taskId, branch: p.branch, sha, changedPaths: staged };
      }
      case 'integration.logresFinishTask': {
        const p = exactKeys(payload, ['branch', 'chatId', 'taskId']);
        if (typeof p.chatId !== 'string' || !/^[A-Za-z0-9._:-]+$/.test(p.chatId) || typeof p.taskId !== 'string' || !/^[A-Za-z0-9._:-]+$/.test(p.taskId) || typeof p.branch !== 'string' || !/^worker\/[A-Za-z0-9._\/-]+$/.test(p.branch)) throw new Error('invalid Logres finish-task payload');
        return this.runArgv({ executable: '/usr/sbin/runuser', argv: ['-u', 'ubuntu', '--', '/home/ubuntu/logres/bin/logres-finish-task', p.chatId, p.taskId, p.branch], timeoutMs: 900_000, maxOutputBytes: 2 * 1024 * 1024 });
      }
      case 'integration.logresWorkerLifecycle': {
        const p = requireLogresWorkerLifecyclePayload(payload);
        if (p.action === 'start') await this.ensureLogresWritableSurfaces();
        const argv = ['-u', 'ubuntu', '--'];
        if (p.action === 'start') { argv.push('/home/ubuntu/logres/bin/logres-worker-start', p.chatId, p.taskId); if (p.branch) argv.push(p.branch); }
        else argv.push('/home/ubuntu/logres/bin/logres-brain', 'release', p.chatId, p.taskId, '--status', 'READY', '--note', p.note!);
        return this.runArgv({ executable: '/usr/sbin/runuser', argv, timeoutMs: 180_000, maxOutputBytes: 1024 * 1024 });
      }
      case 'integration.logresPreflight': {
        const p = requireLogresPreflightPayload(payload);
        if (p.action !== 'status') await this.ensureLogresWritableSurfaces();
        const argv = ['-u', 'ubuntu', '--'];
        if (p.action === 'status') {
          argv.push('/home/ubuntu/logres/bin/logres-merge-preflight', 'status');
        } else if (p.action === 'run') {
          argv.push('/home/ubuntu/logres/bin/logres-merge-preflight', 'run', '--max', String(p.max), '--min-age', '0', '--min-count', '1');
        } else {
          argv.push('/home/ubuntu/logres/bin/logres-merge-train', 'apply-preflight', '--actor', 'lead', String(p.id));
        }
        return this.runArgv({ executable: '/usr/sbin/runuser', argv, timeoutMs: p.action === 'run' ? 900_000 : 300_000, maxOutputBytes: 2 * 1024 * 1024 });
      }
      case 'network.status':
        return this.runArgv({
          executable: '/usr/sbin/ip',
          argv: ['-brief', 'address']
        });
    }
  }

  private async installVerified(p: VerifiedInstallPayload): Promise<{ ok: true }> {
    const resolveBoundaryRoot = async (root: string) => {
      const requested = path.resolve(root);
      const resolved = await realpath(requested);
      if (resolved !== requested) throw new Error('approved root symlink rejected');
      return resolved;
    };

    const sourceInfo = await lstat(p.sourcePath);
    if (!sourceInfo.isFile() || sourceInfo.isSymbolicLink()) throw new Error('deployment source symlink or non-regular file rejected');
    if (sourceInfo.nlink !== 1) throw new Error('deployment source hardlink or unexpected link count rejected');
    if (sourceInfo.size > MAX_VERIFIED_INSTALL_BYTES) throw new Error('deployment source size too large');
    const sourceReal = await realpath(p.sourcePath);
    const sourceRoots = await Promise.all(this.verifiedInstallBoundary.sourceRoots.map(resolveBoundaryRoot));
    if (!sourceRoots.some((root) => insideRoot(sourceReal, root))) throw new Error('path is outside approved root');

    const destination = path.resolve(p.destinationPath);
    const destinationParent = await realpath(path.dirname(destination));
    const destinationRoots = await Promise.all(this.verifiedInstallBoundary.destinationRoots.map(resolveBoundaryRoot));
    if (!destinationRoots.some((root) => insideRoot(destinationParent, root))) throw new Error('path is outside approved root');
    const safeDestination = path.join(destinationParent, path.basename(destination));
    try {
      const current = await lstat(safeDestination);
      if (current.isSymbolicLink()) throw new Error('deployment destination symlink rejected');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
    }

    const content = await readFile(sourceReal);
    const actual = createHash('sha256').update(content).digest('hex');
    if (actual !== p.sha256) throw new Error('artifact digest mismatch');
    const temp = path.join(destinationParent, `.${path.basename(safeDestination)}.nexus-${randomUUID()}.tmp`);
    try {
      await writeFile(temp, content, { flag: 'wx', mode: 0o644 });
      await rename(temp, safeDestination);
    } finally {
      await unlink(temp).catch(() => undefined);
    }
    return { ok: true };
  }

  private async runArgv(input: RunArgvInput): Promise<PrivilegedExecResult> {
    const started = Date.now();
    const child = spawn(input.executable, input.argv, {
      shell: false,
      detached: true,
      ...(input.cwd ? { cwd: input.cwd } : {}),
      stdio: ['ignore', 'pipe', 'pipe']
    });
    const limit = input.maxOutputBytes ?? this.maxOutputBytes;
    let stdout: Buffer = Buffer.alloc(0);
    let stderr: Buffer = Buffer.alloc(0);
    let truncated = false;
    let timedOut = false;
    let killTimer: NodeJS.Timeout | undefined;
    const capture = (current: Buffer, chunk: Buffer): Buffer => {
      const used = stdout.length + stderr.length;
      const remaining = Math.max(0, limit - used);
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
          // Process already exited.
        }
      }, 750);
    }, input.timeoutMs ?? this.defaultTimeoutMs);
    return await new Promise<PrivilegedExecResult>((resolve, reject) => {
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
  }
}
