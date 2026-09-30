import {
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual
} from 'node:crypto';
import { z } from 'zod';

export const PRIVILEGED_OPERATIONS = [
  'process.execArgv',
  'service.status',
  'service.start',
  'service.stop',
  'service.restart',
  'service.enable',
  'service.disable',
  'package.install',
  'filesystem.chmod',
  'filesystem.chown',
  'network.status',
  'network.logresDevinProvision',
  'network.logresDevinTeardown',
  'systemd.logresDevinStart',
  'systemd.logresDevinStop',
  'service.logresManage',
  'service.nexusManage',
  'service.nexusMaintenanceManage',
  'security.logresProfileReload',
  'systemd.logresDaemonReload',
  'sysctl.logresSet',
  'deployment.logresInstallVerified',
  'deployment.logresRuntimePromote',
  'integration.logresBrain',
  'integration.logresCoordinator',
  'integration.logresVmExec',
  'integration.logresCandidateCommit',
  'integration.logresVerify',
  'integration.logresDevice',
  'integration.logresPreflight',
  'integration.logresFinishTask',
  'integration.logresWorkerLifecycle',
  'deployment.nexusInstallVerified',
  'deployment.nexusPromoteVerified',
  'deployment.nexusMaintenanceInstallVerified',
  'deployment.nexusMaintenancePromoteVerified'
] as const;

export type PrivilegedOperation = (typeof PRIVILEGED_OPERATIONS)[number];

export interface PrivilegedMaintenanceContextRef {
  transactionId: string;
  reason: string;
  expiresAt: number;
}

export interface PrivilegedProjectContextRef {
  taskId: string;
  workerId: string;
  branch: string;
}

const absolutePath = z.string().min(1).max(4096).refine((value) => value.startsWith('/'), {
  message: 'path must be absolute'
});
const serviceName = z.string().min(1).max(256).regex(/^[A-Za-z0-9@_.:-]+$/);
const packageName = z.string().min(1).max(256).regex(/^[A-Za-z0-9.+:-]+$/);
const logresId = z.string().min(1).max(160).regex(/^[A-Za-z0-9._:-]+$/);
const logresWorkerId = z.string().min(1).max(128).regex(/^[A-Za-z0-9._:-]+$/);
const logresWorkerBranch = z.string().min(1).max(256).regex(/^worker\/[A-Za-z0-9._\/-]+$/);
const logresWorktree = z.string().min(1).max(4096).regex(/^\/home\/ubuntu\/logres\/work\/[A-Za-z0-9._-]+$/);
const freeDevinModel = z.enum(['swe-2-max', 'swe-2-high', 'swe-2-medium']);
const nexusServiceName = z.string().min(1).max(256).regex(/^nexus-(?:tunnel@ubuntu|privileged-executor|agent|control-plane@ubuntu)\.service$/);
const managedServiceName = z.string().min(1).max(256).regex(/^logres-[A-Za-z0-9@_.:-]+\.service$/);
const appArmorProfile = z.string().min(1).max(128).regex(/^logres-[A-Za-z0-9._-]+$/);
const stagingPath = z.string().min(1).max(4096).regex(/^\/home\/ubuntu\/logres\/staging\/logres-[A-Za-z0-9._-]+$/);
const nexusStagingPath = z.string().min(1).max(4096).regex(/^\/home\/ubuntu\/logres\/staging\/nexus-[A-Za-z0-9@_.:-]+$/);
const nexusRuntimeArchivePath = z.string().min(1).max(4096).regex(/^\/home\/ubuntu\/logres\/(?:staging|control)\/nexus-runtime-[A-Za-z0-9._:-]+\/runtime\.tar\.gz$/);
const nexusMaintenanceStagingPath = z.string().min(1).max(4096).regex(/^\/var\/tmp\/nexus-maintenance\/staging\/nexus-[A-Za-z0-9@_.:-]+$/);
const nexusMaintenanceRuntimeArchivePath = z.string().min(1).max(4096).regex(/^\/var\/tmp\/nexus-maintenance\/staging\/nexus-runtime-[A-Za-z0-9._:-]+\/runtime\.tar\.gz$/);
const nexusDestinationPath = z.string().min(1).max(4096).refine((value) => /^\/etc\/systemd\/system\/nexus-[A-Za-z0-9@_.:-]+\.service$/.test(value), { message: 'destination must be an approved Nexus service path' });
const approvedDestinationPath = z.string().min(1).max(4096).refine((value) =>
  /^\/etc\/systemd\/system\/logres-[A-Za-z0-9@_.:-]+\.service$/.test(value) ||
  /^\/etc\/apparmor\.d\/logres-[A-Za-z0-9._-]+$/.test(value),
  { message: 'destination must be an approved Logres/Nexus host path' }
);
const sha256Hex = z.string().regex(/^[a-f0-9]{64}$/);
const operationSchemas: Record<PrivilegedOperation, z.ZodTypeAny> = {
  'process.execArgv': z.object({
    executable: absolutePath,
    argv: z.array(z.string().max(4096)).max(64).default([]),
    timeoutMs: z.number().int().positive().max(900_000).optional()
  }),
  'service.status': z.object({ name: serviceName }),
  'service.start': z.object({ name: serviceName }),
  'service.stop': z.object({ name: serviceName }),
  'service.restart': z.object({ name: serviceName }),
  'service.enable': z.object({ name: serviceName }),
  'service.disable': z.object({ name: serviceName }),
  'package.install': z.object({
    packages: z.array(packageName).min(1).max(64)
  }),
  'filesystem.chmod': z.object({
    path: absolutePath,
    mode: z.string().regex(/^[0-7]{3,4}$/)
  }),
  'filesystem.chown': z.object({
    path: absolutePath,
    uid: z.number().int().nonnegative(),
    gid: z.number().int().nonnegative()
  }),
  'network.status': z.object({}),
  'network.logresDevinProvision': z.object({
    isolationName: z.string().min(1).max(48).regex(/^[A-Za-z0-9._-]+$/)
  }),
  'network.logresDevinTeardown': z.object({
    isolationName: z.string().min(1).max(48).regex(/^[A-Za-z0-9._-]+$/)
  }),
  'systemd.logresDevinStart': z.object({
    taskId: logresId,
    workerId: logresWorkerId,
    branch: logresWorkerBranch,
    worktree: logresWorktree,
    jobId: z.number().int().positive(),
    model: freeDevinModel,
    permissionMode: z.enum(['smart', 'autonomous'])
  }),
  'systemd.logresDevinStop': z.object({
    isolationName: z.string().min(1).max(48).regex(/^[A-Za-z0-9._-]+$/)
  }),
  'service.nexusManage': z.object({ name: nexusServiceName, action: z.enum(['status','start','stop','restart']) }).strict(),
  'service.nexusMaintenanceManage': z.object({ name: nexusServiceName, action: z.enum(['status','start','stop','restart']) }).strict(),
  'service.logresManage': z.object({
    name: managedServiceName,
    action: z.enum(['status', 'start', 'stop', 'restart'])
  }).strict(),
  'security.logresProfileReload': z.object({ profile: appArmorProfile }).strict(),
  'systemd.logresDaemonReload': z.object({}).strict(),
  'sysctl.logresSet': z.object({
    key: z.literal('net.ipv4.ip_forward'),
    value: z.union([z.literal(0), z.literal(1)])
  }).strict(),
  'deployment.nexusInstallVerified': z.object({ sourcePath: nexusStagingPath, destinationPath: nexusDestinationPath, sha256: sha256Hex }).strict(),
  'deployment.nexusPromoteVerified': z.object({ sourcePath: nexusRuntimeArchivePath, sha256: sha256Hex }).strict(),
  'deployment.nexusMaintenanceInstallVerified': z.object({ sourcePath: nexusMaintenanceStagingPath, destinationPath: nexusDestinationPath, sha256: sha256Hex }).strict(),
  'deployment.nexusMaintenancePromoteVerified': z.object({ sourcePath: nexusMaintenanceRuntimeArchivePath, sha256: sha256Hex }).strict(),
  'deployment.logresInstallVerified': z.object({
    sourcePath: stagingPath,
    destinationPath: approvedDestinationPath,
    sha256: sha256Hex
  }).strict(),
  'deployment.logresRuntimePromote': z.object({
    sha: z.string().regex(/^[a-f0-9]{40}$/)
  }).strict(),
  'integration.logresWorkerLifecycle': z.discriminatedUnion('action', [
    z.object({ action: z.literal('start'), chatId: logresWorkerId, taskId: logresId, branch: logresWorkerBranch.optional() }).strict(),
    z.object({ action: z.literal('release'), chatId: logresWorkerId, taskId: logresId, note: z.string().min(1).max(2048) }).strict()
  ]),
  'integration.logresVerify': z.object({ ref: z.string().min(1).max(256).regex(/^[A-Za-z0-9._\/-]+$/) }).strict(),
  'integration.logresDevice': z.discriminatedUnion('action', [
    z.object({ action: z.literal('screenshot'), outputPath: absolutePath }).strict(),
    z.object({ action: z.literal('logcat'), outputPath: absolutePath }).strict(),
    z.object({ action: z.literal('certify'), sha: z.string().regex(/^[a-f0-9]{40}$/) }).strict()
  ]),
  'integration.logresBrain': z.discriminatedUnion('action', [
    z.object({ action: z.literal('createTask'), taskId: logresId, priority: z.number().int().min(0).max(1000), workType: logresId, title: z.string().min(1).max(4096) }).strict(),
    z.object({ action: z.literal('lease'), chatId: logresWorkerId, taskId: logresId, minutes: z.number().int().min(1).max(1440), branch: logresWorkerBranch }).strict(),
    z.object({ action: z.literal('progress'), chatId: logresWorkerId, taskId: logresId, percent: z.number().int().min(0).max(100), note: z.string().max(4096) }).strict(),
    z.object({ action: z.literal('evidence'), chatId: logresWorkerId, confidence: z.enum(['HIGH','MEDIUM','LOW']), subject: z.string().min(1).max(4096), summary: z.string().min(1).max(8192), taskId: logresId.optional() }).strict(),
    z.object({ action: z.literal('block'), chatId: logresWorkerId, taskId: logresId, note: z.string().min(1).max(4096) }).strict()
  ]),
  'integration.logresCoordinator': z.discriminatedUnion('action', [
    z.object({ action: z.literal('devinDispatch') }).strict(),
    z.object({ action: z.literal('baton'), state: z.enum(['RUNNING','CONTINUE_REQUESTED','PAUSED','WAITING_USER','DONE']), objective: z.string().max(4096).optional(), task: logresId.optional(), note: z.string().max(4096).optional(), newGeneration: z.boolean() }).strict()
  ]),
  'integration.logresVmExec': z.object({ chatId: logresWorkerId, taskId: logresId, branch: logresWorkerBranch, executable: z.enum(['git','npm','node','python3','bash','adb']), argv: z.array(z.string().max(4096)).max(128), cwd: z.string().min(1).max(4096), timeoutMs: z.number().int().positive().max(900000) }).strict(),
  'integration.logresCandidateCommit': z.object({ chatId: logresWorkerId, taskId: logresId, branch: logresWorkerBranch }).strict(),
  'integration.logresFinishTask': z.object({ chatId: logresWorkerId, taskId: logresId, branch: logresWorkerBranch }).strict(),
  'integration.logresPreflight': z.discriminatedUnion('action', [
    z.object({ action: z.literal('status') }).strict(),
    z.object({ action: z.literal('run'), max: z.number().int().min(1).max(8) }).strict(),
    z.object({ action: z.literal('apply'), id: z.number().int().positive() }).strict()
  ])
};

export interface PrivilegedEnvelope {
  requestId: string;
  timestamp: number;
  nonce: string;
  machineId: string;
  operation: PrivilegedOperation;
  payload: unknown;
  projectContext?: PrivilegedProjectContextRef;
  maintenanceContext?: PrivilegedMaintenanceContextRef;
  signature: string;
}

export interface SignPrivilegedRequestInput {
  machineId: string;
  operation: PrivilegedOperation;
  payload: unknown;
  projectContext?: PrivilegedProjectContextRef;
  maintenanceContext?: PrivilegedMaintenanceContextRef;
  timestamp?: number;
}

const envelopeSchema = z.object({
  requestId: z.string().uuid(),
  timestamp: z.number().int().positive(),
  nonce: z.string().regex(/^[a-f0-9]{32}$/),
  machineId: z.string().min(1).max(128).regex(/^[A-Za-z0-9._-]+$/),
  operation: z.enum(PRIVILEGED_OPERATIONS),
  payload: z.unknown(),
  projectContext: z.object({ taskId: logresId, workerId: logresWorkerId, branch: logresWorkerBranch }).strict().optional(),
  maintenanceContext: z.object({ transactionId: z.string().min(1).max(160).regex(/^[A-Za-z0-9._:-]+$/), reason: z.string().min(1).max(4096), expiresAt: z.number().int().positive() }).strict().optional(),
  signature: z.string().regex(/^[a-f0-9]{64}$/)
});

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, item]) => item !== undefined)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, item]) => [key, canonicalize(item)])
    );
  }
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function unsignedEnvelope(
  envelope: Omit<PrivilegedEnvelope, 'signature'>
): Omit<PrivilegedEnvelope, 'signature'> {
  return {
    requestId: envelope.requestId,
    timestamp: envelope.timestamp,
    nonce: envelope.nonce,
    machineId: envelope.machineId,
    operation: envelope.operation,
    payload: envelope.payload,
    ...(envelope.projectContext === undefined ? {} : { projectContext: envelope.projectContext }),
    ...(envelope.maintenanceContext === undefined ? {} : { maintenanceContext: envelope.maintenanceContext })
  };
}

function signatureFor(
  envelope: Omit<PrivilegedEnvelope, 'signature'>,
  key: Buffer
): string {
  return createHmac('sha256', key)
    .update(canonicalJson(unsignedEnvelope(envelope)))
    .digest('hex');
}

export function parsePrivilegedPayload(
  operation: PrivilegedOperation,
  payload: unknown
): unknown {
  const schema = operationSchemas[operation];
  if (!schema) throw new Error('unsupported privileged operation');
  return schema.parse(payload);
}

export function signPrivilegedRequest(
  input: SignPrivilegedRequestInput,
  key: Buffer
): PrivilegedEnvelope {
  if (!(PRIVILEGED_OPERATIONS as readonly string[]).includes(input.operation)) {
    throw new Error('unsupported privileged operation');
  }
  const payload = parsePrivilegedPayload(input.operation, input.payload);
  const unsigned: Omit<PrivilegedEnvelope, 'signature'> = {
    requestId: randomUUID(),
    timestamp: input.timestamp ?? Date.now(),
    nonce: randomBytes(16).toString('hex'),
    machineId: input.machineId,
    operation: input.operation,
    payload,
    ...(input.projectContext === undefined ? {} : { projectContext: input.projectContext }),
    ...(input.maintenanceContext === undefined ? {} : { maintenanceContext: input.maintenanceContext })
  };
  return { ...unsigned, signature: signatureFor(unsigned, key) };
}

export interface NonceConsumer {
  consume(nonce: string, now?: number): void;
}

export class NonceTracker implements NonceConsumer {
  private readonly seen = new Map<string, number>();

  consume(nonce: string, now = Date.now()): void {
    for (const [value, expiresAt] of this.seen) {
      if (expiresAt <= now) this.seen.delete(value);
    }
    if (this.seen.has(nonce)) throw new Error('replayed nonce');
    this.seen.set(nonce, now + 120_000);
  }
}

export function verifyPrivilegedRequest(
  candidate: unknown,
  key: Buffer,
  nonces: NonceConsumer,
  now = Date.now()
): PrivilegedEnvelope {
  const envelope = envelopeSchema.parse(candidate);
  if (Math.abs(now - envelope.timestamp) > 60_000) {
    throw new Error('request timestamp outside allowed skew');
  }
  const payload = parsePrivilegedPayload(envelope.operation, envelope.payload);
  const unsigned: Omit<PrivilegedEnvelope, 'signature'> = {
    requestId: envelope.requestId,
    timestamp: envelope.timestamp,
    nonce: envelope.nonce,
    machineId: envelope.machineId,
    operation: envelope.operation,
    payload,
    ...(envelope.projectContext === undefined ? {} : { projectContext: envelope.projectContext }),
    ...(envelope.maintenanceContext === undefined ? {} : { maintenanceContext: envelope.maintenanceContext })
  };
  const expected = Buffer.from(signatureFor(unsigned, key), 'hex');
  const actual = Buffer.from(envelope.signature, 'hex');
  if (expected.length !== actual.length || !timingSafeEqual(expected, actual)) {
    throw new Error('invalid signature');
  }
  nonces.consume(envelope.nonce, now);
  return { ...unsigned, signature: envelope.signature };
}
