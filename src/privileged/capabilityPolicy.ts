import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { MACHINE_CAPABILITIES } from '../machines/types.js';

export const PRIVILEGE_RISK_CLASSES = [
  'AUTO',
  'GOVERNED',
  'TEMPORARY',
  'HUMAN_ONLY'
] as const;

export type PrivilegeRiskClass = (typeof PRIVILEGE_RISK_CLASSES)[number];

const capabilitySchema = z.object({
  id: z.string().min(1).max(160).regex(/^[A-Za-z0-9._:-]+$/),
  operation: z.string().min(1).max(160).regex(/^[A-Za-z0-9._:-]+$/),
  riskClass: z.enum(PRIVILEGE_RISK_CLASSES),
  requiredMachineCapability: z.enum(MACHINE_CAPABILITIES),
  requireLogresLease: z.boolean().optional(),
  expiresAt: z.number().int().nonnegative().optional()
}).strict();

const bundleSchema = z.object({
  id: z.string().min(1).max(160).regex(/^[A-Za-z0-9._:-]+$/),
  capabilities: z.array(capabilitySchema).min(1)
}).strict();

const manifestSchema = z.object({
  schemaVersion: z.literal(1),
  policyVersion: z.string().min(1).max(160),
  validFrom: z.number().int().nonnegative().optional(),
  validUntil: z.number().int().nonnegative().optional(),
  bundles: z.array(bundleSchema).min(1)
}).strict();

export type CapabilityPolicyManifest = z.infer<typeof manifestSchema>;
export type CapabilityPolicyEntry = z.infer<typeof capabilitySchema>;

export interface LoadedCapabilityPolicy {
  policy: CapabilityPolicyManifest;
  digest: string;
  sourcePath: string;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
        .map(([key, item]) => [key, canonicalize(item)])
    );
  }
  return value;
}

function normalizedPolicy(policy: CapabilityPolicyManifest): CapabilityPolicyManifest {
  return {
    ...policy,
    bundles: [...policy.bundles]
      .map((bundle) => ({
        ...bundle,
        capabilities: [...bundle.capabilities].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
      }))
      .sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
  };
}

function validateConsistency(policy: CapabilityPolicyManifest, now: number): void {
  if (policy.validFrom !== undefined && now < policy.validFrom) {
    throw new Error('privileged policy is not yet valid');
  }
  if (policy.validUntil !== undefined && now >= policy.validUntil) {
    throw new Error('privileged policy expired');
  }
  if (
    policy.validFrom !== undefined &&
    policy.validUntil !== undefined &&
    policy.validUntil <= policy.validFrom
  ) {
    throw new Error('invalid privileged policy validity window');
  }

  const bundleIds = new Set<string>();
  const capabilityIds = new Set<string>();
  const operations = new Set<string>();
  for (const bundle of policy.bundles) {
    if (bundleIds.has(bundle.id)) throw new Error(`duplicate bundle id: ${bundle.id}`);
    bundleIds.add(bundle.id);
    for (const capability of bundle.capabilities) {
      if (capabilityIds.has(capability.id)) {
        throw new Error(`duplicate capability id: ${capability.id}`);
      }
      capabilityIds.add(capability.id);
      if (operations.has(capability.operation)) {
        throw new Error(`duplicate operation mapping: ${capability.operation}`);
      }
      operations.add(capability.operation);
      if (capability.riskClass === 'TEMPORARY' && capability.expiresAt === undefined) {
        throw new Error(`TEMPORARY capability requires expiresAt: ${capability.id}`);
      }
      if (capability.riskClass !== 'TEMPORARY' && capability.expiresAt !== undefined) {
        throw new Error(`expiresAt is only valid for TEMPORARY capability: ${capability.id}`);
      }
      if (capability.riskClass === 'GOVERNED' && capability.requireLogresLease !== true) {
        throw new Error(`GOVERNED capability requires requireLogresLease: ${capability.id}`);
      }
      if (capability.riskClass !== 'GOVERNED' && capability.requireLogresLease !== undefined) {
        throw new Error(`requireLogresLease is only valid for GOVERNED capability: ${capability.id}`);
      }
    }
  }
}

export function loadCapabilityPolicy(
  policyPath: string,
  now = Date.now()
): LoadedCapabilityPolicy {
  const sourcePath = path.resolve(policyPath);
  if (realpathSync.native(sourcePath) !== sourcePath) {
    throw new Error('privileged policy path must be a regular file without symlink components');
  }
  const fd = openSync(sourcePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let body: string;
  try {
    const info = fstatSync(fd);
    if (!info.isFile()) throw new Error('privileged policy path must be a regular file');
    body = readFileSync(fd, 'utf8');
  } finally {
    closeSync(fd);
  }

  const candidate = JSON.parse(body) as unknown;
  const policy = manifestSchema.parse(candidate);
  validateConsistency(policy, now);
  const normalized = canonicalize(normalizedPolicy(policy));
  const digest = createHash('sha256')
    .update(JSON.stringify(normalized))
    .digest('hex');
  return { policy: normalized as CapabilityPolicyManifest, digest, sourcePath };
}
