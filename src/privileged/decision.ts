import type { MachineCapability } from '../machines/types.js';
import type {
  LoadedCapabilityPolicy,
  PrivilegeRiskClass
} from './capabilityPolicy.js';
import type { LogresLeaseContext } from './logresContext.js';

export interface PrivilegeRequestContext {
  machineId: string;
  operation: string;
  payload: unknown;
  now: number;
}

export interface PrivilegeProjectContext {
  machineCapabilities: ReadonlySet<MachineCapability>;
  logresLease: LogresLeaseContext | null;
  maintenanceTransaction: { transactionId: string; reason: string; expiresAt: number } | null;
}

export interface PolicyDecision {
  allowed: boolean;
  capabilityId: string | null;
  riskClass: PrivilegeRiskClass | null;
  policyVersion: string;
  policyDigest: string;
  reason: string;
}

function decision(
  policy: LoadedCapabilityPolicy,
  allowed: boolean,
  reason: string,
  capabilityId: string | null,
  riskClass: PrivilegeRiskClass | null
): PolicyDecision {
  return {
    allowed,
    capabilityId,
    riskClass,
    policyVersion: policy.policy.policyVersion,
    policyDigest: policy.digest,
    reason
  };
}

export function evaluatePrivilegeRequest(
  policy: LoadedCapabilityPolicy,
  context: PrivilegeRequestContext,
  projectContext: PrivilegeProjectContext
): PolicyDecision {
  const matches = policy.policy.bundles
    .flatMap((bundle) => bundle.capabilities)
    .filter((capability) => capability.operation === context.operation);

  if (matches.length === 0) {
    return decision(policy, false, 'operation is not authorized by privileged policy', null, null);
  }
  if (matches.length !== 1) {
    return decision(policy, false, 'operation maps to multiple privileged capabilities', null, null);
  }

  const capability = matches[0];
  if (!projectContext.machineCapabilities.has(capability.requiredMachineCapability)) {
    return decision(
      policy,
      false,
      `required machine capability missing: ${capability.requiredMachineCapability}`,
      capability.id,
      capability.riskClass
    );
  }

  if (capability.riskClass === 'HUMAN_ONLY') {
    return decision(policy, false, 'capability is HUMAN_ONLY', capability.id, capability.riskClass);
  }

  if (
    capability.riskClass === 'TEMPORARY' &&
    (capability.expiresAt === undefined || context.now >= capability.expiresAt)
  ) {
    return decision(policy, false, 'temporary privileged grant expired', capability.id, capability.riskClass);
  }

  if (capability.riskClass === 'GOVERNED') {
    if (capability.requireLogresLease) {
      if (!projectContext.logresLease || !Number.isFinite(projectContext.logresLease.expiresAt) || projectContext.logresLease.expiresAt <= context.now) {
        return decision(policy, false, 'active Logres lease required', capability.id, capability.riskClass);
      }
    } else if (capability.requireMaintenanceTransaction) {
      if (!projectContext.maintenanceTransaction || !Number.isFinite(projectContext.maintenanceTransaction.expiresAt) || projectContext.maintenanceTransaction.expiresAt <= context.now) {
        return decision(policy, false, 'active maintenance transaction required', capability.id, capability.riskClass);
      }
    } else {
      return decision(policy, false, 'governed capability has no governance authority', capability.id, capability.riskClass);
    }
  }

  return decision(policy, true, 'allowed by privileged capability policy', capability.id, capability.riskClass);
}
