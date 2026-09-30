import type { MachineCapability } from '../machines/types.js';

export interface CreateRemoteJobInput {
  kind: string;
  payload: Record<string, unknown>;
  targetMachineId?: string;
  requiredCapability?: MachineCapability;
  priority?: number;
  reassignable?: boolean;
}

export interface RemoteRequeueResult {
  requeued: number;
  failed: number;
}
