export const MACHINE_CAPABILITIES = [
  'AUTONOMOUS_EXEC',
  'FILESYSTEM_WRITE',
  'SERVICE_CONTROL',
  'PACKAGE_INSTALL',
  'HOST_PERMISSIONS',
  'NETWORK_ADMIN',
  'CONTAINER_ADMIN',
  'PRIVILEGED_EXECUTOR'
] as const;

export type MachineCapability = (typeof MACHINE_CAPABILITIES)[number];
export type MachineStatus = 'ENROLLED' | 'ONLINE' | 'OFFLINE' | 'REVOKED';

export interface EnrollMachineInput {
  id: string;
  displayName: string;
  certificateFingerprint: string;
  metadata?: Record<string, unknown>;
}

export interface MachineRecord {
  id: string;
  displayName: string;
  certificateFingerprint: string;
  status: MachineStatus;
  lastSeenAt: string | null;
  enrolledAt: string;
  revokedAt: string | null;
  metadata: Record<string, unknown>;
  capabilities: MachineCapability[];
}

export function isMachineCapability(value: string): value is MachineCapability {
  return (MACHINE_CAPABILITIES as readonly string[]).includes(value);
}
