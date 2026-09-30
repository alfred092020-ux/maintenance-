import type { BrainStore } from '../brain/store.js';
import type { MachineCapability } from '../machines/types.js';
import type { PrivilegedOperation } from './protocol.js';

const REQUIRED_CAPABILITY: Record<PrivilegedOperation, MachineCapability> = {
  'process.execArgv': 'PRIVILEGED_EXECUTOR',
  'service.status': 'SERVICE_CONTROL',
  'service.start': 'SERVICE_CONTROL',
  'service.stop': 'SERVICE_CONTROL',
  'service.restart': 'SERVICE_CONTROL',
  'service.enable': 'SERVICE_CONTROL',
  'service.disable': 'SERVICE_CONTROL',
  'package.install': 'PACKAGE_INSTALL',
  'filesystem.chmod': 'HOST_PERMISSIONS',
  'filesystem.chown': 'HOST_PERMISSIONS',
  'network.status': 'NETWORK_ADMIN',
  'network.logresDevinProvision': 'NETWORK_ADMIN',
  'network.logresDevinTeardown': 'NETWORK_ADMIN',
  'systemd.logresDevinStart': 'SERVICE_CONTROL',
  'systemd.logresDevinStop': 'SERVICE_CONTROL',
  'service.logresManage': 'SERVICE_CONTROL',
  'service.nexusManage': 'SERVICE_CONTROL',
  'security.logresProfileReload': 'HOST_PERMISSIONS',
  'systemd.logresDaemonReload': 'SERVICE_CONTROL',
  'sysctl.logresSet': 'NETWORK_ADMIN',
  'deployment.logresInstallVerified': 'HOST_PERMISSIONS',
  'deployment.logresRuntimePromote': 'HOST_PERMISSIONS',
  'integration.logresPreflight': 'HOST_PERMISSIONS',
  'integration.logresVerify': 'AUTONOMOUS_EXEC',
  'integration.logresDevice': 'AUTONOMOUS_EXEC',
  'integration.logresBrain': 'HOST_PERMISSIONS',
  'integration.logresCoordinator': 'AUTONOMOUS_EXEC',
  'integration.logresVmExec': 'AUTONOMOUS_EXEC',
  'integration.logresCandidateCommit': 'AUTONOMOUS_EXEC',
  'integration.logresFinishTask': 'HOST_PERMISSIONS',
  'integration.logresWorkerLifecycle': 'HOST_PERMISSIONS',
  'deployment.nexusInstallVerified': 'HOST_PERMISSIONS',
  'deployment.nexusPromoteVerified': 'HOST_PERMISSIONS'
};

export function requiredCapabilityFor(
  operation: PrivilegedOperation
): MachineCapability {
  return REQUIRED_CAPABILITY[operation];
}

export function authorizePrivilegedOperation(
  store: BrainStore,
  machineId: string,
  operation: PrivilegedOperation
): void {
  const machine = store.getMachine(machineId);
  if (!machine) throw new Error('machine not found');
  if (machine.status === 'REVOKED') throw new Error('machine is revoked');

  const required = requiredCapabilityFor(operation);
  if (!store.machineHasCapability(machineId, required)) {
    throw new Error(`capability denied: ${required}`);
  }
}


export function machineCapabilitiesForPrivilegedPolicy(
  store: BrainStore,
  machineId: string
): ReadonlySet<MachineCapability> {
  const machine = store.getMachine(machineId);
  if (!machine) throw new Error('machine not found');
  if (machine.status === 'REVOKED') throw new Error('machine is revoked');
  return new Set(machine.capabilities);
}
