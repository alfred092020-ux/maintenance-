import type { BrainStore } from '../brain/store.js';
import type { MachineCapability, MachineRecord } from '../machines/types.js';

export interface MachineRouteRequest {
  requiredCapability: MachineCapability;
  preferredMachineId?: string;
}

function reportedLoad(machine: MachineRecord): number {
  const loadAverage = machine.metadata.loadAverage;
  if (
    Array.isArray(loadAverage) &&
    typeof loadAverage[0] === 'number' &&
    Number.isFinite(loadAverage[0])
  ) {
    return loadAverage[0];
  }

  const load = machine.metadata.load;
  if (typeof load === 'number' && Number.isFinite(load)) {
    return load;
  }

  return Number.POSITIVE_INFINITY;
}

export function selectMachineForJob(
  store: BrainStore,
  request: MachineRouteRequest
): MachineRecord | undefined {
  const candidates = store.listMachines().filter((machine) => {
    return (
      machine.status === 'ONLINE' &&
      store.machineHasCapability(machine.id, request.requiredCapability)
    );
  });

  if (request.preferredMachineId) {
    const preferred = candidates.find(
      (machine) => machine.id === request.preferredMachineId
    );
    if (preferred) return preferred;
  }

  const activeCounts = new Map<string, number>();
  for (const job of store.listRemoteJobs('RUNNING')) {
    if (!job.leaseOwner) continue;
    activeCounts.set(
      job.leaseOwner,
      (activeCounts.get(job.leaseOwner) ?? 0) + 1
    );
  }

  return candidates
    .sort((a, b) => {
      const activeDelta =
        (activeCounts.get(a.id) ?? 0) - (activeCounts.get(b.id) ?? 0);
      if (activeDelta !== 0) return activeDelta;

      const loadDelta = reportedLoad(a) - reportedLoad(b);
      if (Number.isFinite(loadDelta) && loadDelta !== 0) return loadDelta;
      if (reportedLoad(a) !== reportedLoad(b)) {
        return Number.isFinite(reportedLoad(a)) ? -1 : 1;
      }

      return a.id.localeCompare(b.id);
    })[0];
}

export class ExecutionRouter {
  constructor(private readonly store: BrainStore) {}

  select(
    requiredCapability: MachineCapability,
    preferredMachineId?: string
  ): MachineRecord | undefined {
    return selectMachineForJob(this.store, {
      requiredCapability,
      ...(preferredMachineId === undefined ? {} : { preferredMachineId })
    });
  }
}
