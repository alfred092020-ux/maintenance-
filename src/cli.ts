import { access, mkdir, stat } from 'node:fs/promises';
import { constants } from 'node:fs';
import path from 'node:path';
import { openDatabase, openReadOnlyDatabase } from './brain/db.js';
import { BrainStore } from './brain/store.js';
import { loadConfig } from './config.js';
import {
  MACHINE_CAPABILITIES,
  type MachineCapability
} from './machines/types.js';

const VERSION = '0.1.0';

function statusPayload() {
  const config = loadConfig();
  const db = openReadOnlyDatabase(config.dbPath);
  if (!db) {
    return {
      database: config.dbPath,
      jobs: { queued: 0, running: 0 },
      logres: config.logresRoot,
      version: VERSION
    };
  }

  const store = new BrainStore(db);
  try {
    return {
      database: config.dbPath,
      jobs: {
        queued: store.countJobsByStatus('QUEUED'),
        running: store.countJobsByStatus('RUNNING')
      },
      logres: config.logresRoot,
      version: VERSION
    };
  } finally {
    store.close();
  }
}

async function check(run: () => Promise<void>): Promise<boolean> {
  try {
    await run();
    return true;
  } catch {
    return false;
  }
}

async function doctorPayload() {
  const config = loadConfig();
  await mkdir(config.stateDir, { recursive: true });

  const stateDirWritable = await check(() => access(config.stateDir, constants.W_OK));

  let sqlite = false;
  try {
    const store = new BrainStore(openDatabase(config.dbPath));
    store.close();
    sqlite = true;
  } catch {
    sqlite = false;
  }

  const logresLeadExecutable = await check(() =>
    access(path.join(config.logresRoot, 'bin/logres-lead'), constants.X_OK)
  );

  const gameRepoPresent = await check(async () => {
    const info = await stat(path.join(config.logresRoot, 'src/awakened-realms'));
    if (!info.isDirectory()) throw new Error('game repo is not a directory');
  });

  const nodeVersion = Number(process.versions.node.split('.')[0]) >= 24;

  const privilegedSocket =
    config.privilegedSocketPath === null
      ? null
      : await check(() => access(config.privilegedSocketPath!, constants.W_OK));

  const agentTlsConfigured = [
    config.agentCaPath,
    config.agentCertPath,
    config.agentKeyPath
  ].some((value) => value !== null);

  const agentTls =
    !agentTlsConfigured
      ? null
      : await check(async () => {
          if (!config.agentCaPath || !config.agentCertPath || !config.agentKeyPath) {
            throw new Error('incomplete agent TLS configuration');
          }
          await Promise.all([
            access(config.agentCaPath, constants.R_OK),
            access(config.agentCertPath, constants.R_OK),
            access(config.agentKeyPath, constants.R_OK)
          ]);
        });

  const checks = {
    stateDirWritable,
    sqlite,
    logresLeadExecutable,
    gameRepoPresent,
    nodeVersion
  };
  return {
    ok: Object.values(checks).every(Boolean),
    checks,
    optional: {
      privilegedSocket,
      agentTls
    },
    ...statusPayload()
  };
}


function openStore(): BrainStore {
  const config = loadConfig();
  return new BrainStore(openDatabase(config.dbPath));
}

function parseCapabilities(value: string): MachineCapability[] {
  const values = value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
  for (const item of values) {
    if (!(MACHINE_CAPABILITIES as readonly string[]).includes(item)) {
      throw new Error(`invalid machine capability: ${item}`);
    }
  }
  return [...new Set(values)] as MachineCapability[];
}

function machineListPayload() {
  const config = loadConfig();
  const db = openReadOnlyDatabase(config.dbPath);
  if (!db) return [];
  const store = new BrainStore(db);
  try {
    return store.listMachines();
  } finally {
    store.close();
  }
}

async function main() {
  const command = process.argv[2];
  if (command === 'status') {
    console.log(JSON.stringify(statusPayload()));
    return;
  }
  if (command === 'doctor') {
    const result = await doctorPayload();
    console.log(JSON.stringify(result));
    if (!result.ok) process.exitCode = 1;
    return;
  }
  if (command === 'machine-list') {
    console.log(JSON.stringify(machineListPayload()));
    return;
  }
  if (command === 'machine-enroll') {
    const [id, displayName, fingerprint] = process.argv.slice(3);
    if (!id || !displayName || !fingerprint) {
      throw new Error(
        'Usage: nexus machine-enroll <id> <displayName> <sha256Fingerprint>'
      );
    }
    const store = openStore();
    try {
      console.log(JSON.stringify(store.enrollMachine({
        id,
        displayName,
        certificateFingerprint: fingerprint
      }, 'cli')));
    } finally {
      store.close();
    }
    return;
  }
  if (command === 'machine-capabilities') {
    const [id, capabilities] = process.argv.slice(3);
    if (!id || capabilities === undefined) {
      throw new Error(
        'Usage: nexus machine-capabilities <id> <commaSeparatedCapabilities>'
      );
    }
    const store = openStore();
    try {
      store.setMachineCapabilities(
        id,
        parseCapabilities(capabilities),
        'cli'
      );
      console.log(JSON.stringify(store.getMachine(id)));
    } finally {
      store.close();
    }
    return;
  }
  if (command === 'machine-revoke') {
    const id = process.argv[3];
    if (!id) {
      throw new Error('Usage: nexus machine-revoke <id>');
    }
    const store = openStore();
    try {
      if (!store.revokeMachine(id, 'cli')) {
        throw new Error('machine not found or already revoked');
      }
      console.log(JSON.stringify(store.getMachine(id)));
    } finally {
      store.close();
    }
    return;
  }

  console.error(
    'Usage: nexus <status|doctor|machine-list|machine-enroll|machine-capabilities|machine-revoke>'
  );
  process.exitCode = 2;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
