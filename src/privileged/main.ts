import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { openDatabase } from '../brain/db.js';
import { BrainStore } from '../brain/store.js';
import { loadConfig, type NexusConfig } from '../config.js';
import { SecretStore } from '../security/secretStore.js';
import { SystemPrivilegedOperations } from './operations.js';
import { loadCapabilityPolicy } from './capabilityPolicy.js';
import { LogresPrivilegeContextResolver } from './logresContext.js';
import { createPrivilegedServer } from './server.js';

export function loadStartupCapabilityPolicy(config: NexusConfig) {
  if (!config.privilegedPolicyPath) throw new Error('privileged policy path is required');
  try {
    return loadCapabilityPolicy(config.privilegedPolicyPath);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`privileged policy load failed: ${message}`);
  }
}

export async function main(): Promise<void> {
  const config = loadConfig();
  if (!config.privilegedSocketPath || !config.privilegedSecretId || !config.privilegedPolicyPath) {
    throw new Error('privileged executor configuration is incomplete');
  }

  const secret = new SecretStore(config.secretStoreDir)
    .resolveSecret(config.privilegedSecretId);
  if (!/^[a-f0-9]{64}$/i.test(secret)) {
    throw new Error('invalid privileged auth key material');
  }

  const policy = loadStartupCapabilityPolicy(config);
  const store = new BrainStore(openDatabase(config.dbPath));
  const server = createPrivilegedServer({
    socketPath: config.privilegedSocketPath,
    key: Buffer.from(secret, 'hex'),
    store,
    policy,
    logresContextResolver: new LogresPrivilegeContextResolver(
      path.join(config.logresRoot, 'control', 'control.sqlite')
    ),
    executor: new SystemPrivilegedOperations(
      config.commandTimeoutMs,
      config.maxOutputBytes,
      new Set(config.privilegedExecAllowlist)
    )
  });

  await server.start();
  console.error(`Nexus privileged executor listening at ${config.privilegedSocketPath}`);

  const shutdown = async () => {
    await server.stop();
    store.close();
    process.exit(0);
  };
  process.once('SIGTERM', shutdown);
  process.once('SIGINT', shutdown);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
