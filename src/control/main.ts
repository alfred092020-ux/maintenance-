import { readFileSync } from 'node:fs';
import { createAgentServer } from '../agent/server.js';
import { ArtifactStore } from '../artifacts/store.js';
import { openDatabase } from '../brain/db.js';
import { BrainStore } from '../brain/store.js';
import { loadConfig } from '../config.js';

function requiredPath(
  value: string | null,
  name: string
): string {
  if (!value) throw new Error(`missing required configuration: ${name}`);
  return value;
}

async function main(): Promise<void> {
  const config = loadConfig();
  if (
    !Number.isInteger(config.controlListenPort) ||
    config.controlListenPort < 1 ||
    config.controlListenPort > 65535
  ) {
    throw new Error('invalid NEXUS_CONTROL_LISTEN_PORT');
  }

  const store = new BrainStore(openDatabase(config.dbPath));
  const artifacts = new ArtifactStore(config.artifactDir);
  const server = createAgentServer({
    host: config.controlListenHost,
    port: config.controlListenPort,
    key: readFileSync(
      requiredPath(config.controlKeyPath, 'NEXUS_CONTROL_KEY_PATH')
    ),
    cert: readFileSync(
      requiredPath(config.controlCertPath, 'NEXUS_CONTROL_CERT_PATH')
    ),
    ca: readFileSync(
      requiredPath(config.controlCaPath, 'NEXUS_CONTROL_CA_PATH')
    ),
    store,
    artifactStore: artifacts,
    maxBodyBytes: config.controlMaxBodyBytes,
    maxArtifactBytes: config.controlMaxArtifactBytes
  });

  const address = await server.start();
  console.error(
    `Nexus control plane listening on ${address.host}:${address.port}`
  );

  let stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    await server.stop();
    store.close();
  };

  process.once('SIGTERM', () => {
    void shutdown().then(() => process.exit(0));
  });
  process.once('SIGINT', () => {
    void shutdown().then(() => process.exit(0));
  });
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
