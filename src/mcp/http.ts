import { createRemoteMcpServer } from './httpServer.js';

async function main(): Promise<void> {
  const server = createRemoteMcpServer();
  const address = await server.start();
  console.error(
    `Nexus MCP HTTPS listening on ${address.host}:${address.port}`
  );

  let stopping = false;
  const shutdown = async () => {
    if (stopping) return;
    stopping = true;
    await server.stop();
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
