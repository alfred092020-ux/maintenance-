import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { buildServer } from './buildServer.js';

serveStdio(() => buildServer(), {
  onerror(error) {
    console.error('[nexus-commander]', error);
  }
});
