import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import type { TLSSocket } from 'node:tls';
import type { BrainStore } from '../brain/store.js';
import type { ArtifactStore } from '../artifacts/store.js';
import { redactValue } from '../security/redact.js';
import { certificateFingerprint } from './identity.js';

export interface AgentServerOptions {
  host: string;
  port: number;
  key: Buffer;
  cert: Buffer;
  ca: Buffer;
  store: BrainStore;
  maxBodyBytes?: number;
  artifactStore?: ArtifactStore;
  maxArtifactBytes?: number;
}

export interface AgentServerHandle {
  start(): Promise<{ host: string; port: number }>;
  stop(): Promise<void>;
}

function sendJson(
  response: import('node:http').ServerResponse,
  statusCode: number,
  body: unknown
): void {
  const encoded = JSON.stringify(redactValue(body));
  response.writeHead(statusCode, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(encoded)
  });
  response.end(encoded);
}

async function readBinaryBody(
  request: import('node:http').IncomingMessage,
  maxBytes: number
): Promise<{ bytes: Buffer; sha256: string }> {
  const contentLength = Number(request.headers['content-length'] ?? 0);
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    throw new Error('artifact upload too large');
  }

  return await new Promise((resolve, reject) => {
    let total = 0;
    let failed = false;
    const chunks: Buffer[] = [];
    const hash = createHash('sha256');

    request.on('data', (chunk: Buffer) => {
      if (failed) return;
      total += chunk.length;
      if (total > maxBytes) {
        failed = true;
        reject(new Error('artifact upload too large'));
        request.resume();
        return;
      }
      hash.update(chunk);
      chunks.push(chunk);
    });
    request.once('end', () => {
      if (failed) return;
      resolve({
        bytes: Buffer.concat(chunks),
        sha256: hash.digest('hex')
      });
    });
    request.once('error', reject);
  });
}

async function readJsonBody(
  request: import('node:http').IncomingMessage,
  maxBytes: number
): Promise<Record<string, unknown>> {
  return await new Promise((resolve, reject) => {
    let total = 0;
    const chunks: Buffer[] = [];

    request.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error('request body too large'));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.once('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        const parsed = text.length === 0 ? {} : JSON.parse(text);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          throw new Error('request body must be an object');
        }
        resolve(parsed as Record<string, unknown>);
      } catch (error) {
        reject(error);
      }
    });
    request.once('error', reject);
  });
}

export function createAgentServer(
  options: AgentServerOptions
): AgentServerHandle {
  let server: Server | undefined;

  return {
    async start() {
      if (server) throw new Error('agent server already started');

      server = createServer({
        key: options.key,
        cert: options.cert,
        ca: options.ca,
        requestCert: true,
        rejectUnauthorized: true
      }, async (request, response) => {
        try {
          const socket = request.socket as TLSSocket;
          if (!socket.authorized) {
            sendJson(response, 401, { error: 'client certificate unauthorized' });
            return;
          }

          const peer = socket.getPeerCertificate(true);
          const raw = peer.raw;
          if (!raw) {
            sendJson(response, 401, { error: 'peer certificate missing' });
            return;
          }

          const fingerprint = certificateFingerprint(raw);
          const machine = options.store.findMachineByFingerprint(fingerprint);
          if (!machine || machine.status === 'REVOKED') {
            sendJson(response, 403, { error: 'machine certificate not enrolled' });
            return;
          }

          if (request.method === 'GET' && request.url === '/v1/identity') {
            sendJson(response, 200, {
              id: machine.id,
              displayName: machine.displayName,
              status: machine.status,
              capabilities: machine.capabilities,
              enrolledAt: machine.enrolledAt
            });
            return;
          }

          if (request.method === 'POST' && request.url === '/v1/heartbeat') {
            const metadata = await readJsonBody(
              request,
              options.maxBodyBytes ?? 64 * 1024
            );
            const updated = options.store.heartbeatMachine(
              machine.id,
              metadata
            );
            sendJson(response, 200, {
              ok: true,
              machineId: machine.id,
              lastSeenAt: updated.lastSeenAt
            });
            return;
          }

          const artifactMatch =
            /^\/v1\/artifacts\/([a-f0-9]{64})$/.exec(request.url ?? '');
          if (artifactMatch && options.artifactStore) {
            const sha256 = artifactMatch[1];

            if (request.method === 'PUT') {
              const upload = await readBinaryBody(
                request,
                options.maxArtifactBytes ?? 64 * 1024 * 1024
              );
              if (upload.sha256 !== sha256) {
                throw new Error('artifact hash mismatch');
              }
              const metadata = await options.artifactStore.put(
                upload.bytes,
                sha256
              );
              sendJson(response, 200, metadata);
              return;
            }

            if (request.method === 'HEAD') {
              const exists = await options.artifactStore.has(sha256);
              if (!exists) {
                response.writeHead(404);
                response.end();
                return;
              }
              const metadata = await options.artifactStore.metadata(sha256);
              response.writeHead(200, {
                'content-length': metadata.bytes,
                'x-nexus-sha256': sha256
              });
              response.end();
              return;
            }

            if (request.method === 'GET') {
              const exists = await options.artifactStore.has(sha256);
              if (!exists) {
                sendJson(response, 404, { error: 'artifact not found' });
                return;
              }
              const bytes = await options.artifactStore.get(sha256);
              response.writeHead(200, {
                'content-type': 'application/octet-stream',
                'content-length': bytes.length,
                'x-nexus-sha256': sha256
              });
              response.end(bytes);
              return;
            }
          }

          if (request.method === 'POST' && request.url === '/v1/jobs/lease') {
            const body = await readJsonBody(
              request,
              options.maxBodyBytes ?? 64 * 1024
            );
            const leaseMs =
              typeof body.leaseMs === 'number' ? body.leaseMs : 30_000;

            options.store.requeueExpiredRemoteJobs(Date.now());
            const job = options.store.leaseRemoteJob(
              machine.id,
              leaseMs,
              Date.now()
            );

            sendJson(response, 200, {
              job: job ?? null
            });
            return;
          }

          const heartbeatMatch =
            request.method === 'POST'
              ? /^\/v1\/jobs\/([^/]+)\/heartbeat$/.exec(request.url ?? '')
              : null;
          if (heartbeatMatch) {
            const body = await readJsonBody(
              request,
              options.maxBodyBytes ?? 64 * 1024
            );
            const leaseMs =
              typeof body.leaseMs === 'number' ? body.leaseMs : 30_000;
            const jobId = decodeURIComponent(heartbeatMatch[1]);
            options.store.heartbeatRemoteLease(
              jobId,
              machine.id,
              leaseMs,
              Date.now()
            );
            sendJson(response, 200, {
              ok: true,
              jobId
            });
            return;
          }

          const resultMatch =
            request.method === 'POST'
              ? /^\/v1\/jobs\/([^/]+)\/result$/.exec(request.url ?? '')
              : null;
          if (resultMatch) {
            const body = await readJsonBody(
              request,
              options.maxBodyBytes ?? 64 * 1024
            );
            const status =
              body.status === 'FAILED' ? 'FAILED' : 'SUCCEEDED';
            const jobId = decodeURIComponent(resultMatch[1]);
            options.store.finishRemoteJob(
              jobId,
              machine.id,
              body.result ?? null,
              Date.now(),
              status
            );
            sendJson(response, 200, {
              ok: true,
              jobId,
              status
            });
            return;
          }

          sendJson(response, 404, { error: 'not found' });
        } catch (error) {
          sendJson(response, 400, {
            error: error instanceof Error ? error.message : String(error)
          });
        }
      });

      await new Promise<void>((resolve, reject) => {
        const current = server!;
        current.once('error', reject);
        current.listen(options.port, options.host, () => {
          current.off('error', reject);
          resolve();
        });
      });

      const address = server.address() as AddressInfo;
      return { host: options.host, port: address.port };
    },

    async stop() {
      if (!server) return;
      const current = server;
      server = undefined;
      await new Promise<void>((resolve, reject) => {
        current.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      });
    }
  };
}
