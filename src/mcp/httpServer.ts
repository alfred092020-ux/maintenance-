import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:https';
import { Readable } from 'node:stream';
import type { TLSSocket } from 'node:tls';
import { createMcpHandler } from '@modelcontextprotocol/server';
import { openDatabase } from '../brain/db.js';
import { BrainStore } from '../brain/store.js';
import { loadConfig, type NexusConfig } from '../config.js';
import { LocalExecutor } from '../executor/localExecutor.js';
import { JobRunner } from '../jobs/jobRunner.js';
import {
  buildServer,
  reconcileGatewayStartup
} from './buildServer.js';
import {
  JwksAccessTokenVerifier,
  oauthChallenge,
  oauthProtectedResourceMetadata,
  type AccessTokenVerifier
} from './oauth.js';

export interface RemoteMcpServerOptions {
  config?: NexusConfig;
  tokenVerifier?: AccessTokenVerifier;
  maxRequestBytes?: number;
}

export interface RemoteMcpServerHandle {
  start(): Promise<{ host: string; port: number }>;
  stop(): Promise<void>;
}

function required(
  value: string | null,
  name: string
): string {
  if (!value) throw new Error(`missing required configuration: ${name}`);
  return value;
}

function bearerToken(
  header: string | undefined
): string | undefined {
  if (!header) return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1];
}

async function readBody(
  request: import('node:http').IncomingMessage,
  maxBytes: number
): Promise<Buffer> {
  if (request.method === 'GET' || request.method === 'HEAD') {
    return Buffer.alloc(0);
  }

  const length = Number(request.headers['content-length'] ?? 0);
  if (Number.isFinite(length) && length > maxBytes) {
    throw new Error('mcp request too large');
  }

  const chunks: Buffer[] = [];
  let total = 0;
  return await new Promise((resolve, reject) => {
    let failed = false;
    request.on('data', (chunk: Buffer) => {
      if (failed) return;
      total += chunk.length;
      if (total > maxBytes) {
        failed = true;
        reject(new Error('mcp request too large'));
        request.resume();
        return;
      }
      chunks.push(chunk);
    });
    request.once('end', () => {
      if (!failed) resolve(Buffer.concat(chunks));
    });
    request.once('error', reject);
  });
}
function sendJson(
  response: import('node:http').ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {}
): void {
  const encoded = JSON.stringify(body);
  response.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(encoded),
    ...headers
  });
  response.end(encoded);
}

async function sendWebResponse(
  response: import('node:http').ServerResponse,
  webResponse: Response
): Promise<void> {
  response.statusCode = webResponse.status;
  webResponse.headers.forEach((value, name) => {
    response.setHeader(name, value);
  });

  if (!webResponse.body) {
    response.end();
    return;
  }

  await new Promise<void>((resolve, reject) => {
    const readable = Readable.fromWeb(webResponse.body as never);
    readable.once('error', reject);
    response.once('error', reject);
    response.once('finish', resolve);
    readable.pipe(response);
  });
}

function originAllowed(
  origin: string | undefined,
  allowedOrigins: string[]
): boolean {
  if (!origin) return true;
  return allowedOrigins.includes(origin);
}

export function createRemoteMcpServer(
  options: RemoteMcpServerOptions = {}
): RemoteMcpServerHandle {
  const config = options.config ?? loadConfig();
  const publicUrl = required(
    config.mcpPublicUrl,
    'NEXUS_MCP_PUBLIC_URL'
  );
  const resourceUrl = new URL(publicUrl);
  if (resourceUrl.protocol !== 'https:') {
    throw new Error('NEXUS_MCP_PUBLIC_URL must use https');
  }
  if (resourceUrl.pathname !== '/mcp') {
    throw new Error('NEXUS_MCP_PUBLIC_URL must end in /mcp');
  }

  const issuer = required(config.oauthIssuer, 'NEXUS_OAUTH_ISSUER');
  const audience = config.oauthAudience ?? publicUrl;
  const tokenVerifier =
    options.tokenVerifier ??
    new JwksAccessTokenVerifier(
      required(config.oauthJwksUri, 'NEXUS_OAUTH_JWKS_URI'),
      issuer,
      audience,
      config.oauthScope
    );

  const store = new BrainStore(openDatabase(config.dbPath));
  const executor = new LocalExecutor(store, 'mcp-http');
  const runner = new JobRunner(store, executor, {
    timeoutMs: config.commandTimeoutMs,
    maxOutputBytes: config.maxOutputBytes
  });
  reconcileGatewayStartup(config, store, runner);

  const handler = createMcpHandler(
    () => buildServer({
      config,
      store,
      executor,
      runner,
      performStartupRecovery: false
    }),
    {
      responseMode: 'auto',
      onerror(error) {
        console.error('[nexus-mcp-http]', error);
      }
    }
  );

  let server: Server | undefined;
  return {
    async start() {
      if (server) throw new Error('remote MCP server already started');

      const clientCa =
        config.mcpClientCaPath === null
          ? undefined
          : readFileSync(config.mcpClientCaPath);

      server = createServer({
        cert: readFileSync(
          required(config.mcpTlsCertPath, 'NEXUS_MCP_TLS_CERT_PATH')
        ),
        key: readFileSync(
          required(config.mcpTlsKeyPath, 'NEXUS_MCP_TLS_KEY_PATH')
        ),
        ...(clientCa === undefined
          ? {}
          : {
              ca: clientCa,
              requestCert: true,
              rejectUnauthorized: true
            })
      }, async (request, response) => {
        try {
          if (clientCa !== undefined) {
            const socket = request.socket as TLSSocket;
            const peer = socket.getPeerCertificate();
            const san = peer.subjectaltname ?? '';
            if (
              !socket.authorized ||
              !san.split(',').map((value) => value.trim())
                .includes('DNS:mtls.prod.connectors.openai.com')
            ) {
              sendJson(response, 401, {
                error: 'untrusted MCP client certificate'
              });
              return;
            }
          }

          const path = request.url?.split('?')[0] ?? '/';
          const host = request.headers.host;
          if (host !== resourceUrl.host) {
            sendJson(response, 421, { error: 'invalid host' });
            return;
          }

          const origin =
            typeof request.headers.origin === 'string'
              ? request.headers.origin
              : undefined;
          if (!originAllowed(origin, config.mcpAllowedOrigins)) {
            sendJson(response, 403, { error: 'origin not allowed' });
            return;
          }

          if (
            request.method === 'GET' &&
            path === '/.well-known/oauth-protected-resource'
          ) {
            sendJson(
              response,
              200,
              oauthProtectedResourceMetadata(
                publicUrl,
                issuer,
                config.oauthScope
              )
            );
            return;
          }

          if (request.method === 'GET' && path === '/healthz') {
            sendJson(response, 200, { ok: true });
            return;
          }

          if (path !== '/mcp') {
            sendJson(response, 404, { error: 'not found' });
            return;
          }

          const token = bearerToken(
            typeof request.headers.authorization === 'string'
              ? request.headers.authorization
              : undefined
          );
          const challenge = oauthChallenge(
            publicUrl,
            config.oauthScope
          );
          if (!token) {
            sendJson(
              response,
              401,
              { error: 'authentication required' },
              { 'www-authenticate': challenge }
            );
            return;
          }

          let identity;
          try {
            identity = await tokenVerifier.verify(token);
          } catch (error) {
            const message =
              error instanceof Error ? error.message : String(error);
            const insufficient = /insufficient.*scope/i.test(message);
            sendJson(
              response,
              insufficient ? 403 : 401,
              {
                error: insufficient
                  ? 'insufficient_scope'
                  : 'invalid_token'
              },
              {
                'www-authenticate': oauthChallenge(
                  publicUrl,
                  config.oauthScope,
                  insufficient ? 'insufficient_scope' : 'invalid_token',
                  message
                )
              }
            );
            return;
          }

          const body = await readBody(
            request,
            options.maxRequestBytes ?? 2 * 1024 * 1024
          );
          const headers = new Headers();
          for (const [name, value] of Object.entries(request.headers)) {
            if (typeof value === 'string') {
              headers.set(name, value);
            } else if (Array.isArray(value)) {
              headers.set(name, value.join(', '));
            }
          }

          const webRequest = new Request(
            new URL(request.url ?? '/mcp', resourceUrl.origin),
            {
              method: request.method,
              headers,
              ...(body.length > 0
                ? { body: Uint8Array.from(body) }
                : {})
            }
          );

          const webResponse = await handler.fetch(webRequest, {
            authInfo: {
              token,
              clientId: identity.clientId,
              scopes: identity.scopes,
              ...(identity.expiresAt === undefined
                ? {}
                : { expiresAt: identity.expiresAt }),
              resource: resourceUrl,
              extra: {
                subject: identity.subject
              }
            }
          });
          await sendWebResponse(response, webResponse);
        } catch (error) {
          const message =
            error instanceof Error ? error.message : String(error);
          const status = message === 'mcp request too large' ? 413 : 500;
          sendJson(response, status, {
            error: status === 413 ? message : 'internal server error'
          });
          if (status === 500) {
            console.error('[nexus-mcp-http]', error);
          }
        }
      });

      await new Promise<void>((resolve, reject) => {
        const current = server!;
        current.once('error', reject);
        current.listen(
          config.mcpListenPort,
          config.mcpListenHost,
          () => {
            current.off('error', reject);
            resolve();
          }
        );
      });

      const address = server.address();
      if (!address || typeof address === 'string') {
        throw new Error('remote MCP server has no TCP address');
      }
      return {
        host: config.mcpListenHost,
        port: address.port
      };
    },

    async stop() {
      if (!server) return;
      const current = server;
      server = undefined;
      await handler.close();
      await new Promise<void>((resolve, reject) => {
        current.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      });
      store.close();
    }
  };
}
