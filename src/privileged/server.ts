import { chmodSync, existsSync, unlinkSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import type { BrainStore } from '../brain/store.js';
import { redactText, redactValue } from '../security/redact.js';
import { authorizePrivilegedOperation, machineCapabilitiesForPrivilegedPolicy } from './policy.js';
import type { LoadedCapabilityPolicy } from './capabilityPolicy.js';
import { evaluatePrivilegeRequest } from './decision.js';
import type { LogresPrivilegeContextResolver } from './logresContext.js';
import {
  verifyPrivilegedRequest,
  type NonceConsumer,
  type PrivilegedEnvelope
} from './protocol.js';
import type {
  PrivilegedOperationExecutor,
  PrivilegedOperationResult
} from './operations.js';

export type { PrivilegedOperationExecutor } from './operations.js';

export interface PrivilegedServerOptions {
  socketPath: string;
  key: Buffer;
  store: BrainStore;
  policy: LoadedCapabilityPolicy;
  logresContextResolver: Pick<LogresPrivilegeContextResolver, 'resolve'>;
  executor: PrivilegedOperationExecutor;
  maxRequestBytes?: number;
}

export interface PrivilegedServerHandle {
  start(): Promise<void>;
  stop(): Promise<void>;
}

interface PrivilegedResponse {
  requestId: string;
  ok: boolean;
  result?: unknown;
  error?: string;
}

function responseLine(response: PrivilegedResponse): string {
  return JSON.stringify(redactValue(response)) + '\n';
}

function requestIdFromPrefix(buffer: Buffer): string {
  const text = buffer.subarray(0, Math.min(buffer.length, 512)).toString('utf8');
  return /"requestId"\s*:\s*"([^"]+)"/.exec(text)?.[1] ?? 'unknown';
}

export function createPrivilegedServer(
  options: PrivilegedServerOptions
): PrivilegedServerHandle {
  const nonces: NonceConsumer = {
    consume(nonce, now = Date.now()) {
      if (!options.store.consumePrivilegedNonce(nonce, now)) {
        throw new Error('replayed nonce');
      }
    }
  };
  let server: Server | undefined;

  async function handleEnvelope(
    candidate: unknown
  ): Promise<PrivilegedResponse> {
    let requestId = 'unknown';
    try {
      if (candidate && typeof candidate === 'object') {
        requestId =
          String((candidate as Record<string, unknown>).requestId ?? 'unknown');
      }
      const envelope = verifyPrivilegedRequest(
        candidate,
        options.key,
        nonces
      );
      requestId = envelope.requestId;
      authorizePrivilegedOperation(
        options.store,
        envelope.machineId,
        envelope.operation
      );
      const projectRef = envelope.projectContext;
      const lease = projectRef
        ? options.logresContextResolver.resolve(
            projectRef.taskId, projectRef.workerId, projectRef.branch
          )
        : null;
      const decision = evaluatePrivilegeRequest(
        options.policy,
        {
          machineId: envelope.machineId,
          operation: envelope.operation,
          payload: envelope.payload,
          now: Date.now()
        },
        {
          machineCapabilities: machineCapabilitiesForPrivilegedPolicy(
            options.store,
            envelope.machineId
          ),
          logresLease: lease
        }
      );
      if (!decision.allowed) {
        options.store.appendAudit({
          action: 'privileged.reject',
          actor: envelope.machineId,
          target: envelope.operation,
          detail: {
            requestId: envelope.requestId,
            capabilityId: decision.capabilityId,
            riskClass: decision.riskClass,
            policyVersion: decision.policyVersion,
            policyDigest: decision.policyDigest,
            projectContext: envelope.projectContext ?? null,
            reason: decision.reason
          }
        });
        return {
          requestId,
          ok: false,
          error: redactText(decision.reason)
        };
      }

      const result = await options.executor.execute(
        envelope.operation,
        envelope.payload
      );

      options.store.appendAudit({
        action: 'privileged.execute',
        actor: envelope.machineId,
        target: envelope.operation,
        detail: {
          requestId: envelope.requestId,
          ok: true,
          capabilityId: decision.capabilityId,
          riskClass: decision.riskClass,
          policyVersion: decision.policyVersion,
          policyDigest: decision.policyDigest,
          projectContext: envelope.projectContext ?? null
        }
      });

      return {
        requestId,
        ok: true,
        result: redactValue(result)
      };
    } catch (error) {
      const message = redactText(
        error instanceof Error ? error.message : String(error)
      );
      options.store.appendAudit({
        action: 'privileged.reject',
        actor: 'privileged-server',
        target: requestId,
        detail: { error: message }
      });
      return { requestId, ok: false, error: message };
    }
  }
  function handleSocket(socket: Socket): void {
    const maxBytes = options.maxRequestBytes ?? 1024 * 1024;
    let buffer = Buffer.alloc(0);
    let finished = false;

    const sendAndClose = (response: PrivilegedResponse) => {
      if (finished) return;
      finished = true;
      socket.end(responseLine(response));
    };

    socket.on('data', async (chunk: Buffer) => {
      if (finished) return;

      if (buffer.length + chunk.length > maxBytes) {
        const remaining = Math.max(0, 512 - buffer.length);
        const prefix = Buffer.concat([
          buffer.subarray(0, 512),
          chunk.subarray(0, remaining)
        ]);
        sendAndClose({
          requestId: requestIdFromPrefix(prefix),
          ok: false,
          error: 'request too large'
        });
        return;
      }

      buffer = Buffer.concat([buffer, chunk]);

      const newline = buffer.indexOf(0x0a);
      if (newline === -1) return;

      const line = buffer.subarray(0, newline).toString('utf8');
      try {
        const candidate = JSON.parse(line) as PrivilegedEnvelope;
        sendAndClose(await handleEnvelope(candidate));
      } catch (error) {
        sendAndClose({
          requestId: requestIdFromPrefix(buffer),
          ok: false,
          error: redactText(
            error instanceof Error ? error.message : String(error)
          )
        });
      }
    });
  }
  return {
    async start() {
      if (server) return;
      if (existsSync(options.socketPath)) unlinkSync(options.socketPath);

      server = createServer(handleSocket);
      await new Promise<void>((resolve, reject) => {
        const current = server!;
        current.once('error', reject);
        current.listen(options.socketPath, () => {
          current.off('error', reject);
          resolve();
        });
      });
      chmodSync(options.socketPath, 0o660);
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
      if (existsSync(options.socketPath)) unlinkSync(options.socketPath);
    }
  };
}
