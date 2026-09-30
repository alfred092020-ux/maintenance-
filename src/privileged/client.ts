import { createConnection } from 'node:net';
import type { PrivilegedOperation, PrivilegedProjectContextRef } from './protocol.js';
import {
  signPrivilegedRequest,
  type PrivilegedEnvelope
} from './protocol.js';

export interface PrivilegedResponse {
  requestId: string;
  ok: boolean;
  result?: unknown;
  error?: string;
}

export interface PrivilegedClientOptions {
  socketPath: string;
  key: Buffer;
  machineId: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export class PrivilegedClient {
  constructor(private readonly options: PrivilegedClientOptions) {}

  request(operation: PrivilegedOperation, payload: unknown, projectContext?: PrivilegedProjectContextRef) {
    const envelope = signPrivilegedRequest({
      machineId: this.options.machineId,
      operation,
      payload,
      ...(projectContext === undefined ? {} : { projectContext })
    }, this.options.key);
    return this.sendEnvelope(envelope);
  }
  sendEnvelope(envelope: PrivilegedEnvelope): Promise<PrivilegedResponse> {
    const timeoutMs = this.options.timeoutMs ?? 30_000;
    const maxBytes = this.options.maxResponseBytes ?? 1024 * 1024;

    return new Promise((resolve, reject) => {
      const socket = createConnection(this.options.socketPath);
      let buffer = Buffer.alloc(0);
      const timer = setTimeout(() => {
        socket.destroy();
        reject(new Error('privileged request timeout'));
      }, timeoutMs);

      const finish = (response: PrivilegedResponse) => {
        clearTimeout(timer);
        socket.destroy();
        if (response.requestId !== envelope.requestId) {
          reject(new Error('privileged response correlation mismatch'));
          return;
        }
        resolve(response);
      };

      socket.once('connect', () => {
        socket.write(JSON.stringify(envelope) + '\n');
      });
      socket.on('data', (chunk: Buffer) => {
        if (buffer.length + chunk.length > maxBytes) {
          clearTimeout(timer);
          socket.destroy();
          reject(new Error('privileged response too large'));
          return;
        }
        buffer = Buffer.concat([buffer, chunk]);
        const newline = buffer.indexOf(0x0a);
        if (newline === -1) return;
        const line = buffer.subarray(0, newline).toString('utf8');
        try {
          finish(JSON.parse(line) as PrivilegedResponse);
        } catch (error) {
          clearTimeout(timer);
          socket.destroy();
          reject(error);
        }
      });

      socket.once('error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
  }
}
