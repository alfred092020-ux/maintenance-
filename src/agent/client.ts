import { request as httpsRequest } from 'node:https';

export interface AgentClientOptions {
  host: string;
  port: number;
  ca: Buffer;
  cert: Buffer;
  key: Buffer;
  servername?: string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  maxArtifactBytes?: number;
}

export class AgentClient {
  constructor(private readonly options: AgentClientOptions) {}

  identity(): Promise<Record<string, unknown>> {
    return this.request('GET', '/v1/identity');
  }

  heartbeat(
    metadata: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    return this.request('POST', '/v1/heartbeat', metadata);
  }

  leaseJob(
    leaseMs = 30_000,
    capabilities: string[] = []
  ): Promise<Record<string, unknown>> {
    return this.request('POST', '/v1/jobs/lease', {
      leaseMs,
      capabilities
    });
  }

  heartbeatJob(
    jobId: string,
    leaseMs = 30_000
  ): Promise<Record<string, unknown>> {
    return this.request('POST', `/v1/jobs/${encodeURIComponent(jobId)}/heartbeat`, {
      leaseMs
    });
  }

  finishJob(
    jobId: string,
    input: {
      status: 'SUCCEEDED' | 'FAILED';
      result: unknown;
    }
  ): Promise<Record<string, unknown>> {
    return this.request('POST', `/v1/jobs/${encodeURIComponent(jobId)}/result`, {
      status: input.status,
      result: input.result
    });
  }

  async hasArtifact(sha256: string): Promise<boolean> {
    this.validateArtifactSha256(sha256);
    const response = await this.artifactRequest(
      'HEAD',
      `/v1/artifacts/${sha256}`
    );
    if (response.statusCode === 200) return true;
    if (response.statusCode === 404) return false;
    throw new Error(`artifact request failed: ${response.statusCode}`);
  }

  async putArtifact(
    sha256: string,
    bytes: Buffer
  ): Promise<Record<string, unknown>> {
    this.validateArtifactSha256(sha256);
    const response = await this.artifactRequest(
      'PUT',
      `/v1/artifacts/${sha256}`,
      bytes
    );
    const text = response.body.toString('utf8');
    let parsed: Record<string, unknown> = {};
    try {
      parsed = text ? JSON.parse(text) as Record<string, unknown> : {};
    } catch {
      throw new Error('invalid artifact response JSON');
    }
    if (response.statusCode < 200 || response.statusCode >= 300) {
      const message =
        typeof parsed.error === 'string' ? parsed.error : JSON.stringify(parsed);
      throw new Error(
        `artifact request failed: ${response.statusCode} ${message}`
      );
    }
    return parsed;
  }

  async getArtifact(sha256: string): Promise<Buffer> {
    this.validateArtifactSha256(sha256);
    const response = await this.artifactRequest(
      'GET',
      `/v1/artifacts/${sha256}`
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw new Error(
        `artifact request failed: ${response.statusCode} ${response.body.toString('utf8')}`
      );
    }
    return response.body;
  }

  private validateArtifactSha256(sha256: string): void {
    if (!/^[a-f0-9]{64}$/.test(sha256)) {
      throw new Error('invalid artifact sha256');
    }
  }

  private artifactRequest(
    method: 'GET' | 'HEAD' | 'PUT',
    path: string,
    body?: Buffer
  ): Promise<{
    statusCode: number;
    body: Buffer;
  }> {
    const maxBytes = this.options.maxArtifactBytes ?? 64 * 1024 * 1024;

    return new Promise((resolve, reject) => {
      const req = httpsRequest({
        host: this.options.host,
        port: this.options.port,
        ...(this.options.servername
          ? { servername: this.options.servername }
          : {}),
        method,
        path,
        ca: this.options.ca,
        cert: this.options.cert,
        key: this.options.key,
        rejectUnauthorized: true,
        headers: body === undefined ? undefined : {
          'content-type': 'application/octet-stream',
          'content-length': body.length
        }
      }, (response) => {
        let total = 0;
        const chunks: Buffer[] = [];

        response.on('data', (chunk: Buffer) => {
          total += chunk.length;
          if (total > maxBytes) {
            req.destroy(new Error('artifact response too large'));
            return;
          }
          chunks.push(chunk);
        });

        response.once('end', () => {
          resolve({
            statusCode: response.statusCode ?? 500,
            body: Buffer.concat(chunks)
          });
        });
      });

      req.setTimeout(this.options.timeoutMs ?? 30_000, () => {
        req.destroy(new Error('artifact request timeout'));
      });
      req.once('error', reject);
      if (body !== undefined) req.write(body);
      req.end();
    });
  }

  private request(
    method: string,
    path: string,
    body?: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const maxBytes = this.options.maxResponseBytes ?? 256 * 1024;

    return new Promise((resolve, reject) => {
      const req = httpsRequest({
        host: this.options.host,
        port: this.options.port,
        ...(this.options.servername
          ? { servername: this.options.servername }
          : {}),
        method,
        path,
        ca: this.options.ca,
        cert: this.options.cert,
        key: this.options.key,
        rejectUnauthorized: true,
        headers: payload === undefined ? undefined : {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(payload)
        }
      }, (response) => {
        let total = 0;
        const chunks: Buffer[] = [];

        response.on('data', (chunk: Buffer) => {
          total += chunk.length;
          if (total > maxBytes) {
            req.destroy(new Error('agent response too large'));
            return;
          }
          chunks.push(chunk);
        });

        response.once('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let parsed: Record<string, unknown> = {};
          try {
            parsed = text ? JSON.parse(text) as Record<string, unknown> : {};
          } catch {
            reject(new Error('invalid agent response JSON'));
            return;
          }

          if ((response.statusCode ?? 500) < 200 ||
              (response.statusCode ?? 500) >= 300) {
            reject(new Error(
              `agent request failed: ${response.statusCode} ${JSON.stringify(parsed)}`
            ));
            return;
          }
          resolve(parsed);
        });
      });

      req.setTimeout(this.options.timeoutMs ?? 30_000, () => {
        req.destroy(new Error('agent request timeout'));
      });
      req.once('error', reject);
      if (payload !== undefined) req.write(payload);
      req.end();
    });
  }
}
