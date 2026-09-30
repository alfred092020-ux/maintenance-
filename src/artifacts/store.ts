import { createHash, randomUUID } from 'node:crypto';
import {
  access,
  mkdir,
  open,
  readFile,
  rename,
  stat,
  unlink
} from 'node:fs/promises';
import path from 'node:path';

export interface ArtifactMetadata {
  sha256: string;
  bytes: number;
  createdAt: string;
  updatedAt: string;
}

const SHA256 = /^[a-f0-9]{64}$/;

export class ArtifactStore {
  constructor(private readonly root: string) {}

  async put(
    bytes: Buffer,
    claimedSha256?: string
  ): Promise<ArtifactMetadata> {
    if (claimedSha256 !== undefined) this.validateSha256(claimedSha256);

    const sha256 = createHash('sha256').update(bytes).digest('hex');
    if (claimedSha256 !== undefined && claimedSha256 !== sha256) {
      throw new Error('artifact hash mismatch');
    }

    const finalPath = this.artifactPath(sha256);
    await mkdir(path.dirname(finalPath), { recursive: true });

    if (await this.exists(finalPath)) {
      return await this.metadata(sha256);
    }

    const tempPath = path.join(
      path.dirname(finalPath),
      `.${sha256}.${randomUUID()}.tmp`
    );
    const handle = await open(tempPath, 'wx', 0o600);
    try {
      await handle.writeFile(bytes);
      await handle.sync();
    } finally {
      await handle.close();
    }

    try {
      await rename(tempPath, finalPath);
    } catch (error) {
      await unlink(tempPath).catch(() => undefined);
      throw error;
    }

    return await this.metadata(sha256);
  }

  async get(sha256: string): Promise<Buffer> {
    this.validateSha256(sha256);
    return await readFile(this.artifactPath(sha256));
  }

  async has(sha256: string): Promise<boolean> {
    this.validateSha256(sha256);
    return await this.exists(this.artifactPath(sha256));
  }

  async metadata(sha256: string): Promise<ArtifactMetadata> {
    this.validateSha256(sha256);
    const info = await stat(this.artifactPath(sha256));
    return {
      sha256,
      bytes: info.size,
      createdAt: info.birthtime.toISOString(),
      updatedAt: info.mtime.toISOString()
    };
  }

  private validateSha256(sha256: string): void {
    if (!SHA256.test(sha256)) {
      throw new Error('invalid artifact sha256');
    }
  }

  private artifactPath(sha256: string): string {
    this.validateSha256(sha256);
    return path.join(this.root, sha256.slice(0, 2), sha256);
  }

  private async exists(filePath: string): Promise<boolean> {
    try {
      await access(filePath);
      return true;
    } catch {
      return false;
    }
  }
}
