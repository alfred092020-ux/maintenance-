import { randomBytes } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  fsyncSync,
  existsSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  statSync,
  writeFileSync
} from 'node:fs';
import path from 'node:path';

export interface SecretMetadata {
  id: string;
  createdAt: string;
  updatedAt: string;
  bytes: number;
}

const ID_PATTERN = /^sec_[a-f0-9]{32}$/;

export class SecretStore {
  constructor(private readonly root: string) {
    const existed = existsSync(root);
    mkdirSync(root, { recursive: true, mode: 0o700 });
    // A hardened MCP tunnel may mount an existing secret store read-only.
    // Opening it for secret resolution must not require metadata mutation.
    if (!existed) chmodSync(root, 0o700);
  }

  createSecret(value: string): SecretMetadata {
    const id = `sec_${randomBytes(16).toString('hex')}`;
    this.writeAtomic(id, value);
    return this.metadata(id);
  }

  resolveSecret(id: string): string {
    return readFileSync(this.secretPath(this.validateId(id)), 'utf8');
  }

  replaceSecret(id: string, value: string): SecretMetadata {
    const validId = this.validateId(id);
    statSync(this.secretPath(validId));
    this.writeAtomic(validId, value);
    return this.metadata(validId);
  }

  listSecrets(): SecretMetadata[] {
    return readdirSync(this.root)
      .filter((name) => name.endsWith('.secret'))
      .map((name) => name.slice(0, -'.secret'.length))
      .filter((id) => ID_PATTERN.test(id))
      .sort()
      .map((id) => this.metadata(id));
  }

  private writeAtomic(id: string, value: string): void {
    const finalPath = this.secretPath(id);
    const tempPath = path.join(
      this.root,
      `.${id}.${randomBytes(8).toString('hex')}.tmp`
    );
    const fd = openSync(tempPath, 'wx', 0o600);
    try {
      writeFileSync(fd, value, { encoding: 'utf8' });
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    chmodSync(tempPath, 0o600);
    renameSync(tempPath, finalPath);
    chmodSync(finalPath, 0o600);
  }

  private metadata(id: string): SecretMetadata {
    const info = statSync(this.secretPath(id));
    return {
      id,
      createdAt: info.birthtime.toISOString(),
      updatedAt: info.mtime.toISOString(),
      bytes: info.size
    };
  }

  private validateId(id: string): string {
    if (!ID_PATTERN.test(id)) throw new Error('invalid secret id');
    return id;
  }

  private secretPath(id: string): string {
    return path.join(this.root, `${id}.secret`);
  }
}
