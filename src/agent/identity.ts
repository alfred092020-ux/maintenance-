import { createHash } from 'node:crypto';

export function certificateFingerprint(rawCertificate: Buffer): string {
  if (rawCertificate.length === 0) throw new Error('peer certificate missing');
  return createHash('sha256').update(rawCertificate).digest('hex');
}
