import { createHash, randomUUID } from 'node:crypto';
import { mkdir, rename, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';

const proposalSchema = z.object({
  requestedCapabilityId: z.string().min(1).max(160).regex(/^[A-Za-z0-9._:-]+$/),
  rationale: z.string().min(1).max(4000),
  scope: z.string().min(1).max(4000),
  rollbackNote: z.string().min(1).max(4000),
  requester: z.string().min(1).max(160).regex(/^[A-Za-z0-9._:-]+$/),
  createdAt: z.number().int().nonnegative(),
  evidenceRefs: z.array(z.string().min(1).max(512)).max(64)
}).strict();

export type PrivilegePolicyProposal = z.infer<typeof proposalSchema>;

export async function writePolicyProposal(
  proposalDir: string,
  proposal: PrivilegePolicyProposal
): Promise<{ path: string; sha256: string }> {
  const parsed = proposalSchema.parse(proposal);
  const resolved = path.resolve(proposalDir);
  try {
    const info = await stat(resolved);
    if (!info.isDirectory()) throw new Error('proposal path must be a directory');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== 'ENOENT') throw error;
    if (path.extname(resolved)) throw new Error('proposal path must be a directory');
    await mkdir(resolved, { recursive: true, mode: 0o700 });
  }
  const body = `${JSON.stringify(parsed, null, 2)}\n`;
  const sha256 = createHash('sha256').update(body).digest('hex');
  const name = `${parsed.createdAt}-${parsed.requestedCapabilityId}-${randomUUID()}.json`;
  const target = path.join(resolved, name);
  const temp = `${target}.tmp`;
  await writeFile(temp, body, { flag: 'wx', mode: 0o600 });
  await rename(temp, target);
  return { path: target, sha256 };
}
