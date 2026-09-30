import { openDatabase } from '../brain/db.js';
import { BrainStore } from '../brain/store.js';
import { loadConfig } from '../config.js';
import { LocalExecutor } from '../executor/localExecutor.js';
import { JobRunner } from './jobRunner.js';

async function main(): Promise<void> {
  const jobId = process.argv[2];
  if (!jobId) throw new Error('job id is required');

  const config = loadConfig();
  const store = new BrainStore(openDatabase(config.dbPath));
  try {
    const runner = new JobRunner(store, new LocalExecutor(store, `job-worker:${process.pid}`), {
      timeoutMs: config.commandTimeoutMs,
      maxOutputBytes: config.maxOutputBytes
    });
    const ran = await runner.runJob(jobId, `pid:${process.pid}`);
    if (!ran) process.exitCode = 3;
  } finally {
    store.close();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
