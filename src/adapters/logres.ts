import path from 'node:path';
import type { PrivilegedClient } from '../privileged/client.js';
import type { PrivilegedOperation } from '../privileged/protocol.js';
import type { LocalExecutor, ExecResult } from '../executor/localExecutor.js';

const ID_RE = /^[A-Za-z0-9._:-]+$/;
const BRANCH_RE = /^[A-Za-z0-9._\/-]+$/;
const REF_RE = /^[A-Za-z0-9._\/-]+$/;
const BATON_STATES = new Set(['RUNNING', 'CONTINUE_REQUESTED', 'PAUSED', 'WAITING_USER', 'DONE']);

function assertId(value: string, label: string): string {
  if (!ID_RE.test(value)) throw new Error(`invalid ${label}`);
  return value;
}

function assertBranch(value: string): string {
  if (!BRANCH_RE.test(value) || value === 'main' || value === 'feat/logres-reconstruction') {
    throw new Error('invalid or protected branch');
  }
  return value;
}

function assertRef(value: string): string {
  if (!REF_RE.test(value)) throw new Error('invalid git ref');
  return value;
}

function quote(value: string): string {
  if (value.includes('\0')) throw new Error('invalid text');
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

function covered(path: string, prefix: string): boolean {
  const p = path.replace(/^\/+|\/+$/g, '');
  const q = prefix.replace(/^\/+|\/+$/g, '');
  return p === q || p.startsWith(q + '/') || q.startsWith(p + '/');
}

export class LogresAdapter {
  constructor(
    private readonly executor: Pick<LocalExecutor, 'exec'> & Partial<Pick<LocalExecutor, 'execReadOnly' | 'readFile'>>,
    private readonly root: string,
    private readonly privilegedClient?: Pick<PrivilegedClient, 'request'>
  ) {}

  private exec(command: string, timeoutMs = 120_000, maxOutputBytes = 512 * 1024) {
    return this.executor.exec({ command, timeoutMs, maxOutputBytes });
  }

  private readExec(command: string, timeoutMs = 120_000, maxOutputBytes = 512 * 1024) {
    const fn = this.executor.execReadOnly ?? this.executor.exec.bind(this.executor);
    return fn.call(this.executor, { command, timeoutMs, maxOutputBytes });
  }

  private async checkedRead(command: string, timeoutMs = 120_000, maxOutputBytes = 512 * 1024): Promise<ExecResult> {
    const result = await this.readExec(command, timeoutMs, maxOutputBytes);
    if (result.timedOut || result.exitCode !== 0) throw new Error('Logres command failed: ' + (result.stderr.trim() || result.stdout.trim() || String(result.exitCode)));
    return result;
  }

  private async checked(
    command: string,
    timeoutMs = 120_000,
    maxOutputBytes = 512 * 1024
  ): Promise<ExecResult> {
    const result = await this.exec(command, timeoutMs, maxOutputBytes);
    if (result.timedOut || result.exitCode !== 0) {
      throw new Error(
        'Logres command failed: ' +
          (result.stderr.trim() || result.stdout.trim() || String(result.exitCode))
      );
    }
    return result;
  }

  private lead(args: string) {
    return this.readExec(`${this.root}/bin/logres-lead ${args}`);
  }

  brief() {
    return this.lead('brief');
  }

  next() {
    return this.lead('next');
  }

  queue() {
    return this.lead('queue');
  }

  verify(ref: string) {
    assertRef(ref);
    if (this.privilegedClient) return this.privilegedClient.request('integration.logresVerify', { ref }).then((response) => { if (!response.ok) throw new Error(response.error ?? 'privileged verification failed'); return response.result as ExecResult; });
    return this.exec(`${this.root}/bin/logres-verify-ref ${ref}`, 900_000, 1024 * 1024);
  }

  brainCreateTask(taskId: string, priority: number, workType: string, title: string) {
    assertId(taskId, 'task id');
    if (!Number.isInteger(priority) || priority < 0 || priority > 1000) throw new Error('invalid priority');
    assertId(workType, 'work type');
    if (this.privilegedClient) return this.privilegedClient.request('integration.logresBrain', { action: 'createTask', taskId, priority, workType, title });
    return this.exec(`${this.root}/bin/logres-control new-task ${taskId} ${priority} ${workType} ${quote(title)}`);
  }

  brainLease(chatId: string, taskId: string, minutes: number, branch: string) {
    assertId(chatId, 'chat id'); assertId(taskId, 'task id'); assertBranch(branch);
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) throw new Error('invalid lease minutes');
    if (this.privilegedClient) return this.privilegedClient.request('integration.logresBrain', { action: 'lease', chatId, taskId, minutes, branch });
    return this.exec(`${this.root}/bin/logres-brain lease ${chatId} ${taskId} --minutes ${minutes} --branch ${branch}`);
  }

  brainProgress(chatId: string, taskId: string, percent: number, note: string) {
    assertId(chatId, 'chat id'); assertId(taskId, 'task id');
    if (!Number.isInteger(percent) || percent < 0 || percent > 100) throw new Error('invalid progress');
    if (this.privilegedClient) return this.privilegedClient.request('integration.logresBrain', { action: 'progress', chatId, taskId, percent, note });
    return this.exec(`${this.root}/bin/logres-brain progress ${chatId} ${taskId} ${percent} --note ${quote(note)}`);
  }

  brainEvidence(chatId: string, confidence: 'HIGH' | 'MEDIUM' | 'LOW', subject: string, summary: string, taskId?: string) {
    assertId(chatId, 'chat id'); if (taskId) assertId(taskId, 'task id');
    if (this.privilegedClient) return this.privilegedClient.request('integration.logresBrain', { action: 'evidence', chatId, confidence, subject, summary, ...(taskId ? { taskId } : {}) });
    return this.exec(`${this.root}/bin/logres-brain evidence ${chatId} ${confidence} ${quote(subject)} ${quote(summary)}${taskId ? ` --task ${taskId}` : ''}`);
  }

  brainBlock(chatId: string, taskId: string, note: string) {
    assertId(chatId, 'chat id'); assertId(taskId, 'task id');
    if (this.privilegedClient) return this.privilegedClient.request('integration.logresBrain', { action: 'block', chatId, taskId, note });
    return this.exec(`${this.root}/bin/logres-brain release ${chatId} ${taskId} --status BLOCKED_DEP --note ${quote(note)}`);
  }

  taskStatus(taskId: string) {
    assertId(taskId, 'task id');
    return this.readExec(
      `${this.root}/bin/logres-brain history --task ${taskId} --limit 50`
    );
  }

  private deviceArtifactPath(value: string) {
    const resolved = path.resolve(value);
    const root = path.resolve(this.root, 'artifacts');
    if (!resolved.startsWith(root + path.sep)) throw new Error('device artifact path outside Logres artifacts');
    return resolved;
  }

  deviceQaStatus() { return this.readExec(`${this.root}/bin/logres-phone-qa status`, 60_000); }
  deviceScreenshot(outputPath: string) {
    const resolved = this.deviceArtifactPath(outputPath);
    if (this.privilegedClient) return this.privilegedClient.request('integration.logresDevice', { action: 'screenshot', outputPath: resolved }).then((response) => { if (!response.ok) throw new Error(response.error ?? 'privileged screenshot failed'); return response.result; });
    return this.exec(`${this.root}/bin/logres-phone-qa screenshot ${quote(resolved)}`, 120_000);
  }
  deviceLogcat(outputPath: string) {
    const resolved = this.deviceArtifactPath(outputPath);
    if (this.privilegedClient) return this.privilegedClient.request('integration.logresDevice', { action: 'logcat', outputPath: resolved }).then((response) => { if (!response.ok) throw new Error(response.error ?? 'privileged logcat failed'); return response.result; });
    return this.exec(`${this.root}/bin/logres-phone-qa logcat ${quote(resolved)}`, 120_000, 2 * 1024 * 1024);
  }
  deviceCertify(sha: string) {
    if (!/^[a-f0-9]{40}$/.test(sha)) throw new Error('invalid exact SHA');
    if (this.privilegedClient) return this.privilegedClient.request('integration.logresDevice', { action: 'certify', sha }).then((response) => { if (!response.ok) throw new Error(response.error ?? 'privileged device certification failed'); return response.result; });
    return this.exec(`${this.root}/bin/logres-hardware-qa --sha ${sha}`, 900_000, 2 * 1024 * 1024);
  }

  async continueMission(chatId: string) {
    assertId(chatId, 'chat id');
    await this.next();
    return this.workerStart(chatId, 'AUTO');
  }

  workerStart(chatId: string, taskId: string, branch?: string) {
    assertId(chatId, 'chat id');
    if (taskId !== 'AUTO') assertId(taskId, 'task id');
    if (branch) assertBranch(branch);
    if (!this.privilegedClient) { const branchArg = branch ? ` ${branch}` : ''; return this.exec(`${this.root}/bin/logres-worker-start ${chatId} ${taskId}${branchArg}`, 180_000, 1024 * 1024); }
    return this.privilegedClient.request('integration.logresWorkerLifecycle', { action: 'start', chatId, taskId, ...(branch ? { branch } : {}) });
  }

  workerRelease(chatId: string, taskId: string, note = 'released through Nexus typed bridge') {
    assertId(chatId, 'chat id'); assertId(taskId, 'task id');
    if (!this.privilegedClient) return this.exec(`${this.root}/bin/logres-brain release ${chatId} ${taskId} --status READY --note ${quote(note)}`);
    return this.privilegedClient.request('integration.logresWorkerLifecycle', { action: 'release', chatId, taskId, note });
  }


  async resolveWorkerIsolation(
    chatId: string,
    taskId: string,
    branch: string,
    allowHistorical = false
  ) {
    assertId(chatId, 'chat id');
    assertId(taskId, 'task id');
    assertBranch(branch);

    const db = this.root + '/control/control.sqlite';
    const repo = this.root + '/src/awakened-realms';
    const leaseQuery =
      "select coalesce(chat_id,''), coalesce(branch,'') from brain_task_leases where task_id='" +
      taskId + "';";
    const lease = (await this.checkedRead(
      'sqlite3 -readonly ' + quote(db) + " -separator '|' " + quote(leaseQuery)
    )).stdout.trim();
    let [owner = '', leaseBranch = ''] = lease.split('|');
    if (owner) {
      if (owner !== chatId) {
        throw new Error('task lease is not owned by ' + chatId);
      }
      if (leaseBranch !== branch) {
        throw new Error('task lease branch does not match requested branch');
      }
    } else if (allowHistorical) {
      const historyQuery =
        "select coalesce(chat_id,''), coalesce(branch,'') from lease_history where task_id='" +
        taskId + "' order by id desc limit 1;";
      const historical = (await this.checkedRead(
        'sqlite3 -readonly ' + quote(db) + " -separator '|' " + quote(historyQuery)
      )).stdout.trim();
      [owner = '', leaseBranch = ''] = historical.split('|');
      if (owner !== chatId || leaseBranch !== branch) {
        throw new Error('latest task lease history does not match requested worker');
      }
    } else {
      throw new Error('task lease is not owned by ' + chatId);
    }

    const worktrees = (await this.checkedRead(
      'git -C ' + quote(repo) + ' worktree list --porcelain'
    )).stdout.split(/\n\n+/);
    const target = worktrees.find((block) =>
      block.split(/\r?\n/).includes('branch refs/heads/' + branch)
    );
    const rawWorktree = target
      ?.split(/\r?\n/)
      .find((line) => line.startsWith('worktree '))
      ?.slice('worktree '.length)
      .trim();
    if (!rawWorktree) throw new Error('no worktree registered for branch');

    const worktree = path.resolve(rawWorktree);
    const workRoot = path.resolve(this.root, 'work');
    if (worktree === workRoot || !worktree.startsWith(workRoot + path.sep)) {
      throw new Error('worker worktree is outside managed Logres work root');
    }
    const isolationName = path.basename(worktree)
      .replace(/[^A-Za-z0-9._-]+/g, '-')
      .replace(/^[-.]+|[-.]+$/g, '')
      .slice(0, 48) || 'worker';
    return { chatId, taskId, branch, worktree, isolationName };
  }


  private async workerContext(chatId: string, taskId: string, branch: string) {
    return this.resolveWorkerIsolation(chatId, taskId, branch);
  }

  private resolveWorkerPath(worktree: string, relativePath = '.'): string {
    if (path.isAbsolute(relativePath)) throw new Error('worker path must be relative');
    const resolved = path.resolve(worktree, relativePath);
    if (resolved !== worktree && !resolved.startsWith(worktree + path.sep)) {
      throw new Error('worker path escapes managed worktree');
    }
    return resolved;
  }

  private vmExecutableCommand(
    worktree: string,
    executable: 'git' | 'npm' | 'node' | 'python3' | 'bash' | 'adb',
    argv: string[]
  ): string {
    if (argv.length > 128 || argv.some((arg) => arg.length > 4096 || arg.includes('\0'))) {
      throw new Error('invalid VM argv');
    }
    const executablePath = {
      git: '/usr/bin/git',
      npm: '/usr/bin/npm',
      node: '/usr/bin/node',
      python3: '/usr/bin/python3',
      bash: '/usr/bin/bash',
      adb: '/usr/bin/adb'
    }[executable];

    if ((executable === 'node' && argv.some((arg) => arg === '-e' || arg === '--eval')) ||
        (executable === 'python3' && argv.some((arg) => arg === '-c')) ||
        (executable === 'bash' && argv.some((arg) => arg === '-c'))) {
      throw new Error('inline code execution is not approved for VM commands');
    }

    if (executable === 'bash') {
      const script = argv.find((arg) => !arg.startsWith('-'));
      if (!script) throw new Error('bash VM command requires a worktree script');
      this.resolveWorkerPath(worktree, script);
    }

    const safeArgs = argv.map((arg) => quote(arg)).join(' ');
    const gitEnv = executable === 'git'
      ? 'GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null '
      : '';
    return `${gitEnv}${quote(executablePath)}${safeArgs ? ' ' + safeArgs : ''}`;
  }

  async vmExec(
    chatId: string,
    taskId: string,
    branch: string,
    executable: 'git' | 'npm' | 'node' | 'python3' | 'bash' | 'adb',
    argv: string[],
    cwd = '.',
    timeoutMs = 120_000
  ) {
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 900_000) {
      throw new Error('invalid VM timeout');
    }
    if (this.privilegedClient) {
      const response = await this.governedPrivilegedRequest(chatId, taskId, branch, 'integration.logresVmExec', { chatId, taskId, branch, executable, argv, cwd, timeoutMs });
      if (!response.ok) throw new Error(response.error ?? 'privileged VM execution failed');
      return response.result as ExecResult;
    }
    const identity = await this.workerContext(chatId, taskId, branch);
    const workingDirectory = this.resolveWorkerPath(identity.worktree, cwd);
    const command = this.vmExecutableCommand(identity.worktree, executable, argv);
    return this.exec(
      `cd ${quote(workingDirectory)} && ${command}`,
      timeoutMs,
      1024 * 1024
    );
  }

  async vmReadFile(
    chatId: string,
    taskId: string,
    branch: string,
    filePath: string,
    maxBytes = 1024 * 1024
  ) {
    if (!this.executor.readFile) throw new Error('file reads are not configured');
    if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 4 * 1024 * 1024) {
      throw new Error('invalid VM read bound');
    }
    const identity = await this.workerContext(chatId, taskId, branch);
    const resolved = path.resolve(filePath);
    const allowedRoots = [
      identity.worktree,
      path.resolve(this.root, 'control'),
      path.resolve(this.root, 'logs'),
      path.resolve(this.root, 'artifacts')
    ];
    if (!allowedRoots.some((root) => resolved === root || resolved.startsWith(root + path.sep))) {
      throw new Error('VM file path is outside approved Logres roots');
    }
    return this.executor.readFile(resolved, maxBytes);
  }

  async gitState(chatId: string, taskId: string, branch: string) {
    const identity = await this.workerContext(chatId, taskId, branch);
    const repo = this.root + '/src/awakened-realms';
    const integrationHead = (await this.checkedRead(
      'git -C ' + quote(repo) + ' rev-parse feat/logres-reconstruction'
    )).stdout.trim();
    const originIntegrationHead = (await this.checkedRead(
      'git -C ' + quote(repo) + ' rev-parse origin/feat/logres-reconstruction'
    )).stdout.trim();
    const workerHead = (await this.checkedRead(
      'git -C ' + quote(identity.worktree) + ' rev-parse HEAD'
    )).stdout.trim();
    const status = (await this.checkedRead(
      'git -C ' + quote(identity.worktree) + ' status --short --branch'
    )).stdout;
    return {
      integrationBranch: 'feat/logres-reconstruction',
      integrationHead,
      originIntegrationHead,
      workerBranch: branch,
      workerHead,
      worktree: identity.worktree,
      status,
      clean: status.trim() === ''
    };
  }

  async processList(chatId: string, taskId: string, branch: string) {
    await this.workerContext(chatId, taskId, branch);
    return this.readExec(
      "/usr/bin/ps -eo pid=,ppid=,user=,stat=,etime=,comm= --sort=pid",
      30_000,
      512 * 1024
    );
  }

  private requirePrivilegedClient(): Pick<PrivilegedClient, 'request'> {
    if (!this.privilegedClient) {
      throw new Error('privileged Nexus client is not configured');
    }
    return this.privilegedClient;
  }

  private async governedPrivilegedRequest(
    chatId: string, taskId: string, branch: string,
    operation: PrivilegedOperation, payload: unknown
  ) {
    assertId(chatId, 'chat id');
    assertId(taskId, 'task id');
    assertBranch(branch);
    // The privileged executor performs the authoritative live-lease check.
    // Do not route this through the tunnel-side audited LocalExecutor: the
    // hardened tunnel intentionally has read-only access to the Nexus DB.
    return this.requirePrivilegedClient().request(
      operation, payload, { taskId, workerId: chatId, branch }
    );
  }

  async manageHostService(chatId: string, taskId: string, branch: string, name: string, action: 'status' | 'start' | 'stop' | 'restart') {
    return this.governedPrivilegedRequest(chatId, taskId, branch, 'service.logresManage', { name, action });
  }

  async reloadSecurityProfile(chatId: string, taskId: string, branch: string, profile: string) {
    return this.governedPrivilegedRequest(chatId, taskId, branch, 'security.logresProfileReload', { profile });
  }

  async reloadSystemd(chatId: string, taskId: string, branch: string) {
    return this.governedPrivilegedRequest(chatId, taskId, branch, 'systemd.logresDaemonReload', {});
  }

  async setHostSysctl(chatId: string, taskId: string, branch: string, key: 'net.ipv4.ip_forward', value: 0 | 1) {
    return this.governedPrivilegedRequest(chatId, taskId, branch, 'sysctl.logresSet', { key, value });
  }

  async installVerifiedHostArtifact(chatId: string, taskId: string, branch: string, sourcePath: string, destinationPath: string, sha256: string) {
    return this.governedPrivilegedRequest(chatId, taskId, branch, 'deployment.logresInstallVerified', { sourcePath, destinationPath, sha256 });
  }

  async promoteVerifiedNexusRuntime(chatId: string, taskId: string, branch: string, sourcePath: string, sha256: string) {
    return this.governedPrivilegedRequest(chatId, taskId, branch, 'deployment.nexusPromoteVerified', { sourcePath, sha256 });
  }

  async promoteLogresRuntime(chatId: string, taskId: string, branch: string, sha: string) {
    return this.governedPrivilegedRequest(chatId, taskId, branch, 'deployment.logresRuntimePromote', { sha });
  }

  async provisionWorkerNetwork(chatId: string, taskId: string, branch: string) {
    const identity = await this.resolveWorkerIsolation(chatId, taskId, branch);
    return this.requirePrivilegedClient().request(
      'network.logresDevinProvision',
      { isolationName: identity.isolationName },
      { taskId, workerId: chatId, branch }
    );
  }

  async teardownWorkerNetwork(chatId: string, taskId: string, branch: string) {
    const identity = await this.resolveWorkerIsolation(
      chatId, taskId, branch, true
    );
    return this.requirePrivilegedClient().request(
      'network.logresDevinTeardown',
      { isolationName: identity.isolationName }
    );
  }

  async startWorkerTransient(
    chatId: string,
    taskId: string,
    branch: string,
    jobId: number,
    model: 'swe-2-max' | 'swe-2-high' | 'swe-2-medium',
    permissionMode: 'smart' | 'autonomous'
  ) {
    if (!Number.isInteger(jobId) || jobId < 1) throw new Error('invalid job id');
    const identity = await this.resolveWorkerIsolation(chatId, taskId, branch);
    return this.requirePrivilegedClient().request(
      'systemd.logresDevinStart',
      {
        taskId,
        workerId: chatId,
        branch,
        worktree: identity.worktree,
        jobId,
        model,
        permissionMode
      },
      { taskId, workerId: chatId, branch }
    );
  }

  async stopWorkerTransient(chatId: string, taskId: string, branch: string) {
    const identity = await this.resolveWorkerIsolation(chatId, taskId, branch, true);
    return this.requirePrivilegedClient().request(
      'systemd.logresDevinStop',
      { isolationName: identity.isolationName }
    );
  }

  async gitDiffStat(chatId: string, taskId: string, branch: string) {
    const identity = await this.resolveWorkerIsolation(chatId, taskId, branch);
    return this.checkedRead(`git -C ${quote(identity.worktree)} diff --stat`);
  }

  certifySha(ref: string) { return this.verify(ref); }

  async candidateCommit(chatId: string, taskId: string, branch: string) {
    assertId(chatId, 'chat id');
    assertId(taskId, 'task id');
    assertBranch(branch);
    if (this.privilegedClient) {
      const response = await this.governedPrivilegedRequest(chatId, taskId, branch, 'integration.logresCandidateCommit', { chatId, taskId, branch });
      if (!response.ok) throw new Error(response.error ?? 'privileged candidate commit failed');
      return response.result as { taskId: string; branch: string; sha: string; changedPaths: string[] };
    }

    const db = this.root + '/control/control.sqlite';
    const repo = this.root + '/src/awakened-realms';
    const ownerQuery =
      "select coalesce(chat_id,'') from brain_task_leases where task_id='" + taskId + "';";
    const scopeQuery =
      "select path_prefix from task_scopes where task_id='" + taskId +
      "' union select path_prefix from claims where task_id='" + taskId + "' order by 1;";

    const owner = (await this.checked(
      'sqlite3 -readonly ' + quote(db) + ' ' + quote(ownerQuery)
    )).stdout.trim();
    if (owner !== chatId) {
      throw new Error('task lease is not owned by ' + chatId);
    }

    const scopes = (await this.checked(
      'sqlite3 -readonly ' + quote(db) + ' ' + quote(scopeQuery)
    )).stdout.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
    if (scopes.length === 0) throw new Error('task has no declared or claimed scopes');

    const worktrees = (await this.checked(
      'git -C ' + quote(repo) + ' worktree list --porcelain'
    )).stdout.split(/\n\n+/);
    const target = worktrees.find((block) =>
      block.split(/\r?\n/).includes('branch refs/heads/' + branch)
    );
    const worktree = target
      ?.split(/\r?\n/)
      .find((line) => line.startsWith('worktree '))
      ?.slice('worktree '.length)
      .trim();
    if (!worktree) throw new Error('no worktree registered for branch');

    const commands = [
      'git -C ' + quote(worktree) + ' diff --name-only',
      'git -C ' + quote(worktree) + ' diff --cached --name-only',
      'git -C ' + quote(worktree) + ' ls-files --others --exclude-standard'
    ];
    const dirty = new Set<string>();
    for (const command of commands) {
      const output = (await this.checked(command)).stdout;
      for (const path of output.split(/\r?\n/).map((value) => value.trim()).filter(Boolean)) {
        dirty.add(path);
      }
    }
    if (dirty.size === 0) throw new Error('no candidate changes');

    const violations = [...dirty].filter(
      (path) => !scopes.some((prefix) => covered(path, prefix))
    );
    if (violations.length > 0) {
      throw new Error('candidate changes outside task scope: ' + violations.join(', '));
    }

    await this.checked('git -C ' + quote(worktree) + ' diff --check');
    await this.checked('git -C ' + quote(worktree) + ' diff --cached --check');
    await this.checked('git -C ' + quote(worktree) + ' add -A');

    const staged = (await this.checked(
      'git -C ' + quote(worktree) + ' diff --cached --name-only'
    )).stdout.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
    if (staged.length === 0) throw new Error('no staged candidate changes');
    const stagedViolations = staged.filter(
      (path) => !scopes.some((prefix) => covered(path, prefix))
    );
    if (stagedViolations.length > 0) {
      throw new Error('staged changes outside task scope: ' + stagedViolations.join(', '));
    }

    await this.checked(
      'git -C ' + quote(worktree) +
        " -c user.name='Nexus Typed Bridge' -c user.email='nexus-typed-bridge@local.invalid' commit -m " +
        quote('worker: ' + taskId + ' typed candidate')
    );
    const residual = (await this.checked(
      'git -C ' + quote(worktree) + ' status --porcelain'
    )).stdout.trim();
    if (residual) throw new Error('worktree changed during candidate commit');

    const sha = (await this.checked(
      'git -C ' + quote(worktree) + ' rev-parse HEAD'
    )).stdout.trim();
    return { taskId, branch, sha, changedPaths: staged };
  }

  finishTask(chatId: string, taskId: string, branch?: string) {
    assertId(chatId, 'chat id');
    assertId(taskId, 'task id');
    if (branch) assertBranch(branch);
    if (this.privilegedClient && branch) {
      return this.governedPrivilegedRequest(chatId, taskId, branch, 'integration.logresFinishTask', { chatId, taskId, branch });
    }
    const branchArg = branch ? ` ${branch}` : '';
    return this.exec(`${this.root}/bin/logres-finish-task ${chatId} ${taskId}${branchArg}`, 900_000, 2 * 1024 * 1024);
  }

  async projectHealth() {
    const [brief, swarm, preflight, integration, origin] = await Promise.all([
      this.brief(), this.swarmStatus(), Promise.resolve({ stdout: 'governed-preflight-status-requires-worker-context', stderr: '', exitCode: 0, signal: null, truncated: false, timedOut: false, durationMs: 0 }),
      this.readExec(`git -C ${quote(this.root + '/src/awakened-realms')} rev-parse feat/logres-reconstruction`),
      this.readExec(`git -C ${quote(this.root + '/src/awakened-realms')} rev-parse origin/feat/logres-reconstruction`)
    ]);
    return {
      integrationHead: integration.stdout.trim(),
      originIntegrationHead: origin.stdout.trim(),
      integrationClean: integration.stdout.trim() === origin.stdout.trim(),
      brain: brief.stdout.slice(0, 32 * 1024),
      swarm: swarm.stdout.slice(0, 32 * 1024),
      preflight: preflight.stdout.slice(0, 16 * 1024)
    };
  }

  swarmStatus() {
    return this.readExec(`${this.root}/bin/logres-swarm status`);
  }

  devinDispatch() {
    if (this.privilegedClient) return this.privilegedClient.request('integration.logresCoordinator', { action: 'devinDispatch' });
    return this.exec(`${this.root}/bin/logres-swarm tick`, 300_000, 1024 * 1024);
  }

  preflightStatus(chatId: string, taskId: string, branch: string) {
    return this.governedPrivilegedRequest(chatId, taskId, branch, 'integration.logresPreflight', { action: 'status' });
  }

  preflightRun(chatId: string, taskId: string, branch: string, max = 1) {
    if (!Number.isInteger(max) || max < 1 || max > 8) {
      throw new Error('invalid preflight max');
    }
    return this.governedPrivilegedRequest(chatId, taskId, branch, 'integration.logresPreflight', { action: 'run', max });
  }

  preflightApply(chatId: string, taskId: string, branch: string, id: number) {
    if (!Number.isInteger(id) || id < 1) throw new Error('invalid preflight id');
    return this.governedPrivilegedRequest(chatId, taskId, branch, 'integration.logresPreflight', { action: 'apply', id });
  }

  baton(
    state: string,
    options: {
      objective?: string;
      task?: string;
      note?: string;
      newGeneration?: boolean;
    } = {}
  ) {
    const normalized = state.trim().toUpperCase();
    if (!BATON_STATES.has(normalized)) throw new Error('invalid baton state');
    if (options.task) assertId(options.task, 'task id');
    if (this.privilegedClient) return this.privilegedClient.request('integration.logresCoordinator', { action: 'baton', state: normalized, ...options, newGeneration: options.newGeneration ?? false });
    const args = [
      `${this.root}/bin/logres-supervisor baton --state ${normalized}`,
      options.objective ? `--objective ${quote(options.objective)}` : '',
      options.task ? `--task ${options.task}` : '',
      options.note ? `--note ${quote(options.note)}` : '',
      options.newGeneration ? '--new-generation' : ''
    ].filter(Boolean).join(' ');
    return this.exec(args);
  }

  batonStatus() {
    return this.readExec(`${this.root}/bin/logres-supervisor baton-status`);
  }
}
