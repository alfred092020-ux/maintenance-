import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/server';
import { z } from 'zod';
import { LogresAdapter } from '../adapters/logres.js';
import { openDatabase } from '../brain/db.js';
import { BrainStore, type JobRecord } from '../brain/store.js';
import { loadConfig, type NexusConfig } from '../config.js';
import { LocalExecutor } from '../executor/localExecutor.js';
import { JobRunner } from '../jobs/jobRunner.js';
import { PrivilegedClient, type PrivilegedResponse } from '../privileged/client.js';
import { writePolicyProposal } from '../privileged/proposals.js';
import { SecretStore } from '../security/secretStore.js';
import { spawnDetachedJobWorker } from '../jobs/spawnWorker.js';
import { MACHINE_CAPABILITIES } from '../machines/types.js';
import { ExecutionRouter } from '../remote/router.js';
import { redactText, redactValue } from '../security/redact.js';
import { readTunnelHealth } from '../runtime/tunnelHealth.js';

const VERSION = '0.1.0';

function textResult(value: unknown) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(redactValue(value)) }]
  };
}

function publicJob(job: JobRecord) {
  const payload = { ...job.payload };
  if (typeof payload.command === 'string') {
    payload.command = redactText(payload.command);
  }
  return { ...job, payload };
}

function configuredPrivilegedClient(
  config: NexusConfig
): PrivilegedClient | undefined {
  const values = [
    config.privilegedSocketPath,
    config.privilegedSecretId,
    config.localMachineId
  ];
  const configured = values.filter(Boolean).length;
  if (configured === 0) return undefined;
  if (configured !== values.length) {
    throw new Error('incomplete privileged client configuration');
  }

  const secretValue = new SecretStore(config.secretStoreDir)
    .resolveSecret(config.privilegedSecretId!);
  if (!/^[a-f0-9]{64}$/i.test(secretValue)) {
    throw new Error('invalid privileged auth key material');
  }

  return new PrivilegedClient({
    socketPath: config.privilegedSocketPath!,
    key: Buffer.from(secretValue, 'hex'),
    machineId: config.localMachineId!
  });
}

function privilegedResult(response: PrivilegedResponse) {
  if (!response.ok) {
    return {
      isError: true,
      content: [{
        type: 'text' as const,
        text: JSON.stringify({ error: response.error ?? 'privileged operation failed' })
      }]
    };
  }
  return textResult(response.result ?? { ok: true });
}

function createJobDispatcher(
  config: NexusConfig,
  store: BrainStore,
  launchJobWorker: (config: NexusConfig, jobId: string) => number
) {
  return (jobId: string, actor: string): number => {
    try {
      const workerPid = launchJobWorker(config, jobId);
      store.appendAudit({
        action: 'job.dispatch',
        actor,
        target: jobId,
        detail: { workerPid }
      });
      return workerPid;
    } catch (error) {
      store.appendAudit({
        action: 'job.dispatch_failed',
        actor,
        target: jobId,
        detail: {
          message: error instanceof Error ? error.message : String(error)
        }
      });
      throw error;
    }
  };
}

export function reconcileGatewayStartup(
  config: NexusConfig,
  store: BrainStore,
  runner: JobRunner,
  launchJobWorker: (config: NexusConfig, jobId: string) => number =
    spawnDetachedJobWorker
): void {
  const dispatchJob = createJobDispatcher(
    config,
    store,
    launchJobWorker
  );
  runner.reconcileOnStartup();
  for (const job of store.listLocalJobsByStatus('QUEUED')) {
    try {
      dispatchJob(job.id, 'mcp-startup');
    } catch {
      // Keep the job QUEUED so a later gateway startup can retry dispatch.
    }
  }
}

export interface BuildServerOptions {
  config?: NexusConfig;
  store?: BrainStore;
  executor?: LocalExecutor;
  logres?: LogresAdapter;
  runner?: JobRunner;
  launchJobWorker?: (config: NexusConfig, jobId: string) => number;
  privilegedClient?: Pick<PrivilegedClient, 'request' | 'maintenanceRequest'> | null;
  performStartupRecovery?: boolean;
}

export function buildServer(options: BuildServerOptions = {}): McpServer {
  const config = options.config ?? loadConfig();
  const store = options.store ?? new BrainStore(openDatabase(config.dbPath));
  const executor = options.executor ?? new LocalExecutor(store, 'mcp');
  const privilegedClient =
    options.privilegedClient === null
      ? undefined
      : options.privilegedClient ?? configuredPrivilegedClient(config);
  const logres =
    options.logres ?? new LogresAdapter(executor, config.logresRoot, privilegedClient);
  const runner =
    options.runner ??
    new JobRunner(store, executor, {
      timeoutMs: config.commandTimeoutMs,
      maxOutputBytes: config.maxOutputBytes
    });
  const launchJobWorker = options.launchJobWorker ?? spawnDetachedJobWorker;
  const executionRouter = new ExecutionRouter(store);
  const dispatchJob = createJobDispatcher(
    config,
    store,
    launchJobWorker
  );

  if (options.performStartupRecovery ?? true) {
    reconcileGatewayStartup(
      config,
      store,
      runner,
      launchJobWorker
    );
  }

  const server = new McpServer({
    name: 'nexus-commander',
    version: VERSION
  });

  const absolutePath = z.string().min(1).refine((value) => path.isAbsolute(value), {
    message: 'path must be absolute'
  });
  const serviceName = z.string().min(1).max(256).regex(/^[A-Za-z0-9@_.:-]+$/);
  const packageName = z.string().min(1).max(256).regex(/^[A-Za-z0-9.+:-]+$/);
  const authToolMeta = config.mcpPublicUrl
    ? {
        securitySchemes: [
          { type: 'oauth2', scopes: [config.oauthScope] }
        ]
      }
    : {};

  server.registerTool(
    'nexus_tunnel_health',
    {
      description: 'Read the supervised OpenAI Secure MCP Tunnel health without exposing credentials.',
      _meta: authToolMeta,
      inputSchema: z.object({})
    },
    async () => textResult(await readTunnelHealth())
  );

  server.registerTool(
    'nexus_status',
    {
      description: 'Read the local Nexus Commander control-plane status.',
      _meta: authToolMeta,
      inputSchema: z.object({})
    },
    async () =>
      textResult({
        database: config.dbPath,
        jobs: {
          queued: store.countJobsByStatus('QUEUED'),
          running: store.countJobsByStatus('RUNNING')
        },
        logres: config.logresRoot,
        version: VERSION
      })
  );

  server.registerTool(
    'nexus_machine_list',
    {
      description: 'List machines enrolled in Nexus Commander.',
      _meta: authToolMeta,
      inputSchema: z.object({})
    },
    async () => textResult(store.listMachines())
  );

  server.registerTool(
    'nexus_machine_health',
    {
      description: 'Read one enrolled machine health and capability record.',
      _meta: authToolMeta,
      inputSchema: z.object({
        id: z.string().min(1).max(128).regex(/^[A-Za-z0-9._-]+$/)
      })
    },
    async ({ id }) => {
      const machine = store.getMachine(id);
      if (!machine) {
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: JSON.stringify({ error: 'machine not found', id })
          }]
        };
      }
      return textResult(machine);
    }
  );

  server.registerTool(
    'nexus_machine_route',
    {
      description: 'Select a healthy enrolled machine deterministically for a required capability.',
      _meta: authToolMeta,
      inputSchema: z.object({
        requiredCapability: z.enum(MACHINE_CAPABILITIES),
        preferredMachineId: z.string().min(1).max(128).regex(/^[A-Za-z0-9._-]+$/).optional()
      })
    },
    async ({ requiredCapability, preferredMachineId }) => {
      const machine = executionRouter.select(
        requiredCapability,
        preferredMachineId
      );
      if (!machine) {
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: JSON.stringify({ error: 'no healthy capable machine' })
          }]
        };
      }
      return textResult(machine);
    }
  );

  server.registerTool(
    'nexus_remote_exec',
    {
      description: 'Queue an unprivileged command for execution on a healthy enrolled remote machine.',
      _meta: authToolMeta,
      inputSchema: z.object({
        command: z.string().min(1).max(64 * 1024),
        timeoutMs: z.number().int().positive().max(900_000).optional(),
        maxOutputBytes: z.number().int().positive().max(16 * 1024 * 1024).optional(),
        preferredMachineId: z.string().min(1).max(128).regex(/^[A-Za-z0-9._-]+$/).optional(),
        priority: z.number().int().min(0).max(1_000_000).optional(),
        reassignable: z.boolean().optional()
      })
    },
    async ({
      command,
      timeoutMs,
      maxOutputBytes,
      preferredMachineId,
      priority,
      reassignable
    }) => {
      const machine = executionRouter.select(
        'AUTONOMOUS_EXEC',
        preferredMachineId
      );
      if (!machine) {
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: JSON.stringify({ error: 'no healthy capable machine' })
          }]
        };
      }

      const id = store.createRemoteJob({
        kind: 'remote.exec',
        payload: {
          command,
          ...(timeoutMs === undefined ? {} : { timeoutMs }),
          ...(maxOutputBytes === undefined ? {} : { maxOutputBytes })
        },
        targetMachineId: machine.id,
        requiredCapability: 'AUTONOMOUS_EXEC',
        ...(priority === undefined ? {} : { priority }),
        ...(reassignable === undefined ? {} : { reassignable })
      }, 'mcp');

      return textResult({
        id,
        targetMachineId: machine.id,
        status: 'QUEUED'
      });
    }
  );

  server.registerTool(
    'nexus_remote_job_status',
    {
      description: 'Read one durable remote job by ID.',
      _meta: authToolMeta,
      inputSchema: z.object({
        id: z.string().uuid()
      })
    },
    async ({ id }) => {
      const job = store.getJob(id);
      if (!job || job.executionScope !== 'remote') {
        return {
          isError: true,
          content: [{
            type: 'text' as const,
            text: JSON.stringify({ error: 'remote job not found', id })
          }]
        };
      }
      return textResult(publicJob(job));
    }
  );

  server.registerTool(
    'nexus_remote_requeue_expired',
    {
      description: 'Reconcile expired remote leases, requeueing only reassignable work.',
      _meta: authToolMeta,
      inputSchema: z.object({})
    },
    async () => textResult(store.requeueExpiredRemoteJobs(Date.now()))
  );

  server.registerTool(
    'nexus_event_sync',
    {
      description: 'Read an ordered bounded event delta after an event ID.',
      _meta: authToolMeta,
      inputSchema: z.object({
        afterEventId: z.number().int().min(0).default(0),
        limit: z.number().int().min(1).max(100).default(50)
      })
    },
    async ({ afterEventId, limit }) => {
      const events = store.listEventsAfter(afterEventId, limit);
      return textResult({
        events,
        nextAfterEventId:
          events.length === 0
            ? afterEventId
            : events[events.length - 1]!.id
      });
    }
  );

  server.registerTool(
    'nexus_exec',
    {
      description: 'Execute a bounded command on the enrolled local development machine.',
      _meta: authToolMeta,
      inputSchema: z.object({
        command: z.string().min(1),
        timeoutMs: z.number().int().positive().max(900_000).optional()
      })
    },
    async ({ command, timeoutMs }) =>
      textResult(
        await executor.exec({
          command,
          timeoutMs: timeoutMs ?? config.commandTimeoutMs,
          maxOutputBytes: config.maxOutputBytes
        })
      )
  );

  server.registerTool(
    'nexus_read_file',
    {
      description: 'Read a bounded UTF-8 file from an absolute path.',
      _meta: authToolMeta,
      inputSchema: z.object({
        path: absolutePath,
        maxBytes: z.number().int().positive().max(config.maxOutputBytes).optional()
      })
    },
    async ({ path: filePath, maxBytes }) => {
      const result = await executor.readFile(filePath, maxBytes ?? config.maxOutputBytes);
      return textResult({ ...result, content: redactText(result.content) });
    }
  );

  server.registerTool(
    'nexus_write_file',
    {
      description: 'Atomically write a UTF-8 file at an absolute path.',
      _meta: authToolMeta,
      inputSchema: z.object({
        path: absolutePath,
        content: z.string().refine(
          (value) => Buffer.byteLength(value, 'utf8') <= config.maxOutputBytes,
          { message: 'content exceeds maximum write size' }
        )
      })
    },
    async ({ path: filePath, content }) => {
      await executor.writeFile(filePath, content);
      return textResult({ ok: true, path: filePath, bytes: Buffer.byteLength(content, 'utf8') });
    }
  );

  server.registerTool(
    'nexus_job_create',
    {
      description: 'Create a durable queued local exec job.',
      _meta: authToolMeta,
      inputSchema: z.object({
        command: z.string().min(1)
      })
    },
    async ({ command }) => {
      const id = store.createJob({ kind: 'exec', payload: { command } }, 'mcp');
      const workerPid = dispatchJob(id, 'mcp');
      return textResult({ id, status: 'QUEUED', workerPid });
    }
  );

  server.registerTool(
    'nexus_job_status',
    {
      description: 'Read one durable job by ID.',
      _meta: authToolMeta,
      inputSchema: z.object({
        id: z.string().uuid()
      })
    },
    async ({ id }) => {
      const job = store.getJob(id);
      if (!job) {
        return {
          isError: true,
          content: [{ type: 'text' as const, text: JSON.stringify({ error: 'job not found', id }) }]
        };
      }
      return textResult(publicJob(job));
    }
  );



  const logresWorkerContextSchema = {
    chatId: z.string().min(1).max(128),
    taskId: z.string().min(1).max(160),
    branch: z.string().min(1).max(256).regex(/^worker\/[A-Za-z0-9._\/-]+$/)
  };

  if (privilegedClient) {
    server.registerTool(
      'nexus_privileged_policy_propose',
      {
        description: 'Write a non-authoritative privileged capability proposal for operator review.',
        _meta: authToolMeta,
        inputSchema: z.object({
          requestedCapabilityId: z.string().min(1).max(160).regex(/^[A-Za-z0-9._:-]+$/),
          rationale: z.string().min(1).max(4000),
          scope: z.string().min(1).max(4000),
          rollbackNote: z.string().min(1).max(4000),
          requester: z.string().min(1).max(160).regex(/^[A-Za-z0-9._:-]+$/),
          evidenceRefs: z.array(z.string().min(1).max(512)).max(64).default([])
        }).strict()
      },
      async ({ requestedCapabilityId, rationale, scope, rollbackNote, requester, evidenceRefs }) =>
        textResult(await writePolicyProposal(config.privilegedProposalDir, {
          requestedCapabilityId, rationale, scope, rollbackNote, requester,
          createdAt: Date.now(), evidenceRefs
        }))
    );
    server.registerTool(
      'nexus_service_status',
      {
        description: 'Read status for a host service through the privileged executor.',
      _meta: authToolMeta,
        inputSchema: z.object({ name: serviceName })
      },
      async ({ name }) =>
        privilegedResult(
          await privilegedClient.request('service.status', { name })
        )
    );

    server.registerTool(
      'nexus_service_restart',
      {
        description: 'Restart a host service through the privileged executor.',
      _meta: authToolMeta,
        inputSchema: z.object({ name: serviceName })
      },
      async ({ name }) =>
        privilegedResult(
          await privilegedClient.request('service.restart', { name })
        )
    );

    server.registerTool(
      'nexus_package_install',
      {
        description: 'Install operating-system packages through the privileged executor.',
      _meta: authToolMeta,
        inputSchema: z.object({
          packages: z.array(packageName).min(1).max(64)
        })
      },
      async ({ packages }) =>
        privilegedResult(
          await privilegedClient.request('package.install', { packages })
        )
    );

    server.registerTool(
      'nexus_host_exec_argv',
      {
        description: 'Execute an absolute program with argv through the privileged executor.',
      _meta: authToolMeta,
        inputSchema: z.object({
          executable: absolutePath,
          argv: z.array(z.string().max(4096)).max(64).default([]),
          timeoutMs: z.number().int().positive().max(900_000).optional()
        })
      },
      async ({ executable, argv, timeoutMs }) =>
        privilegedResult(
          await privilegedClient.request('process.execArgv', {
            executable,
            argv,
            ...(timeoutMs === undefined ? {} : { timeoutMs })
          })
        )
    );

    server.registerTool(
      'nexus_logres_devin_network_provision',
      {
        description: 'Provision the certified per-worker Logres Devin netns+nftables boundary after live lease/worktree validation.',
        _meta: authToolMeta,
        inputSchema: z.object({
          chatId: z.string().min(1).max(128),
          taskId: z.string().min(1).max(160),
          branch: z.string().min(1).max(256)
        })
      },
      async ({ chatId, taskId, branch }) =>
        privilegedResult(
          await logres.provisionWorkerNetwork(chatId, taskId, branch)
        )
    );

    server.registerTool(
      'nexus_logres_devin_network_teardown',
      {
        description: 'Tear down the certified per-worker Logres Devin network boundary after live lease/worktree validation.',
        _meta: authToolMeta,
        inputSchema: z.object({
          chatId: z.string().min(1).max(128),
          taskId: z.string().min(1).max(160),
          branch: z.string().min(1).max(256)
        })
      },
      async ({ chatId, taskId, branch }) =>
        privilegedResult(
          await logres.teardownWorkerNetwork(chatId, taskId, branch)
        )
    );

    server.registerTool(
      'nexus_logres_devin_transient_start',
      {
        description: 'Launch one governed unattended Devin worker in the certified transient systemd boundary after live lease/worktree validation.',
        _meta: authToolMeta,
        inputSchema: z.object({
          chatId: z.string().min(1).max(128),
          taskId: z.string().min(1).max(160),
          branch: z.string().min(1).max(256),
          jobId: z.number().int().positive(),
          model: z.enum(['swe-2-max', 'swe-2-high', 'swe-2-medium']),
          permissionMode: z.enum(['smart', 'autonomous'])
        })
      },
      async ({ chatId, taskId, branch, jobId, model, permissionMode }) =>
        privilegedResult(
          await logres.startWorkerTransient(
            chatId, taskId, branch, jobId, model, permissionMode
          )
        )
    );

    server.registerTool(
      'nexus_logres_devin_transient_stop',
      {
        description: 'Stop one governed Logres Devin transient unit after live or latest matching historical lease validation.',
        _meta: authToolMeta,
        inputSchema: z.object({
          chatId: z.string().min(1).max(128),
          taskId: z.string().min(1).max(160),
          branch: z.string().min(1).max(256)
        })
      },
      async ({ chatId, taskId, branch }) =>
        privilegedResult(
          await logres.stopWorkerTransient(chatId, taskId, branch)
        )
    );

    const governedContextSchema = {
      chatId: z.string().min(1).max(128),
      taskId: z.string().min(1).max(160),
      branch: z.string().min(1).max(256).regex(/^worker\/[A-Za-z0-9._\/-]+$/)
    };

    server.registerTool(
      'nexus_logres_service_manage',
      {
        description: 'Manage one Logres/Nexus-owned service under a live Logres task lease.',
        _meta: authToolMeta,
        inputSchema: z.object({ ...governedContextSchema, name: z.string().regex(/^(?:logres|nexus)-[A-Za-z0-9@_.:-]+\.service$/), action: z.enum(['status','start','stop','restart']) }).strict()
      },
      async ({ chatId, taskId, branch, name, action }) =>
        privilegedResult(await logres.manageHostService(chatId, taskId, branch, name, action))
    );

    server.registerTool(
      'nexus_logres_security_profile_reload',
      {
        description: 'Reload one Logres AppArmor profile under a live Logres task lease.',
        _meta: authToolMeta,
        inputSchema: z.object({ ...governedContextSchema, profile: z.string().regex(/^logres-[A-Za-z0-9._-]+$/) }).strict()
      },
      async ({ chatId, taskId, branch, profile }) =>
        privilegedResult(await logres.reloadSecurityProfile(chatId, taskId, branch, profile))
    );

    server.registerTool(
      'nexus_logres_systemd_daemon_reload',
      {
        description: 'Reload systemd configuration under a live Logres task lease.',
        _meta: authToolMeta,
        inputSchema: z.object(governedContextSchema).strict()
      },
      async ({ chatId, taskId, branch }) =>
        privilegedResult(await logres.reloadSystemd(chatId, taskId, branch))
    );

    server.registerTool(
      'nexus_logres_sysctl_set',
      {
        description: 'Set an approved Logres host sysctl under a live task lease.',
        _meta: authToolMeta,
        inputSchema: z.object({ ...governedContextSchema, key: z.literal('net.ipv4.ip_forward'), value: z.union([z.literal(0), z.literal(1)]) }).strict()
      },
      async ({ chatId, taskId, branch, key, value }) =>
        privilegedResult(await logres.setHostSysctl(chatId, taskId, branch, key, value))
    );

    server.registerTool(
      'nexus_logres_install_verified',
      {
        description: 'Install a digest-verified staged Logres/Nexus artifact under a live task lease.',
        _meta: authToolMeta,
        inputSchema: z.object({ ...governedContextSchema, sourcePath: absolutePath, destinationPath: absolutePath, sha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict()
      },
      async ({ chatId, taskId, branch, sourcePath, destinationPath, sha256 }) =>
        privilegedResult(await logres.installVerifiedHostArtifact(chatId, taskId, branch, sourcePath, destinationPath, sha256))
    );

    server.registerTool(
      'nexus_logres_runtime_promote',
      {
        description: 'Promote the exact current canonical Logres integration SHA into the protected runtime under a live task lease.',
        _meta: authToolMeta,
        inputSchema: z.object({
          ...governedContextSchema,
          sha: z.string().regex(/^[a-f0-9]{40}$/)
        }).strict()
      },
      async ({ chatId, taskId, branch, sha }) =>
        privilegedResult(await logres.promoteLogresRuntime(chatId, taskId, branch, sha))
    );

    server.registerTool(
      'nexus_runtime_promote_verified',
      {
        description: 'Promote a digest-verified staged Nexus runtime under a live Logres task lease with automatic rollback health checks.',
        _meta: authToolMeta,
        inputSchema: z.object({
          ...governedContextSchema,
          sourcePath: z.string().regex(/^\/home\/ubuntu\/logres\/staging\/nexus-runtime-[A-Za-z0-9._:-]+\/runtime\.tar\.gz$/),
          sha256: z.string().regex(/^[a-f0-9]{64}$/)
        }).strict()
      },
      async ({ chatId, taskId, branch, sourcePath, sha256 }) =>
        privilegedResult(await logres.promoteVerifiedNexusRuntime(chatId, taskId, branch, sourcePath, sha256))
    );

    const maintenanceContextSchema = {
      transactionId: z.string().min(1).max(160).regex(/^[A-Za-z0-9._:-]+$/),
      reason: z.string().min(1).max(4096)
    };

    server.registerTool(
      'nexus_maintenance_service_manage',
      { description: 'Manage an approved Nexus service under a signed maintenance transaction.', _meta: authToolMeta, inputSchema: z.object({ ...maintenanceContextSchema, name: z.string().regex(/^nexus-(?:tunnel@ubuntu|privileged-executor|agent|control-plane@ubuntu)\.service$/), action: z.enum(['status','start','stop','restart']) }).strict() },
      async ({ transactionId, reason, name, action }) => privilegedResult(await logres.maintenanceManageNexusService(transactionId, reason, name, action))
    );
    server.registerTool(
      'nexus_maintenance_install_verified',
      { description: 'Install a digest-verified Nexus maintenance artifact without product lease semantics.', _meta: authToolMeta, inputSchema: z.object({ ...maintenanceContextSchema, sourcePath: z.string().regex(/^\/var\/tmp\/nexus-maintenance\/staging\/nexus-[A-Za-z0-9@_.:-]+$/), destinationPath: absolutePath, sha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict() },
      async ({ transactionId, reason, sourcePath, destinationPath, sha256 }) => privilegedResult(await logres.maintenanceInstallVerified(transactionId, reason, sourcePath, destinationPath, sha256))
    );
    server.registerTool(
      'nexus_maintenance_runtime_promote_verified',
      { description: 'Promote a digest-verified Nexus runtime under a signed maintenance transaction without a product lease.', _meta: authToolMeta, inputSchema: z.object({ ...maintenanceContextSchema, sourcePath: z.string().regex(/^\/var\/tmp\/nexus-maintenance\/staging\/nexus-runtime-[A-Za-z0-9._:-]+\/runtime\.tar\.gz$/), sha256: z.string().regex(/^[a-f0-9]{64}$/) }).strict() },
      async ({ transactionId, reason, sourcePath, sha256 }) => privilegedResult(await logres.maintenancePromoteVerified(transactionId, reason, sourcePath, sha256))
    );

  }

  server.registerTool('nexus_logres_brain_task_create', { description: 'Create a canonical Brain task.', _meta: authToolMeta, inputSchema: z.object({ taskId: z.string().min(1).max(160), priority: z.number().int().min(0).max(1000), workType: z.string().min(1).max(128), title: z.string().min(1).max(4096) }) }, async ({ taskId, priority, workType, title }) => textResult(await logres.brainCreateTask(taskId, priority, workType, title)));
  server.registerTool('nexus_logres_brain_lease', { description: 'Acquire or renew a canonical Brain task lease.', _meta: authToolMeta, inputSchema: z.object({ chatId: z.string().min(1).max(128), taskId: z.string().min(1).max(160), minutes: z.number().int().min(1).max(1440).default(60), branch: z.string().min(1).max(256) }) }, async ({ chatId, taskId, minutes, branch }) => textResult(await logres.brainLease(chatId, taskId, minutes, branch)));
  server.registerTool('nexus_logres_brain_progress', { description: 'Record canonical Brain task progress.', _meta: authToolMeta, inputSchema: z.object({ chatId: z.string().min(1).max(128), taskId: z.string().min(1).max(160), percent: z.number().int().min(0).max(100), note: z.string().max(4096).default('') }) }, async ({ chatId, taskId, percent, note }) => textResult(await logres.brainProgress(chatId, taskId, percent, note)));
  server.registerTool('nexus_logres_brain_evidence', { description: 'Record canonical Brain evidence.', _meta: authToolMeta, inputSchema: z.object({ chatId: z.string().min(1).max(128), confidence: z.enum(['HIGH','MEDIUM','LOW']), subject: z.string().min(1).max(4096), summary: z.string().min(1).max(8192), taskId: z.string().min(1).max(160).optional() }) }, async ({ chatId, confidence, subject, summary, taskId }) => textResult(await logres.brainEvidence(chatId, confidence, subject, summary, taskId)));
  server.registerTool('nexus_logres_brain_block', { description: 'Release a canonical Brain task as dependency-blocked.', _meta: authToolMeta, inputSchema: z.object({ chatId: z.string().min(1).max(128), taskId: z.string().min(1).max(160), note: z.string().min(1).max(4096) }) }, async ({ chatId, taskId, note }) => textResult(await logres.brainBlock(chatId, taskId, note)));
  server.registerTool('nexus_logres_project_health', { description: 'Read consolidated bounded Logres Brain, Git, worker, preflight, and tunnel health.', _meta: authToolMeta, inputSchema: z.object({}) }, async () => textResult({ ...(await logres.projectHealth()), tunnel: await readTunnelHealth() }));

  server.registerTool(
    'nexus_logres_vm_exec',
    {
      description: 'Run an approved argv-style command inside the live leased Logres worker worktree. Inline shell/code execution is rejected.',
      _meta: authToolMeta,
      inputSchema: z.object({
        ...logresWorkerContextSchema,
        executable: z.enum(['git', 'npm', 'node', 'python3', 'bash', 'adb']),
        argv: z.array(z.string().max(4096)).max(128).default([]),
        cwd: z.string().min(1).max(4096).default('.'),
        timeoutMs: z.number().int().positive().max(900_000).optional()
      }).strict()
    },
    async ({ chatId, taskId, branch, executable, argv, cwd, timeoutMs }) =>
      textResult(await logres.vmExec(
        chatId, taskId, branch, executable, argv, cwd, timeoutMs
      ))
  );

  server.registerTool(
    'nexus_logres_vm_read_file',
    {
      description: 'Read a bounded file only from the live leased worktree or approved Logres control/log/artifact roots.',
      _meta: authToolMeta,
      inputSchema: z.object({
        ...logresWorkerContextSchema,
        path: absolutePath,
        maxBytes: z.number().int().positive().max(4 * 1024 * 1024).optional()
      }).strict()
    },
    async ({ chatId, taskId, branch, path: filePath, maxBytes }) =>
      textResult(await logres.vmReadFile(chatId, taskId, branch, filePath, maxBytes))
  );

  server.registerTool(
    'nexus_logres_git_state',
    {
      description: 'Read canonical integration HEAD plus the live leased worker branch, worktree, HEAD, and status.',
      _meta: authToolMeta,
      inputSchema: z.object(logresWorkerContextSchema).strict()
    },
    async ({ chatId, taskId, branch }) =>
      textResult(await logres.gitState(chatId, taskId, branch))
  );

  server.registerTool(
    'nexus_logres_process_list',
    {
      description: 'Inspect a bounded credential-safe process list after validating the live Logres task lease.',
      _meta: authToolMeta,
      inputSchema: z.object(logresWorkerContextSchema).strict()
    },
    async ({ chatId, taskId, branch }) =>
      textResult(await logres.processList(chatId, taskId, branch))
  );

  server.registerTool(
    'nexus_logres_brief',
    {
      description: 'Read the canonical Logres lead brief.',
      _meta: authToolMeta,
      inputSchema: z.object({})
    },
    async () => textResult(await logres.brief())
  );

  server.registerTool(
    'nexus_logres_next',
    {
      description: 'Read the canonical Logres critical-path READY tasks.',
      _meta: authToolMeta,
      inputSchema: z.object({})
    },
    async () => textResult(await logres.next())
  );

  server.registerTool(
    'nexus_logres_queue',
    {
      description: 'Read the canonical Logres integration queue.',
      _meta: authToolMeta,
      inputSchema: z.object({})
    },
    async () => textResult(await logres.queue())
  );

  server.registerTool('nexus_logres_git_diff_stat', { description: 'Read bounded diff statistics for a lease-bound worker worktree.', _meta: authToolMeta, inputSchema: z.object({ chatId: z.string().min(1).max(128), taskId: z.string().min(1).max(160), branch: z.string().min(1).max(256) }) }, async ({ chatId, taskId, branch }) => textResult(await logres.gitDiffStat(chatId, taskId, branch)));
  server.registerTool('nexus_logres_certify_sha', { description: 'Run the canonical verification contract for an exact approved git SHA.', _meta: authToolMeta, inputSchema: z.object({ sha: z.string().regex(/^[a-f0-9]{7,64}$/) }) }, async ({ sha }) => textResult(await logres.certifySha(sha)));

  server.registerTool(
    'nexus_logres_verify',
    {
      description: 'Run clean Logres verification for an approved git ref.',
      _meta: authToolMeta,
      inputSchema: z.object({
        ref: z.string().min(1)
      })
    },
    async ({ ref }) => textResult(await logres.verify(ref))
  );


  server.registerTool(
    'nexus_logres_task_status',
    {
      description: 'Read recent canonical Brain history for one Logres task.',
      _meta: authToolMeta,
      inputSchema: z.object({ taskId: z.string().min(1).max(160) })
    },
    async ({ taskId }) => textResult(await logres.taskStatus(taskId))
  );

  server.registerTool('nexus_logres_continue_mission', { description: 'Re-read live Brain READY work and advance the highest-priority safe eligible task through canonical AUTO worker bootstrap.', _meta: authToolMeta, inputSchema: z.object({ chatId: z.string().min(1).max(128) }) }, async ({ chatId }) => textResult(await logres.continueMission(chatId)));
  server.registerTool('nexus_logres_start_task', { description: 'Start one explicit governed Logres task through canonical worker bootstrap.', _meta: authToolMeta, inputSchema: z.object({ chatId: z.string().min(1).max(128), taskId: z.string().min(1).max(160), branch: z.string().min(1).max(256).optional() }) }, async ({ chatId, taskId, branch }) => textResult(await logres.workerStart(chatId, taskId, branch)));

  server.registerTool(
    'nexus_logres_worker_start',
    {
      description: 'Start or resume one governed Logres worker through the canonical worker bootstrap.',
      _meta: authToolMeta,
      inputSchema: z.object({
        chatId: z.string().min(1).max(128),
        taskId: z.string().min(1).max(160),
        branch: z.string().min(1).max(256).optional()
      })
    },
    async ({ chatId, taskId, branch }) =>
      textResult(await logres.workerStart(chatId, taskId, branch))
  );

  server.registerTool(
    'nexus_logres_worker_release',
    {
      description: 'Release one governed Logres worker lease back to READY.',
      _meta: authToolMeta,
      inputSchema: z.object({
        chatId: z.string().min(1).max(128),
        taskId: z.string().min(1).max(160),
        note: z.string().max(2048).optional()
      })
    },
    async ({ chatId, taskId, note }) =>
      textResult(await logres.workerRelease(chatId, taskId, note))
  );

  server.registerTool(
    'nexus_logres_candidate_commit',
    {
      description: 'Commit one dirty Logres worker candidate only after live lease and path-scope validation.',
      _meta: authToolMeta,
      inputSchema: z.object({
        chatId: z.string().min(1).max(128),
        taskId: z.string().min(1).max(160),
        branch: z.string().min(1).max(256)
      })
    },
    async ({ chatId, taskId, branch }) =>
      textResult(await logres.candidateCommit(chatId, taskId, branch))
  );

  server.registerTool(
    'nexus_logres_finish_task',
    {
      description: 'Run canonical scoped worker handoff and queue a verified candidate for shared preflight.',
      _meta: authToolMeta,
      inputSchema: z.object({
        chatId: z.string().min(1).max(128),
        taskId: z.string().min(1).max(160),
        branch: z.string().min(1).max(256).optional()
      })
    },
    async ({ chatId, taskId, branch }) =>
      textResult(await logres.finishTask(chatId, taskId, branch))
  );

  server.registerTool(
    'nexus_logres_swarm_status',
    {
      description: 'Read governed Logres swarm status.',
      _meta: authToolMeta,
      inputSchema: z.object({})
    },
    async () => textResult(await logres.swarmStatus())
  );

  server.registerTool('nexus_logres_device_status', { description: 'Read Samsung QA transport and ADB readiness through the canonical phone QA bridge.', _meta: authToolMeta, inputSchema: z.object({}) }, async () => textResult(await logres.deviceQaStatus()));
  server.registerTool('nexus_logres_device_screenshot', { description: 'Capture Samsung proof screenshot into the approved Logres artifacts root.', _meta: authToolMeta, inputSchema: z.object({ outputPath: absolutePath }) }, async ({ outputPath }) => textResult(await logres.deviceScreenshot(outputPath)));
  server.registerTool('nexus_logres_device_logcat', { description: 'Capture bounded Samsung logcat into the approved Logres artifacts root.', _meta: authToolMeta, inputSchema: z.object({ outputPath: absolutePath }) }, async ({ outputPath }) => textResult(await logres.deviceLogcat(outputPath)));
  server.registerTool('nexus_logres_device_certify', { description: 'Run canonical Samsung hardware QA for an exact 40-character candidate SHA.', _meta: authToolMeta, inputSchema: z.object({ sha: z.string().regex(/^[a-f0-9]{40}$/) }) }, async ({ sha }) => textResult(await logres.deviceCertify(sha)));

  server.registerTool(
    'nexus_logres_devin_dispatch',
    {
      description: 'Run one governed swarm tick that may dispatch safe Devin work under current gates.',
      _meta: authToolMeta,
      inputSchema: z.object({})
    },
    async () => textResult(await logres.devinDispatch())
  );

  server.registerTool(
    'nexus_logres_preflight_status',
    {
      description: 'Read canonical merge-preflight status.',
      _meta: authToolMeta,
      inputSchema: z.object(logresWorkerContextSchema).strict()
    },
    async ({ chatId, taskId, branch }) => textResult(await logres.preflightStatus(chatId, taskId, branch))
  );

  server.registerTool(
    'nexus_logres_preflight_run',
    {
      description: 'Run bounded canonical merge preflight for queued candidates.',
      _meta: authToolMeta,
      inputSchema: z.object({ ...logresWorkerContextSchema, max: z.number().int().min(1).max(8).default(1) }).strict()
    },
    async ({ chatId, taskId, branch, max }) => textResult(await logres.preflightRun(chatId, taskId, branch, max))
  );

  server.registerTool(
    'nexus_logres_preflight_apply',
    {
      description: 'Apply one already-verified canonical preflight through the guarded merge train.',
      _meta: authToolMeta,
      inputSchema: z.object({ ...logresWorkerContextSchema, id: z.number().int().positive() }).strict()
    },
    async ({ chatId, taskId, branch, id }) => textResult(await logres.preflightApply(chatId, taskId, branch, id))
  );

  server.registerTool(
    'nexus_logres_baton',
    {
      description: 'Write a typed ChatGPT coordinator Baton heartbeat or state transition.',
      _meta: authToolMeta,
      inputSchema: z.object({
        state: z.enum(['RUNNING', 'CONTINUE_REQUESTED', 'PAUSED', 'WAITING_USER', 'DONE']),
        objective: z.string().max(4096).optional(),
        task: z.string().min(1).max(160).optional(),
        note: z.string().max(4096).optional(),
        newGeneration: z.boolean().default(false)
      })
    },
    async ({ state, objective, task, note, newGeneration }) =>
      textResult(await logres.baton(state, { objective, task, note, newGeneration }))
  );

  server.registerTool(
    'nexus_logres_baton_status',
    {
      description: 'Read coordinator Baton and deterministic Devin failover status.',
      _meta: authToolMeta,
      inputSchema: z.object({})
    },
    async () => textResult(await logres.batonStatus())
  );

  return server;
}
