import path from 'node:path';

export interface NexusConfig {
  stateDir: string;
  dbPath: string;
  logDir: string;
  commandTimeoutMs: number;
  maxOutputBytes: number;
  logresRoot: string;
  secretStoreDir: string;
  privilegedSocketPath: string | null;
  privilegedSecretId: string | null;
  privilegedPolicyPath: string | null;
  privilegedProposalDir: string;
  localMachineId: string | null;
  agentCaPath: string | null;
  agentCertPath: string | null;
  agentKeyPath: string | null;
  privilegedExecAllowlist: string[];
  artifactDir: string;
  controlListenHost: string;
  controlListenPort: number;
  controlCaPath: string | null;
  controlCertPath: string | null;
  controlKeyPath: string | null;
  controlMaxBodyBytes: number;
  controlMaxArtifactBytes: number;
  mcpListenHost: string;
  mcpListenPort: number;
  mcpPublicUrl: string | null;
  mcpTlsCertPath: string | null;
  mcpTlsKeyPath: string | null;
  mcpClientCaPath: string | null;
  oauthIssuer: string | null;
  oauthJwksUri: string | null;
  oauthAudience: string | null;
  oauthScope: string;
  mcpAllowedOrigins: string[];
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): NexusConfig {
  const home = env.HOME ?? '/home/ubuntu';
  const stateDir = env.NEXUS_STATE_DIR ?? path.join(home, '.local/state/nexus-commander');
  return {
    stateDir,
    dbPath: env.NEXUS_DB_PATH ?? path.join(stateDir, 'nexus.sqlite'),
    logDir: env.NEXUS_LOG_DIR ?? path.join(stateDir, 'logs'),
    commandTimeoutMs: Number(env.NEXUS_COMMAND_TIMEOUT_MS ?? 120_000),
    maxOutputBytes: Number(env.NEXUS_MAX_OUTPUT_BYTES ?? 1_048_576),
    logresRoot: env.NEXUS_LOGRES_ROOT ?? '/home/ubuntu/logres',
    secretStoreDir: env.NEXUS_SECRET_STORE_DIR ?? path.join(stateDir, 'secrets'),
    privilegedSocketPath: env.NEXUS_PRIVILEGED_SOCKET ?? null,
    privilegedSecretId: env.NEXUS_PRIVILEGED_SECRET_ID ?? null,
    privilegedPolicyPath: env.NEXUS_PRIVILEGED_POLICY ?? null,
    privilegedProposalDir: env.NEXUS_PRIVILEGED_PROPOSAL_DIR ?? path.join(stateDir, 'privileged-policy-proposals'),
    localMachineId: env.NEXUS_MACHINE_ID ?? null,
    agentCaPath: env.NEXUS_AGENT_CA_PATH ?? null,
    agentCertPath: env.NEXUS_AGENT_CERT_PATH ?? null,
    agentKeyPath: env.NEXUS_AGENT_KEY_PATH ?? null,
    privilegedExecAllowlist: (env.NEXUS_PRIVILEGED_EXEC_ALLOWLIST ?? '')
      .split(',')
      .map((value) => value.trim())
      .filter((value) => value.length > 0),
    artifactDir: env.NEXUS_ARTIFACT_DIR ?? path.join(stateDir, 'artifacts'),
    controlListenHost: env.NEXUS_CONTROL_LISTEN_HOST ?? '127.0.0.1',
    controlListenPort: Number(env.NEXUS_CONTROL_LISTEN_PORT ?? 7443),
    controlCaPath: env.NEXUS_CONTROL_CA_PATH ?? null,
    controlCertPath: env.NEXUS_CONTROL_CERT_PATH ?? null,
    controlKeyPath: env.NEXUS_CONTROL_KEY_PATH ?? null,
    controlMaxBodyBytes: Number(env.NEXUS_CONTROL_MAX_BODY_BYTES ?? 65_536),
    controlMaxArtifactBytes: Number(
      env.NEXUS_CONTROL_MAX_ARTIFACT_BYTES ?? 67_108_864
    ),
    mcpListenHost: env.NEXUS_MCP_LISTEN_HOST ?? '127.0.0.1',
    mcpListenPort: Number(env.NEXUS_MCP_LISTEN_PORT ?? 7444),
    mcpPublicUrl: env.NEXUS_MCP_PUBLIC_URL ?? null,
    mcpTlsCertPath: env.NEXUS_MCP_TLS_CERT_PATH ?? null,
    mcpTlsKeyPath: env.NEXUS_MCP_TLS_KEY_PATH ?? null,
    mcpClientCaPath: env.NEXUS_MCP_CLIENT_CA_PATH ?? null,
    oauthIssuer: env.NEXUS_OAUTH_ISSUER ?? null,
    oauthJwksUri: env.NEXUS_OAUTH_JWKS_URI ?? null,
    oauthAudience: env.NEXUS_OAUTH_AUDIENCE ?? null,
    oauthScope: env.NEXUS_OAUTH_SCOPE ?? 'nexus:control',
    mcpAllowedOrigins: (env.NEXUS_MCP_ALLOWED_ORIGINS ?? '')
      .split(',')
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
  };
}
