#!/usr/bin/env bash
set -euo pipefail

# Tests must never inherit live deployed Nexus runtime state from a parent MCP job.
# Each test may set its own NEXUS_* variables after this wrapper starts.
for name in   NEXUS_STATE_DIR   NEXUS_DB_PATH   NEXUS_LOG_DIR   NEXUS_SECRET_STORE_DIR   NEXUS_PRIVILEGED_SOCKET   NEXUS_PRIVILEGED_SECRET_ID   NEXUS_MACHINE_ID   NEXUS_AGENT_CA_PATH   NEXUS_AGENT_CERT_PATH   NEXUS_AGENT_KEY_PATH   NEXUS_ARTIFACT_DIR   NEXUS_CONTROL_CA_PATH   NEXUS_CONTROL_CERT_PATH   NEXUS_CONTROL_KEY_PATH   NEXUS_MCP_PUBLIC_URL   NEXUS_MCP_TLS_CERT_PATH   NEXUS_MCP_TLS_KEY_PATH   NEXUS_MCP_CLIENT_CA_PATH   NEXUS_OAUTH_ISSUER   NEXUS_OAUTH_JWKS_URI   NEXUS_OAUTH_AUDIENCE; do
  unset "$name"
done

exec "$(dirname "$0")/../node_modules/.bin/vitest" run --dir tests
