#!/usr/bin/env bash
set -euo pipefail
[[ $# -eq 1 ]] || { echo 'usage: break_glass.sh <known-good-runtime-dir>' >&2; exit 2; }
src="$1"; [[ -d "$src" ]] || { echo 'known-good runtime missing' >&2; exit 3; }
[[ "$(id -u)" -eq 0 ]] || { echo 'root required' >&2; exit 4; }
[[ -f "$src/dist/src/mcp/buildServer.js" && -f "$src/dist/src/privileged/main.js" ]] || { echo 'invalid runtime' >&2; exit 5; }
ts=$(date -u +%Y%m%dT%H%M%SZ); printf '%s BREAK_GLASS restore=%s operator=%s\n' "$ts" "$src" "${SUDO_USER:-root}" >> /var/log/nexus-maintenance-break-glass.log
systemctl stop nexus-tunnel@ubuntu.service nexus-privileged-executor.service || true
rm -rf /opt/nexus-commander.failed; [[ ! -e /opt/nexus-commander ]] || mv /opt/nexus-commander /opt/nexus-commander.failed
cp -a "$src" /opt/nexus-commander
systemctl start nexus-privileged-executor.service nexus-tunnel@ubuntu.service
systemctl is-active --quiet nexus-privileged-executor.service nexus-tunnel@ubuntu.service
