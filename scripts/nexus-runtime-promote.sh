#!/usr/bin/env bash
set -euo pipefail

SOURCE=""
EXPECTED_SHA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --source) SOURCE="${2:-}"; shift 2 ;;
    --sha256) EXPECTED_SHA="${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ "$EUID" -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
[[ "$SOURCE" =~ ^/home/ubuntu/logres/(staging|control)/nexus-runtime-[A-Za-z0-9._:-]+/runtime\.tar\.gz$ || "$SOURCE" =~ ^/var/tmp/nexus-maintenance/staging/nexus-runtime-[A-Za-z0-9._:-]+/runtime\.tar\.gz$ ]] || { echo "invalid runtime archive path" >&2; exit 2; }
[[ "$EXPECTED_SHA" =~ ^[a-f0-9]{64}$ ]] || { echo "invalid runtime digest" >&2; exit 2; }
[[ -f "$SOURCE" && ! -L "$SOURCE" ]] || { echo "runtime archive must be a regular non-symlink file" >&2; exit 1; }
[[ "$(stat -c %h "$SOURCE")" == "1" ]] || { echo "runtime archive hardlink rejected" >&2; exit 1; }
(( $(stat -c %s "$SOURCE") <= 268435456 )) || { echo "runtime archive too large" >&2; exit 1; }
[[ "$(sha256sum "$SOURCE" | awk '{print $1}')" == "$EXPECTED_SHA" ]] || { echo "runtime archive digest mismatch" >&2; exit 1; }

SHORT="${EXPECTED_SHA:0:12}"
STAGING="/opt/nexus-commander.new.${SHORT}.$$"
PREVIOUS="/opt/nexus-commander.previous"
POLICY="/etc/nexus-commander/privileged-policy.json"
POLICY_BACKUP="/etc/nexus-commander/privileged-policy.json.previous"
SWAPPED=0
COMMITTED=0

cleanup() {
  rc=$?
  set +e
  if [[ "$COMMITTED" -ne 1 && "$SWAPPED" -eq 1 ]]; then
    rm -rf /opt/nexus-commander
    if [[ -d "$PREVIOUS" ]]; then mv "$PREVIOUS" /opt/nexus-commander; fi
    if [[ -f "$POLICY_BACKUP" ]]; then cp -f "$POLICY_BACKUP" "$POLICY"; chmod 0640 "$POLICY"; chown root:nexus "$POLICY"; fi
  fi
  rm -rf "$STAGING"
  mount -o remount,ro / >/dev/null 2>&1 || true
  exit "$rc"
}
trap cleanup EXIT INT TERM

mount -o remount,rw /
rm -rf "$STAGING"
mkdir -p "$STAGING"

while IFS= read -r entry; do
  entry="${entry#./}"
  [[ -z "$entry" ]] && continue
  [[ "$entry" != /* && "$entry" != *"../"* && "$entry" != ".." ]] || { echo "unsafe archive entry: $entry" >&2; exit 1; }
  case "$entry" in
    dist|dist/*|src|src/*|deploy|deploy/privileged-policy.json|scripts|scripts/nexus-runtime-promote.sh|scripts/nexus-runtime-post-promote.sh|scripts/logres-runtime-promote-root.sh|package.json|package-lock.json) ;;
    *) echo "unexpected runtime archive entry: $entry" >&2; exit 1 ;;
  esac
done < <(tar -tzf "$SOURCE")

if tar -tvzf "$SOURCE" | awk '$1 ~ /^[lh]/ { found=1 } END { exit found ? 0 : 1 }'; then
  echo "runtime archive links rejected" >&2
  exit 1
fi

tar -xzf "$SOURCE" -C "$STAGING" --no-same-owner --no-same-permissions
for required in \
  dist/src/mcp/buildServer.js \
  dist/src/mcp/stdio.js \
  dist/src/privileged/main.js \
  dist/src/control/main.js \
  dist/src/config.js \
  dist/src/security/secretStore.js \
  dist/src/privileged/client.js; do
  [[ -f "$STAGING/$required" ]] || { echo "required production runtime missing: $required" >&2; exit 1; }
done
[[ -f "$STAGING/src/jobs/worker.ts" ]] || { echo "durable job source missing" >&2; exit 1; }
for module in \
  dist/src/mcp/stdio.js \
  dist/src/privileged/main.js \
  dist/src/control/main.js; do
  node --check "$STAGING/$module" >/dev/null || { echo "production runtime syntax check failed: $module" >&2; exit 1; }
done
[[ -f "$STAGING/deploy/privileged-policy.json" ]] || { echo "privileged policy missing" >&2; exit 1; }
[[ -x "$STAGING/scripts/nexus-runtime-promote.sh" ]] || chmod 0755 "$STAGING/scripts/nexus-runtime-promote.sh"
[[ -x "$STAGING/scripts/nexus-runtime-post-promote.sh" ]] || chmod 0755 "$STAGING/scripts/nexus-runtime-post-promote.sh"
[[ -x "$STAGING/scripts/logres-runtime-promote-root.sh" ]] || chmod 0755 "$STAGING/scripts/logres-runtime-promote-root.sh"
node -e 'const p=require(process.argv[1]); if (!p.dependencies || p.dependencies.tsx !== "4.23.15") process.exit(2)' "$STAGING/package.json"
npm_config_cache=/home/ubuntu/logres/control/npm-cache npm --prefix "$STAGING" ci --omit=dev --ignore-scripts
[[ -x "$STAGING/node_modules/.bin/tsx" ]] || { echo "production tsx runtime missing" >&2; exit 1; }
# The privileged executor runs with UMask=0007. A freshly-created staging root
# therefore starts as 0770 and would become root-only after a simple go-w.
# Normalize the runtime tree so unprivileged Nexus services can traverse/read it
# while keeping all write access root-only. Preserve executable bits on scripts
# and npm bins via X.
chmod -R a+rX,go-w "$STAGING"
[[ "$(stat -c %a "$STAGING")" == "755" ]] || { echo "runtime root permissions invalid" >&2; exit 1; }
for required in \
  dist/src/mcp/stdio.js \
  dist/src/privileged/main.js \
  dist/src/control/main.js; do
  test -r "$STAGING/$required" || { echo "runtime entrypoint unreadable: $required" >&2; exit 1; }
done
chown -R root:root "$STAGING"

cp -f "$POLICY" "$POLICY_BACKUP"
chmod 0640 "$POLICY_BACKUP"
chown root:nexus "$POLICY_BACKUP"
rm -rf "$PREVIOUS"
if [[ -d /opt/nexus-commander ]]; then mv /opt/nexus-commander "$PREVIOUS"; fi
mv "$STAGING" /opt/nexus-commander
SWAPPED=1
install -o root -g nexus -m 0640 /opt/nexus-commander/deploy/privileged-policy.json "$POLICY"

UNIT="nexus-post-promote-${SHORT}-$$"
systemd-run --quiet --unit="$UNIT" --on-active=2s /opt/nexus-commander/scripts/nexus-runtime-post-promote.sh
COMMITTED=1
printf 'NEXUS_RUNTIME_PROMOTION_SCHEDULED sha256=%s\n' "$EXPECTED_SHA"
