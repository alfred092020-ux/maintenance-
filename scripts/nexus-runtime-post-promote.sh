#!/usr/bin/env bash
set -euo pipefail

PREVIOUS="/opt/nexus-commander.previous"
POLICY="/etc/nexus-commander/privileged-policy.json"
POLICY_BACKUP="/etc/nexus-commander/privileged-policy.json.previous"
FAILED="/opt/nexus-commander.failed.$(date +%s)"
SERVICES=(nexus-privileged-executor.service nexus-tunnel@ubuntu.service nexus-control-plane@ubuntu.service)

mount -o remount,rw /
cleanup() { mount -o remount,ro / >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Bootstrap compatibility: older promoters inherit UMask=0007 from the
# privileged executor and can leave the swapped runtime root as 0750 root:root.
# Normalize the complete runtime tree before any unprivileged Nexus service is
# restarted. Future promotions perform the same normalization before swap.
chmod -R a+rX,go-w /opt/nexus-commander
[[ "$(stat -c %a /opt/nexus-commander)" == "755" ]] || { echo "runtime root permissions invalid after normalization" >&2; exit 1; }
for required in \
  dist/src/mcp/stdio.js \
  dist/src/privileged/main.js \
  dist/src/control/main.js; do
  [[ -r "/opt/nexus-commander/$required" ]] || { echo "runtime entrypoint unreadable before restart: $required" >&2; exit 1; }
  runuser -u ubuntu -- test -r "/opt/nexus-commander/$required" || { echo "ubuntu cannot read runtime entrypoint: $required" >&2; exit 1; }
done

if [[ -f /opt/nexus-commander/deploy/systemd/nexus-tunnel@.service ]]; then
  install -o root -g root -m 0644 /opt/nexus-commander/deploy/systemd/nexus-tunnel@.service /etc/systemd/system/nexus-tunnel@.service
  rm -f /etc/systemd/system/nexus-tunnel@ubuntu.service.d/worker-write.conf
fi
systemctl daemon-reload
systemctl restart "${SERVICES[@]}"
for service in "${SERVICES[@]}"; do
  healthy=0
  for _ in $(seq 1 30); do
    if systemctl is-active --quiet "$service"; then
      pid1=$(systemctl show -p MainPID --value "$service")
      sleep 2
      pid2=$(systemctl show -p MainPID --value "$service")
      if [[ "$pid1" =~ ^[1-9][0-9]*$ && "$pid1" == "$pid2" ]] && systemctl is-active --quiet "$service"; then
        healthy=1
        break
      fi
    fi
    sleep 1
  done
  if [[ "$healthy" -ne 1 ]]; then
    systemctl stop "${SERVICES[@]}" >/dev/null 2>&1 || true
    mv /opt/nexus-commander "$FAILED" || true
    if [[ -d "$PREVIOUS" ]]; then mv "$PREVIOUS" /opt/nexus-commander; fi
    if [[ -f "$POLICY_BACKUP" ]]; then cp -f "$POLICY_BACKUP" "$POLICY"; chmod 0640 "$POLICY"; chown root:nexus "$POLICY"; fi
    chmod -R a+rX,go-w /opt/nexus-commander >/dev/null 2>&1 || true
    systemctl daemon-reload
    systemctl restart "${SERVICES[@]}"
    echo "Nexus promotion health check failed for $service; rolled back" >&2
    exit 1
  fi
done

echo "NEXUS_RUNTIME_PROMOTION_HEALTHY"
