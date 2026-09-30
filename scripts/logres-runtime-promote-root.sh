#!/usr/bin/env bash
set -euo pipefail
SHA=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sha) SHA="${2:-}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ "$EUID" -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
[[ "$SHA" =~ ^[a-f0-9]{40}$ ]] || { echo "invalid integration sha" >&2; exit 2; }
REPO=/home/ubuntu/logres/src/awakened-realms
CURRENT="$(/usr/sbin/runuser -u ubuntu -- git -C "$REPO" rev-parse feat/logres-reconstruction)"
[[ "$SHA" == "$CURRENT" ]] || { echo "requested sha is not current canonical integration" >&2; exit 1; }
mount -o remount,rw /
cleanup() { mount -o remount,ro / >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=safe.directory \
GIT_CONFIG_VALUE_0="$REPO" \
  /home/ubuntu/logres/bin/logres-runtime-deploy --sha "$SHA" --json
sync
