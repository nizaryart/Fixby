#!/usr/bin/env bash
# Runs a command while the VulnTrack service is forwarded to 127.0.0.1:$PORT.
set -euo pipefail

NAMESPACE="${NAMESPACE:-vulntrack}"
PORT="${PORT:-8080}"

kubectl -n "$NAMESPACE" port-forward svc/vulntrack "$PORT:80" >/dev/null 2>&1 &
forward=$!
trap 'kill "$forward" 2>/dev/null || true' EXIT

for _ in $(seq 1 30); do
  curl -sf "http://127.0.0.1:$PORT/health" >/dev/null && break
  sleep 1
done

"$@"
