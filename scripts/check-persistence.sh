#!/usr/bin/env bash
# Restarts the pod and checks that findings written before the restart are still on the volume.
set -euo pipefail

NAMESPACE="${NAMESPACE:-vulntrack}"
: "${VULNTRACK_TOKEN:?VULNTRACK_TOKEN must hold the API token}"

kubectl -n "$NAMESPACE" rollout restart deployment/vulntrack
kubectl -n "$NAMESPACE" rollout status deployment/vulntrack --timeout 120s

findings="$(scripts/with-port-forward.sh curl -sf -H "Authorization: Bearer $VULNTRACK_TOKEN" http://127.0.0.1:8080/api/findings)"
if ! grep -F "Smoke test finding" <<<"$findings" >/dev/null; then
  echo "FAIL: the finding created before the restart is gone" >&2
  exit 1
fi
echo "data survived the restart"
