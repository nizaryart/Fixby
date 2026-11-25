#!/usr/bin/env bash
# Deploys the scanned image archive to a local kind cluster, in a namespace that enforces the "restricted" Pod Security Standard.
set -euo pipefail

: "${VULNTRACK_TOKEN:?VULNTRACK_TOKEN must hold the API token}"
: "${TAG:?TAG must match the tag inside the image archive}"
CLUSTER="${CLUSTER:-vulntrack}"
NAMESPACE="${NAMESPACE:-vulntrack}"
ARCHIVE="${ARCHIVE:-image.tar}"

if ! kind get clusters 2>/dev/null | grep -x "$CLUSTER" >/dev/null; then
  kind create cluster --name "$CLUSTER" --wait 120s
fi
kind load image-archive "$ARCHIVE" --name "$CLUSTER"

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "$NAMESPACE" --overwrite \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/warn=restricted \
  pod-security.kubernetes.io/audit=restricted

if probe=$(kubectl -n "$NAMESPACE" run psa-probe --image=busybox:1.37 --privileged --restart=Never --dry-run=server -o name 2>&1); then
  echo "Pod Security Admission accepted a privileged pod; refusing to deploy" >&2
  exit 1
elif ! grep -q "violates PodSecurity" <<<"$probe"; then
  echo "Unexpected error while probing Pod Security Admission: $probe" >&2
  exit 1
fi

printf '%s' "$VULNTRACK_TOKEN" \
  | kubectl -n "$NAMESPACE" create secret generic vulntrack-api --from-file=token=/dev/stdin --dry-run=client -o yaml \
  | kubectl apply -f -

helm upgrade --install vulntrack helm/vulntrack --namespace "$NAMESPACE" \
  --set image.tag="$TAG" --wait --timeout 3m
