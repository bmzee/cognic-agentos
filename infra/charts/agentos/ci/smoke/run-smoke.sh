#!/usr/bin/env bash
# Sprint 14B-Z1a env-gated kind Ready-smoke. Requires: docker, kind, kubectl, helm.
# Proves the real default-adapters image reaches /readyz=200 in k8s against six real backends.
set -euo pipefail

CLUSTER="${KIND_CLUSTER:-cognic-z1a-smoke}"
NS="cognic-smoke"
IMAGE="${COGNIC_IMAGE:-cognic-agentos:smoke}"
CHART="infra/charts/agentos"

cleanup() { kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> build + load the default-adapters image"
docker build -f infra/agentos/Dockerfile --target default-adapters -t "$IMAGE" .
kind create cluster --name "$CLUSTER"
kind load docker-image "$IMAGE" --name "$CLUSTER"

echo "==> bring up the six real backends"
kubectl create namespace "$NS"
kubectl -n "$NS" apply -f "$CHART/ci/smoke/backends.yaml"
kubectl -n "$NS" wait --for=condition=available --timeout=300s deploy --all

echo "==> install the AgentOS chart"
helm install rel "$CHART" -n "$NS" -f "$CHART/ci/smoke-values.yaml"

echo "==> wait for the AgentOS pod to reach Ready (real /readyz: all five adapters ok)"
kubectl -n "$NS" rollout status deploy/rel-agentos --timeout=300s
kubectl -n "$NS" wait --for=condition=ready pod -l app.kubernetes.io/name=agentos --timeout=300s

echo "==> assert /readyz=200"
kubectl -n "$NS" port-forward svc/rel-agentos 8000:8000 >/dev/null 2>&1 &
PF=$!; sleep 4
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/api/v1/readyz)
kill "$PF" 2>/dev/null || true
echo "/readyz => $code"
test "$code" = "200"
echo "SMOKE PASS"
