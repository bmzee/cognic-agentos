#!/usr/bin/env bash
# Sprint 14B-Z1b-d-2 env-gated AKS live-cloud smoke. Operator-run (requires: az, kubectl, helm; `az login` done).
# Exercises Z1b-b (ESO-from-Key-Vault) + Z1b-d-1 (workload identity) + Z1a (Ready) end-to-end on real AKS.
# PREREQ: deploy infra/azure/aks-smoke/main.bicep first (this reads its outputs). The smoke does NOT create
# or delete the AKS cluster — the Bicep owns it; it is rerunnable. Azure teardown is documented in the runbook.
# NOT runnable in the kernel authoring env (no Azure creds; az/bicep/shellcheck absent there).
set -euo pipefail

# --- inputs (Bicep deployment outputs / env) ---
RG="${AZ_RESOURCE_GROUP:?set AZ_RESOURCE_GROUP to the Bicep deployment resource group}"
DEPLOYMENT="${AZ_DEPLOYMENT:-aks-smoke}"
AGENTOS_NAMESPACE="${AGENTOS_NAMESPACE:-cognic-smoke}"   # MUST equal the Bicep agentosNamespace param
RELEASE="rel"
CHART="infra/charts/agentos"
COGNIC_IMAGE_REPOSITORY="${COGNIC_IMAGE_REPOSITORY:?set COGNIC_IMAGE_REPOSITORY to a registry your AKS can pull (the default-adapters image)}"
COGNIC_IMAGE_TAG="${COGNIC_IMAGE_TAG:?set COGNIC_IMAGE_TAG to the image tag}"
IMAGE="${COGNIC_IMAGE_REPOSITORY}:${COGNIC_IMAGE_TAG}"   # the Deployment AND the migration Job use this
ENABLE_OTLP="${ENABLE_OTLP:-1}"                          # 1 = OTLP on (3-key gate); 0 = OTLP off (2-key fallback)
OTEL_HEADERS_JSON="${OTEL_HEADERS_JSON:-{}}"             # e.g. {"Authorization":"Basic <b64>"} (used only when ENABLE_OTLP=1)

out() { az deployment group show -g "$RG" -n "$DEPLOYMENT" --query "properties.outputs.$1.value" -o tsv; }
CLUSTER="$(out clusterName)"
KEYVAULT="$(out keyVaultName)"
UAMI_CLIENT_ID="$(out uamiClientId)"
KV_URI="https://${KEYVAULT}.vault.azure.net"
SECRET="${RELEASE}-agentos-secrets"

echo "==> get kubeconfig for $CLUSTER"
az aks get-credentials -g "$RG" -n "$CLUSTER" --overwrite-existing

echo "==> pin the AgentOS namespace ($AGENTOS_NAMESPACE) — MUST match the Bicep agentosNamespace"
kubectl get namespace "$AGENTOS_NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$AGENTOS_NAMESPACE"

echo "==> install ESO (its own namespace, not \$AGENTOS_NAMESPACE)"
helm repo add external-secrets https://charts.external-secrets.io >/dev/null 2>&1 || true
helm repo update >/dev/null
helm upgrade --install external-secrets external-secrets/external-secrets \
  -n external-secrets --create-namespace --wait

echo "==> bring up the six in-cluster backends"
kubectl apply -n "$AGENTOS_NAMESPACE" -f "$CHART/ci/smoke/backends.yaml"
kubectl -n "$AGENTOS_NAMESPACE" wait --for=condition=available --timeout=300s deploy --all

echo "==> apply the Azure Key Vault SecretStore (workload identity -> chart SA)"
sed "s|__KEY_VAULT_URI__|$KV_URI|" infra/azure/aks-smoke/secretstore.yaml \
  | kubectl apply -n "$AGENTOS_NAMESPACE" -f -

echo "==> seed Key Vault (2 bootstrap secrets; Azure KV names have NO slashes)"
az keyvault secret set --vault-name "$KEYVAULT" --name agentos-database-url \
  --value "postgresql+asyncpg://cognic:cognic@postgres:5432/cognic" >/dev/null
az keyvault secret set --vault-name "$KEYVAULT" --name agentos-vault-token \
  --value "smoke-root-token" >/dev/null

if [[ "$ENABLE_OTLP" == "1" ]]; then
  echo "==> OTLP on: seed the header secret + apply the auxiliary Merge ExternalSecret"
  az keyvault secret set --vault-name "$KEYVAULT" --name agentos-otel-headers \
    --value "$OTEL_HEADERS_JSON" >/dev/null
  kubectl apply -n "$AGENTOS_NAMESPACE" -f infra/azure/aks-smoke/externalsecret-otel-headers.yaml
else
  echo "==> OTLP off (ENABLE_OTLP=0): delete any prior auxiliary Merge ExternalSecret (escape an Owner/Merge conflict on rerun)"
  kubectl -n "$AGENTOS_NAMESPACE" delete externalsecret/agentos-otel-headers --ignore-not-found=true --wait=true
fi

echo "==> helm install AgentOS (ESO + WI on; migrations OFF -> post-gate Job; OTLP per ENABLE_OTLP)"
# smoke-values.yaml hardcodes the kind-loaded image (cognic-agentos:smoke); override it with the
# operator's REGISTRY image so the AKS Deployment pulls a real image (NOT just the migration Job).
# Build the Helm args as an always-non-empty array so the expansion never emits a stray empty arg
# (the `${arr[@]+...}` empty-array idiom is shell-fragile — safe under bash, but not under zsh).
helm_args=(upgrade --install "$RELEASE" "$CHART" -n "$AGENTOS_NAMESPACE"
  -f "$CHART/ci/smoke-values.yaml"
  -f infra/azure/aks-smoke/aks-smoke-values.yaml
  --set-string image.repository="$COGNIC_IMAGE_REPOSITORY"
  --set-string image.tag="$COGNIC_IMAGE_TAG"
  --set-string image.pullPolicy=Always
  --set-string serviceAccount.annotations."azure\.workload\.identity/client-id"="$UAMI_CLIENT_ID"
)
if [[ "$ENABLE_OTLP" != "1" ]]; then
  # blank the endpoint (export becomes a no-op) + the header key (no OTLP-header env) so the 3rd
  # Secret key is not required and the gate below drops to 2 keys.
  helm_args+=(--set otel.exporter.endpoint= --set otel.exporter.headersSecretKey=)
fi
helm "${helm_args[@]}"

KEY_COUNT=$([[ "$ENABLE_OTLP" == "1" ]] && echo 3 || echo 2)
echo "==> fail-loud ${KEY_COUNT}-key gate: ESO (+ the Merge aux when OTLP on) must populate $SECRET"
deadline=$(( SECONDS + 300 ))
have_keys() {
  local data
  data="$(kubectl -n "$AGENTOS_NAMESPACE" get secret "$SECRET" -o jsonpath='{.data}' 2>/dev/null || true)"
  [[ "$data" == *COGNIC_DATABASE_URL* && "$data" == *COGNIC_VAULT_TOKEN* ]] || return 1
  if [[ "$ENABLE_OTLP" == "1" ]]; then
    [[ "$data" == *COGNIC_OTEL_EXPORTER_HEADERS* ]] || return 1
  fi
  return 0
}
until have_keys; do
  if (( SECONDS > deadline )); then
    echo "FAIL: $SECRET missing a required key after 300s (ESO/WI failure or, with OTLP on, an Owner+Merge conflict — retry with ENABLE_OTLP=0)" >&2
    kubectl -n "$AGENTOS_NAMESPACE" get secret "$SECRET" -o jsonpath='{.data}' >&2 || true
    exit 1
  fi
  sleep 5
done
echo "    all ${KEY_COUNT} keys present"

echo "==> run the smoke-owned (non-hook) migration Job"
# delete any prior Job first — a completed Job will not re-run, and a Job pod template is immutable
# (an apply with a changed image/template would be rejected); this keeps the smoke rerunnable.
kubectl -n "$AGENTOS_NAMESPACE" delete job/agentos-migrate --ignore-not-found=true --wait=true
sed "s|__AGENTOS_IMAGE__|$IMAGE|" infra/azure/aks-smoke/migrate-job.yaml \
  | kubectl apply -n "$AGENTOS_NAMESPACE" -f -
kubectl -n "$AGENTOS_NAMESPACE" wait --for=condition=complete job/agentos-migrate --timeout=300s

echo "==> roll the Deployment so fresh pods see the migrated schema"
kubectl -n "$AGENTOS_NAMESPACE" rollout restart deploy/"${RELEASE}-agentos"
kubectl -n "$AGENTOS_NAMESPACE" rollout status deploy/"${RELEASE}-agentos" --timeout=300s
kubectl -n "$AGENTOS_NAMESPACE" wait --for=condition=ready pod -l app.kubernetes.io/name=agentos --timeout=300s

echo "==> assert /readyz=200"
kubectl -n "$AGENTOS_NAMESPACE" port-forward "svc/${RELEASE}-agentos" 8000:8000 >/dev/null 2>&1 &
PF=$!; sleep 4
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/api/v1/readyz)
kill "$PF" 2>/dev/null || true
echo "/readyz => $code"
test "$code" = "200"
echo "AKS SMOKE PASS"
