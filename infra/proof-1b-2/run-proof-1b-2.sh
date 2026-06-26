#!/usr/bin/env bash
# Proof 1b-2 — deployed governed MCP invocation loop.
# Operator-run + env-gated (COGNIC_RUN_PROOF_1B2=1); NO default-on CI job (needs an
# image build + kind + cosign/syft/grype + a live Vault/Postgres). Extends the
# Proof 1b-1 deploy harness (run-proof-1b-1.sh): deploys the default-adapters AgentOS
# image under a thin proof-only create_proof_app factory (fixed-actor binder), a
# private-ClusterIP MCP tool Service (10.96.0.50), and an emulated-external AS at a
# genuine-global externalIP (192.88.99.9, kube-proxy-intercepted, NO real egress).
#
# Proves the full governed MCP path against the deployed kernel:
#   * BAR 1 (checkpoint) — the PR-2b-1 override + exact-IP allow-list carve-out is
#     load-bearing: a seeded allow-list permits the resource leg
#     (audit.mcp_allowlist_permitted, host 10.96.0.50); removing the row on a COLD
#     pod refuses (mcp_discovery_url_refused / refused_component=host_address).
#   * BAR 2 (completion) — discovery_status=auth_ready + real list_tools/call_tool.
#
# Bar 1 is a CHECKPOINT (prints "BAR 1 PASS"); Bar 2 is COMPLETION (prints
# "PROOF 1b-2 (BAR 2) PASS"). On Bar 2 failure the runner captures logs +
# discovery_status + the authz reason to docs/VALIDATION-RESULTS.md and exits
# non-zero — the proof is NEVER redefined downward.
set -euo pipefail

if [[ "${COGNIC_RUN_PROOF_1B2:-}" != "1" ]]; then
  echo "skipped: set COGNIC_RUN_PROOF_1B2=1 to run the operator proof" >&2
  exit 0
fi

CLUSTER="${KIND_CLUSTER:-cognic-proof1b2}"
NS="cognic-proof1b2"
CHART="infra/charts/agentos"
PROOF_DIR="infra/proof-1b-2"
STAGING_SRC="infra/proof-1b/proof1b-staging"        # 1b-1 trust staging output
STAGING_DST="$PROOF_DIR/proof1b-staging"            # transient build-context copy
PROOF_APP_SRC="tests/integration/proof_1b_2"        # the proof-only app factory
PROOF_APP_DST="$PROOF_DIR/proof_1b_2"               # transient build-context copy
BASE_IMAGE="cognic-agentos:proof1b2-base"
IMAGE="cognic-agentos:proof1b2"
MCP_IMAGE="cognic-proof-mcp:1b2"
AS_IMAGE="cognic-proof-as:1b2"
PF=""

die() { echo "FAIL: $*" >&2; exit 1; }

# The backend image refs, sourced from backends.yaml (DRY — stays in sync with the
# smoke backends; awk field $2 ignores the trailing "# …" comment on each image: line).
_backend_images() {
  awk '/^[[:space:]]*image:/ {print $2}' "$CHART/ci/smoke/backends.yaml"
}

pf_stop() {
  [ -n "${PF:-}" ] && kill "$PF" 2>/dev/null || true
  PF=""
}

pf_start() {
  pf_stop
  kubectl -n "$NS" port-forward svc/rel-agentos 8000:8000 >/dev/null 2>&1 &
  PF=$!
  sleep 4
}

# Roll to a COLD pod so a fresh boot sees the current DB/Vault state, then wait Ready.
# Load-bearing for the Bar 1 delta: MCPHost caches BOTH the OAuth token and the
# list_tools result per tenant, so the allow-list-removed refusal is only observable
# on a cold pod.
roll_and_wait() {
  kubectl -n "$NS" rollout restart deploy/rel-agentos
  kubectl -n "$NS" rollout status deploy/rel-agentos --timeout=300s
  kubectl -n "$NS" wait --for=condition=ready pod -l app.kubernetes.io/name=agentos --timeout=300s
}

# Bar 2 failure path: capture diagnostics to docs/VALIDATION-RESULTS.md + exit non-zero.
# NEVER downgrade the proof — a Bar 2 failure is a recorded finding, not a redefinition.
bar2_fail() {
  local where="$1"
  echo "FAIL: Bar 2 ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local logs ds reason
  logs="$(kubectl -n "$NS" logs deploy/rel-agentos 2>&1 | tail -150 || true)"
  ds="$(curl -s "http://127.0.0.1:8000/api/v1/system/plugins?tenant_id=proof-1b-2" 2>/dev/null || true)"
  reason="$(grep -Eo 'mcp_[a-z_]*refused|refused_component=[a-z_]+|discovery_status=[a-z_]+' <<<"$logs" | sort -u || true)"
  {
    echo ""
    echo "## Proof 1b-2 — Bar 2 FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- authz / discovery reason markers:"
    echo '```'
    echo "${reason:-<none captured>}"
    echo '```'
    echo "- discovery_status snapshot (GET /api/v1/system/plugins?tenant_id=proof-1b-2):"
    echo '```json'
    echo "${ds:-<no response>}"
    echo '```'
    echo "- AgentOS pod logs (tail 150):"
    echo '```'
    echo "$logs"
    echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

cleanup() {
  pf_stop
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  # remove the transient build-context copies (NOT the sources)
  rm -rf "$STAGING_DST" "$PROOF_APP_DST" 2>/dev/null || true
}
trap cleanup EXIT

# --- 1. preflight ---------------------------------------------------------------
echo "==> [1/11] tool preflight"
for tool in docker kind kubectl helm uv cosign syft grype curl python3; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool '$tool' not on PATH"
done

# --- 2. rebuild the pack wheel (so the Task-1 env-driven server edits are in it) -
echo "==> [2/11] rebuild the cognic-tool-search wheel (Task-1 edits)"
( cd examples/cognic-tool-search && uv build --wheel )

# --- 3. stage the trust inputs (signed wheel + 8 attestations + cosign.pub) ------
echo "==> [3/11] stage the trust inputs"
rm -rf "$STAGING_SRC"
uv run python -m tests.integration.proof_1b.stage_trust_inputs "$STAGING_SRC"

# --- 4. build the four images ---------------------------------------------------
echo "==> [4/11] build the default-adapters base image"
docker build -f infra/agentos/Dockerfile --target default-adapters -t "$BASE_IMAGE" .

echo "==> [4/11] copy the staging + proof_1b_2 app into the proof build context"
rm -rf "$STAGING_DST" "$PROOF_APP_DST"
cp -r "$STAGING_SRC" "$STAGING_DST"
cp -r "$PROOF_APP_SRC" "$PROOF_APP_DST"

echo "==> [4/11] build the proof AgentOS image (create_proof_app + trust staging baked in)"
docker build -f "$PROOF_DIR/Dockerfile.agentos-proof" --build-arg BASE_IMAGE="$BASE_IMAGE" -t "$IMAGE" "$PROOF_DIR"

echo "==> [4/11] build the private-ClusterIP MCP tool Service image"
docker build -f "$PROOF_DIR/Dockerfile.mcp-server" -t "$MCP_IMAGE" .

echo "==> [4/11] build the emulated-external AS image"
docker build -f "$PROOF_DIR/Dockerfile.as" -t "$AS_IMAGE" .

# --- 5. kind create + load (3 proof images + pre-pulled backends) ---------------
echo "==> [5/11] pre-pull the backend images (host docker cache)"
while IFS= read -r _img; do
  [ -n "$_img" ] || continue
  echo "  docker pull $_img"
  docker pull "$_img" >/dev/null
done < <(_backend_images)

echo "==> [5/11] create kind cluster + load the 3 proof images"
kind create cluster --name "$CLUSTER"
kind load docker-image "$IMAGE" "$MCP_IMAGE" "$AS_IMAGE" --name "$CLUSTER"

echo "==> [5/11] kind load the pre-pulled backend images into the node"
while IFS= read -r _img; do
  [ -n "$_img" ] || continue
  echo "  kind load $_img"
  kind load docker-image "$_img" --name "$CLUSTER"
done < <(_backend_images)

# --- 6. namespace + the six real backends ---------------------------------------
echo "==> [6/11] bring up the six real backends"
kubectl create namespace "$NS"
kubectl -n "$NS" apply -f "$CHART/ci/smoke/backends.yaml"
kubectl -n "$NS" wait --for=condition=available --timeout=300s deploy --all

# --- 7. Vault init/seed (KV v1 + OAuth + AS-allowlist) --------------------------
# Must run after Vault is up (backend wait above) and before AgentOS reads it.
echo "==> [7/11] seed Vault (KV v1 conversion + OAuth + AS allow-list)"
NS="$NS" bash "$PROOF_DIR/seed-vault.sh"

# --- 8. helm install (prod profile; migrations OFF — Gap 3) ---------------------
echo "==> [8/11] install the AgentOS chart under the proof-1b-2 overlay"
helm install rel "$CHART" -n "$NS" -f "$PROOF_DIR/proof-1b-2-values.yaml"

# --- 9. migrate Job + apply the MCP/AS manifests --------------------------------
# Gap 3 sidestep: the chart's pre-install migration HOOK deadlocks on a fresh install
# (references the normal-resource SA + Secret Helm creates AFTER hooks). So migrations
# are OFF in the overlay and run here as a non-hook Job AFTER install (default SA).
echo "==> [9/11] run the proof-owned (non-hook) migration Job"
kubectl -n "$NS" delete job/agentos-migrate --ignore-not-found=true --wait=true
sed "s|__AGENTOS_IMAGE__|$IMAGE|" "$PROOF_DIR/migrate-job.yaml" | kubectl apply -n "$NS" -f -
kubectl -n "$NS" wait --for=condition=complete job/agentos-migrate --timeout=300s

echo "==> [9/11] apply the MCP tool Service + AS manifests; wait Ready"
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/mcp-server.yaml" -f "$PROOF_DIR/manifests/auth-server.yaml"
kubectl -n "$NS" rollout status deploy/proof-mcp --timeout=180s
kubectl -n "$NS" rollout status deploy/proof-as --timeout=180s

# --- 10. DB seed (override + allow-list rows — after migrations created the tables)
# CALLS the T8 seed script; the runner NEVER inlines the override/allow-list INSERTs
# (drift-prevention — the seed contract lives in seed-db.sh alone).
echo "==> [10/11] seed Postgres (override + exact-IP allow-list rows)"
NS="$NS" bash "$PROOF_DIR/seed-db.sh"

# --- 11. roll to a cold pod + port-forward --------------------------------------
echo "==> [11/11] roll the Deployment so fresh pods boot against the migrated+seeded DB"
roll_and_wait
pf_start

# ================================ BAR 1 (checkpoint) ============================
# The PR-2b-1 carve-out is load-bearing — pinned cold-cache sequence.
echo "==> BAR 1.1 — allow-list seeded: the resource leg is PERMITTED"
curl -sf http://127.0.0.1:8000/api/v1/mcp/servers/cognic-tool-search/tools >/dev/null \
  || die "Bar 1.1: list_tools did not return 200 with the allow-list seeded"
LOGS="$(kubectl -n "$NS" logs deploy/rel-agentos)"
grep -qF "audit.mcp_allowlist_permitted" <<<"$LOGS" \
  || die "Bar 1.1: audit.mcp_allowlist_permitted did not fire"
grep -qF "10.96.0.50" <<<"$LOGS" \
  || die "Bar 1.1: permit event did not carry host 10.96.0.50"
echo "  Bar 1.1 OK: audit.mcp_allowlist_permitted fired for host 10.96.0.50"

echo "==> BAR 1.2 — remove the allow-list row, restart COLD: the leg MUST refuse"
kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -v ON_ERROR_STOP=1 \
  -c "DELETE FROM mcp_internal_host_allowlist WHERE tenant_id='proof-1b-2' AND ip='10.96.0.50';"
roll_and_wait
pf_start
REFUSE_CODE="$(curl -s -o /tmp/proof1b2-refuse-body \
  -w '%{http_code}' http://127.0.0.1:8000/api/v1/mcp/servers/cognic-tool-search/tools || true)"
[ "$REFUSE_CODE" != "200" ] \
  || die "Bar 1.2: expected a refusal with the allow-list removed, got HTTP 200"
LOGS="$(kubectl -n "$NS" logs deploy/rel-agentos)"
grep -qF "mcp_discovery_url_refused" <<<"$LOGS" \
  || die "Bar 1.2: mcp_discovery_url_refused did not fire after allow-list removal"
grep -qF "host_address" <<<"$LOGS" \
  || die "Bar 1.2: refusal did not carry refused_component=host_address"
echo "  Bar 1.2 OK: HTTP $REFUSE_CODE + mcp_discovery_url_refused / host_address (carve-out is load-bearing)"

echo "==> BAR 1.3 — re-seed the allow-list, restart COLD: clean state for Bar 2"
NS="$NS" bash "$PROOF_DIR/seed-db.sh"
roll_and_wait
pf_start
echo "BAR 1 PASS"

# ================================ BAR 2 (completion) ===========================
echo "==> BAR 2 — full governed loop: list_tools + call_tool + discovery_status=auth_ready"
curl -sf -X GET http://127.0.0.1:8000/api/v1/mcp/servers/cognic-tool-search/tools \
  >/tmp/proof1b2-tools.json || bar2_fail "list_tools"

curl -sf -X POST http://127.0.0.1:8000/api/v1/mcp/servers/cognic-tool-search/tools/call \
  -H 'Content-Type: application/json' \
  -d '{"tool_name":"search_policy_docs","arguments":{"query":"policy"}}' \
  >/tmp/proof1b2-call.json || bar2_fail "call_tool"

curl -sf "http://127.0.0.1:8000/api/v1/system/plugins?tenant_id=proof-1b-2" \
  >/tmp/proof1b2-plugins.json || bar2_fail "plugins_read"

python3 - <<'PY' || bar2_fail "discovery_status"
import json
doc = json.load(open("/tmp/proof1b2-plugins.json"))
rows = [p for p in doc.get("plugins", []) if p.get("pack_id") == "cognic-tool-search"]
assert rows, f"FAIL: cognic-tool-search row absent (payload={doc})"
ds = rows[0].get("discovery_status")
assert ds == "auth_ready", f"FAIL: discovery_status={ds!r} expected auth_ready (payload={doc})"
print("Bar 2 OK: discovery_status=auth_ready")
PY

echo "PROOF 1b-2 (BAR 2) PASS"
