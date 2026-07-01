#!/usr/bin/env bash
# Proof M4 (operator-grade pack install flow) — the deployed proof that the pack
# LIFECYCLE STATE governs MCP callability through the GOVERNED OPERATOR PATH, against
# the deployed kernel + the RELEASED, signed cognic-tool-oracle-schema@v0.1.0 pack.
#
# It EXTENDS the proven Proof 1b-2c runner: same released pack, same in-cluster Oracle
# XE + RS256/JWKS AS, same single-effective MCP URL (10.96.0.51:8765/mcp). The DELTA is
# the SEEDING: proof-1b-2c INSERTed the override + allow-list carve-out rows directly;
# M4 REMOVES that and drives the REAL operator API instead —
#   submit -> claim -> approve -> allow-list -> configure -> install
# — so `install`'s materializer MATERIALIZES those derived rows from the DESIRED
# runtime-config record (`configure` writes it). `disable`/`revoke` RETRACT them.
# `mcp_authz` is UNCHANGED — it reads the derived rows exactly as today.
#
# The multi-actor identities come from a PROOF-ONLY header-driven binder
# (tests/integration/proof_m4/proof_app.py::MultiActorProofBinder, selected via the
# X-Proof-Role request header). PRODUCTION requires a real bank-overlay ActorBinder +
# a single-engine eager-injection deploy; this is proof-only.
#
# Operator-run + env-gated (COGNIC_RUN_PROOF_M4=1); NO default-on CI job (needs an image
# build + kind + a live Vault/Postgres + an in-cluster Oracle XE).
#
# Proves (BARs):
#   * BAR 1 (happy) — the full operator lifecycle via the API materializes the
#     override + allow-list rows (asserted via the decision_history events
#     mcp.override.set + mcp.allowlist.add) -> discovery_status=auth_ready ->
#     call_tool(describe_table owner=COGNIC table=EMPLOYEES) returns FULL_NAME.
#   * BAR 2 (negatives) — install refused when NOT approved / NOT allow-listed / NOT
#     configured / Vault OAuth ref absent; approve refused on a signature-red pack
#     (the existing 5-gate — signature stays REAL). Each via the API, asserting the
#     closed-enum reason.
#   * BAR 3 (disable/revoke) — post-install `disable` -> the next governed probe is
#     refused (discovery_status=refused); re-`install` (the disabled->installed
#     re-enable) restores callability; `revoke` -> refused + terminal.
#
# BAR 1 is COMPLETION (prints "PROOF M4 (BAR 1) PASS"); BAR 2 + BAR 3 harden it. On any
# BAR failure the runner captures logs + discovery_status + the authz/refusal reason to
# docs/VALIDATION-RESULTS.md and exits non-zero — the proof is NEVER redefined downward.
set -euo pipefail

if [[ "${COGNIC_RUN_PROOF_M4:-}" != "1" ]]; then
  echo "skipped: set COGNIC_RUN_PROOF_M4=1 to run the operator proof" >&2
  exit 0
fi

CLUSTER="${KIND_CLUSTER:-cognic-proofm4}"
NS="cognic-proofm4"
CHART="infra/charts/agentos"
PROOF_DIR="infra/proof-m4"
STAGING_DST="$PROOF_DIR/proof-m4-staging"           # released-pack staging output (build context)
PROOF_APP_SRC="tests/integration/proof_m4"          # the proof-only multi-actor app factory
PROOF_APP_DST="$PROOF_DIR/proof_m4"                 # transient build-context copy
AGENTOS_SRC_SRC="src/cognic_agentos"                # current kernel source overlay
AGENTOS_SRC_DST="$PROOF_DIR/cognic_agentos"         # transient build-context copy
BASE_IMAGE="cognic-agentos:proof1b2-base"           # reused — same default-adapters base as proof-1b-2c
IMAGE="cognic-agentos:proofm4"
MCP_IMAGE="cognic-proof-oracle-pack:m4"
AS_IMAGE="cognic-proof-as:m4"
TENANT="proof-m4"
PACK_ID="cognic-tool-oracle-schema"
PACK_WHEEL="cognic_tool_oracle_schema-0.1.0-py3-none-any.whl"
BASE_URL="http://127.0.0.1:8000"
PF=""

die() { echo "FAIL: $*" >&2; exit 1; }

# The backend image refs, sourced from backends.yaml (DRY — stays in sync with the
# smoke backends; awk field $2 ignores the trailing "# …" comment on each image: line).
_backend_images() {
  awk '/^[[:space:]]*image:/ {print $2}' "$CHART/ci/smoke/backends.yaml"
}

# Extra (non-backend) images the manifests reference with imagePullPolicy: IfNotPresent —
# pre-pulled + kind-loaded so the kind node never reaches the internet for them:
# oracle-xe (manifests/oracle-xe.yaml) + busybox (the oracle-pack wait-for-xe initContainer).
_extra_images() {
  printf '%s\n' "gvenzl/oracle-xe:21-slim" "busybox:1.36"
}

docker_pull_with_retry() {
  local img="$1"
  local max=5
  local attempt=1
  if [[ "${COGNIC_PROOF_M4_REUSE_IMAGES:-0}" == "1" ]] && docker image inspect "$img" >/dev/null 2>&1; then
    echo "  using cached image $img (COGNIC_PROOF_M4_REUSE_IMAGES=1)"
    return 0
  fi
  while true; do
    if docker pull "$img" >/dev/null; then
      return 0
    fi
    if [ "$attempt" -ge "$max" ]; then
      echo "docker pull failed after $attempt attempts: $img" >&2
      return 1
    fi
    echo "docker pull failed for $img (attempt $attempt/$max); retrying in 3s" >&2
    attempt=$((attempt + 1))
    sleep 3
  done
}

docker_build_with_retry() {
  local max=3
  local attempt=1
  while true; do
    if docker build "$@"; then
      return 0
    fi
    if [ "$attempt" -ge "$max" ]; then
      echo "docker build failed after $attempt attempts: $*" >&2
      return 1
    fi
    echo "docker build failed (attempt $attempt/$max); retrying in 3s: $*" >&2
    attempt=$((attempt + 1))
    sleep 3
  done
}

require_cached_image() {
  local img="$1"
  docker image inspect "$img" >/dev/null 2>&1 || die \
    "COGNIC_PROOF_M4_REUSE_IMAGES=1 requested, but required image is absent: $img"
}

pf_stop() {
  [ -n "${PF:-}" ] && kill "$PF" 2>/dev/null || true
  PF=""
}

pf_start() {
  pf_stop
  kubectl -n "$NS" port-forward svc/rel-agentos 8000:8000 >/dev/null 2>&1 &
  PF=$!
  local _i
  for _i in $(seq 1 30); do
    if curl -sf "$BASE_URL/api/v1/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  bar_fail "port-forward did not expose a healthy AgentOS API"
}

# Roll to a COLD pod so a fresh boot sees the current DB/Vault state, then wait Ready.
# Load-bearing for the discovery-status deltas: MCPHost caches BOTH the OAuth token and
# the list_tools result per tenant, so a callability change (install materializes / disable
# retracts the carve-out rows) is only observable on a cold pod.
roll_and_wait() {
  kubectl -n "$NS" rollout restart deploy/rel-agentos
  kubectl -n "$NS" rollout status deploy/rel-agentos --timeout=600s \
    || agentos_fail "rel-agentos rollout did not complete within 600s"
  kubectl -n "$NS" wait --for=condition=ready pod -l app.kubernetes.io/name=agentos --timeout=600s \
    || agentos_fail "rel-agentos pod did not become Ready within 600s"
}

# ---- Multi-actor API helpers (drive the REAL operator API via X-Proof-Role) ---------
# api <ROLE> <METHOD> <PATH> [JSON_BODY] -> stdout is the response body; sets HTTP_CODE.
# The role header selects the proof Actor (author/reviewer/operator/mcp); tenant +
# originator come from the bound Actor, never the URL.
HTTP_CODE=""
HTTP_CODE_FILE="/tmp/proofm4-code"
load_http_code() {
  HTTP_CODE="$(cat "$HTTP_CODE_FILE" 2>/dev/null || true)"
}

api() {
  local role="$1" method="$2" path="$3" body="${4:-}"
  local out
  if [ -n "$body" ]; then
    out="$(curl -s -o /tmp/proofm4-resp -w '%{http_code}' -X "$method" \
      -H "X-Proof-Role: $role" -H 'Content-Type: application/json' \
      -d "$body" "$BASE_URL$path")"
  else
    out="$(curl -s -o /tmp/proofm4-resp -w '%{http_code}' -X "$method" \
      -H "X-Proof-Role: $role" "$BASE_URL$path")"
  fi
  HTTP_CODE="$out"
  printf '%s' "$out" > "$HTTP_CODE_FILE"
  cat /tmp/proofm4-resp
}

# discovery_status of the pack row from GET /system/plugins?tenant_id=proof-m4.
discovery_status() {
  local body
  body="$(curl -sf "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
  if [ -z "$body" ]; then
    echo "<unreachable>"
    return 0
  fi
  python3 - "$PACK_ID" "$body" <<'PY'
import json, sys
pack_id = sys.argv[1]
try:
    doc = json.loads(sys.argv[2])
except Exception:
    print("<invalid-json>")
    raise SystemExit(0)
rows = [p for p in doc.get("plugins", []) if p.get("pack_id") == pack_id]
print(rows[0].get("discovery_status") if rows else "<row-absent>")
PY
}

# ---- Failure diagnostics (mirror proof-1b-2c: capture then exit non-zero) ------------
bar_fail() {
  local where="$1"
  echo "FAIL: $where — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local logs ds dh derived audit reason
  logs="$(kubectl -n "$NS" logs deploy/rel-agentos 2>&1 | tail -150 || true)"
  ds="$(curl -s "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
  dh="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT event_type, payload::text FROM decision_history WHERE event_type LIKE 'mcp.%' OR event_type LIKE 'pack.lifecycle.%' ORDER BY sequence DESC LIMIT 20;" 2>/dev/null || true)"
  derived="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT 'override|' || tenant_id || '|' || pack_id || '|' || server_url_override FROM mcp_server_url_override UNION ALL SELECT 'allowlist|' || tenant_id || '|' || ip || '|' || set_by_actor FROM mcp_internal_host_allowlist ORDER BY 1;" 2>/dev/null || true)"
  audit="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT event_type, payload::text FROM audit_event WHERE event_type='audit.mcp_allowlist_permitted' ORDER BY sequence DESC LIMIT 5;" 2>/dev/null || true)"
  reason="$(grep -Eo 'install_[a-z_]+|mcp_[a-z_]*refused|discovery_status=[a-z_]+|materialize_[a-z_]+' <<<"$logs" | sort -u || true)"
  {
    echo ""
    echo "## Proof M4 — FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- last API response (HTTP $HTTP_CODE):"
    echo '```json'
    cat /tmp/proofm4-resp 2>/dev/null || echo "<no response captured>"
    echo ""
    echo '```'
    echo "- refusal / discovery reason markers:"
    echo '```'
    echo "${reason:-<none captured>}"
    echo '```'
    echo "- discovery_status snapshot (GET /api/v1/system/plugins?tenant_id=$TENANT):"
    echo '```json'
    echo "${ds:-<no response>}"
    echo '```'
    echo "- decision_history (mcp.* / pack.lifecycle.* tail 20):"
    echo '```'
    echo "${dh:-<none>}"
    echo '```'
    echo "- derived MCP config rows (override + allow-list):"
    echo '```'
    echo "${derived:-<none>}"
    echo '```'
    echo "- audit.mcp_allowlist_permitted tail:"
    echo '```'
    echo "${audit:-<none>}"
    echo '```'
    echo "- AgentOS pod logs (tail 150):"
    echo '```'
    echo "$logs"
    echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

# Step-5 XE-readiness failure path (mirrors proof-1b-2c xe_fail).
xe_fail() {
  local where="$1"
  echo "FAIL: oracle-xe ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local pods desc logs
  pods="$(kubectl -n "$NS" get pods 2>&1 || true)"
  desc="$(kubectl -n "$NS" describe pod -l app=oracle-xe 2>&1 | tail -90 || true)"
  logs="$(kubectl -n "$NS" logs -l app=oracle-xe --tail=120 2>&1 || true)"
  {
    echo ""
    echo "## Proof M4 — Oracle XE readiness FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- pods:"; echo '```'; echo "$pods"; echo '```'
    echo "- oracle-xe describe (tail 90):"; echo '```'; echo "$desc"; echo '```'
    echo "- oracle-xe logs (tail 120):"; echo '```'; echo "$logs"; echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

# Step-5 backends-readiness failure path (mirrors proof-1b-2c backends_fail).
backends_fail() {
  local where="$1"
  echo "FAIL: backends ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local wide ddeploy dpods
  wide="$(kubectl -n "$NS" get deploy,pods -o wide 2>&1 || true)"
  ddeploy="$(kubectl -n "$NS" describe deploy -l 'app notin (oracle-xe)' 2>&1 | tail -120 || true)"
  dpods="$(kubectl -n "$NS" describe pod -l 'app notin (oracle-xe)' 2>&1 | tail -150 || true)"
  {
    echo ""
    echo "## Proof M4 — backends readiness FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- deploy + pods (-o wide):"; echo '```'; echo "$wide"; echo '```'
    echo "- backend deploy describe (tail 120):"; echo '```'; echo "$ddeploy"; echo '```'
    echo "- backend pod describe (tail 150):"; echo '```'; echo "$dpods"; echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

migrate_fail() {
  local where="$1"
  echo "FAIL: migrate ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local wide desc logs events
  wide="$(kubectl -n "$NS" get job/agentos-migrate,pod -l job-name=agentos-migrate -o wide 2>&1 || true)"
  desc="$(kubectl -n "$NS" describe job/agentos-migrate 2>&1 || true)"
  logs="$(kubectl -n "$NS" logs job/agentos-migrate --all-containers=true --tail=180 2>&1 || true)"
  events="$(kubectl -n "$NS" get events --sort-by=.lastTimestamp 2>&1 | tail -120 || true)"
  {
    echo ""
    echo "## Proof M4 — migration Job FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- migrate job + pod (-o wide):"; echo '```'; echo "$wide"; echo '```'
    echo "- migrate job describe:"; echo '```'; echo "$desc"; echo '```'
    echo "- migrate logs (tail 180):"; echo '```'; echo "$logs"; echo '```'
    echo "- namespace events (tail 120):"; echo '```'; echo "$events"; echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

agentos_fail() {
  local where="$1"
  echo "FAIL: $where — capturing AgentOS rollout diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local wide desc pods logs events
  wide="$(kubectl -n "$NS" get deploy/rel-agentos,pod -l app.kubernetes.io/name=agentos -o wide 2>&1 || true)"
  desc="$(kubectl -n "$NS" describe deploy/rel-agentos 2>&1 || true)"
  pods="$(kubectl -n "$NS" describe pod -l app.kubernetes.io/name=agentos 2>&1 || true)"
  logs="$(kubectl -n "$NS" logs -l app.kubernetes.io/name=agentos --all-containers=true --tail=220 --prefix 2>&1 || true)"
  events="$(kubectl -n "$NS" get events --sort-by=.lastTimestamp 2>&1 | tail -160 || true)"
  {
    echo ""
    echo "## Proof M4 — AgentOS rollout FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- rel-agentos deploy/pods (-o wide):"; echo '```'; echo "$wide"; echo '```'
    echo "- rel-agentos deployment describe:"; echo '```'; echo "$desc"; echo '```'
    echo "- rel-agentos pod describe:"; echo '```'; echo "$pods"; echo '```'
    echo "- rel-agentos logs (tail 220):"; echo '```'; echo "$logs"; echo '```'
    echo "- namespace events (tail 160):"; echo '```'; echo "$events"; echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

cleanup() {
  pf_stop
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  # remove the transient build-context copies (NOT the sources)
  rm -rf "$STAGING_DST" "$PROOF_APP_DST" "$AGENTOS_SRC_DST" "$PROOF_DIR/_local_as.py" 2>/dev/null || true
}
trap cleanup EXIT

# --- 1. preflight ---------------------------------------------------------------
echo "==> [1/10] tool preflight"
for tool in docker kind kubectl helm uv cosign syft grype curl python3 gh; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool '$tool' not on PATH"
done

# --- 2. stage the RELEASED pack (download v0.1.0 + sha256-verify + arrange) ------
echo "==> [2/10] stage the released cognic-tool-oracle-schema@v0.1.0 (download, not build)"
rm -rf "$STAGING_DST"
uv run python -m tests.integration.proof_m4.stage_released_pack "$STAGING_DST"

# --- 3. build the four images ---------------------------------------------------
if [[ "${COGNIC_PROOF_M4_REUSE_IMAGES:-0}" == "1" ]]; then
  echo "==> [3/10] reuse existing proof images (COGNIC_PROOF_M4_REUSE_IMAGES=1)"
  require_cached_image "$MCP_IMAGE"
  require_cached_image "$AS_IMAGE"
  if [[ "${COGNIC_PROOF_M4_REBUILD_AGENTOS:-0}" == "1" ]]; then
    echo "==> [3/10] rebuild AgentOS proof image from the cached base plus current source"
    require_cached_image "$BASE_IMAGE"
    rm -rf "$PROOF_APP_DST"
    cp -r "$PROOF_APP_SRC" "$PROOF_APP_DST"
    rm -rf "$AGENTOS_SRC_DST"
    cp -r "$AGENTOS_SRC_SRC" "$AGENTOS_SRC_DST"
    docker_build_with_retry -f "$PROOF_DIR/Dockerfile.agentos-proof" --build-arg BASE_IMAGE="$BASE_IMAGE" -t "$IMAGE" "$PROOF_DIR"
  else
    require_cached_image "$BASE_IMAGE"
    require_cached_image "$IMAGE"
  fi
else
  echo "==> [3/10] build the default-adapters base image"
  docker_build_with_retry -f infra/agentos/Dockerfile --target default-adapters -t "$BASE_IMAGE" .

  echo "==> [3/10] copy the proof_m4 app into the proof build context"
  rm -rf "$PROOF_APP_DST"
  cp -r "$PROOF_APP_SRC" "$PROOF_APP_DST"
  rm -rf "$AGENTOS_SRC_DST"
  cp -r "$AGENTOS_SRC_SRC" "$AGENTOS_SRC_DST"

  echo "==> [3/10] build the proof AgentOS image (create_proof_app multi-actor + released trust staging baked in)"
  docker_build_with_retry -f "$PROOF_DIR/Dockerfile.agentos-proof" --build-arg BASE_IMAGE="$BASE_IMAGE" -t "$IMAGE" "$PROOF_DIR"

  echo "==> [3/10] build the released oracle-pack MCP tool Service image"
  # Context = $PROOF_DIR: Dockerfile.oracle-pack reads the released wheel from
  # proof-m4-staging/wheel/ (staged under $PROOF_DIR in step 2).
  docker_build_with_retry -f "$PROOF_DIR/Dockerfile.oracle-pack" -t "$MCP_IMAGE" "$PROOF_DIR"

  echo "==> [3/10] build the emulated-external AS image (RS256 mode)"
  # Vendor the single AS fixture into the proof build context (.dockerignore excludes tests/
  # from the repo-root context). Mirrors the agentos-proof + oracle-pack copy-into-context
  # pattern; cleanup() removes the copy.
  cp tests/integration/pack_loop/_local_as.py "$PROOF_DIR/_local_as.py"
  docker_build_with_retry -f "$PROOF_DIR/Dockerfile.as" -t "$AS_IMAGE" "$PROOF_DIR"
fi

# --- 4. kind create + load (3 proof images + backends + oracle-xe + busybox) -----
echo "==> [4/10] pre-pull the backend + extra images (host docker cache)"
while IFS= read -r _img; do
  [ -n "$_img" ] || continue
  echo "  docker pull $_img"
  docker_pull_with_retry "$_img"
done < <(_backend_images; _extra_images)

echo "==> [4/10] create kind cluster + load the 3 proof images"
kind create cluster --name "$CLUSTER"
kind load docker-image "$IMAGE" "$MCP_IMAGE" "$AS_IMAGE" --name "$CLUSTER"

echo "==> [4/10] kind load the pre-pulled backend + extra images into the node"
while IFS= read -r _img; do
  [ -n "$_img" ] || continue
  echo "  kind load $_img"
  kind load docker-image "$_img" --name "$CLUSTER"
done < <(_backend_images; _extra_images)

# --- 5. namespace + the six real backends, THEN the in-cluster Oracle XE ----------
# Sequenced startup (proof-1b-2c attempt-4 finding): the qemu-emulated gvenzl XE boot
# saturates the node CPU; overlapping it with backend startup starves even lightweight
# backends past the 300s wait. Sequenced, the backends come up uncontended, then XE boots
# while they sit idle on a dedicated 1200s budget.
echo "==> [5/10] bring up the six backends, then the seeded Oracle XE"
kubectl create namespace "$NS"
kubectl -n "$NS" apply -f "$CHART/ci/smoke/backends.yaml"
kubectl -n "$NS" wait --for=condition=available --timeout=300s deploy -l 'app notin (oracle-xe)' \
  || backends_fail "six shared backends not Available within 300s before XE start"
kubectl -n "$NS" create configmap oracle-xe-seed \
  --from-file=seed_schema.sql="$PROOF_DIR/oracle-seed/seed_schema.sql" \
  --dry-run=client -o yaml | kubectl apply -n "$NS" -f -
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-xe.yaml"
kubectl -n "$NS" wait --for=condition=ready pod -l app=oracle-xe --timeout=1200s \
  || xe_fail "oracle-xe pod not Ready within 1200s (qemu-emulated XE first boot under kind)"

# --- 6. Vault init/seed (KV v1 + OAuth + AS-allowlist) --------------------------
# Must run after Vault is up and before AgentOS reads it. KEPT from proof-1b-2c (ADR-026
# D5 — the OAuth material is provisioned BY REFERENCE; `configure` records the Vault paths,
# `install`'s materializer validates they resolve).
echo "==> [6/10] seed Vault (KV v1 conversion + OAuth + AS allow-list — by reference, D5)"
NS="$NS" bash "$PROOF_DIR/seed-vault.sh"

# --- 7. helm install (prod profile; migrations OFF — Gap 3) ---------------------
echo "==> [7/10] install the AgentOS chart under the proof-m4 overlay"
helm install rel "$CHART" -n "$NS" -f "$PROOF_DIR/proof-m4-values.yaml"

# --- 8. migrate Job + apply the oracle-pack/AS manifests ------------------------
echo "==> [8/10] run the proof-owned (non-hook) migration Job"
kubectl -n "$NS" delete job/agentos-migrate --ignore-not-found=true --wait=true
sed "s|__AGENTOS_IMAGE__|$IMAGE|" "$PROOF_DIR/migrate-job.yaml" | kubectl apply -n "$NS" -f -
kubectl -n "$NS" wait --for=condition=complete job/agentos-migrate --timeout=300s \
  || migrate_fail "agentos-migrate did not complete within 300s"

echo "==> [8/10] apply the oracle-pack MCP tool Service + AS manifests; wait Ready"
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-pack.yaml" -f "$PROOF_DIR/manifests/auth-server.yaml"
kubectl -n "$NS" rollout status deploy/proof-oracle-pack --timeout=180s
kubectl -n "$NS" rollout status deploy/proof-as --timeout=180s

# --- 9. DB seed (NO override/allow-list INSERT — install materializes them, M4) --
# CALLS the seed script; the runner NEVER inlines the override/allow-list INSERTs. Under
# M4 the derived rows are MATERIALIZED by `install`, so seed-db.sh is a no-op guard.
echo "==> [9/10] seed-db.sh (M4: NO derived-row INSERT — install materializes them)"
NS="$NS" bash "$PROOF_DIR/seed-db.sh"

# --- 10. roll to a cold pod + port-forward --------------------------------------
echo "==> [10/10] roll the Deployment so fresh pods boot against the migrated DB"
roll_and_wait
pf_start

# ================================ BAR 1 (happy) ================================
# Drive the FULL governed operator lifecycle via the REAL API, multi-actor via the
# X-Proof-Role header. Each step asserts the expected HTTP status.
echo "==> BAR 1 — governed operator lifecycle: submit -> claim -> approve -> allow-list -> configure -> install"

# The manifest the author submits (matches the released oracle pack). Its
# sha256(canonical_bytes(manifest)) MUST equal the draft's manifest_digest, and
# manifest.pack.kind MUST equal the draft kind ("tool"). manifest[supply_chain].
# attestation_paths + the submit signed_artefact_root drive the approve signature gate
# against the staged /opt/cognic/pack-attestations tree.
#
# Compute the manifest + its canonical digest with the KERNEL's canonical_bytes so the
# submit cheap-pre-check (sha256(canonical_bytes(manifest)) == manifest_digest) passes —
# the digest stays byte-coupled to the submitted bytes.
MANIFEST_JSON="$(uv run python - "$PACK_ID" "$PACK_WHEEL" <<'PY'
import json, sys
pack_id, wheel = sys.argv[1], sys.argv[2]
manifest = {
    "pack": {"kind": "tool", "name": pack_id, "version": "0.1.0"},
    "identity": {
        "agent_id": pack_id,
        "display_name": "Cognic Oracle Schema (proof-m4)",
        "provider_organization": "Cognic",
        "provider_url": "https://cognic.example",
    },
    "mcp": {"server_url": "http://10.96.0.51:8765/mcp", "scopes": ["oracle_schema.read"]},
    "risk_tier": {"tier": "read_only"},
    "supply_chain": {
        "attestation_paths": [
            "cosign.sig",
            "bundle.sigstore",
            "sbom.cdx.json",
            "slsa-provenance.intoto.json",
            "intoto-layout.json",
            "vuln-scan.json",
            "license-audit.json",
        ],
        "blob_path": wheel,
    },
}
print(json.dumps(manifest))
PY
)"
MANIFEST_DIGEST="$(uv run python - <<PY
from cognic_agentos.core.canonical import canonical_bytes
import hashlib, json
m = json.loads('''$MANIFEST_JSON''')
print(hashlib.sha256(canonical_bytes(m)).hexdigest())
PY
)"
# The signed_artefact_digest is a separate 32-byte hex field on the draft record (not
# gate-checked by approve; a well-formed lowercase-hex value satisfies the DTO validator).
SIGNED_DIGEST="$(printf '%064x' 1)"

# BAR 1.1 — create the draft (author). Body carries the distribution pack_id + kind +
# the two hex digests; the actor's tenant is bound from the header role (NOT the body).
echo "==> BAR 1.1 — create draft (author)"
CREATE_BODY="$(python3 - "$PACK_ID" "$MANIFEST_DIGEST" "$SIGNED_DIGEST" <<'PY'
import json, sys
pack_id, md, sd = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({
    "kind": "tool",
    "pack_id": pack_id,
    "display_name": "Cognic Oracle Schema (proof-m4)",
    "manifest_digest": md,
    "signed_artefact_digest": sd,
}))
PY
)"
CREATE_RESP="$(api author POST /api/v1/packs/drafts "$CREATE_BODY")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "201" ] || bar_fail "BAR 1.1 create_draft (HTTP $HTTP_CODE)"
PACK_UUID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$CREATE_RESP")"
[ -n "$PACK_UUID" ] || bar_fail "BAR 1.1 create_draft did not return a pack id"
echo "  draft created: pack_uuid=$PACK_UUID"

# BAR 1.2 — submit the draft (author). manifest + signed_artefact_root (the staged
# attestation dir on the approve-time host = the pod's /opt/cognic/pack-attestations/<id>/<ver>).
echo "==> BAR 1.2 — submit draft (author)"
SIGNED_ARTEFACT_ROOT="/opt/cognic/pack-attestations/$PACK_ID/0.1.0"
SUBMIT_BODY="$(python3 - "$SIGNED_ARTEFACT_ROOT" <<PY
import json, sys
root = sys.argv[1]
manifest = json.loads('''$MANIFEST_JSON''')
print(json.dumps({"manifest": manifest, "signed_artefact_root": root}))
PY
)"
api author POST "/api/v1/packs/drafts/$PACK_UUID/submit" "$SUBMIT_BODY" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1.2 submit (HTTP $HTTP_CODE)"

# BAR 1.3 — claim (reviewer; DISTINCT subject from author -> role-separation passes).
echo "==> BAR 1.3 — claim (reviewer)"
api reviewer POST "/api/v1/packs/$PACK_UUID/claim" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1.3 claim (HTTP $HTTP_CODE)"

# BAR 1.4 — approve (reviewer). 5-gate composition: SIGNATURE is genuinely GREEN (the
# proof app's TrustGate cosign-verifies the released, signed pack against the staged
# _default trust root); the FOUR non-signature gates (evaluation / adversarial / owasp /
# reviewer-ack) are OVERRIDDEN via override_reason. The reviewer role holds
# pack.override.approval_gate (the override scope is checked on the SAME actor that hits
# the reviewer-scoped /approve endpoint). Signature is NON-overridable (ADR-012 §110), so
# the override cannot manufacture a green signature — it only skips the four gates whose
# evidence this proof does not attach. PROOF-ONLY (a real reviewer attaches genuine
# evaluation / adversarial evidence).
echo "==> BAR 1.4 — approve (reviewer; signature REAL-green, 4 non-signature gates overridden)"
APPROVE_BODY="$(python3 - <<'PY'
import json
print(json.dumps({
    "acknowledgement": {
        "data_governance_acknowledged": True,
        "risk_tier_acknowledged": True,
        "supply_chain_acknowledged": True,
        "conformance_acknowledged": True,
    },
    "override_reason": "prerelease_validation",
}))
PY
)"
APPROVE_RESP="$(api reviewer POST "/api/v1/packs/$PACK_UUID/approve" "$APPROVE_BODY")"
load_http_code # after api command substitution
# 200 = approved (all-green OR override-granted). A 412 with a NON-signature red gate that
# was NOT overridden is a proof bug; a 412 with the SIGNATURE gate red means the real
# cosign verification failed (a genuine finding — capture + fail, never redefine down).
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1.4 approve (HTTP $HTTP_CODE; body: $APPROVE_RESP)"

# BAR 1.5 — allow-list (operator; human-actor gate + pack.allow_list).
echo "==> BAR 1.5 — allow-list (operator, human-actor)"
api operator POST "/api/v1/packs/$PACK_UUID/allow-list" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1.5 allow-list (HTTP $HTTP_CODE)"

# BAR 1.6 — configure (operator; human-actor gate + pack.configure). Writes the DESIRED
# runtime-config record: server_url_override = the in-cluster MCP ClusterIP /mcp; the
# internal_host_allowlist IP; the OAuth + AS Vault refs (the seed-vault.sh paths). install
# will MATERIALIZE these into the derived carve-out tables.
echo "==> BAR 1.6 — configure (operator; writes the desired runtime-config record)"
CONFIGURE_BODY="$(python3 - "$TENANT" <<'PY'
import json, sys
tenant = sys.argv[1]
# ashost is the AS issuer host_port key seed-vault.sh used: 192.88.99.9_9000.
print(json.dumps({
    "server_url_override": "http://10.96.0.51:8765/mcp",
    "internal_host_allowlist": ["10.96.0.51"],
    "oauth_credential_ref": f"secret/cognic/{tenant}/mcp-oauth/192.88.99.9_9000",
    "as_allowlist_ref": f"secret/cognic/{tenant}/mcp-as-allowlist",
}))
PY
)"
api operator PUT "/api/v1/packs/$PACK_UUID/runtime-config" "$CONFIGURE_BODY" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1.6 configure (HTTP $HTTP_CODE)"

# BAR 1.7 — install (operator; pack.install). The 5-gate install saga: lifecycle valid +
# boot-registered (gate 2, from app.state.plugin_registry) + runtime-config complete
# (gate 3) + materialize (gate 4 validates the Vault refs, then projects the derived
# override + allow-list rows) + set activation_status=active.
echo "==> BAR 1.7 — install (operator; materializes the derived carve-out rows)"
INSTALL_RESP="$(api operator POST "/api/v1/packs/$PACK_UUID/install")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1.7 install (HTTP $HTTP_CODE; body: $INSTALL_RESP)"

# BAR 1.8 — assert the derived rows were MATERIALIZED (via the decision_history events
# mcp.override.set + mcp.allowlist.add the materializer's store mutators emit). This is
# the M4 governance proof: the carve-out rows exist ONLY because install materialized
# them from the configured record — never seeded directly.
echo "==> BAR 1.8 — assert materialization (decision_history: mcp.override.set + mcp.allowlist.add)"
MAT="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
  -c "SELECT event_type FROM decision_history WHERE event_type IN ('mcp.override.set','mcp.allowlist.add');")"
DERIVED_ROWS="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
  -c "SELECT 'override|' || tenant_id || '|' || pack_id || '|' || server_url_override FROM mcp_server_url_override UNION ALL SELECT 'allowlist|' || tenant_id || '|' || ip || '|' || set_by_actor FROM mcp_internal_host_allowlist ORDER BY 1;")"
grep -qF "mcp.override.set" <<<"$MAT" \
  || bar_fail "BAR 1.8 no mcp.override.set materialization event (got: ${MAT:-<none>})"
grep -qF "mcp.allowlist.add" <<<"$MAT" \
  || bar_fail "BAR 1.8 no mcp.allowlist.add materialization event (got: ${MAT:-<none>})"
grep -qF "override|$TENANT|$PACK_ID|http://10.96.0.51:8765/mcp" <<<"$DERIVED_ROWS" \
  || bar_fail "BAR 1.8 no derived override row (got: ${DERIVED_ROWS:-<none>})"
grep -qF "allowlist|$TENANT|10.96.0.51|proof-m4-operator" <<<"$DERIVED_ROWS" \
  || bar_fail "BAR 1.8 no derived allow-list row (got: ${DERIVED_ROWS:-<none>})"
echo "  Bar 1.8 OK: override + allow-list rows materialized by install (not seeded)"

# BAR 1.9 — roll cold so the next MCP probe sees the materialized carve-out rows.
# discovery_status is observational: MCPHost records it when list_tools/call_tool runs,
# not at startup.
echo "==> BAR 1.9 — roll cold so the next MCP probe sees the materialized carve-outs"
roll_and_wait
pf_start
echo "  Bar 1.9 OK: cold pod ready"

# BAR 1.10 — the governed call: list_tools + call_tool(describe_table) returns FULL_NAME
# and records discovery_status=auth_ready.
echo "==> BAR 1.10 — governed loop: list_tools + call_tool(describe_table) -> FULL_NAME + auth_ready"
api mcp GET "/api/v1/mcp/servers/$PACK_ID/tools" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1.10 list_tools (HTTP $HTTP_CODE)"
CALL_RESP="$(api mcp POST "/api/v1/mcp/servers/$PACK_ID/tools/call" \
  '{"tool_name":"describe_table","arguments":{"owner":"COGNIC","table":"EMPLOYEES"}}')"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1.10 call_tool (HTTP $HTTP_CODE)"
grep -qF "FULL_NAME" <<<"$CALL_RESP" \
  || bar_fail "BAR 1.10 call_tool_content (no EMPLOYEES column metadata: $CALL_RESP)"
DS="$(discovery_status)"
[ "$DS" = "auth_ready" ] || bar_fail "BAR 1.10 discovery_status=$DS (expected auth_ready)"
echo "PROOF M4 (BAR 1) PASS"

# ================================ BAR 2 (negatives) ============================
# Each install-refused negative uses a SEPARATE fresh draft advanced to exactly the
# from-state that trips one gate, then asserts the closed-enum InstallRefusalReason. The
# approve-signature-red negative proves the 5-gate signature stays REAL.
echo "==> BAR 2 — negatives (install gate refusals + approve signature-red)"

# Helper: create+submit a fresh draft, return its pack_uuid. (Author role.)
_fresh_submitted_pack() {
  local suffix="$1"
  local body resp uuid
  # Reuse the same manifest/digest (the distribution pack_id is shared across drafts;
  # gate 2 keys on the distribution name, which is boot-registered once).
  body="$(python3 - "$PACK_ID" "$MANIFEST_DIGEST" "$SIGNED_DIGEST" <<'PY'
import json, sys
pack_id, md, sd = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({"kind":"tool","pack_id":pack_id,
  "display_name":"proof-m4 negative","manifest_digest":md,"signed_artefact_digest":sd}))
PY
)"
  resp="$(api author POST /api/v1/packs/drafts "$body")"
  load_http_code # after api command substitution
  [ "$HTTP_CODE" = "201" ] || return 1
  uuid="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$resp")"
  local sroot="/opt/cognic/pack-attestations/$PACK_ID/0.1.0"
  local sbody
  sbody="$(python3 - "$sroot" <<PY
import json,sys
print(json.dumps({"manifest": json.loads('''$MANIFEST_JSON'''), "signed_artefact_root": sys.argv[1]}))
PY
)"
  api author POST "/api/v1/packs/drafts/$uuid/submit" "$sbody" >/dev/null
  [ "$HTTP_CODE" = "200" ] || return 1
  echo "$uuid"
}

# Assert an install call refuses with a specific closed-enum reason + status.
_assert_install_refused() {
  local uuid="$1" want_status="$2" want_reason="$3" label="$4"
  local resp got_reason
  resp="$(api operator POST "/api/v1/packs/$uuid/install")"
  load_http_code # after api command substitution
  [ "$HTTP_CODE" = "$want_status" ] \
    || bar_fail "BAR 2 $label — install status $HTTP_CODE (expected $want_status; body: $resp)"
  got_reason="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("detail",{}).get("reason",""))' <<<"$resp" 2>/dev/null || true)"
  [ "$got_reason" = "$want_reason" ] \
    || bar_fail "BAR 2 $label — reason '$got_reason' (expected '$want_reason'; body: $resp)"
  echo "  Bar 2 OK: $label -> HTTP $want_status $want_reason"
}

# BAR 2.1 — install refused when NOT approved (still submitted/under_review): gate 1
# lifecycle dry-run refuses (install requires allow_listed/disabled) -> 409
# lifecycle_transition_invalid_state_pair.
echo "==> BAR 2.1 — install refused: not approved/allow-listed (lifecycle gate 1)"
NEG1="$(_fresh_submitted_pack neg1)" || bar_fail "BAR 2.1 setup"
_assert_install_refused "$NEG1" 409 "lifecycle_transition_invalid_state_pair" "not-allow-listed"

# BAR 2.2 — install refused when NOT configured: advance a fresh pack to allow_listed
# (approve + allow-list) but SKIP configure -> gate 3 install_runtime_config_missing.
echo "==> BAR 2.2 — install refused: not configured (gate 3)"
NEG2="$(_fresh_submitted_pack neg2)" || bar_fail "BAR 2.2 setup"
api reviewer POST "/api/v1/packs/$NEG2/claim" >/dev/null; [ "$HTTP_CODE" = "200" ] || bar_fail "BAR 2.2 claim"
api reviewer POST "/api/v1/packs/$NEG2/approve" "$APPROVE_BODY" >/dev/null; [ "$HTTP_CODE" = "200" ] || bar_fail "BAR 2.2 approve"
api operator POST "/api/v1/packs/$NEG2/allow-list" >/dev/null; [ "$HTTP_CODE" = "200" ] || bar_fail "BAR 2.2 allow-list"
_assert_install_refused "$NEG2" 409 "install_runtime_config_missing" "not-configured"

# BAR 2.3 — install refused when the Vault OAuth ref is absent: configure with a
# NON-EXISTENT oauth_credential_ref (points at an unseeded Vault path) -> gate 4
# materialize refuses -> 409 install_runtime_config_vault_ref_unresolved.
echo "==> BAR 2.3 — install refused: Vault OAuth ref absent (gate 4 materialize)"
NEG3="$(_fresh_submitted_pack neg3)" || bar_fail "BAR 2.3 setup"
api reviewer POST "/api/v1/packs/$NEG3/claim" >/dev/null; [ "$HTTP_CODE" = "200" ] || bar_fail "BAR 2.3 claim"
api reviewer POST "/api/v1/packs/$NEG3/approve" "$APPROVE_BODY" >/dev/null; [ "$HTTP_CODE" = "200" ] || bar_fail "BAR 2.3 approve"
api operator POST "/api/v1/packs/$NEG3/allow-list" >/dev/null; [ "$HTTP_CODE" = "200" ] || bar_fail "BAR 2.3 allow-list"
NEG3_CFG="$(python3 - "$TENANT" <<'PY'
import json, sys
tenant = sys.argv[1]
print(json.dumps({
    "server_url_override": "http://10.96.0.51:8765/mcp",
    "internal_host_allowlist": ["10.96.0.51"],
    "oauth_credential_ref": f"secret/cognic/{tenant}/mcp-oauth/DOES-NOT-EXIST_0000",
    "as_allowlist_ref": f"secret/cognic/{tenant}/mcp-as-allowlist",
}))
PY
)"
api operator PUT "/api/v1/packs/$NEG3/runtime-config" "$NEG3_CFG" >/dev/null; [ "$HTTP_CODE" = "200" ] || bar_fail "BAR 2.3 configure"
_assert_install_refused "$NEG3" 409 "install_runtime_config_vault_ref_unresolved" "vault-oauth-absent"

# BAR 2.4 — approve refused on a SIGNATURE-RED pack (the 5-gate signature stays REAL).
# Submit a fresh draft whose signed_artefact_root points at a directory with NO staged
# attestations, so the approve signature gate's cosign verification fails -> the signature
# gate is red + NON-OVERRIDABLE -> 412 even WITH override_reason supplied.
echo "==> BAR 2.4 — approve refused on signature-red pack (signature non-overridable)"
NEG4_BODY="$(python3 - "$PACK_ID" "$MANIFEST_DIGEST" "$SIGNED_DIGEST" <<'PY'
import json, sys
pack_id, md, sd = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({"kind":"tool","pack_id":pack_id,
  "display_name":"proof-m4 sig-red","manifest_digest":md,"signed_artefact_digest":sd}))
PY
)"
NEG4_RESP="$(api author POST /api/v1/packs/drafts "$NEG4_BODY")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "201" ] || bar_fail "BAR 2.4 create"
NEG4="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$NEG4_RESP")"
# signed_artefact_root points at a dir with NO staged attestation files -> cosign fails.
NEG4_SUBMIT="$(python3 - <<PY
import json
print(json.dumps({"manifest": json.loads('''$MANIFEST_JSON'''),
                  "signed_artefact_root": "/opt/cognic/pack-attestations/NO-SUCH-PACK/9.9.9"}))
PY
)"
api author POST "/api/v1/packs/drafts/$NEG4/submit" "$NEG4_SUBMIT" >/dev/null; [ "$HTTP_CODE" = "200" ] || bar_fail "BAR 2.4 submit"
api reviewer POST "/api/v1/packs/$NEG4/claim" >/dev/null; [ "$HTTP_CODE" = "200" ] || bar_fail "BAR 2.4 claim"
# Approve WITH override_reason — signature is non-overridable, so a red signature still 412s.
NEG4_APPROVE="$(api reviewer POST "/api/v1/packs/$NEG4/approve" "$APPROVE_BODY")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "412" ] || bar_fail "BAR 2.4 approve expected 412 on signature-red (HTTP $HTTP_CODE; body: $NEG4_APPROVE)"
grep -qE "signature" <<<"$NEG4_APPROVE" \
  || bar_fail "BAR 2.4 approve 412 body did not reference the signature gate (body: $NEG4_APPROVE)"
echo "  Bar 2.4 OK: signature-red pack refused approve 412 (signature stays REAL, non-overridable)"
echo "PROOF M4 (BAR 2) PASS"

# ================================ BAR 3 (disable/revoke) =======================
# Operate on the BAR-1 installed pack ($PACK_UUID). disable -> refused; re-install ->
# callable again; revoke -> refused + terminal.
echo "==> BAR 3 — disable -> refused; re-install -> restored; revoke -> refused+terminal"

# BAR 3.1 — disable (operator). Retracts the derived rows; the next cold probe refuses.
echo "==> BAR 3.1 — disable (operator; retract) -> discovery_status=refused"
api operator POST "/api/v1/packs/$PACK_UUID/disable" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 3.1 disable (HTTP $HTTP_CODE)"
roll_and_wait
pf_start
DISABLED_PROBE="$(api mcp GET "/api/v1/mcp/servers/$PACK_ID/tools")"
load_http_code # after api command substitution
[ "$HTTP_CODE" != "200" ] \
  || bar_fail "BAR 3.1 list_tools unexpectedly succeeded after disable (body: $DISABLED_PROBE)"
DS="$(discovery_status)"
[ "$DS" = "refused" ] || bar_fail "BAR 3.1 discovery_status=$DS (expected refused after disable)"
echo "  Bar 3.1 OK: disable retracted the carve-out rows -> discovery_status=refused"

# BAR 3.2 — re-install from disabled (the disabled->installed re-enable, Task 5).
# Re-materializes -> callable again.
echo "==> BAR 3.2 — re-install (disabled->installed re-enable) -> auth_ready + call_tool"
INSTALL2="$(api operator POST "/api/v1/packs/$PACK_UUID/install")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 3.2 re-install (HTTP $HTTP_CODE; body: $INSTALL2)"
roll_and_wait
pf_start
CALL2="$(api mcp POST "/api/v1/mcp/servers/$PACK_ID/tools/call" \
  '{"tool_name":"describe_table","arguments":{"owner":"COGNIC","table":"EMPLOYEES"}}')"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 3.2 call_tool after re-install (HTTP $HTTP_CODE)"
grep -qF "FULL_NAME" <<<"$CALL2" || bar_fail "BAR 3.2 call_tool after re-install lacked FULL_NAME (body: $CALL2)"
DS="$(discovery_status)"
[ "$DS" = "auth_ready" ] || bar_fail "BAR 3.2 discovery_status=$DS (expected auth_ready after re-install)"
echo "  Bar 3.2 OK: re-install restored callability (auth_ready + call_tool)"

# BAR 3.3 — revoke (operator). Retracts + terminal; the next cold probe refuses.
echo "==> BAR 3.3 — revoke (operator; retract + terminal) -> refused"
api operator POST "/api/v1/packs/$PACK_UUID/revoke" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 3.3 revoke (HTTP $HTTP_CODE)"
roll_and_wait
pf_start
REVOKED_PROBE="$(api mcp GET "/api/v1/mcp/servers/$PACK_ID/tools")"
load_http_code # after api command substitution
[ "$HTTP_CODE" != "200" ] \
  || bar_fail "BAR 3.3 list_tools unexpectedly succeeded after revoke (body: $REVOKED_PROBE)"
DS="$(discovery_status)"
[ "$DS" = "refused" ] || bar_fail "BAR 3.3 discovery_status=$DS (expected refused after revoke)"
# revoked is terminal — re-install must refuse (no revoked->installed).
REVOKED_INSTALL="$(api operator POST "/api/v1/packs/$PACK_UUID/install")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "409" ] || bar_fail "BAR 3.3 install-after-revoke expected 409 terminal (HTTP $HTTP_CODE; body: $REVOKED_INSTALL)"
echo "  Bar 3.3 OK: revoke -> discovery_status=refused + install-after-revoke 409 (terminal)"
echo "PROOF M4 (BAR 3) PASS"

echo "PROOF M4 (ALL BARS) PASS"
