#!/usr/bin/env bash
# Proof M5 (real hook pack — deployed DLP pre-invocation gate) — the deployed proof
# that a RELEASED, signed HOOK pack's dlp_pre hooks govern MCP tool invocation
# through the kernel's ADR-017 DLP gate, against the deployed kernel + TWO released,
# signed packs (released assets only — neither is built from source here):
#   * cognic-tool-oracle-schema@v0.2.0 — the DLP-governed re-release (its
#     [data_governance].dlp_pre_hooks binds the two schema-guard hooks); operator-
#     installed via the M4-proven governed flow (submit -> claim -> approve ->
#     allow-list -> configure -> install; install MATERIALIZES the derived MCP
#     carve-out rows — seed-db.sh stays a no-op guard).
#   * cognic-hook-schema-guard@v0.1.0 — the signed hook pack (two arg-gated,
#     deterministic, no-LLM dlp_pre hooks). Baked into the KERNEL image + trust-
#     registered at boot ONLY (spec §6 decision B) — NEVER operator-installed; its
#     per-pack cosign key is staged at trust-roots/hook-packs/<pack_id>/cosign.pub
#     and resolved by the kernel boot loop (registry_boot, ADR-002 hooks amendment).
#
# It EXTENDS the proven Proof M4 runner: same multi-actor proof app (X-Proof-Role
# binder, now proof_m5), same in-cluster Oracle XE + RS256/JWKS AS, same single
# effective MCP URL (10.96.0.51:8765/mcp), same governed operator-install flow for
# the tool. The DELTA is the THREE DLP BARS — all three call the SAME deployed
# v0.2.0 tool through the governed MCP route with the ARGUMENT as the only variable:
#   * BAR 1 (permitted)  — table=EMPLOYEES -> the hook fires + ALLOWS -> the tool
#     executes -> 200 + FULL_NAME.
#   * BAR 2 (forbidden)  — table=__FORBIDDEN__ -> refuse_forbidden_schema_arg
#     policy-refuses -> 403 dlp_pre_refused + policy_reason=forbidden_schema_arg,
#     REFUSED BEFORE THE TOOL (no new audit.tool_invocation success row) and the
#     evidence is DIGEST-ONLY (the forbidden literal appears in NO audit_event /
#     decision_history row; dlp_policy_input_digest is the correlator).
#   * BAR 3 (explode)    — table=__EXPLODE__ -> the first hook passes,
#     explode_schema_guard raises -> dlp_dispatcher_failed -> 409 dlp_pre_failed
#     (fail-closed: a broken hook is a refusal, never a silent bypass).
#
# Operator-run + env-gated (COGNIC_RUN_PROOF_M5=1); NO default-on CI job (needs an
# image build + kind + a live Vault/Postgres + an in-cluster Oracle XE).
#
# On any BAR failure the runner captures logs + HTTP status + the refusal reason to
# docs/VALIDATION-RESULTS.md and exits non-zero — the proof is NEVER redefined
# downward. On all-pass it prints "PROOF M5 (ALL BARS) PASS" and exits 0.
set -euo pipefail

if [[ "${COGNIC_RUN_PROOF_M5:-}" != "1" ]]; then
  echo "skipped: set COGNIC_RUN_PROOF_M5=1 to run the hook-pack DLP proof" >&2
  exit 0
fi

CLUSTER="${KIND_CLUSTER:-cognic-proofm5}"
NS="cognic-proofm5"
CHART="infra/charts/agentos"
PROOF_DIR="infra/proof-m5"
STAGING_DST="$PROOF_DIR/proof-m5-staging"           # released-pack staging output (build context)
PROOF_APP_SRC="tests/integration/proof_m5"          # the proof-only multi-actor app factory
PROOF_APP_DST="$PROOF_DIR/proof_m5"                 # transient build-context copy
AGENTOS_SRC_SRC="src/cognic_agentos"                # current kernel source overlay (the M5 DLP wiring)
AGENTOS_SRC_DST="$PROOF_DIR/cognic_agentos"         # transient build-context copy
BASE_IMAGE="cognic-agentos:proof1b2-base"           # reused — same default-adapters base as proof-1b-2c/m4
IMAGE="cognic-agentos:proofm5"
MCP_IMAGE="cognic-proof-oracle-pack:m5"
AS_IMAGE="cognic-proof-as:m5"
TENANT="proof-m5"
PACK_ID="cognic-tool-oracle-schema"
HOOK_PACK_ID="cognic-hook-schema-guard"
PACK_WHEEL="cognic_tool_oracle_schema-0.2.0-py3-none-any.whl"
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
  if [[ "${COGNIC_PROOF_M5_REUSE_IMAGES:-0}" == "1" ]] && docker image inspect "$img" >/dev/null 2>&1; then
    echo "  using cached image $img (COGNIC_PROOF_M5_REUSE_IMAGES=1)"
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
    "COGNIC_PROOF_M5_REUSE_IMAGES=1 requested, but required image is absent: $img"
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
# Load-bearing after install: MCPHost caches BOTH the OAuth token and the list_tools
# result per tenant, so the materialized carve-out rows are only observable on a cold
# pod. (The DLP scan itself is per-call — BARs 2/3 need no roll after BAR 1.)
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
HTTP_CODE_FILE="/tmp/proofm5-code"
load_http_code() {
  HTTP_CODE="$(cat "$HTTP_CODE_FILE" 2>/dev/null || true)"
}

api() {
  local role="$1" method="$2" path="$3" body="${4:-}"
  local out
  if [ -n "$body" ]; then
    out="$(curl -s -o /tmp/proofm5-resp -w '%{http_code}' -X "$method" \
      -H "X-Proof-Role: $role" -H 'Content-Type: application/json' \
      -d "$body" "$BASE_URL$path")"
  else
    out="$(curl -s -o /tmp/proofm5-resp -w '%{http_code}' -X "$method" \
      -H "X-Proof-Role: $role" "$BASE_URL$path")"
  fi
  HTTP_CODE="$out"
  printf '%s' "$out" > "$HTTP_CODE_FILE"
  cat /tmp/proofm5-resp
}

# discovery_status of the TOOL pack row from GET /system/plugins?tenant_id=proof-m5.
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

# ---- DLP evidence helpers (the BAR 2/3 audit-chain reads) ----------------------------
# Count of SUCCESSFUL tool executions (audit.tool_invocation rows). The "did the tool
# run?" axis for the DLP bars: BAR 1 raises it; BARs 2/3 must leave it UNCHANGED —
# the dlp_pre refusal fires BEFORE token/session/transport work reaches the tool.
tool_invocation_count() {
  kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT count(*) FROM audit_event WHERE event_type='audit.tool_invocation';"
}

# The newest refusal evidence row (audit.tool_invocation_refused payload) — the DLP
# refusal rows carry refusal_reason + dlp_policy_input_digest + dlp_failed_hook_id.
latest_tool_refusal_payload() {
  kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT payload::text FROM audit_event WHERE event_type='audit.tool_invocation_refused' ORDER BY sequence DESC LIMIT 1;"
}

# Rows across BOTH evidence tables whose payload carries the given literal — the
# digest-only invariant probe (must be 0: the argument plaintext NEVER enters the
# chain; only dlp_policy_input_digest does). strpos, NOT LIKE — '_' is a LIKE
# single-char wildcard and both sentinel literals are underscore-heavy.
evidence_rows_containing_literal() {
  local literal="$1"
  kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT (SELECT count(*) FROM audit_event WHERE strpos(payload::text, '$literal') > 0) + (SELECT count(*) FROM decision_history WHERE strpos(payload::text, '$literal') > 0);"
}

# ---- Hook-pack registry-admission preflight ------------------------------------------
# The hook pack is TRUST-REGISTERED at boot ONLY (spec §6 decision B) — never
# operator-installed, so it has no lifecycle rows to probe. Its admission evidence is
# the boot registration: (a) the registered candidate row on GET /system/plugins
# (status=registered, kind=hooks — the cosign gate + per-tenant allow-list passed
# against the per-pack hook trust root), and (b) NO hook-admission / DLP-guard
# construction failure markers in the pod's boot logs (build_dlp_guard is per-pack
# fail-soft: a skipped hook pack would leave every hooked call 409ing). Registration
# is per-pod (boot-time), so the runner re-asserts on the pod that serves the bars.
assert_hook_pack_registered() {
  local where="$1" body hook_errs
  body="$(curl -sf "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
  [ -n "$body" ] || bar_fail "$where — /api/v1/system/plugins unreachable for the hook-pack probe"
  if ! python3 - "$HOOK_PACK_ID" "$body" <<'PY'
import json, sys
pack_id, raw = sys.argv[1], sys.argv[2]
try:
    doc = json.loads(raw)
except Exception:
    print("plugins response is not JSON", file=sys.stderr)
    raise SystemExit(1)
rows = [p for p in doc.get("plugins", []) if p.get("pack_id") == pack_id]
if not rows:
    print(f"hook pack {pack_id}: no registered candidate row", file=sys.stderr)
    raise SystemExit(1)
row = rows[0]
if row.get("status") != "registered" or row.get("kind") != "hooks":
    print(
        f"hook pack {pack_id}: status={row.get('status')!r} kind={row.get('kind')!r} "
        f"refusal_reason={row.get('refusal_reason')!r}",
        file=sys.stderr,
    )
    raise SystemExit(1)
print(
    f"  hook pack registry-admitted: {pack_id} kind=hooks status=registered "
    f"grade={row.get('attestation_grade')}"
)
PY
  then
    bar_fail "$where — hook pack not registry-admitted (trust-register-at-boot failed)"
  fi
  hook_errs="$(kubectl -n "$NS" logs deploy/rel-agentos 2>/dev/null \
    | grep -E 'hook\.(pack_manifest_malformed|block_malformed|distribution_not_found|declaration_no_entry_point|declaration_malformed|pack_malformed|registry_refused)|dlp_guard_construction_failed|hook_pack_trust_root_invalid' \
    || true)"
  [ -z "$hook_errs" ] \
    || bar_fail "$where — hook admission / DLP-guard failures in boot logs: $hook_errs"
}

# ---- Failure diagnostics (mirror proof-m4: capture then exit non-zero) ---------------
bar_fail() {
  local where="$1"
  echo "FAIL: $where — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local logs ds dh derived tool_audit hook_logs reason
  logs="$(kubectl -n "$NS" logs deploy/rel-agentos 2>&1 | tail -150 || true)"
  ds="$(curl -s "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
  dh="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT event_type, payload::text FROM decision_history WHERE event_type LIKE 'mcp%' OR event_type LIKE 'pack.lifecycle.%' ORDER BY sequence DESC LIMIT 20;" 2>/dev/null || true)"
  derived="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT 'override|' || tenant_id || '|' || pack_id || '|' || server_url_override FROM mcp_server_url_override UNION ALL SELECT 'allowlist|' || tenant_id || '|' || ip || '|' || set_by_actor FROM mcp_internal_host_allowlist ORDER BY 1;" 2>/dev/null || true)"
  tool_audit="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT event_type, payload::text FROM audit_event WHERE event_type LIKE 'audit.tool_invocation%' ORDER BY sequence DESC LIMIT 10;" 2>/dev/null || true)"
  hook_logs="$(grep -E 'hook\.|dlp' <<<"$logs" | tail -40 || true)"
  reason="$(grep -Eo 'install_[a-z_]+|mcp_[a-z_]*refused|dlp_[a-z_]+|hook_[a-z_]+|discovery_status=[a-z_]+|materialize_[a-z_]+' <<<"$logs" | sort -u || true)"
  {
    echo ""
    echo "## Proof M5 — FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- last API response (HTTP $HTTP_CODE):"
    echo '```json'
    cat /tmp/proofm5-resp 2>/dev/null || echo "<no response captured>"
    echo ""
    echo '```'
    echo "- refusal / DLP / hook reason markers:"
    echo '```'
    echo "${reason:-<none captured>}"
    echo '```'
    echo "- audit.tool_invocation* evidence rows (tail 10 — the DLP bars' axis):"
    echo '```'
    echo "${tool_audit:-<none>}"
    echo '```'
    echo "- hook/DLP pod-log markers (tail 40):"
    echo '```'
    echo "${hook_logs:-<none>}"
    echo '```'
    echo "- discovery_status snapshot (GET /api/v1/system/plugins?tenant_id=$TENANT):"
    echo '```json'
    echo "${ds:-<no response>}"
    echo '```'
    echo "- decision_history (mcp* / pack.lifecycle.* tail 20):"
    echo '```'
    echo "${dh:-<none>}"
    echo '```'
    echo "- derived MCP config rows (override + allow-list):"
    echo '```'
    echo "${derived:-<none>}"
    echo '```'
    echo "- AgentOS pod logs (tail 150):"
    echo '```'
    echo "$logs"
    echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

# Step-5 XE-readiness failure path (mirrors proof-m4 xe_fail).
xe_fail() {
  local where="$1"
  echo "FAIL: oracle-xe ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local pods desc logs
  pods="$(kubectl -n "$NS" get pods 2>&1 || true)"
  desc="$(kubectl -n "$NS" describe pod -l app=oracle-xe 2>&1 | tail -90 || true)"
  logs="$(kubectl -n "$NS" logs -l app=oracle-xe --tail=120 2>&1 || true)"
  {
    echo ""
    echo "## Proof M5 — Oracle XE readiness FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- pods:"; echo '```'; echo "$pods"; echo '```'
    echo "- oracle-xe describe (tail 90):"; echo '```'; echo "$desc"; echo '```'
    echo "- oracle-xe logs (tail 120):"; echo '```'; echo "$logs"; echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

# Step-5 backends-readiness failure path (mirrors proof-m4 backends_fail).
backends_fail() {
  local where="$1"
  echo "FAIL: backends ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local wide ddeploy dpods
  wide="$(kubectl -n "$NS" get deploy,pods -o wide 2>&1 || true)"
  ddeploy="$(kubectl -n "$NS" describe deploy -l 'app notin (oracle-xe)' 2>&1 | tail -120 || true)"
  dpods="$(kubectl -n "$NS" describe pod -l 'app notin (oracle-xe)' 2>&1 | tail -150 || true)"
  {
    echo ""
    echo "## Proof M5 — backends readiness FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
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
    echo "## Proof M5 — migration Job FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
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
    echo "## Proof M5 — AgentOS rollout FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
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

# --- 2. stage the TWO RELEASED packs (download + sha256-verify + arrange) --------
# M5 delta vs proof-m4: the staging contract lives in the proof-owned shell script
# stage-packs.sh (oracle v0.2.0 + the hook pack v0.1.0, two-key trust roots), not a
# python module. Download, not build.
echo "==> [2/10] stage the released packs via stage-packs.sh (download, not build)"
rm -rf "$STAGING_DST"
bash "$PROOF_DIR/stage-packs.sh" "$STAGING_DST"

# --- 3. build the four images ---------------------------------------------------
if [[ "${COGNIC_PROOF_M5_REUSE_IMAGES:-0}" == "1" ]]; then
  echo "==> [3/10] reuse existing proof images (COGNIC_PROOF_M5_REUSE_IMAGES=1)"
  require_cached_image "$MCP_IMAGE"
  require_cached_image "$AS_IMAGE"
  if [[ "${COGNIC_PROOF_M5_REBUILD_AGENTOS:-0}" == "1" ]]; then
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

  echo "==> [3/10] copy the proof_m5 app into the proof build context"
  rm -rf "$PROOF_APP_DST"
  cp -r "$PROOF_APP_SRC" "$PROOF_APP_DST"
  rm -rf "$AGENTOS_SRC_DST"
  cp -r "$AGENTOS_SRC_SRC" "$AGENTOS_SRC_DST"

  echo "==> [3/10] build the proof AgentOS image (create_proof_app multi-actor + BOTH released packs' trust staging baked in)"
  docker_build_with_retry -f "$PROOF_DIR/Dockerfile.agentos-proof" --build-arg BASE_IMAGE="$BASE_IMAGE" -t "$IMAGE" "$PROOF_DIR"

  echo "==> [3/10] build the released oracle-pack MCP tool Service image (v0.2.0)"
  # Context = $PROOF_DIR: Dockerfile.oracle-pack reads the released wheel from
  # proof-m5-staging/wheel/ (staged under $PROOF_DIR in step 2).
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
# Must run after Vault is up and before AgentOS reads it. KEPT from proof-m4 (ADR-026
# D5 — the OAuth material is provisioned BY REFERENCE; `configure` records the Vault
# paths, `install`'s materializer validates they resolve). The hook pack needs NO
# Vault material (hooks are in-process kernel code — no OAuth, no MCP endpoint).
echo "==> [6/10] seed Vault (KV v1 conversion + OAuth + AS allow-list — by reference, D5)"
NS="$NS" bash "$PROOF_DIR/seed-vault.sh"

# --- 7. helm install (prod profile; migrations OFF — Gap 3) ---------------------
echo "==> [7/10] install the AgentOS chart under the proof-m5 overlay"
helm install rel "$CHART" -n "$NS" -f "$PROOF_DIR/proof-m5-values.yaml"

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
# CALLS the seed script; the runner NEVER inlines the override/allow-list INSERTs.
# Inherited M4 governance property: the derived rows are MATERIALIZED by `install`,
# so seed-db.sh is a no-op guard. The hook pack needs no DB seeding at all.
echo "==> [9/10] seed-db.sh (M5: NO derived-row INSERT — install materializes them)"
NS="$NS" bash "$PROOF_DIR/seed-db.sh"

# --- 10. roll to a cold pod + port-forward --------------------------------------
echo "==> [10/10] roll the Deployment so fresh pods boot against the migrated DB"
roll_and_wait
pf_start

# ---- Hook-pack preflight (before the bars; fail fast before the lifecycle) ------
# spec §6 decision B: the hook pack takes the trust-register + registry-admit path
# ONLY. Assert the boot admitted it BEFORE driving the operator lifecycle.
echo "==> preflight — hook pack trust-registered + registry-admitted at boot"
assert_hook_pack_registered "hook-pack preflight (first boot)"

# ============================ SETUP (M4 governed install) ======================
# Operator-install the DLP-governed ORACLE tool v0.2.0 EXACTLY as proven in M4:
# the full governed lifecycle via the REAL API, multi-actor via X-Proof-Role. The
# HOOK pack deliberately takes NO part in this flow. Each step asserts the
# expected HTTP status; these are SETUP steps (the M5 bars are the three DLP
# calls below), but any failure still captures + exits non-zero.
echo "==> SETUP — governed operator lifecycle: submit -> claim -> approve -> allow-list -> configure -> install (oracle v0.2.0)"

# The manifest the author submits (matches the released v0.2.0 oracle pack, incl.
# the [data_governance] block whose dlp_pre_hooks bind the two schema-guard hooks —
# the M5 release delta). Its sha256(canonical_bytes(manifest)) MUST equal the
# draft's manifest_digest, and manifest.pack.kind MUST equal the draft kind
# ("tool"). manifest[supply_chain].attestation_paths + the submit
# signed_artefact_root drive the approve signature gate against the staged
# /opt/cognic/pack-attestations tree. NOTE: the runtime DLP gate reads dlp_pre_hooks
# from the INSTALLED wheel's manifest (the boot-registered distribution), not from
# this submitted copy — this copy is the honest lifecycle-evidence record.
#
# Compute the manifest + its canonical digest with the KERNEL's canonical_bytes so
# the submit cheap-pre-check (sha256(canonical_bytes(manifest)) == manifest_digest)
# passes — the digest stays byte-coupled to the submitted bytes.
MANIFEST_JSON="$(uv run python - "$PACK_ID" "$PACK_WHEEL" <<'PY'
import json, sys
pack_id, wheel = sys.argv[1], sys.argv[2]
manifest = {
    "pack": {"kind": "tool", "name": pack_id, "version": "0.2.0"},
    "identity": {
        "agent_id": pack_id,
        "display_name": "Cognic Oracle Schema (proof-m5)",
        "provider_organization": "Cognic",
        "provider_url": "https://cognic.example",
    },
    "mcp": {"server_url": "http://10.96.0.51:8765/mcp", "scopes": ["oracle_schema.read"]},
    "risk_tier": {"tier": "read_only"},
    "data_governance": {
        "data_classes": ["internal"],
        "purpose": "operational_telemetry",
        "retention_policy": "none",
        "dlp_pre_hooks": ["refuse_forbidden_schema_arg", "explode_schema_guard"],
    },
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

# SETUP 1 — create the draft (author). Body carries the distribution pack_id + kind +
# the two hex digests; the actor's tenant is bound from the header role (NOT the body).
echo "==> SETUP 1 — create draft (author)"
CREATE_BODY="$(python3 - "$PACK_ID" "$MANIFEST_DIGEST" "$SIGNED_DIGEST" <<'PY'
import json, sys
pack_id, md, sd = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({
    "kind": "tool",
    "pack_id": pack_id,
    "display_name": "Cognic Oracle Schema (proof-m5)",
    "manifest_digest": md,
    "signed_artefact_digest": sd,
}))
PY
)"
CREATE_RESP="$(api author POST /api/v1/packs/drafts "$CREATE_BODY")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "201" ] || bar_fail "SETUP 1 create_draft (HTTP $HTTP_CODE)"
PACK_UUID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$CREATE_RESP")"
[ -n "$PACK_UUID" ] || bar_fail "SETUP 1 create_draft did not return a pack id"
echo "  draft created: pack_uuid=$PACK_UUID"

# SETUP 2 — submit the draft (author). manifest + signed_artefact_root (the staged
# attestation dir on the approve-time host = the pod's /opt/cognic/pack-attestations/<id>/<ver>).
echo "==> SETUP 2 — submit draft (author)"
SIGNED_ARTEFACT_ROOT="/opt/cognic/pack-attestations/$PACK_ID/0.2.0"
SUBMIT_BODY="$(python3 - "$SIGNED_ARTEFACT_ROOT" <<PY
import json, sys
root = sys.argv[1]
manifest = json.loads('''$MANIFEST_JSON''')
print(json.dumps({"manifest": manifest, "signed_artefact_root": root}))
PY
)"
api author POST "/api/v1/packs/drafts/$PACK_UUID/submit" "$SUBMIT_BODY" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "SETUP 2 submit (HTTP $HTTP_CODE)"

# SETUP 3 — claim (reviewer; DISTINCT subject from author -> role-separation passes).
echo "==> SETUP 3 — claim (reviewer)"
api reviewer POST "/api/v1/packs/$PACK_UUID/claim" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "SETUP 3 claim (HTTP $HTTP_CODE)"

# SETUP 4 — approve (reviewer). 5-gate composition: SIGNATURE is genuinely GREEN (the
# proof app's TrustGate cosign-verifies the released, signed v0.2.0 pack against the
# staged _default trust root); the FOUR non-signature gates (evaluation / adversarial /
# owasp / reviewer-ack) are OVERRIDDEN via override_reason. The reviewer role holds
# pack.override.approval_gate (the override scope is checked on the SAME actor that
# hits the reviewer-scoped /approve endpoint). Signature is NON-overridable (ADR-012
# §110), so the override cannot manufacture a green signature — it only skips the four
# gates whose evidence this proof does not attach. PROOF-ONLY (a real reviewer attaches
# genuine evaluation / adversarial evidence).
echo "==> SETUP 4 — approve (reviewer; signature REAL-green, 4 non-signature gates overridden)"
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
[ "$HTTP_CODE" = "200" ] || bar_fail "SETUP 4 approve (HTTP $HTTP_CODE; body: $APPROVE_RESP)"

# SETUP 5 — allow-list (operator; human-actor gate + pack.allow_list).
echo "==> SETUP 5 — allow-list (operator, human-actor)"
api operator POST "/api/v1/packs/$PACK_UUID/allow-list" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "SETUP 5 allow-list (HTTP $HTTP_CODE)"

# SETUP 6 — configure (operator; human-actor gate + pack.configure). Writes the DESIRED
# runtime-config record: server_url_override = the in-cluster MCP ClusterIP /mcp; the
# internal_host_allowlist IP; the OAuth + AS Vault refs (the seed-vault.sh paths). install
# will MATERIALIZE these into the derived carve-out tables.
echo "==> SETUP 6 — configure (operator; writes the desired runtime-config record)"
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
[ "$HTTP_CODE" = "200" ] || bar_fail "SETUP 6 configure (HTTP $HTTP_CODE)"

# SETUP 7 — install (operator; pack.install). The 5-gate install saga: lifecycle valid +
# boot-registered (gate 2, from app.state.plugin_registry) + runtime-config complete
# (gate 3) + materialize (gate 4 validates the Vault refs, then projects the derived
# override + allow-list rows) + set activation_status=active.
echo "==> SETUP 7 — install (operator; materializes the derived carve-out rows)"
INSTALL_RESP="$(api operator POST "/api/v1/packs/$PACK_UUID/install")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "SETUP 7 install (HTTP $HTTP_CODE; body: $INSTALL_RESP)"

# SETUP 8 — assert the derived rows were MATERIALIZED (via the decision_history events
# mcp.override.set + mcp.allowlist.add the materializer's store mutators emit). The
# inherited M4 governance property: the carve-out rows exist ONLY because install
# materialized them from the configured record — never seeded directly.
echo "==> SETUP 8 — assert materialization (decision_history: mcp.override.set + mcp.allowlist.add)"
MAT="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
  -c "SELECT event_type FROM decision_history WHERE event_type IN ('mcp.override.set','mcp.allowlist.add');")"
DERIVED_ROWS="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
  -c "SELECT 'override|' || tenant_id || '|' || pack_id || '|' || server_url_override FROM mcp_server_url_override UNION ALL SELECT 'allowlist|' || tenant_id || '|' || ip || '|' || set_by_actor FROM mcp_internal_host_allowlist ORDER BY 1;")"
grep -qF "mcp.override.set" <<<"$MAT" \
  || bar_fail "SETUP 8 no mcp.override.set materialization event (got: ${MAT:-<none>})"
grep -qF "mcp.allowlist.add" <<<"$MAT" \
  || bar_fail "SETUP 8 no mcp.allowlist.add materialization event (got: ${MAT:-<none>})"
grep -qF "override|$TENANT|$PACK_ID|http://10.96.0.51:8765/mcp" <<<"$DERIVED_ROWS" \
  || bar_fail "SETUP 8 no derived override row (got: ${DERIVED_ROWS:-<none>})"
grep -qF "allowlist|$TENANT|10.96.0.51|proof-m5-operator" <<<"$DERIVED_ROWS" \
  || bar_fail "SETUP 8 no derived allow-list row (got: ${DERIVED_ROWS:-<none>})"
echo "  SETUP 8 OK: override + allow-list rows materialized by install (not seeded)"

# SETUP 9 — roll cold so the governed MCP probe sees the materialized carve-out rows
# (MCPHost caches the OAuth token + list_tools per tenant; install happened after boot).
echo "==> SETUP 9 — roll cold so the MCP probe sees the materialized carve-outs"
roll_and_wait
pf_start
echo "  SETUP 9 OK: cold pod ready"

# ================================ BAR 1 (permitted → executes) =================
# The PERMITTED argument: the dlp_pre hook chain runs and ALLOWS, the tool executes,
# the seeded EMPLOYEES column metadata comes back. Proves the hook FIRES on the
# governed path AND a clean call passes unchanged. Re-asserts the hook admission on
# THIS pod first (registration is per-pod, and this cold pod serves all three bars).
echo "==> BAR 1 — permitted arg (table=EMPLOYEES): hook allows -> tool executes -> 200 + FULL_NAME"
assert_hook_pack_registered "BAR 1 preflight (hook pack on the serving pod)"
api mcp GET "/api/v1/mcp/servers/$PACK_ID/tools" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1 list_tools (HTTP $HTTP_CODE)"
CALL1_RESP="$(api mcp POST "/api/v1/mcp/servers/$PACK_ID/tools/call" \
  '{"tool_name":"describe_table","arguments":{"owner":"COGNIC","table":"EMPLOYEES"}}')"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1 call_tool permitted arg (HTTP $HTTP_CODE; body: $CALL1_RESP)"
grep -qF "FULL_NAME" <<<"$CALL1_RESP" \
  || bar_fail "BAR 1 call_tool content (no EMPLOYEES column metadata: $CALL1_RESP)"
DS="$(discovery_status)"
[ "$DS" = "auth_ready" ] || bar_fail "BAR 1 discovery_status=$DS (expected auth_ready)"
# The success evidence row exists — the baseline the BAR 2/3 "no new tool execution"
# deltas contrast against.
TOOL_INVOCATIONS_AFTER_BAR1="$(tool_invocation_count)"
[ "$TOOL_INVOCATIONS_AFTER_BAR1" -ge 1 ] \
  || bar_fail "BAR 1 no audit.tool_invocation success row (count=$TOOL_INVOCATIONS_AFTER_BAR1)"
echo "  Bar 1 OK: hook allowed + tool executed (FULL_NAME) + audit.tool_invocation row present"
echo "PROOF M5 (BAR 1) PASS"

# ================================ BAR 2 (forbidden → refused BEFORE the tool) ==
# The FORBIDDEN argument (same tool, same pack, same pod — the argument is the only
# variable): refuse_forbidden_schema_arg policy-refuses -> 403 dlp_pre_refused with
# policy_reason=forbidden_schema_arg. Then prove the refusal fired BEFORE the tool:
# (a) NO new audit.tool_invocation success row appeared for this call; the refusal
# row is audit.tool_invocation_refused with refusal_reason=dlp_pre_refused; and
# (b) DIGEST-ONLY — the forbidden literal appears in NO audit_event /
# decision_history payload (only dlp_policy_input_digest correlates the call).
echo "==> BAR 2 — forbidden arg (table=__FORBIDDEN__): 403 dlp_pre_refused BEFORE the tool"
TOOL_INVOCATIONS_BEFORE_BAR2="$(tool_invocation_count)"
CALL2_RESP="$(api mcp POST "/api/v1/mcp/servers/$PACK_ID/tools/call" \
  '{"tool_name":"describe_table","arguments":{"owner":"COGNIC","table":"__FORBIDDEN__"}}')"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "403" ] || bar_fail "BAR 2 expected HTTP 403 dlp_pre_refused (HTTP $HTTP_CODE; body: $CALL2_RESP)"
BAR2_REASON="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("detail",{}).get("reason",""))' <<<"$CALL2_RESP" 2>/dev/null || true)"
[ "$BAR2_REASON" = "dlp_pre_refused" ] \
  || bar_fail "BAR 2 reason '$BAR2_REASON' (expected 'dlp_pre_refused'; body: $CALL2_RESP)"
BAR2_POLICY_REASON="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("detail",{}).get("policy_reason",""))' <<<"$CALL2_RESP" 2>/dev/null || true)"
[ "$BAR2_POLICY_REASON" = "forbidden_schema_arg" ] \
  || bar_fail "BAR 2 policy_reason '$BAR2_POLICY_REASON' (expected 'forbidden_schema_arg'; body: $CALL2_RESP)"

# (a) refused BEFORE the tool: the audit.tool_invocation success count is UNCHANGED
# by the BAR-2 call (the BAR-1 success row is the contrast baseline).
TOOL_INVOCATIONS_AFTER_BAR2="$(tool_invocation_count)"
[ "$TOOL_INVOCATIONS_AFTER_BAR2" = "$TOOL_INVOCATIONS_BEFORE_BAR2" ] \
  || bar_fail "BAR 2 a tool execution occurred (audit.tool_invocation $TOOL_INVOCATIONS_BEFORE_BAR2 -> $TOOL_INVOCATIONS_AFTER_BAR2)"
# ...and the newest refusal row IS the DLP policy refusal, attributed to the
# refusing hook, carrying the sha256 digest correlator.
BAR2_REFUSAL_PAYLOAD="$(latest_tool_refusal_payload)"
[ -n "$BAR2_REFUSAL_PAYLOAD" ] || bar_fail "BAR 2 no audit.tool_invocation_refused row"
if ! python3 - "$BAR2_REFUSAL_PAYLOAD" <<'PY'
import json, re, sys
payload = json.loads(sys.argv[1])
reason = payload.get("refusal_reason")
digest = payload.get("dlp_policy_input_digest") or ""
hook = payload.get("dlp_failed_hook_id")
ok = (
    reason == "dlp_pre_refused"
    and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
    and hook == "refuse_forbidden_schema_arg"
)
if not ok:
    print(
        f"refusal_reason={reason!r} dlp_policy_input_digest={digest!r} "
        f"dlp_failed_hook_id={hook!r}",
        file=sys.stderr,
    )
    raise SystemExit(1)
print(f"  refusal row OK: dlp_pre_refused by refuse_forbidden_schema_arg digest={digest[:12]}...")
PY
then
  bar_fail "BAR 2 refusal row not a digest-carrying dlp_pre_refused (payload: $BAR2_REFUSAL_PAYLOAD)"
fi
# (b) digest-only evidence: the forbidden literal appears NOWHERE in the audit or
# decision chains — the payload carries only dlp_policy_input_digest, never the
# argument plaintext.
FORBIDDEN_LITERAL_ROWS="$(evidence_rows_containing_literal '__FORBIDDEN__')"
[ "$FORBIDDEN_LITERAL_ROWS" = "0" ] \
  || bar_fail "BAR 2 digest-only violated: __FORBIDDEN__ appears in $FORBIDDEN_LITERAL_ROWS evidence row(s)"
echo "  Bar 2 OK: 403 dlp_pre_refused (policy_reason=forbidden_schema_arg), no tool execution, digest-only evidence"
echo "PROOF M5 (BAR 2) PASS"

# ================================ BAR 3 (explode → fail-closed) ================
# The EXPLODE argument: the first hook passes, explode_schema_guard raises ->
# dlp_dispatcher_failed -> 409 dlp_pre_failed. A broken hook is a REFUSAL, never a
# silent bypass (Wave-1 fail-closed) — and still no tool execution, still digest-only.
echo "==> BAR 3 — explode arg (table=__EXPLODE__): hook raises -> 409 dlp_pre_failed (fail-closed)"
TOOL_INVOCATIONS_BEFORE_BAR3="$(tool_invocation_count)"
CALL3_RESP="$(api mcp POST "/api/v1/mcp/servers/$PACK_ID/tools/call" \
  '{"tool_name":"describe_table","arguments":{"owner":"COGNIC","table":"__EXPLODE__"}}')"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "409" ] || bar_fail "BAR 3 expected HTTP 409 dlp_pre_failed (HTTP $HTTP_CODE; body: $CALL3_RESP)"
BAR3_REASON="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("detail",{}).get("reason",""))' <<<"$CALL3_RESP" 2>/dev/null || true)"
[ "$BAR3_REASON" = "dlp_pre_failed" ] \
  || bar_fail "BAR 3 reason '$BAR3_REASON' (expected 'dlp_pre_failed'; body: $CALL3_RESP)"
TOOL_INVOCATIONS_AFTER_BAR3="$(tool_invocation_count)"
[ "$TOOL_INVOCATIONS_AFTER_BAR3" = "$TOOL_INVOCATIONS_BEFORE_BAR3" ] \
  || bar_fail "BAR 3 a tool execution occurred (audit.tool_invocation $TOOL_INVOCATIONS_BEFORE_BAR3 -> $TOOL_INVOCATIONS_AFTER_BAR3)"
BAR3_REFUSAL_PAYLOAD="$(latest_tool_refusal_payload)"
[ -n "$BAR3_REFUSAL_PAYLOAD" ] || bar_fail "BAR 3 no audit.tool_invocation_refused row"
if ! python3 - "$BAR3_REFUSAL_PAYLOAD" <<'PY'
import json, re, sys
payload = json.loads(sys.argv[1])
reason = payload.get("refusal_reason")
digest = payload.get("dlp_policy_input_digest") or ""
hook = payload.get("dlp_failed_hook_id")
ok = (
    reason == "dlp_pre_failed"
    and re.fullmatch(r"[0-9a-f]{64}", digest) is not None
    and hook == "explode_schema_guard"
)
if not ok:
    print(
        f"refusal_reason={reason!r} dlp_policy_input_digest={digest!r} "
        f"dlp_failed_hook_id={hook!r}",
        file=sys.stderr,
    )
    raise SystemExit(1)
print(f"  refusal row OK: dlp_pre_failed by explode_schema_guard digest={digest[:12]}...")
PY
then
  bar_fail "BAR 3 refusal row not a digest-carrying dlp_pre_failed (payload: $BAR3_REFUSAL_PAYLOAD)"
fi
EXPLODE_LITERAL_ROWS="$(evidence_rows_containing_literal '__EXPLODE__')"
[ "$EXPLODE_LITERAL_ROWS" = "0" ] \
  || bar_fail "BAR 3 digest-only violated: __EXPLODE__ appears in $EXPLODE_LITERAL_ROWS evidence row(s)"
echo "  Bar 3 OK: 409 dlp_pre_failed (fail-closed), no tool execution, digest-only evidence"
echo "PROOF M5 (BAR 3) PASS"

echo "PROOF M5 (ALL BARS) PASS"
