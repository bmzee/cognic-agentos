#!/usr/bin/env bash
# Proof 1b-2c (M3-E2c) — deployed governed MCP invocation loop against the
# RELEASED, signed cognic-tool-oracle-schema@v0.1.0 pack.
#
# Operator-run + env-gated (COGNIC_RUN_PROOF_1B2C=1); NO default-on CI job (needs an
# image build + kind + a live Vault/Postgres + an in-cluster Oracle XE). It ADAPTS the
# proven Proof 1b-2 runner (run-proof-1b-2.sh) with the M3-E2c deltas:
#   * the pack is the RELEASED v0.1.0 artifact, STAGED BY DOWNLOAD (gh release download +
#     sha256 verify) — never a local wheel rebuild (acceptance criterion #1);
#   * an in-cluster Oracle XE (gvenzl/oracle-xe:21-slim) seeded once on first boot from
#     oracle-seed/seed_schema.sql backs the pack's read_only schema-metadata tools;
#   * the AS runs in RS256 mode (COGNIC_PROOF_AS_SIGNING_MODE=rs256) so the released
#     pack's REAL PyJWKClient/RS256 verifier can verify the token (the 1b-2 example
#     accepted any bearer).
#
# Proves the full governed MCP path against the deployed kernel:
#   * BAR 1 (checkpoint) — the PR-2b-1 override + exact-IP allow-list carve-out is
#     load-bearing: a seeded allow-list permits the resource leg
#     (audit.mcp_allowlist_permitted, host 10.96.0.51); removing the row on a COLD
#     pod refuses (mcp_discovery_url_refused / discovery_status=refused).
#   * BAR 2 (completion) — discovery_status=auth_ready + a REAL list_tools + a REAL
#     call_tool(describe_table owner=COGNIC table=EMPLOYEES) returning the seeded
#     EMPLOYEES column metadata.
#
# Bar 1 is a CHECKPOINT (prints "BAR 1 PASS"); Bar 2 is COMPLETION (prints
# "PROOF 1b-2c (BAR 2) PASS"). On Bar 2 failure the runner captures logs +
# discovery_status + the authz reason to docs/VALIDATION-RESULTS.md and exits
# non-zero — the proof is NEVER redefined downward.
#
# Optional (env-gated COGNIC_PROOF_VERIFIER_NEGATIVE=1, off by default): after Bar 2,
# point the pack's expected audience at a non-matching URL and prove call_tool FAILS
# because the pack's real RS256 verifier rejects the aud mismatch, then revert.
set -euo pipefail

if [[ "${COGNIC_RUN_PROOF_1B2C:-}" != "1" ]]; then
  echo "skipped: set COGNIC_RUN_PROOF_1B2C=1 to run the operator proof" >&2
  exit 0
fi

CLUSTER="${KIND_CLUSTER:-cognic-proof1b2c}"
NS="cognic-proof1b2c"
CHART="infra/charts/agentos"
PROOF_DIR="infra/proof-1b-2c"
STAGING_DST="$PROOF_DIR/proof1b2c-staging"          # released-pack staging output (build context)
PROOF_APP_SRC="tests/integration/proof_1b_2c"       # the proof-only app factory
PROOF_APP_DST="$PROOF_DIR/proof_1b_2c"              # transient build-context copy
BASE_IMAGE="cognic-agentos:proof1b2-base"           # reused — same default-adapters base as 1b-2
IMAGE="cognic-agentos:proof1b2c"
MCP_IMAGE="cognic-proof-oracle-pack:1b2c"
AS_IMAGE="cognic-proof-as:1b2c"
PF=""

die() { echo "FAIL: $*" >&2; exit 1; }

# The backend image refs, sourced from backends.yaml (DRY — stays in sync with the
# smoke backends; awk field $2 ignores the trailing "# …" comment on each image: line).
_backend_images() {
  awk '/^[[:space:]]*image:/ {print $2}' "$CHART/ci/smoke/backends.yaml"
}

# Extra (non-backend) images the M3-E2c manifests reference with imagePullPolicy:
# IfNotPresent — pre-pulled + kind-loaded so the kind node never reaches the internet
# for them: oracle-xe (manifests/oracle-xe.yaml) + busybox (the oracle-pack wait-for-xe
# initContainer in manifests/oracle-pack.yaml).
_extra_images() {
  printf '%s\n' "gvenzl/oracle-xe:21-slim" "busybox:1.36"
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
  ds="$(curl -s "http://127.0.0.1:8000/api/v1/system/plugins?tenant_id=proof-1b-2c" 2>/dev/null || true)"
  reason="$(grep -Eo 'mcp_[a-z_]*refused|refused_component=[a-z_]+|discovery_status=[a-z_]+' <<<"$logs" | sort -u || true)"
  {
    echo ""
    echo "## Proof 1b-2c — Bar 2 FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- authz / discovery reason markers:"
    echo '```'
    echo "${reason:-<none captured>}"
    echo '```'
    echo "- discovery_status snapshot (GET /api/v1/system/plugins?tenant_id=proof-1b-2c):"
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

# Step-5 XE-readiness failure path: capture the XE pod state + boot logs to
# docs/VALIDATION-RESULTS.md BEFORE the trap deletes the cluster (mirrors bar2_fail).
# The qemu-emulated gvenzl XE first boot is slow under kind; if it still exceeds the
# (bumped) readiness budget this records WHY (describe/events/logs) instead of a bare timeout.
xe_fail() {
  local where="$1"
  echo "FAIL: oracle-xe ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local pods desc logs
  pods="$(kubectl -n "$NS" get pods 2>&1 || true)"
  desc="$(kubectl -n "$NS" describe pod -l app=oracle-xe 2>&1 | tail -90 || true)"
  logs="$(kubectl -n "$NS" logs -l app=oracle-xe --tail=120 2>&1 || true)"
  {
    echo ""
    echo "## Proof 1b-2c — Oracle XE readiness FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- pods:"
    echo '```'
    echo "$pods"
    echo '```'
    echo "- oracle-xe describe (tail 90):"
    echo '```'
    echo "$desc"
    echo '```'
    echo "- oracle-xe logs (tail 120):"
    echo '```'
    echo "$logs"
    echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

# Step-5 backends-readiness failure path: capture the backend deploy/pod state to
# docs/VALIDATION-RESULTS.md BEFORE the trap deletes the cluster (mirrors xe_fail).
# The six shared backends start BEFORE XE now; if they don't reach Available the
# describe/get output records WHY (pending/scheduling/resource) instead of a bare timeout.
backends_fail() {
  local where="$1"
  echo "FAIL: backends ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local wide ddeploy dpods
  wide="$(kubectl -n "$NS" get deploy,pods -o wide 2>&1 || true)"
  ddeploy="$(kubectl -n "$NS" describe deploy -l 'app notin (oracle-xe)' 2>&1 | tail -120 || true)"
  dpods="$(kubectl -n "$NS" describe pod -l 'app notin (oracle-xe)' 2>&1 | tail -150 || true)"
  {
    echo ""
    echo "## Proof 1b-2c — backends readiness FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- deploy + pods (-o wide):"
    echo '```'
    echo "$wide"
    echo '```'
    echo "- backend deploy describe (tail 120):"
    echo '```'
    echo "$ddeploy"
    echo '```'
    echo "- backend pod describe (tail 150):"
    echo '```'
    echo "$dpods"
    echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

cleanup() {
  pf_stop
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  # remove the transient build-context copies (NOT the sources)
  rm -rf "$STAGING_DST" "$PROOF_APP_DST" "$PROOF_DIR/_local_as.py" 2>/dev/null || true
}
trap cleanup EXIT

# --- 1. preflight ---------------------------------------------------------------
# `gh` is added for the released-asset download (stage_released_pack.py); cosign/syft/
# grype are retained from the 1b-2 list (the kernel boot-time trust gate still verifies
# the staged attestations) even though host-side staging no longer invokes them.
echo "==> [1/10] tool preflight"
for tool in docker kind kubectl helm uv cosign syft grype curl python3 gh; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool '$tool' not on PATH"
done

# --- 2. stage the RELEASED pack (download v0.1.0 + sha256-verify + arrange) ------
# Released artifact ONLY (acceptance criterion #1) — NO local wheel rebuild. The helper
# downloads the v0.1.0 GitHub release, verifies the wheel + cosign.pub digests, and
# arranges the trust tree DIRECTLY into the build-context dir (proof1b2c-staging/).
echo "==> [2/10] stage the released cognic-tool-oracle-schema@v0.1.0 (download, not build)"
rm -rf "$STAGING_DST"
uv run python -m tests.integration.proof_1b_2c.stage_released_pack "$STAGING_DST"

# --- 3. build the four images ---------------------------------------------------
echo "==> [3/10] build the default-adapters base image"
docker build -f infra/agentos/Dockerfile --target default-adapters -t "$BASE_IMAGE" .

echo "==> [3/10] copy the proof_1b_2c app into the proof build context"
rm -rf "$PROOF_APP_DST"
cp -r "$PROOF_APP_SRC" "$PROOF_APP_DST"

echo "==> [3/10] build the proof AgentOS image (create_proof_app + released trust staging baked in)"
docker build -f "$PROOF_DIR/Dockerfile.agentos-proof" --build-arg BASE_IMAGE="$BASE_IMAGE" -t "$IMAGE" "$PROOF_DIR"

echo "==> [3/10] build the released oracle-pack MCP tool Service image"
# Context = $PROOF_DIR (NOT repo root): Dockerfile.oracle-pack reads the released wheel
# from proof1b2c-staging/wheel/ (staged under $PROOF_DIR in step 2), so the build context
# must be $PROOF_DIR for that COPY source to resolve.
docker build -f "$PROOF_DIR/Dockerfile.oracle-pack" -t "$MCP_IMAGE" "$PROOF_DIR"

echo "==> [3/10] build the emulated-external AS image (RS256 mode)"
# Vendor the single AS fixture into the proof build context, then build with context
# = $PROOF_DIR (NOT repo root): .dockerignore excludes tests/ from the repo-root context,
# so a repo-root COPY of tests/integration/pack_loop/_local_as.py is filtered out + fails.
# Mirrors the agentos-proof + oracle-pack copy-into-context pattern; cleanup() removes the copy.
cp tests/integration/pack_loop/_local_as.py "$PROOF_DIR/_local_as.py"
docker build -f "$PROOF_DIR/Dockerfile.as" -t "$AS_IMAGE" "$PROOF_DIR"

# --- 4. kind create + load (3 proof images + backends + oracle-xe + busybox) -----
echo "==> [4/10] pre-pull the backend + extra images (host docker cache)"
while IFS= read -r _img; do
  [ -n "$_img" ] || continue
  echo "  docker pull $_img"
  docker pull "$_img" >/dev/null
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
# Sequenced startup (NOT overlapped): bring the six shared backends up and wait them
# Available BEFORE applying XE. The qemu-emulated gvenzl XE boot saturates the node CPU;
# overlapping it with the backend startup starves even lightweight backends
# (postgres/qdrant/vault) past the 300s wait (M3-E2c attempt-4 finding). Sequenced, the
# backends come up uncontended, then XE boots while they sit idle on a dedicated 1200s
# budget (its emulated first boot runs well past the native ~3-5 min). backends_fail /
# xe_fail capture the pod state if either wait is exceeded.
echo "==> [5/10] bring up the six backends, then the seeded Oracle XE"
kubectl create namespace "$NS"
# (1) the six shared backends FIRST; wait them Available BEFORE XE is applied. The
# `app notin (oracle-xe)` selector picks exactly the six backends (only XE carries
# app=oracle-xe). backends_fail captures their state if they miss the 300s gate.
kubectl -n "$NS" apply -f "$CHART/ci/smoke/backends.yaml"
kubectl -n "$NS" wait --for=condition=available --timeout=300s deploy -l 'app notin (oracle-xe)' \
  || backends_fail "six shared backends not Available within 300s before XE start"
# (2) only AFTER the backends are up: build the seed ConfigMap straight from the SQL file
# (single source of truth — no embedded copy, no drift; mounted at
# /container-entrypoint-initdb.d) and apply XE. It boots while the backends sit idle.
kubectl -n "$NS" create configmap oracle-xe-seed \
  --from-file=seed_schema.sql="$PROOF_DIR/oracle-seed/seed_schema.sql" \
  --dry-run=client -o yaml | kubectl apply -n "$NS" -f -
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-xe.yaml"
kubectl -n "$NS" wait --for=condition=ready pod -l app=oracle-xe --timeout=1200s \
  || xe_fail "oracle-xe pod not Ready within 1200s (qemu-emulated XE first boot under kind)"

# --- 6. Vault init/seed (KV v1 + OAuth + AS-allowlist) --------------------------
# Must run after Vault is up (backend wait above) and before AgentOS reads it.
echo "==> [6/10] seed Vault (KV v1 conversion + OAuth + AS allow-list)"
NS="$NS" bash "$PROOF_DIR/seed-vault.sh"

# --- 7. helm install (prod profile; migrations OFF — Gap 3) ---------------------
echo "==> [7/10] install the AgentOS chart under the proof-1b-2c overlay"
helm install rel "$CHART" -n "$NS" -f "$PROOF_DIR/proof-1b-2c-values.yaml"

# --- 8. migrate Job + apply the oracle-pack/AS manifests ------------------------
# Gap 3 sidestep: the chart's pre-install migration HOOK deadlocks on a fresh install
# (references the normal-resource SA + Secret Helm creates AFTER hooks). So migrations
# are OFF in the overlay and run here as a non-hook Job AFTER install (default SA).
echo "==> [8/10] run the proof-owned (non-hook) migration Job"
kubectl -n "$NS" delete job/agentos-migrate --ignore-not-found=true --wait=true
sed "s|__AGENTOS_IMAGE__|$IMAGE|" "$PROOF_DIR/migrate-job.yaml" | kubectl apply -n "$NS" -f -
kubectl -n "$NS" wait --for=condition=complete job/agentos-migrate --timeout=300s

echo "==> [8/10] apply the oracle-pack MCP tool Service + AS manifests; wait Ready"
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-pack.yaml" -f "$PROOF_DIR/manifests/auth-server.yaml"
kubectl -n "$NS" rollout status deploy/proof-oracle-pack --timeout=180s
kubectl -n "$NS" rollout status deploy/proof-as --timeout=180s

# --- 9. DB seed (override + allow-list rows — after migrations created the tables)
# CALLS the seed script; the runner NEVER inlines the override/allow-list INSERTs
# (drift-prevention — the seed contract lives in seed-db.sh alone).
echo "==> [9/10] seed Postgres (override + exact-IP allow-list rows)"
NS="$NS" bash "$PROOF_DIR/seed-db.sh"

# --- 10. roll to a cold pod + port-forward --------------------------------------
echo "==> [10/10] roll the Deployment so fresh pods boot against the migrated+seeded DB"
roll_and_wait
pf_start

# ================================ BAR 1 (checkpoint) ============================
# The PR-2b-1 carve-out is load-bearing — pinned cold-cache sequence.
echo "==> BAR 1.1 — allow-list seeded: the resource leg is PERMITTED"
curl -sf http://127.0.0.1:8000/api/v1/mcp/servers/cognic-tool-oracle-schema/tools >/dev/null \
  || die "Bar 1.1: list_tools did not return 200 with the allow-list seeded"
# Evidence surface: the permit is a DD-2 audit-store event (mcp_authz.py
# self._audit.append(AuditEvent("audit.mcp_allowlist_permitted", payload={host,...}))),
# persisted to the audit_event table — NOT a stdout log (AuditStore.append never logs the
# event). Query the table; payload carries the permitted host. (payload::text + grep avoids
# a jsonb-operator assumption about the GovernanceJSON column type.)
PERMIT="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
  -c "SELECT payload::text FROM audit_event WHERE event_type='audit.mcp_allowlist_permitted';")"
grep -qF "10.96.0.51" <<<"$PERMIT" \
  || die "Bar 1.1: no audit.mcp_allowlist_permitted event carrying host 10.96.0.51 in audit_event (got: ${PERMIT:-<none>})"
echo "  Bar 1.1 OK: audit.mcp_allowlist_permitted persisted for host 10.96.0.51 (audit_event table)"

echo "==> BAR 1.2 — remove the allow-list row, restart COLD: the leg MUST refuse"
kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -v ON_ERROR_STOP=1 \
  -c "DELETE FROM mcp_internal_host_allowlist WHERE tenant_id='proof-1b-2c' AND ip='10.96.0.51';"
roll_and_wait
pf_start
REFUSE_CODE="$(curl -s -o /tmp/proof1b2c-refuse-body \
  -w '%{http_code}' http://127.0.0.1:8000/api/v1/mcp/servers/cognic-tool-oracle-schema/tools || true)"
[ "$REFUSE_CODE" != "200" ] \
  || die "Bar 1.2: expected a refusal with the allow-list removed, got HTTP 200"
# Evidence surface: the refusal is a raised MCPAuthzError → the reason lands in the HTTP
# response BODY (not stdout, not an audit event); refused_component=host_address is an
# exception attr NOT surfaced in the body, so assert discovery_status=refused via
# /system/plugins instead (the same API evidence model Bar 2 uses for auth_ready).
grep -qF "mcp_discovery_url_refused" /tmp/proof1b2c-refuse-body \
  || die "Bar 1.2: response body did not carry mcp_discovery_url_refused (got: $(cat /tmp/proof1b2c-refuse-body))"
curl -sf "http://127.0.0.1:8000/api/v1/system/plugins?tenant_id=proof-1b-2c" >/tmp/proof1b2c-refuse-plugins.json \
  || die "Bar 1.2: /system/plugins read failed"
python3 - <<'PY' || die "Bar 1.2: discovery_status not refused after allow-list removal"
import json
doc = json.load(open("/tmp/proof1b2c-refuse-plugins.json"))
rows = [p for p in doc.get("plugins", []) if p.get("pack_id") == "cognic-tool-oracle-schema"]
assert rows, f"FAIL: cognic-tool-oracle-schema row absent (payload={doc})"
ds = rows[0].get("discovery_status")
assert ds == "refused", f"FAIL: discovery_status={ds!r} expected refused (payload={doc})"
PY
echo "  Bar 1.2 OK: HTTP $REFUSE_CODE + mcp_discovery_url_refused (body) + discovery_status=refused (carve-out is load-bearing)"

echo "==> BAR 1.3 — re-seed the allow-list, restart COLD: clean state for Bar 2"
NS="$NS" bash "$PROOF_DIR/seed-db.sh"
roll_and_wait
pf_start
echo "BAR 1 PASS"

# ================================ BAR 2 (completion) ===========================
echo "==> BAR 2 — full governed loop: list_tools + call_tool(describe_table) + discovery_status=auth_ready"
curl -sf -X GET http://127.0.0.1:8000/api/v1/mcp/servers/cognic-tool-oracle-schema/tools \
  >/tmp/proof1b2c-tools.json || bar2_fail "list_tools"

# call_tool the released pack's describe_table over the governed MCP route. The 200
# envelope's `payload` is the MCP SDK CallToolResult (content[]/structuredContent),
# so the seeded EMPLOYEES column metadata appears verbatim in the response JSON.
curl -sf -X POST http://127.0.0.1:8000/api/v1/mcp/servers/cognic-tool-oracle-schema/tools/call \
  -H 'Content-Type: application/json' \
  -d '{"tool_name":"describe_table","arguments":{"owner":"COGNIC","table":"EMPLOYEES"}}' \
  >/tmp/proof1b2c-call.json || bar2_fail "call_tool"
# Content assertion: a bare 200 is not enough — a degraded (isError) response is still
# 200. Require a REAL seeded EMPLOYEES column (Oracle upper-cases identifiers, so the
# data-dictionary name is FULL_NAME) in the call_tool payload.
grep -qF "FULL_NAME" /tmp/proof1b2c-call.json \
  || bar2_fail "call_tool_content (no EMPLOYEES column metadata: $(cat /tmp/proof1b2c-call.json))"

curl -sf "http://127.0.0.1:8000/api/v1/system/plugins?tenant_id=proof-1b-2c" \
  >/tmp/proof1b2c-plugins.json || bar2_fail "plugins_read"

python3 - <<'PY' || bar2_fail "discovery_status"
import json
doc = json.load(open("/tmp/proof1b2c-plugins.json"))
rows = [p for p in doc.get("plugins", []) if p.get("pack_id") == "cognic-tool-oracle-schema"]
assert rows, f"FAIL: cognic-tool-oracle-schema row absent (payload={doc})"
ds = rows[0].get("discovery_status")
assert ds == "auth_ready", f"FAIL: discovery_status={ds!r} expected auth_ready (payload={doc})"
print("Bar 2 OK: discovery_status=auth_ready")
PY

echo "PROOF 1b-2c (BAR 2) PASS"

# =================== OPTIONAL verifier negative (off by default) ================
# Env-gated COGNIC_PROOF_VERIFIER_NEGATIVE=1. Point the pack's expected audience at a
# NON-matching URL: the AS still mints aud=http://10.96.0.51:8765/mcp (the override
# resource), so the pack's REAL RS256 verifier rejects the token → call_tool MUST FAIL.
# Then revert so the cluster is left in the Bar-2-green shape. Kept off the main run so
# the proof's happy path stays lean.
if [[ "${COGNIC_PROOF_VERIFIER_NEGATIVE:-}" == "1" ]]; then
  echo "==> OPTIONAL — verifier negative: aud mismatch must FAIL call_tool"
  kubectl -n "$NS" set env deploy/proof-oracle-pack COGNIC_OAUTH_AUDIENCE=http://10.96.0.99:8765/mcp
  kubectl -n "$NS" rollout status deploy/proof-oracle-pack --timeout=180s
  roll_and_wait
  pf_start
  NEG_CODE="$(curl -s -o /tmp/proof1b2c-neg-body -w '%{http_code}' \
    -X POST http://127.0.0.1:8000/api/v1/mcp/servers/cognic-tool-oracle-schema/tools/call \
    -H 'Content-Type: application/json' \
    -d '{"tool_name":"describe_table","arguments":{"owner":"COGNIC","table":"EMPLOYEES"}}' || true)"
  [ "$NEG_CODE" != "200" ] \
    || die "verifier negative: expected call_tool to FAIL on aud mismatch, got HTTP 200 (body: $(cat /tmp/proof1b2c-neg-body))"
  echo "  verifier negative OK: call_tool refused (HTTP $NEG_CODE) on aud mismatch"
  echo "==> OPTIONAL — revert the audience to the matching URL"
  kubectl -n "$NS" set env deploy/proof-oracle-pack COGNIC_OAUTH_AUDIENCE=http://10.96.0.51:8765/mcp
  kubectl -n "$NS" rollout status deploy/proof-oracle-pack --timeout=180s
  roll_and_wait
  pf_start
  echo "  verifier negative reverted: audience back to http://10.96.0.51:8765/mcp"
fi
