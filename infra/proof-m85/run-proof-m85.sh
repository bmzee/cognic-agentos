#!/usr/bin/env bash
# Proof M8.5 SLICE (conversational substrate — BARs 1-3) — the vertical-slice
# gate for ADR-028: the kernel-owned CONVERSATION primitive (`/api/v1/
# conversations`) wrapping the PROVEN M8 governed agent loop, live on kind.
# The deployment is the proof-m8 bring-up VERBATIM (same SEVEN released,
# signed packs, same M4 governed operator install for the oracle tool, same
# in-cluster Oracle XE + RS256/JWKS AS + litellm cloud tier); the ONLY new
# surface under test is the conversation API and its evidence:
#   * conversation.created / conversation.turn_completed chain rows are
#     DIGEST-ONLY (question_sha256/answer_sha256 + byte counts); plaintext
#     lives solely in the erasable conversation_turns columns;
#   * every turn re-enters the M8 dispatch chokepoint — assignment ->
#     entitlement -> policy re-checked per dispatch of every turn (I-2);
#   * prior turns come EXCLUSIVELY from the kernel store (I-1): the wire has
#     NO history-accepting field (extra="forbid").
#
# THE THREE BARS (plan Task 8, rulings 2026-07-10 — ALL MANDATORY, never
# redefined downward; any bar failure captures diagnostics + exits non-zero):
#   * BAR 1 (governed multi-turn e2e) — analyst.amir creates a conversation
#     with bank-analyst; turn 1 asks the deterministic top-3-depositors
#     question; turn 2 asks a follow-up CONTAINING NO ENTITY NAME ("the
#     second-largest of those") answerable only via replayed turn-1 context.
#     MECHANICAL pins (load-bearing): turn-2 agent.run.started carries
#     prior_context_turns=2 + a prior_context_sha256 this runner RECOMPUTES
#     independently from conversation_turns plaintext (framing
#     "user:<question>\nassistant:<answer>"); TWO chain lineages, all
#     tenant-scoped (run-5 ruling 2026-07-10): the CONTEXT lineage seq=2 ->
#     run -> started/completed with the turn-2 dispatch count DELIBERATELY
#     UNCONSTRAINED (0 = context reuse; >=1 = legitimate re-verification),
#     and the DISPATCH lineage seq=1 -> run -> started/completed -> >=1 ok
#     retail run_readonly_query dispatch (the three-hop conversation ->
#     run -> dispatch join rides the turn that DID dispatch);
#     question/answer digests on every turn_completed row equal sha256 of
#     the stored plaintext; dual identity (actor_id=analyst.amir, payload
#     agent_id=bank-analyst) on every conversation.% and agent.run.% row of
#     the runs. The answer-content checks (turn-1 top-3 names; turn-2 rank-2
#     name) are model-driven FUNCTIONAL ACCEPTANCE CRITERIA — MANDATORY, a
#     miss fails the bar — but distinct from the mechanical pins, which are
#     the invariant evidence.
#   * BAR 2 (record integrity — DETERMINISTIC, no model call) — FIVE forged
#     history fields (messages / history / prior_context / context /
#     transcript) each 422 AND each error body identifies extra_forbidden for
#     the submitted field; plus the ZERO-LOOP pin: agent.run.% and
#     conversation.turn_completed counts and the conversation turn_count are
#     byte-identical before/after the probe block.
#   * BAR 3 (mid-conversation revocation — the I-2 pin) — its OWN
#     conversation on the FINANCIALS scope: turn 1 (GL question) completes
#     with an ok financials dispatch row; the runner then proves EXACTLY ONE
#     amir financials entitlement row existed, DELETEs it (readback 0), and
#     turn 2 asks a FRESH financials question (branch P&L — not answerable
#     from replayed context). Load-bearing pins: >=1 dispatch row refused
#     agent_scope_not_entitled scope_id=financials for run 2 AND EXACTLY 0 ok
#     financials dispatches for run 2. HTTP stays 200 — a dispatch refusal is
#     a governed answer, and the bar asserts CHAIN ROWS, never the status.
#     The entitlement is then RESTORED (readback 1). Note the PT-3 posture:
#     revocation does not un-disclose turn-1 content already in the
#     transcript; the bar proves no FRESH data crosses the revoked scope.
#
# HONESTY BOUNDARY (recorded in README.md): BAR 2 is fully deterministic.
# BARs 1 and 3 carry BOTH mechanical chain pins (the invariant evidence) AND
# model-driven functional acceptance criteria (answer contents) — the latter
# are MANDATORY but flake-prone; a miss fails the bar and reads as a model-
# behaviour failure, not an integrity failure. BARs 4-7 of ADR-028 are NOT
# run here — this is the vertical-slice gate, not the M8.5 production proof.
# The analyst roles carry ONLY the four conversation.* scopes (no agent.ask):
# the slice exercises the conversation surface exclusively. No bar depends on
# OTLP spans — the otel collector is inherited diagnostics (ruling R6).
#
# Operator-run + env-gated (COGNIC_RUN_PROOF_M85=1); NO default-on CI job
# (needs an image build + kind + live Vault/Postgres/Redis + in-cluster
# Oracle XE + a local TLS registry + the host docker socket + the operator's
# CLOUD provider key). The provider key env (COGNIC_PROOF_M85_TIER1_API_KEY)
# is REQUIRED at the gate — operator env at run time, never committed, never
# image-baked.
#
# On any BAR failure the runner captures logs + HTTP status + the
# conversation.% / agent.run.% / dispatch / audit evidence to
# docs/VALIDATION-RESULTS.md and exits non-zero — the proof is NEVER
# redefined downward. On all-pass it prints
# "PROOF M8.5 SLICE (BARS 1-3) PASS" and exits 0.
set -euo pipefail

if [[ "${COGNIC_RUN_PROOF_M85:-}" != "1" ]]; then
  echo "skipped: set COGNIC_RUN_PROOF_M85=1 to run the governed-agent-loop proof" >&2
  exit 0
fi

# The operator's CLOUD provider key — REQUIRED (fail loud, never a silent
# self-hosted fallback: BARs 1 and 3 drive the REAL cloud tier through the M8
# loop). The name matches proof-m85-values.yaml's litellm_params api_key env
# reference.
if [[ -z "${COGNIC_PROOF_M85_TIER1_API_KEY:-}" ]]; then
  echo "FAIL: COGNIC_PROOF_M85_TIER1_API_KEY is unset — the M8.5 slice drives a REAL" >&2
  echo "      cloud tier-1 model (BARs 1 and 3 are model-driven turns). Export the" >&2
  echo "      operator's provider API key and re-run. (Provider swap = ONE values diff" >&2
  echo "      + COGNIC_PROOF_M85_ALLOWED_PROVIDERS/COGNIC_PROOF_M85_POLICY_MODE — README.)" >&2
  exit 1
fi

# Key-isolation window (review finding 1, 2026-07-10 round 3): copy the key
# into a NON-exported shell variable and DROP the exported variable NOW —
# before the FIRST external process — so no child (curl, stage-packs,
# cosign, openssl, docker, kubectl, ...) ever inherits it. A plain
# assignment to a NEW name carries no export attribute; under `set -u` any
# straggler reference to the exported name fails loud.
_PROVIDER_KEY_LOCAL="$COGNIC_PROOF_M85_TIER1_API_KEY"
unset COGNIC_PROOF_M85_TIER1_API_KEY

# ZERO-SPEND provider-key VALIDITY probe (added after the 2026-07-10 run-2
# finding: a rotated/invalid key surfaced only at BAR 1 — a 401 on the first
# completion, ~25 minutes into a fully-green bring-up). GET /v1/models bills
# nothing and proves the key BEFORE any cluster work starts. OpenAI-only: a
# provider swap (the README one-values-diff) changes the auth endpoint, so
# the probe SKIPS with a notice rather than false-failing a non-OpenAI key.
# Hardened per review (2026-07-10): bounded timeouts (5s connect / 15s
# total); the bearer header rides STDIN (-H @-), NEVER curl argv, so a `ps`
# snapshot cannot expose the key; and the FOUR outcomes are diagnosed
# SEPARATELY — a transport/DNS/timeout failure or an unexpected HTTP status
# is "validity UNDETERMINED, fix connectivity", never "rotate the key".
if [[ "${COGNIC_PROOF_M85_ALLOWED_PROVIDERS:-openai}" == "openai" ]]; then
  set +e
  KEY_PROBE_CODE="$(printf 'Authorization: Bearer %s\n' "$_PROVIDER_KEY_LOCAL" \
    | curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 \
        -H @- https://api.openai.com/v1/models)"
  KEY_PROBE_RC=$?
  set -e
  if [[ "$KEY_PROBE_RC" -ne 0 ]]; then
    echo "FAIL: provider-key preflight could not REACH api.openai.com (curl exit" >&2
    echo "      $KEY_PROBE_RC — transport/DNS/timeout; key validity UNDETERMINED)." >&2
    echo "      Fix connectivity and re-run; do NOT rotate the key on this signal." >&2
    exit 1
  fi
  case "$KEY_PROBE_CODE" in
    200)
      echo "provider-key preflight OK (zero-spend GET /v1/models: HTTP 200)"
      ;;
    401|403)
      echo "FAIL: COGNIC_PROOF_M85_TIER1_API_KEY was REFUSED by api.openai.com (HTTP" >&2
      echo "      $KEY_PROBE_CODE on the zero-spend GET /v1/models probe) — refusing" >&2
      echo "      BEFORE any cluster work. Rotate/re-export the key and re-run." >&2
      exit 1
      ;;
    *)
      echo "FAIL: unexpected provider response on the key preflight (HTTP" >&2
      echo "      $KEY_PROBE_CODE; key validity UNDETERMINED) — refusing BEFORE any" >&2
      echo "      cluster work. Inspect provider status; do NOT assume a bad key." >&2
      exit 1
      ;;
  esac
else
  echo "provider-key preflight SKIPPED (provider swap: ${COGNIC_PROOF_M85_ALLOWED_PROVIDERS} — no OpenAI probe)"
fi

CLUSTER="${KIND_CLUSTER:-cognic-proofm85}"
NS="cognic-proofm85"
CHART="infra/charts/agentos"
PROOF_DIR="infra/proof-m85"
STAGING_DST="$PROOF_DIR/proof-m85-staging"           # released-pack staging output (build context)
CANONICAL_DIR="$STAGING_DST/canonical-trust"        # proof canonical cosign key + registry CA (baked into the kernel image)
PROOF_APP_SRC="$PROOF_DIR/proof_m85"                 # the proof-only multi-actor app factory (ALREADY in-context — no copy step)
AGENTOS_SRC_SRC="src/cognic_agentos"                # current kernel source overlay (the M8 wiring)
AGENTOS_SRC_DST="$PROOF_DIR/cognic_agentos"         # transient build-context copy
BASE_IMAGE="cognic-agentos:proof1b2-base"           # reused — same default-adapters base as proof-1b-2c/m4/m5/m6
IMAGE="cognic-agentos:proofm85"
MCP_IMAGE="cognic-proof-oracle-pack:m85"
AS_IMAGE="cognic-proof-as:m85"
TENANT="proof-m85"
PACK_ID="cognic-tool-oracle-schema"
HOOK_PACK_ID="cognic-hook-schema-guard"
AGENT_PACK_ID="cognic-agent-bank-analyst"
AGENT_ID="bank-analyst"                             # the AGENT.md frontmatter name (the ask path segment)
SKILL_IDS=("customer-data" "financial-data" "cards-data" "atm-recon")
SKILL_PACK_IDS=("cognic-skill-customer-data" "cognic-skill-financial-data" "cognic-skill-cards-data" "cognic-skill-atm-recon")
PACK_WHEEL="cognic_tool_oracle_schema-0.3.0-py3-none-any.whl"
BASE_URL="http://127.0.0.1:8000"
PF=""
QC_TMP=""                                           # per-run PRIVATE query-context key dir (mktemp; removed by the trap)

# Cloud-policy posture — operator env at deploy time (never committed, never
# image-baked). Provider swap = the README's one-values-diff + these two envs.
ALLOWED_PROVIDERS="${COGNIC_PROOF_M85_ALLOWED_PROVIDERS:-openai}"
POLICY_MODE="${COGNIC_PROOF_M85_POLICY_MODE:-cloud_openai}"

# ---- proof canonical-image re-home (the REAL sandbox admission trust posture) ----
# The M6 executable-skill posture deploys UNCHANGED (hosted_skills precondition
# — see the header): the canonical sandbox images must be REAL, digest-pinned,
# proof-signed refs in a registry the node + pod + host all reach (G7 refuses
# ghcr.io/bmzee refs in prod). Both images re-home from their PUBLISHED
# canonical digests (core/config.py defaults) — pull, re-tag, push, cosign-sign
# under the per-run proof canonical key. NO fixture flag, real TLS.
REGISTRY_NAME="cognic-proof-m85-registry"
# Host port for the local TLS registry. 5000 collides with macOS AirPlay
# Receiver (ControlCenter listens on *:5000 — hit live 2026-07-03), so default
# to an uncommon port; override via COGNIC_PROOF_M85_REGISTRY_PORT. The
# preflight fail-loud-probes it before any cluster work starts.
REGISTRY_PORT="${COGNIC_PROOF_M85_REGISTRY_PORT:-5551}"
# ONE ref string everywhere. Resolution per context (live-probed 2026-07-03):
#   * host docker daemon (push) + host cosign: via the /etc/hosts loopback
#     entry verified at preflight (the daemon CANNOT resolve docker-network
#     aliases); 127.0.0.1:$REGISTRY_PORT reaches the published port.
#   * kind node containerd: docker-network DNS on the `kind` bridge.
#   * kernel pod (in-pod cosign at sandbox admission): the deterministic
#     hostAliases patch at step 8 (registry kind-net IP).
REGISTRY_REF_HOST="$REGISTRY_NAME:$REGISTRY_PORT"
# Persistent local-proof TLS material for the registry — minted ONCE at
# preflight (no sudo; ~/.cognic mirrors the pack-signing key-custody
# convention) and REUSED across runs so the one-time operator certs.d trust
# stays valid. Each run COPIES it into the per-run $CANONICAL_DIR so every
# downstream consumer (registry mount, SSL_CERT_FILE, the kernel-image trust
# bundle) reads one location, unchanged.
REGISTRY_TLS_DIR="${COGNIC_PROOF_M85_REGISTRY_TLS_DIR:-$HOME/.cognic/proof-m85/registry-tls}"
# The PUBLISHED canonical images (Settings defaults; re-homed + re-signed here).
# Pinned digests from core/config.py sandbox_canonical_runtime_python_image +
# sandbox_canonical_egress_proxy_image.
PUBLISHED_RUNTIME_PYTHON="ghcr.io/bmzee/cognic-agentos/sandbox-runtime-python@sha256:b9ed3440ebf8535ba779f574b3c12a45095720ce78c292d8cc5cd338990e8eac"
PUBLISHED_EGRESS_PROXY="ghcr.io/bmzee/cognic-agentos/sandbox-egress-proxy@sha256:eb4ea75b427d0bc42039c68039eec51d6b0d0789400ba5bfdbf470ebec9139aa"
RUNTIME_PYTHON_REF=""                               # filled after push+sign (digest-pinned)
EGRESS_PROXY_REF=""                                 # filled after push+sign (digest-pinned)

die() { echo "FAIL: $*" >&2; exit 1; }

# The backend image refs, sourced from backends.yaml (DRY — stays in sync with the
# smoke backends; awk field $2 ignores the trailing "# …" comment on each image: line).
_backend_images() {
  awk '/^[[:space:]]*image:/ {print $2}' "$CHART/ci/smoke/backends.yaml"
}

# Extra (non-backend) images the proof references with imagePullPolicy: IfNotPresent —
# pre-pulled + kind-loaded so the kind node never reaches the internet for them:
# oracle-xe + busybox (the oracle-pack wait-for-xe + the topology-perms init) +
# redis (the scheduler control plane) + registry:2 (the local TLS registry) +
# the OTLP collector (inherited diagnostics — ruling R6: NO M8.5 bar depends
# on spans; manifests/otel-collector.yaml).
_extra_images() {
  printf '%s\n' "gvenzl/oracle-xe:21-slim" "busybox:1.36" "redis:7.4-alpine" "registry:2" \
    "otel/opentelemetry-collector:0.111.0"
}

docker_pull_with_retry() {
  local img="$1"
  # 8 x 10s (~80s window): a transient resolver blip NXDOMAINed ghcr.io for
  # longer than the old 5 x 3s window could ride out (M6 run 8, 2026-07-04).
  local max=8
  local attempt=1
  if [[ "${COGNIC_PROOF_M85_REUSE_IMAGES:-0}" == "1" ]] && docker image inspect "$img" >/dev/null 2>&1; then
    echo "  using cached image $img (COGNIC_PROOF_M85_REUSE_IMAGES=1)"
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
    echo "docker pull failed for $img (attempt $attempt/$max); retrying in 10s" >&2
    attempt=$((attempt + 1))
    sleep 10
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
# pod — and the agent's dispatched run_readonly_query rides that same MCPHost.
roll_and_wait() {
  kubectl -n "$NS" rollout restart deploy/rel-agentos
  kubectl -n "$NS" rollout status deploy/rel-agentos --timeout=600s \
    || agentos_fail "rel-agentos rollout did not complete within 600s"
  kubectl -n "$NS" wait --for=condition=ready pod -l app.kubernetes.io/name=agentos --timeout=600s \
    || agentos_fail "rel-agentos pod did not become Ready within 600s"
}

# ---- Multi-actor API helpers (drive the REAL operator + agent API via X-Proof-Role)
# api <ROLE> <METHOD> <PATH> [JSON_BODY] -> stdout is the response body; sets HTTP_CODE.
# The role header selects the proof Actor (author/reviewer/operator/mcp/amir/sara);
# tenant + originator come from the bound Actor, never the URL. The two ANALYST
# roles carry ONLY the four conversation.* scopes (ruling 2026-07-10 — no
# agent.ask; the slice exercises the conversation surface exclusively); the
# kernel-side entitlement matrix keys on their subjects (analyst.amir /
# analyst.sara).
HTTP_CODE=""
# Both paths are assigned under the private per-run $QC_TMP after it is
# minted (finding 2, 2026-07-10 — never shared /tmp); api() refuses loud if
# called earlier (mirrors the PSQL guard).
HTTP_CODE_FILE=""
API_RESP_FILE=""
load_http_code() {
  HTTP_CODE="$(cat "$HTTP_CODE_FILE" 2>/dev/null || true)"
}

api() {
  local role="$1" method="$2" path="$3" body="${4:-}"
  local out
  [ -n "$HTTP_CODE_FILE" ] && [ -n "$API_RESP_FILE" ] \
    || die "api() called before QC_TMP was minted (programming error)"
  if [ -n "$body" ]; then
    out="$(curl -s -o "$API_RESP_FILE" -w '%{http_code}' -X "$method" \
      -H "X-Proof-Role: $role" -H 'Content-Type: application/json' \
      -d "$body" "$BASE_URL$path")"
  else
    out="$(curl -s -o "$API_RESP_FILE" -w '%{http_code}' -X "$method" \
      -H "X-Proof-Role: $role" "$BASE_URL$path")"
  fi
  HTTP_CODE="$out"
  printf '%s' "$out" > "$HTTP_CODE_FILE"
  cat "$API_RESP_FILE"
}

# ask <ROLE> <QUESTION> — one governed single-shot run via the A13 ask route.
# The question is JSON-encoded via python3 so quoting can never corrupt the body.
# NOTE: the ask route can take minutes end-to-end (cloud model, several rounds)
# — curl has no per-call timeout here; the loop's own wall-clock bound governs.
# ---- Conversation-surface helpers (the ONLY analyst surface in this slice) --------
# There is deliberately NO ask() helper and the analyst roles carry NO agent.ask
# scope (ruling 2026-07-10): the M8.5 slice exercises the conversation surface
# exclusively — a stray single-shot /ask would 403.

# conv_create <ROLE> — POST /api/v1/conversations for bank-analyst; prints the body.
conv_create() {
  local role="$1" body
  body="$(python3 -c 'import json,sys; print(json.dumps({"agent_id": sys.argv[1]}))' "$AGENT_ID")"
  api "$role" POST "/api/v1/conversations" "$body"
}

# conv_turn <ROLE> <CONVERSATION_ID> <MESSAGE> — POST one governed turn. The
# message is JSON-encoded via python3 so quoting can never corrupt the body.
# NOTE: a turn can take minutes end-to-end (cloud model, several dispatch
# rounds) — curl has no per-call timeout here; the loop's own wall-clock bound
# governs, and the conversation claim TTL (600s) exceeds it by design.
conv_turn() {
  local role="$1" cid="$2" message="$3" body
  body="$(python3 -c 'import json,sys; print(json.dumps({"user_message": sys.argv[1]}))' "$message")"
  api "$role" POST "/api/v1/conversations/$cid/turns" "$body"
}

# conv_get <ROLE> <CONVERSATION_ID> — GET the conversation record.
conv_get() {
  local role="$1" cid="$2"
  api "$role" GET "/api/v1/conversations/$cid"
}

# json_field <FIELD> <JSON> — a top-level string/number field, or "" when absent.
# Args are (field, json): the body reads json.loads(argv[2]).get(argv[1]), so the
# JSON must land in argv[2] and the field name in argv[1] — pass "$1" "$2" in order.
# (Swapping them makes json.loads() parse the bare field name, which raises and is
# swallowed by the trailing `|| true`, silently yielding "" — the M8 run-12 BAR-1
# false failure where terminal_state read '' though the body carried "completed".)
json_field() {
  python3 -c 'import json,sys; v=json.loads(sys.argv[2]).get(sys.argv[1]); print("" if v is None else v)' \
    "$1" "$2" 2>/dev/null || true
}

# json_assert <LABEL> <PY_SOURCE> [ARGS...] — an inline python3 predicate over
# JSON args, fail-capturing (mirrors the PSQL discipline, run-3 finding): the
# python body must print exactly "ok" on success; ANY nonzero exit, traceback,
# or non-ok output routes through bar_fail WITH the captured detail preserved
# (a raised assertion inside a bare command substitution would abort the
# runner under `set -e` with no failure capture).
json_assert() {
  local label="$1" src="$2"
  shift 2
  local out rc
  set +e
  out="$(python3 -c "$src" "$@" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ] || [ "$out" != "ok" ]; then
    bar_fail "$label (rc=$rc): ${out:-<no output>}"
  fi
}

# discovery_status of the TOOL pack row from GET /system/plugins?tenant_id=proof-m85.
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

# ---- Evidence helpers (the BAR chain reads — EVERY query tenant-scoped) ----------
# Ruling 2026-07-10: every evidence query carries tenant_id='proof-m85'
# (decision_history + audit_event carry the column directly;
# conversation_turns has no tenant column, so its reads JOIN conversations
# and scope on c.tenant_id).
#
# PSQL is the SOLE load-bearing SQL path (run-3 finding, 2026-07-10: a raw
# psql SQL error inside a command substitution aborted the runner under
# `set -e` with NO failure capture). A nonzero psql routes through bar_fail
# WITH the psql error text preserved: bar_fail runs inside the caller's
# subshell — its capture side effects persist, its exit ends the subshell
# nonzero, and the parent's `set -e` keeps the runner's exit nonzero.
# Tolerant DIRECT psql is permitted ONLY inside bar_fail's own diagnostics
# (structurally pinned) — everything load-bearing goes through here.
PSQL() {
  local sql="$1" out rc err_file
  # The stderr capture lives under the per-run PRIVATE $QC_TMP (0700, minted
  # by mktemp -d, removed by the cleanup trap) — review finding 2026-07-10:
  # a predictable shared /tmp path is a symlink/truncation hazard AND leaks
  # residue past the run. PSQL is only callable AFTER the key-mint step;
  # calling it earlier is a programming error, refused loud.
  [ -n "${QC_TMP:-}" ] || die "PSQL called before QC_TMP was minted (programming error)"
  err_file="$QC_TMP/psql-err"
  set +e
  out="$(kubectl -n "$NS" exec -i deploy/postgres -- psql -U cognic -d cognic -tA -c "$sql" 2>"$err_file")"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    bar_fail "load-bearing SQL failed (psql rc=$rc; sql: $sql; psql: $(cat "$err_file" 2>/dev/null || echo '<no stderr captured>'))"
  fi
  printf '%s\n' "$out"
}

# Count of successful executions for ONE tool name (payload->>'tool_name') —
# the "did a tool actually run?" downstream axis (BAR 1 raises it; BAR 2's
# zero-loop pin holds the whole agent.run.% axis flat instead).
tool_invocation_count_for() {
  local tool_name="$1"
  PSQL "SELECT count(*) FROM audit_event WHERE event_type='audit.tool_invocation' AND tenant_id='$TENANT' AND payload->>'tool_name'='$tool_name';"
}

# Dispatch-chokepoint evidence: agent.run.dispatch rows for ONE run, optionally
# narrowed by an extra SQL predicate over the payload (A10: one digest-only row
# per dispatch on EVERY arm; actor_id = the ORIGINATOR, agent_id in payload).
run_dispatch_count() {
  local run_id="$1" extra="${2:-}"
  PSQL "SELECT count(*) FROM decision_history WHERE event_type='agent.run.dispatch' AND tenant_id='$TENANT' AND payload->>'run_id'='$run_id'${extra:+ AND $extra};"
}

# Run-level rows (started / dispatch / terminal) violating the ADR-027 §f dual
# identity for the run: EVERY row must carry actor_id == the originator subject
# AND payload agent_id == bank-analyst. Expected: 0.
run_dual_identity_violations() {
  local run_id="$1" subject="$2"
  PSQL "SELECT count(*) FROM decision_history WHERE event_type LIKE 'agent.run.%' AND tenant_id='$TENANT' AND payload->>'run_id'='$run_id' AND (payload->>'actor_id' IS DISTINCT FROM '$subject' OR payload->>'agent_id' IS DISTINCT FROM '$AGENT_ID');"
}

run_event_count() {
  local run_id="$1" event="$2"
  PSQL "SELECT count(*) FROM decision_history WHERE event_type='$event' AND tenant_id='$TENANT' AND payload->>'run_id'='$run_id';"
}

# ---- Conversation evidence helpers (the ADR-028 chain + erasable-store axes) ------

# conversation.% chain rows for ONE conversation, optionally narrowed.
conv_event_count() {
  local cid="$1" event="$2" extra="${3:-}"
  PSQL "SELECT count(*) FROM decision_history WHERE event_type='$event' AND tenant_id='$TENANT' AND payload->>'conversation_id'='$cid'${extra:+ AND $extra};"
}

# Hop 1 of the three-hop join: conversation.turn_completed(seq) -> agent_run_id.
conv_turn_run_id() {
  local cid="$1" seq="$2"
  PSQL "SELECT payload->>'agent_run_id' FROM decision_history WHERE event_type='conversation.turn_completed' AND tenant_id='$TENANT' AND payload->>'conversation_id'='$cid' AND payload->>'seq'='$seq';"
}

# A digest field off the seq's turn_completed chain row (question_sha256 /
# answer_sha256 / prompt_tokens / ...).
conv_turn_chain_field() {
  local cid="$1" seq="$2" field="$3"
  PSQL "SELECT payload->>'$field' FROM decision_history WHERE event_type='conversation.turn_completed' AND tenant_id='$TENANT' AND payload->>'conversation_id'='$cid' AND payload->>'seq'='$seq';"
}

# conversation.% rows violating the creator identity: EVERY conversation.% row
# for the conversation must carry actor_id == the creator subject. Expected: 0.
conv_dual_identity_violations() {
  local cid="$1" subject="$2"
  PSQL "SELECT count(*) FROM decision_history WHERE event_type LIKE 'conversation.%' AND tenant_id='$TENANT' AND payload->>'conversation_id'='$cid' AND payload->>'actor_id' IS DISTINCT FROM '$subject';"
}

# Plaintext from the ERASABLE store (conversation_turns has no tenant column —
# scope rides the JOIN to conversations.tenant_id). base64-wrapped so newlines
# and quotes inside the plaintext survive the kubectl/psql pipe intact for the
# digest recompute.
conv_turn_plaintext_b64() {
  local cid="$1" seq="$2" col="$3"
  PSQL "SELECT encode(convert_to(t.$col, 'UTF8'), 'base64') FROM conversation_turns t JOIN conversations c ON c.conversation_id = t.conversation_id WHERE c.tenant_id='$TENANT' AND t.conversation_id='$cid' AND t.seq=$seq;" | tr -d '\n'
}

# assert_turn_digest_coupling <CID> <SEQ> — the digest<->plaintext coupling pin:
# the seq's turn_completed chain digests equal sha256 of the stored plaintext.
assert_turn_digest_coupling() {
  local cid="$1" seq="$2" q_b64 a_b64 q_sha a_sha q_chain a_chain
  q_b64="$(conv_turn_plaintext_b64 "$cid" "$seq" user_message)"
  a_b64="$(conv_turn_plaintext_b64 "$cid" "$seq" answer)"
  [ -n "$q_b64" ] || bar_fail "digest coupling ($cid seq $seq) — no user_message plaintext row"
  [ -n "$a_b64" ] || bar_fail "digest coupling ($cid seq $seq) — no answer plaintext row"
  q_sha="$(python3 -c 'import base64,hashlib,sys; print(hashlib.sha256(base64.b64decode(sys.argv[1])).hexdigest())' "$q_b64")"
  a_sha="$(python3 -c 'import base64,hashlib,sys; print(hashlib.sha256(base64.b64decode(sys.argv[1])).hexdigest())' "$a_b64")"
  q_chain="$(conv_turn_chain_field "$cid" "$seq" question_sha256)"
  a_chain="$(conv_turn_chain_field "$cid" "$seq" answer_sha256)"
  [ "$q_sha" = "$q_chain" ] || bar_fail "digest coupling ($cid seq $seq) — question_sha256 chain=$q_chain recomputed=$q_sha"
  [ "$a_sha" = "$a_chain" ] || bar_fail "digest coupling ($cid seq $seq) — answer_sha256 chain=$a_chain recomputed=$a_sha"
}

# The BAR-3 entitlement axis (kernel-side rows the dispatch gate 2 reads live).
entitlement_count() {
  local subject="$1" scope="$2"
  PSQL "SELECT count(*) FROM entitlements WHERE tenant_id='$TENANT' AND subject='$subject' AND scope_id='$scope';"
}

entitlement_delete() {
  local subject="$1" scope="$2"
  PSQL "DELETE FROM entitlements WHERE tenant_id='$TENANT' AND subject='$subject' AND scope_id='$scope';"
}

entitlement_restore() {
  local subject="$1" scope="$2"
  PSQL "INSERT INTO entitlements (id, tenant_id, subject, scope_id, created_at) VALUES (gen_random_uuid(), '$TENANT', '$subject', '$scope', now()) ON CONFLICT ON CONSTRAINT uq_entitlements_tenant_subject_scope DO NOTHING;"
}

# ---- Answer-shape helpers ---------------------------------------------------------
# No stack trace / no raw engine error may ever reach an analyst-visible answer
# (the tool envelope carries closed-form messages + exception CLASS names only).
assert_no_stack_trace() {
  local where="$1" answer="$2"
  if grep -qF "Traceback (most recent call last)" <<<"$answer"; then
    bar_fail "$where — a Python stack trace leaked into the answer"
  fi
  if grep -qE 'ORA-[0-9]{5}' <<<"$answer"; then
    bar_fail "$where — a raw Oracle engine error leaked into the answer"
  fi
}

# ---- Step-0 hosted/registered surface asserts -------------------------------------
# ALL SIX M8 packs + the hook dependency registered; the 4 instruction skills
# hosted (hosted_skills — the surface that exists only on the sandbox-real
# path, the M6 posture unchanged); bank-analyst hosted (hosted_agents) with
# EXACTLY the requested capability sets the kernel seed grants.
assert_m8_surfaces() {
  local where="$1" body
  body="$(curl -sf "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
  [ -n "$body" ] || bar_fail "$where — /api/v1/system/plugins unreachable for the M8 surface probe"
  if ! python3 - "$body" <<'PY'
import json, sys

doc = json.loads(sys.argv[1])
plugins = {p.get("pack_id"): p for p in doc.get("plugins", [])}
expected_kinds = {
    "cognic-tool-oracle-schema": "tools",
    "cognic-hook-schema-guard": "hooks",
    "cognic-skill-customer-data": "skills",
    "cognic-skill-financial-data": "skills",
    "cognic-skill-cards-data": "skills",
    "cognic-skill-atm-recon": "skills",
    "cognic-agent-bank-analyst": "agents",
}
failures: list[str] = []
for pack_id, kind in expected_kinds.items():
    row = plugins.get(pack_id)
    if row is None:
        failures.append(f"{pack_id}: no registered candidate row")
        continue
    if row.get("status") != "registered" or row.get("kind") != kind:
        failures.append(
            f"{pack_id}: status={row.get('status')!r} kind={row.get('kind')!r} "
            f"refusal_reason={row.get('refusal_reason')!r} (expected registered/{kind})"
        )

hosted_skills = {h.get("skill_id") for h in doc.get("hosted_skills", [])}
for skill_id in ("customer-data", "financial-data", "cards-data", "atm-recon"):
    if skill_id not in hosted_skills:
        failures.append(f"instruction skill {skill_id}: not in hosted_skills")

agents = {a.get("agent_id"): a for a in doc.get("hosted_agents", [])}
agent = agents.get("bank-analyst")
if agent is None:
    failures.append("bank-analyst: not in hosted_agents (loop composition failed?)")
else:
    if set(agent.get("requested_skills") or []) != {"customer-data", "financial-data", "cards-data"}:
        failures.append(f"bank-analyst requested_skills wrong: {agent.get('requested_skills')!r}")
    if list(agent.get("requested_tools") or []) != ["cognic-tool-oracle-schema/run_readonly_query"]:
        failures.append(f"bank-analyst requested_tools wrong: {agent.get('requested_tools')!r}")
    if agent.get("max_steps") != 6:
        failures.append(f"bank-analyst max_steps wrong: {agent.get('max_steps')!r}")
    if agent.get("risk_tier") != "customer_data_read":
        failures.append(f"bank-analyst risk_tier wrong: {agent.get('risk_tier')!r}")

if failures:
    for failure in failures:
        print(failure, file=sys.stderr)
    raise SystemExit(1)
print(
    "  M8 surfaces OK: 7 packs registered (tools/hooks/4x skills/agents), "
    "4 instruction skills hosted, bank-analyst hosted (requested sets + tier verified)"
)
PY
  then
    bar_fail "$where — M8 registered/hosted surface assert failed (plugins/hosted_skills/hosted_agents)"
  fi
  local boot_errs
  # Fail LOUD on any fail-soft construction failure or any per-pack warn-skip:
  # every one of these leaves a bar-load-bearing surface silently absent
  # (agent loop -> 503; skill executor -> no hosted_skills; agent/skill
  # ingest skips -> missing hosted rows).
  boot_errs="$(kubectl -n "$NS" logs deploy/rel-agentos 2>/dev/null \
    | grep -E 'agent.loop_construction_failed|agent.loop_composition_warning|skill.executor_construction_failed|sandbox.runtime_construction_failed|agent\.(pack_manifest_malformed|agent_md_not_found|agent_md_invalid|requested_skills_malformed|requested_tools_malformed|max_steps_invalid|risk_tier_missing|duplicate_agent_id)|skill\.(pack_manifest_malformed|mode_invalid|instruction_mode_declares_executable|skill_md_not_found|skill_md_invalid|duplicate_skill_id)' \
    || true)"
  [ -z "$boot_errs" ] \
    || bar_fail "$where — agent/skill/sandbox construction or ingest failures in boot logs: $boot_errs"
}

# ---- Hook-pack registry-admission preflight (M5/M6-inherited) ---------------------
# The oracle v0.3.0 manifest binds dlp_pre hooks; the hook pack must be admitted
# at boot or every governed tool call (incl. the agent's run_readonly_query)
# fail-closes at the DLP gate.
assert_hook_pack_registered() {
  local where="$1" body hook_errs
  body="$(curl -sf "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
  [ -n "$body" ] || bar_fail "$where — /api/v1/system/plugins unreachable for the hook-pack probe"
  if ! python3 - "$HOOK_PACK_ID" "$body" <<'PY'
import json, sys
pack_id, raw = sys.argv[1], sys.argv[2]
doc = json.loads(raw)
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
print(f"  hook pack registry-admitted: {pack_id} kind=hooks status=registered")
PY
  then
    bar_fail "$where — hook pack not registry-admitted (trust-register-at-boot failed)"
  fi
  hook_errs="$(kubectl -n "$NS" logs deploy/rel-agentos 2>/dev/null \
    | grep -E 'dlp_guard_construction_failed|hook_pack_trust_root_invalid|hook\.(pack_manifest_malformed|registry_refused)' \
    || true)"
  [ -z "$hook_errs" ] \
    || bar_fail "$where — hook admission / DLP-guard failures in boot logs: $hook_errs"
}

# ---- Failure diagnostics (mirror proof-m6: capture then exit non-zero) ------------
bar_fail() {
  local where="$1"
  echo "FAIL: $where — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local logs litellm_logs ds conv_rows conv_records run_rows dispatch_rows tool_audit ledger_rows memwrite otel_tail reason
  logs="$(kubectl -n "$NS" logs deploy/rel-agentos 2>&1 | tail -180 || true)"
  # The M8.5 conversation axes: the digest-only chain rows + the operational
  # records (plaintext deliberately NOT captured — digests + counters only).
  conv_rows="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT event_type, payload::text FROM decision_history WHERE event_type LIKE 'conversation.%' AND tenant_id='$TENANT' ORDER BY sequence DESC LIMIT 10;" 2>/dev/null || true)"
  conv_records="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT conversation_id || ' | ' || state || ' | turns=' || turn_count || ' | tokens=' || cumulative_tokens || ' | in_progress=' || turn_in_progress FROM conversations WHERE tenant_id='$TENANT' ORDER BY created_at DESC LIMIT 6;" 2>/dev/null || true)"
  # M8 finding #7: on an upstream_error the litellm router's OWN logs carry
  # the real reason (e.g. "No connected db", provider auth) the gateway's
  # raise_for_status() drops — capture them so a gateway/bar failure is
  # self-diagnosing without a local repro.
  litellm_logs="$(kubectl -n "$NS" logs deploy/litellm 2>&1 | tail -120 || true)"
  ds="$(curl -s "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
  run_rows="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT event_type, payload::text FROM decision_history WHERE event_type LIKE 'agent.run.%' AND event_type <> 'agent.run.dispatch' AND tenant_id='$TENANT' ORDER BY sequence DESC LIMIT 10;" 2>/dev/null || true)"
  dispatch_rows="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT payload::text FROM decision_history WHERE event_type='agent.run.dispatch' AND tenant_id='$TENANT' ORDER BY sequence DESC LIMIT 12;" 2>/dev/null || true)"
  tool_audit="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT event_type, payload::text FROM audit_event WHERE (event_type LIKE 'audit.tool_invocation%' OR event_type='gateway.cloud_policy_denied') AND tenant_id='$TENANT' ORDER BY sequence DESC LIMIT 12;" 2>/dev/null || true)"
  ledger_rows="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT request_id || ' | ' || litellm_alias || ' | ' || upstream_model || ' | external=' || external || ' | ' || provenance || ' | ' || outcome FROM gateway_call_ledger WHERE tenant_id='$TENANT' ORDER BY ts DESC LIMIT 8;" 2>/dev/null || true)"
  memwrite="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT payload::text FROM decision_history WHERE event_type='memory.write' AND tenant_id='$TENANT' ORDER BY sequence DESC LIMIT 4;" 2>/dev/null || true)"
  otel_tail="$(kubectl -n "$NS" logs deploy/otel-collector 2>/dev/null | tail -60 || true)"
  reason="$(grep -Eo 'conversation_[a-z_]+|conversation\.composition_failed|agent_[a-z_]+|sql_[a-z_]+|query_context_[a-z_]+|mcp_[a-z_]+|dlp_[a-z_]+|agent\.loop_[a-z_]+|skill\.executor_construction_failed|sandbox\.runtime_construction_failed|discovery_status=[a-z_]+' <<<"$logs" | sort -u || true)"
  {
    echo ""
    echo "## Proof M8.5 slice — FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- last API response (HTTP $HTTP_CODE):"
    echo '```json'
    cat "$API_RESP_FILE" 2>/dev/null || echo "<no response captured>"
    echo ""
    echo '```'
    echo "- conversation.% chain rows (tail 10 — digest-only):"
    echo '```'
    echo "${conv_rows:-<none>}"
    echo '```'
    echo "- conversations operational records (tail 6 — no plaintext):"
    echo '```'
    echo "${conv_records:-<none>}"
    echo '```'
    echo "- agent / dispatch / gateway reason markers:"
    echo '```'
    echo "${reason:-<none captured>}"
    echo '```'
    echo "- agent.run.% run rows (tail 10 — started/terminal, digest-only):"
    echo '```'
    echo "${run_rows:-<none>}"
    echo '```'
    echo "- agent.run.dispatch rows (tail 12 — the A10 chokepoint axis):"
    echo '```'
    echo "${dispatch_rows:-<none>}"
    echo '```'
    echo "- audit.tool_invocation% + gateway.cloud_policy_denied (tail 12):"
    echo '```'
    echo "${tool_audit:-<none>}"
    echo '```'
    echo "- gateway_call_ledger (tail 8 — the ADR-007 honesty axis):"
    echo '```'
    echo "${ledger_rows:-<none>}"
    echo '```'
    echo "- litellm router logs (tail 120 — finding #7 upstream-reason surface):"
    echo '```'
    echo "${litellm_logs:-<none>}"
    echo '```'
    echo "- memory.write rows (tail 4 — the task-tier digest axis):"
    echo '```'
    echo "${memwrite:-<none>}"
    echo '```'
    echo "- /api/v1/system/plugins snapshot (plugins + hosted_skills + hosted_agents):"
    echo '```json'
    echo "${ds:-<no response>}"
    echo '```'
    echo "- otel-collector log (tail 60 — inherited diagnostics; no M8.5 bar depends on spans):"
    echo '```'
    echo "${otel_tail:-<none>}"
    echo '```'
    echo "- AgentOS pod logs (tail 180):"
    echo '```'
    echo "$logs"
    echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

# Step-5 XE-readiness failure path (mirrors proof-m6 xe_fail).
xe_fail() {
  local where="$1"
  echo "FAIL: oracle-xe ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local pods desc logs
  pods="$(kubectl -n "$NS" get pods 2>&1 || true)"
  desc="$(kubectl -n "$NS" describe pod -l app=oracle-xe 2>&1 | tail -90 || true)"
  logs="$(kubectl -n "$NS" logs -l app=oracle-xe --tail=120 2>&1 || true)"
  {
    echo ""
    echo "## Proof M8.5 slice — Oracle XE readiness FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- pods:"; echo '```'; echo "$pods"; echo '```'
    echo "- oracle-xe describe (tail 90):"; echo '```'; echo "$desc"; echo '```'
    echo "- oracle-xe logs (tail 120):"; echo '```'; echo "$logs"; echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

# Step-5 backends-readiness failure path (mirrors proof-m6 backends_fail).
backends_fail() {
  local where="$1"
  echo "FAIL: backends ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local wide ddeploy dpods notready_logs p
  wide="$(kubectl -n "$NS" get deploy,pods -o wide 2>&1 || true)"
  ddeploy="$(kubectl -n "$NS" describe deploy -l 'app notin (oracle-xe)' 2>&1 | tail -120 || true)"
  dpods="$(kubectl -n "$NS" describe pod -l 'app notin (oracle-xe)' 2>&1 | tail -150 || true)"
  # Every not-ready backend pod gets its OWN logs + previous-instance logs +
  # describe (the M6 run-4/5 + run-18 capture findings: the fault pod must
  # survive the all-pods tail truncation). Comment kept OUTSIDE the command
  # substitution: macOS bash 3.2 mis-parses parens inside comments inside "$( ... )".
  notready_logs="$(for p in $(kubectl -n "$NS" get pods -l 'app notin (oracle-xe)' \
      -o jsonpath='{range .items[?(@.status.containerStatuses[0].ready==false)]}{.metadata.name}{"\n"}{end}' 2>/dev/null); do
    echo "----- logs: $p (tail 80) -----"
    kubectl -n "$NS" logs "$p" --tail=80 2>&1 || true
    echo "----- previous-instance logs: $p (tail 40) -----"
    kubectl -n "$NS" logs "$p" --tail=40 --previous 2>&1 || true
    echo "----- describe: $p (tail 60) -----"
    kubectl -n "$NS" describe pod "$p" 2>&1 | tail -60 || true
  done)"
  {
    echo ""
    echo "## Proof M8.5 slice — backends readiness FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- deploy + pods (-o wide):"; echo '```'; echo "$wide"; echo '```'
    echo "- backend deploy describe (tail 120):"; echo '```'; echo "$ddeploy"; echo '```'
    echo "- backend pod describe (tail 150):"; echo '```'; echo "$dpods"; echo '```'
    echo "- NOT-READY backend pod logs (current + previous instance):"; echo '```'; echo "${notready_logs:-<all backend pods ready at capture>}"; echo '```'
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
    echo "## Proof M8.5 slice — migration Job FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
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
    echo "## Proof M8.5 slice — AgentOS rollout FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
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
  docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
  # remove the transient build-context copies (NOT the sources); proof_m85/ is a
  # tracked in-context source, so it is NOT removed. The per-run PRIVATE
  # query-context key dir ($QC_TMP) is removed unconditionally — the private
  # PEM must never outlive the run on the operator host.
  rm -rf "$STAGING_DST" "$AGENTOS_SRC_DST" "$PROOF_DIR/policies" "$PROOF_DIR/_local_as.py" 2>/dev/null || true
  [ -n "${QC_TMP:-}" ] && rm -rf "$QC_TMP" 2>/dev/null || true
  # The per-run canonical SIGNING keypair dir (the run-2 custody fix): removed
  # unconditionally like $QC_TMP — the dev-grade signing key never outlives
  # the run on the operator host.
  [ -n "${CANONICAL_KEY_TMP:-}" ] && rm -rf "$CANONICAL_KEY_TMP" 2>/dev/null || true
}
trap cleanup EXIT

# --- 1. preflight -----------------------------------------------------------------
echo "==> [1/11] tool preflight"
for tool in docker kind kubectl helm uv cosign syft grype curl python3 gh openssl; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool '$tool' not on PATH"
done
# Registry host-port preflight — fail LOUD with an actionable message here,
# not mid-run at `docker run -p` (macOS ControlCenter/AirPlay owns *:5000 by
# default, which is why the default moved to $REGISTRY_PORT).
python3 - "$REGISTRY_PORT" <<'PY' || die "registry port $REGISTRY_PORT already in use (lsof -nP -iTCP:$REGISTRY_PORT -sTCP:LISTEN shows the holder); override via COGNIC_PROOF_M85_REGISTRY_PORT"
import socket, sys

s = socket.socket()
try:
    s.bind(("0.0.0.0", int(sys.argv[1])))
finally:
    s.close()
PY

# Persistent registry TLS CA — mint ONCE if absent (no sudo; reused across
# runs so the one-time certs.d trust below keeps matching byte-for-byte).
if [ ! -f "$REGISTRY_TLS_DIR/registry-ca.pem" ]; then
  mkdir -p "$REGISTRY_TLS_DIR" && chmod 700 "$REGISTRY_TLS_DIR"
  openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout "$REGISTRY_TLS_DIR/registry-key.pem" \
    -out "$REGISTRY_TLS_DIR/registry-ca.pem" \
    -days 3650 -subj "/CN=$REGISTRY_NAME" \
    -addext "subjectAltName=DNS:$REGISTRY_NAME,DNS:localhost,IP:127.0.0.1"
  echo "  minted the persistent proof-registry TLS CA at $REGISTRY_TLS_DIR"
fi

# The runner is deliberately SUDO-FREE: a backgrounded run has no TTY for a
# password prompt (hit live 2026-07-03 — `sudo: a terminal is required`). The
# TWO root-owned trust prerequisites are ONE-TIME operator steps, verified
# fail-loud here with copy-paste instructions:
_setup_help() {
  cat >&2 <<EOF
FAIL: one-time operator trust setup missing ($1).
Run these once in a REAL terminal (sudo prompts for your password):
  sudo sh -c 'echo "127.0.0.1 $REGISTRY_NAME" >> /etc/hosts'
  sudo mkdir -p "/etc/docker/certs.d/$REGISTRY_REF_HOST"
  sudo install -m 0644 "$REGISTRY_TLS_DIR/registry-ca.pem" "/etc/docker/certs.d/$REGISTRY_REF_HOST/ca.crt"
Then re-run the proof. (Loopback-only + local-CA trust; removal:
  sudo sed -i '' "/[[:space:]]$REGISTRY_NAME\$/d" /etc/hosts
  sudo rm -rf "/etc/docker/certs.d/$REGISTRY_REF_HOST")
EOF
  exit 1
}
grep -qE "[[:space:]]$REGISTRY_NAME($|[[:space:]])" /etc/hosts \
  || _setup_help "/etc/hosts loopback entry for $REGISTRY_NAME"
# Readability first, with its own message: `sudo cp` of the 0600-mode CA
# leaves a root-unreadable ca.crt (hit live 2026-07-03 — cmp reads as the
# invoking user; docker itself reads as root and would NOT catch this), which
# is why the instructions use `install -m 0644` (a CA cert is public bytes).
[ -r "/etc/docker/certs.d/$REGISTRY_REF_HOST/ca.crt" ] \
  || _setup_help "certs.d ca.crt absent or not world-readable (use install -m 0644, not cp)"
cmp -s "$REGISTRY_TLS_DIR/registry-ca.pem" "/etc/docker/certs.d/$REGISTRY_REF_HOST/ca.crt" \
  || _setup_help "docker certs.d trust of the persistent proof CA at /etc/docker/certs.d/$REGISTRY_REF_HOST/ca.crt"

# --- 1b. proof-input cleanliness (provenance — finding 5, 2026-07-10) ---------------
# The kernel-source guard (section 3) covers the OVERLAY inputs; this one
# covers the PROOF inputs the run executes — the runner itself, the proof
# app, the Dockerfiles/manifests/values/seeds, the chart, the base-image
# Dockerfile, the structural suite, and the AS executable source
# (tests/integration/pack_loop/_local_as.py — copied into the proof
# authentication-server image). Runs BEFORE anything materializes
# (staging/copies land under infra/proof-m85 and are NOT gitignored), so a
# dirty state here is genuinely operator-authored or stale residue from an
# aborted run — either way the evidence would cite HEAD while different
# proof code executed. docs/VALIDATION-RESULTS.md is deliberately excluded
# (failure captures append to it).
PROOF_INPUT_DIRTY="$(git status --porcelain -- infra/proof-m85 infra/charts/agentos infra/agentos tests/unit/infra/test_proof_m85_structure.py tests/integration/pack_loop/_local_as.py)"
if [ -n "$PROOF_INPUT_DIRTY" ]; then
  die "proof inputs are DIRTY — the evidence would cite HEAD while different proof code executes. Commit, stash, or clean first:
$PROOF_INPUT_DIRTY"
fi
echo "==> [1/11] proof-input cleanliness OK (proof dir + chart + base Dockerfile + structural suite)"

# --- 2. stage the SEVEN RELEASED packs (download + sha256-verify + arrange) --------
echo "==> [2/11] stage the released packs via stage-packs.sh (download, not build)"
rm -rf "$STAGING_DST"
bash "$PROOF_DIR/stage-packs.sh" "$STAGING_DST"

# --- 2b. mint the proof canonical-image trust material (baked into the kernel image)
# The proof canonical cosign keypair (dev-grade, per-run, never reused) + the local
# TLS registry's self-signed CA. Both are baked into the kernel image by
# Dockerfile.agentos-proof (canonical-trust/cosign.pub -> the admission trust root;
# canonical-trust/registry-ca.pem -> the SSL_CERT_FILE bundle) so the in-pod cosign
# verify trusts the proof registry's TLS + the proof canonical signatures.
echo "==> [2/11] mint the proof canonical cosign keypair + stage the persistent registry TLS cert"
# Custody split (the run-2 live finding — the in-run guard below caught the
# original shape copying registry-key.pem AND minting cosign.key inside the
# build context): ONLY PUBLIC material enters $CANONICAL_DIR (the docker build
# context). The canonical SIGNING key lives in a 0700 mktemp OUTSIDE staging
# (host-side `cosign sign` reads it at the re-home step; the image needs only
# cosign.pub), and the registry TLS PRIVATE key never leaves $REGISTRY_TLS_DIR
# (the registry container mounts it directly). proof-m6 carries the same
# latent copy (run-proof-m6.sh:638) — reported as a follow-up finding.
mkdir -p "$CANONICAL_DIR"
CANONICAL_KEY_TMP="$(mktemp -d)"
chmod 700 "$CANONICAL_KEY_TMP"
export COSIGN_PASSWORD=""   # dev-grade proof key; empty password (NEVER a production key — custody is a Human-only decision per build-and-sign.md)
( cd "$CANONICAL_KEY_TMP" && cosign generate-key-pair )   # -> cosign.key + cosign.pub OUTSIDE the build context
cp "$CANONICAL_KEY_TMP/cosign.pub" "$CANONICAL_DIR/cosign.pub"
cp "$REGISTRY_TLS_DIR/registry-ca.pem" "$CANONICAL_DIR/"
chmod -R a+rX "$CANONICAL_DIR"

# --- 2c. mint the per-run QUERY-CONTEXT keypair (ADR-027 §c key custody) -----------
# RS256 needs an RSA keypair. The PUBLIC PEM is staged into the build contexts
# (proof-m85-staging/query-context/ -> baked into BOTH images: the kernel's
# verification surfaces + the oracle-pack Service's
# COGNIC_QUERY_CONTEXT_PUBLIC_KEYS verifier). The PRIVATE PEM NEVER enters any
# build context or image layer: it is written to a 0700 mktemp dir OUTSIDE the
# staging tree, shipped ONLY as the k8s Secret `proof-m85-query-context`
# (mounted at /run/cognic/query-context — the exact path the image ENV
# COGNIC_AGENT_QUERY_CONTEXT_SIGNING_KEY_PATH references), and removed by the
# cleanup trap. An unreadable/missing key fails the loop composition loud (the
# ask route 503s; Step 0's hosted_agents assert catches it).
echo "==> [2/11] mint the per-run query-context keypair (public -> staging; PRIVATE -> Secret only)"
QC_TMP="$(mktemp -d)"
chmod 700 "$QC_TMP"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "$QC_TMP/query-context-private.pem"
chmod 600 "$QC_TMP/query-context-private.pem"
mkdir -p "$STAGING_DST/query-context"
openssl pkey -in "$QC_TMP/query-context-private.pem" -pubout \
  -out "$STAGING_DST/query-context/query-context-public.pem"
chmod a+r "$STAGING_DST/query-context/query-context-public.pem"
# Guard the custody invariant in-run: no private key material below the staging
# tree (the docker build contexts) — belt-and-braces on top of the structural test.
if grep -rlE "PRIVATE KEY-----" "$STAGING_DST" >/dev/null 2>&1; then
  die "custody violation: private key material found under $STAGING_DST (must never enter a build context)"
fi

# Provider-key custody (finding 1, 2026-07-10): the key must NEVER ride a
# process argument vector — `--from-literal=...="$KEY"` exposed it to any
# local `ps` for the kubectl lifetime. The EXPORTED variable was already
# dropped at the preflight (round-3 finding 1: no child inherits it); the
# non-exported local persists to a 0600 file under the private per-run dir
# (printf is a bash BUILTIN — no exec, no argv) and is retired here. The
# Secret is created --from-file; the file dies with $QC_TMP (cleanup trap).
PROVIDER_KEY_FILE="$QC_TMP/tier1-api-key"
( umask 077; printf '%s' "$_PROVIDER_KEY_LOCAL" > "$PROVIDER_KEY_FILE" )
unset _PROVIDER_KEY_LOCAL

# The api() response/status files live under the SAME private dir (finding 2,
# 2026-07-10: predictable mode-0644 shared-/tmp paths persisted transcript
# plaintext past the run and permitted symlink/truncation attacks).
HTTP_CODE_FILE="$QC_TMP/http-code"
API_RESP_FILE="$QC_TMP/api-resp"

# --- 3. build the three images ------------------------------------------------------
echo "==> [3/11] resolve the kernel source revision (provenance — finding 2, 2026-07-10)"
# The image label must name the EXACT revision of the kernel source the
# overlay copies below — a hardcoded anchor goes stale the moment the branch
# moves, and a dirty tree would label a revision the source does not match.
KERNEL_GIT_SHA="$(git rev-parse HEAD)"
KERNEL_TREE_DIRTY="$(git status --porcelain -- src alembic.ini pyproject.toml uv.lock policies)"
if [ -n "$KERNEL_TREE_DIRTY" ]; then
  die "kernel source tree is DIRTY — the kernel-anchor label would be false. Commit or stash first:
$KERNEL_TREE_DIRTY"
fi
echo "    kernel revision: $KERNEL_GIT_SHA (kernel-source tree clean)"

echo "==> [3/11] copy the current kernel source into the proof build context (the M8 wiring)"
rm -rf "$AGENTOS_SRC_DST"
cp -r "$AGENTOS_SRC_SRC" "$AGENTOS_SRC_DST"
# proof_m85/ (the multi-actor app factory, $PROOF_APP_SRC) already lives inside
# $PROOF_DIR — it is IN the docker build context, so no copy step is needed.
echo "    proof app factory in-context at $PROOF_APP_SRC (no copy)"
# The policy bundles (incl. the NEW agents.rego) ride the same overlay pattern.
rm -rf "$PROOF_DIR/policies"
cp -r policies "$PROOF_DIR/policies"

echo "==> [3/11] build the default-adapters base image"
docker_build_with_retry -f infra/agentos/Dockerfile --target default-adapters -t "$BASE_IMAGE" .

echo "==> [3/11] build the proof AgentOS kernel image (create_proof_app + SEVEN released packs + trust + query-context public key)"
docker_build_with_retry -f "$PROOF_DIR/Dockerfile.agentos-proof" --build-arg BASE_IMAGE="$BASE_IMAGE" \
  --build-arg KERNEL_GIT_SHA="$KERNEL_GIT_SHA" -t "$IMAGE" "$PROOF_DIR"
# Verify the built image label equals the computed revision (finding 2): the
# label IS the provenance the evidence cites, so it must be read back from
# the artifact, never assumed from the build invocation.
LABEL_SHA="$(docker inspect -f '{{ index .Config.Labels "io.cognic.proof.kernel-anchor" }}' "$IMAGE")"
[ "$LABEL_SHA" = "$KERNEL_GIT_SHA" ] \
  || die "image kernel-anchor label '$LABEL_SHA' != source revision '$KERNEL_GIT_SHA'"
echo "    image kernel-anchor label verified: $LABEL_SHA"

echo "==> [3/11] build the released oracle-pack MCP tool Service image (v0.3.0 + query-context public key)"
docker_build_with_retry -f "$PROOF_DIR/Dockerfile.oracle-pack" -t "$MCP_IMAGE" "$PROOF_DIR"

echo "==> [3/11] build the emulated-external AS image (RS256 mode)"
cp tests/integration/pack_loop/_local_as.py "$PROOF_DIR/_local_as.py"
docker_build_with_retry -f "$PROOF_DIR/Dockerfile.as" -t "$AS_IMAGE" "$PROOF_DIR"

# --- 4. kind create + load (3 in-cluster proof images + backends + extras) ----------
echo "==> [4/11] pre-pull the backend + extra images (host docker cache)"
while IFS= read -r _img; do
  [ -n "$_img" ] || continue
  echo "  docker pull $_img"
  docker_pull_with_retry "$_img"
done < <(_backend_images; _extra_images)

echo "==> [4/11] create the kind cluster with the sandbox topology (docker sock + broker share)"
kind create cluster --name "$CLUSTER" --config "$PROOF_DIR/kind-config.yaml"

echo "==> [4/11] load the 3 in-cluster proof images (kernel + oracle-pack + AS)"
# NOTE: the sandbox runtime + egress-proxy images are NOT kind-loaded — the
# DockerSibling backend runs them as SIBLING containers on the HOST docker daemon
# (via the mounted /var/run/docker.sock), and the admission gate cosign-verifies
# them from the local registry. They live on host docker + the registry, not in kind.
kind load docker-image "$IMAGE" "$MCP_IMAGE" "$AS_IMAGE" --name "$CLUSTER"

echo "==> [4/11] kind load the pre-pulled backend + extra images into the node"
while IFS= read -r _img; do
  [ -n "$_img" ] || continue
  echo "  kind load $_img"
  kind load docker-image "$_img" --name "$CLUSTER"
done < <(_backend_images; _extra_images)

# --- 4b. local TLS registry + canonical re-home (pull->push->sign->digest-pin) -----
# The M6 executable-skill posture deploys UNCHANGED, so the canonical trust
# chain must be REAL (G7 refuses ghcr.io/bmzee refs in prod; a placeholder ref
# the boot would trust is forbidden by the production-grade rule). Run a TLS
# registry:2 on the kind docker network; re-home BOTH PUBLISHED canonical
# images into it; cosign-sign both under the proof canonical key. Real TLS
# (no insecure-registry bypass flag), NO fixture flag.
echo "==> [4/11] start the local TLS registry:2 on the kind network + trust its CA on the host"
docker run -d --restart=always --name "$REGISTRY_NAME" --network kind \
  -v "$REGISTRY_TLS_DIR:/certs:ro" \
  -e "REGISTRY_HTTP_ADDR=0.0.0.0:$REGISTRY_PORT" \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry-ca.pem \
  -e REGISTRY_HTTP_TLS_KEY=/certs/registry-key.pem \
  -p "$REGISTRY_PORT:$REGISTRY_PORT" \
  registry:2

echo "==> [4/11] re-home + cosign-sign BOTH canonical sandbox images under the proof canonical key"
# (1) the sandbox-runtime WORKLOAD image (re-homed from the PUBLISHED canonical
# digest — the M8 delta vs M6: no executable skill wheel exists to bake, so
# there is no local runtime-image build; the published canonical artifact is
# re-homed exactly like the egress proxy, per the documented bank re-home flow).
docker_pull_with_retry "$PUBLISHED_RUNTIME_PYTHON"
docker tag "$PUBLISHED_RUNTIME_PYTHON" "$REGISTRY_REF_HOST/sandbox-runtime-python:proofm85"
docker push "$REGISTRY_REF_HOST/sandbox-runtime-python:proofm85"
# RepoDigests can carry STALE entries from earlier proofs on the same host
# (run-4 live finding: the egress-proxy image still held a
# cognic-proof-m6-registry digest from the July-4 M6 proof and `index 0`
# picked it) — select the entry for THIS registry explicitly.
RUNTIME_PYTHON_REF="$(docker inspect "$REGISTRY_REF_HOST/sandbox-runtime-python:proofm85" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep "^$REGISTRY_REF_HOST/sandbox-runtime-python@" | head -1)"
[ -n "$RUNTIME_PYTHON_REF" ] || die "could not capture the pushed sandbox-runtime-python RepoDigests ref for $REGISTRY_REF_HOST"
# --registry-cacert: host-side cosign dials the self-signed TLS registry. On
# macOS, Go's platform verifier (Security.framework) ignores SSL_CERT_FILE and
# enforces Apple's TLS policy (825-day cap + serverAuth EKU), which rejects
# the persistent proof CA ("certificate is not standards compliant" — hit
# live 2026-07-03). The explicit flag installs a PURE-GO custom root pool,
# sidestepping the platform verifier; the SAN covers $REGISTRY_NAME.
cosign sign --registry-cacert "$CANONICAL_DIR/registry-ca.pem" \
  --key "$CANONICAL_KEY_TMP/cosign.key" --tlog-upload=false --use-signing-config=false \
  --yes "$RUNTIME_PYTHON_REF"
# (2) the egress-proxy SIDECAR image (re-homed from the published canonical digest)
docker_pull_with_retry "$PUBLISHED_EGRESS_PROXY"
docker tag "$PUBLISHED_EGRESS_PROXY" "$REGISTRY_REF_HOST/sandbox-egress-proxy:proofm85"
docker push "$REGISTRY_REF_HOST/sandbox-egress-proxy:proofm85"
EGRESS_PROXY_REF="$(docker inspect "$REGISTRY_REF_HOST/sandbox-egress-proxy:proofm85" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep "^$REGISTRY_REF_HOST/sandbox-egress-proxy@" | head -1)"
[ -n "$EGRESS_PROXY_REF" ] || die "could not capture the pushed sandbox-egress-proxy RepoDigests ref for $REGISTRY_REF_HOST"
cosign sign --registry-cacert "$CANONICAL_DIR/registry-ca.pem" \
  --key "$CANONICAL_KEY_TMP/cosign.key" --tlog-upload=false --use-signing-config=false \
  --yes "$EGRESS_PROXY_REF"
echo "  canonical refs (digest-pinned, proof-signed): runtime=$RUNTIME_PYTHON_REF proxy=$EGRESS_PROXY_REF"

# --- 5. namespace + the six real backends + Redis + OTLP collector, then Oracle XE --
echo "==> [5/11] bring up the six backends + Redis + otel-collector, then the seeded Oracle XE"
kubectl create namespace "$NS"
kubectl -n "$NS" apply -f "$CHART/ci/smoke/backends.yaml"
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/redis.yaml"
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/otel-collector.yaml"
# The redis Service in the shared-backends namespace makes kubelet's
# service-link env injection hand EVERY pod REDIS_PORT=tcp://<clusterip>:6379 —
# which langfuse v2 validates as ITS OWN numeric Redis config and hard-rejects
# ("Invalid environment variables: { REDIS_PORT: ['Expected number, received
# nan'] }" — reproduced byte-exact 2026-07-04). Disable service links on
# langfuse — the patch rolls a fresh clean-env ReplicaSet deterministically.
# The shared ci/smoke/backends.yaml is deliberately untouched mid-proof.
kubectl -n "$NS" patch deploy/langfuse --type=strategic \
  -p '{"spec":{"template":{"spec":{"enableServiceLinks":false}}}}'
# Per-deployment PARALLEL waits with individual 600s budgets: `kubectl wait`
# on a label selector consumes its budget SEQUENTIALLY in alphabetical order,
# so one slow deployment (langfuse — M6 runs 4-5) burns the WHOLE budget alone
# and the other backends report "timed out" unexamined. Parallel waits give
# each backend its own budget and name the ACTUAL laggards in the failure message.
BACKEND_WAIT_FAILURES="$STAGING_DST/.backend-wait-failures"
rm -f "$BACKEND_WAIT_FAILURES"
for _d in $(kubectl -n "$NS" get deploy -l 'app notin (oracle-xe)' -o name); do
  (
    kubectl -n "$NS" wait --for=condition=available --timeout=600s "$_d" >/dev/null 2>&1 \
      || echo "$_d" >> "$BACKEND_WAIT_FAILURES"
  ) &
done
wait
if [ -s "$BACKEND_WAIT_FAILURES" ]; then
  backends_fail "not Available within 600s: $(tr '\n' ' ' < "$BACKEND_WAIT_FAILURES")"
fi
echo "  all backend deployments Available"
kubectl -n "$NS" create configmap oracle-xe-seed \
  --from-file=seed_schema.sql="$PROOF_DIR/oracle-seed/seed_schema.sql" \
  --dry-run=client -o yaml | kubectl apply -n "$NS" -f -
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-xe.yaml"
# 2400s: the qemu-emulated (amd64-on-arm64) XE first boot creates the whole
# database inside the readiness window; run-5 live finding — 1200s expired
# mid-creation with the listener already up (the image itself is preloaded
# into the node, so none of this window is pull time).
# Poll loop, NOT one long `kubectl wait` (run-7 live findings, both pinned):
#   * `kubectl wait -l ...` resolves the selector ONCE at invocation and then
#     waits on those pod OBJECTS — if the pod is recreated mid-wait, the wait
#     sits on a deleted object until timeout even when the replacement goes
#     Ready.
#   * The qemu-emulated XE occasionally dies within seconds of its FIRST
#     start (environmental; ORA-01081 on every restart after — stale
#     instance state in the pod-scoped sandbox never self-heals). The ONLY
#     recovery is recreating the POD (fresh sandbox). Auto-recreate on a
#     detected crash loop, at most $_XE_MAX_RECREATES times, and keep
#     polling the LABEL so the replacement is picked up.
_XE_DEADLINE=$(( $(date +%s) + 2400 ))
_XE_MAX_RECREATES=3
_xe_recreates=0
until kubectl -n "$NS" get pods -l app=oracle-xe 2>/dev/null | grep -qE "1/1\s+Running"; do
  if [ "$(date +%s)" -ge "$_XE_DEADLINE" ]; then
    xe_fail "oracle-xe pod not Ready within 2400s (qemu-emulated XE first boot under kind)"
  fi
  _xe_restarts="$(kubectl -n "$NS" get pods -l app=oracle-xe \
    -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}' 2>/dev/null || echo 0)"
  if [ "${_xe_restarts:-0}" -ge 2 ]; then
    if [ "$_xe_recreates" -ge "$_XE_MAX_RECREATES" ]; then
      xe_fail "oracle-xe crash-looping after $_xe_recreates pod recreations (qemu emulation unstable — restart Docker Desktop / prune the VM and re-run)"
    fi
    _xe_recreates=$(( _xe_recreates + 1 ))
    echo "  oracle-xe crash-looping (restarts=$_xe_restarts) — recreating the pod for a fresh sandbox ($_xe_recreates/$_XE_MAX_RECREATES)"
    kubectl -n "$NS" delete pod -l app=oracle-xe --wait=false >/dev/null 2>&1 || true
    sleep 20
  fi
  sleep 15
done

# --- 6. Vault init/seed (KV v1 + OAuth + AS-allowlist) ------------------------------
echo "==> [6/11] seed Vault (KV v1 conversion + OAuth + AS allow-list — by reference, D5)"
NS="$NS" bash "$PROOF_DIR/seed-vault.sh"

# --- 7. helm install (prod profile; migrations OFF; digest-pinned canonical images) -
echo "==> [7/11] install the AgentOS chart under the proof-m85 overlay + the proof canonical refs"
# The digest-pinned, proof-signed canonical refs are injected via --set (the static
# overlay must NOT carry a personal-registry ref — deploy-safety guard G7).
helm install rel "$CHART" -n "$NS" -f "$PROOF_DIR/proof-m85-values.yaml" \
  --set sandbox.canonicalRuntimeImage="$RUNTIME_PYTHON_REF" \
  --set sandbox.canonicalEgressProxyImage="$EGRESS_PROXY_REF"

# --- 8. migrate Job + secrets + manifests + patches + env ---------------------------
echo "==> [8/11] run the proof-owned (non-hook) migration Job (schema -> head, rev 0016)"
kubectl -n "$NS" delete job/agentos-migrate --ignore-not-found=true --wait=true
sed "s|__AGENTOS_IMAGE__|$IMAGE|" "$PROOF_DIR/migrate-job.yaml" | kubectl apply -n "$NS" -f -
kubectl -n "$NS" wait --for=condition=complete job/agentos-migrate --timeout=300s \
  || migrate_fail "agentos-migrate did not complete within 300s"

# Live schema readback (finding 2, 2026-07-10: the proof previously CLAIMED
# head 0015 with no readback — the M8.5-B read APIs hard-require the 0016
# correlation column + query indexes, so prove the deployed schema shape).
SCHEMA_REV="$(PSQL "SELECT version_num FROM alembic_version;")"
[ "$SCHEMA_REV" = "0016" ] \
  || migrate_fail "alembic_version reads '$SCHEMA_REV' after the migrate Job (expected 0016)"
SHAPE_0016="$(PSQL "SELECT (SELECT count(*) FROM information_schema.columns WHERE table_name='conversation_turns' AND column_name='turn_completed_request_id') || '|' || (SELECT count(*) FROM pg_indexes WHERE indexname IN ('ix_decision_history_tenant_event_sequence','ix_conversations_tenant_creator_created'));")"
[ "$SHAPE_0016" = "1|2" ] \
  || migrate_fail "0016 schema shape readback '$SHAPE_0016' (expected '1|2': correlation column + the two read-model indexes)"
echo "    schema readback OK: alembic head 0016; correlation column + both read-model indexes present"

pack_fail() {
  # Step-8 capture (run-7 live finding: the oracle-pack rollout timeout left
  # NO diagnostics — the cluster was torn down before anything was captured).
  # Mirrors the xe_fail/backends_fail shape; includes INIT-container logs
  # (wait-for-xe) + previous-instance logs so a crash loop or a stuck init
  # is diagnosable post-teardown.
  local where="$1"
  echo "FAIL: oracle-pack/AS ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local pods desc logs initlogs prevlogs aslogs
  pods="$(kubectl -n "$NS" get deploy,pods -o wide 2>&1 || true)"
  desc="$(kubectl -n "$NS" describe pod -l app=proof-oracle-pack 2>&1 | tail -100 || true)"
  logs="$(kubectl -n "$NS" logs -l app=proof-oracle-pack --all-containers --tail=100 2>&1 || true)"
  initlogs="$(kubectl -n "$NS" logs -l app=proof-oracle-pack -c wait-for-xe --tail=40 2>&1 || true)"
  prevlogs="$(kubectl -n "$NS" logs -l app=proof-oracle-pack --previous --tail=60 2>&1 || true)"
  aslogs="$(kubectl -n "$NS" logs -l app=proof-as --tail=60 2>&1 || true)"
  {
    echo ""
    echo "## Proof M8.5 slice — oracle-pack/AS rollout FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- deploys/pods:"; echo '\`\`\`'; echo "$pods"; echo '\`\`\`'
    echo "- oracle-pack describe (tail):"; echo '\`\`\`'; echo "$desc"; echo '\`\`\`'
    echo "- oracle-pack logs (all containers, tail):"; echo '\`\`\`'; echo "$logs"; echo '\`\`\`'
    echo "- wait-for-xe init logs (tail):"; echo '\`\`\`'; echo "$initlogs"; echo '\`\`\`'
    echo "- oracle-pack previous-instance logs (tail):"; echo '\`\`\`'; echo "$prevlogs"; echo '\`\`\`'
    echo "- proof-as logs (tail):"; echo '\`\`\`'; echo "$aslogs"; echo '\`\`\`'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

echo "==> [8/11] apply the oracle-pack MCP tool Service + AS manifests; wait Ready"
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-pack.yaml" -f "$PROOF_DIR/manifests/auth-server.yaml"
kubectl -n "$NS" rollout status deploy/proof-oracle-pack --timeout=300s \
  || pack_fail "proof-oracle-pack rollout not available within 300s"
kubectl -n "$NS" rollout status deploy/proof-as --timeout=180s \
  || pack_fail "proof-as rollout not available within 180s"

echo "==> [8/11] create the per-run Secrets (query-context PRIVATE key + provider API key)"
# The PRIVATE query-context key ships ONLY as this Secret (mounted read-only at
# /run/cognic/query-context by agentos-sandbox-patch.yaml); the provider key
# rides its own Secret consumed ONLY by the litellm router pod. Neither value
# ever lands in a manifest file, a values file, an image layer, or the repo.
kubectl -n "$NS" create secret generic proof-m85-query-context \
  --from-file=query-context-private.pem="$QC_TMP/query-context-private.pem"
kubectl -n "$NS" create secret generic proof-m85-provider-key \
  --from-file=COGNIC_PROOF_M85_TIER1_API_KEY="$PROVIDER_KEY_FILE"

echo "==> [8/11] patch the AgentOS Deployment (sandbox topology + query-context Secret mount)"
# The chart ships no extraVolume/extraEnv hooks; these surfaces are proof
# TOPOLOGY (the DockerSibling sibling pattern + the broker's host-shared socket
# dir + the M8 signing-key runtime mount).
kubectl -n "$NS" patch deploy/rel-agentos --patch-file "$PROOF_DIR/agentos-sandbox-patch.yaml"

# Deterministic in-pod registry name resolution for the sandbox admission gate:
# the kernel pod's cosign verify dials $REGISTRY_REF_HOST, and cluster DNS
# knows no docker-network alias — patch a hostAliases entry with the
# registry's kind-net IP (reachable pod -> node -> docker bridge).
REGISTRY_KIND_IP="$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "$REGISTRY_NAME")"
[ -n "$REGISTRY_KIND_IP" ] || die "could not determine the registry's kind-network IP for the hostAliases patch"
kubectl -n "$NS" patch deploy/rel-agentos --type=strategic \
  -p "$(printf '{"spec":{"template":{"spec":{"hostAliases":[{"ip":"%s","hostnames":["%s"]}]}}}}' "$REGISTRY_KIND_IP" "$REGISTRY_NAME")"

echo "==> [8/11] set the cloud-policy + run-bound + conversation env on the kernel Deployment (operator env, never image-baked)"
# COGNIC_ALLOW_EXTERNAL_LLM + COGNIC_POLICY_MODE + COGNIC_ALLOWED_PROVIDERS: the
# ADR-007 posture (values + images carry no cloud toggle).
# COGNIC_LITELLM_MASTER_KEY: under the PROD profile the kernel refuses a
# PLAINTEXT litellm_master_key (config.py
# secret_plain_value_forbidden_in_strict_profile), so the gateway presents
# a VAULT-RESOLVED key (finding #6; harness/runtime.py resolves it via
# adapters.secret at lifespan, from the field seed-vault.sh seeds at
# secret/cognic/proof-m85/litellm key=...). The proof's litellm router runs
# WITHOUT general_settings.master_key (finding #7 — no DB dependency), so it
# IGNORES the presented key; the vault path stays wired ONLY to keep the
# prod secret-hygiene guard exercised.
# COGNIC_AGENT_RUN_TOKEN_BUDGET / _WALL_CLOCK_S: OPERATIONAL run
# bounds raised for a real cloud provider's latency + SKILL.md-sized prompts
# (defaults 24k/120s are sized for unit fixtures); NOT a bar surface — no bar
# tests the bound, and no bar is redefined by raising it.
# COGNIC_CONVERSATION_CLAIM_TTL_S=600 (M8.5 recon finding R1, ruled
# 2026-07-10): the ConversationTurnExecutor's construction guard requires
# claim_ttl_s > agent_run_wall_clock_s (turn.py — a slow turn must never have
# its claim stolen and double-run). The default 300.0 does NOT exceed the
# 300s wall clock set below, and the lifespan fail-softs the WHOLE
# conversation block (portal/api/app.py — store AND executor both None), so
# WITHOUT this line every /api/v1/conversations route 503s.
kubectl -n "$NS" set env deploy/rel-agentos \
  COGNIC_ALLOW_EXTERNAL_LLM=true \
  COGNIC_POLICY_MODE="$POLICY_MODE" \
  COGNIC_ALLOWED_PROVIDERS="$ALLOWED_PROVIDERS" \
  COGNIC_LITELLM_MASTER_KEY=vault://secret/cognic/proof-m85/litellm \
  COGNIC_CONVERSATION_CLAIM_TTL_S=600 \
  COGNIC_AGENT_RUN_TOKEN_BUDGET=60000 \
  COGNIC_AGENT_RUN_WALL_CLOCK_S=300

echo "==> [8/11] point the litellm router at the chart-rendered model_list + the provider key"
# ONE model_list: the chart renders values.litellm.config into the
# rel-agentos-litellm ConfigMap (the kernel mounts it at
# /app/infra/litellm/config.yaml — the gateway's PreflightResolver provenance
# source); this patch re-points the in-cluster litellm Deployment's cfg volume
# at the SAME ConfigMap so live routing and preflight provenance can never
# diverge, and injects the operator's provider key from the Secret (the ONLY
# pod that ever sees it).
kubectl -n "$NS" patch deploy/litellm --type=strategic -p '{
  "spec": {"template": {"spec": {
    "volumes": [{"name": "cfg", "configMap": {"name": "rel-agentos-litellm"}}],
    "containers": [{
      "name": "litellm",
      "env": [{
        "name": "COGNIC_PROOF_M85_TIER1_API_KEY",
        "valueFrom": {"secretKeyRef": {"name": "proof-m85-provider-key", "key": "COGNIC_PROOF_M85_TIER1_API_KEY"}}
      }]
    }]
  }}}}'
kubectl -n "$NS" rollout status deploy/litellm --timeout=300s

# --- 9. DB seed (kernel-seed.sql: the 0014 rows; NO derived carve-out INSERT) -------
echo "==> [9/11] seed-db.sh (M8: the 0014 scope/entitlement/assignment rows; install materializes the carve-outs)"
NS="$NS" bash "$PROOF_DIR/seed-db.sh"

# --- 10. roll to the fully-wired pod + port-forward + STEP 0 ------------------------
echo "==> [10/11] roll the Deployment so a fresh pod boots with the topology + secrets + migrated/seeded DB"
roll_and_wait
pf_start

echo "==> STEP 0 — registered/hosted surfaces (all 7 packs; 4 instruction skills; bank-analyst) + hook admission"
assert_m8_surfaces "STEP 0 (first boot)"
assert_hook_pack_registered "STEP 0 (first boot)"

# ============================ SETUP (M4 governed install) ==========================
# Operator-install the DLP-governed ORACLE tool v0.3.0 EXACTLY as proven in
# M4/M5/M6: the full governed lifecycle via the REAL API, multi-actor via
# X-Proof-Role. The HOOK + SKILL + AGENT packs deliberately take NO part in
# this flow (trust-register + hosting only).
echo "==> [11/11] SETUP — governed operator lifecycle for the oracle v0.3.0 tool (submit -> claim -> approve -> allow-list -> configure -> install)"

MANIFEST_JSON="$(uv run python - "$PACK_ID" "$PACK_WHEEL" <<'PY'
import json, sys
pack_id, wheel = sys.argv[1], sys.argv[2]
manifest = {
    "pack": {"kind": "tool", "name": pack_id, "version": "0.3.0"},
    "identity": {
        "agent_id": pack_id,
        "display_name": "Cognic Oracle Schema (proof-m85)",
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
SIGNED_DIGEST="$(printf '%064x' 1)"

echo "==> SETUP 1 — create draft (author)"
CREATE_BODY="$(python3 - "$PACK_ID" "$MANIFEST_DIGEST" "$SIGNED_DIGEST" <<'PY'
import json, sys
pack_id, md, sd = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({
    "kind": "tool",
    "pack_id": pack_id,
    "display_name": "Cognic Oracle Schema (proof-m85)",
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

echo "==> SETUP 2 — submit draft (author)"
SIGNED_ARTEFACT_ROOT="/opt/cognic/pack-attestations/$PACK_ID/0.3.0"
SUBMIT_BODY="$(python3 - "$SIGNED_ARTEFACT_ROOT" <<PY
import json, sys
root = sys.argv[1]
manifest = json.loads('''$MANIFEST_JSON''')
print(json.dumps({"manifest": manifest, "signed_artefact_root": root}))
PY
)"
api author POST "/api/v1/packs/drafts/$PACK_UUID/submit" "$SUBMIT_BODY" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "SETUP 2 submit (HTTP $HTTP_CODE)"

echo "==> SETUP 3 — claim (reviewer; DISTINCT subject from author -> role-separation passes)"
api reviewer POST "/api/v1/packs/$PACK_UUID/claim" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "SETUP 3 claim (HTTP $HTTP_CODE)"

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
[ "$HTTP_CODE" = "200" ] || bar_fail "SETUP 4 approve (HTTP $HTTP_CODE; body: $APPROVE_RESP)"

echo "==> SETUP 5 — allow-list (operator, human-actor)"
api operator POST "/api/v1/packs/$PACK_UUID/allow-list" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "SETUP 5 allow-list (HTTP $HTTP_CODE)"

echo "==> SETUP 6 — configure (operator; writes the desired runtime-config record)"
CONFIGURE_BODY="$(python3 - "$TENANT" <<'PY'
import json, sys
tenant = sys.argv[1]
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

echo "==> SETUP 7 — install (operator; materializes the derived carve-out rows)"
INSTALL_RESP="$(api operator POST "/api/v1/packs/$PACK_UUID/install")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "SETUP 7 install (HTTP $HTTP_CODE; body: $INSTALL_RESP)"

echo "==> SETUP 8 — assert materialization (decision_history: mcp.override.set + mcp.allowlist.add)"
MAT="$(PSQL "SELECT event_type FROM decision_history WHERE event_type IN ('mcp.override.set','mcp.allowlist.add') AND tenant_id='$TENANT';")"
DERIVED_ROWS="$(PSQL "SELECT 'override|' || tenant_id || '|' || pack_id || '|' || server_url_override FROM mcp_server_url_override WHERE tenant_id='$TENANT' UNION ALL SELECT 'allowlist|' || tenant_id || '|' || ip || '|' || set_by_actor FROM mcp_internal_host_allowlist WHERE tenant_id='$TENANT' ORDER BY 1;")"
grep -qF "mcp.override.set" <<<"$MAT" \
  || bar_fail "SETUP 8 no mcp.override.set materialization event (got: ${MAT:-<none>})"
grep -qF "mcp.allowlist.add" <<<"$MAT" \
  || bar_fail "SETUP 8 no mcp.allowlist.add materialization event (got: ${MAT:-<none>})"
grep -qF "override|$TENANT|$PACK_ID|http://10.96.0.51:8765/mcp" <<<"$DERIVED_ROWS" \
  || bar_fail "SETUP 8 no derived override row (got: ${DERIVED_ROWS:-<none>})"
grep -qF "allowlist|$TENANT|10.96.0.51|proof-m85-operator" <<<"$DERIVED_ROWS" \
  || bar_fail "SETUP 8 no derived allow-list row (got: ${DERIVED_ROWS:-<none>})"
echo "  SETUP 8 OK: override + allow-list rows materialized by install (not seeded)"

echo "==> SETUP 9 — roll cold so the MCP probe + the agent's dispatched tool calls see the materialized carve-outs"
roll_and_wait
pf_start
echo "  SETUP 9 OK: cold pod ready"

# Re-assert the hosted/registered surfaces on THIS pod (per-pod boot-time) —
# it serves all three bars.
assert_m8_surfaces "BAR preflight (M8 surfaces on the serving pod)"
assert_hook_pack_registered "BAR preflight (hook pack on the serving pod)"

# Warm the MCPHost per-tenant OAuth token + list_tools cache (governed MCP route)
# so the agent's dispatched run_readonly_query rides a warm cache + a carve-out
# failure surfaces as a clear MCP error, not an opaque dispatch 502.
api mcp GET "/api/v1/mcp/servers/$PACK_ID/tools" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR preflight warm-up list_tools (HTTP $HTTP_CODE — MCP carve-out not live?)"
DS="$(discovery_status)"
[ "$DS" = "auth_ready" ] || bar_fail "BAR preflight discovery_status=$DS (expected auth_ready — the governed MCP carve-out)"

# ================================ BAR 1 (governed multi-turn e2e) ==================
# analyst.amir creates a conversation with bank-analyst and drives TWO governed
# turns. Turn 1 asks the deterministic top-3-depositors question; turn 2 asks a
# follow-up CONTAINING NO ENTITY NAME, answerable only if turn 1's answer was
# replayed from the kernel store. The INVARIANT evidence is mechanical: the
# turn-2 agent.run.started prior-context evidence (recomputed independently),
# the three-hop chain join, the digest<->plaintext coupling, and dual identity.
# The answer-content checks (top-3 names; the rank-2 name) are model-driven
# FUNCTIONAL ACCEPTANCE CRITERIA — mandatory, but a miss reads as a model-
# behaviour failure, not an integrity failure.
echo "==> BAR 1 — governed multi-turn e2e (analyst.amir, conversation with $AGENT_ID)"
RRQ_BEFORE_BAR1="$(tool_invocation_count_for run_readonly_query)"
BAR1_CREATE_RESP="$(conv_create amir)"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "201" ] || bar_fail "BAR 1 create conversation (HTTP $HTTP_CODE; body: $BAR1_CREATE_RESP)"
BAR1_CID="$(json_field conversation_id "$BAR1_CREATE_RESP")"
[ -n "$BAR1_CID" ] || bar_fail "BAR 1 no conversation_id in the create response (body: $BAR1_CREATE_RESP)"
[ "$(json_field state "$BAR1_CREATE_RESP")" = "active" ] || bar_fail "BAR 1 create state not active (body: $BAR1_CREATE_RESP)"
[ "$(conv_event_count "$BAR1_CID" conversation.created)" = "1" ] \
  || bar_fail "BAR 1 no conversation.created chain row for $BAR1_CID"

# --- Turn 1: the deterministic retail question (grounding turn). -------------------
BAR1_T1_RESP="$(conv_turn amir "$BAR1_CID" "Who are the top 3 customers by total deposit balance this quarter? List each customer's name and total balance, largest first.")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1 turn 1 (HTTP $HTTP_CODE; body: $BAR1_T1_RESP)"
BAR1_T1_STATE="$(json_field terminal_state "$BAR1_T1_RESP")"
BAR1_T1_ANSWER="$(json_field answer "$BAR1_T1_RESP")"
BAR1_RUN1="$(json_field agent_run_id "$BAR1_T1_RESP")"
[ "$BAR1_T1_STATE" = "completed" ] || bar_fail "BAR 1 turn 1 terminal_state '$BAR1_T1_STATE' (expected 'completed'; body: $BAR1_T1_RESP)"
[ "$(json_field seq "$BAR1_T1_RESP")" = "1" ] || bar_fail "BAR 1 turn 1 seq != 1 (body: $BAR1_T1_RESP)"
[ -n "$BAR1_RUN1" ] || bar_fail "BAR 1 turn 1 no agent_run_id (body: $BAR1_T1_RESP)"
assert_no_stack_trace "BAR 1 (turn 1)" "$BAR1_T1_ANSWER"
# The seeded deterministic top-3 (SUM(BALANCE) descending, PKR @ 2026-06-30) —
# a model-driven FUNCTIONAL ACCEPTANCE CRITERION, MANDATORY (a miss fails the
# bar); the dispatch/audit rows below are the invariant evidence.
for name in "Ayesha Khan" "Bilal Sheikh" "Chandni Malik"; do
  grep -qF "$name" <<<"$BAR1_T1_ANSWER" || bar_fail "BAR 1 turn 1 answer missing seeded top-3 customer '$name' (answer: $BAR1_T1_ANSWER)"
done
# Turn 1 ran with an EMPTY prior context (the genesis turn).
[ "$(PSQL "SELECT payload->>'prior_context_turns' FROM decision_history WHERE event_type='agent.run.started' AND tenant_id='$TENANT' AND payload->>'run_id'='$BAR1_RUN1';")" = "0" ] \
  || bar_fail "BAR 1 turn 1 agent.run.started prior_context_turns != 0"
# The governed tool actually executed downstream (retail scope, well-formed digest).
RRQ_OK_T1="$(run_dispatch_count "$BAR1_RUN1" "payload->>'outcome'='ok' AND payload->>'capability_ref'='$PACK_ID/run_readonly_query' AND payload->>'scope_id'='retail_analytics' AND payload->>'args_sha256' ~ '^[0-9a-f]{64}\$'")"
[ "$RRQ_OK_T1" -ge 1 ] || bar_fail "BAR 1 turn 1 no ok run_readonly_query dispatch row (scope retail_analytics) for $BAR1_RUN1"
RRQ_AFTER_BAR1_T1="$(tool_invocation_count_for run_readonly_query)"
[ "$RRQ_AFTER_BAR1_T1" -gt "$RRQ_BEFORE_BAR1" ] \
  || bar_fail "BAR 1 turn 1 no new audit.tool_invocation row for run_readonly_query ($RRQ_BEFORE_BAR1 -> $RRQ_AFTER_BAR1_T1)"

# --- Turn 2: the context-dependent follow-up (NO entity name in the question). -----
BAR1_T2_Q="Of those, what is the second-largest customer's total balance? Name the customer and the amount."
BAR1_T2_RESP="$(conv_turn amir "$BAR1_CID" "$BAR1_T2_Q")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1 turn 2 (HTTP $HTTP_CODE; body: $BAR1_T2_RESP)"
BAR1_T2_STATE="$(json_field terminal_state "$BAR1_T2_RESP")"
BAR1_T2_ANSWER="$(json_field answer "$BAR1_T2_RESP")"
BAR1_RUN2="$(json_field agent_run_id "$BAR1_T2_RESP")"
[ "$BAR1_T2_STATE" = "completed" ] || bar_fail "BAR 1 turn 2 terminal_state '$BAR1_T2_STATE' (expected 'completed'; body: $BAR1_T2_RESP)"
[ "$(json_field seq "$BAR1_T2_RESP")" = "2" ] || bar_fail "BAR 1 turn 2 seq != 2 (body: $BAR1_T2_RESP)"
[ -n "$BAR1_RUN2" ] || bar_fail "BAR 1 turn 2 no agent_run_id (body: $BAR1_T2_RESP)"
assert_no_stack_trace "BAR 1 (turn 2)" "$BAR1_T2_ANSWER"
# Model-driven FUNCTIONAL ACCEPTANCE CRITERION — MANDATORY (a miss fails the
# bar): the rank-2 depositor named without appearing in the question. Distinct
# from the MECHANICAL PINS below, which are the invariant evidence; this check
# is the flake-prone model-behaviour half (see the README honesty boundary).
grep -qF "Bilal Sheikh" <<<"$BAR1_T2_ANSWER" \
  || bar_fail "BAR 1 turn 2 answer does not name the seeded rank-2 depositor (Bilal Sheikh) — the model-driven acceptance criterion failed (answer: $BAR1_T2_ANSWER)"

# MECHANICAL PIN 1 — the turn-2 run consumed EXACTLY the kernel-store context:
# prior_context_turns=2 AND prior_context_sha256 == sha256 over the loop's
# framing "user:<question>\nassistant:<answer>" (loop.py:299), recomputed HERE
# from the conversation_turns plaintext (base64-safe transport).
BAR1_T2_STARTED="$(PSQL "SELECT (payload->>'prior_context_turns') || '|' || (payload->>'prior_context_sha256') FROM decision_history WHERE event_type='agent.run.started' AND tenant_id='$TENANT' AND payload->>'run_id'='$BAR1_RUN2';")"
BAR1_T2_PCT="${BAR1_T2_STARTED%%|*}"
BAR1_T2_PCSHA="${BAR1_T2_STARTED##*|}"
[ "$BAR1_T2_PCT" = "2" ] || bar_fail "BAR 1 turn 2 prior_context_turns='$BAR1_T2_PCT' (expected 2 — one replayed turn = user+assistant)"
T1_Q_B64="$(conv_turn_plaintext_b64 "$BAR1_CID" 1 user_message)"
T1_A_B64="$(conv_turn_plaintext_b64 "$BAR1_CID" 1 answer)"
RECOMPUTED_PCSHA="$(python3 - "$T1_Q_B64" "$T1_A_B64" <<'PY'
import base64, hashlib, sys
question = base64.b64decode(sys.argv[1]).decode("utf-8")
answer = base64.b64decode(sys.argv[2]).decode("utf-8")
encoded = f"user:{question}\nassistant:{answer}".encode("utf-8")
print(hashlib.sha256(encoded).hexdigest())
PY
)"
[ "$BAR1_T2_PCSHA" = "$RECOMPUTED_PCSHA" ] \
  || bar_fail "BAR 1 turn 2 prior_context_sha256 chain=$BAR1_T2_PCSHA recomputed=$RECOMPUTED_PCSHA — the assembled context is NOT the kernel-store turn-1 plaintext"
echo "  Bar 1 pin OK: prior_context_turns=2 + prior_context_sha256 recomputed from the kernel store"

# MECHANICAL PIN 2 — the chain join, re-anchored per the run-5 ruling
# (2026-07-10): a live run proved turn 2 can answer ENTIRELY from the
# replayed context with ZERO dispatches (steps_used=1 — correct, desirable
# behaviour), so requiring a turn-2 dispatch row was a model-behaviour
# assumption baked into a mechanical pin. Two lineages, all tenant-scoped:
#
# (a) TURN-2 CONTEXT lineage: seq=2 -> BAR1_RUN2 -> started/completed. The
#     turn-2 run's dispatch count is DELIBERATELY UNCONSTRAINED — 0 means
#     context reuse; >=1 means legitimate re-verification; neither fails.
HOP1_T2_RUN="$(conv_turn_run_id "$BAR1_CID" 2)"
[ "$HOP1_T2_RUN" = "$BAR1_RUN2" ] \
  || bar_fail "BAR 1 context lineage — turn_completed(seq=2) agent_run_id='$HOP1_T2_RUN' != wire agent_run_id='$BAR1_RUN2'"
[ "$(run_event_count "$BAR1_RUN2" agent.run.completed)" = "1" ] \
  || bar_fail "BAR 1 context lineage — no agent.run.completed row for $BAR1_RUN2"
[ "$(run_event_count "$BAR1_RUN2" agent.run.started)" = "1" ] \
  || bar_fail "BAR 1 context lineage — no agent.run.started row for $BAR1_RUN2"
# (b) CONVERSATION DISPATCH lineage — the three-hop join rides the turn
#     that DID dispatch: seq=1 -> BAR1_RUN1 -> started/completed -> >=1
#     dispatch (the STRONGER predicate: a successful run_readonly_query
#     under scope retail_analytics with a well-formed args digest).
HOP1_T1_RUN="$(conv_turn_run_id "$BAR1_CID" 1)"
[ "$HOP1_T1_RUN" = "$BAR1_RUN1" ] \
  || bar_fail "BAR 1 dispatch lineage — turn_completed(seq=1) agent_run_id='$HOP1_T1_RUN' != wire agent_run_id='$BAR1_RUN1'"
[ "$(run_event_count "$BAR1_RUN1" agent.run.completed)" = "1" ] \
  || bar_fail "BAR 1 dispatch lineage — no agent.run.completed row for $BAR1_RUN1"
[ "$(run_event_count "$BAR1_RUN1" agent.run.started)" = "1" ] \
  || bar_fail "BAR 1 dispatch lineage — no agent.run.started row for $BAR1_RUN1"
HOP3_DISPATCH="$(run_dispatch_count "$BAR1_RUN1" "payload->>'outcome'='ok' AND payload->>'capability_ref'='$PACK_ID/run_readonly_query' AND payload->>'scope_id'='retail_analytics' AND payload->>'args_sha256' ~ '^[0-9a-f]{64}\$'")"
[ "$HOP3_DISPATCH" -ge 1 ] \
  || bar_fail "BAR 1 dispatch lineage — no ok retail run_readonly_query dispatch row for $BAR1_RUN1"
echo "  Bar 1 pin OK: context lineage (seq=2 -> run -> started/completed; dispatches unconstrained) + dispatch lineage (seq=1 -> run -> ok retail dispatch)"

# MECHANICAL PIN 3 — digest<->plaintext coupling on BOTH turn_completed rows.
[ "$(conv_event_count "$BAR1_CID" conversation.turn_completed)" = "2" ] \
  || bar_fail "BAR 1 expected exactly 2 conversation.turn_completed rows for $BAR1_CID"
assert_turn_digest_coupling "$BAR1_CID" 1
assert_turn_digest_coupling "$BAR1_CID" 2
echo "  Bar 1 pin OK: question/answer sha256 digests on both turn rows equal the stored plaintext"

# MECHANICAL PIN 4 — dual identity: every agent.run.% row of BOTH runs AND
# every conversation.% row of the conversation carries the creator identity.
[ "$(run_dual_identity_violations "$BAR1_RUN1" analyst.amir)" = "0" ] \
  || bar_fail "BAR 1 dual-identity violation on the $BAR1_RUN1 evidence rows"
[ "$(run_dual_identity_violations "$BAR1_RUN2" analyst.amir)" = "0" ] \
  || bar_fail "BAR 1 dual-identity violation on the $BAR1_RUN2 evidence rows"
[ "$(conv_dual_identity_violations "$BAR1_CID" analyst.amir)" = "0" ] \
  || bar_fail "BAR 1 conversation.% rows for $BAR1_CID not all actor_id=analyst.amir"
# The operational record agrees with the wire.
BAR1_GET_RESP="$(conv_get amir "$BAR1_CID")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1 GET conversation (HTTP $HTTP_CODE)"
[ "$(json_field turn_count "$BAR1_GET_RESP")" = "2" ] || bar_fail "BAR 1 turn_count != 2 (body: $BAR1_GET_RESP)"
echo "  Bar 1 OK: two governed turns, context replay pinned mechanically, three-hop join + digests + dual identity verified"
echo "PROOF M8.5 SLICE (BAR 1) PASS"

# ================================ BAR 2 (record integrity — deterministic) =========
# NO model call. FIVE forged history fields each 422 with an extra_forbidden
# error naming the submitted field (I-1: the wire has NO history-accepting
# field), and the ZERO-LOOP pin proves the rejected requests never touched the
# loop or the conversation record.
echo "==> BAR 2 — record integrity (five forged history fields; deterministic)"
AGENT_ROWS_BEFORE_BAR2="$(PSQL "SELECT count(*) FROM decision_history WHERE event_type LIKE 'agent.run.%' AND tenant_id='$TENANT';")"
TURN_ROWS_BEFORE_BAR2="$(conv_event_count "$BAR1_CID" conversation.turn_completed)"
for field in messages history prior_context context transcript; do
  BAR2_BODY="$(python3 -c 'import json,sys; print(json.dumps({"user_message": "q", sys.argv[1]: [{"role": "user", "content": "forged history"}]}))' "$field")"
  BAR2_RESP="$(api amir POST "/api/v1/conversations/$BAR1_CID/turns" "$BAR2_BODY")"
  load_http_code # after api command substitution
  [ "$HTTP_CODE" = "422" ] || bar_fail "BAR 2 forged field '$field' accepted (HTTP $HTTP_CODE; body: $BAR2_RESP)"
  # Status alone is insufficient (ruling 2026-07-10): the 422 body must carry
  # a Pydantic extra_forbidden error whose loc names the submitted field.
  python3 - "$field" "$BAR2_RESP" <<'PY' || bar_fail "BAR 2 forged field '$field' — 422 body carries no extra_forbidden error for the field (body: $BAR2_RESP)"
import json, sys
field, raw = sys.argv[1], sys.argv[2]
doc = json.loads(raw)
errors = doc.get("detail", [])
if not isinstance(errors, list):
    raise SystemExit(1)
hits = [
    e for e in errors
    if isinstance(e, dict) and e.get("type") == "extra_forbidden" and field in [str(part) for part in e.get("loc", [])]
]
raise SystemExit(0 if hits else 1)
PY
done
# ZERO-LOOP pin: the five refusals produced NO agent run rows, NO new turn
# rows, and left the operational turn_count untouched.
AGENT_ROWS_AFTER_BAR2="$(PSQL "SELECT count(*) FROM decision_history WHERE event_type LIKE 'agent.run.%' AND tenant_id='$TENANT';")"
TURN_ROWS_AFTER_BAR2="$(conv_event_count "$BAR1_CID" conversation.turn_completed)"
[ "$AGENT_ROWS_AFTER_BAR2" = "$AGENT_ROWS_BEFORE_BAR2" ] \
  || bar_fail "BAR 2 agent.run.% rows moved ($AGENT_ROWS_BEFORE_BAR2 -> $AGENT_ROWS_AFTER_BAR2) — a forged-history request reached the loop"
[ "$TURN_ROWS_AFTER_BAR2" = "$TURN_ROWS_BEFORE_BAR2" ] \
  || bar_fail "BAR 2 conversation.turn_completed rows moved ($TURN_ROWS_BEFORE_BAR2 -> $TURN_ROWS_AFTER_BAR2)"
BAR2_GET_RESP="$(conv_get amir "$BAR1_CID")"
load_http_code # after api command substitution
[ "$(json_field turn_count "$BAR2_GET_RESP")" = "2" ] || bar_fail "BAR 2 turn_count moved (body: $BAR2_GET_RESP)"
# The POSITIVE half of I-1 is BAR 1's mechanical pin 1: the assembled context
# hash equals the kernel-store recompute — the context can only have come from
# the store, because the wire cannot even represent a client transcript.
echo "  Bar 2 OK: five forged fields 422 extra_forbidden (messages/history/prior_context/context/transcript); zero-loop pin held"
echo "PROOF M8.5 SLICE (BAR 2) PASS"

# ================================ BAR 3 (mid-conversation revocation — I-2) ========
# Its OWN conversation on the FINANCIALS scope (BAR 1's retail stays
# untouched). Turn 1 completes through scope financials; the runner then
# proves EXACTLY ONE amir financials entitlement row exists, DELETEs it
# (readback 0), and turn 2 asks a FRESH financials question NOT answerable
# from the replayed turn-1 context (ruling R3 — asking the same question again
# would be answerable from the transcript and might never dispatch). The
# load-bearing pins are chain rows: >=1 refused agent_scope_not_entitled
# financials dispatch for run 2 AND exactly 0 ok financials dispatches for
# run 2. HTTP stays 200 — a dispatch refusal is a governed answer. The
# entitlement is RESTORED afterwards (readback 1). PT-3 posture: revocation
# does not un-disclose turn-1 content already in the transcript; this bar
# proves no FRESH data crosses the revoked scope.
echo "==> BAR 3 — mid-conversation revocation (amir, financials; no envelope cache)"
BAR3_CREATE_RESP="$(conv_create amir)"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "201" ] || bar_fail "BAR 3 create conversation (HTTP $HTTP_CODE; body: $BAR3_CREATE_RESP)"
BAR3_CID="$(json_field conversation_id "$BAR3_CREATE_RESP")"
[ -n "$BAR3_CID" ] || bar_fail "BAR 3 no conversation_id (body: $BAR3_CREATE_RESP)"

# --- Turn 1: financials succeeds while the entitlement is live. --------------------
BAR3_T1_RESP="$(conv_turn amir "$BAR3_CID" "What is the total general-ledger balance across all accounts as of quarter end? Give one figure.")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 3 turn 1 (HTTP $HTTP_CODE; body: $BAR3_T1_RESP)"
BAR3_T1_STATE="$(json_field terminal_state "$BAR3_T1_RESP")"
BAR3_RUN1="$(json_field agent_run_id "$BAR3_T1_RESP")"
BAR3_T1_ANSWER="$(json_field answer "$BAR3_T1_RESP")"
[ "$BAR3_T1_STATE" = "completed" ] || bar_fail "BAR 3 turn 1 terminal_state '$BAR3_T1_STATE' (body: $BAR3_T1_RESP)"
assert_no_stack_trace "BAR 3 (turn 1)" "$BAR3_T1_ANSWER"
BAR3_T1_FIN_OK="$(run_dispatch_count "$BAR3_RUN1" "payload->>'outcome'='ok' AND payload->>'capability_ref'='$PACK_ID/run_readonly_query' AND payload->>'scope_id'='financials'")"
[ "$BAR3_T1_FIN_OK" -ge 1 ] \
  || bar_fail "BAR 3 turn 1 no ok financials run_readonly_query dispatch row for $BAR3_RUN1 — the scope was not exercised while entitled"
echo "  Bar 3 leg 1 OK: financials dispatched ok while the entitlement was live"

# --- Revoke MID-CONVERSATION: exactly one row existed, delete it, readback 0. ------
ENT_BEFORE="$(entitlement_count analyst.amir financials)"
[ "$ENT_BEFORE" = "1" ] \
  || bar_fail "BAR 3 expected EXACTLY ONE amir financials entitlement row before revocation (got $ENT_BEFORE)"
entitlement_delete analyst.amir financials >/dev/null
ENT_AFTER_DELETE="$(entitlement_count analyst.amir financials)"
[ "$ENT_AFTER_DELETE" = "0" ] \
  || bar_fail "BAR 3 entitlement row survived the DELETE (count $ENT_AFTER_DELETE)"
echo "  Bar 3 revocation OK: 1 -> 0 amir financials entitlement rows (mid-conversation)"

# --- Turn 2: a FRESH financials question against the revoked scope. ----------------
BAR3_T2_RESP="$(conv_turn amir "$BAR3_CID" "Which branch had the highest profit-and-loss result last quarter, and what was the figure? If that data is not available to you, say so plainly.")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 3 turn 2 (HTTP $HTTP_CODE; body: $BAR3_T2_RESP) — a dispatch refusal is a governed answer, never an error status"
BAR3_RUN2="$(json_field agent_run_id "$BAR3_T2_RESP")"
BAR3_T2_ANSWER="$(json_field answer "$BAR3_T2_RESP")"
[ -n "$BAR3_RUN2" ] || bar_fail "BAR 3 turn 2 no agent_run_id (body: $BAR3_T2_RESP)"
[ -n "$BAR3_T2_ANSWER" ] || bar_fail "BAR 3 turn 2 empty answer (the refusal must surface as a graceful answer)"
assert_no_stack_trace "BAR 3 (turn 2)" "$BAR3_T2_ANSWER"
# LOAD-BEARING PIN A: >=1 dispatch row refused agent_scope_not_entitled on
# scope financials for run 2 — the envelope was re-resolved against CURRENT
# entitlements on THIS turn (no cache from turn 1).
BAR3_REFUSED="$(run_dispatch_count "$BAR3_RUN2" "payload->>'outcome'='refused' AND payload->>'refusal_reason'='agent_scope_not_entitled' AND payload->>'scope_id'='financials'")"
[ "$BAR3_REFUSED" -ge 1 ] \
  || bar_fail "BAR 3 turn 2 no refused agent_scope_not_entitled financials dispatch row for $BAR3_RUN2 — the revocation did not bite (envelope cached?)"
# LOAD-BEARING PIN B: EXACTLY 0 ok financials dispatches for run 2 — no fresh
# data crossed the revoked scope.
BAR3_FIN_OK_T2="$(run_dispatch_count "$BAR3_RUN2" "payload->>'outcome'='ok' AND payload->>'scope_id'='financials'")"
[ "$BAR3_FIN_OK_T2" = "0" ] \
  || bar_fail "BAR 3 turn 2 an ok financials dispatch EXECUTED after revocation ($BAR3_FIN_OK_T2 row(s))"
# Graceful not-available answer — a model-driven FUNCTIONAL ACCEPTANCE
# CRITERION, MANDATORY (a miss fails the bar); the refused/zero-ok chain rows
# above are the invariant evidence.
grep -qiE "not (available|entitled|permitted|authoriz)|scope|access|unable|cannot|can't|denied|restricted" <<<"$BAR3_T2_ANSWER" \
  || bar_fail "BAR 3 turn 2 answer does not read as a graceful not-available answer (answer: $BAR3_T2_ANSWER)"
echo "  Bar 3 leg 2 OK: post-revocation financials dispatch refused (agent_scope_not_entitled), zero ok financials dispatches"

# --- Restore + readback (the seed matrix is left EXACTLY as found). ----------------
entitlement_restore analyst.amir financials >/dev/null
ENT_AFTER_RESTORE="$(entitlement_count analyst.amir financials)"
[ "$ENT_AFTER_RESTORE" = "1" ] \
  || bar_fail "BAR 3 entitlement restore failed (count $ENT_AFTER_RESTORE, expected 1)"
echo "  Bar 3 restore OK: amir financials entitlement back to exactly 1 row"
echo "PROOF M8.5 SLICE (BAR 3) PASS"

echo "PROOF M8.5 SLICE (BARS 1-3) PASS"

# ================================ M8.5-B (READ APIS) ================================
# The governed read surface (list / transcript / turn-chain) over the SAME
# kernel record BARs 1-3 produced above — deterministic, ZERO new model calls:
# every predicate reads what the bars already wrote. The foreign-tenant reader
# (analyst.zara, tenant proof-foreign — the 7th proof role carrying the SAME
# four conversation.* scopes as the analysts) proves tenant isolation is the
# storage WHERE clause, not the scope set; sara (same tenant, different
# creator) proves creator isolation the same way. Byte-identity doctrine: the
# cross-actor and cross-tenant 404 bodies must equal the genuine unknown-id
# 404 byte-for-byte, so a probe cannot distinguish "exists but not yours"
# from "does not exist".

echo "==> M8.5-B READ 1 — list (amir): finds the BAR 1 + BAR 3 conversations"
B_LIST_RESP="$(api amir GET "/api/v1/conversations?limit=50")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "M8.5-B READ 1 list (HTTP $HTTP_CODE; body: $B_LIST_RESP)"
json_assert "M8.5-B READ 1 list contents" '
import json, sys
doc = json.loads(sys.argv[1])
bar1, bar3, agent = sys.argv[2], sys.argv[3], sys.argv[4]
items = {i["conversation_id"]: i for i in doc["items"]}
assert bar1 in items, f"BAR 1 conversation {bar1} not in the list: {sorted(items)}"
assert bar3 in items, f"BAR 3 conversation {bar3} not in the list: {sorted(items)}"
for cid in (bar1, bar3):
    row = items[cid]
    assert row["turn_count"] == 2, row
    assert row["agent_id"] == agent, row
    assert row["state"] == "active", row
    assert row["cumulative_tokens"] > 0, row
print("ok")
' "$B_LIST_RESP" "$BAR1_CID" "$BAR3_CID" "$AGENT_ID"
echo "  M8.5-B READ 1 OK: both bar conversations listed with turn_count=2"

echo "==> M8.5-B READ 1b — list pagination (limit=1 cursor walk covers both conversations)"
B_PAGE1="$(api amir GET "/api/v1/conversations?limit=1")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "M8.5-B READ 1b page 1 (HTTP $HTTP_CODE; body: $B_PAGE1)"
B_CURSOR="$(json_field next_cursor "$B_PAGE1")"
[ -n "$B_CURSOR" ] || bar_fail "M8.5-B READ 1b page 1 minted no next_cursor (body: $B_PAGE1)"
B_PAGE2="$(api amir GET "/api/v1/conversations?limit=1&cursor=$B_CURSOR")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "M8.5-B READ 1b page 2 (HTTP $HTTP_CODE; body: $B_PAGE2)"
json_assert "M8.5-B READ 1b cursor walk" '
import json, sys
page1, page2 = json.loads(sys.argv[1]), json.loads(sys.argv[2])
expected = {sys.argv[3], sys.argv[4]}
ids1 = [i["conversation_id"] for i in page1["items"]]
ids2 = [i["conversation_id"] for i in page2["items"]]
assert len(ids1) == 1, page1
assert len(ids2) == 1, page2
assert set(ids1) | set(ids2) == expected, (ids1, ids2)
assert not set(ids1) & set(ids2), (ids1, ids2)
assert page2["next_cursor"] is None, page2  # exactly 2 owned -> the walk terminates
print("ok")
' "$B_PAGE1" "$B_PAGE2" "$BAR1_CID" "$BAR3_CID"
echo "  M8.5-B READ 1b OK: two limit=1 pages, disjoint, cover exactly the two bar conversations, walk terminates"

echo "==> M8.5-B READ 1c — cursor probes: malformed / wrong-version / filter-mismatch all 422 cursor_invalid"
B_PROBE_MALFORMED="$(api amir GET "/api/v1/conversations?cursor=@@not-base64url@@")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "422" ] || bar_fail "M8.5-B READ 1c malformed cursor (HTTP $HTTP_CODE; body: $B_PROBE_MALFORMED)"
json_assert "M8.5-B READ 1c malformed cursor reason" '
import json, sys
assert json.loads(sys.argv[1])["detail"]["reason"] == "cursor_invalid", sys.argv[1]
print("ok")
' "$B_PROBE_MALFORMED"
B_WRONGV_CURSOR="$(python3 -c 'import base64, json; print(base64.urlsafe_b64encode(json.dumps({"v": 999}).encode()).decode())')"
B_PROBE_WRONGV="$(api amir GET "/api/v1/conversations?cursor=$B_WRONGV_CURSOR")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "422" ] || bar_fail "M8.5-B READ 1c wrong-version cursor (HTTP $HTTP_CODE; body: $B_PROBE_WRONGV)"
json_assert "M8.5-B READ 1c wrong-version cursor reason" '
import json, sys
assert json.loads(sys.argv[1])["detail"]["reason"] == "cursor_invalid", sys.argv[1]
print("ok")
' "$B_PROBE_WRONGV"
# Filter-mismatch: B_CURSOR was minted with NO state filter; replaying it with
# state=closed is a mismatched cursor, not a new query (the filter is BOUND
# INTO the cursor).
B_PROBE_MISMATCH="$(api amir GET "/api/v1/conversations?limit=1&cursor=$B_CURSOR&state=closed")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "422" ] || bar_fail "M8.5-B READ 1c filter-mismatch cursor (HTTP $HTTP_CODE; body: $B_PROBE_MISMATCH)"
json_assert "M8.5-B READ 1c filter-mismatch cursor reason" '
import json, sys
assert json.loads(sys.argv[1])["detail"]["reason"] == "cursor_invalid", sys.argv[1]
print("ok")
' "$B_PROBE_MISMATCH"
echo "  M8.5-B READ 1c OK: all three cursor probes refused 422 cursor_invalid"

echo "==> M8.5-B READ 2 — transcript (amir, BAR 1): plaintext + ordering + tokens + watermark"
B_TRANS="$(api amir GET "/api/v1/conversations/$BAR1_CID/transcript")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "M8.5-B READ 2 transcript (HTTP $HTTP_CODE; body: $B_TRANS)"
json_assert "M8.5-B READ 2 transcript contents" '
import json, sys
doc = json.loads(sys.argv[1])
cid, run1, run2, q1_prefix = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
assert doc["conversation"]["conversation_id"] == cid, doc["conversation"]
assert doc["conversation"]["turn_count"] == 2, doc["conversation"]
assert doc["watermark"] == 2, doc["watermark"]
turns = doc["turns"]
assert [t["seq"] for t in turns] == [1, 2], [t["seq"] for t in turns]
for t in turns:
    assert isinstance(t["user_message"], str) and t["user_message"], t["seq"]
    assert isinstance(t["answer"], str) and t["answer"], t["seq"]
    assert t["erased_at"] is None, t["seq"]
    assert t["prompt_tokens"] > 0 and t["completion_tokens"] > 0, t["seq"]
    assert t["created_at"], t["seq"]
assert turns[0]["user_message"].startswith(q1_prefix), turns[0]["user_message"][:80]
assert turns[0]["agent_run_id"] == run1, (turns[0]["agent_run_id"], run1)
assert turns[1]["agent_run_id"] == run2, (turns[1]["agent_run_id"], run2)
assert doc["next_cursor"] is None, doc["next_cursor"]  # both turns fit one page
print("ok")
' "$B_TRANS" "$BAR1_CID" "$BAR1_RUN1" "$BAR1_RUN2" "Who are the top 3 customers"
# Persist the transcript for READ 6: its four plaintexts (both questions +
# both answers) become the DYNAMIC banned markers of the access-log scan.
printf '%s' "$B_TRANS" > "$QC_TMP/conv-transcript.json"
echo "  M8.5-B READ 2 OK: both turns plaintext (non-null, erased_at null), ordered, token-attributed, runs match the wire"

echo "==> M8.5-B READ 2b — transcript pagination (limit=1; frozen watermark on both pages)"
B_TP1="$(api amir GET "/api/v1/conversations/$BAR1_CID/transcript?limit=1")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "M8.5-B READ 2b page 1 (HTTP $HTTP_CODE; body: $B_TP1)"
B_TCURSOR="$(json_field next_cursor "$B_TP1")"
[ -n "$B_TCURSOR" ] || bar_fail "M8.5-B READ 2b page 1 minted no next_cursor (body: $B_TP1)"
B_TP2="$(api amir GET "/api/v1/conversations/$BAR1_CID/transcript?limit=1&cursor=$B_TCURSOR")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "M8.5-B READ 2b page 2 (HTTP $HTTP_CODE; body: $B_TP2)"
json_assert "M8.5-B READ 2b watermark pagination" '
import json, sys
page1, page2 = json.loads(sys.argv[1]), json.loads(sys.argv[2])
assert [t["seq"] for t in page1["turns"]] == [1], page1["turns"]
assert [t["seq"] for t in page2["turns"]] == [2], page2["turns"]
assert page1["watermark"] == 2 and page2["watermark"] == 2, (page1["watermark"], page2["watermark"])
assert page2["next_cursor"] is None, page2["next_cursor"]
print("ok")
' "$B_TP1" "$B_TP2"
echo "  M8.5-B READ 2b OK: seq 1 then seq 2 across pages under the frozen watermark 2"

echo "==> M8.5-B READ 3 — turn chain (amir, BAR 1 turn 1): four curated blocks + >=1 ok retail dispatch"
B_CHAIN1="$(api amir GET "/api/v1/conversations/$BAR1_CID/turns/1/chain")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "M8.5-B READ 3 chain turn 1 (HTTP $HTTP_CODE; body: $B_CHAIN1)"
json_assert "M8.5-B READ 3 chain turn 1 contents" '
import json, re, sys
doc = json.loads(sys.argv[1])
run1, agent, pack = sys.argv[2], sys.argv[3], sys.argv[4]
assert set(doc) == {"turn_completed", "started", "terminal", "dispatches"}, sorted(doc)
tc, st, tm = doc["turn_completed"], doc["started"], doc["terminal"]
assert tc["seq"] == 1 and tc["agent_run_id"] == run1, tc
assert tc["actor_id"] == "analyst.amir", tc
hex64 = re.compile(r"[0-9a-f]{64}")
for digest in (
    tc["question_sha256"],
    tc["answer_sha256"],
    st["question_sha256"],
    st["prior_context_sha256"],
    tm["answer_sha256"],
):
    assert hex64.fullmatch(digest), digest  # 64-HEX, not merely 64 chars
assert tc["prompt_tokens"] > 0 and tc["completion_tokens"] > 0, tc
assert st["run_id"] == run1 and st["agent_id"] == agent, st
assert st["originator_subject"] == "analyst.amir", st
assert st["actor_id"] == "analyst.amir", st
assert st["prior_context_turns"] == 0, st  # the grounding turn replays nothing
# The started<->hop1 digest coupling: both digest the SAME user_message.
assert st["question_sha256"] == tc["question_sha256"], (st["question_sha256"], tc["question_sha256"])
assert tm["terminal_state"] == "completed", tm
assert tm["answer_sha256"] == tc["answer_sha256"], (tm["answer_sha256"], tc["answer_sha256"])
assert st["sequence"] < tm["sequence"] < tc["sequence"], (st["sequence"], tm["sequence"], tc["sequence"])
dispatches = doc["dispatches"]
assert isinstance(dispatches, list) and len(dispatches) >= 1, dispatches
assert all(st["sequence"] < d["sequence"] < tm["sequence"] for d in dispatches), dispatches
ok_retail = [
    d
    for d in dispatches
    if d["outcome"] == "ok"
    and d["scope_id"] == "retail_analytics"
    and d["capability_ref"] == pack + "/run_readonly_query"
]
assert ok_retail, dispatches
assert all(hex64.fullmatch(d["args_sha256"]) for d in dispatches), dispatches
# finding 4 (2026-07-10): result_sha256 is surfaced too — validate EVERY
# non-null one as 64-hex (the kernel contract keeps it nullable), and the
# ok retail dispatch executed a real query, so ITS result digest must be
# present and valid.
for d in dispatches:
    if d["result_sha256"] is not None:
        assert hex64.fullmatch(d["result_sha256"]), d
assert all(
    d["result_sha256"] is not None and hex64.fullmatch(d["result_sha256"]) for d in ok_retail
), ok_retail
print("ok")
' "$B_CHAIN1" "$BAR1_RUN1" "$AGENT_ID" "$PACK_ID"
echo "  M8.5-B READ 3 OK: four blocks, started<terminal ordering, >=1 ok retail dispatch inside the window, digests only"

echo "==> M8.5-B READ 3b — turn chain (BAR 1 turn 2): dispatches UNCONSTRAINED-as-array (run-5 ruling)"
B_CHAIN2="$(api amir GET "/api/v1/conversations/$BAR1_CID/turns/2/chain")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "M8.5-B READ 3b chain turn 2 (HTTP $HTTP_CODE; body: $B_CHAIN2)"
json_assert "M8.5-B READ 3b chain turn 2 contents" '
import json, sys
doc = json.loads(sys.argv[1])
run2 = sys.argv[2]
tc, st, tm = doc["turn_completed"], doc["started"], doc["terminal"]
assert tc["seq"] == 2 and tc["agent_run_id"] == run2, tc
assert st["run_id"] == run2, st
# One replayed turn = TWO messages (user + assistant): the kernel records
# len(prior_context), which counts PriorTurn MESSAGES (loop.py), not stored
# turns — the SAME semantic BAR 1 pins live (finding 1, 2026-07-10: an ==1
# assertion here guaranteed a post-spend failure).
assert st["prior_context_turns"] == 2, st
assert tm["terminal_state"] == "completed", tm
# The run-5 ruling: the turn-2 dispatch COUNT is deliberately unconstrained
# (0 = context reuse; >=1 = re-verification). The pin is SHAPE: an array of
# curated dispatch projections, every one inside the run window.
dispatches = doc["dispatches"]
assert isinstance(dispatches, list), type(dispatches).__name__
assert all(st["sequence"] < d["sequence"] < tm["sequence"] for d in dispatches), dispatches
print("ok")
' "$B_CHAIN2" "$BAR1_RUN2"
B_T2_DISPATCH_COUNT="$(python3 -c 'import json, sys; print(len(json.loads(sys.argv[1])["dispatches"]))' "$B_CHAIN2" 2>/dev/null || echo "?")"
echo "  M8.5-B READ 3b OK: turn-2 chain joined; dispatches observed (unconstrained): $B_T2_DISPATCH_COUNT"

echo "==> M8.5-B READ 4 — byte-identical 404: unknown-id / cross-actor / cross-tenant x transcript+chain"
B_UNKNOWN_CID="9e9e9e9e-9e9e-4e9e-8e9e-9e9e9e9e9e9e"
B_404_T_UNKNOWN="$(api amir GET "/api/v1/conversations/$B_UNKNOWN_CID/transcript")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "404" ] || bar_fail "M8.5-B READ 4 unknown-id transcript (HTTP $HTTP_CODE; body: $B_404_T_UNKNOWN)"
B_404_T_SARA="$(api sara GET "/api/v1/conversations/$BAR1_CID/transcript")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "404" ] || bar_fail "M8.5-B READ 4 cross-actor transcript (HTTP $HTTP_CODE; body: $B_404_T_SARA)"
B_404_T_FOREIGN="$(api foreign GET "/api/v1/conversations/$BAR1_CID/transcript")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "404" ] || bar_fail "M8.5-B READ 4 cross-tenant transcript (HTTP $HTTP_CODE; body: $B_404_T_FOREIGN)"
[ "$B_404_T_SARA" = "$B_404_T_UNKNOWN" ] \
  || bar_fail "M8.5-B READ 4 cross-actor transcript 404 body differs from the unknown-id body (sara: $B_404_T_SARA; unknown: $B_404_T_UNKNOWN)"
[ "$B_404_T_FOREIGN" = "$B_404_T_UNKNOWN" ] \
  || bar_fail "M8.5-B READ 4 cross-tenant transcript 404 body differs from the unknown-id body (foreign: $B_404_T_FOREIGN; unknown: $B_404_T_UNKNOWN)"
B_404_C_UNKNOWN="$(api amir GET "/api/v1/conversations/$B_UNKNOWN_CID/turns/1/chain")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "404" ] || bar_fail "M8.5-B READ 4 unknown-id chain (HTTP $HTTP_CODE; body: $B_404_C_UNKNOWN)"
B_404_C_SARA="$(api sara GET "/api/v1/conversations/$BAR1_CID/turns/1/chain")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "404" ] || bar_fail "M8.5-B READ 4 cross-actor chain (HTTP $HTTP_CODE; body: $B_404_C_SARA)"
B_404_C_FOREIGN="$(api foreign GET "/api/v1/conversations/$BAR1_CID/turns/1/chain")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "404" ] || bar_fail "M8.5-B READ 4 cross-tenant chain (HTTP $HTTP_CODE; body: $B_404_C_FOREIGN)"
[ "$B_404_C_SARA" = "$B_404_C_UNKNOWN" ] \
  || bar_fail "M8.5-B READ 4 cross-actor chain 404 body differs from the unknown-id body (sara: $B_404_C_SARA; unknown: $B_404_C_UNKNOWN)"
[ "$B_404_C_FOREIGN" = "$B_404_C_UNKNOWN" ] \
  || bar_fail "M8.5-B READ 4 cross-tenant chain 404 body differs from the unknown-id body (foreign: $B_404_C_FOREIGN; unknown: $B_404_C_UNKNOWN)"
json_assert "M8.5-B READ 4 collapse reason" '
import json, sys
assert json.loads(sys.argv[1])["detail"]["reason"] == "conversation_not_found", sys.argv[1]
print("ok")
' "$B_404_T_UNKNOWN"
# Owner-visible distinctness: an absent TURN on a conversation amir DOES own
# is the two-level 404 semantic — turn_not_found, never the collapse body.
B_404_TURN="$(api amir GET "/api/v1/conversations/$BAR1_CID/turns/99/chain")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "404" ] || bar_fail "M8.5-B READ 4 owner-visible absent turn (HTTP $HTTP_CODE; body: $B_404_TURN)"
json_assert "M8.5-B READ 4 owner-visible turn_not_found" '
import json, sys
assert json.loads(sys.argv[1])["detail"]["reason"] == "turn_not_found", sys.argv[1]
print("ok")
' "$B_404_TURN"
echo "  M8.5-B READ 4 OK: six-way byte-identical collapse; owner-visible turn_not_found stays distinct"

echo "==> M8.5-B READ 5 — creator + tenant isolation on list: sara and the foreign reader see EMPTY"
B_LIST_SARA="$(api sara GET "/api/v1/conversations")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "M8.5-B READ 5 sara list (HTTP $HTTP_CODE; body: $B_LIST_SARA)"
json_assert "M8.5-B READ 5 sara list empty" '
import json, sys
doc = json.loads(sys.argv[1])
assert doc["items"] == [] and doc["next_cursor"] is None, doc
print("ok")
' "$B_LIST_SARA"
B_LIST_FOREIGN="$(api foreign GET "/api/v1/conversations")"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "M8.5-B READ 5 foreign list (HTTP $HTTP_CODE; body: $B_LIST_FOREIGN)"
json_assert "M8.5-B READ 5 foreign list empty" '
import json, sys
doc = json.loads(sys.argv[1])
assert doc["items"] == [] and doc["next_cursor"] is None, doc
print("ok")
' "$B_LIST_FOREIGN"
echo "  M8.5-B READ 5 OK: fully-scoped sara (same tenant) and zara (foreign tenant) both list empty"

echo "==> M8.5-B READ 6 — access logs: identifiers + outcome only, never transcript plaintext"
set +e
kubectl -n "$NS" logs -l app.kubernetes.io/name=agentos --all-containers=true --tail=8000 \
  2>"$QC_TMP/conv-access-err" | grep -F "portal.conversations." > "$QC_TMP/conv-access-lines"
B_ACCESS_RC=$?
set -e
[ "$B_ACCESS_RC" -eq 0 ] \
  || bar_fail "M8.5-B READ 6 no portal.conversations.* access-log lines (rc=$B_ACCESS_RC; kubectl stderr: $(cat "$QC_TMP/conv-access-err" 2>/dev/null || echo "<none>"))"
json_assert "M8.5-B READ 6 access-log contents" '
import json, sys
path, transcript_path = sys.argv[1], sys.argv[2]
recs, raw = [], []
with open(path, encoding="utf-8", errors="replace") as fh:
    for line in fh:
        raw.append(line)
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        msg = doc.get("message", "")
        if isinstance(msg, str) and msg.startswith("portal.conversations."):
            recs.append(doc)
assert recs, "no parseable portal.conversations.* records"
def ok_lines(suffix):
    return [r for r in recs if r["message"] == "portal.conversations." + suffix and r.get("outcome") == "ok"]
assert ok_lines("list"), "no ok list access record"
assert ok_lines("transcript"), "no ok transcript access record"
assert ok_lines("chain"), "no ok chain access record"
amir_transcript = [
    r
    for r in ok_lines("transcript")
    if r.get("tenant_id") == "proof-m85" and r.get("actor_subject") == "analyst.amir" and r.get("conversation_id")
]
assert amir_transcript, "no transcript access record carrying the amir identifiers"
foreign_list = [
    r for r in ok_lines("list") if r.get("tenant_id") == "proof-foreign" and r.get("actor_subject") == "analyst.zara"
]
assert foreign_list, "no list access record for the foreign reader (the empty read must still leave a trail)"
# DYNAMIC banned markers (finding 7, 2026-07-10: two static question
# fragments proved almost nothing): EVERY line-fragment (>=16 chars) of
# EVERY live transcript plaintext — both questions AND both model answers —
# plus the two static fragments (the BAR-3 plaintexts never rode a read
# response, so they stay static).
with open(transcript_path, encoding="utf-8") as fh:
    tdoc = json.load(fh)
fragments = []
for turn in tdoc["turns"]:
    for text in (turn.get("user_message"), turn.get("answer")):
        if not isinstance(text, str):
            continue
        for frag in text.splitlines():
            frag = frag.strip()
            if len(frag) >= 16:
                fragments.append(frag)
assert fragments, "the live transcript carried no scannable plaintext fragments"
banned = ["top 3 customers", "general-ledger balance"] + fragments
for line in raw:
    for idx, marker in enumerate(banned):
        assert marker not in line, (
            "transcript plaintext leaked into an access-log line "
            "(banned marker index %d; fragment redacted)" % idx
        )
print("ok")
' "$QC_TMP/conv-access-lines" "$QC_TMP/conv-transcript.json"
echo "  M8.5-B READ 6 OK: list/transcript/chain access trails with identifiers + outcome; zero plaintext in the access lines"

echo "  M8.5-B OK: read APIs verified over the live bar record (no new model calls)"
echo "PROOF M8.5-B (READ APIS) PASS"
