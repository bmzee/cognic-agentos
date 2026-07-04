#!/usr/bin/env bash
# Proof M6 (governed agent skill — deployed 3-bar proof) — the deployed proof
# that a RELEASED, signed SKILL pack's executable action runs FULLY SANDBOXED and
# reaches MCP tools ONLY through the kernel-side broker (enforcing declared_tools
# per call + routing to MCPHost.call_tool), against the deployed kernel + THREE
# released, signed packs (released assets only — none built from source here):
#   * cognic-skill-schema-summary@v0.1.0 — the M6 governed skill: SKILL.md
#     (hosted, read-only) + the signed cognic.skills executable action. Baked
#     into the kernel image (SKILL.md hosting/ingestion, ADR-025) AND the sandbox
#     runtime image (the ONLY place the action executes). Trust-registered at
#     boot against skill-packs/<id>/cosign.pub; NEVER operator-installed.
#   * cognic-tool-oracle-schema@v0.2.0 — the M5 DLP-governed tool release, reused;
#     operator-installed via the M4 flow; the skill's declared tools resolve to it.
#   * cognic-hook-schema-guard@v0.1.0 — the M5 hook pack, reused; baked +
#     trust-registered (REQUIRED: the oracle v0.2.0 manifest binds its dlp_pre
#     hooks; an absent hook pack fail-closes every governed tool call).
#
# It EXTENDS the proven Proof M4/M5 runner: same multi-actor proof app (X-Proof-
# Role binder, now proof_m6), same in-cluster Oracle XE + RS256/JWKS AS + single
# effective MCP URL (10.96.0.51:8765/mcp), same governed operator-install flow
# for the tool. The DELTAS: (a) the managed DockerSibling sandbox runtime + the
# Redis scheduler control plane (the skill executor's preconditions); (b) the
# REAL sandbox admission gate exercised via the documented bank re-home flow
# (re-tag + push + cosign-sign the canonical images under a proof canonical key
# in a local TLS registry — NO fixture bypass); (c) the THREE governed-skill
# bars, all POSTing the SAME deployed skill with the ARGUMENT as the only var:
#   * BAR 1 (composition) — owner=COGNIC -> 200 completed + fixed-shape summary
#     + the two DECLARED tools' governed audit.tool_invocation rows (list_tables
#     + describe_table) + a digest-only skill.invoked decision row.
#   * BAR 2 (undeclared refused) — mode=forbidden -> the action requests the
#     UNDECLARED get_constraints -> the broker refuses skill_tool_not_declared
#     BEFORE MCPHost.call_tool -> 403, zero get_constraints evidence, tool count
#     unchanged.
#   * BAR 3 (isolation — MANDATORY) — mode=exfil -> the action's direct outbound
#     call is blocked by --network none -> fail-closed 502 skill_runtime_error,
#     no ambient credential, no success marker anywhere.
#
# Operator-run + env-gated (COGNIC_RUN_PROOF_M6=1); NO default-on CI job (needs an
# image build + kind + a live Vault/Postgres/Redis + in-cluster Oracle XE + a
# local TLS registry + the host docker socket for the sibling sandbox).
#
# On any BAR failure the runner captures logs + HTTP status + the refusal reason
# + the skill.invoked / audit.tool_invocation% evidence to docs/VALIDATION-
# RESULTS.md and exits non-zero — the proof is NEVER redefined downward (BAR 3
# especially: isolation is mandatory, never weakened). On all-pass it prints
# "PROOF M6 (ALL BARS) PASS" and exits 0.
set -euo pipefail

if [[ "${COGNIC_RUN_PROOF_M6:-}" != "1" ]]; then
  echo "skipped: set COGNIC_RUN_PROOF_M6=1 to run the governed-agent-skill proof" >&2
  exit 0
fi

CLUSTER="${KIND_CLUSTER:-cognic-proofm6}"
NS="cognic-proofm6"
CHART="infra/charts/agentos"
PROOF_DIR="infra/proof-m6"
STAGING_DST="$PROOF_DIR/proof-m6-staging"           # released-pack staging output (build context)
CANONICAL_DIR="$STAGING_DST/canonical-trust"        # proof canonical cosign key + registry CA (baked into the kernel image)
PROOF_APP_SRC="$PROOF_DIR/proof_m6"                 # the proof-only multi-actor app factory (ALREADY in-context — no copy step)
AGENTOS_SRC_SRC="src/cognic_agentos"                # current kernel source overlay (the M6 wiring)
AGENTOS_SRC_DST="$PROOF_DIR/cognic_agentos"         # transient build-context copy
BASE_IMAGE="cognic-agentos:proof1b2-base"           # reused — same default-adapters base as proof-1b-2c/m4/m5
IMAGE="cognic-agentos:proofm6"
MCP_IMAGE="cognic-proof-oracle-pack:m6"
AS_IMAGE="cognic-proof-as:m6"
SKILL_RUNTIME_LOCAL_TAG="cognic-proof-skill-runtime:m6"  # the sandbox runtime image (host-local; re-homed to the registry below)
TENANT="proof-m6"
PACK_ID="cognic-tool-oracle-schema"
HOOK_PACK_ID="cognic-hook-schema-guard"
SKILL_PACK_ID="cognic-skill-schema-summary"
SKILL_ID="schema-summary"                           # the SKILL.md frontmatter name (the invoke path segment)
PACK_WHEEL="cognic_tool_oracle_schema-0.2.0-py3-none-any.whl"
BASE_URL="http://127.0.0.1:8000"
PF=""

# ---- proof canonical-image re-home (the REAL sandbox admission gate) -----------
# The sandbox admission pipeline cosign-verifies the runtime image against the
# canonical trust root (sandbox/catalog.py). We enact the DOCUMENTED bank re-home
# flow (core/config.py: "re-home to your registry + re-sign under their canonical
# trust root"; infra/sandbox/build-and-sign.md) with a dev-grade proof key — NO
# fixture flag, the full cosign verify runs. A local TLS registry on the kind
# docker network holds the images + their cosign signatures.
REGISTRY_NAME="cognic-proof-m6-registry"
# Host port for the local TLS registry. 5000 collides with macOS AirPlay
# Receiver (ControlCenter listens on *:5000 — hit live 2026-07-03), so default
# to an uncommon port; override via COGNIC_PROOF_M6_REGISTRY_PORT. The
# preflight fail-loud-probes it before any cluster work starts.
REGISTRY_PORT="${COGNIC_PROOF_M6_REGISTRY_PORT:-5551}"
# ONE ref string everywhere. Resolution per context (live-probed 2026-07-03):
#   * host docker daemon (push + the DockerSibling workload pull) + host
#     cosign: via the /etc/hosts loopback entry added at step 4 — the daemon
#     CANNOT resolve docker-network aliases (probe: "lookup ...: no such
#     host"); 127.0.0.1:$REGISTRY_PORT reaches the published port.
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
REGISTRY_TLS_DIR="${COGNIC_PROOF_M6_REGISTRY_TLS_DIR:-$HOME/.cognic/proof-m6/registry-tls}"
# The PUBLISHED canonical egress-proxy image (Settings default; re-homed + re-signed
# here). Pinned digest from core/config.py sandbox_canonical_egress_proxy_image.
PUBLISHED_EGRESS_PROXY="ghcr.io/bmzee/cognic-agentos/sandbox-egress-proxy@sha256:eb4ea75b427d0bc42039c68039eec51d6b0d0789400ba5bfdbf470ebec9139aa"
SKILL_RUNTIME_REF=""                                # filled after push+sign (digest-pinned)
EGRESS_PROXY_REF=""                                 # filled after push+sign (digest-pinned)

die() { echo "FAIL: $*" >&2; exit 1; }

# The backend image refs, sourced from backends.yaml (DRY — stays in sync with the
# smoke backends; awk field $2 ignores the trailing "# …" comment on each image: line).
_backend_images() {
  awk '/^[[:space:]]*image:/ {print $2}' "$CHART/ci/smoke/backends.yaml"
}

# Extra (non-backend) images the proof references with imagePullPolicy: IfNotPresent —
# pre-pulled + kind-loaded so the kind node never reaches the internet for them:
# oracle-xe + busybox (the oracle-pack wait-for-xe + the broker-share-perms init) +
# redis (the M6 scheduler control plane, manifests/redis.yaml) + registry:2 (the
# local TLS registry for the canonical re-home).
_extra_images() {
  printf '%s\n' "gvenzl/oracle-xe:21-slim" "busybox:1.36" "redis:7.4-alpine" "registry:2"
}

docker_pull_with_retry() {
  local img="$1"
  # 8 x 10s (~80s window): a transient resolver blip NXDOMAINed ghcr.io for
  # longer than the old 5 x 3s window could ride out (run 8, 2026-07-04).
  local max=8
  local attempt=1
  if [[ "${COGNIC_PROOF_M6_REUSE_IMAGES:-0}" == "1" ]] && docker image inspect "$img" >/dev/null 2>&1; then
    echo "  using cached image $img (COGNIC_PROOF_M6_REUSE_IMAGES=1)"
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
# pod — and the skill's broker-mediated tool calls ride that same MCPHost.
roll_and_wait() {
  kubectl -n "$NS" rollout restart deploy/rel-agentos
  kubectl -n "$NS" rollout status deploy/rel-agentos --timeout=600s \
    || agentos_fail "rel-agentos rollout did not complete within 600s"
  kubectl -n "$NS" wait --for=condition=ready pod -l app.kubernetes.io/name=agentos --timeout=600s \
    || agentos_fail "rel-agentos pod did not become Ready within 600s"
}

# ---- Multi-actor API helpers (drive the REAL operator + skill API via X-Proof-Role)
# api <ROLE> <METHOD> <PATH> [JSON_BODY] -> stdout is the response body; sets HTTP_CODE.
# The role header selects the proof Actor (author/reviewer/operator/mcp); tenant +
# originator come from the bound Actor, never the URL. The `mcp` role holds BOTH the
# governed MCP scopes AND skill.invoke, so the three bars ride it.
HTTP_CODE=""
HTTP_CODE_FILE="/tmp/proofm6-code"
load_http_code() {
  HTTP_CODE="$(cat "$HTTP_CODE_FILE" 2>/dev/null || true)"
}

api() {
  local role="$1" method="$2" path="$3" body="${4:-}"
  local out
  if [ -n "$body" ]; then
    out="$(curl -s -o /tmp/proofm6-resp -w '%{http_code}' -X "$method" \
      -H "X-Proof-Role: $role" -H 'Content-Type: application/json' \
      -d "$body" "$BASE_URL$path")"
  else
    out="$(curl -s -o /tmp/proofm6-resp -w '%{http_code}' -X "$method" \
      -H "X-Proof-Role: $role" "$BASE_URL$path")"
  fi
  HTTP_CODE="$out"
  printf '%s' "$out" > "$HTTP_CODE_FILE"
  cat /tmp/proofm6-resp
}

# discovery_status of the TOOL pack row from GET /system/plugins?tenant_id=proof-m6.
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

# ---- Skill-invocation evidence helpers (the BAR audit-chain reads) -------------
# Count of ALL successful tool executions (audit.tool_invocation rows) — the "did a
# tool run?" axis: BAR 1's declared calls raise it; BARs 2/3 must leave it UNCHANGED
# (the broker refuses / the sandbox blocks BEFORE any tool executes).
tool_invocation_count() {
  kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT count(*) FROM audit_event WHERE event_type='audit.tool_invocation';"
}

# Count of successful executions for ONE tool name (payload->>'tool_name'). The
# execution-layer evidence axis: BAR 1 asserts BOTH declared tools (list_tables +
# describe_table) ran; BAR 2 asserts the UNDECLARED get_constraints ran ZERO times.
# GovernanceJSON renders as native JSON on Postgres, so ->> is valid.
tool_invocation_count_for() {
  local tool_name="$1"
  kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT count(*) FROM audit_event WHERE event_type='audit.tool_invocation' AND payload->>'tool_name'='$tool_name';"
}

# The newest instruction-layer skill.invoked decision row (digest-only payload:
# skill_id + terminal_state + reason + arguments_sha256 + stdout_sha256; NEVER raw
# args/stdout). decision_history stores DecisionRecord.decision_type in its
# event_type column (core/decision_history.py), so we filter event_type='skill.invoked'.
latest_skill_invoked_payload() {
  kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT payload::text FROM decision_history WHERE event_type='skill.invoked' ORDER BY sequence DESC LIMIT 1;"
}

# Rows across BOTH evidence tables whose payload carries the given literal — the
# leak probe (BAR 3: the exfil success marker must be 0 everywhere). strpos, NOT
# LIKE — the sandbox never lets the marker be produced; this proves it.
evidence_rows_containing_literal() {
  local literal="$1"
  kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT (SELECT count(*) FROM audit_event WHERE strpos(payload::text, '$literal') > 0) + (SELECT count(*) FROM decision_history WHERE strpos(payload::text, '$literal') > 0);"
}

# ---- Skill-pack hosting preflight ---------------------------------------------
# The skill pack is trust-registered + HOSTED at boot (ADR-025): assert (a) the
# registered candidate row on GET /system/plugins (status=registered, kind=skills —
# the cosign gate against skill-packs/<id>/cosign.pub + the tenant allow-list
# passed), (b) the hosted_skills ingestion row (SKILL.md validated + declared_tools
# cross-checked against the registered oracle MCP server), and (c) NO skill/sandbox
# construction failures in the pod's boot logs (both are fail-soft: a failure leaves
# app.state.skill_executor None and the route 503s, so the bars must fail LOUD here
# instead). Hosting is per-pod (boot-time), so the runner re-asserts on the pod that
# serves the bars.
assert_skill_pack_hosted() {
  local where="$1" body
  body="$(curl -sf "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
  [ -n "$body" ] || bar_fail "$where — /api/v1/system/plugins unreachable for the skill-pack probe"
  if ! python3 - "$SKILL_PACK_ID" "$SKILL_ID" "$body" <<'PY'
import json, sys
pack_id, skill_id, raw = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    doc = json.loads(raw)
except Exception:
    print("plugins response is not JSON", file=sys.stderr)
    raise SystemExit(1)
rows = [p for p in doc.get("plugins", []) if p.get("pack_id") == pack_id]
if not rows:
    print(f"skill pack {pack_id}: no registered candidate row", file=sys.stderr)
    raise SystemExit(1)
row = rows[0]
if row.get("status") != "registered" or row.get("kind") != "skills":
    print(
        f"skill pack {pack_id}: status={row.get('status')!r} kind={row.get('kind')!r} "
        f"refusal_reason={row.get('refusal_reason')!r}",
        file=sys.stderr,
    )
    raise SystemExit(1)
hosted_rows = [h for h in doc.get("hosted_skills", []) if h.get("skill_id") == skill_id]
if not hosted_rows:
    print(
        f"skill {skill_id}: registered but NOT in hosted_skills "
        f"(SKILL.md ingestion / declared_tools cross-check failed, or the "
        f"skill executor did not construct)",
        file=sys.stderr,
    )
    raise SystemExit(1)
hosted = hosted_rows[0]
hosted_skill_id = hosted.get("skill_id")
print(
    f"  skill hosted: {pack_id} kind=skills status=registered "
    f"skill_id={hosted_skill_id} declared_tools={hosted.get('declared_tools')}"
)
PY
  then
    bar_fail "$where — skill pack not hosted (trust-register / SKILL.md ingestion / executor construction failed)"
  fi
  local boot_errs
  # Unescaped dots on the two fail-soft markers so the literal reason strings
  # (skill.executor_construction_failed / sandbox.runtime_construction_failed)
  # appear verbatim; `.` still matches the literal dot in the grep ERE.
  boot_errs="$(kubectl -n "$NS" logs deploy/rel-agentos 2>/dev/null \
    | grep -E 'skill.executor_construction_failed|sandbox.runtime_construction_failed|skill\.(pack_manifest_malformed|declared_tools_malformed|declared_tool_unregistered|skill_md_not_found|skill_md_invalid|entry_point_unresolved)' \
    || true)"
  [ -z "$boot_errs" ] \
    || bar_fail "$where — skill hosting / sandbox construction failures in boot logs: $boot_errs"
}

# ---- Hook-pack registry-admission preflight (M5-inherited) ---------------------
# The oracle v0.2.0 manifest binds dlp_pre hooks; the hook pack must be admitted at
# boot or every governed tool call (incl. the skill's) fail-closes at the DLP gate.
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

# ---- Failure diagnostics (mirror proof-m5: capture then exit non-zero) ----------
bar_fail() {
  local where="$1"
  echo "FAIL: $where — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local logs ds skill_audit skill_dh sandbox_dh reason
  logs="$(kubectl -n "$NS" logs deploy/rel-agentos 2>&1 | tail -180 || true)"
  ds="$(curl -s "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
  skill_audit="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT event_type, payload::text FROM audit_event WHERE event_type LIKE 'audit.tool_invocation%' ORDER BY sequence DESC LIMIT 12;" 2>/dev/null || true)"
  skill_dh="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT event_type, payload::text FROM decision_history WHERE event_type='skill.invoked' ORDER BY sequence DESC LIMIT 8;" 2>/dev/null || true)"
  # Run 19: the sandbox failed CLOSED on ONE refused egress attempt, and the
  # refused HOST lives ONLY on the sandbox.policy.violated chain row's
  # payload.proxy_log — which this capture did not read, so the fault host
  # was lost with the cluster. Capture the sandbox decision rows too.
  sandbox_dh="$(kubectl -n "$NS" exec deploy/postgres -- psql -U cognic -d cognic -tA \
    -c "SELECT event_type, payload::text FROM decision_history WHERE event_type LIKE 'sandbox.%' ORDER BY sequence DESC LIMIT 8;" 2>/dev/null || true)"
  reason="$(grep -Eo 'skill_[a-z_]+|sandbox_[a-z_]+|dlp_[a-z_]+|skill\.executor_construction_failed|sandbox\.runtime_construction_failed|discovery_status=[a-z_]+' <<<"$logs" | sort -u || true)"
  {
    echo ""
    echo "## Proof M6 — FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- last API response (HTTP $HTTP_CODE):"
    echo '```json'
    cat /tmp/proofm6-resp 2>/dev/null || echo "<no response captured>"
    echo ""
    echo '```'
    echo "- skill / sandbox reason markers:"
    echo '```'
    echo "${reason:-<none captured>}"
    echo '```'
    echo "- audit.tool_invocation% evidence (tail 12 — the execution-layer axis):"
    echo '```'
    echo "${skill_audit:-<none>}"
    echo '```'
    echo "- skill.invoked decision rows (tail 8 — the instruction-layer axis):"
    echo '```'
    echo "${skill_dh:-<none>}"
    echo '```'
    echo "- sandbox.% decision rows (tail 8 — lifecycle + policy.violated incl. proxy_log hosts):"
    echo '```'
    echo "${sandbox_dh:-<none>}"
    echo '```'
    echo "- /api/v1/system/plugins snapshot (plugins + hosted_skills):"
    echo '```json'
    echo "${ds:-<no response>}"
    echo '```'
    echo "- AgentOS pod logs (tail 180):"
    echo '```'
    echo "$logs"
    echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

# Step-5 XE-readiness failure path (mirrors proof-m5 xe_fail).
xe_fail() {
  local where="$1"
  echo "FAIL: oracle-xe ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local pods desc logs
  pods="$(kubectl -n "$NS" get pods 2>&1 || true)"
  desc="$(kubectl -n "$NS" describe pod -l app=oracle-xe 2>&1 | tail -90 || true)"
  logs="$(kubectl -n "$NS" logs -l app=oracle-xe --tail=120 2>&1 || true)"
  {
    echo ""
    echo "## Proof M6 — Oracle XE readiness FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- pods:"; echo '```'; echo "$pods"; echo '```'
    echo "- oracle-xe describe (tail 90):"; echo '```'; echo "$desc"; echo '```'
    echo "- oracle-xe logs (tail 120):"; echo '```'; echo "$logs"; echo '```'
  } >> docs/VALIDATION-RESULTS.md
  exit 1
}

# Step-5 backends-readiness failure path (mirrors proof-m5 backends_fail).
backends_fail() {
  local where="$1"
  echo "FAIL: backends ($where) — capturing diagnostics to docs/VALIDATION-RESULTS.md" >&2
  local wide ddeploy dpods notready_logs p
  wide="$(kubectl -n "$NS" get deploy,pods -o wide 2>&1 || true)"
  ddeploy="$(kubectl -n "$NS" describe deploy -l 'app notin (oracle-xe)' 2>&1 | tail -120 || true)"
  dpods="$(kubectl -n "$NS" describe pod -l 'app notin (oracle-xe)' 2>&1 | tail -150 || true)"
  # Runs 4-5 captured describes but NO pod logs — the actual fault (why a
  # container is Running-but-unready, or what it printed before its early
  # crashes) lives in `logs` + `logs --previous`. Capture both for every
  # not-ready backend pod.
  # Run 18: the all-pods describe tail-150 truncated the ONE pod that
  # mattered — a ContainerCreating pod has NO logs; its postStart/mount
  # events live only in describe, and they were cut. Each not-ready pod
  # gets its OWN describe tail below so the fault pod always survives
  # truncation. Comment kept OUTSIDE the command substitution: macOS
  # bash 3.2 mis-parses parens inside comments inside "$( ... )".
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
    echo "## Proof M6 — backends readiness FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
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
    echo "## Proof M6 — migration Job FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
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
    echo "## Proof M6 — AgentOS rollout FAILURE ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
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
  # remove the transient build-context copies (NOT the sources); proof_m6/ is a
  # tracked in-context source, so it is NOT removed.
  rm -rf "$STAGING_DST" "$AGENTOS_SRC_DST" "$PROOF_DIR/_local_as.py" 2>/dev/null || true
}
trap cleanup EXIT

# --- 1. preflight ---------------------------------------------------------------
echo "==> [1/11] tool preflight"
for tool in docker kind kubectl helm uv cosign syft grype curl python3 gh openssl; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool '$tool' not on PATH"
done
# Registry host-port preflight — fail LOUD with an actionable message here,
# not mid-run at `docker run -p` (macOS ControlCenter/AirPlay owns *:5000 by
# default, which is why the default moved to $REGISTRY_PORT).
python3 - "$REGISTRY_PORT" <<'PY' || die "registry port $REGISTRY_PORT already in use (lsof -nP -iTCP:$REGISTRY_PORT -sTCP:LISTEN shows the holder); override via COGNIC_PROOF_M6_REGISTRY_PORT"
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

# --- 2. stage the THREE RELEASED packs (download + sha256-verify + arrange) ------
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
mkdir -p "$CANONICAL_DIR"
export COSIGN_PASSWORD=""   # dev-grade proof key; empty password (NEVER a production key — custody is a Human-only decision per build-and-sign.md)
( cd "$CANONICAL_DIR" && cosign generate-key-pair )   # -> cosign.key + cosign.pub in CANONICAL_DIR
# The registry TLS CA/key are PERSISTENT (minted once at preflight, no sudo —
# the one-time operator certs.d trust must keep matching byte-for-byte across
# runs); COPY them into the per-run canonical dir so the registry mount, the
# SSL_CERT_FILE consumers, and the kernel-image trust bundle all read one
# location. SAN = the ref host + localhost so cosign + docker verify TLS
# against the same name the pod + host resolve.
cp "$REGISTRY_TLS_DIR/registry-ca.pem" "$REGISTRY_TLS_DIR/registry-key.pem" "$CANONICAL_DIR/"
chmod -R a+rX "$CANONICAL_DIR"

# --- 3. build the four images ---------------------------------------------------
echo "==> [3/11] copy the current kernel source into the proof build context (the M6 wiring)"
rm -rf "$AGENTOS_SRC_DST"
cp -r "$AGENTOS_SRC_SRC" "$AGENTOS_SRC_DST"
# proof_m6/ (the multi-actor app factory, $PROOF_APP_SRC) already lives inside
# $PROOF_DIR — it is IN the docker build context, so no copy step is needed.
echo "    proof app factory in-context at $PROOF_APP_SRC (no copy)"

echo "==> [3/11] build the default-adapters base image"
docker_build_with_retry -f infra/agentos/Dockerfile --target default-adapters -t "$BASE_IMAGE" .

echo "==> [3/11] build the proof AgentOS kernel image (create_proof_app + THREE released packs + sandbox trust)"
docker_build_with_retry -f "$PROOF_DIR/Dockerfile.agentos-proof" --build-arg BASE_IMAGE="$BASE_IMAGE" -t "$IMAGE" "$PROOF_DIR"

echo "==> [3/11] build the SANDBOX RUNTIME image (branch SDK overlay + released skill wheel; host-local)"
docker_build_with_retry -f "$PROOF_DIR/Dockerfile.skill-runtime" --build-arg BASE_IMAGE="$BASE_IMAGE" -t "$SKILL_RUNTIME_LOCAL_TAG" "$PROOF_DIR"

echo "==> [3/11] build the released oracle-pack MCP tool Service image (v0.2.0)"
docker_build_with_retry -f "$PROOF_DIR/Dockerfile.oracle-pack" -t "$MCP_IMAGE" "$PROOF_DIR"

echo "==> [3/11] build the emulated-external AS image (RS256 mode)"
cp tests/integration/pack_loop/_local_as.py "$PROOF_DIR/_local_as.py"
docker_build_with_retry -f "$PROOF_DIR/Dockerfile.as" -t "$AS_IMAGE" "$PROOF_DIR"

# --- 4. kind create + load (3 in-cluster proof images + backends + extras) --------
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

# --- 4b. local TLS registry + canonical re-home (build->push->sign->digest-pin) ---
# The REAL sandbox admission gate (sandbox/catalog.py cosign verify) needs the
# canonical images signed under the proof canonical key + reachable at a stable
# ref. Run a TLS registry:2 on the kind docker network so BOTH the kind node/pod
# (kind net) AND the host resolve $REGISTRY_REF_HOST; trust its CA on the host
# docker daemon. Real TLS (no insecure-registry bypass flag), NO fixture flag.
#
# Pod->registry name resolution is handled DETERMINISTICALLY at step 8: the
# runner computes the registry's kind-net IP and patches a hostAliases entry
# into the agentos Deployment (the kernel pod's in-pod cosign then resolves
# $REGISTRY_NAME directly; reachable pod -> node -> docker bridge). This
# replaced the earlier "operator adds if needed" fallback after the 2026-07-03
# live run proved the host daemon cannot resolve docker-network aliases at all.
echo "==> [4/11] start the local TLS registry:2 on the kind network + trust its CA on the host"
docker run -d --restart=always --name "$REGISTRY_NAME" --network kind \
  -v "$(cd "$CANONICAL_DIR" && pwd):/certs:ro" \
  -e "REGISTRY_HTTP_ADDR=0.0.0.0:$REGISTRY_PORT" \
  -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/registry-ca.pem \
  -e REGISTRY_HTTP_TLS_KEY=/certs/registry-key.pem \
  -p "$REGISTRY_PORT:$REGISTRY_PORT" \
  registry:2
# The host docker daemon cannot resolve docker-network aliases (live probe:
# `docker push $REGISTRY_NAME:PORT/...` -> "lookup ...: no such host"), so the
# SINGLE ref string resolves host-side via the loopback /etc/hosts entry ->
# the published port. That entry + the certs.d trust of the persistent CA are
# ONE-TIME operator-owned trust config, already VERIFIED at preflight — the
# runner itself is sudo-free (a backgrounded run has no TTY for a prompt).

echo "==> [4/11] re-home + cosign-sign BOTH canonical sandbox images under the proof canonical key"
# (1) the skill-runtime WORKLOAD image (built above, host-local)
docker tag "$SKILL_RUNTIME_LOCAL_TAG" "$REGISTRY_REF_HOST/sandbox-runtime-python:proofm6"
docker push "$REGISTRY_REF_HOST/sandbox-runtime-python:proofm6"
SKILL_RUNTIME_REF="$(docker inspect "$REGISTRY_REF_HOST/sandbox-runtime-python:proofm6" --format '{{index .RepoDigests 0}}')"
[ -n "$SKILL_RUNTIME_REF" ] || die "could not capture the pushed sandbox-runtime-python RepoDigests ref"
# --registry-cacert: host-side cosign dials the self-signed TLS registry. On
# macOS, Go's platform verifier (Security.framework) ignores SSL_CERT_FILE and
# enforces Apple's TLS policy (825-day cap + serverAuth EKU), which rejects
# the persistent proof CA ("certificate is not standards compliant" — hit
# live 2026-07-03). The explicit flag installs a PURE-GO custom root pool,
# sidestepping the platform verifier; the SAN covers $REGISTRY_NAME.
cosign sign --registry-cacert "$CANONICAL_DIR/registry-ca.pem" \
  --key "$CANONICAL_DIR/cosign.key" --yes "$SKILL_RUNTIME_REF"
# (2) the egress-proxy SIDECAR image (re-homed from the published canonical digest)
docker_pull_with_retry "$PUBLISHED_EGRESS_PROXY"
docker tag "$PUBLISHED_EGRESS_PROXY" "$REGISTRY_REF_HOST/sandbox-egress-proxy:proofm6"
docker push "$REGISTRY_REF_HOST/sandbox-egress-proxy:proofm6"
EGRESS_PROXY_REF="$(docker inspect "$REGISTRY_REF_HOST/sandbox-egress-proxy:proofm6" --format '{{index .RepoDigests 0}}')"
[ -n "$EGRESS_PROXY_REF" ] || die "could not capture the pushed sandbox-egress-proxy RepoDigests ref"
cosign sign --registry-cacert "$CANONICAL_DIR/registry-ca.pem" \
  --key "$CANONICAL_DIR/cosign.key" --yes "$EGRESS_PROXY_REF"
echo "  canonical refs (digest-pinned, proof-signed): runtime=$SKILL_RUNTIME_REF proxy=$EGRESS_PROXY_REF"

# --- 5. namespace + the six real backends + Redis, THEN the in-cluster Oracle XE --
echo "==> [5/11] bring up the six backends + Redis, then the seeded Oracle XE"
kubectl create namespace "$NS"
kubectl -n "$NS" apply -f "$CHART/ci/smoke/backends.yaml"
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/redis.yaml"
# M6 adds the redis Service (the scheduler control plane) to the shared-
# backends namespace, and kubelet's service-link env injection then hands
# EVERY pod REDIS_PORT=tcp://<clusterip>:6379 — which langfuse v2 validates
# as ITS OWN numeric Redis config and hard-rejects ("Invalid environment
# variables: { REDIS_PORT: ['Expected number, received nan'] }" — reproduced
# byte-exact 2026-07-04; M5 passed because it had NO redis). Disable service
# links on langfuse — the patch rolls a fresh clean-env ReplicaSet
# deterministically. The shared ci/smoke/backends.yaml is deliberately
# untouched mid-proof; fixing the fixture itself is a flagged follow-up.
kubectl -n "$NS" patch deploy/langfuse --type=strategic \
  -p '{"spec":{"template":{"spec":{"enableServiceLinks":false}}}}'
# Per-deployment PARALLEL waits with individual 600s budgets: `kubectl wait`
# on a label selector consumes its budget SEQUENTIALLY in alphabetical order,
# so one slow deployment (langfuse — runs 4-5) burns the WHOLE budget alone
# and the other six report "timed out" unexamined. Parallel waits give each
# backend its own budget and name the ACTUAL laggards in the failure message.
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
kubectl -n "$NS" wait --for=condition=ready pod -l app=oracle-xe --timeout=1200s \
  || xe_fail "oracle-xe pod not Ready within 1200s (qemu-emulated XE first boot under kind)"

# --- 6. Vault init/seed (KV v1 + OAuth + AS-allowlist) --------------------------
echo "==> [6/11] seed Vault (KV v1 conversion + OAuth + AS allow-list — by reference, D5)"
NS="$NS" bash "$PROOF_DIR/seed-vault.sh"

# --- 7. helm install (prod profile; migrations OFF; digest-pinned canonical images)
echo "==> [7/11] install the AgentOS chart under the proof-m6 overlay + the proof canonical refs"
# The digest-pinned, proof-signed canonical refs are injected via --set (the static
# overlay must NOT carry a personal-registry ref — deploy-safety guard G7).
helm install rel "$CHART" -n "$NS" -f "$PROOF_DIR/proof-m6-values.yaml" \
  --set sandbox.canonicalRuntimeImage="$SKILL_RUNTIME_REF" \
  --set sandbox.canonicalEgressProxyImage="$EGRESS_PROXY_REF"

# --- 8. migrate Job + apply the oracle-pack/AS manifests + the sandbox patch -----
echo "==> [8/11] run the proof-owned (non-hook) migration Job"
kubectl -n "$NS" delete job/agentos-migrate --ignore-not-found=true --wait=true
sed "s|__AGENTOS_IMAGE__|$IMAGE|" "$PROOF_DIR/migrate-job.yaml" | kubectl apply -n "$NS" -f -
kubectl -n "$NS" wait --for=condition=complete job/agentos-migrate --timeout=300s \
  || migrate_fail "agentos-migrate did not complete within 300s"

echo "==> [8/11] apply the oracle-pack MCP tool Service + AS manifests; wait Ready"
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/oracle-pack.yaml" -f "$PROOF_DIR/manifests/auth-server.yaml"
kubectl -n "$NS" rollout status deploy/proof-oracle-pack --timeout=180s
kubectl -n "$NS" rollout status deploy/proof-as --timeout=180s

echo "==> [8/11] patch the AgentOS Deployment with the sandbox topology (docker sock + broker share + TMPDIR)"
# The chart ships no extraVolume/extraEnv hooks; these three surfaces are proof
# TOPOLOGY (the DockerSibling sibling pattern + the broker's host-shared socket dir).
kubectl -n "$NS" patch deploy/rel-agentos --patch-file "$PROOF_DIR/agentos-sandbox-patch.yaml"

# Deterministic in-pod registry name resolution for the sandbox admission gate:
# the kernel pod's cosign verify dials $REGISTRY_REF_HOST, and cluster DNS
# knows no docker-network alias — patch a hostAliases entry with the
# registry's kind-net IP (reachable pod -> node -> docker bridge). Replaces
# the earlier "operator adds if needed" fallback with a deterministic step.
REGISTRY_KIND_IP="$(docker inspect -f '{{.NetworkSettings.Networks.kind.IPAddress}}' "$REGISTRY_NAME")"
[ -n "$REGISTRY_KIND_IP" ] || die "could not determine the registry's kind-network IP for the hostAliases patch"
kubectl -n "$NS" patch deploy/rel-agentos --type=strategic \
  -p "$(printf '{"spec":{"template":{"spec":{"hostAliases":[{"ip":"%s","hostnames":["%s"]}]}}}}' "$REGISTRY_KIND_IP" "$REGISTRY_NAME")"

# --- 9. DB seed (NO override/allow-list INSERT — install materializes them, M4) --
echo "==> [9/11] seed-db.sh (M6: NO derived-row INSERT — install materializes them)"
NS="$NS" bash "$PROOF_DIR/seed-db.sh"

# --- 10. roll to the sandbox-topology pod (migrated DB) + port-forward -----------
echo "==> [10/11] roll the Deployment so a fresh pod boots with the sandbox topology + migrated DB"
roll_and_wait
pf_start

# ---- Skill + hook preflight (before the lifecycle; fail fast) -------------------
echo "==> preflight — skill pack hosted + hook pack registry-admitted at boot"
assert_skill_pack_hosted "skill-pack preflight (first boot)"
assert_hook_pack_registered "hook-pack preflight (first boot)"

# ============================ SETUP (M4 governed install) ======================
# Operator-install the DLP-governed ORACLE tool v0.2.0 EXACTLY as proven in M4/M5:
# the full governed lifecycle via the REAL API, multi-actor via X-Proof-Role. The
# HOOK + SKILL packs deliberately take NO part in this flow (trust-register only).
echo "==> [11/11] SETUP — governed operator lifecycle for the oracle v0.2.0 tool (submit -> claim -> approve -> allow-list -> configure -> install)"

MANIFEST_JSON="$(uv run python - "$PACK_ID" "$PACK_WHEEL" <<'PY'
import json, sys
pack_id, wheel = sys.argv[1], sys.argv[2]
manifest = {
    "pack": {"kind": "tool", "name": pack_id, "version": "0.2.0"},
    "identity": {
        "agent_id": pack_id,
        "display_name": "Cognic Oracle Schema (proof-m6)",
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
    "display_name": "Cognic Oracle Schema (proof-m6)",
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
grep -qF "allowlist|$TENANT|10.96.0.51|proof-m6-operator" <<<"$DERIVED_ROWS" \
  || bar_fail "SETUP 8 no derived allow-list row (got: ${DERIVED_ROWS:-<none>})"
echo "  SETUP 8 OK: override + allow-list rows materialized by install (not seeded)"

echo "==> SETUP 9 — roll cold so the MCP probe + the skill's broker calls see the materialized carve-outs"
roll_and_wait
pf_start
echo "  SETUP 9 OK: cold pod ready"

# Re-assert hosting on THIS pod (per-pod boot-time) — it serves all three bars.
assert_skill_pack_hosted "BAR 1 preflight (skill pack on the serving pod)"
assert_hook_pack_registered "BAR 1 preflight (hook pack on the serving pod)"

# Warm the MCPHost per-tenant OAuth token + list_tools cache (governed MCP route)
# so the skill's own list_tables call rides a warm cache + a carve-out failure
# surfaces as a clear MCP error, not an opaque skill 502.
api mcp GET "/api/v1/mcp/servers/$PACK_ID/tools" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1 warm-up list_tools (HTTP $HTTP_CODE — MCP carve-out not live?)"
DS="$(discovery_status)"
[ "$DS" = "auth_ready" ] || bar_fail "BAR 1 discovery_status=$DS (expected auth_ready — the governed MCP carve-out)"

# ================================ BAR 1 (composition works) ====================
# owner=COGNIC -> the executor runs the action SANDBOXED; the broker mediates the
# DECLARED list_tables + describe_table through MCPHost.call_tool; a fixed-shape
# summary returns. Dual-layer evidence: BOTH declared tools' audit.tool_invocation
# rows (execution layer) + ONE digest-only skill.invoked decision row (instruction
# layer).
echo "==> BAR 1 — composition works (owner=COGNIC): 200 + fixed summary + dual-layer evidence"
BAR1_RESP="$(api mcp POST "/api/v1/skills/$SKILL_ID/invoke" \
  '{"arguments":{"owner":"COGNIC"}}')"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR 1 skill invoke (HTTP $HTTP_CODE; body: $BAR1_RESP)"
BAR1_STATE="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("terminal_state",""))' <<<"$BAR1_RESP" 2>/dev/null || true)"
[ "$BAR1_STATE" = "completed" ] || bar_fail "BAR 1 terminal_state '$BAR1_STATE' (expected 'completed'; body: $BAR1_RESP)"
# fixed-shape summary over the seeded schema (2 tables; EMPLOYEES carries FULL_NAME).
grep -qF '"table_count"' <<<"$BAR1_RESP" || bar_fail "BAR 1 no table_count in summary (body: $BAR1_RESP)"
grep -qF "DEPARTMENTS" <<<"$BAR1_RESP" || bar_fail "BAR 1 no DEPARTMENTS table in summary (body: $BAR1_RESP)"
grep -qF "EMPLOYEES" <<<"$BAR1_RESP" || bar_fail "BAR 1 no EMPLOYEES table in summary (body: $BAR1_RESP)"
grep -qF "FULL_NAME" <<<"$BAR1_RESP" || bar_fail "BAR 1 no EMPLOYEES column metadata (FULL_NAME; body: $BAR1_RESP)"
# execution-layer evidence: BOTH declared tools ran through the broker -> call_tool.
LIST_TABLES_ROWS="$(tool_invocation_count_for list_tables)"
DESCRIBE_TABLE_ROWS="$(tool_invocation_count_for describe_table)"
[ "$LIST_TABLES_ROWS" -ge 1 ] \
  || bar_fail "BAR 1 no governed list_tables audit.tool_invocation row (count=$LIST_TABLES_ROWS)"
[ "$DESCRIBE_TABLE_ROWS" -ge 1 ] \
  || bar_fail "BAR 1 no governed describe_table audit.tool_invocation row (count=$DESCRIBE_TABLE_ROWS)"
# instruction-layer evidence: ONE digest-only skill.invoked decision row.
BAR1_SKILL_PAYLOAD="$(latest_skill_invoked_payload)"
[ -n "$BAR1_SKILL_PAYLOAD" ] || bar_fail "BAR 1 no skill.invoked decision row"
if ! python3 - "$BAR1_SKILL_PAYLOAD" "$SKILL_ID" <<'PY'
import json, re, sys
payload = json.loads(sys.argv[1])
skill_id = sys.argv[2]
state = payload.get("terminal_state")
args_digest = payload.get("arguments_sha256") or ""
# digest-only: the arguments hash is present + well-formed; the raw owner never appears.
ok = (
    payload.get("skill_id") == skill_id
    and state == "completed"
    and re.fullmatch(r"[0-9a-f]{64}", args_digest) is not None
    and "owner" not in payload  # no raw arguments in the chain row
)
if not ok:
    print(
        f"skill_id={payload.get('skill_id')!r} terminal_state={state!r} "
        f"arguments_sha256={args_digest!r}",
        file=sys.stderr,
    )
    raise SystemExit(1)
print(f"  skill.invoked row OK: completed, arguments_sha256={args_digest[:12]}... (digest-only)")
PY
then
  bar_fail "BAR 1 skill.invoked row not a completed digest-only record (payload: $BAR1_SKILL_PAYLOAD)"
fi
echo "  Bar 1 OK: sandboxed composition, broker-mediated declared tools, dual-layer evidence"
echo "PROOF M6 (BAR 1) PASS"

# ================================ BAR 2 (undeclared refused BEFORE call_tool) ==
# mode=forbidden -> the action requests get_constraints (a REAL oracle tool OUTSIDE
# declared_tools) -> the broker refuses skill_tool_not_declared BEFORE MCPHost.
# call_tool: 403, ZERO get_constraints evidence, the success-count UNCHANGED.
echo "==> BAR 2 — undeclared tool (mode=forbidden): 403 skill_tool_not_declared BEFORE call_tool"
TOOL_INVOCATIONS_BEFORE_BAR2="$(tool_invocation_count)"
BAR2_RESP="$(api mcp POST "/api/v1/skills/$SKILL_ID/invoke" \
  '{"arguments":{"owner":"COGNIC","mode":"forbidden"}}')"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "403" ] || bar_fail "BAR 2 expected HTTP 403 skill_tool_not_declared (HTTP $HTTP_CODE; body: $BAR2_RESP)"
BAR2_STATE="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("terminal_state",""))' <<<"$BAR2_RESP" 2>/dev/null || true)"
BAR2_REASON="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("refusal_reason",""))' <<<"$BAR2_RESP" 2>/dev/null || true)"
[ "$BAR2_STATE" = "refused" ] || bar_fail "BAR 2 terminal_state '$BAR2_STATE' (expected 'refused'; body: $BAR2_RESP)"
[ "$BAR2_REASON" = "skill_tool_not_declared" ] \
  || bar_fail "BAR 2 refusal_reason '$BAR2_REASON' (expected 'skill_tool_not_declared'; body: $BAR2_RESP)"
# refused BEFORE the tool: the success count is UNCHANGED, and the UNDECLARED
# get_constraints tool has ZERO audit.tool_invocation rows (call_tool never reached).
TOOL_INVOCATIONS_AFTER_BAR2="$(tool_invocation_count)"
[ "$TOOL_INVOCATIONS_AFTER_BAR2" = "$TOOL_INVOCATIONS_BEFORE_BAR2" ] \
  || bar_fail "BAR 2 a tool execution occurred (audit.tool_invocation $TOOL_INVOCATIONS_BEFORE_BAR2 -> $TOOL_INVOCATIONS_AFTER_BAR2)"
GET_CONSTRAINTS_ROWS="$(tool_invocation_count_for get_constraints)"
[ "$GET_CONSTRAINTS_ROWS" = "0" ] \
  || bar_fail "BAR 2 the undeclared get_constraints tool executed $GET_CONSTRAINTS_ROWS time(s) (broker did not refuse before call_tool)"
echo "  Bar 2 OK: 403 skill_tool_not_declared, get_constraints never invoked, tool count unchanged"
echo "PROOF M6 (BAR 2) PASS"

# ================================ BAR 3 (isolation — MANDATORY) ================
# mode=exfil -> the action attempts a DIRECT outbound HTTP call (bypassing the
# broker) -> blocked by --network none (egress_allow_list=(), no ambient
# credentials) -> the failure propagates fail-closed -> 502 skill_runtime_error.
# Isolation is a REQUIRED part of M6 (spec §8) — never redefined downward. The
# success marker (unexpectedly_succeeded) must appear NOWHERE.
echo "==> BAR 3 — isolation holds (mode=exfil): direct outbound blocked -> 502 skill_runtime_error (fail-closed)"
TOOL_INVOCATIONS_BEFORE_BAR3="$(tool_invocation_count)"
BAR3_RESP="$(api mcp POST "/api/v1/skills/$SKILL_ID/invoke" \
  '{"arguments":{"owner":"COGNIC","mode":"exfil"}}')"
load_http_code # after api command substitution
[ "$HTTP_CODE" = "502" ] || bar_fail "BAR 3 expected HTTP 502 skill_runtime_error (HTTP $HTTP_CODE; body: $BAR3_RESP)"
BAR3_STATE="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("terminal_state",""))' <<<"$BAR3_RESP" 2>/dev/null || true)"
BAR3_REASON="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("refusal_reason",""))' <<<"$BAR3_RESP" 2>/dev/null || true)"
[ "$BAR3_STATE" = "failed" ] || bar_fail "BAR 3 terminal_state '$BAR3_STATE' (expected 'failed'; body: $BAR3_RESP)"
[ "$BAR3_REASON" = "skill_runtime_error" ] \
  || bar_fail "BAR 3 refusal_reason '$BAR3_REASON' (expected 'skill_runtime_error'; body: $BAR3_RESP)"
# no tool executed (the exfil probe goes direct, not through the broker), and the
# skill's success marker never leaks (it is only produced if the outbound SUCCEEDS,
# which --network none forbids) — check the response AND both evidence chains.
TOOL_INVOCATIONS_AFTER_BAR3="$(tool_invocation_count)"
[ "$TOOL_INVOCATIONS_AFTER_BAR3" = "$TOOL_INVOCATIONS_BEFORE_BAR3" ] \
  || bar_fail "BAR 3 a tool execution occurred (audit.tool_invocation $TOOL_INVOCATIONS_BEFORE_BAR3 -> $TOOL_INVOCATIONS_AFTER_BAR3)"
grep -qF "unexpectedly_succeeded" <<<"$BAR3_RESP" \
  && bar_fail "BAR 3 ISOLATION BREACH: the exfil probe succeeded (response carried unexpectedly_succeeded)"
EXFIL_MARKER_ROWS="$(evidence_rows_containing_literal 'unexpectedly_succeeded')"
[ "$EXFIL_MARKER_ROWS" = "0" ] \
  || bar_fail "BAR 3 ISOLATION BREACH: unexpectedly_succeeded appears in $EXFIL_MARKER_ROWS evidence row(s)"
echo "  Bar 3 OK: --network none blocked the direct egress, 502 skill_runtime_error fail-closed, no success marker anywhere"
echo "PROOF M6 (BAR 3) PASS"

echo "PROOF M6 (ALL BARS) PASS"
