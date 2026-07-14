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
# Operator-run + env-gated (COGNIC_RUN_PROOF_M85C=1); NO default-on CI job
# (needs an image build + kind + live Vault/Postgres/Redis + in-cluster
# Oracle XE + a local TLS registry + the host docker socket + the operator's
# CLOUD provider key). The provider key env (COGNIC_PROOF_M85C_TIER1_API_KEY)
# is REQUIRED at the gate — operator env at run time, never committed, never
# image-baked.
#
# On any BAR failure the runner captures logs + HTTP status + the
# conversation.% / agent.run.% / dispatch / audit evidence to
# docs/VALIDATION-RESULTS.md and exits non-zero — the proof is NEVER
# redefined downward. On all-pass it prints
# "PROOF M8.5-C (BARS 1-3) PASS" and exits 0.
set -euo pipefail

if [[ "${COGNIC_RUN_PROOF_M85C:-}" != "1" ]]; then
  echo "skipped: set COGNIC_RUN_PROOF_M85C=1 to run the governed-agent-loop proof" >&2
  exit 0
fi

# This runner uses associative arrays for the identity/token matrix. macOS still
# ships Bash 3.2, where `declare -A` is unsupported; without an explicit gate the
# documented `./run-proof-m85c.sh` invocation validates the provider key and then
# dies later at the first declaration. Refuse before ANY provider call or cluster
# work, with an actionable diagnostic instead of a parser-era shell error.
if [[ "${BASH_VERSINFO[0]:-0}" -lt 4 ]]; then
  echo "FAIL: proof-m85c requires Bash 4.0+ (associative arrays); this shell is" >&2
  echo "      Bash ${BASH_VERSION:-unknown}. Install a current Bash and invoke the" >&2
  echo "      runner with that binary. Refusing before provider or cluster work." >&2
  exit 1
fi

# The operator's CLOUD provider key — REQUIRED (fail loud, never a silent
# self-hosted fallback: BARs 1 and 3 drive the REAL cloud tier through the M8
# loop). The name matches proof-m85c-values.yaml's litellm_params api_key env
# reference.
if [[ -z "${COGNIC_PROOF_M85C_TIER1_API_KEY:-}" ]]; then
  echo "FAIL: COGNIC_PROOF_M85C_TIER1_API_KEY is unset — the M8.5 slice drives a REAL" >&2
  echo "      cloud tier-1 model (BARs 1 and 3 are model-driven turns). Export the" >&2
  echo "      operator's provider API key and re-run. (Provider swap = ONE values diff" >&2
  echo "      + COGNIC_PROOF_M85C_ALLOWED_PROVIDERS/COGNIC_PROOF_M85C_POLICY_MODE — README.)" >&2
  exit 1
fi

# Key-isolation window (review finding 1, 2026-07-10 round 3): copy the key
# into a NON-exported shell variable and DROP the exported variable NOW —
# before the FIRST external process — so no child (curl, stage-packs,
# cosign, openssl, docker, kubectl, ...) ever inherits it. A plain
# assignment to a NEW name carries no export attribute; under `set -u` any
# straggler reference to the exported name fails loud.
_PROVIDER_KEY_LOCAL="$COGNIC_PROOF_M85C_TIER1_API_KEY"
unset COGNIC_PROOF_M85C_TIER1_API_KEY


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
if [[ "${COGNIC_PROOF_M85C_ALLOWED_PROVIDERS:-openai}" == "openai" ]]; then
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
      echo "FAIL: COGNIC_PROOF_M85C_TIER1_API_KEY was REFUSED by api.openai.com (HTTP" >&2
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
  echo "provider-key preflight SKIPPED (provider swap: ${COGNIC_PROOF_M85C_ALLOWED_PROVIDERS} — no OpenAI probe)"
fi

CLUSTER="${KIND_CLUSTER:-cognic-proofm85c}"
NS="cognic-proofm85c"
CHART="infra/charts/agentos"
PROOF_DIR="infra/proof-m85c"
STAGING_DST="$PROOF_DIR/proof-m85c-staging"           # released-pack staging output (build context)
CANONICAL_DIR="$STAGING_DST/canonical-trust"        # proof canonical cosign key + registry CA (baked into the kernel image)
PROOF_APP_SRC="$PROOF_DIR/proof_m85c"                 # the proof-only multi-actor app factory (ALREADY in-context — no copy step)
AGENTOS_SRC_SRC="src/cognic_agentos"                # current kernel source overlay (the M8 wiring)
AGENTOS_SRC_DST="$PROOF_DIR/cognic_agentos"         # transient build-context copy
BASE_IMAGE="cognic-agentos:proof1b2-base"           # reused — same default-adapters base as proof-1b-2c/m4/m5/m6
IMAGE="cognic-agentos:proofm85c"
MCP_IMAGE="cognic-proof-oracle-pack:m85"
AS_IMAGE="cognic-proof-as:m85"
TENANT="proof-m85c"
PACK_ID="cognic-tool-oracle-schema"
HOOK_PACK_ID="cognic-hook-schema-guard"
AGENT_PACK_ID="cognic-agent-bank-analyst"
AGENT_ID="bank-analyst"                             # the AGENT.md frontmatter name (the ask path segment)
SKILL_IDS=("customer-data" "financial-data" "cards-data" "atm-recon")
SKILL_PACK_IDS=("cognic-skill-customer-data" "cognic-skill-financial-data" "cognic-skill-cards-data" "cognic-skill-atm-recon")
PACK_WHEEL="cognic_tool_oracle_schema-0.3.0-py3-none-any.whl"

# ---- The approval-probe pack's trust pins (Bar D drives the probe) ----------------
# THE PIN IS A MAINTAINER COMMIT, NOT AN OPERATOR EXPORT (review 2026-07-12, F4).
# The pre-review runner REQUIRED two exported digest env vars and exited 1 without
# them — but stage-packs.sh had already been converted to COMMITTED LITERALS and
# ignores those variables entirely. So the operator was forced to export values that
# were then discarded, and the README documented a prerequisite that did nothing.
# Those env vars are now GONE from this runner: the two names below are the
# stage-packs.sh SHELL VARIABLES the preflight reads, not environment inputs.
#
# An env-supplied digest is not a pin at all: whoever runs the proof could swap the
# release AND export a digest that matches the swap, and the "verification" would
# pass. A pin only means something when it is COMMITTED in the tree that the
# proof-input cleanliness guard checks BEFORE the run. So the live-run prerequisite
# is that a MAINTAINER has committed the two released digests into stage-packs.sh —
# and "released" is DERIVED from that fact here, never from an operator flag.
#
# This is a preflight: it fails LOUD in the first seconds, not 25 minutes in at Bar D.
_probe_pin() {   # read a committed `NAME="value"` literal out of stage-packs.sh
  sed -n "s/^$1=\"\\([^\"]*\\)\".*/\\1/p" "$PROOF_DIR/stage-packs.sh" | sed -n 1p
}
PROBE_WHEEL_PIN="$(_probe_pin PROBE_WHEEL_SHA256)"
PROBE_PUB_PIN="$(_probe_pin PROBE_PUB_SHA256)"
for _pin_pair in "PROBE_WHEEL_SHA256:$PROBE_WHEEL_PIN" "PROBE_PUB_SHA256:$PROBE_PUB_PIN"; do
  _pin_name="${_pin_pair%%:*}"
  _pin_value="${_pin_pair#*:}"
  if [ -z "$_pin_value" ]; then
    echo "FAIL: could not read the committed literal $_pin_name from $PROOF_DIR/stage-packs.sh" >&2
    echo "      (renamed or removed?). The probe's trust pins are maintainer-committed" >&2
    echo "      literals — the runner refuses to proceed without reading them." >&2
    exit 1
  fi
  if [ "$_pin_value" = "FILL_AT_RELEASE" ]; then
    echo "FAIL: the approval-probe pack is not pinned — $_pin_name in" >&2
    echo "      $PROOF_DIR/stage-packs.sh is still the FILL_AT_RELEASE sentinel." >&2
    echo "" >&2
    echo "      The live-run prerequisite is a MAINTAINER COMMIT of the two released" >&2
    echo "      digests, NOT an operator export: release the probe" >&2
    echo "      (cognic-tool-approval-probe: release.sh -> gh release create v0.1.0)," >&2
    echo "      then COMMIT the two sha256 values release.sh prints into stage-packs.sh" >&2
    echo "      (PROBE_WHEEL_SHA256 / PROBE_PUB_SHA256)." >&2
    echo "" >&2
    echo "      A pin the person running the proof supplies at run time is not a pin:" >&2
    echo "      they could swap the release and export a matching digest." >&2
    exit 1
  fi
done
unset _pin_pair _pin_name _pin_value
# RELEASED is DERIVED from the pins being real (assigned, never read from the
# operator's environment — an exported value cannot turn the probe arm on or off).
export COGNIC_PROOF_M85C_PROBE_RELEASED=1

# ---- M8.5-C identity + TLS surfaces ----------------------------------------------
# AgentOS serves HTTPS now (spec §5.1 TLS matrix): every curl to the kernel
# verifies against the per-run proof CA. There is no `http://` and no
# `-k`/`verify=False` on the human-identity path.
#
# Host port plan (three TLS surfaces, three distinct loopback ports so nothing
# collides). Keycloak MUST be reached on the SAME `cognic-proof-keycloak:8443`
# authority from BOTH the in-cluster kernel (cluster DNS) and the host-side
# driver + browser (an /etc/hosts loopback entry), so that ONE issuer string
# holds in every token the binder ever compares. That claims loopback:8443, so
# AgentOS's host port-forward moves off 8443 (its Service port stays 8443 — TLS
# does not care about the host-side port, and the cert SANs cover 127.0.0.1).
AGENTOS_PORT=8443                                    # the Service / container port (matches values + the image CMD)
AGENTOS_HOST_PORT=18443                              # the host port-forward (distinct from Keycloak's 8443)
BASE_URL="https://127.0.0.1:$AGENTOS_HOST_PORT"
# The per-run proof CA + the certs it signs (AgentOS, Keycloak, the BFF). All
# minted under $PKI_TMP (0700 mktemp, removed by the trap) — never committed,
# never image-baked. curl reads the CA via --cacert on EVERY kernel call.
PKI_TMP=""
PROOF_CA=""                                         # $PKI_TMP/proof-ca.pem (filled at the PKI step)
# The reference OIDC IdP. ONE hostname resolves identically in-cluster and on the
# host (an /etc/hosts loopback entry + a port-forward), so ONE issuer string holds
# in every token the binder ever compares.
KC_IMAGE="keycloak/keycloak:26.2@sha256:4883630ef9db14031cde3e60700c9a9a8eaf1b5c24db1589d6a2d43de38ba2a9"
KC_HOST="cognic-proof-keycloak"
KC_PORT=8443
KC_ISSUER="https://$KC_HOST:$KC_PORT/realms/proof-m85c"
KC_CLIENT="cognic-harness"
# The BFF (the product under test). Its image ships from the cognic-harness repo
# as a cosign-signed, digest-pinned artifact the runner verifies before load
# (spec §5.1). The harness repo lives beside this one.
HARNESS_REPO_DIR="${COGNIC_HARNESS_REPO_DIR:-../cognic-harness}"
HARNESS_IMAGE="cognic-harness:proofm85c"
HARNESS_HOST="cognic-proof-harness"
HARNESS_PORT=8443
HARNESS_BASE_URL="https://127.0.0.1:8444"           # host port-forward -> the BFF Service
# The v1 harness deliberately exposes no synthetic health route. `/signin` is
# its unauthenticated, side-effect-free serving probe: a 200 proves the shipped
# web route is live after the lifespan's OIDC discovery. Keep this in lockstep
# with manifests/bff.yaml; the structural suite pins both sides.
BFF_SERVING_PATH="/signin"
# The proof driver reuses the SAME cognic-harness client through a loopback
# redirect, so azp stays cognic-harness on every token the kernel sees. This URI
# is registered in the realm as a second redirect; nothing ever listens on it —
# the scripted flow reads the code off the 302 Location.
DRIVER_REDIRECT_URI="http://127.0.0.1:47113/proof-driver-callback"
BFF_REDIRECT_URI="$HARNESS_BASE_URL/auth/callback"

# The high-risk approval-probe pack (spec §6): a separately-released, cosign-signed
# MCP tool whose single tool `probe_write` appends a nonce to a proof-local ledger.
# Its manifest tier is high_risk_custom -> the ADR-014 four-eyes flow.
PROBE_PACK_ID="cognic-tool-approval-probe"
PROBE_PACK_VERSION="0.1.0"
PROBE_WHEEL="cognic_tool_approval_probe-0.1.0-py3-none-any.whl"
PROBE_IMAGE="cognic-proof-probe-pack:m85c"
PROBE_TOOL="probe_write"
PROBE_LEDGER_PATH="/var/probe/ledger"               # readable only by the runner via kubectl exec

# --- The identity matrix (replaces the retired X-Proof-Role binder) ---------------
# Every identity is a REAL Keycloak user. The runner logs each in via the scripted
# Authorization Code + PKCE flow (keycloak/pkce_login.py) and caches the minted
# access token; api() attaches it as a Bearer. Tenant + scopes ride the token's
# claims, verified locally by the reference binder — never a client header.
# This map exists ONLY so the runner can look up "which user for this step" and
# assert the claim contract; the SCOPES are authored in keycloak/gen_realm.py and
# proven against the minted token by keycloak/assert_claim_contract.py.
declare -A IDENTITY_TENANT=(
  [author]=proof-m85c [reviewer]=proof-m85c [operator]=proof-m85c
  [amir]=proof-m85c [sara]=proof-m85c [dana]=proof-m85c [erin]=proof-m85c
  [zara]=proof-foreign
)
declare -A IDENTITY_USER=(
  [author]=proof-m85c-author [reviewer]=proof-m85c-reviewer [operator]=proof-m85c-operator
  [amir]=analyst.amir [sara]=analyst.sara [dana]=approver.dana [erin]=approver.erin
  [zara]=analyst.zara
)
# The EXACT cognic_scopes set each user's token must carry (CSV, for the claim
# preflight). Kept in lockstep with keycloak/gen_realm.py by
# test_proof_m85c_structure.py so a scope drift between the realm and this map
# fails a unit test, not a live bar 30 minutes in.
declare -A IDENTITY_SCOPES=(
  [author]="pack.submit"
  [reviewer]="pack.review.claim,pack.review.approve,pack.review.reject,pack.override.approval_gate"
  [operator]="pack.allow_list,pack.configure,pack.install,pack.disable,pack.revoke,pack.uninstall,pack.audit.read"
  [amir]="conversation.create,conversation.read,conversation.post_turn,conversation.close,mcp.tool.list,mcp.tool.invoke"
  [sara]="conversation.create,conversation.read,conversation.post_turn,conversation.close,mcp.tool.list,mcp.tool.invoke"
  [dana]="tool.approve.high_risk_custom,tool.approve.observe"
  [erin]="tool.approve.high_risk_custom,tool.approve.observe"
  [zara]="conversation.create,conversation.read,conversation.post_turn,conversation.close,tool.approve.observe"
)
#: role -> cached Bearer access token (filled lazily by ensure_token()).
declare -A ROLE_TOKEN=()

PF=""
PF_KC=""                                            # keycloak host port-forward pid
PF_BFF=""                                           # BFF host port-forward pid
QC_TMP=""                                           # per-run PRIVATE query-context key dir (mktemp; removed by the trap)
KC_CRED_TMP=""                                      # per-run PRIVATE realm-credentials dir (mktemp; removed by the trap)

# ---- Per-step replica attribution (spec §5.2 Bar A: "Value-free proof logs record
# which pod served each step") -----------------------------------------------------
# The BFF exposes NO per-pod response header (the driver's served_by is [] — see
# playwright/README.md), so attribution cannot be OBSERVED off the wire. It is
# ESTABLISHED instead: every host port-forward targets a NAMED POD (`kubectl
# port-forward pod/<name>` bypasses the Service and connects to exactly that pod),
# so the runner CHOOSES the replica that serves each step and then records it. That
# is a fact the runner created, not an inference about which pod kube-proxy happened
# to pick — strictly stronger than reading a header the BFF would have to be trusted
# to set correctly.
BFF_POD_1=""                                        # the two live replica names, re-resolved
BFF_POD_2=""                                        # after ANYTHING that replaces pods
BFF_CURRENT_POD=""                                  # the pod the host 8444 forward targets NOW

# Cloud-policy posture — operator env at deploy time (never committed, never
# image-baked). Provider swap = the README's one-values-diff + these two envs.
ALLOWED_PROVIDERS="${COGNIC_PROOF_M85C_ALLOWED_PROVIDERS:-openai}"
POLICY_MODE="${COGNIC_PROOF_M85C_POLICY_MODE:-cloud_openai}"

# ---- proof canonical-image re-home (the REAL sandbox admission trust posture) ----
# The M6 executable-skill posture deploys UNCHANGED (hosted_skills precondition
# — see the header): the canonical sandbox images must be REAL, digest-pinned,
# proof-signed refs in a registry the node + pod + host all reach (G7 refuses
# ghcr.io/bmzee refs in prod). Both images re-home from their PUBLISHED
# canonical digests (core/config.py defaults) — pull, re-tag, push, cosign-sign
# under the per-run proof canonical key. NO fixture flag, real TLS.
REGISTRY_NAME="cognic-proof-m85c-registry"
# Host port for the local TLS registry. 5000 collides with macOS AirPlay
# Receiver (ControlCenter listens on *:5000 — hit live 2026-07-03), so default
# to an uncommon port; override via COGNIC_PROOF_M85C_REGISTRY_PORT. The
# preflight fail-loud-probes it before any cluster work starts.
REGISTRY_PORT="${COGNIC_PROOF_M85C_REGISTRY_PORT:-5551}"
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
REGISTRY_TLS_DIR="${COGNIC_PROOF_M85C_REGISTRY_TLS_DIR:-$HOME/.cognic/proof-m85c/registry-tls}"
# The PUBLISHED canonical images (Settings defaults; re-homed + re-signed here).
# Pinned digests from core/config.py sandbox_canonical_runtime_python_image +
# sandbox_canonical_egress_proxy_image.
PUBLISHED_RUNTIME_PYTHON="ghcr.io/bmzee/cognic-agentos/sandbox-runtime-python@sha256:b9ed3440ebf8535ba779f574b3c12a45095720ce78c292d8cc5cd338990e8eac"
PUBLISHED_EGRESS_PROXY="ghcr.io/bmzee/cognic-agentos/sandbox-egress-proxy@sha256:eb4ea75b427d0bc42039c68039eec51d6b0d0789400ba5bfdbf470ebec9139aa"
RUNTIME_PYTHON_REF=""                               # filled after push+sign (digest-pinned)
EGRESS_PROXY_REF=""                                 # filled after push+sign (digest-pinned)

die() { echo "FAIL: $*" >&2; exit 1; }

# redact <VALUE> — a NON-REVERSIBLE fingerprint of a credential, for failure messages.
#
# WHY (review 2026-07-12 round 4, F1). A failing bar is DIAGNOSED from its message,
# and those messages land in docs/VALIDATION-RESULTS.md and in the operator's
# terminal scrollback. Several of them used to interpolate the credential itself —
# the login JSON (which carries both session ids AND the callback URL with its
# one-time authorization code), the two session ids, the cookie dump. A proof whose
# FAILURE PATH discloses the very secrets its SUCCESS PATH proves are held
# server-side is not a custody proof.
#
# The fix is not to drop the detail — a message you cannot act on is its own defect —
# but to carry the FACT without the VALUE. `sha256(value)[:8]` + the length is enough
# to answer every question a failure actually raises ("are these two ids the same?",
# "was it empty?", "did it change between steps?") and reverses to nothing.
#
# The value rides STDIN, never argv — this helper exists precisely because its input
# is a credential, and argv is world-readable via `ps`.
redact() {
  printf '%s' "${1:-}" | python3 -c '
import hashlib, sys
raw = sys.stdin.buffer.read()
if not raw:
    print("<empty>")
else:
    print("sha256:" + hashlib.sha256(raw).hexdigest()[:8] + "/len=" + str(len(raw)))
'
}

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
  if [[ "${COGNIC_PROOF_M85C_REUSE_IMAGES:-0}" == "1" ]] && docker image inspect "$img" >/dev/null 2>&1; then
    echo "  using cached image $img (COGNIC_PROOF_M85C_REUSE_IMAGES=1)"
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
  kubectl -n "$NS" port-forward svc/rel-agentos "$AGENTOS_HOST_PORT:$AGENTOS_PORT" >/dev/null 2>&1 &
  PF=$!
  local _i
  for _i in $(seq 1 30); do
    # AgentOS serves HTTPS under the proof CA now — verify, never -k.
    if curl -sf --cacert "$PROOF_CA" "$BASE_URL/api/v1/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  bar_fail "port-forward did not expose a healthy AgentOS API"
}

# The Keycloak host port-forward — binds loopback:8443 so the host reaches the
# IdP at exactly `cognic-proof-keycloak:8443` (via the /etc/hosts entry), the
# SAME authority the in-cluster kernel uses. That single-issuer identity is what
# lets the reference binder compare `iss` with one exact string regardless of who
# minted the token.
kc_pf_start() {
  [ -n "${PF_KC:-}" ] && kill "$PF_KC" 2>/dev/null || true
  kubectl -n "$NS" port-forward --address 127.0.0.1 svc/cognic-proof-keycloak "$KC_PORT:$KC_PORT" >/dev/null 2>&1 &
  PF_KC=$!
  local _i
  for _i in $(seq 1 60); do
    if curl -sf --cacert "$PROOF_CA" "$KC_ISSUER/.well-known/openid-configuration" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  bar_fail "Keycloak host port-forward did not expose a reachable discovery document at $KC_ISSUER"
}

# bff_resolve_pods — (re-)resolve the two live BFF replica names into BFF_POD_1 /
# BFF_POD_2. MUST run after ANYTHING that replaces pods (the rollouts inside
# bff_set_ttls, the deliberate pod kill in S9) — a stale name would make the
# attribution below NAME A POD THAT NO LONGER EXISTS, and `kubectl port-forward`
# would simply fail. A terminating pod KEEPS phase=Running, so phase filtering alone
# is insufficient: require no deletionTimestamp AND Ready=True, then require the
# Deployment's exact two-replica postcondition before binding either name.
bff_resolve_pods() {
  local pods _i
  BFF_POD_1=""
  BFF_POD_2=""
  for _i in $(seq 1 30); do
    if pods="$(kubectl -n "$NS" get pods -l app=cognic-proof-harness -o json 2>/dev/null \
      | python3 -c '
import json, sys
document = json.load(sys.stdin)
names = sorted(
    "pod/" + item["metadata"]["name"]
    for item in document.get("items", [])
    if item.get("metadata", {}).get("deletionTimestamp") is None
    and item.get("status", {}).get("phase") == "Running"
    and any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in item.get("status", {}).get("conditions", [])
    )
)
if len(names) != 2:
    raise SystemExit(2)
print("\n".join(names))
')"; then
      BFF_POD_1="$(printf '%s\n' "$pods" | sed -n 1p)"
      BFF_POD_2="$(printf '%s\n' "$pods" | sed -n 2p)"
      return 0
    fi
    sleep 1
  done
  bar_fail "the BFF did not settle at exactly 2 Ready, non-Terminating replicas — per-step attribution cannot safely bind a pod"
}

# bff_served_by <STEP> [POD] — the value-free per-step attribution line (spec §5.2
# Bar A). Value-free by construction: a pod NAME carries no session, token, claim or
# customer material. Defaults to the pod the host forward currently targets.
bff_served_by() {
  local step="$1" pod="${2:-$BFF_CURRENT_POD}"
  [ -n "$pod" ] \
    || bar_fail "bff_served_by($step): no BFF pod is bound to the host forward (programming error) — the step's serving replica cannot be recorded"
  echo "  step=$step served_by=${pod#pod/}"
}

# The BFF host port-forward — the browser + the driver reach the product here.
#
# ALWAYS POD-TARGETED, never `svc/…`. Forwarding to the Service would hand the
# choice of replica to kube-proxy and leave the runner GUESSING which pod served a
# step; forwarding to `pod/<name>` bypasses the Service entirely, so the serving
# replica is a fact the runner ESTABLISHED. It ALTERNATES between the two replicas
# across calls, so both genuinely serve real Bar A traffic rather than one sitting
# idle behind a load balancer that never picked it.
bff_pf_start() {
  bff_resolve_pods
  local next="$BFF_POD_1"
  if [ -n "$BFF_POD_2" ] && [ "$BFF_CURRENT_POD" = "$BFF_POD_1" ]; then
    next="$BFF_POD_2"                 # alternate: the last step used pod 1
  fi
  bff_pf_pod "$next"
}

# Roll to a COLD pod so a fresh boot sees the current DB/Vault state, then wait Ready.
# Load-bearing after install: MCPHost caches BOTH the OAuth token and the list_tools
# result per tenant, so the materialized carve-out rows are only observable on a cold
# pod — and the agent's dispatched run_readonly_query rides that same MCPHost.
roll_and_wait() {
  kubectl -n "$NS" rollout restart deploy/rel-agentos
  # `rollout status` is the Deployment-owned readiness gate: it succeeds only after
  # the updated replica is Available and the old replicas are retired. Never follow
  # it with `kubectl wait pod -l ...`: selector waits bind the pod objects that exist
  # at invocation, so a predecessor deleted during the rollout can consume the whole
  # timeout even while the replacement pod is Ready (attempt-5 live finding).
  kubectl -n "$NS" rollout status deploy/rel-agentos --timeout=600s \
    || agentos_fail "rel-agentos rollout did not complete within 600s"
}

# ---- Multi-actor API helpers (drive the REAL operator + agent API via OIDC tokens)
# The X-Proof-Role binder is GONE (spec §4). Every identity is a real Keycloak
# user; api() attaches that user's REAL access token as a Bearer, and the
# reference OIDC binder verifies it locally (signature/issuer/audience/azp/time/
# tenant/scopes) before the kernel sees an Actor. Tenant + originator ride the
# token's claims — never a client header, never the URL.
HTTP_CODE=""
# Both paths are assigned under the private per-run $QC_TMP after it is
# minted (finding 2, 2026-07-10 — never shared /tmp); api() refuses loud if
# called earlier (mirrors the PSQL guard).
HTTP_CODE_FILE=""
API_RESP_FILE=""
load_http_code() {
  HTTP_CODE="$(cat "$HTTP_CODE_FILE" 2>/dev/null || true)"
}

# token_has_life <JWT> <FLOOR_S> — true iff the token's `exp` is more than FLOOR_S
# seconds in the future. DECODE-ONLY: this is a client-side cache-freshness check,
# NOT a verification (the reference binder is the only thing that verifies, and
# Bar B proves it). A token this cannot parse is treated as unusable (fail closed
# → re-mint), never as fresh.
#
# SECRET CUSTODY: the JWT rides STDIN, never argv. It is a live bearer credential,
# and a process's argument vector is world-readable — a `ps` snapshot during the
# python3 child's lifetime would hand any local user a usable token. This is the
# same rule api() obeys with `curl -K -`. The numeric FLOOR stays on argv: an
# integer is not a secret.
token_has_life() {
  printf '%s' "$1" | python3 -c '
import base64, json, sys, time
tok, floor = sys.stdin.read(), int(sys.argv[1])
try:
    payload = tok.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    sys.exit(0 if float(claims["exp"]) - time.time() > floor else 1)
except Exception:
    sys.exit(1)
' "$2"
}

# ensure_token <ROLE> — lazily mint (and cache) the role's REAL access token via
# the scripted Authorization Code + PKCE flow against the SAME cognic-harness
# client (keycloak/pkce_login.py). This is the ordinary interactive flow with the
# login form posted programmatically — NOT a Direct Access Grant and NOT client
# credentials (both are disabled on the client; Bar B proves the attempts fail).
# The client secret + the user password ride the ENVIRONMENT of the child
# (never argv — a `ps` snapshot would expose an argv secret). The minted token is
# cached in ROLE_TOKEN[$role]; nothing is written to disk here.
#
# The cache is EXPIRY-AWARE (Codex round-2 finding): the realm mints 900s access
# tokens, and the proof spends MINUTES between a role's first token and its last
# use (three cloud-model turns at up to 180s each sit between Bar A and Bar D).
# The pre-review cache returned the first token FOREVER, so a long run would send
# an expired bearer and the kernel would 403 `token_expired` — a proof failure
# that looks exactly like a governance bug. A cached token is now REUSED only
# while it still has > _TOKEN_MIN_LIFE_S of life; otherwise it is re-minted
# through the same PKCE flow. (Bar B's expired-token leg mints its OWN short-life
# token deliberately — it never rides this cache.)
_TOKEN_MIN_LIFE_S=120
ensure_token() {
  local role="$1"
  if [ -n "${ROLE_TOKEN[$role]:-}" ] && token_has_life "${ROLE_TOKEN[$role]}" "$_TOKEN_MIN_LIFE_S"; then
    return 0
  fi
  local user="${IDENTITY_USER[$role]:-}"
  [ -n "$user" ] || die "ensure_token: unknown role '$role'"
  [ -n "$KC_CRED_TMP" ] || die "ensure_token called before the realm credentials were minted"
  # The per-user password lives in the 0600 realm-credentials.env under the
  # private per-run dir. Look up its shell-safe var name (analyst.amir -> KC_PW_ANALYST_AMIR).
  local pw_var="KC_PW_$(printf '%s' "$user" | tr '[:lower:].-' '[:upper:]__')"
  local tokens_json rc
  set +e
  tokens_json="$(
    KC_CLIENT_SECRET="$KC_CLIENT_SECRET" \
    KC_USER_PASSWORD="$(grep "^$pw_var=" "$KC_CRED_TMP/realm-credentials.env" | cut -d= -f2-)" \
      python3 "$PROOF_DIR/keycloak/pkce_login.py" \
        "$KC_ISSUER" "$KC_CLIENT" "$DRIVER_REDIRECT_URI" "$user" "$PROOF_CA"
  )"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] || bar_fail "ensure_token: PKCE login failed for $user (rc=$rc)"
  ROLE_TOKEN[$role]="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' <<<"$tokens_json")"
  [ -n "${ROLE_TOKEN[$role]}" ] || bar_fail "ensure_token: no access_token minted for $user"
}

# ---- Keycloak ADMIN API (the deterministic lever for the time-dependent cases) ----
# Two live cases the spec REQUIRES (Bar A S6 concurrent refresh; Bar B expired
# token) are time-dependent: one needs a session whose access token is INSIDE the
# BFF's 60s refresh margin, the other needs an already-EXPIRED token. With the
# realm's 900s lifespan both would mean sleeping for a quarter of an hour, and the
# pre-review runner ducked them into unit suites instead (the Codex round-2 P1).
#
# The honest lever is Keycloak's OWN per-client override, `access.token.lifespan`
# (gen_realm.py pins it to the realm default 900 so the committed posture is
# UNCHANGED). The runner TEMPORARILY shrinks it, exercises the case against the
# real IdP + the real binder + the real BFF, and RESTORES it. `azp` stays
# `cognic-harness` throughout — the locked grant profile is untouched and the
# binder sees exactly the token shape it sees in every other leg. The mutation is
# disclosed in the README; a restore failure is a hard bar_fail, never a silent
# carry-over into the following bars.
KC_ADMIN_BASE="https://$KC_HOST:$KC_PORT"
KC_ADMIN_REALM="proof-m85c"
KC_ADMIN_USERNAME="proof-admin"

# SECRET CUSTODY (the same rule the rest of the runner obeys, and a structural
# test pins it): NEITHER the admin password NOR the admin bearer may ride a
# process argument vector — a `ps` snapshot on a shared host would expose them for
# the process lifetime. The password goes to curl's body on stdin (-d @-); the
# bearer goes through curl's config on stdin (-K -), exactly as api() does. The
# PUT is the one call that needs stdin for BOTH, so its body rides a 0600 file
# under the private per-run dir and stdin carries the header.
#
# The admin token rides the MASTER realm's built-in `admin-cli` client. That is a
# different realm and a different client from the locked `cognic-harness` profile
# Bar B pins — enabling it here does not weaken that proof.
kc_admin_token() {
  printf 'grant_type=password&client_id=admin-cli&username=%s&password=%s' \
    "$KC_ADMIN_USERNAME" "$(cat "$KC_CRED_TMP/kc-admin-password")" \
    | curl -s --cacert "$PROOF_CA" -d @- \
        "$KC_ADMIN_BASE/realms/master/protocol/openid-connect/token" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null
}

# kc_admin_get <PATH> — an admin GET with the bearer on stdin (never argv).
kc_admin_get() {
  local tok="$1" path="$2"
  printf 'header = "Authorization: Bearer %s"\n' "$tok" \
    | curl -s -K - --cacert "$PROOF_CA" "$KC_ADMIN_BASE$path"
}

# kc_set_access_token_lifespan <SECONDS> — READ-MODIFY-WRITE the client rep, so no
# other attribute (notably the rfc9068 at+jwt header type, on which every token in
# this proof depends) can be clobbered by a blind PUT.
kc_set_access_token_lifespan() {
  local seconds="$1" tok uuid rep_file code
  tok="$(kc_admin_token)"
  [ -n "$tok" ] || bar_fail "Keycloak admin token could not be obtained (admin-cli password grant on the master realm)"
  uuid="$(kc_admin_get "$tok" "/admin/realms/$KC_ADMIN_REALM/clients?clientId=$KC_CLIENT" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d[0]["id"] if d else "")')"
  [ -n "$uuid" ] || bar_fail "Keycloak admin API did not resolve the $KC_CLIENT client uuid"
  rep_file="$QC_TMP/kc-client-rep.json"
  ( umask 077; kc_admin_get "$tok" "/admin/realms/$KC_ADMIN_REALM/clients/$uuid" \
    | python3 -c '
import json, sys
rep = json.load(sys.stdin)
attrs = rep.setdefault("attributes", {})
# Fail LOUD rather than silently shipping a client whose at+jwt header type was
# dropped — the binder refuses every token without it and every bar would fail
# with an unrelated-looking error.
if attrs.get("access.token.header.type.rfc9068") != "true":
    raise SystemExit("the live client rep has no rfc9068 header-type attribute")
attrs["access.token.lifespan"] = sys.argv[1]
print(json.dumps(rep))
' "$seconds" > "$rep_file" ) \
    || bar_fail "Keycloak admin API returned no usable client representation for $KC_CLIENT (rfc9068 attribute missing?)"
  code="$(printf 'header = "Authorization: Bearer %s"\n' "$tok" \
    | curl -s -o /dev/null -w '%{http_code}' -K - --cacert "$PROOF_CA" \
        -X PUT -H "Content-Type: application/json" --data-binary "@$rep_file" \
        "$KC_ADMIN_BASE/admin/realms/$KC_ADMIN_REALM/clients/$uuid")"
  rm -f "$rep_file"
  [ "$code" = "204" ] \
    || bar_fail "Keycloak admin API refused the access.token.lifespan=$seconds update (HTTP $code)"
}

# kc_refresh_event_count — the INDEPENDENT observer for S6. Keycloak's own user-
# event log counts every refresh_token grant it served (gen_realm.py enables
# eventsEnabled + the REFRESH_TOKEN / REFRESH_TOKEN_ERROR types). If the BFF's
# single-flight broke and both replicas refreshed, Keycloak records TWO. This is a
# third party to the BFF, exactly as the probe ledger is a third party to the
# kernel — a self-reported "I refreshed once" line from the harness would not do.
# Prints "<refresh_ok_count> <refresh_error_count>".
kc_refresh_event_count() {
  local tok
  tok="$(kc_admin_token)"
  [ -n "$tok" ] || bar_fail "Keycloak admin token could not be obtained (refresh-event count)"
  kc_admin_get "$tok" \
    "/admin/realms/$KC_ADMIN_REALM/events?type=REFRESH_TOKEN&type=REFRESH_TOKEN_ERROR&max=2000" \
    | python3 -c '
import json, sys
events = json.load(sys.stdin)
ok = sum(1 for e in events if e.get("type") == "REFRESH_TOKEN")
err = sum(1 for e in events if e.get("type") == "REFRESH_TOKEN_ERROR")
print(f"{ok} {err}")
'
}

api() {
  local role="$1" method="$2" path="$3" body="${4:-}"
  local out
  [ -n "$HTTP_CODE_FILE" ] && [ -n "$API_RESP_FILE" ] \
    || die "api() called before QC_TMP was minted (programming error)"
  ensure_token "$role"
  # The bearer rides curl's config on STDIN (-K -), never argv — a `ps` snapshot
  # of the curl process must not expose the token. AgentOS is HTTPS under the
  # proof CA; we verify, never -k.
  if [ -n "$body" ]; then
    out="$(printf 'header = "Authorization: Bearer %s"\n' "${ROLE_TOKEN[$role]}" | curl -s -K - \
      -o "$API_RESP_FILE" -w '%{http_code}' --cacert "$PROOF_CA" -X "$method" \
      -H 'Content-Type: application/json' -d "$body" "$BASE_URL$path")"
  else
    out="$(printf 'header = "Authorization: Bearer %s"\n' "${ROLE_TOKEN[$role]}" | curl -s -K - \
      -o "$API_RESP_FILE" -w '%{http_code}' --cacert "$PROOF_CA" -X "$method" "$BASE_URL$path")"
  fi
  HTTP_CODE="$out"
  printf '%s' "$out" > "$HTTP_CODE_FILE"
  cat "$API_RESP_FILE"
}

# ---- Browser driver helper (the Playwright driver drives + observes; the runner
# makes every pass/fail judgement from the emitted JSON — a driver that decided a
# bar outcome would hide failures). Every browser bar goes through drive().
#
# drive <SUBCOMMAND> [ARGS...] -> stdout is the driver's JSON result. A non-zero
# driver exit is an INTERACTION failure (page never loaded, selector absent) and
# fails the bar with the driver's stderr diagnostic preserved. Global flags
# (base-url + the proof CA for SPKI pinning + a per-call out file) are attached
# here; the login subcommand additionally reads HARNESS_USER_PASSWORD from the
# env of the child (never argv). --leaf pins the SPKI of the on-disk harness +
# keycloak leaf certs the runner minted (the browser navigates to both origins);
# the driver fails closed if no pins can be computed — never a blanket bypass.
DRIVER_DIR="$PROOF_DIR/playwright"
DRIVER_VENV_TMP=""                                    # one per-run driver runtime; removed by cleanup
DRIVER_PYTHON=""                                      # direct interpreter; live bars never invoke uv
drive() {
  local sub="$1"
  shift
  [ -n "${QC_TMP:-}" ] || die "drive() called before QC_TMP was minted (programming error)"
  local out_file="$QC_TMP/driver-out.json" err_file="$QC_TMP/driver-err" rc
  set +e
  ( cd "$DRIVER_DIR" && "$DRIVER_PYTHON" driver.py "$sub" \
      --base-url "$HARNESS_BASE_URL" --ca "$PROOF_CA" \
      --leaf "$PKI_TMP/harness.crt" --leaf "$PKI_TMP/keycloak.crt" \
      --out "$out_file" --no-sandbox "$@" ) \
    >/dev/null 2>"$err_file"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    bar_fail "browser driver '$sub' interaction failed (rc=$rc): $(head -c 800 "$err_file" 2>/dev/null || echo '<no stderr>')"
  fi
  cat "$out_file"
}

# drive_replay_cookie <COOKIE_VALUE> — `driver.py replay-cookie` with the cookie in
# the CHILD'S ENVIRONMENT (COGNIC_PROOF_COOKIE_VALUE), never argv.
#
# POSSESSION OF THE COOKIE VALUE *IS* THE SESSION (review 2026-07-12, F1): it is a
# bearer credential exactly like an access token, and the pre-review call sites put
# it on the driver's ARGUMENT VECTOR (a value-bearing flag, since deleted from the
# driver) — visible to any local `ps` for the whole browser run (seconds, not
# milliseconds). With that flag gone this wrapper is the only way in; the env-prefix
# form below applies the variable to the `uv` child ALONE (the same shape drive_login
# uses for the password), never to the runner's own environment.
drive_replay_cookie() {
  local value="$1"
  [ -n "${QC_TMP:-}" ] || die "drive_replay_cookie() called before QC_TMP was minted (programming error)"
  [ -n "$value" ] \
    || bar_fail "drive_replay_cookie: EMPTY cookie value — a valueless cookie would make the replay probe report authenticated=false for the wrong reason (a vacuous pass)"
  local out_file="$QC_TMP/driver-out.json" err_file="$QC_TMP/driver-err" rc
  set +e
  ( cd "$DRIVER_DIR" && COGNIC_PROOF_COOKIE_VALUE="$value" "$DRIVER_PYTHON" \
      driver.py replay-cookie \
      --base-url "$HARNESS_BASE_URL" --ca "$PROOF_CA" \
      --leaf "$PKI_TMP/harness.crt" --leaf "$PKI_TMP/keycloak.crt" \
      --out "$out_file" --no-sandbox ) \
    >/dev/null 2>"$err_file"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    bar_fail "browser driver 'replay-cookie' interaction failed (rc=$rc): $(head -c 800 "$err_file" 2>/dev/null || echo '<no stderr>')"
  fi
  cat "$out_file"
}

# drive_replay_callback <CALLBACK_URL> <COOKIE_VALUE> — `driver.py replay-callback`
# with BOTH credentials in the CHILD'S ENVIRONMENT, never argv.
#
# The callback URL is a credential too (F1): it carries `?code=<one-time authz
# code>&state=…`, and that code is EXCHANGEABLE FOR TOKENS. The pre-review call
# site put it on argv.
#
# The cookie is REQUIRED here even though the driver keeps it optional: S5's whole
# point (round-2 R2) is that the replay must carry the PRE-AUTH cookie to reach
# consume_oidc() — a cookieless replay dies at the session gate and proves nothing
# about single-use state. The driver still supports the cookieless shape (an unset
# env var) so it stays drivable by hand.
drive_replay_callback() {
  local url="$1" cookie="$2"
  [ -n "${QC_TMP:-}" ] || die "drive_replay_callback() called before QC_TMP was minted (programming error)"
  [ -n "$url" ] || bar_fail "drive_replay_callback: empty callback URL (nothing to replay)"
  [ -n "$cookie" ] \
    || bar_fail "drive_replay_callback: EMPTY pre-auth cookie — a cookieless replay is refused at the BFF's session gate (no_login_session) BEFORE consume_oidc() runs, so S5 would prove nothing about state/nonce single-use"
  local out_file="$QC_TMP/driver-out.json" err_file="$QC_TMP/driver-err" rc
  set +e
  ( cd "$DRIVER_DIR" \
      && COGNIC_PROOF_CALLBACK_URL="$url" COGNIC_PROOF_COOKIE_VALUE="$cookie" \
         "$DRIVER_PYTHON" driver.py replay-callback \
         --base-url "$HARNESS_BASE_URL" --ca "$PROOF_CA" \
         --leaf "$PKI_TMP/harness.crt" --leaf "$PKI_TMP/keycloak.crt" \
         --out "$out_file" --no-sandbox ) \
    >/dev/null 2>"$err_file"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ]; then
    bar_fail "browser driver 'replay-callback' interaction failed (rc=$rc): $(head -c 800 "$err_file" 2>/dev/null || echo '<no stderr>')"
  fi
  cat "$out_file"
}

# drive_login <ROLE> [LANDING_PATH] — drive a REAL browser login for the role's Keycloak user,
# reading the per-user password from the realm-credentials env (via the child's
# env, never argv). Prints the login JSON; persists the session state-file per
# role so later drive() calls reuse the authenticated context. The destination
# defaults to chat; approval-only humans explicitly land on /approvals so login
# completion never requires the unrelated conversation.read scope.
drive_login() {
  # TWO STATEMENTS, DELIBERATELY. Found while building the round-5 mutation tests, and it
  # is a LIVE-RUN-FATAL bug that had never fired only because the proof has never been run
  # end to end: `local a="$1" b="${MAP[$a]}"` DOES NOT WORK. Bash word-expands EVERY
  # argument of the `local` builtin BEFORE the builtin assigns any of them, so the `$a`
  # inside the second argument is the OUTER (unset) `a`, never the one being assigned
  # beside it. Under the `set -u` this script runs with, that is a hard
  # `role: unbound variable` abort — reproduced on bash 3.2, 4.4 AND 5.2. Bar A's very
  # first call is `drive_login amir`, so the entire proof died on its first login, on
  # every bash version. (`ensure_token` is fine: its lookup is a separate statement, by
  # which time `role` really is bound.)
  local role="$1" landing_path="${2:-/}" user
  user="${IDENTITY_USER[$role]:-}"
  [ -n "$user" ] || die "drive_login: unknown role '$role'"
  local pw_var="KC_PW_$(printf '%s' "$user" | tr '[:lower:].-' '[:upper:]__')"
  local pw out_file="$QC_TMP/driver-out.json" err_file="$QC_TMP/driver-err" rc
  pw="$(grep "^$pw_var=" "$KC_CRED_TMP/realm-credentials.env" | cut -d= -f2-)"
  set +e
  ( cd "$DRIVER_DIR" && HARNESS_USER_PASSWORD="$pw" "$DRIVER_PYTHON" \
      driver.py login --username "$user" \
      --landing-path "$landing_path" \
      --base-url "$HARNESS_BASE_URL" --ca "$PROOF_CA" \
      --leaf "$PKI_TMP/harness.crt" --leaf "$PKI_TMP/keycloak.crt" \
      --state-file "$QC_TMP/session-$role.json" --out "$out_file" --no-sandbox ) \
    >/dev/null 2>"$err_file"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] || bar_fail "browser login for $user failed (rc=$rc): $(head -c 800 "$err_file" 2>/dev/null)"
  cat "$out_file"
}

# _LOGIN_OUTCOME_PY — classify a login drive into the CLOSED 3-value outcome vocabulary.
#
# A FAILED DRIVE IS NOT AN OBSERVATION OF A REFUSAL (review 2026-07-12 round 5, F1).
# The pre-review drive_login_capture synthesised {"ok": false, "login_failed": true} for
# EVERY non-zero exit and every empty --out. That conflates two completely different
# events:
#
#   1. THE BFF REFUSED THE LOGIN            — the claim S7 makes; and
#   2. THE PROOF HARNESS BROKE              — a Chromium crash, a selector typo, a `uv`
#                                             dependency-resolution failure, an OOM, a
#                                             password missing from the credentials file.
#
# Every one of (2) satisfied S7's assertion. So a broken driver MANUFACTURED the evidence
# that the BFF failed closed — the fabricated default is always the safe-looking one, and
# it is invisible on a green run.
#
# The driver now OBSERVES the BFF's own HTTP status on the login navigation (page.goto()
# returns the Response on a non-2xx) and writes a discriminated observation to --out
# BEFORE exiting non-zero. This reader passes that observation through — and ONLY that:
#
#   outcome=authenticated   the driver's own JSON; the BFF authenticated the login.
#   outcome=refused         the BFF ITSELF refused, carrying the OBSERVED http_status.
#   outcome=driver_error    minted HERE, never by the driver: an empty --out, a partial
#                           write, a non-JSON body, an unknown/absent outcome, or an
#                           exit code that contradicts the document. NOT evidence of
#                           anything whatsoever about the BFF.
#
# The out file is a CREDENTIAL (a successful login JSON carries both session ids and the
# `?code=` callback URL), so it rides STDIN. Only the exit code and the stderr PATH — a
# number and a path, neither a secret — are on argv.
_LOGIN_OUTCOME_PY='
import json, sys

rc, err_path = int(sys.argv[1]), sys.argv[2]

def driver_error(detail):
    try:
        with open(err_path, "r", errors="replace") as handle:
            stderr = handle.read()[-400:]
    except OSError:
        stderr = "<the driver stderr file could not be read>"
    print(json.dumps({
        "ok": False,
        "outcome": "driver_error",
        "detail": detail,
        "rc": rc,
        "stderr": stderr,
    }))
    raise SystemExit(0)

raw = sys.stdin.read()
if not raw.strip():
    driver_error("the driver wrote NO result document to --out")
try:
    doc = json.loads(raw)
except ValueError as exc:
    driver_error("the driver result document does not parse as JSON (%s)" % (exc,))
if not isinstance(doc, dict):
    driver_error("the driver result document is not a JSON object")
outcome = doc.get("outcome")
if outcome == "authenticated":
    if rc != 0:
        driver_error("the driver reported authenticated but exited %d" % (rc,))
elif outcome == "refused":
    if not isinstance(doc.get("http_status"), int):
        driver_error("the driver reported refused with NO observed http_status")
    # driver.py owns LOGIN_REFUSED_EXIT = 5. A refusal-shaped document paired
    # with any other status is contradictory and must never be trusted; the
    # cross-file regression pins this literal to the driver constant.
    if rc != 5:
        driver_error("the driver reported refused but exited %d, not the refusal code 5" % (rc,))
else:
    driver_error("the driver result carries no known outcome (got %r)" % (outcome,))
print(json.dumps(doc))
'

# drive_login_capture <ROLE> — drive a login and REPORT its outcome rather than
# bar_failing on it, so the CORRECT fail-closed login S7 depends on does not abort the
# whole proof. It emits the closed 3-value outcome above; the caller judges.
#
# It NEVER bar_fails (which would also be swallowed here: callers invoke it as
# `A_OUTAGE="$(drive_login_capture …)"`, and bash 3.2 ignores `set -e` inside the subshell
# of an assignment's command substitution). _LOGIN_OUTCOME_PY always exits 0 and always
# prints a well-formed document, so the outcome is ALWAYS readable — and every outcome
# other than the driver's own observation is `driver_error`, which the caller must treat
# as a broken proof, never as a passing one.
drive_login_capture() {
  # TWO STATEMENTS — see the note on drive_login above. `local a="$1" b="${MAP[$a]}"` aborts
  # under `set -u` on every bash version.
  local role="$1" user
  user="${IDENTITY_USER[$role]:-}"
  [ -n "$user" ] || die "drive_login_capture: unknown role '$role'"
  local pw_var="KC_PW_$(printf '%s' "$user" | tr '[:lower:].-' '[:upper:]__')"
  local pw out_file="$QC_TMP/driver-out.json" err_file="$QC_TMP/driver-err" rc
  pw="$(grep "^$pw_var=" "$KC_CRED_TMP/realm-credentials.env" | cut -d= -f2-)"
  : > "$out_file"
  : > "$err_file"
  set +e
  ( cd "$DRIVER_DIR" && HARNESS_USER_PASSWORD="$pw" "$DRIVER_PYTHON" \
      driver.py login --username "$user" \
      --base-url "$HARNESS_BASE_URL" --ca "$PROOF_CA" \
      --leaf "$PKI_TMP/harness.crt" --leaf "$PKI_TMP/keycloak.crt" \
      --state-file "$QC_TMP/session-$role.json" --out "$out_file" --no-sandbox ) \
    >/dev/null 2>"$err_file"
  rc=$?
  set -e
  python3 -c "$_LOGIN_OUTCOME_PY" "$rc" "$err_file" < "$out_file"
}

# bff_fresh_login_status — the HTTP status of a COOKIE-LESS, CA-verified `GET /login`.
#
# THE DIRECT, DRIVER-FREE OBSERVATION OF S7's CLAIM (round 5, F1). There is no browser in
# this loop, so there is no fabrication surface in it at all. `GET /login` →
# `AuthService.begin_login()` → `store.create_pre_auth()` is the FIRST session-store touch
# in the entire login flow; with the store destroyed it raises SessionStoreUnavailable,
# and the harness's registered handler returns EXACTLY 503 ("Store outage → fail closed
# with a 503; never a memory continuation (S7)"). So a plain cookie-less GET is a direct
# HTTP observation of the very refusal S7 asserts.
#
# `bff_status` is the WRONG tool here: it always sends a `Cookie:` header, and this probe
# must be a FRESH, UNAUTHENTICATED login. No cookie means no bearer credential, so nothing
# needs to ride stdin — the URL and flags stay on argv, as always.
#
# CONTRACT (the kubectl_capture contract): PRINTS the status and RETURNS curl's exit
# status. The caller MUST check it. curl prints `000` for %{http_code} when the connection
# never happened — a TLS failure, an unreachable BFF, a dead port-forward, a bad CA — and
# a tool that could not run has OBSERVED NOTHING. `-L` is deliberately absent: the healthy
# path 3xx-redirects to Keycloak, and following it would report KEYCLOAK's status instead
# of the BFF's.
bff_fresh_login_status() {
  local code rc
  set +e
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 --cacert "$PROOF_CA" \
    "$HARNESS_BASE_URL/login")"
  rc=$?
  set -e
  printf '%s' "$code"
  return "$rc"
}

# bff_pf_pod <POD-NAME> — port-forward the host 8444 to ONE specific BFF pod (never
# the Service) so a step provably hits a NAMED replica. This is how Bar A attributes
# "which pod served each step" without a per-pod response header: the runner CHOOSES
# the pod. It is the ONLY way the host forward is ever established (bff_pf_start
# delegates here), and it records the choice in BFF_CURRENT_POD so bff_served_by can
# name the serving replica for every subsequent step.
bff_pf_pod() {
  local pod="$1" _i
  [ -n "$pod" ] || bar_fail "bff_pf_pod: empty pod name (programming error)"
  BFF_CURRENT_POD="$pod"
  [ -n "${PF_BFF:-}" ] && kill "$PF_BFF" 2>/dev/null || true
  kubectl -n "$NS" port-forward --address 127.0.0.1 "$pod" "8444:$HARNESS_PORT" >/dev/null 2>&1 &
  PF_BFF=$!
  for _i in $(seq 1 30); do
    if curl -fsS -o /dev/null --max-time 5 --cacert "$PROOF_CA" \
        "$HARNESS_BASE_URL$BFF_SERVING_PATH" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  bff_fail "per-pod port-forward to $pod did not become reachable"
}

# ---- BFF probes used by the live session cases (S4 / S6 / S7 / S10) --------------
# The single session cookie the BFF sets (cognic_harness/auth/cookies.py).
BFF_COOKIE_NAME="__Host-cognic_session"

# SECRET CUSTODY for the cookie (applies to bff_status + bff_touch below).
# POSSESSION OF THE `__Host-cognic_session` VALUE *IS* THE SESSION — it is a bearer
# credential exactly like an access token, and the whole point of Bar A is that the
# BFF hands the browser nothing else. So it must never ride curl's argv (`-H
# "Cookie: …"`), where a `ps` snapshot by any local user captures it for the
# process lifetime. It goes through curl's config on STDIN (`-K -`), exactly as
# api() does with the Authorization bearer. The URL and the flags stay on argv:
# neither is a secret.

# bff_status <COOKIE_VALUE> [URL] — the EXACT HTTP status the BFF returns for a
# session cookie. The driver reports a semantic `authenticated` boolean, which is
# the right observable for "is this session alive"; this is the right observable
# when the SPEC names a status (S7: "fails closed with 503"). Both are used.
bff_status() {
  printf 'header = "Cookie: %s=%s"\n' "$BFF_COOKIE_NAME" "$1" \
    | curl -s -K - -o /dev/null -w '%{http_code}' --max-time 30 --cacert "$PROOF_CA" \
        "${2:-$HARNESS_BASE_URL/}"
}

# bff_touch <COOKIE_VALUE> — a cheap authenticated request that TOUCHES the idle
# TTL. Used by S4 leg 2 to keep a session continuously active (a browser drive
# would work but costs seconds per call and would blur the TTL timing the leg
# depends on).
#
# EVERY TOUCH MUST LAND (review 2026-07-12, F2). The pre-review helper ended in
# `|| true` and never looked at the status — so if the touches silently stopped
# landing (a dead port-forward, a rolled pod, a rejected cookie), the session would
# die of IDLE expiry at 45s and the final `authenticated=false` at ~165s would be
# misattributed to the ABSOLUTE TTL. The leg would "prove" absolute expiry using
# idle expiry. An unverified touch destroys the leg's entire timing argument, so a
# non-200 (or a transport failure) is a hard bar_fail, never a swallowed error.
bff_touch() {
  local code rc
  set +e
  code="$(printf 'header = "Cookie: %s=%s"\n' "$BFF_COOKIE_NAME" "$1" \
    | curl -s -K - -o /dev/null -w '%{http_code}' --max-time 30 --cacert "$PROOF_CA" \
        "$HARNESS_BASE_URL/")"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] \
    || bar_fail "BAR A S4 leg 2: a keep-alive touch could not REACH the BFF (curl exit $rc). An unverified touch destroys the leg's timing argument — an idle-expired session would then be misread as absolute-TTL expiry."
  [ "$code" = "200" ] \
    || bar_fail "BAR A S4 leg 2: a keep-alive touch returned HTTP $code (expected 200). The session is NOT being kept active, so a later death cannot be attributed to the ABSOLUTE TTL — idle expiry would explain it just as well."
}

# bff_set_ttls <IDLE_S> <ABSOLUTE_S> — repoint the BFF's session TTLs and roll.
# S4 (idle vs absolute TTL independence) is unobservable at the committed proof
# TTLs (idle 900s / absolute 28800s): proving it would mean sleeping for eight
# hours. The honest lever is the BFF's OWN configuration surface — the same env
# vars a bank operator sets (COGNIC_HARNESS_SESSION_{IDLE,ABSOLUTE}_TTL_S,
# bootstrap/settings.py:122). The runner shrinks them, proves BOTH legs against
# the real Redis-backed store, and RESTORES. Disclosed in the README; a restore
# failure is a hard bar_fail, never a silent carry-over.
#
# The rollout REPLACES both pods, so bff_pf_start's bff_resolve_pods is what keeps
# the per-step replica attribution honest across it (a stale pod name would name a
# replica that no longer exists).
bff_set_ttls() {
  kubectl -n "$NS" set env deploy/cognic-proof-harness \
    "COGNIC_HARNESS_SESSION_IDLE_TTL_S=$1" "COGNIC_HARNESS_SESSION_ABSOLUTE_TTL_S=$2" >/dev/null \
    || bar_fail "BAR A S4 could not set the BFF session TTLs (idle=$1 absolute=$2)"
  kubectl -n "$NS" rollout status deploy/cognic-proof-harness --timeout=180s \
    || bff_fail "BAR A S4 the BFF did not roll out with TTLs idle=$1 absolute=$2"
  BFF_CURRENT_POD=""            # the pods this named are GONE — re-resolve, never reuse
  bff_pf_start
}

# bff_pf_dual — port-forward BOTH replicas SIMULTANEOUSLY (pod A on 8444, pod B on
# 8445). S6 requires "exactly one winner ACROSS REPLICAS": firing a burst at the
# Service would let kube-proxy land every request on one pod, which proves nothing
# about cross-replica contention. Two live forwards let the runner split the burst
# deterministically. Sets BFF_POD_A_URL / BFF_POD_B_URL.
BFF_POD_A_URL="https://127.0.0.1:8444"
BFF_POD_B_URL="https://127.0.0.1:8445"
bff_pf_dual() {
  local pod_a="$1" pod_b="$2" _i
  [ -n "${PF_BFF:-}" ] && kill "$PF_BFF" 2>/dev/null || true
  [ -n "${PF_BFF_B:-}" ] && kill "$PF_BFF_B" 2>/dev/null || true
  kubectl -n "$NS" port-forward --address 127.0.0.1 "$pod_a" "8444:$HARNESS_PORT" >/dev/null 2>&1 &
  PF_BFF=$!
  BFF_CURRENT_POD="$pod_a"      # 8444 targets pod A for the duration of the dual window
  kubectl -n "$NS" port-forward --address 127.0.0.1 "$pod_b" "8445:$HARNESS_PORT" >/dev/null 2>&1 &
  PF_BFF_B=$!
  for _i in $(seq 1 30); do
    if curl -fsS -o /dev/null --max-time 5 --cacert "$PROOF_CA" \
         "$BFF_POD_A_URL$BFF_SERVING_PATH" 2>/dev/null \
       && curl -fsS -o /dev/null --max-time 5 --cacert "$PROOF_CA" \
         "$BFF_POD_B_URL$BFF_SERVING_PATH" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  bff_fail "BAR A S6 could not port-forward BOTH replicas simultaneously ($pod_a, $pod_b)"
}

# bff_pf_dual_stop — drop the second forward and restore the single named-pod forward.
bff_pf_dual_stop() {
  [ -n "${PF_BFF_B:-}" ] && kill "$PF_BFF_B" 2>/dev/null || true
  PF_BFF_B=""
  bff_pf_start
}

# ---- Refusal-marker COUNTS (never existence) --------------------------------------
# Both refusal asserts below are COUNT DELTAS, not existence checks (review
# 2026-07-12, F9). An existence check — "a line carrying this reason appears
# somewhere in a multi-minute log window" — is satisfied by a marker an EARLIER step
# left behind, so the step's own request need never have refused, or reached the
# server, at all. That is the exact false-positive shape the reviewer rejected in S5
# ("a BFF that never consumes state/nonce would still pass"), and it is not
# hypothetical: any earlier request in the window carrying a lapsed bearer would
# plant a `token_expired` marker that Bar B's deliberate expired-token leg could
# then free-ride on. The technique is the one S6 already uses for Keycloak's refresh
# events: snapshot the count, act, require it to have STRICTLY INCREASED.
#
# The window is deliberately WIDE (30 min > the whole proof's post-deploy phase).
# It does not need to be tight — a delta does not care what else is in the window —
# and a window that AGED between the pre-read and the post-read could under-count
# and produce a spurious FAIL.
_REFUSAL_LOG_WINDOW="1800s"

# kubectl_capture <LABEL> <KUBECTL ARGS...> — a kubectl read that FAILS LOUD.
#
# A FAILED READ IS NOT AN OBSERVATION (review 2026-07-12 round 4, F2 + F2-b). This is
# the single most dangerous shape in the whole runner, and it appeared three times:
#
#     n="$(kubectl ... 2>/dev/null | grep -c "$marker" || true)"; echo "${n:-0}"
#
# If the kubectl call FAILS — an API blip, a port-forward that died, a pod churning
# under a rollout — `2>/dev/null` hides the error, grep sees empty input, and the
# helper returns **0**. That is byte-identical to a legitimate "I looked, and there
# were none". Every caller then treats a NON-OBSERVATION as a hard negative
# observation, and the proof's most load-bearing claims are exactly the negative ones:
# "the refusal marker count ROSE because of THIS request" and "the probe ledger is
# still ZERO, so the denied tool did NOT execute". The reviewer reproduced the
# free-ride end to end: failed pre-read -> 0; a STALE marker already in the window is
# then counted -> 1; delta +1 -> the assert passes although the step's own request
# never refused (or never even reached the server).
#
# So: capture stdout, capture the exit status SEPARATELY, and die loudly on any
# non-zero exit. Never degrade a read error into a value a caller could mistake for
# data. stderr goes to a FILE rather than being merged into stdout, so a kubectl
# warning can never be counted as a log line — and the caller's failure message still
# carries it, so the operator can see WHY the read failed.
#
# WHY THIS HELPER DOES NOT bar_fail ITSELF — a bash 3.2 semantic, and a nasty one.
# `set -e` is IGNORED inside the subshell of a command substitution that is part of an
# assignment. So in
#
#     count="$(some_helper)"          # some_helper's body runs with -e effectively OFF
#         …and inside some_helper:  logs="$(kubectl_capture …)"
#
# a bar_fail (i.e. `exit 1`) raised INSIDE kubectl_capture ends only kubectl_capture's
# own subshell. some_helper does NOT abort — it sails on past the failed assignment
# with `logs` empty, counts zero matches, and returns a perfectly clean "0". The
# fabricated zero comes straight back, wearing a bar_fail message as camouflage. (This
# was verified empirically on bash 3.2 while building the fix; a directly-called
# bar_fail is fine — the runner's other helpers all do that — it is only the extra
# substitution level that swallows the exit.)
#
# Hence the contract: kubectl_capture PRINTS stdout and RETURNS kubectl's exit status.
# Every caller MUST check that status explicitly and raise its OWN bar_fail, which then
# sits directly in the substituted function and does end the run.
kubectl_capture() {
  local rc
  [ -n "${QC_TMP:-}" ] \
    || die "kubectl_capture called before QC_TMP was minted (programming error)"
  set +e
  kubectl "$@" 2>"$QC_TMP/kubectl-capture-err"
  rc=$?
  set -e
  return "$rc"
}

# _kubectl_capture_err — the stderr of the most recent kubectl_capture, clipped, for
# the caller's failure message. (A FILE, so it survives the subshell the capture ran
# in; a shell variable set in there would not.)
_kubectl_capture_err() {
  head -c 400 "$QC_TMP/kubectl-capture-err" 2>/dev/null || printf '<no stderr captured>'
}

# bff_refusal_count <REASON> — how many times the BFF has logged its value-free
# marker ("auth.callback.refused reason=<r>", cognic_harness/web/auth_routes.py) for
# this reason. Both replicas are searched (either may have served the request).
#
# The log read goes through kubectl_capture, so a FAILED read dies rather than
# reporting 0 (F2 — see the note there). Only a SUCCESSFUL read is counted, and the
# one legitimate non-zero exit in the pipeline — `grep -c` exits 1 when it counts
# ZERO matches — is normalised to 0 EXPLICITLY, by exit code, so it can never be
# confused with the read failure it used to be lumped in with.
bff_refusal_count() {
  local reason="$1" logs n rc
  # The read's exit status is checked EXPLICITLY, and the bar_fail sits HERE rather
  # than inside kubectl_capture — see the set -e note above: one substitution level
  # deeper and the refusal would be swallowed and the fabricated 0 returned anyway.
  set +e
  logs="$(kubectl_capture -n "$NS" logs "--since=$_REFUSAL_LOG_WINDOW" -l app=cognic-proof-harness --tail=-1)"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] \
    || bar_fail "bff_refusal_count($reason) — the BFF log read FAILED (kubectl exit $rc): $(_kubectl_capture_err). REFUSING to report a count: a failed read is indistinguishable from a legitimate zero, and a fabricated zero pre-count is exactly what lets a refusal delta free-ride on a STALE marker left by an earlier step — the step's own request need never have refused, or even reached the server."
  set +e
  n="$(printf '%s\n' "$logs" | grep -c "auth.callback.refused reason=$reason")"
  rc=$?
  set -e
  case "$rc" in
    0) ;;                 # matches found
    1) n=0 ;;             # grep's documented "zero matches" exit — a REAL zero
    *) bar_fail "bff_refusal_count($reason): grep failed with exit $rc while counting a SUCCESSFUL log read — the count cannot be trusted and must not be reported as 0" ;;
  esac
  n="$(printf '%s' "$n" | tr -d '[:space:]')"
  case "$n" in
    ''|*[!0-9]*) bar_fail "bff_refusal_count($reason): non-numeric marker count '$n' (programming error)" ;;
  esac
  printf '%s' "$n"
}

# assert_bff_refusal <REASON> <PRE_COUNT> — prove THIS step's request fired the named
# gate in the BFF's login/callback flow. It is what makes S5 non-vacuous: a
# cookieless callback replay refuses with `no_login_session` WITHOUT ever reaching
# consume_oidc(), so "it refused" proves nothing about single-use state — only
# `login_state_already_consumed` does, and only if THIS replay is what emitted it.
#
# PRE_COUNT is REQUIRED. A missing argument is a programming error and dies rather
# than silently degrading to the weak existence semantics this replaced.
assert_bff_refusal() {
  local reason="$1" pre="${2:-}" post
  [ -n "$pre" ] \
    || die "assert_bff_refusal($reason): missing the PRE_COUNT argument (programming error). Snapshot bff_refusal_count BEFORE the action: without a delta the assert degrades to 'a matching line exists somewhere in the window', which a marker from an earlier step satisfies — the step's own request need never have refused at all."
  case "$pre" in
    ''|*[!0-9]*) die "assert_bff_refusal($reason): non-numeric PRE_COUNT '$pre' (programming error)" ;;
  esac
  post="$(bff_refusal_count "$reason")"
  [ "$post" -gt "$pre" ] \
    || bar_fail "BAR A expected THIS request to make the BFF refuse with reason=$reason, but the marker count did NOT increase (before=$pre after=$post) — either the request never reached the BFF, or it refused at a DIFFERENT gate. A pre-existing marker in the log window cannot stand in for it, so the case is not proven."
}

# session_redis_key <COOKIE_VALUE> — the exact Redis key the BFF stores a session
# under: _SESS_PREFIX + HMAC-SHA256(session_hmac_secret, session_id)
# (cognic_harness/auth/redis_store.py:169). The runner MINTS that HMAC secret, so
# it can address one specific record — S10 is a controlled single-variable
# experiment, not a SCAN-and-guess.
#
# SECRET CUSTODY: the COOKIE rides STDIN (it is the session — a bearer credential;
# argv is `ps`-visible). The HMAC-secret's PATH stays on argv: a path is not a
# credential, and the file itself is 0600 under the private per-run dir.
session_redis_key() {
  printf '%s' "$1" | python3 -c '
import hashlib, hmac, sys
secret = open(sys.argv[1], "rb").read()
session_id = sys.stdin.read()
print("sess:" + hmac.new(secret, session_id.encode(), hashlib.sha256).hexdigest())
' "$KC_CRED_TMP/h-session-hmac-secret"
}

# redis_bff_cli <ARGS...> — redis-cli inside the redis-bff pod, over the SAME TLS
# the BFF uses (the proof CA is mounted into the pod for exactly this) and as the
# SAME ACL user. No --insecure, no plaintext port: the store is TLS-only and the
# default user is disabled.
#
# The ACL password is read from the ACL file that is ALREADY MOUNTED IN THE POD
# and handed to redis-cli through REDISCLI_AUTH. It therefore appears in neither
# the operator host's `kubectl` argv (a `ps` there would expose it — the same
# custody rule the rest of the runner obeys) nor the pod's own `redis-cli` argv.
# Nothing new is disclosed: the pod already holds that credential at rest.
redis_bff_cli() {
  kubectl -n "$NS" exec deploy/redis-bff -- sh -c '
REDISCLI_AUTH="$(sed -n "s/^user bff on >\([^ ]*\) .*/\1/p" /etc/redis-acl/users.acl)"
[ -n "$REDISCLI_AUTH" ] || { echo "could not read the bff ACL password inside the pod" >&2; exit 1; }
export REDISCLI_AUTH
exec redis-cli --tls --cacert /etc/proof-ca/proof-ca.pem -h redis-bff -p 6380 --user bff "$@"
' _ "$@"
}

# redis_bff_cli_stdin <ARGS...> — the SAME in-pod redis-cli, but with the operator's
# STDIN FORWARDED into the pod (`kubectl exec -i`) and handed to `redis-cli -x`,
# which reads the command's LAST argument from stdin.
#
# WHY IT EXISTS (review 2026-07-12, F1). A session RECORD is the most sensitive
# object in this proof: it carries the OAuth ACCESS, REFRESH and ID tokens the BFF
# holds server-side (that custody is the whole point of Bar A). The pre-review S10
# write passed it as `redis_bff_cli SET "$KEY" "$RECORD" KEEPTTL`, which put the
# complete record on the operator host's `kubectl` argv AND on the pod's own
# `redis-cli` argv — world-readable to any local `ps` for the duration. With `-x`
# the value never appears on EITHER argument vector.
#
# The KEY may stay on argv: `sess:<hmac-hex>` is a derived HMAC-SHA256 digest. It
# authenticates nothing, it is not the cookie, and it cannot be reversed into one —
# it is an address, not a credential.
redis_bff_cli_stdin() {
  kubectl -n "$NS" exec -i deploy/redis-bff -- sh -c '
REDISCLI_AUTH="$(sed -n "s/^user bff on >\([^ ]*\) .*/\1/p" /etc/redis-acl/users.acl)"
[ -n "$REDISCLI_AUTH" ] || { echo "could not read the bff ACL password inside the pod" >&2; exit 1; }
export REDISCLI_AUTH
exec redis-cli -x --tls --cacert /etc/proof-ca/proof-ca.pem -h redis-bff -p 6380 --user bff "$@"
' _ "$@"
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

# ---- JSON readers: THE DOCUMENT ALWAYS RIDES STDIN -------------------------------
#
# SECRET CUSTODY (review 2026-07-12 round 4, F1). Every helper below used to take the
# JSON document on python3's ARGUMENT VECTOR. That vector is world-readable — any
# local user's `ps` captures it for the child's whole lifetime — and the documents
# these helpers are handed are the most sensitive objects in the proof:
#
#   * the LOGIN JSON        — carries the pre- AND post-auth session ids (possession of
#                             a session id IS the session) and the callback URL, whose
#                             `?code=` is a one-time authorization code EXCHANGEABLE
#                             FOR TOKENS;
#   * the COOKIE DUMP       — carries the live `__Host-cognic_session` cookie VALUE.
#
# So the document goes on STDIN, always. Field NAMES, ids, sequence numbers and file
# paths may stay on argv: none of them is a credential. This is the same rule api()
# already obeys with `curl -K -` for the bearer, and token_has_life for the JWT.

# _JSON_GET_PY — the shared body behind json_field / jq_get. The document arrives on
# STDIN; the field NAME is argv[1].
#
# BOOLEANS PRINT AS JSON (`true` / `false`), NOT AS PYTHON (`True` / `False`)
# — review 2026-07-12 round 4, found while smoke-testing the stdin conversion.
#
# This is a LIVE-RUN-FATAL bug in its own right, and it had never fired because the
# proof has not yet been run end to end. `print(v)` on a Python bool emits `True`, and
# EIGHTEEN call sites compare the result against the lowercase JSON spelling:
#
#     [ "$(jq_get authenticated "$A_STALE")" = "false" ] || bar_fail ...
#
# `[ "False" = "false" ]` is FALSE, so seventeen of them would have bar_failed on a
# perfectly healthy BFF — Bar A would have died on its very first assertion. The
# eighteenth is worse: S7's outage check reads
#
#     [ "$A_OUTAGE_OK" != "true" ] || bar_fail "a login SUCCEEDED with Redis down ..."
#
# and `"True" != "true"` is TRUE, so it would have passed VACUOUSLY — the assertion
# that the BFF must not fall back to memory could never have fired, even if it did.
#
# So the field is rendered in its JSON spelling: bools as `true`/`false`, dicts and
# lists via json.dumps, and every other scalar bare (a bare string is what the session
# ids and callback URLs must stay). `isinstance(v, bool)` is tested BEFORE the numeric
# fall-through because in Python `bool` IS a subclass of `int`.
_JSON_GET_PY='
import json, sys
v = json.loads(sys.stdin.read()).get(sys.argv[1])
if v is None:
    print("")
elif isinstance(v, bool):
    print("true" if v else "false")
elif isinstance(v, (dict, list)):
    print(json.dumps(v))
else:
    print(v)
'

# json_field <FIELD> <JSON> — a top-level field, or "" when absent.
# The JSON rides STDIN; only the field NAME is on argv.
json_field() {
  printf '%s' "${2:-}" | python3 -c "$_JSON_GET_PY" "$1" 2>/dev/null || true
}

# json_assert <LABEL> <PY_SOURCE> <JSON> [ARGS...] — an inline python3 predicate over
# a JSON document, fail-capturing (mirrors the PSQL discipline, run-3 finding): the
# python body must print exactly "ok" on success; ANY nonzero exit, traceback, or
# non-ok output routes through bar_fail WITH the captured detail preserved (a raised
# assertion inside a bare command substitution would abort the runner under `set -e`
# with no failure capture).
#
# THE DOCUMENT IS ARGUMENT 3 AND RIDES STDIN. Predicates therefore read it as
# `json.loads(sys.stdin.read())`, and any FURTHER arguments start at `sys.argv[1]`.
# (S8 hands this helper the live cookie dump; before the fix that dump sat on argv.)
#
# THE CAPTURED DETAIL MUST STAY VALUE-FREE. It is printed by bar_fail into the proof
# log, so a predicate MUST NOT embed document values in its assertion messages — carry
# the NAMES and the SHAPE FACTS instead (S8's messages were rewritten for exactly
# this). Python tracebacks quote the failing SOURCE LINE, never the stdin content, so
# with the document off argv and the messages value-free the detail can no longer
# disclose a credential.
json_assert() {
  local label="$1" src="$2" doc="$3"
  shift 3
  local out rc
  set +e
  out="$(printf '%s' "$doc" | python3 -c "$src" "$@" 2>&1)"
  rc=$?
  set -e
  if [ "$rc" -ne 0 ] || [ "$out" != "ok" ]; then
    bar_fail "$label (rc=$rc): ${out:-<no output>}"
  fi
}

# discovery_status of the TOOL pack row from GET /system/plugins?tenant_id=proof-m85c.
discovery_status() {
  local body
  body="$(curl -sf --cacert "$PROOF_CA" "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
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
# Ruling 2026-07-10: every evidence query carries tenant_id='proof-m85c'
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

# conv_turn_seqs <CID> — the COMPLETE, ORDERED list of turn sequence numbers the
# kernel STORED for the conversation, one per line. This is the authority Bar E
# compares the RENDERED transcript against (the transcript screen renders from this
# same store, via the conversation read API).
#
# Tenant-scoped through the JOIN: conversation_turns carries no tenant column, so
# scope rides conversations.tenant_id — the same discipline as
# conv_turn_plaintext_b64. Table + column names are the kernel's own
# (core/conversation/storage.py:109-141, migration 0015): conversation_turns(seq,
# conversation_id), conversations(conversation_id, tenant_id).
conv_turn_seqs() {
  local cid="$1"
  PSQL "SELECT t.seq FROM conversation_turns t JOIN conversations c ON c.conversation_id = t.conversation_id WHERE c.tenant_id='$TENANT' AND t.conversation_id='$cid' ORDER BY t.seq ASC;"
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

# bound_subject <keycloak-username> — the issuer-qualified subject the reference
# binder binds for that identity ("<issuer>#<sub-uuid>"), sourced from the
# realm-subjects.env the generator emits. The reference binder binds the STABLE,
# non-reassignable sub (NOT the mutable preferred_username), so the kernel keys
# entitlements / approvals / conversations by THIS value. Every out-of-band DB
# subject operation in the runner MUST resolve through here — passing the bare
# login name (e.g. "analyst.amir") would match zero seeded rows and a revocation
# would silently fail to bite. Mirrors the seed-db.sh rendering of the same file.
bound_subject() {
  local user="$1" var
  [ -n "${KC_CRED_TMP:-}" ] || die "bound_subject called before the realm was generated"
  var="KC_SUB_$(printf '%s' "$user" | tr '[:lower:].-' '[:upper:]__')"
  local val
  val="$(grep "^$var=" "$KC_CRED_TMP/realm-subjects.env" | cut -d= -f2-)"
  [ -n "$val" ] || die "bound_subject: no $var in realm-subjects.env (generator drift?)"
  printf '%s' "$val"
}

# The BAR-3 entitlement axis (kernel-side rows the dispatch gate 2 reads live).
entitlement_count() {
  local subject="$1" scope="$2"
  PSQL "SELECT count(*) FROM entitlements WHERE tenant_id='$TENANT' AND subject='$subject' AND scope_id='$scope';"
}

# approval_queue_order — the kernel's OWN ordering of the actionable approval
# queue, straight from the DB: tenant-scoped, state IN (pending, awaiting_second),
# ORDER BY created_at ASC, request_id ASC (core/approval/storage.py:345-353 — the
# HP-4 keyset the 0017 index backs). Bar D.7 compares the PAGINATED id sequence
# against this list IN ORDER: set equality alone would pass on a reversed or
# shuffled walk, and the spec requires "correct ordering".
approval_queue_order() {
  PSQL "SELECT request_id FROM approval_requests WHERE tenant_id='$TENANT' AND state IN ('pending','awaiting_second') ORDER BY created_at ASC, request_id ASC;"
}

# conv_turn_chain_sequence <CID> <SEQ> — the hash-chain ROW sequence of a turn's
# `conversation.turn_completed` event (decision_history.sequence, a COLUMN — not a
# payload field). The evidence screen renders exactly this value
# (evidence_chain.html:11), so it is genuine chain evidence. NOTE the page heading's
# "seq" is NOT: that is the URL path param echoed back, so asserting on it would
# prove nothing about the chain.
conv_turn_chain_sequence() {
  local cid="$1" seq="$2"
  PSQL "SELECT sequence FROM decision_history WHERE event_type='conversation.turn_completed' AND tenant_id='$TENANT' AND payload->>'conversation_id'='$cid' AND payload->>'seq'='$seq';"
}

# assert_rendered_transcript_matches_chain <EVIDENCE_JSON> <CID> — Bar E's core.
# For EVERY turn the transcript screen rendered: re-hash the rendered question and
# answer TEXT and require the digests to equal the kernel's chain-row digests for
# that turn. The pre-review bar only asserted the transcript was non-empty and then
# compared digests the CHAIN screen had rendered against the DB — i.e. it compared
# the kernel's numbers with the kernel's numbers, and never looked at the words on
# the page. A stale, truncated or wrong transcript passed that (Codex round-2 P1).
# Hashing the rendered text is what binds the SCREEN to the CHAIN.
#
# COMPLETENESS FIRST (review 2026-07-12, F6). The per-turn digest checks below only
# look at the turns that WERE rendered, so on their own they accept ANY NON-EMPTY
# SUBSET: a transcript that silently DROPPED turn 1 (or turn 2) still passed every
# one of them. The rendered sequence list must therefore EQUAL the kernel's complete
# stored turn list — exactly, and in order — before the digests mean anything.
assert_rendered_transcript_matches_chain() {
  local evid="$1" cid="$2" n seq q_sha a_sha db_q db_a run_id db_run
  local expected_seqs rendered_seqs next_page

  # (0) The transcript screen PAGINATES (evidence_transcript.html). If a further page
  # exists, `transcript_turns` is a page, not the transcript, and the completeness
  # comparison below would be against a truncated list. Today's proof conversations
  # are far short of a page — but if a future conversation ever crosses that
  # boundary, THIS fails loud (with the fix named) rather than silently passing on a
  # partial transcript: the driver must be taught to walk the pages.
  # Every read below feeds the evidence document on STDIN, never argv (F1 — uniform
  # with jq_get / json_assert / _e_field; the loop INDEX may stay on argv).
  next_page="$(printf '%s' "$evid" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("transcript_next_page_available"))')"
  [ "$next_page" = "False" ] \
    || bar_fail "BAR E the transcript screen reports a FURTHER PAGE (transcript_next_page_available=$next_page) — the rendered turns are only the first page, so 'the transcript matches the chain' cannot be judged. The driver must walk the pagination (evidence_transcript.html a.next-page) before this bar can pass."

  # (1) COMPLETENESS — the rendered sequence list must EQUAL the kernel's complete
  # turn list for this conversation, in order.
  expected_seqs="$(conv_turn_seqs "$cid" | tr -d '\r' | tr '\n' ' ' | sed 's/  *$//')"
  rendered_seqs="$(printf '%s' "$evid" | python3 -c 'import json,sys; print(" ".join(str(t["sequence"]) for t in json.loads(sys.stdin.read())["transcript_turns"]))')"
  [ -n "$expected_seqs" ] \
    || bar_fail "BAR E the kernel stored NO turns for conversation $cid — there is nothing for the transcript to match (the conversation or its tenant scope is wrong)"
  [ "$rendered_seqs" = "$expected_seqs" ] \
    || bar_fail "BAR E the RENDERED transcript is not the kernel's complete turn list for $cid — rendered=[$rendered_seqs] expected=[$expected_seqs] (exact order required). A transcript that silently drops or reorders a turn passes every per-turn digest check below, because those only inspect the turns that were rendered."
  echo "    Bar E: the transcript renders EXACTLY the kernel's stored turns, in order ([$expected_seqs])"

  n="$(printf '%s' "$evid" | python3 -c 'import json,sys; print(len(json.loads(sys.stdin.read())["transcript_turns"]))')"
  [ "$n" -ge 1 ] || bar_fail "BAR E the transcript screen rendered NO turns"
  local _i=0
  while [ "$_i" -lt "$n" ]; do
    seq="$(printf '%s' "$evid" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["transcript_turns"][int(sys.argv[1])]["sequence"])' "$_i")"
    run_id="$(printf '%s' "$evid" | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["transcript_turns"][int(sys.argv[1])]["agent_run_id"])' "$_i")"
    # sha256 over the VERBATIM rendered text (the driver never strips or normalises).
    q_sha="$(printf '%s' "$evid" | python3 -c '
import hashlib, json, sys
turn = json.loads(sys.stdin.read())["transcript_turns"][int(sys.argv[1])]
print(hashlib.sha256(turn["question_text"].encode()).hexdigest())
' "$_i")"
    a_sha="$(printf '%s' "$evid" | python3 -c '
import hashlib, json, sys
turn = json.loads(sys.stdin.read())["transcript_turns"][int(sys.argv[1])]
print(hashlib.sha256(turn["answer_text"].encode()).hexdigest())
' "$_i")"
    db_q="$(conv_turn_chain_field "$cid" "$seq" question_sha256)"
    db_a="$(conv_turn_chain_field "$cid" "$seq" answer_sha256)"
    db_run="$(conv_turn_run_id "$cid" "$seq")"
    [ -n "$db_q" ] && [ -n "$db_a" ] \
      || bar_fail "BAR E no chain row for the RENDERED transcript turn seq=$seq — the screen shows a turn the kernel never chained"
    [ "$q_sha" = "$db_q" ] \
      || bar_fail "BAR E turn $seq: sha256 of the RENDERED question text ($q_sha) != the kernel chain row's question_sha256 ($db_q) — the transcript is not the governed text"
    [ "$a_sha" = "$db_a" ] \
      || bar_fail "BAR E turn $seq: sha256 of the RENDERED answer text ($a_sha) != the kernel chain row's answer_sha256 ($db_a) — the transcript is not the governed text"
    [ -n "$run_id" ] && [ "$run_id" = "$db_run" ] \
      || bar_fail "BAR E turn $seq: the rendered agent_run_id ($run_id) != the chain row's ($db_run) — the hashed text is not bound to the turn whose digests it matched"
    echo "    Bar E turn $seq: rendered text re-hashes to the chain digests (q=${q_sha:0:12}… a=${a_sha:0:12}…), bound to run $run_id"
    _i=$((_i + 1))
  done
  echo "  Bar E: all $n rendered transcript turns re-hash to their kernel chain rows"
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
  body="$(curl -sf --cacert "$PROOF_CA" "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
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
  body="$(curl -sf --cacert "$PROOF_CA" "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
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
  ds="$(curl -s --cacert "$PROOF_CA" "$BASE_URL/api/v1/system/plugins?tenant_id=$TENANT" 2>/dev/null || true)"
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

# BFF readiness/reachability failures need BFF-owned diagnostics before the
# generic evidence capture runs. Pod describe/events are deliberately captured
# instead of access logs: an OIDC callback URL can contain a short-lived code +
# state in its query string, and failure evidence must never persist either.
bff_fail() {
  local where="$1" bff_state bff_describe
  bff_state="$(kubectl -n "$NS" get deployment,pods \
    -l app=cognic-proof-harness -o wide 2>&1 || true)"
  bff_describe="$(kubectl -n "$NS" describe pods -l app=cognic-proof-harness \
    2>&1 | tail -180 || true)"
  {
    echo ""
    echo "## Proof M8.5-C BFF readiness diagnostics ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    echo ""
    echo "- Failed step: \`$where\`"
    echo "- BFF deployment + pods:"
    echo '```'
    echo "${bff_state:-<none>}"
    echo '```'
    echo "- BFF pod describe/events (tail 180; access logs deliberately excluded):"
    echo '```'
    echo "${bff_describe:-<none>}"
    echo '```'
  } >> docs/VALIDATION-RESULTS.md
  bar_fail "$where"
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
  wide="$(kubectl -n "$NS" get deployment,pods -l app.kubernetes.io/name=agentos -o wide 2>&1 || true)"
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
  [ -n "${PF_KC:-}" ] && kill "$PF_KC" 2>/dev/null || true
  [ -n "${PF_BFF:-}" ] && kill "$PF_BFF" 2>/dev/null || true
  # The SECOND per-pod forward S6 opens for the cross-replica refresh race — it
  # is normally closed by bff_pf_dual_stop, but a bar_fail mid-race would leave
  # it dangling on 8445 and poison a subsequent run.
  [ -n "${PF_BFF_B:-}" ] && kill "$PF_BFF_B" 2>/dev/null || true
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  # Attempt 11 left an Exited(137) control-plane container behind even though
  # cleanup ran. `kind delete` is best-effort here and its diagnostic used to be
  # discarded, so enforce the actual postcondition: remove only node containers
  # carrying this exact proof-cluster label. This also covers a kind command that
  # returns success while a stopped node survives.
  while IFS= read -r _kind_node_id; do
    [ -n "$_kind_node_id" ] || continue
    echo "WARN: cleanup: removing residual kind node for cluster $CLUSTER" >&2
    docker rm -f "$_kind_node_id" >/dev/null 2>&1 || true
  done < <(docker ps -aq --filter "label=io.x-k8s.kind.cluster=$CLUSTER" 2>/dev/null || true)
  docker rm -f "$REGISTRY_NAME" >/dev/null 2>&1 || true
  # remove the transient build-context copies (NOT the sources); proof_m85c/ +
  # overlay_reference/ + keycloak/ are tracked in-context sources, so they are
  # NOT removed. The per-run PRIVATE key dirs are removed unconditionally — no
  # private PEM, realm secret, or user password may outlive the run on the host.
  rm -rf "$STAGING_DST" "$AGENTOS_SRC_DST" "$PROOF_DIR/policies" "$PROOF_DIR/_local_as.py" 2>/dev/null || true
  [ -n "${QC_TMP:-}" ] && rm -rf "$QC_TMP" 2>/dev/null || true
  # The per-run canonical SIGNING keypair dir (the run-2 custody fix): removed
  # unconditionally like $QC_TMP — the dev-grade signing key never outlives
  # the run on the operator host.
  [ -n "${CANONICAL_KEY_TMP:-}" ] && rm -rf "$CANONICAL_KEY_TMP" 2>/dev/null || true
  # The per-run approve-signing key (the M8.5-C shared tools-kind _default key):
  # removed unconditionally — the dev-grade approve key never outlives the run.
  [ -n "${APPROVE_KEY_TMP:-}" ] && rm -rf "$APPROVE_KEY_TMP" 2>/dev/null || true
  # The per-run proof PKI (CA + leaf private keys) and the Keycloak realm dir
  # (client secret + every user password) — the highest-value secrets in the
  # run; removed unconditionally.
  [ -n "${PKI_TMP:-}" ] && rm -rf "$PKI_TMP" 2>/dev/null || true
  [ -n "${KC_CRED_TMP:-}" ] && rm -rf "$KC_CRED_TMP" 2>/dev/null || true
  # Browser interactions must never resolve packages mid-bar. The driver gets one
  # private runtime before cluster work; remove it with the rest of the run state.
  [ -n "${DRIVER_VENV_TMP:-}" ] && rm -rf "$DRIVER_VENV_TMP" 2>/dev/null || true
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
python3 - "$REGISTRY_PORT" <<'PY' || die "registry port $REGISTRY_PORT already in use (lsof -nP -iTCP:$REGISTRY_PORT -sTCP:LISTEN shows the holder); override via COGNIC_PROOF_M85C_REGISTRY_PORT"
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

# M8.5-C: the IdP + BFF host names must resolve to loopback so the host-side
# driver + browser reach Keycloak at the SAME `cognic-proof-keycloak` authority
# the in-cluster kernel uses (one issuer everywhere) and the BFF at its own
# name. One-time operator step; verified fail-loud here with copy-paste.
_m85c_hosts_help() {
  cat >&2 <<EOF
FAIL: one-time operator /etc/hosts setup missing ($1).
The reference IdP must resolve to the SAME authority in-cluster and on the host
so ONE issuer string holds in every token. Run once in a REAL terminal:
  sudo sh -c 'printf "127.0.0.1 %s\\n127.0.0.1 %s\\n" "$KC_HOST" "$HARNESS_HOST" >> /etc/hosts'
Then re-run the proof. (Removal:
  sudo sed -i '' "/[[:space:]]$KC_HOST\$/d;/[[:space:]]$HARNESS_HOST\$/d" /etc/hosts)
EOF
  exit 1
}
grep -qE "[[:space:]]$KC_HOST($|[[:space:]])" /etc/hosts \
  || _m85c_hosts_help "/etc/hosts loopback entry for $KC_HOST"
grep -qE "[[:space:]]$HARNESS_HOST($|[[:space:]])" /etc/hosts \
  || _m85c_hosts_help "/etc/hosts loopback entry for $HARNESS_HOST"
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
# Dockerfile, ALL THREE proof suites (structural + reference-binder +
# remediation — the binder suite guards the code that actually runs in the
# kernel, and the remediation suite is what stops a fixed defect from
# silently regressing back into the live run), and the AS executable source
# (tests/integration/pack_loop/_local_as.py — copied into the proof
# authentication-server image). Runs BEFORE anything materializes
# (staging/copies land under infra/proof-m85c and are NOT gitignored), so a
# dirty state here is genuinely operator-authored or stale residue from an
# aborted run — either way the evidence would cite HEAD while different
# proof code executed. docs/VALIDATION-RESULTS.md is deliberately excluded
# (failure captures append to it).
PROOF_INPUT_DIRTY="$(git status --porcelain -- infra/proof-m85c infra/charts/agentos infra/agentos tests/unit/infra/test_proof_m85c_structure.py tests/unit/infra/test_proof_m85c_reference_binder.py tests/unit/infra/test_proof_m85c_remediation.py tests/integration/pack_loop/_local_as.py)"
if [ -n "$PROOF_INPUT_DIRTY" ]; then
  die "proof inputs are DIRTY — the evidence would cite HEAD while different proof code executes. Commit, stash, or clean first:
$PROOF_INPUT_DIRTY"
fi
echo "==> [1/11] proof-input cleanliness OK (proof dir + chart + base Dockerfile + structural suite)"

# --- 1c. materialize the browser-driver runtime ONCE, before cluster work ---------
# Attempt 11 reached Bar A S3 after several successful browser interactions, then a
# fresh `uv run --with-requirements` tried to revalidate cryptography against PyPI.
# A transient DNS failure therefore turned an already-running live bar into a package-
# resolver failure. Build one private Python 3.12 environment now, prove its Chromium
# binary is installed now, and invoke its interpreter directly for every later drive.
# Dependency or browser-download failures are still fail-loud, but happen before the
# expensive cluster setup; no Bar A-F interaction has uv or network resolution in its
# execution path.
echo "==> [1/11] materialize the browser-driver runtime (one resolver pass, pre-cluster)"
DRIVER_VENV_TMP="$(mktemp -d)"
chmod 700 "$DRIVER_VENV_TMP"
uv venv --python 3.12 --no-python-downloads "$DRIVER_VENV_TMP/venv"
DRIVER_PYTHON="$DRIVER_VENV_TMP/venv/bin/python"
uv pip install --python "$DRIVER_PYTHON" --exact --strict \
  --requirements "$DRIVER_DIR/requirements.txt"
"$DRIVER_PYTHON" -m playwright install chromium
"$DRIVER_PYTHON" -c 'import cryptography; from playwright.sync_api import sync_playwright'
echo "  browser-driver runtime OK: Python 3.12 + isolated requirements + Chromium"

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
# (proof-m85c-staging/query-context/ -> baked into BOTH images: the kernel's
# verification surfaces + the oracle-pack Service's
# COGNIC_QUERY_CONTEXT_PUBLIC_KEYS verifier). The PRIVATE PEM NEVER enters any
# build context or image layer: it is written to a 0700 mktemp dir OUTSIDE the
# staging tree, shipped ONLY as the k8s Secret `proof-m85c-query-context`
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

# --- 2d. mint the per-run proof PKI + the Keycloak realm (M8.5-C) -------------------
# The proof CA + one leaf per TLS surface (AgentOS / Keycloak / BFF), all under a
# 0700 mktemp removed by the cleanup trap. Private keys reach the cluster ONLY as
# `kubectl create secret` inputs; nothing is committed or image-baked.
echo "==> [2/11] mint the per-run proof PKI (CA + AgentOS/Keycloak/BFF leaf certs)"
PKI_TMP="$(mktemp -d)"
chmod 700 "$PKI_TMP"
bash "$PROOF_DIR/mint-pki.sh" "$PKI_TMP"
PROOF_CA="$PKI_TMP/proof-ca.pem"

# The reference-binder CA the kernel pod mounts + verifies Keycloak against. It is
# the SAME CA bytes as $PROOF_CA — one root of trust for the whole proof.
echo "==> [2/11] generate the Keycloak realm (8 identities; locked grant profile; exact audience)"
KC_CRED_TMP="$(mktemp -d)"
chmod 700 "$KC_CRED_TMP"
python3 "$PROOF_DIR/keycloak/gen_realm.py" "$KC_CRED_TMP" "$BFF_REDIRECT_URI" "$DRIVER_REDIRECT_URI"
# Source the realm's confidential-client secret into a NON-exported runner var so
# ensure_token() can hand it to the PKCE child via env (never argv). The file is
# 0600 under the private per-run dir and dies with $KC_CRED_TMP.
KC_CLIENT_SECRET="$(grep '^KC_CLIENT_SECRET=' "$KC_CRED_TMP/realm-credentials.env" | cut -d= -f2-)"
[ -n "$KC_CLIENT_SECRET" ] || die "realm generation did not emit a client secret"

# The api() response/status files live under the SAME private dir (finding 2,
# 2026-07-10: predictable mode-0644 shared-/tmp paths persisted transcript
# plaintext past the run and permitted symlink/truncation attacks).
HTTP_CODE_FILE="$QC_TMP/http-code"
API_RESP_FILE="$QC_TMP/api-resp"

# --- 2e. the shared approve trust root (M8.5-C two-tools-kind-pack re-sign) ---------
# The approve 5-gate signature root is resolved PER TENANT (ProofStagedTrustRootResolver
# returns <prefix>/_default/cosign.pub for every tenant). M8.5-C installs TWO
# tools-kind packs through the approve flow — the oracle AND the probe — and a
# tenant-keyed root cannot carry two release keys. So the proof mints ONE
# per-run approve-signing key, stages its PUBLIC half as _default/cosign.pub
# (overriding stage-packs' oracle-release-key default), and RE-SIGNS BOTH
# tools-kind wheels' cosign.sig under it. This is SAFE + LOCALIZED: only the two
# tools-kind packs use _default (hook/skill/agent packs verify against their own
# per-pack roots, untouched); boot trust-registration of the oracle re-reads the
# re-signed sig against the same _default, so it stays consistent. Analogous to
# the canonical-image re-home (which re-signs published images under a proof key).
# GOVERNANCE NOTE: this is the one M8.5-C change to a proven (M8) trust-staging
# path; it is exercised only in the operator's live kind run (README honesty §).
echo "==> [2/11] mint the proof approve-signing key + re-sign both tools-kind wheels under _default"
APPROVE_KEY_TMP="$(mktemp -d)"
chmod 700 "$APPROVE_KEY_TMP"
( cd "$APPROVE_KEY_TMP" && cosign generate-key-pair )   # COSIGN_PASSWORD="" already exported at 2b
cp "$APPROVE_KEY_TMP/cosign.pub" "$STAGING_DST/trust-roots/_default/cosign.pub"
# Re-sign each tools-kind wheel's cosign.sig (the approve gate's `cosign verify-blob
# --key _default/cosign.pub --signature <cosign.sig> <wheel>` reads exit code only).
_resign_tools_pack() {
  local pack_id="$1" version="$2" wheel="$3"
  local att="$STAGING_DST/pack-attestations/$pack_id/$version"
  local release_pub="$STAGING_DST/release-pubs/$pack_id.pub"
  local proof_sig="$att/.cosign.sig.proof.$$"
  local sign_detail sign_err="$QC_TMP/re-sign-$pack_id-sign.err"
  local verify_detail verify_err="$QC_TMP/re-sign-$pack_id-verify.err"
  [ -f "$att/$wheel" ] || die "re-sign: staged wheel missing at $att/$wheel"
  [ -f "$att/cosign.sig" ] || die "re-sign: original cosign.sig missing at $att/cosign.sig"
  [ -f "$release_pub" ] || die "re-sign: released cosign.pub missing at $release_pub (stage-packs did not stage it)"
  # Verify the ORIGINAL release signature over the wheel under the RELEASE key
  # BEFORE overwriting it (finding, 2026-07-12). The wheel bytes are already
  # digest-pinned to the maintainer-locked SHA in stage-packs; this additionally
  # proves the release actually SIGNED those exact bytes, so the proof never
  # re-signs a wheel whose release signature was invalid or absent.
  # ADR-016 release signing deliberately uses --tlog-upload=false. The pinned
  # release key + wheel digest are the offline trust anchors; asking Rekor for
  # a deliberately absent entry is both incorrect and network-dependent.
  if ! cosign verify-blob --insecure-ignore-tlog=true --key "$release_pub" \
      --signature "$att/cosign.sig" "$att/$wheel" \
      >/dev/null 2>"$verify_err"; then
    verify_detail="$(head -c 500 "$verify_err")"
    [ -n "$verify_detail" ] || verify_detail="no cosign diagnostic"
    die "re-sign: could not cryptographically verify the ORIGINAL $pack_id/$version cosign.sig under its released cosign.pub — refusing to re-sign unauthenticated bytes; cosign: $verify_detail"
  fi
  # Cosign 3 defaults --use-signing-config=true, which conflicts with the
  # air-gapped --tlog-upload=false posture. Keep the detached legacy signature
  # the runtime trust gate consumes, matching the ADR-016 signing bridge.
  if ! cosign sign-blob --key "$APPROVE_KEY_TMP/cosign.key" --tlog-upload=false \
      --use-signing-config=false --new-bundle-format=false \
      --yes --output-signature "$proof_sig" "$att/$wheel" \
      >/dev/null 2>"$sign_err"; then
    sign_detail="$(head -c 500 "$sign_err")"
    [ -n "$sign_detail" ] || sign_detail="no cosign diagnostic"
    die "re-sign: could not sign $pack_id/$version under the proof approve key; the authenticated release signature remains untouched; cosign: $sign_detail"
  fi
  [ -s "$proof_sig" ] \
    || die "re-sign: cosign reported success for $pack_id/$version but emitted no detached signature"
  mv "$proof_sig" "$att/cosign.sig"
  echo "  re-signed $pack_id/$version cosign.sig under the proof approve key (original verified under release key first)"
}
_resign_tools_pack "$PACK_ID" "0.3.0" "$PACK_WHEEL"
_resign_tools_pack "$PROBE_PACK_ID" "$PROBE_PACK_VERSION" "$PROBE_WHEEL"

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
# proof_m85c/ (the multi-actor app factory, $PROOF_APP_SRC) already lives inside
# $PROOF_DIR — it is IN the docker build context, so no copy step is needed.
echo "    proof app factory in-context at $PROOF_APP_SRC (no copy)"
# The policy bundles (incl. the NEW agents.rego) ride the same overlay pattern.
rm -rf "$PROOF_DIR/policies"
cp -r policies "$PROOF_DIR/policies"

echo "==> [3/11] build the default-adapters base image"
# Docker Desktop's bridge DNS can fail while the host resolver remains healthy
# (attempt-6 live finding). These two networked builds use the host resolver; every
# fetched dependency remains lock- or digest-pinned by its owning Dockerfile.
docker_build_with_retry --network=host -f infra/agentos/Dockerfile \
  --build-arg COGNIC_INCLUDE_SANDBOX_DOCKER=true \
  --target default-adapters -t "$BASE_IMAGE" .
docker run --rm --network=none "$BASE_IMAGE" \
  /opt/venv/bin/python -c "import aiodocker, aiohttp" \
  || die "locked sandbox-docker extra missing from the proof base image"

echo "==> [3/11] build the proof AgentOS kernel image (create_proof_app + SEVEN released packs + trust + query-context public key)"
docker_build_with_retry --network=host -f "$PROOF_DIR/Dockerfile.agentos-proof" \
  --build-arg BASE_IMAGE="$BASE_IMAGE" \
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

echo "==> [3/11] build the released approval-probe MCP tool Service image (v0.1.0, high_risk_custom)"
docker_build_with_retry -f "$PROOF_DIR/Dockerfile.probe-pack" -t "$PROBE_IMAGE" "$PROOF_DIR"

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
kind load docker-image "$IMAGE" "$MCP_IMAGE" "$PROBE_IMAGE" "$AS_IMAGE" --name "$CLUSTER"

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
docker tag "$PUBLISHED_RUNTIME_PYTHON" "$REGISTRY_REF_HOST/sandbox-runtime-python:proofm85c"
docker push "$REGISTRY_REF_HOST/sandbox-runtime-python:proofm85c"
# RepoDigests can carry STALE entries from earlier proofs on the same host
# (run-4 live finding: the egress-proxy image still held a
# cognic-proof-m6-registry digest from the July-4 M6 proof and `index 0`
# picked it) — select the entry for THIS registry explicitly.
RUNTIME_PYTHON_REF="$(docker inspect "$REGISTRY_REF_HOST/sandbox-runtime-python:proofm85c" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep "^$REGISTRY_REF_HOST/sandbox-runtime-python@" | head -1)"
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
docker tag "$PUBLISHED_EGRESS_PROXY" "$REGISTRY_REF_HOST/sandbox-egress-proxy:proofm85c"
docker push "$REGISTRY_REF_HOST/sandbox-egress-proxy:proofm85c"
EGRESS_PROXY_REF="$(docker inspect "$REGISTRY_REF_HOST/sandbox-egress-proxy:proofm85c" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep "^$REGISTRY_REF_HOST/sandbox-egress-proxy@" | head -1)"
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

# --- 5b. the reference proof IdP (Keycloak) ----------------------------------------
# Deployed WITH the backends so its realm is imported + minting by the time the
# AgentOS pod boots (the reference binder fetches discovery + JWKS at startup with
# a bounded retry). The realm is a SECRET (client secret + every user password);
# the TLS cert is the per-run leaf; the CA the whole proof trusts is the SAME
# $PROOF_CA. The bootstrap-admin password is throwaway — the proof never touches
# the admin API (the realm arrives entirely by import).
echo "==> [5/11] deploy the reference proof IdP (Keycloak 26.2; realm imported from a Secret)"
kubectl -n "$NS" create secret generic proof-m85c-keycloak-realm \
  --from-file=realm.json="$KC_CRED_TMP/realm.json"
kubectl -n "$NS" create secret tls proof-m85c-keycloak-tls \
  --cert="$PKI_TMP/keycloak.crt" --key="$PKI_TMP/keycloak.key"
# The admin password rides a 0600 file under the private per-run dir, NOT
# --from-literal (finding, 2026-07-12): a --from-literal value is visible in the
# kubectl process argument vector to any `ps` on the shared host — the same argv
# exposure already fixed for the provider key. --from-file reads the value from a
# file whose bytes never touch argv.
# printf '%s' (no trailing newline): kubectl --from-file uses the file bytes
# VERBATIM, so a naked `openssl > file` would bake a trailing "\n" into the
# secret value that --from-literal="$(...)" would have stripped.
( umask 077; printf '%s' "$(openssl rand -hex 16)" > "$KC_CRED_TMP/kc-admin-password" )
kubectl -n "$NS" create secret generic proof-m85c-keycloak-admin \
  --from-file=password="$KC_CRED_TMP/kc-admin-password"
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/keycloak.yaml"
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
# Keycloak rides the same parallel budget it was applied under. Its pod-level
# readiness is a TCP probe; the REAL "realm imported + minting correct tokens"
# gate is the claim-contract preflight after the kernel is up.
kubectl -n "$NS" wait --for=condition=available --timeout=600s deploy/cognic-proof-keycloak \
  || backends_fail "cognic-proof-keycloak not Available within 600s"
echo "  Keycloak Available"
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
echo "==> [7/11] install the AgentOS chart under the proof-m85c overlay + the proof canonical refs"
# The digest-pinned, proof-signed canonical refs are injected via --set (the static
# overlay must NOT carry a personal-registry ref — deploy-safety guard G7).
helm install rel "$CHART" -n "$NS" -f "$PROOF_DIR/proof-m85c-values.yaml" \
  --set sandbox.canonicalRuntimeImage="$RUNTIME_PYTHON_REF" \
  --set sandbox.canonicalEgressProxyImage="$EGRESS_PROXY_REF"

# --- 8. migrate Job + secrets + manifests + patches + env ---------------------------
echo "==> [8/11] run the proof-owned (non-hook) migration Job (schema -> head, rev 0017)"
kubectl -n "$NS" delete job/agentos-migrate --ignore-not-found=true --wait=true
sed "s|__AGENTOS_IMAGE__|$IMAGE|" "$PROOF_DIR/migrate-job.yaml" | kubectl apply -n "$NS" -f -
kubectl -n "$NS" wait --for=condition=complete job/agentos-migrate --timeout=300s \
  || migrate_fail "agentos-migrate did not complete within 300s"

# Live schema readback (finding-2 lineage, 2026-07-10: never CLAIM a head
# revision without reading it back). M8.5-C head is 0017 — the HP-4 approval
# queue keyset index (T1) on top of the 0016 read-model shape; both proven.
SCHEMA_REV="$(PSQL "SELECT version_num FROM alembic_version;")"
[ "$SCHEMA_REV" = "0017" ] \
  || migrate_fail "alembic_version reads '$SCHEMA_REV' after the migrate Job (expected 0017)"
SHAPE_0016="$(PSQL "SELECT (SELECT count(*) FROM information_schema.columns WHERE table_name='conversation_turns' AND column_name='turn_completed_request_id') || '|' || (SELECT count(*) FROM pg_indexes WHERE indexname IN ('ix_decision_history_tenant_event_sequence','ix_conversations_tenant_creator_created'));")"
[ "$SHAPE_0016" = "1|2" ] \
  || migrate_fail "0016 schema shape readback '$SHAPE_0016' (expected '1|2': correlation column + the two read-model indexes)"
SHAPE_0017="$(PSQL "SELECT count(*) FROM pg_indexes WHERE indexname='ix_approval_requests_tenant_created_request';")"
[ "$SHAPE_0017" = "1" ] \
  || migrate_fail "0017 schema shape readback '$SHAPE_0017' (expected '1': the HP-4 approval-queue keyset index)"
echo "    schema readback OK: alembic head 0017; 0016 read-model shape + the HP-4 keyset index present"

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
kubectl -n "$NS" create secret generic proof-m85c-query-context \
  --from-file=query-context-private.pem="$QC_TMP/query-context-private.pem"
kubectl -n "$NS" create secret generic proof-m85c-provider-key \
  --from-file=COGNIC_PROOF_M85C_TIER1_API_KEY="$PROVIDER_KEY_FILE"
# M8.5-C: the kernel's OWN TLS cert (uvicorn --ssl-*) + the proof CA the
# reference binder verifies Keycloak against. Both mounted by the deployment
# patch; the CA is public bytes, the cert's key stays group-only.
kubectl -n "$NS" create secret tls proof-m85c-agentos-tls \
  --cert="$PKI_TMP/agentos.crt" --key="$PKI_TMP/agentos.key"
kubectl -n "$NS" create secret generic proof-m85c-ca \
  --from-file=proof-ca.pem="$PROOF_CA"

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
# secret/cognic/proof-m85c/litellm key=...). The proof's litellm router runs
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
# COGNIC_PROOF_M85C_OIDC_ISSUER / _OIDC_CA_BUNDLE (M8.5-C): the reference OIDC
# binder is the ONLY identity path (spec §4). The proof app's factory reads these
# to build the binder at startup; both are operator env, never image-baked. The
# CA path is the deployment patch's mount of the proof-m85c-ca Secret. An unset
# issuer or an unreadable CA fails the boot loud — there is deliberately no
# unauthenticated / header / trust-the-claims fallback to start under.
# COGNIC_APPROVAL_FOUR_EYES_TTL_S=1800 (spec §5.1, "Four-eyes TTL"): the ADR-014
# default is 60s (config.py approval_four_eyes_ttl_s) — far shorter than the
# Playwright-paced Bar D grant → self-grant-second-refused → distinct-approver
# grant-second → re-call sequence (two real browser logins + several page
# navigations between the FIRST grant and the granted re-call). Without this the
# grant lazily expires mid-workflow and D.5 would 403 tool_approval_expired
# instead of executing. The spec pins the raised TTL as CONFIGURATION for the
# proof, NOT a change to the kernel default (config.py stays 60). The
# single-approval TTL is raised in lockstep for defensive parity (the probe is
# high_risk_custom → four-eyes, so four-eyes is the load-bearing one).
kubectl -n "$NS" set env deploy/rel-agentos \
  COGNIC_ALLOW_EXTERNAL_LLM=true \
  COGNIC_POLICY_MODE="$POLICY_MODE" \
  COGNIC_ALLOWED_PROVIDERS="$ALLOWED_PROVIDERS" \
  COGNIC_LITELLM_MASTER_KEY=vault://secret/cognic/proof-m85c/litellm \
  COGNIC_CONVERSATION_CLAIM_TTL_S=600 \
  COGNIC_AGENT_RUN_TOKEN_BUDGET=60000 \
  COGNIC_AGENT_RUN_WALL_CLOCK_S=300 \
  COGNIC_APPROVAL_FOUR_EYES_TTL_S=1800 \
  COGNIC_APPROVAL_SINGLE_TTL_S=1800 \
  COGNIC_PROOF_M85C_OIDC_ISSUER="$KC_ISSUER" \
  COGNIC_PROOF_M85C_OIDC_CA_BUNDLE=/etc/proof-ca/proof-ca.pem

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
        "name": "COGNIC_PROOF_M85C_TIER1_API_KEY",
        "valueFrom": {"secretKeyRef": {"name": "proof-m85c-provider-key", "key": "COGNIC_PROOF_M85C_TIER1_API_KEY"}}
      }]
    }]
  }}}}'
kubectl -n "$NS" rollout status deploy/litellm --timeout=300s

# --- 9. DB seed (kernel-seed.sql: the 0014 rows; NO derived carve-out INSERT) -------
echo "==> [9/11] seed-db.sh (M8: the 0014 scope/entitlement/assignment rows; install materializes the carve-outs)"
# The entitlement rows are keyed by the binder's issuer-qualified subject
# (kernel-seed.sql carries __SUBJECT_*__ placeholders); seed-db.sh renders them
# from realm-subjects.env. Fail loud there if the var is unset or the file absent.
COGNIC_PROOF_M85C_REALM_SUBJECTS="$KC_CRED_TMP/realm-subjects.env" \
  NS="$NS" bash "$PROOF_DIR/seed-db.sh"

# --- 10. roll to the fully-wired pod + port-forward + STEP 0 ------------------------
echo "==> [10/11] roll the Deployment so a fresh pod boots with the topology + secrets + migrated/seeded DB"
roll_and_wait
pf_start
# The IdP host port-forward, then the CLAIM-CONTRACT PREFLIGHT: the single most
# valuable minute in the whole run. Before ANY bar spends a cent or a minute,
# mint a real token for one identity and assert the EXACT contract the realm
# emits — header typ=at+jwt, aud EXACTLY {cognic-agentos}, azp, tenant, and the
# scope array. Keycloak 26.2 defaults the rfc9068 header type OFF and a stock
# token also carries `account` in aud, so all three would silently break the
# binder and every bar would 403 identically with no signal pointing at the
# realm. This preflight turns that into a 60-second, self-diagnosing failure.
kc_pf_start
echo "==> STEP 0a — reference-binder claim-contract preflight (real token, real realm)"
CLAIM_TOKENS="$KC_CRED_TMP/claim-preflight-tokens.json"
KC_USER_PASSWORD="$(grep '^KC_PW_ANALYST_AMIR=' "$KC_CRED_TMP/realm-credentials.env" | cut -d= -f2-)" \
KC_CLIENT_SECRET="$KC_CLIENT_SECRET" \
  python3 "$PROOF_DIR/keycloak/pkce_login.py" \
    "$KC_ISSUER" "$KC_CLIENT" "$DRIVER_REDIRECT_URI" "analyst.amir" "$PROOF_CA" \
    > "$CLAIM_TOKENS" \
  || bar_fail "STEP 0a — could not mint a real token for analyst.amir (PKCE flow failed against the live realm)"
python3 "$PROOF_DIR/keycloak/assert_claim_contract.py" \
  "$CLAIM_TOKENS" "$KC_ISSUER" "analyst.amir" "proof-m85c" "${IDENTITY_SCOPES[amir]}" \
  || bar_fail "STEP 0a — the realm's emitted claim contract does not match the pinned one (see stderr; the binder would refuse every request)"
rm -f "$CLAIM_TOKENS"
echo "  STEP 0a OK: the live realm mints the exact pinned claim contract (typ/aud/azp/tenant/scopes)"

echo "==> STEP 0 — registered/hosted surfaces (all 7 packs; 4 instruction skills; bank-analyst) + hook admission"
assert_m8_surfaces "STEP 0 (first boot)"
assert_hook_pack_registered "STEP 0 (first boot)"

# ============================ BFF bring-up (the product under test) ================
# Build the Cognic Harness BFF image from its repo, prove its signature, load it,
# and deploy TWO replicas behind one Service with a dedicated TLS session Redis.
# AgentOS + Keycloak are already up, so the BFF's startup discovery + its
# in-cluster AgentOS/IdP/Redis legs all have something to reach.
echo "==> BFF 1 — build the Cognic Harness image from its repo (clean-tree provenance)"
[ -d "$HARNESS_REPO_DIR" ] || die "the cognic-harness repo is not at $HARNESS_REPO_DIR (set COGNIC_HARNESS_REPO_DIR)"
HARNESS_GIT_SHA="$(git -C "$HARNESS_REPO_DIR" rev-parse HEAD)"
HARNESS_TREE_DIRTY="$(git -C "$HARNESS_REPO_DIR" status --porcelain)"
[ -z "$HARNESS_TREE_DIRTY" ] || die "the cognic-harness tree is DIRTY — the proof would cite $HARNESS_GIT_SHA while a different BFF runs:
$HARNESS_TREE_DIRTY"
echo "    harness revision: $HARNESS_GIT_SHA (clean tree)"
# Thread the clean-tree revision into the image's provenance label (finding,
# 2026-07-12): the Dockerfile's ARG BUILD_SHA defaults to "dev", so without this
# the deployed BFF reports COGNIC_HARNESS_BUILD_SHA=dev while the runner cites the
# real $HARNESS_GIT_SHA — a provenance mismatch. Passing it makes the image
# self-report the exact revision the proof pins.
docker_build_with_retry -f "$HARNESS_REPO_DIR/Dockerfile" --build-arg BUILD_SHA="$HARNESS_GIT_SHA" \
  -t "$HARNESS_IMAGE" "$HARNESS_REPO_DIR"

# Signature-before-load (spec §5.1): push to the local proof registry, cosign-sign
# under the proof canonical key, and cosign-VERIFY — the BFF image only reaches
# the cluster after its signature verifies. (In production the harness repo's CI
# publishes the signed, digest-pinned image and the runner verifies THAT; the
# proof signs a locally-built image from the pinned clean-tree commit, which is
# the same sign->verify->load discipline over the same trust root.)
echo "==> BFF 2 — sign + verify the harness image before load"
docker tag "$HARNESS_IMAGE" "$REGISTRY_REF_HOST/cognic-harness:proofm85c"
docker push "$REGISTRY_REF_HOST/cognic-harness:proofm85c"
HARNESS_REF="$(docker inspect "$REGISTRY_REF_HOST/cognic-harness:proofm85c" --format '{{range .RepoDigests}}{{println .}}{{end}}' | grep "^$REGISTRY_REF_HOST/cognic-harness@" | head -1)"
[ -n "$HARNESS_REF" ] || die "could not capture the pushed harness image digest ref"
cosign sign --registry-cacert "$CANONICAL_DIR/registry-ca.pem" \
  --key "$CANONICAL_KEY_TMP/cosign.key" --tlog-upload=false --use-signing-config=false \
  --yes "$HARNESS_REF"
cosign verify --insecure-ignore-tlog=true --registry-cacert "$CANONICAL_DIR/registry-ca.pem" \
  --key "$CANONICAL_DIR/cosign.pub" "$HARNESS_REF" >/dev/null \
  || die "BFF image signature did NOT verify — refusing to load an unsigned harness image"
echo "    harness image signature verified: $HARNESS_REF"
# The deployment runs the mutable local tag $HARNESS_IMAGE, but the signature was
# verified on the registry digest ref $HARNESS_REF. Assert the two are the SAME
# image ID (finding, 2026-07-12): `docker tag` copied one build into both names,
# so the verified bytes ARE the loaded bytes — this pins that a future refactor
# cannot rebuild between the tag and the verify and ship unverified bytes under
# the tag. (kind loads by tag into the node; a digest-pinned deploy is not
# expressible against a kind-loaded image, so this equality IS the pin.)
_H_TAG_ID="$(docker inspect --format '{{.Id}}' "$HARNESS_IMAGE")"
_H_REF_ID="$(docker inspect --format '{{.Id}}' "$HARNESS_REF")"
[ -n "$_H_TAG_ID" ] && [ "$_H_TAG_ID" = "$_H_REF_ID" ] \
  || die "BFF image identity mismatch — the loaded tag ($_H_TAG_ID) is not the verified digest ref ($_H_REF_ID)"
kind load docker-image "$HARNESS_IMAGE" --name "$CLUSTER"

echo "==> BFF 3 — the dedicated TLS session Redis (BFF-only ACL, persistence off)"
# The ACL file (per-run BFF password; never committed) + the TLS cert Secret.
REDIS_BFF_PW="$(openssl rand -hex 24)"
REDIS_ACL_FILE="$KC_CRED_TMP/redis-users.acl"
( umask 077; printf 'user default off\nuser bff on >%s ~* +@all\n' "$REDIS_BFF_PW" > "$REDIS_ACL_FILE" )
kubectl -n "$NS" create secret generic proof-m85c-redis-bff-acl --from-file=users.acl="$REDIS_ACL_FILE"
kubectl -n "$NS" create secret tls proof-m85c-redis-bff-tls \
  --cert="$PKI_TMP/redis-bff.crt" --key="$PKI_TMP/redis-bff.key"
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/redis-bff.yaml"
kubectl -n "$NS" rollout status deploy/redis-bff --timeout=180s \
  || bar_fail "redis-bff (the BFF session store) did not become ready within 180s"

echo "==> BFF 4 — the harness Secrets (OIDC client secret + session HMAC + the rediss:// URL)"
# The BFF's confidential-client secret is the SAME one the realm minted (the BFF
# and the proof driver share the cognic-harness client). The session HMAC secret
# is a fresh >=32-char per-run value. The redis URL carries the ACL password —
# all three ride a Secret, never inline, never committed.
# Every value rides a 0600 file under the private per-run dir, NOT --from-literal
# (finding, 2026-07-12): the OIDC client secret, the session HMAC secret, and the
# rediss:// URL (which embeds the ACL password) would all be exposed in the
# kubectl process argument vector to any `ps` on the shared host — the same argv
# exposure already fixed for the provider key. --from-file keeps them off argv.
# printf '%s' everywhere (no trailing newline): kubectl --from-file uses the file
# bytes VERBATIM. A trailing "\n" on the HMAC secret would change its value vs the
# old --from-literal="$HARNESS_HMAC"; on the rediss:// URL it would corrupt the
# DSN the BFF dials.
( umask 077
  printf '%s' "$KC_CLIENT_SECRET"                          > "$KC_CRED_TMP/h-oidc-client-secret"
  printf '%s' "$(openssl rand -hex 32)"                    > "$KC_CRED_TMP/h-session-hmac-secret"
  printf 'rediss://bff:%s@redis-bff:6380/0' "$REDIS_BFF_PW" > "$KC_CRED_TMP/h-redis-url"
)
kubectl -n "$NS" create secret generic proof-m85c-harness-secrets \
  --from-file=oidc-client-secret="$KC_CRED_TMP/h-oidc-client-secret" \
  --from-file=session-hmac-secret="$KC_CRED_TMP/h-session-hmac-secret" \
  --from-file=redis-url="$KC_CRED_TMP/h-redis-url"
kubectl -n "$NS" create secret tls proof-m85c-harness-tls \
  --cert="$PKI_TMP/harness.crt" --key="$PKI_TMP/harness.key"

echo "==> BFF 5 — deploy the two BFF replicas + port-forward"
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/bff.yaml"
kubectl -n "$NS" rollout status deploy/cognic-proof-harness --timeout=300s \
  || bff_fail "the BFF (cognic-proof-harness) did not become ready within 300s"
bff_pf_start
echo "  BFF ready: 2 replicas behind svc/cognic-proof-harness; host port-forward at $HARNESS_BASE_URL"

# Pin the TLS-key custody (finding, 2026-07-12): the image runs as uid/gid 10001
# and the kubernetes.io/tls Secret is mounted root-owned 0440, so the pod can
# only read its own private key because bff.yaml sets pod securityContext.fsGroup
# =10001 (the kubelet chowns the volume to gid 10001). If a future edit drops
# fsGroup the pod would fail to read tls.key and never serve — the readiness gate
# above would already have failed, but this makes the ROOT CAUSE explicit rather
# than a mystery timeout. Assert the effective uid + that the mounted key is
# group-readable by the runtime group.
_BFF_POD0="$(kubectl -n "$NS" get pods -l app=cognic-proof-harness -o name | head -1)"
_BFF_IDU="$(kubectl -n "$NS" exec "$_BFF_POD0" -- id -u 2>/dev/null | tr -d '[:space:]')"
[ "$_BFF_IDU" = "10001" ] || bar_fail "BFF custody: expected the container to run as uid 10001, got '$_BFF_IDU'"
kubectl -n "$NS" exec "$_BFF_POD0" -- sh -c 'test -r /etc/harness-tls/tls.key' \
  || bar_fail "BFF custody: uid 10001 CANNOT read /etc/harness-tls/tls.key — fsGroup not applied? (the pod could not have served TLS)"
echo "  BFF custody OK: runs as uid 10001 and can read its own TLS private key (fsGroup honoured)"

# ============================ SETUP (M4 governed install) ==========================
# Operator-install the DLP-governed ORACLE tool v0.3.0 EXACTLY as proven in
# M4/M5/M6: the full governed lifecycle via the REAL API. Identity is now REAL
# OIDC — the author/reviewer/operator steps each ride that user's Keycloak access
# token (api() mints it via the scripted PKCE flow), verified by the reference
# binder. The HOOK + SKILL + AGENT packs deliberately take NO part in this flow
# (trust-register + hosting only).
echo "==> [11/11] SETUP — governed operator lifecycle for the oracle v0.3.0 tool (submit -> claim -> approve -> allow-list -> configure -> install)"

MANIFEST_JSON="$(uv run python - "$PACK_ID" "$PACK_WHEEL" <<'PY'
import json, sys
pack_id, wheel = sys.argv[1], sys.argv[2]
manifest = {
    "pack": {"kind": "tool", "name": pack_id, "version": "0.3.0"},
    "identity": {
        "agent_id": pack_id,
        "display_name": "Cognic Oracle Schema (proof-m85c)",
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
    "display_name": "Cognic Oracle Schema (proof-m85c)",
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
SETUP_OPERATOR_SUBJECT="$(bound_subject "${IDENTITY_USER[operator]}")"
grep -qF "mcp.override.set" <<<"$MAT" \
  || bar_fail "SETUP 8 no mcp.override.set materialization event (got: ${MAT:-<none>})"
grep -qF "mcp.allowlist.add" <<<"$MAT" \
  || bar_fail "SETUP 8 no mcp.allowlist.add materialization event (got: ${MAT:-<none>})"
grep -qF "override|$TENANT|$PACK_ID|http://10.96.0.51:8765/mcp" <<<"$DERIVED_ROWS" \
  || bar_fail "SETUP 8 no derived override row (got: ${DERIVED_ROWS:-<none>})"
grep -qF "allowlist|$TENANT|10.96.0.51|$SETUP_OPERATOR_SUBJECT" <<<"$DERIVED_ROWS" \
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
#
# The retired `mcp` SERVICE role's ONLY job was this warm-up. In M8.5-C there is
# no service principal — the reference binder derives actor_type from the locked
# grant profile, which has no client-credentials grant (Bar B proves the attempt
# fails), so a machine identity cannot exist. amir carries mcp.tool.list for
# exactly this reason: the warm-up is a real human's governed MCP read, not a
# distinct machine login.
api amir GET "/api/v1/mcp/servers/$PACK_ID/tools" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR preflight warm-up list_tools (HTTP $HTTP_CODE — MCP carve-out not live?)"
DS="$(discovery_status)"
[ "$DS" = "auth_ready" ] || bar_fail "BAR preflight discovery_status=$DS (expected auth_ready — the governed MCP carve-out)"


# ============================ PROBE PACK install (Bar D's high-risk tool) ==========
# The four-eyes approval probe (spec §6): a high_risk_custom MCP tool installed
# through the SAME governed operator lifecycle as the oracle tool, using real
# OIDC tokens. tools.rego maps high_risk_custom -> require_4_eyes, so every
# probe_write invocation Bar D drives goes through the genuine ADR-014 four-eyes
# flow. The probe image was built + kind-loaded at step 3/4; here we run the
# lifecycle + deploy the Service + roll cold so the carve-out is live.
echo "==> PROBE SETUP — governed operator lifecycle for the approval-probe pack (high_risk_custom)"
PROBE_MANIFEST_JSON="$(uv run python - "$PROBE_PACK_ID" "$PROBE_PACK_VERSION" <<'PY'
import json, sys
pack_id, version = sys.argv[1], sys.argv[2]
manifest = {
    "pack": {"kind": "tool", "name": pack_id, "version": version},
    "identity": {
        "agent_id": pack_id,
        "display_name": "Cognic Approval Probe (proof-m85c)",
        "provider_organization": "Cognic",
        "provider_url": "https://cognic.example",
    },
    "mcp": {"server_url": "http://10.96.0.52:8766/mcp", "scopes": ["approval_probe.write"]},
    "risk_tier": {"tier": "high_risk_custom"},
    "data_governance": {
        "data_classes": ["internal", "audit_trail"],
        "purpose": "audit_evidence",
        "retention_policy": "purpose_window",
        "retention_max_window": 7,
    },
    "supply_chain": {
        "attestation_paths": [
            "cosign.sig", "bundle.sigstore", "sbom.cdx.json",
            "slsa-provenance.intoto.json", "intoto-layout.json",
            "vuln-scan.json", "license-audit.json",
        ],
        "blob_path": "cognic_tool_approval_probe-0.1.0-py3-none-any.whl",
    },
}
print(json.dumps(manifest))
PY
)"
PROBE_MANIFEST_DIGEST="$(uv run python - <<PY
from cognic_agentos.core.canonical import canonical_bytes
import hashlib, json
m = json.loads('''$PROBE_MANIFEST_JSON''')
print(hashlib.sha256(canonical_bytes(m)).hexdigest())
PY
)"
PROBE_CREATE_BODY="$(python3 - "$PROBE_PACK_ID" "$PROBE_MANIFEST_DIGEST" "$SIGNED_DIGEST" <<'PY'
import json, sys
pack_id, md, sd = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({"kind": "tool", "pack_id": pack_id, "display_name": "Cognic Approval Probe (proof-m85c)", "manifest_digest": md, "signed_artefact_digest": sd}))
PY
)"
PROBE_CREATE_RESP="$(api author POST /api/v1/packs/drafts "$PROBE_CREATE_BODY")"
load_http_code
[ "$HTTP_CODE" = "201" ] || bar_fail "PROBE SETUP create_draft (HTTP $HTTP_CODE; body: $PROBE_CREATE_RESP)"
PROBE_UUID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$PROBE_CREATE_RESP")"
[ -n "$PROBE_UUID" ] || bar_fail "PROBE SETUP no pack id"
PROBE_ROOT="/opt/cognic/pack-attestations/$PROBE_PACK_ID/$PROBE_PACK_VERSION"
PROBE_SUBMIT_BODY="$(python3 - "$PROBE_ROOT" <<PY
import json, sys
print(json.dumps({"manifest": json.loads('''$PROBE_MANIFEST_JSON'''), "signed_artefact_root": sys.argv[1]}))
PY
)"
api author POST "/api/v1/packs/drafts/$PROBE_UUID/submit" "$PROBE_SUBMIT_BODY" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "PROBE SETUP submit (HTTP $HTTP_CODE)"
api reviewer POST "/api/v1/packs/$PROBE_UUID/claim" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "PROBE SETUP claim (HTTP $HTTP_CODE)"
api reviewer POST "/api/v1/packs/$PROBE_UUID/approve" "$APPROVE_BODY" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "PROBE SETUP approve (HTTP $HTTP_CODE)"
api operator POST "/api/v1/packs/$PROBE_UUID/allow-list" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "PROBE SETUP allow-list (HTTP $HTTP_CODE)"
PROBE_CONFIGURE_BODY="$(python3 - "$TENANT" <<'PY'
import json, sys
tenant = sys.argv[1]
print(json.dumps({
    "server_url_override": "http://10.96.0.52:8766/mcp",
    "internal_host_allowlist": ["10.96.0.52"],
    "oauth_credential_ref": f"secret/cognic/{tenant}/mcp-oauth/192.88.99.9_9000",
    "as_allowlist_ref": f"secret/cognic/{tenant}/mcp-as-allowlist",
}))
PY
)"
api operator PUT "/api/v1/packs/$PROBE_UUID/runtime-config" "$PROBE_CONFIGURE_BODY" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "PROBE SETUP configure (HTTP $HTTP_CODE)"
api operator POST "/api/v1/packs/$PROBE_UUID/install" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "PROBE SETUP install (HTTP $HTTP_CODE)"
echo "  PROBE SETUP OK: approval-probe installed (high_risk_custom -> four-eyes)"

echo "==> PROBE SETUP — deploy the probe MCP Service + roll cold so the carve-out is live"
kubectl -n "$NS" apply -f "$PROOF_DIR/manifests/probe-pack.yaml"
kubectl -n "$NS" rollout status deploy/proof-probe-pack --timeout=300s \
  || pack_fail "proof-probe-pack rollout not available within 300s"
roll_and_wait
pf_start
# Warm the probe's per-tenant OAuth token + list_tools cache (amir holds mcp.tool.list).
api amir GET "/api/v1/mcp/servers/$PROBE_PACK_ID/tools" >/dev/null
[ "$HTTP_CODE" = "200" ] || bar_fail "PROBE SETUP warm-up list_tools (HTTP $HTTP_CODE — probe carve-out not live?)"
echo "  PROBE SETUP OK: probe Service deployed, carve-out warm"

# The driver toolchain preflight — prove the driver's CLI surface + JSON shapes
# without a browser BEFORE the first live bar (a driver bug must not masquerade
# as a bar failure 30 minutes in).
echo "==> BAR preflight — browser driver selftest (CLI surface + JSON shapes, no browser)"
( cd "$DRIVER_DIR" && "$DRIVER_PYTHON" driver.py selftest ) \
  || bar_fail "browser driver selftest failed — fix the driver before the live bars"
echo "  driver selftest OK"

# probe_ledger_count — the INDEPENDENT execution observer (spec §6): the number
# of lines in the proof-local ledger, read by the runner alone via kubectl exec.
# "zero execution" is provable because nothing but the runner can read it.
#
# A FAILED READ MUST NEVER READ AS "0" (review 2026-07-12 round 4, F2-b). This is the
# proof's single most load-bearing NEGATIVE observable: every `= "0"` assertion in
# Bars B and D — the ledger did not move on a PENDING request, did not move after a
# DENY, did not move after only ONE of the two four-eyes grants — is what proves a
# high-risk tool did NOT execute. The pre-review in-pod command was
#
#     sh -c "wc -l < $PROBE_LEDGER_PATH 2>/dev/null || echo 0"
#
# which collapsed three genuinely different states onto the single value 0:
#   * the ledger FILE IS ABSENT        — a legitimate zero: the probe tool creates the
#                                        ledger on its FIRST execution, so "no file" IS
#                                        "nothing has run". This is the expected
#                                        initial state and the ONLY tolerated
#                                        zero-by-absence;
#   * the file exists, zero lines      — a legitimate zero;
#   * the file exists, THE READ FAILED — permissions, an I/O error, a truncated or
#                                        locked file: NOT AN OBSERVATION AT ALL, and
#                                        yet reported as "zero execution".
# The third case is the hole, and it hands every "must stay 0" assertion in the proof
# its PASS for free — while an executed tool sits unread in a file nobody could open.
#
# The in-pod script below therefore distinguishes the three EXPLICITLY: absence is an
# affirmative 0, and any other failure exits non-zero with a named reason. There is no
# `2>/dev/null` over the read and no `|| echo 0` catch-all. The runner then reads it
# through kubectl_capture, which dies loudly on a non-zero exit rather than letting it
# decay into an empty string that merely HAPPENS to fail an equality check today — so
# a future `= ""` comparison cannot quietly resurrect the hole. Finally the value is
# validated as a non-negative integer before it is returned: no caller may ever
# compare against "0" without that 0 having been genuinely observed.
probe_ledger_count() {
  local out rc
  # Exit status checked EXPLICITLY, bar_fail raised HERE (see the set -e note above
  # kubectl_capture: a refusal one substitution level deeper is swallowed, and the
  # fabricated "0" — the very value every "the tool did NOT execute" assertion in Bars
  # B and D rests on — comes straight back).
  set +e
  out="$(kubectl_capture -n "$NS" exec deploy/proof-probe-pack -- sh -c '
set -u
ledger="$1"
if [ ! -e "$ledger" ]; then
  # AFFIRMATIVE zero: the probe tool creates the ledger on its FIRST execution.
  echo 0
  exit 0
fi
if [ ! -r "$ledger" ]; then
  echo "probe_ledger_unreadable: $ledger exists but cannot be read" >&2
  exit 21
fi
if ! count="$(wc -l < "$ledger")"; then
  echo "probe_ledger_read_failed: wc -l < $ledger failed" >&2
  exit 22
fi
printf "%s\n" "$count"
' _ "$PROBE_LEDGER_PATH")"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] \
    || bar_fail "probe_ledger_count — the ledger read FAILED (exit $rc): $(_kubectl_capture_err). REFUSING to report a count. (exit 21 = the ledger exists but cannot be read; exit 22 = the read itself failed; anything else = the kubectl exec never landed.) Every 'the ledger stayed 0' assertion in Bars B and D is a claim that a DENIED, PENDING or under-approved high-risk tool did NOT execute — it may only ever rest on a zero that was genuinely OBSERVED, never on one manufactured by a read that failed."
  out="$(printf '%s' "$out" | tr -d '[:space:]')"
  case "$out" in
    ''|*[!0-9]*)
      bar_fail "probe_ledger_count: the ledger read returned a NON-NUMERIC value ('$out'). REFUSING to report a count: every 'the ledger stayed 0' assertion in Bars B and D is a claim that a high-risk tool did NOT execute, and it may only ever rest on a value that was actually observed." ;;
  esac
  printf '%s' "$out"
}

# jq_get <FIELD> <JSON> — a top-level field off a driver JSON result (python, no jq dep).
#
# The DOCUMENT rides STDIN, the field NAME stays on argv (F1 — see the custody note
# above json_field). This is the helper the S1 login result flows through, and that
# result carries both session ids AND the callback URL with its one-time authorization
# code; on argv, a `ps` snapshot during the python3 child's life captured all of it.
#
# Shares _JSON_GET_PY with json_field, so BOTH render booleans in their JSON spelling
# — see the note there for the eighteen call sites that depend on it.
jq_get() {
  printf '%s' "${2:-}" | python3 -c "$_JSON_GET_PY" "$1" 2>/dev/null || true
}

# assert_chat_turn_completed <WHERE> <DRIVER_JSON> — a model-driven UI turn is
# not evidence merely because the browser interaction returned JSON. The BFF POST
# itself must have completed its 303 flow and the rendered transcript must gain
# exactly one turn. This catches upstream transport timeouts before a later XSS or
# chain assertion mislabels the resulting empty/in-progress conversation.
assert_chat_turn_completed() {
  local where="$1" doc="$2" status before after answer expected
  status="$(jq_get status "$doc")"
  before="$(jq_get turns_before "$doc")"
  after="$(jq_get turn_count "$doc")"
  answer="$(jq_get answer_text "$doc")"
  [ "$status" = "303" ] \
    || bar_fail "$where — the BFF turn POST did not complete its governed redirect (HTTP $status, expected 303)"
  case "$before" in
    ''|*[!0-9]*)
      bar_fail "$where — the browser returned a non-numeric prior turn count ('$before')" ;;
  esac
  case "$after" in
    ''|*[!0-9]*)
      bar_fail "$where — the browser returned a non-numeric resulting turn count ('$after')" ;;
  esac
  expected=$((before + 1))
  [ "$after" -eq "$expected" ] \
    || bar_fail "$where — the rendered transcript did not advance by exactly one turn (before=$before, after=$after)"
  [ -n "$answer" ] \
    || bar_fail "$where — the completed rendered turn carried no governed answer"
}

# mint_probe_request <ROLE> — mint ONE four-eyes approval request through the REAL
# MCP invoke path (spec §5.1: the direct MCP surface, outside the BFF). The role's
# PKCE token invokes probe_write; a high_risk_custom tool returns 202 +
# tool_approval_pending with a minted approval_request_id. Prints TWO
# tab-separated fields: "<request_id>\t<nonce>". The nonce is the request's BOUND
# argument — REPLAYING the request (recall_probe) requires re-sending BOTH the
# approval_request_id AND this exact nonce, because the engine binds args to the
# request. Discarding the nonce (the pre-review defect) made every recall mint a
# FRESH request instead of replaying the granted one, so Bar D's denial /
# four-eyes-execute / originator-isolation legs never exercised the HP-4 replay
# path at all.
mint_probe_request() {
  local role="$1" nonce resp rid parse_out parse_rc
  nonce="probe-$(python3 -c 'import secrets; print(secrets.token_hex(8))')"
  local body
  body="$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"probe_write","arguments":{"nonce":sys.argv[1]}}))' "$nonce")"
  resp="$(api "$role" POST "/api/v1/mcp/servers/$PROBE_PACK_ID/tools/call" "$body")"
  load_http_code
  [ "$HTTP_CODE" = "202" ] || bar_fail "mint_probe_request($role) expected 202 tool_approval_pending, got HTTP $HTTP_CODE (body: $resp)"
  # FastAPI wraps HTTPException detail under the top-level `detail` key. Parse the
  # exact wire contract and fail through bar_fail: a bare command-substitution error
  # under set -e would otherwise exit without the proof's diagnostic capture.
  set +e
  parse_out="$(printf '%s' "$resp" | python3 -c '
import json, sys, uuid

doc = json.load(sys.stdin)
if not isinstance(doc, dict):
    raise ValueError("response_not_object")
detail = doc.get("detail")
if not isinstance(detail, dict):
    raise ValueError("detail_not_object")
if detail.get("reason") != "tool_approval_pending":
    raise ValueError("reason_not_tool_approval_pending")
rid = detail.get("approval_request_id")
if not isinstance(rid, str):
    raise ValueError("approval_request_id_not_string")
try:
    parsed = uuid.UUID(rid)
except ValueError:
    raise ValueError("approval_request_id_not_uuid") from None
if str(parsed) != rid:
    raise ValueError("approval_request_id_not_canonical_uuid")
print(rid)
' 2>&1)"
  parse_rc=$?
  set -e
  if [ "$parse_rc" -ne 0 ] || [ -z "$parse_out" ]; then
    bar_fail "mint_probe_request($role): invalid 202 tool_approval_pending envelope (rc=$parse_rc): ${parse_out:-<no output>}"
  fi
  rid="$parse_out"
  printf '%s\t%s\n' "$rid" "$nonce"
}

# recall_probe <ROLE> <REQUEST_ID> <NONCE> — REPLAY an existing request: re-invoke
# probe_write carrying BOTH the approval_request_id AND its bound nonce, so the
# kernel matches the SAME request (its pending/denied/granted/originator state)
# instead of minting a fresh one. Prints the body; sets HTTP_CODE via the global;
# the caller inspects both. This is the "exact re-call" the honesty boundary
# defines: actor/tenant/tool/args-bound, NOT exactly-once — a granted shape may
# replay until expiry. The verify precedence (spec §2.2) is
# tenant → originator → args/tool binding → state, so the ORIGINAL nonce is
# required for a denied/pending/granted state refusal to surface (a wrong nonce
# would short-circuit to tool_approval_binding_mismatch first).
recall_probe() {
  local role="$1" rid="$2" nonce="$3" body
  [ -n "$rid" ] || bar_fail "recall_probe($role): empty request id (programming error)"
  body="$(python3 -c 'import json,sys; print(json.dumps({"tool_name":"probe_write","arguments":{"nonce":sys.argv[2]},"approval_request_id":sys.argv[1]}))' "$rid" "$nonce")"
  api "$role" POST "/api/v1/mcp/servers/$PROBE_PACK_ID/tools/call" "$body"
}

# ============================ BAR A — session / BFF custody ========================
# The ten session cases (§3.3 S1-S10) + the replica/outage/CSRF/XSS custody
# proofs. The BFF holds every token server-side in the shared TLS Redis; the
# browser gets only the opaque __Host- cookie. Each case is judged by the runner
# from the driver's emitted JSON, never by the driver itself.
#
# PER-STEP REPLICA ATTRIBUTION (spec §5.2 Bar A: "Value-free proof logs record which
# pod served each step"). Every host forward targets a NAMED POD, so each step below
# announces its serving replica — `step=<name> served_by=<pod>` — as a fact the
# runner ESTABLISHED by choosing the pod, not an inference about kube-proxy. The
# forward alternates replicas across steps, so both pods genuinely serve traffic.
echo "==> BAR A — session / BFF custody (S1-S10 + replica / outage / CSRF / XSS)"

# S1 — login rotates the pre-auth session; the old cookie is unusable.
bff_served_by "A.S1"
A_LOGIN="$(drive_login amir)"
# THE LOGIN JSON IS A CREDENTIAL BUNDLE (review 2026-07-12 round 4, F1): it carries
# BOTH session ids AND the callback URL, whose `?code=` is a one-time authorization
# code exchangeable for tokens. So it never appears in a message — only its
# non-reversible fingerprint. The FACT each assertion needs (did the login report
# ok=true? are the two ids EQUAL?) is stated in words; the values stay out of the log.
[ "$(jq_get ok "$A_LOGIN")" = "true" ] \
  || bar_fail "BAR A S1 login did not complete — the driver's login JSON did not report ok=true (body $(redact "$A_LOGIN"))"
A_PRE="$(jq_get pre_auth_session_id "$A_LOGIN")"
A_POST="$(jq_get post_auth_session_id "$A_LOGIN")"
[ -n "$A_POST" ] || bar_fail "BAR A S1 no post-auth session id"
# The pre-auth id is REQUIRED, not optional: S1's rotation check and S5's replay
# both rest on it. The pre-review `if [ -n "$A_PRE" ]` silently skipped the
# rotation assertion when the driver failed to capture it.
[ -n "$A_PRE" ] \
  || bar_fail "BAR A S1 no pre-auth session id captured — the rotation (S1) and single-use-state (S5) cases cannot be judged"
[ "$A_PRE" != "$A_POST" ] \
  || bar_fail "BAR A S1 login did NOT rotate the session — the pre-auth and post-auth session ids are IDENTICAL (both $(redact "$A_PRE")). Possession of a session id IS the session, so the ids themselves are never printed; the equal fingerprints are the proof they did not rotate."
A_STALE="$(drive_replay_cookie "$A_PRE")"
[ "$(jq_get authenticated "$A_STALE")" = "false" ] \
  || bar_fail "BAR A S1 the pre-auth cookie is STILL usable after login (session not rotated closed)"
echo "  Bar A S1 OK: login rotated the session; the pre-auth cookie is dead"

# S5 — the OIDC state/nonce is consumed EXACTLY ONCE.
#
# The replay MUST carry the PRE-AUTH cookie (Codex round-2 P1). The BFF's
# complete_callback() reads the session cookie FIRST and refuses `no_login_session`
# BEFORE it ever calls consume_oidc() (cognic_harness/auth/service.py:125-129).
# The pre-review leg replayed the callback URL in a COOKIELESS context, so it
# died at that first gate: it never reached the one-time-state check at all, and
# a BFF that NEVER consumed state/nonce would have passed it. Replaying WITH the
# pre-auth cookie drives the flow to consume_oidc(), where a correct BFF finds the
# transaction already spent and refuses `login_state_already_consumed`.
#
# Two observables, both required: the replay must NOT authenticate, AND the BFF's
# value-free refusal marker must name the SINGLE-USE gate — otherwise "it refused"
# is satisfied by the cookie gate and proves nothing.
bff_served_by "A.S5"
A_CB="$(jq_get callback_url "$A_LOGIN")"
[ -n "$A_CB" ] && [ "$A_CB" != "null" ] \
  || bar_fail "BAR A S5 the login did not surface a callback_url to replay (driver could not observe /auth/callback)"
# The marker COUNT before the replay — assert_bff_refusal requires a delta, not the
# mere existence of a matching line somewhere in the log window (F9).
A_S5_PRE="$(bff_refusal_count login_state_already_consumed)"
A_REPLAY="$(drive_replay_callback "$A_CB" "$A_PRE")"
[ "$(jq_get authenticated "$A_REPLAY")" = "false" ] \
  || bar_fail "BAR A S5 replaying the CONSUMED OIDC callback AUTHENTICATED (state/nonce not single-use)"
assert_bff_refusal login_state_already_consumed "$A_S5_PRE"
echo "  Bar A S5 OK: the OIDC state/nonce is single-use — the replay reached consume_oidc() (pre-auth cookie attached) and was refused login_state_already_consumed"

# S8 — the cookie carries NO OAuth material (only the opaque session id).
bff_served_by "A.S8"
A_COOKIES="$(drive cookie-dump --state-file "$QC_TMP/session-amir.json")"
# THE COOKIE DUMP IS A CREDENTIAL — it carries the live `__Host-cognic_session` VALUE.
# It therefore rides STDIN (F1: json_assert's document argument), and EVERY assertion
# message below carries only cookie NAMES and SHAPE FACTS. The pre-review predicate
# ended its flag assertions with `, sess` — so a failure printed the whole cookie
# dict, VALUE INCLUDED, straight into the proof log via bar_fail. A custody proof whose
# failure path discloses the session is not a custody proof.
json_assert "BAR A S8 cookie content" '
import json, sys
doc = json.loads(sys.stdin.read())
names = {c["name"] for c in doc["cookies"]}
assert "__Host-cognic_session" in names, f"no __Host- session cookie: {sorted(names)}"
sess = next(c for c in doc["cookies"] if c["name"] == "__Host-cognic_session")
secure = sess["secure"]
http_only = sess["httpOnly"]
assert secure and http_only, (
    f"__Host-cognic_session flags wrong: secure={secure!r} httpOnly={http_only!r}"
)
# Playwright projects the EFFECTIVE host into `domain` even when Set-Cookie had
# no Domain attribute. Chromium accepting the __Host- prefix plus Secure + `/`
# is the no-Domain proof; the projected value must equal this proof origin.
path = sess["path"]
effective_domain = sess.get("domain")
assert path == "/" and effective_domain == "127.0.0.1", (
    f"__Host-cognic_session is not __Host--shaped: path={path!r} "
    f"effective_domain={effective_domain!r}"
)
# No cookie value may contain OAuth material — a JWT is dot-delimited base64url,
# an access/refresh token is long+opaque; the session id is a short opaque handle.
# The value is INSPECTED but never REPORTED: the message names the cookie only.
for c in doc["cookies"]:
    v = c["value"]
    name = c["name"]
    assert v.count(".") < 2, f"cookie {name} looks like a JWT (dot-delimited)"
    assert "eyJ" not in v, f"cookie {name} contains a base64url JWT header"
print("ok")
' "$A_COOKIES"
echo "  Bar A S8 OK: the cookie carries only the opaque __Host- session id — no OAuth material"

# S2 — cross-replica: the SAME session cookie authenticates against EACH replica
# INDIVIDUALLY. The BFF exposes no per-pod response header, so the runner attributes
# the replica by port-forwarding to ONE named pod at a time — a request provably
# hits that pod (this is the same mechanism every other Bar A step now uses for its
# `served_by` line; S2 just makes BOTH pods explicit in one leg). Both pods
# resolving the same cookie proves the session lives in the shared Redis, not a
# replica's memory (stronger than "deployed twice", which the survivor could satisfy
# alone).
bff_resolve_pods
A_POD_A="$BFF_POD_1"
A_POD_B="$BFF_POD_2"
[ -n "$A_POD_A" ] && [ -n "$A_POD_B" ] && [ "$A_POD_A" != "$A_POD_B" ] \
  || bar_fail "BAR A S2 expected 2 DISTINCT BFF replicas (got A='$A_POD_A' B='$A_POD_B') — a single-replica check cannot prove the session is shared"
for _pod in "$A_POD_A" "$A_POD_B"; do
  bff_pf_pod "$_pod"
  bff_served_by "A.S2"
  _auth="$(drive_replay_cookie "$A_POST")"
  [ "$(jq_get authenticated "$_auth")" = "true" ] \
    || bar_fail "BAR A S2 the session did NOT authenticate against replica $_pod (not shared via Redis?)"
  echo "  Bar A S2: session authenticated against replica $_pod"
done
bff_pf_start   # back to a single named-pod forward (alternating)
echo "  Bar A S2 OK: the SAME session authenticated against BOTH replicas (shared in Redis)"

# S9 — restarting a replica does not lose the session: delete one pod, let the
# deployment recover two, prove the SAME cookie still authenticates.
#
# The KILL ITSELF MUST BE PROVEN (Codex round-2 P1). The pre-review leg swallowed
# a failed delete with `|| true` and then asserted only that the cookie still
# worked — so if the delete silently failed (wrong name, RBAC, a race), NOTHING
# restarted, `rollout status` passed trivially against the untouched pods, the
# cookie of course still authenticated, and S9 "passed" having proven nothing.
# Now: capture the victim's UID, REQUIRE the delete to succeed, and REQUIRE the
# recovered set to no longer contain that UID — a pod genuinely died and a new one
# genuinely replaced it.
A_POD_A_UID="$(kubectl -n "$NS" get "$A_POD_A" -o jsonpath='{.metadata.uid}')"
[ -n "$A_POD_A_UID" ] || bar_fail "BAR A S9 could not read the victim pod's UID — the restart could not be verified"
kubectl -n "$NS" delete "$A_POD_A" --wait=true >/dev/null \
  || bar_fail "BAR A S9 the victim pod delete FAILED — no replica restarted, so the leg would prove nothing"
kubectl -n "$NS" rollout status deploy/cognic-proof-harness --timeout=180s \
  || bff_fail "BAR A S9 the BFF did not recover 2 replicas after a pod kill"
A_UIDS_AFTER=" $(kubectl -n "$NS" get pods -l app=cognic-proof-harness -o jsonpath='{.items[*].metadata.uid}') "
case "$A_UIDS_AFTER" in
  *" $A_POD_A_UID "*)
    bar_fail "BAR A S9 the killed pod ($A_POD_A_UID) is STILL running — nothing actually restarted" ;;
esac
[ "$(kubectl -n "$NS" get pods -l app=cognic-proof-harness --no-headers 2>/dev/null | wc -l | tr -d ' ')" = "2" ] \
  || bar_fail "BAR A S9 the BFF did not settle back to exactly 2 replicas after the kill"
# The pod the forward was targeting may be the one just KILLED — drop it and
# re-resolve, or the attribution would name a pod that no longer exists.
BFF_CURRENT_POD=""
bff_pf_start
bff_served_by "A.S9"
A_AFTER_KILL="$(drive_replay_cookie "$A_POST")"
[ "$(jq_get authenticated "$A_AFTER_KILL")" = "true" ] \
  || bar_fail "BAR A S9 the session did NOT survive a replica kill (not shared via Redis?)"
echo "  Bar A S9 OK: a replica was provably killed (UID $A_POD_A_UID gone, 2 replicas recovered) and the session survived — it lives in Redis, not a pod"

# CSRF — an unsafe request with a missing/garbage CSRF token is refused with the
# EXACT governed status + reason (403 {"reason":"csrf_invalid"}, web/dependencies.py:73),
# never a generic 400 (which could mask a validation error rather than the gate).
bff_served_by "A.CSRF"
A_CSRF="$(drive csrf-probe --path /conversations --state-file "$QC_TMP/session-amir.json")"
A_CSRF_STATUS="$(jq_get status "$A_CSRF")"
A_CSRF_REASON="$(jq_get body_reason "$A_CSRF")"
[ "$A_CSRF_STATUS" = "403" ] \
  || bar_fail "BAR A CSRF probe was not refused with the governed 403 (status $A_CSRF_STATUS)"
[ "$A_CSRF_REASON" = "csrf_invalid" ] \
  || bar_fail "BAR A CSRF probe refused but not with reason csrf_invalid (reason '$A_CSRF_REASON')"
echo "  Bar A CSRF OK: an unsafe request without a valid CSRF token is refused 403 csrf_invalid"

# XSS — hostile output renders INERT. Post a turn whose user message carries live
# attack markup, then prove on the rendered conversation + evidence surfaces that
# (a) no injected script executed AND (b) the markup is actually PRESENT as inert
# escaped text (rendered_text_contains_markup) — so the test cannot pass by the
# content simply being absent (the pre-review defect: a nonexistent conversation
# trivially reported script_executed=false with nothing rendered).
bff_served_by "A.XSS"
A_XSS_MSG='<script>window.__XSS_FIRED=true</script><img src=x onerror="window.__XSS_FIRED=true"> — also, in one sentence, what is 2+2?'
A_XSS_TURN="$(drive chat-turn --create --agent-id "$AGENT_ID" --message "$A_XSS_MSG" --state-file "$QC_TMP/session-amir.json")"
assert_chat_turn_completed "BAR A XSS" "$A_XSS_TURN"
A_XSS_CID="$(jq_get conversation_id "$A_XSS_TURN")"
[ -n "$A_XSS_CID" ] || bar_fail "BAR A XSS could not create a conversation carrying the hostile message (body: $A_XSS_TURN)"
A_XSS="$(drive xss-probe --conversation-id "$A_XSS_CID" --state-file "$QC_TMP/session-amir.json")"
[ "$(jq_get script_executed "$A_XSS")" = "false" ] \
  || bar_fail "BAR A XSS — injected script EXECUTED (output not rendered inert)"
[ "$(jq_get rendered_text_contains_markup "$A_XSS")" = "true" ] \
  || bar_fail "BAR A XSS — the hostile markup was NOT present as rendered text (vacuous pass: nothing to escape?)"
echo "  Bar A XSS OK: hostile markup rendered inert as escaped text; no script executed"

# S3 — logout invalidates the session on BOTH replicas: after logout, the same
# cookie is dead when replayed against EACH named pod (cross-replica revocation,
# not just local). Pod names may have changed after the S9 kill, so re-resolve.
bff_served_by "A.S3-logout"
A_LOGOUT="$(drive logout --state-file "$QC_TMP/session-amir.json")"
[ "$(jq_get cookie_cleared "$A_LOGOUT")" = "true" ] || bar_fail "BAR A S3 logout did not clear the cookie"
bff_resolve_pods                 # pod names CHANGED in the S9 kill — never reuse the old ones
A_POD_A2="$BFF_POD_1"
A_POD_B2="$BFF_POD_2"
# Both replicas are REQUIRED (Codex round-2 P1): the pre-review loop `continue`d
# past an empty pod name and still printed "dead across BOTH replicas", so a
# one-replica cluster would have satisfied a cross-replica revocation claim.
[ -n "$A_POD_A2" ] && [ -n "$A_POD_B2" ] && [ "$A_POD_A2" != "$A_POD_B2" ] \
  || bar_fail "BAR A S3 expected 2 DISTINCT BFF replicas post-S9 (got A='$A_POD_A2' B='$A_POD_B2') — cross-replica revocation cannot be judged against one pod"
for _pod in "$A_POD_A2" "$A_POD_B2"; do
  bff_pf_pod "$_pod"
  bff_served_by "A.S3"
  A_DEAD="$(drive_replay_cookie "$A_POST")"
  [ "$(jq_get authenticated "$A_DEAD")" = "false" ] \
    || bar_fail "BAR A S3 the session is STILL usable after logout on replica $_pod (revocation not cross-replica)"
  echo "  Bar A S3: post-logout cookie is dead on replica $_pod"
done
bff_pf_start
echo "  Bar A S3 OK: logout revoked the session family; the cookie is dead across BOTH replicas"

# S7 — Redis outage fails CLOSED. The spec names the status ("re-authentication /
# 503; never memory continuation") and the BFF implements exactly it: a
# SessionStoreUnavailable is mapped to a 503 (cognic_harness/web/__init__.py:43-45).
#
# The pre-review leg asserted only `ok != true` on a browser login — satisfied by
# ANY driver failure (a chromium crash, a page timeout, a typo'd selector), so it
# could pass while the BFF happily continued from memory (Codex round-2 P1). Now
# the leg runs a CONTROLLED experiment on a LIVE session:
#   control    — a fresh session returns 200 with the store up, and a cookie-less
#                GET /login 3xx-redirects to Keycloak (the probe reaches the route);
#   outage     — the SAME cookie must return EXACTLY 503 (not 200: that is the
#                forbidden memory continuation; and not a generic 5xx);
#   fresh HTTP — a cookie-less GET /login must return EXACTLY 503 (the DIRECT,
#                driver-free observation — see below);
#   fresh BROWSER — a real browser login must report an OBSERVED BFF refusal.
#
# THE REFUSAL MUST BE THE BFF'S, NOT THE HARNESS'S (review 2026-07-12 round 5, F1).
# The round-4 fix made the browser leg demand an OBSERVED `false` rather than a
# non-`true`, which closed the fabrication inside jq_get — but it left the fabrication one
# level UP, in drive_login_capture, which synthesised {"ok": false, …} for EVERY non-zero
# driver exit. `ok: false` therefore still conflated "the BFF refused" (the claim) with
# "the proof harness broke" (a Chromium crash, a selector typo, a `uv` failure, a missing
# password) — and every one of those MANUFACTURED the evidence that the BFF failed closed.
#
# Both halves are fixed, belt and braces:
#
#   (1) A DIRECT HTTP PROBE with no browser in the loop at all, and therefore no
#       fabrication surface: a cookie-less CA-verified `GET /login` must return EXACTLY
#       503. That is a direct observation of the very claim — `create_pre_auth()` is the
#       first store touch in the login flow and its SessionStoreUnavailable maps to 503.
#       A transport failure is rejected EXPLICITLY: curl prints `000` when the connection
#       never happened, and a tool that could not run has observed nothing.
#
#   (2) THE BROWSER LEG NOW CARRIES A DISCRIMINATED OUTCOME. The driver observes the
#       BFF's own status on the /login navigation and reports `refused` + `http_status`;
#       anything it could not observe is `driver_error`. S7 demands `refused` AND `503`,
#       and bar_fails LOUD on `driver_error` — a broken harness is a broken proof, never
#       a passing one.
bff_served_by "A.S7"
A_S7="$(drive_login sara)"
A_S7_C="$(jq_get post_auth_session_id "$A_S7")"
[ -n "$A_S7_C" ] || bar_fail "BAR A S7 could not establish the control session"
A_S7_UP="$(bff_status "$A_S7_C")"
[ "$A_S7_UP" = "200" ] \
  || bar_fail "BAR A S7 control failed: a live session did not return 200 with the store UP (got $A_S7_UP) — the outage assertion below would be meaningless"
# CONTROL for the direct probe: with the store UP the same cookie-less GET /login must
# 3xx-redirect to Keycloak. This proves the probe REACHES the login route (a typo'd path
# would 404 here, and a 503 later would then be attributable to anything at all).
set +e
A_S7_FRESH_UP="$(bff_fresh_login_status)"
A_S7_FRESH_UP_RC=$?
set -e
[ "$A_S7_FRESH_UP_RC" -eq 0 ] \
  || bar_fail "BAR A S7 control failed: the cookie-less GET /login probe could not REACH the BFF with the store UP (curl exit $A_S7_FRESH_UP_RC, http_code '$A_S7_FRESH_UP')"
case "$A_S7_FRESH_UP" in
  30[0-9]) ;;
  *) bar_fail "BAR A S7 control failed: a cookie-less GET /login returned HTTP $A_S7_FRESH_UP with the store UP (expected a 3xx redirect to Keycloak). The probe is not reaching the login route, so the 503 it is about to demand would prove nothing." ;;
esac
kubectl -n "$NS" scale deploy/redis-bff --replicas=0 >/dev/null
kubectl -n "$NS" wait --for=delete pod -l app=redis-bff --timeout=60s >/dev/null 2>&1 || sleep 10
A_S7_DOWN="$(bff_status "$A_S7_C")"
[ "$A_S7_DOWN" != "200" ] \
  || bar_fail "BAR A S7 the session STILL served 200 with the store DOWN — the BFF continued from memory (FORBIDDEN)"
[ "$A_S7_DOWN" = "503" ] \
  || bar_fail "BAR A S7 the store outage did not fail closed with the governed 503 (got $A_S7_DOWN)"

# (1) THE DIRECT, DRIVER-FREE PROBE — a cookie-less GET /login must be EXACTLY 503.
set +e
A_S7_FRESH_DOWN="$(bff_fresh_login_status)"
A_S7_FRESH_DOWN_RC=$?
set -e
[ "$A_S7_FRESH_DOWN_RC" -eq 0 ] \
  || bar_fail "BAR A S7 the cookie-less GET /login probe could not REACH the BFF with the store down (curl exit $A_S7_FRESH_DOWN_RC, http_code '$A_S7_FRESH_DOWN'). curl reports 000 when the connection never happened, and a tool that could not run has OBSERVED NOTHING — a failed probe may never be read as 'the BFF refused'."
[ "$A_S7_FRESH_DOWN" = "503" ] \
  || bar_fail "BAR A S7 a FRESH cookie-less GET /login returned HTTP $A_S7_FRESH_DOWN with the session store DOWN (expected EXACTLY 503). A 3xx means the BFF minted a pre-auth login state with no store to mint it into — it continued from memory (FORBIDDEN). Anything else is not the governed fail-closed refusal."

# (2) THE BROWSER LEG — a real fresh login must report an OBSERVED BFF refusal.
A_OUTAGE="$(drive_login_capture zara)"
A_OUTAGE_OUTCOME="$(jq_get outcome "$A_OUTAGE")"
A_OUTAGE_DETAIL="$(jq_get detail "$A_OUTAGE")"
A_OUTAGE_STATUS="$(jq_get http_status "$A_OUTAGE")"
[ "$A_OUTAGE_OUTCOME" = "refused" ] \
  || bar_fail "BAR A S7 the during-outage BROWSER login did not report an OBSERVED BFF refusal (outcome=\"$A_OUTAGE_OUTCOME\", expected \"refused\"). outcome=authenticated means the BFF AUTHENTICATED a fresh login with Redis DOWN — it fell back to memory (FORBIDDEN). outcome=driver_error means THE PROOF HARNESS BROKE (a Chromium crash, a selector typo, a uv failure, an unparseable or partial driver result) — a failed drive is NOT an observation of a refusal and may never award this leg. driver detail: $A_OUTAGE_DETAIL"
[ "$A_OUTAGE_STATUS" = "503" ] \
  || bar_fail "BAR A S7 the browser login was refused by the BFF with HTTP $A_OUTAGE_STATUS, not the governed 503. The refusal was OBSERVED, but it is not the governed store-outage refusal the spec names."
kubectl -n "$NS" scale deploy/redis-bff --replicas=1 >/dev/null
kubectl -n "$NS" rollout status deploy/redis-bff --timeout=120s \
  || bar_fail "BAR A S7 redis-bff did not recover after the outage test"
bff_pf_start
echo "  Bar A S7 OK: the live session's own cookie AND a cookie-less GET /login BOTH returned the EXACT governed 503 with the store destroyed (a direct HTTP observation — no browser in the loop); the real browser login reported an OBSERVED BFF refusal (outcome=refused http_status=$A_OUTAGE_STATUS), never a driver error; store recovered"
# The store has no persistence (`save ""`), so recovery deliberately WIPES every
# session — users re-authenticate. The legs below each mint their own fresh login.

# S6 — concurrent refresh has EXACTLY ONE winner, ACROSS REPLICAS, and preserves
# the rotated token.
#
# Two things make this liveable rather than unit-only. (1) The BFF refreshes when
# the access token is within its 60s margin (auth/service.py:69), so a token minted
# with a ~70s lifespan puts a brand-new session immediately inside that margin —
# no 15-minute wait. (2) Keycloak's OWN event log counts every refresh_token grant
# it served, which is an INDEPENDENT observer: if the single-flight broke and both
# replicas refreshed, Keycloak records two. A "we refreshed once" line from the
# harness itself would be self-report, not proof — the same reason the probe ledger
# (not the kernel) is what counts executions in Bar D.
kc_set_access_token_lifespan 70
bff_served_by "A.S6-login"
A_S6_LOGIN="$(drive_login sara)"
A_S6_C="$(jq_get post_auth_session_id "$A_S6_LOGIN")"
[ -n "$A_S6_C" ] || bar_fail "BAR A S6 could not establish a session for the refresh race"
bff_resolve_pods
A_S6_POD_A="$BFF_POD_1"
A_S6_POD_B="$BFF_POD_2"
[ -n "$A_S6_POD_A" ] && [ -n "$A_S6_POD_B" ] && [ "$A_S6_POD_A" != "$A_S6_POD_B" ] \
  || bar_fail "BAR A S6 expected 2 DISTINCT BFF replicas to race (got '$A_S6_POD_A' / '$A_S6_POD_B')"
bff_pf_dual "$A_S6_POD_A" "$A_S6_POD_B"
# The burst is split deliberately across BOTH replicas — both serve it, so both are
# recorded as serving this step.
bff_served_by "A.S6-burst" "$A_S6_POD_A"
bff_served_by "A.S6-burst" "$A_S6_POD_B"
# Read the counters, then sit until the token is INSIDE the refresh margin (70s
# lifespan, 60s margin -> ~12s), then fire the burst.
A_S6_BEFORE="$(kc_refresh_event_count)"
A_S6_OK_BEFORE="$(printf '%s' "$A_S6_BEFORE" | cut -d' ' -f1)"
A_S6_ERR_BEFORE="$(printf '%s' "$A_S6_BEFORE" | cut -d' ' -f2)"
sleep 15
# 8 concurrent requests, 4 to EACH replica. Every one must succeed: a loser of the
# refresh lock must WAIT for the winner and then serve on the rotated token — it
# must not error, and it must not clobber the winner's token with a stale one.
A_S6_OUT="$QC_TMP/s6-burst"
: > "$A_S6_OUT"
# Collect the burst PIDs and wait on THOSE only. A bare `wait` would also block on
# the long-lived port-forward children (PF_BFF / PF_BFF_B / PF_KC), which never
# exit — the proof would hang here forever.
A_S6_PIDS=""
for _i in 1 2 3 4; do
  ( printf '%s\n' "$(bff_status "$A_S6_C" "$BFF_POD_A_URL/")" >> "$A_S6_OUT" ) &
  A_S6_PIDS="$A_S6_PIDS $!"
  ( printf '%s\n' "$(bff_status "$A_S6_C" "$BFF_POD_B_URL/")" >> "$A_S6_OUT" ) &
  A_S6_PIDS="$A_S6_PIDS $!"
done
# shellcheck disable=SC2086  # deliberate word-splitting: these are separate PIDs
wait $A_S6_PIDS
A_S6_NON200="$(grep -cv '^200$' "$A_S6_OUT" || true)"
[ "$(wc -l < "$A_S6_OUT" | tr -d ' ')" = "8" ] \
  || bar_fail "BAR A S6 the concurrent burst did not produce 8 results (got $(wc -l < "$A_S6_OUT" | tr -d ' '))"
[ "$A_S6_NON200" = "0" ] \
  || bar_fail "BAR A S6 $A_S6_NON200 of 8 concurrent cross-replica requests did NOT return 200 — a refresh loser errored instead of riding the winner's rotated token"
sleep 3
A_S6_AFTER="$(kc_refresh_event_count)"
A_S6_OK_AFTER="$(printf '%s' "$A_S6_AFTER" | cut -d' ' -f1)"
A_S6_ERR_AFTER="$(printf '%s' "$A_S6_AFTER" | cut -d' ' -f2)"
A_S6_REFRESHES=$((A_S6_OK_AFTER - A_S6_OK_BEFORE))
A_S6_ERRS=$((A_S6_ERR_AFTER - A_S6_ERR_BEFORE))
[ "$A_S6_REFRESHES" = "1" ] \
  || bar_fail "BAR A S6 Keycloak served $A_S6_REFRESHES refresh_token grants for the burst (expected EXACTLY 1) — the cross-replica single-flight did not hold"
[ "$A_S6_ERRS" = "0" ] \
  || bar_fail "BAR A S6 Keycloak recorded $A_S6_ERRS REFRESH_TOKEN_ERROR events — a replica reused a spent refresh token (the rotated token was not preserved)"
# The session must still be usable on the rotated token.
[ "$(jq_get authenticated "$(drive_replay_cookie "$A_S6_C")")" = "true" ] \
  || bar_fail "BAR A S6 the session died after the refresh race — the rotated token was not preserved"
bff_pf_dual_stop
kc_set_access_token_lifespan 900
echo "  Bar A S6 OK: 8 concurrent requests across BOTH replicas -> Keycloak served EXACTLY 1 refresh (0 reuse errors); every request 200; the rotated token survived"

# S10 — an unknown session-record schema version REFUSES (fail closed).
#
# A CONTROLLED SINGLE-VARIABLE EXPERIMENT. The runner mints the BFF's session-HMAC
# secret, so it can compute the exact Redis key for one specific session
# (sess:HMAC(secret, session_id), auth/redis_store.py:169) rather than scanning and
# guessing. It proves the cookie authenticates, changes NOTHING about that record
# except its `v` field (auth/session_models.py:171 writes v=1; from_wire refuses any
# other value), and proves the very same cookie now fails closed. Same key, same
# TTL, same bytes otherwise — the ONLY difference is the schema version, so the
# refusal cannot be explained by anything else.
bff_served_by "A.S10"
A_S10_LOGIN="$(drive_login zara)"
A_S10_C="$(jq_get post_auth_session_id "$A_S10_LOGIN")"
[ -n "$A_S10_C" ] || bar_fail "BAR A S10 could not establish a throwaway session"
[ "$(jq_get authenticated "$(drive_replay_cookie "$A_S10_C")")" = "true" ] \
  || bar_fail "BAR A S10 control failed: the throwaway session does not authenticate BEFORE the mutation"
A_S10_KEY="$(session_redis_key "$A_S10_C")"
# redis-cli emits RAW output when its stdout is a pipe, so this is the stored JSON
# verbatim (a missing key yields an empty string). Deliberately NOT --no-raw: that
# re-quotes the value with C-style escapes, which are not guaranteed JSON-parseable.
# The KEY on argv is fine (a derived HMAC digest — an address, not a credential);
# the VALUE arrives on stdout, never on any argument vector.
A_S10_REC="$(redis_bff_cli GET "$A_S10_KEY" 2>/dev/null || true)"
[ -n "$A_S10_REC" ] \
  || bar_fail "BAR A S10 could not read the live session record at $A_S10_KEY (the HMAC key derivation or the redis-cli path is wrong — the leg cannot mutate what it cannot address)"

# THE COPY THE RUNNER HOLDS MUST BE THE BYTES REDIS HOLDS (review 2026-07-12 round 5, F3).
# `A_S10_REC="$(redis_bff_cli GET …)"` reads through a command substitution, which strips
# TRAILING NEWLINES. If the stored value ever carried one, the copy in this shell would
# already differ from the stored bytes and the "only `v` changed" claim would be false
# before the mutation had even run. So it is PROVEN, not assumed: redis hashes its OWN
# stored bytes with its OWN sha1 and the runner hashes its copy. A digest is not a
# credential (it is non-reversible), so it may be compared and printed freely.
_S10_SHA1_LUA='local v = redis.call("GET", KEYS[1])
if not v then return redis.error_reply("s10_key_gone") end
return redis.sha1hex(v)'
A_S10_STORED_SHA1="$(redis_bff_cli EVAL "$_S10_SHA1_LUA" 1 "$A_S10_KEY" 2>&1 | tr -d '[:space:]')"
A_S10_LOCAL_SHA1="$(printf '%s' "$A_S10_REC" | python3 -c '
import hashlib, sys
print(hashlib.sha1(sys.stdin.buffer.read()).hexdigest())
')"
case "$A_S10_STORED_SHA1" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
  *) bar_fail "BAR A S10 could not read redis's OWN digest of the stored record — redis said '$A_S10_STORED_SHA1'. Without it the runner cannot prove the copy it is about to mutate is the record redis actually holds, and the single-variable claim rests on exactly that." ;;
esac
[ "$A_S10_STORED_SHA1" = "$A_S10_LOCAL_SHA1" ] \
  || bar_fail "BAR A S10 the record this shell read is NOT byte-identical to the record redis stores (redis sha1=$A_S10_STORED_SHA1, local sha1=$A_S10_LOCAL_SHA1). Something mangled the bytes in transit — most likely a trailing newline stripped by the command substitution. The 'same bytes except v' claim would be FALSE, so the leg refuses rather than making it."

# THE MUTATION IS A BOUNDED, VERIFIED, EXACT BYTE REPLACEMENT (round 5, F3).
#
# The pre-review rewrite round-tripped the record through Python's JSON encoder with
# COMPACT separators (`separators=(",", ":")`), while the harness stores it with json.dumps'
# DEFAULT separators (`", "` / `": "`, redis_store.py `_dumps`). So EVERY SEPARATOR BYTE IN
# THE RECORD CHANGED, not just `v` — while the comment and the success line both claimed
# "same bytes". The conclusion still held (the semantic fields were unchanged), but the
# CLAIM WAS FALSE, and this document's whole value is that its claims are exactly true.
# Worse, the round trip was a HIDDEN SECOND VARIABLE: the day `to_wire()` grows a field
# whose json.loads/json.dumps round trip is not byte-faithful (key ordering, a numeric
# repr, non-ASCII escaping), "only `v` changed" silently becomes false in a way that DOES
# matter, and nothing would have caught it.
#
# So the record is NEVER re-serialised. The version VALUE's exact byte span is located,
# required to be UNIQUE (a blind str.replace could match inside another value; zero or
# more than one candidate is a hard refusal), and only those bytes are replaced. The
# result is then VERIFIED before it is used — parses / v == 999 / every other key and
# value identical IN ORDER / the bytes outside the replaced span byte-for-byte unchanged.
# Nothing about the harness's separator style is assumed: the token is DERIVED from the
# record actually read, and if the serializer ever changes this breaks LOUD.
_S10_MUTATE_PY='
import json, re, sys

raw = sys.stdin.buffer.read()
try:
    original = json.loads(raw)
except ValueError as exc:
    raise SystemExit("s10_record_unparseable: %s" % (exc,))
if not isinstance(original, dict):
    raise SystemExit("s10_record_is_not_a_json_object")
if original.get("v") != 1:
    raise SystemExit("s10_unexpected_stored_schema_version: %r" % (original.get("v"),))

# The version VALUE, in whatever separator style the record was actually written in. The
# negative lookahead keeps a nested "v": 10 / 1.5 from being mistaken for a bare 1.
token = re.compile(rb"(\"v\"\s*:\s*)(1)(?![0-9.eE])")
spans = [m.span(2) for m in token.finditer(raw)]
if len(spans) != 1:
    raise SystemExit(
        "s10_version_token_not_unique: %d candidate spans in the stored record (need "
        "exactly 1). A blind replacement could have hit a value that merely LOOKS like "
        "the version field." % (len(spans),)
    )
start, end = spans[0]
if raw[start:end] != b"1":
    raise SystemExit("s10_version_span_derivation_wrong")

mutated = raw[:start] + b"999" + raw[end:]

# VERIFY BEFORE USE — byte level AND semantic level. Any failure is a loud refusal.
if mutated[:start] != raw[:start] or mutated[start + 3:] != raw[end:]:
    raise SystemExit("s10_bytes_changed_outside_the_version_span")
try:
    check = json.loads(mutated)
except ValueError as exc:
    raise SystemExit("s10_mutated_record_unparseable: %s" % (exc,))
if check.get("v") != 999:
    raise SystemExit("s10_mutated_version_wrong: %r" % (check.get("v"),))
if [(k, val) for k, val in check.items() if k != "v"] != [
    (k, val) for k, val in original.items() if k != "v"
]:
    raise SystemExit("s10_a_non_version_field_changed")

sys.stdout.buffer.write(mutated)
'
set +e
A_S10_MUT="$(printf '%s' "$A_S10_REC" | python3 -c "$_S10_MUTATE_PY" 2>"$QC_TMP/s10-mutate-err")"
A_S10_REWRITE_RC=$?
set -e
[ "$A_S10_REWRITE_RC" -eq 0 ] && [ -n "$A_S10_MUT" ] \
  || bar_fail "BAR A S10 the version-only byte replacement REFUSED (exit $A_S10_REWRITE_RC): $(head -c 400 "$QC_TMP/s10-mutate-err" 2>/dev/null). The leg will not proceed on a record it cannot mutate in EXACTLY one place: a rewrite that changed anything besides the version bytes would make this a multi-variable experiment, and the refusal it goes on to observe would no longer be attributable to the schema version."

# THE REWRITE IS ATOMIC AND EXPIRY-PRESERVING (review 2026-07-12 round 4, F4).
#
# S10 is billed as a CONTROLLED SINGLE-VARIABLE experiment: same key, same bytes, same
# deadline — only `v` changes — so the refusal cannot be explained by anything else. The
# "same bytes" half of that sentence is now TRUE rather than aspirational: the record is
# never re-serialised, only the version value's verified byte span is replaced (F3 above),
# and the copy that was mutated was proven byte-identical to redis's own stored bytes.
# This block is what makes the "same deadline" half true.
#
# The pre-review write did not deliver that, and its comment claimed the opposite. It
# read `PTTL` at instant T_r, did client-side work (a python3 spawn + a JSON mutation),
# then wrote `PSETEX <key> <that PTTL> <value>` at instant T_w — so the NEW deadline
# was T_w + PTTL while the ORIGINAL was T_r + PTTL. The record's life was silently
# EXTENDED by (T_w - T_r). Measured live: PTTL=4999, wait 1s, rewrite -> 4996 instead
# of ~3999. The leg was changing TWO variables — the schema version AND the expiry.
#
# The fix reads the TTL and writes the new value INSIDE ONE server-side evaluation:
# `SET … KEEPTTL` retains the existing deadline EXACTLY, so there is no client-side
# window to extend. The live-record PRECONDITION (a session key MUST carry a positive
# TTL; -1 = no expiry, -2 = key gone — both real failures) is evaluated INSIDE the
# script too, so it cannot be raced either.
#
# The script RETURNS the preserved TTL in milliseconds. That return value is the
# success signal: redis-cli's exit code is deliberately NOT relied on (its behaviour on
# a Lua `error_reply` varies by version), so instead the runner requires a POSITIVE
# INTEGER back. A Lua refusal ("(error) s10_no_expiry"), a transport failure, an ACL
# denial — every one of them surfaces as non-numeric text and fails loud.
_S10_REWRITE_LUA='local ttl = redis.call("PTTL", KEYS[1])
if ttl == -2 then return redis.error_reply("s10_key_gone") end
if ttl == -1 then return redis.error_reply("s10_no_expiry") end
if ttl <= 0 then return redis.error_reply("s10_nonpositive_ttl") end
redis.call("SET", KEYS[1], ARGV[1], "KEEPTTL")
return ttl'
# The RECORD (which carries the OAuth access + refresh + id tokens) rides STDIN into
# the pod and into `redis-cli -x`, which takes the command's LAST argument from stdin.
# For `EVAL <script> 1 <key>` that lands it in ARGV[1] — so the record appears on
# NEITHER the host's `kubectl` argv NOR the pod's `redis-cli` argv. The SCRIPT is code,
# not a credential, and the KEY is a derived HMAC digest (an address, not a
# credential): both may stay on argv.
set +e
A_S10_PTTL="$(printf '%s' "$A_S10_MUT" \
  | redis_bff_cli_stdin EVAL "$_S10_REWRITE_LUA" 1 "$A_S10_KEY" 2>&1 \
  | tr -d '[:space:]')"
set -e
case "$A_S10_PTTL" in
  ''|*[!0-9]*)
    bar_fail "BAR A S10 the atomic version-rewrite did not return a preserved positive TTL — redis said '$A_S10_PTTL'. (s10_key_gone = the key vanished mid-experiment; s10_no_expiry = the record carries NO expiry, so it is not a live session record; anything else is a transport or ACL failure.) A live session record MUST carry a positive idle TTL, or the leg cannot rewrite it without changing its lifetime — which would make this a two-variable experiment and prove nothing." ;;
esac
[ "$(jq_get authenticated "$(drive_replay_cookie "$A_S10_C")")" = "false" ] \
  || bar_fail "BAR A S10 the session STILL authenticated with an UNKNOWN schema version (v=999) — the record reader did not fail closed"
echo "  Bar A S10 OK: same cookie, same key, same deadline (retained EXACTLY by an atomic server-side SET…KEEPTTL — ${A_S10_PTTL}ms still to run), and the stored record is BYTE-IDENTICAL apart from the 1 byte that encoded the schema version (verified: the read copy hashed to redis's own sha1 $A_S10_STORED_SHA1; the version value's byte span was unique; every other key, value and separator byte is unchanged). The ONLY difference is the schema version (1 -> 999) -> the BFF fails closed"

# S4 — idle and absolute TTLs behave INDEPENDENTLY.
#
# Unobservable at the committed proof TTLs (idle 900s / absolute 28800s) — proving
# them would mean sleeping for eight hours, which is why the pre-review runner
# ducked S4 into the store conformance suite. The honest lever is the BFF's OWN
# operator configuration surface (the same env vars a bank sets): shrink the TTLs,
# prove BOTH legs against the real Redis-backed store, restore. Run LAST in Bar A
# so its two rollouts disturb no earlier leg.
#   leg 1 — an IDLE session dies at the idle TTL while the absolute TTL has NOT
#           elapsed  => idle is enforced independently of the absolute window.
#   leg 2 — an ACTIVE session still dies at the absolute TTL => absolute is
#           enforced independently of activity.
#
# LEG 2's WHOLE ARGUMENT IS ARITHMETIC (review 2026-07-12, F2). The pre-review leg
# touched the session every 15s and then probed at ~165s — but it never checked that
# the touches LANDED (bff_touch ended in `|| true`), and it kept touching PAST the
# absolute deadline. If the touches had silently stopped landing (a dead
# port-forward, a rolled pod, a rejected cookie), the session would have died of
# IDLE expiry at ~45s and the final `authenticated=false` would have been credited
# to the ABSOLUTE TTL: the leg would have "proven" absolute expiry using idle
# expiry. Two things fix it:
#   (a) every touch must return 200 (bff_touch now bar_fails otherwise), and
#   (b) IDLE EXPIRY IS ARITHMETICALLY EXCLUDED as the cause of death — the last
#       SUCCESSFUL touch is still INSIDE the absolute window, the runner then STOPS
#       touching and crosses the absolute boundary, and the gap between that last
#       touch and the final probe is STRICTLY LESS than the idle TTL. So at the
#       moment of the probe the session had been idle for less than the idle TTL:
#       the only clock that can have killed it is the absolute one.
# _s4_assert_timing_plan re-derives (b) from the constants and fails loud if a
# future TTL/cadence edit ever breaks it — a silent regression here would turn the
# bar back into a false positive, which is precisely the defect being fixed.
#
# The IDLE TTL doubles as the leg-2 budget for "stop touching -> cross the absolute
# boundary -> drive a browser probe". A browser launch costs seconds and is not
# perfectly predictable, so the idle TTL is set at 60s (not the minimum that would
# satisfy the arithmetic) to leave ~20-30s of headroom against a slow Chromium
# start. Too tight and a slow launch trips the realized-exclusion guard below — a
# SAFE failure (it fails loud, never falsely passes) but a needless one on a
# 40-minute live run.
# WHICH SIDE OF EACH INTERVAL WE MEASURE (review 2026-07-12 round 4, F3).
#
# Every bound below is taken on the CONSERVATIVE side — the side that can only make an
# assertion HARDER to satisfy. Getting the side wrong does not weaken the leg a
# little; it destroys it, because a bound taken on the wrong side proves nothing at
# all while still LOOKING like arithmetic. Concretely:
#
#   * to EXCLUDE idle expiry we need an UPPER bound on how long the session was idle.
#     The BFF refreshes `last_seen_at` while it PROCESSES the touch — i.e. at some
#     instant >= the moment the request was SENT. So (probe_done - touch_SENT) is an
#     upper bound; (probe_done - touch_RESPONDED) is a LOWER bound, and asserting a
#     lower bound is below the TTL says nothing about the real interval. The
#     pre-review leg stamped the touch AFTER the response and was therefore unsound.
#     It is now stamped BEFORE the request leaves, so a SLOW touch response only makes
#     the computed interval GROW — it fails safe.
#
#   * to EXCLUDE absolute expiry we need an UPPER bound on the session's age. The
#     session is created DURING the login, so created_at >= the instant just BEFORE
#     the login started, and (probe_done - pre_login) is an upper bound.
#
#   * to ESTABLISH that absolute expiry HAS elapsed (leg 2's positive claim) we need a
#     LOWER bound on the age — and there `_S4_T0`, stamped AFTER the login, is the
#     conservative choice: it UNDERSTATES the age, so "measured > TTL" implies
#     "true > TTL". Same variable, opposite direction, both safe. See the notes at the
#     realized checks.
#
# CLOCK DOMAIN. Every instant here is `date +%s` on the RUNNER HOST. The session
# record's own created_at / last_seen_at live in the BFF POD's clock domain, and any
# interval spanning the two is silently corrupted by clock skew — so the leg
# deliberately does NOT read them, and bounds each interval entirely inside one clock
# domain using request-start / response-end instants it can observe directly.
_S4_IDLE_TTL_S=60           # the shrunken idle TTL
_S4_ABSOLUTE_TTL_S=150      # the shrunken absolute TTL
_S4_LEG1_SLEEP_S=75         # leg 1: idle < sleep < absolute
_S4_TOUCH_EVERY_S=15        # leg 2 cadence: must be < idle, or the loop idles out
_S4_MID_CHECK_S=120         # leg 2: the "still alive at 2x the idle TTL" checkpoint
_S4_LAST_TOUCH_S=135        # leg 2: the LAST touch — still inside the absolute window
_S4_FINAL_PROBE_S=160       # leg 2: the probe — past absolute, and < idle after the last touch
# The browser costs the two legs pay INSIDE a TTL window. A Chromium launch is seconds
# and is not perfectly predictable, so the plan reserves a budget for it and the guard
# below proves the constants still satisfy the exclusions WITH that budget spent. The
# realized instants are re-checked at run time regardless — the budget only decides
# whether a plan is FEASIBLE, never whether a run was VALID.
_S4_LEG1_BROWSER_BUDGET_S=60  # leg 1: login + control probe + final probe
_S4_PROBE_BUDGET_S=30         # leg 2: the final probe's own duration (it counts against idle)

_s4_assert_timing_plan() {
  # leg 1 — the idle death must be unambiguous: past the idle TTL, well short of absolute.
  { [ "$_S4_IDLE_TTL_S" -lt "$_S4_LEG1_SLEEP_S" ] && [ "$_S4_LEG1_SLEEP_S" -lt "$_S4_ABSOLUTE_TTL_S" ]; } \
    || bar_fail "BAR A S4 timing plan broken (leg 1): need idle($_S4_IDLE_TTL_S) < sleep($_S4_LEG1_SLEEP_S) < absolute($_S4_ABSOLUTE_TTL_S), or the leg-1 death cannot be attributed to the IDLE TTL"
  # leg 1 — THE ABSOLUTE EXCLUSION. The WHOLE leg (login + control + sleep + final
  # probe) must fit INSIDE the absolute window, or the absolute TTL may have elapsed by
  # the probe and an ABSOLUTE death would be credited to the IDLE clock this leg
  # claims. The pre-review leg checked nothing of the sort.
  [ "$((_S4_LEG1_SLEEP_S + _S4_LEG1_BROWSER_BUDGET_S))" -lt "$_S4_ABSOLUTE_TTL_S" ] \
    || bar_fail "BAR A S4 timing plan broken (leg 1): the sleep ($_S4_LEG1_SLEEP_S s) plus the browser budget ($_S4_LEG1_BROWSER_BUDGET_S s for the login + control + probe drives) is not STRICTLY INSIDE the absolute window ($_S4_ABSOLUTE_TTL_S s) — the session could die of ABSOLUTE expiry before the probe, and the leg would credit that death to the IDLE TTL"
  # leg 2 — the touch cadence must keep the session inside the idle window.
  [ "$_S4_TOUCH_EVERY_S" -lt "$_S4_IDLE_TTL_S" ] \
    || bar_fail "BAR A S4 timing plan broken (leg 2): the touch cadence ($_S4_TOUCH_EVERY_S s) is not shorter than the idle TTL ($_S4_IDLE_TTL_S s) — the 'continuously active' session would idle out mid-loop"
  # leg 2 — the mid-check must be past the idle TTL (else it proves nothing) and
  # before the last touch (else it is not a MID check).
  { [ "$_S4_MID_CHECK_S" -gt "$_S4_IDLE_TTL_S" ] && [ "$_S4_MID_CHECK_S" -lt "$_S4_LAST_TOUCH_S" ]; } \
    || bar_fail "BAR A S4 timing plan broken (leg 2): the mid-check ($_S4_MID_CHECK_S s) must fall after the idle TTL ($_S4_IDLE_TTL_S s) and before the last touch ($_S4_LAST_TOUCH_S s)"
  # leg 2 — THE EXCLUSION. These three are what make absolute the only possible killer.
  [ "$_S4_LAST_TOUCH_S" -lt "$_S4_ABSOLUTE_TTL_S" ] \
    || bar_fail "BAR A S4 timing plan broken (leg 2): the last touch ($_S4_LAST_TOUCH_S s) is not INSIDE the absolute window ($_S4_ABSOLUTE_TTL_S s) — a touch after the deadline cannot succeed, and the leg needs the session provably active right up to it"
  [ "$_S4_FINAL_PROBE_S" -gt "$_S4_ABSOLUTE_TTL_S" ] \
    || bar_fail "BAR A S4 timing plan broken (leg 2): the final probe ($_S4_FINAL_PROBE_S s) does not cross the absolute window ($_S4_ABSOLUTE_TTL_S s) — there would be nothing to prove"
  [ "$((_S4_FINAL_PROBE_S - _S4_LAST_TOUCH_S))" -lt "$_S4_IDLE_TTL_S" ] \
    || bar_fail "BAR A S4 timing plan broken (leg 2): the gap between the last touch ($_S4_LAST_TOUCH_S s) and the final probe ($_S4_FINAL_PROBE_S s) is not STRICTLY LESS than the idle TTL ($_S4_IDLE_TTL_S s) — IDLE expiry would explain the death just as well as absolute expiry, and the leg would prove nothing"
  # leg 2 — ... and the PROBE'S OWN DURATION counts against that idle window too. The
  # realized interval is bounded by (probe_DONE - touch_SENT), not by the planned
  # (probe_start - touch_start), so a plan that only just fits on paper fails the
  # realized check the moment the browser takes a few seconds. Prove the headroom here.
  [ "$((_S4_FINAL_PROBE_S + _S4_PROBE_BUDGET_S - _S4_LAST_TOUCH_S))" -lt "$_S4_IDLE_TTL_S" ] \
    || bar_fail "BAR A S4 timing plan broken (leg 2): the last touch ($_S4_LAST_TOUCH_S s) to the END of the final probe (${_S4_FINAL_PROBE_S}s + a ${_S4_PROBE_BUDGET_S}s browser budget) is not STRICTLY LESS than the idle TTL ($_S4_IDLE_TTL_S s) — the session would be idle for longer than the idle TTL by the time the probe lands, so IDLE expiry would explain the death just as well as ABSOLUTE expiry"
}
_s4_assert_timing_plan

# Wall-clock, not a count of sleeps: a browser drive costs SECONDS, so a
# sleep-counter drifts away from reality and the exclusion arithmetic above would be
# checked against a fiction. Every instant below is measured against the login.
_S4_T0=0
_s4_elapsed() { echo $(( $(date +%s) - _S4_T0 )); }
_s4_sleep_until() {   # sleep until `elapsed >= $1`
  local target="$1" delta
  delta=$(( target - $(_s4_elapsed) ))
  [ "$delta" -gt 0 ] && sleep "$delta"
  return 0
}

bff_set_ttls "$_S4_IDLE_TTL_S" "$_S4_ABSOLUTE_TTL_S"
bff_served_by "A.S4-leg1"
# THE ABSOLUTE-EXCLUSION BOUND (review 2026-07-12 round 4, F3b). Leg 1 claims "the
# session died of IDLE while the ABSOLUTE window was still open" — but the pre-review
# leg never checked the second half of that sentence against the wall clock at all. It
# slept 75s under a 150s absolute TTL and assumed the rest of the leg was free; in
# reality it also pays for a Chromium launch + an OIDC round trip (the login) and TWO
# more browser drives (the control and the probe). A slow run pushes the session's true
# absolute age past 150s, at which point an ABSOLUTE death is credited to the IDLE
# clock and the leg proves the opposite of what it claims.
#
# Stamp the instant BEFORE the login: the session is minted DURING it, so
# created_at >= this, and (probe_done - pre_login) is an UPPER BOUND on the session's
# true absolute age at the probe. If that upper bound is BELOW the absolute TTL, the
# absolute window provably had NOT elapsed — which leaves IDLE as the only clock that
# can have killed it. Stamping AFTER the login would understate the age and prove
# nothing.
_S4_L1_PRE_LOGIN_AT="$(date +%s)"
A_S4A="$(drive_login sara)"
A_S4A_C="$(jq_get post_auth_session_id "$A_S4A")"
[ -n "$A_S4A_C" ] || bar_fail "BAR A S4 leg 1 could not establish a session"
[ "$(jq_get authenticated "$(drive_replay_cookie "$A_S4A_C")")" = "true" ] \
  || bar_fail "BAR A S4 leg 1 control failed: the fresh session does not authenticate"
sleep "$_S4_LEG1_SLEEP_S"      # > the idle TTL, and far short of the absolute one
A_S4A_FINAL="$(drive_replay_cookie "$A_S4A_C")"
_S4_L1_PROBE_DONE_AT="$(date +%s)"
_S4_L1_ABS_AGE_MAX=$(( _S4_L1_PROBE_DONE_AT - _S4_L1_PRE_LOGIN_AT ))
# The exclusion is asserted BEFORE the observation it licenses: if the absolute window
# may have elapsed, the `authenticated=false` below is UNINTERPRETABLE — it would be
# equally well explained by the very clock this leg is trying to rule out.
[ "$_S4_L1_ABS_AGE_MAX" -lt "$_S4_ABSOLUTE_TTL_S" ] \
  || bar_fail "BAR A S4 leg 1 the session's absolute age at the probe was AT MOST ${_S4_L1_ABS_AGE_MAX}s, which is NOT below the ${_S4_ABSOLUTE_TTL_S}s absolute TTL — so the ABSOLUTE window may have elapsed and an absolute death would be indistinguishable from the idle death this leg claims. The run drifted: the login + control + probe browser drives overran the ${_S4_LEG1_BROWSER_BUDGET_S}s budget."
[ "$(jq_get authenticated "$A_S4A_FINAL")" = "false" ] \
  || bar_fail "BAR A S4 leg 1 an IDLE session survived past the ${_S4_IDLE_TTL_S}s idle TTL (idle TTL not enforced)"
echo "  Bar A S4 leg 1 OK: an idle session died at the ${_S4_IDLE_TTL_S}s idle TTL while its absolute age was AT MOST ${_S4_L1_ABS_AGE_MAX}s — strictly inside the ${_S4_ABSOLUTE_TTL_S}s absolute window. ABSOLUTE expiry is arithmetically excluded, so the IDLE TTL is the only clock that can have killed it"

bff_served_by "A.S4-leg2"
A_S4B="$(drive_login sara)"
A_S4B_C="$(jq_get post_auth_session_id "$A_S4B")"
[ -n "$A_S4B_C" ] || bar_fail "BAR A S4 leg 2 could not establish a session"
# _S4_T0 is stamped AFTER the login, so it UNDERSTATES the session's absolute age
# (created_at <= T0). That is the CONSERVATIVE side for leg 2's positive claim
# — `A_S4_PROBE_AT > absolute` implies the TRUE age also exceeded it — so it is kept
# deliberately. It is the UNSAFE side for the "the last touch was still inside the
# absolute window" check further down; see the note there for what actually carries
# that claim.
_S4_T0="$(date +%s)"           # t=0 for leg 2: the session is alive as of now
A_S4_LAST_TOUCH_AT=-1
A_S4_MID_DONE=0
A_S4_NEXT="$_S4_TOUCH_EVERY_S"
while [ "$A_S4_NEXT" -le "$_S4_LAST_TOUCH_S" ]; do
  _s4_sleep_until "$A_S4_NEXT"
  # STAMP THE TOUCH BEFORE THE REQUEST LEAVES (review 2026-07-12 round 4, F3a).
  #
  # The idle interval this leg must bound is (probe_evaluation - last_seen_at). The BFF
  # refreshes `last_seen_at` while it PROCESSES the touch — at some instant >= the
  # moment the request was SENT. So:
  #   * (probe_done - touch_SENT)      is an UPPER bound on the true idle interval;
  #   * (probe_done - touch_RESPONDED) is a LOWER bound.
  # The pre-review leg stamped AFTER `bff_touch` returned and then asserted that its
  # LOWER bound was below the idle TTL — which does not constrain the true interval at
  # all. Stamping at SEND makes the computed interval an upper bound, so the assertion
  # is sound; and because SEND <= RESPONSE, a SLOW touch response can only make that
  # interval GROW. The leg fails safe under exactly the condition (a sluggish BFF) that
  # used to hide the flaw.
  A_S4_TOUCH_SENT_AT="$(_s4_elapsed)"
  bff_touch "$A_S4B_C"                     # keep it ACTIVE; bar_fails unless HTTP 200
  A_S4_LAST_TOUCH_AT="$A_S4_TOUCH_SENT_AT"
  if [ "$A_S4_MID_DONE" -eq 0 ] && [ "$A_S4_NEXT" -ge "$_S4_MID_CHECK_S" ]; then
    # The mid-flight checkpoint: still alive at 2x the idle TTL, deep inside the
    # absolute window — this is what proves the touching genuinely held idle off.
    [ "$(jq_get authenticated "$(drive_replay_cookie "$A_S4B_C")")" = "true" ] \
      || bar_fail "BAR A S4 leg 2 a CONTINUOUSLY ACTIVE session died at ~${A_S4_LAST_TOUCH_AT}s — past the ${_S4_IDLE_TTL_S}s idle TTL but well inside the ${_S4_ABSOLUTE_TTL_S}s absolute window: the idle TTL bit an active session, so the two TTLs are NOT independent"
    A_S4_MID_DONE=1
  fi
  A_S4_NEXT=$(( A_S4_NEXT + _S4_TOUCH_EVERY_S ))
done
[ "$A_S4_MID_DONE" -eq 1 ] \
  || bar_fail "BAR A S4 leg 2 the mid-flight liveness checkpoint never ran (touch loop mis-scheduled) — the leg cannot claim the touching held idle off"
[ "$A_S4_LAST_TOUCH_AT" -ge 0 ] \
  || bar_fail "BAR A S4 leg 2 no touch ever landed — the leg cannot claim the session was active"

# STOP TOUCHING. Cross the absolute boundary and probe. From here the session is
# idle — but for LESS than the idle TTL, which is what excludes idle expiry.
_s4_sleep_until "$_S4_FINAL_PROBE_S"
A_S4_PROBE_AT="$(_s4_elapsed)"
A_S4B_FINAL="$(drive_replay_cookie "$A_S4B_C")"
A_S4_PROBE_DONE_AT="$(_s4_elapsed)"
# THE REALIZED EXCLUSION — the same arithmetic as the plan, but over what ACTUALLY
# happened on the wall clock (a slow browser launch or a stalled rollout could have
# pushed the real instants past the plan). Each bound is taken on the side that can
# only make the assertion HARDER; the three differ, and the differences are the whole
# argument (review 2026-07-12 round 4, F3):
#
#   [1] the last touch is INSIDE the absolute window. `_S4_T0` is stamped after the
#       login, so this elapsed value UNDERSTATES the session's true age — the UNSAFE
#       direction for this particular claim. It is kept as a DRIFT DETECTOR, not as
#       the proof. What actually carries "the session was alive at the last touch" is
#       the touch's own HTTP 200: a dead session gets a 303 to /signin, and bff_touch
#       bar_fails on anything but 200. Do NOT "simplify" that 200 check away on the
#       grounds that this line covers it — it does not.
#
#   [2] the probe STARTED after the absolute deadline. `_S4_T0` understates the age
#       here too, which for THIS claim is the SAFE direction: true age >= measured, so
#       measured > TTL implies true > TTL. The absolute window provably elapsed.
#
#   [3] the probe FINISHED within the idle window measured from the touch's SEND
#       instant. Both ends are conservative: last_seen_at >= touch_sent, and the BFF's
#       idle evaluation happened no later than probe_done — so this is an UPPER bound
#       on the true idle interval, and being under the idle TTL genuinely excludes idle
#       expiry. (Pre-review this was measured from the touch's RESPONSE, which is a
#       LOWER bound and excluded nothing.)
[ "$A_S4_LAST_TOUCH_AT" -lt "$_S4_ABSOLUTE_TTL_S" ] \
  || bar_fail "BAR A S4 leg 2 the last successful touch was sent at ${A_S4_LAST_TOUCH_AT}s, at/after the ${_S4_ABSOLUTE_TTL_S}s absolute deadline — the run drifted and the leg's timing argument does not hold"
[ "$A_S4_PROBE_AT" -gt "$_S4_ABSOLUTE_TTL_S" ] \
  || bar_fail "BAR A S4 leg 2 the final probe started at ${A_S4_PROBE_AT}s, before the ${_S4_ABSOLUTE_TTL_S}s absolute deadline — nothing is being proven"
[ "$(( A_S4_PROBE_DONE_AT - A_S4_LAST_TOUCH_AT ))" -lt "$_S4_IDLE_TTL_S" ] \
  || bar_fail "BAR A S4 leg 2 the final probe finished ${A_S4_PROBE_DONE_AT}s in, i.e. at most $(( A_S4_PROBE_DONE_AT - A_S4_LAST_TOUCH_AT ))s after the last touch was SENT (${A_S4_LAST_TOUCH_AT}s) — that upper bound on the idle interval is NOT less than the ${_S4_IDLE_TTL_S}s idle TTL, so IDLE expiry explains the death just as well as absolute expiry and the leg proves nothing"
[ "$(jq_get authenticated "$A_S4B_FINAL")" = "false" ] \
  || bar_fail "BAR A S4 leg 2 the session survived past the ${_S4_ABSOLUTE_TTL_S}s ABSOLUTE TTL despite continuous activity (absolute TTL not enforced — a session could live forever by staying busy)"
bff_set_ttls 900 28800
echo "  Bar A S4 leg 2 OK: every touch landed (HTTP 200), the last one sent at ${A_S4_LAST_TOUCH_AT}s — inside the ${_S4_ABSOLUTE_TTL_S}s absolute window — and the session was still alive at the ${_S4_MID_CHECK_S}s checkpoint (2x the idle TTL); it then died by the ${A_S4_PROBE_AT}s probe, having been idle for AT MOST $(( A_S4_PROBE_DONE_AT - A_S4_LAST_TOUCH_AT ))s (< the ${_S4_IDLE_TTL_S}s idle TTL). Idle expiry is arithmetically excluded: the ABSOLUTE TTL killed it, and the two TTLs are independent"
echo "  Bar A S4/S6/S10 OK: all three proven LIVE on kind (no conformance-suite delegation)"
echo "PROOF M8.5-C (BAR A) PASS"

# ============================ BAR B — identity ====================================
# The ruled identity requirements. The browser login proves the human path; the
# negative space (wrong-audience / expired / malformed / unknown-key / real-ID-
# token substitution / the disabled grants) is driven DIRECTLY against Keycloak
# + AgentOS with the PKCE driver, because those are token-shape refusals the
# browser never exercises.
echo "==> BAR B — identity (real login + the token-refusal negative space)"

# binder_refusal_count <REASON> — how many times the reference binder has logged its
# value-free marker ("reference_binder.refused reason=<r>" — no token, no subject,
# no claim material) for this reason.
#
# The SAME fail-loud read discipline as bff_refusal_count (F2): the read goes through
# kubectl_capture and dies on any failure, and only `grep -c`'s documented exit-1
# ("zero matches") normalises to 0. It is the same bug twice, so it is the same fix
# twice — Bar B's expired-token leg is precisely the one a stale `token_expired`
# marker plus a failed pre-read would have handed a free pass.
binder_refusal_count() {
  local reason="$1" logs n rc
  set +e
  logs="$(kubectl_capture -n "$NS" logs "--since=$_REFUSAL_LOG_WINDOW" --tail=-1 deploy/rel-agentos)"
  rc=$?
  set -e
  [ "$rc" -eq 0 ] \
    || bar_fail "binder_refusal_count($reason) — the AgentOS log read FAILED (kubectl exit $rc): $(_kubectl_capture_err). REFUSING to report a count: a failed read is indistinguishable from a legitimate zero, and a fabricated zero pre-count would let Bar B's expired-token leg free-ride on a STALE token_expired marker planted by any earlier lapsed bearer in the window."
  set +e
  n="$(printf '%s\n' "$logs" | grep -c "reference_binder.refused reason=$reason")"
  rc=$?
  set -e
  case "$rc" in
    0) ;;                 # matches found
    1) n=0 ;;             # grep's documented "zero matches" exit — a REAL zero
    *) bar_fail "binder_refusal_count($reason): grep failed with exit $rc while counting a SUCCESSFUL log read — the count cannot be trusted and must not be reported as 0" ;;
  esac
  n="$(printf '%s' "$n" | tr -d '[:space:]')"
  case "$n" in
    ''|*[!0-9]*) bar_fail "binder_refusal_count($reason): non-numeric marker count '$n' (programming error)" ;;
  esac
  printf '%s' "$n"
}

# assert_binder_refusal <REASON> <PRE_COUNT> — prove THIS request made the reference
# binder fire the named gate. A bare 403 proves "refused"; this proves "refused for
# THIS reason, BY THIS REQUEST".
#
# A COUNT DELTA, not an existence check (F9 — see the note above bff_refusal_count).
# The concrete free-ride this closes: Bar B's expired-token leg deliberately sends a
# lapsed bearer, but ANY earlier request in the window that happened to carry a
# lapsed bearer would have planted a `token_expired` marker of its own — and an
# existence check would happily accept it even if the leg's own request never
# reached the kernel. PRE_COUNT is REQUIRED; a missing argument dies rather than
# degrading back to existence semantics.
assert_binder_refusal() {
  local reason="$1" pre="${2:-}" post
  [ -n "$pre" ] \
    || die "assert_binder_refusal($reason): missing the PRE_COUNT argument (programming error). Snapshot binder_refusal_count BEFORE the request: without a delta the assert degrades to 'a matching line exists somewhere in the window', which a marker from an earlier step satisfies."
  case "$pre" in
    ''|*[!0-9]*) die "assert_binder_refusal($reason): non-numeric PRE_COUNT '$pre' (programming error)" ;;
  esac
  post="$(binder_refusal_count "$reason")"
  [ "$post" -gt "$pre" ] \
    || bar_fail "BAR B expected THIS request to make the binder refuse with reason=$reason, but the marker count did NOT increase (before=$pre after=$post) — either the request never reached the kernel, or the WRONG gate fired. A pre-existing marker in the log window cannot stand in for it, so the case is not proven."
}

# --- the approver binds as actor_type=human -----------------------------------
# The queue GET requires only tool.approve.observe, so a 200 there does NOT prove
# human binding. Prove it via a HUMAN-GATED action: dana DENIES a throwaway
# request (deny is gated by RequireHumanActor at the kernel). ONE throwaway
# request serves both this and the manipulated-RBAC probe; it ends DENIED
# (terminal), so it never executes (ledger 0) and never enters Bar D.7's queue.
drive_login dana /approvals >/dev/null
drive_login amir >/dev/null   # amir was logged out by Bar A S3
B_THROW="$(mint_probe_request amir | cut -f1)"
[ -n "$B_THROW" ] || bar_fail "BAR B could not mint a throwaway approval request"

# Manipulated UI: amir (NO approve scope) crafts a grant POST (valid session +
# valid CSRF, the hidden button bypassed) against the REAL request. AgentOS RBAC
# must refuse with the kernel's governed 403 (scope), NOT a 404 — the pre-review
# probe targeted a nonexistent id and accepted 404, which proves nothing about
# RBAC. The BFF forwards amir's token and surfaces the kernel status verbatim.
B_MANIP="$(drive manipulated-post --path "/approvals/$B_THROW/grant" --field "reason=x" --state-file "$QC_TMP/session-amir.json")"
B_MANIP_STATUS="$(jq_get status "$B_MANIP")"
[ "$B_MANIP_STATUS" = "403" ] \
  || bar_fail "BAR B a manipulated under-scoped grant was NOT refused with the kernel's 403 (status $B_MANIP_STATUS — a 404 proves nothing about RBAC)"
echo "  Bar B OK: a manipulated grant by an under-scoped actor is refused by AgentOS RBAC (403)"

# dana denies the (still-pending) throwaway — a human-gated action succeeding
# proves dana bound actor_type=human.
B_HDENY="$(drive approvals-act --request-id "$B_THROW" --action deny --reason "bar-b human-binding probe" --state-file "$QC_TMP/session-dana.json")"
B_HDENY_STATUS="$(jq_get status "$B_HDENY")"
[ "$B_HDENY_STATUS" = "200" ] || [ "$B_HDENY_STATUS" = "303" ] \
  || bar_fail "BAR B dana could not perform the human-gated deny (status $B_HDENY_STATUS) — did she bind actor_type=human?"
[ "$(probe_ledger_count)" = "0" ] || bar_fail "BAR B the human-binding probe moved the ledger (must stay 0)"
echo "  Bar B OK: the approver (dana) binds actor_type=human — a human-gated deny succeeded; ledger 0"

# --- the locked grant profile's NEGATIVE SPACE --------------------------------
#
# THE ONLY UNGUARDED NEGATIVE ASSERTIONS IN THE RUNNER (review 2026-07-12 round 5, F2).
# Both legs read `[ "$CODE" != "200" ] || bar_fail`, which is fail-OPEN four ways over:
#
#   * it passes on 400, 401, 403, 404 (a TYPO'D ENDPOINT would "prove" the grant is
#     disabled), 500 (Keycloak itself broke), 502 …;
#   * `-o /dev/null` DISCARDED the body, so the OAuth error contract could not even be
#     inspected;
#   * `curl -s` with no exit-status check prints `000` on a TRANSPORT failure — a TLS
#     error, an unreachable Keycloak, a dead port-forward, a bad CA — and
#     `[ "000" != "200" ]` is TRUE. A TOTAL FAILURE TO CONTACT KEYCLOAK PASSED THE
#     ASSERTION. A tool that could not run has observed nothing;
#   * and even a LEGITIMATE 400 does not carry the claim. If direct-access grants were
#     ENABLED but dana's password were wrong, Keycloak returns 400 too — as
#     `invalid_grant`. The STATUS alone cannot tell "this client may not use this grant
#     type" apart from "your credentials were wrong".
#
# THE CONTRACT. RFC 6749 §5.2 defines `unauthorized_client` as "the authenticated client
# is not authorized to use this authorization grant type" — which is precisely and only
# the claim. Keycloak returns it for BOTH legs here, because the client secret we send is
# VALID: client authentication SUCCEEDS, and the GRANT-TYPE check is what fails. For the
# password grant Keycloak refuses on the grant type BEFORE it ever looks at the password,
# which is exactly what makes `unauthorized_client` the right discriminator.

# kc_token_probe <BODY_FILE> — POST the form body on STDIN to Keycloak's token endpoint.
# Writes the RESPONSE BODY to <BODY_FILE>, PRINTS the HTTP status, and RETURNS curl's own
# exit status (the kubectl_capture contract — the CALLER raises its own bar_fail, because
# one substitution level deeper bash 3.2 would swallow it and hand back a clean value).
# The body carries the client secret (and, on the password leg, a user password), so it
# rides STDIN via `-d @-`; only the URL and the flags are on argv.
kc_token_probe() {
  local body_file="$1" code rc
  [ -n "$body_file" ] || die "kc_token_probe: missing BODY_FILE (programming error)"
  : > "$body_file"
  set +e
  code="$(curl -s -o "$body_file" -w '%{http_code}' --max-time 30 --cacert "$PROOF_CA" \
    -d @- "$KC_ISSUER/protocol/openid-connect/token")"
  rc=$?
  set -e
  printf '%s' "$code"
  return "$rc"
}

# _OAUTH_ERROR_PY — the OAuth `error` code of a refusal body, or a NON-ZERO EXIT.
# It never falls back to a benign default: an unparseable body, a non-object, a missing or
# non-string `error` all EXIT 1, so the caller cannot mistake "I could not read the
# reason" for "the reason was fine".
_OAUTH_ERROR_PY='
import json, sys
try:
    doc = json.loads(sys.stdin.read())
except ValueError:
    raise SystemExit(1)
if not isinstance(doc, dict):
    raise SystemExit(1)
err = doc.get("error")
if not isinstance(err, str) or not err:
    raise SystemExit(1)
print(err)
'

# assert_grant_disabled <LABEL> <BODY_FILE> <CURL_RC> <HTTP_STATUS> — pass ONLY on an
# OBSERVED OAuth refusal that NAMES THE GRANT TYPE as the reason. Fails loud on a
# transport failure, any 2xx, any 5xx, a 404, a non-JSON body, and a refusal for a
# DIFFERENT reason. Sets GRANT_OBSERVED_ERROR to the observed code.
#
# It must be called WITHOUT a command substitution — a bar_fail inside `$( … )` would be
# swallowed by bash 3.2 — hence the global rather than a printed return value.
GRANT_OBSERVED_ERROR=""
assert_grant_disabled() {
  local label="$1" body_file="$2" rc="$3" code="$4" err err_rc
  [ "$rc" -eq 0 ] \
    || bar_fail "BAR B $label — the token request never REACHED Keycloak (curl exit $rc, http_code '$code'). curl reports 000 when the connection never happened, and the pre-review assertion (status != 200) was TRUE for 000 — so an unreached server would have 'proven' the grant is disabled. A tool that could not run has observed nothing."
  [ "$code" = "400" ] \
    || bar_fail "BAR B $label — expected Keycloak's OAuth refusal status 400, got HTTP $code. A 2xx means the grant SUCCEEDED and the locked profile does NOT hold. A 404 means the token endpoint is wrong, so the probe observed nothing about the grant profile. A 5xx means Keycloak failed, which is not a refusal."
  set +e
  err="$(python3 -c "$_OAUTH_ERROR_PY" < "$body_file")"
  err_rc=$?
  set -e
  [ "$err_rc" -eq 0 ] && [ -n "$err" ] \
    || bar_fail "BAR B $label — the refusal body is not a JSON object carrying a string error field, so the REASON Keycloak refused was never observed. A refusal whose reason cannot be read is not evidence that the GRANT TYPE was refused. Body: $(head -c 200 "$body_file" 2>/dev/null)"
  [ "$err" = "unauthorized_client" ] \
    || bar_fail "BAR B $label — Keycloak refused with error=$err, NOT unauthorized_client. Only unauthorized_client means 'the authenticated client is not authorized to use this authorization grant type' (RFC 6749 §5.2), which IS the claim. invalid_client = the client secret was wrong. invalid_grant = the credentials were wrong — a password grant that is ENABLED refuses a bad password in exactly this way, so accepting it would let the leg pass while direct access is live. invalid_request = the probe itself was malformed. None of those observe the grant profile."
  GRANT_OBSERVED_ERROR="$err"
}

set +e
B_CC="$(printf 'grant_type=client_credentials&client_id=%s&client_secret=%s' \
  "$KC_CLIENT" "$KC_CLIENT_SECRET" | kc_token_probe "$QC_TMP/kc-cc-body.json")"
B_CC_RC=$?
set -e
assert_grant_disabled "client-credentials grant" "$QC_TMP/kc-cc-body.json" "$B_CC_RC" "$B_CC"
B_CC_ERR="$GRANT_OBSERVED_ERROR"

B_DANA_PW="$(grep '^KC_PW_APPROVER_DANA=' "$KC_CRED_TMP/realm-credentials.env" | cut -d= -f2-)"
[ -n "$B_DANA_PW" ] \
  || bar_fail "BAR B could not read dana's password from the realm credentials — the direct-access probe would send an EMPTY password, and Keycloak would refuse it for the WRONG reason"
set +e
B_DAG="$(printf 'grant_type=password&client_id=%s&client_secret=%s&username=approver.dana&password=%s&scope=openid' \
  "$KC_CLIENT" "$KC_CLIENT_SECRET" "$B_DANA_PW" | kc_token_probe "$QC_TMP/kc-dag-body.json")"
B_DAG_RC=$?
set -e
assert_grant_disabled "direct-access (password) grant" "$QC_TMP/kc-dag-body.json" "$B_DAG_RC" "$B_DAG"
B_DAG_ERR="$GRANT_OBSERVED_ERROR"

echo "  Bar B OK: client-credentials (HTTP $B_CC, error=$B_CC_ERR) + direct-access (HTTP $B_DAG, error=$B_DAG_ERR) — both refused BY GRANT TYPE against a VALID client secret, so the locked profile holds"

# --- token-shape refusals at AgentOS, each pinned to its EXACT binder gate -----
B_AMIR_PW="$(grep '^KC_PW_ANALYST_AMIR=' "$KC_CRED_TMP/realm-credentials.env" | cut -d= -f2-)"
B_TOKENS="$KC_CRED_TMP/bar-b-tokens.json"
KC_USER_PASSWORD="$B_AMIR_PW" KC_CLIENT_SECRET="$KC_CLIENT_SECRET" \
  python3 "$PROOF_DIR/keycloak/pkce_login.py" "$KC_ISSUER" "$KC_CLIENT" "$DRIVER_REDIRECT_URI" "analyst.amir" "$PROOF_CA" > "$B_TOKENS" \
  || bar_fail "BAR B could not mint a real amir token for the tamper tests"

# real-ID-token substitution: the ID token's header typ is not at+jwt -> typ_not_at_jwt.
B_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id_token"])' "$B_TOKENS")"
B_TYP_PRE="$(binder_refusal_count typ_not_at_jwt)"
B_ID_CODE="$(printf 'header = "Authorization: Bearer %s"\n' "$B_ID" | curl -s -o /dev/null -w '%{http_code}' -K - --cacert "$PROOF_CA" "$BASE_URL/api/v1/conversations")"
[ "$B_ID_CODE" = "403" ] || bar_fail "BAR B the ID token was ACCEPTED in place of the access token (HTTP $B_ID_CODE, expected 403)"
assert_binder_refusal typ_not_at_jwt "$B_TYP_PRE"

# malformed bearer -> token_malformed.
B_MAL_PRE="$(binder_refusal_count token_malformed)"
B_BAD_CODE="$(printf 'header = "Authorization: Bearer not.a.jwt"\n' | curl -s -o /dev/null -w '%{http_code}' -K - --cacert "$PROOF_CA" "$BASE_URL/api/v1/conversations")"
[ "$B_BAD_CODE" = "403" ] || bar_fail "BAR B a malformed bearer was ACCEPTED (HTTP $B_BAD_CODE, expected 403)"
assert_binder_refusal token_malformed "$B_MAL_PRE"

# unknown signing key: swap the access token's kid to an unknown value. The binder
# checks kid membership in the JWKS BEFORE the signature, so kid_unknown fires even
# though the mutated header no longer matches the signature.
B_UK="$(python3 -c '
import base64, json, sys
tok = json.load(open(sys.argv[1]))["access_token"]
h, p, s = tok.split(".")
def b64d(x): return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
def b64e(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
hdr = json.loads(b64d(h)); hdr["kid"] = "unknown-kid-proof-000"
print(b64e(json.dumps(hdr, separators=(",", ":")).encode()) + "." + p + "." + s)
' "$B_TOKENS")"
B_KID_PRE="$(binder_refusal_count kid_unknown)"
B_UK_CODE="$(printf 'header = "Authorization: Bearer %s"\n' "$B_UK" | curl -s -o /dev/null -w '%{http_code}' -K - --cacert "$PROOF_CA" "$BASE_URL/api/v1/conversations")"
[ "$B_UK_CODE" = "403" ] || bar_fail "BAR B a token with an unknown kid was ACCEPTED (HTTP $B_UK_CODE)"
assert_binder_refusal kid_unknown "$B_KID_PRE"

# wrong audience: an OTHERWISE-PERFECT token (correct azp/typ/signature/exp) whose
# only defect is a SECOND audience (the wrong-audience optional scope) -> the
# binder's EXACT-audience gate fires audience_not_exact.
B_WA_TOKENS="$KC_CRED_TMP/bar-b-wrongaud.json"
KC_USER_PASSWORD="$B_AMIR_PW" KC_CLIENT_SECRET="$KC_CLIENT_SECRET" \
  python3 "$PROOF_DIR/keycloak/pkce_login.py" "$KC_ISSUER" "$KC_CLIENT" "$DRIVER_REDIRECT_URI" "analyst.amir" "$PROOF_CA" "openid wrong-audience" > "$B_WA_TOKENS" \
  || bar_fail "BAR B could not mint a wrong-audience token (is the wrong-audience optional scope on the realm?)"
B_WA="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["access_token"])' "$B_WA_TOKENS")"
B_AUD_PRE="$(binder_refusal_count audience_not_exact)"
B_WA_CODE="$(printf 'header = "Authorization: Bearer %s"\n' "$B_WA" | curl -s -o /dev/null -w '%{http_code}' -K - --cacert "$PROOF_CA" "$BASE_URL/api/v1/conversations")"
[ "$B_WA_CODE" = "403" ] || bar_fail "BAR B a wrong-audience token was ACCEPTED (HTTP $B_WA_CODE) — the exact-audience gate did not fire"
assert_binder_refusal audience_not_exact "$B_AUD_PRE"
rm -f "$B_TOKENS" "$B_WA_TOKENS"
echo "  Bar B OK: id-token(typ_not_at_jwt) + malformed(token_malformed) + unknown-key(kid_unknown) + wrong-audience(audience_not_exact) each refused at its EXACT binder gate"

# expired token: an OTHERWISE-PERFECT cognic-harness token (correct issuer, azp,
# audience, at+jwt header, real signature) whose ONLY defect is that it has lapsed.
#
# The pre-review runner ducked this into the binder's unit suite, claiming a live
# leg would need a multi-minute wait (Codex round-2 P1). It does not: Keycloak's
# per-client `access.token.lifespan` override mints a 10-second token from the SAME
# client, so `azp` stays `cognic-harness` and the binder walks its gates in exactly
# the order it does for every other request — reaching the `exp` check (binder.py:274,
# AFTER the azp check at :269) with a genuinely expired, genuinely signed token.
# The lifespan is restored immediately afterwards.
kc_set_access_token_lifespan 10
B_EXP_TOKENS="$KC_CRED_TMP/bar-b-expired.json"
KC_USER_PASSWORD="$B_AMIR_PW" KC_CLIENT_SECRET="$KC_CLIENT_SECRET" \
  python3 "$PROOF_DIR/keycloak/pkce_login.py" "$KC_ISSUER" "$KC_CLIENT" "$DRIVER_REDIRECT_URI" "analyst.amir" "$PROOF_CA" > "$B_EXP_TOKENS" \
  || { kc_set_access_token_lifespan 900; bar_fail "BAR B could not mint a short-life token for the expiry test"; }
B_EXP="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["access_token"])' "$B_EXP_TOKENS")"
# Prove the token is short-lived BEFORE spending the wait — otherwise a silently
# ignored lifespan override would turn this into a vacuous 900s-token test.
token_has_life "$B_EXP" 60 \
  && { kc_set_access_token_lifespan 900; bar_fail "BAR B the expiry-test token still has >60s of life — the access.token.lifespan override did not take effect, so the leg would prove nothing"; }
sleep 13                       # > the 10s lifespan: the token is now genuinely expired
token_has_life "$B_EXP" 0 \
  && { kc_set_access_token_lifespan 900; bar_fail "BAR B the expiry-test token has NOT expired after the wait"; }
B_EXP_PRE="$(binder_refusal_count token_expired)"
B_EXP_CODE="$(printf 'header = "Authorization: Bearer %s"\n' "$B_EXP" | curl -s -o /dev/null -w '%{http_code}' -K - --cacert "$PROOF_CA" "$BASE_URL/api/v1/conversations")"
rm -f "$B_EXP_TOKENS"
kc_set_access_token_lifespan 900
[ "$B_EXP_CODE" = "403" ] || bar_fail "BAR B an EXPIRED token was ACCEPTED (HTTP $B_EXP_CODE, expected 403)"
assert_binder_refusal token_expired "$B_EXP_PRE"
echo "  Bar B OK: an expired (but otherwise perfect, really-signed, same-azp) token is refused LIVE at the binder's exp gate (token_expired)"
echo "PROOF M8.5-C (BAR B) PASS"

# ============================ BAR C — chat ========================================
# A governed multi-turn conversation THROUGH THE UI, plus one entitlement-revoked
# turn whose refusal renders in the UI AND correlates to the chain row by exact
# id / digest / sequence / refusal fields (the DB side is the runner's PSQL).
echo "==> BAR C — governed chat through the BFF UI + a revoked-turn refusal"
C_T1="$(drive chat-turn --message "Who are the top 3 customers by total deposit balance this quarter? Name each and the balance." --state-file "$QC_TMP/session-amir.json")"
assert_chat_turn_completed "BAR C turn 1" "$C_T1"
C_CID="$(jq_get conversation_id "$C_T1")"
[ -n "$C_CID" ] || bar_fail "BAR C turn 1 rendered no conversation id (body: $C_T1)"
C_ANSWER1="$(jq_get answer_text "$C_T1")"
assert_no_stack_trace "BAR C (turn 1)" "$C_ANSWER1"
# The chain rows the UI turn produced are tenant-scoped kernel evidence.
[ "$(conv_event_count "$C_CID" conversation.created)" = "1" ] \
  || bar_fail "BAR C no conversation.created chain row for the UI conversation $C_CID"
C_RUN1="$(conv_turn_run_id "$C_CID" 1)"
[ -n "$C_RUN1" ] || bar_fail "BAR C no agent_run_id on the turn-1 chain row"
C_DISPATCH="$(run_dispatch_count "$C_RUN1" "payload->>'outcome'='ok' AND payload->>'scope_id'='retail_analytics'")"
[ "$C_DISPATCH" -ge 1 ] || bar_fail "BAR C turn 1 no ok retail dispatch for the UI run $C_RUN1"
assert_turn_digest_coupling "$C_CID" 1
echo "  Bar C leg 1 OK: a governed UI turn, chain-joined, digests coupled to the stored plaintext"

# Revoke amir's financials entitlement mid-conversation, then a FRESH financials
# question: the refusal must render in the UI AND the chain must show the refused
# dispatch. (The runner uses financials so the revocation bites a scope turn 1
# did not disclose.)
# Resolve amir's BOUND subject (issuer#sub) — the kernel keys entitlements by it,
# NOT by the login name. Using the bare "analyst.amir" here would delete zero rows
# and the revocation would silently not bite (a false PASS).
C_AMIR_SUB="$(bound_subject analyst.amir)"
C_ENT_BEFORE="$(entitlement_count "$C_AMIR_SUB" financials)"
[ "$C_ENT_BEFORE" = "1" ] || bar_fail "BAR C expected exactly 1 amir financials entitlement before revocation (got $C_ENT_BEFORE for subject $C_AMIR_SUB)"
entitlement_delete "$C_AMIR_SUB" financials >/dev/null
C_T2="$(drive chat-turn --message "Which branch had the highest profit-and-loss last quarter, and what was the figure? If you cannot access that data, say so." --conversation-id "$C_CID" --state-file "$QC_TMP/session-amir.json")"
assert_chat_turn_completed "BAR C turn 2" "$C_T2"
C_ANSWER2="$(jq_get answer_text "$C_T2")"
[ -n "$C_ANSWER2" ] || bar_fail "BAR C turn 2 rendered no answer (the refusal must surface as a governed answer)"
assert_no_stack_trace "BAR C (turn 2)" "$C_ANSWER2"
C_RUN2="$(conv_turn_run_id "$C_CID" 2)"
[ -n "$C_RUN2" ] || bar_fail "BAR C no agent_run_id on the turn-2 chain row"
C_REFUSED="$(run_dispatch_count "$C_RUN2" "payload->>'outcome'='refused' AND payload->>'refusal_reason'='agent_scope_not_entitled' AND payload->>'scope_id'='financials'")"
[ "$C_REFUSED" -ge 1 ] \
  || bar_fail "BAR C turn 2 no refused agent_scope_not_entitled financials dispatch for $C_RUN2 (revocation did not bite in the UI turn)"
C_FIN_OK="$(run_dispatch_count "$C_RUN2" "payload->>'outcome'='ok' AND payload->>'scope_id'='financials'")"
[ "$C_FIN_OK" = "0" ] || bar_fail "BAR C turn 2 an ok financials dispatch executed after revocation ($C_FIN_OK rows)"
entitlement_restore "$C_AMIR_SUB" financials >/dev/null
[ "$(entitlement_count "$C_AMIR_SUB" financials)" = "1" ] || bar_fail "BAR C entitlement restore failed"

# The spec (§5.2 Bar C) requires the refusal to RENDER IN THE UI and correlate to
# the chain row "by exact ID, digest, sequence, and refusal fields". The pre-review
# leg asserted only that turn 2 produced a NON-EMPTY answer and that the DB held a
# refused row (Codex round-2 P1) — so a model that hallucinated a plausible P&L
# figure while the dispatch was refused underneath would have passed, and nothing
# tied the rendered page to the chain at all. Now the runner reads the EVIDENCE
# SCREEN for turn 2 and requires the refusal to be visible there:
#   * a rendered dispatch row carrying outcome=refused + agent_scope_not_entitled
#     + scope=financials — the scope is load-bearing, because turn 2 dispatches the
#     SAME capability twice (retail ok, financials refused) and without the scope
#     the two rows are indistinguishable (this gap was in the HARNESS template and
#     was closed as part of this round);
#   * NO rendered dispatch showing an OK financials read;
#   * the rendered agent_run_id + chain-row sequence + question/answer digests all
#     equal the kernel's.
C_EVID2="$(drive evidence --conversation-id "$C_CID" --seq 2 --state-file "$QC_TMP/session-amir.json")"
C_DB_SEQ2="$(conv_turn_chain_sequence "$C_CID" 2)"
[ -n "$C_DB_SEQ2" ] || bar_fail "BAR C could not read the turn-2 chain-row sequence from the DB"
json_assert "BAR C turn 2 renders the refusal and correlates to the chain row" '
import hashlib, json, sys
doc = json.loads(sys.stdin.read())
run_id, db_seq = sys.argv[1], sys.argv[2]
chain = doc["chain"]
tc = chain["turn_completed"]
cols = chain["dispatch_columns"]
# The scope column MUST be rendered, or the refusal is not attributable to a scope.
assert "scope_id" in cols, f"the evidence screen renders no scope column (columns={cols}) — the refused dispatch cannot be attributed to a scope"
rows = chain["dispatches"]
refused = [
    d for d in rows
    if d.get("outcome") == "refused"
    and d.get("refusal_reason") == "agent_scope_not_entitled"
    and d.get("scope_id") == "financials"
]
assert refused, f"no RENDERED dispatch shows the financials refusal (rows={rows})"
leaked = [d for d in rows if d.get("outcome") == "ok" and d.get("scope_id") == "financials"]
assert not leaked, f"the evidence screen renders an OK financials dispatch after revocation: {leaked}"
# exact ID + sequence + digests, all against the kernel'\''s own chain row
assert tc["agent_run_id"] == run_id, (tc["agent_run_id"], run_id)
assert str(tc["sequence"]) == str(db_seq), (tc["sequence"], db_seq)
# digest coupling for TURN 2 (the pre-review bar coupled turn 1 only)
turns = {int(t["sequence"]): t for t in doc["transcript_turns"]}
assert 2 in turns, f"the transcript screen does not render turn 2 (turns={sorted(turns)})"
q = hashlib.sha256(turns[2]["question_text"].encode()).hexdigest()
a = hashlib.sha256(turns[2]["answer_text"].encode()).hexdigest()
assert q == tc["question_sha256"], f"turn-2 rendered question re-hashes to {q}, chain says {tc[\"question_sha256\"]}"
assert a == tc["answer_sha256"], f"turn-2 rendered answer re-hashes to {a}, chain says {tc[\"answer_sha256\"]}"
print("ok")
' "$C_EVID2" "$C_RUN2" "$C_DB_SEQ2"
echo "  Bar C leg 2 OK: the refusal RENDERS (outcome=refused / agent_scope_not_entitled / scope=financials), no OK financials row, and the screen correlates to the chain by run-id + sequence + both digests"
echo "PROOF M8.5-C (BAR C) PASS"

# ============================ BAR D — approvals (the ledger proves refusal) =======
# The eight-step four-eyes sequence. The INDEPENDENT observer is the probe ledger
# (kubectl exec, runner-only): every "ledger stays 0 / exactly 1" assertion reads
# it directly. Approvers act through the BFF approvals screen (driver); requests
# are minted through the REAL MCP path (direct invoke).
echo "==> BAR D — approvals: four-eyes over the high-risk probe (ledger = the independent observer)"
D_LEDGER0="$(probe_ledger_count)"
[ "$D_LEDGER0" = "0" ] || bar_fail "BAR D the probe ledger was non-zero at the start ($D_LEDGER0) — a stale execution?"
drive_login dana /approvals >/dev/null
drive_login erin /approvals >/dev/null

# D.1 — amir's initial probe call -> 202 pending, ledger 0; the inbox renders it.
# mint_probe_request now returns "<request_id>\t<nonce>": the nonce is the BOUND
# argument that every replay of this request must re-send.
D_MINT1="$(mint_probe_request amir)"
D_REQ1="$(printf '%s' "$D_MINT1" | cut -f1)"
D_NONCE1="$(printf '%s' "$D_MINT1" | cut -f2)"
[ -n "$D_REQ1" ] && [ -n "$D_NONCE1" ] || bar_fail "BAR D.1 no approval_request_id/nonce minted (got '$D_MINT1')"
[ "$(probe_ledger_count)" = "0" ] || bar_fail "BAR D.1 the ledger moved on a PENDING request (must be 0)"
D_INBOX="$(drive approvals-list --state-file "$QC_TMP/session-dana.json")"
json_assert "BAR D.1 inbox renders the pending request" '
import json, sys
doc = json.loads(sys.stdin.read()); rid = sys.argv[1]
assert doc["status"] == 200, doc
assert any(r.get("request_id") == rid for r in doc["rows"]), (rid, [r.get("request_id") for r in doc["rows"]])
print("ok")
' "$D_INBOX" "$D_REQ1"
echo "  Bar D.1 OK: pending request rendered in the inbox; ledger 0"

# D.2 — denial leg: dana denies -> amir REPLAYS the SAME request (approval_request_id
# + the original nonce) -> tool_approval_denied, ledger stays 0. Sending the
# original nonce is required: with a wrong nonce the engine would short-circuit to
# tool_approval_binding_mismatch (args gate) before reaching the denied state.
D_DENY="$(drive approvals-act --request-id "$D_REQ1" --action deny --reason "not permitted" --state-file "$QC_TMP/session-dana.json")"
[ "$(jq_get status "$D_DENY")" = "200" ] || [ "$(jq_get status "$D_DENY")" = "303" ] \
  || bar_fail "BAR D.2 deny action failed (status $(jq_get status "$D_DENY"))"
D_RECALL_DENIED="$(recall_probe amir "$D_REQ1" "$D_NONCE1")"
load_http_code
[ "$HTTP_CODE" = "403" ] || bar_fail "BAR D.2 amir's replay after DENY was not refused (HTTP $HTTP_CODE)"
json_assert "BAR D.2 denied reason" '
import json, sys
doc = json.loads(sys.stdin.read())
reason = (doc.get("detail") or {}).get("reason") if isinstance(doc.get("detail"), dict) else doc.get("reason")
assert reason == "tool_approval_denied", doc
print("ok")
' "$D_RECALL_DENIED"
[ "$(probe_ledger_count)" = "0" ] || bar_fail "BAR D.2 the ledger moved after a DENY (must stay 0)"
echo "  Bar D.2 OK: denied -> exact-shape replay refused tool_approval_denied; ledger stays 0"

# D.3 + D.4 + D.5 — fresh request; first grant only (dana) -> amir's exact-shape
# replay remains pending, ledger 0; four-eyes: dana's grant-second on her own grant
# refused; erin (distinct) succeeds; amir's re-call now EXECUTES -> ledger exactly 1.
D_MINT2="$(mint_probe_request amir)"
D_REQ2="$(printf '%s' "$D_MINT2" | cut -f1)"
D_NONCE2="$(printf '%s' "$D_MINT2" | cut -f2)"
[ -n "$D_REQ2" ] && [ -n "$D_NONCE2" ] || bar_fail "BAR D.3 no request/nonce minted (got '$D_MINT2')"
drive approvals-act --request-id "$D_REQ2" --action grant --reason "first review" --state-file "$QC_TMP/session-dana.json" >/dev/null
D_RECALL_PENDING="$(recall_probe amir "$D_REQ2" "$D_NONCE2")"
load_http_code
[ "$HTTP_CODE" = "202" ] || bar_fail "BAR D.3 amir's replay after ONE grant was not still-pending (HTTP $HTTP_CODE)"
json_assert "BAR D.3 still-pending reason" '
import json, sys
doc = json.loads(sys.stdin.read())
reason = (doc.get("detail") or {}).get("reason") if isinstance(doc.get("detail"), dict) else doc.get("reason")
assert reason == "tool_approval_pending", doc
print("ok")
' "$D_RECALL_PENDING"
[ "$(probe_ledger_count)" = "0" ] || bar_fail "BAR D.3 the ledger moved after ONE grant (four-eyes needs two; must stay 0)"
# D.4 — dana attempts grant-second on her OWN grant: refused (four-eyes distinctness).
D_SELF2="$(drive approvals-act --request-id "$D_REQ2" --action grant-second --reason "self" --state-file "$QC_TMP/session-dana.json")"
D_SELF2_STATUS="$(jq_get status "$D_SELF2")"
[ "$D_SELF2_STATUS" = "403" ] || [ "$D_SELF2_STATUS" = "409" ] \
  || bar_fail "BAR D.4 dana's grant-second on her OWN grant was NOT refused (status $D_SELF2_STATUS)"
# erin (distinct human) succeeds.
drive_login erin /approvals >/dev/null
drive approvals-act --request-id "$D_REQ2" --action grant-second --reason "second review" --state-file "$QC_TMP/session-erin.json" >/dev/null
echo "  Bar D.4 OK: self grant-second refused ($D_SELF2_STATUS); a distinct approver (erin) completed four-eyes"
# D.5 — amir's exact-shape re-call (same request-id + nonce) now executes -> ledger EXACTLY 1.
recall_probe amir "$D_REQ2" "$D_NONCE2" >/dev/null
load_http_code
[ "$HTTP_CODE" = "200" ] || bar_fail "BAR D.5 amir's re-call after four-eyes did NOT execute (HTTP $HTTP_CODE)"
D_LEDGER1="$(probe_ledger_count)"
[ "$D_LEDGER1" = "1" ] || bar_fail "BAR D.5 the ledger is $D_LEDGER1 after the granted re-call (expected EXACTLY 1)"
echo "  Bar D.5 OK: four-eyes complete -> exact-shape re-call executed -> ledger EXACTLY 1"

# D.6 — originator isolation: sara (same tenant, same MCP invocation authority,
# DIFFERENT subject) replays amir's GRANTED request-id with the EXACT shape (same
# nonce) -> tool_approval_originator_mismatch, ledger stays 1. The refusal cannot
# be scope or tenant invisibility (sara has both) — only the actor-bound replay
# gate (HP-4) explains it. This is the whole point of the milestone; the
# pre-review recall sent a fresh nonce with no request-id, so it minted sara her
# OWN request and never exercised the binding at all.
D_SARA_RECALL="$(recall_probe sara "$D_REQ2" "$D_NONCE2")"
load_http_code
[ "$HTTP_CODE" = "403" ] || bar_fail "BAR D.6 sara's replay of amir's granted shape was not refused (HTTP $HTTP_CODE)"
json_assert "BAR D.6 originator mismatch reason" '
import json, sys
doc = json.loads(sys.stdin.read())
reason = (doc.get("detail") or {}).get("reason") if isinstance(doc.get("detail"), dict) else doc.get("reason")
assert reason == "tool_approval_originator_mismatch", doc
print("ok")
' "$D_SARA_RECALL"
[ "$(probe_ledger_count)" = "1" ] || bar_fail "BAR D.6 the ledger moved on sara's replay (must stay 1)"
echo "  Bar D.6 OK: originator isolation — sara's exact-shape replay refused tool_approval_originator_mismatch; ledger stays 1"

# D.7 — pagination over the real MCP-minted queue. Mint exactly 51 fresh requests
# (all pending), CAPTURING each request-id, then walk the driver's Link pagination
# and assert the paginated id-set EQUALS the minted set exactly (no dupes, no
# omissions), with a Link continuation on page one and none on the last. The
# earlier requests are terminal (D_REQ1 denied, D_REQ2 granted, B_THROW denied), so
# the actionable queue is exactly these 51. The pre-review check discarded the ids
# and only asserted len>=50 — it could not catch a dropped or duplicated id.
D_LEDGER_BEFORE_PAGE="$(probe_ledger_count)"
D_MINTED_IDS="$QC_TMP/d7-minted-ids.txt"
: > "$D_MINTED_IDS"
for _i in $(seq 1 51); do mint_probe_request amir | cut -f1 >> "$D_MINTED_IDS"; done
[ "$(probe_ledger_count)" = "$D_LEDGER_BEFORE_PAGE" ] \
  || bar_fail "BAR D.7 minting pending requests moved the ledger (pending must never execute)"
D_PAGES="$(drive approvals-paginate --state-file "$QC_TMP/session-dana.json")"
# The kernel's OWN keyset order, read straight from the DB. The pre-review check
# asserted only SET equality — which passes just as happily on a reversed or
# shuffled walk, while the spec (§5.2 D.7) requires "correct ordering" (Codex
# round-2 P2). A keyset paginator that mis-orders silently drops or repeats rows
# at page boundaries under concurrent inserts, so order is not cosmetic.
D_EXPECTED_ORDER="$QC_TMP/d7-expected-order.txt"
approval_queue_order > "$D_EXPECTED_ORDER"
json_assert "BAR D.7 pagination integrity (exact id-set AND exact keyset order)" '
import json, sys
doc = json.loads(sys.stdin.read())
minted = [l.strip().lower() for l in open(sys.argv[1]) if l.strip()]
expected = [l.strip().lower() for l in open(sys.argv[2]) if l.strip()]
ids = [str(i).lower() for i in doc["request_ids"]]
assert len(minted) == 51, f"expected 51 minted request ids, captured {len(minted)}"
assert doc["pages"] >= 2, f"expected >=2 pages, got {doc[\"pages\"]}"
assert len(ids) == len(set(ids)), "duplicate request ids across pages"
only_p = sorted(set(ids) - set(minted))[:3]
only_m = sorted(set(minted) - set(ids))[:3]
assert set(ids) == set(minted), f"paginated set != minted set (only_paginated={only_p} only_minted={only_m})"
# The DB-derived actionable queue must itself BE the 51 (every earlier request is
# terminal) — otherwise the order comparison below would be against the wrong set.
assert set(expected) == set(minted), f"the DB actionable queue is not the 51 minted requests (db={len(expected)})"
# ORDER, not just membership: the paginated walk must reproduce the kernel keyset
# (created_at ASC, request_id ASC) exactly, element by element.
if ids != expected:
    first = next((n for n, (a, b) in enumerate(zip(ids, expected)) if a != b), min(len(ids), len(expected)))
    raise AssertionError(
        f"paginated ORDER != the kernel keyset order (created_at ASC, request_id ASC); "
        f"first divergence at index {first}: paginated={ids[first:first+3]} expected={expected[first:first+3]}"
    )
assert doc["link_on_first_page"] is True, "no Link continuation on page 1"
assert doc["link_on_last_page"] is False, "a Link continuation is present on the LAST page"
print("ok")
' "$D_PAGES" "$D_MINTED_IDS" "$D_EXPECTED_ORDER"
echo "  Bar D.7 OK: Link pagination — EXACT 51-id set, no dupes/omissions, the walk reproduces the kernel keyset ORDER exactly, Link on page 1 and none on the last"

# D.8 — a non-observer (amir holds no approve scope) gets a RENDERED 403 refusal
# view (never a hidden-empty state); the foreign-tenant observer sees an empty
# queue of their own.
drive_login amir >/dev/null
D_NONOBS="$(drive approvals-list --state-file "$QC_TMP/session-amir.json")"
D_NONOBS_STATUS="$(jq_get status "$D_NONOBS")"
[ "$D_NONOBS_STATUS" = "403" ] \
  || bar_fail "BAR D.8 the non-observer (amir) did not get a rendered 403 refusal (status $D_NONOBS_STATUS)"
[ "$(jq_get refusal_rendered "$D_NONOBS")" = "true" ] \
  || bar_fail "BAR D.8 amir's 403 was a hidden-empty state, not a rendered refusal view"
drive_login zara >/dev/null
D_FOREIGN="$(drive approvals-list --state-file "$QC_TMP/session-zara.json")"
json_assert "BAR D.8 foreign observer sees an empty own-queue" '
import json, sys
doc = json.loads(sys.stdin.read())
assert doc["status"] == 200, doc
assert doc["rows"] == [], doc  # the foreign tenant has none of proof-m85c'\''s requests
print("ok")
' "$D_FOREIGN"
echo "  Bar D.8 OK: non-observer rendered 403; foreign observer sees an empty own-queue"
echo "PROOF M8.5-C (BAR D) PASS"

# ============================ BAR E — evidence ====================================
# The transcript + per-turn chain screens render; the driver extracts the rendered
# ids/digests; the runner's PSQL performs EVERY DB comparison. The BFF image
# retains ZERO DB driver (Bar F asserts it structurally too).
echo "==> BAR E — evidence: rendered transcript + chain reconciled against the DB by PSQL"
drive_login amir >/dev/null
E_EVID="$(drive evidence --conversation-id "$C_CID" --seq 1 --state-file "$QC_TMP/session-amir.json")"
json_assert "BAR E rendered chain shape" '
import json, sys
doc = json.loads(sys.stdin.read())
chain = doc["chain"]
assert set(chain) >= {"turn_completed", "started", "terminal", "dispatches"}, sorted(chain)
assert doc["transcript_turns"], "no transcript turns rendered"
print("ok")
' "$E_EVID"

# THE transcript assertion (Codex round-2 P1). The pre-review bar checked only that
# `transcript_turns` was non-empty and then compared digests the CHAIN screen had
# rendered against the DB — the kernel'"'"'s numbers against the kernel'"'"'s numbers. It
# never looked at the WORDS on the page, so a stale, truncated or plain wrong
# transcript passed. Here every RENDERED turn'"'"'s text is re-hashed and required to
# equal that turn'"'"'s chain-row digests, bound by the rendered agent_run_id.
assert_rendered_transcript_matches_chain "$E_EVID" "$C_CID"
# The runner recomputes the reconciliation from the DB: the rendered agent_run_id
# AND the rendered question/answer digests on the chain screen MUST equal the
# kernel's stored chain-row values. The pre-review bar compared only agent_run_id;
# the spec (§5.2 Bar E) requires the DIGESTS to reconcile too — that is what proves
# the evidence screen shows the SAME governed bytes the kernel hash-chained, not a
# re-rendering. conv_turn_chain_field reads the chain row's own sha256 fields.
# The evidence document rides STDIN; only the FIELD NAME is on argv (F1 — the same
# rule jq_get / json_assert obey. This document is governed conversation content
# rather than a bearer credential, but the rule is kept uniform so no future call site
# has to reason about which reader is safe to hand a secret to).
_e_field() {
  printf '%s' "${1:-}" \
    | python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["chain"]["turn_completed"].get(sys.argv[1],""))' \
        "$2" 2>/dev/null || true
}
E_RENDERED_RUN="$(_e_field "$E_EVID" agent_run_id)"
E_DB_RUN="$(conv_turn_run_id "$C_CID" 1)"
[ -n "$E_RENDERED_RUN" ] && [ "$E_RENDERED_RUN" = "$E_DB_RUN" ] \
  || bar_fail "BAR E the rendered agent_run_id ($E_RENDERED_RUN) does not equal the DB chain row ($E_DB_RUN)"
E_RENDERED_QSHA="$(_e_field "$E_EVID" question_sha256)"
E_DB_QSHA="$(conv_turn_chain_field "$C_CID" 1 question_sha256)"
[ -n "$E_RENDERED_QSHA" ] && [ "$E_RENDERED_QSHA" = "$E_DB_QSHA" ] \
  || bar_fail "BAR E the rendered question_sha256 ($E_RENDERED_QSHA) does not equal the DB chain row ($E_DB_QSHA)"
E_RENDERED_ASHA="$(_e_field "$E_EVID" answer_sha256)"
E_DB_ASHA="$(conv_turn_chain_field "$C_CID" 1 answer_sha256)"
[ -n "$E_RENDERED_ASHA" ] && [ "$E_RENDERED_ASHA" = "$E_DB_ASHA" ] \
  || bar_fail "BAR E the rendered answer_sha256 ($E_RENDERED_ASHA) does not equal the DB chain row ($E_DB_ASHA)"
echo "  Bar E OK: evidence screens rendered; run id AND question/answer digests reconcile to the kernel chain row (PSQL-verified)"
echo "PROOF M8.5-C (BAR E) PASS"

# ============================ BAR F — structural ==================================
# The production BFF bundle: exactly three screens, no DB client, no operator
# APIs, no proof-header code, no |safe, CSP present, vendored htmx checksum
# verified. Asserted against the RUNNING BFF image (not the source tree) so the
# claim is about what actually deploys.
echo "==> BAR F — structural (against the running BFF image)"
F_POD="$(kubectl -n "$NS" get pods -l app=cognic-proof-harness -o name | head -1)"
F_PKG="/opt/venv/lib/python*/site-packages/cognic_harness"
# No DB driver in the image (spec §5.2 + the harness contract: zero DB connectivity).
F_DBMODS="$(kubectl -n "$NS" exec "$F_POD" -- python -c "
import importlib.util as u
mods = ['sqlalchemy','psycopg','psycopg2','asyncpg','oracledb','cx_Oracle','pymysql']
present = [m for m in mods if u.find_spec(m) is not None]
print(','.join(present))
" 2>/dev/null || echo "<probe-failed>")"
[ -z "$F_DBMODS" ] || bar_fail "BAR F the BFF image carries DB driver module(s): $F_DBMODS (must be zero)"

# EXACTLY THREE SCREENS: the shipped web package must carry ONLY the auth flow +
# the three screen route modules (auth/chat/approvals/evidence) — no operator,
# admin, pack-lifecycle, or pack-builder surface (spec §5.2 Bar F). Assert the
# exact set of *_routes.py, so a stray operator/builder module fails loud.
F_ROUTES="$(kubectl -n "$NS" exec "$F_POD" -- sh -c "cd $F_PKG/web && ls *_routes.py 2>/dev/null | sort | tr '\n' ' '" 2>/dev/null || echo '<probe-failed>')"
_EXPECTED_ROUTES="approvals_routes.py auth_routes.py chat_routes.py evidence_routes.py "
[ "$F_ROUTES" = "$_EXPECTED_ROUTES" ] \
  || bar_fail "BAR F the shipped web route modules are '$F_ROUTES' — expected exactly '$_EXPECTED_ROUTES' (an operator/admin/pack/builder screen must NOT ship)"

# A SCAN THAT COULD NOT RUN HAS OBSERVED NOTHING (review 2026-07-12 round 5, F5).
# The three scans below all ended in `|| true`, so a grep/find that could not run AT ALL
# — a wrong $F_PKG, no shell in the image, a failed exec — yielded the empty string, and
# `[ -z "" ]` PASSED. A failed scan was reported as a clean bundle. Each now checks the
# tool's exit status EXPLICITLY, through the fail-loud kubectl_capture.

# NO proof-header / actor-header path in the production bundle (spec §5.2 Bar B +
# Bar F). The X-Proof-Role binder that M8.5-A/B used is deleted, not gated — the
# production harness must carry no header-based actor-injection code at all.
#
# `grep -rl` exits 0 on a match, 1 on ZERO matches (the clean case) and >1 on a real
# error, so the three states are told apart by exit CODE — never collapsed onto "".
set +e
F_ACTORHDR="$(kubectl_capture -n "$NS" exec "$F_POD" -- sh -c "grep -rliE 'x-proof-role|x-actor|proof.role|actor.header' $F_PKG")"
F_ACTORHDR_RC=$?
set -e
case "$F_ACTORHDR_RC" in
  0) bar_fail "BAR F the BFF bundle carries proof-header / actor-header code: $F_ACTORHDR (there must be NO actor-header path)" ;;
  1) ;;   # grep's documented "no matches" — an OBSERVED clean bundle
  *) bar_fail "BAR F the actor-header scan could not RUN (exit $F_ACTORHDR_RC): $(_kubectl_capture_err). A scan that could not run has observed NOTHING, and a non-observation is not evidence of a clean bundle." ;;
esac

# NO AUTOESCAPE BYPASS in any template shipped in the running image (spec §5.2 Bar F).
#
# This is the strongest claim in Bar F — no XSS escape hatch — and it was the WEAKEST
# check: `grep -rl '|safe'`. A grep for that literal is evaded by every one of
# `{{ x| safe }}`, `{{ x |  safe }}`, `{{ x | safe }}`,
# `{% filter safe %}{{ x }}{% endfilter %}`, and `{% autoescape false %}…{% endautoescape %}`
# — which disables escaping for a whole block and contains no `safe` filter at all.
#
# So the gate is now SEMANTIC. The image IS a Jinja app, so the scanner parses EVERY
# shipped template with the very same jinja2 that renders them and walks the AST. It
# reasons about NODES, not about spelling, which is what makes it un-evadable by
# rewording:
#
#   * a `Filter` node named `safe`                  — every `|safe` spelling, anywhere in a
#                                                     filter chain;
#   * a `{% filter safe %}` block                   — the block form;
#   * ANY `{% autoescape %}` node, BANNED OUTRIGHT  — even `{% autoescape true %}`, because
#                                                     permitting the node lets a later edit
#                                                     flip it to false without tripping the
#                                                     gate.
#
# FAIL-LOUD — the doctrine, applied to the scanner itself:
#   * a template that FAILS TO PARSE is an OFFENDER, never a skip: a syntax-error template
#     must not be able to evade the gate;
#   * THE TEMPLATE CENSUS IS EXACTLY EIGHT. If the glob is wrong, a file is missing, or an
#     unknown-suffix file is added, the scan refuses. Jinja loads filenames rather than a
#     security-relevant extension vocabulary, so an extension allow-list would let a `.tpl`
#     sit outside the gate while eight clean HTML files still satisfy the old count.
#
# CROSS-REPO LOCKSTEP: `cognic-harness` guards its own source tree and CI bundle with an
# equivalent semantic scan. This copy is deliberately INDEPENDENT — no runtime cross-repo
# import is possible, and this one asserts against the RUNNING IMAGE rather than a source
# tree. Its behaviour is pinned by this repo's own mutation tests
# (tests/unit/infra/test_proof_m85c_remediation.py), exactly as theirs pins theirs.
#
# The glob is resolved by PYTHON (`glob.glob`), not by a pod shell: `kubectl exec` runs no
# shell, so `$F_PKG` reaches the scanner un-expanded. Zero matching roots is a hard failure.
_F_TEMPLATE_SCAN_PY='
import glob, os, sys

try:
    import jinja2
    from jinja2 import nodes
except Exception as exc:
    print("SCANNER_ERROR jinja2 is not importable in the running image: %r" % (exc,))
    raise SystemExit(2)

roots = sorted(p for p in glob.glob(sys.argv[1]) if os.path.isdir(p))
if not roots:
    print("SCANNER_ERROR the shipped package directory was not found: %s" % (sys.argv[1],))
    raise SystemExit(2)

EXPECTED_TEMPLATES = (
    "approval_detail.html",
    "approvals.html",
    "base.html",
    "chat.html",
    "evidence_chain.html",
    "evidence_list.html",
    "evidence_transcript.html",
    "login.html",
)
templates = []
observed_names = []
for root in roots:
    template_root = os.path.join(root, "web", "templates")
    if not os.path.isdir(template_root):
        print("SCANNER_ERROR template directory is missing: %s" % (template_root,))
        raise SystemExit(2)
    for dirpath, _dirnames, filenames in os.walk(template_root):
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            templates.append(path)
            observed_names.append(os.path.relpath(path, template_root))
templates.sort()
observed_names.sort()

env = jinja2.Environment()
offenders = []
for path in templates:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
    except OSError as exc:
        offenders.append("%s: UNREADABLE, so it cannot be cleared (%r)" % (path, exc))
        continue
    try:
        ast = env.parse(source)
    except Exception as exc:
        offenders.append("%s: UNPARSEABLE, so it cannot be cleared (%s)" % (path, exc))
        continue
    for node in ast.find_all(nodes.Filter):
        if node.name == "safe":
            offenders.append("%s:%s: the safe filter — an autoescape bypass" % (path, node.lineno))
    for node in ast.find_all(nodes.FilterBlock):
        if getattr(node.filter, "name", None) == "safe":
            offenders.append("%s:%s: a filter-safe BLOCK — an autoescape bypass" % (path, node.lineno))
    for node in ast.find_all(nodes.EvalContextModifier):
        for option in node.options:
            if option.key == "autoescape":
                offenders.append(
                    "%s:%s: an autoescape block — BANNED OUTRIGHT, even when true, because "
                    "permitting the node lets a later edit flip it to false" % (path, node.lineno)
                )

for line in offenders:
    print("OFFENDER " + line)
print("TEMPLATES_SCANNED=%d" % (len(templates),))
print("OFFENDERS=%d" % (len(offenders),))
if not templates:
    print(
        "SCANNER_ERROR ZERO templates were scanned. The scan OBSERVED NOTHING, which is "
        "not the same as a clean bundle."
    )
    raise SystemExit(2)
if tuple(observed_names) != EXPECTED_TEMPLATES:
    print(
        "SCANNER_ERROR shipped template census mismatch: expected %r, observed %r"
        % (EXPECTED_TEMPLATES, tuple(observed_names))
    )
    raise SystemExit(2)
if offenders:
    raise SystemExit(1)
'
set +e
F_TPL="$(kubectl_capture -n "$NS" exec "$F_POD" -- python -c "$_F_TEMPLATE_SCAN_PY" "$F_PKG")"
F_TPL_RC=$?
set -e
[ "$F_TPL_RC" -eq 0 ] \
  || bar_fail "BAR F the shipped templates did NOT clear the autoescape-bypass scan (exit $F_TPL_RC): $F_TPL $(_kubectl_capture_err). Exit 1 = the scanner found offenders (each listed above as OFFENDER <file>:<line>). Exit 2 = the scanner could not observe the templates at all, which is NOT a clean bundle. Any other exit = the exec itself failed."
F_TPL_N="$(printf '%s\n' "$F_TPL" | sed -n 's/^TEMPLATES_SCANNED=\([0-9][0-9]*\)$/\1/p')"
case "$F_TPL_N" in
  ''|*[!0-9]*) bar_fail "BAR F the template scan exited 0 but reported no TEMPLATES_SCANNED count: $F_TPL. It observed nothing, and a non-observation may not stand in for a clean bundle." ;;
esac
[ "$F_TPL_N" = "8" ] \
  || bar_fail "BAR F the template scan did not observe the exact 8-file template census (got $F_TPL_N). A missing, renamed, or added file is a reviewed bundle-contract change; an unknown extension must never sit outside the scan."

# htmx (spec §5.2 Bar F "vendored htmx checksum verified"): the harness vendors
# htmx ONLY where it removes friction (spec §3.1) and this build ships plain
# progressively-enhanced HTML WITHOUT it. Assert it is genuinely ABSENT rather
# than shipped un-pinned — if a future build vendors htmx, this fails loud until a
# checksum pin is added (an un-pinned vendored asset is a supply-chain gap).
#
# `find` exits 0 with empty output when it matched nothing, and non-zero when the path
# itself is unreachable — so, unlike grep, a clean result and a failed scan are told apart
# by the exit status alone.
set +e
F_HTMX="$(kubectl_capture -n "$NS" exec "$F_POD" -- sh -c "find $F_PKG -iname '*htmx*'")"
F_HTMX_RC=$?
set -e
[ "$F_HTMX_RC" -eq 0 ] \
  || bar_fail "BAR F the htmx scan could not RUN (exit $F_HTMX_RC): $(_kubectl_capture_err). A scan that could not run has observed NOTHING — it is not evidence that no un-pinned asset is vendored."
[ -z "$F_HTMX" ] \
  || bar_fail "BAR F htmx is vendored ($F_HTMX) but this bar does not verify a checksum pin — add the pin (an un-pinned vendored asset is forbidden)"

# CSP + no-store present (the security middleware). /signin is the reachable
# unauthenticated surface; the middleware sets both on every response.
F_HEADERS="$(curl -s -D - -o /dev/null --cacert "$PROOF_CA" "$HARNESS_BASE_URL/signin" 2>/dev/null || true)"
grep -qiE "content-security-policy" <<<"$F_HEADERS" \
  || bar_fail "BAR F no Content-Security-Policy header on the BFF"
grep -qiE "cache-control:.*no-store" <<<"$F_HEADERS" \
  || bar_fail "BAR F no Cache-Control: no-store header on the BFF"
echo "  Bar F OK: zero DB modules; exactly the 3 screens (+auth); no actor-header path; $F_TPL_N shipped templates ALL parsed with the image's own jinja2 and NONE carries an autoescape bypass (no safe filter in any spelling, no filter-safe block, no autoescape node); htmx absent (no un-pinned asset); CSP + no-store present"
echo "PROOF M8.5-C (BAR F) PASS"

echo "PROOF M8.5-C (BARS A-F) PASS"
