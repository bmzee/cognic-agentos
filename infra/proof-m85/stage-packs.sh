#!/usr/bin/env bash
# infra/proof-m85/stage-packs.sh — stage the released, signed packs for the
# M8.5 SLICE proof (same SEVEN M8 releases — the conversation substrate adds no pack). RELEASED ASSETS ONLY (never a source rebuild):
#
#   THE SIX PART-B RELEASES (maintainer-locked digest pins):
#   * cognic-tool-oracle-schema@v0.3.0    — the governed run_readonly_query tool
#     (M8 B1). Operator-installed via the M4 lifecycle flow by the runner; the
#     agent's granted tool ref resolves to THIS deployed server. Verifies the
#     kernel-minted query-context token before honoring any stamped fact.
#   * cognic-skill-customer-data@v0.1.0   — instruction skill; teaches scope
#     retail_analytics (RETAIL_ANALYTICS.V_CUSTOMER_DEPOSITS + V_CUSTOMER_PROFILE).
#   * cognic-skill-financial-data@v0.1.0  — instruction skill; teaches scope
#     financials (FIN.V_GL_BALANCES + V_BRANCH_PNL).
#   * cognic-skill-cards-data@v0.1.0      — instruction skill; teaches scope
#     cards_analytics (CARDS.V_CARD_ACCOUNTS + V_CARD_SPEND).
#   * cognic-skill-atm-recon@v0.1.0       — instruction skill; teaches scope
#     atm_recon (CARDS.V_ATM_SETTLEMENTS + V_ATM_DISPUTES). Released + hosted
#     but NEVER granted to the agent and NEVER entitled to any analyst — the
#     standing BAR-2 negative.
#   * cognic-agent-bank-analyst@v0.1.0    — the declarative agent pack (persona
#     AGENT.md + inert marker; NO agent code). Trust-registered at boot against
#     its per-pack DUAL root: cosign.pub (wheel signature) + agent-card.pub
#     (the AgentCard-JWS trust root — the JWS is NEVER verified against
#     cosign.pub per the M8 finding-#4 custody split). agent-card.jws +
#     agent-card.json are staged for standalone verification.
#
#   PLUS ONE REUSED M5 RELEASE (dependency, byte-identical M5/M6 pins):
#   * cognic-hook-schema-guard@v0.1.0     — the M5 signed hook pack. REQUIRED
#     even though M8 adds no hook bar: the oracle v0.3.0 wheel's baked manifest
#     declares [data_governance].dlp_pre_hooks = ["refuse_forbidden_schema_arg",
#     "explode_schema_guard"] — with the hook pack absent, EVERY governed call
#     to the tool fail-closes at the DLP gate (MCPHost: dlp_pre_hooks declared
#     but unresolvable -> fail closed) and BAR 1 could never pass. Same
#     rationale + same pins as infra/proof-m6/stage-packs.sh.
#
# All instruction skills ride the B2-pre manifest-walk discovery arm (content
# packs — no entry point); the agent pack rides the cognic.agents entry-point
# arm (inert marker only). All SEVEN wheels are pip-installed into the kernel
# venv; the oracle wheel additionally feeds Dockerfile.oracle-pack.
#
# Mirrors infra/proof-m6/stage-packs.sh (download via `gh release download`
# with retry -> sha256-verify EVERY pinned digest fail-closed -> arrange the
# staging tree the Dockerfiles consume). run-proof-m85.sh (Task C2) calls this
# at its stage step:  bash infra/proof-m85/stage-packs.sh <staging-dst>
#
# Staging tree produced (all paths relative to <staging-dst>):
#   wheel/<all seven wheels>                              -> pip install into the kernel venv
#                                                            (oracle wheel also feeds Dockerfile.oracle-pack)
#   pack-attestations/<pack_id>/<version>/                -> wheel + the 7 attestations, all seven packs
#   trust-roots/_default/cosign.pub                       -> the ORACLE pack key (the kernel's LOCKED
#                                                            boot convention <prefix>/_default/cosign.pub
#                                                            for tools-kind packs, registry_boot.py, AND
#                                                            the approve 5-gate's signature root)
#   trust-roots/hook-packs/cognic-hook-schema-guard/cosign.pub
#                                                         -> the HOOK pack key (M5 layout, unchanged)
#   trust-roots/skill-packs/<pack_id>/cosign.pub          -> ONE key PER skill pack (four distinct
#                                                            signers; harness/registry_boot.py
#                                                            _SKILL_PACK_TRUST_ROOT_SUBDIR = "skill-packs")
#   trust-roots/agent-packs/cognic-agent-bank-analyst/cosign.pub
#                                                         -> the AGENT pack cosign key (M8 A9 layout;
#                                                            registry_boot.py _AGENT_PACK_TRUST_ROOT_SUBDIR
#                                                            = "agent-packs")
#   trust-roots/agent-packs/cognic-agent-bank-analyst/agent-card.pub
#                                                         -> the AgentCard-JWS trust root (dual-root
#                                                            shape; Settings.agent_card_jws_trust_root_path
#                                                            points here — NEVER cosign.pub)
#   agent-cards/cognic-agent-bank-analyst/agent-card.jws  -> the released signed AgentCard
#   agent-cards/cognic-agent-bank-analyst/agent-card.json -> the card JSON (standalone verification)
#   staged-digests.sha256                                 -> stage-time digest record: EVERY staged
#                                                            asset's sha256 as staged (incl.
#                                                            agent-card.json, which has no locked pin
#                                                            — computed + recorded here at stage time)
#   policies/plugin_allowlist.json                        -> ALL SEVEN pack ids under "_default"
#   alembic.ini                                           -> the deployed migration config
#
# NOTE: the query-context keypair + the proof CANONICAL-IMAGE trust material
# are NOT staged here — the runner (Task C2) generates them AFTER this script
# and BEFORE the image builds (proof-m85-staging/query-context/ carries ONLY
# the PUBLIC PEM into the build contexts; the PRIVATE key is staged to a
# runtime mount/secret path and NEVER enters any image layer), because key
# material is minted per proof run while THIS script stages only released,
# pinned bytes.
set -euo pipefail

ORACLE_REPO="bmzee/cognic-tool-oracle-schema"
ORACLE_TAG="v0.3.0"
ORACLE_VERSION="0.3.0"
ORACLE_PACK_ID="cognic-tool-oracle-schema"
ORACLE_WHEEL="cognic_tool_oracle_schema-0.3.0-py3-none-any.whl"
# Release-asset digests — maintainer-locked C1 pins. A mismatch means the
# release moved under us: FAIL CLOSED, never re-pin silently.
ORACLE_WHEEL_SHA256="a520e4374408513033d589e68cfff2011cbc129575de82147a40427ee3e4a4ed"
ORACLE_PUB_SHA256="43c33fbe7f4b16683d47886b81cb1b9684495cbb9a92989b10f5b8cd72ba2e78"  # unchanged since v0.1.0

CUSTOMER_REPO="bmzee/cognic-skill-customer-data"
CUSTOMER_TAG="v0.1.0"
CUSTOMER_VERSION="0.1.0"
CUSTOMER_PACK_ID="cognic-skill-customer-data"
CUSTOMER_WHEEL="cognic_skill_customer_data-0.1.0-py3-none-any.whl"
CUSTOMER_WHEEL_SHA256="253e1d83f9e2507cf65abf7993795fa42dc86bd1f60f7545ad805dd85c99d41c"
CUSTOMER_PUB_SHA256="2ac85879bf0bc8bb01fac6547210c0ae1b391af789614785cd02240486dbe499"

FINANCIAL_REPO="bmzee/cognic-skill-financial-data"
FINANCIAL_TAG="v0.1.0"
FINANCIAL_VERSION="0.1.0"
FINANCIAL_PACK_ID="cognic-skill-financial-data"
FINANCIAL_WHEEL="cognic_skill_financial_data-0.1.0-py3-none-any.whl"
FINANCIAL_WHEEL_SHA256="15b26a81911b0704965aaf5b4287c0a26feb01a0107e89d9cbc0b420eb416567"
FINANCIAL_PUB_SHA256="dc3a1f0f0477b3ceb2699d8654a01432214abe034834a394424b7b124913e34d"

CARDS_REPO="bmzee/cognic-skill-cards-data"
CARDS_TAG="v0.1.0"
CARDS_VERSION="0.1.0"
CARDS_PACK_ID="cognic-skill-cards-data"
CARDS_WHEEL="cognic_skill_cards_data-0.1.0-py3-none-any.whl"
CARDS_WHEEL_SHA256="a4b6f4c3ad330a116be47a59eec16fcb1f1b93904d41361c8e607bcfca5f154b"
CARDS_PUB_SHA256="99307c338f8922937e9bed3dcbcd014621eadc4980b8d78acc1a89fe7ff001e6"

ATMRECON_REPO="bmzee/cognic-skill-atm-recon"
ATMRECON_TAG="v0.1.0"
ATMRECON_VERSION="0.1.0"
ATMRECON_PACK_ID="cognic-skill-atm-recon"
ATMRECON_WHEEL="cognic_skill_atm_recon-0.1.0-py3-none-any.whl"
ATMRECON_WHEEL_SHA256="f53e290ad61b614ec4ba55f9c7d7e86f0e7e7b6870595492d5251092dd35c7ad"
ATMRECON_PUB_SHA256="e1b0c58aa95a355bb418a5ef7b847dc7702145babd280e6db521137f46fe0c59"

AGENT_REPO="bmzee/cognic-agent-bank-analyst"
AGENT_TAG="v0.1.0"
AGENT_VERSION="0.1.0"
AGENT_PACK_ID="cognic-agent-bank-analyst"
AGENT_WHEEL="cognic_agent_bank_analyst-0.1.0-py3-none-any.whl"
AGENT_WHEEL_SHA256="77be5140a11e25970b28e13be9df9d33d4cf7f16ee267d27061e09fa96bcdec9"
AGENT_PUB_SHA256="532fe8e2181008be86a06c19c3552aedd901a74fd9da3f405ab8e119e783929e"
# The dual-root + card assets (M8 finding-#4 custody split: agent-card.pub is
# the JWS trust root, a SEPARATE cryptographic identity from cosign.pub).
AGENT_CARD_PUB_SHA256="c691d31693459a52226d7190b07dd07e1fdb21a1abdf0324a9225c7c2558d214"
AGENT_CARD_JWS_SHA256="71207eaf5956d08a0b9bc1381bce75113478295c5b968c18b600dc16efb0e13a"
# agent-card.json carries NO locked pin — its digest is computed + recorded at
# stage time into staged-digests.sha256 (the proof-m6 stage-time pattern).

HOOK_REPO="bmzee/cognic-hook-schema-guard"
HOOK_TAG="v0.1.0"
HOOK_VERSION="0.1.0"
HOOK_PACK_ID="cognic-hook-schema-guard"
HOOK_WHEEL="cognic_hook_schema_guard-0.1.0-py3-none-any.whl"
# Byte-identical to the M5/M6 pins (same release, reused as the DLP dependency).
HOOK_WHEEL_SHA256="1cc4d8001571db22d3e8686a213b33a99a4f2fa79a14754ed7dc194077134432"
HOOK_PUB_SHA256="e8a8fd3c046c0697e0470858f3033c9238a4228c4c519952b00d31aab8908e49"

# The 7-attestation released-bundle contract (identical to the M3..M6 shape).
ATTESTATIONS=(
  "cosign.sig"
  "bundle.sigstore"
  "sbom.cdx.json"
  "slsa-provenance.intoto.json"
  "intoto-layout.json"
  "vuln-scan.json"
  "license-audit.json"
)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGING_DST="${1:-$REPO_ROOT/infra/proof-m85/proof-m85-staging}"

die() { echo "FAIL: $*" >&2; exit 1; }

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

_sha256() {
  # portable: linux ships sha256sum, macOS ships shasum
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

_download_release() {
  # _download_release <repo> <tag> <dst-dir> — gh release download with retry
  # (mirrors the M5/M6 stager: 5 attempts, 3s backoff).
  local repo="$1" tag="$2" dst="$3"
  mkdir -p "$dst"
  local max=5 attempt=1
  while true; do
    if gh release download "$tag" --repo "$repo" --dir "$dst" --clobber; then
      return 0
    fi
    if [ "$attempt" -ge "$max" ]; then
      die "gh release download failed after $attempt attempts: $repo@$tag"
    fi
    echo "gh release download failed for $repo@$tag (attempt $attempt/$max); retrying in 3s" >&2
    attempt=$((attempt + 1))
    sleep 3
  done
}

_verify_digest() {
  # _verify_digest <file> <expected-sha256> <label> — FAIL CLOSED on mismatch.
  local file="$1" expected="$2" label="$3" got
  [ -s "$file" ] || die "$label missing or empty: $file"
  got="$(_sha256 "$file")"
  if [ "$got" != "$expected" ]; then
    die "$label sha256 mismatch: got $got expected $expected ($file)"
  fi
  echo "  digest OK: $label $expected"
}

_verify_attestations_present() {
  # every released attestation file must exist + be non-empty (mirrors the
  # resolver's present+non-empty contract before anything is staged).
  local src="$1" label="$2" name
  for name in "${ATTESTATIONS[@]}"; do
    [ -s "$src/$name" ] || die "$label attestation missing or empty: $src/$name"
  done
}

_stage_pack_attestations() {
  # _stage_pack_attestations <src> <pack-id> <version> <wheel> — the per-pack
  # attestation tree resolve_pack_attestations() walks at boot registration:
  # <pack-attestation-root>/<distribution_name>/<version>/{wheel + 7 attestations}.
  local src="$1" pack_id="$2" version="$3" wheel="$4" name
  local att="$STAGING_DST/pack-attestations/$pack_id/$version"
  mkdir -p "$att"
  cp "$src/$wheel" "$att/$wheel"
  for name in "${ATTESTATIONS[@]}"; do
    cp "$src/$name" "$att/$name"
  done
}

_record_staged_digest() {
  # _record_staged_digest <file> <label> — compute + record the sha256 of a
  # STAGED asset at stage time (the proof-m6 stage-time pattern; used for
  # assets without a maintainer-locked pin, e.g. agent-card.json, AND as the
  # examiner record of every staged byte).
  local file="$1" label="$2" got
  [ -s "$file" ] || die "staged asset missing or empty: $file ($label)"
  got="$(_sha256 "$file")"
  printf '%s  %s\n' "$got" "$label" >> "$STAGING_DST/staged-digests.sha256"
  echo "  staged digest recorded: $label $got"
}

echo "==> stage-packs: download the seven released packs (released assets only, never built here)"
ORACLE_SRC="$TMP/oracle"
CUSTOMER_SRC="$TMP/customer"
FINANCIAL_SRC="$TMP/financial"
CARDS_SRC="$TMP/cards"
ATMRECON_SRC="$TMP/atmrecon"
AGENT_SRC="$TMP/agent"
HOOK_SRC="$TMP/hook"
_download_release "$ORACLE_REPO" "$ORACLE_TAG" "$ORACLE_SRC"
_download_release "$CUSTOMER_REPO" "$CUSTOMER_TAG" "$CUSTOMER_SRC"
_download_release "$FINANCIAL_REPO" "$FINANCIAL_TAG" "$FINANCIAL_SRC"
_download_release "$CARDS_REPO" "$CARDS_TAG" "$CARDS_SRC"
_download_release "$ATMRECON_REPO" "$ATMRECON_TAG" "$ATMRECON_SRC"
_download_release "$AGENT_REPO" "$AGENT_TAG" "$AGENT_SRC"
_download_release "$HOOK_REPO" "$HOOK_TAG" "$HOOK_SRC"

echo "==> stage-packs: sha256-verify every pinned release digest (fail-closed)"
_verify_digest "$ORACLE_SRC/$ORACLE_WHEEL" "$ORACLE_WHEEL_SHA256" "$ORACLE_PACK_ID wheel"
_verify_digest "$ORACLE_SRC/cosign.pub" "$ORACLE_PUB_SHA256" "$ORACLE_PACK_ID cosign.pub"
_verify_digest "$CUSTOMER_SRC/$CUSTOMER_WHEEL" "$CUSTOMER_WHEEL_SHA256" "$CUSTOMER_PACK_ID wheel"
_verify_digest "$CUSTOMER_SRC/cosign.pub" "$CUSTOMER_PUB_SHA256" "$CUSTOMER_PACK_ID cosign.pub"
_verify_digest "$FINANCIAL_SRC/$FINANCIAL_WHEEL" "$FINANCIAL_WHEEL_SHA256" "$FINANCIAL_PACK_ID wheel"
_verify_digest "$FINANCIAL_SRC/cosign.pub" "$FINANCIAL_PUB_SHA256" "$FINANCIAL_PACK_ID cosign.pub"
_verify_digest "$CARDS_SRC/$CARDS_WHEEL" "$CARDS_WHEEL_SHA256" "$CARDS_PACK_ID wheel"
_verify_digest "$CARDS_SRC/cosign.pub" "$CARDS_PUB_SHA256" "$CARDS_PACK_ID cosign.pub"
_verify_digest "$ATMRECON_SRC/$ATMRECON_WHEEL" "$ATMRECON_WHEEL_SHA256" "$ATMRECON_PACK_ID wheel"
_verify_digest "$ATMRECON_SRC/cosign.pub" "$ATMRECON_PUB_SHA256" "$ATMRECON_PACK_ID cosign.pub"
_verify_digest "$AGENT_SRC/$AGENT_WHEEL" "$AGENT_WHEEL_SHA256" "$AGENT_PACK_ID wheel"
_verify_digest "$AGENT_SRC/cosign.pub" "$AGENT_PUB_SHA256" "$AGENT_PACK_ID cosign.pub"
_verify_digest "$AGENT_SRC/agent-card.pub" "$AGENT_CARD_PUB_SHA256" "$AGENT_PACK_ID agent-card.pub"
_verify_digest "$AGENT_SRC/agent-card.jws" "$AGENT_CARD_JWS_SHA256" "$AGENT_PACK_ID agent-card.jws"
_verify_digest "$HOOK_SRC/$HOOK_WHEEL" "$HOOK_WHEEL_SHA256" "$HOOK_PACK_ID wheel"
_verify_digest "$HOOK_SRC/cosign.pub" "$HOOK_PUB_SHA256" "$HOOK_PACK_ID cosign.pub"
_verify_attestations_present "$ORACLE_SRC" "$ORACLE_PACK_ID"
_verify_attestations_present "$CUSTOMER_SRC" "$CUSTOMER_PACK_ID"
_verify_attestations_present "$FINANCIAL_SRC" "$FINANCIAL_PACK_ID"
_verify_attestations_present "$CARDS_SRC" "$CARDS_PACK_ID"
_verify_attestations_present "$ATMRECON_SRC" "$ATMRECON_PACK_ID"
_verify_attestations_present "$AGENT_SRC" "$AGENT_PACK_ID"
_verify_attestations_present "$HOOK_SRC" "$HOOK_PACK_ID"

echo "==> stage-packs: arrange the staging tree at $STAGING_DST"
rm -rf "$STAGING_DST"
mkdir -p "$STAGING_DST/wheel"
: > "$STAGING_DST/staged-digests.sha256"
# ALL SEVEN wheels: Dockerfile.agentos-proof pip-installs wheel/*.whl into the
# kernel venv (the oracle pack's cognic.tools entry point + the hook pack's
# cognic.hooks entry points + the agent pack's cognic.agents inert marker
# become boot-discoverable; the four INSTRUCTION skill packs carry NO entry
# point and are discovered by the B2-pre manifest-walk arm over the installed
# distributions). Dockerfile.oracle-pack additionally installs the oracle
# wheel into the standalone MCP tool Service image.
cp "$ORACLE_SRC/$ORACLE_WHEEL" "$STAGING_DST/wheel/$ORACLE_WHEEL"
cp "$CUSTOMER_SRC/$CUSTOMER_WHEEL" "$STAGING_DST/wheel/$CUSTOMER_WHEEL"
cp "$FINANCIAL_SRC/$FINANCIAL_WHEEL" "$STAGING_DST/wheel/$FINANCIAL_WHEEL"
cp "$CARDS_SRC/$CARDS_WHEEL" "$STAGING_DST/wheel/$CARDS_WHEEL"
cp "$ATMRECON_SRC/$ATMRECON_WHEEL" "$STAGING_DST/wheel/$ATMRECON_WHEEL"
cp "$AGENT_SRC/$AGENT_WHEEL" "$STAGING_DST/wheel/$AGENT_WHEEL"
cp "$HOOK_SRC/$HOOK_WHEEL" "$STAGING_DST/wheel/$HOOK_WHEEL"

_stage_pack_attestations "$ORACLE_SRC" "$ORACLE_PACK_ID" "$ORACLE_VERSION" "$ORACLE_WHEEL"
_stage_pack_attestations "$CUSTOMER_SRC" "$CUSTOMER_PACK_ID" "$CUSTOMER_VERSION" "$CUSTOMER_WHEEL"
_stage_pack_attestations "$FINANCIAL_SRC" "$FINANCIAL_PACK_ID" "$FINANCIAL_VERSION" "$FINANCIAL_WHEEL"
_stage_pack_attestations "$CARDS_SRC" "$CARDS_PACK_ID" "$CARDS_VERSION" "$CARDS_WHEEL"
_stage_pack_attestations "$ATMRECON_SRC" "$ATMRECON_PACK_ID" "$ATMRECON_VERSION" "$ATMRECON_WHEEL"
_stage_pack_attestations "$AGENT_SRC" "$AGENT_PACK_ID" "$AGENT_VERSION" "$AGENT_WHEEL"
_stage_pack_attestations "$HOOK_SRC" "$HOOK_PACK_ID" "$HOOK_VERSION" "$HOOK_WHEEL"

# Trust roots — SEVEN DISTINCT SIGNERS under one COGNIC_TRUST_ROOT_PREFIX
# (trust_gate.py path containment):
#   * the LOCKED _default convention carries the ORACLE key (tools-kind packs
#     verify against <prefix>/_default/cosign.pub; also the approve 5-gate's
#     signature root);
#   * the HOOK key is per-pack under hook-packs/ (M5 layout);
#   * each SKILL key is per-pack under skill-packs/ (registry_boot
#     _SKILL_PACK_TRUST_ROOT_SUBDIR);
#   * the AGENT key is per-pack under agent-packs/ (M8 A9 layout,
#     _AGENT_PACK_TRUST_ROOT_SUBDIR) — PLUS the dual-root agent-card.pub
#     (the AgentCard-JWS trust root; Settings.agent_card_jws_trust_root_path)
#     staged NEXT TO the cosign key so both canonicalise under the prefix.
mkdir -p "$STAGING_DST/trust-roots/_default"
cp "$ORACLE_SRC/cosign.pub" "$STAGING_DST/trust-roots/_default/cosign.pub"
mkdir -p "$STAGING_DST/trust-roots/hook-packs/$HOOK_PACK_ID"
cp "$HOOK_SRC/cosign.pub" "$STAGING_DST/trust-roots/hook-packs/$HOOK_PACK_ID/cosign.pub"
mkdir -p "$STAGING_DST/trust-roots/skill-packs/$CUSTOMER_PACK_ID"
cp "$CUSTOMER_SRC/cosign.pub" "$STAGING_DST/trust-roots/skill-packs/$CUSTOMER_PACK_ID/cosign.pub"
mkdir -p "$STAGING_DST/trust-roots/skill-packs/$FINANCIAL_PACK_ID"
cp "$FINANCIAL_SRC/cosign.pub" "$STAGING_DST/trust-roots/skill-packs/$FINANCIAL_PACK_ID/cosign.pub"
mkdir -p "$STAGING_DST/trust-roots/skill-packs/$CARDS_PACK_ID"
cp "$CARDS_SRC/cosign.pub" "$STAGING_DST/trust-roots/skill-packs/$CARDS_PACK_ID/cosign.pub"
mkdir -p "$STAGING_DST/trust-roots/skill-packs/$ATMRECON_PACK_ID"
cp "$ATMRECON_SRC/cosign.pub" "$STAGING_DST/trust-roots/skill-packs/$ATMRECON_PACK_ID/cosign.pub"
mkdir -p "$STAGING_DST/trust-roots/agent-packs/$AGENT_PACK_ID"
cp "$AGENT_SRC/cosign.pub" "$STAGING_DST/trust-roots/agent-packs/$AGENT_PACK_ID/cosign.pub"
cp "$AGENT_SRC/agent-card.pub" "$STAGING_DST/trust-roots/agent-packs/$AGENT_PACK_ID/agent-card.pub"

# The released AgentCard (JWS + JSON) — staged where the proof needs
# standalone verification (verify the JWS against agent-card.pub, never
# cosign.pub). agent-card.json has NO maintainer-locked pin: its digest is
# computed + recorded at stage time (fail-loud if the release lacks it).
mkdir -p "$STAGING_DST/agent-cards/$AGENT_PACK_ID"
cp "$AGENT_SRC/agent-card.jws" "$STAGING_DST/agent-cards/$AGENT_PACK_ID/agent-card.jws"
[ -s "$AGENT_SRC/agent-card.json" ] || die "$AGENT_PACK_ID agent-card.json missing from the release assets"
cp "$AGENT_SRC/agent-card.json" "$STAGING_DST/agent-cards/$AGENT_PACK_ID/agent-card.json"

# Stage-time digest record — every staged asset, one line each (the assets
# with locked pins were already fail-closed-verified above; recording them
# again here gives the examiner ONE flat record of the staged bytes).
_record_staged_digest "$STAGING_DST/wheel/$ORACLE_WHEEL" "wheel/$ORACLE_WHEEL"
_record_staged_digest "$STAGING_DST/wheel/$CUSTOMER_WHEEL" "wheel/$CUSTOMER_WHEEL"
_record_staged_digest "$STAGING_DST/wheel/$FINANCIAL_WHEEL" "wheel/$FINANCIAL_WHEEL"
_record_staged_digest "$STAGING_DST/wheel/$CARDS_WHEEL" "wheel/$CARDS_WHEEL"
_record_staged_digest "$STAGING_DST/wheel/$ATMRECON_WHEEL" "wheel/$ATMRECON_WHEEL"
_record_staged_digest "$STAGING_DST/wheel/$AGENT_WHEEL" "wheel/$AGENT_WHEEL"
_record_staged_digest "$STAGING_DST/wheel/$HOOK_WHEEL" "wheel/$HOOK_WHEEL"
_record_staged_digest "$STAGING_DST/trust-roots/agent-packs/$AGENT_PACK_ID/agent-card.pub" \
  "trust-roots/agent-packs/$AGENT_PACK_ID/agent-card.pub"
_record_staged_digest "$STAGING_DST/agent-cards/$AGENT_PACK_ID/agent-card.jws" \
  "agent-cards/$AGENT_PACK_ID/agent-card.jws"
_record_staged_digest "$STAGING_DST/agent-cards/$AGENT_PACK_ID/agent-card.json" \
  "agent-cards/$AGENT_PACK_ID/agent-card.json"

# Per-tenant plugin allow-list: ALL SEVEN released packs admitted for the
# _default tenant (registration refuses not_in_tenant_allowlist otherwise).
mkdir -p "$STAGING_DST/policies"
printf '{"_default": ["%s", "%s", "%s", "%s", "%s", "%s", "%s"]}\n' \
  "$ORACLE_PACK_ID" "$HOOK_PACK_ID" "$CUSTOMER_PACK_ID" "$FINANCIAL_PACK_ID" \
  "$CARDS_PACK_ID" "$ATMRECON_PACK_ID" "$AGENT_PACK_ID" \
  > "$STAGING_DST/policies/plugin_allowlist.json"

cp "$REPO_ROOT/alembic.ini" "$STAGING_DST/alembic.ini"

# world-readable (+ dir-traversable) so the non-root user in each image can
# read everything COPY'd from this tree (mirrors the M5/M6 chmod pass).
chmod -R a+rX "$STAGING_DST"

echo "staged released $ORACLE_PACK_ID@$ORACLE_VERSION + $HOOK_PACK_ID@$HOOK_VERSION + 4 instruction-skill packs@0.1.0 + $AGENT_PACK_ID@$AGENT_VERSION -> $STAGING_DST"
