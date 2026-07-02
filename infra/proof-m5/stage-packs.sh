#!/usr/bin/env bash
# infra/proof-m5/stage-packs.sh — stage the TWO RELEASED, signed packs for the M5
# (hook-pack DLP) proof. RELEASED ASSETS ONLY (never a source rebuild):
#
#   * cognic-tool-oracle-schema@v0.2.0  — the DLP-governed re-release of the M3/M4
#     tool (its [data_governance].dlp_pre_hooks binds the two schema-guard hooks).
#     Operator-installed via the M4 lifecycle flow by the runner.
#   * cognic-hook-schema-guard@v0.1.0   — the signed hook pack (two dlp_pre hooks,
#     zero runtime deps by design). Baked into the KERNEL image + trust-registered
#     only — NEVER operator-installed (spec §6 decision B).
#
# Mirrors tests/integration/proof_m4/stage_released_pack.py (download via
# `gh release download` with retry -> sha256-verify EVERY pinned digest ->
# arrange the staging tree Dockerfile.agentos-proof / Dockerfile.oracle-pack
# consume) — relocated to a proof-owned shell script so the whole M5 staging
# contract lives under infra/proof-m5/. run-proof-m5.sh (Task 10) calls this
# at its stage step:  bash infra/proof-m5/stage-packs.sh <staging-dst>
#
# Staging tree produced (all paths relative to <staging-dst>):
#   wheel/<both wheels>                                   -> pip install into the kernel venv
#                                                            (oracle wheel also feeds Dockerfile.oracle-pack)
#   pack-attestations/cognic-tool-oracle-schema/0.2.0/    -> wheel + the 7 attestations
#   pack-attestations/cognic-hook-schema-guard/0.1.0/     -> wheel + the 7 attestations
#   trust-roots/_default/cosign.pub                       -> the ORACLE pack key (the kernel's LOCKED
#                                                            boot convention <prefix>/_default/cosign.pub,
#                                                            registry_boot.py, AND the approve 5-gate's
#                                                            signature root via ProofStagedTrustRootResolver)
#   trust-roots/hook-packs/cognic-hook-schema-guard/cosign.pub
#                                                         -> the HOOK pack key. The two released packs are
#                                                            signed with DIFFERENT cosign keys, and the stock
#                                                            boot loop verifies every pack against the single
#                                                            _default key — so the hook key is staged at a
#                                                            per-pack path that still canonicalises under
#                                                            COGNIC_TRUST_ROOT_PREFIX (trust_gate.py:516) for
#                                                            the proof app's per-pack hook trust-registration.
#                                                            NOT a tenant directory.
#   policies/plugin_allowlist.json                        -> BOTH pack ids under "_default"
#   alembic.ini                                           -> the deployed migration config
set -euo pipefail

ORACLE_REPO="bmzee/cognic-tool-oracle-schema"
ORACLE_TAG="v0.2.0"
ORACLE_VERSION="0.2.0"
ORACLE_PACK_ID="cognic-tool-oracle-schema"
ORACLE_WHEEL="cognic_tool_oracle_schema-0.2.0-py3-none-any.whl"
# Release-asset digests — pinned the way stage_released_pack.py pinned v0.1.0.
# A mismatch means the release moved under us: FAIL CLOSED, never re-pin silently.
ORACLE_WHEEL_SHA256="2961ce5d4aaf97425ab5851670f65e76c64164a5922b99d6f0e982a634be0439"
ORACLE_PUB_SHA256="43c33fbe7f4b16683d47886b81cb1b9684495cbb9a92989b10f5b8cd72ba2e78"  # unchanged from v0.1.0

HOOK_REPO="bmzee/cognic-hook-schema-guard"
HOOK_TAG="v0.1.0"
HOOK_VERSION="0.1.0"
HOOK_PACK_ID="cognic-hook-schema-guard"
HOOK_WHEEL="cognic_hook_schema_guard-0.1.0-py3-none-any.whl"
HOOK_WHEEL_SHA256="1cc4d8001571db22d3e8686a213b33a99a4f2fa79a14754ed7dc194077134432"
HOOK_PUB_SHA256="e8a8fd3c046c0697e0470858f3033c9238a4228c4c519952b00d31aab8908e49"

# The 7-attestation released-bundle contract (identical to the M3/M4 release shape).
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
STAGING_DST="${1:-$REPO_ROOT/infra/proof-m5/proof-m5-staging}"

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
  # (mirrors stage_released_pack.download: 5 attempts, 3s backoff).
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

echo "==> stage-packs: download the two released packs (released assets only, never built here)"
ORACLE_SRC="$TMP/oracle"
HOOK_SRC="$TMP/hook"
_download_release "$ORACLE_REPO" "$ORACLE_TAG" "$ORACLE_SRC"
_download_release "$HOOK_REPO" "$HOOK_TAG" "$HOOK_SRC"

echo "==> stage-packs: sha256-verify every pinned release digest (fail-closed)"
_verify_digest "$ORACLE_SRC/$ORACLE_WHEEL" "$ORACLE_WHEEL_SHA256" "$ORACLE_PACK_ID wheel"
_verify_digest "$ORACLE_SRC/cosign.pub" "$ORACLE_PUB_SHA256" "$ORACLE_PACK_ID cosign.pub"
_verify_digest "$HOOK_SRC/$HOOK_WHEEL" "$HOOK_WHEEL_SHA256" "$HOOK_PACK_ID wheel"
_verify_digest "$HOOK_SRC/cosign.pub" "$HOOK_PUB_SHA256" "$HOOK_PACK_ID cosign.pub"
_verify_attestations_present "$ORACLE_SRC" "$ORACLE_PACK_ID"
_verify_attestations_present "$HOOK_SRC" "$HOOK_PACK_ID"

echo "==> stage-packs: arrange the staging tree at $STAGING_DST"
rm -rf "$STAGING_DST"
mkdir -p "$STAGING_DST/wheel"
# BOTH wheels: Dockerfile.agentos-proof pip-installs wheel/*.whl into the kernel
# venv (the hook pack's cognic.hooks entry points + the oracle pack's cognic.tools
# entry point become boot-discoverable); Dockerfile.oracle-pack additionally
# installs the oracle wheel into the standalone MCP tool Service image.
cp "$ORACLE_SRC/$ORACLE_WHEEL" "$STAGING_DST/wheel/$ORACLE_WHEEL"
cp "$HOOK_SRC/$HOOK_WHEEL" "$STAGING_DST/wheel/$HOOK_WHEEL"

_stage_pack_attestations "$ORACLE_SRC" "$ORACLE_PACK_ID" "$ORACLE_VERSION" "$ORACLE_WHEEL"
_stage_pack_attestations "$HOOK_SRC" "$HOOK_PACK_ID" "$HOOK_VERSION" "$HOOK_WHEEL"

# Trust roots — TWO DISTINCT KEYS (see the header note): the LOCKED _default
# convention carries the ORACLE key; the hook key is staged per-pack under the
# same prefix so it canonicalises for the hook pack's trust registration.
mkdir -p "$STAGING_DST/trust-roots/_default"
cp "$ORACLE_SRC/cosign.pub" "$STAGING_DST/trust-roots/_default/cosign.pub"
mkdir -p "$STAGING_DST/trust-roots/hook-packs/$HOOK_PACK_ID"
cp "$HOOK_SRC/cosign.pub" "$STAGING_DST/trust-roots/hook-packs/$HOOK_PACK_ID/cosign.pub"

# Per-tenant plugin allow-list: BOTH released packs admitted for the _default
# tenant (registration refuses not_in_tenant_allowlist otherwise).
mkdir -p "$STAGING_DST/policies"
printf '{"_default": ["%s", "%s"]}\n' "$ORACLE_PACK_ID" "$HOOK_PACK_ID" \
  > "$STAGING_DST/policies/plugin_allowlist.json"

cp "$REPO_ROOT/alembic.ini" "$STAGING_DST/alembic.ini"

# world-readable (+ dir-traversable) so the non-root cognic user in the image can
# read everything COPY'd from this tree (mirrors stage_released_pack's chmod pass).
chmod -R a+rX "$STAGING_DST"

echo "staged released $ORACLE_PACK_ID@$ORACLE_VERSION + $HOOK_PACK_ID@$HOOK_VERSION -> $STAGING_DST"
