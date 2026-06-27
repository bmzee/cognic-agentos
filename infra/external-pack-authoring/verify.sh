#!/usr/bin/env bash
# External-pack authoring enablement — operator-run verification (PR-1).
#
# Proves a CLEAN external pack repo (the proven examples/cognic-tool-search
# shape — a FastMCP server with NO AgentOS runtime dependency) can obtain the
# UNPUBLISHED AgentOS authoring/governance CLI via the git-pinned install and
# run `agentos validate` (+ `sign --bundle`/`verify` when cosign/syft/grype are
# present). The kernel ships no PyPI/release artifact, so this git form is the
# only external-consumption path; PR-1 makes the scaffolds emit it.
#
# Env-gated — inert unless COGNIC_RUN_EXTERNAL_PACK_ENABLEMENT=1.
# Kernel ref: defaults to the current pushed HEAD SHA (the tag v0.0.1 is cut
# only AFTER PR-1 merges green). At PR-1 closeout, re-run with
# COGNIC_AGENTOS_GIT_REF=v0.0.1 to confirm the exact tag the scaffolds pin.
#
# Missing cosign/syft/grype are recorded as "tooling absent" — NOT silently
# skipped. Record the outcome in docs/VALIDATION-RESULTS.md.
set -euo pipefail

if [[ "${COGNIC_RUN_EXTERNAL_PACK_ENABLEMENT:-}" != "1" ]]; then
  echo "external-pack-authoring verify: inert (set COGNIC_RUN_EXTERNAL_PACK_ENABLEMENT=1 to run)"
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GIT_URL="${COGNIC_AGENTOS_GIT_URL:-https://github.com/bmzee/cognic-agentos}"
GIT_REF="${COGNIC_AGENTOS_GIT_REF:-$(git -C "$REPO_ROOT" rev-parse HEAD)}"
EXAMPLE_PACK="$REPO_ROOT/examples/cognic-tool-search"

[[ -d "$EXAMPLE_PACK" ]] || { echo "FAIL: proven example pack not found at $EXAMPLE_PACK"; exit 1; }

WORK="$(mktemp -d)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "=== external-pack-authoring verify ==="
echo "kernel git install: $GIT_URL @ $GIT_REF"

# 1) Clean external pack repo (the proven shape), staged OUTSIDE the kernel tree.
PACK="$WORK/cognic-tool-search-ext"
mkdir -p "$PACK"
cp -R "$EXAMPLE_PACK"/. "$PACK/"
find "$PACK" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
rm -rf "$PACK/.venv" 2>/dev/null || true
echo "external pack staged at $PACK"

# 2) Fresh venv + git-install the AgentOS CLI (from git only; NO local editable).
python3 -m venv "$WORK/venv"
# shellcheck disable=SC1091
source "$WORK/venv/bin/activate"
python -m pip install --quiet --upgrade pip
echo "installing: cognic-agentos @ git+$GIT_URL@$GIT_REF"
python -m pip install "cognic-agentos @ git+$GIT_URL@$GIT_REF"
command -v agentos >/dev/null || { echo "FAIL: agentos CLI not on PATH after git-install"; exit 1; }
echo "agentos CLI obtained from git: $(command -v agentos)"

# 3) validate — the hard proof (lean; no external binaries). Fail-loud.
echo "=== agentos validate ==="
( cd "$PACK" && agentos validate . )
echo "VALIDATE=pass"

# 4) sign --bundle + verify — best-effort, only when the binaries are present.
MISSING=()
for bin in cosign syft grype; do command -v "$bin" >/dev/null || MISSING+=("$bin"); done
if [[ ${#MISSING[@]} -eq 0 ]]; then
  echo "=== agentos sign --bundle + verify (cosign/syft/grype present) ==="
  ( cd "$PACK" && agentos sign --bundle . && agentos verify . )
  echo "SIGN_VERIFY=ran"
else
  echo "TOOLING ABSENT: ${MISSING[*]} — sign/verify NOT run."
  echo "  (validate alone PROVES external CLI consumption; sign/verify additionally need these"
  echo "   binaries + a cosign signing identity. Record as 'tooling absent', NOT a full pass.)"
  echo "SIGN_VERIFY=tooling_absent:${MISSING[*]}"
fi

echo "=== external-pack-authoring verify: VALIDATE PASS (sign/verify per the tooling line above) ==="
