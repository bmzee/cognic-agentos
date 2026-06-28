#!/usr/bin/env bash
# External-pack authoring enablement — operator-run verification (M3-E1).
#
# Proves a CLEAN external pack repo (the proven examples/cognic-tool-search
# shape — a FastMCP server with NO AgentOS runtime dependency) can obtain the
# UNPUBLISHED AgentOS authoring/governance CLI via the git-pinned install and
# run `agentos validate` (+ `sign --bundle`/`verify` when
# cosign/syft/grype/pip-licenses are present). The kernel ships no
# PyPI/release artifact, so this git form is the only external-consumption
# path; M3-E1 makes the scaffolds emit it.
#
# Env-gated — inert unless COGNIC_RUN_EXTERNAL_PACK_ENABLEMENT=1.
# Kernel ref: defaults to the current pushed HEAD SHA. At closeout, re-run with
# COGNIC_AGENTOS_GIT_REF=v0.0.1 to confirm the exact tag the scaffolds pin.
#
# The venv is pinned to Python 3.12 via `uv venv --python 3.12`: the kernel
# requires `>=3.12,<3.13`, so a system python3 of 3.13+ FAILS the git-install
# (M3-E1 closeout finding — the original `python3 -m venv` used the system
# python and broke on 3.13.1). uv resolves/installs 3.12 reliably.
#
# Missing cosign/syft/grype/pip-licenses are recorded as "tooling absent" —
# NOT silently skipped. Record the outcome in docs/VALIDATION-RESULTS.md.
set -euo pipefail

if [[ "${COGNIC_RUN_EXTERNAL_PACK_ENABLEMENT:-}" != "1" ]]; then
  echo "external-pack-authoring verify: inert (set COGNIC_RUN_EXTERNAL_PACK_ENABLEMENT=1 to run)"
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GIT_URL="${COGNIC_AGENTOS_GIT_URL:-https://github.com/bmzee/cognic-agentos}"
GIT_REF="${COGNIC_AGENTOS_GIT_REF:-$(git -C "$REPO_ROOT" rev-parse HEAD)}"
EXAMPLE_PACK="$REPO_ROOT/examples/cognic-tool-search"

command -v uv >/dev/null || { echo "FAIL: uv not found — required to pin the Python 3.12 venv"; exit 1; }
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

# 2) Fresh Python 3.12 venv + git-install the AgentOS CLI (from git only; NO local
#    editable). The kernel pins >=3.12,<3.13, so the venv MUST be 3.12 — uv pins it.
uv venv --python 3.12 "$WORK/venv"
VENV_PY="$WORK/venv/bin/python"
VENV_AGENTOS="$WORK/venv/bin/agentos"
echo "venv python: $("$VENV_PY" --version)"
echo "installing: cognic-agentos @ git+$GIT_URL@$GIT_REF"
uv pip install --python "$VENV_PY" "cognic-agentos @ git+$GIT_URL@$GIT_REF"
[[ -x "$VENV_AGENTOS" ]] || { echo "FAIL: agentos CLI not present after git-install"; exit 1; }
echo "agentos CLI obtained from git: $VENV_AGENTOS"

# 3) validate — the hard proof (lean; no external binaries). Fail-loud.
echo "=== agentos validate ==="
( cd "$PACK" && "$VENV_AGENTOS" validate . )
echo "VALIDATE=pass"

# 4) sign --bundle + verify — best-effort, only when the binaries are present.
MISSING=()
# All FOUR binaries `agentos sign --bundle` shells out to (cosign sign-blob + syft
# SBOM + grype vuln + pip-licenses license audit). Omitting pip-licenses let the
# script enter the sign branch on a host that has the first three but not the
# auditor → `sign-bundle: FAIL` instead of a clean "tooling absent" (M3-E1 finding).
for bin in cosign syft grype pip-licenses; do command -v "$bin" >/dev/null || MISSING+=("$bin"); done
if [[ ${#MISSING[@]} -eq 0 ]]; then
  echo "=== agentos sign --bundle + verify (cosign/syft/grype/pip-licenses present) ==="
  ( cd "$PACK" && "$VENV_AGENTOS" sign --bundle . && "$VENV_AGENTOS" verify . )
  echo "SIGN_VERIFY=ran"
else
  echo "TOOLING ABSENT: ${MISSING[*]} — sign/verify NOT run."
  echo "  (validate alone PROVES external CLI consumption; sign/verify additionally need these"
  echo "   binaries + a cosign signing identity. Record as 'tooling absent', NOT a full pass.)"
  echo "SIGN_VERIFY=tooling_absent:${MISSING[*]}"
fi

echo "=== external-pack-authoring verify: VALIDATE PASS (sign/verify per the tooling line above) ==="
