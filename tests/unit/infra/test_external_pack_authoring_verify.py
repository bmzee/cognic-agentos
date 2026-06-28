"""M3-E1 — structural gate for the external-pack-authoring verification script.

Pins the operator-run verify script's load-bearing invariants OFFLINE — without
running it (it is env-gated behind ``COGNIC_RUN_EXTERNAL_PACK_ENABLEMENT=1`` and
git-installs the kernel + spins a venv). Mirrors the proof-harness structural
tests (``tests/unit/proof_1b_2/test_proof_runner.py``). The script proves a
clean external pack repo can obtain the unpublished AgentOS CLI via the
git-pinned install + run ``agentos validate`` (+ sign/verify when the
supply-chain binaries exist).
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCRIPT = _REPO_ROOT / "infra" / "external-pack-authoring" / "verify.sh"

_GATE_GUARD = 'if [[ "${COGNIC_RUN_EXTERNAL_PACK_ENABLEMENT:-}" != "1" ]]; then'


def _text() -> str:
    return _SCRIPT.read_text()


def test_script_exists() -> None:
    assert _SCRIPT.is_file(), f"verify script not found at {_SCRIPT}"


def test_script_is_strict_bash() -> None:
    text = _text()
    assert text.startswith("#!/usr/bin/env bash"), "must start with the bash shebang"
    assert "set -euo pipefail" in text, "must `set -euo pipefail`"


def test_script_is_env_gated_and_inert_by_default() -> None:
    # Off by default: the env gate makes the script a no-op (exit 0) unless the
    # operator opts in, so it never git-installs / spins a venv in normal CI.
    text = _text()
    assert "COGNIC_RUN_EXTERNAL_PACK_ENABLEMENT" in text
    assert _GATE_GUARD in text, "must carry the COGNIC_RUN_EXTERNAL_PACK_ENABLEMENT != 1 gate guard"
    start = text.index(_GATE_GUARD)
    end = text.index("\nfi", start)
    assert "exit 0" in text[start:end], "must exit 0 cleanly when the gate is unset"


def test_script_git_installs_the_kernel_not_local_editable() -> None:
    # The whole point: prove EXTERNAL consumption via the git form, not a local
    # editable that would mask the unpublished-kernel gap.
    text = _text()
    assert "cognic-agentos @ git+" in text, "must git-install the kernel"
    assert "pip install -e" not in text, "must NOT install the kernel as a local editable"


def test_script_pins_python_312_venv() -> None:
    # M3-E1 closeout finding: the kernel requires >=3.12,<3.13, so the venv MUST be
    # 3.12. The original system `python3 -m venv` used a 3.13+ interpreter and broke.
    text = _text()
    assert "uv venv --python 3.12" in text, (
        "the venv must be pinned to Python 3.12 (the kernel caps at <3.13)"
    )
    # The negative targets the venv-CREATION command, not the explanatory header
    # comment (which legitimately names the rejected pattern): scan non-comment lines.
    code_lines = [ln for ln in text.splitlines() if not ln.lstrip().startswith("#")]
    assert not any("python3 -m venv" in ln for ln in code_lines), (
        "must NOT create the venv with the system python3 — it may be 3.13+ which fails the install"
    )


def test_script_runs_validate_then_conditional_sign_verify() -> None:
    text = _text()
    assert "validate ." in text, "must run agentos validate (the hard proof)"
    assert "sign --bundle ." in text, "must run agentos sign --bundle (conditionally)"
    assert "verify ." in text, "must run agentos verify (conditionally)"


def test_script_records_tooling_absent_not_silent_skip() -> None:
    text = _text()
    # All four binaries `agentos sign --bundle` shells out to — pip-licenses
    # included so the host-tooling gate matches what sign actually needs.
    for bin_name in ("cosign", "syft", "grype", "pip-licenses"):
        assert bin_name in text, f"must check for {bin_name}"
    assert "TOOLING ABSENT" in text or "tooling_absent" in text, (
        "missing supply-chain binaries must be recorded as 'tooling absent', not silently skipped"
    )


def test_script_builds_pack_from_proven_example() -> None:
    assert "examples/cognic-tool-search" in _text(), (
        "the external pack must be built from the proven cognic-tool-search example shape"
    )
