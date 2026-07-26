"""D2 post-fix lock for ``protocol/mcp_authz.py``.

ADR-026 D6 originally required M4 to leave this critical authorization
control byte-identical to its base. D2 is the separately reviewed exception:
it adds tenant isolation to the OAuth token cache and in-flight keys. This
guard retains the base-ref/checkout-depth hardening while admitting only the
exact reviewed D2 bytes when the base still contains the tenantless version.

After D2 reaches the base branch, ordinary byte equality resumes. A later
change remains a deliberate, separately reviewed action that must update this
guard's expectation in the same packet.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

import cognic_agentos.protocol.mcp_authz as mcp_authz

_MCP_AUTHZ_REPO_PATH = "src/cognic_agentos/protocol/mcp_authz.py"
_MCP_AUTHZ_REVIEWED_D2_SHA256 = "56e410c8c34472dbd87e3c3e50963b1899cffa3b23949dc870db617033b4dfbd"


def _repo_root() -> Path:
    """Walk up to the repo root (the dir carrying ``pyproject.toml``) — robust to
    the test's nesting depth (no fragile ``parents[N]`` index)."""
    for parent in Path(__file__).resolve().parents:
        if (parent / "pyproject.toml").exists():
            return parent
    raise RuntimeError("repo root (pyproject.toml) not found")  # pragma: no cover


def _git_show(ref: str, repo_path: str) -> bytes | None:
    """Bytes of ``repo_path`` at ``ref``, or None if the ref / path is not
    resolvable (e.g. a shallow clone without the base branch)."""
    try:
        result = subprocess.run(
            ["git", "show", f"{ref}:{repo_path}"],
            cwd=_repo_root(),
            capture_output=True,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - env-dependent
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _in_ci() -> bool:
    """True under GitHub Actions (or generic CI). IN CI the guard MUST NOT skip —
    a skip there would silently weaken the mcp_authz proof at the merge gate."""
    return os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("CI") == "true"


def _base_ref_candidates() -> tuple[str, ...]:
    """Base refs to byte-compare against, most-specific first. On a GitHub PR the
    base branch name lives in ``GITHUB_BASE_REF`` (which may NOT be ``main`` — a
    stacked PR) and the fetched remote-tracking ref is ``origin/<base>``; the
    lint+test job checks out with ``fetch-depth: 0`` so that ref is present. Fall
    back to ``main`` / ``origin/main`` for local runs + push-to-main CI."""
    refs: list[str] = []
    base = os.environ.get("GITHUB_BASE_REF")
    if base:
        refs.append(f"origin/{base}")
    refs.extend(["main", "origin/main"])
    return tuple(refs)


def test_mcp_authz_matches_base_or_reviewed_d2_reference() -> None:
    """Accept base equality after D2 lands, else only the exact reviewed fix.

    Base-ref resolution stays CI-hardened: no resolvable base fails loud in CI
    and skips loud only for a local shallow checkout. A tenantless base is not
    itself accepted—the working bytes must match the reviewed D2 digest.
    """
    current = (_repo_root() / _MCP_AUTHZ_REPO_PATH).read_bytes()
    base_bytes: bytes | None = None
    tried = _base_ref_candidates()
    for ref in tried:
        base_bytes = _git_show(ref, _MCP_AUTHZ_REPO_PATH)
        if base_bytes is not None:
            break
    if base_bytes is None:
        message = (
            f"cannot resolve any base ref {tried} to byte-compare mcp_authz.py. "
            "The lint+test CI job checks out with fetch-depth: 0 so the base ref "
            "(origin/<base>) is present; a missing base ref here means a "
            "checkout-depth regression (fix the workflow) — or a local run "
            "without the base branch."
        )
        if _in_ci():
            pytest.fail(message)  # never skip in CI — the proof must not degrade
        pytest.skip(message)  # pragma: no cover - local-only (no base branch)

    base_digest = hashlib.sha256(base_bytes).hexdigest()
    current_digest = hashlib.sha256(current).hexdigest()
    if base_digest == _MCP_AUTHZ_REVIEWED_D2_SHA256:
        assert current == base_bytes, (
            "protocol/mcp_authz.py has drifted from the reviewed D2 bytes now "
            "present on the base branch"
        )
    else:
        assert current_digest == _MCP_AUTHZ_REVIEWED_D2_SHA256, (
            "protocol/mcp_authz.py must match the exact reviewed D2 tenant-"
            "isolation reference while the base still carries the tenantless "
            "cache implementation"
        )


def test_mcp_authz_still_defines_public_enforcement_surface() -> None:
    """Always-run defence-in-depth: the public authz client still exists."""
    assert hasattr(mcp_authz, "MCPAuthzClient")
