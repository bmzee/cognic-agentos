"""ADR-026 D6 (M4 Task 7) — ``protocol/mcp_authz.py`` is UNCHANGED by M4.

M4 routes pack callability through the DESIRED runtime-config record →
materializer → DERIVED override / allow-list rows that ``mcp_authz`` ALREADY
reads (the live-proven Bar-1 SSRF carve-out). A safety property of the design
(D6) is that the trust-critical ``mcp_authz`` module is NOT touched — M4 adds a
new WRITE path (the materializer is the sole writer) but does not alter the
READ / enforcement path.

This guard FAILS if anyone edits ``protocol/mcp_authz.py`` on this branch
(``[[feedback_security_regression_hardening]]`` — the pin must fire on a real
change): it byte-compares the working-tree file against its version on the base
branch (``origin/<base>`` in PR CI; ``main`` locally). A legitimate future change
to ``mcp_authz`` must be a DELIBERATE, separately-reviewed decision that updates
this guard's expectation in the same PR.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

import cognic_agentos.protocol.mcp_authz as mcp_authz

_MCP_AUTHZ_REPO_PATH = "src/cognic_agentos/protocol/mcp_authz.py"


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
    a skip there would silently weaken the mcp_authz-untouched proof at the exact
    merge-gating point it protects (the P2 flagged at Task-7 review)."""
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


def test_mcp_authz_byte_identical_to_main() -> None:
    """The working-tree ``mcp_authz.py`` is byte-identical to its version on the
    base branch — M4 does not touch the trust-critical read / enforcement path.

    Base-ref resolution is CI-hardened (P2): the lint+test job checks out with
    ``fetch-depth: 0`` so ``origin/<base>`` resolves. If NO base ref resolves,
    the guard FAILS LOUD in CI (never a silent skip — the proof must not degrade
    at the merge gate) and skips loud only for a local run without the base
    branch (a contributor convenience, never the CI path)."""
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
    assert current == base_bytes, (
        "protocol/mcp_authz.py has been MODIFIED relative to the base branch. "
        "ADR-026 D6 requires the trust-critical mcp_authz read/enforcement path "
        "to stay UNCHANGED by M4 (the materializer is a new WRITE path only). If "
        "this change is intentional + separately reviewed, update this guard in "
        "the same PR."
    )


def test_mcp_authz_still_defines_public_enforcement_surface() -> None:
    """Always-run defence-in-depth (independent of git): the module still exposes
    its public authz client, so a gross deletion / rename is caught even where
    the git byte-compare skips. Behavior is pinned by the dedicated mcp_authz
    suite; this is a presence check only."""
    assert hasattr(mcp_authz, "MCPAuthzClient")
