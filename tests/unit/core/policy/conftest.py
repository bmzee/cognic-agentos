"""Sprint 4 T2 — fixtures for the OPAEngine seed test surface.

Mirrors the ``tests/unit/core/test_decision_history.py`` engine fixture
shape: per-test SQLite-aiosqlite engine with both Sprint-2 chain
heads (audit_event + decision_history) seeded, plus the AuditStore
and DecisionHistoryStore wired against that engine.

The OPAEngine consumes BOTH stores: ``audit_store`` for any internal
audit emissions (none in the Sprint-4 seed; reserved for future
extension) and ``decision_history_store`` for the load-bearing
``policy.bundle_loaded`` + ``policy.decision_evaluated`` emissions
that ADR-015 §"Engine integration" mandates.
"""

from __future__ import annotations

import subprocess
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore


@pytest.fixture
async def policy_engine_db(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """SQLite-aiosqlite engine with audit_event + decision_history +
    chain_heads tables created and both chain heads seeded."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'policy_engine_test.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="decision_history",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
async def audit_store(policy_engine_db: AsyncEngine) -> AuditStore:
    return AuditStore(policy_engine_db)


@pytest.fixture
async def decision_history_store(
    policy_engine_db: AsyncEngine,
) -> DecisionHistoryStore:
    return DecisionHistoryStore(policy_engine_db)


def write_valid_bundle(tmp_path: Path) -> Path:
    """Write a minimal-valid Rego bundle to ``tmp_path/supply_chain.rego``."""
    bundle = tmp_path / "supply_chain.rego"
    bundle.write_text(
        """\
package cognic.supply_chain

default allow := false

allow if {
    input.attestation_grade == "full"
}
"""
    )
    return bundle


def fake_opa_eval_response(*, allow: bool) -> str:
    """Return the JSON shape ``opa eval`` produces for a single boolean
    expression query."""
    import json as _json

    return _json.dumps(
        {
            "result": [
                {
                    "expressions": [
                        {
                            "value": allow,
                            "text": "data.cognic.supply_chain.allow",
                            "location": {"row": 1, "col": 1},
                        }
                    ]
                }
            ]
        }
    )


def fake_completed_process(
    stdout: str, returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    """Build a ``subprocess.CompletedProcess`` for shim-based tests."""
    return subprocess.CompletedProcess(
        args=["opa"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def opa_shim(
    eval_stdout: str | None = None,
    *,
    eval_returncode: int = 0,
    eval_stderr: str = "",
) -> Any:
    """Build a ``subprocess.run`` shim that handles BOTH the construction-
    time ``opa fmt --diff`` syntax check and the per-call ``opa eval``.

    OPA is not installed in the unit-test environment, so any test that
    constructs an ``OPAEngine`` with ``opa_path`` set must shim the
    subprocess at both call sites. This helper differentiates by
    inspecting ``argv``: ``fmt`` → success (bundle is well-formed for
    test fixture purposes); ``eval`` → caller-supplied stdout/stderr.

    Args:
        eval_stdout: JSON output the shim returns for the ``eval`` call.
            ``None`` → assertion error (test forgot to set it).
        eval_returncode: Override exit code for the ``eval`` call.
            Default 0.
        eval_stderr: Override stderr for the ``eval`` call. Real OPA
            writes errors to stderr (not stdout), so non-zero-exit
            tests should set this.

    Returns:
        A callable suitable for ``side_effect=`` in
        ``unittest.mock.patch``.
    """

    def _run(argv: Any, **kwargs: Any) -> Any:
        if "fmt" in argv:
            return fake_completed_process(stdout="", returncode=0)
        if "eval" in argv:
            assert eval_stdout is not None, "test forgot to provide eval_stdout"
            return fake_completed_process(
                stdout=eval_stdout, returncode=eval_returncode, stderr=eval_stderr
            )
        raise AssertionError(f"unexpected opa argv: {argv}")

    return _run
