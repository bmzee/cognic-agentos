"""Sprint-11.5a T8 — direct OPA invocation against
``policies/_default/memory.rego``.

Validates the Wave-1 governed-memory admission bundle's three BOOLEAN-only
decision points (``long_term.allow`` / ``cross_subject.allow`` /
``restricted_class_write.allow``) against the input shape the T9 Python
memory gate will assemble per ADR-015 + ADR-019. Skipped on systems
without OPA installed; without it the bundle goes untested end-to-end.

Unlike ``scheduler.rego`` these decision points expose ONLY a boolean
``allow`` — there is NO Rego ``refusal_reason`` closed-enum here. The
``MemoryRefusalReason`` mapping (``memory_long_term_write_denied`` /
``memory_cross_subject_access_refused`` / ...) is assigned by the T9
Python gate, NOT by Rego.

Decision matrix covered:

* default-deny baseline (``tenant_override=false`` → ``allow=false``) for
  every decision point — the kernel NEVER permits by default
* explicit ``tenant_override=true`` permits each decision point (the only
  Wave-1 true path; banks ship this local Rego layer)
* missing ``tenant_override`` key entirely → default-deny (fails closed;
  the kernel never permits on absent input)
"""

from __future__ import annotations

import shutil
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.policy.engine import OPAEngine

opa_required = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary not installed — skip the direct-OPA smoke; the "
    "T9 memory-gate unit-test suite covers the Rego dispatch matrix via "
    "AsyncMock once it lands",
)

MEMORY_BUNDLE = Path("policies/_default/memory.rego")

#: The three BOOLEAN-only decision points exposed by ``memory.rego``. Each
#: resolves to ``data.cognic.memory.<rule>.allow`` (a bool) — NOT the
#: ``{"allow": bool}`` object — because ``OPAEngine._parse_decision``
#: requires the expression value to be a Python ``bool``.
_POINTS = [
    "data.cognic.memory.long_term.allow",
    "data.cognic.memory.cross_subject.allow",
    "data.cognic.memory.restricted_class_write.allow",
]


@pytest.fixture
async def opa_memory(tmp_path: Path) -> AsyncGenerator[OPAEngine, None]:
    """Build a real :class:`OPAEngine` over an in-memory SQLite audit +
    decision_history pair so the engine's ``policy.bundle_loaded`` +
    ``policy.decision_evaluated`` audit emits don't error.

    Mirrors the canonical fixture at
    ``tests/unit/policies/test_scheduler_rego.py`` (Sprint-10.5b T7).
    """
    sa_engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'memory_rego.db'}")
    async with sa_engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    engine = await OPAEngine.create(
        bundle_path=MEMORY_BUNDLE,
        audit_store=AuditStore(sa_engine),
        decision_history_store=DecisionHistoryStore(sa_engine),
    )
    yield engine
    await sa_engine.dispose()


@opa_required
@pytest.mark.asyncio
@pytest.mark.parametrize("point", _POINTS)
async def test_default_deny(opa_memory: OPAEngine, point: str) -> None:
    """ADR-015 default-deny baseline: ``tenant_override=false`` → deny on
    every decision point. A permissive default would silently authorise
    governed-memory writes the moment 11.5a ships."""
    decision = await opa_memory.evaluate(decision_point=point, input={"tenant_override": False})
    assert decision.allow is False


@opa_required
@pytest.mark.asyncio
@pytest.mark.parametrize("point", _POINTS)
async def test_tenant_override_permits(opa_memory: OPAEngine, point: str) -> None:
    """Explicit ``tenant_override=true`` is the only Wave-1 true path —
    banks ship this local Rego layer to permit a governed-memory write."""
    decision = await opa_memory.evaluate(decision_point=point, input={"tenant_override": True})
    assert decision.allow is True


@opa_required
@pytest.mark.asyncio
@pytest.mark.parametrize("point", _POINTS)
async def test_missing_input_field_fails_closed(opa_memory: OPAEngine, point: str) -> None:
    """No ``tenant_override`` key at all → default-deny (the kernel never
    permits by default)."""
    decision = await opa_memory.evaluate(decision_point=point, input={})
    assert decision.allow is False
