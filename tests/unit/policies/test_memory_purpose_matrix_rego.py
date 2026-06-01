"""Sprint-11.5a T8 — direct OPA invocation against
``policies/_default/memory_purpose_matrix.rego``.

Validates the Wave-1 memory-recall purpose-compatibility bundle's single
BOOLEAN-only decision point (``recall.purpose_compatible.allow``) against
the input shape the T9 Python memory gate will assemble per ADR-015 +
ADR-019. Skipped on systems without OPA installed.

The decision point exposes ONLY a boolean ``allow`` — there is NO Rego
``refusal_reason`` closed-enum here. The T9 Python gate maps a deny here
to ``memory_purpose_mismatch``.

Decision matrix covered:

* identical write/recall purpose → compatible (``allow=true``)
* an explicitly-listed compatible pair → compatible (``allow=true``)
* a mismatched (unlisted, non-identical) pair → default-deny
* missing both fields → default-deny (fails closed)

NOTE: the decision point is ``…purpose_compatible.allow`` (the bool
inside the object), NOT ``…purpose_compatible`` — because
``OPAEngine._parse_decision`` requires the expression value to be a
Python ``bool``.
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

PURPOSE_BUNDLE = Path("policies/_default/memory_purpose_matrix.rego")
_POINT = "data.cognic.memory.recall.purpose_compatible.allow"


@pytest.fixture
async def opa_purpose(tmp_path: Path) -> AsyncGenerator[OPAEngine, None]:
    """Build a real :class:`OPAEngine` over an in-memory SQLite audit +
    decision_history pair so the engine's ``policy.bundle_loaded`` +
    ``policy.decision_evaluated`` audit emits don't error.

    Mirrors the canonical fixture at
    ``tests/unit/policies/test_scheduler_rego.py`` (Sprint-10.5b T7).
    """
    sa_engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'memory_purpose_rego.db'}")
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
        bundle_path=PURPOSE_BUNDLE,
        audit_store=AuditStore(sa_engine),
        decision_history_store=DecisionHistoryStore(sa_engine),
    )
    yield engine
    await sa_engine.dispose()


@opa_required
@pytest.mark.asyncio
async def test_identical_purpose_compatible(opa_purpose: OPAEngine) -> None:
    """A recall purpose identical to the stored write purpose is always
    compatible."""
    decision = await opa_purpose.evaluate(
        decision_point=_POINT,
        input={"write_purpose": "customer_support", "recall_purpose": "customer_support"},
    )
    assert decision.allow is True


@opa_required
@pytest.mark.asyncio
async def test_listed_compatible_pair_allowed(opa_purpose: OPAEngine) -> None:
    """An explicitly-listed compatible pair is compatible. The kernel
    seeds the conservative bank-grade pair list; overlays may TIGHTEN
    (shrink) it but not loosen the kernel default-deny."""
    decision = await opa_purpose.evaluate(
        decision_point=_POINT,
        input={"write_purpose": "transaction_processing", "recall_purpose": "regulatory_reporting"},
    )
    assert decision.allow is True


@opa_required
@pytest.mark.asyncio
async def test_mismatched_purpose_denied(opa_purpose: OPAEngine) -> None:
    """A non-identical, unlisted pair is incompatible → default-deny. The
    T9 gate maps this to ``memory_purpose_mismatch``."""
    decision = await opa_purpose.evaluate(
        decision_point=_POINT,
        input={"write_purpose": "fraud_detection", "recall_purpose": "operational_telemetry"},
    )
    assert decision.allow is False


@opa_required
@pytest.mark.asyncio
async def test_default_deny_on_missing_fields(opa_purpose: OPAEngine) -> None:
    """Missing both purpose fields → default-deny (fails closed; the
    kernel never permits on absent input)."""
    decision = await opa_purpose.evaluate(decision_point=_POINT, input={})
    assert decision.allow is False
