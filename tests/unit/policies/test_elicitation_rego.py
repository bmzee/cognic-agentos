"""Sprint 7B.4 T8 — direct OPA invocation against
``policies/_default/elicitation.rego``.

Validates the Rego bundle's `allow` rule against the same shape the
gate sends. Skipped on systems without OPA installed (CI runs OPA-
bearing lanes by ensuring `opa` is on PATH); local dev runs the gate
unit-test suite instead via the AsyncMock(`OPAEngine`) path at
``tests/unit/portal/api/ui/test_elicitation_gate.py``.

This suite is the PRODUCTION-grade smoke for the bundle — it shells
out to the real OPA binary and verifies the policy decision matrix
end-to-end (no AsyncMock stub between the test + the runtime). Without
it, a Rego-syntax regression (e.g. accidentally inverting a rule,
mis-naming the package or rule, deleting `default allow := false`) would
go undetected until the first portal-wired deployment.
"""

from __future__ import annotations

import shutil
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
    reason="opa binary not installed — skip the direct-OPA smoke; the gate "
    "unit-test suite covers the Rego dispatch matrix via AsyncMock at "
    "tests/unit/portal/api/ui/test_elicitation_gate.py",
)


@pytest.fixture
async def engine(tmp_path):
    """Build a real :class:`OPAEngine` over an in-memory SQLite audit +
    decision_history pair so the engine's `policy.bundle_loaded` +
    `policy.decision_evaluated` audit emits don't error.

    Mirrors the canonical pattern at
    ``tests/unit/core/policy/conftest.py`` — the verified `_chain_heads`
    columns are `chain_id` + `latest_sequence` + `latest_hash` +
    `updated_at` (NOT `last_hash` / `last_sequence` — that would be
    Sprint-2 R3 schema drift). Seeds both chain heads with the
    canonical :data:`ZERO_HASH` value at sequence 0.
    """
    url = f"sqlite+aiosqlite:///{tmp_path / 'elicitation_rego_test.db'}"
    sa_engine = create_async_engine(url)
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
    audit = AuditStore(sa_engine)
    dh = DecisionHistoryStore(sa_engine)
    yield OPAEngine(
        bundle_path=Path("policies/_default/elicitation.rego"),
        audit_store=audit,
        decision_history_store=dh,
    )
    await sa_engine.dispose()


@opa_required
class TestElicitationRegoDecisionMatrix:
    """Direct-OPA decision matrix per the bundle's documented rules:

    - URL mode is ALWAYS allowed (regardless of data_classes)
    - form mode is allowed only when data_classes ∩
      {customer_pii, payment_action, regulator_communication} = ∅
    - default allow := false (any unmatched input → deny)
    """

    @pytest.mark.asyncio
    async def test_url_mode_with_clean_classes_allows(self, engine: OPAEngine) -> None:
        d = await engine.evaluate(
            decision_point="data.cognic.ui.elicitation_submit.allow",
            input={"mode": "url", "data_classes": ["public"]},
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_url_mode_with_restricted_class_still_allows(self, engine: OPAEngine) -> None:
        """URL completion is safe regardless of data classes — the user
        completes off-system at the bank-overlay's URL surface."""
        d = await engine.evaluate(
            decision_point="data.cognic.ui.elicitation_submit.allow",
            input={"mode": "url", "data_classes": ["customer_pii"]},
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_form_mode_with_clean_classes_allows(self, engine: OPAEngine) -> None:
        d = await engine.evaluate(
            decision_point="data.cognic.ui.elicitation_submit.allow",
            input={"mode": "form", "data_classes": ["public", "internal"]},
        )
        assert d.allow is True

    @pytest.mark.parametrize(
        "restricted",
        ["customer_pii", "payment_action", "regulator_communication"],
    )
    @pytest.mark.asyncio
    async def test_form_mode_with_restricted_class_denies(
        self, engine: OPAEngine, restricted: str
    ) -> None:
        d = await engine.evaluate(
            decision_point="data.cognic.ui.elicitation_submit.allow",
            input={"mode": "form", "data_classes": [restricted]},
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_default_deny_on_unrecognised_mode(self, engine: OPAEngine) -> None:
        """`default allow := false` per ADR-015 — any mode value that
        doesn't match the two `allow if` rules (e.g. a typo or a
        not-yet-supported mode) refuses."""
        d = await engine.evaluate(
            decision_point="data.cognic.ui.elicitation_submit.allow",
            input={"mode": "nonexistent", "data_classes": ["public"]},
        )
        assert d.allow is False
