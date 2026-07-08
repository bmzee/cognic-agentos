"""M8 Task A5 (ADR-027 + ADR-015) — direct OPA invocation against
``policies/_default/agents.rego``.

Validates the Wave-1 agent-dispatch bundle's BOOL-ONLY ``allow`` rule at
``data.cognic.agents.dispatch.allow`` against the 11-key input shape the
``AgentDispatchPolicy`` (same batch) assembles. Skipped on systems without
OPA installed (CI runs OPA-bearing lanes by ensuring ``opa`` is on PATH);
without it the bundle goes untested end-to-end.

This suite is the PRODUCTION-grade smoke for the bundle — it shells out to
the real OPA binary via ``OPAEngine``. Deliberately NO string
``refusal_reason`` decision-point tests: the bundle is bool-only by design
(the Python dispatcher owns the refusal vocabulary; the A10 dispatcher maps
every bundle deny to the wire refusal ``agent_policy_denied``).

Decision matrix covered:

* default-deny baseline (empty input → ``allow=false`` per ADR-015)
* allow: both attestations strictly ``true`` + each capability_kind in
  ``{skill, tool, builtin}`` + ``step_index < max_steps``
* defense-in-depth (the sandbox.rego rule-4 precedent): EACH attestation
  refuses independently — ``assignment_verified=false`` denies even with
  ``entitlement_verified=true`` and vice versa, so a bypassed Python gate
  cannot admit through the other gate's attestation
* strict ``== true``: truthy non-true values (``"true"`` string, ``1``
  int) must NOT satisfy either attestation conjunct
* step bounds: ``step_index == max_steps`` and ``step_index > max_steps``
  both deny; ``step_index == max_steps - 1`` allows
* unknown capability kind (``"hook"``, ``"builtin_x"``) denies
* missing-keys shape-mismatch denies via the default
"""

from __future__ import annotations

import shutil
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.policy.engine import OPAEngine

opa_required = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary not installed — skip the direct-OPA smoke; the "
    "AgentDispatchPolicy unit-test suite covers the fail-closed envelope "
    "via stub OPAEngine without it",
)


AGENTS_DECISION_POINT_ALLOW = "data.cognic.agents.dispatch.allow"
AGENTS_BUNDLE_PATH = Path("policies/_default/agents.rego")

#: The closed capability-kind vocabulary the bundle's allow rule admits.
#: Mirrors ``CapabilityRef.kind`` at ``core/agent/_types.py``.
_CAPABILITY_KINDS = ("skill", "tool", "builtin")


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncGenerator[OPAEngine, None]:
    """Build a real :class:`OPAEngine` over an in-memory SQLite audit +
    decision_history pair so the engine's ``policy.bundle_loaded`` +
    ``policy.decision_evaluated`` audit emits don't error.

    Mirrors the canonical pattern at
    ``tests/unit/policies/test_scheduler_rego.py``.
    """
    url = f"sqlite+aiosqlite:///{tmp_path / 'agents_rego_test.db'}"
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
    yield await OPAEngine.create(
        bundle_path=AGENTS_BUNDLE_PATH,
        audit_store=audit,
        decision_history_store=dh,
    )
    await sa_engine.dispose()


def _dispatch_input(**overrides: Any) -> dict[str, Any]:
    """Construct a happy-path dispatch input dict per the 11-key contract
    the ``AgentDispatchPolicy._build_rego_input`` projection threads. Each
    test arm overrides one field to exercise its refusal path. Field names
    are IDENTICAL to the ``AgentPolicyInput`` field names (no key
    translations — unlike the scheduler's ``class_``/``actor_subject``)."""
    base: dict[str, Any] = {
        "tenant_id": "tenant-a",
        "agent_id": "bank-analyst",
        "originator_subject": "human:analyst@bank",
        "capability_kind": "skill",
        "capability_ref": "cognic-skill-schema-summary",
        "scope_id": None,
        "pack_risk_tier": "customer_data_read",
        "step_index": 0,
        "max_steps": 6,
        "assignment_verified": True,
        "entitlement_verified": True,
    }
    base.update(overrides)
    return base


@opa_required
class TestAgentsRegoDefaultDeny:
    """ADR-015 default-deny baseline."""

    @pytest.mark.asyncio
    async def test_default_deny_baseline_empty_input(self, engine: OPAEngine) -> None:
        """``data.cognic.agents.dispatch.allow`` defaults to ``false``
        per ADR-015 default-deny. Empty input → deny."""
        d = await engine.evaluate(
            decision_point=AGENTS_DECISION_POINT_ALLOW,
            input={},
        )
        assert d.allow is False


@opa_required
class TestAgentsRegoAllowMatrix:
    """The single allow rule: both attestations strictly true + kind in
    the 3-value vocabulary + step_index < max_steps."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("kind", _CAPABILITY_KINDS)
    async def test_allow_each_capability_kind_when_fully_attested(
        self, engine: OPAEngine, kind: str
    ) -> None:
        d = await engine.evaluate(
            decision_point=AGENTS_DECISION_POINT_ALLOW,
            input=_dispatch_input(capability_kind=kind),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_allow_at_last_step_index_before_max(self, engine: OPAEngine) -> None:
        """Bounds boundary: ``step_index == max_steps - 1`` is the LAST
        admissible step."""
        d = await engine.evaluate(
            decision_point=AGENTS_DECISION_POINT_ALLOW,
            input=_dispatch_input(step_index=5, max_steps=6),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_allow_with_null_scope_id(self, engine: OPAEngine) -> None:
        """``scope_id`` is nullable metadata for the bundle — a tool
        dispatch with no data scope still admits when every conjunct
        holds (``_dispatch_input`` defaults ``scope_id=None``)."""
        d = await engine.evaluate(
            decision_point=AGENTS_DECISION_POINT_ALLOW,
            input=_dispatch_input(capability_kind="tool", scope_id=None),
        )
        assert d.allow is True


@opa_required
class TestAgentsRegoDefenseInDepth:
    """The sandbox.rego rule-4 precedent: even if ONE Python gate is
    bypassed, the OTHER attestation alone must never admit. Each
    attestation refuses independently — pinned in BOTH directions."""

    @pytest.mark.asyncio
    async def test_assignment_unverified_denies_even_with_entitlement_verified(
        self, engine: OPAEngine
    ) -> None:
        d = await engine.evaluate(
            decision_point=AGENTS_DECISION_POINT_ALLOW,
            input=_dispatch_input(assignment_verified=False, entitlement_verified=True),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_entitlement_unverified_denies_even_with_assignment_verified(
        self, engine: OPAEngine
    ) -> None:
        d = await engine.evaluate(
            decision_point=AGENTS_DECISION_POINT_ALLOW,
            input=_dispatch_input(assignment_verified=True, entitlement_verified=False),
        )
        assert d.allow is False


@opa_required
class TestAgentsRegoStrictAttestation:
    """Strict ``== true`` — a truthy non-true value must NOT satisfy
    either attestation conjunct (mirrors sandbox.rego's strict
    ``input.approval_verified == true`` arm-2 contract)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("field", ["assignment_verified", "entitlement_verified"])
    @pytest.mark.parametrize("truthy_non_true", ["true", 1])
    async def test_truthy_non_true_attestation_denies(
        self, engine: OPAEngine, field: str, truthy_non_true: Any
    ) -> None:
        d = await engine.evaluate(
            decision_point=AGENTS_DECISION_POINT_ALLOW,
            input=_dispatch_input(**{field: truthy_non_true}),
        )
        assert d.allow is False


@opa_required
class TestAgentsRegoStepBounds:
    """``step_index < max_steps`` — at-bound and over-bound both deny."""

    @pytest.mark.asyncio
    async def test_step_index_equal_to_max_steps_denies(self, engine: OPAEngine) -> None:
        d = await engine.evaluate(
            decision_point=AGENTS_DECISION_POINT_ALLOW,
            input=_dispatch_input(step_index=6, max_steps=6),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_step_index_greater_than_max_steps_denies(self, engine: OPAEngine) -> None:
        d = await engine.evaluate(
            decision_point=AGENTS_DECISION_POINT_ALLOW,
            input=_dispatch_input(step_index=7, max_steps=6),
        )
        assert d.allow is False


@opa_required
class TestAgentsRegoUnknownKind:
    """Capability kind outside ``{skill, tool, builtin}`` denies —
    including the near-miss prefix shape (``builtin_x``) so a set-vs-
    prefix regression cannot silently widen the vocabulary."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("kind", ["hook", "builtin_x"])
    async def test_unknown_capability_kind_denies(self, engine: OPAEngine, kind: str) -> None:
        d = await engine.evaluate(
            decision_point=AGENTS_DECISION_POINT_ALLOW,
            input=_dispatch_input(capability_kind=kind),
        )
        assert d.allow is False


@opa_required
class TestAgentsRegoShapeMismatch:
    """Missing-key inputs fall through to the default deny — every
    conjunct reads ``input.<key>`` strictly, so an absent key leaves the
    rule body undefined (fail-closed)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "missing_key",
        [
            "assignment_verified",
            "entitlement_verified",
            "capability_kind",
            "step_index",
            "max_steps",
        ],
    )
    async def test_missing_key_denies(self, engine: OPAEngine, missing_key: str) -> None:
        inp = _dispatch_input()
        del inp[missing_key]
        d = await engine.evaluate(decision_point=AGENTS_DECISION_POINT_ALLOW, input=inp)
        assert d.allow is False
