"""M8 Task A5 (ADR-027 + ADR-015) — AgentDispatchPolicy + AgentPolicyInput tests.

Validates ``AgentDispatchPolicy.evaluate()`` against the real Wave-1
``policies/_default/agents.rego`` bundle (same batch). Covers:

* Allow path: ``PolicyDecision(allow=True, policy_reason=None)``.
* Deny path: ``PolicyDecision(allow=False, policy_reason=None)`` — the
  bundle is BOOL-ONLY (no string refusal_reason document), so the deny
  carries NO internal diagnostic; the A10 dispatcher maps every deny to
  the wire refusal ``agent_policy_denied``.
* Fail-closed envelope: OpaNotInstalledError / RegoEvaluationError in
  OPAEngine surfaces as ``PolicyDecision(allow=False,
  policy_reason="opa_unavailable")``.
* Input-threading drift detector: the 12-key exact set the bundle reads,
  each threaded verbatim (field names identical — no key translations,
  unlike the scheduler's ``class_``/``actor_subject``).
* Canonical-owner pin: ``PolicyDecision`` is IMPORTED from
  ``core/scheduler/policy.py`` (the producer module), never re-declared.
* Deliberate-deviation pin: NO ``_MINIMAL_SUBPROCESS_ENV`` constant — the
  scheduler copy exists ONLY for its ``_fetch_refusal_reason`` direct
  subprocess; this module is bool-only through OPAEngine and spawns no
  subprocess, so a copied env constant would be dead code.

OPA-dependent tests are gated behind ``@opa_required`` skip (mirrors the
scheduler suite); the fail-closed tests use a stub OPAEngine that raises
on every evaluate call so they run without OPA installed.
"""

from __future__ import annotations

import shutil
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.agent.policy import (
    AgentDispatchPolicy,
    AgentPolicyInput,
    PolicyDecision,
)
from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.policy.engine import (
    Decision,
    OPAEngine,
    OpaNotInstalledError,
    RegoEvaluationError,
)

opa_required = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary not installed — skip the AgentDispatchPolicy + real-"
    "bundle smoke; the fail-closed sub-suite still runs via stub OPAEngine",
)


AGENTS_BUNDLE_PATH = Path("policies/_default/agents.rego")

#: The 12-key Rego input contract the bundle reads off ``input.<key>``.
#: Drift between this set and ``_build_rego_input`` = silent policy
#: regression (Rego sees undefined values + the allow rule fails by
#: default-deny).
_EXPECTED_REGO_INPUT_KEYS = {
    "tenant_id",
    "agent_id",
    "originator_subject",
    "capability_kind",
    "capability_class",
    "capability_ref",
    "scope_id",
    "pack_risk_tier",
    "step_index",
    "max_steps",
    "assignment_verified",
    "entitlement_verified",
}


def _policy_input(**overrides: Any) -> AgentPolicyInput:
    base: dict[str, Any] = {
        "tenant_id": "tenant-a",
        "agent_id": "bank-analyst",
        "originator_subject": "human:analyst@bank",
        "capability_kind": "skill",
        "capability_class": "unscoped",
        "capability_ref": "cognic-skill-schema-summary",
        "scope_id": None,
        "pack_risk_tier": "customer_data_read",
        "step_index": 0,
        "max_steps": 6,
        "assignment_verified": True,
        "entitlement_verified": True,
    }
    base.update(overrides)
    return AgentPolicyInput(**base)


@pytest.fixture
async def opa_engine(tmp_path: Path) -> AsyncGenerator[OPAEngine, None]:
    """Build a real :class:`OPAEngine` over an in-memory SQLite audit +
    decision_history pair pointing at the real Wave-1 agents.rego bundle.
    Mirrors the ``tests/unit/core/scheduler/test_policy.py`` fixture."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'agent_policy_test.db'}"
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


# --- Canonical-owner + deliberate-deviation pins ---------------------------


class TestAgentPolicyModuleContract:
    def test_policy_decision_is_the_scheduler_canonical_class(self) -> None:
        """The house canonical-owner pattern — ``core/agent/policy.py``
        re-imports ``PolicyDecision`` from its producer module
        ``core/scheduler/policy.py`` (the way ``scheduler/engine.py``
        re-exports it); a duplicate declaration would fork the frozen
        dataclass identity across the two policy seams."""
        from cognic_agentos.core.scheduler.policy import (
            PolicyDecision as SchedulerPolicyDecision,
        )

        assert PolicyDecision is SchedulerPolicyDecision

    def test_no_minimal_subprocess_env_constant(self) -> None:
        """DELIBERATE plan deviation (controller-authorized): the
        scheduler's ``_MINIMAL_SUBPROCESS_ENV`` copy exists ONLY for its
        ``_fetch_refusal_reason`` direct subprocess; the agent module is
        bool-only through OPAEngine and spawns no subprocess — a copied
        env constant would be dead code. Pin its ABSENCE so a future
        copy-paste from the scheduler mirror trips review."""
        import cognic_agentos.core.agent.policy as agent_policy_module

        assert not hasattr(agent_policy_module, "_MINIMAL_SUBPROCESS_ENV")

    def test_no_fetch_refusal_reason_helper(self) -> None:
        """Companion deviation pin — the bundle is bool-only, so there is
        no string decision point to fetch and no second subprocess."""
        assert not hasattr(AgentDispatchPolicy, "_fetch_refusal_reason")


# --- Input-threading drift detector ----------------------------------------


class TestAgentDispatchPolicyInputThreading:
    """Pins the 12-key input contract. INTENTIONALLY NOT behind
    ``@opa_required`` — every test calls the pure-Python static method
    ``AgentDispatchPolicy._build_rego_input`` which has no OPA
    dependency (the scheduler R1 P2 precedent: gating would skip the
    projection-contract regression on every OPA-less CI lane)."""

    def test_build_rego_input_includes_exactly_the_documented_keys(self) -> None:
        rego_input = AgentDispatchPolicy._build_rego_input(_policy_input())
        assert set(rego_input.keys()) == _EXPECTED_REGO_INPUT_KEYS

    def test_build_rego_input_threads_every_field_verbatim(self) -> None:
        """Field names are IDENTICAL to the AgentPolicyInput field names
        (no translations — unlike the scheduler's ``class_`` /
        ``actor_subject``); every value rides through verbatim."""
        policy_input = _policy_input(
            tenant_id="tenant-b",
            agent_id="ops-agent",
            originator_subject="svc:portal",
            capability_kind="tool",
            capability_class="data_query",
            capability_ref="cognic-tool-oracle-schema/run_readonly_query",
            scope_id="customer-data",
            pack_risk_tier="customer_data_read",
            step_index=3,
            max_steps=8,
            assignment_verified=True,
            entitlement_verified=False,
        )
        rego_input = AgentDispatchPolicy._build_rego_input(policy_input)
        assert rego_input == {
            "tenant_id": "tenant-b",
            "agent_id": "ops-agent",
            "originator_subject": "svc:portal",
            "capability_kind": "tool",
            "capability_class": "data_query",
            "capability_ref": "cognic-tool-oracle-schema/run_readonly_query",
            "scope_id": "customer-data",
            "pack_risk_tier": "customer_data_read",
            "step_index": 3,
            "max_steps": 8,
            "assignment_verified": True,
            "entitlement_verified": False,
        }

    def test_build_rego_input_threads_nullable_scope_id(self) -> None:
        """``scope_id`` is ALWAYS present but nullable — a tool dispatch
        with no data scope threads ``None`` (never drops the key)."""
        rego_input = AgentDispatchPolicy._build_rego_input(_policy_input(scope_id=None))
        assert "scope_id" in rego_input
        assert rego_input["scope_id"] is None


# --- Allow / deny mapping via stub engine ----------------------------------


class _FixedDecisionStubOPAEngine:
    """Returns a fixed Decision-shaped object from every evaluate call.
    Mirrors the OPAEngine.evaluate signature structurally (only method-
    level conformance is checked at the AgentDispatchPolicy call site)."""

    def __init__(self, *, allow: bool) -> None:
        self._allow = allow
        self.seen_inputs: list[dict[str, Any]] = []
        self.seen_decision_points: list[str] = []

    async def evaluate(self, *, decision_point: str, input: dict[str, Any]) -> Decision:
        self.seen_decision_points.append(decision_point)
        self.seen_inputs.append(input)
        return Decision(
            allow=self._allow,
            rule_matched=decision_point,
            reasoning="rule matched: allow" if self._allow else "rule matched: deny (default)",
            decision_data=None,
        )


class TestAgentDispatchPolicyDecisionMapping:
    @pytest.mark.asyncio
    async def test_allow_true_maps_to_allow_with_policy_reason_none(self) -> None:
        stub = _FixedDecisionStubOPAEngine(allow=True)
        policy = AgentDispatchPolicy(opa_engine=stub)  # type: ignore[arg-type]
        decision = await policy.evaluate(_policy_input())
        assert decision == PolicyDecision(allow=True, policy_reason=None)

    @pytest.mark.asyncio
    async def test_deny_maps_to_deny_with_policy_reason_none(self) -> None:
        """Bool-only bundle contract: NO second subprocess, NO internal
        diagnostic — the deny rides with ``policy_reason=None`` and the
        A10 dispatcher owns the wire mapping to ``agent_policy_denied``."""
        stub = _FixedDecisionStubOPAEngine(allow=False)
        policy = AgentDispatchPolicy(opa_engine=stub)  # type: ignore[arg-type]
        decision = await policy.evaluate(_policy_input(assignment_verified=False))
        assert decision == PolicyDecision(allow=False, policy_reason=None)

    @pytest.mark.asyncio
    async def test_evaluate_queries_the_agents_dispatch_decision_point(self) -> None:
        """The decision point is the compile-time constant
        ``data.cognic.agents.dispatch.allow`` and the projected 12-key
        input is what reaches the engine."""
        stub = _FixedDecisionStubOPAEngine(allow=True)
        policy = AgentDispatchPolicy(opa_engine=stub)  # type: ignore[arg-type]
        await policy.evaluate(_policy_input())
        assert stub.seen_decision_points == ["data.cognic.agents.dispatch.allow"]
        assert set(stub.seen_inputs[0].keys()) == _EXPECTED_REGO_INPUT_KEYS


# --- Fail-closed envelope (runs WITHOUT opa via stub OPAEngine) -------------


class _FailingStubOPAEngine:
    """Raises on every evaluate call — pins the fail-closed envelope."""

    def __init__(self, *, exc: type[Exception], msg: str) -> None:
        self._exc = exc
        self._msg = msg

    async def evaluate(self, *, decision_point: str, input: dict[str, Any]) -> Decision:
        raise self._exc(self._msg)


class TestAgentDispatchPolicyFailClosed:
    """OPA error surface MUST fail-closed at the policy layer: deny +
    policy_reason="opa_unavailable" (the scheduler plan-§1181 mirror)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("exc", "msg"),
        [
            (OpaNotInstalledError, "opa not found on PATH"),
            (RegoEvaluationError, "OPA returned malformed JSON"),
        ],
    )
    async def test_engine_errors_fail_closed_with_opa_unavailable(
        self, exc: type[Exception], msg: str
    ) -> None:
        stub = _FailingStubOPAEngine(exc=exc, msg=msg)
        policy = AgentDispatchPolicy(opa_engine=stub)  # type: ignore[arg-type]
        decision = await policy.evaluate(_policy_input())
        assert decision == PolicyDecision(allow=False, policy_reason="opa_unavailable")


# --- End-to-end through the real OPAEngine + the real agents.rego -----------


@opa_required
class TestAgentDispatchPolicyEndToEnd:
    """Full pipeline: AgentPolicyInput → 12-key Rego input → real OPA
    subprocess over the real agents.rego bundle → PolicyDecision."""

    @pytest.mark.asyncio
    async def test_both_verified_skill_dispatch_allows(self, opa_engine: OPAEngine) -> None:
        policy = AgentDispatchPolicy(opa_engine=opa_engine)
        decision = await policy.evaluate(
            _policy_input(
                capability_kind="skill",
                assignment_verified=True,
                entitlement_verified=True,
            )
        )
        assert decision == PolicyDecision(allow=True, policy_reason=None)

    @pytest.mark.asyncio
    async def test_unattested_dispatch_denies(self, opa_engine: OPAEngine) -> None:
        policy = AgentDispatchPolicy(opa_engine=opa_engine)
        decision = await policy.evaluate(_policy_input(assignment_verified=False))
        assert decision == PolicyDecision(allow=False, policy_reason=None)


# --- AgentPolicyInput dataclass shape ---------------------------------------


class TestAgentPolicyInputDataclass:
    def test_agent_policy_input_is_frozen(self) -> None:
        import dataclasses

        policy_input = _policy_input()
        with pytest.raises(dataclasses.FrozenInstanceError):
            policy_input.tenant_id = "tenant-x"  # type: ignore[misc]

    def test_agent_policy_input_field_names_match_rego_key_set(self) -> None:
        """The no-translation contract at the type level: the dataclass
        field-name set IS the Rego input key set."""
        import dataclasses

        field_names = {f.name for f in dataclasses.fields(AgentPolicyInput)}
        assert field_names == _EXPECTED_REGO_INPUT_KEYS
