"""Sprint 10.5b T7 — direct OPA invocation against
``policies/_default/scheduler.rego``.

Validates the Wave-1 scheduler admission bundle's ``allow`` rule +
``refusal_reason`` closed-enum vocabulary against the input shape the
SchedulerPolicy (T8) will assemble per spec §4.8. Skipped on systems
without OPA installed (CI runs OPA-bearing lanes by ensuring ``opa``
is on PATH); without it the bundle goes untested end-to-end.

This suite is the PRODUCTION-grade smoke for the bundle — it shells
out to the real OPA binary (via ``OPAEngine`` for boolean ``allow``
decisions, via a direct subprocess helper for string ``refusal_reason``
decisions). Without it, a Rego-syntax regression (e.g. accidentally
inverting a rule, mis-naming the package or decision point, deleting
``default allow := false``) would go undetected until the first
scheduler-admission deployment.

Decision matrix covered (per spec §4.8):

* default-deny baseline (no input → ``allow=false`` + refusal_reason
  defaults to ``scheduler_default_deny``)
* allow on the 2-value Wave-1 safe-tier set
  (``{read_only, internal_write}``) x the 2-value class vocabulary
  (``{interactive, background}``)
* refuse on all 6 high-risk tiers unconditionally
  (``scheduler_high_risk_tier_refused_pre_13_5``; mirrors the
  Sprint 8A ``sandbox.rego`` ``sandbox_high_risk_tier_refused_pre_13_5``
  pre-Sprint-13.5 contract — when ``core/approval/engine.py`` wires
  up at 13.5, the high-risk-tier refusal lifts)
* refuse on unknown class (``scheduler_class_unknown``)
* **deterministic precedence**: when BOTH class is unknown AND
  pack_risk_tier is high-risk, refusal_reason MUST be
  ``scheduler_class_unknown`` (class-vocabulary check is the FIRST
  arm of the else-chain; pins the no-complete-document-conflict
  invariant per plan §1090)
* refusal-reason vocabulary closed: every refusal path produces one
  of the 3 closed-enum strings:
  ``{scheduler_high_risk_tier_refused_pre_13_5,
  scheduler_class_unknown, scheduler_default_deny}``
"""

from __future__ import annotations

import json
import shutil
import subprocess
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
    "T8 SchedulerPolicy unit-test suite covers the Rego dispatch matrix "
    "via AsyncMock once it lands",
)


SCHEDULER_DECISION_POINT_ALLOW = "data.cognic.scheduler.admit.allow"
SCHEDULER_DECISION_POINT_REASON = "data.cognic.scheduler.admit.refusal_reason"
SCHEDULER_BUNDLE_PATH = Path("policies/_default/scheduler.rego")

#: Closed-enum refusal vocabulary per plan §1091 — every refusal path
#: in the bundle MUST produce one of these 3 strings. Drift detector at
#: ``test_refusal_reason_vocabulary_is_closed`` pins this set against
#: every observed refusal across the decision matrix.
_VALID_REFUSAL_REASONS: frozenset[str] = frozenset(
    {
        "scheduler_high_risk_tier_refused_pre_13_5",
        "scheduler_class_unknown",
        "scheduler_default_deny",
    }
)

#: 6-value high-risk tier set per ADR-014 + sandbox.rego mirror. Refused
#: pre-Sprint-13.5 when ``core/approval/engine.py`` is unwired.
_HIGH_RISK_TIERS = (
    "customer_data_read",
    "customer_data_write",
    "payment_action",
    "regulator_communication",
    "cross_tenant",
    "high_risk_custom",
)


def _opa_eval_string_value(input_dict: dict[str, Any], decision_point: str) -> Any:
    """Direct OPA subprocess call returning the parsed JSON value of
    ``data.<path>``. Used for ``refusal_reason`` (string) since the
    Sprint-4 ``OPAEngine`` evaluator only handles boolean expressions.

    Mirrors the subprocess shape at ``OPAEngine.evaluate`` (list-form
    argv; no shell; check=True so a non-zero exit raises). Test-only
    helper — the production SchedulerPolicy goes through OPAEngine for
    ``allow`` and will get a small OPAEngine string extension at T8.
    """
    proc = subprocess.run(
        [
            "opa",
            "eval",
            "--data",
            str(SCHEDULER_BUNDLE_PATH),
            "--format",
            "json",
            "--stdin-input",
            decision_point,
        ],
        input=json.dumps(input_dict),
        capture_output=True,
        text=True,
        check=True,
    )
    payload = json.loads(proc.stdout)
    return payload["result"][0]["expressions"][0]["value"]


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncGenerator[OPAEngine, None]:
    """Build a real :class:`OPAEngine` over an in-memory SQLite audit +
    decision_history pair so the engine's ``policy.bundle_loaded`` +
    ``policy.decision_evaluated`` audit emits don't error.

    Mirrors the canonical pattern at
    ``tests/unit/policies/test_sandbox_rego.py`` (Sprint-8A T11).
    """
    url = f"sqlite+aiosqlite:///{tmp_path / 'scheduler_rego_test.db'}"
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
        bundle_path=SCHEDULER_BUNDLE_PATH,
        audit_store=audit,
        decision_history_store=dh,
    )
    await sa_engine.dispose()


def _safe_allow_input(
    *,
    pack_risk_tier: str = "internal_write",
    class_: str = "interactive",
    tenant_id: str = "tenant-a",
    pack_id: str = "pack-x",
    actor_subject: str = "svc-a",
    pack_kind: str = "tool",
    requested_estimated_tokens: int = 500,
    current_tenant_concurrent_count: int = 0,
) -> dict[str, Any]:
    """Construct a happy-path admission input dict per spec §4.8 field
    set. Each test arm overrides one field to exercise its refusal
    path. Field names mirror what T8 ``SchedulerPolicy`` will thread
    from ``SubmitInput`` — the bundle reads them directly off
    ``input.<field>``."""
    return {
        "tenant_id": tenant_id,
        "pack_id": pack_id,
        "actor_subject": actor_subject,
        "class": class_,
        "pack_kind": pack_kind,
        "pack_risk_tier": pack_risk_tier,
        "current_tenant_concurrent_count": current_tenant_concurrent_count,
        "requested_estimated_tokens": requested_estimated_tokens,
    }


@opa_required
class TestSchedulerRegoAllowMatrix:
    """Direct-OPA ``allow`` decision matrix per spec §4.8."""

    @pytest.mark.asyncio
    async def test_default_deny_baseline_empty_input(self, engine: OPAEngine) -> None:
        """``data.cognic.scheduler.admit.allow`` defaults to ``false``
        per ADR-015 default-deny. Empty input → deny."""
        d = await engine.evaluate(
            decision_point=SCHEDULER_DECISION_POINT_ALLOW,
            input={},
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_allow_read_only_interactive(self, engine: OPAEngine) -> None:
        d = await engine.evaluate(
            decision_point=SCHEDULER_DECISION_POINT_ALLOW,
            input=_safe_allow_input(pack_risk_tier="read_only", class_="interactive"),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_allow_read_only_background(self, engine: OPAEngine) -> None:
        d = await engine.evaluate(
            decision_point=SCHEDULER_DECISION_POINT_ALLOW,
            input=_safe_allow_input(pack_risk_tier="read_only", class_="background"),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_allow_internal_write_interactive(self, engine: OPAEngine) -> None:
        d = await engine.evaluate(
            decision_point=SCHEDULER_DECISION_POINT_ALLOW,
            input=_safe_allow_input(pack_risk_tier="internal_write", class_="interactive"),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_allow_internal_write_background(self, engine: OPAEngine) -> None:
        d = await engine.evaluate(
            decision_point=SCHEDULER_DECISION_POINT_ALLOW,
            input=_safe_allow_input(pack_risk_tier="internal_write", class_="background"),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize("tier", _HIGH_RISK_TIERS)
    @pytest.mark.parametrize("class_", ["interactive", "background"])
    async def test_deny_six_high_risk_tiers_across_both_classes(
        self,
        engine: OPAEngine,
        tier: str,
        class_: str,
    ) -> None:
        """Pre-Sprint-13.5: 6 high-risk tiers x 2 classes = 12 deny
        cases. Mirrors ``sandbox.rego``'s pre-13.5 contract. When
        ``core/approval/engine.py`` wires up at 13.5, this refusal
        lifts; until then, high-risk admission is unconditionally
        denied at the scheduler layer."""
        d = await engine.evaluate(
            decision_point=SCHEDULER_DECISION_POINT_ALLOW,
            input=_safe_allow_input(pack_risk_tier=tier, class_=class_),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_deny_unknown_class_batch(self, engine: OPAEngine) -> None:
        """Class outside the 2-value Wave-1 vocabulary refuses regardless
        of tier (per spec §4.8 + ADR-022)."""
        d = await engine.evaluate(
            decision_point=SCHEDULER_DECISION_POINT_ALLOW,
            input=_safe_allow_input(pack_risk_tier="internal_write", class_="batch"),
        )
        assert d.allow is False


@opa_required
class TestSchedulerRegoRefusalReasonVocabulary:
    """Direct-subprocess ``refusal_reason`` decision matrix. The
    Sprint-4 ``OPAEngine`` evaluator only handles boolean expressions,
    so refusal_reason (a string) goes through the direct subprocess
    helper. T8 ``SchedulerPolicy`` will get an OPAEngine extension for
    string-returning decisions when it lands."""

    def test_default_refusal_reason_on_empty_input(self) -> None:
        """Empty input → no class match + no tier match → falls through
        to ``scheduler_default_deny``."""
        reason = _opa_eval_string_value({}, SCHEDULER_DECISION_POINT_REASON)
        assert reason == "scheduler_default_deny"

    @pytest.mark.parametrize("tier", _HIGH_RISK_TIERS)
    def test_high_risk_tier_refusal_reason(self, tier: str) -> None:
        """Known class + high-risk tier → ``scheduler_high_risk_tier_refused_pre_13_5``."""
        reason = _opa_eval_string_value(
            _safe_allow_input(pack_risk_tier=tier, class_="interactive"),
            SCHEDULER_DECISION_POINT_REASON,
        )
        assert reason == "scheduler_high_risk_tier_refused_pre_13_5"

    def test_unknown_class_refusal_reason(self) -> None:
        """Unknown class + safe tier → ``scheduler_class_unknown``."""
        reason = _opa_eval_string_value(
            _safe_allow_input(pack_risk_tier="internal_write", class_="batch"),
            SCHEDULER_DECISION_POINT_REASON,
        )
        assert reason == "scheduler_class_unknown"

    def test_deterministic_precedence_unknown_class_wins_over_high_risk_tier(self) -> None:
        """Plan §1090 — when class is unknown AND tier is high-risk,
        the else-chain ordering MUST surface ``scheduler_class_unknown``
        (class-vocabulary is the FIRST arm). Pins the no-complete-
        document-conflict invariant: Rego would error if two ``:=``
        rules both matched, so the if/else chain is the way to express
        deterministic precedence."""
        reason = _opa_eval_string_value(
            _safe_allow_input(pack_risk_tier="payment_action", class_="batch"),
            SCHEDULER_DECISION_POINT_REASON,
        )
        assert reason == "scheduler_class_unknown"

    def test_allow_path_refusal_reason_is_raw_default_deny_at_rego_layer(self) -> None:
        """**Raw-Rego-layer behaviour** — when ``allow=true``, the
        bundle's ``refusal_reason`` document STILL evaluates to a
        defined string (``scheduler_default_deny``) because Rego
        documents are not gated on each other. This is a property of
        the bundle, NOT a contract the T8 ``SchedulerPolicy`` layer
        propagates upward.

        **T8 contract**: ``SchedulerPolicy.evaluate`` MUST suppress
        the refusal_reason when ``allow=true`` and return
        ``PolicyDecision(allow=True, policy_reason=None)`` per plan
        §1179 — surfacing ``"scheduler_default_deny"`` as the
        policy_reason on an allowed decision would be audit/SIEM
        misleading (an examiner reading the audit log would see a
        deny reason on an allow row). The Rego layer cannot enforce
        this gating cheaply (documents evaluate independently); the
        Python policy layer is the right enforcement surface.

        This test pins the Rego document's raw behaviour so T8
        implementors know what they're receiving — NOT a contract
        for what to propagate upward. The matching T8 test will pin
        ``policy_reason is None`` when ``allow=True``.
        """
        reason = _opa_eval_string_value(
            _safe_allow_input(pack_risk_tier="internal_write", class_="interactive"),
            SCHEDULER_DECISION_POINT_REASON,
        )
        # Safe tier + known class: no class_unknown match, no
        # high_risk_tier match → falls through to default.
        assert reason == "scheduler_default_deny"


@opa_required
class TestSchedulerRegoVocabularyClosed:
    """Drift detector — every refusal_reason emitted across the
    decision matrix MUST be in the closed-enum set. Pins the
    wire-protocol-public contract per plan §1091."""

    def test_refusal_reason_vocabulary_is_closed(self) -> None:
        """Sweep every observed refusal across the decision matrix +
        assert each landed value is in _VALID_REFUSAL_REASONS."""
        observed: set[str] = set()
        # Default-deny on empty
        observed.add(_opa_eval_string_value({}, SCHEDULER_DECISION_POINT_REASON))
        # All 6 high-risk tiers
        for tier in _HIGH_RISK_TIERS:
            observed.add(
                _opa_eval_string_value(
                    _safe_allow_input(pack_risk_tier=tier, class_="interactive"),
                    SCHEDULER_DECISION_POINT_REASON,
                )
            )
        # Unknown class
        observed.add(
            _opa_eval_string_value(
                _safe_allow_input(pack_risk_tier="internal_write", class_="batch"),
                SCHEDULER_DECISION_POINT_REASON,
            )
        )
        # Precedence case
        observed.add(
            _opa_eval_string_value(
                _safe_allow_input(pack_risk_tier="payment_action", class_="batch"),
                SCHEDULER_DECISION_POINT_REASON,
            )
        )
        # Allow case
        observed.add(
            _opa_eval_string_value(
                _safe_allow_input(pack_risk_tier="internal_write", class_="interactive"),
                SCHEDULER_DECISION_POINT_REASON,
            )
        )
        assert observed.issubset(_VALID_REFUSAL_REASONS), (
            f"observed refusal_reason values {observed!r} not subset of "
            f"closed vocabulary {_VALID_REFUSAL_REASONS!r}"
        )
