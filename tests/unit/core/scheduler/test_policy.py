"""Sprint 10.5b T8 — SchedulerPolicy + PolicyDecision tests.

Validates SchedulerPolicy.evaluate() against the real Wave-1
scheduler.rego bundle landed at T7. Covers:

* Allow path: ``PolicyDecision(allow=True, policy_reason=None)`` —
  the T7 raw-bundle ``refusal_reason`` is SUPPRESSED at the policy
  layer per plan §1179 (propagating ``scheduler_default_deny`` on
  an allow row would be audit/SIEM misleading; this test pins the
  T8 suppression contract that T7's test docstring explicitly
  flagged).
* Deny paths with closed-enum refusal_reason threaded from the
  Rego bundle into ``policy_reason``: high-risk-tier + unknown-class
  + deterministic precedence (unknown-class wins over high-risk-tier
  when both match — pins the T7 if/else chain ordering through the
  Python policy boundary).
* Fail-closed envelope: OpaNotInstalledError / RegoEvaluationError
  in OPAEngine surfaces as ``PolicyDecision(allow=False,
  policy_reason="opa_unavailable")`` — engine still routes this to
  the public ``refused_policy_denied`` outcome (vocabulary separation
  per plan §1167).
* Input-threading drift detector: every key SchedulerPolicy builds
  into the Rego input dict matches what the bundle reads. Drift here
  = silent policy decision regression (Rego would see undefined values
  + most rules would fail-by-default-deny).
* Vocabulary boundary: every ``policy_reason`` value SchedulerPolicy
  can return is NOT in the wire-public ``SchedulerRefusalReason``
  Literal — pins the public-vs-internal separation per plan §1167.

OPA-dependent tests are gated behind ``@opa_required`` skip (mirrors
T7); the fail-closed test uses a stub OPAEngine subclass that raises
on every evaluate call so it runs without OPA installed.
"""

from __future__ import annotations

import shutil
import typing
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.policy.engine import (
    Decision,
    OPAEngine,
    OpaNotInstalledError,
    RegoEvaluationError,
)
from cognic_agentos.core.scheduler._types import (
    SchedulerRefusalReason,
    SubmitInput,
    TaskActor,
)
from cognic_agentos.core.scheduler.policy import (
    PolicyDecision,
    SchedulerPolicy,
)

opa_required = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary not installed — skip the SchedulerPolicy + real-bundle "
    "smoke; the fail-closed sub-suite still runs via stub OPAEngine",
)


SCHEDULER_BUNDLE_PATH = Path("policies/_default/scheduler.rego")


@pytest.fixture
async def opa_engine(tmp_path: Path) -> AsyncGenerator[OPAEngine, None]:
    """Build a real :class:`OPAEngine` over an in-memory SQLite audit +
    decision_history pair pointing at the real Wave-1 scheduler.rego
    bundle landed at T7. Mirrors the
    ``tests/unit/policies/test_scheduler_rego.py`` fixture shape."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'scheduler_policy_test.db'}"
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


def _make_submit_input(
    *,
    tenant_id: str = "tenant-a",
    pack_id: str = "pack-x",
    actor_subject: str = "svc-a",
    class_: str = "interactive",
    pack_kind: str = "tool",
    pack_risk_tier: str = "internal_write",
    requested_estimated_tokens: int = 500,
) -> SubmitInput:
    return SubmitInput(
        tenant_id=tenant_id,
        pack_id=pack_id,
        actor=TaskActor(subject=actor_subject, tenant_id=tenant_id, actor_type="service"),
        class_=class_,  # type: ignore[arg-type]
        pack_kind=pack_kind,
        pack_risk_tier=pack_risk_tier,
        requested_estimated_tokens=requested_estimated_tokens,
    )


# --- Allow / deny matrix via real OPA + scheduler.rego ----------------------


@opa_required
class TestSchedulerPolicyAllowDenyMatrix:
    """End-to-end through the real OPAEngine + the real T7 Wave-1
    scheduler.rego bundle. Pins the (SubmitInput → Rego input dict →
    bundle decision → PolicyDecision) full pipeline."""

    @pytest.mark.asyncio
    async def test_allow_path_returns_allow_with_policy_reason_none(
        self, opa_engine: OPAEngine
    ) -> None:
        """Plan §1179 — when the Rego bundle returns allow=true,
        SchedulerPolicy MUST return PolicyDecision(allow=True,
        policy_reason=None). The bundle's raw refusal_reason
        document is ``scheduler_default_deny`` even on the allow
        path (Rego documents are not gated on each other); the
        policy layer suppresses to None per the T7 docstring
        contract — surfacing the misleading default_deny string on
        an allow row would be audit/SIEM-confusing."""
        policy = SchedulerPolicy(opa_engine=opa_engine)
        decision = await policy.evaluate(
            _make_submit_input(pack_risk_tier="internal_write", class_="interactive")
        )
        assert decision == PolicyDecision(allow=True, policy_reason=None)

    @pytest.mark.asyncio
    async def test_high_risk_tier_returns_deny_with_internal_reason(
        self, opa_engine: OPAEngine
    ) -> None:
        """High-risk tier WITHOUT an attested grant
        (``_make_submit_input`` defaults ``approval_verified=False``)
        surfaces as PolicyDecision(allow=False,
        policy_reason="scheduler_high_risk_tier_refused_pre_13_5") —
        post-Sprint-13.5c2 this is the unverified arm of the CONVERT;
        a verified grant admits via allow arm 2. The reason string is
        INTERNAL diagnostic (audit-only); the engine's submit() maps
        this → public refused_policy_denied outcome per plan §1167."""
        policy = SchedulerPolicy(opa_engine=opa_engine)
        decision = await policy.evaluate(
            _make_submit_input(pack_risk_tier="payment_action", class_="interactive")
        )
        assert decision.allow is False
        assert decision.policy_reason == "scheduler_high_risk_tier_refused_pre_13_5"

    @pytest.mark.asyncio
    async def test_unknown_class_returns_deny_with_class_unknown_reason(
        self, opa_engine: OPAEngine
    ) -> None:
        policy = SchedulerPolicy(opa_engine=opa_engine)
        decision = await policy.evaluate(
            _make_submit_input(pack_risk_tier="internal_write", class_="batch")
        )
        assert decision.allow is False
        assert decision.policy_reason == "scheduler_class_unknown"

    @pytest.mark.asyncio
    async def test_deterministic_precedence_through_policy_layer(
        self, opa_engine: OPAEngine
    ) -> None:
        """Pins the T7 if/else chain ordering through the Python
        policy boundary — unknown-class BEATS high-risk-tier when
        both match. Without this regression the precedence could
        silently drift if the bundle is reordered."""
        policy = SchedulerPolicy(opa_engine=opa_engine)
        decision = await policy.evaluate(
            _make_submit_input(pack_risk_tier="payment_action", class_="batch")
        )
        assert decision.allow is False
        assert decision.policy_reason == "scheduler_class_unknown"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "tier",
        [
            "customer_data_read",
            "customer_data_write",
            "payment_action",
            "regulator_communication",
            "cross_tenant",
            "high_risk_custom",
        ],
    )
    async def test_all_six_high_risk_tiers_route_to_pre_13_5_reason(
        self, opa_engine: OPAEngine, tier: str
    ) -> None:
        policy = SchedulerPolicy(opa_engine=opa_engine)
        decision = await policy.evaluate(
            _make_submit_input(pack_risk_tier=tier, class_="background")
        )
        assert decision.allow is False
        assert decision.policy_reason == "scheduler_high_risk_tier_refused_pre_13_5"


# --- Fail-closed envelope (runs WITHOUT opa via stub OPAEngine) -----------


class _FailingStubOPAEngine:
    """Test stub for OPAEngine that raises on every evaluate call.
    Mirrors the OPAEngine.evaluate signature structurally (only
    method-level conformance is checked at the SchedulerPolicy call
    site; the Sprint-4 OPAEngine isn't a @runtime_checkable Protocol)."""

    def __init__(self, *, exc: type[Exception], msg: str) -> None:
        self._exc = exc
        self._msg = msg
        self._bundle_path = SCHEDULER_BUNDLE_PATH  # for refusal_reason path

    async def evaluate(self, *, decision_point: str, input: dict[str, Any]) -> Decision:
        raise self._exc(self._msg)


class TestSchedulerPolicyFailClosed:
    """Per plan §1181 — OPA error surface MUST fail-closed at the
    policy layer: deny + policy_reason="opa_unavailable". The engine
    still routes this to the public refused_policy_denied outcome."""

    @pytest.mark.asyncio
    async def test_opa_not_installed_fails_closed_with_opa_unavailable(self) -> None:
        stub = _FailingStubOPAEngine(exc=OpaNotInstalledError, msg="opa not found on PATH")
        policy = SchedulerPolicy(opa_engine=stub)  # type: ignore[arg-type]
        decision = await policy.evaluate(_make_submit_input())
        assert decision == PolicyDecision(allow=False, policy_reason="opa_unavailable")

    @pytest.mark.asyncio
    async def test_rego_evaluation_error_fails_closed_with_opa_unavailable(self) -> None:
        stub = _FailingStubOPAEngine(exc=RegoEvaluationError, msg="OPA returned malformed JSON")
        policy = SchedulerPolicy(opa_engine=stub)  # type: ignore[arg-type]
        decision = await policy.evaluate(_make_submit_input())
        assert decision == PolicyDecision(allow=False, policy_reason="opa_unavailable")


# --- Input-threading drift detector ---------------------------------------


class TestSchedulerPolicyInputThreading:
    """Pins the spec §4.8 input-key set. Drift between SchedulerPolicy
    and the Rego bundle = silent policy decision regression (Rego sees
    undefined values + most rules fail-by-default-deny). Plan §1182.

    Round-1 P2 reviewer fix: this class is INTENTIONALLY NOT behind
    ``@opa_required`` — every test calls the pure-Python static method
    ``SchedulerPolicy._build_rego_input`` which has no OPA dependency.
    Gating this class would skip the projection-contract regression on
    every OPA-less CI lane, leaving the most-likely-future-regression
    class (per spec §6.1 watchpoint) untested most of the time."""

    def test_build_rego_input_includes_all_spec_keys(self) -> None:
        """9-key contract: the spec §4.8 8-key set + the Sprint-13.5c2
        ``approval_verified`` attestation key (ADR-014 — ALWAYS threaded;
        the bundle's high-risk allow arm requires it strictly true)."""
        rego_input = SchedulerPolicy._build_rego_input(_make_submit_input())
        assert set(rego_input.keys()) == {
            "tenant_id",
            "pack_id",
            "actor_subject",
            "class",
            "pack_kind",
            "pack_risk_tier",
            "current_tenant_concurrent_count",
            "requested_estimated_tokens",
            "approval_verified",
        }

    def test_build_rego_input_threads_engine_owned_attestation(self) -> None:
        """Sprint 13.5c2 (ADR-014): the ENGINE-OWNED ``approval_verified``
        bool is threaded verbatim — True on a verified grant, False
        otherwise; the key is ALWAYS present (falsy-by-absence is the
        bundle's defence, not the projection's contract)."""
        import dataclasses

        verified = dataclasses.replace(_make_submit_input(), approval_verified=True)
        assert SchedulerPolicy._build_rego_input(verified)["approval_verified"] is True
        assert SchedulerPolicy._build_rego_input(_make_submit_input())["approval_verified"] is False

    def test_build_rego_input_threads_class_under_correct_key(self) -> None:
        """SubmitInput.class_ has a trailing underscore (Python keyword
        collision); the Rego bundle reads input.class (no underscore).
        Pin the key-name translation."""
        rego_input = SchedulerPolicy._build_rego_input(_make_submit_input(class_="background"))
        assert rego_input["class"] == "background"
        assert "class_" not in rego_input

    def test_build_rego_input_threads_actor_subject_not_full_actor_object(self) -> None:
        """The Rego bundle reads input.actor_subject (a string), not
        a nested input.actor.subject. Pin the projection."""
        rego_input = SchedulerPolicy._build_rego_input(_make_submit_input(actor_subject="svc-x"))
        assert rego_input["actor_subject"] == "svc-x"
        assert "actor" not in rego_input


# --- Vocabulary-boundary regression ---------------------------------------


class TestSchedulerPolicyVocabularyBoundary:
    """Plan §1167 + §1183 — every internal policy_reason value MUST
    NOT appear in the wire-public SchedulerRefusalReason Literal.
    Engine.submit() bridges by mapping all denies → public
    refused_policy_denied + carrying policy_reason as audit-only.
    Drift here = silent leak of an internal diagnostic string into
    the wire-public closed-enum."""

    def test_opa_unavailable_is_not_in_wire_public_refusal_enum(self) -> None:
        wire_public = set(typing.get_args(SchedulerRefusalReason))
        assert "opa_unavailable" not in wire_public

    def test_rego_reason_strings_are_not_in_wire_public_refusal_enum(self) -> None:
        wire_public = set(typing.get_args(SchedulerRefusalReason))
        for rego_reason in (
            "scheduler_high_risk_tier_refused_pre_13_5",
            "scheduler_class_unknown",
            "scheduler_default_deny",
        ):
            assert rego_reason not in wire_public, (
                f"{rego_reason!r} from rego bundle MUST stay internal — "
                f"engine.submit() bridges via refused_policy_denied"
            )


# --- PolicyDecision dataclass shape ---------------------------------------


class TestPolicyDecisionDataclass:
    def test_policy_decision_is_frozen(self) -> None:
        import dataclasses

        d = PolicyDecision(allow=True, policy_reason=None)
        with pytest.raises(dataclasses.FrozenInstanceError):
            d.allow = False  # type: ignore[misc]

    def test_policy_decision_equality_by_value(self) -> None:
        assert PolicyDecision(allow=True, policy_reason=None) == PolicyDecision(
            allow=True, policy_reason=None
        )
        assert PolicyDecision(allow=False, policy_reason="x") != PolicyDecision(
            allow=False, policy_reason="y"
        )

    def test_policy_decision_allow_true_with_none_reason_allowed(self) -> None:
        """The canonical allow shape per plan §1179."""
        d = PolicyDecision(allow=True, policy_reason=None)
        assert d.allow is True
        assert d.policy_reason is None


# --- Subprocess env parity drift detector --------------------------------


class TestSchedulerPolicySubprocessEnvParity:
    """Round-1 P2 reviewer fix — pin the SchedulerPolicy subprocess
    env constant against the OPAEngine constant. CC subprocess
    invariants (PATH + HOME) MUST stay in lockstep between the two
    modules; drift = OPA binary may see different filesystem search
    paths or write incidental caches to different locations,
    silently changing security posture.

    Test-only drift detector per
    [[feedback_drift_detector_test_only_no_runtime_import]] — both
    production modules declare their OWN local copy of the env dict
    (avoids cross-module runtime import which would trip the engine's
    halt-before-commit rule on every SchedulerPolicy edit); this test
    imports from BOTH and asserts equality so any future drift trips
    at CI time."""

    def test_minimal_subprocess_env_matches_opa_engine_canonical(self) -> None:
        from cognic_agentos.core.policy.engine import (
            _MINIMAL_SUBPROCESS_ENV as opa_engine_env,
        )
        from cognic_agentos.core.scheduler.policy import (
            _MINIMAL_SUBPROCESS_ENV as scheduler_policy_env,
        )

        assert scheduler_policy_env == opa_engine_env, (
            f"SchedulerPolicy subprocess env {scheduler_policy_env!r} has "
            f"drifted from OPAEngine canonical {opa_engine_env!r}. CC "
            f"subprocess invariant — both modules invoke the same opa "
            f"binary against the same bundle + must use the same env."
        )

    def test_canonical_env_contains_path_and_home_only(self) -> None:
        """Document the exact wire-public contract — PATH for binary
        resolution + HOME=/tmp to keep incidental cache writes off the
        AgentOS service-account home per OPAEngine §2 invariant 5."""
        from cognic_agentos.core.scheduler.policy import (
            _MINIMAL_SUBPROCESS_ENV as scheduler_policy_env,
        )

        assert set(scheduler_policy_env.keys()) == {"PATH", "HOME"}
        assert scheduler_policy_env["HOME"] == "/tmp"


# --- Z1b focused-coverage repair: _fetch_refusal_reason error paths -----
#
# Per [[feedback_verify_promotion_meets_floor_at_promotion_time]], Z1b
# gate-promotion runs the coverage check against fresh data in the SAME
# commit. The opa_required tests above cover the happy paths (allow=true
# + deny-with-reason); these tests cover the subprocess error paths in
# ``_fetch_refusal_reason`` that the OPA-binary path doesn't naturally
# exercise. All use a stub OPAEngine + monkeypatched subprocess.run so
# they're OPA-binary-independent.


class _StubOPAEngineForRefusalReason:
    """Minimal stub exposing only the 3 attrs ``_fetch_refusal_reason``
    reads off the injected OPAEngine: ``_opa_path`` / ``_bundle_path``
    / ``_eval_timeout_s``. Construct with ``opa_path=None`` to exercise
    the OpaNotInstalledError path at policy.py:270; default opa_path
    is just a sentinel string + tests monkeypatch subprocess.run to
    avoid actually invoking opa."""

    def __init__(
        self,
        *,
        opa_path: str | None = "/fake/opa",
        bundle_path: Path = SCHEDULER_BUNDLE_PATH,
        eval_timeout_s: float = 5.0,
    ) -> None:
        self._opa_path = opa_path
        self._bundle_path = bundle_path
        self._eval_timeout_s = eval_timeout_s


class TestSchedulerPolicyFetchRefusalReasonErrorPaths:
    """Targeted coverage for the ``_fetch_refusal_reason`` subprocess
    error paths (Z1b gate-promotion repair). Each test exercises one
    branch of the helper's try/except + result-shape validation chain
    so the 95% line / 90% branch floor is met on fresh coverage data."""

    def test_opa_path_none_raises_opa_not_installed(self) -> None:
        """policy.py:269-273 — when the injected OPAEngine has
        ``_opa_path = None``, the helper short-circuits with
        ``OpaNotInstalledError`` without invoking subprocess."""
        policy = SchedulerPolicy(opa_engine=_StubOPAEngineForRefusalReason(opa_path=None))  # type: ignore[arg-type]
        with pytest.raises(OpaNotInstalledError, match="opa not found on PATH"):
            policy._fetch_refusal_reason({})

    def test_subprocess_timeout_translates_to_rego_evaluation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """policy.py:296-299 — ``subprocess.TimeoutExpired`` translates
        to ``RegoEvaluationError`` with a timeout message."""
        import subprocess as subprocess_module

        def _raise_timeout(*args: Any, **kwargs: Any) -> Any:
            raise subprocess_module.TimeoutExpired(cmd=args[0], timeout=5.0)

        monkeypatch.setattr("cognic_agentos.core.scheduler.policy.subprocess.run", _raise_timeout)
        policy = SchedulerPolicy(opa_engine=_StubOPAEngineForRefusalReason())  # type: ignore[arg-type]
        with pytest.raises(RegoEvaluationError, match="evaluate timeout"):
            policy._fetch_refusal_reason({})

    def test_file_not_found_translates_to_opa_not_installed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """policy.py:300-304 — ``FileNotFoundError`` from
        ``subprocess.run`` (binary missing) translates to
        ``OpaNotInstalledError``."""

        def _raise_filenotfound(*args: Any, **kwargs: Any) -> Any:
            raise FileNotFoundError("/fake/opa")

        monkeypatch.setattr(
            "cognic_agentos.core.scheduler.policy.subprocess.run", _raise_filenotfound
        )
        policy = SchedulerPolicy(opa_engine=_StubOPAEngineForRefusalReason())  # type: ignore[arg-type]
        with pytest.raises(OpaNotInstalledError, match="opa binary not found at pinned path"):
            policy._fetch_refusal_reason({})

    def test_nonzero_returncode_raises_rego_evaluation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """policy.py:306-310 — non-zero exit code from opa subprocess
        translates to ``RegoEvaluationError`` carrying the stderr repr."""
        import subprocess as subprocess_module

        def _return_nonzero(*args: Any, **kwargs: Any) -> Any:
            return subprocess_module.CompletedProcess(
                args=args[0],
                returncode=1,
                stdout="",
                stderr="opa: bundle invalid",
            )

        monkeypatch.setattr("cognic_agentos.core.scheduler.policy.subprocess.run", _return_nonzero)
        policy = SchedulerPolicy(opa_engine=_StubOPAEngineForRefusalReason())  # type: ignore[arg-type]
        with pytest.raises(RegoEvaluationError, match="non-zero exit"):
            policy._fetch_refusal_reason({})

    def test_malformed_json_stdout_raises_rego_evaluation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """policy.py:312-317 — JSON decode failure on stdout translates
        to ``RegoEvaluationError``."""
        import subprocess as subprocess_module

        def _return_malformed_json(*args: Any, **kwargs: Any) -> Any:
            return subprocess_module.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout="not-json{",
                stderr="",
            )

        monkeypatch.setattr(
            "cognic_agentos.core.scheduler.policy.subprocess.run", _return_malformed_json
        )
        policy = SchedulerPolicy(opa_engine=_StubOPAEngineForRefusalReason())  # type: ignore[arg-type]
        with pytest.raises(RegoEvaluationError, match="malformed JSON"):
            policy._fetch_refusal_reason({})

    def test_non_dict_json_root_raises_rego_evaluation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """policy.py:318-321 — JSON parses to a list (not dict)
        translates to ``RegoEvaluationError``."""
        import subprocess as subprocess_module

        def _return_list_json(*args: Any, **kwargs: Any) -> Any:
            return subprocess_module.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout="[]",
                stderr="",
            )

        monkeypatch.setattr(
            "cognic_agentos.core.scheduler.policy.subprocess.run", _return_list_json
        )
        policy = SchedulerPolicy(opa_engine=_StubOPAEngineForRefusalReason())  # type: ignore[arg-type]
        with pytest.raises(RegoEvaluationError, match="not an object"):
            policy._fetch_refusal_reason({})

    def test_empty_result_array_raises_rego_evaluation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """policy.py:322-324 — ``result: []`` (no rule matched)
        translates to ``RegoEvaluationError``."""
        import subprocess as subprocess_module

        def _return_empty_result(*args: Any, **kwargs: Any) -> Any:
            return subprocess_module.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='{"result": []}',
                stderr="",
            )

        monkeypatch.setattr(
            "cognic_agentos.core.scheduler.policy.subprocess.run", _return_empty_result
        )
        policy = SchedulerPolicy(opa_engine=_StubOPAEngineForRefusalReason())  # type: ignore[arg-type]
        with pytest.raises(RegoEvaluationError, match="empty result set"):
            policy._fetch_refusal_reason({})

    def test_unexpected_result_shape_raises_rego_evaluation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """policy.py:325-328 — result has unexpected shape (missing
        ``expressions`` key) translates to ``RegoEvaluationError``."""
        import subprocess as subprocess_module

        def _return_unexpected_shape(*args: Any, **kwargs: Any) -> Any:
            return subprocess_module.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='{"result": [{"unexpected": "shape"}]}',
                stderr="",
            )

        monkeypatch.setattr(
            "cognic_agentos.core.scheduler.policy.subprocess.run", _return_unexpected_shape
        )
        policy = SchedulerPolicy(opa_engine=_StubOPAEngineForRefusalReason())  # type: ignore[arg-type]
        with pytest.raises(RegoEvaluationError, match="result shape unexpected"):
            policy._fetch_refusal_reason({})

    def test_non_string_expression_value_raises_rego_evaluation_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """policy.py:329-332 — when ``expressions[0]['value']`` is not
        a string (e.g. opa returned a bool for a refusal_reason
        decision point), translate to ``RegoEvaluationError``."""
        import subprocess as subprocess_module

        def _return_non_string_value(*args: Any, **kwargs: Any) -> Any:
            return subprocess_module.CompletedProcess(
                args=args[0],
                returncode=0,
                stdout='{"result": [{"expressions": [{"value": 42}]}]}',
                stderr="",
            )

        monkeypatch.setattr(
            "cognic_agentos.core.scheduler.policy.subprocess.run", _return_non_string_value
        )
        policy = SchedulerPolicy(opa_engine=_StubOPAEngineForRefusalReason())  # type: ignore[arg-type]
        with pytest.raises(RegoEvaluationError, match="not string"):
            policy._fetch_refusal_reason({})


class TestSchedulerPolicyEvaluateDenyPathRefusalReasonFailClosed:
    """Z1b coverage — pins ``policy.py:197-201`` fail-closed path
    (when allow=False AND _fetch_refusal_reason raises, return
    ``PolicyDecision(allow=False, policy_reason="opa_unavailable")``).
    The deny verdict is preserved even when we can't determine the
    specific reason."""

    @pytest.mark.asyncio
    async def test_deny_path_fetch_refusal_reason_failure_fails_closed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When OPAEngine.evaluate returns allow=False AND the
        subsequent ``_fetch_refusal_reason`` call raises (subprocess
        timeout, malformed output, etc), the policy MUST still
        return ``PolicyDecision(allow=False, policy_reason="opa_unavailable")``
        — the deny verdict stands; we just can't surface the
        specific Rego reason."""
        from cognic_agentos.core.policy.engine import Decision

        class _DenyStubEngine:
            async def evaluate(self, *, decision_point: str, input: dict[str, Any]) -> Decision:
                return Decision(
                    allow=False,
                    rule_matched=decision_point,
                    reasoning="rule matched: deny (default)",
                    decision_data=None,
                )

        policy = SchedulerPolicy(opa_engine=_DenyStubEngine())  # type: ignore[arg-type]

        # Force _fetch_refusal_reason to raise by monkeypatching it
        # to raise RegoEvaluationError directly
        def _raise_rego_error(rego_input: dict[str, Any]) -> str:
            raise RegoEvaluationError("simulated reason-fetch failure")

        monkeypatch.setattr(policy, "_fetch_refusal_reason", _raise_rego_error)
        decision = await policy.evaluate(_make_submit_input())
        assert decision == PolicyDecision(allow=False, policy_reason="opa_unavailable")
