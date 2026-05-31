"""Sprint 11.5a T9 — per-recall gate (§7.2) precedence + branch coverage.

CRITICAL CONTROL. Every refusal test stacks at least one LATER-step failure
into the same input and proves the EARLIER (target) reason wins. The recall
gate runs no kill-switch / DLP / consent / retention — only the four §7.2
steps (sub-agent guard, capability, subject scope, purpose matrix).
"""

from __future__ import annotations

import inspect

import pytest

from cognic_agentos.core.dlp.scanner import DLPVerdict
from cognic_agentos.core.memory._context import MemoryCallerContext
from cognic_agentos.core.memory.gate import MemoryGate
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, SubjectRef
from cognic_agentos.core.policy.engine import (
    Decision,
    OpaNotInstalledError,
    RegoEvaluationError,
)

_PURPOSE_POINT = "data.cognic.memory.recall.purpose_compatible.allow"
_CROSS_SUBJECT_POINT = "data.cognic.memory.cross_subject.allow"


# --------------------------------------------------------------------------- #
# Fakes.
# --------------------------------------------------------------------------- #


class _Frozen:
    def __init__(self, frozen: bool = False) -> None:
        self._frozen = frozen

    async def is_write_frozen(self, *, tenant_id: str) -> bool:
        return self._frozen


class _FakeDLP:
    def scan(self, value: object) -> DLPVerdict:
        return DLPVerdict(detected_classes=frozenset(), redaction_spans=(), confidence=0.0)


class _FakeConsent:
    async def validate(
        self, token: object, **kw: object
    ) -> None:  # pragma: no cover - unused on recall
        return None


class _FakeOPA:
    def __init__(
        self,
        *,
        allow: bool = True,
        raises: dict[str, Exception] | None = None,
        allow_by_point: dict[str, bool] | None = None,
    ) -> None:
        self._allow = allow
        self._raises = raises or {}
        self._allow_by_point = allow_by_point or {}
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def evaluate(self, *, decision_point: str, input: dict[str, object]) -> Decision:
        self.calls.append((decision_point, input))
        exc = self._raises.get(decision_point)
        if exc is not None:
            raise exc
        allow = self._allow_by_point.get(decision_point, self._allow)
        return Decision(
            allow=allow, rule_matched=decision_point, reasoning="fake", decision_data=None
        )


_SUBJ = SubjectRef(kind="human", id="cust-7")
_OTHER_SUBJ = SubjectRef(kind="human", id="cust-999")

# A full read-capability set so capability never accidentally trips.
_ALL_CAPS = frozenset({"memory_read.scratch", "memory_read.task", "memory_read.long_term"})


def _ctx(**over: object) -> MemoryCallerContext:
    base: dict[str, object] = dict(
        tenant_id="t1",
        agent_id="kyc",
        actor_id="svc",
        served_subject=_SUBJ,
        is_subagent=False,
        long_term_writes_allowed=True,
        cross_subject_recall=False,
        memory_read_capabilities=_ALL_CAPS,
        declared_purposes=frozenset({"customer_support"}),
        declared_data_classes=frozenset({"public"}),
        risk_tier="internal_write",
    )
    base.update(over)
    return MemoryCallerContext(**base)  # type: ignore[arg-type]


def _gate(
    *, context: MemoryCallerContext | None = None, policy: _FakeOPA | None = None
) -> MemoryGate:
    return MemoryGate(
        context=context or _ctx(),
        dlp=_FakeDLP(),
        consent=_FakeConsent(),  # type: ignore[arg-type]
        policy=policy or _FakeOPA(),  # type: ignore[arg-type]
        kill_switch=_Frozen(False),
    )


# --------------------------------------------------------------------------- #
# Step 1 — sub-agent durable-access guard.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("tier", ["task", "long_term"])
async def test_subagent_durable_recall_refused_winning_over_capability_and_purpose(tier):
    # Sub-agent reading a durable tier; stack a missing capability (later step 2)
    # AND a purpose-matrix deny (later step 4) — step 1 must win.
    ctx = _ctx(is_subagent=True, memory_read_capabilities=frozenset())
    gate = _gate(context=ctx, policy=_FakeOPA(allow=False))
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_recall(tier=tier, recall_purpose="customer_support")
    assert ei.value.reason == "memory_subagent_durable_access_refused"


async def test_subagent_scratch_recall_allowed():
    # §7.3 I2: children may read scratch only. The gate returns None on success
    # and raises MemoryOperationRefused on every refusal path — reaching past
    # the call without an exception IS the success assertion.
    ctx = _ctx(is_subagent=True)
    gate = _gate(context=ctx)
    await gate.check_recall(tier="scratch", recall_purpose="customer_support")


# --------------------------------------------------------------------------- #
# Step 2 — read capability for the tier.
# --------------------------------------------------------------------------- #


async def test_capability_missing_refused_winning_over_subject_scope_and_purpose():
    # No memory_read.task capability; stack a cross-subject scope failure
    # (later step 3) AND a purpose-matrix deny (later step 4) — step 2 wins.
    ctx = _ctx(memory_read_capabilities=frozenset({"memory_read.scratch"}))
    gate = _gate(context=ctx, policy=_FakeOPA(allow=False))
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_recall(
            tier="task",
            recall_purpose="customer_support",
            subject=_OTHER_SUBJ,  # would trip step 3
        )
    assert ei.value.reason == "memory_recall_capability_missing"


@pytest.mark.parametrize(
    "tier,cap",
    [
        ("scratch", "memory_read.scratch"),
        ("task", "memory_read.task"),
        ("long_term", "memory_read.long_term"),
    ],
)
async def test_capability_is_tier_specific(tier, cap):
    # Holding ONLY the matching capability passes; holding a different tier's
    # capability does not.
    ctx = _ctx(memory_read_capabilities=frozenset({cap}))
    gate = _gate(context=ctx)
    await gate.check_recall(tier=tier, recall_purpose="customer_support")  # no raise == pass

    wrong = _ctx(memory_read_capabilities=frozenset({"memory_read.scratch"}) - {cap})
    gate2 = _gate(context=wrong)
    if cap != "memory_read.scratch":
        with pytest.raises(MemoryOperationRefused) as ei:
            await gate2.check_recall(tier=tier, recall_purpose="customer_support")
        assert ei.value.reason == "memory_recall_capability_missing"


# --------------------------------------------------------------------------- #
# Step 3 — subject scope (explicit-subject reads only).
# --------------------------------------------------------------------------- #


async def test_cross_subject_read_refused_when_not_declared_winning_over_purpose():
    # Explicit subject != served; cross_subject_recall not declared. Stack a
    # purpose-matrix deny (later step 4) — step 3 must win.
    ctx = _ctx(cross_subject_recall=False)
    gate = _gate(context=ctx, policy=_FakeOPA(allow=False))
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_recall(
            tier="task",
            recall_purpose="customer_support",
            subject=_OTHER_SUBJ,
        )
    assert ei.value.reason == "memory_cross_subject_access_refused"


async def test_cross_subject_read_refused_when_rego_denies_winning_over_purpose():
    ctx = _ctx(cross_subject_recall=True)
    gate = _gate(
        context=ctx,
        policy=_FakeOPA(
            allow_by_point={_CROSS_SUBJECT_POINT: False, _PURPOSE_POINT: False},
        ),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_recall(
            tier="task",
            recall_purpose="customer_support",
            subject=_OTHER_SUBJ,
        )
    assert ei.value.reason == "memory_cross_subject_access_refused"


async def test_cross_subject_read_rego_error_maps_to_cross_subject_refusal():
    # Per-decision-point fail-closed: cross_subject Rego error -> cross-subject
    # refusal, NOT purpose mismatch.
    ctx = _ctx(cross_subject_recall=True)
    gate = _gate(
        context=ctx,
        policy=_FakeOPA(raises={_CROSS_SUBJECT_POINT: OpaNotInstalledError("no opa")}),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_recall(
            tier="task",
            recall_purpose="customer_support",
            subject=_OTHER_SUBJ,
        )
    assert ei.value.reason == "memory_cross_subject_access_refused"


async def test_cross_subject_read_allowed_when_declared_and_rego_allows():
    ctx = _ctx(cross_subject_recall=True)
    gate = _gate(context=ctx, policy=_FakeOPA(allow=True))
    await gate.check_recall(  # no raise == pass
        tier="task",
        recall_purpose="customer_support",
        subject=_OTHER_SUBJ,
    )


async def test_same_subject_read_skips_cross_subject_rego():
    policy = _FakeOPA(allow=True)
    gate = _gate(context=_ctx(), policy=policy)
    await gate.check_recall(
        tier="task",
        recall_purpose="customer_support",
        subject=_SUBJ,  # equals served subject
    )
    assert all(p != _CROSS_SUBJECT_POINT for p, _ in policy.calls)


async def test_implicit_subject_read_skips_subject_scope():
    # subject=None -> implicit served-subject read; step 3 is N/A.
    policy = _FakeOPA(allow=True)
    gate = _gate(context=_ctx(cross_subject_recall=False), policy=policy)
    await gate.check_recall(tier="task", recall_purpose="customer_support", subject=None)
    assert all(p != _CROSS_SUBJECT_POINT for p, _ in policy.calls)


# --------------------------------------------------------------------------- #
# Step 4 — purpose-compatibility matrix.
# --------------------------------------------------------------------------- #


async def test_purpose_mismatch_when_rego_denies():
    # Last refusal step; nothing later to stack -> prove it fires after a clean
    # pass of steps 1-3.
    gate = _gate(policy=_FakeOPA(allow_by_point={_PURPOSE_POINT: False}))
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_recall(
            tier="task",
            recall_purpose="regulatory_reporting",
            write_purpose="customer_support",
        )
    assert ei.value.reason == "memory_purpose_mismatch"


async def test_purpose_matrix_rego_error_maps_to_purpose_mismatch():
    # Per-decision-point fail-closed: purpose-matrix OPA error -> purpose
    # mismatch.
    gate = _gate(policy=_FakeOPA(raises={_PURPOSE_POINT: RegoEvaluationError("boom")}))
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_recall(tier="task", recall_purpose="customer_support")
    assert ei.value.reason == "memory_purpose_mismatch"


async def test_purpose_matrix_passes_recall_and_write_purpose_into_rego_input():
    policy = _FakeOPA(allow=True)
    gate = _gate(policy=policy)
    await gate.check_recall(
        tier="task",
        recall_purpose="fraud_detection",
        write_purpose="customer_support",
    )
    purpose_calls = [inp for p, inp in policy.calls if p == _PURPOSE_POINT]
    assert len(purpose_calls) == 1
    assert purpose_calls[0]["recall_purpose"] == "fraud_detection"
    assert purpose_calls[0]["write_purpose"] == "customer_support"


# --------------------------------------------------------------------------- #
# Step 5 — success.
# --------------------------------------------------------------------------- #


async def test_recall_proceeds_on_clean_path():
    # Clean path: the gate returns None and does not raise.
    gate = _gate(policy=_FakeOPA(allow=True))
    await gate.check_recall(tier="long_term", recall_purpose="customer_support")


async def test_recall_write_purpose_defaults_to_none():
    # write_purpose is optional; the gate still consults the matrix with None.
    policy = _FakeOPA(allow=True)
    gate = _gate(policy=policy)
    await gate.check_recall(tier="task", recall_purpose="customer_support")
    purpose_calls = [inp for p, inp in policy.calls if p == _PURPOSE_POINT]
    assert purpose_calls[0]["write_purpose"] is None


# --------------------------------------------------------------------------- #
# Contract guards.
# --------------------------------------------------------------------------- #


def test_check_recall_does_not_accept_caller_identity():
    sig_params = set(inspect.signature(MemoryGate.check_recall).parameters)
    for forbidden in ("tenant_id", "agent_id", "actor_id", "served_subject"):
        assert forbidden not in sig_params


def test_check_recall_returns_none_annotation():
    ret = inspect.signature(MemoryGate.check_recall).return_annotation
    assert ret in (None, "None", type(None))
