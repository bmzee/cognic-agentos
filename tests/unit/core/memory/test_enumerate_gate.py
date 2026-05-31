"""Sprint 11.5a T10 — enumerate-family recall gate (``check_enumerate``).

CRITICAL CONTROL. ``check_enumerate`` is the §7.2-minus-keyed-record gate that
``MemoryAPI.list_for_subject`` / ``MemoryAPI.list_blocks`` run before walking a
subject's records. Ordered precedence IS the contract (sub-agent durable guard →
per-tier read capability → subject scope); the first applicable failure
short-circuits and raises the typed ``MemoryOperationRefused`` carrying the
wire-public closed-enum reason. Enumeration is NOT a capability bypass — EVERY
enumerated tier must be held.

Mirrors ``test_recall_gate.py``'s fakes/builders (bare ``async def``; the gate
is constructed directly so the test exercises ``check_enumerate`` in isolation
from the adapter + audit).
"""

from __future__ import annotations

import pytest

from cognic_agentos.core.dlp.scanner import DLPVerdict
from cognic_agentos.core.memory._context import MemoryCallerContext
from cognic_agentos.core.memory.gate import MemoryGate
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, SubjectRef
from cognic_agentos.core.policy.engine import Decision

# --------------------------------------------------------------------------- #
# Fakes (mirror test_recall_gate.py).
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
    ) -> None:  # pragma: no cover - unused on enumerate
        return None


class _FakeOPA:
    def __init__(self, *, allow: bool = True) -> None:
        self._allow = allow
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def evaluate(self, *, decision_point: str, input: dict[str, object]) -> Decision:
        self.calls.append((decision_point, input))
        return Decision(
            allow=self._allow, rule_matched=decision_point, reasoning="fake", decision_data=None
        )


_SUBJ = SubjectRef(kind="human", id="cust-7")
_OTHER_SUBJ = SubjectRef(kind="human", id="cust-999")

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


@pytest.mark.parametrize("tiers", [("task",), ("long_term",), ("task", "long_term")])
async def test_subagent_durable_enumerate_refused(tiers):
    # Sub-agent enumerating ANY durable tier; stack missing caps (later step 2)
    # AND a cross-subject scope failure (later step 3) — step 1 must win.
    ctx = _ctx(is_subagent=True, memory_read_capabilities=frozenset(), cross_subject_recall=False)
    gate = _gate(context=ctx)
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_enumerate(_OTHER_SUBJ, tiers=tiers)
    assert ei.value.reason == "memory_subagent_durable_access_refused"


async def test_subagent_scratch_enumerate_allowed():
    # §7.3 I2: a sub-agent may enumerate scratch only — step 1 does not fire.
    ctx = _ctx(is_subagent=True)
    gate = _gate(context=ctx)
    await gate.check_enumerate(_SUBJ, tiers=("scratch",))  # no raise == pass


# --------------------------------------------------------------------------- #
# Step 2 — read capability for EVERY enumerated tier.
# --------------------------------------------------------------------------- #


async def test_enumerate_capability_missing_refused():
    # Caps lack memory_read.long_term; enumerate ("long_term",) -> step 2 fires.
    ctx = _ctx(memory_read_capabilities=frozenset({"memory_read.task"}))
    gate = _gate(context=ctx)
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_enumerate(_SUBJ, tiers=("long_term",))
    assert ei.value.reason == "memory_recall_capability_missing"


async def test_enumerate_requires_every_tier_capability_winning_over_subject_scope():
    # Holding only memory_read.task while enumerating ("task","long_term") must
    # refuse on the missing long_term cap; stack a cross-subject scope failure
    # (later step 3) — step 2 wins.
    ctx = _ctx(memory_read_capabilities=frozenset({"memory_read.task"}), cross_subject_recall=False)
    gate = _gate(context=ctx)
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_enumerate(_OTHER_SUBJ, tiers=("task", "long_term"))
    assert ei.value.reason == "memory_recall_capability_missing"


# --------------------------------------------------------------------------- #
# Step 3 — subject scope (cross-subject leak guard).
# --------------------------------------------------------------------------- #


async def test_cross_subject_enumerate_refused_when_not_declared():
    # Explicit subject != served, cross_subject_recall=False -> step 3 fires.
    ctx = _ctx(cross_subject_recall=False)
    gate = _gate(context=ctx)
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_enumerate(_OTHER_SUBJ, tiers=("task", "long_term"))
    assert ei.value.reason == "memory_cross_subject_access_refused"


async def test_cross_subject_enumerate_refused_when_rego_denies():
    ctx = _ctx(cross_subject_recall=True)
    gate = _gate(context=ctx, policy=_FakeOPA(allow=False))
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_enumerate(_OTHER_SUBJ, tiers=("task", "long_term"))
    assert ei.value.reason == "memory_cross_subject_access_refused"


async def test_cross_subject_enumerate_allowed_when_declared_and_rego_allows():
    ctx = _ctx(cross_subject_recall=True)
    gate = _gate(context=ctx, policy=_FakeOPA(allow=True))
    await gate.check_enumerate(_OTHER_SUBJ, tiers=("task", "long_term"))  # no raise == pass


# --------------------------------------------------------------------------- #
# Step 4 — success (served subject, full caps, non-subagent).
# --------------------------------------------------------------------------- #


async def test_served_subject_enumerate_proceeds():
    # subject == served, full caps, not a sub-agent. The gate returns None on
    # success and raises MemoryOperationRefused on every refusal path — reaching
    # past the call without an exception IS the success assertion (mirrors
    # test_recall_gate.py's success-path idiom; check_enumerate is typed -> None).
    gate = _gate(context=_ctx())
    await gate.check_enumerate(_SUBJ, tiers=("task", "long_term"))


async def test_same_subject_enumerate_skips_cross_subject_rego():
    # subject == served -> step 3 is N/A; the cross-subject Rego is never called.
    policy = _FakeOPA(allow=True)
    gate = _gate(context=_ctx(), policy=policy)
    await gate.check_enumerate(_SUBJ, tiers=("task", "long_term"))
    assert policy.calls == []


async def test_enumerate_default_tiers_are_durable():
    # Default tiers=("task","long_term"); a context lacking long_term cap is
    # refused even without passing tiers explicitly.
    ctx = _ctx(memory_read_capabilities=frozenset({"memory_read.task"}))
    gate = _gate(context=ctx)
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_enumerate(_SUBJ)
    assert ei.value.reason == "memory_recall_capability_missing"
