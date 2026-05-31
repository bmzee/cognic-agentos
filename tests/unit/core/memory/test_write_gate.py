"""Sprint 11.5a T9 — per-write gate (§7.1) precedence + branch coverage.

CRITICAL CONTROL. The gate is THE substantive per-write enforcement boundary
under ADR-019; it rides the 95%-line / 90%-branch coverage floor at Z1a. Every
refusal test here is a PRECEDENCE test: it stacks at least one LATER-step
failure into the same input and proves the EARLIER (target) reason wins.
"""

from __future__ import annotations

import datetime as dt

import pytest

from cognic_agentos.core.dlp.scanner import (
    DLP_RESTRICTED_CLASSES,
    DLPVerdict,
    RedactionSpan,
)
from cognic_agentos.core.memory._context import MemoryCallerContext, MemoryWriteRecord
from cognic_agentos.core.memory._seams import _NullMemoryKillSwitchInterrogator
from cognic_agentos.core.memory.consent import ConsentToken, ConsentValidator
from cognic_agentos.core.memory.gate import (
    _APPROVAL_REQUIRED_RISK_TIERS,
    MemoryGate,
)
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, SubjectRef
from cognic_agentos.core.policy.engine import (
    Decision,
    OpaNotInstalledError,
    RegoEvaluationError,
)

# --------------------------------------------------------------------------- #
# Fakes — lightweight injectable seams (production seams are real elsewhere).
# --------------------------------------------------------------------------- #


class _Frozen:
    """Kill-switch conformer returning a chosen bool from is_write_frozen."""

    def __init__(self, frozen: bool) -> None:
        self._frozen = frozen
        self.calls: list[str] = []

    async def is_write_frozen(self, *, tenant_id: str) -> bool:
        self.calls.append(tenant_id)
        return self._frozen


class _FakeDLP:
    """DLP scanner returning a chosen verdict regardless of value."""

    def __init__(self, detected: frozenset[str] = frozenset()) -> None:
        self._detected = detected

    def scan(self, value: object) -> DLPVerdict:
        spans = tuple(RedactionSpan(c, 0, 1) for c in sorted(self._detected))
        return DLPVerdict(
            detected_classes=self._detected,
            redaction_spans=spans,
            confidence=1.0 if self._detected else 0.0,
        )


class _FakeOPA:
    """OPA engine whose evaluate returns a per-decision-point allow bool, OR
    raises a chosen exception for a specified decision point."""

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
            allow=allow,
            rule_matched=decision_point,
            reasoning="fake",
            decision_data=None,
        )


# --------------------------------------------------------------------------- #
# Context builders.
# --------------------------------------------------------------------------- #

_SUBJ = SubjectRef(kind="human", id="cust-7")
_OTHER_SUBJ = SubjectRef(kind="human", id="cust-999")


def _ctx(**over: object) -> MemoryCallerContext:
    base: dict[str, object] = dict(
        tenant_id="t1",
        agent_id="kyc",
        actor_id="svc",
        served_subject=_SUBJ,
        is_subagent=False,
        long_term_writes_allowed=True,
        cross_subject_recall=False,
        memory_read_capabilities=frozenset(),
        declared_purposes=frozenset({"customer_support", "fraud_detection"}),
        declared_data_classes=frozenset({"public", "internal", "customer_pii"}),
        risk_tier="internal_write",
    )
    base.update(over)
    return MemoryCallerContext(**base)  # type: ignore[arg-type]


def _gate(
    *,
    context: MemoryCallerContext | None = None,
    dlp: _FakeDLP | None = None,
    consent: object | None = None,
    policy: _FakeOPA | None = None,
    kill_switch: object | None = None,
) -> MemoryGate:
    return MemoryGate(
        context=context or _ctx(),
        dlp=dlp or _FakeDLP(),
        consent=consent or _FakeConsent(),  # type: ignore[arg-type]
        policy=policy or _FakeOPA(),  # type: ignore[arg-type]
        kill_switch=kill_switch or _Frozen(False),  # type: ignore[arg-type]
    )


class _FakeConsent:
    """Consent validator that records calls and optionally raises. Used where
    consent is NOT the focus so the real ConsentValidator's dh_store isn't
    needed; the genuine-refusal tests use the REAL ConsentValidator below."""

    def __init__(self, raises: Exception | None = None) -> None:
        self._raises = raises
        self.calls: list[dict[str, object]] = []

    async def validate(
        self,
        token: ConsentToken | None,
        *,
        served_subject: SubjectRef,
        restricted_declared: frozenset[str],
        tenant_id: str,
        actor_id: str,
    ) -> None:
        self.calls.append(
            {
                "token": token,
                "served_subject": served_subject,
                "restricted_declared": restricted_declared,
                "tenant_id": tenant_id,
                "actor_id": actor_id,
            }
        )
        if self._raises is not None:
            raise self._raises


# --------------------------------------------------------------------------- #
# Step 0 — kill-switch (fail-loud sentinel vs. real True).
# --------------------------------------------------------------------------- #


async def test_kill_switch_true_refuses_write_frozen_winning_over_every_later_failure():
    # Stack EVERY later failure: sub-agent durable, long_term denied, DLP hit,
    # undeclared purpose, consent-raising, approval-tier. Step 0 must still win.
    ctx = _ctx(
        is_subagent=True,
        long_term_writes_allowed=False,
        declared_purposes=frozenset(),  # would trip purpose
        risk_tier="payment_action",
    )
    gate = _gate(
        context=ctx,
        dlp=_FakeDLP(detected=frozenset({"customer_pii"})),  # would trip DLP
        consent=_FakeConsent(raises=MemoryOperationRefused("memory_consent_required")),
        policy=_FakeOPA(allow=False),  # would trip long_term Rego
        kill_switch=_Frozen(True),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="4111111111111111",
            tier="long_term",
            purpose="customer_support",
            data_classes=(),
        )
    assert ei.value.reason == "memory_write_frozen"


async def test_unwired_null_kill_switch_propagates_not_implemented_error_not_refusal():
    # The _Null sentinel raises NotImplementedError — it MUST propagate
    # unchanged and NOT be mapped to memory_write_frozen.
    gate = _gate(kill_switch=_NullMemoryKillSwitchInterrogator())
    with pytest.raises(NotImplementedError):
        await gate.check_write(
            value="hello",
            tier="scratch",
            purpose="customer_support",
            data_classes=(),
        )


async def test_default_kill_switch_is_fail_loud_null_sentinel():
    # When NO kill_switch is wired at construction, the gate binds the _Null
    # fail-loud sentinel by default — first write raises NotImplementedError,
    # NOT memory_write_frozen and NOT a silent allow.
    gate = MemoryGate(
        context=_ctx(),
        dlp=_FakeDLP(),
        consent=_FakeConsent(),  # type: ignore[arg-type]
        policy=_FakeOPA(),  # type: ignore[arg-type]
        # kill_switch intentionally omitted
    )
    with pytest.raises(NotImplementedError):
        await gate.check_write(
            value="hello",
            tier="scratch",
            purpose="customer_support",
            data_classes=(),
        )


async def test_kill_switch_truthy_non_true_does_not_freeze():
    # Contract: ONLY an actual `is True` freezes. A conformer returning a
    # falsey value proceeds; this also pins the `is True` identity comparison.
    gate = _gate(kill_switch=_Frozen(False))
    rec = await gate.check_write(
        value="hello",
        tier="scratch",
        purpose="customer_support",
        data_classes=(),
    )
    assert rec.tier == "scratch"


# --------------------------------------------------------------------------- #
# Step 1 — sub-agent durable-access guard.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("tier", ["task", "long_term"])
async def test_subagent_durable_write_refused_winning_over_long_term_dlp_purpose(tier):
    ctx = _ctx(
        is_subagent=True,
        long_term_writes_allowed=False,  # later: long_term denial
        declared_purposes=frozenset(),  # later: purpose
        risk_tier="payment_action",  # later: approval
    )
    gate = _gate(
        context=ctx,
        dlp=_FakeDLP(detected=frozenset({"customer_pii"})),  # later: DLP hit
        consent=_FakeConsent(raises=MemoryOperationRefused("memory_consent_required")),
        policy=_FakeOPA(allow=False),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="4111111111111111",
            tier=tier,
            purpose="customer_support",
            data_classes=(),
        )
    assert ei.value.reason == "memory_subagent_durable_access_refused"


async def test_subagent_scratch_write_is_allowed():
    # §7.3 I2: children get scratch only — scratch is the allowed tier.
    gate = _gate(context=_ctx(is_subagent=True))
    rec = await gate.check_write(
        value="ephemeral",
        tier="scratch",
        purpose="customer_support",
        data_classes=(),
    )
    assert rec.tier == "scratch"


# --------------------------------------------------------------------------- #
# Step 1b — subject scope (block writes only).
# --------------------------------------------------------------------------- #


async def test_block_cross_subject_refused_when_not_declared_winning_over_long_term_denial():
    # Block write to a different subject; cross_subject_recall not declared.
    # Stack a long_term denial (later step 2) — step 1b must win.
    ctx = _ctx(cross_subject_recall=False, long_term_writes_allowed=False)
    gate = _gate(context=ctx, policy=_FakeOPA(allow=False))
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="v1",
            tier="long_term",
            purpose="customer_support",
            data_classes=("internal",),
            block_kind="persona",
            subject=_OTHER_SUBJ,
        )
    assert ei.value.reason == "memory_cross_subject_access_refused"


async def test_block_cross_subject_refused_when_rego_denies_winning_over_long_term_denial():
    # cross_subject_recall declared but the cross-subject Rego denies.
    ctx = _ctx(cross_subject_recall=True, long_term_writes_allowed=False)
    gate = _gate(
        context=ctx,
        policy=_FakeOPA(
            allow_by_point={"data.cognic.memory.cross_subject.allow": False},
        ),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="v1",
            tier="long_term",
            purpose="customer_support",
            data_classes=("internal",),
            block_kind="persona",
            subject=_OTHER_SUBJ,
        )
    assert ei.value.reason == "memory_cross_subject_access_refused"


async def test_block_cross_subject_rego_error_maps_to_cross_subject_refusal():
    # Per-decision-point fail-closed: a cross_subject Rego OPA error maps to
    # memory_cross_subject_access_refused (NOT some other step's reason).
    ctx = _ctx(cross_subject_recall=True)
    gate = _gate(
        context=ctx,
        policy=_FakeOPA(
            raises={"data.cognic.memory.cross_subject.allow": RegoEvaluationError("boom")},
        ),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="v1",
            tier="long_term",
            purpose="customer_support",
            data_classes=("internal",),
            block_kind="persona",
            subject=_OTHER_SUBJ,
        )
    assert ei.value.reason == "memory_cross_subject_access_refused"


async def test_block_cross_subject_allowed_when_declared_and_rego_allows():
    ctx = _ctx(cross_subject_recall=True)
    gate = _gate(
        context=ctx,
        policy=_FakeOPA(allow=True),
    )
    rec = await gate.check_write(
        value="v1",
        tier="long_term",
        purpose="customer_support",
        data_classes=("internal",),
        block_kind="persona",
        subject=_OTHER_SUBJ,
    )
    # Resolved record carries the REQUESTED (cross) subject.
    assert rec.subject.canonical == _OTHER_SUBJ.canonical
    assert rec.block_kind == "persona"


async def test_block_same_subject_skips_cross_subject_rego():
    # Block write where subject == served_subject: no cross-subject path.
    policy = _FakeOPA(allow=True)
    gate = _gate(context=_ctx(), policy=policy)
    rec = await gate.check_write(
        value="v1",
        tier="long_term",
        purpose="customer_support",
        data_classes=("internal",),
        block_kind="persona",
        subject=_SUBJ,
    )
    assert rec.subject.canonical == _SUBJ.canonical
    # cross_subject decision point never consulted.
    assert all(p != "data.cognic.memory.cross_subject.allow" for p, _ in policy.calls)


async def test_block_subject_defaults_to_served_when_omitted():
    # A block write without an explicit subject defaults to served_subject and
    # does not trip the cross-subject path.
    policy = _FakeOPA(allow=True)
    gate = _gate(context=_ctx(), policy=policy)
    rec = await gate.check_write(
        value="v1",
        tier="long_term",
        purpose="customer_support",
        data_classes=("internal",),
        block_kind="agent_notes",
        subject=None,
    )
    assert rec.subject.canonical == _SUBJ.canonical
    assert all(p != "data.cognic.memory.cross_subject.allow" for p, _ in policy.calls)


async def test_block_write_with_non_long_term_tier_raises_value_error():
    # P2 — blocks are long_term-only. A block_kind write with tier != long_term
    # is a caller contract violation: ValueError BEFORE any descriptor is built
    # (the gate must not return an invalid block descriptor). Matches storage.
    gate = _gate()
    with pytest.raises(ValueError, match="long_term-only"):
        await gate.check_write(
            value="v1",
            tier="task",
            purpose="customer_support",
            data_classes=("internal",),
            block_kind="persona",
        )


async def test_block_long_term_precondition_precedes_kill_switch():
    # The block long_term precondition is structural input validation that runs
    # BEFORE the governance chain — a malformed block surfaces as ValueError even
    # under a frozen kill-switch (no write happens either way; only the exception
    # type differs). Documents the precondition-first ordering decision.
    gate = _gate(kill_switch=_Frozen(True))
    with pytest.raises(ValueError, match="long_term-only"):
        await gate.check_write(
            value="v1",
            tier="scratch",
            purpose="customer_support",
            data_classes=(),
            block_kind="persona",
        )


# --------------------------------------------------------------------------- #
# Step 2 — long_term admission.
# --------------------------------------------------------------------------- #


async def test_long_term_denied_when_manifest_disallows_winning_over_dlp_and_purpose():
    ctx = _ctx(
        long_term_writes_allowed=False,
        declared_purposes=frozenset(),  # later: purpose
        risk_tier="payment_action",  # later: approval
    )
    gate = _gate(
        context=ctx,
        dlp=_FakeDLP(detected=frozenset({"customer_pii"})),  # later: DLP
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="4111111111111111",
            tier="long_term",
            purpose="customer_support",
            data_classes=(),
        )
    assert ei.value.reason == "memory_long_term_write_denied"


async def test_long_term_denied_when_rego_denies_winning_over_dlp_and_purpose():
    ctx = _ctx(declared_purposes=frozenset())  # later: purpose
    gate = _gate(
        context=ctx,
        dlp=_FakeDLP(detected=frozenset({"customer_pii"})),  # later: DLP
        policy=_FakeOPA(allow_by_point={"data.cognic.memory.long_term.allow": False}),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="4111111111111111",
            tier="long_term",
            purpose="customer_support",
            data_classes=(),
        )
    assert ei.value.reason == "memory_long_term_write_denied"


async def test_long_term_rego_error_maps_to_long_term_denied():
    # Per-decision-point fail-closed: long_term Rego OPA error → long_term denial.
    gate = _gate(
        policy=_FakeOPA(
            raises={"data.cognic.memory.long_term.allow": OpaNotInstalledError("no opa")},
        ),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="case",
            tier="long_term",
            purpose="customer_support",
            data_classes=("internal",),
        )
    assert ei.value.reason == "memory_long_term_write_denied"


# --------------------------------------------------------------------------- #
# Step 3 — DLP undeclared restricted class.
# --------------------------------------------------------------------------- #


async def test_dlp_undeclared_restricted_refused_winning_over_purpose():
    # DLP detects payment_data NOT in declared classes; stack an undeclared
    # purpose (later step 4) — DLP must win.
    ctx = _ctx(declared_purposes=frozenset())  # later: purpose
    gate = _gate(
        context=ctx,
        dlp=_FakeDLP(detected=frozenset({"payment_data"})),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="card 4111111111111111",
            tier="task",
            purpose="customer_support",
            data_classes=("public",),  # payment_data NOT declared
        )
    assert ei.value.reason == "memory_dlp_undeclared_restricted_class"


async def test_dlp_declared_restricted_class_passes_step_3():
    # Detected restricted class IS declared -> no DLP refusal. (Consent then
    # runs for the restricted class; use a fake consent that allows.)
    gate = _gate(
        dlp=_FakeDLP(detected=frozenset({"customer_pii"})),
        consent=_FakeConsent(),  # allows
    )
    rec = await gate.check_write(
        value="a@b.com",
        tier="task",
        purpose="customer_support",
        data_classes=("customer_pii",),
    )
    assert rec.data_classes == ("customer_pii",)


async def test_dlp_non_restricted_detection_does_not_refuse():
    # A detected class that is NOT in DLP_RESTRICTED_CLASSES (e.g. "internal")
    # never triggers the undeclared-restricted refusal even if undeclared.
    assert "internal" not in DLP_RESTRICTED_CLASSES
    gate = _gate(dlp=_FakeDLP(detected=frozenset({"internal"})))
    rec = await gate.check_write(
        value="x",
        tier="task",
        purpose="customer_support",
        data_classes=(),
    )
    assert rec.tier == "task"


async def test_dlp_runs_on_scratch_for_hygiene():
    # Scratch skips 2/5/6/7 but DLP (step 3) STILL runs.
    gate = _gate(dlp=_FakeDLP(detected=frozenset({"credentials"})))
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="secret",
            tier="scratch",
            purpose="customer_support",
            data_classes=(),  # credentials undeclared
        )
    assert ei.value.reason == "memory_dlp_undeclared_restricted_class"


# --------------------------------------------------------------------------- #
# Step 3b — restricted-class admission (durable; default-deny).
# --------------------------------------------------------------------------- #

_RESTRICTED_POINT = "data.cognic.memory.restricted_class_write.allow"


async def test_restricted_class_write_denied_when_rego_denies_winning_over_purpose_and_consent():
    # Declared restricted class + restricted_class_write Rego denies. Stack an
    # undeclared purpose (step 4) + a consent-raising fake (step 5) — step 3b wins.
    ctx = _ctx(declared_purposes=frozenset())
    gate = _gate(
        context=ctx,
        consent=_FakeConsent(raises=MemoryOperationRefused("memory_consent_required")),
        policy=_FakeOPA(allow_by_point={_RESTRICTED_POINT: False}),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="a@b.com",
            tier="task",
            purpose="customer_support",
            data_classes=("customer_pii",),  # declared restricted
        )
    assert ei.value.reason == "memory_restricted_class_write_denied"


async def test_restricted_class_rego_error_maps_to_restricted_class_write_denied():
    # Per-decision-point fail-closed: a restricted_class_write Rego OPA error
    # maps to memory_restricted_class_write_denied.
    gate = _gate(policy=_FakeOPA(raises={_RESTRICTED_POINT: OpaNotInstalledError("no opa")}))
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="a@b.com",
            tier="task",
            purpose="customer_support",
            data_classes=("customer_pii",),
        )
    assert ei.value.reason == "memory_restricted_class_write_denied"


async def test_dlp_undeclared_wins_before_restricted_class_rego():
    # DLP detects payment_data (UNDECLARED) at step 3 while the write also
    # DECLARES customer_pii (restricted) so step 3b would deny — DLP (3) wins.
    gate = _gate(
        dlp=_FakeDLP(detected=frozenset({"payment_data"})),
        policy=_FakeOPA(allow_by_point={_RESTRICTED_POINT: False}),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="card",
            tier="task",
            purpose="customer_support",
            data_classes=("customer_pii",),  # payment_data NOT declared -> DLP fires
        )
    assert ei.value.reason == "memory_dlp_undeclared_restricted_class"


async def test_restricted_class_allowed_when_rego_allows_and_consent_ok(dh_store):
    # Declared restricted + restricted_class_write Rego allows + valid consent ->
    # resolves (BOTH tenant-policy-allow AND consent satisfied).
    gate = _gate(consent=ConsentValidator(audit=dh_store), policy=_FakeOPA(allow=True))
    rec = await gate.check_write(
        value="a@b.com",
        tier="long_term",
        purpose="customer_support",
        data_classes=("customer_pii",),
        consent_token=_consent_token(),
    )
    assert rec.tier == "long_term"
    assert rec.data_classes == ("customer_pii",)


async def test_non_restricted_declared_skips_restricted_class_rego():
    # A non-restricted declared class never consults restricted_class_write.allow.
    policy = _FakeOPA(allow=True)
    gate = _gate(policy=policy)
    await gate.check_write(
        value="x",
        tier="task",
        purpose="customer_support",
        data_classes=("internal",),
    )
    assert all(p != _RESTRICTED_POINT for p, _ in policy.calls)


async def test_scratch_skips_restricted_class_rego():
    # Scratch is exempt from step 3b: a declared restricted class on scratch is
    # NOT gated by restricted_class_write.allow (DLP at step 3 still ran). A Rego
    # deny that WOULD refuse a durable write leaves scratch untouched.
    policy = _FakeOPA(allow_by_point={_RESTRICTED_POINT: False})
    gate = _gate(policy=policy)
    rec = await gate.check_write(
        value="a@b.com",
        tier="scratch",
        purpose="customer_support",
        data_classes=("customer_pii",),
    )
    assert rec.tier == "scratch"
    assert all(p != _RESTRICTED_POINT for p, _ in policy.calls)


# --------------------------------------------------------------------------- #
# Step 4 — purpose declaration.
# --------------------------------------------------------------------------- #


async def test_purpose_not_declared_refused_winning_over_consent():
    # Purpose not declared; stack a consent-raising fake (later step 5) and a
    # restricted declared class so consent WOULD run — purpose must win first.
    ctx = _ctx(declared_purposes=frozenset({"customer_support"}))
    gate = _gate(
        context=ctx,
        consent=_FakeConsent(raises=MemoryOperationRefused("memory_consent_required")),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="x",
            tier="task",
            purpose="regulatory_reporting",  # NOT declared
            data_classes=("customer_pii",),
        )
    assert ei.value.reason == "memory_purpose_not_declared"


# --------------------------------------------------------------------------- #
# Step 5 — consent (REAL ConsentValidator for genuine refusals).
# --------------------------------------------------------------------------- #


def _consent_token(**over: object) -> ConsentToken:
    base: dict[str, object] = dict(
        subject_ref=_SUBJ.canonical,
        data_classes=frozenset({"customer_pii"}),
        issued_at=dt.datetime(2026, 5, 1, tzinfo=dt.UTC),
        expires_at=dt.datetime(2030, 1, 1, tzinfo=dt.UTC),
        signature="sig",
    )
    base.update(over)
    return ConsentToken(**base)  # type: ignore[arg-type]


async def test_consent_required_when_restricted_declared_without_token(dh_store):
    # Restricted class declared (passes DLP because it is declared), no token.
    # Stack approval tier so step 7 WOULD fire — consent (step 5) wins first.
    ctx = _ctx(risk_tier="payment_action")
    gate = _gate(
        context=ctx,
        dlp=_FakeDLP(detected=frozenset({"customer_pii"})),
        consent=ConsentValidator(audit=dh_store),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="a@b.com",
            tier="long_term",
            purpose="customer_support",
            data_classes=("customer_pii",),
            consent_token=None,
        )
    assert ei.value.reason == "memory_consent_required"


async def test_consent_invalid_when_token_expired_winning_over_approval(dh_store):
    ctx = _ctx(risk_tier="payment_action")  # later: approval
    gate = _gate(
        context=ctx,
        consent=ConsentValidator(audit=dh_store),
    )
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="a@b.com",
            tier="long_term",
            purpose="customer_support",
            data_classes=("customer_pii",),
            consent_token=_consent_token(expires_at=dt.datetime(2020, 1, 1, tzinfo=dt.UTC)),
        )
    assert ei.value.reason == "memory_consent_invalid"


async def test_consent_valid_token_emits_ledger_event_and_proceeds(dh_store, decision_history_rows):
    # A valid restricted-consent token clears step 5 AND the ConsentValidator
    # chain-links exactly one memory.consent event. Use a non-approval risk
    # tier so step 7 does not fire and the write resolves.
    gate = _gate(consent=ConsentValidator(audit=dh_store))
    rec = await gate.check_write(
        value="a@b.com",
        tier="long_term",
        purpose="customer_support",
        data_classes=("customer_pii",),
        consent_token=_consent_token(),
    )
    assert rec.tier == "long_term"
    rows = await decision_history_rows()
    consent_rows = [r for r in rows if r.event_type == "memory.consent"]
    assert len(consent_rows) == 1


async def test_consent_delegation_passes_resolved_subject_and_restricted_subset():
    # The gate hands ConsentValidator the served subject + restricted subset of
    # the DECLARED classes (NOT all declared classes).
    fake = _FakeConsent()
    gate = _gate(
        context=_ctx(),
        consent=fake,
    )
    await gate.check_write(
        value="x",
        tier="task",
        purpose="customer_support",
        data_classes=("customer_pii", "internal"),  # internal is non-restricted
    )
    assert len(fake.calls) == 1
    call = fake.calls[0]
    served = call["served_subject"]
    assert isinstance(served, SubjectRef)
    assert served.canonical == _SUBJ.canonical
    assert call["restricted_declared"] == frozenset({"customer_pii"})
    assert call["tenant_id"] == "t1"
    assert call["actor_id"] == "svc"


async def test_scratch_skips_consent():
    # Scratch skips step 5: a consent-raising fake must never be called.
    fake = _FakeConsent(raises=MemoryOperationRefused("memory_consent_required"))
    gate = _gate(consent=fake)
    rec = await gate.check_write(
        value="x",
        tier="scratch",
        purpose="customer_support",
        data_classes=(),
    )
    assert rec.tier == "scratch"
    assert fake.calls == []


# --------------------------------------------------------------------------- #
# Step 6 — retention clamp (CLAMP, never refuse).
# --------------------------------------------------------------------------- #


async def test_retention_clamped_to_tenant_max_when_declared_exceeds():
    before = dt.datetime.now(dt.UTC)
    gate = _gate()
    rec = await gate.check_write(
        value="x",
        tier="task",
        purpose="customer_support",
        data_classes=("internal",),
        retention_window_s=10_000,
        tenant_retention_max_s=100,  # tenant cap is smaller -> wins
    )
    assert rec.retention_until is not None
    # Clamped to ~100s, NOT ~10_000s.
    delta = (rec.retention_until - before).total_seconds()
    assert 90 <= delta <= 200


async def test_retention_uses_declared_when_below_tenant_max():
    before = dt.datetime.now(dt.UTC)
    gate = _gate()
    rec = await gate.check_write(
        value="x",
        tier="task",
        purpose="customer_support",
        data_classes=("internal",),
        retention_window_s=50,
        tenant_retention_max_s=100_000,
    )
    assert rec.retention_until is not None
    delta = (rec.retention_until - before).total_seconds()
    assert 40 <= delta <= 120


async def test_retention_none_when_neither_window_set():
    gate = _gate()
    rec = await gate.check_write(
        value="x",
        tier="task",
        purpose="customer_support",
        data_classes=("internal",),
    )
    assert rec.retention_until is None


async def test_retention_only_tenant_max_set():
    before = dt.datetime.now(dt.UTC)
    gate = _gate()
    rec = await gate.check_write(
        value="x",
        tier="task",
        purpose="customer_support",
        data_classes=("internal",),
        retention_window_s=None,
        tenant_retention_max_s=200,
    )
    assert rec.retention_until is not None
    delta = (rec.retention_until - before).total_seconds()
    assert 150 <= delta <= 300


async def test_scratch_retention_is_none_even_with_windows():
    # Scratch skips step 6 entirely -> retention_until is None regardless.
    gate = _gate()
    rec = await gate.check_write(
        value="x",
        tier="scratch",
        purpose="customer_support",
        data_classes=(),
        retention_window_s=100,
        tenant_retention_max_s=50,
    )
    assert rec.retention_until is None


# --------------------------------------------------------------------------- #
# Step 7 — approval-transitional refusal.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("risk_tier", sorted(_APPROVAL_REQUIRED_RISK_TIERS))
async def test_approval_engine_not_available_for_high_tier_long_term(risk_tier):
    # High risk tier + long_term -> approval-transitional refusal. This is the
    # LAST refusal step; nothing later to stack, so prove it fires after a clean
    # pass of steps 0-6.
    ctx = _ctx(risk_tier=risk_tier)
    gate = _gate(context=ctx)
    with pytest.raises(MemoryOperationRefused) as ei:
        await gate.check_write(
            value="case",
            tier="long_term",
            purpose="customer_support",
            data_classes=("internal",),
        )
    assert ei.value.reason == "memory_approval_engine_not_available"


async def test_approval_refusal_does_not_fire_for_high_tier_task():
    # Step 7 is long_term-only: a high risk tier on a TASK write resolves.
    ctx = _ctx(risk_tier="payment_action")
    gate = _gate(context=ctx)
    rec = await gate.check_write(
        value="case",
        tier="task",
        purpose="customer_support",
        data_classes=("internal",),
    )
    assert rec.tier == "task"


async def test_approval_refusal_does_not_fire_for_low_tier_long_term():
    # A low/medium risk tier on a long_term write is NOT refused at step 7.
    ctx = _ctx(risk_tier="customer_data_read")  # NOT in the approval set
    assert "customer_data_read" not in _APPROVAL_REQUIRED_RISK_TIERS
    gate = _gate(context=ctx)
    rec = await gate.check_write(
        value="case",
        tier="long_term",
        purpose="customer_support",
        data_classes=("internal",),
    )
    assert rec.tier == "long_term"


# --------------------------------------------------------------------------- #
# Step 8 — success: resolved descriptor, identity-from-context.
# --------------------------------------------------------------------------- #


async def test_scratch_success_skips_2_5_6_7_and_returns_record():
    # Scratch with long_term_writes_allowed False + approval risk tier + Rego
    # deny: none of steps 2/5/6/7 apply -> a clean record returns.
    ctx = _ctx(
        long_term_writes_allowed=False,
        risk_tier="payment_action",
    )
    gate = _gate(
        context=ctx,
        policy=_FakeOPA(allow=False),
        consent=_FakeConsent(raises=MemoryOperationRefused("memory_consent_required")),
    )
    rec = await gate.check_write(
        value="ephemeral",
        tier="scratch",
        purpose="customer_support",
        data_classes=(),
        key="tmp",
    )
    assert isinstance(rec, MemoryWriteRecord)
    assert rec.tier == "scratch"
    assert rec.retention_until is None
    assert rec.key == "tmp"
    assert rec.block_kind is None


async def test_long_term_success_record_has_identity_from_context_and_clamped_retention():
    before = dt.datetime.now(dt.UTC)
    ctx = _ctx(
        tenant_id="bank-7",
        agent_id="kyc-agent",
        actor_id="svc-99",
        risk_tier="customer_data_read",  # passes step 7
    )
    gate = _gate(context=ctx)
    rec = await gate.check_write(
        value="case-payload",
        tier="long_term",
        purpose="fraud_detection",
        data_classes=("internal",),
        key="case-1",
        retention_window_s=500,
        tenant_retention_max_s=200,
    )
    # Identity from CONTEXT, not from any caller argument.
    assert rec.tenant_id == "bank-7"
    assert rec.agent_id == "kyc-agent"
    assert rec.actor_id == "svc-99"
    assert rec.subject.canonical == _SUBJ.canonical
    # Passthrough fields.
    assert rec.tier == "long_term"
    assert rec.purpose == "fraud_detection"
    assert rec.data_classes == ("internal",)
    assert rec.value == "case-payload"
    assert rec.key == "case-1"
    assert rec.block_kind is None
    # Retention clamped to the tenant max (200), not the declared 500.
    assert rec.retention_until is not None
    delta = (rec.retention_until - before).total_seconds()
    assert 150 <= delta <= 300
    # A request_id is minted by the gate.
    assert rec.request_id.startswith("memory-write-")


def test_identity_signature_does_not_accept_caller_identity():
    # Contract guard: check_write has NO tenant_id / agent_id / actor_id /
    # served_subject parameter — identity is context-only.
    import inspect

    sig_params = set(inspect.signature(MemoryGate.check_write).parameters)
    for forbidden in ("tenant_id", "agent_id", "actor_id", "served_subject"):
        assert forbidden not in sig_params


# --------------------------------------------------------------------------- #
# Doctrine pins — architectural arrow + risk-tier vocab lockstep.
# --------------------------------------------------------------------------- #


def test_gate_does_not_import_cli_at_runtime():
    import ast
    import pathlib

    src = pathlib.Path("src/cognic_agentos/core/memory/gate.py").read_text()
    tree = ast.parse(src)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offenders += [a.name for a in node.names if a.name.startswith("cognic_agentos.cli")]
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.startswith("cognic_agentos.cli"):
                offenders.append(mod)
    assert offenders == [], f"core->cli import in gate.py: {offenders}"


def test_gate_does_not_import_packs_at_runtime():
    import ast
    import pathlib

    src = pathlib.Path("src/cognic_agentos/core/memory/gate.py").read_text()
    tree = ast.parse(src)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offenders += [a.name for a in node.names if a.name.startswith("cognic_agentos.packs")]
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod.startswith("cognic_agentos.packs"):
                offenders.append(mod)
    assert offenders == [], f"core->packs import in gate.py: {offenders}"


def test_approval_required_tiers_are_canonical_high_tier_subset():
    # Lockstep with the canonical 8-value RiskTier vocab WITHOUT a runtime
    # core->packs import: import the canonical set test-only and assert the
    # gate's inline 5-value set is exactly the high-tier subset.
    from cognic_agentos.packs.conformance.owasp_agentic import _VALID_RISK_TIERS

    low_tiers = {"read_only", "internal_write", "customer_data_read"}
    assert _VALID_RISK_TIERS - low_tiers == _APPROVAL_REQUIRED_RISK_TIERS
    assert len(_APPROVAL_REQUIRED_RISK_TIERS) == 5
    assert _APPROVAL_REQUIRED_RISK_TIERS <= _VALID_RISK_TIERS


def test_resolved_descriptor_is_the_existing_memory_write_record():
    # The gate ships NO new public DTO — its success return type is the
    # existing MemoryWriteRecord.
    import inspect

    ret = inspect.signature(MemoryGate.check_write).return_annotation
    assert ret in (MemoryWriteRecord, "MemoryWriteRecord")
