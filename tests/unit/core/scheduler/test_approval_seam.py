"""Sprint 13.5c2 (ADR-014) — scheduler approval seam cutover tests."""

from __future__ import annotations

import dataclasses
import typing

import pytest


def test_admission_outcome_carries_five_approval_values() -> None:
    # Wire-protocol-public (spec §4): +5 on BOTH Literals; wire-equal subset
    # holds (pinned independently at test_closed_enums.py).
    from cognic_agentos.core.scheduler._types import (
        SchedulerAdmissionOutcome,
        SchedulerRefusalReason,
    )

    approval_values = {
        "refused_approval_pending",
        "refused_approval_denied",
        "refused_approval_expired",
        "refused_approval_binding_mismatch",
        "refused_approval_request_not_found",
    }
    assert approval_values <= set(typing.get_args(SchedulerAdmissionOutcome))
    assert approval_values <= set(typing.get_args(SchedulerRefusalReason))


def test_storage_closed_enum_guard_includes_approval_reasons() -> None:
    # storage._VALID_REFUSAL_REASONS is built via typing.get_args — the
    # runtime guard must accept the +5 with ZERO storage-code change.
    from cognic_agentos.core.scheduler.storage import _VALID_REFUSAL_REASONS

    assert "refused_approval_pending" in _VALID_REFUSAL_REASONS
    assert len(_VALID_REFUSAL_REASONS) == 10


def test_admission_decision_approval_request_id_defaults_none() -> None:
    from cognic_agentos.core.scheduler._types import AdmissionDecision

    d = AdmissionDecision(outcome="accepted_immediate", task_id=None)
    assert d.approval_request_id is None  # additive — old constructors green
    p = AdmissionDecision(
        outcome="refused_approval_pending", task_id=None, approval_request_id="abc"
    )
    assert p.approval_request_id == "abc"


def test_submit_input_carries_three_new_defaulted_fields() -> None:
    # Spec §2: approval_request_id (carrier) / approval_verified
    # (ENGINE-OWNED) / data_classes — all defaulted so every existing
    # constructor stays green.
    from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor

    base = SubmitInput(
        tenant_id="t-1",
        pack_id="pack-x",
        actor=TaskActor(subject="svc-a", tenant_id="t-1", actor_type="service"),
        class_="interactive",
        pack_kind="tool",
        pack_risk_tier="internal_write",
        requested_estimated_tokens=500,
    )
    assert base.approval_request_id is None
    assert base.approval_verified is False
    assert base.data_classes == ()
    rich = dataclasses.replace(
        base,
        approval_request_id="11111111-1111-1111-1111-111111111111",
        approval_verified=True,
        data_classes=("payment_data",),
    )
    assert rich.approval_verified is True


def test_submit_input_invalid_field_vocabulary_two_values() -> None:
    # Spec §4: 1 → 2 (+ approval_request_id); Literal + frozenset lockstep
    # is pinned by test_engine.py::test_t10_invalid_field_literal_in_lockstep_with_constant.
    from cognic_agentos.core.scheduler.engine import (
        _VALID_SUBMIT_INPUT_INVALID_FIELDS,
        SchedulerSubmitInputInvalidField,
    )

    assert set(typing.get_args(SchedulerSubmitInputInvalidField)) == {
        "parent_task_id",
        "approval_request_id",
    }
    assert (
        frozenset({"parent_task_id", "approval_request_id"}) == _VALID_SUBMIT_INPUT_INVALID_FIELDS
    )


# ---------------------------------------------------------------------------
# T2 — binding-digest helpers (spec §3.3, actor-bound F4)
# ---------------------------------------------------------------------------


def _seam_submit_input(**overrides: object) -> object:
    from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor

    base: dict[str, object] = {
        "tenant_id": "t-1",
        "pack_id": "pack-x",
        "actor": TaskActor(subject="agent-1", tenant_id="t-1", actor_type="service"),
        "class_": "interactive",
        "pack_kind": "tool",
        "pack_risk_tier": "payment_action",
        "requested_estimated_tokens": 500,
        "data_classes": ("payment_data",),
    }
    base.update(overrides)
    return SubmitInput(**base)  # type: ignore[arg-type]


def test_canonical_scheduler_identity_shape_and_collision_proofing() -> None:
    from cognic_agentos.core.scheduler.engine import _canonical_scheduler_identity

    ident = _canonical_scheduler_identity(pack_id="pack-x", pack_kind="tool")
    assert ident.startswith("scheduler:")
    assert len(ident) == 10 + 64  # "scheduler:" + hexdigest — fits String(256)
    assert ident == _canonical_scheduler_identity(pack_id="pack-x", pack_kind="tool")
    # Collision-proofing (the F4 doctrine): separator content cannot alias.
    a = _canonical_scheduler_identity(pack_id="a:b", pack_kind="c")
    b = _canonical_scheduler_identity(pack_id="a", pack_kind="b:c")
    assert a != b


def test_args_digest_disposition_map_covers_every_submit_input_field() -> None:
    # Spec §3.3 drift pin (c1 doctrine extended): every SubmitInput field is
    # EXPLICITLY dispositioned; a future field FAILS here until its binding
    # decision is made.
    from cognic_agentos.core.scheduler._types import SubmitInput

    digested = {"class_", "pack_risk_tier", "requested_estimated_tokens", "parent_task_id"}
    digested_via_actor = {"actor"}  # as actor.subject + actor.actor_type
    identity = {"pack_id", "pack_kind"}
    envelope_first_class = {"tenant_id", "data_classes"}
    carrier_or_attestation = {"approval_request_id", "approval_verified"}
    assert {f.name for f in dataclasses.fields(SubmitInput)} == (
        digested | digested_via_actor | identity | envelope_first_class | carrier_or_attestation
    )


def test_args_digest_binds_actor_tokens_and_parent() -> None:
    # Spec §3.3 (USER-LOCKED actor binding): an actor swap, a token-request
    # change, or a parent change MUST change the digest; tenant/data_classes
    # changes MUST NOT (envelope-first-class).
    from cognic_agentos.core.scheduler._types import TaskActor
    from cognic_agentos.core.scheduler.engine import _submit_args_digest

    base = _submit_args_digest(_seam_submit_input())  # type: ignore[arg-type]
    assert base == _submit_args_digest(_seam_submit_input())  # type: ignore[arg-type]
    swapped_actor = _seam_submit_input(
        actor=TaskActor(subject="agent-2", tenant_id="t-1", actor_type="service")
    )
    human_actor = _seam_submit_input(
        actor=TaskActor(subject="agent-1", tenant_id="t-1", actor_type="human")
    )
    assert _submit_args_digest(swapped_actor) != base  # type: ignore[arg-type]
    assert _submit_args_digest(human_actor) != base  # type: ignore[arg-type]
    assert _submit_args_digest(_seam_submit_input(requested_estimated_tokens=501)) != base  # type: ignore[arg-type]
    assert (
        _submit_args_digest(
            _seam_submit_input(parent_task_id="11111111-1111-1111-1111-111111111111")  # type: ignore[arg-type]
        )
        != base
    )
    # Exclusion pins — every non-digested bucket of the disposition map is
    # proven BEHAVIOURALLY (not just by the field-set map): changing an
    # envelope-first-class or carrier/attestation field leaves the digest
    # unchanged, so the helper cannot silently start binding one.
    assert _submit_args_digest(_seam_submit_input(data_classes=())) == base  # type: ignore[arg-type]
    assert _submit_args_digest(_seam_submit_input(tenant_id="t-2")) == base  # type: ignore[arg-type]
    assert (
        _submit_args_digest(
            _seam_submit_input(approval_request_id="11111111-1111-1111-1111-111111111111")  # type: ignore[arg-type]
        )
        == base
    )
    assert _submit_args_digest(_seam_submit_input(approval_verified=True)) == base  # type: ignore[arg-type]


def test_submit_redacted_context_shape_and_cap() -> None:
    from cognic_agentos.core.approval._types import APPROVAL_REDACTED_CONTEXT_MAX_LEN
    from cognic_agentos.core.scheduler.engine import _submit_redacted_context

    text = _submit_redacted_context(_seam_submit_input())  # type: ignore[arg-type]
    assert text.startswith("scheduler_submit pack_id=pack-x ")
    assert "class=interactive" in text and "risk_tier=payment_action" in text
    long = _submit_redacted_context(_seam_submit_input(pack_id="p" * 5000))  # type: ignore[arg-type]
    assert len(long) == APPROVAL_REDACTED_CONTEXT_MAX_LEN


# ---------------------------------------------------------------------------
# T4+ wired-engine fixtures (one alembic-migrated DB serves BOTH stores —
# scheduler_tasks lands in migration 0005; approval fixtures mirror
# tests/unit/sandbox/test_approval_seam.py)
# ---------------------------------------------------------------------------


class _MutableClock:
    """Advanceable approval-engine clock (the expired-re-submission test
    moves time past the flow TTL; everything else uses the fixed default)."""

    def __init__(self) -> None:
        from datetime import UTC, datetime

        self.now = datetime(2026, 6, 12, 12, 0, tzinfo=UTC)

    def __call__(self) -> object:
        return self.now


class _StubApprovalPolicy:
    """Fixed-flow classifier (OPA-free; mirrors the c1 seam stub)."""

    def __init__(self, flow: str = "require_single_approval") -> None:
        self._flow = flow

    async def classify(self, *, risk_tier: str) -> str:
        return self._flow


async def _mk_migrated_db(tmp_path: object) -> object:
    import asyncio as _asyncio

    from alembic import command
    from sqlalchemy.ext.asyncio import create_async_engine

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path}/scheduler-seam.db"
    cfg = make_alembic_config(url)
    await _asyncio.to_thread(command.upgrade, cfg, "head")
    return create_async_engine(url)


def _mk_approval_engine(db: object, *, flow: str, clock: object = None) -> object:
    from datetime import UTC, datetime

    from cognic_agentos.core.approval.engine import ApprovalEngine
    from cognic_agentos.core.approval.storage import ApprovalRequestStore
    from cognic_agentos.core.config import build_settings_without_env_file
    from cognic_agentos.core.decision_history import DecisionHistoryStore

    return ApprovalEngine(
        policy=_StubApprovalPolicy(flow),
        store=ApprovalRequestStore(DecisionHistoryStore(db)),  # type: ignore[arg-type]
        settings=build_settings_without_env_file(),
        clock=clock or (lambda: datetime(2026, 6, 12, 12, 0, tzinfo=UTC)),  # type: ignore[arg-type]
    )


class _CapturingPolicy:
    """Policy-evaluator stub capturing the SubmitInput the engine hands it —
    the engine-level attestation pin (the Rego-level pin lives at T3)."""

    def __init__(self, allow: bool = True) -> None:
        self.allow = allow
        self.seen: list[object] = []

    async def __call__(self, submit_input: object) -> object:
        from cognic_agentos.core.scheduler.policy import PolicyDecision

        self.seen.append(submit_input)
        return PolicyDecision(allow=self.allow, policy_reason=None if self.allow else "x")


class _AllowAllQuota:
    async def would_admit(
        self, *, task_id: object, tenant_id: str, pack_id: str, estimated_tokens: int
    ) -> bool:
        return True

    async def release_reservation(self, task_id: object) -> None:
        return None


class _InactiveKillSwitch:
    async def is_active(self, *, tenant_id: str, pack_id: str) -> bool:
        return False


class _ActiveKillSwitch:
    async def is_active(self, *, tenant_id: str, pack_id: str) -> bool:
        return True


class _InstalledPackState:
    async def is_installed(self, *, tenant_id: str, pack_id: str) -> bool:
        return True


def _mk_scheduler_engine(
    db: object,
    *,
    approval_engine: object = None,
    policy: object = None,
    kill_switch: object = None,
) -> object:
    """Engine over the migrated DB with permissive operational seams (the
    null sentinels are fail-loud per the production-grade rule, so tests
    supply installed/inactive/allow-all stubs; T5's ordering pin overrides
    ``kill_switch``)."""
    from cognic_agentos.core.scheduler.engine import SchedulerEngine
    from cognic_agentos.core.scheduler.queue import ConcurrencyCaps
    from cognic_agentos.core.scheduler.storage import SchedulerStorage

    return SchedulerEngine(
        storage=SchedulerStorage(db),  # type: ignore[arg-type]
        caps=ConcurrencyCaps(
            per_tenant_interactive=2, per_tenant_background=4, per_pack=4, per_actor=4
        ),
        class_settings={"interactive": (2, 0.200), "background": (4, 5.0)},
        policy_evaluator=policy,  # type: ignore[arg-type]
        quota_interrogator=_AllowAllQuota(),
        kill_switch_interrogator=kill_switch or _InactiveKillSwitch(),  # type: ignore[arg-type]
        pack_state_interrogator=_InstalledPackState(),
        approval_engine=approval_engine,  # type: ignore[arg-type]
    )


async def _load_admission_rows(db: object) -> list[tuple[str, dict[str, object]]]:
    """(event_type, payload) for every scheduler.admission_* chain row.

    NOTE: the DB column is ``event_type`` (decision_history.py:196) even
    though the ``DecisionRecord`` dataclass field is ``decision_type``.
    Raw ``text()`` bypasses the GovernanceJSON type decoder, so ``payload``
    comes back as a JSON string -> ``json.loads``."""
    import json

    from sqlalchemy import text

    async with db.connect() as conn:  # type: ignore[attr-defined]
        rows = await conn.execute(
            text(
                "SELECT event_type, payload FROM decision_history "
                "WHERE event_type LIKE 'scheduler.admission%' ORDER BY sequence"
            )
        )
        return [(r[0], json.loads(r[1])) for r in rows]


# ---------------------------------------------------------------------------
# T4 — wired first-admission path (spec §3.1/§3.2/§3.4/§3.5)
# ---------------------------------------------------------------------------


class TestWiredFirstAdmission:
    async def test_high_tier_first_submit_refuses_pending_with_correlator(
        self, tmp_path: object
    ) -> None:
        import uuid as _uuid

        db = await _mk_migrated_db(tmp_path)
        engine = _mk_scheduler_engine(
            db, approval_engine=_mk_approval_engine(db, flow="require_4_eyes")
        )
        decision = await engine.submit(submit_input=_seam_submit_input(), request_id="req-1")  # type: ignore[attr-defined]
        assert decision.outcome == "refused_approval_pending"
        assert decision.task_id is None
        rid = _uuid.UUID(decision.approval_request_id)
        # Refused chain row carries BOTH conditional evidence keys (spec §6):
        rows = await _load_admission_rows(db)
        assert rows[-1][0] == "scheduler.admission_refused"
        payload = rows[-1][1]
        assert payload["reason"] == "refused_approval_pending"
        assert payload["approval_request_id"] == str(rid)
        assert payload["approval_flow"] == "require_4_eyes"
        # Envelope-sourcing pins (spec §3.3/§3.4) via the approval store:
        from cognic_agentos.core.approval.storage import ApprovalRequestStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore

        detail = await ApprovalRequestStore(DecisionHistoryStore(db)).load_detail(  # type: ignore[arg-type]
            request_id=rid, tenant_id="t-1"
        )
        assert detail is not None and detail.state == "pending"
        assert detail.tool_identity.startswith("scheduler:")
        assert detail.redacted_context.startswith("scheduler_submit pack_id=")
        assert detail.data_classes == ("payment_data",)

    async def test_auto_flow_proceeds_with_false_attestation_and_no_rows(
        self, tmp_path: object
    ) -> None:
        db = await _mk_migrated_db(tmp_path)
        policy = _CapturingPolicy(allow=True)
        engine = _mk_scheduler_engine(
            db, approval_engine=_mk_approval_engine(db, flow="auto_run"), policy=policy
        )
        decision = await engine.submit(submit_input=_seam_submit_input(), request_id="req-1")  # type: ignore[attr-defined]
        assert decision.outcome == "accepted_immediate"
        assert policy.seen[0].approval_verified is False  # type: ignore[attr-defined]
        from cognic_agentos.core.approval.storage import ApprovalRequestStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore

        assert await ApprovalRequestStore(DecisionHistoryStore(db)).list_pending("t-1") == []  # type: ignore[arg-type]

    async def test_tightened_safe_tier_requires_approval(self, tmp_path: object) -> None:
        db = await _mk_migrated_db(tmp_path)
        engine = _mk_scheduler_engine(
            db, approval_engine=_mk_approval_engine(db, flow="require_single_approval")
        )
        decision = await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(pack_risk_tier="internal_write", data_classes=()),
            request_id="req-1",
        )
        assert decision.outcome == "refused_approval_pending"

    async def test_regulator_tier_required_refs_carry_request_id(self, tmp_path: object) -> None:
        # Spec §3.5: required_refs["audit_record_ref"] = the submit request_id
        # (the b2 pattern; NO minted correlator).
        import uuid as _uuid

        db = await _mk_migrated_db(tmp_path)
        engine = _mk_scheduler_engine(
            db, approval_engine=_mk_approval_engine(db, flow="require_4_eyes")
        )
        decision = await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(pack_risk_tier="regulator_communication"),
            request_id="req-reg-7",
        )
        assert decision.outcome == "refused_approval_pending"
        from cognic_agentos.core.approval.storage import ApprovalRequestStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore

        detail = await ApprovalRequestStore(DecisionHistoryStore(db)).load_detail(  # type: ignore[arg-type]
            request_id=_uuid.UUID(decision.approval_request_id), tenant_id="t-1"
        )
        assert detail is not None
        assert detail.required_refs == {"audit_record_ref": "req-reg-7"}

    async def test_anti_forgery_caller_true_is_overwritten(self, tmp_path: object) -> None:
        # F1 LOCK: caller-supplied approval_verified=True is ALWAYS replaced.
        # Unwired engine + high tier + capturing policy -> policy sees False.
        db = await _mk_migrated_db(tmp_path)
        policy = _CapturingPolicy(allow=False)
        engine = _mk_scheduler_engine(db, approval_engine=None, policy=policy)
        decision = await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(approval_verified=True), request_id="req-1"
        )
        assert decision.outcome == "refused_policy_denied"
        assert policy.seen[0].approval_verified is False  # type: ignore[attr-defined]

    async def test_engine_absent_valid_dangling_id_is_inert(self, tmp_path: object) -> None:
        # c1-mirror pin: unwired + VALID approval_request_id -> parsed but
        # never consulted; safe tier admits normally.
        db = await _mk_migrated_db(tmp_path)
        engine = _mk_scheduler_engine(db, approval_engine=None, policy=_CapturingPolicy())
        decision = await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(
                pack_risk_tier="internal_write",
                data_classes=(),
                approval_request_id="11111111-1111-1111-1111-111111111111",
            ),
            request_id="req-1",
        )
        assert decision.outcome == "accepted_immediate"

    async def test_malformed_approval_request_id_typed_fail_loud_even_unwired(
        self, tmp_path: object
    ) -> None:
        # F3 LOCK: parse is UNCONDITIONAL (the parent_task_id mirror).
        from cognic_agentos.core.scheduler.engine import SchedulerSubmitInputInvalid

        db = await _mk_migrated_db(tmp_path)
        engine = _mk_scheduler_engine(db, approval_engine=None, policy=_CapturingPolicy())
        with pytest.raises(SchedulerSubmitInputInvalid) as exc:
            await engine.submit(  # type: ignore[attr-defined]
                submit_input=_seam_submit_input(approval_request_id="not-a-uuid"),
                request_id="req-1",
            )
        assert exc.value.field == "approval_request_id"


# ---------------------------------------------------------------------------
# T5 — re-submission verify path (spec §3.3/§3.6)
# ---------------------------------------------------------------------------


def _approver(subject: str = "rev@bank.example") -> object:
    from cognic_agentos.core.approval._types import ApprovalActor

    return ApprovalActor(
        subject=subject,
        tenant_id="t-1",
        actor_type="human",
        scopes=frozenset({"tool.approve.payment"}),
    )


class TestWiredReSubmission:
    async def _pending_request(self, engine: object) -> object:
        import uuid as _uuid

        decision = await engine.submit(submit_input=_seam_submit_input(), request_id="req-1")  # type: ignore[attr-defined]
        assert decision.outcome == "refused_approval_pending"
        return _uuid.UUID(decision.approval_request_id)

    async def test_granted_resubmit_admits_and_attests(self, tmp_path: object) -> None:
        db = await _mk_migrated_db(tmp_path)
        approval = _mk_approval_engine(db, flow="require_single_approval")
        policy = _CapturingPolicy(allow=True)
        engine = _mk_scheduler_engine(db, approval_engine=approval, policy=policy)
        rid = await self._pending_request(engine)
        await approval.grant(request_id=rid, tenant_id="t-1", approver=_approver())  # type: ignore[attr-defined]
        decision = await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(approval_request_id=str(rid)), request_id="req-2"
        )
        assert decision.outcome == "accepted_immediate"
        assert policy.seen[-1].approval_verified is True  # type: ignore[attr-defined]

    async def test_actor_swap_binding_mismatch(self, tmp_path: object) -> None:
        # The c2 refinement pin: a DIFFERENT same-tenant actor cannot ride a
        # granted approval (actor identity is IN the binding digest).
        from cognic_agentos.core.scheduler._types import TaskActor

        db = await _mk_migrated_db(tmp_path)
        approval = _mk_approval_engine(db, flow="require_single_approval")
        engine = _mk_scheduler_engine(db, approval_engine=approval, policy=_CapturingPolicy())
        rid = await self._pending_request(engine)
        await approval.grant(request_id=rid, tenant_id="t-1", approver=_approver())  # type: ignore[attr-defined]
        decision = await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(
                actor=TaskActor(subject="agent-2", tenant_id="t-1", actor_type="service"),
                approval_request_id=str(rid),
            ),
            request_id="req-2",
        )
        assert decision.outcome == "refused_approval_binding_mismatch"
        assert decision.approval_request_id is None  # pending-only carrier

    async def test_token_change_binding_mismatch(self, tmp_path: object) -> None:
        db = await _mk_migrated_db(tmp_path)
        approval = _mk_approval_engine(db, flow="require_single_approval")
        engine = _mk_scheduler_engine(db, approval_engine=approval, policy=_CapturingPolicy())
        rid = await self._pending_request(engine)
        await approval.grant(request_id=rid, tenant_id="t-1", approver=_approver())  # type: ignore[attr-defined]
        decision = await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(
                requested_estimated_tokens=501, approval_request_id=str(rid)
            ),
            request_id="req-2",
        )
        assert decision.outcome == "refused_approval_binding_mismatch"

    async def test_parent_narrowed_resubmit_still_verifies(self, tmp_path: object) -> None:
        # Spec §3.3 ORIGINAL-tokens rule: parent-budget narrowing between
        # grant and re-submit must NOT spuriously mismatch — the digest reads
        # the ORIGINAL SubmitInput, never the narrowed effective copy.
        import uuid as _uuid

        class _ShrinkingBudget:
            def __init__(self) -> None:
                self.budgets = [400, 100]  # narrower on the re-submit

            async def remaining_budget_for(self, parent_task_id: object) -> int:
                return self.budgets.pop(0)

        from cognic_agentos.core.scheduler.engine import SchedulerEngine
        from cognic_agentos.core.scheduler.queue import ConcurrencyCaps
        from cognic_agentos.core.scheduler.storage import SchedulerStorage

        db = await _mk_migrated_db(tmp_path)
        approval = _mk_approval_engine(db, flow="require_single_approval")
        policy = _CapturingPolicy(allow=True)
        engine = SchedulerEngine(
            storage=SchedulerStorage(db),  # type: ignore[arg-type]
            caps=ConcurrencyCaps(
                per_tenant_interactive=2, per_tenant_background=4, per_pack=4, per_actor=4
            ),
            class_settings={"interactive": (2, 0.200), "background": (4, 5.0)},
            policy_evaluator=policy,  # type: ignore[arg-type]
            quota_interrogator=_AllowAllQuota(),
            kill_switch_interrogator=_InactiveKillSwitch(),
            pack_state_interrogator=_InstalledPackState(),
            parent_budget_resolver=_ShrinkingBudget(),
            approval_engine=approval,  # type: ignore[arg-type]
        )
        parent = str(_uuid.uuid4())
        first = await engine.submit(
            submit_input=_seam_submit_input(parent_task_id=parent),  # type: ignore[arg-type]
            request_id="req-1",
        )
        assert first.outcome == "refused_approval_pending"
        rid = _uuid.UUID(first.approval_request_id)
        await approval.grant(request_id=rid, tenant_id="t-1", approver=_approver())  # type: ignore[attr-defined]
        decision = await engine.submit(
            submit_input=_seam_submit_input(  # type: ignore[arg-type]
                parent_task_id=parent, approval_request_id=str(rid)
            ),
            request_id="req-2",
        )
        assert decision.outcome == "accepted_immediate"

    async def test_still_pending_denied_expired_and_not_found(self, tmp_path: object) -> None:
        import uuid as _uuid
        from datetime import timedelta

        db = await _mk_migrated_db(tmp_path)
        clock = _MutableClock()
        approval = _mk_approval_engine(db, flow="require_single_approval", clock=clock)
        engine = _mk_scheduler_engine(db, approval_engine=approval, policy=_CapturingPolicy())
        # still pending:
        rid = await self._pending_request(engine)
        d = await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(approval_request_id=str(rid)), request_id="r2"
        )
        assert d.outcome == "refused_approval_pending"
        assert d.approval_request_id == str(rid)  # pending keeps the carrier
        # denied:
        await approval.deny(  # type: ignore[attr-defined]
            request_id=rid, tenant_id="t-1", approver=_approver(), reason="not appropriate"
        )
        d = await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(approval_request_id=str(rid)), request_id="r3"
        )
        assert d.outcome == "refused_approval_denied"
        # expired (fresh request; clock past the 300s single TTL):
        rid2 = await self._pending_request(engine)
        clock.now += timedelta(hours=1)
        d = await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(approval_request_id=str(rid2)), request_id="r4"
        )
        assert d.outcome == "refused_approval_expired"
        # unknown == not found (cross-tenant is the same shape BY
        # CONSTRUCTION — the engine load is tenant-scoped):
        d = await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(approval_request_id=str(_uuid.uuid4())),
            request_id="r5",
        )
        assert d.outcome == "refused_approval_request_not_found"

    async def test_non_mismatch_transition_refusal_propagates_raw(self, tmp_path: object) -> None:
        # The verify re-raise arm (spec §3.6): any non-binding-mismatch
        # ApprovalTransitionRefused propagates RAW (fail-loud) — no silent
        # mapping for reasons the verify path should never produce, and no
        # admission_refused evidence row for a propagated exception.
        from cognic_agentos.core.approval._types import ApprovalTransitionRefused

        class _RaisingVerifyEngine:
            async def verify_grant_for_action(self, **kwargs: object) -> object:
                raise ApprovalTransitionRefused("approval_already_finalized")

        db = await _mk_migrated_db(tmp_path)
        engine = _mk_scheduler_engine(
            db, approval_engine=_RaisingVerifyEngine(), policy=_CapturingPolicy()
        )
        with pytest.raises(ApprovalTransitionRefused) as exc:
            await engine.submit(  # type: ignore[attr-defined]
                submit_input=_seam_submit_input(
                    approval_request_id="11111111-1111-1111-1111-111111111111"
                ),
                request_id="req-1",
            )
        assert exc.value.reason == "approval_already_finalized"
        assert await _load_admission_rows(db) == []

    async def test_kill_switch_beats_approval_zero_approval_rows(self, tmp_path: object) -> None:
        # Ordering pin (spec §3.1): a killed pack never reaches create_request.
        from cognic_agentos.core.approval.storage import ApprovalRequestStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore

        db = await _mk_migrated_db(tmp_path)
        engine = _mk_scheduler_engine(
            db,
            approval_engine=_mk_approval_engine(db, flow="require_single_approval"),
            kill_switch=_ActiveKillSwitch(),
        )
        decision = await engine.submit(submit_input=_seam_submit_input(), request_id="req-1")  # type: ignore[attr-defined]
        assert decision.outcome == "refused_kill_switch_active"
        assert await ApprovalRequestStore(DecisionHistoryStore(db)).list_pending("t-1") == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# T6 — accepted-row evidence + byte-identical pins (spec §6)
# ---------------------------------------------------------------------------


class TestAcceptedRowEvidence:
    async def test_granted_resubmit_accepted_row_carries_join_keys(self, tmp_path: object) -> None:
        # Spec §6 (user-locked P1): the accepted row needs the correlator or
        # the examiner join accepted -> approval.* is impossible for
        # non-regulator tiers (audit_record_ref exists ONLY for
        # regulator_communication).
        import uuid as _uuid

        db = await _mk_migrated_db(tmp_path)
        approval = _mk_approval_engine(db, flow="require_single_approval")
        engine = _mk_scheduler_engine(db, approval_engine=approval, policy=_CapturingPolicy())
        first = await engine.submit(submit_input=_seam_submit_input(), request_id="req-1")  # type: ignore[attr-defined]
        rid = _uuid.UUID(first.approval_request_id)
        await approval.grant(request_id=rid, tenant_id="t-1", approver=_approver())  # type: ignore[attr-defined]
        await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(approval_request_id=str(rid)), request_id="req-2"
        )
        rows = await _load_admission_rows(db)
        accepted = [p for t, p in rows if t == "scheduler.admission_accepted"]
        assert accepted[-1]["approval_verified"] is True
        assert accepted[-1]["approval_request_id"] == str(rid)

    async def test_non_approval_accepted_row_has_false_and_no_correlator(
        self, tmp_path: object
    ) -> None:
        db = await _mk_migrated_db(tmp_path)
        engine = _mk_scheduler_engine(
            db,
            approval_engine=_mk_approval_engine(db, flow="auto_run"),
            policy=_CapturingPolicy(),
        )
        await engine.submit(submit_input=_seam_submit_input(), request_id="req-1")  # type: ignore[attr-defined]
        rows = await _load_admission_rows(db)
        assert rows[-1][0] == "scheduler.admission_accepted"
        payload = rows[-1][1]
        assert payload["approval_verified"] is False
        assert "approval_request_id" not in payload

    async def test_non_approval_refused_row_keyset_byte_identical(self, tmp_path: object) -> None:
        # Spec §6: the 5 pre-c2 refusal reasons' payload shape is UNCHANGED
        # (conditional keys; additive-only schema).
        db = await _mk_migrated_db(tmp_path)
        engine = _mk_scheduler_engine(
            db,
            approval_engine=_mk_approval_engine(db, flow="require_single_approval"),
            kill_switch=_ActiveKillSwitch(),
        )
        await engine.submit(submit_input=_seam_submit_input(), request_id="req-1")  # type: ignore[attr-defined]
        rows = await _load_admission_rows(db)
        assert rows[-1][0] == "scheduler.admission_refused"
        # 13 storage-built keys + "actor_id" merged by DecisionHistoryStore
        # at append time (from DecisionRecord.actor_id) — the REAL on-disk
        # pre-c2 shape, found empirically at T6 watched-fail.
        assert set(rows[-1][1].keys()) == {
            "task_id",
            "tenant_id",
            "pack_id",
            "actor_subject",
            "actor_type",
            "class_",
            "pack_kind",
            "pack_risk_tier",
            "requested_estimated_tokens",
            "parent_task_id",
            "submitted_at",
            "reason",
            "policy_reason",
            "actor_id",
        }

    async def test_storage_guard_accepts_each_new_reason(self, tmp_path: object) -> None:
        import uuid as _uuid

        from cognic_agentos.core.scheduler.storage import SchedulerStorage

        db = await _mk_migrated_db(tmp_path)
        store = SchedulerStorage(db)  # type: ignore[arg-type]
        for reason in (
            "refused_approval_pending",
            "refused_approval_denied",
            "refused_approval_expired",
            "refused_approval_binding_mismatch",
            "refused_approval_request_not_found",
        ):
            await store.record_admission_refused(
                refused_task_id=_uuid.uuid4(),
                submit_input=_seam_submit_input(),  # type: ignore[arg-type]
                reason=reason,
                request_id=f"req-{reason}",
            )
