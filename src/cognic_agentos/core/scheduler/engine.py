"""Sprint 10.5a T5 — SchedulerEngine orchestrator (ADR-022).

Public seam: coordinates ``SchedulerStorage`` + ``BoundedQueue`` per
(tenant, class) + ``ConcurrencyCaps`` + injected ``QuotaInterrogator``
+ ``KillSwitchInterrogator`` + ``ParentBudgetResolver`` Protocols
(consumer-owned per [[feedback_consumer_owned_protocol_for_unlanded_dep]];
Sprint 11 + 13.5 supply real conformers later) + a policy_evaluator
callable seam (T8 wires the real ``SchedulerPolicy`` class).

Critical-controls module (core/ stop-rule per AGENTS.md).
Every edit is halt-before-commit per
[[feedback_strict_review_off_gate]].

Public method surface (per spec §4.2 + §4.9):
  * ``submit(submit_input, request_id)`` → ``AdmissionDecision``
  * ``mark_running(task_id, request_id)`` → ``None``
  * ``complete(task_id, request_id)`` → ``None``
  * ``fail(task_id, payload, request_id)`` → ``None``
  * ``cancel(task_id, actor, reason, request_id)`` → ``None``
  * ``preempt(task_id, request_id)`` → ``None``
  * ``reap_expired(*, queue_ttl_s_per_class, now=None, request_id="scheduler-reaper")``
    → ``int`` (count of expired tasks). Round-6 reviewer P1/P2 fix —
    sweeps ``_queued_attribution`` for tasks past their per-class TTL,
    transitions ``pending → expired``, releases quota, removes from
    queue. Operator reconciler loops typically invoke on a timer.

Wave-1 design choices:
  * In-memory concurrency counters per (tenant, class) + per-pack +
    per-actor. Single-AgentOS-instance only (per ADR-022 "What this
    is NOT" — multi-instance work-stealing is Wave-2).
  * No runtime ``isinstance(seam, Protocol)`` validation per
    round-4 P2 doctrine — ``runtime_checkable`` Protocols only check
    attribute presence (not signatures or awaitability); authority
    lives at the awaited call sites; tests pin conformer behavior
    end-to-end.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Literal

from cognic_agentos.core.scheduler._seams import (
    KillSwitchInterrogator,
    PackStateInterrogator,
    ParentBudgetResolver,
    QuotaInterrogator,
    _NullKillSwitchInterrogator,
    _NullPackStateInterrogator,
    _NullParentBudgetResolver,
    _NullQuotaInterrogator,
    compute_child_budget,
)
from cognic_agentos.core.scheduler._types import (
    AdmissionDecision,
    SchedulerPriorityClass,
    SchedulerRefusalReason,
    SchedulerTaskCancelledReason,
    SchedulerTaskState,
    SubmitInput,
    TaskFailedPayload,
)
from cognic_agentos.core.scheduler.policy import PolicyDecision as PolicyDecision
from cognic_agentos.core.scheduler.queue import (
    BoundedQueue,
    ConcurrencyCaps,
    QueueFull,
)
from cognic_agentos.core.scheduler.storage import SchedulerStorage

# Re-export contract — the historical T5-era import path
# ``from cognic_agentos.core.scheduler.engine import PolicyDecision``
# continues to work because the symbol is bound at module load via the
# import above. T8 re-homes the canonical definition to
# ``core/scheduler/policy.py`` (the producer module) per plan §1169;
# engine remains the consumer + the back-compat re-export site.
# NOTE: deliberately NO ``__all__`` declaration — this module exposes
# multiple public symbols (SchedulerEngine, SchedulerPromotionRefused,
# SchedulerPromotionRefusedReason, _VALID_PROMOTION_REFUSED_REASONS,
# PolicyDecision, PolicyEvaluator) that downstream consumers import by
# name; an ``__all__`` would risk silently breaking those import paths.


#: Policy evaluator callable shape. T8 SchedulerPolicy will conform.
#: Wave-1: engine accepts a None default = "allow everything"; tests
#: inject stubs.
PolicyEvaluator = Callable[[SubmitInput], Awaitable[PolicyDecision]]


@dataclass(frozen=True)
class _TaskAttribution:
    """Per-task counter-attribution snapshot. Round-5 reviewer P1 #2
    fix: terminal-state transitions must decrement the in-memory
    concurrency counters that were incremented at accepted_immediate;
    storing the attribution at submit time lets _transition_terminal
    find the right counter buckets without re-reading from storage.

    Round-6 reviewer P1 fix: ``enqueued_at`` added so ``reap_expired``
    can compute per-task wait time against a passed-in queue TTL
    without an extra storage round-trip."""

    tenant_id: str
    class_: SchedulerPriorityClass
    pack_id: str
    actor_subject: str
    enqueued_at: datetime


#: Round-7 reviewer P1 fix — closed-enum reason vocabulary for the
#: ``SchedulerPromotionRefused`` typed exception. Two values:
#:   * ``caps_saturated`` — the three concurrency caps (per-tenant/class,
#:     per-pack, per-actor) all checked but at least one is at limit.
#:     Caller should retry when a terminal-state event has freed a slot.
#:   * ``not_at_queue_head`` — the requested ``task_id`` is queued but
#:     not at the FIFO head; promotion of out-of-order tasks would
#:     violate the locked "FIFO within class" scheduler contract per
#:     spec §4.3. Caller should promote the head first.
SchedulerPromotionRefusedReason = Literal["caps_saturated", "not_at_queue_head"]


#: Closed-enum field-name vocabulary for ``SchedulerSubmitInputInvalid``.
#: Wave-1 has exactly 1 value (``parent_task_id``); future field-shape
#: validations grow this Literal additively. Drift detector at
#: ``test_t10_invalid_field_literal_in_lockstep_with_constant`` pins
#: the Literal arms against the frozenset constant below.
SchedulerSubmitInputInvalidField = Literal["parent_task_id"]

#: Build-time invariant: vocabulary frozenset for AST-comparable drift
#: detection (test imports both this set + the Literal + asserts
#: equality, mirroring the ``SchedulerPromotionRefusedReason`` pattern
#: at the top of this module).
_VALID_SUBMIT_INPUT_INVALID_FIELDS: Final[frozenset[str]] = frozenset({"parent_task_id"})


class SchedulerSubmitInputInvalid(Exception):
    """Raised by ``submit()`` when a SubmitInput field fails engine-
    boundary shape validation BEFORE any seam consultation.

    Round-1 P2 reviewer fix: ``SubmitInput.parent_task_id`` is typed
    as ``str | None`` for serialization convenience (HTTP / chain
    payload) but the engine must parse it via ``uuid.UUID(...)``
    before threading to :class:`~cognic_agentos.core.scheduler._seams.ParentBudgetResolver`
    (whose ``remaining_budget_for`` accepts ``uuid.UUID``). A
    malformed string would raise raw ``ValueError`` from the UUID
    constructor, bypassing the documented T10 fail-loud-via-sentinel
    contract. This typed exception catches the parse failure +
    surfaces it with a closed-enum ``field`` + free-form ``reason``
    for examiner correlation.

    Round-1 P3 reviewer fix: ``field`` is typed as the closed-enum
    :data:`SchedulerSubmitInputInvalidField` Literal (1-value Wave-1
    vocabulary: ``parent_task_id``) rather than free-form ``str``.
    Mirrors the :class:`SchedulerPromotionRefused` ``reason`` pattern.

    Wave-1 coverage: ``parent_task_id`` malformed-UUID only. Future
    field-shape validations grow the Literal additively + extend the
    vocabulary frozenset in lockstep.
    """

    def __init__(self, *, field: SchedulerSubmitInputInvalidField, reason: str) -> None:
        super().__init__(f"scheduler_submit_input_invalid: field={field} reason={reason}")
        self.field: SchedulerSubmitInputInvalidField = field
        self.reason = reason


class SchedulerPromotionRefused(Exception):
    """Raised by ``mark_running`` when a queued task cannot be promoted.

    Round-6 reviewer P1 fix added the typed exception (round-5
    ``mark_running`` silently violated the caps contract for promoted
    queued tasks). Round-7 reviewer P1 fix extended it to carry a
    closed-enum ``reason`` field distinguishing the two refusal modes:
    caps still saturated vs FIFO out-of-order. Carries ``task_id`` for
    examiner correlation."""

    def __init__(
        self,
        task_id: uuid.UUID,
        *,
        reason: SchedulerPromotionRefusedReason,
    ) -> None:
        super().__init__(f"scheduler_promotion_refused_{reason}: {task_id}")
        self.task_id = task_id
        self.reason = reason


#: Build-time invariant: vocabulary set frozen for AST-comparable drift
#: detection (test_round7 regression imports both this set + the Literal
#: + asserts equality).
_VALID_PROMOTION_REFUSED_REASONS: Final[frozenset[str]] = frozenset(
    {"caps_saturated", "not_at_queue_head"}
)


class SchedulerEngine:
    """ADR-022 runtime scheduler primitive. Orchestrates storage +
    queue + concurrency caps + 3 consumer-owned seams + policy
    callable. NOT thread-safe; single asyncio event loop per
    instance."""

    def __init__(
        self,
        *,
        storage: SchedulerStorage,
        caps: ConcurrencyCaps,
        class_settings: dict[SchedulerPriorityClass, tuple[int, float]],
        policy_evaluator: PolicyEvaluator | None = None,
        quota_interrogator: QuotaInterrogator | None = None,
        kill_switch_interrogator: KillSwitchInterrogator | None = None,
        parent_budget_resolver: ParentBudgetResolver | None = None,
        pack_state_interrogator: PackStateInterrogator | None = None,
    ) -> None:
        self._storage = storage
        self._caps = caps
        self._class_settings = class_settings
        self._policy = policy_evaluator
        self._quota: QuotaInterrogator = (
            quota_interrogator if quota_interrogator is not None else _NullQuotaInterrogator()
        )
        self._kill_switch: KillSwitchInterrogator = (
            kill_switch_interrogator
            if kill_switch_interrogator is not None
            else _NullKillSwitchInterrogator()
        )
        self._parent_budget: ParentBudgetResolver = (
            parent_budget_resolver
            if parent_budget_resolver is not None
            else _NullParentBudgetResolver()
        )
        self._pack_state: PackStateInterrogator = (
            pack_state_interrogator
            if pack_state_interrogator is not None
            else _NullPackStateInterrogator()
        )
        # In-memory per-(tenant, class) BoundedQueue; created on first
        # submission per tenant/class pair.
        self._queues: dict[tuple[str, SchedulerPriorityClass], BoundedQueue] = {}
        # In-memory concurrency counters (Wave-1; multi-instance =
        # Wave-2 distributed counter substrate per ADR-022).
        self._tenant_class_counts: dict[tuple[str, SchedulerPriorityClass], int] = {}
        self._pack_counts: dict[str, int] = {}
        self._actor_counts: dict[str, int] = {}
        # Round-5 reviewer P1 #2 + #3 fixes: per-task attribution maps
        # so terminal-state transitions can decrement the right
        # counters (running) OR remove the task from its queue
        # (queued). Tasks promoted from queued → running migrate from
        # _queued_attribution to _running_attribution at mark_running.
        self._running_attribution: dict[uuid.UUID, _TaskAttribution] = {}
        self._queued_attribution: dict[uuid.UUID, _TaskAttribution] = {}

    # --- public submit/transition surface --------------------------------

    async def submit(
        self,
        *,
        submit_input: SubmitInput,
        request_id: str,
    ) -> AdmissionDecision:
        """Spec §4.2/§4.3: mint task_id; consult kill-switch + policy +
        quota seams; reserve concurrency-cap slot OR enqueue OR refuse.

        Wave-1 ordering (matches spec §4.3 + round-4 P1
        reservation-leak-guard contract):

          1. Resolve parent budget if SubmitInput.parent_task_id present
             (via ParentBudgetResolver seam; fail-loud sentinel
             default).
          2. kill_switch.is_active(tenant, pack) → refused_kill_switch_active
          3. policy_evaluator(submit_input) → refused_policy_denied
          4. quota.would_admit(task_id, tenant, pack, effective_tokens)
             → if False, refused_quota_exhausted (NO reservation made).
             On True, reservation is held; subsequent failures MUST
             release via the round-4 try/except envelope.
          5. caps.has_headroom_for(...) → if True, accepted_immediate;
             storage.submit(); increment counts.
          6. Else queue has capacity → accepted_queued;
             storage.submit(); enqueue.
          7. Else refused_queue_full with retry_after_s.
        """
        task_id = uuid.uuid4()

        # T10 parent-budget narrowing per ADR-005 + plan §1255-1259.
        # When ``parent_task_id`` is set, consult ParentBudgetResolver
        # for the parent's remaining token budget + narrow the child's
        # requested estimate via the pure-functional helper. The
        # narrowed value is threaded to BOTH quota.would_admit AND the
        # storage row via a dataclasses.replace projection — closes
        # the round-6 P1 #2 audit/quota-mismatch finding (quota was
        # reserving the narrowed value while storage recorded the
        # original request; T10 makes both see the same value).
        #
        # Fail-loud contract: when parent_task_id is set AND the
        # default ``_NullParentBudgetResolver`` sentinel is wired (no
        # real conformer injected), the await on remaining_budget_for
        # propagates ``NotImplementedError`` per the production-grade-
        # rule sentinel contract. Replaces round-7's explicit-engine-
        # guard pattern — the failure mode is now seam-Protocol
        # propagation, not engine pre-check.
        effective_tokens = submit_input.requested_estimated_tokens
        if submit_input.parent_task_id is not None:
            # Round-1 P2 reviewer fix: parse the str → UUID via
            # explicit try/except so a malformed string surfaces as the
            # documented typed SchedulerSubmitInputInvalid, NOT a raw
            # ValueError. Without this guard, a caller bug (e.g.
            # passing "not-a-uuid") would bypass the T10 fail-loud-via-
            # sentinel contract because the parse would fail BEFORE the
            # resolver call.
            try:
                parent_uuid = uuid.UUID(submit_input.parent_task_id)
            except ValueError as exc:
                raise SchedulerSubmitInputInvalid(
                    field="parent_task_id",
                    reason=(f"not a valid UUID string: {submit_input.parent_task_id!r}"),
                ) from exc
            parent_remaining = await self._parent_budget.remaining_budget_for(parent_uuid)
            effective_tokens = compute_child_budget(
                parent_remaining_budget=parent_remaining,
                child_pack_quota=submit_input.requested_estimated_tokens,
            )
        # Project the narrowed value into a SubmitInput copy so
        # downstream consumers (quota, storage, attribution, audit)
        # see the same value. dataclasses.replace skipped when
        # narrowing is a no-op (== original) to keep the identity
        # check at the call site cheap.
        effective_submit_input = (
            submit_input
            if effective_tokens == submit_input.requested_estimated_tokens
            else dataclasses.replace(submit_input, requested_estimated_tokens=effective_tokens)
        )

        # Step 2: pack installed?
        if not await self._pack_state.is_installed(
            tenant_id=effective_submit_input.tenant_id,
            pack_id=effective_submit_input.pack_id,
        ):
            await self._emit_admission_refused(
                refused_task_id=task_id,
                submit_input=effective_submit_input,
                reason="refused_pack_not_installed",
                request_id=request_id,
            )
            return AdmissionDecision(
                outcome="refused_pack_not_installed",
                task_id=None,
            )

        # Step 3: kill switch
        if await self._kill_switch.is_active(
            tenant_id=effective_submit_input.tenant_id,
            pack_id=effective_submit_input.pack_id,
        ):
            await self._emit_admission_refused(
                refused_task_id=task_id,
                submit_input=effective_submit_input,
                reason="refused_kill_switch_active",
                request_id=request_id,
            )
            return AdmissionDecision(
                outcome="refused_kill_switch_active",
                task_id=None,
            )

        # Step 4: policy
        if self._policy is not None:
            policy_decision = await self._policy(effective_submit_input)
            if not policy_decision.allow:
                await self._emit_admission_refused(
                    refused_task_id=task_id,
                    submit_input=effective_submit_input,
                    reason="refused_policy_denied",
                    request_id=request_id,
                    policy_reason=policy_decision.policy_reason,
                )
                return AdmissionDecision(
                    outcome="refused_policy_denied",
                    task_id=None,
                    policy_reason=policy_decision.policy_reason,
                )

        # Step 5: quota reservation (TRUE = reserves; FALSE = no
        # reservation made). T10 — quota sees the narrowed effective
        # value, matching what storage will record per the round-6
        # P1 #2 audit/quota-mismatch reviewer finding closure.
        reserved = await self._quota.would_admit(
            task_id=task_id,
            tenant_id=effective_submit_input.tenant_id,
            pack_id=effective_submit_input.pack_id,
            estimated_tokens=effective_tokens,
        )
        if not reserved:
            await self._emit_admission_refused(
                refused_task_id=task_id,
                submit_input=effective_submit_input,
                reason="refused_quota_exhausted",
                request_id=request_id,
            )
            return AdmissionDecision(
                outcome="refused_quota_exhausted",
                task_id=None,
            )

        # Steps 6-8: wrap all subsequent admission work in a try block.
        # Round-4 P1 contract: except BaseException → release before
        # re-raise. Round-5 P1 #1 contract: refused_queue_full does NOT
        # raise but DOES need release, so the post-try outcome check
        # handles that explicitly.
        try:
            decision = await self._do_admission_work(
                task_id=task_id,
                submit_input=effective_submit_input,
                request_id=request_id,
            )
        except BaseException:
            await self._quota.release_reservation(task_id)
            raise

        # Round-5 P1 #1 fix: any refused outcome from
        # _do_admission_work happens AFTER successful quota reservation,
        # so we MUST release before returning the refusal to the caller.
        # Currently the only refused outcome from this path is
        # refused_queue_full (caps + queue both saturated); future
        # refused outcomes added here MUST follow the same pattern.
        # Hardcoded reason value (NOT decision.outcome) so the
        # SchedulerRefusalReason Literal type stays narrow — caller
        # additions of new refused outcomes need to extend the Literal
        # AND re-route here explicitly, not silently flow through.
        if decision.outcome == "refused_queue_full":
            await self._quota.release_reservation(task_id)
            # Emit the admission_refused audit row for the queue-full
            # path (the earlier 4 refusal paths returned before this
            # point + emitted their own row).
            await self._emit_admission_refused(
                refused_task_id=task_id,
                submit_input=effective_submit_input,
                reason="refused_queue_full",
                request_id=request_id,
            )
        return decision

    async def _emit_admission_refused(
        self,
        *,
        refused_task_id: uuid.UUID,
        submit_input: SubmitInput,
        reason: SchedulerRefusalReason,
        request_id: str,
        policy_reason: str | None = None,
    ) -> None:
        """Emit a scheduler.admission_refused chain row for the given
        refusal reason. Round-5 reviewer P1 #5 fix — closes the
        audit-pack gap where refusals previously returned only an
        AdmissionDecision to the caller without persisting any
        evidence."""
        await self._storage.record_admission_refused(
            refused_task_id=refused_task_id,
            submit_input=submit_input,
            reason=reason,
            request_id=request_id,
            policy_reason=policy_reason,
        )

    async def _do_admission_work(
        self,
        *,
        task_id: uuid.UUID,
        submit_input: SubmitInput,
        request_id: str,
    ) -> AdmissionDecision:
        """Caps headroom check → enqueue OR accepted_immediate OR
        refused_queue_full. Runs inside submit()'s reservation-leak
        guard envelope.

        Round-5 reviewer P1 #2/#3/#4 fixes: maintains _running_attribution
        on accepted_immediate (for terminal-state count decrement) and
        _queued_attribution on accepted_queued (for cancel-from-queue
        removal). The queued path rolls back the enqueue on storage
        failure so an orphaned queue entry can never block future
        admissions."""
        tenant_class_key = (submit_input.tenant_id, submit_input.class_)
        tenant_count = self._tenant_class_counts.get(tenant_class_key, 0)
        pack_count = self._pack_counts.get(submit_input.pack_id, 0)
        actor_count = self._actor_counts.get(submit_input.actor.subject, 0)
        attribution = _TaskAttribution(
            tenant_id=submit_input.tenant_id,
            class_=submit_input.class_,
            pack_id=submit_input.pack_id,
            actor_subject=submit_input.actor.subject,
            enqueued_at=datetime.now(UTC),
        )

        if self._caps.has_headroom_for(
            class_=submit_input.class_,
            tenant_count=tenant_count,
            pack_count=pack_count,
            actor_count=actor_count,
        ):
            # accepted_immediate: storage.submit FIRST (storage failure
            # rolls back via outer try/except releasing quota; nothing
            # counter-side to undo yet), THEN attribution + counter
            # increment on success.
            await self._storage.submit(
                task_id=task_id,
                submit_input=submit_input,
                request_id=request_id,
            )
            self._tenant_class_counts[tenant_class_key] = tenant_count + 1
            self._pack_counts[submit_input.pack_id] = pack_count + 1
            self._actor_counts[submit_input.actor.subject] = actor_count + 1
            self._running_attribution[task_id] = attribution
            return AdmissionDecision(outcome="accepted_immediate", task_id=str(task_id))

        # Caps saturated → try queue
        queue = self._get_or_create_queue(submit_input.tenant_id, submit_input.class_)
        try:
            queue.enqueue(task_id)
        except QueueFull:
            return AdmissionDecision(
                outcome="refused_queue_full",
                task_id=None,
                retry_after_s=queue.compute_retry_after_s(),
            )

        # Round-5 reviewer P1 #4 fix: roll back the enqueue if storage
        # fails. Without this, the queue holds a task_id with no
        # backing storage row, permanently consuming queue depth.
        try:
            await self._storage.submit(
                task_id=task_id,
                submit_input=submit_input,
                request_id=request_id,
            )
        except BaseException:
            queue.remove(task_id)
            raise
        self._queued_attribution[task_id] = attribution
        return AdmissionDecision(outcome="accepted_queued", task_id=str(task_id))

    async def mark_running(self, task_id: uuid.UUID, *, request_id: str) -> None:
        """Transition pending → running. Emits scheduler.task_started.
        Per spec §4.4 (post-amendment): running means workload has
        actually started.

        Round-7 reviewer P1 fix — queued lifecycle ordering:

        For a task in ``_queued_attribution``, the engine MUST:
          1. Verify ``task_id`` is the FIFO head of its (tenant, class)
             queue. Out-of-order promotion violates the locked "FIFO
             within class" contract per spec §4.3 — raises
             ``SchedulerPromotionRefused(reason="not_at_queue_head")``
             without mutating any state.
          2. Re-check concurrency caps using the queued task's
             attribution. If still saturated, raise
             ``SchedulerPromotionRefused(reason="caps_saturated")``
             without mutating any state. Task stays queued for retry.
          3. Issue the durable ``pending → running`` storage transition
             FIRST. If storage fails, no in-memory bookkeeping has
             been touched, so re-raise propagates cleanly with engine
             state matching the persisted DB state.
          4. ONLY ON SUCCESS, commit the bookkeeping: increment
             counters, migrate attribution
             ``_queued_attribution → _running_attribution``, and
             dequeue the task from the BoundedQueue.

        The round-6 implementation reversed steps 3-4 — bookkeeping
        first, then storage — which left the engine ahead of the DB on
        storage failure. Durable-first order makes the engine state
        rollback-by-design (no rollback code needed because nothing
        in-memory mutates until durable success). Wave-1 single-asyncio-
        loop assumption: mark_running is the single writer for promotion
        (no race between caps recheck and durable transition).

        For a task in ``_running_attribution`` (accepted_immediate
        path — counters were already incremented at submit), just
        issue the storage transition.

        For a task in neither tracking dict, just issue the storage
        transition. This permits external callers / test fixtures to
        drive transitions without engine bookkeeping; the storage
        row's state-machine validator still gates the transition.
        """
        queued_attr = self._queued_attribution.get(task_id)
        if queued_attr is not None:
            tenant_class_key = (queued_attr.tenant_id, queued_attr.class_)
            queue = self._queues.get(tenant_class_key)
            # Step 1: FIFO check
            if queue is None or queue.peek() != task_id:
                raise SchedulerPromotionRefused(task_id, reason="not_at_queue_head")
            # Step 2: cap re-check
            tenant_count = self._tenant_class_counts.get(tenant_class_key, 0)
            pack_count = self._pack_counts.get(queued_attr.pack_id, 0)
            actor_count = self._actor_counts.get(queued_attr.actor_subject, 0)
            if not self._caps.has_headroom_for(
                class_=queued_attr.class_,
                tenant_count=tenant_count,
                pack_count=pack_count,
                actor_count=actor_count,
            ):
                raise SchedulerPromotionRefused(task_id, reason="caps_saturated")
            # Step 3: durable transition FIRST (no in-memory mutation yet)
            await self._storage.transition(
                task_id=task_id,
                from_state="pending",
                to_state="running",
                actor_id="scheduler-engine",
                request_id=request_id,
                payload_extras={},
            )
            # Step 4: only on success, commit bookkeeping
            self._tenant_class_counts[tenant_class_key] = tenant_count + 1
            self._pack_counts[queued_attr.pack_id] = pack_count + 1
            self._actor_counts[queued_attr.actor_subject] = actor_count + 1
            self._running_attribution[task_id] = queued_attr
            del self._queued_attribution[task_id]
            queue.remove(task_id)
            return
        # Non-queued path: accepted_immediate or external caller
        await self._storage.transition(
            task_id=task_id,
            from_state="pending",
            to_state="running",
            actor_id="scheduler-engine",
            request_id=request_id,
            payload_extras={},
        )

    async def reap_expired(
        self,
        *,
        queue_ttl_s_per_class: dict[SchedulerPriorityClass, float],
        now: datetime | None = None,
        request_id: str = "scheduler-reaper",
    ) -> int:
        """Sweep ``_queued_attribution`` for tasks past their queue TTL
        and transition them ``pending → expired``. Returns the count
        of expired tasks.

        Per spec §4.4 + ADR-022 §X: queue TTL is per-class; a queued
        task whose age exceeds its class TTL is given up on — the
        ``pending → expired`` transition releases the quota reservation,
        removes the task from the FIFO queue, decrements the queue's
        attribution dict, and emits a ``scheduler.task_expired`` chain
        row via ``_transition_terminal``.

        Round-6 reviewer P1/P2 fix — adds the public seam the plan
        listed at task-T5 docstring + the spec listed at §4.4 but the
        round-5 implementation omitted (leaving ``pending → expired``
        unreachable through the engine).

        The TTL is passed in per call (rather than configured at
        construction) so operator reconciler loops can wire it from
        ``Settings`` at the call site (T6) without engine reconstruction.
        Wave-2 will likely configure at construction once the
        distributed-counter substrate lands.

        Callers (operator reconciler loop) typically invoke this on a
        timer (e.g. every 5s); the method is idempotent (no double-
        expiry of an already-expired task because the storage state
        machine refuses ``expired → expired``).
        """
        actual_now = now if now is not None else datetime.now(UTC)
        expired_count = 0
        # Snapshot the items() list so we can mutate _queued_attribution
        # via _transition_terminal during iteration.
        for task_id, attribution in list(self._queued_attribution.items()):
            ttl_s = queue_ttl_s_per_class.get(attribution.class_)
            if ttl_s is None:
                # No TTL configured for this class; skip.
                continue
            age_s = (actual_now - attribution.enqueued_at).total_seconds()
            if age_s < ttl_s:
                continue
            await self._transition_terminal(
                task_id=task_id,
                from_state="pending",
                to_state="expired",
                request_id=request_id,
                payload_extras={
                    "reason": "queue_ttl_exceeded",
                    "age_s": age_s,
                    "queue_ttl_s": ttl_s,
                },
            )
            expired_count += 1
        return expired_count

    async def complete(self, task_id: uuid.UUID, *, request_id: str) -> None:
        """Transition running → completed. Releases quota reservation."""
        await self._transition_terminal(
            task_id=task_id,
            from_state="running",
            to_state="completed",
            request_id=request_id,
            payload_extras={},
        )

    async def fail(
        self,
        task_id: uuid.UUID,
        *,
        payload: TaskFailedPayload,
        request_id: str,
    ) -> None:
        """Transition running → failed (or pending → failed per
        ADR-022 amendment for create/projection failure). Releases quota
        reservation. Per spec §4.2: payload carries cross-layer
        correlation (sandbox_refusal_reason + sandbox_event_id)."""
        # The from_state could be pending or running depending on
        # whether the task ever started. Probe storage to determine.
        from_state = await self._read_state(task_id)
        await self._transition_terminal(
            task_id=task_id,
            from_state=from_state,
            to_state="failed",
            request_id=request_id,
            payload_extras={
                "reason": payload.reason,
                "sandbox_refusal_reason": payload.sandbox_refusal_reason,
                "sandbox_event_id": payload.sandbox_event_id,
            },
        )

    async def cancel(
        self,
        task_id: uuid.UUID,
        *,
        actor: Any,  # TaskActor (avoiding circular import in signature)  # type: ignore[valid-type]
        reason: SchedulerTaskCancelledReason,
        request_id: str,
    ) -> None:
        """Cooperative cancellation per spec §4.6 + ADR-022 amendment.
        Supports both running → cancelled AND pending → cancelled
        (cancel-during-create)."""
        from_state = await self._read_state(task_id)
        # NOTE: ``cancelled_by`` is distinct from ``actor_subject`` (which
        # lives in the row-locked evidence snapshot as the task's ORIGINAL
        # submitter). The cancelling actor may differ — e.g. a tenant
        # admin cancelling another user's task. Using a distinct key
        # avoids overlap with _RESERVED_TRANSITION_PAYLOAD_KEYS (which
        # caught this exact bug in the round-4 P1 guard).
        await self._transition_terminal(
            task_id=task_id,
            from_state=from_state,
            to_state="cancelled",
            request_id=request_id,
            payload_extras={
                "cancelled_by": actor.subject,
                "reason": reason,
            },
        )

    async def preempt(self, task_id: uuid.UUID, *, request_id: str) -> None:
        """Transition running → preempted. Wave-1 only trigger is
        quota_exhausted_in_flight per spec §4.4."""
        await self._transition_terminal(
            task_id=task_id,
            from_state="running",
            to_state="preempted",
            request_id=request_id,
            payload_extras={"reason": "quota_exhausted_in_flight"},
        )

    # --- internal helpers --------------------------------------------

    def _get_or_create_queue(self, tenant_id: str, class_: SchedulerPriorityClass) -> BoundedQueue:
        key = (tenant_id, class_)
        existing = self._queues.get(key)
        if existing is not None:
            return existing
        max_depth, sla_s = self._class_settings[class_]
        queue = BoundedQueue(max_depth=max_depth, class_sla_s=sla_s)
        self._queues[key] = queue
        return queue

    async def _transition_terminal(
        self,
        *,
        task_id: uuid.UUID,
        from_state: SchedulerTaskState,
        to_state: SchedulerTaskState,
        request_id: str,
        payload_extras: dict[str, object],
    ) -> None:
        """Common terminal-state transition path: storage.transition()
        + release quota reservation + decrement in-memory concurrency
        counters (running tasks) OR remove from queue (queued tasks).

        Round-5 reviewer P1 #2/#3 fixes:
          * If task is in _running_attribution (was counted at
            accepted_immediate OR promoted via mark_running from
            queue), decrement the matching per-tenant/class +
            per-pack + per-actor counts so capacity reopens.
          * If task is in _queued_attribution (still waiting), remove
            it from the matching (tenant, class) queue so the queue
            slot reopens.
        """
        await self._storage.transition(
            task_id=task_id,
            from_state=from_state,
            to_state=to_state,
            actor_id="scheduler-engine",
            request_id=request_id,
            payload_extras=payload_extras,
        )
        # Decrement counters / remove from queue based on attribution
        running_attr = self._running_attribution.pop(task_id, None)
        if running_attr is not None:
            self._decrement_counts(running_attr)
        queued_attr = self._queued_attribution.pop(task_id, None)
        if queued_attr is not None:
            queue = self._queues.get((queued_attr.tenant_id, queued_attr.class_))
            if queue is not None:
                queue.remove(task_id)
        # Quota release is idempotent per Protocol contract; safe to
        # call regardless of whether would_admit reserved successfully.
        await self._quota.release_reservation(task_id)

    def _decrement_counts(self, attribution: _TaskAttribution) -> None:
        """Round-5 reviewer P1 #2 fix: decrement the three counter
        dimensions for a task whose terminal-state transition just
        succeeded. Clamps at 0 defensively (an extra decrement on an
        already-zero counter is a bug, not a state to silently
        propagate)."""
        tenant_class_key = (attribution.tenant_id, attribution.class_)
        self._tenant_class_counts[tenant_class_key] = max(
            0, self._tenant_class_counts.get(tenant_class_key, 0) - 1
        )
        self._pack_counts[attribution.pack_id] = max(
            0, self._pack_counts.get(attribution.pack_id, 0) - 1
        )
        self._actor_counts[attribution.actor_subject] = max(
            0, self._actor_counts.get(attribution.actor_subject, 0) - 1
        )

    async def _read_state(self, task_id: uuid.UUID) -> SchedulerTaskState:
        """Probe storage for the current state. Used by fail() + cancel()
        which can fire from either pending OR running per the ADR-022
        amendments."""
        from sqlalchemy import select

        from cognic_agentos.core.scheduler.storage import _scheduler_tasks

        async with self._storage._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_scheduler_tasks.c.state).where(_scheduler_tasks.c.task_id == task_id)
                )
            ).first()
        if row is None:
            from cognic_agentos.core.scheduler.storage import (
                SchedulerTaskNotFound,
            )

            raise SchedulerTaskNotFound(task_id)
        # Cast: column is checked by ck_scheduler_tasks_state to be one
        # of the 7 SchedulerTaskState Literal values.
        return row.state  # type: ignore[no-any-return]
