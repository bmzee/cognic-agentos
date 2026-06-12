"""Sprint 10.5 consumer-owned Protocol seams for cross-sprint
dependencies that don't yet exist in this workspace. Each Protocol +
fail-loud sentinel ships in Sprint 10.5a per
[[feedback_consumer_owned_protocol_for_unlanded_dep]]; the owning
future sprint structurally conforms (NOT re-imports) when its module
lands.

Four Protocols ship in T5:
  * QuotaInterrogator → Sprint 13.6 will conform at
    core/emergency/quotas.QuotaEngine (emergency controls carved from
    13.5 to 13.6 at the 2026-06-12 reconciliation)
  * KillSwitchInterrogator → Sprint 13.6 will conform at
    core/emergency/kill_switches.KillSwitchEngine
  * ParentBudgetResolver → Sprint 11 sub-agent primitive will conform
    at subagent/budget_resolver (or wherever subagent settles)
  * PackStateInterrogator → packs/storage.PackRecordStore will conform
    at the SchedulerEngine wiring task (10.5b T9 or later integration).
    Added per round-5 reviewer P2 #6 — the 5th refusal value
    `refused_pack_not_installed` from spec §4.2 needs this seam to be
    reachable. Sentinel raises NotImplementedError; pre-wiring
    deployments must inject a structural conformer (a callable closure
    around the existing packs/storage.PackRecordStore.list_for_tenant
    or similar is sufficient).

Plus the pure-functional ``compute_child_budget`` helper (T10 wires it
into SchedulerEngine.submit at the parent_task_id call site).

Critical-controls module (core/ stop-rule per AGENTS.md).
Every edit is halt-before-commit per
[[feedback_strict_review_off_gate]].
"""

from __future__ import annotations

import uuid
from typing import Protocol, runtime_checkable


@runtime_checkable
class QuotaInterrogator(Protocol):
    """Sprint 13.6 will implement at core/emergency/quotas.QuotaEngine
    (emergency controls carved from 13.5 to 13.6 at the 2026-06-12
    reconciliation).

    Sprint 10.5 SchedulerEngine constructs with a QuotaInterrogator
    instance via DI; production wiring uses _NullQuotaInterrogator
    until Sprint 13.6 ships the real implementation.

    Two-method API (the storage/quota reservation needs a handle so
    terminal-state release can refer back to the reservation):

    - ``would_admit`` returns True iff the reservation was made;
      on True the implementation has atomically reserved
      ``estimated_tokens`` against tenant + pack budgets keyed by
      ``task_id``.
    - ``release_reservation`` releases the reservation. Idempotent:
      calling on an unknown/already-released task_id is a no-op (per
      Sprint 10.5b T9 contract — terminal-state code paths may fire
      multiple times in failure scenarios and must not raise).
    """

    async def would_admit(
        self,
        *,
        task_id: uuid.UUID,
        tenant_id: str,
        pack_id: str,
        estimated_tokens: int,
    ) -> bool: ...

    async def release_reservation(self, task_id: uuid.UUID) -> None: ...


@runtime_checkable
class KillSwitchInterrogator(Protocol):
    """Sprint 13.6 will implement at
    core/emergency/kill_switches.KillSwitchEngine (emergency carved
    from 13.5 to 13.6 at the 2026-06-12 reconciliation)."""

    async def is_active(
        self,
        *,
        tenant_id: str,
        pack_id: str,
    ) -> bool: ...


@runtime_checkable
class PackStateInterrogator(Protocol):
    """Cross-layer pack-state read seam. The conformer will live at the
    packs/storage.PackRecordStore consumer site (10.5b T9 or later
    integration); core/scheduler/ does NOT import packs/storage
    directly per the layering invariant.

    Returns True iff the pack with the given tenant + pack_id pair is
    currently in the ``installed`` lifecycle state per the Sprint 7B
    pack lifecycle state machine. Used by SchedulerEngine to surface
    ``refused_pack_not_installed`` (the 5th spec §4.2 refusal value)
    without coupling to packs/storage.
    """

    async def is_installed(
        self,
        *,
        tenant_id: str,
        pack_id: str,
    ) -> bool: ...


@runtime_checkable
class ParentBudgetResolver(Protocol):
    """Sprint 11 sub-agent primitive will implement at
    subagent/budget_resolver (or wherever subagent settles).

    Resolves a parent task's remaining token budget for sub-agent
    submissions. Pure read-only seam — does NOT mutate the parent
    task's budget (that's the parent task's own quota-engine
    reservation)."""

    async def remaining_budget_for(self, parent_task_id: uuid.UUID) -> int: ...


class _NullQuotaInterrogator:
    """Fail-loud sentinel raising NotImplementedError pointing at Sprint 13.6.

    Production deployments wire a real QuotaInterrogator from
    core/emergency/quotas at app-startup; the sentinel is the production-
    grade-rule-compliant default that ensures a wiring miss surfaces
    immediately rather than silently allowing submission."""

    async def would_admit(
        self,
        *,
        task_id: uuid.UUID,
        tenant_id: str,
        pack_id: str,
        estimated_tokens: int,
    ) -> bool:
        raise NotImplementedError(
            "QuotaInterrogator not wired. Sprint 13.6 (core/emergency/quotas.py) "
            "supplies the real implementation; pre-13.6 deployments must inject "
            "a structural conformer at SchedulerEngine construction."
        )

    async def release_reservation(self, task_id: uuid.UUID) -> None:
        raise NotImplementedError(
            "QuotaInterrogator not wired. See Sprint 13.6 (core/emergency/quotas.py)."
        )


class _NullKillSwitchInterrogator:
    """Fail-loud sentinel raising NotImplementedError pointing at Sprint 13.6."""

    async def is_active(self, *, tenant_id: str, pack_id: str) -> bool:
        raise NotImplementedError(
            "KillSwitchInterrogator not wired. Sprint 13.6 "
            "(core/emergency/kill_switches.py) supplies the real implementation; "
            "pre-13.6 deployments must inject a structural conformer at "
            "SchedulerEngine construction."
        )


class _NullPackStateInterrogator:
    """Fail-loud sentinel. Production wiring (10.5b T9 or later
    integration task) MUST inject a structural conformer; default
    sentinel raises NotImplementedError so a wiring miss surfaces
    immediately rather than silently allowing every pack as
    ``installed``."""

    async def is_installed(self, *, tenant_id: str, pack_id: str) -> bool:
        raise NotImplementedError(
            "PackStateInterrogator not wired. The pack-state seam must be "
            "supplied at SchedulerEngine construction by a structural "
            "conformer over packs/storage.PackRecordStore (or equivalent). "
            "Sprint 10.5b T9 (or later integration task) wires the real "
            "conformer; pre-wiring deployments cannot use the "
            "refused_pack_not_installed admission outcome."
        )


class _NullParentBudgetResolver:
    """Fail-loud sentinel. Production deployments wire a Sprint 11
    ParentBudgetResolver structural conformer at SchedulerEngine
    construction; the sentinel is the production-grade-rule-compliant
    default that ensures a wiring miss surfaces immediately rather
    than silently allowing unbounded sub-agent submissions."""

    async def remaining_budget_for(self, parent_task_id: uuid.UUID) -> int:
        raise NotImplementedError(
            "ParentBudgetResolver not wired. Sprint 11 (sub-agent primitive) "
            "supplies the real implementation; pre-Sprint-11 deployments must "
            "either inject a structural conformer at SchedulerEngine construction "
            "OR submit only with SubmitInput.parent_task_id=None. Submitting "
            "parent_task_id=<non-None> with the sentinel attached propagates "
            "NotImplementedError fail-loud (NOT a closed-enum refusal)."
        )


def compute_child_budget(
    *,
    parent_remaining_budget: int,
    child_pack_quota: int,
) -> int:
    """Pure-functional sub-agent budget narrowing per ADR-005 amendment.

    Returns ``min(child_pack_quota, parent_remaining_budget)``. Both
    inputs are required non-negative integers. SchedulerEngine.submit()
    (T10 wiring) calls this helper after resolving
    ``parent_remaining_budget`` via the injected ParentBudgetResolver
    Protocol (default sentinel fails loud; Sprint 11 supplies the real
    conformer).
    """
    if parent_remaining_budget < 0:
        raise ValueError(f"parent_remaining_budget must be >= 0; got {parent_remaining_budget}")
    if child_pack_quota < 0:
        raise ValueError(f"child_pack_quota must be >= 0; got {child_pack_quota}")
    return min(child_pack_quota, parent_remaining_budget)


# --- Sprint 10.5b T11 — sandbox-substrate-independence exception ---------


@runtime_checkable
class SandboxAdapter(Protocol):
    """T11 round-2 P1 — Scheduler-owned consumer Protocol for the
    sandbox lifecycle. Atomic create + destroy pair: the scheduler
    API makes it IMPOSSIBLE to inject just one half (which would
    leak external sandbox resources on the storage-failure-after-
    create path documented at the T11 round-1 P1 reviewer fix).

    The AgentOS app's DI binder at startup supplies a structurally-
    conforming object that wraps the real
    ``cognic_agentos.sandbox.protocol.SandboxBackend`` (or the future-
    equivalent ``cognic_agentos.subagent.*`` adapter for sub-agent-
    bearing tasks). Scheduler NEVER imports from sandbox/* (pinned by
    the AST guard at ``tests/unit/core/scheduler/test_architecture_no_sandbox_import.py``);
    this Protocol is the scheduler-side declared contract per
    [[feedback_consumer_owned_protocol_for_unlanded_dep]].

    Two-method contract:
      * ``create(task_id)`` — provision the workload sandbox for
        ``task_id``. Raise :class:`SandboxCreateRefused` (THIS module's
        typed exception, NOT the sandbox-layer's native
        ``SandboxLifecycleRefused``) on a closed-set create refusal;
        the DI binder translates upstream sandbox exceptions to this
        scheduler-owned type. Generic exceptions propagate uncaught.
      * ``destroy(task_id)`` — best-effort compensating cleanup
        called by the engine when ``storage.transition`` fails AFTER
        ``create`` succeeded. Idempotent: callers may invoke on an
        already-destroyed task_id; implementations MUST NOT raise on
        not-found.

    The atomic-pair API is the round-2 P1 fix for the round-1 reviewer
    finding — the prior signature (two separate callable kwargs)
    documented the leak but allowed production miswiring; the
    Protocol makes the leaky combination unrepresentable.
    """

    async def create(self, task_id: uuid.UUID) -> None: ...

    async def destroy(self, task_id: uuid.UUID) -> None: ...


class SandboxCreateRefused(Exception):
    """Scheduler-owned typed exception representing a sandbox-create
    refusal at the engine's mark_running call site.

    **Substrate independence contract (T11)**: scheduler NEVER imports
    from ``cognic_agentos.sandbox/*`` (pinned by the AST guard at
    ``tests/unit/core/scheduler/test_architecture_no_sandbox_import.py``).
    The AgentOS app's DI binder at startup wraps any
    ``sandbox.SandboxLifecycleRefused`` (or future-equivalent typed
    exception) into THIS scheduler-owned class before passing the
    create callable to ``SchedulerEngine.mark_running``. Mirrors the
    [[feedback_consumer_owned_protocol_for_unlanded_dep]] pattern at
    a higher abstraction level — the scheduler owns the exception
    shape it consumes; the sandbox layer owns its own.

    Two attributes flow to the scheduler's
    ``TaskFailedPayload``:
      * ``reason``: free-form upstream sandbox closed-enum value
        (e.g. ``"sandbox_credential_mint_failed_vault_path_not_found"``).
        Threaded onto ``TaskFailedPayload.sandbox_refusal_reason``
        for spec §5.8 step 7 cross-layer correlation.
      * ``event_id``: chain-derived event id from the sandbox's
        ``sandbox.lifecycle.create_refused`` audit row, or ``None``
        if the create refusal happened pre-audit. Threaded onto
        ``TaskFailedPayload.sandbox_event_id``.
    """

    def __init__(self, *, reason: str, event_id: str | None = None) -> None:
        super().__init__(f"sandbox_create_refused: reason={reason} event_id={event_id!r}")
        self.reason = reason
        self.event_id = event_id
