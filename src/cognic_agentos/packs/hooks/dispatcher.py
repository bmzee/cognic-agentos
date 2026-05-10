"""Sprint-7A2 T7 — runtime hook deterministic-phase dispatcher.

Per Doctrine Lock D + Doctrine Lock E in
``docs/superpowers/plans/2026-05-09-sprint-7a2-hook-packs-runtime.md``:

  ``HookDispatcher`` deterministic phase dispatcher. Single-writer
  for the dispatch loop. For each (phase, ordered hook list), invokes
  hooks in deterministic order (``ordering_rank`` ascending — the
  rank table at ``cli/_governance_vocab.HOOK_ORDERING_RANK`` —
  with ties broken by ``hook_id`` alphabetic), enforces per-hook
  timeout via ``asyncio.wait_for``, applies failure policy
  (fail_closed default), emits audit + decision-history rows for
  every hook decision, and short-circuits the dispatch chain on the
  first ``decision="refuse"``.

Boundary: registry owns admission; dispatcher owns runtime decision.
The two never share mutable state — the dispatcher reads an
**immutable snapshot** of ``(phase, hook_id) → HookEntry`` at
dispatch entry. A self-registering hook (e.g., a hook that calls
back into the registry during ``_invoke``) cannot extend the
dispatcher's iteration target — the snapshot is taken once per
dispatch call.

Five closed-enum failure modes (per Doctrine Lock E):

* ``hook_timeout`` — :func:`asyncio.wait_for` exceeded
  ``min(entry.timeout_seconds, runtime_ceiling)``. Fail-closed
  regardless of ``fail_policy`` (timeout fires at the dispatcher
  level, outside the hook's _invoke catch boundary).
* ``hook_exception`` — Hook ``_invoke`` raised any unhandled
  exception. Fail-closed UNLESS ``fail_policy="fail_open"`` AND
  the exception's class name (walked through ``type(exc).__mro__``)
  matches ``fail_open_exception``.
* ``hook_malformed_result`` — Hook ``invoke()`` returned a non-
  ``HookResult`` shape OR a ``HookResult`` with internally-
  inconsistent fields (caught by the SDK seam as
  ``HookContractError``). Fail-closed regardless — SDK contract
  violations are programming errors, never recoverable.
* ``hook_policy_refused`` — Hook returned
  ``HookResult(decision="refuse", policy_reason=...)`` legitimately.
  Fail-closed; ``policy_reason`` propagates to the refusal envelope
  the calling pack sees.
* ``hook_payload_unscannable`` — Payload exceeded
  ``max_payload_bytes``. Fail-closed BEFORE invoking any hook.
  Bounds runtime risk against payloads too large to scan in time.

**Payload-contents-never-logged invariant** (Doctrine Lock E): the
``payload`` argument is opaque bytes. The dispatcher computes
``hashlib.sha256(payload).hexdigest()`` once at dispatch entry for
the audit row's ``policy_input_digest`` field but NEVER includes
the payload bytes themselves in any audit / decision-history / log
line / repr / str / format / f-string. The companion AST regression
at ``tests/architecture/test_hook_payload_never_logged.py`` is the
mechanical guardrail — refusing ``print`` / ``logging.*`` /
``logger.*`` / ``f"...{payload}..."`` / ``str(payload)`` /
``payload.decode(...)`` and similar shapes anywhere in this file.

Critical-controls promotion: this module joins the gate at T12
closeout (37 → 40, alongside ``packs/hooks/registry.py`` and
``cli/validators/hooks.py``).
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Final, Literal

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.packs.hooks.registry import HookEntry, HookRegistry
from cognic_agentos.sdk.hook import (
    Hook,
    HookContext,
    HookContractError,
    HookResult,
)

__all__ = [
    "HookDispatchOutcome",
    "HookDispatchResult",
    "HookDispatchSelectionError",
    "HookDispatcher",
    "HookFailureMode",
]


#: Closed-enum chain-level outcome (3 values). Adding a value
#: requires doctrine review (T12 critical-controls promotion pins
#: this as wire-shape contract for the calling-pack refusal envelope).
HookDispatchOutcome = Literal[
    "passed",  # every hook returned decision=pass / redact / mask; chain completed
    "refused",  # a hook returned decision=refuse (legitimate policy refusal)
    "failed",  # timeout / exception / malformed result / payload unscannable
]


#: Closed-enum failure-mode taxonomy from Doctrine Lock E (5 values).
#: ``None`` for ``outcome="passed"``; populated otherwise.
HookFailureMode = Literal[
    "hook_timeout",
    "hook_exception",
    "hook_malformed_result",
    "hook_policy_refused",
    "hook_payload_unscannable",
]


# ---------------------------------------------------------------------------
# Selection-error raised by ``dispatch_for_pack`` (T8) when a declared
# hook_id is missing from the registry snapshot. T8 R1 P2-2 fix: this
# is the **normal path** for the unresolved-ID case, NOT a dead-code
# defense-in-depth raise. DLPGuard delegates first to
# ``dispatch_for_pack`` so the dispatcher's budget-check-before-lookup
# precedence is preserved; an unknown hook_id encountered AFTER the
# budget check raises this exception, which DLPGuard catches and
# routes to the closed-enum ``dlp_hook_id_unresolved`` terminus.
#
# Carries structured ``hook_id`` + ``phase`` attributes (rather than
# only a stringified message) so DLPGuard can populate audit rows +
# ``DLPGuardOutcome.failed_hook_id`` without re-parsing the message.
#
# Inherits :class:`RuntimeError` so a generic ``except RuntimeError``
# also catches it (defense-in-depth — old-style callers).
# ---------------------------------------------------------------------------


class HookDispatchSelectionError(RuntimeError):
    """Raised by :meth:`HookDispatcher.dispatch_for_pack` when a
    declared ``hook_id`` is not registered for the requested phase.

    This is the **primary signal** for the unresolved-ID case — T8
    R1 P2-2 review removed DLPGuard's pre-validation pass, so
    DLPGuard delegates first and catches this exception as the
    normal route to ``dlp_hook_id_unresolved``.

    The unresolved ``hook_id`` + ``phase`` are exposed as structured
    attributes (:attr:`HookDispatchSelectionError.hook_id` /
    :attr:`HookDispatchSelectionError.phase`) so callers (DLPGuard,
    T8) can populate audit rows + outcome fields without re-parsing
    the exception message.

    The exception fires only AFTER the dispatcher's budget check has
    passed (lookup runs after budget per
    :meth:`HookDispatcher.dispatch_for_pack` step order), so an
    oversized payload + unresolved id correctly routes to
    ``hook_payload_unscannable``, NOT to this exception.
    """

    def __init__(self, *, hook_id: str, phase: HookPhase) -> None:
        self.hook_id: Final[str] = hook_id
        self.phase: Final[HookPhase] = phase
        super().__init__(
            "declared hook_id "
            + repr(hook_id)
            + " is not registered for phase "
            + repr(phase)
            + "; caller (DLPGuard) catches this and routes to "
            + "``dlp_hook_id_unresolved``."
        )


# ---------------------------------------------------------------------------
# Audit-row callback type — the dispatcher emits a token-free dict per
# hook decision; the runtime composition site (Sprint-7B) wires it to
# the AuditStore + DecisionHistoryStore. Wave-1 the callback is
# optional (no-op when None).
# ---------------------------------------------------------------------------


AuditEmitter = Callable[[dict[str, object]], Awaitable[None]]


# ---------------------------------------------------------------------------
# DispatchResult — frozen + slotted wire-shape for the calling pack
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HookDispatchResult:
    """Result of a single :meth:`HookDispatcher.dispatch` call.

    ``outcome`` + ``failure_mode`` are the closed-enum routing
    surface; the calling-pack invocation surface (Sprint-7B
    integration) consumes these to build its refusal envelope.

    ``final_payload`` carries the payload AS SEEN BY THE NEXT STAGE:
    on ``passed``, the (possibly redact/mask-transformed) payload;
    on ``refused`` / ``failed``, the LAST payload before the chain
    halted (no transformation by a halting hook).

    ``policy_input_digest`` is the SHA-256 hex digest of the
    **original** payload (never the transformed payload). The
    dispatcher computes this once at dispatch entry and propagates
    it to every audit row + the result envelope.
    """

    outcome: HookDispatchOutcome
    final_payload: bytes
    failure_mode: HookFailureMode | None
    failed_hook_id: str | None
    failed_pack_distribution_name: str | None
    policy_reason: str | None
    policy_input_digest: str


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


class HookDispatcher:
    """Deterministic phase dispatcher.

    Reads :meth:`HookRegistry.get_phase_hooks` exactly once at
    dispatch entry; iterates the local tuple thereafter. Snapshot
    semantics ensure a self-registering hook cannot extend the
    iteration target mid-dispatch.

    Construction takes:

    * ``registry`` — the verified-pack admission gate. The dispatcher
      reads-only; mutation happens at admission.
    * ``max_payload_bytes`` — hard ceiling on payload size. Payloads
      strictly larger refuse fail-closed with
      ``hook_payload_unscannable`` BEFORE any hook runs.
    * ``max_timeout_seconds_runtime`` — runtime per-hook ceiling; the
      dispatcher uses ``min(entry.timeout_seconds, runtime_ceiling)``.
      Defense-in-depth against a permissive admission ceiling.
    * ``audit_emitter`` — optional async callback that receives one
      token-free dict per hook decision. Wave-1 may be ``None``;
      Sprint-7B wires the AuditStore + DecisionHistoryStore.
    """

    def __init__(
        self,
        *,
        registry: HookRegistry,
        max_payload_bytes: int,
        max_timeout_seconds_runtime: float,
        audit_emitter: AuditEmitter | None = None,
    ) -> None:
        if max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be > 0; got " + repr(max_payload_bytes))
        if max_timeout_seconds_runtime <= 0:
            raise ValueError(
                "max_timeout_seconds_runtime must be > 0; got " + repr(max_timeout_seconds_runtime)
            )
        self._registry: Final[HookRegistry] = registry
        self._max_payload_bytes: Final[int] = max_payload_bytes
        self._max_timeout_seconds_runtime: Final[float] = max_timeout_seconds_runtime
        self._audit_emitter: Final[AuditEmitter | None] = audit_emitter

    async def dispatch(
        self,
        *,
        phase: HookPhase,
        payload: bytes,
        context_template: HookContext,
    ) -> HookDispatchResult:
        """Run the deterministic hook chain for ``phase`` against
        ``payload``.

        ``context_template`` is the caller's invocation context with
        ``hook_id=""`` as a sentinel. The dispatcher fills ``hook_id``
        per-hook via :func:`dataclasses.replace`. Mismatched
        ``phase`` between the template and the dispatch argument
        raises :class:`ValueError` fail-fast (the call site is
        confused about which phase it's running).

        Returns a :class:`HookDispatchResult` with the closed-enum
        outcome + (when applicable) the failure mode + failing
        hook_id + policy reason. Never raises for hook-level failures
        — those are routed to ``outcome="failed"``. Caller-input
        validation (template sentinel, phase agreement) raises
        :class:`ValueError` fail-fast.
        """
        # Caller-input validation — fail-fast on template confusion.
        if context_template.hook_id != "":
            raise ValueError(
                "context_template.hook_id must be the empty-string "
                "sentinel; the dispatcher fills hook_id per-hook. "
                "Got: " + repr(context_template.hook_id)
            )
        if context_template.phase != phase:
            raise ValueError(
                "context_template.phase ("
                + repr(context_template.phase)
                + ") does not match dispatch argument phase ("
                + repr(phase)
                + "); caller is confused about which phase to run."
            )

        # Compute the original-payload digest ONCE; propagate to every
        # audit row + the result envelope. The digest is NEVER the
        # transformed payload's digest.
        digest = hashlib.sha256(payload).hexdigest()

        # Pre-loop budget check — payloads too large refuse fail-closed
        # BEFORE any hook runs (mirrors A2A wave2 classifier doctrine).
        if len(payload) > self._max_payload_bytes:
            await self._maybe_emit_audit(
                event_type="hook.payload_unscannable",
                phase=phase,
                hook_id=None,
                pack_distribution_name=None,
                pack_distribution_version=None,
                outcome="failed",
                failure_mode="hook_payload_unscannable",
                policy_reason=None,
                policy_input_digest=digest,
                tenant_id=context_template.tenant_id,
                request_id=context_template.request_id,
            )
            return HookDispatchResult(
                outcome="failed",
                final_payload=payload,
                failure_mode="hook_payload_unscannable",
                failed_hook_id=None,
                failed_pack_distribution_name=None,
                policy_reason=None,
                policy_input_digest=digest,
            )

        # SNAPSHOT — single read. A self-registering hook cannot
        # extend this iteration target mid-dispatch.
        phase_hooks = self._registry.get_phase_hooks(phase)

        current_payload = payload
        for entry in phase_hooks:
            outcome = await self._invoke_one(
                entry=entry,
                phase=phase,
                payload=current_payload,
                context_template=context_template,
                policy_input_digest=digest,
            )

            if outcome.outcome == "passed":
                # Successful pass — possibly with payload transformation.
                # ``outcome.final_payload`` is the post-hook payload
                # (or unchanged on decision=pass).
                current_payload = outcome.final_payload
                continue

            # Halt on the first non-pass outcome — refuse / fail propagate.
            return outcome

        # Every hook returned pass / redact / mask; chain completed.
        return HookDispatchResult(
            outcome="passed",
            final_payload=current_payload,
            failure_mode=None,
            failed_hook_id=None,
            failed_pack_distribution_name=None,
            policy_reason=None,
            policy_input_digest=digest,
        )

    # --- per-pack dispatch ---------------------------------------------------

    async def dispatch_for_pack(
        self,
        *,
        phase: HookPhase,
        declared_hook_ids: Sequence[str],
        payload: bytes,
        context_template: HookContext,
    ) -> HookDispatchResult:
        """Sprint-7A2 T8 — run the per-pack subset of registered hooks.

        Per ADR-017 line 97: "pack manifest names which hooks must run;
        AgentOS resolves them via the plugin registry." A calling pack
        declares ``[data_governance].dlp_pre_hooks`` /
        ``dlp_post_hooks`` listing the hook_ids that MUST run for this
        pack's invocations. This method runs ONLY those hooks — other
        hooks registered under the same phase but NOT in
        ``declared_hook_ids`` do not run for this pack.

        Order: dispatcher-canonical (``ordering_rank`` ascending; ties
        broken by ``hook_id`` alphabetic — same as :meth:`dispatch`).
        NOT the order of ``declared_hook_ids``. Pack authors do not
        control runtime order via declaration ordering; the rank table
        at ``cli/_governance_vocab.HOOK_ORDERING_RANK`` is the
        deterministic-order primitive.

        Empty ``declared_hook_ids`` returns ``outcome="passed"`` with
        the payload unchanged — a calling pack that declares no DLP
        hooks for the phase has nothing to run. Payload digest is
        still computed for audit-row correlation.

        Step order inside dispatch_for_pack: caller-input validation
        → digest → **budget check** → snapshot → resolve+dedup
        declared_hook_ids → sort by canonical order → iterate. The
        budget check fires BEFORE lookup, so an oversized payload
        with an unknown hook_id returns ``outcome="failed"`` /
        ``hook_payload_unscannable`` rather than raising
        :class:`HookDispatchSelectionError`. Manifest declarations
        with duplicate hook_ids are silently deduped at the
        snapshot-resolve step (a hook runs at most once per
        dispatch); T10's manifest validator is the build-time gate.

        A ``declared_hook_id`` missing from the registry snapshot
        raises :class:`HookDispatchSelectionError` AFTER the budget
        check has passed. T8 R1 P2-2 fix: DLPGuard catches this
        exception as the primary route to ``dlp_hook_id_unresolved``
        — DLPGuard does NOT pre-validate hook_id resolution itself,
        so the dispatcher's precedence (budget before lookup) stays
        intact.

        Caller-input validation (template hook_id sentinel + phase
        agreement) raises :class:`ValueError` fail-fast — same as
        :meth:`dispatch`.
        """
        # Caller-input validation — fail-fast on template confusion.
        # Mirrors :meth:`dispatch`; both validations apply to dispatch_for_pack.
        if context_template.hook_id != "":
            raise ValueError(
                "context_template.hook_id must be the empty-string "
                "sentinel; the dispatcher fills hook_id per-hook. "
                "Got: " + repr(context_template.hook_id)
            )
        if context_template.phase != phase:
            raise ValueError(
                "context_template.phase ("
                + repr(context_template.phase)
                + ") does not match dispatch argument phase ("
                + repr(phase)
                + "); caller is confused about which phase to run."
            )

        # Compute the original-payload digest ONCE; propagate to every
        # audit row + the result envelope. Same invariant as :meth:`dispatch`.
        digest = hashlib.sha256(payload).hexdigest()

        # Pre-loop budget check — payloads too large refuse fail-closed
        # BEFORE any hook runs. MUST come before the unresolved-id
        # lookup so that an unscannable-payload + unresolved-ids combo
        # routes to the failure outcome rather than raising
        # HookDispatchSelectionError. Payload-budget is the more
        # operator-actionable signal.
        if len(payload) > self._max_payload_bytes:
            await self._maybe_emit_audit(
                event_type="hook.payload_unscannable",
                phase=phase,
                hook_id=None,
                pack_distribution_name=None,
                pack_distribution_version=None,
                outcome="failed",
                failure_mode="hook_payload_unscannable",
                policy_reason=None,
                policy_input_digest=digest,
                tenant_id=context_template.tenant_id,
                request_id=context_template.request_id,
            )
            return HookDispatchResult(
                outcome="failed",
                final_payload=payload,
                failure_mode="hook_payload_unscannable",
                failed_hook_id=None,
                failed_pack_distribution_name=None,
                policy_reason=None,
                policy_input_digest=digest,
            )

        # SNAPSHOT — single read, same semantics as :meth:`dispatch`.
        # A self-registering hook cannot extend the iteration target
        # mid-dispatch (the snapshot is taken once per dispatch call).
        phase_hooks = self._registry.get_phase_hooks(phase)

        # Build a (phase, hook_id) → entry index from the snapshot for
        # O(1) declared-id lookup. Iterating ``declared_hook_ids`` and
        # then re-iterating ``phase_hooks`` would be O(n²) — fine at
        # Wave-1 scale but the index pattern is cheap.
        entry_by_hook_id: dict[str, HookEntry] = {e.hook_id: e for e in phase_hooks}

        # Resolve declared_hook_ids against the snapshot. T10's
        # validator refuses duplicate hook_ids in
        # ``[data_governance].dlp_pre_hooks`` / ``dlp_post_hooks``
        # at build time; runtime defense-in-depth here silently
        # dedupes the iteration target (a hook runs AT MOST ONCE per
        # dispatch even if the manifest's array somehow contains
        # duplicates). An unresolved id raises
        # :class:`HookDispatchSelectionError` — DLPGuard catches it
        # for the ``dlp_hook_id_unresolved`` terminus.
        seen_hook_ids: set[str] = set()
        resolved_entries: list[HookEntry] = []
        for hook_id in declared_hook_ids:
            if hook_id in seen_hook_ids:
                # Silent runtime dedupe — manifest validator T10 is
                # the build-time gate; this guard is fail-safe.
                continue
            seen_hook_ids.add(hook_id)
            entry = entry_by_hook_id.get(hook_id)
            if entry is None:
                raise HookDispatchSelectionError(hook_id=hook_id, phase=phase)
            resolved_entries.append(entry)

        # Sort resolved entries by dispatcher-canonical order:
        # ``ordering_rank`` ascending, ties by ``hook_id`` alphabetic.
        # NOT by the order of ``declared_hook_ids`` — the rank table
        # at ``cli/_governance_vocab.HOOK_ORDERING_RANK`` is the
        # deterministic-order primitive (same as
        # :meth:`HookRegistry.get_phase_hooks`).
        resolved_entries.sort(key=lambda e: (e.ordering_rank, e.hook_id))

        current_payload = payload
        for entry in resolved_entries:
            outcome = await self._invoke_one(
                entry=entry,
                phase=phase,
                payload=current_payload,
                context_template=context_template,
                policy_input_digest=digest,
            )
            if outcome.outcome == "passed":
                # Successful pass — possibly with payload transformation.
                current_payload = outcome.final_payload
                continue
            # Halt on the first non-pass outcome — refuse / fail propagate.
            return outcome

        # Every declared hook returned pass / redact / mask; chain completed.
        return HookDispatchResult(
            outcome="passed",
            final_payload=current_payload,
            failure_mode=None,
            failed_hook_id=None,
            failed_pack_distribution_name=None,
            policy_reason=None,
            policy_input_digest=digest,
        )

    # --- per-hook invocation -------------------------------------------------

    async def _invoke_one(
        self,
        *,
        entry: HookEntry,
        phase: HookPhase,
        payload: bytes,
        context_template: HookContext,
        policy_input_digest: str,
    ) -> HookDispatchResult:
        """Invoke a single hook with timeout + exception routing.

        Returns a partial :class:`HookDispatchResult`:

        * ``outcome="passed"`` with ``final_payload`` set to the
          post-hook payload (transformed or unchanged) — the caller
          continues iteration.
        * Any other outcome — the caller halts iteration and returns
          this result.

        Failure-mode mapping:

        * :class:`asyncio.TimeoutError` → ``hook_timeout`` (always
          fail-closed; fail_open never applies — the timeout fires
          OUTSIDE the hook's catch boundary).
        * :class:`HookContractError` (any subclass) →
          ``hook_malformed_result`` (always fail-closed; SDK contract
          violations are programming errors).
        * Any other :class:`Exception` → ``hook_exception``, with
          fail-open carve-out: if ``entry.fail_policy="fail_open"``
          AND the exception's class name (walked through MRO)
          matches ``entry.fail_open_exception``, treat as if the
          hook returned ``decision="pass"``.
        """
        # Resolve timeout — defense-in-depth ``min()``.
        clamped_timeout = min(entry.timeout_seconds, self._max_timeout_seconds_runtime)
        # Build the per-hook context — only ``hook_id`` varies.
        context = dataclasses.replace(context_template, hook_id=entry.hook_id)

        # Resolve the Hook subclass via the deferred-load callable
        # (NOT invoked at admission; this is the first time pack code
        # runs for this entry). Instantiation errors here are routed
        # to hook_exception — an unimportable / uninstantiable hook
        # is fail-closed.
        try:
            hook_cls = entry.callable_loader()
            if not isinstance(hook_cls, type) or not issubclass(hook_cls, Hook):
                # Loader returned the wrong shape — treat as malformed.
                return await self._failure_result(
                    entry=entry,
                    phase=phase,
                    payload=payload,
                    failure_mode="hook_malformed_result",
                    policy_reason=None,
                    policy_input_digest=policy_input_digest,
                    tenant_id=context_template.tenant_id,
                    request_id=context_template.request_id,
                )
            instance = hook_cls()
        except HookContractError:
            # SDK contract violations from the loader / constructor
            # path are programming errors — always fail-closed, NEVER
            # fail-open. MUST be caught BEFORE the generic Exception
            # handler below, otherwise a malicious declaration with
            # ``fail_policy="fail_open"`` and ``fail_open_exception``
            # set to ``HookContractError`` (or any subclass name —
            # ``HookResultShapeError`` / ``HookContextError`` /
            # ``HookPayloadError``) would smuggle a contract violation
            # past the malformed-result gate via the
            # ``_route_exception`` MRO walk and be treated as a pass.
            # T7 R1 review fix — symmetry with the post-instantiation
            # ``except HookContractError`` block below.
            return await self._failure_result(
                entry=entry,
                phase=phase,
                payload=payload,
                failure_mode="hook_malformed_result",
                policy_reason=None,
                policy_input_digest=policy_input_digest,
                tenant_id=context_template.tenant_id,
                request_id=context_template.request_id,
            )
        except Exception as exc:
            # Loader / constructor exceptions other than contract
            # violations — route through fail-policy (the carve-out
            # CAN apply here for genuine recoverable errors like
            # transient import failures the pack author has annotated).
            return await self._route_exception(
                entry=entry,
                phase=phase,
                payload=payload,
                exc=exc,
                policy_input_digest=policy_input_digest,
                tenant_id=context_template.tenant_id,
                request_id=context_template.request_id,
            )

        # Run with timeout — asyncio.wait_for cancels the coroutine on
        # timeout (cooperative cancellation; the hook MUST honor
        # cancellation within reasonable time per the asyncio
        # contract).
        try:
            result = await asyncio.wait_for(
                instance.invoke(context, payload),
                timeout=clamped_timeout,
            )
        except TimeoutError:
            return await self._failure_result(
                entry=entry,
                phase=phase,
                payload=payload,
                failure_mode="hook_timeout",
                policy_reason=None,
                policy_input_digest=policy_input_digest,
                tenant_id=context_template.tenant_id,
                request_id=context_template.request_id,
            )
        except HookContractError:
            # SDK contract violation — programming error, never recoverable.
            return await self._failure_result(
                entry=entry,
                phase=phase,
                payload=payload,
                failure_mode="hook_malformed_result",
                policy_reason=None,
                policy_input_digest=policy_input_digest,
                tenant_id=context_template.tenant_id,
                request_id=context_template.request_id,
            )
        except Exception as exc:
            return await self._route_exception(
                entry=entry,
                phase=phase,
                payload=payload,
                exc=exc,
                policy_input_digest=policy_input_digest,
                tenant_id=context_template.tenant_id,
                request_id=context_template.request_id,
            )

        # Decision routing — refuse halts the chain; pass / redact /
        # mask continue with the appropriate forward payload.
        return await self._route_decision(
            entry=entry,
            phase=phase,
            payload=payload,
            result=result,
            policy_input_digest=policy_input_digest,
            tenant_id=context_template.tenant_id,
            request_id=context_template.request_id,
        )

    async def _route_decision(
        self,
        *,
        entry: HookEntry,
        phase: HookPhase,
        payload: bytes,
        result: HookResult,
        policy_input_digest: str,
        tenant_id: str,
        request_id: str,
    ) -> HookDispatchResult:
        """Map a successfully-returned :class:`HookResult` to a
        :class:`HookDispatchResult`. The SDK seam already validated
        the decision-↔-fields invariant; this routing trusts the
        result shape."""
        decision = result.decision

        if decision == "pass":
            await self._maybe_emit_audit(
                event_type="hook.decision",
                phase=phase,
                hook_id=entry.hook_id,
                pack_distribution_name=entry.pack_distribution_name,
                pack_distribution_version=entry.pack_distribution_version,
                outcome="passed",
                failure_mode=None,
                policy_reason=None,
                policy_input_digest=policy_input_digest,
                tenant_id=tenant_id,
                request_id=request_id,
                decision="pass",
            )
            return HookDispatchResult(
                outcome="passed",
                final_payload=payload,
                failure_mode=None,
                failed_hook_id=None,
                failed_pack_distribution_name=None,
                policy_reason=None,
                policy_input_digest=policy_input_digest,
            )

        if decision in ("redact", "mask"):
            # SDK seam pinned that redacted_payload is bytes for
            # redact/mask; mypy narrowing requires the explicit check.
            new_payload = result.redacted_payload
            assert isinstance(new_payload, bytes)
            await self._maybe_emit_audit(
                event_type="hook.decision",
                phase=phase,
                hook_id=entry.hook_id,
                pack_distribution_name=entry.pack_distribution_name,
                pack_distribution_version=entry.pack_distribution_version,
                outcome="passed",
                failure_mode=None,
                policy_reason=None,
                policy_input_digest=policy_input_digest,
                tenant_id=tenant_id,
                request_id=request_id,
                decision=decision,
            )
            return HookDispatchResult(
                outcome="passed",
                final_payload=new_payload,
                failure_mode=None,
                failed_hook_id=None,
                failed_pack_distribution_name=None,
                policy_reason=None,
                policy_input_digest=policy_input_digest,
            )

        # decision == "refuse" — SDK seam pinned policy_reason is non-empty.
        reason = result.policy_reason
        assert isinstance(reason, str) and reason
        await self._maybe_emit_audit(
            event_type="hook.refused",
            phase=phase,
            hook_id=entry.hook_id,
            pack_distribution_name=entry.pack_distribution_name,
            pack_distribution_version=entry.pack_distribution_version,
            outcome="refused",
            failure_mode="hook_policy_refused",
            policy_reason=reason,
            policy_input_digest=policy_input_digest,
            tenant_id=tenant_id,
            request_id=request_id,
            decision="refuse",
        )
        return HookDispatchResult(
            outcome="refused",
            final_payload=payload,
            failure_mode="hook_policy_refused",
            failed_hook_id=entry.hook_id,
            failed_pack_distribution_name=entry.pack_distribution_name,
            policy_reason=reason,
            policy_input_digest=policy_input_digest,
        )

    async def _route_exception(
        self,
        *,
        entry: HookEntry,
        phase: HookPhase,
        payload: bytes,
        exc: BaseException,
        policy_input_digest: str,
        tenant_id: str,
        request_id: str,
    ) -> HookDispatchResult:
        """Apply the fail-policy carve-out for a generic exception.

        Fail-open requires:
          * ``entry.fail_policy == "fail_open"``
          * ``entry.fail_open_exception`` is a non-empty string
          * the exception's class name (walked through
            ``type(exc).__mro__``, considering both ``__name__`` and
            ``__qualname__``) matches the declared name.

        If all three hold, treat as ``decision="pass"`` (chain
        continues with payload unchanged). Otherwise → ``hook_exception``
        fail-closed.
        """
        if (
            entry.fail_policy == "fail_open"
            and entry.fail_open_exception
            and self._exception_matches_declared(exc, entry.fail_open_exception)
        ):
            await self._maybe_emit_audit(
                event_type="hook.fail_open",
                phase=phase,
                hook_id=entry.hook_id,
                pack_distribution_name=entry.pack_distribution_name,
                pack_distribution_version=entry.pack_distribution_version,
                outcome="passed",
                failure_mode=None,
                policy_reason=None,
                policy_input_digest=policy_input_digest,
                tenant_id=tenant_id,
                request_id=request_id,
                decision="pass",
                exception_class=type(exc).__qualname__,
            )
            return HookDispatchResult(
                outcome="passed",
                final_payload=payload,
                failure_mode=None,
                failed_hook_id=None,
                failed_pack_distribution_name=None,
                policy_reason=None,
                policy_input_digest=policy_input_digest,
            )
        return await self._failure_result(
            entry=entry,
            phase=phase,
            payload=payload,
            failure_mode="hook_exception",
            policy_reason=None,
            policy_input_digest=policy_input_digest,
            tenant_id=tenant_id,
            request_id=request_id,
            exception_class=type(exc).__qualname__,
        )

    @staticmethod
    def _exception_matches_declared(exc: BaseException, declared_name: str) -> bool:
        """True if any class in ``type(exc).__mro__`` has either
        ``__name__`` or ``__qualname__`` equal to ``declared_name``.

        Walks the MRO so a subclass of the declared exception class
        also fail-opens (matches the Python ``except`` matching
        convention). Class-name match (NOT isinstance) keeps the
        dispatcher decoupled from importing the hook pack's exception
        classes.
        """
        for cls in type(exc).__mro__:
            if cls.__name__ == declared_name or cls.__qualname__ == declared_name:
                return True
        return False

    # --- failure / audit helpers --------------------------------------------

    async def _failure_result(
        self,
        *,
        entry: HookEntry,
        phase: HookPhase,
        payload: bytes,
        failure_mode: HookFailureMode,
        policy_reason: str | None,
        policy_input_digest: str,
        tenant_id: str,
        request_id: str,
        exception_class: str | None = None,
    ) -> HookDispatchResult:
        """Build a fail-closed :class:`HookDispatchResult` and emit
        the audit row. Centralises the failure-side construction so
        every fail-mode goes through the same audit shape."""
        await self._maybe_emit_audit(
            event_type="hook.failed",
            phase=phase,
            hook_id=entry.hook_id,
            pack_distribution_name=entry.pack_distribution_name,
            pack_distribution_version=entry.pack_distribution_version,
            outcome="failed",
            failure_mode=failure_mode,
            policy_reason=policy_reason,
            policy_input_digest=policy_input_digest,
            tenant_id=tenant_id,
            request_id=request_id,
            exception_class=exception_class,
        )
        return HookDispatchResult(
            outcome="failed",
            final_payload=payload,
            failure_mode=failure_mode,
            failed_hook_id=entry.hook_id,
            failed_pack_distribution_name=entry.pack_distribution_name,
            policy_reason=policy_reason,
            policy_input_digest=policy_input_digest,
        )

    async def _maybe_emit_audit(
        self,
        *,
        event_type: str,
        phase: HookPhase,
        hook_id: str | None,
        pack_distribution_name: str | None,
        pack_distribution_version: str | None,
        outcome: HookDispatchOutcome,
        failure_mode: HookFailureMode | None,
        policy_reason: str | None,
        policy_input_digest: str,
        tenant_id: str,
        request_id: str,
        decision: str | None = None,
        exception_class: str | None = None,
    ) -> None:
        """Build the token-free audit row dict and dispatch to the
        configured emitter. The dict carries IDs + closed-enum routing
        metadata + the SHA-256 digest — NEVER the payload bytes."""
        if self._audit_emitter is None:
            return
        row: dict[str, object] = {
            "event_type": event_type,
            "phase": phase,
            "hook_id": hook_id,
            "pack_distribution_name": pack_distribution_name,
            "pack_distribution_version": pack_distribution_version,
            "outcome": outcome,
            "failure_mode": failure_mode,
            "policy_reason": policy_reason,
            "policy_input_digest": policy_input_digest,
            "tenant_id": tenant_id,
            "request_id": request_id,
            "decision": decision,
            "exception_class": exception_class,
        }
        await self._audit_emitter(row)
