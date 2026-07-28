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

Six closed-enum failure modes (per Doctrine Lock E + ADR-028 R25):

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
  Fail-closed. Legacy DLP callers retain their established
  ``policy_reason`` propagation. Conversation callers suppress the
  hook-authored string from evidence and collapse the wire refusal to
  the kernel-owned ``conversation_hook_refused`` value.
* ``hook_payload_unscannable`` — Payload exceeded
  ``max_payload_bytes``. Fail-closed BEFORE invoking any hook.
  Bounds runtime risk against payloads too large to scan in time.
* ``hook_conversation_transformation_unsupported`` — A
  ``conversation_input`` / ``conversation_output`` hook returned
  ``redact`` or ``mask`` while F-S2a admits PASS/REFUSE only. The
  attempted envelope digest is evidenced, the original payload is
  retained, and the turn refuses. Legacy ``dlp_pre`` / ``dlp_post``
  transformations are unchanged. Conversation transformations remain
  deferred until F-S3 lands the hook-aware examiner projection and
  before/after digest continuity in the same slice.

**Payload-contents-never-logged invariant** (Doctrine Lock E): the
``payload`` argument is opaque bytes. The dispatcher computes
``hashlib.sha256(payload).hexdigest()`` once at dispatch entry for
the audit row's ``policy_input_digest`` field. Each decision row also
binds the actual per-hook before/after bytes through
``hook_input_digest`` / ``hook_output_digest`` so transformations are
evidenced without values on the legacy DLP phases and attempted conversation
transformations are evidenced before fail-closed refusal. Conversation-output
rows carry exactly one disjoint origin identity:
``output_origin="agent_run"`` with a real ``agent-run-*`` ID, or
``output_origin="approval_delivery"`` with an
``approval-delivery-<canonical UUID>`` ID. The dispatcher NEVER includes payload bytes
themselves in any audit / decision-history / log line / repr / str /
format / f-string. The companion AST regression
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
import uuid
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
    "passed",  # DLP may pass/transform; conversation phases pass unchanged
    "refused",  # a hook returned decision=refuse (legitimate policy refusal)
    "failed",  # technical failure, including unsupported conversation transform
]


#: Closed-enum failure-mode taxonomy from Doctrine Lock E + ADR-028 R25
#: (6 values).
#: ``None`` for ``outcome="passed"``; populated otherwise.
HookFailureMode = Literal[
    "hook_timeout",
    "hook_exception",
    "hook_malformed_result",
    "hook_policy_refused",
    "hook_payload_unscannable",
    "hook_conversation_transformation_unsupported",
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
TransformedPayloadValidator = Callable[[bytes], None]
EvidenceValueProjector = Callable[[bytes], bytes]


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
    on DLP ``passed``, the possibly redact/mask-transformed payload;
    on conversation-phase ``passed``, the byte-identical input payload;
    on ``refused`` / ``failed``, the LAST payload before the chain
    halted (no transformation by a halting hook).

    ``policy_input_digest`` is the SHA-256 hex digest of the
    **original** payload (never the transformed payload). The
    dispatcher computes this once at dispatch entry and propagates
    it to every audit row + the result envelope.

    ``hook_decision_count`` counts the correlated rows produced for this
    phase, including the one technical-failure row produced by a pre-loop
    payload-budget or required-nonempty refusal. A caller that persists this
    count as examiner correlation must inject a fail-loud ``audit_emitter``;
    ``build_hook_runtime`` does so on the production composition path.
    """

    outcome: HookDispatchOutcome
    final_payload: bytes
    failure_mode: HookFailureMode | None
    failed_hook_id: str | None
    failed_pack_distribution_name: str | None
    policy_reason: str | None
    policy_input_digest: str
    hook_decision_count: int = 0
    _evidence_output_value: bytes | None = dataclasses.field(
        default=None,
        repr=False,
        compare=False,
    )


class HookDispatchEvidenceError(RuntimeError):
    """Evidence failed after a prefix of hook decisions committed.

    Attributes carry only in-memory routing state. The exception message and
    repr never include payload bytes.
    """

    def __init__(self, *, final_payload: bytes, hook_decision_count: int) -> None:
        super().__init__("hook evidence emission failed")
        self.final_payload = final_payload
        self.hook_decision_count = hook_decision_count


class _HookEvidenceEmissionFailed(RuntimeError):
    """Internal marker distinguishing sink failure from hook failure."""


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

    @property
    def evidence_emission_configured(self) -> bool:
        """Whether successful dispatch can append its value-free evidence."""

        return self._audit_emitter is not None

    async def dispatch(
        self,
        *,
        phase: HookPhase,
        payload: bytes,
        context_template: HookContext,
        require_nonempty: bool = False,
        transformed_payload_validator: TransformedPayloadValidator | None = None,
        evidence_value_projector: EvidenceValueProjector | None = None,
        evidence_input_value: bytes | None = None,
    ) -> HookDispatchResult:
        """Run the deterministic hook chain for ``phase`` against
        ``payload``.

        ``context_template`` is the caller's invocation context with
        ``hook_id=""`` as a sentinel. The dispatcher fills ``hook_id``
        per-hook via :func:`dataclasses.replace`. Mismatched
        ``phase`` between the template and the dispatch argument
        raises :class:`ValueError` fail-fast (the call site is
        confused about which phase it's running).

        ``require_nonempty=True`` makes an empty phase chain fail closed as
        ``hook_exception``. Conversation boundaries use this posture because
        an absent safety chain must never become an implicit pass; legacy DLP
        callers retain the historical empty-chain pass by default.

        ``transformed_payload_validator`` is an optional caller-owned,
        schema-neutral callback applied to every redact/mask result before
        success evidence is emitted or the next hook sees it on legacy DLP
        phases. Conversation phases refuse transformations before this
        callback because F-S2a admits PASS/REFUSE only.

        ``evidence_value_projector`` is an optional caller-owned,
        schema-neutral projection from the governed envelope to the exact
        scalar bytes whose downstream continuity an examiner must verify.
        Conversation output supplies its UTF-8 ``answer`` projection. The
        dispatcher hashes those bytes before/after every successful hook and
        never emits the bytes themselves; phases without such a scalar leave
        the additive evidence fields null.

        ``evidence_input_value`` lets a caller bind the initial scalar without
        reparsing an over-ceiling envelope. Conversation output supplies the
        exact model/system UTF-8 bytes. It is carried only long enough to hash
        evidence and is never emitted or logged.

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
        if evidence_input_value is not None and evidence_value_projector is None:
            raise ValueError(
                "evidence_input_value requires evidence_value_projector for transformed hops"
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
                hook_input_digest=digest,
                hook_output_digest=digest,
                tenant_id=context_template.tenant_id,
                request_id=context_template.request_id,
                conversation_id=context_template.conversation_id,
                conversation_turn_seq=context_template.conversation_turn_seq,
                agent_run_id=context_template.agent_run_id,
                output_origin=context_template.output_origin,
                approval_delivery_id=context_template.approval_delivery_id,
                hook_input_value=evidence_input_value,
                hook_output_value=evidence_input_value,
            )
            return HookDispatchResult(
                outcome="failed",
                final_payload=payload,
                failure_mode="hook_payload_unscannable",
                failed_hook_id=None,
                failed_pack_distribution_name=None,
                policy_reason=None,
                policy_input_digest=digest,
                hook_decision_count=1,
            )

        # SNAPSHOT — single read. A self-registering hook cannot
        # extend this iteration target mid-dispatch.
        phase_hooks = self._registry.get_phase_hooks(phase)
        if require_nonempty and not phase_hooks:
            await self._maybe_emit_audit(
                event_type="hook.failed",
                phase=phase,
                hook_id=None,
                pack_distribution_name=None,
                pack_distribution_version=None,
                outcome="failed",
                failure_mode="hook_exception",
                policy_reason=None,
                policy_input_digest=digest,
                hook_input_digest=digest,
                hook_output_digest=digest,
                tenant_id=context_template.tenant_id,
                request_id=context_template.request_id,
                conversation_id=context_template.conversation_id,
                conversation_turn_seq=context_template.conversation_turn_seq,
                agent_run_id=context_template.agent_run_id,
                output_origin=context_template.output_origin,
                approval_delivery_id=context_template.approval_delivery_id,
                hook_input_value=evidence_input_value,
                hook_output_value=evidence_input_value,
            )
            return HookDispatchResult(
                outcome="failed",
                final_payload=payload,
                failure_mode="hook_exception",
                failed_hook_id=None,
                failed_pack_distribution_name=None,
                policy_reason=None,
                policy_input_digest=digest,
                hook_decision_count=1,
            )

        current_payload = payload
        current_evidence_value = evidence_input_value
        hook_decision_count = 0
        for entry in phase_hooks:
            try:
                outcome = await self._invoke_one(
                    entry=entry,
                    phase=phase,
                    payload=current_payload,
                    context_template=context_template,
                    policy_input_digest=digest,
                    transformed_payload_validator=transformed_payload_validator,
                    evidence_value_projector=evidence_value_projector,
                    evidence_input_value=current_evidence_value,
                )
            except _HookEvidenceEmissionFailed as exc:
                raise HookDispatchEvidenceError(
                    final_payload=current_payload,
                    hook_decision_count=hook_decision_count,
                ) from exc
            # With a configured emitter, a returned outcome means the
            # fail-loud evidence append for this hook completed. The
            # conversation adapter refuses dispatchers without an emitter and
            # persists this exact count, so a deleted identity/pass row cannot
            # be hidden merely because its before/after digests were equal.
            hook_decision_count += 1

            if outcome.outcome == "passed":
                # Legacy DLP passes may transform. Conversation-phase passes
                # are byte-identical because F-S2a rejects redact/mask.
                current_payload = outcome.final_payload
                current_evidence_value = outcome._evidence_output_value
                continue

            # Halt on the first non-pass outcome — refuse / fail propagate.
            return dataclasses.replace(
                outcome,
                hook_decision_count=hook_decision_count,
                _evidence_output_value=None,
            )

        # Every hook completed: DLP may pass/redact/mask; conversation hooks
        # all passed without transformation.
        return HookDispatchResult(
            outcome="passed",
            final_payload=current_payload,
            failure_mode=None,
            failed_hook_id=None,
            failed_pack_distribution_name=None,
            policy_reason=None,
            policy_input_digest=digest,
            hook_decision_count=hook_decision_count,
        )

    def phase_timeout_budget_s(self, phase: HookPhase) -> float:
        """Return the admitted invocation-timeout sum for one phase.

        Registry construction is complete before the dispatcher is exposed by
        the composition root, so this snapshot is stable for the dispatcher's
        lifetime. The sum is exact for the declared hook invocation windows,
        with each declaration clamped by the runtime ceiling.
        """

        return sum(
            (
                min(entry.timeout_seconds, self._max_timeout_seconds_runtime)
                for entry in self._registry.get_phase_hooks(phase)
            ),
            start=0.0,
        )

    def has_phase_hooks(self, phase: HookPhase) -> bool:
        """Whether the immutable registry snapshot admits this phase."""

        return bool(self._registry.get_phase_hooks(phase))

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
                hook_input_digest=digest,
                hook_output_digest=digest,
                tenant_id=context_template.tenant_id,
                request_id=context_template.request_id,
                conversation_id=context_template.conversation_id,
                conversation_turn_seq=context_template.conversation_turn_seq,
                agent_run_id=context_template.agent_run_id,
                output_origin=context_template.output_origin,
                approval_delivery_id=context_template.approval_delivery_id,
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
        hook_decision_count = 0
        for entry in resolved_entries:
            outcome = await self._invoke_one(
                entry=entry,
                phase=phase,
                payload=current_payload,
                context_template=context_template,
                policy_input_digest=digest,
                transformed_payload_validator=None,
                evidence_value_projector=None,
                evidence_input_value=None,
            )
            hook_decision_count += 1
            if outcome.outcome == "passed":
                # Successful pass — possibly with payload transformation.
                current_payload = outcome.final_payload
                continue
            # Halt on the first non-pass outcome — refuse / fail propagate.
            return dataclasses.replace(outcome, hook_decision_count=hook_decision_count)

        # Every declared hook returned pass / redact / mask; chain completed.
        return HookDispatchResult(
            outcome="passed",
            final_payload=current_payload,
            failure_mode=None,
            failed_hook_id=None,
            failed_pack_distribution_name=None,
            policy_reason=None,
            policy_input_digest=digest,
            hook_decision_count=hook_decision_count,
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
        transformed_payload_validator: TransformedPayloadValidator | None,
        evidence_value_projector: EvidenceValueProjector | None,
        evidence_input_value: bytes | None,
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
                    conversation_id=context_template.conversation_id,
                    conversation_turn_seq=context_template.conversation_turn_seq,
                    agent_run_id=context_template.agent_run_id,
                    output_origin=context_template.output_origin,
                    approval_delivery_id=context_template.approval_delivery_id,
                    evidence_input_value=evidence_input_value,
                )
            # The signed declaration is the authority for runtime identity.
            # A loadable Hook subclass with different class metadata is a
            # mispackaged (or substituted) implementation, not permission to
            # execute under the declaration's hook_id / phase in evidence.
            if hook_cls.hook_id != entry.hook_id or hook_cls.phase != phase:
                return await self._failure_result(
                    entry=entry,
                    phase=phase,
                    payload=payload,
                    failure_mode="hook_malformed_result",
                    policy_reason=None,
                    policy_input_digest=policy_input_digest,
                    tenant_id=context_template.tenant_id,
                    request_id=context_template.request_id,
                    conversation_id=context_template.conversation_id,
                    conversation_turn_seq=context_template.conversation_turn_seq,
                    agent_run_id=context_template.agent_run_id,
                    output_origin=context_template.output_origin,
                    approval_delivery_id=context_template.approval_delivery_id,
                    evidence_input_value=evidence_input_value,
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
                conversation_id=context_template.conversation_id,
                conversation_turn_seq=context_template.conversation_turn_seq,
                agent_run_id=context_template.agent_run_id,
                output_origin=context_template.output_origin,
                approval_delivery_id=context_template.approval_delivery_id,
                evidence_input_value=evidence_input_value,
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
                conversation_id=context_template.conversation_id,
                conversation_turn_seq=context_template.conversation_turn_seq,
                agent_run_id=context_template.agent_run_id,
                output_origin=context_template.output_origin,
                approval_delivery_id=context_template.approval_delivery_id,
                evidence_value_projector=evidence_value_projector,
                evidence_input_value=evidence_input_value,
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
                conversation_id=context_template.conversation_id,
                conversation_turn_seq=context_template.conversation_turn_seq,
                agent_run_id=context_template.agent_run_id,
                output_origin=context_template.output_origin,
                approval_delivery_id=context_template.approval_delivery_id,
                evidence_input_value=evidence_input_value,
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
                conversation_id=context_template.conversation_id,
                conversation_turn_seq=context_template.conversation_turn_seq,
                agent_run_id=context_template.agent_run_id,
                output_origin=context_template.output_origin,
                approval_delivery_id=context_template.approval_delivery_id,
                evidence_input_value=evidence_input_value,
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
                conversation_id=context_template.conversation_id,
                conversation_turn_seq=context_template.conversation_turn_seq,
                agent_run_id=context_template.agent_run_id,
                output_origin=context_template.output_origin,
                approval_delivery_id=context_template.approval_delivery_id,
                evidence_value_projector=evidence_value_projector,
                evidence_input_value=evidence_input_value,
            )

        # Decision routing — refuse halts; pass continues; redact/mask
        # continue only for DLP and fail closed for conversation phases.
        return await self._route_decision(
            entry=entry,
            phase=phase,
            payload=payload,
            result=result,
            policy_input_digest=policy_input_digest,
            tenant_id=context_template.tenant_id,
            request_id=context_template.request_id,
            conversation_id=context_template.conversation_id,
            conversation_turn_seq=context_template.conversation_turn_seq,
            agent_run_id=context_template.agent_run_id,
            output_origin=context_template.output_origin,
            approval_delivery_id=context_template.approval_delivery_id,
            transformed_payload_validator=transformed_payload_validator,
            evidence_value_projector=evidence_value_projector,
            evidence_input_value=evidence_input_value,
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
        conversation_id: str | None,
        conversation_turn_seq: int | None,
        agent_run_id: str | None,
        output_origin: Literal["agent_run", "approval_delivery"] | None,
        approval_delivery_id: str | None,
        transformed_payload_validator: TransformedPayloadValidator | None,
        evidence_value_projector: EvidenceValueProjector | None,
        evidence_input_value: bytes | None,
    ) -> HookDispatchResult:
        """Map a successfully-returned :class:`HookResult` to a
        :class:`HookDispatchResult`. The SDK seam already validated
        the decision-↔-fields invariant; this routing trusts the
        result shape."""
        decision = result.decision

        try:
            input_value = evidence_input_value
            if input_value is None and evidence_value_projector is not None:
                input_value = evidence_value_projector(payload)
        except Exception:
            return await self._failure_result(
                entry=entry,
                phase=phase,
                payload=payload,
                failure_mode="hook_malformed_result",
                policy_reason=None,
                policy_input_digest=policy_input_digest,
                tenant_id=tenant_id,
                request_id=request_id,
                conversation_id=conversation_id,
                conversation_turn_seq=conversation_turn_seq,
                agent_run_id=agent_run_id,
                output_origin=output_origin,
                approval_delivery_id=approval_delivery_id,
                evidence_input_value=evidence_input_value,
            )

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
                hook_input_digest=hashlib.sha256(payload).hexdigest(),
                hook_output_digest=hashlib.sha256(payload).hexdigest(),
                tenant_id=tenant_id,
                request_id=request_id,
                conversation_id=conversation_id,
                conversation_turn_seq=conversation_turn_seq,
                agent_run_id=agent_run_id,
                output_origin=output_origin,
                approval_delivery_id=approval_delivery_id,
                decision="pass",
                hook_input_value=input_value,
                hook_output_value=input_value,
            )
            return HookDispatchResult(
                outcome="passed",
                final_payload=payload,
                failure_mode=None,
                failed_hook_id=None,
                failed_pack_distribution_name=None,
                policy_reason=None,
                policy_input_digest=policy_input_digest,
                _evidence_output_value=input_value,
            )

        if decision in ("redact", "mask"):
            # SDK seam pinned that redacted_payload is bytes for
            # redact/mask; mypy narrowing requires the explicit check.
            new_payload = result.redacted_payload
            assert isinstance(new_payload, bytes)
            if phase in ("conversation_input", "conversation_output"):
                # R25: conversation phases are PASS/REFUSE-only in F-S2a.
                # Evidence the attempted envelope digest but retain the
                # original payload; F-S3 owns transformation together with
                # hook-aware examiner projection + scalar digest continuity.
                return await self._failure_result(
                    entry=entry,
                    phase=phase,
                    payload=payload,
                    failure_mode="hook_conversation_transformation_unsupported",
                    policy_reason=None,
                    policy_input_digest=policy_input_digest,
                    tenant_id=tenant_id,
                    request_id=request_id,
                    conversation_id=conversation_id,
                    conversation_turn_seq=conversation_turn_seq,
                    agent_run_id=agent_run_id,
                    output_origin=output_origin,
                    approval_delivery_id=approval_delivery_id,
                    hook_output_payload=new_payload,
                    evidence_input_value=input_value,
                )
            if transformed_payload_validator is not None:
                try:
                    transformed_payload_validator(new_payload)
                except Exception:
                    # Caller-owned structural validation is part of the hook
                    # result contract. Refuse before success evidence or the
                    # next hook can observe a temporarily forged envelope.
                    return await self._failure_result(
                        entry=entry,
                        phase=phase,
                        payload=payload,
                        failure_mode="hook_malformed_result",
                        policy_reason=None,
                        policy_input_digest=policy_input_digest,
                        tenant_id=tenant_id,
                        request_id=request_id,
                        conversation_id=conversation_id,
                        conversation_turn_seq=conversation_turn_seq,
                        agent_run_id=agent_run_id,
                        output_origin=output_origin,
                        approval_delivery_id=approval_delivery_id,
                        hook_output_payload=new_payload,
                        evidence_input_value=input_value,
                    )
            try:
                output_value = (
                    evidence_value_projector(new_payload)
                    if evidence_value_projector is not None
                    else None
                )
            except Exception:
                return await self._failure_result(
                    entry=entry,
                    phase=phase,
                    payload=payload,
                    failure_mode="hook_malformed_result",
                    policy_reason=None,
                    policy_input_digest=policy_input_digest,
                    tenant_id=tenant_id,
                    request_id=request_id,
                    conversation_id=conversation_id,
                    conversation_turn_seq=conversation_turn_seq,
                    agent_run_id=agent_run_id,
                    output_origin=output_origin,
                    approval_delivery_id=approval_delivery_id,
                    hook_output_payload=new_payload,
                    evidence_input_value=input_value,
                )
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
                hook_input_digest=hashlib.sha256(payload).hexdigest(),
                hook_output_digest=hashlib.sha256(new_payload).hexdigest(),
                tenant_id=tenant_id,
                request_id=request_id,
                conversation_id=conversation_id,
                conversation_turn_seq=conversation_turn_seq,
                agent_run_id=agent_run_id,
                output_origin=output_origin,
                approval_delivery_id=approval_delivery_id,
                decision=decision,
                hook_input_value=input_value,
                hook_output_value=output_value,
            )
            return HookDispatchResult(
                outcome="passed",
                final_payload=new_payload,
                failure_mode=None,
                failed_hook_id=None,
                failed_pack_distribution_name=None,
                policy_reason=None,
                policy_input_digest=policy_input_digest,
                _evidence_output_value=output_value,
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
            hook_input_digest=hashlib.sha256(payload).hexdigest(),
            hook_output_digest=hashlib.sha256(payload).hexdigest(),
            tenant_id=tenant_id,
            request_id=request_id,
            conversation_id=conversation_id,
            conversation_turn_seq=conversation_turn_seq,
            agent_run_id=agent_run_id,
            output_origin=output_origin,
            approval_delivery_id=approval_delivery_id,
            decision="refuse",
            hook_input_value=input_value,
            hook_output_value=input_value,
        )
        return HookDispatchResult(
            outcome="refused",
            final_payload=payload,
            failure_mode="hook_policy_refused",
            failed_hook_id=entry.hook_id,
            failed_pack_distribution_name=entry.pack_distribution_name,
            policy_reason=reason,
            policy_input_digest=policy_input_digest,
            _evidence_output_value=input_value,
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
        conversation_id: str | None,
        conversation_turn_seq: int | None,
        agent_run_id: str | None,
        output_origin: Literal["agent_run", "approval_delivery"] | None,
        approval_delivery_id: str | None,
        evidence_value_projector: EvidenceValueProjector | None,
        evidence_input_value: bytes | None,
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
            try:
                value = evidence_input_value
                if value is None and evidence_value_projector is not None:
                    value = evidence_value_projector(payload)
            except Exception:
                return await self._failure_result(
                    entry=entry,
                    phase=phase,
                    payload=payload,
                    failure_mode="hook_malformed_result",
                    policy_reason=None,
                    policy_input_digest=policy_input_digest,
                    tenant_id=tenant_id,
                    request_id=request_id,
                    conversation_id=conversation_id,
                    conversation_turn_seq=conversation_turn_seq,
                    agent_run_id=agent_run_id,
                    output_origin=output_origin,
                    approval_delivery_id=approval_delivery_id,
                    evidence_input_value=evidence_input_value,
                )
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
                hook_input_digest=hashlib.sha256(payload).hexdigest(),
                hook_output_digest=hashlib.sha256(payload).hexdigest(),
                tenant_id=tenant_id,
                request_id=request_id,
                conversation_id=conversation_id,
                conversation_turn_seq=conversation_turn_seq,
                agent_run_id=agent_run_id,
                output_origin=output_origin,
                approval_delivery_id=approval_delivery_id,
                decision="pass",
                exception_class=type(exc).__qualname__,
                hook_input_value=value,
                hook_output_value=value,
            )
            return HookDispatchResult(
                outcome="passed",
                final_payload=payload,
                failure_mode=None,
                failed_hook_id=None,
                failed_pack_distribution_name=None,
                policy_reason=None,
                policy_input_digest=policy_input_digest,
                _evidence_output_value=value,
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
            conversation_id=conversation_id,
            conversation_turn_seq=conversation_turn_seq,
            agent_run_id=agent_run_id,
            output_origin=output_origin,
            approval_delivery_id=approval_delivery_id,
            exception_class=type(exc).__qualname__,
            evidence_input_value=evidence_input_value,
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
        conversation_id: str | None,
        conversation_turn_seq: int | None,
        agent_run_id: str | None,
        output_origin: Literal["agent_run", "approval_delivery"] | None = None,
        approval_delivery_id: str | None = None,
        exception_class: str | None = None,
        hook_output_payload: bytes | None = None,
        evidence_input_value: bytes | None = None,
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
            hook_input_digest=hashlib.sha256(payload).hexdigest(),
            hook_output_digest=hashlib.sha256(
                payload if hook_output_payload is None else hook_output_payload
            ).hexdigest(),
            tenant_id=tenant_id,
            request_id=request_id,
            conversation_id=conversation_id,
            conversation_turn_seq=conversation_turn_seq,
            agent_run_id=agent_run_id,
            output_origin=output_origin,
            approval_delivery_id=approval_delivery_id,
            exception_class=exception_class,
            hook_input_value=evidence_input_value,
            hook_output_value=evidence_input_value,
        )
        return HookDispatchResult(
            outcome="failed",
            final_payload=payload,
            failure_mode=failure_mode,
            failed_hook_id=entry.hook_id,
            failed_pack_distribution_name=entry.pack_distribution_name,
            policy_reason=policy_reason,
            policy_input_digest=policy_input_digest,
            _evidence_output_value=evidence_input_value,
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
        hook_input_digest: str,
        hook_output_digest: str,
        tenant_id: str,
        request_id: str,
        conversation_id: str | None,
        conversation_turn_seq: int | None,
        agent_run_id: str | None,
        output_origin: Literal["agent_run", "approval_delivery"] | None = None,
        approval_delivery_id: str | None = None,
        decision: str | None = None,
        exception_class: str | None = None,
        hook_input_value: bytes | None = None,
        hook_output_value: bytes | None = None,
    ) -> None:
        """Build the token-free audit row dict and dispatch to the
        configured emitter. The dict carries IDs + closed-enum routing
        metadata + original/per-hook SHA-256 digests — NEVER payload bytes."""
        if self._audit_emitter is None:
            return
        if phase in ("conversation_input", "conversation_output"):
            try:
                parsed_conversation_id = uuid.UUID(conversation_id or "")
            except (AttributeError, TypeError, ValueError) as exc:
                raise ValueError(
                    "conversation hook evidence requires a canonical conversation_id"
                ) from exc
            if str(parsed_conversation_id) != conversation_id or (
                isinstance(conversation_turn_seq, bool)
                or not isinstance(conversation_turn_seq, int)
                or conversation_turn_seq <= 0
            ):
                raise ValueError("conversation hook evidence requires canonical turn correlation")
        elif conversation_id is not None or conversation_turn_seq is not None:
            raise ValueError("non-conversation hook evidence cannot carry turn correlation")
        if phase == "conversation_output":
            if output_origin == "agent_run":
                if (
                    not isinstance(agent_run_id, str)
                    or not agent_run_id.startswith("agent-run-")
                    or agent_run_id == "agent-run-"
                    or approval_delivery_id is not None
                ):
                    raise ValueError("agent_run hook evidence correlation is malformed")
            elif output_origin == "approval_delivery":
                prefix = "approval-delivery-"
                raw_id = approval_delivery_id
                try:
                    parsed_delivery_id = uuid.UUID(
                        raw_id[len(prefix) :]
                        if isinstance(raw_id, str) and raw_id.startswith(prefix)
                        else ""
                    )
                except ValueError as exc:
                    raise ValueError(
                        "approval_delivery hook evidence correlation is malformed"
                    ) from exc
                if raw_id != prefix + str(parsed_delivery_id) or agent_run_id is not None:
                    raise ValueError("approval_delivery hook evidence correlation is malformed")
            else:
                raise ValueError("conversation output hook evidence requires output_origin")
        elif output_origin is not None or approval_delivery_id is not None:
            raise ValueError("non-output hook evidence cannot carry output identity")
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
            "hook_input_digest": hook_input_digest,
            "hook_output_digest": hook_output_digest,
            "tenant_id": tenant_id,
            "request_id": request_id,
            "decision": decision,
            "exception_class": exception_class,
            "hook_input_value_sha256": (
                hashlib.sha256(hook_input_value).hexdigest()
                if hook_input_value is not None
                else None
            ),
            "hook_output_value_sha256": (
                hashlib.sha256(hook_output_value).hexdigest()
                if hook_output_value is not None
                else None
            ),
        }
        if phase in ("conversation_input", "conversation_output"):
            assert conversation_id is not None
            assert conversation_turn_seq is not None
            row["conversation_id"] = conversation_id
            row["conversation_turn_seq"] = conversation_turn_seq
            if phase == "conversation_output":
                row["output_origin"] = output_origin
                row["agent_run_id"] = agent_run_id
                row["approval_delivery_id"] = approval_delivery_id
        if phase in ("conversation_input", "conversation_output"):
            # Pack-controlled strings can themselves encode screened content:
            # a refusal can echo it through ``policy_reason`` and a hook can
            # dynamically name an exception class from it. Conversation
            # evidence is value-free, so retain only closed dispatcher
            # vocabulary, signed hook identity, correlation, and digests.
            row["policy_reason"] = None
            row["exception_class"] = None
        try:
            await self._audit_emitter(row)
        except Exception as exc:
            raise _HookEvidenceEmissionFailed from exc
