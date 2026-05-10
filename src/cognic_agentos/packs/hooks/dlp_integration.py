"""Sprint-7A2 T8 — runtime DLP scan adapter.

Per ADR-017 line 97 ("pack manifest names which hooks must run; AgentOS
resolves them via the plugin registry"). :class:`DLPGuard` adapts the
generic :class:`HookDispatcher` runtime engine (T7) to the data-
governance pre/post phase semantics ADR-017 specifies, with per-pack
hook selection driven by the calling pack's manifest declarations.

Per-pack selector semantics — ONLY hooks named in the calling pack's
``[data_governance].dlp_pre_hooks`` / ``dlp_post_hooks`` run for that
pack's invocations. Other hooks registered under the same phase but
NOT in the calling pack's declarations do not run for this pack. Order
within the selected subset is dispatcher-canonical (``ordering_rank``
ascending; ties by ``hook_id`` alphabetic — the rank table at
``cli/_governance_vocab.HOOK_ORDERING_RANK``); manifest declaration
order does NOT control runtime order.

Closed-enum :class:`DLPRefusalReason` (3 values per Doctrine Lock E +
Sprint-7A2 T8 lock):

* ``dlp_hook_id_unresolved`` — a declared ``hook_id`` does not resolve
  to a registered hook for the requested phase. The dispatcher's
  ``dispatch_for_pack`` raises :class:`HookDispatchSelectionError`
  AFTER the budget check passes; DLPGuard catches that exception and
  routes it to this terminus. Audit row emitted via the optional
  ``audit_emitter``.
* ``dlp_dispatcher_failed`` — the dispatcher returned ``outcome="failed"``
  (timeout / exception / malformed result / payload-unscannable). The
  underlying :data:`HookFailureMode` propagates via
  :attr:`DLPGuardOutcome.underlying_failure_mode` for the calling-pack
  refusal envelope.
* ``dlp_dispatcher_refused`` — the dispatcher returned ``outcome="refused"``
  (legitimate ``hook_policy_refused`` from a hook that returned
  ``decision="refuse"``). The hook's policy reason propagates via
  :attr:`DLPGuardOutcome.underlying_policy_reason`.

Step order — DLPGuard delegates first to preserve dispatcher precedence
(T8 R1 P2-2 fix):

  1. Caller-input validation (phase agreement + hook_id sentinel).
  2. Delegate to :meth:`HookDispatcher.dispatch_for_pack`. The
     dispatcher does the payload-budget check FIRST (before lookup),
     so an oversized payload + unknown hook_id correctly returns
     ``dlp_dispatcher_failed`` / ``hook_payload_unscannable`` rather
     than ``dlp_hook_id_unresolved``.
  3. Catch :class:`HookDispatchSelectionError` (raised when an
     unknown hook_id is encountered AFTER the budget check) and
     route to the ``dlp_hook_id_unresolved`` terminus. The exception
     carries the offending ``hook_id`` + ``phase`` as structured
     attributes so the audit row + ``DLPGuardOutcome.failed_hook_id``
     populate without re-parsing the message.
  4. Translate the dispatcher's :class:`HookDispatchResult` to a
     :class:`DLPGuardOutcome`.

DLPGuard does NOT pre-validate hook_id resolution against the
registry; an earlier R0 draft did so, but R1 P2-2 review caught that
the pre-validation pass ran lookup BEFORE the dispatcher's budget
check, inverting precedence. Removing the pre-validation step keeps
the dispatcher as the single source of truth for precedence
ordering.

Payload-contents-never-logged invariant (Doctrine Lock E): the
``payload`` argument is opaque bytes. DLPGuard inherits the
dispatcher's ``policy_input_digest`` (sha256 of the original payload)
and never includes raw payload bytes in audit rows / logs / repr / str
/ format / f-strings. Pinned by the AST-walk regression at
``tests/architecture/test_hook_payload_never_logged.py`` extending in
T8 to cover this module.

Critical-controls promotion: this module joins the gate at T12 closeout
alongside ``packs/hooks/registry.py``, ``packs/hooks/dispatcher.py``,
and ``cli/validators/hooks.py``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Final, Literal

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.packs.hooks.dispatcher import (
    HookDispatcher,
    HookDispatchSelectionError,
    HookFailureMode,
)
from cognic_agentos.sdk.hook import HookContext

__all__ = [
    "AuditEmitter",
    "DLPGuard",
    "DLPGuardOutcome",
    "DLPRefusalReason",
]


#: Closed-enum DLP refusal taxonomy (3 values per Sprint-7A2 T8 +
#: Doctrine Lock E). Adding a value forces doctrine review — pinned via
#: ``typing.get_args`` regression in
#: ``tests/unit/packs/hooks/test_dlp_hook_integration.py``.
DLPRefusalReason = Literal[
    "dlp_hook_id_unresolved",
    "dlp_dispatcher_failed",
    "dlp_dispatcher_refused",
]


#: Audit-row callback the calling-pack invocation surface (Sprint-7B
#: integration) wires to the AuditStore + DecisionHistoryStore. Wave-1
#: optional (no-op when None).
AuditEmitter = Callable[[dict[str, object]], Awaitable[None]]


# ---------------------------------------------------------------------------
# DLPGuardOutcome — frozen + slotted wire-shape
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DLPGuardOutcome:
    """Result of a single :meth:`DLPGuard.scan_pre` /
    :meth:`DLPGuard.scan_post` call.

    ``outcome`` is the binary decision the calling-pack invocation
    surface routes on:

    * ``"passed"`` — every declared hook returned pass / redact / mask;
      ``final_payload`` carries the (possibly transformed) payload to
      forward to the pack code (``scan_pre``) or to the caller
      (``scan_post``).
    * ``"refused"`` — at least one declared hook refused, or the
      dispatcher failed, or a declared ``hook_id`` did not resolve.
      ``refusal_reason`` is the closed-enum routing surface;
      ``underlying_failure_mode`` + ``underlying_policy_reason``
      carry the dispatcher-level detail.

    ``policy_input_digest`` is the sha256 hex digest of the **original**
    payload (never the transformed payload). Computed once by the
    dispatcher and propagated for audit-row correlation.
    """

    outcome: Literal["passed", "refused"]
    """Binary decision — calling-pack invocation routes on this."""

    final_payload: bytes
    """For ``passed``: the (possibly transformed) payload to forward.
    For ``refused``: the ORIGINAL payload (no transformation by a
    halting hook)."""

    refusal_reason: DLPRefusalReason | None
    """Closed-enum DLP refusal reason; None for ``passed``."""

    underlying_failure_mode: HookFailureMode | None
    """Dispatcher-level failure mode (when ``refusal_reason`` is
    ``dlp_dispatcher_failed`` or ``dlp_dispatcher_refused``); None
    for ``dlp_hook_id_unresolved`` and ``passed``."""

    underlying_policy_reason: str | None
    """Hook's policy_reason for ``dlp_dispatcher_refused``; None
    otherwise."""

    failed_hook_id: str | None
    """The hook_id that triggered the refusal (when refused due to
    a specific hook); None for ``dlp_hook_id_unresolved`` and
    ``passed``."""

    failed_pack_distribution_name: str | None
    """The hook pack distribution that owns ``failed_hook_id``; None
    for ``dlp_hook_id_unresolved`` and ``passed``."""

    policy_input_digest: str
    """sha256 hex of the ORIGINAL payload — never the transformed
    payload. Propagates from the dispatcher for audit-row
    correlation."""


# ---------------------------------------------------------------------------
# DLPGuard
# ---------------------------------------------------------------------------


class DLPGuard:
    """Runtime DLP scan adapter — per-pack selector over the dispatcher.

    Constructed with a :class:`HookDispatcher` (which already holds a
    reference to the verified-pack registry; DLPGuard delegates ALL
    registry reads through the dispatcher to preserve the budget-
    check-before-lookup precedence) + an optional :data:`AuditEmitter`
    callback for refusal-path audit rows.

    T8 R1 P2-2 fix: DLPGuard does NOT take a separate ``registry``
    argument. An earlier draft pre-validated hook_id resolution
    against ``registry.snapshot()`` BEFORE delegating, but that
    bypassed the dispatcher's payload-budget check (the dispatcher
    runs budget BEFORE lookup; DLPGuard's pre-validation ran lookup
    BEFORE budget). Removing the pre-validation step preserves the
    dispatcher's precedence: an oversized payload + unknown hook_id
    correctly returns ``dlp_dispatcher_failed`` /
    ``hook_payload_unscannable`` rather than ``dlp_hook_id_unresolved``.
    """

    def __init__(
        self,
        *,
        dispatcher: HookDispatcher,
        audit_emitter: AuditEmitter | None = None,
    ) -> None:
        self._dispatcher: Final[HookDispatcher] = dispatcher
        self._audit_emitter: Final[AuditEmitter | None] = audit_emitter

    async def scan_pre(
        self,
        *,
        payload: bytes,
        declared_hook_ids: Sequence[str],
        context_template: HookContext,
    ) -> DLPGuardOutcome:
        """Run the calling pack's declared ``dlp_pre`` hooks against
        ``payload`` BEFORE the pack code sees it.

        Per ADR-017 ("Pre-invocation: DLP pre-hooks run (PII redaction,
        etc.)"). ``declared_hook_ids`` is the calling pack's manifest's
        ``[data_governance].dlp_pre_hooks`` array. Empty array is a
        legitimate "no DLP scan" declaration — returns
        ``outcome="passed"`` with the payload unchanged.

        See :class:`DLPGuard` and :class:`DLPGuardOutcome` for the
        contract.
        """
        return await self._scan(
            phase="dlp_pre",
            payload=payload,
            declared_hook_ids=declared_hook_ids,
            context_template=context_template,
        )

    async def scan_post(
        self,
        *,
        payload: bytes,
        declared_hook_ids: Sequence[str],
        context_template: HookContext,
    ) -> DLPGuardOutcome:
        """Run the calling pack's declared ``dlp_post`` hooks against
        ``payload`` BEFORE the output reaches the caller.

        Per ADR-017 ("Post-invocation: DLP post-hooks run (masking,
        redaction). Output reaches the caller only after hooks
        complete.") Mirror of :meth:`scan_pre` for the post phase.
        """
        return await self._scan(
            phase="dlp_post",
            payload=payload,
            declared_hook_ids=declared_hook_ids,
            context_template=context_template,
        )

    # --- private ------------------------------------------------------------

    async def _scan(
        self,
        *,
        phase: HookPhase,
        payload: bytes,
        declared_hook_ids: Sequence[str],
        context_template: HookContext,
    ) -> DLPGuardOutcome:
        """Shared body for :meth:`scan_pre` / :meth:`scan_post`.

        Step order — DLPGuard delegates ALL precedence decisions
        (payload-budget vs hook_id resolution) to
        :meth:`HookDispatcher.dispatch_for_pack` so the dispatcher's
        budget-check-before-lookup ordering is preserved. T8 R1 fix:
        an oversized payload + unknown hook_id MUST return
        ``dlp_dispatcher_failed`` / ``hook_payload_unscannable``
        (correct precedence), NOT ``dlp_hook_id_unresolved``.

          1. Caller-input validation (phase agreement + hook_id
             sentinel) — fail-fast :class:`ValueError` mirroring the
             dispatcher's contract.
          2. Delegate to ``dispatch_for_pack``. The dispatcher does:
             budget check → snapshot → resolve declared_hook_ids
             (silently dedupes) → dispatch. An unresolved id raises
             :class:`HookDispatchSelectionError`; an oversized payload
             returns ``failed/hook_payload_unscannable`` BEFORE the
             lookup runs.
          3. Catch :class:`HookDispatchSelectionError` and route to
             ``dlp_hook_id_unresolved`` (audit + refused outcome).
             The catch fires only when the dispatcher's resolution
             step was actually reached — i.e., the budget check
             passed.
          4. Translate the dispatcher's :class:`HookDispatchResult`
             to a :class:`DLPGuardOutcome`:

               * ``passed`` → ``outcome="passed"`` with the
                 dispatcher's (possibly transformed) ``final_payload``.
               * ``refused`` → ``outcome="refused"`` with
                 ``refusal_reason="dlp_dispatcher_refused"`` and
                 ``final_payload`` set to the **ORIGINAL** payload
                 (NOT ``dispatch_result.final_payload``, which may be
                 a partially-transformed last-seen payload from an
                 earlier redact hook). T8 R1 P2-1 fix.
               * ``failed`` → ``outcome="refused"`` with
                 ``refusal_reason="dlp_dispatcher_failed"`` and
                 ``final_payload`` set to the **ORIGINAL** payload.
        """
        # Step 1: caller-input validation. Mirrors dispatcher's contract;
        # apply at the DLPGuard boundary too so callers get a uniform
        # signal regardless of which adapter they use.
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
                + ") does not match scan phase ("
                + repr(phase)
                + "); caller is confused about which phase to run."
            )

        # Step 2: delegate to the dispatcher. The dispatcher does the
        # budget check FIRST (before lookup), so an oversized payload
        # with an unknown hook_id correctly returns failed/
        # hook_payload_unscannable — NOT a hook_id_unresolved
        # raise. T8 R1 P2-2 fix preserves this precedence by removing
        # DLPGuard's own pre-validation pass.
        try:
            dispatch_result = await self._dispatcher.dispatch_for_pack(
                phase=phase,
                declared_hook_ids=declared_hook_ids,
                payload=payload,
                context_template=context_template,
            )
        except HookDispatchSelectionError as exc:
            # Step 3: unresolved hook_id terminus. The dispatcher's
            # budget check already passed (lookup wouldn't have been
            # reached otherwise) — so this is exclusively the
            # "hook_id named in manifest is not registered" case.
            digest = hashlib.sha256(payload).hexdigest()
            unresolved_hook_id = exc.hook_id
            await self._maybe_emit_refusal_audit(
                phase=phase,
                refusal_reason="dlp_hook_id_unresolved",
                underlying_failure_mode=None,
                underlying_policy_reason=None,
                failed_hook_id=unresolved_hook_id,
                failed_pack_distribution_name=None,
                policy_input_digest=digest,
                tenant_id=context_template.tenant_id,
                request_id=context_template.request_id,
            )
            return DLPGuardOutcome(
                outcome="refused",
                final_payload=payload,
                refusal_reason="dlp_hook_id_unresolved",
                underlying_failure_mode=None,
                underlying_policy_reason=None,
                failed_hook_id=unresolved_hook_id,
                failed_pack_distribution_name=None,
                policy_input_digest=digest,
            )

        # Step 4: translate the dispatcher result.
        if dispatch_result.outcome == "passed":
            # Happy path. No DLPGuard-level audit emission — the
            # dispatcher's per-hook emitter (Sprint-7B integration)
            # carries the per-hook audit; DLPGuard emits ONLY on
            # refusal paths to keep the audit chain ordered.
            return DLPGuardOutcome(
                outcome="passed",
                final_payload=dispatch_result.final_payload,
                refusal_reason=None,
                underlying_failure_mode=None,
                underlying_policy_reason=None,
                failed_hook_id=None,
                failed_pack_distribution_name=None,
                policy_input_digest=dispatch_result.policy_input_digest,
            )

        # Refusal path — dispatcher returned "refused" or "failed".
        # **DLPGuard contract: final_payload on refusal is the ORIGINAL
        # payload, NOT** ``dispatch_result.final_payload`` (which may
        # be a partially-transformed last-seen payload from an earlier
        # redact/mask hook in the chain that completed before a later
        # hook refused). T8 R1 P2-1 fix prevents leaking partially-
        # transformed bytes to a future caller that assumes refused
        # outcomes carry the original input.
        if dispatch_result.outcome == "refused":
            refusal_reason: DLPRefusalReason = "dlp_dispatcher_refused"
        else:
            # outcome == "failed"
            refusal_reason = "dlp_dispatcher_failed"

        await self._maybe_emit_refusal_audit(
            phase=phase,
            refusal_reason=refusal_reason,
            underlying_failure_mode=dispatch_result.failure_mode,
            underlying_policy_reason=dispatch_result.policy_reason,
            failed_hook_id=dispatch_result.failed_hook_id,
            failed_pack_distribution_name=dispatch_result.failed_pack_distribution_name,
            policy_input_digest=dispatch_result.policy_input_digest,
            tenant_id=context_template.tenant_id,
            request_id=context_template.request_id,
        )
        return DLPGuardOutcome(
            outcome="refused",
            # ORIGINAL payload — not dispatch_result.final_payload.
            # See contract docstring above (T8 R1 P2-1 fix).
            final_payload=payload,
            refusal_reason=refusal_reason,
            underlying_failure_mode=dispatch_result.failure_mode,
            underlying_policy_reason=dispatch_result.policy_reason,
            failed_hook_id=dispatch_result.failed_hook_id,
            failed_pack_distribution_name=dispatch_result.failed_pack_distribution_name,
            policy_input_digest=dispatch_result.policy_input_digest,
        )

    async def _maybe_emit_refusal_audit(
        self,
        *,
        phase: HookPhase,
        refusal_reason: DLPRefusalReason,
        underlying_failure_mode: HookFailureMode | None,
        underlying_policy_reason: str | None,
        failed_hook_id: str | None,
        failed_pack_distribution_name: str | None,
        policy_input_digest: str,
        tenant_id: str,
        request_id: str,
    ) -> None:
        """Emit a token-free audit row on a refusal path.

        Strict invariant — the dict carries IDs + closed-enum policy
        metadata + the policy_input_digest only. Payload bytes never
        appear here. The companion AST regression at
        ``tests/architecture/test_hook_payload_never_logged.py``
        mechanically pins the invariant; this docstring is the
        contract.
        """
        if self._audit_emitter is None:
            return
        row: dict[str, object] = {
            "event_type": "dlp.guard_refused",
            "phase": phase,
            "refusal_reason": refusal_reason,
            "underlying_failure_mode": underlying_failure_mode,
            "underlying_policy_reason": underlying_policy_reason,
            "failed_hook_id": failed_hook_id,
            "failed_pack_distribution_name": failed_pack_distribution_name,
            "policy_input_digest": policy_input_digest,
            "tenant_id": tenant_id,
            "request_id": request_id,
        }
        await self._audit_emitter(row)
