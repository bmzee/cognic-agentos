"""Sprint-7B.4 T8 — submit_elicitation 5-step gate per ADR-020 §69-77.

Async, pure-functional gate. Called by the T11 POST /api/v1/ui/actions
handler when `action_class == "submit_elicitation"`. Returns a frozen
:class:`GateOutcome` carrying (allowed, reason, ctx):

  - ``allowed=True`` ⇒ caller proceeds to ``adapter.handle_submission``
  - ``allowed=False`` ⇒ caller maps `reason` to the
    ``ActionRejectionReason`` chain-event vocabulary + emits the
    `frontend_action.rejected` chain row WITHOUT calling the backend

5-step refusal contract (per design spec §5b):

  Step 1 — adapter wired? (``adapter is None`` OR kernel-default raises
           ``NotImplementedError``) → `elicitation_backend_unwired`
  Step 2 — ``adapter.get_context(elicitation_id, tenant_id)`` returns
           ``None`` → `elicitation_unknown_id`
  Step 3 — mode parity: ``request.mode in ctx.elicitation_modes``
           (BOTH directions — neither over-permits) →
           `elicitation_mode_not_permitted`
  Step 4 — form-mode + restricted-data-class intersection (only fires
           on form mode; URL-mode submissions are safe regardless of
           data_classes because the user completes off-system at the
           bank-overlay's URL surface) →
           `elicitation_restricted_data_class`
  Step 5 — Rego eval at ``data.cognic.ui.elicitation_submit.allow``:
           rego_engine=None OR OpaNotInstalledError →
           `elicitation_unwired_evaluator`; allow=False OR
           RegoEvaluationError → `elicitation_rego_denied`; allow=True →
           green path

Architectural arrow: the gate has NO runtime dependency on
``protocol.mcp_capabilities`` (or any portal/protocol-internal set);
the local :data:`_RESTRICTED_DATA_CLASSES` frozenset is a deliberate
inline copy of the runtime-side canonical at
``protocol/mcp_capabilities._RESTRICTED_DATA_CLASSES``. Three-way
lockstep — gate ↔ Rego bundle ↔ canonical — is pinned by a test-only
drift detector at
``tests/unit/portal/api/ui/test_elicitation_gate.py::TestRestrictedClassesThreeWayLockstep``.

CC classification per ADR-012 §41 / 7B.3 T7 precedent: this module IS
the policy boundary for the submit_elicitation surface. Promoted to
critical-controls because the closed-enum 10-value
:data:`ActionRejectionReason` vocabulary + the gate's step-ordering +
the fail-closed Rego-error mapping all drive the T11 action handler's
wire-protocol-public refusal body.
"""

from __future__ import annotations

import dataclasses
import logging
from typing import Any, Literal

from cognic_agentos.core.policy.engine import (
    OPAEngine,
    OpaNotInstalledError,
    RegoBundleInvalidError,
    RegoBundleNotFoundError,
    RegoEvaluationError,
)
from cognic_agentos.protocol.elicitation_adapter import (
    ElicitationAdapter,
    ElicitationContext,
)

_LOG = logging.getLogger(__name__)


#: Sprint-7B.4 T8 — local mirror of the runtime canonical at
#: :data:`cognic_agentos.protocol.mcp_capabilities._RESTRICTED_DATA_CLASSES`
#: (3-value set: customer_pii / payment_action / regulator_communication).
#:
#: The inline copy is deliberate per the user-locked architectural
#: doctrine: a runtime cross-module import from this gate into
#: ``protocol/mcp_capabilities`` would introduce a portal →
#: protocol-internal arrow that's not currently permitted. Equality
#: across the 3 sources of truth (this constant + the Rego bundle's
#: ``restricted_classes`` set + the mcp_capabilities canonical) is
#: pinned by ``tests/unit/portal/api/ui/test_elicitation_gate.py::
#: TestRestrictedClassesThreeWayLockstep`` at every CI run.
#:
#: Build-time vocabulary (``cli/_governance_vocab.RESTRICTED_DATA_CLASSES``,
#: 4 values, uses ``payment_data``) is intentionally DIFFERENT — see
#: the existing comment at ``cli/_governance_vocab.py:93-98`` for the
#: deferred reconciliation rationale. T8 is NOT the place to fix the
#: build-time/runtime vocab split.
_RESTRICTED_DATA_CLASSES: frozenset[str] = frozenset(
    {
        "customer_pii",
        "payment_action",
        "regulator_communication",
    }
)


#: 10-value closed-enum vocabulary for the
#: ``frontend_action.rejected`` chain row's ``payload.reason`` field
#: when the rejected action_class is ``submit_elicitation``. T11
#: action handler also uses these for the other action classes (the
#: 3 ``action_backend_deferred_*`` reasons cover approve / deny /
#: cancel_run / interrupt / resume per the design spec § stub paths).
#:
#: Wire-protocol-public per ADR-020 §69-77 + the AGENTS.md "Wire-
#: protocol contracts" stop rule. ANY change to this Literal — value
#: rename, removal, or addition — is a wire-protocol break that
#: examiner consumers (reading the chain row's ``payload.reason``)
#: and bank-overlay UIs (rendering the denial body) both depend on.
ActionRejectionReason = Literal[
    # Deferred-stub reasons for the 5 non-submit_elicitation action_classes.
    # T11 action handler returns these for the approve/deny/cancel_run/
    # interrupt/resume routes whose backend wiring lands in later sprints.
    "action_backend_deferred_to_sprint_13_5",
    "action_backend_deferred_no_run_primitive",
    "action_backend_deferred_sandbox_unwired",
    # Step 3 — mode parity
    "elicitation_mode_not_permitted",
    # Step 4 — restricted-data-class intersection (form-mode only)
    "elicitation_restricted_data_class",
    # Step 5 — Rego refusal OR evaluation error (fail-closed)
    "elicitation_rego_denied",
    # Step 5 — Rego subsystem unavailable (engine=None OR no OPA binary)
    "elicitation_unwired_evaluator",
    # Adapter backend failure AFTER the gate passed (raised by
    # adapter.handle_submission at the T11 action handler — distinct
    # from the gate's pre-dispatch refusals so operators can tell
    # "gate refused" apart from "backend rejected" in audit logs).
    "elicitation_backend_failed",
    # Step 1 — adapter not wired (None OR kernel-default raises)
    "elicitation_backend_unwired",
    # Step 2 — adapter returned None for the elicitation_id
    "elicitation_unknown_id",
]


@dataclasses.dataclass(frozen=True)
class GateOutcome:
    """Return shape of :func:`evaluate_elicitation_submission`.

    Frozen so the T11 action handler can carry the same outcome value
    through the chain-row append path without aliasing risk. The
    ``ctx`` field is populated whenever the adapter resolution
    succeeded (Steps 3+ refusals) so the handler can include
    ``originating_pack_id`` / ``originating_decision_record_id`` in
    the rejection chain row's payload for examiner traceability."""

    allowed: bool
    reason: ActionRejectionReason | None
    ctx: ElicitationContext | None


async def evaluate_elicitation_submission(
    *,
    request: Any,
    actor: Any,
    adapter: ElicitationAdapter | None,
    rego_engine: OPAEngine | None,
) -> GateOutcome:
    """Async 5-step gate per ADR-020 §69-77.

    Expected `request` shape (duck-typed): the gate reads
    ``request.elicitation_id`` (str), ``request.mode`` (``"url"`` or
    ``"form"``), and ``request.form_payload`` (dict | None). The T9
    :class:`cognic_agentos.portal.api.ui.dto.SubmitElicitationActionRequest`
    Pydantic DTO satisfies this shape; test stubs do likewise. ``Any``
    in the signature keeps the gate Pydantic-free + reusable from
    non-portal contexts (CLI dry-run, batch backfill).

    Expected `actor` shape (duck-typed): the gate reads
    ``actor.tenant_id`` (str). The portal
    :class:`cognic_agentos.portal.rbac.actor.Actor` satisfies this shape.

    Returns a frozen :class:`GateOutcome` with `allowed` + `reason` +
    optional `ctx`. See module docstring for the full step contract +
    the wire-protocol-public closed-enum reason vocabulary at
    :data:`ActionRejectionReason`.
    """
    # ----- Step 1 — adapter wired? -----
    if adapter is None:
        return GateOutcome(
            allowed=False,
            reason="elicitation_backend_unwired",
            ctx=None,
        )

    # ----- Step 2 — context lookup (tenant-scoped) -----
    try:
        ctx = await adapter.get_context(
            elicitation_id=request.elicitation_id,
            tenant_id=actor.tenant_id,
        )
    except NotImplementedError:
        # KernelDefaultElicitationAdapter from T7 raises this — same
        # operator-visible reason as adapter=None (the bank overlay
        # forgot to inject a real adapter via
        # `create_app(elicitation_adapter=...)`).
        return GateOutcome(
            allowed=False,
            reason="elicitation_backend_unwired",
            ctx=None,
        )
    if ctx is None:
        return GateOutcome(
            allowed=False,
            reason="elicitation_unknown_id",
            ctx=None,
        )

    # ----- Step 3 — mode parity (BOTH directions per spec §5b P1) -----
    if request.mode not in ctx.elicitation_modes:
        return GateOutcome(
            allowed=False,
            reason="elicitation_mode_not_permitted",
            ctx=ctx,
        )

    # ----- Step 4 — restricted-data-class refusal (form-mode only) -----
    # URL-mode submissions are safe regardless of data_classes — the
    # user completes the elicitation off-system at the bank-overlay's
    # URL surface; no restricted data crosses the portal HTTP boundary.
    if request.mode == "form" and _RESTRICTED_DATA_CLASSES.intersection(ctx.data_classes):
        return GateOutcome(
            allowed=False,
            reason="elicitation_restricted_data_class",
            ctx=ctx,
        )

    # ----- Step 5 — Rego eval at data.cognic.ui.elicitation_submit.allow -----
    if rego_engine is None:
        return GateOutcome(
            allowed=False,
            reason="elicitation_unwired_evaluator",
            ctx=ctx,
        )
    try:
        decision = await rego_engine.evaluate(
            decision_point="data.cognic.ui.elicitation_submit.allow",
            input={
                "tenant_id": actor.tenant_id,
                "elicitation_id": request.elicitation_id,
                "originating_pack_id": ctx.originating_pack_id,
                "mode": request.mode,
                "data_classes": list(ctx.data_classes),
                "has_form_payload": request.form_payload is not None,
            },
        )
    except OpaNotInstalledError:
        # OPA binary not installed at the bank-overlay deployment.
        # Same closed-enum reason as rego_engine=None — operators read
        # either as "Rego subsystem not available"; recoverable by
        # installing the binary.
        return GateOutcome(
            allowed=False,
            reason="elicitation_unwired_evaluator",
            ctx=ctx,
        )
    except (RegoBundleNotFoundError, RegoBundleInvalidError, RegoEvaluationError):
        # Bundle missing / invalid / evaluation crashed mid-rule.
        # Fail-closed: refuse rather than admit; log via _LOG so
        # operators can pinpoint the bundle issue. Distinct from
        # `elicitation_unwired_evaluator` (which is recoverable by
        # installing OPA).
        _LOG.error("ui.elicitation.rego_evaluation_failed", exc_info=True)
        return GateOutcome(
            allowed=False,
            reason="elicitation_rego_denied",
            ctx=ctx,
        )

    if not decision.allow:
        return GateOutcome(
            allowed=False,
            reason="elicitation_rego_denied",
            ctx=ctx,
        )

    # ----- Green path -----
    return GateOutcome(allowed=True, reason=None, ctx=ctx)


__all__ = [
    "_RESTRICTED_DATA_CLASSES",
    "ActionRejectionReason",
    "GateOutcome",
    "evaluate_elicitation_submission",
]
