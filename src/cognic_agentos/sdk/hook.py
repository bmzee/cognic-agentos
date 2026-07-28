"""Sprint-7A2 T2 — `agentos_sdk.Hook` base class for governance hook
implementations.

Subclass + register under the ``cognic.hooks`` entry-point group in
``pyproject.toml``. The runtime hook dispatcher (Sprint-7A2 T8) consumes
this contract. The build-time validator (Sprint-7A2 T6) cross-checks manifest
hook IDs against pyproject entry-point keys; deferred subclass ``hook_id`` +
``phase`` metadata is checked by the dispatcher at first invocation. Per
Doctrine Decision E: every commit touching this surface halts before commit
(semver-stability concern, NOT critical-controls security gate).

Template-method pattern (mirrors ``Tool`` / ``Skill`` from Sprint-7A
T2):

  - Public ``invoke(context, payload)`` is ``@typing.final`` + enforced
    at runtime via ``__init_subclass__`` — subclasses MUST override
    ``_invoke`` instead. The MRO walk catches mixin smuggling (a
    sibling-mixin class defining ``invoke`` ahead of ``Hook`` in MRO).
  - ``invoke()`` validates ``context`` + ``payload`` shape BEFORE
    delegating to ``_invoke``; validates the returned ``HookResult``
    shape + decision-↔-fields invariants AFTER. Failures raise
    ``HookContractError`` subclasses; the runtime dispatcher (T8)
    catches the entire ``HookError`` hierarchy as a single deterministic
    refusal surface.

The base class deliberately does NOT emit audit events — audit emission
belongs to the runtime hook dispatcher (Sprint-7A2 T8) which has the
``AuditStore`` + ``DecisionHistoryStore`` + tenant context the bare
Hook instance does not. This mirrors Sprint-7A T2 ``Tool``'s same
boundary (audit emission lives in ``mcp_host._emit_call_evidence``,
not in ``Tool.invoke``).

Payload-contents-never-logged invariant (Doctrine Lock E from the
plan-of-record): ``HookContext`` carries IDs + closed-enum policy
metadata + manifest cross-references but NOT the payload bytes
themselves. The dispatcher passes ``payload`` as a separate argument
to ``_invoke`` so the context is safely loggable; pinned at runtime
by the AST-walk regression
``tests/architecture/test_hook_payload_never_logged.py`` (lands at
Sprint-7A2 T7).
"""

from __future__ import annotations

import abc
import dataclasses
import uuid
from typing import Any, ClassVar, Literal, final

from cognic_agentos.cli._governance_vocab import HookPhase

#: Closed-enum decision the hook returns to the dispatcher, shared by
#: ADR-017 DLP and ADR-028 conversation phases:
#:
#:   - ``"pass"``: payload unchanged; dispatcher continues to the next
#:     hook (or to the governed caller after the final hook).
#:   - ``"redact"``: payload was modified (PII redacted); dispatcher
#:     replaces the in-flight payload with ``redacted_payload`` and
#:     continues on ``dlp_pre``. An F-S2a ``conversation_input`` /
#:     ``conversation_output`` use fails closed instead.
#:   - ``"mask"``: payload was modified (account numbers / secrets
#:     masked); dispatcher replaces the payload and continues. Used by
#:     ``dlp_post`` hooks; conversation phases fail closed in F-S2a.
#:   - ``"refuse"``: hook explicitly refuses the call; dispatcher
#:     short-circuits the dispatch chain + the calling pack's
#:     invocation is refused with the closed-enum
#:     ``hook_policy_refused`` runtime failure mode (per
#:     plan-of-record Doctrine Lock E). ``policy_reason`` MUST be
#:     populated.
HookDecision = Literal["pass", "redact", "mask", "refuse"]


class HookError(Exception):
    """Base class for all SDK Hook errors. The runtime hook dispatcher
    (Sprint-7A2 T8) catches this single class to refuse a hook
    invocation; every contract-validation subclass below is reachable
    via that catch."""


class HookContractError(HookError):
    """Hook-contract violation surfaced by the SDK's template-method
    seam — base class for the four sub-cases below.

    The runtime dispatcher's catch routes any of these to the
    closed-enum ``hook_malformed_result`` runtime failure mode
    (per Doctrine Lock E). Pack-author bugs land here, NOT raw
    ``TypeError`` / ``AttributeError`` past the SDK boundary.
    """


class HookContextError(HookContractError):
    """The ``HookContext`` passed to ``invoke()`` is None / wrong type
    / missing a required field. Dispatcher invariants pin the shape
    upstream, so this is reachable only via direct test invocation
    or a malformed dispatcher."""


class HookPayloadError(HookContractError):
    """The ``payload`` argument to ``invoke()`` is None / not bytes.
    Dispatcher upstream enforces ``isinstance(payload, bytes)`` so
    this is reachable only via direct test invocation."""


class HookResultShapeError(HookContractError):
    """``Hook._invoke()`` returned a non-``HookResult`` value, or a
    ``HookResult`` whose fields violate the decision-↔-fields
    invariant (e.g., ``decision="redact"`` with
    ``redacted_payload=None``; ``decision="refuse"`` without
    ``policy_reason``)."""


@dataclasses.dataclass(frozen=True, slots=True)
class HookContext:
    """Token-free metadata passed to every hook invocation.

    Carries IDs + closed-enum policy metadata + manifest cross-
    references the hook may key its decision off. Does NOT carry the
    payload bytes — the dispatcher passes payload separately to
    ``_invoke()`` so the context is safely loggable. Pinned by the
    AST-walk regression at
    ``tests/architecture/test_hook_payload_never_logged.py``
    (Sprint-7A2 T7).

    Frozen + slotted — pack authors cannot mutate the context across
    hook chain entries, and the dispatcher's per-hook copy is cheap.
    """

    hook_id: str
    """The hook_id this invocation targets — matches the hook pack's
    ``[hooks].declarations[].hook_id`` declaration. DLP phases additionally
    resolve it from the calling pack's ``dlp_*_hooks`` reference; conversation
    phases are selected phase-wide and have no calling-pack hook-id list."""

    phase: HookPhase
    """Closed-enum DLP or conversation input/output hook phase.
    Sourced from ``cognic_agentos.cli._governance_vocab.HookPhase``."""

    pack_id: str
    """The CALLING pack's ``[pack].pack_id`` — the pack whose
    invocation this hook is gating. NOT the hook pack's own pack_id;
    the dispatcher (Sprint-7A2 T8) populates this from the
    runtime-invocation context."""

    tenant_id: str
    """Per-tenant binding so a hook can apply tenant-specific
    policy. Sourced from the runtime's tenant-context propagation."""

    request_id: str
    """Stable request identifier for audit-chain correlation."""

    trace_id: str | None
    """Distributed-trace identifier (None when called outside a
    traced request)."""

    parent_trace_id: str | None
    """Parent-trace identifier for cross-agent chain linkage (None at
    the top of a chain). Mirrors the Sprint-6 A2A endpoint's chain-
    linkage pattern."""

    manifest_data_classes: tuple[str, ...]
    """The CALLING pack's declared ``[data_governance].data_classes``,
    snapshot at admission time. Lets the hook key its decision off
    declared classes without re-parsing the manifest at dispatch time.
    Tuple (immutable) so the hook cannot mutate the snapshot."""

    manifest_purpose: str
    """The CALLING pack's declared ``[data_governance].purpose``,
    snapshot at admission time."""

    conversation_id: str | None = None
    """Conversation UUID for conversation-phase evidence correlation.
    ``None`` for DLP and other non-conversation callers."""

    conversation_turn_seq: int | None = None
    """Physical conversation turn sequence paired with ``conversation_id``."""

    agent_run_id: str | None = None
    """Model-execution correlation on conversation output.

    Present only when ``output_origin == "agent_run"`` and required to use
    the production ``agent-run-`` namespace. Approval delivery deliberately
    uses :attr:`approval_delivery_id` instead.
    """

    output_origin: Literal["agent_run", "approval_delivery"] | None = None
    """Discriminator for conversation-output evidence correlation.

    ``None`` on conversation input and every non-conversation phase.
    """

    approval_delivery_id: str | None = None
    """Approval-rendering correlation on conversation output.

    Present only when ``output_origin == "approval_delivery"`` and shaped as
    ``approval-delivery-<canonical UUID>``. It is never placed in
    :attr:`agent_run_id`, so examiners cannot mistake a synthetic delivery
    identity for an ``agent.run.*`` identity.
    """


@dataclasses.dataclass(frozen=True, slots=True)
class HookResult:
    """Token-free result returned to the dispatcher.

    ``decision`` is the closed-enum the dispatcher routes on:

      - ``"pass"`` / ``"refuse"``: ``redacted_payload`` MUST be None.
      - ``"redact"`` / ``"mask"``: ``redacted_payload`` MUST be bytes
        (the modified payload the dispatcher carries to the next
        hook / to pack code / to the caller).
      - ``"refuse"``: ``policy_reason`` MUST be a non-empty string
        authored by the hook. The dispatcher retains it in the caller result.
        Conversation evidence deliberately suppresses the pack-controlled
        string so screened content cannot be encoded into a governed row.

    The decision-↔-fields invariant is enforced by ``Hook.invoke()``
    AFTER ``_invoke`` returns; violations raise
    ``HookResultShapeError`` (subclass of ``HookContractError`` → in
    the ``HookError`` hierarchy → caught by the dispatcher's single
    refusal-surface catch).

    Frozen + slotted; ``audit_metadata`` is the only mutable
    container. It is reserved SDK metadata: the current runtime
    dispatcher neither emits nor otherwise consumes it. Pack authors
    must not rely on persistence and must never place payload bytes in
    it.
    """

    decision: HookDecision
    """Closed-enum decision the dispatcher routes on."""

    redacted_payload: bytes | None
    """For ``redact`` / ``mask`` decisions: the modified payload bytes
    the dispatcher carries forward. MUST be None for ``pass`` /
    ``refuse``."""

    policy_reason: str | None
    """For ``refuse`` decisions: non-empty hook-authored reason retained in
    the caller result. The conversation evidence path suppresses this
    pack-controlled string. MUST be None for ``pass`` / ``redact`` / ``mask``;
    MUST be a non-empty string for ``refuse``."""

    audit_metadata: dict[str, Any] = dataclasses.field(default_factory=dict)
    """Reserved token-free metadata.

    The current runtime dispatcher does not emit or otherwise consume
    it. Hooks MUST NOT rely on persistence and MUST NOT include
    payload bytes; the pack-author convention + the AST-walk
    regression
    (``tests/architecture/test_hook_payload_never_logged.py``) carry
    the latter invariant.
    """


def _validate_hook_context(context: Any) -> None:
    """Refuse a non-``HookContext`` argument before ``_invoke`` runs.
    Dispatcher invariants pin this upstream; the SDK still validates
    so direct test invocations + malformed dispatchers don't slip
    untyped values past ``_invoke``."""
    if context is None:
        raise HookContextError("HookContext argument is None")
    if not isinstance(context, HookContext):
        raise HookContextError(
            f"HookContext argument is {type(context).__name__}, expected HookContext"
        )
    if context.phase in ("conversation_input", "conversation_output"):
        try:
            parsed_conversation_id = uuid.UUID(context.conversation_id or "")
        except ValueError as exc:
            raise HookContextError(
                "conversation-phase HookContext requires a canonical conversation_id"
            ) from exc
        if str(parsed_conversation_id) != context.conversation_id:
            raise HookContextError(
                "conversation-phase HookContext requires a canonical conversation_id"
            )
        if (
            isinstance(context.conversation_turn_seq, bool)
            or not isinstance(context.conversation_turn_seq, int)
            or context.conversation_turn_seq <= 0
        ):
            raise HookContextError(
                "conversation-phase HookContext requires a positive conversation_turn_seq"
            )
        if context.phase == "conversation_input" and (
            context.agent_run_id is not None
            or context.output_origin is not None
            or context.approval_delivery_id is not None
        ):
            raise HookContextError("conversation_input HookContext cannot carry output correlation")
        if context.phase == "conversation_output":
            if context.output_origin == "agent_run":
                if (
                    not isinstance(context.agent_run_id, str)
                    or not context.agent_run_id.startswith("agent-run-")
                    or context.agent_run_id == "agent-run-"
                    or context.approval_delivery_id is not None
                ):
                    raise HookContextError(
                        "agent_run output requires one agent-run-* identity and "
                        "no approval_delivery_id"
                    )
            elif context.output_origin == "approval_delivery":
                prefix = "approval-delivery-"
                raw_id = context.approval_delivery_id
                try:
                    parsed_delivery_id = uuid.UUID(
                        raw_id[len(prefix) :]
                        if isinstance(raw_id, str) and raw_id.startswith(prefix)
                        else ""
                    )
                except ValueError as exc:
                    raise HookContextError(
                        "approval_delivery output requires a canonical "
                        "approval-delivery-<uuid> identity"
                    ) from exc
                if raw_id != prefix + str(parsed_delivery_id) or context.agent_run_id is not None:
                    raise HookContextError(
                        "approval_delivery output requires one canonical delivery "
                        "identity and no agent_run_id"
                    )
            else:
                raise HookContextError(
                    "conversation_output HookContext requires a known output_origin"
                )
    elif (
        context.conversation_id is not None
        or context.conversation_turn_seq is not None
        or context.agent_run_id is not None
        or context.output_origin is not None
        or context.approval_delivery_id is not None
    ):
        raise HookContextError(
            "non-conversation HookContext cannot carry conversation correlation fields"
        )


def _validate_hook_payload(payload: Any) -> None:
    """Refuse a non-bytes payload before ``_invoke`` runs. Dispatcher
    upstream enforces ``isinstance(payload, bytes)``; the SDK still
    validates here for direct-test-invocation paths."""
    if payload is None:
        raise HookPayloadError("payload argument is None")
    if not isinstance(payload, bytes):
        raise HookPayloadError(f"payload argument is {type(payload).__name__}, expected bytes")


def _validate_hook_result(result: Any) -> None:
    """Validate the ``HookResult`` ``_invoke`` returned: type, then
    the decision-↔-fields invariant.

    Sub-cases (all routed to ``HookResultShapeError``):

      - non-``HookResult`` shape (e.g., the subclass returned a dict
        / None / a wrong dataclass).
      - a decision outside the four-value :data:`HookDecision` vocabulary.
      - ``decision="pass"`` or ``"refuse"`` with ``redacted_payload``
        not None.
      - ``decision="redact"`` or ``"mask"`` with ``redacted_payload``
        None or non-bytes.
      - ``decision="refuse"`` with ``policy_reason`` None / empty /
        whitespace.
      - ``decision`` in {``pass``, ``redact``, ``mask``} with
        ``policy_reason`` not None (only ``refuse`` carries a reason).
    """
    if not isinstance(result, HookResult):
        raise HookResultShapeError(f"_invoke returned {type(result).__name__}, expected HookResult")
    decision = result.decision
    if decision not in ("pass", "redact", "mask", "refuse"):
        raise HookResultShapeError(
            f"HookResult.decision={decision!r} is outside the closed HookDecision vocabulary"
        )
    if decision in ("pass", "refuse") and result.redacted_payload is not None:
        raise HookResultShapeError(
            f"HookResult.decision={decision!r} requires redacted_payload=None; "
            f"got {type(result.redacted_payload).__name__}"
        )
    if decision in ("redact", "mask"):
        if result.redacted_payload is None:
            raise HookResultShapeError(
                f"HookResult.decision={decision!r} requires redacted_payload to be bytes; got None"
            )
        if not isinstance(result.redacted_payload, bytes):
            raise HookResultShapeError(
                f"HookResult.decision={decision!r} requires redacted_payload "
                f"to be bytes; got {type(result.redacted_payload).__name__}"
            )
    if decision == "refuse":
        if not isinstance(result.policy_reason, str) or not result.policy_reason.strip():
            raise HookResultShapeError(
                'HookResult.decision="refuse" requires policy_reason to be a non-empty string'
            )
    elif result.policy_reason is not None:
        raise HookResultShapeError(
            f"HookResult.decision={decision!r} requires policy_reason=None "
            f"(only `refuse` carries a reason); got {result.policy_reason!r}"
        )


class Hook(abc.ABC):
    """Base class for ``cognic.hooks`` entry-point implementations.

    Subclasses declare ``hook_id`` + ``phase`` as ClassVar fields,
    override ``_invoke`` for the actual work, and let the SDK's
    template-method validation seam handle context/payload/result
    shape checks.

    Contract validation is enforced by the SDK base — pack authors
    CANNOT skip it by forgetting (the seam is enforced via
    ``__init_subclass__`` + ``@typing.final`` together).

    Per Doctrine Decision E: this is public API; halt-before-commit
    on every change.
    """

    hook_id: ClassVar[str]
    """Stable identifier matching the manifest's
    ``[hooks].declarations[].hook_id``. DLP callers reference it through the
    calling pack's ``dlp_*_hooks`` lists; conversation phases do not."""

    phase: ClassVar[HookPhase]
    """Closed-enum DLP or conversation input/output hook phase."""

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Runtime enforcement of the ``invoke`` template-method seam.

        ``typing.final`` is mypy-only; Python runtime allows a
        subclass to override ``invoke`` despite the decorator.
        Without this guard, a pack author who shadows ``invoke``
        bypasses the SDK's context / payload / result validation.

        Walk ``cls.__mro__`` and refuse any ancestor (other than
        ``Hook`` itself and ``object``) that defines ``invoke``
        directly. This catches mixin smuggling that the simpler
        ``cls.__dict__`` check would miss (e.g.,
        ``class Bypass: async def invoke(...): ...; class Sub(Bypass, Hook): pass``).
        Mirrors the Sprint-7A T2 ``Tool`` pattern (R8 P2 #1 there).
        """
        super().__init_subclass__(**kwargs)
        for ancestor in cls.__mro__:
            if ancestor is Hook or ancestor is object:
                continue
            if "invoke" in ancestor.__dict__:
                raise TypeError(
                    f"{cls.__qualname__} resolves Hook.invoke() to a non-base "
                    f"override defined in {ancestor.__qualname__} (in MRO before "
                    "Hook). The Hook template-method contract pins ``invoke`` as "
                    "final; the only allowed owner is the SDK's Hook base. "
                    "Either remove the override from "
                    f"{ancestor.__qualname__} or refactor it to override "
                    "_invoke instead so the SDK's context / payload / result "
                    "validation seam cannot be bypassed via mixin smuggling."
                )

    @final
    async def invoke(self, context: HookContext, payload: bytes) -> HookResult:
        """Public entry point. Validates ``context`` + ``payload``
        shape BEFORE delegating to ``_invoke``; validates the returned
        ``HookResult`` shape + decision-↔-fields invariants AFTER.

        Subclasses MUST NOT override this method (pinned via
        ``@typing.final`` for mypy + ``__init_subclass__`` for
        runtime).

        Raises (all in the ``HookError`` hierarchy so the runtime
        dispatcher's single ``except HookError`` catches every path):

          - ``HookContextError`` — context is None or non-
            ``HookContext``.
          - ``HookPayloadError`` — payload is None or non-bytes.
          - ``HookResultShapeError`` — ``_invoke`` returned a non-
            ``HookResult`` shape OR a ``HookResult`` whose decision-
            ↔-fields invariant is violated.
        """
        _validate_hook_context(context)
        _validate_hook_payload(payload)
        result = await self._invoke(context, payload)
        _validate_hook_result(result)
        return result

    @abc.abstractmethod
    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        """Subclass-specific behaviour. The base class has already
        validated ``context`` + ``payload`` by the time this is
        called; the base will validate the returned ``HookResult``
        afterwards. Subclasses focus on the actual policy decision,
        not the validation discipline."""
        raise NotImplementedError


__all__ = [
    "Hook",
    "HookContext",
    "HookContextError",
    "HookContractError",
    "HookDecision",
    "HookError",
    "HookPayloadError",
    "HookResult",
    "HookResultShapeError",
]
