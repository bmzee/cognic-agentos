"""Sprint-7A2 T2 — `agentos_sdk.Hook` base class for governance hook
implementations.

Subclass + register under the ``cognic.hooks`` entry-point group in
``pyproject.toml``. The runtime hook dispatcher (Sprint-7A2 T8) consumes
this contract; the build-time validator (Sprint-7A2 T6) cross-checks
manifest declarations against subclass ``hook_id`` + ``phase``
ClassVars. Per Doctrine Decision E: every commit touching this surface
halts before commit (semver-stability concern, NOT critical-controls
security gate).

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
from typing import Any, ClassVar, Literal, final

from cognic_agentos.cli._governance_vocab import HookPhase

#: Closed-enum decision the hook returns to the dispatcher. Wave-1
#: narrow per ADR-017:
#:
#:   - ``"pass"``: payload unchanged; dispatcher continues to the next
#:     hook (or to pack code for the final ``dlp_pre`` hook /
#:     to the caller for the final ``dlp_post`` hook).
#:   - ``"redact"``: payload was modified (PII redacted); dispatcher
#:     replaces the in-flight payload with ``redacted_payload`` and
#:     continues. Used by ``dlp_pre`` redaction hooks.
#:   - ``"mask"``: payload was modified (account numbers / secrets
#:     masked); dispatcher replaces the payload and continues. Used by
#:     ``dlp_post`` masking hooks.
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
    """The hook_id this invocation targets — matches the calling
    pack's ``[data_governance].dlp_{pre,post}_hooks`` reference and
    the hook pack's ``[hooks].declarations[].hook_id`` declaration."""

    phase: HookPhase
    """Closed-enum hook phase (Wave-1: ``dlp_pre`` / ``dlp_post``).
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


@dataclasses.dataclass(frozen=True, slots=True)
class HookResult:
    """Token-free result returned to the dispatcher.

    ``decision`` is the closed-enum the dispatcher routes on:

      - ``"pass"`` / ``"refuse"``: ``redacted_payload`` MUST be None.
      - ``"redact"`` / ``"mask"``: ``redacted_payload`` MUST be bytes
        (the modified payload the dispatcher carries to the next
        hook / to pack code / to the caller).
      - ``"refuse"``: ``policy_reason`` MUST be a non-empty string
        (closed-enum from the calling pack's policy vocabulary; the
        dispatcher propagates it into the ``hook_policy_refused``
        audit row + the refusal envelope returned to the caller).

    The decision-↔-fields invariant is enforced by ``Hook.invoke()``
    AFTER ``_invoke`` returns; violations raise
    ``HookResultShapeError`` (subclass of ``HookContractError`` → in
    the ``HookError`` hierarchy → caught by the dispatcher's single
    refusal-surface catch).

    Frozen + slotted; ``audit_metadata`` is the only mutable
    container (a regular dict so the hook can add token-free metadata
    rows). The base class does NOT validate dict contents; the
    dispatcher's audit emission path strips any keys that match the
    payload-never-logged invariant (T8 closed-list).
    """

    decision: HookDecision
    """Closed-enum decision the dispatcher routes on."""

    redacted_payload: bytes | None
    """For ``redact`` / ``mask`` decisions: the modified payload bytes
    the dispatcher carries forward. MUST be None for ``pass`` /
    ``refuse``."""

    policy_reason: str | None
    """For ``refuse`` decisions: closed-enum policy reason from the
    calling pack's policy vocabulary; propagates to the
    ``hook_policy_refused`` audit row + caller refusal envelope.
    MUST be None for ``pass`` / ``redact`` / ``mask``; MUST be a
    non-empty string for ``refuse``."""

    audit_metadata: dict[str, Any] = dataclasses.field(default_factory=dict)
    """Token-free metadata the hook wants the dispatcher to attach
    to its audit row. Hooks MUST NOT include payload bytes here —
    the dispatcher's emission path doesn't deeply scan the dict; the
    pack-author convention + the AST-walk regression
    (``tests/architecture/test_hook_payload_never_logged.py``) carry
    the invariant."""


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
        if result.policy_reason is None or not result.policy_reason.strip():
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
    ``[hooks].declarations[].hook_id`` + the calling pack's
    ``[data_governance].dlp_{pre,post}_hooks`` reference."""

    phase: ClassVar[HookPhase]
    """Closed-enum hook phase (Wave-1: ``dlp_pre`` / ``dlp_post``)."""

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
