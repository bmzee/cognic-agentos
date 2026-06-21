"""protocol/a2a_errors.py — A2A 1.0 spec error taxonomy + AgentOS
policy-refusal reasons + ``A2AErrorResponse`` JSON-RPC wire envelope.

**Critical-controls module per AGENTS.md** (Sprint-6 plan-of-record
R3 P2 #2): owns the spec wire :data:`A2AErrorCode` literal + the
AgentOS :data:`A2APolicyRefusalReason` literal + the
:data:`_POLICY_REASON_TO_SPEC_CODE` mapping. Drift in any of these
changes what remote A2A callers see — wire-protocol drift =
wire-protocol break.

Per Sprint-6 R2 P2 #1 reviewer correction (folded into the closed
literal set in ``protocol/__init__.py`` at T1), the spec wire codes
and the AgentOS-policy reasons are two SEPARATE literals:

  - :data:`A2AErrorCode` — wire-protocol codes per A2A 1.0
    §"Error codes". Every literal MUST appear verbatim in the spec.
    Wave-1 surface = the 14 codes Sprint-6 actually consumes; future
    spec-defined codes (e.g. for push-notification config errors
    when that feature lands in Wave 2) are appended here in their
    owning sprint.
  - :data:`A2APolicyRefusalReason` — AgentOS-specific reasons
    surfaced in the ``data.policy_reason`` field on top of a
    spec-conformant ``error.code``. Operators / audit consumers /
    bank reviewers see the rich reason; remote A2A callers see only
    the spec code.

T11 R0 doctrine #1 (pinned with implementation engineer): T9
(``a2a_endpoint.py``) is NOT refactored to consult this map — T9's
inline hardcoding of ``invalid_request`` / ``method_not_found`` /
``unsupported_operation`` for authz / routing / wave-2 refusals
already agrees with what this map produces for every overlapping
case (same wire outcomes). The
:class:`tests.unit.protocol.test_a2a_errors.TestT9Alignment`
regression pins that alignment so a future map edit cannot
silently desynchronise from T9's emission paths.

T11 R0 doctrine #2: :class:`A2AErrorResponse` (T11) and
:class:`A2AEndpointError` (T9) live at different layers — both
retained. ``A2AEndpointError`` is the Python exception type T9
raises inside ``handle()`` to abort processing; ``A2AErrorResponse``
is the JSON-RPC-shaped response envelope T11 builds for HTTP
serialization. The deferred HTTP-route integration converts the
former into the latter at egress.

R4 P2 reviewer correction (Sprint-6 plan-of-record): the
:data:`_POLICY_REASON_TO_SPEC_CODE` mapping lives module-private
inside ``a2a_errors.py`` — NOT in ``protocol/__init__.py`` and NOT
re-imported elsewhere — to avoid the cyclic-import hazard the
original draft introduced. Co-locating with the
:func:`from_policy_reason` builder keeps it the single point of
truth.
"""

from __future__ import annotations

import dataclasses
import typing
from typing import TYPE_CHECKING, Any, Final

from cognic_agentos.protocol import A2AErrorCode, A2APolicyRefusalReason

if TYPE_CHECKING:
    # Runtime import would be a cycle: a2a_endpoint imports from this
    # package (and admission-side siblings). ``from_endpoint_error``
    # below is duck-typed on ``exc.code`` / ``exc.payload`` and never
    # references this name at runtime.
    from cognic_agentos.protocol.a2a_endpoint import A2AEndpointError

# ---------------------------------------------------------------------------
# AgentOS policy reason → A2A 1.0 spec wire code mapping
# ---------------------------------------------------------------------------


#: Closed mapping :data:`A2APolicyRefusalReason` →
#: :data:`A2AErrorCode`. Every value in
#: :data:`A2APolicyRefusalReason` MUST appear here exactly once
#: (drift detector pinned in
#: ``tests/unit/protocol/test_a2a_errors.py``); every value MUST be
#: a member of :data:`A2AErrorCode` (codomain check).
#:
#: T9 alignment: the four overlapping reasons (``anonymous_refused``,
#: ``tenant_token_invalid``, ``unknown_target``,
#: ``wave2_feature_refused``) produce the same wire codes
#: ``A2AEndpoint.handle()`` hardcodes today — same wire outcomes
#: for every overlapping case. The other 7 entries cover the
#: deferred surfaces (agent-card refusals, capability gates,
#: artifact retention) that integration tasks will consume.
_POLICY_REASON_TO_SPEC_CODE: Final[dict[A2APolicyRefusalReason, A2AErrorCode]] = {
    # Identity / trust failures: the agent card we resolved was
    # unsigned / signed by a non-allow-listed signer / missing.
    # Spec ``invalid_agent_response`` is the closest spec-defined
    # bucket (the agent's published identity material is invalid).
    "agent_card_signature_invalid": "invalid_agent_response",
    "agent_card_signer_not_allowlisted": "invalid_agent_response",
    "agent_card_not_found": "invalid_agent_response",
    # Authn / authz: missing or invalid credentials. Spec maps to
    # ``invalid_request`` (the JSON-RPC envelope itself was
    # well-formed but the request can't be honoured for
    # authentication reasons). Anonymous is the only flavour
    # surfaced as ``anonymous_refused``; every other authz failure
    # is opaque on the wire as ``tenant_token_invalid``.
    "anonymous_refused": "invalid_request",
    "tenant_token_invalid": "invalid_request",
    # Routing failures: the addressed agent isn't registered (or is
    # registered but refused at trust-gate time). Spec
    # ``method_not_found`` per JSON-RPC 2.0 inheritance.
    "unknown_target": "method_not_found",
    # Capability gates: the agent doesn't declare the requested
    # capability OR streaming is requested but not supported. Spec
    # ``unsupported_operation``.
    "capability_not_supported": "unsupported_operation",
    "streaming_not_supported": "unsupported_operation",
    # Artifact policy: payload exceeds tenant-configured size cap or
    # retention has lapsed. Spec ``invalid_params`` (the request
    # carries parameters the endpoint cannot honour).
    "artifact_too_large": "invalid_params",
    "artifact_retention_exceeded": "invalid_params",
    # Wave-2 refusals: feature is spec-valid but Wave-1 refused.
    # Spec ``unsupported_operation`` with the specific
    # ``feature_subtag`` distinguishing which Wave-2 surface
    # (push-notification, multimodal, task-resumption, ...).
    "wave2_feature_refused": "unsupported_operation",
    # Wave-1 inbound-receiver gate refusals (Sprint-1): the method
    # gate refuses any method but ``message/send`` as
    # ``unsupported_operation``; the dumb route refuses a
    # missing/empty tenant header as ``invalid_request`` (the
    # JSON-RPC envelope is well-formed but the request can't be
    # honoured without a tenant to authorise the token against).
    "method_not_supported_wave1": "unsupported_operation",
    "tenant_header_missing": "invalid_request",
}


# ---------------------------------------------------------------------------
# Wire-integration maps (deferred JSON-RPC route serialization)
# ---------------------------------------------------------------------------


#: Spec wire code → JSON-RPC 2.0 integer ``error.code``. The 5
#: JSON-RPC-2.0-reserved codes are fixed by the base spec; the 9
#: A2A-specific codes are the authoritative integers published by the
#: pinned ``a2a-sdk`` (``a2a.utils.errors.JSON_RPC_ERROR_CODE_MAP`` —
#: drift-pinned in ``tests/unit/protocol/test_a2a_errors.py`` under
#: ``COGNIC_RUN_A2A_UPSTREAM=1``). ``error.code`` is an INTEGER per
#: JSON-RPC 2.0, so the string :data:`A2AErrorCode` must be projected
#: onto its wire integer here. Every value of :data:`A2AErrorCode`
#: MUST appear (the completeness test pins this).
_SPEC_CODE_TO_JSONRPC_INT: Final[dict[A2AErrorCode, int]] = {
    # JSON-RPC 2.0 reserved (fixed by the base spec):
    "parse_error": -32700,
    "invalid_request": -32600,
    "method_not_found": -32601,
    "invalid_params": -32602,
    "internal_error": -32603,
    # A2A-specific (a2a-sdk a2a.utils.errors.JSON_RPC_ERROR_CODE_MAP):
    "task_not_found": -32001,
    "task_not_cancelable": -32002,
    "push_notification_not_supported": -32003,
    "unsupported_operation": -32004,
    "content_type_not_supported": -32005,
    "invalid_agent_response": -32006,
    "extended_agent_card_not_configured": -32007,
    "extension_support_required": -32008,
    "version_not_supported": -32009,
}


#: HTTP status the route stamps per spec code. Mirrors the per-factory
#: choices (default 400; ``internal_error`` 500; ``task_not_found``
#: 404). Single source for the route's ``from_endpoint_error`` path.
#: Built over :data:`A2AErrorCode` so every code is mapped (the
#: completeness test pins this).
_SPEC_CODE_TO_HTTP_STATUS: Final[dict[A2AErrorCode, int]] = {
    code: (500 if code == "internal_error" else 404 if code == "task_not_found" else 400)
    for code in typing.get_args(A2AErrorCode)
}


# ---------------------------------------------------------------------------
# Wire envelope
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class A2AErrorResponse:
    """Spec-conformant A2A error response envelope.

    The wire surface is JSON-RPC-2.0-shaped::

        {
          "jsonrpc": "2.0",
          "id": <request id>,
          "error": {
            "code": <int from spec>,
            "message": <human-readable>,
            "data": {
              "policy_reason": <AgentOS policy reason>,
              "feature_subtag": <wave-2 sub-tag>,
              ...
            }
          }
        }

    The HTTP-route integration (deferred) walks this dataclass and
    serialises onto the wire; the ``http_status`` field is the
    spec-mapped HTTP status code the response handler sets.

    Frozen + slotted so the wire payload cannot be mutated between
    construction and egress.
    """

    code: A2AErrorCode
    message: str
    spec_section: str
    policy_reason: A2APolicyRefusalReason | None = None
    feature_subtag: str | None = None
    payload: dict[str, str] | None = None
    http_status: int = 400

    def to_jsonrpc(self, *, jsonrpc_id: str | int | None = None) -> dict[str, Any]:
        """Serialise to the JSON-RPC 2.0 error envelope. ``error.code``
        is the integer spec code (via :data:`_SPEC_CODE_TO_JSONRPC_INT`);
        ``policy_reason`` / ``feature_subtag`` / ``payload`` ride in
        ``error.data``. ``jsonrpc_id`` is ``None`` for Wave-1 (echoing
        the request's JSON-RPC id would need body parsing the dumb route
        deliberately avoids).
        """
        data: dict[str, Any] = {}
        if self.policy_reason is not None:
            data["policy_reason"] = self.policy_reason
        if self.feature_subtag is not None:
            data["feature_subtag"] = self.feature_subtag
        if self.payload:
            data.update(self.payload)
        error_obj: dict[str, Any] = {
            "code": _SPEC_CODE_TO_JSONRPC_INT[self.code],
            "message": self.message,
        }
        if data:
            error_obj["data"] = data
        return {"jsonrpc": "2.0", "id": jsonrpc_id, "error": error_obj}


# ---------------------------------------------------------------------------
# Factories
# ---------------------------------------------------------------------------


def from_policy_reason(
    reason: A2APolicyRefusalReason,
    *,
    message: str,
    feature_subtag: str | None = None,
    payload: dict[str, str] | None = None,
) -> A2AErrorResponse:
    """Build an :class:`A2AErrorResponse` from an AgentOS policy
    refusal reason. The spec wire code is resolved via
    :data:`_POLICY_REASON_TO_SPEC_CODE` so the wire contract stays
    spec-conformant; the policy reason rides in ``data.policy_reason``
    for examiner visibility.

    Raises :class:`KeyError` if ``reason`` is not in the map (defence
    against a future literal addition that lands without updating the
    map; the completeness test pins the dataset, this pins the
    call-site behaviour).
    """
    spec_code = _POLICY_REASON_TO_SPEC_CODE[reason]
    return A2AErrorResponse(
        code=spec_code,
        message=message,
        spec_section="A2A-1.0 §error-codes",
        policy_reason=reason,
        feature_subtag=feature_subtag,
        payload=payload,
    )


def from_endpoint_error(exc: A2AEndpointError) -> A2AErrorResponse:
    """Build the wire response from an :class:`A2AEndpoint` refusal.

    The endpoint raises ``A2AEndpointError(code, message, **payload)``;
    ``policy_reason`` (when present) rides in ``payload``. The
    ``http_status`` comes from :data:`_SPEC_CODE_TO_HTTP_STATUS`.

    Duck-typed on ``exc.code`` / ``exc.payload`` (no ``isinstance``) so
    this module never imports ``a2a_endpoint`` at runtime — that would
    be an import cycle (``a2a_endpoint`` imports from this package and
    its admission-side siblings).
    """
    policy_reason = exc.payload.get("policy_reason")
    extra = {k: str(v) for k, v in exc.payload.items() if k != "policy_reason"}
    return A2AErrorResponse(
        code=exc.code,
        message=str(exc),
        spec_section="A2A-1.0 §error-codes",
        policy_reason=policy_reason,
        payload=extra or None,
        http_status=_SPEC_CODE_TO_HTTP_STATUS[exc.code],
    )


# JSON-RPC envelope error factories (5):


def parse_error(detail: str) -> A2AErrorResponse:
    return A2AErrorResponse(
        code="parse_error",
        message=f"JSON parse error: {detail}",
        spec_section="A2A-1.0 §error-codes (JSON-RPC inherited)",
    )


def invalid_request(detail: str) -> A2AErrorResponse:
    return A2AErrorResponse(
        code="invalid_request",
        message=f"invalid request: {detail}",
        spec_section="A2A-1.0 §error-codes (JSON-RPC inherited)",
    )


def method_not_found(method: str) -> A2AErrorResponse:
    return A2AErrorResponse(
        code="method_not_found",
        message=f"method not found: {method!r}",
        spec_section="A2A-1.0 §error-codes (JSON-RPC inherited)",
        payload={"method": method},
    )


def invalid_params(detail: str) -> A2AErrorResponse:
    return A2AErrorResponse(
        code="invalid_params",
        message=f"invalid params: {detail}",
        spec_section="A2A-1.0 §error-codes (JSON-RPC inherited)",
    )


def internal_error() -> A2AErrorResponse:
    return A2AErrorResponse(
        code="internal_error",
        message="internal server error",
        spec_section="A2A-1.0 §error-codes (JSON-RPC inherited)",
        http_status=500,
    )


# A2A 1.0 spec-defined task / dispatch error factories (9):


def task_not_found(task_id: str) -> A2AErrorResponse:
    return A2AErrorResponse(
        code="task_not_found",
        message=f"task {task_id!r} not found in the endpoint's task store",
        spec_section="A2A-1.0 §error-codes",
        payload={"task_id": task_id},
        http_status=404,
    )


def task_not_cancelable(task_id: str) -> A2AErrorResponse:
    return A2AErrorResponse(
        code="task_not_cancelable",
        message=(
            f"task {task_id!r} is in a terminal state and cannot be "
            f"cancelled (already succeeded / failed / cancelled)"
        ),
        spec_section="A2A-1.0 §error-codes",
        payload={"task_id": task_id},
    )


def version_not_supported(supported: str) -> A2AErrorResponse:
    return A2AErrorResponse(
        code="version_not_supported",
        message=(f"A2A version negotiation refused; supported version: {supported}"),
        spec_section="A2A-1.0 §error-codes",
        payload={"supported": supported},
    )


def unsupported_operation(method: str) -> A2AErrorResponse:
    return A2AErrorResponse(
        code="unsupported_operation",
        message=f"operation {method!r} is not supported by this endpoint",
        spec_section="A2A-1.0 §error-codes",
        payload={"method": method},
    )


def content_type_not_supported(declared: str) -> A2AErrorResponse:
    return A2AErrorResponse(
        code="content_type_not_supported",
        message=f"content type {declared!r} not supported",
        spec_section="A2A-1.0 §error-codes",
        payload={"declared_content_type": declared},
    )


def invalid_agent_response(reason: str) -> A2AErrorResponse:
    return A2AErrorResponse(
        code="invalid_agent_response",
        message=f"agent handler returned an invalid response: {reason}",
        spec_section="A2A-1.0 §error-codes",
    )


def push_notification_not_supported() -> A2AErrorResponse:
    return A2AErrorResponse(
        code="push_notification_not_supported",
        message=(
            "push-notification subscribe is a Wave-2 feature; this "
            "endpoint speaks Wave-1 only (Decision Lock #2)"
        ),
        spec_section="A2A-1.0 §error-codes",
    )


def extended_agent_card_not_configured() -> A2AErrorResponse:
    return A2AErrorResponse(
        code="extended_agent_card_not_configured",
        message=(
            "extended agent card is not configured for this agent in the current pack manifest"
        ),
        spec_section="A2A-1.0 §error-codes",
    )


def extension_support_required(missing_extension: str) -> A2AErrorResponse:
    return A2AErrorResponse(
        code="extension_support_required",
        message=(f"extension {missing_extension!r} is required but not supported by this endpoint"),
        spec_section="A2A-1.0 §error-codes",
        payload={"missing_extension": missing_extension},
    )


__all__ = (
    "A2AErrorResponse",
    "content_type_not_supported",
    "extended_agent_card_not_configured",
    "extension_support_required",
    "from_endpoint_error",
    "from_policy_reason",
    "internal_error",
    "invalid_agent_response",
    "invalid_params",
    "invalid_request",
    "method_not_found",
    "parse_error",
    "push_notification_not_supported",
    "task_not_cancelable",
    "task_not_found",
    "unsupported_operation",
    "version_not_supported",
)
