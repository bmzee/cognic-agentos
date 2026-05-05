"""protocol/a2a_endpoint.py — A2A inbound receiver + task lifecycle.

Critical-controls module per AGENTS.md (Sprint-6 amendment, "Protocol
— A2A endpoint" section). Single owner of the A2A inbound receiver,
the task-lifecycle state machine, and chain linkage across the A2A
boundary.

Per ADR-003: incoming messages identify the target agent by entry-
point name; the endpoint resolves via :class:`PluginRegistry` (under
the ``agents`` :data:`PluginKind`) and dispatches to the agent pack's
``handle(payload, task=...)`` method.

Task lifecycle (state machine — single-writer, single-owner):

    created → running → succeeded | failed | cancelled

Transitions are mutated only by :meth:`A2AEndpoint._transition`; that
method validates the transition against
:data:`_LEGAL_STATE_TRANSITIONS` and refuses backwards / illegal
transitions with ``ValueError``. Cancellation lands in T13.

Chain linkage: every inbound message takes the caller-supplied
``parent_trace_id`` (mints one if absent) + a fresh ``child_trace_id``
(``uuid.uuid4().hex``). Both flow into ``a2a.task_*`` audit +
``decision_history.a2a_call`` rows so the cross-agent chain is
walkable end-to-end. Mirrors Sprint-2's hash-chain primitives
extended across the A2A boundary.

Six gates (in fixed order):

    1. Version negotiation (``A2A-Version`` header → T8 6-case
       matrix; only ``accepted`` / ``higher_minor_degraded`` proceed).
       Refusal: spec ``version_not_supported`` + ``Supported-A2A-
       Versions`` retry hint.

    2. Authentication (per-tenant pinned token via T5
       :class:`A2AAuthzClient`). Closed-enum
       :data:`A2AAuthzReason` → spec :data:`A2AErrorCode` map:

           a2a_anonymous_refused → invalid_request + anonymous_refused
           everything else        → invalid_request + tenant_token_invalid

       (T11 ``protocol/a2a_errors.py`` formalises the full map; T9's
       inline mapping covers the gates this module fires — see the
       ``_AUTHZ_REASON_TO_POLICY_REASON`` table below.)

    3. Wave-2 feature refusal (push-notification subscribe / task
       resumption / multimodal Part shapes all map to spec
       ``unsupported_operation`` + policy-reason
       ``wave2_feature_refused`` per Decision Lock #2). **Fires
       before routing** so a registered Wave-1 agent never receives
       Wave-2 traffic — relying on routing first would let a Wave-2
       method whose entry-point name happens to match an agent slip
       past the gate and reach the agent's handler.

    4. Routing (target agent → :class:`PluginRegistry.load` under the
       ``agents`` kind). :class:`PluginNotRegistered` and
       :class:`RegistrationRefused` BOTH map to spec
       ``method_not_found`` + policy-reason ``unknown_target``.
       Surfacing the registry's internal refusal vocabulary across
       the A2A wire would leak trust-state to remote callers; the
       :data:`A2APolicyRefusalReason` only carries
       ``unknown_target`` for routing failures.

    5. Task creation + dispatch (single-writer ``TaskState``
       transitions through :meth:`_create_task` →
       :meth:`_transition`). Lifecycle audit + decision rows emitted
       on every transition by :meth:`_emit_a2a_evidence`.

    6. Lifecycle transition emit. Audit + decision-history pipeline
       failures safe-swallow (token-free + payload-redacted log
       only); the primary outcome (success / refusal) propagates to
       the caller. Same discipline as Sprint-5
       ``_safe_audit_close_failure``.

Token-free invariant: the bearer token's ``value`` bytes NEVER
appear in :class:`A2AEndpointError.payload`, audit payloads, or
decision payloads. The T5 :class:`A2AAuthzClient` fixture validates
the token; the endpoint never sees the raw bytes after that point.

This module is **runtime-side** per the Sprint-6 T2 optional-
dependency contract (``_PROTOCOL_OPTIONAL_DEPS`` lists
``cognic_agentos.protocol.a2a_endpoint`` against the ``a2a``
SDK namespace). Construction calls :func:`require_a2a` so that
mounting the endpoint on a kernel-image deployment (which ships
without ``a2a-sdk`` per Sprint-5 R3 P1 / Sprint-6 T2 doctrine)
fails loudly with :class:`A2ANotAvailableError` instead of silently
degrading. The module ``import`` itself is tolerated to fail under
``stub_a2a_missing`` (the test fixture that simulates the kernel-
image posture); the constructor's ``require_a2a()`` is the
load-bearing gate. The dispatch ``agent.handle()`` call is the
SDK boundary: agents are registered via the ``agents`` plugin kind
and their handler entry-point is what consumes the protobuf-typed
payload.
"""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import logging
import time
import uuid
from typing import Any, Final

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
)
from cognic_agentos.protocol import (
    A2AAuthzReason,
    A2AErrorCode,
    A2APolicyRefusalReason,
    require_a2a,
)
from cognic_agentos.protocol.a2a_agent_cards import A2AAgentCardVerifier
from cognic_agentos.protocol.a2a_authz import A2AAuthzClient, A2AAuthzError
from cognic_agentos.protocol.a2a_version import negotiate_inbound_version
from cognic_agentos.protocol.plugin_registry import (
    PluginNotRegistered,
    PluginRegistry,
    RegistrationRefused,
)

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Closed-enum vocabulary
# ---------------------------------------------------------------------------


class TaskState(enum.Enum):
    """A2A task lifecycle state machine. Single-writer (the endpoint).

    Per A2A 1.0 spec the running-state set is open-ended, but
    Wave-1 only emits these five values; T13 ``a2a_cancellation``
    is the only path that mints :attr:`CANCELLED`.
    """

    CREATED = "created"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


#: Legal transitions. Backwards / cross-terminal moves refused with
#: ``ValueError``. Re-entering a terminal state is also refused
#: (the audit chain MUST NOT carry a ``succeeded → succeeded``
#: row; that would be a single-writer-violation symptom).
_LEGAL_STATE_TRANSITIONS: Final[dict[TaskState, frozenset[TaskState]]] = {
    TaskState.CREATED: frozenset({TaskState.RUNNING, TaskState.CANCELLED}),
    TaskState.RUNNING: frozenset({TaskState.SUCCEEDED, TaskState.FAILED, TaskState.CANCELLED}),
    TaskState.SUCCEEDED: frozenset(),
    TaskState.FAILED: frozenset(),
    TaskState.CANCELLED: frozenset(),
}


#: Audit-event-type literal per :class:`TaskState` transition. Not
#: a ``Literal[…]`` (the AuditEvent.event_type column is a free-form
#: string per Sprint-2); this is the closed dispatch table that
#: pins the wire-event vocabulary the audit chain emits.
_TRANSITION_TO_EVENT_TYPE: Final[dict[TaskState, str]] = {
    TaskState.CREATED: "a2a.task_received",
    TaskState.RUNNING: "a2a.task_running",
    TaskState.SUCCEEDED: "a2a.task_succeeded",
    TaskState.FAILED: "a2a.task_failed",
    TaskState.CANCELLED: "a2a.task_cancelled",
}


#: Closed map :data:`A2AAuthzReason` → :data:`A2APolicyRefusalReason`.
#: Anonymous is the only value that surfaces as ``anonymous_refused``;
#: every other authz failure is opaque to the remote caller as
#: ``tenant_token_invalid``. Surfacing finer-grained reasons (audience
#: mismatch, scope insufficient, revocation, vault-read failure) over
#: the A2A wire would leak token-state across tenants. The audit
#: chain still carries the original :data:`A2AAuthzReason` in the
#: payload's ``authz_reason`` field for examiners.
_AUTHZ_REASON_TO_POLICY_REASON: Final[dict[A2AAuthzReason, A2APolicyRefusalReason]] = {
    "a2a_anonymous_refused": "anonymous_refused",
    "a2a_token_missing": "tenant_token_invalid",
    "a2a_token_malformed": "tenant_token_invalid",
    "a2a_tenant_mismatch": "tenant_token_invalid",
    "a2a_token_revoked": "tenant_token_invalid",
    "a2a_vault_read_failed": "tenant_token_invalid",
    "a2a_audience_mismatch": "tenant_token_invalid",
    "a2a_scope_insufficient": "tenant_token_invalid",
}


#: Wave-2 method-name → feature sub-tag. T9 inspects the inbound
#: payload for these JSON-RPC method names and refuses with
#: ``unsupported_operation`` + ``wave2_feature_refused``. T11 will
#: subsume this list inside ``protocol/a2a_errors.py``; T9 carries
#: it inline so the gate fires today.
_WAVE2_METHOD_TO_FEATURE: Final[dict[str, str]] = {
    "tasks/pushNotificationConfig/set": "push_notification_subscribe",
    "tasks/pushNotificationConfig/get": "push_notification_subscribe",
    "tasks/resubscribe": "task_resumption",
}


#: Wave-2 ``Part`` field-name signals per the A2A 1.0 ``Part``
#: protobuf message (``a2a/types/a2a_pb2.pyi`` ships with
#: ``a2a-sdk == 1.0.2``). The Part oneof is:
#:
#:   - ``text``  (Wave-1 — free-form prose)
#:   - ``data``  (Wave-1 — Struct of business JSON)
#:   - ``raw``   (Wave-2 — file bytes)
#:   - ``url``   (Wave-2 — file URL)
#:
#: Any Part populated with ``raw`` or ``url`` is Wave-2 traffic
#: regardless of which JSON-RPC method delivered it. Per A2A-
#: CONFORMANCE.md §"Multi-modal payloads" + Decision Lock #2 we
#: refuse such payloads with ``unsupported_operation`` +
#: ``wave2_feature_refused`` BEFORE routing/dispatch so a Wave-1
#: agent never receives Wave-2 traffic.
#:
#: T9 R2 P2 reviewer correction: the Part discriminator is the
#: presence of these protobuf-JSON field names on actual ``parts[]``
#: entries — NOT a synthetic ``kind`` discriminator (the upstream
#: spec has no ``kind`` field) and NOT the older A2A 0.3 ``mimeType``
#: name (1.0 renamed it to ``media_type`` / JSON ``mediaType``).
#: Recursing through arbitrary dict trees was also wrong: it
#: erroneously refused Wave-1 ``data`` parts that legitimately carry
#: business JSON containing keys like ``kind`` or ``mimeType``.
_WAVE2_PART_FIELDS: Final[frozenset[str]] = frozenset({"raw", "url"})


#: Wave-2 ``media_type`` prefixes per the A2A 1.0 ``Part.media_type``
#: field (JSON serialised as ``mediaType``; protobuf JSON also accepts
#: the snake-case ``media_type`` alias). Image / audio / video media
#: types are Wave-2 by spec category. ``application/*`` (PDFs,
#: arbitrary binaries) is left to the ``raw``/``url`` field-presence
#: check above — a PDF Part necessarily sets ``raw`` or ``url`` and
#: gets refused on that signal.
_WAVE2_MEDIA_TYPE_PREFIXES: Final[tuple[str, ...]] = (
    "image/",
    "audio/",
    "video/",
)


#: Field names whose values MUST NOT be descended into when scanning
#: for Wave-2 Parts. ``data`` is the Wave-1 business-JSON Struct (a
#: data part legitimately carries ``{"mimeType": "image/png"}`` as
#: business metadata; that's not a Wave-2 multimodal part — it's
#: caller-supplied data the agent will route through its own
#: classifier). ``metadata`` is the operator-supplied free-form
#: per-Part Struct on the Part proto and the Message proto. The
#: walker descends through every other key by name (params, message,
#: history, ...) so future A2A method shapes that nest ``parts[]``
#: at new paths are still covered.
_PART_DESCENT_BLOCKED_KEYS: Final[frozenset[str]] = frozenset({"data", "metadata"})


#: Hard bounds for the Wave-2 envelope walker per T9 R3 P2 reviewer
#: correction. The walker is **iterative** (explicit stack, not
#: Python recursion) so an attacker-controlled deeply-nested JSON
#: payload cannot raise :class:`RecursionError` and bypass the closed
#: refusal path. If either bound is exceeded the walker fails closed:
#: refuses with sub-tag ``payload_unscannable`` so examiners can
#: distinguish a deliberate-Wave-2 refusal (``multimodal_payload``)
#: from a defensive refusal of a payload too large to scan safely.
#:
#: 64 levels of nesting is well above any reasonable A2A envelope
#: depth (typical: ``params.message.history[i].parts[j]`` is 5
#: levels). 10 000 nodes is well above any reasonable A2A message
#: size — a 1 MB payload at ~50 bytes/node would still fit.
_MAX_PAYLOAD_DEPTH: Final[int] = 64
_MAX_PAYLOAD_NODES: Final[int] = 10_000


# ---------------------------------------------------------------------------
# Dataclasses + exception
# ---------------------------------------------------------------------------


@dataclasses.dataclass(slots=True)
class TaskRecord:
    """Per-task state container — owned by the endpoint, mutated only
    via :meth:`A2AEndpoint._transition`.

    Not frozen: ``state`` / ``updated_at`` / ``response_payload_digest``
    / ``error_code`` are mutated through the single-writer
    :meth:`_transition`. The dataclass is :func:`slots` so the field
    set is locked at class-definition time (no ad-hoc attribute
    extension).
    """

    task_id: str
    target_agent: str
    parent_trace_id: str
    child_trace_id: str
    state: TaskState
    created_at: float
    updated_at: float
    payload_digest: str
    response_payload_digest: str | None = None
    error_code: A2AErrorCode | None = None


class A2AEndpointError(Exception):
    """Inbound A2A handling failure with a closed-enum spec error
    code + structured payload for audit emission.

    Per Sprint-5 T15 R1 P2 #3 doctrine: raw lower-layer exception
    text NEVER appears in the message body; ``type(exc).__name__``
    lands in the payload only (under ``error_type``). The bearer
    token bytes never appear in any field.
    """

    def __init__(self, code: A2AErrorCode, message: str = "", **payload: Any) -> None:
        self.code: A2AErrorCode = code
        self.payload: dict[str, Any] = payload
        super().__init__(f"{code}: {message}" if message else code)


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


class A2AEndpoint:
    """Single owner of the A2A inbound receiver + task lifecycle.

    Critical-controls invariants:

    - Single-writer for ``TaskState`` transitions
      (:meth:`_transition` is the only mutation path; backwards /
      illegal moves raise ``ValueError``).
    - Audit emission on every transition (``a2a.task_*`` events).
    - Decision-history mirror of every transition (parallel rows;
      same ``request_id`` + ``tenant_id`` correlate the two
      surfaces — T11 substrate).
    - Anonymous refusal (every call requires
      :class:`A2AAuthzClient` validation; no anonymous bypass).
    - Wave-2 feature refusal per Decision Lock #2 (push-notification
      subscribe / multi-modal payloads / long-running task
      resumption refused with ``wave2_feature_refused``).
    - Token-free audit / decision payloads (the bearer token's
      ``value`` bytes never reach the chain).

    Runtime-side construction: ``__init__`` calls :func:`require_a2a`
    so mounting :class:`A2AEndpoint` on a kernel-image deployment
    (which deliberately ships without ``a2a-sdk`` per Sprint-5 R3 P1
    / Sprint-6 T2 doctrine) raises :class:`A2ANotAvailableError`
    immediately. Mirrors the Sprint-5
    :class:`MCPHost.__init__` / :func:`require_mcp` regression. The
    module itself is listed in :data:`_PROTOCOL_OPTIONAL_DEPS`
    against the ``a2a`` SDK namespace; admission-side modules
    (``a2a_authz``, ``a2a_agent_cards``, ``a2a_schema``,
    ``a2a_version``, ``a2a_errors``, ``a2a_capability_negotiation``,
    ``a2a_cancellation``) are NOT in that map and construct without
    the SDK — only :class:`A2AEndpoint` /
    :class:`A2AStreamingHandler` / :class:`A2AArtifactsManager` gate
    on it at construction.

    Once construction succeeds, the SDK boundary at request time is
    the dispatch :meth:`agent.handle` call (the agent pack
    consumes the protobuf-typed payload); the endpoint itself
    orchestrates admission-side modules around that dispatch.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        plugin_registry: PluginRegistry,
        authz_client: A2AAuthzClient,
        agent_card_verifier: A2AAgentCardVerifier,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        # T9 R1 P2 #5 — runtime-side SDK gate. ``A2AEndpoint`` is in
        # the T2 ``_PROTOCOL_OPTIONAL_DEPS`` map; mounting it on a
        # kernel-image deployment (no ``a2a-sdk``) MUST raise
        # :class:`A2ANotAvailableError` immediately so the operator
        # rebuilds with ``--extra adapters`` rather than discovering
        # the gap at first inbound traffic. Mirrors Sprint-5
        # ``MCPHost.__init__`` which calls ``require_mcp()`` for the
        # same reason.
        require_a2a()
        self._settings = settings
        self._registry = plugin_registry
        self._authz = authz_client
        self._cards = agent_card_verifier
        self._audit = audit_store
        self._dh = decision_history_store
        self._tasks: dict[str, TaskRecord] = {}

    # --- inbound entry --------------------------------------------------

    async def handle(
        self,
        *,
        target_agent: str,
        payload: bytes,
        authorization_header: str | None,
        a2a_version_header: str | None,
        parent_trace_id: str | None,
        tenant_id: str,
        request_id: str,
    ) -> dict[str, Any]:
        """Inbound entry point. Walks the 6 gates in fixed order and
        either dispatches to the resolved agent (returning the
        handler's response dict) or raises :class:`A2AEndpointError`
        with one of the closed-enum spec codes.

        Never propagates a raw exception to the caller — handler
        exceptions get wrapped as ``internal_error``; gate refusals
        carry the spec code that matches the gate.
        """
        # Mint the cross-agent chain trace ids up front so even
        # gate refusals (no task created) can correlate against the
        # caller's parent trace.
        effective_parent_trace_id = parent_trace_id or uuid.uuid4().hex
        child_trace_id = uuid.uuid4().hex

        # Gate 1 — version negotiation.
        # Pre-task refusals all share the same chain-linkage payload
        # (parent + child trace ids + payload digest + target agent +
        # error code + optional policy reason). T9 R1 P2 #1 reviewer
        # correction: every gate refusal MUST emit a chained audit +
        # decision_history row carrying the caller's parent trace +
        # the locally-minted child trace, so the cross-agent chain is
        # walkable end-to-end including the refusal leg.
        payload_digest = hashlib.sha256(payload).hexdigest()

        decision = negotiate_inbound_version(
            a2a_version_header=a2a_version_header,
        )
        if decision.outcome not in ("accepted", "higher_minor_degraded"):
            await self._emit_refusal_evidence(
                event_type="a2a.task_refused",
                request_id=request_id,
                tenant_id=tenant_id,
                target_agent=target_agent,
                parent_trace_id=effective_parent_trace_id,
                child_trace_id=child_trace_id,
                payload_digest=payload_digest,
                error_code="version_not_supported",
                gate="version",
                extra={
                    "outcome": decision.outcome,
                    "supported": decision.response_header_value,
                },
            )
            raise A2AEndpointError(
                "version_not_supported",
                f"A2A version negotiation refused: {decision.outcome}",
                outcome=decision.outcome,
                supported=decision.response_header_value,
            )

        # Gate 2 — authentication.
        try:
            await self._authz.validate_inbound_token(
                authorization_header=authorization_header,
                tenant_id=tenant_id,
                request_id=request_id,
            )
        except A2AAuthzError as authz_exc:
            policy_reason = _AUTHZ_REASON_TO_POLICY_REASON[authz_exc.reason]
            spec_code: A2AErrorCode = "invalid_request"
            await self._emit_refusal_evidence(
                event_type="a2a.task_refused",
                request_id=request_id,
                tenant_id=tenant_id,
                target_agent=target_agent,
                parent_trace_id=effective_parent_trace_id,
                child_trace_id=child_trace_id,
                payload_digest=payload_digest,
                error_code=spec_code,
                policy_reason=policy_reason,
                gate="authn",
                extra={"authz_reason": authz_exc.reason},
            )
            raise A2AEndpointError(
                spec_code,
                "A2A authorization refused",
                policy_reason=policy_reason,
                authz_reason=authz_exc.reason,
            ) from authz_exc

        # Gate 3 — Wave-2 feature refusal (runs before routing so a
        # registered Wave-1 agent never receives Wave-2 traffic; a
        # method/payload pair that matches a registered agent name
        # would otherwise slip past the gate at routing time).
        wave2_feature = self._classify_wave2_feature(payload)
        if wave2_feature is not None:
            await self._emit_refusal_evidence(
                event_type="a2a.task_refused",
                request_id=request_id,
                tenant_id=tenant_id,
                target_agent=target_agent,
                parent_trace_id=effective_parent_trace_id,
                child_trace_id=child_trace_id,
                payload_digest=payload_digest,
                error_code="unsupported_operation",
                policy_reason="wave2_feature_refused",
                gate="wave2",
                extra={"wave2_feature": wave2_feature},
            )
            raise A2AEndpointError(
                "unsupported_operation",
                f"Wave-2 feature refused: {wave2_feature}",
                policy_reason="wave2_feature_refused",
                wave2_feature=wave2_feature,
            )

        # Gate 4 — routing.
        try:
            agent = self._registry.load("agents", target_agent)
        except (PluginNotRegistered, RegistrationRefused) as reg_exc:
            await self._emit_refusal_evidence(
                event_type="a2a.task_refused",
                request_id=request_id,
                tenant_id=tenant_id,
                target_agent=target_agent,
                parent_trace_id=effective_parent_trace_id,
                child_trace_id=child_trace_id,
                payload_digest=payload_digest,
                error_code="method_not_found",
                policy_reason="unknown_target",
                gate="routing",
                extra={"registry_error_class": type(reg_exc).__name__},
            )
            raise A2AEndpointError(
                "method_not_found",
                "target agent not resolvable (per ADR-002 plugin registry)",
                policy_reason="unknown_target",
                target_agent=target_agent,
            ) from reg_exc

        # Gate 5 — task creation + dispatch.
        task = self._create_task(
            target_agent=target_agent,
            parent_trace_id=effective_parent_trace_id,
            child_trace_id=child_trace_id,
            payload=payload,
            request_id=request_id,
            tenant_id=tenant_id,
        )
        await self._emit_a2a_evidence(
            task=task,
            transition=TaskState.CREATED,
            request_id=request_id,
            tenant_id=tenant_id,
        )

        await self._transition_async(
            task=task,
            new_state=TaskState.RUNNING,
            request_id=request_id,
            tenant_id=tenant_id,
        )

        try:
            response: Any = await agent.handle(payload, task=task)
        except Exception as handler_exc:
            error_class = type(handler_exc).__name__
            await self._transition_async(
                task=task,
                new_state=TaskState.FAILED,
                request_id=request_id,
                tenant_id=tenant_id,
                error_class=error_class,
            )
            raise A2AEndpointError(
                "internal_error",
                "agent handler raised",
                error_type=error_class,
            ) from handler_exc

        # Per A2A 1.0 the handler MUST return a JSON-RPC-shaped dict;
        # a non-dict is a protocol violation refused as
        # ``invalid_agent_response``. We surface this BEFORE emitting
        # the SUCCEEDED transition so the audit chain does not record
        # a success for what was actually an invalid response.
        if not isinstance(response, dict):
            await self._transition_async(
                task=task,
                new_state=TaskState.FAILED,
                request_id=request_id,
                tenant_id=tenant_id,
                error_class=type(response).__name__,
                error_code="invalid_agent_response",
            )
            raise A2AEndpointError(
                "invalid_agent_response",
                "agent handler returned a non-dict response",
                response_type=type(response).__name__,
            )

        response_dict: dict[str, Any] = response

        # T9 R1 P2 #3 reviewer correction: the response dict MUST
        # also be canonicalisable (no bytes / non-finite floats /
        # tuples / non-string keys). The audit chain hashes the
        # response_payload_digest into ``a2a.task_succeeded``; if the
        # response is not canonical-form-clean, the digest would have
        # been ``None`` (silently lost evidence) AND the response
        # cannot be re-encoded by any downstream JSON-RPC envelope
        # builder. Refuse with ``invalid_agent_response`` BEFORE
        # SUCCEEDED so the audit chain matches the wire outcome.
        try:
            response_digest = _canonicalise_response_digest(response_dict)
        except (TypeError, ValueError) as canon_exc:
            await self._transition_async(
                task=task,
                new_state=TaskState.FAILED,
                request_id=request_id,
                tenant_id=tenant_id,
                error_class=type(canon_exc).__name__,
                error_code="invalid_agent_response",
            )
            raise A2AEndpointError(
                "invalid_agent_response",
                "agent handler returned a non-canonical response",
                response_canonical_error_class=type(canon_exc).__name__,
            ) from canon_exc

        await self._transition_async(
            task=task,
            new_state=TaskState.SUCCEEDED,
            request_id=request_id,
            tenant_id=tenant_id,
            response_digest=response_digest,
        )
        return response_dict

    # --- single-writer state machine -----------------------------------

    def _create_task(
        self,
        *,
        target_agent: str,
        parent_trace_id: str,
        child_trace_id: str,
        payload: bytes,
        request_id: str,
        tenant_id: str,
    ) -> TaskRecord:
        now = time.time()
        record = TaskRecord(
            task_id=uuid.uuid4().hex,
            target_agent=target_agent,
            parent_trace_id=parent_trace_id,
            child_trace_id=child_trace_id,
            state=TaskState.CREATED,
            created_at=now,
            updated_at=now,
            payload_digest=hashlib.sha256(payload).hexdigest(),
        )
        self._tasks[record.task_id] = record
        return record

    def _transition(
        self,
        task: TaskRecord,
        new_state: TaskState,
        *,
        response_digest: str | None = None,
        error_class: str | None = None,
        error_code: A2AErrorCode | None = None,
    ) -> None:
        """Single-writer transition. Refuses backwards / illegal
        transitions with ``ValueError``; updates ``state`` /
        ``updated_at`` / ``response_payload_digest`` / ``error_code``
        in place.

        ``error_code`` (T9 R1 P2 #4 reviewer correction) is the
        explicit spec wire code the audit + decision payloads
        record on a FAILED transition. The earlier draft hardcoded
        ``internal_error`` for every failure path, which made the
        audit row disagree with the wire error returned to the
        caller (e.g., ``invalid_agent_response`` returned to the
        caller, ``internal_error`` written into the chain — examiner
        evidence diverges from caller observation). The caller
        passes the code that matches what it raised; ``None`` falls
        back to ``internal_error`` for raw handler-exception paths
        where we genuinely don't know any more than that.
        """
        legal = _LEGAL_STATE_TRANSITIONS[task.state]
        if new_state not in legal:
            raise ValueError(
                f"illegal A2A task transition {task.state.value} → "
                f"{new_state.value} for task {task.task_id} "
                f"(legal next: {sorted(s.value for s in legal)})"
            )
        task.state = new_state
        task.updated_at = time.time()
        if response_digest is not None:
            task.response_payload_digest = response_digest
        if new_state is TaskState.FAILED:
            task.error_code = error_code if error_code is not None else "internal_error"

    async def _transition_async(
        self,
        *,
        task: TaskRecord,
        new_state: TaskState,
        request_id: str,
        tenant_id: str,
        response_digest: str | None = None,
        error_class: str | None = None,
        error_code: A2AErrorCode | None = None,
    ) -> None:
        """Apply the transition + emit the parallel audit + decision
        rows. Pipeline failures safe-swallow per the Sprint-5
        ``_emit_call_evidence`` discipline.

        ``error_code`` plumbs the explicit spec code from the caller
        through to :meth:`_transition` so the audit/decision payload
        for a FAILED transition matches the wire error returned to
        the caller (T9 R1 P2 #4).
        """
        self._transition(
            task,
            new_state,
            response_digest=response_digest,
            error_class=error_class,
            error_code=error_code,
        )
        await self._emit_a2a_evidence(
            task=task,
            transition=new_state,
            request_id=request_id,
            tenant_id=tenant_id,
            error_class=error_class,
        )

    # --- evidence emission ---------------------------------------------

    async def _emit_refusal_evidence(
        self,
        *,
        event_type: str,
        request_id: str,
        tenant_id: str,
        target_agent: str,
        parent_trace_id: str,
        child_trace_id: str,
        payload_digest: str,
        error_code: A2AErrorCode,
        gate: str,
        policy_reason: A2APolicyRefusalReason | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """T9 R1 P2 #1 — chain-linkage emission for pre-task gate
        refusals.

        Pre-task refusals (version / authn / wave-2 / routing) raise
        before any :class:`TaskRecord` is minted, so the per-task
        ``_emit_a2a_evidence`` path doesn't fire. Without this helper
        the chain would be silent on every refusal — examiners
        querying the audit chain by request_id would see no row at
        all for refused calls, which is the exact divergence ADR-003
        + A2A-CONFORMANCE.md "every A2A call is chain-linked" forbid.

        Emits parallel ``audit_event`` (``a2a.task_refused``) +
        ``decision_history`` (``a2a_call`` with ``transition='refused'``)
        rows. Same safe-swallow discipline as
        :meth:`_emit_a2a_evidence` — pipeline failures log token-free
        and let the refusal propagate to the caller. The audit row
        carries ``gate`` so examiners can identify which boundary
        fired without parsing the closed-enum codes.

        ``policy_reason`` is optional because the version gate has no
        AgentOS policy reason — the refusal is wire-protocol-spec
        directly. Authn / wave-2 / routing all carry one.
        """
        common: dict[str, Any] = {
            "target_agent": target_agent,
            "parent_trace_id": parent_trace_id,
            "child_trace_id": child_trace_id,
            "payload_digest": payload_digest,
            "error_code": error_code,
            "gate": gate,
        }
        if policy_reason is not None:
            common["policy_reason"] = policy_reason
        if extra:
            common.update(extra)

        try:
            await self._audit.append(
                AuditEvent(
                    event_type=event_type,
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload=dict(common),
                )
            )
        except Exception as audit_exc:
            _LOG.warning(
                "audit append failed while emitting %s for A2A refusal "
                "(target_agent=%s request_id=%s gate=%s "
                "audit_error_type=%s); refusal still propagates to the "
                "caller.",
                event_type,
                target_agent,
                request_id,
                gate,
                type(audit_exc).__name__,
            )

        decision_payload = dict(common)
        decision_payload["transition"] = "refused"
        try:
            await self._dh.append(
                DecisionRecord(
                    decision_type="a2a_call",
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload=decision_payload,
                )
            )
        except Exception as decision_exc:
            _LOG.warning(
                "decision_history append failed for a2a_call refusal "
                "(target_agent=%s request_id=%s gate=%s "
                "decision_error_type=%s); refusal still propagates to "
                "the caller.",
                target_agent,
                request_id,
                gate,
                type(decision_exc).__name__,
            )

    async def _emit_a2a_evidence(
        self,
        *,
        task: TaskRecord,
        transition: TaskState,
        request_id: str,
        tenant_id: str,
        error_class: str | None = None,
    ) -> None:
        """Emit the parallel ``audit_event`` + ``decision_history``
        rows for one task transition.

        Per Sprint-5 T11 discipline: every ``request_id`` flowing
        through ``handle`` produces a sequence of (transition →
        audit row + decision_history row) pairs, both correlated by
        ``request_id``. Audit-pipeline failure does NOT mask the
        primary outcome; same for decision-history-pipeline failure.

        Token-free + payload-redacted: the bearer token bytes never
        appear here; the inbound payload bytes never appear either
        (only the SHA-256 digest in ``payload_digest``). ``error_class``
        carries only ``type(exc).__name__`` — the raw exception
        message is dropped on the floor by design.
        """
        common: dict[str, Any] = {
            "task_id": task.task_id,
            "target_agent": task.target_agent,
            "parent_trace_id": task.parent_trace_id,
            "child_trace_id": task.child_trace_id,
            "task_state": task.state.value,
            "payload_digest": task.payload_digest,
        }
        if task.response_payload_digest is not None:
            common["response_payload_digest"] = task.response_payload_digest
        if error_class is not None:
            common["error_class"] = error_class
        if task.error_code is not None:
            common["error_code"] = task.error_code

        event_type = _TRANSITION_TO_EVENT_TYPE[transition]
        try:
            await self._audit.append(
                AuditEvent(
                    event_type=event_type,
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload=dict(common),
                )
            )
        except Exception as audit_exc:
            _LOG.warning(
                "audit append failed while emitting %s for A2A task "
                "(task_id=%s target_agent=%s request_id=%s "
                "audit_error_type=%s); primary outcome still "
                "propagates to the caller.",
                event_type,
                task.task_id,
                task.target_agent,
                request_id,
                type(audit_exc).__name__,
            )

        decision_payload = dict(common)
        decision_payload["transition"] = transition.value
        try:
            await self._dh.append(
                DecisionRecord(
                    decision_type="a2a_call",
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload=decision_payload,
                )
            )
        except Exception as decision_exc:
            _LOG.warning(
                "decision_history append failed for a2a_call "
                "(task_id=%s target_agent=%s request_id=%s "
                "transition=%s decision_error_type=%s); primary "
                "outcome still propagates to the caller.",
                task.task_id,
                task.target_agent,
                request_id,
                transition.value,
                type(decision_exc).__name__,
            )

    # --- helpers --------------------------------------------------------

    @staticmethod
    def _classify_wave2_feature(payload: bytes) -> str | None:
        """Inspect the inbound JSON-RPC payload for Wave-2 traffic.
        Returns the feature sub-tag (e.g.
        ``push_notification_subscribe`` / ``multimodal_payload`` /
        ``payload_unscannable``) if Wave-2 / unscannable; ``None``
        if the payload is Wave-1 / opaque / unparseable.

        Three signals checked:

          1. **JSON-RPC method name** — push-notification subscribe
             + task resumption per :data:`_WAVE2_METHOD_TO_FEATURE`
             (R1 P2 #2).

          2. **A2A 1.0 ``Part`` shape** — entries of any ``parts``
             array whose protobuf-JSON field names indicate Wave-2:
             ``raw`` (file bytes), ``url`` (file URL), or
             ``mediaType``/``media_type`` starting with a Wave-2
             prefix. Scoped to actual ``parts[]`` arrays; skips
             Wave-1 ``data`` / ``metadata`` Struct values (R2 P2).

          3. **Walker bounds** — :func:`_scan_envelope_for_wave2`
             is iterative + depth/node-bounded, and returns
             ``"payload_unscannable"`` if the limits are exceeded.
             Plus :class:`RecursionError` from the C-side
             ``json`` decoder itself maps to the same fail-closed
             sub-tag (R5 P2). T9 R3 P2 + R5 P2 reviewer
             corrections: an attacker-controlled deeply-nested
             JSON payload MUST NOT raise :class:`RecursionError`
             before the closed refusal path fires — neither in our
             walker nor in the upstream decoder — fail closed with
             chained refusal evidence instead.

        Unparseable payloads (``ValueError`` / ``UnicodeDecodeError``
        from ``json.loads``) are NOT refused here — they flow to the
        agent's handler, which is responsible for spec-conformant
        ``parse_error`` / ``invalid_request`` responses on its own
        protobuf surface. T9's gate only refuses traffic we
        explicitly know is Wave-2 OR that we can't safely scan.
        """
        try:
            decoded = json.loads(payload)
        except (ValueError, UnicodeDecodeError):
            return None
        except RecursionError:
            # T9 R5 P2 reviewer correction — Python's CPython
            # ``_json`` decoder is recursive over nested objects /
            # arrays in C; extremely deep valid JSON (~10k+
            # nested) trips the C-side recursion budget and raises
            # ``RecursionError`` BEFORE the iterative
            # :func:`_scan_envelope_for_wave2` walker runs. That
            # escapes the closed :class:`A2AEndpointError` refusal
            # path AND skips the chained ``a2a.task_refused``
            # evidence emission. Map this to the same fail-closed
            # path the walker uses on its own depth/node limit
            # exceedance — sub-tag ``payload_unscannable``, so
            # examiners can distinguish defence-side refusals from
            # deliberate-Wave-2 refusals.
            return "payload_unscannable"
        if not isinstance(decoded, dict):
            return None

        method = decoded.get("method")
        if isinstance(method, str):
            method_feature = _WAVE2_METHOD_TO_FEATURE.get(method)
            if method_feature is not None:
                return method_feature

        return _scan_envelope_for_wave2(decoded)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _scan_envelope_for_wave2(decoded: Any) -> str | None:
    """Iterative + depth/node-bounded walker over the parsed JSON-RPC
    envelope, looking for any ``parts`` array whose entries are
    Wave-2 A2A 1.0 ``Part`` shapes.

    Per the A2A 1.0 ``Part`` proto (verified against
    ``a2a/types/a2a_pb2.pyi`` shipped with ``a2a-sdk == 1.0.2``):

        message Part {
            oneof part {
                string text = 1;
                bytes  raw  = 2;
                string url  = 3;
                Value  data = 4;
            }
            Struct metadata     = 5;
            string filename     = 6;
            string media_type   = 7;
        }

    Returns:

      - ``"multimodal_payload"`` if any ``parts[]`` entry has a
        Wave-2 oneof field set (``raw`` / ``url``) or a Wave-2
        ``mediaType`` / ``media_type`` prefix.
      - ``"payload_unscannable"`` if the walker's depth or node-count
        bound is exceeded (T9 R3 P2 fail-closed path — an attacker-
        controlled deeply-nested payload cannot escape the closed
        refusal path by raising :class:`RecursionError`).
      - ``None`` if the payload contains no Wave-2 ``Part`` shapes.

    Walker discipline:

      - **Iterative** (explicit ``list`` stack — no Python recursion).
        T9 R3 P2 reviewer correction: the prior recursive walker
        was unbounded by anything other than Python's default
        recursion limit (1000), so a 1500-level deep JSON payload
        would raise raw ``RecursionError`` BEFORE the gate decided
        anything — escaping the closed :class:`A2AEndpointError`
        refusal path AND skipping the chain-linkage emission.
      - **Bounded by :data:`_MAX_PAYLOAD_DEPTH` (64) and
        :data:`_MAX_PAYLOAD_NODES` (10 000)**. Either limit fires
        ``"payload_unscannable"`` immediately; the gate then refuses
        with chained refusal evidence carrying the sub-tag, so
        examiners can distinguish defence-side refusals from
        deliberate-Wave-2 refusals.
      - **Scoped to ``parts[]`` lists** — only entries of a list
        whose dict-key is ``parts`` are interpreted as ``Part``
        objects. The walker descends through every other dict-key
        in the envelope structure (``params``, ``message``,
        ``history``, ...) so future A2A method shapes that nest
        ``parts[]`` at new paths still get covered, but it does NOT
        descend through ``data`` (Wave-1 business JSON Struct — a
        data part legitimately carries ``{"mimeType": "image/png"}``
        as caller business metadata) or ``metadata`` (operator-
        supplied per-Part Struct + per-Message Struct).
    """
    if not isinstance(decoded, dict | list):
        return None

    stack: list[tuple[Any, int]] = [(decoded, 0)]
    members_visited = 0
    while stack:
        node, depth = stack.pop()
        if depth > _MAX_PAYLOAD_DEPTH:
            return "payload_unscannable"

        if isinstance(node, dict):
            parts = node.get("parts")
            if isinstance(parts, list):
                for entry in parts:
                    members_visited += 1
                    if members_visited > _MAX_PAYLOAD_NODES:
                        return "payload_unscannable"
                    if isinstance(entry, dict) and _is_wave2_part(entry):
                        return "multimodal_payload"
            # T9 R4 P2 #1: count every key/value visit, not just the
            # ones that get pushed onto the stack as containers. A flat
            # dict of 20 000 scalar members would otherwise pop ONE
            # container, walk through 20 000 items, and complete
            # without tripping the bound — burning CPU on attacker-
            # controlled JSON structure before the gate decides
            # anything. Counting every member tightens the budget to
            # real work performed.
            for k, v in node.items():
                members_visited += 1
                if members_visited > _MAX_PAYLOAD_NODES:
                    return "payload_unscannable"
                if k in _PART_DESCENT_BLOCKED_KEYS or k == "parts":
                    continue
                if isinstance(v, dict | list):
                    stack.append((v, depth + 1))
        elif isinstance(node, list):
            for v in node:
                members_visited += 1
                if members_visited > _MAX_PAYLOAD_NODES:
                    return "payload_unscannable"
                if isinstance(v, dict | list):
                    stack.append((v, depth + 1))
    return None


def _is_wave2_part(part: dict[str, Any]) -> bool:
    """Return True iff a parsed JSON Part entry represents Wave-2
    traffic per the A2A 1.0 ``Part`` proto (``raw`` / ``url`` oneof
    field set, or ``mediaType`` / ``media_type`` indicating Wave-2
    media category).

    Field-presence semantics: protobuf-JSON serialises an unset
    oneof field by omitting it, and a set ``raw`` field appears as a
    base64 string. We refuse on key presence — even an empty-string
    ``url`` or zero-length ``raw`` indicates the agent declared a
    Wave-2 oneof branch, which is enough signal to refuse.

    T9 R4 P2 #2 — both protobuf-JSON aliases (``mediaType`` /
    ``media_type``) are checked **independently**. The earlier
    ``part.get("mediaType") or part.get("media_type")``
    short-circuited on the first truthy alias, so a payload
    declaring ``{"mediaType": "application/json", "media_type":
    "image/png"}`` would return ``"application/json"`` (truthy
    Wave-1) and bypass refusal even though a future protobuf-JSON
    parser that prefers the canonical snake-case field name would
    surface ``"image/png"`` to the agent. Defence-in-depth: if
    EITHER alias has a Wave-2 prefix, refuse; non-string values on
    one alias must NOT mask a Wave-2 string on the other.
    """
    if any(f in part for f in _WAVE2_PART_FIELDS):
        return True
    for alias in ("mediaType", "media_type"):
        media = part.get(alias)
        if isinstance(media, str) and any(
            media.lower().startswith(prefix) for prefix in _WAVE2_MEDIA_TYPE_PREFIXES
        ):
            return True
    return False


def _canonicalise_response_digest(response: dict[str, Any]) -> str:
    """Return SHA-256 digest of the canonicalised handler response.

    Uses :func:`canonical_bytes` so the digest is computed over the
    SAME bytes the audit chain hashes — drift between the response-
    digest column and the actual evidence row would make the
    response-payload-digest meaningless to examiners.

    Raises ``TypeError`` / ``ValueError`` if the response is not
    canonical-form-clean (bytes, non-finite floats, tuples, non-
    string dict keys, naive datetimes, ...). The caller maps these
    onto :data:`A2AErrorCode` ``invalid_agent_response`` so the
    audit chain agrees with the wire error returned to the caller —
    the earlier draft's ``return None`` on canonicalisation failure
    silently produced a SUCCEEDED transition + missing digest, which
    is the exact divergence the chain is meant to prevent (T9 R1 P2
    #3 reviewer correction).
    """
    return hashlib.sha256(canonical_bytes(response)).hexdigest()


__all__ = (
    "A2AEndpoint",
    "A2AEndpointError",
    "TaskRecord",
    "TaskState",
)
