"""protocol/a2a_streaming.py — A2A 1.0 task streaming wire-format adapter.

NOT portal/UI SSE — that's Sprint 7B per ADR-020 §"Implementation
phases". The two surfaces are distinct:

    | Surface              | Sprint  | Wire format
    | -------------------- | ------- | -------------------------------------
    | A2A task streaming   | 6 (T10) | A2A 1.0 ``StreamResponse`` protobuf
    | UI event-stream SSE  | 7B      | W3C Server-Sent Events (text/event-stream)

This module ONLY implements A2A's spec wire format. Per ADR-003 +
Sprint-6 plan-of-record T10.

Authoritative wire-format contract (verified against
``a2a-sdk == 1.0.2``, ``a2a/types/a2a_pb2.pyi``):

    StreamResponse {
        oneof payload {
            Task                    task            = 1;  // initial Task envelope
            Message                 message         = 2;  // synchronous reply
            TaskStatusUpdateEvent   status_update   = 3;  // lifecycle transition
            TaskArtifactUpdateEvent artifact_update = 4;  // artifact chunk
        }
    }

    TaskStatusUpdateEvent { task_id; context_id; TaskStatus status; metadata }
    TaskArtifactUpdateEvent { task_id; context_id; Artifact artifact;
                              append; last_chunk; metadata }

Lifecycle progress / completion / failure ride
``TaskStatusUpdateEvent.status.state`` (one of 9 SDK ``TaskState``
enum values: ``TASK_STATE_SUBMITTED``, ``TASK_STATE_WORKING``,
``TASK_STATE_COMPLETED``, ``TASK_STATE_FAILED``, ``TASK_STATE_CANCELED``,
``TASK_STATE_INPUT_REQUIRED``, ``TASK_STATE_REJECTED``,
``TASK_STATE_AUTH_REQUIRED``, plus ``TASK_STATE_UNSPECIFIED`` which
is never emitted). Artifact streaming rides
``TaskArtifactUpdateEvent`` with ``append`` / ``last_chunk`` flags.

There is no textual ``task.progress`` / ``task.completed`` /
``task.failed`` envelope vocabulary in the spec — those were the
day-1 plan-of-record sketch and the plan skeleton is bracketed as
historical (T10 R0 P3).

T10 doctrines (locked before implementation):

    1. **SDK protobuf JSON only, via T6 schema-module boundary.**
       Envelopes built exclusively via the lazy re-exports on
       :mod:`cognic_agentos.protocol.a2a_schema` (``StreamResponse``,
       ``TaskStatusUpdateEvent``, ``TaskArtifactUpdateEvent``,
       ``TaskStatus``, ``TaskState``); wire encoding via
       :func:`google.protobuf.json_format.MessageToJson`. No
       hand-rolled envelope JSON in the wire path. Direct imports of
       ``a2a.types`` / ``a2a.types.a2a_pb2`` are forbidden — every
       SDK type used here MUST be in
       :data:`a2a_schema._REEXPORTED_TYPE_NAMES` so the T6 drift-
       gate covers the full wire surface (T10 R1 P2 #2).

    2. **Runtime-side SDK gate at construction.**
       :class:`A2AStreamingEmitter` is in
       :data:`_PROTOCOL_OPTIONAL_DEPS` alongside ``a2a_endpoint`` +
       ``a2a_artifacts``. ``__init__`` calls :func:`require_a2a` so
       mounting on a kernel-image deployment (no ``a2a-sdk``) fails
       loudly with :class:`A2ANotAvailableError` immediately. Mirrors
       T9 :class:`A2AEndpoint` / Sprint-5 :class:`MCPHost`.

    3. **Chain-linkage evidence per envelope.** Every emitted
       :class:`StreamResponse` produces parallel ``audit_event``
       (``a2a.stream_chunk``) + ``decision_history`` (``a2a_stream``)
       rows carrying payload digest, stream sequence, task / context
       ids, envelope kind (one of the four oneof field names), and
       parent / child trace ids the upstream T9 endpoint minted.
       Audit + decision pipeline failures safe-swallow per the
       Sprint-5 ``_emit_call_evidence`` discipline (mirrors T9
       ``_emit_a2a_evidence``).

    4. **``StreamState`` is the public boundary; T9 mapping is
       deferred.** T10 exposes the 8-value :data:`StreamState`
       Literal vocabulary directly (``submitted`` / ``working`` /
       ``completed`` / ``failed`` / ``canceled`` /
       ``input_required`` / ``rejected`` / ``auth_required``),
       which mirrors the SDK ``TaskState`` enum 1:1 (minus the
       never-emitted ``TASK_STATE_UNSPECIFIED``). T9's narrower
       AgentOS lifecycle vocabulary (``created`` / ``running`` /
       ``succeeded`` / ``failed`` / ``cancelled``) is NOT the
       direct input to this emitter — the spelling drift
       (``succeeded`` vs ``completed``, ``cancelled`` vs
       ``canceled``) plus T9's narrower set (no
       ``input_required`` / ``rejected`` / ``auth_required``)
       means an automatic adapter at this boundary would either
       silently lose spec-valid Wave-1 lifecycle states or
       require a non-trivial mapping table that itself is the
       endpoint-integration surface.

       **The deferred endpoint-integration task is responsible
       for the T9 ``TaskState`` → :data:`StreamState` adapter**
       (alongside the wire-format integration into
       ``A2AEndpoint.handle()``). T10 ships the wire emitter
       only. Tests in ``test_a2a_streaming.py`` pin that
       ``emit_status`` rejects T9 spellings explicitly so a
       future endpoint-integration PR cannot accidentally couple
       the two surfaces without doing the deliberate mapping
       work.

    5. **Standalone emitter.** T10 ships :class:`A2AStreamingEmitter`
       + :func:`encode_stream_response` ONLY. Endpoint integration
       (detect ``streaming = true`` agent handlers, delegate via
       chunked-transfer response) is deliberately deferred — that
       work touches :class:`A2AEndpoint`, which is on the
       critical-controls list, and ships with its own halt-before-
       commit in a later task.
"""

from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Any, Final, Literal

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
)
from cognic_agentos.protocol import require_a2a

if TYPE_CHECKING:
    # Static-typing-only imports. At runtime the SDK is loaded
    # lazily via :func:`require_a2a` + per-method imports through
    # the schema-module re-export boundary so the module file
    # imports cleanly even when ``a2a-sdk`` is missing.
    #
    # T10 R1 P2 #2: imports ride
    # :mod:`cognic_agentos.protocol.a2a_schema`'s lazy re-export
    # surface — NOT ``a2a.types`` directly. The schema module is
    # the drift-gate-protected boundary (T6); routing all SDK type
    # references through it keeps the streaming wire surface inside
    # that contract. Adding a new SDK type to this module requires
    # extending :data:`a2a_schema._REEXPORTED_TYPE_NAMES` first so
    # the schema-drift detector covers it.
    from cognic_agentos.protocol.a2a_schema import (  # noqa: F401
        Artifact,
        StreamResponse,
        TaskArtifactUpdateEvent,
        TaskState,
        TaskStatus,
        TaskStatusUpdateEvent,
    )

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Closed-enum vocabulary
# ---------------------------------------------------------------------------


#: AgentOS-side stream lifecycle state. 8 values mapping 1:1 onto the
#: 8 emitted SDK ``TaskState`` enum values
#: (``TASK_STATE_UNSPECIFIED`` is never produced — protobuf reserves
#: it as the default-zero sentinel for unset oneof discriminators,
#: which never describes a real lifecycle transition).
StreamState = Literal[
    "submitted",
    "working",
    "completed",
    "failed",
    "canceled",
    "input_required",
    "rejected",
    "auth_required",
]


#: Closed-enum :class:`StreamResponse` ``oneof payload`` field-name.
#: Used in the ``envelope_kind`` audit + decision-history payload
#: field so examiners can filter by stream-envelope class without
#: parsing the full protobuf.
StreamEnvelopeKind = Literal[
    "task",
    "message",
    "status_update",
    "artifact_update",
]


#: Closed AgentOS-→-SDK ``TaskState`` enum mapping. Lazy SDK lookup
#: per the T6 ``a2a_schema`` deferred-load doctrine: the dict starts
#: empty and is populated on first
#: :meth:`A2AStreamingEmitter.emit_status` invocation (the SDK has
#: been ``require_a2a()``-gated by then). A module-level eager
#: import would force the SDK to be present at import time, which
#: would defeat the T2 kernel-vs-default-adapters image split.
_AGENTOS_TO_SDK_STATE_NAMES: Final[dict[StreamState, str]] = {
    "submitted": "TASK_STATE_SUBMITTED",
    "working": "TASK_STATE_WORKING",
    "completed": "TASK_STATE_COMPLETED",
    "failed": "TASK_STATE_FAILED",
    "canceled": "TASK_STATE_CANCELED",
    "input_required": "TASK_STATE_INPUT_REQUIRED",
    "rejected": "TASK_STATE_REJECTED",
    "auth_required": "TASK_STATE_AUTH_REQUIRED",
}


# ---------------------------------------------------------------------------
# Emitter
# ---------------------------------------------------------------------------


class A2AStreamingEmitter:
    """Spec-compliant A2A 1.0 task streaming emitter.

    One instance per active streaming task; envelopes are produced
    as protobuf :class:`StreamResponse` messages and chain-linked
    into the audit + decision_history substrates. The caller (the
    deferred T9-integration in a later task) flushes the encoded
    bytes onto the wire via chunked HTTP.

    Critical invariants:

      - Runtime-side SDK gate at construction (:func:`require_a2a`).
      - Sequence monotonically increments per emit (protocol-level
        ordering signal for replays).
      - Every emit produces parallel chained audit + decision_history
        rows with digest + sequence + task/context ids + envelope
        kind + parent/child trace ids.
      - Audit + decision pipeline failures safe-swallow; the
        envelope still returns to the caller so the wire continues.
    """

    def __init__(
        self,
        *,
        task_id: str,
        context_id: str,
        parent_trace_id: str,
        child_trace_id: str,
        tenant_id: str,
        request_id: str,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        # Runtime-side SDK gate. Mirrors T9 ``A2AEndpoint.__init__``.
        require_a2a()
        self._task_id = task_id
        self._context_id = context_id
        self._parent_trace_id = parent_trace_id
        self._child_trace_id = child_trace_id
        self._tenant_id = tenant_id
        self._request_id = request_id
        self._audit = audit_store
        self._dh = decision_history_store
        self._sequence = 0

    @property
    def sequence(self) -> int:
        """Current stream sequence (last emitted envelope's number).
        Starts at 0; each successful emit increments by 1 BEFORE
        the audit/decision rows are written (so the row carries the
        emit's own sequence, not the previous one)."""
        return self._sequence

    async def emit_status(
        self,
        *,
        state: StreamState,
    ) -> StreamResponse:
        """Emit a :class:`TaskStatusUpdateEvent` carrying the
        SDK ``TaskState`` value mapped from :data:`StreamState`.
        Returns the protobuf :class:`StreamResponse` so the caller
        can encode + flush it onto the wire.

        Per T10 doctrine #4 the public boundary is :data:`StreamState`;
        T9 ``TaskState`` → :data:`StreamState` mapping is the
        deferred endpoint-integration surface, NOT this emitter.
        """
        # T10 R1 P2 #2 — schema-module re-export boundary. All SDK
        # type references travel through ``a2a_schema`` so the
        # streaming wire surface stays inside the T6 drift-gate
        # contract. ``TaskState`` is the protobuf
        # ``EnumTypeWrapper`` instance — its attributes are the
        # integer enum values (e.g. ``TaskState.TASK_STATE_WORKING``
        # is ``2``).
        from cognic_agentos.protocol.a2a_schema import (
            StreamResponse,
            TaskState,
            TaskStatus,
            TaskStatusUpdateEvent,
        )

        sdk_state_name = _AGENTOS_TO_SDK_STATE_NAMES[state]
        sdk_state = getattr(TaskState, sdk_state_name)

        status = TaskStatus(state=sdk_state)
        update = TaskStatusUpdateEvent(
            task_id=self._task_id,
            context_id=self._context_id,
            status=status,
        )
        envelope = StreamResponse(status_update=update)

        self._sequence += 1
        await self._emit_streaming_evidence(
            envelope_kind="status_update",
            envelope=envelope,
            extra={"agentos_state": state},
        )
        return envelope

    async def emit_artifact(
        self,
        *,
        artifact: Artifact,
        append: bool = False,
        last_chunk: bool = False,
    ) -> StreamResponse:
        """Emit a :class:`TaskArtifactUpdateEvent` carrying an
        artifact chunk. ``append`` signals continuation of a prior
        artifact; ``last_chunk`` terminates the artifact's stream
        (the chunked-transfer response itself terminates separately
        on lifecycle COMPLETED / FAILED).
        """
        # T10 R1 P2 #2 — schema-module re-export boundary.
        from cognic_agentos.protocol.a2a_schema import (
            StreamResponse,
            TaskArtifactUpdateEvent,
        )

        update = TaskArtifactUpdateEvent(
            task_id=self._task_id,
            context_id=self._context_id,
            artifact=artifact,
            append=append,
            last_chunk=last_chunk,
        )
        envelope = StreamResponse(artifact_update=update)

        self._sequence += 1
        await self._emit_streaming_evidence(
            envelope_kind="artifact_update",
            envelope=envelope,
            extra={
                "artifact_id": artifact.artifact_id,
                "append": append,
                "last_chunk": last_chunk,
            },
        )
        return envelope

    async def _emit_streaming_evidence(
        self,
        *,
        envelope_kind: StreamEnvelopeKind,
        envelope: StreamResponse,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Emit the parallel ``audit_event`` + ``decision_history``
        rows for one stream envelope. Mirrors T9
        ``_emit_a2a_evidence`` discipline: pipeline failures
        safe-swallow + log token-free; the envelope still returns
        to the caller so the wire continues.

        Payload digest is computed over the wire bytes
        (``MessageToJson`` output) so examiners reading the audit
        chain can re-encode + verify a captured envelope matches
        the chain row.
        """
        encoded = encode_stream_response(envelope)
        common: dict[str, Any] = {
            "task_id": self._task_id,
            "context_id": self._context_id,
            "parent_trace_id": self._parent_trace_id,
            "child_trace_id": self._child_trace_id,
            "stream_sequence": self._sequence,
            "envelope_kind": envelope_kind,
            "payload_digest": hashlib.sha256(encoded).hexdigest(),
        }
        if extra:
            common.update(extra)

        try:
            await self._audit.append(
                AuditEvent(
                    event_type="a2a.stream_chunk",
                    request_id=self._request_id,
                    tenant_id=self._tenant_id,
                    payload=dict(common),
                )
            )
        except Exception as audit_exc:
            _LOG.warning(
                "audit append failed for a2a.stream_chunk "
                "(task_id=%s sequence=%s envelope_kind=%s "
                "audit_error_type=%s); envelope still returns to "
                "the caller.",
                self._task_id,
                self._sequence,
                envelope_kind,
                type(audit_exc).__name__,
            )

        try:
            await self._dh.append(
                DecisionRecord(
                    decision_type="a2a_stream",
                    request_id=self._request_id,
                    tenant_id=self._tenant_id,
                    payload=dict(common),
                )
            )
        except Exception as decision_exc:
            _LOG.warning(
                "decision_history append failed for a2a_stream "
                "(task_id=%s sequence=%s envelope_kind=%s "
                "decision_error_type=%s); envelope still returns to "
                "the caller.",
                self._task_id,
                self._sequence,
                envelope_kind,
                type(decision_exc).__name__,
            )


# ---------------------------------------------------------------------------
# Wire encoder
# ---------------------------------------------------------------------------


def encode_stream_response(envelope: StreamResponse) -> bytes:
    """Encode a :class:`StreamResponse` to UTF-8 wire bytes via the
    SDK's :func:`google.protobuf.json_format.MessageToJson`.

    The encoder produces canonical protobuf-JSON: snake_case proto
    fields become camelCase JSON keys (``status_update`` →
    ``statusUpdate``, ``task_id`` → ``taskId``); enum values
    serialize as their string name (``TASK_STATE_WORKING``); default-
    valued fields are omitted.

    Hand-rolled JSON is forbidden in the wire path — the test
    contract pins this with a source-level grep. A future drift to
    custom JSON would silently desynchronise the wire format from
    the upstream A2A 1.0 spec.
    """
    require_a2a()
    from google.protobuf.json_format import MessageToJson

    encoded: str = MessageToJson(envelope, indent=None)
    return encoded.encode("utf-8")


__all__ = (
    "A2AStreamingEmitter",
    "StreamEnvelopeKind",
    "StreamState",
    "encode_stream_response",
)
