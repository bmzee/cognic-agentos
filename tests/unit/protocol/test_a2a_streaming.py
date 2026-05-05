"""Sprint 6 T10 — protocol/a2a_streaming.py contract tests.

Pin the A2A 1.0 task streaming wire-format adapter per ADR-003 +
Sprint-6 plan-of-record T10. **NOT portal/UI SSE** — that's
Sprint 7B per ADR-020 §"Implementation phases".

Authoritative wire format (verified against ``a2a-sdk == 1.0.2``,
``a2a/types/a2a_pb2.pyi``):

    StreamResponse {
        oneof payload {
            Task                    task            = 1;
            Message                 message         = 2;
            TaskStatusUpdateEvent   status_update   = 3;
            TaskArtifactUpdateEvent artifact_update = 4;
        }
    }

Lifecycle progress / completion / failure ride
``TaskStatusUpdateEvent.status.state`` (one of 9 SDK ``TaskState``
enum values). Artifact streaming rides ``TaskArtifactUpdateEvent``
with ``append`` / ``last_chunk`` flags. There is NO textual
``task.progress`` / ``task.completed`` / ``task.failed`` envelope
vocabulary in the spec — those were the day-1 sketch's stand-in
and the plan skeleton is bracketed as historical (T10 R0 P3).

Doctrines pinned by these tests:

  1. SDK protobuf JSON only — every envelope wire-encoded via
     ``google.protobuf.json_format.MessageToJson``; never
     hand-rolled JSON.
  2. Runtime-side SDK gate — ``A2AStreamingEmitter.__init__`` calls
     :func:`require_a2a`. Module is in ``_PROTOCOL_OPTIONAL_DEPS``
     alongside ``a2a_endpoint`` + ``a2a_artifacts``.
  3. Chain-linkage evidence per envelope — parallel ``audit_event``
     (``a2a.stream_chunk``) + ``decision_history`` rows carrying
     payload digest, stream sequence, task / context ids,
     envelope kind, and parent / child trace ids.
  4. AgentOS ``StreamState`` → SDK ``TaskState`` closed mapping at
     the boundary; tests pin the literal-set arithmetic.
  5. Standalone emitter — T10 ships the adapter ONLY; endpoint
     integration is deferred (see plan-of-record §T10).
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.audit import AuditEvent
from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.protocol.a2a_streaming import (
    A2AStreamingEmitter,
    StreamState,
    encode_stream_response,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def audit_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock(return_value=(None, b""))
    return mock


@pytest.fixture
def decision_history_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock(return_value=(None, b""))
    return mock


@pytest.fixture
def emitter(
    audit_store: MagicMock,
    decision_history_store: MagicMock,
) -> A2AStreamingEmitter:
    return A2AStreamingEmitter(
        task_id="task-abc",
        context_id="ctx-xyz",
        parent_trace_id="parent-trace-1",
        child_trace_id="child-trace-1",
        tenant_id="bank_a",
        request_id="rid-stream-1",
        audit_store=audit_store,
        decision_history_store=decision_history_store,
    )


# =============================================================================
# Module shape + closed-enum vocabulary
# =============================================================================


class TestModuleShape:
    """Pin the public surface so future refactors can't silently
    rename or drop fields the audit / wire contract depends on."""

    def test_stream_state_is_closed_enum(self) -> None:
        from typing import get_args

        assert set(get_args(StreamState)) == {
            "submitted",
            "working",
            "completed",
            "failed",
            "canceled",
            "input_required",
            "rejected",
            "auth_required",
        }

    def test_emitter_starts_at_sequence_zero(self, emitter: A2AStreamingEmitter) -> None:
        assert emitter.sequence == 0


# =============================================================================
# Runtime-side SDK gate
# =============================================================================


class TestRuntimeSdkGate:
    """``A2AStreamingEmitter.__init__`` MUST call ``require_a2a()``
    so mounting the streaming emitter on a kernel-image deployment
    (no ``a2a-sdk``) raises :class:`A2ANotAvailableError` immediately
    rather than at first emit. Mirrors T9's same regression."""

    def test_require_a2a_called_at_construction(
        self,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from cognic_agentos.protocol import A2ANotAvailableError
        from cognic_agentos.protocol import a2a_streaming as streaming_mod

        called: list[bool] = []

        def _stub() -> None:
            called.append(True)
            raise A2ANotAvailableError("sdk missing")

        monkeypatch.setattr(streaming_mod, "require_a2a", _stub)

        with pytest.raises(A2ANotAvailableError):
            A2AStreamingEmitter(
                task_id="t",
                context_id="c",
                parent_trace_id="p",
                child_trace_id="cd",
                tenant_id="bank_a",
                request_id="rid",
                audit_store=audit_store,
                decision_history_store=decision_history_store,
            )
        assert called

    def test_streaming_listed_in_protocol_optional_deps(self) -> None:
        from cognic_agentos.protocol import _PROTOCOL_OPTIONAL_DEPS

        assert "cognic_agentos.protocol.a2a_streaming" in _PROTOCOL_OPTIONAL_DEPS
        assert _PROTOCOL_OPTIONAL_DEPS["cognic_agentos.protocol.a2a_streaming"] == frozenset(
            {"a2a"}
        )


# =============================================================================
# Lifecycle status-update envelopes
# =============================================================================


class TestStatusUpdateEnvelope:
    """``emit_status`` builds a real :class:`StreamResponse` protobuf
    with a ``status_update`` payload carrying the SDK-mapped
    ``TaskStatus.state``. Pin the wire format + the closed
    AgentOS→SDK state mapping."""

    @pytest.mark.parametrize(
        ("agentos_state", "sdk_state_name"),
        [
            ("submitted", "TASK_STATE_SUBMITTED"),
            ("working", "TASK_STATE_WORKING"),
            ("completed", "TASK_STATE_COMPLETED"),
            ("failed", "TASK_STATE_FAILED"),
            ("canceled", "TASK_STATE_CANCELED"),
            ("input_required", "TASK_STATE_INPUT_REQUIRED"),
            ("rejected", "TASK_STATE_REJECTED"),
            ("auth_required", "TASK_STATE_AUTH_REQUIRED"),
        ],
    )
    async def test_emit_status_maps_state_to_sdk(
        self,
        emitter: A2AStreamingEmitter,
        agentos_state: StreamState,
        sdk_state_name: str,
    ) -> None:
        envelope = await emitter.emit_status(state=agentos_state)
        assert envelope.WhichOneof("payload") == "status_update"
        assert envelope.status_update.task_id == "task-abc"
        assert envelope.status_update.context_id == "ctx-xyz"
        # Encode + decode the JSON to assert the wire-level state
        # name matches the spec enum string.
        encoded = json.loads(encode_stream_response(envelope).decode("utf-8"))
        assert encoded["statusUpdate"]["status"]["state"] == sdk_state_name

    async def test_emit_status_increments_sequence(
        self,
        emitter: A2AStreamingEmitter,
    ) -> None:
        await emitter.emit_status(state="working")
        assert emitter.sequence == 1
        await emitter.emit_status(state="working")
        assert emitter.sequence == 2
        await emitter.emit_status(state="completed")
        assert emitter.sequence == 3


# =============================================================================
# Public-boundary contract: StreamState ≠ T9 TaskState (R1 P2 #1)
# =============================================================================
#
# T10 exposes the SDK-aligned StreamState Literal as its public
# boundary. T9's AgentOS TaskState (created/running/succeeded/
# failed/cancelled) is NOT a valid input here — the deferred
# endpoint-integration task owns that adapter. This test class pins
# the boundary contract so a future endpoint-integration PR cannot
# accidentally couple the two surfaces without doing the deliberate
# mapping work.


class TestStreamStateBoundary:
    """T10 R1 P2 #1 — StreamState is the public boundary."""

    @pytest.mark.parametrize(
        "t9_taskstate_spelling",
        [
            "created",  # T9 has this; SDK has TASK_STATE_SUBMITTED
            "running",  # T9 has this; SDK has TASK_STATE_WORKING
            "succeeded",  # T9 spelling vs SDK TASK_STATE_COMPLETED
            "cancelled",  # T9 British spelling vs SDK American "canceled"
        ],
    )
    async def test_t9_spellings_refused(
        self,
        emitter: A2AStreamingEmitter,
        t9_taskstate_spelling: str,
    ) -> None:
        """The four T9 ``TaskState`` values whose spelling differs
        from :data:`StreamState` (``created`` / ``running`` /
        ``succeeded`` / ``cancelled``) MUST raise rather than
        silently mis-emit. ``failed`` is the only value that
        spells the same in both vocabularies and is therefore
        accepted (correctly mapping onto ``TASK_STATE_FAILED``)."""
        with pytest.raises(KeyError):
            await emitter.emit_status(
                state=t9_taskstate_spelling,  # type: ignore[arg-type]
            )

    async def test_streamstate_set_is_sdk_aligned(self) -> None:
        """The StreamState Literal MUST mirror the SDK enum 1:1
        (minus TASK_STATE_UNSPECIFIED). A future SDK addition
        widens both boundaries; T6's schema-drift gate catches
        the SDK side and this test catches the AgentOS side."""
        from typing import get_args

        import a2a.types.a2a_pb2 as pb2

        sdk_names = {
            name
            for name in dir(pb2)
            if name.startswith("TASK_STATE_") and name != "TASK_STATE_UNSPECIFIED"
        }
        # Project the AgentOS StreamState Literal onto the SDK
        # constant names via the closed mapping the module already
        # carries.
        from cognic_agentos.protocol.a2a_streaming import (
            _AGENTOS_TO_SDK_STATE_NAMES,
        )

        assert set(get_args(StreamState)) == set(_AGENTOS_TO_SDK_STATE_NAMES.keys())
        assert set(_AGENTOS_TO_SDK_STATE_NAMES.values()) == sdk_names


# =============================================================================
# Artifact-update envelopes
# =============================================================================


class TestArtifactUpdateEnvelope:
    """``emit_artifact`` builds a :class:`StreamResponse` with an
    ``artifact_update`` payload carrying the artifact, ``append``
    flag, and ``last_chunk`` flag."""

    async def test_emit_artifact_basic(
        self,
        emitter: A2AStreamingEmitter,
    ) -> None:
        from a2a.types import Artifact, Part

        artifact = Artifact(
            artifact_id="a1",
            name="output",
            parts=[Part(text="hello world")],
        )
        envelope = await emitter.emit_artifact(artifact=artifact, append=False, last_chunk=False)
        assert envelope.WhichOneof("payload") == "artifact_update"
        assert envelope.artifact_update.task_id == "task-abc"
        assert envelope.artifact_update.context_id == "ctx-xyz"
        assert envelope.artifact_update.artifact.artifact_id == "a1"
        assert not envelope.artifact_update.append
        assert not envelope.artifact_update.last_chunk

    async def test_emit_artifact_append_chunk(
        self,
        emitter: A2AStreamingEmitter,
    ) -> None:
        from a2a.types import Artifact, Part

        artifact = Artifact(artifact_id="a1", parts=[Part(text="chunk-2")])
        envelope = await emitter.emit_artifact(artifact=artifact, append=True, last_chunk=False)
        assert envelope.artifact_update.append is True
        assert envelope.artifact_update.last_chunk is False

    async def test_emit_artifact_last_chunk(
        self,
        emitter: A2AStreamingEmitter,
    ) -> None:
        from a2a.types import Artifact, Part

        artifact = Artifact(artifact_id="a1", parts=[Part(text="final")])
        envelope = await emitter.emit_artifact(artifact=artifact, append=True, last_chunk=True)
        assert envelope.artifact_update.last_chunk is True


# =============================================================================
# Wire-format encoding (SDK protobuf JSON)
# =============================================================================


class TestWireFormat:
    """Every envelope MUST be encoded via the SDK's
    ``google.protobuf.json_format.MessageToJson`` so we stay
    spec-compliant. NEVER hand-roll JSON.
    """

    async def test_encode_stream_response_is_valid_json(
        self,
        emitter: A2AStreamingEmitter,
    ) -> None:
        envelope = await emitter.emit_status(state="working")
        encoded = encode_stream_response(envelope)
        assert isinstance(encoded, bytes)
        # Must round-trip as valid JSON.
        decoded = json.loads(encoded.decode("utf-8"))
        # Per protobuf-JSON: snake_case proto fields become camelCase
        # in JSON. ``status_update`` (oneof field name) → ``statusUpdate``.
        assert "statusUpdate" in decoded

    async def test_encode_uses_camel_case_field_names(
        self,
        emitter: A2AStreamingEmitter,
    ) -> None:
        """Pin the protobuf-JSON convention: snake_case proto field
        names serialize to camelCase JSON. A future drift to
        snake_case would break A2A-1.0-conforming consumers."""
        envelope = await emitter.emit_status(state="working")
        encoded = encode_stream_response(envelope).decode("utf-8")
        decoded = json.loads(encoded)
        status_update = decoded["statusUpdate"]
        assert "taskId" in status_update
        assert "task_id" not in status_update
        assert "contextId" in status_update
        assert "context_id" not in status_update

    async def test_encode_artifact_camel_case(
        self,
        emitter: A2AStreamingEmitter,
    ) -> None:
        from a2a.types import Artifact, Part

        artifact = Artifact(artifact_id="a1", parts=[Part(text="x")])
        envelope = await emitter.emit_artifact(artifact=artifact, append=True, last_chunk=False)
        encoded = encode_stream_response(envelope).decode("utf-8")
        decoded = json.loads(encoded)
        assert "artifactUpdate" in decoded
        assert "artifactId" in decoded["artifactUpdate"]["artifact"]
        # Booleans + protobuf JSON: append=True is included; last_chunk=False
        # may be omitted (default-value omission is protobuf's default
        # JSON behaviour). Don't pin last_chunk presence either way —
        # pin only that hand-rolled snake_case is absent.
        assert "last_chunk" not in decoded["artifactUpdate"]


# =============================================================================
# Chain-linkage evidence
# =============================================================================


class TestChainEvidence:
    """Every emitted envelope produces parallel ``audit_event`` +
    ``decision_history`` rows with chain-linkage fields. Mirrors
    T9's ``_emit_a2a_evidence`` pattern."""

    async def test_status_emission_emits_audit_and_decision(
        self,
        emitter: A2AStreamingEmitter,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        await emitter.emit_status(state="working")
        assert audit_store.append.await_count == 1
        assert decision_history_store.append.await_count == 1

        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "a2a.stream_chunk"
        assert event.request_id == "rid-stream-1"
        assert event.tenant_id == "bank_a"
        assert event.payload["task_id"] == "task-abc"
        assert event.payload["context_id"] == "ctx-xyz"
        assert event.payload["parent_trace_id"] == "parent-trace-1"
        assert event.payload["child_trace_id"] == "child-trace-1"
        assert event.payload["stream_sequence"] == 1
        assert event.payload["envelope_kind"] == "status_update"
        assert event.payload["payload_digest"]
        assert event.payload["agentos_state"] == "working"

    async def test_artifact_emission_emits_audit_and_decision(
        self,
        emitter: A2AStreamingEmitter,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        from a2a.types import Artifact, Part

        artifact = Artifact(artifact_id="a1", parts=[Part(text="x")])
        await emitter.emit_artifact(artifact=artifact, append=False, last_chunk=True)

        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "a2a.stream_chunk"
        assert event.payload["envelope_kind"] == "artifact_update"
        assert event.payload["artifact_id"] == "a1"
        assert event.payload["last_chunk"] is True

    async def test_payload_digest_is_sha256_of_encoded_bytes(
        self,
        emitter: A2AStreamingEmitter,
        audit_store: MagicMock,
    ) -> None:
        import hashlib

        envelope = await emitter.emit_status(state="working")
        # Re-encode + hash; must match the audit row's digest.
        expected = hashlib.sha256(encode_stream_response(envelope)).hexdigest()
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.payload["payload_digest"] == expected

    async def test_stream_sequence_increments_in_evidence(
        self,
        emitter: A2AStreamingEmitter,
        audit_store: MagicMock,
    ) -> None:
        await emitter.emit_status(state="submitted")
        await emitter.emit_status(state="working")
        await emitter.emit_status(state="completed")
        sequences = [
            call.args[0].payload["stream_sequence"] for call in audit_store.append.call_args_list
        ]
        assert sequences == [1, 2, 3]

    async def test_decision_history_payload_mirrors_audit_payload(
        self,
        emitter: A2AStreamingEmitter,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        await emitter.emit_status(state="working")
        audit_event: AuditEvent = audit_store.append.call_args.args[0]
        decision_record: DecisionRecord = decision_history_store.append.call_args.args[0]
        assert audit_event.request_id == decision_record.request_id
        assert audit_event.tenant_id == decision_record.tenant_id
        assert decision_record.decision_type == "a2a_stream"
        # Chain-linkage fields match between the two surfaces.
        for key in (
            "task_id",
            "context_id",
            "parent_trace_id",
            "child_trace_id",
            "stream_sequence",
            "envelope_kind",
            "payload_digest",
        ):
            assert audit_event.payload[key] == decision_record.payload[key]


# =============================================================================
# Audit-pipeline safe-swallow
# =============================================================================


class TestSafeSwallow:
    """Audit + decision-history pipeline failures MUST NOT mask the
    primary outcome — the emitter still returns the envelope so the
    caller can flush it onto the wire. Mirrors Sprint-5
    ``_emit_call_evidence`` discipline."""

    async def test_audit_failure_does_not_mask_envelope_emission(
        self,
        emitter: A2AStreamingEmitter,
        audit_store: MagicMock,
    ) -> None:
        audit_store.append.side_effect = RuntimeError("audit pipe broken")
        envelope = await emitter.emit_status(state="working")
        # Caller still receives the envelope.
        assert envelope.WhichOneof("payload") == "status_update"

    async def test_decision_history_failure_does_not_mask_envelope_emission(
        self,
        emitter: A2AStreamingEmitter,
        decision_history_store: MagicMock,
    ) -> None:
        decision_history_store.append.side_effect = RuntimeError("dh pipe broken")
        envelope = await emitter.emit_status(state="working")
        assert envelope.WhichOneof("payload") == "status_update"


# =============================================================================
# No hand-rolled JSON
# =============================================================================


class TestNoHandRolledJson:
    """The streaming module MUST delegate JSON encoding to the SDK's
    protobuf encoder. A regression that hand-rolls JSON would
    silently desynchronise the wire format from upstream spec
    evolution."""

    def test_module_uses_json_format_message_to_json(self) -> None:
        """Source-level pin: the only JSON-emitting call site in the
        module is :func:`google.protobuf.json_format.MessageToJson`.
        ``json.dumps`` / hand-built strings are forbidden in the
        wire path."""
        import inspect

        from cognic_agentos.protocol import a2a_streaming as mod

        source = inspect.getsource(mod)
        # The SDK encoder MUST be referenced.
        assert "MessageToJson" in source
        # Hand-rolled JSON encoders MUST NOT appear in the wire path.
        # (``json`` may still be imported for evidence-payload work
        # via canonical_bytes / hashlib digests, so we don't ban the
        # import outright — we ban the specific dump calls.)
        assert "json.dumps" not in source


# =============================================================================
# Schema-module boundary (R1 P2 #2)
# =============================================================================


class TestSchemaModuleBoundary:
    """T10 R1 P2 #2 — every SDK type used by the streaming module
    MUST travel through :mod:`cognic_agentos.protocol.a2a_schema`'s
    lazy re-export surface so the T6 drift-gate covers the full
    wire vocabulary.
    """

    def test_streaming_imports_no_direct_a2a_types(self) -> None:
        """Source-level pin: the streaming module MUST NOT
        ``import`` ``a2a.types`` or ``a2a.types.a2a_pb2`` directly.
        All SDK types come through ``a2a_schema``.

        Restrict the check to actual import statements (AST-walk)
        so docstring prose referencing the SDK module path for
        verification context (``a2a/types/a2a_pb2.pyi``) doesn't
        falsely trip."""
        import ast
        import inspect

        from cognic_agentos.protocol import a2a_streaming as mod

        tree = ast.parse(inspect.getsource(mod))
        forbidden_modules = {"a2a", "a2a.types", "a2a.types.a2a_pb2"}
        offenders: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in forbidden_modules or alias.name.startswith("a2a."):
                        offenders.append(f"import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module in forbidden_modules or module.startswith("a2a."):
                    offenders.append(f"from {module} import ...")
        assert not offenders, (
            f"a2a_streaming module imports SDK types directly "
            f"(forbidden per T10 R1 P2 #2 — must travel through "
            f"a2a_schema): {offenders}"
        )

    def test_required_sdk_types_are_in_schema_reexport_set(self) -> None:
        """Pin the contract: every SDK type the streaming module
        consumes (via ``a2a_schema`` re-export) MUST be in
        :data:`a2a_schema._REEXPORTED_TYPE_NAMES`. A future addition
        without updating both ends trips this test."""
        from cognic_agentos.protocol.a2a_schema import _REEXPORTED_TYPE_NAMES

        required = {
            "StreamResponse",
            "TaskStatusUpdateEvent",
            "TaskArtifactUpdateEvent",
            "TaskStatus",
            "TaskState",
            "Artifact",
        }
        missing = required - _REEXPORTED_TYPE_NAMES
        assert not missing, (
            f"streaming wire surface MUST be covered by the T6 "
            f"schema-drift gate; missing re-exports: {sorted(missing)}"
        )
