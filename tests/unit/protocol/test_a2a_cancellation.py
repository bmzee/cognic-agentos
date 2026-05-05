"""Sprint 6 T11 — protocol/a2a_cancellation.py contract tests.

Per ADR-003 + Sprint-6 plan-of-record T11: A2A task cancellation
primitive. ``A2ATaskCancellationHandler.cancel_task(task_id)``
flips an in-flight task's lifecycle to ``CANCELLED`` via the T9
endpoint's :meth:`_transition_async`; subsequent attempts against
the cancelled task raise the spec ``task_not_cancelable`` error.

T11 R0 doctrine #5 (locked with implementation engineer):

  - **Standalone module; endpoint injected.** The cancellation
    handler is constructed with an :class:`A2AEndpoint` reference;
    it does NOT live as a method on the endpoint.
  - **No second writer to ``TaskState``.** All transitions go
    through ``endpoint._transition_async``; the cancellation
    handler NEVER mutates :class:`TaskRecord.state` directly.
    T9's single-writer invariant stays load-bearing.
  - **Spec-conformant refusals.** Unknown ``task_id`` →
    ``task_not_found``. Already-terminal task → ``task_not_cancelable``.
    Both surface as :class:`A2AErrorResponse` per T11 doctrine #2
    (separate from T9's :class:`A2AEndpointError`).
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.audit import AuditEvent
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol.a2a_authz import A2APinnedToken
from cognic_agentos.protocol.a2a_cancellation import (
    A2ATaskCancellationHandler,
    CancellationError,
)
from cognic_agentos.protocol.a2a_endpoint import (
    A2AEndpoint,
    TaskRecord,
    TaskState,
)

# =============================================================================
# Fixtures — mirror the T9 test layout
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
def authz_client() -> MagicMock:
    mock = MagicMock()
    mock.validate_inbound_token = AsyncMock(
        return_value=A2APinnedToken(
            value="active-token",
            tenant_id="bank_a",
            issued_at=1_700_000_000.0,
            expires_at=None,
        ),
    )
    return mock


@pytest.fixture
def agent_card_verifier() -> MagicMock:
    return MagicMock()


@pytest.fixture
def plugin_registry() -> MagicMock:
    return MagicMock()


@pytest.fixture
def endpoint(
    authz_client: MagicMock,
    agent_card_verifier: MagicMock,
    plugin_registry: MagicMock,
    audit_store: MagicMock,
    decision_history_store: MagicMock,
) -> A2AEndpoint:
    return A2AEndpoint(
        settings=build_settings_without_env_file(),
        plugin_registry=plugin_registry,
        authz_client=authz_client,
        agent_card_verifier=agent_card_verifier,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
    )


@pytest.fixture
def handler(endpoint: A2AEndpoint) -> A2ATaskCancellationHandler:
    return A2ATaskCancellationHandler(endpoint=endpoint)


def _seed_task(
    endpoint: A2AEndpoint,
    *,
    task_id: str = "task-abc",
    state: TaskState = TaskState.RUNNING,
) -> TaskRecord:
    """Inject a task into the endpoint's task store. Mirrors what
    T9's ``_create_task`` does at handle() time."""
    now = time.time()
    record = TaskRecord(
        task_id=task_id,
        target_agent="agent_alpha",
        parent_trace_id="parent-trace-1",
        child_trace_id="child-trace-1",
        state=state,
        created_at=now,
        updated_at=now,
        payload_digest="a" * 64,
    )
    endpoint._tasks[task_id] = record
    return record


# =============================================================================
# Happy path — cancel an in-flight task
# =============================================================================


class TestCancelHappyPath:
    """Cancellation of a running task transitions to CANCELLED via
    the endpoint's ``_transition_async`` and emits the chained
    ``a2a.task_cancelled`` audit row (T9's ``_emit_a2a_evidence``
    handles emission automatically)."""

    async def test_cancel_running_task_transitions_to_cancelled(
        self,
        handler: A2ATaskCancellationHandler,
        endpoint: A2AEndpoint,
    ) -> None:
        task = _seed_task(endpoint, state=TaskState.RUNNING)
        await handler.cancel_task(
            task_id="task-abc",
            request_id="rid-cancel-1",
            tenant_id="bank_a",
        )
        assert task.state == TaskState.CANCELLED

    async def test_cancel_created_task_transitions_to_cancelled(
        self,
        handler: A2ATaskCancellationHandler,
        endpoint: A2AEndpoint,
    ) -> None:
        """A task in CREATED state (no run yet) is also cancelable
        per T9's ``_LEGAL_STATE_TRANSITIONS``."""
        task = _seed_task(endpoint, state=TaskState.CREATED)
        await handler.cancel_task(
            task_id="task-abc",
            request_id="rid-cancel-2",
            tenant_id="bank_a",
        )
        assert task.state == TaskState.CANCELLED

    async def test_cancel_emits_chained_audit_row(
        self,
        handler: A2ATaskCancellationHandler,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        _seed_task(endpoint, state=TaskState.RUNNING)
        await handler.cancel_task(
            task_id="task-abc",
            request_id="rid-cancel-3",
            tenant_id="bank_a",
        )
        # Last audit row is a2a.task_cancelled (emitted by T9
        # _emit_a2a_evidence on the CANCELLED transition).
        last_event: AuditEvent = audit_store.append.call_args.args[0]
        assert last_event.event_type == "a2a.task_cancelled"
        assert last_event.payload["task_id"] == "task-abc"
        assert last_event.payload["task_state"] == "cancelled"


# =============================================================================
# Refusal: unknown task_id → task_not_found
# =============================================================================


class TestUnknownTaskId:
    async def test_unknown_task_raises_task_not_found(
        self,
        handler: A2ATaskCancellationHandler,
    ) -> None:
        with pytest.raises(CancellationError) as exc:
            await handler.cancel_task(
                task_id="ghost-task",
                request_id="rid-cancel-4",
                tenant_id="bank_a",
            )
        assert exc.value.response.code == "task_not_found"
        assert exc.value.response.http_status == 404
        assert exc.value.response.payload is not None
        assert exc.value.response.payload["task_id"] == "ghost-task"


# =============================================================================
# Refusal: already-terminal task → task_not_cancelable
# =============================================================================


class TestAlreadyTerminal:
    """Tasks in SUCCEEDED / FAILED / CANCELLED state are terminal
    per T9's state machine; cancellation MUST raise
    ``task_not_cancelable`` rather than re-emitting a transition."""

    @pytest.mark.parametrize(
        "terminal_state",
        [TaskState.SUCCEEDED, TaskState.FAILED, TaskState.CANCELLED],
    )
    async def test_terminal_state_raises_task_not_cancelable(
        self,
        handler: A2ATaskCancellationHandler,
        endpoint: A2AEndpoint,
        terminal_state: TaskState,
    ) -> None:
        _seed_task(endpoint, state=terminal_state)
        with pytest.raises(CancellationError) as exc:
            await handler.cancel_task(
                task_id="task-abc",
                request_id="rid-cancel-5",
                tenant_id="bank_a",
            )
        assert exc.value.response.code == "task_not_cancelable"
        assert exc.value.response.payload is not None
        assert exc.value.response.payload["task_id"] == "task-abc"


# =============================================================================
# Single-writer invariant: handler never mutates TaskState directly
# =============================================================================


class TestSingleWriterInvariant:
    """T9 invariant: only ``A2AEndpoint._transition`` mutates
    ``TaskState``. The cancellation handler MUST go through the
    endpoint's transition path; it MUST NOT touch ``task.state``
    directly."""

    async def test_handler_uses_endpoint_transition_async(
        self,
        handler: A2ATaskCancellationHandler,
        endpoint: A2AEndpoint,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Spy on ``_transition_async``; cancellation MUST call it
        exactly once with state=CANCELLED."""
        _seed_task(endpoint, state=TaskState.RUNNING)
        calls: list[dict[str, object]] = []

        original = endpoint._transition_async

        async def _spy(**kwargs: object) -> None:
            calls.append(kwargs)
            await original(**kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(endpoint, "_transition_async", _spy)

        await handler.cancel_task(
            task_id="task-abc",
            request_id="rid-cancel-6",
            tenant_id="bank_a",
        )
        assert len(calls) == 1
        assert calls[0]["new_state"] == TaskState.CANCELLED

    async def test_handler_never_writes_taskstate_directly(self) -> None:
        """Source-level pin: the cancellation module MUST NOT
        mutate ``TaskRecord.state`` directly. Only acceptable
        mutation path is via ``endpoint._transition_async``.
        AST-walks the source for ``.state =`` assignments."""
        import ast
        import inspect

        from cognic_agentos.protocol import a2a_cancellation as mod

        tree = ast.parse(inspect.getsource(mod))
        offenders: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute) and target.attr == "state":
                        offenders.append(ast.unparse(target))
            elif (
                isinstance(node, ast.AugAssign)
                and isinstance(node.target, ast.Attribute)
                and node.target.attr == "state"
            ):
                offenders.append(ast.unparse(node.target))
        assert not offenders, (
            f"a2a_cancellation MUST NOT mutate .state directly "
            f"(violates T9 single-writer invariant): {offenders}"
        )


# =============================================================================
# CancellationError shape
# =============================================================================


class TestCancellationErrorShape:
    """``CancellationError`` carries the spec-conformant
    :class:`A2AErrorResponse` for the HTTP-route integration to
    serialize."""

    def test_carries_a2a_error_response(self) -> None:
        from cognic_agentos.protocol.a2a_errors import task_not_found

        resp = task_not_found("task-x")
        err = CancellationError(resp)
        assert err.response is resp
        assert err.response.code == "task_not_found"


# =============================================================================
# T11 R1 P2 #3 — Refusal paths emit chained evidence
# =============================================================================
#
# Per T9 R1 P2 #1 precedent: every A2A call is chain-linked
# including refusals. Cancellation refusals (task_not_found +
# task_not_cancelable) MUST emit ``a2a.task_refused`` audit +
# ``a2a_call`` decision-history rows with parent/child trace ids,
# payload digest, error_code, gate="cancellation", and policy
# context.


class TestUnknownTaskRefusalEvidence:
    async def test_emits_audit_row(
        self,
        handler: A2ATaskCancellationHandler,
        audit_store: MagicMock,
    ) -> None:
        with pytest.raises(CancellationError):
            await handler.cancel_task(
                task_id="ghost-task",
                request_id="rid-cancel-7",
                tenant_id="bank_a",
            )
        # Exactly one audit row + one decision row emitted.
        assert audit_store.append.await_count == 1
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "a2a.task_refused"
        assert event.request_id == "rid-cancel-7"
        assert event.tenant_id == "bank_a"
        assert event.payload["error_code"] == "task_not_found"
        assert event.payload["gate"] == "cancellation"
        assert event.payload["task_id"] == "ghost-task"
        assert event.payload["parent_trace_id"]
        assert event.payload["child_trace_id"]
        assert event.payload["payload_digest"]

    async def test_emits_decision_history_row(
        self,
        handler: A2ATaskCancellationHandler,
        decision_history_store: MagicMock,
    ) -> None:
        with pytest.raises(CancellationError):
            await handler.cancel_task(
                task_id="ghost-task",
                request_id="rid-cancel-8",
                tenant_id="bank_a",
            )
        assert decision_history_store.append.await_count == 1

    async def test_caller_parent_trace_carried_through(
        self,
        handler: A2ATaskCancellationHandler,
        audit_store: MagicMock,
    ) -> None:
        """Caller-supplied parent_trace_id wins over the locally-
        minted fallback."""
        with pytest.raises(CancellationError):
            await handler.cancel_task(
                task_id="ghost-task",
                request_id="rid-cancel-9",
                tenant_id="bank_a",
                parent_trace_id="caller-parent-xyz",
            )
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.payload["parent_trace_id"] == "caller-parent-xyz"

    async def test_parent_trace_minted_when_absent(
        self,
        handler: A2ATaskCancellationHandler,
        audit_store: MagicMock,
    ) -> None:
        """If caller doesn't supply parent_trace_id, the handler
        mints one so the chain still links."""
        with pytest.raises(CancellationError):
            await handler.cancel_task(
                task_id="ghost-task",
                request_id="rid-cancel-10",
                tenant_id="bank_a",
            )
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.payload["parent_trace_id"]
        # Minted parent ≠ minted child (always distinct UUIDs).
        assert event.payload["parent_trace_id"] != event.payload["child_trace_id"]


class TestTerminalTaskRefusalEvidence:
    async def test_terminal_task_emits_audit_row(
        self,
        handler: A2ATaskCancellationHandler,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        _seed_task(endpoint, state=TaskState.SUCCEEDED)
        with pytest.raises(CancellationError):
            await handler.cancel_task(
                task_id="task-abc",
                request_id="rid-cancel-11",
                tenant_id="bank_a",
            )
        # Find the refusal row (last audit append).
        last_event: AuditEvent = audit_store.append.call_args.args[0]
        assert last_event.event_type == "a2a.task_refused"
        assert last_event.payload["error_code"] == "task_not_cancelable"
        assert last_event.payload["gate"] == "cancellation"
        assert last_event.payload["task_id"] == "task-abc"
        assert last_event.payload["task_state"] == "succeeded"
        # Real task carries its own target_agent; the refusal row
        # surfaces it (not the ``<unknown-task>`` sentinel).
        assert last_event.payload["target_agent"] == "agent_alpha"

    async def test_terminal_task_emits_decision_history_row(
        self,
        handler: A2ATaskCancellationHandler,
        endpoint: A2AEndpoint,
        decision_history_store: MagicMock,
    ) -> None:
        _seed_task(endpoint, state=TaskState.FAILED)
        with pytest.raises(CancellationError):
            await handler.cancel_task(
                task_id="task-abc",
                request_id="rid-cancel-12",
                tenant_id="bank_a",
            )
        # Decision row emitted on the refusal path.
        assert decision_history_store.append.await_count == 1
        record = decision_history_store.append.call_args.args[0]
        assert record.payload["error_code"] == "task_not_cancelable"
        assert record.payload["gate"] == "cancellation"

    async def test_payload_digest_is_sha256_of_task_id(
        self,
        handler: A2ATaskCancellationHandler,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        """T11 R1 P2 #3 — cancellation requests have no inbound
        payload body, so the chain-linkage digest is computed over
        the request's canonical identity (task_id) instead. Pin
        that the digest is reproducible from the task_id alone."""
        import hashlib as _hashlib

        _seed_task(endpoint, state=TaskState.CANCELLED)
        with pytest.raises(CancellationError):
            await handler.cancel_task(
                task_id="task-abc",
                request_id="rid-cancel-13",
                tenant_id="bank_a",
            )
        last_event: AuditEvent = audit_store.append.call_args.args[0]
        expected = _hashlib.sha256(b"task-abc").hexdigest()
        assert last_event.payload["payload_digest"] == expected

    async def test_audit_failure_does_not_mask_refusal(
        self,
        handler: A2ATaskCancellationHandler,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        """T9 ``_emit_refusal_evidence`` already safe-swallows audit
        failures (T9 contract). Refusal MUST still propagate to the
        caller via :class:`CancellationError`."""
        _seed_task(endpoint, state=TaskState.SUCCEEDED)
        audit_store.append.side_effect = RuntimeError("audit pipe broken")
        with pytest.raises(CancellationError) as exc:
            await handler.cancel_task(
                task_id="task-abc",
                request_id="rid-cancel-14",
                tenant_id="bank_a",
            )
        assert exc.value.response.code == "task_not_cancelable"


class TestSuccessPathEvidenceRoute:
    """Successful cancellations don't get a separate refusal row —
    T9's ``_emit_a2a_evidence`` emits ``a2a.task_cancelled`` on the
    CANCELLED transition. The cancellation handler must NOT
    double-emit (refusal + transition rows would lie about what
    happened)."""

    async def test_success_path_emits_only_transition_row(
        self,
        handler: A2ATaskCancellationHandler,
        endpoint: A2AEndpoint,
        audit_store: MagicMock,
    ) -> None:
        _seed_task(endpoint, state=TaskState.RUNNING)
        await handler.cancel_task(
            task_id="task-abc",
            request_id="rid-cancel-15",
            tenant_id="bank_a",
        )
        event_types = [call.args[0].event_type for call in audit_store.append.call_args_list]
        # T9 emits exactly one a2a.task_cancelled on transition.
        # The handler MUST NOT add an a2a.task_refused row for
        # successful cancellations.
        assert event_types.count("a2a.task_cancelled") == 1
        assert "a2a.task_refused" not in event_types
