"""protocol/a2a_cancellation.py — A2A task cancellation primitive.

Per ADR-003 + Sprint-6 plan-of-record T11:
:class:`A2ATaskCancellationHandler` flips an in-flight task's
lifecycle to :class:`TaskState.CANCELLED` via the T9 endpoint's
:meth:`A2AEndpoint._transition_async`; subsequent attempts against
the cancelled task surface as the spec ``task_not_cancelable``
error.

T11 R0 doctrines (locked with implementation engineer):

  - **Standalone module; endpoint injected.** The handler is
    constructed with an :class:`A2AEndpoint` reference and lives
    OUTSIDE :class:`A2AEndpoint` itself. T9's ``a2a_endpoint.py``
    is on the critical-controls list; T11 keeps T9 untouched.
  - **No second writer to ``TaskState``.** All transitions go
    through ``endpoint._transition_async``; this handler NEVER
    mutates :attr:`TaskRecord.state` directly. T9's single-writer
    invariant stays load-bearing — a regression-pinned AST-walk
    in the test suite enforces this at source-text level.
  - **Spec-conformant refusals via :class:`A2AErrorResponse`.**
    Unknown ``task_id`` → ``task_not_found``. Already-terminal
    task (SUCCEEDED / FAILED / CANCELLED) → ``task_not_cancelable``.
    The handler raises :class:`CancellationError` carrying the
    response so the deferred HTTP-route integration serializes it
    onto the wire.

T11 R1 P2 #3 — **Refusal paths emit chained evidence.** Per the
T9 R1 P2 #1 precedent ("every A2A call is chain-linked, including
the refusal leg") and ADR-003 + A2A-CONFORMANCE.md "every A2A
call is chain-linked" — both ``task_not_found`` and
``task_not_cancelable`` refusals emit ``a2a.task_refused`` audit +
``a2a_call`` decision-history rows via the endpoint's
:meth:`A2AEndpoint._emit_refusal_evidence` helper, with
``gate="cancellation"``. Successful cancellations don't need a
separate refusal row — T9's ``_emit_a2a_evidence`` already emits
``a2a.task_cancelled`` on the CANCELLED transition.

For chain-linkage parity with T9's pre-task gate refusals:

  - ``parent_trace_id`` is caller-supplied (the HTTP route forwards
    it from the inbound request); minted fresh if absent.
  - ``child_trace_id`` is locally minted per cancellation request.
  - ``payload_digest`` is SHA-256 of the cancellation request's
    canonical identity string (``task_id``) — cancellation
    requests have no inbound payload body, but the chain still
    needs an integrity-bound identifier.

Future endpoint integration (deferred): the HTTP route
``POST /v1/tasks/{task_id}:cancel`` constructs a
:class:`A2ATaskCancellationHandler` per request, calls
:meth:`cancel_task` (forwarding ``parent_trace_id`` from the
inbound), and serialises the :class:`A2AErrorResponse` in
:class:`CancellationError` exceptions onto a JSON-RPC error
envelope. That work touches the HTTP layer + ``A2AEndpoint``
wiring and lands separately.

NOT critical-controls per AGENTS.md (delegates to T9's transition
path + T9's chain-linkage helper; carries no independent
state-machine authority).
"""

from __future__ import annotations

import hashlib
import uuid

from cognic_agentos.protocol.a2a_endpoint import A2AEndpoint, TaskState
from cognic_agentos.protocol.a2a_errors import (
    A2AErrorResponse,
    task_not_cancelable,
    task_not_found,
)

#: Terminal task states — cancellation refused with
#: ``task_not_cancelable`` per A2A 1.0 spec. Mirrors T9's
#: :data:`_LEGAL_STATE_TRANSITIONS` for these states (the legal
#: outgoing-transition set is empty for all three).
_TERMINAL_STATES: frozenset[TaskState] = frozenset(
    {TaskState.SUCCEEDED, TaskState.FAILED, TaskState.CANCELLED}
)

#: Sentinel target-agent name for the ``task_not_found`` refusal
#: row. The cancellation request didn't resolve to a known task,
#: so we have no real ``target_agent`` to record. The audit row
#: still emits with this sentinel so examiners querying by
#: ``target_agent`` can find unknown-target cancellation attempts.
_UNKNOWN_TARGET_AGENT_SENTINEL = "<unknown-task>"


class CancellationError(Exception):
    """Raised by :meth:`A2ATaskCancellationHandler.cancel_task` on
    spec-conformant refusal paths. Carries the
    :class:`A2AErrorResponse` the deferred HTTP-route integration
    serializes onto the JSON-RPC error envelope.

    Distinct from T9's :class:`A2AEndpointError` per T11 R0
    doctrine #2 — different layers, both retained:

      - :class:`A2AEndpointError` — T9's internal control flow
        exception (raised inside ``handle()`` to abort processing).
      - :class:`CancellationError` — T11's wire-response carrier
        (the HTTP layer converts the attached
        :class:`A2AErrorResponse` to JSON-RPC bytes at egress).
    """

    def __init__(self, response: A2AErrorResponse) -> None:
        self.response: A2AErrorResponse = response
        super().__init__(f"{response.code}: {response.message}")


class A2ATaskCancellationHandler:
    """Standalone cancellation primitive.

    Construction injects the :class:`A2AEndpoint` whose
    ``_tasks`` store the handler reads + whose
    ``_transition_async`` + ``_emit_refusal_evidence`` it
    delegates to. Reaching into ``endpoint._tasks`` is a deliberate
    boundary choice (T11 R0 doctrine #5: standalone module +
    endpoint injected) — the alternative is adding a public
    accessor to T9's critical-controls module, which T11
    deliberately avoids.

    Usage::

        handler = A2ATaskCancellationHandler(endpoint=endpoint)
        try:
            await handler.cancel_task(
                task_id="task-abc",
                request_id="rid-1",
                tenant_id="bank_a",
                parent_trace_id="parent-xyz",  # optional
            )
        except CancellationError as exc:
            # exc.response is the A2AErrorResponse for the wire
            ...
    """

    def __init__(self, *, endpoint: A2AEndpoint) -> None:
        self._endpoint = endpoint

    async def cancel_task(
        self,
        *,
        task_id: str,
        request_id: str,
        tenant_id: str,
        parent_trace_id: str | None = None,
    ) -> None:
        """Cancel an in-flight task.

        Returns ``None`` on success (audit + decision-history rows
        are emitted by T9's ``_emit_a2a_evidence`` at the
        ``a2a.task_cancelled`` transition).

        Raises :class:`CancellationError` carrying the
        :class:`A2AErrorResponse` on:

          - Unknown ``task_id`` → spec ``task_not_found`` (HTTP 404).
          - Task in terminal state → spec ``task_not_cancelable``.

        The transition itself goes through
        ``endpoint._transition_async`` so T9's single-writer
        invariant + chain-linkage emission are preserved.

        Both refusal paths emit ``a2a.task_refused`` chain
        evidence (T11 R1 P2 #3) carrying caller-supplied
        ``parent_trace_id`` (or a freshly-minted UUID if absent),
        a locally-minted ``child_trace_id``, the cancellation
        request's identity digest (SHA-256 of ``task_id``), and
        ``gate="cancellation"`` so examiners can distinguish
        cancellation refusals from inbound-call refusals at the
        T9 gates.
        """
        # Mint chain-linkage trace ids up front so both refusal +
        # success paths share the same identity context. Mirrors T9's
        # handle() flow.
        effective_parent_trace_id = parent_trace_id or uuid.uuid4().hex
        child_trace_id = uuid.uuid4().hex
        # Cancellation requests have no inbound payload body — use
        # the canonical identity string (task_id) as the chain-
        # linkage digest source.
        request_digest = hashlib.sha256(task_id.encode("utf-8")).hexdigest()

        task = self._endpoint._tasks.get(task_id)
        if task is None:
            await self._endpoint._emit_refusal_evidence(
                event_type="a2a.task_refused",
                request_id=request_id,
                tenant_id=tenant_id,
                target_agent=_UNKNOWN_TARGET_AGENT_SENTINEL,
                parent_trace_id=effective_parent_trace_id,
                child_trace_id=child_trace_id,
                payload_digest=request_digest,
                error_code="task_not_found",
                gate="cancellation",
                extra={"task_id": task_id},
            )
            raise CancellationError(task_not_found(task_id))

        if task.state in _TERMINAL_STATES:
            await self._endpoint._emit_refusal_evidence(
                event_type="a2a.task_refused",
                request_id=request_id,
                tenant_id=tenant_id,
                target_agent=task.target_agent,
                parent_trace_id=effective_parent_trace_id,
                child_trace_id=child_trace_id,
                payload_digest=request_digest,
                error_code="task_not_cancelable",
                gate="cancellation",
                extra={"task_id": task_id, "task_state": task.state.value},
            )
            raise CancellationError(task_not_cancelable(task_id))

        # Delegate to T9's single-writer transition path. T9 emits
        # the chained ``a2a.task_cancelled`` audit + decision-
        # history rows automatically via ``_emit_a2a_evidence``;
        # T11 adds no separate emission to avoid double-counting.
        await self._endpoint._transition_async(
            task=task,
            new_state=TaskState.CANCELLED,
            request_id=request_id,
            tenant_id=tenant_id,
        )


__all__ = (
    "A2ATaskCancellationHandler",
    "CancellationError",
)
