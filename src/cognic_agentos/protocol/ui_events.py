"""protocol/ui_events.py — UI event-stream typed schema (Wave 1).

**Critical-controls module per AGENTS.md** (Sprint-6 amendment, per
ADR-020 stop rule on the public event schema). The schema MUST be
stable from day one even though Sprint 6 ships ONLY the in-process
emit-hook layer; the SSE transport endpoint lands at Sprint 7B.

Per ADR-020 + Sprint-6 plan-of-record T12: this is the public event
contract that ANY UI consuming AgentOS events implements. **All 11
Wave-1 event families ship as Pydantic models in Sprint 6**; **3
families have wired emit hooks** (``tool_call``, ``artifact``,
``decision_audit``). The other 8 families are schema-only stubs
whose emit hooks land in their owning sprints per ADR-020 §
"Implementation phases".

T12 R0 doctrines (locked with implementation engineer):

  1. **Layer-safe append-hook surface; ``core/`` MUST NOT import
     ``protocol/``.** :class:`UIEventEmitter` consumes the generic
     :data:`AuditAppendHook` / :data:`DecisionAppendHook` Callables
     from ``core/audit.py`` + ``core/decision_history.py``;
     ``core/`` knows nothing about this module.

  2. **Awaited sequential post-commit firing.** Stores fire hooks
     AFTER the chain-write commits + BEFORE :meth:`append` returns;
     this module's :meth:`UIEventEmitter.emit` walks registered
     :class:`UIEventHook` subscribers awaitedly. One broken
     subscriber does NOT poison subsequent ones (try/except per
     subscriber, log token-free).

  3. **Hook payload is the persisted snapshot** (already
     independent of the caller's mutable raw payload —
     ``AppendedEventSnapshot`` / ``AppendedDecisionSnapshot`` carry
     the canonical-form-projected dict).

  4. **``run_id: str | None = None`` for Sprint 6** (no agent-run
     primitive yet; Sprint-7A introduces it).

  5. **``event_id`` via ``python-ulid``** — Crockford-base32, 26
     chars; prefixed ``evt_`` (total 30 chars). Time-orderable for
     SSE-resume cursor semantics.

  6. **Pydantic v2 family-level + type-level Literal discrimination.**
     Each model carries both ``family: Literal["..."]`` AND
     ``type: Literal["..."]`` so the discriminated union resolves
     unambiguously across families that share a ``type`` value
     (e.g. ``completed`` appears in ``agent_run`` / ``tool_call`` /
     ``subagent`` / ``artifact``).

  7. **Routing mappings (locked at R0)**:

         audit.tool_invocation         → tool_call.completed
         audit.tool_invocation_refused → tool_call.denied
         audit.tool_invocation_error   → tool_call.failed
         a2a.artifact_prepared         → artifact.completed
         every DecisionHistoryStore.append → decision_audit.event_appended

  8. **Wired-family pin: ``frozenset({"tool_call", "artifact",
     "decision_audit"})``.** Drift detector in
     ``test_ui_event_taxonomy_completeness.py``.

Wire format (per ADR-020):

    {
      "event_id":   "evt_01HV...",
      "ts":         "2026-04-27T14:23:11.123Z",
      "tenant":     "bank-a",
      "run_id":     null,                 # Sprint-7A populates
      "trace_id":   "trace_01HV...",
      "family":     "tool_call",
      "type":       "approved",
      "data":       { ... family-specific ... },
      "audit_chain_hash": "sha256:..."
    }

The ``audit_chain_hash`` field lets a subscribing UI verify the
event corresponds to a real audit/decision row without trusting the
SSE channel alone.

**No SSE endpoint in Sprint 6.** Per ADR-020 §"Implementation
phases", SSE transport lands in Sprint 7B. Sprint 6 ships ONLY the
typed Pydantic schema + the in-process emit-hook layer.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import logging
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Final, Literal

import pydantic
from ulid import ULID

from cognic_agentos.core.audit import AppendedEventSnapshot, AuditStore
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import (
    AppendedDecisionSnapshot,
    DecisionHistoryStore,
)

_LOG = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Closed-enum vocabularies
# ---------------------------------------------------------------------------


#: All 11 Wave-1 event families per ADR-020 §"Event taxonomy (Wave 1)".
#: The drift detector in ``test_ui_event_taxonomy_completeness.py``
#: pins this set against ADR-020 — adding or dropping a family
#: trips the test before merge.
_WAVE_1_FAMILIES: Final[frozenset[str]] = frozenset(
    {
        "agent_run",
        "tool_call",
        "subagent",
        "approval",
        "artifact",
        "interrupt",
        "frontend_action",
        "memory",
        "decision_audit",
        "policy",
        "kill_switch",
    }
)


#: Sprint-6-WIRED families — emit hooks observable in this sprint.
#: The other 8 families ship schema-only stubs in Sprint 6; their
#: emit hooks land in their owning sprints per ADR-020 phase table.
_WIRED_IN_SPRINT_6: Final[frozenset[str]] = frozenset({"tool_call", "artifact", "decision_audit"})


#: Audit ``event_type`` → (family, type) routing for the
#: ``tool_call`` mirror (T12 R0 doctrine #7). Source-of-truth for
#: Sprint-5 MCP host's ``audit.tool_invocation_*`` event vocabulary.
_TOOL_CALL_AUDIT_ROUTING: Final[dict[str, tuple[Literal["tool_call"], str]]] = {
    "audit.tool_invocation": ("tool_call", "completed"),
    "audit.tool_invocation_refused": ("tool_call", "denied"),
    "audit.tool_invocation_error": ("tool_call", "failed"),
}

#: Audit ``event_type`` → (family, type) routing for the
#: ``artifact`` mirror.
_ARTIFACT_AUDIT_ROUTING: Final[dict[str, tuple[Literal["artifact"], str]]] = {
    "a2a.artifact_prepared": ("artifact", "completed"),
}


#: Schema version pinned at ``"1.0"`` per ADR-020. Bumping requires a
#: deliberate reviewed change tied to a wire-format migration.
SCHEMA_VERSION: Final[str] = "1.0"


# ---------------------------------------------------------------------------
# event_id generation
# ---------------------------------------------------------------------------


def _new_event_id() -> str:
    """Generate a fresh ``event_id`` per ADR-020 wire format.

    Returns ``"evt_<ULID>"`` where ``<ULID>`` is a 26-char
    Crockford-base32 string from :class:`ulid.ULID` (time-orderable
    for SSE-resume cursor semantics in Sprint-7B). Total length: 30
    chars (4-char ``evt_`` prefix + 26-char ULID body).

    Per T12 R0 doctrine #5: UUID4 fallback explicitly NOT permitted —
    the time-orderability + sortability are required for resume
    cursor semantics.
    """
    return f"evt_{ULID()}"


# ---------------------------------------------------------------------------
# Pydantic event-family models — 11 Wave-1 families, all schema-shipped
# ---------------------------------------------------------------------------


class _BaseEvent(pydantic.BaseModel):
    """Base for every Wave-1 UI event. ``family`` and ``type`` are
    overridden by Literal-typed defaults in each subclass so Pydantic
    can discriminate the union by both fields.

    Frozen via ``model_config`` so the wire payload cannot be mutated
    between construction and HTTP serialization (Sprint-7B).
    """

    event_id: str = pydantic.Field(default_factory=_new_event_id)
    ts: _dt.datetime
    tenant: str | None = None
    run_id: str | None = None
    trace_id: str | None = None
    data: dict[str, Any] = pydantic.Field(default_factory=dict)
    audit_chain_hash: str

    model_config = pydantic.ConfigDict(frozen=True)


# ---- agent_run.* (schema only — Sprint-7A wires) -----------------------------


class AgentRunStarted(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["started"] = "started"


class AgentRunProgress(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["progress"] = "progress"


class AgentRunCompleted(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["completed"] = "completed"


class AgentRunFailed(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["failed"] = "failed"


class AgentRunCancelled(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["cancelled"] = "cancelled"


class AgentRunPaused(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["paused"] = "paused"


class AgentRunResumed(_BaseEvent):
    family: Literal["agent_run"] = "agent_run"
    type: Literal["resumed"] = "resumed"


# ---- tool_call.* (WIRED — Sprint-5 audit mirror) -----------------------------


class ToolCallRequested(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["requested"] = "requested"


class ToolCallApproved(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["approved"] = "approved"


class ToolCallDenied(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["denied"] = "denied"


class ToolCallStarted(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["started"] = "started"


class ToolCallProgress(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["progress"] = "progress"


class ToolCallCompleted(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["completed"] = "completed"


class ToolCallFailed(_BaseEvent):
    family: Literal["tool_call"] = "tool_call"
    type: Literal["failed"] = "failed"


# ---- subagent.* (schema only — Sprint-8 wires) -------------------------------


class SubagentSpawned(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["spawned"] = "spawned"


class SubagentCompleted(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["completed"] = "completed"


class SubagentFailed(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["failed"] = "failed"


class SubagentRecursionCapped(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["recursion_capped"] = "recursion_capped"


# ---- approval.* (schema only — Sprint-13.5 wires) ----------------------------


class ApprovalPending(_BaseEvent):
    family: Literal["approval"] = "approval"
    type: Literal["pending"] = "pending"


class ApprovalGranted(_BaseEvent):
    family: Literal["approval"] = "approval"
    type: Literal["granted"] = "granted"


class ApprovalGrantedSecond(_BaseEvent):
    family: Literal["approval"] = "approval"
    type: Literal["granted_second"] = "granted_second"


class ApprovalDenied(_BaseEvent):
    family: Literal["approval"] = "approval"
    type: Literal["denied"] = "denied"


class ApprovalExpired(_BaseEvent):
    family: Literal["approval"] = "approval"
    type: Literal["expired"] = "expired"


# ---- artifact.* (WIRED — Sprint-6 T11 mirror) --------------------------------


class ArtifactStarted(_BaseEvent):
    family: Literal["artifact"] = "artifact"
    type: Literal["started"] = "started"


class ArtifactChunk(_BaseEvent):
    family: Literal["artifact"] = "artifact"
    type: Literal["chunk"] = "chunk"


class ArtifactCompleted(_BaseEvent):
    family: Literal["artifact"] = "artifact"
    type: Literal["completed"] = "completed"


# ---- interrupt.* (schema only — Sprint-13.5 wires) ---------------------------


class InterruptRequestedByAgent(_BaseEvent):
    family: Literal["interrupt"] = "interrupt"
    type: Literal["requested_by_agent"] = "requested_by_agent"


class InterruptRequestedByOperator(_BaseEvent):
    family: Literal["interrupt"] = "interrupt"
    type: Literal["requested_by_operator"] = "requested_by_operator"


class InterruptAcknowledged(_BaseEvent):
    family: Literal["interrupt"] = "interrupt"
    type: Literal["acknowledged"] = "acknowledged"


# ---- frontend_action.* (schema only — Sprint-7B wires) -----------------------


class FrontendActionSubmitted(_BaseEvent):
    family: Literal["frontend_action"] = "frontend_action"
    type: Literal["submitted"] = "submitted"


class FrontendActionAccepted(_BaseEvent):
    family: Literal["frontend_action"] = "frontend_action"
    type: Literal["accepted"] = "accepted"


class FrontendActionRejected(_BaseEvent):
    family: Literal["frontend_action"] = "frontend_action"
    type: Literal["rejected"] = "rejected"


# ---- memory.* (schema only — Sprint-11.5 wires) ------------------------------


class MemoryRecallStarted(_BaseEvent):
    family: Literal["memory"] = "memory"
    type: Literal["recall_started"] = "recall_started"


class MemoryRecallCompleted(_BaseEvent):
    family: Literal["memory"] = "memory"
    type: Literal["recall_completed"] = "recall_completed"


class MemoryForget(_BaseEvent):
    family: Literal["memory"] = "memory"
    type: Literal["forget"] = "forget"


class MemoryRedact(_BaseEvent):
    family: Literal["memory"] = "memory"
    type: Literal["redact"] = "redact"


# ---- decision_audit.* (WIRED — generic DH mirror) ----------------------------


class DecisionAuditEventAppended(_BaseEvent):
    family: Literal["decision_audit"] = "decision_audit"
    type: Literal["event_appended"] = "event_appended"


# ---- policy.* (schema only — Sprint-13.5 wires) ------------------------------


class PolicyDecisionEvaluated(_BaseEvent):
    family: Literal["policy"] = "policy"
    type: Literal["decision_evaluated"] = "decision_evaluated"


class PolicyBundleLoaded(_BaseEvent):
    family: Literal["policy"] = "policy"
    type: Literal["bundle_loaded"] = "bundle_loaded"


# ---- kill_switch.* (schema only — Sprint-13.5 wires) -------------------------


class KillSwitchFlipped(_BaseEvent):
    family: Literal["kill_switch"] = "kill_switch"
    type: Literal["flipped"] = "flipped"


class KillSwitchReverted(_BaseEvent):
    family: Literal["kill_switch"] = "kill_switch"
    type: Literal["reverted"] = "reverted"


# ---------------------------------------------------------------------------
# Discriminated union — Pydantic v2 Annotated[Union[...], discriminator]
# ---------------------------------------------------------------------------


#: All 35 typed event subclasses (sum of family-event-counts across
#: the 11 Wave-1 families per ADR-020 §"Event taxonomy (Wave 1)"):
#: 7 agent_run + 7 tool_call + 4 subagent + 5 approval + 3 artifact +
#: 3 interrupt + 3 frontend_action + 4 memory + 1 decision_audit +
#: 2 policy + 2 kill_switch.
#:
#: Per T12 R1 P2 #1 reviewer correction: the discriminated union is
#: built as a **two-level structure** rather than a flat union with
#: a single ``Field(discriminator="family")``. Pydantic rejects the
#: flat shape with ``TypeError: Value '<family>' for discriminator
#: 'family' mapped to multiple choices`` because each family has
#: multiple event classes (e.g. 7 ToolCall events all share
#: ``family="tool_call"``). The two-level shape:
#:
#:   1. Per-family inner union discriminated on ``type`` (each
#:      family's ``type`` values ARE unique within the family).
#:   2. Top-level :data:`UIEvent` union discriminated on ``family``,
#:      where each branch is one of the per-family inner unions.
#:
#: ``TypeAdapter(UIEvent)`` builds + validates cleanly with this
#: shape (regression-pinned in
#: ``test_ui_event_taxonomy_completeness.py``).


# Per-family inner unions, each discriminated on ``type``:

_AgentRunEvent = Annotated[
    AgentRunStarted
    | AgentRunProgress
    | AgentRunCompleted
    | AgentRunFailed
    | AgentRunCancelled
    | AgentRunPaused
    | AgentRunResumed,
    pydantic.Field(discriminator="type"),
]

_ToolCallEvent = Annotated[
    ToolCallRequested
    | ToolCallApproved
    | ToolCallDenied
    | ToolCallStarted
    | ToolCallProgress
    | ToolCallCompleted
    | ToolCallFailed,
    pydantic.Field(discriminator="type"),
]

_SubagentEvent = Annotated[
    SubagentSpawned | SubagentCompleted | SubagentFailed | SubagentRecursionCapped,
    pydantic.Field(discriminator="type"),
]

_ApprovalEvent = Annotated[
    ApprovalPending | ApprovalGranted | ApprovalGrantedSecond | ApprovalDenied | ApprovalExpired,
    pydantic.Field(discriminator="type"),
]

_ArtifactEvent = Annotated[
    ArtifactStarted | ArtifactChunk | ArtifactCompleted,
    pydantic.Field(discriminator="type"),
]

_InterruptEvent = Annotated[
    InterruptRequestedByAgent | InterruptRequestedByOperator | InterruptAcknowledged,
    pydantic.Field(discriminator="type"),
]

_FrontendActionEvent = Annotated[
    FrontendActionSubmitted | FrontendActionAccepted | FrontendActionRejected,
    pydantic.Field(discriminator="type"),
]

_MemoryEvent = Annotated[
    MemoryRecallStarted | MemoryRecallCompleted | MemoryForget | MemoryRedact,
    pydantic.Field(discriminator="type"),
]

# decision_audit has only one event type today, but the union form
# keeps the per-family shape consistent for future Wave-2 additions.
_DecisionAuditEvent = Annotated[DecisionAuditEventAppended, pydantic.Field(discriminator="type")]

_PolicyEvent = Annotated[
    PolicyDecisionEvaluated | PolicyBundleLoaded,
    pydantic.Field(discriminator="type"),
]

_KillSwitchEvent = Annotated[
    KillSwitchFlipped | KillSwitchReverted,
    pydantic.Field(discriminator="type"),
]


# Top-level union discriminated on ``family``. Each branch is one of
# the per-family unions above; ``family`` is unique across branches.
UIEvent = Annotated[
    _AgentRunEvent
    | _ToolCallEvent
    | _SubagentEvent
    | _ApprovalEvent
    | _ArtifactEvent
    | _InterruptEvent
    | _FrontendActionEvent
    | _MemoryEvent
    | _DecisionAuditEvent
    | _PolicyEvent
    | _KillSwitchEvent,
    pydantic.Field(discriminator="family"),
]


# ---------------------------------------------------------------------------
# Hook protocol + emitter
# ---------------------------------------------------------------------------


UIEventHook = Callable[[Any], Awaitable[None]]
"""In-process subscriber to UI events.

Sprint-7B's SSE endpoint will register a :data:`UIEventHook` that
buffers events for SSE delivery; Sprint 6 only ships the protocol +
the in-process emit-hook layer (no observable subscribers in Sprint
6 itself; tests register hooks explicitly).

Implementations MUST be cheap — every audit emit also fires the UI
hook in-process; a slow hook backs up the audit append (T12 R0
doctrine #2 documented cost).
"""


class UIEventEmitter:
    """In-process UI event emitter.

    Constructed with :class:`AuditStore` + :class:`DecisionHistoryStore`
    references; registers itself as a post-commit append-hook on
    each. Every audit emit produces a typed UI event from the
    Sprint-6-WIRED family map (``tool_call`` / ``artifact``); every
    decision-history emit produces a generic
    :class:`DecisionAuditEventAppended`.

    Per T12 R0 doctrine #1: this class lives in ``protocol/``;
    ``core/`` does not import it. The wiring is one-way:
    :class:`AuditStore` / :class:`DecisionHistoryStore` expose
    layer-safe :meth:`register_append_hook` Callable surfaces; the
    :class:`UIEventEmitter` registers concrete hooks at construction.
    """

    def __init__(
        self,
        *,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        self._hooks: list[UIEventHook] = []
        # Register both append hooks at construction. The hook
        # callables are bound methods on this instance — when
        # ``audit_store.append`` (or ``dh_store.append``) commits,
        # the post-commit hook runs against this emitter, classifies
        # the snapshot, and dispatches typed UI events to any
        # registered ``UIEventHook`` subscribers.
        audit_store.register_append_hook(self._on_audit_append)
        decision_history_store.register_append_hook(self._on_decision_append)

    def register_hook(self, hook: UIEventHook) -> None:
        """Register a downstream UI event subscriber.

        Sprint-7B's SSE buffer registers a hook here; Sprint-6
        tests register inline collector hooks. Subscriber failures
        are isolated per :meth:`_safe_emit`.
        """
        self._hooks.append(hook)

    async def _on_audit_append(self, snapshot: AppendedEventSnapshot) -> None:
        """Hook fired by :class:`AuditStore` post-commit. Classifies
        the snapshot's ``event_type`` against the Sprint-6-wired
        family routing tables; emits a typed UI event when matched
        AND **always also emits a generic
        ``decision_audit.event_appended``** so the ADR-020 contract
        ("every existing audit event mirrors") holds for audit-only
        events too (T12 R2 P2 #1 reviewer correction — the prior
        no-op fallback silently dropped audit-only sources like
        ``guardrail.trip``, ``trust_gate.cosign_timeout``, future
        gateway events that don't write to ``decision_history``).
        """
        event_type = snapshot.event_type
        if event_type in _TOOL_CALL_AUDIT_ROUTING:
            tc_family, tc_type = _TOOL_CALL_AUDIT_ROUTING[event_type]
            await self._emit_tool_call(snapshot, tc_family, tc_type)
        elif event_type in _ARTIFACT_AUDIT_ROUTING:
            art_family, art_type = _ARTIFACT_AUDIT_ROUTING[event_type]
            await self._emit_artifact(snapshot, art_family, art_type)
        # ALWAYS emit the generic decision_audit mirror for audit
        # rows regardless of typed-family routing (T12 R2 P2 #1):
        # an audit-only event with no DH counterpart still mirrors
        # via this path; an event that ALSO writes to DH gets
        # mirrored twice (once per chain), and ``data.chain_id``
        # discriminates so consumers see exactly one event per
        # chain row.
        await self._emit_generic_decision_audit_for_audit(snapshot)

    async def _on_decision_append(self, snapshot: AppendedDecisionSnapshot) -> None:
        """Hook fired by :class:`DecisionHistoryStore` post-commit.
        EVERY DH append produces a ``decision_audit.event_appended``
        UI event regardless of subsystem origin (T12 R0 doctrine
        #7 — "every existing audit event mirrors" load-bearing
        contract per ADR-020 Sprint-6 phase row).

        T12 R2 P2 #2 reviewer correction: the ``data`` field carries
        the source row's identity (``event_type``, ``payload_digest``,
        ``request_id``, ``sequence``, ``chain_id``, ``tenant_id``)
        so a reconnecting UI / examiner can identify the source
        without fetching the DB row.
        """
        event = DecisionAuditEventAppended(
            ts=snapshot.created_at,
            tenant=snapshot.tenant_id,
            trace_id=snapshot.trace_id,
            audit_chain_hash=_format_chain_hash(snapshot.new_hash),
            data={
                "event_type": snapshot.decision_type,
                "payload_digest": _payload_digest(snapshot.payload),
                "request_id": snapshot.request_id,
                "sequence": snapshot.sequence,
                "chain_id": snapshot.chain_id,
                "tenant_id": snapshot.tenant_id,
            },
        )
        await self._safe_emit(event)

    async def _emit_generic_decision_audit_for_audit(self, snapshot: AppendedEventSnapshot) -> None:
        """Emit the generic ``decision_audit.event_appended`` mirror
        for an :class:`AuditStore` append (T12 R2 P2 #1). Carries
        the same payload-identity fields as the DH-side variant so
        consumers can identify the source uniformly across both
        chains; ``data.chain_id`` distinguishes ``"audit_event"``
        from ``"decision_history"``.
        """
        event = DecisionAuditEventAppended(
            ts=snapshot.created_at,
            tenant=snapshot.tenant_id,
            trace_id=snapshot.trace_id,
            audit_chain_hash=_format_chain_hash(snapshot.new_hash),
            data={
                "event_type": snapshot.event_type,
                "payload_digest": _payload_digest(snapshot.payload),
                "request_id": snapshot.request_id,
                "sequence": snapshot.sequence,
                "chain_id": snapshot.chain_id,
                "tenant_id": snapshot.tenant_id,
            },
        )
        await self._safe_emit(event)

    async def _emit_tool_call(
        self,
        snapshot: AppendedEventSnapshot,
        family: Literal["tool_call"],
        type_name: str,
    ) -> None:
        """Build the typed ``tool_call.*`` event from the audit
        snapshot."""
        event_cls: type[_BaseEvent]
        if type_name == "completed":
            event_cls = ToolCallCompleted
        elif type_name == "denied":
            event_cls = ToolCallDenied
        elif type_name == "failed":
            event_cls = ToolCallFailed
        else:  # pragma: no cover (closed routing table)
            return
        event = event_cls(
            ts=snapshot.created_at,
            tenant=snapshot.tenant_id,
            trace_id=snapshot.trace_id,
            audit_chain_hash=_format_chain_hash(snapshot.new_hash),
            data={
                "request_id": snapshot.request_id,
                "sequence": snapshot.sequence,
                "audit_event_type": snapshot.event_type,
            },
        )
        await self._safe_emit(event)

    async def _emit_artifact(
        self,
        snapshot: AppendedEventSnapshot,
        family: Literal["artifact"],
        type_name: str,
    ) -> None:
        """Build the typed ``artifact.*`` event from the audit
        snapshot."""
        if type_name != "completed":  # pragma: no cover (closed routing table)
            return
        event = ArtifactCompleted(
            ts=snapshot.created_at,
            tenant=snapshot.tenant_id,
            trace_id=snapshot.trace_id,
            audit_chain_hash=_format_chain_hash(snapshot.new_hash),
            data={
                "request_id": snapshot.request_id,
                "sequence": snapshot.sequence,
                "audit_event_type": snapshot.event_type,
            },
        )
        await self._safe_emit(event)

    async def _safe_emit(self, event: _BaseEvent) -> None:
        """Dispatch to all registered hooks. One broken hook does
        NOT poison emission to subsequent hooks — try/except per
        hook, log token-free, continue iteration.

        T12 R1 P2 #2 reviewer correction: each hook receives a
        **deep copy** of ``event`` via ``model_copy(deep=True)``.
        Pydantic v2's ``frozen=True`` is shallow — the dict
        referenced by ``event.data`` is mutable, and a misbehaving
        first hook could mutate it before later hooks see it
        (subverting the wire-payload-immutability invariant the
        public schema claims). Deep-copying per hook gives each
        subscriber its own independent reference; mutation by
        subscriber A cannot affect subscriber B or any future SSE
        buffer (Sprint-7B).
        """
        # Subclasses (ToolCallCompleted, ArtifactCompleted, ...) carry
        # ``family`` + ``type`` Literal fields; the base class doesn't
        # statically know about them, so read via Pydantic's runtime
        # field accessor.
        event_dump = event.model_dump()
        event_family = event_dump.get("family")
        event_type = event_dump.get("type")
        # T12 R2 P3 reviewer correction: snapshot the registry before
        # dispatch. A hook that calls ``register_hook`` during
        # emission would otherwise be invoked for the current event
        # AND keep extending the loop's iteration target — a
        # self-registering hook never returns. ``tuple(self._hooks)``
        # freezes the dispatch list at entry; new registrations land
        # for the NEXT emission.
        for hook in tuple(self._hooks):
            try:
                # Deep-copy per hook (T12 R1 P2 #2). Pydantic's
                # ``model_copy(deep=True)`` recursively copies
                # mutable containers + nested models so a hook
                # mutating ``copy.data`` cannot affect any other
                # hook's view.
                hook_event = event.model_copy(deep=True)
                await hook(hook_event)
            except Exception as exc:
                _LOG.warning(
                    "ui_events.hook_emit_failed: hook=%s family=%s "
                    "type=%s error_type=%s; subsequent hooks unaffected.",
                    getattr(hook, "__qualname__", type(hook).__name__),
                    event_family,
                    event_type,
                    type(exc).__name__,
                )


def _format_chain_hash(hash_bytes: bytes) -> str:
    """Format a chain-row hash as ``"sha256:<hex>"`` per ADR-020
    wire-format spec."""
    return f"sha256:{hash_bytes.hex()}"


def _payload_digest(payload: dict[str, Any]) -> str:
    """SHA-256 digest of the canonicalised payload (T12 R2 P2 #2).

    The digest is computed over the same canonical bytes the audit /
    decision_history chains hash into the chain row, so a UI
    consumer comparing the ``data.payload_digest`` field against a
    later DB read can verify byte-equivalence.

    Returns ``"sha256:<hex>"`` for parity with the chain-hash format
    (the leading scheme tag lets future bumps swap algorithms
    without ambiguity).
    """
    return f"sha256:{hashlib.sha256(canonical_bytes(payload)).hexdigest()}"


__all__ = (
    "SCHEMA_VERSION",
    "AgentRunCancelled",
    "AgentRunCompleted",
    "AgentRunFailed",
    "AgentRunPaused",
    "AgentRunProgress",
    "AgentRunResumed",
    # event family models — agent_run
    "AgentRunStarted",
    "ApprovalDenied",
    "ApprovalExpired",
    "ApprovalGranted",
    "ApprovalGrantedSecond",
    # approval
    "ApprovalPending",
    "ArtifactChunk",
    "ArtifactCompleted",
    # artifact
    "ArtifactStarted",
    # decision_audit
    "DecisionAuditEventAppended",
    "FrontendActionAccepted",
    "FrontendActionRejected",
    # frontend_action
    "FrontendActionSubmitted",
    "InterruptAcknowledged",
    # interrupt
    "InterruptRequestedByAgent",
    "InterruptRequestedByOperator",
    # kill_switch
    "KillSwitchFlipped",
    "KillSwitchReverted",
    "MemoryForget",
    "MemoryRecallCompleted",
    # memory
    "MemoryRecallStarted",
    "MemoryRedact",
    "PolicyBundleLoaded",
    # policy
    "PolicyDecisionEvaluated",
    "SubagentCompleted",
    "SubagentFailed",
    "SubagentRecursionCapped",
    # subagent
    "SubagentSpawned",
    "ToolCallApproved",
    "ToolCallCompleted",
    "ToolCallDenied",
    "ToolCallFailed",
    "ToolCallProgress",
    # tool_call
    "ToolCallRequested",
    "ToolCallStarted",
    "UIEvent",
    "UIEventEmitter",
    "UIEventHook",
)
