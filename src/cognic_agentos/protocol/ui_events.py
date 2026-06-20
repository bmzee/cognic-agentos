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

import asyncio
import dataclasses
import datetime as _dt
import hashlib
import logging
import uuid
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from typing import Annotated, Any, Final, Literal, get_args

import pydantic
from ulid import ULID

from cognic_agentos.core.audit import AppendedEventSnapshot, AuditStore
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import (
    AppendedDecisionSnapshot,
    DecisionHistoryStore,
    DecisionRecord,
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


#: Sprint-7B.4 T3 — the 9 families that flow over SSE in Wave 1.
#:
#: A strict subset of :data:`_WAVE_1_FAMILIES` (11 families). The 2
#: excluded families (``tool_call`` + ``artifact``) are audit-event-
#: backed (mirrored from the audit chain by the Sprint-6 hook), not
#: decision-history-backed; the Wave-1 SSE transport is
#: decision-history-only per the design spec §4.2. The byte slot for
#: an audit-event SSE surface stays reserved (cursor `chain_disc=0x02`
#: refuses fail-closed in :func:`_decode_chain_cursor`) for a Wave-2
#: expansion that does NOT re-cut the wire format.
#:
#: Drift in this set is wire-protocol drift — pinned by the
#: TestSSEWave1StreamedFamilies regression in
#: ``tests/unit/protocol/test_ui_events_rbac_denial_type.py``.
_SSE_WAVE_1_STREAMED_FAMILIES: Final[frozenset[str]] = frozenset(
    {
        "policy",
        "decision_audit",
        "agent_run",
        "subagent",
        "approval",
        "interrupt",
        "frontend_action",
        "memory",
        "kill_switch",
    }
)


#: Sprint-7B.4 T3 — protocol-owned 9-value union over the 4 portal RBAC
#: denial vocabularies (`portal/rbac/enforcement.RBACDenialReason` +
#: `portal/rbac/tenant_isolation.TenantIsolationFailure` +
#: `portal/rbac/human_actor.HumanActorDenialReason` +
#: `portal/rbac/role_separation.RoleSeparationFailure`).
#:
#: **Architectural-arrow invariant:** this Literal is defined HERE,
#: NOT imported from `portal/rbac/*`. The protocol layer is upstream
#: of portal; the union equality with the 4 source Literals is
#: enforced AT THE TEST LAYER so this module stays import-clean.
#:
#: Used as the discriminator on `rbac.<denial_type>` chain events
#: appended via `UIEventBroker.emit_rbac_denial` (Sprint 7B.4 T4),
#: which feeds the `PolicyRBACDenied` typed-projector path. Drift
#: with the 4 portal vocabularies is wire-protocol drift (the 403
#: response body's `reason` field per ADR-012 §40 + AGENTS.md
#: "Wire-protocol contracts" stop rule).
RBACDenialType = Literal[
    # from portal/rbac/enforcement.py:53 — RBACDenialReason (3)
    "actor_unauthenticated",
    "scope_not_held",
    "actor_binder_not_configured",
    # from portal/rbac/tenant_isolation.py:67 — TenantIsolationFailure (4)
    "tenant_id_mismatch",
    "pack_not_found",
    "actor_tenant_id_missing",
    "pack_store_not_configured",
    # from portal/rbac/human_actor.py:48 — HumanActorDenialReason (1)
    "actor_type_must_be_human",
    # from portal/rbac/role_separation.py:93 — RoleSeparationFailure (1)
    "actor_cannot_review_own_pack",
]


#: Sprint-7B.4 T4 R1 — runtime-checkable closed-set view of
#: :data:`RBACDenialType`. Computed once at module import (Literal members
#: are static; `get_args` is cheap-but-not-free). Both the typed-projector
#: dispatcher AND :meth:`UIEventBroker.emit_rbac_denial` gate the
#: `rbac.<denial_type>` vocabulary against THIS frozenset:
#:
#:   - Dispatcher: an unknown `rbac.<suffix>` falls through to None
#:     (mirror-only path) rather than silently routing to
#:     :class:`PolicyRBACDenied` and weakening the 9-value vocabulary.
#:   - Broker emit seam: an unknown `denial_type` refuses with
#:     :class:`ValueError` BEFORE any chain row is appended — caller
#:     typos cannot persist out-of-vocabulary RBAC chain rows.
#:
#: Drift detector in `tests/unit/protocol/test_ui_events_rbac_denial_type.py`
#: pins this set against the 4 portal RBAC Literals (union equality).
_RBAC_DENIAL_TYPE_VALUES: Final[frozenset[str]] = frozenset(get_args(RBACDenialType))


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
# Chain-derived event_id cursor (Sprint-7B.4 T3) — wire-protocol-public
# ---------------------------------------------------------------------------
#
# SSE-resume cursors per ADR-020 + the 7B.4 design spec §4.3. The
# event_id format remains `evt_<26 base32 ULID>` (30 chars total) as
# already published in Sprint 6, but for typed events derived from a
# chain row the 16-byte ULID payload is NOT random — it encodes the
# chain coordinates so the SSE replay endpoint can decode a resume
# cursor back into `(chain_id, sequence, ordinal, type_hash)` without
# round-tripping the database.
#
# **16-byte payload layout (locked at 7B.4 design spec §4.3):**
#
#     | offset | bytes | field        | meaning                                |
#     |--------|-------|--------------|----------------------------------------|
#     | 0      | 1     | chain_disc   | 0x01=decision_history, 0x02=audit_event |
#     | 1..8   | 8     | sequence     | big-endian chain row sequence          |
#     | 9      | 1     | ordinal      | per-row event ordinal (0=typed, 1=mirror) |
#     | 10..15 | 6     | type_hash    | sha256("<family>.<type>")[:6]          |
#
# Wave-1 only honors `chain_disc=0x01` (decision_history). Cursors
# minted against the audit chain (`chain_disc=0x02`) decode-refuse
# with :class:`CursorChainUnsupported`; the byte slot stays reserved
# so a Wave-2 audit-event SSE surface can use it without re-cutting
# the wire format.
#
# Determinism is load-bearing: the broker resolves the event_id of
# an in-flight chain append by re-encoding the persisted
# (sequence, ordinal, family, type) tuple. If `_chain_derived_event_id`
# were nondeterministic the broker's captured event_id would diverge
# from the SSE-fanout event_id and subscribers would see cursor drift.


#: Wave-1 supports `decision_history` only. `audit_event` is byte-reserved
#: for the Wave-2 audit-event SSE surface; the decoder refuses it
#: fail-closed in Wave-1.
ChainId = Literal["decision_history", "audit_event"]

#: Forward map: ChainId → 1-byte discriminator written at payload offset 0.
_CHAIN_DISCRIMINATOR_BYTES: Final[dict[ChainId, int]] = {
    "decision_history": 0x01,
    "audit_event": 0x02,
}

#: Reverse map for decode. Closed-set on the forward map's values; any
#: byte outside this set raises :class:`CursorChainUnsupported`.
_CHAIN_DISCRIMINATOR_REVERSE: Final[dict[int, ChainId]] = {
    v: k for k, v in _CHAIN_DISCRIMINATOR_BYTES.items()
}


class CursorMalformed(ValueError):
    """Cursor `event_id` failed shape validation (wrong prefix, wrong
    length, or base32 decoding raised). Maps to HTTP 422 ``cursor_malformed``
    at the SSE route per the design spec §4.3."""


class CursorChainUnsupported(ValueError):
    """Cursor's `chain_disc` byte is outside the Wave-1 supported set.
    Wave-1 supports `chain_disc=0x01` (decision_history) only;
    `chain_disc=0x02` is byte-reserved for the Wave-2 audit-event SSE
    surface and refuses fail-closed here so a probe cannot fall back
    to the decision_history chain by accident. Maps to HTTP 422
    ``cursor_chain_unsupported`` at the SSE route."""


@dataclasses.dataclass(frozen=True, slots=True)
class ChainCursor:
    """Decoded cursor coordinates per the locked 16-byte payload layout.

    `type_hash` is exactly 6 bytes; the boundary `type_hash` drift
    detector in the replay path compares this against the projector's
    expected `sha256("<family>.<type>")[:6]` to detect Pydantic-model
    rename drift mid-stream."""

    chain_id: ChainId
    sequence: int
    ordinal: int
    type_hash: bytes  # exactly 6 bytes


def _chain_derived_event_id(
    *,
    chain_id: ChainId,
    sequence: int,
    ordinal: int,
    family: str,
    type_: str,
) -> str:
    """Encode the 16-byte cursor payload into ``evt_<26 base32>``.

    The output shape matches :func:`_new_event_id` (30 chars total,
    ``evt_`` prefix, 26-char Crockford-base32 ULID body) so SSE
    consumers cannot distinguish chain-derived cursors from random
    event_ids by inspection — the decoder is the only authoritative
    source of cursor coordinates.

    Per the locked T3 layout: ``chain_disc`` (1 byte) + ``sequence``
    (8 bytes big-endian) + ``ordinal`` (1 byte) + ``type_hash``
    (6 bytes = sha256(family.type)[:6]) = exactly 16 bytes.
    """
    chain_disc = _CHAIN_DISCRIMINATOR_BYTES[chain_id].to_bytes(1, "big")
    seq_bytes = sequence.to_bytes(8, "big")
    ordinal_byte = ordinal.to_bytes(1, "big")
    type_hash = hashlib.sha256(f"{family}.{type_}".encode()).digest()[:6]
    payload = chain_disc + seq_bytes + ordinal_byte + type_hash
    # Length guard — load-bearing: ULID.from_bytes() raises on != 16 bytes,
    # but the explicit assert pins the spec-locked size as a regression boundary.
    assert len(payload) == 16, f"cursor payload must be 16 bytes, got {len(payload)}"
    return f"evt_{ULID.from_bytes(payload)}"


def _decode_chain_cursor(event_id: str) -> ChainCursor:
    """Decode ``evt_<26 base32>`` → :class:`ChainCursor`.

    Fail-closed at every shape boundary: malformed prefix / length /
    base32 → :class:`CursorMalformed`; unsupported `chain_disc` byte
    → :class:`CursorChainUnsupported`. No silent fallback — a
    Wave-2 cursor passed to a Wave-1 endpoint MUST refuse, NOT
    re-interpret as decision_history.
    """
    if not event_id.startswith("evt_") or len(event_id) != 30:
        raise CursorMalformed(f"invalid event_id format: {event_id!r}")
    try:
        payload = bytes(ULID.from_str(event_id[4:]))
    except (ValueError, TypeError) as exc:
        raise CursorMalformed(f"base32 decode failed for {event_id!r}") from exc
    chain_disc = payload[0]
    if chain_disc not in _CHAIN_DISCRIMINATOR_REVERSE:
        raise CursorChainUnsupported(f"chain_disc=0x{chain_disc:02x} not in Wave-1 supported set")
    if chain_disc != 0x01:  # Wave-1: only decision_history is honored
        raise CursorChainUnsupported(
            f"chain_disc=0x{chain_disc:02x} reserved for Wave-2 (audit_event SSE)"
        )
    return ChainCursor(
        chain_id=_CHAIN_DISCRIMINATOR_REVERSE[chain_disc],
        sequence=int.from_bytes(payload[1:9], "big"),
        ordinal=payload[9],
        type_hash=payload[10:16],
    )


# ---------------------------------------------------------------------------
# AppendResult — broker chain-append return shape (Sprint-7B.4 T3)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class AppendResult:
    """Sprint-7B.4 T3 — broker chain-append return shape.

    Returned by every ``UIEventBroker.emit_*`` / ``append_*`` seam
    (T4). The deterministic ``event_id`` is resolved by the broker
    from the typed event that fires synchronously during the awaited
    ``DecisionHistoryStore.append`` — see T4 for the ContextVar
    capture mechanism that bridges the typed-projector hook back to
    the broker's `append_*` return.

    Wire-protocol-public to T10 SSE route handlers (the
    ``submitted_event_id`` + ``resolution_event_id`` cursors on
    ``ActionResponse`` are these values), and to T11 action-route
    handlers. Field additions are wire-extensions; renames or
    removals are wire-breaking.

    Frozen + slotted: instances cannot be mutated after construction;
    test fixtures and route handlers can safely hand the same
    ``AppendResult`` to multiple consumers without aliasing risk.
    """

    record_id: uuid.UUID
    chain_hash: bytes
    event_id: str


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


# ---- subagent.* (emit hooks wired in Sprint 11b T9 — ADR-005 + ADR-020) ------


class SubagentSpawned(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["spawned"] = "spawned"


class SubagentCompleted(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["completed"] = "completed"


class SubagentFailed(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["failed"] = "failed"


class SubagentPending(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["pending"] = "pending"


class SubagentRecursionCapped(_BaseEvent):
    family: Literal["subagent"] = "subagent"
    type: Literal["recursion_capped"] = "recursion_capped"


# ---- approval.* (schema only — the 13.5 arc landed the approval engine +
# portal WITHOUT UI emit hooks; wiring is a named follow-up, unscheduled) ------


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


# ---- interrupt.* (schema only — unwired; no run primitive exists yet, so the
# emit hooks ride the managed-runtime work, unscheduled) -----------------------


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


# ---- policy.* (decision_evaluated + rbac_denied WIRED via the typed-projector
# registry below; bundle_loaded remains schema-only) ---------------------------


class PolicyDecisionEvaluated(_BaseEvent):
    family: Literal["policy"] = "policy"
    type: Literal["decision_evaluated"] = "decision_evaluated"


class PolicyBundleLoaded(_BaseEvent):
    family: Literal["policy"] = "policy"
    type: Literal["bundle_loaded"] = "bundle_loaded"


class PolicyRBACDenied(_BaseEvent):
    """Sprint-7B.4 T3 — typed event for `rbac.<denial_type>` chain rows.

    Reuses the reserved `policy.*` family slot per ADR-020 — the
    11-family `_WAVE_1_FAMILIES` set stays unchanged, the
    `rbac.<denial_type>` decision_type collapses onto the existing
    `policy` family rather than introducing a 12th family.

    The portal-typed fields (`denial_type`, `actor_subject`,
    `request_id`, `required_scope`, `pack_id`, etc.) travel inside
    the inherited `data: dict[str, Any]` field — NOT as bare typed
    attributes — per the architectural-arrow invariant (protocol
    cannot import portal-owned closed-enum types).
    """

    family: Literal["policy"] = "policy"
    type: Literal["rbac_denied"] = "rbac_denied"


# ---- kill_switch.* (wired Sprint 13.6 — emergency.kill_switch_* projectors) --


class KillSwitchFlipped(_BaseEvent):
    family: Literal["kill_switch"] = "kill_switch"
    type: Literal["flipped"] = "flipped"


class KillSwitchReverted(_BaseEvent):
    family: Literal["kill_switch"] = "kill_switch"
    type: Literal["reverted"] = "reverted"


# ---------------------------------------------------------------------------
# Discriminated union — Pydantic v2 Annotated[Union[...], discriminator]
# ---------------------------------------------------------------------------


#: All 36 typed event subclasses (sum of family-event-counts across
#: the 11 Wave-1 families per ADR-020 §"Event taxonomy (Wave 1)"):
#: 7 agent_run + 7 tool_call + 4 subagent + 5 approval + 3 artifact +
#: 3 interrupt + 3 frontend_action + 4 memory + 1 decision_audit +
#: 3 policy + 2 kill_switch.
#: (policy bumped 2 → 3 at Sprint-7B.4 T3 / R1: PolicyRBACDenied lands
#: in the policy.* slot alongside PolicyDecisionEvaluated +
#: PolicyBundleLoaded; the `_PolicyEvent` discriminated union and the
#: total count update together so TypeAdapter(UIEvent) accepts every
#: defined event class.)
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
    SubagentSpawned
    | SubagentCompleted
    | SubagentFailed
    | SubagentPending
    | SubagentRecursionCapped,
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
    PolicyDecisionEvaluated | PolicyBundleLoaded | PolicyRBACDenied,
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
# Typed decision_history projectors (Sprint-7B.4 T4) — wire-protocol-public
# ---------------------------------------------------------------------------
#
# 4 exact-match projectors + 1 prefix-match (`rbac.*`) project decision_history
# rows whose decision_type matches a known shape into the typed event family
# slot. Unknown decision_types fall through to None — the emitter still emits
# the always-on `decision_audit.event_appended` mirror at ordinal 1.
#
# Each projector consumes an :class:`AppendedDecisionSnapshot` (post-commit
# snapshot from the DH chain) and returns a typed _BaseEvent subclass whose
# `event_id` is the deterministic 16-byte cursor for (chain_id, sequence,
# ordinal=0, family.type) per T3.


def _project_frontend_action_submitted(
    snapshot: AppendedDecisionSnapshot,
) -> FrontendActionSubmitted:
    return FrontendActionSubmitted(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="frontend_action",
            type_="submitted",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


def _project_frontend_action_accepted(snapshot: AppendedDecisionSnapshot) -> FrontendActionAccepted:
    return FrontendActionAccepted(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="frontend_action",
            type_="accepted",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


def _project_frontend_action_rejected(snapshot: AppendedDecisionSnapshot) -> FrontendActionRejected:
    return FrontendActionRejected(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="frontend_action",
            type_="rejected",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


def _project_policy_decision_evaluated(
    snapshot: AppendedDecisionSnapshot,
) -> PolicyDecisionEvaluated:
    return PolicyDecisionEvaluated(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="policy",
            type_="decision_evaluated",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


def _project_policy_rbac_denied(snapshot: AppendedDecisionSnapshot) -> PolicyRBACDenied:
    """Prefix-matched: snapshot.decision_type starts with `rbac.`."""
    return PolicyRBACDenied(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="policy",
            type_="rbac_denied",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


def _project_subagent_spawned(snapshot: AppendedDecisionSnapshot) -> SubagentSpawned:
    """Sprint 11b T9 — subagent.spawn → subagent.spawned (ADR-005 §Audit)."""
    return SubagentSpawned(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="subagent",
            type_="spawned",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


def _project_subagent_return(
    snapshot: AppendedDecisionSnapshot,
) -> SubagentCompleted | SubagentFailed | SubagentPending:
    """Sprint 11b T9 — subagent.return → completed/failed by payload['outcome']
    (`{"completed","failed"}` per subagent/audit.py). Anything that is not
    `"completed"` (incl. a missing/unknown outcome) projects to
    `subagent.failed` — the conservative UI signal. ALWAYS returns a typed
    event (never None) so the replay-snapshot drift test's not-None invariant
    holds for this registry entry."""
    family: Literal["subagent"] = "subagent"
    if snapshot.payload.get("outcome") == "completed":
        return SubagentCompleted(
            event_id=_chain_derived_event_id(
                chain_id="decision_history",
                sequence=snapshot.sequence,
                ordinal=0,
                family=family,
                type_="completed",
            ),
            ts=snapshot.created_at,
            tenant=snapshot.tenant_id,
            trace_id=snapshot.trace_id,
            audit_chain_hash=_format_chain_hash(snapshot.new_hash),
            data=snapshot.payload,
        )
    if snapshot.payload.get("outcome") == "pending_approval":
        return SubagentPending(
            event_id=_chain_derived_event_id(
                chain_id="decision_history",
                sequence=snapshot.sequence,
                ordinal=0,
                family=family,
                type_="pending",
            ),
            ts=snapshot.created_at,
            tenant=snapshot.tenant_id,
            trace_id=snapshot.trace_id,
            audit_chain_hash=_format_chain_hash(snapshot.new_hash),
            data=snapshot.payload,
        )
    return SubagentFailed(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family=family,
            type_="failed",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


# ---------------------------------------------------------------------------
# Sprint 11.5c T6 — memory.* typed projectors
# ---------------------------------------------------------------------------
# Four chain decision_types wire to three model classes:
#   memory.read              → MemoryRecallCompleted  (data = snapshot.payload)
#   memory.forget            → MemoryForget           (data = {**payload, "purged": False})
#   memory.regulator_erasure → MemoryForget           (data = {**payload, "purged": True})
#   memory.redact            → MemoryRedact           (data = snapshot.payload)
#
# The `purged` bool injection is the ONE deliberate deviation from the
# pure-payload pass-through: both `memory.forget` (tombstone) and
# `memory.regulator_erasure` (physical purge) collapse onto MemoryForget
# (type="forget"), so the projected data MUST carry `purged` so the UI can
# distinguish the two without inspecting the (now-erased) decision_type.
#
# MemoryRecallStarted stays a schema-only stub — there is no chain row
# emitted at recall-START (only at recall-COMPLETE), so no projector is
# registered for it.


def _project_memory_recall_completed(
    snapshot: AppendedDecisionSnapshot,
) -> MemoryRecallCompleted:
    """Sprint 11.5c T6 — memory.read → memory.recall_completed."""
    return MemoryRecallCompleted(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="memory",
            type_="recall_completed",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


def _project_memory_forget(
    snapshot: AppendedDecisionSnapshot,
) -> MemoryForget:
    """Sprint 11.5c T6 — memory.forget → memory.forget (purged=False).

    Tombstone path: the record is soft-deleted. `purged=False` distinguishes
    this from `memory.regulator_erasure` (purged=True) in the UI event stream
    without requiring the consumer to read the (now-erased) decision_type.
    """
    return MemoryForget(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="memory",
            type_="forget",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        # Inject `purged=False` — tombstone, NOT physical erasure.
        data={**snapshot.payload, "purged": False},
    )


def _project_memory_regulator_erasure(
    snapshot: AppendedDecisionSnapshot,
) -> MemoryForget:
    """Sprint 11.5c T6 — memory.regulator_erasure → memory.forget (purged=True).

    Physical erasure path (regulator order). `purged=True` distinguishes this
    from `memory.forget` (purged=False) in the UI event stream without
    requiring the consumer to read the (now-erased) decision_type.
    """
    return MemoryForget(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="memory",
            type_="forget",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        # Inject `purged=True` — physical erasure, NOT a tombstone.
        data={**snapshot.payload, "purged": True},
    )


def _project_memory_redact(
    snapshot: AppendedDecisionSnapshot,
) -> MemoryRedact:
    """Sprint 11.5c T6 — memory.redact → memory.redact."""
    return MemoryRedact(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="memory",
            type_="redact",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


def _is_subagent_depth_cap(snapshot: AppendedDecisionSnapshot) -> bool:
    """Sprint 11b T9 — scope an escalation.opened row to a subagent recursion
    cap. The T6 spawn path refuses a depth-exceeding spawn BEFORE it emits
    subagent.spawn, opening an escalation with `level="depth_exceeded"` carrying
    the `subagent-spawn-*` request_id. Both signals MUST match so a generic
    escalation (different level) or a depth cap from another subsystem
    (different request_id prefix) does NOT project subagent.recursion_capped."""
    return snapshot.payload.get("level") == "depth_exceeded" and snapshot.request_id.startswith(
        "subagent-spawn-"
    )


def _project_subagent_recursion_capped(
    snapshot: AppendedDecisionSnapshot,
) -> SubagentRecursionCapped:
    """Sprint 11b T9 — a scoped depth-cap escalation.opened row →
    subagent.recursion_capped. Reached via the dispatcher's escalation branch
    AFTER :func:`_is_subagent_depth_cap` confirms the scoping (A-projector)."""
    return SubagentRecursionCapped(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="subagent",
            type_="recursion_capped",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


def _project_kill_switch_flipped(snapshot: AppendedDecisionSnapshot) -> KillSwitchFlipped:
    """Sprint 13.6 T3 — emergency.kill_switch_flipped → kill_switch.flipped
    (ADR-018 + ADR-020). The flip payload (class / scope_key / category /
    reason / active / enforcement_status + the DH-merged actor_id) rides
    ``data`` per the policy-family precedent — no model field changes."""
    return KillSwitchFlipped(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="kill_switch",
            type_="flipped",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


def _project_kill_switch_reverted(snapshot: AppendedDecisionSnapshot) -> KillSwitchReverted:
    """Sprint 13.6 T3 — emergency.kill_switch_reverted → kill_switch.reverted."""
    return KillSwitchReverted(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=0,
            family="kill_switch",
            type_="reverted",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


#: Exact-match dispatch table from DH `decision_type` → typed projector.
#: Prefix-matched `rbac.*` falls out of this map and into the dispatcher's
#: prefix check below; `escalation.opened` falls out into the scoped subagent
#: depth-cap branch. Drift: adding a new typed projector requires (a) a new
#: projector function, (b) entry here OR prefix/conditional support, (c) the
#: class added to `_TYPED_PROJECTION_CLASSES` (so the ContextVar capture fires).
_DECISION_HISTORY_TYPED_PROJECTORS: Final[
    dict[str, Callable[[AppendedDecisionSnapshot], _BaseEvent]]
] = {
    "frontend_action.submitted": _project_frontend_action_submitted,
    "frontend_action.accepted": _project_frontend_action_accepted,
    "frontend_action.rejected": _project_frontend_action_rejected,
    "policy.decision_evaluated": _project_policy_decision_evaluated,
    "subagent.spawn": _project_subagent_spawned,
    "subagent.return": _project_subagent_return,
    # Sprint 11.5c T6 — memory.* chain event projectors.
    # `memory.forget` and `memory.regulator_erasure` both map to MemoryForget
    # but inject distinct `purged` bool values (False/True) so the UI can
    # distinguish a tombstone from a physical erasure without inspecting the
    # (now-erased) decision_type.
    "memory.read": _project_memory_recall_completed,
    "memory.forget": _project_memory_forget,
    "memory.regulator_erasure": _project_memory_regulator_erasure,
    "memory.redact": _project_memory_redact,
    # Sprint 13.6 T3 — emergency kill-switch flip/revert evidence rows
    # (ADR-018; the kill_switch family's owning sprint per the ADR-020
    # phase table).
    "emergency.kill_switch_flipped": _project_kill_switch_flipped,
    "emergency.kill_switch_reverted": _project_kill_switch_reverted,
}


def _project_typed_decision_history(snapshot: AppendedDecisionSnapshot) -> _BaseEvent | None:
    """Dispatch a DH snapshot to its typed projector.

    Returns the typed event for known decision_types (4 exact-match keys +
    `rbac.<suffix>` where `<suffix>` is in :data:`_RBAC_DENIAL_TYPE_VALUES`),
    or None when no projector matches. The caller MUST still emit the
    generic `decision_audit.event_appended` mirror at ordinal 1 regardless
    of typed-projection outcome.

    R1 fix: the `rbac.*` prefix is gated against the 9-value closed set
    rather than promoting ANY suffix. An unknown `rbac.<typo>` falls
    through to None (mirror-only path) — silently routing a typo to
    :class:`PolicyRBACDenied` would weaken the locked vocabulary and let
    a mis-spelled denial appear as a real typed policy event.
    """
    dt = snapshot.decision_type
    if dt in _DECISION_HISTORY_TYPED_PROJECTORS:
        return _DECISION_HISTORY_TYPED_PROJECTORS[dt](snapshot)
    if dt.startswith("rbac."):
        suffix = dt[len("rbac.") :]
        if suffix in _RBAC_DENIAL_TYPE_VALUES:
            return _project_policy_rbac_denied(snapshot)
        # Unknown rbac.<suffix> falls through — mirror-only emission.
    # Subagent recursion cap (Sprint 11b T9): the T6 depth-refusal path refuses
    # BEFORE it emits subagent.spawn, so its only evidence is a scoped
    # escalation.opened row. A generic escalation.opened falls through to None.
    if dt == "escalation.opened" and _is_subagent_depth_cap(snapshot):
        return _project_subagent_recursion_capped(snapshot)
    return None


@dataclasses.dataclass(frozen=True)
class _DHReplaySnapshot:
    """Sprint-7B.4 T10 R3 #1 — replay-side snapshot shape compatible with
    :class:`AppendedDecisionSnapshot` field access.

    Constructed by ``_replay_from_decision_history`` in
    :file:`portal/api/ui/stream_routes.py` from raw SQLAlchemy rows of
    the exported :data:`cognic_agentos.core.decision_history._decision_history`
    Table; consumed by the existing typed projectors
    (:func:`_project_typed_decision_history`,
    :func:`_build_decision_audit_for_dh_snapshot`) so the live + replay
    paths stay byte-identical.

    Carries EXACTLY the fields the projector functions read — drift
    between this dataclass and the projector field-access surface is
    pinned by
    :class:`tests.unit.protocol.test_ui_events_dh_replay_snapshot.TestDHReplaySnapshotShapeMatchesAppendedDecisionSnapshot`
    (4 regressions: field-name subset of ``AppendedDecisionSnapshot``,
    exact 9-field set, projector access surface ⊆ replay fields, +
    runtime projector-call smoke against a constructed instance).

    Module-private (leading underscore) — NOT in ``__all__``. The
    consumers are :func:`_project_typed_decision_history` +
    :func:`_build_decision_audit_for_dh_snapshot` (also module-private
    helpers) and the T10 SSE replay path (which imports it via the
    underscore name explicitly).
    """

    sequence: int
    decision_type: str
    tenant_id: str | None
    trace_id: str | None
    request_id: str
    payload: dict[str, Any]
    new_hash: bytes
    chain_id: str
    created_at: _dt.datetime


def _build_decision_audit_for_dh_snapshot(
    snapshot: AppendedDecisionSnapshot,
) -> DecisionAuditEventAppended:
    """R3 #2 shared helper: build the `decision_audit.event_appended`
    mirror for a DH chain snapshot. Used BOTH by
    :meth:`UIEventEmitter._on_decision_append` (live emit at ordinal 1)
    AND by the T10 SSE replay path so the live + replay paths stay
    byte-identical (same event_id, same data keyset).

    Carries the source row's identity (`event_type`, `payload_digest`,
    `request_id`, `sequence`, `chain_id`, `tenant_id`) per T12 R2 P2 #2
    so a reconnecting UI / examiner can identify the source without
    fetching the DB row.
    """
    return DecisionAuditEventAppended(
        event_id=_chain_derived_event_id(
            chain_id="decision_history",
            sequence=snapshot.sequence,
            ordinal=1,
            family="decision_audit",
            type_="event_appended",
        ),
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


# ---------------------------------------------------------------------------
# UIEventBroker primitive (Sprint-7B.4 T4)
# ---------------------------------------------------------------------------
#
# FastAPI-free in-memory pub/sub primitive. Sits between the DH-store's
# post-commit hook and the SSE route handler:
#
#   POST /actions
#     ↓
#   broker.append_frontend_action_submitted(...)        ← T4 seam
#     ↓
#   DecisionHistoryStore.append(record)                 ← Sprint-2 primitive
#     ↓
#   UIEventEmitter._on_decision_append(snapshot)        ← Sprint-6 hook
#     ↓
#   broker._fanout_hook(typed_event)                    ← T4 ContextVar capture
#       (captures event_id via ContextVar.set BEFORE fan-out)
#     ↓
#   broker._fanout_hook(decision_audit_mirror)          ← ordinal 1
#     ↓
#   AppendResult(record_id, chain_hash, event_id)       ← returned to caller
#
# The ContextVar capture is the load-bearing seam: it lets `_append` resolve
# the deterministic event_id from the typed event that fires synchronously
# during the awaited DH-store append, WITHOUT the broker needing to know how
# the projector mints event_ids.


#: Classes whose `event_id` should be captured into the ContextVar during
#: hook dispatch. The `decision_audit.event_appended` mirror is INTENTIONALLY
#: excluded so its ordinal-1 event_id does NOT overwrite the typed ordinal-0
#: event_id captured first.
_TYPED_PROJECTION_CLASSES: Final[frozenset[type]] = frozenset(
    {
        FrontendActionSubmitted,
        FrontendActionAccepted,
        FrontendActionRejected,
        PolicyDecisionEvaluated,
        PolicyRBACDenied,
        SubagentSpawned,
        SubagentCompleted,
        SubagentFailed,
        SubagentPending,
        SubagentRecursionCapped,
        # Sprint 11.5c T6 — memory.* wired classes.
        # MemoryRecallStarted is intentionally EXCLUDED — it is a schema-only
        # stub with no chain row at recall-START (only recall-COMPLETE fires).
        MemoryRecallCompleted,
        MemoryForget,
        MemoryRedact,
        # Sprint 13.6 T3 — kill_switch family wired (ADR-018).
        KillSwitchFlipped,
        KillSwitchReverted,
    }
)


#: Task-scoped ContextVar capturing the event_id of the typed event projected
#: during the most recent `broker._append` call. Reset to None at the top of
#: every `_append` so a missing typed projection trips the RuntimeError
#: fail-loud path rather than returning a stale event_id from a previous append.
_PENDING_TYPED_EVENT_ID: ContextVar[str | None] = ContextVar(
    "ui_broker_pending_typed_event_id", default=None
)


class TenantConnectionCapExceeded(RuntimeError):
    """Raised by :meth:`UIEventBroker.register_subscriber` when the
    per-tenant SSE-subscriber cap (`Settings.ui_event_stream_per_tenant_cap`)
    is hit. Carries the tenant + cap for operator diagnostics. Maps to
    HTTP 429 `tenant_connection_cap_exceeded` at the T10 SSE route.

    Wave-1 SSE deployments bound concurrent connections per tenant to
    protect the broker from a single-tenant exhaustion attack.
    """

    def __init__(self, *, tenant_id: str, cap: int) -> None:
        super().__init__(
            f"per-tenant SSE subscriber cap exceeded for tenant={tenant_id!r} (cap={cap})"
        )
        self.tenant_id = tenant_id
        self.cap = cap


@dataclasses.dataclass
class Subscriber:
    """One in-process SSE subscriber's per-connection state.

    NOT frozen — `last_activity_at` and `overflow_count` mutate over the
    connection lifetime. `queue` is a bounded `asyncio.Queue` so a slow
    consumer cannot grow broker memory unboundedly.
    """

    tenant_id: str
    run_id_filter: str | None
    family_filter: frozenset[str] | None
    queue: asyncio.Queue[Any]
    overflow_count: int = 0
    last_activity_at: _dt.datetime = dataclasses.field(
        default_factory=lambda: _dt.datetime.now(_dt.UTC)
    )

    def unregister(self) -> None:  # pragma: no cover - convenience hook, T10 wires
        """Convenience marker used by SSE route handlers; the actual removal
        is done by :meth:`UIEventBroker.unregister_subscriber`."""


class UIEventBroker:
    """FastAPI-free in-memory pub/sub primitive per Sprint 7B.4 T4 + ADR-020.

    Wired by `register_with_emitter(emitter)` which subscribes the broker's
    `_fanout_hook` to the existing :class:`UIEventEmitter`. Every event the
    emitter publishes flows through `_fanout_hook` for:

      1. ContextVar capture (typed events only) — populates the pending
         event_id so `_append` can return it inside :class:`AppendResult`.
      2. Family + chain_id filter (Wave-1 SSE = decision-history-only).
      3. Per-subscriber tenant + run_id + family filter.
      4. Bounded `asyncio.Queue` enqueue with overflow accounting.

    The broker also owns the "centralized chain emit" seam for the
    frontend-action and rbac-denial decision_types — route handlers call
    `broker.append_frontend_action_*` / `broker.emit_rbac_denial` instead
    of constructing :class:`DecisionRecord` and calling the DH store
    directly. This guarantees every chain row carrying these decision_types
    flows through the typed-projector path and produces a resolvable
    `event_id` on the returned :class:`AppendResult`.
    """

    def __init__(self, *, decision_history_store: DecisionHistoryStore, settings: Any) -> None:
        self._history = decision_history_store
        self._settings = settings
        self._subscribers: list[Subscriber] = []
        self._per_tenant_count: dict[str, int] = {}

    # ----- emitter hook registration -----

    def register_with_emitter(self, emitter: UIEventEmitter) -> None:
        """Register `_fanout_hook` as a downstream UI event subscriber on
        the emitter. Called once at app bootstrap (T12 `create_app`)."""
        emitter.register_hook(self._fanout_hook)

    async def _fanout_hook(self, event: Any) -> None:
        # 1) Capture event_id FIRST for the typed projection slot — runs
        #    synchronously inside the awaited DH-store append so `_append`
        #    can read the ContextVar after the await returns. Filtered to
        #    `_TYPED_PROJECTION_CLASSES` so the ordinal-1 decision_audit
        #    mirror does NOT overwrite the typed event_id.
        if type(event) in _TYPED_PROJECTION_CLASSES:
            _PENDING_TYPED_EVENT_ID.set(event.event_id)
        # 2) Wave-1 family filter — `tool_call` + `artifact` are
        #    audit-event-backed; they reach the emitter but DO NOT flow
        #    over SSE in Wave-1.
        if event.family not in _SSE_WAVE_1_STREAMED_FAMILIES:
            return
        # 2b) The decision_audit mirror carries the source `chain_id` inside
        #     its data dict; only audit-event-backed mirrors are filtered here
        #     (Wave-1 SSE = decision_history-backed mirrors only).
        if event.family == "decision_audit" and event.data.get("chain_id") != "decision_history":
            return
        # 3) Per-subscriber fan-out with bounded queue.
        for sub in self._subscribers:
            if sub.tenant_id != event.tenant:
                continue
            if sub.run_id_filter is not None and event.run_id != sub.run_id_filter:
                continue
            if sub.family_filter is not None and event.family not in sub.family_filter:
                continue
            try:
                sub.queue.put_nowait(event)
            except asyncio.QueueFull:
                sub.overflow_count += 1
                _LOG.warning(
                    "ui.subscriber.queue_overflow",
                    extra={
                        "tenant": sub.tenant_id,
                        "overflow_count": sub.overflow_count,
                    },
                )

    # ----- centralized chain emit seams -----

    async def append_frontend_action_submitted(
        self,
        *,
        request_id: str,
        action_class: str,
        actor_subject: str,
        client_correlation_id: str | None,
        payload_digest: str,
        tenant_id: str,
        elicitation_mode: str | None = None,
    ) -> AppendResult:
        payload: dict[str, Any] = {
            "request_id": request_id,
            "action_class": action_class,
            "actor_subject": actor_subject,
            "client_correlation_id": client_correlation_id,
            "payload_digest": payload_digest,
        }
        if elicitation_mode is not None:
            payload["elicitation_mode"] = elicitation_mode
        return await self._append(
            decision_type="frontend_action.submitted",
            tenant_id=tenant_id,
            request_id=request_id,
            payload=payload,
            iso_controls=("A.5.31",),
        )

    async def append_frontend_action_accepted(
        self,
        *,
        request_id: str,
        action_class: str,
        actor_subject: str,
        client_correlation_id: str | None,
        submitted_event_id: str,
        tenant_id: str,
        elicitation_mode: str | None = None,
        originating_decision_record_id: str | None = None,
    ) -> AppendResult:
        payload: dict[str, Any] = {
            "request_id": request_id,
            "action_class": action_class,
            "actor_subject": actor_subject,
            "client_correlation_id": client_correlation_id,
            "outcome": "accepted",
            "submitted_event_id": submitted_event_id,
        }
        # P1 #5 (R2): submit_elicitation resolution rows carry BOTH keys
        # together (closed-keyset invariant).
        if elicitation_mode is not None:
            payload["elicitation_mode"] = elicitation_mode
            payload["originating_decision_record_id"] = originating_decision_record_id
        return await self._append(
            decision_type="frontend_action.accepted",
            tenant_id=tenant_id,
            request_id=request_id,
            payload=payload,
            iso_controls=("A.5.31",),
        )

    async def append_frontend_action_rejected(
        self,
        *,
        request_id: str,
        action_class: str,
        actor_subject: str,
        client_correlation_id: str | None,
        submitted_event_id: str,
        reason: str,
        tenant_id: str,
        elicitation_mode: str | None = None,
        originating_decision_record_id: str | None = None,
    ) -> AppendResult:
        payload: dict[str, Any] = {
            "request_id": request_id,
            "action_class": action_class,
            "actor_subject": actor_subject,
            "client_correlation_id": client_correlation_id,
            "outcome": "rejected",
            "submitted_event_id": submitted_event_id,
            "reason": reason,
        }
        if elicitation_mode is not None:
            payload["elicitation_mode"] = elicitation_mode
            payload["originating_decision_record_id"] = originating_decision_record_id
        return await self._append(
            decision_type="frontend_action.rejected",
            tenant_id=tenant_id,
            request_id=request_id,
            payload=payload,
            iso_controls=("A.5.31",),
        )

    async def emit_rbac_denial(
        self,
        *,
        denial_type: RBACDenialType,
        actor_subject: str | None,
        request_id: str,
        http_status: int,
        tenant_id: str | None,
        required_scope: str | None = None,
        pack_id: str | None = None,
        actor_type: str | None = None,
        pack_created_by: str | None = None,
        resource_type: str | None = None,
    ) -> AppendResult:
        """Append a `rbac.<denial_type>` chain row.

        `denial_type` is the protocol-owned :data:`RBACDenialType` 9-value
        closed-enum union over the 4 portal RBAC denial vocabularies.

        tenant_id contract (per design spec P1 #5):
          - actor IS resolved at the call site → pass `actor.tenant_id`.
          - actor is UNRESOLVED (actor_unauthenticated /
            actor_binder_not_configured) → pass `tenant_id=None`. The
            chain row writes (audit surface preserved); SSE subscribers
            filter by event.tenant so unauth denials never reach any
            tenant's stream by design.

        R1 fix: validates `denial_type` against :data:`_RBAC_DENIAL_TYPE_VALUES`
        BEFORE any chain append. The type annotation alone is not enforced at
        runtime (mypy is build-time; callers using `Any` or string literals
        can bypass it), so this runtime guard is the load-bearing seam that
        keeps caller typos from persisting out-of-vocabulary `rbac.<typo>`
        rows. Refusal raises :class:`ValueError` BEFORE `_append` — no chain
        side-effect on invalid input.
        """
        if denial_type not in _RBAC_DENIAL_TYPE_VALUES:
            raise ValueError(
                f"denial_type {denial_type!r} not in the 9-value RBACDenialType "
                f"closed enum; got one of {sorted(_RBAC_DENIAL_TYPE_VALUES)}"
            )
        decision_type = f"rbac.{denial_type}"
        payload: dict[str, Any] = {
            "denial_type": denial_type,
            "actor_subject": actor_subject,
            "denied_at": _dt.datetime.now(_dt.UTC).isoformat(),
            "request_id": request_id,
            "http_status": http_status,
        }
        # Optional fields included only when non-None — keeps the chain
        # payload's keyset minimal and predictable.
        for key, value in (
            ("required_scope", required_scope),
            ("pack_id", pack_id),
            ("actor_type", actor_type),
            ("pack_created_by", pack_created_by),
            ("resource_type", resource_type),
        ):
            if value is not None:
                payload[key] = value
        return await self._append(
            decision_type=decision_type,
            tenant_id=tenant_id,
            request_id=request_id,
            payload=payload,
            iso_controls=("A.5.31",),
        )

    async def _append(
        self,
        *,
        decision_type: str,
        tenant_id: str | None,
        request_id: str,
        payload: dict[str, Any],
        iso_controls: tuple[str, ...],
    ) -> AppendResult:
        """Shared chain-append + event_id resolution path.

        Reset ContextVar to None BEFORE the await so a missing typed
        projector trips the RuntimeError fail-loud path rather than
        returning a stale event_id from a previous append. Production-grade
        rule: no silent fallback to a placeholder cursor.
        """
        _PENDING_TYPED_EVENT_ID.set(None)
        record = DecisionRecord(
            decision_type=decision_type,
            tenant_id=tenant_id,
            request_id=request_id,
            payload=payload,
            iso_controls=iso_controls,
        )
        record_id, chain_hash = await self._history.append(record)
        event_id = _PENDING_TYPED_EVENT_ID.get()
        if event_id is None:
            raise RuntimeError(
                f"broker append seam: no typed event projected for "
                f"decision_type={decision_type!r}; check _DECISION_HISTORY_TYPED_PROJECTORS"
            )
        return AppendResult(record_id=record_id, chain_hash=chain_hash, event_id=event_id)

    # ----- subscriber lifecycle -----

    def register_subscriber(
        self,
        *,
        tenant_id: str,
        run_id_filter: str | None = None,
        family_filter: frozenset[str] | None = None,
    ) -> Subscriber:
        cap = self._settings.ui_event_stream_per_tenant_cap
        if self._per_tenant_count.get(tenant_id, 0) >= cap:
            raise TenantConnectionCapExceeded(tenant_id=tenant_id, cap=cap)
        sub = Subscriber(
            tenant_id=tenant_id,
            run_id_filter=run_id_filter,
            family_filter=family_filter,
            queue=asyncio.Queue(maxsize=self._settings.ui_event_stream_queue_maxsize),
        )
        self._subscribers.append(sub)
        self._per_tenant_count[tenant_id] = self._per_tenant_count.get(tenant_id, 0) + 1
        return sub

    def unregister_subscriber(self, sub: Subscriber) -> None:
        if sub in self._subscribers:
            self._subscribers.remove(sub)
            self._per_tenant_count[sub.tenant_id] = max(
                0, self._per_tenant_count.get(sub.tenant_id, 1) - 1
            )

    def reap_idle(self, now: _dt.datetime) -> int:
        """Close subscribers whose last_activity_at is more than
        `ui_event_stream_idle_timeout_s` seconds before `now`. Returns the
        count of reaped subscribers; called by the T10 SSE route's reap task
        on a cadence."""
        idle_s = self._settings.ui_event_stream_idle_timeout_s
        reaped = 0
        for sub in list(self._subscribers):  # copy — unregister mutates the list
            if (now - sub.last_activity_at).total_seconds() > idle_s:
                self.unregister_subscriber(sub)
                reaped += 1
        return reaped


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

        Two-slot emit per the Sprint-7B.4 T4 canonical projection order:

          - **Ordinal 0 — typed projector (if matched):** dispatches
            through `_project_typed_decision_history`; emits a typed
            family event (FrontendActionSubmitted / accepted / rejected,
            PolicyDecisionEvaluated, or PolicyRBACDenied) when the
            decision_type matches a known shape. Unknown decision_types
            skip this slot.
          - **Ordinal 1 — decision_audit mirror (always):** the
            Sprint-6 invariant. Every DH append emits a generic
            `decision_audit.event_appended` mirror via the shared
            `_build_decision_audit_for_dh_snapshot` helper (R3 #2 —
            shared between live emit + T10 SSE replay so the two paths
            stay byte-identical).

        T12 R2 P2 #2 invariant preserved: the mirror's `data` field
        carries the source row's identity (`event_type`, `payload_digest`,
        `request_id`, `sequence`, `chain_id`, `tenant_id`) so a
        reconnecting UI / examiner can identify the source without
        fetching the DB row.
        """
        typed = _project_typed_decision_history(snapshot)
        if typed is not None:
            await self._safe_emit(typed)
        await self._safe_emit(_build_decision_audit_for_dh_snapshot(snapshot))

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
    "PolicyRBACDenied",
    "SubagentCompleted",
    "SubagentFailed",
    "SubagentPending",
    "SubagentRecursionCapped",
    # subagent
    "SubagentSpawned",
    # broker (Sprint-7B.4 T4)
    "Subscriber",
    "TenantConnectionCapExceeded",
    "ToolCallApproved",
    "ToolCallCompleted",
    "ToolCallDenied",
    "ToolCallFailed",
    "ToolCallProgress",
    # tool_call
    "ToolCallRequested",
    "ToolCallStarted",
    "UIEvent",
    "UIEventBroker",
    "UIEventEmitter",
    "UIEventHook",
)
