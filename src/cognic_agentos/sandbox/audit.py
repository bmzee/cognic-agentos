"""Sprint 8A T4 — sandbox lifecycle event emitters.

NOT on the durable critical-controls coverage gate (thin chain-row
converter; the substantive audit-chain invariants are enforced upstream
by the on-gate ``core/audit.py`` + ``core/decision_history.py`` +
``core/canonical.py``). Per spec §17 critical-controls-scope rationale.

Verified against ``core/decision_history.py:206`` ``DecisionRecord``
shape + ``:409`` ``append_with_precondition`` signature at session
compose time per ``feedback_verify_code_citations_at_doc_write``:

* ``DecisionRecord`` is ``frozen=True, slots=True`` with **exactly 10
  constructor fields** (3 required: ``decision_type`` / ``request_id`` /
  ``payload``; 7 optional: ``actor_id`` / ``tenant_id`` / ``trace_id`` /
  ``span_id`` / ``langfuse_trace_id`` / ``provider_label`` /
  ``iso_controls``). ``session_id`` lives on ``payload`` (per the
  established ``escalation.py:560`` pattern) — NOT as a top-level
  ``DecisionRecord`` field. The fields ``record_id`` / ``chain_id`` /
  ``sequence`` / ``new_hash`` / ``created_at`` live on the SEPARATE
  ``AppendedDecisionSnapshot`` dataclass at
  ``core/decision_history.py:252`` (post-commit hook surface) — NOT
  fields the implementor passes to the ``DecisionRecord`` constructor.
* ``append_with_precondition`` signature: ``precondition`` is
  ``async (conn, prev_sequence, prev_hash) -> T``; ``record_builder``
  is ``sync (captured: T) -> DecisionRecord``. The precondition runs
  INSIDE the chain-head ``FOR UPDATE`` lock; for audit-only events with
  no state precondition, the closure is a no-op that returns ``None``.

ISO 42001 mapping: every chain row tagged with ``("A.6.2.5",)`` per
ADR-006 amendment (sandbox lifecycle audit).
"""

from __future__ import annotations

import typing
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncConnection

from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
)
from cognic_agentos.sandbox.protocol import SandboxLifecycleEvent

_VALID_EVENTS: frozenset[str] = frozenset(typing.get_args(SandboxLifecycleEvent))


# Per-event payload shape contracts (informational; the emit signature
# accepts any dict and the runtime callers MUST match these per spec §4.3):
#   sandbox.lifecycle.created        → {"warm_pool_hit": bool}
#   sandbox.lifecycle.exec_completed → {"exit_code": int, "proxy_log": list[dict]}
#   sandbox.lifecycle.destroyed      → {"duration_s": float}
#   sandbox.lifecycle.refused        → {"reason": SandboxRefusalReason}
#   sandbox.policy.violated          → {"reason": SandboxPolicyViolationReason}
#   sandbox.warm_pool.precreated     → {"pool_key": str, "pool_size_after": int}
#   sandbox.warm_pool.checked_out    → {"pool_key": str, "pool_size_after": int}
#   sandbox.warm_pool.drained        → {"pool_key": str, "drained_count": int}
#
# ``session_id`` is threaded onto every payload by ``emit_sandbox_event``
# (NOT a top-level DR field per the verified DecisionRecord shape).


async def emit_sandbox_event(
    decision_history_store: DecisionHistoryStore,
    *,
    event: SandboxLifecycleEvent,
    tenant_id: str,
    actor_id: str,
    trace_id: str,
    session_id: str,
    payload: dict[str, Any],
) -> tuple[uuid.UUID, bytes]:
    """Emit one sandbox lifecycle event into the chain.

    Tagged with ISO 42001 ``A.6.2.5`` per ADR-006 amendment.

    Returns the ``(record_id, new_hash)`` tuple from
    ``DecisionHistoryStore.append_with_precondition`` per
    ``core/decision_history.py:414``.

    Audit-only events have no transactional precondition (no state
    machine; nothing to read+lock before insert), so the precondition
    closure is a no-op returning ``None``. The ``record_builder``
    receives the captured value (``None``) and builds the
    ``DecisionRecord``.

    ``actor_id`` matches the ``DecisionRecord.actor_id`` constructor
    field; the store-side ``_validate_and_normalize_record`` (per
    ``core/decision_history.py:432``) merges it into the canonicalised
    persisted payload under the key ``"actor_id"`` before hashing.
    ``session_id`` is threaded onto the caller's payload dict before
    handoff (NOT a top-level DR field — session-scoped values follow
    the ``escalation.py:560`` payload-merge pattern).
    """

    if event not in _VALID_EVENTS:
        raise ValueError(
            f"{event!r} is not a valid SandboxLifecycleEvent; "
            f"expected one of {sorted(_VALID_EVENTS)}"
        )

    # Merge session_id into payload — NOT a top-level DR field per the
    # verified core/decision_history.py:206 shape.
    full_payload = {**payload, "session_id": session_id}
    request_id = f"sandbox-evt-{uuid.uuid4().hex}"

    async def _precondition(
        _conn: AsyncConnection,
        _prev_sequence: int,
        _prev_hash: bytes,
    ) -> None:
        # Audit-only — no state to project; no validator to run inside
        # the chain-head lock; returns None which flows into _build_record.
        return None

    def _build_record(_captured: None) -> DecisionRecord:
        # Constructs the 10-field DecisionRecord per
        # core/decision_history.py:206. record_id / chain_id / sequence /
        # new_hash / created_at live on the SEPARATE
        # AppendedDecisionSnapshot (post-commit, hook-only) — NOT on
        # DecisionRecord; the store assigns those snapshot fields after
        # commit and passes the snapshot to hooks.
        return DecisionRecord(
            decision_type=event,
            request_id=request_id,
            payload=full_payload,
            actor_id=actor_id,
            tenant_id=tenant_id,
            trace_id=trace_id,
            iso_controls=("A.6.2.5",),
        )

    return await decision_history_store.append_with_precondition(
        record_builder=_build_record,
        precondition=_precondition,
    )
