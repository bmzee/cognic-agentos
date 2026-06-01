"""Sprint 11.5a T11 — episodic recall: the ``long_term`` + purpose view.

CRITICAL CONTROL (``core/`` stop-rule per AGENTS.md — Memory governance
enforcement, ADR-019). :func:`recall_episodes` is NOT a fourth memory tier; it
is a VIEW over a served-context agent's active ``long_term`` *keyed* records
for one subject, purpose-filtered, joined to ``decision_history`` for the
originating ``trace_id``.

**Pin-2 — fail loud on vector ranking.** Vector-ranked episodic recall is
deferred to 11.5b. 11.5a supports ONLY ``similarity_threshold == 0.0`` (the
``long_term`` + purpose slice); any ``> 0.0`` value raises ``NotImplementedError``
rather than silently degrading to the unranked view.

**Pin-1 — agent-scoped.** Identity (``tenant_id`` + ``agent_id``) is threaded
into the adapter read, so the view is scoped to the calling agent's own records
(the T10 reads are agent-scoped; a record belongs to the agent that wrote it).

**F2=A — decision-history linkage WITHOUT a new public read API.** The store
exposes no public read seam, so :func:`_trace_map` reads the exported
``_decision_history`` Table through ``dh_store._engine`` and matches
``memory.write`` rows by ``payload["record_id"]`` (mirroring the
``decision_history_rows`` conftest fixture). A record's ``trace_id`` is returned
when present, else ``None``.

**Arch invariant** (pinned by
``tests/unit/architecture/test_memory_layer_c_no_direct_storage.py``): this
module MUST NOT runtime-import ``cognic_agentos.core.memory.storage`` — the
:class:`MemoryAdapter` Protocol is imported under ``TYPE_CHECKING`` only.
Importing ``cognic_agentos.core.decision_history`` (for the ``_decision_history``
Table) is fine — it is a different module and opens no gate-bypass.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa

from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.memory._context import Episode

if TYPE_CHECKING:
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    from cognic_agentos.core.memory.storage import MemoryAdapter
    from cognic_agentos.core.memory.tiers import SubjectRef


async def recall_episodes(
    subject: SubjectRef,
    *,
    similarity_threshold: float,
    purpose: str,
    adapter: MemoryAdapter,
    dh_store: DecisionHistoryStore,
    tenant_id: str,
    agent_id: str,
) -> list[Episode]:
    """Return the calling agent's active ``long_term`` keyed records for
    ``subject`` whose stored ``purpose`` matches, as :class:`Episode`s joined to
    their originating ``decision_history`` ``trace_id``.

    Pin-2: ``similarity_threshold > 0.0`` raises ``NotImplementedError`` (vector
    ranking is 11.5b). Pin-1: the read is agent-scoped via ``tenant_id`` +
    ``agent_id``. Blocks (``block_kind is not None``) are excluded — episodes are
    keyed records only. The ``summary`` is the stored value rendered to ``str``.
    """

    # Pin-2 — vector-ranked recall is 11.5b; only the 0.0 (long_term + purpose)
    # view is supported in 11.5a. Fail loud rather than silently un-rank.
    if similarity_threshold > 0.0:
        raise NotImplementedError(
            "vector-ranked episodic recall is deferred to 11.5b; 11.5a supports only "
            "similarity_threshold=0.0 (the long_term + purpose view)"
        )

    hits = await adapter.list_for_subject(tenant_id=tenant_id, agent_id=agent_id, subject=subject)
    matched = [
        h for h in hits if h.tier == "long_term" and h.block_kind is None and h.purpose == purpose
    ]
    trace_map = await _trace_map(dh_store, tenant_id=tenant_id)
    return [
        Episode(
            record_id=h.record_id,
            summary=str(h.value),
            decision_trace_id=trace_map.get(str(h.record_id)),
            created_at=h.created_at,
        )
        for h in matched
    ]


async def _trace_map(dh_store: DecisionHistoryStore, *, tenant_id: str) -> dict[str, str | None]:
    """Map ``str(record_id)`` → originating ``trace_id`` for every
    ``memory.write`` chain row scoped to ``tenant_id`` (F2=A).

    Reads the exported ``_decision_history`` Table directly through
    ``dh_store._engine`` — the store has no public read API, so this mirrors the
    ``decision_history_rows`` conftest fixture. A ``memory.write`` row's
    ``payload["record_id"]`` is the ``str(uuid)`` set by
    ``storage._build_write_record``; ``trace_id`` is ``None`` when the write
    carried no trace context."""

    stmt = sa.select(_decision_history.c.payload, _decision_history.c.trace_id).where(
        _decision_history.c.event_type == "memory.write",
        _decision_history.c.tenant_id == tenant_id,
    )
    async with dh_store._engine.connect() as conn:
        rows = (await conn.execute(stmt)).all()
    out: dict[str, str | None] = {}
    for row in rows:
        payload = row.payload or {}
        rid = payload.get("record_id")
        if rid is not None:
            out[rid] = row.trace_id
    return out


__all__ = ("recall_episodes",)
