"""Sprint 11.5c T7 — episodic recall: vector path wired.

CRITICAL CONTROL (``core/`` stop-rule per AGENTS.md — Memory governance
enforcement, ADR-019). :func:`recall_episodes` is NOT a fourth memory tier; it
is a VIEW over a served-context agent's active ``long_term`` *keyed* records
for one subject, purpose-filtered, joined to ``decision_history`` for the
originating ``trace_id``.

**Pin-2 replaced in 11.5c.** ``similarity_threshold > 0.0`` with a ``query``
+ a wired ``vector_index`` now runs the real vector path. Without ``query`` OR
without ``vector_index``, raises
``MemoryOperationRefused("memory_vector_recall_unavailable")``.

**Authz-intersection contract (security crux).** The governed set is fetched
FIRST via ``adapter.list_for_subject`` (agent-scoped active long_term records).
Vector hits whose ``id`` is NOT in this set are DROPPED — a hit the agent does
not govern MUST NOT become an Episode.

**Score filter.** Governed hits with ``vhit.score < similarity_threshold`` are
dropped. For qdrant cosine, higher score = closer match.

**Pin-1 — agent-scoped.** Identity (``tenant_id`` + ``agent_id``) is threaded
into the adapter read, so the view is scoped to the calling agent's own records.

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
``MemoryVectorIndex`` is imported under ``TYPE_CHECKING`` only (same rule).
Importing ``cognic_agentos.core.decision_history`` (for the ``_decision_history``
Table) is fine — it is a different module and opens no gate-bypass.
Importing ``cognic_agentos.core.memory.tiers`` (for ``MemoryOperationRefused``)
at runtime is fine — tiers is not storage.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa

from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.memory._context import Episode
from cognic_agentos.core.memory.tiers import MemoryOperationRefused

if TYPE_CHECKING:
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    from cognic_agentos.core.memory.storage import MemoryAdapter
    from cognic_agentos.core.memory.tiers import SubjectRef
    from cognic_agentos.core.memory.vector import MemoryVectorIndex


async def recall_episodes(
    subject: SubjectRef,
    *,
    similarity_threshold: float,
    purpose: str,
    adapter: MemoryAdapter,
    dh_store: DecisionHistoryStore,
    tenant_id: str,
    agent_id: str,
    query: str | None = None,
    vector_index: MemoryVectorIndex | None = None,
    limit: int = 10,
) -> list[Episode]:
    """Return the calling agent's active ``long_term`` keyed records for
    ``subject`` whose stored ``purpose`` matches, as :class:`Episode`s joined to
    their originating ``decision_history`` ``trace_id``.

    When ``similarity_threshold > 0.0``, runs the vector-ranked path (wired in
    11.5c): requires a NON-BLANK ``query`` AND a wired ``vector_index``; raises
    ``MemoryOperationRefused("memory_vector_recall_unavailable")`` if ``query``
    is missing / blank / whitespace-only OR ``vector_index`` is missing (a blank
    query is semantically "no query"). The governed set (``list_for_subject``)
    is fetched FIRST for
    authz-intersection — vector hits whose ``id`` is NOT in the governed set are
    dropped. Governed hits with ``vhit.score < similarity_threshold`` are also
    dropped. Results are returned in the index's similarity order.

    When ``similarity_threshold == 0.0``, the unchanged long_term + purpose view
    is returned (``query`` and ``vector_index`` are ignored).

    Pin-1: the read is agent-scoped via ``tenant_id`` + ``agent_id``. Blocks
    (``block_kind is not None``) are excluded — episodes are keyed records only.
    The ``summary`` is the stored value rendered to ``str``.
    """

    if similarity_threshold > 0.0:
        # A blank/whitespace-only query is semantically "no query" — normalize
        # and refuse, so query="" / "   " cannot bypass the contract and run a
        # vector search on empty text. The normalized text is what we embed.
        normalized_query = (query or "").strip()
        if not normalized_query or vector_index is None:
            raise MemoryOperationRefused("memory_vector_recall_unavailable")
        # Governed set FIRST (authz-correct): the agent-scoped active long_term
        # keyed records for this subject + purpose.
        hits = await adapter.list_for_subject(
            tenant_id=tenant_id, agent_id=agent_id, subject=subject
        )
        governed = {
            str(h.record_id): h
            for h in hits
            if h.tier == "long_term" and h.block_kind is None and h.purpose == purpose
        }
        ranked = await vector_index.search(text=normalized_query, purpose=purpose, limit=limit)
        trace_map = await _trace_map(dh_store, tenant_id=tenant_id)
        out: list[Episode] = []
        for vhit in ranked:
            if vhit.score < similarity_threshold:
                continue  # below-threshold dropped (qdrant cosine: higher score = closer)
            h = governed.get(vhit.id)
            if h is None:
                continue  # index hit NOT in the governed set → drop (authz)
            out.append(
                Episode(
                    record_id=h.record_id,
                    summary=str(h.value),
                    decision_trace_id=trace_map.get(str(h.record_id)),
                    created_at=h.created_at,
                )
            )
        return out
    # similarity_threshold == 0.0 — unchanged long_term + purpose view (below).

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
