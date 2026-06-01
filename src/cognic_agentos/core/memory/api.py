"""Sprint 11.5a T10 — MemoryAPI, the single Layer-C governed-memory access path.

CRITICAL CONTROL (``core/`` stop-rule per AGENTS.md — Memory governance
enforcement, ADR-019). ``MemoryAPI`` wires the T9 :class:`MemoryGate` (per-write
/ per-recall / per-enumerate governance) and the injected :class:`MemoryAdapter`
backend into the public memory operations. It is THE seam a Layer C agent uses;
direct adapter access from anywhere but here is forbidden (pinned by
``tests/unit/architecture/test_memory_layer_c_no_direct_storage.py``).

**11.5a op surface — 7 ops.** ``remember`` / ``recall`` / ``upsert_block`` /
``read_block`` / ``list_for_subject`` / ``list_blocks`` / ``recall_episodes``
(the 7th op landed in T11 — the ``long_term`` + purpose episodic view, joined
to ``decision_history``; vector-ranked recall is deferred to 11.5c). The
lifecycle ops (``forget`` / ``redact`` / ``export``) are ABSENT: memory writes
are not production-wired until erasure/redaction lands in 11.5b and ``export``
in 11.5c — MemoryAPI is DI-tested, not harness-injected, in 11.5a.

**Identity is read from the bound** :class:`MemoryCallerContext` **only.** Every
op runs through the gate, which reads ``tenant_id`` / ``agent_id`` / ``actor_id``
/ served-subject from the bound context — a caller cannot smuggle a different
identity through the op arguments. Refusals surface as the typed
:class:`~cognic_agentos.core.memory.tiers.MemoryOperationRefused` raised by the
gate; MemoryAPI does not catch or translate them.

**``memory.read`` audit (ADR-019 §recall + ADR-006).** The keyed reads
(``recall`` / ``read_block``), ``list_for_subject``, and ``recall_episodes``
each emit exactly one ``memory.read`` :class:`DecisionRecord` (plain append; no
precondition) stamped with ISO controls ``("A.7.4", "A.8.2")``. The keyed-read
payload carries ``{tier, purpose, subject_ref, hit, record_id}``;
``list_for_subject`` carries ``{op, tiers, subject_ref, hit, count}``;
``recall_episodes`` carries ``{op, subject_ref, purpose, hit, count}``. None
carry a value or value-digest. ``list_blocks`` deliberately emits NO
``memory.read`` (block refs are not a value read — they are a structural listing
whose contents are governed at the later ``read_block``).
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.memory import episodes as _episodes
from cognic_agentos.core.memory._context import (
    BlockRef,
    MemoryHit,
    MemoryRecordId,
)
from cognic_agentos.core.memory._seams import (
    MemoryKillSwitchInterrogator,
    _NullMemoryKillSwitchInterrogator,
)
from cognic_agentos.core.memory.gate import MemoryGate
from cognic_agentos.core.memory.tiers import BlockKind, MemoryTier, SubjectRef

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.dlp.scanner import DLPScanner
    from cognic_agentos.core.memory._context import Episode, MemoryCallerContext
    from cognic_agentos.core.memory.consent import ConsentToken, ConsentValidator

    # The adapter is INJECTED — there is NO runtime import of
    # cognic_agentos.core.memory.storage from this module (the governed access
    # path is MemoryAPI; storage stays behind the gate). TYPE_CHECKING-only.
    from cognic_agentos.core.memory.storage import MemoryAdapter
    from cognic_agentos.core.policy.engine import OPAEngine

#: ISO 42001 control tuple stamped on every ``memory.read`` chain row.
#: A.7.4 (impact assessment) / A.8.2 (data quality) per ADR-019 + ADR-006.
#: Tuple at the boundary; ``DecisionHistoryStore`` converts to a list before
#: ``canonical_bytes`` (which rejects tuples).
_MEMORY_READ_ISO_CONTROLS: tuple[str, ...] = ("A.7.4", "A.8.2")

#: Default tiers an enumerate spans (the two durable tiers). Mirrors the gate's
#: ``check_enumerate`` default; the API passes this explicitly so the audit row
#: records exactly which tiers were enumerated.
_ENUMERATE_TIERS: tuple[MemoryTier, ...] = ("task", "long_term")


class MemoryAPI:
    """The single Layer-C governed-memory access path (ADR-019 §7).

    Construction binds one :class:`MemoryCallerContext` (via the constructed
    :class:`MemoryGate`) and the injected adapter + audit store. A
    ``MemoryAPI`` instance is bound to exactly one Layer C caller context by the
    harness — identity is never taken from the per-op arguments."""

    def __init__(
        self,
        *,
        context: MemoryCallerContext,
        adapter: MemoryAdapter,
        dlp: DLPScanner,
        consent: ConsentValidator,
        policy: OPAEngine,
        kill_switch: MemoryKillSwitchInterrogator | None = None,
        audit: DecisionHistoryStore,
        settings: Settings,
    ) -> None:
        # Fail-loud default: bind the _NullMemoryKillSwitchInterrogator sentinel
        # when no kill-switch is wired (raises NotImplementedError on the first
        # durable write) — a production deployment that forgets to wire the real
        # kill-switch fails loud, never silently allows during a compliance
        # freeze. `= None` + bind-here mirrors gate.py and avoids ruff B008.
        bound_kill_switch: MemoryKillSwitchInterrogator = (
            kill_switch if kill_switch is not None else _NullMemoryKillSwitchInterrogator()
        )
        self._gate = MemoryGate(
            context=context,
            dlp=dlp,
            consent=consent,
            policy=policy,
            kill_switch=bound_kill_switch,
        )
        self._adapter = adapter
        self._audit = audit
        self._context = context
        self._settings = settings

    # -- Write ops ---------------------------------------------------------

    async def remember(
        self,
        key: str,
        value: object,
        *,
        tier: MemoryTier,
        data_classes: tuple[str, ...] | list[str],
        purpose: str,
        consent_token: ConsentToken | None = None,
        retention_window_s: int | None = None,
    ) -> MemoryRecordId:
        """Write a keyed memory under the served subject. Runs the §7.1 write
        gate (which builds the resolved descriptor) then persists via the
        adapter; returns the generated record id."""

        record = await self._gate.check_write(
            value=value,
            tier=tier,
            purpose=purpose,
            data_classes=tuple(data_classes),
            key=key,
            consent_token=consent_token,
            retention_window_s=retention_window_s,
        )
        return await self._adapter.put(record)

    async def upsert_block(
        self,
        kind: BlockKind,
        *,
        subject: SubjectRef,
        value: object,
        data_classes: tuple[str, ...] | list[str],
        purpose: str,
        consent_token: ConsentToken | None = None,
    ) -> MemoryRecordId:
        """Singleton block upsert (always ``long_term``). Runs the §7.1 write
        gate (block-mode: subject-scope check at step 1b) then upserts via the
        adapter; returns the new version's record id."""

        record = await self._gate.check_write(
            value=value,
            tier="long_term",
            purpose=purpose,
            data_classes=tuple(data_classes),
            block_kind=kind,
            subject=subject,
            consent_token=consent_token,
        )
        return await self._adapter.upsert_block(record)

    # -- Keyed reads -------------------------------------------------------

    async def recall(self, key: str, *, tier: MemoryTier, purpose: str) -> MemoryHit | None:
        """Recall a keyed memory under the served subject. Runs the §7.2 pre-read
        authz (sub-agent / capability / subject scope), reads via the adapter,
        then runs the purpose matrix against the STORED write purpose
        (``hit.purpose``) — a recall whose purpose is incompatible with the
        record's write purpose is refused (``memory_purpose_mismatch``) and the
        value is NOT returned. Emits one ``memory.read`` event (hit or miss) on
        the authorized path and returns the hit (or ``None``)."""

        ctx = self._context
        await self._gate.check_recall_preread(tier=tier, subject=None)
        hit = await self._adapter.get(
            tenant_id=ctx.tenant_id,
            agent_id=ctx.agent_id,
            subject=ctx.served_subject,
            tier=tier,
            key=key,
        )
        if hit is not None:
            await self._gate.check_recall_purpose(recall_purpose=purpose, write_purpose=hit.purpose)
        await self._emit_keyed_read(tier=tier, purpose=purpose, subject=ctx.served_subject, hit=hit)
        return hit

    async def read_block(
        self, kind: BlockKind, *, subject: SubjectRef, purpose: str
    ) -> MemoryHit | None:
        """Read a singleton block (always ``long_term``). Runs the §7.2 pre-read
        authz (explicit-subject scope), reads via the adapter, then runs the
        purpose matrix against the stored ``hit.purpose`` (incompatible →
        ``memory_purpose_mismatch``, value not returned). Emits one
        ``memory.read`` event and returns the hit (or ``None``)."""

        ctx = self._context
        await self._gate.check_recall_preread(tier="long_term", subject=subject)
        hit = await self._adapter.get(
            tenant_id=ctx.tenant_id,
            agent_id=ctx.agent_id,
            subject=subject,
            tier="long_term",
            block_kind=kind,
        )
        if hit is not None:
            await self._gate.check_recall_purpose(recall_purpose=purpose, write_purpose=hit.purpose)
        await self._emit_keyed_read(tier="long_term", purpose=purpose, subject=subject, hit=hit)
        return hit

    # -- Enumerate reads ---------------------------------------------------

    async def list_for_subject(self, subject: SubjectRef) -> list[MemoryRecordId]:
        """Enumerate the active record ids for ``subject`` across the two
        durable tiers. Runs the §7.2-minus-keyed enumerate gate, reads via the
        adapter, emits ONE ``memory.read`` enumerate event, and returns the
        record ids."""

        ctx = self._context
        await self._gate.check_enumerate(subject, tiers=_ENUMERATE_TIERS)
        hits = await self._adapter.list_for_subject(
            tenant_id=ctx.tenant_id, agent_id=ctx.agent_id, subject=subject
        )
        results = [h.record_id for h in hits]
        await self._audit.append(
            DecisionRecord(
                decision_type="memory.read",
                request_id=f"memory-read-{uuid.uuid4().hex}",
                payload={
                    "op": "list_for_subject",
                    "tiers": list(_ENUMERATE_TIERS),
                    "subject_ref": subject.canonical,
                    "hit": bool(results),
                    "count": len(results),
                },
                actor_id=ctx.actor_id,
                tenant_id=ctx.tenant_id,
                iso_controls=_MEMORY_READ_ISO_CONTROLS,
            )
        )
        return results

    async def list_blocks(self, subject: SubjectRef) -> list[BlockRef]:
        """Enumerate the active block refs for ``subject`` (``long_term`` only).
        Runs the enumerate gate scoped to the ``long_term`` tier and returns the
        block refs. Emits NO ``memory.read`` — a block listing is structural; the
        block contents are governed at the later ``read_block``."""

        ctx = self._context
        await self._gate.check_enumerate(subject, tiers=("long_term",))
        return await self._adapter.list_blocks(
            tenant_id=ctx.tenant_id, agent_id=ctx.agent_id, subject=subject
        )

    # -- Episodic recall (7th op) ------------------------------------------

    async def recall_episodes(
        self, subject: SubjectRef, *, similarity_threshold: float, purpose: str
    ) -> list[Episode]:
        """Episodic recall (7th 11.5a op) — a view over the served-context agent's
        long_term records for ``subject``, purpose-filtered, joined to
        decision_history. Runs the enumerate gate (long_term tier), delegates to
        :func:`episodes.recall_episodes`, emits one enumerate-shape
        ``memory.read``.

        Pin-2: a ``similarity_threshold > 0.0`` call passes the gate then
        propagates :func:`episodes.recall_episodes`'s ``NotImplementedError``
        (vector-ranked recall is 11.5c) — no ``memory.read`` is emitted on that
        path."""

        ctx = self._context
        await self._gate.check_enumerate(subject, tiers=("long_term",))
        eps = await _episodes.recall_episodes(
            subject,
            similarity_threshold=similarity_threshold,
            purpose=purpose,
            adapter=self._adapter,
            dh_store=self._audit,
            tenant_id=ctx.tenant_id,
            agent_id=ctx.agent_id,
        )
        await self._audit.append(
            DecisionRecord(
                decision_type="memory.read",
                request_id=f"memory-read-{uuid.uuid4().hex}",
                payload={
                    "op": "recall_episodes",
                    "subject_ref": subject.canonical,
                    "purpose": purpose,
                    "hit": bool(eps),
                    "count": len(eps),
                },
                actor_id=ctx.actor_id,
                tenant_id=ctx.tenant_id,
                iso_controls=_MEMORY_READ_ISO_CONTROLS,
            )
        )
        return eps

    # -- memory.read emit (keyed reads) ------------------------------------

    async def _emit_keyed_read(
        self, *, tier: MemoryTier, purpose: str, subject: SubjectRef, hit: MemoryHit | None
    ) -> None:
        """Emit one ``memory.read`` event for a KEYED read (``recall`` /
        ``read_block``). Plain append, no precondition. The payload records the
        hit/miss + the record id on a hit (never the value)."""

        ctx = self._context
        await self._audit.append(
            DecisionRecord(
                decision_type="memory.read",
                request_id=f"memory-read-{uuid.uuid4().hex}",
                payload={
                    "tier": tier,
                    "purpose": purpose,
                    "subject_ref": subject.canonical,
                    "hit": hit is not None,
                    "record_id": str(hit.record_id) if hit else None,
                },
                actor_id=ctx.actor_id,
                tenant_id=ctx.tenant_id,
                iso_controls=_MEMORY_READ_ISO_CONTROLS,
            )
        )


__all__ = ("MemoryAPI",)
