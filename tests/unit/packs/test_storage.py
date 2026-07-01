"""Sprint 7B.1 T3 — bank pack record store (SQLite-substrate unit suite).

Per the plan-of-record at
``docs/superpowers/plans/2026-05-10-sprint-7b1-lifecycle-state-machine.md``
T3 §"SQLite/unit shape tests": prove API contracts (round-trip,
chain-emission shape, refusal-rolls-back, list-by-status,
load-lifecycle-history, Pydantic vocabulary). Concurrency / row-locking
proofs (``SELECT ... FOR UPDATE`` serialisation under contention) live
in ``tests/integration/packs/test_storage_lock_serialisation.py`` —
SQLite cannot honour ``FOR UPDATE`` row-level locking (database-level
locks only) so the production-grade race proof requires real
Postgres + Oracle (mirrors Sprint 2.5 escalation T3 / T9 split per
``tests/unit/core/test_escalation.py:56-60``).

Halt-before-commit per AGENTS.md "Authoring — Bank pack lifecycle
(Sprint 7B.1)" + ``feedback_strict_review_off_gate.md``: critical
controls module under TDD with ≥95% line / ≥90% branch coverage on
``packs/storage.py`` after the gate-list extension at T7.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, ClassVar

import pydantic
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.packs.lifecycle import (
    _VALID_TRANSITIONS,
    LifecycleRefusalReason,
    PackKind,
    PackState,
    TransitionName,
    iso_controls_for,
)
from cognic_agentos.packs.storage import (
    _TRANSITION_TO_TARGET_STATE,
    LifecycleTransitionRefused,
    PackNotFound,
    PackRecord,
    PackRecordRefusalReason,
    PackRecordRefused,
    PackRecordStore,
    _packs,
)

# ===========================================================================
# Fixtures
# ===========================================================================


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    """Per-test SQLite-aiosqlite engine with the governance schema +
    seeded chain heads + the new ``packs`` table.

    Mirrors ``tests/unit/core/test_escalation.py:86-115`` — both
    ``audit_event`` and ``decision_history`` chain heads are seeded so
    the storage layer's ``transition()`` (which writes to
    ``decision_history`` via ``DecisionHistoryStore``) works
    end-to-end. The ``packs`` Table is registered against the same
    ``_metadata`` (imported from ``core/audit``) at storage-module
    load time, so ``_metadata.create_all(conn)`` creates it alongside
    the chain tables — same posture as how ``decision_history``
    registers against ``core/audit._metadata``."""

    url = f"sqlite+aiosqlite:///{tmp_path / 'packs.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="decision_history",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
async def store(engine: AsyncEngine) -> PackRecordStore:
    return PackRecordStore(engine)


def _make_record(
    *,
    pack_id: str = "cognic-tool-example-minimal",
    kind: PackKind = "tool",
    state: PackState = "draft",
    record_id: uuid.UUID | None = None,
    tenant_id: str | None = None,
    sbom_pointer: str | None = None,
    last_actor: str | None = None,
) -> PackRecord:
    """Construct a fully-populated PackRecord for tests. Defaults to a
    fresh ``draft``-state tool pack with deterministic 32-byte digest
    bytes (so equality checks across save/load round-trips succeed)."""

    now = datetime.now(UTC)
    return PackRecord(
        id=record_id or uuid.uuid4(),
        kind=kind,
        pack_id=pack_id,
        display_name=pack_id,
        state=state,
        manifest_digest=b"\x01" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=sbom_pointer,
        tenant_id=tenant_id,
        created_by="canary-author",
        last_actor=last_actor or "canary-author",
        created_at=now,
        updated_at=now,
    )


async def _count_chain_rows(eng: AsyncEngine) -> int:
    async with eng.connect() as conn:
        return int(
            (await conn.execute(select(func.count(_decision_history.c.sequence)))).scalar_one()
        )


async def _read_pack_state(eng: AsyncEngine, pack_id: uuid.UUID) -> str | None:
    async with eng.connect() as conn:
        result = await conn.execute(select(_packs.c.state).where(_packs.c.id == pack_id))
        row = result.first()
    return row[0] if row else None


# ===========================================================================
# PackRecord Pydantic shape
# ===========================================================================


class TestSprint7B1PackRecordModel:
    """``PackRecord`` is a Pydantic v2 ``frozen=True`` + ``extra="forbid"``
    model. Pydantic vocabulary correctness is enforced at construction
    (Doctrine Lock E layer 1) — out-of-vocabulary kind / state values
    are rejected before they reach the Postgres CHECK constraint or the
    chain-emission path."""

    def test_construction_round_trips_all_fields(self) -> None:
        rid = uuid.uuid4()
        rec = _make_record(record_id=rid)
        assert rec.id == rid
        assert rec.kind == "tool"
        assert rec.state == "draft"
        assert rec.manifest_digest == b"\x01" * 32
        assert rec.signed_artefact_digest == b"\x02" * 32
        assert rec.sbom_pointer is None
        assert rec.tenant_id is None
        assert rec.created_by == "canary-author"

    def test_kind_literal_rejects_unknown_value(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            PackRecord(
                id=uuid.uuid4(),
                kind="workflow",  # type: ignore[arg-type]
                pack_id="x",
                display_name="x",
                state="draft",
                manifest_digest=b"\x00" * 32,
                signed_artefact_digest=b"\x00" * 32,
                sbom_pointer=None,
                tenant_id=None,
                created_by="a",
                last_actor="a",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

    def test_state_literal_rejects_unknown_value(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            PackRecord(
                id=uuid.uuid4(),
                kind="tool",
                pack_id="x",
                display_name="x",
                state="quarantined",  # type: ignore[arg-type]
                manifest_digest=b"\x00" * 32,
                signed_artefact_digest=b"\x00" * 32,
                sbom_pointer=None,
                tenant_id=None,
                created_by="a",
                last_actor="a",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

    def test_extra_field_forbidden(self) -> None:
        # Pydantic ``extra="forbid"`` — unknown attribute raises at
        # construction so a stray field cannot land in the chain
        # payload by accident.
        with pytest.raises(pydantic.ValidationError):
            PackRecord(
                id=uuid.uuid4(),
                kind="tool",
                pack_id="x",
                display_name="x",
                state="draft",
                manifest_digest=b"\x00" * 32,
                signed_artefact_digest=b"\x00" * 32,
                sbom_pointer=None,
                tenant_id=None,
                created_by="a",
                last_actor="a",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                stray_field="boom",  # type: ignore[call-arg]
            )

    def test_frozen_assignment_raises(self) -> None:
        rec = _make_record()
        with pytest.raises(pydantic.ValidationError):
            rec.state = "submitted"

    def test_optional_fields_accept_none(self) -> None:
        rec = _make_record(sbom_pointer=None, tenant_id=None)
        assert rec.sbom_pointer is None
        assert rec.tenant_id is None


# ===========================================================================
# LifecycleTransitionRefused exception
# ===========================================================================


class TestSprint7B1LifecycleTransitionRefusedException:
    """``LifecycleTransitionRefused`` carries the closed-enum
    :data:`LifecycleRefusalReason` from
    :mod:`cognic_agentos.packs.lifecycle` so callers (T3+ T6
    consumers, future portal handlers in 7B.2) can dispatch on the
    exact failure mode without parsing strings."""

    def test_inherits_exception(self) -> None:
        assert issubclass(LifecycleTransitionRefused, Exception)

    def test_carries_reason_attribute(self) -> None:
        exc = LifecycleTransitionRefused("lifecycle_transition_invalid_state_pair")
        assert exc.reason == "lifecycle_transition_invalid_state_pair"

    def test_str_representation_includes_reason(self) -> None:
        exc = LifecycleTransitionRefused("lifecycle_transition_terminal_state")
        assert "lifecycle_transition_terminal_state" in str(exc)


# ===========================================================================
# _TRANSITION_TO_TARGET_STATE drift detector
# ===========================================================================


class TestSprint7B1TransitionToTargetStateMap:
    """``_TRANSITION_TO_TARGET_STATE`` (in ``packs/storage``) is the
    transition-name → target-state mapping the storage layer derives
    ``to_state`` from before invoking ``validate_transition``. It is a
    cache of the per-transition-target-state derivation that
    ``_VALID_TRANSITIONS`` (in ``packs/lifecycle``) implies. A drift
    between the two would let storage advance to a state the validator
    refuses — pinned here.

    The map is necessary because every ``_VALID_TRANSITIONS`` entry has
    exactly one legal ``to_state`` (verified below), so storage can
    derive ``to_state`` from ``transition`` alone without forcing
    callers to pass the redundant ``to_state`` argument."""

    def test_map_covers_every_transition(self) -> None:
        # Every TransitionName key has an entry. Adding a new
        # transition without updating this map fails here, by design.
        assert set(_TRANSITION_TO_TARGET_STATE.keys()) == set(_VALID_TRANSITIONS.keys())

    def test_target_state_unique_per_transition_in_lifecycle_table(self) -> None:
        # Cross-check the precondition the storage layer relies on:
        # every transition's legal pairs share a single to_state.
        # Without this, the storage layer would need a (from, transition)
        # → to_state lookup and the API surface would have to take
        # to_state as an explicit argument.
        for transition_name, pairs in _VALID_TRANSITIONS.items():
            to_states = {to_state for _, to_state in pairs}
            assert len(to_states) == 1, (
                f"transition {transition_name!r} has multiple legal to_states: {to_states!r}; "
                "storage's transition() API derives to_state from transition_name alone "
                "and would need redesign if this invariant breaks."
            )

    def test_map_target_state_matches_lifecycle_table(self) -> None:
        # Drift detector: storage's cached map MUST match the
        # to_state extracted from lifecycle's legal-pairs table.
        for transition_name, target in _TRANSITION_TO_TARGET_STATE.items():
            pairs = _VALID_TRANSITIONS[transition_name]
            to_states = {to_state for _, to_state in pairs}
            assert to_states == {target}, (
                f"_TRANSITION_TO_TARGET_STATE[{transition_name!r}]={target!r} "
                f"diverges from _VALID_TRANSITIONS[{transition_name!r}] to_state set {to_states!r}"
            )


# ===========================================================================
# PackRecordStore.save_draft + load
# ===========================================================================


class TestSprint7B1PackRecordStoreSaveDraftAndLoad:
    """Round-trip a draft-state PackRecord through ``save_draft`` and
    ``load``. ``save_draft`` is the entry point to the state machine —
    it inserts the row but does NOT emit a chain event (draft creation
    is not a transition; it is the genesis). The first chain event
    fires on the first ``transition()`` (typically ``submit``)."""

    async def test_save_draft_returns_id(self, store: PackRecordStore) -> None:
        rec = _make_record()
        returned_id = await store.save_draft(rec)
        assert returned_id == rec.id

    async def test_load_returns_pack_record(self, store: PackRecordStore) -> None:
        rec = _make_record(pack_id="cognic-skill-example-minimal", kind="skill")
        await store.save_draft(rec)
        loaded = await store.load(rec.id)
        assert loaded is not None
        assert loaded.id == rec.id
        assert loaded.kind == "skill"
        assert loaded.state == "draft"
        assert loaded.pack_id == "cognic-skill-example-minimal"
        assert loaded.manifest_digest == rec.manifest_digest
        assert loaded.signed_artefact_digest == rec.signed_artefact_digest

    async def test_load_returns_none_for_unknown_id(self, store: PackRecordStore) -> None:
        loaded = await store.load(uuid.uuid4())
        assert loaded is None

    async def test_save_draft_does_not_emit_chain_row(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        before = await _count_chain_rows(engine)
        await store.save_draft(_make_record())
        after = await _count_chain_rows(engine)
        # Genesis chain-head rows are seeded, but no decision_history
        # row exists yet because save_draft is not a state transition.
        assert after == before


# ===========================================================================
# PackRecordStore.transition — happy paths
# ===========================================================================


class TestSprint7B1PackRecordStoreTransitionHappyPath:
    """Each legal transition emits one ``pack.lifecycle.<to_state>``
    row to ``decision_history`` AND atomically advances the
    ``packs.state`` cache. The chain row is the source of truth per
    Doctrine Lock D — ``packs.state`` is a denormalised cache for O(1)
    reads."""

    async def test_submit_advances_draft_to_submitted(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record()
        await store.save_draft(rec)
        before = await _count_chain_rows(engine)
        record_id, h = await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="author-1",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-submit-canary",
        )
        # Chain row count grew by one.
        assert await _count_chain_rows(engine) == before + 1
        # State cache moved.
        assert await _read_pack_state(engine, rec.id) == "submitted"
        # Public API returns (record_id, hash).
        assert isinstance(record_id, uuid.UUID)
        assert isinstance(h, bytes) and len(h) == 32

    async def test_chain_row_decision_type_carries_target_state(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record()
        await store.save_draft(rec)
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="author-1",
            tenant_id="tenant-canary",
            evidence_pointer=None,
            request_id="req-decision-type-canary",
        )
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_decision_history.c.event_type, _decision_history.c.payload)
                    .order_by(_decision_history.c.sequence.desc())
                    .limit(1)
                )
            ).one()
        assert row.event_type == "pack.lifecycle.submitted"
        # Payload carries lifecycle context for downstream consumers
        # (7B.3 evidence panels, 7B.4 UI events).
        payload = row.payload
        assert payload["pack_id"] == str(rec.id)
        assert payload["kind"] == "tool"
        assert payload["from_state"] == "draft"
        assert payload["to_state"] == "submitted"
        assert payload["transition_name"] == "submit"

    async def test_full_lifecycle_walk(self, store: PackRecordStore, engine: AsyncEngine) -> None:
        # draft → submitted → under_review → approved → allow_listed → installed →
        # disabled → revoked → uninstalled. Nine states traversed via eight
        # successful transitions emitting eight chain rows; final state cache
        # reads "uninstalled". (T3 R1 P3 doc-precision fix — durable doctrine
        # for the lifecycle shape; prose must match the count assertion
        # `before + 8` below.)
        rec = _make_record()
        await store.save_draft(rec)
        sequence: list[tuple[TransitionName, PackState]] = [
            ("submit", "submitted"),
            ("claim", "under_review"),
            ("approve", "approved"),
            ("allow_list", "allow_listed"),
            ("install", "installed"),
            ("disable", "disabled"),
            ("revoke", "revoked"),
            ("uninstall", "uninstalled"),
        ]
        before = await _count_chain_rows(engine)
        for trans, expected_state in sequence:
            await store.transition(
                pack_id=rec.id,
                transition=trans,
                actor_id=f"actor-{trans}",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-{trans}",
            )
            assert await _read_pack_state(engine, rec.id) == expected_state
        # 8 transitions emitted 8 rows.
        assert await _count_chain_rows(engine) == before + 8

    async def test_m4_reenable_disabled_pack_via_install_transition(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        # M4 (ADR-012 amendment) — a disabled pack RE-INSTALLS via the widened
        # ``install`` transition (disabled → installed) WITHOUT a new
        # approval/allow-list cycle. Storage needs NO map change: ``install``
        # already maps to ``installed``; the from-state widening lives in
        # validate_transition (which storage delegates to). End-to-end proof.
        rec = _make_record()
        await store.save_draft(rec)
        for trans in ("submit", "claim", "approve", "allow_list", "install", "disable"):
            await store.transition(
                pack_id=rec.id,
                transition=trans,
                actor_id=f"actor-{trans}",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-{trans}",
            )
        assert await _read_pack_state(engine, rec.id) == "disabled"
        # Re-enable: disabled → installed via the SAME ``install`` transition.
        before = await _count_chain_rows(engine)
        await store.transition(
            pack_id=rec.id,
            transition="install",
            actor_id="actor-reinstall",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-reinstall",
        )
        assert await _read_pack_state(engine, rec.id) == "installed"
        # Exactly one new chain row (the pack.lifecycle.installed re-enable event).
        assert await _count_chain_rows(engine) == before + 1

    async def test_m4_revoked_pack_cannot_be_reinstalled(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        # ``revoke`` stays terminal — a revoked pack canNOT be re-installed. The
        # widened ``install`` accepts ``disabled``, NOT ``revoked`` →
        # LifecycleTransitionRefused(invalid_state_pair); the row is unchanged.
        rec = _make_record()
        await store.save_draft(rec)
        for trans in ("submit", "claim", "approve", "allow_list", "install", "revoke"):
            await store.transition(
                pack_id=rec.id,
                transition=trans,
                actor_id=f"actor-{trans}",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-{trans}",
            )
        assert await _read_pack_state(engine, rec.id) == "revoked"
        before = await _count_chain_rows(engine)
        with pytest.raises(LifecycleTransitionRefused) as exc:
            await store.transition(
                pack_id=rec.id,
                transition="install",
                actor_id="actor-bad-reinstall",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req-bad-reinstall",
            )
        assert exc.value.reason == "lifecycle_transition_invalid_state_pair"
        # Refusal rolled back — state unchanged, no chain row emitted.
        assert await _read_pack_state(engine, rec.id) == "revoked"
        assert await _count_chain_rows(engine) == before

    async def test_iso_controls_recorded_in_chain_payload(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        # Sprint 7B.1 T5 (R1 P2 reviewer fix): storage.transition()
        # derives iso_controls canonically from the transition name; the
        # public API no longer accepts an ``iso_controls`` argument so
        # callers cannot emit an audit-untagged or wrongly-tagged chain
        # row. The chain row's ``iso_controls`` column AND
        # ``payload['iso_controls']`` MUST both equal
        # ``iso_controls_for("submit")``. Pin a fresh lookup here against
        # the canonical map (drift in the map without updating
        # ``test_lifecycle_audit.py::TestSprint7B1IsoControlsMapShape``
        # would fail there first; this assertion catches the inverse —
        # the helper drifts without the canonical assertion catching it).
        rec = _make_record()
        await store.save_draft(rec)
        expected_controls = iso_controls_for("submit")
        assert expected_controls == ("A.5.31", "A.6.2.4"), (
            "submit-transition iso_controls drifted from "
            "Sprint-7B.1-T5 canonical mapping; if intentional update "
            "test_lifecycle_audit.py::TestSprint7B1IsoControlsMapShape "
            "in the same commit"
        )
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="author-1",
            tenant_id=None,
            evidence_pointer="s3://bucket/evidence-1",
            request_id="req-iso-canary",
        )
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_decision_history.c.payload, _decision_history.c.iso_controls)
                    .order_by(_decision_history.c.sequence.desc())
                    .limit(1)
                )
            ).one()
        assert tuple(row.iso_controls) == expected_controls
        assert row.payload["evidence_pointer"] == "s3://bucket/evidence-1"
        assert tuple(row.payload["iso_controls"]) == expected_controls

    async def test_transition_omits_actor_type_payload_key_when_not_supplied(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """Sprint 7B.2 T6 slice 2 — backward-compat guardrail per user
        Path-B R24 review: existing call sites that do NOT pass the
        new ``actor_type`` kwarg MUST produce chain rows whose payload
        does NOT carry the ``actor_type`` key. This preserves byte-shape
        compatibility with every chain row written before slice 2 +
        with every storage call site that doesn't need the human-actor
        evidence (T5 review surface, T4 author surface, every pre-T6
        sprint's chain rows).
        """
        rec = _make_record()
        await store.save_draft(rec)
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="author-1",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-actor-type-omitted",
        )
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_decision_history.c.payload)
                    .order_by(_decision_history.c.sequence.desc())
                    .limit(1)
                )
            ).one()
        assert "actor_type" not in row.payload, (
            "chain row payload MUST NOT carry the 'actor_type' key when "
            "the kwarg is not supplied — byte-shape backward-compat with "
            f"pre-slice-2 chain rows; got payload={row.payload!r}"
        )

    async def test_transition_persists_actor_type_human_in_payload(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """Sprint 7B.2 T6 slice 2 — Path B + B2 implementation: when
        ``actor_type="human"`` is passed to ``transition()``, the
        chain row's ``payload["actor_type"]`` MUST equal ``"human"``.
        This is the watchpoint (d) examiner-traceability surface — a
        flat top-level payload key (NOT nested under
        ``actor_attributes``) per user-chosen Option B2.
        """
        rec = _make_record()
        await store.save_draft(rec)
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="operator-1",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-actor-type-human",
            actor_type="human",
        )
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_decision_history.c.payload)
                    .order_by(_decision_history.c.sequence.desc())
                    .limit(1)
                )
            ).one()
        assert row.payload.get("actor_type") == "human", (
            "chain row payload['actor_type'] MUST equal 'human' when the "
            f"kwarg is passed; got payload={row.payload!r}"
        )

    async def test_transition_persists_actor_type_service_in_payload(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """Sprint 7B.2 T6 slice 2 — the storage layer's ``actor_type``
        kwarg is a thin string passthrough; it does NOT enforce the
        ``"human"`` / ``"service"`` ActorType vocabulary (that lives in
        ``portal/rbac/actor.py:49`` and is enforced at the endpoint
        boundary via :class:`RequireHumanActor`). Storage just
        persists whatever string the caller passes — proves the seam
        is generic enough for slices 3-4 (install/disable/revoke/
        uninstall) which pass through actor_type without re-asserting
        the human-actor invariant (those endpoints don't gate on
        actor_type but the audit surface still records it).
        """
        rec = _make_record()
        await store.save_draft(rec)
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="ci-bot-1",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-actor-type-service",
            actor_type="service",
        )
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_decision_history.c.payload)
                    .order_by(_decision_history.c.sequence.desc())
                    .limit(1)
                )
            ).one()
        assert row.payload.get("actor_type") == "service"

    async def test_caller_cannot_supply_iso_controls_argument(self, store: PackRecordStore) -> None:
        # Sprint 7B.1 T5 R1 P2: storage.transition() no longer accepts
        # ``iso_controls`` as a kwarg — the canonical mapping in
        # ``packs.lifecycle`` is the single source of truth per ADR-006
        # §"Evidence emission". Pinning this against accidental
        # reintroduction of the parameter (which would re-open the
        # untagged-chain-row attack surface that R1 P2 closed).
        rec = _make_record()
        await store.save_draft(rec)
        with pytest.raises(TypeError) as ei:
            await store.transition(
                pack_id=rec.id,
                transition="submit",
                actor_id="author-1",
                tenant_id=None,
                evidence_pointer=None,
                iso_controls=("A.5.31",),  # type: ignore[call-arg]
                request_id="req-iso-arg-refused",
            )
        # The standard CPython kwarg-mismatch message includes the
        # bad kwarg name. Pinning the exact substring would couple to
        # CPython error-message wording (unstable across versions);
        # asserting the name appears in the diagnostic is sufficient.
        assert "iso_controls" in str(ei.value)


# ===========================================================================
# PackRecordStore.transition — refusal paths
# ===========================================================================


class TestSprint7B1PackRecordStoreTransitionRefused:
    """Refused transitions fail-closed. The precondition raises
    ``LifecycleTransitionRefused`` BEFORE the chain INSERT runs;
    ``append_with_precondition`` rolls the transaction back; chain
    count + state cache are unchanged."""

    async def test_invalid_state_pair_raises(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        # Try to submit a pack that's already in the submitted state —
        # generic invalid-state-pair fallthrough.
        rec = _make_record()
        await store.save_draft(rec)
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="author-1",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-canary-1",
        )
        chain_before = await _count_chain_rows(engine)
        state_before = await _read_pack_state(engine, rec.id)
        with pytest.raises(LifecycleTransitionRefused) as ei:
            await store.transition(
                pack_id=rec.id,
                transition="submit",
                actor_id="author-1",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req-canary-2",
            )
        assert ei.value.reason == "lifecycle_transition_invalid_state_pair"
        # No chain row inserted (rollback).
        assert await _count_chain_rows(engine) == chain_before
        # State cache unchanged.
        assert await _read_pack_state(engine, rec.id) == state_before

    async def test_approve_without_review_claim_emits_specific_reason(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        # submitted → approved skips under_review — the per-transition
        # specific reason fires with better operator diagnostics than
        # the generic invalid-state-pair fallthrough.
        rec = _make_record()
        await store.save_draft(rec)
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="author-1",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-1",
        )
        chain_before = await _count_chain_rows(engine)
        with pytest.raises(LifecycleTransitionRefused) as ei:
            await store.transition(
                pack_id=rec.id,
                transition="approve",
                actor_id="reviewer-1",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req-2",
            )
        assert ei.value.reason == "lifecycle_transition_approve_without_review_claim"
        assert await _count_chain_rows(engine) == chain_before
        assert await _read_pack_state(engine, rec.id) == "submitted"

    async def test_terminal_state_raises(self, store: PackRecordStore, engine: AsyncEngine) -> None:
        # Drive the pack to uninstalled, then try to transition out —
        # should raise terminal_state.
        rec = _make_record()
        await store.save_draft(rec)
        for trans in (
            "submit",
            "claim",
            "approve",
            "allow_list",
            "install",
            "disable",
            "revoke",
            "uninstall",
        ):
            await store.transition(
                pack_id=rec.id,
                transition=trans,
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-{trans}",
            )
        chain_before = await _count_chain_rows(engine)
        with pytest.raises(LifecycleTransitionRefused) as ei:
            await store.transition(
                pack_id=rec.id,
                transition="install",
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req-after-uninstalled",
            )
        assert ei.value.reason == "lifecycle_transition_terminal_state"
        assert await _count_chain_rows(engine) == chain_before
        assert await _read_pack_state(engine, rec.id) == "uninstalled"


# ===========================================================================
# PackRecordStore.transition — pack-not-found
# ===========================================================================


class TestSprint7B1PackRecordStoreTransitionPackNotFound:
    """``transition()`` against a pack id that has no row in ``packs``
    raises ``PackNotFound`` from the precondition. Mirrors
    ``EscalationNotFound`` from ``core/escalation.py``."""

    async def test_transition_unknown_pack_raises(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        chain_before = await _count_chain_rows(engine)
        with pytest.raises(PackNotFound):
            await store.transition(
                pack_id=uuid.uuid4(),
                transition="submit",
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req-missing",
            )
        # No row inserted (rollback).
        assert await _count_chain_rows(engine) == chain_before


# ===========================================================================
# PackRecordStore.list_by_status
# ===========================================================================


class TestSprint7B1PackRecordStoreListByStatus:
    """``list_by_status(state)`` returns packs whose denormalised
    ``packs.state`` cache matches. Used by Sprint 7B.2 portal queue
    queries (``GET /packs?state=submitted``). Pagination via ``limit``
    + ``cursor`` (insertion-order)."""

    async def test_filters_by_state(self, store: PackRecordStore) -> None:
        # Seed three drafts; advance one to submitted.
        rec_a = _make_record(pack_id="pack-a")
        rec_b = _make_record(pack_id="pack-b")
        rec_c = _make_record(pack_id="pack-c")
        for r in (rec_a, rec_b, rec_c):
            await store.save_draft(r)
        await store.transition(
            pack_id=rec_a.id,
            transition="submit",
            actor_id="canary",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-canary",
        )

        drafts = await store.list_by_status("draft")
        submitted = await store.list_by_status("submitted")

        assert {r.id for r in drafts} == {rec_b.id, rec_c.id}
        assert {r.id for r in submitted} == {rec_a.id}

    async def test_returns_empty_when_no_match(self, store: PackRecordStore) -> None:
        await store.save_draft(_make_record())
        result = await store.list_by_status("approved")
        assert result == []

    async def test_pagination_limit_caps_result_set(self, store: PackRecordStore) -> None:
        for i in range(5):
            await store.save_draft(_make_record(pack_id=f"pack-{i}"))
        result = await store.list_by_status("draft", limit=2)
        assert len(result) == 2

    async def test_pagination_cursor_skips_records_at_or_before(
        self, store: PackRecordStore
    ) -> None:
        # Seed five drafts; first page (cursor=None) returns 2 in id-asc
        # order; cursor pagination feeds the last-returned id into the
        # next page request and the second page contains records strictly
        # after that cursor.
        for i in range(5):
            await store.save_draft(_make_record(pack_id=f"pack-{i}"))
        page1 = await store.list_by_status("draft", limit=2)
        assert len(page1) == 2
        page2 = await store.list_by_status("draft", limit=2, cursor=page1[-1].id)
        assert len(page2) == 2
        # Cursor pagination MUST exclude the cursor record itself + every
        # record before it; the page1 + page2 result sets are disjoint by
        # id.
        assert {r.id for r in page1}.isdisjoint({r.id for r in page2})


# ===========================================================================
# PackRecordStore.load_lifecycle_history
# ===========================================================================


class TestSprint7B1PackRecordStoreLoadLifecycleHistory:
    """``load_lifecycle_history(pack_id)`` walks the
    ``decision_history.event_type LIKE 'pack.lifecycle.%'`` slice
    filtered to ``payload['pack_id'] == str(pack_id)``. Mirrors
    ``core/escalation.py:_read_current_state_within_txn`` JSON-key
    extraction approach (dialect-portable: client-side filter on
    payload key)."""

    async def test_returns_chain_rows_in_sequence_order(self, store: PackRecordStore) -> None:
        rec = _make_record()
        await store.save_draft(rec)
        for trans in ("submit", "claim", "approve"):
            await store.transition(
                pack_id=rec.id,
                transition=trans,
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-{trans}",
            )
        history = await store.load_lifecycle_history(rec.id)
        assert [h.decision_type for h in history] == [
            "pack.lifecycle.submitted",
            "pack.lifecycle.under_review",
            "pack.lifecycle.approved",
        ]

    async def test_filters_to_pack_id(self, store: PackRecordStore) -> None:
        # Two packs; one transition each. History should only reflect
        # the asked-for pack's transitions.
        rec_a = _make_record(pack_id="pack-a")
        rec_b = _make_record(pack_id="pack-b")
        for r in (rec_a, rec_b):
            await store.save_draft(r)
            await store.transition(
                pack_id=r.id,
                transition="submit",
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-{r.pack_id}",
            )
        history_a = await store.load_lifecycle_history(rec_a.id)
        history_b = await store.load_lifecycle_history(rec_b.id)
        assert len(history_a) == 1
        assert len(history_b) == 1
        assert history_a[0].payload["pack_id"] == str(rec_a.id)
        assert history_b[0].payload["pack_id"] == str(rec_b.id)

    async def test_returns_empty_when_no_transitions(self, store: PackRecordStore) -> None:
        rec = _make_record()
        await store.save_draft(rec)
        history = await store.load_lifecycle_history(rec.id)
        assert history == []


# ===========================================================================
# PackRecordStore.load_pack_audit_events (review §4.4 — C-narrow)
# ===========================================================================


class TestPackRecordStoreLoadPackAuditEvents:
    """``load_pack_audit_events(pack_id)`` is the examiner-facing audit
    reader (review §4.4, C-narrow). It surfaces BOTH lifecycle
    transitions (``pack.lifecycle.%``) AND force-approve authorisations
    (``pack.approval_override``) for a pack, filtered to
    ``payload['pack_id'] == str(pack_id)`` and sorted by ``sequence``.

    Distinct from :meth:`load_lifecycle_history`, which stays
    lifecycle-only (it feeds the detail view + evidence projectors whose
    contract MUST NOT change). ``pack.evidence_read.*`` rows are
    DELIBERATELY excluded at this stage (deferred per the §4.4 C-narrow
    decision) — see ``test_excludes_evidence_read_events``.
    """

    _SNAPSHOT: ClassVar[dict[str, Any]] = {"pack_kind": "tool", "all_green": False, "gates": []}

    async def test_returns_lifecycle_and_override_rows_in_sequence_order(
        self, store: PackRecordStore
    ) -> None:
        # pin #1 — both row families surfaced, in chain (sequence) order.
        rec = _make_record()
        await store.save_draft(rec)
        for trans in ("submit", "claim"):
            await store.transition(
                pack_id=rec.id,
                transition=trans,
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-{trans}",
            )
        await store.append_override_event(
            pack_id=rec.id,
            override_actor_subject="alice@bank.example",
            override_reason="security_exception",
            gate_composition_snapshot=self._SNAPSHOT,
            request_id="req-override",
        )
        events = await store.load_pack_audit_events(rec.id)
        # submit + claim happen first; the override authorisation last.
        assert [e.decision_type for e in events] == [
            "pack.lifecycle.submitted",
            "pack.lifecycle.under_review",
            "pack.approval_override",
        ]

    async def test_load_lifecycle_history_still_excludes_override(
        self, store: PackRecordStore
    ) -> None:
        # pin #2 GUARD — broadening the audit reader MUST NOT leak the
        # override row into load_lifecycle_history (which feeds the detail
        # view + projectors). Characterises the preserved lifecycle-only
        # contract.
        rec = _make_record()
        await store.save_draft(rec)
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="canary",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-submit",
        )
        await store.append_override_event(
            pack_id=rec.id,
            override_actor_subject="alice@bank.example",
            override_reason="security_exception",
            gate_composition_snapshot=self._SNAPSHOT,
            request_id="req-override",
        )
        lifecycle = await store.load_lifecycle_history(rec.id)
        assert [e.decision_type for e in lifecycle] == ["pack.lifecycle.submitted"]
        assert "pack.approval_override" not in {e.decision_type for e in lifecycle}

    async def test_filters_to_pack_id_no_cross_pack_override_leak(
        self, store: PackRecordStore
    ) -> None:
        # pin #5 — pack B's override MUST NOT appear in pack A's audit.
        rec_a = _make_record(pack_id="pack-a")
        rec_b = _make_record(pack_id="pack-b")
        for r in (rec_a, rec_b):
            await store.save_draft(r)
            await store.transition(
                pack_id=r.id,
                transition="submit",
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-submit-{r.pack_id}",
            )
            await store.append_override_event(
                pack_id=r.id,
                override_actor_subject="alice@bank.example",
                override_reason="security_exception",
                gate_composition_snapshot=self._SNAPSHOT,
                request_id=f"req-override-{r.pack_id}",
            )
        events_a = await store.load_pack_audit_events(rec_a.id)
        assert {e.payload["pack_id"] for e in events_a} == {str(rec_a.id)}
        assert "pack.approval_override" in {e.decision_type for e in events_a}
        assert all(e.payload["pack_id"] != str(rec_b.id) for e in events_a)

    async def test_excludes_evidence_read_events(self, store: PackRecordStore) -> None:
        # pin #6 (DELIBERATE deferral, not forgotten) — ``pack.evidence_read.*``
        # rows are NOT surfaced under the §4.4 C-narrow decision. A future
        # sprint may widen the union; until then this guard makes the
        # exclusion explicit.
        rec = _make_record()
        await store.save_draft(rec)
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="canary",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-submit",
        )
        await store.append_override_event(
            pack_id=rec.id,
            override_actor_subject="alice@bank.example",
            override_reason="security_exception",
            gate_composition_snapshot=self._SNAPSHOT,
            request_id="req-override",
        )
        await store.append_evidence_read_event(
            pack_id=rec.id,
            actor_subject="reviewer-alice",
            panel_name="data_governance",
            tenant_id=rec.tenant_id or "t1",
            request_id="req-evidence-read",
        )
        decision_types = {e.decision_type for e in await store.load_pack_audit_events(rec.id)}
        assert "pack.lifecycle.submitted" in decision_types
        assert "pack.approval_override" in decision_types
        assert not any(dt.startswith("pack.evidence_read") for dt in decision_types)

    async def test_returns_empty_when_no_events(self, store: PackRecordStore) -> None:
        rec = _make_record()
        await store.save_draft(rec)
        events = await store.load_pack_audit_events(rec.id)
        assert events == []


# ===========================================================================
# Module surface exports
# ===========================================================================


class TestSprint7B1PackStorageModuleSurface:
    """Pin the ``packs.storage`` ``__all__`` so a future refactor can't
    silently drop a public-API symbol the runtime / portal expects."""

    def test_all_exports_present(self) -> None:
        from cognic_agentos.packs import storage as mod

        for name in (
            "LifecycleTransitionRefused",
            "PackNotFound",
            "PackRecord",
            "PackRecordRefusalReason",
            "PackRecordRefused",
            "PackRecordStore",
        ):
            assert hasattr(mod, name), f"packs.storage missing {name!r}"

    def test_lifecycle_refusal_reason_re_exported_via_lifecycle(self) -> None:
        # The exception's ``reason`` attribute carries
        # ``LifecycleRefusalReason`` from ``packs.lifecycle`` — pin that
        # the storage module re-uses (does not redefine) the closed
        # enum.
        from cognic_agentos.packs.lifecycle import LifecycleRefusalReason as LRR

        # Constructing the exception with a known LifecycleRefusalReason
        # value should work without coercion.
        exc = LifecycleTransitionRefused("lifecycle_transition_terminal_state")
        assert exc.reason in set(LifecycleRefusalReason.__args__)  # type: ignore[attr-defined]
        # Type-only confirmation: same alias.
        assert LifecycleRefusalReason is LRR


# ===========================================================================
# T3 R1 P2 #1 — save_draft non-draft refusal (blocker fix)
# ===========================================================================


class TestSprint7B1PackRecordStoreSaveDraftRefusesNonDraft:
    """``save_draft`` is the entry point to the state machine; ``record.state``
    MUST be ``"draft"``. Without this guard, a caller could construct
    ``PackRecord(state="installed", ...)`` and ``save_draft`` would
    persist it with NO ``decision_history`` predecessor — bypassing
    the entire lifecycle audit chain.

    Pinned by reproducing the original failure: 10 representative
    non-draft states refused with the closed-enum
    ``pack_record_save_draft_initial_state_not_draft`` reason; no
    ``packs`` row inserted; no ``decision_history`` row emitted.
    Per ``feedback_security_regression_hardening.md`` this regression
    was reproduced locally before the fix landed (T3 R1 P2 #1)."""

    @pytest.mark.parametrize(
        "non_draft_state",
        [
            "submitted",
            "under_review",
            "approved",
            "rejected",
            "withdrawn",
            "allow_listed",
            "installed",
            "disabled",
            "revoked",
            "uninstalled",
        ],
    )
    async def test_each_non_draft_state_refused(
        self,
        store: PackRecordStore,
        engine: AsyncEngine,
        non_draft_state: str,
    ) -> None:
        rec = _make_record(state=non_draft_state)  # type: ignore[arg-type]
        chain_before = await _count_chain_rows(engine)
        with pytest.raises(PackRecordRefused) as ei:
            await store.save_draft(rec)
        # Closed-enum reason carries the exact failure mode.
        assert ei.value.reason == "pack_record_save_draft_initial_state_not_draft"
        # And the offending state is captured for operator diagnostics.
        assert ei.value.state == non_draft_state
        # Pack row NEVER inserted — load() must return None.
        loaded = await store.load(rec.id)
        assert loaded is None, (
            f"pack row leaked through save_draft refusal for state={non_draft_state!r}"
        )
        # Chain row count unchanged.
        assert await _count_chain_rows(engine) == chain_before

    async def test_draft_state_still_admitted(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        # Negative-of-the-negative: positive control proves the guard
        # does NOT over-refuse legitimate draft submissions.
        rec = _make_record(state="draft")
        returned_id = await store.save_draft(rec)
        assert returned_id == rec.id
        loaded = await store.load(rec.id)
        assert loaded is not None and loaded.state == "draft"


class TestSprint7B1PackRecordRefusedException:
    """``PackRecordRefused`` carries the closed-enum
    :data:`PackRecordRefusalReason` + the offending state for operator
    diagnostics. Distinct from :class:`LifecycleTransitionRefused`
    because the lifecycle table never had a chance to run — this is
    an API-contract refusal, not a state-machine refusal."""

    def test_inherits_exception(self) -> None:
        assert issubclass(PackRecordRefused, Exception)

    def test_distinct_from_lifecycle_transition_refused(self) -> None:
        # Two unrelated exception classes; callers MUST be able to
        # except them separately.
        assert not issubclass(PackRecordRefused, LifecycleTransitionRefused)
        assert not issubclass(LifecycleTransitionRefused, PackRecordRefused)

    def test_reason_in_closed_enum(self) -> None:
        exc = PackRecordRefused(
            "pack_record_save_draft_initial_state_not_draft",
            state="installed",
        )
        assert exc.reason in set(PackRecordRefusalReason.__args__)  # type: ignore[attr-defined]
        assert exc.state == "installed"

    def test_state_optional_for_future_reasons(self) -> None:
        # Future reasons may not have an offending state to surface;
        # the constructor accepts ``state=None`` and the message
        # collapses gracefully.
        exc = PackRecordRefused("pack_record_save_draft_initial_state_not_draft")
        assert exc.state is None
        # Non-empty message; doesn't crash.
        assert "pack_record_save_draft_initial_state_not_draft" in str(exc)


# ===========================================================================
# T3 R1 P2 #2 — unknown transition name guard (blocker fix; mirrors
# packs/lifecycle.py step-3 guard from T2 R1 P2)
# ===========================================================================


class TestSprint7B1PackRecordStoreTransitionNameUnknownGuard:
    """``transition()`` indexes ``_TRANSITION_TO_TARGET_STATE[transition]``
    to derive ``to_state``. Without a runtime guard, an out-of-vocabulary
    transition like ``transition="archive"`` would raise ``KeyError``
    before reaching the ``validate_transition`` lifecycle layer —
    leaking an unstructured exception past the closed-enum boundary.

    The fix mirrors ``packs/lifecycle.py``'s step-3 guard from T2 R1
    P2: both layers MUST refuse out-of-vocabulary transition names
    with the same ``lifecycle_transition_name_unknown`` closed-enum
    reason. This is the same asymmetric-runtime-guard pattern (Python
    does not enforce ``Literal`` at runtime, so consumers of a Literal
    type that index into a ``Mapping`` keyed by that Literal need a
    runtime guard before the indexed access). Per
    ``feedback_security_regression_hardening.md`` this regression was
    reproduced locally before the fix landed (T3 R1 P2 #2)."""

    async def test_unknown_transition_name_raises_closed_enum(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record()
        await store.save_draft(rec)
        chain_before = await _count_chain_rows(engine)
        state_before = await _read_pack_state(engine, rec.id)
        with pytest.raises(LifecycleTransitionRefused) as ei:
            await store.transition(
                pack_id=rec.id,
                transition="archive",  # type: ignore[arg-type]
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req-archive",
            )
        # Closed-enum reason mirrors the lifecycle layer's guard
        # (T2 R1 P2's ``lifecycle_transition_name_unknown`` is the
        # canonical closed-enum value for both layers).
        assert ei.value.reason == "lifecycle_transition_name_unknown"
        # No chain row inserted (the guard runs BEFORE
        # append_with_precondition).
        assert await _count_chain_rows(engine) == chain_before
        # State cache unchanged.
        assert await _read_pack_state(engine, rec.id) == state_before

    @pytest.mark.parametrize(
        "fake_transition",
        ["archive", "purge", "delete", "promote", ""],
    )
    async def test_no_keyerror_leak_for_string_inputs(
        self, store: PackRecordStore, engine: AsyncEngine, fake_transition: str
    ) -> None:
        # No matter what string the caller passes, the closed-enum
        # boundary holds — never a raw KeyError. Mirrors T2's
        # TestSprint7B1NoKeyErrorLeakInvariant doctrine for the
        # storage layer. (Type-discipline violations like
        # ``transition=[]`` may still raise TypeError at the hashable
        # membership check; same scope as T2's narrow contract.)
        rec = _make_record()
        await store.save_draft(rec)
        try:
            await store.transition(
                pack_id=rec.id,
                transition=fake_transition,  # type: ignore[arg-type]
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req",
            )
        except LifecycleTransitionRefused as exc:
            assert exc.reason == "lifecycle_transition_name_unknown"
        except KeyError as exc:  # pragma: no cover — regression sentinel
            pytest.fail(
                f"KeyError({exc!r}) leaked past closed-enum boundary "
                f"for transition={fake_transition!r}; storage's runtime "
                f"guard regressed (T3 R1 P2 #2)"
            )


# ===========================================================================
# T3 R1 P2 — security-regression hardening per
# feedback_security_regression_hardening.md
# ===========================================================================


class TestSprint7B1StorageGuardsLoadBearing:
    """Prove the new storage-layer guards are load-bearing by asserting
    they fire on EXACTLY the malformed inputs the reviewer reproduced.
    Per ``feedback_security_regression_hardening.md``: pair every
    security-critical regression with a self-test that proves the
    detector fires on known-bad input + a temporary fix-revert proof
    that the test would FAIL without the fix. The fix-revert proof for
    these guards was demonstrated in the T3 R1 P2 reproducer
    (one-liner script that confirmed both blockers BEFORE the
    runtime guards landed)."""

    async def test_save_draft_guard_fires_on_reviewer_reproduced_input(
        self, store: PackRecordStore
    ) -> None:
        # The reviewer's exact reproduction case: state="installed"
        # without any prior draft → submit → ... → install transitions.
        rec = _make_record(state="installed")
        with pytest.raises(PackRecordRefused) as ei:
            await store.save_draft(rec)
        assert ei.value.reason == "pack_record_save_draft_initial_state_not_draft"
        # Reproduces the exact diagnostic the reviewer flagged: the
        # would-be installed pack does NOT exist after the refusal.
        assert (await store.load(rec.id)) is None

    async def test_transition_name_guard_fires_on_reviewer_reproduced_input(
        self, store: PackRecordStore
    ) -> None:
        # The reviewer's exact reproduction case: transition="archive".
        rec = _make_record()
        await store.save_draft(rec)
        with pytest.raises(LifecycleTransitionRefused) as ei:
            await store.transition(
                pack_id=rec.id,
                transition="archive",  # type: ignore[arg-type]
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req",
            )
        # Closed-enum boundary holds — KeyError("archive") would have
        # surfaced raw without this guard.
        assert ei.value.reason == "lifecycle_transition_name_unknown"
