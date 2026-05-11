"""Sprint 7B.1 T5 — ISO 42001 control mapping + fail-closed semantics.

Per the plan-of-record at
``docs/superpowers/plans/2026-05-10-sprint-7b1-lifecycle-state-machine.md``
T5 §"ISO 42001 control mapping + fail-closed semantics tests".

Test surface:

- ``_TRANSITION_TO_ISO_CONTROLS`` build-time drift detectors: the
  canonical mapping in ``packs/lifecycle.py`` covers every
  :data:`cognic_agentos.packs.lifecycle.TransitionName` value with codes
  drawn from the closed ``_KNOWN_ISO_CONTROL_CODES`` vocabulary.
  Adding a new transition without an ISO entry, or adding an ISO code
  not in the closed vocabulary, fails here at build time.
- :func:`cognic_agentos.packs.lifecycle.iso_controls_for` public-helper
  contract: returns the canonical tuple for known transitions, refuses
  out-of-vocabulary transitions with the same
  ``"lifecycle_transition_name_unknown"`` closed-enum reason that
  ``validate_transition`` returns at its step-3 guard (mirrors the
  asymmetric-runtime-guard doctrine in
  ``feedback_strict_review_off_gate.md``).
- Chain-emission completeness: every transition name causes the
  matching ISO controls to land in both
  ``DecisionRecord.payload['iso_controls']`` (canonically derived
  inside ``PackRecordStore.transition`` per T5 R1 P2 — callers do
  NOT supply tags, they are looked up via
  :func:`iso_controls_for` from the transition name) AND the chain
  row's own ``iso_controls`` column (canonical envelope field; the
  verifier re-reads this column). The full 10-transition lifecycle
  walk emits one chain row per transition.
- Chain integrity: :meth:`ChainVerifier.walk` over the
  ``decision_history`` chain returns ``is_clean=True`` after a
  5-transition install-path slice (``submit`` → ``claim`` →
  ``approve`` → ``allow_list`` → ``install``). Proves the
  ``DecisionHistoryStore.append_with_precondition`` rollup hashes
  the ``iso_controls`` field as part of the canonical envelope per
  ``core/chain_verifier.py:170`` — post-write mutation of the stored
  ``iso_controls`` bytes (or any other envelope field) surfaces as
  ``hash_mismatch``. This walk does NOT prove tag-presence: a
  regression that wrote ``iso_controls=[]`` (or wrongly-mapped tags)
  consistently on both the write side AND the row column would still
  hash-match. Tag-presence + canonical-mapping enforcement (across
  every transition name, including the branches the install-path
  slice does not exercise) lives in the per-transition canonical-
  match assertions at
  ``TestSprint7B1IsoControlsRecordedForEveryTransition`` below; the
  walk catches **mutation of correctly-tagged rows** (over the
  install-path subset), the canonical-match test catches **incorrect
  tagging at write time** (across all 10 ``TransitionName`` values).
  Together they cover the two distinct attack surfaces.
- Fail-closed semantics: each refusal class not covered in
  ``test_storage.py`` proves zero chain row insertion + zero
  ``packs.state`` cache mutation. ``test_storage.py`` already covers
  ``lifecycle_transition_invalid_state_pair`` (assertion at
  ``test_storage.py:564``) and
  ``lifecycle_transition_approve_without_review_claim`` (assertion at
  ``test_storage.py:596``).
  This module covers the remaining classes:
  PREFLIGHT (no DB connection acquired):
    - ``lifecycle_transition_name_unknown`` — asymmetric-runtime-guard
      at storage entry (mirrors the lifecycle.py step-3 guard from
      T2 R1 P2 + T3 R1 P2 #2).
  IN-PRECONDITION (transaction rolls back):
    - ``lifecycle_transition_terminal_state``
    - ``lifecycle_transition_double_install``
    - ``lifecycle_transition_revoke_already_revoked``
    - ``lifecycle_transition_disable_not_installed``

Concurrency proofs (``SELECT ... FOR UPDATE`` serialisation under
contention) intentionally live at the integration level in
``tests/integration/packs/test_storage_lock_serialisation.py`` —
SQLite cannot honour ``FOR UPDATE`` row-level locking (database-level
locks only). The unit suite here uses the same SQLite substrate as
``test_storage.py`` and asserts in-transaction rollback contracts that
do not depend on row-level locks (the rollback is from the precondition
``raise``, not from a lock-contention loser).

Halt-before-commit per AGENTS.md "Authoring — Bank pack lifecycle
(Sprint 7B.1)" + ``feedback_strict_review_off_gate.md``: critical
controls module under TDD with ≥95% line / ≥90% branch coverage on
``packs/lifecycle.py`` after the gate-list extension at T7.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, get_args

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.chain_verifier import ChainVerifier
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.packs.lifecycle import (
    _KNOWN_ISO_CONTROL_CODES,
    _TRANSITION_TO_ISO_CONTROLS,
    LifecycleTransitionRefused,
    PackKind,
    PackState,
    TransitionName,
    iso_controls_for,
)
from cognic_agentos.packs.storage import (
    PackRecord,
    PackRecordStore,
    _packs,
)

# ===========================================================================
# Fixtures (mirror tests/unit/packs/test_storage.py:58-99)
# ===========================================================================


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    """Per-test SQLite-aiosqlite engine with the governance schema +
    seeded chain heads + ``packs`` table. Mirrors
    ``tests/unit/packs/test_storage.py:58-94``. The fixture must seed
    the ``decision_history`` chain head — ``ChainVerifier.walk`` (the
    chain-integrity test) reads ``governance_chain_heads`` and would
    surface ``head_mismatch`` on an absent head row even on an empty
    chain."""

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
) -> PackRecord:
    """Construct a fully-populated PackRecord for tests. Mirrors
    ``tests/unit/packs/test_storage.py:102-131`` — deterministic 32-byte
    digest bytes so chain integrity checks survive across save/load."""

    now = datetime.now(UTC)
    return PackRecord(
        id=record_id or uuid.uuid4(),
        kind=kind,
        pack_id=pack_id,
        display_name=pack_id,
        state=state,
        manifest_digest=b"\x01" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id=None,
        created_by="canary-author",
        last_actor="canary-author",
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
# Stage 1 — _TRANSITION_TO_ISO_CONTROLS shape + drift detectors
# ===========================================================================


class TestSprint7B1IsoControlsMapShape:
    """``_TRANSITION_TO_ISO_CONTROLS`` is the canonical
    transition-name → ISO 42001 controls mapping pinned at module
    scope in ``packs/lifecycle.py``. T5 §"ISO 42001 control mapping"
    in the plan-of-record. Drift detectors:

    - Every ``TransitionName`` value has an entry (adding a new
      transition without an ISO tag fails here).
    - Every value is a tuple of nonempty strings drawn from the
      closed ``_KNOWN_ISO_CONTROL_CODES`` vocabulary (adding an
      ISO code outside the closed set fails here — pinning T5
      doctrine that vocabulary additions go through deliberate
      sprints, NOT silent map edits)."""

    def test_map_keys_match_transition_name_literal(self) -> None:
        # Build-time invariant: every TransitionName has an ISO entry.
        # Mirrors the ``_TRANSITION_TO_TARGET_STATE`` drift detector at
        # tests/unit/packs/test_storage.py:284-287.
        assert set(_TRANSITION_TO_ISO_CONTROLS.keys()) == set(get_args(TransitionName))

    def test_every_value_is_nonempty_tuple_of_strings(self) -> None:
        # ISO controls are tuples (not lists, not frozensets) for
        # canonical-form parity with DecisionRecord.iso_controls
        # (typed as ``tuple[str, ...]`` per core/decision_history.py:249).
        # Empty tuples would emit untagged chain rows — refused by the
        # build-time invariant.
        for transition_name, controls in _TRANSITION_TO_ISO_CONTROLS.items():
            assert isinstance(controls, tuple), (
                f"transition {transition_name!r}: iso_controls is "
                f"{type(controls).__name__}, must be tuple"
            )
            assert len(controls) > 0, (
                f"transition {transition_name!r}: iso_controls is empty; "
                "every pack-lifecycle event MUST emit at least one ISO control "
                "tag for examiner-ready audit evidence per ADR-006"
            )
            for code in controls:
                assert isinstance(code, str), (
                    f"transition {transition_name!r}: iso_controls element "
                    f"{code!r} is {type(code).__name__}, must be str"
                )
                assert code.strip() == code and len(code) > 0, (
                    f"transition {transition_name!r}: iso_controls element "
                    f"{code!r} is empty / whitespace-padded"
                )

    def test_every_code_is_in_known_iso_control_vocabulary(self) -> None:
        # Closed-vocabulary detector: every iso code MUST be a member
        # of ``_KNOWN_ISO_CONTROL_CODES``. Silent additions to the map
        # with a fresh code outside the vocabulary fail here. Future
        # sprints widening the vocabulary MUST update
        # ``_KNOWN_ISO_CONTROL_CODES`` AND the controls registry
        # (ADR-006 Phase 3.1) in the same commit.
        for transition_name, controls in _TRANSITION_TO_ISO_CONTROLS.items():
            for code in controls:
                assert code in _KNOWN_ISO_CONTROL_CODES, (
                    f"transition {transition_name!r}: iso_controls code "
                    f"{code!r} is not in _KNOWN_ISO_CONTROL_CODES "
                    f"{sorted(_KNOWN_ISO_CONTROL_CODES)!r}"
                )


# ===========================================================================
# Stage 2 — iso_controls_for() public-helper contract
# ===========================================================================


class TestSprint7B1IsoControlsForHelper:
    """:func:`iso_controls_for` is the public lookup seam.
    Sprint 7B.2 portal handlers + future callers use it to derive the
    canonical ISO controls before calling
    :meth:`PackRecordStore.transition` — single source of truth for
    what controls each transition tags."""

    def test_helper_returns_canonical_tuple_for_every_transition(self) -> None:
        # Helper output == map entry for every known transition. Pin
        # against future helper drift (the helper MUST NOT augment /
        # filter / reorder).
        for transition_name in get_args(TransitionName):
            assert iso_controls_for(transition_name) == _TRANSITION_TO_ISO_CONTROLS[transition_name]

    def test_helper_refuses_unknown_transition_with_closed_enum_reason(self) -> None:
        # Asymmetric-runtime-guard doctrine (per
        # ``feedback_strict_review_off_gate.md`` §8 — lifecycle.py
        # step-3 guard at T2 R1 P2 + storage.py preflight guard at
        # T3 R1 P2 #2): every public seam that takes a Literal /
        # closed-enum argument MUST runtime-validate it and raise
        # ``LifecycleTransitionRefused`` with the closed-enum
        # ``lifecycle_transition_name_unknown`` reason — NOT raise a
        # bare KeyError leaking the dictionary internals.
        with pytest.raises(LifecycleTransitionRefused) as ei:
            iso_controls_for("archive")  # type: ignore[arg-type]
        assert ei.value.reason == "lifecycle_transition_name_unknown"


# ===========================================================================
# Stage 3 — chain-emission completeness: every transition emits the
# canonical iso_controls into both payload['iso_controls'] and the
# chain row's iso_controls column.
# ===========================================================================


class TestSprint7B1IsoControlsRecordedForEveryTransition:
    """Walk a full 10-transition lifecycle slice and verify the canonical
    ISO controls land in both the chain row's ``iso_controls`` column
    AND ``payload['iso_controls']`` for each transition.

    Two distinct landing sites because the chain envelope and the
    payload column serve different consumers:

    - Chain row ``iso_controls`` is part of the canonical envelope
      hashed into ``record_hash`` (per ``core/chain_verifier.py:170``).
      Examiner-side tamper-evidence walkers re-hash the envelope and
      compare; tamper with the column → ``hash_mismatch``.
    - ``payload['iso_controls']`` is the JSON-encoded shape the portal
      API surfaces to operators reading evidence rows. Storage stamps
      both (``payload['iso_controls']`` at
      ``packs/storage.py:519`` + the
      ``DecisionRecord(..., iso_controls=...)`` kwarg at
      ``packs/storage.py:521``) on every transition row, both populated
      from the same ``canonical_iso_controls`` local that
      ``packs/storage.py:456`` derives via :func:`iso_controls_for`.
    """

    async def test_full_lifecycle_walk_tags_every_chain_row_with_canonical_controls(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        # Walk the full 10-transition lifecycle. Each transition's
        # chain row MUST carry the canonical iso_controls from the
        # lifecycle map.
        #
        # The lifecycle walk uses two records because no single
        # pack-record path touches all 10 transitions (the state
        # machine branches at approve/reject + at disable/revoke +
        # at withdraw branches off the linear path). The two records
        # together cover: rec_a — submit, claim, reject; rec_b —
        # submit, claim, approve, allow_list, install, disable,
        # revoke, uninstall. Plus rec_c — submit, withdraw — to
        # cover the withdraw branch. Together that exercises every
        # TransitionName key.
        rec_a = _make_record(pack_id="rec-a-rejected-path")
        rec_b = _make_record(pack_id="rec-b-full-install-path")
        rec_c = _make_record(pack_id="rec-c-withdraw-path")
        await store.save_draft(rec_a)
        await store.save_draft(rec_b)
        await store.save_draft(rec_c)

        # Sequenced transitions across the three records.
        walks: list[tuple[uuid.UUID, TransitionName]] = [
            (rec_a.id, "submit"),
            (rec_a.id, "claim"),
            (rec_a.id, "reject"),
            (rec_b.id, "submit"),
            (rec_b.id, "claim"),
            (rec_b.id, "approve"),
            (rec_b.id, "allow_list"),
            (rec_b.id, "install"),
            (rec_b.id, "disable"),
            (rec_b.id, "revoke"),
            (rec_b.id, "uninstall"),
            (rec_c.id, "submit"),
            (rec_c.id, "withdraw"),
        ]
        for i, (pack_id, transition) in enumerate(walks):
            await store.transition(
                pack_id=pack_id,
                transition=transition,
                actor_id="audit-canary-actor",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-audit-{i}",
            )

        # Walk all emitted chain rows and verify each carries the
        # canonical iso_controls for its transition name. The
        # payload's ``transition_name`` is the key into the
        # canonical map.
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.iso_controls,
                        _decision_history.c.payload,
                    )
                    .where(_decision_history.c.event_type.like("pack.lifecycle.%"))
                    .order_by(_decision_history.c.sequence)
                )
            ).all()

        # 13 transitions emitted across the three records (every
        # TransitionName visited at least once).
        assert len(rows) == 13
        # Coverage: every TransitionName appears at least once in
        # the walk.
        observed_transitions = {row.payload["transition_name"] for row in rows}
        assert observed_transitions == set(get_args(TransitionName))

        # Per-row canonical-match assertion.
        for row in rows:
            transition_name: TransitionName = row.payload["transition_name"]
            expected = iso_controls_for(transition_name)
            # Chain envelope column (tamper-evident).
            assert tuple(row.iso_controls) == expected, (
                f"chain row iso_controls drift for transition {transition_name!r}: "
                f"row={row.iso_controls!r}, expected={expected!r}"
            )
            # Payload JSON (operator-readable).
            assert tuple(row.payload["iso_controls"]) == expected, (
                f"payload['iso_controls'] drift for transition {transition_name!r}: "
                f"row={row.payload['iso_controls']!r}, expected={expected!r}"
            )


# ===========================================================================
# Stage 4 — Chain integrity over an install-path slice
# ===========================================================================


class TestSprint7B1LifecycleChainIntegrity:
    """``ChainVerifier.walk()`` over the ``decision_history`` chain
    returns ``is_clean=True`` after a 5-transition install-path slice
    (``submit`` → ``claim`` → ``approve`` → ``allow_list`` →
    ``install``) has been emitted. Proves the rollup written by
    ``DecisionHistoryStore.append_with_precondition`` reconstructs
    against the canonical envelope assembly at
    ``core/chain_verifier.py:138-172``: every row's stored
    ``record_hash`` equals ``sha256(prev_hash || canonical_bytes(env))``
    where ``env`` includes ``row.iso_controls`` verbatim.

    The install-path subset is sufficient for hash/envelope integrity
    coverage — the same canonical-envelope assembly runs on every
    row regardless of transition name. Whole-vocabulary coverage of
    transition names lives in the Stage 3 canonical-match test above
    (:class:`TestSprint7B1IsoControlsRecordedForEveryTransition`);
    that test asserts the WRITTEN tags equal :func:`iso_controls_for`
    for each of the 10 ``TransitionName`` values.

    Scope (what THIS test catches):

    - Post-write mutation of any envelope field on any chain row
      (``iso_controls``, ``payload``, ``record_id``, ``sequence``,
      ``tenant_id``, ``created_at``, etc.) surfaces as
      ``hash_mismatch``.
    - Asymmetric envelope drift — e.g. a regression that dropped
      ``iso_controls`` from the write-side envelope while the verifier
      still reads ``row.iso_controls`` — surfaces as ``hash_mismatch``
      on every subsequent row.
    - Sequence gaps + prev-hash anchor breaks (``sequence_gap`` /
      ``prev_hash_mismatch``) + chain-head drift (``head_mismatch``).

    Out of scope (NOT proven here): canonical tag-presence and
    transition-name → controls correctness. A regression that wrote
    ``iso_controls=[]`` or wrongly-mapped tags consistently on both
    the write side AND the row column would still hash-match — the
    walk cannot distinguish "correctly-tagged" from "consistently-
    wrongly-tagged". That enforcement lives in
    :class:`TestSprint7B1IsoControlsRecordedForEveryTransition`
    (per-row canonical-match against :func:`iso_controls_for`)."""

    async def test_walk_clean_after_install_path_slice(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-integrity-walk")
        await store.save_draft(rec)
        for transition in ("submit", "claim", "approve", "allow_list", "install"):
            await store.transition(
                pack_id=rec.id,
                transition=transition,
                actor_id="integrity-actor",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-integ-{transition}",
            )
        verifier = ChainVerifier(engine, chain_id="decision_history")
        report = await verifier.walk()
        assert report.is_clean is True, (
            f"chain walk surfaced break: kind={report.break_kind!r}, "
            f"first_break_sequence={report.first_break_sequence!r}, "
            f"detail={report.detail!r}"
        )
        # records_checked == 5 transitions emitted in this fixture.
        assert report.records_checked == 5


# ===========================================================================
# Stage 5 — Fail-closed semantics for refusal classes not covered in
# test_storage.py. Each canary asserts (a) the right closed-enum reason
# fires, (b) zero new chain row landed, (c) zero state cache mutation.
# ===========================================================================


class TestSprint7B1FailClosedRefusalPaths:
    """Refusal classes from ``LifecycleRefusalReason`` flowing through
    ``PackRecordStore.transition``. Each test asserts the
    fail-closed contract: chain INSERT + state UPDATE both atomic on
    the precondition raise (Doctrine Lock D in the plan-of-record).

    Split into PREFLIGHT (no DB connection acquired) and
    IN-PRECONDITION (transaction rolls back) — both result in
    no-chain-row + no-state-mutation but via different mechanisms.
    The asymmetric-runtime-guard doctrine
    (``feedback_strict_review_off_gate.md`` §8) requires the
    PREFLIGHT layer to raise the same closed-enum reason as the
    IN-PRECONDITION layer for an out-of-vocabulary transition name."""

    # ---- PREFLIGHT (no DB connection acquired) ---------------------

    async def test_preflight_unknown_transition_name_no_chain_row_no_state_mutation(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        # The runtime guard at ``packs/storage.py:437-438`` (T3 R1 P2 #2)
        # rejects out-of-vocabulary transition names BEFORE any DB
        # connection is acquired. Mirrors ``validate_transition`` step
        # 3 (T2 R1 P2) at ``packs/lifecycle.py:472-473`` and the
        # :func:`iso_controls_for` guard at ``packs/lifecycle.py:393-394``
        # (T5 R1 P2) — all three sites raise
        # :class:`LifecycleTransitionRefused` with the same closed-enum
        # ``"lifecycle_transition_name_unknown"`` reason for any input
        # outside the canonical 10-tuple :data:`TransitionName`.
        rec = _make_record(pack_id="rec-preflight-canary")
        await store.save_draft(rec)
        chain_before = await _count_chain_rows(engine)
        state_before = await _read_pack_state(engine, rec.id)

        with pytest.raises(LifecycleTransitionRefused) as ei:
            await store.transition(
                pack_id=rec.id,
                transition="archive",  # type: ignore[arg-type]
                actor_id="preflight-actor",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req-preflight",
            )
        assert ei.value.reason == "lifecycle_transition_name_unknown"
        assert await _count_chain_rows(engine) == chain_before
        assert await _read_pack_state(engine, rec.id) == state_before

    # ---- IN-PRECONDITION (transaction rolls back) ------------------

    async def test_terminal_state_refusal_no_chain_row_no_state_mutation(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        # Drive a record to ``uninstalled`` (terminal), then attempt
        # to transition further. ``validate_transition`` fires the
        # terminal-state guard at step 4
        # (``packs/lifecycle.py:481-482`` after the T5 ISO-doc + helper
        # expansion + T8 R3 Option B comment expansions shifted the
        # step-4 line range; step 3's transition-name guard is the
        # neighbouring pair at ``packs/lifecycle.py:472-473``).
        rec = _make_record(pack_id="rec-terminal-canary")
        await store.save_draft(rec)
        for transition in ("submit", "claim", "approve", "allow_list", "install", "disable"):
            await store.transition(
                pack_id=rec.id,
                transition=transition,
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-terminal-{transition}",
            )
        await store.transition(
            pack_id=rec.id,
            transition="uninstall",
            actor_id="canary",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-terminal-uninstall",
        )
        # Pack now in terminal "uninstalled" — any further transition
        # MUST refuse with terminal_state.
        chain_before = await _count_chain_rows(engine)
        state_before = await _read_pack_state(engine, rec.id)
        assert state_before == "uninstalled"

        with pytest.raises(LifecycleTransitionRefused) as ei:
            await store.transition(
                pack_id=rec.id,
                transition="install",
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req-terminal-attempt",
            )
        assert ei.value.reason == "lifecycle_transition_terminal_state"
        assert await _count_chain_rows(engine) == chain_before
        assert await _read_pack_state(engine, rec.id) == state_before

    async def test_double_install_refusal_no_chain_row_no_state_mutation(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-double-install-canary")
        await store.save_draft(rec)
        for transition in ("submit", "claim", "approve", "allow_list", "install"):
            await store.transition(
                pack_id=rec.id,
                transition=transition,
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-dbl-{transition}",
            )
        chain_before = await _count_chain_rows(engine)
        state_before = await _read_pack_state(engine, rec.id)
        assert state_before == "installed"

        with pytest.raises(LifecycleTransitionRefused) as ei:
            await store.transition(
                pack_id=rec.id,
                transition="install",
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req-dbl-attempt",
            )
        assert ei.value.reason == "lifecycle_transition_double_install"
        assert await _count_chain_rows(engine) == chain_before
        assert await _read_pack_state(engine, rec.id) == state_before

    async def test_revoke_already_revoked_no_chain_row_no_state_mutation(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_record(pack_id="rec-revoke-revoked-canary")
        await store.save_draft(rec)
        for transition in ("submit", "claim", "approve", "allow_list", "install", "revoke"):
            await store.transition(
                pack_id=rec.id,
                transition=transition,
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-revrev-{transition}",
            )
        chain_before = await _count_chain_rows(engine)
        state_before = await _read_pack_state(engine, rec.id)
        assert state_before == "revoked"

        with pytest.raises(LifecycleTransitionRefused) as ei:
            await store.transition(
                pack_id=rec.id,
                transition="revoke",
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req-revrev-attempt",
            )
        assert ei.value.reason == "lifecycle_transition_revoke_already_revoked"
        assert await _count_chain_rows(engine) == chain_before
        assert await _read_pack_state(engine, rec.id) == state_before

    async def test_disable_not_installed_no_chain_row_no_state_mutation(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        # Disable applies only to installed packs. Try to disable a
        # pack stuck in ``approved`` (no install yet) and prove the
        # specific refusal fires.
        rec = _make_record(pack_id="rec-disable-not-installed")
        await store.save_draft(rec)
        for transition in ("submit", "claim", "approve"):
            await store.transition(
                pack_id=rec.id,
                transition=transition,
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-dni-{transition}",
            )
        chain_before = await _count_chain_rows(engine)
        state_before = await _read_pack_state(engine, rec.id)
        assert state_before == "approved"

        with pytest.raises(LifecycleTransitionRefused) as ei:
            await store.transition(
                pack_id=rec.id,
                transition="disable",
                actor_id="canary",
                tenant_id=None,
                evidence_pointer=None,
                request_id="req-dni-attempt",
            )
        assert ei.value.reason == "lifecycle_transition_disable_not_installed"
        assert await _count_chain_rows(engine) == chain_before
        assert await _read_pack_state(engine, rec.id) == state_before
