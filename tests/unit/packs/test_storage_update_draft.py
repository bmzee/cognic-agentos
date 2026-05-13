"""Sprint 7B.2 T4 — :meth:`PackRecordStore.update_draft` unit tests.

Per the plan-of-record at
``docs/superpowers/plans/2026-05-11-sprint-7b2-portal-api-rbac-owasp.md``
Task 4 §"Atomicity specification (Round 4 P2 #3 + Round 6 P3 #4)":
``update_draft()`` is the in-place edit path for ``draft``-state packs
(developer iterating on a draft before submitting it for review). The
method is CRITICAL CONTROLS by virtue of being added to a Sprint-7B.1
critical-controls module (``packs/storage.py``) — CC-ADJ source
extension per AGENTS.md "no casual refactors" rule.

Refusal-precedence contract (pins this test module's coverage):

1. **Field-allowlist refusal** (pure-Python, BEFORE any DB call) — keys
   outside the 4-field allow-list refuse with
   ``pack_record_update_field_not_allowed``.
2. **Per-field value-shape refusal** (pure-Python, BEFORE any DB call) —
   allow-listed keys whose values fail the per-field shape contract
   refuse with ``pack_record_update_field_invalid_shape`` + structured-log
   emission (``packs.update_draft.invalid_shape`` with field-name in
   ``extra``).
3. **Atomic UPDATE with state precondition** — the SQL UPDATE has
   ``state = 'draft'`` in the WHERE clause.
4. **Rowcount-based refusal disambiguation** — rowcount==0 triggers a
   follow-up SELECT to disambiguate ``PackNotFound`` from
   ``pack_record_update_non_draft_state``.

Watchpoints from the plan §"Halt summary watchpoints" (g) — atomicity:
the row-lock serialisation under contention proof lives at the
integration level (live Postgres + Oracle); the SQLite unit fixture
here covers the deterministic-precondition path.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.packs.lifecycle import PackKind
from cognic_agentos.packs.storage import (
    PackNotFound,
    PackRecord,
    PackRecordRefused,
    PackRecordStore,
    _is_valid_update_value_shape,
    _packs,
)

# ===========================================================================
# Fixtures (mirror tests/unit/packs/test_storage.py:58-100)
# ===========================================================================


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    """Per-test SQLite-aiosqlite engine with the governance schema +
    seeded chain heads + the ``packs`` table. Mirrors
    ``tests/unit/packs/test_storage.py:58-95``."""

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


def _make_draft(
    *,
    pack_id: str = "cognic-tool-update-draft-canary",
    kind: PackKind = "tool",
    record_id: uuid.UUID | None = None,
    tenant_id: str | None = None,
    sbom_pointer: str | None = None,
) -> PackRecord:
    """Construct a fully-populated draft-state PackRecord for tests.
    Deterministic 32-byte digests so equality checks across update +
    re-load succeed."""

    now = datetime.now(UTC)
    return PackRecord(
        id=record_id or uuid.uuid4(),
        kind=kind,
        pack_id=pack_id,
        display_name=pack_id,
        state="draft",
        manifest_digest=b"\x01" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=sbom_pointer,
        tenant_id=tenant_id,
        created_by="canary-original-author",
        last_actor="canary-original-author",
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
# Stage 1 — Happy path
# ===========================================================================


class TestSprint7B2UpdateDraftHappyPath:
    """``update_draft()`` against a draft-state pack with allow-listed
    fields + well-shaped values — succeeds; persists the changes;
    bumps ``last_actor`` + ``updated_at``; emits NO chain row."""

    async def test_update_draft_persists_display_name_change(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_draft()
        await store.save_draft(rec)
        chain_before = await _count_chain_rows(engine)

        await store.update_draft(
            pack_id=rec.id,
            updates={"display_name": "Renamed Pack"},
            actor_id="canary-modifier",
        )

        loaded = await store.load(rec.id)
        assert loaded is not None
        assert loaded.display_name == "Renamed Pack"
        # Other allow-listed fields untouched on this update.
        assert loaded.manifest_digest == b"\x01" * 32
        assert loaded.signed_artefact_digest == b"\x02" * 32
        # Genesis-state pattern — NO chain row emitted.
        assert await _count_chain_rows(engine) == chain_before
        # State unchanged.
        assert await _read_pack_state(engine, rec.id) == "draft"

    async def test_update_draft_persists_all_four_allowlisted_fields(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_draft()
        await store.save_draft(rec)
        chain_before = await _count_chain_rows(engine)

        new_manifest = b"\xab" * 32
        new_signed = b"\xcd" * 32
        await store.update_draft(
            pack_id=rec.id,
            updates={
                "display_name": "Multi-Field Update",
                "manifest_digest": new_manifest,
                "signed_artefact_digest": new_signed,
                "sbom_pointer": "s3://sboms/v2",
            },
            actor_id="canary-modifier",
        )

        loaded = await store.load(rec.id)
        assert loaded is not None
        assert loaded.display_name == "Multi-Field Update"
        assert loaded.manifest_digest == new_manifest
        assert loaded.signed_artefact_digest == new_signed
        assert loaded.sbom_pointer == "s3://sboms/v2"
        assert await _count_chain_rows(engine) == chain_before

    async def test_update_draft_bumps_last_actor_and_updated_at(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """Audit-trail invariant pin (plan §"Audit trail invariant"):
        ``last_actor`` always bumps to the calling actor; ``created_by``
        NEVER mutates (it sits in the 5-field immutable set)."""
        rec = _make_draft()
        await store.save_draft(rec)
        before = await store.load(rec.id)
        assert before is not None
        original_created_by = before.created_by
        original_updated_at = before.updated_at

        # Sleep-equivalent: use a value-only update so we can detect
        # the timestamp bump without timing flakiness; the auto-bump
        # is the contract, not the elapsed wall-clock.
        await store.update_draft(
            pack_id=rec.id,
            updates={"display_name": "Updated For Audit"},
            actor_id="canary-different-modifier",
        )

        after = await store.load(rec.id)
        assert after is not None
        assert after.last_actor == "canary-different-modifier"
        # created_by is the ORIGINAL author — immutable even when a
        # different actor performs the update (same-tenant author
        # collaboration is allowed per plan Round 7 P2 #4; the audit
        # trail captures this via last_actor distinct from created_by).
        assert after.created_by == original_created_by == "canary-original-author"
        # updated_at advances (or at minimum is >= original — SQLite's
        # resolution makes strict > sometimes flaky; check >=).
        assert after.updated_at >= original_updated_at

    async def test_update_draft_with_sbom_pointer_none(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """``sbom_pointer`` allows ``None`` per its per-field shape
        contract; empty string refuses with invalid-shape. Pin the None
        path explicitly."""
        rec = _make_draft(sbom_pointer="s3://sboms/v1")
        await store.save_draft(rec)
        chain_before = await _count_chain_rows(engine)

        await store.update_draft(
            pack_id=rec.id,
            updates={"sbom_pointer": None},
            actor_id="canary-modifier",
        )

        loaded = await store.load(rec.id)
        assert loaded is not None
        assert loaded.sbom_pointer is None
        assert await _count_chain_rows(engine) == chain_before


# ===========================================================================
# Stage 2 — Field-allowlist refusal (Step 1; pure-Python; no DB call)
# ===========================================================================


class TestSprint7B2UpdateDraftFieldAllowlist:
    """Per the plan's atomicity spec Step 1: keys outside the 4-field
    allow-list refuse with ``pack_record_update_field_not_allowed``
    BEFORE any DB connection is acquired. Covers attempts to mutate
    the 5 immutable fields (tenant_id / state / kind / pack_id /
    created_by) — all routed to the same closed-enum reason for
    uniform caller dispatch."""

    @pytest.mark.parametrize(
        "forbidden_field,value",
        [
            ("tenant_id", "attacker-tenant"),
            ("state", "approved"),
            ("kind", "agent"),
            ("pack_id", "attacker-pack-id"),
            ("created_by", "attacker-author"),
            ("id", uuid.uuid4()),
            ("last_actor", "attacker-actor"),  # auto-bumped; caller can't set
            ("updated_at", datetime.now(UTC)),  # auto-bumped; caller can't set
            ("created_at", datetime.now(UTC)),  # immutable creation timestamp
            ("totally_unknown_field", "anything"),
        ],
    )
    async def test_update_draft_refuses_field_not_allowed(
        self,
        store: PackRecordStore,
        engine: AsyncEngine,
        forbidden_field: str,
        value: Any,
    ) -> None:
        rec = _make_draft()
        await store.save_draft(rec)
        chain_before = await _count_chain_rows(engine)
        before = await store.load(rec.id)

        with pytest.raises(PackRecordRefused) as ei:
            await store.update_draft(
                pack_id=rec.id,
                updates={forbidden_field: value},
                actor_id="canary-modifier",
            )
        assert ei.value.reason == "pack_record_update_field_not_allowed"

        # Fail-closed: no chain row, no row mutation, even last_actor
        # untouched (the refusal fires BEFORE the atomic UPDATE).
        assert await _count_chain_rows(engine) == chain_before
        after = await store.load(rec.id)
        assert after == before

    async def test_update_draft_refuses_mixed_allowed_and_disallowed_keys(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """An update dict carrying BOTH an allow-listed key AND a
        forbidden key MUST refuse — the allow-listed key's value never
        lands. Pin the single-bad-key-poisons-batch contract."""
        rec = _make_draft()
        await store.save_draft(rec)
        before = await store.load(rec.id)

        with pytest.raises(PackRecordRefused) as ei:
            await store.update_draft(
                pack_id=rec.id,
                updates={
                    "display_name": "Should Not Persist",
                    "tenant_id": "attacker-tenant",
                },
                actor_id="canary-modifier",
            )
        assert ei.value.reason == "pack_record_update_field_not_allowed"

        after = await store.load(rec.id)
        assert after == before


# ===========================================================================
# Stage 3 — Per-field value-shape refusal (Step 2; pure-Python; no DB call)
# ===========================================================================


class TestSprint7B2UpdateDraftValueShape:
    """Per the plan's atomicity spec Step 2: allow-listed keys whose
    values fail the per-field shape contract refuse with
    ``pack_record_update_field_invalid_shape`` BEFORE any DB call.
    Failing field name surfaces via structured-log emission
    (``packs.update_draft.invalid_shape``) for SIEM correlation; the
    typed-exception payload carries the closed-enum reason ONLY
    (Round 7 P2 #3 — no field-name extension to PackRecordRefused).

    Pinned per Round 6 P3 #4 + Round 9 P3 #3 — parametrized over
    all 4 allow-listed fields for completeness."""

    @pytest.mark.parametrize(
        "field,bad_value",
        [
            # display_name: must be str, non-empty, ≤256 chars
            ("display_name", 42),  # non-str
            ("display_name", ""),  # empty
            ("display_name", "x" * 257),  # too long
            ("display_name", None),  # None disallowed for display_name
            # manifest_digest: must be bytes, exactly 32 bytes
            ("manifest_digest", "should-be-bytes-not-str"),  # non-bytes
            ("manifest_digest", b"too_short"),  # wrong length
            ("manifest_digest", b"\x00" * 33),  # off-by-one too long
            ("manifest_digest", None),  # None disallowed
            # signed_artefact_digest: must be bytes, exactly 32 bytes
            ("signed_artefact_digest", "non-bytes"),
            ("signed_artefact_digest", b"\x00" * 31),
            ("signed_artefact_digest", b""),  # empty
            ("signed_artefact_digest", None),
            # sbom_pointer: must be str non-empty OR None
            ("sbom_pointer", ""),  # empty str disallowed
            ("sbom_pointer", 42),  # non-str
            ("sbom_pointer", b"bytes-not-str"),  # bytes disallowed
        ],
    )
    async def test_update_draft_refuses_invalid_shape_before_db_call(
        self,
        store: PackRecordStore,
        engine: AsyncEngine,
        caplog: pytest.LogCaptureFixture,
        field: str,
        bad_value: Any,
    ) -> None:
        """Per-field value-shape regression set. Each parametrized case:

        (a) raises ``PackRecordRefused`` with closed-enum reason
            ``pack_record_update_field_invalid_shape``
        (b) emits a structured WARNING log at
            ``cognic_agentos.packs.storage`` logger with
            ``packs.update_draft.invalid_shape`` message + the failing
            field name in ``extra``
        (c) the row stays untouched (refusal BEFORE the atomic UPDATE)
        (d) no chain row lands
        """
        rec = _make_draft()
        await store.save_draft(rec)
        chain_before = await _count_chain_rows(engine)
        before = await store.load(rec.id)

        with (
            caplog.at_level(logging.WARNING, logger="cognic_agentos.packs.storage"),
            pytest.raises(PackRecordRefused) as ei,
        ):
            await store.update_draft(
                pack_id=rec.id,
                updates={field: bad_value},
                actor_id="canary-modifier",
            )
        # (a) closed-enum reason
        assert ei.value.reason == "pack_record_update_field_invalid_shape"
        # (b) structured-log emission with field-name diagnostic
        invalid_shape_records = [
            r for r in caplog.records if r.message == "packs.update_draft.invalid_shape"
        ]
        assert len(invalid_shape_records) == 1, (
            f"expected exactly 1 packs.update_draft.invalid_shape log for {field}; "
            f"got {len(invalid_shape_records)}"
        )
        log_record = invalid_shape_records[0]
        assert getattr(log_record, "field", None) == field, (
            f"log record's extra.field={getattr(log_record, 'field', None)!r}; expected {field!r}"
        )
        assert getattr(log_record, "pack_id", None) == str(rec.id)
        # (c) fail-closed — row unchanged
        after = await store.load(rec.id)
        assert after == before
        # (d) no chain row
        assert await _count_chain_rows(engine) == chain_before

    async def test_update_draft_refused_field_name_NOT_in_exception_payload(
        self, store: PackRecordStore
    ) -> None:
        """Round 7 P2 #3 decision: ``PackRecordRefused.__init__`` signature
        is unchanged at ``(reason, *, state=None)``. The exception does
        NOT carry a failing-field attribute; field-name diagnostic
        surfaces ONLY via structured-log emission."""
        rec = _make_draft()
        await store.save_draft(rec)

        with pytest.raises(PackRecordRefused) as ei:
            await store.update_draft(
                pack_id=rec.id,
                updates={"manifest_digest": b"\x00" * 16},  # wrong length
                actor_id="canary-modifier",
            )
        # closed-enum reason carried
        assert ei.value.reason == "pack_record_update_field_invalid_shape"
        # NO `field` / `failing_field` / etc attribute on the exception
        assert not hasattr(ei.value, "field")
        assert not hasattr(ei.value, "failing_field")
        # state stays optional + None per the 7B.1 signature
        assert ei.value.state is None


# ===========================================================================
# Stage 4 — Atomic-UPDATE state-precondition (Step 3 + 4)
# ===========================================================================


class TestSprint7B2UpdateDraftStatePrecondition:
    """Per the plan's atomicity spec Steps 3-4: the atomic UPDATE has
    ``state = 'draft'`` in the WHERE clause; rowcount==0 disambiguates
    via follow-up SELECT into ``PackNotFound`` vs
    ``pack_record_update_non_draft_state``."""

    @pytest.mark.parametrize(
        "advance_transitions,expected_advanced_state",
        [
            (("submit",), "submitted"),
            (("submit", "claim"), "under_review"),
            (("submit", "claim", "approve"), "approved"),
            (("cancel_draft",), "withdrawn"),
            (("submit", "withdraw"), "withdrawn"),
        ],
    )
    async def test_update_draft_refuses_non_draft_state(
        self,
        store: PackRecordStore,
        engine: AsyncEngine,
        advance_transitions: tuple[str, ...],
        expected_advanced_state: str,
    ) -> None:
        """After any transition(s) advance the pack out of ``draft``,
        ``update_draft()`` refuses with
        ``pack_record_update_non_draft_state``. Parametrized over the
        first few legal advance paths to pin the contract holds across
        post-submit AND post-withdraw AND post-cancel_draft state."""
        rec = _make_draft()
        await store.save_draft(rec)
        for i, t in enumerate(advance_transitions):
            await store.transition(
                pack_id=rec.id,
                transition=t,  # type: ignore[arg-type]
                actor_id="advancer",
                tenant_id=None,
                evidence_pointer=None,
                request_id=f"req-advance-{i}",
            )
        assert await _read_pack_state(engine, rec.id) == expected_advanced_state
        chain_before = await _count_chain_rows(engine)
        before = await store.load(rec.id)

        with pytest.raises(PackRecordRefused) as ei:
            await store.update_draft(
                pack_id=rec.id,
                updates={"display_name": "Should Not Persist"},
                actor_id="canary-modifier",
            )
        assert ei.value.reason == "pack_record_update_non_draft_state"
        # The exception's optional ``state`` field carries the live
        # state we saw (so callers can dispatch on it for richer error
        # messages without re-loading the pack).
        assert ei.value.state == expected_advanced_state

        # No chain row, no mutation.
        assert await _count_chain_rows(engine) == chain_before
        after = await store.load(rec.id)
        assert after == before

    async def test_update_draft_pack_not_found(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """Missing pack — ``PackNotFound`` (NOT a ``PackRecordRefused``),
        carrying the pack_id."""
        unknown_id = uuid.uuid4()
        chain_before = await _count_chain_rows(engine)

        with pytest.raises(PackNotFound) as ei:
            await store.update_draft(
                pack_id=unknown_id,
                updates={"display_name": "Anything"},
                actor_id="canary-modifier",
            )
        assert ei.value.pack_id == unknown_id
        # No state created out of thin air.
        assert await _read_pack_state(engine, unknown_id) is None
        assert await _count_chain_rows(engine) == chain_before


# ===========================================================================
# Stage 5 — Genesis-state pattern — NO chain row emitted EVER
# ===========================================================================


class TestSprint7B2UpdateDraftNoChainRow:
    """The plan's invariant: ``update_draft`` mirrors ``save_draft``'s
    genesis-state pattern — neither emits a chain row. The pack is still
    in the pre-submit window where the audit chain has not yet started;
    the first chain event fires on the first ``transition()``. Pin this
    invariant across all success + refusal paths."""

    async def test_no_chain_row_emitted_on_happy_path(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        rec = _make_draft()
        await store.save_draft(rec)
        baseline = await _count_chain_rows(engine)

        # Multiple successful updates — chain count stays flat.
        for i in range(5):
            await store.update_draft(
                pack_id=rec.id,
                updates={"display_name": f"v{i}"},
                actor_id=f"actor-{i}",
            )
            assert await _count_chain_rows(engine) == baseline

    async def test_no_chain_row_emitted_on_any_refusal_path(
        self, store: PackRecordStore, engine: AsyncEngine
    ) -> None:
        """Every refusal path (allow-list, value-shape, non-draft-state,
        not-found) MUST leave the chain count untouched. Single
        regression test that exercises all four refusal modes in
        sequence."""
        rec = _make_draft()
        await store.save_draft(rec)
        baseline = await _count_chain_rows(engine)

        # (1) allow-list refusal
        with pytest.raises(PackRecordRefused):
            await store.update_draft(
                pack_id=rec.id,
                updates={"tenant_id": "x"},
                actor_id="a",
            )
        assert await _count_chain_rows(engine) == baseline

        # (2) value-shape refusal
        with pytest.raises(PackRecordRefused):
            await store.update_draft(
                pack_id=rec.id,
                updates={"manifest_digest": b"short"},
                actor_id="a",
            )
        assert await _count_chain_rows(engine) == baseline

        # (3) pack-not-found
        with pytest.raises(PackNotFound):
            await store.update_draft(
                pack_id=uuid.uuid4(),
                updates={"display_name": "x"},
                actor_id="a",
            )
        assert await _count_chain_rows(engine) == baseline

        # (4) non-draft-state — advance the pack then attempt update
        await store.transition(
            pack_id=rec.id,
            transition="submit",
            actor_id="advancer",
            tenant_id=None,
            evidence_pointer=None,
            request_id="req-advance-final",
        )
        post_advance_baseline = await _count_chain_rows(engine)
        assert post_advance_baseline == baseline + 1  # submit emitted ONE row
        with pytest.raises(PackRecordRefused):
            await store.update_draft(
                pack_id=rec.id,
                updates={"display_name": "x"},
                actor_id="a",
            )
        # Refusal path leaves count at post-advance baseline.
        assert await _count_chain_rows(engine) == post_advance_baseline


# ===========================================================================
# Stage 6 — _is_valid_update_value_shape() helper unit tests
# ===========================================================================


class TestSprint7B2UpdateValueShapeHelper:
    """The pure-Python value-shape validator helper. Independent
    coverage so test failures here surface as helper-shape bugs vs
    integration bugs in update_draft itself."""

    @pytest.mark.parametrize(
        "value",
        ["x", "x" * 256, "Pack Name with spaces", "a"],
    )
    def test_display_name_accepts_valid_strings(self, value: str) -> None:
        assert _is_valid_update_value_shape("display_name", value) is True

    @pytest.mark.parametrize(
        "value",
        ["", 42, None, b"bytes", "x" * 257, [], {}],
    )
    def test_display_name_refuses_invalid_values(self, value: Any) -> None:
        assert _is_valid_update_value_shape("display_name", value) is False

    @pytest.mark.parametrize("field", ["manifest_digest", "signed_artefact_digest"])
    def test_digests_accept_exactly_32_bytes(self, field: str) -> None:
        assert _is_valid_update_value_shape(field, b"\x00" * 32) is True
        assert _is_valid_update_value_shape(field, b"\xff" * 32) is True

    @pytest.mark.parametrize("field", ["manifest_digest", "signed_artefact_digest"])
    @pytest.mark.parametrize(
        "bad_value",
        [b"", b"\x00" * 31, b"\x00" * 33, "string-not-bytes", None, 42],
    )
    def test_digests_refuse_invalid_values(self, field: str, bad_value: Any) -> None:
        assert _is_valid_update_value_shape(field, bad_value) is False

    def test_sbom_pointer_accepts_none(self) -> None:
        assert _is_valid_update_value_shape("sbom_pointer", None) is True

    @pytest.mark.parametrize("value", ["s3://sboms/v1", "x", "https://example/sbom.json"])
    def test_sbom_pointer_accepts_nonempty_strings(self, value: str) -> None:
        assert _is_valid_update_value_shape("sbom_pointer", value) is True

    @pytest.mark.parametrize("bad_value", ["", 42, b"bytes", []])
    def test_sbom_pointer_refuses_invalid_values(self, bad_value: Any) -> None:
        assert _is_valid_update_value_shape("sbom_pointer", bad_value) is False

    def test_helper_refuses_unknown_field_defensively(self) -> None:
        """Defence-in-depth: even though Step 1's allow-list check should
        intercept unknown fields first, the helper itself returns False
        for any name outside the 4-field allow-list."""
        for unknown in ("tenant_id", "state", "kind", "pack_id", "created_by", "id"):
            assert _is_valid_update_value_shape(unknown, "anything") is False
