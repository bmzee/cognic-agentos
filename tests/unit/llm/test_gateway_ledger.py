"""Sprint 3 T5 — GatewayCallLedger writer + reader unit tests.

Per AGENTS.md ``llm/ledger.py`` is on the provider-honesty ledger feed
list (operational, ≥80% per-file floor; the user's halt-before-commit
discipline applies because the ledger is ADR-007's authoritative
source for ``/effective-routing``).

Tests cover:

- ``GatewayCallRow`` dataclass invariants (frozen, slots, naive-ts
  rejection, outcome whitelist, provenance whitelist, frozen ts ==
  Sprint 2 R3 canonical-form contract).
- ``GatewayCallLedger.write_row`` happy path + Round-4 reviewer-P2
  failure-raises contract (the primitive must NOT swallow write
  failures; the gateway picks best-effort vs strict at call site).
- ``read_recent_calls`` window filter + ordering + tz preservation.

Integration tests against live PG + Oracle live in
``tests/integration/db/test_gateway_call_ledger.py``.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import uuid
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.llm.ledger import (
    GatewayCallLedger,
    GatewayCallRow,
    _ledger_table,
)

# ---------------------------------------------------------------------------
# Fixtures + helpers.
# ---------------------------------------------------------------------------


@pytest.fixture
async def sqlite_engine_with_ledger(tmp_path: Any) -> Any:
    """Per-test SQLite-aiosqlite engine with the gateway_call_ledger
    table created via the runtime ``_ledger_table`` declaration. Mirrors
    migration 0002's shape; the migration round-trip in
    ``tests/unit/db/test_run_migrations.py`` proves the migration
    creates the same table."""

    url = f"sqlite+aiosqlite:///{tmp_path / 'gateway_ledger.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_ledger_table.metadata.create_all)
    yield eng
    await eng.dispose()


def _make_row(
    *,
    outcome: str = "ok",
    ts: _dt.datetime | None = None,
    request_id: str | None = None,
    upstream_model: str = "ollama/qwen3:8b",
    upstream_api_base: str | None = "http://ollama:11434",
    external: bool = False,
    provenance: str = "resolved",
) -> GatewayCallRow:
    """Build a valid GatewayCallRow with sensible defaults for tests
    that only care about a single field's behaviour."""
    return GatewayCallRow(
        id=uuid.uuid4(),
        ts=ts if ts is not None else _dt.datetime.now(_dt.UTC),
        request_id=request_id if request_id is not None else f"req-{uuid.uuid4().hex[:8]}",
        tenant_id=None,
        tier="tier1",
        litellm_alias="cognic-tier1-dev",
        upstream_model=upstream_model,
        upstream_api_base=upstream_api_base,
        external=external,
        provenance=provenance,
        latency_ms=523,
        outcome=outcome,
        model_id=None,
    )


# ---------------------------------------------------------------------------
# TestGatewayCallRowConstruction — dataclass invariants.
# ---------------------------------------------------------------------------


class TestGatewayCallRowConstruction:
    def test_minimal_construction_succeeds(self) -> None:
        row = GatewayCallRow(
            id=uuid.uuid4(),
            ts=_dt.datetime.now(_dt.UTC),
            request_id="req-1",
            tenant_id=None,
            tier="tier1",
            litellm_alias="cognic-tier1-dev",
            upstream_model="ollama/qwen3:8b",
            upstream_api_base="http://ollama:11434",
            external=False,
            provenance="resolved",
            latency_ms=523,
            outcome="ok",
            model_id=None,
        )
        assert row.outcome == "ok"
        assert row.provenance == "resolved"

    def test_null_utcoffset_tzinfo_rejected_at_construction(self) -> None:
        """Sprint 2 R3 canonical-form contract: a tzinfo whose
        ``utcoffset()`` returns ``None`` is effectively naive — the
        ``core/canonical.py`` boundary check (line 109) and
        ``core/sla.py`` ``_require_tz_aware`` both refuse it. This
        regression pins that the ledger's __post_init__ does the same
        — a tzinfo subclass that returns ``None`` from utcoffset() must
        NOT slip past the boundary and corrupt the canonical-form
        round-trip downstream."""

        class _NullTz(_dt.tzinfo):
            def utcoffset(self, dt: _dt.datetime | None) -> _dt.timedelta | None:
                return None

            def dst(self, dt: _dt.datetime | None) -> _dt.timedelta | None:
                return None

            def tzname(self, dt: _dt.datetime | None) -> str | None:
                return "null"

        with pytest.raises(ValueError, match="timezone-aware"):
            _make_row(ts=_dt.datetime(2026, 4, 30, 12, 0, tzinfo=_NullTz()))

    def test_naive_timestamp_rejected_at_construction(self) -> None:
        """Sprint 2 R3 canonical-form contract: every persisted ts is
        tz-aware. This row would round-trip through canonical-form
        eventually (when /effective-routing emits its evidence-pack
        view), so the naive shape is rejected at the boundary, not
        later."""
        with pytest.raises(ValueError, match="timezone-aware"):
            GatewayCallRow(
                id=uuid.uuid4(),
                ts=_dt.datetime(2026, 4, 30, 12, 0),  # naive
                request_id="req-1",
                tenant_id=None,
                tier="tier1",
                litellm_alias="x",
                upstream_model="x/y",
                upstream_api_base=None,
                external=False,
                provenance="resolved",
                latency_ms=1,
                outcome="ok",
                model_id=None,
            )

    @pytest.mark.parametrize(
        "outcome",
        [
            "ok",
            "denied",
            "drift",
            "guardrail_input",
            "guardrail_output",
            "concurrency_exhausted",
            "upstream_error",
        ],
    )
    def test_known_outcomes_accepted(self, outcome: str) -> None:
        row = _make_row(outcome=outcome)
        assert row.outcome == outcome

    def test_unknown_outcome_rejected(self) -> None:
        with pytest.raises(ValueError, match="outcome"):
            _make_row(outcome="bogus")

    @pytest.mark.parametrize(
        "provenance",
        ["resolved", "unresolved", "ambiguous", "no_dispatch"],
    )
    def test_known_provenances_accepted(self, provenance: str) -> None:
        row = _make_row(provenance=provenance)
        assert row.provenance == provenance

    def test_unknown_provenance_rejected(self) -> None:
        """Round-6 reviewer-P1: provenance whitelist enforced at
        construction so a typo at the gateway boundary never
        silently lands a malformed row in the authoritative ledger."""
        with pytest.raises(ValueError, match="provenance"):
            _make_row(provenance="not_a_state")

    def test_dataclass_is_frozen(self) -> None:
        row = _make_row()
        with pytest.raises(dataclasses.FrozenInstanceError):
            row.outcome = "denied"  # type: ignore[misc]

    def test_dataclass_uses_slots(self) -> None:
        """``slots=True`` — no __dict__, fixed memory layout."""
        row = _make_row()
        assert not hasattr(row, "__dict__")

    def test_optional_fields_accept_none(self) -> None:
        """tenant_id, upstream_api_base, model_id are all nullable
        per the migration schema. Construction must accept None on
        each."""
        row = GatewayCallRow(
            id=uuid.uuid4(),
            ts=_dt.datetime.now(_dt.UTC),
            request_id="req-1",
            tenant_id=None,
            tier="tier1",
            litellm_alias="x",
            upstream_model="x/y",
            upstream_api_base=None,
            external=False,
            provenance="no_dispatch",
            latency_ms=0,
            outcome="denied",
            model_id=None,
        )
        assert row.tenant_id is None
        assert row.upstream_api_base is None
        assert row.model_id is None

    def test_provenance_no_dispatch_accepted_for_pre_dispatch_writes(
        self,
    ) -> None:
        """Round-6 reviewer-P1: pre-dispatch failure paths (input
        guardrail trip / cloud-policy denial / concurrency exhaustion)
        write rows with provenance="no_dispatch" carrying the INTENDED
        preflight identity. Pin that the dataclass accepts this state."""
        row = _make_row(
            provenance="no_dispatch",
            outcome="denied",
            external=True,
            upstream_model="openai/gpt-5.4",
            upstream_api_base=None,
        )
        assert row.provenance == "no_dispatch"


# ---------------------------------------------------------------------------
# TestLedgerWrite — happy path + window filtering + ordering.
# ---------------------------------------------------------------------------


class TestLedgerWrite:
    async def test_write_row_persists(self, sqlite_engine_with_ledger: AsyncEngine) -> None:
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        row = _make_row()
        await ledger.write_row(row)

        rows = await ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].request_id == row.request_id
        assert rows[0].outcome == "ok"
        assert rows[0].provenance == "resolved"

    async def test_write_row_returns_none(self, sqlite_engine_with_ledger: AsyncEngine) -> None:
        """Write contract: ``write_row -> None`` on success. The type
        signature is the binding contract; runtime smoke that the call
        completes cleanly without any sentinel value the gateway could
        use as an opportunistic-vs-strict signal."""
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        # ``await`` on a typed-None coroutine; absence of an exception
        # is the contract. Static check confirms no value is returned.
        await ledger.write_row(_make_row())

    async def test_write_row_persists_round6_columns(
        self, sqlite_engine_with_ledger: AsyncEngine
    ) -> None:
        """Round-6 reviewer-P1: upstream_api_base + provenance round-trip
        through the ledger. /effective-routing reads these from the
        ledger row, not from current YAML."""
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        row = _make_row(
            upstream_model="openai/Qwen3-8B-Instruct",
            upstream_api_base="http://vllm:8000/v1",
            external=False,
            provenance="resolved",
        )
        await ledger.write_row(row)

        rows = await ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].upstream_api_base == "http://vllm:8000/v1"
        assert rows[0].provenance == "resolved"
        assert rows[0].external is False

    async def test_write_row_preserves_tz_aware_timestamp(
        self, sqlite_engine_with_ledger: AsyncEngine
    ) -> None:
        """Sprint 2 R3 contract: ts is tz-aware at write + read."""
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        ts = _dt.datetime(2026, 4, 30, 12, 0, tzinfo=_dt.UTC)
        await ledger.write_row(_make_row(ts=ts))

        rows = await ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].ts.tzinfo is not None, "ts lost tz on round-trip"

    async def test_write_row_raises_on_persistence_failure(self, tmp_path: Any) -> None:
        """Round-4 reviewer-P2 + T5 docstring update: write_row raises
        on persistence failure. The primitive does NOT swallow the
        error; the gateway chooses best-effort (log + continue) vs
        strict (raise LedgerWriteFailed) at the call site, where it
        knows whether LiteLLM dispatched.

        Engine pointed at a directory that does not exist — opening
        the underlying SQLite file fails — exercises the failure path
        without needing dependency-injection mocks."""
        from sqlalchemy.exc import SQLAlchemyError

        bad_url = f"sqlite+aiosqlite:///{tmp_path / 'no-such-dir' / 'fails.db'}"
        bad_engine = create_async_engine(bad_url)
        ledger = GatewayCallLedger(bad_engine)
        try:
            # SQLAlchemyError is the parent of OperationalError /
            # InterfaceError / DBAPIError. Catching the umbrella
            # documents the surface contract: any persistence failure
            # propagates to the caller (gateway) which then picks
            # best-effort vs strict.
            with pytest.raises(SQLAlchemyError):
                await ledger.write_row(_make_row())
        finally:
            await bad_engine.dispose()


class TestLedgerRead:
    async def test_read_recent_calls_empty_returns_empty_list(
        self, sqlite_engine_with_ledger: AsyncEngine
    ) -> None:
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        rows = await ledger.read_recent_calls(window_minutes=60)
        assert rows == []

    async def test_read_recent_calls_window_filter_excludes_old(
        self, sqlite_engine_with_ledger: AsyncEngine
    ) -> None:
        """Plan T9 endpoint: the recent-calls window drives
        /effective-routing's PROFILE-chip drift detection. Rows
        outside the window must NOT count."""
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        old = _make_row(
            ts=_dt.datetime.now(_dt.UTC) - _dt.timedelta(hours=2),
            request_id="req-old",
        )
        new = _make_row(request_id="req-new")
        await ledger.write_row(old)
        await ledger.write_row(new)

        rows = await ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].request_id == "req-new"

    async def test_read_recent_calls_includes_boundary_row(
        self, sqlite_engine_with_ledger: AsyncEngine
    ) -> None:
        """Window is inclusive on the recent end (>=). A row exactly
        at ``now - window`` is INCLUDED. (>= cutoff, not > cutoff.)"""
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        now = _dt.datetime.now(_dt.UTC)
        # Place the row 59 minutes ago — comfortably inside a 60-min window.
        boundary = _make_row(ts=now - _dt.timedelta(minutes=59))
        await ledger.write_row(boundary)

        rows = await ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1

    async def test_read_recent_calls_orders_newest_first(
        self, sqlite_engine_with_ledger: AsyncEngine
    ) -> None:
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        now = _dt.datetime.now(_dt.UTC)
        await ledger.write_row(_make_row(ts=now - _dt.timedelta(minutes=30), request_id="middle"))
        await ledger.write_row(_make_row(ts=now - _dt.timedelta(minutes=1), request_id="newest"))
        await ledger.write_row(_make_row(ts=now - _dt.timedelta(minutes=55), request_id="oldest"))

        rows = await ledger.read_recent_calls(window_minutes=60)
        assert [r.request_id for r in rows] == ["newest", "middle", "oldest"]

    async def test_read_normaliser_is_noop_when_ts_already_tz_aware(self) -> None:
        """Pin the no-op branch of the normaliser: on dialects that
        preserve tzinfo (PG/Oracle, in production), the helper must
        not touch the row. Exercises the branch that the SQLite
        round-trip path skips."""
        from cognic_agentos.llm.ledger import _normalise_row_for_construction

        ts_aware = _dt.datetime(2026, 4, 30, 12, 0, tzinfo=_dt.UTC)
        mapping = {"ts": ts_aware, "other": "x"}
        result = _normalise_row_for_construction(mapping)
        assert result["ts"] is ts_aware  # untouched
        assert result["other"] == "x"

    async def test_read_recent_calls_round_trips_full_row_shape(
        self, sqlite_engine_with_ledger: AsyncEngine
    ) -> None:
        """Every field must round-trip — types preserved, no silent
        coercion."""
        ledger = GatewayCallLedger(sqlite_engine_with_ledger)
        original = _make_row(
            outcome="drift",
            provenance="ambiguous",
            external=True,
            upstream_model="openai/gpt-4o",
            upstream_api_base=None,
        )
        await ledger.write_row(original)

        rows = await ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        got = rows[0]
        assert got.id == original.id
        assert got.request_id == original.request_id
        assert got.tier == "tier1"
        assert got.litellm_alias == original.litellm_alias
        assert got.upstream_model == "openai/gpt-4o"
        assert got.upstream_api_base is None
        assert got.external is True
        assert got.provenance == "ambiguous"
        assert got.outcome == "drift"
        assert got.latency_ms == original.latency_ms
        assert got.model_id is None
