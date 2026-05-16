"""Sprint 7B.4 T10 — replay-then-live boundary regressions.

Per ADR-020 §60 + spec §4.3 + the locked cursor doctrine:
  - Reconnect via a cursor MUST NOT lose events between the cursor
    coordinate and the live tail
  - Boundary row dedup: for the cursor's own row, replay yields
    ordinals > cursor.ordinal (no duplicate delivery of the cursored
    event)
  - Cursor with sequence past chain tip → 422 ``cursor_not_found``
  - Cursor for a row owned by another tenant → 404 with the
    pack_not_found body shape (cross-tenant invisible)
  - Cursor whose ``type_hash`` differs from the projector's recomputed
    hash → 500 ``cursor_projection_drift_detected`` (fail-closed; the
    Pydantic model the projector emits has been renamed since the
    cursor was minted)
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.ui_events import UIEventBroker
from tests.unit.portal.api.ui.sse_test_helpers import (
    UvicornAppFactory,
    _async_client,
    _iter_sse_events,
    _next_sse_event,
    _real_client,
)


class TestReplayThenLiveBoundary:
    @pytest.mark.asyncio
    async def test_no_events_lost_on_reconnect(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
    ) -> None:
        """Cursor at row[2] (the typed event at ordinal 0) → expect
        replay to deliver row[3] + row[4] (each row produces a typed
        event at ordinal 0 plus a decision_audit mirror at ordinal 1;
        the test consumes 2 events to confirm row[3]'s typed event
        delivers immediately after the cursor's boundary row finishes
        its remaining ordinals)."""
        rows = []
        for n in range(5):
            r = await broker.append_frontend_action_submitted(
                request_id=f"portal-req-{n}",
                action_class="approve",
                actor_subject="u1",
                client_correlation_id=None,
                payload_digest=f"sha256:{n:02x}",
                tenant_id="t1",
            )
            rows.append(r)
        cursor = rows[2].event_id  # typed event at ordinal 0 of row[2]
        received_ids: list[str] = []
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream("GET", f"/api/v1/ui/events/since/{cursor}") as resp,
        ):
            # First event after cursor is the boundary row's ordinal 1
            # (decision_audit mirror); then row[3]'s ordinal 0; then
            # row[3]'s ordinal 1; etc. Use the single-walk iter helper
            # — calling _next_sse_event multiple times re-creates the
            # aiter_lines iterator + raises StreamConsumed.
            async for e in _iter_sse_events(resp, max_events=3):
                received_ids.append(e["id"])
        # Boundary row's ordinal 1 must arrive (NOT the typed event at
        # ordinal 0 which the cursor already saw).
        assert received_ids[0] != rows[2].event_id
        # Row[3]'s typed event (ordinal 0) MUST appear.
        assert rows[3].event_id in received_ids

    @pytest.mark.asyncio
    async def test_boundary_dedup_by_event_id(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
    ) -> None:
        """Threat-model-revert pin (per plan §4113): cursor at
        (sequence=N, ordinal=0) MUST NOT redeliver the ordinal=0 typed
        event; the next event yielded is the ordinal=1 decision_audit
        mirror for the same row."""
        r = await broker.append_frontend_action_submitted(
            request_id="portal-req-1",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:11",
            tenant_id="t1",
        )
        # r.event_id encodes ordinal=0 (the typed event)
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream("GET", f"/api/v1/ui/events/since/{r.event_id}") as resp,
        ):
            got = await asyncio.wait_for(_next_sse_event(resp), timeout=2.0)
        # The next event for the same row is the decision_audit mirror at ordinal 1.
        assert got["event"] == "decision_audit.event_appended"

    @pytest.mark.asyncio
    async def test_cursor_not_found_422(
        self, app: FastAPI, broker: UIEventBroker, actor_t1: Actor
    ) -> None:
        """Cursor with sequence beyond the chain tip refuses 422."""
        from cognic_agentos.protocol.ui_events import _chain_derived_event_id

        bogus_cursor = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=999_999_999,
            ordinal=0,
            family="frontend_action",
            type_="submitted",
        )
        async with _async_client(app) as c:
            r = await c.get(f"/api/v1/ui/events/since/{bogus_cursor}")
        assert r.status_code == 422
        assert r.json()["detail"]["reason"] == "cursor_not_found"

    @pytest.mark.asyncio
    async def test_cursor_tenant_mismatch_404_invisible(
        self, app: FastAPI, broker: UIEventBroker, actor_t1: Actor
    ) -> None:
        """Cross-tenant cursor returns 404 with the SAME body shape as
        the pack_not_found 404 — a probe cannot enumerate event_ids
        across tenants by comparing response shapes."""
        r_t2 = await broker.append_frontend_action_submitted(
            request_id="portal-req-t2",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:11",
            tenant_id="t2",
        )
        async with _async_client(app) as c:
            r = await c.get(f"/api/v1/ui/events/since/{r_t2.event_id}")
        assert r.status_code == 404
        assert r.json()["detail"]["reason"] == "pack_not_found"

    @pytest.mark.asyncio
    async def test_cursor_projection_drift_detected_500(
        self,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Threat-model-revert pin (per plan §4114): patch out the typed
        projector for ``frontend_action.submitted`` so the boundary row's
        type_hash recomputation in replay diverges from the cursor's
        encoded hash → 500 ``cursor_projection_drift_detected``."""
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-1",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:11",
            tenant_id="t1",
        )
        # Remove the typed projector so replay's projector returns None
        # at the boundary row → recomputed type_hash mismatches the
        # cursor's encoded hash → 500.
        from cognic_agentos.protocol import ui_events

        patched = {
            k: v
            for k, v in ui_events._DECISION_HISTORY_TYPED_PROJECTORS.items()
            if k != "frontend_action.submitted"
        }
        monkeypatch.setattr(ui_events, "_DECISION_HISTORY_TYPED_PROJECTORS", patched)
        async with _async_client(app) as c:
            r = await c.get(f"/api/v1/ui/events/since/{r_a.event_id}")
        assert r.status_code == 500
        assert r.json()["detail"]["reason"] == "cursor_projection_drift_detected"
