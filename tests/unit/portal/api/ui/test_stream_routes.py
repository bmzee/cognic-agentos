"""Sprint 7B.4 T10 — basic SSE endpoint shape + RBAC + family filter.

Per ADR-020 §60-63 + spec §4.3 — three SSE GET endpoints, each gated
by a per-endpoint RBAC scope, each serving Wave-1 streamed families
only (audit-event-backed families like ``tool_call.*`` and ``artifact.*``
are filtered out at the broker — they live in the audit chain at
Wave 1 + ship via the Wave-2 audit-event SSE surface):

  - ``GET /api/v1/ui/runs/{run_id}/events`` — gated by ``ui.run_stream``
  - ``GET /api/v1/ui/tenants/{tenant_id}/events`` — gated by ``ui.tenant_stream``;
    cross-tenant returns 404 ``pack_not_found`` (cross-tenant invisible)
  - ``GET /api/v1/ui/events/since/{event_id}`` — gated by ``ui.tenant_stream``;
    replays from the cursor

A ``?families=`` query-param filter narrows the live tail to a subset
of the Wave-1 family set; unknown family names refuse 422
``family_filter_unknown``.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastapi import FastAPI

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.ui_events import UIEventBroker
from tests.unit.portal.api.ui.sse_test_helpers import (
    UvicornAppFactory,
    _async_client,
    _iter_sse_events,
    _next_sse_event,
    _real_client,
    emit_audit_tool_call_event,
    emit_test_policy_event_and_memory_event,
)


class TestEndpoint1RunStreamShape:
    @pytest.mark.asyncio
    async def test_run_stream_returns_text_event_stream(
        self, uvicorn_app_factory: UvicornAppFactory, app: FastAPI, actor_t1: Actor
    ) -> None:
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream("GET", "/api/v1/ui/runs/run_1/events") as r,
        ):
            assert r.status_code == 200
            assert r.headers["content-type"].startswith("text/event-stream")

    @pytest.mark.asyncio
    async def test_run_stream_rbac_required(self, app: FastAPI) -> None:
        """R9 #2 + R6 #4: swap ``app.state.actor_binder`` so the REAL
        ``_bind_actor`` runs and catches ``ActorBinderUnauthenticated``
        → maps to 403 + emits the ``policy.rbac_denied`` chain row
        (the code under test). Using
        ``app.dependency_overrides[_bind_actor]`` would BYPASS the
        dep entirely + skip the chain-row emit we're testing."""
        from cognic_agentos.portal.rbac.actor import ActorBinderUnauthenticated

        class _RaisesUnauthBinder:
            def bind(self, *, request):
                raise ActorBinderUnauthenticated("no token")

        original_binder = app.state.actor_binder
        app.state.actor_binder = _RaisesUnauthBinder()
        try:
            async with _async_client(app) as c:
                r = await c.get("/api/v1/ui/runs/run_1/events")
            assert r.status_code == 403
        finally:
            app.state.actor_binder = original_binder


class TestEndpoint2TenantStreamCrossTenant404:
    @pytest.mark.asyncio
    async def test_cross_tenant_returns_404_invisible(self, app: FastAPI, actor_t1: Actor) -> None:
        """A request for tenant t2 by an actor whose ``tenant_id`` is t1
        gets the SAME 404 body shape as ``pack_not_found`` — a probe
        cannot enumerate tenant_ids by response shape."""
        async with _async_client(app) as c:
            r = await c.get("/api/v1/ui/tenants/t2/events")
        assert r.status_code == 404
        assert r.json()["detail"]["reason"] == "pack_not_found"


class TestEndpoint3SinceCursorReplay:
    @pytest.mark.asyncio
    async def test_replay_then_live(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
    ) -> None:
        """Append 3 chain rows; subscribe with cursor=r1.event_id;
        expect r2 + r3's typed events in replay (each row also has an
        ordinal-1 decision_audit mirror; the iter helper collects 2
        events; the first event is the boundary row's ordinal-1
        mirror so we collect 4 events and assert the typed-event IDs
        appear in the collected set)."""
        r1 = await broker.append_frontend_action_submitted(
            request_id="portal-req-1",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:11",
            tenant_id="t1",
        )
        r2 = await broker.append_frontend_action_submitted(
            request_id="portal-req-2",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:22",
            tenant_id="t1",
        )
        r3 = await broker.append_frontend_action_submitted(
            request_id="portal-req-3",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:33",
            tenant_id="t1",
        )
        events_received: list[dict[str, Any]] = []
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream("GET", f"/api/v1/ui/events/since/{r1.event_id}") as resp,
        ):
            # Collect 4 events: r1's ordinal-1 mirror + r2's typed +
            # r2's mirror + r3's typed (then break before live tail).
            async for chunk in _iter_sse_events(resp, max_events=4):
                events_received.append(chunk)
        ids = [e["id"] for e in events_received]
        # Both subsequent rows' typed event_ids MUST appear in replay
        # (the boundary row's typed event ALREADY seen at the cursor
        # coordinate is NOT redelivered — see test_boundary_dedup).
        assert r2.event_id in ids
        assert r3.event_id in ids
        # Cursored row's typed event MUST NOT appear (dedup).
        assert r1.event_id not in ids


class TestFamilyFilter:
    @pytest.mark.asyncio
    async def test_families_query_param_filters_replay_and_live(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
    ) -> None:
        # Use endpoint 2 (``/tenants/{tenant_id}/events``) NOT
        # endpoint 1 (``/runs/{run_id}/events``) — the helper
        # ``emit_test_policy_event_and_memory_event`` emits a
        # ``policy.rbac_denied`` event with ``run_id=None`` (per the
        # canonical RBAC-denial shape); the broker's subscriber filter
        # ``run_id_filter != event.run_id`` rejects None-run_id events
        # on endpoint-1 subscribers. Endpoint 2 has no run_id filter
        # so the family-filter behavior is observable in isolation.
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream(
                "GET",
                "/api/v1/ui/tenants/t1/events?families=frontend_action,policy",
            ) as resp,
        ):
            await emit_test_policy_event_and_memory_event(broker)
            got = await asyncio.wait_for(_next_sse_event(resp), timeout=2.0)
        assert got["event"].startswith("policy.") or got["event"].startswith("frontend_action.")

    @pytest.mark.asyncio
    async def test_family_filter_unknown_422(self, app: FastAPI, actor_t1: Actor) -> None:
        async with _async_client(app) as c:
            r = await c.get("/api/v1/ui/runs/run_1/events?families=bogus")
        assert r.status_code == 422
        assert r.json()["detail"]["reason"] == "family_filter_unknown"


class TestTenantConnectionCapExceeded:
    @pytest.mark.asyncio
    async def test_429_when_per_tenant_cap_hit(
        self, uvicorn_app_factory: UvicornAppFactory, app_low_cap: FastAPI, actor_t1: Actor
    ) -> None:
        """Per plan §3475-3479: use ``app_low_cap`` (NOT ``app`` +
        parameter ``settings_low_cap``) — the latter would resolve
        settings_low_cap as a sibling fixture but the broker mounted
        in ``app`` was built from the DEFAULT ``settings`` (cap=50)
        so the second stream would never 429. ``app_low_cap``
        re-roots both ``create_app`` AND ``build_stream_routes
        (broker=)`` at settings_low_cap (cap=1) so the cap actually
        fires."""
        async with (
            uvicorn_app_factory(app_low_cap) as base_url,
            _real_client(base_url) as c,
            c.stream("GET", "/api/v1/ui/tenants/t1/events"),
        ):
            # First stream is still open via the c.stream context;
            # the second request from the same client hits the
            # per-tenant cap (cap=1) and refuses 429.
            r2 = await c.get("/api/v1/ui/tenants/t1/events")
        assert r2.status_code == 429
        assert r2.json()["detail"]["reason"] == "tenant_connection_cap_exceeded"


class TestAuditBackedFamiliesExcludedFromSSE:
    """Wave-1 SSE = decision-history-only. ``tool_call.*`` and
    ``artifact.*`` events live in the audit chain and never reach SSE
    subscribers — the broker's family filter rejects them at the dispatch
    boundary."""

    @pytest.mark.asyncio
    async def test_tool_call_event_not_delivered_to_sse(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        audit_store: AuditStore,
        actor_t1: Actor,
    ) -> None:
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream("GET", "/api/v1/ui/tenants/t1/events") as resp,
        ):
            await emit_audit_tool_call_event(audit_store, tenant_id="t1")
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(_next_sse_event(resp), timeout=0.3)
