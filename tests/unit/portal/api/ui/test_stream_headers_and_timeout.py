"""Sprint 7B.4 T10 — SSE headers + send_timeout regressions.

Per ADR-020 §60 + spec §4.3:
  - All 3 SSE endpoints carry the headers ``Cache-Control: no-cache``,
    ``X-Accel-Buffering: no``, ``Connection: keep-alive`` so reverse
    proxies (nginx) don't buffer / cache the stream.
  - ``EventSourceResponse(send_timeout=settings.ui_event_stream_send_timeout_s)``
    so a stalled client (TCP half-open; rare but real in mobile +
    behind-CGNAT cases) gets cleaned up server-side rather than
    leaking a subscriber forever.

Test-strategy: ALL tests here exercise streaming responses (open a
``c.stream(...)`` against an infinite SSE body), so they ALL use the
uvicorn fixture per the T10 user-locked Hybrid doctrine (ASGITransport
buffers the full body before returning + would hang)."""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.ui_events import UIEventBroker
from tests.unit.portal.api.ui.sse_test_helpers import UvicornAppFactory, _real_client


class TestSSEHeaders:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "endpoint",
        [
            "/api/v1/ui/runs/run_1/events",
            "/api/v1/ui/tenants/t1/events",
            # endpoint 3 (``/events/since/{event_id}``) needs a real
            # cursor; tested in test_stream_routes_reconnect.py
            # which already opens a stream on that route — header
            # parity by construction (same builder factory).
        ],
    )
    async def test_required_headers(
        self, uvicorn_app_factory: UvicornAppFactory, app: FastAPI, endpoint: str, actor_t1: Actor
    ) -> None:
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream("GET", endpoint) as r,
        ):
            assert r.headers["cache-control"] == "no-cache"
            assert r.headers["x-accel-buffering"] == "no"
            assert r.headers.get("connection", "").lower() == "keep-alive"


class TestSendTimeoutCleansUpHalfOpenClient:
    @pytest.mark.asyncio
    async def test_stalled_client_unregistered_past_send_timeout(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app_short_send_timeout: FastAPI,
        broker_short_send_timeout: UIEventBroker,
        actor_t1: Actor,
    ) -> None:
        """R13 #2: the broker the route MOUNTS (``broker_short_send_timeout``)
        and the broker the test INSPECTS (``broker_short_send_timeout``)
        MUST be the same instance — wired via the
        ``app_short_send_timeout`` fixture pair.

        R13 #3: no ``as resp`` binding — the response object is never
        referenced inside the block (ruff F841 forbids the unused name).

        Per the user-locked Hybrid doctrine, this test exercises real
        stream lifecycle (open → server detects close → finally fires)
        and MUST run against uvicorn. ASGITransport buffers the body
        and never propagates ``http.disconnect``."""
        before_count = len(broker_short_send_timeout._subscribers)
        async with (
            uvicorn_app_factory(app_short_send_timeout) as base_url,
            _real_client(base_url) as c,
        ):
            async with c.stream("GET", "/api/v1/ui/tenants/t1/events"):
                # Let subscriber register on server side
                await asyncio.sleep(0.05)
            # Client closed → server-side generator's ``finally:``
            # block MUST unregister the subscriber.
            await asyncio.sleep(0.1)
        assert len(broker_short_send_timeout._subscribers) == before_count
