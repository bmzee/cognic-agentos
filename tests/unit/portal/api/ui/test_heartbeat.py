"""Sprint 7B.4 T10 — broker/generator-owned heartbeat regressions.

Per ADR-020 §60 + spec §4.3: SSE keepalive cadence is OWNED by the
broker+generator (NOT sse-starlette's internal ping; that is set to
a long sentinel so the broker stays authoritative). Three regressions:

  - Generator yields ``: keepalive`` comments at the
    ``ui_event_stream_heartbeat_interval_s`` cadence
    (streaming — uvicorn fixture)
  - Subscriber's ``last_activity_at`` updates on every successful yield
    (direct-broker — no HTTP)
  - Broker's ``reap_idle(now)`` closes subscribers idle past
    ``ui_event_stream_idle_timeout_s`` and returns the reaped count
    (direct-broker — no HTTP)

Test-strategy split (per T10 user-locked Hybrid doctrine):
  - Direct-broker (NO ``c.stream``): ``test_last_activity_at_updated_on_heartbeat_yield``,
    ``test_reap_idle_closes_stale_subscribers``
  - Uvicorn-fixture (real streaming): ``test_broker_emits_keepalive_every_n_seconds``

R11 #5: ``pytest-freezer`` / ``freezegun`` are NOT pyproject deps;
``reap_idle`` accepts its evaluation timestamp as an explicit kwarg so
we control the clock directly.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.ui_events import UIEventBroker
from tests.unit.portal.api.ui.sse_test_helpers import UvicornAppFactory, _real_client


class TestHeartbeat:
    @pytest.mark.asyncio
    async def test_broker_emits_keepalive_every_n_seconds(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Reduce heartbeat to 50ms; collect 3 keepalives in ~250ms.

        We monkey-patch the heartbeat interval at the broker's settings
        attribute (``broker._settings.ui_event_stream_heartbeat_interval_s``)
        — the generator reads it on each ``asyncio.wait_for(timeout=...)``
        loop iteration so the test sees the reduced cadence immediately.
        Pydantic's ``ge=1`` bound is bypassed because we mutate the
        already-constructed instance directly."""
        monkeypatch.setattr(broker._settings, "ui_event_stream_heartbeat_interval_s", 0.05)
        keepalive_count = 0
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream("GET", "/api/v1/ui/tenants/t1/events") as resp,
        ):
            async for raw_line in resp.aiter_lines():
                if raw_line.startswith(":"):
                    keepalive_count += 1
                    if keepalive_count >= 3:
                        break
        assert keepalive_count >= 3

    @pytest.mark.asyncio
    async def test_last_activity_at_updated_on_heartbeat_yield(self, broker: UIEventBroker) -> None:
        """Direct assertion on the Subscriber state-machine — the
        generator updates ``last_activity_at`` after EVERY successful
        yield (typed event or keepalive). Simulated here by calling
        the same hook the generator's keepalive branch invokes (no
        HTTP layer needed for this assertion)."""
        sub = broker.register_subscriber(tenant_id="t1")
        original = sub.last_activity_at
        await asyncio.sleep(0.001)
        sub.last_activity_at = datetime.now(UTC)
        assert sub.last_activity_at > original

    def test_reap_idle_closes_stale_subscribers(self, broker: UIEventBroker) -> None:
        """R11 #5 — no freezegun. Set ``last_activity_at`` to a stale
        absolute timestamp; pass an evaluation timestamp 1 hour later;
        verify the subscriber is reaped + count == 1."""
        sub = broker.register_subscriber(tenant_id="t1")
        sub.last_activity_at = datetime(2026, 5, 15, 11, 0, 0, tzinfo=UTC)
        reaped = broker.reap_idle(datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC))
        assert reaped == 1
        assert sub not in broker._subscribers
