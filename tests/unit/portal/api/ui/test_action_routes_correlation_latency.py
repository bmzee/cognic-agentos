"""Sprint 7B.4 T11 — POST /actions → SSE correlation latency.

Deterministic ``asyncio.wait_for(timeout=0.2)`` proof that the
``frontend_action.submitted`` event the action handler appends reaches
an SSE subscriber within 200ms of the POST. Per spec §4.4i, the
correlation latency is the load-bearing path for the UI's optimistic-
submit reconciliation; the wait-for timeout pins it as a hard SLA
rather than a flaky P99-over-N test.

Uses the uvicorn fixture (per the T10 user-locked Hybrid doctrine)
because the test opens a streaming SSE response — ASGITransport
buffers the full body before returning + would hang.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI

from tests.unit.portal.api.ui.sse_test_helpers import (
    UvicornAppFactory,
    _next_sse_event,
    _real_client,
)


class TestActionPOSTCorrelationEventDeliveredWithin200ms:
    @pytest.mark.asyncio
    async def test_correlation_event_arrives_within_200ms(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app_with_scopes_and_broker: FastAPI,
    ) -> None:
        """Subscribe SSE → fire POST → assert the typed event arrives
        on the stream within 200ms.

        The SSE subscriber + the POST handler share the SAME broker
        instance (via the fixture-scope=function ``broker`` fixture);
        the typed-projector hook fires synchronously inside the awaited
        DH-store append, so the event lands on the subscriber's queue
        BEFORE the POST returns. The 200ms timeout bounds the
        in-process scheduling latency."""
        async with (
            uvicorn_app_factory(app_with_scopes_and_broker) as base_url,
            _real_client(base_url) as c,
            c.stream(
                "GET",
                "/api/v1/ui/tenants/t1/events?families=frontend_action",
            ) as sse,
        ):
            post_task = asyncio.create_task(
                c.post(
                    "/api/v1/ui/actions",
                    json={
                        "action_class": "approve",
                        "approval_id": "ap_1",
                        "decision": "grant",
                    },
                )
            )
            event = await asyncio.wait_for(_next_sse_event(sse), timeout=0.2)
            await post_task
        # ``_next_sse_event`` returns the SSE wrapper:
        #   event["event"]                — SSE event-name header
        #                                   ``"<family>.<type>"``
        #   event["data"]                 — parsed JSON of the SSE
        #                                   ``data:`` line (the full
        #                                   Pydantic typed-event after
        #                                   model_dump_json)
        #   event["data"]["data"]         — the business payload (from
        #                                   ``snapshot.payload`` per
        #                                   ``_project_frontend_action_submitted``)
        assert event["event"] == "frontend_action.submitted"
        assert event["data"]["family"] == "frontend_action"
        assert event["data"]["type"] == "submitted"
        assert event["data"]["data"]["action_class"] == "approve"
