"""Sprint 7B.4 T11 — POST /actions → SSE correlation-ordering contract.

**Causal-ordering proof** that the ``frontend_action.submitted`` event
the action handler appends reaches the SSE subscriber **before the
POST returns to the client**. Per ``protocol/ui_events.py``'s broker
contract the typed-projector hook fires synchronously inside the
awaited DH-store append; per spec §4.4i this synchronous-emit
invariant is the load-bearing path for the UI's optimistic-submit
reconciliation.

**2026-05-23 hardening (post-9.5b-merge incident):** this test
previously used ``asyncio.wait_for(timeout=0.2)`` as a wall-clock SLA;
the post-merge CI run ``26333142853`` on ``main`` surfaced the
underlying flake — a single GH-Actions-runner scheduler burst at the
SSE-generator / uvicorn flush layer pushed first-event arrival past
the 200ms deadline on otherwise-unchanged code (the same diff passed
the PR-side CI five minutes earlier on the same SHA family).

The hardened form uses ``asyncio.wait`` race semantics
(``FIRST_COMPLETED`` + event-task-must-be-in-done) to pin the
causal-ordering invariant directly. The race resolves in tens of
milliseconds under any realistic load; the assertion ONLY fires when
the POST genuinely finishes WITHOUT the typed event in flight — which
is the actual broken-invariant signature. Outer 5s timeout bounds
test runtime to prevent suite hangs; well above any realistic CI
latency.

Uses the uvicorn fixture (per the T10 user-locked Hybrid doctrine)
because the test opens a streaming SSE response — ASGITransport
buffers the full body before returning + would hang.
"""

from __future__ import annotations

import asyncio
import contextlib

import pytest
from fastapi import FastAPI

from tests.unit.portal.api.ui.sse_test_helpers import (
    UvicornAppFactory,
    _next_sse_event,
    _real_client,
)


class TestActionPOSTCorrelationEventReachesSubscriberBeforePOSTReturns:
    @pytest.mark.asyncio
    async def test_correlation_event_arrives_before_post_returns(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app_with_scopes_and_broker: FastAPI,
    ) -> None:
        """Subscribe SSE → fire POST → assert the typed event task wins
        (or ties) a race against the POST-completion task.

        The synchronous-emit invariant (file docstring + spec §4.4i +
        ``protocol/ui_events.py`` broker contract): the typed-projector
        hook fires SYNCHRONOUSLY inside the awaited DH-store append, so
        the event lands on the subscriber's queue BEFORE the POST
        handler returns its response.

        Race semantics (``asyncio.wait`` + ``FIRST_COMPLETED``):

        - ✓ done={event_task}, pending={post_task} — event arrived
          first; clean win for the synchronous-emit invariant.
        - ✓ done={event_task, post_task} — legitimate tie (both futures
          resolved in the same scheduler iteration before ``wait``
          regained control); ``event_task in done`` still holds so the
          assertion passes. Treating a tie as PASS accepts that uvicorn
          flushes the two parallel response paths on indistinguishable
          wall-clock ticks under normal load — a tie is NOT a contract
          violation.
        - ✗ done={post_task}, pending={event_task} — POST finished and
          the SSE event is STILL in flight. The synchronous-emit
          invariant is broken (or an upstream regression made the
          broker emit happen async-after-POST); assertion fires with a
          diagnostic message.

        The 5s outer timeout bounds runtime; under any realistic latency
        the race resolves in tens of milliseconds. Replaces the
        pre-hardening 200ms wall-clock SLA whose only flake mode was
        GH-runner scheduler bursts — NOT a broker-level regression.
        """
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
                ),
                name="post_task",
            )
            event_task = asyncio.create_task(
                _next_sse_event(sse),
                name="event_task",
            )
            try:
                done, pending = await asyncio.wait(
                    {event_task, post_task},
                    timeout=5.0,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                # The load-bearing invariant: SSE event reaches the
                # subscriber BEFORE the POST returns. ``FIRST_COMPLETED``
                # returns when AT LEAST one future completes; ``done``
                # may contain one OR both tasks. If only ``post_task`` is
                # in ``done`` at that moment, the event task is still
                # pending — the synchronous-emit invariant is broken. A
                # tie (both in ``done``) is acceptable: it means uvicorn
                # flushed both response paths within the same scheduler
                # iteration, which is NOT a contract violation.
                assert event_task in done, (
                    "POST returned before the typed event reached the "
                    "SSE subscriber — the synchronous typed-projector "
                    "emit invariant (test docstring + spec §4.4i + "
                    "protocol/ui_events.py broker contract) is broken. "
                    f"done={sorted(t.get_name() for t in done)}, "
                    f"pending={sorted(t.get_name() for t in pending)}"
                )
                event = event_task.result()
            finally:
                # Drain both tasks regardless of outcome — prevents
                # unawaited-task warnings + ensures both complete or
                # cancel cleanly before fixture teardown closes the SSE
                # stream and the uvicorn worker.
                if not post_task.done():
                    with contextlib.suppress(Exception):
                        await post_task
                if not event_task.done():
                    event_task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await event_task
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
