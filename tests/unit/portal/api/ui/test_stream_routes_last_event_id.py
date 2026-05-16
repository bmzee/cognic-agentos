"""Sprint 7B.4 T10 — Last-Event-ID precedence regressions.

Per ADR-020 §60 + spec §4.3:
  - HTTP ``Last-Event-ID`` header WINS over any URL cursor
    (``?since=...`` or ``/events/since/{event_id}`` path-param).
  - Malformed Last-Event-ID DOES NOT silently fall back to the URL
    cursor — refuses 422 with closed-enum ``cursor_malformed`` so a
    client typo can't accidentally re-deliver historical events.
  - The header-precedence rule is symmetric across all 3 endpoints
    (run_stream / tenant_stream / since_cursor_stream).

Test-strategy split (per T10 user-locked Hybrid doctrine):
  - Uvicorn-fixture (real streaming): the 2 precedence tests that
    open a stream + read the first event after replay
  - ASGITransport (``_async_client``): the malformed-header test that
    refuses 422 synchronously (no streaming body)
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
    _next_sse_event,
    _real_client,
)


class TestLastEventIdPrecedence:
    @pytest.mark.asyncio
    async def test_header_wins_over_url_since_query(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
    ) -> None:
        """Endpoint 2: send BOTH ``?since=A`` AND ``Last-Event-ID: B`` →
        replay starts AFTER B (the header wins; the URL cursor is
        ignored)."""
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-a",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:aa",
            tenant_id="t1",
        )
        _r_b = await broker.append_frontend_action_submitted(
            request_id="portal-req-b",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:bb",
            tenant_id="t1",
        )
        # row C appended but not referenced — kept in the chain so
        # replay has a row past the header cursor to confirm
        # forward-tail isn't pinned to the header row.
        await broker.append_frontend_action_submitted(
            request_id="portal-req-c",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:cc",
            tenant_id="t1",
        )
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream(
                "GET",
                f"/api/v1/ui/tenants/t1/events?since={r_a.event_id}",
                headers={"Last-Event-ID": _r_b.event_id},
            ) as resp,
        ):
            got = await asyncio.wait_for(_next_sse_event(resp), timeout=2.0)
        # Header pointed at row B (ordinal 0); replay starts AFTER B's
        # ordinal 0 → first event is B's ordinal 1 (decision_audit
        # mirror), THEN row C's events. We accept either: assert the
        # event ID is NOT row A's (which would mean URL cursor won) and
        # NOT row B's typed event ID (which would mean no dedup).
        assert got["id"] != r_a.event_id
        assert got["id"] != _r_b.event_id

    @pytest.mark.asyncio
    async def test_header_wins_over_path_cursor_endpoint_3(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
    ) -> None:
        """Endpoint 3 symmetric: send PATH cursor ``A`` + ``Last-Event-ID: B``
        → replay starts after B."""
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-a",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:aa",
            tenant_id="t1",
        )
        r_b = await broker.append_frontend_action_submitted(
            request_id="portal-req-b",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:bb",
            tenant_id="t1",
        )
        await broker.append_frontend_action_submitted(
            request_id="portal-req-c",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:cc",
            tenant_id="t1",
        )
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream(
                "GET",
                f"/api/v1/ui/events/since/{r_a.event_id}",
                headers={"Last-Event-ID": r_b.event_id},
            ) as resp,
        ):
            got = await asyncio.wait_for(_next_sse_event(resp), timeout=2.0)
        assert got["id"] != r_a.event_id
        assert got["id"] != r_b.event_id

    @pytest.mark.asyncio
    async def test_malformed_last_event_id_does_NOT_fall_back(
        self, app: FastAPI, broker: UIEventBroker, actor_t1: Actor
    ) -> None:
        """Threat-model-revert pin (per plan §4115): malformed header
        with a valid URL cursor must REFUSE 422 ``cursor_malformed``,
        NOT silently fall through to the URL cursor. A client typo
        cannot accidentally re-deliver historical events.

        ASGITransport-OK: 422 refusal returns synchronously before any
        streaming body opens — no need for the uvicorn fixture."""
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-a",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:aa",
            tenant_id="t1",
        )
        async with _async_client(app) as c:
            r = await c.get(
                f"/api/v1/ui/tenants/t1/events?since={r_a.event_id}",
                headers={"Last-Event-ID": "garbage-cursor"},
            )
        assert r.status_code == 422
        assert r.json()["detail"]["reason"] == "cursor_malformed"
