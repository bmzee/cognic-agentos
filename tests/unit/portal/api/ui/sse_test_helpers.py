"""Sprint 7B.4 T6 — plain helper functions used by T6 RBAC tests + the
T10/T11/T12 SSE / action / well-known tests.

NOT fixtures — imported explicitly per pytest's documented behavior
(plain callables in conftest.py do NOT auto-inject into test module
globals; only fixtures requested as test parameters are). Test files
import via the cross-directory absolute path:

    from tests.unit.portal.api.ui.sse_test_helpers import (
        _async_client, _next_sse_event, _read_recent_decision_history_rows, ...
    )

This module ships at T6 (per the R6 #1 task-ordering fix in the
plan-of-record) so the T6 RBAC conftest's cross-directory import
resolves at T6 execution time, NOT only after T10 ships. T10/T11/T12
reuse this module unchanged — no extension.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.ui_events import UIEventBroker


class _FixtureActorBinder:
    """Sync ActorBinder returning a fixture-provided actor.

    Preserves the sync `ActorBinder.bind` Protocol contract (T6 P1 #4)
    so the real `_bind_actor` wrapper exercises its sync-call path
    even under test."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Any) -> Actor:
        return self._actor


def _async_client(app: Any, *, base_url: str = "http://t") -> httpx.AsyncClient:
    """ASGI transport wrapper for httpx 0.28+.

    httpx 0.28 dropped the legacy `AsyncClient(app=app, ...)` shortcut;
    callers must wrap the ASGI app in `httpx.ASGITransport` and pass
    it as the `transport=` kwarg. Verified against `uv.lock` httpx
    pin (>=0.28) and the repo's existing httpx usage convention.
    Centralising the wrapping here keeps test bodies terse:

        async with _async_client(app) as c:
            r = await c.get("/api/v1/...")
    """
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base_url)


async def _next_sse_event(response: httpx.Response) -> dict[str, Any]:
    """Parse the next ServerSentEvent off a streaming httpx response.

    Returns the SSE wrapper as `{id, event, data}` where `event` is the
    SSE event-name header (`"<family>.<type>"`) and `data` is the parsed
    JSON payload of the `data:` line. Skips comment lines (`: keepalive`
    heartbeats). Raises RuntimeError if the stream ends without a
    complete event."""
    pending: dict[str, str] = {}
    async for raw in response.aiter_lines():
        if raw.startswith(":"):
            continue
        if raw == "":
            if "data" in pending:
                return {
                    "id": pending.get("id"),
                    "event": pending.get("event"),
                    "data": json.loads(pending["data"]),
                }
            pending = {}
            continue
        if ":" in raw:
            key, _, val = raw.partition(":")
            pending[key.strip()] = val.lstrip(" ")
    raise RuntimeError("SSE stream ended without an event")


async def _iter_sse_events(
    response: httpx.Response, *, max_events: int
) -> AsyncIterator[dict[str, Any]]:
    """Yield up to max_events ServerSentEvents off `response`."""
    for _ in range(max_events):
        yield await _next_sse_event(response)


async def _read_recent_decision_history_rows(broker_or_app: Any) -> list[Any]:
    """Direct SQLAlchemy read of the 50 most-recent `_decision_history`
    rows (newest-first by sequence).

    Returns raw SQLAlchemy Row objects — callers read `row.event_type`,
    `row.tenant_id`, `row.payload`, etc. (Note: SQL column is `event_type`,
    NOT `decision_type` — `decision_type` is the `DecisionRecord` dataclass
    field, mapped to the `event_type` column at write time per the
    7B.4 R4 #1 doctrine.)

    Accepts either a FastAPI app (reads `app.state.decision_history_store`)
    or a broker (reads `broker._history`); both paths terminate at the
    same `AsyncEngine`."""
    from fastapi import FastAPI
    from sqlalchemy import select

    from cognic_agentos.core.decision_history import _decision_history

    if isinstance(broker_or_app, FastAPI):
        engine = broker_or_app.state.decision_history_store._engine
    else:
        engine = broker_or_app._history._engine
    async with engine.begin() as conn:
        result = await conn.execute(
            select(_decision_history).order_by(_decision_history.c.sequence.desc()).limit(50)
        )
        return list(result.fetchall())


async def emit_test_policy_event_and_memory_event(broker: UIEventBroker) -> None:
    """Helper for the T10 family-filter regression — emits a
    `policy.rbac_denied` chain event via the broker's standard seam.
    Tests MUST `await` this — the broker append seam is async."""
    await broker.emit_rbac_denial(
        denial_type="scope_not_held",
        actor_subject="u_test",
        tenant_id="t1",
        request_id="portal-req-test-policy",
        http_status=403,
        required_scope="ui.action.approve",
    )


async def emit_audit_tool_call_event(audit_store: AuditStore, *, tenant_id: str) -> None:
    """Helper for the T10 Wave-1-SSE family-filter regression —
    appends a synthetic `tool_call.started` event to the audit chain
    so the test can assert audit-backed events DO NOT reach SSE
    subscribers (Wave-1 SSE = decision-history-only).

    `AuditStore.append` takes a single `AuditEvent` object (not kwargs);
    `AuditEvent` has no `actor_subject` field — actor identity travels
    inside `payload`. Fixed test request_id so the family-filter
    regression can assert on the row by request_id."""
    await audit_store.append(
        AuditEvent(
            event_type="tool_call.started",
            request_id="portal-req-test-tool-call",
            tenant_id=tenant_id,
            payload={
                "tool_name": "echo",
                "tool_call_id": "tc_test",
                "actor_subject": "u_test",
            },
        )
    )
