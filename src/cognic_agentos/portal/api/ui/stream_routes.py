"""Sprint-7B.4 T10 — 3 SSE GET endpoints per ADR-020 §60-63.

Three SSE GETs gated by per-endpoint RBAC scopes; each serves the
Wave-1 streamed-family set (decision-history-only — audit-event-backed
families ``tool_call.*`` and ``artifact.*`` are filtered out at the
broker per spec §4.3):

  - ``GET /runs/{run_id}/events`` — gated by ``ui.run_stream``;
    filters live tail by ``run_id == path-param``
  - ``GET /tenants/{tenant_id}/events`` — gated by ``ui.tenant_stream``;
    cross-tenant returns 404 ``pack_not_found`` (cross-tenant invisible);
    optional ``?since=<event_id>`` URL cursor for replay
  - ``GET /events/since/{event_id}`` — gated by ``ui.tenant_stream``;
    replay from the path-param cursor

Wire-protocol contracts:

  - ``Last-Event-ID`` header WINS over any URL cursor. Malformed header
    refuses 422 ``cursor_malformed`` (no silent fall-back).
  - Cursor validation: ``cursor_malformed`` (decode failure),
    ``cursor_chain_unsupported`` (chain_disc outside Wave-1 supported set),
    ``cursor_not_found`` (sequence past chain tip),
    cross-tenant 404 ``pack_not_found`` (invisible),
    ``cursor_projection_drift_detected`` (boundary row's projector
    output diverges from cursor's encoded type_hash — pinned by
    threat-model-revert test).
  - Per-tenant connection cap from
    ``Settings.ui_event_stream_per_tenant_cap``;
    over-cap refuses 429 ``tenant_connection_cap_exceeded``.
  - SSE response headers: ``Cache-Control: no-cache``,
    ``X-Accel-Buffering: no``, ``Connection: keep-alive``.
  - ``EventSourceResponse(send_timeout=settings.ui_event_stream_send_timeout_s)``
    so a stalled client (TCP half-open) is cleaned up server-side.
  - Heartbeat owned by the broker/generator at
    ``ui_event_stream_heartbeat_interval_s``; ``sse-starlette``'s
    internal ping is set to a long sentinel (86400s) so the broker
    stays authoritative for keepalive cadence.

Architecture-arrow note: routes capture ``broker`` + ``settings`` +
``decision_history_store`` via closure rather than reading
``request.app.state.<dep>`` — T10 plan-vs-reality drift #1 resolution.
``create_app`` populates ``app.state.decision_history_store`` but
NOT ``app.state.settings``; closure-capture keeps ``create_app``
untouched (avoids a CC-ADJ to portal/api/app.py) and matches the
existing ``broker=`` capture pattern.

NOTE: ``from __future__ import annotations`` is DELIBERATELY OMITTED —
PEP 563 string-deferred annotations would break FastAPI's
``inspect.signature()`` / ``typing.get_type_hints()`` resolution on
the ``actor: Actor = Depends(RequireScope(...))`` route signatures
(standing-offer invariant; same as ``operator_routes.py`` +
``inspection_routes.py``)."""

import asyncio
import hashlib
import logging
from datetime import UTC, datetime
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from sqlalchemy import select
from sse_starlette.sse import EventSourceResponse, ServerSentEvent  # type: ignore[attr-defined]

from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import (
    AppendedDecisionSnapshot,
    DecisionHistoryStore,
    _decision_history,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.protocol.ui_events import (
    _SSE_WAVE_1_STREAMED_FAMILIES,
    ChainCursor,
    CursorChainUnsupported,
    CursorMalformed,
    Subscriber,
    TenantConnectionCapExceeded,
    UIEventBroker,
    _BaseEvent,
    _build_decision_audit_for_dh_snapshot,
    _decode_chain_cursor,
    _DHReplaySnapshot,
    _project_typed_decision_history,
)

_LOG = logging.getLogger(__name__)


#: Closed-enum 4-value vocabulary for cursor refusal bodies. Wire-
#: protocol-public per ADR-020 + AGENTS.md "Wire-protocol contracts"
#: stop rule — every UI client reads ``detail.reason`` on a 4xx/5xx
#: response and drift breaks bank-overlay error handling.
#:
#: ``cursor_tenant_mismatch`` is intentionally NOT in this vocabulary.
#: A cross-tenant cursor MUST surface as the SAME 404 body shape as
#: the unknown-pack 404 (``{"reason": "pack_not_found"}``) — per the
#: cross-tenant-invisible doctrine, a probe cannot enumerate tenant
#: boundaries by comparing response shapes. The closed enum here
#: lists ONLY reasons the routes actually emit; keeping
#: ``cursor_tenant_mismatch`` as an un-emitted value would weaken
#: the published refusal contract.
CursorRefusalReason = Literal[
    "cursor_malformed",
    "cursor_chain_unsupported",
    "cursor_not_found",
    "cursor_projection_drift_detected",
]


#: 1-value vocabulary for the family-filter-unknown refusal body.
FamilyFilterRefusalReason = Literal["family_filter_unknown"]


#: Shared response headers per spec §4.3. Sent on every successful
#: SSE response (200 status).
_SSE_RESPONSE_HEADERS: dict[str, str] = {
    "Cache-Control": "no-cache",
    "X-Accel-Buffering": "no",
    "Connection": "keep-alive",
}


#: sse-starlette's internal ping is set to a long sentinel so the
#: broker/generator-owned heartbeat stays authoritative. The generator
#: yields ``: keepalive`` comments every
#: ``settings.ui_event_stream_heartbeat_interval_s`` per spec §4.3.
_SSE_STARLETTE_PING_SENTINEL_S: int = 86400


def build_stream_routes(
    *,
    broker: UIEventBroker,
    settings: Settings,
    decision_history_store: DecisionHistoryStore,
) -> APIRouter:
    """Build the SSE stream router with closure-captured deps.

    T10 plan-vs-reality drift #1: the three deps are captured here
    (NOT looked up via ``request.app.state.<dep>``) because
    ``create_app`` populates ``app.state.decision_history_store`` +
    ``app.state.ui_event_broker`` but NOT ``app.state.settings``.
    Closure-capture keeps ``create_app`` untouched + matches the
    existing ``broker=`` pattern.

    The returned :class:`APIRouter` carries 3 SSE GET endpoints; the
    caller MUST include it under ``/api/v1/ui`` (the prefix is owned
    by ``create_app``'s mounting block, not this factory, so a
    bank overlay can re-prefix if needed).
    """

    router = APIRouter()

    async def _resolve_effective_cursor(
        last_event_id: str | None, url_cursor: str | None
    ) -> ChainCursor | None:
        """Resolve the effective cursor per the Last-Event-ID
        precedence rule (spec §4.3):

          - ``Last-Event-ID`` header WINS over URL cursor
            (``?since=`` query or path-param)
          - Malformed header refuses 422 ``cursor_malformed`` WITHOUT
            silent fall-back to the URL cursor (threat-model-revert
            pin — a client typo cannot accidentally re-deliver
            historical events)
          - Returns ``None`` only when BOTH inputs are absent
        """
        chosen = last_event_id if last_event_id else url_cursor
        if not chosen:
            return None
        try:
            return _decode_chain_cursor(chosen)
        except CursorMalformed as exc:
            raise HTTPException(status_code=422, detail={"reason": "cursor_malformed"}) from exc
        except CursorChainUnsupported as exc:
            raise HTTPException(
                status_code=422, detail={"reason": "cursor_chain_unsupported"}
            ) from exc

    async def _validate_cursor_tenant(cursor: ChainCursor, actor_tenant_id: str) -> None:
        """Cross-tenant + cursor-not-found + type_hash-drift validation.

        Reads the boundary row via a direct SQLAlchemy select against
        the exported ``_decision_history`` Table (the same read seam
        the replay path uses; no nonexistent ``DecisionHistoryStore``
        method).

        Raises:
          - 422 ``cursor_not_found`` if the row is missing
          - 404 ``pack_not_found`` if the row's tenant_id differs
            from the actor's (cross-tenant invisible)
          - 500 ``cursor_projection_drift_detected`` if the boundary
            row's projected event family.type hash diverges from the
            cursor's encoded ``type_hash`` (Pydantic model rename
            since the cursor was minted, OR the typed projector was
            unregistered)

        This check runs BEFORE the EventSourceResponse opens so the
        500 status actually reaches the client — raising inside the
        body generator after 200-OK is sent would leave the client
        with a broken stream + an opaque connection drop.
        """
        async with decision_history_store._engine.begin() as conn:
            row = (
                await conn.execute(
                    select(
                        _decision_history.c.tenant_id,
                        _decision_history.c.event_type,
                        _decision_history.c.sequence,
                        _decision_history.c.trace_id,
                        _decision_history.c.request_id,
                        _decision_history.c.payload,
                        _decision_history.c.hash,
                        _decision_history.c.created_at,
                    ).where(_decision_history.c.sequence == cursor.sequence)
                )
            ).first()
        if row is None:
            raise HTTPException(status_code=422, detail={"reason": "cursor_not_found"})
        if row.tenant_id != actor_tenant_id:
            # Cross-tenant — same body shape as pack_not_found so a
            # probe cannot enumerate cursors across tenants by shape.
            raise HTTPException(status_code=404, detail={"reason": "pack_not_found"})
        # Type-hash drift detection: project the boundary row through
        # the same projectors the replay path uses; recompute the
        # event-name hash; compare to the cursor's encoded
        # ``type_hash``. Mismatch (or missing typed event when the
        # cursor sits at ordinal 0) → 500 fail-closed.
        snapshot_cast = cast(
            AppendedDecisionSnapshot,
            _DHReplaySnapshot(
                sequence=row.sequence,
                decision_type=row.event_type,
                tenant_id=row.tenant_id,
                trace_id=row.trace_id,
                request_id=row.request_id,
                payload=row.payload,
                new_hash=row.hash,
                chain_id="decision_history",
                created_at=row.created_at,
            ),
        )
        typed = _project_typed_decision_history(snapshot_cast)
        mirror = _build_decision_audit_for_dh_snapshot(snapshot_cast)
        boundary = typed if cursor.ordinal == 0 else mirror
        if boundary is None:
            # Cursor expected a typed event but projector returned
            # None — Pydantic model unregistered since cursor was
            # minted.
            raise HTTPException(
                status_code=500,
                detail={"reason": "cursor_projection_drift_detected"},
            )
        # `family` + `type` live on every `_BaseEvent` subclass as
        # Literal-typed defaults but mypy sees the base abstract class
        # via the projector return type. The structural shape is
        # guaranteed by `_TYPED_PROJECTION_CLASSES` membership.
        recomputed = hashlib.sha256(
            f"{boundary.family}.{boundary.type}".encode()  # type: ignore[attr-defined]
        ).digest()[:6]
        if recomputed != cursor.type_hash:
            raise HTTPException(
                status_code=500,
                detail={"reason": "cursor_projection_drift_detected"},
            )

    def _parse_family_filter(families: str | None) -> frozenset[str] | None:
        """Parse ``?families=`` query-param.

        ``None`` (no query) → no filter; otherwise split on ``,``,
        intersect against ``_SSE_WAVE_1_STREAMED_FAMILIES``; unknown
        names refuse 422 ``family_filter_unknown``.
        """
        if not families:
            return None
        requested = frozenset(s.strip() for s in families.split(",") if s.strip())
        unknown = requested - _SSE_WAVE_1_STREAMED_FAMILIES
        if unknown:
            raise HTTPException(
                status_code=422,
                detail={
                    "reason": "family_filter_unknown",
                    "unknown_families": sorted(unknown),
                },
            )
        return requested

    def _register_or_429(
        *,
        tenant_id: str,
        run_id_filter: str | None,
        family_filter: frozenset[str] | None,
    ) -> Subscriber:
        try:
            return broker.register_subscriber(
                tenant_id=tenant_id,
                run_id_filter=run_id_filter,
                family_filter=family_filter,
            )
        except TenantConnectionCapExceeded as exc:
            raise HTTPException(
                status_code=429,
                detail={"reason": "tenant_connection_cap_exceeded"},
            ) from exc

    def _build_response(subscriber: Subscriber, cursor: ChainCursor | None) -> EventSourceResponse:
        return EventSourceResponse(
            _sse_generator(
                broker=broker,
                subscriber=subscriber,
                cursor=cursor,
                store=decision_history_store,
                settings=settings,
            ),
            ping=_SSE_STARLETTE_PING_SENTINEL_S,
            send_timeout=settings.ui_event_stream_send_timeout_s,
            headers=_SSE_RESPONSE_HEADERS,
        )

    # Closure-local ``RequireScope`` instances — constructed once at
    # ``build_stream_routes`` call time, then referenced as
    # ``Annotated[Actor, Depends(<local>)]`` in each route signature.
    # The Annotated form avoids ruff B008 (function calls in argument
    # defaults) AND mirrors the operator_routes / inspection_routes
    # closure-local-deps pattern (per the standing-offer §30 invariant
    # that ``from __future__ import annotations`` is DELIBERATELY
    # OMITTED so FastAPI's ``inspect.signature()`` resolves these).
    _require_run_stream = RequireScope("ui.run_stream")
    _require_tenant_stream = RequireScope("ui.tenant_stream")

    @router.get("/runs/{run_id}/events")
    async def run_stream(
        request: Request,
        run_id: str,
        actor: Annotated[Actor, Depends(_require_run_stream)],
        families: Annotated[str | None, Query()] = None,
        last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    ) -> EventSourceResponse:
        del request  # unused — kept so future drift to request.state is one edit
        family_filter = _parse_family_filter(families)
        cursor = await _resolve_effective_cursor(last_event_id, url_cursor=None)
        if cursor is not None:
            await _validate_cursor_tenant(cursor, actor.tenant_id)
        subscriber = _register_or_429(
            tenant_id=actor.tenant_id,
            run_id_filter=run_id,
            family_filter=family_filter,
        )
        return _build_response(subscriber, cursor)

    @router.get("/tenants/{tenant_id}/events")
    async def tenant_stream(
        request: Request,
        tenant_id: str,
        actor: Annotated[Actor, Depends(_require_tenant_stream)],
        families: Annotated[str | None, Query()] = None,
        since: Annotated[str | None, Query()] = None,
        last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    ) -> EventSourceResponse:
        del request
        if tenant_id != actor.tenant_id:
            # Cross-tenant — invisible 404 (same body shape as
            # pack_not_found per the cross-tenant-invisible doctrine).
            raise HTTPException(status_code=404, detail={"reason": "pack_not_found"})
        family_filter = _parse_family_filter(families)
        cursor = await _resolve_effective_cursor(last_event_id, since)
        if cursor is not None:
            await _validate_cursor_tenant(cursor, actor.tenant_id)
        subscriber = _register_or_429(
            tenant_id=actor.tenant_id,
            run_id_filter=None,
            family_filter=family_filter,
        )
        return _build_response(subscriber, cursor)

    @router.get("/events/since/{event_id}")
    async def since_cursor_stream(
        request: Request,
        event_id: str,
        actor: Annotated[Actor, Depends(_require_tenant_stream)],
        run_id: Annotated[str | None, Query()] = None,
        families: Annotated[str | None, Query()] = None,
        last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    ) -> EventSourceResponse:
        del request
        family_filter = _parse_family_filter(families)
        cursor = await _resolve_effective_cursor(last_event_id, url_cursor=event_id)
        # Path-param always provides event_id so cursor is non-None here
        # unless _resolve_effective_cursor raised.
        assert cursor is not None
        await _validate_cursor_tenant(cursor, actor.tenant_id)
        subscriber = _register_or_429(
            tenant_id=actor.tenant_id,
            run_id_filter=run_id,
            family_filter=family_filter,
        )
        return _build_response(subscriber, cursor)

    return router


# ---------------------------------------------------------------------------
# SSE generator (replay → live tail) + helpers.
# ---------------------------------------------------------------------------


async def _sse_generator(
    *,
    broker: UIEventBroker,
    subscriber: Subscriber,
    cursor: ChainCursor | None,
    store: DecisionHistoryStore,
    settings: Settings,
) -> Any:
    # Return ``Any`` so the AsyncGenerator type doesn't fight
    # ``EventSourceResponse``'s loose annotation.
    """Replay-then-live SSE generator.

    Phase 1 — replay: if ``cursor`` is provided, walk historical chain
    rows from ``cursor.sequence`` to chain tip; for the boundary row,
    apply type_hash drift detection + skip events the client already
    saw (``ord_n <= cursor.ordinal``).

    Phase 2 — live: dequeue from ``subscriber.queue`` with
    ``asyncio.wait_for(timeout=heartbeat_interval_s)``; on TimeoutError
    yield a ``: keepalive`` comment. ``last_activity_at`` updates on
    every successful yield.

    Phase 3 — cleanup: ``finally:`` block calls
    ``broker.unregister_subscriber(...)`` so a closed client connection
    (or a half-open one past ``send_timeout``) doesn't leak a
    subscriber row.
    """
    try:
        if cursor is not None:
            async for hist_event in _replay_from_decision_history(
                store=store, cursor=cursor, subscriber=subscriber
            ):
                yield _encode(hist_event)
                subscriber.last_activity_at = datetime.now(UTC)
        while True:
            try:
                event = await asyncio.wait_for(
                    subscriber.queue.get(),
                    timeout=settings.ui_event_stream_heartbeat_interval_s,
                )
                yield _encode(event)
                subscriber.last_activity_at = datetime.now(UTC)
            except TimeoutError:
                # Broker/generator-owned heartbeat — yield a comment
                # so the connection stays warm + intermediaries don't
                # see the stream as idle. NOT sse-starlette's internal
                # ping (which is set to the long sentinel).
                yield ServerSentEvent(comment="keepalive")
                subscriber.last_activity_at = datetime.now(UTC)
    finally:
        broker.unregister_subscriber(subscriber)


def _encode(event: _BaseEvent) -> ServerSentEvent:
    # `family` + `type` live on every `_BaseEvent` subclass as
    # Literal-typed defaults — the base type is structural only.
    return ServerSentEvent(
        id=event.event_id,
        event=f"{event.family}.{event.type}",  # type: ignore[attr-defined]
        data=event.model_dump_json(),
    )


async def _replay_from_decision_history(
    *,
    store: DecisionHistoryStore,
    cursor: ChainCursor,
    subscriber: Subscriber,
) -> Any:  # AsyncGenerator[_BaseEvent, None]
    """Replay decision-history events from ``cursor.sequence`` to tip.

    Reads via the exported ``_decision_history`` Table directly (the
    Table IS the supported public surface — ``__all__`` at
    :file:`core/decision_history.py:632` exports it). The broker holds
    the ``AsyncEngine`` via ``store._engine`` (existing Sprint-6
    attribute used by ``AuditStore``'s hook chain).

    Boundary semantics:
      - At ``row.sequence == cursor.sequence``: the boundary row's
        events at ``ord_n <= cursor.ordinal`` are skipped (the client
        already saw them); BEFORE the skip, type_hash drift is checked
        — if the boundary event's recomputed
        ``sha256("<family>.<type>")[:6]`` diverges from the cursor's
        encoded ``type_hash``, refuse 500
        ``cursor_projection_drift_detected``. Drift also fires when
        the cursor encodes a typed event (``ordinal=0``) but the
        projector now returns None (Pydantic model renamed since the
        cursor was minted).
      - Beyond the boundary: yield every event that passes the broker's
        Wave-1 family filter + the subscriber's optional ``run_id``
        and ``family`` filters.
    """
    engine = store._engine
    async with engine.begin() as conn:
        # 1) Snapshot the chain tip (read-only).
        tip_stmt = (
            select(_decision_history.c.sequence)
            .order_by(_decision_history.c.sequence.desc())
            .limit(1)
        )
        tip_row = (await conn.execute(tip_stmt)).first()
        tip = tip_row.sequence if tip_row is not None else 0

        # 2) Read rows in [cursor.sequence, tip] for the actor's
        # tenant, ordered by sequence ASC.
        rows_stmt = (
            select(_decision_history)
            .where(_decision_history.c.sequence >= cursor.sequence)
            .where(_decision_history.c.sequence <= tip)
            .where(_decision_history.c.tenant_id == subscriber.tenant_id)
            .order_by(_decision_history.c.sequence.asc())
        )
        rows = (await conn.execute(rows_stmt)).fetchall()

    # 3) Project + yield outside the DB transaction.
    # R4 #1: `_decision_history` columns are `event_type` + `hash` (NOT
    # decision_type / new_hash); map onto _DHReplaySnapshot's
    # projector-facing names explicitly so the same projector functions
    # work in live + replay.
    for row in rows:
        snapshot = _DHReplaySnapshot(
            sequence=row.sequence,
            decision_type=row.event_type,
            tenant_id=row.tenant_id,
            trace_id=row.trace_id,
            request_id=row.request_id,
            payload=row.payload,
            new_hash=row.hash,
            chain_id="decision_history",
            created_at=row.created_at,
        )
        # Structural-shape compatibility: _DHReplaySnapshot fields are a
        # superset of the AppendedDecisionSnapshot fields the projectors
        # read (pinned by test_dh_replay_snapshot_shape_matches_appended_decision_snapshot).
        # `cast` keeps mypy happy without adding a Union to the projector
        # signature (which would expand the CC blast radius in ui_events.py).
        snapshot_cast = cast(AppendedDecisionSnapshot, snapshot)
        typed = _project_typed_decision_history(snapshot_cast)
        mirror = _build_decision_audit_for_dh_snapshot(snapshot_cast)

        ordered_events: list[tuple[int, _BaseEvent]] = []
        if typed is not None:
            ordered_events.append((0, typed))
        ordered_events.append((1, mirror))

        # Type-hash drift detection lives in ``_validate_cursor_tenant``
        # (pre-stream) so a 500 actually reaches the client. Raising
        # HTTPException from inside this generator (post-200-OK) leaves
        # the client with a broken stream + opaque connection drop.

        for ord_n, event in ordered_events:
            # Boundary row: skip events the client already saw.
            if row.sequence == cursor.sequence and ord_n <= cursor.ordinal:
                continue
            # `family` lives on every `_BaseEvent` subclass as a
            # Literal-typed default (the base abstract class doesn't
            # declare it). Cast access here mirrors `_encode`.
            family: str = event.family  # type: ignore[attr-defined]
            # Wave-1 family filter — audit-event-backed families are
            # never streamed to SSE subscribers; they live in the
            # audit chain at Wave 1 + ship via the Wave-2 audit-event
            # SSE surface.
            if family not in _SSE_WAVE_1_STREAMED_FAMILIES:
                continue
            # decision_audit family is shared by the audit chain
            # (Wave 2) + the DH-mirror path (Wave 1). At replay we
            # only want the DH-mirror rows.
            if family == "decision_audit" and event.data.get("chain_id") != "decision_history":
                continue
            # Subscriber-level filters.
            if subscriber.run_id_filter and event.run_id != subscriber.run_id_filter:
                continue
            if subscriber.family_filter and family not in subscriber.family_filter:
                continue
            yield event


__all__ = [
    "CursorRefusalReason",
    "FamilyFilterRefusalReason",
    "build_stream_routes",
]
