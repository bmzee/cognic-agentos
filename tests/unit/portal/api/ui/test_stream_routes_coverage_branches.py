"""Sprint 7B.4 T14 coverage repair — 8 tests covering the production
branches the T10 test suite missed, bringing
``portal/api/ui/stream_routes.py`` from 91.71%/82.50% to the 95/90 floor
required for T13's critical-controls promotion.

Each test names the production branch it covers + the user-locked
doctrine that branch implements. Per the T14 R0 doctrine
(stream_routes.py STAYS on the gate because every uncovered branch
is real wire/security behavior — SSE resume / cursor refusal /
cross-tenant invisibility / replay filtering — coverage gaps mean
the test suite is incomplete, NOT that the module is off-gate):

  1. ``test_cursor_chain_unsupported_422`` — covers lines 175-176 +
     branch [174→175]. A cursor with ``chain_disc=0x02`` (Wave-2
     audit-event slot, reserved) → ``CursorChainUnsupported`` →
     422 ``cursor_chain_unsupported``. The fail-closed-on-unsupported-
     chain doctrine prevents a probe from falling back to the
     decision-history chain via the wrong chain byte.

  2. ``test_run_stream_with_last_event_id_validates_cursor`` —
     covers line 343 + branch [342, 343]. run_stream's cursor source
     is ONLY ``Last-Event-ID`` (no ``?since=`` on this route).
     Without this test, the ``if cursor is not None:`` branch in
     ``run_stream`` was unreached even though the equivalent
     ``tenant_stream`` branch was covered via the existing
     ``?since=`` test.

  3. ``test_replay_skips_event_when_run_id_filter_mismatches`` —
     covers line 578 + branch [577, 578]. Subscriber's
     ``run_id_filter == "run_1"`` AND event's ``run_id == None`` →
     filter rejects.

  4. ``test_replay_skips_event_when_family_filter_mismatches`` —
     covers line 580 + branch [579, 580]. Subscriber's
     ``family_filter == frozenset({"policy"})`` AND event's
     ``family == "frontend_action"`` → filter rejects.

  5. ``test_replay_skips_decision_audit_with_wrong_chain_id`` —
     covers line 575 + branch [574, 575]. The decision_audit mirror
     family is shared by Wave-1 DH chain + Wave-2 audit-event chain;
     at replay we only want DH-mirror rows
     (``data.chain_id == "decision_history"``). A decision_audit
     event with ``chain_id != "decision_history"`` is dropped.
     Synthesised via injected projector for the SSE replay path.

  6. ``test_replay_skips_event_when_family_not_in_wave_1_streamed_set`` —
     covers line 570 + branch [569, 570]. Wave-1 SSE drops audit-
     event-backed families (``tool_call.*`` / ``artifact.*``); they
     ship via the deferred Wave-2 audit-event SSE surface. Branch
     unreachable through the current dispatcher (every routed
     decision_type maps to a streamed family); synthesised via
     monkeypatched projector returning a non-streamed family event.

  7. ``test_cursor_projection_drift_detected_on_recompute_mismatch`` —
     covers line 262 + branch [261, 262]. The existing
     ``test_cursor_projection_drift_detected_500`` test (in
     ``test_stream_routes_reconnect.py``) exercises the
     ``boundary is None`` path (projector unregistered); this test
     exercises the OTHER drift path — projector returns a DIFFERENT
     family/type than the cursor encoded → recomputed type_hash
     mismatches → 500 ``cursor_projection_drift_detected``.

  8. ``test_replay_with_unrecognised_decision_type_skips_typed_event`` —
     covers branch [548, 550]. ``if typed is not None:
     ordered_events.append((0, typed))`` — False branch (skip the
     append) fires when the dispatcher's ``decision_type`` lookup
     returns None (e.g. ``policy.bundle_loaded`` is not in the
     dispatcher dict). Only the ordinal-1 decision_audit mirror is
     replayed.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from fastapi import FastAPI
from ulid import ULID

from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.ui_events import (
    PolicyRBACDenied,
    ToolCallRequested,
    UIEventBroker,
)
from tests.unit.portal.api.ui.sse_test_helpers import (
    UvicornAppFactory,
    _async_client,
    _iter_sse_events,
    _next_sse_event,
    _real_client,
)


def _mint_synthetic_cursor(
    *, chain_disc: int, sequence: int = 1, ordinal: int = 0, type_hash: bytes = b"\x00" * 6
) -> str:
    """Construct a 16-byte cursor payload + base32-encode to ``evt_<ULID>``.

    Bypasses ``_chain_derived_event_id`` (which only accepts
    ``ChainId = Literal["decision_history"]``) so tests can mint
    cursors for the reserved/unsupported chain_disc bytes
    (e.g. 0x02 = Wave-2 audit-event slot)."""
    payload = (
        chain_disc.to_bytes(1, "big")
        + sequence.to_bytes(8, "big")
        + ordinal.to_bytes(1, "big")
        + type_hash
    )
    assert len(payload) == 16
    return f"evt_{ULID.from_bytes(payload)}"


# ---------------------------------------------------------------------------
# Cursor refusal branches
# ---------------------------------------------------------------------------


class TestCursorChainUnsupported422:
    """Branch [174→175] + lines 175-176 — Wave-2 audit-event chain
    byte (0x02) is reserved + refuses fail-closed per the protocol
    cursor doctrine."""

    @pytest.mark.asyncio
    async def test_cursor_chain_unsupported_422(self, app: FastAPI, actor_t1: Actor) -> None:
        # chain_disc=0x02 is the reserved Wave-2 audit-event slot;
        # _decode_chain_cursor raises CursorChainUnsupported; route
        # catches + 422.
        bad_cursor = _mint_synthetic_cursor(chain_disc=0x02)
        async with _async_client(app) as c:
            r = await c.get(f"/api/v1/ui/events/since/{bad_cursor}")
        assert r.status_code == 422
        assert r.json()["detail"]["reason"] == "cursor_chain_unsupported"


class TestRunStreamWithLastEventIdValidatesCursor:
    """Branch [342, 343] + line 343 — run_stream's
    ``if cursor is not None: await _validate_cursor_tenant(...)``
    fires only when a Last-Event-ID header is sent (run_stream has
    no ``?since=`` query). The existing run-stream tests didn't
    send a header so this branch was unreached.

    R1 P1 #1 strengthening: the test sends a cursor that SHOULD FAIL
    validation (well-formed but sequence past chain tip) and asserts
    the route returns 422 ``cursor_not_found``. A coverage-only test
    that sent a VALID cursor + asserted 200 would pass even if
    ``_validate_cursor_tenant`` were deleted from the run_stream
    handler — not load-bearing. The refusal-shape assertion proves
    run_stream actually enforces cursor validation rather than just
    accepting the header + opening the stream."""

    @pytest.mark.asyncio
    async def test_run_stream_refuses_last_event_id_cursor_past_tip(
        self,
        app: FastAPI,
        actor_t1: Actor,
    ) -> None:
        # Mint a syntactically valid cursor (chain_disc=0x01 is the
        # decision_history slot, so _decode_chain_cursor returns a
        # well-formed ChainCursor — NOT a malformed-decode refusal)
        # but with sequence past the chain tip (the test starts
        # with an empty chain; sequence 999_999_999 cannot exist).
        # _validate_cursor_tenant's SELECT returns None → raises
        # HTTPException(422, cursor_not_found).
        #
        # ASGITransport is fine here — the route refuses BEFORE the
        # SSE response body opens (422 returns synchronously; no
        # streaming body for ASGITransport to buffer).
        bad_cursor = _mint_synthetic_cursor(
            chain_disc=0x01,
            sequence=999_999_999,
            ordinal=0,
        )
        async with _async_client(app) as c:
            r = await c.get(
                "/api/v1/ui/runs/run_1/events",
                headers={"Last-Event-ID": bad_cursor},
            )
        assert r.status_code == 422
        assert r.json()["detail"]["reason"] == "cursor_not_found"


class TestCursorProjectionDriftDetectedOnRecomputeMismatch:
    """Branch [261, 262] + line 262 — the second drift path. The
    existing reconnect test patches the dispatcher to REMOVE the
    projector (boundary is None path); this test patches the
    dispatcher to return a DIFFERENT family/type so the recomputed
    type_hash mismatches the cursor's encoded type_hash."""

    @pytest.mark.asyncio
    async def test_drift_via_projector_swap(
        self,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-1",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:11",
            tenant_id="t1",
        )

        # Swap the frontend_action.submitted projector for one that
        # returns a PolicyRBACDenied event — different family/type
        # so the recomputed hash != cursor.type_hash.
        from cognic_agentos.protocol import ui_events
        from cognic_agentos.protocol.ui_events import (
            _chain_derived_event_id,
            _project_typed_decision_history,  # noqa: F401 — re-imported below
        )

        def _wrong_family_projector(snapshot):
            return PolicyRBACDenied(
                event_id=_chain_derived_event_id(
                    chain_id="decision_history",
                    sequence=snapshot.sequence,
                    ordinal=0,
                    family="policy",
                    type_="rbac_denied",
                ),
                ts=snapshot.created_at,
                tenant=snapshot.tenant_id,
                trace_id=snapshot.trace_id,
                audit_chain_hash="0x00",
                data={},
            )

        patched = {
            **ui_events._DECISION_HISTORY_TYPED_PROJECTORS,
            "frontend_action.submitted": _wrong_family_projector,
        }
        monkeypatch.setattr(ui_events, "_DECISION_HISTORY_TYPED_PROJECTORS", patched)

        async with _async_client(app) as c:
            r = await c.get(f"/api/v1/ui/events/since/{r_a.event_id}")
        assert r.status_code == 500
        assert r.json()["detail"]["reason"] == "cursor_projection_drift_detected"


# ---------------------------------------------------------------------------
# Replay-loop filter branches
# ---------------------------------------------------------------------------


class TestReplayFilterDrops:
    """4 replay-loop ``continue`` branches in
    ``_replay_from_decision_history`` — the subscriber-side filters
    that drop events before they reach the SSE stream during replay.
    Live-tail emit path covers these branches via the broker's
    ``_fanout_hook``; replay-time coverage requires explicit tests."""

    @pytest.mark.asyncio
    async def test_replay_skips_event_when_run_id_filter_mismatches(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
    ) -> None:
        """Line 578 + branch [577, 578]. run_stream sets
        subscriber.run_id_filter from the path-param; events from
        ``broker.append_frontend_action_submitted`` carry
        ``run_id=None`` (the projector doesn't populate it); during
        replay the filter rejects the event."""
        # Append 2 rows so replay has rows past the cursor.
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-a",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:aa",
            tenant_id="t1",
        )
        await broker.append_frontend_action_submitted(
            request_id="portal-req-b",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:bb",
            tenant_id="t1",
        )
        # Reconnect to run_stream with run_id="run_1" + Last-Event-ID
        # → replay's run_id_filter rejects every event (event.run_id
        # is None ≠ "run_1") → no SSE event delivered.
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream(
                "GET",
                "/api/v1/ui/runs/run_1/events",
                headers={"Last-Event-ID": r_a.event_id},
            ) as resp,
        ):
            assert resp.status_code == 200
            # Replay should drop ALL events → only keepalive arrives.
            # Use a short timeout — if any frontend_action event leaks
            # through, _next_sse_event returns it; we then fail.
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(_next_sse_event(resp), timeout=0.3)

    @pytest.mark.asyncio
    async def test_replay_skips_event_when_family_filter_mismatches(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
    ) -> None:
        """Line 580 + branch [579, 580]. ``?families=policy`` excludes
        ``frontend_action`` events from replay."""
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-a",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:aa",
            tenant_id="t1",
        )
        await broker.append_frontend_action_submitted(
            request_id="portal-req-b",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:bb",
            tenant_id="t1",
        )
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream(
                "GET",
                f"/api/v1/ui/events/since/{r_a.event_id}?families=policy",
            ) as resp,
        ):
            assert resp.status_code == 200
            # Every replayed event has family="frontend_action" or
            # "decision_audit" — neither matches the "policy" filter;
            # all dropped.
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(_next_sse_event(resp), timeout=0.3)

    @pytest.mark.asyncio
    async def test_replay_skips_decision_audit_with_wrong_chain_id(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Line 575 + branch [574, 575]. The decision_audit mirror
        from an audit-event-chain row would have
        ``data["chain_id"] != "decision_history"``; replay drops it.
        Replay constructs ``_DHReplaySnapshot(chain_id="decision_history",
        ...)`` hardcoded so we monkey-patch the mirror builder to
        emit ``chain_id="audit_event"`` in the event data dict."""
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-1",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:11",
            tenant_id="t1",
        )
        # Append a 2nd row so the cursor lands on r_a (typed event,
        # ordinal=0) and replay walks past it (cursor's row + the
        # 2nd row); both rows' decision_audit mirrors come back from
        # the patched builder with chain_id != "decision_history".
        await broker.append_frontend_action_submitted(
            request_id="portal-req-2",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:22",
            tenant_id="t1",
        )

        # Patch _build_decision_audit_for_dh_snapshot AT THE STREAM-
        # ROUTES IMPORT SITE — stream_routes.py imports the symbol
        # via ``from cognic_agentos.protocol.ui_events import
        # _build_decision_audit_for_dh_snapshot``, which binds a
        # local reference at module-load time. A patch on
        # ``ui_events._build_decision_audit_for_dh_snapshot`` is
        # invisible to stream_routes (it has its own local
        # reference). The typed-projector path WORKS via dict
        # monkeypatch because ``_project_typed_decision_history``
        # resolves ``_DECISION_HISTORY_TYPED_PROJECTORS`` from its
        # OWN module namespace at call time — but the mirror builder
        # has no such indirection.
        from cognic_agentos.portal.api.ui import stream_routes
        from cognic_agentos.protocol.ui_events import (
            DecisionAuditEventAppended,
            _chain_derived_event_id,
        )

        def _wrong_chain_mirror(snapshot):
            return DecisionAuditEventAppended(
                event_id=_chain_derived_event_id(
                    chain_id="decision_history",
                    sequence=snapshot.sequence,
                    ordinal=1,
                    family="decision_audit",
                    type_="event_appended",
                ),
                ts=snapshot.created_at,
                tenant=snapshot.tenant_id,
                trace_id=snapshot.trace_id,
                audit_chain_hash="0x00",
                data={"chain_id": "audit_event"},  # WRONG chain_id
            )

        monkeypatch.setattr(
            stream_routes,
            "_build_decision_audit_for_dh_snapshot",
            _wrong_chain_mirror,
        )

        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream("GET", f"/api/v1/ui/events/since/{r_a.event_id}") as resp,
        ):
            # Replay: r_a's typed event is already-seen (cursor =
            # r_a.event_id at ordinal 0) → skipped via boundary
            # dedup. r_a's mirror is filtered (wrong chain_id).
            # r_b's typed event is YIELDED. r_b's mirror is filtered.
            # Collect events; only r_b's typed should arrive.
            events: list[dict[str, Any]] = []
            async for chunk in _iter_sse_events(resp, max_events=1):
                events.append(chunk)
        assert len(events) == 1
        assert events[0]["event"] == "frontend_action.submitted"
        # The replay also exercised the "wrong chain_id" continue.

    @pytest.mark.asyncio
    async def test_replay_skips_event_when_family_not_in_wave_1_streamed_set(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        actor_t1: Actor,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Line 570 + branch [569, 570]. The Wave-1 SSE-streamed
        family set excludes ``tool_call.*`` + ``artifact.*`` (those
        are audit-event-backed; Wave-2 SSE surface). Patch the
        dispatcher to add a projector that returns a ``tool_call``
        event for the frontend_action.submitted decision_type; replay
        drops it."""
        # Append BOTH rows BEFORE patching the dispatcher — the
        # broker's append seam reads back the typed event_id via the
        # ContextVar capture inside ``_fanout_hook``, and that capture
        # is filtered by ``_TYPED_PROJECTION_CLASSES`` membership.
        # A patched projector returning ``ToolCallRequested`` would
        # bypass the capture (``ToolCallRequested`` IS in
        # ``_TYPED_PROJECTION_CLASSES``, but the broker's
        # ``append_frontend_action_submitted`` seam EXPECTS the
        # capture to come from a ``FrontendActionSubmitted`` event;
        # mismatched class → raises "no typed event projected"). So
        # the patch only fires during REPLAY (where the dispatcher
        # is monkey-patched fresh per the existing reconnect-test
        # pattern), NOT during the live append.
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-a",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:aa",
            tenant_id="t1",
        )
        await broker.append_frontend_action_submitted(
            request_id="portal-req-b",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:bb",
            tenant_id="t1",
        )
        from cognic_agentos.protocol import ui_events
        from cognic_agentos.protocol.ui_events import _chain_derived_event_id

        def _tool_call_projector(snapshot):
            return ToolCallRequested(
                event_id=_chain_derived_event_id(
                    chain_id="decision_history",
                    sequence=snapshot.sequence,
                    ordinal=0,
                    family="tool_call",
                    type_="requested",
                ),
                ts=snapshot.created_at,
                tenant=snapshot.tenant_id,
                trace_id=snapshot.trace_id,
                audit_chain_hash="0x00",
                data={},
            )

        patched = {
            **ui_events._DECISION_HISTORY_TYPED_PROJECTORS,
            "frontend_action.submitted": _tool_call_projector,
        }
        monkeypatch.setattr(ui_events, "_DECISION_HISTORY_TYPED_PROJECTORS", patched)

        # Mint a cursor for the BOUNDARY row's PATCHED projection
        # (tool_call.requested) so the pre-stream
        # ``_validate_cursor_tenant`` boundary check passes — the
        # boundary event IS a tool_call.requested, recomputed
        # type_hash matches.
        from sqlalchemy import select

        from cognic_agentos.core.decision_history import _decision_history

        engine = broker._history._engine
        async with engine.begin() as conn:
            row = (
                await conn.execute(
                    select(_decision_history.c.sequence)
                    .where(_decision_history.c.sequence > 0)
                    .order_by(_decision_history.c.sequence.asc())
                    .limit(1)
                )
            ).first()
        assert row is not None
        cursor_for_tool_call = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=row.sequence,
            ordinal=0,
            family="tool_call",
            type_="requested",
        )
        # The cursor must match r_a's event_id under the patched
        # projector. (r_a was minted via the real projector pre-
        # patch — that event_id is for "frontend_action.submitted".
        # We're synthesising a fresh cursor for the patched-replay
        # path so the boundary check passes.)
        del r_a  # not used beyond setup

        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream("GET", f"/api/v1/ui/events/since/{cursor_for_tool_call}") as resp,
        ):
            # Replay walks r_a + r_b.
            #   r_a (boundary): typed=tool_call.requested at ord 0,
            #     SKIPPED via dedup (ord_n=0 ≤ cursor.ordinal=0);
            #     mirror=decision_audit at ord 1, KEPT.
            #   r_b: typed=tool_call.requested at ord 0,
            #     family="tool_call" NOT in _SSE_WAVE_1_STREAMED_FAMILIES
            #     → DROPPED via branch [569, 570] (the branch under
            #     test); mirror=decision_audit at ord 1, KEPT.
            # Collect 2 events; both should be decision_audit mirrors
            # (the typed tool_call.requested for r_b was filtered).
            events: list[dict[str, Any]] = []
            async for chunk in _iter_sse_events(resp, max_events=2):
                events.append(chunk)
        for e in events:
            assert e["event"] == "decision_audit.event_appended"


# ---------------------------------------------------------------------------
# Typed-projector-None branch in the replay loop
# ---------------------------------------------------------------------------


class TestReplayWithUnrecognisedDecisionType:
    """Branch [548, 550] — ``if typed is not None: ordered_events.append(...)``
    False path. The dispatcher's ``decision_type`` lookup returns None
    for unrecognised types (e.g. ``policy.bundle_loaded`` is not yet
    in the dispatcher dict per the Sprint-8 deferred items)."""

    @pytest.mark.asyncio
    async def test_replay_skips_typed_event_when_dispatcher_returns_none(
        self,
        uvicorn_app_factory: UvicornAppFactory,
        app: FastAPI,
        broker: UIEventBroker,
        decision_history_store: DecisionHistoryStore,
        actor_t1: Actor,
    ) -> None:
        # Append a frontend_action.submitted (dispatcher-routed) so
        # the cursor coordinate is valid.
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-a",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id=None,
            payload_digest="sha256:aa",
            tenant_id="t1",
        )
        # Append a 2nd row via the GENERIC DecisionHistoryStore.append
        # with an unrecognised decision_type — bypasses the broker's
        # frontend_action seam. The replay walks past the boundary
        # row + encounters this row; the dispatcher's lookup returns
        # None → branch [548, 550] False path → only the ordinal-1
        # mirror is added to ordered_events.
        await decision_history_store.append(
            DecisionRecord(
                decision_type="policy.bundle_loaded",
                request_id="portal-req-bundle",
                payload={"bundle_path": "/etc/policies/some.rego"},
                tenant_id="t1",
                actor_id=None,
            )
        )
        async with (
            uvicorn_app_factory(app) as base_url,
            _real_client(base_url) as c,
            c.stream("GET", f"/api/v1/ui/events/since/{r_a.event_id}") as resp,
        ):
            # Boundary row: r_a (cursor.ordinal=0 typed skipped;
            # ordinal=1 mirror emitted). 2nd row: typed is None
            # (no projector for policy.bundle_loaded) → ordered_events
            # only carries (1, mirror); replay yields the mirror.
            events: list[dict[str, Any]] = []
            async for chunk in _iter_sse_events(resp, max_events=2):
                events.append(chunk)
        # Both events are decision_audit mirrors — the boundary row's
        # mirror AND the policy.bundle_loaded row's mirror (no typed
        # event for the latter because the dispatcher returned None).
        for e in events:
            assert e["event"] == "decision_audit.event_appended"
