"""Sprint 7B.4 T6 — async RBAC + dual-surface denial emission + tenant
routing + fail-closed contract regressions.

`portal/rbac/{enforcement,tenant_isolation,human_actor,role_separation}.py`
are all on the AGENTS.md critical-controls list + the "Wire-protocol
contracts" stop rule (every 403/500 carries a closed-enum
:data:`RBACDenialReason` body). These regressions defend:

  - Every one of the 9 :data:`RBACDenialType` values emits BOTH a
    structured log AND a chain row via the shared
    ``_emit_denial_or_500`` helper.
  - The ``tenant_id`` argument is explicit on every emit per the
    design spec P1 #5: resolved actor → ``actor.tenant_id``; unauth
    path → ``None`` (chain row carries NULL; SSE subscribers filter
    by tenant so unauth denials never reach any tenant's stream).
  - Fail-closed 500: if ``broker.emit_rbac_denial`` raises, the RBAC
    dep raises ``HTTPException(500, detail={"reason":
    "rbac_denial_emit_failed"})`` instead of swallowing the
    audit-loss silently.
  - The T6 portal request-id middleware mints a ``portal-req-<uuid4>``
    onto ``request.state.request_id`` for every ``/api/v1/*`` path.
  - ``ActorBinder.bind`` Protocol stays sync per P1 #4 — only the
    ``_bind_actor`` wrapper is async.

Cross-directory imports: helpers come from the T6-owned
``tests/unit/portal/api/ui/sse_test_helpers.py`` (per the R6 #1
task-ordering fix).
"""

from __future__ import annotations

from typing import Any, get_args
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI

# Sprint-7B.4 T6 wire-shape: `httpx` removed — every request goes
# through `_async_client(...)` (httpx 0.28+ ASGITransport wrapper)
# so the bare module name is not referenced anywhere in this file.
from cognic_agentos.protocol.ui_events import RBACDenialType, UIEventBroker
from tests.unit.portal.api.ui.sse_test_helpers import (
    _async_client,
    _read_recent_decision_history_rows,
)


class TestRBACDenialDualSurfaceEmission:
    """Each of the 9 :data:`RBACDenialType` values must emit BOTH a
    structured log record (operations surface, ALWAYS) AND a chain
    row (examiner surface, when broker wired). Pinned via the
    parametrized 9-branch denial dispatcher in `conftest.py`."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("denial_type", list(get_args(RBACDenialType)))
    async def test_each_denial_type_emits_log_then_chain_row(
        self,
        app_with_broker: FastAPI,
        caplog: pytest.LogCaptureFixture,
        denial_type: str,
        _setup_denial_path: Any,
    ) -> None:
        import logging

        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.rbac.enforcement")
        # Dispatcher returns (method, path, kwargs) for THIS denial type;
        # hardcoding POST /api/v1/packs/drafts would only exercise 1/9
        # branches.
        method, path, kwargs = _setup_denial_path(app_with_broker, denial_type)
        async with _async_client(app_with_broker) as c:
            await c.request(method, path, **kwargs)

        # Surface 1: structured log. Match on EITHER the new wire-shape
        # message (`portal.rbac.<denial_type>`) OR the structured
        # `reason` attribute (defence-in-depth for emissions from
        # adjacent test contexts).
        log_key = f"portal.rbac.{denial_type}"
        matched_logs = [
            r
            for r in caplog.records
            if r.message == log_key or getattr(r, "reason", None) == denial_type
        ]
        assert matched_logs, (
            f"no structured log record matched message={log_key!r} "
            f"OR reason={denial_type!r}; got messages: "
            f"{[r.message for r in caplog.records]}"
        )

        # Surface 2: chain row. SQL column is `event_type`, NOT
        # `decision_type` (Sprint-2 schema; DecisionRecord dataclass
        # field name is mapped to the column at write time).
        rows = await _read_recent_decision_history_rows(app_with_broker)
        matched_rows = [r for r in rows if r.event_type == f"rbac.{denial_type}"]
        assert matched_rows, (
            f"no decision_history chain row with event_type={f'rbac.{denial_type}'!r}; "
            f"got event_types: {[r.event_type for r in rows]}"
        )


class TestRBACDenialTenantRouting:
    """Design spec P1 #5 — explicit ``tenant_id`` on every
    ``emit_rbac_denial`` call. Resolved actor → ``actor.tenant_id``;
    unauth path (no actor resolved) → ``None``. Chain rows with
    ``tenant_id=None`` are audit-only — SSE subscribers filter by
    ``event.tenant`` so they never reach any tenant's stream by
    design (documented in the closeout's "Out of scope" section)."""

    @pytest.mark.asyncio
    async def test_resolved_actor_passes_tenant_to_emit(
        self,
        app_with_broker: FastAPI,
        broker: UIEventBroker,
        _setup_denial_path: Any,
    ) -> None:
        # scope_not_held branch: actor IS resolved (tenant_id="t1");
        # route requires `pack.allow_list` which the actor lacks.
        method, path, kwargs = _setup_denial_path(app_with_broker, "scope_not_held")
        spy = AsyncMock(wraps=broker.emit_rbac_denial)
        broker.emit_rbac_denial = spy  # type: ignore[method-assign]
        async with _async_client(app_with_broker) as c:
            await c.request(method, path, **kwargs)
        spy.assert_awaited_once()
        assert spy.await_args is not None  # mypy narrowing for next line
        assert spy.await_args.kwargs["tenant_id"] == "t1"

    @pytest.mark.asyncio
    async def test_unauthenticated_emits_with_tenant_none(
        self,
        app_with_broker: FastAPI,
        broker: UIEventBroker,
        _setup_denial_path: Any,
    ) -> None:
        # actor_unauthenticated branch: binder raises
        # ActorBinderUnauthenticated; no actor resolved → tenant_id=None.
        method, path, kwargs = _setup_denial_path(app_with_broker, "actor_unauthenticated")
        spy = AsyncMock(wraps=broker.emit_rbac_denial)
        broker.emit_rbac_denial = spy  # type: ignore[method-assign]
        async with _async_client(app_with_broker) as c:
            await c.request(method, path, **kwargs)
        spy.assert_awaited_once()
        assert spy.await_args is not None  # mypy narrowing for next line
        assert spy.await_args.kwargs["tenant_id"] is None


class TestRBACDenialFailClosedOnEmitFailure:
    """If ``broker.emit_rbac_denial`` raises, the RBAC dep MUST raise
    ``HTTPException(500, detail={"reason": "rbac_denial_emit_failed"})``
    — NOT silently swallow the audit-loss. Pinned by threat-model-revert
    (see commit message).
    """

    @pytest.mark.asyncio
    async def test_emit_failure_raises_500_not_silent(
        self,
        app_with_broker: FastAPI,
        broker: UIEventBroker,
        monkeypatch: pytest.MonkeyPatch,
        _setup_denial_path: Any,
    ) -> None:
        # scope_not_held branch is guaranteed to reach
        # broker.emit_rbac_denial (which the monkeypatch forces to raise).
        method, path, kwargs = _setup_denial_path(app_with_broker, "scope_not_held")
        monkeypatch.setattr(
            broker,
            "emit_rbac_denial",
            AsyncMock(side_effect=RuntimeError("simulated DB outage")),
        )
        async with _async_client(app_with_broker) as c:
            r = await c.request(method, path, **kwargs)
        assert r.status_code == 500
        assert r.json()["detail"]["reason"] == "rbac_denial_emit_failed"


class TestRequestIdMiddleware:
    """The T6 portal request-id middleware mints
    ``portal-req-<uuid4.hex>`` (42 chars ≤ 64 column cap) onto
    ``request.state.request_id`` for every ``/api/v1/*`` path.
    Verified by triggering a denial and reading the emitted log
    record's ``request_id`` field — the same id the chain row
    carries."""

    @pytest.mark.asyncio
    async def test_middleware_mints_portal_req_id_for_api_v1(
        self,
        app_with_broker: FastAPI,
        caplog: pytest.LogCaptureFixture,
        _setup_denial_path: Any,
    ) -> None:
        import logging

        caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.rbac.enforcement")
        method, path, kwargs = _setup_denial_path(app_with_broker, "scope_not_held")
        async with _async_client(app_with_broker) as c:
            await c.request(method, path, **kwargs)

        denial_logs = [r for r in caplog.records if r.message == "portal.rbac.scope_not_held"]
        assert denial_logs, "expected at least one scope_not_held denial log"
        # `request_id` is injected onto every LogRecord by the
        # observability layer's `_ContextFilter` (see
        # `cognic_agentos/observability/logging.py:43-44`) — not part
        # of LogRecord's static type so we read it via getattr.
        request_id: str = denial_logs[0].request_id  # type: ignore[attr-defined]
        assert request_id.startswith("portal-req-"), (
            f"request_id must come from the T6 portal middleware "
            f"('portal-req-' prefix); got {request_id!r}"
        )
        # `portal-req-` (11 chars) + 32-char uuid4.hex = 43 chars total;
        # the design spec says 42 ≤ len ≤ 64. Defence-in-depth for the
        # request_id column cap.
        assert 42 <= len(request_id) <= 64, (
            f"request_id length {len(request_id)} outside [42, 64]; got {request_id!r}"
        )


class TestSyncBinderContractPreserved:
    """Design spec P1 #4 — :meth:`ActorBinder.bind` stays sync; only
    the ``_bind_actor`` wrapper is async. Pinned by inspecting the
    Protocol's ``bind`` callable — if a future refactor accidentally
    converts it to async, this AST-level regression fires."""

    def test_actor_binder_protocol_bind_is_sync(self) -> None:
        import inspect

        from cognic_agentos.portal.rbac.actor import ActorBinder

        assert not inspect.iscoroutinefunction(ActorBinder.bind), (
            "ActorBinder.bind MUST stay sync per design spec P1 #4 "
            "(_bind_actor wraps it in an async function; the Protocol "
            "itself is unchanged from Sprint 7B.2)"
        )

    def test_kernel_default_actor_binder_bind_is_sync(self) -> None:
        import inspect

        from cognic_agentos.portal.rbac.actor import KernelDefaultActorBinder

        assert not inspect.iscoroutinefunction(KernelDefaultActorBinder.bind), (
            "KernelDefaultActorBinder.bind MUST stay sync (mirrors the Protocol contract above)"
        )
