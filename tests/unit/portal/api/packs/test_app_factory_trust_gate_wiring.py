"""Sprint 7B.3 T9 — ``create_app`` trust-gate + trust-root-resolver wiring.

``create_app`` gains two optional kwargs (``trust_gate`` /
``trust_root_resolver``); both are attached to ``app.state`` (mirroring
the ``app.state.actor_binder`` pattern) AND threaded into
``build_packs_router``. When omitted both default ``None`` — the
approve handler then resolves Gate 1 to a ``red`` SignatureGateInput
rather than crashing (fail-closed). The pack router still mounts
without them — they are independent of the actor-binder + store mount
gate.
"""

from __future__ import annotations

import inspect

from fastapi.testclient import TestClient

from cognic_agentos.portal.api.app import create_app
from tests.unit.portal.api.packs._approve_test_support import (
    StubBinder,
    StubTrustGate,
    StubTrustRootResolver,
    make_actor,
)


class _StubStore:
    """Bare :class:`PackRecordStore` stand-in for the mount-decision
    smoke tests (no store method is invoked at construction time)."""


class TestSprint7B3T9CreateAppTrustGateWiring:
    """``create_app`` accepts, defaults, and attaches the T9 kwargs."""

    def test_signature_has_trust_gate_and_resolver_defaulting_none(self) -> None:
        params = inspect.signature(create_app).parameters
        for name in ("trust_gate", "trust_root_resolver"):
            assert name in params, f"create_app missing {name}"
            assert params[name].kind is inspect.Parameter.KEYWORD_ONLY
            assert params[name].default is None

    def test_app_state_carries_trust_gate_and_resolver_after_startup(self) -> None:
        gate = StubTrustGate()
        resolver = StubTrustRootResolver()
        app = create_app(
            actor_binder=StubBinder(make_actor()),
            pack_record_store=_StubStore(),  # type: ignore[arg-type]
            trust_gate=gate,  # type: ignore[arg-type]
            # StubTrustRootResolver structurally satisfies the runtime-
            # checkable TrustRootResolver Protocol — no ignore needed.
            trust_root_resolver=resolver,
        )
        # ``app.state.*`` is attached inside the lifespan — enter the
        # TestClient context so lifespan startup runs.
        with TestClient(app):
            assert app.state.trust_gate is gate
            assert app.state.trust_root_resolver is resolver

    def test_app_state_trust_gate_and_resolver_default_none(self) -> None:
        app = create_app(
            actor_binder=StubBinder(make_actor()),
            pack_record_store=_StubStore(),  # type: ignore[arg-type]
        )
        with TestClient(app):
            assert app.state.trust_gate is None
            assert app.state.trust_root_resolver is None

    def test_pack_router_still_mounts_without_trust_gate(self) -> None:
        # The trust-gate kwargs are independent of the actor_binder +
        # pack_record_store mount gate — the router mounts regardless.
        app = create_app(
            actor_binder=StubBinder(make_actor()),
            pack_record_store=_StubStore(),  # type: ignore[arg-type]
        )
        assert app.state.pack_router_mounted is True
        compiled = {getattr(route, "path", "") for route in app.routes}
        assert "/api/v1/packs/{pack_id}/approve" in compiled
