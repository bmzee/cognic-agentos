"""Sprint 7B.3 T9 — ``build_review_routes`` / ``build_packs_router``
trust-gate + trust-root-resolver wiring (R1 P2 #3 + R2 P2 #1).

The approve endpoint's gate-1 (cosign signature) resolution needs a
:class:`~cognic_agentos.protocol.trust_gate.TrustGate` verifier + a
:class:`~cognic_agentos.protocol.trust_root_resolver.TrustRootResolver`.
Both are threaded ``create_app`` → ``build_packs_router`` →
``build_review_routes`` → the handler closure. This file pins the two
intermediate factory signatures: both kwargs present, keyword-only,
defaulting ``None``, AND backward-compatible (the T5/T6 ``store=``-only
call sites must still build).
"""

from __future__ import annotations

import inspect

from fastapi import FastAPI

from cognic_agentos.portal.api.packs import build_packs_router
from cognic_agentos.portal.api.packs.review_routes import build_review_routes
from tests.unit.portal.api.packs._approve_test_support import (
    StubTrustGate,
    StubTrustRootResolver,
)


class _StubStore:
    """Bare :class:`PackRecordStore` stand-in — the factory builders do
    not invoke store methods at build time."""


_APPROVE_PATH = "/api/v1/packs/{pack_id}/approve"


class TestSprint7B3T9BuildReviewRoutesWiring:
    """``build_review_routes`` accepts + defaults the two T9 kwargs."""

    def test_signature_has_trust_gate_and_resolver_keyword_only(self) -> None:
        params = inspect.signature(build_review_routes).parameters
        for name in ("trust_gate", "trust_root_resolver"):
            assert name in params, f"build_review_routes missing {name}"
            assert params[name].kind is inspect.Parameter.KEYWORD_ONLY
            assert params[name].default is None

    def test_store_only_call_still_builds(self) -> None:
        # Backward-compat — the T5/T6 call sites pass ``store=`` only.
        router = build_review_routes(store=_StubStore())  # type: ignore[arg-type]
        assert router is not None

    def test_accepts_real_stub_instances(self) -> None:
        router = build_review_routes(
            store=_StubStore(),  # type: ignore[arg-type]
            trust_gate=StubTrustGate(),  # type: ignore[arg-type]
            # StubTrustRootResolver structurally satisfies the runtime-
            # checkable TrustRootResolver Protocol — no ignore needed.
            trust_root_resolver=StubTrustRootResolver(),
        )
        assert router is not None


class TestSprint7B3T9BuildPacksRouterWiring:
    """``build_packs_router`` accepts + threads the two T9 kwargs."""

    def test_signature_has_trust_gate_and_resolver_keyword_only(self) -> None:
        params = inspect.signature(build_packs_router).parameters
        for name in ("trust_gate", "trust_root_resolver"):
            assert name in params, f"build_packs_router missing {name}"
            assert params[name].kind is inspect.Parameter.KEYWORD_ONLY
            assert params[name].default is None

    def test_store_only_call_still_registers_approve_route(self) -> None:
        router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
        app = FastAPI()
        app.include_router(router)
        compiled = {getattr(route, "path", "") for route in app.routes}
        assert _APPROVE_PATH in compiled

    def test_threading_stubs_through_still_registers_approve_route(self) -> None:
        router = build_packs_router(
            store=_StubStore(),  # type: ignore[arg-type]
            trust_gate=StubTrustGate(),  # type: ignore[arg-type]
            # StubTrustRootResolver structurally satisfies the runtime-
            # checkable TrustRootResolver Protocol — no ignore needed.
            trust_root_resolver=StubTrustRootResolver(),
        )
        app = FastAPI()
        app.include_router(router)
        compiled = {getattr(route, "path", "") for route in app.routes}
        assert _APPROVE_PATH in compiled
        # The approve route is a POST (the T5 stub was POST; T9 keeps it).
        approve_methods = {
            method
            for route in app.routes
            if getattr(route, "path", "") == _APPROVE_PATH
            for method in getattr(route, "methods", set())
        }
        assert "POST" in approve_methods
