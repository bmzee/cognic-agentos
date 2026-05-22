"""Sprint 9 — compliance route-package composition + shared deps (ADR-006).

`from __future__ import annotations` is DELIBERATELY OMITTED — FastAPI
resolves `Annotated[..., Depends(<closure-local>)]` via inspect.signature;
PEP-563 string annotations break that (standing portal-route invariant —
see portal/api/ui/router.py).
"""

from fastapi import APIRouter, HTTPException, Request

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters import Adapters


def _require_adapters(request: Request) -> Adapters:
    """Request-time resolver for the live adapter pool. `app.state.adapters`
    is populated by the lifespan AFTER router mount, so it cannot be
    closure-captured at build time. Fails loud 503 when adapters are not
    built (e.g. create_app called without an adapter_registry). The
    evidence-pack exporter needs both adapters.relational.engine AND
    adapters.secret (vault:// signing-key resolution), so the dependency
    resolves the whole pool per spec §7's request-time adapter dependency."""
    adapters: Adapters | None = getattr(request.app.state, "adapters", None)
    if adapters is None:
        raise HTTPException(status_code=503, detail={"reason": "compliance_adapters_unavailable"})
    return adapters


def build_compliance_routes(*, settings: Settings) -> APIRouter:
    """Compose the examiner compliance endpoints into one router. T6
    wires the evidence-pack endpoint; T7 extends this with the trace
    explorer (the `build_trace_routes` include is added in T7 Step 3)."""
    from cognic_agentos.portal.api.compliance.evidence_pack_routes import (
        build_evidence_pack_routes,
    )
    from cognic_agentos.portal.api.compliance.trace_routes import build_trace_routes

    router = APIRouter()
    router.include_router(build_evidence_pack_routes(settings=settings))
    router.include_router(build_trace_routes(settings=settings))
    return router
