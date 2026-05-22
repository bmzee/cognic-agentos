"""Sprint 9 — GET /api/v1/compliance/evidence-pack (ADR-006).

`from __future__ import annotations` OMITTED — standing portal-route invariant.
"""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from cognic_agentos.compliance.iso42001.evidence_pack import export_evidence_pack
from cognic_agentos.compliance.iso42001.signing import EvidencePackSigningError
from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters import Adapters
from cognic_agentos.portal.api.compliance.router import _require_adapters
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope


def build_evidence_pack_routes(*, settings: Settings) -> APIRouter:
    router = APIRouter()
    _require_evidence_scope = RequireScope("compliance.evidence_pack.read")

    @router.get(f"{settings.api_prefix}/compliance/evidence-pack")
    async def evidence_pack(
        actor: Annotated[Actor, Depends(_require_evidence_scope)],
        adapters: Annotated[Adapters, Depends(_require_adapters)],
        scope: Annotated[str, Query()],
        from_: Annotated[datetime, Query(alias="from")],
        to: Annotated[datetime, Query(alias="to")],
    ) -> Response:
        # Cross-tenant invisible: an examiner exports ONLY their own
        # tenant's pack. A scope mismatch returns 404 — never a 403 hint
        # that would let a probe enumerate tenant IDs.
        if actor.tenant_id != scope:
            raise HTTPException(status_code=404, detail={"reason": "evidence_pack_not_found"})
        try:
            tarball = await export_evidence_pack(
                engine=adapters.relational.engine,
                tenant_id=scope,
                period_start=from_,
                period_end=to,
                signing_key_path=settings.evidence_pack_signing_key_path,
                secret_adapter=adapters.secret,
            )
        except EvidencePackSigningError as exc:
            # Signing misconfiguration is a server/operator fault — 500,
            # fail-loud; never a silently-unsigned pack.
            raise HTTPException(
                status_code=500,
                detail={"reason": "evidence_pack_signing_failed", "message": str(exc)},
            ) from exc
        return Response(
            content=tarball,
            media_type="application/gzip",
            headers={
                "Content-Disposition": (f'attachment; filename="evidence-pack-{scope}.tar.gz"')
            },
        )

    return router
