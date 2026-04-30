"""Sprint 3 portal surface: ``/api/v1/system/*`` route handlers.

Layer classification: **portal surface**.

Holds the operator-facing policy + provider-honesty endpoints split
out from ``app.py`` so the test surface can grow without crowding the
factory:

- T8: ``GET /api/v1/system/policy`` — the cloud-policy posture
  snapshot. Returns the operator-declared knobs the gateway uses to
  decide allow/deny on every call. Read-only; reflects current
  ``Settings``. Per ADR-007 this is the *intent* surface; the
  authoritative *outcome* surface is :func:`/api/v1/system/effective-
  routing` (T9), which reads from the ``gateway_call_ledger``.
- T9 (next commit): ``GET /api/v1/system/effective-routing`` — the
  outcome-of-record surface. Reads the ledger as authoritative;
  surfaces alias / model_string / api_base / external / provenance
  for recent calls within the configured window.

The two endpoints stay co-located so future operator-portal additions
(kill switches, quota status, etc.) can land in this module rather
than re-densifying ``app.py``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from cognic_agentos.core.config import Settings


def build_system_router(settings: Settings) -> APIRouter:
    """Build the ``/api/v1/system/*`` router.

    Settings are bound at router-construction time (not at request
    time) so the closure shape mirrors :func:`_build_router` in
    ``app.py``. Tests inject a different ``Settings`` by passing a
    custom instance to :func:`create_app`, which re-builds the router.
    """

    router = APIRouter(prefix=f"{settings.api_prefix}/system", tags=["system"])

    @router.get("/policy", summary="Cloud-policy posture (intent)")
    async def policy() -> dict[str, Any]:
        """Return the current cloud-policy posture per ADR-007.

        The response reflects the operator-declared *intent* knobs the
        gateway consults on every call. Pairs with
        ``/api/v1/system/effective-routing`` (T9) which reports the
        actual *outcome* observed from the ``gateway_call_ledger``.

        Returns:
            A flat dict with the cloud-policy enforcement surface and
            the alias contract. Field naming follows the operator-
            facing vocabulary (``mode`` rather than ``policy_mode``)
            so portal UIs and audit integrations have a stable shape.
        """

        return {
            "allow_external_llm": settings.allow_external_llm,
            "mode": settings.policy_mode,
            "allowed_providers": list(settings.allowed_providers),
            "llm_guardrail_scope": settings.llm_guardrail_scope,
            "tier1_alias": settings.tier1_alias,
            "tier2_alias": settings.tier2_alias,
            "provider_honesty_ledger_window_minutes": (
                settings.provider_honesty_ledger_window_minutes
            ),
        }

    return router


__all__ = ("build_system_router",)
