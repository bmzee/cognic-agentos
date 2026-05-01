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
- T9: ``GET /api/v1/system/effective-routing`` — the outcome-of-
  record surface. Reads the ledger as authoritative; surfaces alias /
  model_string / api_base / external / provenance for recent calls
  within the configured window. Per ADR-007 §"two layers" this
  endpoint NEVER fails closed on missing data — when no ledger is
  attached or no calls have been made, the response is still 200
  with empty aggregates + the intent surface from settings.

The two endpoints stay co-located so future operator-portal additions
(kill switches, quota status, etc.) can land in this module rather
than re-densifying ``app.py``.

Round-6 reviewer-P1: ``upstream_api_base`` and ``provenance`` are
read FROM the ledger row, NEVER re-resolved against current YAML at
request time. Historical rows stay authoritative even if the
operator rotates ``infra/litellm/config.yaml`` between the call and
the read.

Round-7 reviewer-P1: PROFILE-chip drift detection filters to
``provenance != "no_dispatch"`` (post-dispatch states only —
``resolved`` + ``unresolved`` + ``ambiguous``). Pre-dispatch best-
effort rows carry ``no_dispatch`` and reflect intended preflight
identity from a denial / guardrail trip / concurrency exhaustion;
they did not contact the upstream and must not count toward drift.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from fastapi import APIRouter, Request

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters import Adapters
from cognic_agentos.llm.ledger import GatewayCallLedger, GatewayCallRow

logger = logging.getLogger(__name__)


def _intent_label(settings: Settings) -> str:
    """Operator-declared intent: ``self-hosted`` if external is
    closed, ``cloud`` otherwise. Cloud sub-modes (``cloud_openai`` /
    ``cloud_anthropic`` / ``cloud_mixed``) all collapse to the
    operator-facing ``cloud`` label here — sub-mode detail is on the
    /policy endpoint."""
    return "self-hosted" if not settings.allow_external_llm else "cloud"


def _drift_count(rows: list[GatewayCallRow], settings: Settings) -> int:
    """Count post-dispatch rows that violate the operator's intent.

    Round-7 reviewer-P1: filter to ``provenance != "no_dispatch"``.
    The drift signal is "operator said self-hosted, but the ledger
    has post-dispatch external rows". Cloud-intent operators don't
    raise a drift chip here — non-allow-listed actual upstreams fail
    loudly via the gateway's post-response policy recheck (T6) +
    audit_event(gateway.cloud_policy_denied).
    """
    if settings.allow_external_llm:
        return 0
    return sum(1 for r in rows if r.provenance != "no_dispatch" and r.external)


async def _probe_langfuse(adapters: Adapters | None) -> bool:
    """Opportunistic Langfuse availability flag.

    ADR-007 §"two layers": Langfuse is enrichment, not the
    authoritative source. The ``/effective-routing`` honesty claim
    NEVER depends on Langfuse being up. Probe failure → ``false``;
    the rest of the body is unaffected.
    """
    if adapters is None:
        return False
    try:
        health = await adapters.observability.health_check()
    except Exception:
        # Opportunistic probe — never raise into the response per
        # ADR-007 §"two layers" (Langfuse is enrichment, not the
        # authoritative source).
        logger.exception("langfuse health probe raised; reporting unavailable")
        return False
    return health.status == "ok"


def _row_dict(row: GatewayCallRow) -> dict[str, Any]:
    """Stable per-row JSON shape. Field naming mirrors the ledger
    column names so operators searching the audit trail see the same
    keys here and in their database tooling. Round-6 reviewer-P1:
    api_base + provenance come from the persisted row."""
    return {
        "ts": row.ts.isoformat(),
        "request_id": row.request_id,
        "tenant_id": row.tenant_id,
        "tier": row.tier,
        "litellm_alias": row.litellm_alias,
        "upstream_model": row.upstream_model,
        "upstream_api_base": row.upstream_api_base,
        "external": row.external,
        "provenance": row.provenance,
        "outcome": row.outcome,
        "latency_ms": row.latency_ms,
    }


def build_system_router(settings: Settings) -> APIRouter:
    """Build the ``/api/v1/system/*`` router.

    Settings are bound at router-construction time (not at request
    time) so the closure shape mirrors :func:`_build_router` in
    ``app.py``. The ledger + adapters dependencies are read off
    ``request.app.state`` at request time so the lifespan injects
    them once at startup.
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

    @router.get(
        "/effective-routing",
        summary="Provider-honesty outcome surface (authoritative)",
    )
    async def effective_routing(request: Request) -> dict[str, Any]:
        """Return the ledger-authoritative provider-honesty surface
        per ADR-007.

        The response carries:
          * ``recent_calls_window_minutes`` — the operator-configured
            window (``settings.provider_honesty_ledger_window_minutes``).
          * ``recent_calls`` — ``upstream_model`` → count map across
            all rows in window.
          * ``recent_call_details`` — per-row detail (Round-6 P1: the
            persisted ``upstream_api_base`` + ``provenance``, NOT
            re-resolved from current YAML).
          * ``profile`` — the operator chip with ``intent`` (from
            settings), ``post_dispatch_count`` (provenance !=
            ``no_dispatch``), ``drift_count`` (intent=self-hosted
            with external post-dispatch rows present), and ``chip``
            (the human-facing label, e.g. ``self-hosted (DRIFT)``).
          * ``langfuse_available`` — opportunistic Langfuse probe.
            Reflects enrichment availability; the honesty claim never
            depends on it.

        Returns 200 in every case the route is reachable. Per ADR-007
        the honesty surface NEVER fails closed on missing data; the
        operator sees an honest empty picture, not an outage.
        """

        ledger: GatewayCallLedger | None = getattr(request.app.state, "gateway_ledger", None)
        adapters: Adapters | None = getattr(request.app.state, "adapters", None)

        window = settings.provider_honesty_ledger_window_minutes
        rows: list[GatewayCallRow] = []
        if ledger is not None:
            rows = await ledger.read_recent_calls(window_minutes=window)

        counts = Counter(r.upstream_model for r in rows)
        post_dispatch_rows = [r for r in rows if r.provenance != "no_dispatch"]
        drift_count = _drift_count(rows, settings)
        intent = _intent_label(settings)
        chip = f"{intent} (DRIFT)" if drift_count > 0 else intent

        langfuse_available = await _probe_langfuse(adapters)

        return {
            "recent_calls_window_minutes": window,
            "recent_calls": dict(counts),
            "recent_call_details": [_row_dict(r) for r in rows],
            "profile": {
                "intent": intent,
                "post_dispatch_count": len(post_dispatch_rows),
                "drift_count": drift_count,
                "chip": chip,
            },
            "langfuse_available": langfuse_available,
        }

    return router


__all__ = ("build_system_router",)
