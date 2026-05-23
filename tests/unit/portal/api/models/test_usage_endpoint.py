"""Sprint 9.5b C3 — ``GET /api/v1/models/{model_id}/usage``.

**User-locked review bar (PR #35 R2 C3 directive verbatim):**

2. ``/api/v1/models/{model_id}/usage`` requires ``model.usage.read`` +
   ``RequireModelTenantOwnership`` BEFORE any ledger availability check.
3. Cross-tenant / unknown models still collapse to
   ``{"reason": "model_not_found"}``, even when ``gateway_ledger=None``.
4. Missing ledger returns 503 ``gateway_ledger_not_configured`` only
   AFTER scope + tenant gates pass.

The 503 surface is the user-locked PR #35 R2 D7 policy: ``/usage`` is
a documented public endpoint once 9.5b lands; missing backend ledger
returns 503 (route exists, backend not wired) — NOT 404 (would look
like route drift) and NOT silent-skip (would hide the partial config).

Security-gates-first dep-chain ordering: the FastAPI dep chain
resolves ``RequireScope`` + ``RequireModelTenantOwnership`` BEFORE
the handler body, so a missing-scope caller sees 403 + ``scope_not_held``
and a cross-tenant probe sees 404 + ``model_not_found`` — the 503 is
a backend-config signal, NOT a security signal.

Standing-offer §30 invariant: ``from __future__ import annotations``
is safe here — no FastAPI routes are defined inline with closure-local
``Depends`` references; routes invoked via httpx only.
"""

from __future__ import annotations

import datetime as _dt
import uuid
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.llm.ledger import GatewayCallLedger, GatewayCallRow

# Sample model the /usage tests register before probing.
_REGISTER_PAYLOAD = {
    "model_id": "m-u",
    "version": "1",
    "kind": "foundation",
}
_USAGE_QUERY = "?from=2026-01-01T00:00:00Z&to=2027-01-01T00:00:00Z"


# ──────────────────────────────────────────────────────────────────────
# Bar #2 — scope + tenant gates run BEFORE the ledger availability
# check
# ──────────────────────────────────────────────────────────────────────


async def test_usage_requires_model_usage_read_scope(
    make_app: Callable[..., FastAPI],
) -> None:
    """Bar #2 — actor lacking ``model.usage.read`` gets 403
    ``scope_not_held`` regardless of model existence + ledger
    presence. The scope gate is a FastAPI ``Depends`` so it runs
    BEFORE the handler body's 503 check."""
    app = make_app(scopes=frozenset({"model.register"}))  # no usage scope
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        await c.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        r = await c.get(f"/api/v1/models/m-u/usage{_USAGE_QUERY}")
    assert r.status_code == 403
    assert r.json()["detail"]["reason"] == "scope_not_held"


# ──────────────────────────────────────────────────────────────────────
# Bar #3 — cross-tenant / unknown models still collapse to
# ``model_not_found`` even when ``gateway_ledger=None``
# ──────────────────────────────────────────────────────────────────────


async def test_usage_security_gates_run_before_ledger_check(
    make_app: Callable[..., FastAPI],
) -> None:
    """Bar #3 + #4 — cross-tenant probe must see 404
    ``model_not_found`` (the wire-body-collapse contract), NOT 503
    ``gateway_ledger_not_configured``. The 503 would leak that the
    model exists on the wrong tenant — security gate must take
    precedence."""
    # Tenant A registers the model.
    app_a = make_app(scopes=frozenset({"model.register"}))
    async with AsyncClient(transport=ASGITransport(app=app_a), base_url="http://test") as c:
        await c.post("/api/v1/models", json=_REGISTER_PAYLOAD)
    # Tenant B probes /usage with explicit ledger=None.
    app_b = make_app(
        tenant_id="tenant-other",
        scopes=frozenset({"model.usage.read"}),
        gateway_ledger=None,
    )
    async with AsyncClient(transport=ASGITransport(app=app_b), base_url="http://test") as c:
        r = await c.get(f"/api/v1/models/m-u/usage{_USAGE_QUERY}")
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "model_not_found"


async def test_usage_unknown_model_returns_404_even_when_ledger_is_none(
    make_app: Callable[..., FastAPI],
) -> None:
    """Bar #3 — an unknown ``model_id`` (no registered row at all)
    also collapses to 404 ``model_not_found``, NOT 503. Symmetric
    with the cross-tenant case — both render as "model not found"
    so a probe cannot distinguish unknown-model from
    wrong-tenant-known-model from missing-ledger."""
    app = make_app(
        scopes=frozenset({"model.usage.read"}),
        gateway_ledger=None,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        r = await c.get(f"/api/v1/models/m-never-registered/usage{_USAGE_QUERY}")
    assert r.status_code == 404
    assert r.json()["detail"]["reason"] == "model_not_found"


# ──────────────────────────────────────────────────────────────────────
# Bar #4 — missing ledger returns 503 ``gateway_ledger_not_configured``
# AFTER scope + tenant gates pass
# ──────────────────────────────────────────────────────────────────────


async def test_usage_returns_503_when_gateway_ledger_is_none(
    make_app: Callable[..., FastAPI],
) -> None:
    """Bar #4 — user-locked D7 policy. With all security gates
    passed (scope held, tenant matches, model exists), a missing
    ``gateway_ledger`` surfaces as 503 + closed-enum
    ``gateway_ledger_not_configured``. NOT 404 (would look like
    route drift); NOT silent-skip (would hide the partial config)."""
    app = make_app(
        scopes=frozenset({"model.register", "model.usage.read"}),
        gateway_ledger=None,
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        await c.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        r = await c.get(f"/api/v1/models/m-u/usage{_USAGE_QUERY}")
    assert r.status_code == 503
    assert r.json() == {"detail": {"reason": "gateway_ledger_not_configured"}}


# ──────────────────────────────────────────────────────────────────────
# Happy path — ledger present + matching rows + zero-row case
# ──────────────────────────────────────────────────────────────────────


async def test_usage_returns_count_zero_when_no_calls(
    make_app: Callable[..., FastAPI],
) -> None:
    """Backward-compat baseline — when the ledger is wired but no
    matching rows exist in the window, return 200 with count=0.
    Pin the wire shape ``{"model_id": ..., "count": 0}``."""
    app = make_app(scopes=frozenset({"model.register", "model.usage.read"}))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        await c.post("/api/v1/models", json=_REGISTER_PAYLOAD)
        r = await c.get(f"/api/v1/models/m-u/usage{_USAGE_QUERY}")
    assert r.status_code == 200
    assert r.json() == {"model_id": "m-u", "count": 0}


async def test_usage_returns_actual_count_when_ledger_has_matching_rows(
    make_app: Callable[..., FastAPI],
    engine: AsyncEngine,
) -> None:
    """Positive count case — register a model, seed N ledger rows
    with the matching ``model_id``, assert ``/usage`` reports N.
    The conftest's default ``make_app`` wires a real
    ``GatewayCallLedger`` backed by the test engine, so writing
    rows via the same engine surfaces in the response."""
    app = make_app(scopes=frozenset({"model.register", "model.usage.read"}))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        await c.post("/api/v1/models", json=_REGISTER_PAYLOAD)

        # Seed 3 rows with model_id="m-u" + 1 row with a different
        # model_id (proves the exact-match gate at the ledger level).
        ledger = GatewayCallLedger(engine)
        now = _dt.datetime.now(_dt.UTC)
        for _ in range(3):
            await ledger.write_row(_make_ledger_row(model_id="m-u", ts=now))
        await ledger.write_row(_make_ledger_row(model_id="m-other", ts=now))

        r = await c.get(f"/api/v1/models/m-u/usage{_USAGE_QUERY}")
    assert r.status_code == 200
    body = r.json()
    assert body == {"model_id": "m-u", "count": 3}


def _make_ledger_row(*, model_id: str, ts: _dt.datetime) -> GatewayCallRow:
    """Minimal ledger row builder for /usage positive-count tests."""
    return GatewayCallRow(
        id=uuid.uuid4(),
        ts=ts,
        request_id="r",
        tenant_id="tenant-acme",
        tier="tier1",
        litellm_alias="cognic-tier1-dev",
        upstream_model="u",
        upstream_api_base=None,
        external=False,
        provenance="resolved",
        latency_ms=1,
        outcome="ok",
        model_id=model_id,
    )


# Suppress unused-import warnings — Any imported for future use.
_ = Any
