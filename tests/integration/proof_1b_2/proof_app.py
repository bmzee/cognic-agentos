"""PROOF-ONLY app factory + fixed-actor binder for Proof 1b-2.

NOT kernel product behavior. Production requires a real bank-overlay ActorBinder
(OIDC/mTLS-backed). This binder yields ONE fixed Actor scoped to the proof tenant
and exactly the two MCP tool scopes, so the deployed governed MCP invoke route
(/api/v1/mcp/...) can be driven end-to-end. It does NOT fork runtime behavior —
it calls the normal create_app() and only sets app.state.actor_binder.
"""

from __future__ import annotations

from typing import Final

from fastapi import FastAPI, Request

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.scopes import MCPRBACScope

PROOF_TENANT: Final = "proof-1b-2"
# Precise element type (vs the plan's bare ``Final``) so strict mypy accepts the
# standalone constant at the ``Actor(scopes=...)`` call site: a bare ``Final``
# infers ``frozenset[str]``, which is NOT assignable to the typed ``Actor.scopes``
# field. ``frozenset`` is covariant, so ``frozenset[MCPRBACScope]`` IS assignable
# to the wider scope-union field. Same repo idiom as ``MCP_SCOPES`` (scopes.py).
PROOF_SCOPES: Final[frozenset[MCPRBACScope]] = frozenset({"mcp.tool.list", "mcp.tool.invoke"})


class ProofActorBinder:
    """Yields a single fixed proof Actor for every request. PROOF-ONLY."""

    def bind(self, *, request: Request | None) -> Actor:  # matches the kernel ActorBinder Protocol
        return Actor(
            subject="proof-1b-2-operator",
            tenant_id=PROOF_TENANT,
            scopes=PROOF_SCOPES,
            actor_type="service",
        )


def create_proof_app() -> FastAPI:
    # ``bundled_registry`` is the SAME symbol + import path ``create_prod_app``
    # uses (app.py:51 import, app.py:1773 call) — the default-adapters set.
    # Deferred imports keep this module importable (factory-not-called) without
    # a live engine; create_app builds adapters in the lifespan, not here.
    from cognic_agentos.db.adapters import bundled_registry
    from cognic_agentos.portal.api.app import create_app

    app = create_app(adapter_registry=bundled_registry)
    app.state.actor_binder = ProofActorBinder()
    return app
