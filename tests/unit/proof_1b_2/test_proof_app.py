"""Unit tests for the Proof 1b-2 proof-only ActorBinder + create_proof_app factory.

These pin the proof-only fixed-Actor binder (tenant ``proof-1b-2`` + EXACTLY the
two ``mcp.tool.*`` scopes) and the thin ``create_proof_app`` factory that overlays
``app.state.actor_binder`` onto the NORMAL kernel app — proving the proof harness
does NOT fork kernel runtime behavior and is NOT kernel product code.
"""

from __future__ import annotations

from fastapi import FastAPI

from tests.integration.proof_1b_2.proof_app import (
    PROOF_SCOPES,
    PROOF_TENANT,
    ProofActorBinder,
)


def test_binder_yields_fixed_proof_actor() -> None:
    actor = ProofActorBinder().bind(request=None)
    assert actor.tenant_id == PROOF_TENANT == "proof-1b-2"
    assert set(actor.scopes) == PROOF_SCOPES == {"mcp.tool.list", "mcp.tool.invoke"}
    assert actor.actor_type == "service"


def test_scopes_are_exactly_the_two_mcp_tool_scopes() -> None:
    # guardrail: no broader grant leaks in
    assert ProofActorBinder().bind(request=None).scopes == frozenset(
        {"mcp.tool.list", "mcp.tool.invoke"}
    )


def test_proof_app_module_is_proof_only_not_kernel() -> None:
    # HARD BAR item 5 — pin that the binder/factory live in the PROOF harness
    # (under tests/), NOT the kernel (src/cognic_agentos/). Production still
    # requires a real bank-overlay ActorBinder; this binder is proof-only.
    import tests.integration.proof_1b_2.proof_app as proof_app

    module_file = proof_app.__file__
    assert module_file is not None
    assert "/tests/" in module_file
    assert "/src/cognic_agentos/" not in module_file
    # The proof-only caveat lives in the module docstring.
    assert proof_app.__doc__ is not None
    assert "bank-overlay ActorBinder" in proof_app.__doc__


def test_create_proof_app_overlays_only_the_actor_binder() -> None:
    # HARD BAR item 6 — smoke the factory. create_app builds adapters in the
    # FastAPI lifespan (build_adapters_async at app.py:641), NOT at construction,
    # so the factory can be called in a unit test without a live DB/engine.
    from tests.integration.proof_1b_2.proof_app import create_proof_app

    app = create_proof_app()
    assert isinstance(app, FastAPI)
    assert isinstance(app.state.actor_binder, ProofActorBinder)
