"""Wave-1 T6 — adversarial pass-rate floor: parameterization + caller threading.

The gate-3 (adversarial) floor was a baked ``0.99`` in ``review_routes.py``; T6
makes it the operator-configured ``Settings.adversarial_pass_rate_floor``,
threaded ``create_app → build_packs_router → build_review_routes → the approve
handler closure`` (mirrors the ``trust_gate`` thread). These tests pin:

1. ``_build_adversarial_gate_input`` honours its ``pass_rate_floor`` parameter
   (the SAME pass-rate is red against a tighter floor, green against a looser).
2. ``build_packs_router`` forwards the floor to ``build_review_routes``.
3. ``create_app`` threads ``settings.adversarial_pass_rate_floor`` (the captured
   ``settings``, NOT ``get_settings()``) into ``build_packs_router``.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import APIRouter
from fastapi.testclient import TestClient

from cognic_agentos.core.config import Settings
from cognic_agentos.packs.storage import PackRecordStore
from cognic_agentos.portal.api import app as app_module
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.api.packs import router as router_module
from cognic_agentos.portal.api.packs.review_routes import _build_adversarial_gate_input
from tests.unit.portal.api.packs._approve_test_support import (
    StubBinder,
    approve_body,
    build_app,
    make_actor,
    seed_under_review_pack,
)


class _StubStore:
    """Bare ``PackRecordStore`` stand-in — no method is invoked at router
    construction time (the store is captured in a closure)."""


def test_pass_rate_floor_parameter_drives_outcome() -> None:
    # pass_rate 0.995: BELOW a 0.999 floor → red; AT/ABOVE the 0.99 kernel floor → green.
    raw = {
        "pass_rate": 0.995,
        "high_severity_failures": 0,
        "regressions": 0,
        "regression_evaluated": False,
        "candidate_run_id": "run-13c",
        "baseline_run_id": None,
    }

    strict = _build_adversarial_gate_input(raw, pass_rate_floor=0.999)
    assert strict.outcome == "red"
    assert strict.red_reason == "adversarial_corpus_pass_rate_below_threshold"

    lenient = _build_adversarial_gate_input(raw, pass_rate_floor=0.99)
    assert lenient.outcome == "green"


def test_build_packs_router_forwards_floor_to_review(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, float | None] = {}

    def _capture(**kwargs: object) -> APIRouter:
        captured["floor"] = kwargs.get("adversarial_pass_rate_floor")  # type: ignore[assignment]
        return APIRouter()

    monkeypatch.setattr(router_module, "build_review_routes", _capture)
    router_module.build_packs_router(store=_StubStore(), adversarial_pass_rate_floor=0.997)  # type: ignore[arg-type]
    assert captured["floor"] == 0.997


def test_create_app_threads_settings_floor_to_packs_router(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, float | None] = {}

    def _capture(**kwargs: object) -> APIRouter:
        captured["floor"] = kwargs.get("adversarial_pass_rate_floor")  # type: ignore[assignment]
        return APIRouter()

    monkeypatch.setattr(app_module, "build_packs_router", _capture)
    # A configured (tighter-than-default) floor proves the value came from the
    # PASSED settings, not get_settings() (which would yield the 0.99 default).
    create_app(
        settings=Settings(runtime_profile="dev", adversarial_pass_rate_floor=0.997),
        actor_binder=StubBinder(make_actor()),
        pack_record_store=_StubStore(),  # type: ignore[arg-type]
    )
    assert captured["floor"] == 0.997


def _adversarial_gate(detail: dict[str, Any]) -> dict[str, Any]:
    return next(g for g in detail["gates"] if g["gate"] == "adversarial")


async def test_approve_handler_threads_configured_floor_to_gate3(store: PackRecordStore) -> None:
    """The FINAL closure hop, end-to-end: the approve handler passes the
    ``build_review_routes``-captured floor into ``_build_adversarial_gate_input``.

    A pack with adversarial ``pass_rate=0.995`` resolves gate-3 RED under a
    configured ``0.999`` floor but GREEN under the default ``0.99`` kernel floor —
    proving the configured floor reaches the gate DECISION through the full
    ``create_app → build_packs_router → build_review_routes → approve handler``
    thread. A regression dropping the handler's ``pass_rate_floor=`` arg would
    make BOTH green (the helper's default), failing the strict half.
    """
    pass_rate_995 = {
        "pass_rate": 0.995,
        "high_severity_failures": 0,
        "regressions": 0,
        "regression_evaluated": False,
        "candidate_run_id": "run-13c",
        "baseline_run_id": None,
    }
    record_strict = await seed_under_review_pack(store, adversarial=pass_rate_995)
    record_default = await seed_under_review_pack(store, adversarial=pass_rate_995)

    # Configured tighter floor 0.999 → 0.995 is below → gate-3 RED.
    app_strict = create_app(
        settings=Settings(runtime_profile="dev", adversarial_pass_rate_floor=0.999),
        actor_binder=StubBinder(make_actor()),
        pack_record_store=store,
    )
    with TestClient(app_strict) as client:
        resp = client.post(f"/api/v1/packs/{record_strict.id}/approve", json=approve_body())
    assert resp.status_code == 412, resp.text  # not all green (gate-1 signature also red)
    gate = _adversarial_gate(resp.json()["detail"])
    assert gate["outcome"] == "red"
    assert gate["red_reason"] == "adversarial_corpus_pass_rate_below_threshold"

    # Default kernel floor 0.99 (via build_app — no settings override) → 0.995 is
    # at/above the floor → gate-3 GREEN.
    app_default = build_app(actor=make_actor(), store=store)
    with TestClient(app_default) as client:
        resp = client.post(f"/api/v1/packs/{record_default.id}/approve", json=approve_body())
    assert resp.status_code == 412, resp.text
    gate = _adversarial_gate(resp.json()["detail"])
    assert gate["outcome"] == "green"
