"""Sprint 7B.2 T2 — RequireScope dependency + closed-enum RBACDenialReason.

Pins (plan Round 2 P2 #4 narrowing — STRUCTURED HTTP DENIAL ONLY in 7B.2):

- 3-value closed-enum :data:`RBACDenialReason`:
  ``actor_unauthenticated`` / ``scope_not_held`` / ``actor_binder_not_configured``.
- 403 on ``scope_not_held``: body carries ``reason`` + ``required_scope`` +
  ``actor_subject`` so callers can trace which scope was missing without
  re-binding the actor.
- 403 on ``actor_unauthenticated``: body carries only ``reason`` (no
  actor_subject — there is no resolved actor).
- 500 on ``actor_binder_not_configured`` (kernel misconfig, NOT a client
  error — the bank-overlay binder is not plugged in).
- Application-logging side-effect: structured log record emitted at every
  denial. NOT a hash-chained audit event in 7B.2; full chain emission
  ships in Sprint 7B.4 per plan Round 5 P3 #5 — the denial-event schema
  fits the ``policy.*`` event family slot reserved in
  :file:`src/cognic_agentos/protocol/ui_events.py`.
- Every closed-enum :data:`RBACDenialReason` value has a real emit path
  reachable through a test in this module.
"""

import logging
from typing import Annotated, Any, get_args

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from cognic_agentos.portal.rbac.actor import (
    Actor,
    ActorBinder,
    ActorBinderUnauthenticated,
    KernelDefaultActorBinder,
)
from cognic_agentos.portal.rbac.enforcement import (
    RBACDenialReason,
    RequireScope,
)

# ---------------------------------------------------------------------------
# Closed-enum stability pins
# ---------------------------------------------------------------------------


def test_rbac_denial_reason_literal_frozen_at_3_values() -> None:
    """Plan Round 2 P2 #4 — exactly 3 denial reasons in 7B.2."""
    assert set(get_args(RBACDenialReason)) == {
        "actor_unauthenticated",
        "scope_not_held",
        "actor_binder_not_configured",
    }


# ---------------------------------------------------------------------------
# Test fixtures — minimal FastAPI app + pluggable binders
# ---------------------------------------------------------------------------


class _StubBinder:
    """Test-only binder returning a fixed Actor. Lives in the test module
    per :file:`AGENTS.md` test-fixture-placement rule."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


class _UnauthenticatedBinder:
    """Test-only binder that always raises :class:`ActorBinderUnauthenticated`."""

    def bind(self, *, request: Request) -> Actor:
        raise ActorBinderUnauthenticated("missing bearer token")


def _make_app(binder: ActorBinder, *, required_scope: str) -> FastAPI:
    """Build a minimal app with a single route guarded by ``RequireScope``."""
    app = FastAPI()
    app.state.actor_binder = binder

    dep = RequireScope(required_scope)  # type: ignore[arg-type]

    @app.get("/guarded")
    def guarded(actor: Annotated[Actor, Depends(dep)]) -> dict[str, str]:
        return {"subject": actor.subject}

    return app


def _human_actor(**overrides: Any) -> Actor:
    defaults: dict[str, Any] = {
        "subject": "alice@bank.example",
        "tenant_id": "t1",
        "scopes": frozenset({"pack.submit"}),
        "actor_type": "human",
    }
    defaults.update(overrides)
    return Actor(**defaults)


# ---------------------------------------------------------------------------
# Green-path: scope held → 200 + Actor passed to handler
# ---------------------------------------------------------------------------


def test_require_scope_admits_actor_with_required_scope() -> None:
    actor = _human_actor(scopes=frozenset({"pack.submit"}))
    app = _make_app(_StubBinder(actor), required_scope="pack.submit")
    response = TestClient(app).get("/guarded")
    assert response.status_code == 200
    assert response.json() == {"subject": "alice@bank.example"}


# ---------------------------------------------------------------------------
# Refusal path 1 — actor lacks required scope → 403 scope_not_held
# ---------------------------------------------------------------------------


def test_require_scope_refuses_actor_missing_required_scope() -> None:
    actor = _human_actor(scopes=frozenset({"pack.withdraw"}))
    app = _make_app(_StubBinder(actor), required_scope="pack.submit")
    response = TestClient(app).get("/guarded")
    assert response.status_code == 403
    body = response.json()
    assert body["detail"]["reason"] == "scope_not_held"
    assert body["detail"]["required_scope"] == "pack.submit"
    assert body["detail"]["actor_subject"] == "alice@bank.example"


def test_scope_not_held_denial_emits_structured_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Sprint-7B.4 T6 — denial events emit structured log records via the
    shared ``_emit_denial_or_500`` helper. Wire-shape change: message is
    now ``portal.rbac.<denial_type>`` (e.g. ``portal.rbac.scope_not_held``)
    instead of the previous constant ``portal.rbac.denied``. Structured
    ``reason`` attribute unchanged — operators querying on the structured
    field stay compatible. Hash-chain emission lives at T6 too via the
    same helper; this test covers only the log surface."""
    actor = _human_actor(scopes=frozenset({"pack.withdraw"}))
    app = _make_app(_StubBinder(actor), required_scope="pack.submit")
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.rbac.enforcement"):
        TestClient(app).get("/guarded")
    denied = [r for r in caplog.records if r.message == "portal.rbac.scope_not_held"]
    assert len(denied) == 1
    record = denied[0]
    assert getattr(record, "reason", None) == "scope_not_held"
    assert getattr(record, "required_scope", None) == "pack.submit"
    assert getattr(record, "actor_subject", None) == "alice@bank.example"


# ---------------------------------------------------------------------------
# Refusal path 2 — binder raises ActorBinderUnauthenticated → 403
# ---------------------------------------------------------------------------


def test_require_scope_refuses_unauthenticated_binding() -> None:
    app = _make_app(_UnauthenticatedBinder(), required_scope="pack.submit")
    response = TestClient(app).get("/guarded")
    assert response.status_code == 403
    body = response.json()
    assert body["detail"]["reason"] == "actor_unauthenticated"
    # No actor_subject on unauthenticated denial — no actor was resolved.
    assert "actor_subject" not in body["detail"]


def test_actor_unauthenticated_denial_emits_structured_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Sprint-7B.4 T6 wire-shape: message is now `portal.rbac.<denial_type>`
    # via the shared `_emit_denial_or_500` helper (was `portal.rbac.denied`).
    app = _make_app(_UnauthenticatedBinder(), required_scope="pack.submit")
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.rbac.enforcement"):
        TestClient(app).get("/guarded")
    denied = [r for r in caplog.records if r.message == "portal.rbac.actor_unauthenticated"]
    assert len(denied) == 1
    assert getattr(denied[0], "reason", None) == "actor_unauthenticated"


# ---------------------------------------------------------------------------
# Refusal path 3 — kernel-default binder still plugged in → 500
# ---------------------------------------------------------------------------


def test_require_scope_returns_500_when_kernel_default_binder_active() -> None:
    """Kernel-misconfig — bank overlay forgot to inject a real binder.
    Structured 500 (NOT 403) so a client cannot mistake it for an auth
    failure that retrying with different credentials might fix."""
    app = _make_app(KernelDefaultActorBinder(), required_scope="pack.submit")
    response = TestClient(app, raise_server_exceptions=False).get("/guarded")
    assert response.status_code == 500
    body = response.json()
    assert body["detail"]["reason"] == "actor_binder_not_configured"


def test_actor_binder_not_configured_emits_structured_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Sprint-7B.4 T6 wire-shape: message is now `portal.rbac.<denial_type>`
    # via the shared `_emit_denial_or_500` helper (was `portal.rbac.denied`).
    app = _make_app(KernelDefaultActorBinder(), required_scope="pack.submit")
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.rbac.enforcement"):
        TestClient(app, raise_server_exceptions=False).get("/guarded")
    denied = [r for r in caplog.records if r.message == "portal.rbac.actor_binder_not_configured"]
    assert len(denied) == 1
    assert getattr(denied[0], "reason", None) == "actor_binder_not_configured"


def test_require_scope_returns_500_when_actor_binder_attr_missing() -> None:
    """Defence-in-depth — distinct from :class:`KernelDefaultActorBinder`
    being plugged in. This covers the case where ``app.state.actor_binder``
    was never set at all (e.g. test setup error or bank-overlay bootstrap
    misorder). Both failure modes surface the same 500
    ``actor_binder_not_configured`` reason so callers cannot distinguish
    the two misconfig shapes (defence-in-depth against fingerprinting)."""
    app = FastAPI()
    # Intentionally do NOT set app.state.actor_binder.
    dep = RequireScope("pack.submit")

    @app.get("/g")
    def g(actor: Annotated[Actor, Depends(dep)]) -> dict[str, str]:
        return {"subject": actor.subject}

    response = TestClient(app, raise_server_exceptions=False).get("/g")
    assert response.status_code == 500
    assert response.json()["detail"]["reason"] == "actor_binder_not_configured"


# ---------------------------------------------------------------------------
# Closed-enum coverage — every value reachable via a real emit path
# ---------------------------------------------------------------------------


def test_every_rbac_denial_reason_has_a_real_emit_path() -> None:
    """Catches the regression where a new :data:`RBACDenialReason` value
    is added without a corresponding code path in :class:`RequireScope`.
    The set of reasons exercised across this module must equal the closed
    enum's full vocabulary."""
    exercised = {
        "scope_not_held",
        "actor_unauthenticated",
        "actor_binder_not_configured",
    }
    assert exercised == set(get_args(RBACDenialReason))
