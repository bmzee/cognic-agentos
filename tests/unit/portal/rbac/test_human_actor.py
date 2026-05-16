"""Sprint 7B.2 T2 — RequireHumanActor dependency + closed-enum actor_type_must_be_human.

Plan Round 1 P3 #8 — operator-surface endpoints that finalise per-tenant
state changes (specifically ``/allow-list`` per AGENTS.md
"Per-tenant allow-list changes" human-only-decisions rule) must refuse
service actors. :class:`RequireHumanActor` is the gate.

Pins:

- Admits :class:`Actor` with ``actor_type == "human"``.
- Refuses :class:`Actor` with ``actor_type == "service"`` with 403 +
  ``{"reason": "actor_type_must_be_human"}``.
- Closed-enum stability — out-of-vocab ``actor_type`` already refused at
  :class:`Actor` construction by Pydantic; this guard is purely the
  human-vs-service discriminator inside the wire-protocol vocabulary.
- Module is intentionally separate from :mod:`.enforcement` because the
  closed-enum vocabulary is distinct + the use-case is operator-only.
"""

import logging
from typing import Annotated, Any, get_args

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from cognic_agentos.portal.rbac.actor import Actor, ActorBinder
from cognic_agentos.portal.rbac.human_actor import (
    HumanActorDenialReason,
    RequireHumanActor,
)

# ---------------------------------------------------------------------------
# Closed-enum stability pin
# ---------------------------------------------------------------------------


def test_human_actor_denial_reason_literal_frozen_at_1_value() -> None:
    """Plan Round 1 P3 #8 — exactly 1 denial reason for the human-only guard."""
    assert set(get_args(HumanActorDenialReason)) == {"actor_type_must_be_human"}


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_actor(**overrides: Any) -> Actor:
    defaults: dict[str, Any] = {
        "subject": "alice@bank.example",
        "tenant_id": "t1",
        "scopes": frozenset({"pack.allow_list"}),
        "actor_type": "human",
    }
    defaults.update(overrides)
    return Actor(**defaults)


def _make_app(actor: Actor) -> FastAPI:
    app = FastAPI()
    binder: ActorBinder = _StubBinder(actor)
    app.state.actor_binder = binder

    dep = RequireHumanActor()

    @app.get("/operator/allow-list")
    def allow_list(
        actor: Annotated[Actor, Depends(dep)],
    ) -> dict[str, str]:
        return {"subject": actor.subject, "actor_type": actor.actor_type}

    return app


# ---------------------------------------------------------------------------
# Green path
# ---------------------------------------------------------------------------


def test_require_human_actor_admits_human() -> None:
    actor = _make_actor(actor_type="human")
    response = TestClient(_make_app(actor)).get("/operator/allow-list")
    assert response.status_code == 200
    body = response.json()
    assert body["actor_type"] == "human"


# ---------------------------------------------------------------------------
# Refusal path
# ---------------------------------------------------------------------------


def test_require_human_actor_refuses_service() -> None:
    actor = _make_actor(actor_type="service")
    response = TestClient(_make_app(actor)).get("/operator/allow-list")
    assert response.status_code == 403
    body = response.json()
    assert body["detail"]["reason"] == "actor_type_must_be_human"
    assert body["detail"]["actor_subject"] == "alice@bank.example"


def test_require_human_actor_refusal_emits_structured_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """T2 R1 P2 #2 — caplog parity with :file:`test_enforcement.py`. The
    closed-enum :data:`HumanActorDenialReason` value must emit a
    structured log record at ``cognic_agentos.portal.rbac.enforcement``
    (Sprint-7B.4 T6 wire-shape: emission now routes through the shared
    ``_emit_denial_or_500`` helper, so the logger source moves from
    ``human_actor`` to ``enforcement`` and the message becomes
    ``portal.rbac.actor_type_must_be_human``). Without this pin the
    logging side-effect can regress while the HTTP-response test stays
    green; the structured ``reason`` / ``actor_subject`` / ``actor_type``
    fields are unchanged."""
    actor = _make_actor(actor_type="service")
    app = _make_app(actor)
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.rbac.enforcement"):
        TestClient(app).get("/operator/allow-list")
    records = [r for r in caplog.records if r.message == "portal.rbac.actor_type_must_be_human"]
    assert len(records) == 1
    record = records[0]
    assert getattr(record, "reason", None) == "actor_type_must_be_human"
    assert getattr(record, "actor_subject", None) == "alice@bank.example"
    assert getattr(record, "actor_type", None) == "service"


# ---------------------------------------------------------------------------
# Closed-enum coverage
# ---------------------------------------------------------------------------


def test_every_human_actor_denial_reason_has_a_real_emit_path() -> None:
    """Catches the regression where a new :data:`HumanActorDenialReason`
    value is added without a corresponding test."""
    exercised = {"actor_type_must_be_human"}
    assert exercised == set(get_args(HumanActorDenialReason))
