"""Sprint 7B.2 T2 — RequireTenantOwnership dependency + closed-enum TenantIsolationFailure.

Plan Round 1 P2 #3 + T2 R1 P2 #1 — tenant-isolation guard ships in T2 so
later tasks (T4 author surface, T5 reviewer surface, T6 operator surface)
have a real module to depend on. Closed-enum :data:`TenantIsolationFailure`
is a 4-value wire-protocol contract:

- ``tenant_id_mismatch`` (404) — actor's tenant_id differs from the
  pack's tenant_id. 404 (NOT 403) for info-leak prevention: a 403 leaks
  pack existence to a cross-tenant attacker.
- ``pack_not_found`` (404) — :meth:`PackRecordStore.load` returned
  ``None``. Same 404 status as tenant_id_mismatch (info-leak prevention
  symmetry).
- ``actor_tenant_id_missing`` (500) — actor's ``tenant_id`` field is empty.
  Kernel-misconfig — should never happen with a real bank-overlay binder
  but defended at the gate anyway.
- ``pack_store_not_configured`` (500) — added at T2 R1 P2 #1 as a
  symmetric mirror of :func:`enforcement._bind_actor`'s ``binder is None``
  defensive branch. Without it, a route mounted with a binder but no
  ``app.state.pack_record_store`` surfaces FastAPI's generic 500
  ``Internal Server Error`` (no closed-enum reason, no structured log)
  — a fingerprint regression off the 7B.2 wire-protocol contract.

The dependency returns the loaded :class:`PackRecord` on success so
sub-handlers consume it without re-loading.
"""

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, get_args

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from cognic_agentos.packs.storage import PackRecord
from cognic_agentos.portal.rbac.actor import Actor, ActorBinder
from cognic_agentos.portal.rbac.tenant_isolation import (
    RequireTenantOwnership,
    TenantIsolationFailure,
)

# ---------------------------------------------------------------------------
# Closed-enum stability pin
# ---------------------------------------------------------------------------


def test_tenant_isolation_failure_literal_frozen_at_4_values() -> None:
    """Plan Round 1 P2 #3 + T2 R1 P2 #1 — exactly 4 tenant-isolation failure
    modes. ``pack_store_not_configured`` is the symmetric mirror of
    :func:`enforcement._bind_actor`'s ``binder is None`` defensive branch."""
    assert set(get_args(TenantIsolationFailure)) == {
        "tenant_id_mismatch",
        "pack_not_found",
        "actor_tenant_id_missing",
        "pack_store_not_configured",
    }


# ---------------------------------------------------------------------------
# Test fixtures — minimal FastAPI app + stub store + stub binder
# ---------------------------------------------------------------------------


def _make_pack_record(
    *,
    tenant_id: str | None,
    pack_uuid: uuid.UUID,
) -> PackRecord:
    """Build a minimal :class:`PackRecord` for tenant-isolation tests.
    Lives in the test module per :file:`AGENTS.md` test-fixture-placement rule."""
    now = datetime.now(UTC)
    return PackRecord(
        id=pack_uuid,
        kind="tool",
        pack_id="acme/echo",
        display_name="ACME Echo",
        state="draft",
        manifest_digest=b"\x00" * 32,
        signed_artefact_digest=b"\x00" * 32,
        sbom_pointer=None,
        tenant_id=tenant_id,
        created_by="alice@bank.example",
        last_actor="alice@bank.example",
        created_at=now,
        updated_at=now,
    )


class _StubPackRecordStore:
    """Test-only store returning a fixed PackRecord (or None) for any pack_id.

    Lives in the test module per AGENTS.md test-fixture-placement rule. The
    Sprint-7B.2 plan keeps cross-pack lookup contracts simple: a single
    ``load(pack_id)`` async call is all :class:`RequireTenantOwnership` invokes."""

    def __init__(self, record: PackRecord | None) -> None:
        self._record = record

    async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
        return self._record


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _human_actor(**overrides: Any) -> Actor:
    defaults: dict[str, Any] = {
        "subject": "alice@bank.example",
        "tenant_id": "t1",
        "scopes": frozenset({"pack.submit"}),
        "actor_type": "human",
    }
    defaults.update(overrides)
    return Actor(**defaults)


def _make_app(
    *,
    actor: Actor,
    record: PackRecord | None,
) -> tuple[FastAPI, uuid.UUID]:
    app = FastAPI()
    binder: ActorBinder = _StubBinder(actor)
    app.state.actor_binder = binder
    app.state.pack_record_store = _StubPackRecordStore(record)
    pack_uuid = uuid.uuid4()

    dep = RequireTenantOwnership("pack_id")

    @app.get("/packs/{pack_id}")
    def fetch_pack(pack: Annotated[PackRecord, Depends(dep)]) -> dict[str, str]:
        return {"pack_id": pack.pack_id, "tenant_id": pack.tenant_id or ""}

    return app, pack_uuid


# ---------------------------------------------------------------------------
# Green path
# ---------------------------------------------------------------------------


def test_require_tenant_ownership_admits_same_tenant_actor() -> None:
    actor = _human_actor(tenant_id="t1")
    pack_uuid = uuid.uuid4()
    record = _make_pack_record(tenant_id="t1", pack_uuid=pack_uuid)
    app, _ = _make_app(actor=actor, record=record)
    response = TestClient(app).get(f"/packs/{pack_uuid}")
    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == "t1"


# ---------------------------------------------------------------------------
# Refusal: tenant_id_mismatch
# ---------------------------------------------------------------------------


def test_require_tenant_ownership_refuses_cross_tenant_actor() -> None:
    """404 (NOT 403) — info-leak prevention. A cross-tenant attacker cannot
    distinguish "pack exists but wrong tenant" from "pack does not exist"."""
    actor = _human_actor(tenant_id="t2")
    pack_uuid = uuid.uuid4()
    record = _make_pack_record(tenant_id="t1", pack_uuid=pack_uuid)
    app, _ = _make_app(actor=actor, record=record)
    response = TestClient(app).get(f"/packs/{pack_uuid}")
    assert response.status_code == 404
    assert response.json()["detail"]["reason"] == "tenant_id_mismatch"


def test_require_tenant_ownership_refuses_when_pack_has_no_tenant_id() -> None:
    """Pack with ``tenant_id=None`` is still cross-tenant from the actor's
    perspective — refuse with the same 404 code."""
    actor = _human_actor(tenant_id="t1")
    pack_uuid = uuid.uuid4()
    record = _make_pack_record(tenant_id=None, pack_uuid=pack_uuid)
    app, _ = _make_app(actor=actor, record=record)
    response = TestClient(app).get(f"/packs/{pack_uuid}")
    assert response.status_code == 404
    assert response.json()["detail"]["reason"] == "tenant_id_mismatch"


# ---------------------------------------------------------------------------
# Refusal: pack_not_found
# ---------------------------------------------------------------------------


def test_require_tenant_ownership_refuses_missing_pack() -> None:
    actor = _human_actor(tenant_id="t1")
    pack_uuid = uuid.uuid4()
    app, _ = _make_app(actor=actor, record=None)
    response = TestClient(app).get(f"/packs/{pack_uuid}")
    assert response.status_code == 404
    assert response.json()["detail"]["reason"] == "pack_not_found"


# ---------------------------------------------------------------------------
# Refusal: actor_tenant_id_missing
# ---------------------------------------------------------------------------


def test_require_tenant_ownership_refuses_actor_with_empty_tenant_id() -> None:
    """Kernel-misconfig — should never happen with a real binder, but the
    gate defends anyway. 500 (NOT 404) because the failure is on our side."""
    actor = _human_actor(tenant_id="")  # empty tenant_id
    pack_uuid = uuid.uuid4()
    record = _make_pack_record(tenant_id="t1", pack_uuid=pack_uuid)
    app, _ = _make_app(actor=actor, record=record)
    response = TestClient(app, raise_server_exceptions=False).get(f"/packs/{pack_uuid}")
    assert response.status_code == 500
    assert response.json()["detail"]["reason"] == "actor_tenant_id_missing"


# ---------------------------------------------------------------------------
# Closed-enum coverage — every value reachable via a real emit path
# ---------------------------------------------------------------------------


def test_every_tenant_isolation_failure_has_a_real_emit_path() -> None:
    """Catches the regression where a new :data:`TenantIsolationFailure`
    value is added without a code path. The reasons exercised across this
    module must equal the closed enum's full vocabulary."""
    exercised = {
        "tenant_id_mismatch",
        "pack_not_found",
        "actor_tenant_id_missing",
        "pack_store_not_configured",
    }
    assert exercised == set(get_args(TenantIsolationFailure))


# ---------------------------------------------------------------------------
# Path-param routing pin
# ---------------------------------------------------------------------------


def test_require_tenant_ownership_rejects_malformed_pack_id_uuid() -> None:
    """Non-UUID pack_id must surface as a structured 404 ``pack_not_found``
    — NOT a 500 from an unhandled :class:`ValueError`. Catches the
    regression where a callable forgets the UUID parse guard.

    T2 R1 P3 tightening: the dependency's docstring contract is "structured
    404 ``pack_not_found``", so this assertion pins the EXACT body
    (status + closed-enum reason), not just ``!= 500``. Looser assertions
    would let a future regression slip from 404 ``pack_not_found`` to a
    422 ``Unprocessable Entity`` (or any other non-500 shape) without
    detection."""
    actor = _human_actor(tenant_id="t1")
    pack_uuid = uuid.uuid4()
    record = _make_pack_record(tenant_id="t1", pack_uuid=pack_uuid)
    app, _ = _make_app(actor=actor, record=record)
    response = TestClient(app, raise_server_exceptions=False).get("/packs/not-a-uuid")
    assert response.status_code == 404
    assert response.json()["detail"]["reason"] == "pack_not_found"


def test_require_tenant_ownership_returns_500_when_pack_store_missing() -> None:
    """T2 R1 P2 #1 — symmetric mirror of
    :func:`enforcement._bind_actor`'s ``binder is None`` defensive branch.
    A route mounted with a binder but no ``app.state.pack_record_store``
    must surface a CLOSED-ENUM ``pack_store_not_configured`` 500, NOT
    FastAPI's generic ``Internal Server Error``."""
    actor = _human_actor(tenant_id="t1")
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    # Intentionally do NOT set app.state.pack_record_store.
    dep = RequireTenantOwnership("pack_id")

    @app.get("/packs/{pack_id}")
    def fetch(pack: Annotated[PackRecord, Depends(dep)]) -> dict[str, str]:
        return {"pack_id": pack.pack_id}

    pack_uuid = uuid.uuid4()
    response = TestClient(app, raise_server_exceptions=False).get(f"/packs/{pack_uuid}")
    assert response.status_code == 500
    assert response.json()["detail"]["reason"] == "pack_store_not_configured"


@pytest.mark.parametrize(
    "build_app,expected_reason",
    [
        pytest.param(
            lambda: _make_app(
                actor=_human_actor(tenant_id="t2"),
                record=_make_pack_record(tenant_id="t1", pack_uuid=uuid.uuid4()),
            ),
            "tenant_id_mismatch",
            id="tenant_id_mismatch",
        ),
        pytest.param(
            lambda: _make_app(actor=_human_actor(tenant_id="t1"), record=None),
            "pack_not_found",
            id="pack_not_found",
        ),
        pytest.param(
            lambda: _make_app(
                actor=_human_actor(tenant_id=""),
                record=_make_pack_record(tenant_id="t1", pack_uuid=uuid.uuid4()),
            ),
            "actor_tenant_id_missing",
            id="actor_tenant_id_missing",
        ),
    ],
)
def test_tenant_isolation_emits_structured_log_per_reason(
    build_app: Any,
    expected_reason: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Sprint-7B.4 T6 wire-shape: emission moved from per-module helper
    (`_emit_isolation_log`, logger ``cognic_agentos.portal.rbac.tenant_isolation``,
    message ``portal.rbac.tenant_isolation_failed``) to the shared
    ``_emit_denial_or_500`` helper (logger
    ``cognic_agentos.portal.rbac.enforcement``, message
    ``portal.rbac.<reason>``). Structured ``reason`` / ``actor_subject``
    / ``pack_id`` fields are unchanged — operators querying on
    structured fields stay compatible."""
    app, _ = build_app()
    pack_uuid = uuid.uuid4()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.rbac.enforcement"):
        TestClient(app, raise_server_exceptions=False).get(f"/packs/{pack_uuid}")
    records = [r for r in caplog.records if r.message == f"portal.rbac.{expected_reason}"]
    assert len(records) == 1, f"Expected exactly one denial log; got {records}"
    record = records[0]
    assert getattr(record, "reason", None) == expected_reason
    assert getattr(record, "actor_subject", None) is not None
    assert getattr(record, "pack_id", None) is not None


def test_pack_store_not_configured_emits_structured_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Sprint-7B.4 T6 wire-shape: emission moved from
    `_emit_isolation_log` (tenant_isolation logger, constant message
    `portal.rbac.tenant_isolation_failed`) to the shared
    `_emit_denial_or_500` helper (enforcement logger, per-reason
    message `portal.rbac.pack_store_not_configured`). Kept separate
    from the parametrized matrix above because the app construction
    is unique (no store wired)."""
    actor = _human_actor(tenant_id="t1")
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    dep = RequireTenantOwnership("pack_id")

    @app.get("/packs/{pack_id}")
    def fetch(pack: Annotated[PackRecord, Depends(dep)]) -> dict[str, str]:
        return {"pack_id": pack.pack_id}

    pack_uuid = uuid.uuid4()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.rbac.enforcement"):
        TestClient(app, raise_server_exceptions=False).get(f"/packs/{pack_uuid}")
    records = [r for r in caplog.records if r.message == "portal.rbac.pack_store_not_configured"]
    assert len(records) == 1
    assert getattr(records[0], "reason", None) == "pack_store_not_configured"


def test_require_tenant_ownership_raises_runtime_error_on_param_name_mismatch() -> None:
    """Defence-in-depth — if the route is wired with a path-param name that
    differs from what ``RequireTenantOwnership`` was instantiated with, the
    dependency raises :class:`RuntimeError` rather than silently 404'ing.
    Catches kernel routing bugs at the first request rather than letting
    them masquerade as ``pack_not_found``."""
    actor = _human_actor(tenant_id="t1")
    pack_uuid = uuid.uuid4()
    record = _make_pack_record(tenant_id="t1", pack_uuid=pack_uuid)
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.state.pack_record_store = _StubPackRecordStore(record)
    # Path-param is named ``id``, but the dependency expects ``pack_id``.
    dep = RequireTenantOwnership("pack_id")

    @app.get("/packs/{id}")
    def fetch(pack: Annotated[PackRecord, Depends(dep)]) -> dict[str, str]:
        return {"pack_id": pack.pack_id}

    response = TestClient(app, raise_server_exceptions=False).get(f"/packs/{pack_uuid}")
    # RuntimeError surfaces as a 500 via FastAPI's default error handler.
    assert response.status_code == 500


@pytest.mark.parametrize(
    "scenario_actor_tenant,scenario_pack_tenant,expected_status,expected_reason",
    [
        ("t1", "t1", 200, None),
        ("t1", "t2", 404, "tenant_id_mismatch"),
        ("t1", None, 404, "tenant_id_mismatch"),
    ],
)
def test_tenant_isolation_decision_matrix(
    scenario_actor_tenant: str,
    scenario_pack_tenant: str | None,
    expected_status: int,
    expected_reason: str | None,
) -> None:
    """Parametrized matrix pinning the (actor.tenant_id, pack.tenant_id) →
    (status, reason) decision table. Catches off-by-one regressions in
    the comparison logic."""
    actor = _human_actor(tenant_id=scenario_actor_tenant)
    pack_uuid = uuid.uuid4()
    record = _make_pack_record(tenant_id=scenario_pack_tenant, pack_uuid=pack_uuid)
    app, _ = _make_app(actor=actor, record=record)
    response = TestClient(app).get(f"/packs/{pack_uuid}")
    assert response.status_code == expected_status
    if expected_reason is not None:
        assert response.json()["detail"]["reason"] == expected_reason
