"""Sprint 7B.2 T3 — pack-router scaffolding + DTO round-trip pins.

Plan §"Task 3: Pack DTOs + sub-router scaffolding + app factory wiring" —
the empty `build_packs_router` ships in T3; T4-T7 add real routes. T3
test surface is therefore:

- The router carries the canonical ``/api/v1/packs`` prefix (ADR-012 §55).
- The router mounts on a FastAPI app without raising.
- The pack DTO base class is frozen + ``extra="forbid"`` (mirrors
  :class:`Actor` at ``portal/rbac/actor.py:52``); pin both behaviours.
- The :class:`PackResponse` view round-trips through Pydantic without
  loss when fed a real :class:`PackRecord`-shaped payload.

Watchpoint (c) from the halt summary: ``/api/v1/packs`` is the canonical
prefix that every T4-T7 endpoint test depends on; a rename here breaks
the entire downstream test surface.
"""

import datetime
import uuid

import pydantic
import pytest
from fastapi import FastAPI

from cognic_agentos.portal.api.packs import build_packs_router
from cognic_agentos.portal.api.packs.dto import PackBaseModel, PackResponse

# ---------------------------------------------------------------------------
# Stub PackRecordStore (sufficient for T3 — no method calls in T3 yet)
# ---------------------------------------------------------------------------


class _StubStore:
    """Test-only :class:`PackRecordStore` stand-in. T3 ships an empty
    router so no method calls land on the store; T4-T7 will pin real
    interactions."""


# ---------------------------------------------------------------------------
# Router scaffolding
# ---------------------------------------------------------------------------


def test_build_packs_router_returns_router_with_canonical_prefix() -> None:
    """Plan §T3 + ADR-012 §55 — the pack-router prefix MUST be
    ``/api/v1/packs``. Rename here breaks every T4-T7 endpoint test."""
    router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
    assert router.prefix == "/api/v1/packs"


def test_build_packs_router_is_an_apirouter() -> None:
    """Defensive type pin so a future refactor that swaps the return
    type to e.g. a tuple doesn't break the mount path silently."""
    from fastapi import APIRouter

    router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
    assert isinstance(router, APIRouter)


def test_build_packs_router_mounts_on_fastapi_app_without_raising() -> None:
    """T3 ships an empty router (T4-T7 will populate); mount must
    succeed even with zero sub-routes so downstream tasks can hang
    routes off it."""
    app = FastAPI()
    router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
    app.include_router(router)
    # No routes mounted yet — but the include_router call must not raise.
    # T4 will land the first real sub-route under this prefix.
    paths = {getattr(route, "path", "") for route in app.routes}
    # Confirm that AT LEAST the routes mounted by FastAPI itself
    # (default openapi/redoc/docs handlers) are present; the empty
    # router neither adds nor blocks them.
    assert any(p.startswith("/openapi") for p in paths)


def test_build_packs_router_requires_keyword_only_store() -> None:
    """Defence-in-depth — the ``store`` parameter is keyword-only so a
    future signature drift (e.g. adding ``actor_binder`` positionally)
    cannot silently shift the store argument."""
    with pytest.raises(TypeError):
        build_packs_router(_StubStore())  # type: ignore[arg-type,misc]


# ---------------------------------------------------------------------------
# DTO scaffolding — PackBaseModel base + PackResponse view
# ---------------------------------------------------------------------------


def test_pack_base_model_is_frozen() -> None:
    """Mirrors :class:`Actor.model_config` at
    ``portal/rbac/actor.py:68`` — DTOs are frozen so downstream handlers
    cannot mutate them mid-request."""

    class _Concrete(PackBaseModel):
        value: str

    instance = _Concrete(value="x")
    with pytest.raises(pydantic.ValidationError):
        instance.value = "mutated"


def test_pack_base_model_forbids_extra_fields() -> None:
    """``extra="forbid"`` so a bank-overlay extension cannot smuggle
    extra fields through the wire-shape without an explicit kernel
    update — mirrors :class:`Actor.model_config`."""

    class _Concrete(PackBaseModel):
        value: str

    with pytest.raises(pydantic.ValidationError):
        _Concrete(value="x", smuggled="bad")  # type: ignore[call-arg]


def _make_pack_response_payload() -> dict[str, object]:
    """Returns a complete :class:`PackResponse` payload that mirrors the
    :class:`PackRecord` field set at ``packs/storage.py:351-378`` minus
    the two SHA-256 digests (security: digests are admin-only and
    surface only on the inspection-tier endpoints at T7 per the
    plan-of-record's ``inspection_routes.py``)."""
    return {
        "id": uuid.UUID("00000000-0000-0000-0000-000000000001"),
        "kind": "tool",
        "pack_id": "cognic-tool-example",
        "display_name": "Example Tool Pack",
        "state": "draft",
        "tenant_id": "t1",
        "created_by": "alice@bank.example",
        "last_actor": "alice@bank.example",
        "created_at": datetime.datetime(2026, 5, 11, 12, 0, 0, tzinfo=datetime.UTC),
        "updated_at": datetime.datetime(2026, 5, 11, 12, 0, 0, tzinfo=datetime.UTC),
    }


def test_pack_response_round_trips_through_pydantic() -> None:
    """The :class:`PackResponse` view must round-trip without loss:
    ``model_validate`` → ``model_dump`` produces a structurally
    identical payload (UUIDs and datetimes serialise to their canonical
    forms but reverse cleanly)."""
    payload = _make_pack_response_payload()
    response = PackResponse.model_validate(payload)
    # Re-validate the dumped payload to prove round-trip integrity
    redumped = PackResponse.model_validate(response.model_dump())
    assert redumped == response


def test_pack_response_carries_no_digest_fields() -> None:
    """Plan watchpoint — :class:`PackResponse` is the DEFAULT
    public-surface view of a pack; the two SHA-256 digests are
    admin-only and surface on the inspection-tier endpoints at T7
    per the plan-of-record's ``inspection_routes.py``. Pin the
    field set here so a T4-T7 refactor cannot silently add a digest
    field to the default view."""
    fields = set(PackResponse.model_fields.keys())
    assert "manifest_digest" not in fields
    assert "signed_artefact_digest" not in fields


def test_pack_response_field_set_matches_plan() -> None:
    """Pin the exact field-set so any drift surfaces as a test
    failure rather than silent wire-shape change."""
    expected = {
        "id",
        "kind",
        "pack_id",
        "display_name",
        "state",
        "tenant_id",
        "created_by",
        "last_actor",
        "created_at",
        "updated_at",
    }
    assert set(PackResponse.model_fields.keys()) == expected


def test_pack_response_kind_validates_against_packkind_literal() -> None:
    """Kind is constrained to the :data:`PackKind` Literal at
    ``packs/lifecycle.py:111``; an out-of-vocab kind raises a Pydantic
    validation error (closed-enum wire-protocol contract)."""
    payload = _make_pack_response_payload()
    payload["kind"] = "not_a_real_kind"
    with pytest.raises(pydantic.ValidationError):
        PackResponse.model_validate(payload)


def test_pack_response_state_validates_against_packstate_literal() -> None:
    """State is constrained to the :data:`PackState` Literal at
    ``packs/lifecycle.py:116``; an out-of-vocab state raises a Pydantic
    validation error."""
    payload = _make_pack_response_payload()
    payload["state"] = "not_a_real_state"
    with pytest.raises(pydantic.ValidationError):
        PackResponse.model_validate(payload)


def test_pack_response_round_trips_through_a_real_packrecord() -> None:
    """T3-R1 P3 closure — :class:`PackResponse` accepts a real
    :class:`PackRecord` instance via ``from_attributes=True``;
    T4-T7 route authors can pass a freshly-loaded record directly
    without an intermediate ``model_dump`` conversion.

    Crucially, the source record carries the two SHA-256 digests but
    the DTO's narrower projection silently DOES NOT read them — pin
    via negative-assertion that the dumped DTO has zero digest fields
    AND positive-assertion that all 10 declared fields round-trip
    cleanly from the source record."""
    from cognic_agentos.packs.storage import PackRecord

    record = PackRecord(
        id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        kind="tool",
        pack_id="cognic-tool-example",
        display_name="Example Tool Pack",
        state="draft",
        manifest_digest=b"\x00" * 32,
        signed_artefact_digest=b"\xff" * 32,
        sbom_pointer=None,
        tenant_id="t1",
        created_by="alice@bank.example",
        last_actor="alice@bank.example",
        created_at=datetime.datetime(2026, 5, 11, 12, 0, 0, tzinfo=datetime.UTC),
        updated_at=datetime.datetime(2026, 5, 11, 12, 0, 0, tzinfo=datetime.UTC),
    )

    response = PackResponse.model_validate(record)

    # All 10 declared fields round-trip from the source PackRecord
    assert response.id == record.id
    assert response.kind == record.kind
    assert response.pack_id == record.pack_id
    assert response.display_name == record.display_name
    assert response.state == record.state
    assert response.tenant_id == record.tenant_id
    assert response.created_by == record.created_by
    assert response.last_actor == record.last_actor
    assert response.created_at == record.created_at
    assert response.updated_at == record.updated_at

    # Negative pin: digests on the source record are NOT carried to
    # the dumped DTO — the narrower projection keeps cryptographic
    # material off the default read surface even when the source
    # carries it.
    dumped = response.model_dump()
    assert "manifest_digest" not in dumped
    assert "signed_artefact_digest" not in dumped


def test_pack_response_strict_input_still_refuses_extra_fields_in_dict() -> None:
    """T3-R1 P3 closure — ``from_attributes=True`` was added in T3-R1
    to support attribute-bearing source objects. The strict
    ``extra="forbid"`` contract MUST still apply to dict-shaped wire
    inputs so a smuggled extra field in a JSON payload refuses.

    Confirms that ``from_attributes`` enables the read-from-attributes
    fallback for declared fields ONLY; it does NOT relax the dict-input
    extra-field gate that defends the wire-protocol contract."""
    payload = _make_pack_response_payload()
    payload["smuggled_extra_field"] = "attacker-controlled"
    with pytest.raises(pydantic.ValidationError):
        PackResponse.model_validate(payload)
