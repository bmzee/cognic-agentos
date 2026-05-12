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
from typing import get_args

import pydantic
import pytest
from fastapi import FastAPI

from cognic_agentos.portal.api.packs import build_packs_router
from cognic_agentos.portal.api.packs.dto import (
    PackBaseModel,
    PackEvidenceResponse,
    PackResponse,
    RejectDraftRequest,
    RejectionReason,
)

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


# ===========================================================================
# Sprint 7B.2 T5 — RejectionReason 7-value closed-enum vocabulary
# (Round 11 P2 #2; anchored to ADR-012 §41 5-gate composition + ops)
# ===========================================================================


class TestSprint7B2RejectionReasonVocabulary:
    """Plan Round 11 P2 #2 — ``RejectionReason`` 7-value closed-enum
    vocabulary anchored to ADR-012 §41 5-gate composition + 2
    operational categories + free-form fallback.

    Wire-protocol-public: the literal IS carried in :class:`RejectDraftRequest`
    bodies and in the T5 reject-handler structured-log ``extra["reason"]``.
    Any addition/rename/removal is a wire-protocol break per AGENTS.md
    "Wire-protocol contracts" stop rule + ``feedback_strict_review_off_gate.md``
    closed-enum stability doctrine.
    """

    def test_literal_values_pinned_at_7(self) -> None:
        """Plan Round 11 P2 #2 — exactly 7 closed-enum values, in the
        canonical set anchored to ADR-012 §41 5-gate composition:

        - ``signature_invalid`` — cosign / SLSA failure (gate 1)
        - ``evaluation_pass_rate_below_threshold`` — ADR-010 eval harness red (gate 2)
        - ``adversarial_corpus_pass_rate_below_threshold`` — ADR-011 adversarial red (gate 3)
        - ``owasp_conformance_red`` — ADR-012 §41 OWASP gate red (gate 4)
        - ``data_governance_unfit`` — ADR-017 data-class / purpose mismatch
        - ``documentation_incomplete`` — operational; manifest fields incomplete
        - ``other`` — free-form fallback; ``comments`` is the diagnostic
        """
        expected = {
            "signature_invalid",
            "evaluation_pass_rate_below_threshold",
            "adversarial_corpus_pass_rate_below_threshold",
            "owasp_conformance_red",
            "data_governance_unfit",
            "documentation_incomplete",
            "other",
        }
        actual = set(get_args(RejectionReason))
        assert actual == expected
        assert len(actual) == 7


# ===========================================================================
# Sprint 7B.2 T5 — RejectDraftRequest DTO (Round 11 P2 #2 + Round 11 P2 #3)
# ===========================================================================


class TestSprint7B2RejectDraftRequest:
    """Plan Round 11 P2 #2 + Round 11 P2 #3 — POST /api/v1/packs/{pack_id}/reject
    body schema. Carries ``reason`` (closed-enum) + ``comments`` (non-empty
    str); when ``reason == "other"`` the ``comments`` field carries the
    free-form diagnostic.

    T5 ships reject as a bare transition + structured-log only emission
    of these fields (per Round 11 P2 #3); T9 carry-forward amends the
    reject handler to persist ``{"rejection_reason": …, "reviewer_comments": …}``
    to the chain row via ``evidence_attachments`` (per Round 12 P2 #2).
    """

    def test_round_trips_valid_reason_and_comments(self) -> None:
        """Happy path — every closed-enum reason validates with
        non-empty comments."""
        for reason_value in get_args(RejectionReason):
            req = RejectDraftRequest(
                reason=reason_value,
                comments="sample diagnostic",
            )
            assert req.reason == reason_value
            assert req.comments == "sample diagnostic"

    def test_refuses_out_of_vocab_reason(self) -> None:
        """An out-of-vocab reason value MUST refuse at Pydantic
        validation — the closed-enum is wire-protocol-public + a string
        like ``"not_a_real_reason"`` would silently land in the
        structured-log emission as evidence if not caught here."""
        with pytest.raises(pydantic.ValidationError):
            RejectDraftRequest(
                reason="not_a_real_reason",  # type: ignore[arg-type]
                comments="diagnostic",
            )

    def test_refuses_empty_comments(self) -> None:
        """``comments`` is REQUIRED non-empty (``Field(min_length=1)``).
        Empty comments leave the reject chain row with no diagnostic
        and break the audit-evidence contract per ADR-012 §42."""
        with pytest.raises(pydantic.ValidationError):
            RejectDraftRequest(
                reason="signature_invalid",
                comments="",
            )

    def test_refuses_other_reason_without_comments(self) -> None:
        """Plan Round 11 P2 #2 — when ``reason == "other"`` the
        ``comments`` field IS the free-form diagnostic and MUST be
        non-empty (the ``other`` value carries no semantic content of
        its own; comments are the evidence surface). Pinned via a
        Pydantic ``model_validator(mode="after")``.

        Note: the non-empty constraint is enforced for ALL reasons via
        ``Field(min_length=1)`` per ``test_refuses_empty_comments``;
        this test is the explicit cross-axis pin for the ``other``
        case so a future relaxation of the ``min_length=1`` field
        constraint cannot silently undermine the ``other`` evidence
        contract.
        """
        with pytest.raises(pydantic.ValidationError):
            RejectDraftRequest(
                reason="other",
                comments="",
            )

    def test_refuses_other_reason_with_whitespace_only_comments(self) -> None:
        """Plan Round 11 P2 #2 — defensive-cross-axis pin: the
        ``Field(min_length=1)`` constraint accepts a whitespace-only
        string (length > 0), but the model_validator's ``.strip()``
        check rejects it for the ``other`` reason (whitespace-only
        comments carry no diagnostic content; the ``other`` reason's
        comments are the audit-evidence surface).

        Exercises the model_validator branch that
        ``test_refuses_empty_comments`` cannot reach (because
        ``Field(min_length=1)`` rejects ``""`` before the validator
        runs). The two tests together pin both layers of the contract.
        """
        with pytest.raises(pydantic.ValidationError):
            RejectDraftRequest(
                reason="other",
                comments="   ",  # whitespace-only; passes min_length=1
            )

    def test_is_frozen(self) -> None:
        """DTO inherits :class:`PackBaseModel` (frozen) — handler
        cannot mutate the body mid-request."""
        req = RejectDraftRequest(reason="signature_invalid", comments="x")
        with pytest.raises(pydantic.ValidationError):
            req.comments = "mutated"

    def test_forbids_extra_fields(self) -> None:
        """``extra="forbid"`` from :class:`PackBaseModel` — smuggled
        fields refuse at validation."""
        with pytest.raises(pydantic.ValidationError):
            RejectDraftRequest(
                reason="signature_invalid",
                comments="x",
                smuggled_field="bad",  # type: ignore[call-arg]
            )


# ===========================================================================
# Sprint 7B.2 T5 — PackEvidenceResponse DTO (Round 11 P3 #5)
# ===========================================================================


class TestSprint7B2PackEvidenceResponse:
    """Plan Round 11 P3 #5 — GET /api/v1/packs/{pack_id}/evidence
    response shape. Carries the conformance evidence attached by T9's
    auto-run-on-submit wire (read from the chain ``payload.conformance``).

    Two-field shape:
    - ``conformance: dict[str, Any] | None`` — populated when T9 has
      attached evidence to the submit chain row; ``None`` pre-T9 or when
      the pack has no submit row.
    - ``reviewer_evidence_panels: None`` — literal-typed at ``None``
      in 7B.2; 7B.3 fills in with the full evidence-panel object.
    """

    def test_accepts_conformance_dict(self) -> None:
        """The conformance kwarg accepts an arbitrary dict (the OWASP
        runner emits the result schema; T9 will pin the inner shape)."""
        resp = PackEvidenceResponse(
            conformance={"status": "green", "checks": []},
            reviewer_evidence_panels=None,
        )
        assert resp.conformance == {"status": "green", "checks": []}
        assert resp.reviewer_evidence_panels is None

    def test_accepts_null_conformance_for_pre_t9_chains(self) -> None:
        """Plan T5 caveat — pre-T9 submit chain rows carry no
        ``payload.conformance`` key; the read path surfaces ``None``
        and the endpoint MUST return a structured ``null`` rather than
        a 500."""
        resp = PackEvidenceResponse(
            conformance=None,
            reviewer_evidence_panels=None,
        )
        assert resp.conformance is None
        assert resp.reviewer_evidence_panels is None

    def test_reviewer_evidence_panels_only_accepts_none(self) -> None:
        """Plan Round 11 P3 #5 — ``reviewer_evidence_panels`` is
        literal-typed at ``None`` in 7B.2 (always-null surface; 7B.3
        will widen). A non-None value here would silently break the
        wire-protocol-public contract that the field is ALWAYS null
        in 7B.2."""
        with pytest.raises(pydantic.ValidationError):
            PackEvidenceResponse(
                conformance=None,
                reviewer_evidence_panels={"some": "thing"},  # type: ignore[arg-type]
            )

    def test_is_frozen(self) -> None:
        """DTO inherits :class:`PackBaseModel` (frozen)."""
        resp = PackEvidenceResponse(conformance=None, reviewer_evidence_panels=None)
        with pytest.raises(pydantic.ValidationError):
            resp.conformance = {}

    def test_forbids_extra_fields(self) -> None:
        """``extra="forbid"`` from :class:`PackBaseModel`."""
        with pytest.raises(pydantic.ValidationError):
            PackEvidenceResponse(
                conformance=None,
                reviewer_evidence_panels=None,
                smuggled_panel="bad",  # type: ignore[call-arg]
            )
