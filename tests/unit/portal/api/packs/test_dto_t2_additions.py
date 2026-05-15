"""Sprint 7B.3 T2 Slice D — DTO additions for reviewer-ack + approve
request + submit bundle-root.

Three new wire-protocol-public surfaces in ``portal/api/packs/dto.py``:

1. :class:`ReviewerAcknowledgement` — 4-boolean panel-ack model.
   Consumed by the approve endpoint (T9). Frozen + extra=forbid.
2. :class:`ApproveRequest` — approve endpoint request body. Carries
   the acknowledgement field + optional ``override_reason``
   (:data:`ApprovalOverrideReason` from
   :mod:`cognic_agentos.packs.approval_types` per R5 P2 #1's neutral-
   domain-vocab pattern).
3. Extension to :class:`SubmitDraftRequest` — NEW REQUIRED field
   ``signed_artefact_root: str`` (R6 P2 #4). MUST be an absolute path;
   non-empty; path-traversal-safe (no ``..`` segments). The Pydantic
   validator refuses relative paths at request-body parse time → 400
   Bad Request before any storage call.

R8 P2 #4 authority-model clarification: ``signed_artefact_root`` is
SUBMIT-DECLARED at the author surface (NOT operator-declared). The
author who runs ``agentos sign`` declares the bundle root location at
submit time alongside the manifest body; ``pack.submit`` scope is the
only RBAC scope required.
"""

from __future__ import annotations

import pytest

from cognic_agentos.packs.approval_types import ApprovalOverrideReason

# ===========================================================================
# Section A — ReviewerAcknowledgement model shape
# ===========================================================================


class TestSprint7B3T2ReviewerAcknowledgementModel:
    """4-boolean panel-ack model; frozen + extra=forbid."""

    def test_all_four_booleans_required_as_fields(self) -> None:
        """Model exposes the 4 panel-ack fields named per the plan."""
        from cognic_agentos.portal.api.packs.dto import ReviewerAcknowledgement

        ack = ReviewerAcknowledgement(
            data_governance_acknowledged=True,
            risk_tier_acknowledged=True,
            supply_chain_acknowledged=True,
            conformance_acknowledged=True,
        )

        assert ack.data_governance_acknowledged is True
        assert ack.risk_tier_acknowledged is True
        assert ack.supply_chain_acknowledged is True
        assert ack.conformance_acknowledged is True

    def test_defaults_all_false(self) -> None:
        """Default-constructed ack has all 4 booleans set to False;
        reviewer MUST explicitly flip them to True for the gate 5 check
        to pass."""
        from cognic_agentos.portal.api.packs.dto import ReviewerAcknowledgement

        ack = ReviewerAcknowledgement()

        assert ack.data_governance_acknowledged is False
        assert ack.risk_tier_acknowledged is False
        assert ack.supply_chain_acknowledged is False
        assert ack.conformance_acknowledged is False

    def test_extra_field_forbidden(self) -> None:
        """``extra="forbid"`` per PackBaseModel inheritance: smuggling
        unmodelled fields refuses at validation."""
        import pydantic

        from cognic_agentos.portal.api.packs.dto import ReviewerAcknowledgement

        with pytest.raises(pydantic.ValidationError):
            ReviewerAcknowledgement(
                data_governance_acknowledged=True,
                smuggled_field="injection-attempt",  # type: ignore[call-arg]
            )

    def test_model_is_frozen(self) -> None:
        """``frozen=True`` per PackBaseModel inheritance: post-construction
        mutation refuses (confused-deputy defense)."""
        import pydantic

        from cognic_agentos.portal.api.packs.dto import ReviewerAcknowledgement

        ack = ReviewerAcknowledgement()
        with pytest.raises(pydantic.ValidationError):
            ack.data_governance_acknowledged = True


# ===========================================================================
# Section B — ApproveRequest model shape
# ===========================================================================


class TestSprint7B3T2ApproveRequestModel:
    """Approve endpoint request body — acknowledgement + optional override."""

    def test_acknowledgement_field_required(self) -> None:
        """``ApproveRequest.acknowledgement`` is required."""
        import pydantic

        from cognic_agentos.portal.api.packs.dto import ApproveRequest

        with pytest.raises(pydantic.ValidationError):
            ApproveRequest()  # type: ignore[call-arg]

    def test_override_reason_optional_default_none(self) -> None:
        """Constructed without ``override_reason`` → field is None;
        approve flow's non-override path takes effect."""
        from cognic_agentos.portal.api.packs.dto import (
            ApproveRequest,
            ReviewerAcknowledgement,
        )

        req = ApproveRequest(acknowledgement=ReviewerAcknowledgement())

        assert req.override_reason is None
        assert req.acknowledgement.data_governance_acknowledged is False

    @pytest.mark.parametrize(
        "reason",
        ["security_exception", "prerelease_validation", "legacy_grandfather", "other"],
    )
    def test_override_reason_accepts_each_canonical_value(
        self, reason: ApprovalOverrideReason
    ) -> None:
        """All 4 ADR-012 §107 closed-enum values accepted."""
        from cognic_agentos.portal.api.packs.dto import (
            ApproveRequest,
            ReviewerAcknowledgement,
        )

        req = ApproveRequest(
            acknowledgement=ReviewerAcknowledgement(),
            override_reason=reason,
        )

        assert req.override_reason == reason

    def test_override_reason_rejects_unknown_value(self) -> None:
        """Out-of-vocabulary override reason → ValidationError. The
        closed enum at :mod:`cognic_agentos.packs.approval_types` IS
        wire-protocol contract per ADR-012 §107."""
        import pydantic

        from cognic_agentos.portal.api.packs.dto import (
            ApproveRequest,
            ReviewerAcknowledgement,
        )

        with pytest.raises(pydantic.ValidationError):
            ApproveRequest(
                acknowledgement=ReviewerAcknowledgement(),
                override_reason="rubber_stamp",  # type: ignore[arg-type]
            )

    def test_extra_field_forbidden(self) -> None:
        """``extra="forbid"`` per PackBaseModel inheritance."""
        import pydantic

        from cognic_agentos.portal.api.packs.dto import (
            ApproveRequest,
            ReviewerAcknowledgement,
        )

        with pytest.raises(pydantic.ValidationError):
            ApproveRequest(
                acknowledgement=ReviewerAcknowledgement(),
                smuggled="injection",  # type: ignore[call-arg]
            )


# ===========================================================================
# Section C — SubmitDraftRequest.signed_artefact_root extension (R6 P2 #4)
# ===========================================================================


class TestSprint7B3T2SubmitDraftRequestSignedArtefactRoot:
    """``SubmitDraftRequest.signed_artefact_root`` is REQUIRED + absolute
    + non-empty + path-traversal-safe (R6 P2 #4 + R8 P2 #4)."""

    def test_signed_artefact_root_required(self) -> None:
        """Missing field → ValidationError (signed_artefact_root has no
        default; R6 P2 #4 declared it REQUIRED at the submit endpoint)."""
        import pydantic

        from cognic_agentos.portal.api.packs.dto import SubmitDraftRequest

        with pytest.raises(pydantic.ValidationError) as exc_info:
            SubmitDraftRequest(manifest={"pack": {"name": "x", "version": "1"}})  # type: ignore[call-arg]
        # Verify the missing field is signed_artefact_root, not manifest.
        assert any(err["loc"] == ("signed_artefact_root",) for err in exc_info.value.errors())

    def test_absolute_path_accepted(self) -> None:
        """Standard Unix absolute path → accepted."""
        from cognic_agentos.portal.api.packs.dto import SubmitDraftRequest

        req = SubmitDraftRequest(
            manifest={"pack": {"name": "x", "version": "1"}},
            signed_artefact_root="/var/cognic/bundles/tenant-a/x-1.0",
        )

        assert req.signed_artefact_root == "/var/cognic/bundles/tenant-a/x-1.0"

    def test_relative_path_refused(self) -> None:
        """Relative path → ValidationError (R5 P2 #3 + R6 P2 #4 doctrine).
        At approve time the handler has no base for relative-path
        resolution; relative paths cannot reach the cosign verifier."""
        import pydantic

        from cognic_agentos.portal.api.packs.dto import SubmitDraftRequest

        with pytest.raises(pydantic.ValidationError):
            SubmitDraftRequest(
                manifest={"pack": {"name": "x", "version": "1"}},
                signed_artefact_root="relative/path/bundle",
            )

    def test_empty_string_refused(self) -> None:
        """Empty string → ValidationError; reviewer cannot pretend the
        bundle root exists at the empty path."""
        import pydantic

        from cognic_agentos.portal.api.packs.dto import SubmitDraftRequest

        with pytest.raises(pydantic.ValidationError):
            SubmitDraftRequest(
                manifest={"pack": {"name": "x", "version": "1"}},
                signed_artefact_root="",
            )

    def test_path_traversal_segments_refused(self) -> None:
        """Absolute path containing ``..`` segments → ValidationError.
        Defense in depth: the resolver refuses these too via the
        SignaturePathRedReason traversal codes, but the request-body
        gate fires first."""
        import pydantic

        from cognic_agentos.portal.api.packs.dto import SubmitDraftRequest

        with pytest.raises(pydantic.ValidationError):
            SubmitDraftRequest(
                manifest={"pack": {"name": "x", "version": "1"}},
                signed_artefact_root="/var/cognic/../etc/bundles",
            )

    def test_manifest_field_still_required(self) -> None:
        """R6 P2 #4 ADDED ``signed_artefact_root``; pre-existing
        ``manifest`` field MUST remain required for T9-era callers."""
        import pydantic

        from cognic_agentos.portal.api.packs.dto import SubmitDraftRequest

        with pytest.raises(pydantic.ValidationError) as exc_info:
            SubmitDraftRequest(signed_artefact_root="/var/cognic/x")  # type: ignore[call-arg]
        assert any(err["loc"] == ("manifest",) for err in exc_info.value.errors())

    def test_both_fields_present_happy_path(self) -> None:
        """Standard submit body: manifest + signed_artefact_root both
        present + valid → accepts."""
        from cognic_agentos.portal.api.packs.dto import SubmitDraftRequest

        req = SubmitDraftRequest(
            manifest={
                "pack": {"name": "x", "version": "1", "kind": "tool"},
                "supply_chain": {
                    "attestation_paths": ["cosign.sig"],
                    "blob_path": "x-1.whl",
                },
            },
            signed_artefact_root="/var/cognic/bundles/x-1",
        )

        assert req.signed_artefact_root == "/var/cognic/bundles/x-1"
        assert req.manifest["pack"]["kind"] == "tool"
