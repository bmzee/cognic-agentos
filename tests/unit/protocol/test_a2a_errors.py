"""Sprint 6 T11 — protocol/a2a_errors.py contract tests.

A2A 1.0 spec error taxonomy (``A2AErrorCode`` Literal — 14 spec
wire codes) + AgentOS policy-refusal reasons (``A2APolicyRefusalReason``
Literal — 11 AgentOS reasons surfaced in ``data.policy_reason``) +
the ``_POLICY_REASON_TO_SPEC_CODE`` mapping.

Doctrines pinned by these tests (T11 R0):

  1. The map is the canonical source-of-truth; T9 is NOT refactored
     (T9's inline hardcoding agrees with the map for every overlapping
     case — same wire outcomes).
  2. ``A2AErrorResponse`` (T11) + ``A2AEndpointError`` (T9) live at
     different layers — both retained.
  3. Mapping completeness: every ``A2APolicyRefusalReason`` value has
     exactly one entry in ``_POLICY_REASON_TO_SPEC_CODE``.
  4. Mapping codomain: every value in the map is a member of
     ``A2AErrorCode`` — wire-protocol contract preservation.
  5. Spec-code factories: 14 functions, one per ``A2AErrorCode``.
  6. T9 alignment: anonymous + tenant_token_invalid + unknown_target
     + wave2_feature_refused all produce the same wire codes T9
     hardcodes today (regression pin against future drift).

This module is on the **critical-controls floor** per Sprint-6 plan-of-
record R3 P2 #2 — wire-protocol drift = wire-protocol break.
"""

from __future__ import annotations

import dataclasses
from typing import get_args

import pytest

from cognic_agentos.protocol import A2AErrorCode, A2APolicyRefusalReason
from cognic_agentos.protocol.a2a_errors import (
    _POLICY_REASON_TO_SPEC_CODE,
    A2AErrorResponse,
    content_type_not_supported,
    extended_agent_card_not_configured,
    extension_support_required,
    from_policy_reason,
    internal_error,
    invalid_agent_response,
    invalid_params,
    invalid_request,
    method_not_found,
    parse_error,
    push_notification_not_supported,
    task_not_cancelable,
    task_not_found,
    unsupported_operation,
    version_not_supported,
)

# =============================================================================
# Mapping completeness + codomain
# =============================================================================


class TestMappingCompleteness:
    """Every ``A2APolicyRefusalReason`` MUST appear in
    ``_POLICY_REASON_TO_SPEC_CODE`` exactly once. A future addition
    to the policy-refusal Literal must update this map (the test
    drift detector trips first)."""

    def test_every_policy_reason_has_a_spec_code(self) -> None:
        all_reasons = set(get_args(A2APolicyRefusalReason))
        mapped_reasons = set(_POLICY_REASON_TO_SPEC_CODE.keys())
        missing = all_reasons - mapped_reasons
        assert not missing, (
            f"A2APolicyRefusalReason values without a spec-code "
            f"mapping (T11 wire-protocol drift): {sorted(missing)}"
        )

    def test_no_extra_keys_in_map(self) -> None:
        all_reasons = set(get_args(A2APolicyRefusalReason))
        mapped_reasons = set(_POLICY_REASON_TO_SPEC_CODE.keys())
        extra = mapped_reasons - all_reasons
        assert not extra, (
            f"_POLICY_REASON_TO_SPEC_CODE has keys not in "
            f"A2APolicyRefusalReason (typo / dead entry): "
            f"{sorted(extra)}"
        )

    def test_every_mapped_value_is_a_spec_code(self) -> None:
        """Codomain check: every value in the map MUST be a member
        of :data:`A2AErrorCode`. Otherwise the mapping silently
        emits a non-spec wire code."""
        spec_codes = set(get_args(A2AErrorCode))
        for reason, code in _POLICY_REASON_TO_SPEC_CODE.items():
            assert code in spec_codes, (
                f"_POLICY_REASON_TO_SPEC_CODE[{reason!r}] = {code!r} "
                f"is NOT in A2AErrorCode — wire contract violated"
            )

    def test_map_has_exactly_eleven_entries(self) -> None:
        """11 = current cardinality of A2APolicyRefusalReason. Pinned
        so a literal addition without map update trips early."""
        assert len(_POLICY_REASON_TO_SPEC_CODE) == 11


# =============================================================================
# T9 alignment — same wire codes T9 emits today
# =============================================================================


class TestT9Alignment:
    """T11 R0 doctrine #1: T9 is NOT refactored. T9's inline hardcoded
    spec codes for the policy reasons it emits MUST agree with what
    the centralised map produces — same wire outcomes for every
    overlapping case. This regression pins that alignment so a future
    map edit cannot silently desynchronise from T9."""

    @pytest.mark.parametrize(
        ("policy_reason", "expected_t9_wire_code"),
        [
            # T9 emits invalid_request for both authn refusal flavours
            # (a2a_endpoint.py:472 hardcodes ``"invalid_request"``)
            ("anonymous_refused", "invalid_request"),
            ("tenant_token_invalid", "invalid_request"),
            # T9 emits method_not_found for routing refusals
            # (a2a_endpoint.py raise inside PluginNotRegistered /
            # RegistrationRefused branch)
            ("unknown_target", "method_not_found"),
            # T9 emits unsupported_operation for wave2 refusals
            ("wave2_feature_refused", "unsupported_operation"),
        ],
    )
    def test_t9_overlapping_reasons_align(
        self,
        policy_reason: A2APolicyRefusalReason,
        expected_t9_wire_code: A2AErrorCode,
    ) -> None:
        assert _POLICY_REASON_TO_SPEC_CODE[policy_reason] == expected_t9_wire_code


# =============================================================================
# A2AErrorResponse dataclass shape
# =============================================================================


class TestErrorResponseShape:
    """The error-response envelope is the JSON-RPC-shaped wire
    surface for HTTP serialization. Must be frozen+slots so the wire
    cannot be mutated between construction and egress."""

    def test_dataclass_is_frozen_and_slotted(self) -> None:
        # frozen check — assignment raises
        resp = A2AErrorResponse(
            code="invalid_request",
            message="test",
            spec_section="A2A-1.0 §error-codes",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            resp.code = "method_not_found"  # type: ignore[misc]

        # slotted check — no __dict__
        assert not hasattr(resp, "__dict__")

    def test_required_fields(self) -> None:
        fields = {f.name for f in dataclasses.fields(A2AErrorResponse)}
        required = {
            "code",
            "message",
            "spec_section",
            "policy_reason",
            "feature_subtag",
            "payload",
            "http_status",
        }
        missing = required - fields
        assert not missing, f"A2AErrorResponse missing fields: {missing}"

    def test_default_http_status_is_400(self) -> None:
        resp = A2AErrorResponse(
            code="invalid_request",
            message="x",
            spec_section="A2A-1.0 §error-codes",
        )
        assert resp.http_status == 400

    def test_optional_policy_reason_defaults_to_none(self) -> None:
        resp = A2AErrorResponse(
            code="task_not_found",
            message="x",
            spec_section="A2A-1.0 §error-codes",
        )
        assert resp.policy_reason is None
        assert resp.feature_subtag is None
        assert resp.payload is None


# =============================================================================
# from_policy_reason factory
# =============================================================================


class TestFromPolicyReason:
    """``from_policy_reason`` projects an AgentOS policy reason onto
    the spec-conformant wire response, carrying the policy reason
    in ``data.policy_reason`` for examiner visibility."""

    def test_anonymous_refused_maps_to_invalid_request(self) -> None:
        resp = from_policy_reason("anonymous_refused", message="missing Authorization header")
        assert resp.code == "invalid_request"
        assert resp.policy_reason == "anonymous_refused"

    def test_unknown_target_maps_to_method_not_found(self) -> None:
        resp = from_policy_reason("unknown_target", message="agent not registered")
        assert resp.code == "method_not_found"
        assert resp.policy_reason == "unknown_target"

    def test_wave2_feature_refused_maps_to_unsupported_operation(self) -> None:
        resp = from_policy_reason(
            "wave2_feature_refused",
            message="multimodal payload not in Wave 1",
            feature_subtag="multimodal_payload",
        )
        assert resp.code == "unsupported_operation"
        assert resp.policy_reason == "wave2_feature_refused"
        assert resp.feature_subtag == "multimodal_payload"

    def test_payload_carries_through(self) -> None:
        resp = from_policy_reason(
            "tenant_token_invalid",
            message="token revoked",
            payload={"authz_reason": "a2a_token_revoked"},
        )
        assert resp.payload == {"authz_reason": "a2a_token_revoked"}

    def test_unmapped_reason_raises(self) -> None:
        """Defensive against a future Literal addition that lands
        without updating the map. The completeness test above pins
        the dataset; this pins the call-site behaviour."""
        with pytest.raises(KeyError):
            from_policy_reason(
                "this_reason_does_not_exist",  # type: ignore[arg-type]
                message="x",
            )


# =============================================================================
# Spec-code factories — 14 total
# =============================================================================


class TestSpecCodeFactories:
    """One factory per ``A2AErrorCode`` literal. These are the
    spec-only error paths — no AgentOS policy reason layered on top."""

    def test_parse_error(self) -> None:
        resp = parse_error("malformed JSON")
        assert resp.code == "parse_error"
        assert resp.policy_reason is None

    def test_invalid_request(self) -> None:
        resp = invalid_request("malformed envelope")
        assert resp.code == "invalid_request"

    def test_method_not_found(self) -> None:
        resp = method_not_found("tasks/unknown")
        assert resp.code == "method_not_found"

    def test_invalid_params(self) -> None:
        resp = invalid_params("missing required field")
        assert resp.code == "invalid_params"

    def test_internal_error(self) -> None:
        resp = internal_error()
        assert resp.code == "internal_error"
        assert resp.http_status == 500

    def test_task_not_found(self) -> None:
        resp = task_not_found("task-abc")
        assert resp.code == "task_not_found"
        assert resp.http_status == 404
        assert resp.payload is not None
        assert resp.payload["task_id"] == "task-abc"

    def test_task_not_cancelable(self) -> None:
        resp = task_not_cancelable("task-abc")
        assert resp.code == "task_not_cancelable"

    def test_version_not_supported(self) -> None:
        resp = version_not_supported("1.0")
        assert resp.code == "version_not_supported"
        assert resp.payload is not None
        assert resp.payload["supported"] == "1.0"

    def test_unsupported_operation(self) -> None:
        resp = unsupported_operation("tasks/resubscribe")
        assert resp.code == "unsupported_operation"

    def test_content_type_not_supported(self) -> None:
        resp = content_type_not_supported("text/csv")
        assert resp.code == "content_type_not_supported"

    def test_invalid_agent_response(self) -> None:
        resp = invalid_agent_response("non-canonical")
        assert resp.code == "invalid_agent_response"

    def test_push_notification_not_supported(self) -> None:
        resp = push_notification_not_supported()
        assert resp.code == "push_notification_not_supported"

    def test_extended_agent_card_not_configured(self) -> None:
        resp = extended_agent_card_not_configured()
        assert resp.code == "extended_agent_card_not_configured"

    def test_extension_support_required(self) -> None:
        resp = extension_support_required("urn:a2a:ext:foo")
        assert resp.code == "extension_support_required"
        assert resp.payload is not None
        assert resp.payload["missing_extension"] == "urn:a2a:ext:foo"


# =============================================================================
# A2AErrorCode literal-set arithmetic
# =============================================================================


class TestErrorCodeLiteralSet:
    def test_a2a_error_code_has_fourteen_values(self) -> None:
        """14 spec wire codes per A2A 1.0 §"Error codes" — pinned so
        a future addition without explicit review trips immediately."""
        assert len(get_args(A2AErrorCode)) == 14

    def test_a2a_policy_refusal_reason_has_eleven_values(self) -> None:
        """11 AgentOS-specific refusal reasons surfaced in
        ``data.policy_reason``."""
        assert len(get_args(A2APolicyRefusalReason)) == 11
