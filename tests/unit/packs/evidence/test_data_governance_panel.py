"""Sprint 7B.3 T3 — data-governance evidence-panel CRITICAL CONTROLS tests.

Slice A coverage (drift detectors): pins the closed-enum 7-value
Literal at
:data:`cognic_agentos.packs.evidence.data_governance.DataGovernanceDiffFlag`
per plan §303. Drift between this Literal and:

- The :class:`DataGovernancePanel` DTO at
  ``portal/api/packs/dto.py`` — the wire-protocol contract for the
  ``tenant_policy_diff`` field.
- The :func:`project_data_governance_panel` projector (Slice B) — the
  values it may emit on ``tenant_policy_diff``.
- 7B.3 reviewer evidence-panel renderers (downstream consumers).

is wire-protocol-public regression.

Slice B coverage (projector contract): pins the pure-functional
:func:`project_data_governance_panel` contract per plan §302 + §304:

- Reads ``manifest["data_governance"]`` defensively (missing block,
  non-dict block, missing optional fields all default to empty).
- Echoes ``record_kind`` verbatim onto the output's ``pack_kind``.
- ``tenant_policy is None`` → empty diff tuple (plan §304 contract).
- ``tenant_policy`` wired + no violations → ``("none",)`` sentinel
  (distinguishes from the empty-tuple-on-no-policy case).
- Each of the 6 violation flags fires on its own dedicated case.
"""

from __future__ import annotations

import typing
from typing import ClassVar

from cognic_agentos.packs.evidence import data_governance as _module
from cognic_agentos.packs.evidence.data_governance import (
    DataGovernanceDiffFlag,
    DataGovernancePanelData,
    TenantDataGovernancePolicy,
    project_data_governance_panel,
)


class TestSprint7B3T3SliceADataGovernanceDiffFlagVocab:
    """Drift detectors for :data:`DataGovernanceDiffFlag`."""

    _EXPECTED_VALUES: ClassVar[frozenset[str]] = frozenset(
        {
            "data_class_not_in_tenant_allowlist",
            "purpose_not_declared",
            "retention_exceeds_tenant_max",
            "egress_endpoint_not_in_tenant_allowlist",
            "dlp_pre_hook_missing",
            "dlp_post_hook_missing",
            "none",
        }
    )

    def test_exact_value_set(self) -> None:
        """Lock the exact 7-value vocabulary per plan §303."""
        assert frozenset(typing.get_args(DataGovernanceDiffFlag)) == self._EXPECTED_VALUES

    def test_exact_count(self) -> None:
        """Count guard pinned independently for crisp drift-diagnosis.

        If the value set changes but the count guard is updated in the
        same commit, ``test_exact_value_set`` fires and points at the
        specific value-level drift; if only the count guard fires it
        signals a parallel addition without value-set update.
        """
        assert len(typing.get_args(DataGovernanceDiffFlag)) == 7

    def test_module_all_surface_includes_diff_flag(self) -> None:
        """``DataGovernanceDiffFlag`` MUST appear in the module's
        ``__all__`` — a refactor that drops the symbol from the public
        surface would silently break the dto / projector / route
        consumers (PEP 8 + Pydantic Literal resolution depends on the
        symbol being importable from the module path).
        """
        assert "DataGovernanceDiffFlag" in _module.__all__


# ---------------------------------------------------------------------------
# Sprint 7B.3 T3 Slice B — :func:`project_data_governance_panel` contract
# ---------------------------------------------------------------------------


class TestSprint7B3T3SliceBProjectDataGovernancePanel:
    """Pure-functional projector contract per plan §302 + §304."""

    # -- shared fixtures ----------------------------------------------------

    _FULL_MANIFEST: ClassVar[dict[str, object]] = {
        "data_governance": {
            "data_classes": ["customer_pii", "audit_trail"],
            "purpose": "transaction_processing",
            "purpose_description": "End-to-end payment processing flow",
            "retention_policy": "regulator_floor",
            "retention_max_window": 2592000,  # 30 days in seconds
            "egress_allow_list": ["https://core-banking.internal", "https://kyc-vendor.example"],
            "dlp_pre_hooks": ["redact_pii_in_input"],
            "dlp_post_hooks": ["mask_account_numbers"],
        }
    }

    # -- structural / passthrough -------------------------------------------

    def test_returns_data_governance_panel_data_instance(self) -> None:
        result = project_data_governance_panel(manifest=self._FULL_MANIFEST, record_kind="tool")
        assert isinstance(result, DataGovernancePanelData)

    def test_pack_kind_echoes_record_kind_verbatim(self) -> None:
        """Per plan §302 — ``pack_kind`` MUST come from the authoritative
        :class:`PackRecord.kind` passed in by the route handler (not from
        the manifest)."""
        for kind in ("tool", "skill", "agent", "hook"):
            result = project_data_governance_panel(
                manifest=self._FULL_MANIFEST,
                record_kind=kind,
            )
            assert result.pack_kind == kind

    def test_full_manifest_field_passthrough(self) -> None:
        """All 8 data-governance fields read through to the panel."""
        result = project_data_governance_panel(manifest=self._FULL_MANIFEST, record_kind="agent")
        assert result.data_classes == ("customer_pii", "audit_trail")
        assert result.purpose == "transaction_processing"
        assert result.purpose_description == "End-to-end payment processing flow"
        assert result.retention_policy == "regulator_floor"
        assert result.retention_max_window == "2592000"
        assert result.egress_allow_list == (
            "https://core-banking.internal",
            "https://kyc-vendor.example",
        )
        assert result.dlp_pre_hooks == ("redact_pii_in_input",)
        assert result.dlp_post_hooks == ("mask_account_numbers",)

    def test_retention_max_window_stringified_for_display(self) -> None:
        """Manifest stores ``retention_max_window`` as a positive number;
        the panel surfaces it as a string for display per plan §302."""
        result = project_data_governance_panel(
            manifest={
                "data_governance": {
                    "retention_policy": "purpose_window",
                    "retention_max_window": 86400.5,
                }
            },
            record_kind="tool",
        )
        assert result.retention_max_window == "86400.5"

    def test_retention_max_window_missing_defaults_empty_string(self) -> None:
        """Missing field surfaces as ``""`` (the retention_policy="none"
        case where the validator allows omitting the window)."""
        result = project_data_governance_panel(
            manifest={"data_governance": {"retention_policy": "none"}},
            record_kind="tool",
        )
        assert result.retention_max_window == ""

    def test_missing_data_governance_block_defaults_empty(self) -> None:
        """Manifest with no ``data_governance`` key surfaces all fields
        as empty values (NOT a KeyError)."""
        result = project_data_governance_panel(manifest={}, record_kind="tool")
        assert result.data_classes == ()
        assert result.purpose == ""
        assert result.purpose_description == ""
        assert result.retention_policy == ""
        assert result.retention_max_window == ""
        assert result.egress_allow_list == ()
        assert result.dlp_pre_hooks == ()
        assert result.dlp_post_hooks == ()

    def test_malformed_data_governance_block_defaults_empty(self) -> None:
        """Manifest with ``data_governance`` as a non-dict (e.g. list,
        string, None) surfaces all fields as empty values. Defends
        against the case where a partially-corrupted persisted manifest
        slips past upstream shape gates."""
        result = project_data_governance_panel(
            manifest={"data_governance": "not-a-dict"}, record_kind="tool"
        )
        assert result.data_classes == ()
        assert result.purpose == ""

    def test_purpose_description_optional_defaults_empty(self) -> None:
        """``purpose_description`` is optional in the manifest (the
        validator does not require it) — missing surfaces as ``""``."""
        result = project_data_governance_panel(
            manifest={
                "data_governance": {
                    "purpose": "regulatory_reporting",
                    "retention_policy": "none",
                }
            },
            record_kind="tool",
        )
        assert result.purpose == "regulatory_reporting"
        assert result.purpose_description == ""

    # -- tenant_policy_diff contract ---------------------------------------

    def test_no_tenant_policy_returns_empty_diff_tuple(self) -> None:
        """Plan §304 contract — when the tenant-policy substrate is not
        wired (caller passes ``None``), the diff is ``()`` (empty),
        NOT ``("none",)``. Distinguishes "no policy configured" from
        "policy wired + no violations"."""
        result = project_data_governance_panel(
            manifest=self._FULL_MANIFEST, record_kind="tool", tenant_policy=None
        )
        assert result.tenant_policy_diff == ()

    def test_tenant_policy_match_returns_none_sentinel(self) -> None:
        """When policy is wired AND no violations found, diff is
        ``("none",)`` per plan §303 docstring contract."""
        permissive_policy: TenantDataGovernancePolicy = {
            "allowed_data_classes": frozenset({"customer_pii", "audit_trail"}),
            "allowed_purposes": frozenset({"transaction_processing"}),
            "max_retention_window": 31536000.0,  # 1 year
            "allowed_egress_endpoints": frozenset(
                {"https://core-banking.internal", "https://kyc-vendor.example"}
            ),
            "required_dlp_pre_hooks": frozenset({"redact_pii_in_input"}),
            "required_dlp_post_hooks": frozenset({"mask_account_numbers"}),
        }
        result = project_data_governance_panel(
            manifest=self._FULL_MANIFEST,
            record_kind="tool",
            tenant_policy=permissive_policy,
        )
        assert result.tenant_policy_diff == ("none",)

    def test_diff_data_class_not_in_tenant_allowlist(self) -> None:
        policy: TenantDataGovernancePolicy = {
            "allowed_data_classes": frozenset({"public", "internal"})
        }
        result = project_data_governance_panel(
            manifest=self._FULL_MANIFEST, record_kind="tool", tenant_policy=policy
        )
        assert "data_class_not_in_tenant_allowlist" in result.tenant_policy_diff

    def test_diff_purpose_not_declared(self) -> None:
        policy: TenantDataGovernancePolicy = {"allowed_purposes": frozenset({"customer_support"})}
        result = project_data_governance_panel(
            manifest=self._FULL_MANIFEST, record_kind="tool", tenant_policy=policy
        )
        assert "purpose_not_declared" in result.tenant_policy_diff

    def test_diff_retention_exceeds_tenant_max(self) -> None:
        policy: TenantDataGovernancePolicy = {"max_retention_window": 60.0}
        result = project_data_governance_panel(
            manifest=self._FULL_MANIFEST, record_kind="tool", tenant_policy=policy
        )
        assert "retention_exceeds_tenant_max" in result.tenant_policy_diff

    def test_diff_egress_endpoint_not_in_tenant_allowlist(self) -> None:
        policy: TenantDataGovernancePolicy = {
            "allowed_egress_endpoints": frozenset({"https://core-banking.internal"})
        }
        result = project_data_governance_panel(
            manifest=self._FULL_MANIFEST, record_kind="tool", tenant_policy=policy
        )
        assert "egress_endpoint_not_in_tenant_allowlist" in result.tenant_policy_diff

    def test_diff_dlp_pre_hook_missing(self) -> None:
        policy: TenantDataGovernancePolicy = {
            "required_dlp_pre_hooks": frozenset({"redact_pii_in_input", "consent_check"})
        }
        result = project_data_governance_panel(
            manifest=self._FULL_MANIFEST, record_kind="tool", tenant_policy=policy
        )
        assert "dlp_pre_hook_missing" in result.tenant_policy_diff

    def test_diff_dlp_post_hook_missing(self) -> None:
        policy: TenantDataGovernancePolicy = {
            "required_dlp_post_hooks": frozenset({"mask_account_numbers", "audit_egress_log"})
        }
        result = project_data_governance_panel(
            manifest=self._FULL_MANIFEST, record_kind="tool", tenant_policy=policy
        )
        assert "dlp_post_hook_missing" in result.tenant_policy_diff

    # -- defensive shape branches -----------------------------------------

    def test_data_classes_non_list_in_block_defaults_empty(self) -> None:
        """A persisted manifest with a non-list ``data_classes`` (e.g. a
        single string accidentally written without list wrapping)
        surfaces as ``()`` rather than crashing. Covers the
        ``not isinstance(value, list)`` defensive branch in
        :func:`_coerce_str_tuple`."""
        result = project_data_governance_panel(
            manifest={
                "data_governance": {
                    "data_classes": "customer_pii",  # not wrapped in a list
                    "purpose": "transaction_processing",
                    "retention_policy": "none",
                }
            },
            record_kind="tool",
        )
        assert result.data_classes == ()

    def test_retention_max_window_bool_is_not_a_positive_number(self) -> None:
        """A persisted manifest with ``retention_max_window = True``
        (TOML bool slipping past upstream gates) MUST NOT trip the
        ``retention_exceeds_tenant_max`` flag — bool is rejected by
        :func:`_is_positive_number` even though ``True`` is an int
        subclass. Mirrors the build-time validator's bool guard."""
        policy: TenantDataGovernancePolicy = {"max_retention_window": 0.5}
        result = project_data_governance_panel(
            manifest={
                "data_governance": {
                    "retention_policy": "purpose_window",
                    "retention_max_window": True,  # NOT a real positive number
                }
            },
            record_kind="tool",
            tenant_policy=policy,
        )
        assert "retention_exceeds_tenant_max" not in result.tenant_policy_diff

    def test_retention_max_window_non_numeric_is_not_compared(self) -> None:
        """A persisted manifest with a string ``retention_max_window``
        (e.g. ``"30d"``) MUST NOT trip the comparison; the projector
        treats it as not-comparable and surfaces the raw string on the
        panel for the reviewer to flag manually. Covers the
        ``not isinstance(value, (int, float))`` defensive branch."""
        policy: TenantDataGovernancePolicy = {"max_retention_window": 60.0}
        result = project_data_governance_panel(
            manifest={
                "data_governance": {
                    "retention_policy": "purpose_window",
                    "retention_max_window": "30d",
                }
            },
            record_kind="tool",
            tenant_policy=policy,
        )
        assert "retention_exceeds_tenant_max" not in result.tenant_policy_diff
        # The string still surfaces on the panel for reviewer display.
        assert result.retention_max_window == "30d"

    def test_multiple_violations_yield_multiple_flags_without_none_sentinel(
        self,
    ) -> None:
        """When multiple violations fire, the diff carries each flag
        AND does NOT include the ``"none"`` sentinel — the sentinel is
        emitted ONLY when zero violations were detected against a wired
        policy."""
        policy: TenantDataGovernancePolicy = {
            "allowed_data_classes": frozenset({"public"}),
            "allowed_purposes": frozenset({"customer_support"}),
        }
        result = project_data_governance_panel(
            manifest=self._FULL_MANIFEST, record_kind="tool", tenant_policy=policy
        )
        assert "data_class_not_in_tenant_allowlist" in result.tenant_policy_diff
        assert "purpose_not_declared" in result.tenant_policy_diff
        assert "none" not in result.tenant_policy_diff
