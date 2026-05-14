"""Sprint 7B.3 T3 Slice C — :class:`DataGovernancePanel` DTO wire-shape tests.

Pins the new Pydantic v2 DTO at
:class:`cognic_agentos.portal.api.packs.dto.DataGovernancePanel` per
plan §302. Tests cover:

- Pydantic ``from_attributes=True`` interop with the
  :class:`DataGovernancePanelData` projector output (Slice B).
- Frozen + ``extra="forbid"`` invariants inherited from
  :class:`PackBaseModel` (mirrors the T2 DTO doctrine).
- Field-set drift detector (any addition/removal MUST update the DTO
  + projector + drift detector in lockstep).
- ``pack_kind`` Literal narrowness (out-of-vocab values refuse at
  Pydantic-validation time).
"""

from __future__ import annotations

from typing import ClassVar

import pydantic
import pytest

from cognic_agentos.packs.evidence.data_governance import (
    DataGovernancePanelData,
    project_data_governance_panel,
)
from cognic_agentos.portal.api.packs.dto import DataGovernancePanel


class TestSprint7B3T3SliceCDataGovernancePanelWireShape:
    """Wire-shape contract for the new Pydantic DTO."""

    _MANIFEST: ClassVar[dict[str, object]] = {
        "data_governance": {
            "data_classes": ["customer_pii"],
            "purpose": "transaction_processing",
            "retention_policy": "regulator_floor",
            "retention_max_window": 86400,
            "egress_allow_list": ["https://core-banking.internal"],
            "dlp_pre_hooks": ["redact_pii_in_input"],
            "dlp_post_hooks": ["mask_account_numbers"],
        }
    }

    def test_model_validate_accepts_projector_output_via_from_attributes(
        self,
    ) -> None:
        """:class:`DataGovernancePanel` MUST accept a freshly-projected
        :class:`DataGovernancePanelData` instance directly via
        ``from_attributes=True`` (no intermediate ``dataclasses.asdict``
        step). Mirrors the T2 :class:`PackResponse` interop pattern."""
        panel_data = project_data_governance_panel(manifest=self._MANIFEST, record_kind="tool")
        panel = DataGovernancePanel.model_validate(panel_data)
        assert panel.pack_kind == "tool"
        assert panel.data_classes == ("customer_pii",)
        assert panel.purpose == "transaction_processing"
        assert panel.retention_max_window == "86400"
        assert panel.tenant_policy_diff == ()

    def test_model_validate_accepts_dict_input(self) -> None:
        """DTO MUST also accept dict input (the standard Pydantic path)
        so route handlers can construct from kwargs too."""
        panel = DataGovernancePanel.model_validate(
            {
                "pack_kind": "agent",
                "data_classes": ("public",),
                "purpose": "customer_support",
                "purpose_description": "",
                "retention_policy": "session_only",
                "retention_max_window": "3600",
                "egress_allow_list": (),
                "dlp_pre_hooks": (),
                "dlp_post_hooks": (),
                "tenant_policy_diff": ("none",),
            }
        )
        assert panel.pack_kind == "agent"
        assert panel.tenant_policy_diff == ("none",)

    def test_frozen_invariant(self) -> None:
        """``frozen=True`` inherited from :class:`PackBaseModel` — handler
        cannot mutate the DTO mid-request (confused-deputy defence)."""
        panel = DataGovernancePanel.model_validate(
            DataGovernancePanelData(
                pack_kind="tool",
                data_classes=(),
                purpose="",
                purpose_description="",
                retention_policy="",
                retention_max_window="",
                egress_allow_list=(),
                dlp_pre_hooks=(),
                dlp_post_hooks=(),
                tenant_policy_diff=(),
            )
        )
        with pytest.raises(pydantic.ValidationError):
            panel.pack_kind = "agent"

    def test_extra_forbid_invariant(self) -> None:
        """``extra="forbid"`` inherited from :class:`PackBaseModel` —
        smuggled unmodelled fields refuse at validation."""
        with pytest.raises(pydantic.ValidationError):
            DataGovernancePanel.model_validate(
                {
                    "pack_kind": "tool",
                    "data_classes": (),
                    "purpose": "",
                    "purpose_description": "",
                    "retention_policy": "",
                    "retention_max_window": "",
                    "egress_allow_list": (),
                    "dlp_pre_hooks": (),
                    "dlp_post_hooks": (),
                    "tenant_policy_diff": (),
                    "smuggled_extra_field": "bypass-attempt",
                }
            )

    def test_pack_kind_literal_rejects_out_of_vocab(self) -> None:
        """:class:`PackKind` Literal constraint applies — an unknown
        kind value refuses at Pydantic-validation time (drift defence
        against a future ``PackKind`` extension that forgets to update
        the panel)."""
        with pytest.raises(pydantic.ValidationError):
            DataGovernancePanel.model_validate(
                {
                    "pack_kind": "not_a_real_kind",
                    "data_classes": (),
                    "purpose": "",
                    "purpose_description": "",
                    "retention_policy": "",
                    "retention_max_window": "",
                    "egress_allow_list": (),
                    "dlp_pre_hooks": (),
                    "dlp_post_hooks": (),
                    "tenant_policy_diff": (),
                }
            )

    def test_tenant_policy_diff_literal_rejects_out_of_vocab(self) -> None:
        """The tuple element type IS :data:`DataGovernanceDiffFlag` — an
        out-of-vocab value MUST refuse at validation. Locks the
        projector → DTO drift surface."""
        with pytest.raises(pydantic.ValidationError):
            DataGovernancePanel.model_validate(
                {
                    "pack_kind": "tool",
                    "data_classes": (),
                    "purpose": "",
                    "purpose_description": "",
                    "retention_policy": "",
                    "retention_max_window": "",
                    "egress_allow_list": (),
                    "dlp_pre_hooks": (),
                    "dlp_post_hooks": (),
                    "tenant_policy_diff": ("not_a_real_diff_flag",),
                }
            )

    def test_field_set_pinned(self) -> None:
        """Pin the exact 10-field set per plan §302. A future addition
        or removal MUST update this test in the same commit as the
        DTO + projector + projector-data tuple."""
        expected = {
            "pack_kind",
            "data_classes",
            "purpose",
            "purpose_description",
            "retention_policy",
            "retention_max_window",
            "egress_allow_list",
            "dlp_pre_hooks",
            "dlp_post_hooks",
            "tenant_policy_diff",
        }
        assert set(DataGovernancePanel.model_fields) == expected
