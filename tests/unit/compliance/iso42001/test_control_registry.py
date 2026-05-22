"""Sprint 9 T1 — ISO 42001 control registry."""

from __future__ import annotations

import typing

from cognic_agentos.compliance.iso42001.controls import (
    ISO42001_CONTROLS,
    ComplianceControlId,
    control_ids,
)

_EXPECTED = {
    "ISO42001.A.6.2.5",
    "ISO42001.A.6.2.6",
    "ISO42001.A.7.4",
    "ISO42001.A.7.6",
    "ISO42001.A.8.2",
    "ISO42001.A.8.5",
    "ISO42001.A.9.2",
    "ISO42001.A.10.2",
}


def test_registry_holds_exactly_the_eight_adr006_controls() -> None:
    assert control_ids() == _EXPECTED
    assert len(ISO42001_CONTROLS) == 8


def test_control_id_literal_matches_registry() -> None:
    assert set(typing.get_args(ComplianceControlId)) == _EXPECTED


def test_every_entry_has_canonical_id_display_and_intended_hooks() -> None:
    for entry in ISO42001_CONTROLS:
        assert entry.control_id.startswith("ISO42001.A.")
        assert entry.display == entry.control_id.removeprefix("ISO42001.")
        assert entry.title
        assert entry.intended_hooks  # non-empty tuple
