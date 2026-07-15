"""D-S1 Task 3: build-time MCP tool capability-class validation."""

from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.cli.validators.mcp import (
    _CAPABILITY_CLASSES,
    _RESERVED_CAPABILITY_CLASSES,
    validate,
    validate_tool_capability_classes,
)


def _manifest(tools: list[Any], tier: str = "read_only") -> dict[str, Any]:
    return {
        "pack": {"pack_id": "p", "kind": "tool", "schema_version": 1},
        "risk_tier": {"tier": tier},
        "tool": {
            "cognic": {
                "mcp": {"transport": "streamable-http"},
                "tools": tools,
            }
        },
    }


def test_capability_class_vocabulary_is_closed() -> None:
    assert frozenset({"data_query", "action", "unscoped"}) == _CAPABILITY_CLASSES
    assert frozenset({"retrieval"}) == _RESERVED_CAPABILITY_CLASSES


@pytest.mark.parametrize("capability_class", ["data_query", "unscoped"])
def test_valid_non_action_declaration_passes(capability_class: str) -> None:
    findings = validate_tool_capability_classes(
        _manifest([{"name": "q", "capability_class": capability_class}])
    )

    assert findings == []


@pytest.mark.parametrize(
    ("tools", "failure_mode"),
    [
        ([{"name": "q"}], "capability_class_missing"),
        ([{"name": "q", "capability_class": "nonsense"}], "capability_class_unknown"),
        ([{"name": "q", "capability_class": "retrieval"}], "capability_class_reserved"),
        ([{"name": "q", "capability_class": 7}], "capability_class_not_string"),
        ([{"capability_class": "unscoped"}], "tool_name_missing"),
        ([{"name": "", "capability_class": "unscoped"}], "tool_name_missing"),
        (
            [
                {"name": "q", "capability_class": "unscoped"},
                {"name": "q", "capability_class": "data_query"},
            ],
            "tool_name_duplicate",
        ),
        ([7], "tool_entry_not_table"),
    ],
)
def test_malformed_declarations_refuse(tools: list[Any], failure_mode: str) -> None:
    findings = validate_tool_capability_classes(_manifest(tools))

    assert len(findings) == 1
    assert findings[0].severity == "refusal"
    assert findings[0].reason == "mcp_tool_capability_class_invalid"
    assert findings[0].payload["failure_mode"] == failure_mode


def test_present_tools_field_must_be_an_array() -> None:
    manifest = _manifest([])
    manifest["tool"]["cognic"]["tools"] = {"name": "q"}

    findings = validate_tool_capability_classes(manifest)

    assert len(findings) == 1
    assert findings[0].reason == "mcp_tool_capability_class_invalid"
    assert findings[0].payload["failure_mode"] == "tools_not_array"


@pytest.mark.parametrize("auto_run_tier", ["read_only", "internal_write"])
def test_an_action_tool_cannot_live_in_an_auto_run_pack(auto_run_tier: str) -> None:
    """A write tool cannot inherit a tier that bypasses human approval."""
    findings = validate_tool_capability_classes(
        _manifest(
            [{"name": "w", "capability_class": "action"}],
            tier=auto_run_tier,
        )
    )

    assert len(findings) == 1
    assert findings[0].reason == "mcp_action_tool_in_auto_run_pack"
    assert findings[0].payload["pack_risk_tier"] == auto_run_tier
    assert findings[0].payload["tool_name"] == "w"


def test_an_action_tool_in_a_high_risk_pack_passes() -> None:
    findings = validate_tool_capability_classes(
        _manifest(
            [{"name": "w", "capability_class": "action"}],
            tier="high_risk_custom",
        )
    )

    assert findings == []


def test_absent_tools_array_is_not_a_build_time_refusal() -> None:
    """Pre-S1 packs remain legal; the dispatcher catches undeclared tools."""
    manifest = {
        "pack": {"pack_id": "p", "kind": "tool", "schema_version": 1},
        "risk_tier": {"tier": "read_only"},
        "tool": {"cognic": {"mcp": {"transport": "streamable-http"}}},
    }

    assert validate_tool_capability_classes(manifest) == []


def test_module_entry_point_runs_capability_class_validation() -> None:
    findings = validate(
        _manifest([{"name": "w", "capability_class": "action"}]),
        Path("cognic-pack-manifest.toml"),
    )

    assert [finding.reason for finding in findings] == ["mcp_action_tool_in_auto_run_pack"]
