"""Sprint-7A T9 — MCP conformance-validator regressions.

The MCP validator's Wave-1 scope is a cross-block check: the
``[mcp]`` flags ``caching`` + ``elicitation_form`` are refused when
the pack also declares restricted data classes in
``[data_governance].data_classes``.

Schema scope (build-time, cognic-pack-manifest.toml):

  - Top-level ``[mcp]`` — the canonical Sprint-7A T5 shape (matches
    the rest of cognic-pack-manifest's top-level governance blocks).
  - ``[tool.cognic.mcp]`` — backward-compat fallback (mirrors the
    A2A R23 P2 #1 / R24 P2 #1 dual-path doctrine, so authors who
    copy the legacy shape from ``docs/MCP-CONFORMANCE.md`` get
    validated too).

Out of T9 scope:

  - The runtime per-tool gate at
    ``protocol.mcp_capabilities.evaluate_manifest_validation``
    operates on **pyproject.toml**'s ``[tool.cognic.mcp]`` +
    ``[[tool.cognic.tools]]`` shape with per-tool ``data_classes`` +
    ``caching_strategy = "ttl"`` checks. That's a different file +
    surface, complementing the build-time pack-level check here.
    Aligning the two schemas is a future doctrine question; T9
    does NOT touch the runtime module.

  - ``mcp_wave2_feature_in_wave1_manifest`` is reserved in the
    closed-enum literal but has no fire-path at T9: no Wave-2
    MCP fields are defined in the runtime layer yet. Adding a
    speculative sentinel here would create drift the T1 ownership-
    map gate would reject.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli.validators import mcp


def _tool_manifest_with_mcp(
    *,
    data_classes: list[Any] | None = None,
    **mcp_overrides: Any,
) -> dict[str, Any]:
    """Build a tool-kind manifest with the canonical T5 shape:
    top-level ``[mcp]`` + top-level ``[data_governance]``."""
    base_mcp: dict[str, Any] = {
        "caching": False,
        "elicitation_form": False,
    }
    for k, v in mcp_overrides.items():
        if v is None:
            base_mcp.pop(k, None)
        else:
            base_mcp[k] = v
    return {
        "pack": {"pack_id": "cognic-tool-demo", "kind": "tool"},
        "mcp": base_mcp,
        "data_governance": {
            "data_classes": data_classes if data_classes is not None else ["public"],
        },
    }


# ---------------------------------------------------------------------------
# (a) [mcp] block absent / non-dict — nothing to refuse
# ---------------------------------------------------------------------------


def test_mcp_no_block_returns_empty(tmp_path: Path) -> None:
    """Skill packs and agent packs ship without an ``[mcp]`` block.
    The validator must NOT refuse them — the block is per-kind."""
    findings = mcp.validate({"pack": {"pack_id": "cognic-skill-x", "kind": "skill"}}, tmp_path)
    assert findings == []


def test_mcp_block_not_a_dict_returns_empty(tmp_path: Path) -> None:
    """Defense-in-depth: under normal orchestrator dispatch the T6
    shape gate guarantees ``[mcp]`` is a dict if present, but direct
    unit-test entry points may bypass that."""
    findings = mcp.validate(
        {"pack": {"pack_id": "cognic-tool-x", "kind": "tool"}, "mcp": "not-a-table"},
        tmp_path,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# (b) Wave-1-clean manifest — no findings
# ---------------------------------------------------------------------------


def test_mcp_wave1_clean_returns_empty(tmp_path: Path) -> None:
    findings = mcp.validate(_tool_manifest_with_mcp(), tmp_path)
    assert findings == []


def test_mcp_caching_with_public_data_classes_no_refusal(tmp_path: Path) -> None:
    """``caching = true`` is ALLOWED when the pack declares only
    non-restricted data classes."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(caching=True, data_classes=["public", "internal"]),
        tmp_path,
    )
    assert findings == []


def test_mcp_elicitation_form_with_public_data_classes_no_refusal(tmp_path: Path) -> None:
    """``elicitation_form = true`` is ALLOWED when the pack declares
    only non-restricted data classes."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(elicitation_form=True, data_classes=["public", "internal"]),
        tmp_path,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# (c) Restricted-data-class cross-check refusals
# ---------------------------------------------------------------------------


def test_mcp_caching_with_restricted_data_class_refuses(tmp_path: Path) -> None:
    """``caching = true`` AND data_classes contains "customer_pii" →
    ``mcp_caching_restricted_data_class`` refusal."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(caching=True, data_classes=["customer_pii"]),
        tmp_path,
    )
    matching = [f for f in findings if f.reason == "mcp_caching_restricted_data_class"]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"
    assert matching[0].affects_exit_code is True
    assert "customer_pii" in matching[0].payload["restricted_data_classes"]


def test_mcp_elicitation_form_with_restricted_data_class_refuses(tmp_path: Path) -> None:
    """``elicitation_form = true`` AND data_classes contains "customer_pii"
    → ``mcp_elicitation_form_restricted_data_class`` refusal."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(elicitation_form=True, data_classes=["customer_pii"]),
        tmp_path,
    )
    matching = [f for f in findings if f.reason == "mcp_elicitation_form_restricted_data_class"]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"
    assert "customer_pii" in matching[0].payload["restricted_data_classes"]


def test_mcp_caching_false_with_restricted_data_class_no_refusal(tmp_path: Path) -> None:
    """The cross-check fires only when caching is True AND data is
    restricted. caching=false with restricted data → no refusal."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(caching=False, data_classes=["customer_pii"]),
        tmp_path,
    )
    assert not any(f.reason == "mcp_caching_restricted_data_class" for f in findings)


def test_mcp_caching_string_with_restricted_data_class_no_refusal(tmp_path: Path) -> None:
    """Bool-only check (mirrors T8): a string ``"true"`` is NOT
    treated as caching opt-in."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(caching="true", data_classes=["customer_pii"]),
        tmp_path,
    )
    assert not any(f.reason == "mcp_caching_restricted_data_class" for f in findings)


def test_mcp_both_refusals_emit_together(tmp_path: Path) -> None:
    """``caching = true`` AND ``elicitation_form = true`` AND
    restricted data → both refusals surface (one per offending
    flag)."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(caching=True, elicitation_form=True, data_classes=["customer_pii"]),
        tmp_path,
    )
    refusal_reasons = {f.reason for f in findings}
    assert "mcp_caching_restricted_data_class" in refusal_reasons
    assert "mcp_elicitation_form_restricted_data_class" in refusal_reasons


# ---------------------------------------------------------------------------
# (d) data_classes shape variations
# ---------------------------------------------------------------------------


def test_mcp_data_classes_with_author_fill_placeholder_no_refusal(tmp_path: Path) -> None:
    """T5 scaffolds ship ``data_classes`` with an AUTHOR-FILL
    placeholder string. That doesn't match "customer_pii" exactly, so
    it doesn't fire the cross-check (T10 data_governance validator
    will refuse the placeholder itself; T9 doesn't double-fire)."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(
            caching=True,
            data_classes=["AUTHOR-FILL: e.g., public, internal, confidential, restricted"],
        ),
        tmp_path,
    )
    assert not any(f.reason == "mcp_caching_restricted_data_class" for f in findings)


def test_mcp_data_classes_missing_no_refusal(tmp_path: Path) -> None:
    """``[data_governance].data_classes`` absent → no restricted-
    class set to intersect with → no cross-check refusal. T10's
    data-governance validator owns refusing the missing field
    itself."""
    manifest = {
        "pack": {"pack_id": "cognic-tool-x", "kind": "tool"},
        "mcp": {"caching": True, "elicitation_form": True},
        "data_governance": {},
    }
    findings = mcp.validate(manifest, tmp_path)
    assert not any(
        f.reason
        in (
            "mcp_caching_restricted_data_class",
            "mcp_elicitation_form_restricted_data_class",
        )
        for f in findings
    )


def test_mcp_data_classes_non_list_no_refusal(tmp_path: Path) -> None:
    """``data_classes = "customer_pii"`` (scalar instead of list) →
    treated as no declared classes, no cross-check refusal. T10
    owns the shape refusal."""
    manifest = {
        "pack": {"pack_id": "cognic-tool-x", "kind": "tool"},
        "mcp": {"caching": True},
        "data_governance": {"data_classes": "customer_pii"},
    }
    findings = mcp.validate(manifest, tmp_path)
    assert not any(f.reason == "mcp_caching_restricted_data_class" for f in findings)


def test_mcp_data_classes_with_non_string_entries_filtered(tmp_path: Path) -> None:
    """Non-string entries in data_classes (e.g., ints) are filtered
    out; only string entries can match "customer_pii"."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(caching=True, data_classes=[42, "customer_pii", None]),
        tmp_path,
    )
    matching = [f for f in findings if f.reason == "mcp_caching_restricted_data_class"]
    assert len(matching) == 1
    assert matching[0].payload["restricted_data_classes"] == ["customer_pii"]


def test_mcp_data_classes_whitespace_normalised(tmp_path: Path) -> None:
    """Whitespace around class names is stripped before matching."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(caching=True, data_classes=["  customer_pii  "]),
        tmp_path,
    )
    matching = [f for f in findings if f.reason == "mcp_caching_restricted_data_class"]
    assert len(matching) == 1


# ---------------------------------------------------------------------------
# (e) Dual-path validation (top-level [mcp] + [tool.cognic.mcp])
# ---------------------------------------------------------------------------


def test_mcp_validator_refuses_at_tool_cognic_mcp_path(tmp_path: Path) -> None:
    """Pack-author who follows ``docs/MCP-CONFORMANCE.md`` (which uses
    the legacy ``[tool.cognic.mcp]`` shape) gets validated too."""
    manifest = {
        "pack": {"pack_id": "cognic-tool-x", "kind": "tool"},
        "tool": {"cognic": {"mcp": {"caching": True}}},
        "data_governance": {"data_classes": ["customer_pii"]},
    }
    findings = mcp.validate(manifest, tmp_path)
    matching = [f for f in findings if f.reason == "mcp_caching_restricted_data_class"]
    assert len(matching) == 1
    assert matching[0].payload["block_path"] == "tool.cognic.mcp"


def test_mcp_validator_handles_partial_tool_cognic_path(tmp_path: Path) -> None:
    """Defensive: ``[tool]`` without ``[tool.cognic]`` does not crash."""
    findings = mcp.validate(
        {
            "pack": {"pack_id": "cognic-tool-x", "kind": "tool"},
            "tool": {"poetry": {}},
            "data_governance": {"data_classes": ["customer_pii"]},
        },
        tmp_path,
    )
    assert findings == []


def test_mcp_validator_handles_non_dict_tool(tmp_path: Path) -> None:
    """Defensive: ``[tool]`` set to a scalar does not crash."""
    findings = mcp.validate(
        {
            "pack": {"pack_id": "cognic-tool-x", "kind": "tool"},
            "tool": "not-a-table",
            "data_governance": {"data_classes": ["customer_pii"]},
        },
        tmp_path,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# (f) Type-shape pin + scaffold lifecycle pinner
# ---------------------------------------------------------------------------


def test_mcp_validator_returns_validator_finding_instances(tmp_path: Path) -> None:
    findings = mcp.validate(
        _tool_manifest_with_mcp(caching=True, data_classes=["customer_pii"]),
        tmp_path,
    )
    assert findings, "expected at least one finding"
    for f in findings:
        assert isinstance(f, ValidatorFinding)


def test_mcp_validator_accepts_scaffolded_tool_template(tmp_path: Path) -> None:
    """T5 tool scaffold's [mcp] + [data_governance] blocks pass T9
    cleanly. Drift detector — if the scaffold renames ``caching`` /
    ``elicitation_form`` without updating the validator, this trips.
    """
    import tomllib

    from cognic_agentos.cli.init import scaffold

    pack_root = scaffold(kind="tool", pack_name="example", parent_dir=tmp_path)
    parsed = tomllib.loads((pack_root / "cognic-pack-manifest.toml").read_text())
    findings = mcp.validate(parsed, pack_root)
    # Default scaffold has caching=false, elicitation_form=false, +
    # AUTHOR-FILL data_classes (which doesn't match "customer_pii"
    # exactly), so no T9 refusals fire.
    assert findings == [], (
        "T5 tool scaffold's [mcp] block produces refusals from T9; "
        "field-name drift between scaffold + validator. "
        f"Findings: {[(f.reason, f.payload) for f in findings]!r}"
    )


def test_mcp_validator_refuses_scaffolded_tool_with_restricted_caching(tmp_path: Path) -> None:
    """The corollary regression: when an author replaces the
    AUTHOR-FILL data_classes with ``["customer_pii"]`` AND flips
    ``caching = false`` to ``true``, T9 trips. Pins that the scaffold's
    field names align with the validator's recognized vocabulary."""
    import tomllib

    from cognic_agentos.cli.init import scaffold

    pack_root = scaffold(kind="tool", pack_name="example", parent_dir=tmp_path)
    manifest_path = pack_root / "cognic-pack-manifest.toml"
    text = manifest_path.read_text()
    text = text.replace("caching = false", "caching = true")
    # The T5 tool template's data_classes AUTHOR-FILL hint lists the
    # canonical DataClass values pipe-separated; replace the whole
    # placeholder line with a concrete restricted-tier class.
    old_data_classes_line = (
        'data_classes = ["AUTHOR-FILL: e.g., public | internal | '
        "customer_pii | payment_data | credentials | regulator_communication | "
        'audit_trail | model_inputs | model_outputs"]'
    )
    text = text.replace(old_data_classes_line, 'data_classes = ["customer_pii"]')
    manifest_path.write_text(text)

    parsed = tomllib.loads(manifest_path.read_text())
    findings = mcp.validate(parsed, pack_root)
    assert any(f.reason == "mcp_caching_restricted_data_class" for f in findings)


# ---------------------------------------------------------------------------
# (g) Exposed restricted-class set
# ---------------------------------------------------------------------------


def test_mcp_validator_exposes_restricted_classes_constant() -> None:
    """The validator exports its restricted-class set so tests +
    docs reference a single source of truth. Wave-1 scope: just
    "customer_pii"."""
    # T10 consolidated the restricted-class set into the canonical
    # vocab module; T9's mcp validator imports from there. The assertion
    # here is on the canonical source-of-truth.
    from cognic_agentos.cli._governance_vocab import RESTRICTED_DATA_CLASSES

    assert "customer_pii" in RESTRICTED_DATA_CLASSES


@pytest.mark.parametrize("klass", ["public", "internal", "confidential"])
def test_mcp_non_restricted_classes_do_not_trip_refusal(tmp_path: Path, klass: str) -> None:
    """Only "customer_pii" trips the cross-check at Wave-1 (per the
    closed-enum reason name). Other classes are caching-allowed."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(caching=True, data_classes=[klass]),
        tmp_path,
    )
    assert not any(f.reason == "mcp_caching_restricted_data_class" for f in findings)


# ---------------------------------------------------------------------------
# (h) R26 P2 #1 — runtime/docs field families (caching_strategy / elicitation_modes)
# ---------------------------------------------------------------------------


def test_mcp_caching_strategy_ttl_with_restricted_refuses(tmp_path: Path) -> None:
    """Runtime/docs shape: ``caching_strategy = "ttl"`` AND restricted
    data → refuse. Mirrors the runtime gate's behavior; without this,
    a docs-shaped manifest would bypass T9."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(caching_strategy="ttl", data_classes=["customer_pii"]),
        tmp_path,
    )
    matching = [f for f in findings if f.reason == "mcp_caching_restricted_data_class"]
    assert len(matching) == 1
    assert matching[0].payload["field"] == "mcp.caching_strategy"


def test_mcp_caching_strategy_none_with_restricted_no_refusal(tmp_path: Path) -> None:
    """Only ``caching_strategy = "ttl"`` is risky (matches runtime
    gate's narrow scope). Other strategies do not refuse."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(caching_strategy="none", data_classes=["customer_pii"]),
        tmp_path,
    )
    assert not any(f.reason == "mcp_caching_restricted_data_class" for f in findings)


def test_mcp_caching_strategy_memory_with_restricted_no_refusal(tmp_path: Path) -> None:
    """Memory caches don't survive process restarts; only TTL is the
    flagged risk in Wave-1."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(caching_strategy="memory", data_classes=["customer_pii"]),
        tmp_path,
    )
    assert not any(f.reason == "mcp_caching_restricted_data_class" for f in findings)


def test_mcp_elicitation_modes_form_with_restricted_refuses(tmp_path: Path) -> None:
    """Runtime/docs shape: ``elicitation_modes`` containing ``"form"``
    AND restricted data → refuse."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(elicitation_modes=["form"], data_classes=["customer_pii"]),
        tmp_path,
    )
    matching = [f for f in findings if f.reason == "mcp_elicitation_form_restricted_data_class"]
    assert len(matching) == 1
    assert matching[0].payload["field"] == "mcp.elicitation_modes"


def test_mcp_elicitation_modes_other_with_restricted_no_refusal(tmp_path: Path) -> None:
    """``elicitation_modes`` with other modes (e.g., "text") is fine."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(elicitation_modes=["text", "voice"], data_classes=["customer_pii"]),
        tmp_path,
    )
    assert not any(f.reason == "mcp_elicitation_form_restricted_data_class" for f in findings)


def test_mcp_elicitation_modes_empty_list_no_refusal(tmp_path: Path) -> None:
    findings = mcp.validate(
        _tool_manifest_with_mcp(elicitation_modes=[], data_classes=["customer_pii"]),
        tmp_path,
    )
    assert not any(f.reason == "mcp_elicitation_form_restricted_data_class" for f in findings)


def test_mcp_elicitation_modes_non_list_no_refusal(tmp_path: Path) -> None:
    """Defensive: ``elicitation_modes`` set to a scalar instead of a
    list does not crash and doesn't fire."""
    findings = mcp.validate(
        _tool_manifest_with_mcp(elicitation_modes="form", data_classes=["customer_pii"]),
        tmp_path,
    )
    assert not any(f.reason == "mcp_elicitation_form_restricted_data_class" for f in findings)


def test_mcp_runtime_field_families_at_legacy_path_refuse(tmp_path: Path) -> None:
    """The R26 P2 #1 load-bearing case: a docs-shaped manifest with
    ``caching_strategy="ttl"`` AND ``elicitation_modes=["form"]``
    placed at ``[tool.cognic.mcp]`` (legacy path) AND restricted
    data classes → BOTH refusals fire. Without this regression the
    legacy path was a complete bypass for runtime/docs-shaped
    declarations."""
    manifest = {
        "pack": {"pack_id": "cognic-tool-x", "kind": "tool"},
        "tool": {
            "cognic": {
                "mcp": {
                    "caching_strategy": "ttl",
                    "elicitation_modes": ["form"],
                }
            }
        },
        "data_governance": {"data_classes": ["customer_pii"]},
    }
    findings = mcp.validate(manifest, tmp_path)
    refusal_fields = {
        (f.reason, f.payload.get("field")) for f in findings if f.severity == "refusal"
    }
    assert (
        "mcp_caching_restricted_data_class",
        "tool.cognic.mcp.caching_strategy",
    ) in refusal_fields
    assert (
        "mcp_elicitation_form_restricted_data_class",
        "tool.cognic.mcp.elicitation_modes",
    ) in refusal_fields


# ---------------------------------------------------------------------------
# (i) R26 P2 #2 — legacy [tool.cognic.data_governance] cross-check
# ---------------------------------------------------------------------------


def test_mcp_restricted_at_legacy_data_governance_path_refuses(tmp_path: Path) -> None:
    """The R26 P2 #2 load-bearing case: restricted data classes
    declared at the legacy ``[tool.cognic.data_governance]`` path
    still trigger the cross-check, even when ``[mcp]`` is at the
    canonical top-level. Without this dual-path lookup, a docs-
    shaped data-governance block bypassed the gate."""
    manifest = {
        "pack": {"pack_id": "cognic-tool-x", "kind": "tool"},
        "mcp": {"caching": True},
        "tool": {"cognic": {"data_governance": {"data_classes": ["customer_pii"]}}},
    }
    findings = mcp.validate(manifest, tmp_path)
    matching = [f for f in findings if f.reason == "mcp_caching_restricted_data_class"]
    assert len(matching) == 1


def test_mcp_restricted_classes_unioned_across_governance_paths(tmp_path: Path) -> None:
    """If a manifest declares classes at BOTH governance paths, the
    union is used for the cross-check. Authors cannot hide a
    restricted class by splitting it across the two locations."""
    manifest = {
        "pack": {"pack_id": "cognic-tool-x", "kind": "tool"},
        "mcp": {"caching": True},
        "data_governance": {"data_classes": ["public"]},
        "tool": {"cognic": {"data_governance": {"data_classes": ["customer_pii"]}}},
    }
    findings = mcp.validate(manifest, tmp_path)
    assert any(f.reason == "mcp_caching_restricted_data_class" for f in findings)


def test_mcp_legacy_data_governance_partial_path_no_crash(tmp_path: Path) -> None:
    """Defensive: ``[tool]`` without ``[tool.cognic.data_governance]``
    falls through cleanly."""
    manifest = {
        "pack": {"pack_id": "cognic-tool-x", "kind": "tool"},
        "mcp": {"caching": True},
        "tool": {"cognic": {"some_other_block": {}}},
    }
    findings = mcp.validate(manifest, tmp_path)
    # No data_classes declared at all → no cross-check refusal.
    assert findings == []


def test_mcp_legacy_data_governance_non_dict_no_crash(tmp_path: Path) -> None:
    """Defensive: ``[tool.cognic.data_governance]`` set to a scalar
    falls through cleanly."""
    manifest = {
        "pack": {"pack_id": "cognic-tool-x", "kind": "tool"},
        "mcp": {"caching": True},
        "tool": {"cognic": {"data_governance": "not-a-table"}},
    }
    findings = mcp.validate(manifest, tmp_path)
    assert findings == []
