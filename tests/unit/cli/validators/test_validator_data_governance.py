"""Sprint-7A T10 — ADR-017 data-governance-validator regressions.

Critical-controls module per Doctrine Decision G — runtime DLP
enforcement depends on this contract. Bad declarations propagate to
runtime mis-handling, so the build-time validator is the load-bearing
gate that catches manifest inconsistencies before the pack ships.

Validator contract (per ADR-017 + the plan-of-record T10 section):

  - ``data_classes`` (required): non-empty list of strings, each
    matching a value in the closed-enum ``DataClass`` literal at
    ``cli/_governance_vocab.py``. AUTHOR-FILL placeholders + empty
    strings + non-string entries refused.
  - ``purpose`` (required): single string matching ``Purpose``.
  - ``retention_policy`` (required): single string matching
    ``RetentionPolicy``.
  - ``retention_max_window`` (required when ``retention_policy != "none"``):
    positive number (TOML int or float) representing the retention
    period; semantics per pack-author docs.
  - ``egress_allow_list`` (optional): list of strings; non-list
    refused as malformed.

  Cross-validation:
    - ``[risk_tier].tier == "low"`` AND data_classes intersects the
      restricted set → ``data_governance_contract_inconsistent_with_risk_tier``.
      (Other tier values are tolerable; the bright line is "low" tier
      claiming sensitive data classes.)
    - ``[mcp].caching = true`` (or ``caching_strategy = "ttl"``) AND
      data_classes intersects the restricted set →
      ``data_governance_contract_inconsistent_with_mcp_caching``.
      (T9 fires its own refusal on the same violation; T10 fires the
      data-governance perspective so authors see the cross-check
      from both sides.)

Closed-enum reasons (T10 owns):

  - ``data_governance_contract_missing`` — catch-all for any
    field-shape failure; ``payload.failure_mode`` distinguishes
    (``data_classes_missing`` / ``data_classes_empty`` /
    ``data_classes_invalid_value`` / ``purpose_missing`` /
    ``purpose_invalid`` / ``retention_policy_missing`` /
    ``retention_policy_invalid`` / ``retention_max_window_missing`` /
    ``retention_max_window_invalid`` / ``egress_allow_list_invalid_shape``).
  - ``data_governance_contract_inconsistent_with_risk_tier``.
  - ``data_governance_contract_inconsistent_with_mcp_caching``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli.validators import data_governance


def _manifest(
    *,
    data_classes: Any = None,
    purpose: Any = "transaction_processing",
    retention_policy: Any = "none",
    retention_max_window: Any = None,
    egress_allow_list: Any = None,
    risk_tier: Any = "medium",
    mcp_caching: bool | None = None,
    drop_data_governance: bool = False,
) -> dict[str, Any]:
    """Build a manifest dict with a populated ``[data_governance]``
    block; per-test overrides via kwargs. ``None`` for an explicit
    field deletes it (so absence can be tested)."""
    if drop_data_governance:
        gov: dict[str, Any] = {}
    else:
        gov = {
            "data_classes": (data_classes if data_classes is not None else ["public", "internal"]),
            "purpose": purpose,
            "retention_policy": retention_policy,
        }
        if retention_max_window is not None:
            gov["retention_max_window"] = retention_max_window
        if egress_allow_list is not None:
            gov["egress_allow_list"] = egress_allow_list
        # Allow tests to delete fields by passing the special sentinel.
        gov = {k: v for k, v in gov.items() if v is not _DELETE}

    manifest: dict[str, Any] = {
        "pack": {"pack_id": "cognic-tool-demo", "kind": "tool"},
    }
    if not drop_data_governance:
        manifest["data_governance"] = gov

    if risk_tier is not None:
        manifest["risk_tier"] = {"tier": risk_tier}

    if mcp_caching is not None:
        manifest["mcp"] = {"caching": mcp_caching}

    return manifest


_DELETE = object()


# ---------------------------------------------------------------------------
# (a) Block presence
# ---------------------------------------------------------------------------


def test_data_governance_block_absent_no_findings(tmp_path: Path) -> None:
    """If ``[data_governance]`` is absent entirely, the orchestrator's
    shape gate (T6) refuses with ``manifest_missing_required_block``;
    this validator is never called for that case. Direct unit-test
    entry without the block: validator no-ops."""
    findings = data_governance.validate(
        {"pack": {"pack_id": "cognic-tool-x", "kind": "tool"}},
        tmp_path,
    )
    assert findings == []


def test_data_governance_block_not_a_dict_no_findings(tmp_path: Path) -> None:
    """Defense-in-depth: malformed block falls through cleanly."""
    findings = data_governance.validate(
        {"pack": {"pack_id": "cognic-tool-x", "kind": "tool"}, "data_governance": "x"},
        tmp_path,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# (b) data_classes shape
# ---------------------------------------------------------------------------


def test_data_classes_missing_refuses(tmp_path: Path) -> None:
    findings = data_governance.validate(
        {
            "pack": {"pack_id": "x", "kind": "tool"},
            "data_governance": {
                "purpose": "transaction_processing",
                "retention_policy": "none",
            },
        },
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.reason == "data_governance_contract_missing"
        and f.payload.get("failure_mode") == "data_classes_missing"
    ]
    assert len(matching) == 1


def test_data_classes_empty_refuses(tmp_path: Path) -> None:
    findings = data_governance.validate(_manifest(data_classes=[]), tmp_path)
    matching = [f for f in findings if f.payload.get("failure_mode") == "data_classes_empty"]
    assert len(matching) == 1


def test_data_classes_non_list_refuses(tmp_path: Path) -> None:
    findings = data_governance.validate(_manifest(data_classes="public"), tmp_path)
    matching = [f for f in findings if f.payload.get("failure_mode") == "data_classes_missing"]
    assert len(matching) == 1


@pytest.mark.parametrize("bad_value", ["AUTHOR-FILL: e.g., public", "made_up_class", "", "   "])
def test_data_classes_invalid_value_refuses(tmp_path: Path, bad_value: str) -> None:
    """Any value not in the closed-enum DataClass literal trips
    refusal. Includes AUTHOR-FILL placeholders + empty/whitespace
    strings."""
    findings = data_governance.validate(_manifest(data_classes=[bad_value]), tmp_path)
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "data_classes_invalid_value"
    ]
    assert matching, (
        f"expected data_classes_invalid_value finding for {bad_value!r}; "
        f"got {[(f.reason, f.payload) for f in findings]!r}"
    )
    assert bad_value in matching[0].payload.get("invalid_values", [])


def test_data_classes_non_string_entry_refuses(tmp_path: Path) -> None:
    findings = data_governance.validate(_manifest(data_classes=[42]), tmp_path)
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "data_classes_invalid_value"
    ]
    assert len(matching) == 1


def test_data_classes_all_valid_no_finding(tmp_path: Path) -> None:
    findings = data_governance.validate(_manifest(data_classes=["public", "internal"]), tmp_path)
    assert not any(f.payload.get("failure_mode", "").startswith("data_classes_") for f in findings)


# ---------------------------------------------------------------------------
# (c) purpose
# ---------------------------------------------------------------------------


def test_purpose_missing_refuses(tmp_path: Path) -> None:
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {
            "data_classes": ["public"],
            "retention_policy": "none",
        },
    }
    findings = data_governance.validate(manifest, tmp_path)
    matching = [f for f in findings if f.payload.get("failure_mode") == "purpose_missing"]
    assert len(matching) == 1


@pytest.mark.parametrize(
    "bad_purpose",
    ["AUTHOR-FILL: business purpose", "made_up_purpose", "", 42],
)
def test_purpose_invalid_refuses(tmp_path: Path, bad_purpose: Any) -> None:
    findings = data_governance.validate(_manifest(purpose=bad_purpose), tmp_path)
    matching = [
        f
        for f in findings
        if f.payload.get("failure_mode") in ("purpose_missing", "purpose_invalid")
    ]
    assert matching, (
        f"expected purpose_missing/invalid finding for {bad_purpose!r}; "
        f"got {[(f.reason, f.payload) for f in findings]!r}"
    )


def test_purpose_valid_no_finding(tmp_path: Path) -> None:
    findings = data_governance.validate(_manifest(purpose="transaction_processing"), tmp_path)
    assert not any(f.payload.get("failure_mode", "").startswith("purpose_") for f in findings)


# ---------------------------------------------------------------------------
# (d) retention_policy
# ---------------------------------------------------------------------------


def test_retention_policy_missing_refuses(tmp_path: Path) -> None:
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {
            "data_classes": ["public"],
            "purpose": "transaction_processing",
        },
    }
    findings = data_governance.validate(manifest, tmp_path)
    matching = [f for f in findings if f.payload.get("failure_mode") == "retention_policy_missing"]
    assert len(matching) == 1


def test_retention_policy_invalid_refuses(tmp_path: Path) -> None:
    findings = data_governance.validate(_manifest(retention_policy="forever_and_ever"), tmp_path)
    matching = [f for f in findings if f.payload.get("failure_mode") == "retention_policy_invalid"]
    assert len(matching) == 1


# ---------------------------------------------------------------------------
# (e) retention_max_window (conditional on retention_policy)
# ---------------------------------------------------------------------------


def test_retention_max_window_required_when_policy_not_none(tmp_path: Path) -> None:
    """Any retention_policy other than "none" requires a positive
    retention_max_window (the policy declares the shape; the window
    declares the magnitude)."""
    findings = data_governance.validate(_manifest(retention_policy="purpose_window"), tmp_path)
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "retention_max_window_missing"
    ]
    assert len(matching) == 1


def test_retention_max_window_not_required_when_policy_none(tmp_path: Path) -> None:
    findings = data_governance.validate(_manifest(retention_policy="none"), tmp_path)
    assert not any(
        f.payload.get("failure_mode") == "retention_max_window_missing" for f in findings
    )


@pytest.mark.parametrize("bad_window", [0, -1, "thirty days", None])
def test_retention_max_window_invalid_refuses(tmp_path: Path, bad_window: Any) -> None:
    """Non-positive numbers + non-numeric values refused. ``None``
    counts as missing when retention_policy != "none"."""
    findings = data_governance.validate(
        _manifest(retention_policy="purpose_window", retention_max_window=bad_window),
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.payload.get("failure_mode")
        in ("retention_max_window_missing", "retention_max_window_invalid")
    ]
    assert matching


def test_retention_max_window_valid_no_finding(tmp_path: Path) -> None:
    findings = data_governance.validate(
        _manifest(retention_policy="purpose_window", retention_max_window=90),
        tmp_path,
    )
    assert not any(
        f.payload.get("failure_mode", "").startswith("retention_max_window_") for f in findings
    )


# ---------------------------------------------------------------------------
# (f) egress_allow_list
# ---------------------------------------------------------------------------


def test_egress_allow_list_optional_default_no_finding(tmp_path: Path) -> None:
    """Absent ``egress_allow_list`` is fine — no egress declared."""
    findings = data_governance.validate(_manifest(), tmp_path)
    assert not any(
        f.payload.get("failure_mode") == "egress_allow_list_invalid_shape" for f in findings
    )


def test_egress_allow_list_empty_list_no_finding(tmp_path: Path) -> None:
    findings = data_governance.validate(_manifest(egress_allow_list=[]), tmp_path)
    assert not any(
        f.payload.get("failure_mode") == "egress_allow_list_invalid_shape" for f in findings
    )


def test_egress_allow_list_non_list_refuses(tmp_path: Path) -> None:
    findings = data_governance.validate(_manifest(egress_allow_list="api.example.com"), tmp_path)
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "egress_allow_list_invalid_shape"
    ]
    assert len(matching) == 1


def test_egress_allow_list_non_string_entry_refuses(tmp_path: Path) -> None:
    findings = data_governance.validate(
        _manifest(egress_allow_list=["api.example.com", 42]), tmp_path
    )
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "egress_allow_list_invalid_shape"
    ]
    assert len(matching) == 1


# ---------------------------------------------------------------------------
# (g) Cross-validation: risk_tier
# ---------------------------------------------------------------------------


def test_low_tier_with_restricted_class_refuses(tmp_path: Path) -> None:
    findings = data_governance.validate(
        _manifest(data_classes=["customer_pii"], risk_tier="low"), tmp_path
    )
    matching = [
        f for f in findings if f.reason == "data_governance_contract_inconsistent_with_risk_tier"
    ]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"
    assert "customer_pii" in matching[0].payload["restricted_data_classes"]
    assert matching[0].payload["risk_tier"] == "low"


def test_low_tier_with_non_restricted_class_no_refusal(tmp_path: Path) -> None:
    findings = data_governance.validate(
        _manifest(data_classes=["public", "internal"], risk_tier="low"), tmp_path
    )
    assert not any(
        f.reason == "data_governance_contract_inconsistent_with_risk_tier" for f in findings
    )


def test_high_tier_with_restricted_class_no_refusal(tmp_path: Path) -> None:
    """A high-tier pack handling restricted data is consistent — no
    risk_tier refusal."""
    findings = data_governance.validate(
        _manifest(data_classes=["customer_pii"], risk_tier="high"), tmp_path
    )
    assert not any(
        f.reason == "data_governance_contract_inconsistent_with_risk_tier" for f in findings
    )


def test_risk_tier_block_missing_no_cross_check(tmp_path: Path) -> None:
    """If [risk_tier] is absent, T11 owns the missing-block refusal;
    T10 doesn't double-fire — just skips the cross-check."""
    manifest = _manifest(data_classes=["customer_pii"])
    manifest.pop("risk_tier", None)
    findings = data_governance.validate(manifest, tmp_path)
    assert not any(
        f.reason == "data_governance_contract_inconsistent_with_risk_tier" for f in findings
    )


# ---------------------------------------------------------------------------
# (h) Cross-validation: mcp_caching
# ---------------------------------------------------------------------------


def test_mcp_caching_with_restricted_class_refuses(tmp_path: Path) -> None:
    findings = data_governance.validate(
        _manifest(data_classes=["customer_pii"], mcp_caching=True), tmp_path
    )
    matching = [
        f for f in findings if f.reason == "data_governance_contract_inconsistent_with_mcp_caching"
    ]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"
    assert "customer_pii" in matching[0].payload["restricted_data_classes"]


def test_mcp_caching_strategy_ttl_with_restricted_refuses(tmp_path: Path) -> None:
    """The string-strategy form (caching_strategy="ttl") also trips
    the cross-check, mirroring T9's dual-field-family detection."""
    manifest = _manifest(data_classes=["customer_pii"])
    manifest["mcp"] = {"caching_strategy": "ttl"}
    findings = data_governance.validate(manifest, tmp_path)
    matching = [
        f for f in findings if f.reason == "data_governance_contract_inconsistent_with_mcp_caching"
    ]
    assert len(matching) == 1


def test_mcp_block_missing_no_cross_check(tmp_path: Path) -> None:
    """Skill packs + agent packs ship without [mcp]; absent [mcp]
    means no cross-check fires."""
    manifest = _manifest(data_classes=["customer_pii"])
    manifest.pop("mcp", None)
    findings = data_governance.validate(manifest, tmp_path)
    assert not any(
        f.reason == "data_governance_contract_inconsistent_with_mcp_caching" for f in findings
    )


def test_mcp_caching_with_non_restricted_class_no_refusal(tmp_path: Path) -> None:
    findings = data_governance.validate(
        _manifest(data_classes=["public"], mcp_caching=True), tmp_path
    )
    assert not any(
        f.reason == "data_governance_contract_inconsistent_with_mcp_caching" for f in findings
    )


# ---------------------------------------------------------------------------
# (i) Dual-path lookup ([data_governance] + [tool.cognic.data_governance])
# ---------------------------------------------------------------------------


def test_legacy_data_governance_path_validated(tmp_path: Path) -> None:
    """Manifests using the legacy ``[tool.cognic.data_governance]``
    layout still get validated."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "tool": {
            "cognic": {
                "data_governance": {
                    "data_classes": ["AUTHOR-FILL: e.g., public, restricted"],
                    "purpose": "transaction_processing",
                    "retention_policy": "none",
                }
            }
        },
    }
    findings = data_governance.validate(manifest, tmp_path)
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "data_classes_invalid_value"
    ]
    assert matching


# ---------------------------------------------------------------------------
# (j) Type-shape pin + happy path
# ---------------------------------------------------------------------------


def test_data_governance_findings_are_validator_finding_instances(tmp_path: Path) -> None:
    findings = data_governance.validate(_manifest(data_classes=[]), tmp_path)
    assert findings, "expected at least one finding"
    for f in findings:
        assert isinstance(f, ValidatorFinding)


def test_retention_max_window_bool_rejected(tmp_path: Path) -> None:
    """Booleans subclass int in Python; without an explicit guard,
    ``retention_max_window = true`` would slip through (``True > 0``
    is true). The validator rejects bools to keep the contract
    type-strict."""
    findings = data_governance.validate(
        _manifest(retention_policy="purpose_window", retention_max_window=True),
        tmp_path,
    )
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "retention_max_window_invalid"
    ]
    assert len(matching) == 1


def test_risk_tier_non_string_no_cross_check(tmp_path: Path) -> None:
    """Defensive: ``[risk_tier].tier`` set to a non-string value falls
    through cleanly (T11 owns the shape refusal)."""
    manifest = _manifest(data_classes=["customer_pii"], risk_tier=42)
    findings = data_governance.validate(manifest, tmp_path)
    assert not any(
        f.reason == "data_governance_contract_inconsistent_with_risk_tier" for f in findings
    )


def test_mcp_cross_check_iterates_both_locations(tmp_path: Path) -> None:
    """The mcp_caching cross-check iterates both [mcp] paths. If the
    canonical top-level [mcp] doesn't enable caching but the legacy
    [tool.cognic.mcp] does (with caching_strategy="ttl"), the
    cross-check still fires."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {
            "data_classes": ["customer_pii"],
            "purpose": "transaction_processing",
            "retention_policy": "none",
        },
        "mcp": {"caching": False},
        "tool": {"cognic": {"mcp": {"caching_strategy": "ttl"}}},
    }
    findings = data_governance.validate(manifest, tmp_path)
    matching = [
        f for f in findings if f.reason == "data_governance_contract_inconsistent_with_mcp_caching"
    ]
    assert len(matching) == 1


# ---------------------------------------------------------------------------
# (j) R27 P2 #2 — union semantics across both data_governance paths
# ---------------------------------------------------------------------------


def test_split_classes_across_paths_unioned_for_cross_check(tmp_path: Path) -> None:
    """The R27 P2 #2 load-bearing case: a manifest that declares safe
    classes at the canonical location AND smuggles restricted classes
    at the legacy location MUST still trip the cross-checks. Without
    union semantics, a pack could split declarations to bypass the
    restricted-data gate."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {
            "data_classes": ["public"],
            "purpose": "transaction_processing",
            "retention_policy": "none",
        },
        "tool": {
            "cognic": {
                "data_governance": {
                    "data_classes": ["customer_pii"],
                    "purpose": "transaction_processing",
                    "retention_policy": "none",
                }
            }
        },
        "risk_tier": {"tier": "low"},
    }
    findings = data_governance.validate(manifest, tmp_path)
    matching = [
        f for f in findings if f.reason == "data_governance_contract_inconsistent_with_risk_tier"
    ]
    assert len(matching) == 1, (
        "split-path data_classes declaration bypassed the cross-check; "
        f"findings: {[(f.reason, f.payload) for f in findings]!r}"
    )
    assert "customer_pii" in matching[0].payload["restricted_data_classes"]


def test_each_path_validated_independently(tmp_path: Path) -> None:
    """Field-shape failures fire independently for each declared
    location — pack authors get refusals for whatever's broken in
    each block."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {
            # missing data_classes
            "purpose": "transaction_processing",
            "retention_policy": "none",
        },
        "tool": {
            "cognic": {
                "data_governance": {
                    "data_classes": ["customer_pii"],
                    # missing purpose
                    "retention_policy": "none",
                }
            }
        },
    }
    findings = data_governance.validate(manifest, tmp_path)
    block_paths_with_findings = {
        f.payload["block_path"] for f in findings if f.reason == "data_governance_contract_missing"
    }
    assert "data_governance" in block_paths_with_findings, (
        "expected data_classes_missing on canonical block"
    )
    assert "tool.cognic.data_governance" in block_paths_with_findings, (
        "expected purpose_missing on legacy block"
    )


def test_data_governance_full_pass_returns_empty(tmp_path: Path) -> None:
    """Every field populated with valid values + cross-validations
    consistent → empty findings."""
    findings = data_governance.validate(
        _manifest(
            data_classes=["public", "internal"],
            purpose="transaction_processing",
            retention_policy="purpose_window",
            retention_max_window=90,
            egress_allow_list=["api.example.com"],
            risk_tier="medium",
        ),
        tmp_path,
    )
    assert findings == []
