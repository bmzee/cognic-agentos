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
  - ``dlp_pre_hooks`` / ``dlp_post_hooks`` (optional, Sprint-7A2 T10
    extension): list of snake_case hook_id strings; per-list
    duplicates refused; cross-pack resolution remains a runtime
    registry concern.

  Cross-validation:
    - Declared risk tier in :data:`LOW_AUTHORITY_TIERS` (the ADR-014
      ``read_only`` / ``internal_write`` set) AND data_classes
      intersects the :data:`RESTRICTED_DATA_CLASSES` set →
      ``data_governance_contract_inconsistent_with_risk_tier``. The
      tier is read from BOTH the canonical ``[risk_tier].tier`` (T5
      shape) AND the legacy ``[tool.cognic.runtime].risk_tier``
      (docs / fixture-aligned shape per ``docs/BUILD_PLAN.md:528``);
      either declaration with the restricted-class combination
      trips the refusal. Higher-authority tiers
      (``customer_data_read`` and above per ADR-014's tier ordering)
      are tolerable on this T10-side check; T11 owns the per-class
      minimum-tier enforcement.
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
    Sprint-7A2 T10 adds six new failure_mode values:
    ``dlp_pre_hooks_invalid_shape`` / ``dlp_post_hooks_invalid_shape``
    / ``dlp_pre_hooks_invalid_hook_id`` / ``dlp_post_hooks_invalid_hook_id``
    / ``dlp_pre_hooks_duplicate`` / ``dlp_post_hooks_duplicate``.
  - ``data_governance_contract_inconsistent_with_risk_tier``.
  - ``data_governance_contract_inconsistent_with_mcp_caching``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli.validators import data_governance
from cognic_agentos.cli.validators import hooks as _hooks_validator


def _manifest(
    *,
    data_classes: Any = None,
    purpose: Any = "transaction_processing",
    retention_policy: Any = "none",
    retention_max_window: Any = None,
    egress_allow_list: Any = None,
    dlp_pre_hooks: Any = None,
    dlp_post_hooks: Any = None,
    risk_tier: Any = "customer_data_read",
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
        # Sprint-7A2 T10: dlp_*_hooks are optional shape-validated lists
        # of snake_case hook_ids. ``None`` here means absent (validator
        # no-ops); explicit ``[]`` means present-and-empty (also valid;
        # tests that pin empty-list semantics pass ``[]`` directly).
        if dlp_pre_hooks is not None:
            gov["dlp_pre_hooks"] = dlp_pre_hooks
        if dlp_post_hooks is not None:
            gov["dlp_post_hooks"] = dlp_post_hooks
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
        _manifest(data_classes=["customer_pii"], risk_tier="read_only"), tmp_path
    )
    matching = [
        f for f in findings if f.reason == "data_governance_contract_inconsistent_with_risk_tier"
    ]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"
    assert "customer_pii" in matching[0].payload["restricted_data_classes"]
    assert matching[0].payload["risk_tier"] == "read_only"


def test_low_tier_with_non_restricted_class_no_refusal(tmp_path: Path) -> None:
    findings = data_governance.validate(
        _manifest(data_classes=["public", "internal"], risk_tier="read_only"), tmp_path
    )
    assert not any(
        f.reason == "data_governance_contract_inconsistent_with_risk_tier" for f in findings
    )


def test_high_tier_with_restricted_class_no_refusal(tmp_path: Path) -> None:
    """A high-tier pack handling restricted data is consistent — no
    risk_tier refusal."""
    findings = data_governance.validate(
        _manifest(data_classes=["customer_pii"], risk_tier="customer_data_write"), tmp_path
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


def test_legacy_runtime_risk_tier_path_triggers_cross_check(tmp_path: Path) -> None:
    """T11 doctrine fix: T10's cross-check reads the legacy
    ``[tool.cognic.runtime].risk_tier`` shape too, so a docs-shaped
    manifest declaring ``read_only`` there + ``customer_pii`` in
    data_classes still trips the refusal."""
    manifest = _manifest(data_classes=["customer_pii"])
    manifest.pop("risk_tier", None)
    manifest["tool"] = {"cognic": {"runtime": {"risk_tier": "read_only"}}}
    findings = data_governance.validate(manifest, tmp_path)
    matching = [
        f for f in findings if f.reason == "data_governance_contract_inconsistent_with_risk_tier"
    ]
    assert len(matching) == 1
    assert matching[0].payload["risk_tier"] == "read_only"
    assert "customer_pii" in matching[0].payload["restricted_data_classes"]


def test_split_path_low_tier_smuggle_caught_by_union(tmp_path: Path) -> None:
    """Pack-author splits the declaration: canonical ``[risk_tier].tier``
    set to a high-authority tier (``customer_data_write``) but legacy
    ``[tool.cognic.runtime].risk_tier`` smuggles ``read_only``. T10's
    cross-check unions across both paths — the legacy declaration
    still trips the refusal because the runtime DLP enforcer cannot
    rely on either declaration alone being authoritative."""
    manifest = _manifest(data_classes=["customer_pii"], risk_tier="customer_data_write")
    manifest["tool"] = {"cognic": {"runtime": {"risk_tier": "read_only"}}}
    findings = data_governance.validate(manifest, tmp_path)
    matching = [
        f for f in findings if f.reason == "data_governance_contract_inconsistent_with_risk_tier"
    ]
    assert len(matching) == 1
    assert matching[0].payload["risk_tier"] == "read_only"


def test_legacy_runtime_non_string_risk_tier_no_cross_check(tmp_path: Path) -> None:
    """Defensive: ``[tool.cognic.runtime].risk_tier`` declared as a
    non-string falls through cleanly (T11 owns the shape refusal)."""
    manifest = _manifest(data_classes=["customer_pii"])
    manifest.pop("risk_tier", None)
    manifest["tool"] = {"cognic": {"runtime": {"risk_tier": 42}}}
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
        "risk_tier": {"tier": "read_only"},
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
            risk_tier="customer_data_read",
        ),
        tmp_path,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# (k) Sprint-7A2 T10 — dlp_pre_hooks / dlp_post_hooks shape
# ---------------------------------------------------------------------------
#
# Per ADR-017 + the Sprint-7A2 plan-of-record T10 paragraph:
# shape-validate ``dlp_pre_hooks`` + ``dlp_post_hooks`` as string
# arrays of snake_case hook_ids. Cross-pack resolution (i.e., whether
# the named hook_id actually corresponds to a registered hook in any
# verified hook pack) remains a runtime registry concern — build-time
# validator only checks shape + identifier syntax + per-list
# uniqueness.
#
# Six new ``payload.failure_mode`` values land under the existing
# ``data_governance_contract_missing`` closed-enum reason (no new
# ValidatorReason member; consistent with the 10-failure-mode pattern
# the validator already uses for data_classes / purpose / retention /
# egress_allow_list field-shape failures).


def test_dlp_hook_ref_pattern_mirrors_hook_id_pattern_drift_guard() -> None:
    """**Lock-B drift guard.** ``data_governance._HOOK_REF_PATTERN`` is
    a documented mirror of ``validators/hooks.py:_HOOK_ID_PATTERN``;
    the per-id parametrized tests above only sample a handful of bad
    inputs, so if the hooks-validator regex later changes intentionally
    (e.g., to allow leading underscores, or to require a length cap),
    this mirror could silently diverge and pack authors would see
    contradictory refusals across the two validators (T6 hooks-side
    accepts an id that T10 dlp-reference-side refuses, or vice versa).

    Pin the mirror invariant directly: both ``re.Pattern.pattern``
    strings AND both ``re.Pattern.flags`` integers MUST match. If
    either side genuinely needs to change, this test forces the same
    commit to update both — at which point the maintainer either
    re-syncs the mirror or consciously breaks the invariant after
    re-evaluating the cross-validator-consistency contract.

    Sister-doctrine to the AST self-test pattern from T7's
    payload-never-logged regression (per
    ``feedback_security_regression_hardening.md``): load-bearing
    invariants get explicit pins, not just docstrings.
    """
    assert data_governance._HOOK_REF_PATTERN.pattern == _hooks_validator._HOOK_ID_PATTERN.pattern, (
        "data_governance._HOOK_REF_PATTERN diverged from "
        "validators/hooks.py:_HOOK_ID_PATTERN. The mirror is "
        "load-bearing for cross-validator consistency on hook_id "
        "syntax; either re-sync, or update both sites + this test "
        "consciously after re-evaluating the contract."
    )
    assert data_governance._HOOK_REF_PATTERN.flags == _hooks_validator._HOOK_ID_PATTERN.flags, (
        "data_governance._HOOK_REF_PATTERN re flags drifted from "
        "validators/hooks.py:_HOOK_ID_PATTERN flags."
    )


def test_dlp_pre_hooks_absent_no_finding(tmp_path: Path) -> None:
    """``dlp_pre_hooks`` is OPTIONAL — absence produces no finding."""
    findings = data_governance.validate(_manifest(), tmp_path)
    assert not any(f.payload.get("failure_mode", "").startswith("dlp_pre_hooks_") for f in findings)


def test_dlp_post_hooks_absent_no_finding(tmp_path: Path) -> None:
    """``dlp_post_hooks`` is OPTIONAL — absence produces no finding."""
    findings = data_governance.validate(_manifest(), tmp_path)
    assert not any(
        f.payload.get("failure_mode", "").startswith("dlp_post_hooks_") for f in findings
    )


def test_dlp_pre_hooks_empty_list_no_finding(tmp_path: Path) -> None:
    """Explicit empty list (``dlp_pre_hooks = []``) is valid — pack
    declares zero pre-hooks. No finding."""
    findings = data_governance.validate(_manifest(dlp_pre_hooks=[]), tmp_path)
    assert not any(f.payload.get("failure_mode", "").startswith("dlp_pre_hooks_") for f in findings)


def test_dlp_post_hooks_empty_list_no_finding(tmp_path: Path) -> None:
    findings = data_governance.validate(_manifest(dlp_post_hooks=[]), tmp_path)
    assert not any(
        f.payload.get("failure_mode", "").startswith("dlp_post_hooks_") for f in findings
    )


@pytest.mark.parametrize(
    "bad_value",
    [
        "redact_pii_in_input",  # bare string, not a list
        42,  # number
        {"redact": True},  # dict
        ("redact_pii",),  # tuple — TOML produces list, not tuple
    ],
)
def test_dlp_pre_hooks_non_list_refused(tmp_path: Path, bad_value: Any) -> None:
    """``dlp_pre_hooks`` must be a list (TOML array). Any non-list
    shape trips ``dlp_pre_hooks_invalid_shape``."""
    findings = data_governance.validate(_manifest(dlp_pre_hooks=bad_value), tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "data_governance_contract_missing"
        and f.payload.get("failure_mode") == "dlp_pre_hooks_invalid_shape"
    ]
    assert len(matching) == 1, (
        f"expected dlp_pre_hooks_invalid_shape for {bad_value!r}; "
        f"got {[(f.reason, f.payload) for f in findings]!r}"
    )


@pytest.mark.parametrize(
    "bad_value",
    [
        "mask_account_numbers",
        42,
        {"mask": True},
        ("mask_account",),
    ],
)
def test_dlp_post_hooks_non_list_refused(tmp_path: Path, bad_value: Any) -> None:
    findings = data_governance.validate(_manifest(dlp_post_hooks=bad_value), tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "data_governance_contract_missing"
        and f.payload.get("failure_mode") == "dlp_post_hooks_invalid_shape"
    ]
    assert len(matching) == 1


def test_dlp_pre_hooks_non_string_entry_refused(tmp_path: Path) -> None:
    """A list with a non-string entry (``[\"redact_pii\", 42]``) is
    structurally malformed → ``dlp_pre_hooks_invalid_shape``."""
    findings = data_governance.validate(_manifest(dlp_pre_hooks=["redact_pii", 42]), tmp_path)
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "dlp_pre_hooks_invalid_shape"
    ]
    assert len(matching) == 1


def test_dlp_post_hooks_non_string_entry_refused(tmp_path: Path) -> None:
    findings = data_governance.validate(_manifest(dlp_post_hooks=["mask_accounts", None]), tmp_path)
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "dlp_post_hooks_invalid_shape"
    ]
    assert len(matching) == 1


@pytest.mark.parametrize(
    "bad_id",
    [
        "Bad-Name",  # hyphen + uppercase
        "redact pii",  # space
        "1leading_digit",  # starts with digit
        "UPPER_CASE",  # uppercase
        "",  # empty
        "_leading_underscore",  # T6's _HOOK_ID_PATTERN starts with [a-z]
        "trailing-",  # hyphen
        "with.dot",  # dot
    ],
)
def test_dlp_pre_hooks_invalid_hook_id_refused(tmp_path: Path, bad_id: str) -> None:
    """Each entry MUST match the snake_case identifier pattern
    (``^[a-z][a-z0-9_]*$``). Any miss trips
    ``dlp_pre_hooks_invalid_hook_id``. Mirrors the same pattern at
    ``cli/validators/hooks.py:_HOOK_ID_PATTERN`` (T6); the regex is
    duplicated as a documented mirror."""
    findings = data_governance.validate(_manifest(dlp_pre_hooks=[bad_id]), tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "data_governance_contract_missing"
        and f.payload.get("failure_mode") == "dlp_pre_hooks_invalid_hook_id"
    ]
    assert matching, (
        f"expected dlp_pre_hooks_invalid_hook_id for {bad_id!r}; "
        f"got {[(f.reason, f.payload) for f in findings]!r}"
    )
    assert matching[0].payload.get("invalid_value") == bad_id


@pytest.mark.parametrize(
    "bad_id",
    [
        "Bad-Name",
        "redact pii",
        "1leading_digit",
        "UPPER_CASE",
        "",
        "_leading_underscore",
        "trailing-",
        "with.dot",
    ],
)
def test_dlp_post_hooks_invalid_hook_id_refused(tmp_path: Path, bad_id: str) -> None:
    findings = data_governance.validate(_manifest(dlp_post_hooks=[bad_id]), tmp_path)
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "dlp_post_hooks_invalid_hook_id"
    ]
    assert matching


def test_dlp_pre_hooks_duplicate_refused(tmp_path: Path) -> None:
    """Per the lock: REFUSE duplicates at build time. Tightens manifest
    canonicalization; surfaces author error loudly. Doesn't compete with
    T8 dispatcher's runtime dedupe (runtime stays defensive, build-time
    stays canonical)."""
    findings = data_governance.validate(
        _manifest(dlp_pre_hooks=["redact_pii", "redact_pii"]), tmp_path
    )
    matching = [
        f
        for f in findings
        if f.reason == "data_governance_contract_missing"
        and f.payload.get("failure_mode") == "dlp_pre_hooks_duplicate"
    ]
    assert len(matching) == 1
    assert matching[0].payload.get("duplicate_hook_id") == "redact_pii"


def test_dlp_post_hooks_duplicate_refused(tmp_path: Path) -> None:
    findings = data_governance.validate(
        _manifest(dlp_post_hooks=["mask_accounts", "mask_accounts", "redact_post"]),
        tmp_path,
    )
    matching = [f for f in findings if f.payload.get("failure_mode") == "dlp_post_hooks_duplicate"]
    assert len(matching) == 1
    assert matching[0].payload.get("duplicate_hook_id") == "mask_accounts"


def test_dlp_pre_and_post_hooks_can_share_id(tmp_path: Path) -> None:
    """Per-list uniqueness is the only check. The same hook_id appearing
    in BOTH ``dlp_pre_hooks`` and ``dlp_post_hooks`` is allowed — a
    single Hook implementation can register for both phases via
    separate declarations. T10 does NOT cross-check the two lists."""
    findings = data_governance.validate(
        _manifest(
            dlp_pre_hooks=["redact_pii"],
            dlp_post_hooks=["redact_pii"],
        ),
        tmp_path,
    )
    assert not any(
        f.payload.get("failure_mode", "").startswith("dlp_pre_hooks_")
        or f.payload.get("failure_mode", "").startswith("dlp_post_hooks_")
        for f in findings
    )


def test_dlp_pre_hooks_valid_passes(tmp_path: Path) -> None:
    """Snake_case entries, no duplicates → no finding."""
    findings = data_governance.validate(
        _manifest(dlp_pre_hooks=["redact_pii_in_input", "scrub_secrets"]), tmp_path
    )
    assert not any(f.payload.get("failure_mode", "").startswith("dlp_pre_hooks_") for f in findings)


def test_dlp_post_hooks_valid_passes(tmp_path: Path) -> None:
    findings = data_governance.validate(
        _manifest(dlp_post_hooks=["mask_account_numbers", "redact_response"]), tmp_path
    )
    assert not any(
        f.payload.get("failure_mode", "").startswith("dlp_post_hooks_") for f in findings
    )


def test_dlp_hooks_legacy_path_validated(tmp_path: Path) -> None:
    """Manifests using the legacy ``[tool.cognic.data_governance]``
    layout get the same shape validation. Mirrors the existing legacy
    path test at section (i)."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "tool": {
            "cognic": {
                "data_governance": {
                    "data_classes": ["public"],
                    "purpose": "transaction_processing",
                    "retention_policy": "none",
                    "dlp_pre_hooks": ["Bad-Name"],
                }
            }
        },
    }
    findings = data_governance.validate(manifest, tmp_path)
    matching = [
        f
        for f in findings
        if f.payload.get("failure_mode") == "dlp_pre_hooks_invalid_hook_id"
        and f.payload.get("block_path") == "tool.cognic.data_governance"
    ]
    assert len(matching) == 1, (
        f"expected legacy-path dlp_pre_hooks_invalid_hook_id; "
        f"got {[(f.reason, f.payload) for f in findings]!r}"
    )


def test_dlp_hooks_each_block_validated_independently(tmp_path: Path) -> None:
    """When BOTH the canonical and the legacy data_governance blocks
    declare ``dlp_pre_hooks`` with different problems, EACH block fires
    its own refusal. Mirrors the section (j) "each path validated
    independently" pattern (R27 P2 #2 union doctrine inherited from
    Sprint-7A T10)."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {
            "data_classes": ["public"],
            "purpose": "transaction_processing",
            "retention_policy": "none",
            "dlp_pre_hooks": ["good_id", "good_id"],  # duplicate
        },
        "tool": {
            "cognic": {
                "data_governance": {
                    "data_classes": ["public"],
                    "purpose": "transaction_processing",
                    "retention_policy": "none",
                    "dlp_pre_hooks": ["Bad-Name"],  # invalid syntax
                }
            }
        },
    }
    findings = data_governance.validate(manifest, tmp_path)
    block_paths_with_dup = {
        f.payload["block_path"]
        for f in findings
        if f.payload.get("failure_mode") == "dlp_pre_hooks_duplicate"
    }
    block_paths_with_syntax = {
        f.payload["block_path"]
        for f in findings
        if f.payload.get("failure_mode") == "dlp_pre_hooks_invalid_hook_id"
    }
    assert "data_governance" in block_paths_with_dup
    assert "tool.cognic.data_governance" in block_paths_with_syntax


def test_dlp_hooks_full_happy_path(tmp_path: Path) -> None:
    """Every field populated including dlp_*_hooks → empty findings."""
    findings = data_governance.validate(
        _manifest(
            data_classes=["public", "internal"],
            purpose="transaction_processing",
            retention_policy="purpose_window",
            retention_max_window=90,
            egress_allow_list=["api.example.com"],
            dlp_pre_hooks=["redact_pii_in_input", "validate_input_shape"],
            dlp_post_hooks=["mask_account_numbers", "egress_check"],
            risk_tier="customer_data_read",
        ),
        tmp_path,
    )
    assert findings == []
