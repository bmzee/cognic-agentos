"""Sprint-7A T11 — ADR-014 risk-tier-consistency validator regressions.

The risk-tier validator's primary job is the cross-consistency check
between ``[risk_tier].tier`` and ``[data_governance].data_classes``:
each restricted data class has a minimum tier the pack must declare
to handle it, per ADR-014's tier-to-action model.

Validator scope (Wave-1):

  - ``[risk_tier].tier`` (required): single string from the closed-
    enum ``RiskTier`` literal at ``cli/_governance_vocab.py`` (8
    ADR-014 values: ``read_only`` / ``internal_write`` /
    ``customer_data_read`` / ``customer_data_write`` /
    ``payment_action`` / ``regulator_communication`` /
    ``cross_tenant`` / ``high_risk_custom``). AUTHOR-FILL
    placeholders, missing field, made-up values all refused.
  - Cross-consistency: for each declared data class with a
    minimum-tier requirement (mapping in
    ``cli._governance_vocab.DATA_CLASS_TO_MIN_RISK_TIER``), refuse
    if the declared tier is BELOW the minimum required for that
    class. Tier ordering is the ADR-014 tuple; "below" means
    "earlier in the tuple".

Closed-enum reason T11 owns:

  - ``risk_tier_inconsistent_with_data_classes`` — used both for
    "tier value not in closed-enum" failures AND for cross-
    consistency violations. Payload's ``failure_mode``
    distinguishes (``tier_missing`` / ``tier_invalid_value`` /
    ``tier_below_minimum_for_data_class``).

Dual-path lookup: ``[risk_tier].tier`` (canonical T5) +
``[tool.cognic.runtime].risk_tier`` (legacy/docs/fixture-aligned —
mirrors ``docs/BUILD_PLAN.md`` line 528, ``docs/HOW-TO-WRITE-A-PACK.md``,
the Sprint-7A plan-of-record §"Task 11", and both reference fixture
packs at ``tests/fixtures/cognic_test_{mcp,agent}_pack/``).

The two paths nest differently. The canonical T5 shape is a sub-table
with one named field::

    [risk_tier]
    tier = "read_only"

The legacy ``[tool.cognic.runtime]`` block is a richer runtime-config
sub-table with the value declared as a flat ``risk_tier`` field::

    [tool.cognic.runtime]
    risk_tier = "read_only"

Both surface to the validator with identical semantics — closed-enum
membership + per-data-class minimum-tier cross-check; payload's
``block_path`` distinguishes the source path so authors can locate
each violation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli.validators import risk_tier


def _manifest(
    *,
    tier: Any = "read_only",
    data_classes: Any = None,
    drop_risk_tier: bool = False,
) -> dict[str, Any]:
    """Build a manifest with a populated ``[risk_tier]`` block + a
    ``[data_governance]`` block. ``tier=None`` deletes the field;
    ``drop_risk_tier=True`` removes the entire block."""
    manifest: dict[str, Any] = {
        "pack": {"pack_id": "cognic-tool-demo", "kind": "tool"},
        "data_governance": {
            "data_classes": data_classes if data_classes is not None else ["public"],
        },
    }
    if not drop_risk_tier:
        block: dict[str, Any] = {}
        if tier is not None:
            block["tier"] = tier
        manifest["risk_tier"] = block
    return manifest


# ---------------------------------------------------------------------------
# (a) Block presence
# ---------------------------------------------------------------------------


def test_risk_tier_block_absent_no_findings(tmp_path: Path) -> None:
    """Per-T6-shape-gate: an absent block trips the orchestrator's
    manifest_missing_required_block. T11 itself is never called for
    that case; direct unit-test entry no-ops."""
    findings = risk_tier.validate({"pack": {"pack_id": "x", "kind": "tool"}}, tmp_path)
    assert findings == []


def test_risk_tier_block_not_a_dict_no_findings(tmp_path: Path) -> None:
    """Defensive: malformed block falls through cleanly."""
    findings = risk_tier.validate(
        {"pack": {"pack_id": "x", "kind": "tool"}, "risk_tier": "not-a-table"},
        tmp_path,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# (b) tier closed-enum check
# ---------------------------------------------------------------------------


def test_risk_tier_missing_refuses(tmp_path: Path) -> None:
    findings = risk_tier.validate(_manifest(tier=None), tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "risk_tier_inconsistent_with_data_classes"
        and f.payload.get("failure_mode") == "tier_missing"
    ]
    assert len(matching) == 1
    assert matching[0].severity == "refusal"


@pytest.mark.parametrize(
    "bad_tier",
    [
        "AUTHOR-FILL: low | medium | high | restricted",
        "low",  # legacy T5 vocab — no longer accepted
        "medium",
        "high",
        "restricted",
        "made_up_tier",
        "",
        "   ",
        42,
        None,
    ],
)
def test_risk_tier_invalid_value_refuses(tmp_path: Path, bad_tier: Any) -> None:
    """Any tier value not in the closed-enum RiskTier literal trips
    refusal. AUTHOR-FILL placeholders + the legacy T5 vocab values
    (low / medium / high / restricted) + made-up + non-strings all
    fail."""
    findings = risk_tier.validate(_manifest(tier=bad_tier), tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "risk_tier_inconsistent_with_data_classes"
        and f.payload.get("failure_mode") in ("tier_missing", "tier_invalid_value")
    ]
    assert matching, f"expected refusal for tier={bad_tier!r}; got {findings!r}"


@pytest.mark.parametrize(
    "good_tier",
    [
        "read_only",
        "internal_write",
        "customer_data_read",
        "customer_data_write",
        "payment_action",
        "regulator_communication",
        "cross_tenant",
        "high_risk_custom",
    ],
)
def test_risk_tier_valid_value_no_shape_finding(tmp_path: Path, good_tier: str) -> None:
    """Each ADR-014 tier value passes the closed-enum check."""
    findings = risk_tier.validate(_manifest(tier=good_tier), tmp_path)
    assert not any(
        f.payload.get("failure_mode") in ("tier_missing", "tier_invalid_value") for f in findings
    )


# ---------------------------------------------------------------------------
# (c) Cross-consistency: per-data-class minimum tier
# ---------------------------------------------------------------------------


def test_customer_pii_with_read_only_tier_refuses(tmp_path: Path) -> None:
    """``data_classes`` includes ``customer_pii`` but tier is
    ``read_only`` (below the customer_data_read minimum) → refuse."""
    findings = risk_tier.validate(
        _manifest(tier="read_only", data_classes=["public", "customer_pii"]),
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.reason == "risk_tier_inconsistent_with_data_classes"
        and f.payload.get("failure_mode") == "tier_below_minimum_for_data_class"
    ]
    assert len(matching) == 1
    assert matching[0].payload["data_class"] == "customer_pii"
    assert matching[0].payload["declared_tier"] == "read_only"
    assert matching[0].payload["minimum_tier"] == "customer_data_read"


def test_customer_pii_with_customer_data_read_tier_passes(tmp_path: Path) -> None:
    """``customer_pii`` AT the minimum tier passes."""
    findings = risk_tier.validate(
        _manifest(tier="customer_data_read", data_classes=["customer_pii"]),
        tmp_path,
    )
    assert not any(
        f.payload.get("failure_mode") == "tier_below_minimum_for_data_class" for f in findings
    )


def test_customer_pii_with_higher_tier_passes(tmp_path: Path) -> None:
    """``customer_pii`` ABOVE the minimum tier passes."""
    findings = risk_tier.validate(
        _manifest(tier="payment_action", data_classes=["customer_pii"]),
        tmp_path,
    )
    assert not any(
        f.payload.get("failure_mode") == "tier_below_minimum_for_data_class" for f in findings
    )


def test_payment_data_with_customer_data_read_refuses(tmp_path: Path) -> None:
    """``payment_data`` requires at least ``payment_action``;
    ``customer_data_read`` is below."""
    findings = risk_tier.validate(
        _manifest(tier="customer_data_read", data_classes=["payment_data"]),
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.payload.get("failure_mode") == "tier_below_minimum_for_data_class"
        and f.payload.get("data_class") == "payment_data"
    ]
    assert len(matching) == 1


def test_credentials_requires_customer_data_write(tmp_path: Path) -> None:
    findings = risk_tier.validate(
        _manifest(tier="customer_data_read", data_classes=["credentials"]),
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.payload.get("data_class") == "credentials"
        and f.payload.get("minimum_tier") == "customer_data_write"
    ]
    assert len(matching) == 1


def test_regulator_communication_requires_regulator_communication_tier(
    tmp_path: Path,
) -> None:
    findings = risk_tier.validate(
        _manifest(tier="payment_action", data_classes=["regulator_communication"]),
        tmp_path,
    )
    matching = [
        f
        for f in findings
        if f.payload.get("data_class") == "regulator_communication"
        and f.payload.get("minimum_tier") == "regulator_communication"
    ]
    assert len(matching) == 1


def test_public_internal_classes_no_minimum_tier(tmp_path: Path) -> None:
    """``public`` and ``internal`` carry no minimum-tier requirement.
    ``read_only`` is fine for them."""
    findings = risk_tier.validate(
        _manifest(tier="read_only", data_classes=["public", "internal"]),
        tmp_path,
    )
    assert not any(
        f.payload.get("failure_mode") == "tier_below_minimum_for_data_class" for f in findings
    )


def test_multiple_restricted_classes_emit_per_class_findings(tmp_path: Path) -> None:
    """One refusal per offending data class so authors get
    per-class remediation."""
    findings = risk_tier.validate(
        _manifest(
            tier="read_only",
            data_classes=["customer_pii", "payment_data", "credentials"],
        ),
        tmp_path,
    )
    refusal_classes = {
        f.payload.get("data_class")
        for f in findings
        if f.payload.get("failure_mode") == "tier_below_minimum_for_data_class"
    }
    assert refusal_classes == {"customer_pii", "payment_data", "credentials"}


def test_non_string_data_classes_filtered_in_cross_check(tmp_path: Path) -> None:
    """Mixed-type data_classes list — non-string + empty entries are
    filtered before the cross-check; only valid string classes are
    matched against the minimum-tier mapping."""
    findings = risk_tier.validate(
        _manifest(
            tier="read_only",
            data_classes=[42, "customer_pii", "", None, "  "],
        ),
        tmp_path,
    )
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "tier_below_minimum_for_data_class"
    ]
    # Only "customer_pii" is a valid string class with a minimum tier.
    assert len(matching) == 1
    assert matching[0].payload["data_class"] == "customer_pii"


def test_no_data_classes_no_cross_check_refusal(tmp_path: Path) -> None:
    """If [data_governance].data_classes is missing, T10 owns the
    refusal; T11 doesn't double-fire — just skips the cross-check."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "risk_tier": {"tier": "read_only"},
        "data_governance": {},
    }
    findings = risk_tier.validate(manifest, tmp_path)
    assert not any(
        f.payload.get("failure_mode") == "tier_below_minimum_for_data_class" for f in findings
    )


def test_invalid_tier_skips_cross_check(tmp_path: Path) -> None:
    """If the tier itself is invalid, the cross-check doesn't fire
    (we don't know where in the ordering an invalid value sits).
    Only the tier_invalid_value refusal surfaces."""
    findings = risk_tier.validate(
        _manifest(tier="made_up_tier", data_classes=["customer_pii"]),
        tmp_path,
    )
    failure_modes = {f.payload.get("failure_mode") for f in findings}
    assert "tier_invalid_value" in failure_modes
    assert "tier_below_minimum_for_data_class" not in failure_modes


# ---------------------------------------------------------------------------
# (d) Dual-path lookup
# ---------------------------------------------------------------------------


def test_legacy_runtime_risk_tier_path_validated(tmp_path: Path) -> None:
    """Manifests using the legacy ``[tool.cognic.runtime].risk_tier``
    layout (the docs / fixture-aligned shape per
    ``docs/BUILD_PLAN.md:528`` + ``docs/HOW-TO-WRITE-A-PACK.md``)
    still get validated."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {"data_classes": ["customer_pii"]},
        "tool": {"cognic": {"runtime": {"risk_tier": "read_only"}}},
    }
    findings = risk_tier.validate(manifest, tmp_path)
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "tier_below_minimum_for_data_class"
    ]
    assert len(matching) == 1
    assert matching[0].payload["block_path"] == "tool.cognic.runtime.risk_tier"


def test_legacy_runtime_path_invalid_value_refuses(tmp_path: Path) -> None:
    """A made-up tier value declared at the legacy runtime path trips
    the closed-enum refusal with the runtime-path block label."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {"data_classes": ["public"]},
        "tool": {"cognic": {"runtime": {"risk_tier": "made_up_legacy"}}},
    }
    findings = risk_tier.validate(manifest, tmp_path)
    matching = [f for f in findings if f.payload.get("failure_mode") == "tier_invalid_value"]
    assert len(matching) == 1
    assert matching[0].payload["block_path"] == "tool.cognic.runtime.risk_tier"


def test_legacy_runtime_path_happy_path_no_findings(tmp_path: Path) -> None:
    """Docs-shaped manifest declaring only the legacy
    ``[tool.cognic.runtime].risk_tier`` (no canonical ``[risk_tier]``
    block) with a valid tier and a non-restricted data class set
    returns clean."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {"data_classes": ["public", "internal"]},
        "tool": {"cognic": {"runtime": {"risk_tier": "read_only"}}},
    }
    findings = risk_tier.validate(manifest, tmp_path)
    assert findings == []


def test_both_paths_validated_independently(tmp_path: Path) -> None:
    """Mirrors T10's R27 P2 #2 doctrine: each declared path validates
    independently. If BOTH the canonical ``[risk_tier].tier`` AND the
    legacy ``[tool.cognic.runtime].risk_tier`` declare a problem, both
    findings surface so authors fix each location."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {"data_classes": ["public"]},
        "risk_tier": {"tier": "made_up_top_level"},
        "tool": {"cognic": {"runtime": {"risk_tier": "made_up_legacy"}}},
    }
    findings = risk_tier.validate(manifest, tmp_path)
    block_paths = {
        f.payload.get("block_path")
        for f in findings
        if f.payload.get("failure_mode") == "tier_invalid_value"
    }
    assert block_paths == {"risk_tier", "tool.cognic.runtime.risk_tier"}


def test_split_path_smuggle_attempt_caught_via_union(tmp_path: Path) -> None:
    """Split-location bypass attempt: canonical declares a safe tier
    (``read_only``) while the legacy runtime path smuggles the same
    safe tier — but ``data_classes`` includes ``customer_pii`` which
    requires AT LEAST ``customer_data_read``. Both declared paths sit
    below the minimum so each fires its own per-class refusal (one
    finding per (path, data_class) pair). Pack-author cannot dodge the
    cross-check by splitting declarations."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {"data_classes": ["customer_pii"]},
        "risk_tier": {"tier": "read_only"},
        "tool": {"cognic": {"runtime": {"risk_tier": "read_only"}}},
    }
    findings = risk_tier.validate(manifest, tmp_path)
    matching = [
        f for f in findings if f.payload.get("failure_mode") == "tier_below_minimum_for_data_class"
    ]
    block_paths = {f.payload.get("block_path") for f in matching}
    assert block_paths == {"risk_tier", "tool.cognic.runtime.risk_tier"}


def test_legacy_runtime_partial_path_no_crash(tmp_path: Path) -> None:
    """``[tool]`` without ``[tool.cognic.runtime]`` falls through
    cleanly."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {"data_classes": ["public"]},
        "tool": {"cognic": {"some_other_block": {}}},
    }
    findings = risk_tier.validate(manifest, tmp_path)
    assert findings == []


def test_legacy_runtime_block_without_risk_tier_field_no_crash(tmp_path: Path) -> None:
    """``[tool.cognic.runtime]`` present but carrying no ``risk_tier``
    field (e.g., only other runtime settings) does not trip a missing-
    field refusal on the legacy path — the validator only validates
    the legacy path when the field is actually declared. Missing-on-
    every-path is the orchestrator's shape-gate concern."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {"data_classes": ["public"]},
        "tool": {"cognic": {"runtime": {"some_other_setting": "x"}}},
    }
    findings = risk_tier.validate(manifest, tmp_path)
    assert findings == []


def test_legacy_runtime_non_dict_no_crash(tmp_path: Path) -> None:
    """``[tool.cognic.runtime]`` declared as a scalar (defensive
    guard) falls through cleanly."""
    manifest = {
        "pack": {"pack_id": "x", "kind": "tool"},
        "data_governance": {"data_classes": ["public"]},
        "tool": {"cognic": {"runtime": "not-a-table"}},
    }
    findings = risk_tier.validate(manifest, tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# (e) Type-shape pin + happy path
# ---------------------------------------------------------------------------


def test_risk_tier_findings_are_validator_finding_instances(tmp_path: Path) -> None:
    findings = risk_tier.validate(_manifest(tier="not-a-tier"), tmp_path)
    assert findings, "expected at least one finding"
    for f in findings:
        assert isinstance(f, ValidatorFinding)


def test_risk_tier_full_pass_returns_empty(tmp_path: Path) -> None:
    findings = risk_tier.validate(
        _manifest(
            tier="customer_data_write",
            data_classes=["public", "internal", "customer_pii"],
        ),
        tmp_path,
    )
    assert findings == []


# ---------------------------------------------------------------------------
# (f) Vocabulary exposure (lifecycle pinner)
# ---------------------------------------------------------------------------


def test_risk_tier_vocab_exports_canonical_values() -> None:
    """The canonical vocab module exports RiskTier + RISK_TIER_ORDER
    + DATA_CLASS_TO_MIN_RISK_TIER. T11 imports from there;
    consolidation guard pins them."""
    import typing

    from cognic_agentos.cli._governance_vocab import (
        DATA_CLASS_TO_MIN_RISK_TIER,
        LOW_AUTHORITY_TIERS,
        RISK_TIER_ORDER,
        RiskTier,
    )

    assert typing.get_args(RiskTier), "RiskTier literal is empty"
    declared = set(typing.get_args(RiskTier))
    assert set(RISK_TIER_ORDER) == declared, (
        "RISK_TIER_ORDER + RiskTier literal disagree on the canonical tier set"
    )
    # Every minimum-required tier in the per-class mapping MUST be a
    # valid RiskTier.
    for klass, min_tier in DATA_CLASS_TO_MIN_RISK_TIER.items():
        assert min_tier in declared, (
            f"DATA_CLASS_TO_MIN_RISK_TIER[{klass!r}] = {min_tier!r} is not a valid RiskTier value"
        )
    # LOW_AUTHORITY_TIERS members all valid.
    for tier in LOW_AUTHORITY_TIERS:
        assert tier in declared
