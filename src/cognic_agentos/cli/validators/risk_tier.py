"""Sprint-7A T11 — ADR-014 risk-tier consistency validator.

Validates the manifest's risk-tier declaration against the closed-
enum ``RiskTier`` literal at ``cli/_governance_vocab.py`` AND cross-
checks that the declared tier is high enough for the declared data
classes per ADR-014's tier-to-action model.

Validator scope (Wave-1):

  - Canonical T5 shape: ``[risk_tier].tier`` (required): single
    string drawn from the 8-value :data:`RiskTier` literal
    (``read_only`` / ``internal_write`` / ``customer_data_read`` /
    ``customer_data_write`` / ``payment_action`` /
    ``regulator_communication`` / ``cross_tenant`` /
    ``high_risk_custom``). AUTHOR-FILL placeholders, missing field,
    legacy T5 vocab values (``low`` / ``medium`` / ``high`` /
    ``restricted``), and made-up values all refused.
  - Legacy/docs/runtime shape: ``[tool.cognic.runtime].risk_tier``
    (per ``docs/BUILD_PLAN.md`` line 528, ``docs/HOW-TO-WRITE-A-PACK.md``,
    the Sprint-7A plan-of-record §"Task 11", and both reference
    fixture packs at ``tests/fixtures/cognic_test_{mcp,agent}_pack/``).
    The legacy path's ``risk_tier`` is a flat string field directly
    inside the richer ``[tool.cognic.runtime]`` runtime-config
    sub-table — NOT a separate sub-table. Validated identically to
    the canonical path when present.
  - Cross-consistency: for each declared data class with a minimum-
    tier requirement (see
    :data:`cognic_agentos.cli._governance_vocab.DATA_CLASS_TO_MIN_RISK_TIER`),
    refuse if the declared tier sits BELOW the minimum required for
    that class. "Below" is index-based against
    :data:`RISK_TIER_ORDER`.

Closed-enum reason T11 owns:

  - ``risk_tier_inconsistent_with_data_classes`` — used for both
    closed-enum value failures AND cross-consistency violations.
    ``payload.failure_mode`` distinguishes (``tier_missing`` /
    ``tier_invalid_value`` / ``tier_below_minimum_for_data_class``).

Dual-path lookup mirrors T8/T9/T10 doctrine: each declared path
validates independently when both are declared, with payload's
``block_path`` distinguishing the source so authors can locate each
violation. The two paths nest differently (sub-table-with-named-field
vs flat-field-inside-larger-block) but surface identical semantics.

T10's ``data_governance_contract_inconsistent_with_risk_tier`` fires
on the same conceptual violation from the data-governance perspective
(low-authority tier + restricted data) — the two refusals are
informational duplicates; pack-author who fixes either side stops
both.

Validator-promotion call (Doctrine Decision G): the cross-consistency
check is the validator's primary job + adds real allow/deny logic.
Plan-of-record marks T11 "expected promotion to critical-controls
gate at T16". Halt-before-commit applies regardless per the user's
strict-review override.
"""

from __future__ import annotations

import typing
from pathlib import Path
from typing import Any

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli._governance_vocab import (
    DATA_CLASS_TO_MIN_RISK_TIER,
    RISK_TIER_ORDER,
    RiskTier,
)

#: Canonical RiskTier value set, derived from the closed-enum literal
#: at module load.
_VALID_TIERS: frozenset[str] = frozenset(typing.get_args(RiskTier))


#: Sentinel returned by the canonical-path locator when ``[risk_tier]``
#: is a TOML sub-table but the ``tier`` field is absent. Distinguishes
#: "field absent" (fires ``tier_missing``) from "block absent"
#: (handled by the orchestrator's shape gate).
_FIELD_ABSENT: Any = object()


def _resolve_path(data: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any] | None:
    """Walk ``path`` through ``data``; return the leaf dict or
    ``None`` on any non-dict intermediate."""
    cursor: Any = data
    for segment in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(segment)
    return cursor if isinstance(cursor, dict) else None


def _located_tier_declarations(data: dict[str, Any]) -> list[tuple[str, Any]]:
    """Return ``(block_path, raw_tier_value)`` pairs — one per
    declared/expected risk-tier location — in deterministic dispatch
    order (canonical T5 first, legacy runtime second).

    Canonical T5 shape (``[risk_tier].tier``) emits a pair whenever
    ``[risk_tier]`` resolves to a TOML sub-table; the raw value is
    whatever ``block.get("tier")`` returns (including ``None`` for
    field-absent — this fires the ``tier_missing`` refusal). The
    canonical path "owns" the field-absent failure mode because that
    block exists for the sole purpose of declaring the tier.

    Legacy shape (``[tool.cognic.runtime].risk_tier``) emits a pair
    only when the runtime block is a sub-table AND the ``risk_tier``
    key is present. The legacy block has other runtime-config
    purposes; an absent ``risk_tier`` field there is not by itself a
    refusal (the orchestrator's shape gate ensures at least one path
    declares the tier overall).
    """
    located: list[tuple[str, Any]] = []

    top_block = _resolve_path(data, ("risk_tier",))
    if top_block is not None:
        # Distinguish "block declared, field absent" from "field
        # declared as None" using a sentinel — both surface as
        # ``tier_missing`` but the ``in`` check guards the latter
        # from being mishandled if a future TOML-equivalent ever
        # makes ``None`` representable as a value. tomllib never
        # produces ``None`` today; the sentinel keeps the contract
        # explicit.
        raw = top_block.get("tier", _FIELD_ABSENT)
        located.append(("risk_tier", raw))

    runtime_block = _resolve_path(data, ("tool", "cognic", "runtime"))
    if runtime_block is not None and "risk_tier" in runtime_block:
        located.append(("tool.cognic.runtime.risk_tier", runtime_block["risk_tier"]))

    return located


def _declared_data_classes(data: dict[str, Any]) -> set[str]:
    """Return the union of declared data classes across both
    governance paths (mirrors T10's R27 P2 #2 union semantics).
    Whitespace stripped; non-string entries filtered."""
    classes: set[str] = set()
    for accessor in (
        ("data_governance",),
        ("tool", "cognic", "data_governance"),
    ):
        block = _resolve_path(data, accessor)
        if block is None:
            continue
        raw = block.get("data_classes")
        if not isinstance(raw, list):
            continue
        for entry in raw:
            if isinstance(entry, str) and entry.strip():
                classes.add(entry.strip())
    return classes


def _refusal(*, prefix: str, failure_mode: str, message: str, **extra: Any) -> ValidatorFinding:
    """Build a refusal-severity ``risk_tier_inconsistent_with_data_classes``
    finding. The single closed-enum reason is reused across all T11
    failure modes; ``payload.failure_mode`` distinguishes."""
    return ValidatorFinding(
        severity="refusal",
        reason="risk_tier_inconsistent_with_data_classes",
        message=message,
        payload={"block_path": prefix, "failure_mode": failure_mode, **extra},
    )


def _validate_tier_value(raw: Any, prefix: str) -> tuple[list[ValidatorFinding], str | None]:
    """Validate a raw tier value's shape + closed-enum membership.

    Returns ``(findings, normalised_tier)``; ``normalised_tier`` is
    the validated value (or ``None`` if shape failed) for the
    cross-check to consume.

    ``prefix`` is the dotted path the tier was located at (e.g.,
    ``risk_tier`` for the canonical shape or
    ``tool.cognic.runtime.risk_tier`` for the legacy shape) — used
    in finding messages + payload's ``block_path`` so authors can
    locate each violation.

    The ``_FIELD_ABSENT`` sentinel surfaces from the canonical-path
    locator when ``[risk_tier]`` is declared as a sub-table but the
    ``tier`` field is missing; it triggers the ``tier_missing``
    refusal. Other ``None`` / non-string / out-of-vocab values
    trigger ``tier_invalid_value``.
    """
    findings: list[ValidatorFinding] = []
    if raw is _FIELD_ABSENT:
        findings.append(
            _refusal(
                prefix=prefix,
                failure_mode="tier_missing",
                message=(
                    f"{prefix} is required; declare a value from "
                    "the closed-enum RiskTier vocabulary at "
                    "cli._governance_vocab.py."
                ),
            )
        )
        return findings, None

    if not isinstance(raw, str) or raw.strip() not in _VALID_TIERS:
        findings.append(
            _refusal(
                prefix=prefix,
                failure_mode="tier_invalid_value",
                message=(
                    f"{prefix} value {raw!r} is not in the closed-"
                    f"enum RiskTier vocabulary. Allowed values: "
                    f"{sorted(_VALID_TIERS)!r}."
                ),
                invalid_value=raw,
                allowed_values=sorted(_VALID_TIERS),
            )
        )
        return findings, None

    return findings, raw.strip()


def _cross_check_tier_for_data_classes(
    declared_tier: str, declared_classes: set[str], prefix: str
) -> list[ValidatorFinding]:
    """For each declared data class with a minimum-tier requirement,
    refuse if the declared tier is below the minimum.

    Tier comparison is index-based against RISK_TIER_ORDER (lowest-
    authority first). One finding per offending class so authors get
    per-class remediation.
    """
    findings: list[ValidatorFinding] = []
    declared_index = RISK_TIER_ORDER.index(declared_tier)

    for klass in sorted(declared_classes):
        min_required = DATA_CLASS_TO_MIN_RISK_TIER.get(klass)
        if min_required is None:
            continue
        required_index = RISK_TIER_ORDER.index(min_required)
        if declared_index < required_index:
            findings.append(
                _refusal(
                    prefix=prefix,
                    failure_mode="tier_below_minimum_for_data_class",
                    message=(
                        f"{prefix}={declared_tier!r} is below the "
                        f"minimum required ({min_required!r}) for declared "
                        f"data_class {klass!r}; raise the tier or remove "
                        "the data class from [data_governance]."
                    ),
                    data_class=klass,
                    declared_tier=declared_tier,
                    minimum_tier=min_required,
                )
            )

    return findings


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Validate the manifest's risk-tier declaration per ADR-014.

    Returns refusal-severity findings or an empty list. Both the
    canonical ``[risk_tier].tier`` and the legacy
    ``[tool.cognic.runtime].risk_tier`` paths are inspected; each
    declared location validates independently.
    """
    del pack_path  # T11 reads only the parsed manifest dict

    located = _located_tier_declarations(data)
    if not located:
        return []

    declared_classes = _declared_data_classes(data)
    findings: list[ValidatorFinding] = []

    for prefix, raw_tier in located:
        tier_findings, normalised_tier = _validate_tier_value(raw_tier, prefix)
        findings.extend(tier_findings)

        # Cross-check fires only when the tier itself is well-shaped;
        # otherwise we don't know where in the ordering the value
        # would sit, and emitting a tier_below_minimum_for_data_class
        # finding alongside tier_invalid_value would just add noise.
        if normalised_tier is not None and declared_classes:
            findings.extend(
                _cross_check_tier_for_data_classes(normalised_tier, declared_classes, prefix)
            )

    return findings


__all__ = ["validate"]
