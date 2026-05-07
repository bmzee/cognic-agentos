"""Sprint-7A T10 — ADR-017 data-governance validator (CRITICAL CONTROLS).

Per Doctrine Decision G this module is on the critical-controls floor
(95% line / 90% branch). The runtime DLP enforcement substrate
depends on this contract — bad declarations propagate to runtime
mis-handling, so the build-time validator is the load-bearing gate
that catches manifest inconsistencies BEFORE the pack ships.

The vocabulary lives at
:mod:`cognic_agentos.cli._governance_vocab` (build-time owner). When
the runtime DLP enforcement substrate per ADR-017 ships, the literals
MUST be either imported from here directly OR migrated to a shared
module in the same commit that lights up runtime DLP — the build-time
validator and the runtime enforcer cannot diverge on what counts as
``customer_pii`` without producing pack-author confusion + audit
gaps. This is load-bearing; future maintainers, do not duplicate.

Validator scope (Wave-1):

  - ``data_classes`` (required): non-empty list of strings, each
    matching a value in the :data:`DataClass` closed-enum literal.
  - ``purpose`` (required): single string matching :data:`Purpose`.
  - ``retention_policy`` (required): matches :data:`RetentionPolicy`.
  - ``retention_max_window`` (required when retention_policy != "none"):
    positive number.
  - ``egress_allow_list`` (optional): if present, must be a list of
    strings.

  Cross-validation:

  - ``[risk_tier].tier == "low"`` AND data_classes intersects the
    :data:`RESTRICTED_DATA_CLASSES` set →
    ``data_governance_contract_inconsistent_with_risk_tier``.
  - ``[mcp].caching = true`` (or ``caching_strategy = "ttl"``) AND
    data_classes intersects the restricted set →
    ``data_governance_contract_inconsistent_with_mcp_caching``.

Closed-enum reasons T10 owns:

  - ``data_governance_contract_missing`` — catch-all for field-shape
    failures; ``payload.failure_mode`` distinguishes (mirrors T6's
    ``manifest_missing_required_block`` failure-mode pattern).
  - ``data_governance_contract_inconsistent_with_risk_tier``.
  - ``data_governance_contract_inconsistent_with_mcp_caching``.

Out of T10 scope:

  - ``dlp_pre_hooks`` / ``dlp_post_hooks`` cross-check against pack
    exports (the plan-of-record mentioned this as a stretch goal;
    the closed-enum doesn't carry a reason for hook-name mismatch
    yet, so deferring to a future sprint).
  - ``requires_consent`` / ``regulator_retention_required`` — boolean
    fields that don't have closed-enum reasons attached. T10 leaves
    them to the runtime consent gate (the build-time check would be
    purely informational).
"""

from __future__ import annotations

import typing
from pathlib import Path
from typing import Any

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli._governance_vocab import (
    RESTRICTED_DATA_CLASSES,
    DataClass,
    Purpose,
    RetentionPolicy,
)

#: Canonical DataClass closed-enum value set, derived from the
#: build-time vocabulary literal at module load. ``typing.get_args``
#: reads the Literal's argument tuple at runtime; mypy strict mode
#: rejects ``Literal.__args__`` direct attribute access.
_VALID_DATA_CLASSES: frozenset[str] = frozenset(typing.get_args(DataClass))
_VALID_PURPOSES: frozenset[str] = frozenset(typing.get_args(Purpose))
_VALID_RETENTION_POLICIES: frozenset[str] = frozenset(typing.get_args(RetentionPolicy))


#: Closed-enum tuple of (path-prefix, accessor-tuple) pairs for the
#: ``[data_governance]`` block. Mirrors T9's R26 P2 #2 dual-path
#: doctrine: top-level is canonical T5 shape, ``[tool.cognic.*]`` is
#: legacy/docs-aligned fallback.
_DATA_GOVERNANCE_LOCATIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("data_governance", ("data_governance",)),
    ("tool.cognic.data_governance", ("tool", "cognic", "data_governance")),
)


def _resolve_path(data: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any] | None:
    """Walk ``path`` through ``data``; return the leaf dict or
    ``None`` on any non-dict intermediate."""
    cursor: Any = data
    for segment in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(segment)
    return cursor if isinstance(cursor, dict) else None


def _governance_blocks(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Locate the ``[data_governance]`` block(s). Returns a list of
    ``(prefix, block_dict)`` pairs, one per resolved location.

    R27 P2 #2 reviewer correction: when BOTH locations are present,
    return BOTH (validate each independently + union for cross-checks)
    rather than top-level-wins. The earlier "wins" semantics let a
    pack declare safe ``data_classes = ["public"]`` at the canonical
    location while smuggling restricted classes at the legacy
    location — T10's cross-check then operated only on the safe
    set + missed the restricted-data violation. Mirrors T9's union
    semantics across the same dual-path doctrine.
    """
    located: list[tuple[str, dict[str, Any]]] = []
    for prefix, accessor in _DATA_GOVERNANCE_LOCATIONS:
        block = _resolve_path(data, accessor)
        if block is not None:
            located.append((prefix, block))
    return located


def _refusal(*, prefix: str, failure_mode: str, message: str, **extra: Any) -> ValidatorFinding:
    """Build a refusal-severity ``data_governance_contract_missing``
    finding with the supplied failure-mode + extra payload keys."""
    return ValidatorFinding(
        severity="refusal",
        reason="data_governance_contract_missing",
        message=message,
        payload={"block_path": prefix, "failure_mode": failure_mode, **extra},
    )


def _validate_data_classes(
    block: dict[str, Any], prefix: str
) -> tuple[list[ValidatorFinding], list[str]]:
    """Validate ``data_classes`` shape + values. Returns
    ``(findings, normalised_classes)``; normalised_classes is the
    list of valid class strings (used by cross-validation when the
    shape is otherwise OK)."""
    findings: list[ValidatorFinding] = []
    raw = block.get("data_classes")
    if raw is None or not isinstance(raw, list):
        findings.append(
            _refusal(
                prefix=prefix,
                failure_mode="data_classes_missing",
                message=(
                    f"{prefix}.data_classes must be present + a non-empty "
                    "list of strings drawn from the closed-enum DataClass "
                    "vocabulary at cli._governance_vocab.py."
                ),
            )
        )
        return findings, []

    if not raw:
        findings.append(
            _refusal(
                prefix=prefix,
                failure_mode="data_classes_empty",
                message=(
                    f"{prefix}.data_classes is an empty list; declare at "
                    "least one class. Use 'public' or 'internal' if the "
                    "pack handles non-sensitive data only."
                ),
            )
        )
        return findings, []

    invalid_values: list[Any] = []
    valid: list[str] = []
    for entry in raw:
        if not isinstance(entry, str) or entry.strip() not in _VALID_DATA_CLASSES:
            invalid_values.append(entry)
        else:
            valid.append(entry.strip())

    if invalid_values:
        findings.append(
            _refusal(
                prefix=prefix,
                failure_mode="data_classes_invalid_value",
                message=(
                    f"{prefix}.data_classes contains values outside the "
                    f"closed-enum DataClass vocabulary: {invalid_values!r}. "
                    f"Allowed values: {sorted(_VALID_DATA_CLASSES)!r}."
                ),
                invalid_values=invalid_values,
                allowed_values=sorted(_VALID_DATA_CLASSES),
            )
        )

    return findings, valid


def _validate_purpose(block: dict[str, Any], prefix: str) -> list[ValidatorFinding]:
    findings: list[ValidatorFinding] = []
    raw = block.get("purpose")
    if raw is None:
        findings.append(
            _refusal(
                prefix=prefix,
                failure_mode="purpose_missing",
                message=(
                    f"{prefix}.purpose is required; declare a value from "
                    "the closed-enum Purpose vocabulary at "
                    "cli._governance_vocab.py."
                ),
            )
        )
        return findings

    if not isinstance(raw, str) or raw.strip() not in _VALID_PURPOSES:
        findings.append(
            _refusal(
                prefix=prefix,
                failure_mode="purpose_invalid",
                message=(
                    f"{prefix}.purpose value {raw!r} is not in the closed-"
                    f"enum Purpose vocabulary. Allowed values: "
                    f"{sorted(_VALID_PURPOSES)!r}."
                ),
                invalid_value=raw,
                allowed_values=sorted(_VALID_PURPOSES),
            )
        )

    return findings


def _validate_retention(block: dict[str, Any], prefix: str) -> list[ValidatorFinding]:
    findings: list[ValidatorFinding] = []
    raw = block.get("retention_policy")
    if raw is None:
        findings.append(
            _refusal(
                prefix=prefix,
                failure_mode="retention_policy_missing",
                message=(
                    f"{prefix}.retention_policy is required; declare a "
                    "value from the closed-enum RetentionPolicy "
                    "vocabulary at cli._governance_vocab.py."
                ),
            )
        )
        return findings

    if not isinstance(raw, str) or raw.strip() not in _VALID_RETENTION_POLICIES:
        findings.append(
            _refusal(
                prefix=prefix,
                failure_mode="retention_policy_invalid",
                message=(
                    f"{prefix}.retention_policy value {raw!r} is not in "
                    f"the closed-enum RetentionPolicy vocabulary. Allowed "
                    f"values: {sorted(_VALID_RETENTION_POLICIES)!r}."
                ),
                invalid_value=raw,
                allowed_values=sorted(_VALID_RETENTION_POLICIES),
            )
        )
        return findings

    # retention_max_window required iff retention_policy != "none"
    policy_value = raw.strip()
    if policy_value != "none":
        window = block.get("retention_max_window")
        if window is None:
            findings.append(
                _refusal(
                    prefix=prefix,
                    failure_mode="retention_max_window_missing",
                    message=(
                        f"{prefix}.retention_max_window is required when "
                        f"retention_policy is {policy_value!r}; declare a "
                        "positive number representing the retention period."
                    ),
                )
            )
        elif not _is_positive_number(window):
            findings.append(
                _refusal(
                    prefix=prefix,
                    failure_mode="retention_max_window_invalid",
                    message=(
                        f"{prefix}.retention_max_window value {window!r} is not a positive number."
                    ),
                    invalid_value=window,
                )
            )

    return findings


def _is_positive_number(value: Any) -> bool:
    """True iff ``value`` is a TOML int or float and strictly > 0.
    Booleans (which are ``int`` subclasses) are explicitly rejected
    so ``retention_max_window = true`` doesn't slip through."""
    if isinstance(value, bool):
        return False
    if not isinstance(value, (int, float)):
        return False
    return value > 0


def _validate_egress_allow_list(block: dict[str, Any], prefix: str) -> list[ValidatorFinding]:
    findings: list[ValidatorFinding] = []
    if "egress_allow_list" not in block:
        return findings

    raw = block["egress_allow_list"]
    if not isinstance(raw, list) or not all(isinstance(entry, str) for entry in raw):
        findings.append(
            _refusal(
                prefix=prefix,
                failure_mode="egress_allow_list_invalid_shape",
                message=(f"{prefix}.egress_allow_list must be a list of strings."),
                invalid_value=raw,
            )
        )

    return findings


def _cross_check_risk_tier(
    declared_classes: list[str], data: dict[str, Any]
) -> list[ValidatorFinding]:
    """Refuse a "low" risk_tier declaration when data_classes
    intersects the restricted set."""
    risk_block = data.get("risk_tier")
    if not isinstance(risk_block, dict):
        return []
    tier = risk_block.get("tier")
    if not isinstance(tier, str):
        return []
    if tier.strip() != "low":
        return []
    restricted = sorted(set(declared_classes) & RESTRICTED_DATA_CLASSES)
    if not restricted:
        return []
    return [
        ValidatorFinding(
            severity="refusal",
            reason="data_governance_contract_inconsistent_with_risk_tier",
            message=(
                f"risk_tier.tier='low' but data_governance.data_classes "
                f"declares restricted classes ({restricted}); a low-tier "
                "pack cannot handle restricted-tier data. Either raise the "
                "tier or remove the restricted classes."
            ),
            payload={
                "risk_tier": "low",
                "restricted_data_classes": restricted,
            },
        )
    ]


def _mcp_caching_enabled(data: dict[str, Any]) -> bool:
    """Mirrors T9's caching-detection across both field families
    (``caching = true`` boolean OR ``caching_strategy = "ttl"`` string)
    + both ``[mcp]`` paths (canonical + legacy)."""
    for accessor in (("mcp",), ("tool", "cognic", "mcp")):
        block = _resolve_path(data, accessor)
        if block is None:
            continue
        if block.get("caching") is True:
            return True
        if block.get("caching_strategy") == "ttl":
            return True
    return False


def _cross_check_mcp_caching(
    declared_classes: list[str], data: dict[str, Any]
) -> list[ValidatorFinding]:
    """Refuse caching+restricted-class combination from the data-
    governance perspective. T9 fires its own refusal on the same
    violation (mcp_caching_restricted_data_class); T10 fires the
    governance-side perspective so authors see the cross-check from
    both sides."""
    if not _mcp_caching_enabled(data):
        return []
    restricted = sorted(set(declared_classes) & RESTRICTED_DATA_CLASSES)
    if not restricted:
        return []
    return [
        ValidatorFinding(
            severity="refusal",
            reason="data_governance_contract_inconsistent_with_mcp_caching",
            message=(
                f"data_governance.data_classes declares restricted classes "
                f"({restricted}) but the manifest also enables MCP caching; "
                "caching restricted-class data is forbidden in Wave-1. "
                "Disable caching or remove the restricted class."
            ),
            payload={"restricted_data_classes": restricted},
        )
    ]


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Validate the manifest's ``[data_governance]`` block per
    ADR-017's Wave-1 strictness matrix.

    Returns refusal-severity findings or an empty list. The
    orchestrator's shape gate (T6) ensures ``[data_governance]`` is
    present at the canonical or legacy location by the time this
    validator is dispatched; direct unit-test entry points pass
    an absent block via the no-op return.

    R27 P2 #2 reviewer correction: when BOTH the canonical
    ``[data_governance]`` and the legacy ``[tool.cognic.data_governance]``
    are declared, EACH block is validated independently AND the
    cross-checks operate on the UNION of declared data classes.
    Without this, a pack declaring safe classes at the canonical
    location while smuggling restricted classes at the legacy
    location bypassed the cross-checks.
    """
    del pack_path  # T10 reads only the parsed manifest dict

    located = _governance_blocks(data)
    if not located:
        return []

    findings: list[ValidatorFinding] = []
    union_valid_classes: set[str] = set()

    # Validate each block independently — duplicate-shape declarations
    # surface their own findings; union'd valid classes feed the
    # cross-checks below.
    for prefix, block in located:
        data_classes_findings, valid_classes = _validate_data_classes(block, prefix)
        findings.extend(data_classes_findings)
        union_valid_classes.update(valid_classes)
        findings.extend(_validate_purpose(block, prefix))
        findings.extend(_validate_retention(block, prefix))
        findings.extend(_validate_egress_allow_list(block, prefix))

    # Cross-validation operates on the union of valid classes across
    # both paths. Pack authors cannot hide a restricted class from the
    # cross-check by splitting declarations.
    if union_valid_classes:
        all_valid_classes = sorted(union_valid_classes)
        findings.extend(_cross_check_risk_tier(all_valid_classes, data))
        findings.extend(_cross_check_mcp_caching(all_valid_classes, data))

    return findings


__all__ = ["validate"]
