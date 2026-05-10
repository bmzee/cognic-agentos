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
  - ``dlp_pre_hooks`` / ``dlp_post_hooks`` (optional, Sprint-7A2 T10
    extension): if present, each must be a list of snake_case
    hook_id strings; per-list duplicates refused; cross-pack
    resolution is runtime concern (see ``_validate_dlp_hook_list``).

  Cross-validation:

  - Declared risk tier in :data:`LOW_AUTHORITY_TIERS` (the ADR-014
    ``read_only`` / ``internal_write`` set) AND data_classes
    intersects the :data:`RESTRICTED_DATA_CLASSES` set →
    ``data_governance_contract_inconsistent_with_risk_tier``. The
    risk tier is read from BOTH the canonical ``[risk_tier].tier``
    (T5 shape) AND the legacy ``[tool.cognic.runtime].risk_tier``
    (docs / fixture-aligned shape per ``docs/BUILD_PLAN.md:528``);
    either declaration with the restricted-class combination trips
    the refusal. Mirrors T11's per-data-class cross-check from the
    data-governance side (informational duplicate; either fix
    stops both refusals).
  - ``[mcp].caching = true`` (or ``caching_strategy = "ttl"``) AND
    data_classes intersects the restricted set →
    ``data_governance_contract_inconsistent_with_mcp_caching``.

Closed-enum reasons T10 owns:

  - ``data_governance_contract_missing`` — catch-all for field-shape
    failures; ``payload.failure_mode`` distinguishes (mirrors T6's
    ``manifest_missing_required_block`` failure-mode pattern). The
    Sprint-7A2 T10 extension adds six new failure_mode values for
    the dlp_*_hooks fields:
    ``dlp_pre_hooks_invalid_shape`` / ``dlp_post_hooks_invalid_shape``
    (not a list, or contains a non-string entry),
    ``dlp_pre_hooks_invalid_hook_id`` / ``dlp_post_hooks_invalid_hook_id``
    (entry fails snake_case),
    ``dlp_pre_hooks_duplicate`` / ``dlp_post_hooks_duplicate``
    (same hook_id more than once per list).
  - ``data_governance_contract_inconsistent_with_risk_tier``.
  - ``data_governance_contract_inconsistent_with_mcp_caching``.

Out of T10 scope:

  - Cross-pack resolution of ``dlp_pre_hooks`` / ``dlp_post_hooks``
    entries (i.e., whether a named hook_id corresponds to a
    registered hook in any verified hook pack). Runtime registry
    + dispatcher concern per Sprint-7A2 T6 / T7 / T8; build-time
    validator only checks shape + syntax + per-list uniqueness.
  - ``requires_consent`` / ``regulator_retention_required`` — boolean
    fields that don't have closed-enum reasons attached. T10 leaves
    them to the runtime consent gate (the build-time check would be
    purely informational).
"""

from __future__ import annotations

import re as _re
import typing
from pathlib import Path
from typing import Any, Final

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli._governance_vocab import (
    LOW_AUTHORITY_TIERS,
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

#: Sprint-7A2 T10 — snake_case validator for ``dlp_pre_hooks`` /
#: ``dlp_post_hooks`` entries. Documented mirror of
#: ``cli/validators/hooks.py:_HOOK_ID_PATTERN``; the regex is
#: duplicated rather than imported per the T10 lock-point decision
#: (narrowest blast radius — both validators co-evolve under the
#: ``cli/validators/`` namespace and share doctrine ownership).
#:
#: If this regex ever drifts from ``validators/hooks.py:_HOOK_ID_PATTERN``,
#: pack authors will see contradictory refusals (T6 hooks-validator
#: accepts a hook_id the T10 dlp-reference validator refuses, or
#: vice versa). The mirror is load-bearing; future maintainers, do
#: not relax it without re-syncing both sites.
_HOOK_REF_PATTERN: Final[_re.Pattern[str]] = _re.compile(r"^[a-z][a-z0-9_]*$")


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


def _validate_dlp_hook_list(
    block: dict[str, Any], prefix: str, field_name: str
) -> list[ValidatorFinding]:
    """Sprint-7A2 T10 — shape-validate one of ``dlp_pre_hooks`` /
    ``dlp_post_hooks``.

    The field is OPTIONAL: absence produces no finding. An empty list
    (``[]``) is explicitly valid (pack declares zero hooks for that
    phase).

    Three failure modes (each prefixed with ``field_name``):

      - ``<field>_invalid_shape`` — value is not a list, OR the list
        contains a non-string entry. Single refusal per block; the
        whole list is rejected as malformed (subsequent identifier /
        duplicate checks short-circuit because they cannot operate on
        a malformed list safely).
      - ``<field>_invalid_hook_id`` — at least one entry fails the
        snake_case identifier regex. One refusal per offending entry
        with ``payload.invalid_value`` + ``payload.index`` for author
        diagnostics.
      - ``<field>_duplicate`` — same hook_id appears more than once
        in the list. One refusal per duplicate group with
        ``payload.duplicate_hook_id``. Build-time canonicalization is
        loud-on-author-error; the T8 dispatcher's runtime dedupe
        stays defensive (silent) so the two layers don't double-error.

    Cross-pack resolution (i.e., whether ``redact_pii`` actually
    corresponds to a hook_id declared by some installed hook pack)
    is RUNTIME concern — the registry's admission gate (T6) + the
    dispatcher's per-pack selector (T8) own that. Build-time only
    checks shape + identifier syntax + per-list uniqueness.
    """
    if field_name not in block:
        return []

    raw = block[field_name]
    findings: list[ValidatorFinding] = []

    # Shape check: must be a list of strings.
    if not isinstance(raw, list) or not all(isinstance(entry, str) for entry in raw):
        findings.append(
            _refusal(
                prefix=prefix,
                failure_mode=f"{field_name}_invalid_shape",
                message=(
                    f"{prefix}.{field_name} must be a list of snake_case "
                    f"hook_id strings (got {raw!r}). The runtime DLP "
                    "dispatcher resolves these against installed hook "
                    "packs at admission; build-time only checks shape."
                ),
                invalid_value=raw,
            )
        )
        # Short-circuit — the list is structurally malformed; running
        # identifier-syntax + duplicate checks on it would be unsafe.
        return findings

    # Identifier-syntax check: each entry must match snake_case.
    for index, entry in enumerate(raw):
        if not _HOOK_REF_PATTERN.match(entry):
            findings.append(
                _refusal(
                    prefix=prefix,
                    failure_mode=f"{field_name}_invalid_hook_id",
                    message=(
                        f"{prefix}.{field_name}[{index}] = {entry!r} is "
                        "not a snake_case identifier (lowercase ASCII "
                        "letters / digits / underscores; must not start "
                        "with a digit). Mirrors the hook_id syntax T6 "
                        "enforces on hook-pack manifest declarations."
                    ),
                    invalid_value=entry,
                    index=index,
                )
            )

    # Duplicate-within-list check. Per the T10 lock: REFUSE duplicates
    # at build time. Each duplicate group surfaces ONE refusal so an
    # author seeing ``["x", "x", "x"]`` gets one finding for ``x``,
    # not two.
    seen: set[str] = set()
    duplicates_reported: set[str] = set()
    for entry in raw:
        if entry in seen and entry not in duplicates_reported:
            findings.append(
                _refusal(
                    prefix=prefix,
                    failure_mode=f"{field_name}_duplicate",
                    message=(
                        f"{prefix}.{field_name} declares hook_id "
                        f"{entry!r} more than once. Each hook_id MUST "
                        "appear at most once per phase list; remove "
                        "the duplicate(s)."
                    ),
                    duplicate_hook_id=entry,
                )
            )
            duplicates_reported.add(entry)
        seen.add(entry)

    return findings


def _declared_risk_tiers(data: dict[str, Any]) -> list[str]:
    """Return every declared risk-tier string across both manifest
    shapes, in dispatch order (canonical T5 first, legacy runtime
    second). Whitespace stripped; non-string entries filtered.

    Canonical: ``[risk_tier].tier``. Legacy: ``[tool.cognic.runtime].risk_tier``
    (the docs / fixture-aligned shape; see the T11 doctrine fix
    docstring at :mod:`cognic_agentos.cli.validators.risk_tier`).
    """
    tiers: list[str] = []

    risk_block = _resolve_path(data, ("risk_tier",))
    if risk_block is not None:
        tier = risk_block.get("tier")
        if isinstance(tier, str) and tier.strip():
            tiers.append(tier.strip())

    runtime_block = _resolve_path(data, ("tool", "cognic", "runtime"))
    if runtime_block is not None:
        tier = runtime_block.get("risk_tier")
        if isinstance(tier, str) and tier.strip():
            tiers.append(tier.strip())

    return tiers


def _cross_check_risk_tier(
    declared_classes: list[str], data: dict[str, Any]
) -> list[ValidatorFinding]:
    """Refuse a low-authority risk_tier declaration when data_classes
    intersects the restricted set.

    The "low-authority" tier set is the canonical
    :data:`cognic_agentos.cli._governance_vocab.LOW_AUTHORITY_TIERS`
    (``{"read_only", "internal_write"}`` per ADR-014). T11's
    risk_tier validator owns the per-class minimum-tier cross-check
    using a richer mapping; T10's framing here is the data-governance
    perspective on the same conceptual violation, narrowed to the
    bright-line low-authority set so the two refusals fire as
    informational duplicates (pack-author who fixes either side
    stops both).

    Inspects both manifest shapes: canonical ``[risk_tier].tier`` AND
    legacy ``[tool.cognic.runtime].risk_tier``. The first declared
    low-authority tier intersecting restricted data classes trips
    the refusal — the union semantic prevents pack authors from
    splitting declarations across paths to dodge the cross-check.
    """
    for tier in _declared_risk_tiers(data):
        if tier not in LOW_AUTHORITY_TIERS:
            continue
        restricted = sorted(set(declared_classes) & RESTRICTED_DATA_CLASSES)
        if not restricted:
            continue
        return [
            ValidatorFinding(
                severity="refusal",
                reason="data_governance_contract_inconsistent_with_risk_tier",
                message=(
                    f"declared risk_tier {tier!r} is in the low-"
                    f"authority set ({sorted(LOW_AUTHORITY_TIERS)!r}) but "
                    f"data_governance.data_classes declares restricted "
                    f"classes ({restricted}); raise the tier or remove the "
                    "restricted classes."
                ),
                payload={
                    "risk_tier": tier,
                    "restricted_data_classes": restricted,
                },
            )
        ]
    return []


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
        # Sprint-7A2 T10 — dlp_pre_hooks / dlp_post_hooks shape +
        # snake_case + per-list uniqueness. Per-block (each declared
        # location validated independently); cross-pack resolution
        # remains a runtime registry concern.
        findings.extend(_validate_dlp_hook_list(block, prefix, "dlp_pre_hooks"))
        findings.extend(_validate_dlp_hook_list(block, prefix, "dlp_post_hooks"))

    # Cross-validation operates on the union of valid classes across
    # both paths. Pack authors cannot hide a restricted class from the
    # cross-check by splitting declarations.
    if union_valid_classes:
        all_valid_classes = sorted(union_valid_classes)
        findings.extend(_cross_check_risk_tier(all_valid_classes, data))
        findings.extend(_cross_check_mcp_caching(all_valid_classes, data))

    return findings


__all__ = ["validate"]
