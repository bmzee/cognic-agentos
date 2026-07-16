"""Sprint-7A T9 — MCP conformance validator.

Wave-1 build-time refusal layer for cognic-pack-manifest.toml's
``[mcp]`` block. Cross-references ``[data_governance].data_classes``
(top-level T5 shape) to refuse caching + form-elicitation against
restricted data — manifest-level inconsistencies authors should fix
BEFORE the runtime per-tool DLP gate (a separate surface; see
"out of scope" below).

Scope (T9):

  - ``[mcp].caching = true`` AND ``[data_governance].data_classes``
    contains a restricted class → ``mcp_caching_restricted_data_class``.
  - ``[mcp].elicitation_form = true`` AND ``data_classes`` contains
    a restricted class → ``mcp_elicitation_form_restricted_data_class``.
  - Both blocks supported via dual-path lookup (top-level ``[mcp]`` is
    canonical T5 / R23 P2 #1; ``[tool.cognic.mcp]`` is the legacy /
    docs-aligned fallback).

Out of T9 scope:

  - The runtime per-tool gate at
    :func:`cognic_agentos.protocol.mcp_capabilities.evaluate_manifest_validation`
    operates on **pyproject.toml**'s ``[tool.cognic.mcp]`` +
    ``[[tool.cognic.tools]]`` arrays with per-tool ``data_classes``
    + ``caching_strategy = "ttl"`` checks against a domain-specific
    restricted set (``customer_pii`` / ``payment_action`` /
    ``regulator_communication``). T9 is the build-time, pack-level
    cross-check; the runtime is the per-tool admission gate. They
    operate on different files + different shapes by design;
    aligning them is a future doctrine question.

  - ``mcp_wave2_feature_in_wave1_manifest`` is reserved in the
    closed-enum literal but has no fire-path at T9: no Wave-2 MCP
    fields are defined in the runtime layer yet. Adding a
    speculative sentinel here would create drift the T1 ownership-
    map gate would reject. T16 closeout reassesses if a real
    Wave-2 MCP field appears.

  - AUTHOR-FILL placeholder values in ``data_classes`` aren't
    matched against the restricted set (an AUTHOR-FILL string is
    not literally "restricted"). T10's data-governance validator
    refuses the placeholder itself; T9 stays focused on the
    cross-check + does not double-fire.

Validator-promotion call (Doctrine Decision G): the cross-block
data-class check adds real allow/deny logic on top of pure-
delegation. Plan-of-record marks T9 as "expected promotion to
critical-controls gate at T16". Halt-before-commit applies per
the user's "strict review even off-gate" override on
conformance-validator work.

D-S1 extends this validator with build-time checks for declared
``[[tool.cognic.tools]]`` capability classes and refuses action
tools in auto-run packs. Runtime dispatch remains the fail-closed
authority for tools absent from the declaration.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli._governance_vocab import (
    RESTRICTED_DATA_CLASSES as _RESTRICTED_DATA_CLASSES,
)

#: Restricted-tier data classes per ADR-017. Single source of truth
#: at :data:`cognic_agentos.cli._governance_vocab.RESTRICTED_DATA_CLASSES`
#: (T10 owns the set; T9 imports from there so the build-time
#: validators agree on which classes are restricted).
#:
#: T10's R26 P2 doctrine notes the runtime layer uses a partly-
#: overlapping domain-specific set
#: (``protocol.mcp_capabilities._RESTRICTED_DATA_CLASSES`` —
#: ``customer_pii`` / ``payment_action`` / ``regulator_communication``).
#: Reconciliation between build-time + runtime is a future doctrine
#: commit; the migration-guard test in
#: ``test_data_governance_vocab_consolidation.py`` pins the contract.


#: Closed-enum tuple of (path-prefix, accessor-tuple) pairs the
#: validator inspects for the ``[mcp]`` block. Mirrors the A2A
#: validator's R23 P2 #1 / R24 P2 #1 dual-path doctrine: top-level
#: is canonical, nested is backward-compat.
_MCP_BLOCK_LOCATIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("mcp", ("mcp",)),
    ("tool.cognic.mcp", ("tool", "cognic", "mcp")),
)

#: Closed-enum tuple of (path-prefix, accessor-tuple) pairs for the
#: ``[data_governance]`` block. R26 P2 #2: the legacy
#: ``[tool.cognic.data_governance]`` path is recognized too so the
#: cross-check operates on the union of declared classes across both
#: shapes. Without this, a docs-shaped manifest declaring restricted
#: data at ``[tool.cognic.data_governance]`` while also declaring
#: ``mcp.caching = true`` would silently bypass the cross-check.
_DATA_GOVERNANCE_LOCATIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("data_governance", ("data_governance",)),
    ("tool.cognic.data_governance", ("tool", "cognic", "data_governance")),
)

#: Closed capability-class vocabulary for ``[[tool.cognic.tools]]``.
_CAPABILITY_CLASSES: Final[frozenset[str]] = frozenset({"data_query", "action", "unscoped"})

#: Reserved for a later milestone; accepting it now would silently downgrade
#: a declared-but-unimplemented authority class.
_RESERVED_CAPABILITY_CLASSES: Final[frozenset[str]] = frozenset({"retrieval"})

#: Pack tiers that do not require human approval. An action-class tool cannot
#: inherit either tier without opening a build-time governance hole.
_AUTO_RUN_TIERS: Final[frozenset[str]] = frozenset({"read_only", "internal_write"})


def _resolve_path(data: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any] | None:
    """Walk ``path`` through ``data``; return the leaf dict or
    ``None`` on any non-dict intermediate."""
    cursor: Any = data
    for segment in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(segment)
    return cursor if isinstance(cursor, dict) else None


def validate_tool_capability_classes(
    data: dict[str, Any],
) -> list[ValidatorFinding]:
    """Validate declared per-tool capability classes without importing pack code.

    Absence remains legal for pre-S1 packs. The runtime dispatcher separately
    refuses tools that lack a declaration, preserving deferred pack loading at
    build time while keeping dispatch fail-closed.
    """
    tool_cognic = _resolve_path(data, ("tool", "cognic"))
    if tool_cognic is None or "tools" not in tool_cognic:
        return []

    tools = tool_cognic["tools"]
    if not isinstance(tools, list):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="mcp_tool_capability_class_invalid",
                message="tool.cognic.tools must be an array of tables.",
                payload={"failure_mode": "tools_not_array"},
            )
        ]

    risk_tier = _resolve_path(data, ("risk_tier",))
    pack_tier = risk_tier.get("tier") if risk_tier is not None else None
    seen: set[str] = set()

    for entry in tools:
        if not isinstance(entry, dict):
            return [
                ValidatorFinding(
                    severity="refusal",
                    reason="mcp_tool_capability_class_invalid",
                    message="[[tool.cognic.tools]] entries must be tables.",
                    payload={"failure_mode": "tool_entry_not_table"},
                )
            ]

        name = entry.get("name")
        if not isinstance(name, str) or not name:
            return [
                ValidatorFinding(
                    severity="refusal",
                    reason="mcp_tool_capability_class_invalid",
                    message=("every [[tool.cognic.tools]] entry needs a non-empty string name."),
                    payload={"failure_mode": "tool_name_missing"},
                )
            ]

        if name in seen:
            return [
                ValidatorFinding(
                    severity="refusal",
                    reason="mcp_tool_capability_class_invalid",
                    message=f"tool {name!r} is declared more than once.",
                    payload={
                        "failure_mode": "tool_name_duplicate",
                        "tool_name": name,
                    },
                )
            ]
        seen.add(name)

        capability_class = entry.get("capability_class")
        if capability_class is None:
            failure_mode = "capability_class_missing"
        elif not isinstance(capability_class, str):
            failure_mode = "capability_class_not_string"
        elif capability_class in _RESERVED_CAPABILITY_CLASSES:
            failure_mode = "capability_class_reserved"
        elif capability_class not in _CAPABILITY_CLASSES:
            failure_mode = "capability_class_unknown"
        else:
            failure_mode = ""

        if failure_mode:
            return [
                ValidatorFinding(
                    severity="refusal",
                    reason="mcp_tool_capability_class_invalid",
                    message=(
                        f"tool {name!r}: capability_class must be one of "
                        f"{sorted(_CAPABILITY_CLASSES)}."
                    ),
                    payload={
                        "failure_mode": failure_mode,
                        "tool_name": name,
                    },
                )
            ]

        if (
            capability_class == "action"
            and isinstance(pack_tier, str)
            and pack_tier in _AUTO_RUN_TIERS
        ):
            return [
                ValidatorFinding(
                    severity="refusal",
                    reason="mcp_action_tool_in_auto_run_pack",
                    message=(
                        f"tool {name!r} is capability_class=action but pack tier "
                        f"{pack_tier!r} does not require human approval. Raise "
                        "the pack tier or move the tool to a separate pack."
                    ),
                    payload={
                        "failure_mode": "action_tool_in_auto_run_pack",
                        "tool_name": name,
                        "pack_risk_tier": pack_tier,
                    },
                )
            ]

    return []


def _declared_data_classes(data: dict[str, Any]) -> set[str]:
    """Return the union of declared data classes across both
    ``[data_governance]`` shapes (R26 P2 #2). Whitespace stripped;
    non-string entries filtered; non-list ``data_classes`` field
    treated as empty (T10 owns the shape refusal)."""
    classes: set[str] = set()
    for _prefix, accessor in _DATA_GOVERNANCE_LOCATIONS:
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


def _detect_caching_field(block: dict[str, Any], prefix: str) -> str | None:
    """R26 P2 #1: detect caching across both field families. Returns
    the qualified field name that triggered detection, or ``None``.

    Both shapes are recognized:

      - ``caching = true`` (T5-scaffolded boolean shape).
      - ``caching_strategy = "ttl"`` (runtime/docs string-strategy
        shape; only ``"ttl"`` trips the refusal — mirrors the runtime
        gate at
        :func:`cognic_agentos.protocol.mcp_capabilities.evaluate_manifest_validation`,
        which treats only TTL caches as restricted-data risk because
        TTL caches survive process restarts).
    """
    if block.get("caching") is True:
        return f"{prefix}.caching"
    if block.get("caching_strategy") == "ttl":
        return f"{prefix}.caching_strategy"
    return None


def _detect_form_elicitation_field(block: dict[str, Any], prefix: str) -> str | None:
    """R26 P2 #1: detect form-mode elicitation across both field
    families. Returns the qualified field name or ``None``.

    Both shapes are recognized:

      - ``elicitation_form = true`` (T5-scaffolded boolean shape).
      - ``elicitation_modes`` list containing ``"form"`` (runtime/
        docs list shape; mirrors the runtime gate's
        ``"form" in elicitation_modes`` check).
    """
    if block.get("elicitation_form") is True:
        return f"{prefix}.elicitation_form"
    modes = block.get("elicitation_modes")
    if isinstance(modes, list) and "form" in modes:
        return f"{prefix}.elicitation_modes"
    return None


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Validate the manifest's ``[mcp]`` block per the Wave-1
    MCP-conformance matrix. Cross-references
    ``[data_governance].data_classes`` for the restricted-class
    refusals.

    Returns refusal-severity findings or an empty list. Per-kind:
    skill + agent packs ship without ``[mcp]`` and produce no
    findings here.
    """
    del pack_path  # T9 reads only the parsed manifest dict
    findings = validate_tool_capability_classes(data)

    declared_classes = _declared_data_classes(data)
    restricted_intersect = sorted(declared_classes & _RESTRICTED_DATA_CLASSES)
    if not restricted_intersect:
        # No restricted classes declared → neither cross-check fires
        # regardless of [mcp] content. Skip block traversal entirely.
        return findings

    for prefix, accessor in _MCP_BLOCK_LOCATIONS:
        block = _resolve_path(data, accessor)
        if block is None:
            continue

        caching_field = _detect_caching_field(block, prefix)
        if caching_field is not None:
            findings.append(
                ValidatorFinding(
                    severity="refusal",
                    reason="mcp_caching_restricted_data_class",
                    message=(
                        f"{caching_field} declares caching but the pack "
                        f"declares restricted data classes ({restricted_intersect}); "
                        "caching restricted-class data is forbidden in "
                        "Wave-1 (the cache could leak the protected "
                        "values). Disable caching or remove the "
                        "restricted class from [data_governance]."
                    ),
                    payload={
                        "block_path": prefix,
                        "field": caching_field,
                        "restricted_data_classes": restricted_intersect,
                    },
                )
            )

        elicitation_field = _detect_form_elicitation_field(block, prefix)
        if elicitation_field is not None:
            findings.append(
                ValidatorFinding(
                    severity="refusal",
                    reason="mcp_elicitation_form_restricted_data_class",
                    message=(
                        f"{elicitation_field} declares form-mode elicitation "
                        f"but the pack declares restricted data classes "
                        f"({restricted_intersect}); form-mode elicitation "
                        "against restricted-class data is forbidden in "
                        "Wave-1. Disable form-mode elicitation or remove "
                        "the restricted class from [data_governance]."
                    ),
                    payload={
                        "block_path": prefix,
                        "field": elicitation_field,
                        "restricted_data_classes": restricted_intersect,
                    },
                )
            )

    return findings


__all__ = ["validate", "validate_tool_capability_classes"]
