"""Sprint 11.5c T2 — [learning_surface] manifest validator (ADR-019).

CRITICAL CONTROL (CLI build-time half of the memory-governance trust gate per
ADR-008 + ADR-019). Validates a pack's [learning_surface] declaration: a
closed-enum mode + a learnable-data-class allow-list. Refuses restricted data
classes declared learnable (a pack cannot self-grant customer_pii / payment_data
/ credentials / regulator_communication as a learning surface). Dual-path lookup
([tool.cognic.learning_surface] canonical per ADR-019 §52 + [learning_surface]
compat alias) per feedback_dual_path_doctrine.

Closed-enum design (ADR-019 §52): there is ONE ``ValidatorReason`` value —
``learning_surface_violation``. The specific sub-case rides
``payload["failure_mode"]`` (NOT separate reasons). Do NOT mint per-sub-case
``ValidatorReason`` values.

Failure modes (``payload["failure_mode"]``):

  - ``invalid_shape`` — block is present but not a TOML table (e.g., a bare
    string or integer).
  - ``mode_invalid`` — ``[..].mode`` value is not in the closed-enum
    ``LearningSurfaceMode`` literal.
  - ``learnable_data_classes_not_list`` — ``[..].learnable_data_classes`` is
    present but not an array.
  - ``data_class_invalid`` — a member of ``learnable_data_classes`` is not a
    string OR is not in the ``DataClass`` closed-enum.
  - ``data_class_restricted_forbidden`` — a member of
    ``learnable_data_classes`` is a known ``DataClass`` but appears in the
    ``RESTRICTED_DATA_CLASSES`` frozenset; a pack cannot self-grant a
    restricted class as a learning surface.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, get_args

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli._governance_vocab import (
    RESTRICTED_DATA_CLASSES,
    DataClass,
    LearningSurfaceMode,
)

_VALID_MODES: frozenset[str] = frozenset(get_args(LearningSurfaceMode))
_VALID_DATA_CLASSES: frozenset[str] = frozenset(get_args(DataClass))

# Canonical path is [tool.cognic.learning_surface] (ADR-019 §52); top-level
# [learning_surface] is a compat alias (the broader dual-path convention per
# feedback_dual_path_doctrine).
_LOCATIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("tool.cognic.learning_surface", ("tool", "cognic", "learning_surface")),
    ("learning_surface", ("learning_surface",)),
)


def _resolve(data: dict[str, Any], accessor: tuple[str, ...]) -> Any:
    """Walk ``data`` via ``accessor`` keys and return the leaf value (or
    ``None`` if any intermediate step is absent or not a dict).

    Returns the leaf as-is — isinstance-checks apply only to intermediate
    nodes, so a non-dict leaf (e.g., a bare string) is returned as-is rather
    than collapsed to ``None``. This preserves the "present-but-wrong-shape"
    signal that the ``not isinstance(block, dict)`` branch depends on.

    Do NOT replace with ``data_governance._resolve_path``: that helper returns
    ``None`` for a non-table leaf, which would mask the ``invalid_shape``
    finding when ``[learning_surface] = "yes"`` is declared.
    """
    node: Any = data
    for k in accessor:
        if not isinstance(node, dict) or k not in node:
            return None
        node = node[k]
    return node


def _violation(
    *,
    prefix: str,
    failure_mode: str,
    message: str,
    **extra: Any,
) -> ValidatorFinding:
    """Construct a ``learning_surface_violation`` finding.

    Single closed-enum reason per ADR-019 §52; ``failure_mode`` in the
    payload discriminates the sub-case (mirrors
    ``supply_chain_attestation_path_unresolvable``'s payload pattern).
    """
    return ValidatorFinding(
        severity="refusal",
        reason="learning_surface_violation",
        message=message,
        payload={"block_path": prefix, "failure_mode": failure_mode, **extra},
    )


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Validate the ``[learning_surface]`` block (and its compat alias).

    Silent on packs that do not declare a ``[learning_surface]`` block at
    either path — the block is optional; absence means the pack never writes
    to long_term memory as a learning surface.

    Checks performed for each resolved block:

    1. Shape: must be a TOML sub-table (``dict``).
    2. ``mode``: if present, must be a ``LearningSurfaceMode`` value.
    3. ``learnable_data_classes``: if present, must be a list; each member
       must be a ``DataClass`` value AND must not appear in
       ``RESTRICTED_DATA_CLASSES``.
    """
    findings: list[ValidatorFinding] = []
    for prefix, accessor in _LOCATIONS:
        block = _resolve(data, accessor)
        if block is None:
            continue
        if not isinstance(block, dict):
            findings.append(
                _violation(
                    prefix=prefix,
                    failure_mode="invalid_shape",
                    message=(f"[{prefix}] must be a TOML table; got {type(block).__name__}"),
                )
            )
            continue

        # --- mode ---
        mode = block.get("mode")
        if mode is not None and mode not in _VALID_MODES:
            findings.append(
                _violation(
                    prefix=prefix,
                    failure_mode="mode_invalid",
                    message=(
                        f"[{prefix}].mode={mode!r} is not a valid "
                        f"LearningSurfaceMode; expected one of "
                        f"{sorted(_VALID_MODES)}"
                    ),
                    value=mode,
                )
            )

        # --- learnable_data_classes ---
        ldc = block.get("learnable_data_classes")
        if ldc is not None and not isinstance(ldc, list):
            findings.append(
                _violation(
                    prefix=prefix,
                    failure_mode="learnable_data_classes_not_list",
                    message=(
                        f"[{prefix}].learnable_data_classes must be an array; "
                        f"got {type(ldc).__name__}"
                    ),
                )
            )
            # Skip member-loop — iterating a bare string would yield one
            # finding PER CHARACTER (per-char spam) instead of one shape
            # refusal. Assign empty so the loop below is a no-op.
            ldc = []

        for dc in ldc or []:
            if not isinstance(dc, str) or dc not in _VALID_DATA_CLASSES:
                findings.append(
                    _violation(
                        prefix=prefix,
                        failure_mode="data_class_invalid",
                        message=(
                            f"[{prefix}].learnable_data_classes: {dc!r} is not a valid DataClass"
                        ),
                        value=dc,
                    )
                )
            elif dc in RESTRICTED_DATA_CLASSES:
                findings.append(
                    _violation(
                        prefix=prefix,
                        failure_mode="data_class_restricted_forbidden",
                        message=(
                            f"[{prefix}].learnable_data_classes: {dc!r} is a "
                            f"restricted class and may not be declared a "
                            f"learning surface"
                        ),
                        value=dc,
                    )
                )

    return findings
