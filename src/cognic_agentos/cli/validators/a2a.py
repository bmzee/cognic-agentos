"""Sprint-7A T8 — A2A conformance validator.

Build-time refusal layer that mirrors the runtime A2A capability
reader's Wave-2-field filter (
:data:`cognic_agentos.protocol.a2a_capability_negotiation._WAVE2_MANIFEST_FIELDS`).
The runtime reader silently filters Wave-2-opt-in declarations at
registration time per Decision Lock #2; the build-time validator
fires an explicit refusal so pack authors fix the manifest BEFORE
shipping rather than discovering the silent filter after the pack
is registered.

Wave-1 scope (T8):

  - ``[a2a].push_notification_config = true`` (the only Wave-2
    field flagged in the runtime filter today; new Wave-2 fields
    added to the runtime set are picked up automatically by the
    validator iteration here).

Out of T8 scope:

  - ``streaming = true`` cross-check against ``identity.agent_card_url`` —
    T7's identity validator already enforces ``agent_card_url``
    presence for agent packs, so a streaming agent pack without a
    card URL is already refused upstream. Adding a duplicate
    refusal here would create double-emission noise without
    catching anything T7 misses.
  - Tool/skill packs declaring ``[a2a]`` (no closed-enum reason
    yet; if this becomes a doctrinal concern, T16 introduces the
    reason at gate-promotion time).

Validator-promotion call (Doctrine Decision G): T8 borders on pure
delegation but adds a real fire-path the runtime reader does NOT
(the reader silently filters; the validator refuses). The plan-of-
record defers final critical-controls promotion to T16 closeout
based on combined T7-T12 implementation depth. T8 halts before
commit per the user's "strict review even off-gate" override.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.protocol.a2a_capability_negotiation import _WAVE2_MANIFEST_FIELDS

#: Closed-enum tuple of (field-path-prefix, accessor-tuple) pairs
#: the validator checks for the ``[a2a]`` capability declarations.
#: Two locations are recognized so pack authors who follow either
#: shape get build-time validation:
#:
#:   - Top-level ``[a2a]`` — the canonical T5-scaffolded shape that
#:     mirrors the rest of cognic-pack-manifest.toml's top-level
#:     governance blocks ([identity] / [data_governance] / etc.).
#:   - ``[tool.cognic.a2a]`` — the legacy/runtime-aligned shape used
#:     by the runtime reader at
#:     :func:`cognic_agentos.protocol.a2a_capability_negotiation.read_pack_capabilities`
#:     and the historical example in ``docs/A2A-CONFORMANCE.md``.
#:     Pack authors copying from the doc would otherwise bypass the
#:     validator entirely (R23 P2 #1).
#:
#: A pack that declares ``[a2a]`` AND ``[tool.cognic.a2a]`` gets
#: validated against BOTH (refusals carry the location prefix in
#: ``payload.field`` so CI parsers can render targeted remediation).
_A2A_BLOCK_LOCATIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("a2a", ("a2a",)),
    ("tool.cognic.a2a", ("tool", "cognic", "a2a")),
)


def _resolve_path(data: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any] | None:
    """Walk ``path`` through ``data``; return the leaf dict if every
    intermediate step resolves to a dict, otherwise ``None``."""
    cursor: Any = data
    for segment in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(segment)
    return cursor if isinstance(cursor, dict) else None


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Validate the manifest's A2A capability declarations against the
    Wave-1 conformance matrix.

    Both the T5-scaffolded top-level ``[a2a]`` and the legacy/runtime-
    aligned ``[tool.cognic.a2a]`` are checked (R23 P2 #1) so pack
    authors who follow either shape get the same build-time refusal
    on Wave-2-opt-in declarations. Returns refusal-severity findings
    or an empty list.
    """
    del pack_path  # T8 reads only the parsed manifest dict
    findings: list[ValidatorFinding] = []

    for prefix, accessor in _A2A_BLOCK_LOCATIONS:
        block = _resolve_path(data, accessor)
        if block is None:
            continue

        # Mirror the runtime reader's Wave-2 filter set. Iterating
        # over _WAVE2_MANIFEST_FIELDS (rather than hardcoding
        # "push_notification_config" here) means a future Wave-2
        # field added to the runtime layer automatically gets a
        # build-time refusal here too — single source of truth for
        # what's Wave-2.
        for field in sorted(_WAVE2_MANIFEST_FIELDS):
            # Strict bool-only check, mirroring the runtime reader's
            # _bool_or_false posture: a string "true" is NOT treated
            # as Wave-2 opt-in. Pack authors who set non-bool values
            # get the same silent-filter behavior as at runtime,
            # NOT a spurious type-mismatch refusal.
            if block.get(field) is True:
                full_field_path = f"{prefix}.{field}"
                findings.append(
                    ValidatorFinding(
                        severity="refusal",
                        reason="a2a_wave2_feature_in_wave1_manifest",
                        message=(
                            f"{full_field_path} is set to true but the "
                            "field is Wave-2-only; the runtime reader "
                            "silently filters this at registration. Set "
                            "the field to false (or remove it) until "
                            "Wave-2 lifts the gate."
                        ),
                        payload={"field": full_field_path},
                    )
                )

    return findings


__all__ = ["validate"]
