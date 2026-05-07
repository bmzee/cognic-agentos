"""Sprint-7A T3 — `agentos_sdk.compliance` ISO-42001 control helpers.

Pack authors call :func:`declare_iso_42001_controls` at module-import
time to register their pack's control declarations. The validate
command's identity validator (Sprint-7A T7) cross-checks declared
controls against the manifest's claimed coverage.

Public surface:

  - :class:`ControlDeclaration` — frozen dataclass carrying one
    control entry (clause + declaration + optional evidence path).
  - :func:`declare_iso_42001_controls` — variadic registration helper
    appending to the module-level registry.
  - :func:`declared_iso_42001_controls` — read accessor returning a
    tuple snapshot. Pack-author code reads via this accessor; direct
    access to the underscore-prefixed registry is forbidden.

Test-only:

  - :func:`_reset_declared_iso_42001_controls` — clears the registry
    so per-test fixtures can exercise registration in isolation. The
    underscore prefix + exclusion from ``__all__`` signals
    "test-only" to pack-author IDEs.

Per Doctrine Decision E: every commit touching this surface halts
before commit (semver-stability concern, NOT critical-controls
security gate).
"""

from __future__ import annotations

import dataclasses
from pathlib import Path


@dataclasses.dataclass(frozen=True, slots=True)
class ControlDeclaration:
    """One ISO 42001 control-coverage entry declared by a pack.

    Pack authors construct one of these for every control their pack
    honors; the validate command (T7) cross-checks declared entries
    against the manifest's claimed coverage matrix and refuses
    registration on mismatch (closed-enum reason
    ``identity_oasf_capability_set_missing`` is the only T1-seeded
    related reason; broader cross-check reasons land at T7).

    Frozen + slotted: declarations cannot be mutated after
    construction. Pack-author code treats them as read-only
    certificates of behaviour.
    """

    iso_42001_clause: str
    """ISO 42001 clause identifier — e.g., ``"A.6.4 Information
    security in supplier relationships"``. The free-form text is the
    pack-author's choice; T7 normalises against the published
    ISO-42001 clause vocabulary."""

    declaration: str
    """Human-readable description of what the pack does to honor the
    clause. Surfaced verbatim in the validate command's compliance-
    coverage rendering."""

    evidence_path: Path | None
    """Optional pack-relative path to a supporting artifact (e.g.,
    ``Path("compliance/A_6_4.md")``). ``None`` is permitted for
    policy-level declarations with no on-disk artifact."""


#: Module-level registry. Pack-author code MUST NOT read this
#: directly — use :func:`declared_iso_42001_controls` for the
#: read accessor that returns an immutable tuple snapshot.
_DECLARED_CONTROLS: list[ControlDeclaration] = []


def declare_iso_42001_controls(*controls: ControlDeclaration) -> None:
    """Register one or more :class:`ControlDeclaration` entries with
    the module-level registry.

    Variadic call signature so pack authors can register a batch
    in a single call::

        declare_iso_42001_controls(
            ControlDeclaration(
                iso_42001_clause="A.6.4 Information security in supplier relationships",
                declaration="Pack ships a signed SBOM via cosign sign-blob.",
                evidence_path=Path("compliance/A_6_4.md"),
            ),
            ControlDeclaration(
                iso_42001_clause="A.6.1.2 Segregation of duties",
                declaration="No third-party LLM calls in this pack.",
                evidence_path=None,
            ),
        )

    Repeated calls accumulate — pack authors can split declarations
    across modules and every call appends to the same registry.
    Cross-pack ordering follows registration order (which is
    pack-import order in the host process).
    """
    _DECLARED_CONTROLS.extend(controls)


def declared_iso_42001_controls() -> tuple[ControlDeclaration, ...]:
    """Return a tuple snapshot of every registered
    :class:`ControlDeclaration`. Pack-author code uses this accessor
    rather than the underscore-prefixed registry so the registry
    state cannot be mutated through the return value."""
    return tuple(_DECLARED_CONTROLS)


def _reset_declared_iso_42001_controls() -> None:
    """Clear the registry. Test-only — pack-author production code
    MUST NOT call this. Pytest fixtures that exercise registration
    use this between tests to avoid cross-test contamination.

    Excluded from :data:`__all__` so import-* never picks it up.
    """
    _DECLARED_CONTROLS.clear()


__all__ = [
    "ControlDeclaration",
    "declare_iso_42001_controls",
    "declared_iso_42001_controls",
]
