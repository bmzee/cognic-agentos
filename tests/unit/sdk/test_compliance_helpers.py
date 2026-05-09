"""Sprint-7A T3 — `agentos_sdk.compliance` ISO-42001 control helpers.

Pack authors call ``declare_iso_42001_controls(...)`` at module-import
time to register their pack's control declarations; the validate
command's identity validator (T7) cross-checks declared controls
against the manifest's claimed coverage. Per Doctrine Decision E,
every commit touching this surface halts before commit.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _reset_registry_between_tests() -> None:
    """The ISO-42001 declared-controls registry is module-level
    global state; reset it before every test to avoid cross-test
    contamination. The reset helper is underscore-prefixed in the
    public API to signal "test-only"."""
    from cognic_agentos.sdk.compliance import _reset_declared_iso_42001_controls

    _reset_declared_iso_42001_controls()


# ---------------------------------------------------------------------------
# ControlDeclaration dataclass
# ---------------------------------------------------------------------------


def test_control_declaration_carries_three_fields() -> None:
    from cognic_agentos.sdk.compliance import ControlDeclaration

    decl = ControlDeclaration(
        iso_42001_clause="A.6.4 Information security in supplier relationships",
        declaration="Pack ships a signed SBOM via cosign sign-blob.",
        evidence_path=Path("compliance/A_6_4.md"),
    )

    assert decl.iso_42001_clause.startswith("A.6.4")
    assert "cosign" in decl.declaration
    assert decl.evidence_path == Path("compliance/A_6_4.md")


def test_control_declaration_evidence_path_is_optional() -> None:
    """Declarations CAN omit the evidence-path; some declarations
    are policy-level (no on-disk artifact)."""
    from cognic_agentos.sdk.compliance import ControlDeclaration

    decl = ControlDeclaration(
        iso_42001_clause="A.6.1.2",
        declaration="No third-party LLM calls in this pack.",
        evidence_path=None,
    )

    assert decl.evidence_path is None


def test_control_declaration_is_frozen() -> None:
    """Declarations are immutable once constructed — pack authors
    treat them as read-only certificates of behaviour."""
    from cognic_agentos.sdk.compliance import ControlDeclaration

    decl = ControlDeclaration(
        iso_42001_clause="A.6.4",
        declaration="x",
        evidence_path=None,
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        decl.declaration = "y"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# declare_iso_42001_controls + accessor
# ---------------------------------------------------------------------------


def test_declare_iso_42001_controls_appends_to_registry() -> None:
    from cognic_agentos.sdk.compliance import (
        ControlDeclaration,
        declare_iso_42001_controls,
        declared_iso_42001_controls,
    )

    a = ControlDeclaration(iso_42001_clause="A.6.4", declaration="d-a", evidence_path=None)
    b = ControlDeclaration(iso_42001_clause="A.7.2", declaration="d-b", evidence_path=None)
    declare_iso_42001_controls(a, b)

    assert declared_iso_42001_controls() == (a, b)


def test_declare_iso_42001_controls_supports_repeated_calls() -> None:
    """Pack authors can split declarations across modules; every call
    appends to the global registry."""
    from cognic_agentos.sdk.compliance import (
        ControlDeclaration,
        declare_iso_42001_controls,
        declared_iso_42001_controls,
    )

    a = ControlDeclaration(iso_42001_clause="A.6.4", declaration="d-a", evidence_path=None)
    b = ControlDeclaration(iso_42001_clause="A.7.2", declaration="d-b", evidence_path=None)

    declare_iso_42001_controls(a)
    declare_iso_42001_controls(b)

    assert declared_iso_42001_controls() == (a, b)


def test_declared_iso_42001_controls_returns_tuple() -> None:
    """The accessor returns a tuple — pack-author code CANNOT mutate
    the registry by manipulating the return value."""
    from cognic_agentos.sdk.compliance import (
        ControlDeclaration,
        declare_iso_42001_controls,
        declared_iso_42001_controls,
    )

    declare_iso_42001_controls(
        ControlDeclaration(iso_42001_clause="A.6.4", declaration="d", evidence_path=None)
    )

    result = declared_iso_42001_controls()
    assert isinstance(result, tuple)


def test_declared_iso_42001_controls_initial_empty() -> None:
    """The autouse fixture resets between tests; initial state is
    an empty tuple."""
    from cognic_agentos.sdk.compliance import declared_iso_42001_controls

    assert declared_iso_42001_controls() == ()


# ---------------------------------------------------------------------------
# Public re-exports
# ---------------------------------------------------------------------------


def test_compliance_module_exports_public_surface() -> None:
    """The four public names are reachable from
    ``cognic_agentos.sdk.compliance``; the reset helper is
    underscore-prefixed (test-only signal) and excluded from
    ``__all__``."""
    from cognic_agentos.sdk import compliance as c

    for name in (
        "ControlDeclaration",
        "declare_iso_42001_controls",
        "declared_iso_42001_controls",
    ):
        assert name in c.__all__, f"{name} missing from compliance.__all__"
    assert "_reset_declared_iso_42001_controls" not in c.__all__
