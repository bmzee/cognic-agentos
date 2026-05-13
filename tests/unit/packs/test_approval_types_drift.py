"""Sprint 7B.3 T2 Slice A — drift detector for ``packs/approval_types.py``.

The :data:`cognic_agentos.packs.approval_types.ApprovalOverrideReason`
closed-enum Literal IS the wire-protocol contract for the approve
endpoint's request-body ``override_reason`` field per ADR-012 §107.
Banks consume the 4 values via API requests; drift between the Literal
and the ADR documentation is a wire-protocol-public regression class.

This drift detector pins the closed-enum vocabulary against ADR-012
§107 doctrine with three regressions per R7 P3 #5:

1. **Exact-set equality** — ``typing.get_args(ApprovalOverrideReason)``
   matches the ADR-012 §107 four-value set verbatim.
2. **Count guard** — the Literal has exactly 4 members. Independent
   of the set check so a future divergence diagnoses cleanly.
3. **AST scan** — the module declares ONLY the Literal (no executable
   logic, no functions, no classes); this pins the off-floor rationale
   from R7 P3 #5 (per-file coverage gates are meaningless for type-only
   modules; drift detector is the substantive guard).

The module stays OFF the durable critical-controls coverage gate
per R7 P3 #5; this drift detector + the existing scope test layer
are the substantive regression coverage.
"""

from __future__ import annotations

import ast
import typing
from pathlib import Path

_EXPECTED_OVERRIDE_REASONS = frozenset(
    {
        "security_exception",
        "prerelease_validation",
        "legacy_grandfather",
        "other",
    }
)
"""ADR-012 §107 closed-enum vocabulary for approval override reasons.

Source of truth: ``docs/adrs/ADR-012-bank-pack-lifecycle.md`` §107
("Requires a categorised reason ... security_exception | prerelease_
validation | legacy_grandfather | other"). Drift between this fixture
and the live Literal is the failure mode this module detects.
"""


class TestSprint7B3T2SliceAApprovalOverrideReasonVocabulary:
    """R7 P3 #5 drift detector — three regressions against ADR-012 §107."""

    def test_approval_override_reason_matches_canonical_adr012_set(self) -> None:
        """Exact-set equality against ADR-012 §107.

        Imports ``ApprovalOverrideReason`` from the live module +
        compares ``typing.get_args(...)`` against the ADR fixture.
        Drift in either direction (extra value / missing value /
        renamed value) fails this assertion.
        """
        from cognic_agentos.packs.approval_types import ApprovalOverrideReason

        assert frozenset(typing.get_args(ApprovalOverrideReason)) == _EXPECTED_OVERRIDE_REASONS

    def test_approval_override_reason_has_exactly_four_values(self) -> None:
        """Count guard — pinned independently for crisp drift diagnosis.

        If R10 closed-enum drift (e.g. someone adds a 5th value), the
        set equality test above fails AND this count guard fails.
        Two failing tests pinpoint "vocabulary changed" rather than
        "the test framework broke".
        """
        from cognic_agentos.packs.approval_types import ApprovalOverrideReason

        assert len(typing.get_args(ApprovalOverrideReason)) == 4

    def test_module_declares_only_the_literal_no_executable_logic(self) -> None:
        """AST scan asserting the module is type-only per R7 P3 #5.

        Pins the off-floor rationale: ``packs/approval_types.py`` is a
        neutral domain vocabulary module with no executable logic, so
        per-file coverage gates are meaningless. This test fails if a
        future change adds functions, classes, or executable statements
        that would warrant on-gate promotion.

        Allowed top-level nodes: ``Import`` / ``ImportFrom`` /
        ``Assign`` / ``AnnAssign`` / ``Expr`` (module docstring).
        Any ``FunctionDef`` / ``AsyncFunctionDef`` / ``ClassDef`` /
        ``If`` / ``For`` / ``While`` / etc. flips the off-floor
        decision and this regression must be re-reviewed.
        """
        module_path = (
            Path(__file__).resolve().parents[3]
            / "src"
            / "cognic_agentos"
            / "packs"
            / "approval_types.py"
        )
        source = module_path.read_text()
        tree = ast.parse(source)

        allowed_node_types = (
            ast.Import,
            ast.ImportFrom,
            ast.Assign,
            ast.AnnAssign,
            ast.Expr,  # bare expressions; the module docstring lives here
        )
        for node in tree.body:
            assert isinstance(node, allowed_node_types), (
                f"packs/approval_types.py must remain type-only per R7 P3 #5 "
                f"off-floor rationale; found disallowed AST node "
                f"{type(node).__name__} at line {node.lineno}. If executable "
                f"logic is required, T11 must re-decide the on-gate status."
            )
