"""Per-pack-kind applicability matrix tests (Sprint 7B.2 T8).

Per the T8 user lock:

- ``_APPLICABILITY: dict[OWASPCheckCategory, frozenset[PackKind]]`` lives at
  module scope; runner consults it BEFORE invoking a check.
- Each check body's own ``not_applicable`` paths (e.g. skill-specific checks
  rejecting a non-skill manifest) remain valid; the matrix is an ADDITIONAL
  short-circuit so the wire-protocol contract is examiner-readable from the
  static table (no need to read every check body to predict applicability).
- The matrix matches the user-locked proposal exactly:

  - ``tool_misuse``              → all 4 kinds
  - ``goal_hijacking``           → ``agent``, ``skill``
  - ``identity_abuse``           → all 4 kinds
  - ``prompt_injected_skills``   → ``skill`` only
  - ``dependency_poisoning``     → all 4 kinds
  - ``secret_exfiltration``      → all 4 kinds
  - ``unsafe_filesystem``        → ``tool``, ``skill``, ``agent`` (hook N/A
    per ADR-004 — hooks have no FS surface)
  - ``unsafe_network``           → all 4 kinds
  - ``supply_chain_integrity``   → all 4 kinds
  - ``skills_top_10``            → ``skill`` only
"""

from __future__ import annotations

import typing

import pytest

_PACK_KINDS: tuple[str, ...] = ("tool", "skill", "agent", "hook")

# User-locked matrix per the T8 handling note. Pinned here as a literal so the
# matrix-shape test compares the production constant against an independent
# source-of-truth rather than self-referencing.
_EXPECTED_APPLICABILITY: dict[str, frozenset[str]] = {
    "tool_misuse": frozenset({"tool", "skill", "agent", "hook"}),
    "goal_hijacking": frozenset({"agent", "skill"}),
    "identity_abuse": frozenset({"tool", "skill", "agent", "hook"}),
    "prompt_injected_skills": frozenset({"skill"}),
    "dependency_poisoning": frozenset({"tool", "skill", "agent", "hook"}),
    "secret_exfiltration": frozenset({"tool", "skill", "agent", "hook"}),
    "unsafe_filesystem": frozenset({"tool", "skill", "agent"}),
    "unsafe_network": frozenset({"tool", "skill", "agent", "hook"}),
    "supply_chain_integrity": frozenset({"tool", "skill", "agent", "hook"}),
    "skills_top_10": frozenset({"skill"}),
}


class TestApplicabilityMatrixShape:
    """Pin the ``_APPLICABILITY`` constant at module scope is the user-locked shape."""

    def test_applicability_exists_at_module_scope(self) -> None:
        from cognic_agentos.packs.conformance import owasp_agentic

        assert hasattr(owasp_agentic, "_APPLICABILITY")
        assert isinstance(owasp_agentic._APPLICABILITY, dict)

    def test_applicability_has_one_entry_per_owasp_category(self) -> None:
        from cognic_agentos.packs.conformance import owasp_agentic
        from cognic_agentos.packs.conformance.checks import OWASPCheckCategory

        all_categories = set(typing.get_args(OWASPCheckCategory))
        assert set(owasp_agentic._APPLICABILITY.keys()) == all_categories

    def test_applicability_matches_user_locked_matrix(self) -> None:
        """Compare the production constant against the locked source-of-truth.

        Tightly pins the matrix shape — any drift from the user-locked proposal
        without explicit re-authorization fails this test."""
        from cognic_agentos.packs.conformance import owasp_agentic

        assert dict(owasp_agentic._APPLICABILITY) == _EXPECTED_APPLICABILITY

    def test_every_value_is_a_frozenset_of_known_pack_kinds(self) -> None:
        from cognic_agentos.packs.conformance import owasp_agentic

        valid_kinds = set(_PACK_KINDS)
        for category, kinds in owasp_agentic._APPLICABILITY.items():
            assert isinstance(kinds, frozenset), (
                f"{category!r}: expected frozenset, got {type(kinds).__name__}"
            )
            assert kinds <= valid_kinds, (
                f"{category!r}: kinds {kinds!r} not subset of {valid_kinds!r}"
            )
            assert kinds, f"{category!r}: applicability set is empty"


class TestCategorySetCohesion:
    """Cross-set drift guard (user-requested T8 closeout review guard).

    The three places that enumerate the OWASP categories — the closed-enum
    Literal, the static applicability matrix, and the ordered runner registry
    — MUST all carry the same 10-element category set. Drift in any one
    surface without the other two is the most likely future regression
    (add a new check / forget the matrix; rename a check / forget the Literal;
    etc.).
    """

    def test_check_registry_and_applicability_and_literal_share_category_set(
        self,
    ) -> None:
        from cognic_agentos.packs.conformance import owasp_agentic
        from cognic_agentos.packs.conformance.checks import OWASPCheckCategory

        literal_categories = set(typing.get_args(OWASPCheckCategory))
        registry_categories = {cat for cat, _ in owasp_agentic._CHECK_REGISTRY}
        applicability_categories = set(owasp_agentic._APPLICABILITY.keys())

        assert literal_categories == registry_categories, (
            f"_CHECK_REGISTRY drifted from OWASPCheckCategory: "
            f"literal-only={literal_categories - registry_categories}, "
            f"registry-only={registry_categories - literal_categories}"
        )
        assert literal_categories == applicability_categories, (
            f"_APPLICABILITY drifted from OWASPCheckCategory: "
            f"literal-only={literal_categories - applicability_categories}, "
            f"matrix-only={applicability_categories - literal_categories}"
        )

    def test_check_registry_order_matches_owasp_check_category_literal_order(
        self,
    ) -> None:
        """Per user lock: 'preserve _CHECK_REGISTRY / OWASPCheckCategory order
        for report results and errored_categories.' The literal's declaration
        order IS the registry's iteration order; drift would re-order
        ``errored_categories`` in the chain payload."""
        from cognic_agentos.packs.conformance import owasp_agentic
        from cognic_agentos.packs.conformance.checks import OWASPCheckCategory

        literal_order = list(typing.get_args(OWASPCheckCategory))
        registry_order = [cat for cat, _ in owasp_agentic._CHECK_REGISTRY]

        assert registry_order == literal_order, (
            f"_CHECK_REGISTRY ordering drift from OWASPCheckCategory literal: "
            f"registry={registry_order!r}, literal={literal_order!r}"
        )


class TestApplicabilityFullMatrix:
    """Full 10 x 4 matrix — for each (category, pack_kind), assert that the runner
    short-circuits to ``not_applicable`` when the kind is not applicable.

    40 parametrized cases. The runner-side enforcement runs through
    ``run_owasp_conformance`` so the test exercises the integration of the matrix
    short-circuit with the dispatch loop (not just the static table)."""

    @pytest.mark.parametrize(
        ("category", "pack_kind"),
        [(cat, kind) for cat in _EXPECTED_APPLICABILITY for kind in _PACK_KINDS],
    )
    def test_runner_short_circuits_when_kind_not_applicable(
        self, category: str, pack_kind: str
    ) -> None:
        from cognic_agentos.packs.conformance.owasp_agentic import (
            run_owasp_conformance,
        )

        # Minimum manifest that wouldn't trigger the runner's exception path —
        # individual checks may pass / fail / N/A on the body, but if the
        # matrix says the kind is not applicable, the runner short-circuits
        # BEFORE the body runs.
        manifest: dict[str, object] = {
            "pack": {"kind": pack_kind, "name": "demo", "version": "1.0.0"},
        }

        report = run_owasp_conformance(manifest)
        result = report.results[category]  # type: ignore[index]

        applicable_kinds = _EXPECTED_APPLICABILITY[category]
        if pack_kind not in applicable_kinds:
            assert result.status == "not_applicable", (
                f"({category}, {pack_kind}): expected not_applicable per matrix, "
                f"got {result.status!r} with findings={result.findings!r}"
            )
            # Short-circuit finding uses the stable field-path format:
            # "manifest.pack.kind: ..."
            assert any(f.startswith("manifest.pack.kind:") for f in result.findings), (
                f"({category}, {pack_kind}): short-circuit finding must start "
                f"with 'manifest.pack.kind:', got {result.findings!r}"
            )
