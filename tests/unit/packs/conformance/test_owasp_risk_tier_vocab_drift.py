"""Sprint-7B.2 R45 — risk-tier vocabulary drift detector.

The OWASP ``check_tool_misuse`` validates ``manifest.risk_tier.tier``
against :data:`cognic_agentos.packs.conformance.owasp_agentic._VALID_RISK_TIERS`,
an inlined frozenset that MUST stay in lockstep with ADR-014's
canonical authority ordering at
:data:`cognic_agentos.cli._governance_vocab.RiskTier`. The OWASP
matrix is wire-protocol-public per ADR-006 and the validator-side
vocabulary is wire-protocol-public per ADR-008 — drift between them
forces every validator-clean pack into red OWASP conformance.

This file pins the lockstep without coupling the production
conformance code to the CLI layer. The architectural arrow is
``cli → packs`` (CLI validators import from packs / depends on the
matrix's wire types); reversing that arrow inside production code
would create a circular dependency and break the layering doctrine.
The test file imports BOTH surfaces and asserts they match — that's
the seam where coupling is allowed.

Per the R45 reviewer answer: "add a drift test comparing the OWASP
set to ``typing.get_args(cli._governance_vocab.RiskTier)`` without
importing CLI from production conformance code".
"""

from __future__ import annotations

import typing


class TestSprint7B2R45RiskTierVocabularyLockstep:
    def test_owasp_valid_risk_tiers_matches_canonical_adr014_set(self) -> None:
        """The OWASP-side ``_VALID_RISK_TIERS`` frozenset MUST equal
        ``frozenset(typing.get_args(RiskTier))``. Sprint-7B.2 R45 fixed
        an earlier T8 seed that hard-coded ``{"low", "medium", "high"}``
        — a vocabulary that does not appear in ADR-014's canonical
        ``RiskTier`` Literal. Without this lockstep, every
        validator-clean pack is forced into red OWASP conformance on
        ``check_tool_misuse``."""
        from cognic_agentos.cli._governance_vocab import RiskTier
        from cognic_agentos.packs.conformance.owasp_agentic import _VALID_RISK_TIERS

        canonical = frozenset(typing.get_args(RiskTier))
        assert canonical == _VALID_RISK_TIERS, (
            f"OWASP risk-tier vocabulary diverged from ADR-014 canonical set; "
            f"OWASP={sorted(_VALID_RISK_TIERS)!r} vs "
            f"canonical={sorted(canonical)!r}; "
            "see plan-of-record R45 and the Sprint-7B.2 closeout for context"
        )

    def test_canonical_set_has_exactly_eight_values(self) -> None:
        """ADR-014's canonical authority ordering has 8 tiers; the
        OWASP matrix MUST cover the full set so any validator-clean
        pack flows through the conformance arm without a false-fail
        on the risk-tier probe. Pinned independently of the equality
        assertion above so the failure mode is diagnosed crisply
        (count drift vs. value drift)."""
        from cognic_agentos.packs.conformance.owasp_agentic import _VALID_RISK_TIERS

        assert len(_VALID_RISK_TIERS) == 8, (
            f"expected 8 canonical risk tiers per ADR-014; got "
            f"{len(_VALID_RISK_TIERS)}: {sorted(_VALID_RISK_TIERS)!r}"
        )

    def test_production_conformance_module_does_not_import_cli(self) -> None:
        """The architectural arrow runs ``cli → packs``. The OWASP
        matrix module MUST NOT import from ``cognic_agentos.cli`` to
        validate its inlined ``_VALID_RISK_TIERS`` against the canonical
        ``RiskTier`` Literal at runtime — that import would create a
        circular dependency through ``cli/validators/risk_tier.py``
        which already consumes the matrix's wire types. AST scan of
        the module source pins the deferred-boundary contract."""
        import ast
        from pathlib import Path

        module_path = (
            Path(__file__).resolve().parents[4]
            / "src"
            / "cognic_agentos"
            / "packs"
            / "conformance"
            / "owasp_agentic.py"
        )
        tree = ast.parse(module_path.read_text())
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module)

        forbidden = {
            m for m in imports if m == "cognic_agentos.cli" or m.startswith("cognic_agentos.cli.")
        }
        assert forbidden == set(), (
            f"packs/conformance/owasp_agentic.py must not import from "
            f"cognic_agentos.cli (architectural arrow runs cli → packs); "
            f"found {forbidden!r}. The drift detector in this file enforces "
            "lockstep at test time without coupling production code."
        )
