"""Sprint 3 T2 — tier alias resolver.

Critical-controls module per AGENTS.md (``llm/gateway.py`` — cloud-policy
enforcer + provider-honesty ledger feed). Coverage gate: ≥95% line / ≥90%
branch per-file. T2 ships only the tier→alias-name translation; the
api_base-aware classifier + ``ResolvedUpstream`` dataclass live in
``llm/preflight.py`` (T6) per the plan's Round-2 reviewer-P1#2 fix.
"""

from __future__ import annotations

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.llm.gateway import (
    Tier,
    UnknownTierError,
    resolve_tier_alias,
)


class TestResolveTierAlias:
    """Plan T2 test set — three positive cases + the unknown-tier raise."""

    def test_tier1_resolves_from_settings(self) -> None:
        s = Settings(tier1_alias="cognic-tier1-vllm")
        assert resolve_tier_alias("tier1", s) == "cognic-tier1-vllm"

    def test_tier2_resolves_from_settings(self) -> None:
        s = Settings(tier2_alias="cognic-tier2-sglang")
        assert resolve_tier_alias("tier2", s) == "cognic-tier2-sglang"

    def test_unknown_tier_raises(self) -> None:
        s = Settings()
        with pytest.raises(UnknownTierError, match="unknown tier"):
            resolve_tier_alias("tier99", s)


class TestResolveTierAliasNegativePaths:
    """Critical-controls negative-path coverage — drives the per-file gate
    + pins behaviour future implementers (or T6) might inadvertently break.
    """

    @pytest.mark.parametrize(
        "tier",
        ["", "TIER1", "Tier1", "tier3", "tier 1", " tier1", "tier1 ", "0", "1"],
    )
    def test_anything_other_than_tier1_or_tier2_raises(self, tier: str) -> None:
        """Case-sensitive, exact-match — no normalisation, no fallback."""
        s = Settings()
        with pytest.raises(UnknownTierError, match="unknown tier"):
            resolve_tier_alias(tier, s)

    def test_unknown_tier_error_subclasses_value_error(self) -> None:
        """Callers catching ValueError still trip on this — important
        for any caller that does generic settings/validation handling
        (e.g. the gateway's own audit-emission paths)."""
        assert issubclass(UnknownTierError, ValueError)

    def test_tier_literal_carries_only_two_members(self) -> None:
        """Sprint 3 vocabulary is fixed at tier1+tier2; Sprint 9.5
        (ADR-013 model registry) extends. Pin the surface so an
        accidental Literal expansion fails this test, prompting the
        implementer to also extend resolve_tier_alias + the unknown-tier
        path.
        """
        from typing import get_args

        assert set(get_args(Tier)) == {"tier1", "tier2"}

    def test_unknown_tier_message_lists_known_tiers(self) -> None:
        """Operator-friendly error message: the message tells the user
        what the known set is, so a misconfigured caller doesn't have
        to grep the source. Plan §1 contract."""
        s = Settings()
        with pytest.raises(UnknownTierError) as exc_info:
            resolve_tier_alias("not-a-tier", s)
        msg = str(exc_info.value)
        assert "tier1" in msg
        assert "tier2" in msg
        assert "not-a-tier" in msg
