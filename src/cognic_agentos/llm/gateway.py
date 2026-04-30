"""LLM gateway (Sprint 3) — tier alias resolution + completion flow.

Layer classification: **platform primitive** (critical control per
AGENTS.md — cloud-policy enforcer + provider-honesty ledger feed).

Sprint 3 T2 ships only the tier-name → LiteLLM-alias translator.
The LiteLLM-alias → :class:`ResolvedUpstream` resolver + the
api_base-aware classifier live in :mod:`cognic_agentos.llm.preflight`
(T6) so the classification primitives and the YAML parser stay
co-located. Keeping classification out of this module also avoids
the ``gateway.py → preflight.py → gateway.py`` circular dependency
the Round-1 plan shape carried.

The full ``LLMGateway.completion`` flow lands in T6.

References:
- ``docs/superpowers/plans/2026-04-30-sprint-3-llm-gateway-and-provider-honesty.md``
  Decision-Locking §1 (provider alias semantics: three layers).
- ADR-007 (Provider-Honesty Enforcement).
"""

from __future__ import annotations

from typing import Literal

from cognic_agentos.core.config import Settings

#: Tier vocabulary. Sprint 3 ships two tiers; Sprint 9.5
#: (ADR-013 model registry) may extend.
Tier = Literal["tier1", "tier2"]


class UnknownTierError(ValueError):
    """Raised when :func:`resolve_tier_alias` sees a tier outside
    the :data:`Tier` literal."""


def resolve_tier_alias(tier: str, settings: Settings) -> str:
    """Resolve a tier name to the configured LiteLLM alias.

    Reads ``settings.tier1_alias`` / ``settings.tier2_alias``. Sprint 3
    ships only two tiers; an unknown tier raises
    :class:`UnknownTierError`. The error message lists the known set
    so an operator misconfigured caller does not need to grep the
    source.

    Per Decision-Locking §1: this layer ships only the tier→alias
    translation. The alias→upstream resolution + api_base-aware
    classification happen at the gateway boundary (T6) via
    :class:`cognic_agentos.llm.preflight.PreflightResolver`.

    Args:
        tier: Caller-facing tier name (``"tier1"`` or ``"tier2"``).
        settings: Process settings carrying ``tier1_alias`` and
            ``tier2_alias``.

    Returns:
        The LiteLLM alias (e.g. ``"cognic-tier1-dev"``).

    Raises:
        UnknownTierError: ``tier`` is not in :data:`Tier`. Subclass of
            :class:`ValueError` so generic settings/validation handlers
            still trip on it.
    """
    if tier == "tier1":
        return settings.tier1_alias
    if tier == "tier2":
        return settings.tier2_alias
    raise UnknownTierError(f"unknown tier {tier!r}; expected one of: tier1, tier2")


__all__ = ("Tier", "UnknownTierError", "resolve_tier_alias")
