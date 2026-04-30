"""Preflight resolution primitives for the LLM gateway (Sprint 3).

Layer classification: **platform primitive** (critical control per
AGENTS.md — provider-honesty ledger feed).

T3 ships only the :class:`ResolvedUpstream` dataclass. T6 extends this
module with:

- ``_is_external(model_string, api_base)`` — api_base-aware classifier
  per Round-2 reviewer-P1#2.
- ``SELF_HOSTED_MODEL_PREFIXES`` + ``_KNOWN_CLOUD_HOST_SUFFIXES`` +
  ``_is_private_host`` — the classification helpers.
- ``UnknownAliasError`` + :class:`PreflightResolver` — YAML parser +
  ``resolve(alias) -> ResolvedUpstream`` + ``reverse_lookup(model_string)
  -> tuple[ResolvedUpstream, ...]`` (Round-3 reviewer-P1).

Splitting the dataclass out of the resolver keeps the type importable
by :mod:`cognic_agentos.llm.policy` (T3) without forcing the whole
preflight surface forward to T3 time. The dataclass shape is locked by
the plan's Decision-Locking §1 contract; T6 adds construction logic
around it without changing the shape.

References:
- ``docs/superpowers/plans/2026-04-30-sprint-3-llm-gateway-and-provider-honesty.md``
  Decision-Locking §1 (provider alias semantics: three layers +
  ``ResolvedUpstream`` + four-state provenance).
- ADR-007 (Provider-Honesty Enforcement).
"""

from __future__ import annotations

import dataclasses
from typing import Literal


@dataclasses.dataclass(frozen=True, slots=True)
class ResolvedUpstream:
    """Enriched upstream identity used by the cloud-policy enforcer.

    All fields are post-substitution (resolved at the YAML parser's
    ``resolve()`` call site, T6). Round-2 reviewer-P1#2 baked in:
    ``external`` reflects the api_base-aware classification, NOT a
    bare model-prefix check (so vLLM/SGLang serving ``model: openai/X``
    against a private api_base classify as self-hosted, the canonical
    production OpenAI-compat self-hosted shape).

    Round-4 + Round-5 + Round-6 reviewer-P1: ``provenance`` carries
    the provenance state. ``"resolved"`` is the unambiguous case
    (single reverse_lookup match OR no reverse-lookup needed in the
    pre-call resolve path). ``"unresolved"`` covers zero
    reverse_lookup matches AND LiteLLM responses with missing/invalid
    ``model`` fields. ``"ambiguous"`` covers multiple reverse_lookup
    matches with disagreeing classifications (the OpenAI-compat
    self-hosted vs cloud-OpenAI YAML-collision case).

    :func:`cognic_agentos.llm.policy.enforce_cloud_policy` denies
    UNCONDITIONALLY when ``provenance != "resolved"`` — even with
    ``allow_external_llm=True`` and the surface provider on
    ``allowed_providers`` — because we genuinely cannot prove which
    upstream LiteLLM dispatched against, and provenance is the
    bedrock of ADR-007.

    Attributes:
        alias: The LiteLLM alias that produced this resolution.
        model_string: Post-``${VAR}``-substitution model identifier.
            On the unresolved-missing-field path the gateway populates
            ``"<missing>"`` so the ledger row carries a non-empty
            string the operator can recognise.
        api_base: Post-substitution api_base (if declared in YAML).
            ``None`` when (a) the YAML didn't declare one, OR (b) the
            gateway built a fail-closed ResolvedUpstream on the
            unresolved/ambiguous paths and refused to claim a
            preflight api_base it can't verify.
        external: The api_base-aware classification (priority order
            in T6's ``_is_external``: api_base on cloud-host allow-list
            → external; private/loopback host → self-hosted; api_base
            unset → fall back to model prefix).
        provenance: One of ``"resolved" | "unresolved" | "ambiguous"``.
            Defaults to ``"resolved"`` since most resolution paths
            produce an unambiguous result; fail-closed paths set the
            other values explicitly.
    """

    alias: str
    model_string: str
    api_base: str | None
    external: bool
    provenance: Literal["resolved", "unresolved", "ambiguous"] = "resolved"

    def provider(self) -> str | None:
        """Extract the provider prefix from ``model_string``.

        Used by :func:`cognic_agentos.llm.policy.enforce_cloud_policy`
        to check the :class:`Settings.allowed_providers` allow-list.
        Returns ``None`` for empty strings or strings that start with
        a slash so the allow-list check denies the call (fail-closed).
        Returns the whole string when there's no slash so unknown
        shapes (no provider declared) deny by default unless the
        operator explicitly allow-listed that string.
        """
        head, _, _ = self.model_string.partition("/")
        return head or None


__all__ = ("ResolvedUpstream",)
