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
import ipaddress
import os
import re
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml


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


# ===========================================================================
# T6: Classification helpers + PreflightResolver.
# ===========================================================================


class UnknownAliasError(KeyError):
    """Raised by :class:`PreflightResolver.resolve` when ``alias`` is not
    declared in the loaded ``infra/litellm/config.yaml``. Subclass of
    :class:`KeyError` so generic dict-style error handling matches."""


#: Self-hosted model-string prefixes. Only consulted when ``api_base``
#: is unset (otherwise the api_base host is dispositive). Per
#: Decision-Locking §1: anything else fails closed as external.
SELF_HOSTED_MODEL_PREFIXES: tuple[str, ...] = (
    "ollama/",
    "vllm/",
    "sglang/",
    "openai-compat/",
    "local/",
)

#: Known external-cloud host suffixes. If ``api_base`` hostname matches
#: any of these, the upstream is external regardless of model prefix.
#: Per Decision-Locking §1: ``api_base`` is dispositive.
_KNOWN_CLOUD_HOST_SUFFIXES: tuple[str, ...] = (
    "api.openai.com",
    ".openai.azure.com",
    "api.anthropic.com",
    ".bedrock.amazonaws.com",  # bedrock-runtime.<region>.amazonaws.com
    ".bedrock-runtime.amazonaws.com",
    "api.cohere.ai",
    "api.cohere.com",
    ".googleapis.com",
    "generativelanguage.googleapis.com",
)

#: LiteLLM-compatible ``${VAR}`` / ``${VAR:-default}`` substitution
#: pattern. Matches LiteLLM's own substitution shape so the parsed
#: upstream string is identical to what LiteLLM resolves at dispatch.
_ENV_VAR_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}]*))?\}")


def _substitute_env(value: str) -> str:
    """LiteLLM-compatible ``${VAR}`` / ``${VAR:-default}`` substitution.

    Raises :class:`ValueError` if a referenced variable is unset AND
    no default form is provided. Round-3 reviewer-P1#3: substitution
    is **lazy** — called by :class:`PreflightResolver.resolve`, NOT
    by ``from_yaml``, so unused aliases with unset env vars don't
    block resolver construction.
    """

    def replace(match: re.Match[str]) -> str:
        var_name = match.group(1)
        default = match.group(2)
        if var_name in os.environ:
            return os.environ[var_name]
        if default is not None:
            return default
        raise ValueError(
            f"environment variable {var_name!r} required by litellm config but not set"
        )

    return _ENV_VAR_RE.sub(replace, value)


def _is_private_host(host: str) -> bool:
    """Container DNS / RFC1918 / loopback / ``*.local`` /
    ``*.internal`` / ``*.svc``.

    Single-label hostnames (no ``.``) are treated as private — these
    are the docker-compose-style container DNS names like ``vllm``,
    ``ollama``, ``sglang``. Per Decision-Locking §1.
    """
    if not host:
        return False
    if host == "localhost":
        return True
    if host.endswith((".local", ".internal", ".svc", ".svc.cluster.local")):
        return True
    # No-tld single-label name is a docker-compose-style hostname.
    if "." not in host:
        return True
    # IP literals — RFC1918 / loopback / link-local.
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _is_known_cloud_host(host: str) -> bool:
    """``api_base`` host matches a known external-cloud suffix."""
    if not host:
        return False
    return any(host == sfx.lstrip(".") or host.endswith(sfx) for sfx in _KNOWN_CLOUD_HOST_SUFFIXES)


def _is_external(model_string: str, api_base: str | None) -> bool:
    """Cloud-policy classification per Decision-Locking §1 priority order.

    1. ``api_base`` set + host on the known-cloud allow-list → external.
    2. ``api_base`` set + host is private/local → self-hosted.
    3. ``api_base`` set + host unrecognised → external (fail-closed).
    4. ``api_base`` unset + model prefix on self-hosted list → self-hosted.
    5. ``api_base`` unset + unknown prefix → external (fail-closed).

    Round-2 reviewer-P1#2: vLLM/SGLang serving ``model: openai/X``
    against a private api_base must classify as self-hosted (the
    production OpenAI-compat self-hosted shape).
    """
    if api_base is not None:
        host = (urlparse(api_base).hostname or "").lower()
        if _is_known_cloud_host(host):
            return True
        # Spelled out as ``if private: False else True`` rather than
        # ``return not private`` so each branch carries the
        # operator-visible reasoning. ``noqa: SIM103`` covers ruff's
        # offer to inline; the comments on each branch are doctrine,
        # not noise.
        if _is_private_host(host):  # noqa: SIM103
            return False
        return True  # api_base set, host unrecognised → fail-closed external
    # api_base unset — fall back to model prefix.
    if any(model_string.startswith(p) for p in SELF_HOSTED_MODEL_PREFIXES):  # noqa: SIM103
        return False
    return True  # unknown prefix without api_base → fail-closed external


@dataclasses.dataclass(frozen=True, slots=True)
class _RawEntry:
    """Internal — RAW (un-substituted) templates parsed from the YAML.

    Round-3 reviewer-P1#3: ``PreflightResolver.from_yaml`` stores
    these unchanged. ``resolve(alias)`` does the ``${VAR}``
    substitution lazily so unused aliases with unset env vars don't
    block resolver construction in dev/CI environments.
    """

    model_template: str
    api_base_template: str | None


class PreflightResolver:
    """Resolve a LiteLLM alias to an enriched :class:`ResolvedUpstream`.

    Two operations:

    - ``resolve(alias)`` — substitute env vars + classify via
      ``_is_external`` + return a frozen ``ResolvedUpstream``.
    - ``reverse_lookup(model_string)`` — return ALL aliases whose
      resolved ``model_string`` matches. Returns ``tuple[..., ...]``
      so the gateway can detect ambiguous YAML collisions
      (Round-3 reviewer-P1).

    Round-3 reviewer-P1#3: ``from_yaml`` stores RAW templates; the
    substitution happens at ``resolve`` time. This means a dev/CI
    environment with unset production env vars can still load the
    resolver — they only fail if the operator actually tries to
    resolve those production aliases.
    """

    def __init__(self, raw_entries: dict[str, _RawEntry]) -> None:
        self._raw = dict(raw_entries)

    @classmethod
    def from_yaml(cls, path: Path) -> PreflightResolver:
        """Parse the YAML and store RAW templates.

        Defensive against partially-edited YAML: entries missing
        ``model_name`` or ``litellm_params.model`` are skipped, not
        raised on. Operator-friendly behaviour.
        """
        raw = yaml.safe_load(Path(path).read_text())
        model_list: list[dict[str, Any]] = (raw or {}).get("model_list") or []
        entries: dict[str, _RawEntry] = {}
        for entry in model_list:
            alias = entry.get("model_name")
            params = entry.get("litellm_params") or {}
            model_template = params.get("model")
            api_base_template = params.get("api_base")
            if not alias or not model_template:
                continue
            entries[alias] = _RawEntry(
                model_template=model_template,
                api_base_template=api_base_template,
            )
        return cls(entries)

    def resolve(self, alias: str) -> ResolvedUpstream:
        """Resolve ``alias`` to a :class:`ResolvedUpstream`.

        Substitutes env vars NOW (lazy). Raises
        :class:`UnknownAliasError` on unknown alias; raises
        :class:`ValueError` if a required env var is unset and no
        default is declared.
        """
        if alias not in self._raw:
            raise UnknownAliasError(
                f"alias {alias!r} not declared in litellm config; known: {sorted(self._raw)}"
            )
        entry = self._raw[alias]
        model_string = _substitute_env(entry.model_template)
        api_base = _substitute_env(entry.api_base_template) if entry.api_base_template else None
        return ResolvedUpstream(
            alias=alias,
            model_string=model_string,
            api_base=api_base,
            external=_is_external(model_string, api_base),
        )

    def reverse_lookup(self, model_string: str) -> tuple[ResolvedUpstream, ...]:
        """Find ALL aliases whose resolved ``model_string`` matches.

        Returns a tuple — empty when nothing matches, single-entry
        on the common case, multi-entry on the load-bearing
        ambiguity case (Round-3 reviewer-P1): two aliases that share
        the same model_string but differ in api_base /
        classification — e.g. a self-hosted vLLM serving
        ``openai/gpt-4o`` and the real cloud ``openai/gpt-4o``
        declared as separate aliases.

        Returning all matches keeps this primitive free of policy.
        The gateway is the right place to decide what to do with an
        ambiguous match (see ``LLMGateway._build_actual_resolved``).

        Skips aliases whose env vars are unresolvable so reverse-
        lookup of a working dev path doesn't fail because an
        unrelated production alias has unset env vars.
        """
        out: list[ResolvedUpstream] = []
        for alias in self._raw:
            try:
                resolved = self.resolve(alias)
            except ValueError:
                continue  # unresolvable env — skip
            if resolved.model_string == model_string:
                out.append(resolved)
        return tuple(out)

    @property
    def known_aliases(self) -> tuple[str, ...]:
        return tuple(self._raw)


__all__ = (
    "SELF_HOSTED_MODEL_PREFIXES",
    "PreflightResolver",
    "ResolvedUpstream",
    "UnknownAliasError",
    "_is_external",
    "_is_private_host",
)
