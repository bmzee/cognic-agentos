"""Agent-pack hosting/ingestion (M8 A8, ADR-027).

Off-gate composition module (mirrors ``harness/skill_host.py`` +
``harness/mcp_host.py``). Walks the ALREADY-TRUSTED registry candidates (trust
is upstream — the plugin registry's cosign gate ran before any candidate is
iterable here), re-extracts each pack's manifest ``[agent]`` block + ``AGENT.md``
WITHOUT importing pack code (the ADR-002 §gate 1 deferred-load discipline —
agent-pack Python NEVER loads into the kernel process), validates the persona
shape via the REUSED skill_manifest frontmatter contract, reads the requested
capability lists + ``max_steps`` + the MANDATORY risk tier, and yields a
:class:`LoadedAgentRecord` per admitted agent.

Per-pack fail-closed: a malformed manifest / missing-or-invalid AGENT.md /
malformed requested lists / invalid max_steps / MISSING RISK TIER warn-skips
the pack (logged) — the boot still succeeds, the bad agent is simply not
hosted. Mirrors the M5 mapper doctrine. The risk-tier skip is deliberately
fail-closed: a record without a tier cannot be dispatched (the A5+ loop
admits by tier), so hosting it would defer the failure to run time.

NO ``build_agent_loop`` here — the governed loop composition is A13; A8 ships
the record loader + the ``hosted_agents`` operator-surface summary rows only.
"""

from __future__ import annotations

import hashlib
import importlib.metadata as md
import logging
from typing import TYPE_CHECKING, Any, Protocol

from cognic_agentos.core.agent._types import LoadedAgentRecord
from cognic_agentos.protocol.agent_manifest import (
    AgentManifestNotFound,
    SkillManifestInvalid,
    extract_agent_md,
    parse_skill_md,
    validate_skill_md,
)
from cognic_agentos.protocol.mcp_manifest import (
    PackManifestMalformedError,
    PackManifestNotFoundError,
    extract_pack_manifest,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate

logger = logging.getLogger(__name__)

#: ``max_steps`` closed bounds (ADR-027 — mirrors the build-time validator at
#: ``cli/validators/agents.py``; drift between the two is a build-hosts-what-
#: runtime-refuses bug class, pinned test-side).
_MAX_STEPS_MIN = 1
_MAX_STEPS_MAX = 32


class _RegistryCandidates(Protocol):
    """Structural seam — anything exposing the registered-candidate iterator
    (the real ``PluginRegistry`` or a test stub)."""

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]: ...


def _agent_block(manifest: dict[str, Any]) -> dict[str, Any] | None:
    """``[agent]`` (canonical) with the legacy ``[tool.cognic.agent]`` fallback
    (dual-path doctrine); ``None`` when absent (non-agent pack)."""
    block = manifest.get("agent")
    if isinstance(block, dict):
        return block
    tool = manifest.get("tool")
    cognic = tool.get("cognic") if isinstance(tool, dict) else None
    legacy = cognic.get("agent") if isinstance(cognic, dict) else None
    return legacy if isinstance(legacy, dict) else None


def _risk_tier(manifest: dict[str, Any]) -> str | None:
    """The pack's declared risk tier — canonical ``[risk_tier].tier`` first,
    then the legacy ``[tool.cognic.runtime].risk_tier`` shape (the same
    legacy mapping ``cli/validate._resolves_in_legacy_path`` honours);
    ``None`` when absent / non-string / blank (the loader warn-skips —
    fail closed, a record without a tier cannot be dispatched)."""
    rt = manifest.get("risk_tier")
    if isinstance(rt, dict):
        tier = rt.get("tier")
        if isinstance(tier, str) and tier.strip():
            return tier
    tool = manifest.get("tool")
    cognic = tool.get("cognic") if isinstance(tool, dict) else None
    runtime = cognic.get("runtime") if isinstance(cognic, dict) else None
    tier = runtime.get("risk_tier") if isinstance(runtime, dict) else None
    return tier if isinstance(tier, str) and tier.strip() else None


def _requested_skills(block: dict[str, Any]) -> tuple[str, ...] | None:
    """``[agent].requested_skills`` as a tuple of non-empty strings; ABSENT →
    ``()`` (an agent may request no skills); ``None`` on any shape violation."""
    raw = block.get("requested_skills")
    if raw is None:
        return ()
    if not isinstance(raw, list):
        return None
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            return None
        out.append(item)
    return tuple(out)


def _requested_tools(block: dict[str, Any]) -> tuple[str, ...] | None:
    """``[agent].requested_tools`` as a tuple of well-formed
    ``<server_id>/<tool_name>`` identities (the first-``/``-partition rule);
    ABSENT → ``()``; ``None`` on any shape violation."""
    raw = block.get("requested_tools")
    if raw is None:
        return ()
    if not isinstance(raw, list):
        return None
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            return None
        server_id, _, tool_name = item.partition("/")
        if not server_id or not tool_name:
            return None
        out.append(item)
    return tuple(out)


class _MaxStepsInvalid(Exception):
    """Module-private: an out-of-bounds / mistyped ``max_steps`` value."""


def _max_steps(block: dict[str, Any]) -> int | None:
    """``[agent].max_steps`` — ABSENT → ``None`` (the loop's kernel default);
    an int in 1..32 → the value; anything else (incl. ``bool``) raises
    :class:`_MaxStepsInvalid` so the loader warn-skips."""
    raw = block.get("max_steps")
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise _MaxStepsInvalid(repr(raw))
    if not isinstance(raw, int):
        raise _MaxStepsInvalid(repr(raw))
    if not (_MAX_STEPS_MIN <= raw <= _MAX_STEPS_MAX):
        raise _MaxStepsInvalid(repr(raw))
    return raw


def _distribution_version(distribution_name: str) -> str | None:
    """The installed distribution's version; ``None`` when not visible."""
    try:
        return md.distribution(distribution_name).version
    except md.PackageNotFoundError:
        return None


def _build_agent_records(
    *,
    registry: _RegistryCandidates,
    settings: object,
) -> dict[str, LoadedAgentRecord]:
    """Walk the trusted candidates + admit each valid agent pack to an
    ``{agent_id: LoadedAgentRecord}`` map. Per-pack fail-closed warn-skip.

    ``settings`` is accepted for seam parity with ``_build_skill_records``
    (the A13 loop composition threads the real ``Settings``); A8 reads no
    field from it."""
    del settings  # reserved for the A13 loop composition — no A8 field read.
    records: dict[str, LoadedAgentRecord] = {}
    for cand in registry.iter_registered_pack_candidates():
        try:
            manifest = extract_pack_manifest(
                distribution_name=cand.distribution_name, package_name=cand.package_name
            )
        except PackManifestNotFoundError:
            continue  # no manifest -> no agent intent -> silent skip
        except PackManifestMalformedError:
            logger.warning(
                "agent.pack_manifest_malformed",
                extra={"distribution_name": cand.distribution_name},
            )
            continue
        block = _agent_block(manifest)
        if block is None:
            continue  # non-agent pack
        try:
            text = extract_agent_md(
                distribution_name=cand.distribution_name, package_name=cand.package_name
            )
        except AgentManifestNotFound:
            logger.warning(
                "agent.agent_md_not_found",
                extra={"distribution_name": cand.distribution_name},
            )
            continue
        try:
            frontmatter, body = parse_skill_md(text)
            validate_skill_md(frontmatter, body=body)
        except SkillManifestInvalid as exc:
            logger.warning(
                "agent.agent_md_invalid",
                extra={"distribution_name": cand.distribution_name, "reason": exc.reason},
            )
            continue
        agent_id = frontmatter["name"]  # validated str
        requested_skills = _requested_skills(block)
        if requested_skills is None:
            logger.warning(
                "agent.requested_skills_malformed",
                extra={"distribution_name": cand.distribution_name},
            )
            continue
        requested_tools = _requested_tools(block)
        if requested_tools is None:
            logger.warning(
                "agent.requested_tools_malformed",
                extra={"distribution_name": cand.distribution_name},
            )
            continue
        try:
            max_steps = _max_steps(block)
        except _MaxStepsInvalid:
            logger.warning(
                "agent.max_steps_invalid",
                extra={"distribution_name": cand.distribution_name},
            )
            continue
        risk_tier = _risk_tier(manifest)
        if risk_tier is None:
            # Fail closed: the A5+ loop admits by tier; a tier-less record
            # could never be dispatched — refuse it at ingest, not run time.
            logger.warning(
                "agent.risk_tier_missing",
                extra={"distribution_name": cand.distribution_name},
            )
            continue
        if agent_id in records:
            logger.warning(
                "agent.duplicate_agent_id",
                extra={"distribution_name": cand.distribution_name, "agent_id": agent_id},
            )
            continue  # cross-pack agent_id conflict -> fail closed (keep the first)
        records[agent_id] = LoadedAgentRecord(
            agent_id=agent_id,
            persona_body=body,
            persona_sha256=hashlib.sha256(body.encode("utf-8")).hexdigest(),
            requested_skills=requested_skills,
            requested_tools=requested_tools,
            max_steps=max_steps,
            risk_tier=risk_tier,
            pack_version=_distribution_version(cand.distribution_name) or "",
            signed_artefact_digest=cand.signature_digest,
            registered=True,
        )
    return records


def hosted_agents_summary(records: dict[str, LoadedAgentRecord]) -> list[dict[str, Any]]:
    """Project the admitted records onto the ``/api/v1/system/plugins``
    ``hosted_agents`` operator-surface rows (the ``hosted_skills`` mirror —
    the A13 lifespan attaches these to ``app.state.hosted_agents``). The
    persona body/digest deliberately do NOT ride the operator surface."""
    return [
        {
            "agent_id": rec.agent_id,
            "requested_skills": list(rec.requested_skills),
            "requested_tools": list(rec.requested_tools),
            "max_steps": rec.max_steps,
            "risk_tier": rec.risk_tier,
            "pack_version": rec.pack_version,
        }
        for rec in records.values()
    ]


__all__ = ["hosted_agents_summary"]
