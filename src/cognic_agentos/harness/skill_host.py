"""Skill-pack hosting/ingestion + the governed skill-executor builder (M6, ADR-025).

Off-gate composition module (mirrors ``harness/mcp_host.py`` + ``harness/hook_registry.py``).
Walks the ALREADY-TRUSTED registry candidates (trust is upstream — the plugin
registry's cosign gate ran before any candidate is iterable here), re-extracts
each pack's manifest ``[skill].declared_tools`` + ``SKILL.md`` WITHOUT importing
pack code (the ADR-002 §gate 1 deferred-load discipline — ADR-025 D1 forbids the
action ever loading into the kernel process), validates the SKILL.md shape,
cross-checks each declared ``<server_id>/<tool_name>`` against the registered MCP
servers, and yields a :class:`LoadedSkillRecord` per admitted skill.

Per-pack fail-closed: a malformed SKILL.md / malformed ``declared_tools`` /
missing entry-point / unregistered-tool reference warn-skips the pack (logged) —
the boot still succeeds, the bad skill is simply not hosted (invoking it then
404s ``skill_not_found``). Mirrors the M5 mapper doctrine.

This is also home to :class:`_MCPHostCallProxy` — the ``core/skill.SkillCallProxy``
conformer wrapping ``MCPHost.call_tool`` — because ``core/skill`` cannot import
``protocol`` (the ``core -> protocol`` arrow is forbidden; the host is reached
ONLY through the injected seam).
"""

from __future__ import annotations

import importlib.metadata as md
import logging
from typing import TYPE_CHECKING, Any, Protocol

from cognic_agentos.core.skill._types import LoadedSkillRecord
from cognic_agentos.core.skill.executor import SkillExecutor
from cognic_agentos.protocol.mcp_manifest import (
    PackManifestMalformedError,
    PackManifestNotFoundError,
    extract_pack_manifest,
)
from cognic_agentos.protocol.skill_manifest import (
    SkillManifestInvalid,
    SkillManifestNotFound,
    extract_skill_md,
    parse_skill_md,
    validate_skill_md,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate

logger = logging.getLogger(__name__)


class _RegistryCandidates(Protocol):
    """Structural seam — anything exposing the registered-candidate iterator
    (the real ``PluginRegistry`` or a test stub)."""

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]: ...


class _SkillHostSettings(Protocol):
    """Narrow seam — the only ``Settings`` field the host reads (the fallback
    runtime image for a skill pack that does not declare its own)."""

    sandbox_canonical_runtime_python_image: str


class _SkillHostRuntime(Protocol):
    """Narrow seam — the only ``Runtime`` field the host reads (threaded into the
    executor for the ``skill.invoked`` evidence rows). Declared as a read-only
    property so the real ``Runtime`` (whose ``decision_history_store`` is a
    read-only attribute) structurally conforms."""

    @property
    def decision_history_store(self) -> Any: ...


def _skill_block(manifest: dict[str, Any]) -> dict[str, Any] | None:
    """``[skill]`` (canonical) with the legacy ``[tool.cognic.skill]`` fallback
    (dual-path doctrine); ``None`` when absent (non-skill pack)."""
    block = manifest.get("skill")
    if isinstance(block, dict):
        return block
    tool = manifest.get("tool")
    cognic = tool.get("cognic") if isinstance(tool, dict) else None
    legacy = cognic.get("skill") if isinstance(cognic, dict) else None
    return legacy if isinstance(legacy, dict) else None


def _declared_tools(skill_block: dict[str, Any]) -> tuple[str, ...] | None:
    """``[skill].declared_tools`` as a non-empty tuple of well-formed
    ``<server_id>/<tool_name>`` identities; ``None`` on any shape violation
    (missing / not a list / empty / a non-string or malformed entry)."""
    raw = skill_block.get("declared_tools")
    if not isinstance(raw, list) or not raw:
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


def _skill_entry_point_info(distribution_name: str) -> tuple[str | None, str | None]:
    """The distribution's single ``cognic.skills`` entry-point NAME + its version;
    ``(None, None)`` when the distribution is not visible OR does not declare
    exactly one ``cognic.skills`` entry-point (the runner resolves the action by
    entry-point name, so a zero/ambiguous mapping is fail-closed)."""
    try:
        dist = md.distribution(distribution_name)
    except md.PackageNotFoundError:
        return None, None
    eps = [ep for ep in dist.entry_points if ep.group == "cognic.skills"]
    if len(eps) != 1:
        return None, None
    return eps[0].name, dist.version


def _digest_bytes(sig: str | None) -> bytes:
    """Best-effort hex-decode of the registry's ``signature_digest`` (tolerating
    a ``sha256:`` prefix) to the ``LoadedSkillRecord.signed_artefact_digest``
    bytes; ``b""`` when absent/unparseable (the skill runner's own trust anchor
    is its cosign-verified runtime image + the upstream registration, not this
    field — the read_only sandbox tier does not gate on it)."""
    if not sig:
        return b""
    hexpart = sig.split(":", 1)[1] if ":" in sig else sig
    try:
        return bytes.fromhex(hexpart)
    except ValueError:
        return b""


def _registered_mcp_server_ids(registry: _RegistryCandidates) -> frozenset[str]:
    """The set of registered-pack distribution names that declare a
    ``[tool.cognic.mcp]`` block — the authoritative registered-MCP-server id set
    (``server_id`` in the MCP host mapper is the distribution name) the skill
    loader cross-checks ``declared_tools`` against."""
    ids: set[str] = set()
    for cand in registry.iter_registered_pack_candidates():
        try:
            manifest = extract_pack_manifest(
                distribution_name=cand.distribution_name, package_name=cand.package_name
            )
        except (PackManifestNotFoundError, PackManifestMalformedError):
            continue
        tool = manifest.get("tool")
        cognic = tool.get("cognic") if isinstance(tool, dict) else None
        if isinstance(cognic, dict) and isinstance(cognic.get("mcp"), dict):
            ids.add(cand.distribution_name)
    return frozenset(ids)


def _build_skill_records(
    *,
    registry: _RegistryCandidates,
    settings: _SkillHostSettings,
    registered_mcp_servers: frozenset[str],
) -> dict[str, LoadedSkillRecord]:
    """Walk the trusted candidates + admit each valid skill pack to a
    ``{skill_id: LoadedSkillRecord}`` map. Per-pack fail-closed warn-skip."""
    records: dict[str, LoadedSkillRecord] = {}
    for cand in registry.iter_registered_pack_candidates():
        try:
            manifest = extract_pack_manifest(
                distribution_name=cand.distribution_name, package_name=cand.package_name
            )
        except PackManifestNotFoundError:
            continue  # no manifest -> no skill intent -> silent skip
        except PackManifestMalformedError:
            logger.warning(
                "skill.pack_manifest_malformed",
                extra={"distribution_name": cand.distribution_name},
            )
            continue
        block = _skill_block(manifest)
        if block is None:
            continue  # non-skill pack
        declared = _declared_tools(block)
        if declared is None:
            logger.warning(
                "skill.declared_tools_malformed",
                extra={"distribution_name": cand.distribution_name},
            )
            continue
        # Cross-check every declared tool's server against the registered MCP set.
        unresolved = sorted(
            {
                t.partition("/")[0]
                for t in declared
                if t.partition("/")[0] not in registered_mcp_servers
            }
        )
        if unresolved:
            logger.warning(
                "skill.declared_tool_unregistered",
                extra={"distribution_name": cand.distribution_name, "servers": unresolved},
            )
            continue
        try:
            text = extract_skill_md(
                distribution_name=cand.distribution_name, package_name=cand.package_name
            )
        except SkillManifestNotFound:
            logger.warning(
                "skill.skill_md_not_found",
                extra={"distribution_name": cand.distribution_name},
            )
            continue
        try:
            frontmatter, body = parse_skill_md(text)
            validate_skill_md(frontmatter, body=body)
        except SkillManifestInvalid as exc:
            logger.warning(
                "skill.skill_md_invalid",
                extra={"distribution_name": cand.distribution_name, "reason": exc.reason},
            )
            continue
        skill_id = frontmatter["name"]  # validated str
        ep_name, version = _skill_entry_point_info(cand.distribution_name)
        if ep_name is None:
            logger.warning(
                "skill.entry_point_unresolved",
                extra={"distribution_name": cand.distribution_name},
            )
            continue
        raw_image = block.get("runtime_image")
        runtime_image = (
            raw_image
            if isinstance(raw_image, str) and raw_image.strip()
            else settings.sandbox_canonical_runtime_python_image
        )
        if skill_id in records:
            logger.warning(
                "skill.duplicate_skill_id",
                extra={"distribution_name": cand.distribution_name, "skill_id": skill_id},
            )
            continue  # cross-pack skill_id conflict -> fail closed (keep the first)
        records[skill_id] = LoadedSkillRecord(
            skill_id=skill_id,
            entry_point_name=ep_name,
            declared_tools=declared,
            runtime_image=runtime_image,
            registered=True,
            pack_version=version or "",
            signed_artefact_digest=_digest_bytes(cand.signature_digest),
        )
    return records


class _RegistrySkillRecordLoader:
    """``core/skill.SkillRecordLoader`` conformer over a boot-built record map.
    ``load_for_skill`` is a dict lookup by ``skill_id`` (the SKILL.md ``name``);
    the ``tenant_id`` is accepted for the seam contract but skills are hosted
    globally from the registry (tenant governance applies DOWNSTREAM at the broker
    + MCP host), so it does not narrow the lookup."""

    def __init__(self, records: dict[str, LoadedSkillRecord]) -> None:
        self._records = records

    async def load_for_skill(self, *, skill_id: str, tenant_id: str) -> LoadedSkillRecord | None:
        return self._records.get(skill_id)


class _MCPHostCallProxy:
    """``core/skill.SkillCallProxy`` conformer wrapping ``MCPHost.call_tool``.

    Threads the broker's bound tenant/actor + per-call ``request_id`` into the
    host so OAuth / approval / DLP / audit apply automatically downstream, and
    returns the tool result ``payload`` (a JSON-able value the broker frames back
    to the sandboxed action) — never the full ``CallResult`` envelope."""

    def __init__(self, mcp_host: Any) -> None:
        self._host = mcp_host

    async def call(
        self,
        *,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        request_id: str,
        tenant_id: str,
        originator_subject: str,
    ) -> Any:
        result = await self._host.call_tool(
            server_id=server_id,
            tool_name=tool_name,
            arguments=arguments,
            request_id=request_id,
            tenant_id=tenant_id,
            originator_subject=originator_subject,
        )
        return getattr(result, "payload", result)


def build_skill_executor(
    *,
    registry: _RegistryCandidates,
    runtime: _SkillHostRuntime,
    settings: _SkillHostSettings,
    mcp_host: Any,
    sandbox_backend: Any,
) -> tuple[SkillExecutor, list[dict[str, Any]]]:
    """Assemble the production skill executor over the trusted candidates + return
    ``(executor, hosted_skills_summary)``. The summary rows feed the
    ``/api/v1/system/plugins`` ``hosted_skills`` surface. Called on the SDK-present
    lifespan path (the MCP host + sandbox backend must already be constructed)."""
    servers = _registered_mcp_server_ids(registry)
    records = _build_skill_records(
        registry=registry, settings=settings, registered_mcp_servers=servers
    )
    loader = _RegistrySkillRecordLoader(records)
    executor = SkillExecutor(
        sandbox_backend=sandbox_backend,
        skill_loader=loader,
        call_proxy=_MCPHostCallProxy(mcp_host),
        decision_history_store=runtime.decision_history_store,
    )
    hosted = [
        {
            "skill_id": rec.skill_id,
            "entry_point": rec.entry_point_name,
            "declared_tools": list(rec.declared_tools),
            "runtime_image": rec.runtime_image,
            "pack_version": rec.pack_version,
        }
        for rec in records.values()
    ]
    return executor, hosted


__all__ = ["build_skill_executor"]
