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

M8 A7 (ADR-027) — instruction-only mode: ``[skill].mode = "instruction"``
(ABSENT → ``"executable"``, every pre-A7 pack byte-unchanged) hosts the
SKILL.md guidance with NO executable surface — the instruction branch SKIPS
the declared-tools gate, the entry-point gate, the MCP cross-check, and
runtime-image resolution; it warn-skips a pack that declares an executable
surface anyway (``skill.instruction_mode_declares_executable``); the optional
``[skill].referenced_tools`` list is non-authoritative reviewer evidence
(shape violations + unregistered references warn-log ONLY, never a refusal).

This is also home to :class:`_MCPHostCallProxy` — the ``core/skill.SkillCallProxy``
conformer wrapping ``MCPHost.call_tool`` — because ``core/skill`` cannot import
``protocol`` (the ``core -> protocol`` arrow is forbidden; the host is reached
ONLY through the injected seam).
"""

from __future__ import annotations

import importlib.metadata as md
import json
import logging
from typing import TYPE_CHECKING, Any, Literal, Protocol

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


def _skill_mode(skill_block: dict[str, Any]) -> Literal["executable", "instruction"] | None:
    """``[skill].mode`` (M8 A7, ADR-027). ABSENT → ``"executable"`` — every
    pre-A7 skill pack is byte-unchanged. An out-of-vocabulary value → ``None``
    (the loader warn-skips: the pack's intent cannot be determined)."""
    raw = skill_block.get("mode")
    if raw is None:
        return "executable"
    if raw == "executable":
        return "executable"
    if raw == "instruction":
        return "instruction"
    return None


def _referenced_tools(skill_block: dict[str, Any]) -> tuple[str, ...] | None:
    """``[skill].referenced_tools`` (M8 A7 — instruction-mode NON-AUTHORITATIVE
    reviewer evidence). ABSENT → ``()`` (nothing referenced); a well-formed list
    of ``<server_id>/<tool_name>`` identities (empty allowed) → the tuple;
    any shape violation → ``None`` (the loader warn-LOGS and hosts anyway —
    the field grants no authority, so malformation is never a refusal)."""
    raw = skill_block.get("referenced_tools")
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


def _declares_skill_entry_point(distribution_name: str) -> bool:
    """True iff the installed distribution declares ANY ``cognic.skills``
    entry point (M8 A7 — instruction-mode packs must not declare one; unlike
    :func:`_skill_entry_point_info`, an ambiguous 2+ mapping also counts).
    A not-installed distribution declares none."""
    try:
        dist = md.distribution(distribution_name)
    except md.PackageNotFoundError:
        return False
    return any(ep.group == "cognic.skills" for ep in dist.entry_points)


def _distribution_version(distribution_name: str) -> str | None:
    """The installed distribution's version; ``None`` when not visible
    (instruction-mode packs have no entry point to ride the version lookup
    in :func:`_skill_entry_point_info`, so they resolve it directly)."""
    try:
        return md.distribution(distribution_name).version
    except md.PackageNotFoundError:
        return None


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
        mode = _skill_mode(block)
        if mode is None:
            logger.warning(
                "skill.mode_invalid",
                extra={
                    "distribution_name": cand.distribution_name,
                    "declared_mode": block.get("mode"),
                },
            )
            continue
        if mode == "instruction":
            # M8 A7 (ADR-027) — instruction-only mode: host the SKILL.md
            # guidance with NO executable surface. SKIPS the declared-tools
            # gate, the entry-point gate, the MCP cross-check, and
            # runtime-image resolution. A pack that declares an executable
            # surface anyway is an author error → warn-skip (fail closed).
            if block.get("declared_tools"):
                logger.warning(
                    "skill.instruction_mode_declares_executable",
                    extra={
                        "distribution_name": cand.distribution_name,
                        "surface": "declared_tools",
                    },
                )
                continue
            if _declares_skill_entry_point(cand.distribution_name):
                logger.warning(
                    "skill.instruction_mode_declares_executable",
                    extra={
                        "distribution_name": cand.distribution_name,
                        "surface": "entry_point",
                    },
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
            # referenced_tools is NON-AUTHORITATIVE reviewer evidence — shape
            # violations + unregistered-server references warn-log ONLY (the
            # field grants no authority; the broker never sees it).
            referenced = _referenced_tools(block)
            if referenced is None:
                logger.warning(
                    "skill.referenced_tools_malformed",
                    extra={"distribution_name": cand.distribution_name},
                )
                referenced = ()
            unresolved_refs = sorted(
                {
                    t.partition("/")[0]
                    for t in referenced
                    if t.partition("/")[0] not in registered_mcp_servers
                }
            )
            if unresolved_refs:
                logger.warning(
                    "skill.referenced_tool_unregistered",
                    extra={
                        "distribution_name": cand.distribution_name,
                        "servers": unresolved_refs,
                    },
                )
            if skill_id in records:
                logger.warning(
                    "skill.duplicate_skill_id",
                    extra={"distribution_name": cand.distribution_name, "skill_id": skill_id},
                )
                continue  # cross-pack skill_id conflict -> fail closed (keep the first)
            records[skill_id] = LoadedSkillRecord(
                skill_id=skill_id,
                mode="instruction",
                description=frontmatter["description"],
                skill_md_body=body,
                registered=True,
                pack_version=_distribution_version(cand.distribution_name) or "",
                signed_artefact_digest=_digest_bytes(cand.signature_digest),
            )
            continue
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


class MCPToolResultError(Exception):
    """Downstream MCP tool completed the wire call but flagged a tool-level
    error (``CallToolResult.isError``) — M6 run-16 finding #17a, fail-closed.

    Raised BEFORE projection so the failure surfaces through the broker's
    downstream-failure arm (in-band ``skill_tool_invocation_failed`` + the
    finding-#16 WARNING) instead of masquerading as a success result the
    action's defensive extractors would quietly reduce to an empty summary.
    The message NEVER carries the tool's content text (it may hold SQL
    fragments / customer data — the broker hashes unknown-exception detail,
    but the invariant holds at the raise site, not one layer up); ``reason``
    is the short closed marker the broker WARNING surfaces as
    ``downstream_reason``."""

    reason = "mcp_tool_result_is_error"

    def __init__(self) -> None:
        super().__init__("downstream MCP tool result carries isError=true")


def _project_tool_result(payload: Any) -> Any:
    """Project an mcp SDK ``CallToolResult`` to the JSON-frameable tool-level
    result the broker's wire contract requires (M6 run-16 finding #17a).

    The broker frames the proxied result with stdlib ``json.dumps``
    (``sdk/skill_transport.encode_frame``); an mcp SDK ``CallToolResult`` is
    a pydantic model and not JSON-able, so returning it raw kills EVERY real
    governed tool call in-band at the broker's result-frame arm. ADR-025's
    contract ("returns only the tool result"; wire arm ``{"ok": true,
    "result": { ... }}``) and the SDK ``ToolRegistry`` convention the pack
    authors write against (``await tool.invoke(**kwargs) -> dict`` — the
    handler's own dict) pin the projection target. Recovery order:

    1. ``isError`` true -> raise :class:`MCPToolResultError` (fail-closed;
       a tool-level error is not a result).
    2. ``structuredContent`` dict -> return it (the authoritative, schema'd
       realization of the handler dict).
    3. exactly ONE text content block whose text parses to a JSON object ->
       return that dict (the FastMCP bare ``-> dict`` realization: mcp
       1.27.0 generates NO output schema for a bare ``dict`` annotation, so
       the handler dict rides only as JSON text — the live oracle-pack
       case).
    4. otherwise the ``model_dump(mode="json", by_alias=True,
       exclude_none=True)`` envelope — honest fallback, still frameable.
    5. non-model payloads (no ``model_dump``) pass through unchanged (plain
       JSON data from stub hosts / future hosts).

    Duck-typed on purpose: this off-gate builder module must stay importable
    without the optional ``mcp`` SDK extra (the tests drive REAL
    ``mcp.types`` objects through it)."""
    if getattr(payload, "isError", False) or getattr(payload, "is_error", False):
        raise MCPToolResultError()
    dump = getattr(payload, "model_dump", None)
    if dump is None:
        return payload
    structured = getattr(payload, "structuredContent", None)
    if structured is None:
        structured = getattr(payload, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    content = getattr(payload, "content", None)
    if isinstance(content, list) and len(content) == 1:
        block = content[0]
        text = getattr(block, "text", None)
        if getattr(block, "type", None) == "text" and isinstance(text, str):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                return parsed
    return dump(mode="json", by_alias=True, exclude_none=True)


class _MCPHostCallProxy:
    """``core/skill.SkillCallProxy`` conformer wrapping ``MCPHost.call_tool``.

    Threads the broker's bound tenant/actor + per-call ``request_id`` into the
    host so OAuth / approval / DLP / audit apply automatically downstream, and
    returns the tool result projected to a JSON-able value the broker frames
    back to the sandboxed action (:func:`_project_tool_result`) — never the
    full ``CallResult`` envelope, never a raw mcp SDK pydantic model."""

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
        return _project_tool_result(getattr(result, "payload", result))


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
