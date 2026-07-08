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

M8 A13 adds :func:`build_agent_loop` — the governed-loop composition seam the
``create_app`` lifespan calls (the ``build_skill_executor`` mirror). It owns
the 3-state dependency discipline per
``feedback_conditional_router_mount_partial_config_warning`` (ALL gateable
deps → loop; SOME missing → None + ONE warning naming them; ZERO → None,
quiet) and assembles the A4 stores + the A5 Rego policy + the A10 dispatcher
+ the A11 loop over the boot-hosted agent + instruction-skill records.
"""

from __future__ import annotations

import hashlib
import importlib.metadata as md
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol, cast

from cognic_agentos.core.agent._types import LoadedAgentRecord
from cognic_agentos.core.agent.assignments import AssignmentStore
from cognic_agentos.core.agent.dispatch import AgentDispatcher
from cognic_agentos.core.agent.loop import AgentLoop
from cognic_agentos.core.agent.policy import AgentDispatchPolicy
from cognic_agentos.core.entitlements.store import EntitlementStore
from cognic_agentos.core.policy.engine import OPAEngine
from cognic_agentos.harness.skill_host import (
    _build_skill_records,
    _project_tool_result,
    _registered_mcp_server_ids,
)
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
    import uuid
    from collections.abc import Iterator, Mapping

    from sqlalchemy.ext.asyncio import AsyncEngine

    from cognic_agentos.core.skill._types import LoadedSkillRecord
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


# ---------------------------------------------------------------------------
# M8 A13 (ADR-027) — governed-loop composition
# ---------------------------------------------------------------------------


class _AgentLoopRuntime(Protocol):
    """Narrow seam — the four ``Runtime`` members the loop composition reads.
    Declared as read-only properties so the real frozen-dataclass ``Runtime``
    structurally conforms (the ``_SkillHostRuntime`` precedent)."""

    @property
    def llm_gateway(self) -> Any: ...

    @property
    def memory_api_factory(self) -> Any: ...

    @property
    def audit_store(self) -> Any: ...

    @property
    def decision_history_store(self) -> Any: ...


class _AgentLoopSettings(Protocol):
    """Narrow seam — the ``Settings`` fields the loop composition reads (the
    real ``Settings`` conforms structurally; the skill-record walk inside
    additionally needs the canonical runtime image field)."""

    agents_policy_bundle: Path
    agent_query_context_signing_key_path: str | None
    agent_query_context_ttl_s: float
    agent_max_steps: int
    agent_run_token_budget: int
    agent_run_wall_clock_s: float
    opa_path: str | None
    opa_eval_timeout_s: float
    sandbox_canonical_runtime_python_image: str


class _RegistryAgentRecordLoader:
    """``core/agent.AgentRecordLoader`` conformer over the boot-built record
    map. Hosted agents are PLATFORM-hosted (registry-global, trust-gated
    upstream at registration) — tenant isolation rides the A4 tenant-scoped
    assignment + entitlement stores downstream (an agent with no grants for a
    tenant dispatches nothing), so ``tenant_id`` is accepted for the seam
    contract but does not narrow the lookup (the
    ``_RegistrySkillRecordLoader`` precedent)."""

    def __init__(self, records: dict[str, LoadedAgentRecord]) -> None:
        self._records = records

    async def load_for_agent(self, *, agent_id: str, tenant_id: str) -> LoadedAgentRecord | None:
        return self._records.get(agent_id)


class _InstructionSkillBodyReader:
    """``core/agent.SkillBodyReader`` conformer over the boot-hosted skill
    records — INSTRUCTION-mode records only. An executable-mode record has no
    in-prompt body surface (the M8 lane reads guidance; executing actions is
    the M6 executor's lane), and an unknown id reads as absent — both return
    ``None`` so the ``read_skill`` built-in surfaces a graceful miss."""

    def __init__(self, records: dict[str, LoadedSkillRecord]) -> None:
        self._records = records

    def read(self, skill_id: str) -> tuple[str, str] | None:
        record = self._records.get(skill_id)
        if record is None or record.mode != "instruction" or record.skill_md_body is None:
            return None
        return record.description, record.skill_md_body


class _MCPHostAgentToolProxy:
    """``core/agent.AgentToolProxy`` conformer wrapping ``MCPHost.call_tool``
    (the ``_MCPHostCallProxy`` mirror, including its result→dict projection —
    OAuth / approval / DLP / audit apply automatically downstream in the
    host). ``core/agent`` cannot import ``protocol``; the host is reached
    ONLY through this injected seam."""

    def __init__(self, mcp_host: Any) -> None:
        self._host = mcp_host

    async def call_tool(
        self,
        *,
        server_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        request_id: str,
        tenant_id: str,
        originator_subject: str,
        approval_request_id: uuid.UUID | None,
    ) -> dict[str, Any]:
        result = await self._host.call_tool(
            server_id=server_id,
            tool_name=tool_name,
            arguments=arguments,
            request_id=request_id,
            tenant_id=tenant_id,
            originator_subject=originator_subject,
            approval_request_id=approval_request_id,
        )
        # The projection target is the handler's own dict for every real
        # governed tool (structuredContent / single-JSON-text / model_dump
        # envelope — see _project_tool_result); the cast keeps the seam's
        # declared dict contract under strict mypy while the duck-typed
        # stub-host passthrough arm stays possible (canonical_bytes at the
        # dispatcher's evidence boundary handles either shape).
        return cast("dict[str, Any]", _project_tool_result(getattr(result, "payload", result)))


def _resolve_signing_key(path_value: str | None) -> tuple[bytes | None, list[str]]:
    """Resolve ``Settings.agent_query_context_signing_key_path`` to PEM bytes.

    ``None`` → ``(None, [])`` (no stamped tools deployable — the dispatcher
    fails loud at first stamped mint per ADR-027 §c). A ``vault://`` URI →
    ``(None, [warning])``: the builder's controller-authorized signature has
    no secret-adapter seam, so vault-backed resolution is NOT wired at A13 —
    the explicit warning names the consequence. A plain path →
    ``(Path.read_bytes(), [])``; a read failure propagates to the lifespan's
    fail-soft catch (the loop then stays None — an unreadable key is a
    deployment error, not a silently-unsigned run)."""
    if path_value is None:
        return None, []
    if path_value.startswith("vault://"):
        return None, [
            f"agent_query_context_signing_key_path={path_value!r}: vault:// "
            "signing-key resolution not wired yet — stamped-tool dispatches "
            "will fail loud at mint"
        ]
    return Path(path_value).read_bytes(), []


async def build_agent_loop(
    *,
    runtime: _AgentLoopRuntime,
    settings: _AgentLoopSettings,
    registry: _RegistryCandidates | None,
    mcp_host: Any,
    engine: AsyncEngine,
) -> tuple[AgentLoop | None, list[str], list[dict[str, Any]]]:
    """Assemble the production governed agent loop (M8 A13) over the trusted
    candidates + return ``(loop, warnings, hosted_agents)`` — the third
    element is the :func:`hosted_agents_summary` operator-surface rows for
    ``app.state.hosted_agents`` (read by ``/api/v1/system/plugins`` at
    ``portal/api/system_routes.py``; the ``build_skill_executor`` →
    ``hosted_skills`` mirror).

    3-state dependency discipline per
    ``feedback_conditional_router_mount_partial_config_warning`` over the four
    gateable deps (``registry`` / ``mcp_host`` / ``runtime.llm_gateway`` /
    ``runtime.memory_api_factory``):

      * ALL present → ``(AgentLoop, [], hosted rows)`` (plus at most the
        vault:// signing-key warning — see :func:`_resolve_signing_key`);
      * SOME missing → ``(None, [ONE warning naming the missing deps], [])``;
      * ZERO present → ``(None, [], [])`` — QUIET (nothing agent-shaped was
        ever configured on this deployment; warning would be noise).

    Hosted rows ride ONLY the built path: surfacing an agent as hosted while
    the ask surface 503s would be an operator-facing overclaim (the M6
    posture — ``hosted_skills`` rows and the executor land together).
    """
    missing = [
        name
        for name, present in (
            ("registry", registry is not None),
            ("mcp_host", mcp_host is not None),
            ("llm_gateway", getattr(runtime, "llm_gateway", None) is not None),
            ("memory_api_factory", getattr(runtime, "memory_api_factory", None) is not None),
        )
        if not present
    ]
    if len(missing) == 4:
        return None, [], []  # zero gateable deps — stay quiet.
    if missing:
        return (
            None,
            ["agent loop not built — missing dependencies: " + ", ".join(sorted(missing))],
            [],
        )
    assert registry is not None  # narrowed by the gate above

    # Boot-hosted records: the A8 agent packs + the instruction-mode skill
    # records the read_skill built-in serves bodies from.
    agent_records = _build_agent_records(registry=registry, settings=settings)
    skill_records = _build_skill_records(
        registry=registry,
        settings=settings,
        registered_mcp_servers=_registered_mcp_server_ids(registry),
    )

    # A5 — the agents.rego dispatch bundle over a dedicated OPAEngine (the
    # scheduler-OPA construction mirror at harness/runtime.py).
    agents_opa = await OPAEngine.create(
        bundle_path=settings.agents_policy_bundle,
        audit_store=runtime.audit_store,
        decision_history_store=runtime.decision_history_store,
        opa_path=settings.opa_path,
        eval_timeout_s=settings.opa_eval_timeout_s,
    )

    signing_key_pem, warnings = _resolve_signing_key(settings.agent_query_context_signing_key_path)
    skill_reader = _InstructionSkillBodyReader(skill_records)
    dispatcher = AgentDispatcher(
        entitlements=EntitlementStore(engine),
        policy=AgentDispatchPolicy(opa_engine=agents_opa),
        tool_proxy=_MCPHostAgentToolProxy(mcp_host),
        skill_reader=skill_reader,
        memory_factory=runtime.memory_api_factory,
        decision_history=runtime.decision_history_store,
        query_context_signing_key_pem=signing_key_pem,
        query_context_ttl_s=settings.agent_query_context_ttl_s,
    )
    loop = AgentLoop(
        record_loader=_RegistryAgentRecordLoader(agent_records),
        assignments=AssignmentStore(engine),
        gateway=runtime.llm_gateway,
        dispatcher=dispatcher,
        skill_reader=skill_reader,
        memory_factory=runtime.memory_api_factory,
        decision_history=runtime.decision_history_store,
        default_max_steps=settings.agent_max_steps,
        run_token_budget=settings.agent_run_token_budget,
        run_wall_clock_s=settings.agent_run_wall_clock_s,
        tier="tier1",
    )
    return loop, warnings, hosted_agents_summary(agent_records)


__all__ = ["build_agent_loop", "hosted_agents_summary"]
