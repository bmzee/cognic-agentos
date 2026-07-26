"""``build_agent_loop`` production-composition conformance.

Scope statement for the package lives in
:mod:`tests.integration.agent_loop.test_kernel_conformance`; read it before
citing anything here. What THIS module adds beyond the pack-load foundation:

PROVEN — the REAL production entry point ``harness.agent_host.build_agent_loop``
is called and its 3-state dependency discipline exercised end to end (ALL
present / SOME missing / ZERO present). Real throughout: the Alembic-migrated
database, ``AuditStore`` and ``DecisionHistoryStore`` over it, the ``OPAEngine``
against the shipped ``policies/_default/agents.rego`` (its syntax check runs at
construction with the real ``opa`` binary), the returned ``AgentLoop``, and the
``hosted_agents_summary`` operator projection.

SUBSTITUTED, additionally to the package-level seams:

* ``runtime`` and ``settings`` are ``_AgentLoopRuntime`` / ``_AgentLoopSettings``
  conformers, not the frozen ``Runtime`` / real ``Settings``. Field names and
  types mirror the Protocols exactly, so a Protocol change fails type-check
  here — but the real objects' own construction is not exercised;
* ``llm_gateway`` is a ``ScriptedGateway``; ``mcp_host`` and
  ``memory_api_factory`` are opaque sentinels. This module COMPOSES the loop
  and never runs it, so neither is reached.

REQUIRES ``opa`` on PATH. ``LoopSettings.opa_path`` resolves via
``shutil.which``; with opa absent, composition raises ``OpaNotInstalledError``
at the policy-engine constructor rather than silently degrading.

NOT YET PROVEN by this module: dispatch. No ``ask()`` call, therefore no
assignment/entitlement/policy gate, no refusal feedback, and no dispatch
evidence. That is the next packet.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

import cognic_agentos.harness.agent_host as agent_host
from cognic_agentos.core.agent.loop import AgentLoop
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.decision_history import DecisionHistoryStore

from ._synthetic import (
    DEFAULT_AGENT_ID,
    DEFAULT_DIST,
    DEFAULT_PACKAGE,
    DEFAULT_VERSION,
    FakeDist,
    LoopRuntime,
    LoopSettings,
    Registry,
    ScriptedGateway,
    candidate,
    pack_record_files,
    write_agent_pack,
)

_SENTINEL = object()


def _install_pack(dists: list[Any], tmp_path: Path, **kwargs: Any) -> None:
    root = tmp_path / "site-packages"
    package = kwargs.pop("package", DEFAULT_PACKAGE)
    write_agent_pack(root, package=package, **kwargs)
    dists.append(
        FakeDist(
            name=DEFAULT_DIST,
            version=DEFAULT_VERSION,
            root=root,
            files=pack_record_files(package),
        )
    )


def _runtime(engine: AsyncEngine, **overrides: Any) -> LoopRuntime:
    """A fully-configured runtime; override a member with ``None`` to drop a dep.

    ``audit_store`` and ``decision_history_store`` are the REAL hash-chained
    stores over the migrated engine — the policy engine writes evidence through
    them during composition, and the dispatch packet reads that chain back.
    """
    base: dict[str, Any] = {
        "llm_gateway": ScriptedGateway(),
        "memory_api_factory": _SENTINEL,
        "audit_store": AuditStore(engine),
        "decision_history_store": DecisionHistoryStore(engine),
    }
    base.update(overrides)
    return LoopRuntime(**base)


class TestDependencyDiscipline:
    """The 3-state gate at ``agent_host.py:573`` is an operator-facing contract:
    a deployment with nothing agent-shaped must stay QUIET, while a
    half-configured one must say exactly what is missing. Getting this backwards
    either floods logs on every gateway-only deployment or hides a
    misconfiguration behind silence.
    """

    async def test_zero_gateable_deps_is_quiet(self, engine: AsyncEngine) -> None:
        loop, warnings, hosted = await agent_host.build_agent_loop(
            runtime=_runtime(engine, llm_gateway=None, memory_api_factory=None),
            settings=LoopSettings(),
            registry=None,
            mcp_host=None,
            engine=engine,
        )

        assert loop is None
        assert warnings == [], "a deployment with no agent surface must not warn"
        assert hosted == []

    async def test_partial_config_warns_once_naming_every_missing_dep(
        self, engine: AsyncEngine
    ) -> None:
        loop, warnings, hosted = await agent_host.build_agent_loop(
            runtime=_runtime(engine, memory_api_factory=None),
            settings=LoopSettings(),
            registry=Registry([candidate()]),
            mcp_host=None,
            engine=engine,
        )

        assert loop is None
        assert hosted == [], "hosted rows must never surface without a built loop"
        # EXACTLY one warning, naming BOTH missing deps — one-warning-per-dep
        # would be noise, and naming only the first would send an operator
        # round the loop twice.
        assert len(warnings) == 1
        assert "mcp_host" in warnings[0]
        assert "memory_api_factory" in warnings[0]
        assert "llm_gateway" not in warnings[0]
        assert "registry" not in warnings[0]

    async def test_all_deps_present_builds_the_real_loop_and_hosts_the_agent(
        self, engine: AsyncEngine, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        _install_pack(metadata_env, tmp_path)

        loop, warnings, hosted = await agent_host.build_agent_loop(
            runtime=_runtime(engine),
            settings=LoopSettings(),
            registry=Registry([candidate()]),
            mcp_host=_SENTINEL,
            engine=engine,
        )

        assert isinstance(loop, AgentLoop), "must return the REAL AgentLoop"
        assert warnings == []

        # Hosted rows ride ONLY the built path — surfacing an agent as hosted
        # while /ask 503s would be an operator-facing overclaim.
        assert [row["agent_id"] for row in hosted] == [DEFAULT_AGENT_ID]

    async def test_hosted_rows_never_surface_without_a_loop(
        self, engine: AsyncEngine, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        """The pack is admissible, but a dep is missing — hosted rows must still
        be empty. This is the arm that would silently overclaim if the hosted
        projection were computed before the dependency gate."""
        _install_pack(metadata_env, tmp_path)

        loop, warnings, hosted = await agent_host.build_agent_loop(
            runtime=_runtime(engine, llm_gateway=None),
            settings=LoopSettings(),
            registry=Registry([candidate()]),
            mcp_host=_SENTINEL,
            engine=engine,
        )

        assert loop is None
        assert hosted == []
        assert len(warnings) == 1 and "llm_gateway" in warnings[0]


class TestComposedLoopWiring:
    """The built loop must carry the REAL collaborators, not defaults."""

    @pytest.fixture
    async def built(
        self, engine: AsyncEngine, metadata_env: list[Any], tmp_path: Path
    ) -> tuple[AgentLoop, ScriptedGateway]:
        _install_pack(metadata_env, tmp_path)
        gateway = ScriptedGateway()
        loop, warnings, _ = await agent_host.build_agent_loop(
            runtime=_runtime(engine, llm_gateway=gateway),
            settings=LoopSettings(agent_max_steps=7, agent_run_token_budget=1234),
            registry=Registry([candidate()]),
            mcp_host=_SENTINEL,
            engine=engine,
        )
        assert isinstance(loop, AgentLoop) and warnings == []
        return loop, gateway

    async def test_settings_are_threaded_into_the_loop(
        self, built: tuple[AgentLoop, ScriptedGateway]
    ) -> None:
        """Bounds come from Settings, not from AgentLoop's own defaults — a
        deployment that tightens max_steps must actually tighten it."""
        loop, _ = built
        assert loop._default_max_steps == 7
        assert loop._run_token_budget == 1234

    async def test_gateway_is_the_injected_instance(
        self, built: tuple[AgentLoop, ScriptedGateway]
    ) -> None:
        loop, gateway = built
        # ScriptedGateway is a STRUCTURAL stand-in, not an LLMGateway subclass,
        # so compare as plain objects: the assertion is about identity (the
        # injected instance survived composition), not nominal type.
        assert cast(object, loop._gateway) is gateway

    async def test_record_loader_resolves_the_synthetic_agent(
        self, built: tuple[AgentLoop, ScriptedGateway]
    ) -> None:
        """The loop's record loader is bound to the boot-built records, so the
        agent the composition hosted is the agent the loop can resolve."""
        loop, _ = built
        record = await loop._record_loader.load_for_agent(agent_id=DEFAULT_AGENT_ID, tenant_id="t1")
        assert record is not None
        assert record.agent_id == DEFAULT_AGENT_ID
        assert record.registered is True

    async def test_unknown_agent_resolves_to_none(
        self, built: tuple[AgentLoop, ScriptedGateway]
    ) -> None:
        loop, _ = built
        assert await loop._record_loader.load_for_agent(agent_id="nope", tenant_id="t1") is None
