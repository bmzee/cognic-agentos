"""``build_agent_loop`` production-composition conformance.

Read the package scope statement before citing this module.

PROVEN:

* the real ``harness.agent_host.build_agent_loop`` entry point implements the
  ZERO/SOME/ALL dependency discipline, including exact partial-config warning
  text and the invariant that hosted rows never appear without a loop;
* the ALL path returns a real ``AgentLoop`` whose Assignment, Entitlement,
  AgentDispatchPolicy, OPA, AuditStore, DecisionHistoryStore, and gateway
  collaborators are pinned by type and/or object identity to the instances
  composed over the migrated database;
* the OPA engine loads the current ``policies/_default/agents.rego`` bytes and
  writes exactly one ``policy.bundle_loaded`` row carrying that path and digest;
* ``hosted_agents_summary`` exposes the exact six-key operator projection and
  excludes persona body/digest;
* the tested kernel default/budget/clock values and the pack-authored
  ``max_steps`` are stored on their respective composed objects. Ask-time
  precedence and bound enforcement are not claimed by this composition-only
  module.

SUBSTITUTED, additionally to the package-level seams:

* ``runtime`` and ``settings`` are ``_AgentLoopRuntime`` / ``_AgentLoopSettings``
  conformers, not the frozen ``Runtime`` / real ``Settings``. Focused
  assertions pin the values used here; real object construction and an
  exhaustive future Protocol/type-drift guarantee are not claimed;
* ``llm_gateway`` is a ``ScriptedGateway``; ``mcp_host`` and
  ``memory_api_factory`` are opaque sentinels. This module COMPOSES the loop
  and never runs it, so neither is reached.

OPA: ``OPAEngine`` resolves ``opa_path or shutil.which("opa")`` and, when that
is ``None``, skips construction-time syntax validation and logs one warning.
Tests whose claim depends on real OPA carry ``@opa_required``; the absent-OPA
test pins both that log and the distinct empty builder-warning list.

NOT PROVEN HERE: a dispatch decision. The sibling dispatch module owns that
coverage; composition alone proves loading/wiring, never policy evaluation.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

import cognic_agentos.harness.agent_host as agent_host
from cognic_agentos.core.agent.assignments import AssignmentStore
from cognic_agentos.core.agent.loop import AgentLoop
from cognic_agentos.core.agent.policy import AgentDispatchPolicy
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history
from cognic_agentos.core.entitlements.store import EntitlementStore
from cognic_agentos.core.policy.engine import OPAEngine, RegoBundleInvalidError

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
    write_agent_pack,
)

_SENTINEL = object()

opa_required = pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not installed")

_BROKEN_REGO = "package cognic.agents.dispatch\n\nthis is not valid rego {{{\n"


class TestOpaBundleValidationArms:
    """Both arms of ``OPAEngine``'s construction-time bundle check.

    A VALID bundle cannot distinguish "validation ran" from "validation was
    skipped" — both look identical. These tests use a deliberately BROKEN
    bundle so the two arms are separable.
    """

    @opa_required
    async def test_invalid_bundle_is_refused_at_construction(
        self, engine: AsyncEngine, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        """With opa resolvable, a malformed bundle must fail composition —
        this is what proves the syntax check actually executes."""
        _install_pack(metadata_env, tmp_path)
        bad = tmp_path / "broken.rego"
        bad.write_text(_BROKEN_REGO, encoding="utf-8")

        with pytest.raises(RegoBundleInvalidError):
            await agent_host.build_agent_loop(
                runtime=_runtime(engine),
                settings=LoopSettings(agents_policy_bundle=bad),
                registry=Registry([candidate()]),
                mcp_host=_SENTINEL,
                engine=engine,
            )

    async def test_absent_opa_defers_validation_and_logs_warning(
        self,
        engine: AsyncEngine,
        metadata_env: list[Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """With opa UNRESOLVABLE the same malformed bundle composes fine.

        ``OPAEngine`` resolves ``opa_path or shutil.which("opa")``, so
        ``opa_path=None`` alone is NOT enough — the engine re-resolves from
        PATH. The engine module's ``shutil.which`` must be patched too. The
        operational warning and the builder's return-list warning are separate
        surfaces and are asserted separately.
        """
        _install_pack(metadata_env, tmp_path)
        bad = tmp_path / "broken.rego"
        bad.write_text(_BROKEN_REGO, encoding="utf-8")
        monkeypatch.setattr("cognic_agentos.core.policy.engine.shutil.which", lambda _name: None)

        with caplog.at_level(logging.WARNING, logger="cognic_agentos.core.policy.engine"):
            loop, warnings, _ = await agent_host.build_agent_loop(
                runtime=_runtime(engine),
                settings=LoopSettings(agents_policy_bundle=bad, opa_path=None),
                registry=Registry([candidate()]),
                mcp_host=_SENTINEL,
                engine=engine,
            )

        assert isinstance(loop, AgentLoop), "deferred validation must still compose"
        assert warnings == []
        assert loop._dispatcher._policy._opa_engine._opa_path is None
        emitted = [
            rec
            for rec in caplog.records
            if rec.name == "cognic_agentos.core.policy.engine" and rec.levelno >= logging.WARNING
        ]
        assert [rec.getMessage() for rec in emitted] == [
            "OPA binary not found at engine construction; "
            "Rego syntax validation deferred. Calls to evaluate() "
            "will fail-closed with OpaNotInstalledError until OPA "
            f"is installed. bundle={bad}"
        ]


def _install_pack(dists: list[Any], tmp_path: Path, **kwargs: Any) -> None:
    root = tmp_path / "site-packages"
    package = kwargs.pop("package", DEFAULT_PACKAGE)
    write_agent_pack(root, package=package, **kwargs)
    dists.append(
        FakeDist(
            name=DEFAULT_DIST,
            version=DEFAULT_VERSION,
            root=root,
        )
    )


def _runtime(engine: AsyncEngine, **overrides: Any) -> LoopRuntime:
    """A fully-configured runtime; override a member with ``None`` to drop a dep.

    ``audit_store`` and ``decision_history_store`` are the REAL hash-chained
    stores over the migrated engine. Composition evidence
    (``policy.bundle_loaded``) is written through ``decision_history_store``
    ONLY — ``audit_store`` is injected and real but carries no composition
    evidence.
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
    """The 3-state dependency gate is an operator-facing contract:
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
        # EXACT string, not substring membership. Substring checks let a
        # PHANTOM dependency ride along in the warning undetected, which would
        # send an operator hunting for something that is configured fine.
        assert warnings == [
            "agent loop not built — missing dependencies: mcp_host, memory_api_factory"
        ]

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

        # Exact public projection. Persona body/digest are deliberately absent;
        # checking only agent_id would let a future operator-surface leak pass.
        assert hosted == [
            {
                "agent_id": DEFAULT_AGENT_ID,
                "requested_skills": ["conformance-skill"],
                "requested_tools": ["conformance-server/conformance_query"],
                "max_steps": 4,
                "risk_tier": "read_only",
                "pack_version": DEFAULT_VERSION,
            }
        ]

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


@dataclass(frozen=True, slots=True)
class _BuiltLoop:
    loop: AgentLoop
    gateway: ScriptedGateway
    runtime: LoopRuntime


class TestComposedLoopWiring:
    """The built loop must carry the REAL collaborators, not defaults."""

    @pytest.fixture
    async def built(
        self, engine: AsyncEngine, metadata_env: list[Any], tmp_path: Path
    ) -> _BuiltLoop:
        _install_pack(metadata_env, tmp_path)
        gateway = ScriptedGateway()
        runtime = _runtime(engine, llm_gateway=gateway)
        loop, warnings, _ = await agent_host.build_agent_loop(
            runtime=runtime,
            settings=LoopSettings(
                agent_max_steps=7,
                agent_run_token_budget=1234,
                agent_run_wall_clock_s=2.5,
            ),
            registry=Registry([candidate()]),
            mcp_host=_SENTINEL,
            engine=engine,
        )
        assert isinstance(loop, AgentLoop) and warnings == []
        return _BuiltLoop(loop=loop, gateway=gateway, runtime=runtime)

    async def test_settings_are_threaded_into_the_loop(self, built: _BuiltLoop) -> None:
        """Pin the two stored inputs without claiming ask-time enforcement.

        ``agent_max_steps=7`` is stored as the loop fallback while this fixture
        record stores authored ``max_steps=4``. The loop's ask-time precedence
        rule and each bound's enforcement are covered elsewhere, not here.
        """
        loop = built.loop
        assert loop._default_max_steps == 7
        assert loop._run_token_budget == 1234
        assert loop._run_wall_clock_s == 2.5

        record = await loop._record_loader.load_for_agent(agent_id=DEFAULT_AGENT_ID, tenant_id="t1")
        assert record is not None
        assert record.max_steps == 4

    def test_fixture_policy_path_matches_the_real_settings_default(self) -> None:
        """Avoid a line-number citation: compare to the actual field default."""
        real_default = Settings.model_fields["agents_policy_bundle"].default
        assert LoopSettings().agents_policy_bundle == real_default

    async def test_dispatcher_holds_the_real_governance_collaborators(
        self, built: _BuiltLoop, engine: AsyncEngine
    ) -> None:
        """Executing real code is not the same as being WIRED to it.

        Without these, swapping AssignmentStore / EntitlementStore / the policy
        for inert objects would leave every other assertion in this module
        green, because composition alone never dispatches.
        """
        loop = built.loop
        dispatcher = loop._dispatcher
        runtime = built.runtime

        assert isinstance(loop._assignments, AssignmentStore)
        assert isinstance(dispatcher._entitlements, EntitlementStore)
        assert isinstance(dispatcher._policy, AgentDispatchPolicy)
        assert isinstance(dispatcher._policy._opa_engine, OPAEngine)
        assert isinstance(runtime.audit_store, AuditStore)
        assert isinstance(runtime.decision_history_store, DecisionHistoryStore)

        # Same migrated engine end to end — a store bound to a DIFFERENT engine
        # would read an empty database and refuse everything for the wrong reason.
        assert loop._assignments._engine is engine
        assert dispatcher._entitlements._engine is engine
        assert runtime.audit_store._engine is engine
        assert runtime.decision_history_store._engine is engine
        policy_engine = dispatcher._policy._opa_engine
        assert policy_engine._audit_store is runtime.audit_store
        assert policy_engine._decision_history_store is runtime.decision_history_store
        assert loop._decision_history is runtime.decision_history_store
        assert dispatcher._decision_history is runtime.decision_history_store

    async def test_policy_engine_pins_the_shipped_agents_bundle(self, built: _BuiltLoop) -> None:
        """Composition must load the current shipped bundle bytes."""
        loop = built.loop
        engine_ = loop._dispatcher._policy._opa_engine
        expected = hashlib.sha256(Path("policies/_default/agents.rego").read_bytes()).hexdigest()
        assert engine_._bundle_sha256 == expected

    async def test_composition_writes_exactly_one_bundle_loaded_row(
        self, built: _BuiltLoop, engine: AsyncEngine
    ) -> None:
        """Composition evidence rides decision_history — and rides it ONCE.
        A second row would mean the bundle was loaded twice per boot."""
        _ = built  # composition already happened in the fixture
        async with engine.begin() as conn:
            rows = (
                await conn.execute(
                    sa.select(
                        _decision_history.c.event_type,
                        _decision_history.c.payload,
                    ).where(_decision_history.c.event_type == "policy.bundle_loaded")
                )
            ).all()
        assert len(rows) == 1
        expected_path = str(Path("policies/_default/agents.rego"))
        expected_digest = hashlib.sha256(Path(expected_path).read_bytes()).hexdigest()
        assert rows[0].payload["bundle_path"] == expected_path
        assert rows[0].payload["bundle_sha256"] == expected_digest

    async def test_gateway_is_the_injected_instance(self, built: _BuiltLoop) -> None:
        loop, gateway = built.loop, built.gateway
        # ScriptedGateway is a STRUCTURAL stand-in, not an LLMGateway subclass,
        # so compare as plain objects: the assertion is about identity (the
        # injected instance survived composition), not nominal type.
        assert cast(object, loop._gateway) is gateway

    async def test_record_loader_resolves_the_synthetic_agent(self, built: _BuiltLoop) -> None:
        """The loop's record loader is bound to the boot-built records, so the
        agent the composition hosted is the agent the loop can resolve."""
        loop = built.loop
        record = await loop._record_loader.load_for_agent(agent_id=DEFAULT_AGENT_ID, tenant_id="t1")
        assert record is not None
        assert record.agent_id == DEFAULT_AGENT_ID
        assert record.registered is True

    async def test_unknown_agent_resolves_to_none(self, built: _BuiltLoop) -> None:
        loop = built.loop
        assert await loop._record_loader.load_for_agent(agent_id="nope", tenant_id="t1") is None
