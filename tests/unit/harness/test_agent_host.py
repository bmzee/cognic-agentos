"""M8 A8 (ADR-027) — agent-pack hosting/ingestion.

``_build_agent_records`` walks the trust-registered candidates, re-extracts
each pack's manifest ``[agent]`` block + ``AGENT.md`` WITHOUT importing pack
code, validates the persona shape (the REUSED skill_manifest frontmatter
contract), reads the requested capability lists + ``max_steps`` + the
mandatory risk tier, and yields a :class:`LoadedAgentRecord` per admitted
agent. Per-pack fail-closed warn-skip mirrors ``_build_skill_records`` — a
bad agent pack is not hosted, never crashes the boot.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Any, ClassVar, cast

import pytest

import cognic_agentos.harness.agent_host as agent_host
from cognic_agentos.cli.validators.data_governance import (
    _DATA_GOVERNANCE_LOCATIONS,
)
from cognic_agentos.core.agent._types import LoadedAgentRecord
from cognic_agentos.protocol.agent_manifest import AgentManifestNotFound
from cognic_agentos.protocol.mcp_manifest import (
    PackManifestMalformedError,
    PackManifestNotFoundError,
)

_VALID_AGENT_MD = """---
name: schema-advisor
description: Answers schema questions through governed skills and tools.
---
You are a schema advisor. Use read_skill before invoking any skill.
"""


class _Cand:
    def __init__(
        self,
        distribution_name: str,
        *,
        package_name: str = "pkg",
        signature_digest: str | None = "sha256:" + "ab" * 32,
    ) -> None:
        self.distribution_name = distribution_name
        self.package_name = package_name
        self.signature_digest = signature_digest


class _Registry:
    def __init__(self, cands: list[_Cand]) -> None:
        self._c = cands

    def iter_registered_pack_candidates(self) -> Any:
        return iter(self._c)


class _Settings:
    """No agent-host Settings field is read at A8 — the seam is reserved."""


def _agent_manifest(
    block: dict[str, Any] | None = None,
    *,
    tier: str | None = "customer_data_read",
    legacy: bool = False,
) -> dict[str, Any]:
    if block is None:
        block = {
            "persona_path": "AGENT.md",
            "requested_skills": ["schema-summary"],
            "requested_tools": ["cognic-tool-oracle-schema/describe_table"],
            "max_steps": 8,
        }
    manifest: dict[str, Any] = {
        "pack": {
            "pack_id": "cognic-agent-advisor",
            "kind": "agent",
        }
    }
    if legacy:
        manifest["tool"] = {"cognic": {"agent": block}}
    else:
        manifest["agent"] = block
    if tier is not None:
        manifest["risk_tier"] = {"tier": tier}
    manifest["data_governance"] = {
        "data_classes": ["internal"],
        "purpose": "operational_telemetry",
    }
    return manifest


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    manifests: dict[str, Any],
    agent_mds: dict[str, str] | None = None,
    versions: dict[str, str | None] | None = None,
) -> None:
    agent_mds = agent_mds or {}
    versions = versions or {}

    def _fake_manifest(*, distribution_name: str, package_name: str) -> dict[str, Any]:
        if distribution_name not in manifests:
            raise PackManifestNotFoundError(distribution_name)
        manifest: dict[str, Any] = manifests[distribution_name]
        return manifest

    def _fake_agent_md(*, distribution_name: str, package_name: str) -> str:
        if distribution_name not in agent_mds:
            raise AgentManifestNotFound(distribution_name)
        return agent_mds[distribution_name]

    def _fake_version(distribution_name: str) -> str | None:
        return versions.get(distribution_name, "0.1.0")

    monkeypatch.setattr(agent_host, "extract_pack_manifest", _fake_manifest)
    monkeypatch.setattr(agent_host, "extract_agent_md", _fake_agent_md)
    monkeypatch.setattr(agent_host, "_distribution_version", _fake_version)


def _build(reg: _Registry) -> dict[str, LoadedAgentRecord]:
    return agent_host._build_agent_records(registry=reg, settings=_Settings())


# ============================ happy path =====================================
def test_build_tool_capability_classes_fail_closed_shapes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifests: dict[str, Any] = {
        "missing": PackManifestNotFoundError("missing"),
        "malformed": PackManifestMalformedError("malformed"),
        "not-a-list": {"tool": {"cognic": {"tools": "invalid"}}},
        "mixed": {
            "tool": {
                "cognic": {
                    "tools": [
                        "not-a-table",
                        {"name": "", "capability_class": "action"},
                        {"name": "no-class"},
                        {"name": "execute", "capability_class": "action"},
                    ]
                }
            }
        },
    }

    def _extract(*, distribution_name: str, package_name: str) -> dict[str, Any]:
        del package_name
        result = manifests[distribution_name]
        if isinstance(result, Exception):
            raise result
        return cast(dict[str, Any], result)

    monkeypatch.setattr(agent_host, "extract_pack_manifest", _extract)

    assert agent_host.build_tool_capability_classes(
        _Registry([_Cand(name) for name in manifests])
    ) == {"mixed/execute": "action"}


def test_manifest_shape_helpers_cover_fail_closed_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (
        agent_host._risk_tier(
            {
                "risk_tier": {"tier": " "},
                "tool": {"cognic": {"runtime": {"risk_tier": "read_only"}}},
            }
        )
        == "read_only"
    )
    assert agent_host._requested_skills({"requested_skills": [""]}) is None
    assert agent_host._requested_tools({"requested_tools": "bad"}) is None
    assert agent_host._requested_tools({"requested_tools": [7]}) is None

    metadata_module = cast(Any, agent_host).md

    def _missing_distribution(_name: str) -> Any:
        raise metadata_module.PackageNotFoundError

    monkeypatch.setattr(metadata_module, "distribution", _missing_distribution)
    assert agent_host._distribution_version("not-installed") is None


def test_governance_projection_legacy_pack_id_and_absent_declaration() -> None:
    assert agent_host._agent_governance_projection(
        {"tool": {"cognic": {"pack": {"pack_id": "legacy-agent"}}}},
        distribution_name="legacy-agent",
    ) == ("legacy-agent", (), "")


def test_build_records_yields_valid_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": _agent_manifest()},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )
    reg = _Registry([_Cand("cognic-agent-advisor")])
    records = _build(reg)
    assert set(records) == {"schema-advisor"}
    rec = records["schema-advisor"]
    assert isinstance(rec, LoadedAgentRecord)
    assert "schema advisor" in rec.persona_body
    assert rec.persona_sha256 == hashlib.sha256(rec.persona_body.encode("utf-8")).hexdigest()
    assert rec.requested_skills == ("schema-summary",)
    assert rec.requested_tools == ("cognic-tool-oracle-schema/describe_table",)
    assert rec.max_steps == 8
    assert rec.risk_tier == "customer_data_read"
    assert rec.pack_version == "0.1.0"
    assert rec.signed_artefact_digest == "sha256:" + "ab" * 32
    assert rec.registered is True
    assert rec.pack_id == "cognic-agent-advisor"
    assert rec.manifest_data_classes == ("internal",)
    assert rec.manifest_purpose == "operational_telemetry"


def test_build_records_projects_legacy_governance_location(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _agent_manifest()
    governance = manifest.pop("data_governance")
    manifest.setdefault("tool", {}).setdefault("cognic", {})["data_governance"] = governance
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": manifest},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )

    record = _build(_Registry([_Cand("cognic-agent-advisor")]))["schema-advisor"]

    assert record.manifest_data_classes == ("internal",)
    assert record.manifest_purpose == "operational_telemetry"


def test_agent_host_governance_locations_match_admission_validator() -> None:
    assert agent_host._AGENT_DATA_GOVERNANCE_LOCATIONS == _DATA_GOVERNANCE_LOCATIONS


def test_build_records_unions_consistent_dual_governance_locations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _agent_manifest()
    manifest.setdefault("tool", {}).setdefault("cognic", {})["data_governance"] = {
        "data_classes": ["customer_pii"],
        "purpose": "operational_telemetry",
    }
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": manifest},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )

    record = _build(_Registry([_Cand("cognic-agent-advisor")]))["schema-advisor"]

    assert record.manifest_data_classes == ("customer_pii", "internal")


def test_build_records_warn_skips_ambiguous_dual_governance_purpose(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    manifest = _agent_manifest()
    manifest.setdefault("tool", {}).setdefault("cognic", {})["data_governance"] = {
        "data_classes": ["internal"],
        "purpose": "customer_support",
    }
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": manifest},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )

    with caplog.at_level("WARNING"):
        records = _build(_Registry([_Cand("cognic-agent-advisor")]))

    assert records == {}
    assert [record.message for record in caplog.records] == ["agent.data_governance_malformed"]


def test_build_records_uses_admission_whitespace_and_duplicate_normalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = _agent_manifest()
    manifest["data_governance"] = {
        "data_classes": [" internal ", "internal"],
        "purpose": " operational_telemetry ",
    }
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": manifest},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )

    record = _build(_Registry([_Cand("cognic-agent-advisor")]))["schema-advisor"]

    assert record.manifest_data_classes == ("internal",)
    assert record.manifest_purpose == "operational_telemetry"


@pytest.mark.parametrize(
    "governance",
    [
        "not-a-table",
        {"data_classes": [], "purpose": "operational_telemetry"},
        {"data_classes": ["unknown"], "purpose": "operational_telemetry"},
        {"data_classes": ["internal"], "purpose": "unknown"},
    ],
)
def test_explicit_malformed_agent_governance_warn_skips(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    governance: Any,
) -> None:
    manifest = _agent_manifest()
    manifest["data_governance"] = governance
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": manifest},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )

    with caplog.at_level(logging.WARNING):
        records = _build(_Registry([_Cand("cognic-agent-advisor")]))

    assert records == {}
    assert "agent.data_governance_malformed" in caplog.text


def test_legacy_block_path_honored(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": _agent_manifest(legacy=True)},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )
    records = _build(_Registry([_Cand("cognic-agent-advisor")]))
    assert set(records) == {"schema-advisor"}


def test_requested_lists_and_max_steps_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": _agent_manifest({"persona_path": "AGENT.md"})},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )
    records = _build(_Registry([_Cand("cognic-agent-advisor")]))
    rec = records["schema-advisor"]
    assert rec.requested_skills == ()
    assert rec.requested_tools == ()
    assert rec.max_steps is None


def test_legacy_runtime_risk_tier_honored(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = _agent_manifest(tier=None)
    manifest.setdefault("tool", {}).setdefault("cognic", {})["runtime"] = {"risk_tier": "read_only"}
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": manifest},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )
    records = _build(_Registry([_Cand("cognic-agent-advisor")]))
    assert records["schema-advisor"].risk_tier == "read_only"


def test_absent_signature_digest_maps_to_none(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": _agent_manifest()},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )
    records = _build(_Registry([_Cand("cognic-agent-advisor", signature_digest=None)]))
    assert records["schema-advisor"].signed_artefact_digest is None


def test_unresolvable_version_maps_to_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": _agent_manifest()},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
        versions={"cognic-agent-advisor": None},
    )
    records = _build(_Registry([_Cand("cognic-agent-advisor")]))
    assert records["schema-advisor"].pack_version == ""


# ============================ warn-skips =====================================
def test_no_manifest_pack_silently_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, manifests={})
    assert _build(_Registry([_Cand("cognic-tool-x")])) == {}


def test_non_agent_pack_silently_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, manifests={"cognic-tool-x": {"skill": {"mode": "instruction"}}})
    assert _build(_Registry([_Cand("cognic-tool-x")])) == {}


def test_malformed_manifest_warn_skips(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from cognic_agentos.protocol.mcp_manifest import PackManifestMalformedError

    def _raise(**_kw: Any) -> dict[str, Any]:
        raise PackManifestMalformedError("boom")

    monkeypatch.setattr(agent_host, "extract_pack_manifest", _raise)
    with caplog.at_level(logging.WARNING):
        records = agent_host._build_agent_records(
            registry=_Registry([_Cand("cognic-agent-bad")]), settings=_Settings()
        )
    assert records == {}
    assert "agent.pack_manifest_malformed" in caplog.text


def test_missing_agent_md_warn_skips(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch(monkeypatch, manifests={"cognic-agent-advisor": _agent_manifest()}, agent_mds={})
    with caplog.at_level(logging.WARNING):
        records = _build(_Registry([_Cand("cognic-agent-advisor")]))
    assert records == {}
    assert "agent.agent_md_not_found" in caplog.text


def test_invalid_agent_md_warn_skips(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": _agent_manifest()},
        agent_mds={"cognic-agent-advisor": "no frontmatter fence\n"},
    )
    with caplog.at_level(logging.WARNING):
        records = _build(_Registry([_Cand("cognic-agent-advisor")]))
    assert records == {}
    assert "agent.agent_md_invalid" in caplog.text


def test_malformed_requested_skills_warn_skips(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch(
        monkeypatch,
        manifests={
            "cognic-agent-advisor": _agent_manifest(
                {"persona_path": "AGENT.md", "requested_skills": "not-a-list"}
            )
        },
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )
    with caplog.at_level(logging.WARNING):
        records = _build(_Registry([_Cand("cognic-agent-advisor")]))
    assert records == {}
    assert "agent.requested_skills_malformed" in caplog.text


def test_malformed_requested_tools_warn_skips(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch(
        monkeypatch,
        manifests={
            "cognic-agent-advisor": _agent_manifest(
                {"persona_path": "AGENT.md", "requested_tools": ["no-slash-identity"]}
            )
        },
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )
    with caplog.at_level(logging.WARNING):
        records = _build(_Registry([_Cand("cognic-agent-advisor")]))
    assert records == {}
    assert "agent.requested_tools_malformed" in caplog.text


@pytest.mark.parametrize("bad", [0, 33, True, "5"])
def test_invalid_max_steps_warn_skips(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, bad: Any
) -> None:
    _patch(
        monkeypatch,
        manifests={
            "cognic-agent-advisor": _agent_manifest({"persona_path": "AGENT.md", "max_steps": bad})
        },
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )
    with caplog.at_level(logging.WARNING):
        records = _build(_Registry([_Cand("cognic-agent-advisor")]))
    assert records == {}
    assert "agent.max_steps_invalid" in caplog.text


def test_missing_risk_tier_warn_skips_fail_closed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A record without a tier cannot be dispatched — fail closed at ingest."""
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": _agent_manifest(tier=None)},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )
    with caplog.at_level(logging.WARNING):
        records = _build(_Registry([_Cand("cognic-agent-advisor")]))
    assert records == {}
    assert "agent.risk_tier_missing" in caplog.text


def test_duplicate_agent_id_keeps_first(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch(
        monkeypatch,
        manifests={
            "cognic-agent-one": _agent_manifest(),
            "cognic-agent-two": _agent_manifest(),
        },
        agent_mds={
            "cognic-agent-one": _VALID_AGENT_MD,
            "cognic-agent-two": _VALID_AGENT_MD,
        },
    )
    with caplog.at_level(logging.WARNING):
        records = _build(_Registry([_Cand("cognic-agent-one"), _Cand("cognic-agent-two")]))
    assert set(records) == {"schema-advisor"}
    assert "agent.duplicate_agent_id" in caplog.text


def test_one_bad_pack_never_blocks_the_sibling(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={
            "cognic-agent-bad": _agent_manifest(tier=None),  # no risk tier -> skip
            "cognic-agent-good": _agent_manifest(),
        },
        agent_mds={
            "cognic-agent-bad": _VALID_AGENT_MD,
            "cognic-agent-good": _VALID_AGENT_MD.replace("schema-advisor", "good-advisor"),
        },
    )
    records = _build(_Registry([_Cand("cognic-agent-bad"), _Cand("cognic-agent-good")]))
    assert set(records) == {"good-advisor"}


# ============================ hosted_agents summary ==========================
def test_hosted_agents_summary_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": _agent_manifest()},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )
    records = _build(_Registry([_Cand("cognic-agent-advisor")]))
    rows = agent_host.hosted_agents_summary(records)
    assert rows == [
        {
            "agent_id": "schema-advisor",
            "requested_skills": ["schema-summary"],
            "requested_tools": ["cognic-tool-oracle-schema/describe_table"],
            "max_steps": 8,
            "risk_tier": "customer_data_read",
            "pack_version": "0.1.0",
        }
    ]


# ============================ /system/plugins surface ========================
def test_system_plugins_surfaces_hosted_agents() -> None:
    """The A8 operator surface: ``hosted_agents`` rides top-level on
    GET /api/v1/system/plugins, read absent-safe off app.state exactly like
    ``hosted_skills`` (empty when the lifespan has not populated the slot)."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from cognic_agentos.core.config import build_settings_without_env_file
    from cognic_agentos.portal.api.system_routes import build_system_router

    settings = build_settings_without_env_file()
    rows = [
        {
            "agent_id": "schema-advisor",
            "requested_skills": ["schema-summary"],
            "requested_tools": [],
            "max_steps": None,
            "risk_tier": "read_only",
            "pack_version": "0.1.0",
        }
    ]
    app = FastAPI()
    app.include_router(build_system_router(settings))
    app.state.hosted_agents = rows
    body = TestClient(app).get("/api/v1/system/plugins").json()
    assert body["hosted_agents"] == rows
    # summary wire-shape untouched (closed dict — hosted_agents rides top-level).
    assert "hosted_agents" not in body["summary"]


def test_system_plugins_hosted_agents_absent_safe() -> None:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from cognic_agentos.core.config import build_settings_without_env_file
    from cognic_agentos.portal.api.system_routes import build_system_router

    app = FastAPI()
    app.include_router(build_system_router(build_settings_without_env_file()))
    body = TestClient(app).get("/api/v1/system/plugins").json()
    assert body["hosted_agents"] == []


# ===================== A13 — build_agent_loop composition ====================
#
# The 3-state dependency discipline per
# ``feedback_conditional_router_mount_partial_config_warning``: ALL gateable
# deps present → (loop, []); SOME missing → (None, [ONE warning naming them]);
# ZERO present → (None, []) QUIET. Plus the signing-key resolution arms and
# the record-loader / skill-body-reader / tool-proxy conformers.


class _StubDecisionHistory:
    def __init__(self) -> None:
        self.rows: list[Any] = []

    async def append(self, record: Any) -> None:
        self.rows.append(record)


class _StubRuntime:
    def __init__(
        self,
        *,
        llm_gateway: Any = "GATEWAY",
        memory_api_factory: Any = "MEMORY_FACTORY",
    ) -> None:
        self.llm_gateway = llm_gateway
        self.memory_api_factory = memory_api_factory
        self.audit_store = object()
        self.decision_history_store = _StubDecisionHistory()


class _LoopSettings:
    """Structural conformer for the A13 ``_AgentLoopSettings`` seam (the real
    ``Settings`` conforms; tests stub only the read fields)."""

    def __init__(self, *, signing_key_path: str | None = None) -> None:
        from pathlib import Path as _P

        self.agents_policy_bundle = _P("policies/_default/agents.rego")
        self.agent_query_context_signing_key_path = signing_key_path
        self.agent_query_context_ttl_s = 120.0
        self.agent_max_steps = 6
        self.agent_run_token_budget = 24_000
        self.agent_run_wall_clock_s = 120.0
        self.opa_path: str | None = None
        self.opa_eval_timeout_s = 5.0
        self.sandbox_canonical_runtime_python_image = "ghcr.io/cognic/sandbox-runtime-python:1"


async def _build_loop(
    *,
    runtime: Any = "DEFAULT",
    registry: Any = "DEFAULT",
    mcp_host: Any = "MCP_HOST",
    settings: Any = "DEFAULT",
) -> Any:
    from sqlalchemy.ext.asyncio import AsyncEngine

    if runtime == "DEFAULT":
        runtime = _StubRuntime()
    if registry == "DEFAULT":
        registry = _Registry([])
    if settings == "DEFAULT":
        settings = _LoopSettings()
    return await agent_host.build_agent_loop_with_records(
        runtime=runtime,
        settings=settings,
        registry=registry,
        mcp_host=mcp_host,
        engine=cast(AsyncEngine, object()),
    )


async def test_build_agent_loop_preserves_three_value_return_contract() -> None:
    from sqlalchemy.ext.asyncio import AsyncEngine

    result = await agent_host.build_agent_loop(
        runtime=_StubRuntime(),
        settings=_LoopSettings(),
        registry=_Registry([]),
        mcp_host="MCP_HOST",
        engine=cast(AsyncEngine, object()),
    )

    assert len(result) == 3


async def test_build_agent_loop_all_deps_builds_loop_no_warnings() -> None:
    from cognic_agentos.core.agent.loop import AgentLoop

    loop, warnings, hosted, records = await _build_loop()
    assert isinstance(loop, AgentLoop)
    assert warnings == []
    assert hosted == []  # empty registry — no hosted rows
    assert dict(records) == {}


async def test_build_agent_loop_threads_signed_tool_capability_classes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability_classes = {
        "cognic-tool-oracle-schema/run_readonly_query": "data_query",
        "srv/metadata": "unscoped",
    }
    calls: list[Any] = []

    def _build(registry: Any) -> dict[str, str]:
        calls.append(registry)
        return capability_classes

    monkeypatch.setattr(agent_host, "build_tool_capability_classes", _build)
    registry = _Registry([])

    loop, warnings, _hosted, _records = await _build_loop(registry=registry)

    assert loop is not None
    assert warnings == []
    assert calls == [registry]
    assert loop._tool_capability_classes == capability_classes
    assert loop._dispatcher._tool_capability_classes == capability_classes
    assert loop._action_tool_schema_provider._host == "MCP_HOST"


async def test_build_agent_loop_some_missing_returns_none_plus_single_warning() -> None:
    loop, warnings, hosted, records = await _build_loop(mcp_host=None)
    assert loop is None
    assert len(warnings) == 1
    assert "mcp_host" in warnings[0]
    assert hosted == []  # rows ride ONLY the built path
    assert dict(records) == {}


async def test_build_agent_loop_multiple_missing_still_single_warning_naming_all() -> None:
    runtime = _StubRuntime(memory_api_factory=None)
    loop, warnings, hosted, records = await _build_loop(runtime=runtime, mcp_host=None)
    assert loop is None
    assert len(warnings) == 1
    assert "mcp_host" in warnings[0]
    assert "memory_api_factory" in warnings[0]
    assert hosted == []
    assert dict(records) == {}


async def test_build_agent_loop_zero_deps_stays_quiet() -> None:
    runtime = _StubRuntime(llm_gateway=None, memory_api_factory=None)
    loop, warnings, hosted, records = await _build_loop(
        runtime=runtime, registry=None, mcp_host=None
    )
    assert loop is None
    assert warnings == []
    assert hosted == []
    assert dict(records) == {}


async def test_build_agent_loop_plain_path_signing_key_read_bytes(tmp_path: Any) -> None:
    key = tmp_path / "qc-signing.pem"
    key.write_bytes(b"PEM-BYTES")
    loop, warnings, _hosted, _records = await _build_loop(
        settings=_LoopSettings(signing_key_path=str(key))
    )
    assert loop is not None
    assert warnings == []
    # the dispatcher received the key bytes (private-attr probe — composition pin).
    assert loop._dispatcher._signing_key_pem == b"PEM-BYTES"


async def test_build_agent_loop_vault_uri_ships_warn_plus_none_key() -> None:
    """The controller-reported branch: ``vault://`` resolution is NOT wired at
    A13 — the builder warns explicitly and passes None (stamped-tool
    dispatches then fail loud at mint per the dispatcher's deployment-error
    contract)."""
    loop, warnings, _hosted, _records = await _build_loop(
        settings=_LoopSettings(signing_key_path="vault://secret/agent-qc-key")
    )
    assert loop is not None
    assert len(warnings) == 1
    assert "vault://" in warnings[0]
    assert loop._dispatcher._signing_key_pem is None


async def test_build_agent_loop_missing_key_file_raises_to_fail_soft_caller() -> None:
    with pytest.raises(OSError):
        await _build_loop(settings=_LoopSettings(signing_key_path="/nonexistent/key.pem"))


async def test_build_agent_loop_returns_hosted_agent_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The maintainer-directed A13 wiring: the 3rd tuple element carries the
    hosted_agents_summary rows for app.state.hosted_agents (read by
    /api/v1/system/plugins) — the build_skill_executor → hosted_skills
    mirror. Rows flow ONLY when the loop builds."""
    _patch(
        monkeypatch,
        manifests={"cognic-agent-advisor": _agent_manifest()},
        agent_mds={"cognic-agent-advisor": _VALID_AGENT_MD},
    )
    reg = _Registry([_Cand("cognic-agent-advisor")])
    loop, warnings, hosted, records = await _build_loop(registry=reg)
    assert loop is not None
    assert warnings == []
    assert [row["agent_id"] for row in hosted] == ["schema-advisor"]
    # The rows ARE the hosted_agents_summary projection of the built records.
    expected = agent_host.hosted_agents_summary(
        agent_host._build_agent_records(registry=reg, settings=_LoopSettings())
    )
    assert hosted == expected
    assert set(records) == {"schema-advisor"}
    with pytest.raises(TypeError):
        cast(Any, records)["replacement"] = records["schema-advisor"]


def test_instruction_skill_body_reader_arms() -> None:
    from cognic_agentos.core.skill._types import LoadedSkillRecord

    records = {
        "schema-summary": LoadedSkillRecord(
            skill_id="schema-summary",
            mode="instruction",
            description="Summarises a schema.",
            skill_md_body="# Schema summary\nGuidance body.",
        ),
        "exec-skill": LoadedSkillRecord(
            skill_id="exec-skill",
            entry_point_name="run",
            declared_tools=("srv/tool",),
            runtime_image="img:1",
        ),
    }
    reader = agent_host._InstructionSkillBodyReader(records)
    assert reader.read("schema-summary") == (
        "Summarises a schema.",
        "# Schema summary\nGuidance body.",
    )
    assert reader.read("exec-skill") is None  # executable mode — no body surface
    assert reader.read("ghost") is None  # unknown id


async def test_registry_agent_record_loader_lookup() -> None:
    record = LoadedAgentRecord(
        agent_id="schema-advisor",
        persona_body="persona",
        persona_sha256=hashlib.sha256(b"persona").hexdigest(),
        requested_skills=(),
        requested_tools=(),
        max_steps=None,
        risk_tier="read_only",
        pack_version="0.1.0",
        signed_artefact_digest=None,
        registered=True,
    )
    loader = agent_host._RegistryAgentRecordLoader({"schema-advisor": record})
    assert (await loader.load_for_agent(agent_id="schema-advisor", tenant_id="tenant-a")) is record
    assert (await loader.load_for_agent(agent_id="ghost", tenant_id="tenant-a")) is None


async def test_mcp_host_agent_tool_proxy_threads_and_projects() -> None:
    class _StubHost:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        async def call_tool(self, **kwargs: Any) -> Any:
            self.calls.append(kwargs)

            class _Result:
                payload: ClassVar[dict[str, Any]] = {"rows": 3}

            return _Result()

    host = _StubHost()
    proxy = agent_host._MCPHostAgentToolProxy(host)
    result = await proxy.call_tool(
        server_id="cognic-tool-oracle-schema",
        tool_name="describe_table",
        arguments={"table": "ACCOUNTS"},
        request_id="agent-tool-" + "cd" * 16,
        tenant_id="tenant-a",
        originator_subject="analyst@bank",
        approval_request_id=None,
    )
    assert result == {"rows": 3}
    assert len(host.calls) == 1
    call = host.calls[0]
    assert call["server_id"] == "cognic-tool-oracle-schema"
    assert call["tool_name"] == "describe_table"
    assert call["arguments"] == {"table": "ACCOUNTS"}
    assert call["tenant_id"] == "tenant-a"
    assert call["originator_subject"] == "analyst@bank"
    assert call["approval_request_id"] is None


async def test_mcp_action_schema_provider_reads_only_requested_live_schemas() -> None:
    class _Tool:
        def __init__(self, name: str, schema: dict[str, Any]) -> None:
            self.name = name
            self.inputSchema = schema

    class _StubHost:
        def __init__(self) -> None:
            self.calls: list[dict[str, Any]] = []

        async def list_tools(self, **kwargs: Any) -> list[Any]:
            self.calls.append(kwargs)
            if kwargs["server_id"] == "leave":
                return [
                    _Tool(
                        "apply_leave",
                        {
                            "type": "object",
                            "properties": {"start_date": {"type": "string"}},
                            "required": ["start_date"],
                        },
                    ),
                    _Tool("not_granted", {"type": "object", "properties": {}}),
                ]
            return [
                {
                    "name": "probe_write",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"nonce": {"type": "string"}},
                        "required": ["nonce"],
                    },
                }
            ]

    host = _StubHost()
    provider = agent_host._MCPHostActionToolSchemaProvider(host)

    schemas = await provider.load_action_schemas(
        tenant_id="tenant-a",
        tool_refs=frozenset({"leave/apply_leave", "probe/probe_write"}),
    )

    assert set(schemas) == {"leave/apply_leave", "probe/probe_write"}
    assert schemas["leave/apply_leave"]["required"] == ["start_date"]
    assert schemas["probe/probe_write"]["required"] == ["nonce"]
    assert [call["server_id"] for call in host.calls] == ["leave", "probe"]
    assert all(call["tenant_id"] == "tenant-a" for call in host.calls)
    assert all(call["request_id"].startswith("agent-schema-") for call in host.calls)


async def test_mcp_action_schema_provider_omits_duplicate_descriptors() -> None:
    class _StubHost:
        async def list_tools(self, **_kwargs: Any) -> list[dict[str, Any]]:
            descriptor = {
                "name": "apply_leave",
                "inputSchema": {"type": "object", "properties": {}},
            }
            return [descriptor, descriptor]

    provider = agent_host._MCPHostActionToolSchemaProvider(_StubHost())

    assert (
        await provider.load_action_schemas(
            tenant_id="tenant-a",
            tool_refs=frozenset({"leave/apply_leave"}),
        )
        == {}
    )


async def test_mcp_action_schema_provider_rejects_bad_refs_and_bad_schemas() -> None:
    class _Descriptor:
        name = "fallback"
        inputSchema = None
        input_schema: ClassVar[dict[str, str]] = {"type": "object"}

    class _StubHost:
        def __init__(self) -> None:
            self.calls = 0

        async def list_tools(self, **_kwargs: Any) -> list[Any]:
            self.calls += 1
            return [
                _Descriptor(),
                {"name": "bad-schema", "inputSchema": "not-a-table"},
            ]

    host = _StubHost()
    provider = agent_host._MCPHostActionToolSchemaProvider(host)

    assert (
        await provider.load_action_schemas(
            tenant_id="tenant-a",
            tool_refs=frozenset({"missing-separator"}),
        )
        == {}
    )
    assert host.calls == 0
    assert await provider.load_action_schemas(
        tenant_id="tenant-a",
        tool_refs=frozenset({"srv/fallback", "srv/bad-schema"}),
    ) == {"srv/fallback": {"type": "object"}}


@pytest.mark.parametrize(
    ("reason", "payload", "expected_exception"),
    [
        ("mcp_capability_refused", {}, "passthrough"),
        ("tool_approval_pending", {"flow": "require_assigned"}, "missing_id"),
        (
            "tool_approval_pending",
            {"approval_request_id": str(uuid.uuid4()), "flow": 7},
            "malformed_flow",
        ),
    ],
)
async def test_mcp_host_agent_tool_proxy_refusal_shapes_fail_closed(
    reason: str,
    payload: dict[str, Any],
    expected_exception: str,
) -> None:
    from cognic_agentos.protocol.mcp_host import (
        MCPToolInvocationRefused,
        ToolInvocationRefusalReason,
    )

    class _StubHost:
        async def call_tool(self, **_kwargs: Any) -> Any:
            raise MCPToolInvocationRefused(
                cast(ToolInvocationRefusalReason, reason),
                **payload,
            )

    proxy = agent_host._MCPHostAgentToolProxy(_StubHost())
    expected_type: type[Exception] = (
        MCPToolInvocationRefused if expected_exception == "passthrough" else RuntimeError
    )
    with pytest.raises(expected_type):
        await proxy.call_tool(
            server_id="probe",
            tool_name="probe_write",
            arguments={},
            request_id="agent-tool-refused",
            tenant_id="tenant-a",
            originator_subject="analyst",
            approval_request_id=None,
        )


async def test_mcp_host_agent_tool_proxy_translates_pending_approval() -> None:
    import cognic_agentos.core.agent.dispatch as agent_dispatch
    from cognic_agentos.protocol.mcp_host import MCPToolInvocationRefused

    approval_request_id = str(uuid.uuid4())

    class _StubHost:
        async def call_tool(self, **_kwargs: Any) -> Any:
            raise MCPToolInvocationRefused(
                "tool_approval_pending",
                approval_request_id=approval_request_id,
                flow="require_assigned",
            )

    proxy = agent_host._MCPHostAgentToolProxy(_StubHost())
    with pytest.raises(agent_dispatch.AgentToolApprovalPending) as exc_info:
        await proxy.call_tool(
            server_id="probe",
            tool_name="probe_write",
            arguments={"amount": 10},
            request_id="agent-tool-pending",
            tenant_id="tenant-a",
            originator_subject="analyst.amir",
            approval_request_id=None,
        )
    assert exc_info.value.approval_request_id == approval_request_id
    assert exc_info.value.flow == "require_assigned"
