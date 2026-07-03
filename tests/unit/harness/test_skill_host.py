"""M6 Task A7 (ADR-025) — skill-pack hosting/ingestion.

The loader walks the trust-registered candidates, re-extracts each pack's
manifest ``[skill].declared_tools`` + ``SKILL.md`` WITHOUT importing pack code,
validates the SKILL.md shape, cross-checks declared tools against the registered
MCP servers, and yields a :class:`LoadedSkillRecord` per admitted skill. A
malformed SKILL.md / malformed declared_tools / unregistered-tool reference
warn-skips the pack (never crashes the boot), mirroring the M5 mapper doctrine.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from cognic_agentos.core.skill._types import LoadedSkillRecord
from cognic_agentos.harness import skill_host
from cognic_agentos.protocol.mcp_manifest import PackManifestNotFoundError
from cognic_agentos.protocol.skill_manifest import SkillManifestNotFound

_VALID_SKILL_MD = """---
name: schema-summary
description: Summarize an Oracle schema.
---
Body instructions here.
"""


class _Cand:
    def __init__(
        self,
        distribution_name: str,
        *,
        package_name: str = "pkg",
        signature_digest: str | None = "abcd",
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
    sandbox_canonical_runtime_python_image = "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64


def _skill_manifest(declared: list[str], *, runtime_image: str | None = None) -> dict[str, Any]:
    block: dict[str, Any] = {"declared_tools": declared}
    if runtime_image is not None:
        block["runtime_image"] = runtime_image
    return {"skill": block}


def _mcp_manifest() -> dict[str, Any]:
    return {"tool": {"cognic": {"mcp": {"server_url": "https://x", "transport": "http"}}}}


def _patch(
    monkeypatch: pytest.MonkeyPatch,
    *,
    manifests: dict[str, Any],
    skill_mds: dict[str, str] | None = None,
    eps: dict[str, tuple[str | None, str | None]] | None = None,
) -> None:
    skill_mds = skill_mds or {}
    eps = eps or {}

    def _fake_manifest(*, distribution_name: str, package_name: str) -> dict[str, Any]:
        if distribution_name not in manifests:
            raise PackManifestNotFoundError(distribution_name)
        manifest: dict[str, Any] = manifests[distribution_name]
        return manifest

    def _fake_skill_md(*, distribution_name: str, package_name: str) -> str:
        if distribution_name not in skill_mds:
            raise SkillManifestNotFound(distribution_name)
        return skill_mds[distribution_name]

    def _fake_ep(distribution_name: str) -> tuple[str | None, str | None]:
        return eps.get(distribution_name, ("schema_summary", "0.1.0"))

    monkeypatch.setattr(skill_host, "extract_pack_manifest", _fake_manifest)
    monkeypatch.setattr(skill_host, "extract_skill_md", _fake_skill_md)
    monkeypatch.setattr(skill_host, "_skill_entry_point_info", _fake_ep)


# ============================ registered MCP server set ======================
def test_registered_mcp_server_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-tool-oracle": _mcp_manifest(), "cognic-skill-x": _skill_manifest([])},
    )
    reg = _Registry([_Cand("cognic-tool-oracle"), _Cand("cognic-skill-x")])
    assert skill_host._registered_mcp_server_ids(reg) == frozenset({"cognic-tool-oracle"})


# ============================ happy path =====================================
def test_build_records_yields_valid_skill(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={
            "cognic-tool-oracle-schema": _mcp_manifest(),
            "cognic-skill-schema-summary": _skill_manifest(
                [
                    "cognic-tool-oracle-schema/list_tables",
                    "cognic-tool-oracle-schema/describe_table",
                ]
            ),
        },
        skill_mds={"cognic-skill-schema-summary": _VALID_SKILL_MD},
    )
    reg = _Registry([_Cand("cognic-tool-oracle-schema"), _Cand("cognic-skill-schema-summary")])
    servers = skill_host._registered_mcp_server_ids(reg)
    records = skill_host._build_skill_records(
        registry=reg, settings=_Settings(), registered_mcp_servers=servers
    )
    assert set(records) == {"schema-summary"}
    rec = records["schema-summary"]
    assert isinstance(rec, LoadedSkillRecord)
    assert rec.entry_point_name == "schema_summary"
    assert rec.declared_tools == (
        "cognic-tool-oracle-schema/list_tables",
        "cognic-tool-oracle-schema/describe_table",
    )
    assert rec.registered is True
    assert rec.pack_version == "0.1.0"
    assert rec.runtime_image == _Settings.sandbox_canonical_runtime_python_image


def test_manifest_declared_runtime_image_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    img = "cognic/skill-schema-summary:v1@sha256:" + "b" * 64
    _patch(
        monkeypatch,
        manifests={
            "cognic-tool-oracle-schema": _mcp_manifest(),
            "cognic-skill-schema-summary": _skill_manifest(
                ["cognic-tool-oracle-schema/list_tables"], runtime_image=img
            ),
        },
        skill_mds={"cognic-skill-schema-summary": _VALID_SKILL_MD},
    )
    reg = _Registry([_Cand("cognic-tool-oracle-schema"), _Cand("cognic-skill-schema-summary")])
    servers = skill_host._registered_mcp_server_ids(reg)
    records = skill_host._build_skill_records(
        registry=reg, settings=_Settings(), registered_mcp_servers=servers
    )
    assert records["schema-summary"].runtime_image == img


# ============================ warn-skips =====================================
def test_malformed_skill_md_warn_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={
            "cognic-tool-oracle-schema": _mcp_manifest(),
            "cognic-skill-bad": _skill_manifest(["cognic-tool-oracle-schema/list_tables"]),
        },
        skill_mds={
            "cognic-skill-bad": "---\nname: Bad Name Uppercase\ndescription: d\n---\nbody\n"
        },
    )
    reg = _Registry([_Cand("cognic-tool-oracle-schema"), _Cand("cognic-skill-bad")])
    servers = skill_host._registered_mcp_server_ids(reg)
    records = skill_host._build_skill_records(
        registry=reg, settings=_Settings(), registered_mcp_servers=servers
    )
    assert records == {}  # bad SKILL.md name -> warn-skip -> not hosted


def test_missing_skill_md_warn_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={
            "cognic-tool-oracle-schema": _mcp_manifest(),
            "cognic-skill-nomd": _skill_manifest(["cognic-tool-oracle-schema/list_tables"]),
        },
        skill_mds={},  # no SKILL.md for the skill -> SkillManifestNotFound
    )
    reg = _Registry([_Cand("cognic-tool-oracle-schema"), _Cand("cognic-skill-nomd")])
    servers = skill_host._registered_mcp_server_ids(reg)
    records = skill_host._build_skill_records(
        registry=reg, settings=_Settings(), registered_mcp_servers=servers
    )
    assert records == {}


def test_declared_tool_unregistered_warn_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    # the skill references a server that is NOT a registered MCP server.
    _patch(
        monkeypatch,
        manifests={
            "cognic-skill-orphan": _skill_manifest(["cognic-tool-ghost/list_tables"]),
        },
        skill_mds={"cognic-skill-orphan": _VALID_SKILL_MD},
    )
    reg = _Registry([_Cand("cognic-skill-orphan")])
    servers = skill_host._registered_mcp_server_ids(reg)  # frozenset() — no MCP packs
    records = skill_host._build_skill_records(
        registry=reg, settings=_Settings(), registered_mcp_servers=servers
    )
    assert records == {}


def test_malformed_declared_tools_warn_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-skill-bad": {"skill": {"declared_tools": "not-a-list"}}},
        skill_mds={"cognic-skill-bad": _VALID_SKILL_MD},
    )
    reg = _Registry([_Cand("cognic-skill-bad")])
    records = skill_host._build_skill_records(
        registry=reg, settings=_Settings(), registered_mcp_servers=frozenset()
    )
    assert records == {}


def test_non_skill_pack_silently_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, manifests={"cognic-tool-oracle-schema": _mcp_manifest()})
    reg = _Registry([_Cand("cognic-tool-oracle-schema")])
    records = skill_host._build_skill_records(
        registry=reg,
        settings=_Settings(),
        registered_mcp_servers=frozenset({"cognic-tool-oracle-schema"}),
    )
    assert records == {}  # a pure MCP pack is not a skill


def test_no_manifest_pack_silently_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, manifests={})  # every extract raises PackManifestNotFoundError
    reg = _Registry([_Cand("cognic-agent-foo")])
    records = skill_host._build_skill_records(
        registry=reg, settings=_Settings(), registered_mcp_servers=frozenset()
    )
    assert records == {}


def test_no_entry_point_warn_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(
        monkeypatch,
        manifests={
            "cognic-tool-oracle-schema": _mcp_manifest(),
            "cognic-skill-noep": _skill_manifest(["cognic-tool-oracle-schema/list_tables"]),
        },
        skill_mds={"cognic-skill-noep": _VALID_SKILL_MD},
        eps={"cognic-skill-noep": (None, None)},  # no cognic.skills entry-point
    )
    reg = _Registry([_Cand("cognic-tool-oracle-schema"), _Cand("cognic-skill-noep")])
    servers = skill_host._registered_mcp_server_ids(reg)
    records = skill_host._build_skill_records(
        registry=reg, settings=_Settings(), registered_mcp_servers=servers
    )
    assert records == {}


# ============================ loader + executor build ========================
async def test_loader_resolves_by_skill_id() -> None:
    rec = LoadedSkillRecord(
        skill_id="schema-summary",
        entry_point_name="schema_summary",
        declared_tools=("s/t",),
        runtime_image="img",
    )
    loader = skill_host._RegistrySkillRecordLoader({"schema-summary": rec})
    assert await loader.load_for_skill(skill_id="schema-summary", tenant_id="t") is rec
    assert await loader.load_for_skill(skill_id="ghost", tenant_id="t") is None


class _StubMCPHost:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def call_tool(
        self,
        *,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        request_id: str,
        tenant_id: str,
        originator_subject: str = "",
        approval_request_id: Any = None,
    ) -> Any:
        self.calls.append(
            {
                "server_id": server_id,
                "tool_name": tool_name,
                "originator_subject": originator_subject,
            }
        )

        return SimpleNamespace(payload={"rows": [["T1"]]})


async def test_mcp_host_call_proxy_returns_payload() -> None:
    host = _StubMCPHost()
    proxy = skill_host._MCPHostCallProxy(host)
    out = await proxy.call(
        server_id="oracle",
        tool_name="list_tables",
        arguments={"owner": "X"},
        request_id="skill-tool-1",
        tenant_id="tenant-a",
        originator_subject="agent-x",
    )
    assert out == {"rows": [["T1"]]}
    assert host.calls == [
        {"server_id": "oracle", "tool_name": "list_tables", "originator_subject": "agent-x"}
    ]


class _StubRuntime:
    def __init__(self) -> None:
        self.decision_history_store = object()


def test_build_skill_executor_returns_executor_and_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    from cognic_agentos.core.skill.executor import SkillExecutor

    _patch(
        monkeypatch,
        manifests={
            "cognic-tool-oracle-schema": _mcp_manifest(),
            "cognic-skill-schema-summary": _skill_manifest(
                ["cognic-tool-oracle-schema/list_tables"]
            ),
        },
        skill_mds={"cognic-skill-schema-summary": _VALID_SKILL_MD},
    )
    reg = _Registry([_Cand("cognic-tool-oracle-schema"), _Cand("cognic-skill-schema-summary")])
    executor, hosted = skill_host.build_skill_executor(
        registry=reg,
        runtime=_StubRuntime(),
        settings=_Settings(),
        mcp_host=_StubMCPHost(),
        sandbox_backend=object(),
    )
    assert isinstance(executor, SkillExecutor)
    assert len(hosted) == 1
    assert hosted[0]["skill_id"] == "schema-summary"
    assert hosted[0]["declared_tools"] == ["cognic-tool-oracle-schema/list_tables"]
