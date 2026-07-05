"""M6 Task A7 (ADR-025) — skill-pack hosting/ingestion.

The loader walks the trust-registered candidates, re-extracts each pack's
manifest ``[skill].declared_tools`` + ``SKILL.md`` WITHOUT importing pack code,
validates the SKILL.md shape, cross-checks declared tools against the registered
MCP servers, and yields a :class:`LoadedSkillRecord` per admitted skill. A
malformed SKILL.md / malformed declared_tools / unregistered-tool reference
warn-skips the pack (never crashes the boot), mirroring the M5 mapper doctrine.

M8 A7 (ADR-027) adds the instruction-only mode section at the foot: an
``[skill].mode = "instruction"`` pack hosts its SKILL.md guidance with NO
executable surface (no entry point, no declared tools, no runtime image).
"""

from __future__ import annotations

import logging
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


# ---------------------------------------------------------------------------
# M6 run-16 finding #17a — CallToolResult -> JSON-frameable tool-result
# projection. The broker frames the proxied result with stdlib json.dumps
# (sdk/skill_transport.encode_frame); an mcp SDK ``CallToolResult`` is a
# pydantic model and NOT json.dumps-able, so without projection EVERY real
# governed tool call dies in-band at the broker's result-frame arm. Tests
# use REAL ``mcp.types`` objects (the fixture-papers-over-production-gap
# lesson: the plain-dict stub above is exactly how #17 survived Part A).
# ---------------------------------------------------------------------------


class _PayloadHost:
    """Stub host returning a caller-supplied payload (a REAL mcp SDK object
    in the tests below) inside the ``CallResult``-shaped envelope."""

    def __init__(self, payload: Any) -> None:
        self._payload = payload

    async def call_tool(self, **_kwargs: Any) -> Any:
        return SimpleNamespace(payload=self._payload)


async def _project(payload: Any) -> Any:
    proxy = skill_host._MCPHostCallProxy(_PayloadHost(payload))
    return await proxy.call(
        server_id="cognic-tool-oracle-schema",
        tool_name="list_tables",
        arguments={"owner": "COGNIC"},
        request_id="skill-tool-1",
        tenant_id="tenant-a",
        originator_subject="agent-x",
    )


async def test_call_proxy_projects_structured_content() -> None:
    """Arm 2: ``structuredContent`` (the schema'd realization) wins — the
    action receives the tool handler's own dict, and it json-frames."""
    import json

    from mcp.types import CallToolResult, TextContent

    payload = CallToolResult(
        content=[TextContent(type="text", text='{"items": []}')],
        structuredContent={"items": [{"table_name": "ACCOUNTS"}]},
        isError=False,
    )
    out = await _project(payload)
    assert out == {"items": [{"table_name": "ACCOUNTS"}]}
    json.dumps({"ok": True, "result": out})  # the broker's frame contract


async def test_call_proxy_parses_single_text_content_json_object() -> None:
    """Arm 3 (the LIVE oracle case): FastMCP 1.27 bare ``-> dict`` handlers
    produce NO structuredContent — the tool dict rides only as JSON text in
    the single TextContent block. The projection recovers it."""
    import json

    from mcp.types import CallToolResult, TextContent

    payload = CallToolResult(
        content=[
            TextContent(type="text", text='{"items": [{"table_name": "ACCOUNTS"}], "count": 1}')
        ],
        isError=False,
    )
    assert payload.structuredContent is None
    out = await _project(payload)
    assert out == {"items": [{"table_name": "ACCOUNTS"}], "count": 1}
    json.dumps({"ok": True, "result": out})


async def test_call_proxy_real_fastmcp_bare_dict_handler_end_to_end() -> None:
    """Integration-grade: a REAL in-memory FastMCP server with an
    oracle-shaped bare ``-> dict`` handler, driven through a REAL mcp
    client session — the exact wire realization run 16 failed on."""
    import json

    from mcp.server.fastmcp import FastMCP
    from mcp.shared.memory import create_connected_server_and_client_session

    server = FastMCP("probe")

    # The BARE ``dict`` annotation is the fixture: FastMCP 1.27 generates no
    # output schema for it (structuredContent=None — the text-only realization
    # this test exists to pin), while ``dict[str, Any]`` WOULD populate
    # structuredContent and silently exercise arm 2 instead.
    @server.tool(name="list_tables", description="probe")
    async def list_tables(owner: str) -> dict:  # type: ignore[type-arg]
        return {"items": [{"table_name": "ACCOUNTS"}], "owner": owner}

    class _FastMCPBackedHost:
        async def call_tool(self, *, tool_name: str, arguments: dict[str, Any], **_: Any) -> Any:
            async with create_connected_server_and_client_session(server._mcp_server) as session:
                result = await session.call_tool(name=tool_name, arguments=arguments)
            # Realization guard: if a future mcp bump starts populating
            # structuredContent for bare-dict handlers, this test would
            # silently stop exercising the text-parse arm — fail loud instead.
            assert result.structuredContent is None
            return SimpleNamespace(payload=result)

    proxy = skill_host._MCPHostCallProxy(_FastMCPBackedHost())
    out = await proxy.call(
        server_id="cognic-tool-oracle-schema",
        tool_name="list_tables",
        arguments={"owner": "COGNIC"},
        request_id="skill-tool-1",
        tenant_id="tenant-a",
        originator_subject="agent-x",
    )
    assert out == {"items": [{"table_name": "ACCOUNTS"}], "owner": "COGNIC"}
    json.dumps({"ok": True, "result": out})


async def test_call_proxy_prose_text_falls_back_to_envelope() -> None:
    """Arm 4: no structured output and the text is not a JSON object —
    the JSON-mode model dump is the honest, still-frameable fallback."""
    import json

    from mcp.types import CallToolResult, TextContent

    payload = CallToolResult(
        content=[TextContent(type="text", text="plain prose, not JSON")],
        isError=False,
    )
    out = await _project(payload)
    assert isinstance(out, dict)
    assert out["content"][0]["text"] == "plain prose, not JSON"
    assert out["isError"] is False
    json.dumps({"ok": True, "result": out})


async def test_call_proxy_text_json_non_object_falls_back_to_envelope() -> None:
    """Arm 4 boundary: text that parses to a JSON ARRAY (not an object)
    must NOT be returned bare — the runner-side transport requires a
    dict result (``MalformedFrame`` otherwise)."""
    import json

    from mcp.types import CallToolResult, TextContent

    payload = CallToolResult(
        content=[TextContent(type="text", text='["a", "b"]')],
        isError=False,
    )
    out = await _project(payload)
    assert isinstance(out, dict)
    assert out["content"][0]["text"] == '["a", "b"]'
    json.dumps({"ok": True, "result": out})


async def test_call_proxy_multiple_text_blocks_fall_back_to_envelope() -> None:
    """Arm 3 requires EXACTLY ONE text block — with two, there is no
    single 'handler dict' to recover; the envelope preserves both."""
    import json

    from mcp.types import CallToolResult, TextContent

    payload = CallToolResult(
        content=[
            TextContent(type="text", text='{"a": 1}'),
            TextContent(type="text", text='{"b": 2}'),
        ],
        isError=False,
    )
    out = await _project(payload)
    assert isinstance(out, dict)
    assert len(out["content"]) == 2
    json.dumps({"ok": True, "result": out})


async def test_call_proxy_is_error_raises_safe_local_exception() -> None:
    """Arm 1 (fail-closed): a tool-level MCP error must NOT masquerade as
    a skill success result. The raise happens BEFORE projection, and the
    exception message NEVER carries the tool's content text (may hold SQL
    fragments / data) — the broker logs unknown-exception detail as a
    sha256 only."""
    from mcp.types import CallToolResult, TextContent

    payload = CallToolResult(
        content=[TextContent(type="text", text="ORA-00942: table or view SECRET_T does not exist")],
        isError=True,
    )
    with pytest.raises(skill_host.MCPToolResultError) as excinfo:
        await _project(payload)
    assert "ORA-00942" not in str(excinfo.value)
    assert "SECRET_T" not in str(excinfo.value)
    # The short closed marker the broker WARNING surfaces as downstream_reason.
    assert excinfo.value.reason == "mcp_tool_result_is_error"


async def test_call_proxy_plain_payload_passes_through_unchanged() -> None:
    """Arm 5: non-model payloads (no ``model_dump``) pass through — the
    back-compat contract for stub hosts + any host returning plain data."""
    import json

    out = await _project({"rows": [["T1"]]})
    assert out == {"rows": [["T1"]]}
    json.dumps({"ok": True, "result": out})


# ---------------------------------------------------------------------------
# M8 A7 (ADR-027) — instruction-only skill mode. Absent mode -> "executable"
# (every existing pack byte-unchanged; the whole suite above passes untouched);
# instruction records SKIP the declared-tools gate, the entry-point gate, the
# MCP cross-check, and runtime-image resolution; they REFUSE (warn-skip) a pack
# that declares an executable surface anyway; referenced_tools is
# non-authoritative reviewer evidence — warn ONLY, never a refusal.
# ---------------------------------------------------------------------------

_VALID_INSTRUCTION_SKILL_MD = """---
name: schema-notes
description: Explains how to reason about the schema.
---
Read the table list, then describe relationships deterministically.
"""


def _instruction_manifest(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    block: dict[str, Any] = {"mode": "instruction"}
    if extra:
        block.update(extra)
    return {"skill": block}


def test_instruction_pack_hosted_without_executable_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-skill-notes": _instruction_manifest()},
        skill_mds={"cognic-skill-notes": _VALID_INSTRUCTION_SKILL_MD},
    )
    reg = _Registry([_Cand("cognic-skill-notes")])
    records = skill_host._build_skill_records(
        registry=reg, settings=_Settings(), registered_mcp_servers=frozenset()
    )
    assert set(records) == {"schema-notes"}
    rec = records["schema-notes"]
    assert rec.mode == "instruction"
    assert rec.entry_point_name is None
    assert rec.declared_tools == ()
    assert rec.runtime_image is None
    assert rec.description == "Explains how to reason about the schema."
    assert rec.skill_md_body is not None
    assert "Read the table list" in rec.skill_md_body
    assert rec.registered is True


def test_executable_records_carry_executable_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Absent-mode default pinned: the pre-A7 manifest shape (no ``mode`` key)
    yields an executable-mode record with no instruction-only payload."""
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
    servers = skill_host._registered_mcp_server_ids(reg)
    records = skill_host._build_skill_records(
        registry=reg, settings=_Settings(), registered_mcp_servers=servers
    )
    rec = records["schema-summary"]
    assert rec.mode == "executable"
    assert rec.skill_md_body is None
    assert rec.description == ""


def test_invalid_mode_value_warn_skips(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-skill-weird": {"skill": {"mode": "interpretive-dance"}}},
        skill_mds={"cognic-skill-weird": _VALID_INSTRUCTION_SKILL_MD},
    )
    reg = _Registry([_Cand("cognic-skill-weird")])
    with caplog.at_level(logging.WARNING):
        records = skill_host._build_skill_records(
            registry=reg, settings=_Settings(), registered_mcp_servers=frozenset()
        )
    assert records == {}
    assert "skill.mode_invalid" in caplog.text


def test_instruction_pack_with_declared_tools_warn_skips(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-skill-notes": _instruction_manifest({"declared_tools": ["srv/tool"]})},
        skill_mds={"cognic-skill-notes": _VALID_INSTRUCTION_SKILL_MD},
    )
    reg = _Registry([_Cand("cognic-skill-notes")])
    with caplog.at_level(logging.WARNING):
        records = skill_host._build_skill_records(
            registry=reg, settings=_Settings(), registered_mcp_servers=frozenset()
        )
    assert records == {}
    assert "skill.instruction_mode_declares_executable" in caplog.text


def test_instruction_pack_with_entry_point_warn_skips(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-skill-notes": _instruction_manifest()},
        skill_mds={"cognic-skill-notes": _VALID_INSTRUCTION_SKILL_MD},
    )
    monkeypatch.setattr(skill_host, "_declares_skill_entry_point", lambda d: True)
    reg = _Registry([_Cand("cognic-skill-notes")])
    with caplog.at_level(logging.WARNING):
        records = skill_host._build_skill_records(
            registry=reg, settings=_Settings(), registered_mcp_servers=frozenset()
        )
    assert records == {}
    assert "skill.instruction_mode_declares_executable" in caplog.text


def test_instruction_pack_empty_declared_tools_is_hosted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``declared_tools = []`` is NOT an executable surface (partition-aligned
    with the runtime truthiness rule) — the instruction pack still hosts."""
    _patch(
        monkeypatch,
        manifests={"cognic-skill-notes": _instruction_manifest({"declared_tools": []})},
        skill_mds={"cognic-skill-notes": _VALID_INSTRUCTION_SKILL_MD},
    )
    reg = _Registry([_Cand("cognic-skill-notes")])
    records = skill_host._build_skill_records(
        registry=reg, settings=_Settings(), registered_mcp_servers=frozenset()
    )
    assert set(records) == {"schema-notes"}


def test_instruction_referenced_tools_unregistered_warns_but_hosts(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Unresolved referenced_tools entries are reviewer evidence, not an
    authority claim — warn log ONLY, the skill is still hosted."""
    _patch(
        monkeypatch,
        manifests={
            "cognic-skill-notes": _instruction_manifest(
                {"referenced_tools": ["cognic-tool-ghost/list_tables"]}
            )
        },
        skill_mds={"cognic-skill-notes": _VALID_INSTRUCTION_SKILL_MD},
    )
    reg = _Registry([_Cand("cognic-skill-notes")])
    with caplog.at_level(logging.WARNING):
        records = skill_host._build_skill_records(
            registry=reg, settings=_Settings(), registered_mcp_servers=frozenset()
        )
    assert set(records) == {"schema-notes"}
    assert "skill.referenced_tool_unregistered" in caplog.text


def test_instruction_referenced_tools_malformed_warns_but_hosts(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch(
        monkeypatch,
        manifests={"cognic-skill-notes": _instruction_manifest({"referenced_tools": "not-a-list"})},
        skill_mds={"cognic-skill-notes": _VALID_INSTRUCTION_SKILL_MD},
    )
    reg = _Registry([_Cand("cognic-skill-notes")])
    with caplog.at_level(logging.WARNING):
        records = skill_host._build_skill_records(
            registry=reg, settings=_Settings(), registered_mcp_servers=frozenset()
        )
    assert set(records) == {"schema-notes"}
    assert "skill.referenced_tools_malformed" in caplog.text


def test_instruction_referenced_tools_registered_hosts_without_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _patch(
        monkeypatch,
        manifests={
            "cognic-tool-oracle-schema": _mcp_manifest(),
            "cognic-skill-notes": _instruction_manifest(
                {"referenced_tools": ["cognic-tool-oracle-schema/list_tables"]}
            ),
        },
        skill_mds={"cognic-skill-notes": _VALID_INSTRUCTION_SKILL_MD},
    )
    reg = _Registry([_Cand("cognic-tool-oracle-schema"), _Cand("cognic-skill-notes")])
    servers = skill_host._registered_mcp_server_ids(reg)
    with caplog.at_level(logging.WARNING):
        records = skill_host._build_skill_records(
            registry=reg, settings=_Settings(), registered_mcp_servers=servers
        )
    assert set(records) == {"schema-notes"}
    assert "skill.referenced_tool_unregistered" not in caplog.text


def test_instruction_pack_missing_skill_md_warn_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """Instruction mode is SKILL.md-only hosting — a missing SKILL.md still
    warn-skips exactly like the executable path (the body IS the skill)."""
    _patch(monkeypatch, manifests={"cognic-skill-notes": _instruction_manifest()}, skill_mds={})
    reg = _Registry([_Cand("cognic-skill-notes")])
    records = skill_host._build_skill_records(
        registry=reg, settings=_Settings(), registered_mcp_servers=frozenset()
    )
    assert records == {}


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
