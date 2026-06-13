"""Sprint 13.8 (ADR-002) — harness MCP-host builder + manifest->MCPServerEntry mapper."""

import logging
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from cognic_agentos.db.adapters.factory import build_adapters
from cognic_agentos.harness import build_runtime
from cognic_agentos.harness.mcp_host import (
    _MCP_HTTP_SERVED_TRANSPORTS,
    _map_registered_packs_to_servers,
    build_mcp_host,
)
from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate


def _litellm_yaml(tmp_path: Path) -> Path:
    """Minimal LiteLLM config (mirrors tests/unit/harness/test_runtime.py)."""
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n"
        "  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n"
        "      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return cfg


class _StubRegistry:
    def __init__(self, candidates: list[RegisteredPackCandidate]) -> None:
        self._c = candidates

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]:
        return iter(self._c)


def _cand(dist: str = "cognic-tool-foo", pkg: str = "cognic_tool_foo") -> RegisteredPackCandidate:
    return RegisteredPackCandidate(distribution_name=dist, package_name=pkg, signature_digest="dg")


_GOOD_MANIFEST = {
    "tool": {
        "cognic": {
            "mcp": {
                "transport": "streamable-http",
                "server_url": "https://mcp.example/sse",
                "scopes": ["mcp:tools"],
            }
        }
    },
    "risk_tier": {"tier": "customer_data_read"},
    "data_governance": {"data_classes": ["customer_pii"]},
}


def test_valid_pack_maps_to_server_entry(monkeypatch):
    monkeypatch.setattr(
        "cognic_agentos.harness.mcp_host.extract_pack_manifest", lambda **kw: _GOOD_MANIFEST
    )
    servers = _map_registered_packs_to_servers(_StubRegistry([_cand()]))
    e = servers["cognic-tool-foo"]
    assert e.server_url == "https://mcp.example/sse"
    assert e.transport_kind == "streamable-http"
    assert e.manifest_scopes == ("mcp:tools",)
    assert e.risk_tier == "customer_data_read"
    assert e.pack_signature_digest == "dg"  # carried through
    assert e.data_classes == ("customer_pii",)


def test_manifest_not_found_silent_skip(monkeypatch, caplog):
    from cognic_agentos.protocol.mcp_manifest import PackManifestNotFoundError

    def _raise(**kw):
        raise PackManifestNotFoundError("no manifest")

    monkeypatch.setattr("cognic_agentos.harness.mcp_host.extract_pack_manifest", _raise)
    with caplog.at_level(logging.WARNING):
        servers = _map_registered_packs_to_servers(_StubRegistry([_cand()]))
    assert servers == {}
    assert len(caplog.records) == 0  # ZERO warnings (no MCP intent)


def test_manifest_malformed_skips_with_one_warning(monkeypatch, caplog):
    from cognic_agentos.protocol.mcp_manifest import PackManifestMalformedError

    def _raise(**kw):
        raise PackManifestMalformedError("bad toml")

    monkeypatch.setattr("cognic_agentos.harness.mcp_host.extract_pack_manifest", _raise)
    with caplog.at_level(logging.WARNING):
        servers = _map_registered_packs_to_servers(_StubRegistry([_cand()]))
    assert servers == {}
    assert len(caplog.records) == 1  # exactly one structured warning


def test_absent_mcp_block_silent_skip(monkeypatch, caplog):
    monkeypatch.setattr(
        "cognic_agentos.harness.mcp_host.extract_pack_manifest",
        lambda **kw: {"tool": {"cognic": {}}},  # no mcp key
    )
    with caplog.at_level(logging.WARNING):
        servers = _map_registered_packs_to_servers(_StubRegistry([_cand()]))
    assert servers == {}
    assert len(caplog.records) == 0  # non-MCP pack → silent


def test_present_but_malformed_block_warns(monkeypatch, caplog):
    monkeypatch.setattr(
        "cognic_agentos.harness.mcp_host.extract_pack_manifest",
        lambda **kw: {
            "tool": {"cognic": {"mcp": {"transport": "streamable-http"}}}
        },  # no server_url
    )
    with caplog.at_level(logging.WARNING):
        servers = _map_registered_packs_to_servers(_StubRegistry([_cand()]))
    assert servers == {}
    assert len(caplog.records) == 1


@pytest.mark.parametrize("bad_scopes", [None, "mcp:tools", [123], [""], ["ok", ""]])
def test_missing_or_invalid_scopes_warns_and_skips(monkeypatch, caplog, bad_scopes):
    # scopes is a REQUIRED field — missing/non-list/empty-or-non-string entry →
    # warn+skip (NOT a silently-empty-scope server). `None` means absent.
    mcp = {"transport": "streamable-http", "server_url": "https://x/sse"}
    if bad_scopes is not None:
        mcp["scopes"] = bad_scopes
    monkeypatch.setattr(
        "cognic_agentos.harness.mcp_host.extract_pack_manifest",
        lambda **kw: {"tool": {"cognic": {"mcp": mcp}}, "risk_tier": {"tier": "read_only"}},
    )
    with caplog.at_level(logging.WARNING):
        servers = _map_registered_packs_to_servers(_StubRegistry([_cand()]))
    assert servers == {}
    assert len(caplog.records) == 1


def test_empty_scopes_list_is_valid(monkeypatch):
    # an empty scopes list [] passes admission, so the mapper serves it.
    mcp = {"transport": "streamable-http", "server_url": "https://x/sse", "scopes": []}
    monkeypatch.setattr(
        "cognic_agentos.harness.mcp_host.extract_pack_manifest",
        lambda **kw: {"tool": {"cognic": {"mcp": mcp}}, "risk_tier": {"tier": "read_only"}},
    )
    servers = _map_registered_packs_to_servers(_StubRegistry([_cand()]))
    assert servers["cognic-tool-foo"].manifest_scopes == ()


@pytest.mark.parametrize("bad_url", ["file:///etc/passwd", "gopher://x", "ftp://h/f"])
def test_non_http_server_url_warns_and_skips(monkeypatch, caplog, bad_url):
    # mirror the admission SSRF pre-filter — non-http/https scheme → warn+skip.
    mcp = {"transport": "streamable-http", "server_url": bad_url, "scopes": ["s"]}
    monkeypatch.setattr(
        "cognic_agentos.harness.mcp_host.extract_pack_manifest",
        lambda **kw: {"tool": {"cognic": {"mcp": mcp}}, "risk_tier": {"tier": "read_only"}},
    )
    with caplog.at_level(logging.WARNING):
        servers = _map_registered_packs_to_servers(_StubRegistry([_cand()]))
    assert servers == {}
    assert len(caplog.records) == 1


@pytest.mark.parametrize("bad_dc", ["oops", [123], [""], ["ok", ""]])
def test_malformed_data_classes_warns_and_skips(monkeypatch, caplog, bad_dc):
    # data_classes flows into the approval envelope — an explicit-but-malformed
    # shape warns+skips (NOT silently dropped). absent/empty is fine.
    mcp = {"transport": "streamable-http", "server_url": "https://x/sse", "scopes": ["s"]}
    monkeypatch.setattr(
        "cognic_agentos.harness.mcp_host.extract_pack_manifest",
        lambda **kw: {
            "tool": {"cognic": {"mcp": mcp}},
            "risk_tier": {"tier": "read_only"},
            "data_governance": {"data_classes": bad_dc},
        },
    )
    with caplog.at_level(logging.WARNING):
        servers = _map_registered_packs_to_servers(_StubRegistry([_cand()]))
    assert servers == {}
    assert len(caplog.records) == 1


def test_stdio_transport_not_served(monkeypatch):
    mcp = {"transport": "stdio", "server_url": "x", "scopes": ["s"]}
    monkeypatch.setattr(
        "cognic_agentos.harness.mcp_host.extract_pack_manifest",
        lambda **kw: {"tool": {"cognic": {"mcp": mcp}}, "risk_tier": {"tier": "read_only"}},
    )
    servers = _map_registered_packs_to_servers(_StubRegistry([_cand()]))
    assert servers == {}  # Wave-1 HTTP family only


def test_served_set_drift_against_capabilities_constant():
    # the mapper's HTTP served-set MUST equal mcp_capabilities._HTTP_TRANSPORT_VALUES
    # (test-only cross-import per the drift-detector doctrine; NO runtime import).
    from cognic_agentos.protocol.mcp_capabilities import _HTTP_TRANSPORT_VALUES

    assert _MCP_HTTP_SERVED_TRANSPORTS == _HTTP_TRANSPORT_VALUES


async def test_build_mcp_host_wires_approval_engine(
    memory_registry, memory_settings, tmp_path, monkeypatch
):
    monkeypatch.setattr(
        "cognic_agentos.harness.mcp_host.extract_pack_manifest", lambda **kw: _GOOD_MANIFEST
    )
    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory"}
    )
    adapters = build_adapters(s, registry=memory_registry)
    await adapters.open_all()
    runtime = await build_runtime(s, adapters)
    client = httpx.AsyncClient()
    try:
        host = build_mcp_host(
            registry=_StubRegistry([_cand()]),
            runtime=runtime,
            settings=s,
            http_client=client,
            vault_client=adapters.secret,
        )
        assert host._approval_engine is runtime.approval_engine  # 13.5b2 seam wired
        assert "cognic-tool-foo" in host._servers
    finally:
        await client.aclose()
        await runtime.aclose()
        await adapters.close_all()
