# tests/integration/pack_loop/test_manifest_validate.py
"""Proof 1a Task 3 — the single manifest is accepted by `agentos validate`.

This is the LOCK-2 "two consumers, one manifest" check. UNVERIFIED until run:
whether `agentos validate` tolerates a [tool.cognic.mcp] block on a tool-kind
manifest. A refusal here is a real finding to record in VALIDATION-RESULTS.md
and resolve (e.g. relocate the runtime block), NOT a test bug.
"""

import importlib.util
from pathlib import Path

import pytest

_PACK = Path(__file__).resolve().parents[3] / "examples" / "cognic-tool-search"


def test_manifest_exists_with_both_block_families() -> None:
    import tomllib

    manifest = (_PACK / "cognic-pack-manifest.toml").read_bytes()
    data = tomllib.loads(manifest.decode("utf-8"))
    # build-time top-level blocks
    assert data["pack"]["pack_id"] == "cognic-tool-search"
    assert data["pack"]["kind"] == "tool"
    assert {"agent_id", "display_name", "provider_organization", "provider_url"} <= set(
        data["identity"]
    )
    assert data["risk_tier"]["tier"] == "read_only"
    assert "data_classes" in data["data_governance"]
    assert "attestation_paths" in data["supply_chain"]
    # runtime nested block
    mcp = data["tool"]["cognic"]["mcp"]
    assert mcp["transport"] == "streamable-http"
    assert mcp["auth"] == "oauth-prm"
    assert mcp["server_url"] == "http://127.0.0.1:8765/mcp"
    assert mcp["scopes"] == ["mcp:tools"]


@pytest.mark.skipif(
    importlib.util.find_spec("cognic_tool_search") is None,
    reason="cognic-tool-search not installed; run `uv pip install -e examples/cognic-tool-search`",
)
def test_runtime_extracts_mcp_block_from_installed_package() -> None:
    """LOCK-2 guard: the `force-include` lands the root manifest as package data
    inside the wheel, so the RUNTIME path (`extract_pack_manifest` via
    `Distribution.locate_file`) reads the SAME `[tool.cognic.mcp]` block the CLI
    validates. Without this test the force-include could silently regress and the
    shape test above (which only parses the root file) would still pass — the
    commit's "force-include" claim would be unguarded. Skipped when the pack is
    not installed; the proof harness installs it editable.
    """
    from cognic_agentos.protocol.mcp_manifest import extract_pack_manifest

    manifest = extract_pack_manifest(
        distribution_name="cognic-tool-search", package_name="cognic_tool_search"
    )
    mcp = manifest["tool"]["cognic"]["mcp"]
    assert mcp["transport"] == "streamable-http"
    assert mcp["auth"] == "oauth-prm"
    assert mcp["server_url"] == "http://127.0.0.1:8765/mcp"
    assert mcp["scopes"] == ["mcp:tools"]
