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
from typing import Any

import pytest

from cognic_agentos.core.agent._types import LoadedAgentRecord
from cognic_agentos.harness import agent_host
from cognic_agentos.protocol.agent_manifest import AgentManifestNotFound
from cognic_agentos.protocol.mcp_manifest import PackManifestNotFoundError

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
    manifest: dict[str, Any] = {}
    if legacy:
        manifest["tool"] = {"cognic": {"agent": block}}
    else:
        manifest["agent"] = block
    if tier is not None:
        manifest["risk_tier"] = {"tier": tier}
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
