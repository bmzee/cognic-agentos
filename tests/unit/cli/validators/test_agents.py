"""M8 A8 (ADR-027) — `[agent]` block + `AGENT.md` validator regressions.

Tests cover:

  - Kind gating: the ``[agent]`` block is MANDATORY on ``kind = "agent"``
    packs (``agent_manifest_block_missing``); non-agent packs without one are
    silent; non-agent packs WITH one are validated (block presence fires the
    arms for every kind — mirroring ``validators/skills.py``), never
    kind-constraint-refused.
  - persona_path: the identity.py resolve-then-validate discipline (reject
    absolute + ``..`` + backslash BEFORE resolve; then resolve; then
    containment) + build-time parse/validate of the AGENT.md file via the
    REUSED skill_manifest frontmatter contract.
  - requested_skills / requested_tools: shape / id-syntax / dedupe (the
    data_governance DLP-hook-list validation pattern).
  - max_steps: optional int 1..32; bool is not int.
  - Orchestrator: ``[mcp]`` forbidden on agent packs
    (``agent_pack_kind_constraint_violated`` + ``mcp_block_forbidden``) while
    ``[a2a]`` stays LEGAL; hook-pack constraint behavior unchanged; the
    agents validator dispatches after skills.
  - Closed-enum vocabulary: 5 ``agent_manifest_*`` reasons owned by
    ``validators/agents.py`` + the orchestrator-owned
    ``agent_pack_kind_constraint_violated``.
"""

from __future__ import annotations

import typing
from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.cli import _VALIDATOR_REASON_OWNERSHIP, ValidatorFinding, ValidatorReason
from cognic_agentos.cli.validators import agents

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_AGENT_MD = (
    "---\n"
    "name: schema-advisor\n"
    "description: Answers schema questions through governed skills and tools.\n"
    "---\n"
    "\n"
    "# Persona\n"
    "\n"
    "You are a schema advisor. Use read_skill before invoking any skill.\n"
)


def _write_agent_md(
    pack_path: Path, *, text: str = _VALID_AGENT_MD, name: str = "AGENT.md"
) -> None:
    (pack_path / name).write_text(text, encoding="utf-8")


def _data(
    *,
    kind: str = "agent",
    block: Any = None,
    legacy_block: Any = None,
    omit_block: bool = False,
) -> dict[str, Any]:
    """Build a parsed-manifest dict. ``block`` lands at the canonical
    top-level ``[agent]`` path; ``legacy_block`` at ``[tool.cognic.agent]``."""
    data: dict[str, Any] = {"pack": {"pack_id": "cognic-agent-x", "kind": kind}}
    if not omit_block and block is not None:
        data["agent"] = block
    if legacy_block is not None:
        data["tool"] = {"cognic": {"agent": legacy_block}}
    return data


def _valid_block(**overrides: Any) -> dict[str, Any]:
    block: dict[str, Any] = {
        "persona_path": "AGENT.md",
        "requested_skills": ["schema-summary"],
        "requested_tools": ["cognic-tool-oracle-schema/describe_table"],
        "max_steps": 8,
    }
    block.update(overrides)
    return block


def _modes(findings: list[ValidatorFinding], reason: str) -> set[str | None]:
    return {f.payload.get("failure_mode") for f in findings if f.reason == reason}


# ---------------------------------------------------------------------------
# (a) Kind gating
# ---------------------------------------------------------------------------


def test_agent_kind_without_block_refuses_block_missing(tmp_path: Path) -> None:
    findings = agents.validate(_data(omit_block=True), tmp_path)
    assert [f.reason for f in findings] == ["agent_manifest_block_missing"]
    assert "block_absent" in _modes(findings, "agent_manifest_block_missing")


def test_non_agent_kind_without_block_is_silent(tmp_path: Path) -> None:
    findings = agents.validate(_data(kind="tool", omit_block=True), tmp_path)
    assert findings == []


def test_non_agent_pack_with_valid_block_is_validated_clean(tmp_path: Path) -> None:
    """Mirrors validators/skills.py: a non-agent pack declaring the block is
    VALIDATED (block presence fires the arms for every kind), never
    kind-constraint-refused."""
    _write_agent_md(tmp_path)
    findings = agents.validate(_data(kind="tool", block=_valid_block()), tmp_path)
    assert findings == []


def test_non_agent_pack_with_malformed_block_refuses(tmp_path: Path) -> None:
    _write_agent_md(tmp_path)
    findings = agents.validate(_data(kind="tool", block=_valid_block(max_steps=0)), tmp_path)
    assert any(f.reason == "agent_manifest_max_steps_invalid" for f in findings)


def test_block_not_table_refuses(tmp_path: Path) -> None:
    findings = agents.validate(_data(block="not-a-table"), tmp_path)
    assert "block_not_table" in _modes(findings, "agent_manifest_block_missing")


# ---------------------------------------------------------------------------
# (b) Valid packs — canonical + legacy block paths
# ---------------------------------------------------------------------------


def test_valid_agent_pack_validates_clean(tmp_path: Path) -> None:
    _write_agent_md(tmp_path)
    findings = agents.validate(_data(block=_valid_block()), tmp_path)
    assert findings == []


def test_valid_agent_pack_via_legacy_block_validates_clean(tmp_path: Path) -> None:
    _write_agent_md(tmp_path)
    findings = agents.validate(_data(omit_block=True, legacy_block=_valid_block()), tmp_path)
    assert findings == []


def test_persona_path_absent_defaults_to_agent_md(tmp_path: Path) -> None:
    """persona_path is conventionally ``AGENT.md``; an absent field validates
    the default location so the scaffold's minimal block stays valid."""
    _write_agent_md(tmp_path)
    block = _valid_block()
    del block["persona_path"]
    findings = agents.validate(_data(block=block), tmp_path)
    assert findings == []


def test_requested_lists_and_max_steps_optional(tmp_path: Path) -> None:
    _write_agent_md(tmp_path)
    findings = agents.validate(_data(block={"persona_path": "AGENT.md"}), tmp_path)
    assert findings == []


def test_both_block_paths_validated_with_block_path_payload(tmp_path: Path) -> None:
    _write_agent_md(tmp_path)
    findings = agents.validate(
        _data(block=_valid_block(max_steps=0), legacy_block=_valid_block(max_steps=99)),
        tmp_path,
    )
    block_paths = {
        f.payload.get("block_path")
        for f in findings
        if f.reason == "agent_manifest_max_steps_invalid"
    }
    assert block_paths == {"agent", "tool.cognic.agent"}


# ---------------------------------------------------------------------------
# (c) persona_path arms — resolve-then-validate discipline
# ---------------------------------------------------------------------------


def test_persona_path_absolute_rejected_before_resolve(tmp_path: Path) -> None:
    findings = agents.validate(_data(block=_valid_block(persona_path="/etc/hosts")), tmp_path)
    assert "absolute_path_rejected" in _modes(findings, "agent_manifest_persona_path_invalid")


def test_persona_path_traversal_rejected_before_resolve(tmp_path: Path) -> None:
    # ``..`` is rejected BEFORE any resolve() call (resolve-then-validate
    # step 1) — even when the target happens to exist.
    outside = tmp_path.parent / "outside-agent.md"
    outside.write_text(_VALID_AGENT_MD, encoding="utf-8")
    findings = agents.validate(
        _data(block=_valid_block(persona_path=f"../{outside.name}")), tmp_path
    )
    assert "path_escape_rejected" in _modes(findings, "agent_manifest_persona_path_invalid")


def test_persona_path_symlink_escape_fails_containment(tmp_path: Path) -> None:
    # A clean-looking relative path whose resolution escapes the pack root
    # (via a symlink) fails the containment step.
    outside_dir = tmp_path.parent / "outside-personas"
    outside_dir.mkdir(exist_ok=True)
    (outside_dir / "AGENT.md").write_text(_VALID_AGENT_MD, encoding="utf-8")
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "personas").symlink_to(outside_dir)
    findings = agents.validate(_data(block=_valid_block(persona_path="personas/AGENT.md")), pack)
    assert "path_escape_rejected" in _modes(findings, "agent_manifest_persona_path_invalid")


def test_persona_path_file_not_found(tmp_path: Path) -> None:
    findings = agents.validate(_data(block=_valid_block()), tmp_path)  # no AGENT.md written
    assert "file_not_found" in _modes(findings, "agent_manifest_persona_path_invalid")


def test_persona_path_not_valid_agent_md(tmp_path: Path) -> None:
    _write_agent_md(tmp_path, text="no frontmatter fence here\n")
    findings = agents.validate(_data(block=_valid_block()), tmp_path)
    assert "not_valid_agent_md" in _modes(findings, "agent_manifest_persona_path_invalid")


def test_persona_path_empty_body_not_valid_agent_md(tmp_path: Path) -> None:
    _write_agent_md(tmp_path, text="---\nname: schema-advisor\ndescription: Valid.\n---\n\n")
    findings = agents.validate(_data(block=_valid_block()), tmp_path)
    assert "not_valid_agent_md" in _modes(findings, "agent_manifest_persona_path_invalid")


@pytest.mark.parametrize("value", [42, "", "   ", "AUTHOR-FILL: path to the persona"])
def test_persona_path_value_invalid(tmp_path: Path, value: Any) -> None:
    findings = agents.validate(_data(block=_valid_block(persona_path=value)), tmp_path)
    assert "value_invalid" in _modes(findings, "agent_manifest_persona_path_invalid")


# ---------------------------------------------------------------------------
# (d) requested_skills arms
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "mode_expected"),
    [
        ("schema-summary", "invalid_shape"),
        ([42], "invalid_shape"),
        (["Bad_Skill_ID"], "invalid_skill_id"),
        (["-lead"], "invalid_skill_id"),
        (["schema-summary", "schema-summary"], "duplicate"),
    ],
    ids=["not-a-list", "non-string", "bad-id", "lead-hyphen", "duplicate"],
)
def test_requested_skills_arms(tmp_path: Path, value: Any, mode_expected: str) -> None:
    _write_agent_md(tmp_path)
    findings = agents.validate(_data(block=_valid_block(requested_skills=value)), tmp_path)
    assert mode_expected in _modes(findings, "agent_manifest_requested_skills_invalid")


def test_requested_skills_empty_list_valid(tmp_path: Path) -> None:
    _write_agent_md(tmp_path)
    findings = agents.validate(_data(block=_valid_block(requested_skills=[])), tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# (e) requested_tools arms
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "mode_expected"),
    [
        ("a/b", "invalid_shape"),
        ([42], "invalid_shape"),
        (["describe_table"], "invalid_tool_identity"),
        (["/describe_table"], "invalid_tool_identity"),
        (["srv/"], "invalid_tool_identity"),
        (["a/b", "a/b"], "duplicate"),
    ],
    ids=["not-a-list", "non-string", "no-slash", "empty-server", "empty-tool", "duplicate"],
)
def test_requested_tools_arms(tmp_path: Path, value: Any, mode_expected: str) -> None:
    _write_agent_md(tmp_path)
    findings = agents.validate(_data(block=_valid_block(requested_tools=value)), tmp_path)
    assert mode_expected in _modes(findings, "agent_manifest_requested_tools_invalid")


def test_requested_tools_multi_slash_matches_runtime_partition_rule(tmp_path: Path) -> None:
    """The first ``/`` splits; a tool_name containing further slashes is
    representable at runtime and MUST validate clean."""
    _write_agent_md(tmp_path)
    findings = agents.validate(_data(block=_valid_block(requested_tools=["a/b/c"])), tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# (f) max_steps arms
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", [0, 33, -1, True, False, "5", 1.5])
def test_max_steps_invalid_values_refuse(tmp_path: Path, value: Any) -> None:
    _write_agent_md(tmp_path)
    findings = agents.validate(_data(block=_valid_block(max_steps=value)), tmp_path)
    assert any(f.reason == "agent_manifest_max_steps_invalid" for f in findings)


@pytest.mark.parametrize("value", [1, 32, 16])
def test_max_steps_bounds_valid(tmp_path: Path, value: Any) -> None:
    _write_agent_md(tmp_path)
    findings = agents.validate(_data(block=_valid_block(max_steps=value)), tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# (g) Orchestrator — forbidden [mcp] on agent packs; [a2a] stays legal;
#     dispatch order; hook behavior unchanged
# ---------------------------------------------------------------------------


def test_agent_pack_declaring_mcp_refused_by_orchestrator(tmp_path: Path) -> None:
    from cognic_agentos.cli.validate import _check_pack_kind_constraints

    data: dict[str, Any] = {
        "pack": {"pack_id": "cognic-agent-x", "kind": "agent"},
        "mcp": {"transport": "http"},
    }
    findings = _check_pack_kind_constraints(data, tmp_path / "cognic-pack-manifest.toml")
    assert len(findings) == 1
    f = findings[0]
    assert f.reason == "agent_pack_kind_constraint_violated"
    assert f.payload["failure_mode"] == "mcp_block_forbidden"
    assert f.payload["block_path"] == "mcp"


def test_agent_pack_declaring_legacy_mcp_refused(tmp_path: Path) -> None:
    from cognic_agentos.cli.validate import _check_pack_kind_constraints

    data: dict[str, Any] = {
        "pack": {"pack_id": "cognic-agent-x", "kind": "agent"},
        "tool": {"cognic": {"mcp": {"transport": "http"}}},
    }
    findings = _check_pack_kind_constraints(data, tmp_path / "cognic-pack-manifest.toml")
    assert len(findings) == 1
    assert findings[0].reason == "agent_pack_kind_constraint_violated"
    assert findings[0].payload["block_path"] == "tool.cognic.mcp"


def test_agent_pack_declaring_a2a_is_legal(tmp_path: Path) -> None:
    """BOTH directions pinned: [mcp] forbidden (above), [a2a] LEGAL — agent
    packs are A2A-speaking by design."""
    from cognic_agentos.cli.validate import _check_pack_kind_constraints

    data: dict[str, Any] = {
        "pack": {"pack_id": "cognic-agent-x", "kind": "agent"},
        "a2a": {"capabilities": {}},
    }
    findings = _check_pack_kind_constraints(data, tmp_path / "cognic-pack-manifest.toml")
    assert findings == []


def test_hook_pack_constraint_behavior_unchanged(tmp_path: Path) -> None:
    """The A8 generalisation keeps the hook arm byte-compatible: same reason,
    same failure_mode, same 'hook packs are not A2A-speaking' message copy."""
    from cognic_agentos.cli.validate import _check_pack_kind_constraints

    data: dict[str, Any] = {
        "pack": {"pack_id": "cognic-hook-x", "kind": "hook"},
        "a2a": {"capabilities": {}},
    }
    findings = _check_pack_kind_constraints(data, tmp_path / "cognic-pack-manifest.toml")
    assert len(findings) == 1
    f = findings[0]
    assert f.reason == "hook_pack_kind_constraint_violated"
    assert f.payload["failure_mode"] == "a2a_block_forbidden"
    assert "hook packs are not A2A-speaking" in f.message


def test_agents_validator_dispatched_after_skills(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cognic_agentos.cli.validate import run_validators

    manifest = (
        '[pack]\npack_id = "cognic-agent-x"\nkind = "agent"\n\n'
        "[identity]\n[data_governance]\n[risk_tier]\n[supply_chain]\n"
    )
    (tmp_path / "cognic-pack-manifest.toml").write_text(manifest, encoding="utf-8")
    order: list[str] = []

    def _spy(tag: str) -> Any:
        def _validate(data: dict[str, Any], pack_path: Path) -> list[Any]:
            order.append(tag)
            return []

        return _validate

    # run_validators resolves ``skills.validate`` / ``agents.validate`` off the
    # validator MODULES at call time — patching the modules' attributes
    # intercepts the orchestrator's dispatch.
    monkeypatch.setattr("cognic_agentos.cli.validators.skills.validate", _spy("skills"))
    monkeypatch.setattr("cognic_agentos.cli.validators.agents.validate", _spy("agents"))
    run_validators(tmp_path)
    assert order == ["skills", "agents"]


# ---------------------------------------------------------------------------
# (h) Severity + closed-enum vocabulary
# ---------------------------------------------------------------------------


def test_all_findings_are_refusal_severity(tmp_path: Path) -> None:
    findings = agents.validate(
        _data(block=_valid_block(max_steps=0, requested_skills=["Bad_ID"])), tmp_path
    )
    assert findings, "expected findings from the compound-failure fixture"
    assert {f.severity for f in findings} == {"refusal"}


_AGENT_MANIFEST_REASONS: tuple[str, ...] = (
    "agent_manifest_block_missing",
    "agent_manifest_persona_path_invalid",
    "agent_manifest_requested_skills_invalid",
    "agent_manifest_requested_tools_invalid",
    "agent_manifest_max_steps_invalid",
)


@pytest.mark.parametrize("reason", _AGENT_MANIFEST_REASONS)
def test_agent_manifest_reason_in_validator_reason_literal(reason: str) -> None:
    assert reason in typing.get_args(ValidatorReason)


@pytest.mark.parametrize("reason", _AGENT_MANIFEST_REASONS)
def test_agent_manifest_reason_owned_by_agents_validator(reason: str) -> None:
    assert _VALIDATOR_REASON_OWNERSHIP[reason] == "validators/agents.py"  # type: ignore[index]


def test_agent_pack_kind_constraint_owned_by_orchestrator() -> None:
    assert "agent_pack_kind_constraint_violated" in typing.get_args(ValidatorReason)
    assert _VALIDATOR_REASON_OWNERSHIP["agent_pack_kind_constraint_violated"] == "validate.py"
