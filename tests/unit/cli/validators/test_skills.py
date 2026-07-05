"""M6 A9 (ADR-025) — `[skill]` block + `SKILL.md` validator regressions.

Tests cover:

  - Intent gating: silent when NEITHER a ``[skill]`` block (either path) NOR
    a pack-root ``SKILL.md`` is present — for every kind INCLUDING
    ``kind = "skill"`` (the legacy Sprint-7A composition-skill carve-out:
    ``examples/cognic-skill-example-minimal`` ships neither and stays valid).
  - A valid M6 skill pack (block + SKILL.md + exactly-one ``cognic.skills``
    entry point) validates clean — canonical AND legacy block paths.
  - Every refusal arm: block shape; SKILL.md missing / blank / malformed
    (protocol closed-enum reasons ride ``payload.failure_mode``);
    ``declared_tools`` shape (absent / not-list / empty / non-string /
    malformed identity / duplicate / AUTHOR-FILL); entry-point cross-check
    (absent / ambiguous / pyproject unparseable).
  - The ``<server_id>/<tool_name>`` identity rule is PARTITION-aligned with
    the runtime enforcement (``core/skill/broker.py`` +
    ``harness/skill_host.py`` both use ``str.partition("/")``): the first
    ``/`` splits; both halves must be non-empty; a tool_name containing
    further slashes is representable at runtime and therefore accepted here.
  - Closed-enum vocabulary: the 5 ``skill_manifest_*`` reasons live in
    ``ValidatorReason`` + are owned by ``validators/skills.py``.
"""

from __future__ import annotations

import typing
from pathlib import Path
from typing import Any

import pytest

from cognic_agentos.cli import _VALIDATOR_REASON_OWNERSHIP, ValidatorFinding, ValidatorReason
from cognic_agentos.cli.validators import skills

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_SKILL_MD = (
    "---\n"
    "name: cognic-skill-x\n"
    "description: Summarises a table schema through governed MCP tool calls.\n"
    "---\n"
    "\n"
    "# Instructions\n"
    "\n"
    "Call the declared tool, then summarise the result deterministically.\n"
)

_VALID_PYPROJECT = (
    "[project]\n"
    'name = "cognic-skill-x"\n'
    'version = "0.1.0"\n'
    "\n"
    '[project.entry-points."cognic.skills"]\n'
    'x = "cognic_skill_x.skill:XSkill"\n'
)

_VALID_TOOLS = ["cognic-tool-oracle-schema/describe_table"]


def _write_pack_files(
    pack_path: Path,
    *,
    skill_md: str | None = _VALID_SKILL_MD,
    pyproject: str | None = _VALID_PYPROJECT,
) -> None:
    """Materialise the on-disk halves of a skill pack (SKILL.md +
    pyproject.toml); ``None`` omits the file."""
    if skill_md is not None:
        (pack_path / "SKILL.md").write_text(skill_md)
    if pyproject is not None:
        (pack_path / "pyproject.toml").write_text(pyproject)


def _data(
    *,
    kind: str = "skill",
    block: Any = None,
    legacy_block: Any = None,
    omit_block: bool = False,
) -> dict[str, Any]:
    """Build a parsed-manifest dict. ``block`` lands at the canonical
    top-level ``[skill]`` path; ``legacy_block`` at ``[tool.cognic.skill]``."""
    data: dict[str, Any] = {"pack": {"pack_id": "cognic-skill-x", "kind": kind}}
    if not omit_block and block is not None:
        data["skill"] = block
    if legacy_block is not None:
        data["tool"] = {"cognic": {"skill": legacy_block}}
    return data


def _modes(findings: list[ValidatorFinding], reason: str) -> set[str | None]:
    return {f.payload.get("failure_mode") for f in findings if f.reason == reason}


# ---------------------------------------------------------------------------
# (a) Intent gating — silent paths
# ---------------------------------------------------------------------------


def test_non_skill_pack_without_block_or_skill_md_is_silent(tmp_path: Path) -> None:
    findings = skills.validate(_data(kind="tool", omit_block=True), tmp_path)
    assert findings == []


def test_skill_kind_without_block_or_skill_md_is_silent(tmp_path: Path) -> None:
    """The legacy carve-out pin: ``kind = "skill"`` predates M6 (the
    Sprint-7A SDK ``Skill.execute()`` composition kind — e.g. the reference
    pack at examples/cognic-skill-example-minimal). A skill-kind pack with
    neither M6 signal (no [skill] block, no SKILL.md) is NOT an M6
    executable skill and MUST stay silent — mirroring the runtime loader
    (harness/skill_host.py hosts by block presence, never by kind)."""
    findings = skills.validate(_data(kind="skill", omit_block=True), tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# (b) Valid M6 skill pack — clean on both block paths
# ---------------------------------------------------------------------------


def test_valid_skill_pack_validates_clean(tmp_path: Path) -> None:
    _write_pack_files(tmp_path)
    findings = skills.validate(_data(block={"declared_tools": list(_VALID_TOOLS)}), tmp_path)
    assert findings == []


def test_valid_skill_pack_via_legacy_block_validates_clean(tmp_path: Path) -> None:
    _write_pack_files(tmp_path)
    findings = skills.validate(
        _data(omit_block=True, legacy_block={"declared_tools": list(_VALID_TOOLS)}), tmp_path
    )
    assert findings == []


def test_non_skill_pack_with_valid_block_is_validated_clean(tmp_path: Path) -> None:
    """Mirrors validators/hooks.py: a non-skill pack declaring the block is
    VALIDATED (block presence = executable-skill intent, kind-agnostic —
    exactly the runtime loader's semantics), never kind-constraint-refused."""
    _write_pack_files(tmp_path)
    findings = skills.validate(
        _data(kind="tool", block={"declared_tools": list(_VALID_TOOLS)}), tmp_path
    )
    assert findings == []


def test_non_skill_pack_with_malformed_block_refuses(tmp_path: Path) -> None:
    """Block presence fires the full arm set for ANY kind."""
    _write_pack_files(tmp_path)
    findings = skills.validate(_data(kind="tool", block={"declared_tools": []}), tmp_path)
    assert "list_empty" in _modes(findings, "skill_manifest_declared_tools_invalid")


# ---------------------------------------------------------------------------
# (c) Block shape arms
# ---------------------------------------------------------------------------


def test_skill_md_present_without_block_refuses_block_missing(tmp_path: Path) -> None:
    """SKILL.md at the pack root without a [skill] block: the runtime loader
    would never host it (block presence is the hosting signal) — refuse so
    the author learns at build time, not from a silent hosting skip."""
    _write_pack_files(tmp_path)
    findings = skills.validate(_data(omit_block=True), tmp_path)
    modes = _modes(findings, "skill_manifest_block_shape_invalid")
    assert "block_missing_for_skill_intent" in modes


def test_block_not_table_refuses(tmp_path: Path) -> None:
    _write_pack_files(tmp_path)
    findings = skills.validate(_data(block="not-a-table"), tmp_path)
    assert "block_not_table" in _modes(findings, "skill_manifest_block_shape_invalid")


def test_both_block_paths_validated_with_block_path_payload(tmp_path: Path) -> None:
    """A pack declaring BOTH the canonical and legacy blocks gets refusals
    from each, with ``payload.block_path`` distinguishing the source
    (mirrors the hooks dual-path doctrine)."""
    _write_pack_files(tmp_path)
    findings = skills.validate(
        _data(block={"declared_tools": []}, legacy_block={"declared_tools": []}), tmp_path
    )
    block_paths = {
        f.payload.get("block_path")
        for f in findings
        if f.reason == "skill_manifest_declared_tools_invalid"
    }
    assert block_paths == {"skill", "tool.cognic.skill"}


# ---------------------------------------------------------------------------
# (d) SKILL.md arms
# ---------------------------------------------------------------------------


def test_block_present_without_skill_md_refuses_file_absent(tmp_path: Path) -> None:
    _write_pack_files(tmp_path, skill_md=None)
    findings = skills.validate(_data(block={"declared_tools": list(_VALID_TOOLS)}), tmp_path)
    assert "file_absent" in _modes(findings, "skill_manifest_skill_md_missing")


def test_blank_skill_md_refuses_file_blank(tmp_path: Path) -> None:
    _write_pack_files(tmp_path, skill_md="   \n\n  ")
    findings = skills.validate(_data(block={"declared_tools": list(_VALID_TOOLS)}), tmp_path)
    assert "file_blank" in _modes(findings, "skill_manifest_skill_md_missing")


def test_skill_md_malformed_frontmatter_refuses(tmp_path: Path) -> None:
    _write_pack_files(tmp_path, skill_md="no frontmatter fence here\n")
    findings = skills.validate(_data(block={"declared_tools": list(_VALID_TOOLS)}), tmp_path)
    assert "skill_md_frontmatter_malformed" in _modes(findings, "skill_manifest_skill_md_invalid")


def test_skill_md_invalid_name_refuses(tmp_path: Path) -> None:
    bad = _VALID_SKILL_MD.replace("name: cognic-skill-x", "name: Bad_Name!")
    _write_pack_files(tmp_path, skill_md=bad)
    findings = skills.validate(_data(block={"declared_tools": list(_VALID_TOOLS)}), tmp_path)
    assert "skill_md_name_invalid" in _modes(findings, "skill_manifest_skill_md_invalid")


def test_skill_md_description_too_long_refuses(tmp_path: Path) -> None:
    long_description = "x" * 1025
    bad = _VALID_SKILL_MD.replace(
        "description: Summarises a table schema through governed MCP tool calls.",
        f"description: {long_description}",
    )
    _write_pack_files(tmp_path, skill_md=bad)
    findings = skills.validate(_data(block={"declared_tools": list(_VALID_TOOLS)}), tmp_path)
    assert "skill_md_description_too_long" in _modes(findings, "skill_manifest_skill_md_invalid")


def test_skill_md_empty_body_refuses(tmp_path: Path) -> None:
    bad = "---\nname: cognic-skill-x\ndescription: Valid description.\n---\n\n"
    _write_pack_files(tmp_path, skill_md=bad)
    findings = skills.validate(_data(block={"declared_tools": list(_VALID_TOOLS)}), tmp_path)
    assert "skill_md_body_empty" in _modes(findings, "skill_manifest_skill_md_invalid")


def test_skill_md_author_fill_description_refuses(tmp_path: Path) -> None:
    """Build-time AUTHOR-FILL hygiene (identity/supply_chain doctrine): the
    scaffolded description placeholder must NOT pass validation silently.
    CLI-only check — the runtime hosting validator (protocol/skill_manifest)
    accepts any string <= 1024 chars."""
    bad = _VALID_SKILL_MD.replace(
        "description: Summarises a table schema through governed MCP tool calls.",
        "description: 'AUTHOR-FILL: one-sentence summary of what this skill does.'",
    )
    _write_pack_files(tmp_path, skill_md=bad)
    findings = skills.validate(_data(block={"declared_tools": list(_VALID_TOOLS)}), tmp_path)
    assert "description_author_fill" in _modes(findings, "skill_manifest_skill_md_invalid")


# ---------------------------------------------------------------------------
# (e) declared_tools arms
# ---------------------------------------------------------------------------


def test_declared_tools_absent_refuses(tmp_path: Path) -> None:
    _write_pack_files(tmp_path)
    findings = skills.validate(_data(block={}), tmp_path)
    assert "field_absent" in _modes(findings, "skill_manifest_declared_tools_invalid")


def test_declared_tools_not_a_list_refuses(tmp_path: Path) -> None:
    _write_pack_files(tmp_path)
    findings = skills.validate(_data(block={"declared_tools": "a/b"}), tmp_path)
    assert "not_a_list" in _modes(findings, "skill_manifest_declared_tools_invalid")


def test_declared_tools_empty_list_refuses(tmp_path: Path) -> None:
    _write_pack_files(tmp_path)
    findings = skills.validate(_data(block={"declared_tools": []}), tmp_path)
    assert "list_empty" in _modes(findings, "skill_manifest_declared_tools_invalid")


def test_declared_tools_non_string_entry_refuses(tmp_path: Path) -> None:
    _write_pack_files(tmp_path)
    findings = skills.validate(_data(block={"declared_tools": [42]}), tmp_path)
    assert "entry_not_a_string" in _modes(findings, "skill_manifest_declared_tools_invalid")


@pytest.mark.parametrize(
    "entry",
    ["describe_table", "/describe_table", "cognic-tool-oracle-schema/", "/"],
    ids=["no-slash", "empty-server", "empty-tool", "bare-slash"],
)
def test_declared_tools_malformed_identity_refuses(tmp_path: Path, entry: str) -> None:
    _write_pack_files(tmp_path)
    findings = skills.validate(_data(block={"declared_tools": [entry]}), tmp_path)
    assert "entry_identity_malformed" in _modes(findings, "skill_manifest_declared_tools_invalid")


def test_declared_tools_multi_slash_matches_runtime_partition_rule(tmp_path: Path) -> None:
    """PARTITION alignment pin: the runtime splits on the FIRST slash only
    (core/skill/broker.py + harness/skill_host.py both use
    ``str.partition("/")``), so ``a/b/c`` is a representable identity
    (server ``a``, tool ``b/c``) and MUST validate clean — the build-time
    rule never refuses what the runtime would host."""
    _write_pack_files(tmp_path)
    findings = skills.validate(_data(block={"declared_tools": ["a/b/c"]}), tmp_path)
    assert findings == []


def test_declared_tools_duplicate_refuses(tmp_path: Path) -> None:
    _write_pack_files(tmp_path)
    entry = _VALID_TOOLS[0]
    findings = skills.validate(_data(block={"declared_tools": [entry, entry]}), tmp_path)
    assert "entry_duplicate" in _modes(findings, "skill_manifest_declared_tools_invalid")


def test_declared_tools_author_fill_refuses(tmp_path: Path) -> None:
    """The scaffolded AUTHOR-FILL entry carries a slash inside the hint copy,
    so the partition rule ALONE would accept it — the explicit AUTHOR-FILL
    prefix check is what keeps a fresh scaffold from validating clean."""
    _write_pack_files(tmp_path)
    placeholder = "AUTHOR-FILL: e.g., cognic-tool-oracle-schema/describe_table"
    findings = skills.validate(_data(block={"declared_tools": [placeholder]}), tmp_path)
    assert "entry_author_fill" in _modes(findings, "skill_manifest_declared_tools_invalid")


# ---------------------------------------------------------------------------
# (f) Entry-point cross-check arms
# ---------------------------------------------------------------------------


def test_entry_point_absent_refuses(tmp_path: Path) -> None:
    _write_pack_files(
        tmp_path,
        pyproject='[project]\nname = "cognic-skill-x"\nversion = "0.1.0"\n',
    )
    findings = skills.validate(_data(block={"declared_tools": list(_VALID_TOOLS)}), tmp_path)
    assert "entry_point_absent" in _modes(findings, "skill_manifest_entry_point_mismatch")


def test_entry_point_ambiguous_refuses(tmp_path: Path) -> None:
    """The runtime resolver requires EXACTLY ONE ``cognic.skills`` entry
    point (harness/skill_host._skill_entry_point_info fail-closes on
    ``len(eps) != 1``); two entries would warn-skip the pack at boot."""
    _write_pack_files(
        tmp_path,
        pyproject=(
            "[project]\n"
            'name = "cognic-skill-x"\n'
            'version = "0.1.0"\n'
            "\n"
            '[project.entry-points."cognic.skills"]\n'
            'x = "cognic_skill_x.skill:XSkill"\n'
            'y = "cognic_skill_x.other:YSkill"\n'
        ),
    )
    findings = skills.validate(_data(block={"declared_tools": list(_VALID_TOOLS)}), tmp_path)
    assert "entry_point_ambiguous" in _modes(findings, "skill_manifest_entry_point_mismatch")


def test_pyproject_missing_refuses_unparseable(tmp_path: Path) -> None:
    _write_pack_files(tmp_path, pyproject=None)
    findings = skills.validate(_data(block={"declared_tools": list(_VALID_TOOLS)}), tmp_path)
    assert "pyproject_unparseable" in _modes(findings, "skill_manifest_entry_point_mismatch")


def test_pyproject_malformed_refuses_unparseable(tmp_path: Path) -> None:
    _write_pack_files(tmp_path, pyproject="not [ valid toml ===")
    findings = skills.validate(_data(block={"declared_tools": list(_VALID_TOOLS)}), tmp_path)
    assert "pyproject_unparseable" in _modes(findings, "skill_manifest_entry_point_mismatch")


# ---------------------------------------------------------------------------
# (f2) M8 A7 — instruction-only skill mode
# ---------------------------------------------------------------------------

_PYPROJECT_NO_EP = "[project]\nname = 'cognic-skill-x'\nversion = '0.1.0'\n".replace("'", '"')


def test_explicit_executable_mode_validates_clean(tmp_path: Path) -> None:
    """``mode = "executable"`` is byte-identical to the absent-mode default."""
    _write_pack_files(tmp_path)
    findings = skills.validate(
        _data(block={"mode": "executable", "declared_tools": list(_VALID_TOOLS)}), tmp_path
    )
    assert findings == []


def test_mode_invalid_value_refuses_block_shape(tmp_path: Path) -> None:
    _write_pack_files(tmp_path)
    findings = skills.validate(
        _data(block={"mode": "interpretive-dance", "declared_tools": list(_VALID_TOOLS)}),
        tmp_path,
    )
    assert "mode_invalid" in _modes(findings, "skill_manifest_block_shape_invalid")


def test_valid_instruction_pack_validates_clean(tmp_path: Path) -> None:
    """Instruction mode: no declared_tools requirement, no entry-point
    requirement — a SKILL.md + a bare pyproject (no cognic.skills EP) is a
    complete instruction skill pack."""
    _write_pack_files(tmp_path, pyproject=_PYPROJECT_NO_EP)
    findings = skills.validate(_data(block={"mode": "instruction"}), tmp_path)
    assert findings == []


def test_instruction_mode_with_declared_tools_refuses(tmp_path: Path) -> None:
    _write_pack_files(tmp_path, pyproject=_PYPROJECT_NO_EP)
    findings = skills.validate(
        _data(block={"mode": "instruction", "declared_tools": list(_VALID_TOOLS)}), tmp_path
    )
    assert any(f.reason == "skill_manifest_instruction_mode_declares_tools" for f in findings)


def test_instruction_mode_with_empty_declared_tools_clean(tmp_path: Path) -> None:
    """``declared_tools = []`` is not an executable surface — partition-aligned
    with the runtime loader's truthiness rule (build time never refuses what
    the runtime would host)."""
    _write_pack_files(tmp_path, pyproject=_PYPROJECT_NO_EP)
    findings = skills.validate(_data(block={"mode": "instruction", "declared_tools": []}), tmp_path)
    assert findings == []


def test_instruction_mode_with_entry_point_refuses(tmp_path: Path) -> None:
    """An instruction pack declaring a ``cognic.skills`` entry point is an
    author error (the runtime loader would warn-skip it at boot)."""
    _write_pack_files(tmp_path)  # _VALID_PYPROJECT declares one cognic.skills EP
    findings = skills.validate(_data(block={"mode": "instruction"}), tmp_path)
    assert any(f.reason == "skill_manifest_instruction_mode_has_entry_point" for f in findings)


def test_instruction_mode_still_requires_skill_md(tmp_path: Path) -> None:
    _write_pack_files(tmp_path, skill_md=None, pyproject=_PYPROJECT_NO_EP)
    findings = skills.validate(_data(block={"mode": "instruction"}), tmp_path)
    assert "file_absent" in _modes(findings, "skill_manifest_skill_md_missing")


def test_instruction_mode_unreadable_pyproject_refuses(tmp_path: Path) -> None:
    """Without a parseable pyproject the validator cannot verify the no-EP
    invariant — fail closed with the shared pyproject_unparseable arm."""
    _write_pack_files(tmp_path, pyproject=None)
    findings = skills.validate(_data(block={"mode": "instruction"}), tmp_path)
    assert "pyproject_unparseable" in _modes(findings, "skill_manifest_entry_point_mismatch")


# ---------------------------------------------------------------------------
# (f3) M8 A7 — referenced_tools (non-authoritative reviewer evidence)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "mode_expected"),
    [
        ("a/b", "not_a_list"),
        ([42], "entry_not_a_string"),
        (["describe_table"], "entry_identity_malformed"),
        (["a/b", "a/b"], "entry_duplicate"),
        (["AUTHOR-FILL: e.g., cognic-tool-x/y"], "entry_author_fill"),
    ],
    ids=["not-a-list", "non-string", "malformed", "duplicate", "author-fill"],
)
def test_referenced_tools_shape_arms_refuse(tmp_path: Path, value: Any, mode_expected: str) -> None:
    _write_pack_files(tmp_path, pyproject=_PYPROJECT_NO_EP)
    findings = skills.validate(
        _data(block={"mode": "instruction", "referenced_tools": value}), tmp_path
    )
    assert mode_expected in _modes(findings, "skill_manifest_referenced_tools_invalid")


def test_referenced_tools_valid_emits_unverifiable_warning_only(tmp_path: Path) -> None:
    """A shape-clean non-empty referenced_tools list emits ONE warning-severity
    finding (the entries cannot be verified against a live registered-MCP set
    at build time) and NO refusal — exit code stays 0."""
    _write_pack_files(tmp_path, pyproject=_PYPROJECT_NO_EP)
    findings = skills.validate(
        _data(
            block={
                "mode": "instruction",
                "referenced_tools": ["cognic-tool-oracle-schema/list_tables"],
            }
        ),
        tmp_path,
    )
    warnings = [f for f in findings if f.reason == "skill_manifest_referenced_tool_unverifiable"]
    assert len(warnings) == 1
    assert warnings[0].severity == "warning"
    assert warnings[0].affects_exit_code is False
    assert [f for f in findings if f.severity == "refusal"] == []


def test_referenced_tools_empty_list_is_silent(tmp_path: Path) -> None:
    _write_pack_files(tmp_path, pyproject=_PYPROJECT_NO_EP)
    findings = skills.validate(
        _data(block={"mode": "instruction", "referenced_tools": []}), tmp_path
    )
    assert findings == []


def test_referenced_tools_shape_validated_on_executable_blocks_too(tmp_path: Path) -> None:
    """The field is shape-validated wherever present (either mode)."""
    _write_pack_files(tmp_path)
    findings = skills.validate(
        _data(block={"declared_tools": list(_VALID_TOOLS), "referenced_tools": ["bad"]}),
        tmp_path,
    )
    assert "entry_identity_malformed" in _modes(findings, "skill_manifest_referenced_tools_invalid")


# ---------------------------------------------------------------------------
# (g) Severity + closed-enum vocabulary
# ---------------------------------------------------------------------------


def test_all_findings_are_refusal_severity(tmp_path: Path) -> None:
    """This validator has no warning paths — every arm is a refusal."""
    _write_pack_files(tmp_path, skill_md=None, pyproject=None)
    findings = skills.validate(_data(block={"declared_tools": []}), tmp_path)
    assert findings, "expected at least one finding from the compound-failure fixture"
    assert {f.severity for f in findings} == {"refusal"}


_SKILL_MANIFEST_REASONS: tuple[str, ...] = (
    "skill_manifest_block_shape_invalid",
    "skill_manifest_skill_md_missing",
    "skill_manifest_skill_md_invalid",
    "skill_manifest_declared_tools_invalid",
    "skill_manifest_entry_point_mismatch",
    # M8 A7 (ADR-027) — instruction-only mode + referenced_tools evidence.
    "skill_manifest_instruction_mode_declares_tools",
    "skill_manifest_instruction_mode_has_entry_point",
    "skill_manifest_referenced_tools_invalid",
    "skill_manifest_referenced_tool_unverifiable",
)


@pytest.mark.parametrize("reason", _SKILL_MANIFEST_REASONS)
def test_skill_manifest_reason_in_validator_reason_literal(reason: str) -> None:
    assert reason in typing.get_args(ValidatorReason)


@pytest.mark.parametrize("reason", _SKILL_MANIFEST_REASONS)
def test_skill_manifest_reason_owned_by_skills_validator(reason: str) -> None:
    assert _VALIDATOR_REASON_OWNERSHIP[reason] == "validators/skills.py"  # type: ignore[index]


def test_referenced_tool_unverifiable_is_warning_severity() -> None:
    """The unverifiable-reference reason is the validator's ONLY warning —
    it joins ``_WARNING_REASONS`` (severity partition) while the other three
    A7 reasons stay refusals."""
    from cognic_agentos.cli import _WARNING_REASONS, severity_for

    assert "skill_manifest_referenced_tool_unverifiable" in _WARNING_REASONS
    assert severity_for("skill_manifest_referenced_tool_unverifiable") == "warning"
    assert severity_for("skill_manifest_instruction_mode_declares_tools") == "refusal"
    assert severity_for("skill_manifest_instruction_mode_has_entry_point") == "refusal"
    assert severity_for("skill_manifest_referenced_tools_invalid") == "refusal"
