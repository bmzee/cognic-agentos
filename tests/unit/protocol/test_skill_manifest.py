"""M6 Task A7 (ADR-025) — SKILL.md frontmatter reader + validator.

Pure-function coverage of ``parse_skill_md`` + ``validate_skill_md`` (the
agentskills.io shape gate: name regex, description ≤ 1024, non-empty body) plus
``extract_skill_md``'s deferred-load / not-found contract.
"""

from __future__ import annotations

from typing import get_args

import pytest

from cognic_agentos.protocol.skill_manifest import (
    SkillManifestInvalid,
    SkillManifestNotFound,
    SkillMdValidationReason,
    extract_skill_md,
    parse_skill_md,
    validate_skill_md,
)

_VALID = """---
name: schema-summary
description: Summarize an Oracle schema's tables and key columns.
---
Procedural instructions an M8 agent will read to decide to invoke this skill.
"""


# ============================ parse ==========================================
def test_parse_splits_frontmatter_and_body() -> None:
    fm, body = parse_skill_md(_VALID)
    assert fm["name"] == "schema-summary"
    assert fm["description"].startswith("Summarize")
    assert "Procedural instructions" in body


def test_parse_missing_delimiters_is_malformed() -> None:
    with pytest.raises(SkillManifestInvalid) as ei:
        parse_skill_md("no frontmatter here, just text")
    assert ei.value.reason == "skill_md_frontmatter_malformed"


def test_parse_non_mapping_frontmatter_is_malformed() -> None:
    with pytest.raises(SkillManifestInvalid) as ei:
        parse_skill_md("---\n- a\n- b\n---\nbody\n")
    assert ei.value.reason == "skill_md_frontmatter_malformed"


def test_parse_bad_yaml_is_malformed() -> None:
    with pytest.raises(SkillManifestInvalid) as ei:
        parse_skill_md("---\nname: [unterminated\n---\nbody\n")
    assert ei.value.reason == "skill_md_frontmatter_malformed"


# ============================ validate =======================================
def test_validate_accepts_valid() -> None:
    fm, body = parse_skill_md(_VALID)
    validate_skill_md(fm, body=body)  # no raise


@pytest.mark.parametrize(
    "name",
    [
        "schema-summary",
        "a",
        "s3",
        "a-b-c",
        "x" * 64,  # boundary: 1 + 62 + 1
    ],
)
def test_validate_accepts_good_names(name: str) -> None:
    validate_skill_md({"name": name, "description": "d"}, body="b")


@pytest.mark.parametrize(
    "name",
    [
        "Schema-Summary",  # uppercase
        "-lead",  # leading hyphen
        "trail-",  # trailing hyphen
        "has space",
        "has_underscore",
        "x" * 65,  # too long
        "",  # empty
    ],
)
def test_validate_rejects_bad_names(name: str) -> None:
    with pytest.raises(SkillManifestInvalid) as ei:
        validate_skill_md({"name": name, "description": "d"}, body="b")
    assert ei.value.reason == "skill_md_name_invalid"


def test_validate_rejects_missing_name() -> None:
    with pytest.raises(SkillManifestInvalid) as ei:
        validate_skill_md({"description": "d"}, body="b")
    assert ei.value.reason == "skill_md_name_invalid"


def test_validate_rejects_non_string_name() -> None:
    with pytest.raises(SkillManifestInvalid) as ei:
        validate_skill_md({"name": 42, "description": "d"}, body="b")
    assert ei.value.reason == "skill_md_name_invalid"


def test_validate_rejects_missing_description() -> None:
    with pytest.raises(SkillManifestInvalid) as ei:
        validate_skill_md({"name": "ok"}, body="b")
    assert ei.value.reason == "skill_md_description_invalid"


def test_validate_rejects_too_long_description() -> None:
    with pytest.raises(SkillManifestInvalid) as ei:
        validate_skill_md({"name": "ok", "description": "x" * 1025}, body="b")
    assert ei.value.reason == "skill_md_description_too_long"


def test_validate_accepts_max_length_description() -> None:
    validate_skill_md({"name": "ok", "description": "x" * 1024}, body="b")  # no raise


@pytest.mark.parametrize("body", ["", "   ", "\n\t\n"])
def test_validate_rejects_empty_body(body: str) -> None:
    with pytest.raises(SkillManifestInvalid) as ei:
        validate_skill_md({"name": "ok", "description": "d"}, body=body)
    assert ei.value.reason == "skill_md_body_empty"


# ============================ closed enum ====================================
def test_validation_reason_closed_enum() -> None:
    assert set(get_args(SkillMdValidationReason)) == {
        "skill_md_frontmatter_malformed",
        "skill_md_name_invalid",
        "skill_md_description_invalid",
        "skill_md_description_too_long",
        "skill_md_body_empty",
    }


# ============================ extract (deferred-load) ========================
def test_extract_not_found_for_absent_distribution() -> None:
    with pytest.raises(SkillManifestNotFound):
        extract_skill_md(
            distribution_name="cognic-skill-nonexistent-xyz",
            package_name="cognic_skill_nonexistent",
        )


def test_extract_rejects_path_shaped_package_name() -> None:
    # defence-in-depth: a path-shaped package_name is rejected BEFORE any
    # locate_file resolution (mirrors extract_pack_manifest's guard).
    with pytest.raises(SkillManifestNotFound):
        extract_skill_md(distribution_name="whatever", package_name="../etc/passwd")
