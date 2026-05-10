"""Sprint-7A2 T5 — `cli/validators/hooks.py` regressions (CRITICAL CONTROLS).

Per Doctrine Decision G + Sprint-7A2 T12 promotion: this validator
joins the strict 95/90 critical-controls floor at T12. T5 ships the
full refusal-arms-per-closed-enum-reason coverage + happy-path arm +
R23 dual-path arm + pyproject↔manifest cross-check arms.

Closed-enum reasons covered (7 emitted by hooks.py + the 9th
``hook_unresolved_reference`` is also emitted by hooks.py for the
manifest_only side of the entry-point cross-check):

  - ``hook_block_shape_invalid``
      * block_missing_for_hook_pack
      * declarations_field_absent
      * declarations_field_not_list
      * declarations_empty
      * declaration_entry_not_table
      * declaration_missing_required_field
  - ``hook_id_invalid``
      * invalid_shape (non-snake_case)
      * duplicate_in_manifest
  - ``hook_phase_invalid``
      * not_in_closed_enum
      * not_a_string
  - ``hook_ordering_class_invalid``
      * not_in_closed_enum
      * not_a_string
      * phase_class_mismatch
  - ``hook_timeout_invalid``
      * not_a_positive_number
      * above_ceiling
  - ``hook_fail_policy_invalid``
      * not_in_closed_enum
      * not_a_string
      * fail_open_without_exception
  - ``hook_entry_point_mismatch``
      * pyproject_only
      * pyproject_unparseable
  - ``hook_unresolved_reference``
      * manifest_only

(``hook_pack_kind_constraint_violated`` is the 8th hook reason but
it's owned by ``cli/validate.py`` per Sprint-7A2 T4 ownership move
— covered by tests in ``test_cli_validate.py``.)
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from cognic_agentos.cli.validators.hooks import validate

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse(toml_body: str) -> dict[str, Any]:
    return tomllib.loads(toml_body)


_VALID_HOOK_DECLARATION = """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"
"""


_VALID_PYPROJECT_BODY = """
[project]
name = "cognic-hook-test"
version = "0.1.0"

[project.entry-points."cognic.hooks"]
redact_pii_in_input = "cognic_hook_test.hook:RedactHook"
"""


def _write_pyproject(pack_path: Path, body: str = _VALID_PYPROJECT_BODY) -> None:
    pack_path.mkdir(parents=True, exist_ok=True)
    (pack_path / "pyproject.toml").write_text(body)


def _hook_pack_manifest(declarations_block: str = _VALID_HOOK_DECLARATION) -> str:
    """Build a kind="hook" manifest body with a configurable
    [hooks].declarations block. Other Wave-1 blocks are present
    but minimal — the hook validator skips them."""
    return f"""\
[pack]
pack_id = "cognic-hook-test"
kind = "hook"

[identity]
agent_id = "did:web:example.com:hooks:test"
display_name = "Test Hook"
provider_organization = "Example Org"
provider_url = "https://example.com"

[data_governance]
data_classes = ["public"]
purpose = "operational_telemetry"
retention_policy = "none"

[risk_tier]
tier = "read_only"

[supply_chain]
attestation_paths = ["attestations/cosign.sig"]
{declarations_block}
"""


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_hooks_validator_returns_empty_for_valid_hook_pack(tmp_path: Path) -> None:
    """Clean kind="hook" manifest with one valid [[hooks.declarations]]
    + matching pyproject entry-point → no findings."""
    _write_pyproject(tmp_path)
    data = _parse(_hook_pack_manifest())
    findings = validate(data, tmp_path)
    assert findings == []


def test_hooks_validator_returns_empty_for_non_hook_pack_without_hooks_block(
    tmp_path: Path,
) -> None:
    """Non-hook pack (kind="tool") without a [hooks] block: validator
    is silently inactive. Wave-1 narrow."""
    data = _parse(
        """\
[pack]
pack_id = "cognic-tool-test"
kind = "tool"

[identity]
agent_id = "did:web:example.com:tools:test"
display_name = "Test Tool"
provider_organization = "Example Org"
provider_url = "https://example.com"

[data_governance]
data_classes = ["public"]
purpose = "operational_telemetry"
retention_policy = "none"

[risk_tier]
tier = "read_only"

[supply_chain]
attestation_paths = ["attestations/cosign.sig"]
"""
    )
    findings = validate(data, tmp_path)
    assert findings == []


# ---------------------------------------------------------------------------
# hook_block_shape_invalid arms
# ---------------------------------------------------------------------------


def test_hooks_validator_refuses_block_missing_for_hook_pack(tmp_path: Path) -> None:
    """kind="hook" without [hooks] block → block_missing_for_hook_pack."""
    body = _hook_pack_manifest("")  # no [hooks] block
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_block_shape_invalid"
        and f.payload["failure_mode"] == "block_missing_for_hook_pack"
        for f in findings
    ), [f.payload for f in findings]


def test_hooks_validator_refuses_declarations_field_absent(tmp_path: Path) -> None:
    """[hooks] present but declarations field absent."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest("\n[hooks]\n")
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_block_shape_invalid"
        and f.payload["failure_mode"] == "declarations_field_absent"
        for f in findings
    )


def test_hooks_validator_refuses_declarations_field_not_list(tmp_path: Path) -> None:
    """declarations is a string (not array-of-tables)."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest('\n[hooks]\ndeclarations = "not a list"\n')
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_block_shape_invalid"
        and f.payload["failure_mode"] == "declarations_field_not_list"
        for f in findings
    )


def test_hooks_validator_refuses_declarations_empty(tmp_path: Path) -> None:
    """declarations is empty list."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest("\n[hooks]\ndeclarations = []\n")
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_block_shape_invalid" and f.payload["failure_mode"] == "declarations_empty"
        for f in findings
    )


def test_hooks_validator_refuses_declaration_missing_required_field(
    tmp_path: Path,
) -> None:
    """One declaration missing the timeout_seconds field."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = "input_redaction"
fail_policy = "fail_closed"
# timeout_seconds intentionally missing
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    missing_findings = [
        f
        for f in findings
        if f.reason == "hook_block_shape_invalid"
        and f.payload["failure_mode"] == "declaration_missing_required_field"
    ]
    assert len(missing_findings) == 1
    assert missing_findings[0].payload["field"] == "timeout_seconds"


# ---------------------------------------------------------------------------
# hook_id_invalid arms
# ---------------------------------------------------------------------------


def test_hooks_validator_refuses_hook_id_invalid_shape(tmp_path: Path) -> None:
    """hook_id with hyphen → invalid_shape."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "Has-Hyphens"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_id_invalid" and f.payload["failure_mode"] == "invalid_shape"
        for f in findings
    )


def test_hooks_validator_refuses_duplicate_hook_id(tmp_path: Path) -> None:
    """Two declarations with the same hook_id."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"

[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_post"
ordering_class = "output_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    duplicate_findings = [
        f
        for f in findings
        if f.reason == "hook_id_invalid" and f.payload["failure_mode"] == "duplicate_in_manifest"
    ]
    assert len(duplicate_findings) == 1


# ---------------------------------------------------------------------------
# hook_phase_invalid arms
# ---------------------------------------------------------------------------


def test_hooks_validator_refuses_phase_not_in_closed_enum(tmp_path: Path) -> None:
    """phase = "memory_pre" (not a Wave-1 value)."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "memory_redact"
phase = "memory_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_phase_invalid" and f.payload["failure_mode"] == "not_in_closed_enum"
        for f in findings
    )


def test_hooks_validator_refuses_phase_not_a_string(tmp_path: Path) -> None:
    """phase = 1 (integer, not string)."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "weird"
phase = 1
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_phase_invalid" and f.payload["failure_mode"] == "not_a_string"
        for f in findings
    )


# ---------------------------------------------------------------------------
# hook_ordering_class_invalid arms
# ---------------------------------------------------------------------------


def test_hooks_validator_refuses_ordering_class_not_in_closed_enum(
    tmp_path: Path,
) -> None:
    """ordering_class = "wild_card" (not a Wave-1 value)."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = "wild_card"
timeout_seconds = 5.0
fail_policy = "fail_closed"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_ordering_class_invalid"
        and f.payload["failure_mode"] == "not_in_closed_enum"
        for f in findings
    )


def test_hooks_validator_refuses_ordering_class_not_a_string(tmp_path: Path) -> None:
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = 42
timeout_seconds = 5.0
fail_policy = "fail_closed"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_ordering_class_invalid" and f.payload["failure_mode"] == "not_a_string"
        for f in findings
    )


def test_hooks_validator_refuses_phase_class_mismatch(tmp_path: Path) -> None:
    """phase=dlp_pre + ordering_class=output_validation → mismatch."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "weird"
phase = "dlp_pre"
ordering_class = "output_validation"
timeout_seconds = 5.0
fail_policy = "fail_closed"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    mismatch_findings = [
        f
        for f in findings
        if f.reason == "hook_ordering_class_invalid"
        and f.payload["failure_mode"] == "phase_class_mismatch"
    ]
    assert len(mismatch_findings) == 1
    payload = mismatch_findings[0].payload
    assert payload["declared_phase"] == "dlp_pre"
    assert payload["declared_ordering_class"] == "output_validation"
    assert payload["expected_phase_for_class"] == "dlp_post"


# ---------------------------------------------------------------------------
# hook_timeout_invalid arms
# ---------------------------------------------------------------------------


def test_hooks_validator_refuses_timeout_zero(tmp_path: Path) -> None:
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 0
fail_policy = "fail_closed"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_timeout_invalid" and f.payload["failure_mode"] == "not_a_positive_number"
        for f in findings
    )


def test_hooks_validator_refuses_timeout_negative(tmp_path: Path) -> None:
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = -1.5
fail_policy = "fail_closed"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_timeout_invalid" and f.payload["failure_mode"] == "not_a_positive_number"
        for f in findings
    )


def test_hooks_validator_refuses_timeout_above_ceiling(tmp_path: Path) -> None:
    """timeout_seconds = 60.0 > Settings.hook_max_timeout_s default (30.0)."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "slow_hook"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 60.0
fail_policy = "fail_closed"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    above_findings = [
        f
        for f in findings
        if f.reason == "hook_timeout_invalid" and f.payload["failure_mode"] == "above_ceiling"
    ]
    assert len(above_findings) == 1
    assert above_findings[0].payload["declared_value"] == 60.0
    assert above_findings[0].payload["ceiling_seconds"] == 30.0


def test_hooks_validator_refuses_timeout_bool_true(tmp_path: Path) -> None:
    """timeout_seconds = true (bool, not number) → not_a_positive_number.
    Bool is an int subclass in Python; the validator MUST refuse
    explicitly so True doesn't slip through the int branch."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "weird"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = true
fail_policy = "fail_closed"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_timeout_invalid" and f.payload["failure_mode"] == "not_a_positive_number"
        for f in findings
    )


# ---------------------------------------------------------------------------
# hook_fail_policy_invalid arms
# ---------------------------------------------------------------------------


def test_hooks_validator_refuses_fail_policy_not_in_closed_enum(
    tmp_path: Path,
) -> None:
    """fail_policy = "best_effort" (not in closed enum)."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "best_effort"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_fail_policy_invalid" and f.payload["failure_mode"] == "not_in_closed_enum"
        for f in findings
    )


def test_hooks_validator_refuses_fail_policy_not_a_string(tmp_path: Path) -> None:
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = 1
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_fail_policy_invalid" and f.payload["failure_mode"] == "not_a_string"
        for f in findings
    )


def test_hooks_validator_refuses_fail_open_without_exception(tmp_path: Path) -> None:
    """Wave-1 narrow: fail_policy="fail_open" is refused until the
    fail_open_exception declaration shape lands in a follow-up sprint."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_open"
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_fail_policy_invalid"
        and f.payload["failure_mode"] == "fail_open_without_exception"
        for f in findings
    )


# ---------------------------------------------------------------------------
# hook_entry_point_mismatch + hook_unresolved_reference arms
# ---------------------------------------------------------------------------


def test_hooks_validator_refuses_pyproject_only_entry(tmp_path: Path) -> None:
    """pyproject declares an entry-point that has no matching
    [hooks].declarations entry → hook_entry_point_mismatch with
    failure_mode=pyproject_only."""
    _write_pyproject(
        tmp_path,
        body="""
[project]
name = "cognic-hook-test"
version = "0.1.0"

[project.entry-points."cognic.hooks"]
redact_pii_in_input = "cognic_hook_test.hook:RedactHook"
mask_account_numbers = "cognic_hook_test.hook:MaskHook"
""",
    )
    # Manifest only declares one of the two pyproject entries.
    body = _hook_pack_manifest()
    data = _parse(body)
    findings = validate(data, tmp_path)
    mismatch_findings = [
        f
        for f in findings
        if f.reason == "hook_entry_point_mismatch" and f.payload["failure_mode"] == "pyproject_only"
    ]
    assert len(mismatch_findings) == 1
    assert mismatch_findings[0].payload["hook_id"] == "mask_account_numbers"


def test_hooks_validator_refuses_manifest_only_entry(tmp_path: Path) -> None:
    """Manifest declares a hook_id with no matching pyproject entry-
    point → hook_unresolved_reference with failure_mode=manifest_only.
    The manifest forward-references something pyproject doesn't define."""
    _write_pyproject(
        tmp_path,
        body="""
[project]
name = "cognic-hook-test"
version = "0.1.0"

[project.entry-points."cognic.hooks"]
# pyproject is empty for this group.
""",
    )
    body = _hook_pack_manifest()  # manifest declares "redact_pii_in_input"
    data = _parse(body)
    findings = validate(data, tmp_path)
    unresolved_findings = [
        f
        for f in findings
        if f.reason == "hook_unresolved_reference" and f.payload["failure_mode"] == "manifest_only"
    ]
    assert len(unresolved_findings) == 1
    assert unresolved_findings[0].payload["hook_id"] == "redact_pii_in_input"


def test_hooks_validator_refuses_pyproject_unparseable_missing(tmp_path: Path) -> None:
    """No pyproject.toml on disk → hook_entry_point_mismatch with
    failure_mode=pyproject_unparseable."""
    # Don't write a pyproject; just write the manifest.
    body = _hook_pack_manifest()
    data = _parse(body)
    findings = validate(data, tmp_path)
    unparseable_findings = [
        f
        for f in findings
        if f.reason == "hook_entry_point_mismatch"
        and f.payload["failure_mode"] == "pyproject_unparseable"
    ]
    assert len(unparseable_findings) == 1
    assert unparseable_findings[0].payload["error_type"] == "FileNotFoundError"


def test_hooks_validator_refuses_pyproject_unparseable_malformed_toml(
    tmp_path: Path,
) -> None:
    """Malformed pyproject TOML → hook_entry_point_mismatch with
    failure_mode=pyproject_unparseable + error_type=TOMLDecodeError."""
    pack_path = tmp_path
    pack_path.mkdir(parents=True, exist_ok=True)
    (pack_path / "pyproject.toml").write_text("this is = = = not = valid TOML")
    body = _hook_pack_manifest()
    data = _parse(body)
    findings = validate(data, pack_path)
    unparseable_findings = [
        f
        for f in findings
        if f.reason == "hook_entry_point_mismatch"
        and f.payload["failure_mode"] == "pyproject_unparseable"
    ]
    assert len(unparseable_findings) == 1


# ---------------------------------------------------------------------------
# R23 dual-path lookup
# ---------------------------------------------------------------------------


def test_hooks_validator_validates_legacy_tool_cognic_hooks_path(
    tmp_path: Path,
) -> None:
    """A pack declaring [tool.cognic.hooks] (legacy R23 shape) gets
    validated against the same field rules as the canonical [hooks]
    block. This test uses an invalid phase to confirm the validator
    fires through the legacy path."""
    _write_pyproject(tmp_path)
    body = """\
[pack]
pack_id = "cognic-hook-test"
kind = "hook"

[identity]
agent_id = "did:web:example.com:hooks:test"
display_name = "Test Hook"
provider_organization = "Example Org"
provider_url = "https://example.com"

[data_governance]
data_classes = ["public"]
purpose = "operational_telemetry"
retention_policy = "none"

[risk_tier]
tier = "read_only"

[supply_chain]
attestation_paths = ["attestations/cosign.sig"]

[[tool.cognic.hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "memory_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"
"""
    data = _parse(body)
    findings = validate(data, tmp_path)
    legacy_phase_findings = [
        f
        for f in findings
        if f.reason == "hook_phase_invalid" and f.payload["block_path"] == "tool.cognic.hooks"
    ]
    assert len(legacy_phase_findings) == 1


def test_hooks_validator_validates_both_canonical_and_legacy_paths(
    tmp_path: Path,
) -> None:
    """Pack declaring BOTH [hooks] AND [tool.cognic.hooks] gets
    validated against both — refusals carry payload.block_path
    distinguishing the source. Pinning so a future refactor that
    accidentally short-circuits one path is caught."""
    _write_pyproject(tmp_path)
    body = """\
[pack]
pack_id = "cognic-hook-test"
kind = "hook"

[identity]
agent_id = "did:web:example.com:hooks:test"
display_name = "Test Hook"
provider_organization = "Example Org"
provider_url = "https://example.com"

[data_governance]
data_classes = ["public"]
purpose = "operational_telemetry"
retention_policy = "none"

[risk_tier]
tier = "read_only"

[supply_chain]
attestation_paths = ["attestations/cosign.sig"]

[[hooks.declarations]]
hook_id = "canonical_bad"
phase = "memory_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"

[[tool.cognic.hooks.declarations]]
hook_id = "legacy_bad"
phase = "memory_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"
"""
    data = _parse(body)
    findings = validate(data, tmp_path)
    block_paths_with_phase_refusals = {
        f.payload["block_path"] for f in findings if f.reason == "hook_phase_invalid"
    }
    assert block_paths_with_phase_refusals == {"hooks", "tool.cognic.hooks"}


# ---------------------------------------------------------------------------
# Closed-enum returned shape
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# T12 floor-uplift coverage closures (CRITICAL CONTROLS)
# ---------------------------------------------------------------------------
#
# Sprint-7A2 T12 promotes ``cli/validators/hooks.py`` to the strict
# 95/90 critical-controls coverage gate. The seven blocks below close
# the residual line + branch coverage gap surfaced by the T12 probe:
#
#   * Inner ``_validate_hook_block`` non-dict block branch (the OUTER
#     "block missing entirely" branch is already tested at line 170,
#     but the inner "block-present-but-not-a-table" branch is a
#     separate refusal site).
#   * ``declaration_entry_not_table`` shape failure (declarations array
#     contains a non-table entry — TOML allows ``declarations = [42]``).
#   * The four per-field ``if value is None: return []`` skip branches
#     in ``_validate_hook_id_field`` / ``_validate_phase_field`` /
#     ``_validate_ordering_class_field`` / ``_validate_fail_policy_field``
#     (reached when a declaration omits the field; the missing-field
#     refusal is emitted by ``_validate_declaration``'s required-field
#     check, NOT by the per-field validator). The timeout None-skip is
#     already covered by ``test_hooks_validator_refuses_declaration_missing_required_field``.
#   * Three malformed-pyproject defenses in ``_read_pyproject_hook_entry_points``
#     (``project`` not a dict; ``entry-points`` not a dict;
#     ``cognic.hooks`` not a dict). Each routes to the empty-entry-points
#     return path so the cross-check emits ``manifest_only`` for every
#     manifest-declared hook_id.
#   * The ``elif pack_kind == "hook"`` branch in ``validate()`` that
#     suppresses the entry-point cross-check when EVERY declaration
#     was malformed (no valid hook_ids accumulated → cross-check skip).


def test_hooks_validator_refuses_inner_hooks_block_not_a_dict(tmp_path: Path) -> None:
    """[hooks] is present but its value is not a TOML table — the
    inner ``_validate_hook_block`` non-dict branch fires (separate
    refusal site from the OUTER ``not located_blocks`` branch already
    tested above)."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest("")  # no [hooks] block in body
    data = _parse(body)
    # Force a non-table value at the canonical path so _resolve_path
    # returns a string. TOML parser would normally treat ``[hooks]``
    # as a table header; injecting via the parsed dict is the cleanest
    # way to exercise the inner-branch defense.
    data["hooks"] = "not a dict"
    findings = validate(data, tmp_path)
    matching = [
        f
        for f in findings
        if f.reason == "hook_block_shape_invalid"
        and f.payload["failure_mode"] == "block_missing_for_hook_pack"
        and f.payload["block_path"] == "hooks"
    ]
    assert len(matching) == 1, [f.payload for f in findings]
    assert "expected a TOML table" in matching[0].message


def test_hooks_validator_refuses_declaration_entry_not_a_table(tmp_path: Path) -> None:
    """declarations array contains non-table entries → one
    ``declaration_entry_not_table`` shape finding per non-table."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest("\n[hooks]\ndeclarations = [42, 'string-value']\n")
    data = _parse(body)
    findings = validate(data, tmp_path)
    not_table_findings = [
        f
        for f in findings
        if f.reason == "hook_block_shape_invalid"
        and f.payload["failure_mode"] == "declaration_entry_not_table"
    ]
    assert len(not_table_findings) == 2, [f.payload for f in findings]
    indexes = sorted(f.payload["declaration_index"] for f in not_table_findings)
    assert indexes == [0, 1]


def test_hooks_validator_skips_hook_id_field_validator_when_field_missing(
    tmp_path: Path,
) -> None:
    """Declaration missing ``hook_id`` → ``_validate_hook_id_field``
    early-returns ``[]`` on ``value is None``; the missing-field
    refusal comes from the required-field check, NOT from the per-
    field validator."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"
# hook_id intentionally missing
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    # Required-field refusal is present.
    missing = [
        f
        for f in findings
        if f.reason == "hook_block_shape_invalid"
        and f.payload["failure_mode"] == "declaration_missing_required_field"
        and f.payload["field"] == "hook_id"
    ]
    assert len(missing) == 1
    # The per-field validator did NOT emit a hook_id_invalid refusal
    # (it short-circuited on the None-skip branch).
    assert not any(f.reason == "hook_id_invalid" for f in findings)


def test_hooks_validator_skips_phase_field_validator_when_field_missing(
    tmp_path: Path,
) -> None:
    """Declaration missing ``phase`` → ``_validate_phase_field``
    early-returns on the None-skip branch."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"
# phase intentionally missing
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_block_shape_invalid"
        and f.payload["failure_mode"] == "declaration_missing_required_field"
        and f.payload["field"] == "phase"
        for f in findings
    )
    assert not any(f.reason == "hook_phase_invalid" for f in findings)


def test_hooks_validator_skips_ordering_class_field_validator_when_field_missing(
    tmp_path: Path,
) -> None:
    """Declaration missing ``ordering_class`` → per-field validator's
    None-skip branch fires (and downstream phase-class-mismatch check
    is also skipped since ordering_class is None)."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
timeout_seconds = 5.0
fail_policy = "fail_closed"
# ordering_class intentionally missing
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_block_shape_invalid"
        and f.payload["failure_mode"] == "declaration_missing_required_field"
        and f.payload["field"] == "ordering_class"
        for f in findings
    )
    assert not any(f.reason == "hook_ordering_class_invalid" for f in findings)


def test_hooks_validator_skips_fail_policy_field_validator_when_field_missing(
    tmp_path: Path,
) -> None:
    """Declaration missing ``fail_policy`` → per-field validator's
    None-skip branch fires."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest(
        """
[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
# fail_policy intentionally missing
"""
    )
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_block_shape_invalid"
        and f.payload["failure_mode"] == "declaration_missing_required_field"
        and f.payload["field"] == "fail_policy"
        for f in findings
    )
    assert not any(f.reason == "hook_fail_policy_invalid" for f in findings)


def test_hooks_validator_pyproject_project_section_not_a_dict(tmp_path: Path) -> None:
    """pyproject.toml has top-level ``project = "string"`` (not a
    table) → ``_read_pyproject_hook_entry_points`` returns ``({}, None)``;
    cross-check sees zero entry points, manifest hook_id surfaces as
    ``manifest_only`` ``hook_unresolved_reference``."""
    _write_pyproject(tmp_path, body='project = "not a table"\n')
    data = _parse(_hook_pack_manifest())
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_unresolved_reference"
        and f.payload["failure_mode"] == "manifest_only"
        and f.payload["hook_id"] == "redact_pii_in_input"
        for f in findings
    ), [f.payload for f in findings]


def test_hooks_validator_pyproject_entry_points_not_a_dict(tmp_path: Path) -> None:
    """pyproject.toml has ``[project]`` but ``entry-points`` is a
    string (not a table) → empty entry-point set → ``manifest_only``
    refusal for the manifest-declared hook_id."""
    _write_pyproject(
        tmp_path,
        body=(
            "[project]\n"
            'name = "cognic-hook-test"\n'
            'version = "0.1.0"\n'
            'entry-points = "not a table"\n'
        ),
    )
    data = _parse(_hook_pack_manifest())
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_unresolved_reference"
        and f.payload["failure_mode"] == "manifest_only"
        and f.payload["hook_id"] == "redact_pii_in_input"
        for f in findings
    ), [f.payload for f in findings]


def test_hooks_validator_pyproject_cognic_hooks_not_a_dict(tmp_path: Path) -> None:
    """pyproject.toml has ``[project.entry-points]`` but
    ``"cognic.hooks"`` is a string → empty entry-point set →
    ``manifest_only`` refusal."""
    _write_pyproject(
        tmp_path,
        body=(
            "[project]\n"
            'name = "cognic-hook-test"\n'
            'version = "0.1.0"\n'
            "[project.entry-points]\n"
            '"cognic.hooks" = "not a table"\n'
        ),
    )
    data = _parse(_hook_pack_manifest())
    findings = validate(data, tmp_path)
    assert any(
        f.reason == "hook_unresolved_reference"
        and f.payload["failure_mode"] == "manifest_only"
        and f.payload["hook_id"] == "redact_pii_in_input"
        for f in findings
    ), [f.payload for f in findings]


def test_hooks_validator_skips_cross_check_when_all_declarations_malformed(
    tmp_path: Path,
) -> None:
    """Hook pack with [hooks] block but every declaration is non-
    table → ``all_declared_hook_ids`` stays empty → the
    ``elif pack_kind == "hook"`` branch is taken and the cross-check
    is suppressed (per-declaration refusals are enough; entry-point
    findings on top would be noise)."""
    _write_pyproject(tmp_path)
    body = _hook_pack_manifest("\n[hooks]\ndeclarations = [42]\n")
    data = _parse(body)
    findings = validate(data, tmp_path)
    # The declaration_entry_not_table refusal is present.
    assert any(
        f.reason == "hook_block_shape_invalid"
        and f.payload["failure_mode"] == "declaration_entry_not_table"
        for f in findings
    )
    # But NO entry-point cross-check findings (manifest_only or
    # pyproject_only); the elif-branch suppressed them.
    assert not any(
        f.reason in {"hook_unresolved_reference", "hook_entry_point_mismatch"} for f in findings
    ), [f.payload for f in findings]


def test_hooks_validator_non_hook_pack_with_malformed_hooks_block_skips_cross_check(
    tmp_path: Path,
) -> None:
    """Non-hook pack (e.g. ``kind="tool"``) with a [hooks] block whose
    declarations are all malformed → ``all_declared_hook_ids`` empty
    AND ``pack_kind != "hook"`` so neither the ``if`` arm nor the
    ``elif`` arm fires; control falls through to ``return findings``.
    Pins the [828→835] branch (non-hook fall-through path)."""
    _write_pyproject(tmp_path)
    # kind="tool" pack with a [hooks] block whose declarations are
    # all non-table entries. Wave-1's _FORBIDDEN_BLOCKS_BY_KIND only
    # refuses HOOK packs declaring [a2a]/[mcp]; the orchestrator does
    # NOT fire kind-strict refusal for non-hook [hooks]. But the
    # validator IS NOT silent on the block — it shape-validates the
    # declarations array regardless of pack kind, and the per-
    # declaration refusals (declaration_entry_not_table here) still
    # fire (asserted below).
    #
    # The narrower branch this test pins is the entry-point cross-
    # check fall-through: after every declaration is malformed,
    # all_declared_hook_ids is empty AND pack_kind != "hook", so
    # neither the `if all_declared_hook_ids:` arm nor the
    # `elif pack_kind == "hook":` arm fires; control falls through
    # the L828→835 branch to `return findings` without emitting any
    # hook_unresolved_reference / hook_entry_point_mismatch. This
    # complements the kind="hook" twin above
    # (test_hooks_validator_skips_cross_check_when_all_declarations_malformed)
    # which pins the elif arm.
    body = """
[pack]
pack_id = "cognic-tool-with-bad-hooks"
kind = "tool"

[hooks]
declarations = [42]
"""
    data = _parse(body)
    findings = validate(data, tmp_path)
    # Per-declaration refusal IS emitted.
    assert any(
        f.reason == "hook_block_shape_invalid"
        and f.payload["failure_mode"] == "declaration_entry_not_table"
        for f in findings
    )
    # No cross-check findings (the L828→835 fall-through branch).
    assert not any(
        f.reason in {"hook_unresolved_reference", "hook_entry_point_mismatch"} for f in findings
    )


def test_hooks_validator_returns_validator_finding_instances(tmp_path: Path) -> None:
    """Every finding is a ValidatorFinding (not a raw dict). Pinned
    so a future refactor doesn't accidentally break the orchestrator's
    finding-shape contract."""
    from cognic_agentos.cli import ValidatorFinding

    _write_pyproject(tmp_path)
    body = _hook_pack_manifest("\n[hooks]\n")  # missing declarations
    data = _parse(body)
    findings = validate(data, tmp_path)
    assert all(isinstance(f, ValidatorFinding) for f in findings)
    assert all(f.severity == "refusal" for f in findings)
