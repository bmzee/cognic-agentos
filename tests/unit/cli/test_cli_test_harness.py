"""Sprint-7A T13 — `agentos test-harness` hybrid runner regressions.

Per Doctrine Decision C (post R31 + R32 + R33 narrowing),
``agentos test-harness <pack-path>`` runs:

  1. Manifest parse via the shared loader (same path :func:`run_validators` uses).
  2. The full validate pipeline (every refusal surfaces).
  3. Dispatch dry-run for tool packs only (Wave-1 narrow per R33 P2 #1):
     ``cls() + await instance.invoke()`` with no kwargs against the
     unmodified host runtime — NO ``fixture_settings`` injection,
     NO ``httpx.MockTransport``, NO transport interception. Skill +
     Agent packs are explicitly refused with closed-enum
     ``harness_unsupported_pack_kind`` at the kind-narrowing gate
     per R31 P2 #2.
  4. Emit a conformance report covering identity / A2A / MCP /
     data-governance / risk-tier / supply-chain / dispatch dry-run.

These tests drive the harness against the task-local fixture at
``tests/fixtures/cli_harness_target_pack/`` (R7 P2 #1 task-decoupling
pattern — T13 ships its own fixture so the slice runs without T15's
``examples/`` reference packs having landed yet). The fixture is a
minimal-but-valid synthetic tool pack: validate-clean manifest +
inert ``HarnessTargetTool._invoke`` returning ``{"echo": <input>}``.

Halt-before-commit per the strict-review-off-gate override (the
plan-of-record marks T13 as off-gate / authoring-only, but the
user's standing rule requires halt-before-commit on every conformance
validator commit regardless).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cognic_agentos.cli import ValidatorFinding, app
from cognic_agentos.cli.test_harness import (
    DispatchOutcome,
    HarnessFinding,
    HarnessReason,
    HarnessReport,
    run_harness,
)

# ---------------------------------------------------------------------------
# Fixture path — single-sourced
# ---------------------------------------------------------------------------

#: Repository root resolved from this test file's location. The
#: fixture pack lives at ``<repo>/tests/fixtures/cli_harness_target_pack/``.
_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_HARNESS_TARGET_PACK: Path = _REPO_ROOT / "tests" / "fixtures" / "cli_harness_target_pack"


# ---------------------------------------------------------------------------
# Helper: write a synthetic broken pack into tmp_path
# ---------------------------------------------------------------------------


def _write_pack(
    pack_path: Path,
    *,
    manifest: str | None = None,
    pyproject: str | None = None,
    tool_module: str | None = None,
    attestations: tuple[str, ...] = ("attestations/cosign.sig",),
) -> Path:
    """Synthesize a pack on disk for harness regressions. Each
    keyword overrides the corresponding fixture-pack default; pass
    ``None`` to copy the default fixture file. ``attestations``
    materialises empty placeholder files for each declared path."""
    pack_path.mkdir(parents=True, exist_ok=True)

    if manifest is None:
        manifest_text = (_HARNESS_TARGET_PACK / "cognic-pack-manifest.toml").read_text()
    else:
        manifest_text = manifest
    (pack_path / "cognic-pack-manifest.toml").write_text(manifest_text)

    if pyproject is None:
        pyproject_text = (_HARNESS_TARGET_PACK / "pyproject.toml").read_text()
    else:
        pyproject_text = pyproject
    (pack_path / "pyproject.toml").write_text(pyproject_text)

    if tool_module is None:
        tool_module_text = (
            _HARNESS_TARGET_PACK / "src" / "cognic_tool_harness_target" / "tool.py"
        ).read_text()
        init_text = (
            _HARNESS_TARGET_PACK / "src" / "cognic_tool_harness_target" / "__init__.py"
        ).read_text()
    else:
        tool_module_text = tool_module
        init_text = "from cognic_tool_harness_target.tool import HarnessTargetTool\n"

    module_dir = pack_path / "src" / "cognic_tool_harness_target"
    module_dir.mkdir(parents=True, exist_ok=True)
    (module_dir / "__init__.py").write_text(init_text)
    (module_dir / "tool.py").write_text(tool_module_text)

    attestation_root = pack_path / "attestations"
    attestation_root.mkdir(parents=True, exist_ok=True)
    for relative in attestations:
        target = pack_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b".")

    # Mirror the T13 fixture: declare both attestation files so
    # supply_chain validator stays clean.
    (pack_path / "attestations" / "sbom.cdx.json").write_bytes(b"{}")
    return pack_path


# ---------------------------------------------------------------------------
# Section A — Public API surface (run_harness)
# ---------------------------------------------------------------------------


def test_run_harness_against_fixture_returns_pass_report() -> None:
    """The committed T13 fixture pack passes every harness gate:
    validate clean + entry-point loadable + dispatch dry-run succeeds."""
    report = run_harness(_HARNESS_TARGET_PACK)
    assert isinstance(report, HarnessReport)
    assert report.overall_status == "pass"
    assert report.pack_id == "cognic-tool-harness-target"
    assert report.pack_kind == "tool"
    assert report.validate_findings == []
    assert len(report.dispatch_results) == 1
    assert report.dispatch_results[0].status == "pass"
    assert report.dispatch_results[0].entry_point_name == "harness_target"


def test_run_harness_dispatch_result_carries_entry_point_ref() -> None:
    """The dispatch result records the ``module:class`` reference
    the harness loaded so pack authors can correlate failures to the
    pyproject.toml entry-point declaration."""
    report = run_harness(_HARNESS_TARGET_PACK)
    result = report.dispatch_results[0]
    assert result.entry_point_ref == ("cognic_tool_harness_target.tool:HarnessTargetTool")


def test_run_harness_returns_dataclass_findings_list_not_none() -> None:
    """``HarnessReport.findings`` is always a list (possibly empty),
    never ``None`` — pack-author tooling can iterate without
    None-checks."""
    report = run_harness(_HARNESS_TARGET_PACK)
    assert isinstance(report.findings, list)


# ---------------------------------------------------------------------------
# Section B — Manifest-shape failures bubble up as harness failures
# ---------------------------------------------------------------------------


def test_run_harness_with_missing_manifest_returns_validate_refusal_finding(
    tmp_path: Path,
) -> None:
    """Pack with no ``cognic-pack-manifest.toml`` fails fast: the
    harness records the validate-side ``manifest_not_found`` refusal
    + emits ``harness_validate_refusals_block_dispatch`` + skips
    dispatch entirely."""
    pack_path = tmp_path / "broken_pack"
    pack_path.mkdir()
    # No manifest written.
    report = run_harness(pack_path)
    assert report.overall_status == "fail"
    refusal_reasons = {f.reason for f in report.validate_findings}
    assert "manifest_not_found" in refusal_reasons
    harness_reasons = {f.reason for f in report.findings}
    assert "harness_validate_refusals_block_dispatch" in harness_reasons
    # Dispatch is skipped when validate refuses.
    assert report.dispatch_results == []


def test_run_harness_with_validate_refusal_skips_dispatch(
    tmp_path: Path,
) -> None:
    """Even a partially-valid manifest that trips one validator
    refusal is enough to skip dispatch — the harness's contract is
    "dispatch only against a validate-clean pack" so authors fix
    manifest issues first."""
    # Strip the [identity] block so identity validator refuses.
    bad_manifest = (
        "[pack]\n"
        'pack_id = "cognic-tool-bad"\n'
        'kind = "tool"\n'
        "[data_governance]\n"
        'data_classes = ["public"]\n'
        'purpose = "operational_telemetry"\n'
        'retention_policy = "none"\n'
        "[risk_tier]\n"
        'tier = "read_only"\n'
        "[supply_chain]\n"
        'attestation_paths = ["attestations/cosign.sig"]\n'
    )
    pack_path = tmp_path / "missing_identity_pack"
    pack_path.mkdir()
    (pack_path / "cognic-pack-manifest.toml").write_text(bad_manifest)
    report = run_harness(pack_path)
    assert report.overall_status == "fail"
    assert report.dispatch_results == []
    assert any(f.reason == "harness_validate_refusals_block_dispatch" for f in report.findings)


# ---------------------------------------------------------------------------
# Section C — pyproject.toml resolution
# ---------------------------------------------------------------------------


def test_run_harness_with_missing_pyproject_emits_pyproject_not_found(
    tmp_path: Path,
) -> None:
    """Pack with a clean manifest but no ``pyproject.toml`` cannot
    be dispatched — the harness emits
    ``harness_pyproject_not_found`` + skips dispatch."""
    pack_path = _write_pack(tmp_path / "no_pyproject")
    (pack_path / "pyproject.toml").unlink()
    report = run_harness(pack_path)
    assert report.overall_status == "fail"
    assert report.validate_findings == []
    assert any(f.reason == "harness_pyproject_not_found" for f in report.findings)


def test_run_harness_with_unparseable_pyproject_emits_unparseable(
    tmp_path: Path,
) -> None:
    """Malformed ``pyproject.toml`` trips
    ``harness_pyproject_unparseable`` — the harness collapses
    underlying TOML / decode errors into a closed-enum reason
    (mirrors the validate orchestrator's manifest-shape gate
    discipline at T6)."""
    pack_path = _write_pack(
        tmp_path / "bad_pyproject",
        pyproject="this is = not valid TOML [[\n",
    )
    report = run_harness(pack_path)
    assert report.overall_status == "fail"
    assert any(f.reason == "harness_pyproject_unparseable" for f in report.findings)


def test_run_harness_with_no_entry_points_emits_no_entry_points_declared(
    tmp_path: Path,
) -> None:
    """A pyproject.toml that declares the project but no
    ``[project.entry-points."cognic.tools"]`` (or the matching
    skill / agent group) trips
    ``harness_no_entry_points_declared`` — pack authors who scaffold
    a pack but forget to wire the entry-point group are caught here
    before they hit the runtime trust gate."""
    bare_pyproject = (
        "[project]\n"
        'name = "cognic-tool-no-entry"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        'dependencies = ["cognic-agentos"]\n'
        "[build-system]\n"
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
    )
    pack_path = _write_pack(tmp_path / "no_entry", pyproject=bare_pyproject)
    report = run_harness(pack_path)
    assert report.overall_status == "fail"
    assert any(f.reason == "harness_no_entry_points_declared" for f in report.findings)


# ---------------------------------------------------------------------------
# Section D — Entry-point loading failures
# ---------------------------------------------------------------------------


def test_run_harness_with_unresolvable_entry_point_emits_unresolvable(
    tmp_path: Path,
) -> None:
    """Entry-point declares ``module:class`` whose source file does
    not exist under the pack's ``src/`` tree — the harness emits
    ``harness_entry_point_unresolvable`` per dispatch slot rather
    than raising ImportError."""
    bad_pyproject = (
        "[project]\n"
        'name = "cognic-tool-unresolvable"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        'dependencies = ["cognic-agentos"]\n'
        "\n"
        '[project.entry-points."cognic.tools"]\n'
        'broken = "cognic_tool_does_not_exist.tool:NoSuchTool"\n'
        "\n"
        "[build-system]\n"
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
    )
    pack_path = _write_pack(tmp_path / "unresolvable", pyproject=bad_pyproject)
    report = run_harness(pack_path)
    assert report.overall_status == "fail"
    assert len(report.dispatch_results) == 1
    result = report.dispatch_results[0]
    assert result.status == "fail"
    assert result.failure_reason == "harness_entry_point_unresolvable"
    assert result.entry_point_name == "broken"


def test_run_harness_with_dispatch_exception_emits_dispatch_failed(
    tmp_path: Path,
) -> None:
    """The fixture tool's ``_invoke`` raises a deterministic
    exception — the harness catches it + records
    ``harness_dispatch_failed`` against the affected entry-point
    slot, with ``error_type`` carried in payload."""
    raising_module = (
        "from typing import Any, ClassVar\n"
        "from cognic_agentos.sdk.tool import Tool\n"
        "\n"
        "class HarnessTargetTool(Tool):\n"
        '    name: ClassVar[str] = "harness_target"\n'
        '    input_schema: ClassVar[dict[str, Any]] = {"type": "object", '
        '"properties": {}, "required": [], "additionalProperties": False}\n'
        '    output_schema: ClassVar[dict[str, Any]] = {"type": "object", '
        '"properties": {}, "required": [], "additionalProperties": False}\n'
        "\n"
        "    async def _invoke(self, **kwargs: Any) -> dict[str, Any]:\n"
        '        raise RuntimeError("synthetic dispatch failure")\n'
    )
    pack_path = _write_pack(tmp_path / "dispatch_fail", tool_module=raising_module)
    report = run_harness(pack_path)
    assert report.overall_status == "fail"
    assert len(report.dispatch_results) == 1
    result = report.dispatch_results[0]
    assert result.status == "fail"
    assert result.failure_reason == "harness_dispatch_failed"
    assert result.payload.get("error_type") == "RuntimeError"


# ---------------------------------------------------------------------------
# Section E — Conformance-report contents
# ---------------------------------------------------------------------------


def test_run_harness_report_records_validate_summary_blocks() -> None:
    """The conformance report records per-concern validate summaries
    so pack authors can read off identity / A2A / MCP / data-governance
    / risk-tier / supply-chain status without re-running validate."""
    report = run_harness(_HARNESS_TARGET_PACK)
    assert "identity" in report.validate_summary
    assert "data_governance" in report.validate_summary
    assert "risk_tier" in report.validate_summary
    assert "supply_chain" in report.validate_summary
    # All concerns clean → "pass".
    assert all(status == "pass" for status in report.validate_summary.values())


def test_run_harness_report_dispatch_outcome_records_response_shape() -> None:
    """A successful dispatch records the response shape returned by
    the SDK's :class:`Tool.invoke` template — pack authors can
    diff this against their declared ``output_schema`` during
    iteration."""
    report = run_harness(_HARNESS_TARGET_PACK)
    result = report.dispatch_results[0]
    assert isinstance(result.outcome, DispatchOutcome)
    assert result.outcome.response_keys == ("echo",)


# ---------------------------------------------------------------------------
# Section F — Typer CLI integration
# ---------------------------------------------------------------------------


def test_test_harness_command_replaces_stub_and_passes_against_fixture() -> None:
    """``agentos test-harness <pack>`` now wires through to
    :func:`run_harness` and exits 0 when the conformance report
    overall_status is ``"pass"``. Replaces the T4 fail-loud stub
    regression in ``test_cli_smoke.py`` (R17-style stub-replacement
    pattern)."""
    runner = CliRunner()
    result = runner.invoke(app, ["test-harness", str(_HARNESS_TARGET_PACK)])
    assert result.exit_code == 0, (
        f"agentos test-harness exited {result.exit_code}; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "test-harness: PASS" in result.stdout
    # The Sprint-7A T13 stub pointer MUST no longer appear once T13
    # replaces the T4 stub (mirrors the T6 stub-replacement pattern).
    assert "Sprint-7A T13" not in result.stderr


def test_test_harness_command_exits_1_on_failed_pack(tmp_path: Path) -> None:
    """When the harness produces a failing report, the Typer wrapper
    exits with code 1 — distinct from validate's exit 1 because the
    failure may originate at dispatch (validate-clean pack with
    broken entry-point)."""
    bad_pyproject = (
        "[project]\n"
        'name = "cognic-tool-no-entry"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        'dependencies = ["cognic-agentos"]\n'
        "[build-system]\n"
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
    )
    pack_path = _write_pack(tmp_path / "fail_pack", pyproject=bad_pyproject)
    runner = CliRunner()
    result = runner.invoke(app, ["test-harness", str(pack_path)])
    assert result.exit_code == 1
    assert "harness_no_entry_points_declared" in result.stderr


def test_test_harness_command_json_output_emits_one_object_per_finding(
    tmp_path: Path,
) -> None:
    """``agentos test-harness --json <pack>`` emits the conformance
    report as a single JSON object on stdout (deterministic-ordered
    keys) — matches the CI-parser-friendly shape ``agentos validate
    --json`` ships at T6."""
    bad_pyproject = (
        "[project]\n"
        'name = "cognic-tool-no-entry"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        'dependencies = ["cognic-agentos"]\n'
        "[build-system]\n"
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
    )
    pack_path = _write_pack(tmp_path / "json_fail", pyproject=bad_pyproject)
    runner = CliRunner()
    result = runner.invoke(app, ["test-harness", "--json", str(pack_path)])
    assert result.exit_code == 1
    # The first non-blank line on stdout MUST be a single JSON object.
    payload = json.loads(result.stdout.strip())
    assert payload["overall_status"] == "fail"
    assert any(f["reason"] == "harness_no_entry_points_declared" for f in payload["findings"])


# ---------------------------------------------------------------------------
# Section G — Closed-enum HarnessReason contract
# ---------------------------------------------------------------------------


def test_harness_reason_literal_exposes_every_seeded_reason() -> None:
    """Drift detector — the closed-enum literal in
    :mod:`cognic_agentos.cli.test_harness` MUST cover every reason
    the harness emits in this test suite. Adding a new emit point
    without updating the literal trips this assertion."""
    from typing import get_args

    expected = frozenset(
        {
            "harness_validate_refusals_block_dispatch",
            "harness_pyproject_not_found",
            "harness_pyproject_unparseable",
            "harness_no_entry_points_declared",
            "harness_entry_point_unresolvable",
            "harness_dispatch_failed",
            # R31 P2 #2 — pack kinds outside the Wave-1 dispatch table.
            "harness_unsupported_pack_kind",
        }
    )
    actual = frozenset(get_args(HarnessReason))
    assert actual == expected, (
        f"HarnessReason drift: extra={actual - expected}, missing={expected - actual}"
    )


def test_harness_finding_carries_severity_reason_message() -> None:
    """Carrier dataclass shape mirrors :class:`ValidatorFinding` —
    severity + reason + message + payload, so CI parsers can
    handle harness findings + validate findings through the same
    rendering path."""
    finding = HarnessFinding(
        severity="refusal",
        reason="harness_pyproject_not_found",
        message="x",
    )
    assert finding.severity == "refusal"
    assert finding.reason == "harness_pyproject_not_found"
    assert finding.message == "x"
    assert finding.payload == {}


# ---------------------------------------------------------------------------
# Section H — Lifecycle pinner (T5 scaffolder ↔ T13 harness)
# ---------------------------------------------------------------------------


def test_t5_scaffolder_output_runs_through_harness_with_validate_block(
    tmp_path: Path,
) -> None:
    """A freshly-scaffolded pack (AUTHOR-FILL placeholders + stub
    ``_invoke``) is the canonical iteration loop's starting point.
    The harness MUST surface it as ``overall_status="fail"`` —
    ``agentos validate`` refuses the AUTHOR-FILL identity fields,
    and the harness short-circuits dispatch on that. Pinned here
    so a future T5 template change that accidentally produces a
    validate-clean scaffold (e.g., dropping AUTHOR-FILL entirely)
    is caught at the harness lifecycle gate."""
    from cognic_agentos.cli.init import scaffold

    pack_root = scaffold(kind="tool", pack_name="t13_pinner", parent_dir=tmp_path)
    report = run_harness(pack_root)
    assert report.overall_status == "fail"
    assert any(f.reason == "harness_validate_refusals_block_dispatch" for f in report.findings)


# ---------------------------------------------------------------------------
# Section I — Defensive coverage on entry-point loading edge cases
# ---------------------------------------------------------------------------


def test_run_harness_with_malformed_entry_point_ref_emits_unresolvable(
    tmp_path: Path,
) -> None:
    """An entry-point reference missing the ``module:class`` colon
    is caught by the loader's ValueError branch + surfaced as
    ``harness_entry_point_unresolvable`` (NOT a Python traceback
    leaking past the harness boundary)."""
    bad_pyproject = (
        "[project]\n"
        'name = "cognic-tool-malformed"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        'dependencies = ["cognic-agentos"]\n'
        "\n"
        '[project.entry-points."cognic.tools"]\n'
        'no_colon = "no_module_no_class"\n'
        "\n"
        "[build-system]\n"
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
    )
    pack_path = _write_pack(tmp_path / "malformed_ref", pyproject=bad_pyproject)
    report = run_harness(pack_path)
    result = report.dispatch_results[0]
    assert result.failure_reason == "harness_entry_point_unresolvable"
    assert result.payload.get("error_type") == "ValueError"


def test_run_harness_with_module_class_name_mismatch_emits_unresolvable(
    tmp_path: Path,
) -> None:
    """The module file resolves but the named class is missing —
    AttributeError surfaces as ``harness_entry_point_unresolvable``."""
    bad_pyproject = (
        "[project]\n"
        'name = "cognic-tool-classmiss"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        'dependencies = ["cognic-agentos"]\n'
        "\n"
        '[project.entry-points."cognic.tools"]\n'
        'classmiss = "cognic_tool_harness_target.tool:NoSuchClass"\n'
        "\n"
        "[build-system]\n"
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
    )
    pack_path = _write_pack(tmp_path / "class_miss", pyproject=bad_pyproject)
    report = run_harness(pack_path)
    result = report.dispatch_results[0]
    assert result.failure_reason == "harness_entry_point_unresolvable"
    assert result.payload.get("error_type") == "AttributeError"


def test_run_harness_with_non_class_target_emits_unresolvable(
    tmp_path: Path,
) -> None:
    """The named symbol exists in the module but is not a class
    (e.g., a function) — TypeError surfaces as
    ``harness_entry_point_unresolvable``."""
    function_module = (
        "def HarnessTargetTool():\n"
        '    """A function (not a class) at the entry-point target."""\n'
        "    return None\n"
    )
    pack_path = _write_pack(tmp_path / "non_class", tool_module=function_module)
    report = run_harness(pack_path)
    result = report.dispatch_results[0]
    assert result.failure_reason == "harness_entry_point_unresolvable"
    assert result.payload.get("error_type") == "TypeError"


def test_run_harness_with_module_import_error_emits_unresolvable(
    tmp_path: Path,
) -> None:
    """Module body raises ImportError at import time — the harness's
    exec_module-failure branch (line 389) catches it + cleans up
    sys.modules + surfaces the closed-enum refusal."""
    raising_module = (
        "from typing import Any, ClassVar\n"
        "from cognic_agentos.sdk.tool import Tool\n"
        "\n"
        '_ = __import__("a_module_that_definitely_does_not_exist_12345")\n'
        "\n"
        "class HarnessTargetTool(Tool):\n"
        '    name: ClassVar[str] = "harness_target"\n'
    )
    pack_path = _write_pack(tmp_path / "import_error", tool_module=raising_module)
    report = run_harness(pack_path)
    result = report.dispatch_results[0]
    assert result.failure_reason == "harness_entry_point_unresolvable"
    # ImportError or ModuleNotFoundError both acceptable
    assert result.payload.get("error_type") in {"ImportError", "ModuleNotFoundError"}


# ---------------------------------------------------------------------------
# Section J — format_report unified text-mode + JSON helpers
# ---------------------------------------------------------------------------


def test_format_report_text_mode_appends_annotations_to_summary() -> None:
    """The unified :func:`format_report` text-mode path stitches
    summary + annotations together — kept narrow for callers that
    want a single text blob (the CLI itself uses the split helpers
    so stdout / stderr routing matches validate's pattern)."""
    from cognic_agentos.cli.test_harness import format_report

    bad_report = HarnessReport(
        pack_path="/tmp/x",
        pack_id="x",
        pack_kind="tool",
        overall_status="fail",
        validate_findings=[],
        validate_summary={
            c: "pass"
            for c in (
                "identity",
                "a2a",
                "mcp",
                "data_governance",
                "risk_tier",
                "supply_chain",
            )
        },
        findings=[
            HarnessFinding(
                severity="refusal",
                reason="harness_pyproject_not_found",
                message="missing",
            )
        ],
        dispatch_results=[],
    )
    text = format_report(bad_report, json_output=False)
    assert "test-harness: FAIL" in text
    assert "harness_pyproject_not_found" in text


def test_run_harness_with_warning_only_validate_passes_dispatch(
    tmp_path: Path,
) -> None:
    """A pack whose manifest is missing the AGNTCY/OASF
    ``oasf_capability_set`` field surfaces a warning-severity
    validate finding; the harness MUST treat warnings as non-blocking
    (per validate's severity-aware exit-code semantics) — dispatch
    proceeds + the report's overall_status stays ``"pass"`` if
    dispatch succeeds. Pinned here so a future regression that
    treats warnings as refusals at the harness boundary trips."""
    # Fixture manifest has oasf_capability_set; clone + drop it.
    fixture_manifest = (_HARNESS_TARGET_PACK / "cognic-pack-manifest.toml").read_text()
    warning_manifest = (
        "\n".join(
            line for line in fixture_manifest.splitlines() if "oasf_capability_set" not in line
        )
        + "\n"
    )
    pack_path = _write_pack(tmp_path / "warn_only", manifest=warning_manifest)
    report = run_harness(pack_path)
    # No refusals → dispatch ran → overall pass even though one
    # warning fired.
    assert report.overall_status == "pass"
    warnings = [f for f in report.validate_findings if not f.affects_exit_code]
    assert any(f.reason == "identity_oasf_capability_set_missing" for f in warnings)


def test_run_harness_with_pyproject_missing_entry_point_table_emits_no_entry_points(
    tmp_path: Path,
) -> None:
    """``[project.entry-points]`` table absent (rather than empty)
    trips ``harness_no_entry_points_declared`` via the defensive
    branch in ``_extract_entry_points`` (project block resolves but
    no ``entry-points`` sub-table)."""
    no_entry_points_pyproject = (
        "[project]\n"
        'name = "cognic-tool-noep"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        'dependencies = ["cognic-agentos"]\n'
        # No [project.entry-points] table at all.
        "[build-system]\n"
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
    )
    pack_path = _write_pack(tmp_path / "no_ep", pyproject=no_entry_points_pyproject)
    report = run_harness(pack_path)
    assert report.overall_status == "fail"
    assert any(f.reason == "harness_no_entry_points_declared" for f in report.findings)


def test_run_harness_with_pyproject_project_block_malformed_emits_no_entry_points(
    tmp_path: Path,
) -> None:
    """When ``[project]`` is missing entirely, the defensive empty-
    dict return in ``_extract_entry_points`` keeps the harness from
    crashing on .get() against a non-dict; the caller sees the
    standard ``harness_no_entry_points_declared`` refusal."""
    no_project_pyproject = (
        '[build-system]\nrequires = ["hatchling"]\nbuild-backend = "hatchling.build"\n'
    )
    pack_path = _write_pack(tmp_path / "no_project", pyproject=no_project_pyproject)
    report = run_harness(pack_path)
    assert report.overall_status == "fail"
    assert any(f.reason == "harness_no_entry_points_declared" for f in report.findings)


def test_format_report_summary_renders_dispatch_failure_line() -> None:
    """The summary helper renders a ``dispatch.<name>: fail (reason: msg)``
    line for any non-pass DispatchResult — covers the
    ``format_report_summary`` failure-line branch."""
    from cognic_agentos.cli.test_harness import (
        DispatchResult,
        format_report_summary,
    )

    report = HarnessReport(
        pack_path="/tmp/z",
        pack_id="z",
        pack_kind="tool",
        overall_status="fail",
        validate_findings=[],
        validate_summary={
            c: "pass"
            for c in (
                "identity",
                "a2a",
                "mcp",
                "data_governance",
                "risk_tier",
                "supply_chain",
            )
        },
        findings=[],
        dispatch_results=[
            DispatchResult(
                entry_point_name="thing",
                entry_point_ref="m:C",
                status="fail",
                failure_reason="harness_dispatch_failed",
                failure_message="boom",
            ),
        ],
    )
    text = format_report_summary(report)
    assert "dispatch.thing: fail" in text
    assert "harness_dispatch_failed" in text


def test_format_report_finding_annotations_skips_warnings_appends_refusals() -> None:
    """A validate ``ValidatorFinding`` with warning severity is
    skipped (no annotation); a refusal-severity finding gets one
    annotation line appended. Covers the warning-skip branch in
    :func:`format_report_finding_annotations`."""
    from cognic_agentos.cli.test_harness import format_report_finding_annotations

    report = HarnessReport(
        pack_path="/tmp/w",
        pack_id="w",
        pack_kind="tool",
        overall_status="fail",
        validate_findings=[
            ValidatorFinding(
                severity="warning",
                reason="identity_oasf_capability_set_missing",
                message="warn — should be skipped",
            ),
            ValidatorFinding(
                severity="refusal",
                reason="manifest_not_found",
                message="real refusal",
            ),
        ],
        validate_summary={},
        findings=[],
        dispatch_results=[],
    )
    annotations = format_report_finding_annotations(report)
    assert len(annotations) == 1
    assert "manifest_not_found" in annotations[0]
    assert "identity_oasf_capability_set_missing" not in annotations[0]


def test_format_report_text_mode_no_annotations_returns_summary_only() -> None:
    """No findings → format_report returns the summary unchanged
    (no trailing newline + no annotation lines)."""
    from cognic_agentos.cli.test_harness import format_report

    pass_report = HarnessReport(
        pack_path="/tmp/y",
        pack_id="y",
        pack_kind="tool",
        overall_status="pass",
        validate_findings=[],
        validate_summary={
            c: "pass"
            for c in (
                "identity",
                "a2a",
                "mcp",
                "data_governance",
                "risk_tier",
                "supply_chain",
            )
        },
        findings=[],
        dispatch_results=[],
    )
    text = format_report(pass_report, json_output=False)
    assert "test-harness: PASS" in text
    assert "::error" not in text


# ---------------------------------------------------------------------------
# Section K — R31 P2 #1: entry-point ref escape protection
# ---------------------------------------------------------------------------
#
# An entry-point reference that contains an absolute filesystem path
# (or any non-Python-identifier segment) MUST NOT let the harness
# load modules from outside the pack's src tree. Without segment
# validation, a malicious pack could point ``cognic.tools`` at an
# arbitrary host file (``"/etc/passwd_module:Bad"`` →
# ``Path("/etc/passwd_module").with_suffix(".py")`` is absolute, and
# ``pack_path / "src" / Path("/etc/passwd_module.py")`` discards the
# pack root because the right-hand operand is absolute).
#
# Defense layers:
#
#   1. Segment-validation at parse time — reject any module-path
#      segment that isn't a Python identifier. Catches the
#      leading-slash absolute-path attack at the cheapest cost.
#   2. Resolve-and-relative-to post-check — after computing the
#      candidate module file inside ``pack_path/src``, resolve it
#      and require ``is_relative_to(src_root.resolve())``. Catches
#      symlink-target escapes that the regex doesn't see.


def test_run_harness_entry_point_ref_with_absolute_path_emits_unresolvable(
    tmp_path: Path,
) -> None:
    """Reference like ``/etc/passwd_module:Bad`` is rejected at the
    segment-validation guard with ValueError → surfaces as
    ``harness_entry_point_unresolvable`` BEFORE any filesystem
    probe. Without this guard, the loader could probe + load
    arbitrary files outside the pack tree."""
    bad_pyproject = (
        "[project]\n"
        'name = "cognic-tool-escape-abs"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        'dependencies = ["cognic-agentos"]\n'
        "\n"
        '[project.entry-points."cognic.tools"]\n'
        'escape = "/etc/passwd_module:Bad"\n'
        "\n"
        "[build-system]\n"
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
    )
    pack_path = _write_pack(tmp_path / "absolute_ref", pyproject=bad_pyproject)
    report = run_harness(pack_path)
    result = report.dispatch_results[0]
    assert result.failure_reason == "harness_entry_point_unresolvable"
    assert result.payload.get("error_type") == "ValueError"


def test_run_harness_entry_point_ref_with_dotdot_segment_emits_unresolvable(
    tmp_path: Path,
) -> None:
    """``..``-style traversal segments are also rejected — they
    aren't Python identifiers, so the segment-validation guard
    fires before any filesystem operation."""
    bad_pyproject = (
        "[project]\n"
        'name = "cognic-tool-escape-rel"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        'dependencies = ["cognic-agentos"]\n'
        "\n"
        '[project.entry-points."cognic.tools"]\n'
        'escape = "..outside:Bad"\n'
        "\n"
        "[build-system]\n"
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
    )
    pack_path = _write_pack(tmp_path / "dotdot_ref", pyproject=bad_pyproject)
    report = run_harness(pack_path)
    result = report.dispatch_results[0]
    assert result.failure_reason == "harness_entry_point_unresolvable"
    assert result.payload.get("error_type") == "ValueError"


def test_run_harness_entry_point_via_symlink_outside_pack_src_emits_unresolvable(
    tmp_path: Path,
) -> None:
    """A symlink inside ``pack/src/`` whose target is OUTSIDE the
    pack tree is rejected by the resolve+is_relative_to defense-
    in-depth check (the regex-only segment guard wouldn't see it
    because the linked module name is a valid identifier)."""
    # Plant a real .py file outside the pack tree.
    outside_dir = tmp_path / "outside_pack"
    outside_dir.mkdir()
    outside_module = outside_dir / "evil.py"
    outside_module.write_text(
        "from typing import Any, ClassVar\n"
        "from cognic_agentos.sdk.tool import Tool\n"
        "\n"
        "class Bad(Tool):\n"
        '    name: ClassVar[str] = "bad"\n'
        "    input_schema: ClassVar[dict[str, Any]] = "
        '{"type": "object", "properties": {}, "required": [], '
        '"additionalProperties": False}\n'
        "    output_schema: ClassVar[dict[str, Any]] = "
        '{"type": "object", "properties": {}, "required": [], '
        '"additionalProperties": False}\n'
        "\n"
        "    async def _invoke(self, **kwargs: Any) -> dict[str, Any]:\n"
        '        return {"escaped": True}\n'
    )
    # Build a pack whose entry point references a symlink we'll plant
    # under pack/src/ pointing at the outside file.
    bad_pyproject = (
        "[project]\n"
        'name = "cognic-tool-symlink-escape"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        'dependencies = ["cognic-agentos"]\n'
        "\n"
        '[project.entry-points."cognic.tools"]\n'
        'symesc = "linked_module:Bad"\n'
        "\n"
        "[build-system]\n"
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
    )
    pack_path = _write_pack(tmp_path / "symlink_pack", pyproject=bad_pyproject)
    # Replace whatever module the helper wrote with a symlink at the
    # canonical path the entry-point ref resolves to.
    src_dir = pack_path / "src"
    target_path = src_dir / "linked_module.py"
    if target_path.exists() or target_path.is_symlink():
        target_path.unlink()
    target_path.symlink_to(outside_module)
    report = run_harness(pack_path)
    result = report.dispatch_results[0]
    assert result.failure_reason == "harness_entry_point_unresolvable"
    # The post-resolve relative-to check raises ValueError.
    assert result.payload.get("error_type") == "ValueError"


# ---------------------------------------------------------------------------
# Section L — R31 P2 #2: narrow Wave-1 dispatch to tool packs
# ---------------------------------------------------------------------------


def _validate_clean_skill_manifest() -> str:
    """A validate-clean kind=skill manifest used to exercise the
    pack-kind narrowing gate. Mirrors the T13 fixture pack manifest
    with kind="skill" substituted in + identity fields adjusted to
    pass identity validator's skill-pack rules."""
    return (
        "[pack]\n"
        'pack_id = "cognic-skill-narrowing"\n'
        "schema_version = 1\n"
        'kind = "skill"\n'
        "\n"
        "[identity]\n"
        'agent_id = "did:web:example.com:skills:narrowing"\n'
        'display_name = "Narrowing Skill"\n'
        'provider_organization = "Sprint-7A T13/R31 fixtures"\n'
        'provider_url = "https://example.com/narrowing"\n'
        'oasf_capability_set = ["test.v1"]\n'
        "\n"
        "[data_governance]\n"
        'data_classes = ["public", "internal"]\n'
        'purpose = "operational_telemetry"\n'
        'retention_policy = "none"\n'
        "\n"
        "[risk_tier]\n"
        'tier = "read_only"\n'
        "\n"
        "[supply_chain]\n"
        "attestation_paths = [\n"
        '    "attestations/cosign.sig",\n'
        '    "attestations/sbom.cdx.json",\n'
        "]\n"
    )


def test_run_harness_with_skill_kind_emits_unsupported_pack_kind(
    tmp_path: Path,
) -> None:
    """T13 narrows the harness's dispatch dry-run to ``kind="tool"``
    packs only. Skill packs reach the harness with a validate-clean
    manifest but receive the closed-enum
    ``harness_unsupported_pack_kind`` refusal — pointing at the
    expansion task — instead of a generic dispatch error from
    ``Skill(tools=...)`` not being satisfied."""
    pack_path = _write_pack(
        tmp_path / "skill_pack",
        manifest=_validate_clean_skill_manifest(),
    )
    report = run_harness(pack_path)
    # Validate must be clean for the kind-narrowing gate to be the
    # surfaced refusal — otherwise the validate-refusal short-circuit
    # would mask it.
    refusals = [f for f in report.validate_findings if f.affects_exit_code]
    assert refusals == [], f"validate refused skill manifest: {refusals!r}"
    assert report.overall_status == "fail"
    assert any(f.reason == "harness_unsupported_pack_kind" for f in report.findings)
    assert report.dispatch_results == []


def test_unsupported_pack_kind_finding_carries_pack_kind_in_payload(
    tmp_path: Path,
) -> None:
    """The closed-enum refusal records the offending pack kind in
    payload so CI parsers + harness-extension authors can route
    on the kind without re-parsing the manifest."""
    pack_path = _write_pack(
        tmp_path / "skill_payload",
        manifest=_validate_clean_skill_manifest(),
    )
    report = run_harness(pack_path)
    finding = next(f for f in report.findings if f.reason == "harness_unsupported_pack_kind")
    assert finding.payload["pack_kind"] == "skill"
    assert "tool" in finding.payload["supported_kinds"]


# ---------------------------------------------------------------------------
# Section M — R31 P2 #3: import context spans load + dispatch
# ---------------------------------------------------------------------------


def test_run_harness_dispatch_with_lazy_intra_pack_import_succeeds(
    tmp_path: Path,
) -> None:
    """``_invoke`` does a lazy intra-pack import (``from
    <pack>.helper import VALUE`` inside the method body). The
    harness MUST keep ``pack/src`` on sys.path across both the
    entry-point load AND the dispatch invocation so the lazy
    import resolves cleanly. Without the cross-phase scoping,
    pack code that worked when pip-installed would fail under
    the harness."""
    main_module = (
        "from typing import Any, ClassVar\n"
        "from cognic_agentos.sdk.tool import Tool\n"
        "\n"
        "class HarnessTargetTool(Tool):\n"
        '    name: ClassVar[str] = "harness_target"\n'
        "    input_schema: ClassVar[dict[str, Any]] = "
        '{"type": "object", "properties": {}, "required": [], '
        '"additionalProperties": False}\n'
        "    output_schema: ClassVar[dict[str, Any]] = "
        '{"type": "object", "properties": {"v": {"type": "integer"}}, '
        '"required": ["v"], "additionalProperties": False}\n'
        "\n"
        "    async def _invoke(self, **kwargs: Any) -> dict[str, Any]:\n"
        # Lazy import inside method body. Without sys.path scoping
        # across load + dispatch, this raises ModuleNotFoundError
        # because the entry-point loader had already removed
        # pack/src from sys.path by the time _invoke runs.
        "        from cognic_tool_harness_target.helper import VALUE\n"
        '        return {"v": VALUE}\n'
    )
    pack_path = _write_pack(tmp_path / "lazy_import", tool_module=main_module)
    helper_path = pack_path / "src" / "cognic_tool_harness_target" / "helper.py"
    helper_path.write_text("VALUE = 42\n")
    report = run_harness(pack_path)
    assert report.overall_status == "pass", (
        f"lazy intra-pack import dispatch failed: {report.findings} {report.dispatch_results}"
    )
    assert report.dispatch_results[0].status == "pass"


def test_run_harness_does_not_leave_pack_modules_in_sys_modules(
    tmp_path: Path,
) -> None:
    """Repeated harness invocations don't pollute ``sys.modules``.
    Each dispatch cycle takes a snapshot of ``sys.modules`` at
    entry + pops every newly-added key on exit. Without this,
    in-process test runs (pytest CI, harness-from-harness, etc.)
    would see stale package state across runs — a shipped pack
    that worked on first run might fail on second run with
    silently-cached old class objects.

    Order-independent: clean any prior fixture-pack leakage from
    previous tests before snapshotting so the regression catches
    the leak independent of test execution order."""
    import sys

    pack_path = _write_pack(tmp_path / "modules_cleanup")
    # Defensive cleanup of any prior leakage so this test catches
    # the actual run_harness behavior, not coincidental from-prior-
    # test cache state.
    for stale_key in [
        k for k in list(sys.modules.keys()) if k.startswith("cognic_tool_harness_target")
    ]:
        sys.modules.pop(stale_key, None)
    before = set(sys.modules.keys())
    report = run_harness(pack_path)
    assert report.overall_status == "pass"
    after = set(sys.modules.keys())
    leaked = after - before
    # Strict: no fixture-pack modules added during run_harness.
    pack_module_leaks = {k for k in leaked if k.startswith("cognic_tool_harness_target")}
    assert pack_module_leaks == set(), (
        f"run_harness leaked pack modules into sys.modules: {pack_module_leaks}"
    )


# ---------------------------------------------------------------------------
# Section N — R31 P3: dispatch failures surface on stderr
# ---------------------------------------------------------------------------


def test_test_harness_command_emits_dispatch_failure_to_stderr(
    tmp_path: Path,
) -> None:
    """Failed DispatchResults render ``::error`` annotations on
    stderr (mirrors validate's stderr-bound annotation pattern at
    T6). Without this, CI parsers consuming the validate-style
    stream would miss the harness's actual failure reason — the
    only signal would be exit code 1 with stderr empty."""
    raising_module = (
        "from typing import Any, ClassVar\n"
        "from cognic_agentos.sdk.tool import Tool\n"
        "\n"
        "class HarnessTargetTool(Tool):\n"
        '    name: ClassVar[str] = "harness_target"\n'
        "    input_schema: ClassVar[dict[str, Any]] = "
        '{"type": "object", "properties": {}, "required": [], '
        '"additionalProperties": False}\n'
        "    output_schema: ClassVar[dict[str, Any]] = "
        '{"type": "object", "properties": {}, "required": [], '
        '"additionalProperties": False}\n'
        "\n"
        "    async def _invoke(self, **kwargs: Any) -> dict[str, Any]:\n"
        '        raise RuntimeError("synthetic dispatch failure")\n'
    )
    pack_path = _write_pack(tmp_path / "stderr_dispatch", tool_module=raising_module)
    runner = CliRunner()
    result = runner.invoke(app, ["test-harness", str(pack_path)])
    assert result.exit_code == 1
    assert "::error" in result.stderr
    assert "harness_dispatch_failed" in result.stderr
    assert "harness_target" in result.stderr


def test_format_report_finding_annotations_includes_dispatch_failures() -> None:
    """Direct unit check on :func:`format_report_finding_annotations`
    — failed DispatchResults emit one annotation each, alongside
    validate refusals + harness-side findings."""
    from cognic_agentos.cli.test_harness import (
        DispatchResult,
        format_report_finding_annotations,
    )

    report = HarnessReport(
        pack_path="/tmp/r31p3",
        pack_id="x",
        pack_kind="tool",
        overall_status="fail",
        validate_findings=[],
        validate_summary={
            c: "pass"
            for c in (
                "identity",
                "a2a",
                "mcp",
                "data_governance",
                "risk_tier",
                "supply_chain",
            )
        },
        findings=[],
        dispatch_results=[
            DispatchResult(
                entry_point_name="thing",
                entry_point_ref="m:C",
                status="fail",
                failure_reason="harness_dispatch_failed",
                failure_message="synthetic",
            ),
        ],
    )
    annotations = format_report_finding_annotations(report)
    # Exactly one annotation, carrying the dispatch slot's reason.
    assert len(annotations) == 1
    assert "harness_dispatch_failed" in annotations[0]
    assert "thing" in annotations[0]


# ---------------------------------------------------------------------------
# Section O — R32 P2 #1: pack/src resolve traceback wrap
# ---------------------------------------------------------------------------
#
# An earlier R31 fix wrapped Path.resolve() inside _load_entry_point_class
# but ``_dispatch_one`` resolved ``pack_path / "src"`` BEFORE entering
# its try/finally. A malformed pack with ``src -> src`` (or any other
# filesystem condition that makes ``Path.resolve()`` raise) leaked
# RuntimeError / OSError directly out of run_harness instead of
# returning the deterministic ``harness_entry_point_unresolvable``
# refusal. R32 P2 #1 closes that gap by moving the resolve INSIDE
# the guarded path + collapsing OSError/RuntimeError into the same
# closed-enum reason — same defensive doctrine T12 R29 applied to
# the supply_chain validator's path checks.
#
# Cross-platform regression strategy via ``monkeypatch.setattr`` on
# ``Path.resolve`` (mirrors T12 R29 doctrine for platform-stable
# coverage of resolve-error paths regardless of Python version /
# OS-specific symlink-loop behaviour).


def test_run_harness_with_pack_src_resolve_oserror_emits_unresolvable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``OSError`` from ``(pack_path/'src').resolve()`` (e.g.,
    POSIX errno 40 on a self-referential symlink) is collapsed
    into the closed-enum ``harness_entry_point_unresolvable``
    refusal — never leaks as a traceback to the harness caller.
    Per the T12 R29 doctrine extended here to the harness src-
    resolve path."""
    pack_path = _write_pack(tmp_path / "src_oserror")
    target_src = pack_path / "src"

    real_resolve = Path.resolve

    def _raise_for_pack_src(self: Path, strict: bool = False) -> Path:
        if self == target_src:
            raise OSError(40, "Too many levels of symbolic links", str(self))
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _raise_for_pack_src)

    report = run_harness(pack_path)
    # The harness reached _dispatch_one (validate clean + pyproject
    # parsed + entry-points extracted), then resolve(pack/src)
    # tripped the wrap. Surfaces as a per-slot failure.
    assert report.overall_status == "fail"
    assert len(report.dispatch_results) == 1
    result = report.dispatch_results[0]
    assert result.failure_reason == "harness_entry_point_unresolvable"
    assert result.payload.get("error_type") == "OSError"


def test_run_harness_with_pack_src_resolve_runtime_error_emits_unresolvable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``RuntimeError`` from ``(pack_path/'src').resolve()`` (e.g.,
    older Python's symlink-loop signal) is also collapsed into
    the closed-enum refusal — covers both failure types the
    T12 R29 doctrine pinned for the supply_chain seam."""
    pack_path = _write_pack(tmp_path / "src_runtime_err")
    target_src = pack_path / "src"

    real_resolve = Path.resolve

    def _raise_for_pack_src(self: Path, strict: bool = False) -> Path:
        if self == target_src:
            raise RuntimeError("Symlink loop detected")
        return real_resolve(self, strict=strict)

    monkeypatch.setattr(Path, "resolve", _raise_for_pack_src)

    report = run_harness(pack_path)
    assert report.overall_status == "fail"
    result = report.dispatch_results[0]
    assert result.failure_reason == "harness_entry_point_unresolvable"
    assert result.payload.get("error_type") == "RuntimeError"


# ---------------------------------------------------------------------------
# Section P — R32 P2 #2: sys.modules collision protection
# ---------------------------------------------------------------------------


def test_run_harness_with_module_name_collision_with_stdlib_emits_unresolvable(
    tmp_path: Path,
) -> None:
    """A pack whose entry-point module name collides with an
    already-loaded module (e.g., a stdlib name like ``json``)
    is rejected at the loader BEFORE ``sys.modules[<name>]``
    gets overwritten. Without this pre-check, the loader would
    temporarily replace ``sys.modules['json']`` — corrupting the
    host interpreter for any downstream code that imports during
    dispatch (and leaving the corruption if cleanup fails).

    The set-of-keys cleanup pattern from R31 P2 #3 doesn't catch
    this case because ``"json"`` is in the ``before`` snapshot —
    the diff ``after - before`` excludes it, so the cleanup logic
    skips restoring the original module. Pre-check + reject is
    the load-bearing fix."""
    import sys as real_sys

    bad_pyproject = (
        "[project]\n"
        'name = "cognic-tool-collision"\n'
        'version = "0.1.0"\n'
        'requires-python = ">=3.12"\n'
        'dependencies = ["cognic-agentos"]\n'
        "\n"
        '[project.entry-points."cognic.tools"]\n'
        'collision = "json:CollisionTool"\n'
        "\n"
        "[build-system]\n"
        'requires = ["hatchling"]\n'
        'build-backend = "hatchling.build"\n'
    )
    pack_path = _write_pack(tmp_path / "collision_pack", pyproject=bad_pyproject)
    # Plant ``src/json.py`` so the loader's filesystem probe + the
    # segment-validation + the resolve-and-relative-to check all
    # pass. WITHOUT the pre-check, the loader would replace
    # ``sys.modules["json"]`` with this module + corrupt the host
    # interpreter's stdlib ``json`` for any downstream import.
    (pack_path / "src" / "json.py").write_text(
        "from typing import Any, ClassVar\n"
        "from cognic_agentos.sdk.tool import Tool\n"
        "\n"
        "class CollisionTool(Tool):\n"
        '    name: ClassVar[str] = "collision"\n'
        "    input_schema: ClassVar[dict[str, Any]] = "
        '{"type": "object", "properties": {}, "required": [], '
        '"additionalProperties": False}\n'
        "    output_schema: ClassVar[dict[str, Any]] = "
        '{"type": "object", "properties": {}, "required": [], '
        '"additionalProperties": False}\n'
        "\n"
        "    async def _invoke(self, **kwargs: Any) -> dict[str, Any]:\n"
        "        return {}\n"
    )

    # Snapshot the host's json module BEFORE the harness runs so
    # we can verify it survives unmodified.
    json_before = real_sys.modules.get("json")
    assert json_before is not None, "test prerequisite: stdlib json must be loaded"

    report = run_harness(pack_path)

    json_after = real_sys.modules.get("json")
    # The harness MUST refuse the colliding module name + leave
    # the host interpreter's json module exactly as it was.
    assert json_after is json_before, (
        "harness corrupted host sys.modules['json'] — collision "
        "pre-check failed; the loader temporarily overwrote a "
        "host module."
    )
    assert report.overall_status == "fail"
    result = report.dispatch_results[0]
    assert result.failure_reason == "harness_entry_point_unresolvable"
    assert result.payload.get("error_type") == "ValueError"


# ---------------------------------------------------------------------------
# Section Q — R33 P2 #1: Wave-1 narrow contract pin (no transport interception)
# ---------------------------------------------------------------------------
#
# An earlier draft of the T13 docstrings + Doctrine Decision C in
# the plan-of-record promised "fixture adapters memory-back every
# persistence + secret + observability surface; pack code that
# tries to hit a live HTTP / Vault / Postgres / Langfuse surface
# fails the harness with a deterministic refusal." That sandboxing
# was never implemented — ``_dry_run_invoke`` simply does ``cls()
# + await instance.invoke()`` with no fixture wiring, no
# ``httpx.MockTransport`` injection, no env-var scoping. Pack
# code runs against the unmodified host runtime.
#
# R33 P2 #1 corrects the docs across every site (module docstring,
# plan Doctrine C bullets 3-4, reference-pack lifecycle prose, test
# inventory, closeout criteria) AND pins the chosen narrow behavior
# as documentation-as-code via the regression below.


def test_run_harness_wave1_narrow_contract_no_transport_interception(
    tmp_path: Path,
) -> None:
    """R33 P2 #1 — pin the Wave-1 narrow harness contract.

    The harness's dispatch dry-run runs ``cls() +
    await instance.invoke()`` against the SDK's already-validated
    :class:`Tool.invoke` template AND the unmodified host runtime.
    NO fixture-adapter injection, NO ``httpx.MockTransport``, NO
    env-var sandboxing, NO filesystem isolation. Pack ``_invoke()``
    code runs against whatever the host process exposes.

    Pack authors who need fixture-adapter isolation wire it
    themselves via ``agentos_sdk.testing.fixture_settings`` /
    ``fixture_audit_capture`` in their pack test suite. The
    ``agentos test-harness`` command is the pre-publish sanity
    gate (validate + dispatch + conformance report), NOT a
    sandbox.

    Two assertions pin the contract:

      1. The closed-enum :data:`HarnessReason` literal does NOT
         expose any ``live_transport`` / ``transport_intercepted``
         reason — confirms there is no aspirational sandboxing
         surface lurking in the closed-enum vocabulary.
      2. A pack whose ``_invoke()`` reads a host env var succeeds
         + the dispatch result records the response shape
         unchanged — confirms the host runtime is not modified.

    A future expansion that adds transport interception MUST flip
    this regression to assert the new sandboxing behavior + update
    the module docstring + plan §Doctrine Decision C bullets 3-4
    + reference-pack lifecycle prose + test inventory + closeout
    criteria in the same commit."""
    from typing import get_args

    # Pin (1): no transport-interception reason in the vocabulary.
    refusal_reasons = set(get_args(HarnessReason))
    transport_intercept_reasons = {
        r for r in refusal_reasons if "live_transport" in r or "transport_intercepted" in r
    }
    assert transport_intercept_reasons == set(), (
        f"R33 P2 #1 contract regression: HarnessReason vocabulary now "
        f"includes a transport-interception reason "
        f"({transport_intercept_reasons}); either the harness was "
        "expanded with transport sandboxing or the closed-enum contract "
        "drifted. Update this test + the module docstring + "
        "plan-of-record §Doctrine Decision C in the same commit."
    )

    # Pin (2): pack `_invoke()` observes host runtime unmodified.
    io_module = (
        "import os\n"
        "from typing import Any, ClassVar\n"
        "from cognic_agentos.sdk.tool import Tool\n"
        "\n"
        "class HarnessTargetTool(Tool):\n"
        '    name: ClassVar[str] = "harness_target"\n'
        "    input_schema: ClassVar[dict[str, Any]] = "
        '{"type": "object", "properties": {}, "required": [], '
        '"additionalProperties": False}\n'
        "    output_schema: ClassVar[dict[str, Any]] = "
        '{"type": "object", "properties": '
        '{"path_seen": {"type": "boolean"}}, '
        '"required": ["path_seen"], "additionalProperties": False}\n'
        "\n"
        "    async def _invoke(self, **kwargs: Any) -> dict[str, Any]:\n"
        # Benign host env read; would fail (or return empty) under
        # an env-sandboxed harness. The dispatch-not-crashing IS
        # the load-bearing signal.
        "        path = os.environ.get('PATH', '')\n"
        '        return {"path_seen": bool(path)}\n'
    )
    pack_path = _write_pack(tmp_path / "no_transport_intercept", tool_module=io_module)
    report = run_harness(pack_path)
    assert report.overall_status == "pass", (
        f"R33 P2 #1 — pack with benign host env read failed dispatch; "
        f"the harness may have started intercepting host runtime: "
        f"{report.findings} {report.dispatch_results}"
    )
    assert report.dispatch_results[0].status == "pass"
    assert report.dispatch_results[0].outcome is not None
    assert report.dispatch_results[0].outcome.response_keys == ("path_seen",)
