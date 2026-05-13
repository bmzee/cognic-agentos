"""Sprint-7B.2 T11 — `agentos test-harness` OWASP conformance integration.

Per plan-of-record §1274-1290, T11 ships ONLY the OWASP integration
tail-call: after the existing test-harness validate-pipeline +
per-kind dry-run dispatch completes green, run
``run_owasp_conformance(manifest)`` and surface the report in the
harness output. The full ADR-012 §114-122 fixture-AgentOS-instance
harness is DEFERRED post-7B; explicit deferred-boundary regression
below.

T11 doctrine decisions (locked into tests):

  - **Non-gating evidence per BUILD_PLAN §627.** Conformance failures
    surface as data in :attr:`HarnessReport.conformance` AND as
    ``::warning::`` annotations on stderr, but do NOT flip
    :attr:`HarnessReport.overall_status` to ``"fail"``. Mirrors T9's
    submit-flow design where conformance is wire-protocol-public
    evidence written to the chain row but NOT a gate that blocks the
    transition. The Sprint-7B.3 5-gate composer owns the gating
    decision.
  - **Closed-enum narrowness.** T11 does NOT extend
    :data:`HarnessReason`. New refusal reasons would expand the
    public closed-enum vocabulary; instead, conformance failures live
    in their own structured carrier (:class:`ConformanceSummary`).
  - **Deferred-full-harness boundary.** ``cli/test_harness.py`` does
    NOT import ``cognic_agentos.core.audit`` /
    ``cognic_agentos.core.decision_history`` /
    ``cognic_agentos.core.guardrails`` / ``cognic_agentos.sandbox`` /
    ``cognic_agentos.subagent``. The ADR-012 §114-122 fixture-AgentOS
    work spins up these modules; T11's narrow scope explicitly does
    not. Pinned via AST scan of the module source so a future
    refactor that pulls one of these in trips the regression.
  - **Conformance NOT run when earlier steps failed.** Validate
    refusal / dispatch failure / pyproject failure all skip
    conformance with :attr:`HarnessReport.conformance` left as
    ``None``. Conformance is meaningful only against a pack that has
    already cleared the validate + dispatch gates.

NOT-CC per plan §1290 — extension is narrow and the wrapped runner is
already off the critical-controls floor per its own provenance
docstring (Sprint-7A T13 R4 P3 #5 — public command, NOT test-only
path, off-floor because every gate it surfaces is enforced upstream
by ``cli/validate.run_validators``).
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cognic_agentos.cli import app
from cognic_agentos.cli.test_harness import (
    format_report,
    run_harness,
)

# ---------------------------------------------------------------------------
# Fixture path — single-sourced (mirror test_cli_test_harness.py:57-58)
# ---------------------------------------------------------------------------

_REPO_ROOT: Path = Path(__file__).resolve().parents[3]
_HARNESS_TARGET_PACK: Path = _REPO_ROOT / "tests" / "fixtures" / "cli_harness_target_pack"
_TEST_HARNESS_MODULE_PATH: Path = _REPO_ROOT / "src" / "cognic_agentos" / "cli" / "test_harness.py"

# ---------------------------------------------------------------------------
# Fixture pack builder — synthesizes a tool pack on disk
# ---------------------------------------------------------------------------


def _build_pack(
    pack_path: Path,
    *,
    manifest_overrides: dict[str, str] | None = None,
) -> Path:
    """Copy the committed harness-target fixture into ``pack_path``,
    optionally rewriting individual top-level manifest blocks. Used by
    every test that needs a synthetic pack with a controlled OWASP
    profile."""
    pack_path.mkdir(parents=True, exist_ok=True)

    manifest_text = (_HARNESS_TARGET_PACK / "cognic-pack-manifest.toml").read_text()
    if manifest_overrides:
        for block, replacement in manifest_overrides.items():
            # Replace the block by string substitution — keeps the
            # rewrite trivial for test fixtures without dragging in a
            # full TOML round-trip.
            manifest_text = _rewrite_block(manifest_text, block, replacement)
    (pack_path / "cognic-pack-manifest.toml").write_text(manifest_text)

    pyproject_text = (_HARNESS_TARGET_PACK / "pyproject.toml").read_text()
    (pack_path / "pyproject.toml").write_text(pyproject_text)

    module_dir = pack_path / "src" / "cognic_tool_harness_target"
    module_dir.mkdir(parents=True, exist_ok=True)
    init_text = (
        _HARNESS_TARGET_PACK / "src" / "cognic_tool_harness_target" / "__init__.py"
    ).read_text()
    (module_dir / "__init__.py").write_text(init_text)
    tool_module_text = (
        _HARNESS_TARGET_PACK / "src" / "cognic_tool_harness_target" / "tool.py"
    ).read_text()
    (module_dir / "tool.py").write_text(tool_module_text)

    for relative in ("attestations/cosign.sig", "attestations/sbom.cdx.json"):
        target = pack_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"." if relative.endswith(".sig") else b"{}")
    return pack_path


def _rewrite_block(manifest_text: str, block_name: str, replacement: str) -> str:
    """Replace a ``[block_name]`` section in the manifest with
    ``replacement`` text. Replacement MUST include the ``[block_name]``
    header line. Returns the rewritten text."""
    lines = manifest_text.splitlines()
    start = None
    end = len(lines)
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == f"[{block_name}]":
            start = i
        elif start is not None and stripped.startswith("[") and stripped.endswith("]"):
            end = i
            break
    if start is None:
        # Block not present — append.
        return manifest_text.rstrip() + "\n\n" + replacement.strip() + "\n"
    rewritten = (
        "\n".join(lines[:start]) + "\n" + replacement.strip() + "\n" + "\n".join(lines[end:])
    )
    return rewritten


#: OWASP-clean override for the ``[data_governance]`` block — adds the
#: non-empty ``egress_allow_list`` that ``check_secret_exfiltration``
#: requires (see ``packs/conformance/owasp_agentic.py:check_secret_exfiltration``).
#: The fixture's other blocks are already OWASP-clean post-R45 (which
#: aligned ``_VALID_RISK_TIERS`` with ADR-014's canonical 8-value
#: ``RiskTier`` set), so the fixture's ``tier="read_only"`` now passes
#: both the validator-side risk_tier check AND the OWASP
#: ``check_tool_misuse`` probe.
_GREEN_DATA_GOVERNANCE: str = """\
[data_governance]
data_classes = ["public", "internal"]
purpose = "operational_telemetry"
retention_policy = "none"
egress_allow_list = ["https://example.com"]
"""

_GREEN_OVERRIDES: dict[str, str] = {
    "data_governance": _GREEN_DATA_GOVERNANCE,
}


# ---------------------------------------------------------------------------
# (a) HarnessReport.conformance field shape + default
# ---------------------------------------------------------------------------


class TestSprint7B2T11ConformanceFieldOnHarnessReport:
    def test_harness_report_carries_conformance_field(self, tmp_path: Path) -> None:
        """``HarnessReport`` exposes a ``conformance`` field whose value
        is either :class:`ConformanceSummary` (after a green dispatch)
        or ``None`` (skipped because earlier steps failed)."""
        from cognic_agentos.cli.test_harness import ConformanceSummary

        # Use the fixture AS-IS — it validates clean + dispatches clean,
        # so the conformance arm fires. The exact verdict is not
        # load-bearing for this field-existence test (the fixture
        # lacks ``egress_allow_list`` so ``check_secret_exfiltration``
        # reports fail → verdict is red — but the assertion below only
        # cares that the field is populated, not that it is green).
        pack_path = _build_pack(tmp_path / "owasp_pack")
        report = run_harness(pack_path)
        # Field must exist on the dataclass.
        assert hasattr(report, "conformance")
        # Conformance arm fires after green validate + dispatch.
        assert isinstance(report.conformance, ConformanceSummary)

    def test_conformance_summary_carries_green_bool_and_findings_list(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.test_harness import ConformanceSummary

        pack_path = _build_pack(tmp_path / "owasp_pack")
        report = run_harness(pack_path)
        assert isinstance(report.conformance, ConformanceSummary)
        assert isinstance(report.conformance.green, bool)
        assert isinstance(report.conformance.findings, list)

    def test_conformance_omitted_when_validate_fails(self, tmp_path: Path) -> None:
        """Validate refusal short-circuits the harness pipeline at Step 1.
        Conformance is meaningful only after validate + dispatch are
        green, so it stays ``None`` here."""
        pack_path = tmp_path / "broken_pack"
        pack_path.mkdir()
        # No manifest → manifest_not_found refusal.
        report = run_harness(pack_path)
        assert report.overall_status == "fail"
        assert report.conformance is None

    def test_conformance_omitted_when_dispatch_fails(self, tmp_path: Path) -> None:
        """Dispatch failure (e.g., entry-point unresolvable) skips
        conformance — same rationale as the validate-refusal arm."""
        pack_path = _build_pack(tmp_path / "broken_dispatch_pack")
        # Overwrite pyproject.toml's entry-point to point at a module
        # that does not exist in the pack tree.
        pyproject_text = (pack_path / "pyproject.toml").read_text()
        pyproject_text = pyproject_text.replace(
            "cognic_tool_harness_target.tool:HarnessTargetTool",
            "missing_module.does_not_exist:NoSuchTool",
        )
        (pack_path / "pyproject.toml").write_text(pyproject_text)
        report = run_harness(pack_path)
        assert report.overall_status == "fail"
        assert report.conformance is None


# ---------------------------------------------------------------------------
# (b) Non-gating evidence contract (BUILD_PLAN §627 mirror of T9)
# ---------------------------------------------------------------------------


class TestSprint7B2T11ConformanceNonGating:
    def test_conformance_green_on_clean_manifest_overall_pass(self, tmp_path: Path) -> None:
        """Post-R45, a validator-clean fixture pack augmented with a
        non-empty ``egress_allow_list`` produces ``conformance.green=True``
        through the full ``run_harness`` pipeline. Pre-R45 this path
        was unreachable because OWASP's ``_VALID_RISK_TIERS`` was a
        3-value set disjoint from ADR-014's canonical 8-value
        ``RiskTier`` Literal — every validator-clean pack tripped
        ``check_tool_misuse``. R45 aligned the two vocabularies
        (drift-pinned at
        ``tests/unit/packs/conformance/test_owasp_risk_tier_vocab_drift.py``),
        making this end-to-end green path reachable for the first time."""
        pack_path = _build_pack(
            tmp_path / "owasp_green_pack",
            manifest_overrides=_GREEN_OVERRIDES,
        )
        report = run_harness(pack_path)
        assert report.overall_status == "pass"
        assert report.conformance is not None
        assert report.conformance.green is True
        assert report.conformance.overall_status == "green"
        assert report.conformance.findings == []

    def test_yellow_conformance_surfaces_findings_and_warning(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """**R45 P2 #1 — yellow conformance loses its diagnostic warning.**
        When a checker raises, ``run_owasp_conformance``'s wrapper at
        ``owasp_agentic.run_owasp_conformance:892-896`` synthesizes a
        ``status="not_applicable"`` result AND appends the category
        to ``errored_categories``. Pre-R45 the test-harness
        projection filtered on ``status == "fail"`` only, so a yellow
        verdict produced an empty findings list + zero stderr
        warnings — pack authors lost the incompleteness signal.
        R45 P2 #1 extended the projection to iterate
        ``errored_categories`` too. Pinned by monkeypatching one
        OWASP check to raise and asserting:

          1. ``HarnessReport.conformance.overall_status == "yellow"``.
          2. ``conformance.findings`` is non-empty (synthesised
             exception text surfaces).
          3. At least one ``::warning`` annotation lands on stderr."""
        from cognic_agentos.packs.conformance import owasp_agentic

        pack_path = _build_pack(
            tmp_path / "owasp_yellow_pack",
            manifest_overrides=_GREEN_OVERRIDES,
        )

        def _raising_check(manifest: dict[str, object]) -> object:
            raise RuntimeError("intentional checker failure for T11 R45 test")

        # Replace the first registry entry's body with a raiser so the
        # runner's exception-handler synthesises ``yellow`` overall.
        original_registry = owasp_agentic._CHECK_REGISTRY
        patched = ((original_registry[0][0], _raising_check), *original_registry[1:])
        monkeypatch.setattr(owasp_agentic, "_CHECK_REGISTRY", patched)

        report = run_harness(pack_path)
        # 1. yellow verdict reaches the harness summary.
        assert report.conformance is not None
        assert report.conformance.overall_status == "yellow"
        assert report.conformance.green is False
        # 2. findings non-empty (R45 P2 #1 fix — pre-fix this was []).
        assert report.conformance.findings, (
            "expected at least one finding from the errored category; "
            f"got {report.conformance.findings!r}"
        )
        # 3. ::warning annotation surfaces the diagnostic on stderr.
        from cognic_agentos.cli.test_harness import format_report_finding_annotations

        annotations = format_report_finding_annotations(report)
        warnings = [a for a in annotations if a.startswith("::warning")]
        assert warnings, (
            f"expected at least one ::warning annotation for yellow "
            f"conformance; got {annotations!r}"
        )

    def test_conformance_red_does_not_flip_overall_status_to_fail(self, tmp_path: Path) -> None:
        """**Non-gating evidence contract per BUILD_PLAN §627.** A pack
        that passes validate + dispatch but fails one or more OWASP
        checks surfaces ``conformance.green=False`` + non-empty
        ``findings`` AND STAYS ``overall_status == "pass"``. The
        7B.3 5-gate composer owns the gating decision; the test-harness
        produces evidence, not a gate signal."""
        # The committed fixture has no ``egress_allow_list``, so
        # ``check_secret_exfiltration`` reports fail. Use the fixture
        # AS-IS (no green override) to drive the red-path proof.
        pack_path = _build_pack(tmp_path / "owasp_red_pack")
        report = run_harness(pack_path)
        # Validate + dispatch must succeed for the conformance arm to
        # fire — fail-fast on assertion failure here so the test
        # diagnoses correctly if a future schema change accidentally
        # makes the fixture validate-dirty.
        assert all(r.status == "pass" for r in report.dispatch_results), (
            f"dispatch_results not all green: {report.dispatch_results!r}; "
            f"validate_findings={report.validate_findings!r}"
        )
        assert report.conformance is not None
        # Conformance fails — non-gating: overall_status stays "pass".
        assert report.conformance.green is False
        assert report.conformance.findings, "expected at least one finding"
        # CRITICAL: overall_status stays "pass" per the non-gating
        # contract — this is the load-bearing assertion that pins the
        # BUILD_PLAN §627 doctrine in the test-harness path.
        assert report.overall_status == "pass"

    def test_conformance_findings_contain_owasp_category_prefix(self, tmp_path: Path) -> None:
        """Each finding string is prefixed with its OWASP category so
        pack authors can grep their CI logs for the failing category
        without parsing the JSON."""
        pack_path = _build_pack(tmp_path / "owasp_red_pack")
        report = run_harness(pack_path)
        assert report.conformance is not None
        for finding in report.conformance.findings:
            # Format is "category: <finding-text>".
            assert ":" in finding
            category_prefix = finding.split(":", 1)[0]
            assert category_prefix in {
                "tool_misuse",
                "goal_hijacking",
                "identity_abuse",
                "prompt_injected_skills",
                "dependency_poisoning",
                "secret_exfiltration",
                "unsafe_filesystem",
                "unsafe_network",
                "supply_chain_integrity",
                "skills_top_10",
            }


# ---------------------------------------------------------------------------
# (c) JSON + text output surfaces
# ---------------------------------------------------------------------------


class TestSprint7B2T11ConformanceInOutput:
    def test_json_payload_carries_conformance_dict(self, tmp_path: Path) -> None:
        """The conformance arm fires on the fixture-as-is (validates
        clean + dispatches clean) → ``conformance`` key carries the
        3-key wire-shape dict regardless of whether the verdict is
        green / red / yellow."""
        pack_path = _build_pack(tmp_path / "owasp_pack")
        report = run_harness(pack_path)
        rendered = format_report(report, json_output=True)
        parsed = json.loads(rendered)
        assert "conformance" in parsed
        assert parsed["conformance"] is not None
        # Wire-shape: exactly 3 keys per :class:`ConformanceSummary`
        # field order (green / overall_status / findings).
        assert set(parsed["conformance"].keys()) == {
            "green",
            "overall_status",
            "findings",
        }
        # Verdict is one of the 3 closed-enum values.
        assert parsed["conformance"]["overall_status"] in {"green", "red", "yellow"}

    def test_json_payload_conformance_is_null_when_skipped(self, tmp_path: Path) -> None:
        pack_path = tmp_path / "broken_pack"
        pack_path.mkdir()
        report = run_harness(pack_path)
        rendered = format_report(report, json_output=True)
        parsed = json.loads(rendered)
        # Conformance skipped → null in the JSON payload.
        assert parsed.get("conformance") is None

    def test_text_summary_includes_conformance_verdict_line(self, tmp_path: Path) -> None:
        """Conformance verdict line surfaces in the text summary
        regardless of whether the verdict is green / red / yellow.
        Pack authors scanning the summary see ``conformance: <verdict>``
        below the dispatch lines."""
        pack_path = _build_pack(tmp_path / "owasp_pack")
        report = run_harness(pack_path)
        rendered = format_report(report, json_output=False)
        # Verdict line surfaces in human-readable text.
        assert "conformance" in rendered.lower()
        # Verdict word appears (one of the 3 closed-enum values).
        assert any(verdict in rendered.lower() for verdict in ("green", "red", "yellow"))

    def test_text_annotations_emit_warning_on_owasp_failure(self, tmp_path: Path) -> None:
        """Per the T11 non-gating doctrine, OWASP failures emit
        ``::warning::`` annotations (NOT ``::error::``) — warnings
        render to stderr but do NOT affect exit code, mirroring the
        validate-side warning-severity finding pattern at
        ``cli/__init__.py`` for ``identity_oasf_capability_set_missing``."""
        from cognic_agentos.cli.test_harness import format_report_finding_annotations

        pack_path = _build_pack(tmp_path / "owasp_red_pack")
        report = run_harness(pack_path)
        annotations = format_report_finding_annotations(report)
        warning_lines = [line for line in annotations if line.startswith("::warning")]
        assert warning_lines, f"expected at least one ::warning:: annotation; got {annotations!r}"
        # Each warning line references one of the 10 OWASP categories.
        joined = "\n".join(warning_lines)
        assert any(
            category in joined
            for category in [
                "tool_misuse",
                "goal_hijacking",
                "identity_abuse",
                "prompt_injected_skills",
                "dependency_poisoning",
                "secret_exfiltration",
                "unsafe_filesystem",
                "unsafe_network",
                "supply_chain_integrity",
                "skills_top_10",
            ]
        )


# ---------------------------------------------------------------------------
# (d) Typer command surface — exit-code preservation
# ---------------------------------------------------------------------------


class TestSprint7B2T11TyperCommandExitCodes:
    def test_command_exits_0_on_green_dispatch_with_red_conformance(self, tmp_path: Path) -> None:
        """Non-gating contract end-to-end through the Typer command:
        the existing fixture (no ``egress_allow_list``) fails OWASP
        ``secret_exfiltration`` but dispatch is green → exit 0 because
        conformance is evidence, not a gate."""
        pack_path = _build_pack(tmp_path / "owasp_red_pack")
        runner = CliRunner()
        result = runner.invoke(app, ["test-harness", str(pack_path)])
        assert result.exit_code == 0, (
            f"expected 0 (non-gating per BUILD_PLAN §627), got "
            f"{result.exit_code}; stdout={result.stdout!r}; "
            f"stderr={result.stderr!r}"
        )
        # Warning annotation lands on stderr so CI parsers see the
        # non-gating signal without the build failing.
        assert "::warning" in result.stderr

    def test_command_does_not_emit_conformance_warnings_when_arm_skipped(
        self, tmp_path: Path
    ) -> None:
        """When validate fails, the conformance arm is skipped → no
        ``::warning`` conformance annotations land on stderr (the
        validate-side ``::error`` annotations do, but those are tested
        by the existing ``test_cli_test_harness.py`` suite). Pins the
        skipped-arm contract on the Typer command surface."""
        pack_path = tmp_path / "broken_pack"
        pack_path.mkdir()
        # No manifest → manifest_not_found refusal at validate.
        runner = CliRunner()
        result = runner.invoke(app, ["test-harness", str(pack_path)])
        # Validate refusal → exit 1.
        assert result.exit_code == 1
        # No conformance-warning lines (no green→ no findings; arm skipped).
        assert "conformance:" not in result.stderr


# ---------------------------------------------------------------------------
# (e) Deferred-full-harness boundary (ADR-012 §114-122 post-7B)
# ---------------------------------------------------------------------------


class TestSprint7B2T11DeferredFullHarnessBoundary:
    """The ADR-012 §114-122 fixture-AgentOS-instance harness is
    DEFERRED post-7B per plan §1280. T11's narrow scope MUST NOT pull
    in modules that the full-fixture work would require:

      - ``cognic_agentos.core.audit`` (AuditChain instance)
      - ``cognic_agentos.core.decision_history`` (DecisionHistoryStore)
      - ``cognic_agentos.core.guardrails`` (guardrails engine)
      - ``cognic_agentos.sandbox`` (sandbox boundary)
      - ``cognic_agentos.subagent`` (sub-agent privilege boundary)

    AST scan of ``cli/test_harness.py`` source enforces the deferred
    boundary. A refactor that adds one of these imports trips the
    regression and forces an explicit decision to expand the harness
    scope (which would be a separate doctrine-track decision per
    Round 1 reviewer answer #4)."""

    @staticmethod
    def _collect_imports(module_path: Path) -> set[str]:
        """Walk the module's AST and return the set of every imported
        module path (``a.b.c`` form). Covers both ``import X`` and
        ``from X import Y`` statements."""
        tree = ast.parse(module_path.read_text())
        modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    modules.add(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module)
        return modules

    def test_test_harness_does_not_import_core_audit(self) -> None:
        imports = self._collect_imports(_TEST_HARNESS_MODULE_PATH)
        assert "cognic_agentos.core.audit" not in imports, (
            "T11 narrow scope: cli/test_harness.py must not import core.audit; "
            "see plan §1280 deferred-full-harness boundary"
        )

    def test_test_harness_does_not_import_decision_history(self) -> None:
        imports = self._collect_imports(_TEST_HARNESS_MODULE_PATH)
        assert "cognic_agentos.core.decision_history" not in imports, (
            "T11 narrow scope: cli/test_harness.py must not import "
            "core.decision_history; see plan §1280 deferred-full-harness boundary"
        )

    def test_test_harness_does_not_import_sandbox(self) -> None:
        imports = self._collect_imports(_TEST_HARNESS_MODULE_PATH)
        # Defensive — match anything under ``cognic_agentos.sandbox`` or
        # ``cognic_agentos.sandbox.<sub>``.
        forbidden = {
            m
            for m in imports
            if m == "cognic_agentos.sandbox" or m.startswith("cognic_agentos.sandbox.")
        }
        assert forbidden == set(), (
            f"T11 narrow scope: cli/test_harness.py must not import sandbox; "
            f"found {forbidden!r}; see plan §1280 deferred-full-harness boundary"
        )

    def test_test_harness_does_not_import_subagent(self) -> None:
        imports = self._collect_imports(_TEST_HARNESS_MODULE_PATH)
        forbidden = {
            m
            for m in imports
            if m == "cognic_agentos.subagent" or m.startswith("cognic_agentos.subagent.")
        }
        assert forbidden == set(), (
            f"T11 narrow scope: cli/test_harness.py must not import subagent; "
            f"found {forbidden!r}; see plan §1280 deferred-full-harness boundary"
        )

    def test_test_harness_does_not_import_guardrails(self) -> None:
        imports = self._collect_imports(_TEST_HARNESS_MODULE_PATH)
        assert "cognic_agentos.core.guardrails" not in imports, (
            "T11 narrow scope: cli/test_harness.py must not import "
            "core.guardrails; see plan §1280 deferred-full-harness boundary"
        )

    def test_test_harness_does_import_owasp_runner(self) -> None:
        """Positive proof: the T11 integration legitimately imports
        ``packs.conformance.run_owasp_conformance``. Pinned alongside
        the negative imports so a future refactor that drops the
        integration ALSO trips a regression."""
        imports = self._collect_imports(_TEST_HARNESS_MODULE_PATH)
        # Either path (top-level package OR submodule) counts as the
        # OWASP runner import.
        assert "cognic_agentos.packs.conformance" in imports or any(
            m.startswith("cognic_agentos.packs.conformance") for m in imports
        ), f"expected packs.conformance import; got {imports!r}"


# ---------------------------------------------------------------------------
# (f) ConformanceSummary dataclass shape
# ---------------------------------------------------------------------------


class TestSprint7B2T11ConformanceSummaryShape:
    def test_conformance_summary_field_order_matches_wire_contract(self) -> None:
        """Per ADR-006 evidence-pack-export readers, the wire-shape
        field order is ``green`` / ``overall_status`` / ``findings``.
        Drift breaks JSON consumers that read by positional / by-key."""
        import dataclasses

        from cognic_agentos.cli.test_harness import ConformanceSummary

        field_names = tuple(f.name for f in dataclasses.fields(ConformanceSummary))
        assert field_names == ("green", "overall_status", "findings")

    def test_conformance_summary_is_frozen(self) -> None:
        """Carrier is immutable so test-author assertion-after-handoff
        cannot silently mutate the report."""
        import dataclasses

        from cognic_agentos.cli.test_harness import ConformanceSummary

        # ``frozen=True`` causes ``dataclasses.FrozenInstanceError`` on
        # attribute assignment.
        summary = ConformanceSummary(green=True, overall_status="green", findings=[])
        try:
            summary.green = False  # type: ignore[misc]
        except dataclasses.FrozenInstanceError:
            return
        raise AssertionError("ConformanceSummary should be frozen")
