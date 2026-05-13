"""Sprint-7B.2 T10 — `agentos conformance` CLI extension regressions.

Per the plan-of-record §1255-1273, T10 is a thin CLI wrapper over
:func:`cognic_agentos.packs.conformance.run_owasp_conformance` with the
contract:

  - ``agentos conformance <pack_path>`` runs the matrix and emits a
    human-readable summary to stdout.
  - ``--json`` switches stdout to the runner.py 4-key wire-shape dict
    (``overall_status`` / ``results`` / ``summary`` /
    ``errored_categories``); JSON output round-trips through stdlib
    ``json``.
  - Exit codes: ``0`` = green, ``1`` = red OR yellow (any non-green
    verdict — yellow includes red's signal because the verdict is
    not trustworthy when a checker raised), ``2`` = invocation error
    (missing pack path / missing manifest / unparseable manifest —
    the latter covers UTF-8 decode failure, TOML syntax failure, and
    every ``OSError`` subclass from ``read_bytes`` per R44 P2 #1).
  - Invocation-error refusals carry a closed-enum
    :data:`ConformanceInvocationError` reason. Distinct vocabulary
    from :data:`ConformanceOverallStatus` — those are the conformance
    verdict, these are the wrapper's pre-dispatch outcome.

NOT-CC per plan §1255-1273; the underlying matrix
(``packs/conformance/owasp_agentic.py``) is the critical-controls
module + carries the security-bearing logic. This wrapper is a thin
manifest-parse + dispatch + exit-code translator with no decision
logic of its own.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cognic_agentos.cli import app

# ---------------------------------------------------------------------------
# Test fixtures — synthesise manifests on disk
# ---------------------------------------------------------------------------

#: Minimal manifest that produces a green verdict from
#: ``run_owasp_conformance``. Identity / risk_tier / data_governance /
#: supply_chain are populated to satisfy the OWASP checks that fire on
#: tool packs. No prompts / skills / dependencies fields → those checks
#: are either ``not_applicable`` (per the per-kind applicability matrix)
#: or trivially ``pass``.
_GREEN_TOOL_MANIFEST: str = """\
[pack]
pack_id = "cognic-tool-conformance-green"
kind = "tool"
name = "demo"
version = "1.0.0"

[identity]
agent_id = "did:web:example.com:tools:demo"
display_name = "Demo Tool"
provider_organization = "Example Org"
provider_url = "https://example.com"

[risk_tier]
tier = "low"

[data_governance]
data_classes = ["public"]
purpose = "operational_telemetry"
retention_policy = "none"
egress_allow_list = ["https://example.com"]

[supply_chain]
attestation_paths = ["attestations/cosign.sig"]
"""

#: Manifest that produces at least one red (fail) result. Drops the
#: identity block → ``check_identity_abuse`` flips to fail with the
#: stable ``manifest.identity:`` field-path prefix.
_RED_TOOL_MANIFEST: str = """\
[pack]
pack_id = "cognic-tool-conformance-red"
kind = "tool"
name = "demo"
version = "1.0.0"

[risk_tier]
tier = "low"

[data_governance]
data_classes = ["public"]
purpose = "operational_telemetry"
retention_policy = "none"
egress_allow_list = ["https://example.com"]

[supply_chain]
attestation_paths = ["attestations/cosign.sig"]
"""


def _write_manifest(pack_path: Path, body: str) -> Path:
    pack_path.mkdir(parents=True, exist_ok=True)
    manifest = pack_path / "cognic-pack-manifest.toml"
    manifest.write_text(body)
    return manifest


# ---------------------------------------------------------------------------
# (a) Pure-function seam — run_conformance returns either a
#     ConformanceReport (verdict reached) or a ConformanceInvocationFailure
#     (pre-dispatch error).
# ---------------------------------------------------------------------------


class TestSprint7B2T10RunConformancePureSeam:
    def test_run_conformance_returns_report_on_green_manifest(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.conformance import run_conformance
        from cognic_agentos.packs.conformance import ConformanceReport

        _write_manifest(tmp_path, _GREEN_TOOL_MANIFEST)

        outcome = run_conformance(tmp_path)
        assert isinstance(outcome, ConformanceReport)
        assert outcome.overall_status == "green"

    def test_run_conformance_returns_report_on_red_manifest(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.conformance import run_conformance
        from cognic_agentos.packs.conformance import ConformanceReport

        _write_manifest(tmp_path, _RED_TOOL_MANIFEST)

        outcome = run_conformance(tmp_path)
        assert isinstance(outcome, ConformanceReport)
        assert outcome.overall_status == "red"

    def test_run_conformance_invocation_failure_when_pack_path_missing(
        self, tmp_path: Path
    ) -> None:
        from cognic_agentos.cli.conformance import (
            ConformanceInvocationFailure,
            run_conformance,
        )

        missing = tmp_path / "does-not-exist"
        outcome = run_conformance(missing)
        assert isinstance(outcome, ConformanceInvocationFailure)
        assert outcome.reason == "conformance_pack_path_not_found"

    def test_run_conformance_invocation_failure_when_manifest_missing(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.conformance import (
            ConformanceInvocationFailure,
            run_conformance,
        )

        # Pack path exists, manifest file does NOT exist.
        tmp_path.mkdir(parents=True, exist_ok=True)
        outcome = run_conformance(tmp_path)
        assert isinstance(outcome, ConformanceInvocationFailure)
        assert outcome.reason == "conformance_manifest_not_found"

    def test_run_conformance_invocation_failure_on_unparseable_toml(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.conformance import (
            ConformanceInvocationFailure,
            run_conformance,
        )

        _write_manifest(tmp_path, "= = = bad toml \x00")
        outcome = run_conformance(tmp_path)
        assert isinstance(outcome, ConformanceInvocationFailure)
        assert outcome.reason == "conformance_manifest_unparseable"

    def test_run_conformance_invocation_failure_on_invalid_utf8(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.conformance import (
            ConformanceInvocationFailure,
            run_conformance,
        )

        # Mirror cli/validate.py R19 P2 #2 — invalid UTF-8 routes to
        # the same closed-enum reason as TOML-syntax failures, payload
        # carries the underlying exception class name.
        tmp_path.mkdir(parents=True, exist_ok=True)
        (tmp_path / "cognic-pack-manifest.toml").write_bytes(b"\xff\xfe\xfd")
        outcome = run_conformance(tmp_path)
        assert isinstance(outcome, ConformanceInvocationFailure)
        assert outcome.reason == "conformance_manifest_unparseable"
        assert outcome.payload["error_type"] == "UnicodeDecodeError"

    def test_run_conformance_invocation_failure_on_read_oserror(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R44 P2 #1 — ``manifest_path.read_bytes()`` can raise any
        ``OSError`` subclass (``PermissionError`` on locked-down
        manifests, ``IsADirectoryError`` if the path collides with a
        directory, ``FileNotFoundError`` in a race between
        ``is_file()`` and ``read_bytes`` if the file is deleted
        between calls, etc). The seam contract promises never to
        raise, so every ``OSError`` collapses into the existing
        ``conformance_manifest_unparseable`` invocation failure with
        ``error_type`` distinguishing the subclass for CI parsers."""
        from cognic_agentos.cli.conformance import (
            ConformanceInvocationFailure,
            run_conformance,
        )

        _write_manifest(tmp_path, _GREEN_TOOL_MANIFEST)

        original_read_bytes = Path.read_bytes

        def _raise_permission_error(self: Path) -> bytes:
            if self.name == "cognic-pack-manifest.toml":
                raise PermissionError(f"simulated permission denied: {self}")
            return original_read_bytes(self)

        monkeypatch.setattr(Path, "read_bytes", _raise_permission_error)

        outcome = run_conformance(tmp_path)
        assert isinstance(outcome, ConformanceInvocationFailure)
        assert outcome.reason == "conformance_manifest_unparseable"
        assert outcome.payload["error_type"] == "PermissionError"

    def test_command_exits_2_on_read_permission_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """R44 P2 #1 — Typer command surfaces the ``PermissionError``
        through the existing invocation-error exit-code path (exit 2 +
        ``conformance_manifest_unparseable`` annotation on stderr)."""
        _write_manifest(tmp_path, _GREEN_TOOL_MANIFEST)

        original_read_bytes = Path.read_bytes

        def _raise_permission_error(self: Path) -> bytes:
            if self.name == "cognic-pack-manifest.toml":
                raise PermissionError(f"simulated permission denied: {self}")
            return original_read_bytes(self)

        monkeypatch.setattr(Path, "read_bytes", _raise_permission_error)

        runner = CliRunner()
        result = runner.invoke(app, ["conformance", str(tmp_path)])
        assert result.exit_code == 2, (
            f"expected 2, got {result.exit_code}; stdout={result.stdout!r}; "
            f"stderr={result.stderr!r}"
        )
        assert "conformance_manifest_unparseable" in result.stderr


# ---------------------------------------------------------------------------
# (b) format_report — text vs JSON
# ---------------------------------------------------------------------------


class TestSprint7B2T10FormatReport:
    def test_json_mode_emits_four_key_runner_wire_shape(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.conformance import format_report, run_conformance
        from cognic_agentos.packs.conformance import ConformanceReport

        _write_manifest(tmp_path, _GREEN_TOOL_MANIFEST)
        outcome = run_conformance(tmp_path)
        assert isinstance(outcome, ConformanceReport)

        rendered = format_report(outcome, json_output=True)
        parsed = json.loads(rendered)
        assert set(parsed.keys()) == {
            "overall_status",
            "results",
            "summary",
            "errored_categories",
        }
        # ``errored_categories`` MUST be a list (NOT a tuple) post
        # ``asdict`` — same load-bearing invariant as
        # ``packs/conformance/runner.py`` per the T9 doctrine memory.
        assert isinstance(parsed["errored_categories"], list)

    def test_text_mode_surfaces_overall_status_and_summary(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.conformance import format_report, run_conformance
        from cognic_agentos.packs.conformance import ConformanceReport

        _write_manifest(tmp_path, _GREEN_TOOL_MANIFEST)
        outcome = run_conformance(tmp_path)
        assert isinstance(outcome, ConformanceReport)

        rendered = format_report(outcome, json_output=False)
        assert "green" in rendered
        # The summary line carries the count phrase.
        assert "pass" in rendered

    def test_text_mode_surfaces_per_category_status(self, tmp_path: Path) -> None:
        from cognic_agentos.cli.conformance import format_report, run_conformance
        from cognic_agentos.packs.conformance import ConformanceReport

        _write_manifest(tmp_path, _GREEN_TOOL_MANIFEST)
        outcome = run_conformance(tmp_path)
        assert isinstance(outcome, ConformanceReport)

        rendered = format_report(outcome, json_output=False)
        # Every OWASP category in the report's ``results`` dict
        # appears in the rendered text.
        for category in outcome.results:
            assert category in rendered


# ---------------------------------------------------------------------------
# (c) Typer command — exit codes
# ---------------------------------------------------------------------------


class TestSprint7B2T10TyperCommandExitCodes:
    def test_command_exits_0_on_green(self, tmp_path: Path) -> None:
        _write_manifest(tmp_path, _GREEN_TOOL_MANIFEST)
        runner = CliRunner()
        result = runner.invoke(app, ["conformance", str(tmp_path)])
        assert result.exit_code == 0, (
            f"expected 0, got {result.exit_code}; stdout={result.stdout!r}; "
            f"stderr={result.stderr!r}"
        )
        # Verdict surfaces on stdout (NOT stderr) so non-CI runs see
        # the result cleanly without redirect tricks.
        assert "green" in result.stdout

    def test_command_exits_1_on_red(self, tmp_path: Path) -> None:
        _write_manifest(tmp_path, _RED_TOOL_MANIFEST)
        runner = CliRunner()
        result = runner.invoke(app, ["conformance", str(tmp_path)])
        assert result.exit_code == 1, (
            f"expected 1, got {result.exit_code}; stdout={result.stdout!r}; "
            f"stderr={result.stderr!r}"
        )
        assert "red" in result.stdout

    def test_command_exits_1_on_yellow(self, tmp_path: Path) -> None:
        """A checker exception routes to ``yellow`` per the user-locked
        precedence in ``packs/conformance/owasp_agentic.run_owasp_conformance``
        — and the CLI treats yellow as a non-green outcome (exit 1).
        ``green`` is the ONLY exit-0 verdict; yellow's incompleteness
        signal means the suite is not trustworthy and the CLI surfaces
        that with the same non-zero exit code as red."""
        from cognic_agentos.packs.conformance import owasp_agentic

        _write_manifest(tmp_path, _GREEN_TOOL_MANIFEST)

        def _raising_check(manifest: dict[str, object]) -> object:
            raise RuntimeError("intentional checker failure for T10 test")

        # Replace the first registry entry's body with a raiser so the
        # runner's exception-handler synthesises ``yellow`` overall.
        original_registry = owasp_agentic._CHECK_REGISTRY
        patched = ((original_registry[0][0], _raising_check), *original_registry[1:])

        runner = CliRunner()
        try:
            owasp_agentic._CHECK_REGISTRY = patched  # type: ignore[assignment]
            result = runner.invoke(app, ["conformance", str(tmp_path)])
        finally:
            owasp_agentic._CHECK_REGISTRY = original_registry

        assert result.exit_code == 1, (
            f"expected 1, got {result.exit_code}; stdout={result.stdout!r}; "
            f"stderr={result.stderr!r}"
        )
        assert "yellow" in result.stdout

    def test_command_exits_2_on_missing_pack_path(self, tmp_path: Path) -> None:
        missing = tmp_path / "does-not-exist"
        runner = CliRunner()
        result = runner.invoke(app, ["conformance", str(missing)])
        assert result.exit_code == 2, (
            f"expected 2, got {result.exit_code}; stdout={result.stdout!r}; "
            f"stderr={result.stderr!r}"
        )
        # Invocation-error reason renders to stderr (matches the
        # ``cli/validate.py`` GH-Actions inline-annotation convention).
        assert "conformance_pack_path_not_found" in result.stderr

    def test_command_exits_2_on_missing_manifest(self, tmp_path: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(app, ["conformance", str(tmp_path)])
        assert result.exit_code == 2
        assert "conformance_manifest_not_found" in result.stderr

    def test_command_exits_2_on_unparseable_manifest(self, tmp_path: Path) -> None:
        _write_manifest(tmp_path, "= = = bad toml \x00")
        runner = CliRunner()
        result = runner.invoke(app, ["conformance", str(tmp_path)])
        assert result.exit_code == 2
        assert "conformance_manifest_unparseable" in result.stderr

    def test_command_json_flag_emits_json_on_stdout(self, tmp_path: Path) -> None:
        _write_manifest(tmp_path, _GREEN_TOOL_MANIFEST)
        runner = CliRunner()
        result = runner.invoke(app, ["conformance", str(tmp_path), "--json"])
        assert result.exit_code == 0
        # stdout MUST parse as JSON carrying the runner.py 4-key shape.
        parsed = json.loads(result.stdout)
        assert set(parsed.keys()) == {
            "overall_status",
            "results",
            "summary",
            "errored_categories",
        }
        assert parsed["overall_status"] == "green"


# ---------------------------------------------------------------------------
# (d) Closed-enum reason vocabulary
# ---------------------------------------------------------------------------


class TestSprint7B2T10ClosedEnumReasonVocabulary:
    def test_invocation_error_literal_has_exactly_three_values(self) -> None:
        """The CLI's invocation-error closed-enum is intentionally narrow:
        pack-path-not-found / manifest-not-found / manifest-unparseable.
        Growth points (e.g., a future ``conformance_manifest_not_a_table``
        if the parsed root proves non-dict) MUST update this test in the
        same commit. Mirrors the validator-reason-drift detector
        pattern from Sprint-7A."""
        import typing

        from cognic_agentos.cli.conformance import ConformanceInvocationError

        values = set(typing.get_args(ConformanceInvocationError))
        assert values == {
            "conformance_pack_path_not_found",
            "conformance_manifest_not_found",
            "conformance_manifest_unparseable",
        }
