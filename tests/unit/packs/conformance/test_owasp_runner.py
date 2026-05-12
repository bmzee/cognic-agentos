"""Runner + report-shape tests for the OWASP conformance matrix (Sprint 7B.2 T8).

Pins the wire-protocol-public surfaces declared by ADR-012 §119 + BUILD_PLAN §628 +
plan-of-record §1021-1059:

- ``OWASPCheckCategory`` 10-value closed-enum Literal (watchpoint *a*)
- ``ConformanceOverallStatus`` 3-value Literal (``green`` / ``red`` / ``yellow``)
- ``ConformanceCheckStatus`` 3-value Literal (``pass`` / ``fail`` / ``not_applicable``)
- ``ConformanceCheckResult`` frozen dataclass shape
- ``ConformanceReport`` frozen dataclass shape + 4-field order
- ``ConformanceReport.errored_categories`` tuple (wire-shape extension —
  preserves ``_CHECK_REGISTRY`` order; surfaces runner-level incompleteness via
  the yellow-precedence overall status)
- ``run_owasp_conformance(manifest)`` dispatcher — applicability gate +
  exception-wrapping + yellow-precedence overall-status derivation +
  ``(N errored)`` summary suffix

The per-pack-kind 10x4 applicability matrix lives in
``test_owasp_applicability.py`` (watchpoint *c*); the per-check bodies live in
``test_owasp_checks.py`` (watchpoint *b*).
"""

from __future__ import annotations

import typing
from dataclasses import FrozenInstanceError, is_dataclass

import pytest


class TestSprint7B2T8ClosedEnumVocabulary:
    """Pin the three closed-enum Literals that form T8's wire-protocol surface.

    Doctrine Lock — the 10-value ``OWASPCheckCategory`` Literal IS the wire-protocol
    contract for reviewer evidence: T9 attaches results to the chain payload's
    ``payload.conformance`` extension; 7B.3 reviewers see the same 10-category set;
    a drift here would break evidence-pack export readers per ADR-006.
    """

    def test_owasp_check_category_has_exactly_ten_values(self) -> None:
        from cognic_agentos.packs.conformance.checks import OWASPCheckCategory

        values = set(typing.get_args(OWASPCheckCategory))
        assert values == {
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
        assert len(values) == 10

    def test_conformance_overall_status_has_exactly_three_values(self) -> None:
        """``yellow`` IS the composite-report runner-level-incompleteness sentinel.

        The runner wrapper maps checker-exception → ``yellow`` at the dispatch
        loop (see :class:`TestSprint7B2T8YellowOnCheckerException`); per-check
        status remains in the 3-value :data:`ConformanceCheckStatus` Literal.
        """
        from cognic_agentos.packs.conformance.checks import ConformanceOverallStatus

        values = set(typing.get_args(ConformanceOverallStatus))
        assert values == {"green", "red", "yellow"}
        assert len(values) == 3

    def test_conformance_check_status_has_exactly_three_values(self) -> None:
        from cognic_agentos.packs.conformance.checks import ConformanceCheckStatus

        values = set(typing.get_args(ConformanceCheckStatus))
        assert values == {"pass", "fail", "not_applicable"}
        assert len(values) == 3


class TestSprint7B2T8DataclassShapes:
    """Pin ``ConformanceCheckResult`` + ``ConformanceReport`` frozen-dataclass shapes."""

    def test_conformance_check_result_is_frozen_dataclass(self) -> None:
        from cognic_agentos.packs.conformance.checks import ConformanceCheckResult

        assert is_dataclass(ConformanceCheckResult)
        result = ConformanceCheckResult(
            category="tool_misuse",
            status="pass",
            findings=[],
        )
        with pytest.raises(FrozenInstanceError):
            result.status = "fail"  # type: ignore[misc]

    def test_conformance_check_result_carries_category_status_findings(self) -> None:
        from cognic_agentos.packs.conformance.checks import ConformanceCheckResult

        result = ConformanceCheckResult(
            category="unsafe_network",
            status="fail",
            findings=[
                "manifest.permissions.network: wildcard egress is not allowed",
            ],
        )
        assert result.category == "unsafe_network"
        assert result.status == "fail"
        assert result.findings == [
            "manifest.permissions.network: wildcard egress is not allowed",
        ]

    def test_conformance_report_is_frozen_dataclass(self) -> None:
        from cognic_agentos.packs.conformance.checks import (
            ConformanceCheckResult,
            ConformanceReport,
            OWASPCheckCategory,
        )

        assert is_dataclass(ConformanceReport)
        results: dict[OWASPCheckCategory, ConformanceCheckResult] = {
            "tool_misuse": ConformanceCheckResult(
                category="tool_misuse",
                status="pass",
                findings=[],
            ),
        }
        report = ConformanceReport(
            overall_status="green",
            results=results,
            summary="1 pass / 0 fail / 0 not_applicable",
        )
        with pytest.raises(FrozenInstanceError):
            report.overall_status = "red"  # type: ignore[misc]

    def test_conformance_report_carries_overall_status_results_summary(self) -> None:
        from cognic_agentos.packs.conformance.checks import (
            ConformanceCheckResult,
            ConformanceReport,
            OWASPCheckCategory,
        )

        cats: tuple[OWASPCheckCategory, ...] = ("tool_misuse", "goal_hijacking")
        results = {
            cat: ConformanceCheckResult(category=cat, status="pass", findings=[]) for cat in cats
        }
        report = ConformanceReport(
            overall_status="green",
            results=results,
            summary="2 pass / 0 fail / 0 not_applicable",
        )
        assert report.overall_status == "green"
        assert report.results == results
        assert "2 pass" in report.summary


class TestSprint7B2T8RunnerSkeletonExists:
    """``run_owasp_conformance`` symbol existence."""

    def test_run_owasp_conformance_is_callable(self) -> None:
        from cognic_agentos.packs.conformance.owasp_agentic import run_owasp_conformance

        assert callable(run_owasp_conformance)


class TestSprint7B2T8RunnerComposition:
    """Composite-runner behavior tests covering the green/red verdict path.

    Yellow verdict + checker-exception capture live in
    :class:`TestSprint7B2T8YellowOnCheckerException` +
    :class:`TestSprint7B2T8YellowPrecedenceOverRed` below.
    """

    @staticmethod
    def _well_formed_skill_manifest() -> dict[str, object]:
        """A manifest that passes every applicable check + is N/A on the rest."""
        return {
            "pack": {"kind": "skill", "name": "demo", "version": "1.0.0"},
            "identity": {
                "agent_id": "cognic.demo.v1",
                "display_name": "Demo",
                "provider_organization": "Acme",
                "provider_url": "https://acme.example",
            },
            "risk_tier": {"tier": "medium"},
            "skills": [
                {
                    "name": "summarise",
                    "prompt": "Summarise the input.",
                    "prompt_isolation": True,
                    "tool_allowlist": ["text.summarise"],
                    "secret_access": False,
                    "network_policy": "deny",
                }
            ],
            "data_governance": {
                "data_classes": ["public"],
                "purpose": "demo",
                "retention_policy": "ephemeral",
                "egress_allow_list": ["api.acme.example"],
            },
            "supply_chain": {
                "attestation_paths": ["attestations/cosign.sig"],
            },
        }

    def test_all_applicable_checks_passing_returns_green(self) -> None:
        from cognic_agentos.packs.conformance.owasp_agentic import (
            run_owasp_conformance,
        )

        manifest = self._well_formed_skill_manifest()
        report = run_owasp_conformance(manifest)

        assert report.overall_status == "green"
        # Every result is either pass or not_applicable on a clean fixture.
        for cat, res in report.results.items():
            assert res.status in {"pass", "not_applicable"}, (
                f"{cat}: expected pass or not_applicable on clean fixture, "
                f"got {res.status!r} with findings={res.findings!r}"
            )

    def test_single_failing_check_drops_overall_to_red(self) -> None:
        from cognic_agentos.packs.conformance.owasp_agentic import (
            run_owasp_conformance,
        )

        manifest = self._well_formed_skill_manifest()
        # Inject a failure on check_supply_chain_integrity by emptying the list.
        manifest["supply_chain"] = {"attestation_paths": []}

        report = run_owasp_conformance(manifest)

        assert report.overall_status == "red"
        assert report.results["supply_chain_integrity"].status == "fail"

    def test_report_results_keyed_by_all_ten_categories(self) -> None:
        from cognic_agentos.packs.conformance.owasp_agentic import (
            run_owasp_conformance,
        )

        manifest = self._well_formed_skill_manifest()
        report = run_owasp_conformance(manifest)

        assert set(report.results.keys()) == {
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

    def test_summary_format_includes_three_counts(self) -> None:
        from cognic_agentos.packs.conformance.owasp_agentic import (
            run_owasp_conformance,
        )

        manifest = self._well_formed_skill_manifest()
        report = run_owasp_conformance(manifest)

        # Stable format: "<N> pass / <N> fail / <N> not_applicable"
        assert "pass" in report.summary
        assert "fail" in report.summary
        assert "not_applicable" in report.summary
        # Counts sum to exactly 10 categories.
        import re

        nums = [int(x) for x in re.findall(r"\d+", report.summary)]
        assert sum(nums) == 10, f"summary count must sum to 10, got {report.summary!r} ({nums})"

    def test_summary_counts_match_per_category_statuses(self) -> None:
        from cognic_agentos.packs.conformance.owasp_agentic import (
            run_owasp_conformance,
        )

        manifest = self._well_formed_skill_manifest()
        manifest["supply_chain"] = {"attestation_paths": []}  # one fail
        report = run_owasp_conformance(manifest)

        statuses = [r.status for r in report.results.values()]
        pass_count = statuses.count("pass")
        fail_count = statuses.count("fail")
        na_count = statuses.count("not_applicable")

        assert f"{pass_count} pass" in report.summary, (
            f"summary {report.summary!r} should contain {pass_count} pass"
        )
        assert f"{fail_count} fail" in report.summary, (
            f"summary {report.summary!r} should contain {fail_count} fail"
        )
        assert f"{na_count} not_applicable" in report.summary, (
            f"summary {report.summary!r} should contain {na_count} not_applicable"
        )

    def test_runner_returns_green_or_red_when_no_check_raises(self) -> None:
        """When no check raises, the runner returns ``green`` (all pass/N/A) or
        ``red`` (any fail). ``yellow`` only when checker exceptions are captured
        — see :class:`TestSprint7B2T8YellowOnCheckerException`."""
        from cognic_agentos.packs.conformance.owasp_agentic import (
            run_owasp_conformance,
        )

        manifest_ok = self._well_formed_skill_manifest()
        assert run_owasp_conformance(manifest_ok).overall_status in {"green", "red"}

        manifest_bad: dict[str, object] = {"pack": {}}
        assert run_owasp_conformance(manifest_bad).overall_status in {"green", "red"}


# ---------------------------------------------------------------------------
# ConformanceReport.errored_categories wire-shape extension.
# ---------------------------------------------------------------------------


class TestSprint7B2T8ConformanceReportErroredCategoriesField:
    """Pin the ``ConformanceReport.errored_categories`` wire-shape field.

    Field shape: ``tuple[OWASPCheckCategory, ...] = ()`` (default empty).
    Frozen-dataclass field order:
    ``overall_status, results, summary, errored_categories`` — wire-protocol-
    public per ADR-006 (evidence-pack export consumers read by name + position)."""

    def test_errored_categories_defaults_to_empty_tuple(self) -> None:
        from cognic_agentos.packs.conformance.checks import ConformanceReport

        report = ConformanceReport(
            overall_status="green",
            results={},
            summary="0 pass / 0 fail / 0 not_applicable",
        )
        assert report.errored_categories == ()

    def test_errored_categories_field_is_tuple_typed(self) -> None:
        from cognic_agentos.packs.conformance.checks import ConformanceReport

        report = ConformanceReport(
            overall_status="yellow",
            results={},
            summary="x",
            errored_categories=("tool_misuse",),
        )
        assert report.errored_categories == ("tool_misuse",)
        assert isinstance(report.errored_categories, tuple)

    def test_conformance_report_carries_four_fields_in_locked_order(self) -> None:
        """Frozen-dataclass field order is wire-protocol-public for
        evidence-pack consumers per ADR-006 — drift breaks examiners reading
        positional / keyword-by-name."""
        from dataclasses import fields

        from cognic_agentos.packs.conformance.checks import ConformanceReport

        names = tuple(f.name for f in fields(ConformanceReport))
        assert names == (
            "overall_status",
            "results",
            "summary",
            "errored_categories",
        ), f"locked field order drifted: {names!r}"


# ---------------------------------------------------------------------------
# Runner skips non-applicable check bodies via the matrix.
# ---------------------------------------------------------------------------


class TestSprint7B2T8RunnerSkipsNonApplicable:
    """Per user lock: 'runner does not call N/A check bodies'.

    Verified by replacing a check in the registry with a spy that records
    invocation; assert the spy is NOT called when the pack kind falls outside
    that check's applicability set."""

    def test_runner_does_not_invoke_skills_top_10_body_on_tool_pack(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cognic_agentos.packs.conformance import owasp_agentic
        from cognic_agentos.packs.conformance.checks import ConformanceCheckResult

        call_count = {"n": 0}

        def spy_skills_top_10(_manifest: dict[str, object]) -> ConformanceCheckResult:
            call_count["n"] += 1
            return ConformanceCheckResult(
                category="skills_top_10",
                status="pass",
                findings=[],
            )

        # Replace the registry entry — the runner consults _APPLICABILITY before
        # invoking the check, so on a tool pack the spy MUST NOT be called.
        fake_registry = tuple(
            (cat, spy_skills_top_10 if cat == "skills_top_10" else fn)
            for cat, fn in owasp_agentic._CHECK_REGISTRY
        )
        monkeypatch.setattr(owasp_agentic, "_CHECK_REGISTRY", fake_registry)

        manifest: dict[str, object] = {
            "pack": {"kind": "tool", "name": "x", "version": "1.0.0"},
            "risk_tier": {"tier": "medium"},
        }
        report = owasp_agentic.run_owasp_conformance(manifest)

        assert call_count["n"] == 0, (
            "spy MUST NOT be called for non-applicable kind; _APPLICABILITY short-circuit broken"
        )
        # And the runner still synthesises the result with the matrix-short-
        # circuit field-path prefix.
        assert report.results["skills_top_10"].status == "not_applicable"
        assert any(
            f.startswith("manifest.pack.kind:") for f in report.results["skills_top_10"].findings
        )

    def test_runner_invokes_skills_top_10_body_on_skill_pack(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cognic_agentos.packs.conformance import owasp_agentic
        from cognic_agentos.packs.conformance.checks import ConformanceCheckResult

        call_count = {"n": 0}

        def spy_skills_top_10(_manifest: dict[str, object]) -> ConformanceCheckResult:
            call_count["n"] += 1
            return ConformanceCheckResult(
                category="skills_top_10",
                status="not_applicable",
                findings=["spy: no skills declared"],
            )

        fake_registry = tuple(
            (cat, spy_skills_top_10 if cat == "skills_top_10" else fn)
            for cat, fn in owasp_agentic._CHECK_REGISTRY
        )
        monkeypatch.setattr(owasp_agentic, "_CHECK_REGISTRY", fake_registry)

        manifest: dict[str, object] = {
            "pack": {"kind": "skill", "name": "x", "version": "1.0.0"},
            "risk_tier": {"tier": "low"},
        }
        owasp_agentic.run_owasp_conformance(manifest)

        assert call_count["n"] == 1, (
            "spy MUST be called for applicable kind; matrix is over-filtering"
        )


# ---------------------------------------------------------------------------
# Checker exception → yellow + errored_categories + synthetic finding.
# ---------------------------------------------------------------------------


class TestSprint7B2T8YellowOnCheckerException:
    """Per user lock: a check raising any exception triggers:

    1. ``result.status = "not_applicable"`` (per-check enum unchanged)
    2. ``result.findings = ["manifest: <category> checker raised <ExcType>: <msg>"]``
    3. category appended to ``ConformanceReport.errored_categories``
    4. ``ConformanceReport.overall_status = "yellow"``

    The 3-value per-check enum is preserved; yellow lives on the composite report.
    """

    @staticmethod
    def _registry_with_raising_check(
        owasp_agentic: object, target_category: str, exc: Exception
    ) -> tuple[tuple[str, object], ...]:
        def raising_check(_manifest: dict[str, object]) -> object:
            raise exc

        return tuple(
            (cat, raising_check if cat == target_category else fn)
            for cat, fn in owasp_agentic._CHECK_REGISTRY  # type: ignore[attr-defined]
        )

    def test_checker_raising_produces_yellow_overall_status(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cognic_agentos.packs.conformance import owasp_agentic

        monkeypatch.setattr(
            owasp_agentic,
            "_CHECK_REGISTRY",
            self._registry_with_raising_check(
                owasp_agentic,
                "unsafe_network",
                ValueError("boom"),
            ),
        )

        manifest: dict[str, object] = {
            "pack": {"kind": "tool", "name": "x", "version": "1.0.0"},
            "risk_tier": {"tier": "medium"},
        }
        report = owasp_agentic.run_owasp_conformance(manifest)

        assert report.overall_status == "yellow"

    def test_checker_raising_synthesises_not_applicable_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cognic_agentos.packs.conformance import owasp_agentic

        monkeypatch.setattr(
            owasp_agentic,
            "_CHECK_REGISTRY",
            self._registry_with_raising_check(
                owasp_agentic,
                "unsafe_network",
                ValueError("kaboom"),
            ),
        )

        manifest: dict[str, object] = {
            "pack": {"kind": "tool", "name": "x", "version": "1.0.0"},
            "risk_tier": {"tier": "medium"},
        }
        report = owasp_agentic.run_owasp_conformance(manifest)

        result = report.results["unsafe_network"]
        # Per-check enum preserved — never "errored", never "yellow".
        assert result.status == "not_applicable"
        # Synthetic finding follows the user-locked exact format.
        assert len(result.findings) == 1
        finding = result.findings[0]
        assert finding.startswith("manifest: unsafe_network checker raised ")
        assert "ValueError" in finding
        assert "kaboom" in finding

    def test_checker_raising_appends_to_errored_categories(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cognic_agentos.packs.conformance import owasp_agentic

        monkeypatch.setattr(
            owasp_agentic,
            "_CHECK_REGISTRY",
            self._registry_with_raising_check(
                owasp_agentic,
                "unsafe_network",
                RuntimeError("x"),
            ),
        )

        manifest: dict[str, object] = {
            "pack": {"kind": "tool", "name": "x", "version": "1.0.0"},
            "risk_tier": {"tier": "medium"},
        }
        report = owasp_agentic.run_owasp_conformance(manifest)

        assert report.errored_categories == ("unsafe_network",)

    def test_multiple_errors_preserve_check_registry_order(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Per user lock: 'preserve _CHECK_REGISTRY / OWASPCheckCategory order
        for report results and errored_categories.'"""
        from cognic_agentos.packs.conformance import owasp_agentic
        from cognic_agentos.packs.conformance.checks import ConformanceCheckResult

        def raising_check(_manifest: dict[str, object]) -> ConformanceCheckResult:
            raise RuntimeError("nope")

        # Replace TWO entries; the order in errored_categories must match the
        # CHECK_REGISTRY order, not the order I'm patching them in.
        # secret_exfiltration is registry index 5; tool_misuse is index 0.
        # Even if I patch secret_exfiltration first below, errored_categories
        # must list tool_misuse FIRST per registry order.
        replacements = {"secret_exfiltration", "tool_misuse"}
        fake_registry = tuple(
            (cat, raising_check if cat in replacements else fn)
            for cat, fn in owasp_agentic._CHECK_REGISTRY
        )
        monkeypatch.setattr(owasp_agentic, "_CHECK_REGISTRY", fake_registry)

        manifest: dict[str, object] = {
            "pack": {"kind": "tool", "name": "x", "version": "1.0.0"},
            "risk_tier": {"tier": "medium"},
        }
        report = owasp_agentic.run_owasp_conformance(manifest)

        # tool_misuse (registry index 0) before secret_exfiltration (index 5).
        assert report.errored_categories == ("tool_misuse", "secret_exfiltration")


# ---------------------------------------------------------------------------
# Yellow precedence over red (incompleteness > red verdict).
# ---------------------------------------------------------------------------


class TestSprint7B2T8YellowPrecedenceOverRed:
    """Per user lock: 'yellow takes precedence over red because it means the
    suite was incomplete and the red/green verdict is not trustworthy.'"""

    def test_mixed_error_and_fail_returns_yellow_not_red(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cognic_agentos.packs.conformance import owasp_agentic
        from cognic_agentos.packs.conformance.checks import ConformanceCheckResult

        def raising_check(_manifest: dict[str, object]) -> ConformanceCheckResult:
            raise RuntimeError("checker crashed")

        # Replace check_unsafe_network with a raising one. Compose a manifest
        # that ALSO fails check_supply_chain_integrity (missing block) — a
        # genuine red signal. Yellow must still win.
        fake_registry = tuple(
            (cat, raising_check if cat == "unsafe_network" else fn)
            for cat, fn in owasp_agentic._CHECK_REGISTRY
        )
        monkeypatch.setattr(owasp_agentic, "_CHECK_REGISTRY", fake_registry)

        manifest: dict[str, object] = {
            "pack": {"kind": "tool", "name": "x", "version": "1.0.0"},
            "risk_tier": {"tier": "medium"},
            # supply_chain block deliberately missing → check_supply_chain
            # returns fail → would be "red" if no error.
        }
        report = owasp_agentic.run_owasp_conformance(manifest)

        # Genuine red signal IS present:
        assert report.results["supply_chain_integrity"].status == "fail"
        # But yellow takes precedence:
        assert report.overall_status == "yellow"
        assert "unsafe_network" in report.errored_categories

    def test_pure_error_with_no_other_fails_still_yellow(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cognic_agentos.packs.conformance import owasp_agentic
        from cognic_agentos.packs.conformance.checks import ConformanceCheckResult

        def raising_check(_manifest: dict[str, object]) -> ConformanceCheckResult:
            raise KeyError("oops")

        fake_registry = tuple(
            (cat, raising_check if cat == "tool_misuse" else fn)
            for cat, fn in owasp_agentic._CHECK_REGISTRY
        )
        monkeypatch.setattr(owasp_agentic, "_CHECK_REGISTRY", fake_registry)

        manifest: dict[str, object] = {
            "pack": {"kind": "tool", "name": "x", "version": "1.0.0"},
            "risk_tier": {"tier": "medium"},
            "supply_chain": {"attestation_paths": ["x.sig"]},
        }
        report = owasp_agentic.run_owasp_conformance(manifest)

        # No genuine fail — pure error → still yellow (not green).
        assert report.overall_status == "yellow"


# ---------------------------------------------------------------------------
# Summary string also surfaces errored count when non-zero.
# ---------------------------------------------------------------------------


class TestSprint7B2T8SummaryErroredAnnotation:
    """When ``errored_categories`` is non-empty, the summary appends an
    ``(N errored)`` suffix so human readers see the incompleteness signal."""

    def test_summary_appends_errored_count_when_non_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cognic_agentos.packs.conformance import owasp_agentic
        from cognic_agentos.packs.conformance.checks import ConformanceCheckResult

        def raising_check(_manifest: dict[str, object]) -> ConformanceCheckResult:
            raise ValueError("boom")

        fake_registry = tuple(
            (cat, raising_check if cat == "unsafe_network" else fn)
            for cat, fn in owasp_agentic._CHECK_REGISTRY
        )
        monkeypatch.setattr(owasp_agentic, "_CHECK_REGISTRY", fake_registry)

        manifest: dict[str, object] = {
            "pack": {"kind": "tool", "name": "x", "version": "1.0.0"},
            "risk_tier": {"tier": "medium"},
            "supply_chain": {"attestation_paths": ["x.sig"]},
        }
        report = owasp_agentic.run_owasp_conformance(manifest)

        assert "1 errored" in report.summary

    def test_summary_omits_errored_clause_when_empty(self) -> None:
        from cognic_agentos.packs.conformance.owasp_agentic import (
            run_owasp_conformance,
        )

        manifest: dict[str, object] = {
            "pack": {"kind": "tool", "name": "x", "version": "1.0.0"},
            "risk_tier": {"tier": "medium"},
            "supply_chain": {"attestation_paths": ["x.sig"]},
        }
        report = run_owasp_conformance(manifest)

        assert "errored" not in report.summary
