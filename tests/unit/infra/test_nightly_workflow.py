"""Structural contracts for the nightly gate ladder and morning report."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CI_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "python.yml"
_NIGHTLY_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "nightly.yml"
_DEP_UPGRADE_WORKFLOW = _REPO_ROOT / ".github" / "workflows" / "dep-upgrade.yml"


def _load(path: Path) -> dict[Any, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def _triggers(document: dict[Any, Any]) -> dict[str, Any]:
    # PyYAML follows YAML 1.1 and parses the unquoted GitHub key `on` as True.
    triggers = document.get("on", document.get(True))
    assert isinstance(triggers, dict)
    return triggers


def test_primary_ci_is_reusable_without_changing_direct_triggers() -> None:
    triggers = _triggers(_load(_CI_WORKFLOW))

    assert {"push", "pull_request", "workflow_dispatch", "workflow_call"} <= set(triggers)
    reusable_input = triggers["workflow_call"]["inputs"]["run_credential_free_kind_lanes"]
    assert reusable_input == {
        "description": "Run the credential-free kind smoke and Proof 1b-2 lanes",
        "required": False,
        "type": "boolean",
        "default": False,
    }


def test_kind_lanes_preserve_direct_gates_and_accept_only_the_reusable_input() -> None:
    jobs = _load(_CI_WORKFLOW)["jobs"]
    expected_tokens = {
        "kind-smoke": "vars.COGNIC_RUN_KIND_SMOKE",
        "proof-1b-2": "vars.COGNIC_RUN_PROOF_1B2",
    }

    for job_name, repo_variable in expected_tokens.items():
        gate = jobs[job_name]["if"]
        assert repo_variable in gate
        assert "github.event_name == 'workflow_dispatch'" in gate
        assert "inputs.run_credential_free_kind_lanes == true" in gate

    proof_runs = "\n".join(step["run"] for step in jobs["proof-1b-2"]["steps"] if "run" in step)
    assert "COGNIC_RUN_PROOF_1B2=1 bash infra/proof-1b-2/run-proof-1b-2.sh" in proof_runs


def test_nightly_schedule_reuses_the_complete_gate_ladder() -> None:
    workflow = _load(_NIGHTLY_WORKFLOW)
    triggers = _triggers(workflow)

    assert triggers == {"schedule": [{"cron": "0 21 * * *"}], "workflow_dispatch": None}
    assert set(workflow["jobs"]) == {"gate-ladder", "morning-report"}
    gate = workflow["jobs"]["gate-ladder"]
    assert gate == {
        "name": "full gate ladder + credential-free kind proofs",
        "uses": "./.github/workflows/python.yml",
        "with": {"run_credential_free_kind_lanes": True},
    }
    assert "secrets" not in gate


def test_morning_report_is_singleton_pinned_and_closes_on_green() -> None:
    report = _load(_NIGHTLY_WORKFLOW)["jobs"]["morning-report"]

    assert report["needs"] == "gate-ladder"
    assert "always()" in report["if"]
    assert report["permissions"] == {
        "actions": "read",
        "contents": "read",
        "issues": "write",
    }
    assert report["env"] == {"GATE_RESULT": "${{ needs.gate-ladder.result }}"}
    step = next(step for step in report["steps"] if step.get("uses") == "actions/github-script@v8")
    assert step["with"]["github-token"] == "${{ github.token }}"
    script = step["with"]["script"]
    for token in (
        'const title = "nightly: morning report"',
        'const label = "nightly-red"',
        "listJobsForWorkflowRun",
        "listForRepo",
        "createLabel",
        "issues.create",
        "issues.update",
        "issues.createComment",
        "pinIssue",
        "unpinIssue",
        "isPinned",
        "context.runId",
    ):
        assert token in script
    assert "matches.length > 1" in script
    assert "failures.length === 0" in script


def test_nightly_honesty_boundary_excludes_the_operator_held_live_proof() -> None:
    text = _NIGHTLY_WORKFLOW.read_text(encoding="utf-8")

    assert "Bars A-G" in text
    assert "operator-held provider key" in text
    assert "HUMAN custody decision" in text
    assert "credential-free kind lanes only" in text
    for forbidden in (
        "COGNIC_PROOF_M85C_TIER1_API_KEY",
        "COGNIC_RUN_PROOF_M85C",
        "infra/proof-m85c",
        "run-proof-m85c",
    ):
        assert forbidden not in text


def test_dependency_diff_preview_cannot_sigpipe_under_pipefail() -> None:
    text = _DEP_UPGRADE_WORKFLOW.read_text(encoding="utf-8")

    assert "git --no-pager diff -- uv.lock | head" not in text
    assert 'git --no-pager diff -- uv.lock > "$RUNNER_TEMP/uv-lock.diff"' in text
    assert "sed -n '1,200p' \"$RUNNER_TEMP/uv-lock.diff\"" in text
