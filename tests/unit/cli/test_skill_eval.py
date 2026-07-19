from __future__ import annotations

import importlib
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cognic_agentos.cli import app
from cognic_agentos.cli.skill_eval import _load_reference_results
from cognic_agentos.evaluation.skill_corpus import load_skill_corpus

_FIXTURE = Path("tests/fixtures/skill_eval/valid_pack")


def test_skill_eval_command_forwards_only_explicit_configuration(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: dict[str, object] = {}

    def fake_run(**kwargs: object) -> tuple[int, str]:
        captured.update(kwargs)
        return (0, '{"passed":true}')

    module = importlib.import_module("cognic_agentos.cli.skill_eval")
    monkeypatch.setattr(module, "run_skill_eval_cli", fake_run)
    result = CliRunner().invoke(
        app,
        [
            "skill-eval",
            "--pack",
            "tests/fixtures/skill_eval/valid_pack",
            "--target",
            "https://agentos.test",
            "--agent-id",
            "bank-analyst",
            "--ablation-agent-id",
            "bank-analyst-no-fixture",
            "--reference-results",
            "refs.json",
        ],
        env={"COGNIC_SKILL_EVAL_TOKEN": "TOKEN-CANARY"},
    )

    assert result.exit_code == 0
    assert result.stdout.strip() == '{"passed":true}'
    assert captured == {
        "pack": Path("tests/fixtures/skill_eval/valid_pack"),
        "target": "https://agentos.test",
        "token": "TOKEN-CANARY",
        "agent_id": "bank-analyst",
        "ablation_agent_id": "bank-analyst-no-fixture",
        "reference_results": Path("refs.json"),
    }


def test_skill_eval_command_requires_bearer_token_without_echoing_it() -> None:
    result = CliRunner().invoke(
        app,
        [
            "skill-eval",
            "--pack",
            "tests/fixtures/skill_eval/valid_pack",
            "--target",
            "https://agentos.test",
        ],
        env={"COGNIC_SKILL_EVAL_TOKEN": ""},
    )

    assert result.exit_code == 2
    assert "COGNIC_SKILL_EVAL_TOKEN" in result.stderr


def test_reference_results_provenance_must_match_the_manifest(tmp_path: Path) -> None:
    corpus = load_skill_corpus(_FIXTURE)
    path = tmp_path / "references.json"
    path.write_text(
        """{
  "schema_version": 1,
  "reference": {
    "server_id": "different-server",
    "tool_name": "run_readonly_query",
    "scope_id": "fixture"
  },
  "results": {"fx-001": 42, "fx-002": 42}
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="provenance"):
        _load_reference_results(path, corpus=corpus)


def test_reference_results_returns_only_the_exact_matrix(tmp_path: Path) -> None:
    corpus = load_skill_corpus(_FIXTURE)
    path = tmp_path / "references.json"
    path.write_text(
        """{
  "schema_version": 1,
  "reference": {
    "server_id": "cognic-tool-oracle-schema",
    "tool_name": "run_readonly_query",
    "scope_id": "fixture"
  },
  "results": {"fx-001": 42, "fx-002": 42}
}
""",
        encoding="utf-8",
    )

    assert _load_reference_results(path, corpus=corpus) == {"fx-001": 42, "fx-002": 42}


def test_reference_results_matrix_must_match_live_cases_exactly(tmp_path: Path) -> None:
    corpus = load_skill_corpus(_FIXTURE)
    path = tmp_path / "references.json"
    path.write_text(
        """{
  "schema_version": 1,
  "reference": {
    "server_id": "cognic-tool-oracle-schema",
    "tool_name": "run_readonly_query",
    "scope_id": "fixture"
  },
  "results": {"fx-001": 42}
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="matrix"):
        _load_reference_results(path, corpus=corpus)
