# tests/unit/cli/test_eval_bulk.py
from __future__ import annotations

import textwrap
from pathlib import Path

from typer.testing import CliRunner

from cognic_agentos.cli import app

_GOOD = """\
schema_version: 1
corpus_id: smoke
cases:
  - id: c1
    case_kind: completion
    messages:
      - role: user
        content: "Define CAR."
    assertions:
      contains: ["capital adequacy"]
"""


def _corpus_dir(tmp_path: Path) -> Path:
    (tmp_path / "a.yaml").write_text(textwrap.dedent(_GOOD), encoding="utf-8")
    return tmp_path


def test_dry_run_validates_and_prints_plan_no_network(tmp_path: Path) -> None:
    runner = CliRunner()
    res = runner.invoke(app, ["eval-bulk", "--corpus", str(_corpus_dir(tmp_path)), "--dry-run"])
    assert res.exit_code == 0
    assert "smoke" in res.stdout
    assert "1" in res.stdout  # case count


def test_dry_run_invalid_corpus_exit_1(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("schema_version: 9\ncases: []\n", encoding="utf-8")
    res = CliRunner().invoke(app, ["eval-bulk", "--corpus", str(tmp_path), "--dry-run"])
    assert res.exit_code == 1
    assert "corpus_schema_version_unsupported" in res.stderr or "corpus" in res.stderr


def test_missing_url_without_dry_run_exit_2(tmp_path: Path) -> None:
    res = CliRunner().invoke(app, ["eval-bulk", "--corpus", str(_corpus_dir(tmp_path))])
    assert res.exit_code == 2  # needs --url (or --dry-run)
