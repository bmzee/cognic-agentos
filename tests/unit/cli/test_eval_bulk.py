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


def test_post_path_sends_request_and_renders(tmp_path: Path) -> None:
    from unittest.mock import MagicMock, patch

    fake_resp = MagicMock()
    fake_resp.raise_for_status.return_value = None
    fake_resp.json.return_value = {
        "run_id": "run-1",
        "corpus_id": "smoke",
        "total": 1,
        "passed": 1,
        "failed": 0,
        "errored": 0,
    }
    with patch("httpx.post", return_value=fake_resp) as mock_post:
        res = CliRunner().invoke(
            app,
            [
                "eval-bulk",
                "--corpus",
                str(_corpus_dir(tmp_path)),
                "--url",
                "http://portal.test/",
                "--token",
                "tok-123",
            ],
        )
    assert res.exit_code == 0
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    # URL: trailing slash stripped + endpoint appended
    assert args[0] == "http://portal.test/api/v1/eval/bulk-run"
    assert kwargs["headers"]["Authorization"] == "Bearer tok-123"
    assert kwargs["json"]["target"] == "gateway"
    assert kwargs["json"]["persist_raw_output"] is False
    assert "corpus" in kwargs["json"]
    # render() prints the response corpus_id
    assert "smoke" in res.stdout
