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


def test_dry_run_validates_corpus_and_baseline_uuid_no_network(tmp_path: Path) -> None:
    res = CliRunner().invoke(
        app,
        [
            "eval-replay",
            "--corpus",
            str(_corpus_dir(tmp_path)),
            "--baseline",
            "11111111-1111-1111-1111-111111111111",
            "--dry-run",
        ],
    )
    assert res.exit_code == 0
    assert "smoke" in res.stdout


def test_dry_run_bad_baseline_uuid_exit_1(tmp_path: Path) -> None:
    res = CliRunner().invoke(
        app,
        [
            "eval-replay",
            "--corpus",
            str(_corpus_dir(tmp_path)),
            "--baseline",
            "not-a-uuid",
            "--dry-run",
        ],
    )
    assert res.exit_code == 1
    assert "baseline" in res.stderr.lower()


def test_dry_run_invalid_corpus_exit_1(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("schema_version: 9\ncases: []\n", encoding="utf-8")
    res = CliRunner().invoke(
        app,
        [
            "eval-replay",
            "--corpus",
            str(tmp_path),
            "--baseline",
            "11111111-1111-1111-1111-111111111111",
            "--dry-run",
        ],
    )
    assert res.exit_code == 1
    assert "corpus" in res.stderr.lower()


def test_missing_url_without_dry_run_exit_2(tmp_path: Path) -> None:
    res = CliRunner().invoke(
        app,
        [
            "eval-replay",
            "--corpus",
            str(_corpus_dir(tmp_path)),
            "--baseline",
            "11111111-1111-1111-1111-111111111111",
        ],
    )
    assert res.exit_code == 2


def test_post_path_sends_request_and_renders(tmp_path: Path) -> None:
    # Pin the non-dry-run POST path (mirrors test_eval_bulk.py::test_post_path_*):
    # endpoint, Bearer header, baseline_run_id, persist_raw_output=False, corpus body,
    # and that the success line renders the candidate_run_id + regression count.
    from unittest.mock import MagicMock, patch

    fake_resp = MagicMock()
    fake_resp.raise_for_status.return_value = None
    fake_resp.json.return_value = {
        "baseline_run_id": "11111111-1111-1111-1111-111111111111",
        "candidate_run_id": "22222222-2222-2222-2222-222222222222",
        "corpus_id": "smoke",
        "regressions": 2,
        "has_regressions": True,
    }
    with patch("httpx.post", return_value=fake_resp) as mock_post:
        res = CliRunner().invoke(
            app,
            [
                "eval-replay",
                "--corpus",
                str(_corpus_dir(tmp_path)),
                "--baseline",
                "11111111-1111-1111-1111-111111111111",
                "--url",
                "http://portal.test/",
                "--token",
                "tok-123",
            ],
        )
    assert res.exit_code == 0
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    # URL: trailing slash stripped + replay endpoint appended.
    assert args[0] == "http://portal.test/api/v1/eval/replay"
    assert kwargs["headers"]["Authorization"] == "Bearer tok-123"
    assert kwargs["json"]["baseline_run_id"] == "11111111-1111-1111-1111-111111111111"
    assert kwargs["json"]["persist_raw_output"] is False
    assert "corpus" in kwargs["json"]
    # success line carries the candidate run id + regression count.
    assert "22222222-2222-2222-2222-222222222222" in res.stdout
    assert "regressions=2" in res.stdout
