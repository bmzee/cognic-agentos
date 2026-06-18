"""Rendered-Helm-YAML snapshot drift gate for the AgentOS chart (Sprint 14B-Z1a).

Mirrors the well-known-schema snapshot convention: `helm template` output with a
pinned release name / namespace / values file is byte-compared to a committed
snapshot. Drift fails the gate with the exact regeneration command.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CHART_DIR = _REPO_ROOT / "infra" / "charts" / "agentos"
_SNAPSHOT_VALUES = _CHART_DIR / "ci" / "snapshot-values.yaml"
_SNAPSHOT = Path(__file__).resolve().parent / "helm" / "agentos_rendered.yaml"


def _render() -> str:
    raw = subprocess.run(
        [
            "helm",
            "template",
            "rel",
            str(_CHART_DIR),
            "--namespace",
            "cognic",
            "-f",
            str(_SNAPSHOT_VALUES),
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    # `helm template` ends its combined output with a trailing blank line; normalize
    # to exactly one final newline so the committed snapshot is git-clean.
    return raw.rstrip("\n") + "\n"


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not on PATH")
def test_rendered_chart_matches_snapshot() -> None:
    rendered = _render()
    if not _SNAPSHOT.exists():
        _SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        _SNAPSHOT.write_text(rendered)
        pytest.fail(f"snapshot created at {_SNAPSHOT} — review and commit it, then re-run")
    assert rendered == _SNAPSHOT.read_text(), (
        f"rendered chart drifted from {_SNAPSHOT}. If the drift is intentional, "
        f"regenerate via `rm {_SNAPSHOT} && uv run pytest "
        f"tests/unit/infra/test_helm_chart.py::test_rendered_chart_matches_snapshot -x` "
        f"then commit the new snapshot."
    )


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not on PATH")
def test_chart_lints_clean() -> None:
    result = subprocess.run(
        ["helm", "lint", str(_CHART_DIR), "-f", str(_SNAPSHOT_VALUES)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"helm lint failed:\n{result.stdout}\n{result.stderr}"
