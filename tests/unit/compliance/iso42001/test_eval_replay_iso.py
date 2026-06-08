# tests/unit/compliance/iso42001/test_eval_replay_iso.py
from __future__ import annotations

from cognic_agentos.compliance.iso42001.controls import ISO42001_CONTROLS, ControlEntry


def _entry(cid: str) -> ControlEntry:
    return next(e for e in ISO42001_CONTROLS if e.control_id == cid)


def test_eval_replay_tags_a76_and_a92() -> None:
    assert "eval.replay" in _entry("ISO42001.A.7.6").intended_hooks
    assert "eval.replay" in _entry("ISO42001.A.9.2").intended_hooks
    # both stay implemented (no status change)
    assert _entry("ISO42001.A.7.6").hook_status == "implemented"
    assert _entry("ISO42001.A.9.2").hook_status == "implemented"
