from __future__ import annotations

from cognic_agentos.compliance.iso42001.controls import (
    ISO42001_CONTROLS,
    ControlEntry,
)


def _entry(control_id: str) -> ControlEntry:
    return next(e for e in ISO42001_CONTROLS if e.control_id == control_id)


def test_eval_bulk_run_tags_a76_and_a92() -> None:
    a76 = _entry("ISO42001.A.7.6")
    a92 = _entry("ISO42001.A.9.2")
    assert "eval.bulk_run" in a76.intended_hooks
    assert "eval.bulk_run" in a92.intended_hooks


def test_a76_flipped_to_implemented() -> None:
    a76 = _entry("ISO42001.A.7.6")
    assert a76.hook_status == "implemented"
    assert a76.deferred_reason == ""
