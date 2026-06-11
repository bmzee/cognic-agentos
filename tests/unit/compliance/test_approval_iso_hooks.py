from __future__ import annotations

from cognic_agentos.compliance.iso42001.controls import ISO42001_CONTROLS


def test_approval_wildcard_hooked_on_a625_a74_a102() -> None:
    # The 5 value-free approval.* chain events (requested / granted_first /
    # granted_second / denied / expired) are stamped A.6.2.5 + A.7.4 + A.10.2 per
    # ADR-014; the family is registered via the approval.* wildcard (mirrors the
    # model.lifecycle.* / sandbox.lifecycle.* precedent).
    by_id = {c.control_id: c for c in ISO42001_CONTROLS}
    for ctrl in ("ISO42001.A.6.2.5", "ISO42001.A.7.4", "ISO42001.A.10.2"):
        assert "approval.*" in by_id[ctrl].intended_hooks


def test_all_three_controls_stay_implemented() -> None:
    by_id = {c.control_id: c for c in ISO42001_CONTROLS}
    for ctrl in ("ISO42001.A.6.2.5", "ISO42001.A.7.4", "ISO42001.A.10.2"):
        assert by_id[ctrl].hook_status == "implemented"
