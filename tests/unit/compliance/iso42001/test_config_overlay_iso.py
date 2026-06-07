"""ADR-023 Task 9 — A.6.2.5 tagged with the config.tenant_overlay hooks.

The Task-3 storage emits ``config.tenant_overlay.set`` / ``.cleared`` chain
rows tagged ISO ``A.6.2.5`` (operational responsibilities — an operator
changing a per-tenant config ceiling/floor IS an operational-responsibility
event). This pins that the control registry lists both as intended hooks and
that A.6.2.5 stays ``implemented``.

The resolver's ``config.tenant_overlay.invalid_at_read`` audit event is tagged
ISO ``A.9.2`` and flows through ``audit.append`` — already an A.9.2 intended
hook (a surface-level hook), so A.9.2 needs no per-event addition here.
"""

from cognic_agentos.compliance.iso42001.controls import ISO42001_CONTROLS, ControlEntry


def _entry(control_id: str) -> ControlEntry:
    return next(e for e in ISO42001_CONTROLS if e.control_id == control_id)


def test_a6_2_5_lists_config_overlay_set_and_cleared_hooks() -> None:
    entry = _entry("ISO42001.A.6.2.5")
    assert "config.tenant_overlay.set" in entry.intended_hooks
    assert "config.tenant_overlay.cleared" in entry.intended_hooks


def test_a6_2_5_hook_status_is_implemented() -> None:
    assert _entry("ISO42001.A.6.2.5").hook_status == "implemented"
