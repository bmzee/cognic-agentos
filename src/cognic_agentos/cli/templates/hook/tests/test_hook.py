"""{{ class_name }} smoke tests."""

from __future__ import annotations

import pytest

from {{ module_name }}.{{ kind }} import {{ class_name }}


def test_hook_class_creation_passes_sdk_init_subclass() -> None:
    """Importing the {{ class_name }} module + class-creating the
    subclass passes without tripping the SDK's
    ``Hook.__init_subclass__`` runtime guards (no mixin-smuggled
    ``invoke`` override on the subclass MRO)."""
    assert {{ class_name }}.hook_id  # AUTHOR-FILL: assert exact hook_id once filled in
    assert {{ class_name }}.phase in ("dlp_pre", "dlp_post")


@pytest.mark.skip(reason="AUTHOR-FILL: replace with real test once _invoke() is implemented")
async def test_hook_invoke_pass_decision() -> None:
    """Smoke check that {{ class_name }} returns the expected decision
    for a known-safe payload. Replace with real coverage of every
    decision branch (pass / redact / mask / refuse) once the hook
    behavior lands."""
    from cognic_agentos.sdk.hook import HookContext

    hook = {{ class_name }}()
    context = HookContext(
        hook_id={{ class_name }}.hook_id,
        phase={{ class_name }}.phase,
        pack_id="cognic-tool-example-caller",
        tenant_id="tenant-1",
        request_id="req-1",
        trace_id=None,
        parent_trace_id=None,
        manifest_data_classes=("public",),
        manifest_purpose="operational_telemetry",
    )
    result = await hook.invoke(context, b"payload")
    assert result.decision in ("pass", "redact", "mask", "refuse")
