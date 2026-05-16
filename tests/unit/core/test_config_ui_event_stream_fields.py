"""Sprint 7B.4 T4 — drift detector for the 5 UI event-stream Settings fields.

Per P1 #6 ownership note in the design spec: the 5 fields are wired in
`core/config.py` Settings, not in `protocol/ui_events.py`. This test pins
the names + defaults + value-range floors so a typo or accidental removal
trips before merge. The 5 fields are the only operator-facing knobs for
the SSE transport; their defaults shape the production deployment
envelope (per-tenant cap, queue bound, idle timeout, heartbeat cadence,
send timeout).
"""

from __future__ import annotations

import pydantic
import pytest

from cognic_agentos.core.config import Settings


class TestUIStreamSettingsFields:
    """The 5 fields + their defaults are the wire-protocol contract
    between operator config and the runtime broker. Drift in any
    default would silently change production deployment behavior."""

    def test_all_5_fields_present_with_defaults(self) -> None:
        s = Settings()
        assert s.ui_event_stream_per_tenant_cap == 50
        assert s.ui_event_stream_queue_maxsize == 1000
        assert s.ui_event_stream_idle_timeout_s == 90
        assert s.ui_event_stream_heartbeat_interval_s == 15
        assert s.ui_event_stream_send_timeout_s == 30

    def test_field_count_pinned_at_5(self) -> None:
        """Sentinel: extending this set is a deliberate plan-of-record edit.
        Pinning the count separately from the per-field defaults lets the
        drift error message point at "field added/removed" vs "default
        value changed" without ambiguity."""
        ui_fields = {n for n in Settings.model_fields if n.startswith("ui_event_stream_")}
        assert ui_fields == {
            "ui_event_stream_per_tenant_cap",
            "ui_event_stream_queue_maxsize",
            "ui_event_stream_idle_timeout_s",
            "ui_event_stream_heartbeat_interval_s",
            "ui_event_stream_send_timeout_s",
        }
        assert len(ui_fields) == 5


class TestUIStreamSettingsValidation:
    """Each field has a `ge=...` floor — operator configs that violate
    the floor refuse at Settings load time rather than producing a
    silently-broken broker (cap=0 would refuse every subscriber;
    queue_maxsize<16 would overflow on the very first event burst;
    timeouts<1s would reap subscribers mid-yield)."""

    def test_per_tenant_cap_rejects_zero(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            Settings(ui_event_stream_per_tenant_cap=0)

    def test_queue_maxsize_rejects_below_16(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            Settings(ui_event_stream_queue_maxsize=15)

    def test_idle_timeout_rejects_below_15s(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            Settings(ui_event_stream_idle_timeout_s=14)

    def test_heartbeat_interval_rejects_zero(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            Settings(ui_event_stream_heartbeat_interval_s=0)

    def test_send_timeout_rejects_zero(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            Settings(ui_event_stream_send_timeout_s=0)
