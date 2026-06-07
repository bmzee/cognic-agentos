import uuid
from collections.abc import Mapping

import pytest
from pydantic import ValidationError

from cognic_agentos.core.audit import AuditEvent
from cognic_agentos.core.config import Settings
from cognic_agentos.core.config_overlay.resolver import (
    TenantConfigKeyError,
    TenantConfigOverlayInvalid,
    TenantConfigResolver,
)


# Typed fakes — structurally satisfy the resolver's `_OverlayStore` / `_AuditSink`
# Protocols (mypy `no-untyped-call` is enabled repo-wide, so they must be typed).
class _FakeStore:
    def __init__(self, data: Mapping[str, Mapping[str, object]]) -> None:
        self._data = data
        self.calls = 0

    async def get_many(self, tenant_id: str, field_keys: tuple[str, ...]) -> dict[str, object]:
        self.calls += 1
        return {k: v for k, v in self._data.get(tenant_id, {}).items() if k in field_keys}


class _RecordingAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    async def append(self, event: AuditEvent) -> tuple[uuid.UUID, bytes]:
        self.events.append(event)
        return (uuid.UUID(int=0), b"")  # resolver ignores the return


class _RaisingAudit:
    """Audit sink whose append() always fails (backend down)."""

    def __init__(self) -> None:
        self.attempts = 0

    async def append(self, event: AuditEvent) -> tuple[uuid.UUID, bytes]:
        self.attempts += 1
        raise RuntimeError("audit backend down")


def _settings() -> Settings:
    return Settings(runtime_profile="dev")


def test_throttle_setting_default_and_positive():
    assert _settings().config_overlay_invalid_at_read_throttle_s == 300
    with pytest.raises(ValidationError):
        Settings(runtime_profile="dev", config_overlay_invalid_at_read_throttle_s=0)


async def test_absent_returns_base():
    r = TenantConfigResolver(
        store=_FakeStore({}), base=_settings(), audit=_RecordingAudit(), throttle_s=300
    )
    got = await r.effective_many(("sandbox_per_tenant_max_cpu",), "t1")
    assert got["sandbox_per_tenant_max_cpu"] == _settings().sandbox_per_tenant_max_cpu


async def test_valid_tightened_returned():
    s = _settings()
    store = _FakeStore({"t1": {"sandbox_per_tenant_max_cpu": s.sandbox_per_tenant_max_cpu - 1.0}})
    r = TenantConfigResolver(store=store, base=s, audit=_RecordingAudit(), throttle_s=300)
    assert (
        await r.effective("sandbox_per_tenant_max_cpu", "t1") == s.sandbox_per_tenant_max_cpu - 1.0
    )


async def test_effective_many_single_store_read():
    store = _FakeStore({})
    r = TenantConfigResolver(store=store, base=_settings(), audit=_RecordingAudit(), throttle_s=300)
    await r.effective_many(
        (
            "sandbox_per_tenant_max_cpu",
            "sandbox_per_tenant_max_memory",
            "sandbox_per_tenant_max_walltime",
        ),
        "t1",
    )
    assert store.calls == 1


async def test_invalid_loosening_refuses_and_audits_not_decision_history():
    s = _settings()
    store = _FakeStore({"t1": {"sandbox_per_tenant_max_cpu": s.sandbox_per_tenant_max_cpu + 99.0}})
    audit = _RecordingAudit()
    r = TenantConfigResolver(store=store, base=s, audit=audit, throttle_s=300)
    with pytest.raises(TenantConfigOverlayInvalid):
        await r.effective("sandbox_per_tenant_max_cpu", "t1")
    assert len(audit.events) == 1
    ev = audit.events[0]
    assert ev.event_type == "config.tenant_overlay.invalid_at_read"
    assert ev.request_id  # minted, non-empty (AuditEvent requires it)
    assert ev.tenant_id == "t1"
    assert list(ev.iso_controls) == ["ISO42001.A.9.2"]
    assert ev.payload == {
        "tenant_id": "t1",
        "field_key": "sandbox_per_tenant_max_cpu",
        "reason": "tenant_overlay_loosens_ceiling",
        "base_value": s.sandbox_per_tenant_max_cpu,
        "stored_value": s.sandbox_per_tenant_max_cpu + 99.0,
    }


async def test_key_not_in_registry_raises_key_error():
    r = TenantConfigResolver(
        store=_FakeStore({}), base=_settings(), audit=_RecordingAudit(), throttle_s=300
    )
    with pytest.raises(TenantConfigKeyError):
        await r.effective("require_cosign", "t1")


async def test_invalid_audit_throttled_per_tenant_field_reason():
    s = _settings()
    store = _FakeStore({"t1": {"sandbox_per_tenant_max_cpu": s.sandbox_per_tenant_max_cpu + 99.0}})
    audit = _RecordingAudit()
    r = TenantConfigResolver(store=store, base=s, audit=audit, throttle_s=300)
    for _ in range(3):
        with pytest.raises(TenantConfigOverlayInvalid):
            await r.effective("sandbox_per_tenant_max_cpu", "t1")
    assert len(audit.events) == 1  # refusal fired 3x, audit row throttled to 1


async def test_audit_write_failure_still_raises_typed_refusal():
    # Policy (user-locked): if the audit backend fails, the resolver MUST still
    # raise the typed TenantConfigOverlayInvalid (so sandbox/memory consumers can
    # map it to their closed-enum) — the audit-write failure is logged, not
    # surfaced in place of the refusal.
    s = _settings()
    store = _FakeStore({"t1": {"sandbox_per_tenant_max_cpu": s.sandbox_per_tenant_max_cpu + 99.0}})
    audit = _RaisingAudit()
    r = TenantConfigResolver(store=store, base=s, audit=audit, throttle_s=300)
    with pytest.raises(TenantConfigOverlayInvalid):  # NOT RuntimeError from the backend
        await r.effective("sandbox_per_tenant_max_cpu", "t1")
    assert audit.attempts == 1


async def test_corrupt_non_coercible_stored_value_refuses_and_audits():
    # P1 — a stored value that is not coercible (DB tampering / legacy corruption)
    # is caught at READ time: refuse with tenant_overlay_value_not_coercible + emit
    # the invalid_at_read incident. The Mapping[str, object] store type is what lets
    # this corrupt value be represented + exercised.
    s = _settings()
    store = _FakeStore({"t1": {"sandbox_per_tenant_max_cpu": "not-a-number"}})
    audit = _RecordingAudit()
    r = TenantConfigResolver(store=store, base=s, audit=audit, throttle_s=300)
    with pytest.raises(TenantConfigOverlayInvalid) as e:
        await r.effective("sandbox_per_tenant_max_cpu", "t1")
    assert e.value.reason == "tenant_overlay_value_not_coercible"
    assert len(audit.events) == 1
    assert audit.events[0].payload["reason"] == "tenant_overlay_value_not_coercible"
    assert audit.events[0].payload["stored_value"] == "not-a-number"


async def test_throttle_reemits_when_stored_value_changes():
    # P2 — same (tenant, field, reason) WITHIN the throttle window but a DIFFERENT
    # stored value MUST re-emit (the throttle is keyed on the stored value too).
    s = _settings()
    data: dict[str, dict[str, float]] = {
        "t1": {"sandbox_per_tenant_max_cpu": s.sandbox_per_tenant_max_cpu + 99.0}
    }
    audit = _RecordingAudit()
    r = TenantConfigResolver(store=_FakeStore(data), base=s, audit=audit, throttle_s=300)
    with pytest.raises(TenantConfigOverlayInvalid):
        await r.effective("sandbox_per_tenant_max_cpu", "t1")
    # Mutate the shared dict the fake reads from: same reason (loosens_ceiling),
    # different stored value, still inside the 300s window.
    data["t1"]["sandbox_per_tenant_max_cpu"] = s.sandbox_per_tenant_max_cpu + 50.0
    with pytest.raises(TenantConfigOverlayInvalid):
        await r.effective("sandbox_per_tenant_max_cpu", "t1")
    assert len(audit.events) == 2  # re-emitted because stored_value changed
