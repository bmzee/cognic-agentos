"""ADR-023 Task 8 — per-tenant memory-export retention overlay wiring.

Option A (locked): MemoryAPI gains an OPTIONAL resolver. When wired, export()
resolves ``memory_export_retention_seconds`` via the resolver and threads it into
``export_memory(...)``; when absent (the default until Task 10 wires the real
resolver into the runtime MemoryAPI factory), export() uses
``settings.memory_export_retention_seconds`` exactly as before. A corrupt /
floor-violating stored overlay fails CLOSED with the new closed-enum refusal.

Mirrors the live export harness in ``test_api_export.py`` (fixtures
``memory_adapter`` / ``dh_store`` / ``decision_history_rows``; builders
``SUBJECT`` / ``_task_record``; conftest ``_ctx`` / ``_AllowAllPolicy`` /
``_InactiveKillSwitch``).
"""

from __future__ import annotations

import typing
from typing import Any

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.core.config_overlay.resolver import TenantConfigOverlayInvalid
from cognic_agentos.core.dlp.scanner import ChecksumRegexGazetteerScanner
from cognic_agentos.core.memory._context import MemoryCallerContext
from cognic_agentos.core.memory.api import MemoryAPI
from cognic_agentos.core.memory.consent import ConsentValidator
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, MemoryRefusalReason
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter

from ._builders import SUBJECT, _task_record
from .conftest import _AllowAllPolicy, _ctx, _InactiveKillSwitch


class _FakeResolver:
    """Duck-typed resolver double. export() reads ONE field via effective();
    effective_many() raises so any refactor that routes export retention through
    the batch primitive fails loud. Reaches MemoryAPI through the _api helper's
    Any-typed resolver param (same convention test_api_export uses for the
    memory_adapter / dh_store fakes)."""

    def __init__(self, value: int | float | None = None, *, invalid: bool = False) -> None:
        self._value = value
        self._invalid = invalid
        self.calls: list[tuple[str, str]] = []

    async def effective(self, field_key: str, tenant_id: str) -> int | float:
        self.calls.append((field_key, tenant_id))
        if self._invalid:
            raise TenantConfigOverlayInvalid(
                "memory_export_retention_seconds", "tenant_overlay_below_kernel_floor"
            )
        assert self._value is not None
        return self._value

    async def effective_many(
        self, field_keys: tuple[str, ...], tenant_id: str
    ) -> dict[str, int | float]:
        raise AssertionError("export() must use single-field effective(), not effective_many()")


def _api(
    ctx: MemoryCallerContext,
    memory_adapter: Any,
    dh_store: Any,
    object_store: Any,
    resolver: Any,
    settings: Settings | None = None,
) -> MemoryAPI:
    return MemoryAPI(
        context=ctx,
        adapter=memory_adapter,
        dlp=ChecksumRegexGazetteerScanner(),
        consent=ConsentValidator(audit=dh_store),
        policy=_AllowAllPolicy(),  # type: ignore[arg-type]
        kill_switch=_InactiveKillSwitch(),
        audit=dh_store,
        settings=settings or Settings(),
        object_store=object_store,
        resolver=resolver,
    )


def test_refusal_enum_has_overlay_invalid_value():
    assert "memory_export_tenant_config_overlay_invalid" in typing.get_args(MemoryRefusalReason)


async def test_resolved_retention_reaches_export(
    memory_adapter, dh_store, tmp_path, decision_history_rows
):
    obj = LocalObjectStoreAdapter(root=tmp_path)
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    ten_years = 10 * 365 * 24 * 3600
    resolver = _FakeResolver(value=ten_years)
    api = _api(ctx, memory_adapter, dh_store, obj, resolver)
    await memory_adapter.put(_task_record(value="payload"))
    await api.export(SUBJECT)
    export_rows = [r for r in await decision_history_rows() if r.event_type == "memory.export"]
    assert len(export_rows) == 1
    assert export_rows[0].payload["retention_seconds"] == ten_years
    # Resolved via EXACTLY ONE single-field effective() call with the right tenant.
    assert resolver.calls == [("memory_export_retention_seconds", "t1")]


async def test_resolver_none_uses_settings_retention(
    memory_adapter, dh_store, tmp_path, decision_history_rows
):
    # Option A fallback — resolver=None preserves the base-setting behaviour
    # (byte-equivalent to pre-ADR-023; the runtime factory passes a real
    # resolver only at Task 10).
    obj = LocalObjectStoreAdapter(root=tmp_path)
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    eight_years = 8 * 365 * 24 * 3600
    settings = Settings(memory_export_retention_seconds=eight_years)
    api = _api(ctx, memory_adapter, dh_store, obj, None, settings=settings)
    await memory_adapter.put(_task_record(value="payload"))
    await api.export(SUBJECT)
    export_rows = [r for r in await decision_history_rows() if r.event_type == "memory.export"]
    assert len(export_rows) == 1
    assert export_rows[0].payload["retention_seconds"] == eight_years


async def test_corrupt_overlay_export_fails_closed(memory_adapter, dh_store, tmp_path):
    obj = LocalObjectStoreAdapter(root=tmp_path)
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _api(ctx, memory_adapter, dh_store, obj, _FakeResolver(invalid=True))
    await memory_adapter.put(_task_record(value="payload"))
    with pytest.raises(MemoryOperationRefused) as e:
        await api.export(SUBJECT)
    assert e.value.reason == "memory_export_tenant_config_overlay_invalid"


async def test_fractional_float_overlay_fails_closed(memory_adapter, dh_store, tmp_path):
    # Governance boundary — NEVER silently coerce. A fractional retention value
    # (corrupt resolver/store) must fail CLOSED, not truncate via int(...)
    # (int(220752000.5) -> 220752000 would reintroduce the Task-1 "no silent
    # fractional int coercion" class).
    obj = LocalObjectStoreAdapter(root=tmp_path)
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _api(ctx, memory_adapter, dh_store, obj, _FakeResolver(value=220752000.5))
    await memory_adapter.put(_task_record(value="payload"))
    with pytest.raises(MemoryOperationRefused) as e:
        await api.export(SUBJECT)
    assert e.value.reason == "memory_export_tenant_config_overlay_invalid"


async def test_bool_overlay_fails_closed(memory_adapter, dh_store, tmp_path):
    # Defence-in-depth: bool is an int subclass — a True/False retention value
    # must fail CLOSED even though the registry rejects bool upstream.
    obj = LocalObjectStoreAdapter(root=tmp_path)
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _api(ctx, memory_adapter, dh_store, obj, _FakeResolver(value=True))
    await memory_adapter.put(_task_record(value="payload"))
    with pytest.raises(MemoryOperationRefused) as e:
        await api.export(SUBJECT)
    assert e.value.reason == "memory_export_tenant_config_overlay_invalid"
