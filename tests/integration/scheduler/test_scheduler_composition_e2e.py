"""Sprint 13.7 (ADR-022) — scheduler composition e2e on the REAL build_runtime
output.

T1's harness identity pins prove ``build_runtime`` *constructs* the scheduler
with the real conformers; this e2e proves the constructed shape *works* — a
live ``runtime.scheduler.submit(...)`` flows through quota + kill-switch +
approval + pack-state + policy + storage in one pass. Driven directly (Fork D —
no route/caller in 13.7).

Substrate: the in-memory adapters (db_driver=memory shared sqlite + the
13.7-extended in-memory cache client backing the REAL QuotaEngine plane). The
chain schema comes from ``InMemoryRelationalAdapter.connect()``; ``scheduler_tasks``
+ ``packs`` (both registered against the shared ``core.audit._metadata``) are
added with one idempotent ``_metadata.create_all`` AFTER build_runtime imports
their storage modules.

The installed-admit path reaches the real step-4 ``SchedulerPolicy`` gate, so it
carries ``@opa_required``; the two refusal paths refuse before the policy gate
(engine docstring order: parent_budget -> pack_state -> kill_switch -> approval
-> policy -> quota) and run unconditionally.
"""

from __future__ import annotations

import shutil
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.emergency.quotas import _reserved_tenant_key
from cognic_agentos.core.scheduler._seams import ParentTaskBudgetUnavailable
from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor
from cognic_agentos.db.adapters.factory import build_adapters
from cognic_agentos.harness import build_runtime
from cognic_agentos.packs.storage import PackRecord, PackRecordStore, _packs

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.ext.asyncio import AsyncEngine

    from cognic_agentos.core.config import Settings
    from cognic_agentos.db.adapters.factory import Adapters
    from cognic_agentos.db.adapters.registry import AdapterRegistry
    from cognic_agentos.harness import Runtime

opa_required = pytest.mark.skipif(
    shutil.which("opa") is None,
    reason="opa binary not installed — the installed-admit path reaches the "
    "step-4 SchedulerPolicy gate; the refusal paths run unconditionally",
)


def _litellm_yaml(tmp_path: Path) -> Path:
    """Minimal LiteLLM config so build_runtime's PreflightResolver.from_yaml has
    a real file to read (mirrors tests/unit/harness/test_runtime.py)."""
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n"
        "  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n"
        "      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return cfg


async def _build_composed_runtime(
    memory_registry: AdapterRegistry,
    memory_settings: Settings,
    tmp_path: Path,
) -> tuple[Runtime, Adapters, AsyncEngine]:
    """build_runtime over the in-memory adapters, with scheduler_tasks + packs
    created on the shared engine (connect() seeds only chain schema).
    Caller MUST close in finally: ``await runtime.aclose(); await adapters.close_all()``."""
    s = memory_settings.model_copy(
        update={"litellm_config_path": _litellm_yaml(tmp_path), "cache_driver": "memory"}
    )
    adapters = build_adapters(s, registry=memory_registry)
    await adapters.open_all()  # REQUIRED — InMemoryRelationalAdapter.engine raises until connect()
    runtime = await build_runtime(s, adapters)  # imports scheduler/packs storage
    eng = adapters.relational.engine
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)  # checkfirst -> adds scheduler_tasks + packs
    return runtime, adapters, eng


def _draft_pack(*, pack_id: str, tenant_id: str) -> PackRecord:
    now = datetime.now(UTC)
    return PackRecord(
        id=uuid.uuid4(),
        kind="tool",
        pack_id=pack_id,
        display_name=pack_id,
        state="draft",
        manifest_digest=b"\x01" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id=tenant_id,
        created_by="canary-author",
        last_actor="canary-author",
        created_at=now,
        updated_at=now,
    )


def _submit_input(*, parent_task_id: str | None = None) -> SubmitInput:
    return SubmitInput(
        tenant_id="t-1",
        pack_id="pack-x",
        actor=TaskActor(subject="svc-a", tenant_id="t-1", actor_type="service"),
        class_="interactive",
        pack_kind="tool",
        pack_risk_tier="internal_write",
        requested_estimated_tokens=500,
        parent_task_id=parent_task_id,
    )


@opa_required
async def test_composition_installed_safe_tier_admits(memory_registry, memory_settings, tmp_path):
    """Installed pack + safe tier -> accepted_immediate -> running -> completed,
    composing quota + kill-switch + approval(auto internal_write) + pack-state +
    policy + storage. The tenant quota counter reserves on admit and releases on
    complete (proves the real QuotaEngine plane is wired, not bypassed)."""
    runtime, adapters, eng = await _build_composed_runtime(
        memory_registry, memory_settings, tmp_path
    )
    try:
        scheduler = runtime.scheduler
        cache = adapters.cache
        assert scheduler is not None  # cache_driver=memory -> scheduler built
        assert cache is not None

        rec = _draft_pack(pack_id="pack-x", tenant_id="t-1")
        await PackRecordStore(eng).save_draft(rec)  # genesis guard requires draft
        async with eng.begin() as conn:  # typed UPDATE via the Table (binds UUID correctly)
            await conn.execute(
                _packs.update().where(_packs.c.id == rec.id).values(state="installed")
            )

        window = datetime.now(UTC).strftime("%Y%m%d")
        reserved_key = _reserved_tenant_key("t-1", window)

        d = await scheduler.submit(submit_input=_submit_input(), request_id="req-1")
        assert d.outcome == "accepted_immediate"
        assert d.task_id is not None
        # quota reserved on admit (the real QuotaEngine plane over the cache client).
        assert int(str(await cache.client.get(reserved_key))) == 500

        tid = uuid.UUID(d.task_id)
        await scheduler.mark_running(tid, request_id="req-1")
        await scheduler.complete(tid, request_id="req-1")
        # complete() releases the reservation -> tenant counter back to 0.
        assert int(str(await cache.client.get(reserved_key))) == 0
    finally:
        await runtime.aclose()
        await adapters.close_all()


async def test_composition_non_installed_pack_refused(memory_registry, memory_settings, tmp_path):
    """Non-installed pack -> refused_pack_not_installed. Proves the REAL
    PackStoreStateInterrogator is wired (refuses at the step-2 gate, before the
    policy/OPA gate) — no seeding."""
    runtime, adapters, _eng = await _build_composed_runtime(
        memory_registry, memory_settings, tmp_path
    )
    try:
        scheduler = runtime.scheduler
        assert scheduler is not None
        d = await scheduler.submit(submit_input=_submit_input(), request_id="req-2")
        assert d.outcome == "refused_pack_not_installed"
    finally:
        await runtime.aclose()
        await adapters.close_all()


async def test_composition_subagent_submit_fails_loud(memory_registry, memory_settings, tmp_path):
    """Sub-agent submit (parent_task_id set) -> ParentTaskBudgetUnavailable
    ("parent_not_found") from the real SchedulerTaskParentBudgetResolver wired
    at the composition root: a random parent_task_id has no persisted budget
    snapshot, so it reads as absent. The parent-budget consult precedes
    pack_state/OPA, so this runs unconditionally."""
    runtime, adapters, _eng = await _build_composed_runtime(
        memory_registry, memory_settings, tmp_path
    )
    try:
        scheduler = runtime.scheduler
        assert scheduler is not None
        sub = _submit_input(parent_task_id=str(uuid.uuid4()))
        with pytest.raises(ParentTaskBudgetUnavailable) as ei:
            await scheduler.submit(submit_input=sub, request_id="req-3")
        assert ei.value.reason == "parent_not_found"
    finally:
        await runtime.aclose()
        await adapters.close_all()
