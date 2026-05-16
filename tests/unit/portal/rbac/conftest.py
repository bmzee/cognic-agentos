"""Sprint 7B.4 T6 — pytest fixtures for the RBAC denial chain-emission
test suite.

Fixture inventory + design notes:

- Test-store stack (sqlite_engine, audit_store, decision_history_store,
  ui_event_emitter, broker) mirrors the canonical Sprint-6 emitter-test
  pattern at `tests/unit/protocol/test_ui_events_audit_mirror.py:54-91`.
- `pack_record_store` + 2 seeded packs wire the real PackRecordStore so
  `create_app` mounts the pack routes the denial paths target.
- `actor_t1_with_pack_submit` is the default actor for the cap-test +
  the dispatcher's actor-resolved branches; carries `pack.submit` +
  `pack.audit.read` so it can reach the routes WITHOUT holding the
  scopes specific tests probe for.
- `_setup_denial_path(seeded_packs)` returns a callable that, given an
  app + a denial_type, swaps `app.state.actor_binder` to a binder that
  triggers THAT denial path AND returns the (method, path, kwargs)
  tuple the test should fire. Per the doctrine: swap the BINDER, NOT
  `dependency_overrides[_bind_actor]` (which bypasses the real
  exception-catch + chain-emit path under test).

Cross-directory imports: `_FixtureActorBinder` comes from
`tests/unit/portal/api/ui/sse_test_helpers.py` (T6-owned per the R6 #1
task-ordering fix). The absolute import path resolves because both
sibling `tests/unit/portal/...` packages are reachable from
`tests/__init__.py` upward through the pytest rootdir.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.packs.storage import PackRecord, PackRecordStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.ui_events import UIEventBroker, UIEventEmitter
from tests.unit.portal.api.ui.sse_test_helpers import _FixtureActorBinder


@pytest.fixture
async def sqlite_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """Per-test sqlite engine with both chain heads seeded."""
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'rbac_test.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.fixture
def settings() -> Settings:
    return Settings()


@pytest.fixture
async def audit_store(sqlite_engine: AsyncEngine) -> AuditStore:
    return AuditStore(sqlite_engine)


@pytest.fixture
async def decision_history_store(sqlite_engine: AsyncEngine) -> DecisionHistoryStore:
    return DecisionHistoryStore(sqlite_engine)


@pytest.fixture
async def ui_event_emitter(
    audit_store: AuditStore,
    decision_history_store: DecisionHistoryStore,
) -> UIEventEmitter:
    return UIEventEmitter(
        audit_store=audit_store,
        decision_history_store=decision_history_store,
    )


@pytest.fixture
async def broker(
    decision_history_store: DecisionHistoryStore,
    ui_event_emitter: UIEventEmitter,
    settings: Settings,
) -> UIEventBroker:
    b = UIEventBroker(decision_history_store=decision_history_store, settings=settings)
    b.register_with_emitter(ui_event_emitter)
    return b


@pytest.fixture
async def pack_record_store(sqlite_engine: AsyncEngine) -> PackRecordStore:
    """`PackRecordStore.__init__` takes a single `engine: AsyncEngine`
    arg (verified at `packs/storage.py:491`)."""
    return PackRecordStore(sqlite_engine)


@pytest.fixture
async def seeded_pack_t1(pack_record_store: PackRecordStore) -> PackRecord:
    """A pack in tenant t1 with `created_by="u1"` — drives the
    role_separation `actor_cannot_review_own_pack` path when the test
    actor's subject is also "u1"."""
    record = PackRecord(
        id=uuid.uuid4(),
        kind="tool",
        pack_id="example-tool",
        display_name="Example Tool",
        state="draft",
        manifest_digest=b"\x00" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id="t1",
        created_by="u1",
        last_actor="u1",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    await pack_record_store.save_draft(record)
    return record


@pytest.fixture
async def seeded_pack_t2(pack_record_store: PackRecordStore) -> PackRecord:
    """A pack in tenant t2 — drives the tenant_id_mismatch denial path
    when the test actor is in tenant t1."""
    record = PackRecord(
        id=uuid.uuid4(),
        kind="tool",
        pack_id="t2-tool",
        display_name="T2 Tool",
        state="draft",
        manifest_digest=b"\x00" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id="t2",
        created_by="other-user",
        last_actor="other-user",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    await pack_record_store.save_draft(record)
    return record


@pytest.fixture
def actor_t1_with_pack_submit() -> Actor:
    """Default RBAC-test actor: tenant t1; holds `pack.submit` +
    `pack.audit.read`. Lacks `pack.allow_list`, `pack.review.claim`,
    `pack.review.approve` → forces scope_not_held on those routes."""
    return Actor(
        subject="u1",
        tenant_id="t1",
        actor_type="human",
        scopes=frozenset({"pack.submit", "pack.audit.read"}),
    )


@pytest.fixture
async def app_with_broker(
    broker: UIEventBroker,
    decision_history_store: DecisionHistoryStore,
    audit_store: AuditStore,
    ui_event_emitter: UIEventEmitter,
    pack_record_store: PackRecordStore,
    settings: Settings,
    actor_t1_with_pack_submit: Actor,
) -> FastAPI:
    """App with broker + pack routes wired. `pack_record_store` is
    threaded into `create_app` so the POST /api/v1/packs/* routes
    mount (RBAC denial dispatcher targets them).

    Override `app.state.ui_event_broker` with the test fixture's
    `broker` instance: `create_app` constructs ITS OWN broker from the
    deps it receives, but tests spy on the fixture's `broker` (via
    AsyncMock wrap) — they MUST be the same instance for the spy to
    observe the dep's emit call. Re-attach after create_app so the
    fixture-broker wins."""
    from cognic_agentos.portal.api.app import create_app

    app = create_app(
        settings=settings,
        actor_binder=_FixtureActorBinder(actor_t1_with_pack_submit),
        pack_record_store=pack_record_store,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
    )
    app.state.ui_event_broker = broker
    return app


@pytest.fixture
def _setup_denial_path(
    seeded_pack_t1: PackRecord,
    seeded_pack_t2: PackRecord,
) -> Callable[[FastAPI, str], tuple[str, str, dict[str, Any]]]:
    """9-branch dispatcher — one (binder-swap, request-tuple) pair per
    `RBACDenialType` value.

    Returns a callable `setup(app, denial_type) -> (method, path, kwargs)`.
    The callable mutates `app.state.actor_binder` to a binder that
    triggers the named denial path (NOT `dependency_overrides[_bind_actor]`
    — that would bypass the real `_bind_actor` exception-catch + chain-emit
    path the T6 regression is verifying).
    """
    from cognic_agentos.portal.rbac.actor import (
        ActorBinderUnauthenticated,
        KernelDefaultActorBinder,
    )

    class _RaisesUnauthBinder:
        def bind(self, *, request: Any) -> Actor:
            raise ActorBinderUnauthenticated("no token")

    class _FixedActor:
        def __init__(self, actor: Actor) -> None:
            self._a = actor

        def bind(self, *, request: Any) -> Actor:
            return self._a

    def setup(app: FastAPI, denial_type: str) -> tuple[str, str, dict[str, Any]]:
        if denial_type == "actor_unauthenticated":
            app.state.actor_binder = _RaisesUnauthBinder()
            return ("POST", "/api/v1/packs/drafts", {"json": {"manifest": {}}})

        if denial_type == "actor_binder_not_configured":
            # KernelDefaultActorBinder.bind raises NotImplementedError.
            app.state.actor_binder = KernelDefaultActorBinder()
            return ("POST", "/api/v1/packs/drafts", {"json": {"manifest": {}}})

        if denial_type == "scope_not_held":
            actor = Actor(
                subject="u1",
                tenant_id="t1",
                actor_type="human",
                scopes=frozenset({"pack.submit"}),  # lacks pack.allow_list
            )
            app.state.actor_binder = _FixedActor(actor)
            return (
                "POST",
                f"/api/v1/packs/{seeded_pack_t1.id}/allow-list",
                {"json": {}},
            )

        if denial_type == "tenant_id_mismatch":
            actor = Actor(
                subject="u1",
                tenant_id="t1",
                actor_type="human",
                scopes=frozenset({"pack.audit.read"}),
            )
            app.state.actor_binder = _FixedActor(actor)
            # Actor in t1; pack in t2 → tenant_id_mismatch (rendered as
            # 404 cross-tenant-invisible at the wire; chain row +
            # structured log still emit tenant_id_mismatch).
            return ("GET", f"/api/v1/packs/{seeded_pack_t2.id}", {})

        if denial_type == "pack_not_found":
            actor = Actor(
                subject="u1",
                tenant_id="t1",
                actor_type="human",
                scopes=frozenset({"pack.audit.read"}),
            )
            app.state.actor_binder = _FixedActor(actor)
            # Bogus pack_id under actor's tenant.
            return ("GET", f"/api/v1/packs/{uuid.uuid4()}", {})

        if denial_type == "actor_tenant_id_missing":
            actor = Actor(
                subject="u1",
                tenant_id="",  # only Pydantic-reachable falsy case
                actor_type="human",
                scopes=frozenset({"pack.audit.read"}),
            )
            app.state.actor_binder = _FixedActor(actor)
            # Bare list endpoint is at `/api/v1/packs` (NO trailing
            # slash) per the R33 P2 doctrine decision in inspection_routes.py.
            # A trailing slash would 307-redirect — never reach the
            # actor_tenant_id_missing preflight.
            return ("GET", "/api/v1/packs", {})

        if denial_type == "pack_store_not_configured":
            actor = Actor(
                subject="u1",
                tenant_id="t1",
                actor_type="human",
                scopes=frozenset({"pack.audit.read"}),
            )
            app.state.actor_binder = _FixedActor(actor)
            # Simulate the configuration regression by clearing
            # pack_record_store from app.state at request time.
            app.state.pack_record_store = None
            return ("GET", f"/api/v1/packs/{seeded_pack_t1.id}", {})

        if denial_type == "actor_type_must_be_human":
            actor = Actor(
                subject="svc-bot",
                tenant_id="t1",
                actor_type="service",
                scopes=frozenset({"pack.submit", "pack.allow_list"}),
            )
            app.state.actor_binder = _FixedActor(actor)
            return (
                "POST",
                f"/api/v1/packs/{seeded_pack_t1.id}/allow-list",
                {"json": {}},
            )

        if denial_type == "actor_cannot_review_own_pack":
            actor = Actor(
                subject="u1",  # SAME as seeded_pack_t1.created_by
                tenant_id="t1",
                actor_type="human",
                scopes=frozenset({"pack.review.claim"}),
            )
            app.state.actor_binder = _FixedActor(actor)
            return (
                "POST",
                f"/api/v1/packs/{seeded_pack_t1.id}/claim",
                {"json": {}},
            )

        raise AssertionError(f"unknown RBACDenialType: {denial_type!r}")

    return setup
