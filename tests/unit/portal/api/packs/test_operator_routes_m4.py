"""M4 Task 6 — operator install/disable/revoke SAGA + gates + compensation.

The install/disable/revoke handlers gain the M4 runtime-config materialization
saga (ADR-026 D1/D6). This suite pins:

- the **install saga** ordering + gate refusals (gates 1-4, all read-only
  pre-checks that refuse BEFORE any write) + the happy path (derived
  override + allow-list rows land, ``activation_status="active"``, state
  ``installed``);
- the **compensation contract** — every failed-install path leaves ZERO
  derived rows for the pack + a NON-active / NON-installed record; a
  mid-saga write failure triggers retract (materialize→activate failure) or
  retract+revert-activation (activate→transition failure); a compensation
  step that itself raises surfaces a fail-loud 500
  ``install_compensation_failed``;
- the **disable/revoke sagas** — retract-FIRST (un-expose) then govern in two
  phases: a post-retract **transition** failure (state unchanged) re-materializes
  (compensation) so the pack is left callable rather than silently half-disabled,
  but a **status-write** failure AFTER the transition committed does NOT
  re-materialize — the pack is left fail-closed (retracted / not callable) with
  lifecycle ``disabled``/``revoked`` and a fail-loud 500;
- **re-install from ``disabled``** re-materializes (the ADR-012 multi-from
  ``disabled → installed`` extension);
- the ``from __future__`` AST omission guard + the ``InstallRefusalReason``
  closed-enum count guard (``typing.get_args``, not regex).

**Fixtures** run against the Alembic-MIGRATED DB (NOT ``_metadata.create_all``)
per ``[[feedback_storage_test_migrated_db_not_create_all]]`` so the
migration-only unique constraints + the genesis chain-head seed are exercised
exactly as production sees them. Happy + gate tests use the REAL
:class:`RuntimeConfigMaterializer` wired to the REAL carve-out + config stores
(+ a stub ``vault_reader``) so the derived-row projection is proven
end-to-end; compensation tests use a recording :class:`_StubMaterializer` (with
injectable faults) + a wrapped config store so mid-saga failures are
controllable while the pack store stays real.

**Proving "no derived rows remain"** — every failed-install assertion queries
the REAL override store (``get``) + allow-list store (``get_allowlist``) after
the request and asserts both are empty for the pack/tenant.
"""

from __future__ import annotations

import ast
import asyncio
import pathlib
import uuid
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.mcp_config.materializer import (
    MaterializeResult,
    RuntimeConfigMaterializer,
)
from cognic_agentos.core.mcp_config.runtime_config import (
    PackRuntimeConfigRecord,
    PackRuntimeConfigStore,
)
from cognic_agentos.core.mcp_config.storage import (
    MCPInternalHostAllowlistStore,
    MCPServerUrlOverrideStore,
)
from cognic_agentos.packs.storage import PackNotFound, PackRecord, PackRecordStore
from cognic_agentos.portal.api.packs import operator_routes
from cognic_agentos.portal.api.packs.operator_routes import build_operator_routes
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate

# --------------------------------------------------------------------------- #
# The pack's desired IPs / override / Vault refs used across the suite.
# --------------------------------------------------------------------------- #

_TENANT = "t1"
_OVERRIDE_URL = "http://10.42.0.7:8080/mcp"
_DESIRED_IPS = ("10.42.0.7", "10.42.0.9")
_OAUTH_REF = "secret/cognic/t1/mcp-oauth/10.42.0.7"
_AS_REF = "secret/cognic/t1/mcp-as-allowlist"

#: A vault store shaped exactly as the materializer's validators expect
#: (client_id/client_secret for the oauth ref; a non-empty servers list for
#: the AS ref). Keyed by ref path.
_VALID_VAULT: dict[str, dict[str, Any]] = {
    _OAUTH_REF: {"client_id": "cid", "client_secret": "csecret"},
    _AS_REF: {"servers": ["10.42.0.7:8080"]},
}


# --------------------------------------------------------------------------- #
# Stub actor binder + fake registry + stub vault (mirrors test_operator_routes)
# --------------------------------------------------------------------------- #


class _StubBinder:
    """Test-only ``ActorBinder`` returning a configured actor."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


class _FakeRegistry:
    """Fake ``RegisteredPackReader`` — yields the given distribution names as
    REGISTERED candidates (gate 2 matches ``record.pack_id`` against these)."""

    def __init__(self, distribution_names: tuple[str, ...]) -> None:
        self._names = distribution_names

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]:
        for name in self._names:
            yield RegisteredPackCandidate(
                distribution_name=name,
                package_name=name.replace("-", "_"),
                signature_digest="deadbeef",
            )


class _StubVault:
    """Narrow ``VaultReader`` double — returns the mapping at ``path`` or None."""

    def __init__(self, store: dict[str, dict[str, Any]]) -> None:
        self._store = store

    async def read(self, path: str) -> dict[str, Any] | None:
        return self._store.get(path)


class _StubMaterializer:
    """Recording ``_MaterializerLike`` double with injectable faults.

    ``materialize_raises`` / ``retract_raises`` inject an exception on the NEXT
    call (a callable returning the exception to raise, or None). Every call is
    recorded so compensation ordering can be asserted.
    """

    def __init__(self) -> None:
        self.materialize_calls: list[dict[str, Any]] = []
        self.retract_calls: list[dict[str, Any]] = []
        self.materialize_raises: Exception | None = None
        self.retract_raises: Exception | None = None

    async def materialize(
        self,
        *,
        record: PackRuntimeConfigRecord,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> MaterializeResult:
        self.materialize_calls.append(
            {
                "pack_id": record.pack_id,
                "tenant_id": record.tenant_id,
                "actor_subject": actor_subject,
                "actor_type": actor_type,
                "request_id": request_id,
            }
        )
        if self.materialize_raises is not None:
            exc = self.materialize_raises
            raise exc
        return MaterializeResult(
            override_action="set",
            allowlist_added=_DESIRED_IPS,
            allowlist_removed=(),
            tenant_allowlist_after=frozenset(_DESIRED_IPS),
        )

    async def retract(
        self,
        *,
        tenant_id: str,
        pack_id: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        self.retract_calls.append(
            {
                "tenant_id": tenant_id,
                "pack_id": pack_id,
                "actor_subject": actor_subject,
                "actor_type": actor_type,
                "request_id": request_id,
            }
        )
        if self.retract_raises is not None:
            exc = self.retract_raises
            raise exc


class _FailingActivationConfigStore:
    """Wraps a real ``PackRuntimeConfigStore``; delegates ``get`` but injects a
    fault into ``set_activation_status`` when armed (to test compensation on the
    activation write). ``set_activation_calls`` records each attempted status."""

    def __init__(self, real: PackRuntimeConfigStore) -> None:
        self._real = real
        self.set_activation_calls: list[dict[str, Any]] = []
        self.fail_on_status: str | None = None

    async def get(self, *, tenant_id: str, pack_id: str) -> PackRuntimeConfigRecord | None:
        return await self._real.get(tenant_id=tenant_id, pack_id=pack_id)

    async def set_activation_status(
        self,
        *,
        tenant_id: str,
        pack_id: str,
        status: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        self.set_activation_calls.append({"status": status, "pack_id": pack_id})
        if self.fail_on_status is not None and status == self.fail_on_status:
            raise RuntimeError("injected activation write failure")
        await self._real.set_activation_status(
            tenant_id=tenant_id,
            pack_id=pack_id,
            status=status,
            actor_subject=actor_subject,
            actor_type=actor_type,
            request_id=request_id,
        )


# --------------------------------------------------------------------------- #
# Migrated-DB fixtures + real stores
# --------------------------------------------------------------------------- #


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    """Alembic-migrated SQLite engine — genesis chain heads + migration-only
    constraints exactly as production
    (``[[feedback_storage_test_migrated_db_not_create_all]]``)."""
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'operator_m4.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    eng = create_async_engine(url)
    yield eng
    await eng.dispose()


@pytest.fixture
def store(engine: AsyncEngine) -> PackRecordStore:
    return PackRecordStore(engine)


@pytest.fixture
def override_store(engine: AsyncEngine) -> MCPServerUrlOverrideStore:
    return MCPServerUrlOverrideStore(engine)


@pytest.fixture
def allowlist_store(engine: AsyncEngine) -> MCPInternalHostAllowlistStore:
    return MCPInternalHostAllowlistStore(engine)


@pytest.fixture
def config_store(engine: AsyncEngine) -> PackRuntimeConfigStore:
    return PackRuntimeConfigStore(engine)


@pytest.fixture
def real_materializer(
    override_store: MCPServerUrlOverrideStore,
    allowlist_store: MCPInternalHostAllowlistStore,
    config_store: PackRuntimeConfigStore,
) -> RuntimeConfigMaterializer:
    """The REAL materializer wired to the REAL carve-out + config stores + a
    stub vault that RESOLVES both refs — proves the derived-row projection."""
    return RuntimeConfigMaterializer(
        override_store=override_store,
        allowlist_store=allowlist_store,
        config_store=config_store,
        vault_reader=_StubVault(_VALID_VAULT),
    )


def _make_operator_actor(
    *,
    subject: str = "operator@bank.example",
    tenant_id: str = _TENANT,
    actor_type: str = "human",
) -> Actor:
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=frozenset(
            {"pack.allow_list", "pack.install", "pack.disable", "pack.revoke", "pack.uninstall"}
        ),
        actor_type=actor_type,  # type: ignore[arg-type]
    )


def _build_app(
    *,
    actor: Actor,
    store: Any,
    materializer: Any,
    config_store: Any,
    registry: Any,
) -> FastAPI:
    """Build an app carrying the M4-extended operator router as the SOLE handler
    of the operator paths (the composition root — Task 7 — will later thread the
    same M4 params into ``build_packs_router`` so ``create_app`` mounts the
    saga-enabled router directly).

    We pass ``actor_binder`` but NOT ``pack_record_store`` to ``create_app`` so
    it does NOT auto-mount ``build_packs_router`` (whose ``build_operator_routes``
    has None M4 deps and would shadow ours under FastAPI's first-match routing).
    ``app.state.actor_binder`` is wired by ``create_app``; we set
    ``app.state.pack_record_store`` ourselves (``RequireTenantOwnership`` reads
    it) then mount the M4 operator router alone.

    **Registry is REQUEST-TIME (ADR-026 D6 option B).** Install gate 2 reads
    ``request.app.state.plugin_registry`` — so we pass ``registry`` as the
    ``create_app(plugin_registry=...)`` kwarg (the adapter-less lifespan sets
    ``app.state.plugin_registry = plugin_registry`` and returns early, so the
    request-time read finds it), NOT as a ``build_operator_routes`` factory
    argument (which now takes only the 2 body-time deps, all-2-or-none)."""
    from cognic_agentos.portal.api.app import create_app

    app = create_app(actor_binder=_StubBinder(actor), plugin_registry=registry)
    app.state.pack_record_store = store
    app.include_router(
        build_operator_routes(
            store=store,
            materializer=materializer,
            config_store=config_store,
        ),
        prefix="/api/v1/packs",
    )
    return app


# --------------------------------------------------------------------------- #
# Lifecycle seed helpers (walk a pack to a target state on the real store)
# --------------------------------------------------------------------------- #


async def _seed_allow_listed(
    store: PackRecordStore,
    *,
    tenant_id: str = _TENANT,
    dist_name: str = "cognic-tool-oracle-schema",
) -> PackRecord:
    """draft → submitted → under_review → approved → allow_listed. Returns the
    record with its post-transition state + the deterministic ``pack_id``
    (distribution name) so the registry gate + config key line up."""
    now = datetime.now(UTC)
    record = PackRecord(
        id=uuid.uuid4(),
        kind="tool",
        pack_id=dist_name,
        display_name="Oracle Schema",
        state="draft",
        manifest_digest=b"\x01" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id=tenant_id,
        created_by="bob@bank.example",
        last_actor="bob@bank.example",
        created_at=now,
        updated_at=now,
    )
    await store.save_draft(record)
    for tname, actor_id in (
        ("submit", "bob@bank.example"),
        ("claim", "carol@bank.example"),
        ("approve", "dave@bank.example"),
        ("allow_list", "elena@bank.example"),
    ):
        await store.transition(
            pack_id=record.id,
            transition=tname,  # type: ignore[arg-type]
            actor_id=actor_id,
            tenant_id=tenant_id,
            evidence_pointer=None,
            request_id=f"{tname[:6]}-seed-{record.id.hex[:8]}",
        )
    return record.model_copy(update={"state": "allow_listed"})


async def _seed_installed_via_store(
    store: PackRecordStore,
    *,
    tenant_id: str = _TENANT,
    dist_name: str = "cognic-tool-oracle-schema",
) -> PackRecord:
    """...→ allow_listed → installed (pure store transition; no materialize)."""
    record = await _seed_allow_listed(store, tenant_id=tenant_id, dist_name=dist_name)
    await store.transition(
        pack_id=record.id,
        transition="install",
        actor_id="frank@bank.example",
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"instll-seed-{record.id.hex[:8]}",
    )
    return record.model_copy(update={"state": "installed"})


async def _write_config(
    config_store: PackRuntimeConfigStore,
    *,
    record: PackRecord,
    tenant_id: str = _TENANT,
    server_url_override: str | None = _OVERRIDE_URL,
    allowlist: list[str] | None = None,
    oauth_ref: str | None = _OAUTH_REF,
    as_ref: str | None = _AS_REF,
) -> None:
    """Write the desired runtime-config record keyed by ``str(record.id)`` —
    exactly what Task 3's configure endpoint wrote."""
    await config_store.set_config(
        tenant_id=tenant_id,
        pack_id=str(record.id),
        server_url_override=server_url_override,
        internal_host_allowlist=list(_DESIRED_IPS) if allowlist is None else allowlist,
        oauth_credential_ref=oauth_ref,
        as_allowlist_ref=as_ref,
        actor_subject="operator@bank.example",
        actor_type="human",
        request_id=f"cfg-{record.id.hex[:8]}",
    )


async def _assert_no_derived_rows(
    *,
    override_store: MCPServerUrlOverrideStore,
    allowlist_store: MCPInternalHostAllowlistStore,
    record: PackRecord,
    tenant_id: str = _TENANT,
) -> None:
    """The pack's override is absent AND the tenant allow-list carries none of
    the pack's desired IPs (proves the failed install left ZERO derived rows)."""
    override = await override_store.get(tenant_id=tenant_id, pack_id=str(record.id))
    assert override is None, f"expected NO derived override for the pack; got {override!r}"
    allow = await allowlist_store.get_allowlist(tenant_id=tenant_id)
    leaked = allow & frozenset(_DESIRED_IPS)
    assert not leaked, f"expected NO derived allow-list rows for the pack; leaked {leaked!r}"


_OPERATOR_ROUTES_LOGGER = "cognic_agentos.portal.api.packs.operator_routes"


# --------------------------------------------------------------------------- #
# Module-header + closed-enum guards
# --------------------------------------------------------------------------- #


def test_module_must_not_import_future_annotations() -> None:
    """Standing-offer §30 — ``operator_routes.py`` MUST OMIT
    ``from __future__ import annotations`` (FastAPI closure-cell resolution)."""
    tree = ast.parse(pathlib.Path(operator_routes.__file__).read_text())
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            for alias_node in node.names:
                assert alias_node.name != "annotations", (
                    "operator_routes.py MUST OMIT `from __future__ import annotations`"
                )


def test_install_refusal_reason_closed_enum_count() -> None:
    """The route-owned ``InstallRefusalReason`` closed-enum count is pinned via
    ``typing.get_args`` (NOT regex — comment tokens inside ``Literal[...]``
    would over-count per ``[[feedback_count_enum_values_via_ast_not_regex]]``)."""
    import typing

    values = set(typing.get_args(operator_routes.InstallRefusalReason))
    # 9 install reasons + 8 disable/revoke analogues = 17.
    assert len(values) == operator_routes._INSTALL_REFUSAL_REASON_COUNT
    assert operator_routes._INSTALL_REFUSAL_REASON_COUNT == 17
    for reason in (
        "install_plugin_registry_unavailable",
        "install_pack_not_registered",
        "install_runtime_config_missing",
        "install_runtime_config_incomplete",
        "install_runtime_config_vault_ref_unresolved",
        "install_materialize_failed",
        "install_activation_failed",
        "install_transition_failed",
        "install_compensation_failed",
        "disable_runtime_config_missing",
        "disable_transition_failed",
        "disable_compensation_failed",
        "disable_status_write_failed",
        "revoke_runtime_config_missing",
        "revoke_transition_failed",
        "revoke_compensation_failed",
        "revoke_status_write_failed",
    ):
        assert reason in values, f"{reason} missing from InstallRefusalReason"


def test_factory_accepts_m4_dependencies() -> None:
    """The extended factory accepts the 2 body-time M4 params AND stays
    backward-compatible (``build_operator_routes(store=...)`` alone works so the
    pre-Task-7 composition root + the existing suite keep passing). The registry
    is NOT a factory param (request-time gate) — so it is absent here."""
    from fastapi import APIRouter

    class _Stub: ...

    assert isinstance(build_operator_routes(store=_Stub()), APIRouter)  # type: ignore[arg-type]
    assert isinstance(
        build_operator_routes(
            store=_Stub(),  # type: ignore[arg-type]
            materializer=_StubMaterializer(),
            config_store=_Stub(),  # type: ignore[arg-type]
        ),
        APIRouter,
    )


def test_partial_m4_wiring_raises_value_error() -> None:
    """P3 (all-2-or-none) — a PARTIAL M4 body-time wiring (exactly ONE of
    ``materializer`` / ``config_store`` present) is a mis-configuration that
    would SILENTLY bypass the M4 install materialization gates on the hardened
    install route, so ``build_operator_routes`` FAILS FAST with ValueError. Only
    both (saga) + neither (pre-M4 backward-compat) are valid shapes (both pinned
    by ``test_factory_accepts_m4_dependencies``). The registry is excluded (it is
    a request-time gate, not a body-time dep)."""

    class _Stub: ...

    # materializer only (1 of 2) → ValueError.
    with pytest.raises(ValueError, match="BOTH wired or BOTH absent"):
        build_operator_routes(store=_Stub(), materializer=_StubMaterializer())  # type: ignore[arg-type]
    # config_store only (1 of 2) → ValueError.
    with pytest.raises(ValueError, match="BOTH wired or BOTH absent"):
        build_operator_routes(
            store=_Stub(),  # type: ignore[arg-type]
            config_store=_Stub(),  # type: ignore[arg-type]
        )


# --------------------------------------------------------------------------- #
# Install — happy path (REAL materializer → derived rows land)
# --------------------------------------------------------------------------- #


class TestInstallSagaHappyPath:
    async def test_install_after_configure_materializes_and_installs(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """install after configure → derived override + allow-list rows present
        + ``activation_status == active`` + state ``installed``."""
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 200, response.text
        assert response.json()["state"] == "installed"

        # Derived rows landed (the exposure).
        override = await override_store.get(tenant_id=_TENANT, pack_id=str(record.id))
        assert override == _OVERRIDE_URL
        allow = await allowlist_store.get_allowlist(tenant_id=_TENANT)
        assert frozenset(_DESIRED_IPS) <= allow

        # Desired record is now active.
        cfg = await config_store.get(tenant_id=_TENANT, pack_id=str(record.id))
        assert cfg is not None and cfg.activation_status == "active"

        # Lifecycle state committed.
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "installed"

    async def test_reinstall_from_disabled_rematerializes(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """The ADR-012 multi-from ``disabled → installed`` extension — a
        disabled pack (config marked disabled, no derived rows) re-installs →
        re-materialized (override + allow-list back) + active + installed."""
        # Walk to installed via the real store, then disable it (state only).
        record = await _seed_installed_via_store(store)
        await _write_config(config_store, record=record)
        await config_store.set_activation_status(
            tenant_id=_TENANT,
            pack_id=str(record.id),
            status="disabled",
            actor_subject="op@bank",
            actor_type="human",
            request_id=f"dis-{record.id.hex[:8]}",
        )
        await store.transition(
            pack_id=record.id,
            transition="disable",
            actor_id="op@bank",
            tenant_id=_TENANT,
            evidence_pointer=None,
            request_id=f"disx-{record.id.hex[:8]}",
        )
        # Precondition: no derived rows for the pack yet.
        assert await override_store.get(tenant_id=_TENANT, pack_id=str(record.id)) is None

        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 200, response.text
        assert response.json()["state"] == "installed"
        assert await override_store.get(tenant_id=_TENANT, pack_id=str(record.id)) == _OVERRIDE_URL
        cfg = await config_store.get(tenant_id=_TENANT, pack_id=str(record.id))
        assert cfg is not None and cfg.activation_status == "active"


# --------------------------------------------------------------------------- #
# Install — gate negatives (each → exact 409 reason + ZERO derived rows +
# NO lifecycle transition committed)
# --------------------------------------------------------------------------- #


class TestInstallGateNegatives:
    async def test_gate2_not_boot_registered(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Gate 2 — the pack's ``pack_id`` is NOT among the registry's
        registered candidates → 409 ``install_pack_not_registered``, no writes."""
        import logging

        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry(("some-other-pack",)),  # NOT this pack
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "install_pack_not_registered"
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "allow_listed"  # no transition
        refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.install_refused"
        ]
        assert len(refused) == 1
        assert refused[0].reason == "install_pack_not_registered"  # type: ignore[attr-defined]

    async def test_gate3_runtime_config_missing(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """Gate 3 — NO runtime-config record for the pack → 409
        ``install_runtime_config_missing``, no writes, no transition."""
        record = await _seed_allow_listed(store)
        # NO _write_config.
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "install_runtime_config_missing"
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "allow_listed"

    async def test_gate3_runtime_config_incomplete_missing_oauth_ref(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """Gate 3 — config present but ``oauth_credential_ref is None`` → 409
        ``install_runtime_config_incomplete`` BEFORE materialize runs."""
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record, oauth_ref=None)  # incomplete
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "install_runtime_config_incomplete"
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "allow_listed"

    async def test_gate4_materialize_rejected_vault_ref_unresolved(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """Materialize (A) raises ``MaterializeRejected`` (Vault ref unresolvable)
        AFTER the pack has already transitioned to ``installed`` (B is FIRST under
        the transition-first order) → the failure compensates FORWARD to a
        fail-closed ``disabled`` end state: 409
        ``install_runtime_config_vault_ref_unresolved`` + final state ``disabled``
        + config ``disabled`` + ZERO derived rows. Uses a REAL materializer whose
        stub vault resolves NOTHING (so the read-only validate pass refuses before
        any derived write)."""
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        empty_vault_materializer = RuntimeConfigMaterializer(
            override_store=override_store,
            allowlist_store=allowlist_store,
            config_store=config_store,
            vault_reader=_StubVault({}),  # nothing resolves
        )
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=empty_vault_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "install_runtime_config_vault_ref_unresolved"
        # Fail-CLOSED compensation: the pack transitioned to installed first, so
        # the materialize rejection compensates FORWARD to disabled (never
        # callable-but-not-installed).
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "disabled"
        # Config flipped to disabled (not active, not installed).
        cfg = await config_store.get(tenant_id=_TENANT, pack_id=str(record.id))
        assert cfg is not None and cfg.activation_status == "disabled"

    async def test_gate1_install_from_draft_refused_before_materialize(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """Gate 1 (lifecycle dry-run) — install on a draft pack refuses 409 with
        the lifecycle reason BEFORE any materialize call (materialize NOT
        invoked, zero derived rows)."""
        now = datetime.now(UTC)
        record = PackRecord(
            id=uuid.uuid4(),
            kind="tool",
            pack_id="cognic-tool-oracle-schema",
            display_name="Oracle Schema",
            state="draft",
            manifest_digest=b"\x01" * 32,
            signed_artefact_digest=b"\x02" * 32,
            sbom_pointer=None,
            tenant_id=_TENANT,
            created_by="bob@bank.example",
            last_actor="bob@bank.example",
            created_at=now,
            updated_at=now,
        )
        await store.save_draft(record)
        mat = _StubMaterializer()
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "lifecycle_transition_invalid_state_pair"
        assert mat.materialize_calls == [], "materialize MUST NOT run on a gate-1 refusal"
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )


# --------------------------------------------------------------------------- #
# Install — gate 2 registry is a REQUEST-TIME gate (ADR-026 D6 option B): read
# from app.state.plugin_registry per-request, NOT closed over at factory time.
# --------------------------------------------------------------------------- #


class TestInstallRegistryRequestTimeGate:
    """M4 gate 2 reads the plugin registry at REQUEST time from
    ``app.state.plugin_registry`` — the lifespan populates it AFTER the operator
    router mounts at body time. Pins: (1) the read is request-time (a value set
    AFTER app build is honoured); (2) a ``None`` registry refuses fail-closed 503
    ``install_plugin_registry_unavailable`` (infra), DISTINCT from (3) a
    populated-but-empty registry's 409 ``install_pack_not_registered`` (trust)."""

    async def test_gate2_registry_read_at_request_time_not_factory_time(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """The app is built with ``plugin_registry=None`` (so a factory-time
        closure would capture None → 503). Setting ``app.state.plugin_registry``
        to a registry CARRYING the pack AFTER build — right before the request —
        makes gate 2 PASS (install 200). Proves the registry is read per-request,
        not closed over at mount time."""
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        app = _build_app(
            actor=_make_operator_actor(),
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=None,  # app.state.plugin_registry = None after the lifespan
        )
        with TestClient(app) as client:
            # Populate the registry AFTER the lifespan set it None — the
            # request-time read must observe THIS value (a factory closure would
            # have captured the None and refused 503).
            app.state.plugin_registry = _FakeRegistry((record.pack_id,))
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 200, response.text
        assert response.json()["state"] == "installed"

    async def test_gate2_registry_unavailable_refuses_503_fail_closed(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """``app.state.plugin_registry is None`` (boot trust-registration failed
        / not populated) → gate 2 refuses fail-CLOSED 503
        ``install_plugin_registry_unavailable`` (infra), DISTINCT from the 409
        trust refusal. No writes, no transition."""
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        app = _build_app(
            actor=_make_operator_actor(),
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=None,  # → app.state.plugin_registry = None
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 503
        assert response.json()["detail"]["reason"] == "install_plugin_registry_unavailable"
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "allow_listed"  # no transition

    async def test_gate2_empty_registry_refuses_pack_not_registered(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """A populated-but-EMPTY registry (present, zero candidates) → gate 2
        refuses 409 ``install_pack_not_registered`` (trust), NOT the 503 infra
        reason — the registry IS available, the pack is just not boot-trusted."""
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        app = _build_app(
            actor=_make_operator_actor(),
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry(()),  # present but empty
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "install_pack_not_registered"
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )


# --------------------------------------------------------------------------- #
# Install — compensation (mid-saga failure → retract / revert)
# --------------------------------------------------------------------------- #


class TestInstallCompensation:
    async def test_activation_failure_retracts_and_leaves_non_active(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """B (transition to installed) + A (materialize) succeed, but the LAST
        step C (``set_activation_status`` to ``active``) raises → the post-
        transition failure compensates FORWARD to a fail-closed ``disabled`` end
        state: retract (un-expose) runs → final state ``disabled`` + config
        ``disabled`` + ZERO derived rows → 502 ``install_activation_failed``."""
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()  # materialize succeeds
        failing_cfg = _FailingActivationConfigStore(config_store)
        # Fail the C write; the compensation set-disabled write still succeeds.
        failing_cfg.fail_on_status = "active"
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=mat,
            config_store=failing_cfg,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 502
        assert response.json()["detail"]["reason"] == "install_activation_failed"
        # Forward-to-disabled compensation: retract (un-expose) ran exactly once.
        assert len(mat.retract_calls) == 1
        assert mat.retract_calls[0]["pack_id"] == str(record.id)
        # (Stub materialize doesn't write derived rows; assert the real config
        # was left DISABLED + the lifecycle was compensated FORWARD to disabled.)
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )
        cfg = await config_store.get(tenant_id=_TENANT, pack_id=str(record.id))
        assert cfg is not None and cfg.activation_status == "disabled"
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "disabled"

    async def test_transition_failure_first_no_compensation_pack_unchanged(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """B (transition to installed) is FIRST under the transition-first order.
        A generic B failure needs NO compensation (nothing was written before it):
        materialize is NEVER called, the pack is unchanged (``allow_listed``,
        config still ``configured``), ZERO derived rows → 502
        ``install_transition_failed``."""

        class _TransitionFailStore:
            """Delegates ``load`` to the real store but raises a generic error
            from ``transition`` (a non-lifecycle/non-notfound failure → 502)."""

            def __init__(self, real: PackRecordStore) -> None:
                self._real = real

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                return await self._real.load(pack_id)

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise RuntimeError("injected transition failure")

        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()  # must never be touched
        fail_store: PackRecordStore = _TransitionFailStore(store)  # type: ignore[assignment]
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=fail_store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 502
        assert response.json()["detail"]["reason"] == "install_transition_failed"
        # B is FIRST → no writes happened before it → NO compensation, and
        # materialize (the exposure) was never reached.
        assert mat.materialize_calls == [], "materialize MUST NOT run after a B-first fail"
        assert mat.retract_calls == [], "no compensation retract on a B-first transition fail"
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )
        # Pack unchanged (the fail_store never mutated it; config never touched).
        cfg = await config_store.get(tenant_id=_TENANT, pack_id=str(record.id))
        assert cfg is not None and cfg.activation_status == "configured"
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "allow_listed"

    async def test_transition_lifecycle_refused_is_409_race(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """The B-step ``LifecycleTransitionRefused`` race (gate 1 passed but the
        state changed under a concurrent op). B is FIRST under the transition-
        first order → 409 with the lifecycle reason, NO compensation, materialize
        never reached."""
        from cognic_agentos.packs.lifecycle import LifecycleTransitionRefused

        class _LifecycleRefuseStore:
            def __init__(self, real: PackRecordStore) -> None:
                self._real = real

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                return await self._real.load(pack_id)

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise LifecycleTransitionRefused("lifecycle_transition_double_install")

        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        fail_store: PackRecordStore = _LifecycleRefuseStore(store)  # type: ignore[assignment]
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=fail_store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "lifecycle_transition_double_install"
        # B FIRST → no writes, no compensation, materialize never reached.
        assert mat.materialize_calls == []
        assert mat.retract_calls == []

    async def test_transition_pack_not_found_is_404(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """The B-step ``PackNotFound`` race. B is FIRST under the transition-first
        order → 404 ``pack_not_found``, NO compensation, materialize never
        reached."""

        class _NotFoundStore:
            def __init__(self, real: PackRecordStore) -> None:
                self._real = real

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                return await self._real.load(pack_id)

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise PackNotFound(kwargs["pack_id"])

        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        fail_store: PackRecordStore = _NotFoundStore(store)  # type: ignore[assignment]
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=fail_store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "pack_not_found"
        # B FIRST → no writes, no compensation, materialize never reached.
        assert mat.materialize_calls == []
        assert mat.retract_calls == []

    async def test_compensation_retract_itself_raises_is_500_fail_loud(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """B + A succeed, the LAST step C (``set_activation_status`` → ``active``)
        raises, and the forward-to-disabled compensation's FIRST step (retract)
        ITSELF raises → 500 ``install_compensation_failed`` + a fail-loud
        ``portal.packs.install_compensation_failed`` log carrying pack_id +
        both error strings."""
        import logging

        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        mat.retract_raises = RuntimeError("retract exploded")  # compensation fails
        failing_cfg = _FailingActivationConfigStore(config_store)
        failing_cfg.fail_on_status = "active"  # trigger the C failure → compensation → retract
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=mat,
            config_store=failing_cfg,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 500
        assert response.json()["detail"]["reason"] == "install_compensation_failed"
        comp = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER
            and r.message == "portal.packs.install_compensation_failed"
        ]
        assert len(comp) == 1
        assert comp[0].pack_id == str(record.id)  # type: ignore[attr-defined]

    async def test_install_materialize_failure_leaves_pack_not_callable_and_disabled(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """**Fail-CLOSED pin (the transition-first invariant)** — after a post-
        transition materialize (A) failure, the pack is NOT callable (ZERO derived
        override + ZERO allow-list rows) AND the config is NOT active (it is
        ``disabled``) AND ``packs.state == "disabled"``. Under the transition-
        first order the pack records ``installed`` BEFORE it is exposed, so a
        materialize failure can only leave it installed-then-compensated-to-
        disabled (fail-closed / not-callable), NEVER callable-but-not-installed."""
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        mat.materialize_raises = RuntimeError("materialize mutator exploded post-transition")
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 502
        assert response.json()["detail"]["reason"] == "install_materialize_failed"
        # NOT callable — zero derived override + zero allow-list rows.
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )
        # Config NOT active (compensated FORWARD to disabled).
        cfg = await config_store.get(tenant_id=_TENANT, pack_id=str(record.id))
        assert cfg is not None and cfg.activation_status != "active"
        assert cfg.activation_status == "disabled"
        # Lifecycle fail-closed at disabled (never callable-but-not-installed).
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "disabled"


# --------------------------------------------------------------------------- #
# Disable saga — retract-FIRST then govern; compensation on post-retract failure
# --------------------------------------------------------------------------- #


class TestDisableSaga:
    async def test_disable_retracts_then_transitions(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """disable on an installed+active+materialized pack → retract removes the
        derived rows → state ``disabled`` + ``activation_status == disabled``."""
        # Bring the pack to a real installed+active+materialized posture first
        # (via the install saga).
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        install_app = _build_app(
            actor=_make_operator_actor(),
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(install_app) as client:
            assert client.post(f"/api/v1/packs/{record.id}/install").status_code == 200
        assert await override_store.get(tenant_id=_TENANT, pack_id=str(record.id)) == _OVERRIDE_URL

        # Now disable.
        with TestClient(install_app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")

        assert response.status_code == 200, response.text
        assert response.json()["state"] == "disabled"
        # Derived rows gone (un-exposed).
        assert await override_store.get(tenant_id=_TENANT, pack_id=str(record.id)) is None
        allow = await allowlist_store.get_allowlist(tenant_id=_TENANT)
        assert not (allow & frozenset(_DESIRED_IPS))
        cfg = await config_store.get(tenant_id=_TENANT, pack_id=str(record.id))
        assert cfg is not None and cfg.activation_status == "disabled"

    async def test_disable_runtime_config_missing_is_409(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """A disabled/revoked pack with NO runtime-config record is a bug —
        handled fail-closed as 409 ``disable_runtime_config_missing``."""
        record = await _seed_installed_via_store(store)  # installed, NO config written
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "disable_runtime_config_missing"
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "installed"  # no transition

    async def test_disable_transition_failure_rematerializes_to_stay_callable(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """disable retracts FIRST, then ``store.transition`` fails → the handler
        RE-MATERIALIZES (compensation) so the pack is left callable rather than
        silently un-exposed-but-still-installed → 502 ``disable_transition_failed``.
        Asserts the re-materialize (a second materialize call) ran."""

        class _TransitionFailStore:
            def __init__(self, real: PackRecordStore) -> None:
                self._real = real

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                return await self._real.load(pack_id)

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise RuntimeError("injected disable transition failure")

        record = await _seed_installed_via_store(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        fail_store: PackRecordStore = _TransitionFailStore(store)  # type: ignore[assignment]
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=fail_store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")

        assert response.status_code == 502
        assert response.json()["detail"]["reason"] == "disable_transition_failed"
        # retract ran FIRST (un-expose), then re-materialize compensation.
        assert len(mat.retract_calls) == 1
        assert len(mat.materialize_calls) == 1, (
            "disable transition failure MUST re-materialize to keep the pack callable"
        )

    async def test_revoke_transition_failure_rematerializes_to_stay_callable(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """revoke retracts FIRST, then ``store.transition`` fails (a generic,
        non-lifecycle error) → the handler RE-MATERIALIZES (compensation) and
        returns 502 ``revoke_transition_failed`` — the per-verb reason, NOT the
        ``install_`` one (the P2 wire-contract fix). Asserts the re-materialize ran."""

        class _TransitionFailStore:
            def __init__(self, real: PackRecordStore) -> None:
                self._real = real

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                return await self._real.load(pack_id)

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise RuntimeError("injected revoke transition failure")

        record = await _seed_installed_via_store(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        fail_store: PackRecordStore = _TransitionFailStore(store)  # type: ignore[assignment]
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=fail_store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")

        assert response.status_code == 502
        assert response.json()["detail"]["reason"] == "revoke_transition_failed"
        # retract ran FIRST (un-expose), then re-materialize compensation.
        assert len(mat.retract_calls) == 1
        assert len(mat.materialize_calls) == 1, (
            "revoke transition failure MUST re-materialize to keep the pack callable"
        )

    async def test_disable_compensation_rematerialize_raises_is_500(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """If the disable compensation re-materialize ITSELF raises → 500
        ``disable_compensation_failed`` (fail loud)."""

        class _TransitionFailStore:
            def __init__(self, real: PackRecordStore) -> None:
                self._real = real

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                return await self._real.load(pack_id)

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise RuntimeError("injected disable transition failure")

        record = await _seed_installed_via_store(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        mat.materialize_raises = RuntimeError("re-materialize exploded")
        fail_store: PackRecordStore = _TransitionFailStore(store)  # type: ignore[assignment]
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=fail_store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")

        assert response.status_code == 500
        assert response.json()["detail"]["reason"] == "disable_compensation_failed"


# --------------------------------------------------------------------------- #
# Revoke saga — retract + terminal; re-install refused after revoke
# --------------------------------------------------------------------------- #


class TestRevokeSaga:
    async def test_revoke_retracts_and_terminal(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """revoke on an installed+active+materialized pack → retract removes
        derived rows → state ``revoked`` + ``activation_status == revoked``."""
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        app = _build_app(
            actor=_make_operator_actor(),
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            assert client.post(f"/api/v1/packs/{record.id}/install").status_code == 200
            response = client.post(f"/api/v1/packs/{record.id}/revoke")

        assert response.status_code == 200, response.text
        assert response.json()["state"] == "revoked"
        assert await override_store.get(tenant_id=_TENANT, pack_id=str(record.id)) is None
        allow = await allowlist_store.get_allowlist(tenant_id=_TENANT)
        assert not (allow & frozenset(_DESIRED_IPS))
        cfg = await config_store.get(tenant_id=_TENANT, pack_id=str(record.id))
        assert cfg is not None and cfg.activation_status == "revoked"

    async def test_revoke_from_disabled_leg(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """The multi-from ``disabled → revoked`` leg still works under the M4
        saga (retract on an already-un-exposed pack is a no-op)."""
        record = await _seed_installed_via_store(store)
        await _write_config(config_store, record=record)
        await config_store.set_activation_status(
            tenant_id=_TENANT,
            pack_id=str(record.id),
            status="disabled",
            actor_subject="op@bank",
            actor_type="human",
            request_id=f"dis-{record.id.hex[:8]}",
        )
        await store.transition(
            pack_id=record.id,
            transition="disable",
            actor_id="op@bank",
            tenant_id=_TENANT,
            evidence_pointer=None,
            request_id=f"disx-{record.id.hex[:8]}",
        )
        app = _build_app(
            actor=_make_operator_actor(),
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")

        assert response.status_code == 200, response.text
        assert response.json()["state"] == "revoked"

    async def test_revoked_pack_cannot_reinstall_gate1(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """After revoke (terminal), a re-install is refused at gate 1 (the
        lifecycle dry-run) with the lifecycle reason — materialize never runs."""
        record = await _seed_installed_via_store(store)
        await _write_config(config_store, record=record)
        await config_store.set_activation_status(
            tenant_id=_TENANT,
            pack_id=str(record.id),
            status="revoked",
            actor_subject="op@bank",
            actor_type="human",
            request_id=f"rev-{record.id.hex[:8]}",
        )
        await store.transition(
            pack_id=record.id,
            transition="revoke",
            actor_id="op@bank",
            tenant_id=_TENANT,
            evidence_pointer=None,
            request_id=f"revx-{record.id.hex[:8]}",
        )
        app = _build_app(
            actor=_make_operator_actor(),
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 409
        # revoked → installed is not a legal install pair.
        assert response.json()["detail"]["reason"] == "lifecycle_transition_invalid_state_pair"
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )

    async def test_revoke_runtime_config_missing_is_409(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
    ) -> None:
        """A pack with NO runtime-config record → 409
        ``revoke_runtime_config_missing`` (fail-closed)."""
        record = await _seed_installed_via_store(store)  # installed, NO config
        app = _build_app(
            actor=_make_operator_actor(),
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "revoke_runtime_config_missing"
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "installed"


# --------------------------------------------------------------------------- #
# Backward-compat — the None (pre-Task-7) path is the pure delegate-to-storage
# behavior the existing suite exercises.
# --------------------------------------------------------------------------- #


class TestBackwardCompatNoM4Deps:
    async def test_install_without_m4_deps_is_plain_transition(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
    ) -> None:
        """When materializer/config_store/registry are all None (the
        composition root before Task 7 wires them), install is the pre-M4 plain
        ``store.transition`` — no gates, no materialize, no derived rows."""
        record = await _seed_allow_listed(store)
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor, store=store, materializer=None, config_store=None, registry=None
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 200, response.text
        assert response.json()["state"] == "installed"
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )


# --------------------------------------------------------------------------- #
# Install — remaining compensation branches (A-step mid-materialize generic
# failure; B-step compensation-itself-raises). CC coverage floor.
# --------------------------------------------------------------------------- #


class TestInstallCompensationBranches:
    async def test_materialize_generic_failure_cleanup_retracts_502(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A generic (non-``MaterializeRejected``) failure MID-materialize (A),
        AFTER B transitioned the pack to ``installed`` → the post-transition
        failure compensates FORWARD to a fail-closed ``disabled`` end state
        (retract un-expose + ``disabled`` transition + config ``disabled``) → 502
        ``install_materialize_failed`` + final state ``disabled`` + ZERO derived
        rows + ONE ``portal.packs.install_refused``."""
        import logging

        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        mat.materialize_raises = RuntimeError("mid-materialize mutator exploded")
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 502
        assert response.json()["detail"]["reason"] == "install_materialize_failed"
        assert len(mat.retract_calls) == 1, "cleanup-retract MUST run after a mid-materialize fault"
        refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.install_refused"
        ]
        assert len(refused) == 1
        assert refused[0].reason == "install_materialize_failed"  # type: ignore[attr-defined]
        # Forward-to-disabled compensation: state + config disabled, zero derived.
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "disabled"
        cfg = await config_store.get(tenant_id=_TENANT, pack_id=str(record.id))
        assert cfg is not None and cfg.activation_status == "disabled"

    async def test_materialize_failure_then_cleanup_retract_raises_500(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """B succeeds, a generic materialize (A) failure follows, and the forward-
        to-disabled compensation's FIRST step (retract) ITSELF raises → 500
        ``install_compensation_failed`` (fail loud)."""
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        mat.materialize_raises = RuntimeError("mid-materialize exploded")
        mat.retract_raises = RuntimeError("cleanup retract exploded")
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 500
        assert response.json()["detail"]["reason"] == "install_compensation_failed"

    async def test_compensation_disable_transition_raises_500(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """Under the transition-first order B has no compensation, so the
        "compensation itself raises" branch is exercised via a compensation step
        OTHER than retract: B (transition to ``installed``) succeeds → A
        (materialize) fails generic → the forward-to-disabled compensation runs
        retract (succeeds) then the ``installed → disabled`` transition INSIDE
        compensation raises → 500 ``install_compensation_failed`` (fail loud)."""

        class _InstallOkDisableFailStore:
            """``transition("install", ...)`` delegates to the real store; the
            compensation's ``transition("disable", ...)`` raises."""

            def __init__(self, real: PackRecordStore) -> None:
                self._real = real

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                return await self._real.load(pack_id)

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                if kwargs.get("transition") == "disable":
                    raise RuntimeError("compensation disable transition exploded")
                return await self._real.transition(**kwargs)

        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        mat.materialize_raises = RuntimeError("post-transition materialize exploded")
        fail_store: PackRecordStore = _InstallOkDisableFailStore(store)  # type: ignore[assignment]
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=fail_store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")

        assert response.status_code == 500
        assert response.json()["detail"]["reason"] == "install_compensation_failed"
        # retract (the first compensation step) ran before the disable transition raised.
        assert len(mat.retract_calls) == 1


# --------------------------------------------------------------------------- #
# Disable/revoke — remaining compensation branches (retract-FIRST failure;
# post-retract PackNotFound / LifecycleTransitionRefused race after re-materialize).
# --------------------------------------------------------------------------- #


class TestUnexposeSagaBranches:
    async def test_disable_retract_first_failure_is_500_compensation(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """The disable retract-FIRST leg raising → 500
        ``disable_compensation_failed`` (nothing else attempted; the transition
        never runs)."""
        record = await _seed_installed_via_store(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        mat.retract_raises = RuntimeError("retract-first exploded")
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")

        assert response.status_code == 500
        assert response.json()["detail"]["reason"] == "disable_compensation_failed"
        # The transition never ran — state unchanged.
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "installed"

    async def test_disable_post_retract_pack_not_found_is_404(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """disable retracts, then ``store.transition`` raises ``PackNotFound``
        (race) → re-materialize compensation → 404 ``pack_not_found``."""

        class _NotFoundStore:
            def __init__(self, real: PackRecordStore) -> None:
                self._real = real

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                return await self._real.load(pack_id)

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise PackNotFound(kwargs["pack_id"])

        record = await _seed_installed_via_store(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        fail_store: PackRecordStore = _NotFoundStore(store)  # type: ignore[assignment]
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=fail_store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")

        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "pack_not_found"
        # retract (un-expose) + re-materialize (compensation) both ran.
        assert len(mat.retract_calls) == 1
        assert len(mat.materialize_calls) == 1

    async def test_disable_post_retract_lifecycle_refused_is_409(
        self,
        store: PackRecordStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """disable retracts, then ``store.transition`` raises
        ``LifecycleTransitionRefused`` (race) → re-materialize compensation →
        409 with the lifecycle reason."""
        from cognic_agentos.packs.lifecycle import LifecycleTransitionRefused

        class _RefuseStore:
            def __init__(self, real: PackRecordStore) -> None:
                self._real = real

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                return await self._real.load(pack_id)

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise LifecycleTransitionRefused("lifecycle_transition_disable_not_installed")

        record = await _seed_installed_via_store(store)
        await _write_config(config_store, record=record)
        mat = _StubMaterializer()
        fail_store: PackRecordStore = _RefuseStore(store)  # type: ignore[assignment]
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=fail_store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "lifecycle_transition_disable_not_installed"
        assert len(mat.materialize_calls) == 1  # re-materialize compensation ran

    async def test_revoke_idempotency_gate1_refuses_without_touching_derived(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        config_store: PackRuntimeConfigStore,
    ) -> None:
        """**Safety property** — re-revoke on an already-``revoked`` pack refuses
        at the un-expose saga's gate-1 dry-run (409
        ``lifecycle_transition_revoke_already_revoked``) WITHOUT retracting or
        re-materializing, so a terminal pack is never re-exposed by the
        compensation path (the reason the gate-1 dry-run runs BEFORE retract)."""
        record = await _seed_installed_via_store(store)
        await _write_config(config_store, record=record)
        # Drive the pack terminal (revoked) at both the store + config layers.
        await config_store.set_activation_status(
            tenant_id=_TENANT,
            pack_id=str(record.id),
            status="revoked",
            actor_subject="op@bank",
            actor_type="human",
            request_id=f"rev-{record.id.hex[:8]}",
        )
        await store.transition(
            pack_id=record.id,
            transition="revoke",
            actor_id="op@bank",
            tenant_id=_TENANT,
            evidence_pointer=None,
            request_id=f"revx-{record.id.hex[:8]}",
        )
        mat = _StubMaterializer()
        actor = _make_operator_actor()
        app = _build_app(
            actor=actor,
            store=store,
            materializer=mat,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")

        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == "lifecycle_transition_revoke_already_revoked"
        # Gate 1 refused BEFORE any materializer interaction — the terminal pack
        # is NOT re-exposed.
        assert mat.retract_calls == []
        assert mat.materialize_calls == []
        assert await override_store.get(tenant_id=_TENANT, pack_id=str(record.id)) is None

    async def test_disable_status_write_failure_after_transition_stays_fail_closed(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """**Fail-CLOSED pin (the retract-path invariant)** — a phase-B status
        write failure AFTER the lifecycle transition already committed does NOT
        re-materialize. Under the two-phase split the pack is left retracted
        (ZERO derived rows / not callable) with lifecycle ``disabled``; only the
        now-stale desired-config ``activation_status`` marker is unreconciled,
        surfaced fail-loud 500 ``disable_status_write_failed``. If phase B
        re-materialized (the fail-OPEN bug), the derived rows would be RESTORED
        while the lifecycle says ``disabled`` — callable-while-disabled.

        Uses the REAL materializer so ``_assert_no_derived_rows`` after the
        request IS the no-re-materialize proof: a re-materialize would have
        restored the override + allow-list IPs the retract removed."""
        import logging

        caplog.set_level(logging.ERROR, logger=_OPERATOR_ROUTES_LOGGER)
        # Bring the pack to installed+active+materialized (callable) via the saga.
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        install_app = _build_app(
            actor=_make_operator_actor(),
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(install_app) as client:
            assert client.post(f"/api/v1/packs/{record.id}/install").status_code == 200
        assert await override_store.get(tenant_id=_TENANT, pack_id=str(record.id)) == _OVERRIDE_URL

        # Disable via an app whose config store FAILS the phase-B "disabled"
        # write; the phase-A transition (on the real store) SUCCEEDS first.
        failing_cfg = _FailingActivationConfigStore(config_store)
        failing_cfg.fail_on_status = "disabled"
        disable_app = _build_app(
            actor=_make_operator_actor(),
            store=store,
            materializer=real_materializer,
            config_store=failing_cfg,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(disable_app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")

        assert response.status_code == 500
        assert response.json()["detail"]["reason"] == "disable_status_write_failed"
        # Fail-CLOSED: retract removed the derived rows and phase B did NOT
        # re-materialize (absence here IS the no-re-materialize proof).
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )
        # Lifecycle transition committed (disabled); the config marker is left
        # STALE ("active") — the exact drift the operator must reconcile.
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "disabled"
        cfg = await config_store.get(tenant_id=_TENANT, pack_id=str(record.id))
        assert cfg is not None and cfg.activation_status == "active"
        # Fail-loud phase-B status-write log emitted exactly once.
        logged = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER
            and r.message == "portal.packs.disable_status_write_failed"
        ]
        assert len(logged) == 1

    async def test_revoke_status_write_failure_after_transition_stays_fail_closed(
        self,
        store: PackRecordStore,
        override_store: MCPServerUrlOverrideStore,
        allowlist_store: MCPInternalHostAllowlistStore,
        config_store: PackRuntimeConfigStore,
        real_materializer: RuntimeConfigMaterializer,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Revoke analogue of the retract-path fail-CLOSED invariant — a phase-B
        status write failure AFTER the ``revoked`` transition committed does NOT
        re-materialize. The pack is left retracted (ZERO derived rows) + lifecycle
        ``revoked`` (terminal); the stale ``activation_status`` marker surfaces
        fail-loud 500 ``revoke_status_write_failed``. Callable-while-revoked (the
        fail-OPEN bug) is thereby unrepresentable."""
        import logging

        caplog.set_level(logging.ERROR, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_allow_listed(store)
        await _write_config(config_store, record=record)
        install_app = _build_app(
            actor=_make_operator_actor(),
            store=store,
            materializer=real_materializer,
            config_store=config_store,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(install_app) as client:
            assert client.post(f"/api/v1/packs/{record.id}/install").status_code == 200
        assert await override_store.get(tenant_id=_TENANT, pack_id=str(record.id)) == _OVERRIDE_URL

        failing_cfg = _FailingActivationConfigStore(config_store)
        failing_cfg.fail_on_status = "revoked"
        revoke_app = _build_app(
            actor=_make_operator_actor(),
            store=store,
            materializer=real_materializer,
            config_store=failing_cfg,
            registry=_FakeRegistry((record.pack_id,)),
        )
        with TestClient(revoke_app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")

        assert response.status_code == 500
        assert response.json()["detail"]["reason"] == "revoke_status_write_failed"
        # Fail-CLOSED: retracted + NOT re-materialized (terminal, not callable).
        await _assert_no_derived_rows(
            override_store=override_store, allowlist_store=allowlist_store, record=record
        )
        reloaded = await store.load(record.id)
        assert reloaded is not None and reloaded.state == "revoked"
        cfg = await config_store.get(tenant_id=_TENANT, pack_id=str(record.id))
        assert cfg is not None and cfg.activation_status == "active"
        logged = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER
            and r.message == "portal.packs.revoke_status_write_failed"
        ]
        assert len(logged) == 1
