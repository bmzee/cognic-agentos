"""M4 Task 1 — PackRuntimeConfigStore (desired runtime-config record) tests.

Storage tests run against the Alembic-MIGRATED DB (NOT ``_metadata.create_all``)
so the migration-only unique constraint + the genesis ``decision_history``
chain-head seed are exercised exactly as production sees them
(``[[feedback_storage_test_migrated_db_not_create_all]]``). Cross-tenant
negatives are driven explicitly; the reconfigure-while-active refusal + the ref
grammar + the not-found path carry the required negative-path coverage.
"""

import asyncio
from typing import Any, get_args

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.mcp_config.runtime_config import (
    PackRuntimeConfigRecord,
    PackRuntimeConfigStore,
    RuntimeConfigActivationStatus,
    RuntimeConfigNotFound,
    RuntimeConfigRefusalReason,
    RuntimeConfigRejected,
    _pack_runtime_config,
    _validate_opaque_ref,
)
from cognic_agentos.core.mcp_config.storage import MCPConfigRejected


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    # Migrated DB — genesis decision_history chain head is seeded by 0001.
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'runtimecfg.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    eng = create_async_engine(url)
    yield eng
    await eng.dispose()


@pytest.fixture
def store(engine: AsyncEngine) -> PackRuntimeConfigStore:
    return PackRuntimeConfigStore(engine)


async def _set_full_config(store: PackRuntimeConfigStore, *, request_id: str) -> None:
    await store.set_config(
        tenant_id="t1",
        pack_id="p1",
        server_url_override="http://10.42.0.7:8080/mcp",
        internal_host_allowlist=["10.42.0.7", "10.42.0.9"],
        oauth_credential_ref="secret/cognic/t1/mcp-oauth/10.42.0.7",
        as_allowlist_ref="secret/cognic/t1/mcp-as-allowlist",
        actor_subject="op@bank",
        actor_type="human",
        request_id=request_id,
    )


# --------------------------------------------------------------------------- #
# set_config / get round-trip
# --------------------------------------------------------------------------- #


async def test_set_config_then_get_round_trips_all_fields(store: PackRuntimeConfigStore) -> None:
    await _set_full_config(store, request_id="rc-set-1")
    rec = await store.get(tenant_id="t1", pack_id="p1")
    assert rec is not None
    assert isinstance(rec, PackRuntimeConfigRecord)
    assert rec.tenant_id == "t1"
    assert rec.pack_id == "p1"
    assert rec.server_url_override == "http://10.42.0.7:8080/mcp"
    assert rec.internal_host_allowlist == ("10.42.0.7", "10.42.0.9")
    assert rec.oauth_credential_ref == "secret/cognic/t1/mcp-oauth/10.42.0.7"
    assert rec.as_allowlist_ref == "secret/cognic/t1/mcp-as-allowlist"
    assert rec.activation_status == "configured"
    assert rec.generation == 1
    assert rec.set_by_actor == "op@bank"
    assert rec.last_request_id == "rc-set-1"
    assert rec.set_at is not None


async def test_get_absent_returns_none(store: PackRuntimeConfigStore) -> None:
    assert await store.get(tenant_id="t1", pack_id="never") is None


async def test_set_config_optional_fields_none_round_trip(
    store: PackRuntimeConfigStore,
) -> None:
    # A partial desired record (no override, empty allow-list, no refs) is valid —
    # install-time validates completeness, not this store.
    await store.set_config(
        tenant_id="t1",
        pack_id="p1",
        server_url_override=None,
        internal_host_allowlist=[],
        oauth_credential_ref=None,
        as_allowlist_ref=None,
        actor_subject="op@bank",
        actor_type="human",
        request_id="rc-set-partial",
    )
    rec = await store.get(tenant_id="t1", pack_id="p1")
    assert rec is not None
    assert rec.server_url_override is None
    assert rec.internal_host_allowlist == ()
    assert rec.oauth_credential_ref is None
    assert rec.as_allowlist_ref is None
    assert rec.activation_status == "configured"
    assert rec.generation == 1


async def test_second_set_config_bumps_generation(store: PackRuntimeConfigStore) -> None:
    await _set_full_config(store, request_id="rc-set-g1")
    await store.set_config(
        tenant_id="t1",
        pack_id="p1",
        server_url_override="http://10.42.0.8",
        internal_host_allowlist=["10.42.0.8"],
        oauth_credential_ref="secret/cognic/t1/mcp-oauth/10.42.0.8",
        as_allowlist_ref="secret/cognic/t1/mcp-as-allowlist",
        actor_subject="op2@bank",
        actor_type="human",
        request_id="rc-set-g2",
    )
    rec = await store.get(tenant_id="t1", pack_id="p1")
    assert rec is not None
    assert rec.generation == 2
    assert rec.activation_status == "configured"
    assert rec.server_url_override == "http://10.42.0.8"
    assert rec.internal_host_allowlist == ("10.42.0.8",)
    assert rec.set_by_actor == "op2@bank"


async def test_set_config_update_keeps_single_row(
    store: PackRuntimeConfigStore, engine: AsyncEngine
) -> None:
    await _set_full_config(store, request_id="rc-set-r1")
    await _set_full_config(store, request_id="rc-set-r2")
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_pack_runtime_config))).fetchall())
    assert len(rows) == 1  # UPDATE, not a second INSERT


async def test_set_config_cross_tenant_isolation(store: PackRuntimeConfigStore) -> None:
    await _set_full_config(store, request_id="rc-set-iso")
    # A DIFFERENT tenant reading the same pack_id gets None (cross-tenant deny).
    assert await store.get(tenant_id="t2", pack_id="p1") is None


# --------------------------------------------------------------------------- #
# Reconfigure refusals (active + terminal revoked) + the disabled re-config path
# --------------------------------------------------------------------------- #


async def test_set_config_while_active_refused(store: PackRuntimeConfigStore) -> None:
    await _set_full_config(store, request_id="rc-active-1")
    await store.set_activation_status(
        tenant_id="t1",
        pack_id="p1",
        status="active",
        actor_subject="op@bank",
        actor_type="human",
        request_id="rc-active-activate",
    )
    with pytest.raises(RuntimeConfigRejected) as exc:
        await _set_full_config(store, request_id="rc-active-reconfig")
    assert exc.value.reason == "runtime_config_reconfigure_while_active"
    # The record is unchanged — still active, generation 1.
    rec = await store.get(tenant_id="t1", pack_id="p1")
    assert rec is not None
    assert rec.activation_status == "active"
    assert rec.generation == 1


async def test_set_config_from_disabled_resets_to_configured(
    store: PackRuntimeConfigStore,
) -> None:
    await _set_full_config(store, request_id="rc-dis-1")
    await store.set_activation_status(
        tenant_id="t1",
        pack_id="p1",
        status="disabled",
        actor_subject="op@bank",
        actor_type="human",
        request_id="rc-dis-disable",
    )
    await _set_full_config(store, request_id="rc-dis-reconfig")
    rec = await store.get(tenant_id="t1", pack_id="p1")
    assert rec is not None
    assert rec.activation_status == "configured"
    assert rec.generation == 2


async def test_set_config_from_revoked_refused(
    store: PackRuntimeConfigStore,
) -> None:
    # revoke is terminal: the authoritative desired-state store HARD-REFUSES a
    # reconfigure of a revoked record (defence in depth with the lifecycle state
    # machine + the configure endpoint's lifecycle gate, M4 Tasks 3/5). A direct
    # store caller cannot resurrect a revoked record.
    await _set_full_config(store, request_id="rc-rev-1")
    await store.set_activation_status(
        tenant_id="t1",
        pack_id="p1",
        status="revoked",
        actor_subject="op@bank",
        actor_type="human",
        request_id="rc-rev-revoke",
    )
    with pytest.raises(RuntimeConfigRejected) as exc:
        await _set_full_config(store, request_id="rc-rev-reconfig")
    assert exc.value.reason == "runtime_config_reconfigure_while_revoked"
    # The record is unchanged — still revoked, generation 1.
    rec = await store.get(tenant_id="t1", pack_id="p1")
    assert rec is not None
    assert rec.activation_status == "revoked"
    assert rec.generation == 1


# --------------------------------------------------------------------------- #
# Grammar refusals (propagate as the sibling store's MCPConfigRejected)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ("https://10.42.0.7", "override_url_not_http"),
        ("http://8.8.8.8", "override_url_host_not_internal"),
        ("http://my-host", "override_url_host_not_ip_literal"),
        ("not a url", "override_url_malformed"),
    ],
)
async def test_set_config_invalid_server_url_override_refused(
    store: PackRuntimeConfigStore, engine: AsyncEngine, override: str, reason: str
) -> None:
    with pytest.raises(MCPConfigRejected) as exc:
        await store.set_config(
            tenant_id="t1",
            pack_id="p1",
            server_url_override=override,
            internal_host_allowlist=[],
            oauth_credential_ref=None,
            as_allowlist_ref=None,
            actor_subject="op@bank",
            actor_type="human",
            request_id="rc-bad-url",
        )
    assert exc.value.reason == reason
    # Rolled back: no record row, no chain row.
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_pack_runtime_config))).fetchall())
        chain = list((await conn.execute(select(_decision_history))).fetchall())
    assert rows == []
    assert chain == []


async def test_set_config_invalid_allowlist_entry_refused(
    store: PackRuntimeConfigStore, engine: AsyncEngine
) -> None:
    with pytest.raises(MCPConfigRejected) as exc:
        await store.set_config(
            tenant_id="t1",
            pack_id="p1",
            server_url_override=None,
            internal_host_allowlist=["10.42.0.7", "8.8.8.8"],  # second is public
            oauth_credential_ref=None,
            as_allowlist_ref=None,
            actor_subject="op@bank",
            actor_type="human",
            request_id="rc-bad-ip",
        )
    assert exc.value.reason == "allowlist_ip_hard_blocked"
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_pack_runtime_config))).fetchall())
    assert rows == []


@pytest.mark.parametrize("bad_ref", ["", "   "])
async def test_set_config_invalid_oauth_ref_refused(
    store: PackRuntimeConfigStore, bad_ref: str
) -> None:
    with pytest.raises(RuntimeConfigRejected) as exc:
        await store.set_config(
            tenant_id="t1",
            pack_id="p1",
            server_url_override=None,
            internal_host_allowlist=[],
            oauth_credential_ref=bad_ref,
            as_allowlist_ref=None,
            actor_subject="op@bank",
            actor_type="human",
            request_id="rc-bad-oauth",
        )
    assert exc.value.reason == "runtime_config_oauth_credential_ref_malformed"


async def test_set_config_invalid_as_ref_refused(store: PackRuntimeConfigStore) -> None:
    with pytest.raises(RuntimeConfigRejected) as exc:
        await store.set_config(
            tenant_id="t1",
            pack_id="p1",
            server_url_override=None,
            internal_host_allowlist=[],
            oauth_credential_ref=None,
            as_allowlist_ref="",
            actor_subject="op@bank",
            actor_type="human",
            request_id="rc-bad-as",
        )
    assert exc.value.reason == "runtime_config_as_allowlist_ref_malformed"


# --------------------------------------------------------------------------- #
# _validate_opaque_ref unit coverage (runtime-defense branches incl. non-str)
# --------------------------------------------------------------------------- #


def test_validate_opaque_ref_accepts_none_and_nonempty() -> None:
    _validate_opaque_ref(None, malformed_reason="runtime_config_oauth_credential_ref_malformed")
    _validate_opaque_ref(
        "secret/path", malformed_reason="runtime_config_oauth_credential_ref_malformed"
    )


@pytest.mark.parametrize("bad", ["", "   ", 123, b"bytes", ["list"]])
def test_validate_opaque_ref_rejects(bad: object) -> None:
    with pytest.raises(RuntimeConfigRejected) as exc:
        _validate_opaque_ref(bad, malformed_reason="runtime_config_as_allowlist_ref_malformed")
    assert exc.value.reason == "runtime_config_as_allowlist_ref_malformed"


# --------------------------------------------------------------------------- #
# set_activation_status
# --------------------------------------------------------------------------- #


async def test_set_activation_status_updates_status_not_generation(
    store: PackRuntimeConfigStore,
) -> None:
    await _set_full_config(store, request_id="rc-act-1")
    await store.set_activation_status(
        tenant_id="t1",
        pack_id="p1",
        status="active",
        actor_subject="installer@bank",
        actor_type="human",
        request_id="rc-act-activate",
    )
    rec = await store.get(tenant_id="t1", pack_id="p1")
    assert rec is not None
    assert rec.activation_status == "active"
    assert rec.generation == 1  # activation does NOT bump generation
    assert rec.set_by_actor == "installer@bank"
    assert rec.last_request_id == "rc-act-activate"


async def test_set_activation_status_unknown_status_refused(
    store: PackRuntimeConfigStore,
) -> None:
    await _set_full_config(store, request_id="rc-act-unk-1")
    with pytest.raises(RuntimeConfigRejected) as exc:
        await store.set_activation_status(
            tenant_id="t1",
            pack_id="p1",
            status="bogus",
            actor_subject="op@bank",
            actor_type="human",
            request_id="rc-act-unk",
        )
    assert exc.value.reason == "runtime_config_activation_status_unknown"


async def test_set_activation_status_on_missing_record_raises_not_found(
    store: PackRuntimeConfigStore,
) -> None:
    with pytest.raises(RuntimeConfigNotFound) as exc:
        await store.set_activation_status(
            tenant_id="t1",
            pack_id="never",
            status="active",
            actor_subject="op@bank",
            actor_type="human",
            request_id="rc-act-missing",
        )
    assert exc.value.tenant_id == "t1"
    assert exc.value.pack_id == "never"


# --------------------------------------------------------------------------- #
# Chain rows — exactly one per mutator + exact evidence-snapshot keyset
# --------------------------------------------------------------------------- #


async def test_set_config_appends_exactly_one_chain_row(
    store: PackRuntimeConfigStore, engine: AsyncEngine
) -> None:
    await _set_full_config(store, request_id="rc-chain-set")
    async with engine.connect() as conn:
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "mcp.runtime_config.set"
                    )
                )
            ).fetchall()
        )
    assert len(chain) == 1
    payload = chain[0].payload
    assert set(payload) == {
        "tenant_id",
        "pack_id",
        "server_url_override",
        "internal_host_allowlist",
        "oauth_credential_ref",
        "as_allowlist_ref",
        "activation_status",
        "generation",
        "actor_type",
        "actor_id",  # auto-merged by DecisionHistoryStore from actor_subject
    }
    assert payload["actor_type"] == "human"
    assert payload["actor_id"] == "op@bank"
    assert payload["activation_status"] == "configured"
    assert payload["generation"] == 1
    assert payload["internal_host_allowlist"] == ["10.42.0.7", "10.42.0.9"]
    assert payload["oauth_credential_ref"] == "secret/cognic/t1/mcp-oauth/10.42.0.7"
    assert list(chain[0].iso_controls) == ["ISO42001.A.5.31", "ISO42001.A.6.2.4"]
    assert chain[0].tenant_id == "t1"


async def test_set_activation_status_appends_exactly_one_chain_row(
    store: PackRuntimeConfigStore, engine: AsyncEngine
) -> None:
    await _set_full_config(store, request_id="rc-chain-act-set")
    await store.set_activation_status(
        tenant_id="t1",
        pack_id="p1",
        status="active",
        actor_subject="op@bank",
        actor_type="human",
        request_id="rc-chain-act",
    )
    async with engine.connect() as conn:
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "mcp.runtime_config.activation"
                    )
                )
            ).fetchall()
        )
    assert len(chain) == 1
    payload = chain[0].payload
    assert set(payload) == {
        "tenant_id",
        "pack_id",
        "status",
        "previous_status",
        "actor_type",
        "actor_id",
    }
    assert payload["status"] == "active"
    assert payload["previous_status"] == "configured"
    assert payload["actor_type"] == "human"


# --------------------------------------------------------------------------- #
# Closed-enum count guards (via typing.get_args — NOT regex)
# --------------------------------------------------------------------------- #


def test_activation_status_enum_is_closed_four_values() -> None:
    assert set(get_args(RuntimeConfigActivationStatus)) == {
        "configured",
        "active",
        "disabled",
        "revoked",
    }
    assert len(get_args(RuntimeConfigActivationStatus)) == 4


def test_refusal_reason_enum_is_closed_five_values() -> None:
    assert set(get_args(RuntimeConfigRefusalReason)) == {
        "runtime_config_reconfigure_while_active",
        "runtime_config_reconfigure_while_revoked",
        "runtime_config_oauth_credential_ref_malformed",
        "runtime_config_as_allowlist_ref_malformed",
        "runtime_config_activation_status_unknown",
    }
    assert len(get_args(RuntimeConfigRefusalReason)) == 5


# --------------------------------------------------------------------------- #
# list_for_tenant — tenant-scoped read of every config record (any status)
# --------------------------------------------------------------------------- #


async def test_list_for_tenant_empty_when_none(store: PackRuntimeConfigStore) -> None:
    assert await store.list_for_tenant(tenant_id="t1") == []


async def test_list_for_tenant_returns_all_records_any_status(
    store: PackRuntimeConfigStore,
) -> None:
    # p1 stays configured; p2 is flipped to active; p3 is revoked — list returns
    # all three regardless of activation_status (the materializer needs the union
    # of every record, then filters by status itself).
    await store.set_config(
        tenant_id="t1",
        pack_id="p1",
        server_url_override="http://10.42.0.7",
        internal_host_allowlist=["10.42.0.7"],
        oauth_credential_ref="secret/cognic/t1/oauth/p1",
        as_allowlist_ref="secret/cognic/t1/as",
        actor_subject="op@bank",
        actor_type="human",
        request_id="rc-list-p1",
    )
    await store.set_config(
        tenant_id="t1",
        pack_id="p2",
        server_url_override=None,
        internal_host_allowlist=["10.42.0.8"],
        oauth_credential_ref=None,
        as_allowlist_ref=None,
        actor_subject="op@bank",
        actor_type="human",
        request_id="rc-list-p2",
    )
    await store.set_activation_status(
        tenant_id="t1",
        pack_id="p2",
        status="active",
        actor_subject="op@bank",
        actor_type="human",
        request_id="rc-list-p2-active",
    )
    await store.set_config(
        tenant_id="t1",
        pack_id="p3",
        server_url_override=None,
        internal_host_allowlist=["10.42.0.9"],
        oauth_credential_ref=None,
        as_allowlist_ref=None,
        actor_subject="op@bank",
        actor_type="human",
        request_id="rc-list-p3",
    )
    await store.set_activation_status(
        tenant_id="t1",
        pack_id="p3",
        status="revoked",
        actor_subject="op@bank",
        actor_type="human",
        request_id="rc-list-p3-revoke",
    )

    records = await store.list_for_tenant(tenant_id="t1")
    assert all(isinstance(r, PackRuntimeConfigRecord) for r in records)
    by_pack = {r.pack_id: r for r in records}
    assert set(by_pack) == {"p1", "p2", "p3"}
    assert by_pack["p1"].activation_status == "configured"
    assert by_pack["p1"].server_url_override == "http://10.42.0.7"
    assert by_pack["p1"].internal_host_allowlist == ("10.42.0.7",)
    assert by_pack["p1"].oauth_credential_ref == "secret/cognic/t1/oauth/p1"
    assert by_pack["p2"].activation_status == "active"
    assert by_pack["p2"].internal_host_allowlist == ("10.42.0.8",)
    assert by_pack["p3"].activation_status == "revoked"


async def test_list_for_tenant_cross_tenant_isolation(
    store: PackRuntimeConfigStore,
) -> None:
    # tenant A has p1; tenant B has p2 — listing A returns ONLY p1.
    await store.set_config(
        tenant_id="tA",
        pack_id="p1",
        server_url_override=None,
        internal_host_allowlist=["10.42.0.7"],
        oauth_credential_ref=None,
        as_allowlist_ref=None,
        actor_subject="op@bank",
        actor_type="human",
        request_id="rc-iso-a",
    )
    await store.set_config(
        tenant_id="tB",
        pack_id="p2",
        server_url_override=None,
        internal_host_allowlist=["10.42.0.8"],
        oauth_credential_ref=None,
        as_allowlist_ref=None,
        actor_subject="op@bank",
        actor_type="human",
        request_id="rc-iso-b",
    )
    a_records = await store.list_for_tenant(tenant_id="tA")
    assert {r.pack_id for r in a_records} == {"p1"}
    b_records = await store.list_for_tenant(tenant_id="tB")
    assert {r.pack_id for r in b_records} == {"p2"}
