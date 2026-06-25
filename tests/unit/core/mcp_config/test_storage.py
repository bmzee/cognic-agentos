"""PR-2b-1 Task 1 — MCP override + internal-host allow-list store tests.

Storage tests run against the Alembic-MIGRATED DB (NOT ``_metadata.create_all``)
so the migration-only unique constraints + the genesis ``decision_history``
chain-head seed are exercised exactly as production sees them. Cross-tenant
negatives are driven explicitly (a tenant cannot read another tenant's override
or allow-list).
"""

import asyncio
import ipaddress
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.mcp_config.storage import (
    AllowlistEntryRow,
    MCPConfigRejected,
    MCPInternalHostAllowlistStore,
    MCPServerUrlOverrideStore,
    _mcp_internal_host_allowlist,
    _mcp_server_url_override,
    ip_passes_internal_floor,
    validate_allowlist_ip,
    validate_override_url,
)


@pytest.fixture
async def engine(tmp_path: Any) -> Any:
    # Migrated DB — genesis decision_history chain head is seeded by 0001.
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'mcpcfg.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    eng = create_async_engine(url)
    yield eng
    await eng.dispose()


@pytest.fixture
def override_store(engine: AsyncEngine) -> MCPServerUrlOverrideStore:
    return MCPServerUrlOverrideStore(engine)


@pytest.fixture
def allowlist_store(engine: AsyncEngine) -> MCPInternalHostAllowlistStore:
    return MCPInternalHostAllowlistStore(engine)


# --------------------------------------------------------------------------- #
# Override store
# --------------------------------------------------------------------------- #


async def test_set_override_then_get_returns_url(
    override_store: MCPServerUrlOverrideStore,
) -> None:
    await override_store.set_override(
        tenant_id="t1",
        pack_id="p1",
        server_url="http://10.42.0.7:8080/mcp",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-override-set-1",
    )
    assert await override_store.get(tenant_id="t1", pack_id="p1") == "http://10.42.0.7:8080/mcp"


async def test_clear_override_then_get_returns_none(
    override_store: MCPServerUrlOverrideStore,
) -> None:
    await override_store.set_override(
        tenant_id="t1",
        pack_id="p1",
        server_url="http://10.42.0.7",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-override-set-2",
    )
    await override_store.clear_override(
        tenant_id="t1",
        pack_id="p1",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-override-clear-2",
    )
    assert await override_store.get(tenant_id="t1", pack_id="p1") is None


async def test_clear_override_when_nothing_set_is_idempotent(
    override_store: MCPServerUrlOverrideStore, engine: AsyncEngine
) -> None:
    # Clearing a (tenant, pack) that was never set is idempotent: it still emits
    # a cleared chain row with previous_server_url=None, leaves zero override
    # rows, and does not raise (covers the row-absent arm of the precondition).
    await override_store.clear_override(
        tenant_id="t1",
        pack_id="never-set",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-override-clear-empty",
    )
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_mcp_server_url_override))).fetchall())
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "mcp.override.cleared"
                    )
                )
            ).fetchall()
        )
    assert rows == []
    assert len(chain) == 1
    assert chain[0].payload["previous_server_url"] is None


async def test_override_second_pack_and_cross_tenant_isolation(
    override_store: MCPServerUrlOverrideStore,
) -> None:
    await override_store.set_override(
        tenant_id="t1",
        pack_id="p1",
        server_url="http://10.42.0.7",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-override-set-iso1",
    )
    # A second (tenant, pack) is isolated (no leakage into p1's slot).
    await override_store.set_override(
        tenant_id="t1",
        pack_id="p2",
        server_url="http://10.42.0.9",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-override-set-iso2",
    )
    assert await override_store.get(tenant_id="t1", pack_id="p1") == "http://10.42.0.7"
    assert await override_store.get(tenant_id="t1", pack_id="p2") == "http://10.42.0.9"
    # A DIFFERENT tenant reading the same pack_id gets None (cross-tenant deny).
    assert await override_store.get(tenant_id="t2", pack_id="p1") is None


async def test_set_override_update_path_overwrites_existing(
    override_store: MCPServerUrlOverrideStore, engine: AsyncEngine
) -> None:
    await override_store.set_override(
        tenant_id="t1",
        pack_id="p1",
        server_url="http://10.42.0.7",
        actor_subject="op1",
        actor_type="human",
        request_id="mcp-override-set-a",
    )
    await override_store.set_override(
        tenant_id="t1",
        pack_id="p1",
        server_url="http://10.42.0.8",
        actor_subject="op2",
        actor_type="human",
        request_id="mcp-override-set-b",
    )
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_mcp_server_url_override))).fetchall())
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "mcp.override.set"
                    )
                )
            ).fetchall()
        )
    assert len(rows) == 1  # UPDATE, not a second INSERT
    assert rows[0].server_url_override == "http://10.42.0.8"
    assert rows[0].set_by_actor == "op2"
    assert rows[0].last_request_id == "mcp-override-set-b"
    assert len(chain) == 2
    second = max(chain, key=lambda r: r.sequence)
    assert second.payload["server_url"] == "http://10.42.0.8"
    assert second.payload["previous_server_url"] == "http://10.42.0.7"


async def test_set_override_chain_payload_exact_keyset(
    override_store: MCPServerUrlOverrideStore, engine: AsyncEngine
) -> None:
    await override_store.set_override(
        tenant_id="t1",
        pack_id="p1",
        server_url="http://10.42.0.7:8080/mcp",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-override-set-evidence",
    )
    async with engine.connect() as conn:
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "mcp.override.set"
                    )
                )
            ).fetchall()
        )
    assert len(chain) == 1
    payload = chain[0].payload
    assert set(payload) == {
        "tenant_id",
        "pack_id",
        "server_url",
        "previous_server_url",
        "actor_type",
        "actor_id",
    }
    assert payload["actor_type"] == "human"
    assert payload["actor_id"] == "op@bank"
    assert payload["server_url"] == "http://10.42.0.7:8080/mcp"
    assert payload["previous_server_url"] is None
    assert list(chain[0].iso_controls) == ["ISO42001.A.5.31", "ISO42001.A.6.2.4"]
    assert chain[0].tenant_id == "t1"


async def test_clear_override_chain_payload_exact_keyset(
    override_store: MCPServerUrlOverrideStore, engine: AsyncEngine
) -> None:
    await override_store.set_override(
        tenant_id="t1",
        pack_id="p1",
        server_url="http://10.42.0.7",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-override-set-c",
    )
    await override_store.clear_override(
        tenant_id="t1",
        pack_id="p1",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-override-clear-c",
    )
    async with engine.connect() as conn:
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "mcp.override.cleared"
                    )
                )
            ).fetchall()
        )
    assert len(chain) == 1
    payload = chain[0].payload
    assert set(payload) == {
        "tenant_id",
        "pack_id",
        "previous_server_url",
        "actor_type",
        "actor_id",
    }
    assert payload["actor_type"] == "human"
    assert payload["previous_server_url"] == "http://10.42.0.7"


async def test_set_override_bad_url_writes_zero_rows_zero_chain(
    override_store: MCPServerUrlOverrideStore, engine: AsyncEngine
) -> None:
    # Grammar enforced inside the precondition → the transaction rolls back:
    # no override row, no chain row.
    with pytest.raises(MCPConfigRejected) as exc:
        await override_store.set_override(
            tenant_id="t1",
            pack_id="p1",
            server_url="https://10.42.0.7",
            actor_subject="op@bank",
            actor_type="human",
            request_id="mcp-override-set-bad",
        )
    assert exc.value.reason == "override_url_not_http"
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_mcp_server_url_override))).fetchall())
        chain = list((await conn.execute(select(_decision_history))).fetchall())
    assert rows == []
    assert chain == []


# --------------------------------------------------------------------------- #
# Allow-list store
# --------------------------------------------------------------------------- #


async def test_add_ip_then_get_allowlist_contains(
    allowlist_store: MCPInternalHostAllowlistStore,
) -> None:
    await allowlist_store.add_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-allow-add-1",
    )
    assert await allowlist_store.get_allowlist(tenant_id="t1") == frozenset({"10.42.0.7"})


async def test_remove_ip_drops_entry(
    allowlist_store: MCPInternalHostAllowlistStore,
) -> None:
    await allowlist_store.add_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-allow-add-2",
    )
    await allowlist_store.remove_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-allow-rm-2",
    )
    assert await allowlist_store.get_allowlist(tenant_id="t1") == frozenset()


async def test_add_ip_update_path_idempotent_single_row(
    allowlist_store: MCPInternalHostAllowlistStore, engine: AsyncEngine
) -> None:
    # Re-adding the same (tenant, ip) hits the UPDATE branch (not a second
    # INSERT that would trip the unique constraint): one row, fresh actor +
    # request_id, two chain rows.
    await allowlist_store.add_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="op1",
        actor_type="human",
        request_id="mcp-allow-add-i1",
    )
    await allowlist_store.add_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="op2",
        actor_type="human",
        request_id="mcp-allow-add-i2",
    )
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_mcp_internal_host_allowlist))).fetchall())
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "mcp.allowlist.add"
                    )
                )
            ).fetchall()
        )
    assert len(rows) == 1
    assert rows[0].set_by_actor == "op2"
    assert rows[0].last_request_id == "mcp-allow-add-i2"
    assert len(chain) == 2


async def test_allowlist_cross_tenant_isolation(
    allowlist_store: MCPInternalHostAllowlistStore,
) -> None:
    await allowlist_store.add_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-allow-add-iso",
    )
    # A different tenant sees neither the set nor the list.
    assert await allowlist_store.get_allowlist(tenant_id="t2") == frozenset()
    assert await allowlist_store.list_for_tenant("t2") == []


async def test_list_for_tenant_returns_rows(
    allowlist_store: MCPInternalHostAllowlistStore,
) -> None:
    await allowlist_store.add_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-allow-add-l1",
    )
    await allowlist_store.add_ip(
        tenant_id="t1",
        ip="10.42.0.9",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-allow-add-l2",
    )
    rows = await allowlist_store.list_for_tenant("t1")
    assert all(isinstance(r, AllowlistEntryRow) for r in rows)
    assert {r.ip for r in rows} == {"10.42.0.7", "10.42.0.9"}
    one = next(r for r in rows if r.ip == "10.42.0.7")
    assert one.tenant_id == "t1"
    assert one.set_by_actor == "op@bank"
    assert one.last_request_id == "mcp-allow-add-l1"
    assert one.set_at is not None


async def test_add_ip_canonicalises_ipv6_before_storage(
    allowlist_store: MCPInternalHostAllowlistStore,
) -> None:
    # A non-canonical IPv6 literal is stored in its canonical str() form so the
    # Task-2 guard's exact `str(resolved_ip) in allowlist` comparison matches.
    await allowlist_store.add_ip(
        tenant_id="t1",
        ip="fd00:0:0:0:0:0:0:7",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-allow-add-v6",
    )
    assert await allowlist_store.get_allowlist(tenant_id="t1") == frozenset({"fd00::7"})


async def test_add_ip_chain_payload_exact_keyset(
    allowlist_store: MCPInternalHostAllowlistStore, engine: AsyncEngine
) -> None:
    await allowlist_store.add_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-allow-add-evidence",
    )
    async with engine.connect() as conn:
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "mcp.allowlist.add"
                    )
                )
            ).fetchall()
        )
    assert len(chain) == 1
    payload = chain[0].payload
    assert set(payload) == {"tenant_id", "ip", "actor_type", "actor_id"}
    assert payload["actor_type"] == "human"
    assert payload["actor_id"] == "op@bank"
    assert payload["ip"] == "10.42.0.7"
    assert list(chain[0].iso_controls) == ["ISO42001.A.5.31", "ISO42001.A.6.2.4"]


async def test_remove_ip_chain_event_emitted(
    allowlist_store: MCPInternalHostAllowlistStore, engine: AsyncEngine
) -> None:
    await allowlist_store.add_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-allow-add-r",
    )
    await allowlist_store.remove_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="op@bank",
        actor_type="human",
        request_id="mcp-allow-rm-r",
    )
    async with engine.connect() as conn:
        chain = list(
            (
                await conn.execute(
                    select(_decision_history).where(
                        _decision_history.c.event_type == "mcp.allowlist.remove"
                    )
                )
            ).fetchall()
        )
    assert len(chain) == 1
    assert set(chain[0].payload) == {"tenant_id", "ip", "actor_type", "actor_id"}
    assert chain[0].payload["actor_type"] == "human"


async def test_add_ip_bad_ip_writes_zero_rows_zero_chain(
    allowlist_store: MCPInternalHostAllowlistStore, engine: AsyncEngine
) -> None:
    with pytest.raises(MCPConfigRejected) as exc:
        await allowlist_store.add_ip(
            tenant_id="t1",
            ip="127.0.0.1",
            actor_subject="op@bank",
            actor_type="human",
            request_id="mcp-allow-add-bad",
        )
    assert exc.value.reason == "allowlist_ip_hard_blocked"
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_mcp_internal_host_allowlist))).fetchall())
        chain = list((await conn.execute(select(_decision_history))).fetchall())
    assert rows == []
    assert chain == []


# --------------------------------------------------------------------------- #
# Override grammar (spec §8 — http://-IP-literal)
# --------------------------------------------------------------------------- #


def test_validate_override_url_accepts_ip_literal_http() -> None:
    validate_override_url("http://10.42.0.7:8080/mcp")
    validate_override_url("http://10.42.0.7")
    validate_override_url("http://[fd00::7]:80/mcp")


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("https://10.42.0.7", "override_url_not_http"),
        ("ftp://x", "override_url_not_http"),
        ("http://svc.ns.svc.cluster.local", "override_url_host_not_ip_literal"),
        ("http://8.8.8.8", "override_url_host_not_internal"),
        ("http://8.8.8.8:8080/mcp", "override_url_host_not_internal"),
        ("not a url", "override_url_malformed"),
        ("http://", "override_url_malformed"),
        ("http://[::1", "override_url_malformed"),
        (123, "override_url_not_string"),
        (None, "override_url_not_string"),
    ],
)
def test_validate_override_url_rejects(value: object, reason: str) -> None:
    with pytest.raises(MCPConfigRejected) as exc:
        validate_override_url(value)
    assert exc.value.reason == reason


# --------------------------------------------------------------------------- #
# Allow-list grammar (spec §7 / AS-4 — exact IP, no DNS, no metadata)
# --------------------------------------------------------------------------- #


def test_validate_allowlist_ip_accepts_exact_internal() -> None:
    validate_allowlist_ip("10.42.0.7")
    validate_allowlist_ip("fd00::7")


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("10.0.0.0/8", "allowlist_ip_not_exact"),
        ("8.8.8.8", "allowlist_ip_hard_blocked"),
        ("2001:4860:4860::8888", "allowlist_ip_hard_blocked"),
        ("169.254.169.254", "allowlist_ip_hard_blocked"),
        ("fd00:ec2::254", "allowlist_ip_hard_blocked"),
        ("127.0.0.1", "allowlist_ip_hard_blocked"),
        ("::1", "allowlist_ip_hard_blocked"),
        ("224.0.0.1", "allowlist_ip_hard_blocked"),
        ("0.0.0.0", "allowlist_ip_hard_blocked"),
        ("240.0.0.1", "allowlist_ip_hard_blocked"),
        ("*.svc.cluster.local", "allowlist_ip_malformed"),
        ("my-host", "allowlist_ip_malformed"),
        (123, "allowlist_ip_not_string"),
    ],
)
def test_validate_allowlist_ip_rejects(value: object, reason: str) -> None:
    with pytest.raises(MCPConfigRejected) as exc:
        validate_allowlist_ip(value)
    assert exc.value.reason == reason


# --------------------------------------------------------------------------- #
# Shared internal floor predicate (imported by the Task-2 guard)
# --------------------------------------------------------------------------- #


def test_ip_passes_internal_floor_true_for_internal_addresses() -> None:
    assert ip_passes_internal_floor(ipaddress.ip_address("10.42.0.7")) is True
    assert ip_passes_internal_floor(ipaddress.ip_address("fd00::7")) is True


@pytest.mark.parametrize(
    "blocked",
    [
        "127.0.0.1",  # loopback
        "169.254.1.1",  # link-local
        "224.0.0.1",  # multicast
        "0.0.0.0",  # unspecified
        "240.0.0.1",  # reserved
        "8.8.8.8",  # public IPv4 — internal-only (not is_private)
        "2001:4860:4860::8888",  # public IPv6 — internal-only (not is_private)
        "169.254.169.254",  # metadata (also link-local)
        "fd00:ec2::254",  # metadata IPv6 (passes is_* flags; caught by _METADATA_IPS)
    ],
)
def test_ip_passes_internal_floor_false_for_blocked(blocked: str) -> None:
    assert ip_passes_internal_floor(ipaddress.ip_address(blocked)) is False
