"""PR-2b-1 — operator ``server_url`` override + per-tenant exact-IP internal-host
allow-list, decision-history-audited (ADR-002 amendment; spec §6/§7/§8).

Two stores, both mirroring ``core/config_overlay/storage.py``: current state in a
table, immutable history in the ``decision_history`` chain. Each mutator runs the
in-closure ``append_with_precondition`` pattern — the upsert/delete runs INSIDE
the precondition closure so the state row + chain row + chain head commit in one
transaction (``DecisionHistoryStore.append_with_precondition`` owns the single
``engine.begin()`` envelope; any raise — including a grammar refusal — rolls back
all three, so a rejected write leaves zero rows + zero chain).

Grammar (enforced before storage, inside the precondition):

- ``MCPServerUrlOverrideStore`` — the override is an ``http://``-internal-IP-literal
  (spec §8): scheme MUST be ``http`` (an internal ``https://`` is refused), host
  MUST be an IP literal (a hostname is refused so no DNS is reintroduced on the
  MCP-SDK ``server_url`` leg), AND the IP MUST be internal/private (a public IP is
  refused — public-server repointing is deferred to a follow-up, PR-2b-1 is
  internal-only).
- ``MCPInternalHostAllowlistStore`` — each entry is an EXACT internal IP (spec §7
  / AS-4): no CIDR/range/prefix, no FQDN, and never a metadata/loopback/
  link-local/multicast/unspecified/reserved address (the shared
  :func:`ip_passes_internal_floor` floor). Entries are stored in canonical
  ``str(ip)`` form so the Task-2 guard's ``str(resolved_ip) in allowlist`` exact
  match is order-/format-independent.

Both writes are Human-only at the route boundary (Task 6); the ``actor_type`` is
threaded onto the chain row's payload (chain-payload-is-evidence-snapshot — an
examiner reads the actor type off the chain row alone).
"""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlparse

import sqlalchemy as sa
from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord

# ISO 42001 controls stamped on every mcp.override.* / mcp.allowlist.* chain row.
# A.5.31 — legal/regulatory requirements; A.6.2.4 — (human) operator authority.
_ISO_CONTROLS: tuple[str, ...] = ("ISO42001.A.5.31", "ISO42001.A.6.2.4")

#: Canonical cloud instance-metadata IPs that MUST never be allow-listed even
#: though they pass every ``is_*`` flag (``fd00:ec2::254`` is a private ULA, NOT
#: link-local/reserved, so the range checks miss it). Compared against
#: ``str(ip)`` (canonical form). The IPv4 IMDS endpoint 169.254.169.254 is
#: ALREADY blocked by the ``is_link_local`` clause (169.254.0.0/16), so it does
#: not need an explicit entry here — and a bare-IPv4 string literal is rejected
#: by the ``test_no_env_specific_values`` architecture guard. The set therefore
#: carries only the metadata IP that the range checks would otherwise admit.
_METADATA_IPS: frozenset[str] = frozenset(
    {
        "fd00:ec2::254",  # AWS IPv6 IMDS — a private ULA the is_* range checks miss
    }
)

#: Closed-enum refusal vocabulary carried by :class:`MCPConfigRejected`.
MCPConfigRefusalReason = Literal[
    # override (http://-internal-IP-literal grammar, spec §8)
    "override_url_not_string",
    "override_url_malformed",
    "override_url_not_http",
    "override_url_host_not_ip_literal",
    "override_url_host_not_internal",
    # allow-list (exact-IP grammar, spec §7 / AS-4)
    "allowlist_ip_not_string",
    "allowlist_ip_malformed",
    "allowlist_ip_not_exact",
    "allowlist_ip_hard_blocked",
]


class MCPConfigRejected(Exception):
    """Raised by :func:`validate_override_url` / :func:`validate_allowlist_ip`
    (and propagated out of the store mutators) carrying the closed-enum
    ``reason``. The route layer (Task 6) maps it to a 422 with the reason."""

    def __init__(self, reason: MCPConfigRefusalReason) -> None:
        super().__init__(reason)
        self.reason: MCPConfigRefusalReason = reason


def ip_passes_internal_floor(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Shared internal-host floor — ``True`` only for a PRIVATE internal IP that
    is safe to allow-list. PR-2b-1 is internal-only: ``ip.is_private`` is REQUIRED,
    so a public IP (``8.8.8.8`` / ``2001:4860:4860::8888``) is rejected (public-
    server repointing is deferred). ``False`` for any non-private IP AND for
    loopback / link-local / multicast / unspecified / reserved and the canonical
    instance-metadata IPs.

    Consumed by :func:`validate_allowlist_ip` + :func:`validate_override_url` at
    set-time AND by the Task-2 guard at read-time (defence-in-depth against a
    corrupted allow-list entry that bypassed set-time validation). Module-level +
    exported so ``mcp_authz`` can import it.
    """
    return (
        ip.is_private
        and not (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
            or ip.is_reserved
        )
        and str(ip) not in _METADATA_IPS
    )


def validate_override_url(value: object) -> None:
    """Validate an operator ``server_url`` override (spec §8). Raises
    :class:`MCPConfigRejected`; returns ``None`` on accept."""
    if not isinstance(value, str):
        raise MCPConfigRejected("override_url_not_string")
    try:
        parsed = urlparse(value)
        host = parsed.hostname
    except ValueError as exc:  # malformed IPv6 authority, e.g. "http://[::1"
        raise MCPConfigRejected("override_url_malformed") from exc
    if not parsed.scheme:
        raise MCPConfigRejected("override_url_malformed")
    if parsed.scheme != "http":
        raise MCPConfigRejected("override_url_not_http")
    if not host:
        raise MCPConfigRejected("override_url_malformed")
    try:
        host_ip = ipaddress.ip_address(host)
    except ValueError as exc:
        raise MCPConfigRejected("override_url_host_not_ip_literal") from exc
    if not ip_passes_internal_floor(host_ip):
        # PR-2b-1 is internal-only: a public IP (or loopback/metadata) override
        # would repoint the pack to a non-internal host — public-server
        # repointing is deferred. Reject at set-time.
        raise MCPConfigRejected("override_url_host_not_internal")


def validate_allowlist_ip(value: object) -> None:
    """Validate an internal-host allow-list entry (spec §7 / AS-4). Raises
    :class:`MCPConfigRejected`; returns ``None`` on accept."""
    if not isinstance(value, str):
        raise MCPConfigRejected("allowlist_ip_not_string")
    if "/" in value:  # CIDR/range/prefix — not an exact IP
        raise MCPConfigRejected("allowlist_ip_not_exact")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:  # FQDN, "*.svc.cluster.local", garbage
        raise MCPConfigRejected("allowlist_ip_malformed") from exc
    if not ip_passes_internal_floor(ip):
        raise MCPConfigRejected("allowlist_ip_hard_blocked")


# Pin: sa.TIMESTAMP(timezone=True) — NOT sa.DateTime (Oracle drops the offset).
# Column shapes mirror the 0012 migration exactly; the named unique constraints
# are the migration-only single-row invariants.
_mcp_server_url_override = sa.Table(
    "mcp_server_url_override",
    _metadata,
    sa.Column("id", sa.Uuid(), primary_key=True),
    sa.Column("tenant_id", sa.String(length=128), nullable=False),
    sa.Column("pack_id", sa.String(length=128), nullable=False),
    sa.Column("server_url_override", sa.String(length=2048), nullable=False),
    sa.Column("set_by_actor", sa.String(length=256), nullable=False),
    sa.Column("set_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("last_request_id", sa.String(length=64), nullable=False),
    sa.UniqueConstraint("tenant_id", "pack_id", name="uq_mcp_server_url_override_tenant_pack"),
    sa.Index("ix_mcp_server_url_override_tenant_id", "tenant_id"),
)

_mcp_internal_host_allowlist = sa.Table(
    "mcp_internal_host_allowlist",
    _metadata,
    sa.Column("id", sa.Uuid(), primary_key=True),
    sa.Column("tenant_id", sa.String(length=128), nullable=False),
    sa.Column("ip", sa.String(length=64), nullable=False),
    sa.Column("set_by_actor", sa.String(length=256), nullable=False),
    sa.Column("set_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("last_request_id", sa.String(length=64), nullable=False),
    sa.UniqueConstraint("tenant_id", "ip", name="uq_mcp_internal_host_allowlist_tenant_ip"),
    sa.Index("ix_mcp_internal_host_allowlist_tenant_id", "tenant_id"),
)


@dataclass(frozen=True, slots=True)
class AllowlistEntryRow:
    tenant_id: str
    ip: str
    set_by_actor: str
    set_at: datetime
    last_request_id: str


class MCPServerUrlOverrideStore:
    """Per-``(tenant, pack)`` operator ``server_url`` override (spec §6/§8)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._dh = DecisionHistoryStore(engine)

    async def get(self, *, tenant_id: str, pack_id: str) -> str | None:
        """Resolve-per-use read (Task 4 consumer). Tenant-scoped — a cross-tenant
        ``(tenant, pack)`` reads as absent (``None``)."""
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_mcp_server_url_override.c.server_url_override)
                    .where(_mcp_server_url_override.c.tenant_id == tenant_id)
                    .where(_mcp_server_url_override.c.pack_id == pack_id)
                )
            ).first()
        return row.server_url_override if row is not None else None

    async def set_override(
        self,
        *,
        tenant_id: str,
        pack_id: str,
        server_url: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        async def _precondition(
            conn: AsyncConnection, prev_seq: int, prev_hash: bytes
        ) -> dict[str, Any]:
            row = (
                await conn.execute(
                    select(_mcp_server_url_override.c.server_url_override)
                    .where(_mcp_server_url_override.c.tenant_id == tenant_id)
                    .where(_mcp_server_url_override.c.pack_id == pack_id)
                    .with_for_update()
                )
            ).first()
            previous = row.server_url_override if row is not None else None
            validate_override_url(server_url)  # grammar before storage (rolls back on refusal)
            now = datetime.now(UTC)
            if row is None:
                await conn.execute(
                    insert(_mcp_server_url_override).values(
                        id=uuid.uuid4(),
                        tenant_id=tenant_id,
                        pack_id=pack_id,
                        server_url_override=server_url,
                        set_by_actor=actor_subject,
                        set_at=now,
                        last_request_id=request_id,
                    )
                )
            else:
                await conn.execute(
                    update(_mcp_server_url_override)
                    .where(_mcp_server_url_override.c.tenant_id == tenant_id)
                    .where(_mcp_server_url_override.c.pack_id == pack_id)
                    .values(
                        server_url_override=server_url,
                        set_by_actor=actor_subject,
                        set_at=now,
                        last_request_id=request_id,
                    )
                )
            return {"previous": previous}

        def _build(captured: dict[str, Any]) -> DecisionRecord:
            return DecisionRecord(
                decision_type="mcp.override.set",
                request_id=request_id,
                tenant_id=tenant_id,
                actor_id=actor_subject,
                iso_controls=_ISO_CONTROLS,
                payload={
                    "tenant_id": tenant_id,
                    "pack_id": pack_id,
                    "server_url": server_url,
                    "previous_server_url": captured["previous"],
                    "actor_type": actor_type,
                },
            )

        await self._dh.append_with_precondition(record_builder=_build, precondition=_precondition)

    async def clear_override(
        self,
        *,
        tenant_id: str,
        pack_id: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        async def _precondition(
            conn: AsyncConnection, prev_seq: int, prev_hash: bytes
        ) -> dict[str, Any]:
            row = (
                await conn.execute(
                    select(_mcp_server_url_override.c.server_url_override)
                    .where(_mcp_server_url_override.c.tenant_id == tenant_id)
                    .where(_mcp_server_url_override.c.pack_id == pack_id)
                    .with_for_update()
                )
            ).first()
            previous = row.server_url_override if row is not None else None
            await conn.execute(
                delete(_mcp_server_url_override)
                .where(_mcp_server_url_override.c.tenant_id == tenant_id)
                .where(_mcp_server_url_override.c.pack_id == pack_id)
            )
            return {"previous": previous}

        def _build(captured: dict[str, Any]) -> DecisionRecord:
            return DecisionRecord(
                decision_type="mcp.override.cleared",
                request_id=request_id,
                tenant_id=tenant_id,
                actor_id=actor_subject,
                iso_controls=_ISO_CONTROLS,
                payload={
                    "tenant_id": tenant_id,
                    "pack_id": pack_id,
                    "previous_server_url": captured["previous"],
                    "actor_type": actor_type,
                },
            )

        await self._dh.append_with_precondition(record_builder=_build, precondition=_precondition)


class MCPInternalHostAllowlistStore:
    """Per-tenant exact-IP internal-host allow-list (spec §7 / AS-4)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._dh = DecisionHistoryStore(engine)

    async def get_allowlist(self, *, tenant_id: str) -> frozenset[str]:
        """The tenant's exact-IP allow-list as canonical ``str(ip)`` forms.
        Tenant-scoped — a different tenant reads the empty set."""
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(_mcp_internal_host_allowlist.c.ip).where(
                        _mcp_internal_host_allowlist.c.tenant_id == tenant_id
                    )
                )
            ).fetchall()
        return frozenset(r.ip for r in rows)

    async def list_for_tenant(self, tenant_id: str) -> list[AllowlistEntryRow]:
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(_mcp_internal_host_allowlist).where(
                        _mcp_internal_host_allowlist.c.tenant_id == tenant_id
                    )
                )
            ).fetchall()
        return [
            AllowlistEntryRow(
                tenant_id=r.tenant_id,
                ip=r.ip,
                set_by_actor=r.set_by_actor,
                set_at=r.set_at,
                last_request_id=r.last_request_id,
            )
            for r in rows
        ]

    async def add_ip(
        self,
        *,
        tenant_id: str,
        ip: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        async def _precondition(conn: AsyncConnection, prev_seq: int, prev_hash: bytes) -> str:
            validate_allowlist_ip(ip)  # grammar before storage (rolls back on refusal)
            canonical = str(ipaddress.ip_address(ip))  # store canonical form
            row = (
                await conn.execute(
                    select(_mcp_internal_host_allowlist.c.id)
                    .where(_mcp_internal_host_allowlist.c.tenant_id == tenant_id)
                    .where(_mcp_internal_host_allowlist.c.ip == canonical)
                    .with_for_update()
                )
            ).first()
            now = datetime.now(UTC)
            if row is None:
                await conn.execute(
                    insert(_mcp_internal_host_allowlist).values(
                        id=uuid.uuid4(),
                        tenant_id=tenant_id,
                        ip=canonical,
                        set_by_actor=actor_subject,
                        set_at=now,
                        last_request_id=request_id,
                    )
                )
            else:
                await conn.execute(
                    update(_mcp_internal_host_allowlist)
                    .where(_mcp_internal_host_allowlist.c.tenant_id == tenant_id)
                    .where(_mcp_internal_host_allowlist.c.ip == canonical)
                    .values(
                        set_by_actor=actor_subject,
                        set_at=now,
                        last_request_id=request_id,
                    )
                )
            return canonical

        def _build(canonical: str) -> DecisionRecord:
            return DecisionRecord(
                decision_type="mcp.allowlist.add",
                request_id=request_id,
                tenant_id=tenant_id,
                actor_id=actor_subject,
                iso_controls=_ISO_CONTROLS,
                payload={
                    "tenant_id": tenant_id,
                    "ip": canonical,
                    "actor_type": actor_type,
                },
            )

        await self._dh.append_with_precondition(record_builder=_build, precondition=_precondition)

    async def remove_ip(
        self,
        *,
        tenant_id: str,
        ip: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        async def _precondition(conn: AsyncConnection, prev_seq: int, prev_hash: bytes) -> str:
            validate_allowlist_ip(ip)  # grammar before storage (rolls back on refusal)
            canonical = str(ipaddress.ip_address(ip))
            await conn.execute(
                delete(_mcp_internal_host_allowlist)
                .where(_mcp_internal_host_allowlist.c.tenant_id == tenant_id)
                .where(_mcp_internal_host_allowlist.c.ip == canonical)
            )
            return canonical

        def _build(canonical: str) -> DecisionRecord:
            return DecisionRecord(
                decision_type="mcp.allowlist.remove",
                request_id=request_id,
                tenant_id=tenant_id,
                actor_id=actor_subject,
                iso_controls=_ISO_CONTROLS,
                payload={
                    "tenant_id": tenant_id,
                    "ip": canonical,
                    "actor_type": actor_type,
                },
            )

        await self._dh.append_with_precondition(record_builder=_build, precondition=_precondition)


__all__: tuple[str, ...] = (
    "AllowlistEntryRow",
    "MCPConfigRefusalReason",
    "MCPConfigRejected",
    "MCPInternalHostAllowlistStore",
    "MCPServerUrlOverrideStore",
    "_mcp_internal_host_allowlist",
    "_mcp_server_url_override",
    "ip_passes_internal_floor",
    "validate_allowlist_ip",
    "validate_override_url",
)
