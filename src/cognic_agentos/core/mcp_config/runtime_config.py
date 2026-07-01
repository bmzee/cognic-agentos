"""M4 — per-``(tenant, pack)`` runtime-config record store (ADR-026 D2/D3/D4/D8).

The authoritative **desired** runtime-configuration state. A pack's lifecycle
``configure`` step writes this record (the operator-pre-provisioned override +
internal-host allow-list + OAuth/AS Vault *references*); a materializer (M4
Task 4) later projects it into the **derived** MCP carve-out tables
(``mcp_server_url_override`` + ``mcp_internal_host_allowlist``) on ``install`` and
retracts them on ``disable`` / ``revoke``. This module is the desired-state
record only — it reads NO Vault and writes NO derived rows.

Mirrors ``core/mcp_config/storage.py`` exactly: current state in a table,
immutable history in the ``decision_history`` chain. Each mutator runs the
in-closure ``DecisionHistoryStore.append_with_precondition`` pattern — the
SELECT … FOR UPDATE + the upsert run INSIDE the precondition closure so the
state row + chain row + chain head commit in one transaction (any raise —
including a refusal — rolls back all three, so a rejected write leaves zero new
rows + zero chain).

Grammar (enforced before storage, inside the precondition):

- ``server_url_override`` (optional) reuses :func:`validate_override_url` from the
  sibling carve-out store — the SAME ``http://``-internal-IP-literal grammar the
  materializer will project, so the desired record can never carry a value the
  derived store would reject. A refusal propagates as ``MCPConfigRejected``
  (the sibling closed-enum taxonomy), NOT re-wrapped — one grammar, one reason
  vocabulary across desired + derived.
- each ``internal_host_allowlist`` entry reuses :func:`validate_allowlist_ip` —
  same rationale; refusals propagate as ``MCPConfigRejected``.
- the OAuth/AS refs are OPAQUE strings validated for SHAPE only here (non-empty
  when present); Vault resolution is the materializer's job (Task 4). A bad
  shape raises :class:`RuntimeConfigRejected` (this module's own taxonomy).

**Reconfigure-while-active is refused** (ADR-026 lifecycle extension): once the
record is ``active`` the derived carve-outs are live, and changing desired config
without re-materializing would create desired/derived drift with no reconcile
loop. A live config change is ``disable → configure → install``. From
``configured`` / ``disabled`` a re-config is allowed and resets the status to
``configured`` + bumps ``generation`` (the partial-materialization marker, D8).
**Reconfigure-while-revoked is also refused**: ``revoke`` is terminal, and the
authoritative desired-state store enforces that invariant directly — a direct
store caller cannot resurrect a revoked record to ``configured`` (defence in
depth with the lifecycle state machine + the ``configure`` endpoint's lifecycle
gate, M4 Tasks 3/5).

Writes are Human-only at the route boundary (M4 Task 3); the ``actor_type`` is
threaded onto the chain row's payload (chain-payload-is-evidence-snapshot — an
examiner reads the actor type off the chain row alone).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, get_args

import sqlalchemy as sa
from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.mcp_config.storage import validate_allowlist_ip, validate_override_url
from cognic_agentos.db.types import GovernanceJSON

# ISO 42001 controls stamped on every mcp.runtime_config.* chain row (parity with
# the sibling mcp.override.* / mcp.allowlist.* rows). A.5.31 — legal/regulatory
# requirements; A.6.2.4 — (human) operator authority.
_ISO_CONTROLS: tuple[str, ...] = ("ISO42001.A.5.31", "ISO42001.A.6.2.4")

#: Closed-enum activation status of a ``(tenant, pack)`` runtime-config record.
#: ``configured`` — written by ``configure``, not yet materialized; ``active`` —
#: ``install`` materialized the derived carve-outs; ``disabled`` — ``disable``
#: retracted them (record retained, re-installable); ``revoked`` — ``revoke``
#: retracted them (terminal at the lifecycle layer).
RuntimeConfigActivationStatus = Literal["configured", "active", "disabled", "revoked"]

#: Closed-enum refusal vocabulary carried by :class:`RuntimeConfigRejected`. The
#: ``server_url_override`` / ``internal_host_allowlist`` GRAMMAR refusals are NOT
#: here — they propagate as the sibling store's ``MCPConfigRejected`` so desired
#: + derived share one grammar-reason vocabulary.
RuntimeConfigRefusalReason = Literal[
    "runtime_config_reconfigure_while_active",
    "runtime_config_reconfigure_while_revoked",
    "runtime_config_oauth_credential_ref_malformed",
    "runtime_config_as_allowlist_ref_malformed",
    "runtime_config_activation_status_unknown",
]

#: The valid activation-status set, derived from the Literal so the
#: ``set_activation_status`` runtime guard can never drift from the closed enum.
_VALID_ACTIVATION_STATUSES: frozenset[str] = frozenset(get_args(RuntimeConfigActivationStatus))


class RuntimeConfigRejected(Exception):
    """Raised by the runtime-config store (and propagated out of the mutators)
    carrying the closed-enum ``reason``. The route layer (M4 Task 3) maps it to
    a 4xx with the reason."""

    def __init__(self, reason: RuntimeConfigRefusalReason) -> None:
        super().__init__(reason)
        self.reason: RuntimeConfigRefusalReason = reason


class RuntimeConfigNotFound(Exception):
    """Raised by :meth:`PackRuntimeConfigStore.set_activation_status` when no
    record exists for ``(tenant_id, pack_id)``. Fail-loud (mirrors
    ``packs/storage.PackNotFound``): an activation status cannot be set on a
    pack that was never configured. The route layer maps it to a 404."""

    def __init__(self, tenant_id: str, pack_id: str) -> None:
        super().__init__(f"runtime-config not found for ({tenant_id!r}, {pack_id!r})")
        self.tenant_id = tenant_id
        self.pack_id = pack_id


def _validate_opaque_ref(value: object, *, malformed_reason: RuntimeConfigRefusalReason) -> None:
    """Validate an opaque OAuth/AS Vault REFERENCE for shape only (ADR-026 D5).

    ``None`` is accepted (no reference configured — install-time validates
    presence/completeness per ADR-026 §gate 3, not this store). A present
    reference MUST be a non-empty / non-blank string. Vault resolution is the
    materializer's job (Task 4); this module reads NO Vault.

    Takes ``value: object`` (not ``str | None``) so the runtime defense against a
    non-string sneaking past typing is reachable + unit-testable per
    ``[[feedback_evidence_boundary_runtime_validation]]``.
    """
    if value is None:
        return
    if not isinstance(value, str) or not value.strip():
        raise RuntimeConfigRejected(malformed_reason)


# Pin: sa.TIMESTAMP(timezone=True) — NOT sa.DateTime (Oracle drops the offset);
# GovernanceJSON() for the dialect-portable internal_host_allowlist array (native
# JSON on Postgres/SQLite, JSON-as-CLOB on Oracle). Column shapes mirror the 0013
# migration exactly; the named unique constraint is the migration-only
# single-row-per-(tenant, pack) invariant.
_pack_runtime_config = sa.Table(
    "pack_runtime_config",
    _metadata,
    sa.Column("id", sa.Uuid(), primary_key=True),
    sa.Column("tenant_id", sa.String(length=128), nullable=False),
    sa.Column("pack_id", sa.String(length=128), nullable=False),
    sa.Column("server_url_override", sa.String(length=2048), nullable=True),
    sa.Column("internal_host_allowlist", GovernanceJSON(), nullable=False),
    sa.Column("oauth_credential_ref", sa.String(length=512), nullable=True),
    sa.Column("as_allowlist_ref", sa.String(length=512), nullable=True),
    sa.Column("activation_status", sa.String(length=32), nullable=False),
    sa.Column("generation", sa.Integer(), nullable=False),
    sa.Column("set_by_actor", sa.String(length=256), nullable=False),
    sa.Column("set_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("last_request_id", sa.String(length=64), nullable=False),
    sa.UniqueConstraint("tenant_id", "pack_id", name="uq_pack_runtime_config_tenant_pack"),
    sa.CheckConstraint(
        "activation_status IN ('configured', 'active', 'disabled', 'revoked')",
        name="ck_pack_runtime_config_activation_status",
    ),
    sa.Index("ix_pack_runtime_config_tenant_id", "tenant_id"),
)


@dataclass(frozen=True, slots=True)
class PackRuntimeConfigRecord:
    """The DESIRED runtime-config state for one ``(tenant, pack)`` (ADR-026 D2)."""

    tenant_id: str
    pack_id: str
    server_url_override: str | None
    internal_host_allowlist: tuple[str, ...]
    oauth_credential_ref: str | None
    as_allowlist_ref: str | None
    activation_status: RuntimeConfigActivationStatus
    generation: int
    set_by_actor: str
    set_at: datetime
    last_request_id: str


class PackRuntimeConfigStore:
    """Per-``(tenant, pack)`` desired runtime-config record (ADR-026 §6)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._dh = DecisionHistoryStore(engine)

    async def get(self, *, tenant_id: str, pack_id: str) -> PackRuntimeConfigRecord | None:
        """Read the desired record. Tenant-scoped — a cross-tenant
        ``(tenant, pack)`` reads as absent (``None``)."""
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(_pack_runtime_config)
                    .where(_pack_runtime_config.c.tenant_id == tenant_id)
                    .where(_pack_runtime_config.c.pack_id == pack_id)
                )
            ).first()
        if row is None:
            return None
        return PackRuntimeConfigRecord(
            tenant_id=row.tenant_id,
            pack_id=row.pack_id,
            server_url_override=row.server_url_override,
            internal_host_allowlist=tuple(row.internal_host_allowlist),
            oauth_credential_ref=row.oauth_credential_ref,
            as_allowlist_ref=row.as_allowlist_ref,
            activation_status=row.activation_status,
            generation=int(row.generation),
            set_by_actor=row.set_by_actor,
            set_at=row.set_at,
            last_request_id=row.last_request_id,
        )

    async def list_for_tenant(self, *, tenant_id: str) -> list[PackRuntimeConfigRecord]:
        """All desired records for one tenant (any ``activation_status``). The
        ``WHERE tenant_id`` IS the cross-tenant boundary — another tenant's
        records are NOT returned. Consumed by the Task-4 materializer to compute
        the union allow-list target across a tenant's currently-active configs;
        the caller filters by status itself, so this returns every record."""
        async with self._engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(_pack_runtime_config).where(
                        _pack_runtime_config.c.tenant_id == tenant_id
                    )
                )
            ).fetchall()
        return [
            PackRuntimeConfigRecord(
                tenant_id=row.tenant_id,
                pack_id=row.pack_id,
                server_url_override=row.server_url_override,
                internal_host_allowlist=tuple(row.internal_host_allowlist),
                oauth_credential_ref=row.oauth_credential_ref,
                as_allowlist_ref=row.as_allowlist_ref,
                activation_status=row.activation_status,
                generation=int(row.generation),
                set_by_actor=row.set_by_actor,
                set_at=row.set_at,
                last_request_id=row.last_request_id,
            )
            for row in rows
        ]

    async def set_config(
        self,
        *,
        tenant_id: str,
        pack_id: str,
        server_url_override: str | None,
        internal_host_allowlist: list[str],
        oauth_credential_ref: str | None,
        as_allowlist_ref: str | None,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        """Write the desired config (ADR-026 D4). Refused with
        ``runtime_config_reconfigure_while_active`` when the existing record is
        ``active`` and with ``runtime_config_reconfigure_while_revoked`` when it is
        terminal ``revoked``; otherwise upsert (insert → ``generation=1``; update →
        bump), always (re)setting ``activation_status="configured"``, and append
        one ``mcp.runtime_config.set`` chain row carrying the config snapshot +
        ``actor_type``."""

        async def _precondition(
            conn: AsyncConnection, prev_seq: int, prev_hash: bytes
        ) -> dict[str, Any]:
            row = (
                await conn.execute(
                    select(
                        _pack_runtime_config.c.activation_status,
                        _pack_runtime_config.c.generation,
                    )
                    .where(_pack_runtime_config.c.tenant_id == tenant_id)
                    .where(_pack_runtime_config.c.pack_id == pack_id)
                    .with_for_update()
                )
            ).first()
            # Refuse a reconfigure while the derived carve-outs are live (active),
            # AND refuse a reconfigure of a terminal revoked record: revoke is
            # terminal, and the authoritative desired-state store enforces that
            # invariant directly (not only the lifecycle layer) so no direct store
            # caller can resurrect a revoked record. Both fire BEFORE grammar.
            if row is not None and row.activation_status == "active":
                raise RuntimeConfigRejected("runtime_config_reconfigure_while_active")
            if row is not None and row.activation_status == "revoked":
                raise RuntimeConfigRejected("runtime_config_reconfigure_while_revoked")
            # Grammar before storage (rolls back on refusal). Override + allow-list
            # reuse the derived store's validators → MCPConfigRejected propagates.
            if server_url_override is not None:
                validate_override_url(server_url_override)
            allow: list[str] = list(internal_host_allowlist)
            for entry in allow:
                validate_allowlist_ip(entry)
            _validate_opaque_ref(
                oauth_credential_ref,
                malformed_reason="runtime_config_oauth_credential_ref_malformed",
            )
            _validate_opaque_ref(
                as_allowlist_ref,
                malformed_reason="runtime_config_as_allowlist_ref_malformed",
            )
            now = datetime.now(UTC)
            if row is None:
                generation = 1
                await conn.execute(
                    insert(_pack_runtime_config).values(
                        id=uuid.uuid4(),
                        tenant_id=tenant_id,
                        pack_id=pack_id,
                        server_url_override=server_url_override,
                        internal_host_allowlist=allow,
                        oauth_credential_ref=oauth_credential_ref,
                        as_allowlist_ref=as_allowlist_ref,
                        activation_status="configured",
                        generation=generation,
                        set_by_actor=actor_subject,
                        set_at=now,
                        last_request_id=request_id,
                    )
                )
            else:
                generation = int(row.generation) + 1
                await conn.execute(
                    update(_pack_runtime_config)
                    .where(_pack_runtime_config.c.tenant_id == tenant_id)
                    .where(_pack_runtime_config.c.pack_id == pack_id)
                    .values(
                        server_url_override=server_url_override,
                        internal_host_allowlist=allow,
                        oauth_credential_ref=oauth_credential_ref,
                        as_allowlist_ref=as_allowlist_ref,
                        activation_status="configured",
                        generation=generation,
                        set_by_actor=actor_subject,
                        set_at=now,
                        last_request_id=request_id,
                    )
                )
            return {"generation": generation, "internal_host_allowlist": allow}

        def _build(captured: dict[str, Any]) -> DecisionRecord:
            return DecisionRecord(
                decision_type="mcp.runtime_config.set",
                request_id=request_id,
                tenant_id=tenant_id,
                actor_id=actor_subject,
                iso_controls=_ISO_CONTROLS,
                payload={
                    "tenant_id": tenant_id,
                    "pack_id": pack_id,
                    "server_url_override": server_url_override,
                    "internal_host_allowlist": captured["internal_host_allowlist"],
                    "oauth_credential_ref": oauth_credential_ref,
                    "as_allowlist_ref": as_allowlist_ref,
                    "activation_status": "configured",
                    "generation": captured["generation"],
                    "actor_type": actor_type,
                },
            )

        await self._dh.append_with_precondition(record_builder=_build, precondition=_precondition)

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
        """Update ONLY the activation status (ADR-026 D6 — used by
        install/disable/revoke, M4 Task 6). Does NOT bump ``generation`` (that
        marks desired-config changes, not activation changes). Refuses an
        out-of-vocabulary ``status``; raises :class:`RuntimeConfigNotFound` when
        no record exists. Appends one ``mcp.runtime_config.activation`` chain row."""
        if status not in _VALID_ACTIVATION_STATUSES:
            raise RuntimeConfigRejected("runtime_config_activation_status_unknown")

        async def _precondition(
            conn: AsyncConnection, prev_seq: int, prev_hash: bytes
        ) -> dict[str, Any]:
            row = (
                await conn.execute(
                    select(_pack_runtime_config.c.activation_status)
                    .where(_pack_runtime_config.c.tenant_id == tenant_id)
                    .where(_pack_runtime_config.c.pack_id == pack_id)
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise RuntimeConfigNotFound(tenant_id, pack_id)
            previous_status = row.activation_status
            now = datetime.now(UTC)
            await conn.execute(
                update(_pack_runtime_config)
                .where(_pack_runtime_config.c.tenant_id == tenant_id)
                .where(_pack_runtime_config.c.pack_id == pack_id)
                .values(
                    activation_status=status,
                    set_by_actor=actor_subject,
                    set_at=now,
                    last_request_id=request_id,
                )
            )
            return {"previous_status": previous_status}

        def _build(captured: dict[str, Any]) -> DecisionRecord:
            return DecisionRecord(
                decision_type="mcp.runtime_config.activation",
                request_id=request_id,
                tenant_id=tenant_id,
                actor_id=actor_subject,
                iso_controls=_ISO_CONTROLS,
                payload={
                    "tenant_id": tenant_id,
                    "pack_id": pack_id,
                    "status": status,
                    "previous_status": captured["previous_status"],
                    "actor_type": actor_type,
                },
            )

        await self._dh.append_with_precondition(record_builder=_build, precondition=_precondition)


__all__: tuple[str, ...] = (
    "PackRuntimeConfigRecord",
    "PackRuntimeConfigStore",
    "RuntimeConfigActivationStatus",
    "RuntimeConfigNotFound",
    "RuntimeConfigRefusalReason",
    "RuntimeConfigRejected",
    "_pack_runtime_config",
    "_validate_opaque_ref",
)
