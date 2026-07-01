"""M4 Task 4 — ``RuntimeConfigMaterializer`` (ADR-026 D7).

Projects the DESIRED per-``(tenant, pack)`` :class:`PackRuntimeConfigRecord` into
the EXISTING audited DERIVED MCP carve-out stores on ``install`` and retracts on
``disable`` / ``revoke``:

- :class:`MCPServerUrlOverrideStore` — the operator ``server_url`` override
  (pack-scoped), and
- :class:`MCPInternalHostAllowlistStore` — the per-tenant exact-IP internal-host
  allow-list (tenant-scoped, shared across a tenant's packs).

``protocol/mcp_authz`` reads those derived rows EXACTLY as today — this module
projects INTO the carve-out STORES via their public mutators ONLY; it never
imports ``mcp_authz``, never touches the carve-out tables directly (no raw SQL /
no ``sa.Table`` access), and never changes the desired record's
``activation_status`` (that is Task-6 lifecycle concern). Because every write
goes through a store mutator, the materializer cannot drift from the carve-out
grammar/audit: each mutation is its OWN audited
``DecisionHistoryStore.append_with_precondition`` transaction emitting an
``mcp.override.*`` / ``mcp.allowlist.*`` chain row.

Validate-before-write at ``materialize``: BOTH Vault references
(``oauth_credential_ref`` + ``as_allowlist_ref``) are resolved + shape-validated
READ-ONLY BEFORE any derived write. If either is missing / unresolvable /
malformed the materialize is :class:`MaterializeRejected` and NOTHING is written
(no override, no IP). This module reads Vault via the narrow consumer-owned
:class:`VaultReader` Protocol declared here per
``[[feedback_consumer_owned_protocol_for_unlanded_dep]]`` (the real adapter is
wired at Task 7; it mirrors ``mcp_authz``'s ``self._vault.read(path)``).

Non-atomicity + fail-closed property
------------------------------------
The materialize/retract is NON-ATOMIC across its multiple single-mutator
transactions — there is no enclosing transaction spanning the override write +
the N allow-list writes (each carve-out mutator owns its own ``engine.begin()``
envelope). A crash / fault between mutations leaves a PARTIAL derived state. This
is intentional and SAFE because:

- it is **fail-closed BY ORDERING** — ``materialize`` reconciles the allow-list
  permits FIRST and lands the override (the repoint that EXPOSES the pack at the
  internal host) LAST, so any pre-override failure leaves the override unset → the
  pack is never repointed → not callable. The override-last ordering is
  load-bearing under the union model: a pack's desired IP may already be
  tenant-allow-listed by ANOTHER active pack, so an override-FIRST ordering would
  expose the pack the instant its override landed — even before its own allow-list
  reconcile finished. ``retract`` is the mirror — it clears the override FIRST to
  un-expose, then reconciles the allow-list; and
- it is **idempotent** — every step is check-before-write (set/clear the override
  only when it differs; add/remove an IP only when the live set differs from the
  reconciled target), so re-running ``materialize`` after a partial failure
  CONVERGES to the desired derived state without duplicate STATE rows AND without
  spurious CHAIN rows (a no-op step emits no audit event). The lifecycle layer
  (Task 6) flips ``activation_status`` to ``active`` only after a clean
  materialize, so a re-install (``disable`` → re-``install``) re-runs the
  converging projection.

There is no compensation log: recovery is forward-only re-materialize, not
rollback of the already-landed steps (each landed step is already audited + valid
on its own). The one residual risk this leaves is operator-visible drift if a
materialize fails AND is never retried — the partial derived rows persist (still
fail-closed / not callable) until the next ``install`` / ``disable`` reconciles
them; surfacing that drift (a reconcile sweep) is out of Task-4 scope.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, get_args, runtime_checkable

from cognic_agentos.core.mcp_config.runtime_config import PackRuntimeConfigRecord

#: The two OAuth ``auth_method`` values the materialize accepts when present
#: (absence is also valid). Mirrors the MCP OAuth client-auth methods.
_VALID_OAUTH_AUTH_METHODS: frozenset[str] = frozenset({"client_secret_post", "client_secret_basic"})

#: Closed-enum refusal vocabulary carried by :class:`MaterializeRejected`. Both
#: fire from the read-only Vault-validation pass that runs BEFORE any write.
MaterializeRefusalReason = Literal[
    "materialize_vault_ref_unresolved",
    "materialize_vault_ref_malformed",
]


class MaterializeRejected(Exception):
    """Raised by :meth:`RuntimeConfigMaterializer.materialize` when a required
    Vault reference is missing / unresolvable / malformed. Carries the closed-enum
    ``reason`` + a ``detail`` naming which ref (``oauth`` / ``as``) failed.
    Validate-before-write — when raised, NOTHING has been written to the derived
    carve-out stores."""

    def __init__(self, reason: MaterializeRefusalReason, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason: MaterializeRefusalReason = reason
        self.detail: str = detail


@runtime_checkable
class VaultReader(Protocol):
    """Narrow consumer-owned Vault read seam (ADR-026 D5) — mirrors
    ``mcp_authz``'s ``self._vault.read(path)``. ``read`` returns the secret
    mapping at ``path`` or ``None`` when the path is absent. The real adapter is
    wired at Task 7; tests stub it. Declared here (not imported) per
    ``[[feedback_consumer_owned_protocol_for_unlanded_dep]]`` so this module ships
    independently of the adapter landing."""

    async def read(self, path: str) -> Mapping[str, Any] | None: ...


@runtime_checkable
class _OverrideStore(Protocol):
    """Structural view of :class:`MCPServerUrlOverrideStore` (the mutators the
    materializer calls). Declared for typing only — the real store conforms."""

    async def get(self, *, tenant_id: str, pack_id: str) -> str | None: ...

    async def set_override(
        self,
        *,
        tenant_id: str,
        pack_id: str,
        server_url: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None: ...

    async def clear_override(
        self,
        *,
        tenant_id: str,
        pack_id: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None: ...


@runtime_checkable
class _AllowlistStore(Protocol):
    """Structural view of :class:`MCPInternalHostAllowlistStore`."""

    async def get_allowlist(self, *, tenant_id: str) -> frozenset[str]: ...

    async def add_ip(
        self,
        *,
        tenant_id: str,
        ip: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None: ...

    async def remove_ip(
        self,
        *,
        tenant_id: str,
        ip: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None: ...


@runtime_checkable
class _ConfigStore(Protocol):
    """Structural view of :class:`PackRuntimeConfigStore` — only the tenant-scoped
    ``list_for_tenant`` read is consulted (to compute the union allow-list target
    across a tenant's currently-active configs)."""

    async def list_for_tenant(self, *, tenant_id: str) -> list[PackRuntimeConfigRecord]: ...


@dataclass(frozen=True, slots=True)
class MaterializeResult:
    """What a single ``materialize`` reconciled (for the lifecycle caller's
    structured log / response). ``override_action`` is the override leg's effect;
    ``allowlist_added`` / ``allowlist_removed`` are the IPs the tenant allow-list
    reconcile actually mutated (empty when a no-op); ``tenant_allowlist_after`` is
    the tenant's full derived allow-list once the reconcile completes."""

    override_action: Literal["set", "cleared", "unchanged"]
    allowlist_added: tuple[str, ...]
    allowlist_removed: tuple[str, ...]
    tenant_allowlist_after: frozenset[str]


class RuntimeConfigMaterializer:
    """Projects desired :class:`PackRuntimeConfigRecord` state into the derived
    MCP carve-out stores (ADR-026 D7). See the module docstring for the
    non-atomicity + fail-closed + idempotency contract."""

    def __init__(
        self,
        *,
        override_store: _OverrideStore,
        allowlist_store: _AllowlistStore,
        config_store: _ConfigStore,
        vault_reader: VaultReader,
    ) -> None:
        self._override = override_store
        self._allowlist = allowlist_store
        self._config = config_store
        self._vault = vault_reader

    # ----------------------------------------------------------------------- #
    # Vault-ref validation (read-only, BEFORE any write)
    # ----------------------------------------------------------------------- #

    async def _read_required_ref(self, ref: str | None, *, which: str) -> Mapping[str, Any]:
        """Resolve a REQUIRED Vault ref read-only. Raises
        :class:`MaterializeRejected` (``materialize_vault_ref_unresolved``) when
        the ref is ``None``, absent in Vault, or the read raises."""
        if ref is None:
            raise MaterializeRejected(
                "materialize_vault_ref_unresolved", f"{which} ref is not configured"
            )
        try:
            secret = await self._vault.read(ref)
        except MaterializeRejected:
            raise
        except Exception as exc:
            raise MaterializeRejected(
                "materialize_vault_ref_unresolved", f"{which} ref read failed"
            ) from exc
        if secret is None:
            raise MaterializeRejected(
                "materialize_vault_ref_unresolved", f"{which} ref unresolved in Vault"
            )
        return secret

    async def _validate_oauth_ref(self, ref: str | None) -> None:
        secret = await self._read_required_ref(ref, which="oauth")
        client_id = secret.get("client_id")
        client_secret = secret.get("client_secret")
        if not (isinstance(client_id, str) and client_id.strip()):
            raise MaterializeRejected(
                "materialize_vault_ref_malformed", "oauth ref missing/blank client_id"
            )
        if not (isinstance(client_secret, str) and client_secret.strip()):
            raise MaterializeRejected(
                "materialize_vault_ref_malformed", "oauth ref missing/blank client_secret"
            )
        auth_method = secret.get("auth_method")
        if auth_method is not None and auth_method not in _VALID_OAUTH_AUTH_METHODS:
            raise MaterializeRejected(
                "materialize_vault_ref_malformed", "oauth ref auth_method invalid"
            )

    async def _validate_as_ref(self, ref: str | None) -> None:
        secret = await self._read_required_ref(ref, which="as")
        servers = secret.get("servers")
        if not isinstance(servers, list) or not servers:
            raise MaterializeRejected(
                "materialize_vault_ref_malformed", "as ref servers not a non-empty list"
            )
        for entry in servers:
            if not (isinstance(entry, str) and entry.strip()):
                raise MaterializeRejected(
                    "materialize_vault_ref_malformed", "as ref servers has a blank entry"
                )

    # ----------------------------------------------------------------------- #
    # Public API
    # ----------------------------------------------------------------------- #

    async def materialize(
        self,
        *,
        record: PackRuntimeConfigRecord,
        derived_pack_id: str | None = None,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> MaterializeResult:
        """Project ``record``'s desired state into the derived carve-out stores
        (install path). Order is load-bearing — the override (the repoint that
        EXPOSES the pack at the internal host) lands LAST, after every allow-list
        permit is in place:

        1. Resolve + shape-validate BOTH required Vault refs read-only — refuse
           (write nothing) on the first failure.
        2. Reconcile the tenant allow-list FIRST to the UNION target across the
           tenant's currently-``active`` configs PLUS this record's desired IPs
           (this record may not be ``active`` yet — Task 6 flips it
           post-materialize), via add/remove diffs against the live derived set
           (check-before-write). These IPs are the resource-leg PERMITS.
        3. Reconcile the pack-scoped override LAST (set / clear / no-op,
           check-before-write). The override is the EXPOSURE step: under the union
           model a pack's desired IP may already be tenant-allow-listed by another
           active pack, so an override-FIRST ordering would make the pack callable
           the instant its override landed — even if a later allow-list step
           failed. Override-last keeps a partial materialize fail-closed: any
           pre-override failure leaves the override unset → the pack is never
           repointed → not callable.
        """
        # Step 1 — validate BOTH refs before any write (validate-before-write).
        await self._validate_oauth_ref(record.oauth_credential_ref)
        await self._validate_as_ref(record.as_allowlist_ref)

        # ``record.pack_id`` is the runtime-config/lifecycle key. The derived
        # override row is read by MCPHost using the registry ``server_id``
        # (distribution name), so callers that own both identities must pass the
        # explicit derived key. The default preserves direct materializer tests
        # and legacy single-key callers.
        override_pack_id = derived_pack_id or record.pack_id

        # Step 2 — reconcile the tenant allow-list FIRST (the resource-leg permits
        # must be in place BEFORE the override exposes the pack at the internal
        # host; see the override-last fail-closed rationale in the docstring).
        target = await self._compute_union_target(
            tenant_id=record.tenant_id, extra_ips=record.internal_host_allowlist
        )
        added, removed, after = await self._reconcile_allowlist(
            tenant_id=record.tenant_id,
            target=target,
            actor_subject=actor_subject,
            actor_type=actor_type,
            request_id=request_id,
        )

        # Step 3 — reconcile the pack-scoped override LAST (the exposure step).
        override_action = await self._reconcile_override(
            tenant_id=record.tenant_id,
            pack_id=override_pack_id,
            desired=record.server_url_override,
            actor_subject=actor_subject,
            actor_type=actor_type,
            request_id=request_id,
        )
        return MaterializeResult(
            override_action=override_action,
            allowlist_added=added,
            allowlist_removed=removed,
            tenant_allowlist_after=after,
        )

    async def retract(
        self,
        *,
        tenant_id: str,
        pack_id: str | None = None,
        config_pack_id: str | None = None,
        derived_pack_id: str | None = None,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        """Retract the pack's derived posture (disable / revoke path):

        1. Clear the pack-scoped override (check-before-write).
        2. Reconcile the tenant allow-list to the union target EXCLUDING this pack
           (explicit P-exclusion — robust whether or not Task 6 has already flipped
           P's ``activation_status`` away from ``active``).

        ``config_pack_id`` is the runtime-config/lifecycle key used for the
        active-config union exclusion; ``derived_pack_id`` is the registry
        ``server_id`` / distribution-name key used for the override row that
        MCPHost reads. ``pack_id`` is retained as a legacy single-key shorthand.

        No Vault validation — retract has no Vault dependency.
        """
        if config_pack_id is None:
            config_pack_id = pack_id
        if derived_pack_id is None:
            derived_pack_id = config_pack_id
        if config_pack_id is None or derived_pack_id is None:
            raise TypeError("retract requires pack_id or both config_pack_id and derived_pack_id")

        # Step 1 — clear the override iff present.
        current = await self._override.get(tenant_id=tenant_id, pack_id=derived_pack_id)
        if current is not None:
            await self._override.clear_override(
                tenant_id=tenant_id,
                pack_id=derived_pack_id,
                actor_subject=actor_subject,
                actor_type=actor_type,
                request_id=request_id,
            )

        # Step 2 — reconcile the allow-list to the union of OTHER active packs.
        target = await self._compute_union_target(
            tenant_id=tenant_id, exclude_pack_id=config_pack_id
        )
        await self._reconcile_allowlist(
            tenant_id=tenant_id,
            target=target,
            actor_subject=actor_subject,
            actor_type=actor_type,
            request_id=request_id,
        )

    # ----------------------------------------------------------------------- #
    # Reconcile helpers (check-before-write — idempotent, no spurious chain rows)
    # ----------------------------------------------------------------------- #

    async def _reconcile_override(
        self,
        *,
        tenant_id: str,
        pack_id: str,
        desired: str | None,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> Literal["set", "cleared", "unchanged"]:
        current = await self._override.get(tenant_id=tenant_id, pack_id=pack_id)
        if desired is not None:
            if current != desired:
                await self._override.set_override(
                    tenant_id=tenant_id,
                    pack_id=pack_id,
                    server_url=desired,
                    actor_subject=actor_subject,
                    actor_type=actor_type,
                    request_id=request_id,
                )
                return "set"
            return "unchanged"
        # desired is None — clear an existing derived override (no-op if absent).
        if current is not None:
            await self._override.clear_override(
                tenant_id=tenant_id,
                pack_id=pack_id,
                actor_subject=actor_subject,
                actor_type=actor_type,
                request_id=request_id,
            )
            return "cleared"
        return "unchanged"

    async def _compute_union_target(
        self,
        *,
        tenant_id: str,
        extra_ips: tuple[str, ...] = (),
        exclude_pack_id: str | None = None,
    ) -> set[str]:
        """The tenant allow-list reconcile target: the union of every currently-
        ``active`` config's IPs (optionally excluding one pack) PLUS ``extra_ips``
        (the desired IPs of the record being materialized, which may not be
        ``active`` yet)."""
        records = await self._config.list_for_tenant(tenant_id=tenant_id)
        target: set[str] = set(extra_ips)
        for rec in records:
            if rec.activation_status != "active":
                continue
            if exclude_pack_id is not None and rec.pack_id == exclude_pack_id:
                continue
            target.update(rec.internal_host_allowlist)
        return target

    async def _reconcile_allowlist(
        self,
        *,
        tenant_id: str,
        target: set[str],
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> tuple[tuple[str, ...], tuple[str, ...], frozenset[str]]:
        """Drive the tenant allow-list to ``target`` via add/remove diffs against
        the live derived set (check-before-write → no spurious chain rows on a
        converged re-run). Returns ``(added, removed, after)``."""
        current = await self._allowlist.get_allowlist(tenant_id=tenant_id)
        to_add = sorted(target - current)
        to_remove = sorted(current - target)
        for ip in to_add:
            await self._allowlist.add_ip(
                tenant_id=tenant_id,
                ip=ip,
                actor_subject=actor_subject,
                actor_type=actor_type,
                request_id=request_id,
            )
        for ip in to_remove:
            await self._allowlist.remove_ip(
                tenant_id=tenant_id,
                ip=ip,
                actor_subject=actor_subject,
                actor_type=actor_type,
                request_id=request_id,
            )
        after = await self._allowlist.get_allowlist(tenant_id=tenant_id)
        return tuple(to_add), tuple(to_remove), after


# Count-guard helper consumers can import (the test pins the value count via
# typing.get_args, NOT regex — comment tokens inside Literal[...] would over-count).
_MATERIALIZE_REFUSAL_REASON_COUNT: int = len(get_args(MaterializeRefusalReason))


__all__: tuple[str, ...] = (
    "MaterializeRefusalReason",
    "MaterializeRejected",
    "MaterializeResult",
    "RuntimeConfigMaterializer",
    "VaultReader",
)
