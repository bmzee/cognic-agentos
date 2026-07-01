"""M4 Task 4 — RuntimeConfigMaterializer tests.

The materializer projects the DESIRED ``PackRuntimeConfigRecord`` into the
EXISTING audited DERIVED carve-out stores (the MCP ``server_url`` override store +
the internal-host allow-list store) on ``install`` and retracts on
``disable`` / ``revoke``. It NEVER touches the carve-out tables directly — it
calls ONLY the store mutators, so it cannot drift from their grammar/audit.

These tests drive the materializer over IN-MEMORY STUB stores (recording every
call) + a stub ``vault_reader``, so the contract is exercised without a DB or a
real Vault. The store stubs conform to the EXACT mutator/read APIs the real
stores expose (keyword-only ``actor_subject`` / ``actor_type`` / ``request_id``
threaded into every write). Key properties pinned here:

- validate-BOTH-Vault-refs-before-any-write (a missing/malformed ref → reject +
  zero writes),
- idempotency (a re-run converges; no duplicate STATE mutations, no spurious
  CHAIN mutations via check-before-write),
- the tenant-allow-list UNION reconcile on materialize + the P-EXCLUDING reconcile
  on retract (shared-IP + distinct-IP regressions),
- partial-failure recovery (a mutator raising mid-materialize leaves a partial
  derived state that a re-run converges from — the fail-closed property),
- the AST self-test that the materializer does NOT import ``mcp_authz``,
- the closed-enum count guard via ``typing.get_args``.
"""

import ast
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, get_args

import pytest

from cognic_agentos.core.mcp_config.materializer import (
    MaterializeRefusalReason,
    MaterializeRejected,
    MaterializeResult,
    RuntimeConfigMaterializer,
)
from cognic_agentos.core.mcp_config.runtime_config import PackRuntimeConfigRecord

# --------------------------------------------------------------------------- #
# Stub stores — record every call; conform to the exact production APIs
# --------------------------------------------------------------------------- #


class StubOverrideStore:
    """In-memory ``MCPServerUrlOverrideStore`` double. Holds per-(tenant, pack)
    override + records every mutator call for assertion."""

    def __init__(self) -> None:
        self._state: dict[tuple[str, str], str] = {}
        self.set_calls: list[dict[str, Any]] = []
        self.clear_calls: list[dict[str, Any]] = []

    async def get(self, *, tenant_id: str, pack_id: str) -> str | None:
        return self._state.get((tenant_id, pack_id))

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
        self._state[(tenant_id, pack_id)] = server_url
        self.set_calls.append(
            {
                "tenant_id": tenant_id,
                "pack_id": pack_id,
                "server_url": server_url,
                "actor_subject": actor_subject,
                "actor_type": actor_type,
                "request_id": request_id,
            }
        )

    async def clear_override(
        self,
        *,
        tenant_id: str,
        pack_id: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        self._state.pop((tenant_id, pack_id), None)
        self.clear_calls.append(
            {
                "tenant_id": tenant_id,
                "pack_id": pack_id,
                "actor_subject": actor_subject,
                "actor_type": actor_type,
                "request_id": request_id,
            }
        )

    @property
    def mutations(self) -> int:
        return len(self.set_calls) + len(self.clear_calls)


class StubAllowlistStore:
    """In-memory ``MCPInternalHostAllowlistStore`` double. Holds the per-tenant
    exact-IP set + records every add/remove call."""

    def __init__(self) -> None:
        self._state: dict[str, set[str]] = {}
        self.add_calls: list[dict[str, Any]] = []
        self.remove_calls: list[dict[str, Any]] = []
        # Optional injected fault: raise on the Nth add_ip (1-indexed) once.
        self.raise_on_add_call: int | None = None

    async def get_allowlist(self, *, tenant_id: str) -> frozenset[str]:
        return frozenset(self._state.get(tenant_id, set()))

    async def add_ip(
        self,
        *,
        tenant_id: str,
        ip: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        # Record-then-act ordering mirrors the real store: the audited chain row
        # is the side effect we'd lose if a fault fired AFTER the state mutation,
        # so the fault is injected BEFORE the state write to model a clean
        # transactional rollback (no state row, no chain row) like production.
        if self.raise_on_add_call is not None and len(self.add_calls) + 1 == self.raise_on_add_call:
            self.raise_on_add_call = None
            raise RuntimeError("injected add_ip transport failure")
        self._state.setdefault(tenant_id, set()).add(ip)
        self.add_calls.append(
            {
                "tenant_id": tenant_id,
                "ip": ip,
                "actor_subject": actor_subject,
                "actor_type": actor_type,
                "request_id": request_id,
            }
        )

    async def remove_ip(
        self,
        *,
        tenant_id: str,
        ip: str,
        actor_subject: str,
        actor_type: str,
        request_id: str,
    ) -> None:
        self._state.setdefault(tenant_id, set()).discard(ip)
        self.remove_calls.append(
            {
                "tenant_id": tenant_id,
                "ip": ip,
                "actor_subject": actor_subject,
                "actor_type": actor_type,
                "request_id": request_id,
            }
        )

    @property
    def mutations(self) -> int:
        return len(self.add_calls) + len(self.remove_calls)

    def added_ips(self) -> set[str]:
        return {c["ip"] for c in self.add_calls}

    def removed_ips(self) -> set[str]:
        return {c["ip"] for c in self.remove_calls}


class StubConfigStore:
    """In-memory ``PackRuntimeConfigStore`` double — only ``list_for_tenant`` is
    consulted by the materializer (it reads the union of a tenant's records)."""

    def __init__(self, records: list[PackRuntimeConfigRecord] | None = None) -> None:
        self._records: list[PackRuntimeConfigRecord] = list(records or [])

    def set_records(self, records: list[PackRuntimeConfigRecord]) -> None:
        self._records = list(records)

    async def list_for_tenant(self, *, tenant_id: str) -> list[PackRuntimeConfigRecord]:
        return [r for r in self._records if r.tenant_id == tenant_id]


class StubVaultReader:
    """In-memory ``VaultReader`` double. ``read(path)`` returns the configured
    secret mapping, ``None`` for an absent path, or raises a configured fault."""

    def __init__(self, secrets: dict[str, Mapping[str, Any] | None] | None = None) -> None:
        self._secrets: dict[str, Mapping[str, Any] | None] = dict(secrets or {})
        self.raise_for: set[str] = set()
        self.read_paths: list[str] = []
        # A future adapter could do its own validation + raise MaterializeRejected
        # from read(); set this to exercise the materializer's defensive
        # pass-through (the ``except MaterializeRejected: raise`` symmetric-ordering
        # guard) rather than the generic re-wrap-to-unresolved path.
        self.raise_materialize_rejected: MaterializeRejected | None = None

    def put(self, path: str, secret: Mapping[str, Any] | None) -> None:
        self._secrets[path] = secret

    async def read(self, path: str) -> Mapping[str, Any] | None:
        self.read_paths.append(path)
        if self.raise_materialize_rejected is not None:
            raise self.raise_materialize_rejected
        if path in self.raise_for:
            raise RuntimeError(f"injected vault read failure for {path}")
        return self._secrets.get(path)


# --------------------------------------------------------------------------- #
# Fixtures + helpers
# --------------------------------------------------------------------------- #

_OAUTH_REF = "secret/cognic/t1/mcp-oauth/10.42.0.7"
_AS_REF = "secret/cognic/t1/mcp-as-allowlist"

_VALID_OAUTH_SECRET: dict[str, Any] = {
    "client_id": "cid-123",
    "client_secret": "csecret-xyz",
    "auth_method": "client_secret_post",
}
_VALID_AS_SECRET: dict[str, Any] = {"servers": ["https://as.internal.example/token"]}


def _record(
    *,
    tenant_id: str = "t1",
    pack_id: str = "p1",
    server_url_override: str | None = "http://10.42.0.7:8080/mcp",
    internal_host_allowlist: tuple[str, ...] = ("10.42.0.7",),
    oauth_credential_ref: str | None = _OAUTH_REF,
    as_allowlist_ref: str | None = _AS_REF,
    activation_status: str = "configured",
    generation: int = 1,
) -> PackRuntimeConfigRecord:
    return PackRuntimeConfigRecord(
        tenant_id=tenant_id,
        pack_id=pack_id,
        server_url_override=server_url_override,
        internal_host_allowlist=internal_host_allowlist,
        oauth_credential_ref=oauth_credential_ref,
        as_allowlist_ref=as_allowlist_ref,
        activation_status=activation_status,  # type: ignore[arg-type]
        generation=generation,
        set_by_actor="op@bank",
        set_at=datetime.now(UTC),
        last_request_id="rc-prior",
    )


def _materializer(
    *,
    override: StubOverrideStore,
    allowlist: StubAllowlistStore,
    config: StubConfigStore,
    vault: StubVaultReader,
) -> RuntimeConfigMaterializer:
    return RuntimeConfigMaterializer(
        override_store=override,
        allowlist_store=allowlist,
        config_store=config,
        vault_reader=vault,
    )


def _vault_ok() -> StubVaultReader:
    return StubVaultReader({_OAUTH_REF: dict(_VALID_OAUTH_SECRET), _AS_REF: dict(_VALID_AS_SECRET)})


# --------------------------------------------------------------------------- #
# materialize — happy path
# --------------------------------------------------------------------------- #


async def test_materialize_both_refs_valid_sets_override_and_adds_ip() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record()
    config = StubConfigStore([rec])  # current record present (not yet active)
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    result = await mat.materialize(
        record=rec, actor_subject="installer@bank", actor_type="human", request_id="rid-1"
    )

    # Override set to the desired value.
    assert await override.get(tenant_id="t1", pack_id="p1") == "http://10.42.0.7:8080/mcp"
    assert len(override.set_calls) == 1
    assert override.set_calls[0]["request_id"] == "rid-1"
    assert override.set_calls[0]["actor_subject"] == "installer@bank"
    assert override.set_calls[0]["actor_type"] == "human"
    # Exactly the desired IP added; nothing removed.
    assert allowlist.added_ips() == {"10.42.0.7"}
    assert allowlist.removed_ips() == set()
    assert allowlist.add_calls[0]["request_id"] == "rid-1"
    # Result shape.
    assert isinstance(result, MaterializeResult)
    assert result.override_action == "set"
    assert set(result.allowlist_added) == {"10.42.0.7"}
    assert result.allowlist_removed == ()
    assert result.tenant_allowlist_after == frozenset({"10.42.0.7"})


async def test_materialize_uses_registry_server_id_for_override_not_config_record_id() -> None:
    """The runtime-config record is keyed by the lifecycle UUID, but MCPHost
    resolves ``server_url`` overrides by registry ``server_id`` (distribution
    name). Materialize must therefore write the derived override under the
    registry key, not the config-record key."""
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record(pack_id="lifecycle-uuid-123")
    config = StubConfigStore([rec])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    await mat.materialize(
        record=rec,
        derived_pack_id="cognic-tool-oracle-schema",
        actor_subject="installer@bank",
        actor_type="human",
        request_id="rid-derived",
    )

    assert (
        await override.get(tenant_id="t1", pack_id="cognic-tool-oracle-schema")
        == "http://10.42.0.7:8080/mcp"
    )
    assert await override.get(tenant_id="t1", pack_id="lifecycle-uuid-123") is None


async def test_materialize_threads_request_id_to_every_mutator() -> None:
    # P desires two IPs; the override is set + both IPs added — all under one rid.
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record(internal_host_allowlist=("10.42.0.7", "10.42.0.9"))
    config = StubConfigStore([rec])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    await mat.materialize(
        record=rec, actor_subject="installer@bank", actor_type="human", request_id="rid-thread"
    )
    rids = {c["request_id"] for c in override.set_calls} | {
        c["request_id"] for c in allowlist.add_calls
    }
    assert rids == {"rid-thread"}
    assert allowlist.added_ips() == {"10.42.0.7", "10.42.0.9"}


# --------------------------------------------------------------------------- #
# materialize — Vault ref validation (validate-before-write)
# --------------------------------------------------------------------------- #


async def test_materialize_missing_oauth_ref_rejects_and_writes_nothing() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record(oauth_credential_ref=None)
    config = StubConfigStore([rec])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    with pytest.raises(MaterializeRejected) as exc:
        await mat.materialize(
            record=rec, actor_subject="op", actor_type="human", request_id="rid-x"
        )
    assert exc.value.reason == "materialize_vault_ref_unresolved"
    assert override.mutations == 0
    assert allowlist.mutations == 0


async def test_materialize_missing_as_ref_rejects_and_writes_nothing() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record(as_allowlist_ref=None)
    config = StubConfigStore([rec])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    with pytest.raises(MaterializeRejected) as exc:
        await mat.materialize(
            record=rec, actor_subject="op", actor_type="human", request_id="rid-x"
        )
    assert exc.value.reason == "materialize_vault_ref_unresolved"
    assert override.mutations == 0
    assert allowlist.mutations == 0


async def test_materialize_unresolvable_oauth_ref_rejects_and_writes_nothing() -> None:
    # Ref present on the record but ABSENT in Vault (read returns None).
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record()
    config = StubConfigStore([rec])
    vault = StubVaultReader({_OAUTH_REF: None, _AS_REF: dict(_VALID_AS_SECRET)})
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    with pytest.raises(MaterializeRejected) as exc:
        await mat.materialize(
            record=rec, actor_subject="op", actor_type="human", request_id="rid-x"
        )
    assert exc.value.reason == "materialize_vault_ref_unresolved"
    assert "oauth" in str(exc.value).lower()
    assert override.mutations == 0
    assert allowlist.mutations == 0


async def test_materialize_vault_read_exception_maps_to_unresolved() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record()
    config = StubConfigStore([rec])
    vault = _vault_ok()
    vault.raise_for = {_OAUTH_REF}
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    with pytest.raises(MaterializeRejected) as exc:
        await mat.materialize(
            record=rec, actor_subject="op", actor_type="human", request_id="rid-x"
        )
    assert exc.value.reason == "materialize_vault_ref_unresolved"
    assert override.mutations == 0
    assert allowlist.mutations == 0


async def test_materialize_vault_read_raising_materialize_rejected_passes_through() -> None:
    # Symmetric-exception-ordering guard (materializer.py ``except MaterializeRejected:
    # raise``): if the vault_reader ITSELF raises a MaterializeRejected (a future
    # adapter that does its own shape validation could), it propagates UNCHANGED —
    # NOT swallowed + re-wrapped as ``materialize_vault_ref_unresolved`` by the
    # generic ``except Exception``. Pins the pass-through + validate-before-write.
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record()
    config = StubConfigStore([rec])
    vault = _vault_ok()
    sentinel = MaterializeRejected("materialize_vault_ref_malformed", "adapter-side rejection")
    vault.raise_materialize_rejected = sentinel
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    with pytest.raises(MaterializeRejected) as exc:
        await mat.materialize(
            record=rec, actor_subject="op", actor_type="human", request_id="rid-x"
        )
    # Propagated UNCHANGED (same object) — NOT re-wrapped to _unresolved.
    assert exc.value is sentinel
    assert exc.value.reason == "materialize_vault_ref_malformed"
    assert override.mutations == 0
    assert allowlist.mutations == 0


@pytest.mark.parametrize(
    "bad_oauth",
    [
        {},  # empty
        {"client_id": "cid"},  # missing client_secret
        {"client_secret": "sec"},  # missing client_id
        {"client_id": "", "client_secret": "sec"},  # blank client_id
        {"client_id": "cid", "client_secret": ""},  # blank client_secret
        {"client_id": "   ", "client_secret": "sec"},  # whitespace-only client_id
        {"client_id": "cid", "client_secret": "   "},  # whitespace-only client_secret
        {"client_id": 123, "client_secret": "sec"},  # non-str client_id
        {"client_id": "cid", "client_secret": "sec", "auth_method": "bogus"},  # bad auth_method
    ],
)
async def test_materialize_malformed_oauth_ref_rejects(bad_oauth: dict[str, Any]) -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record()
    config = StubConfigStore([rec])
    vault = StubVaultReader({_OAUTH_REF: bad_oauth, _AS_REF: dict(_VALID_AS_SECRET)})
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    with pytest.raises(MaterializeRejected) as exc:
        await mat.materialize(
            record=rec, actor_subject="op", actor_type="human", request_id="rid-x"
        )
    assert exc.value.reason == "materialize_vault_ref_malformed"
    assert "oauth" in str(exc.value).lower()
    assert override.mutations == 0
    assert allowlist.mutations == 0


async def test_materialize_accepts_oauth_without_auth_method() -> None:
    # auth_method is OPTIONAL — absence is valid.
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record()
    config = StubConfigStore([rec])
    vault = StubVaultReader(
        {
            _OAUTH_REF: {"client_id": "cid", "client_secret": "sec"},
            _AS_REF: dict(_VALID_AS_SECRET),
        }
    )
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    result = await mat.materialize(
        record=rec, actor_subject="op", actor_type="human", request_id="rid-ok"
    )
    assert result.override_action == "set"


async def test_materialize_accepts_oauth_with_client_secret_basic() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record()
    config = StubConfigStore([rec])
    vault = StubVaultReader(
        {
            _OAUTH_REF: {
                "client_id": "cid",
                "client_secret": "sec",
                "auth_method": "client_secret_basic",
            },
            _AS_REF: dict(_VALID_AS_SECRET),
        }
    )
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)
    result = await mat.materialize(
        record=rec, actor_subject="op", actor_type="human", request_id="rid-ok"
    )
    assert result.override_action == "set"


@pytest.mark.parametrize(
    "bad_as",
    [
        {},  # missing servers
        {"servers": []},  # empty list
        {"servers": "https://as"},  # not a list
        {"servers": ["https://as", ""]},  # blank entry
        {"servers": ["https://as", "   "]},  # whitespace entry
        {"servers": [123]},  # non-str entry
    ],
)
async def test_materialize_malformed_as_ref_rejects(bad_as: dict[str, Any]) -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record()
    config = StubConfigStore([rec])
    vault = StubVaultReader({_OAUTH_REF: dict(_VALID_OAUTH_SECRET), _AS_REF: bad_as})
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    with pytest.raises(MaterializeRejected) as exc:
        await mat.materialize(
            record=rec, actor_subject="op", actor_type="human", request_id="rid-x"
        )
    assert exc.value.reason == "materialize_vault_ref_malformed"
    assert "as" in str(exc.value).lower()
    assert override.mutations == 0
    assert allowlist.mutations == 0


# --------------------------------------------------------------------------- #
# materialize — idempotency
# --------------------------------------------------------------------------- #


async def test_materialize_is_idempotent_second_run_zero_mutations() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record(internal_host_allowlist=("10.42.0.7", "10.42.0.9"))
    config = StubConfigStore([rec])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    await mat.materialize(record=rec, actor_subject="op", actor_type="human", request_id="rid-1")
    first_override = override.mutations
    first_allowlist = allowlist.mutations
    assert first_override == 1
    assert first_allowlist == 2

    # Second run with the SAME stubbed state → check-before-write → zero new
    # mutations (no duplicate override set, no duplicate add_ip).
    result2 = await mat.materialize(
        record=rec, actor_subject="op", actor_type="human", request_id="rid-2"
    )
    assert override.mutations == first_override
    assert allowlist.mutations == first_allowlist
    assert result2.override_action == "unchanged"
    assert result2.allowlist_added == ()
    assert result2.allowlist_removed == ()


# --------------------------------------------------------------------------- #
# materialize — override reconcile (set / clear / no-op)
# --------------------------------------------------------------------------- #


async def test_materialize_override_none_clears_existing_derived_override() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    # A derived override already exists, but the desired record carries None.
    await override.set_override(
        tenant_id="t1",
        pack_id="p1",
        server_url="http://10.42.0.7:8080/mcp",
        actor_subject="seed",
        actor_type="human",
        request_id="seed",
    )
    seed_clears = len(override.clear_calls)
    rec = _record(server_url_override=None)
    config = StubConfigStore([rec])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    result = await mat.materialize(
        record=rec, actor_subject="op", actor_type="human", request_id="rid-clr"
    )
    assert await override.get(tenant_id="t1", pack_id="p1") is None
    assert len(override.clear_calls) == seed_clears + 1
    assert result.override_action == "cleared"


async def test_materialize_override_changed_calls_set() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    await override.set_override(
        tenant_id="t1",
        pack_id="p1",
        server_url="http://10.42.0.7:8080/mcp",
        actor_subject="seed",
        actor_type="human",
        request_id="seed",
    )
    rec = _record(server_url_override="http://10.42.0.8:9090/mcp")
    config = StubConfigStore([rec])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    result = await mat.materialize(
        record=rec, actor_subject="op", actor_type="human", request_id="rid-chg"
    )
    assert await override.get(tenant_id="t1", pack_id="p1") == "http://10.42.0.8:9090/mcp"
    assert result.override_action == "set"


async def test_materialize_override_unchanged_is_noop() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    await override.set_override(
        tenant_id="t1",
        pack_id="p1",
        server_url="http://10.42.0.7:8080/mcp",
        actor_subject="seed",
        actor_type="human",
        request_id="seed",
    )
    seed_sets = len(override.set_calls)
    rec = _record(server_url_override="http://10.42.0.7:8080/mcp")  # identical
    config = StubConfigStore([rec])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    result = await mat.materialize(
        record=rec, actor_subject="op", actor_type="human", request_id="rid-noop"
    )
    assert len(override.set_calls) == seed_sets  # NO new set
    assert override.clear_calls == []
    assert result.override_action == "unchanged"


async def test_materialize_override_none_when_no_derived_is_noop() -> None:
    # desired override None + no derived override → no-op (no clear emitted).
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    rec = _record(server_url_override=None)
    config = StubConfigStore([rec])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    result = await mat.materialize(
        record=rec, actor_subject="op", actor_type="human", request_id="rid-noop2"
    )
    assert override.mutations == 0
    assert result.override_action == "unchanged"


# --------------------------------------------------------------------------- #
# materialize — union allow-list target across active configs
# --------------------------------------------------------------------------- #


async def test_materialize_union_target_includes_other_active_pack_ips() -> None:
    # Pack Q already active with {ipQ}; the tenant derived allow-list already has
    # ipQ. Materializing P (desires {ipP}) converges the allow-list to the union
    # of {ipQ} and {ipP} — ipP added, ipQ untouched.
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    await allowlist.add_ip(
        tenant_id="t1",
        ip="10.42.0.50",
        actor_subject="seed",
        actor_type="human",
        request_id="seed",
    )
    q = _record(pack_id="q", internal_host_allowlist=("10.42.0.50",), activation_status="active")
    p = _record(pack_id="p1", internal_host_allowlist=("10.42.0.7",))
    config = StubConfigStore([q, p])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    result = await mat.materialize(
        record=p, actor_subject="op", actor_type="human", request_id="rid-union"
    )
    assert await allowlist.get_allowlist(tenant_id="t1") == frozenset({"10.42.0.50", "10.42.0.7"})
    assert result.allowlist_added == ("10.42.0.7",)
    assert "10.42.0.50" not in allowlist.removed_ips()
    assert result.tenant_allowlist_after == frozenset({"10.42.0.50", "10.42.0.7"})


async def test_materialize_does_not_count_disabled_pack_ips_in_union() -> None:
    # A disabled pack's IPs are NOT part of the union target — but the current
    # record being materialized IS included explicitly (it may not be active yet).
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    # Stale derived row for a now-disabled pack's IP — materialize should remove it.
    await allowlist.add_ip(
        tenant_id="t1",
        ip="10.42.0.99",
        actor_subject="seed",
        actor_type="human",
        request_id="seed",
    )
    disabled = _record(
        pack_id="old", internal_host_allowlist=("10.42.0.99",), activation_status="disabled"
    )
    p = _record(pack_id="p1", internal_host_allowlist=("10.42.0.7",))
    config = StubConfigStore([disabled, p])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    await mat.materialize(record=p, actor_subject="op", actor_type="human", request_id="rid-d")
    after = await allowlist.get_allowlist(tenant_id="t1")
    assert after == frozenset({"10.42.0.7"})  # 10.42.0.99 removed (disabled, not in union)


# --------------------------------------------------------------------------- #
# retract
# --------------------------------------------------------------------------- #


async def test_retract_clears_override_and_removes_pack_ips() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    await override.set_override(
        tenant_id="t1",
        pack_id="p1",
        server_url="http://10.42.0.7:8080/mcp",
        actor_subject="seed",
        actor_type="human",
        request_id="seed",
    )
    await allowlist.add_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="seed",
        actor_type="human",
        request_id="seed",
    )
    # P is the only config; after retract its IP is no longer in any active union.
    p = _record(pack_id="p1", internal_host_allowlist=("10.42.0.7",), activation_status="disabled")
    config = StubConfigStore([p])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    await mat.retract(
        tenant_id="t1", pack_id="p1", actor_subject="op", actor_type="human", request_id="rid-ret"
    )
    assert await override.get(tenant_id="t1", pack_id="p1") is None
    assert len(override.clear_calls) == 1
    assert await allowlist.get_allowlist(tenant_id="t1") == frozenset()
    assert allowlist.removed_ips() == {"10.42.0.7"}


async def test_retract_is_idempotent_on_empty_state() -> None:
    # Re-running retract on an already-empty derived state → zero mutations.
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    p = _record(pack_id="p1", internal_host_allowlist=("10.42.0.7",), activation_status="revoked")
    config = StubConfigStore([p])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    await mat.retract(
        tenant_id="t1", pack_id="p1", actor_subject="op", actor_type="human", request_id="rid-1"
    )
    assert override.mutations == 0
    assert allowlist.mutations == 0
    # Second run: still zero.
    await mat.retract(
        tenant_id="t1", pack_id="p1", actor_subject="op", actor_type="human", request_id="rid-2"
    )
    assert override.mutations == 0
    assert allowlist.mutations == 0


async def test_retract_clears_registry_server_id_override_not_config_record_id() -> None:
    """Retract has the same split as materialize: the active-config union uses
    the lifecycle/config key, while the derived override row is keyed by the
    registry server id."""
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    await override.set_override(
        tenant_id="t1",
        pack_id="cognic-tool-oracle-schema",
        server_url="http://10.42.0.7:8080/mcp",
        actor_subject="seed",
        actor_type="human",
        request_id="seed",
    )
    await allowlist.add_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="seed",
        actor_type="human",
        request_id="seed",
    )
    p = _record(
        pack_id="lifecycle-uuid-123",
        internal_host_allowlist=("10.42.0.7",),
        activation_status="disabled",
    )
    config = StubConfigStore([p])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    await mat.retract(
        tenant_id="t1",
        config_pack_id="lifecycle-uuid-123",
        derived_pack_id="cognic-tool-oracle-schema",
        actor_subject="op",
        actor_type="human",
        request_id="rid-ret",
    )

    assert await override.get(tenant_id="t1", pack_id="cognic-tool-oracle-schema") is None
    assert await allowlist.get_allowlist(tenant_id="t1") == frozenset()


async def test_retract_requires_a_pack_key() -> None:
    mat = _materializer(
        override=StubOverrideStore(),
        allowlist=StubAllowlistStore(),
        config=StubConfigStore(),
        vault=_vault_ok(),
    )

    with pytest.raises(TypeError, match="retract requires pack_id"):
        await mat.retract(
            tenant_id="t1",
            actor_subject="op",
            actor_type="human",
            request_id="rid-ret",
        )


async def test_retract_threads_request_id() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    await override.set_override(
        tenant_id="t1",
        pack_id="p1",
        server_url="http://10.42.0.7:8080/mcp",
        actor_subject="seed",
        actor_type="human",
        request_id="seed",
    )
    await allowlist.add_ip(
        tenant_id="t1",
        ip="10.42.0.7",
        actor_subject="seed",
        actor_type="human",
        request_id="seed",
    )
    p = _record(pack_id="p1", internal_host_allowlist=("10.42.0.7",), activation_status="disabled")
    config = StubConfigStore([p])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    await mat.retract(
        tenant_id="t1",
        pack_id="p1",
        actor_subject="retractor@bank",
        actor_type="human",
        request_id="rid-ret",
    )
    assert override.clear_calls[0]["request_id"] == "rid-ret"
    assert override.clear_calls[0]["actor_subject"] == "retractor@bank"
    assert allowlist.remove_calls[0]["request_id"] == "rid-ret"


# --------------------------------------------------------------------------- #
# Tenant-union REGRESSION #1 — shared IP across two active packs
# --------------------------------------------------------------------------- #


async def test_retract_shared_ip_remains_while_other_active() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    shared = "10.42.0.77"
    await allowlist.add_ip(
        tenant_id="t1",
        ip=shared,
        actor_subject="seed",
        actor_type="human",
        request_id="seed",
    )
    a = _record(pack_id="a", internal_host_allowlist=(shared,), activation_status="active")
    b = _record(pack_id="b", internal_host_allowlist=(shared,), activation_status="active")
    config = StubConfigStore([a, b])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    # retract(A): B still active with the shared IP → IP REMAINS.
    await mat.retract(
        tenant_id="t1", pack_id="a", actor_subject="op", actor_type="human", request_id="rid-a"
    )
    assert await allowlist.get_allowlist(tenant_id="t1") == frozenset({shared})
    assert shared not in allowlist.removed_ips()

    # Now A is disabled in the config store + retract(B) → no active pack holds it.
    config.set_records(
        [
            _record(pack_id="a", internal_host_allowlist=(shared,), activation_status="disabled"),
            _record(pack_id="b", internal_host_allowlist=(shared,), activation_status="disabled"),
        ]
    )
    await mat.retract(
        tenant_id="t1", pack_id="b", actor_subject="op", actor_type="human", request_id="rid-b"
    )
    assert await allowlist.get_allowlist(tenant_id="t1") == frozenset()
    assert shared in allowlist.removed_ips()


# --------------------------------------------------------------------------- #
# Tenant-union REGRESSION #2 — distinct IPs across two active packs
# --------------------------------------------------------------------------- #


async def test_retract_distinct_ips_only_removes_packs_own() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    ip_a, ip_b = "10.42.0.10", "10.42.0.20"
    for ip in (ip_a, ip_b):
        await allowlist.add_ip(
            tenant_id="t1",
            ip=ip,
            actor_subject="seed",
            actor_type="human",
            request_id="seed",
        )
    a = _record(pack_id="a", internal_host_allowlist=(ip_a,), activation_status="active")
    b = _record(pack_id="b", internal_host_allowlist=(ip_b,), activation_status="active")
    config = StubConfigStore([a, b])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    # retract(A): only ipA removed; ipB remains (B still active).
    await mat.retract(
        tenant_id="t1", pack_id="a", actor_subject="op", actor_type="human", request_id="rid-a"
    )
    assert await allowlist.get_allowlist(tenant_id="t1") == frozenset({ip_b})
    assert allowlist.removed_ips() == {ip_a}


# --------------------------------------------------------------------------- #
# Partial-failure recovery — a re-run converges (fail-closed property)
# --------------------------------------------------------------------------- #


async def test_materialize_partial_failure_recovers_on_rerun() -> None:
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    # Two desired IPs; the FIRST add_ip raises → the allow-list reconcile (Step 2)
    # fails BEFORE the override (Step 3, the exposure step) is reached.
    allowlist.raise_on_add_call = 1
    rec = _record(internal_host_allowlist=("10.42.0.7", "10.42.0.9"))
    config = StubConfigStore([rec])
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    with pytest.raises(RuntimeError, match="injected add_ip transport failure"):
        await mat.materialize(
            record=rec, actor_subject="op", actor_type="human", request_id="rid-1"
        )
    # FAIL-CLOSED BY ORDERING: the allow-list reconcile runs FIRST, so its failure
    # leaves the override UNSET → the pack is never repointed → not callable.
    assert override.mutations == 0
    after_partial = await allowlist.get_allowlist(tenant_id="t1")
    assert after_partial != frozenset({"10.42.0.7", "10.42.0.9"})  # NOT converged yet

    # Re-run with a healthy stub → idempotent recovery converges the allow-list AND
    # NOW lands the override (the exposure step) once every permit is in place.
    result = await mat.materialize(
        record=rec, actor_subject="op", actor_type="human", request_id="rid-2"
    )
    assert await allowlist.get_allowlist(tenant_id="t1") == frozenset({"10.42.0.7", "10.42.0.9"})
    assert override.mutations == 1  # override lands on the recovering re-run
    assert await override.get(tenant_id="t1", pack_id="p1") == "http://10.42.0.7:8080/mcp"
    # The re-run only added what was MISSING (idempotent — no duplicate adds for
    # an IP that already landed before the fault).
    assert set(result.allowlist_added) <= {"10.42.0.7", "10.42.0.9"}
    assert result.tenant_allowlist_after == frozenset({"10.42.0.7", "10.42.0.9"})


async def test_materialize_shared_ip_present_but_allowlist_failure_leaves_override_unset() -> None:
    # P1 fail-closed-by-ordering regression: P desires a SHARED IP already
    # tenant-allow-listed by an active sibling Q, PLUS a NEW IP whose add fails.
    # The override (the exposure step) must NOT land — so P is not callable via its
    # override even though its shared IP is already permitted. (Under an
    # override-FIRST ordering this assertion would FAIL — the override would land
    # before the allow-list reconcile failed.)
    override = StubOverrideStore()
    allowlist = StubAllowlistStore()
    shared_ip = "10.42.0.7"
    new_ip = "10.42.0.9"
    q = _record(pack_id="q", internal_host_allowlist=(shared_ip,), activation_status="active")
    p = _record(pack_id="p", internal_host_allowlist=(shared_ip, new_ip))
    config = StubConfigStore([q, p])
    # Seed the derived allow-list with Q's shared IP (Q is active + materialized),
    # then reset the recorded adds so the injected fault targets P's first add.
    await allowlist.add_ip(
        tenant_id="t1", ip=shared_ip, actor_subject="q", actor_type="human", request_id="q-rid"
    )
    allowlist.add_calls.clear()
    allowlist.raise_on_add_call = 1
    vault = _vault_ok()
    mat = _materializer(override=override, allowlist=allowlist, config=config, vault=vault)

    with pytest.raises(RuntimeError, match="injected add_ip transport failure"):
        await mat.materialize(record=p, actor_subject="op", actor_type="human", request_id="rid-p")
    # The override never landed (P not repointed → not callable), even though P's
    # shared IP is in the tenant allow-list from Q.
    assert override.mutations == 0
    assert await override.get(tenant_id="t1", pack_id="p") is None
    # Q's shared IP remains; P's new_ip never landed (the failing add).
    assert await allowlist.get_allowlist(tenant_id="t1") == frozenset({shared_ip})


# --------------------------------------------------------------------------- #
# AST self-test — the materializer must NOT import mcp_authz
# --------------------------------------------------------------------------- #


def test_materializer_module_does_not_import_mcp_authz() -> None:
    """The materializer projects into the derived carve-out STORES only; it must
    never reach into ``protocol/mcp_authz`` (which READS those derived rows). An
    import would couple the desired→derived projection to the read path and risk
    a circular dependency. Pinned by an AST walk of every import form."""
    module_path = Path("src/cognic_agentos/core/mcp_config/materializer.py")
    tree = ast.parse(module_path.read_text())
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod:
                imported.append(mod)
            imported.extend(f"{mod}.{alias.name}" if mod else alias.name for alias in node.names)
    offenders = [m for m in imported if "mcp_authz" in m]
    assert offenders == [], (
        f"materializer.py imports mcp_authz {offenders!r}; the materializer must "
        f"project into the derived STORES only (mcp_authz READS those rows). "
        f"Remove the import — desired→derived projection must not couple to the "
        f"read path."
    )


# --------------------------------------------------------------------------- #
# Closed-enum count guard (via typing.get_args — NOT regex)
# --------------------------------------------------------------------------- #


def test_materialize_refusal_reason_enum_is_closed_two_values() -> None:
    assert set(get_args(MaterializeRefusalReason)) == {
        "materialize_vault_ref_unresolved",
        "materialize_vault_ref_malformed",
    }
    assert len(get_args(MaterializeRefusalReason)) == 2
