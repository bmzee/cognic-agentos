"""VaultAdapter — SecretAdapter consuming the shared core/_vault_transport.

Driver name: ``vault``. Auto-registers into ``bundled_registry`` on import.

Sprint 10 T3 refactor — the adapter delegates ALL hvac mechanics through
the Sprint 10 shared :class:`cognic_agentos.core._vault_transport.VaultTransport`
(see ADR-009 + the Sprint 10 spec at
``docs/superpowers/specs/2026-05-23-sprint-10-vault-credential-leasing-design.md``).
Both this adapter (kernel-secrets fetch) AND the Sprint 10
:class:`cognic_agentos.sandbox.credentials.VaultCredentialAdapter`
(T6 — dynamic credential leasing) share the same VaultTransport when
``create_app`` wires them with one shared instance: one hvac.Client,
one static-token auth context, one retry discipline.

T3 user-locked carve-out: ``VaultAdapter.lease()`` MUST funnel
through ``transport.read(path)`` (NOT ``transport.lease(path, ttl_s)``)
to preserve the Sprint-1C wire contract (the response is wrapped in
a Sprint-1C :class:`SecretLease` shape). ``transport.lease`` is the
T4-consumer API that wraps the raw hvac response in
:class:`cognic_agentos.core.vault.CredentialLease` for the dynamic-
secret leasing path at ``core/vault.py::lease_credential``; the
kernel-secrets adapter MUST NOT switch to it without an explicit
ADR amendment. Post-Z2-Gap-Q (Sprint 10 round-9, 2026-05-24) both
``transport.read`` and ``transport.lease`` delegate to
``client.read(path)`` at the hvac level — the carve-out remains
load-bearing because the two transport methods exist to give the
two distinct consumer-shape contracts (SecretLease vs CredentialLease)
independent forward-evolution surfaces (e.g. future PKI write-style
support lands as a separate transport method, not a runtime
overload of ``lease()``).

T3 health mapping (R3 contract preservation): the adapter maps the
4-state :class:`cognic_agentos.core._vault_transport.VaultTransportProbe`
returned by ``transport.health_check()`` to the existing
``AdapterHealth`` shape, preserving the Sprint-1C detail strings
pinned at ``tests/unit/db/test_vault_adapter.py::TestHealth``
(``"vault not initialized"`` / ``"vault sealed"`` / exception
class name / ``ok`` + ``latency_ms``).

Backward-compat: the 3-arg constructor (``addr``, ``token``,
``namespace``) keeps working — when ``transport=None`` the adapter
lazily mints one internally on first method call, preserving the
Sprint-1C side-effect-free-constructor invariant.
"""

from __future__ import annotations

import time
from typing import Any

from cognic_agentos.core._vault_transport import VaultTransport
from cognic_agentos.db.adapters.protocols import AdapterHealth, SecretLease
from cognic_agentos.db.adapters.registry import bundled_registry


class VaultAdapter:
    driver = "vault"

    def __init__(
        self,
        addr: str | None,
        token: str | None,
        namespace: str | None,
        *,
        transport: VaultTransport | None = None,
    ) -> None:
        if not addr:
            raise ValueError("VaultAdapter requires vault_addr; got empty/None")
        self._addr = addr.rstrip("/")
        self._token = token
        self._namespace = namespace
        # Sprint 10 T3 — optional shared VaultTransport injection. When
        # None, lazily build on first method call (preserves the
        # Sprint-1C side-effect-free-constructor contract; out-of-tree
        # consumers that construct with the 3-arg form keep working).
        self._transport = transport

    def _ensure_transport(self) -> VaultTransport:
        if self._transport is None:
            # Adapter-side defaults: matches the Sprint-1C convention
            # (10s timeout; 3 retries). When a shared transport IS
            # injected via create_app the operator-tuned Settings
            # values flow through; the adapter-side defaults here
            # only apply to the legacy 3-arg construction path.
            self._transport = VaultTransport(
                vault_addr=self._addr,
                vault_token=self._token,
                vault_namespace=self._namespace,
                timeout_s=10.0,
                max_retries=3,
            )
        return self._transport

    async def read(self, path: str) -> dict[str, Any]:
        resp = await self._ensure_transport().read(path)
        if resp is None:
            raise KeyError(path)
        data = resp.get("data", {})
        # KV v2 nests under data/data; KV v1 returns under data.
        # Adapter-layer normalisation; the transport stays raw per
        # spec §2.3 to keep the shared transport agnostic.
        if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
            return dict(data["data"])
        return dict(data)

    async def write(self, path: str, value: dict[str, Any]) -> None:
        # KV v2 paths look like "<mount>/data/<key>" and require a
        # ``data={...}`` envelope on the request body. KV v1 paths
        # take the value as raw kwargs. Symmetric with read(): same
        # detection rule (presence of ``/data/`` segment).
        if "/data/" in path:
            await self._ensure_transport().write(path, {"data": value})
        else:
            await self._ensure_transport().write(path, value)

    async def lease(self, path: str, ttl_s: int) -> SecretLease:
        # Sprint 10 T3 USER-LOCKED CARVE-OUT: lease() funnels through
        # transport.read(), NOT transport.lease(), to preserve the
        # Sprint-1C wire contract (response wrapped in the Sprint-1C
        # SecretLease shape below). transport.lease() is the T4-
        # consumer API that wraps the raw hvac response in
        # core.vault.CredentialLease for the dynamic-secret leasing
        # path at core/vault.py::lease_credential; switching to it
        # here would change the Sprint-1C semantic + break the pinned
        # TestLeaseRevoke::test_lease assertion. Post-Z2-Gap-Q (Sprint
        # 10 round-9, 2026-05-24) both transport.read + transport.lease
        # delegate to client.read(path) at the hvac level — the carve-
        # out remains load-bearing because the two transport methods
        # give the two distinct consumer-shape contracts independent
        # forward-evolution surfaces. Pinned by
        # test_lease_uses_transport_read_not_transport_lease at T3.
        resp = await self._ensure_transport().read(path)
        if resp is None:
            raise KeyError(path)
        return SecretLease(
            lease_id=resp.get("lease_id", ""),
            ttl_s=int(resp.get("lease_duration", ttl_s)),
            value=dict(resp.get("data", {})),
        )

    async def revoke(self, lease_id: str) -> None:
        await self._ensure_transport().revoke(lease_id)

    async def health_check(self) -> AdapterHealth:
        # Sprint 10 T3 R3 health mapping — the 4-state
        # VaultTransportProbe returned by the transport is mapped to
        # the Sprint-1C-pinned AdapterHealth strings. Pinned by
        # test_health_check_maps_all_4_probe_states at T3 +
        # TestHealth.* at Sprint 1C.
        start = time.perf_counter()
        probe = await self._ensure_transport().health_check()
        latency_ms = (time.perf_counter() - start) * 1000.0
        if probe.ok:
            return AdapterHealth(
                status="ok",
                driver=self.driver,
                latency_ms=latency_ms,
            )
        if probe.reason == "vault_not_initialized":
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail="vault not initialized",
            )
        if probe.reason == "vault_sealed":
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail="vault sealed",
            )
        # error_class case (or any other VaultTransportProbe state)
        return AdapterHealth(
            status="unreachable",
            driver=self.driver,
            detail=probe.error_class,
        )


bundled_registry.register("secret", "vault", VaultAdapter)
