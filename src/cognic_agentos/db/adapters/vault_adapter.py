"""VaultAdapter — SecretAdapter via hvac (per ADR-009 + BUILD_PLAN).

Driver name: ``vault``. Auto-registers into ``bundled_registry`` on import.

hvac is the standard Python client for HashiCorp Vault. It is synchronous,
so every blocking call is wrapped with ``asyncio.to_thread`` to keep the
FastAPI event loop cooperative. The hvac.Client instance is created lazily
on first use so adapter construction remains side-effect-free (the
constructor never opens a network connection).
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import hvac

from cognic_agentos.db.adapters.protocols import AdapterHealth, SecretLease
from cognic_agentos.db.adapters.registry import bundled_registry


class VaultAdapter:
    driver = "vault"

    def __init__(
        self,
        addr: str | None,
        token: str | None,
        namespace: str | None,
    ) -> None:
        if not addr:
            raise ValueError("VaultAdapter requires vault_addr; got empty/None")
        self._addr = addr.rstrip("/")
        self._token = token
        self._namespace = namespace
        self._client: hvac.Client | None = None

    def _ensure_client(self) -> hvac.Client:
        if self._client is None:
            self._client = hvac.Client(
                url=self._addr,
                token=self._token,
                namespace=self._namespace,
            )
        return self._client

    async def read(self, path: str) -> dict[str, Any]:
        def _read() -> dict[str, Any]:
            client = self._ensure_client()
            resp = client.read(path)
            if resp is None:
                raise KeyError(path)
            data = resp.get("data", {})
            # KV v2 nests under data/data; KV v1 returns under data
            if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict):
                return dict(data["data"])
            return dict(data)

        return await asyncio.to_thread(_read)

    async def write(self, path: str, value: dict[str, Any]) -> None:
        def _write() -> None:
            client = self._ensure_client()
            # KV v2 paths look like "<mount>/data/<key>" and require a
            # ``data={...}`` envelope on the request body. KV v1 paths
            # take the value as raw kwargs. Symmetric with read(): same
            # detection rule (presence of ``/data/`` segment).
            if "/data/" in path:
                client.write(path, data=value)
            else:
                client.write(path, **value)

        await asyncio.to_thread(_write)

    async def lease(self, path: str, ttl_s: int) -> SecretLease:
        def _lease() -> SecretLease:
            client = self._ensure_client()
            resp = client.read(path)
            if resp is None:
                raise KeyError(path)
            return SecretLease(
                lease_id=resp.get("lease_id", ""),
                ttl_s=int(resp.get("lease_duration", ttl_s)),
                value=dict(resp.get("data", {})),
            )

        return await asyncio.to_thread(_lease)

    async def revoke(self, lease_id: str) -> None:
        def _revoke() -> None:
            client = self._ensure_client()
            client.sys.revoke_lease(lease_id=lease_id)

        await asyncio.to_thread(_revoke)

    async def health_check(self) -> AdapterHealth:
        start = time.perf_counter()

        def _probe() -> dict[str, Any]:
            client = self._ensure_client()
            return dict(client.sys.read_health_status(method="GET") or {})

        try:
            status = await asyncio.to_thread(_probe)
        except Exception as exc:
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail=type(exc).__name__,
            )

        if not status.get("initialized", False):
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail="vault not initialized",
            )
        if status.get("sealed", True):
            return AdapterHealth(
                status="unreachable",
                driver=self.driver,
                detail="vault sealed",
            )
        return AdapterHealth(
            status="ok",
            driver=self.driver,
            latency_ms=(time.perf_counter() - start) * 1000.0,
        )


bundled_registry.register("secret", "vault", VaultAdapter)
