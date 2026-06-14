"""Sprint 14A-A — harness/sandbox.py composition helpers.

is_sandbox_available() DockerSibling-only matrix + the PackRecordStoreLoader
conformer projection + build_sandbox_backend()'s vault-addr precondition guard
and its no-client-leak-on-internal-failure contract. (asyncio_mode=auto, mixed
sync/async tests, so no module-level marker.)
"""

from __future__ import annotations

import builtins
import sys
import uuid
from typing import Any

import pytest

from cognic_agentos.core.config import Settings
from cognic_agentos.core.run.executor import LoadedPackRecord
from cognic_agentos.harness.sandbox import (
    PackRecordStoreLoader,
    build_sandbox_backend,
    is_sandbox_available,
)


def test_is_sandbox_available_true_for_docker_sibling_with_aiodocker() -> None:
    # aiodocker IS in the uv venv (adapters extra) -> docker_sibling is available.
    assert is_sandbox_available(Settings(sandbox_backend="docker_sibling")) is True


def test_is_sandbox_available_false_for_kubernetes_pod_in_14a_a() -> None:
    # 14A-A is DockerSibling-only; kubernetes_pod is deferred -> False.
    assert is_sandbox_available(Settings(sandbox_backend="kubernetes_pod")) is False


def test_is_sandbox_available_false_when_aiodocker_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    real_import = builtins.__import__

    def _fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "aiodocker" or name.startswith("aiodocker."):
            raise ImportError("simulated missing aiodocker")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    monkeypatch.delitem(sys.modules, "aiodocker", raising=False)
    assert is_sandbox_available(Settings(sandbox_backend="docker_sibling")) is False


class _StubPackRecord:
    def __init__(self, **kw: Any) -> None:
        self.__dict__.update(kw)


class _StubStore:
    def __init__(self, record: Any) -> None:
        self._record = record
        self.loaded: list[uuid.UUID] = []

    async def load(self, pack_id: uuid.UUID) -> Any:
        self.loaded.append(pack_id)
        return self._record


async def test_pack_record_store_loader_projects_record() -> None:
    rec = _StubPackRecord(
        tenant_id="tenant-a",
        pack_id="cognic-tool-foo",
        kind="tool",
        signed_artefact_digest=b"\xab" * 32,
        state="installed",
    )
    store = _StubStore(rec)
    loader = PackRecordStoreLoader(store=store)  # type: ignore[arg-type]
    pk = uuid.uuid4()
    out = await loader.load_for_run(pack_uuid=pk)
    assert out == LoadedPackRecord(
        tenant_id="tenant-a",
        pack_id="cognic-tool-foo",
        kind="tool",
        signed_artefact_digest=b"\xab" * 32,
        state="installed",
    )
    assert store.loaded == [pk]  # direct uuid load, no tenant scan


async def test_pack_record_store_loader_returns_none_on_missing() -> None:
    store = _StubStore(None)
    loader = PackRecordStoreLoader(store=store)  # type: ignore[arg-type]
    assert await loader.load_for_run(pack_uuid=uuid.uuid4()) is None


class _Runtime:
    audit_store = object()
    decision_history_store = object()


async def test_build_sandbox_backend_fail_softs_without_vault_addr() -> None:
    # vault_addr unset -> RuntimeError (the lifespan catches it -> fail-soft).
    s = Settings(sandbox_backend="docker_sibling", vault_addr=None)
    with pytest.raises(RuntimeError, match="vault_addr"):
        await build_sandbox_backend(settings=s, runtime=_Runtime())  # type: ignore[arg-type]


async def test_build_sandbox_backend_closes_client_on_internal_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The just-created docker client is closed before re-raise when an internal
    # step fails (no leak). aiodocker.Docker -> a spy; OPAEngine.create -> raises.
    from unittest.mock import AsyncMock

    closed = {"v": False}

    class _FakeClient:
        async def close(self) -> None:
            closed["v"] = True

    monkeypatch.setattr("aiodocker.Docker", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(
        "cognic_agentos.core.policy.engine.OPAEngine.create",
        AsyncMock(side_effect=RuntimeError("opa down")),
    )
    s = Settings(sandbox_backend="docker_sibling", vault_addr="http://vault:8200")
    with pytest.raises(RuntimeError, match="opa down"):
        await build_sandbox_backend(settings=s, runtime=_Runtime())  # type: ignore[arg-type]
    assert closed["v"] is True  # client closed before the re-raise
