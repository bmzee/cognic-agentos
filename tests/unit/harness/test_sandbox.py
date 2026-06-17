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


class _StubSubmitRow:
    # find_latest_submit_row reads .decision_type + .payload (pure-functional, no isinstance).
    def __init__(self, manifest: object | None) -> None:
        self.decision_type = "pack.lifecycle.submitted"
        self.payload = {} if manifest is None else {"manifest": manifest}


class _StubStore:
    def __init__(self, record: Any, *, history: list[Any] | None = None) -> None:
        self._record = record
        self._history = history if history is not None else []
        self.loaded: list[uuid.UUID] = []

    async def load(self, pack_id: uuid.UUID) -> Any:
        self.loaded.append(pack_id)
        return self._record

    async def load_lifecycle_history(self, pack_id: uuid.UUID) -> list[Any]:
        return self._history


def _installed_pack_record() -> _StubPackRecord:
    return _StubPackRecord(
        tenant_id="tenant-a",
        pack_id="cognic-tool-foo",
        kind="tool",
        signed_artefact_digest=b"\xab" * 32,
        state="installed",
    )


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
        risk_tier=None,
        data_classes=(),
    )
    assert store.loaded == [pk]  # direct uuid load, no tenant scan


async def test_pack_record_store_loader_returns_none_on_missing() -> None:
    store = _StubStore(None)
    loader = PackRecordStoreLoader(store=store)  # type: ignore[arg-type]
    assert await loader.load_for_run(pack_uuid=uuid.uuid4()) is None


async def test_loader_extracts_high_risk_tier_and_data_classes() -> None:
    manifest = {
        "risk_tier": {"tier": "customer_data_read"},
        "data_governance": {"data_classes": ["customer_pii", "payment_action"]},
    }
    store = _StubStore(_installed_pack_record(), history=[_StubSubmitRow(manifest)])
    rec = await PackRecordStoreLoader(store=store).load_for_run(pack_uuid=uuid.uuid4())  # type: ignore[arg-type]
    assert rec is not None
    assert rec.risk_tier == "customer_data_read"
    assert rec.data_classes == ("customer_pii", "payment_action")


async def test_loader_absent_data_classes_is_empty_tuple() -> None:
    manifest = {"risk_tier": {"tier": "internal_write"}}  # no data_governance block
    store = _StubStore(_installed_pack_record(), history=[_StubSubmitRow(manifest)])
    rec = await PackRecordStoreLoader(store=store).load_for_run(pack_uuid=uuid.uuid4())  # type: ignore[arg-type]
    assert rec is not None
    assert rec.risk_tier == "internal_write"
    assert rec.data_classes == ()  # absent -> () (NOT the None malformed sentinel)


async def test_loader_malformed_data_classes_is_none_sentinel() -> None:
    manifest = {
        "risk_tier": {"tier": "internal_write"},
        "data_governance": {"data_classes": "customer_pii"},
    }  # str, not a list
    store = _StubStore(_installed_pack_record(), history=[_StubSubmitRow(manifest)])
    rec = await PackRecordStoreLoader(store=store).load_for_run(pack_uuid=uuid.uuid4())  # type: ignore[arg-type]
    assert rec is not None
    assert rec.data_classes is None  # malformed sentinel


async def test_loader_no_submit_manifest_yields_none_tier() -> None:
    store = _StubStore(
        _installed_pack_record(), history=[_StubSubmitRow(None)]
    )  # submit row, no manifest
    rec = await PackRecordStoreLoader(store=store).load_for_run(pack_uuid=uuid.uuid4())  # type: ignore[arg-type]
    assert rec is not None
    assert rec.risk_tier is None  # unresolved -> the executor refuses (T3)
    assert rec.data_classes == ()


class _Runtime:
    audit_store = object()
    decision_history_store = object()
    approval_engine = object()  # Sprint 14A-A2b — threaded into get_backend


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


async def test_build_sandbox_backend_threads_approval_engine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Sprint 14A-A2b: build_sandbox_backend threads runtime.approval_engine into
    # get_backend (which forwards it to the backend __init__). get_backend is
    # imported FUNCTION-LOCALLY from backend_factory, so patch the SOURCE module.
    from unittest.mock import AsyncMock

    captured: dict[str, Any] = {}

    class _FakeClient:
        async def close(self) -> None:
            pass

    monkeypatch.setattr("aiodocker.Docker", lambda *a, **k: _FakeClient())
    monkeypatch.setattr(
        "cognic_agentos.core.policy.engine.OPAEngine.create", AsyncMock(return_value=object())
    )

    def _fake_get_backend(settings: Any, /, **kwargs: Any) -> Any:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("cognic_agentos.sandbox.backend_factory.get_backend", _fake_get_backend)

    runtime = _Runtime()
    s = Settings(sandbox_backend="docker_sibling", vault_addr="http://vault:8200")
    _backend, _client = await build_sandbox_backend(settings=s, runtime=runtime)  # type: ignore[arg-type]
    assert captured["approval_engine"] is runtime.approval_engine
