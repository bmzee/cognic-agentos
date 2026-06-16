"""Sprint 14A-A2a — POST /api/v1/runs route. Stub executor + stub binder set on
app.state (after lifespan startup); the route is mounted at construction
(unconditional). The request-time dep returns 503 when the executor is absent."""

from __future__ import annotations

import base64
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cognic_agentos.core.run.executor import RunResult
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Any) -> Actor:
        return self._actor


class _StubExecutor:
    def __init__(self, result: RunResult) -> None:
        self._result = result
        self.calls: list[Any] = []

    async def run(self, request: Any) -> RunResult:
        self.calls.append(request)
        return self._result


def _actor() -> Actor:
    return Actor(
        subject="svc", tenant_id="t", scopes=frozenset({"run.submit"}), actor_type="service"
    )


def _make_app(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> Any:
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return create_app(
        memory_settings.model_copy(update={"litellm_config_path": cfg, "cache_driver": "memory"}),
        adapter_registry=memory_registry,
    )


def _body() -> dict[str, Any]:
    return {
        "pack_id": "cognic-tool-foo",
        "pack_uuid": "11111111-1111-1111-1111-111111111111",
        "pack_version": "1.0.0",
        "argv": ["echo", "hi"],
    }


def _post(
    memory_settings: Any,
    memory_registry: Any,
    tmp_path: Any,
    *,
    executor: Any,
    actor: Actor | None = None,
    body: dict[str, Any] | None = None,
) -> Any:
    app = _make_app(memory_settings, memory_registry, tmp_path)
    with TestClient(app) as client:
        # set AFTER lifespan startup so the stubs survive any pre-seed
        app.state.actor_binder = _StubBinder(actor if actor is not None else _actor())
        app.state.managed_run_executor = executor
        return client.post("/api/v1/runs", json=body if body is not None else _body())


@pytest.mark.parametrize(
    "result,expected_status",
    [
        (RunResult("rid", "tid", "completed", 0, b"out", b"", None, None), 200),
        (RunResult("rid", "tid", "pending_approval", None, b"", b"", None, "arid-9"), 202),
        (
            RunResult(
                "rid",
                "tid",
                "refused",
                None,
                b"",
                b"",
                "sandbox_high_risk_tier_refused_pre_13_5",
                None,
            ),
            409,
        ),
        (RunResult("rid", "tid", "failed", None, b"", b"", None, None), 502),
    ],
)
def test_terminal_state_maps_to_status(
    memory_settings: Any,
    memory_registry: Any,
    tmp_path: Any,
    result: RunResult,
    expected_status: int,
) -> None:
    resp = _post(memory_settings, memory_registry, tmp_path, executor=_StubExecutor(result))
    assert resp.status_code == expected_status
    payload = resp.json()
    assert payload["terminal_state"] == result.terminal_state
    assert payload["approval_request_id"] == result.approval_request_id


def test_completed_run_base64_encodes_raw_output(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    resp = _post(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_StubExecutor(
            RunResult("rid", "tid", "completed", 0, b"hello\x00", b"err", None, None)
        ),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert base64.b64decode(body["stdout_b64"]) == b"hello\x00"
    assert body["stdout_bytes"] == 6
    assert base64.b64decode(body["stderr_b64"]) == b"err"
    assert body["stderr_bytes"] == 3


def test_body_approval_request_id_and_actor_reach_executor(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    executor = _StubExecutor(RunResult("rid", "tid", "completed", 0, b"", b"", None, None))
    arid = "22222222-2222-2222-2222-222222222222"
    body = _body()
    body["approval_request_id"] = arid
    resp = _post(memory_settings, memory_registry, tmp_path, executor=executor, body=body)
    assert resp.status_code == 200
    # route -> executor threading: body correlator + bound actor + tenant-from-actor
    assert len(executor.calls) == 1
    run_request = executor.calls[0]
    assert run_request.approval_request_id == uuid.UUID(arid)
    assert run_request.tenant_id == "t"  # the bound actor's tenant, NOT from body
    assert run_request.actor.subject == "svc"  # the bound actor reaches the executor
    assert run_request.argv == ("echo", "hi")  # tuple, verbatim (no shell concat)


def test_503_when_executor_not_populated(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    resp = _post(memory_settings, memory_registry, tmp_path, executor=None)
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "sandbox_runtime_unavailable"


def test_422_on_empty_argv(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> None:
    body = _body()
    body["argv"] = []
    resp = _post(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_StubExecutor(RunResult("rid", "tid", "completed", 0, b"", b"", None, None)),
        body=body,
    )
    assert resp.status_code == 422


def test_422_on_extra_tenant_field(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    body = _body()
    body["tenant_id"] = "attacker"
    resp = _post(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_StubExecutor(RunResult("rid", "tid", "completed", 0, b"", b"", None, None)),
        body=body,
    )
    assert resp.status_code == 422
