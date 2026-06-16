"""Sprint 14A-A2a — POST /api/v1/runs route. Stub executor + stub binder set on
app.state (after lifespan startup); the route is mounted at construction
(unconditional). The request-time dep returns 503 when the executor is absent."""

from __future__ import annotations

import base64
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cognic_agentos.core.run.executor import (
    RunNotResumable,
    RunResult,
    RunResumeApprovalMismatch,
    RunResumeConflict,
    RunResumePendingApprovalRequired,
)
from cognic_agentos.core.run.storage import RunNotFound
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


class _ResumeStubExecutor:
    """Stub for resume(): either returns a RunResult or raises a pre-flight
    exception. Records the keyword call args so the route->executor threading
    (run_id path-param + bound actor + argv tuple) can be asserted."""

    def __init__(self, *, result: RunResult | None = None, raises: Exception | None = None) -> None:
        self._result = result
        self._raises = raises
        self.calls: list[dict[str, Any]] = []

    async def resume(
        self, *, run_id: Any, actor: Any, argv: Any, approval_request_id: Any = None
    ) -> RunResult:
        self.calls.append(
            {
                "run_id": run_id,
                "actor": actor,
                "argv": argv,
                "approval_request_id": approval_request_id,
            }
        )
        if self._raises is not None:
            raise self._raises
        assert self._result is not None
        return self._result


def _actor() -> Actor:
    return Actor(
        subject="svc",
        tenant_id="t",
        scopes=frozenset({"run.submit", "run.resume"}),
        actor_type="service",
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


_RUN_ID = "33333333-3333-3333-3333-333333333333"


def _resume_body() -> dict[str, Any]:
    return {"argv": ["cont", "go"]}


def _post_resume(
    memory_settings: Any,
    memory_registry: Any,
    tmp_path: Any,
    *,
    executor: Any,
    actor: Actor | None = None,
    body: dict[str, Any] | None = None,
    run_id: str = _RUN_ID,
) -> Any:
    app = _make_app(memory_settings, memory_registry, tmp_path)
    with TestClient(app) as client:
        # set AFTER lifespan startup so the stubs survive any pre-seed
        app.state.actor_binder = _StubBinder(actor if actor is not None else _actor())
        app.state.managed_run_executor = executor
        return client.post(
            f"/api/v1/runs/{run_id}/resume",
            json=body if body is not None else _resume_body(),
        )


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
    assert payload["run_id"] == result.run_id  # A3b: run_id on the submit response body


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


# --- Sprint 14A-A3b — POST /api/v1/runs/{run_id}/resume ---------------------


@pytest.mark.parametrize(
    "result,expected_status",
    [
        # resume() produces completed / failed / refused (never suspended), but
        # the status map type-covers suspended -> 202 too.
        (RunResult(_RUN_ID, None, "completed", 0, b"more", b"", None, None), 200),
        (RunResult(_RUN_ID, None, "failed", None, b"", b"", None, None), 502),
        (
            RunResult(
                _RUN_ID, None, "refused", None, b"", b"", "sandbox_wake_checkpoint_corrupt", None
            ),
            409,
        ),
    ],
)
def test_resume_terminal_state_maps_to_status(
    memory_settings: Any,
    memory_registry: Any,
    tmp_path: Any,
    result: RunResult,
    expected_status: int,
) -> None:
    resp = _post_resume(
        memory_settings, memory_registry, tmp_path, executor=_ResumeStubExecutor(result=result)
    )
    assert resp.status_code == expected_status
    payload = resp.json()
    assert payload["terminal_state"] == result.terminal_state
    assert payload["run_id"] == result.run_id  # A3b: run_id on the resume response body


def test_resume_threads_run_id_actor_and_argv_to_executor(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    executor = _ResumeStubExecutor(
        result=RunResult(_RUN_ID, None, "completed", 0, b"out", b"err", None, None)
    )
    resp = _post_resume(memory_settings, memory_registry, tmp_path, executor=executor)
    assert resp.status_code == 200
    body = resp.json()
    assert base64.b64decode(body["stdout_b64"]) == b"out"
    assert base64.b64decode(body["stderr_b64"]) == b"err"
    # route -> executor threading: path-param run_id + bound actor + argv tuple
    assert len(executor.calls) == 1
    call = executor.calls[0]
    assert call["run_id"] == uuid.UUID(_RUN_ID)  # path param parsed to UUID
    assert call["actor"].subject == "svc"  # the bound actor reaches the executor
    assert call["argv"] == ("cont", "go")  # tuple, verbatim (no shell concat)


def test_resume_404_when_run_not_found(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    resp = _post_resume(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_ResumeStubExecutor(raises=RunNotFound(uuid.UUID(_RUN_ID))),
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["reason"] == "run_not_found"


def test_resume_409_when_run_not_suspended_carries_current_state(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    resp = _post_resume(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_ResumeStubExecutor(raises=RunNotResumable("completed")),
    )
    assert resp.status_code == 409
    detail = resp.json()["detail"]
    assert detail["reason"] == "run_not_suspended"
    assert detail["current_state"] == "completed"


def test_resume_409_on_resume_conflict(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    resp = _post_resume(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_ResumeStubExecutor(raises=RunResumeConflict(uuid.UUID(_RUN_ID))),
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "run_resume_conflict"


def test_resume_403_when_scope_not_held(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    # an actor WITHOUT run.resume (only run.submit) is refused at the dep chain
    submit_only = Actor(
        subject="svc", tenant_id="t", scopes=frozenset({"run.submit"}), actor_type="service"
    )
    resp = _post_resume(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_ResumeStubExecutor(
            result=RunResult(_RUN_ID, None, "completed", 0, b"", b"", None, None)
        ),
        actor=submit_only,
    )
    assert resp.status_code == 403


def test_resume_503_when_executor_not_populated(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    resp = _post_resume(memory_settings, memory_registry, tmp_path, executor=None)
    assert resp.status_code == 503
    assert resp.json()["detail"]["reason"] == "sandbox_runtime_unavailable"


def test_resume_422_on_empty_argv(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    resp = _post_resume(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_ResumeStubExecutor(
            result=RunResult(_RUN_ID, None, "completed", 0, b"", b"", None, None)
        ),
        body={"argv": []},
    )
    assert resp.status_code == 422


def test_resume_422_on_extra_field(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    resp = _post_resume(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_ResumeStubExecutor(
            result=RunResult(_RUN_ID, None, "completed", 0, b"", b"", None, None)
        ),
        body={"argv": ["go"], "tenant_id": "attacker"},
    )
    assert resp.status_code == 422


# --- Sprint 14A-A3c — wake-approval correlator + no-re-mint refusal mappings ---


def test_resume_202_and_echoes_approval_request_id_when_pending(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    # resume() yields pending_approval (cold-create approval checkpoint at wake);
    # the route returns 202 + the minted approval_request_id for the operator to grant.
    resp = _post_resume(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_ResumeStubExecutor(
            result=RunResult(_RUN_ID, None, "pending_approval", None, b"", b"", None, "arid-7")
        ),
    )
    assert resp.status_code == 202
    payload = resp.json()
    assert payload["terminal_state"] == "pending_approval"
    assert payload["approval_request_id"] == "arid-7"
    assert payload["run_id"] == _RUN_ID


def test_resume_200_when_completed(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    resp = _post_resume(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_ResumeStubExecutor(
            result=RunResult(_RUN_ID, None, "completed", 0, b"done", b"", None, None)
        ),
    )
    assert resp.status_code == 200
    assert resp.json()["terminal_state"] == "completed"


def test_resume_409_when_approval_id_required(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    # re-resume of a wake-pending run WITHOUT the correlator -> 409 (no re-mint).
    resp = _post_resume(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_ResumeStubExecutor(raises=RunResumePendingApprovalRequired(uuid.UUID(_RUN_ID))),
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "run_resume_approval_id_required"


def test_resume_409_when_approval_id_mismatch(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    # re-resume with a correlator that does NOT match the pending request -> 409.
    resp = _post_resume(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=_ResumeStubExecutor(raises=RunResumeApprovalMismatch(uuid.UUID(_RUN_ID))),
    )
    assert resp.status_code == 409
    assert resp.json()["detail"]["reason"] == "run_resume_approval_id_mismatch"


def test_resume_threads_approval_request_id_to_executor(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    # the optional body correlator threads through to executor.resume(...).
    executor = _ResumeStubExecutor(
        result=RunResult(_RUN_ID, None, "completed", 0, b"", b"", None, None)
    )
    arid = "44444444-4444-4444-4444-444444444444"
    resp = _post_resume(
        memory_settings,
        memory_registry,
        tmp_path,
        executor=executor,
        body={"argv": ["cont"], "approval_request_id": arid},
    )
    assert resp.status_code == 200
    assert len(executor.calls) == 1
    assert executor.calls[0]["approval_request_id"] == uuid.UUID(arid)


def test_resume_approval_request_id_optional_defaults_none(
    memory_settings: Any, memory_registry: Any, tmp_path: Any
) -> None:
    # omitting the correlator threads None (the first-resume shape).
    executor = _ResumeStubExecutor(
        result=RunResult(_RUN_ID, None, "completed", 0, b"", b"", None, None)
    )
    resp = _post_resume(memory_settings, memory_registry, tmp_path, executor=executor)
    assert resp.status_code == 200
    assert len(executor.calls) == 1
    assert executor.calls[0]["approval_request_id"] is None
