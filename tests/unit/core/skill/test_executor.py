"""M6 Task A5 (ADR-025) — SkillExecutor orchestration over a REAL SkillBroker +
REAL DecisionHistoryStore (in-memory sqlite) with a STUB SandboxBackend + STUB
SkillRecordLoader + a SPY SkillCallProxy.

The stub sandbox session does NOT run the real ``skill_runner`` — instead its
``exec`` connects to the broker over the SAME Unix socket the runner would (via
the ``writable_mounts`` host path the executor mounts), presents the session
token, sends a tool request, and writes a runner-shaped result frame to stdout.
That exercises the REAL broker's per-call ``declared_tools`` enforcement end to
end: the happy path routes a DECLARED tool through to the spy proxy; the
forbidden path sends an UNDECLARED tool and proves the broker refused it BEFORE
the proxy (zero recorded calls) and the executor surfaced the passthrough
``skill_tool_not_declared``.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history
from cognic_agentos.core.skill._types import (
    LoadedSkillRecord,
    SkillInvokeRefusalReason,
    SkillInvokeResult,
    SkillInvokeTerminalState,
)
from cognic_agentos.core.skill.executor import (
    _ENV_ARGUMENTS_JSON,
    _ENV_BROKER_SESSION_TOKEN,
    _ENV_BROKER_SOCKET,
    _ENV_DECLARED_TOOLS_JSON,
    _ENV_ENTRY_POINT,
    _SKILL_RUNNER_MODULE,
    SkillExecutor,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox.protocol import SandboxExecResult
from cognic_agentos.sdk.skill_transport import decode_frame_async, encode_frame

pytestmark = pytest.mark.asyncio

_IMAGE = "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64


# --- in-memory DB (mirror tests/unit/core/run/test_executor.py) --------------
@pytest.fixture
async def db(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'skill.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


def _actor() -> Actor:
    return Actor(subject="agent-x", tenant_id="tenant-a", scopes=frozenset(), actor_type="service")


# --- spy call proxy ----------------------------------------------------------
class _SpyProxy:
    """Records every governed ``call`` the broker routes to it. On the forbidden
    path the broker refuses BEFORE reaching here, so ``calls`` stays empty."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    async def call(
        self,
        *,
        server_id: str,
        tool_name: str,
        arguments: dict[str, Any],
        request_id: str,
        tenant_id: str,
        originator_subject: str,
    ) -> Any:
        self.calls.append((server_id, tool_name, dict(arguments)))
        return {"rows": [["EMPLOYEES"], ["DEPARTMENTS"]]}


# --- stub skill-record loader ------------------------------------------------
class _StubLoader:
    def __init__(self, record: LoadedSkillRecord | None) -> None:
        self._record = record
        self.calls: list[tuple[str, str]] = []

    async def load_for_skill(self, *, skill_id: str, tenant_id: str) -> LoadedSkillRecord | None:
        self.calls.append((skill_id, tenant_id))
        return self._record


# --- stub sandbox backend/session that drives the REAL broker over the socket -
class _RunnerSimSession:
    """Simulates the in-sandbox runner: connects to the broker via the mounted
    host socket, presents the session token, sends ONE tool request, and writes
    the runner's result frame to stdout."""

    def __init__(self, *, policy: Any, tool_ref: str, arguments: dict[str, Any]) -> None:
        self.session_id = uuid.uuid4().hex
        self.policy = policy
        self._tool_ref = tool_ref
        self._arguments = arguments
        self.destroy_calls = 0

    async def exec(
        self, command: list[str], *, timeout_s: float | None = None
    ) -> SandboxExecResult:
        env = {
            tok.split("=", 1)[0]: tok.split("=", 1)[1]
            for tok in command
            if tok.startswith("COGNIC_SKILL_")
        }
        session_token = env[_ENV_BROKER_SESSION_TOKEN]
        # The runner connects to the CONTAINER socket path; the test resolves the
        # HOST socket from the mount the executor added (container /run/cognic-skill
        # -> host broker_dir).
        mount = self.policy.writable_mounts[0]
        assert mount.container_path == "/run/cognic-skill"
        host_sock = os.path.join(mount.host_path, "broker.sock")
        reader, writer = await asyncio.open_unix_connection(host_sock)
        writer.write(
            encode_frame(
                {
                    "session_token": session_token,
                    "tool_ref": self._tool_ref,
                    "arguments": self._arguments,
                }
            )
        )
        await writer.drain()
        resp = await decode_frame_async(reader, required_keys=("ok",))
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
        if resp.get("ok") is True:
            frame = encode_frame(
                {"ok": True, "result": {"schema": "COGNIC", "tool_result": resp.get("result")}}
            )
            return SandboxExecResult(stdout=frame, stderr=b"", exit_code=0)
        frame = encode_frame({"ok": False, "refused": True, "reason": resp.get("reason")})
        return SandboxExecResult(stdout=frame, stderr=b"", exit_code=1)

    async def destroy(self) -> None:
        self.destroy_calls += 1


class _RunnerSimBackend:
    def __init__(self, *, tool_ref: str, arguments: dict[str, Any]) -> None:
        self._tool_ref = tool_ref
        self._arguments = arguments
        self.created: list[_RunnerSimSession] = []
        self.last_requires_credentials: Any = "UNSET"
        self.last_policy: Any = None
        self.last_pack_context: Any = None

    async def create(
        self,
        policy: Any,
        *,
        actor: Any,
        tenant_id: str,
        pack_context: Any,
        use_warm_pool: bool = True,
        requires_credentials: Any = (),
        approval_request_id: Any = None,
    ) -> _RunnerSimSession:
        self.last_requires_credentials = requires_credentials
        self.last_policy = policy
        self.last_pack_context = pack_context
        session = _RunnerSimSession(
            policy=policy, tool_ref=self._tool_ref, arguments=self._arguments
        )
        self.created.append(session)
        return session


# --- a plain raising/echo backend for the non-socket paths --------------------
class _EchoSession:
    def __init__(
        self,
        *,
        policy: Any,
        stdout: bytes,
        exec_raises: Exception | None,
        destroy_raises: Exception | None = None,
        stderr: bytes = b"",
        exit_code: int = 0,
    ) -> None:
        self.session_id = uuid.uuid4().hex
        self.policy = policy
        self._stdout = stdout
        self._stderr = stderr
        self._exit_code = exit_code
        self._exec_raises = exec_raises
        self._destroy_raises = destroy_raises
        self.destroy_calls = 0

    async def exec(
        self, command: list[str], *, timeout_s: float | None = None
    ) -> SandboxExecResult:
        if self._exec_raises is not None:
            raise self._exec_raises
        return SandboxExecResult(
            stdout=self._stdout, stderr=self._stderr, exit_code=self._exit_code
        )

    async def destroy(self) -> None:
        self.destroy_calls += 1
        if self._destroy_raises is not None:
            raise self._destroy_raises


class _EchoBackend:
    def __init__(
        self,
        *,
        stdout: bytes = b"",
        create_raises: Exception | None = None,
        exec_raises: Exception | None = None,
        destroy_raises: Exception | None = None,
        stderr: bytes = b"",
        exit_code: int = 0,
    ) -> None:
        self._stdout = stdout
        self._stderr = stderr
        self._exit_code = exit_code
        self._create_raises = create_raises
        self._exec_raises = exec_raises
        self._destroy_raises = destroy_raises
        self.created: list[_EchoSession] = []
        self.last_requires_credentials: Any = "UNSET"
        self.last_policy: Any = None

    async def create(
        self,
        policy: Any,
        *,
        actor: Any,
        tenant_id: str,
        pack_context: Any,
        use_warm_pool: bool = True,
        requires_credentials: Any = (),
        approval_request_id: Any = None,
    ) -> _EchoSession:
        self.last_requires_credentials = requires_credentials
        self.last_policy = policy
        if self._create_raises is not None:
            raise self._create_raises
        session = _EchoSession(
            policy=policy,
            stdout=self._stdout,
            exec_raises=self._exec_raises,
            destroy_raises=self._destroy_raises,
            stderr=self._stderr,
            exit_code=self._exit_code,
        )
        self.created.append(session)
        return session


def _record(declared: tuple[str, ...], *, registered: bool = True) -> LoadedSkillRecord:
    return LoadedSkillRecord(
        skill_id="schema-summary",
        entry_point_name="schema_summary",
        declared_tools=declared,
        runtime_image=_IMAGE,
        registered=registered,
        pack_version="0.1.0",
        signed_artefact_digest=b"\xab\xcd",
    )


async def _decision_types(db: AsyncEngine) -> list[str]:
    async with db.connect() as conn:
        rows = list(
            await conn.execute(
                select(_decision_history.c.event_type).order_by(_decision_history.c.sequence)
            )
        )
    return [r[0] for r in rows]


async def _latest_payload(db: AsyncEngine, decision_type: str) -> dict[str, Any]:
    async with db.connect() as conn:
        row = (
            await conn.execute(
                select(_decision_history.c.payload)
                .where(_decision_history.c.event_type == decision_type)
                .order_by(_decision_history.c.sequence.desc())
            )
        ).first()
    assert row is not None, f"no chain row of type {decision_type}"
    payload: dict[str, Any] = row[0]
    return payload


# ============================ closed-enum pins ================================
async def test_refusal_reason_closed_enum() -> None:
    from typing import get_args

    assert set(get_args(SkillInvokeRefusalReason)) == {
        "skill_not_found",
        "skill_not_registered",
        "skill_not_executable",
        "skill_runtime_error",
    }


async def test_terminal_state_closed_enum() -> None:
    from typing import get_args

    assert set(get_args(SkillInvokeTerminalState)) == {"completed", "refused", "failed"}


async def test_env_var_names_match_sdk_skill_runner() -> None:
    # Test-only drift detector: core/skill keeps a LOCAL copy of the 5-env-var
    # contract (the core/skill -> sdk arrow is forbidden at runtime); this test
    # imports the SDK to prove the copy is in lockstep.
    from cognic_agentos.sdk import skill_runner

    assert _ENV_BROKER_SOCKET == skill_runner.ENV_BROKER_SOCKET
    assert _ENV_BROKER_SESSION_TOKEN == skill_runner.ENV_BROKER_SESSION_TOKEN
    assert _ENV_ENTRY_POINT == skill_runner.ENV_ENTRY_POINT
    assert _ENV_DECLARED_TOOLS_JSON == skill_runner.ENV_DECLARED_TOOLS_JSON
    assert _ENV_ARGUMENTS_JSON == skill_runner.ENV_ARGUMENTS_JSON


# ============================ happy path =====================================
async def test_happy_path_routes_declared_tool_and_returns_result(db: AsyncEngine) -> None:
    proxy = _SpyProxy()
    backend = _RunnerSimBackend(tool_ref="oracle/list_tables", arguments={"owner": "COGNIC"})
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(
        skill_id="schema-summary", arguments={"owner": "COGNIC"}, actor=_actor()
    )
    assert isinstance(result, SkillInvokeResult)
    assert result.terminal_state == "completed"
    assert result.refusal_reason is None
    assert result.result == {
        "schema": "COGNIC",
        "tool_result": {"rows": [["EMPLOYEES"], ["DEPARTMENTS"]]},
    }
    # broker routed the DECLARED tool through to the governed proxy exactly once.
    assert proxy.calls == [("oracle", "list_tables", {"owner": "COGNIC"})]
    # dual-layer evidence: exactly one skill.invoked instruction-layer row.
    assert await _decision_types(db) == ["skill.invoked"]
    payload = await _latest_payload(db, "skill.invoked")
    assert payload["skill_id"] == "schema-summary"
    assert payload["terminal_state"] == "completed"
    assert payload["actor_id"] == "agent-x"
    # digest-only: never raw arguments/stdout in the chain.
    assert "arguments" not in payload
    assert isinstance(payload["arguments_sha256"], str) and len(payload["arguments_sha256"]) == 64
    assert isinstance(payload["stdout_sha256"], str)
    assert payload["exit_code"] == 0
    # teardown always ran.
    assert backend.created[0].destroy_calls == 1


# ============================ invariant #9 + #10 =============================
async def test_create_uses_no_network_policy_and_no_credentials(db: AsyncEngine) -> None:
    proxy = _SpyProxy()
    backend = _RunnerSimBackend(tool_ref="oracle/list_tables", arguments={"owner": "COGNIC"})
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    await ex.invoke(skill_id="schema-summary", arguments={"owner": "COGNIC"}, actor=_actor())
    # invariant #9 — --network none is egress_allow_list=().
    assert backend.last_policy.egress_allow_list == ()
    # invariant #10 — no ambient credentials.
    assert backend.last_requires_credentials == ()
    # the broker socket dir is mounted read-write at the container path.
    mounts = backend.last_policy.writable_mounts
    assert len(mounts) == 1
    assert mounts[0].container_path == "/run/cognic-skill"
    assert mounts[0].read_only is False
    # the sandbox runs the skill's own runtime image + the runner module command.
    assert backend.last_policy.runtime_image == _IMAGE


# ============================ forbidden path (load-bearing) ===================
async def test_forbidden_tool_refused_by_broker_before_proxy(db: AsyncEngine) -> None:
    proxy = _SpyProxy()
    # declared set does NOT include get_constraints; the sim sends it anyway.
    backend = _RunnerSimBackend(tool_ref="oracle/get_constraints", arguments={"owner": "COGNIC"})
    loader = _StubLoader(_record(("oracle/list_tables", "oracle/describe_table")))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(
        skill_id="schema-summary", arguments={"owner": "COGNIC"}, actor=_actor()
    )
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "skill_tool_not_declared"
    assert result.result is None
    # THE load-bearing assertion: the broker refused BEFORE the proxy — zero calls.
    assert proxy.calls == []
    payload = await _latest_payload(db, "skill.invoked")
    assert payload["terminal_state"] == "refused"
    assert payload["reason"] == "skill_tool_not_declared"
    # teardown still ran.
    assert backend.created[0].destroy_calls == 1


# ============================ teardown on exec exception =====================
async def test_teardown_runs_on_exec_exception(db: AsyncEngine) -> None:
    proxy = _SpyProxy()
    backend = _EchoBackend(exec_raises=RuntimeError("workload blew up"))
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(
        skill_id="schema-summary", arguments={"owner": "COGNIC"}, actor=_actor()
    )
    assert result.terminal_state == "failed"
    assert result.refusal_reason == "skill_runtime_error"
    # session.destroy ran even though exec raised (finally-guarded teardown).
    assert backend.created[0].destroy_calls == 1
    payload = await _latest_payload(db, "skill.invoked")
    assert payload["terminal_state"] == "failed"
    assert payload["reason"] == "skill_runtime_error"


# ============================ create() raising ===============================
async def test_create_failure_maps_to_runtime_error_no_session(db: AsyncEngine) -> None:
    proxy = _SpyProxy()
    backend = _EchoBackend(create_raises=RuntimeError("admission blew up"))
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(
        skill_id="schema-summary", arguments={"owner": "COGNIC"}, actor=_actor()
    )
    assert result.terminal_state == "failed"
    assert result.refusal_reason == "skill_runtime_error"
    assert backend.created == []  # create raised -> no session


# ============================ unparseable frame ==============================
async def test_unparseable_stdout_frame_maps_to_runtime_error(db: AsyncEngine) -> None:
    proxy = _SpyProxy()
    backend = _EchoBackend(stdout=b"not a length-framed json frame at all")
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(
        skill_id="schema-summary", arguments={"owner": "COGNIC"}, actor=_actor()
    )
    assert result.terminal_state == "failed"
    assert result.refusal_reason == "skill_runtime_error"
    assert backend.created[0].destroy_calls == 1


# ============================ pre-flight refusals ============================
async def test_skill_not_found_when_loader_returns_none(db: AsyncEngine) -> None:
    proxy = _SpyProxy()
    backend = _EchoBackend()
    loader = _StubLoader(None)
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(skill_id="ghost", arguments={}, actor=_actor())
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "skill_not_found"
    assert backend.created == []  # no sandbox for a pre-flight refusal
    payload = await _latest_payload(db, "skill.invoked")
    assert payload["terminal_state"] == "refused"
    assert payload["reason"] == "skill_not_found"


async def test_skill_not_registered_when_record_not_registered(db: AsyncEngine) -> None:
    proxy = _SpyProxy()
    backend = _EchoBackend()
    loader = _StubLoader(_record(("oracle/list_tables",), registered=False))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(skill_id="schema-summary", arguments={}, actor=_actor())
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "skill_not_registered"
    assert backend.created == []


async def test_instruction_record_refused_skill_not_executable(db: AsyncEngine) -> None:
    """A7 (ADR-027): an instruction-mode record carries no executable action —
    the fail-closed mode guard refuses it pre-flight with the closed-enum
    ``skill_not_executable`` and it must NEVER reach ``backend.create``
    (spy-pinned: zero sessions created)."""
    proxy = _SpyProxy()
    backend = _EchoBackend()
    record = LoadedSkillRecord(
        skill_id="schema-notes",
        mode="instruction",
        description="Explains how to reason about the schema.",
        skill_md_body="Read the table list, then describe relationships.",
    )
    loader = _StubLoader(record)
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(skill_id="schema-notes", arguments={}, actor=_actor())
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "skill_not_executable"
    assert result.result is None
    # THE load-bearing assertion: no sandbox session was ever created.
    assert backend.created == []
    assert proxy.calls == []
    payload = await _latest_payload(db, "skill.invoked")
    assert payload["terminal_state"] == "refused"
    assert payload["reason"] == "skill_not_executable"


async def test_executable_mode_default_still_runs(db: AsyncEngine) -> None:
    """The ABSENT-mode default is ``executable`` — every pre-A7 record shape
    (no ``mode`` kwarg) still reaches the sandbox exactly as before."""
    record = _record(("oracle/list_tables",))
    assert record.mode == "executable"
    assert record.skill_md_body is None
    assert record.description == ""


async def test_loader_receives_actor_tenant(db: AsyncEngine) -> None:
    proxy = _SpyProxy()
    backend = _EchoBackend()
    loader = _StubLoader(None)
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    await ex.invoke(skill_id="schema-summary", arguments={}, actor=_actor())
    assert loader.calls == [("schema-summary", "tenant-a")]


# ============================ command shape ==================================
async def test_exec_command_carries_env_and_runner_module(db: AsyncEngine) -> None:
    captured: dict[str, Any] = {}

    class _CaptureSession(_EchoSession):
        async def exec(
            self, command: list[str], *, timeout_s: float | None = None
        ) -> SandboxExecResult:
            captured["command"] = command
            return SandboxExecResult(
                stdout=encode_frame({"ok": True, "result": {}}), stderr=b"", exit_code=0
            )

    class _CaptureBackend(_EchoBackend):
        async def create(self, policy: Any, **kw: Any) -> _CaptureSession:
            self.last_policy = policy
            self.last_requires_credentials = kw.get("requires_credentials")
            s = _CaptureSession(policy=policy, stdout=b"", exec_raises=None)
            self.created.append(s)
            return s

    proxy = _SpyProxy()
    backend = _CaptureBackend()
    loader = _StubLoader(_record(("oracle/list_tables", "oracle/describe_table")))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    await ex.invoke(skill_id="schema-summary", arguments={"owner": "COGNIC"}, actor=_actor())
    cmd = captured["command"]
    assert cmd[0] == "env"
    assert cmd[-3:] == ["python", "-m", _SKILL_RUNNER_MODULE]
    joined = "\n".join(cmd)
    assert f"{_ENV_BROKER_SOCKET}=/run/cognic-skill/broker.sock" in joined
    assert f"{_ENV_ENTRY_POINT}=schema_summary" in joined
    assert f'{_ENV_DECLARED_TOOLS_JSON}=["oracle/list_tables", "oracle/describe_table"]' in joined
    assert f'{_ENV_ARGUMENTS_JSON}={{"owner": "COGNIC"}}' in joined
    # the session token token is present + non-empty.
    token_tokens = [c for c in cmd if c.startswith(f"{_ENV_BROKER_SESSION_TOKEN}=")]
    assert len(token_tokens) == 1 and len(token_tokens[0].split("=", 1)[1]) >= 32


# ============================ negative-path branch coverage ==================
async def test_destroy_exception_is_best_effort_and_does_not_flip_outcome(db: AsyncEngine) -> None:
    # teardown-guarded: a session.destroy() that raises is swallowed (logged) and
    # the completed result still returns (the finally never flips the outcome).
    proxy = _SpyProxy()
    backend = _EchoBackend(
        stdout=encode_frame({"ok": True, "result": {"done": 1}}),
        destroy_raises=RuntimeError("teardown blew up"),
    )
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(skill_id="schema-summary", arguments={}, actor=_actor())
    assert result.terminal_state == "completed"
    assert result.result == {"done": 1}
    assert backend.created[0].destroy_calls == 1  # destroy WAS attempted


async def test_session_destroyed_even_if_broker_handle_close_raises(
    db: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Independent-teardown hardening: handle.close() and session.destroy() are
    # torn down INDEPENDENTLY in the finally. If handle.close() raises, the
    # sandbox session MUST still be destroyed (teardown is a critical boundary;
    # it must not depend on the broker's internal OSError-suppression). Without
    # the hardening, the bare ``await handle.close()`` in the finally would
    # propagate — flipping the completed outcome to a raise AND skipping
    # session.destroy() entirely.
    from cognic_agentos.core.skill._types import _BrokerHandle

    orig_close = _BrokerHandle.close

    async def _close_then_raise(self: _BrokerHandle) -> None:
        await orig_close(self)  # still clean up the real socket + 0700 dir
        raise RuntimeError("broker close boom")

    monkeypatch.setattr(_BrokerHandle, "close", _close_then_raise)
    proxy = _SpyProxy()
    backend = _EchoBackend(stdout=encode_frame({"ok": True, "result": {"done": 1}}))
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(skill_id="schema-summary", arguments={}, actor=_actor())
    # the broker-close raise was swallowed — the completed outcome is NOT flipped,
    assert result.terminal_state == "completed"
    assert result.result == {"done": 1}
    # and — the load-bearing assertion — the sandbox session was STILL destroyed.
    assert backend.created[0].destroy_calls == 1


async def test_ok_false_without_refused_maps_to_runtime_error(db: AsyncEngine) -> None:
    # a frame that is neither a success nor a well-formed refusal -> runtime_error.
    proxy = _SpyProxy()
    backend = _EchoBackend(stdout=encode_frame({"ok": False, "note": "weird"}))
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(skill_id="schema-summary", arguments={}, actor=_actor())
    assert result.terminal_state == "failed"
    assert result.refusal_reason == "skill_runtime_error"


async def test_refused_frame_with_non_string_reason_maps_to_runtime_error(db: AsyncEngine) -> None:
    proxy = _SpyProxy()
    backend = _EchoBackend(stdout=encode_frame({"ok": False, "refused": True, "reason": 42}))
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(skill_id="schema-summary", arguments={}, actor=_actor())
    assert result.terminal_state == "failed"
    assert result.refusal_reason == "skill_runtime_error"


async def test_short_stdout_below_prefix_len_maps_to_runtime_error(db: AsyncEngine) -> None:
    # stdout shorter than the 4-byte length prefix -> no parseable frame.
    proxy = _SpyProxy()
    backend = _EchoBackend(stdout=b"ab")
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(skill_id="schema-summary", arguments={}, actor=_actor())
    assert result.terminal_state == "failed"
    assert result.refusal_reason == "skill_runtime_error"


async def test_preamble_before_final_frame_is_tolerated(db: AsyncEngine) -> None:
    # a (hostile) action that prints to stdout before the runner's final frame:
    # the tail-anchored parse still finds the frame.
    proxy = _SpyProxy()
    preamble = b"noise printed by the action\n"
    frame = encode_frame({"ok": True, "result": {"k": "v"}})
    backend = _EchoBackend(stdout=preamble + frame)
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    result = await ex.invoke(skill_id="schema-summary", arguments={}, actor=_actor())
    assert result.terminal_state == "completed"
    assert result.result == {"k": "v"}


async def test_zero_execution_timeout_rejected() -> None:
    with pytest.raises(ValueError, match="execution_timeout_s"):
        SkillExecutor(
            sandbox_backend=object(),  # type: ignore[arg-type]
            skill_loader=_StubLoader(None),
            call_proxy=_SpyProxy(),
            decision_history_store=object(),  # type: ignore[arg-type]
            execution_timeout_s=0.0,
        )


# ---------------------------------------------------------------------------
# M6 run-14 finding #15 — bounded stderr WARNING on skill_runtime_error
# ---------------------------------------------------------------------------


async def test_runner_failure_warns_with_bounded_stderr(
    db: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    """A runner crash (no parseable frame) MUST surface an
    operator-actionable WARNING carrying exit_code + stderr_sha256 + a
    BOUNDED replace-decoded stderr excerpt. Without it a deployed
    skill runtime error is undiagnosable — the run-14 blocker was
    root-caused only by code archaeology + a local repro because the
    runner's traceback was captured then dropped. Evidence stays
    digest-only (no schema change); the excerpt lives on the LOG axis
    only."""

    # 5000 bytes of traceback-ish stderr incl. one invalid-UTF8 byte —
    # pins both the bound AND the replace-decode (a raw .decode() would
    # raise UnicodeDecodeError past the taxonomy).
    stderr = b"Traceback (most recent call last):\n" + b"\xff" + b"x" * 4964
    proxy = _SpyProxy()
    backend = _EchoBackend(stdout=b"", stderr=stderr, exit_code=1)
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.core.skill.executor"):
        result = await ex.invoke(skill_id="schema-summary", arguments={}, actor=_actor())
    assert result.refusal_reason == "skill_runtime_error"
    warnings = [r for r in caplog.records if r.message == "skill.invoke.runner_failed"]
    assert len(warnings) == 1
    record = warnings[0]
    assert record.exit_code == 1  # type: ignore[attr-defined]
    # #17c — the correlator rides the collision-proof key (see the section below).
    assert record.invoke_request_id.startswith("skill-")  # type: ignore[attr-defined]
    assert record.stderr_sha256 == hashlib.sha256(stderr).hexdigest()  # type: ignore[attr-defined]
    excerpt = record.stderr_excerpt  # type: ignore[attr-defined]
    assert len(excerpt) == 2048  # bounded — never the full multi-KB stream
    assert excerpt.startswith("Traceback (most recent call last):")
    assert "\ufffd" in excerpt  # replace-decoded, not raised


async def test_runner_success_emits_no_runner_failed_warning(
    db: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    """Mutually-exclusive emission: the green path emits ZERO
    runner_failed warnings (log-noise on success would poison
    operator alerting on the failure signal)."""

    proxy = _SpyProxy()
    backend = _EchoBackend(stdout=encode_frame({"ok": True, "result": {"k": "v"}}))
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.core.skill.executor"):
        result = await ex.invoke(skill_id="schema-summary", arguments={}, actor=_actor())
    assert result.terminal_state == "completed"
    assert [r for r in caplog.records if r.message == "skill.invoke.runner_failed"] == []


# ---------------------------------------------------------------------------
# M6 finding #17c (executor half) — the per-invocation correlator rides
# invoke_request_id, NOT request_id: the observability _ContextFilter on the
# production root handler OWNS record.request_id/trace_id/span_id and stamps
# the ambient portal context over same-named extras, silently replacing the
# executor's minted skill-<hex> correlator on every failure WARNING. Mirror
# of the broker's tool_request_id fix (2f36bfb). The skill.invoked CHAIN row
# keeps request_id (the chain-side name is not a log extra and is untouched
# by the filter); the LOG key is the collision-proof one — an operator joins
# log.invoke_request_id == decision_history.request_id.
# ---------------------------------------------------------------------------


async def test_invoke_request_id_survives_production_context_filter(
    db: AsyncEngine, caplog: pytest.LogCaptureFixture
) -> None:
    """Deterministic #17c pin: install the real production _ContextFilter at
    root-handler position 0 (ahead of caplog's capture handler, mirroring the
    long-lived-production-handler-first ordering) and prove record.request_id
    is clobbered by the (unbound) ambient context while invoke_request_id
    carries the minted skill-<hex> correlator through intact."""
    from cognic_agentos.observability.logging import _ContextFilter

    class _FilterOnlyHandler(logging.Handler):
        """No-op emit that still RUNS its filters — logging.NullHandler
        overrides handle() to skip filtering entirely, so it cannot stand
        in for the production handler here."""

        def emit(self, record: logging.LogRecord) -> None:
            return None

    filter_handler = _FilterOnlyHandler()
    filter_handler.addFilter(_ContextFilter())
    root = logging.getLogger()
    root.handlers.insert(0, filter_handler)
    try:
        proxy = _SpyProxy()
        backend = _EchoBackend(exec_raises=RuntimeError("exec boom"))
        loader = _StubLoader(_record(("oracle/list_tables",)))
        ex = SkillExecutor(
            sandbox_backend=backend,  # type: ignore[arg-type]
            skill_loader=loader,
            call_proxy=proxy,
            decision_history_store=DecisionHistoryStore(db),
            execution_timeout_s=5.0,
        )
        with caplog.at_level(logging.WARNING, logger="cognic_agentos.core.skill.executor"):
            result = await ex.invoke(skill_id="schema-summary", arguments={}, actor=_actor())
        assert result.refusal_reason == "skill_runtime_error"
        warnings = [r for r in caplog.records if r.message == "skill.invoke.sandbox_failed"]
        assert len(warnings) == 1
        rec = warnings[0]
        # The filter clobbered record.request_id with the (unbound) ambient
        # context — proving a same-named extra would have been destroyed...
        assert rec.request_id is None  # type: ignore[attr-defined]
        # ...while the distinct key carries the correlator through intact.
        assert rec.invoke_request_id.startswith("skill-")  # type: ignore[attr-defined]
    finally:
        root.removeHandler(filter_handler)


async def test_all_failure_warnings_carry_the_same_invoke_request_id(
    db: AsyncEngine, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Per-site coverage for the remaining WARNING sites in ONE invocation:
    exec-raise (sandbox_failed) + broker-close raise (broker_close_failed) +
    destroy raise (session_destroy_failed) all fire, each carrying the SAME
    minted invoke_request_id — the property that makes the key a correlator
    across a single invoke's failure cascade."""
    from cognic_agentos.core.skill._types import _BrokerHandle

    orig_close = _BrokerHandle.close

    async def _close_then_raise(self: _BrokerHandle) -> None:
        await orig_close(self)  # still clean up the real socket + 0700 dir
        raise RuntimeError("broker close boom")

    monkeypatch.setattr(_BrokerHandle, "close", _close_then_raise)
    proxy = _SpyProxy()
    backend = _EchoBackend(
        exec_raises=RuntimeError("exec boom"),
        destroy_raises=RuntimeError("destroy boom"),
    )
    loader = _StubLoader(_record(("oracle/list_tables",)))
    ex = SkillExecutor(
        sandbox_backend=backend,  # type: ignore[arg-type]
        skill_loader=loader,
        call_proxy=proxy,
        decision_history_store=DecisionHistoryStore(db),
        execution_timeout_s=5.0,
    )
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.core.skill.executor"):
        result = await ex.invoke(skill_id="schema-summary", arguments={}, actor=_actor())
    assert result.refusal_reason == "skill_runtime_error"
    by_message = {
        m: [r for r in caplog.records if r.message == m]
        for m in (
            "skill.invoke.sandbox_failed",
            "skill.broker_close_failed",
            "skill.session_destroy_failed",
        )
    }
    assert all(len(records) == 1 for records in by_message.values()), by_message
    ids = {records[0].invoke_request_id for records in by_message.values()}  # type: ignore[attr-defined]
    assert len(ids) == 1  # one invocation, one correlator across the cascade
    assert next(iter(ids)).startswith("skill-")
