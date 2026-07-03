"""M6 Task A4 (ADR-025) — generic in-sandbox skill-runner tests.

The runner is the SDK-light harness baked into the immutable skill
runtime image: it resolves the target ``cognic.skills`` entry point
INSIDE the sandbox, binds a broker-backed ``BrokerToolRegistry``, runs
``Skill.execute(**kwargs)`` and (via ``_main``) emits the result as a
final length-framed JSON frame on stdout. This suite pins:

- the green path: a declared tool call round-trips over a real Unix
  socket to a stub broker and the skill result returns;
- the refusal path: an UNDECLARED tool call surfaces the broker's
  ``SkillToolRefused("skill_tool_not_declared")`` out of ``run_skill``;
- entry-point resolution failures (absent / ambiguous / not a Skill);
- the unmodified ``Skill.__init__`` declared_tools cross-check firing
  against the broker registry's ``list_tools()``;
- the ``_main`` env contract (the EXACT five env-var names Task A5
  passes) + the final stdout frame on both the success and refusal
  arms;
- the SDK-light import fence (stdlib + ``cognic_agentos.sdk.*`` only).
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import shutil
import sys
import tempfile
from collections.abc import AsyncIterator, Iterator
from importlib import metadata
from pathlib import Path
from typing import Any, ClassVar

import pytest

import cognic_agentos.sdk.skill_runner as skill_runner
from cognic_agentos.sdk.skill import Skill, SkillUnregisteredToolError
from cognic_agentos.sdk.skill_transport import (
    SkillToolRefused,
    decode_frame,
    decode_frame_async,
    encode_frame,
)

_EP_GROUP = "cognic.skills"
_STUB_TOKEN = "stub-session-token"


# ---------------------------------------------------------------------------
# Fake skills (resolved via REAL importlib.metadata.EntryPoint.load())
# ---------------------------------------------------------------------------


class FakeSchemaSkill(Skill):
    name: ClassVar[str] = "schema-summary"
    declared_tools: ClassVar[tuple[str, ...]] = ("oracle/list_tables",)

    async def execute(self, **kwargs: Any) -> dict[str, Any]:
        tool = self._tools.get("oracle/list_tables")
        listing = await tool.invoke(owner=kwargs["owner"])
        return {"summary": listing["tables"]}


class ForbiddenToolSkill(Skill):
    name: ClassVar[str] = "forbidden"
    declared_tools: ClassVar[tuple[str, ...]] = ("oracle/list_tables",)

    async def execute(self, **kwargs: Any) -> dict[str, Any]:
        # Composition-time attempt to reach a tool OUTSIDE the declared
        # set — the broker (stub here) must refuse it per invariant #11.
        tool = self._tools.get("oracle/get_constraints")
        result: dict[str, Any] = await tool.invoke()
        return result


class NotASkill:
    """Entry-point target that is not a Skill subclass."""


def _ep(name: str, attr: str) -> metadata.EntryPoint:
    return metadata.EntryPoint(
        name=name, value=f"tests.unit.sdk.test_skill_runner:{attr}", group=_EP_GROUP
    )


def _install_entry_points(monkeypatch: pytest.MonkeyPatch, *eps: metadata.EntryPoint) -> None:
    def _fake_entry_points(*, group: str) -> tuple[metadata.EntryPoint, ...]:
        assert group == _EP_GROUP
        return eps

    monkeypatch.setattr(skill_runner, "entry_points", _fake_entry_points)


# ---------------------------------------------------------------------------
# Stub broker socket (emulates the A3 broker's declared-check wire arms)
# ---------------------------------------------------------------------------


class _StubBroker:
    def __init__(self, sock_path: str, *, declared: frozenset[str], result: dict[str, Any]) -> None:
        self.sock_path = sock_path
        self.session_token = _STUB_TOKEN
        self.requests: list[dict[str, Any]] = []
        self._declared = declared
        self._result = result
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_unix_server(self._handle, path=self.sock_path)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        frame = await decode_frame_async(reader)
        self.requests.append(frame)
        if frame.get("session_token") != self.session_token:
            response: dict[str, Any] = {
                "ok": False,
                "refused": True,
                "reason": "skill_broker_unauthorized",
            }
        elif frame["tool_ref"] in self._declared:
            response = {"ok": True, "result": self._result}
        else:
            response = {"ok": False, "refused": True, "reason": "skill_tool_not_declared"}
        writer.write(encode_frame(response))
        await writer.drain()
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()


@pytest.fixture
def short_sock_dir() -> Iterator[str]:
    # AF_UNIX sun_path cap (~104 bytes on darwin) rules out pytest tmp_path.
    d = tempfile.mkdtemp(prefix="csk-a4-")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
async def stub_broker(short_sock_dir: str) -> AsyncIterator[_StubBroker]:
    stub = _StubBroker(
        str(Path(short_sock_dir) / "s.sock"),
        declared=frozenset({"oracle/list_tables"}),
        result={"tables": ["EMPLOYEES", "DEPARTMENTS"]},
    )
    await stub.start()
    yield stub
    await stub.stop()


# ---------------------------------------------------------------------------
# run_skill — resolution + execution
# ---------------------------------------------------------------------------


async def test_run_skill_green_path_round_trips_tool_call(
    stub_broker: _StubBroker, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_entry_points(monkeypatch, _ep("schema-summary", "FakeSchemaSkill"))
    result = await asyncio.wait_for(
        skill_runner.run_skill(
            entry_point_name="schema-summary",
            sock_path=stub_broker.sock_path,
            session_token=stub_broker.session_token,
            declared_tools=["oracle/list_tables"],
            kwargs={"owner": "COGNIC"},
        ),
        timeout=5.0,
    )
    assert result == {"summary": ["EMPLOYEES", "DEPARTMENTS"]}
    assert stub_broker.requests == [
        {
            "session_token": _STUB_TOKEN,
            "tool_ref": "oracle/list_tables",
            "arguments": {"owner": "COGNIC"},
        }
    ]


async def test_run_skill_surfaces_undeclared_tool_refusal(
    stub_broker: _StubBroker, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_entry_points(monkeypatch, _ep("forbidden", "ForbiddenToolSkill"))
    with pytest.raises(SkillToolRefused) as exc_info:
        await asyncio.wait_for(
            skill_runner.run_skill(
                entry_point_name="forbidden",
                sock_path=stub_broker.sock_path,
                session_token=stub_broker.session_token,
                # The ClassVar cross-check passes (list_tables IS declared);
                # the REQUEST for get_constraints is what gets refused.
                declared_tools=["oracle/list_tables"],
                kwargs={},
            ),
            timeout=5.0,
        )
    assert exc_info.value.reason == "skill_tool_not_declared"


async def test_run_skill_unknown_entry_point_fails_loud(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_entry_points(monkeypatch)  # no entry points at all
    with pytest.raises(LookupError, match="no-such-skill"):
        await skill_runner.run_skill(
            entry_point_name="no-such-skill",
            sock_path="/run/x.sock",
            session_token="tok",
            declared_tools=[],
            kwargs={},
        )


async def test_run_skill_ambiguous_entry_point_fails_loud(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_entry_points(
        monkeypatch,
        _ep("schema-summary", "FakeSchemaSkill"),
        _ep("schema-summary", "ForbiddenToolSkill"),
    )
    with pytest.raises(LookupError, match="ambiguous"):
        await skill_runner.run_skill(
            entry_point_name="schema-summary",
            sock_path="/run/x.sock",
            session_token="tok",
            declared_tools=["oracle/list_tables"],
            kwargs={},
        )


async def test_run_skill_non_skill_entry_point_fails_loud(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_entry_points(monkeypatch, _ep("bogus", "NotASkill"))
    with pytest.raises(TypeError, match="Skill subclass"):
        await skill_runner.run_skill(
            entry_point_name="bogus",
            sock_path="/run/x.sock",
            session_token="tok",
            declared_tools=[],
            kwargs={},
        )


async def test_run_skill_declared_tools_cross_check_unmodified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The existing Skill.__init__ ClassVar cross-check runs against the
    # broker registry's list_tools() BEFORE execute — a skill declaring
    # a tool the executor did not grant is refused at instantiation.
    _install_entry_points(monkeypatch, _ep("schema-summary", "FakeSchemaSkill"))
    with pytest.raises(SkillUnregisteredToolError):
        await skill_runner.run_skill(
            entry_point_name="schema-summary",
            sock_path="/run/x.sock",
            session_token="tok",
            declared_tools=[],  # the grant does NOT include oracle/list_tables
            kwargs={"owner": "COGNIC"},
        )


# ---------------------------------------------------------------------------
# _main — the env contract Task A5 passes + the final stdout frame
# ---------------------------------------------------------------------------


def test_env_var_names_are_the_a5_contract() -> None:
    assert skill_runner.ENV_BROKER_SOCKET == "COGNIC_SKILL_BROKER_SOCKET"
    assert skill_runner.ENV_BROKER_SESSION_TOKEN == "COGNIC_SKILL_BROKER_SESSION_TOKEN"
    assert skill_runner.ENV_ENTRY_POINT == "COGNIC_SKILL_ENTRY_POINT"
    assert skill_runner.ENV_DECLARED_TOOLS_JSON == "COGNIC_SKILL_DECLARED_TOOLS_JSON"
    assert skill_runner.ENV_ARGUMENTS_JSON == "COGNIC_SKILL_ARGUMENTS_JSON"


class _BytesReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self.bytes_read = 0

    def read(self, n: int) -> bytes:
        chunk = self._data[self.bytes_read : self.bytes_read + n]
        self.bytes_read += len(chunk)
        return chunk


@pytest.fixture
def runner_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(skill_runner.ENV_ENTRY_POINT, "schema-summary")
    monkeypatch.setenv(skill_runner.ENV_BROKER_SOCKET, "/run/cognic-skill/broker.sock")
    monkeypatch.setenv(skill_runner.ENV_BROKER_SESSION_TOKEN, "tok-main")
    monkeypatch.setenv(skill_runner.ENV_DECLARED_TOOLS_JSON, '["oracle/list_tables"]')
    monkeypatch.setenv(skill_runner.ENV_ARGUMENTS_JSON, '{"owner": "COGNIC"}')


@pytest.mark.usefixtures("runner_env")
def test_main_success_writes_final_result_frame(
    monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    recorded: dict[str, Any] = {}

    async def _fake_run_skill(**kwargs: Any) -> dict[str, Any]:
        recorded.update(kwargs)
        return {"answer": 42}

    monkeypatch.setattr(skill_runner, "run_skill", _fake_run_skill)
    assert skill_runner._main() == 0
    # The env → run_skill projection is EXACTLY the A5 contract.
    assert recorded == {
        "entry_point_name": "schema-summary",
        "sock_path": "/run/cognic-skill/broker.sock",
        "session_token": "tok-main",
        "declared_tools": ["oracle/list_tables"],
        "kwargs": {"owner": "COGNIC"},
    }
    out = capsysbinary.readouterr().out
    assert decode_frame(_BytesReader(out), required_keys=("ok",)) == {
        "ok": True,
        "result": {"answer": 42},
    }


@pytest.mark.usefixtures("runner_env")
def test_main_tool_refusal_writes_refusal_frame_and_exits_nonzero(
    monkeypatch: pytest.MonkeyPatch, capsysbinary: pytest.CaptureFixture[bytes]
) -> None:
    async def _fake_run_skill(**kwargs: Any) -> dict[str, Any]:
        raise SkillToolRefused("skill_tool_not_declared")

    monkeypatch.setattr(skill_runner, "run_skill", _fake_run_skill)
    assert skill_runner._main() == 1
    out = capsysbinary.readouterr().out
    assert decode_frame(_BytesReader(out), required_keys=("ok",)) == {
        "ok": False,
        "refused": True,
        "reason": "skill_tool_not_declared",
    }


@pytest.mark.usefixtures("runner_env")
def test_main_missing_env_fails_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(skill_runner.ENV_BROKER_SESSION_TOKEN)
    with pytest.raises(RuntimeError, match="COGNIC_SKILL_BROKER_SESSION_TOKEN"):
        skill_runner._main()


@pytest.mark.usefixtures("runner_env")
def test_main_declared_tools_must_be_string_array(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(skill_runner.ENV_DECLARED_TOOLS_JSON, '{"not": "a list"}')
    with pytest.raises(RuntimeError, match="COGNIC_SKILL_DECLARED_TOOLS_JSON"):
        skill_runner._main()


@pytest.mark.usefixtures("runner_env")
def test_main_arguments_must_be_object(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(skill_runner.ENV_ARGUMENTS_JSON, "[1, 2]")
    with pytest.raises(RuntimeError, match="COGNIC_SKILL_ARGUMENTS_JSON"):
        skill_runner._main()


# ---------------------------------------------------------------------------
# SDK-light fence — stdlib + cognic_agentos.sdk.* only (the runner ships
# in the minimal sandbox runtime image; a kernel import here would both
# break the image build and smuggle kernel surface into the sandbox)
# ---------------------------------------------------------------------------


def test_runner_imports_are_sdk_light() -> None:
    module_path = Path(skill_runner.__file__)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "relative imports forbidden in SDK-light modules"
            assert node.module is not None
            names = [node.module]
        else:
            continue
        for name in names:
            top = name.split(".")[0]
            allowed = top in sys.stdlib_module_names or name.startswith("cognic_agentos.sdk")
            assert allowed, (
                f"forbidden import {name!r} in SDK-light skill_runner "
                "(stdlib + cognic_agentos.sdk.* only)"
            )
