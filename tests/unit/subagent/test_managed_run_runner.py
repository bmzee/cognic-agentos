import uuid
from typing import Any

import pytest

from cognic_agentos.core.run.executor import RunRequest, RunResult
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.subagent._types import ChildRunContext, ManagedRunChildSpec
from cognic_agentos.subagent.managed_run_runner import ManagedRunChildRunner


class _StubExecutor:
    def __init__(self, result: RunResult) -> None:
        self._result = result
        self.seen: RunRequest | None = None

    async def run(self, request: RunRequest) -> RunResult:
        self.seen = request
        return self._result


# minimal installed-pack record shape the runner reads — PackRecord has NO version column.
class _Rec:
    def __init__(self, pack_id: str, row_id: uuid.UUID) -> None:
        self.pack_id, self.id = pack_id, row_id


class _StubPackStore:
    def __init__(self, records: list[_Rec]) -> None:
        self._records = records

    async def list_for_tenant(
        self,
        tenant_id: str,
        *,
        limit: int,
        cursor: uuid.UUID | None = None,
        state: str | None = None,
    ) -> list[_Rec]:
        return self._records


def _actor(tenant: str = "t") -> Actor:
    return Actor(subject="svc-a", tenant_id=tenant, scopes=frozenset(), actor_type="service")


def _spec(
    *, pack_id: str = "p", pack_version: str = "1.2", argv: tuple[str, ...] = ("--x",)
) -> ManagedRunChildSpec:
    return ManagedRunChildSpec(pack_id=pack_id, pack_version=pack_version, argv=argv)


def _ctx(
    managed_run: ManagedRunChildSpec | None,
    *,
    tenant: str = "t",
    tokens: int = 100,
    parent: str | None = None,
) -> ChildRunContext:
    return ChildRunContext(
        prompt="p",
        granted_tools=frozenset(),
        requested_estimated_tokens=tokens,
        tenant_id=tenant,
        current_depth=1,
        child_trace_id="c",
        request_id="r",
        parent_record_id=uuid.uuid4(),
        actor=_actor(tenant),
        parent_task_id=parent,
        managed_run=managed_run,
    )


def _result(**kw: Any) -> RunResult:
    base: dict[str, Any] = dict(
        run_id="run-1",
        task_id="task-1",
        terminal_state="completed",
        exit_code=0,
        stdout=b"",
        stderr=b"",
        refusal_reason=None,
    )
    base.update(kw)
    return RunResult(**base)


async def test_fail_closed_when_managed_run_is_none() -> None:
    runner = ManagedRunChildRunner(executor=_StubExecutor(_result()), pack_store=_StubPackStore([]))
    child = await runner.run(_ctx(None))
    assert child.ok is False
    assert "managed_run" in child.summary  # fail-closed; no executor call


async def test_fail_closed_when_actor_is_none() -> None:
    # The other `or` branch of the runner's guard — managed_run present but actor=None.
    ctx = ChildRunContext(
        prompt="p",
        granted_tools=frozenset(),
        requested_estimated_tokens=10,
        tenant_id="t",
        current_depth=1,
        child_trace_id="c",
        request_id="r",
        parent_record_id=uuid.uuid4(),
        managed_run=_spec(),
        actor=None,
    )
    runner = ManagedRunChildRunner(executor=_StubExecutor(_result()), pack_store=_StubPackStore([]))
    child = await runner.run(ctx)
    assert child.ok is False
    assert "actor" in child.summary  # fail-closed on the missing portal Actor


async def test_zero_pack_matches_fail_closed() -> None:
    runner = ManagedRunChildRunner(
        executor=_StubExecutor(_result()),
        pack_store=_StubPackStore([]),
    )
    child = await runner.run(_ctx(_spec(pack_id="missing")))
    assert child.ok is False


async def test_multiple_pack_matches_fail_closed() -> None:
    dupes = [_Rec("p", uuid.uuid4()), _Rec("p", uuid.uuid4())]
    runner = ManagedRunChildRunner(
        executor=_StubExecutor(_result()),
        pack_store=_StubPackStore(dupes),
    )
    child = await runner.run(_ctx(_spec()))
    assert child.ok is False


async def test_happy_path_builds_run_request_and_maps_completed() -> None:
    row_id = uuid.uuid4()
    ex = _StubExecutor(_result(terminal_state="completed", exit_code=0))
    runner = ManagedRunChildRunner(executor=ex, pack_store=_StubPackStore([_Rec("p", row_id)]))
    child = await runner.run(
        _ctx(
            _spec(pack_id="p", pack_version="1.2"),
            tokens=77,
            parent="11111111-1111-1111-1111-111111111111",
        )
    )
    assert child.ok is True
    assert ex.seen is not None
    assert ex.seen.pack_id == "p" and ex.seen.pack_uuid == row_id
    # from the SPEC, not the record (PackRecord has no version)
    assert ex.seen.pack_version == "1.2"
    assert ex.seen.actor.subject == "svc-a"  # the full Actor threaded to RunRequest
    assert ex.seen.argv == ("--x",)
    assert ex.seen.parent_task_id == "11111111-1111-1111-1111-111111111111"  # string passthrough
    assert ex.seen.requested_estimated_tokens == 77
    assert child.tokens_used == 0  # documented metering gap


@pytest.mark.parametrize(
    "state,ok",
    [
        ("completed", True),
        ("failed", False),
        ("refused", False),
        ("pending_approval", False),
        ("suspended", False),
    ],
)
async def test_maps_every_run_terminal_state(state: str, ok: bool) -> None:
    exit_code = 0 if state == "completed" else 1
    ex = _StubExecutor(_result(terminal_state=state, exit_code=exit_code))
    runner = ManagedRunChildRunner(
        executor=ex, pack_store=_StubPackStore([_Rec("p", uuid.uuid4())])
    )
    child = await runner.run(_ctx(_spec()))
    assert child.ok is ok


@pytest.mark.parametrize(
    "state,expected_summary",
    [
        ("suspended", "suspended_child_unsupported"),
        ("pending_approval", "pending_approval_child_unsupported"),
    ],
)
async def test_special_case_summaries(state: str, expected_summary: str) -> None:
    # suspended + pending_approval get EXPLICIT summaries (spec §4), not the
    # generic `run=... state=... exit=...` fall-through.
    ex = _StubExecutor(_result(terminal_state=state, exit_code=1))
    runner = ManagedRunChildRunner(
        executor=ex, pack_store=_StubPackStore([_Rec("p", uuid.uuid4())])
    )
    child = await runner.run(_ctx(_spec()))
    assert child.ok is False
    assert child.summary == expected_summary


async def test_completed_nonzero_exit_is_not_ok() -> None:
    ex = _StubExecutor(_result(terminal_state="completed", exit_code=3))
    runner = ManagedRunChildRunner(
        executor=ex, pack_store=_StubPackStore([_Rec("p", uuid.uuid4())])
    )
    child = await runner.run(_ctx(_spec()))
    assert child.ok is False
