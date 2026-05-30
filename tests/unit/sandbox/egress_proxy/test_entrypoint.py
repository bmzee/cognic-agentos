"""T6 — egress-proxy PID1 entrypoint orchestration (DI/fakes only).

These tests exercise :class:`entrypoint.EgressProxyEntrypoint` WITHOUT a real
tinyproxy and WITHOUT real OS signals. Every external effect is injected:

* a fake launcher (``_FakeProc`` recording terminate/kill/wait/poll) so launch +
  shutdown are observable;
* a no-op ``sleep`` so the loop never actually blocks;
* ``tmp_path`` for the config dir, native log, and access.jsonl;
* crafted ``env`` dicts.

Shutdown is driven by calling ``stop()`` directly (the signal-handler seam is
kept thin precisely so tests never register real handlers).

``cognic_egress_shim`` / ``entrypoint`` are image content under
``infra/sandbox/egress-proxy/`` (a hyphenated, non-importable dir put on
sys.path by ``conftest.py``); mypy cannot resolve them because ``infra/`` is
outside the ``src``/``tests`` type-check roots.
"""

import json
from collections.abc import Callable
from pathlib import Path
from typing import ClassVar

import pytest
from cognic_egress_shim import ShimStartupError  # type: ignore[import-not-found]
from entrypoint import EgressProxyEntrypoint, Proc, _proxy_argv  # type: ignore[import-not-found]


class _FakeProc:
    """Records terminate/kill/wait/poll for shutdown assertions.

    ``alive_after_terminate`` models a hung child: when True, ``wait`` raises
    ``TimeoutExpired`` (forcing the kill path) and ``poll`` reports running until
    ``kill`` is called; when False, the child exits cleanly on terminate.
    """

    def __init__(self, *, alive_after_terminate: bool = False) -> None:
        self.alive_after_terminate = alive_after_terminate
        self.terminated = False
        self.killed = False
        self.wait_calls: list[float | None] = []
        self._running = True

    def terminate(self) -> None:
        self.terminated = True
        if not self.alive_after_terminate:
            self._running = False

    def kill(self) -> None:
        self.killed = True
        self._running = False

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls.append(timeout)
        if self._running and self.alive_after_terminate and timeout is not None:
            import subprocess

            raise subprocess.TimeoutExpired(cmd="tinyproxy", timeout=timeout)
        return 0

    def poll(self) -> int | None:
        return None if self._running else 0


class _ExitedProc:
    """A proxy that has ALREADY exited on its own (crash / bad config / bind
    failure) — ``poll`` reports its return code immediately, with no
    ``terminate`` first. Models the PID1-liveness scenario the wrapper must
    notice: the managed child died and ``run()`` must stop looping + propagate
    status instead of sleeping forever."""

    def __init__(self, *, returncode: int) -> None:
        self.returncode = returncode
        self.terminated = False
        self.killed = False

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode  # already exited


def _no_sleep(_seconds: float) -> None:
    """Injected sleep that never blocks the test loop."""


def _make_entrypoint(
    tmp_path: Path,
    *,
    env: dict[str, str],
    launcher: Callable[[list[str]], Proc],
) -> EgressProxyEntrypoint:
    """Construct an entrypoint wired to tmp_path files + an injected launcher."""
    return EgressProxyEntrypoint(
        env=env,
        config_dir=tmp_path / "conf",
        native_log_path=tmp_path / "tinyproxy.native.log",
        access_jsonl_path=tmp_path / "access.jsonl",
        launch_proxy=launcher,
        sleep=_no_sleep,
        poll_interval_s=0.0,
        shutdown_grace_s=0.01,
    )


def _native_line(level: str, ts: str, pid: int, message: str) -> str:
    """Build one tinyproxy ``LogLevel Info`` line in the shim-recognised shape."""
    return f"{level}   {ts} [{pid}]: {message}"


def _request_line(ts: str, target: str, *, method: str = "GET") -> str:
    return _native_line(
        "CONNECT", ts, 42, f"Request (file descriptor 2): {method} {target} HTTP/1.1"
    )


def _established_line(ts: str, host: str) -> str:
    return _native_line(
        "CONNECT", ts, 42, f'Established connection to host "{host}" using file descriptor 3.'
    )


# ---------------------------------------------------------------------------
# 1. Refuse startup on missing/empty SESSION_ID — launcher NOT called.
# ---------------------------------------------------------------------------
class TestRefuseStartupOnMissingSession:
    def test_setup_raises_and_launcher_not_called_on_missing_session(self, tmp_path):
        calls: list[list[str]] = []

        def _launcher(argv):
            calls.append(argv)
            return _FakeProc()

        ep = _make_entrypoint(tmp_path, env={}, launcher=_launcher)
        with pytest.raises(ShimStartupError):
            ep._setup()
        assert calls == []  # proxy must NOT start without a session correlation.

    def test_setup_raises_on_empty_session(self, tmp_path):
        calls: list[list[str]] = []

        def _launcher(argv):
            calls.append(argv)
            return _FakeProc()

        ep = _make_entrypoint(tmp_path, env={"SESSION_ID": ""}, launcher=_launcher)
        with pytest.raises(ShimStartupError):
            ep._setup()
        assert calls == []

    def test_run_propagates_refusal_and_launcher_not_called(self, tmp_path):
        calls: list[list[str]] = []

        def _launcher(argv):
            calls.append(argv)
            return _FakeProc()

        ep = _make_entrypoint(tmp_path, env={}, launcher=_launcher)
        with pytest.raises(ShimStartupError):
            ep.run()
        assert calls == []


# ---------------------------------------------------------------------------
# 2. Malformed ALLOW_LIST => deny-all filter, but proxy STILL starts.
# ---------------------------------------------------------------------------
class TestMalformedAllowListDeniesAllButStarts:
    def test_malformed_allow_list_writes_empty_filter_and_still_launches(self, tmp_path):
        calls: list[list[str]] = []

        def _launcher(argv):
            calls.append(argv)
            return _FakeProc()

        ep = _make_entrypoint(
            tmp_path,
            env={"SESSION_ID": "sess-1", "ALLOW_LIST": "not json"},
            launcher=_launcher,
        )
        ep._setup()

        filter_path = tmp_path / "conf" / "tinyproxy.filter"
        assert filter_path.read_text(encoding="utf-8") == ""  # deny-all.
        assert len(calls) == 1  # proxy WAS launched despite deny-all.

    def test_absent_allow_list_also_deny_all_and_launches(self, tmp_path):
        calls: list[list[str]] = []

        def _launcher(argv):
            calls.append(argv)
            return _FakeProc()

        ep = _make_entrypoint(tmp_path, env={"SESSION_ID": "sess-1"}, launcher=_launcher)
        ep._setup()
        assert (tmp_path / "conf" / "tinyproxy.filter").read_text(encoding="utf-8") == ""
        assert len(calls) == 1

    def test_valid_allow_list_renders_anchored_host(self, tmp_path):
        ep = _make_entrypoint(
            tmp_path,
            env={"SESSION_ID": "sess-1", "ALLOW_LIST": '["api.example.com"]'},
            launcher=lambda argv: _FakeProc(),
        )
        ep._setup()
        content = (tmp_path / "conf" / "tinyproxy.filter").read_text(encoding="utf-8")
        assert content.splitlines() == [r"^api\.example\.com$"]


# ---------------------------------------------------------------------------
# 3. access.jsonl created BEFORE launch (asserted AT launch time).
# ---------------------------------------------------------------------------
class TestAccessJsonlCreatedBeforeLaunch:
    def test_sink_exists_when_launcher_is_invoked(self, tmp_path):
        access_path = tmp_path / "access.jsonl"
        observed_existed: list[bool] = []

        def _launcher(argv):
            observed_existed.append(access_path.exists())
            return _FakeProc()

        ep = _make_entrypoint(tmp_path, env={"SESSION_ID": "sess-1"}, launcher=_launcher)
        ep._setup()
        assert observed_existed == [True]  # existed at the moment of launch.

    def test_sink_is_empty_at_creation(self, tmp_path):
        ep = _make_entrypoint(
            tmp_path, env={"SESSION_ID": "sess-1"}, launcher=lambda argv: _FakeProc()
        )
        ep._setup()
        assert (tmp_path / "access.jsonl").read_text(encoding="utf-8") == ""


# ---------------------------------------------------------------------------
# 4. argv is a LIST, no shell.
# ---------------------------------------------------------------------------
class TestArgvIsListNoShell:
    def test_launcher_receives_argv_list(self, tmp_path):
        received: list[list[str]] = []

        def _launcher(argv):
            received.append(argv)
            return _FakeProc()

        ep = _make_entrypoint(tmp_path, env={"SESSION_ID": "sess-1"}, launcher=_launcher)
        ep._setup()
        assert len(received) == 1
        argv = received[0]
        assert isinstance(argv, list)
        conf_path = str(tmp_path / "conf" / "tinyproxy.conf")
        assert argv == ["tinyproxy", "-d", "-c", conf_path]

    def test_proxy_argv_shape_is_pinned_list(self):
        argv = _proxy_argv(Path("/etc/cognic-proxy/tinyproxy.conf"))
        assert argv == ["tinyproxy", "-d", "-c", "/etc/cognic-proxy/tinyproxy.conf"]
        assert isinstance(argv, list)

    def test_default_launcher_uses_no_shell(self):
        # The production default launcher must use subprocess with a list argv,
        # never shell=True. Inspect the EXECUTABLE source (docstring stripped, so
        # the prose "NEVER uses shell=True" in the docstring does not count) to
        # pin this without spawning a real process.
        import ast
        import inspect

        import entrypoint

        func = ast.parse(inspect.getsource(entrypoint._default_launch_proxy)).body[0]
        assert isinstance(func, ast.FunctionDef)
        # Drop the leading docstring expression if present.
        body = func.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        executable_src = "\n".join(ast.unparse(node) for node in body)
        assert "shell=True" not in executable_src
        assert "subprocess.Popen(argv)" in executable_src


# ---------------------------------------------------------------------------
# 5. Incremental tail, no dup, cross-poll pairing.
# ---------------------------------------------------------------------------
class TestIncrementalTailNoDupCrossPoll:
    def test_request_then_outcome_across_two_ticks_pairs_once(self, tmp_path):
        native = tmp_path / "tinyproxy.native.log"
        ep = _make_entrypoint(
            tmp_path, env={"SESSION_ID": "sess-x"}, launcher=lambda argv: _FakeProc()
        )
        parser = ep._setup()

        # Tick 1: only the Request line is present -> pending, 0 records emitted.
        native.write_text(
            _request_line("May 28 15:08:52.926", "http://allowed.test/") + "\n",
            encoding="utf-8",
        )
        ep._tick(parser)
        assert (tmp_path / "access.jsonl").read_text(encoding="utf-8") == ""

        # Tick 2: append the Established outcome -> exactly 1 paired record.
        with native.open("a", encoding="utf-8") as fh:
            fh.write(_established_line("May 28 15:08:52.928", "allowed.test") + "\n")
        ep._tick(parser)

        lines = [
            ln for ln in (tmp_path / "access.jsonl").read_text(encoding="utf-8").splitlines() if ln
        ]
        assert len(lines) == 1
        rec = json.loads(lines[0])
        assert rec["host"] == "allowed.test"
        assert rec["method"] == "GET"
        assert rec["outcome"] == "allowed"
        assert rec["policy_id"] == "sess-x"

        # Tick 3: no new bytes -> no re-emit / dup.
        ep._tick(parser)
        lines_after = [
            ln for ln in (tmp_path / "access.jsonl").read_text(encoding="utf-8").splitlines() if ln
        ]
        assert len(lines_after) == 1

    def test_offset_advances_and_consumed_bytes_not_reparsed(self, tmp_path):
        native = tmp_path / "tinyproxy.native.log"
        ep = _make_entrypoint(
            tmp_path, env={"SESSION_ID": "sess-x"}, launcher=lambda argv: _FakeProc()
        )
        parser = ep._setup()

        full_pair = (
            _request_line("May 28 15:08:52.926", "http://a.test/")
            + "\n"
            + _established_line("May 28 15:08:52.928", "a.test")
            + "\n"
        )
        native.write_text(full_pair, encoding="utf-8")
        ep._tick(parser)
        first_offset = ep._native_offset
        assert first_offset == len(full_pair.encode("utf-8"))

        # No new bytes: a second tick reads nothing, offset unchanged, no dup.
        ep._tick(parser)
        assert ep._native_offset == first_offset
        lines = [
            ln for ln in (tmp_path / "access.jsonl").read_text(encoding="utf-8").splitlines() if ln
        ]
        assert len(lines) == 1

    def test_partial_trailing_line_buffered_until_newline(self, tmp_path):
        native = tmp_path / "tinyproxy.native.log"
        ep = _make_entrypoint(
            tmp_path, env={"SESSION_ID": "sess-x"}, launcher=lambda argv: _FakeProc()
        )
        parser = ep._setup()

        # Write a Request line WITHOUT a trailing newline -> partial; no complete
        # line yet, so 0 records and the fragment is buffered.
        partial = _request_line("May 28 15:08:52.926", "http://b.test/")
        native.write_text(partial, encoding="utf-8")
        ep._tick(parser)
        assert ep._partial_line == partial
        assert (tmp_path / "access.jsonl").read_text(encoding="utf-8") == ""

        # Complete the line + add the outcome -> the buffered fragment joins and
        # both pair into exactly one record.
        with native.open("a", encoding="utf-8") as fh:
            fh.write("\n" + _established_line("May 28 15:08:52.928", "b.test") + "\n")
        ep._tick(parser)
        assert ep._partial_line == ""
        lines = [
            ln for ln in (tmp_path / "access.jsonl").read_text(encoding="utf-8").splitlines() if ln
        ]
        assert len(lines) == 1
        assert json.loads(lines[0])["host"] == "b.test"

    def test_tick_before_native_log_exists_is_noop(self, tmp_path):
        ep = _make_entrypoint(
            tmp_path, env={"SESSION_ID": "sess-x"}, launcher=lambda argv: _FakeProc()
        )
        parser = ep._setup()
        # tinyproxy has not created its native log yet -> tick is a no-op.
        assert not (tmp_path / "tinyproxy.native.log").exists()
        ep._tick(parser)  # must not raise.
        assert (tmp_path / "access.jsonl").read_text(encoding="utf-8") == ""


# ---------------------------------------------------------------------------
# 6. Noise / malformed line non-fatal.
# ---------------------------------------------------------------------------
class TestNoiseLineNonFatal:
    def test_garbage_between_valid_lines_does_not_raise_and_records_still_emit(self, tmp_path):
        native = tmp_path / "tinyproxy.native.log"
        ep = _make_entrypoint(
            tmp_path, env={"SESSION_ID": "sess-x"}, launcher=lambda argv: _FakeProc()
        )
        parser = ep._setup()

        log = "\n".join(
            [
                _request_line("May 28 15:08:52.926", "http://ok.test/"),
                "!!! totally unparseable garbage line @@@ not a tinyproxy info line",
                _established_line("May 28 15:08:52.928", "ok.test"),
            ]
        )
        native.write_text(log + "\n", encoding="utf-8")
        ep._tick(parser)  # must not raise.

        lines = [
            ln for ln in (tmp_path / "access.jsonl").read_text(encoding="utf-8").splitlines() if ln
        ]
        assert len(lines) == 1
        assert json.loads(lines[0])["host"] == "ok.test"


# ---------------------------------------------------------------------------
# 7. JSONL flushed + parseable, carries ProxyAccessRecord keys.
# ---------------------------------------------------------------------------
class TestJsonlFlushedAndParseable:
    _RECORD_KEYS: ClassVar[set[str]] = {
        "host",
        "method",
        "timestamp",
        "policy_id",
        "outcome",
        "refusal_reason",
    }

    def test_each_line_loads_cleanly_with_expected_keys(self, tmp_path):
        native = tmp_path / "tinyproxy.native.log"
        ep = _make_entrypoint(
            tmp_path, env={"SESSION_ID": "sess-keys"}, launcher=lambda argv: _FakeProc()
        )
        parser = ep._setup()

        log = "\n".join(
            [
                _request_line("May 28 15:08:52.926", "http://allowed.test/"),
                _established_line("May 28 15:08:52.928", "allowed.test"),
                _request_line("May 28 15:08:52.946", "http://denied.test/"),
                _native_line(
                    "NOTICE",
                    "May 28 15:08:52.946",
                    42,
                    'Proxying refused on filtered domain "denied.test"',
                ),
            ]
        )
        native.write_text(log + "\n", encoding="utf-8")
        ep._tick(parser)

        lines = [
            ln for ln in (tmp_path / "access.jsonl").read_text(encoding="utf-8").splitlines() if ln
        ]
        assert len(lines) == 2
        for ln in lines:
            rec = json.loads(ln)  # parses cleanly.
            assert set(rec.keys()) == self._RECORD_KEYS
            assert rec["policy_id"] == "sess-keys"

        allowed, refused = (json.loads(lines[0]), json.loads(lines[1]))
        assert allowed["outcome"] == "allowed" and allowed["refusal_reason"] is None
        assert refused["outcome"] == "refused"
        assert refused["refusal_reason"] == "not_in_allow_list"


# ---------------------------------------------------------------------------
# 8. Shutdown: terminate + bounded wait, kill only if it did not exit.
# ---------------------------------------------------------------------------
class TestShutdown:
    def test_clean_exit_no_kill(self, tmp_path):
        proc = _FakeProc(alive_after_terminate=False)
        ep = _make_entrypoint(tmp_path, env={"SESSION_ID": "sess-1"}, launcher=lambda argv: proc)
        ep._setup()
        ep.stop()
        ep._shutdown_proxy()

        assert proc.terminated is True
        assert proc.wait_calls  # a bounded wait happened.
        assert proc.wait_calls[0] == ep.shutdown_grace_s  # bounded, not infinite.
        assert proc.killed is False  # exited cleanly -> no kill.

    def test_hung_proc_gets_killed(self, tmp_path):
        proc = _FakeProc(alive_after_terminate=True)
        ep = _make_entrypoint(
            tmp_path,
            env={"SESSION_ID": "sess-1"},
            launcher=lambda argv: proc,
        )
        ep._setup()
        ep.stop()
        ep._shutdown_proxy()

        assert proc.terminated is True
        assert proc.wait_calls[0] == ep.shutdown_grace_s  # bounded wait first.
        assert proc.killed is True  # did not exit -> escalated to kill.

    def test_shutdown_noop_when_proxy_never_launched(self, tmp_path):
        # Refuse-startup leaves _proc None; _shutdown_proxy must be a safe no-op.
        ep = _make_entrypoint(tmp_path, env={}, launcher=lambda argv: _FakeProc())
        ep._shutdown_proxy()  # must not raise.

    def test_run_loop_stops_and_shuts_down(self, tmp_path):
        # A sleep seam that stops the loop after the first tick so run() returns,
        # then assert the proxy was shut down via the finally block.
        proc = _FakeProc(alive_after_terminate=False)
        ep = _make_entrypoint(tmp_path, env={"SESSION_ID": "sess-1"}, launcher=lambda argv: proc)

        def _stop_after_first(_seconds: float) -> None:
            ep.stop()

        ep.sleep = _stop_after_first
        ep.run()
        assert proc.terminated is True


# ---------------------------------------------------------------------------
# 9. PID1 liveness: the managed proxy dying on its own must stop the loop
#    immediately (no further sleep) and propagate the exit status.
# ---------------------------------------------------------------------------
class TestRunExitsWhenProxyDies:
    def test_run_exits_immediately_no_sleep_when_proxy_already_dead(self, tmp_path):
        sleeps: list[float] = []
        proc = _ExitedProc(returncode=0)
        ep = EgressProxyEntrypoint(
            env={"SESSION_ID": "sess-live"},
            config_dir=tmp_path / "conf",
            native_log_path=tmp_path / "tinyproxy.native.log",
            access_jsonl_path=tmp_path / "access.jsonl",
            launch_proxy=lambda argv: proc,
            sleep=sleeps.append,
            poll_interval_s=0.0,
            shutdown_grace_s=0.01,
        )
        rc = ep.run()
        assert rc == 0
        # The child was dead on the first poll, so run() broke BEFORE sleeping —
        # a live sidecar must not keep ticking around a dead proxy.
        assert sleeps == []
        # Already exited -> _shutdown_proxy must not terminate/kill it.
        assert proc.terminated is False
        assert proc.killed is False

    def test_run_propagates_proxy_exit_code(self, tmp_path):
        proc = _ExitedProc(returncode=1)
        ep = _make_entrypoint(tmp_path, env={"SESSION_ID": "sess-live"}, launcher=lambda argv: proc)
        # Non-zero child status propagates to the PID1 return code so
        # orchestration can restart/fail the sidecar honestly.
        assert ep.run() == 1

    def test_shutdown_skips_terminate_on_already_exited_child(self, tmp_path):
        proc = _ExitedProc(returncode=0)
        ep = _make_entrypoint(tmp_path, env={"SESSION_ID": "sess-1"}, launcher=lambda argv: proc)
        ep._setup()
        ep._shutdown_proxy()
        assert proc.terminated is False
        assert proc.killed is False
