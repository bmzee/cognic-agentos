"""Canonical egress-proxy PID1 entrypoint — launches + tails managed tinyproxy.

This module is IMAGE CONTENT: it runs as PID1 INSIDE the cognic egress-proxy
Docker container, NOT inside the AgentOS Python package. It therefore uses ONLY
the Python standard library and MUST NOT import from ``cognic_agentos`` (the
package is not present in the proxy image). The only same-dir import is the pure
shim helpers from :mod:`cognic_egress_shim` (also image content).

Responsibilities (the T6 wiring of the T2-T5a pure pieces into a live process):

  1. Resolve ``policy_id`` from the env (``SESSION_ID``) — refuse startup if
     absent/empty (fail-closed: never run a proxy whose audit records cannot be
     correlated to a session).
  2. Render the tinyproxy Filter file from ``ALLOW_LIST`` — malformed input
     renders a deny-all filter (``""``), which is NOT a refuse-startup: the proxy
     still runs, it just denies all egress.
  3. Render + write the tinyproxy.conf.
  4. Create the ``access.jsonl`` sink file BEFORE launching the proxy (the
     backend reads it; it must exist by the time the proxy can emit anything).
  5. Launch tinyproxy as a managed foreground child (``-d``) with an argv LIST
     (never a shell string).
  6. Incrementally tail tinyproxy's NATIVE text log, parse newly-completed lines
     through the stateful :class:`cognic_egress_shim._LogParser`, and append each
     resolved ProxyAccessRecord as one JSONL line to ``access.jsonl`` (flushing
     promptly). The tail is incremental: it advances a byte offset and never
     re-reads/re-parses already-consumed bytes, and it buffers any partial
     trailing line for the next tick so a Request/outcome pair split across two
     polls still pairs.
  7. On SIGTERM/SIGINT, stop the loop and terminate the proxy (bounded wait, then
     kill if it does not exit).

The TWO log files are DISTINCT and MUST NOT be conflated:
  * the NATIVE log (``native_log_path``) — tinyproxy's own ``LogFile`` text
    output, which this entrypoint TAILS;
  * the access.jsonl (``access_jsonl_path``) — the ProxyAccessRecord JSONL this
    entrypoint WRITES for the AgentOS backend to read.

Everything below is structured around dependency-injection seams (launcher,
sleep, clock-free file paths) so the orchestration is unit-testable WITHOUT a
real tinyproxy or real OS signals — see ``tests/unit/sandbox/egress_proxy/``.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Protocol

from cognic_egress_shim import (  # type: ignore[import-not-found]
    _LogParser,
    render_filter_file,
    render_tinyproxy_conf,
    resolve_policy_id,
)

# AgentOS-internal constants (NOT workload-controlled). The native log is what
# tinyproxy writes (and the entrypoint tails); the access.jsonl is what the
# entrypoint writes (and the backend reads). They are DIFFERENT files — see the
# module docstring.
_DEFAULT_CONFIG_DIR = Path("/etc/cognic-proxy")
_DEFAULT_NATIVE_LOG_PATH = Path("/var/log/cognic-proxy/tinyproxy.native.log")
_DEFAULT_ACCESS_JSONL_PATH = Path("/var/log/cognic-proxy/access.jsonl")

# Filenames written into ``config_dir``.
_FILTER_FILENAME = "tinyproxy.filter"
_CONF_FILENAME = "tinyproxy.conf"

# Loop cadence + shutdown grace (seconds). Conservative defaults; the loop is
# I/O-bound on a growing local file so a sub-second poll keeps audit latency low.
_DEFAULT_POLL_INTERVAL_S = 0.5
_DEFAULT_SHUTDOWN_GRACE_S = 5.0


class Proc(Protocol):
    """The narrow subprocess surface the entrypoint manages.

    A real :class:`subprocess.Popen` structurally conforms. Tests inject a fake
    recording terminate/kill/wait so shutdown is exercised without a real child.
    """

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def poll(self) -> int | None: ...


def _default_launch_proxy(argv: list[str]) -> Proc:
    """Production launcher: spawn tinyproxy as a managed child via an argv LIST.

    NEVER uses ``shell=True`` — the argv is a list so the OS execs the binary
    directly with no shell interpolation of the (AgentOS-internal but
    still-never-shell) arguments.
    """
    return subprocess.Popen(argv)


def _proxy_argv(conf_path: Path) -> list[str]:
    """Return the tinyproxy launch argv as a LIST (never a shell string).

    ``-d`` runs tinyproxy in the foreground as a managed child so this entrypoint
    can signal it (terminate/kill) for graceful shutdown. ``-c <conf>`` points it
    at the rendered config (which carries the ``LogFile`` = native log path).

    The ``-d`` / ``LogFile`` interaction (does foreground mode still honour the
    file ``LogFile`` directive, or does it force stdout?) is verified LIVE at T13
    against the real binary; for T6 the argv SHAPE is what is pinned.
    """
    return ["tinyproxy", "-d", "-c", str(conf_path)]


class EgressProxyEntrypoint:
    """PID1 orchestrator: setup → launch → incremental tail loop → shutdown.

    All external effects are injected so the loop is unit-testable with fakes:
    ``launch_proxy`` (default wraps :func:`subprocess.Popen`), ``sleep`` (default
    :func:`time.sleep`), and the file paths (default the real container paths).
    """

    def __init__(
        self,
        *,
        env: Mapping[str, str],
        config_dir: Path = _DEFAULT_CONFIG_DIR,
        native_log_path: Path = _DEFAULT_NATIVE_LOG_PATH,
        access_jsonl_path: Path = _DEFAULT_ACCESS_JSONL_PATH,
        launch_proxy: Callable[[list[str]], Proc] = _default_launch_proxy,
        sleep: Callable[[float], None] = time.sleep,
        poll_interval_s: float = _DEFAULT_POLL_INTERVAL_S,
        shutdown_grace_s: float = _DEFAULT_SHUTDOWN_GRACE_S,
    ) -> None:
        self.env = env
        self.config_dir = config_dir
        self.native_log_path = native_log_path
        self.access_jsonl_path = access_jsonl_path
        self.launch_proxy = launch_proxy
        self.sleep = sleep
        self.poll_interval_s = poll_interval_s
        self.shutdown_grace_s = shutdown_grace_s

        # Set by stop() (signal handler or test); checked by the run() loop.
        self._stopped = False
        # The managed proxy handle, set by _setup().
        self._proc: Proc | None = None
        # Incremental-tail state: byte offset already consumed from the native
        # log + a buffer holding any partial trailing line (no newline yet).
        self._native_offset = 0
        self._partial_line = ""

    def _setup(self) -> _LogParser:
        """Render config, create the sink, launch the proxy; return a fresh parser.

        Refuse-startup contract: ``resolve_policy_id`` raises ``ShimStartupError``
        if ``SESSION_ID`` is absent/empty and we let it PROPAGATE — the proxy is
        NOT launched in that case (the launcher is never called).

        Fail-closed-deny contract: a malformed ``ALLOW_LIST`` renders a deny-all
        filter (``""``) but the proxy STILL starts (it just denies everything);
        this is NOT a refuse-startup.

        Ordering invariant: the ``access.jsonl`` sink is created (empty) BEFORE
        the proxy launches, so the backend never races a missing file.
        """
        # 1. Resolve policy_id FIRST — refuse startup before any side effect if
        #    SESSION_ID is absent/empty (let ShimStartupError propagate).
        policy_id = resolve_policy_id(dict(self.env))

        # 2. Render + write the deny-by-default Filter file. Malformed ALLOW_LIST
        #    -> "" (deny-all); the proxy still starts.
        self.config_dir.mkdir(parents=True, exist_ok=True)
        filter_path = self.config_dir / _FILTER_FILENAME
        filter_content = render_filter_file(self.env.get("ALLOW_LIST", ""))
        filter_path.write_text(filter_content, encoding="utf-8")

        # 3. Render + write the tinyproxy.conf (LogFile = NATIVE log, not jsonl).
        conf_path = self.config_dir / _CONF_FILENAME
        conf_content = render_tinyproxy_conf(
            filter_path=str(filter_path), log_path=str(self.native_log_path)
        )
        conf_path.write_text(conf_content, encoding="utf-8")

        # 4. Ensure BOTH log files' parent dirs exist + create the access.jsonl
        #    sink (empty) BEFORE launch. The native log is created by tinyproxy;
        #    we only guarantee its directory.
        self.native_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.access_jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.access_jsonl_path.exists():
            self.access_jsonl_path.write_text("", encoding="utf-8")

        # 5. Launch the managed proxy child with an argv LIST (never a shell).
        self._proc = self.launch_proxy(_proxy_argv(conf_path))

        # 6. Fresh stateful parser for the tail loop (cross-feed pairing).
        return _LogParser(policy_id=policy_id)

    def _read_new_complete_lines(self) -> list[str]:
        """Read native-log bytes since the stored offset; return COMPLETE lines.

        Advances ``self._native_offset`` past everything read this tick. Any
        partial trailing line (no terminating newline) is kept in
        ``self._partial_line`` and prepended next tick, so a line split across
        two reads is never parsed as two broken lines. Already-consumed bytes are
        NEVER re-read (incremental tail; no O(n²) re-parse).

        Returns ``[]`` if the native log does not exist yet (tinyproxy has not
        created it) or no new complete line has arrived.
        """
        if not self.native_log_path.exists():
            return []

        # Open in binary + seek to the consumed offset. Reading only the tail
        # keeps this O(new-bytes), not O(file-size).
        with self.native_log_path.open("rb") as fh:
            fh.seek(self._native_offset)
            chunk = fh.read()
            self._native_offset = fh.tell()

        if not chunk:
            return []

        # Decode tolerantly: a torn multibyte sequence at a chunk boundary must
        # not raise (the byte offset advanced regardless; replacement chars are
        # harmless — they only ever appear inside otherwise-noise lines).
        text = self._partial_line + chunk.decode("utf-8", errors="replace")

        # Split into lines; keep the last fragment buffered IF the chunk did not
        # end on a newline (i.e. the final line is still partial).
        if text.endswith("\n"):
            self._partial_line = ""
            complete = text.splitlines()
        else:
            lines = text.splitlines()
            self._partial_line = lines[-1] if lines else ""
            complete = lines[:-1]
        return complete

    def _tick(self, parser: _LogParser) -> None:
        """ONE incremental poll step: tail → parse → append JSONL (flushed).

        Reads only new complete lines, feeds them to the stateful parser, and
        appends each resolved record as one ``json.dumps`` line to the
        access.jsonl, flushing promptly so the backend sees records without
        waiting for the file to close. A malformed/garbage tinyproxy line is
        NON-FATAL: the parser ignores noise, and any per-record serialisation
        error is swallowed so the loop survives (valid records still emitted).
        """
        complete_lines = self._read_new_complete_lines()
        if not complete_lines:
            return

        try:
            records = parser.feed("\n".join(complete_lines))
        except Exception:
            # Defence-in-depth: the parser is noise-tolerant by design, but a
            # truly unexpected input must not kill the audit loop. Skip this
            # tick's lines and continue; the offset already advanced so we do
            # NOT re-read them.
            return

        if not records:
            return

        with self.access_jsonl_path.open("a", encoding="utf-8") as sink:
            for record in records:
                try:
                    line = json.dumps(record)
                except (TypeError, ValueError):
                    # A record that cannot serialise is dropped (non-fatal); the
                    # remaining valid records in this batch still get written.
                    continue
                sink.write(line + "\n")
            sink.flush()
            # Best-effort durability: fsync so the backend tail sees the bytes
            # even across an ungraceful container stop. Optional — never fatal.
            with contextlib.suppress(OSError):
                os.fsync(sink.fileno())

    def run(self) -> int:
        """Setup, then loop ticks until stopped OR the proxy exits; always shut
        the proxy down. Returns the proxy's exit code (0 on a clean ``stop()``)
        so the PID1 process status reflects proxy health — orchestration can
        restart/fail the sidecar honestly instead of seeing a live container
        wrapping a dead proxy.
        """
        parser = self._setup()
        exit_code = 0
        try:
            while not self._stopped:
                self._tick(parser)
                rc = self._proc.poll() if self._proc is not None else None
                if rc is not None:
                    # The managed proxy exited on its own (crash / bad config /
                    # bind failure / log-path permission). Stop looping NOW — no
                    # further sleep — and propagate its status; never keep a live
                    # sidecar with a dead proxy and no new audit records.
                    exit_code = rc
                    break
                self.sleep(self.poll_interval_s)
            # Final drain: capture any lines written since the last tick (the
            # proxy's dying gasp, or bytes buffered before a stop()).
            self._tick(parser)
        finally:
            self._shutdown_proxy()
        return exit_code

    def stop(self) -> None:
        """Request loop shutdown. Called by the signal handler AND by tests.

        Kept trivial + side-effect-free beyond the flag so it is safe to invoke
        from a signal handler (which runs in a restricted context)."""
        self._stopped = True

    def _shutdown_proxy(self) -> None:
        """Terminate the managed proxy: SIGTERM, bounded wait, then SIGKILL.

        No-op if the proxy was never launched (e.g. refuse-startup). Sends
        terminate first; if it does not exit within ``shutdown_grace_s`` (wait
        times out OR poll still reports running) escalates to kill + reap.
        """
        proc = self._proc
        if proc is None:
            return
        if proc.poll() is not None:
            # Already exited (and reaped by poll) — nothing to terminate/kill.
            # (e.g. run() detected the proxy died on its own.)
            return

        proc.terminate()
        try:
            proc.wait(timeout=self.shutdown_grace_s)
        except subprocess.TimeoutExpired:
            # Did not exit in time -> escalate to SIGKILL + reap.
            proc.kill()
            proc.wait()
            return

        # wait() returned, but double-check it actually exited (a fake/edge proc
        # could return without exiting); escalate if still running.
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    def install_signal_handlers(self) -> None:
        """Register SIGTERM + SIGINT to request shutdown.

        Kept as a THIN, separate method so unit tests never install real signal
        handlers — they drive shutdown by calling :meth:`stop` directly.
        """

        def _handle(_signum: int, _frame: object) -> None:
            # Signal-handler signature is fixed by the signal API; the args are
            # intentionally unused (underscore-prefixed) — we only request stop.
            self.stop()

        signal.signal(signal.SIGTERM, _handle)
        signal.signal(signal.SIGINT, _handle)


def main(_argv: Sequence[str] | None = None) -> None:
    """Production entry: construct from ``os.environ``, install signals, run.

    ``_argv`` is reserved (intentionally unused) so a future caller can pass a
    parsed argv without changing the signature; PID1 takes no CLI args today.
    """
    entrypoint = EgressProxyEntrypoint(env=os.environ)
    entrypoint.install_signal_handlers()
    sys.exit(entrypoint.run())


if __name__ == "__main__":
    main()
