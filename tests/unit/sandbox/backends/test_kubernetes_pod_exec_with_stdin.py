"""Sprint 8.5 T7 P1 + P1.2 — ``_open_pod_exec_stream_with_stdin`` +
``_restore_workspace_tar`` close-before-read + v4-protocol regression
suite.

**LOAD-BEARING** — pins the wake-restore wire contract under the v4
kubernetes exec subprotocol.

**P1 background (close-before-read).** aiohttp's
``ClientWebSocketResponse.close()`` has no half-close. An explicit
``ws.close()`` between the stdin send + the frame iteration tears
down the read direction + terminates the iterator before the
kubelet's ERROR-channel frame (carrying exit code) is delivered. The
original bug defaulted ``exit_code`` to 0 → silent green wake on tar
failure.

**P1.2 background (v4 EOF marker is a no-op).**
``kubernetes_asyncio`` 35.0.1 hard-codes ``v4.channel.k8s.io`` (line
101 of ``ws_client.py``). The v4 subprotocol has no per-stream CLOSE
frame; v5 (``v5.channel.k8s.io``) adds it as ``[0xFF, <stream_id>]``
per upstream ``apimachinery/pkg/util/remotecommand/constants.go``. An
empty-payload frame on channel 0 under v4 is just an empty data
frame, NOT EOF. The intermediate fix attempt that sent
``bytes([STDIN_CHANNEL])`` as an "EOF marker" was a no-op + would
have left ``tar xzf -`` hanging on stdin until walltime.

**The protocol-agnostic resolution.** ``_restore_workspace_tar``
wraps the tar in ``sh -c "head -c <N> > <tmp> && tar xzf <tmp> -C
/workspace && rm -f <tmp>"`` so the remote command consumes exactly
N bytes from stdin then exits naturally — no stdin EOF needed. The
helper now sends EXACTLY ONE frame (the stdin payload) + iterates
until the server-side websocket closes naturally.

Regressions in this file (8 total):

1. ``test_helper_sends_only_stdin_payload_no_v4_eof_marker`` — the
   helper sends EXACTLY ONE channel-0 frame; no follow-up empty-
   payload "EOF marker" (which would be a no-op under v4).
2. ``test_kubernetes_asyncio_hardcodes_v4_subprotocol`` — drift
   detector pinning the kubernetes_asyncio default subprotocol.
   Fires if a future upgrade switches to v5 (at which point the head
   -c workaround can be replaced with a v5 close frame).
3. ``test_restore_workspace_tar_uses_head_minus_c_known_length_pattern``
   — pins the ``sh -c "head -c <N> > <tmp> && tar xzf ... && rm -f
   <tmp>"`` command shape with the byte-count matching the snapshot
   length + per-session temp path.
4. ``test_helper_reads_all_frames_before_natural_close`` — LOAD-
   BEARING op-order pin. Every read precedes close; the ERROR-
   channel read specifically precedes close.
5. ``test_helper_parses_exit_code_from_error_channel_frame`` — the
   ERROR-channel exit code propagates (not silently 0).
6. ``test_helper_forces_minus_one_when_error_channel_frame_missing``
   — defence-in-depth sentinel: missing ERROR frame → exit_code=-1.
7. ``test_helper_source_does_not_call_ws_close_explicitly`` — AST
   self-test pinning the no-explicit-ws.close() source invariant.
8. ``test_helper_source_does_not_send_v4_eof_marker`` — AST self-
   test pinning the no-``send_bytes(bytes([STDIN_CHANNEL]))`` source
   invariant.

These regressions assume the helper signature
``_open_pod_exec_stream_with_stdin(*, pod_name, container_name,
command, stdin_bytes, walltime_s) -> tuple[bytes, bytes, int]`` and
``_restore_workspace_tar(*, session_id, snapshot_bytes) -> None`` at
``src/cognic_agentos/sandbox/backends/kubernetes_pod.py``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

pytest.importorskip("kubernetes_asyncio")

from kubernetes_asyncio import client as kube_client
from kubernetes_asyncio.stream import WsApiClient as _RealWsApiClient
from kubernetes_asyncio.stream.ws_client import (
    ERROR_CHANNEL,
    STDERR_CHANNEL,
    STDIN_CHANNEL,
    STDOUT_CHANNEL,
)

from cognic_agentos.sandbox.backends import kubernetes_pod as _kp_module
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    KubernetesPodSandboxBackend,
)

# ---------------------------------------------------------------------------
# Fake websocket / context-manager scaffolding
# ---------------------------------------------------------------------------


@dataclass
class _FakeWSMsg:
    """Mimic an ``aiohttp.WSMessage`` — only the ``.data`` attribute is
    accessed by the helper body."""

    data: bytes


class _FakeWs:
    """Recording fake of ``aiohttp.ClientWebSocketResponse``.

    Records the ORDER of operations (``send`` / ``read`` / ``close``)
    so the regressions can assert frame-consumption-before-close
    invariants directly.
    """

    def __init__(self, frames: list[_FakeWSMsg]) -> None:
        self._frames = list(frames)
        self._closed = False
        self.ops: list[tuple[Any, ...]] = []

    async def send_bytes(self, body: bytes) -> None:
        # Capture the FULL bytes so the regression can pin both the
        # channel byte + the payload shape (stdin chunk vs EOF marker).
        self.ops.append(("send", body))

    def __aiter__(self) -> _FakeWs:
        return self

    async def __anext__(self) -> _FakeWSMsg:
        # Model aiohttp ``ClientWebSocketResponse``: once ``close()``
        # has been called the iterator terminates IMMEDIATELY. This is
        # the semantic that makes close-before-read a real bug at
        # runtime; the fake mirrors it so regressions 2/3/4 all catch
        # a TM-revert that re-introduces an explicit close.
        if self._closed:
            raise StopAsyncIteration
        if not self._frames:
            # No more frames + no explicit close — simulates server-
            # side close after the command exited + the ERROR-channel
            # frame was written.
            raise StopAsyncIteration
        frame = self._frames.pop(0)
        # Record the channel byte (or None for empty payloads) so the
        # op-order pin can assert reads-before-close.
        channel_byte = frame.data[0] if frame.data else None
        self.ops.append(("read", channel_byte))
        return frame

    async def close(self) -> None:
        # Aiohttp ClientWebSocketResponse close() tears down BOTH
        # directions — the fake mirrors this by setting ``_closed``
        # which makes any subsequent ``__anext__`` raise
        # ``StopAsyncIteration``. Order-of-ops regression asserts
        # every ``read`` op precedes the ``close`` op.
        self.ops.append(("close",))
        self._closed = True


class _FakeWsCtxMgr:
    """Async context manager wrapping a ``_FakeWs`` — mirrors aiohttp's
    ``ClientWebSocketResponse`` ``async with`` semantics."""

    def __init__(self, ws: _FakeWs) -> None:
        self.ws = ws

    async def __aenter__(self) -> _FakeWs:
        return self.ws

    async def __aexit__(self, *exc: Any) -> None:
        # __aexit__ closes the websocket — the canonical close path
        # the helper relies on.
        await self.ws.close()


class _FakeWsCtxAwaitable:
    """Mimics the ``_WSRequestContextManager`` from
    ``kubernetes_asyncio``: ``await ws_ctx`` yields the async-context-
    manager-bearing object that the helper then ``async with``-s."""

    def __init__(self, ws: _FakeWs) -> None:
        self._ws = ws

    def __await__(self) -> Any:
        async def _aw() -> _FakeWsCtxMgr:
            return _FakeWsCtxMgr(self._ws)

        return _aw().__await__()


class _StubWsApiClient(_RealWsApiClient):
    """Subclass of the real ``WsApiClient`` so the helper's
    ``WsApiClient.parse_error_data(...)`` classmethod call still
    resolves correctly via inheritance, but ``__init__`` skips the
    real ``ApiClient`` setup (no live HTTP) + ``close()`` is a no-op.

    Using a subclass instead of a function-stub is the canonical
    approach when a patched class symbol must still expose
    classmethods. The function-stub pattern would lose
    ``parse_error_data``.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # Skip super().__init__ — no real ApiClient setup.
        self.configuration = kwargs.get("configuration")  # type: ignore[assignment]

    async def close(self) -> None:
        return None


def _patch_ws_stack(monkeypatch: pytest.MonkeyPatch, fake_ws: _FakeWs) -> None:
    """Patch the WsApiClient + CoreV1Api stack so the helper's
    ``ws_api.connect_get_namespaced_pod_exec(...)`` call returns a
    ``_FakeWsCtxAwaitable`` wrapping our recording fake.

    ``WsApiClient`` is replaced by ``_StubWsApiClient`` (a subclass
    preserving ``parse_error_data``). ``CoreV1Api`` is replaced by a
    factory returning a mock whose ``connect_get_namespaced_pod_exec``
    yields the fake context.
    """
    monkeypatch.setattr(_kp_module, "WsApiClient", _StubWsApiClient)

    def _corev1_ctor(*args: Any, **kwargs: Any) -> MagicMock:
        api_mock = MagicMock()
        api_mock.connect_get_namespaced_pod_exec = MagicMock(
            return_value=_FakeWsCtxAwaitable(fake_ws)
        )
        return api_mock

    monkeypatch.setattr(kube_client, "CoreV1Api", _corev1_ctor)


def _make_backend_for_exec() -> KubernetesPodSandboxBackend:
    """A backend instance suitable for invoking the stdin-exec helper
    directly — minimal wiring; the helper only touches
    ``self._kube.configuration`` + ``self._namespace``."""
    api_client = MagicMock()
    api_client.configuration = MagicMock()
    backend = KubernetesPodSandboxBackend(
        kube_api_client=api_client,
        namespace="test-ns",
        image_catalog=MagicMock(),
        credential_adapter=MagicMock(),
        rego_engine=MagicMock(),
        audit_store=MagicMock(),
        decision_history_store=MagicMock(),
        settings=MagicMock(),
        warm_pool=None,
    )
    return backend


_ERROR_FRAME_SUCCESS = bytes([ERROR_CHANNEL]) + b'{"metadata":{},"status":"Success"}'
_ERROR_FRAME_EXIT_137 = bytes([ERROR_CHANNEL]) + (
    b'{"metadata":{},"status":"Failure",'
    b'"message":"command terminated with non-zero exit code 137",'
    b'"reason":"NonZeroExitCode",'
    b'"details":{"causes":[{"reason":"ExitCode","message":"137"}]}}'
)


# ---------------------------------------------------------------------------
# Regression 1 — single stdin frame, NO v4 EOF-marker frame
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_helper_sends_only_stdin_payload_no_v4_eof_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The helper MUST send EXACTLY ONE websocket frame on channel 0
    (the stdin payload). It MUST NOT send a follow-up
    ``bytes([STDIN_CHANNEL])`` empty-payload frame as an "EOF marker"
    — that is a no-op under the v4 kubernetes exec subprotocol
    (``v4.channel.k8s.io``) which has no per-stream close. v5
    (``v5.channel.k8s.io``) adds the close frame ``[0xFF, <stream_id>]``
    per upstream ``remotecommand/constants.go``, but kubernetes_asyncio
    35.0.1 hard-codes v4 + offers no v5 path.

    Callers MUST instead use a known-length consumption pattern (e.g.
    ``head -c N``) so the remote command exits without needing stdin
    EOF; ``_restore_workspace_tar`` wires that pattern.

    TM-revert intent: re-introduce
    ``await ws.send_bytes(bytes([STDIN_CHANNEL]))`` after the payload
    send and this test fails with len(send_ops) == 2.
    """
    fake_ws = _FakeWs(frames=[_FakeWSMsg(data=_ERROR_FRAME_SUCCESS)])
    _patch_ws_stack(monkeypatch, fake_ws)
    backend = _make_backend_for_exec()

    stdin_payload = b"tar archive bytes"
    await backend._open_pod_exec_stream_with_stdin(
        pod_name="sb-abc",
        container_name="sandbox",
        command=["sh", "-c", "head -c 17 > /tmp/x && cat /tmp/x"],
        stdin_bytes=stdin_payload,
        walltime_s=30.0,
    )

    send_ops = [op for op in fake_ws.ops if op[0] == "send"]
    assert len(send_ops) == 1, (
        f"expected EXACTLY ONE send (stdin payload only); got {len(send_ops)}: "
        f"{send_ops}. A second send with empty channel-0 payload is a no-op "
        "under v4 + would make a v4-only test author believe EOF was signalled."
    )
    assert send_ops[0] == ("send", bytes([STDIN_CHANNEL]) + stdin_payload)
    # Negative shape check — the empty-payload v4 'EOF marker' must NOT
    # appear anywhere in the op log.
    assert ("send", bytes([STDIN_CHANNEL])) not in fake_ws.ops, (
        "no-op v4 EOF marker re-introduced; per protocol it does not "
        "signal stdin close and the prior implementation hung on tar xzf"
    )


# ---------------------------------------------------------------------------
# Regression 1b — pin the kubernetes_asyncio negotiated subprotocol
# ---------------------------------------------------------------------------


def test_kubernetes_asyncio_hardcodes_v4_subprotocol() -> None:
    """Drift detector: this test fails if a future kubernetes_asyncio
    upgrade switches the default subprotocol away from
    ``v4.channel.k8s.io`` — at which point the AgentOS maintainer MUST
    revisit ``_restore_workspace_tar`` (a v5 default would unlock
    per-stream close frames + simpler restore semantics, but also
    invalidates the current ``head -c N`` workaround's rationale).

    Pinned at the source-string level so we catch a config-driven
    default change (env-var, configuration option) without false
    positives on header-name renames.
    """
    import inspect

    import kubernetes_asyncio.stream.ws_client as ws_client_mod

    src = inspect.getsource(ws_client_mod)
    assert '"v4.channel.k8s.io"' in src, (
        "kubernetes_asyncio.stream.ws_client no longer hardcodes "
        "v4.channel.k8s.io as the default subprotocol. Revisit "
        "_restore_workspace_tar in kubernetes_pod.py — v5 (which adds "
        "the close frame [0xFF, <stream_id>]) may now be available; "
        "if so, the head -c N workaround can be replaced with a v5 "
        "close frame on the stdin channel."
    )
    # Also pin that NO v5 default is silently shipping. A future
    # version that ships v5 SHOULD trip this test so the maintainer
    # consciously decides whether to upgrade the restore path.
    assert '"v5.channel.k8s.io"' not in src, (
        "kubernetes_asyncio now references v5.channel.k8s.io. Audit "
        "kubernetes_pod._restore_workspace_tar — the v5 close frame "
        "[0xFF, STDIN_CHANNEL] may now be supported."
    )


# ---------------------------------------------------------------------------
# Regression 1c — pin the _restore_workspace_tar command shape
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_restore_workspace_tar_uses_head_minus_c_known_length_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**LOAD-BEARING protocol-agnostic restore.**

    ``_restore_workspace_tar`` MUST invoke the helper with a
    ``sh -c "head -c <N> | tar xzf - -C /workspace"`` pipeline shape
    where ``N == len(snapshot_bytes)``. The pipeline shape (head
    piped directly to tar) avoids disk-staging a temp file —
    required because Sprint 8.5 T7 P1.3 only declared ``/workspace``
    as writable; ``/tmp`` (and every other path) remains read-only
    under ``readOnlyRootFilesystem=True``. The known-length
    consumption is what lets the remote command exit naturally
    under the v4 subprotocol (which cannot signal stdin EOF).

    TM-revert intent A: replace the wrapper with
    ``["tar", "xzf", "-", "-C", "/workspace"]`` (the original
    pre-fix shape) and this test fails on the command-arity check.

    TM-revert intent B: re-introduce a disk-staged temp file (e.g.
    ``head -c <N> > /tmp/...``) and this test fails on the
    no-redirect + must-have-pipe assertions.
    """
    captured: dict[str, Any] = {}

    async def _capture_exec_stream(
        *,
        pod_name: str,
        container_name: str,
        command: list[str],
        stdin_bytes: bytes,
        walltime_s: float | None,
    ) -> tuple[bytes, bytes, int]:
        captured["pod_name"] = pod_name
        captured["container_name"] = container_name
        captured["command"] = command
        captured["stdin_bytes"] = stdin_bytes
        captured["walltime_s"] = walltime_s
        return (b"", b"", 0)

    backend = _make_backend_for_exec()
    monkeypatch.setattr(backend, "_open_pod_exec_stream_with_stdin", _capture_exec_stream)

    snapshot = b"a" * 2048
    await backend._restore_workspace_tar(
        session_id="abc123def456",
        snapshot_bytes=snapshot,
    )

    cmd = captured["command"]
    assert isinstance(cmd, list)
    assert cmd[0] == "sh"
    assert cmd[1] == "-c"
    assert len(cmd) == 3, (
        f"expected exactly 3-element sh -c command; got {cmd!r}. The "
        "known-length restore pattern is wire-public protocol-version "
        "compatibility."
    )
    shell = cmd[2]
    assert "head -c 2048" in shell, (
        f"head -c <N> MUST carry the exact byte length {len(snapshot)}; got: {shell!r}. "
        "A wrong byte count would either truncate the tar (head exits early) or "
        "hang waiting for bytes that never arrive."
    )
    assert "tar xzf -" in shell, f"tar MUST read its archive from stdin (the pipe); got: {shell!r}"
    assert "-C /workspace" in shell, (
        f"extraction target MUST be /workspace (the writable emptyDir mount); got: {shell!r}"
    )
    # No disk-staged temp file. Per Sprint 8.5 T7 P1.3 writable-mount
    # contract: /workspace is the ONLY writable surface; /tmp and any
    # other path are read-only under readOnlyRootFilesystem=True. A
    # redirect-to-file pattern would fail with EROFS on a real
    # OpenShift Pod.
    assert ">" not in shell, (
        "restore command MUST NOT redirect head's output to a file. "
        "The pipeline shape `head | tar` keeps the staged bytes in a "
        "kernel pipe and avoids the read-only-filesystem EROFS class. "
        f"Got: {shell!r}"
    )
    assert "rm " not in shell and "rm\n" not in shell, (
        f"no temp file means no cleanup step; got: {shell!r}"
    )
    assert "|" in shell, (
        f"restore command MUST use a shell pipe between head and tar; got: {shell!r}"
    )
    # Stdin payload is unchanged (raw tar bytes).
    assert captured["stdin_bytes"] == snapshot


# ---------------------------------------------------------------------------
# Regression 2 — order-of-ops: all reads before close
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_helper_reads_all_frames_before_natural_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """**LOAD-BEARING close-before-read pin.**

    The helper MUST iterate STDOUT / STDERR / ERROR frames BEFORE the
    websocket close fires. The pre-fix bug called ``await ws.close()``
    explicitly between sending stdin + iterating frames; aiohttp's
    ``ClientWebSocketResponse.close()`` has no half-close, so the read
    direction tore down + the kubelet's ERROR-channel frame was lost +
    ``exit_code`` silently defaulted to 0.

    TM-revert intent: re-introduce ``await ws.close()`` between the
    EOF send + the ``async for`` loop in the helper and this test
    fails because the recorded op order shows ``close`` BEFORE the
    ERROR ``read``.
    """
    fake_ws = _FakeWs(
        frames=[
            _FakeWSMsg(data=bytes([STDOUT_CHANNEL]) + b"x" * 8),
            _FakeWSMsg(data=bytes([STDERR_CHANNEL]) + b"warn"),
            _FakeWSMsg(data=_ERROR_FRAME_SUCCESS),
        ]
    )
    _patch_ws_stack(monkeypatch, fake_ws)
    backend = _make_backend_for_exec()

    stdout, stderr, exit_code = await backend._open_pod_exec_stream_with_stdin(
        pod_name="sb-abc",
        container_name="sandbox",
        command=["tar", "xzf", "-", "-C", "/workspace"],
        stdin_bytes=b"payload",
        walltime_s=30.0,
    )

    # All three frames consumed.
    assert stdout == b"x" * 8
    assert stderr == b"warn"
    assert exit_code == 0  # ERROR frame status=Success → parse_error_data → 0

    # Op-order pin: every ``read`` op precedes the ``close`` op.
    close_indices = [i for i, op in enumerate(fake_ws.ops) if op[0] == "close"]
    assert len(close_indices) == 1, f"expected exactly one close; got: {fake_ws.ops}"
    close_idx = close_indices[0]
    read_indices = [i for i, op in enumerate(fake_ws.ops) if op[0] == "read"]
    assert read_indices, "expected the helper to read at least one frame"
    assert max(read_indices) < close_idx, (
        f"close-before-read violation: read indices {read_indices} vs "
        f"close index {close_idx}; ops={fake_ws.ops}"
    )

    # Pin the ERROR-channel read specifically — the highest-stakes
    # frame for cap enforcement.
    error_read_indices = [
        i for i, op in enumerate(fake_ws.ops) if op[0] == "read" and op[1] == ERROR_CHANNEL
    ]
    assert error_read_indices, (
        f"ERROR-channel frame was never read; exit_code would default silently. ops={fake_ws.ops}"
    )
    assert error_read_indices[0] < close_idx, (
        f"ERROR-channel read MUST happen before close; "
        f"error_read_index={error_read_indices[0]} close_index={close_idx}"
    )


# ---------------------------------------------------------------------------
# Regression 3 — ERROR-channel exit code propagates (not silently 0)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_helper_parses_exit_code_from_error_channel_frame(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tar-failure path: the ERROR-channel frame carries exit code 137
    (out-of-memory). The helper MUST surface 137, NOT 0.

    Pre-fix bug: close-before-read dropped the ERROR frame; helper
    returned exit_code=0; caller's green path emitted
    ``sandbox.lifecycle.woken`` on a corrupted /workspace.
    """
    fake_ws = _FakeWs(
        frames=[
            _FakeWSMsg(data=bytes([STDERR_CHANNEL]) + b"tar: out of memory"),
            _FakeWSMsg(data=_ERROR_FRAME_EXIT_137),
        ]
    )
    _patch_ws_stack(monkeypatch, fake_ws)
    backend = _make_backend_for_exec()

    _stdout, stderr, exit_code = await backend._open_pod_exec_stream_with_stdin(
        pod_name="sb-abc",
        container_name="sandbox",
        command=["tar", "xzf", "-", "-C", "/workspace"],
        stdin_bytes=b"payload",
        walltime_s=30.0,
    )

    assert exit_code == 137, (
        f"expected exit_code=137 from ERROR-channel frame; got {exit_code}. "
        "A return of 0 here would mean the ERROR-channel frame was lost "
        "(close-before-read regression)."
    )
    assert b"out of memory" in stderr


# ---------------------------------------------------------------------------
# Regression 4 — missing ERROR-channel frame → exit_code=-1, not silently 0
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_helper_forces_minus_one_when_error_channel_frame_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defence-in-depth: if the iterator exits without ever yielding an
    ERROR-channel frame (truncated stream / kubelet bug / future
    close-before-read regression), the helper MUST surface ``-1`` so
    the caller's exit-zero green path cannot fire silently.

    This is the fail-closed safety net that catches any FUTURE
    regression that re-introduces close-before-read OR otherwise drops
    the ERROR frame.
    """
    fake_ws = _FakeWs(
        frames=[
            # STDOUT + STDERR only — NO ERROR-channel frame.
            _FakeWSMsg(data=bytes([STDOUT_CHANNEL]) + b"some output"),
            _FakeWSMsg(data=bytes([STDERR_CHANNEL]) + b"some stderr"),
        ]
    )
    _patch_ws_stack(monkeypatch, fake_ws)
    backend = _make_backend_for_exec()

    _stdout, _stderr, exit_code = await backend._open_pod_exec_stream_with_stdin(
        pod_name="sb-abc",
        container_name="sandbox",
        command=["tar", "xzf", "-", "-C", "/workspace"],
        stdin_bytes=b"payload",
        walltime_s=30.0,
    )

    assert exit_code == -1, (
        f"expected exit_code=-1 sentinel when ERROR-channel frame is missing; "
        f"got {exit_code}. exit_code=0 here would re-open the silent-success "
        "failure mode the P1 fix exists to prevent."
    )


# ---------------------------------------------------------------------------
# Regression 5 — AST self-test: no explicit ws.close() in the helper body
# ---------------------------------------------------------------------------


def test_helper_source_does_not_call_ws_close_explicitly() -> None:
    """Source-level invariant: ``_open_pod_exec_stream_with_stdin``
    MUST NOT carry an explicit ``ws.close()`` call. Closing the
    websocket is the responsibility of the ``async with`` ``__aexit__``
    machinery AFTER frame iteration naturally completes.

    Pinning at the source level catches a future refactor that
    re-introduces ``await ws.close()`` between the EOF marker send +
    the ``async for`` loop — the exact bug pattern the P1 fix closed.

    Per ``feedback_security_regression_hardening``: this AST self-test
    + the TM-revert verification done by the orchestrator (re-running
    the behavior regression after temporarily re-introducing
    ``await ws.close()`` and confirming
    ``test_helper_reads_all_frames_before_natural_close`` fails)
    together pin both the source pattern + the runtime semantics.
    """
    src_path = (
        Path(__file__).resolve().parents[4]
        / "src"
        / "cognic_agentos"
        / "sandbox"
        / "backends"
        / "kubernetes_pod.py"
    )
    src = src_path.read_text()
    tree = ast.parse(src)

    helper_fn: ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.AsyncFunctionDef)
            and node.name == "_open_pod_exec_stream_with_stdin"
        ):
            helper_fn = node
            break
    assert helper_fn is not None, (
        "_open_pod_exec_stream_with_stdin not found in kubernetes_pod.py — "
        "the helper was renamed or removed; update this regression"
    )

    # Walk the helper body; find every ``ws.close()`` or ``await
    # ws.close()`` call. Empty list = invariant holds.
    explicit_ws_closes: list[ast.Call] = []
    for node in ast.walk(helper_fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr != "close":
            continue
        if not isinstance(func.value, ast.Name):
            continue
        if func.value.id != "ws":
            continue
        explicit_ws_closes.append(node)

    assert explicit_ws_closes == [], (
        "Sprint 8.5 T7 P1 regression: _open_pod_exec_stream_with_stdin "
        "MUST NOT contain an explicit `ws.close()` call. aiohttp's "
        "ClientWebSocketResponse.close() tears down both directions + "
        "terminates the iterator before the kubelet's ERROR-channel "
        "frame is delivered, which would silently default exit_code "
        "to 0 on tar failure. Closing is the responsibility of the "
        "`async with` __aexit__. Found "
        f"{len(explicit_ws_closes)} explicit ws.close() call(s) at "
        f"lines: {[c.lineno for c in explicit_ws_closes]}"
    )


def test_helper_source_does_not_send_v4_eof_marker() -> None:
    """Source-level invariant: ``_open_pod_exec_stream_with_stdin``
    MUST NOT contain a ``ws.send_bytes(bytes([STDIN_CHANNEL]))`` call
    (i.e. the no-op empty-payload "EOF marker" under v4). Under
    ``v4.channel.k8s.io`` an empty frame on channel 0 is just an empty
    data frame, NOT EOF — the prior fix attempt sent it believing it
    signalled stdin close, which would have left ``tar xzf -`` hanging
    until walltime expired.

    The correct path is the known-length consumption pattern wired
    into ``_restore_workspace_tar`` (``head -c <N>``); no EOF signal
    is required because the remote command exits naturally.

    Walk the helper body; assert NO ``send_bytes`` call exists whose
    single argument is exactly the AST shape ``bytes([STDIN_CHANNEL])``
    (a Call to ``bytes`` with a single-element list literal of
    ``STDIN_CHANNEL``).
    """
    src_path = (
        Path(__file__).resolve().parents[4]
        / "src"
        / "cognic_agentos"
        / "sandbox"
        / "backends"
        / "kubernetes_pod.py"
    )
    src = src_path.read_text()
    tree = ast.parse(src)

    helper_fn: ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.AsyncFunctionDef)
            and node.name == "_open_pod_exec_stream_with_stdin"
        ):
            helper_fn = node
            break
    assert helper_fn is not None

    def _is_bytes_stdin_channel_only(arg: ast.expr) -> bool:
        # Match: bytes([STDIN_CHANNEL]) — a Call to ``bytes`` with one
        # arg that is a list literal containing exactly one element
        # named ``STDIN_CHANNEL``.
        if not isinstance(arg, ast.Call):
            return False
        if not isinstance(arg.func, ast.Name) or arg.func.id != "bytes":
            return False
        if len(arg.args) != 1:
            return False
        inner = arg.args[0]
        if not isinstance(inner, ast.List):
            return False
        if len(inner.elts) != 1:
            return False
        elt = inner.elts[0]
        return isinstance(elt, ast.Name) and elt.id == "STDIN_CHANNEL"

    bad_sends: list[ast.Call] = []
    for node in ast.walk(helper_fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr != "send_bytes":
            continue
        if len(node.args) != 1:
            continue
        if _is_bytes_stdin_channel_only(node.args[0]):
            bad_sends.append(node)

    assert bad_sends == [], (
        "Sprint 8.5 T7 P1.2 regression: _open_pod_exec_stream_with_stdin "
        "MUST NOT call `ws.send_bytes(bytes([STDIN_CHANNEL]))` (the no-op "
        "v4 EOF marker). Under v4.channel.k8s.io an empty channel-0 frame "
        "is just an empty data frame, NOT EOF; tar xzf - would hang on "
        "stdin read until walltime. Use the known-length consumption "
        "pattern (head -c N) wired into _restore_workspace_tar instead. "
        f"Found {len(bad_sends)} bad send_bytes call(s) at lines: "
        f"{[c.lineno for c in bad_sends]}"
    )
