"""Sprint-7A T14.C R15 pivot — isolated-subprocess EntryPoint.load() probe.

Replaces the static-AST loadability walk that R13/R14/R15 reviewer
rounds tried to harden incrementally. The reviewer's repeated finding
was that no static analyzer can prove arbitrary Python imports + name
resolutions succeed; each whack-a-mole round closed the named cases
while adjacent constructs slipped through. The R15 pivot trades the
static analyzer for a real load probe in a constrained subprocess.

Contract:

  :func:`probe_entry_point_loadability` — invoke
  ``importlib.metadata.EntryPoint(...).load()`` against the cosign-
  verified wheel in an isolated child interpreter. Return ``None`` on
  success or a :class:`LoadProbeFailure` carrying the closed-enum
  sub-case + diagnostic payload. Callers wrap in their own top-level
  refusal reason (``verify_entry_point_load_failed``).

Subprocess invariants (mirrors ``protocol/trust_gate.py``):

  - **Same interpreter**: ``sys.executable`` (NOT bare ``python``) so
    PATH cannot pick a different Python.
  - **Isolation**: ``-I`` flag — no PYTHONPATH, no PYTHONSTARTUP, no
    user site-packages. Wheel path goes on ``sys.path`` inside the
    probe script, not via env.
  - **Minimal env**: PATH + HOME only; no caller shell secrets
    inherited. Per-invocation success token is passed via env then
    immediately popped + held only in a probe local — see "Result-
    channel hardening" below.
  - **Timeout**: ``asyncio.wait_for`` with ``settings.load_probe_timeout_s``;
    SIGKILL + reap on timeout.
  - **Structured-output channel**: probe writes JSON result to an
    inherited file descriptor (NOT a path exposed via argv/env, NOT
    stdout / stderr), so module ``print(...)`` / ``sys.stderr.write(...)``
    calls during load cannot corrupt the result. The probe also
    redirects stdout / stderr to ``os.devnull`` during the load
    attempt as defense-in-depth.

Result-channel hardening (R15 follow-up reviewer P2 #2):

  Once a wheel's entry-point code is loaded, that code runs inside
  the probe subprocess and is by definition adversary code. The
  pre-fix design exposed the result-file PATH via ``argv[1]`` and
  held the open ``result_handle`` as a ``__main__`` global, so a
  probe-aware module could:

    1. Read ``sys.argv[1]`` for the result-file path.
    2. Open it + write ``{"ok": true}`` directly.
    3. Call ``os._exit(0)`` to skip the probe's own ``finally`` block.

  Verify would then see ``ok=true`` and accept code that would not
  otherwise have loaded. The post-fix design raises the bar:

    - **No path in argv / env.** Result-file is opened in the
      parent; the file descriptor is passed via ``pass_fds=(fd,)``
      and ``argv[1]`` carries only the fd integer.
    - **No globals in __main__.** All probe state (``result_handle``,
      ``success_token``, ``result_fd``) lives inside the local scope
      of ``_run_probe()``. After value capture, ``sys.argv`` is
      stripped to ``[script_name]``.
    - **Per-invocation success token.** Parent generates a fresh
      256-bit hex token, passes it via ``COGNIC_PROBE_TOKEN`` in the
      subprocess env. The child pops the env entry into a local
      variable BEFORE any imported-module code runs, so the imported
      module cannot read ``os.environ`` to retrieve it. The token is
      written into the result JSON ONLY by probe-owned code, AFTER
      ``ep.load()`` returns successfully.
    - **Parent enforces token match.** A result file claiming
      ``ok=True`` whose ``__cognic_probe_token__`` field does not
      equal the expected token routes to closed-enum failure mode
      ``load_probe_success_token_mismatch`` — refusal, fail-closed.

  Residual risk: a determined module that introspects the probe's
  own stack frame (``sys._getframe(...)`` or
  ``sys.modules['__main__']._run_probe.__code__``) could in
  principle read the local ``success_token``. Stack-frame
  introspection is a much higher attack bar than argv read; the
  trust gate is correctly placed at "before this code runs", and
  this hardening defends against the realistic forge-and-exit
  pattern reviewer P2 #2 named.

Closed-enum failure modes (carried via ``payload.failure_mode``;
caller wraps under top-level ``verify_entry_point_load_failed``):

  - ``load_probe_subprocess_error`` — ``asyncio.create_subprocess_exec``
    raised OSError (binary missing, fork failure).
  - ``load_probe_timeout`` — subprocess didn't complete within
    ``settings.load_probe_timeout_s``.
  - ``load_probe_unparseable_output`` — probe finished but the
    structured-result file was missing / unreadable / not valid JSON.
  - ``load_probe_module_import_failed`` — ``EntryPoint.load()`` raised
    ``ImportError`` / ``ModuleNotFoundError`` (e.g., missing import
    line, bad imported symbol).
  - ``load_probe_object_not_found`` — load reached the module but
    ``getattr(module, object)`` raised ``AttributeError``.
  - ``load_probe_module_runtime_error`` — any other exception during
    load (NameError on forward ref, RuntimeError from top-level
    raise, etc.).
  - ``load_probe_success_token_mismatch`` — probe result claimed
    ``ok=True`` but the per-invocation token was missing / wrong;
    indicates a probe-aware module forged success via the inherited
    result fd and exited before probe-owned token-write executed
    (R15 follow-up P2 #2 fix).
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any, Final


@dataclasses.dataclass(frozen=True, slots=True)
class LoadProbeFailure:
    """Carrier for an entry-point-load-probe refusal. ``failure_mode``
    is the closed-enum sub-case; callers wrap in their own top-level
    closed-enum reason (``verify_entry_point_load_failed``).
    """

    failure_mode: str
    message: str
    payload: dict[str, Any] = dataclasses.field(default_factory=dict)


#: Subprocess invariant: minimal env. Mirrors
#: ``protocol/trust_gate.py::_SUBPROCESS_ENV`` doctrine — only PATH +
#: HOME; no caller shell secrets inherited. The probe doesn't need
#: COSIGN_PASSWORD / VAULT_* / KMS credentials (it only imports
#: pure-Python wheel content).
_SUBPROCESS_ENV: Final[dict[str, str]] = {
    "PATH": "/usr/local/bin:/usr/bin",
    "HOME": "/tmp",
}


#: Embedded probe script. Runs in the child interpreter under
#: ``sys.executable -I -c <this string>``. Reads argv:
#:   argv[1] — result file descriptor INTEGER (NOT a path; inherited
#:             via ``pass_fds=(fd,)`` from the parent — R15 follow-up
#:             P2 #2 hardening)
#:   argv[2] — wheel path (.whl ZIP; placed on sys.path)
#:   argv[3] — module dotted path (e.g., ``pkg.subpkg.mod``)
#:   argv[4] — object name (e.g., ``Cls``; single segment per R11 P2 #1)
#:
#: Per-invocation env:
#:   COGNIC_PROBE_TOKEN — random 256-bit hex token. Probe pops the
#:   env entry into a local variable BEFORE any imported-module code
#:   runs; the token is written into the result JSON only by probe-
#:   owned code AFTER ``ep.load()`` returns. (R15 follow-up P2 #2.)
#:
#: Output schema (JSON):
#:   {"ok": bool,
#:    "__cognic_probe_token__": str,    # present only on ok=True
#:    "phase": "module_import" | "object_lookup"
#:           | "module_runtime" | None,
#:    "error_class": str | None, "error_message": str | None}
#:
#: Phase distinguishes admission-relevant failure modes:
#:   - ``module_import`` — ImportError / ModuleNotFoundError during
#:     ``importlib.import_module``.
#:   - ``object_lookup`` — AttributeError when ``EntryPoint.load`` does
#:     ``getattr`` on the imported module.
#:   - ``module_runtime`` — any other exception during load (NameError
#:     on forward refs, top-level raise, decorator/default failure).
#:
#: Implementation notes:
#:   - All probe state lives inside ``_run_probe()`` locals — NOT
#:     ``__main__`` globals. ``sys.argv`` is stripped to
#:     ``[script_name]`` after value capture. R15 follow-up P2 #2.
#:   - ``contextlib.redirect_stdout`` / ``redirect_stderr`` redirect
#:     module-level prints during ``ep.load()`` to a file object
#:     opened on ``/dev/null`` — NOT ``io.StringIO()``. R15 P3
#:     reviewer correction: an ``io.StringIO`` sink lets a module that
#:     prints in a loop allocate unbounded memory in the child until
#:     timeout or OOM. The devnull file object bounds the redirect at
#:     a kernel-level discard so output suppression stays bounded.
#:   - The probe additionally calls ``os.dup2`` to redirect raw fd 1 +
#:     fd 2 to ``/dev/null`` BEFORE the load — this catches modules
#:     that bypass sys.stdout via ``os.write(1, ...)`` etc., AND it
#:     covers the small window between probe-script start and the
#:     contextlib redirect entering.
#:   - The result fd is inherited from the parent (``pass_fds=(fd,)``);
#:     the path is never visible to the child via argv or env. Probe
#:     opens the fd via ``os.fdopen(...)`` and writes ``json.dump`` in
#:     the finally clause. The structured-output channel never flows
#:     through stdout / stderr.
_PROBE_SCRIPT_SOURCE: Final[str] = r"""
import contextlib
import json
import os
import sys


def _run_probe():
    # R15 follow-up P2 #2: pop the per-invocation success token from
    # os.environ into a local variable BEFORE any imported-module
    # code can read os.environ. The token is now held only in this
    # frame's locals.
    success_token = os.environ.pop("COGNIC_PROBE_TOKEN", "")

    # Capture argv values into locals, then drop argv entirely. The
    # result fd is an inherited file descriptor (pass_fds), not a
    # path — so even if the imported module enumerates open fds via
    # /dev/fd or /proc/self/fd, it does not learn the per-invocation
    # token (which is what the parent matches on).
    result_fd = int(sys.argv[1])
    wheel_path = sys.argv[2]
    module_path = sys.argv[3]
    object_path = sys.argv[4]
    sys.argv = [sys.argv[0]]

    # Open the inherited fd via os.fdopen — closefd=True so the
    # underlying fd is closed when ``result_handle.close()`` runs.
    result_handle = os.fdopen(result_fd, "w", encoding="utf-8", closefd=True)

    result = {
        "ok": False,
        "phase": None,
        "error_class": None,
        "error_message": None,
    }

    # Defense-in-depth: redirect raw fd 1 + 2 to /dev/null BEFORE the
    # load attempt so a module that calls os.write(1, ...) directly
    # cannot leak bytes to the parent's stdout / stderr pipes.
    _devnull_fd = os.open(os.devnull, os.O_WRONLY)
    try:
        os.dup2(_devnull_fd, 1)
        os.dup2(_devnull_fd, 2)
    finally:
        os.close(_devnull_fd)

    # Wheel goes on sys.path so zipimport can resolve the module path.
    sys.path.insert(0, wheel_path)

    # Sinks are devnull file objects (kernel-discarded, bounded) —
    # see module-level docstring for rationale.
    try:
        with open(os.devnull, "w", encoding="utf-8") as _stdout_sink, \
             open(os.devnull, "w", encoding="utf-8") as _stderr_sink, \
             contextlib.redirect_stdout(_stdout_sink), \
             contextlib.redirect_stderr(_stderr_sink):
            from importlib.metadata import EntryPoint

            ep = EntryPoint(
                name="__cognic_load_probe__",
                value=module_path + ":" + object_path,
                group="__cognic_load_probe__",
            )
            try:
                ep.load()
            except (ImportError, ModuleNotFoundError) as exc:
                result["phase"] = "module_import"
                result["error_class"] = type(exc).__name__
                result["error_message"] = str(exc)
            except AttributeError as exc:
                result["phase"] = "object_lookup"
                result["error_class"] = type(exc).__name__
                result["error_message"] = str(exc)
            except BaseException as exc:
                result["phase"] = "module_runtime"
                result["error_class"] = type(exc).__name__
                result["error_message"] = str(exc)
            else:
                # Token written ONLY here, in probe-owned code, AFTER
                # ep.load() returns. A module that pre-emptively
                # writes {"ok": true} to the inherited result fd and
                # calls os._exit(0) cannot include this token without
                # introspecting this frame's locals via
                # sys._getframe / sys.modules['__main__']._run_probe.
                result["ok"] = True
                result["__cognic_probe_token__"] = success_token
    finally:
        json.dump(result, result_handle)
        result_handle.close()


_run_probe()
"""


_FAILURE_MESSAGE_TEMPLATES: Final[dict[str, str]] = {
    "module_import": ("EntryPoint.load() failed at module import: {error_class}: {error_message}"),
    "object_lookup": (
        "EntryPoint.load() imported the module but the named object "
        "was not found: {error_class}: {error_message}"
    ),
    "module_runtime": (
        "EntryPoint.load() failed with a runtime error during module "
        "execution: {error_class}: {error_message}"
    ),
}


_FAILURE_MODE_BY_PHASE: Final[dict[str, str]] = {
    "module_import": "load_probe_module_import_failed",
    "object_lookup": "load_probe_object_not_found",
    "module_runtime": "load_probe_module_runtime_error",
}


async def probe_entry_point_loadability(
    wheel_path: Path,
    *,
    module_path: str,
    object_path: str,
    timeout_s: float,
    python_executable: str | None = None,
) -> LoadProbeFailure | None:
    """Run an ``EntryPoint(...).load()`` probe in an isolated subprocess.

    Returns ``None`` if the entry-point loads cleanly; a
    :class:`LoadProbeFailure` otherwise.

    R15 P2 #2 of the original (pre-pivot) round: ``python_executable``
    defaults to ``sys.executable`` so PATH cannot pick a different
    Python. Tests can inject a sentinel python (e.g., a non-existent
    path) to exercise the ``load_probe_subprocess_error`` arm.

    Parameters mirror the verify orchestrator's local context:
      - ``wheel_path`` — already cosign-verified, integrity-checked,
        AND already passed every non-executing trust check (SBOM
        digest, SLSA, in-toto, AgentCard JWS, manifest re-validation).
        The verify orchestrator places this probe LAST in the trust
        pipeline (R15 follow-up P2 #1) so adversarial code never runs
        before the rest of the bundle is verified.
      - ``module_path`` — entry-point module dotted path
        (manifest-declared, integrity-anchored to wheel content).
      - ``object_path`` — single-segment object name (R11 P2 #1).
      - ``timeout_s`` — ``Settings.load_probe_timeout_s`` (default
        30s); SIGKILL + reap on overrun.

    R15 follow-up P2 #2 result-channel hardening:
      - Result fd inherited via ``pass_fds`` (no path in argv/env).
      - Per-invocation 256-bit hex token in env, popped to a local
        inside the child before any imported-module code runs.
      - Probe-owned code writes the token only in the success branch.
      - Parent rejects ``ok=True`` results whose token does not match
        with closed-enum failure mode
        ``load_probe_success_token_mismatch``.
    """
    interpreter = python_executable if python_executable is not None else sys.executable

    # R15 follow-up P2 #2: per-invocation success token. Rotates per
    # call; parent matches the result file's
    # ``__cognic_probe_token__`` field on success.
    success_token = secrets.token_hex(32)

    # Result-file lives in the system temp dir; cleaned up regardless
    # of subprocess outcome. Open in the parent so we can pass the
    # raw fd to the child via ``pass_fds`` — the path itself never
    # reaches the child's argv or env.
    result_fd, result_path = tempfile.mkstemp(prefix="cognic_load_probe_", suffix=".json")
    parent_fd_held = True

    try:
        # Mark the fd inheritable across exec so pass_fds preserves it.
        os.set_inheritable(result_fd, True)

        # R15 follow-up P2 #2: env carries the per-invocation token.
        # The child immediately ``os.environ.pop("COGNIC_PROBE_TOKEN")``
        # into a local variable before importing the module, so the
        # imported module cannot read os.environ to retrieve it.
        probe_env = {**_SUBPROCESS_ENV, "COGNIC_PROBE_TOKEN": success_token}

        try:
            proc = await asyncio.create_subprocess_exec(
                interpreter,
                "-I",
                "-c",
                _PROBE_SCRIPT_SOURCE,
                str(result_fd),  # argv[1] — fd integer, NOT a path
                str(wheel_path),
                module_path,
                object_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                env=probe_env,
                pass_fds=(result_fd,),
            )
        except OSError as exc:
            return LoadProbeFailure(
                failure_mode="load_probe_subprocess_error",
                message=(
                    f"could not start load-probe subprocess "
                    f"({interpreter!r}): {type(exc).__name__}: {exc}"
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "module_path": module_path,
                    "object_path": object_path,
                    "interpreter": interpreter,
                    "error_class": type(exc).__name__,
                    "error_message": str(exc),
                },
            )

        # Subprocess started. Close the parent's copy of the result fd
        # so we don't keep it open while the child writes; the child
        # owns its inherited copy and writes via os.fdopen + json.dump
        # + close in its finally clause.
        os.close(result_fd)
        parent_fd_held = False

        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout_s)
        except TimeoutError:
            # SIGKILL + reap (mirrors trust_gate doctrine).
            proc.kill()
            await proc.wait()
            return LoadProbeFailure(
                failure_mode="load_probe_timeout",
                message=(
                    f"load-probe subprocess exceeded {timeout_s}s timeout (SIGKILLed + reaped)"
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "module_path": module_path,
                    "object_path": object_path,
                    "timeout_s": timeout_s,
                },
            )

        # Subprocess completed (cleanly or with a non-zero exit code).
        # Parse the structured result file regardless of exit code —
        # an unhandled exception inside the probe still writes the
        # JSON via the try/finally.
        try:
            raw = Path(result_path).read_text(encoding="utf-8")
            result = json.loads(raw)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            return LoadProbeFailure(
                failure_mode="load_probe_unparseable_output",
                message=(
                    f"load-probe finished (rc={proc.returncode}) but "
                    f"the structured result file at {result_path} "
                    f"could not be read / parsed: "
                    f"{type(exc).__name__}: {exc}"
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "module_path": module_path,
                    "object_path": object_path,
                    "returncode": proc.returncode,
                    "error_class": type(exc).__name__,
                    "error_message": str(exc),
                },
            )

        if not isinstance(result, dict):
            return LoadProbeFailure(
                failure_mode="load_probe_unparseable_output",
                message=(
                    f"load-probe result file at {result_path} parsed as "
                    f"{type(result).__name__}, expected JSON object"
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "module_path": module_path,
                    "object_path": object_path,
                    "actual_type": type(result).__name__,
                },
            )

        if result.get("ok") is True:
            # R15 follow-up P2 #2: validate the per-invocation
            # success token. A probe-aware module that forges
            # ``{"ok": true}`` to the inherited result fd and calls
            # ``os._exit(0)`` will land here without the matching
            # token; refuse fail-closed.
            if result.get("__cognic_probe_token__") != success_token:
                return LoadProbeFailure(
                    failure_mode="load_probe_success_token_mismatch",
                    message=(
                        "load-probe result claimed ok=True but the "
                        "per-invocation success token did not match. "
                        "This indicates a probe-aware module attempted "
                        "to forge success via the inherited result fd "
                        "and exit before probe-owned validation. "
                        "Refusing fail-closed."
                    ),
                    payload={
                        "wheel_path": str(wheel_path),
                        "module_path": module_path,
                        "object_path": object_path,
                        "returncode": proc.returncode,
                        "result_keys": sorted(result.keys()),
                    },
                )
            return None

        phase = result.get("phase")
        if phase not in _FAILURE_MODE_BY_PHASE:
            return LoadProbeFailure(
                failure_mode="load_probe_unparseable_output",
                message=(
                    f"load-probe result has unexpected phase {phase!r}; "
                    f"expected one of {sorted(_FAILURE_MODE_BY_PHASE)}"
                ),
                payload={
                    "wheel_path": str(wheel_path),
                    "module_path": module_path,
                    "object_path": object_path,
                    "result": result,
                },
            )

        error_class = result.get("error_class") or "?"
        error_message = result.get("error_message") or "?"
        message = _FAILURE_MESSAGE_TEMPLATES[phase].format(
            error_class=error_class,
            error_message=error_message,
        )
        return LoadProbeFailure(
            failure_mode=_FAILURE_MODE_BY_PHASE[phase],
            message=message,
            payload={
                "wheel_path": str(wheel_path),
                "module_path": module_path,
                "object_path": object_path,
                "phase": phase,
                "error_class": error_class,
                "error_message": error_message,
            },
        )
    finally:
        # If the subprocess never started (OSError) the parent still
        # holds the result fd; close it before unlinking the file.
        if parent_fd_held:
            with contextlib.suppress(OSError):
                os.close(result_fd)
        # Best-effort cleanup of the temporary result file.
        with contextlib.suppress(OSError):
            Path(result_path).unlink(missing_ok=True)


__all__ = [
    "LoadProbeFailure",
    "probe_entry_point_loadability",
]
