"""M6 Task A5 (ADR-025) — the governed skill executor (CRITICAL CONTROLS).

Runs a trust-registered skill's executable action **fully sandboxed** (ADR-004:
``--network none`` + no ambient credentials + isolated filesystem) and mediates
every tool call through the :class:`SkillBroker` (which enforces the skill's
``declared_tools`` per call and routes to ``MCPHost.call_tool``). The action
NEVER loads into the kernel process — the executor opens a sandbox session on
the skill's immutable, cosign-verified runtime image and ``session.exec``'s the
generic in-sandbox skill-runner (``python -m cognic_agentos.sdk.skill_runner``),
passing the invocation parameters through env.

The one governed run (spec §5.1):

  0. Load + validate the trusted skill record (exists / registered) — refuse
     ``skill_not_found`` / ``skill_not_registered`` otherwise.
  1. Serve a per-invocation :class:`SkillBroker` bound to the record's
     ``declared_tools`` + the actor's tenant/subject.
  2. ``create`` the sandbox session with a ``--network none`` policy
     (``egress_allow_list=()`` — invariant #9), **no ambient credentials**
     (``requires_credentials=()`` — invariant #10), and the broker's ``0700``
     socket dir bind-mounted at ``/run/cognic-skill`` (the runner's only egress).
  3. ``exec`` the runner; parse its final length-framed JSON result frame from
     stdout.
  4. ``broker.close()`` + ``session.destroy()`` — both finally-guarded, on
     success AND on any create/exec exception.
  5. Emit ONE ``skill.invoked`` instruction-layer decision row (digest-only —
     never raw arguments/stdout). The per-tool ``call_tool`` execution-layer
     rows are emitted DOWNSTREAM by the MCP host (via the broker's call proxy),
     never duplicated here.

CRITICAL CONTROLS. Kernel-boot-clean: module-level imports are stdlib +
``core.canonical`` + ``core.decision_history`` + ``core.skill._types`` +
``core.skill.broker`` ONLY. ``Actor`` is ``TYPE_CHECKING``-only; the sandbox
types are ``TYPE_CHECKING`` (annotations) + FUNCTION-LOCAL (construction) so a
kernel image without the ``adapters`` extra (no ``hvac`` via
``sandbox.policy -> sandbox.audit -> core.vault``) imports this module cleanly.
No ``portal`` / ``protocol`` / runtime ``sdk`` import. Pinned by
``tests/unit/architecture/test_skill_executor_boundaries.py``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from typing import TYPE_CHECKING, Any, Final

from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.skill._types import (  # core->core, SDK-free
    LoadedSkillRecord,
    SkillCallProxy,
    SkillInvokeRefusalReason,
    SkillInvokeResult,
    SkillInvokeTerminalState,
    SkillRecordLoader,
)
from cognic_agentos.core.skill.broker import SkillBroker  # core->core, SDK-free

if TYPE_CHECKING:
    from cognic_agentos.portal.rbac.actor import Actor

    # sandbox.policy / sandbox.protocol are TYPE_CHECKING (annotations) +
    # FUNCTION-LOCAL (construction, in _build_policy / _build_pack_context /
    # invoke) — a module-level sandbox import would pull hvac (via
    # sandbox.policy -> sandbox.audit -> core.vault -> hvac) and break kernel
    # boot. Only fires when the executor RUNS (adapters image). Pinned by
    # tests/unit/architecture/test_skill_executor_boundaries.py.
    from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
    from cognic_agentos.sandbox.protocol import SandboxBackend, SandboxExecResult, SandboxSession

logger = logging.getLogger(__name__)

#: ISO-control mapping for skill.* evidence is a Human-only decision — deferred
#: (mirrors ``core/run/executor.py``'s ``_RUN_EVIDENCE_ISO_CONTROLS``).
_SKILL_EVIDENCE_ISO_CONTROLS: tuple[str, ...] = ()

#: Wire-public 5-env-var contract the in-sandbox skill-runner reads. A LOCAL copy
#: of ``sdk.skill_runner``'s ``ENV_*`` constants — ``core/skill`` takes NO SDK
#: runtime import (the ``core -> sdk`` arrow is forbidden). A test-only drift
#: detector at ``tests/unit/core/skill/test_executor.py`` pins the copy against
#: ``sdk.skill_runner`` per ``feedback_drift_detector_test_only_no_runtime_import``.
_ENV_BROKER_SOCKET: Final = "COGNIC_SKILL_BROKER_SOCKET"
_ENV_BROKER_SESSION_TOKEN: Final = "COGNIC_SKILL_BROKER_SESSION_TOKEN"
_ENV_ENTRY_POINT: Final = "COGNIC_SKILL_ENTRY_POINT"
_ENV_DECLARED_TOOLS_JSON: Final = "COGNIC_SKILL_DECLARED_TOOLS_JSON"
_ENV_ARGUMENTS_JSON: Final = "COGNIC_SKILL_ARGUMENTS_JSON"

#: The runner harness invoked inside the sandbox + the container mount target
#: for the broker's per-invocation ``0700`` socket dir (host path is the broker
#: handle's dir; the runner connects to ``<container_dir>/broker.sock``).
_SKILL_RUNNER_MODULE: Final = "cognic_agentos.sdk.skill_runner"
_BROKER_CONTAINER_DIR: Final = "/run/cognic-skill"
_BROKER_CONTAINER_SOCKET: Final = "/run/cognic-skill/broker.sock"
_SKILL_TOOL_REQUEST_ID_PREFIX: Final = "skill-tool-"

#: Fixed sandbox resource envelope for a skill runner (the runner + the signed
#: action; deterministic, no network). ``walltime_s`` uses the per-invocation
#: execution timeout (also the broker deadline) so a hung action is torn down.
_SKILL_CPU_CORES: Final = 1.0
_SKILL_MEMORY_MB: Final = 256


def _validate_skill_record(record: LoadedSkillRecord | None) -> SkillInvokeRefusalReason | None:
    """Two fail-closed pre-flight checks. Returns the closed refusal reason or
    ``None`` when the record is invokable. The ``registered`` check is
    executor-side defence in depth over the loader's admission (mirrors
    ``core/run``'s ``pack_record_not_installed``)."""
    if record is None:
        return "skill_not_found"
    if not record.registered:
        return "skill_not_registered"
    return None


class SkillExecutor:
    """Owns the sandbox session + the per-invocation broker directly. Single
    public method :meth:`invoke`.

    ``call_proxy`` is the consumer-owned seam over ``MCPHost.call_tool`` — the
    concrete ``harness.skill_host._MCPHostCallProxy`` adapter wires the real host
    (A7). ``execution_timeout_s`` is BOTH the sandbox walltime cap AND the
    broker's per-invocation deadline."""

    def __init__(
        self,
        *,
        sandbox_backend: SandboxBackend,
        skill_loader: SkillRecordLoader,
        call_proxy: SkillCallProxy,
        decision_history_store: DecisionHistoryStore,
        execution_timeout_s: float = 30.0,
    ) -> None:
        if execution_timeout_s <= 0:
            raise ValueError("execution_timeout_s must be > 0")
        self._sandbox_backend = sandbox_backend
        self._loader = skill_loader
        self._call_proxy = call_proxy
        self._dh = decision_history_store
        self._execution_timeout_s = execution_timeout_s

    async def invoke(
        self, *, skill_id: str, arguments: dict[str, Any], actor: Actor
    ) -> SkillInvokeResult:
        request_id = f"skill-{uuid.uuid4().hex}"

        # Step 0 — load + validate the trusted skill record (pre-flight).
        record = await self._loader.load_for_skill(skill_id=skill_id, tenant_id=actor.tenant_id)
        refusal = _validate_skill_record(record)
        if refusal is not None:
            await self._emit_invoked(
                skill_id=skill_id,
                actor=actor,
                request_id=request_id,
                arguments=arguments,
                terminal_state="refused",
                refusal_reason=refusal,
                exec_result=None,
            )
            return SkillInvokeResult(terminal_state="refused", result=None, refusal_reason=refusal)
        assert record is not None  # narrowed by _validate_skill_record

        # Step 1 — serve a per-invocation broker bound to this skill's authority.
        broker = SkillBroker(
            declared_tools=frozenset(record.declared_tools),
            tenant_id=actor.tenant_id,
            actor_subject=actor.subject,
            request_id_prefix=_SKILL_TOOL_REQUEST_ID_PREFIX,
            call_proxy=self._call_proxy,
            timeout_s=self._execution_timeout_s,
        )
        handle = await broker.serve()
        session: SandboxSession | None = None
        try:
            broker_dir = os.path.dirname(handle.sock_path)
            policy = self._build_policy(record, broker_dir=broker_dir)
            ctx = self._build_pack_context(record)
            command = self._build_command(
                session_token=handle.session_token, record=record, arguments=arguments
            )
            # Steps 2-3 — create + exec. ANY create/exec failure (admission
            # refusal, workload crash) is an infra failure -> skill_runtime_error;
            # the finally still tears the broker + session down.
            try:
                session = await self._sandbox_backend.create(
                    policy,
                    actor=actor,
                    tenant_id=actor.tenant_id,
                    pack_context=ctx,
                    requires_credentials=(),  # invariant #10 — no ambient credentials
                )
                exec_result = await session.exec(command, timeout_s=policy.walltime_s)
            except Exception:
                logger.warning(
                    "skill.invoke.sandbox_failed",
                    extra={"request_id": request_id, "skill_id": skill_id},
                    exc_info=True,
                )
                await self._emit_invoked(
                    skill_id=skill_id,
                    actor=actor,
                    request_id=request_id,
                    arguments=arguments,
                    terminal_state="failed",
                    refusal_reason="skill_runtime_error",
                    exec_result=None,
                )
                return SkillInvokeResult(
                    terminal_state="failed",
                    result=None,
                    refusal_reason="skill_runtime_error",
                )

            # Step 5 — parse the runner's final result frame + emit evidence.
            terminal_state, result, reason = _interpret_frame(
                _parse_runner_frame(exec_result.stdout)
            )
            await self._emit_invoked(
                skill_id=skill_id,
                actor=actor,
                request_id=request_id,
                arguments=arguments,
                terminal_state=terminal_state,
                refusal_reason=reason,
                exec_result=exec_result,
            )
            return SkillInvokeResult(
                terminal_state=terminal_state, result=result, refusal_reason=reason
            )
        finally:
            # Step 4 — finally-guarded teardown: the broker's socket + 0700 dir
            # (via the served handle's idempotent close), then the sandbox
            # session. Both run on success AND on any exception, and are torn
            # down INDEPENDENTLY — a raise from handle.close() MUST NOT skip
            # session.destroy() (teardown is a critical boundary; it must not
            # depend on the broker's internal OSError-suppression to reach the
            # sandbox-session teardown). Pinned by
            # test_session_destroyed_even_if_broker_handle_close_raises.
            try:
                await handle.close()
            except Exception:  # a broker-close raise never skips session destroy.
                logger.warning(
                    "skill.broker_close_failed",
                    extra={"request_id": request_id},
                    exc_info=True,
                )
            if session is not None:
                try:
                    await session.destroy()
                except Exception:  # best-effort teardown — never flips the outcome.
                    logger.warning(
                        "skill.session_destroy_failed",
                        extra={
                            "request_id": request_id,
                            "session_id": getattr(session, "session_id", None),
                        },
                    )

    def _build_command(
        self, *, session_token: str, record: LoadedSkillRecord, arguments: dict[str, Any]
    ) -> list[str]:
        """``env K=V ... python -m cognic_agentos.sdk.skill_runner`` — the 5-env-var
        contract passed to the runner. The ``env`` coreutil prefix is the env
        channel (``SandboxSession.exec`` has no ``env`` kwarg); each ``K=V`` is a
        SEPARATE argv token (no shell, no injection — ``env`` splits on the first
        ``=`` only). The runner connects to the CONTAINER socket path; the mount
        maps ``/run/cognic-skill`` to the broker's host dir."""
        return [
            "env",
            f"{_ENV_BROKER_SOCKET}={_BROKER_CONTAINER_SOCKET}",
            f"{_ENV_BROKER_SESSION_TOKEN}={session_token}",
            f"{_ENV_ENTRY_POINT}={record.entry_point_name}",
            f"{_ENV_DECLARED_TOOLS_JSON}={json.dumps(list(record.declared_tools))}",
            f"{_ENV_ARGUMENTS_JSON}={json.dumps(arguments)}",
            "python",
            "-m",
            _SKILL_RUNNER_MODULE,
        ]

    def _build_policy(self, record: LoadedSkillRecord, *, broker_dir: str) -> SandboxPolicy:
        # Function-local import (kernel-boot-clean — see the module docstring).
        from cognic_agentos.sandbox.policy import SandboxPolicy, WritableMount

        return SandboxPolicy(
            cpu_cores=_SKILL_CPU_CORES,
            cpu_time_budget_s=None,
            memory_mb=_SKILL_MEMORY_MB,
            walltime_s=self._execution_timeout_s,
            runtime_image=record.runtime_image,
            egress_allow_list=(),  # invariant #9 — --network none (no general egress)
            vault_path=None,
            writable_mounts=(
                WritableMount(
                    host_path=broker_dir,
                    container_path=_BROKER_CONTAINER_DIR,
                    read_only=False,  # the runner writes/reads the broker socket
                ),
            ),
        )

    def _build_pack_context(self, record: LoadedSkillRecord) -> PackAdmissionContext:
        # Function-local import (kernel-boot-clean — see the module docstring).
        from cognic_agentos.sandbox.policy import PackAdmissionContext

        # The skill-runner container itself does nothing privileged — it has no
        # network + no credentials; every GOVERNED tool call is broker-mediated
        # and risk-gated DOWNSTREAM by MCPHost. So the runner sandbox admits at
        # ``read_only`` (spec §5.1).
        return PackAdmissionContext(
            pack_id=record.skill_id,
            pack_version=record.pack_version,
            pack_artifact_digest=record.signed_artefact_digest.hex(),
            risk_tier="read_only",
            declares_dynamic_install=False,
            profile="production",
            data_classes=(),
        )

    async def _emit_invoked(
        self,
        *,
        skill_id: str,
        actor: Actor,
        request_id: str,
        arguments: dict[str, Any],
        terminal_state: SkillInvokeTerminalState,
        refusal_reason: str | None,
        exec_result: SandboxExecResult | None,
    ) -> None:
        """ONE ``skill.invoked`` instruction-layer row per invoke, on EVERY
        terminal path. Digest-only: ``arguments_sha256`` + ``stdout_sha256`` +
        counts, NEVER the raw arguments/stdout bytes. The per-tool ``call_tool``
        execution-layer rows are emitted downstream by the MCP host (via the
        broker's call proxy) — not duplicated here."""
        payload: dict[str, Any] = {
            "skill_id": skill_id,
            "terminal_state": terminal_state,
            "reason": refusal_reason,
            "arguments_sha256": hashlib.sha256(canonical_bytes(arguments)).hexdigest(),
        }
        if exec_result is not None:
            payload["stdout_sha256"] = hashlib.sha256(exec_result.stdout).hexdigest()
            payload["stdout_bytes"] = len(exec_result.stdout)
            payload["exit_code"] = exec_result.exit_code
        else:
            payload["stdout_sha256"] = None
            payload["stdout_bytes"] = None
            payload["exit_code"] = None
        await self._dh.append(
            DecisionRecord(
                decision_type="skill.invoked",
                request_id=request_id,
                payload=payload,
                actor_id=actor.subject,
                tenant_id=actor.tenant_id,
                iso_controls=_SKILL_EVIDENCE_ISO_CONTROLS,
            )
        )


def _parse_runner_frame(stdout: bytes) -> dict[str, Any] | None:
    """Decode the runner's FINAL length-framed JSON frame from the TAIL of
    captured stdout.

    The runner writes exactly one frame (``encode_frame`` = 4-byte big-endian
    body-length prefix + body) as its last write. Any preamble a (hostile,
    signed) action prints is skipped by anchoring the frame to the buffer tail:
    the true frame's prefix at offset ``start`` declares ``N`` where
    ``start + 4 + N == len(stdout)`` AND the body parses to a dict carrying the
    ``"ok"`` contract key. Returns ``None`` when no such tail frame exists ->
    the executor maps that to ``skill_runtime_error``."""
    total = len(stdout)
    if total < 4:
        return None
    for start in range(total - 4 + 1):
        declared = int.from_bytes(stdout[start : start + 4], "big")
        if start + 4 + declared != total:
            continue
        body = stdout[start + 4 :]
        try:
            obj = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(obj, dict) and "ok" in obj:
            return obj
    return None


def _interpret_frame(
    frame: dict[str, Any] | None,
) -> tuple[SkillInvokeTerminalState, dict[str, Any] | None, str | None]:
    """Map the runner's result frame to ``(terminal_state, result, reason)``.

    * ``None`` / unparseable / malformed -> ``failed`` + ``skill_runtime_error``.
    * ``{"ok": true, "result": R}`` -> ``completed`` + ``R``.
    * ``{"ok": false, "refused": true, "reason": <str>}`` -> ``refused`` + the
      PASSTHROUGH reason (e.g. ``skill_tool_not_declared`` — the broker's
      load-bearing refusal, surfaced verbatim; the executor NEVER re-implements
      the declared-tools check).
    """
    if frame is None:
        return "failed", None, "skill_runtime_error"
    if frame.get("ok") is True:
        result = frame.get("result")
        return "completed", (result if isinstance(result, dict) else {}), None
    if frame.get("ok") is False and frame.get("refused") is True:
        reason = frame.get("reason")
        if isinstance(reason, str) and reason:
            return "refused", None, reason
    return "failed", None, "skill_runtime_error"


__all__ = ["SkillExecutor"]
