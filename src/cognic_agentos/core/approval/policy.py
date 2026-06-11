"""Sprint 13.5a (ADR-014/015) — ApprovalPolicy: the tools.rego tier->flow bridge.

``core/`` stop-rule + critical-controls. Mirrors ``core/scheduler/policy.py``:
the Sprint-4 :class:`~cognic_agentos.core.policy.engine.OPAEngine` only validates
boolean decision points, so the 3-value ``data.cognic.tools.approval.flow``
STRING is fetched via a direct ``opa eval`` subprocess reusing the engine
instance's ``_opa_path`` / ``_bundle_path`` / ``_eval_timeout_s``. Fail-closed ->
``require_4_eyes`` (strictest) on any OPA error OR an out-of-enum value
(defense-in-depth twin to the engine's Python-path unknown-tier reject per spec
§5 / T-1).
"""

from __future__ import annotations

import asyncio
import json
import subprocess
from typing import Any, Final, get_args

from cognic_agentos.core.approval._types import ApprovalFlow
from cognic_agentos.core.policy.engine import OpaNotInstalledError, RegoEvaluationError

#: Decision-point path for the Wave-1 tool-approval bundle (wire-public).
_TOOLS_FLOW_DECISION_POINT: Final[str] = "data.cognic.tools.approval.flow"

#: Minimal subprocess env — drift-pinned vs ``OPAEngine``'s per
#: ``test_policy.py::test_subprocess_env_parity`` (test-only import of both
#: constants; NO runtime cross-import, per
#: [[feedback_drift_detector_test_only_no_runtime_import]]). Re-defined locally
#: to keep the cross-module surface narrow + avoid re-tripping the on-gate
#: engine module's halt-before-commit rule on every ApprovalPolicy edit.
_MINIMAL_SUBPROCESS_ENV: Final[dict[str, str]] = {
    "PATH": "/usr/local/bin:/usr/bin",
    "HOME": "/tmp",
}

_VALID_FLOWS: Final[frozenset[str]] = frozenset(get_args(ApprovalFlow))
_FAIL_CLOSED_FLOW: Final[ApprovalFlow] = "require_4_eyes"


class ApprovalPolicy:
    """Wave-1 tool-approval tier->flow classifier. Constructor takes an
    :class:`OPAEngine` pointed at ``policies/_default/tools.rego``."""

    def __init__(self, *, opa_engine: Any) -> None:
        # Typed ``Any`` to avoid importing OPAEngine's concrete type at the class
        # boundary; the duck surface used is the same _opa_path / _bundle_path /
        # _eval_timeout_s triple SchedulerPolicy relies on.
        self._opa_engine = opa_engine

    async def classify(self, *, risk_tier: str) -> ApprovalFlow:
        """Return the tier's approval flow. Fail-closed ``require_4_eyes`` on any
        OPA error or out-of-enum value. The blocking ``opa eval`` subprocess runs
        under :func:`asyncio.to_thread` so the event loop is not held."""
        try:
            value = await asyncio.to_thread(self._fetch_flow, {"risk_tier": risk_tier})
        except (OpaNotInstalledError, RegoEvaluationError):
            return _FAIL_CLOSED_FLOW
        if value not in _VALID_FLOWS:
            return _FAIL_CLOSED_FLOW
        return value  # type: ignore[return-value]  # narrowed by the membership check above

    def _fetch_flow(self, rego_input: dict[str, Any]) -> str:
        """Direct ``opa eval`` string fetch. Mirrors
        ``scheduler/policy.py::_fetch_refusal_reason`` discipline: list-form argv
        (NO shell), minimal env, finite timeout, manual returncode + shape checks.

        Raises:
            OpaNotInstalledError: opa path unset / binary not found.
            RegoEvaluationError: non-zero exit, timeout, malformed JSON, or
                unexpected result shape (incl. an empty result set).
        """
        opa_path = self._opa_engine._opa_path
        if opa_path is None:
            raise OpaNotInstalledError("opa not found; cannot classify approval flow")
        argv = [
            opa_path,
            "eval",
            "--data",
            str(self._opa_engine._bundle_path),
            "--format",
            "json",
            "--stdin-input",
            _TOOLS_FLOW_DECISION_POINT,
        ]
        try:
            completed = subprocess.run(
                argv,
                shell=False,
                capture_output=True,
                text=True,
                input=json.dumps(rego_input),
                env=_MINIMAL_SUBPROCESS_ENV,
                timeout=self._opa_engine._eval_timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise RegoEvaluationError("OPA approval-flow evaluate timeout") from exc
        except FileNotFoundError as exc:
            raise OpaNotInstalledError(f"opa binary not found at {opa_path!r}") from exc

        if completed.returncode != 0:
            raise RegoEvaluationError(
                f"OPA approval-flow non-zero exit {completed.returncode}: {completed.stderr!r}"
            )
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RegoEvaluationError(f"OPA approval-flow malformed JSON: {exc.msg}") from exc
        result = payload.get("result", []) if isinstance(payload, dict) else []
        if not result:
            raise RegoEvaluationError("OPA approval-flow empty result; no rule matched")
        try:
            value = result[0]["expressions"][0]["value"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RegoEvaluationError(f"OPA approval-flow result shape unexpected: {exc}") from exc
        if not isinstance(value, str):
            raise RegoEvaluationError("OPA approval-flow value not a string")
        return value
