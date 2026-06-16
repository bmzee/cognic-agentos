"""Sprint 10.5b T8 — SchedulerPolicy: Rego eval glue for the scheduler
admission bundle.

Critical-controls module (``core/`` stop-rule per AGENTS.md L48).
Every edit is halt-before-commit per [[feedback_strict_review_off_gate]].

This module bridges the Wave-1 ``policies/_default/scheduler.rego``
bundle landed at T7 to the Python scheduler runtime. It is the single
Python boundary that:

  1. Projects a ``SubmitInput`` into the Rego input dict shape per
     spec §4.8 (10 keys: ``tenant_id`` / ``pack_id`` / ``actor_subject``
     / ``class`` / ``pack_kind`` / ``pack_risk_tier`` /
     ``current_tenant_concurrent_count`` / ``requested_estimated_tokens``
     / ``approval_verified`` — added at Sprint 13.5c2 per ADR-014: the
     ENGINE-OWNED attestation the bundle's high-risk allow arm requires
     strictly true — / ``approval_delegated_to`` — the 10th key added at
     Sprint 14A-A4a per ADR-022/014: the routing/evidence signal, ALWAYS
     threaded but nullable). Drift between this projection
     and the bundle's ``input.<key>`` reads = silent policy regression —
     pinned by ``test_build_rego_input_includes_all_spec_keys``.

  2. Evaluates the ``data.cognic.scheduler.admit.allow`` decision
     point via the existing :class:`~cognic_agentos.core.policy.engine.OPAEngine`
     (Sprint-4 infrastructure; ``policy.decision_evaluated`` audit
     row emitted per call).

  3. On deny, fetches the ``data.cognic.scheduler.admit.refusal_reason``
     string from the same bundle via a direct ``opa eval`` subprocess
     call. The Sprint-4 OPAEngine only handles boolean expressions
     (per the ``_parse_decision`` validation at
     ``core/policy/engine.py``); the string-returning decision point
     requires a parallel subprocess invocation. The subprocess
     discipline mirrors OPAEngine's invariants — list-form argv,
     ``shell=False``, minimal env, finite timeout — and re-uses the
     OPAEngine instance's ``_opa_path`` / ``_bundle_path`` /
     ``_eval_timeout_s`` so the two calls share configuration.

  4. Maps the ``(allow_bool, refusal_reason_string)`` pair into a
     frozen :class:`PolicyDecision` per the plan §1179 contract:
       * ``allow=True``  → ``PolicyDecision(allow=True, policy_reason=None)``
         The bundle's raw ``refusal_reason`` document is always
         defined (Rego semantics) but the policy layer SUPPRESSES it
         to ``None`` on the allow path. Propagating
         ``scheduler_default_deny`` on an allow row would be
         audit/SIEM misleading — explicitly documented in T7's
         ``test_allow_path_refusal_reason_is_raw_default_deny_at_rego_layer``.
       * ``allow=False`` → ``PolicyDecision(allow=False,
         policy_reason=<rego_refusal_reason>)``. The reason string is
         INTERNAL diagnostic (audit-only); :class:`SchedulerEngine`
         maps every deny → the public ``refused_policy_denied``
         outcome per plan §1167 vocabulary separation. The internal
         string rides through as audit-payload-only detail.

  5. Fail-closed envelope: any
     :class:`~cognic_agentos.core.policy.engine.OpaNotInstalledError`
     or :class:`~cognic_agentos.core.policy.engine.RegoEvaluationError`
     surfaces as ``PolicyDecision(allow=False,
     policy_reason="opa_unavailable")`` — engine still routes to the
     public ``refused_policy_denied`` outcome. Mirrors the Sprint 8A
     admission Stage-2 Rego fail-closed pattern per plan §1181.

**Vocabulary separation contract (plan §1167)**: the wire-public
``SchedulerRefusalReason`` 5-value Literal is the closed-enum surfaced
to callers via ``SchedulerAdmissionOutcome``. The
:class:`PolicyDecision` ``policy_reason`` is a FREE-FORM internal
diagnostic that NEVER appears in the wire-public enum. Pinned by
``TestSchedulerPolicyVocabularyBoundary``.

**Ownership boundary (T9 — Option A doctrine LOCKED)**: this module
owns Rego policy ONLY. Operational gates (``pack_state`` /
``kill_switch`` / ``quota`` / queue / caps) are owned by
:class:`~cognic_agentos.core.scheduler.engine.SchedulerEngine`. Plan
§1210's literal dual-consultation interpretation was REJECTED at T9
kickoff because it conflated ADR-018 (emergency controls) with
ADR-015 (policy-as-code) — kill_switch is an operational real-time
emergency surface, NOT a policy decision; the bundle remains
policy-only and the ``KillSwitchInterrogator`` seam stays
engine-side. Pinned by ``tests/unit/core/scheduler/test_engine.py``
T9 regressions: kill_switch-beats-policy ordering, upstream-refusals-
never-call-quota, no-emergency-import AST guard.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any, Final

from cognic_agentos.core.policy.engine import (
    OPAEngine,
    OpaNotInstalledError,
    RegoEvaluationError,
)
from cognic_agentos.core.scheduler._types import SubmitInput

#: Decision-point path for the Wave-1 scheduler admission bundle.
#: Wire-protocol-public — joins ``data.cognic.sandbox.admit.allow``
#: as the second admission gate in the scheduler ↔ sandbox pipeline.
_SCHEDULER_ALLOW_DECISION_POINT: Final[str] = "data.cognic.scheduler.admit.allow"

#: Companion decision-point for the closed-enum refusal_reason string.
#: Sprint-4 OPAEngine only handles boolean expressions, so fetching
#: this string goes through a direct ``opa eval`` subprocess call.
_SCHEDULER_REASON_DECISION_POINT: Final[str] = "data.cognic.scheduler.admit.refusal_reason"

#: Minimal subprocess env. Mirrors the exact env used by ``OPAEngine``
#: at ``core/policy/engine.py:80-87`` per the §2 invariant 5
#: contract — PATH so OPA's own subprocess-y bits resolve cleanly +
#: HOME=/tmp so incidental cache writes stay off the AgentOS service-
#: account home. Re-defined locally (NOT re-imported from the on-gate
#: core/policy/engine module) to keep the cross-module surface narrow
#: + avoid a cross-import that would re-trip the engine's halt-before-
#: commit rule on every SchedulerPolicy edit. Drift between this
#: constant and OPAEngine's is a critical-controls subprocess-
#: invariant regression: pinned by the test-only drift detector at
#: ``tests/unit/core/scheduler/test_policy.py::
#: TestSchedulerPolicySubprocessEnvParity`` which imports both
#: constants and asserts equality, mirroring the
#: [[feedback_drift_detector_test_only_no_runtime_import]] doctrine.
_MINIMAL_SUBPROCESS_ENV: Final[dict[str, str]] = {
    "PATH": "/usr/local/bin:/usr/bin",
    "HOME": "/tmp",
}


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Frozen result of one ``SchedulerPolicy.evaluate()`` call.

    Plan §1169 — define at top of ``core/scheduler/policy.py``. T5
    seeded this dataclass at ``core/scheduler/engine.py`` as a forward
    stub; T8 re-homes the canonical definition here (the producer
    module) and ``engine.py`` re-imports it for backward compat with
    existing callers.

    Fields:
      * ``allow``: terminal admission verdict — True iff the Rego
        bundle returned allow=true AND no fail-closed envelope fired.
      * ``policy_reason``: free-form INTERNAL diagnostic string;
        NEVER wire-public; audit-only per plan §1167 vocabulary
        separation. ``None`` ONLY when ``allow=True`` (the canonical
        allow shape per plan §1179).
    """

    allow: bool
    policy_reason: str | None


class SchedulerPolicy:
    """Wave-1 scheduler admission policy evaluator.

    Single async public method: ``evaluate(submit_input) ->
    PolicyDecision``. Constructor takes an :class:`OPAEngine`
    instance pointed at the ``policies/_default/scheduler.rego``
    bundle (typically constructed once at AgentOS app startup +
    threaded through DI to the scheduler engine).

    Wave-1 instance state: just the injected OPAEngine. Kill-switch
    consultation is engine-owned per the Option A doctrine LOCKED at
    T9 kickoff (see module-header ownership boundary note above);
    SchedulerPolicy does NOT take a ``KillSwitchInterrogator`` seam.
    """

    def __init__(self, *, opa_engine: OPAEngine) -> None:
        self._opa_engine = opa_engine

    async def evaluate(self, submit_input: SubmitInput) -> PolicyDecision:
        """Evaluate the Wave-1 scheduler admission policy.

        Pipeline per plan §1185 + the module docstring above:
          1. Project SubmitInput → Rego input dict (10 keys: the spec §4.8
             8-key set + ``approval_verified`` per Sprint 13.5c2/ADR-014
             + ``approval_delegated_to`` per Sprint 14A-A4a/ADR-022).
          2. ``opa_engine.evaluate(...allow)`` → bool allow + audit emit.
          3. If allow=True: return ``PolicyDecision(allow=True,
             policy_reason=None)`` (suppress raw bundle refusal_reason
             per plan §1179 — propagating "scheduler_default_deny" on
             an allow row would be audit/SIEM misleading).
          4. If allow=False: fetch refusal_reason via direct subprocess
             + return ``PolicyDecision(allow=False, policy_reason=<str>)``.
          5. Fail-closed envelope: any OpaNotInstalledError or
             RegoEvaluationError → ``PolicyDecision(allow=False,
             policy_reason="opa_unavailable")``.
        """
        rego_input = self._build_rego_input(submit_input)
        try:
            allow_decision = await self._opa_engine.evaluate(
                decision_point=_SCHEDULER_ALLOW_DECISION_POINT,
                input=rego_input,
            )
        except (OpaNotInstalledError, RegoEvaluationError):
            return PolicyDecision(allow=False, policy_reason="opa_unavailable")

        if allow_decision.allow:
            # Plan §1179 suppression contract.
            return PolicyDecision(allow=True, policy_reason=None)

        # Deny path — fetch the closed-enum refusal_reason string.
        try:
            refusal_reason = self._fetch_refusal_reason(rego_input)
        except (OpaNotInstalledError, RegoEvaluationError):
            # Deny stands even if we cannot determine the specific
            # reason. Use "opa_unavailable" as the catch-all internal
            # diagnostic — the actual deny verdict is preserved.
            return PolicyDecision(allow=False, policy_reason="opa_unavailable")
        return PolicyDecision(allow=False, policy_reason=refusal_reason)

    @staticmethod
    def _build_rego_input(submit_input: SubmitInput) -> dict[str, Any]:
        """Project a SubmitInput into the spec §4.8 Rego input shape.

        10-key contract pinned by ``test_build_rego_input_includes_all_spec_keys``:
        ``tenant_id`` / ``pack_id`` / ``actor_subject`` / ``class`` /
        ``pack_kind`` / ``pack_risk_tier`` /
        ``current_tenant_concurrent_count`` / ``requested_estimated_tokens``
        / ``approval_verified`` (Sprint 13.5c2 per ADR-014 — ALWAYS
        threaded; the engine overwrites the field before the policy call)
        / ``approval_delegated_to`` (the 10th key, Sprint 14A-A4a per
        ADR-022/014 — ALWAYS threaded but nullable; the routing/evidence
        signal the bundle's delegated allow arm reads strictly).

        Key translations:
          * ``SubmitInput.class_`` → ``"class"`` (trailing underscore
            stripped — Python keyword collision; Rego reads
            ``input.class``).
          * ``SubmitInput.actor.subject`` → ``"actor_subject"``
            (string projection; bundle reads ``input.actor_subject``
            not ``input.actor.subject``).
          * ``current_tenant_concurrent_count``: Wave-1 stub value 0.
            A future task (post-T9) wires the real per-tenant
            concurrent-task count from
            ``SchedulerEngine._tenant_class_counts`` when the Rego
            bundle starts consuming this input field. T9 deliberately
            does NOT wire this — the bundle's Wave-1 rules
            (`scheduler_class_unknown` / `..._high_risk_tier_..._pre_13_5`
            / `scheduler_default_deny`) make no decisions on
            concurrent count, so stub=0 is correct for Wave-1.
        """
        return {
            "tenant_id": submit_input.tenant_id,
            "pack_id": submit_input.pack_id,
            "actor_subject": submit_input.actor.subject,
            "class": submit_input.class_,
            "pack_kind": submit_input.pack_kind,
            "pack_risk_tier": submit_input.pack_risk_tier,
            # Wave-1 stub — see _build_rego_input docstring above for
            # the post-T9 wiring contract.
            "current_tenant_concurrent_count": 0,
            "requested_estimated_tokens": submit_input.requested_estimated_tokens,
            # Sprint 13.5c2 (ADR-014): ENGINE-OWNED attestation — the engine
            # overwrites this field before the policy call; the bundle's
            # high-risk allow arm requires it strictly true.
            "approval_verified": submit_input.approval_verified,
            # Sprint 14A-A4a (ADR-022 + ADR-014): routing/evidence signal — ALWAYS
            # threaded (nullable). The bundle's delegated allow arm reads it
            # strictly (== "sandbox_admission"); None/absent fails closed.
            "approval_delegated_to": submit_input.approval_delegated_to,
        }

    def _fetch_refusal_reason(self, rego_input: dict[str, Any]) -> str:
        """Fetch the bundle's ``refusal_reason`` string via direct
        ``opa eval`` subprocess.

        Sprint-4 :class:`OPAEngine` ``evaluate()`` validates the result
        is a boolean (see ``OPAEngine._parse_decision`` at
        ``core/policy/engine.py``). The Wave-1 scheduler bundle's
        ``refusal_reason`` is a 3-value closed-enum string, so the
        boolean validator would refuse it. This helper reuses the
        OPAEngine instance's bundle path + binary path + timeout to
        invoke a parallel subprocess that retrieves the string value.

        Subprocess discipline mirrors OPAEngine.evaluate (per
        ``core/policy/engine.py:325-346``):
          * List-form argv (NO shell)
          * ``check=False`` — manually inspect ``returncode``
          * Minimal environment via ``_MINIMAL_SUBPROCESS_ENV``
          * Finite ``timeout`` from the OPAEngine instance

        Raises:
            OpaNotInstalledError: when the OPAEngine's ``_opa_path``
                is None OR the binary cannot be located.
            RegoEvaluationError: subprocess exit non-zero, timeout,
                malformed JSON output, or unexpected shape.
        """
        opa_path = self._opa_engine._opa_path
        if opa_path is None:
            raise OpaNotInstalledError(
                "opa not found on PATH and no override path configured; "
                "cannot fetch SchedulerPolicy refusal_reason"
            )

        argv = [
            opa_path,
            "eval",
            "--data",
            str(self._opa_engine._bundle_path),
            "--format",
            "json",
            "--stdin-input",
            _SCHEDULER_REASON_DECISION_POINT,
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
            raise RegoEvaluationError(
                f"OPA refusal_reason evaluate timeout on bundle {self._opa_engine._bundle_path!s}"
            ) from exc
        except FileNotFoundError as exc:
            raise OpaNotInstalledError(
                f"opa binary not found at pinned path {opa_path!r}; "
                "cannot fetch SchedulerPolicy refusal_reason"
            ) from exc

        if completed.returncode != 0:
            raise RegoEvaluationError(
                f"OPA refusal_reason evaluate non-zero exit "
                f"{completed.returncode}: {completed.stderr!r}"
            )

        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise RegoEvaluationError(
                f"OPA refusal_reason output malformed JSON: {exc.msg}"
            ) from exc
        if not isinstance(payload, dict):
            raise RegoEvaluationError(
                f"OPA refusal_reason JSON root is not an object (got {type(payload).__name__})"
            )
        result = payload.get("result", [])
        if not result:
            raise RegoEvaluationError("OPA refusal_reason empty result set; no rule matched")
        try:
            value = result[0]["expressions"][0]["value"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RegoEvaluationError(f"OPA refusal_reason result shape unexpected: {exc}") from exc
        if not isinstance(value, str):
            raise RegoEvaluationError(
                f"OPA refusal_reason expression value is not string (got {type(value).__name__})"
            )
        return value
