"""M8 Task A5 — AgentDispatchPolicy: Rego eval glue for the agent-dispatch
bundle (CRITICAL CONTROLS).

Critical-controls module (``core/`` stop-rule per AGENTS.md L48).
Every edit is halt-before-commit per [[feedback_strict_review_off_gate]].

This module bridges the Wave-1 ``policies/_default/agents.rego`` bundle
(same batch) to the Python agent runtime, mirroring
``core/scheduler/policy.py``. It is the single Python boundary that:

  1. Projects an :class:`AgentPolicyInput` into the Rego input dict shape
     (11 keys: ``tenant_id`` / ``agent_id`` / ``originator_subject`` /
     ``capability_kind`` / ``capability_ref`` / ``scope_id`` (nullable) /
     ``pack_risk_tier`` / ``step_index`` / ``max_steps`` /
     ``assignment_verified`` / ``entitlement_verified``). Field names are
     IDENTICAL to the Rego input keys — no key translations (unlike the
     scheduler's ``class_``/``actor_subject``). Drift between this
     projection and the bundle's ``input.<key>`` reads = silent policy
     regression — pinned by
     ``test_build_rego_input_includes_exactly_the_documented_keys``.

  2. Evaluates the BOOL-ONLY ``data.cognic.agents.dispatch.allow``
     decision point via the existing
     :class:`~cognic_agentos.core.policy.engine.OPAEngine` (Sprint-4
     infrastructure; ``policy.decision_evaluated`` audit row emitted per
     call).

  3. Maps the bool verdict into the canonical frozen
     :class:`~cognic_agentos.core.scheduler.policy.PolicyDecision`:
       * ``allow=True``  → ``PolicyDecision(allow=True, policy_reason=None)``
       * ``allow=False`` → ``PolicyDecision(allow=False, policy_reason=None)``
         The bundle is bool-only by design — NO string refusal_reason
         document, NO second subprocess, NO internal diagnostic. The
         Python dispatcher owns the refusal vocabulary: the A10
         dispatcher maps every deny to the wire refusal
         ``agent_policy_denied`` (the closed
         ``AgentDispatchRefusalReason`` value at ``core/agent/_types.py``).

  4. Fail-closed envelope: any
     :class:`~cognic_agentos.core.policy.engine.OpaNotInstalledError` or
     :class:`~cognic_agentos.core.policy.engine.RegoEvaluationError`
     surfaces as ``PolicyDecision(allow=False,
     policy_reason="opa_unavailable")`` — the dispatcher still routes to
     the public ``agent_policy_denied`` refusal. Mirrors the scheduler
     plan-§1181 fail-closed pattern.

**Attestation-threading contract (defense in depth per the sandbox.rego
rule-4 precedent)**: ``assignment_verified`` / ``entitlement_verified``
are PYTHON-GATE-OWNED attestations — the A10 dispatcher sets them ONLY
after the assignment gate (gate 1) and the entitlement gate (gate 2)
verified; this module threads them verbatim, and the bundle requires
each STRICTLY ``== true`` so a bypassed Python gate (or a truthy
non-true value) still refuses at the policy layer.

**DELIBERATE plan deviation (controller-authorized)**: NO
``_MINIMAL_SUBPROCESS_ENV`` constant in this module. The scheduler copy
exists ONLY for its ``_fetch_refusal_reason`` direct ``opa eval``
subprocess (the string-returning decision point Sprint-4 OPAEngine
cannot evaluate); this module is bool-only through OPAEngine and spawns
NO subprocess of its own, so a copied env constant would be dead code.
Pinned by ``test_no_minimal_subprocess_env_constant``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Final

from cognic_agentos.core.policy.engine import (
    OPAEngine,
    OpaNotInstalledError,
    RegoEvaluationError,
)

# Canonical-owner import (the house pattern — ``scheduler/engine.py``
# re-exports the same way): PolicyDecision's producer module is
# ``core/scheduler/policy.py``; re-declaring it here would fork the
# frozen dataclass identity across the two policy seams.
from cognic_agentos.core.scheduler.policy import PolicyDecision as PolicyDecision

#: Decision-point path for the Wave-1 agent-dispatch bundle.
#: Wire-protocol-public — joins ``data.cognic.scheduler.admit.allow`` +
#: ``data.cognic.sandbox.admit.allow`` as the policy gate of the
#: governed agent loop's dispatch pipeline.
_AGENTS_ALLOW_DECISION_POINT: Final[str] = "data.cognic.agents.dispatch.allow"


@dataclass(frozen=True, slots=True)
class AgentPolicyInput:
    """Frozen input of one ``AgentDispatchPolicy.evaluate()`` call.

    The 11 fields ARE the Rego input key set (no translations) — the
    field-name/key-set identity is pinned by
    ``test_agent_policy_input_field_names_match_rego_key_set``.

    ``assignment_verified`` / ``entitlement_verified`` are the
    PYTHON-GATE-OWNED attestations (see the module docstring); the A10
    dispatcher constructs this input AFTER gates 1+2 so the bools
    reflect what actually verified. ``scope_id`` is nullable — a tool
    dispatch with no data scope threads ``None`` (the key is ALWAYS
    present in the projection).
    """

    tenant_id: str
    agent_id: str
    originator_subject: str
    capability_kind: str
    capability_ref: str
    scope_id: str | None
    pack_risk_tier: str
    step_index: int
    max_steps: int
    assignment_verified: bool
    entitlement_verified: bool


class AgentDispatchPolicy:
    """Wave-1 agent-dispatch policy evaluator.

    Single async public method: ``evaluate(policy_input) ->
    PolicyDecision``. Constructor takes an :class:`OPAEngine` instance
    pointed at the ``policies/_default/agents.rego`` bundle (typically
    constructed once at the composition root from
    ``Settings.agents_policy_bundle`` + threaded through DI to the A10
    dispatcher).

    Wave-1 instance state: just the injected OPAEngine. The operational
    gates (assignment / entitlement / step bounds / kill switches) are
    dispatcher-owned per the Option A doctrine LOCKED at scheduler T9 —
    this module owns Rego policy ONLY.
    """

    def __init__(self, *, opa_engine: OPAEngine) -> None:
        self._opa_engine = opa_engine

    async def evaluate(self, policy_input: AgentPolicyInput) -> PolicyDecision:
        """Evaluate the Wave-1 agent-dispatch policy.

        Pipeline per the module docstring above:
          1. Project AgentPolicyInput → the 11-key Rego input dict.
          2. ``opa_engine.evaluate(...allow)`` → bool allow + audit emit.
          3. allow=True → ``PolicyDecision(allow=True, policy_reason=None)``.
          4. Deny → ``PolicyDecision(allow=False, policy_reason=None)`` —
             bool-only bundle: NO second subprocess, NO internal
             diagnostic; the A10 dispatcher maps every deny to the wire
             refusal ``agent_policy_denied``.
          5. Fail-closed envelope: any OpaNotInstalledError or
             RegoEvaluationError → ``PolicyDecision(allow=False,
             policy_reason="opa_unavailable")``.
        """
        rego_input = self._build_rego_input(policy_input)
        try:
            allow_decision = await self._opa_engine.evaluate(
                decision_point=_AGENTS_ALLOW_DECISION_POINT,
                input=rego_input,
            )
        except (OpaNotInstalledError, RegoEvaluationError):
            return PolicyDecision(allow=False, policy_reason="opa_unavailable")

        if allow_decision.allow:
            return PolicyDecision(allow=True, policy_reason=None)
        return PolicyDecision(allow=False, policy_reason=None)

    @staticmethod
    def _build_rego_input(policy_input: AgentPolicyInput) -> dict[str, Any]:
        """Project an AgentPolicyInput into the bundle's input shape.

        11-key contract pinned by
        ``test_build_rego_input_includes_exactly_the_documented_keys``:
        ``tenant_id`` / ``agent_id`` / ``originator_subject`` /
        ``capability_kind`` / ``capability_ref`` / ``scope_id`` /
        ``pack_risk_tier`` / ``step_index`` / ``max_steps`` /
        ``assignment_verified`` / ``entitlement_verified``.

        NO key translations — every Rego input key name is IDENTICAL to
        the AgentPolicyInput field name (unlike the scheduler
        projection's ``class_`` → ``"class"`` strip and
        ``actor.subject`` → ``"actor_subject"`` flattening). ``scope_id``
        is ALWAYS present but nullable (``None`` → JSON null; the bundle
        treats it as opaque metadata).
        """
        return {
            "tenant_id": policy_input.tenant_id,
            "agent_id": policy_input.agent_id,
            "originator_subject": policy_input.originator_subject,
            "capability_kind": policy_input.capability_kind,
            "capability_ref": policy_input.capability_ref,
            "scope_id": policy_input.scope_id,
            "pack_risk_tier": policy_input.pack_risk_tier,
            "step_index": policy_input.step_index,
            "max_steps": policy_input.max_steps,
            # PYTHON-GATE-OWNED attestations (defense in depth): threaded
            # verbatim; the bundle requires each strictly == true.
            "assignment_verified": policy_input.assignment_verified,
            "entitlement_verified": policy_input.entitlement_verified,
        }


__all__ = (
    "AgentDispatchPolicy",
    "AgentPolicyInput",
    "PolicyDecision",
)
