# policies/_default/agents.rego
#
# M8 Task A5 — Wave-1 agent-dispatch policy bundle per ADR-027 + ADR-015.
#
# Decision point (wire-protocol-public):
#   data.cognic.agents.dispatch.allow → bool
#
# BOOL-ONLY by design — deliberately NO string refusal_reason document.
# The Python dispatcher owns the refusal vocabulary (the closed 7-value
# AgentDispatchRefusalReason at core/agent/_types.py); a bundle deny
# surfaces on the wire as ``agent_policy_denied`` mapped by the A10
# dispatcher. Adding a reason document here would fork the refusal
# vocabulary across two owners.
#
# Input contract (11 keys, threaded by
# core/agent/policy.py::AgentDispatchPolicy._build_rego_input — field
# names identical to AgentPolicyInput, no key translations):
#   tenant_id            string  — deploying tenant
#   agent_id             string  — the dispatching agent identity
#   originator_subject   string  — the human/service originator subject
#   capability_kind      string  — {"skill", "tool", "builtin"}
#   capability_ref       string  — the targeted capability reference
#   scope_id             string|null — data scope (null when none)
#   pack_risk_tier       string  — the agent pack's manifest risk tier
#   step_index           number  — 0-based index of THIS dispatch step
#   max_steps            number  — the run's step ceiling
#   assignment_verified  bool    — PYTHON-GATE-OWNED attestation: the
#                                  dispatch gate verified the capability
#                                  is in the granted set (gate 1)
#   entitlement_verified bool    — PYTHON-GATE-OWNED attestation: the
#                                  dispatch gate verified the data-scope
#                                  entitlement (gate 2)
#
# Defense-in-depth rationale (the sandbox.rego rule-4 precedent): the
# attestation conjuncts are read with STRICT ``== true`` — even if the
# Python assignment/entitlement gates are bypassed (refactor, direct OPA
# eval, a fresh dispatch path), an unattested or truthy-non-true input
# ("true", 1) refuses. Each attestation refuses INDEPENDENTLY, so a
# bypassed gate cannot admit through the other gate's attestation.
#
# Wire-protocol-public policy bundle. Enrolled in the AGENTS.md
# stop-rule policy-bundle precedent alongside elicitation.rego /
# sampling.rego / sandbox.rego / supply_chain.rego / scheduler.rego.
# Every edit is halt-before-commit per [[feedback_strict_review_off_gate]];
# bank overlays MAY TIGHTEN (add more refusal conditions, refuse on
# tighter kind sets, require explicit per-capability allow-listing).
# LOOSENING the kernel defaults requires a coordinated kernel + ADR
# amendment (ADR-027 §e).

package cognic.agents.dispatch

import future.keywords.if
import future.keywords.in

# ADR-015 default-deny baseline. ``allow`` defaults to false; the single
# positive ``allow if {...}`` rule below must explicitly fire to flip it.
# Missing/shape-mismatched input leaves the rule body undefined →
# fail-closed deny.
default allow := false

# The closed capability-kind vocabulary per ADR-027 — mirrors
# ``CapabilityRef.kind`` at core/agent/_types.py. Built-ins are
# kernel-owned (read_skill / remember) and still ride through the
# bundle: policy is the LAST gate on every dispatch, builtin or not.
_capability_kinds := {"skill", "tool", "builtin"}

# The single allow rule — ALL four conjuncts must hold:
#   1. assignment_verified STRICTLY true (Python gate 1 attestation)
#   2. entitlement_verified STRICTLY true (Python gate 2 attestation)
#   3. capability_kind in the closed 3-value vocabulary
#   4. step_index < max_steps (the run's step ceiling)
allow if {
	input.assignment_verified == true
	input.entitlement_verified == true
	input.capability_kind in _capability_kinds
	input.step_index < input.max_steps
}
