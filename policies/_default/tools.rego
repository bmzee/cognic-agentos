# policies/_default/tools.rego
#
# Sprint-13.5a (ADR-014 + ADR-015) — Wave-1 runtime tool-approval
# tier->flow classifier.
#
# Decision point (wire-protocol-public):
#   data.cognic.tools.approval.flow -> string (3-value closed enum:
#     "auto_run" / "require_single_approval" / "require_4_eyes")
#
# Wire-protocol-public policy bundle. Joins the AGENTS.md stop-rule
# policy-bundle list alongside sandbox.rego / scheduler.rego /
# sampling.rego / elicitation.rego / supply_chain.rego.
#
# Default fail-closed "require_4_eyes" (strictest) for unknown tiers —
# DEFENSE-IN-DEPTH. The normal Python path rejects an out-of-vocabulary
# risk_tier at ApprovalEngine envelope validation (risk_tier_unknown)
# BEFORE reaching this bundle (spec §5 / T-1); this default only fires
# for callers that hit the bundle directly or under future overlay
# drift.
#
# Bank overlays may TIGHTEN (e.g. map customer_data_read ->
# require_4_eyes); LOOSENING the kernel defaults requires a coordinated
# kernel + ADR amendment (the sandbox.rego / scheduler.rego precedent).
package cognic.tools.approval

import future.keywords.if
import future.keywords.in

# Wave-1 tier sets — DISJOINT by construction (a tier in two sets would
# make the complete-rule ``flow`` conflict at eval time, surfacing a
# misclassification bug loudly rather than silently).
_auto_tiers := {"read_only", "internal_write"}

_single_tiers := {"customer_data_read", "customer_data_write"}

_four_eyes_tiers := {
	"payment_action",
	"regulator_communication",
	"cross_tenant",
	"high_risk_custom",
}

# Strictest fall-through. An unknown tier yields require_4_eyes.
default flow := "require_4_eyes"

flow := "auto_run" if input.risk_tier in _auto_tiers

flow := "require_single_approval" if input.risk_tier in _single_tiers

flow := "require_4_eyes" if input.risk_tier in _four_eyes_tiers
