# policies/_default/scheduler.rego
#
# Sprint-10.5b T7 — Wave-1 scheduler admission policy bundle per
# ADR-022 + spec §4.8.
#
# Decision points (wire-protocol-public):
#   data.cognic.scheduler.admit.allow          → bool
#   data.cognic.scheduler.admit.refusal_reason → string (3-value
#                                                 closed-enum)
#
# Wire-protocol-public policy bundle. Enrolled in the AGENTS.md
# stop-rule policy-bundle list at Sprint-10.5b Z1b alongside
# elicitation.rego / sampling.rego / sandbox.rego / supply_chain.rego.
# Every edit is halt-before-commit per [[feedback_strict_review_off_gate]];
# bank overlays MAY TIGHTEN (add more refusal conditions, refuse on
# tighter tier sets, require explicit per-pack allow-listing).
# LOOSENING the kernel defaults requires a coordinated kernel + ADR
# amendment.
#
# Refusal-reason vocabulary (3 closed-enum strings):
#   * "scheduler_class_unknown"
#       Class outside the 2-value Wave-1 vocabulary
#       ({interactive, background}). Admission cannot evaluate tier
#       semantics until class is in vocabulary, so this check is the
#       FIRST arm of the else-chain (deterministic precedence per
#       plan §1090 — pins the no-complete-document-conflict invariant
#       that would otherwise fire if two ':=' rules both matched on
#       the same input).
#   * "scheduler_high_risk_tier_refused_pre_13_5"
#       Pack risk tier is in the 6-value high-risk set per ADR-014.
#       Pre-Sprint-13.5 contract (mirrors the Sprint 8A
#       sandbox.rego sandbox_high_risk_tier_refused_pre_13_5
#       contract): when core/approval/engine.py wires up at 13.5, the
#       high-risk-tier refusal lifts and these tiers route through
#       approval. The cutover itself is an audit event so banks can
#       prove the moment high-risk scheduler admission became gated.
#   * "scheduler_default_deny"
#       Default-deny fall-through. Fires when neither the class-
#       unknown nor the high-risk-tier arm matches AND the allow
#       conjunction did not fire either (e.g. allow path is true OR
#       a future tier is added but neither set lists it). Also
#       returned on empty / shape-mismatched input via the bare-else
#       terminator.

package cognic.scheduler.admit

import future.keywords.if
import future.keywords.in

# ADR-015 default-deny baseline. ``allow`` defaults to false; the
# positive ``allow if {...}`` rule below must explicitly fire to flip
# it. ``refusal_reason`` defaults to ``scheduler_default_deny`` for
# shape-mismatched / missing-input cases the else-chain cannot
# evaluate.
default allow := false

default refusal_reason := "scheduler_default_deny"

# Wave-1 class vocabulary. Class outside this set refuses regardless
# of tier per spec §4.8 — admission cannot evaluate tier semantics
# until class is in vocabulary.
_known_classes := {"interactive", "background"}

# Wave-1 safe-tier allow set per spec §4.8 + ADR-014. Matches the
# Sprint 8A sandbox.rego safe-tier set (read_only + internal_write).
_safe_tiers := {"read_only", "internal_write"}

# 6-value high-risk tier set per ADR-014 + sandbox.rego mirror.
# Refused pre-Sprint-13.5 when core/approval/engine.py is unwired.
# Same set referenced by sandbox.rego's high_risk_tiers + by
# sandbox/admission.py Stage-2 step 4.
_high_risk_tiers := {
	"customer_data_read",
	"customer_data_write",
	"payment_action",
	"regulator_communication",
	"cross_tenant",
	"high_risk_custom",
}

# ``refusal_reason`` is selected via a deterministic if/else chain to
# avoid Rego's complete-document conflict error when two ':=' rules
# both match (e.g. unknown-class AND high-risk-tier in the same
# input). Plan §1090 pins the class-unknown FIRST ordering — admission
# cannot evaluate tier semantics until class is in vocabulary, so the
# class-unknown check takes precedence over the tier check. Bare-else
# terminator returns the default fall-through.
refusal_reason := "scheduler_class_unknown" if {
	not input.class in _known_classes
} else := "scheduler_high_risk_tier_refused_pre_13_5" if {
	input.pack_risk_tier in _high_risk_tiers
} else := "scheduler_default_deny"

# Allow when class is known AND tier is in the Wave-1 safe set. The
# explicit ``not <high_risk>`` guard is defence-in-depth — _safe_tiers
# and _high_risk_tiers are disjoint by construction, so this never
# fires in practice, but the guard prevents future bundle drift from
# silently merging the sets and allowing through what was previously
# refused.
allow if {
	input.class in _known_classes
	input.pack_risk_tier in _safe_tiers
	not input.pack_risk_tier in _high_risk_tiers
}
