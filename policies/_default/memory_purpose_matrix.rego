# policies/_default/memory_purpose_matrix.rego
#
# Sprint-11.5a T8 — Wave-1 memory-recall purpose-compatibility bundle per
# ADR-015 + ADR-019.
#
# Decision point (wire-protocol-public, BOOLEAN-only):
#   data.cognic.memory.recall.purpose_compatible.allow -> bool
#
# Default-deny: a recall purpose is compatible with the stored write
# purpose ONLY when identical OR on the explicit compatible-pair list.
# The T9 Python gate maps a deny here to memory_purpose_mismatch. This
# bundle exposes ONLY a boolean `allow` — there is NO Rego refusal_reason
# closed-enum (contrast scheduler.rego). OPAEngine._parse_decision
# requires the evaluated expression value to be a Python bool, so callers
# MUST point at `purpose_compatible.allow`, never at the
# `{"allow": bool}` object.
#
# Wire-protocol-public policy bundle (AGENTS.md stop-rule). Every edit is
# halt-before-commit per [[feedback_strict_review_off_gate]]; bank
# overlays MAY TIGHTEN (shrink the compatible-pair list). LOOSENING the
# kernel default-deny requires a coordinated kernel + ADR amendment.

package cognic.memory.recall

import future.keywords.if
import future.keywords.in

# ADR-015 default-deny baseline. Incompatible (and missing-field) recalls
# fall through to {"allow": false}; a positive rule below must explicitly
# fire to flip it.
default purpose_compatible := {"allow": false}

# Identical write/recall purpose is always compatible.
purpose_compatible := {"allow": true} if {
	input.write_purpose == input.recall_purpose
}

# Explicitly-listed compatible pairs. Conservative bank-grade seed set;
# bank overlays may TIGHTEN (shrink) this list but not loosen the kernel
# default-deny.
purpose_compatible := {"allow": true} if {
	some pair in _compatible_pairs
	pair == [input.write_purpose, input.recall_purpose]
}

_compatible_pairs := [
	["transaction_processing", "regulatory_reporting"],
	["transaction_processing", "audit_evidence"],
	["fraud_detection", "audit_evidence"],
]
