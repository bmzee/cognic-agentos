# policies/_default/memory.rego
#
# Sprint-11.5a T8 — Wave-1 governed-memory admission policy bundle per
# ADR-015 + ADR-019.
#
# Decision points (wire-protocol-public, BOOLEAN-only):
#   data.cognic.memory.long_term.allow              -> bool
#   data.cognic.memory.cross_subject.allow          -> bool
#   data.cognic.memory.restricted_class_write.allow -> bool
#
# These bundles expose ONLY a boolean `allow` per decision point. The
# closed MemoryRefusalReason mapping (memory_long_term_write_denied /
# memory_cross_subject_access_refused / ...) is assigned by the T9 Python
# gate, NOT by Rego (contrast scheduler.rego which exposes a Rego
# refusal_reason closed-enum). OPAEngine._parse_decision requires the
# evaluated expression value to be a Python bool, so callers MUST point
# at `<rule>.allow`, never at the `{"allow": bool}` object.
#
# Wire-protocol-public policy bundle (AGENTS.md stop-rule). Every edit is
# halt-before-commit per [[feedback_strict_review_off_gate]]; bank
# overlays MAY TIGHTEN (drop the tenant_override permits, add conditions).
# LOOSENING the kernel default-deny requires a coordinated kernel + ADR
# amendment.

package cognic.memory

import future.keywords.if

# ADR-015 default-deny baseline. The kernel NEVER permits by default — a
# permissive default would silently authorise long-term / cross-subject /
# restricted-class writes the moment 11.5a ships. The ONLY Wave-1 true
# path is an explicit tenant_override (a local Rego layer the tenant
# ships); a missing tenant_override key falls through to default-deny.
default long_term := {"allow": false}

default cross_subject := {"allow": false}

default restricted_class_write := {"allow": false}

long_term := {"allow": true} if {
	input.tenant_override == true
}

cross_subject := {"allow": true} if {
	input.tenant_override == true
}

restricted_class_write := {"allow": true} if {
	input.tenant_override == true
}
