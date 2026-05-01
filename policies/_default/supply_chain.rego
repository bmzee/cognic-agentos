package cognic.supply_chain

# Default-deny posture per ADR-007 / ADR-016 fail-closed conventions.
# Sprint 4 default bundle answers exactly one decision_point:
# `data.cognic.supply_chain.allow`. Sprint 13.5 will extend with the
# remaining decision points (packs, models, tools, sandbox, subagent,
# lifecycle) per ADR-015 §"Sprint 13.5 (full)".

default allow := false

# Full-grade packs always allowed (mandatory floor cleared + grace-period
# gates also cleared per Sprint-4 plan §3).
allow if {
	input.attestation_grade == "full"
}

# Partial-grade packs allowed UNLESS the tenant policy requires full grade.
# Per ADR-016 §"Implementation phases" Wave 1 grace period: missing SLSA /
# in-toto / vuln scan / license audit register at partial grade; tenants
# can opt in to strict mode by setting `tenant_policy.require_full = true`.
allow if {
	input.attestation_grade == "partial"
	not input.tenant_policy.require_full
}

# Reasoning surface for operator-facing UIs (Sprint 7B reviewer dashboard
# consumes this). The Sprint-4 evaluator seed exposes Decision.reasoning
# as a free-form string per ADR-015 §"Engine integration"; downstream
# tooling parses by leading prefix.

reasoning := "full attestation grade; mandatory floor + grace-period gates cleared" if {
	input.attestation_grade == "full"
}

reasoning := "partial attestation grade allowed under Wave-1 default tenant policy" if {
	input.attestation_grade == "partial"
	not input.tenant_policy.require_full
}

reasoning := "partial attestation grade refused: tenant requires full grade" if {
	input.attestation_grade == "partial"
	input.tenant_policy.require_full
}
