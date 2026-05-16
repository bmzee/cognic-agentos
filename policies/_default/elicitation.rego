# policies/_default/elicitation.rego
# Sprint-7B.4 T8 — ADR-020 §69-77 + ADR-015 default-deny.
#
# Decision point: data.cognic.ui.elicitation_submit.allow
#
# Input shape (set by portal/api/ui/elicitation_gate.evaluate_elicitation_submission
# at Step 5; pinned by tests/unit/portal/api/ui/test_elicitation_gate.py
# ::TestRegoDecisionPointFormat):
#
#   tenant_id            : string  — actor.tenant_id resolved at the dep
#   elicitation_id       : string  — from the action request body
#   originating_pack_id  : string  — from ElicitationContext.originating_pack_id
#   mode                 : "url" | "form"
#   data_classes         : array of string — from ElicitationContext.data_classes
#   has_form_payload     : bool    — defence-in-depth (mode=form ⇒ true)
#
# Default-deny per ADR-015: allow only fires when one of the explicit
# rules below matches. URL mode is always safe (the user completes
# the elicitation off-system at the bank-overlay's URL surface);
# form mode is only safe when the elicitation's data_classes
# intersect with `restricted_classes` is EMPTY.
#
# `restricted_classes` is the runtime-side 3-value canonical:
# (customer_pii / payment_action / regulator_communication). MUST match
# the python frozenset at
# `protocol/mcp_capabilities._RESTRICTED_DATA_CLASSES` AND the local
# inline copy at `portal/api/ui/elicitation_gate._RESTRICTED_DATA_CLASSES`.
# Three-way drift detector at
# `tests/unit/portal/api/ui/test_elicitation_gate.py
#  ::TestRestrictedClassesThreeWayLockstep` pins the equality —
# the gate module + this Rego bundle + the mcp_capabilities canonical
# MUST agree at every CI run.

package cognic.ui.elicitation_submit

default allow := false

allow if {
    input.mode == "url"
}

allow if {
    input.mode == "form"
    not has_restricted_class
}

restricted_classes := {"customer_pii", "payment_action", "regulator_communication"}

has_restricted_class if {
    some c in input.data_classes
    restricted_classes[c]
}
