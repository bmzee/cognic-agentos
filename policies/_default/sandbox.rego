# policies/_default/sandbox.rego
#
# Sprint-8A T11 — Wave-1 sandbox admission policy bundle per spec §13.
#
# Decision point: data.cognic.sandbox.admit.allow
#
# Wire-protocol-public per AGENTS.md "Stop rules" list (T12 adds
# this bundle alongside sampling.rego / supply_chain.rego /
# elicitation.rego / scheduler.rego). Bank overlays MAY TIGHTEN
# (add more refusal conditions, lower per-tenant caps, refuse
# additional class/tier combinations); LOOSENING the kernel
# defaults REQUIRES an explicit kernel + ADR amendment.
#
# Input shape (set by sandbox/admission.py Stage-2 before OPA eval):
#
#   pack_context.risk_tier                    : string  — ADR-014 8-value tier
#   pack_context.declares_dynamic_install     : bool
#   pack_context.profile                      : "production" | "development"
#   policy.cpu_cores                          : float
#   policy.memory_mb                          : int
#   policy.walltime_s                         : int
#   policy.egress_allow_list                  : array of string (HTTP/HTTPS
#                                               hostnames; non-HTTP schemes
#                                               filtered upstream by T7)
#   policy.vault_path                         : string | null
#   tenant_max.cpu_cores                      : float (when caller pins)
#   tenant_max.memory_mb                      : int   (when caller pins)
#   tenant_max.walltime_s                     : int   (when caller pins)
#   credential_adapter_wired                  : bool — true when a real
#                                               CredentialAdapter (NOT the
#                                               KernelDefaultCredentialAdapter
#                                               stub) is wired
#   runtime_image_in_canonical_set            : bool — precomputed by Python
#                                               against the canonical
#                                               CanonicalImageCatalog (T6);
#                                               passing precomputed bools
#                                               mirrors sampling.rego rather
#                                               than re-implementing set
#                                               membership in Rego
#   runtime_image_in_tenant_allow_list        : bool — precomputed by Python
#                                               against the bank-overlay
#                                               per-tenant allow-list
#
# Default-deny per ADR-015: allow only fires when one of the explicit
# rules below matches. Empty input → deny.
#
# Wave-1 default rules (spec §13):
#
#   1. ALLOW if risk_tier ∈ {read_only, internal_write}
#         AND policy within tenant_max (when caller pins one)
#         AND credential precondition satisfied
#         AND runtime_image authorised (canonical OR tenant allow-list)
#
#   2. REFUSE high-risk tiers unless the Python seam attests a
#      verified grant: risk_tier ∈ {customer_data_read,
#      customer_data_write, payment_action, regulator_communication,
#      cross_tenant, high_risk_custom}. These 6 high-risk tiers
#      require core/approval engine gating per ADR-014. Sprint 13.5c1
#      CONVERTED this rule: a high-risk tier is admissible ONLY when
#      the Python seam attests a verified grant via the strict
#      ``input.approval_verified == true`` bool (the _tier_admissible
#      second arm below); absent/false fail-closed. The engine-absent
#      Python fallback still refuses these tiers with
#      sandbox_high_risk_tier_refused_pre_13_5 BEFORE this bundle is
#      reached. NO escalation-token bypass exists (spec round-1 P2
#      fix) — the ONLY admission path is a verified ADR-014 grant.
#
#   3. REFUSE if policy.vault_path is set AND credential_adapter_wired
#      is false (defence-in-depth with §6.1 step 3 admission check —
#      the KernelDefaultCredentialAdapter stub raises
#      NotImplementedError; refusing here makes the contract surface
#      uniform across the two enforcement layers).
#
#   4. REFUSE if runtime_image is not in the canonical catalog AND
#      not in the tenant allow-list (defence-in-depth with §6.1
#      step 6 catalog-membership check — T11 implementation-notes
#      patch fills the rule-4 gap the plan stub had omitted).
#
#   5. REFUSE if any policy.egress_allow_list entry carries a
#      non-HTTP/HTTPS scheme (defence-in-depth with the Stage-1
#      _validate_egress_host check in sandbox/policy.py +
#      ADR-015 "sandbox.rego owns egress + resource caps"). PURE
#      RegoGUARD — no Python precomputed bool — so the bundle
#      catches the scheme violation independently if Stage-1 is
#      ever bypassed or a future caller wires the bundle directly.
#      The Wave-1 spec §2.1 doctrinal lock restricts sandbox
#      egress to HTTP/HTTPS only.
#
# Sprint 13.5c1 cutover (LANDED — supersedes the pre-13.5 prose that
# promised a one-shot ``sandbox_approval.engine_enabled`` audit event;
# that shape is not implementable in a stateless seam-only sprint and
# is EXPLICITLY superseded per the ADR-014 c1 amendment). Cutover
# evidence is per-decision instead: the engine's own value-free
# ``approval.*`` chain rows (sandbox-originated requests carry the
# ``sandbox:``-prefixed tool_identity + the ``sandbox-admit-*``
# correlation id), the ``sandbox_approval_*`` refusals carrying
# ``approval_request_id``, and the TestSandboxRegoApprovalConvert
# suite proving ``approval_verified`` is REQUIRED for high tiers. The
# per-decision ``approval_gated_admission`` lifecycle event lands with
# the future backend/composition wiring sprint that gives it an
# emission seam.

package cognic.sandbox.admit

import future.keywords.if
import future.keywords.in

default allow := false

# Canonical 6-value high-risk tier set per spec §4.1 + §6.1 + §13.
# Same set referenced by sandbox/admission.py Stage-2 step 4 and by
# the SandboxRefusalReason value sandbox_high_risk_tier_refused_pre_13_5.
high_risk_tiers := {
	"customer_data_read",
	"customer_data_write",
	"payment_action",
	"regulator_communication",
	"cross_tenant",
	"high_risk_custom",
}

# Canonical 2-value Wave-1 safe-tier set per spec §13 rule 1.
safe_tiers := {"read_only", "internal_write"}

allow if {
	_tier_admissible
	_within_tenant_max
	_credential_precondition_satisfied
	_runtime_image_authorised
	_egress_http_only
	_credential_ttl_within_tenant_max
}

# Safe tiers admissible as before (disjointness guard preserved).
_tier_admissible if {
	input.pack_context.risk_tier in safe_tiers
	not input.pack_context.risk_tier in high_risk_tiers
}

# Sprint 13.5c1 CONVERT (ADR-014 c1 amendment — the coordinated
# kernel+ADR loosening): a high-risk tier is admissible ONLY when the
# Python seam attests a verified grant. Strict bool — absence is falsy,
# fail-closed (mirrors the precomputed-bool precedent), so a caller
# that bypasses the Python consult can never admit a high tier.
_tier_admissible if {
	input.pack_context.risk_tier in high_risk_tiers
	input.approval_verified == true
}

# When no tenant_max is provided the caller is the kernel default
# path; cap enforcement defers to the per-tenant settings layer.
_within_tenant_max if {
	not input.tenant_max
}

_within_tenant_max if {
	input.tenant_max
	input.policy.cpu_cores <= input.tenant_max.cpu_cores
	input.policy.memory_mb <= input.tenant_max.memory_mb
	input.policy.walltime_s <= input.tenant_max.walltime_s
}

# Credential precondition: a vault_path is only acceptable when a
# real CredentialAdapter is wired. No vault_path → vacuously
# satisfied (the policy did not request credentials at all).
_credential_precondition_satisfied if {
	not input.policy.vault_path
}

_credential_precondition_satisfied if {
	input.policy.vault_path
	input.credential_adapter_wired == true
}

# Runtime-image authorisation: the image must be in the canonical
# CanonicalImageCatalog OR in the bank-overlay per-tenant allow-list.
# Both inputs are precomputed bools (see sampling.rego precedent)
# rather than re-implementing set membership in Rego against a
# digest-keyed Python data structure.
_runtime_image_authorised if {
	input.runtime_image_in_canonical_set == true
}

_runtime_image_authorised if {
	input.runtime_image_in_tenant_allow_list == true
}

# Egress allow-list shape + scheme guard (rule 5 — genuine
# defence-in-depth in PURE Rego). The Stage-1 _validate_egress_host
# check in sandbox/policy.py already refuses malformed shapes +
# non-HTTP schemes at admission, but spec §13 + ADR-015 require
# the wire-public stop-rule bundle to pin this independently.
# Without these checks a future caller that bypasses Stage-1
# (direct OPA eval, refactor, or a fresh admission path that
# forgets to call validate_policy_shape) reaches this bundle with
# malformed input and would be allowed.
#
# Implementation note: PURE Rego on purpose — passing a precomputed
# `egress_http_only: bool` from Python would just re-rely on
# Stage-1's correctness, defeating the defence-in-depth posture.
# Type guards (`is_array` / `is_string`) + string operations
# (`contains` + `startswith`) are exercised end-to-end by the
# env-gated OPA test matrix.
#
# Three failure modes the guard refuses fail-closed (round-2 P1):
#   (a) egress_allow_list is not an array (e.g. a bare string)
#   (b) any entry is not a string (e.g. int, null, object, array)
#   (c) any string entry carries a non-HTTP/HTTPS scheme
# Empty list is acceptable — caller explicitly opts out of egress.
_egress_http_only if {
	is_array(input.policy.egress_allow_list)
	not _has_invalid_egress_entry
}

# Failure (b) — any entry that is not a string (int / null / object /
# array). The Stage-1 validator's RFC 1123 hostname regex also
# rejects these, but the bundle MUST self-check per the round-2
# defence-in-depth contract; without is_string the per-entry
# string ops below silently no-op on non-string types.
_has_invalid_egress_entry if {
	some entry in input.policy.egress_allow_list
	not is_string(entry)
}

# Failure (c) — any string entry with a non-HTTP/HTTPS scheme
# (e.g. "ftp://..." / "ssh://..." / "file:///..."). String-typed
# precondition (is_string) ensures `contains` + `startswith` see
# a real string; without it Rego's contains(42, "://") is undefined
# and the rule silently no-ops on int entries.
_has_invalid_egress_entry if {
	some entry in input.policy.egress_allow_list
	is_string(entry)
	contains(entry, "://")
	not startswith(entry, "http://")
	not startswith(entry, "https://")
}

# Rule 6 (Sprint 10) — per-tenant max credential TTL cap per ADR-004
# §25/§68/§102 + spec §5.1/§5.2. Wave-1 flat cap: every
# `requires_credentials` entry's `ttl_s` must be <= the tenant's
# configured `max_credential_ttl_s`. Positive helper joined to the
# `allow if` conjunction so the cap actually refuses on the wire (the
# existing bundle has no `count(deny) == 0` precondition and the
# `OPAEngine.evaluate` wrapper returns `Decision(allow: bool, ...)`
# with NO `deny` set surfaced to Python — a standalone `deny[reason]`
# rule would be inert).
#
# Closed-enum reason `sandbox_credential_ttl_exceeds_tenant_max` is
# RESERVED here for Sprint 10 T9 (lifted into the SandboxRefusalReason
# Literal alongside the matching Stage-2 caller mapping). At T8 a
# TTL-exceeded request surfaces through the existing
# `not decision.allow → SandboxLifecycleRefused("sandbox_policy_rego_denied")`
# arm at sandbox/admission.py:584-588. Bisection-clean.
#
# Sprint-8A T11 R2-R3 pure-Rego defence-in-depth: the
# `is_number(cred.ttl_s)` guard inside the helper ensures malformed
# types (string, null, object) refuse fail-closed without an NPE.
# Without the type guard, Rego's `"not-an-int" <= 900` is undefined
# and would silently allow.
#
# Absent OR empty `requires_credentials` (Sprint-8A admission paths
# that never opt into dynamic-lease declarations) is vacuously
# satisfied. Two arms mirror the existing 2-arm
# `_credential_precondition_satisfied` pattern at L137-144:
#   (i) absent — pre-T7 input shape entirely; OR
#   (ii) present — every entry's ttl_s passes the cap (`every` over
#        an empty list also holds, so T7-compatible callers passing
#        the default empty list also pass via this arm).
# Without arm (i) the helper would be undefined on pre-T7-shape input
# (Rego's `every x in undefined { ... }` is undefined), which would
# refuse every existing Sprint-8A admission path the moment rule 6
# joins the `allow if` conjunction.
_credential_ttl_within_tenant_max if {
	not input.requires_credentials
}

_credential_ttl_within_tenant_max if {
	every cred in input.requires_credentials {
		is_number(cred.ttl_s)
		cred.ttl_s <= tenant_max_credential_ttl_s
	}
}

# Tenant overlay first (bank-overlay raise via
# `input.tenant.overlay.max_credential_ttl_s`), kernel default
# fallback (`input.kernel_default.max_credential_ttl_s`) — Wave-1
# admission.py omits the `tenant.overlay` key entirely per spec
# §5.2; the `else` branch always fires for Wave-1 deployments.
# Bank-overlay plumbing for the tenant overlay path is a
# future-sprint hook. Bank overlays may TIGHTEN the cap (lower
# TTL ceiling); LOOSENING the kernel default requires a
# coordinated kernel + ADR amendment per AGENTS.md L150.
tenant_max_credential_ttl_s := ttl if {
	ttl := input.tenant.overlay.max_credential_ttl_s
} else := ttl if {
	ttl := input.kernel_default.max_credential_ttl_s
}
