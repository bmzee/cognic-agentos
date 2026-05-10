# Cognic AgentOS pack manifest specification

Stable specification for `cognic-pack-manifest.toml` — the canonical
machine-readable manifest every plugin pack ships at its root.

This doc is the schema contract. For the build-time validators that
enforce it read `src/cognic_agentos/cli/validators/`. For the runtime
trust gate that re-reads it at admission read
`src/cognic_agentos/protocol/plugin_registry.py`. For pack-author
workflow read `docs/HOW-TO-WRITE-A-PACK.md`.

**Schema version.** This doc covers `[pack].schema_version = 1`
(Wave-1, Sprint-7A). Schema-version bumps require an ADR amendment +
migration support across at least one minor release.

**Canonical layout.** The manifest is TOML 1.0. All blocks live at
the top level (`[pack]`, `[identity]`, `[a2a]`, `[mcp]`,
`[data_governance]`, `[risk_tier]`, `[supply_chain]`). The legacy
`[tool.cognic.*]` shape is accepted for backward compatibility via
the dual-path lookup in every validator + the runtime reader (R23
doctrine); new packs SHOULD use the canonical top-level shape.

---

## 1. `[pack]` — required, mandatory for all kinds

| Field | Type | Required | Notes |
|---|---|---|---|
| `pack_id` | string | yes | Stable kebab-case identifier (e.g., `cognic-tool-example-minimal`). Must equal the pyproject `[project].name`. |
| `schema_version` | int | yes | `1` for Wave-1. |
| `kind` | string | yes | One of `tool` / `skill` / `agent` / `hook`. Cross-checked against the pyproject entry-point group at sign + verify time (R5 P2 #1 wheel-anchored kind derivation). The `hook` kind (Sprint-7A2) maps to the `cognic.hooks` entry-point group and ships per-pack hook declarations in a `[hooks]` block (Section 8). |

The wheel's `cognic.{tools,skills,agents,hooks}` entry-point group is
the **integrity-anchored** source of truth for kind (cosign signs the
wheel; the manifest is mutable). Verify refuses if `[pack].kind`
disagrees with the wheel's entry-point group. Sprint-7A2 T9 extended
the wheel-integrity helper's kind-derivation table to include
`cognic.hooks → "hook"`.

---

## 2. `[identity]` — required, mandatory for all kinds

AGNTCY/OASF Wave-1 identity matrix.

| Field | Type | Required | Notes |
|---|---|---|---|
| `agent_id` | string | yes | Stable identifier; AGNTCY recommends DID-Web (`did:web:example.com:agents:foo`) but any URI-shaped form passes. |
| `display_name` | string | yes | Human-readable name shown in registries. |
| `provider_organization` | string | yes | Operator/vendor name. |
| `provider_url` | string | yes | URL to the provider's pack-author docs. |
| `agent_card_url` | string | yes | URL the agent card is served from in production. |
| `agent_card_jws_path` | string | agent only | Pack-relative path to the AgentCard JWS file (typically `agent_cards/agent-card.jws`). The runtime trust gate reads this at admission; sign --bundle regenerates it from the pack's AgentCard JSON seed using the configured signing key. |
| `oasf_capability_set` | list[string] | optional Wave-1 (warning if absent) | OASF-style capability vocabulary (e.g., `["kyc.v1", "retrieval.v1"]`). |

---

## 3. `[a2a]` — agent packs only; required for kind="agent"

A2A 1.0 capability declarations. Field names mirror the runtime reader
at `protocol.a2a_capability_negotiation.read_pack_capabilities`.

| Field | Type | Required | Notes |
|---|---|---|---|
| `capabilities_supported` | list[string] | yes | Free-form Cognic semantic capabilities (e.g., `["regulatory_qa"]`). |
| `streaming` | bool | yes | A2A 1.0 streaming. |
| `push_notification_config` | bool | yes | A2A 1.0 push notifications. **Wave-2 feature** — must be `false` Wave-1; T8 validator refuses on `true`. |
| `extended_agent_card` | bool | yes | A2A 1.0 extended agent card. |
| `artifacts_supported` | bool | yes | A2A 1.0 artifacts. |

The Wave-2 `push_notification_config = true` refusal mirrors the
runtime reader's silent filter (the reader filters silently; the
validator refuses), so `[a2a]` validator promotes to the
critical-controls gate at T16 per Doctrine Decision G's "non-trivial
allow/deny logic" rule.

---

## 4. `[mcp]` — tool + skill packs (optional for agent packs)

MCP plugin-protocol declarations.

| Field | Type | Required | Notes |
|---|---|---|---|
| `caching` | bool | yes | TTL caching of tool outputs. **Refused** when `data_classes` contains `restricted` (T9 cross-reference). |
| `elicitation_form` | bool | yes | Form-style elicitation prompts. **Refused** when `data_classes` contains `restricted` (T9 cross-reference). |

Runtime/docs alternative shapes also accepted:
- `caching_strategy = "ttl"` (string) — equivalent to `caching = true`.
- `elicitation_modes = ["form"]` (list) — equivalent to `elicitation_form = true`.

---

## 5. `[data_governance]` — required, mandatory for all kinds

ADR-017 contract. Closed-enum vocabularies live at
`cognic_agentos.cli._governance_vocab`.

| Field | Type | Required | Notes |
|---|---|---|---|
| `data_classes` | list[string] | yes | Closed-enum: `public` / `internal` / `customer_pii` / `payment_data` / `credentials` / `regulator_communication` / `audit_trail` / `model_inputs` / `model_outputs`. |
| `purpose` | string | yes | Closed-enum: `transaction_processing` / `regulatory_reporting` / `fraud_detection` / `customer_support` / `audit_evidence` / `operational_telemetry`. |
| `retention_policy` | string | yes | Closed-enum: `none` / `session_only` / `task_only` / `purpose_window` / `regulator_floor` / `indefinite_with_legal_basis`. |
| `retention_max_window` | int | conditional | Required when `retention_policy != "none"`; positive integer (typically days). |
| `egress_allow_list` | list[string] | yes | Allow-listed egress targets (e.g., `["api.example.com"]`); empty list `[]` means no egress. |
| `dlp_pre_hooks` | list[string] | optional (Sprint-7A2) | Closed-enum hook_id references that MUST run before the calling pack's pack-code on every invocation. Each value resolves to a hook_id declared by an installed `kind = "hook"` pack's `[hooks].declarations[].hook_id`. Cross-check is shape-only at validate time (resolution is runtime); see Section 8 + the runbook at `docs/operator-runbooks/hook-pack-failure-policy.md` for the dispatcher contract. |
| `dlp_post_hooks` | list[string] | optional (Sprint-7A2) | Closed-enum hook_id references that MUST run after pack-code returns and before the result reaches the caller. Same resolution semantics as `dlp_pre_hooks`. |

Cross-check with `[risk_tier]`: the declared risk tier MUST be at
or above the minimum tier each data_class requires (T10 + T11
cross-validation).

Cross-check with `[hooks]` (Sprint-7A2): the `dlp_pre_hooks` /
`dlp_post_hooks` lists name hook_ids declared by INSTALLED hook
packs — by convention authored exclusively in `kind = "hook"`
packs' `[hooks]` blocks (Section 8). Validate-time check is
shape-only because cross-pack hook resolution is a runtime
concern; the runtime hook registry + DLPGuard adapter
(`packs/hooks/dlp_integration.py`) emit the
`dlp_hook_id_unresolved` closed-enum refusal at invocation time if
a referenced hook_id has no installed declaration.

---

## 6. `[risk_tier]` — required, mandatory for all kinds

ADR-014 risk-tier declaration. Closed-enum vocabulary at
`cognic_agentos.cli._governance_vocab.RiskTier`.

| Field | Type | Required | Notes |
|---|---|---|---|
| `tier` | string | yes | Closed-enum: `read_only` / `internal_write` / `customer_data_read` / `customer_data_write` / `payment_action` / `regulator_communication` / `cross_tenant` / `high_risk_custom`. |

The 8-value vocabulary supersedes the legacy 4-value
(`low / medium / high / restricted`) shape from earlier sprints; T11
migrated all scaffold templates + fixtures.

Cross-check with `[data_governance].data_classes`: see Section 5.

---

## 7. `[supply_chain]` — required, mandatory for all kinds

ADR-016 supply-chain attestation declaration.

| Field | Type | Required | Notes |
|---|---|---|---|
| `attestation_paths` | list[string] | yes (non-empty) | Pack-relative paths to attestation files. Validator requires the list to be non-empty AND every declared file to exist on disk + be readable. |

Canonical full set (what `agentos sign --bundle` produces):

```toml
[supply_chain]
attestation_paths = [
    "attestations/cosign.sig",
    "attestations/bundle.sigstore",
    "attestations/sbom.cdx.json",
    "attestations/vuln-scan.json",
    "attestations/license-audit.json",
    "attestations/slsa-provenance.intoto.json",
    "attestations/intoto-layout.json",
]
```

**Validate before sign?** No — `agentos validate` refuses if any
declared path is missing on disk. The realistic flow is
`scaffold → fill manifest → build wheel → sign → validate → harness
→ verify`. See HOW-TO-WRITE-A-PACK §0 for the canonical workflow.

---

## 8. `[hooks]` — hook packs only; required for `kind="hook"` (Sprint-7A2)

ADR-017 Sprint-7A2 amendment: hook packs are the 4th first-class pack
kind alongside tool / skill / agent. They ship deterministic
governance extensions (PII redaction / account masking / output
egress checks / etc.) that DLP-aware tool / skill / agent packs
reference via `[data_governance].dlp_pre_hooks` /
`dlp_post_hooks` (Section 5). Hook packs do NOT ship an AgentCard
JWS (the JWS gate in `cli/sign.py` + `cli/verify.py` is gated on
`pack_kind == "agent"`); they DO ship the same seven-attestation
supply-chain set as every other kind.

The `[hooks]` block is **mandatory** for `kind = "hook"` packs. The
Wave-1 orchestrator's `_FORBIDDEN_BLOCKS_BY_KIND` check is
one-directional — it refuses **hook packs** declaring `[a2a]` or
`[mcp]` (Wave-2-feature smuggling defense), but does NOT refuse
non-hook packs declaring `[hooks]`. Wave-1's contract for non-hook
packs with a present `[hooks]` block: **no kind-strict refusal**,
but the block is still **shape-validated** — `cli/validators/hooks.py`
runs the per-declaration shape gate on any located block regardless
of pack kind, so a non-hook pack with malformed `[hooks].declarations`
still receives the normal closed-enum refusals
(`hook_block_shape_invalid` / `hook_id_invalid` / etc.). The kind
short-circuit only governs (a) the outer "no `[hooks]` block at all"
refusal (which fires only when `pack_kind == "hook"`) and (b) the
entry-point cross-check fall-through when every declaration is
malformed (the cross-check skips for non-hook packs). A follow-up
sprint may add a kind-strict refusal for the non-hook-with-`[hooks]`
case; until then, treat shape-validation as the only gate.

Each entry in the `declarations` array-of-tables declares one hook
the pack ships:

```toml
[hooks]

[[hooks.declarations]]
hook_id = "redact_pii_in_input"
phase = "dlp_pre"
ordering_class = "input_redaction"
timeout_seconds = 5.0
fail_policy = "fail_closed"
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `hook_id` | string | yes | snake_case identifier (`^[a-z][a-z0-9_]*$`); MUST match the pyproject `[project.entry-points."cognic.hooks"]` key for this hook. Globally unique within the manifest (`duplicate_in_manifest` refusal). |
| `phase` | string | yes | Closed-enum: `dlp_pre` / `dlp_post`. Sourced from `cognic_agentos.cli._governance_vocab.HookPhase`. |
| `ordering_class` | string | yes | Closed-enum (8 values): `input_validation` / `input_authorization` / `input_redaction` / `input_normalization` (for `dlp_pre`); `output_validation` / `output_egress_check` / `output_redaction` / `output_masking` (for `dlp_post`). The class name's `input_*` / `output_*` stem MUST match the phase or the validator emits `phase_class_mismatch`. The dispatcher orders hooks within a phase by `HOOK_ORDERING_RANK[ordering_class]` ascending, then `hook_id` alphabetic for ties. |
| `timeout_seconds` | float | yes | Per-hook invocation timeout. Positive number ≤ `Settings.hook_max_timeout_s` (default ceiling 30.0). The dispatcher routes timeout to the closed-enum `hook_timeout` failure mode. |
| `fail_policy` | string | yes | Closed-enum: `fail_closed` / `fail_open`. **Wave-1: only `fail_closed` is accepted.** `fail_closed` is the ADR-017 + Doctrine Lock E default — the calling pack's invocation is refused if the hook times out / raises / returns malformed result / explicitly refuses / payload exceeds the unscannable budget. Any `fail_policy = "fail_open"` declaration is REFUSED in Wave-1 with closed-enum `hook_fail_policy_invalid` (failure_mode `fail_open_without_exception`); the matching `fail_open_exception` declaration shape — which would carve out a per-pack exception path on the registry's `HookDeclaration` runtime — is reserved for a follow-up sprint and does NOT live on `[data_governance]`. Use `fail_closed` until that lands. |

Cross-checks the validator runs:

- **pyproject entry-point cross-check.** Every `[hooks].declarations[].hook_id` MUST appear as a `[project.entry-points."cognic.hooks"]` key in the same pack's `pyproject.toml`. Mismatch routes to `hook_unresolved_reference` (manifest references entry-point that doesn't exist) or `hook_entry_point_mismatch` (pyproject declares an entry-point with no manifest declaration). Both refusal sites surface `pyproject_unparseable` for unreadable / malformed pyproject.toml files.
- **Per-declaration shape gate.** Block-shape failures (declarations field absent, declarations not a list, declarations empty, declaration entry not a table, declaration missing required field) all route to the closed-enum `hook_block_shape_invalid` reason with `payload.failure_mode` distinguishing the sub-case.
- **Hook-pack kind-gate (one-directional).** The orchestrator's `_FORBIDDEN_BLOCKS_BY_KIND` check refuses HOOK packs declaring `[a2a]` or `[mcp]` (closed-enum `hook_pack_kind_constraint_violated` with `payload.failure_mode` distinguishing the offending block). The check does NOT fire on non-hook packs declaring `[hooks]` — there is no kind-strict refusal for that path in Wave-1, but `cli/validators/hooks.py` still shape-validates any present `[hooks]` block regardless of pack kind (see the §8 contract paragraph above for the full breakdown).

The full closed-enum refusal taxonomy emitted by `cli/validators/hooks.py`:

| Reason | Failure modes carried via `payload.failure_mode` |
|---|---|
| `hook_block_shape_invalid` | `block_missing_for_hook_pack` / `declarations_field_absent` / `declarations_field_not_list` / `declarations_empty` / `declaration_entry_not_table` / `declaration_missing_required_field` |
| `hook_id_invalid` | `invalid_shape` / `duplicate_in_manifest` |
| `hook_phase_invalid` | `not_in_closed_enum` / `not_a_string` |
| `hook_ordering_class_invalid` | `not_in_closed_enum` / `not_a_string` / `phase_class_mismatch` |
| `hook_timeout_invalid` | `not_a_positive_number` / `above_ceiling` |
| `hook_fail_policy_invalid` | `not_in_closed_enum` / `not_a_string` / `fail_open_without_exception` |
| `hook_entry_point_mismatch` | `pyproject_only` / `pyproject_unparseable` |
| `hook_unresolved_reference` | `manifest_only` |
| `hook_pack_kind_constraint_violated` | (orchestrator-owned; HOOK pack declares `[a2a]` or `[mcp]` — Wave-1's one-directional kind-gate; `payload.failure_mode` distinguishes the offending block) |

For the runtime side of the contract — what happens when a referenced
hook_id can't be resolved at invocation time, when a hook times out,
when `_invoke()` raises — see
`docs/operator-runbooks/hook-pack-failure-policy.md` (the 5 closed-enum
dispatcher failure modes + their on-call remediations).

---

## 9. Stability + versioning

| Item | Stability |
|---|---|
| `[pack]` block field names + types | Backward-compatible across Sprint-7A onward. |
| `[identity]` block field names + types | Same. |
| `[a2a]` / `[mcp]` block field names + types | Same. |
| `[data_governance]` closed-enum values | Same. Adding new values is a non-breaking change; removing or renaming requires schema-version bump. |
| `[risk_tier]` closed-enum values | Same. |
| `[supply_chain].attestation_paths` semantics | Stable; the list of canonical attestation filenames may grow (new attestation kinds) but existing entries remain. |
| Legacy `[tool.cognic.*]` shape | Permanent backward-compatibility per R23 doctrine; new packs SHOULD use the top-level canonical shape. |

**Schema-version bumps.** A bump to `[pack].schema_version = 2`
requires:
- An ADR amendment (likely an extension to ADR-008 / ADR-017).
- Migration support: validators accept v1 + v2 manifests during the
  transition window.
- A migration release note in the next release-notes file.
- A `tools/migrate_pack_manifest.py` helper if the migration is
  non-trivial.

**Closed-enum drift detection.** Every closed-enum value the
manifest references is pinned by a drift-detector test in
`tests/unit/cli/test_governance_vocab.py` (or analogous).

---

## 10. Where the validators live

| Block | Validator |
|---|---|
| Shape gate (block presence + AUTHOR-FILL placeholders) | `cli/validators/shape.py` |
| `[identity]` | `cli/validators/identity.py` |
| `[a2a]` | `cli/validators/a2a.py` |
| `[mcp]` | `cli/validators/mcp.py` |
| `[data_governance]` | `cli/validators/data_governance.py` |
| `[risk_tier]` | `cli/validators/risk_tier.py` |
| `[supply_chain]` | `cli/validators/supply_chain.py` |
| `[hooks]` | `cli/validators/hooks.py` |

Each validator surfaces refusals via the closed-enum
`ValidatorReason` literal at `cognic_agentos.cli.__init__`. Refusal
shapes are stable across Sprint-7A onward.
