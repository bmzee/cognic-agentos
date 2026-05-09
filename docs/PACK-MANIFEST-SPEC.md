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
| `kind` | string | yes | One of `tool` / `skill` / `agent`. Cross-checked against the pyproject entry-point group at sign + verify time (R5 P2 #1 wheel-anchored kind derivation). |

The wheel's `cognic.{tools,skills,agents}` entry-point group is the
**integrity-anchored** source of truth for kind (cosign signs the
wheel; the manifest is mutable). Verify refuses if `[pack].kind`
disagrees with the wheel's entry-point group.

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

Cross-check with `[risk_tier]`: the declared risk tier MUST be at
or above the minimum tier each data_class requires (T10 + T11
cross-validation).

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

## 8. Stability + versioning

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

## 9. Where the validators live

| Block | Validator |
|---|---|
| Shape gate (block presence + AUTHOR-FILL placeholders) | `cli/validators/shape.py` |
| `[identity]` | `cli/validators/identity.py` |
| `[a2a]` | `cli/validators/a2a.py` |
| `[mcp]` | `cli/validators/mcp.py` |
| `[data_governance]` | `cli/validators/data_governance.py` |
| `[risk_tier]` | `cli/validators/risk_tier.py` |
| `[supply_chain]` | `cli/validators/supply_chain.py` |

Each validator surfaces refusals via the closed-enum
`ValidatorReason` literal at `cognic_agentos.cli.__init__`. Refusal
shapes are stable across Sprint-7A onward.
