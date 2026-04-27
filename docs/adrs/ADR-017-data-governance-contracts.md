# ADR-017 — Data Governance Contracts in Pack Manifests

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

Banks deploying AgentOS must answer to multiple data-governance regimes simultaneously: SBP data residency rules, ISO 42001 A.8.x data quality, GDPR-equivalent customer-data-protection laws, EU AI Act high-risk-system data-handling expectations, plus internal bank DLP (data loss prevention) controls.

Pack lifecycle (ADR-012) approves a pack on signature + eval + adversarial + OWASP. None of these tell the bank's compliance officer:

- *What classes of data does this pack touch?* (PII, PCI-CHD, customer-non-public, regulator-non-public, internal-only, public)
- *For what purpose?* (one-time-query, audit, training-data-collection, regulatory-filing)
- *How long will it retain that data?* (none, in-flight only, 7 days, regulator-retention-window)
- *Where can the data egress?* (no egress, internal services only, specific named external endpoints)
- *What DLP hooks must run?* (PII redaction before egress, regulator-data masking, customer-consent check)

Without these declarations as **first-class manifest contracts**, the bank's compliance officer is approving packs without knowing what data they touch — exactly the regulator-finding scenario every bank ops team avoids.

## Decision

Pack manifests declare a **data-governance contract** as a required, machine-readable section. The trust gate (ADR-002) refuses to register a pack without it. Reviewer (ADR-012 Sprint 7B) sees the contract in the evidence view. Runtime (ADR-014 + ADR-015) enforces the declarations via Rego policy.

### Manifest schema (additive to ADR-002 manifest spec)

```yaml
# pyproject.toml or pack manifest YAML
[tool.cognic.data_governance]

# 1. Data classes the pack may touch (whitelist; pack cannot reach beyond)
data_classes = ["customer_pii", "account_balance", "transaction_history"]
# Allowed values:
#   public                — public regulation, KB articles
#   internal              — bank internal docs, non-customer-facing
#   customer_non_public   — customer profile, contact info (non-PII)
#   customer_pii          — name + ID + contact (PII)
#   account_balance       — financial state
#   transaction_history   — financial activity
#   payment_initiation    — funds-movement-touching
#   regulator_non_public  — bank's internal regulatory communications
#   credit_record         — credit / risk record
#   shariah_opinion       — Shariah board records
#   custom:<name>         — bank-defined class with declared semantics

# 2. Purpose declaration (matches ISO 42001 A.7.x impact assessment shape)
purpose = "answer_compliance_question"
purpose_description = "Customer asks 'what's the CTR threshold' — pack searches SBP circulars + composes answer"

# 3. Data retention contract
retention_policy = "in_flight_only"
# Allowed: in_flight_only | session_scope | bounded:<duration> | regulator_window:<years>
retention_max_window = "PT0S"  # ISO 8601 duration; in_flight_only = 0

# 4. Egress contract — where the pack may send data
egress_allow_list = []  # empty list = no external egress
# Examples: ["mcp://cognic-tool-search", "https://api.bank.internal/cbs/v1/*"]
# Wildcards must be operator-approved per tenant Rego policy

# 5. DLP hooks the pack requires (pre/post)
dlp_pre_hooks = ["redact_pii_in_input"]   # run before pack sees data
dlp_post_hooks = ["mask_account_numbers"] # run before pack output reaches caller

# 6. Customer-consent requirement
requires_consent = false
consent_class = null  # if true: which consent token must the session carry

# 7. Regulator-retention requirement
regulator_retention_required = false
regulator_retention_basis = null  # e.g. "SBP-PRD-2025-03 §4.7"
```

### Trust gate enforcement (ADR-002 + ADR-016 extension)

Pack registration refuses if:
- `data_governance` section missing
- Any `data_classes` value not in the controlled vocabulary
- `egress_allow_list` references a host not on the per-tenant operator-approved egress allowlist
- `retention_policy` exceeds the per-tenant maximum
- `requires_consent: true` but no `consent_class` declared
- `regulator_retention_required: true` but no `regulator_retention_basis` cited

### Reviewer (Sprint 7B) evidence view

The reviewer dashboard surfaces the data-governance contract as a structured panel:
- Data classes touched (with PII/customer/regulator highlighting)
- Purpose statement (with diff from previous pack version if applicable)
- Retention window
- Egress targets (with policy-allowed badges)
- DLP hooks declared
- Consent + regulator-retention flags

A reviewer can reject on data-governance grounds with a categorised reason (e.g. "data_class scope expansion not approved", "egress target not policy-allowlisted").

### Runtime enforcement

Per-call:
- Pre-invocation: DLP pre-hooks run (PII redaction, etc.). Hook is a separate adapter `cognic_agentos.dlp.DLPHook` — pack manifest names which hooks must run; AgentOS resolves them via the plugin registry.
- Egress check: any HTTP call from a tool sandbox checks the destination against the manifest's `egress_allow_list` AND the tenant's Rego egress policy. **Reject on mismatch — sandbox kills the call.**
- Post-invocation: DLP post-hooks run (masking, redaction). Output reaches the caller only after hooks complete.
- Data-class crossing: every read of a `customer_pii` source emits a `data_access` audit event tagged with the manifest's `purpose`. Examiner can trace every PII-class data access by purpose.

### Customer-consent integration

When `requires_consent: true`, the harness checks the session for a valid consent token of the declared class before invoking the pack. Missing consent → `ConsentRequired` error. Consent tokens are bank-issued (via the bank's existing consent management system; AgentOS doesn't issue them) and pass through the harness as part of the session context.

### What this is NOT

- **Not a substitute for guardrails** — guardrails block obviously-bad I/O at parse time; data-governance contract declares **policy**, runtime enforces it.
- **Not a substitute for ADR-011 adversarial testing** — adversarial gates test that the pack *can be tricked into* breaking its declarations; the contract states what the declarations are.
- **Not a customer-consent management system** — that's a separate bank-side system. AgentOS consumes consent tokens, doesn't issue them.

## Consequences

### Positive
- **Reviewers can approve packs on data terms**, not just code terms. Bank legal/compliance has a single sheet to evaluate.
- **Examiner-ready** — every PII access is purpose-tagged in the audit chain, mappable to ISO 42001 A.7.4 (impact assessment) and A.10.2 (transparency).
- **DLP is enforced**, not just documented — runtime kills calls that try to exceed the declared egress.
- **EU AI Act high-risk-system documentation** is generated from the manifest, not authored separately.
- **Per-tenant policy lets banks tighten** — a stricter tenant rejects packs that a permissive tenant accepts.

### Negative
- **Pack-author burden** — every pack must declare its contract accurately. Mitigation: SDK CLI (`agentos validate`) checks declared classes against tool implementation (e.g. a tool that calls `query_customer_account` must declare `customer_pii` + `account_balance`).
- **Manifest churn** — when bank-internal data classification changes, all packs may need manifest updates. Versioning policy: manifest changes are a minor pack-version bump (semver).
- **Consent-token integration** — banks vary in consent management. Cognic ships a default consent-token format; banks override per Rego policy.
- **DLP hook ecosystem** — Cognic ships baseline DLP hooks (PII redaction, account masking); banks plug in their own DLP via the plugin registry as `cognic-dlp-<name>` packs.

### Neutral
- This ADR overlaps with ADR-014 (runtime tool approval): a tool with `data_classes: customer_pii` is automatically `risk_tier: customer_data_read` minimum unless the manifest declares otherwise. Schema validation enforces consistency.

## Implementation phases

| Sprint | Work |
|---|---|
| **Sprint 7A** | Pack manifest schema includes `[tool.cognic.data_governance]` section; SDK validator checks against controlled vocabulary; CLI `agentos validate` flags missing/invalid sections |
| **Sprint 7B** | Reviewer evidence view surfaces the contract; rejection categories include data-governance reasons; manifest version bump semver enforced |
| **Sprint 11.5 (DLP seed)** | Minimal `core/dlp/scanner.py` (Presidio-backed) — used by `memory/api.remember()` to enforce consent-token requirement on restricted classes. Same `DLPScanner` protocol Sprint 13.5 will extend. |
| **Sprint 13.5 (full runtime)** | Extends the Sprint 11.5 DLP seed with post-call DLP on tool outputs, custom recogniser plugins, per-tenant recogniser allow/deny lists. Adds: egress check against manifest + Rego policy; consent-token harness integration at the tool-call boundary; data-access audit events tagged with purpose |
| **Wave 2** | Bank-internal DLP plugin packs; consent-token format adapters per bank's existing system |

Sprint 7A grows ~0.5 wu (manifest schema + validator). Sprint 7B grows ~0.5 wu (reviewer evidence panel). Sprint 11.5 absorbs ~0.25 wu for the DLP seed (already inside the Sprint 11.5 envelope). Sprint 13.5 absorbs ~0.5 wu for the full runtime extension.

## References
- ADR-002 (manifest spec — extended here)
- ADR-006 (ISO 42001 — A.7.4 impact, A.10.2 transparency, A.8.x data quality)
- ADR-012 (pack lifecycle — reviewer enforcement point)
- ADR-014 (runtime tool approval — risk-tier consistency)
- ADR-015 (Rego policy — per-tenant data-governance enforcement)
- [GDPR Article 30 — records of processing activities](https://gdpr-info.eu/art-30-gdpr/)
- [EU AI Act — high-risk-system data documentation](https://artificialintelligenceact.eu/)
