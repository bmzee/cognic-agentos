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
- Pre-invocation: DLP pre-hooks run (PII redaction, etc.). Hook is a separate adapter `cognic_agentos.sdk.hook.Hook` — pack manifest names which hooks must run; AgentOS resolves them via the plugin registry. (Sprint-7A2 amendment, 2026-05-10: broadened from the originally-named DLP-only `cognic_agentos.dlp.DLPHook` to a generic phase taxonomy. The DLP pre/post phases are two of the closed-enum hook phases supported in Wave-1; future phases for memory governance / escalation / egress land in follow-up sprints. See "Sprint-7A2 amendments" below.)
- Egress check: any HTTP call from a tool sandbox checks the destination against the manifest's `egress_allow_list` AND the tenant's Rego egress policy. **Reject on mismatch — sandbox kills the call.**
- Post-invocation: DLP post-hooks run (masking, redaction). Output reaches the caller only after hooks complete.
- Data-class crossing: every read of a `customer_pii` source emits a `data_access` audit event tagged with the manifest's `purpose`. Examiner can trace every PII-class data access by purpose.

### DLP hook failure policy *(Sprint-7A2 amendment)*

The runtime hook dispatcher (`packs/hooks/dispatcher.py` per ADR-008 + Sprint-7A2) classifies every hook outcome into one of **five closed-enum failure modes**. Closed-enum so operator runbooks, audit consumers, and policy authors can reason about every possible terminal state without surprise:

| Failure mode | Trigger | Wave-1 default response |
|---|---|---|
| `hook_timeout` | `asyncio.wait_for` exceeded the per-hook `timeout_seconds` clamped against `Settings.hook_max_timeout_s`. | Fail-closed (timeout fires OUTSIDE the hook's catch boundary; fail-open never applies). |
| `hook_exception` | Hook `_invoke()` raised any unhandled `Exception` other than `HookContractError`. | Fail-closed by default. **Carve-out path** — if the hook's `HookDeclaration.fail_policy == "fail_open"` AND the raised exception's class name (walked through MRO per `dispatcher.py:567-569`) matches `HookDeclaration.fail_open_exception`, treat as `decision="pass"`. **Wave-1 reality:** the build-time validator (`cli/validators/hooks.py`) refuses every `fail_policy="fail_open"` declaration with closed-enum `hook_fail_policy_invalid` / `fail_open_without_exception`, so the carve-out is reachable in code but unreachable through the manifest pipeline. The matching build-time manifest shape that would populate `fail_open_exception` is reserved for a follow-up sprint. |
| `hook_malformed_result` | Hook `invoke()` returned a non-`HookResult` / non-coroutine, OR the loader returned a non-Hook subclass, OR `HookContractError` (any subclass) was raised. | **Always fail-closed; never fail-open.** SDK contract violations are programming errors. The pre-instantiation `except HookContractError` block matches BEFORE the generic `except Exception` so a malicious declaration cannot smuggle a contract violation past the malformed-result gate by naming `HookContractError` (or any subclass) as `fail_open_exception`. |
| `hook_policy_refused` | Hook returned `HookResult(decision="refuse", policy_reason=...)`. | Fail-closed; the hook explicitly chose to refuse. |
| `hook_payload_unscannable` | Payload exceeded `Settings.hook_max_payload_bytes` budget BEFORE any hook ran (size-check is a dispatcher precondition). | Fail-closed; never invokes a hook for an over-budget payload. |

**Audit invariant — payload contents are never logged.** Every failure-mode finding records the SHA-256 `policy_input_digest` of the **original** governed payload (computed before any hook transformation) plus the hook ID, phase, ordering class, timeout state, and ISO 42001 control tags. Hook payloads themselves never enter the audit chain: examiners trace WHO ran WHICH hook on a digest-identified governed input, not the input bytes. This invariant is what makes the failure-policy table examiner-readable without leaking customer data.

**Wave-1 fail-closed-only validator boundary.** The build-time validator (`cli/validators/hooks.py`) treats every `fail_policy="fail_open"` declaration as a refusal — closed-enum `hook_fail_policy_invalid` / `fail_open_without_exception`. The runtime registry's `HookDeclaration.fail_open_exception` field is wired (the dispatcher MRO walk is implemented + unit-tested) but unreachable through the validator pipeline until the matching build-time manifest shape lands in a follow-up sprint. The future shape will be a per-`HookDeclaration` exception-class-name field, NOT a `[data_governance]` field — exception class names are a hook-author concern, not a data-governance-contract concern, so they belong on the hook declaration that owns the exception.

**Operator response.** Operator runbook at `docs/operator-runbooks/hook-pack-failure-policy.md` documents per-mode response, audit-trail invariants, and escalation paths. Wave-1 stance: fail-closed is the default for governed-data phases unless and until the policy carve-out (deliberately disabled at the validator boundary) lands.

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
- **Hook pack ecosystem** — Cognic ships baseline hook packs (PII redaction, account masking); banks plug in their own via the plugin registry as `cognic-hook-<name>` packs (Sprint-7A2 naming convention; the runtime registry is name-agnostic — admission is keyed on signed entry-point + ADR-016 bundle, not on pack-name pattern — so any previously-published `cognic-dlp-*` pack remains loadable. `agentos init-hook` produces only `cognic-hook-<name>`-shaped packs going forward).

### Neutral
- This ADR overlaps with ADR-014 (runtime tool approval): a tool with `data_classes: customer_pii` is automatically `risk_tier: customer_data_read` minimum unless the manifest declares otherwise. Schema validation enforces consistency.

## Implementation phases

| Sprint | Work |
|---|---|
| **Sprint 7A** | Pack manifest schema includes `[tool.cognic.data_governance]` section; SDK validator checks against controlled vocabulary; CLI `agentos validate` flags missing/invalid sections |
| **Sprint 7A2** | Hook packs become a first-class authoring kind. SDK ships `cognic_agentos.sdk.hook.Hook` + `HookContext` + `HookResult` + closed-enum `HookPhase`. **Build-time / runtime split for the DLP-hook reference contract:** `cli/validators/data_governance.py` shape-validates `dlp_pre_hooks` / `dlp_post_hooks` as **lists of snake_case strings only** (closed-enum refusals: `<field>_invalid_shape` / `<field>_invalid_hook_id` / `<field>_duplicate`); `cli/validators/hooks.py` validates the `[hooks]` block declarations + cross-checks declared `hook_id`s against pyproject `[project.entry-points."cognic.hooks"]` (in-pack consistency only); cross-pack resolution of a calling pack's `dlp_*_hooks` reference against installed hook-pack IDs is RUNTIME concern — the registry's admission gate plus `DLPGuard` surface unresolved references via the `dlp_hook_id_unresolved` runtime closed-enum, never as a build-time reason. `cli/sign.py` + `cli/verify.py` accept `kind = "hook"` packs through the same ADR-016 supply-chain pipeline. Runtime half: `packs/hooks/registry.py` (verified-hook admission keyed by hook ID + phase + signed-artefact digest; exposes `register_pack` + `snapshot` + `get_phase_hooks`) + `packs/hooks/dispatcher.py` (deterministic phase dispatcher with the 5 closed-enum failure modes documented in "DLP hook failure policy" above; consumes registry snapshots; owns `dispatch` + `dispatch_for_pack`) + `packs/hooks/dlp_integration.py` (DLPGuard wiring `dlp_pre` / `dlp_post` on top of `HookDispatcher.dispatch_for_pack`). Wave-1 fail-closed-only — every `fail_policy="fail_open"` declaration refused at the validator boundary. |
| **Sprint 7B** | Reviewer evidence view surfaces the contract; rejection categories include data-governance reasons; manifest version bump semver enforced |
| **Sprint 11.5 (DLP seed)** | Minimal `core/dlp/scanner.py` (Presidio-backed) — used by `memory/api.remember()` to enforce consent-token requirement on restricted classes. Same `DLPScanner` protocol Sprint 13.5 will extend. |
| **Sprint 13.5 (full runtime)** | Extends the Sprint 11.5 DLP seed with post-call DLP on tool outputs, custom recogniser plugins, per-tenant recogniser allow/deny lists. Adds: egress check against manifest + Rego policy; consent-token harness integration at the tool-call boundary; data-access audit events tagged with purpose |
| **Wave 2** | Bank-internal DLP plugin packs; consent-token format adapters per bank's existing system |

Sprint 7A grows ~0.5 wu (manifest schema + validator). Sprint 7B grows ~0.5 wu (reviewer evidence panel). Sprint 11.5 absorbs ~0.25 wu for the DLP seed (already inside the Sprint 11.5 envelope). Sprint 13.5 absorbs ~0.5 wu for the full runtime extension.

## Sprint-7A2 amendments (descriptive — codifying what shipped, 2026-05-10)

Sprint 7A2 (`feat/sprint-7a2-hook-packs-runtime`) added first-class hook packs as the runtime extension point this ADR's "DLP hooks" subsection always referred to. The original ADR was written before the hook taxonomy firmed up; the amendments are descriptive (codifying what Sprint-7A2 actually shipped), not prescriptive.

- **A2 — Runtime enforcement, line 97.** `cognic_agentos.dlp.DLPHook` → `cognic_agentos.sdk.hook.Hook`. The originally-proposed DLP-only adapter was broadened to a generic `Hook` ABC supporting closed-enum phases (Wave-1: `dlp_pre` + `dlp_post`; future phases for memory governance / escalation / egress).
- **A3 — Negative consequences, line 125 (now line 130).** Hook pack naming aligned with kind-not-phase convention: `cognic-dlp-<name>` → `cognic-hook-<name>`. Runtime registry is name-agnostic (admission is keyed on signed entry-point + ADR-016 bundle, not on pack-name pattern), so any previously-published `cognic-dlp-*` pack remains loadable; `agentos init-hook` produces only `cognic-hook-<name>`-shaped packs going forward.
- **A4 — New "DLP hook failure policy" subsection.** Codifies the 5 closed-enum failure modes (`hook_timeout` / `hook_exception` / `hook_malformed_result` / `hook_policy_refused` / `hook_payload_unscannable`) + the Wave-1 fail-closed-only validator boundary + the runtime carve-out mechanism (`HookDeclaration.fail_open_exception` matched via dispatcher MRO walk per `dispatcher.py:567-569`) + the `policy_input_digest` audit invariant (payload contents are never logged). Operator runbook at `docs/operator-runbooks/hook-pack-failure-policy.md`.
- **Implementation phases table.** Added Sprint 7A2 row enumerating SDK + CLI extensions + runtime registry + dispatcher + DLP integration.

## Sprint 10.6 amendment (workload credential projection — purpose_category + cleanup audit visibility, 2026-05-28)

Sprint 10.6 (`feat/sprint-10.6-workload-credential-projection`, per ADR-004 §25 amendment) adds workload credential projection. Two data-governance touchpoints land in this ADR:

- **Credential `purpose_category` — a credential-specific closed-enum, parallel to the free-form data-governance `purpose`.** The new `[credentials.<logical_name>]` manifest block (spec §5.1) carries a **closed-enum** `purpose_category` with a Wave-1 vocabulary of 8 values — `application_database_read` / `application_database_write` / `audit_log_write` / `external_api_authentication` / `cryptographic_signing` / `cryptographic_decryption` / `service_account_token` / `monitoring_endpoint_access` — plus a free-text `purpose_description` (non-empty, ≤256 chars). This is **NOT a rename** of this ADR's free-form `purpose` field (line 46): credential access has a bounded set of well-known purposes, so a closed enum enables examiner-side aggregation ("show every pack that minted a `cryptographic_signing` credential") that free text cannot. Both fields serve the same ISO 42001 A.7.x purpose-declaration intent. Build-time enforcement: `credentials_purpose_category_invalid_value` + `credentials_purpose_description_invalid_shape` (closed-enum validator reasons in `cli/validators/credentials.py` per spec §5.2).
- **Cleanup audit visibility.** Credential projection teardown emits `sandbox.lifecycle.credentials_projection_cleaned_up` (success) / `sandbox.lifecycle.credentials_projection_cleanup_failed` (failure) chain events. Per `[[feedback_chain_payload_is_evidence_snapshot]]`, these rows carry `logical_name` + `tenant_id` + `lease_id` + `cleanup_target` + `backend_resource_name` + `session_id` provenance (the `cleaned_up` shape omits `vault_path` per the T21 narrower-shape contract; examiners correlate to the earlier `credentials_projected` row via `lease_id` + `logical_name`). The audit chain **never** carries credential field values per ADR-004 §25 / spec §5.7. This lets an examiner prove every projected credential was torn down — closing the "was the minted secret actually removed from the workload?" question on the same hash chain as the mint/projection events. Maps to ISO 42001 A.7.4 (impact assessment) + A.10.2 (transparency), consistent with the existing PII-access purpose-tagging.

The runtime DLP-enforcement surface this ADR otherwise governs is unchanged — credential projection is a sandbox-boundary concern (ADR-004), surfaced here only for the `purpose_category` vocabulary + the cleanup-audit-visibility contract.

## References
- ADR-002 (manifest spec — extended here)
- ADR-006 (ISO 42001 — A.7.4 impact, A.10.2 transparency, A.8.x data quality)
- ADR-008 (authoring platform — `cognic_agentos.sdk.hook.Hook` ABC + `agentos init-hook` scaffold + `kind = "hook"` enumeration)
- ADR-012 (pack lifecycle — reviewer enforcement point)
- ADR-014 (runtime tool approval — risk-tier consistency)
- ADR-015 (Rego policy — per-tenant data-governance enforcement)
- ADR-016 (supply-chain controls — hook packs ride the same cosign + SBOM + SLSA + in-toto bundle as tool / skill / agent packs)
- [GDPR Article 30 — records of processing activities](https://gdpr-info.eu/art-30-gdpr/)
- [EU AI Act — high-risk-system data documentation](https://artificialintelligenceact.eu/)
