# Sprint 7B.3 — Reviewer evidence panels + 5-gate approval composition + reviewer-acknowledgement field enforcement (per ADR-012 + ADR-014 + ADR-016 + ADR-017 + ADR-002/003 + ADR-006) — Closeout Note

**Date:** 2026-05-15
**Sprints closed:** 7B.3 (4 reviewer evidence-panel projectors at `packs/evidence/*.py` — data-governance / risk-tier / supply-chain / conformance-matrix — each a pure-functional projector owning a wire-protocol-public closed-enum diff/flag vocabulary + the pure-functional 5-gate approval composer at `packs/approval_gates.py` deciding the `under_review → approved` transition across 5 orthogonal ADR-012 §41 gates + the ADR-012 §107-110 override path with a categorised `ApprovalOverrideReason` vocabulary + `pack.approval_override` chain event + the approve endpoint at `portal/api/packs/review_routes.py` wired to the composer (replacing the Sprint-7B.2 `HTTPException(503)` stub) + server-side reviewer-acknowledgement field enforcement + 4 GET evidence-panel endpoints at the NEW `portal/api/packs/evidence_routes.py` factory module + evidence-panel access audit emission via the NEW `PackRecordStore.append_evidence_read_event` seam + the manifest-evidence-source seam at `packs/_lifecycle_helpers.py` + 4 new optional `transition()` kwargs threading 7B.3 evidence onto the approve chain row + the `agentos sign --bundle-root` signing extension + critical-controls floor 55 → 60 with 5 modules promoted incrementally at T3-T7 + AGENTS.md "Authoring — Reviewer evidence + 5-gate composer (Sprint 7B.3)" subsection + the `tools/check_critical_coverage.py` count-guard self-test).
**State:** **READY-FOR-GATE** on `feat/sprint-7b3-reviewer-evidence-panels-5-gate`. No push, no PR, no merge until the human authorises per the AGENTS.md per-action rule.
**Pre-T13 tip:** `cffef6b docs(sprint-7b3): T12 — BUILD_PLAN §602 7B.3 CLOSED status flip + 7B.1/7B.2 merge-status correction + R20 plan patch`.
**Stack base:** `a9631ff` on `main` — the merged Sprint-7B.2 PR #23. Unlike Sprint 7B.1 / 7B.2 (which developed as a stacked pair before merging), **Sprint 7B.3 branches directly off merged `main`**: 7B.1 was merged via PR #22 (`83b73c8`) and 7B.2 via PR #23 (`a9631ff`) between the 7B.2 closeout and the 7B.3 start. `git rev-list --count a9631ff..HEAD` therefore reports the 7B.3-only ladder (13 pre-T13 / 14 post-T13) with no stacked-layer arithmetic.
**14 Sprint-7B.3 commits after T13 lands** atop the merged Sprint-7B.2 tip (`a9631ff`): T1 chore (plan-of-record), T2 (reviewer-ack `ApprovalOverrideReason` vocab + `_lifecycle_helpers.py` manifest-evidence seam + 4 `transition()` kwargs + `agentos sign --bundle-root` + `[supply_chain].blob_path` validator), T2 microfix (`test_config.py` validator-reason drift detector updated for the 3 new T2 signing reasons), T3 (`data_governance.py` evidence panel + the NEW `evidence_routes.py` factory module + `router.py` include), T4 (`risk_tier.py` evidence panel + reviewer P2/P3 hardening on `data_governance.py`), T5 (`supply_chain.py` evidence panel + `load_latest_submit_created_at` retention seam), T6 (`conformance_matrix.py` evidence panel + the build-time `conformance_matrix.json` generator + drift detector), T7 (`approval_gates.py` 5-gate composer + 9 closed-enum Literals + binary `SignatureGateOutcome`), T8 (`OverrideRefusalReason` + override-aware composer + `append_override_event` storage seam + `pack.override.approval_gate` RBAC scope 12→13), T9 (approve endpoint 5-gate wiring replacing the 503 stub + override path + `_signature_path_resolver.py` + `trust_root_resolver.py` Protocol + app-factory trust-gate wiring), T10 (evidence-panel access audit emission + `append_evidence_read_event` seam), T11 (AGENTS.md 7B.3 subsection + `check_critical_coverage.py` docstring section 55→60 + count-guard self-test), T12 (BUILD_PLAN §602 7B.3 CLOSED status flip + 7B.1/7B.2 merge-status correction), T13 closeout (this commit).

**Sub-sprint allocation context.** Sprint 7B was pre-split per BUILD_PLAN.md §1142 schedule-risk fallback into 7B.1 + 7B.2 + 7B.3 + 7B.4 before T1. **Sprint 7B.3 is the reviewer evidence panels + 5-gate approval composition + reviewer-acknowledgement field enforcement + gate-override path sub-sprint only.** UI event-stream endpoints (SSE + frontend-action POST + portable JSON schema), RBAC denial chain events, the ADR-012 §114-122 fixture-AgentOS test harness, the eval / adversarial harness chain-payload writers (gates 2-3 evidence), the tenant data-governance policy store, the real `TrustRootResolver` implementation, and `fail_open_exception` build-time manifest shape all defer to 7B.4 / Sprint 11-12 per the hand-off checklist below.

## What ships in `feat/sprint-7b3-reviewer-evidence-panels-5-gate` after Sprint 7B.3

### Reviewer-ack vocab + manifest-evidence seam + signing bundle-root (Sprint-7B.3 T2)

- **`src/cognic_agentos/packs/approval_types.py`** *(NEW)* (T2, NOT-CC — type-only module per R7 P3 #5; OFF the durable gate) — closed-enum **4-value** `ApprovalOverrideReason` Literal at `approval_types.py:42` (`security_exception` / `prerelease_validation` / `legacy_grandfather` / `other`) — wire-protocol-public on the approve endpoint's request body per ADR-012 §107. Single-Literal module with no executable logic; off-floor rationale + a 3-regression drift detector at `tests/unit/packs/test_approval_types_drift.py` (exact-set equality + count guard + AST scan asserting the module declares ONLY the Literal).
- **`src/cognic_agentos/packs/_lifecycle_helpers.py`** *(NEW)* (T2, NOT-CC — module-private pure-functional helper) — `find_latest_submit_row(history) -> DecisionRecord | None` at `_lifecycle_helpers.py:49` walks a pack's `load_lifecycle_history` output newest-first and returns the most recent `pack.lifecycle.submitted` chain row. The AUTHORITATIVE manifest-evidence-source seam for the T3-T6 panel projectors + the T9 approve handler — the persisted manifest lives at `payload["manifest"]` on that row (R1 P2 #1 fix). `_SUBMIT_DECISION_TYPE` at `:34` mirrors the `decision_type=f"pack.lifecycle.{target_state}"` submit-transition f-string at `packs/storage.py:981`; a drift detector pins the equality.
- **`packs/storage.py`** T2 CC-source extension — `transition()` got **4 optional keyword-only kwargs** at `storage.py:728-731` (`reviewer_acknowledgement: dict | None`, `payload_manifest: dict | None`, `override_event_id: str | None`, `signed_artefact_root: str | None`), each persisted conditionally onto the chain-row payload at `:972-979` (`payload["reviewer_acknowledgement"]` / `payload["manifest"]` / `payload["override_event_id"]` / `payload["signed_artefact_root"]`). Additive-only schema — omitted kwargs add no keys; every pre-7B.3 chain row stays byte-shape compatible.
- **`cli/sign.py` + `cli/validators/supply_chain.py` + `cli/__init__.py`** T2 CC-source extensions — `agentos sign --bundle-root <path>` flag (refuses with `sign_wheel_outside_bundle_root` when the resolved wheel is not a descendant of the resolved bundle root) + `cognic-pack-manifest.toml` `[supply_chain].blob_path` write-back (`sign_manifest_blob_path_write_failed` on write failure) + the `[supply_chain].blob_path` field validator (`supply_chain_blob_path_unresolvable`). 3 new wire-protocol-public `ValidatorReason` values in `cli/__init__.py` so the runtime signature gate can bind the cosign blob path at approve time per ADR-012 §110.
- **`portal/api/packs/author_routes.py`** T2 — submit handler threads `payload_manifest=body.manifest` + `signed_artefact_root` into `store.transition()` so the persisted submit chain row carries the full manifest body the evidence panels read.
- **`dto.py`** T2 — `ReviewerAcknowledgement` Pydantic model at `dto.py:435` (one boolean per panel; 4 booleans total).
- **`74ce350` microfix** — `tests/unit/test_config.py` validator-reason drift detector updated for the 3 new T2 signing reasons (test-only; no production change).

### Data-governance evidence panel + evidence_routes.py factory (Sprint-7B.3 T3)

- **`src/cognic_agentos/packs/evidence/data_governance.py`** *(NEW)* (T3, CRITICAL CONTROLS — gate-promoted at T3) — pure-functional ADR-017 data-governance evidence-panel projector. `project_data_governance_panel(*, manifest, record_kind, tenant_policy=None)` at `data_governance.py:300` projects the `[data_governance]` manifest block onto the frozen `DataGovernancePanelData` (at `:172-173`). Owns the wire-protocol-public closed-enum **7-value** `DataGovernanceDiffFlag` Literal at `:81-88` (`data_class_not_in_tenant_allowlist` / `purpose_not_declared` / `retention_exceeds_tenant_max` / `egress_endpoint_not_in_tenant_allowlist` / `dlp_pre_hook_missing` / `dlp_post_hook_missing` / `none`) — the `tenant_policy_diff` tuple vocabulary; `()` means "no tenant policy wired", `("none",)` means "policy wired + no drift". `TenantDataGovernancePolicy` TypedDict at `:132`.
- **`src/cognic_agentos/portal/api/packs/evidence_routes.py`** *(NEW)* (T3, NOT-CC — stays OFF the durable gate per the T11 R19 user decision) — `build_evidence_routes(*, store: PackRecordStore) -> APIRouter` factory at `evidence_routes.py:164`, mirroring the `build_review_routes` / `build_operator_routes` / `build_inspection_routes` pattern. Houses the 4 GET evidence-panel handlers + their RBAC/tenant-isolation dep closures + (from T10) the audit-emission seam. Route-owned closed-enum **3-value** `EvidencePanelRefusalReason` Literal at `:135` (`pack_not_yet_submitted` / `manifest_evidence_not_persisted` / `pack_kind_mismatch`) for the 409 refusal contract. Off-gate per R32 doctrine — no Human-only-decisions enforcement boundary, no actor_type chain-payload provenance surface; the T10 audit-emit CC risk is covered upstream by `packs/storage.py` being on the gate.
- **`portal/api/packs/router.py`** T3 — `include_router(build_evidence_routes(...))` one-line include; router.py stays scaffolding-only per R3 P2 #3 doctrine.
- **`dto.py`** T3 — `DataGovernancePanel` response DTO at `dto.py:545`.
- **Critical-controls floor 55 → 56** at T3 — `data_governance.py` promoted (AGENTS.md L54 explicit stop rule + wire-protocol-public projection of ADR-017 manifest fields).

### Risk-tier evidence panel (Sprint-7B.3 T4)

- **`src/cognic_agentos/packs/evidence/risk_tier.py`** *(NEW)* (T4, CRITICAL CONTROLS — gate-promoted at T4) — pure-functional ADR-014 §24-37 risk-tier evidence-panel projector. `project_risk_tier_panel(*, manifest, record_kind)` at `risk_tier.py:222` projects the `[risk_tier]` block onto the frozen `RiskTierPanelData` (at `:181-182`). Owns the wire-protocol-public closed-enum **7-value** `ApprovalFlowKind` Literal at `:70-78` (`auto_run` / `audit_emphasis` / `single_approval` / `four_eyes` / `four_eyes_categorised` / `operator_legal_signoff` / `pack_declared`) + the 1:1 `_RISK_TIER_TO_APPROVAL_FLOW` mapping table at `:132` keyed by the ADR-014 canonical 8-value `RiskTier`. Drift in either the Literal or the mapping is wire-protocol-public regression.
- **`dto.py`** T4 — `RiskTierPanel` response DTO at `dto.py:619`.
- **`packs/evidence/data_governance.py`** T4 — reviewer P2/P3 hardening (carried in the T4 commit).
- **Critical-controls floor 56 → 57** at T4 — `risk_tier.py` promoted.

### Supply-chain evidence panel + retention storage seam (Sprint-7B.3 T5)

- **`src/cognic_agentos/packs/evidence/supply_chain.py`** *(NEW)* (T5, CRITICAL CONTROLS — gate-promoted at T5) — pure-functional ADR-016 §23-33 + §70-72 supply-chain evidence-panel projector. `project_supply_chain_panel(*, manifest, record_kind, submit_created_at)` at `supply_chain.py:294` projects the `[supply_chain]` block onto the frozen `SupplyChainPanelData` (at `:178-179`), deriving the 7-year sigstore-bundle retention floor from `submit_created_at`. Owns the wire-protocol-public closed-enum **7-value** `AttestationKind` Literal at `:111-119` (`cosign` / `slsa` / `sbom` / `vuln_scan_baseline` / `license_audit` / `sigstore_bundle` / `in_toto`) — also the keyset for the 5-gate composer's Gate 1 evidence lookup. `_CANONICAL_ATTESTATION_BASENAMES` at `:160` maps each canonical attestation filename to the panel field that surfaces its declared path.
- **`packs/storage.py`** T5 CC-source extension — `load_latest_submit_created_at` read seam (feeds the panel's 7-year-retention floor computation). Pure read; no Doctrine Lock D touch.
- **`dto.py`** T5 — `SupplyChainPanel` response DTO at `dto.py:682`.
- **Critical-controls floor 57 → 58** at T5 — `supply_chain.py` promoted.

### Conformance-matrix evidence panel + build-time JSON generator (Sprint-7B.3 T6)

- **`src/cognic_agentos/packs/evidence/conformance_matrix.py`** *(NEW)* (T6, CRITICAL CONTROLS — gate-promoted at T6) — pure-functional ADR-002 + ADR-003 + AGNTCY/OASF Wave-2 protocol-conformance evidence-panel projector. `project_conformance_matrix_panel(*, manifest, record_kind, conformance_payload, matrix=None)` at `conformance_matrix.py:741` compares a pack's manifest-declared MCP / A2A / OASF features against the static-shipped `_CONFORMANCE_MATRIX` (loaded once at import from `conformance_matrix.json` at `:251`) AND defensively reconstructs the persisted `payload["conformance"]` OWASP verdict into the panel-local `OwaspVerdictData` (frozen, at `:397`). Owns the wire-protocol-public closed-enum **6-value** `MatrixComparisonFlag` Literal at `:148-155` (`mcp_capability_restricted` / `mcp_capability_unknown` / `a2a_feature_forbidden` / `a2a_wave2_feature_declared` / `a2a_feature_unknown` / `oasf_capability_wave2_declared`) + the R9 kind-applicability sets `_MCP_APPLICABLE_KINDS` / `_OASF_APPLICABLE_KINDS` at `:316-318`.
- **`src/cognic_agentos/packs/evidence/conformance_matrix.json`** *(NEW)* — static-shipped JSON projection of the two authoritative conformance docs; loaded at module import. Runtime NEVER parses Markdown.
- **`tools/generate_conformance_matrix_json.py`** *(NEW, off-floor — `tools/` scripts are not coverage-tracked per Doctrine F)** — build-time generator parsing `docs/MCP-CONFORMANCE.md` + `docs/A2A-CONFORMANCE.md` → emits the committed JSON. `tests/unit/tools/test_generate_conformance_matrix_json.py` *(NEW)* is the build-time drift detector: re-runs the generator over the live Markdown + asserts byte-for-byte equality with the committed JSON.
- **`dto.py`** T6 — `ConformanceMatrixPanel` response DTO at `dto.py:880` + 4 sub-models (`MatrixDeclarationPanel` / `MatrixComparisonPanel` / `OwaspCheckResultPanel` / `OwaspVerdictPanel`).
- **Critical-controls floor 58 → 59** at T6 — `conformance_matrix.py` promoted.

### 5-gate approval composer (Sprint-7B.3 T7)

- **`src/cognic_agentos/packs/approval_gates.py`** *(NEW)* (T7, CRITICAL CONTROLS — gate-promoted at T7) — the substantive enforcement boundary for the `under_review → approved` lifecycle transition. The pure-functional `compose_approval_gates(*, signature_input, evaluation_input, adversarial_input, owasp_input, pack_kind)` at `approval_gates.py:412` decides whether a pack clears the 5 orthogonal ADR-012 §41 gates. Owns **9 closed-enum Literals** at T7: `ApprovalGateName` 5-value at `:112-118` (canonical order mirrored by `_GATE_ORDER` at `:237`); `ApprovalGateOutcome` 3-value at `:123` (`green` / `red` / `evidence_not_attached`); the binary `SignatureGateOutcome` 2-value at `:140` (`green` / `red` only — makes the illegal `evidence_not_attached` signature state unrepresentable per ADR-012 §110); the 5 per-gate red-reason vocabularies (`SignatureRedReason` 13-value at `:159`, `EvaluationRedReason` 2-value at `:184`, `AdversarialRedReason` 3-value at `:191`, `OwaspRedReason` 3-value at `:199` — incl. `owasp_yellow_blocks_approval` per R10 LOCK Flag #2, `ReviewerAckRedReason` 1-value at `:215`); and the consolidated **22-value** `ApprovalGateRedReason` union — the wire-protocol-public refusal vocabulary the 412 `ApproveRefusalResponse` body carries. `_NON_OVERRIDABLE_GATES = frozenset({"signature"})` at `:249` is the ADR-012 §110 + R10 LOCK Flag #4 policy constant. Pure-functional — no I/O, no DB, no time, no random.
- **Critical-controls floor 59 → 60** at T7 — `approval_gates.py` promoted (substantive enforcement boundary; 10 wire-protocol-public closed-enum Literals counting the T8 `OverrideRefusalReason`).

### Override scope + override-aware composer + override-event storage seam (Sprint-7B.3 T8)

- **`packs/approval_gates.py`** T8 CC extension — the ADR-012 §107 override path. `OverrideRefusalReason` 4-value Literal at `approval_gates.py:510` (`composition_already_all_green` / `override_scope_not_held` / `override_reason_missing` / `non_overridable_red_gate`); the frozen `OverrideDecision` at `:536-537`; `evaluate_override_decision(*, composition, override_scope_held, override_reason)` at `:551` (pure-functional — decides whether the override path may force-approve); and the canonical-safe `composition_snapshot(composition)` serialiser at `:602` for the `pack.approval_override` chain-event payload.
- **`packs/storage.py`** T8 CC-source extension — NEW `append_override_event(...)` at `storage.py:994` emitting a `pack.approval_override` chain event (decision_type) tagged with ISO 42001 `A.6.2.4` (`_OVERRIDE_EVENT_ISO_CONTROLS` at `:400`); returns the frozen `OverrideEventAppendResult(record_id, chain_hash)`. Uses the plain `DecisionHistoryStore.append` API — an override is not a lifecycle transition (no `validate_transition` precondition, no `packs.state` cache mutation).
- **`portal/rbac/scopes.py`** T8 CC-source extension — `PackRBACScope` Literal extended **12 → 13 values** by adding `pack.override.approval_gate` at `scopes.py:59` (the privileged ADR-012 §107-110 override scope); the new `OVERRIDE_SCOPES` frozenset joins the 4 role-group frozensets so the **5-way union** equals `PACK_LIFECYCLE_SCOPES` (partition invariant pinned by the build-plan partition test).

### Approve endpoint 5-gate wiring + override path + trust-gate wiring (Sprint-7B.3 T9)

- **`portal/api/packs/review_routes.py`** T9 CC-source extension — the `approve` handler swaps the Sprint-7B.2 `HTTPException(503)` stub for the real `under_review → approved` transition gated by the composer. The handler owns the wiring: it resolves the 4 pre-computed gate inputs (signature via the trust gate + supply-chain evidence, evaluation + adversarial via chain-row evidence, OWASP via the submit row's `payload["conformance"]`), calls `compose_approval_gates(...)`, derives gate 5 (reviewer-acknowledgement) from the request body, and on all-green threads `reviewer_acknowledgement` + `override_event_id` into `store.transition(...)`. On a red composition it returns 412 with the `ApproveRefusalResponse` body; the override-path branch calls `evaluate_override_decision(...)` + `append_override_event(...)` first.
- **`src/cognic_agentos/packs/_signature_path_resolver.py`** *(NEW)* (T9, NOT-CC — pure-functional helper feeding the on-gate composer) — `resolve_signature_paths(...)` at `_signature_path_resolver.py:177` returns the frozen `SignaturePathResolution` (`outcome` Literal at `:84`); resolves the cosign signature + blob paths from the manifest with path-traversal rejection. Per R7 P2 #1 there is NO standalone `SignaturePathRedReason` Literal — the resolver returns `SignatureRedReason | None` directly so resolver failures fit `SignatureGateInput.red_reason` with no translation table (the 8 path-resolver red-reasons live inside the on-gate `approval_gates.SignatureRedReason`).
- **`src/cognic_agentos/protocol/trust_root_resolver.py`** *(NEW)* (T9, NOT-CC for 7B.3 — Protocol declaration + fail-loud scaffold; becomes CC when the real resolver lands) — the `TrustRootResolver` Protocol at `trust_root_resolver.py:51` (the seam bank overlays plug the real per-tenant trust-root resolver into) + `KernelDefaultTrustRootResolver` at `:73`, whose kernel-default scaffold raises `NotImplementedError` pointing at the ADR per the AGENTS.md production-grade rule (no silent in-process fallback).
- **`portal/api/app.py` + `portal/api/packs/router.py`** T9 — `create_app(*, trust_gate=None, trust_root_resolver=None)` + `build_packs_router(*, store, trust_gate=None, trust_root_resolver=None)` thread both dependencies through to the approve handler's closure; both attach to `app.state.trust_gate` / `app.state.trust_root_resolver`. Missing-resolver path fails closed as `signature_trust_root_not_configured`.
- **`dto.py`** T9 — `ApproveRequest` at `dto.py:463`, `ApproveGateResult` at `:487`, `ApproveRefusalResponse` at `:508` (the 412 refusal body the handler builds from `composition_snapshot(...)`).

### Evidence-panel access audit emission (Sprint-7B.3 T10)

- **`packs/storage.py`** T10 CC-source extension — NEW `append_evidence_read_event(*, pack_id, actor_subject, panel_name, tenant_id, request_id)` at `storage.py:1098` emitting a `pack.evidence_read.<panel_name>` chain event tagged with ISO 42001 `A.5.31` (`_EVIDENCE_READ_EVENT_ISO_CONTROLS` at `:434`); returns the frozen `EvidenceReadEventAppendResult`. Owns the wire-protocol-public closed-enum **4-value** `EvidencePanelName` Literal (`data_governance` / `risk_tier` / `supply_chain` / `conformance_matrix`). `tenant_id` threads to the `DecisionRecord.tenant_id` column, NOT the payload. Plain `DecisionHistoryStore.append` — a panel read is not a lifecycle transition.
- **`portal/api/packs/evidence_routes.py`** T10 — all 4 GET panel handlers emit one `pack.evidence_read.<panel>` audit chain row per successful 200 read, emitted ONLY after BOTH the projector AND the response-DTO `model_validate` succeed (R18 P2 — a `ValidationError` 500 must not leave an orphan chain row; 4xx/5xx paths emit zero audit events). Threat-model-revert verified.

### AGENTS.md doctrine surface + critical-controls coverage gate documentation (Sprint-7B.3 T11)

- **`AGENTS.md`** — NEW `*Authoring — Reviewer evidence + 5-gate composer (Sprint 7B.3):*` subsection inserted under the "Critical-controls rule" section after the 7B.2 conformance subsections — 8 bullets (4 evidence panels + `approval_gates.py` composer + `evidence_routes.py` [noting OFF-gate] + `_lifecycle_helpers.py` + a cross-cutting `storage.py` / `scopes.py` extensions note). Each bullet cites the module's role + ADR section + closed-enum value counts at file:line.
- **`tools/check_critical_coverage.py`** — NEW "Sprint 7B.3" docstring section block (mirrors the existing "Sprint 7B.2 T12" block) documenting the T3-T7 incremental promotions (gate 55 → 60) + the off-gate rationale for `evidence_routes.py` (R32 doctrine; R19 user decision) and `router.py` (scaffolding-only carrier). `_CRITICAL_FILES` UNCHANGED at 60 entries — the per-task-promotion pattern means T11 adds no entries.
- **`tests/unit/tools/test_check_critical_coverage.py`** *(NEW)* — count-guard self-test (5 tests): asserts `len(_CRITICAL_FILES) == 60`, the 5 7B.3 modules present at `(0.95, 0.90)`, `evidence_routes.py` + `router.py` ABSENT (pins the off-gate decision), no duplicate paths. Threat-model-revert verified load-bearing — dropping a gate entry → count + presence assertions fail.
- **R19 decisions** — `evidence_routes.py` stays OFF the durable gate (user decision, superseding the R3 P2 #3 on-gate projection); `router.py` does NOT promote (scaffolding-only carve-out).

### Closeout doc + BUILD_PLAN §602 status flip (Sprint-7B.3 T12 + T13)

- **`docs/BUILD_PLAN.md` §602** (T12) — NEW 7B.3 **CLOSED** status row (critical-controls floor 55 → 60; 5 CC modules promoted incrementally T3-T7; `evidence_routes.py` off-gate per the T11 R19 decision); removed the "7B.3 (…) reserved for owning sub-sprints" trailing clause from the 7B.2 row. **R20 expanded scope (user decision):** corrected the stale 7B.1 + 7B.2 "READY-FOR-GATE awaiting push/PR/merge authorization" text — git reality shows both merged to `main` (7B.1 PR #22 `83b73c8`, 7B.2 PR #23 `a9631ff`); scope bounded to §602's 7B.1 + 7B.2 rows.
- **`docs/closeouts/2026-05-15-sprint-7b3-reviewer-evidence-panels-5-gate.md`** *(NEW; this file)* (T13) — Sprint 7B.3 closeout note; mirrors the Sprint-7B.2 closeout structure + final reference table.

## CI / production-grade gates

| Gate | Workflow | Trigger | Behaviour |
|---|---|---|---|
| Lint + types + tests | `python.yml` → `lint + test` | push / PR | unchanged — `ruff` + `ruff format --check` + `mypy` strict + `pytest -v` |
| Per-file critical-controls coverage gate | `python.yml` → `lint + test` | push / PR | `tools/check_critical_coverage.py` against `coverage.json` — fails CI if any of the **60** critical-controls modules drops below 95% line OR 90% branch (extended in Sprint-7B.3 T3-T7 by 5: T3 `data_governance.py`; T4 `risk_tier.py`; T5 `supply_chain.py`; T6 `conformance_matrix.py`; T7 `approval_gates.py`). T11 added a count-guard self-test pinning the entry count + the 5 7B.3 modules + the off-gate set. |
| MCP / A2A / image-size budget gates | `python.yml` | push / PR | unchanged — Sprint-5/6 floors stay |
| Live Postgres / Oracle integration | `python.yml` | push / PR | unchanged — Sprint-7B.1 canaries unchanged; Sprint-7B.3 ships no new integration tests (panel projectors are pure-functional; route handlers + composer + storage seams exercise SQLite tmp-path substrate at unit scope) |

## Doctrine adherence

- **AGENTS.md per-edit halt-before-commit on critical-controls modules.** Every CC + CC-ADJ commit paused for explicit user authorization. T2 (`storage.py` 4-kwarg CC-source extension + `cli/sign.py` + `cli/validators/supply_chain.py` — halt-reviewed). T3 (`data_governance.py` CC promotion + `evidence_routes.py` — halt-reviewed). T4 (`risk_tier.py` CC promotion — halt-reviewed). T5 (`supply_chain.py` CC promotion + `storage.py` retention seam — halt-reviewed). T6 (`conformance_matrix.py` CC promotion — halt-reviewed). T7 (`approval_gates.py` CC promotion — halt-reviewed). T8 (override path + `append_override_event` storage seam + `scopes.py` 12→13 — halt-reviewed across R13/R14). T9 (approve endpoint CC-source extension + trust-gate wiring — halt-reviewed across R15/R16). T10 (`append_evidence_read_event` storage seam — halt-reviewed across R17/R18). T11 (AGENTS.md doctrine + coverage gate tool — halt-reviewed across R19). T12 (BUILD_PLAN §602 — halt on doctrine documents; R20). T13 (this closeout — halt on doctrine documents).
- **AGENTS.md `core/canonical.py` per-edit stop rule.** Not touched in Sprint 7B.3. The T8 `composition_snapshot` serialiser produces a canonical-safe `dict` (list-not-tuple) so the override-event chain row passes the existing `core/canonical.canonical_bytes` gate unchanged.
- **Closed-enum vocabulary doctrine.** Sprint-7B.3 added **17 new closed-enum vocabularies** (see Final reference table (a)) + extended 2 cross-sprint ones (`PackRBACScope` 12→13, the CLI `ValidatorReason` set +3 signing reasons). Drift detectors live in per-module test files.
- **Production-grade rule.** Every Sprint-7B.3 module ships real integrations: the panel projectors read real persisted manifest bodies from the chain row (`payload["manifest"]`), not synthetic fixtures; the composer is pure-functional with no mock gate results; the approve handler delegates to the real Sprint-4 `TrustGate.verify_pack_signature(...)` for cosign verification; the `TrustRootResolver` kernel-default is a fail-loud `NotImplementedError` scaffold (no silent in-process fallback) per the production-grade rule; `append_override_event` / `append_evidence_read_event` use the real `DecisionHistoryStore.append` Postgres-backed primitive.
- **Doctrine Lock C (lifecycle pure-functional + closed-enum consumer-API wire-protocol).** Preserved. `packs/lifecycle.py` was not touched in Sprint 7B.3 — all the new 7B.3 evidence threads ride the 4 additive `transition()` kwargs (`reviewer_acknowledgement` / `payload_manifest` / `override_event_id` / `signed_artefact_root`), which `storage.py` persists as thin passthroughs; no new `LifecycleRefusalReason` value.
- **Doctrine Lock D (atomic chain-insert + state-cache UPDATE + chain-head UPDATE single transaction).** Preserved. The T2 4-kwarg extension threads additional payload keys but the atomic envelope `append_with_precondition` stays single-transaction / single-commit-point. The T8 `append_override_event` + T10 `append_evidence_read_event` seams deliberately use the plain `DecisionHistoryStore.append` API (NOT `append_with_precondition`) — an override-justification event and a panel-read event are not lifecycle transitions, so they carry no `validate_transition` precondition and no `packs.state` cache mutation.
- **Doctrine F gate-counting rule.** Critical-controls floor extension at T3-T7 adds 5 modules to the 95/90 floor. Modules deliberately OFF the gate carry documented rationale: `evidence_routes.py` (R32 doctrine + R19 user decision — no Human-only-decisions boundary, no actor_type chain-payload provenance surface; audit-emit covered upstream by on-gate `storage.py`); `router.py` (scaffolding-only carrier); `approval_types.py` (type-only single-Literal module — per-file coverage gates are meaningless for type-only modules; drift detector suffices); `_lifecycle_helpers.py` + `_signature_path_resolver.py` (module-private pure-functional helpers feeding on-gate consumers); `trust_root_resolver.py` (Protocol declaration + fail-loud scaffold — becomes CC when the real resolver lands); `tools/generate_conformance_matrix_json.py` (`tools/` scripts not coverage-tracked).
- **Cite-from-source-at-doc-write-time depth doctrine.** Continued from Sprint-7B.2's `feedback_verify_code_citations_at_doc_write.md`. T11's AGENTS.md subsection + this closeout had every code citation (closed-enum value counts, file:line locations, function signatures, ISO control tags, commit hashes) verified at file:line via `Read` / `grep` in the same compose pass. T11 R19 #1-4 + T12 R20 #1-2 were all plan-vs-reality drifts caught by verifying the plan spec against the codebase + git before executing.

## New doctrines established Sprint-7B.3

- **Per-task CC promotion pattern (T3-T7).** Each evidence panel + the composer was promoted to the durable critical-controls gate by its own landing commit, NOT batched into a closing task. T11's coverage-gate work is therefore documentation-only (a docstring section block + a count-guard self-test) — it adds zero `_CRITICAL_FILES` entries. This is the inverse of the Sprint-7B.2 T12 batch promotion; the count-guard self-test at `tests/unit/tools/test_check_critical_coverage.py` is the new durable invariant that pins the result.
- **Plan-spec-vs-reality verification before execution (R19 + R20).** A plan task's acceptance criteria can silently drift from the codebase between when the plan is written and when the task executes. T11's R3-era spec ("add 6 gate entries, bump 55→61") predated the per-task-promotion pattern; T12's spec assumed 7B.1/7B.2 were unmerged stacked branches. Both were caught by verifying the plan against the codebase + `git` reality BEFORE coding, then patching the plan (Round 19 + Round 20) per `feedback_patch_plan_against_doctrine.md`. Saved as a recurring lesson.
- **Off-gate route module with on-gate storage seam (R32 + R19).** `evidence_routes.py` emits audit chain events (T10) but stays off the durable coverage gate: the chain-write goes through `packs/storage.py:append_evidence_read_event`, which IS on the gate. A route module whose only CC-adjacent surface delegates to an on-gate seam does not itself need promotion — the CC risk is covered upstream. Consistent with the Sprint-7B.2 T7 `inspection_routes.py` carve-out.
- **DTO-validation-precedes-audit-emit ordering (R18 P2).** When a route handler both (a) builds a response DTO from a projector output and (b) emits an audit chain row for the successful read, the audit emit MUST follow the DTO `model_validate` — not just the projector — so a projector/DTO contract drift that 500s does not leave an orphan chain row. The 200↔chain-row 1:1 correlation is examiner-facing wire-protocol surface; pinned by a threat-model-revert-verified regression class.
- **Binary gate outcome makes illegal states unrepresentable (T7).** The cosign signature gate is non-overridable per ADR-012 §110, so `SignatureGateOutcome` is a 2-value Literal (`green` / `red`) — distinct from the 3-value `ApprovalGateOutcome` the other 4 gates use. `evidence_not_attached` is structurally unrepresentable for the signature gate; the type system, not a runtime assertion, enforces it.
- **Override is not a transition (T8 + T10).** Both `append_override_event` and `append_evidence_read_event` use the plain `DecisionHistoryStore.append` API rather than `append_with_precondition`. An override-justification event and a panel-read event carry no state-machine precondition and mutate no `packs.state` cache — they are chain-only audit rows. The chain-head row-lock still serialises ordering.

## Test + coverage state

- **Suite size:** **5744 passed / 48 skipped / 624.32s** at the T12 commit baseline (run at HEAD `cffef6b`; T12 + T13 are doctrine + closeout-doc only, so the count equals the T11 executable-test baseline). Delta from the Sprint-7B.2 baseline (5060 passed / 48 skipped): **+684 passed / +0 skipped** — driven by the per-panel projector regressions (T3-T6), the composer's per-gate + override-path matrix (T7-T8), the approve-endpoint 5-gate + override + trust-gate-wiring suites (T9), the T10 evidence-panel audit-emission 1:1-correlation + cross-panel-isolation + DTO-validation-failure regressions, and the T11 count-guard self-test.
- **Per-file critical-controls coverage gate (60 modules at 95/90):** `tools/check_critical_coverage.py` against the fresh `coverage.json` — **gate passed**; all 55 pre-Sprint-7B.3 modules unchanged + 5 Sprint-7B.3 promotions, each at 100% line / 100% branch:

| Module | Sprint owner | Line% | Branch% | Status |
|---|---|---|---|---|
| (55 modules unchanged from `2026-05-13-sprint-7b2-portal-api-rbac-owasp.md`) | 2 – 7B.2 | ≥95 | ≥90 | PASS |
| `packs/evidence/data_governance.py` | 7B.3 T3 | 100.00 | 100.00 | PASS |
| `packs/evidence/risk_tier.py` | 7B.3 T4 | 100.00 | 100.00 | PASS |
| `packs/evidence/supply_chain.py` | 7B.3 T5 | 100.00 | 100.00 | PASS |
| `packs/evidence/conformance_matrix.py` | 7B.3 T6 | 100.00 | 100.00 | PASS |
| `packs/approval_gates.py` | 7B.3 T7 | 100.00 | 100.00 | PASS |

## ADR validation

| ADR | Title | Sprint-7B.3 relevance | Status |
|---|---|---|---|
| ADR-002 / ADR-003 | MCP / A2A protocol conformance | The conformance-matrix evidence panel (T6) compares manifest-declared MCP / A2A features against the static-shipped conformance matrix projection of `MCP-CONFORMANCE.md` + `A2A-CONFORMANCE.md` | ✅ |
| ADR-006 | ISO 42001 control mapping | Override-justification chain events tagged `A.6.2.4` (T8); evidence-panel access events tagged `A.5.31` (T10); the composer's 412 refusal body + `composition_snapshot` are wire-protocol-public for evidence-pack export | ✅ |
| ADR-008 | Authoring platform (SDK + CLI) | `agentos sign --bundle-root` + the `[supply_chain].blob_path` write-back + validator (T2) extend the Sprint-7A signing CLI so the runtime signature gate can bind the cosign blob path at approve time | ✅ |
| ADR-012 | Bank pack lifecycle | §41 5-gate approval composition wired into the `under_review → approved` approve endpoint (replacing the 7B.2 503 stub); §107-110 override path with `ApprovalOverrideReason` + `pack.override.approval_gate` scope + non-overridable cosign signature gate; §84-110 reviewer evidence panels | ✅ |
| ADR-014 | Runtime tool approval / risk tiers | The risk-tier evidence panel (T4) surfaces the declared 8-value `RiskTier` + the `ApprovalFlowKind` it triggers via the 1:1 `_RISK_TIER_TO_APPROVAL_FLOW` mapping | ✅ |
| ADR-016 | Supply-chain controls | The supply-chain evidence panel (T5) surfaces the 7-value `AttestationKind` set + the 7-year sigstore-bundle retention floor; the 5-gate composer's Gate 1 verifies the cosign signature via the Sprint-4 `TrustGate` | ✅ |
| ADR-017 | Data governance contracts | The data-governance evidence panel (T3) projects the `[data_governance]` manifest block + computes the `DataGovernanceDiffFlag` tuple against tenant policy | ✅ |
| ADR-020 | UI event-stream contract | NOT in Sprint-7B.3 scope — UI event-stream endpoints defer to 7B.4 per the hand-off checklist | ⏸ deferred |

## Final reference table (navigation map)

Consolidates the R-round patch surface into a single navigation map. Future implementers reading this closeout can navigate the plan via this section without re-reading every patch-log round.

### (a) New closed-enum vocabularies introduced Sprint-7B.3

| Literal | Values | Module | Owner task |
|---|---|---|---|
| `ApprovalOverrideReason` | 4 (`security_exception` / `prerelease_validation` / `legacy_grandfather` / `other`) | `packs/approval_types.py:42` | T2 |
| `DataGovernanceDiffFlag` | 7 | `packs/evidence/data_governance.py:81-88` | T3 |
| `EvidencePanelRefusalReason` | 3 (`pack_not_yet_submitted` / `manifest_evidence_not_persisted` / `pack_kind_mismatch`) | `portal/api/packs/evidence_routes.py:135` | T3 |
| `ApprovalFlowKind` | 7 | `packs/evidence/risk_tier.py:70-78` | T4 |
| `AttestationKind` | 7 (`cosign` / `slsa` / `sbom` / `vuln_scan_baseline` / `license_audit` / `sigstore_bundle` / `in_toto`) | `packs/evidence/supply_chain.py:111-119` | T5 |
| `MatrixComparisonFlag` | 6 | `packs/evidence/conformance_matrix.py:148-155` | T6 |
| `ApprovalGateName` | 5 (`signature` / `evaluation` / `adversarial` / `owasp_conformance` / `reviewer_acknowledgement`) | `packs/approval_gates.py:112-118` | T7 |
| `ApprovalGateOutcome` | 3 (`green` / `red` / `evidence_not_attached`) | `packs/approval_gates.py:123` | T7 |
| `SignatureGateOutcome` | 2 (`green` / `red` — illegal `evidence_not_attached` unrepresentable) | `packs/approval_gates.py:140` | T7 |
| `SignatureRedReason` | 13 | `packs/approval_gates.py:159` | T7 |
| `EvaluationRedReason` | 2 | `packs/approval_gates.py:184` | T7 |
| `AdversarialRedReason` | 3 | `packs/approval_gates.py:191` | T7 |
| `OwaspRedReason` | 3 (incl. `owasp_yellow_blocks_approval`) | `packs/approval_gates.py:199` | T7 |
| `ReviewerAckRedReason` | 1 (`reviewer_acknowledgement_incomplete`) | `packs/approval_gates.py:215` | T7 |
| `ApprovalGateRedReason` | 22 (consolidated union of the 5 per-gate Literals) | `packs/approval_gates.py` | T7 |
| `OverrideRefusalReason` | 4 (`composition_already_all_green` / `override_scope_not_held` / `override_reason_missing` / `non_overridable_red_gate`) | `packs/approval_gates.py:510` | T8 |
| `EvidencePanelName` | 4 (`data_governance` / `risk_tier` / `supply_chain` / `conformance_matrix`) | `packs/storage.py` | T10 |

### (b) Cross-sprint closed-enum extensions

| Literal | Pre → Post | Owner task | Note |
|---|---|---|---|
| `PackRBACScope` | 12 → 13 | T8 (added `pack.override.approval_gate`) | `portal/rbac/scopes.py:59`; the new `OVERRIDE_SCOPES` frozenset makes the 5-way role-group union equal `PACK_LIFECYCLE_SCOPES` |
| CLI `ValidatorReason` | +3 signing reasons | T2 | `supply_chain_blob_path_unresolvable` + `sign_wheel_outside_bundle_root` + `sign_manifest_blob_path_write_failed` at `cli/__init__.py`; drift detector updated by the `74ce350` microfix |

### (c) Doctrine sweep paths exclusion set

Standard 3-path exclusion used in every closed-enum drift sweep: `.venv/` + `node_modules/` + `dist/` (excluded via the `ag` / `rg` defaults at sprint runtime; not hard-coded into individual tests).

### (d) New CC modules promoted Sprint-7B.3 (5 net — all incremental, per-task)

| Module | Owner task | Rationale |
|---|---|---|
| `packs/evidence/data_governance.py` | T3 | AGENTS.md L54 explicit stop rule; wire-protocol-public projection of ADR-017 manifest fields + the `DataGovernanceDiffFlag` vocabulary |
| `packs/evidence/risk_tier.py` | T4 | ADR-014 risk-tier vocabulary IS the runtime tool-approval contract; `ApprovalFlowKind` + the 1:1 mapping table |
| `packs/evidence/supply_chain.py` | T5 | ADR-016 attestation kinds + 7-year retention math; `AttestationKind` is also the composer's Gate 1 keyset |
| `packs/evidence/conformance_matrix.py` | T6 | ADR-002/003 protocol-conformance comparison + `MatrixComparisonFlag` + the OWASP-verdict reconstruction |
| `packs/approval_gates.py` | T7 (+ T8 override extension) | Substantive enforcement boundary for `under_review → approved`; 10 wire-protocol-public closed-enum Literals + the override path |

### (e) Cross-sprint CC source touches without re-promotion

| Module | Sprint-7B.3 touch | Doctrine Lock preserved |
|---|---|---|
| `packs/storage.py` | T2 4 new `transition()` kwargs (`reviewer_acknowledgement` / `payload_manifest` / `override_event_id` / `signed_artefact_root`) + T5 `load_latest_submit_created_at` read seam + T8 `append_override_event` + T10 `append_evidence_read_event` | Lock D — all 4 seams keep the atomic envelope; the 2 new event seams use plain `append` (not a transition) |
| `portal/rbac/scopes.py` | T8 `PackRBACScope` 12 → 13 (`pack.override.approval_gate`) + `OVERRIDE_SCOPES` frozenset | partition invariant preserved (5-way union = `PACK_LIFECYCLE_SCOPES`) |
| `portal/api/packs/review_routes.py` | T9 approve handler swaps the 503 stub for the composer call + override-path branch | — |
| `portal/api/packs/author_routes.py` | T2 submit handler threads `payload_manifest` + `signed_artefact_root` | — |
| `cli/sign.py` + `cli/validators/supply_chain.py` + `cli/__init__.py` | T2 `--bundle-root` + `[supply_chain].blob_path` write-back + validator + 3 `ValidatorReason` values | — |

### (f) Modules deliberately OFF the durable gate (with rationale)

| Module | Owner task | Off-gate rationale |
|---|---|---|
| `portal/api/packs/evidence_routes.py` | T3 (+ T10 audit-emit) | R32 doctrine + R19 user decision — no Human-only-decisions boundary, no actor_type chain-payload provenance surface; the T10 audit-emit CC risk is covered upstream by on-gate `packs/storage.py` |
| `packs/approval_types.py` | T2 | Type-only single-Literal module (R7 P3 #5) — per-file coverage gates are meaningless for type-only modules; a 3-regression drift detector pins the vocabulary |
| `packs/_lifecycle_helpers.py` | T2 | Module-private pure-functional helper feeding on-gate projectors + the approve handler |
| `packs/_signature_path_resolver.py` | T9 | Module-private pure-functional helper; its red-reasons fold into the on-gate `approval_gates.SignatureRedReason` (R7 P2 #1 — no standalone Literal) |
| `protocol/trust_root_resolver.py` | T9 | Protocol declaration + fail-loud `NotImplementedError` kernel scaffold; becomes CC when the real per-tenant resolver lands (bank-overlay concern) |
| `portal/api/packs/router.py` | T3 | Scaffolding-only `include_router` carrier — no decision logic, no closed-enum vocabulary, no refusal taxonomy |
| `tools/generate_conformance_matrix_json.py` | T6 | `tools/` build-time script — not coverage-tracked per Doctrine F; pinned by the byte-for-byte drift detector |

### (g) Reviewer-round patch surface (plan Self-Review patch log)

Sprint-7B.3's plan-of-record went through Round 0 (initial draft) + **20 reviewer rounds (R1-R20)**: R1-R10 pre-T1 halt review (doctrine conflicts + flag lock-ins), R11-R18 per-task execution-time + pre-commit reviewer rounds (T7 R11/R12, T8 R13/R14, T9 R15/R16, T10 R17/R18), R19 T11 pre-execution doctrine patch (4 plan-vs-codebase conflicts + 2 user decisions: `evidence_routes.py` off-gate, count-guard self-test), R20 T12 pre-execution doctrine patch (1 plan-vs-git-reality conflict + 1 user decision: correct stale 7B.1/7B.2 merge-status text + R20 #2 reviewer catch on the Architecture line). See the plan's Self-Review patch log for the full per-round detail.

## Sprint 7B.4 hand-off checklist

Sprint 7B.4 picks up the **UI event-stream endpoints** layer of ADR-020 + BUILD_PLAN.md §602, plus the carry-forward items below.

- [ ] **UI event-stream endpoints per ADR-020 (BUILD_PLAN §640-645).** SSE endpoints (`GET /api/v1/ui/runs/{run_id}/events`, `GET /api/v1/ui/tenants/{tenant_id}/events`, `GET /api/v1/ui/events/since/{event_id}`); frontend-action POST `/api/v1/ui/actions` (`approve` / `deny` / `cancel_run` / `interrupt` / `resume` / `submit_elicitation`); RBAC scopes `ui.run_stream` + `ui.tenant_stream` + `ui.action.<class>`; per-tenant connection caps + idle-timeout reaping; portable JSON schema at `/.well-known/cognic-ui-events.json`.
- [ ] **RBAC denial chain events.** Currently structured-log only (since Sprint-7B.2 T2); chain emission deferred so the event-stream + chain row land together with the SSE endpoints.
- [ ] **Eval harness chain-payload writer (Sprint 11).** The 5-gate composer's Gate 2 reads `payload["evaluation"]` from the submit chain row; nobody WRITES that payload in 7B.3 (plan Flag #3 default (c) — `evidence_not_attached` is the wire-protocol shape both pre-harness and post-harness). The evaluation harness wiring that writes the gate-2 evidence lands in Sprint 11.
- [ ] **Adversarial harness chain-payload writer (Sprint 12).** Symmetric to the eval harness — Gate 3 reads `payload["adversarial"]`; the adversarial red-team harness wiring that writes the gate-3 evidence lands in Sprint 12.
- [ ] **Tenant data-governance policy store.** The data-governance evidence panel (T3) accepts an optional `tenant_policy: TenantDataGovernancePolicy | None` parameter and computes the `DataGovernanceDiffFlag` tuple against it; no tenant-policy persistence store ships in 7B.3 (the panel returns `()` — "no tenant policy wired" — until one is supplied). The per-tenant policy store + its admin API is a 7B.4 / bank-overlay concern.
- [ ] **Real `TrustRootResolver` implementation.** Sprint-7B.3 ships only the `TrustRootResolver` Protocol + the fail-loud `KernelDefaultTrustRootResolver` scaffold; the real per-tenant trust-root resolver (bank overlays plug in against the Protocol) lands when the trust-root lifecycle work does. Until then the approve endpoint's Gate 1 fails closed as `signature_trust_root_not_configured` when no resolver is wired.
- [ ] **ADR-012 §114-122 fixture-AgentOS instance test harness** — deferred post-7B per plan §1280; AST-scan regressions at Sprint-7B.2 T11 pin `cli/test_harness.py` does NOT import the required modules until an explicit doctrine-track decision expands the scope.
- [ ] **`fail_open_exception` build-time manifest shape per ADR-017 amendment A4** — Sprint-7A2 carry-forward; reserved for Sprint-7B.4 or Sprint-7C2.
- [ ] **Realtime auto-attestation API + compliance helper emit path** — Sprint-7A carry-forward.
- [ ] **Pre-7B sprint rows' stale "READY-FOR-GATE awaiting" text in BUILD_PLAN §602-and-earlier.** T12 corrected §602's 7B.1 + 7B.2 rows but the identical stale text on the Sprint 2.5 / 3 / 4 / 5 / 6 / 7A / 7A2 status lines (those sprints are also merged) was deliberately left as a separate pre-existing concern. A future docs-hygiene pass should sweep them.

## Carryover

None. Every plan T2-T12 deliverable landed; T13 closes the sprint.

## Out of scope (Sprint-7B.3 intentionally did NOT ship)

- **UI event-stream endpoints (SSE + frontend-action POST + portable JSON schema)** — Sprint-7B.4 per ADR-020.
- **RBAC denial chain events** — structured-log only since 7B.2 T2; chain emission deferred so event-stream + chain row land together in 7B.4.
- **Eval / adversarial harness chain-payload writers** — gates 2-3 evidence; the harnesses that WRITE `payload["evaluation"]` / `payload["adversarial"]` land in Sprint 11 / Sprint 12. 7B.3 ships the composer's `evidence_not_attached` wire-protocol shape that is correct both pre-harness and post-harness.
- **Tenant data-governance policy store** — the data-governance panel computes the diff against a supplied `tenant_policy`; the per-tenant policy persistence store is a 7B.4 / bank-overlay concern.
- **Real `TrustRootResolver` implementation** — 7B.3 ships the Protocol + the fail-loud kernel scaffold only.
- **ADR-012 §114-122 fixture-AgentOS instance test harness** — deferred post-7B per plan §1280.
- **`fail_open_exception` build-time manifest shape per ADR-017 amendment A4** — Sprint-7A2 carry-forward.
- **Realtime auto-attestation API + compliance helper emit path** — Sprint-7A carry-forward.
- **Studio UI authoring** — ADR-008 Phase B; explicitly deferred per ADR-008 + ADR-021 reservation.

## Next sprint

**Sprint 7B.4 — UI event-stream endpoints + Sprint-7A/7A2 carry-forward**. See BUILD_PLAN.md §602 status row + the hand-off checklist above. Sprint-7B.3's 5-gate composer + the chain-row `reviewer_acknowledgement` / `override_event_id` / `pack.evidence_read.*` / `pack.approval_override` audit surfaces are the evidence foundation the 7B.4 UI event-stream renders; the composer's `evidence_not_attached` wire-protocol shape is the contract the Sprint 11/12 eval + adversarial harnesses fill in without re-composing the gate.
