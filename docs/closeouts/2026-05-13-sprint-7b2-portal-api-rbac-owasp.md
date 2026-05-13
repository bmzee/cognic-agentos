# Sprint 7B.2 — Portal API + RBAC + OWASP conformance integration (per ADR-012 + ADR-014 + ADR-008) — Closeout Note

**Date:** 2026-05-13
**Sprints closed:** 7B.2 (Portal RBAC primitives at `portal/rbac/*.py` with 6 closed-enum vocabularies + 4 FastAPI dependency factories + Postgres-backed lifecycle handlers at `portal/api/packs/*.py` covering author / review / operator / inspection surfaces × 18 endpoints + OWASP Agentic Top 10 conformance matrix at `packs/conformance/owasp_agentic.py` with applicability gate + yellow-precedence + chain-payload serialization adapter at `packs/conformance/runner.py` + non-gating evidence auto-run on submit transition + chain-row `payload["conformance"]` + dual-surface emission on reject (`payload["evidence_attachments"]` + structured log) + locked manifest-digest TOCTOU close + `agentos conformance` + `agentos test-harness` OWASP integration CLI extensions + critical-controls floor 43 → 55 with 8 modules promoted at T12 plus 4 incrementally promoted at T6 / T8 / T9 + AGENTS.md "Portal RBAC (Sprint 7B.2)" + "Authoring — Portal pack API (Sprint 7B.2)" + "Pack conformance evidence (Sprint 7B.2)" + "Conformance CLI surfaces (Sprint 7B.2, off-floor)" subsections + R45 CC-ADJ risk-tier vocabulary alignment with ADR-014's canonical 8-value `RiskTier` set + drift detector enforcing `cli → packs` architectural arrow).
**State:** **READY-FOR-GATE** on `feat/sprint-7b2-portal-api-rbac-owasp`. No push, no PR, no merge until the human authorises per the AGENTS.md per-action rule.
**Pre-T13 tip:** `ab0cd39 feat(sprint-7b2): T12 + R47 — AGENTS.md Portal RBAC subsection + critical-controls gate 47→55 (CRITICAL CONTROLS)`.
**Stack base:** `768d574` (Sprint 7B.1 tip on `feat/sprint-7b1-lifecycle-state-machine`) — Sprint 7B.2 is stacked on the Sprint 7B.1 closeout commit so the two sub-sprints push as separate stacked branches. **Ancestral baseline:** `fcfdbc2` on `main` — the merged Sprint-7A2 PR #21, reached via the 7B.1 stack layer (9 Sprint-7B.1 commits + 14 Sprint-7B.2 commits = 23 commits total between `fcfdbc2..HEAD` after T13 lands; `git rev-list --count fcfdbc2..HEAD` therefore reports the full two-layer ladder, not the 7B.2-only count).
**14 Sprint-7B.2 commits after T13 lands** atop the Sprint 7B.1 tip (`768d574`): T1 chore (plan-of-record), T2 (`portal/rbac/*` 6 primitives), T3 (DTOs + sub-router scaffolding + app-factory wiring), T4 (author surface + `cancel_draft` lifecycle extension + `update_draft` storage), chore R11-R22 (T5-doctrine-sweep plan refinements), T5 (review surface + `role_separation` closure-factory + `RejectDraftRequest` / `PackEvidenceResponse` DTOs + `list_by_status` tenant filter), T6 (operator surface + `RequireHumanActor` + `actor_type` chain-payload CC-ADJ + multi-from-state pairs + critical-controls floor 43→44), T7 (inspection surface 4 endpoints + `list_for_tenant` storage CC-ADJ extension), T8 (OWASP conformance check matrix + applicability matrix + yellow precedence + floor 44→46), T9 (auto-run conformance on submit + locked manifest-digest precondition + reject `evidence_attachments` dual-surface + floor 46→47), T10 (`agentos conformance` NOT-CC CLI extension + R44 OSError handling), T11 + R45 + R46 (`agentos test-harness` OWASP integration (non-gating per BUILD_PLAN §627) + CC-ADJ risk-tier vocab alignment 3→8 values + drift detector + docs polish), T12 + R47 (AGENTS.md Portal RBAC subsection + critical-controls gate 47→55 + module docstring narrative completeness), T13 closeout (this commit). `git rev-list --count 768d574..HEAD` reports the 7B.2-only ladder (13 pre-T13 / 14 post-T13).

**Sub-sprint allocation context.** Sprint 7B was pre-split per BUILD_PLAN.md §1142 schedule-risk fallback into 7B.1 + 7B.2 + 7B.3 + 7B.4 before T1. **Sprint 7B.2 is the Portal API endpoints + RBAC scopes + OWASP conformance integration sub-sprint only.** Reviewer evidence panels (data-governance / risk-tier / supply-chain / conformance-matrix), 5-gate approval composition with reviewer-acknowledgement field enforcement, UI event-stream endpoints (SSE + frontend-action POST + portable JSON schema), RBAC denial chain events, ADR-012 §114-122 fixture-AgentOS test harness, and `fail_open_exception` build-time manifest shape all defer to 7B.3 / 7B.4 per the hand-off checklist below.

## What ships in `feat/sprint-7b2-portal-api-rbac-owasp` after Sprint 7B.2

### Portal RBAC primitives (Sprint-7B.2 T2)

- **`src/cognic_agentos/portal/rbac/scopes.py`** (T2, CRITICAL CONTROLS — gate-promoted at T12) — closed-enum **12-value** `PackRBACScope` Literal at `scopes.py:41-54` (`pack.submit` / `pack.withdraw` / `pack.review.claim` / `pack.review.approve` / `pack.review.reject` / `pack.allow_list` / `pack.install` / `pack.disable` / `pack.revoke` / `pack.uninstall` / `pack.audit.read` / `pack.invocation.read`) — wire-protocol contract per ADR-012 §40 for every 403 RBAC denial in the portal pack API. 4 role-group frozensets (`AUTHOR_SCOPES` / `REVIEWER_SCOPES` / `OPERATOR_SCOPES` / `EXAMINER_SCOPES`) whose union equals `PACK_LIFECYCLE_SCOPES` — partition invariant pinned by `test_scopes.py::TestPartitionInvariant`.
- **`portal/rbac/actor.py`** (T2, CC) — frozen `Actor` Pydantic model + closed-enum 2-value `ActorType = Literal["human", "service"]` at `actor.py:49`. Identity boundary at portal admission seam. Production-grade fail-loud default — unconfigured actor providers raise `NotImplementedError` pointing at ADR-012 §40.
- **`portal/rbac/enforcement.py`** (T2, CC) — `RequireScope(scope)` FastAPI dependency factory + closed-enum **3-value** `RBACDenialReason = Literal["actor_unauthenticated", "scope_not_held", "actor_binder_not_configured"]` at `enforcement.py:53-57`. Three failure modes: no `Actor` resolved; `scope not in actor.scopes`; actor-binder missing (defensive 500).
- **`portal/rbac/tenant_isolation.py`** (T2 + T2 R1 P2 #1, CC) — `RequireTenantOwnership(pack_id_param)` factory + closed-enum **4-value** `TenantIsolationFailure = Literal["tenant_id_mismatch", "pack_not_found", "actor_tenant_id_missing", "pack_store_not_configured"]` at `tenant_isolation.py:67-72`. Cross-tenant 404 doctrine: pack belonging to tenant A is INVISIBLE to tenant B (404 not 403 so a probe cannot enumerate cross-tenant pack-IDs). Round 1 P2 #3 seeded 3 values; T2 R1 P2 #1 added `pack_store_not_configured` for symmetric missing-store defence.
- **`portal/rbac/human_actor.py`** (T2 + Round 1 P3 #8, CC) — `RequireHumanActor` dependency + closed-enum **1-value** `HumanActorDenialReason = Literal["actor_type_must_be_human"]` at `human_actor.py:48`. Single user-authorized site for the AGENTS.md "Per-tenant allow-list changes" Human-only-decisions doctrine — wired as a sub-dependency on the allow-list endpoint at `operator_routes.py`.
- **`portal/rbac/role_separation.py`** (T5 + Round 11 P2 #4, CC — gate-promoted at T12) — `RequireDifferentActorThanCreator(pack_id_param)` factory + closed-enum **1-value** `RoleSeparationFailure = Literal["actor_cannot_review_own_pack"]` at `role_separation.py:93`. ADR-012 §17 cross-role separation: the actor who created (drafted/submitted) a pack MUST NOT review it. Closure-factory pattern parameterises on `pack_id_param` to avoid sharing instance state across route registrations.

### Sub-router scaffolding + DTOs (Sprint-7B.2 T3)

- **`portal/api/packs/router.py`** (T3, NOT-CC — sub-router scaffolding; no decision logic) — parent `APIRouter(prefix="/api/v1/packs")` that composes the 4 surface sub-routers (author / review / operator / inspection) via `include_router`. R33 P2 route-shape split: T7 bare `GET /api/v1/packs` list endpoint registers DIRECTLY on the parent via `register_inspection_list(parent, *, store)` (path `""`) — FastAPI's `include_router` rejects an empty-prefix include of a sub-router with empty-path route.
- **`portal/api/packs/dto.py`** (T3 + T5 + T9, NOT-CC) — `PackBaseModel` frozen Pydantic shape + 7 wire DTOs: `PackResponse` / `PackDetailResponse` / `PackLifecycleEventResponse` / `ClaimResponse` / `RejectDraftRequest` / `PackEvidenceResponse` / `SubmitDraftRequest`. Owns closed-enum **7-value** `RejectionReason` at `dto.py:123-131` (`signature_invalid` / `evaluation_pass_rate_below_threshold` / `adversarial_corpus_pass_rate_below_threshold` / `owasp_conformance_red` / `data_governance_unfit` / `documentation_incomplete` / `other`) — anchored to ADR-012 §41 5-gate composition + 2 operational categories + free-form fallback.

### Author surface (Sprint-7B.2 T4 — wire-protocol-public)

- **`portal/api/packs/author_routes.py`** (T4, CRITICAL CONTROLS — gate-promoted at T12) — 4 endpoints behind `/api/v1/packs`: POST `/drafts` (`pack.submit`) + PUT `/drafts/{pack_id}` (`pack.submit`) + DELETE `/drafts/{pack_id}` (`pack.withdraw`) + POST `/drafts/{pack_id}/submit` (`pack.submit`). T9 Slice 2 R40 P2 #1 added route-owned closed-enum **1-value** `AuthorRequestRefusalReason = Literal["manifest_digest_mismatch"]` at `author_routes.py` for 400-status request-body refusals (distinct from `AuthorRefusalReason` 409s + `TenantIsolationFailure` 404/500s + `RBACDenialReason` 403/500s — **4-way refusal union**). Auto-runs OWASP conformance on submit via `run_owasp_conformance_for_chain_payload(body.manifest)` OUTSIDE the storage closure; threads `expected_manifest_digest=record.manifest_digest` into `store.transition()` to close the TOCTOU window per plan §1179-1181 + threads `payload_conformance=conformance_payload` to land the 4-key serialised dict on the chain row's `payload["conformance"]`. **Non-gating evidence per BUILD_PLAN §627** — `red` or `yellow` conformance verdict still produces a successful submit; the chain row carries the verdict for 7B.3 reviewer evidence panels + the 5-gate composition (the gate is 7B.3, not 7B.2).
- **`packs/lifecycle.py`** T4 CC-source extension — `_VALID_TRANSITIONS` grew from 10 transitions / 13 legal pairs to **11 transitions / 14 legal pairs** by adding `cancel_draft (draft → withdrawn)` per ADR-012 §59 + Round 1 P2 #2 + Round 2 P2 #6.
- **`packs/storage.py`** T4 CC-source extension — `update_draft()` at `:449` for in-place edit of `draft`-state packs via 4-field allow-list with atomic `UPDATE … WHERE state='draft'` precondition; `PackRecordRefusalReason` Literal grew **1 → 4 values** (added `pack_record_update_non_draft_state` + `pack_record_update_field_not_allowed` + `pack_record_update_field_invalid_shape` per Round 2 P2 #5 + Round 3 P2 #4 + Round 6 P3 #4).

### Review surface (Sprint-7B.2 T5 — wire-protocol-public)

- **`portal/api/packs/review_routes.py`** (T5, CRITICAL CONTROLS — gate-promoted at T12) — 5 endpoints: GET `/review-queue` (`pack.review.claim`; **moved off `/packs?status=submitted`** per Round 12 P2 #1 route-collision resolution) + POST `/{pack_id}/claim` + POST `/{pack_id}/approve` + POST `/{pack_id}/reject` + GET `/{pack_id}/evidence`. Cross-role separation enforced via `RequireDifferentActorThanCreator` on claim/approve/reject (the actor who drafted MUST NOT review). T9 Slice 3 added the **dual-surface emission contract** on reject: rejection_reason + reviewer_comments land on BOTH (a) `portal.packs.review.reject` structured log AND (b) chain row's `payload["evidence_attachments"]` — operational + examiner surfaces.
- **`packs/storage.py`** T5 CC-source extension — `list_by_status(state, limit, cursor, *, tenant_id=None)` at `:891` CC-ADJ per Round 11 P2 #1 + Round 14 P2 #1 backward-compatible signature. Pure read; no Doctrine Lock D touch; uses existing `ix_packs_tenant_state` composite index per migration L129.

### Operator surface (Sprint-7B.2 T6 — wire-protocol-public; Human-only-decisions enforcement boundary)

- **`portal/api/packs/operator_routes.py`** (T6, CRITICAL CONTROLS — gate-promoted at T6) — 5 endpoints: POST `/{pack_id}/allow-list` + POST `/{pack_id}/install` + POST `/{pack_id}/disable` + POST `/{pack_id}/revoke` + DELETE `/{pack_id}/install` (uninstall verb shares the install path with method=DELETE per plan endpoint table). **Allow-list endpoint is the single user-authorized site for the AGENTS.md "Per-tenant allow-list changes" Human-only-decisions doctrine** — wired with `RequireHumanActor()` sub-dependency. R24 Path B + B2 CC-ADJ: every handler threads `actor_type=actor.actor_type` into `transition()` so chain row's `payload["actor_type"]` records the actor type. Multi-from-state pairs pinned explicitly: revoke accepts `installed | disabled → revoked`; uninstall accepts `disabled | revoked → uninstalled`.
- **`packs/storage.py`** T6 CC-source extension — `transition()` got optional keyword-only `actor_type: str | None = None` kwarg at `:631`; when non-None it is persisted as top-level `payload["actor_type"]` key conditionally at `:853-854` (additive-only schema; storage stays a thin string passthrough — the `human | service` closed-enum lives at the rbac boundary).
- **Critical-controls floor 43 → 44** at T6 — `operator_routes.py` promoted because it owns the Human-only-decisions enforcement boundary + the R24 actor_type chain-payload provenance surface.

### Inspection surface (Sprint-7B.2 T7 — examiner-facing read endpoints)

- **`portal/api/packs/inspection_routes.py`** (T7, NOT-CC at task level; **Halt: YES — CC-ADJ propagation**) — 4 examiner-facing read endpoints: GET `/` (list scoped to actor.tenant_id; `pack.audit.read`) + GET `/{pack_id}` + GET `/{pack_id}/audit` + GET `/{pack_id}/invocations`. Off the durable gate per R32 doctrine — pure-read endpoints; no `store.transition()`; no chain-row writes; no Human-only-decisions enforcement boundary. CC risk for tenant-isolation boundary covered by `packs/storage.py:list_for_tenant` already on-gate from T7 Slice 1. R20 P2 #2 + R21 P2 #1: list endpoint runs explicit `actor_tenant_id_missing` preflight (no `{pack_id}` path-param → bypasses `RequireTenantOwnership`).
- **`packs/storage.py`** T7 CC-source extension — NEW `list_for_tenant(tenant_id: str, *, limit=50, cursor=None, state=None) -> list[PackRecord]` at `:933` CC-ADJ per Round 19 P2 #4 + Round 20 P2 #3. REQUIRED `tenant_id` filter (NOT optional — making it optional would re-open cross-tenant leak class). Module-private `_build_list_for_tenant_stmt(...)` at `:1073` is the SOLE query-construction path; production-path-exercising SQL-shape regression pins compiled SQL contains `packs.tenant_id = ` (always) + `packs.state = ` (when state non-None), proving production uses the `ix_packs_tenant_state` composite-index columns. T7 bumped to halt-YES per R20 P2 #1.

### OWASP conformance check matrix (Sprint-7B.2 T8)

- **`packs/conformance/checks.py`** (T8, CRITICAL CONTROLS — gate-promoted at T8) — wire-protocol-public shared types. Owns closed-enum **10-value** `OWASPCheckCategory` Literal at `:11-22` (`tool_misuse` / `goal_hijacking` / `identity_abuse` / `prompt_injected_skills` / `dependency_poisoning` / `secret_exfiltration` / `unsafe_filesystem` / `unsafe_network` / `supply_chain_integrity` / `skills_top_10`) + 3-value `ConformanceCheckStatus = Literal["pass", "fail", "not_applicable"]` (per-check, **never `yellow`**) + 3-value `ConformanceOverallStatus = Literal["green", "red", "yellow"]` (composite). Owns frozen `ConformanceCheckResult` + `ConformanceReport(overall_status, results, summary, errored_categories: tuple[...] = ())` — 4-field order wire-protocol-public per ADR-006.
- **`packs/conformance/owasp_agentic.py`** (T8, CC — gate-promoted at T8; **R45 CC-ADJ at T11**) — 10 deterministic manifest-shape check bodies + `_APPLICABILITY` 10x4 per-pack-kind matrix + `_CHECK_REGISTRY` ordered tuple (1:1 with Literal) + `run_owasp_conformance` dispatcher (applicability gate BEFORE invoking body + exception-wrapping + yellow-precedence overall-status derivation). **Overall-status precedence: yellow > red > green** — yellow takes precedence over red because a checker exception means the suite is incomplete and the red/green verdict is not trustworthy. Cross-set drift guard pins `OWASPCheckCategory` / `_CHECK_REGISTRY` / `_APPLICABILITY` carry the same 10-element category set in registry order.
- **Critical-controls floor 44 → 46** at T8 — `checks.py` + `owasp_agentic.py` promoted.

### Auto-run conformance + dual-surface emission + locked digest (Sprint-7B.2 T9)

- **`packs/conformance/runner.py`** (T9 Slice 2, CC — gate-promoted at T9 Slice 4) — chain-payload serialization adapter. Single public seam `run_owasp_conformance_for_chain_payload(manifest: dict[str, Any]) -> dict[str, Any]` is the WIRE-SHAPE boundary between T8 dispatcher + T9 chain row's `payload["conformance"]` key. Delegates to T8 then converts via `dataclasses.asdict` AND **explicitly converts `errored_categories` from tuple to list** — load-bearing: `dataclasses.asdict` preserves tuples but `core/canonical.canonical_bytes` REJECTS tuples in chain payloads. The 4-key top-level wire shape (`overall_status` / `results` / `summary` / `errored_categories`) is wire-protocol-public per ADR-006.
- **`packs/lifecycle.py`** T9 CC-source extension — `LifecycleRefusalReason` Literal grew **13 → 14 values** (added `lifecycle_transition_manifest_digest_changed_during_submit` — storage-only-emit; NOT emitted by `validate_transition`).
- **`packs/storage.py`** T9 CC-source extension — `transition()` got 3 new optional keyword-only kwargs: `payload_conformance: dict | None` + `expected_manifest_digest: bytes | None` + `evidence_attachments: dict | None`. Storage-only-emit digest cross-check at `:806-808` fires AFTER the row-locked SELECT + BEFORE `validate_transition` (race-condition fix closing TOCTOU window between handler preload + locked precondition). SELECT projection widened from `state, kind` to `state, kind, manifest_digest`.
- **`portal/api/packs/author_routes.py`** T9 Slice 2 — submit handler auto-runs conformance + threads expected_manifest_digest + R40 P2 #1 4-way refusal union (`AuthorRequestRefusalReason`).
- **`portal/api/packs/review_routes.py`** T9 Slice 3 — reject handler `evidence_attachments` chain-row write + dual-surface emission contract.
- **Critical-controls floor 46 → 47** at T9 Slice 4 — `runner.py` promoted.

### `agentos conformance` CLI extension (Sprint-7B.2 T10 — NOT-CC)

- **`src/cognic_agentos/cli/conformance.py`** (T10, NOT-CC per plan §1255-1273 + Sprint-7A T13 R4 P3 #5 doctrine — public command, NOT test-only path; off-floor because every gate it surfaces is enforced upstream by the on-floor matrix at `packs/conformance/owasp_agentic.py`) — thin `agentos conformance <pack_path> [--json]` wrapper. Pure-function seam `run_conformance(pack_path) -> ConformanceReport | ConformanceInvocationFailure` is side-effect-free + never raises (R44 P2 #1 extended `except` to catch `OSError` subclasses too — `PermissionError` / race-induced `FileNotFoundError` / etc collapse into the existing `conformance_manifest_unparseable` invocation failure). Closed-enum **3-value** `ConformanceInvocationError = Literal["conformance_pack_path_not_found", "conformance_manifest_not_found", "conformance_manifest_unparseable"]` distinct from verdict vocabulary. Exit codes: `0` green, `1` red OR yellow (yellow's incompleteness signal surfaces with same non-zero exit as red because verdict is not trustworthy when checker raised), `2` invocation error.

### `agentos test-harness` OWASP integration (Sprint-7B.2 T11 + R45 + R46 — CC-ADJ, non-gating)

- **`src/cognic_agentos/cli/test_harness.py`** (T11 extension, CC-ADJ to off-floor module per Sprint-7A T13 R4 P3 #5) — new `ConformanceSummary(green: bool, overall_status: Literal["green", "red", "yellow"], findings: list[str])` frozen dataclass + new `HarnessReport.conformance: ConformanceSummary | None = None` field (backward-compatible additive). `_build_conformance_summary(pack_path)` projects matrix verdict iterating BOTH red-path `status == "fail"` results AND `report.errored_categories` (R45 P2 #1 fix — pre-fix yellow verdict produced empty findings list + zero stderr warnings, losing incompleteness signal). **NON-GATING evidence per BUILD_PLAN §627** mirrors T9 submit-flow design: non-green verdict does NOT flip `HarnessReport.overall_status` to `"fail"`; surfaces as data in JSON + text summary + `::warning::` stderr annotations. **Deferred-full-harness boundary per plan §1280 + §1286**: AST-scan regressions pin that `cli/test_harness.py` does NOT import `cognic_agentos.core.audit` / `core.decision_history` / `core.guardrails` / `sandbox` / `subagent` — the modules the ADR-012 §114-122 fixture-AgentOS instance harness would require, deferred post-7B. Six AST scans (5 negative + 1 positive on `packs.conformance`).
- **`packs/conformance/owasp_agentic.py`** R45 CC-ADJ — replaced 3-value `_VALID_RISK_TIERS = frozenset({"low", "medium", "high"})` (T8 seed) with canonical ADR-014 **8-value** set (`read_only` / `internal_write` / `customer_data_read` / `customer_data_write` / `payment_action` / `regulator_communication` / `cross_tenant` / `high_risk_custom`) at `owasp_agentic.py:115-140`. Inlined; production module stays self-contained because architectural arrow runs `cli → packs` (reversing would create circular dependency through `cli/validators/risk_tier.py` which already consumes the matrix's wire types). Drift detector at `tests/unit/packs/conformance/test_owasp_risk_tier_vocab_drift.py` enforces lockstep at test time via 3 regressions.

### Critical-controls coverage gate extension (Sprint-7B.2 T12)

- **`tools/check_critical_coverage.py`** — Sprint-7B.2 promotions interleaved across the sprint. T6 added `operator_routes.py` (43 → 44). T8 added `checks.py` + `owasp_agentic.py` (44 → 46). T9 Slice 4 added `runner.py` (46 → 47). **T12 adds the remaining 8 (47 → 55)**: 6 RBAC primitives (`scopes.py` / `actor.py` / `enforcement.py` / `tenant_isolation.py` / `human_actor.py` / `role_separation.py`) + 2 portal pack API route modules (`author_routes.py` / `review_routes.py`). Plan §1298 claimed `43 → 55 (+12)` but 4 modules were promoted incrementally during T6/T8/T9 as each landed its own halt-before-commit CC review. R47 added Sprint-7B.2 T12 paragraph to the module-level historical doctrine narrative documenting the +8 promotion + off-floor rationale for inspection / router / CLI surfaces.

### AGENTS.md doctrine surface (Sprint-7B.2 T12)

- **`AGENTS.md`** — 3 NEW + 1 UPDATED subsections inserted between Sprint-7A2 hook quartet and Isolation boundaries. **NEW** `*Portal RBAC (Sprint 7B.2):*` with 6 bullets (scopes / actor / enforcement / tenant_isolation / human_actor / role_separation) — each pinning closed-enum value count + file:line citation + wire-protocol doctrine. **UPDATED** `packs/conformance/owasp_agentic.py` entry with R45 CC-ADJ paragraph documenting vocabulary alignment + inlined-canonical doctrine + architectural-arrow contract + 3-test drift detector. **NEW** `*Conformance CLI surfaces (Sprint 7B.2, off-floor):*` subsection documenting T10 (`cli/conformance.py`) + T11 (`cli/test_harness.py` ConformanceSummary tail-call) as authoring/dev-only public commands per Sprint-7A T13 R4 P3 #5 doctrine.

### Closeout doc + BUILD_PLAN §602 status flip (Sprint-7B.2 T13 — this commit)

- **`docs/closeouts/2026-05-13-sprint-7b2-portal-api-rbac-owasp.md`** *(NEW; this file)* — Sprint 7B.2 closeout note; mirrors Sprint-7B.1 closeout style + adds the Round 8 reviewer answer #5 final reference table with 7 sub-sections (a-g).
- **`docs/BUILD_PLAN.md` §602** — 7B.2 status row flipped from "reserved" to **CLOSED** with branch tip + critical-controls floor 43 → 55 + 8 CC modules promoted at T12 plus 4 incrementally during T6/T8/T9 (12 net).

## CI / production-grade gates

| Gate | Workflow | Trigger | Behaviour |
|---|---|---|---|
| Lint + types + tests | `python.yml` → `lint + test` | push / PR | unchanged — `ruff` + `ruff format --check` + `mypy` strict + `pytest -v` |
| Per-file critical-controls coverage gate | `python.yml` → `lint + test` | push / PR | `tools/check_critical_coverage.py` against `coverage.json` — fails CI if any of the **55** critical-controls modules drops below 95% line OR 90% branch (extended in Sprint-7B.2 T6/T8/T9/T12 by 12 net: T6 operator_routes; T8 checks + owasp_agentic; T9 runner; T12 6 RBAC + author_routes + review_routes) |
| MCP / A2A / image-size budget gates | `python.yml` | push / PR | unchanged — Sprint-5/6 floors stay |
| Live Postgres / Oracle integration | `python.yml` | push / PR | unchanged — Sprint-7B.1 canaries unchanged; Sprint-7B.2 ships no new integration tests (portal route handlers + conformance matrix exercise SQLite tmp-path substrate at unit scope) |

## Doctrine adherence

- **AGENTS.md per-edit halt-before-commit on critical-controls modules.** Every CC + CC-ADJ commit paused for explicit user authorization. T2 (`portal/rbac/*` 6 modules — halt-reviewed). T3 (DTOs + scaffolding — halt-reviewed). T4 (author surface + `cancel_draft` lifecycle CC-source extension — halt-reviewed). T5 (review surface + `role_separation` + `list_by_status` CC-source extension — halt-reviewed). T6 (operator surface + `RequireHumanActor` + `actor_type` chain-payload CC-ADJ — halt-reviewed across R23-R32). T7 (inspection surface + `list_for_tenant` storage CC-ADJ — halt-reviewed across R33-R35). T8 (OWASP matrix CC promotion — halt-reviewed). T9 (auto-run conformance + locked digest CC-source extension — halt-reviewed across R37-R43). T10 (NOT-CC, but R44 P2/P3 reviewer round closed pre-commit). T11 + R45 + R46 (CC-ADJ to `owasp_agentic.py` vocabulary alignment — halt-reviewed). T12 + R47 (AGENTS.md doctrine + coverage gate config — halt-reviewed). T13 (this closeout + BUILD_PLAN §602 — halts on doctrine documents).
- **AGENTS.md `core/canonical.py` per-edit stop rule.** Not touched in Sprint 7B.2.
- **Closed-enum vocabulary doctrine.** Sprint-7B.2 added **8 new closed-enum vocabularies** (`PackRBACScope` 12 / `RBACDenialReason` 3 / `TenantIsolationFailure` 4 / `ActorType` 2 / `HumanActorDenialReason` 1 / `RoleSeparationFailure` 1 / `RejectionReason` 7 / `OWASPCheckCategory` 10 / `ConformanceCheckStatus` 3 / `ConformanceOverallStatus` 3 / `AuthorRequestRefusalReason` 1 / `ConformanceInvocationError` 3) + extended 3 Sprint-7B.1 ones (TransitionName 10→11 / PackRecordRefusalReason 1→4 / LifecycleRefusalReason 13→14). Drift detectors live in per-module test files.
- **Production-grade rule.** Every Sprint-7B.2 module ships real integrations: portal handlers delegate to `PackRecordStore.transition()` (Postgres-backed atomic primitive) rather than mock data; OWASP matrix runs deterministic manifest-shape checks rather than synthetic results; CLI surfaces delegate to the on-floor matrix rather than carrying their own decision logic. `cli/conformance.run_conformance()` + `cli/test_harness._read_full_manifest_dict()` use real `tomllib` parsing + real filesystem reads, no in-process mocks.
- **Doctrine Lock C (lifecycle pure-functional + closed-enum consumer-API wire-protocol).** Preserved across all T4/T6/T7/T9 CC-source extensions. `packs/lifecycle.py` stays I/O-free; the 14th `LifecycleRefusalReason` value (`lifecycle_transition_manifest_digest_changed_during_submit`) is **storage-only-emit** — NOT emitted by `validate_transition` because the validator has no access to the persisted digest column.
- **Doctrine Lock D (atomic chain-insert + state-cache UPDATE + chain-head UPDATE single transaction).** Preserved. T9 added 3 new optional kwargs to `transition()` but the atomic envelope `append_with_precondition` stays single-transaction / single-commit-point. The SELECT projection widening (`state, kind` → `state, kind, manifest_digest`) at T9 Slice 1 is a wire-protocol-affecting CC change to the chain row's read path; integration tests still pin row-lock serialisation on live PG/Oracle.
- **Doctrine F gate-counting rule.** Critical-controls floor extension at T6 / T8 / T9 / T12 adds 12 modules to the 95/90 floor. Modules deliberately OFF the gate carry documented rationale: `inspection_routes.py` (R32 doctrine — pure-read; tenant-isolation CC risk covered by `list_for_tenant` on-gate); `router.py` (scaffolding-only); `cli/conformance.py` + `cli/test_harness.py` (Sprint-7A T13 R4 P3 #5 — authoring/dev-only public commands).
- **Architectural arrow `cli → packs` (R45 — NEW).** OWASP matrix's `_VALID_RISK_TIERS` inlined at `packs/conformance/owasp_agentic.py:115-140` rather than imported from `cli/_governance_vocab.RiskTier` — reversing the arrow would create circular dependency through `cli/validators/risk_tier.py`. Drift detector at test layer enforces lockstep without coupling production code.

## New doctrines established Sprint-7B.2

- **Non-gating evidence per BUILD_PLAN §627.** Both T9 (submit-flow chain-payload write) and T11 (test-harness tail-call) treat OWASP conformance as wire-protocol-public evidence written to the chain row + stderr warnings, NOT as a gate that blocks the transition. The Sprint-7B.3 5-gate composer owns the gating decision. Pinned by `test_conformance_red_does_not_flip_overall_status_to_fail` at T11.
- **Yellow signal preservation (R45 P2 #1).** All non-green verdicts (red AND yellow) surface diagnostic stderr warnings, not just `fail`-status. Pre-R45 the projection filtered on `status == "fail"` only — a yellow checker-exception verdict produced empty findings + zero stderr warnings. R45 P2 #1 extended the projection to iterate `errored_categories`. Pinned by `test_yellow_conformance_surfaces_findings_and_warning`.
- **Architectural arrow + inline-canonical pattern (R45 P2 #2).** When two production modules share a closed-enum vocabulary across a layered boundary and the architectural arrow forbids the reverse import, the lower-layer module inlines the canonical values + a test-layer drift detector imports BOTH surfaces to enforce lockstep. Production code stays self-contained; coupling lives only at the test seam.
- **4-way refusal union (R40 P2 #1).** Route handlers can carry multiple closed-enum refusal vocabularies for different HTTP status classes — T9's `author_routes.py` owns 4 disjoint enums: `AuthorRefusalReason` (409s) + `AuthorRequestRefusalReason` (400s) + `TenantIsolationFailure` (404/500s) + `RBACDenialReason` (403/500s). Build-time drift detector verifies the route-owned vocab is disjoint from all 3 upstream enums.
- **Dual-surface emission contract (T9 Slice 3).** Categorised reason + comments on reject lands on BOTH structured log (operations surface; load-bearing for live observability) AND chain row's `payload["evidence_attachments"]` (examiner surface; authoritative for evidence-pack export per ADR-006). A future change dropping either surface fails the dual-surface regression test.
- **Storage-only-emit refusal pattern (T9 Slice 1).** When a refusal can ONLY fire from inside the row-locked precondition closure (because the pure-functional validator has no access to the persisted column), the closed-enum reason is added to `LifecycleRefusalReason` but storage's `_precondition` is the SOLE emit site. Documented in `transition()` Raises docstring + `lifecycle.py` value-list comment.
- **Cite-from-source-at-doc-write-time depth doctrine (extended across R37-R47).** ~5 reviewer rounds catching cite-from-memory paraphrase masks across doctrine documents. T12 self-caught one violation (`RBACDenialReason` value names) before reviewer; remaining 5 closed-enum value sets verified at file:line in same compose pass. Saved at `feedback_verify_code_citations_at_doc_write.md`.

## Test + coverage state

- **Suite size:** **5060 passed / 48 skipped / 565s** at T11 + R45 + R46 commit baseline; T12 + R47 + T13 are doctrine + comment-only, no executable tests added. Delta from Sprint-7B.1 baseline (4370 / 46): **+690 tests / +2 skipped** — well above plan §1368 projection of `~4490-4510` due to extensive reviewer-round regression coverage (R37-R47).
- **Per-file critical-controls coverage gate (55 modules at 95/90):** all 43 pre-Sprint-7B.2 modules unchanged + 12 Sprint-7B.2 promotions:

| Module | Sprint owner | Line% | Branch% | Status |
|---|---|---|---|---|
| (43 modules unchanged from `2026-05-11-sprint-7b1-lifecycle-state-machine.md`) | 2 – 7B.1 | ≥95 | ≥90 | PASS |
| `portal/api/packs/operator_routes.py` | 7B.2 T6 | 100 | 100 | PASS |
| `packs/conformance/checks.py` | 7B.2 T8 | 100 | 100 | PASS |
| `packs/conformance/owasp_agentic.py` | 7B.2 T8 + R45 | 99.24 | 97.98 | PASS |
| `packs/conformance/runner.py` | 7B.2 T9 Slice 4 | 100 | 100 | PASS |
| `portal/rbac/scopes.py` | 7B.2 T12 | 100 | 100 | PASS |
| `portal/rbac/actor.py` | 7B.2 T12 | 100 | 100 | PASS |
| `portal/rbac/enforcement.py` | 7B.2 T12 | 100 | 100 | PASS |
| `portal/rbac/tenant_isolation.py` | 7B.2 T12 | 100 | 100 | PASS |
| `portal/rbac/human_actor.py` | 7B.2 T12 | 100 | 100 | PASS |
| `portal/rbac/role_separation.py` | 7B.2 T12 | 100 | 100 | PASS |
| `portal/api/packs/author_routes.py` | 7B.2 T12 | 100 | 100 | PASS |
| `portal/api/packs/review_routes.py` | 7B.2 T12 | 100 | 100 | PASS |

## ADR validation

| ADR | Title | Sprint-7B.2 relevance | Status |
|---|---|---|---|
| ADR-006 | ISO 42001 control mapping | Every lifecycle transition + conformance auto-run emits hash-chained audit row tagged with canonical ISO 42001 control tuples; wire-protocol-public 4-key `payload["conformance"]` + dual-surface `payload["evidence_attachments"]` per ADR-006 | ✅ |
| ADR-008 | Authoring platform (SDK + CLI) | `agentos conformance` (T10) + `agentos test-harness` OWASP integration (T11) extend the Sprint-7A SDK + CLI authoring set | ✅ |
| ADR-012 | Bank pack lifecycle | Portal API surfaces × 18 endpoints + 12 RBAC scopes + OWASP conformance integration auto-run on submit + dual-surface reject emission; Reviewer evidence panels + 5-gate approval composition deferred to 7B.3 | ✅ (Portal API + RBAC + OWASP conformance scope only) |
| ADR-014 | Risk-tier vocabulary | R45 CC-ADJ aligned OWASP matrix's `_VALID_RISK_TIERS` with ADR-014's canonical 8-value `RiskTier` Literal; drift detector at test layer enforces lockstep | ✅ |
| ADR-017 | Data governance contracts | T5 / T6 / T9 handlers carry the rejection_reason + reviewer_comments evidence on chain rows; SDK conformance suite probes data-governance contract shape via `check_secret_exfiltration` (egress_allow_list + DLP hook requirement for sensitive classes) | ✅ |

## Final reference table (Round 8 reviewer answer #5 — navigation map)

Consolidates the R-round patch surface into a single navigation map. Future implementers reading this closeout can navigate the ~1500-line plan via this section without re-reading every patch-log round.

### (a) New closed-enum vocabularies introduced Sprint-7B.2

| Literal | Values | Module |
|---|---|---|
| `PackRBACScope` | 12 | `portal/rbac/scopes.py:41-54` |
| `RBACDenialReason` | 3 (`actor_unauthenticated` / `scope_not_held` / `actor_binder_not_configured`) | `portal/rbac/enforcement.py:53-57` |
| `TenantIsolationFailure` | 4 | `portal/rbac/tenant_isolation.py:67-72` |
| `ActorType` | 2 (`human` / `service`) | `portal/rbac/actor.py:49` |
| `HumanActorDenialReason` | 1 (`actor_type_must_be_human`) | `portal/rbac/human_actor.py:48` |
| `RoleSeparationFailure` | 1 (`actor_cannot_review_own_pack`) | `portal/rbac/role_separation.py:93` |
| `RejectionReason` | 7 (ADR-012 §41 5-gate composition + 2 operational + free-form) | `portal/api/packs/dto.py:123-131` |
| `OWASPCheckCategory` | 10 | `packs/conformance/checks.py:11-22` |
| `ConformanceCheckStatus` | 3 (`pass` / `fail` / `not_applicable`; **never `yellow`**) | `packs/conformance/checks.py` |
| `ConformanceOverallStatus` | 3 (`green` / `red` / `yellow`) | `packs/conformance/checks.py` |
| `AuthorRequestRefusalReason` | 1 (`manifest_digest_mismatch`) | `portal/api/packs/author_routes.py` |
| `ConformanceInvocationError` | 3 (`conformance_pack_path_not_found` / `conformance_manifest_not_found` / `conformance_manifest_unparseable`) | `cli/conformance.py` |

### (b) Cross-sprint 7B.1 closed-enum extensions

| Literal | Pre → Post | Owner task | Sweep sites |
|---|---|---|---|
| `TransitionName` | 10 → 11 | T4 (added `cancel_draft`) | 15 sites / 6 files |
| `PackRecordRefusalReason` | 1 → 4 | T4 (added 3 `update_draft` reasons) | 6 sites / 3 files |
| `LifecycleRefusalReason` | 13 → 14 | T9 (added storage-only-emit digest reason) | 8 sites / 5 files |

### (c) Doctrine sweep paths exclusion set

Standard 3-path exclusion used in every closed-enum drift sweep: `.venv/` + `node_modules/` + `dist/` (excluded via the `ag` / `rg` defaults at sprint runtime; not hard-coded into individual tests).

### (d) New CC modules promoted Sprint-7B.2 (12 net)

| Module | Owner task | Rationale |
|---|---|---|
| `portal/api/packs/operator_routes.py` | T6 | Human-only-decisions enforcement boundary + R24 actor_type chain-payload provenance |
| `packs/conformance/checks.py` | T8 | Wire-protocol-public closed-enum `OWASPCheckCategory` + frozen `ConformanceReport` |
| `packs/conformance/owasp_agentic.py` | T8 (+ R45 CC-ADJ) | 10 deterministic check bodies + applicability matrix + yellow-precedence runner |
| `packs/conformance/runner.py` | T9 Slice 4 | Chain-payload serialization (load-bearing tuple→list conversion + 4-key wire shape) |
| `portal/rbac/scopes.py` | T12 | 12-value `PackRBACScope` + 4 role-group partition invariant |
| `portal/rbac/actor.py` | T12 | Identity boundary + 2-value `ActorType` + production-grade fail-loud default |
| `portal/rbac/enforcement.py` | T12 | `RequireScope` factory + 3-value `RBACDenialReason` |
| `portal/rbac/tenant_isolation.py` | T12 | Cross-tenant 404 doctrine + 4-value `TenantIsolationFailure` |
| `portal/rbac/human_actor.py` | T12 | Human-only-decisions sub-dependency |
| `portal/rbac/role_separation.py` | T12 | ADR-012 §17 cross-role separation |
| `portal/api/packs/author_routes.py` | T12 | Wire-protocol-public author surface + 4-way refusal union |
| `portal/api/packs/review_routes.py` | T12 | Wire-protocol-public review surface + dual-surface emission |

### (e) Cross-sprint CC source touches without re-promotion

| Module | Sprint-7B.2 touch | Doctrine Lock preserved |
|---|---|---|
| `packs/lifecycle.py` | T4 `cancel_draft` + T9 LifecycleRefusalReason 13→14 (storage-only-emit) | Lock C |
| `packs/storage.py` | T4 `update_draft` + T5 `list_by_status` (CC-ADJ; pure read) + T6 `actor_type` kwarg + T7 NEW `list_for_tenant` (CC-ADJ; pure read) + T9 3 new kwargs (`payload_conformance` + `expected_manifest_digest` + `evidence_attachments`) + SELECT projection widening | Lock D |
| `packs/conformance/owasp_agentic.py` | R45 CC-ADJ vocabulary alignment (`_VALID_RISK_TIERS` 3 → 8 values, inlined; architectural arrow `cli → packs` preserved) | — |
| `cli/test_harness.py` | T11 OWASP tail-call (off-floor; non-gating evidence per BUILD_PLAN §627) | Sprint-7A T13 R4 P3 #5 off-floor doctrine |
| `portal/api/packs/author_routes.py` | T9 submit handler extension (cheap pre-check + auto-run conformance + locked-digest precondition; reuses T4 minter) | — |
| `portal/api/packs/review_routes.py` | T9 reject handler `evidence_attachments` chain-row write + dual-surface emission | — |

### (f) Deferred-to-7B.3/7B.4 work

| Item | Owner sprint | Reason |
|---|---|---|
| 4 Reviewer evidence panels (data-governance / risk-tier / supply-chain / conformance-matrix) | 7B.3 | BUILD_PLAN §630-634; require reviewer-acknowledgement field + tenant-policy diff |
| 5-gate approval composition wired into approve endpoint + override path | 7B.3 | ADR-012 §41; T9 wrote the chain-payload `conformance` evidence but did NOT compose the gate |
| UI event-stream endpoints (SSE + frontend-action POST + portable JSON schema) | 7B.4 | ADR-020; BUILD_PLAN §640-645 |
| RBAC denial chain events | 7B.4 | Currently structured-log only; chain emission deferred so event-stream + chain row land together |
| ADR-012 §114-122 fixture-AgentOS instance test harness | post-7B | Each of fixture-mode AgentOS factory + fixture guardrails/audit/decision-history/sandbox wiring + per-pack fixture-loading contract is a sprint of work on its own |
| `fail_open_exception` build-time manifest shape per ADR-017 amendment A4 | Sprint-7C2 or Sprint-7B.4 | Sprint-7A2 carry-forward |
| Realtime auto-attestation API + compliance helper emit path | 7B.4 | Sprint-7A carry-forward |
| Studio UI authoring | ADR-008 Phase B | Explicitly deferred per ADR-008 + ADR-021 reservation |

### (g) Route-table collision resolution (Round 12 P2 #1 + Round 13 P2 #1 + Round 15 P2 #2)

T5 reviewer queue moved off `GET /api/v1/packs?status=submitted` (which would have collided with T7's `GET /api/v1/packs`) to `GET /api/v1/packs/review-queue` (distinct path; gated by `pack.review.claim`). T7 owns `GET /api/v1/packs` (gated by `pack.audit.read`). ADR-012 §62 sketch (`?status=submitted` query param) is impl-deviation noted in plan + this closeout. **Round 13 P2 #1 split:** T5 owns narrow proof `test_review_routes_does_not_register_inspection_list_path` (runs at T5-time before `inspection_routes.py` exists); the full both-routes-reachable regression `test_review_queue_and_inspection_list_both_reachable` ships at T7 once both sub-routers exist. **Round 15 P2 #2 mount-prefix correction:** narrow proof mounts `build_review_routes(store=…)` under a test parent `APIRouter(prefix="/api/v1/packs")` on a fresh `FastAPI()` app + walks `app.routes` asserting COMPILED full path `/api/v1/packs/review-queue` exists AND no route compiles to `/api/v1/packs`.

## Sprint 7B.3 hand-off checklist

Sprint 7B.3 picks up the **Reviewer evidence panels + 5-gate approval composition** layer of ADR-012 + BUILD_PLAN.md §602.

- [ ] **`packs/evidence/data_governance.py`** — `GET /api/v1/packs/{id}/evidence/data-governance` returns manifest's `[data_governance]` contract (data classes, purpose, retention, egress allow-list, DLP hooks, consent requirement) plus diff against tenant policy; reviewer rejects if contract violates policy.
- [ ] **`packs/evidence/risk_tier.py`** — `GET /api/v1/packs/{id}/evidence/risk-tier` returns declared risk tier (8-value ADR-014 vocabulary), approval flow it triggers per ADR-014 (single approval / 4-eyes / cross-tenant gate), and reviewer-acknowledgement field.
- [ ] **`packs/evidence/supply_chain.py`** — `GET /api/v1/packs/{id}/evidence/supply-chain` returns SLSA level, provenance verification result, SBOM contents, vuln-scan summary, license-audit result, Sigstore bundle pointer (with retention expiry date) per ADR-016.
- [ ] **`packs/evidence/conformance_matrix.py`** — `GET /api/v1/packs/{id}/evidence/conformance` reads chain row's `payload["conformance"]` (T9 wire shape; 4 keys) + renders side-by-side with `MCP-CONFORMANCE.md` / `A2A-CONFORMANCE.md` matrices. Pre-T9 / historical submit rows show `None` gracefully (NOT 500).
- [ ] **5-gate approval composition in approve endpoint per ADR-012 §41.** Compose: gate 1 (signature_invalid via supply-chain evidence) + gate 2 (eval pass-rate via evaluation evidence) + gate 3 (adversarial corpus pass-rate via adversarial evidence) + gate 4 (OWASP conformance green via T9 chain row `payload["conformance"].overall_status`) + gate 5 (reviewer-acknowledgement field set on all 4 evidence panels). T9 produced the conformance evidence but did NOT compose the gate — that's 7B.3's owning concern.
- [ ] **Reviewer-acknowledgement field enforcement.** Server-side enforcement (not just UI) that approve refuses if any of the 4 reviewer-acknowledgement fields is unset. Refusal closed-enum extends `AuthorRefusalReason` or owns its own vocabulary per 7B.3 design.
- [ ] **Override path for 5-gate approval.** Per ADR-012 §41; gate override emits its own chain event with override-justification field captured + the closed-enum override reason (cosigner identity + 4-eyes confirmation).
- [ ] **RBAC denial chain events.** Currently structured-log only at T2; chain emission deferred so event-stream + chain row land together with the SSE endpoints in 7B.4.

## Sprint 7B.4 hand-off (carry-forward; reserved for owning sub-sprint)

- **UI event-stream endpoints per ADR-020 (BUILD_PLAN §640-645).** SSE endpoints (`GET /api/v1/ui/runs/{run_id}/events`, `GET /api/v1/ui/tenants/{tenant_id}/events`, `GET /api/v1/ui/events/since/{event_id}`); frontend-action POST `/api/v1/ui/actions` (`approve` / `deny` / `cancel_run` / `interrupt` / `resume` / `submit_elicitation` with MCP elicitation rules enforcement); RBAC scopes `ui.run_stream` + `ui.tenant_stream` + `ui.action.<class>`; per-tenant connection caps + idle-timeout reaping; portable JSON schema at `/.well-known/cognic-ui-events.json`.
- **ADR-012 §114-122 fixture-AgentOS instance test harness** — deferred post-7B per plan §1280; AST-scan regressions at T11 pin `cli/test_harness.py` does NOT import the required modules until an explicit doctrine-track decision expands the scope.
- **`fail_open_exception` build-time manifest shape per ADR-017 amendment A4** — Sprint-7A2 carry-forward.
- **Realtime auto-attestation API + compliance helper emit path** — Sprint-7A carry-forward.

## Carryover

None. Every plan §1062-1252 deliverable for T2-T12 landed. T13 closes the sprint.

## Out of scope (Sprint-7B.2 intentionally did NOT ship)

- **4 Reviewer evidence panels + 5-gate approval composition + reviewer-acknowledgement field enforcement** — Sprint-7B.3 per the hand-off checklist above.
- **UI event-stream endpoints (SSE + frontend-action POST + portable JSON schema)** — Sprint-7B.4 per ADR-020.
- **ADR-012 §114-122 fixture-AgentOS instance test harness** — deferred post-7B per plan §1280 (each of fixture-mode AgentOS factory + fixture wiring + per-pack loading contract is a sprint of work on its own).
- **RBAC denial chain events** — currently structured-log only; chain emission deferred so event-stream + chain row land together in 7B.4.
- **`fail_open_exception` build-time manifest shape per ADR-017 amendment A4** — Sprint-7A2 carry-forward; reserved for Sprint-7B.4 or Sprint-7C2.
- **Realtime auto-attestation API + compliance helper emit path** — Sprint-7A carry-forward; reserved for Sprint-7B.4.
- **Studio UI authoring** — ADR-008 Phase B; explicitly deferred per ADR-008 + ADR-021 reservation.

## Next sprint

**Sprint 7B.3 — Reviewer evidence panels + 5-gate approval composition + reviewer-acknowledgement field enforcement**. See BUILD_PLAN.md §602 status row + the hand-off checklist above. Sprint-7B.2's chain-payload `conformance` evidence + dual-surface `evidence_attachments` write are the foundation Sprint-7B.3 composes the 5-gate decision on top of; the OWASP matrix verdict + the rejection_reason categorisation are both available at the chain-row read path without re-running any expensive checks.
