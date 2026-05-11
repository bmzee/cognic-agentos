# Sprint 7B.2 — Portal API + RBAC + OWASP Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every CRITICAL CONTROLS task uses **halt-before-commit** per `feedback_strict_review_off_gate.md`.

**Goal:** Ship the portal API surface for bank pack lifecycle (ADR-012) atop Sprint-7B.1's lifecycle state machine + storage. 4 surfaces × ~18 endpoints; **12 RBAC scopes** (BUILD_PLAN §622-625 verbatim — the Sprint-7B.1 closeout L119 cite-from-memory typo "14" is fixed at T13 closeout via doctrine cross-reference, not closeout amendment per AGENTS.md immutability) wired through a new `portal/rbac/` subsystem; OWASP Agentic Top 10 + Skills Top 10 conformance suite with auto-run on `submit`; `agentos conformance` + `agentos test-harness` CLI extensions.

**Architecture:** Stack 7B.2 atop local 7B.1 tip (`768d574`). FastAPI `APIRouter` pattern matches `portal/api/system_routes.py:build_system_router`. RBAC enforced via a FastAPI dependency (`RequireScope("pack.…")`) that resolves the request actor via a pluggable `ActorBinder` protocol (kernel ships the protocol + `NotImplementedError` default; bank overlays / test fixtures plug in real / fixture binders — production-grade rule). Pack state transitions delegate to `PackRecordStore.transition()` from 7B.1; **one narrow CC-ADJ lifecycle extension at T4 adds the 11th transition `cancel_draft` mapping `draft → withdrawn` per ADR-012 §59** (extending `packs/lifecycle.py` + lockstep in 3 sibling maps + the `TransitionName` Literal and a doctrine-citation sweep per Round 2 P2 #6). Conformance runs synchronously on `submit` POST; the result attaches as a new `payload.conformance` top-level key on the submit transition's chain row (a payload-schema extension — NOT a canonical-form-algorithm change; the canonical-form algorithm at `core/canonical.py` is unchanged); the lifecycle transition proceeds regardless (per BUILD_PLAN §627 + ADR-012 §41 — the OWASP gate sits at the `approve` boundary, enforced by Sprint 7B.3's 5-gate composition; 7B.2 only produces the evidence). Audit emission stays in `packs/storage.py` (`pack.lifecycle.<target_state>` namespace from 7B.1 T3). **Tenant isolation is route-level (not scope-level)** via a separate `portal/rbac/tenant_isolation.py` guard per Round 1 P2 #3; every endpoint that takes a `{id}` path param resolves the pack and verifies `actor.tenant_id == pack.tenant_id` before any state read or transition. Cross-tenant access returns 404 (info-leak prevention).

**Tech Stack:** FastAPI + Pydantic (existing); `pyjwt` + `cryptography` already in the bundled-adapters extras (Sprint 4 trust-gate dependency reused for the kernel-default JWKS verifier protocol — but kernel ships only the protocol; no JWKS implementation in 7B.2 itself).

---

## Doctrine map

| ADR / doc | Section | What 7B.2 implements |
|---|---|---|
| ADR-012 | §35-48 (state-transition matrix) | RBAC scope per transition wired through `RequireScope` |
| ADR-012 | §54-79 (endpoint surface) | 4 routers × 18 endpoints |
| ADR-012 | §107-110 (override scope) | `pack.override.approval_gate` is **deferred to 7B.3** — ships alongside the 5-gate composer |
| ADR-012 | §114-122 (local governance test harness) | `agentos test-harness` CLI extension |
| ADR-012 | §41 (approval gate composition) | **NOT implemented in 7B.2** — only OWASP conformance EVIDENCE attaches at submit. 5-gate composition gate enforcement lands at Sprint 7B.3. |
| ADR-008 | Phase A SDK + CLI | `agentos conformance` + `agentos test-harness` CLI extensions; mirrors `agentos validate` / `agentos sign` / `agentos verify` patterns |
| ADR-006 | hash-chain ISO 42001 control mapping | `iso_controls_for(transition)` from 7B.1 already in place; 7B.2 reuses unchanged |
| ADR-015 | policy-as-code | RBAC scope check is mechanical literal-set membership; full Rego policy evaluation is **NOT in scope** for 7B.2 (deferred — RBAC scope ≠ policy decision in this sprint) |
| BUILD_PLAN | §622-625 | The **12** scopes verbatim (NOT 14 — see Round 0.5 patch log for the cite-from-memory closeout typo) |
| BUILD_PLAN | §627-630 | OWASP suite + auto-run on submit + `agentos conformance` CLI |
| Closeout 7B.1 | §"hand-off checklist" L114-123 | 6-bullet handoff — fully covered by T2-T11. The L119 line says "14 scopes" but enumerates 12; T13 closeout cites this as a doctrine cross-reference (no closeout amendment per AGENTS.md "don't rewrite history") |
| AGENTS.md | "RBAC (`portal/rbac/`)" stop rule | All new `portal/rbac/*` modules are halt-before-commit CC |

## Out of scope for 7B.2 (deferred to 7B.3 / 7B.4 / later)

- **Reviewer evidence panels** (`packs/evidence/data_governance.py`, `packs/evidence/risk_tier.py`, `packs/evidence/supply_chain.py`, `packs/evidence/conformance_matrix.py`) — Sprint 7B.3.
- **5-gate approval composition** wired into the `approve` endpoint (cosign + allow-list + eval + adversarial + OWASP) — Sprint 7B.3. **7B.2 ships the `approve` endpoint as a fail-loud `HTTPException(503)` scaffold per the production-grade scaffold rule** (Round 1 P2 #1 patch + Round 10 P3 #2 wording fix — the API surface raises `HTTPException`, NOT `NotImplementedError`; the latter is reserved for kernel-default `ActorBinder` stubs per Round 3 P2 #2). The endpoint is mounted, RBAC enforces `pack.review.approve` scope, but invocation raises `HTTPException(503, detail={"reason": "approve_gate_composer_not_wired", "next_sprint": "7B.3", "adr": "ADR-012 §41"})`. **No green-path test for approve in 7B.2** — only the fail-loud-503 contract is pinned. State machine `under_review → approved` transition path is exercised at the storage layer in 7B.1 tests already.
- **UI event-stream endpoints** (SSE + frontend-action POST + `/.well-known/cognic-ui-events.json`) — Sprint 7B.4 per ADR-020.
- **`fail_open_exception` build-time manifest shape** per ADR-017 amendment A4 — Sprint 7B.4 / Sprint 7C2 carry-forward.
- **Realtime auto-attestation API + compliance helper emit path** — Sprint 7B.4 carry-forward from Sprint 7A.
- **Hash-chained RBAC denial events** (`portal.rbac.denied` chain emission per Round 2 P2 #4 narrowing + Round 5 P3 #5 placeholder-sprint tag) — Sprint 7B.4 alongside the ADR-020 UI event-taxonomy extension; the denial-event schema fits the `policy.*` event family slot already reserved in `protocol/ui_events.py`. 7B.2 ships structured-log emission at the application-logging layer only.
- **Real OIDC / SAML / mTLS auth backend** — bank-overlay territory; kernel ships only the `ActorBinder` protocol with `NotImplementedError` default per production-grade rule.
- **Override path** (`pack.override.approval_gate` scope per ADR-012 §107-110) — covered by 7B.3's gate composer; 7B.2 only declares the 12 happy-path scopes.
- **ADR-012 §114-122 fixture-only AgentOS test harness** (loads packs into a fixture-only AgentOS instance + runs against fixture-based guardrails / audit chain / decision history / sandbox policy) — **DEFERRED post-7B**. The existing `cli/test_harness.py` (Sprint-7A T13 hybrid runner; 1321 lines) is NOT a fixture-AgentOS harness; it's a manifest-parse + validate-pipeline + per-kind SDK-seam dry-run runner. T11 in 7B.2 re-scoped to EXTEND the existing `cli/test_harness.py` with OWASP conformance integration ONLY — the full ADR-012 §114-122 harness ships in a separate later sprint where the fixture-AgentOS instance contract is properly designed (round 1 P2 #6).

## Critical-controls forecast

Per AGENTS.md "Stop rules" + "Critical-controls rule":

| New CC module | Rationale |
|---|---|
| `portal/rbac/scopes.py` | AGENTS.md "RBAC (`portal/rbac/`)" stop rule; closed-enum scope literal IS the wire-protocol contract for RBAC denials |
| `portal/rbac/actor.py` | `ActorBinder` protocol + `Actor` dataclass (with `actor_type` field per Round 1 P3 #8) + `ActorBinderUnauthenticated` typed exception (per Round 3 P2 #2); identity boundary; production-grade scaffold-with-fail-loud-default per ADR-008 |
| `portal/rbac/enforcement.py` | `RequireScope` FastAPI dependency; insufficient-scope refusal taxonomy + 403 emission + catches `ActorBinderUnauthenticated` and translates to closed-enum `actor_unauthenticated` (Round 3 P2 #2). **NO audit-chain emission in 7B.2 per Round 2 P2 #4 narrowing** — denials emit structured-log records only at the application-logging layer; **hash-chain denial events deferred to Sprint 7B.4 per Round 5 P3 #5** alongside the realtime auto-attestation API + ADR-020 UI event-taxonomy extension carry-forward (the denial-event schema lives in the same event-taxonomy design space as `ui_events.py`'s `policy.*` event family) |
| `portal/rbac/tenant_isolation.py` | **NEW per Round 1 P2 #3; bumped to 4-value at T2 R1 P2 #1** — route-level tenant guard. `RequireTenantOwnership(pack_id)` dependency that loads `PackRecord.tenant_id` and verifies actor.tenant_id match. Mismatch returns 404 (not 403, to avoid information leak). Closed-enum **4-value** `TenantIsolationFailure` literal: `tenant_id_mismatch` (404) / `pack_not_found` (404) / `actor_tenant_id_missing` (500) / `pack_store_not_configured` (500 — added at T2 R1 P2 #1 as the symmetric mirror of `enforcement._bind_actor`'s `binder is None` defensive branch; without it, a route mounted with a binder but no `app.state.pack_record_store` surfaces FastAPI's generic 500 `Internal Server Error` — wire-protocol fingerprint regression). |
| `portal/rbac/human_actor.py` | **NEW per Round 1 P3 #8** (Round 3 P2 #1 — was missing from this forecast table; present in T12 11-module list). `RequireHumanActor()` dependency that asserts `actor.actor_type == "human"` for operator-surface endpoints that finalise per-tenant changes. Returns 403 with closed-enum `actor_type_must_be_human`. |
| `portal/api/packs/author_routes.py` | Wire-protocol-public lifecycle gates (`submit`, `withdraw` from author surface) |
| `portal/api/packs/review_routes.py` | Wire-protocol-public lifecycle gates (`claim`, `approve`, `reject`) — most consequential transitions per ADR-012 §84-105. **`approve` ships as fail-loud `HTTPException(503)` scaffold per Round 1 P2 #1 + Round 10 P3 #2** — API-surface fail-loud uses HTTP-status semantics, NOT `NotImplementedError` (the latter is reserved for kernel-default `ActorBinder` per Round 3 P2 #2). |
| `portal/api/packs/operator_routes.py` | Wire-protocol-public lifecycle gates (`allow_list`, `install`, `disable`, `revoke`, `uninstall`); `allow_list` carries **additional human-actor-type guard per Round 1 P3 #8** |
| `packs/conformance/checks.py` | Security-bearing check matrix (OWASP Agentic Top 10 + Skills Top 10) |
| `packs/conformance/owasp_agentic.py` | Top-level OWASP runner + closed-enum result taxonomy |
| `packs/conformance/runner.py` | Auto-run-on-submit wire into `PackRecordStore.transition()` — extends existing CC module |

**Not-CC:**
- `portal/api/packs/inspection_routes.py` (read-only inspection; no state transitions; but tenant isolation still enforced at route level)
- `portal/api/packs/dto.py` (Pydantic models; no logic)
- `cli/conformance.py` (thin SDK wrapper)

**CC promotions of existing modules:**
- `portal/api/app.py` — promoted for halt-before-commit on T3 (`actor_binder` wiring + pack-router mounting = enforcement boundary per Round 1 P2 #5). Not added to critical-controls coverage gate because the rest of `app.py` is not security-critical; CC classification is task-level (halt-before-commit on T3) not module-level coverage.
- `packs/lifecycle.py` — CC-ADJ extension at T4: add `cancel_draft` transition (`draft → withdrawn`) to `_VALID_TRANSITIONS` per Round 1 P2 #2.
- `packs/storage.py` — CC-ADJ extension at T9: extend `transition()` payload schema with optional `conformance` key per Round 1 P2 #4 (real DecisionRecord.payload field — not the invented `decision_inputs.evidence`).
- `cli/test_harness.py` — CC-ADJ extension at T11 with OWASP integration per Round 1 P2 #6 (full ADR-012 §114-122 fixture-AgentOS harness deferred).

**Critical-controls floor projected: 43 → 54** at Sprint 7B.2 closeout (+11 new CC modules: 5 RBAC + 3 endpoint surfaces + 3 conformance — recounted after Round 1 P2 #3 added tenant_isolation AND P3 #8 added human_actor). T12 patches `AGENTS.md` + `tools/check_critical_coverage.py` accordingly.

## File structure

### Create (new directories + files)

**RBAC subsystem (new directory):**
- `src/cognic_agentos/portal/rbac/__init__.py`
- `src/cognic_agentos/portal/rbac/scopes.py` — 12-value closed-enum `PackRBACScope` literal + `ScopeSet` type alias + `PACK_LIFECYCLE_SCOPES` frozenset (BUILD_PLAN §622-625 verbatim)
- `src/cognic_agentos/portal/rbac/actor.py` — `Actor` Pydantic model (frozen; carries `subject` / `tenant_id` / `scopes` / **`actor_type` per Round 1 P3 #8**) + `ActorBinder` Protocol + 2-value `ActorType` closed-enum literal (`"human"` / `"service"`) + default `NotImplementedError`-raising `KernelDefaultActorBinder`
- `src/cognic_agentos/portal/rbac/enforcement.py` — `RequireScope(scope)` FastAPI dependency factory + closed-enum `RBACDenialReason` literal (3 values: `actor_unauthenticated` / `scope_not_held` / `actor_binder_not_configured`) + `RBACDenied` exception. **Per Round 1 reviewer answer #3: tenant-mismatch handling is route-level (see `tenant_isolation.py`), NOT scope-level. RBACDenialReason stays at 3 values.**
- `src/cognic_agentos/portal/rbac/tenant_isolation.py` — **NEW per Round 1 P2 #3; bumped to 4-value at T2 R1 P2 #1.** `RequireTenantOwnership(pack_id_param: str)` FastAPI dependency factory; loads the `PackRecord` via `PackRecordStore.load(pack_id)`; verifies `pack.tenant_id == actor.tenant_id`; returns the loaded `PackRecord` on success. Closed-enum **4-value** `TenantIsolationFailure` literal: `tenant_id_mismatch` (returns 404 to avoid info leak per OWASP "verbose error messages" guidance) / `pack_not_found` (also 404) / `actor_tenant_id_missing` (returns 500 — kernel misconfig; an actor with no tenant_id should never have been bound) / `pack_store_not_configured` (returns 500 — symmetric mirror of `enforcement._bind_actor`'s `binder is None` defensive branch; T2 R1 P2 #1 — added so a route mounted with a binder but no `app.state.pack_record_store` surfaces a CLOSED-ENUM 500 instead of FastAPI's generic `Internal Server Error`). `PackRecord.tenant_id` exists today at `packs/storage.py:289` per Sprint-7B.1 T3.
- `src/cognic_agentos/portal/rbac/human_actor.py` — **NEW per Round 1 P3 #8.** `RequireHumanActor()` FastAPI dependency that asserts `actor.actor_type == "human"` for operator-surface endpoints that finalise per-tenant changes (specifically `/allow-list` per AGENTS.md "Human-only decisions" rule). Returns 403 with closed-enum `actor_type_must_be_human`. Service tokens with `pack.allow_list` scope are refused even though they hold the scope.

**Packs API sub-router (new directory):**
- `src/cognic_agentos/portal/api/packs/__init__.py` — exports `build_packs_router`
- `src/cognic_agentos/portal/api/packs/dto.py` — Pydantic request / response models for all 18 endpoints
- `src/cognic_agentos/portal/api/packs/author_routes.py` — 4 endpoints (CC)
- `src/cognic_agentos/portal/api/packs/review_routes.py` — 5 endpoints (CC)
- `src/cognic_agentos/portal/api/packs/operator_routes.py` — 5 endpoints (CC)
- `src/cognic_agentos/portal/api/packs/inspection_routes.py` — 4 endpoints (not-CC; read-only)
- `src/cognic_agentos/portal/api/packs/router.py` — top-level `build_packs_router` that mounts the four sub-routers under `/api/v1/packs`

**Conformance subsystem (new directory):**
- `src/cognic_agentos/packs/conformance/__init__.py`
- `src/cognic_agentos/packs/conformance/checks.py` — 10 individual check functions (one per OWASP category) + closed-enum `OWASPCheckCategory` literal
- `src/cognic_agentos/packs/conformance/owasp_agentic.py` — top-level `run_owasp_conformance(pack_manifest) -> ConformanceReport`
- `src/cognic_agentos/packs/conformance/runner.py` — `run_for_submit(pack_id, store)` glue that ties conformance to the storage layer

**CLI extensions:**
- `src/cognic_agentos/cli/conformance.py` — `agentos conformance <pack_path>` subcommand (NEW)
- `src/cognic_agentos/cli/test_harness.py` — **MODIFY (NOT create)** — existing 1321-line Sprint-7A T13 hybrid runner; T11 adds OWASP tail-call after the per-kind dry-run dispatch per Round 1 P2 #6

### Modify (existing files)

- `src/cognic_agentos/portal/api/app.py` — mount `build_packs_router` via `include_router`; accept `actor_binder` kwarg on `create_app` + `create_prod_app`
- `src/cognic_agentos/packs/storage.py` — extend `PackRecordStore.transition()` to accept an optional `evidence_attachments: dict[str, Any]` payload; persist conformance result on `submit` transitions (T9; preserves Doctrine Lock D atomicity)
- `src/cognic_agentos/cli/__init__.py` — register NEW `conformance` subcommand only (mirrors existing `validate` / `sign` / `verify` wiring). **Round 2 P3 #9 correction**: `test-harness` is ALREADY registered at `cli/__init__.py:475` (Sprint-7A T13). T11 extends the existing `cli/test_harness.py` module body — NO new Typer registration. Extend `ValidatorReason` literal ONLY if a NEW refusal class emerges (not anticipated for the conformance subcommand — conformance failures surface via exit code + JSON report, not validator-style refusal)
- `pyproject.toml` — extend `[project.scripts]` if needed (likely no change; `agentos` is a single entry point with subcommand dispatch)
- `docs/BUILD_PLAN.md` §602 — at T13: flip 7B.2 status row to CLOSED with branch tip + closeout link
- `AGENTS.md` — at T12: add `## Authoring — Bank pack lifecycle portal API (Sprint 7B.2)` subsection mirroring the 7B.1 subsection structure
- `tools/check_critical_coverage.py` — at T12: bump CC floor 43 → 54 + add 11 new module entries with rationale lines (per Round 1 P3 #7 recount: 5 RBAC + 3 endpoint surfaces + 3 conformance)

### Tests

- `tests/unit/portal/rbac/__init__.py`
- `tests/unit/portal/rbac/test_scopes.py` — 12-scope literal stability + cross-reference vs BUILD_PLAN §622-625
- `tests/unit/portal/rbac/test_actor.py` — `ActorBinder` Protocol shape + `Actor` model frozen + `actor_type` closed-enum + default `KernelDefaultActorBinder` raises `NotImplementedError` with ADR-008 citation
- `tests/unit/portal/rbac/test_enforcement.py` — `RequireScope` denies unauthenticated; denies missing-scope with 403 + closed-enum `RBACDenialReason`; allows scope-held; raises `actor_binder_not_configured` when no binder injected
- `tests/unit/portal/rbac/test_tenant_isolation.py` — **NEW (Round 1 P2 #3)** — `RequireTenantOwnership` returns 404 on cross-tenant access; 404 on pack-not-found (info-leak prevention); 500 on `actor_tenant_id_missing`
- `tests/unit/portal/rbac/test_human_actor.py` — **NEW (Round 1 P3 #8)** — `RequireHumanActor` returns 403 on `actor_type == "service"`; admits `actor_type == "human"`
- `tests/unit/portal/test_app_factory_actor_binder_wiring.py` — **NEW (Round 1 P2 #5)** — `create_app(actor_binder=None)` does NOT mount pack router; `create_app(actor_binder=<fixture>, pack_record_store=<fixture>)` mounts; fail-loud-warning on partial wiring
- `tests/unit/portal/api/packs/__init__.py`
- `tests/unit/portal/api/packs/test_router_scaffolding.py` — router mounts at `/api/v1/packs`; DTOs round-trip
- `tests/unit/portal/api/packs/test_author_routes.py` — 4 endpoints × (happy + RBAC-denied + **cross-tenant 404** + invalid-state) — includes `manifest_digest_mismatch` test on submit
- `tests/unit/portal/api/packs/test_review_routes.py` — 5 endpoints × same coverage; **plus `test_approve_fail_loud_503`** pinning the no-state-transition + no-chain-row contract
- `tests/unit/portal/api/packs/test_operator_routes.py` — 5 endpoints × same coverage; **plus `test_allow_list_refuses_service_actor` + `test_allow_list_admits_human_actor`** for Round 1 P3 #8
- `tests/unit/portal/api/packs/test_inspection_routes.py` — 4 endpoints × (happy + RBAC-denied + **cross-tenant 404**)
- `tests/unit/portal/api/packs/test_rbac_enforcement_e2e.py` — cross-role negative paths: author cannot approve own pack; operator cannot review; examiner cannot transition lifecycle; pinned per ADR-012 §17 cross-role separation invariant
- `tests/unit/packs/conformance/__init__.py`
- `tests/unit/packs/conformance/test_owasp_checks.py` — 10 OWASP categories × pass-shape + fail-shape + closed-enum stability + manifest-dict input shape
- `tests/unit/packs/conformance/test_owasp_runner.py` — `run_owasp_conformance(manifest)` integration over fixture packs (clean pack passes; tampered pack triggers expected categories)
- `tests/unit/packs/conformance/test_auto_run_on_submit.py` — submit transitions when conformance green AND when conformance red; in both cases evidence attaches via `payload.conformance` key; pinned per BUILD_PLAN §627
- `tests/unit/packs/test_lifecycle.py` (extend) — **NEW for cancel_draft (Round 1 P2 #2)** — pin transition; pin `draft → withdrawn` ONLY reachable via `cancel_draft`, NOT via `withdraw`
- `tests/unit/packs/test_lifecycle_audit.py` (extend) — pin `cancel_draft` audit-chain emission + pin `payload.conformance` shape in submit-transition audit row + non-submit transitions emit NO `payload.conformance` key
- `tests/unit/packs/test_storage_transition_payload_schema.py` — **NEW (Round 1 P2 #4)** — pin exact `payload` keyset for submit vs other transitions; canonical-form stability for pre-T9 fixture chains
- `tests/unit/cli/test_conformance_cli.py` — `agentos conformance <pack>` exit-code matrix + JSON output stability
- `tests/unit/cli/test_test_harness_owasp_integration.py` — **MODIFY existing test scope per Round 1 P2 #6** — pin OWASP tail-call fires after dry-run; pin deferred-full-harness boundary (no AgentOS / audit / sandbox fixture instances spun up)

**Test growth projection:** Sprint-7B.1 ready state was 4370 passed / 46 skipped. Sprint 7B.2 adds ~150-180 new tests (Round 1 expansions: +5 RBAC test modules × ~8 tests = ~40; 4 endpoint surfaces × ~14 tests = ~56; 4 conformance test modules × ~12 = ~48; 2 CLI tests × ~6 = ~12; +cancel_draft / storage-schema / app-factory-wiring extensions = ~12). Target ready state: ~4520-4550 passed.

---

## Task ladder (13 tasks, TDD-shaped)

> **CC class header:** Each task is one of CC (critical controls — halt-before-commit), CC-ADJ (touches a CC module but the touch is contract-additive scaffolding), CC-doctrine (doctrine-only patch of AGENTS.md / coverage gate / closeout), or NOT-CC.
>
> **Gate-ladder per task** (per `feedback_gate_ladder_per_microfix.md`):
> 1. RED: write failing test
> 2. GREEN: minimal implementation
> 3. Pre-commit narrow gate: `uv run pytest -q tests/unit/<scope>/` + targeted `mypy <touched files>`
> 4. **CC tasks only:** halt-before-commit summary (files modified + tests run + tests passed + critical controls touched + ADR citations + reviewer-watchpoints-to-pinning-regression map)
> 5. Reviewer rounds close
> 6. Commit-gate ladder: `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests` full-tree + full pytest only at explicit `commit` token
> 7. Commit by explicit path; conventional message tagged `(CRITICAL CONTROLS)` on CC tasks

---

### Task 1: Plan landing + branch verification *(chore)*

**Class:** chore plan.

**Files:**
- Verify: `docs/superpowers/plans/2026-05-11-sprint-7b2-portal-api-rbac-owasp.md` exists (this file)
- Modify: none (commit is doctrine-file-only)

- [ ] **Step 1: Verify branch + working tree**

```bash
git status
git log --oneline -1
git branch --show-current
# Expect: feat/sprint-7b2-portal-api-rbac-owasp at 768d574 + this plan file as untracked
```

- [ ] **Step 2: Commit plan file**

```bash
git add docs/superpowers/plans/2026-05-11-sprint-7b2-portal-api-rbac-owasp.md
git commit -m "chore(sprint-7b2): T1 — plan-of-record for portal API + RBAC + OWASP conformance"
```

Halt: no (chore class — same as Sprint 7B.1 T1 precedent).

---

### Task 2: RBAC primitives — scopes, actor, enforcement, tenant_isolation, human_actor *(CRITICAL CONTROLS)*

**Class:** CC. **Halt: YES.**

**Why CC:** AGENTS.md "RBAC (`portal/rbac/`)" stop rule. Closed-enum `PackRBACScope` literal IS the wire-protocol contract for RBAC denials. `RequireScope` + `RequireTenantOwnership` + `RequireHumanActor` dependencies are the enforcement points for every state-transition endpoint in T4-T6. **Round 2 P2 #2 expansion**: T2 also creates the tenant-isolation + human-actor guard modules + tests so later tasks have real modules to depend on.

**Files (all 5 RBAC modules land in T2; later tasks consume but don't create):**
- Create: `src/cognic_agentos/portal/rbac/__init__.py`
- Create: `src/cognic_agentos/portal/rbac/scopes.py`
- Create: `src/cognic_agentos/portal/rbac/actor.py` — includes the 2-value `ActorType` closed-enum literal + `actor_type` field on the frozen `Actor` model per Round 2 P2 #3
- Create: `src/cognic_agentos/portal/rbac/enforcement.py` — `RequireScope` + 3-value `RBACDenialReason` closed-enum. **Round 2 P2 #4 narrowing**: RBAC denials emit STRUCTURED HTTP RESPONSE ONLY (403 with closed-enum reason in the body) — NO hash-chained audit-event emission in 7B.2. Audit-chain integration deferred (would require injecting `DecisionHistoryStore` into the dependency factory, defining a denial-event schema, and wiring `app.state` accordingly). 7B.2 covers the access-control gate; the audit chain remains the system-of-record for STATE TRANSITIONS only. Structured logs at the application-logging layer capture denial events for SIEM correlation; **full hash-chain emission ships in Sprint 7B.4 per Round 5 P3 #5** — designed alongside the ADR-020 UI event-taxonomy extension + the realtime auto-attestation carry-forward (the denial-event schema fits the `policy.*` event family slot already reserved in `protocol/ui_events.py`).
- Create: `src/cognic_agentos/portal/rbac/tenant_isolation.py` per Round 1 P2 #3 (bumped to 4-value at T2 R1 P2 #1) — `RequireTenantOwnership(pack_id_param)` dependency factory; loads `PackRecord` via `PackRecordStore.load(pack_id)` from `app.state.pack_record_store`; verifies `pack.tenant_id == actor.tenant_id`; returns the loaded `PackRecord` on success. Closed-enum **4-value** `TenantIsolationFailure` literal: `tenant_id_mismatch` (404) / `pack_not_found` (404) / `actor_tenant_id_missing` (500 — kernel misconfig) / `pack_store_not_configured` (500 — symmetric mirror of `enforcement._bind_actor`'s `binder is None` defensive branch, T2 R1 P2 #1).
- Create: `src/cognic_agentos/portal/rbac/human_actor.py` per Round 1 P3 #8 — `RequireHumanActor()` dependency that asserts `actor.actor_type == "human"`. Returns 403 with closed-enum `actor_type_must_be_human`. Module is intentionally distinct from `enforcement.py` because the closed-enum vocabulary is distinct + the use-case is operator-only.
- Test: `tests/unit/portal/rbac/__init__.py`
- Test: `tests/unit/portal/rbac/test_scopes.py`
- Test: `tests/unit/portal/rbac/test_actor.py` — includes `ActorType` literal pinning + `Actor` model carrying `actor_type` field
- Test: `tests/unit/portal/rbac/test_enforcement.py`
- Test: `tests/unit/portal/rbac/test_tenant_isolation.py` per Round 1 P2 #3
- Test: `tests/unit/portal/rbac/test_human_actor.py` per Round 1 P3 #8

- [ ] **Step 1: RED — write failing tests for the 12-scope literal**

`tests/unit/portal/rbac/test_scopes.py`:

```python
"""Sprint 7B.2 T2 — RBAC scope literal stability + ADR-012 transition-table cross-check.

Pins:
- The 12 scopes from BUILD_PLAN.md §622-625 verbatim. (The Sprint-7B.1 closeout
  L119 says "14 scopes" but enumerates 12 — known cite-from-memory typo in the
  closeout per Sprint 7B.2 plan self-review Round 0.5. BUILD_PLAN §622-625 is the
  source of truth at 12. The override scope `pack.override.approval_gate` from
  ADR-012 §107-110 ships with Sprint 7B.3's 5-gate composer — not 7B.2.)
- Closed-enum literal stability — any addition or rename is a wire-protocol break
  visible in this test's diff.
"""
from cognic_agentos.portal.rbac.scopes import (
    PACK_LIFECYCLE_SCOPES,
    PackRBACScope,
)


def test_pack_lifecycle_scopes_frozen_at_12_values() -> None:
    """ADR-012 §39 + BUILD_PLAN §622-625 — exactly 12 lifecycle scopes in 7B.2."""
    assert len(PACK_LIFECYCLE_SCOPES) == 12


def test_pack_lifecycle_scopes_match_build_plan_verbatim() -> None:
    """Every scope in BUILD_PLAN §622-625 must appear in PACK_LIFECYCLE_SCOPES."""
    expected = frozenset(
        {
            # Author surface (BUILD_PLAN §622)
            "pack.submit",
            "pack.withdraw",
            # Reviewer surface (BUILD_PLAN §623)
            "pack.review.claim",
            "pack.review.approve",
            "pack.review.reject",
            # Operator surface (BUILD_PLAN §624)
            "pack.allow_list",
            "pack.install",
            "pack.disable",
            "pack.revoke",
            "pack.uninstall",
            # Examiner surface (BUILD_PLAN §625) — also serves the inspection
            # surface per ADR-012 §75 "Inspection — examiner-facing"; basic
            # GET / and GET /{id} require `pack.audit.read` (no separate
            # `pack.read.metadata` scope — inspection is examiner territory)
            "pack.audit.read",
            "pack.invocation.read",
        }
    )
    assert PACK_LIFECYCLE_SCOPES == expected
```

(Plus parametrized literal-shape tests + author/reviewer/operator/examiner role-group tests.)

- [ ] **Step 2: Verify tests fail** (`pytest tests/unit/portal/rbac/test_scopes.py -v`)

- [ ] **Step 3: GREEN — implement `portal/rbac/scopes.py`**

Closed-enum `PackRBACScope` Literal + `ScopeSet` type alias + `PACK_LIFECYCLE_SCOPES` frozenset + per-role-group frozensets (`AUTHOR_SCOPES`, `REVIEWER_SCOPES`, `OPERATOR_SCOPES`, `EXAMINER_SCOPES`).

- [ ] **Step 4: RED — write failing tests for `Actor` + `ActorBinder` Protocol + `ActorType` closed-enum**

`tests/unit/portal/rbac/test_actor.py`:

```python
"""Sprint 7B.2 T2 — Actor model + ActorBinder Protocol + ActorType closed-enum + kernel-default fail-loud.

Pins:
- Actor is an immutable Pydantic model (frozen=True).
- ActorType is a 2-value closed-enum Literal ("human" / "service") per Round 1 P3 #8.
- Actor.actor_type field carries the type discriminator (drives RequireHumanActor).
- ActorBinder Protocol matches the production-grade-rule contract — kernel ships
  the protocol; the bank overlay or test fixture plugs in the real binder.
- KernelDefaultActorBinder.bind() raises NotImplementedError citing ADR-008.
"""
from typing import get_args

import pytest
from cognic_agentos.portal.rbac.actor import (
    Actor,
    ActorBinder,
    ActorType,
    KernelDefaultActorBinder,
)


def test_actor_type_literal_frozen_at_2_values() -> None:
    """Round 1 P3 #8 — exactly 2 actor-type values."""
    assert set(get_args(ActorType)) == {"human", "service"}


def test_actor_is_frozen_and_carries_actor_type() -> None:
    actor = Actor(
        subject="alice@bank.example",
        tenant_id="t1",
        scopes=frozenset({"pack.submit"}),
        actor_type="human",
    )
    assert actor.actor_type == "human"
    with pytest.raises(Exception):  # Pydantic ValidationError or FrozenInstanceError
        actor.subject = "bob@bank.example"  # type: ignore[misc]


def test_actor_rejects_invalid_actor_type() -> None:
    """Closed-enum stability — out-of-vocab actor_type refused at construction."""
    with pytest.raises(Exception):  # Pydantic ValidationError
        Actor(
            subject="x",
            tenant_id="t1",
            scopes=frozenset(),
            actor_type="robot",  # type: ignore[arg-type]
        )


def test_kernel_default_binder_fails_loud() -> None:
    binder: ActorBinder = KernelDefaultActorBinder()
    with pytest.raises(NotImplementedError) as exc:
        binder.bind(request=None)  # type: ignore[arg-type]
    assert "ADR-008" in str(exc.value)
```

- [ ] **Step 5: Verify tests fail**

- [ ] **Step 6: GREEN — implement `portal/rbac/actor.py`**

```python
from typing import Literal, Protocol, TypeAlias

from pydantic import BaseModel, ConfigDict
from starlette.requests import Request

from cognic_agentos.portal.rbac.scopes import ScopeSet


#: 2-value closed-enum actor-type discriminator per Round 1 P3 #8.
#: Bank overlays set this when minting actor identities from the
#: underlying auth backend (OIDC token scope, mTLS cert OU, etc).
#: Used by ``RequireHumanActor`` to gate operator-surface endpoints
#: that finalise per-tenant changes (specifically ``/allow-list``).
ActorType: TypeAlias = Literal["human", "service"]


class Actor(BaseModel):
    """Frozen actor identity bound from the incoming request.

    The bank overlay or test fixture is responsible for producing this from
    whatever auth backend the deployment uses (OIDC bearer / SAML / mTLS).
    The kernel does not assume an auth backend.
    """

    model_config = ConfigDict(frozen=True)

    subject: str
    tenant_id: str
    scopes: ScopeSet
    actor_type: ActorType


class ActorBinderUnauthenticated(Exception):
    """Round 3 P2 #2 emit path for the `actor_unauthenticated` closed-enum value.

    Raised by an `ActorBinder.bind()` implementation when the request carries
    no resolvable auth primitive (missing/invalid bearer token, expired session,
    unknown mTLS cert). The `RequireScope` FastAPI dependency catches this
    exception and translates it to `HTTPException(403, detail={"reason":
    "actor_unauthenticated"})` — preserving the `RBACDenialReason` closed-enum
    as the wire-protocol surface while keeping the binder's typed exception
    idiomatic with the rest of the codebase (LifecycleTransitionRefused /
    PackRecordRefused / etc.).
    """


class ActorBinder(Protocol):
    """Pluggable actor-binding contract.

    The kernel ships only the protocol + a fail-loud default. Production
    deployments inject an implementation that maps the request's auth
    primitives to an Actor.

    Implementations may raise ``ActorBinderUnauthenticated`` when the request
    has no valid auth primitive (vs ``NotImplementedError`` from the kernel
    default binder when no overlay has been configured at all).
    """

    def bind(self, *, request: Request) -> Actor: ...


class KernelDefaultActorBinder:
    """Fail-loud default per ADR-008 + production-grade-rule.

    Raised at request time when no overlay binder has been injected into
    create_app(actor_binder=...). Surfaces a structured NotImplementedError
    rather than a silent identity fallback. Distinct from
    ``ActorBinderUnauthenticated``: this is a kernel-misconfig (no binder
    plugged in), not a per-request auth failure.
    """

    def bind(self, *, request: Request) -> Actor:
        raise NotImplementedError(
            "No ActorBinder configured per ADR-008. Bank overlays must inject "
            "an ActorBinder via create_app(actor_binder=...) before serving "
            "portal API requests. The kernel does not assume an auth backend."
        )
```

- [ ] **Step 7: RED — write failing tests for `RequireScope` FastAPI dependency**

`tests/unit/portal/rbac/test_enforcement.py`:

```python
"""Sprint 7B.2 T2 — RequireScope dependency + closed-enum RBACDenialReason.

Pins (Round 2 P2 #4 narrowing — STRUCTURED HTTP DENIAL ONLY in 7B.2):
- 3-value closed-enum: actor_unauthenticated / scope_not_held / actor_binder_not_configured
- 403 on scope_not_held + actor_unauthenticated
- 500 on actor_binder_not_configured (kernel misconfig, not a client error)
- HTTPException body carries the closed-enum reason + required_scope + actor_subject
- Application-logging side-effect: structured log record emitted at denial (NOT a
  hash-chained audit event in 7B.2; full chain emission deferred to Sprint 7B.4
  per Round 6 P3 #5 singular-owner tag — denial-event schema fits the `policy.*`
  event family slot reserved in `protocol/ui_events.py`)
"""
# ... (full test bodies in implementation)
```

- [ ] **Step 8: Verify tests fail**

- [ ] **Step 9: GREEN — implement `portal/rbac/enforcement.py`**

`RequireScope(scope: PackRBACScope) -> Callable[..., Actor]` factory returning a FastAPI dependency. Resolves the request's `ActorBinder` from `request.app.state.actor_binder`; calls `.bind(request=request)` inside a try/except that catches `ActorBinderUnauthenticated` (per Round 3 P2 #2 emit path) and translates to `HTTPException(403, detail={"reason": "actor_unauthenticated"})`; on success, checks scope membership in `actor.scopes` and raises `HTTPException(403, detail={"reason": "scope_not_held", "required_scope": scope, "actor_subject": actor.subject})` on miss; on `NotImplementedError` (kernel-default-binder case — no overlay configured) raises `HTTPException(500, detail={"reason": "actor_binder_not_configured"})`. **Round 2 P2 #4: NO hash-chained audit emission in 7B.2.** Denials emit a structured log record at the application-logging layer (`logger.warning("portal.rbac.denied", extra={...})`) — SIEM correlation works via the existing structured-logging stack; **full chain-event emission ships in Sprint 7B.4 per Round 5 P3 #5 placeholder tag** — designed alongside the ADR-020 UI event-taxonomy extension; the denial-event schema fits the `policy.*` event family slot already reserved in `protocol/ui_events.py`. The TaskBoundary stop at this scope is documented in `RBACDenied` exception's docstring + the module-level docstring.

All three closed-enum `RBACDenialReason` values now have a real emit path: `actor_unauthenticated` ← `ActorBinderUnauthenticated`-catch; `scope_not_held` ← scope-membership-check miss; `actor_binder_not_configured` ← `NotImplementedError`-catch from `KernelDefaultActorBinder`.

- [ ] **Step 10a: RED + GREEN — `tests/unit/portal/rbac/test_tenant_isolation.py`**

Pin:
- `RequireTenantOwnership(pack_id_param)` loads `PackRecord` via `app.state.pack_record_store.load(pack_id)`
- Cross-tenant access: actor.tenant_id != pack.tenant_id → 404 with `{"reason": "tenant_id_mismatch"}` (404 not 403 — info-leak prevention)
- Pack not found: `PackRecord` is None → 404 with `{"reason": "pack_not_found"}` (same 404 status as tenant mismatch — info-leak prevention symmetry)
- Actor missing tenant_id: 500 with `{"reason": "actor_tenant_id_missing"}` (kernel misconfig — should never happen with a real binder)
- Returns the loaded `PackRecord` on success (sub-handlers consume it without re-loading)

- [ ] **Step 10b: RED + GREEN — `tests/unit/portal/rbac/test_human_actor.py`**

Pin:
- `RequireHumanActor()` admits `actor.actor_type == "human"`
- Refuses `actor.actor_type == "service"` with 403 + `{"reason": "actor_type_must_be_human"}`
- Closed-enum stability — out-of-vocab `actor_type` already refused at `Actor` construction; this guard is purely the human-vs-service discriminator

- [ ] **Step 11: Verify all tests pass** (`pytest tests/unit/portal/rbac/ -v`) — 5 new test modules

- [ ] **Step 12: Pre-commit narrow gate**

```bash
uv run ruff check src/cognic_agentos/portal/rbac/ tests/unit/portal/rbac/
uv run ruff format --check src/cognic_agentos/portal/rbac/ tests/unit/portal/rbac/
uv run mypy src/cognic_agentos/portal/rbac/ tests/unit/portal/rbac/
uv run pytest -q tests/unit/portal/rbac/
```

- [ ] **Step 13: HALT-BEFORE-COMMIT summary** *(CC task)*

Produce halt summary with: files modified + tests run + tests passed + closed-enum vocabulary established + reviewer-watchpoint-to-pinning-regression map for: (a) scope literal stability (12 values), (b) ActorType literal stability (2 values), (c) Actor model frozen + actor_type field, (d) ActorBinder Protocol contract, (e) RequireScope dependency closed-enum denial reasons (3 values), (f) TenantIsolationFailure closed-enum (**4 values** post-T2-R1-P2-#1; 404 not 403; includes defensive `pack_store_not_configured` 500), (g) RequireHumanActor closed-enum (1 value; admits human refuses service), (h) **structured-HTTP-only denial scope** (Round 2 P2 #4 — NO chain-event emission in 7B.2; caplog parity pinned across all 3 RBAC loggers per T2 R1 P2 #2). Wait for `commit` token.

- [ ] **Step 14: Commit-gate ladder** (full-tree ruff/format/mypy + full pytest)

- [ ] **Step 15: Commit**

```bash
git add src/cognic_agentos/portal/rbac/ tests/unit/portal/rbac/
git commit -m "feat(sprint-7b2): T2 — portal/rbac/ scopes + actor + enforcement primitives (CRITICAL CONTROLS)"
```

---

### Task 3: Pack DTOs + sub-router scaffolding + app factory wiring *(CRITICAL CONTROLS)*

**Class:** CC. **Halt: YES.** *(Promoted from NOT-CC per Round 1 P2 #5.)*

**Why CC:** The DTO module itself is logic-free Pydantic, but this task also modifies `portal/api/app.py` to accept the `actor_binder` kwarg + mount the pack-router under `/api/v1/packs`. That wiring IS the enforcement-boundary integration point — miswiring (e.g. forgetting to attach `app.state.actor_binder`, or mounting the router before the dependency injection chain is wired) would either fail-open or surface as a confusing 500 in production. Halt-before-commit applies on the app.py modification specifically; the DTO file is along for the ride.

**Files:**
- Create: `src/cognic_agentos/portal/api/packs/__init__.py`
- Create: `src/cognic_agentos/portal/api/packs/dto.py`
- Create: `src/cognic_agentos/portal/api/packs/router.py` — top-level `build_packs_router(*, store: PackRecordStore)` mounting empty sub-routers (filled in T4-T7)
- Modify: `src/cognic_agentos/portal/api/app.py` — accept `actor_binder: ActorBinder | None = None` + `pack_record_store: PackRecordStore | None = None` kwargs on `create_app`; attach to `app.state.actor_binder` / `app.state.pack_record_store` during `lifespan`; mount `build_packs_router(store=...)` only when `actor_binder` AND `pack_record_store` are both provided. **Kernel-default fail-loud: when `actor_binder is None` but `pack_record_store is not None`, refuse to mount the pack router at startup with a structured warning** (mirrors the `mcp.host_unavailable_in_image` pattern in `create_prod_app`).
- Test: `tests/unit/portal/api/packs/__init__.py`
- Test: `tests/unit/portal/api/packs/test_router_scaffolding.py` — router mounts at `/api/v1/packs`; DTOs round-trip through Pydantic
- Test: `tests/unit/portal/test_app_factory_actor_binder_wiring.py` — `create_app(actor_binder=None)` does NOT mount the pack router; `create_app(actor_binder=<fixture>, pack_record_store=<fixture>)` DOES mount it; `app.state.actor_binder` is the bound binder; deep-copy isolation per Sprint-6 `ui_events.py` pattern is NOT applied (binder is a callable, not a payload).

**Halt summary watchpoints:**
- (a) Fail-loud wiring on missing `actor_binder` (mirrors Sprint-5 T2 `create_prod_app` MCP-availability pattern)
- (b) Router NOT mounted when wiring incomplete — pinned by `test_app_factory_actor_binder_wiring.py` happy + sad cases
- (c) `app.state` attribute names stable across the test fixture pattern (any rename here breaks every endpoint test in T4-T7)
- (d) Defensive isolation: `app.state.actor_binder` is the SAME object across requests by design (the binder is a singleton per-process); pin no-shared-mutable-state via test that constructs two requests and confirms the binder identity is preserved

---

### Task 4: Author surface endpoints — 4 endpoints + `cancel_draft` lifecycle extension *(CRITICAL CONTROLS)*

**Class:** CC. **Halt: YES.**

**Why CC:** Wire-protocol-public lifecycle gates (`submit`, `withdraw`); delegates to `PackRecordStore.save_draft` + `PackRecordStore.transition` from 7B.1. **Plus a CC-ADJ extension to `packs/lifecycle.py`** to add the `cancel_draft` transition per Round 1 P2 #2 resolution.

**Files:**
- Create: `src/cognic_agentos/portal/api/packs/author_routes.py`
- Modify: `src/cognic_agentos/packs/lifecycle.py` — **per Round 3 P2 #3 ownership split** (lifecycle.py owns `TransitionName` + `_VALID_TRANSITIONS` + `_KNOWN_TRANSITIONS` (derived from `get_args(TransitionName)` at `:240` — auto-picks up the 11th value) + `_TRANSITION_TO_ISO_CONTROLS`; storage.py owns its local `_TRANSITION_TO_TARGET_STATE` mirror). At T4: (a) extend `TransitionName` Literal from 10-value to 11-value (add `"cancel_draft"` at `lifecycle.py:133`); (b) extend `_VALID_TRANSITIONS` at `:196` with `cancel_draft: frozenset({("draft", "withdrawn")})`; (c) extend `_TRANSITION_TO_ISO_CONTROLS` at `:290-301` with **`cancel_draft → ("A.5.31",)` per Round 6 P2 #3 decision**: mirrors the existing `withdraw → ("A.5.31",)` mapping at `lifecycle.py:300` (rationale at `:277` says "author cancels the regulatory..."). Both transitions are author-cancellation flows reaching the same `withdrawn` target state; both map to the same ISO 42001 `A.5.31` access-control tuple. Decision committed in-plan to avoid design choice inside the CC source edit; (d) repo-wide doctrine-citation sweep per P2 #6 below; (e) bump `LifecycleRefusalReason` ONLY if a new refusal class emerges — `cancel_draft → withdrawn` itself reuses the existing `…_invalid_state_pair` vocabulary, BUT **T9's race-condition fix per Round 3 P2 #5 adds a new value `lifecycle_transition_manifest_digest_changed_during_submit`** so LifecycleRefusalReason bumps **13 → 14 values** across the 7B.2 sprint (T4 ships only the cancel_draft addition; T9 adds the 14th value when wiring the locked precondition check). **CC-ADJ source change to a Sprint-7B.1 critical-controls module — gets its own R-round review tier per AGENTS.md "no casual refactors" rule.**
- Modify: `src/cognic_agentos/packs/storage.py` — (a) extend local `_TRANSITION_TO_TARGET_STATE` mirror at `:118` to include `cancel_draft → "withdrawn"` (storage owns this map per Round 3 P2 #3; lifecycle.py does NOT have a target-state map); lockstep with lifecycle.py per Sprint-7B.1 T3 R1 P2 #2 asymmetric-guard pattern. (b) **NEW per Round 2 P2 #5 + Round 3 P2 #4 + Round 5 P2 #3 + Round 6 P3 #4: add `update_draft()` method** — `async def update_draft(self, *, pack_id: uuid.UUID, updates: dict[str, Any], actor_id: str) -> None`. **No `tenant_id` parameter** (Round 5 P2 #3 resolution): tenant-mismatch enforcement is route-level only via `RequireTenantOwnership`. Mirrors 7B.1 `save_draft()` at `:313` which also does not accept `tenant_id` as a separate kwarg. For `update_draft`, the `actor_id` is used for the `last_actor` column bump; no other identity field flows through. Semantics: updates a fixed allow-list of 4 non-state fields (`display_name` / `manifest_digest` / `signed_artefact_digest` / `sbom_pointer`) on a `draft`-state pack only. **Bumps `PackRecordRefusalReason` literal 1 → 4 values** (Round 3 P2 #4 added the first two new values; Round 6 P3 #4 adds the fourth for value-shape validation): (i) `pack_record_update_non_draft_state` — pack is not in `draft` state; (ii) `pack_record_update_field_not_allowed` — caller's `updates` dict contains a key outside the 4-field allow-list (covers caller attempts to mutate `tenant_id` / `state` / `kind` / `pack_id` / `created_by` — the **5 immutable fields** per Round 3 reviewer answer); (iii) **NEW per Round 6 P3 #4: `pack_record_update_field_invalid_shape`** — caller's `updates` dict carries an allow-listed key but the value fails the field's type/shape contract; the original 1-value `pack_record_save_draft_initial_state_not_draft` from 7B.1 stays. Refuses fail-loud with `PackRecordRefused(reason=<value>)`. Refuses fail-loud with `PackNotFound` on missing pack. **NO chain row emitted** — mirrors `save_draft()` genesis-state pattern at `storage.py:313`. Tenant-mismatch check is route-level (T4 author_routes) via `RequireTenantOwnership`; storage layer enforces only the state-machine + field-allowlist + value-shape invariants.

  **Value-shape validation contract (Round 6 P3 #4):**

  Per-field shape contracts derived from `PackRecord` field types at `storage.py:268-293`:
  - `display_name` — must be `str`, non-empty, length ≤ 256 chars (DB column is reasonably sized; pin via test that 257-char input refuses)
  - `manifest_digest` — must be `bytes`, exactly 32 bytes (SHA-256 output width); pin via test that `b"too_short"` refuses
  - `signed_artefact_digest` — must be `bytes`, exactly 32 bytes; pin same as manifest_digest
  - `sbom_pointer` — must be `str` (non-empty) OR `None`; pin via test that `""` refuses + `None` is accepted

  Shape check fires AFTER the field-allowlist check (so an unknown key surfaces as `pack_record_update_field_not_allowed`, not as `pack_record_update_field_invalid_shape`) and BEFORE any DB call (so a malformed digest never reaches the atomic UPDATE). Pure-Python validation; mirrors the `cli/validators/` early-refusal pattern.

  **`PackRecordRefused` exception payload contract (Round 7 P2 #3 — closed-enum reason only, no field-name carry):**

  The current `PackRecordRefused.__init__` signature at `storage.py:254-265` is `(self, reason: PackRecordRefusalReason, *, state: PackState | None = None)`. **Round 7 P2 #3 decision: do NOT extend this signature to carry a failing-field name** — keep the exception shape unchanged. Rationale: extending the 7B.1 CC exception class adds cross-sprint surgical surface area; the closed-enum `reason` is sufficient for the caller's dispatch contract; diagnostic field-name info goes in the structured-log emission at the storage-validator boundary rather than in the typed-exception payload.

  **Structured-log emission contract (Round 8 reviewer answer #1):** use module-level `_LOG = logging.getLogger(__name__)` at the top of `packs/storage.py` (mirrors the existing logger convention in the codebase); emit `_LOG.warning("packs.update_draft.invalid_shape", extra={"pack_id": str(pack_id), "field": failing_field})` from inside the value-shape refusal branch BEFORE raising `PackRecordRefused(...)`. Test contract: `test_update_draft_refuses_invalid_shape_before_db_call` uses `caplog` with `caplog.set_level(logging.WARNING, logger="cognic_agentos.packs.storage")`; asserts the closed-enum reason via exception introspection AND asserts the field-name appears in the captured log record's `extra` payload. Two-layer regression: typed-exception path covers caller dispatch; structured-log path covers SIEM correlation + examiner audit.

  **Atomicity specification (Round 4 P2 #3) — order of refusal checks at runtime:**

  1. Field-allowlist refusal (pure-Python) → `pack_record_update_field_not_allowed`
  2. **Per-field value-shape refusal (pure-Python, Round 6 P3 #4)** → `pack_record_update_field_invalid_shape`
  3. Atomic `UPDATE packs SET <allowlisted-fields>, last_actor=:actor_id, updated_at=:now WHERE id=:pack_id AND state='draft'`
  4. Rowcount==0 disambiguation via follow-up SELECT → `PackNotFound` or `pack_record_update_non_draft_state`

  **Atomicity specification (Round 4 P2 #3 + Round 6 P3 #4):**

  1. **Field-allowlist refusal** (pure-Python, before any DB call): if any key in `updates` is outside `{"display_name", "manifest_digest", "signed_artefact_digest", "sbom_pointer"}`, raise `PackRecordRefused("pack_record_update_field_not_allowed")` IMMEDIATELY — no transaction opened, no row touched. Mirrors the early-refusal pattern in Sprint-7B.1 T3 storage's preflight transition-name guard at `:437-438`.
  2. **Per-field value-shape refusal** (pure-Python, Round 6 P3 #4 + Round 7 P2 #3 exception-payload narrowing): for each allow-listed key in `updates`, verify the value matches the per-field shape contract documented above (`str`/non-empty/≤256 for `display_name`; `bytes`/len==32 for both digests; `str|None` non-empty for `sbom_pointer`). First mismatch raises `PackRecordRefused("pack_record_update_field_invalid_shape")` — closed-enum reason ONLY; **no field-name carried in the exception payload** (Round 7 P2 #3 — the existing 7B.1 `PackRecordRefused.__init__` signature stays unchanged at `(reason, *, state=None)`). Failing field name surfaces via structured-log emission at the validator boundary (`logger.warning("packs.update_draft.invalid_shape", extra={"pack_id": ..., "field": ...})`) for SIEM correlation. Fires AFTER step 1 (so unknown keys surface as `…_field_not_allowed`) and BEFORE any DB call (so malformed digests never reach the atomic UPDATE).
  3. **Atomic UPDATE with state precondition** (single SQL statement; no SELECT-then-UPDATE race window):
     ```sql
     UPDATE packs
     SET <allowlisted-fields-from-updates>,
         last_actor = :actor_id,
         updated_at = :now
     WHERE id = :pack_id AND state = 'draft'
     ```
     The `state = 'draft'` predicate is part of the UPDATE's WHERE clause (NOT a separate `SELECT … FOR UPDATE` precondition closure — this method does NOT use `append_with_precondition` since no chain row is emitted; the atomic UPDATE alone provides the consistency guarantee).
  4. **Auto-bumped fields**: `last_actor = actor_id` and `updated_at = datetime.now(UTC)` are ALWAYS overwritten by this UPDATE regardless of which allow-listed fields the caller supplied. Pin both in test.
  5. **Rowcount-based refusal disambiguation**: after the atomic UPDATE, check rowcount:
     - rowcount == 1: success path; return None
     - rowcount == 0: do a follow-up `SELECT id, state FROM packs WHERE id = :pack_id` to disambiguate:
       - if no row returned: raise `PackNotFound(pack_id)`
       - if row returned with `state != "draft"`: raise `PackRecordRefused("pack_record_update_non_draft_state")` — covers the race where a concurrent `transition("submit")` or `transition("cancel_draft")` advanced the pack out of `draft` between the route's preload and our atomic UPDATE
  6. **Transaction boundary**: the UPDATE + disambiguation SELECT run inside a single `async with self._engine.begin()` block. The follow-up SELECT does NOT need `FOR UPDATE` because the disambiguation is purely informational (the actual refusal is already determined by the UPDATE's rowcount=0; the SELECT only chooses between `PackNotFound` vs `pack_record_update_non_draft_state`).

  This shape closes the load-then-update race window (P2 #3): the only authoritative state check is the WHERE clause inside the atomic UPDATE, fired against the live row. A concurrent `submit` / `cancel_draft` that wins the race causes our UPDATE to affect 0 rows, surfacing as a clean refusal. Tests: `test_storage_update_draft.py::test_concurrent_submit_loses_to_update_draft_atomic_update` (integration test under `COGNIC_RUN_POSTGRES_INTEGRATION=1` / `COGNIC_RUN_ORACLE_INTEGRATION=1`) + `test_update_draft_bumps_last_actor_and_updated_at` + `test_update_draft_refuses_field_not_allowed_before_db_call` + `test_update_draft_refuses_invalid_shape_before_db_call` (Round 6 P3 #4 — pin all 4 fields' shape refusals) + `test_update_draft_pack_not_found` + `test_update_draft_emits_no_chain_row`.
- Modify: `AGENTS.md:L123` — update the `_VALID_TRANSITIONS` legal-pair-table count phrase "10 transitions / 13 legal pairs: 7 single-from + 3 multi-from × 2" → "11 transitions / 14 legal pairs: 7 single-from + 3 multi-from × 2 + cancel_draft single-from × 1" per Round 4 P2 #2 (lands at T4 alongside the source change; T9 will edit the SAME LINE for the separate `LifecycleRefusalReason` 13-value → 14-value bump per Round 4 P2 #1)
- Modify: `tools/check_critical_coverage.py:170-171` — docstring rationale "(10 transitions / 13 legal pairs)" → "(11 transitions / 14 legal pairs)" per Round 4 P2 #2

**PackRecordRefusalReason 1→4 doctrine sweep at T4 (NEW per Round 6 P2 #2 + Round 7 P2 #2 corrections):**

Bumping `PackRecordRefusalReason` from 1 value to 4 values requires updating durable references that currently describe the enum as 1-value / save_draft-only. Sites enumerated explicitly via plan-time inspection (Round 8 P2 #2 — single-line proximity grep is insufficient because 2 sites have `save_draft` and `Wave-1` on different lines: `storage.py:231+232` and `storage.py:239+241`):

**Site inventory (Round 7 P2 #2 — corrected to include `storage.py:232` + `:241`):**

`src/cognic_agentos/packs/storage.py` — 4 sites (Round 6 had 2; Round 7 adds 2):
- `:42-43` — module docstring "(Wave-1: only ``pack_record_save_draft_initial_state_not_draft``)" — extend to enumerate all 4 values + name the categories (genesis-state guard + update_draft 3 refusals)
- `:232` — comment above `PackRecordRefusalReason`: "The only Wave-1 reason is the genesis-state guard; future kind-specific or identity-specific preconditions land alongside without breaking the closed-enum dispatch contract." → rewrite acknowledging the 3 update_draft refusals landing at 7B.2 T4
- `:235` — `PackRecordRefusalReason = Literal[...]` definition — extend with 3 new values
- `:241` — `PackRecordRefused` class docstring: "The Wave-1 contract is genesis-state-only" — rewrite for the dual-contract surface (save_draft genesis-state + update_draft API-contract refusals)

`tools/check_critical_coverage.py` — 1 site:
- `:224` — docstring rationale "1-value ``PackRecordRefusalReason`` Literal at :235 (only for" → "4-value ``PackRecordRefusalReason`` Literal at :235 (genesis-state guard + 3 update_draft API-contract refusals)"

`AGENTS.md` — 1 site:
- `L124` — within the `packs/storage.py` subsection bullet, the phrase "PackRecordRefusalReason at :235 is a 1-value Literal (`pack_record_save_draft_initial_state_not_draft`) carried by `PackRecordRefused`" — update to "4-value Literal (`pack_record_save_draft_initial_state_not_draft` + `pack_record_update_non_draft_state` + `pack_record_update_field_not_allowed` + `pack_record_update_field_invalid_shape`)"

**Total: 6 sites in 3 files** (Round 6's 4 sites + Round 7 P2 #2 adds storage.py:232 + :241). Same 3-path exclusion set: 7B.1 closeout + 7B.1 plan + this 7B.2 plan. **False positive deliberately UNCHANGED**: `docs/PACK-MANIFEST-SPEC.md:222` cites Wave-1 for hook `fail_policy`, NOT `PackRecordRefusalReason` — different vocabulary, intentionally untouched.

**Halt summary proof shape (Round 8 P2 #2 — per-site `sed -n` verification because 2 sites have `save_draft` and `Wave-1` on different lines):**

6 sed commands per site PASTED in halt summary with expected post-patch text per site:

- `sed -n '42,43p' src/cognic_agentos/packs/storage.py` → module docstring no longer says "(Wave-1: only ...)"; enumerates all 4 values
- `sed -n '232p' src/cognic_agentos/packs/storage.py` → comment no longer says "only Wave-1 reason is the genesis-state guard"; rewritten for the dual-contract surface
- `sed -n '235p' src/cognic_agentos/packs/storage.py` → `PackRecordRefusalReason = Literal[...]` definition now has 4 values
- `sed -n '241p' src/cognic_agentos/packs/storage.py` → docstring no longer says "Wave-1 contract is genesis-state-only"; rewritten for the dual-contract surface
- `sed -n '224p' tools/check_critical_coverage.py` → rationale says "4-value ``PackRecordRefusalReason``" not "1-value"
- `sed -n '124p' AGENTS.md` → bullet says "4-value Literal" + enumerates all 4 values

Negative sanity grep `grep -rn -E "1-value.{0,20}PackRecordRefusalReason|PackRecordRefusalReason.{0,20}1-value" src/ tests/ tools/ docs/ AGENTS.md` (3-path exclusion) returns ZERO hits post-patch — proves no 1-value drift remains in the proximity-grep-catchable sites. The split-line cases at `storage.py:231-232` + `:239-241` are caught by the per-site sed checks above, not by the proximity grep.
- Test: `tests/unit/portal/api/packs/test_author_routes.py` — 4 endpoints × happy + RBAC-denied + tenant-mismatch + invalid-state paths; manifest-digest-mismatch test on submit
- Test: `tests/unit/packs/test_lifecycle.py` (extend) — pin `cancel_draft` transition; pin that `draft → withdrawn` is ONLY reachable via `cancel_draft`, NOT via the existing `withdraw` transition (asymmetric-runtime-guard pattern preserved); pin `TransitionName` Literal at 11 values; pin `_VALID_TRANSITIONS` map size at 11 keys / 14 legal pairs; update `:143` + `:174` doctrine citations per the 15-site sweep
- Test: `tests/unit/packs/test_lifecycle_audit.py` (extend) — pin `cancel_draft` audit-chain emission + ISO 42001 control tuple; update `:29` + `:308` + `:332` + `:337` + `:524` doctrine citations per the 15-site sweep
- Test: `tests/unit/packs/test_storage_update_draft.py` (NEW per Round 2 P2 #5 + Round 4 P2 #3 atomicity spec + Round 6 P3 #4 value-shape contract + Round 9 P3 #3 test-bullet completeness) — pin `update_draft` happy path (draft state allowed); pin refusal on non-draft state with `pack_record_update_non_draft_state`; pin refusal on field-not-allowed with `pack_record_update_field_not_allowed` BEFORE any DB call; **pin refusal on invalid-shape with `pack_record_update_field_invalid_shape` BEFORE any DB call per Round 6 P3 #4 — covers all 4 fields: `display_name` (non-str / empty / >256 chars); both digests (non-bytes / wrong-length); `sbom_pointer` (empty str)** (`test_update_draft_refuses_invalid_shape_before_db_call` parametrized over the 4 fields per Round 9 P3 #3 — was missing from explicit test bullet); pin structured-log emission via caplog (`logger="cognic_agentos.packs.storage"`) on invalid-shape per Round 8 reviewer answer #1; pin no-chain-row emission (chain count unchanged); pin `last_actor` + `updated_at` auto-bump on every update; pin allow-listed-fields-only contract; pin `PackNotFound` on missing pack; integration test under `COGNIC_RUN_POSTGRES_INTEGRATION=1` / `COGNIC_RUN_ORACLE_INTEGRATION=1` for concurrent-submit race (`test_concurrent_submit_loses_to_update_draft_atomic_update`)

**Lifecycle extension resolution (Round 1 P2 #2):**

ADR-012 §59 explicitly specifies `DELETE /api/v1/packs/drafts/{id}` as "cancel draft" — distinct semantics from the `withdraw` transition (which §39 limits to `submitted` / `under_review` source states). Treating these as separate transitions preserves the audit-chain distinction (a "cancel" is a developer scratching their own draft; a "withdraw" is an author retracting a submission already under reviewer attention). T4 ships the lifecycle extension as the first step before any endpoint code lands:

- `TransitionName` Literal extended from 10 to 11 values (`"cancel_draft"` added at `lifecycle.py:133`)
- `_VALID_TRANSITIONS` mapping at `lifecycle.py:196` gains `cancel_draft: frozenset({("draft", "withdrawn")})`
- `_TRANSITION_TO_ISO_CONTROLS` at `lifecycle.py:290-301` extended in lockstep (lifecycle owns this map)
- `_TRANSITION_TO_TARGET_STATE` at `storage.py:118` extended in lockstep (storage owns this map — Round 3 P2 #3 ownership split)
- `_KNOWN_TRANSITIONS` runtime frozenset (derived from `get_args(TransitionName)` at `lifecycle.py:240`) automatically picks up the 11th value — no manual mirror needed
- Asymmetric-runtime-guard at `lifecycle.py:472-473` (validate_transition step 3 — Round 3 P3 #7 fix: was incorrectly cited as `:393-394` which is actually the `iso_controls_for` guard at the end of its body) still fires for any out-of-vocab transition name — `cancel_draft` joins the vocabulary; arbitrary names still refuse
- 7B.1 storage.py preflight guard at `:437-438` extended in lockstep via its local `_TRANSITION_TO_TARGET_STATE` mirror
- The third asymmetric-runtime-guard at `lifecycle.py:393-394` (the actual `iso_controls_for` guard against `_TRANSITION_TO_ISO_CONTROLS` per Sprint-7B.1 doctrine catalog §11) auto-extends because `_TRANSITION_TO_ISO_CONTROLS` gains the `cancel_draft` entry; no separate change needed at that guard site

**Doctrine sweep required (Round 2 P2 #6 + Round 3 P2 #6 — repo-wide expansion):**

Adding `cancel_draft` makes the transition vocabulary 11 values, not 10. Every durable doc/comment/test that cites "10 transitions" / "10-value" / "10-transition" / "10-tuple" / "canonical 10" / "13 legal pairs" / map sizes must update in lockstep with the source change. **The Sprint-7B.1 closeout itself stays untouched per Round 1 reviewer answer #5 + immutable-committed-closeout doctrine; the 7B.2 closeout records the count delta as a doctrine-cross-reference.**

**Full repo-wide site inventory** (Round 3 P2 #6 + Round 4 P2 #4 — verified via `grep -rn "10-tuple\|10 transitions\|10-transition\|10-value\|canonical 10\|13 legal pairs" src/ tests/ tools/ docs/ AGENTS.md` (Round 4 P2 #4 expansion adds `docs/`) at plan-write time, excluding only the two immutable doc paths called out below):

`src/cognic_agentos/packs/lifecycle.py` — 5 sites:
- `:51` — module-docstring "canonical 10-tuple"
- `:130` — "Canonical 10-tuple of transition names per ADR-012"
- `:192` — "13 legal pairs in total across the 10 transitions (7 single-from + 3 multi-from × 2)"
- `:376` — `iso_controls_for` docstring "Member of the canonical 10-tuple :data:`TransitionName`"
- `:436` — `validate_transition` docstring "10-tuple :data:`TransitionName`"

`src/cognic_agentos/packs/storage.py` — 1 site:
- `:118` — `_TRANSITION_TO_TARGET_STATE` block comment "Each :data:`TransitionName` in the canonical 10-tuple"

`tests/unit/packs/test_lifecycle.py` — 2 sites:
- `:143` — "Pin the exact 13 legal ``(from, to)`` pairs across the 10 transitions"
- `:174` — "across all 10 transitions, exactly 13 legal"

`tests/unit/packs/test_lifecycle_audit.py` — 5 sites:
- `:29` — "The full 10-transition lifecycle"
- `:308` — "Walk a full 10-transition lifecycle slice"
- `:332` — "Walk the full 10-transition lifecycle"
- `:337` — "pack-record path touches all 10 transitions"
- `:524` — "outside the canonical 10-tuple :data:`TransitionName`"

`tools/check_critical_coverage.py` — 1 site:
- `:170-171` — docstring rationale "``_VALID_TRANSITIONS`` legal-pair table at :196 (10 transitions / 13 legal pairs)"

`AGENTS.md` — 1 site:
- `L123` — "`_VALID_TRANSITIONS` legal-pair table at `:196` (10 transitions / 13 legal pairs: 7 single-from + 3 multi-from × 2)" (Round 3 reviewer answer #5: lands at T4 alongside source changes, not deferred to T12)

**Total: 15 sites in 6 files.** Update each to "11 transitions / 14 legal pairs (7 single-from + 3 multi-from × 2 + cancel_draft single-from × 1)" or contextually equivalent phrasing. Also update any "canonical 10-tuple" → "canonical 11-tuple" and "10-value" → "11-value" hits per the patterns above.

**NOT TOUCHED (immutable per AGENTS.md "don't rewrite history") + self-exclusion per Round 5 P2 #1:**
- `docs/closeouts/2026-05-11-sprint-7b1-lifecycle-state-machine.md` (5 internal sites: L4, L17, L38, L80, L104 — all describe what 7B.1 shipped at write time; 7B.2 closeout records the count delta)
- `docs/superpowers/plans/2026-05-10-sprint-7b1-lifecycle-state-machine.md` (3 sites: L190-192, L440 — committed plan; cited counts were correct at write time)
- **`docs/superpowers/plans/2026-05-11-sprint-7b2-portal-api-rbac-owasp.md` (THIS plan file) per Round 5 P2 #1** — after T1 commit, this plan's own historical narrative (Round 0/0.5/0.6/1/2/3/4/5 patch log + inventory blocks + reviewer answers) will contain "10 transitions" / "13 legal pairs" / "13-value LifecycleRefusalReason" as historical record of the work. The plan IS the planning artifact for the work that creates the count transition; it becomes immutable history once committed. Mirrors the 7B.1-plan exclusion convention.

**T4 halt summary requirement (Round 3 P2 #6 + Sprint-7B.1 T8 doctrine §15-§20 cite-from-memory verification rules):** enumerate every one of the 15 touched sites by file:line + the exact pre/post wording + a `grep -rn` re-run AFTER the patch confirming zero residual "10 transitions" / "10-tuple" / "13 legal pairs" hits outside the immutable-doc set. **Halt summary explicitly proves the sweep is complete, not asserts it.**

**Endpoints (ADR-012 §55-59 + BUILD_PLAN §616):**

| Method | Path | Required scope + dependencies | Lifecycle action |
|---|---|---|---|
| POST | `/api/v1/packs/drafts` | `RequireScope("pack.submit")` | `save_draft(state="draft")`; pack `tenant_id` set from `actor.tenant_id` at creation time; `created_by` set from `actor.subject`. No `RequireTenantOwnership` (creating a draft — no existing pack to match against). |
| PUT | `/api/v1/packs/drafts/{id}` | `RequireScope("pack.submit")` + `RequireTenantOwnership(pack_id)` | `update_draft()` (new method on `PackRecordStore`; limited to allow-listed non-state fields). **Same-tenant author collaboration ALLOWED** per Round 7 P2 #4 (see "Draft ownership policy" subsection below) — any actor with `pack.submit` scope in the same tenant can update any draft owned by that tenant. Audit trail captured via `created_by` (original author, immutable) + `last_actor` (current modifier, bumped on every update). |
| POST | `/api/v1/packs/drafts/{id}/submit` | `RequireScope("pack.submit")` + `RequireTenantOwnership(pack_id)` | `transition("submit")` — `draft → submitted`. Conformance auto-run lives here at T9. Same-tenant author collaboration allowed per Round 7 P2 #4 — any actor with `pack.submit` scope in the same tenant can submit any draft owned by that tenant. |
| DELETE | `/api/v1/packs/drafts/{id}` | `RequireScope("pack.withdraw")` + `RequireTenantOwnership(pack_id)` | `transition("cancel_draft")` — `draft → withdrawn` via the NEW transition added in this task. The pre-existing `withdraw` transition still requires source state `submitted` or `under_review` per ADR-012 §39 — unchanged. **Same-tenant collaboration allowed per Round 8 P2 #3: gated by `pack.withdraw` scope (NOT `pack.submit`)** — any actor with `pack.withdraw` scope in the same tenant can cancel any tenant-owned draft. |

**Draft ownership policy (Round 7 P2 #4 resolution):**

The Round 1-6 endpoint narrative said PUT "requires (caller owns the draft)" but defined no concrete `RequireDraftOwnership` guard, refusal shape, or tests. Round 7 P2 #4 + Round 8 P2 #3 resolved this with **explicit same-tenant author collaboration policy** (option (b) from the reviewer), with scope-correct wording per Round 8 P2 #3:

- **What's allowed (scope-correct per Round 8 P2 #3):**
  - **CREATE** (POST `/drafts`): any actor with `pack.submit` scope can create drafts in their tenant
  - **UPDATE** (PUT `/drafts/{id}`): any actor with `pack.submit` scope in the SAME tenant as the draft can update it
  - **SUBMIT** (POST `/drafts/{id}/submit`): any actor with `pack.submit` scope in the same tenant can submit any tenant-owned draft
  - **CANCEL** (DELETE `/drafts/{id}`): any actor with **`pack.withdraw`** scope in the same tenant can cancel any tenant-owned draft (scope distinct from `pack.submit` per BUILD_PLAN §622 author-role-set: `pack.submit` + `pack.withdraw` are the TWO author scopes)
- **What's NOT allowed:** Cross-tenant access (enforced by `RequireTenantOwnership` at the route layer; 404 not 403). Drafts in non-draft states (enforced by storage-layer `update_draft` rowcount check + `cancel_draft` lifecycle table). Actors missing the relevant author scope (`pack.submit` for create/update/submit; `pack.withdraw` for cancel) refused by `RequireScope`.
- **Audit trail invariant:** `PackRecord.created_by` (at `storage.py:290`) captures the ORIGINAL author and is NEVER mutated by `update_draft` (it's in the 5-field immutable set: `tenant_id` / `state` / `kind` / `pack_id` / `created_by`). `PackRecord.last_actor` (at `:291`) is bumped on every `update_draft` + every `transition()` to the calling actor's `subject`. The `pack.lifecycle.submitted` and `pack.lifecycle.withdrawn` chain rows' `payload.actor_id` capture the SUBMITTING / CANCELLING actor (which may differ from `created_by` under same-tenant collaboration). Examiner audit replays the actor lineage via `(created_by, last_actor, chain-row actor_ids)` triple.
- **No `RequireDraftOwnership` guard** is introduced in 7B.2 — the existing `RequireScope(<author-scope>) + RequireTenantOwnership(pack_id)` pair is the complete authorization stack per scope-role.

**Tests pinning same-tenant collaboration across all three mutating paths (Round 8 P2 #4 — was only update; now also submit + cancel):**

- `test_author_routes.py::test_same_tenant_collaboration_allowed_on_draft_update` — actor B (different `subject` from original author A, same `tenant_id`, holds `pack.submit`) calls PUT on A's draft; succeeds; `created_by` remains A; `last_actor` becomes B.
- `test_author_routes.py::test_same_tenant_collaboration_allowed_on_draft_submit` — actor B (different from A, same tenant, holds `pack.submit`) calls POST `/submit` on A's draft; transition succeeds; `created_by` remains A; chain row's `payload.actor_id` is B's subject; `last_actor` becomes B.
- `test_author_routes.py::test_same_tenant_collaboration_allowed_on_draft_cancel` — actor B (different from A, same tenant, holds **`pack.withdraw`** — different scope from update/submit per Round 8 P2 #3 scope split) calls DELETE on A's draft; `cancel_draft` transition succeeds; `created_by` remains A; chain row's `payload.actor_id` is B's subject; `last_actor` becomes B.

**Negative scope-discipline tests (Round 9 P2 #2 — pin the `pack.submit` vs `pack.withdraw` split at the dedicated test layer, NOT via generic `test_rbac_enforcement_e2e.py`):**

- `test_author_routes.py::test_pack_submit_actor_cannot_cancel_draft` — actor holds `pack.submit` ONLY (NOT `pack.withdraw`), same tenant as draft → DELETE returns 403 with `RBACDenialReason("scope_not_held", required_scope="pack.withdraw")`. Asserts NO chain row written + NO state mutation. Pins that `pack.submit` does NOT implicitly grant `pack.withdraw` capability.
- `test_author_routes.py::test_pack_withdraw_actor_cannot_update_draft` — actor holds `pack.withdraw` ONLY (NOT `pack.submit`), same tenant as draft → PUT returns 403 with `RBACDenialReason("scope_not_held", required_scope="pack.submit")`. Asserts NO mutation of `last_actor`/`updated_at`/allow-listed fields.
- `test_author_routes.py::test_pack_withdraw_actor_cannot_submit_draft` — same actor profile (pack.withdraw only) → POST `/submit` returns 403 with `RBACDenialReason("scope_not_held", required_scope="pack.submit")`. Asserts NO chain row written + NO state transition.

These three negative tests + the three positive collaboration tests above ARE the scope-discipline regression set. They live in `test_author_routes.py` next to the positive cases (NOT in generic `test_rbac_enforcement_e2e.py`) so the author-scope split's contract surface is co-located in one file.

Plus cross-tenant 404 already pinned by `test_cross_tenant_returns_404`; actor without any author scope refused 403 already pinned by `test_rbac_enforcement_e2e.py`.

Halt summary watchpoints:
- (a) `cancel_draft` extension to `packs/lifecycle.py` is a CC-ADJ source change to a Sprint-7B.1 critical-controls module — gets its own R-round review tier
- (b) **Lockstep extension** (Round 4 P3 #6 — ownership spelled out): `lifecycle.py:_VALID_TRANSITIONS` (at `:196`) + `lifecycle.py:_TRANSITION_TO_ISO_CONTROLS` (at `:290-301`) + `storage.py:_TRANSITION_TO_TARGET_STATE` (at `:118`) + `lifecycle.py:TransitionName` Literal (at `:133`). 4 separate maps in 2 files; lifecycle.py owns 3, storage.py owns 1; pin via parametrized test that asserts the 4 sources agree on `cancel_draft → withdrawn`
- (c) Asymmetric-runtime-guard pattern preserved (3 instances from 7B.1 doctrine catalog §11 still fire; `cancel_draft` joins the legal vocabulary)
- (d) Tenant-isolation enforcement at every author-surface endpoint that takes a `{id}` path param — pinned by `test_author_routes.py::test_cross_tenant_returns_404` per Round 1 P2 #3
- (e) Idempotency on POST `/submit` — second submit on already-submitted pack returns 409 with closed-enum `lifecycle_transition_invalid_state_pair` from 7B.1
- (f) Audit-chain emission tagged with `pack.lifecycle.submitted` / `pack.lifecycle.withdrawn` namespace from 7B.1
- (g) **`update_draft` atomicity** (Round 4 P2 #3) — pinned by `test_storage_update_draft.py::test_concurrent_submit_loses_to_update_draft_atomic_update` integration test under `COGNIC_RUN_POSTGRES_INTEGRATION=1` / `COGNIC_RUN_ORACLE_INTEGRATION=1`; pin row-lock serialisation behaviour
- (h) **T4 doctrine-sweep evidence in halt summary** (Round 4 P2 #2 + P2 #4 + Round 5 P2 #1) — `grep -rn` AFTER patch over `src/ tests/ tools/ docs/ AGENTS.md` excluding THREE paths: (i) `docs/closeouts/2026-05-11-sprint-7b1-lifecycle-state-machine.md`, (ii) `docs/superpowers/plans/2026-05-10-sprint-7b1-lifecycle-state-machine.md`, (iii) **this 7B.2 plan file `docs/superpowers/plans/2026-05-11-sprint-7b2-portal-api-rbac-owasp.md`** (Round 5 P2 #1 self-exclusion — the plan contains its own historical narrative). Grep pattern: `10-tuple|10 transitions|10-transition|13 legal pairs|canonical 10`. Halt summary PASTES the post-patch grep output proving zero residual hits outside the 3-path exclusion set

---

### Task 5: Review surface endpoints — 5 endpoints *(CRITICAL CONTROLS)*

**Class:** CC. **Halt: YES.**

**Why CC:** Most consequential transitions per ADR-012 §84-105 — but Sprint 7B.2 does NOT enforce the 5-gate approval composition (that's 7B.3). The approve endpoint here is the surface that 7B.3's gate composer wires into.

**Files:**
- Create: `src/cognic_agentos/portal/api/packs/review_routes.py`
- Test: `tests/unit/portal/api/packs/test_review_routes.py`

**Endpoints (ADR-012 §61-66 + BUILD_PLAN §617):**

| Method | Path | Required scope + dependencies | Lifecycle action |
|---|---|---|---|
| GET | `/api/v1/packs?status=submitted` | `RequireScope("pack.review.claim")` (Round 2 P3 #8 — the reviewer queue is gated by the same scope that claims from it; examiner-facing `pack.audit.read` would lock reviewers out of their own queue per BUILD_PLAN §622-625 scope-set) | (read-only list scoped to actor.tenant_id; no per-pack tenant-isolation dependency since the list is filtered server-side) |
| POST | `/api/v1/packs/{id}/claim` | `RequireScope("pack.review.claim")` + `RequireTenantOwnership(pack_id)` | `transition("claim")` — `submitted → under_review` |
| POST | `/api/v1/packs/{id}/approve` | `RequireScope("pack.review.approve")` + `RequireTenantOwnership(pack_id)` | **FAIL-LOUD per Round 1 P2 #1.** Endpoint mounts; RBAC + tenant dependencies fire (so the auth trail records the attempt); on success path the handler raises `HTTPException(503, detail={"reason": "approve_gate_composer_not_wired", "next_sprint": "7B.3", "adr": "ADR-012 §41"})`. NO state transition. NO chain row emitted. NO green-path test in 7B.2 — only the fail-loud contract is pinned. |
| POST | `/api/v1/packs/{id}/reject` | `RequireScope("pack.review.reject")` + `RequireTenantOwnership(pack_id)` | `transition("reject")` — `under_review → rejected` with categorised reasons |
| GET | `/api/v1/packs/{id}/evidence` | `RequireScope("pack.audit.read")` + `RequireTenantOwnership(pack_id)` | (read-only evidence summary; full panels in 7B.3) |

**T5 caveat:** GET `/{id}/evidence` returns ONLY the conformance evidence attached by T9's auto-run-on-submit wire (read from the chain `payload.conformance` per the T9 schema fix in Round 1 P2 #4) — NOT the full reviewer evidence panels (those are 7B.3). Response shape includes `{"conformance": {...}, "reviewer_evidence_panels": null}` with `reviewer_evidence_panels` always null for Sprint 7B.2; 7B.3 fills in.

**Approve-endpoint fail-loud contract (Round 1 P2 #1 resolution):**

ADR-012 §41 requires `approve` to REFUSE when any of the 5 gates is red. Shipping a green-path `approve` that DOES the transition without enforcing the gates would either: (a) make the transition rollback-required when 7B.3 wires the gate composer in (data corruption risk if any pack got approved between 7B.2 land and 7B.3 land), or (b) silently violate ADR-012 §41 in production. Neither is acceptable per the production-grade rule.

Resolution: ship the endpoint as fail-loud `HTTPException(503)`. The endpoint surface exists; RBAC + tenant-isolation dependencies fire (so the auth + audit-trail-for-attempts works); the gate composer absence raises 503 with a structured payload pointing reviewers / authors at the next-sprint ETA. This matches the production-grade scaffold-with-fail-loud pattern documented in `protocol/mcp_host.MCPHost.call_tool` (Sprint-5 plan §T2 step 5 R3 P1 doctrine).

Halt summary watchpoints:
- (a) Approve endpoint NEVER transitions state in 7B.2 — pin via test that counts chain rows before + after an approve attempt and asserts equal
- (b) 503 + structured `reason: approve_gate_composer_not_wired` shape stable + closed-enum at module level
- (c) Closed-enum `RejectionReason` vocabulary at module level — categorised rejection reasons per ADR-012 §42 transition table
- (d) ADR-012 §17 cross-role separation — author cannot review their own pack (test pins via fixture-author actor calling `/claim` or `/reject` on own pack → 403)
- (e) Tenant-isolation enforcement at every review-surface endpoint that takes a `{id}` path param — pinned by `test_review_routes.py::test_cross_tenant_returns_404`
- (f) Audit-chain emission for `/claim` + `/reject` (NOT `/approve` — no chain row in 7B.2)

---

### Task 6: Operator surface endpoints — 5 endpoints *(CRITICAL CONTROLS)*

**Class:** CC. **Halt: YES.**

**Files:**
- Create: `src/cognic_agentos/portal/api/packs/operator_routes.py`
- Test: `tests/unit/portal/api/packs/test_operator_routes.py`

**Endpoints (ADR-012 §68-73 + BUILD_PLAN §618):**

| Method | Path | Required scope + dependencies | Lifecycle action |
|---|---|---|---|
| POST | `/api/v1/packs/{id}/allow-list` | `RequireScope("pack.allow_list")` + `RequireTenantOwnership(pack_id)` + **`RequireHumanActor()` per Round 1 P3 #8** | `transition("allow_list")` — `approved → allow_listed`. **The human-actor-type guarantee is an explicit dependency: service-token actors with `pack.allow_list` scope are REFUSED here with 403 + closed-enum `actor_type_must_be_human`. Pinned by test `test_operator_routes.py::test_allow_list_refuses_service_actor` per Round 1 reviewer answer #1.** |
| POST | `/api/v1/packs/{id}/install` | `RequireScope("pack.install")` + `RequireTenantOwnership(pack_id)` | `transition("install")` — `allow_listed → installed` |
| POST | `/api/v1/packs/{id}/disable` | `RequireScope("pack.disable")` + `RequireTenantOwnership(pack_id)` | `transition("disable")` — `installed → disabled` |
| POST | `/api/v1/packs/{id}/revoke` | `RequireScope("pack.revoke")` + `RequireTenantOwnership(pack_id)` | `transition("revoke")` — `installed/disabled → revoked` |
| DELETE | `/api/v1/packs/{id}/install` | `RequireScope("pack.uninstall")` + `RequireTenantOwnership(pack_id)` | `transition("uninstall")` — `disabled/revoked → uninstalled` |

**Allow-list human-actor doctrine (Round 1 P3 #8 + reviewer answer #1 resolution):**

AGENTS.md "Human-only decisions" lists "Per-tenant allow-list changes" — binding Claude (the AI assistant), but the reviewer's concern is broader: a scoped SERVICE-TOKEN actor (e.g. a CI/CD system holding `pack.allow_list`) silently becoming the human-approval path is exactly the failure mode the rule guards against. Resolution: the `Actor` model carries a closed-enum `actor_type` field (`"human"` / `"service"`); the `RequireHumanActor()` dependency on `/allow-list` ONLY refuses service tokens, not the AI-assistant case (which is upstream — Claude never holds a bank's actor token in production). Bank-overlay binders are responsible for setting `actor_type` correctly when minting actor identities from the underlying auth backend (OIDC token scope, mTLS cert OU, etc).

Halt summary watchpoints:
- (a) Multi-from transitions (`revoke` accepts both `installed` and `disabled`; `uninstall` accepts both `disabled` and `revoked`) — pin via parametrized green-path tests over the 7B.1 `_VALID_TRANSITIONS` table
- (b) Allow-list human-actor-type guarantee — pinned by `test_allow_list_refuses_service_actor` + `test_allow_list_admits_human_actor`
- (c) Tenant-isolation enforcement at every operator-surface endpoint — pinned by `test_cross_tenant_returns_404`
- (d) Audit-chain emission for each transition (allow-list audit row must record `actor.actor_type == "human"` in payload for examiner traceability)
- (e) Idempotency: re-revoke on already-revoked returns 409 with closed-enum `LifecycleTransitionRefused("lifecycle_transition_revoke_already_revoked")` from 7B.1

---

### Task 7: Inspection surface endpoints — 4 endpoints *(not-CC)*

**Class:** NOT-CC.

**Why not-CC:** Read-only inspection; no state transitions; no governance side-effects beyond audit-read.

**Files:**
- Create: `src/cognic_agentos/portal/api/packs/inspection_routes.py`
- Test: `tests/unit/portal/api/packs/test_inspection_routes.py`

**Endpoints (ADR-012 §75-79 + BUILD_PLAN §619):**

| Method | Path | Required scope + dependencies | Behavior |
|---|---|---|---|
| GET | `/api/v1/packs` | `RequireScope("pack.audit.read")` | List packs **scoped to actor.tenant_id**; cross-tenant rows filtered server-side. Inspection is examiner-facing per ADR-012 §75. |
| GET | `/api/v1/packs/{id}` | `RequireScope("pack.audit.read")` + `RequireTenantOwnership(pack_id)` | Pack detail incl. lifecycle history (read from `packs/storage`'s state cache) |
| GET | `/api/v1/packs/{id}/audit` | `RequireScope("pack.audit.read")` + `RequireTenantOwnership(pack_id)` | Hash-chained audit events for this pack — reads via `DecisionHistoryStore` filtered by `payload.pack_id` (per the `_load_for_pack_id` pattern at `packs/storage.py:565-606`) |
| GET | `/api/v1/packs/{id}/invocations?from&to` | `RequireScope("pack.invocation.read")` + `RequireTenantOwnership(pack_id)` | Pack invocation history derived from audit events. **Sprint 7B.2 scope:** returns audit-derived invocation events only; deeper analytics deferred. |

Pagination + cursor handling: reuse the bounded-pagination + opaque-cursor pattern from `protocol/mcp_host.py` (Sprint-5 doctrine). Tests pin cursor opacity + per-tenant scoping + cross-tenant refusal.

**Tenant-isolation tests for the inspection surface (Round 1 P2 #3):**

- `test_list_filters_by_tenant_id` — list endpoint returns ONLY actor.tenant_id rows; pack from tenant B is not in tenant A's list
- `test_detail_cross_tenant_returns_404` — GET `/{id}` for a pack belonging to tenant B from a tenant-A actor returns 404 (not 403 — info-leak prevention)
- `test_audit_cross_tenant_returns_404` — same for `/{id}/audit`
- `test_invocations_cross_tenant_returns_404` — same for `/{id}/invocations`

Standard TDD steps; no halt (read-only inspection; tenant isolation covered at the dependency level via the route-level guard from T2).

---

### Task 8: OWASP conformance check matrix *(CRITICAL CONTROLS)*

**Class:** CC. **Halt: YES.**

**Why CC:** Security-bearing check matrix. The OWASP categories the suite executes ARE the wire-protocol contract for reviewer evidence (T9 attaches results to evidence; 7B.3 reviewers see the same set).

**Files:**
- Create: `src/cognic_agentos/packs/conformance/__init__.py`
- Create: `src/cognic_agentos/packs/conformance/checks.py`
- Create: `src/cognic_agentos/packs/conformance/owasp_agentic.py`
- Test: `tests/unit/packs/conformance/__init__.py`
- Test: `tests/unit/packs/conformance/test_owasp_checks.py`
- Test: `tests/unit/packs/conformance/test_owasp_runner.py`

**Check categories (BUILD_PLAN §628 + ADR-012 §119):**

OWASP Top 10 for Agentic Applications 2026 + Agentic Skills Top 10 — concretely 10 categories implemented as 10 individual check functions. **Input shape**: `manifest: dict[str, Any]` — the parsed manifest dict (same shape `cli/validate.py` consumes). NOT a `PackRecord` (which doesn't carry the manifest server-side per Round 1 P2 #4). Callers (T9 submit endpoint; T10 CLI; T11 test-harness) pass the manifest dict from the request body / from disk.

1. `check_tool_misuse(manifest)` — pack declares tools / capabilities that match its declared kind + risk tier per ADR-014
2. `check_goal_hijacking(manifest)` — manifest's prompt / system-prompt declarations don't contain injection-style escape sequences
3. `check_identity_abuse(manifest)` — manifest's `[identity]` block fields per Sprint 7A `cli/validators/identity.py` are well-formed (delegates)
4. `check_prompt_injected_skills(manifest)` — skill packs declare inputs that pass syntactic injection-pattern checks
5. `check_dependency_poisoning(manifest)` — manifest declares dependencies with pinned versions + signed-artefact digest matches
6. `check_secret_exfiltration(manifest)` — manifest's `[data_governance].egress_allow_list` is non-empty + DLP hooks declared for sensitive data classes per Sprint 7A2 `cli/validators/data_governance.py`
7. `check_unsafe_filesystem(manifest)` — manifest does not declare filesystem-read or filesystem-write capabilities outside the sandbox profile from ADR-004
8. `check_unsafe_network(manifest)` — manifest's network egress declarations match the `[data_governance].egress_allow_list`
9. `check_supply_chain_integrity(manifest)` — Sprint 7A `cli/validators/supply_chain.py` attestation paths are non-empty + reachable
10. `check_skills_top_10(manifest)` — Agentic Skills Top 10 composite check (skill-pack-specific: tool composition safety, skill prompt isolation, etc.)

Each check returns `ConformanceCheckResult(category, status: Literal["pass", "fail", "not_applicable"], findings: list[str])`. `not_applicable` covers e.g. `check_skills_top_10` against a `hook` pack.

`run_owasp_conformance(manifest) -> ConformanceReport` runs all 10; report contains per-category result + overall status (`green` / `red` / `yellow` for partial) + summary.

Halt summary watchpoints:
- (a) Closed-enum `OWASPCheckCategory` 10-value literal stability
- (b) Per-check pass-shape + fail-shape pinning (each check has at least one fixture pack that passes and one that fails)
- (c) Cross-pack-kind applicability — which checks are `not_applicable` for which kinds (4-kind matrix: tool / skill / agent / hook); tested per-kind
- (d) Composite report shape — `ConformanceReport.status` is `red` if any check is `fail`; `green` only if all are `pass` or `not_applicable`

---

### Task 9: Auto-run conformance on submit transition *(CRITICAL CONTROLS)*

**Class:** CC. **Halt: YES.**

**Why CC:** Extends `packs/storage.py` (existing CC module from 7B.1 T3). Wire ties OWASP suite into the atomic transition primitive — must preserve Doctrine Lock D (atomic chain-insert + state-cache UPDATE + chain-head UPDATE under single transaction).

**Round 1 P2 #4 schema fix — actual fields verified at file:line before this rewrite:**

The Round 0 plan referenced two non-existent surfaces:

- **`DecisionRecord.decision_inputs.evidence`** — does not exist. The real field is `DecisionRecord.payload: dict[str, Any]` at `core/decision_history.py:242`. The submit transition's existing payload shape (at `packs/storage.py:512-520`) is already a flat dict with keys `pack_id` / `kind` / `from_state` / `to_state` / `transition_name` / `evidence_pointer` / `iso_controls`.
- **`PackRecordStore.read_manifest(pack_id)`** — does not exist. `PackRecord` (at `packs/storage.py:268-293`) persists `manifest_digest: bytes` ONLY; the full manifest is NOT stored server-side in 7B.1. The full manifest comes from the submit request body.

**Real schema design:**

1. **Manifest source:** the submit endpoint accepts the manifest dict as part of the request body (`SubmitDraftRequest.manifest: dict[str, Any]` in `dto.py`). The author CLI/SDK has the manifest locally (or fetches it from the artefact registry by digest); sends it as JSON in the POST body. Server-side validation: `hashlib.sha256(canonical_bytes(manifest)).digest() == pack.manifest_digest` — request manifest must match the persisted digest. Mismatch returns 400 with `manifest_digest_mismatch`. Pinned by `test_submit_refuses_manifest_digest_mismatch`.
2. **Conformance result location in the chain payload:** extend the existing `payload={...}` dict at `packs/storage.py:512-520` with a NEW optional top-level key `conformance: dict[str, Any] | None` (omitted for non-submit transitions; populated by the submit-route only). This is a payload-schema extension, NOT a canonical-form change — the canonical-form algorithm at `core/canonical.py` is unchanged; only the JSON content of an individual chain row gains a new top-level key. **AGENTS.md "Hash-chain canonical-form" stop rule does NOT apply** — that rule governs the canonicalisation algorithm itself, not what fields appear in `payload`. T9 confirms this in the halt summary.
3. **`evidence_pointer` field semantics:** kept as-is. The pointer is a string reference for future side-table storage (Sprint 7B.3 evidence-panels work owns the side-table design). 7B.2 leaves `evidence_pointer` as `None` on the submit transition; the conformance JSON lives directly in `payload.conformance`.

**Files:**
- Create: `src/cognic_agentos/packs/conformance/runner.py`
- Modify: `src/cognic_agentos/packs/lifecycle.py` — **NEW per Round 4 P2 #1** — bump `LifecycleRefusalReason` Literal **13 → 14 values** by adding `lifecycle_transition_manifest_digest_changed_during_submit` at `lifecycle.py:165-179`. This is a CC-ADJ source change to the Sprint-7B.1 critical-controls module; gets its own R-round review tier per AGENTS.md "no casual refactors" rule. Mirrors T4's `cancel_draft` CC-ADJ pattern.
- Modify: `src/cognic_agentos/packs/storage.py` — (a) extend `transition()` signature with TWO new optional keyword-only kwargs: `payload_conformance: dict[str, Any] | None = None` AND `expected_manifest_digest: bytes | None = None`; (b) capture `payload_conformance` in `_build_record` BEFORE the closure (no I/O inside the closure); merge into the payload dict at `:512-520` when not None; (c) **extend the `SELECT ... FOR UPDATE` query at `:469` per Round 5 P3 #4** from `select(_packs.c.state, _packs.c.kind)` to `select(_packs.c.state, _packs.c.kind, _packs.c.manifest_digest)`; capture `manifest_digest` in the closure alongside the existing `state` + `kind`; (d) **inside the existing `_precondition` closure at `:458` (after the row lock returns at `:473`)** verify `row.manifest_digest == expected_manifest_digest` when the kwarg is provided (skip the check when `expected_manifest_digest is None` — preserves backward compatibility for non-submit transitions); mismatch raises `LifecycleTransitionRefused("lifecycle_transition_manifest_digest_changed_during_submit")` from inside the closure so `engine.begin()` at `core/decision_history.py:482` rolls back atomically (Doctrine Lock D preserved; T7 R7 propagation contract honored — storage does NOT catch the exception); (e) `_build_record` signature continues to capture only `(from_state, kind)` — the `manifest_digest` is checked-then-discarded inside the closure; the chain row payload does NOT carry `manifest_digest` (it's already in the persisted pack row + already keyed to the chain row via `pack_id`). **Preserve Doctrine Lock D** — conformance runs OUTSIDE the closure (in the route handler before calling `transition()`); the kwarg is a captured dict, no I/O inside the closure.
- Modify: `src/cognic_agentos/portal/api/packs/dto.py` — extend `SubmitDraftRequest` with `manifest: dict[str, Any]` field; add `manifest_digest_mismatch` to a route-level closed-enum
- Modify: `AGENTS.md:L123` — **NEW per Round 4 P2 #1 + P2 #2** — update the `LifecycleRefusalReason` 13-value enumeration to 14-value by adding `lifecycle_transition_manifest_digest_changed_during_submit` to the parenthesised list. T4 has already edited the same line for the transition-count phrase ("10 transitions / 13 legal pairs" → "11 transitions / 14 legal pairs"); T9 adds the 14th LifecycleRefusalReason value to the same line. Both edits are surgical text replacements at well-defined sub-strings; no conflict expected.
- Modify: `tools/check_critical_coverage.py:167` — **NEW per Round 4 P2 #1 + P2 #2 + Round 5 P2 #2** — bump docstring rationale "Closed-enum **13-value** ``LifecycleRefusalReason``" → "Closed-enum **14-value** ``LifecycleRefusalReason``" at exactly line 167 (verified via grep at plan-write time)

**T9 LifecycleRefusalReason 13→14 sweep site inventory** (Round 5 P2 #2 — enumerated explicitly, mirroring T4's 15-site inventory pattern. Verified at plan-write time via `grep -rn "13-value\|13 values\|13 reasons\|LifecycleRefusalReason" src/ tests/ tools/ docs/ AGENTS.md` excluding the same 3-path exclusion set as T4):

`src/cognic_agentos/packs/lifecycle.py` — 2 sites:
- `:146` — comment "13-value closed-enum refusal reasons (Doctrine Lock C, finalised at T2 ...)" → "14-value closed-enum refusal reasons (extended Sprint 7B.2 T9 to add manifest-digest-changed-during-submit precondition refusal)"
- `:165-179` — `LifecycleRefusalReason = Literal[...]` definition; extend with 14th value `"lifecycle_transition_manifest_digest_changed_during_submit"`

`src/cognic_agentos/packs/storage.py` — 1 site:
- `:50` — module docstring "(13 reasons)" → "(14 reasons)"

`tests/unit/packs/test_lifecycle.py` — 3 sites (verified via grep at plan-write time; explicit line numbers from grep run at Round 5 plan-write):
- `:70` — comment "Doctrine Lock C — 13 values, finalised at T2 R1 P2" → "Doctrine Lock C — 14 values (13 finalised at T2 R1 P2; +1 at Sprint 7B.2 T9 for manifest-digest-precondition refusal)"
- `:77` — `assert set(get_args(LifecycleRefusalReason)) == {...}` literal enumeration; extend with the 14th string value
- `:234` — `_REASON_TO_FROM_TO_MATRIX` parametrize / emittable-count comment "(12 ...)"; extend with the new value's emit context (or bump count if expressed as a literal)

`AGENTS.md` — 1 site (shared with T4 at the same line):
- `L123` — extend the parenthesised 13-value enumeration with `…_manifest_digest_changed_during_submit` as the 14th value AND bump the "13-value" prefix to "14-value". T4 edits the SAME line for the separate transition-count phrase — both edits are surgical sub-string replacements at well-defined offsets

`tools/check_critical_coverage.py` — 1 site:
- `:167` — docstring rationale "Closed-enum **13-value** ``LifecycleRefusalReason``" → "Closed-enum **14-value** ``LifecycleRefusalReason``"

**Total: 8 sites in 5 files** (T9 sweep). NOT TOUCHED (same 3-path exclusion set as T4): `docs/closeouts/2026-05-11-sprint-7b1-lifecycle-state-machine.md` (multiple internal cites) + `docs/superpowers/plans/2026-05-10-sprint-7b1-lifecycle-state-machine.md` + THIS 7B.2 plan file (Round 5 P2 #1 self-exclusion).

**AuthzReason false-positive inventory (Round 6 P2 #1 — explicit enumeration):**

The bare grep `"13-value\|13 values\|13 reasons"` ALSO matches MCP `AuthzReason` citations across docs/ + tests/. These are intentionally UNCHANGED in 7B.2 (different enum from a different sprint, coincidentally same count). Sites verified via grep at plan-write time:

`tests/unit/protocol/` — 2 sites:
- `test_mcp_registration_auth_probe.py:8` — module docstring "(**13-value** AuthzReason; 11 of which reach ...)"
- `test_refusal_reason_completeness.py:238` — "The :data:`AuthzReason` literal has 13 values; 11 are ..."

`docs/closeouts/2026-05-03-sprint-5-mcp-host.md` — 3 sites (L14, L72, L111): "13-value closed-enum `AuthzReason`" / "13 values; 11 registration-boundary + 2 runtime-only" / etc.

`docs/superpowers/plans/2026-05-02-sprint-5-mcp-host.md` — 3 sites (L1307, L1369, L2315): "13 values total: 11 registration-boundary + 2 runtime-only" / etc.

**Total false positives: 8 sites in 4 files. All AuthzReason / MCP-Sprint-5. UNCHANGED in 7B.2.**

**Deterministic proof shape (Round 6 P2 #1 + Round 7 P2 #1 + Round 8 P2 #1 — per-site sed verification because count phrases and `LifecycleRefusalReason` literal often span DIFFERENT source lines):**

Single-line proximity grep is insufficient — Round 8 P2 #1 caught that 4 of the 8 sweep sites have the count phrase and `LifecycleRefusalReason` on different lines (verified at plan-write time): `storage.py:49-50` (LifecycleRefusalReason at :49, "(13 reasons)" at :50), `test_lifecycle.py:70`+`:77` (count comment at :70, `LifecycleRefusalReason` at :77), and the Literal definition at `lifecycle.py:165-179` which spans 15 lines. A multi-line `rg -U` regex works but is brittle; the cleaner proof is **per-site `sed -n` verification**.

**Halt summary proof shape:**

1. **Per-site verification** — for each of the 8 sweep sites, paste the relevant `sed -n` or `rg -n` output and assert post-patch text matches the expected:

   - `sed -n '146p' src/cognic_agentos/packs/lifecycle.py` → must contain "14-value"
   - `rg -n '^\s*"lifecycle_transition_manifest_digest_changed_during_submit",' src/cognic_agentos/packs/lifecycle.py` → returns **EXACTLY 1 hit** in the `:165-179` Literal range. **Member-line-anchored regex per Round 10 P2 #1** — `^\s*"<value>",` matches ONLY a quoted-string-literal followed by comma (i.e. an actual `Literal[...]` member), NOT a docstring/comment mention. The strict `== 1` count discriminates the source-of-truth member from any stray duplicate mention. Plus `sed -n '165,180p'` as supplementary range context.
   - `sed -n '50p' src/cognic_agentos/packs/storage.py` → must contain "(14 reasons)"
   - `sed -n '70p' tests/unit/packs/test_lifecycle.py` → must contain "14 values"
   - `rg -n '^\s*"lifecycle_transition_manifest_digest_changed_during_submit",' tests/unit/packs/test_lifecycle.py` → returns **EXACTLY 1 hit** in the `:77-92` `set(get_args(LifecycleRefusalReason))` literal range. Same member-line-anchored regex per Round 10 P2 #1 — matches only the actual set element, NOT any docstring / comment mention. The bare-value-name `rg -n "lifecycle_transition_manifest_digest_changed_during_submit"` introduced in Round 9 would have passed even if the value appeared only in a docstring; the anchored form makes the proof source-of-truth specific.
   - `sed -n '234p' tests/unit/packs/test_lifecycle.py` → emittable count bumped (12 → 13 emittable, OR phrasing updated)
   - `sed -n '123p' AGENTS.md` → must contain "14-value" + the new value name `lifecycle_transition_manifest_digest_changed_during_submit` in the enumeration
   - `sed -n '167p' tools/check_critical_coverage.py` → must contain "14-value"

2. **Negative LifecycleRefusalReason-specific sanity check (Round 9 P3 #4 — replaces brittle AuthzReason count==8 coupling)**: the 8 per-site checks above ARE the deterministic proof. AuthzReason historical references in Sprint-5 docs are NOT counted by any halt-summary check — they are informational only. If unrelated Sprint-5 doc edits drift the AuthzReason count, the 7B.2 halt summary does NOT fail because the 8 sweep sites' per-site sed/rg verification is independent of AuthzReason state. This eliminates the cross-sprint state coupling identified in Round 9 P3 #4.

Per-site sed/rg is deterministic by mechanical line-range or value-name match.
- Test: `tests/unit/packs/conformance/test_auto_run_on_submit.py`
- Test: `tests/unit/packs/test_lifecycle.py` (extend) — **NEW per Round 4 P2 #1** — bump the closed-enum vocabulary test at `TestSprint7B1ClosedEnumVocabulary` (pin `LifecycleRefusalReason` at 14 values; pin the new `lifecycle_transition_manifest_digest_changed_during_submit` value's presence; pin no 15th value sneaks in)
- Test: `tests/unit/packs/test_lifecycle_audit.py` (extend) — pin new `payload.conformance` shape in audit row for submit transitions; pin that non-submit transitions emit NO `payload.conformance` key; **NEW per Round 4 P2 #1** — pin the locked manifest-digest precondition fires from inside the closure on mismatch (no chain row + no state mutation + atomic rollback)
- Test: `tests/unit/packs/test_storage_transition_payload_schema.py` (NEW) — pin the exact payload-dict keyset for submit (includes `conformance`) vs other transitions (excludes `conformance`); canonical-form stability test (existing chain-verifier on a pre-T9 fixture chain still verifies green); **NEW per Round 4 P2 #1** — pin `expected_manifest_digest` kwarg behavior (None = no check; matched-digest = transition proceeds; mismatched-digest = refusal from inside row lock)

**Wire design (corrected — Round 2 P2 #7: full transition signature preserved; Round 3 P2 #5: locked manifest-digest precondition added):**

The current `PackRecordStore.transition()` signature at `packs/storage.py:360-369` is:

```python
async def transition(
    self,
    *,
    pack_id: uuid.UUID,
    transition: TransitionName,
    actor_id: str,
    tenant_id: str | None,
    evidence_pointer: str | None,
    request_id: str,
) -> tuple[uuid.UUID, bytes]:
```

T9 extends this with TWO new optional keyword-only kwargs — preserving all 6 existing required args:

1. `payload_conformance: dict[str, Any] | None = None` — captured into the chain payload at `_build_record` time (Round 2 P2 #7).
2. **`expected_manifest_digest: bytes | None = None` (Round 3 P2 #5)** — when provided, the precondition closure (already inside the `SELECT ... FOR UPDATE` row lock at `storage.py:467-473`) compares the locked-row's `manifest_digest` against `expected_manifest_digest`. Mismatch raises `LifecycleTransitionRefused("lifecycle_transition_manifest_digest_changed_during_submit")` — a NEW 14th value on the Sprint-7B.1 `LifecycleRefusalReason` literal (bumped 13 → 14 at T9; mentioned in T4's lifecycle.py modify scope above but **the value lands at T9** when wiring this race-condition fix).

The `evidence_pointer` field semantics stay as-is (string reference; reserved for 7B.3 side-table); the `request_id` is the FastAPI per-request UUID (already bound by `RequestIdMiddleware` in `portal/observability/`).

**Race-condition resolution (Round 3 P2 #5):**

Without the locked precondition check, the submit flow had a TOCTOU window: the route would (a) load `PackRecord` via `RequireTenantOwnership` (outside any row lock), (b) verify `body.manifest` digest matches `pack.manifest_digest`, (c) run conformance over `body.manifest`, (d) call `transition()` which then locks the row. Between (a) and (d), a concurrent `update_draft()` call could mutate `manifest_digest` — leaving the audit chain's `payload.conformance` describing a manifest that no longer matches the persisted pack row. Closing the window: pass `expected_manifest_digest=pack.manifest_digest` from the preloaded record into `transition()`; the precondition closure checks the locked row's digest matches; mismatch fails-closed with the new 14th refusal reason (no chain row written, no state mutation).

```python
# In author_routes.py (T4):
@router.post("/drafts/{pack_id}/submit")
async def submit_draft(
    request: Request,
    pack_id: UUID,
    body: SubmitDraftRequest,
    actor: Actor = Depends(RequireScope("pack.submit")),
    pack: PackRecord = Depends(RequireTenantOwnership("pack_id")),
    store: PackRecordStore = Depends(get_pack_record_store),
):
    # Cheap pre-check (defense-in-depth — the authoritative check is the
    # locked precondition inside transition()).
    if hashlib.sha256(canonical_bytes(body.manifest)).digest() != pack.manifest_digest:
        raise HTTPException(400, detail={"reason": "manifest_digest_mismatch"})
    # Conformance runs OUTSIDE the storage closure (pure function over the dict).
    conformance_report = run_owasp_conformance(body.manifest)
    # Pass two NEW kwargs into transition() alongside the existing 6 required
    # kwargs per the actual storage.py:360-369 signature. The locked
    # expected_manifest_digest check closes the TOCTOU window per Round 3 P2 #5.
    await store.transition(
        pack_id=pack_id,
        transition="submit",
        actor_id=actor.subject,
        tenant_id=actor.tenant_id,
        evidence_pointer=None,  # Reserved for 7B.3 side-table pointer
        request_id=request.state.request_id,  # Bound by RequestIdMiddleware
        payload_conformance=conformance_report.to_dict(),  # NEW T9 kwarg
        expected_manifest_digest=pack.manifest_digest,  # NEW T9 kwarg, Round 3 P2 #5
    )
    return {"pack_id": str(pack_id), "conformance": conformance_report.to_dict()}
```

**Round 2 reviewer answer on `payload.conformance` framing:** the conformance JSON IS evidence/wire-shape CC (the audit-chain payload is the wire-format for evidence-pack export per ADR-006). Adding a top-level optional key extends the payload SCHEMA; it does NOT touch the canonical-form ALGORITHM at `core/canonical.py`. T9 halt summary distinguishes: (a) the canonical-form algorithm (unchanged; algorithm-stability test passes against a pre-T9 fixture chain); (b) the payload schema (extended; tests pin the new optional key + the absence-of-key contract for non-submit transitions). Both are wire-shape concerns; (a) is the AGENTS.md stop-rule territory which 7B.2 does NOT enter; (b) is the per-transaction payload that 7B.2 extends within the existing CC perimeter.

Halt summary watchpoints:
- (a) Doctrine Lock D preservation — `payload_conformance` is captured by `_build_record` BEFORE the closure (no I/O inside the closure); pin via the same `engine.begin()` rollback test pattern from 7B.1 T3
- (b) Real schema fields — `DecisionRecord.payload` not `decision_inputs.evidence`; no `read_manifest` call (Round 1 P2 #4 fix). Halt summary explicitly cites `core/decision_history.py:242` + `packs/storage.py:512-520` to prove the fix landed against ground truth
- (c) Manifest-digest match check (request-body path) — pinned by `test_submit_refuses_manifest_digest_mismatch`
- (c.1) **Locked manifest-digest precondition (Round 3 P2 #5)** — pinned by `test_submit_refuses_manifest_digest_changed_during_submit` — fixture flow: route loads pack (digest A); concurrent `update_draft()` mutates digest to B; route's `transition()` call passes `expected_manifest_digest=A`; locked precondition reads digest B from row-locked SELECT and refuses with `LifecycleTransitionRefused("lifecycle_transition_manifest_digest_changed_during_submit")`; asserts chain row count unchanged + state unchanged + `payload.conformance` NOT written. Plus integration test under `COGNIC_RUN_POSTGRES_INTEGRATION=1` / `COGNIC_RUN_ORACLE_INTEGRATION=1` proving row-lock serialisation
- (d) Per BUILD_PLAN §627 — submission proceeds whether conformance green OR red; conformance result is EVIDENCE, not a gate (gate is 7B.3)
- (e) Canonical-form invariance — adding a new top-level key to `payload` is NOT a canonical-form-algorithm change (algorithm at `core/canonical.py` is unchanged); the per-transaction payload schema IS extended within the existing CC perimeter; pin via pre-T9 chain-verifier fixture still verifying green
- (f) `evidence_pointer` field stays `None` on submit transitions in 7B.2 — pinned by `test_storage_transition_payload_schema.py`; 7B.3 owns the side-table design for the pointer
- (g) Fail-loud on missing manifest — `run_owasp_conformance(None)` raises clear contract error
- (h) **`LifecycleRefusalReason` literal bumped 13 → 14 values** (`lifecycle_transition_manifest_digest_changed_during_submit` is the 14th, added at T9 per Round 4 P2 #1 — pin via parametrized test that enumerates all 14 values + asserts no 15th value sneaks in)
- (i) **T9 doctrine sweep (Round 4 P2 #1 + Round 5 P2 #2 + Round 6 P2 #1 + Round 7 P2 #1 + Round 8 P2 #1 + Round 9 P2 #1 + P3 #4 + Round 10 P2 #1 anchored-member-line)** — T9 owns the `LifecycleRefusalReason` 13→14 sweep over **8 sites in 5 files**: `lifecycle.py:146` + `:165-179` + `storage.py:50` + `test_lifecycle.py:70` + `:77` + `:234` + `AGENTS.md:L123` + `tools/check_critical_coverage.py:167`. Halt summary uses **per-site `sed -n` / anchored `rg -n` verification**: 6 sites use `sed -n '<line>p'` for single-line citations; 2 sites use member-line-anchored `rg -n '^\s*"lifecycle_transition_manifest_digest_changed_during_submit",' <file>` returning **EXACTLY 1 hit** each for the multi-line Literal definitions at `lifecycle.py:165-179` + `test_lifecycle.py:77-92` (Round 10 P2 #1 fix — the `^\s*"<value>",` regex matches ONLY a quoted-string-literal-followed-by-comma, i.e. an actual `Literal[...]` member or set element, NOT a docstring/comment mention; strict `== 1` count is the deterministic proof of source-of-truth enum membership). Round 9 P3 #4: AuthzReason historical sites are informational ONLY — NOT count-gated. The 8 per-site checks ARE the deterministic proof
- (j) **T4 PackRecordRefusalReason 1→4 doctrine sweep (Round 6 P2 #2 + Round 7 P2 #2 + Round 8 P2 #2 per-site sed)** — at T4 (NOT T9): **6 sites in 3 files** (`storage.py:42-43` + `:232` + `:235` + `:241` + `tools/check_critical_coverage.py:224` + `AGENTS.md:L124`). Halt summary uses **per-site `sed -n '<line>p' <file>`** verification (Round 8 P2 #2 — single-line proximity grep can't match `storage.py:231-232` + `:239-241` where `save_draft` and `Wave-1` are on different source lines). 6 sed commands per site PASTED in halt summary. Negative sanity grep `grep -rn -E "1-value.{0,20}PackRecordRefusalReason|PackRecordRefusalReason.{0,20}1-value"` (3-path exclusion) returns ZERO hits post-patch — catches single-line residuals; split-line residuals caught by per-site sed. `docs/PACK-MANIFEST-SPEC.md:222` hook-fail-policy spec doesn't match the narrowed grep (different vocabulary)

---

### Task 10: `agentos conformance` CLI extension *(not-CC)*

**Class:** NOT-CC.

**Why not-CC:** Thin CLI wrapper over `run_owasp_conformance`. Same not-CC pattern as Sprint 7A `agentos validate` was at its first landing.

**Files:**
- Create: `src/cognic_agentos/cli/conformance.py`
- Modify: `src/cognic_agentos/cli/__init__.py` — register NEW `conformance` subcommand only via `@app.command()`; mirrors the existing `validate` registration at `cli/__init__.py:441`. **T10 does NOT touch the existing `test-harness` registration at `cli/__init__.py:475`** — that command already exists from Sprint-7A T13; T11 modifies the existing handler module body, not the registration.
- Test: `tests/unit/cli/test_conformance_cli.py`

**Command:** `agentos conformance <pack_path> [--json | --text]`

Exit codes: 0 = green, 1 = red, 2 = invocation error (missing manifest, etc).

Standard TDD steps; no halt.

---

### Task 11: `agentos test-harness` OWASP conformance integration *(CC-ADJ — not-CC)*

**Class:** CC-ADJ to `cli/test_harness.py` (existing Sprint-7A T13 hybrid runner, 1321 lines). No halt — extension is narrow and the wrapped runner is already off the critical-controls floor per its own provenance docstring (Sprint-7A T13 R4 P3 #5 — public command, NOT test-only path, off-floor because every gate it surfaces is enforced upstream by `cli/validate.run_validators`).

**Why narrow (Round 1 P2 #6 + reviewer answer #4 resolution):**

ADR-012 §114-122 specifies a "fixture-only AgentOS instance" harness that loads packs against "fixture-based guardrails, audit chain, decision history, sandbox policy". The current `cli/test_harness.py` is NOT that — it's a manifest-parse + validate-pipeline + per-kind SDK-seam dry-run runner. Shipping the full ADR-012 §114-122 fixture-AgentOS harness would require: (a) a fixture-mode AgentOS instance factory, (b) fixture guardrails / audit / decision-history / sandbox wiring, (c) a per-pack fixture-loading contract. Each is a sprint of work on its own. **DEFERRED post-7B per the Round 1 reviewer answer #4 acknowledgement.**

T11 in 7B.2 ships ONLY the OWASP integration tail-call: after the existing test-harness validate-pipeline + per-kind dry-run dispatch completes green, run `run_owasp_conformance(manifest)` and surface the report in the harness output. Sub-scope:

**Files:**
- Modify: `src/cognic_agentos/cli/test_harness.py` — add OWASP conformance tail-call after the existing per-kind dispatch loop; surface `conformance.green` / `conformance.findings` in the harness output JSON
- Test: `tests/unit/cli/test_test_harness_owasp_integration.py` — pin OWASP tail-call fires after dry-run; pin a fixture pack that passes dry-run but fails one OWASP check surfaces the failure; pin the deferred-full-harness boundary (T11 does NOT load packs into a fixture AgentOS instance; explicit assertion that no `AgentOS` / `core/audit` / `sandbox` instances are spun up in the test)

**Re-scope notation in plan + closeout:** the harness fixture-AgentOS-instance work is explicitly OUT of 7B.2 scope; out-of-scope section already updated. T13 closeout includes a sprint-allocation table row stamping ADR-012 §114-122 as "DEFERRED post-7B" with a placeholder Sprint identifier (probably 7C or later).

Standard TDD steps; no halt (CC-ADJ to a thin SDK extension over an off-floor existing module).

---

### Task 12: AGENTS.md subsection + critical-controls floor uplift *(CRITICAL CONTROLS — doctrine)*

**Class:** CC-doctrine. **Halt: YES.**

**Why CC-doctrine:** Mirrors Sprint 7B.1 T7. Adds the `## Authoring — Bank pack lifecycle portal API (Sprint 7B.2)` subsection to AGENTS.md with bullet-per-new-CC-module entries (**11 modules** per "Critical-controls forecast" after Round 1 patches: 5 RBAC + 3 endpoint surfaces + 3 conformance). Bumps `tools/check_critical_coverage.py` floor **43 → 54** (+11). Also documents the CC-source touches at T4 (`packs/lifecycle.py` cancel_draft extension) + T9 (`packs/storage.py` payload-conformance extension) + T11 (`cli/test_harness.py` OWASP tail-call) — no re-promotion needed since lifecycle / storage are already CC; test-harness stays off-floor by Sprint-7A T13 R4 P3 #5 provenance.

**Files:**
- Modify: `AGENTS.md` — new subsection L~125 (after the 7B.1 subsection); enumerates 11 new CC modules with file:line citations verified at T12 compose time
- Modify: `tools/check_critical_coverage.py` — bump floor 43 → 54 + add 11 new module entries with rationale lines:
  1. `portal/rbac/scopes.py` — closed-enum scope literal IS wire-protocol for RBAC denials
  2. `portal/rbac/actor.py` — identity boundary + production-grade fail-loud default
  3. `portal/rbac/enforcement.py` — RequireScope dependency + RBACDenialReason closed-enum
  4. `portal/rbac/tenant_isolation.py` — Round 1 P2 #3 + T2 R1 P2 #1 — cross-tenant 404 + 4-value `TenantIsolationFailure` closed-enum (`tenant_id_mismatch` / `pack_not_found` / `actor_tenant_id_missing` / `pack_store_not_configured`)
  5. `portal/rbac/human_actor.py` — Round 1 P3 #8 — actor-type human-only guarantee for allow-list
  6. `portal/api/packs/author_routes.py` — wire-protocol-public author surface
  7. `portal/api/packs/review_routes.py` — wire-protocol-public review surface (approve fail-loud per P2 #1)
  8. `portal/api/packs/operator_routes.py` — wire-protocol-public operator surface
  9. `packs/conformance/checks.py` — security-bearing OWASP check matrix
  10. `packs/conformance/owasp_agentic.py` — top-level OWASP runner
  11. `packs/conformance/runner.py` — auto-run-on-submit integration

Halt summary watchpoints:
- (a) Cite-from-memory verification — every signature / class name / closed-enum count cited in the AGENTS.md subsection MUST be verified at file:line within the same compose pass per `feedback_verify_code_citations_at_doc_write.md`
- (b) Closed-enum value counts (new in 7B.2): `PackRBACScope` (12 — BUILD_PLAN §622-625 verbatim, NOT the closeout-L119 cite-from-memory typo "14"), `RBACDenialReason` (3), `TenantIsolationFailure` (**4** — Round 1 P2 #3 originated at 3; T2 R1 P2 #1 added `pack_store_not_configured` for symmetric missing-store defence), `ActorType` (2 — Round 1 P3 #8), `RequireHumanActor` denial reason (1 value `actor_type_must_be_human`), `OWASPCheckCategory` (10) — all pinned with concrete tests T2 / T8
- (b.1) Closed-enum value counts (extended from 7B.1 in 7B.2): `TransitionName` Literal **10 → 11** values (added `cancel_draft` at T4 per Round 1 P2 #2 + Round 2 P2 #6); `PackRecordRefusalReason` Literal **1 → 4** values (added `pack_record_update_non_draft_state` + `pack_record_update_field_not_allowed` + `pack_record_update_field_invalid_shape` at T4 per Round 2 P2 #5 + Round 3 P2 #4 + **Round 6 P3 #4 value-shape validation**); **`LifecycleRefusalReason` Literal 13 → 14 values** (added `lifecycle_transition_manifest_digest_changed_during_submit` at T9 per Round 3 P2 #5 race-condition fix); `_VALID_TRANSITIONS` map size 10 → 11 keys / 13 → 14 legal pairs; doctrine-citation sweep enumerated at T4 covers **15 sites in 6 files** for transition counts + **6 sites in 3 files for PackRecordRefusalReason 1→4** (Round 6 P2 #2 + Round 7 P2 #2 corrected count from 4 → 6 adding `storage.py:232` + `:241`); T9 owns **8 sites in 5 files for LifecycleRefusalReason 13→14**; same 3-path exclusion set used across all sweeps; halt-summary proof uses per-site `sed -n` verification per Round 8 P2 #1 + P2 #2
- (c) Cross-reference to ADR-012 §39 + §54-79 + §107-110 + §114-122 + BUILD_PLAN §615-630
- (d) Critical-controls floor uplift +11: list each new module + its rationale per AGENTS.md "Critical-controls rule" format
- (e) CC-source touches in 7B.1 modules (`packs/lifecycle.py` from T4; `packs/storage.py` from T9; `cli/test_harness.py` from T11) referenced from the 7B.2 subsection — no re-promotion needed

---

### Task 13: Closeout + BUILD_PLAN §602 status flip + Sprint 7B.3 hand-off *(CRITICAL CONTROLS — doctrine)*

**Class:** CC-doctrine. **Halt: YES.**

**Why CC-doctrine:** Mirrors Sprint 7B.1 T8.

**Files:**
- Create: `docs/closeouts/2026-05-1X-sprint-7b2-portal-api-rbac-owasp.md` (~145 lines mirroring 7B.1 closeout structure)
- Modify: `docs/BUILD_PLAN.md` §602 — flip 7B.2 status row to CLOSED with branch tip
- Verify: AGENTS.md + coverage-gate already patched by T12

Closeout structure (mirroring `docs/closeouts/2026-05-11-sprint-7b1-lifecycle-state-machine.md`, plus Round 8 reviewer answer #5 navigation-map requirement):

1. Header + sub-sprint allocation context
2. Deliverables landed (per-task table)
3. CI gates table (ruff / format / mypy / pytest / critical-controls coverage)
4. Doctrine adherence (per-doctrine bullet)
5. New doctrines established this sprint
6. ADR validation table
7. **Final reference table (NEW per Round 8 reviewer answer #5)** — consolidates the 8-review-round patch surface into a single navigation map:
   - (a) New closed-enum vocabularies (PackRBACScope, RBACDenialReason, TenantIsolationFailure, ActorType, RequireHumanActor denial, OWASPCheckCategory) — value counts + module paths
   - (b) Cross-sprint 7B.1 closed-enum extensions (TransitionName 10→11, PackRecordRefusalReason 1→4, LifecycleRefusalReason 13→14) — count deltas + owner task + sweep site count
   - (c) Doctrine sweep paths exclusion set (3 paths)
   - (d) New CC modules (11) — module path + rationale + owner task
   - (e) Cross-sprint CC source touches (lifecycle.py + storage.py + cli/test_harness.py) — what was extended + which Sprint-7B.1 invariants preserved (Doctrine Locks C/D + asymmetric-runtime-guard pattern)
   - (f) Deferred-to-7B.3/7B.4 work (5-gate composer, evidence panels, UI event streams, RBAC denial chain events, fixture-AgentOS harness, fail_open_exception) — owner sprint + reason
8. Sprint 7B.3 hand-off checklist (evidence panels + 5-gate approval composition wired into approve endpoint + override path)
9. Sprint 7B.4 hand-off carry-forward
10. Carryover
11. Out of scope
12. Next sprint

Halt summary watchpoints:
- (a) Per-citation verification within doctrine surfaces (anchor-only verification is insufficient per T8 R6 lesson §20)
- (b) Suite-size delta measurement (Sprint 7B.1 baseline 4370; Sprint 7B.2 projected ~4490-4510)
- (c) Critical-controls coverage at commit-time per module (each new CC module: line ≥95% / branch ≥90%)
- (d) Sprint 7B.3 hand-off checklist completeness — every BUILD_PLAN §632-636 deliverable enumerated
- (e) **Final reference table completeness (Round 8 reviewer answer #5)** — all 6 sub-sections (a–f) populated; future implementer can navigate the 1286-line plan via this single table without re-reading every patch-log round

---

## Self-Review patch log

Run inline self-review before halting for user doctrine review.

### Round 0 — initial draft

- [x] Spec coverage check: every BUILD_PLAN §615-630 deliverable + every closeout-7B.1 hand-off bullet maps to T2-T11
- [x] Placeholder scan: no "TBD" / "implement later" / "similar to X" — every step has concrete code or explicit doctrine cross-check
- [x] Type consistency: `PackRBACScope` / `Actor` / `RBACDenialReason` / `OWASPCheckCategory` / `ConformanceCheckResult` / `ConformanceReport` referenced consistently across T2 / T8 / T9
- [x] Scope check: NOT a multi-subsystem plan — single-sprint scope = portal API surface for 7B.1's lifecycle state machine
- [x] CC vs not-CC mapping matches AGENTS.md stop rules + critical-controls rule (RBAC subsystem; wire-protocol-public endpoints; security-bearing conformance suite; storage extension)
- [x] Out-of-scope section explicitly enumerates deferrals to 7B.3 / 7B.4 / bank-overlay
- [x] Doctrine map ties each deliverable to its source ADR / BUILD_PLAN §
- [x] Halt-before-commit cadence specified per CC task with concrete watchpoints
- [x] Gate-ladder per `feedback_gate_ladder_per_microfix.md` — narrow at halt; full at commit token

### Round 0.5 — self-caught doctrine conflict (scope count + invented scopes)

**Finding (caught by self-review immediately after Round 0 draft, BEFORE user doctrine review):**

The initial Round 0 draft listed **14 RBAC scopes** — mirroring the Sprint-7B.1 closeout L119 hand-off line ("14 RBAC scopes per ADR-012") — and invented two read scopes (`pack.read.metadata`, `pack.read.lifecycle_history`) to make 14. Cross-reading the three doctrine sources caught the drift:

- **BUILD_PLAN §622-625** enumerates exactly **12** scopes: `pack.submit`, `pack.withdraw` (author 2) + `pack.review.claim`, `pack.review.approve`, `pack.review.reject` (reviewer 3) + `pack.allow_list`, `pack.install`, `pack.disable`, `pack.revoke`, `pack.uninstall` (operator 5) + `pack.audit.read`, `pack.invocation.read` (examiner 2) = 12.
- **ADR-012 §39 transition table** uses **11** scopes via transitions + adds **1 override** (`pack.override.approval_gate` at §107-110) = 12 transition + 1 override. The override ships with Sprint 7B.3's 5-gate composer, not 7B.2.
- **Sprint-7B.1 closeout L119** reads "14 RBAC scopes" but enumerates only **12** — known cite-from-memory typo per Sprint 7B.1 T8 R1 doctrine catalog §15-§16. The closeout itself enumerates 12 verbatim; the "14" prefix is the drift.

**Resolution applied to plan (8 in-place edits across L5, L20-L27 doctrine map, L38 out-of-scope, L70 file-structure, L106 test description, L185 T2 step 1, L194-L195 + L228-L233 + L417-L425 + L446 + L450 + L502-L505 in-table scopes, L640 T12 halt watchpoint):**

1. Scope count fixed to **12** across all in-plan references (Goal, doctrine map, file structure, T2 test code, T12 closed-enum value-count watchpoint).
2. Two invented scopes (`pack.read.metadata`, `pack.read.lifecycle_history`) removed.
3. Endpoint-to-scope mapping rationalised: author-surface endpoints (POST drafts / PUT drafts / POST submit / DELETE drafts) all use `pack.submit` + `pack.withdraw` (the 2 author scopes); inspection-surface endpoints all use `pack.audit.read` (or `pack.invocation.read` for the invocations endpoint) per ADR-012 §75 "Inspection — examiner-facing".
4. Sprint-7B.1 closeout L119 "14" typo NOT amended (closeouts are immutable post-commit per AGENTS.md "don't rewrite history" spirit) — Sprint 7B.2 T13 closeout cites this as a doctrine cross-reference instead.
5. Doctrine map row added at L20 for ADR-012 §107-110 override scope explicitly deferring to 7B.3.

**Doctrine catalog correlation:**

- **§14 (cite-from-memory verification depth)** — primary doctrine that fired here; the "14" came from prior-conversation memory of the 7B.1 closeout, not from re-reading BUILD_PLAN §622-625.
- **§15 (invented-filename-from-naming-convention drift)** — adjacent pattern; here the drift was invented-scope-name-from-naming-convention (`pack.read.metadata` extrapolated from the `pack.audit.read` / `pack.invocation.read` pattern).
- **§20 (per-citation verification within doctrine surfaces)** — would have caught this earlier if the closeout-L119 line had been re-read at draft time rather than at self-review time.

### Round 0.6 — additional T4 doctrine cross-check (lifecycle.py table inspection) — *RESOLVED in Round 1 P2 #2 + Round 2 P2 #6 + Round 3 P2 #6*

**Finding:** T4's DELETE `/api/v1/packs/drafts/{id}` endpoint maps `draft → withdrawn`. ADR-012 §39 enumerates withdraw transitions ONLY from `submitted` / `under_review`; ADR-012 §59 separately specifies the DELETE endpoint as "cancel draft". The 7B.1 `_VALID_TRANSITIONS` table at `packs/lifecycle.py:196` is the source of truth for whether `(draft, withdrawn)` is a legal pair.

**Resolution (updated Round 3 P3 #8 — was previously stated as "deferred"; that wording is now obsolete):** Round 1 P2 #2 + Round 2 P2 #6 + Round 3 P2 #6 resolved this in-plan as a CC-ADJ extension to `packs/lifecycle.py` adding the new `cancel_draft` transition name mapping `(draft, withdrawn)`. T4 ships:
- `TransitionName` Literal extended 10 → 11 values at `lifecycle.py:133`
- `_VALID_TRANSITIONS` extended at `lifecycle.py:196`
- `_TRANSITION_TO_ISO_CONTROLS` extended at `lifecycle.py:290-301`
- `_TRANSITION_TO_TARGET_STATE` mirror extended at `storage.py:118` (Round 3 P2 #3 ownership split)
- 15-site repo-wide doctrine-citation sweep (Round 3 P2 #6 expansion) covering `src/` + `tests/` + `tools/` + `AGENTS.md`; immutable docs left untouched

This entry stays in the patch log as historical record of the question being raised at Round 0.6 self-review; the resolution path lives in Rounds 1/2/3 entries below.

### Round 1 — user doctrine review (9 findings: 6×P2 + 2×P3 + 1×P3 follow-up; all patched into plan)

| # | Priority | Finding | Resolution location |
|---|---|---|---|
| **P2 #1** | P2 | Approve endpoint cannot ship green without 5-gate enforcement — ADR-012 §41 requires refusal when any gate is red; green-path `approve` violates production-grade rule | T5 endpoint table row + new "Approve-endpoint fail-loud contract" subsection + out-of-scope clarification; ships as `HTTPException(503, reason="approve_gate_composer_not_wired")` with NO state transition + NO chain row in 7B.2 |
| **P2 #2** | P2 | Draft DELETE maps to known-invalid lifecycle transition — ADR-012 §39 limits `withdraw` to `submitted`/`under_review`; 7B.1 `_VALID_TRANSITIONS` does not include `(draft, withdrawn)` | T4 title + body rewritten: T4 ships a CC-ADJ extension to `packs/lifecycle.py` adding a NEW `cancel_draft` transition mapping `draft → withdrawn` per ADR-012 §59 "cancel draft" wording; 4-map lockstep extension (`_VALID_TRANSITIONS` / `_TRANSITION_TO_TARGET_STATE` / `_TRANSITION_TO_ISO_CONTROLS` / `storage.py:_TRANSITION_TO_TARGET_STATE`); asymmetric-runtime-guard pattern preserved |
| **P2 #3** | P2 | Portal plan needs explicit tenant isolation — RBAC scopes alone are insufficient; a scoped actor must not transition/inspect another tenant's pack | New `portal/rbac/tenant_isolation.py` CC module (`RequireTenantOwnership(pack_id)` FastAPI dependency); 3-value closed-enum `TenantIsolationFailure` literal; route-level (NOT scope-level — per reviewer answer #3); 404 not 403 (info-leak); every author/review/operator/inspection endpoint that takes `{id}` path param adds this dependency; cross-tenant-refusal tests pinned per surface |
| **P2 #4** | P2 | Evidence attachment cites non-existent storage fields — `decision_inputs.evidence` is invented; `read_manifest()` doesn't exist on `PackRecordStore` | T9 entire section rewritten against ground truth: `DecisionRecord.payload` (verified at `core/decision_history.py:242`); manifest comes from request body (`SubmitDraftRequest.manifest`); server-side digest-match check against `PackRecord.manifest_digest`; conformance attaches as new optional top-level `payload.conformance` key (NOT a canonical-form change; algorithm unchanged); `evidence_pointer` stays as side-table pointer reserved for 7B.3 |
| **P2 #5** | P2 | App factory RBAC wiring should be CC — T3 modifies `portal/api/app.py` (enforcement boundary) but was classed NOT-CC | T3 promoted to CC with halt-before-commit; new `test_app_factory_actor_binder_wiring.py` pins fail-loud-on-missing-binder + router-not-mounted-when-wiring-incomplete; `app.py` classed as task-level CC (halt-before-commit on T3) not module-level coverage-gate addition |
| **P2 #6** | P2 | Harness plan assumes fixture-AgentOS harness that does not exist — `harness/base_agent.py` does not exist; `cli/test_harness.py` (1321 lines) is Sprint-7A T13 hybrid runner, NOT a fixture AgentOS instance | T11 re-scoped: ships OWASP tail-call extension to existing `cli/test_harness.py` ONLY; full ADR-012 §114-122 fixture-AgentOS harness explicitly DEFERRED post-7B in out-of-scope section; T13 closeout sprint-allocation row stamps the deferral with placeholder identifier |
| **P3 #7** | P3 | Critical-controls floor count off-by-one — plan listed 9 new CC modules but said floor 43 → 51 (+8) | Floor recomputed: 43 → 54 (+11 — 9 from initial count + `portal/rbac/tenant_isolation.py` from P2 #3 + `portal/rbac/human_actor.py` from P3 #8); CC-promotions of existing modules (`portal/api/app.py` T3, `packs/lifecycle.py` T4, `packs/storage.py` T9, `cli/test_harness.py` T11) listed separately as task-level CC not module-level coverage additions; counted in T12 line-uplift narrative |
| **P3 #8** | P3 | Allow-list endpoint needs human-operator proof — `pack.allow_list` scope alone insufficient; service-token actors could silently approve | T2 adds 2-value closed-enum `actor_type` field to `Actor` model (`"human"` / `"service"`); new `portal/rbac/human_actor.py` module with `RequireHumanActor()` dependency; T6 `/allow-list` endpoint wires `RequireHumanActor()` dependency; refusal pinned by `test_allow_list_refuses_service_actor` |
| **Reviewer answer #5** | doctrine | Sprint-7B.1 closeout L119 "14 scopes" typo handling | Plan + T13 closeout call out 12 as source-truth count; 7B.1 closeout itself NOT amended; recorded in T13 closeout doctrine cross-reference |

**Round 1 reviewer answers recorded for execution:**

1. **Allow-list:** patched — `RequireHumanActor()` dependency enforces `actor_type == "human"`; service tokens with the scope are refused.
2. **Evidence attachments:** patched — atomic shape preserved; actual storage/chain schema (`DecisionRecord.payload`; no `decision_inputs.evidence`; no `read_manifest()`).
3. **RBACDenialReason:** kept at 3 values for T2; tenant-mismatch handled at route level via new `portal/rbac/tenant_isolation.py` with its own closed-enum.
4. **Test harness:** patched — T11 re-scoped to OWASP integration only; full ADR-012 §114-122 fixture-AgentOS harness deferred post-7B.
5. **7B.1 closeout "14 scopes" typo:** kept history untouched; 7B.2 plan + closeout call out 12 as source-truth count.

### Round 2 — user follow-up doctrine review (7×P2 + 2×P3; all patched into plan)

| # | Priority | Finding | Resolution location |
|---|---|---|---|
| **P2 #1** | P2 | Architecture summary contradicted cancel_draft extension — said "no state-machine changes here" while T4 explicitly extends lifecycle.py | Architecture paragraph rewritten: explicitly cites the one narrow CC-ADJ lifecycle extension at T4 (cancel_draft) + the lockstep maps + the doctrine-citation sweep + tenant-isolation as a separate route-level concern |
| **P2 #2** | P2 | T2 task did not actually create tenant_isolation.py + human_actor.py — only listed them in forecast/file structure | T2 title + Files section + TDD steps expanded: 5 RBAC modules land in T2 (scopes / actor / enforcement / tenant_isolation / human_actor) with 5 corresponding test modules; new steps 10a + 10b for tenant + human guards |
| **P2 #3** | P2 | Actor snippet omitted `actor_type` despite Round 1 P3 #8 requiring it for RequireHumanActor | Step 4 RED test rewritten with 4 test functions including ActorType literal stability + Actor.actor_type assertion + invalid-actor-type refusal; Step 6 GREEN snippet imports `Literal` / `TypeAlias` + defines `ActorType` + extends `Actor` with the field |
| **P2 #4** | P2 | RBAC denial audit emission had no storage dependency — claim of hash-chained audit event without DecisionHistoryStore injection or schema design | T2 enforcement.py NARROWED to structured HTTP denial only — closed-enum reason in 403 response body + structured log record for SIEM correlation. Hash-chain emission EXPLICITLY DEFERRED to a later sprint when the denial-event schema is properly designed (storage dependency + schema + app-state wiring + tests). Step 7 RED docstring + Step 9 GREEN narrative both updated; T13 halt watchpoint #h added |
| **P2 #5** | P2 | update_draft introduced unscheduled storage write API — T4 referenced it but didn't list storage.py as having the method added | T4 Files list explicitly adds `update_draft()` to `packs/storage.py` modify scope with full semantics: allow-list of 4 non-state fields (display_name / manifest_digest / signed_artefact_digest / sbom_pointer); refuses on non-draft state; refuses on PackNotFound; NO chain row emitted (mirrors save_draft() genesis pattern at storage.py:313); bumps `PackRecordRefusalReason` literal 1 → 2 (new `pack_record_update_non_draft_state` value). New `tests/unit/packs/test_storage_update_draft.py` test module |
| **P2 #6** | P2 | cancel_draft changes require doctrine sweep, not only map tests — adding 11th transition changes vocabulary from canonical 10 to 11 | T4 body explicitly enumerates the doctrine-citation sweep: `lifecycle.py:192` source comment + lifecycle/audit test count assertions + AGENTS.md (if it cites the count) + tools/check_critical_coverage.py docstring rationales; explicitly NOT-touched: 7B.1 closeout + 7B.1 plan-of-record (immutable per AGENTS.md "don't rewrite history"). T4 halt summary enumerates every site touched + every site verified-not-to-need-touching per Sprint-7B.1 T8 doctrine §15-§20 |
| **P2 #7** | P2 | Submit pseudocode omitted required transition args — `evidence_pointer` + `request_id` missing | T9 wire-design snippet rewritten with full 6-required-kwarg signature verified at `packs/storage.py:360-369` + the new `payload_conformance` kwarg; `evidence_pointer=None` reserved for 7B.3 side-table; `request_id=request.state.request_id` bound by existing `RequestIdMiddleware`. Halt watchpoint added |
| **P3 #8** | P3 | Reviewer queue used examiner scope (`pack.audit.read`) when BUILD_PLAN §623 only grants reviewers `pack.review.claim/approve/reject` — reviewers would be locked out of their own queue | T5 endpoint table row for GET `/api/v1/packs?status=submitted` rescoped to `RequireScope("pack.review.claim")`; rationale noted in cell + Round 2 P3 #8 reference |
| **P3 #9** | P3 | `cli/__init__.py` modify-list said T10/T11 register new test-harness subcommand, but it already exists at `cli/__init__.py:475` from Sprint-7A T13 | File-structure L106 + T10 Files section both rewritten: T10 registers `conformance` subcommand ONLY; T11 modifies the existing `cli/test_harness.py` module body via the existing registration at `cli/__init__.py:475` (no new Typer registration in T11) |

**Round 2 reviewer answers recorded for execution:**

1. **cancel_draft as CC-ADJ acceptable** if doctrine sweep added — accepted; T4 now explicitly includes the sweep step with file:line citations and the immutable-closeout-NOT-touched contract.
2. **Request-body manifest is right pragmatic split** — accepted; T9 design as-is.
3. **payload.conformance is evidence/wire-shape CC, NOT canonical-form algorithm** — accepted; T9 narrative refined to distinguish (a) algorithm at `core/canonical.py` (untouched; stop-rule territory) vs (b) per-transaction payload schema (extended within existing CC perimeter). Halt watchpoint updated.
4. **404 for cross-tenant is right call** — accepted; tenant_isolation.py module as-is.
5. **Separate human_actor.py is fine but T2 needs to actually create it** — accepted; covered by Round 2 P2 #2 expansion.

### Round 3 — user follow-up doctrine review (6×P2 + 2×P3; all patched into plan)

| # | Priority | Finding | Resolution location |
|---|---|---|---|
| **P2 #1** | P2 | Critical-controls forecast table omitted `portal/rbac/human_actor.py` — said 5 RBAC modules in narrative but listed only 4 in the table | Forecast table extended to include `portal/rbac/human_actor.py` row with rationale (was present in T12 11-module list + file structure + later route dependencies; now consistent in the top forecast surface too) |
| **P2 #2** | P2 | `ActorBinder.bind()` typed `-> Actor` had no emit path for `actor_unauthenticated` closed-enum reason | Added `ActorBinderUnauthenticated(Exception)` typed exception in `portal/rbac/actor.py`; `RequireScope` catches it and translates to `HTTPException(403, detail={"reason": "actor_unauthenticated"})`. Updated `ActorBinder` Protocol docstring to specify both raise contracts (kernel-default raises `NotImplementedError`; per-request unauthenticated raises `ActorBinderUnauthenticated`). All three `RBACDenialReason` values now have a real emit path |
| **P2 #3** | P2 | T4 said `lifecycle.py` extends `_TRANSITION_TO_TARGET_STATE`, but that map is `storage.py`-local | T4 storage.py vs lifecycle.py modify scopes split per ownership: lifecycle.py owns `TransitionName` + `_VALID_TRANSITIONS` + `_TRANSITION_TO_ISO_CONTROLS` + `_KNOWN_TRANSITIONS` (derived); storage.py owns `_TRANSITION_TO_TARGET_STATE` |
| **P2 #4** | P2 | `update_draft` refusal vocabulary incomplete — only 1 new `PackRecordRefusalReason` value, but the function refuses both non-draft state AND non-allowlisted update fields | `PackRecordRefusalReason` literal bumped 1 → 3 values: `pack_record_save_draft_initial_state_not_draft` (existing 7B.1) + `pack_record_update_non_draft_state` (new at T4) + `pack_record_update_field_not_allowed` (new at T4 per P2 #4). 5 immutable fields locked per reviewer answer: `tenant_id` / `state` / `kind` / `pack_id` / `created_by` |
| **P2 #5** | P2 | Submit manifest check raced `update_draft` — TOCTOU between preload digest check and the transition() row lock | T9 wire-design rewritten: `transition()` gains second new kwarg `expected_manifest_digest: bytes | None = None`; precondition closure (inside the `SELECT ... FOR UPDATE` row lock at `storage.py:467-473`) compares locked-row digest against `expected_manifest_digest`; mismatch raises new 14th `LifecycleRefusalReason` value `lifecycle_transition_manifest_digest_changed_during_submit`. New test `test_submit_refuses_manifest_digest_changed_during_submit` pins the race-condition closure (fixture flow: load digest A → concurrent update_draft mutates to B → transition() refuses with locked precondition firing) |
| **P2 #6** | P2 | T4 doctrine sweep missed source 10-tuple comments in `lifecycle.py` (5 sites) + `storage.py` (1 site) + `test_lifecycle_audit.py` (5 sites) + `AGENTS.md` (1 site) — original sweep listed only `lifecycle.py:192` | T4 doctrine sweep expanded to **15 sites in 6 files** via `grep -rn` inventory at plan-write time: `lifecycle.py` :51 / :130 / :192 / :376 / :436 + `storage.py:118` + `test_lifecycle.py` :143 / :174 + `test_lifecycle_audit.py` :29 / :308 / :332 / :337 / :524 + `check_critical_coverage.py:170-171` + `AGENTS.md:L123`. Halt summary requirement: re-run `grep -rn` AFTER patch confirming zero residual hits outside the immutable-doc set |
| **P3 #7** | P3 | Guard citation `lifecycle.py:393-394` pointed at `iso_controls_for` guard, not `validate_transition` step 3 | Citation corrected to `lifecycle.py:472-473` (validate_transition step 3 — matches 7B.1 closeout + memory). The `:393-394` site is the `iso_controls_for` guard against `_TRANSITION_TO_ISO_CONTROLS`; auto-extends because the ISO map gains the `cancel_draft` entry; no separate change needed there |
| **P3 #8** | P3 | Round 0.6 patch log said cancel_draft was deferred — obsolete since Round 1/2 resolved it in-plan | Round 0.6 entry updated with "*RESOLVED in Round 1 P2 #2 + Round 2 P2 #6 + Round 3 P2 #6*" header + bullet list of resolution touch-points; historical context preserved (the question being raised at Round 0.6 self-review) |

**Round 3 reviewer answers recorded for execution:**

1. **`PackRecordRefusalReason` is the right class for `update_draft`** but needs **two** new values — accepted; bumped 1 → 3 values per P2 #4.
2. **`evidence_pointer=None` for submit is OK with current 7B.1 shape** — accepted; T9 wire-design unchanged.
3. **4-field `update_draft` allow-list reasonable**; 5 immutable fields: `tenant_id` / `state` / `kind` / `pack_id` / `created_by` — accepted; T4 update_draft scope updated.
4. **`pack.review.claim` for reviewer queue is right call** — accepted; T5 endpoint table unchanged.
5. **AGENTS.md count updates land at T4** alongside source comments (not deferred to T12); T12 adds the new 7B.2 subsection afterward — accepted; doctrine sweep at T4 includes `AGENTS.md:L123`.

### Round 4 — user follow-up doctrine review (4×P2 + 2×P3; all patched into plan)

| # | Priority | Finding | Resolution location |
|---|---|---|---|
| **P2 #1** | P2 | T9 added a `LifecycleRefusalReason` value but didn't list `lifecycle.py` + lifecycle tests in Files list | T9 Files section expanded: `packs/lifecycle.py` (13→14 enum bump) + `test_lifecycle.py` (closed-enum vocabulary test) + `test_lifecycle_audit.py` (precondition-rollback test) + `AGENTS.md:L123` (enum enumeration sub-string) + `tools/check_critical_coverage.py` (docstring rationale) all explicitly added. New T9 halt watchpoint (i) — T9 OWNS the `LifecycleRefusalReason` 13→14 sweep separate from T4's transition-count sweep |
| **P2 #2** | P2 | T4 doctrine sweep touched files missing from T4 file list — `AGENTS.md:L123` + `tools/check_critical_coverage.py:170-171` were enumerated in the sweep but missing from T4's Files block | T4 Files section gains two explicit Modify entries: `AGENTS.md:L123` (transition-count sub-string edit) + `tools/check_critical_coverage.py:170-171` (docstring rationale). The reviewer's answer clarified: T4 owns transition-count edits, T9 owns LifecycleRefusalReason-count edits; both touch `AGENTS.md:L123` at different sub-strings (no merge conflict expected at the source-text level) |
| **P2 #3** | P2 | `update_draft` atomicity underspecified — load-then-update could race submit/cancel_draft | T4 storage.py modify-scope gains a full atomicity specification: single atomic `UPDATE packs SET … WHERE id = :pack_id AND state = 'draft'` (state predicate in WHERE clause; no separate SELECT-FOR-UPDATE precondition closure); rowcount-based refusal disambiguation (rowcount==0 → follow-up SELECT to disambiguate PackNotFound vs `pack_record_update_non_draft_state`); `last_actor` + `updated_at` auto-bumped on every update; field-allowlist refusal fires BEFORE any DB call (pure-Python); 5 listed tests pin all paths including the integration test under PG/Oracle for concurrent-submit race |
| **P2 #4** | P2 | Transition-count sweep excluded `docs/` despite claiming repo-wide | Grep command extended to `src/ tests/ tools/ docs/ AGENTS.md`; the two immutable doc paths (`docs/closeouts/2026-05-11-sprint-7b1-lifecycle-state-machine.md` + `docs/superpowers/plans/2026-05-10-sprint-7b1-lifecycle-state-machine.md`) explicitly excluded. Verified at plan-write time: `docs/` adds no new drift sites outside the immutable paths (only this 7B.2 plan file itself matches, which is intentional self-reference) |
| **P3 #5** | P3 | Forecast row for `enforcement.py` still said "audit linkage" — obsolete since Round 2 P2 #4 narrowed to structured-HTTP-only | Forecast cell reworded: "**NO audit-chain emission in 7B.2 per Round 2 P2 #4 narrowing** — denials emit structured-log records only at the application-logging layer; hash-chain denial events deferred to a later sprint when the schema is designed end-to-end" |
| **P3 #6** | P3 | T4 watchpoint (b) listed unqualified `_TRANSITION_TO_TARGET_STATE` twice — reintroduced map-ownership confusion fixed in Round 3 P2 #3 | Watchpoint (b) rewritten with explicit qualified names: `lifecycle.py:_VALID_TRANSITIONS` (at `:196`) + `lifecycle.py:_TRANSITION_TO_ISO_CONTROLS` (at `:290-301`) + `storage.py:_TRANSITION_TO_TARGET_STATE` (at `:118`) + `lifecycle.py:TransitionName` Literal (at `:133`). 4 maps in 2 files; lifecycle owns 3, storage owns 1 |

**Round 4 reviewer answers recorded for execution:**

1. **Cross-sprint CC extensions acceptable as CC-ADJ** if file lists + sweeps explicit — accepted; T4 + T9 now both list all touched files including AGENTS.md + tools.
2. **Manifest-digest refusal lands at T9; T9 owns lifecycle.py enum/test/doc update** — accepted; Round 4 P2 #1 patch applied.
3. **Transition-count sweep belongs at T4; LifecycleRefusalReason 13→14 sweep belongs at T9** — accepted; Round 4 P2 #1 + P2 #2 implement the split. Both touch `AGENTS.md:L123` at different sub-strings.
4. **`_KNOWN_TRANSITIONS` correctly derived** from `get_args(TransitionName)` at `lifecycle.py:240` — confirmed; no manual mirror needed.
5. **Expected-manifest-digest check inside row-locked precondition** — accepted; T9 storage.py mod-scope explicitly places the check inside the existing `_precondition` closure at `:458` (after `SELECT … FOR UPDATE` at `:467-473`).

### Round 5 — user follow-up doctrine review (3×P2 + 2×P3; all patched into plan)

| # | Priority | Finding | Resolution location |
|---|---|---|---|
| **P2 #1** | P2 | Doctrine sweep matches the 7B.2 plan itself once committed at T1 | Exclusion set expanded from 2 to 3 paths: 7B.1 closeout + 7B.1 plan + **this 7B.2 plan** (post-T1-commit it becomes immutable history with the patch-log narrative containing "10 transitions" / "13 legal pairs" as historical record). Both T4 and T9 halt watchpoints updated with the 3-path exclusion set; halt-summary grep proofs use the exclusion explicitly |
| **P2 #2** | P2 | T9 LifecycleRefusalReason 13→14 sweep not enumerated (vs T4's precise 15-site inventory) | T9 Files section gains an explicit **8-site inventory** mirroring T4's pattern: `lifecycle.py:146` + `:165-179` + `storage.py:50` + `test_lifecycle.py:70` + `:77` + `:234` + `AGENTS.md:L123` + `tools/check_critical_coverage.py:167`. False-positive matches called out explicitly: `tests/unit/protocol/test_mcp_registration_auth_probe.py:8` + `test_refusal_reason_completeness.py:238` cite `AuthzReason` (MCP) — different enum, coincidentally same 13-value count, intentionally unchanged |
| **P2 #3** | P2 | `update_draft` accepts `tenant_id` but doesn't enforce it (misleading unused parameter or missing storage guard) | `tenant_id` removed from `update_draft()` signature. Resolution: tenant-mismatch is route-level only via `RequireTenantOwnership` (the existing 7B.2 pattern). Storage signature becomes `async def update_draft(self, *, pack_id: uuid.UUID, updates: dict[str, Any], actor_id: str) -> None`. Mirrors 7B.1 `save_draft()` at `:313` which also doesn't accept `tenant_id` as a separate kwarg. Rationale documented inline at T4 storage.py modify-scope |
| **P3 #4** | P3 | `expected_manifest_digest` needs SELECT shape change specified | T9 storage.py modify-scope now explicitly spells out the SELECT extension: `select(_packs.c.state, _packs.c.kind)` at `:469` → `select(_packs.c.state, _packs.c.kind, _packs.c.manifest_digest)`; capture `manifest_digest` in the closure alongside existing `state` + `kind`; check-and-discard after the precondition fires (chain-row payload does NOT carry `manifest_digest` — already keyed by `pack_id`); `_build_record` signature unchanged (returns `tuple[PackState, PackKind]` — closure handles the check internally) |
| **P3 #5** | P3 | RBAC audit-chain deferral lacked an owner sprint | RBAC denial chain-event work tagged with **Sprint 7B.4** placeholder. Rationale: denial events fit the `policy.*` event family slot already reserved in `protocol/ui_events.py`; the schema design space overlaps with ADR-020 UI event taxonomy work already owned by 7B.4. Mirrors the fixture-AgentOS-harness deferral pattern. Out-of-scope section + enforcement.py forecast cell + T2 step 9 narrative all updated with the placeholder-sprint tag |

**Round 5 reviewer answers recorded for execution:**

1. **Split-edit AGENTS.md:L123 at T4 + T9 acceptable** if grep proof excludes 7B.2 plan or plan stops self-matching — accepted; 3-path exclusion set applied per P2 #1.
2. **Rowcount==0 + follow-up SELECT shape fine**, but fix tenant_id ambiguity — accepted; `tenant_id` removed from `update_draft()` signature per P2 #3.
3. **`expected_manifest_digest` as Optional kwarg = right shape** — accepted; no change beyond the SELECT-shape spec per P3 #4.
4. **Tag RBAC denial hash-chain deferral with placeholder sprint** — accepted; 7B.4/7C2 tag applied per P3 #5 across 3 sites in the plan.
5. **Enumerate exact T9 grep sites now, mirroring T4 15-site inventory** — accepted; 8-site inventory documented per P2 #2.

### Round 6 — user follow-up doctrine review (3×P2 + 2×P3; all patched into plan)

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **P2 #1** | P2 | T9 sweep grep `"13-value\|13 values\|13 reasons"` matches 8 historical MCP AuthzReason citations across docs/ + tests/ (intentionally unchanged), making the bare grep proof noisy or falsely claiming residuals | Narrower two-grep proof: (1) `grep -rn "LifecycleRefusalReason" <paths>` then verify each hit cites "14" not "13"; (2) proximity-anchored grep with `(13-…\|…\|13 reasons).{0,80}LifecycleRefusalReason` or vice-versa returns zero hits post-patch. 8 AuthzReason false-positive sites enumerated explicitly in plan: `test_mcp_registration_auth_probe.py:8` + `test_refusal_reason_completeness.py:238` + 3 sites in Sprint-5 closeout L14/L72/L111 + 3 sites in Sprint-5 plan L1307/L1369/L2315 |
| **P2 #2** | P2 | `PackRecordRefusalReason` bumped 1→3 (now 1→4 per Round 6 P3 #4) but T4 didn't sweep durable references calling it 1-value | T4 Files list gains explicit doctrine sweep for the count bump: 4 sites in 3 files — `storage.py:42-43` module docstring "(Wave-1: only ...)" + `storage.py:235` Literal definition + `tools/check_critical_coverage.py:224` rationale "1-value PackRecordRefusalReason" + `AGENTS.md:L124` storage.py subsection bullet. T4 halt watchpoint (j) added with proximity-anchored proof grep |
| **P2 #3** | P2 | `cancel_draft` ISO control tuple undecided — said `("A.5.31",)` "or whichever applies" | Committed to `("A.5.31",)` in-plan. Rationale: mirrors the existing `withdraw → ("A.5.31",)` mapping at `lifecycle.py:300` with `:277` rationale "author cancels the regulatory ..."; both transitions reach the same `withdrawn` target state with same access-control semantics. Decision locked in plan to avoid design choice inside the CC source edit |
| **P3 #4** | P3 | `update_draft` value-shape validation underspecified — digests should be 32-byte SHA-256, string fields need length/non-empty constraints | T4 storage.py mod-scope gains explicit per-field shape contracts: `display_name` (str/non-empty/≤256), `manifest_digest` (bytes/len==32), `signed_artefact_digest` (bytes/len==32), `sbom_pointer` (str non-empty or None). New 4th `PackRecordRefusalReason` value `pack_record_update_field_invalid_shape` (literal bumped 1→3 → 1→4); shape check fires AFTER field-allowlist + BEFORE atomic UPDATE (step 2 in the 6-step atomicity flow). New test `test_update_draft_refuses_invalid_shape_before_db_call` pins all 4 fields |
| **P3 #5** | P3 | RBAC denial chain-event deferral had two owners ("Sprint 7B.4 or a Sprint 7C2 mirror") | Owner singularised to **Sprint 7B.4** across all 4 sites (out-of-scope L37 + forecast cell L50 + T2 Step 7 docstring + T2 Step 9 narrative). "Or 7C2 mirror" hedge removed; the 7B.4 closeout can re-home if scope forces a split. Verified via post-patch grep that "or a Sprint 7C2 mirror" no longer appears in the plan |

**Round 6 reviewer answers recorded for execution:**

1. **`_build_record` unchanged is fine** (check-and-discard inside locked precondition cleaner than widening captured tuple) — accepted; no patch.
2. **AuthzReason callout right instinct but incomplete because docs/ adds more hits** — accepted; Round 6 P2 #1 expanded to enumerate 8 AuthzReason sites + introduces narrower two-grep proof shape.
3. **RBAC denial chain events owned by Sprint 7B.4 singly** — accepted; Round 6 P3 #5 applied across all 4 sites.
4. **No test_lifecycle_audit.py 13-value LifecycleRefusalReason hit** — confirmed by reviewer; 8-site T9 inventory remains correct.
5. **3-path exclusion convention defer to T13 for AGENTS.md inclusion decision** — accepted; T13 closeout will revisit whether the convention belongs as a doctrine rule. 7B.2 uses the convention in-plan without lifting to AGENTS.md.

### Round 7 — user follow-up doctrine review (4×P2; all patched into plan)

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **P2 #1** | P2 | T9 first proof grep (`grep -rn "LifecycleRefusalReason"`) was non-deterministic — matches generic type/doc references that don't and shouldn't cite a count, making the halt-summary verification subjective | Positive grep narrowed to deterministic proximity-anchored form: `grep -rn -E "(14-value\|14 values\|14 reasons).{0,80}(LifecycleRefusalReason)\|LifecycleRefusalReason.{0,80}(14-value\|14 values\|14 reasons)"`. Returns exactly **8 hits** post-patch (one per sweep site). Negative grep same shape with "13". Both deterministic — count==8 positive, count==0 negative. Generic LifecycleRefusalReason type-references no longer match because pattern REQUIRES value-count phrase proximity |
| **P2 #2** | P2 | PackRecordRefusalReason sweep was overbroad (`"Wave-1: only"` matched `docs/PACK-MANIFEST-SPEC.md:222` hook-fail-policy) AND underinclusive (missed `storage.py:232` + `:241` durable Wave-1 contract comments) | Sweep inventory corrected: **6 sites in 3 files** (was 4 sites). Added: `storage.py:232` ("only Wave-1 reason is the genesis-state guard") + `storage.py:241` ("The Wave-1 contract is genesis-state-only"). Proof greps narrowed to TWO deterministic forms: (1) `"1-value.{0,20}PackRecordRefusalReason\|PackRecordRefusalReason.{0,20}1-value"`; (2) `"save_draft.{0,40}(Wave-1\|only Wave-1\|genesis-state-only)"`. `PACK-MANIFEST-SPEC.md:222` hook-fail-policy spec deliberately UNCHANGED — different vocabulary, doesn't match either narrowed grep |
| **P2 #3** | P2 | `PackRecordRefused("pack_record_update_field_invalid_shape")` claimed to carry failing-field-name in exception payload, but `PackRecordRefused.__init__` signature at `storage.py:254-265` only supports `(reason, *, state=None)` | Decision: **do NOT extend the exception class signature**. Closed-enum `reason` is sufficient for caller dispatch contract; field-name diagnostics surface via structured-log emission at validator boundary (`logger.warning("packs.update_draft.invalid_shape", extra={"pack_id": …, "field": …})`). Test contract: caplog assertion, not exception attribute read. Plan updated in 2 sites — atomicity flow step 2 + new "PackRecordRefused exception payload contract" subsection |
| **P2 #4** | P2 | "Caller owns the draft" prose mentioned for PUT but no concrete guard / refusal / tests defined; submit + delete didn't mention the check at all — potential bug allowing any actor with `pack.submit` in same tenant to act on another author's draft | Resolved as **explicit same-tenant author collaboration policy** (option (b)): drop the ownership-guard claim; document that any actor holding `pack.submit` scope in the same tenant can update / submit / cancel any draft in that tenant. Audit trail invariant: `PackRecord.created_by` immutable (in 5-field immutable set per Round 5/6); `last_actor` + chain-row `actor_id` capture the modifier. New test `test_same_tenant_collaboration_allowed_on_draft_update`. NO `RequireDraftOwnership` guard ships in 7B.2 |

**Round 7 reviewer answers recorded for execution:**

1. **`cancel_draft → ("A.5.31",)` acceptable** — accepted; lock-in unchanged from Round 6.
2. **`display_name` 256-char limit matches `_packs.c.display_name = String(256)`** — confirmed by reviewer; existing column constraint, plan's pick matches the actual DB schema.
3. **Two-grep idea good, positive grep needs narrowing** — accepted; Round 7 P2 #1 makes the positive grep proximity-anchored AND count-anchored.
4. **Front-loading AuthzReason false positives right; proof command not depend on them** — accepted; both T9 greps are LifecycleRefusalReason-anchored, eliminating AuthzReason noise mechanically.
5. **update_draft refusal order right (allow-list, shape, atomic state predicate); exception payload shape was the remaining issue** — accepted; Round 7 P2 #3 resolves the exception-payload concern by dropping the field-name claim.

### Round 8 — user follow-up doctrine review (4×P2 + 1×P3; all patched into plan)

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **P2 #1** | P2 | T9 single-line proximity grep cannot match 4 split-line sites — verified: `storage.py:49-50` (LifecycleRefusalReason at :49 / "(13 reasons)" at :50), `test_lifecycle.py:70+77` (count comment at :70 / `LifecycleRefusalReason` at :77), `lifecycle.py:165-179` (15-line Literal block). Single-line proximity grep returns false-clean state | Switched halt-summary proof to **per-site `sed -n '<line>p' <file>` verification** — 8 sed commands PASTED per site with expected post-patch text. Negative sanity grep retained but cross-checks AuthzReason count == 8 unchanged false positives. Per-site sed is mechanically deterministic by line-range match |
| **P2 #2** | P2 | PackRecordRefusalReason proof grep also single-line — same split-line problem at `storage.py:231-232` + `:239-241` | Switched to **per-site `sed -n` verification** — 6 sed commands per site. Negative sanity grep retained for single-line residual catch. Split-line residuals caught only by per-site sed |
| **P2 #3** | P2 | Same-tenant collaboration policy said "any actor with pack.submit can update/submit/cancel" but DELETE endpoint requires `pack.withdraw` — contradicts endpoint table + BUILD_PLAN §622 two-author-scope set | Policy reworded scope-correctly: CREATE / UPDATE / SUBMIT gated by `pack.submit`; CANCEL gated by `pack.withdraw` (the distinct second author scope). Endpoint table cell for DELETE clarified to call out `pack.withdraw` scope explicitly |
| **P2 #4** | P2 | Collaboration policy claimed for update/submit/cancel but only one test (`test_same_tenant_collaboration_allowed_on_draft_update`) was named | Added two more tests pinning the policy across all three mutating paths: `test_same_tenant_collaboration_allowed_on_draft_submit` (pins chain row's `payload.actor_id` is submitter B not author A) + `test_same_tenant_collaboration_allowed_on_draft_cancel` (uses `pack.withdraw` scope per Round 8 P2 #3; pins cancel transition's chain payload + last_actor). Negative paths (cross-tenant 404, missing scope 403) already pinned by existing tests |
| **P3 #5** | P3 | T12 watchpoint still cited "4 sites in 3 files for PackRecordRefusalReason 1→4" — stale from Round 6 before Round 7 P2 #2 corrected to 6 | T12 watchpoint (b.1) updated to "**6 sites in 3 files**" + cross-references Round 7 P2 #2 correction + Round 8 P2 #1 / P2 #2 per-site sed proof shape |

**Round 8 reviewer answers recorded for execution:**

1. **Structured-log emission: use `_LOG = logging.getLogger(__name__)` module-level logger; caplog target `cognic_agentos.packs.storage`** — accepted; `PackRecordRefused` exception payload contract subsection updated with `_LOG` + `caplog.set_level(logging.WARNING, logger="cognic_agentos.packs.storage")` test pattern.
2. **`(created_by, last_actor, chain-row actor_ids)` audit-replay invariant OK for 7B.2 provided submit + cancel tested too** — accepted; Round 8 P2 #4 adds the two missing tests.
3. **Keeping `PackRecordRefused.__init__` unchanged is the right scope call** — accepted; no patch.
4. **`save_draft.{0,40}` grep needs multiline OR per-site checks, not just wider window** — accepted; Round 8 P2 #2 switches to per-site sed verification.
5. **T13 should include a final reference table; at 1286 lines future-us needs a navigation map more than another paragraph** — accepted; T13 closeout structure gains a new **section 7 "Final reference table"** with 6 sub-sections (a–f) consolidating all closed-enum bumps + CC modules + cross-sprint extensions + deferred work into a single navigation surface.

### Round 9 — user follow-up doctrine review (2×P2 + 2×P3; all patched into plan)

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **P2 #1** | P2 | T9 `sed -n '77p'` on `test_lifecycle.py` prints only the `assert set(get_args(LifecycleRefusalReason)) == {` opener, NOT the enum members; passes the halt check even with the new 14th value missing. Same problem at `lifecycle.py:165-179` (15-line Literal definition) | Two sites switch from `sed -n '<line>p'` to **`rg -n "lifecycle_transition_manifest_digest_changed_during_submit" <file>`** — deterministic proof that the new value is present at the source. Other 6 sites stay on `sed -n` (single-line citations). Halt-summary proof shape updated in two places: the T9 narrative proof-shape section + watchpoint (i) |
| **P2 #2** | P2 | Round 8 fixed positive collaboration tests across PUT/submit/cancel but the `pack.submit` vs `pack.withdraw` scope split has NO dedicated negative tests — relies on generic `test_rbac_enforcement_e2e.py`. Given the exact scope mixup just happened in Round 7-8 review, the regression deserves co-located pinning | Three new named negative tests in `test_author_routes.py` next to the positive collaboration tests: `test_pack_submit_actor_cannot_cancel_draft` (pack.submit alone → DELETE 403 with `required_scope="pack.withdraw"`); `test_pack_withdraw_actor_cannot_update_draft` (pack.withdraw alone → PUT 403 with `required_scope="pack.submit"`); `test_pack_withdraw_actor_cannot_submit_draft` (same → POST `/submit` 403). All assert no chain row + no state mutation |
| **P3 #3** | P3 | T4 explicit test-bullet for `test_storage_update_draft.py` listed field-not-allowed, no-chain, last_actor, PackNotFound, race but OMITTED the Round 6 P3 #4 invalid-shape regression even though the atomicity narrative named it | Test bullet extended: added `test_update_draft_refuses_invalid_shape_before_db_call` (parametrized over 4 fields: `display_name` non-str/empty/>256, both digests non-bytes/wrong-length, `sbom_pointer` empty str) + structured-log caplog assertion (`logger="cognic_agentos.packs.storage"` per Round 8 reviewer answer #1) |
| **P3 #4** | P3 | T9 negative sanity check required `grep` returns EXACTLY 8 AuthzReason hits — brittle cross-sprint state coupling. If unrelated Sprint-5 doc edits drift the AuthzReason count, 7B.2 halt summary fails falsely | AuthzReason historical sites demoted from gating check to informational ONLY. The 8 per-site `sed -n`/`rg -n` verifications ARE the deterministic proof of `LifecycleRefusalReason` 13→14 completion. No AuthzReason count == 8 coupling. Plan updated in two places: proof-shape narrative + watchpoint (i) |

**Round 9 reviewer note recorded:** "Two incomplete fixes from Round 8, plus two newly surfaced checklist/proof-strength issues. Plan is much tighter now; these are mostly proof/test-contract edges, not architecture reversals."

### Round 10 — user follow-up doctrine review (1×P2 + 1×P3; all patched into plan)

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **P2 #1** | P2 | Round 9 rg-by-value-name proof with `≥1` threshold can still pass if the new value appears only in a comment/docstring, not in the actual Literal or test set | Switched to **member-line-anchored regex** with strict count: `rg -n '^\s*"lifecycle_transition_manifest_digest_changed_during_submit",' <file>` returns **EXACTLY 1 hit** per site. The `^\s*"<value>",` anchor matches ONLY quoted-string-literal-followed-by-comma (actual `Literal[...]` member or set element), NOT a docstring/comment mention. Plan updated in 3 sites: proof-shape narrative (×2 site bullets) + watchpoint (i) cross-reference |
| **P3 #2** | P3 | API-surface fail-loud for the `approve` endpoint described as `NotImplementedError` in two places (out-of-scope L33 + forecast row L54), but the endpoint actually raises `HTTPException(503, detail={...})` per the rest of the plan. `NotImplementedError` is reserved for kernel-default `ActorBinder` stubs per Round 3 P2 #2 | Both API-surface mentions rewritten to "fail-loud `HTTPException(503)` scaffold" with explicit cross-reference distinguishing the API-surface case (HTTP exception) from the kernel-default-stub case (NotImplementedError). Mirrors the production-grade scaffold-with-fail-loud pattern documented in `protocol/mcp_host.MCPHost.call_tool` |

**Round 10 reviewer note recorded:** "Everything else from the Round 9 list looks closed: the scope negatives are now explicit and co-located, the invalid-shape test is in the concrete T4 bullet, and AuthzReason is no longer a gating count."

### T2 R1 — halt-before-commit doctrine review of executed T2 (3 findings; all closed in source + tests + plan)

This round is distinct from Rounds 0-10: those were pre-T1 plan-of-record reviews; T2 R1 is a post-execution halt-before-commit review of T2's actual implementation against the plan + AGENTS.md doctrine. Findings patched into source/tests + this plan **before** the local T2 commit per `feedback_strict_review_off_gate.md` (strict review applies to every CC commit).

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **P2 #1** | P2 | `RequireTenantOwnership` dereferences `request.app.state.pack_record_store` directly. Route mounted with a binder but no store surfaces FastAPI's generic 500 `Internal Server Error` — no closed-enum reason, no structured log — a fingerprint regression off the 7B.2 wire-protocol contract | **Bumped `TenantIsolationFailure` 3 → 4** with new `pack_store_not_configured` value mirroring `enforcement._bind_actor`'s `binder is None` defensive branch. Source guard at `tenant_isolation.py:118-134`; closed-enum literal extended; tests `test_require_tenant_ownership_returns_500_when_pack_store_missing` + `test_pack_store_not_configured_emits_structured_log` added; literal-frozen-at-3 test renamed to literal-frozen-at-4; closed-enum coverage test bumped. Plan-of-record 6 live forecast sites patched to 4-value; historical Round 1 P2 #3 row left intact as Round-1-era doctrine. |
| **P2 #2** | P2 | Halt summary claimed all RBAC + tenant-isolation + human-actor denial paths emit structured log records, but only `test_enforcement.py` had caplog assertions. Tenant + human-actor logging can regress while HTTP-response tests stay green | Added parametrized `test_tenant_isolation_emits_structured_log_per_reason` covering 3 non-defensive `TenantIsolationFailure` reasons (4th defensive case `pack_store_not_configured` pinned in its own caplog test); added `test_require_human_actor_refusal_emits_structured_log` against `cognic_agentos.portal.rbac.human_actor` logger. All 3 RBAC loggers now have caplog parity. |
| **P3** | P3 | `test_require_tenant_ownership_rejects_malformed_pack_id_uuid` asserted `!= 500` (with comment permitting 422), but `tenant_isolation.py`'s docstring contract is structured `404 pack_not_found` | Tightened assertion to `status_code == 404` + `detail.reason == "pack_not_found"`. Without this, a regression from 404 `pack_not_found` to a 422 `Unprocessable Entity` (or any non-500 shape) would pass silently. |

**T2 R1 post-fix gate ladder:**

- pytest narrow: **60/60 passed** in 0.58s (up from 54/54 pre-R1; +6 tests for R1 fixes)
- coverage: **100% line / 100% branch** maintained on all 5 RBAC modules (117 stmts / 20 branches; 0 missing)
- ruff check + format + mypy: clean narrow + full-tree (`ruff check .`, `ruff format --check .`, `mypy src tests` — 296 files / 283 source files)

**Doctrine drift caught at T2 R1:** plan-of-record stated "3-value `TenantIsolationFailure`" at 6 live forecast sites (lines 51 / 82 / 198 / 472 / 1068 / 1079). Patched verbatim. Historical Round 1 P2 #3 patch-log row at L1187 left intact (it originated the 3-value count; that IS correct history). T13 closeout (line 1107) only lists the literal name without a count — no patch needed there until T13 actual compose-time when the count is verified at file:line per `feedback_verify_code_citations_at_doc_write.md`. T12's L1079 closed-enum-counts watchpoint patched to **4 — T2 R1 P2 #1** so the T12 AGENTS.md uplift carries the correct count forward.

### Round N+ — to be filled in during ANY further user doctrine-review patch cycle

(User may flag additional conflicts after Round 10 / T2-R1 patches; I patch into this file before the affected commit.)

---

## Execution gates (pre-flight before T2 begins)

- [ ] User reviews this plan against doctrine
- [ ] User identifies conflicts (if any)
- [ ] I patch conflicts into this file + update Self-Review patch log
- [ ] User issues `start t2` (or equivalent) token
- [ ] Execution mode chosen (inline vs subagent-driven per `superpowers:executing-plans` skill)
