# Sprint 7B.2 — Portal API + RBAC + OWASP Conformance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Every CRITICAL CONTROLS task uses **halt-before-commit** per `feedback_strict_review_off_gate.md`.

**Goal:** Ship the portal API surface for bank pack lifecycle (ADR-012) atop Sprint-7B.1's lifecycle state machine + storage. 4 surfaces × ~18 endpoints; **12 RBAC scopes** (BUILD_PLAN §622-625 verbatim — the Sprint-7B.1 closeout L119 cite-from-memory typo "14" is fixed at T13 closeout via doctrine cross-reference, not closeout amendment per AGENTS.md immutability) wired through a new `portal/rbac/` subsystem; OWASP Agentic Top 10 + Skills Top 10 conformance suite with auto-run on `submit`; `agentos conformance` + `agentos test-harness` CLI extensions.

**Architecture:** Stack 7B.2 atop local 7B.1 tip (`768d574`). FastAPI `APIRouter` pattern matches `portal/api/system_routes.py:build_system_router`. RBAC enforced via a FastAPI dependency (`RequireScope("pack.…")`) that resolves the request actor via a pluggable `ActorBinder` protocol (kernel ships the protocol + `NotImplementedError` default; bank overlays / test fixtures plug in real / fixture binders — production-grade rule). Pack state transitions delegate to `PackRecordStore.transition()` from 7B.1; **one narrow CC-ADJ lifecycle extension at T4 adds the 11th transition `cancel_draft` mapping `draft → withdrawn` per ADR-012 §59** (extending `packs/lifecycle.py` + lockstep in 3 sibling maps + the `TransitionName` Literal and a doctrine-citation sweep per Round 2 P2 #6). Conformance runs synchronously on `submit` POST; the result attaches as a new `payload.conformance` top-level key on the submit transition's chain row (a payload-schema extension — NOT a canonical-form-algorithm change; the canonical-form algorithm at `core/canonical.py` is unchanged); the lifecycle transition proceeds regardless (per BUILD_PLAN §627 + ADR-012 §41 — the OWASP gate sits at the `approve` boundary, enforced by Sprint 7B.3's 5-gate composition; 7B.2 only produces the evidence). Audit emission stays in `packs/storage.py` (`pack.lifecycle.<target_state>` namespace from 7B.1 T3). **Tenant isolation is route-level (not scope-level)** via a separate `portal/rbac/tenant_isolation.py` guard per Round 1 P2 #3; every endpoint that takes a `{pack_id}` path param resolves the pack and verifies `actor.tenant_id == pack.tenant_id` before any state read or transition. Cross-tenant access returns 404 (info-leak prevention).

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
| `portal/rbac/human_actor.py` | **NEW per Round 1 P3 #8** (Round 3 P2 #1 — was missing from this forecast table; subsequently added to the live forecast table here AND to the T12 enumerated CC-module list — which Round 11 P2 #4 bumped from 11 to **12** entries by adding `role_separation.py`). `RequireHumanActor()` dependency that asserts `actor.actor_type == "human"` for operator-surface endpoints that finalise per-tenant changes. Returns 403 with closed-enum `actor_type_must_be_human`. |
| `portal/rbac/role_separation.py` | **NEW per Round 11 P2 #4 (T5 doctrine sweep); dependency-seam design refined Round 14 P2 #3; closure-safety hardened Round 15 P2 #1.** Exports the **`RequireDifferentActorThanCreator(*, tenant_ownership: Callable[..., Awaitable[PackRecord]])` closure-factory** (function, NOT class) — caller passes the SAME `RequireTenantOwnership(pack_id_param=...)` return value the endpoint declares as `Depends(...)`. **Verified against the live codebase (T2 commit `44af077`):** `RequireTenantOwnership` is a factory function (`def RequireTenantOwnership(...) -> Callable[..., Awaitable[PackRecord]]` at `tenant_isolation.py:96-98`), NOT a class — so the shared variable IS the returned async callable; the type annotation MUST be `Callable[..., Awaitable[PackRecord]]` (NOT `RequireTenantOwnership`, which is the factory function itself). **`role_separation.py` MUST OMIT `from __future__ import annotations`** (unlike sibling RBAC modules at `tenant_isolation.py:37` / `human_actor.py:26` / `enforcement.py:26` which all carry it) — PEP 563 string-deferred annotations would prevent FastAPI's `inspect.signature()` / `typing.get_type_hints()` introspection from resolving `Annotated[PackRecord, Depends(tenant_ownership)]` in the inner closure's namespace (closure-bound `tenant_ownership` is NOT in module globals; the lazy string `"Depends(tenant_ownership)"` evaluation would `NameError`, regressing into the T4-era "FastAPI treats record/actor as query params" silent-failure bug). The factory returns an async closure that internally `Depends(tenant_ownership)` — annotations stay live → FastAPI resolves them against the function's `__closure__` cell-by-cell. FastAPI's per-request callable-identity sub-dependency cache deduplicates the PackRecord load → ONE `store.load` call on the happy path. The closure asserts `actor.subject != record.created_by` for review-surface endpoints (claim / approve / reject). **Round 16 P2 #3 — structured-log emission**: closure emits `_LOG.warning("portal.rbac.role_separation_refused", extra={"reason": "actor_cannot_review_own_pack", "actor_subject": …, "pack_id": …, "pack_created_by": …})` BEFORE raising the `HTTPException`. Module-scoped `_LOG = logging.getLogger(__name__)` mirrors sibling RBAC guards (`tenant_isolation._emit_isolation_log` + `human_actor` + `enforcement._emit_denial_log`); observability tooling sees the denial regardless of caller HTTP-response handling. Returns 403 with closed-enum **1-value** `RoleSeparationFailure` literal: `actor_cannot_review_own_pack`. Enforces ADR-012 §17 cross-role separation invariant. Lives in its own module to keep four enforcement axes orthogonal: `RequireScope` (scope membership) + `RequireTenantOwnership` (tenant boundary) + `RequireHumanActor` (actor-type) + `RequireDifferentActorThanCreator` (role separation). |
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
- `packs/storage.py` — CC-ADJ extension at **T5 (Round 11 P2 #1 + Round 14 P2 #1 — backward-compatible signature)**: extend `list_by_status` with optional keyword-only `tenant_id: str | None = None` filter for the reviewer-queue path. **Exact compatibility-preserving signature**: `list_by_status(state, limit: int = 50, cursor: uuid.UUID | None = None, *, tenant_id: str | None = None)` — keeps `limit` + `cursor` positional-or-keyword with their existing defaults (matches the current `packs/storage.py:797` shape); the new `tenant_id` goes BEHIND the `*` so it is keyword-only-with-default (additive; existing call-sites stay green). Pure-read change; no Doctrine Lock D touch; uses the existing `ix_packs_tenant_state` index per migration L129. **AND at T7 (Round 19 P2 #4 — inspection tenant-scoped seam)**: add NEW method `list_for_tenant(tenant_id: str, *, limit: int = 50, cursor: uuid.UUID | None = None, state: PackState | None = None) -> list[PackRecord]` — REQUIRED `tenant_id` filter (the inspection-list endpoint has no `{pack_id}` so route-level `RequireTenantOwnership` cannot enforce the tenant boundary; storage WHERE-clause is the authoritative server-side filter) + OPTIONAL `state` AND-clause. Pure-read; uses same `ix_packs_tenant_state` index. Marks T7 as CC-ADJ to `packs/storage.py` (T7 itself stays NOT-CC at task-level; only the storage touch is CC-ADJ — same shape as T5's list_by_status extension). **AND at T9 (Round 11 P2 #3 + Round 12 P2 #2 + Round 13 P2 #2 forecast-row refresh)**: extend `transition()` with **THREE** new optional keyword-only kwargs — `payload_conformance` (Round 1 P2 #4 — real DecisionRecord.payload field, not the invented `decision_inputs.evidence`) + `expected_manifest_digest` (Round 3 P2 #5 — locked TOCTOU precondition + new 14th LifecycleRefusalReason value) + **`evidence_attachments`** (Round 11 P2 #3 + Round 12 P2 #2 — generic kwarg that T9 also uses to amend the T5 reject handler with `{"rejection_reason": ..., "reviewer_comments": ...}` chain-row write).
- `cli/test_harness.py` — CC-ADJ extension at T11 with OWASP integration per Round 1 P2 #6 (full ADR-012 §114-122 fixture-AgentOS harness deferred).

**Critical-controls floor projected: 43 → 55** at Sprint 7B.2 closeout (+12 new CC modules: 6 RBAC + 3 endpoint surfaces + 3 conformance — Round 11 P2 #4 added `role_separation.py` for ADR-012 §17 cross-role separation; previously +11 after Round 1 P2 #3 added tenant_isolation + P3 #8 added human_actor). T12 patches `AGENTS.md` + `tools/check_critical_coverage.py` accordingly.

## File structure

### Create (new directories + files)

**RBAC subsystem (new directory):**
- `src/cognic_agentos/portal/rbac/__init__.py`
- `src/cognic_agentos/portal/rbac/scopes.py` — 12-value closed-enum `PackRBACScope` literal + `ScopeSet` type alias + `PACK_LIFECYCLE_SCOPES` frozenset (BUILD_PLAN §622-625 verbatim)
- `src/cognic_agentos/portal/rbac/actor.py` — `Actor` Pydantic model (frozen; carries `subject` / `tenant_id` / `scopes` / **`actor_type` per Round 1 P3 #8**) + `ActorBinder` Protocol + 2-value `ActorType` closed-enum literal (`"human"` / `"service"`) + default `NotImplementedError`-raising `KernelDefaultActorBinder`
- `src/cognic_agentos/portal/rbac/enforcement.py` — `RequireScope(scope)` FastAPI dependency factory + closed-enum `RBACDenialReason` literal (3 values: `actor_unauthenticated` / `scope_not_held` / `actor_binder_not_configured`) + `RBACDenied` exception. **Per Round 1 reviewer answer #3: tenant-mismatch handling is route-level (see `tenant_isolation.py`), NOT scope-level. RBACDenialReason stays at 3 values.**
- `src/cognic_agentos/portal/rbac/tenant_isolation.py` — **NEW per Round 1 P2 #3; bumped to 4-value at T2 R1 P2 #1.** `RequireTenantOwnership(pack_id_param: str)` FastAPI dependency factory; loads the `PackRecord` via `PackRecordStore.load(pack_id)`; verifies `pack.tenant_id == actor.tenant_id`; returns the loaded `PackRecord` on success. Closed-enum **4-value** `TenantIsolationFailure` literal: `tenant_id_mismatch` (returns 404 to avoid info leak per OWASP "verbose error messages" guidance) / `pack_not_found` (also 404) / `actor_tenant_id_missing` (returns 500 — kernel misconfig; an actor with no tenant_id should never have been bound) / `pack_store_not_configured` (returns 500 — symmetric mirror of `enforcement._bind_actor`'s `binder is None` defensive branch; T2 R1 P2 #1 — added so a route mounted with a binder but no `app.state.pack_record_store` surfaces a CLOSED-ENUM 500 instead of FastAPI's generic `Internal Server Error`). `PackRecord.tenant_id` exists today at `packs/storage.py:289` per Sprint-7B.1 T3.
- `src/cognic_agentos/portal/rbac/human_actor.py` — **NEW per Round 1 P3 #8.** `RequireHumanActor()` FastAPI dependency that asserts `actor.actor_type == "human"` for operator-surface endpoints that finalise per-tenant changes (specifically `/allow-list` per AGENTS.md "Human-only decisions" rule). Returns 403 with closed-enum `actor_type_must_be_human`. Service tokens with `pack.allow_list` scope are refused even though they hold the scope.
- `src/cognic_agentos/portal/rbac/role_separation.py` — **NEW per Round 11 P2 #4 (T5 doctrine sweep); dependency-seam design refined Round 14 P2 #3; closure-safety hardened Round 15 P2 #1; structured-log emission added Round 16 P2 #3.** Exports the **`RequireDifferentActorThanCreator(*, tenant_ownership: Callable[..., Awaitable[PackRecord]])` closure-factory function** (NOT a class-with-`__call__`). Three invariants:
  1. **Type annotation for `tenant_ownership` is `Callable[..., Awaitable[PackRecord]]`** (NOT `RequireTenantOwnership` — the latter is the factory function itself per `tenant_isolation.py:96-98`, not a type for instances). Use a module-scoped type alias for readability: `TenantOwnershipDep: TypeAlias = Callable[..., Awaitable[PackRecord]]`.
  2. **`role_separation.py` MUST OMIT `from __future__ import annotations`** — sibling RBAC modules carry it (`tenant_isolation.py:37`, `human_actor.py:26`, `enforcement.py:26`) but PEP 563 string-deferred annotations would make `Annotated[PackRecord, Depends(tenant_ownership)]` inside the inner closure unresolvable (closure cells are NOT in module globals; FastAPI's introspection would `NameError` or silently treat `record` + `actor` as query params, regressing into the T4-era query-param-leakage bug). Annotations stay LIVE → FastAPI resolves against the closure's `__closure__` cells.
  3. **Round 16 P2 #3 — Structured-log emission BEFORE every HTTPException raise.** Module-scoped `_LOG = logging.getLogger(__name__)` mirrors sibling guards (`tenant_isolation._LOG` at `:50`, `human_actor._LOG` at `:37`, `enforcement` likewise). The closure calls `_LOG.warning("portal.rbac.role_separation_refused", extra={"reason": "actor_cannot_review_own_pack", "actor_subject": …, "pack_id": …, "pack_created_by": …})` immediately before the 403 raise, so observability sees the denial regardless of caller HTTP-response capture. Pinned by `test_role_separation_emits_structured_log` caplog regression — without this emission the denial would regress silently in observability while HTTP tests stay green.
  Router-build at T5 passes the SAME `_require_tenant_ownership` (the value returned by `RequireTenantOwnership(pack_id_param="pack_id")`) that the endpoint also declares as `Depends(...)`; FastAPI's per-request sub-dependency cache (keyed by callable identity) deduplicates the PackRecord load → ONE `store.load` call on the happy claim/reject path. Returns 403 with closed-enum **1-value** `RoleSeparationFailure = Literal["actor_cannot_review_own_pack"]`. Enforces ADR-012 §17 cross-role separation invariant. Lives in its own module to keep the four enforcement axes (scope / tenant / actor-type / role-separation) orthogonal.

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
- `src/cognic_agentos/packs/storage.py` — **T5 (Round 11 P2 #1 + Round 14 P2 #1 — backward-compatible signature):** extend `list_by_status` with an optional keyword-only `tenant_id` filter. **Exact compatibility-preserving signature**: `list_by_status(state, limit: int = 50, cursor: uuid.UUID | None = None, *, tenant_id: str | None = None)` — keeps `limit` + `cursor` positional-or-keyword with their existing defaults; the new `tenant_id` lives BEHIND the `*` so it is keyword-only-with-default (additive). When `tenant_id is not None`, WHERE clause adds `tenant_id == :tenant_id` AND uses the existing `ix_packs_tenant_state` composite index per migration L129; when `None`, behaviour is identical to the pre-T5 storage API (no filter). Pure read; no Doctrine Lock D touch. Pinned by three regressions on `tests/unit/packs/test_storage_list_by_status.py`: (1) `test_list_by_status_state_only_backward_compatible` (`store.list_by_status("submitted")` — pre-existing call shape; tenant filter inactive); (2) `test_list_by_status_existing_pagination_signature` (`store.list_by_status("submitted", limit=10, cursor=<uuid>)` — pre-existing positional limit/cursor); (3) `test_list_by_status_tenant_filtered_pagination` (`store.list_by_status("submitted", limit=10, cursor=<uuid>, tenant_id="tenant-a")` — new tenant-filtered path). **T7 (Round 19 P2 #4 + Round 20 P2 #3 + Round 22 P2 #1 propagation):** add NEW method `list_for_tenant(tenant_id: str, *, limit: int = 50, cursor: uuid.UUID | None = None, state: PackState | None = None) -> list[PackRecord]` — REQUIRED `tenant_id` filter + OPTIONAL `state` AND-clause. Pure read; no Doctrine Lock D touch; uses the same `ix_packs_tenant_state` composite index per migration L129. T7 task itself is "NOT-CC endpoint work + CC-ADJ storage touch / Halt: YES" per Round 20 P2 #1; route-level `actor_tenant_id_missing` preflight guard at `inspection_routes.py` per R20 P2 #2 + R21 P2 #1 type-corrected (pack_id="\<list\>" sentinel). Pinned by **5 regressions** on `tests/unit/packs/test_storage_list_for_tenant.py` (R21 P2 #2 bumped 4 → 5): tenant-only filter + optional state AND-clause + cursor pagination + no-packs-empty-list + R21 P2 #2 SQL-shape regression (`test_list_for_tenant_compiles_with_indexed_where_clause` — proves the WHERE clause uses the `ix_packs_tenant_state` composite-index columns via the R22 P2 #2 private statement-builder `_build_list_for_tenant_stmt(...)`). **T9 (Round 11 P2 #3 + Round 12 P2 #2 + Round 13 P2 #2 forecast-row refresh):** extend `transition()` to accept **THREE** optional keyword-only kwargs — `payload_conformance: dict[str, Any] | None = None` + `expected_manifest_digest: bytes | None = None` + **`evidence_attachments: dict[str, Any] | None = None`** (the third kwarg lets T9 amend the T5 reject handler to persist categorised reason + comments via `payload["evidence_attachments"]`); persist conformance result on `submit` transitions; locked precondition closes the load-then-submit TOCTOU window (preserves Doctrine Lock D atomicity).
- `src/cognic_agentos/portal/api/packs/dto.py` — **T5 (Round 11 P3 #5):** add `PackEvidenceResponse` Pydantic model carrying `conformance: dict[str, Any] | None` + `reviewer_evidence_panels: None` (literal-typed at `None` in 7B.2; 7B.3 fills in). Inherits `PackBaseModel` (frozen + extra="forbid"). **T9:** add `SubmitDraftRequest.manifest: dict[str, Any]` field per Round 1 P2 #4 (auto-run conformance dependency on the full manifest body). Also note dto.py is NOT CC per §"Not-CC" — Pydantic-only logic; the security-bearing decisions live in the route handlers + the storage seam.
- `src/cognic_agentos/cli/__init__.py` — register NEW `conformance` subcommand only (mirrors existing `validate` / `sign` / `verify` wiring). **Round 2 P3 #9 correction**: `test-harness` is ALREADY registered at `cli/__init__.py:475` (Sprint-7A T13). T11 extends the existing `cli/test_harness.py` module body — NO new Typer registration. Extend `ValidatorReason` literal ONLY if a NEW refusal class emerges (not anticipated for the conformance subcommand — conformance failures surface via exit code + JSON report, not validator-style refusal)
- `pyproject.toml` — extend `[project.scripts]` if needed (likely no change; `agentos` is a single entry point with subcommand dispatch)
- `docs/BUILD_PLAN.md` §602 — at T13: flip 7B.2 status row to CLOSED with branch tip + closeout link
- `AGENTS.md` — at T12: add `## Authoring — Bank pack lifecycle portal API (Sprint 7B.2)` subsection mirroring the 7B.1 subsection structure
- `tools/check_critical_coverage.py` — at T12: bump CC floor 43 → **55** + add **12** new module entries with rationale lines (per Round 11 P2 #4 — bumped from Round 1 P3 #7's +11 by adding `portal/rbac/role_separation.py`: 6 RBAC + 3 endpoint surfaces + 3 conformance)

### Tests

- `tests/unit/portal/rbac/__init__.py`
- `tests/unit/portal/rbac/test_scopes.py` — 12-scope literal stability + cross-reference vs BUILD_PLAN §622-625
- `tests/unit/portal/rbac/test_actor.py` — `ActorBinder` Protocol shape + `Actor` model frozen + `actor_type` closed-enum + default `KernelDefaultActorBinder` raises `NotImplementedError` with ADR-008 citation
- `tests/unit/portal/rbac/test_enforcement.py` — `RequireScope` denies unauthenticated; denies missing-scope with 403 + closed-enum `RBACDenialReason`; allows scope-held; raises `actor_binder_not_configured` when no binder injected
- `tests/unit/portal/rbac/test_tenant_isolation.py` — **NEW (Round 1 P2 #3)** — `RequireTenantOwnership` returns 404 on cross-tenant access; 404 on pack-not-found (info-leak prevention); 500 on `actor_tenant_id_missing`
- `tests/unit/portal/rbac/test_human_actor.py` — **NEW (Round 1 P3 #8)** — `RequireHumanActor` returns 403 on `actor_type == "service"`; admits `actor_type == "human"`
- `tests/unit/portal/rbac/test_role_separation.py` — **NEW (Round 11 P2 #4)** — `RequireDifferentActorThanCreator` returns 403 on `actor.subject == record.created_by`; admits when different subjects within same tenant; pins `RoleSeparationFailure` literal at 1 value (`actor_cannot_review_own_pack`); pin closed-enum stability invariant.
- `tests/unit/portal/test_app_factory_actor_binder_wiring.py` — **NEW (Round 1 P2 #5)** — `create_app(actor_binder=None)` does NOT mount pack router; `create_app(actor_binder=<fixture>, pack_record_store=<fixture>)` mounts; fail-loud-warning on partial wiring
- `tests/unit/portal/api/packs/__init__.py`
- `tests/unit/portal/api/packs/test_router_scaffolding.py` — router mounts at `/api/v1/packs`; DTOs round-trip
- `tests/unit/portal/api/packs/test_author_routes.py` — 4 endpoints × (happy + RBAC-denied + **cross-tenant 404** + invalid-state) — includes `manifest_digest_mismatch` test on submit
- `tests/unit/portal/api/packs/test_review_routes.py` — 5 endpoints × same coverage; **plus the Round 11 P3 #6 `test_approve_fail_loud_503` 4-axis matrix** pinning dependency-order: (a) no `pack.review.approve` scope → 403 `scope_not_held`; (b) scope held but cross-tenant pack → 404 `tenant_id_mismatch`; (c) scope + same-tenant + `actor.subject == record.created_by` → 403 `actor_cannot_review_own_pack`; (d) scope + same-tenant + different-actor → 503 `approve_gate_composer_not_wired` + no-state-transition + no-chain-row. **Plus `test_reviewer_queue_filters_by_tenant_id` (Round 11 P2 #1 + Round 12 P2 #1)** asserting GET `/api/v1/packs/review-queue` (moved off the colliding `?status=submitted` query path at Round 12 P2 #1) returns ONLY actor.tenant_id rows even when packs from other tenants share the `submitted` state — pinned via two-tenant fixture. **Plus `test_review_routes_does_not_register_inspection_list_path` (Round 13 P2 #1 — T5-narrow proof; Round 15 P2 #2 — mount-prefix correction)** asserting at T5-execution time (when `inspection_routes.py` does NOT yet exist) that the review sub-router built via `build_review_routes(store=…)` AND mounted under a test parent `APIRouter(prefix="/api/v1/packs")` on a fresh `FastAPI()` app exposes compiled full path `GET /api/v1/packs/review-queue` but does NOT expose `GET /api/v1/packs` — pins ownership boundary at T5 without depending on T7's not-yet-existent module. Round 13's original wording asserted full-prefix paths against an un-mounted sub-router (which would have been vacuously true since an un-mounted `APIRouter` exposes only relative paths); R15 P2 #2 corrects the proof shape to mount-under-test-parent so the assertion exercises the actually-deployed compiled path. **Plus `test_build_packs_router_includes_review_routes` (Round 16 P2 #1 — production-wiring regression)** asserting that calling the actual production `build_packs_router(store=stub_store)` factory (NOT a test-fabricated mount) produces an `APIRouter` whose compiled `app.routes` includes `GET /api/v1/packs/review-queue` (T5 review surface wired) AND `POST /api/v1/packs/drafts` (T4 author surface still wired) AND does NOT include `GET /api/v1/packs` (T7 not yet wired). This regression catches the "review_routes.py created but never wired into the parent router" failure mode where T5's manually-mounted test fixture passes while the production surface still ships only author routes. The full **`test_review_queue_and_inspection_list_both_reachable` test ships at T7 (Round 13 P2 #1 split)** once `inspection_routes.py` exists; T7's test asserts the route table on the fully-composed `build_packs_router` contains BOTH `GET /api/v1/packs/review-queue` (T5; `pack.review.claim`) AND `GET /api/v1/packs` (T7; `pack.audit.read`) without shadow. **Plus `test_evidence_returns_null_pre_t9` (Round 11 P3 #5)** asserting GET `/{pack_id}/evidence` returns `{"conformance": null, "reviewer_evidence_panels": null}` for a submit-without-conformance audit row (pre-T9 chain rows). **Plus a forward-looking `test_evidence_surfaces_payload_conformance_post_t9_fixture`** asserting the read path correctly extracts `payload.conformance` from a hand-built submit-transition chain-row fixture carrying the T9 schema. **Plus `test_reject_categorised_reason_logged_only_in_t5` (Round 11 P2 #3)** asserting the reject handler accepts a `RejectionReason` + comments body, structured-logs both, and the chain row's `payload` does NOT carry these fields in 7B.2 (the T9 carry-forward watchpoint pins their migration to chain payload). **Plus `test_claim_handles_pack_not_found_race` + `test_reject_handles_pack_not_found_race` (Round 16 P2 #2)** — stub-store regressions mirroring T4's submit/cancel race tests: a stub store where `transition()` raises `PackNotFound` (simulating concurrent delete between tenant-isolation preload + transition's `SELECT ... FOR UPDATE`); assert handler translates to 404 + `detail={"reason": "pack_not_found"}` (via shared `_PACK_NOT_FOUND_REASON: Final[Literal["pack_not_found"]]` constant imported from `author_routes.py` OR redeclared at `review_routes.py` module scope — implementer's choice; the constant value comes from `TenantIsolationFailure` Literal); asserts no 500 leaks + structured-log emission for the race.
- `tests/unit/portal/api/packs/test_operator_routes.py` — 5 endpoints × same coverage; **plus `test_allow_list_refuses_service_actor` + `test_allow_list_admits_human_actor`** for Round 1 P3 #8. **Plus `test_operator_routes_path_param_name_matches_dependency` (Round 17 P2 #1 carry-forward)** — parametrized over each operator endpoint (allow-list / install / disable / revoke / uninstall) asserting the route's compiled path string contains `"{pack_id}"` AND that issuing a real request with a malformed UUID returns 404 (NEVER 500 — the path-param mismatch fingerprint).
- `tests/unit/portal/api/packs/test_inspection_routes.py` — 4 endpoints × (happy + RBAC-denied + **cross-tenant 404**). **Plus `test_inspection_routes_path_param_name_matches_dependency` (Round 17 P2 #1 carry-forward)** — parametrized over each inspection endpoint with a path UUID (`/{pack_id}` / `/{pack_id}/audit` / `/{pack_id}/invocations`); same shape as the T5/T6 path-param-mismatch regression. **Plus `test_build_packs_router_includes_inspection_routes` (Round 18 P2 #3)** asserting the production `build_packs_router(store=stub_store)` factory output includes the 4 inspection paths (`GET /api/v1/packs` + `GET /api/v1/packs/{pack_id}` + `GET /api/v1/packs/{pack_id}/audit` + `GET /api/v1/packs/{pack_id}/invocations`) AND that BOTH `GET /api/v1/packs/review-queue` (T5) AND `GET /api/v1/packs` (T7) reach distinct handlers — this is the T7-side landing of the `test_review_queue_and_inspection_list_both_reachable` Round 13 P2 #1 carry-forward. **Plus `test_list_returns_500_when_actor_tenant_id_missing` (Round 20 P2 #2 + Round 21 P2 #1 — type-corrected)** — fixture-actor with `tenant_id=""` (empty string; constructible under live `Actor.tenant_id: str` schema at `actor.py:71`) produces 500 + structured body `detail={"reason": "actor_tenant_id_missing"}` + caplog assertion on `cognic_agentos.portal.rbac.tenant_isolation` logger AND assertion that the record's `extra["pack_id"] == "<list>"` (sentinel per the type-safe implementer pattern at the T7 storage row). The `Actor(tenant_id=None)` axis is NOT tested — `Actor.tenant_id: str` rejects None at Pydantic validation; reaching the handler with None is impossible under the typed contract.
- **`tests/unit/packs/test_storage_list_for_tenant.py` (Round 19 P2 #4 + Round 20 P2 #3 + Round 20 P3 #4 + Round 21 P2 #2 — NEW; CC-ADJ storage proof for T7)** — **5 regressions** pinning the new `packs/storage.py::list_for_tenant` method: (1) `test_list_for_tenant_returns_only_matching_tenant_rows` (two-tenant fixture; tenant-A actor gets only tenant-A rows; cross-tenant rows NEVER appear in the result set); (2) `test_list_for_tenant_with_optional_state_filter` (when `state` provided as e.g. `"approved"`, AND-clause applies); (3) `test_list_for_tenant_pagination_cursor` (cursor pagination behaves identically to `list_by_status`'s cursor logic; opaque cursor; deterministic ordering); (4) `test_list_for_tenant_with_no_packs_returns_empty_list` (Round 20 P2 #2 corrected name — was misleading "empty-tenant" in R19; tenant string with NO matching packs returns `[]`; the empty-`actor.tenant_id` axis is now route-level-refused at `inspection_routes.py` per R20 P2 #2 + R21 P2 #1); **(5) Round 21 P2 #2 + Round 22 P2 #2 — `test_list_for_tenant_compiles_with_indexed_where_clause`** — calls the **production module-private statement-builder** `cognic_agentos.packs.storage._build_list_for_tenant_stmt(tenant_id, *, limit, cursor, state=None)` (NEW per R22 P2 #2 — the builder MUST be the SAME callable the public `PackRecordStore.list_for_tenant` invokes, NOT a duplicated `select(_packs).where(...)` in the test); calls `.compile(dialect=...)` on the returned `Select` and asserts the rendered SQL string contains `packs.tenant_id = ` (always present) AND (when state non-None) also `packs.state = `; proves the WHERE clause used by the production query path uses the `ix_packs_tenant_state` composite-index columns without needing env-gated live-DB EXPLAIN inspection. **R22 P2 #2 doctrine — test exercises production path, not a duplicate**: the production `list_for_tenant` method calls `_build_list_for_tenant_stmt(...)` internally to build the `Select` statement before passing to `await conn.execute(...)`; the test imports the same private builder and asserts on its output. If the test wrote its own `select(_packs).where(...)` duplicate, the SQL-shape assertion would pass even if `list_for_tenant`'s production query lost the `tenant_id` clause — vacuous proof. The shared-builder pattern eliminates the duplicate-and-drift bug class. The migration test at `test_migration_20260510_0003.py::test_packs_indexes_present` already pins index presence. Required for T7 halt-summary coverage proof per R20 P2 #1 + R21 P2 #2 watchpoint (c) downgrade.
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
            # GET / and GET /{pack_id} require `pack.audit.read` (no separate
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
| PUT | `/api/v1/packs/drafts/{pack_id}` | `RequireScope("pack.submit")` + `RequireTenantOwnership(pack_id)` | `update_draft()` (new method on `PackRecordStore`; limited to allow-listed non-state fields). **Same-tenant author collaboration ALLOWED** per Round 7 P2 #4 (see "Draft ownership policy" subsection below) — any actor with `pack.submit` scope in the same tenant can update any draft owned by that tenant. Audit trail captured via `created_by` (original author, immutable) + `last_actor` (current modifier, bumped on every update). |
| POST | `/api/v1/packs/drafts/{pack_id}/submit` | `RequireScope("pack.submit")` + `RequireTenantOwnership(pack_id)` | `transition("submit")` — `draft → submitted`. Conformance auto-run lives here at T9. Same-tenant author collaboration allowed per Round 7 P2 #4 — any actor with `pack.submit` scope in the same tenant can submit any draft owned by that tenant. |
| DELETE | `/api/v1/packs/drafts/{pack_id}` | `RequireScope("pack.withdraw")` + `RequireTenantOwnership(pack_id)` | `transition("cancel_draft")` — `draft → withdrawn` via the NEW transition added in this task. The pre-existing `withdraw` transition still requires source state `submitted` or `under_review` per ADR-012 §39 — unchanged. **Same-tenant collaboration allowed per Round 8 P2 #3: gated by `pack.withdraw` scope (NOT `pack.submit`)** — any actor with `pack.withdraw` scope in the same tenant can cancel any tenant-owned draft. |

**Draft ownership policy (Round 7 P2 #4 resolution):**

The Round 1-6 endpoint narrative said PUT "requires (caller owns the draft)" but defined no concrete `RequireDraftOwnership` guard, refusal shape, or tests. Round 7 P2 #4 + Round 8 P2 #3 resolved this with **explicit same-tenant author collaboration policy** (option (b) from the reviewer), with scope-correct wording per Round 8 P2 #3:

- **What's allowed (scope-correct per Round 8 P2 #3):**
  - **CREATE** (POST `/drafts`): any actor with `pack.submit` scope can create drafts in their tenant
  - **UPDATE** (PUT `/drafts/{pack_id}`): any actor with `pack.submit` scope in the SAME tenant as the draft can update it
  - **SUBMIT** (POST `/drafts/{pack_id}/submit`): any actor with `pack.submit` scope in the same tenant can submit any tenant-owned draft
  - **CANCEL** (DELETE `/drafts/{pack_id}`): any actor with **`pack.withdraw`** scope in the same tenant can cancel any tenant-owned draft (scope distinct from `pack.submit` per BUILD_PLAN §622 author-role-set: `pack.submit` + `pack.withdraw` are the TWO author scopes)
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
- (d) Tenant-isolation enforcement at every author-surface endpoint that takes a `{pack_id}` path param — pinned by `test_author_routes.py::test_cross_tenant_returns_404` per Round 1 P2 #3
- (e) Idempotency on POST `/submit` — second submit on already-submitted pack returns 409 with closed-enum `lifecycle_transition_invalid_state_pair` from 7B.1
- (f) Audit-chain emission tagged with `pack.lifecycle.submitted` / `pack.lifecycle.withdrawn` namespace from 7B.1
- (g) **`update_draft` atomicity** (Round 4 P2 #3) — pinned by `test_storage_update_draft.py::test_concurrent_submit_loses_to_update_draft_atomic_update` integration test under `COGNIC_RUN_POSTGRES_INTEGRATION=1` / `COGNIC_RUN_ORACLE_INTEGRATION=1`; pin row-lock serialisation behaviour
- (h) **T4 doctrine-sweep evidence in halt summary** (Round 4 P2 #2 + P2 #4 + Round 5 P2 #1) — `grep -rn` AFTER patch over `src/ tests/ tools/ docs/ AGENTS.md` excluding THREE paths: (i) `docs/closeouts/2026-05-11-sprint-7b1-lifecycle-state-machine.md`, (ii) `docs/superpowers/plans/2026-05-10-sprint-7b1-lifecycle-state-machine.md`, (iii) **this 7B.2 plan file `docs/superpowers/plans/2026-05-11-sprint-7b2-portal-api-rbac-owasp.md`** (Round 5 P2 #1 self-exclusion — the plan contains its own historical narrative). Grep pattern: `10-tuple|10 transitions|10-transition|13 legal pairs|canonical 10`. Halt summary PASTES the post-patch grep output proving zero residual hits outside the 3-path exclusion set

---

### Task 5: Review surface endpoints — 5 endpoints *(CRITICAL CONTROLS)*

**Class:** CC. **Halt: YES.**

**Why CC:** Most consequential transitions per ADR-012 §84-105 — but Sprint 7B.2 does NOT enforce the 5-gate approval composition (that's 7B.3). The approve endpoint here is the surface that 7B.3's gate composer wires into. **Round 11 patch adds a new CC sibling module `portal/rbac/role_separation.py` (P2 #4)** for ADR-012 §17 cross-role separation; storage `list_by_status` extension is CC-ADJ per P2 #1; `PackEvidenceResponse` DTO addition is not-CC per the dto.py classification.

**Files:**
- Create: `src/cognic_agentos/portal/api/packs/review_routes.py`. **Round 14 P2 #2 — review-route request_id minters:** the claim + reject handlers BOTH call `PackRecordStore.transition(..., request_id=...)`, which requires a caller-supplied bounded ID per the Round 13 P2 #3 wire-design contract. T5 declares TWO new request-id prefix constants at module scope: `_PACK_CLAIM_REQUEST_ID_PREFIX: Final[str] = "pack-claim--"` (12 chars; double-dash for prefix-uniqueness against `pack-cancel-`) AND `_PACK_REJECT_REQUEST_ID_PREFIX: Final[str] = "pack-reject-"` (12 chars). T5 **shares the `_mint_request_id` helper from T4's `author_routes.py:98-108`** via an explicit `from cognic_agentos.portal.api.packs.author_routes import _mint_request_id` cross-import — keeps a single source of truth for the minter implementation. Module-foot build-time invariant asserts `len(<prefix>) + 32 <= 64` for both new prefixes (mirrors T4 R3 P2 #1; 12 + 32 = 44, fits under the 64-char `decision_history.request_id` cap). T9 reuses `_PACK_REJECT_REQUEST_ID_PREFIX` when amending the reject handler to write `evidence_attachments` — NO new prefix introduced at T9 per Round 14 P2 #2 (was Round 12 P2 #2's misclaim). **Round 17 P2 #2 — structured-log contract**: module-scoped `_LOG = logging.getLogger(__name__)` mirrors T4's `author_routes._LOG` at `:66`. **Four canonical log events** (closed message-name set; observability tooling buckets on this set):

  | Event when | Logger | Message | `extra` keys |
  |---|---|---|---|
  | reject body received (T5; categorised reason + comments are evidence-bearing pre-T9) | `cognic_agentos.portal.api.packs.review_routes` | `"portal.packs.review.reject"` | `actor_subject`, `pack_id`, `reason` (RejectionReason 7-value), `comments` (full str) |
  | claim transition refused (state-machine OR PackNotFound race OR LifecycleTransitionRefused) | `cognic_agentos.portal.api.packs.review_routes` | `"portal.packs.claim_refused"` | `reason` (closed-enum: `pack_not_found` or one of `LifecycleRefusalReason`), `actor_subject`, `pack_id`, `from_state` (when known) |
  | reject transition refused (state-machine OR PackNotFound race) | `cognic_agentos.portal.api.packs.review_routes` | `"portal.packs.reject_refused"` | `reason` (closed-enum), `actor_subject`, `pack_id`, `from_state` (when known) |
  | approve fail-loud 503 (no transition path) | `cognic_agentos.portal.api.packs.review_routes` | `"portal.packs.approve_fail_loud_503"` | `reason` (`approve_gate_composer_not_wired`), `actor_subject`, `pack_id`, `next_sprint` (`"7B.3"`) |

  Mirrors T4 author_routes log-event naming (`portal.packs.create_draft_refused` at `:432`, `portal.packs.update_draft_refused` at `:476` + `:517`, `portal.packs.submit_refused` at `:584` + `:597`, `portal.packs.cancel_draft_refused` at `:662` + `:675`). **Caplog regressions split per event-type (Round 18 P2 #2 — corrected from the misleading "green-path admit emits no log" R17 wording):**

  | Endpoint + path | Expected log record(s) |
  |---|---|
  | **Reject accepted (green path)** — valid `RejectDraftRequest`; transition succeeds | EXACTLY ONE `portal.packs.review.reject` record fires with `reason`+`comments`+`actor_subject`+`pack_id` extras. This IS the load-bearing T5 evidence surface for the categorised reason (per Round 11 P2 #3); the test MUST assert presence (NOT absence). No `*_refused` event fires. |
  | **Reject refused** — state-machine refusal OR `PackNotFound` race | EXACTLY ONE `portal.packs.reject_refused` record fires with `reason`+`actor_subject`+`pack_id`+`from_state` extras. **No `portal.packs.review.reject` accepted-body record fires** — the categorised log fires only on transition success (mutually exclusive with the refused event; pinned by parametrized assertion that exactly one of the two events fires per request). |
  | **Claim accepted (green path)** — claim transition succeeds | NO log record fires (claim has no T5 evidence surface; the chain row IS the evidence). |
  | **Claim refused** — state-machine refusal OR `PackNotFound` race | EXACTLY ONE `portal.packs.claim_refused` record fires with `reason`+`actor_subject`+`pack_id`+`from_state` extras. |
  | **Approve handler reached** — scope + same-tenant + different-actor (axis (d) of the 4-axis matrix; the only path that reaches the handler body) | EXACTLY ONE `portal.packs.approve_fail_loud_503` record fires with `reason="approve_gate_composer_not_wired"`+`actor_subject`+`pack_id`+`next_sprint="7B.3"` extras. |
  | **Approve short-circuited — axis (a) no scope** | EXACTLY ONE RBAC guard log fires (`enforcement._emit_denial_log` with `reason="scope_not_held"`); NO `portal.packs.approve_fail_loud_503` record fires (handler never reached). |
  | **Approve short-circuited — axis (b) cross-tenant** | EXACTLY ONE tenant-isolation guard log fires (`tenant_isolation._emit_isolation_log` with `reason="tenant_id_mismatch"`); NO `portal.packs.approve_fail_loud_503` record fires. |
  | **Approve short-circuited — axis (c) author-of-pack** | EXACTLY ONE role-separation guard log fires (`role_separation._LOG.warning("portal.rbac.role_separation_refused"…)`); NO `portal.packs.approve_fail_loud_503` record fires. |

  The reject categorised-payload log is the ONLY evidence surface in T5 (per Round 11 P2 #3 / Round 12 P2 #2 carry-forward; T9 amends to chain payload via `evidence_attachments`).
- **Modify: `src/cognic_agentos/portal/api/packs/router.py` (Round 16 P2 #1)** — extend `build_packs_router(*, store)` at `:39-56` to include `build_review_routes(store=store)` alongside the existing `build_author_routes(store=store)` inclusion. The T3-shipped scaffolding wires only `router.include_router(build_author_routes(store=store))` at `:55`; T5 adds a sibling `router.include_router(build_review_routes(store=store))` line and the matching `from cognic_agentos.portal.api.packs.review_routes import build_review_routes` import at `:31` (mirrors the existing `from ... import build_author_routes`). Also update the module docstring at `:1-24` to note review-routes inclusion landed at T5 (was "T5-T7 will add" placeholder text; T5 narrows that to "T5 wires the review sub-router under `/api/v1/packs` for `/review-queue` + `/{pack_id}/claim` + `/{pack_id}/approve` + `/{pack_id}/reject` + `/{pack_id}/evidence`; T6-T7 add the operator + inspection sub-routers in turn"). **Without this wire, T5's `test_review_routes_does_not_register_inspection_list_path` against a manually-mounted test parent would pass while the production `build_packs_router` still exposes only author routes — silently shipping a half-wired review surface.**
- **Create: `src/cognic_agentos/portal/rbac/role_separation.py` (Round 11 P2 #4 + Round 14 P2 #3 — explicit dependency-seam design; Round 15 P2 #1 — closure-safety hardened)** — new CC module per the doctrine sweep above; carries the **`RequireDifferentActorThanCreator` closure-factory** (function, NOT class — see Round 14 P2 #3 + Round 15 P2 #1 below) + 1-value closed-enum `RoleSeparationFailure` literal. **Module-header invariants (Round 15 P2 #1):**
  - **OMIT `from __future__ import annotations`** — sibling RBAC modules carry it (`tenant_isolation.py:37`, `human_actor.py:26`, `enforcement.py:26`) but PEP 563 string-deferred annotations would break the closure-factory pattern (FastAPI's `typing.get_type_hints()` cannot resolve a captured closure variable from a string annotation; the lazy `"Depends(tenant_ownership)"` would `NameError` against module globals because `tenant_ownership` is a closure cell, NOT a module-global symbol — regressing into the T4-era query-param-leakage silent-failure bug).
  - **Type alias `TenantOwnershipDep: TypeAlias = Callable[..., Awaitable[PackRecord]]`** at module scope. Used as the `tenant_ownership` factory-parameter type because `RequireTenantOwnership` is a factory FUNCTION (`def RequireTenantOwnership(...) -> Callable[..., Awaitable[PackRecord]]` at `tenant_isolation.py:96-98`), NOT a class — its return value is what the endpoint declares as `Depends(...)`.

  **Closure-factory pattern code sample** (Round 14 P2 #3 + Round 15 P2 #1):

  ```python
  # role_separation.py — NO `from __future__ import annotations`
  import logging
  from typing import Annotated, Awaitable, Callable, Literal, TypeAlias

  from fastapi import Depends, HTTPException

  from cognic_agentos.packs.storage import PackRecord
  from cognic_agentos.portal.rbac.actor import Actor
  from cognic_agentos.portal.rbac.enforcement import _bind_actor

  # R16 P2 #3 — module-scoped logger mirrors sibling RBAC guards
  # (tenant_isolation.py:50, human_actor.py:37, enforcement.py).
  # Structured-log emission BEFORE every HTTPException so observability
  # tooling sees the denial regardless of whether the HTTP-response
  # surface is captured. Pinned by `test_role_separation_emits_structured_log`.
  _LOG = logging.getLogger(__name__)

  RoleSeparationFailure = Literal["actor_cannot_review_own_pack"]

  #: R15 P2 #1 — type alias for the tenant-ownership factory's return
  #: value. ``RequireTenantOwnership`` (the symbol at
  #: ``tenant_isolation.py:96``) is a factory function — its return value
  #: is what the endpoint declares as ``Depends(...)``. The alias keeps
  #: the role-separation factory's parameter type honest about the
  #: shape it actually accepts.
  TenantOwnershipDep: TypeAlias = Callable[..., Awaitable[PackRecord]]


  def RequireDifferentActorThanCreator(
      *,
      tenant_ownership: TenantOwnershipDep,
  ) -> Callable[..., Awaitable[None]]:
      """Build a FastAPI-compatible dependency that asserts
      ``actor.subject != record.created_by``. Closure-factory shape — the
      ``tenant_ownership`` argument is the EXACT instance the endpoint
      also declares as ``Depends(tenant_ownership)``; FastAPI caches
      sub-dependency results by callable identity within a request, so
      the PackRecord load happens ONCE on the happy path (no duplicate
      ``store.load`` call). The returned closure declares
      ``Depends(tenant_ownership)`` internally so its PackRecord lookup
      hits the same cache entry the endpoint's PackRecord lookup
      populates.

      R15 P2 #1 — annotations on ``_check`` MUST remain live (NOT
      string-deferred) so FastAPI's ``inspect.signature()`` /
      ``typing.get_type_hints()`` introspection resolves the captured
      closure variable ``tenant_ownership`` from the function's
      ``__closure__`` cells (those cells are NOT in module globals; a
      lazy string evaluation against module globals would NameError
      or silently treat ``record`` + ``actor`` as query params).
      """

      async def _check(
          actor: Annotated[Actor, Depends(_bind_actor)],
          record: Annotated[PackRecord, Depends(tenant_ownership)],
      ) -> None:
          if actor.subject == record.created_by:
              # R16 P2 #3 — structured-log emission BEFORE the HTTPException.
              # Sibling RBAC guards (enforcement._emit_denial_log,
              # tenant_isolation._emit_isolation_log, human_actor._LOG.warning)
              # all emit BEFORE raise so observability sees the denial
              # regardless of caller's HTTP-response handling. The reason
              # field is the closed-enum literal so log aggregation can
              # bucket actor_cannot_review_own_pack across tenants without
              # cardinality explosion.
              _LOG.warning(
                  "portal.rbac.role_separation_refused",
                  extra={
                      "reason": "actor_cannot_review_own_pack",
                      "actor_subject": actor.subject,
                      "pack_id": str(record.id),
                      "pack_created_by": record.created_by,
                  },
              )
              raise HTTPException(
                  status_code=403,
                  detail={"reason": "actor_cannot_review_own_pack"},
              )

      return _check
  ```

  At T5 `build_review_routes(store=...)` factory time:

  ```python
  _require_tenant_ownership = RequireTenantOwnership(pack_id_param="pack_id")
  _require_different_actor_than_creator = RequireDifferentActorThanCreator(
      tenant_ownership=_require_tenant_ownership,  # ← SAME instance shared
  )
  # Each review endpoint declares BOTH:
  #   record: Annotated[PackRecord, Depends(_require_tenant_ownership)]
  #   _: Annotated[None, Depends(_require_different_actor_than_creator)]
  # FastAPI's per-request callable-identity cache deduplicates the
  # _require_tenant_ownership resolution → ONE store.load call per request.
  ```

  Refusal-cascade ordering pinned: (1) scope refused → 403 scope_not_held BEFORE tenant; (2) tenant refused → 404 from `_require_tenant_ownership` BEFORE role-separation; (3) actor.subject == record.created_by → 403 actor_cannot_review_own_pack. Pin via `test_role_separation.py::test_dependency_order_rbac_then_tenant_then_role_separation` + `test_role_separation_does_not_duplicate_pack_load` + **NEW R15 P2 #1 test `test_role_separation_resolves_under_fastapi_introspection`** — builds a fresh `FastAPI()` app, mounts a tiny route that depends on `_require_different_actor_than_creator`, calls `app.openapi()` to force FastAPI's full signature introspection, and asserts: (1) no `record` or `actor` parameter appears in the OpenAPI spec's `query` parameter list (would prove the bug); (2) the route returns 403 on author-of-pack (full integration). This test would FAIL deterministically if `from __future__ import annotations` were added to the module — pins the invariant load-bearingly per `feedback_security_regression_hardening.md`.

- **Modify: `src/cognic_agentos/packs/storage.py` (Round 11 P2 #1 + Round 14 P2 #1 — backward-compatible signature)** — extend `list_by_status(state, limit: int = 50, cursor: uuid.UUID | None = None, *, tenant_id: str | None = None)` with optional keyword-only `tenant_id` filter; CC-ADJ to existing CC source. The exact signature shape preserves the pre-T5 positional-or-keyword `limit` / `cursor` with their existing defaults, adding `tenant_id` BEHIND the keyword-only barrier as additive.
- **Modify: `src/cognic_agentos/portal/api/packs/dto.py` (Round 11 P3 #5)** — add `PackEvidenceResponse` Pydantic model + `RejectionReason` 7-value Literal + `RejectDraftRequest` DTO
- Test: `tests/unit/portal/api/packs/test_review_routes.py`. **Round 14 P2 #2 additions**: `test_claim_request_id_bounded_to_64_chars` + `test_reject_request_id_bounded_to_64_chars` (assert `len(request_id) <= 64` on the claim/reject chain rows + the expected `pack-claim--` / `pack-reject-` prefix). **Round 14 P2 #3 additions**: `test_dependency_order_rbac_then_tenant_then_role_separation` (parametrized over claim/approve/reject — RBAC failure → 403 BEFORE tenant lookup; cross-tenant → 404 BEFORE role check; author-of-pack with all gates green → 403 actor_cannot_review_own_pack) + `test_role_separation_does_not_duplicate_pack_load` (asserts `store.load` (via the underlying tenant_isolation `store.load` call) fires EXACTLY ONCE on the happy claim/reject path via a counting-stub store; pins FastAPI cache hit).
- **Test: `tests/unit/portal/rbac/test_role_separation.py` (Round 11 P2 #4 + Round 14 P2 #3 + Round 15 P2 #1 + Round 16 P2 #3)** — pure-unit tests on the `RequireDifferentActorThanCreator` closure factory: (1) admits when `actor.subject != record.created_by`; (2) refuses with 403 + closed-enum body when equal; (3) pins `RoleSeparationFailure` literal at 1 value; (4) **closure-factory shape test** asserts the returned callable's signature reads `actor: Actor` + `record: PackRecord` as sub-dep parameters and references the SAME `tenant_ownership` instance the factory was constructed with (introspection via `inspect.signature(...).parameters`); **(5) Round 15 P2 #1 — `test_module_must_not_import_future_annotations`** parses the live `role_separation.py` AST (via `ast.parse(Path(role_separation.__file__).read_text())`) and asserts NO `ImportFrom(module="__future__", names=[alias(name="annotations")])` node — pins load-bearingly that the module-header invariant cannot regress; **(6) Round 15 P2 #1 — `test_role_separation_resolves_under_fastapi_introspection`** builds a tiny `FastAPI()` test app, mounts a route depending on `_require_different_actor_than_creator`, forces FastAPI's full signature introspection via `app.openapi()`, and asserts no `record` / `actor` parameter appears as `query` parameter in the OpenAPI spec (would prove the broken-closure bug) + asserts the route returns 403 on author-of-pack (integration green path); **(7) Round 16 P2 #3 — `test_role_separation_emits_structured_log`** uses `caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.rbac.role_separation")` and asserts: (a) on the author-of-pack denial path, exactly ONE `_LOG.warning` record fires; (b) its `message` is `"portal.rbac.role_separation_refused"`; (c) its `extra` dict carries `reason="actor_cannot_review_own_pack"` + `actor_subject` + `pack_id` + `pack_created_by`; (d) on the happy admit path (different subjects), NO log record fires. Mirrors the parametrized log-emission test pattern at `tests/unit/portal/rbac/test_tenant_isolation.py::test_tenant_isolation_emits_structured_log_per_reason` (introduced at T2 R1 P2 #2). Per `feedback_security_regression_hardening.md` the AST self-test + OpenAPI introspection + caplog emission are the load-bearing triple for the role_separation invariants.
- **Test: `tests/unit/packs/test_storage_list_by_status.py` (Round 14 P2 #1 — NEW)** — three regressions per the L109 enumeration: `test_list_by_status_state_only_backward_compatible` + `test_list_by_status_existing_pagination_signature` + `test_list_by_status_tenant_filtered_pagination`.

**Endpoints (ADR-012 §61-66 + BUILD_PLAN §617):**

| Method | Path | Required scope + dependencies | Lifecycle action |
|---|---|---|---|
| GET | `/api/v1/packs/review-queue` (**Round 12 P2 #1 — moved off `/api/v1/packs?status=submitted`**) | `RequireScope("pack.review.claim")` (Round 2 P3 #8 — the reviewer queue is gated by the same scope that claims from it; examiner-facing `pack.audit.read` would lock reviewers out of their own queue per BUILD_PLAN §622-625 scope-set) | **Round 11 P2 #1:** handler calls `store.list_by_status("submitted", tenant_id=actor.tenant_id, ...)`. Server-side WHERE clause leverages the existing `ix_packs_tenant_state` composite index per migration L129 — no per-row in-handler filter (avoids pagination skew where filtering N records server-side may yield <limit). No per-pack tenant-isolation dependency required since the storage WHERE clause carries the constraint atomically. **Round 12 P2 #1 — path collision fix:** ADR-012 §62 sketched the path as `GET /api/v1/packs?status=submitted` but FastAPI dispatches by path+method, NOT query string — that path collides with T7's examiner inspection list at `GET /api/v1/packs`, with whichever sub-router mounts first shadowing the other. Resolution: T5 owns `GET /api/v1/packs/review-queue` (distinct path, gated by `pack.review.claim`); T7 owns `GET /api/v1/packs` (examiner list, gated by `pack.audit.read`). Both routers mount cleanly; both routes are reachable. ADR-012 §62 sketch is impl-deviation noted in the plan; the ADR sketch's `?status=submitted` query-param is preserved as a forward-compat alias if needed (NOT 7B.2). |
| POST | `/api/v1/packs/{pack_id}/claim` | `RequireScope("pack.review.claim")` + **shared `_require_tenant_ownership` instance + closure-factory `_require_different_actor_than_creator(tenant_ownership=_require_tenant_ownership)` (Round 11 P2 #4 + Round 14 P2 #3 — ADR-012 §17 dependency-seam design)** | `transition("claim")` — `submitted → under_review`. Refuses with 403 + closed-enum `actor_cannot_review_own_pack` if the claiming actor is also `record.created_by`. **Round 14 P2 #2 — request_id minted via shared `_mint_request_id(_PACK_CLAIM_REQUEST_ID_PREFIX)`** (12 + 32 = 44 chars; under `decision_history.request_id` String(64) cap). **Round 16 P2 #2 — `PackNotFound` race translation:** the tenant-isolation dependency preloads the `PackRecord` BEFORE `store.transition()` fires; a concurrent deleter between the preload + the transition's `SELECT ... FOR UPDATE` raises `PackNotFound` inside the storage precondition. The handler MUST catch `PackNotFound` and translate to 404 + `detail={"reason": _PACK_NOT_FOUND_REASON}` — mirrors the T4 R1 P2 #3 fix for submit/cancel at `author_routes.py:579-594` + `:658-672`. Pinned by `test_claim_handles_pack_not_found_race`. |
| POST | `/api/v1/packs/{pack_id}/approve` | `RequireScope("pack.review.approve")` + **shared `_require_tenant_ownership` + `_require_different_actor_than_creator(tenant_ownership=...)` (Round 11 P2 #4 + Round 14 P2 #3)** | **FAIL-LOUD per Round 1 P2 #1.** Endpoint mounts; **RBAC → tenant-isolation → role-separation** dependencies fire IN THAT ORDER (so the auth trail records the attempt + the role-separation guard refuses author-of-pack BEFORE the 503 fires); on success path (scoped + same-tenant + different-actor) the handler raises `HTTPException(503, detail={"reason": "approve_gate_composer_not_wired", "next_sprint": "7B.3", "adr": "ADR-012 §41"})`. NO state transition. NO chain row emitted. **NO `transition()` call → NO request_id minted** for the 503 path (Round 14 P2 #2 — approve does NOT need a request_id minter in T5 since fail-loud short-circuits before `store.transition()`). NO green-path test in 7B.2 — only the fail-loud contract is pinned via the **4-axis matrix** (Round 11 P3 #6) below. |
| POST | `/api/v1/packs/{pack_id}/reject` | `RequireScope("pack.review.reject")` + **shared `_require_tenant_ownership` + `_require_different_actor_than_creator(tenant_ownership=...)` (Round 11 P2 #4 + Round 14 P2 #3)** | **T5 narrow scope (Round 11 P2 #3 + Round 14 P2 #2):** `transition("reject")` — `under_review → rejected` as a BARE transition. Body carries `RejectDraftRequest` DTO declaring `reason: RejectionReason` (7-value closed-enum per Round 11 P2 #2) + `comments: str` (non-empty). These fields are emitted via structured-log only in 7B.2; they do NOT enter the chain `payload` until T9 wires the categorised payload via `evidence_attachments`. Idempotent re-reject lands 409 `lifecycle_transition_invalid_state_pair`. **Round 14 P2 #2 — request_id minted via shared `_mint_request_id(_PACK_REJECT_REQUEST_ID_PREFIX)`** (T5 owns the prefix declaration; T9 reuses it when amending the handler to write `evidence_attachments`). **Round 16 P2 #2 — `PackNotFound` race translation:** same race + same translation as the claim endpoint above; pinned by `test_reject_handles_pack_not_found_race`. |
| GET | `/api/v1/packs/{pack_id}/evidence` | `RequireScope("pack.audit.read")` + `RequireTenantOwnership(pack_id)` | **Round 11 P3 #5:** Response shape declared by `PackEvidenceResponse` DTO at `portal/api/packs/dto.py` — `{"conformance": dict[str, Any] | None, "reviewer_evidence_panels": None}` (always-null literal in 7B.2; 7B.3 fills in). Read path walks `store.load_lifecycle_history(pack_id)`, finds the most-recent `event_type == "pack.lifecycle.submitted"` row, surfaces its `payload.get("conformance")` or null. Pre-T9 chain rows have no `conformance` key — endpoint returns null (NOT 500). |

**T5 caveat (Round 11 P3 #5 refined):** GET `/{pack_id}/evidence` returns ONLY the conformance evidence attached by T9's auto-run-on-submit wire (read from the chain `payload.conformance` per the T9 schema fix in Round 1 P2 #4) — NOT the full reviewer evidence panels (those are 7B.3). Until T9 lands, all submit chain rows are pre-T9 fixture chains that carry no `conformance` key; the endpoint surfaces `{"conformance": null, "reviewer_evidence_panels": null}` gracefully. Both the pre-T9 null path AND the post-T9 populated path are pinned via tests (the latter via a hand-built audit-row fixture carrying the T9 schema, forward-looking).

**RejectionReason 7-value closed-enum vocabulary (Round 11 P2 #2):**

Anchored to ADR-012 §41's 5-gate composition plus operational categories:

```python
RejectionReason = Literal[
    "signature_invalid",                              # cosign / SLSA failure (gate 1)
    "evaluation_pass_rate_below_threshold",           # ADR-010 eval harness red (gate 2)
    "adversarial_corpus_pass_rate_below_threshold",   # ADR-011 adversarial red (gate 3)
    "owasp_conformance_red",                          # ADR-012 §41 OWASP gate red (gate 4)
    "data_governance_unfit",                          # ADR-017 data-class / purpose mismatch
    "documentation_incomplete",                       # operational — manifest fields incomplete
    "other",                                          # free-form fallback; `comments` is the diagnostic
]
```

Closed-enum stability pinned by `tests/unit/portal/api/packs/test_review_routes.py::TestSprint7B2RejectionReasonVocabulary::test_literal_values_pinned_at_7`. **`comments: str` is required on every reject body** (non-empty); `"other"` REQUIRES `comments` to carry the diagnostic (enforced via Pydantic `model_validator(mode="after")` — empty `comments` when `reason == "other"` refuses at 422).

**Approve-endpoint fail-loud contract (Round 1 P2 #1 resolution + Round 11 P3 #6 4-axis matrix):**

ADR-012 §41 requires `approve` to REFUSE when any of the 5 gates is red. Shipping a green-path `approve` that DOES the transition without enforcing the gates would either: (a) make the transition rollback-required when 7B.3 wires the gate composer in (data corruption risk if any pack got approved between 7B.2 land and 7B.3 land), or (b) silently violate ADR-012 §41 in production. Neither is acceptable per the production-grade rule.

Resolution: ship the endpoint as fail-loud `HTTPException(503)`. The endpoint surface exists; RBAC + tenant-isolation + role-separation dependencies fire IN ORDER (so the auth + audit-trail-for-attempts works + author-of-pack is refused before the 503); the gate composer absence raises 503 with a structured payload pointing reviewers / authors at the next-sprint ETA. This matches the production-grade scaffold-with-fail-loud pattern documented in `protocol/mcp_host.MCPHost.call_tool` (Sprint-5 plan §T2 step 5 R3 P1 doctrine).

**Round 11 P3 #6 — 4-axis fail-loud test matrix** (pinning RBAC → tenant → role-separation → 503 ordering):

| Axis | Actor profile | Expected status | Expected `detail.reason` |
|---|---|---|---|
| (a) no scope | actor lacks `pack.review.approve` | 403 | `scope_not_held` |
| (b) cross-tenant | scope held; `actor.tenant_id != pack.tenant_id` | 404 | `tenant_id_mismatch` |
| (c) author-of-pack | scope + same-tenant; `actor.subject == record.created_by` | 403 | `actor_cannot_review_own_pack` |
| (d) green | scope + same-tenant + different-actor | **503** | `approve_gate_composer_not_wired` |

Each axis asserts: (1) HTTP status, (2) structured body's `detail.reason`, (3) chain row count unchanged (no transition), (4) pack state unchanged.

Halt summary watchpoints:
- (a) Approve endpoint NEVER transitions state in 7B.2 — pin via test that counts chain rows before + after an approve attempt and asserts equal
- (b) 503 + structured `reason: approve_gate_composer_not_wired` shape stable + closed-enum at module level
- (c) **Closed-enum `RejectionReason` vocabulary at module level — 7-value vocabulary per Round 11 P2 #2** (anchored to ADR-012 §41 5-gate composition + operational categories: `signature_invalid` / `evaluation_pass_rate_below_threshold` / `adversarial_corpus_pass_rate_below_threshold` / `owasp_conformance_red` / `data_governance_unfit` / `documentation_incomplete` / `other`). Reject body DTO carries `reason` + `comments: str` (non-empty; required when `reason == "other"`).
- (d) ADR-012 §17 cross-role separation — **enforced by NEW `portal/rbac/role_separation.py::RequireDifferentActorThanCreator` (Round 11 P2 #4)** wired onto claim + approve + reject endpoints; refuses with 403 + closed-enum `actor_cannot_review_own_pack`. Pinned by `test_role_separation.py` (unit) + `test_review_routes.py` per-endpoint integration tests + the approve 4-axis matrix above (axis c).
- (e) Tenant-isolation enforcement at every review-surface endpoint that takes a `{pack_id}` path param — pinned by `test_review_routes.py::test_cross_tenant_returns_404`. **Round 11 P2 #1 + Round 12 P2 #1:** `GET /api/v1/packs/review-queue` (moved off the colliding `?status=submitted` query path at Round 12 P2 #1) is the ONE endpoint without a `{pack_id}` param; tenant isolation lives in the storage WHERE clause (server-side filter) rather than a dependency; pinned by `test_reviewer_queue_filters_by_tenant_id` with a two-tenant fixture. **Round 17 P2 #1 — path-param-name convention:** all review-surface endpoints that take a path UUID use `{pack_id}` (NOT `{id}`) matching the T4 author-surface convention (`/drafts/{pack_id}/...`) and the live shared dependency `RequireTenantOwnership(pack_id_param="pack_id")` at `author_routes.py:388`. The dependency at `tenant_isolation.py:122-129` reads `request.path_params.get(pack_id_param)` and raises `RuntimeError("path-param mismatch")` if absent — using the wrong path-param name fails-loud as a 500 routing bug instead of refusing with structured RBAC/tenant semantics. **NEW regression `test_review_routes_path_param_name_matches_dependency`** parametrized over each review endpoint with a path UUID — asserts the route's compiled path string contains `"{pack_id}"` AND that issuing a real request with a malformed UUID returns 404 with `detail.reason="pack_not_found"` (the structured tenant-isolation refusal), NEVER 500 (which would prove the path-param mismatch). Test parametrized over claim / approve / reject / evidence (the 4 endpoints that take `{pack_id}`).
- (h) **Route-ownership regression — T5-narrow proof (Round 12 P2 #1 + Round 13 P2 #1 split; Round 15 P2 #2 — mount-prefix correction)** — `test_review_routes.py::test_review_routes_does_not_register_inspection_list_path` asserts at T5-execution time (`inspection_routes.py` not yet imported) that the review sub-router carries `GET /review-queue` (relative path on the un-prefixed sub-router) BUT does NOT register `GET /` (or any path that would land at `/api/v1/packs` after the parent mounts at `/api/v1/packs`). **Round 15 P2 #2 — the test MUST use one of two correct shapes** (Round 13's original wording asserted full-prefix paths against an un-mounted sub-router, which would have been vacuously true since the sub-router exposes only relative paths):
  - **Shape A (mount under a test parent — recommended):** build `_review_router = build_review_routes(store=stub_store)`, then mount it onto a fresh `FastAPI()` test app via a parent `APIRouter(prefix="/api/v1/packs")` (mirrors what `build_packs_router` does at production); walk `app.routes` and assert the COMPILED full path `/api/v1/packs/review-queue` exists with `methods={"GET"}` + `pack.review.claim` dependency, AND assert NO route in `app.routes` has compiled path equal to `/api/v1/packs` (the T7 examiner-list path; verifies the review sub-router didn't claim that path inadvertently).
  - **Shape B (test raw sub-router with relative paths):** walk the un-mounted `_review_router.routes` and assert relative path `/review-queue` exists + relative path `/` (or `""`) does NOT exist (latter would be what mounts to `/api/v1/packs` under the parent prefix).
  Shape A is preferred because it tests the actually-deployed shape; the test fixture builds the full prefix-mount the production code path uses. **The full both-routes-reachable regression `test_review_queue_and_inspection_list_both_reachable` ships at T7** once `inspection_routes.py` exists — see §T7 Tests for the carry-forward.
- (f) Audit-chain emission for `/claim` + `/reject` (NOT `/approve` — no chain row in 7B.2). **Reject chain row in T5 carries the bare transition payload only (no `rejection_reason` / `reviewer_comments` keys yet) — T9 carry-forward below.**
- (g) **T9 carry-forward (Round 11 P2 #3) — reject categorised-payload migration:** T9 amends `transition()` with `evidence_attachments: dict[str, Any] | None` (mirrors the T9 conformance kwarg pattern); the T5 reject handler is then amended at T9 to pass `evidence_attachments={"rejection_reason": body.reason, "reviewer_comments": body.comments}` so the chain row's `payload` carries these fields for examiner traceability. T5 ships structured-log emission only; T9 owns the chain-payload extension. Watchpoint (g) is a forward-looking pin — T5 tests assert the chain row does NOT carry these fields in 7B.2; T9 tests assert it DOES post-T9.

---

### Task 6: Operator surface endpoints — 5 endpoints *(CRITICAL CONTROLS)*

**Class:** CC. **Halt: YES.**

**Files:**
- Create: `src/cognic_agentos/portal/api/packs/operator_routes.py`. **Round 18 P2 #4 + Round 19 P3 #3 — operator request_id minters:** all 5 operator handlers call `PackRecordStore.transition(..., request_id=...)`, so T6 declares 5 new request-id prefix constants at module scope (mirrors T5 review_routes pattern). **Exact prefix strings (Round 19 P3 #3 — corrected length count):** `_PACK_ALLOW_LIST_REQUEST_ID_PREFIX: Final[str] = "pack-alowlst-"`, `_PACK_INSTALL_REQUEST_ID_PREFIX: Final[str] = "pack-install-"`, `_PACK_DISABLE_REQUEST_ID_PREFIX: Final[str] = "pack-disable-"`, `_PACK_REVOKE_REQUEST_ID_PREFIX: Final[str] = "pack-revoke--"` (double-dash for prefix-uniqueness against `pack-revoke` substring matches), `_PACK_UNINSTALL_REQUEST_ID_PREFIX: Final[str] = "pack-uninstal"`. **Per-prefix lengths are NOT uniform across T4/T5/T6** — T4 + T5 prefixes are 12 chars (`pack-submit-` / `pack-cancel-` / `pack-claim--` / `pack-reject-`); T6 prefixes are 13 chars (each). What IS uniform is the **invariant `len(<prefix>) + 32 <= 64`** that the module-foot build-time `assert` pins for every prefix (the `decision_history.request_id` `String(64)` column cap). T4 / T5 IDs are 12 + 32 = 44 chars; T6 IDs are 13 + 32 = 45 chars — both fit comfortably under 64. **Caplog + regression tests assert the invariant** `len(request_id) <= 64` AND the expected prefix string per verb, NOT a specific total-length count — eliminates the false-uniformity coupling. All 5 cross-import `_mint_request_id` from `author_routes.py:98-108`. **Round 18 P2 #4 — structured-log contract** (mirrors T5 review_routes 4-event table, scaled to 5 operator verbs): module-scoped `_LOG = logging.getLogger(__name__)` + 5 canonical `portal.packs.<verb>_refused` events (`portal.packs.allow_list_refused` / `portal.packs.install_refused` / `portal.packs.disable_refused` / `portal.packs.revoke_refused` / `portal.packs.uninstall_refused`) — each carries `reason` (closed-enum: `pack_not_found` from race OR `LifecycleRefusalReason` from state-machine) + `actor_subject` + `pack_id` + `from_state` extras. **Round 19 P2 #2 — `actor_type_must_be_human` is NOT in this vocabulary**: `RequireHumanActor()` is a FastAPI sub-dependency that runs BEFORE the operator handler body; a service-token denial short-circuits there and the existing `human_actor._LOG.warning(...)` emits its own log (`reason="actor_type_must_be_human"`). The operator handler never executes on that axis, so it cannot — and must not — emit `portal.packs.allow_list_refused` for that reason. Caplog test contract: a service-actor allow-list request produces EXACTLY ONE `cognic_agentos.portal.rbac.human_actor` log record AND ZERO `portal.packs.allow_list_refused` records (pinned by `test_allow_list_service_actor_emits_human_actor_log_only`). **Round 18 P2 #4 — `PackNotFound` race translation** for all 5 handlers — same shape as T4 submit/cancel + T5 claim/reject; race between `RequireTenantOwnership` preload + `store.transition()` SELECT FOR UPDATE raises `PackNotFound` from inside the storage precondition → translate to 404 + `detail={"reason": _PACK_NOT_FOUND_REASON}` (shared with T5 + T4 via either cross-import or module-local redeclaration).
- **Modify: `src/cognic_agentos/portal/api/packs/router.py` (Round 18 P2 #3 — production-wiring; mirrors R16 P2 #1 for T5)** — extend `build_packs_router(*, store)` to include `build_operator_routes(store=store)` alongside the existing T4 author + T5 review inclusions. Add `from cognic_agentos.portal.api.packs.operator_routes import build_operator_routes` import + `router.include_router(build_operator_routes(store=store))` call. Update module docstring to record T6 wired-state.
- Test: `tests/unit/portal/api/packs/test_operator_routes.py`

**Endpoints (ADR-012 §68-73 + BUILD_PLAN §618):**

| Method | Path | Required scope + dependencies | Lifecycle action |
|---|---|---|---|
| POST | `/api/v1/packs/{pack_id}/allow-list` | `RequireScope("pack.allow_list")` + `RequireTenantOwnership(pack_id)` + **`RequireHumanActor()` per Round 1 P3 #8** | `transition("allow_list")` — `approved → allow_listed`. **The human-actor-type guarantee is an explicit dependency: service-token actors with `pack.allow_list` scope are REFUSED here with 403 + closed-enum `actor_type_must_be_human`. Pinned by test `test_operator_routes.py::test_allow_list_refuses_service_actor` per Round 1 reviewer answer #1.** **Round 18 P2 #4 — request_id via `_mint_request_id(_PACK_ALLOW_LIST_REQUEST_ID_PREFIX)`; `PackNotFound` race translation → 404 `pack_not_found`; refusal events log to `portal.packs.allow_list_refused`.** |
| POST | `/api/v1/packs/{pack_id}/install` | `RequireScope("pack.install")` + `RequireTenantOwnership(pack_id)` | `transition("install")` — `allow_listed → installed`. **Round 18 P2 #4 — request_id via `_mint_request_id(_PACK_INSTALL_REQUEST_ID_PREFIX)`; `PackNotFound` race → 404; refusal log `portal.packs.install_refused`.** |
| POST | `/api/v1/packs/{pack_id}/disable` | `RequireScope("pack.disable")` + `RequireTenantOwnership(pack_id)` | `transition("disable")` — `installed → disabled`. **Round 18 P2 #4 — request_id via `_mint_request_id(_PACK_DISABLE_REQUEST_ID_PREFIX)`; `PackNotFound` race → 404; refusal log `portal.packs.disable_refused`.** |
| POST | `/api/v1/packs/{pack_id}/revoke` | `RequireScope("pack.revoke")` + `RequireTenantOwnership(pack_id)` | `transition("revoke")` — `installed/disabled → revoked`. **Round 18 P2 #4 — request_id via `_mint_request_id(_PACK_REVOKE_REQUEST_ID_PREFIX)`; `PackNotFound` race → 404; refusal log `portal.packs.revoke_refused`.** |
| DELETE | `/api/v1/packs/{pack_id}/install` | `RequireScope("pack.uninstall")` + `RequireTenantOwnership(pack_id)` | `transition("uninstall")` — `disabled/revoked → uninstalled`. **Round 18 P2 #4 — request_id via `_mint_request_id(_PACK_UNINSTALL_REQUEST_ID_PREFIX)`; `PackNotFound` race → 404; refusal log `portal.packs.uninstall_refused`.** |

**Allow-list human-actor doctrine (Round 1 P3 #8 + reviewer answer #1 resolution):**

AGENTS.md "Human-only decisions" lists "Per-tenant allow-list changes" — binding Claude (the AI assistant), but the reviewer's concern is broader: a scoped SERVICE-TOKEN actor (e.g. a CI/CD system holding `pack.allow_list`) silently becoming the human-approval path is exactly the failure mode the rule guards against. Resolution: the `Actor` model carries a closed-enum `actor_type` field (`"human"` / `"service"`); the `RequireHumanActor()` dependency on `/allow-list` ONLY refuses service tokens, not the AI-assistant case (which is upstream — Claude never holds a bank's actor token in production). Bank-overlay binders are responsible for setting `actor_type` correctly when minting actor identities from the underlying auth backend (OIDC token scope, mTLS cert OU, etc).

Halt summary watchpoints:
- (a) Multi-from transitions (`revoke` accepts both `installed` and `disabled`; `uninstall` accepts both `disabled` and `revoked`) — pin via parametrized green-path tests over the 7B.1 `_VALID_TRANSITIONS` table
- (b) Allow-list human-actor-type guarantee — pinned by `test_allow_list_refuses_service_actor` + `test_allow_list_admits_human_actor`
- (c) Tenant-isolation enforcement at every operator-surface endpoint — pinned by `test_cross_tenant_returns_404`
- (d) Audit-chain emission for each transition (allow-list audit row must record `actor.actor_type == "human"` in payload for examiner traceability)
- (e) Idempotency: re-revoke on already-revoked returns 409 with closed-enum `LifecycleTransitionRefused("lifecycle_transition_revoke_already_revoked")` from 7B.1
- (f) **Round 18 P2 #3 — production-wiring regression** — `test_build_packs_router_includes_operator_routes` asserts the production `build_packs_router(store=stub_store)` factory output includes the 5 operator paths under `/api/v1/packs/{pack_id}/...` (allow-list/install/disable/revoke/uninstall via POST or DELETE as appropriate); test mirrors the T5 production-wiring regression pattern (R16 P2 #1).
- (g) **Round 18 P2 #4 — request_id bounded-length parity with T4/T5** — `test_operator_request_id_bounded_to_64_chars` parametrized over all 5 operator verbs asserting `_mint_request_id(<prefix>)` returns ≤64 chars for each `_PACK_<VERB>_REQUEST_ID_PREFIX`. Module-foot build-time invariant pins the 5-prefix-length sum statically.
- (h) **Round 18 P2 #4 — `PackNotFound` race translation parity with T4/T5** — `test_<verb>_handles_pack_not_found_race` parametrized over all 5 operator verbs; stub-store regression where `transition()` raises `PackNotFound`; assert handler translates to 404 + `detail={"reason": "pack_not_found"}`; no 500 leak.
- (i) **Round 18 P2 #4 — structured refusal log emission parity** — `test_<verb>_refused_emits_structured_log` parametrized over all 5 operator verbs; caplog assertion for `portal.packs.<verb>_refused` event with closed-enum reason + actor_subject + pack_id + from_state extras.

---

### Task 7: Inspection surface endpoints — 4 endpoints *(NOT-CC endpoint work + CC-ADJ storage touch)*

**Class:** NOT-CC endpoint work + CC-ADJ storage touch. **Halt: YES** (Round 20 P2 #1).

**Why CC-ADJ / Halt-YES:** Endpoint handlers themselves are read-only and bypass route-level state transitions, but the Round 19 P2 #4 storage-modify row adds `list_for_tenant` to `packs/storage.py` — a critical-control module per the AGENTS.md `packs/storage.py` listing. The new method IS the tenant-enforcement boundary for `GET /api/v1/packs` (the only inspection endpoint without a `{pack_id}` path-param; the storage WHERE-clause is the authoritative server-side filter that cannot be retrofitted by route-level guards). Same shape as T5's `list_by_status` CC-ADJ extension; T5 ships halt-YES, T7 likewise. **Halt-summary requirements per Round 20 P2 #1 (refined Round 21 P2 #2):** (1) `packs/storage.py` line + branch coverage at ≥95% / ≥90% on the new method; (2) test-vector evidence at halt time showing all **5** regressions in `test_storage_list_for_tenant.py` are green (4-tenant-filter regressions + the R21 P2 #2 SQL-shape regression) AND the new route-level `actor_tenant_id_missing` guard test (per Round 20 P2 #2 + Round 21 P2 #1 type-corrected) is green; (3) explicit acknowledgement that `ix_packs_tenant_state` index presence is covered by the existing migration test at `test_migration_20260510_0003.py::test_packs_indexes_present` + the new method's SQL-shape coverage in `test_storage_list_for_tenant.py` proves the WHERE clause uses the index columns (no env-gated EXPLAIN proof required — downgraded per Round 21 P2 #2 to keep the watchpoint matched to declared tests); (4) confirmation no Doctrine Lock D touch.

**Files:**
- Create: `src/cognic_agentos/portal/api/packs/inspection_routes.py`. Read-only — no `store.transition()` calls; no request-id prefix needed; no `PackNotFound` race translation needed (read endpoints surface 404 from the tenant-isolation dependency's existing `pack_not_found` reason).
- **Modify: `src/cognic_agentos/packs/storage.py` (Round 19 P2 #4 — CC-ADJ tenant-scoped inspection seam; Round 22 P2 #2 private statement-builder)** — `GET /api/v1/packs` is the only inspection endpoint without a `{pack_id}` path param, so `RequireTenantOwnership` cannot enforce row-level tenant filtering — server-side WHERE-clause filtering is required (mirrors the T5 reviewer-queue solution via `list_by_status(state, ..., tenant_id=...)`). The T5 extension is state-filtered; T7 inspection needs an UN-state-filtered listing scoped to the actor's tenant. **NEW method `list_for_tenant(tenant_id: str, *, limit: int = 50, cursor: uuid.UUID | None = None, state: PackState | None = None) -> list[PackRecord]`** — server-side WHERE clause `tenant_id == :tenant_id` (REQUIRED — not optional like `list_by_status`; the inspection endpoint cannot list packs without a tenant scope) AND optional `state == :state` when provided. Uses the existing `ix_packs_tenant_state` composite index per migration L129. Pure-read change; no Doctrine Lock D touch. **Round 22 P2 #2 — private statement-builder pattern**: `list_for_tenant` MUST extract its query construction into a module-private helper `_build_list_for_tenant_stmt(tenant_id, *, limit, cursor, state=None) -> Select` that the public method calls before passing to `await conn.execute(...)`. The R21 P2 #2 SQL-shape regression imports this SAME builder via `cognic_agentos.packs.storage._build_list_for_tenant_stmt` and asserts on its compiled output — eliminates the "test-writes-its-own-select-and-assertion-passes-while-production-drifts" vacuous-proof bug class. The builder is module-private (underscore prefix) but module-public for the test import, mirroring the existing `_row_to_record` helper convention in the live module at `packs/storage.py:913`. T7 is **NOT-CC at the task level** but this storage-modify row makes T7 **CC-ADJ to `packs/storage.py`** (same shape as T5 R11 P2 #1 list_by_status extension). Pinned by **5 regressions** on `tests/unit/packs/test_storage_list_for_tenant.py` (R21 P2 #2 bumped 4 → 5; R22 P2 #2 + P3 #3 propagation refresh): (1) `test_list_for_tenant_returns_only_matching_tenant_rows` (two-tenant fixture; tenant-A actor gets only tenant-A rows); (2) `test_list_for_tenant_with_optional_state_filter` (when `state` provided, applies AND clause; index used); (3) `test_list_for_tenant_pagination_cursor` (cursor pagination behaves identically to `list_by_status`'s cursor logic); **(4) Round 20 P2 #2 corrected — `test_list_for_tenant_with_no_packs_returns_empty_list` (storage-layer test asserts the method behaves correctly when the tenant has no packs; the prior R19 wording "empty tenant returns empty list" conflated the empty-`tenant_id` case (kernel binder misconfig — now route-refused with 500 per R20 P2 #2) with the empty-result-set case (legitimate happy-path read). The renamed test asserts the latter: a tenant string with no matching packs returns `[]` correctly);** **(5) Round 21 P2 #2 + Round 22 P2 #2 — `test_list_for_tenant_compiles_with_indexed_where_clause`** — imports the module-private `_build_list_for_tenant_stmt` (the SAME builder the production `list_for_tenant` invokes) and asserts the compiled SQL string contains `packs.tenant_id = ` (always) AND `packs.state = ` (when state non-None); proves the production query path uses the `ix_packs_tenant_state` composite-index columns. The shared-builder pattern eliminates the vacuous-proof bug class where a test-local duplicate `select` could pass while the production query drifts.

**Round 20 P2 #2 + Round 21 P2 #1 — route-level `actor_tenant_id_missing` preflight guard** (added at `inspection_routes.py` for the list endpoint). The other 3 inspection endpoints (`/{pack_id}`, `/{pack_id}/audit`, `/{pack_id}/invocations`) inherit the existing `tenant_isolation.RequireTenantOwnership` semantics including its existing 500 `actor_tenant_id_missing` emission at `tenant_isolation.py:144-152` — the list endpoint is the ONLY one without a `{pack_id}` so the ONLY one without the existing guard. T7 reuses the existing structured-log helper `tenant_isolation._emit_isolation_log` (already public-via-import within `portal/rbac/`) to keep the wire-protocol-public structured-log message + closed-enum `reason` identical to the path-param-tenant-isolated endpoints. **Type-correctness (Round 21 P2 #1):** the live helper signature at `tenant_isolation.py:75-80` is `_emit_isolation_log(*, reason: TenantIsolationFailure, actor_subject: str, pack_id: str)` — `pack_id` is REQUIRED `str` (NOT `str | None`); the R20 wording "the helper accepts None per its existing signature" was wrong. AND `Actor.tenant_id` at `actor.py:71` is typed `str` (NOT `str | None`) — a `None` value cannot be constructed through normal Pydantic validation. The implementer pattern below passes the stable sentinel string `"<list>"` for `pack_id` (no `{pack_id}` exists at this endpoint; the sentinel keeps log-aggregator bucketing clean and stays type-safe under mypy) AND tests only the `tenant_id=""` axis through normal Pydantic construction. **Implementer pattern:**

```python
# In inspection_routes.py list handler — BEFORE calling store.list_for_tenant():
# Round 21 P2 #1: pack_id="<list>" sentinel keeps the type-checker happy
# (helper signature is `pack_id: str` not `str | None`); empty-string actor
# tenant_id is the only reachable falsy case under the live Actor schema
# (Actor.tenant_id: str, no Optional). Both branches of the falsy check
# (`""`, future `0`, etc) route here identically.
if not actor.tenant_id:
    _emit_isolation_log(
        reason="actor_tenant_id_missing",
        actor_subject=actor.subject,
        pack_id="<list>",  # sentinel — no {pack_id} path-param at this endpoint
    )
    raise HTTPException(
        status_code=500,
        detail={"reason": "actor_tenant_id_missing"},
    )
```

Pinned by `test_list_returns_500_when_actor_tenant_id_missing` at `test_inspection_routes.py` — fixture-actor with `tenant_id=""` (empty string; constructible via normal Pydantic validation) produces 500 + structured body + caplog assertion that the record's `extra["pack_id"] == "<list>"`. **The `Actor(tenant_id=None)` axis is NOT covered** (`Actor.tenant_id: str` per `actor.py:71` rejects None at validation time; reaching the route handler with a None `tenant_id` is impossible under the typed contract; any future relaxation to `str | None` would re-open this axis with its own test). Replaces the R19 misleading "empty-tenant storage success" semantics with explicit route-level refusal coverage.
- **Modify: `src/cognic_agentos/portal/api/packs/router.py` (Round 18 P2 #3 — production-wiring; mirrors R16 P2 #1 for T5 + R18 P2 #3 for T6)** — extend `build_packs_router(*, store)` to include `build_inspection_routes(store=store)` alongside the existing T4 author + T5 review + T6 operator inclusions. Add `from cognic_agentos.portal.api.packs.inspection_routes import build_inspection_routes` import + `router.include_router(build_inspection_routes(store=store))` call. Update module docstring to record T7 wired-state (now all four sub-routers wired; the production router is complete at T7).
- Test: `tests/unit/portal/api/packs/test_inspection_routes.py`

**Endpoints (ADR-012 §75-79 + BUILD_PLAN §619):**

| Method | Path | Required scope + dependencies | Behavior |
|---|---|---|---|
| GET | `/api/v1/packs` | `RequireScope("pack.audit.read")` | List packs **scoped to actor.tenant_id**; cross-tenant rows filtered server-side via **NEW `store.list_for_tenant(actor.tenant_id, limit=…, cursor=…)`** seam (Round 19 P2 #4). No per-pack `RequireTenantOwnership` dependency since there is no `{pack_id}` path-param to verify; the storage WHERE-clause is the authoritative tenant boundary. Inspection is examiner-facing per ADR-012 §75. |
| GET | `/api/v1/packs/{pack_id}` | `RequireScope("pack.audit.read")` + `RequireTenantOwnership(pack_id)` | Pack detail incl. lifecycle history (read from `packs/storage`'s state cache) |
| GET | `/api/v1/packs/{pack_id}/audit` | `RequireScope("pack.audit.read")` + `RequireTenantOwnership(pack_id)` | Hash-chained audit events for this pack — reads via `DecisionHistoryStore` filtered by `payload.pack_id` (per the `_load_for_pack_id` pattern at `packs/storage.py:565-606`) |
| GET | `/api/v1/packs/{pack_id}/invocations?from&to` | `RequireScope("pack.invocation.read")` + `RequireTenantOwnership(pack_id)` | Pack invocation history derived from audit events. **Sprint 7B.2 scope:** returns audit-derived invocation events only; deeper analytics deferred. |

Pagination + cursor handling: reuse the bounded-pagination + opaque-cursor pattern from `protocol/mcp_host.py` (Sprint-5 doctrine). Tests pin cursor opacity + per-tenant scoping + cross-tenant refusal.

**Tenant-isolation tests for the inspection surface (Round 1 P2 #3):**

- `test_list_filters_by_tenant_id` — list endpoint returns ONLY actor.tenant_id rows; pack from tenant B is not in tenant A's list
- `test_detail_cross_tenant_returns_404` — GET `/{pack_id}` for a pack belonging to tenant B from a tenant-A actor returns 404 (not 403 — info-leak prevention)
- `test_audit_cross_tenant_returns_404` — same for `/{pack_id}/audit`
- `test_invocations_cross_tenant_returns_404` — same for `/{pack_id}/invocations`
- **`test_review_queue_and_inspection_list_both_reachable` (Round 12 P2 #1 + Round 13 P2 #1 split — T5 carry-forward landing at T7)** — once `inspection_routes.py` exists, asserts the fully-composed `build_packs_router(store=…)` route table contains BOTH `GET /api/v1/packs/review-queue` (T5 reviewer queue; `pack.review.claim` dependency) AND `GET /api/v1/packs` (T7 examiner list; `pack.audit.read` dependency). Walks `app.routes` after mounting `build_packs_router` on a fresh `FastAPI()` test app; asserts both `Route` objects exist, asserts their distinct `name` + `methods={"GET"}` + `path` + dependency-set signatures; pins neither shadows the other after BOTH sub-routers register. T5 owns the narrow "review_routes does NOT register the inspection path" half via `test_review_routes_does_not_register_inspection_list_path` (§T5 watchpoint h).

**Halt-YES discipline** (Round 20 P2 #1 — bumped from "no halt; standard TDD steps"; the CC-ADJ storage touch + the new route-level tenant-actor guard per R20 P2 #2 changes the task class). Halt-summary watchpoints:
- (a) `packs/storage.py::list_for_tenant` coverage at ≥95% line / ≥90% branch over the **5 new storage regressions** at `test_storage_list_for_tenant.py` (Round 22 P3 #3 refresh — was "4 new regressions" pre-R21; bumped at R21 P2 #2): (1) `test_list_for_tenant_returns_only_matching_tenant_rows`; (2) `test_list_for_tenant_with_optional_state_filter`; (3) `test_list_for_tenant_pagination_cursor`; (4) `test_list_for_tenant_with_no_packs_returns_empty_list`; (5) `test_list_for_tenant_compiles_with_indexed_where_clause` (R22 P2 #2 — tests the private statement-builder `_build_list_for_tenant_stmt`). The route-level `actor_tenant_id_missing` guard test (`test_list_returns_500_when_actor_tenant_id_missing` at `test_inspection_routes.py`) is kept SEPARATE per R20 P2 #2 / R21 P2 #1 — it covers the route layer, NOT the storage layer.
- (b) Server-side WHERE-clause is the AUTHORITATIVE tenant boundary — pinned by two-tenant fixture proving no in-handler filtering can leak cross-tenant rows.
- (c) **Round 21 P2 #2 — `ix_packs_tenant_state` index presence + SQL-shape coverage (downgraded from R20's env-gated EXPLAIN proof)** — the canonical index for the new query already has presence coverage via the migration test at `tests/unit/db/test_migration_20260510_0003.py::test_packs_indexes_present` (verifies `ix_packs_tenant_state` exists in the migration's `create_index` calls). For the new method's query SHAPE, the unit tests at `test_storage_list_for_tenant.py` assert the SQL compiles with a `WHERE packs.tenant_id = :tenant_id` clause (and an optional `AND packs.state = :state` when the kwarg is non-None) via SQLAlchemy's `str(stmt.compile())` introspection — this proves the query uses the columns the composite index covers, without needing live-DB EXPLAIN inspection. R20's env-gated `EXPLAIN` proof is downgraded because (i) no env-gated integration test file was declared, (ii) the existing migration + unit-SQL-shape coverage is sufficient for halt-summary confidence, (iii) keeping the gate would have demanded a test nobody planned to implement. A future sprint MAY add the env-gated EXPLAIN as a defence-in-depth proof; not required for T7 halt.
- (d) **Round 20 P2 #2 + Round 21 P2 #1 — `actor_tenant_id_missing` semantics preserved at the list endpoint** — `GET /api/v1/packs` bypasses `RequireTenantOwnership` (no `{pack_id}` path-param) which means it also bypasses the existing `tenant_isolation._emit_isolation_log` for `actor_tenant_id_missing`. The handler MUST run an explicit preflight check that emits the SAME structured log event AND returns the SAME 500 + `detail={"reason": "actor_tenant_id_missing"}` body when `actor.tenant_id` is falsy. **Type-correct implementer pattern (R21 P2 #1):** `Actor.tenant_id: str` at `actor.py:71` so the only reachable falsy case under live Pydantic validation is `""`; the `_emit_isolation_log(pack_id: str)` helper signature at `tenant_isolation.py:75-80` requires `str` so the preflight passes the stable sentinel `pack_id="<list>"` (NOT `None` — that was R20 P2 #2's misclaim, corrected at R21 P2 #1). Kernel binder misconfig is fail-loud-500 across EVERY tenant-isolated endpoint surface; the list endpoint must not silently mask it as a 200 empty-list response. Pinned by `test_list_returns_500_when_actor_tenant_id_missing` (route-level) AND caplog assertion that `extra["pack_id"] == "<list>"`.
- (e) No Doctrine Lock D touch — pure-read; no transaction; no chain-row interaction.

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
- Modify: `src/cognic_agentos/packs/storage.py` — (a) extend `transition()` signature with **THREE** new optional keyword-only kwargs: `payload_conformance: dict[str, Any] | None = None` AND `expected_manifest_digest: bytes | None = None` AND **`evidence_attachments: dict[str, Any] | None = None` (Round 11 P2 #3 — T5 carry-forward for reject categorised payload)**; (b) capture `payload_conformance` AND `evidence_attachments` in `_build_record` BEFORE the closure (no I/O inside the closure); merge into the payload dict at `:512-520` when not None (`payload_conformance` lands at top-level `payload["conformance"]`; `evidence_attachments` lands at top-level `payload["evidence_attachments"]`); (c) **extend the `SELECT ... FOR UPDATE` query at `:469` per Round 5 P3 #4** from `select(_packs.c.state, _packs.c.kind)` to `select(_packs.c.state, _packs.c.kind, _packs.c.manifest_digest)`; capture `manifest_digest` in the closure alongside the existing `state` + `kind`; (d) **inside the existing `_precondition` closure at `:458` (after the row lock returns at `:473`)** verify `row.manifest_digest == expected_manifest_digest` when the kwarg is provided (skip the check when `expected_manifest_digest is None` — preserves backward compatibility for non-submit transitions); mismatch raises `LifecycleTransitionRefused("lifecycle_transition_manifest_digest_changed_during_submit")` from inside the closure so `engine.begin()` at `core/decision_history.py:482` rolls back atomically (Doctrine Lock D preserved; T7 R7 propagation contract honored — storage does NOT catch the exception); (e) `_build_record` signature continues to capture only `(from_state, kind)` — the `manifest_digest` is checked-then-discarded inside the closure; the chain row payload does NOT carry `manifest_digest` (it's already in the persisted pack row + already keyed to the chain row via `pack_id`). **Preserve Doctrine Lock D** — conformance runs OUTSIDE the closure (in the route handler before calling `transition()`); both kwargs are captured dicts; no I/O inside the closure.
- Modify: `src/cognic_agentos/portal/api/packs/dto.py` — extend `SubmitDraftRequest` with `manifest: dict[str, Any]` field; add `manifest_digest_mismatch` to a route-level closed-enum
- **Modify: `src/cognic_agentos/portal/api/packs/author_routes.py` (Round 12 P2 #2 + P2 #3)** — extend the existing `submit_draft` handler (T4 landed at `:545-621`) with: (1) accept `body: SubmitDraftRequest` (T9 DTO with the new `manifest: dict[str, Any]` field); (2) compute `hashlib.sha256(canonical_bytes(body.manifest)).digest()`; if mismatch vs `pack.manifest_digest`, refuse with 400 + closed-enum `manifest_digest_mismatch`; (3) run `run_owasp_conformance(body.manifest)` OUTSIDE the storage closure; (4) pass `payload_conformance=conformance_report.to_dict()` + `expected_manifest_digest=record.manifest_digest` to the existing `await store.transition(...)` call. **REUSES the existing `_mint_request_id(_PACK_SUBMIT_REQUEST_ID_PREFIX)` at `author_routes.py:98-108` + `:93` (Round 12 P2 #3)** — NO fresh `request.state.request_id` lookup; the T4 author surface already minted bounded `pack-submit-<uuid4.hex>` (44 chars) request IDs to fit the `decision_history.request_id` String(64) cap. The minter + prefix constant are already module-scoped in `author_routes.py`; T9's extension is a same-file modification with no cross-module import gymnastics.
- **Modify: `src/cognic_agentos/portal/api/packs/review_routes.py` (Round 12 P2 #2 — T5 carry-forward; Round 14 P2 #2 — prefix-ownership clarification)** — extend the existing T5 `reject_pack` handler with the categorised-payload write: replace structured-log-only emission with `evidence_attachments={"rejection_reason": body.reason, "reviewer_comments": body.comments}` passed into `store.transition()`. Structured-log emission stays (defence-in-depth so observability tooling continues to see the categorised reason); chain payload becomes authoritative source per ADR-006 evidence-pack export contract. **T5 (NOT T9) owns the `_PACK_REJECT_REQUEST_ID_PREFIX = "pack-reject-"` declaration** at `review_routes.py` module scope per Round 14 P2 #2; T9 simply reuses the existing minter call — no new prefix introduced at T9. T5 also declares `_PACK_CLAIM_REQUEST_ID_PREFIX = "pack-claim--"` for the claim handler. Both prefixes are 12 chars; reused `_mint_request_id` from `author_routes.py:98-108` via cross-import gives 12 + 32 = 44 chars per the T4 R3 P2 #1 bounded-request-id invariant.
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
- Test: `tests/unit/packs/test_storage_transition_payload_schema.py` (NEW) — pin the exact payload-dict keyset for submit (includes `conformance`) vs other transitions (excludes `conformance`); canonical-form stability test (existing chain-verifier on a pre-T9 fixture chain still verifies green); **NEW per Round 4 P2 #1** — pin `expected_manifest_digest` kwarg behavior (None = no check; matched-digest = transition proceeds; mismatched-digest = refusal from inside row lock); **NEW per Round 12 P2 #2** — pin `evidence_attachments` kwarg behavior on reject transitions (kwarg None = no `evidence_attachments` key in payload; kwarg dict = `payload["evidence_attachments"]` carries exactly the supplied dict; pin closed-set keys `{"rejection_reason", "reviewer_comments"}` on T9 reject-path emit)
- **Test: `tests/unit/portal/api/packs/test_review_routes.py` (extend at T9 — Round 12 P2 #2 T5 carry-forward)** — add `test_reject_persists_categorised_payload_to_chain_row_post_t9` asserting the T9-extended reject handler writes `payload.evidence_attachments = {"rejection_reason": …, "reviewer_comments": …}` to the chain row (NOT structured-log only). Also add `test_reject_request_id_bounded_to_64_chars` asserting `_mint_request_id(_PACK_REJECT_REQUEST_ID_PREFIX)` returns ≤64 chars (mirrors the T4 R3 P2 #1 bounded-request-id invariant). The T5-era `test_reject_categorised_reason_logged_only_in_t5` test gets RENAMED to `test_reject_categorised_reason_logged_in_t5_and_persisted_post_t9` with explicit fixture-split (pre-T9 expectation: log-only; post-T9 expectation: log + chain payload).
- **Test: `tests/unit/portal/api/packs/test_author_routes.py` (extend at T9 — Round 12 P2 #3 request-id bounded-len invariant)** — add `test_submit_request_id_bounded_to_64_chars_after_t9` asserting the T9-extended `submit_draft` handler's request_id passed into `store.transition()` is ≤64 chars (re-using the existing T4 `_mint_request_id(_PACK_SUBMIT_REQUEST_ID_PREFIX)` minter — NOT `request.state.request_id`). Build-time invariant at module foot already pins this for T4; this test pins the runtime contract holds post-T9 extension.

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

T9 extends this with THREE new optional keyword-only kwargs — preserving all 6 existing required args:

1. `payload_conformance: dict[str, Any] | None = None` — captured into the chain payload at `_build_record` time (Round 2 P2 #7).
2. **`expected_manifest_digest: bytes | None = None` (Round 3 P2 #5)** — when provided, the precondition closure (already inside the `SELECT ... FOR UPDATE` row lock at `storage.py:467-473`) compares the locked-row's `manifest_digest` against `expected_manifest_digest`. Mismatch raises `LifecycleTransitionRefused("lifecycle_transition_manifest_digest_changed_during_submit")` — a NEW 14th value on the Sprint-7B.1 `LifecycleRefusalReason` literal (bumped 13 → 14 at T9; mentioned in T4's lifecycle.py modify scope above but **the value lands at T9** when wiring this race-condition fix).
3. **`evidence_attachments: dict[str, Any] | None = None` (Round 11 P2 #3 — T5 carry-forward)** — generic-shaped kwarg for attaching transition-specific evidence to the chain row's `payload`. When non-None, merged as a top-level `payload["evidence_attachments"] = {...}` key by `_build_record` BEFORE the closure (no I/O inside the closure; mirrors the `payload_conformance` capture pattern). At T9 the T5 reject handler is amended to pass `evidence_attachments={"rejection_reason": body.reason, "reviewer_comments": body.comments}` so the chain row's `payload` carries the categorised reject diagnosis for examiner traceability. Generic shape lets future transitions attach their own evidence types without further `transition()` signature growth (e.g. 7B.3 approve attachments). T5 ships reject as the bare transition + structured-log only; T9 wires the chain-payload migration.

The `evidence_pointer` field semantics stay as-is (string reference; reserved for 7B.3 side-table). **The `request_id` is caller-supplied per the `PackRecordStore.transition()` contract at `packs/storage.py:624` — pack routes mint bounded request IDs via the T4 `_mint_request_id(<prefix>)` helper at `portal/api/packs/author_routes.py:98-108`** (prefixes today: `_PACK_SUBMIT_REQUEST_ID_PREFIX` + `_PACK_CANCEL_REQUEST_ID_PREFIX` at `author_routes.py`; **T5 adds BOTH `_PACK_CLAIM_REQUEST_ID_PREFIX` AND `_PACK_REJECT_REQUEST_ID_PREFIX` at `review_routes.py`** per Round 14 P2 #2 + Round 17 P2 #3 prefix-ownership clarification; **T9 introduces NO new prefix** — only reuses the T5-owned reject prefix when amending the reject handler to write `evidence_attachments`). Each prefix is 12 chars + `uuid4().hex` (32 chars) = 44 chars, leaving headroom under the `decision_history.request_id` `String(64)` cap. **No middleware request-state dependency** — the earlier Round 2 P2 #7 wire-design paragraph misclaimed `request.state.request_id` was bound by a `RequestIdMiddleware`; that middleware does NOT expose `request.state.request_id` today (verified at Round 12 P2 #3) and the storage contract treats `request_id` as a required caller-supplied string. The bounded-minter contract is the single source of truth for pack-route request IDs; build-time invariant at module foot pins prefix + uuid hex length cannot together exceed 64.

**Race-condition resolution (Round 3 P2 #5):**

Without the locked precondition check, the submit flow had a TOCTOU window: the route would (a) load `PackRecord` via `RequireTenantOwnership` (outside any row lock), (b) verify `body.manifest` digest matches `pack.manifest_digest`, (c) run conformance over `body.manifest`, (d) call `transition()` which then locks the row. Between (a) and (d), a concurrent `update_draft()` call could mutate `manifest_digest` — leaving the audit chain's `payload.conformance` describing a manifest that no longer matches the persisted pack row. Closing the window: pass `expected_manifest_digest=pack.manifest_digest` from the preloaded record into `transition()`; the precondition closure checks the locked row's digest matches; mismatch fails-closed with the new 14th refusal reason (no chain row written, no state mutation).

```python
# In author_routes.py — T9 extends the EXISTING T4 submit_draft handler at :545-621.
# The T4 handler already mints bounded request IDs via _mint_request_id(_PACK_SUBMIT_REQUEST_ID_PREFIX)
# at author_routes.py:98-108 + the prefix constant at :93 — reuse those (Round 12 P2 #3).
@router.post(
    "/drafts/{pack_id}/submit",
    summary="Submit a draft for review",
)
async def submit_draft(
    body: SubmitDraftRequest,  # T9 NEW — was no body in T4; T9 adds manifest field
    actor: Annotated[Actor, Depends(_require_pack_submit)],
    record: Annotated[PackRecord, Depends(_require_tenant_ownership)],
) -> PackResponse:
    # T9 NEW — cheap pre-check (defense-in-depth — the authoritative check is the
    # locked precondition inside transition() per Round 3 P2 #5).
    if hashlib.sha256(canonical_bytes(body.manifest)).digest() != record.manifest_digest:
        raise HTTPException(400, detail={"reason": "manifest_digest_mismatch"})
    # T9 NEW — conformance runs OUTSIDE the storage closure (pure function over the dict).
    conformance_report = run_owasp_conformance(body.manifest)
    # T9 extends the existing T4 store.transition() call (at :570-578) with
    # TWO new kwargs. CRITICAL (Round 12 P2 #3): keep the existing
    # _mint_request_id(_PACK_SUBMIT_REQUEST_ID_PREFIX) call — DO NOT switch
    # to request.state.request_id. The request_id middleware does NOT expose
    # request.state.request_id today; the decision_history.request_id column
    # is String(64); the T4 author surface already mints bounded
    # "pack-submit-<uuid4.hex>" IDs (12 + 32 = 44 chars) via the module-scoped
    # minter at author_routes.py:98-108. Build-time invariant at module foot
    # pins prefix + uuid hex length cannot together exceed 64.
    try:
        await store.transition(
            pack_id=record.id,
            transition="submit",
            actor_id=actor.subject,
            tenant_id=actor.tenant_id,
            evidence_pointer=None,  # Reserved for 7B.3 side-table pointer
            request_id=_mint_request_id(_PACK_SUBMIT_REQUEST_ID_PREFIX),  # ← T4-era minter; Round 12 P2 #3
            payload_conformance=conformance_report.to_dict(),  # NEW T9 kwarg
            expected_manifest_digest=record.manifest_digest,   # NEW T9 kwarg, Round 3 P2 #5
        )
    except PackNotFound:
        # Race + existing T4 R1 P2 #3 fix — translate to 404 + closed-enum body.
        raise HTTPException(status_code=404, detail={"reason": _PACK_NOT_FOUND_REASON}) from None
    except LifecycleTransitionRefused as exc:
        # 409 for state-machine refusals (idempotent re-submit, etc); 7B.2
        # idempotency contract preserved.
        raise HTTPException(status_code=409, detail={"reason": exc.reason}) from None

    updated = await store.load(record.id)
    if updated is None:
        raise HTTPException(status_code=404, detail={"reason": _PACK_NOT_FOUND_REASON})
    return _record_to_response(updated)
```

**Round 12 P2 #3 invariant (T9 submit chain row request_id ≤ 64 chars):** the T9-extended `submit_draft` handler reuses the T4 `_mint_request_id(_PACK_SUBMIT_REQUEST_ID_PREFIX)` minter — the existing build-time invariant at `author_routes.py` module foot (T4 R3 P2 #1) pins `len(<prefix> + uuid4().hex) <= 64`. New runtime test `test_submit_request_id_bounded_to_64_chars_after_t9` pins the runtime contract holds post-T9 extension. No new middleware request-state plumbing required.

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

**Why CC-doctrine:** Mirrors Sprint 7B.1 T7. Adds the `## Authoring — Bank pack lifecycle portal API (Sprint 7B.2)` subsection to AGENTS.md with bullet-per-new-CC-module entries (**12 modules** per "Critical-controls forecast" after Round 1 + Round 11 patches: 6 RBAC + 3 endpoint surfaces + 3 conformance). Bumps `tools/check_critical_coverage.py` floor **43 → 55** (+12). Also documents the CC-source touches at T4 (`packs/lifecycle.py` cancel_draft extension) + **T5 (`packs/storage.py` `list_by_status` tenant_id kwarg — Round 11 P2 #1)** + **T7 (`packs/storage.py` `list_for_tenant` NEW method — Round 19 P2 #4 + Round 20 P2 #3)** + T9 (`packs/storage.py` payload-conformance extension + `evidence_attachments` generic kwarg per Round 11 P2 #3) + T11 (`cli/test_harness.py` OWASP tail-call) — no re-promotion needed since lifecycle / storage are already CC; test-harness stays off-floor by Sprint-7A T13 R4 P3 #5 provenance.

**Files:**
- Modify: `AGENTS.md` — new subsection L~125 (after the 7B.1 subsection); enumerates 12 new CC modules with file:line citations verified at T12 compose time
- Modify: `tools/check_critical_coverage.py` — bump floor 43 → 55 + add 12 new module entries with rationale lines:
  1. `portal/rbac/scopes.py` — closed-enum scope literal IS wire-protocol for RBAC denials
  2. `portal/rbac/actor.py` — identity boundary + production-grade fail-loud default
  3. `portal/rbac/enforcement.py` — RequireScope dependency + RBACDenialReason closed-enum
  4. `portal/rbac/tenant_isolation.py` — Round 1 P2 #3 + T2 R1 P2 #1 — cross-tenant 404 + 4-value `TenantIsolationFailure` closed-enum (`tenant_id_mismatch` / `pack_not_found` / `actor_tenant_id_missing` / `pack_store_not_configured`)
  5. `portal/rbac/human_actor.py` — Round 1 P3 #8 — actor-type human-only guarantee for allow-list
  6. **`portal/rbac/role_separation.py` — Round 11 P2 #4 (T5 doctrine sweep) — `RequireDifferentActorThanCreator` dependency + 1-value closed-enum `RoleSeparationFailure` literal (`actor_cannot_review_own_pack`) enforcing ADR-012 §17 cross-role separation**
  7. `portal/api/packs/author_routes.py` — wire-protocol-public author surface
  8. `portal/api/packs/review_routes.py` — wire-protocol-public review surface (approve fail-loud per P2 #1 + 4-axis matrix per Round 11 P3 #6)
  9. `portal/api/packs/operator_routes.py` — wire-protocol-public operator surface
  10. `packs/conformance/checks.py` — security-bearing OWASP check matrix
  11. `packs/conformance/owasp_agentic.py` — top-level OWASP runner
  12. `packs/conformance/runner.py` — auto-run-on-submit integration

Halt summary watchpoints:
- (a) Cite-from-memory verification — every signature / class name / closed-enum count cited in the AGENTS.md subsection MUST be verified at file:line within the same compose pass per `feedback_verify_code_citations_at_doc_write.md`
- (b) Closed-enum value counts (new in 7B.2): `PackRBACScope` (12 — BUILD_PLAN §622-625 verbatim, NOT the closeout-L119 cite-from-memory typo "14"), `RBACDenialReason` (3), `TenantIsolationFailure` (**4** — Round 1 P2 #3 originated at 3; T2 R1 P2 #1 added `pack_store_not_configured` for symmetric missing-store defence), `ActorType` (2 — Round 1 P3 #8), `RequireHumanActor` denial reason (1 value `actor_type_must_be_human`), **`RoleSeparationFailure` (1 value `actor_cannot_review_own_pack` — Round 11 P2 #4)**, **`RejectionReason` (7 values — Round 11 P2 #2; anchored to ADR-012 §41 5-gate composition + operational categories)**, `OWASPCheckCategory` (10) — all pinned with concrete tests T2 / T5 / T8
- (b.1) Closed-enum value counts (extended from 7B.1 in 7B.2): `TransitionName` Literal **10 → 11** values (added `cancel_draft` at T4 per Round 1 P2 #2 + Round 2 P2 #6); `PackRecordRefusalReason` Literal **1 → 4** values (added `pack_record_update_non_draft_state` + `pack_record_update_field_not_allowed` + `pack_record_update_field_invalid_shape` at T4 per Round 2 P2 #5 + Round 3 P2 #4 + **Round 6 P3 #4 value-shape validation**); **`LifecycleRefusalReason` Literal 13 → 14 values** (added `lifecycle_transition_manifest_digest_changed_during_submit` at T9 per Round 3 P2 #5 race-condition fix); `_VALID_TRANSITIONS` map size 10 → 11 keys / 13 → 14 legal pairs; doctrine-citation sweep enumerated at T4 covers **15 sites in 6 files** for transition counts + **6 sites in 3 files for PackRecordRefusalReason 1→4** (Round 6 P2 #2 + Round 7 P2 #2 corrected count from 4 → 6 adding `storage.py:232` + `:241`); T9 owns **8 sites in 5 files for LifecycleRefusalReason 13→14**; same 3-path exclusion set used across all sweeps; halt-summary proof uses per-site `sed -n` verification per Round 8 P2 #1 + P2 #2
- (c) Cross-reference to ADR-012 §39 + §54-79 + §107-110 + §114-122 + BUILD_PLAN §615-630
- (d) Critical-controls floor uplift +12 (Round 11 P2 #4 bumped from +11): list each new module + its rationale per AGENTS.md "Critical-controls rule" format
- (e) **CC-source touches in 7B.1 + 7B.2 modules (Round 13 P3 #4 refresh)** referenced from the 7B.2 subsection — no re-promotion needed:
  1. `packs/lifecycle.py` from T4 — `cancel_draft` transition (`draft → withdrawn`); plus T9 LifecycleRefusalReason 13→14 (`lifecycle_transition_manifest_digest_changed_during_submit`)
  2. **`packs/storage.py` from T5 (Round 11 P2 #1 + Round 13 P3 #4 + Round 14 P2 #1 — backward-compatible signature)** — `list_by_status(state, limit: int = 50, cursor: uuid.UUID | None = None, *, tenant_id: str | None = None)` CC-ADJ extension. Compatibility-preserving signature shape: `limit` + `cursor` stay positional-or-keyword with their pre-T5 defaults; `tenant_id` lives behind `*` as additive keyword-only-with-default. Pure read; no Doctrine Lock D touch; uses existing `ix_packs_tenant_state` index per migration L129. Three regressions pin the contract: state-only call (pre-T5 shape) + existing limit/cursor pagination + new tenant-filtered pagination.
  2a. **`packs/storage.py` from T7 (Round 19 P2 #4 + Round 20 P2 #3 + Round 21 P2 #2 + Round 22 P3 #4 propagation — tenant-scoped inspection seam) — CC-ADJ; T7 halt-YES per Round 20 P2 #1** — NEW method `list_for_tenant(tenant_id: str, *, limit: int = 50, cursor: uuid.UUID | None = None, state: PackState | None = None) -> list[PackRecord]` with REQUIRED `tenant_id` filter + OPTIONAL `state` AND-clause; backed by NEW module-private statement-builder `_build_list_for_tenant_stmt(...)` (R22 P2 #2 — production-path-exercising SQL-shape proof). Pure read; no Doctrine Lock D touch; uses the same `ix_packs_tenant_state` index. **5 regressions** at `tests/unit/packs/test_storage_list_for_tenant.py`: `test_list_for_tenant_returns_only_matching_tenant_rows` + `test_list_for_tenant_with_optional_state_filter` + `test_list_for_tenant_pagination_cursor` + `test_list_for_tenant_with_no_packs_returns_empty_list` (R20 P2 #2 — was the misleading "empty-tenant returns empty list"; the actor-tenant-missing axis lives at the route-level guard at `inspection_routes.py` per R20 P2 #2 + R21 P2 #1, NOT at the storage layer) + **`test_list_for_tenant_compiles_with_indexed_where_clause` (R21 P2 #2 — SQL-shape proof on `_build_list_for_tenant_stmt`; R22 P3 #4 propagation)**.
  3. **`packs/storage.py` from T9 (Round 11 P2 #3 + Round 12 P2 #2 + Round 13 P2 #2 — full three-kwarg surface)** — `transition()` extended with `payload_conformance: dict[str, Any] | None` + `expected_manifest_digest: bytes | None` + `evidence_attachments: dict[str, Any] | None`; preserves Doctrine Lock D
  4. **`portal/api/packs/author_routes.py` from T9 (Round 12 P2 #2 + Round 12 P2 #3)** — extends T4 `submit_draft` handler with conformance pre-run + manifest-digest pre-check + the two new transition() kwargs; reuses the existing `_mint_request_id(_PACK_SUBMIT_REQUEST_ID_PREFIX)` minter (NOT `request.state.request_id`)
  5. **`portal/api/packs/review_routes.py` from T5 (NEW) + T9 carry-forward (Round 12 P2 #2 + Round 17 P2 #3 prefix-ownership clarification)** — T5 creates the module + the claim/reject/approve/evidence handlers + declares BOTH `_PACK_CLAIM_REQUEST_ID_PREFIX` AND `_PACK_REJECT_REQUEST_ID_PREFIX` at module scope (cross-imports `_mint_request_id` from `author_routes.py:98-108`) per the T4 R3 P2 #1 bounded-request-id invariant. T9 amends the T5 reject handler to add `evidence_attachments={"rejection_reason": …, "reviewer_comments": …}` chain-row write replacing structured-log-only emission; T9 introduces NO new request-id prefix — only reuses the T5-owned reject prefix.
  6. `cli/test_harness.py` from T11 — OWASP tail-call integration after per-kind dry-run dispatch

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
7. **Final reference table (NEW per Round 8 reviewer answer #5; refreshed per Round 11 + Round 12 patches; future-proofed per Round 19 P3 #5)** — consolidates the R-round patch surface into a single navigation map (round count avoided to keep this stable across further R-rounds; current state through R18 = R0 + R0.5 + R0.6 + R1–R18, with R-round count growing on every subsequent reviewer pass):
   - (a) New closed-enum vocabularies — value counts + module paths. **Round 11/12 refresh:** (1) `PackRBACScope` (12; `portal/rbac/scopes.py`), (2) `RBACDenialReason` (3; `portal/rbac/enforcement.py`), (3) `TenantIsolationFailure` (4; `portal/rbac/tenant_isolation.py`), (4) `ActorType` (2; `portal/rbac/actor.py`), (5) `RequireHumanActor` denial reason (1: `actor_type_must_be_human`; `portal/rbac/human_actor.py`), (6) **`RoleSeparationFailure` (1: `actor_cannot_review_own_pack`; `portal/rbac/role_separation.py`) — NEW Round 11 P2 #4**, (7) **`RejectionReason` (7 values; `portal/api/packs/dto.py`) — NEW Round 11 P2 #2**, (8) `OWASPCheckCategory` (10; `packs/conformance/checks.py`).
   - (b) Cross-sprint 7B.1 closed-enum extensions (TransitionName 10→11, PackRecordRefusalReason 1→4, LifecycleRefusalReason 13→14) — count deltas + owner task + sweep site count
   - (c) Doctrine sweep paths exclusion set (3 paths)
   - (d) **New CC modules (12 — Round 11 P2 #4 bumped from 11 by adding `role_separation.py`)** — module path + rationale + owner task. Includes the 6 RBAC modules (scopes / actor / enforcement / tenant_isolation / human_actor / **role_separation**) + 3 endpoint surfaces (author_routes / review_routes / operator_routes) + 3 conformance modules (checks / owasp_agentic / runner).
   - (e) Cross-sprint CC source touches — what was extended + which Sprint-7B.1 invariants preserved (Doctrine Locks C/D + asymmetric-runtime-guard pattern). **Round 11/12/14/19/20 refresh:** (1) `packs/lifecycle.py` T4 cancel_draft + T9 LifecycleRefusalReason 13→14; (2) `packs/storage.py` **T5 `list_by_status(state, limit: int = 50, cursor: uuid.UUID | None = None, *, tenant_id: str | None = None)` CC-ADJ extension — NEW Round 11 P2 #1; compatibility-preserving signature per Round 14 P2 #1** (pure read; no Doctrine Lock D touch; uses existing `ix_packs_tenant_state` index); **(2a) `packs/storage.py` T7 `list_for_tenant(tenant_id: str, *, limit, cursor, state: PackState \| None = None) -> list[PackRecord]` CC-ADJ extension — NEW Round 19 P2 #4 + Round 20 P2 #3** (REQUIRED `tenant_id` filter + OPTIONAL `state` AND-clause; pure read; no Doctrine Lock D touch; same `ix_packs_tenant_state` index; T7 bumped to halt-YES per R20 P2 #1; route-level `actor_tenant_id_missing` preflight guard at inspection_routes.py per R20 P2 #2); (3) `packs/storage.py` T9 `transition()` extension with **THREE** new kwargs (`payload_conformance` + `expected_manifest_digest` + **`evidence_attachments` — NEW Round 11 P2 #3**); (4) `cli/test_harness.py` T11 OWASP tail-call; (5) **`portal/api/packs/author_routes.py` T9 extension — Round 12 P2 #2 (T9 reuses the existing T4 `_mint_request_id(_PACK_SUBMIT_REQUEST_ID_PREFIX)` minter per Round 12 P2 #3, NOT request.state.request_id)**; (6) **`portal/api/packs/review_routes.py` T5 NEW + T9 carry-forward — T5 owns `_PACK_CLAIM_REQUEST_ID_PREFIX` / `_PACK_REJECT_REQUEST_ID_PREFIX` declarations + cross-imports `_mint_request_id` from `author_routes.py` per Round 14 P2 #2; T9 amends the reject handler with `evidence_attachments={"rejection_reason": …, "reviewer_comments": …}` chain-row write (replaces structured-log-only emission) per Round 12 P2 #2**.
   - (f) Deferred-to-7B.3/7B.4 work (5-gate composer, evidence panels, UI event streams, RBAC denial chain events, fixture-AgentOS harness, fail_open_exception) — owner sprint + reason
   - **(g) Route-table collision resolution (Round 12 P2 #1 + Round 13 P2 #1 + Round 15 P2 #2) — NEW** — T5 reviewer queue moved off `GET /api/v1/packs?status=submitted` (which would have collided with T7 `GET /api/v1/packs`) to `GET /api/v1/packs/review-queue` (distinct path; gated by `pack.review.claim`). T7 owns `GET /api/v1/packs` (gated by `pack.audit.read`). **Round 13 P2 #1 split:** T5 owns the narrow proof `test_review_routes_does_not_register_inspection_list_path` — runs at T5-execution time before `inspection_routes.py` exists; the full both-routes-reachable regression `test_review_queue_and_inspection_list_both_reachable` ships at T7 once both sub-routers exist. **Round 15 P2 #2 — mount-prefix correction:** the T5-narrow proof mounts `build_review_routes(store=…)` under a test parent `APIRouter(prefix="/api/v1/packs")` on a fresh `FastAPI()` app, then walks `app.routes` and asserts the COMPILED full path `/api/v1/packs/review-queue` exists AND no route compiles to `/api/v1/packs` — R13 original wording asserted against an un-mounted sub-router (vacuously true since un-mounted routers expose only relative paths). ADR-012 §62 sketch (`?status=submitted` query param) is impl-deviation noted in plan + closeout.
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
- (e) **Final reference table completeness (Round 8 reviewer answer #5; refreshed Round 13 P3 #5)** — all **7 sub-sections (a–g)** populated (Round 12 P2 #1 added (g) for the T5↔T7 `GET /api/v1/packs` route-collision resolution); future implementer can navigate the ~1500-line plan via this single table without re-reading every patch-log round. Closeout completeness check explicitly names sub-section (g) "**Route-table collision resolution**" alongside the original 6 (a) closed-enum vocabularies, (b) cross-sprint 7B.1 closed-enum extensions, (c) doctrine sweep paths exclusion set, (d) new CC modules, (e) cross-sprint CC source touches, (f) deferred-to-7B.3/7B.4 work — so a missing (g) on the final closeout fails the completeness gate, NOT just (a–f).

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

### Round 11 — pre-T5 doctrine sweep against the live `41b9865` codebase (6 findings: 4×P2 + 2×P3; all patched into plan)

This round is a pre-T5 plan-vs-code doctrine sweep. T4 has already committed at `41b9865` and the live codebase (lifecycle.py + storage.py + author_routes.py + RBAC primitives at T2/T3) is the new source-of-truth; the T5 plan-of-record was last touched in Round 0 and never sanity-checked against the executed T4 surfaces. Findings patched into the plan **before** any T5 code touches the tree per `feedback_patch_plan_against_doctrine.md`.

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **P2 #1** | P2 | `list_by_status(state, limit, cursor)` at `packs/storage.py:797` has NO `tenant_id` filter, but the plan §T5 endpoint table row 1 says the reviewer queue is "filtered server-side by actor.tenant_id". Without the storage extension, the handler would have to either (a) load N records then in-handler filter to k (pagination skew where `limit=50` returns <50 when some rows belong to other tenants), or (b) silently leak other-tenant rows. Both wrong. | Extend `list_by_status(state, *, tenant_id: str | None = None, limit, cursor)` with optional keyword-only `tenant_id` filter; when non-None, WHERE clause adds `tenant_id == :tenant_id` AND uses the existing `ix_packs_tenant_state` composite index per migration L129. Pure read; no Doctrine Lock D touch. Marked CC-ADJ to storage at T5 (in addition to the T9 transition() extension). Plan §"CC promotions", §"File structure → Modify (existing files)", §"Critical-controls forecast → CC promotions", §T5 endpoint table row 1, §T5 §Files, §T12 docstring rationale + §T12 watchpoint (d) all updated. New test `test_reviewer_queue_filters_by_tenant_id` co-located in `test_review_routes.py`. |
| **P2 #2** | P2 | `RejectionReason` closed-enum vocabulary referenced by §T5 watchpoint (c) "categorised rejection reasons per ADR-012 §42 transition table" but ADR-012 §42 says only "rejection reasons (categorised), reviewer comments" with no enumerated vocabulary — plan never enumerated the values. Implementation would invent the vocabulary at code-write time = wire-protocol fingerprint risk on first deploy. | Enumerate **7-value closed-enum** anchored to ADR-012 §41's 5-gate composition + 2 operational categories: `signature_invalid` / `evaluation_pass_rate_below_threshold` / `adversarial_corpus_pass_rate_below_threshold` / `owasp_conformance_red` / `data_governance_unfit` / `documentation_incomplete` / `other`. `RejectDraftRequest` DTO declares `reason: RejectionReason` + `comments: str` (non-empty); `comments` REQUIRED when `reason == "other"` (Pydantic `model_validator(mode="after")` enforces). Plan §T5 watchpoint (c) + §T5 §Files + §T12 watchpoint (b) closed-enum value-counts updated. Pinned by `TestSprint7B2RejectionReasonVocabulary::test_literal_values_pinned_at_7`. |
| **P2 #3** | P2 | `transition()` at `packs/storage.py:616` accepts only `evidence_pointer: str \| None` — no `evidence_attachments` kwarg exists yet (that lands at T9 per plan §T9). Plan §T5 reject endpoint row says "with categorised reasons" but T5 cannot persist `reason` + `comments` to the chain row without the T9 extension. Naive resolution: smuggle into `evidence_pointer` (overloads the field). Correct resolution: T5 ships reject as bare transition; T9 amends `transition()` + the reject handler together. | T5 ships reject as **bare transition + structured-log emission only** in 7B.2; categorised `reason` + `comments` captured via `_LOG.warning("portal.packs.review.reject", extra={"reason": …, "comments": …})` (mirroring the T4 author-handler structured-log pattern). New plan §T5 watchpoint (g) "T9 carry-forward — amend reject to persist categorised reason + comments via `evidence_attachments`". Plan §T9 §"Wire design" extended with **third optional kwarg `evidence_attachments: dict[str, Any] \| None`** (generic-shaped — lets future transitions attach evidence without further signature growth). T5 test `test_reject_categorised_reason_logged_only_in_t5` pins the chain row does NOT carry these fields in 7B.2; T9 tests assert it does post-T9. |
| **P2 #4** | P2 | §T5 watchpoint (d) "ADR-012 §17 author-cannot-review-own-pack" has NO enforcement seam in the T2-shipped RBAC primitives. Today's `RequireScope` + `RequireTenantOwnership` + `RequireHumanActor` cover scope membership, tenant boundary, and actor-type — but no module enforces `actor.subject != record.created_by`. Implementation would have to bolt this into the review handler bodies inline. | **New CC module `portal/rbac/role_separation.py`** carrying `RequireDifferentActorThanCreator(pack_id_param)` FastAPI dependency + 1-value closed-enum `RoleSeparationFailure = Literal["actor_cannot_review_own_pack"]`. Returns 403 when `actor.subject == record.created_by`. Mirrors the `RequireHumanActor()` shape; lives in its own module so the four orthogonal enforcement axes (scope / tenant / actor-type / role-separation) stay separated. Plan §"Critical-controls forecast" + §"File structure → Create" + §"Tests" + §"Critical-controls floor projected" (54 → **55**; +11 → +12) + §T5 endpoint table rows 2/3/4 (claim + approve + reject deps) + §T5 §Files + §T12 §"Why CC-doctrine" + §T12 numbered list (12 entries; role_separation inserted at position 6) + §T12 watchpoints all updated. New test `test_role_separation.py` co-located with sibling RBAC unit tests. |
| **P3 #5** | P3 | §T5 caveat names the `/{id}/evidence` response shape `{"conformance": …, "reviewer_evidence_panels": null}` but no Pydantic DTO is declared anywhere in the plan. Implementation would invent the shape inline at handler-write time — wire-protocol fingerprint regression risk. | Add `PackEvidenceResponse` Pydantic model to `portal/api/packs/dto.py` (not-CC per existing classification) with `conformance: dict[str, Any] \| None` + `reviewer_evidence_panels: None` (literal-typed at None in 7B.2; 7B.3 fills in). Read-path walks `store.load_lifecycle_history(pack_id)`, finds the most-recent `event_type == "pack.lifecycle.submitted"` row, surfaces its `payload.get("conformance")` or null. Plan §"File structure → Modify (existing files)" + §T5 §Files + §T5 caveat + §T5 endpoint table row 5 all updated. Two regression tests: `test_evidence_returns_null_pre_t9` (pre-T9 chain row) + `test_evidence_surfaces_payload_conformance_post_t9_fixture` (hand-built T9-shape chain row). |
| **P3 #6** | P3 | Approve fail-loud-503 dependency-order is implied but never explicitly pinned. Test surface in plan said `test_approve_fail_loud_503` only — no enumeration of which axis (no scope vs cross-tenant vs author-of-pack vs green) lands which HTTP status / reason. A naive implementation might fire the 503 BEFORE the RBAC / tenant / role-separation guards (silently violating the production-grade auth-trail-for-attempts invariant). | Pin via **4-axis fail-loud test matrix** in §T5: (a) no scope → 403 `scope_not_held`; (b) cross-tenant → 404 `tenant_id_mismatch`; (c) author-of-pack with scope + same-tenant → 403 `actor_cannot_review_own_pack` (depends on P2 #4); (d) scoped + same-tenant + different-actor → 503 `approve_gate_composer_not_wired` + no-state-transition + no-chain-row. Forces RBAC → tenant → role-separation → 503 ordering. Each axis asserts (1) HTTP status, (2) `detail.reason`, (3) chain row count unchanged, (4) pack state unchanged. Plan §T5 §"Approve-endpoint fail-loud contract" + §"Tests" line 126 + §T5 watchpoints (b) (d) (e) all updated. |

**Round 22 (R22) — user follow-up doctrine review of Round 21 patches (2×P2 + 2×P3; all patched into plan)**

R22 surfaces propagation drift from R20/R21's T7 storage seam landing — the top-level §"Modify (existing files)" entry missed the T7 row; the SQL-shape test could prove a duplicated test-local query rather than the production path; the T7 halt watchpoint (a) regression count + the T12 reference table item 2a regression count both stale at "4". Pre-T5 still; no code touched.

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **R22 P2 #1** | P2 | **Incomplete R20/R21 propagation** — Top-level §"Modify (existing files)" entry for `packs/storage.py` described only T5 `list_by_status` + T9 `transition()`; R19/R20 added T7 `list_for_tenant` to the §"CC promotions" entry + T7 §"Files" + T12 + T13 surfaces but missed this 5th surface. AGENTS.md / closeout authors reading the live forecast surface would not see T7 listed alongside T5/T9. | T5 + T7 + T9 storage extensions now enumerated in the L113 row with the same halt-YES / pure-read / no-Doctrine-Lock-D / 5-regression-proof language. R22 P2 #1 site flagged inline. Plan updated in 1 site: §"Modify (existing files)" `packs/storage.py` row. |
| **R22 P2 #2** | P2 | **Newly surfaced** — R21 P2 #2's `test_list_for_tenant_compiles_with_indexed_where_clause` was written to call `select(_packs).where(...)` directly in the test body — but a test-local `select` that compiles to the right SQL proves NOTHING about whether the production `list_for_tenant` method actually constructs its query the same way. The test would pass even if the production code lost the `tenant_id` WHERE clause (or never built the `Select` at all). | **Private statement-builder pattern declared**: the production `list_for_tenant` MUST extract its query construction into a module-private helper `_build_list_for_tenant_stmt(tenant_id, *, limit, cursor, state=None) -> Select`. The R21 P2 #2 SQL-shape regression imports this SAME builder via `from cognic_agentos.packs.storage import _build_list_for_tenant_stmt` and asserts on its compiled output — eliminates the "test-writes-its-own-select-and-assertion-passes-while-production-drifts" vacuous-proof bug class. The builder is module-private (underscore prefix) but module-importable for tests, mirroring the live `_row_to_record` helper convention at `packs/storage.py:913`. Plan updated in 2 sites: T7 §"Files" storage row (builder pattern + rationale) + top-level §"Tests" inventory (test imports the production builder, not a duplicate). |
| **R22 P3 #3** | P3 | **Incomplete R21 P2 #2 propagation** — T7 watchpoint (a) still said coverage is over "4 new regressions" with stale "empty-tenant-route-refusal mapping" wording from a pre-R21 draft. R21 P2 #2 bumped the test count to 5 but propagation missed this watchpoint. Halt checklist coverage-target language inconsistent with the inventory. | Watchpoint (a) refreshed to enumerate **5 storage regressions** by name (tenant-only / state filter / cursor / no-packs-empty-list / SQL-shape) + explicit note that the route-level `actor_tenant_id_missing` guard test stays SEPARATE per R20 P2 #2 / R21 P2 #1 (storage layer ≠ route layer; storage covers result-set behaviour, route covers actor-presence preflight). Plan updated in 1 site: T7 watchpoint (a). |
| **R22 P3 #4** | P3 | **Incomplete R21 P2 #2 propagation** — T12 watchpoint (e) item 2a still listed 4 `test_storage_list_for_tenant.py` regressions, omitting the R21 P2 #2 SQL-shape regression. AGENTS.md uplift would have shipped with a stale doctrine surface vs the T7 halt section. | Item 2a refreshed to **5 regressions** with explicit `test_list_for_tenant_compiles_with_indexed_where_clause` name + cross-reference to R22 P2 #2 private statement-builder pattern. Plan updated in 1 site: T12 watchpoint (e) item 2a. |

**Round 22 reviewer notes recorded for execution:**

1. **Every doctrine claim about an Xn-N pattern (X = test / kwarg / regression) needs propagation across ALL N surfaces in the same patch** — R21 P2 #2 bumped storage tests from 4 to 5 but propagation missed 2 downstream surfaces (T7 watchpoint a + T12 item 2a). R-round lesson: when a count bumps anywhere, the patch MUST grep for all instances of the old count in the live forecast surface + update each in the same compose pass.
2. **SQL-shape proofs must exercise the production query path, not a duplicate test query** — the "private statement-builder + import-from-test" pattern is the canonical pattern for proving query SHAPE without live-DB EXPLAIN inspection. R-round lesson: any test that asserts on a SQL string MUST import the SAME builder the production code uses (typically a module-private `_build_<surface>_stmt` helper); writing the test's own `select(...).where(...)` produces vacuous proof. The shared-builder pattern is the elimination of the duplicate-and-drift bug class.

---

**Round 21 (R21) — user follow-up doctrine review of Round 20 patches (2×P2; all patched into plan)**

R21 surfaces a type-correctness break in the R20 preflight sample (the cited helper signature doesn't accept None) and a missing test surface for the R20 EXPLAIN watchpoint. Pre-T5 still; no code touched.

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **R21 P2 #1** | P2 | **Incomplete R20 P2 #2 fix** — The R20 preflight code sample called `tenant_isolation._emit_isolation_log(..., pack_id=None)` claiming "the helper accepts None per its existing signature", but the LIVE helper signature at `tenant_isolation.py:75-80` is `_emit_isolation_log(*, reason: TenantIsolationFailure, actor_subject: str, pack_id: str)` — `pack_id` is REQUIRED `str` (NOT `str \| None`). Mypy would refuse the implementation as written. Compounding: R20's matching test asked for an `Actor(tenant_id=None)` axis, but `Actor.tenant_id: str` at `actor.py:71` rejects None at Pydantic validation — so reaching the handler with a None tenant_id is impossible under the typed contract; the None-axis test could only construct via `Actor.model_construct(...)` defensive bypass. | Implementer-pattern code block rewritten to pass `pack_id="<list>"` (stable sentinel string keeping log-aggregator bucketing discoverable + type-safe under mypy). Test surface narrowed to ONLY the `tenant_id=""` axis (constructible via normal Pydantic validation) with explicit caplog assertion `extra["pack_id"] == "<list>"`. `Actor(tenant_id=None)` axis explicitly dropped + documented as unreachable under the live typed contract. Plan updated in 3 sites: T7 §"Files" inspection storage row preflight code block + top-level §"Tests" inspection-routes test entry + T7 watchpoint (d). |
| **R21 P2 #2** | P2 | **Incomplete R20 P2 #1 fix** — R20 added T7 watchpoint (c) requiring "EXPLAIN-style query-plan inspection in the integration test (env-gated on `COGNIC_RUN_POSTGRES_INTEGRATION=1`)" but no integration test file was declared in the plan (the test inventory only declares the unit-level `test_storage_list_for_tenant.py`). The halt checklist would demand a proof nobody planned to implement. | Watchpoint (c) downgraded from env-gated EXPLAIN proof to **migration-test index-presence + unit SQL-shape coverage** — the index already has presence coverage at `test_migration_20260510_0003.py::test_packs_indexes_present`; the new method's SQL-shape coverage adds a 5th regression `test_list_for_tenant_compiles_with_indexed_where_clause` at `test_storage_list_for_tenant.py` asserting the compiled SQL string contains `packs.tenant_id = ` (always) AND `packs.state = ` (when state kwarg non-None), proving the WHERE clause uses the index columns without needing live-DB EXPLAIN. T7 §"Halt-summary requirements" item (3) also refined to match the downgrade. Plan updated in 3 sites: T7 watchpoint (c) + T7 §"Halt-summary requirements" item (3) + top-level §"Tests" inventory test_storage_list_for_tenant.py row (4 → **5** regressions). |

**Round 21 reviewer notes recorded for execution:**

1. **Verify all live helper signatures + typed-attribute types at plan-write time** — R20's "the helper accepts None per its existing signature" was a cite-from-memory claim that contradicted the actual `_emit_isolation_log(pack_id: str)` signature. R-round lesson: every code-block-shaped plan claim that invokes a live helper or types a Pydantic field MUST be grep-verified against the live source (`grep -n "^def _emit_isolation_log\|^class Actor\|tenant_id:" <file>`) within the same compose pass per `feedback_verify_code_citations_at_doc_write.md`.
2. **Every halt-summary watchpoint needs a declared test surface that proves it** — R20's env-gated EXPLAIN watchpoint had no matching test file declared. R-round lesson: when adding a watchpoint that requires a NEW test (live-DB inspection / integration probe / fixture setup), the same patch MUST declare the test file in the top-level §"Tests" inventory; otherwise the watchpoint should downgrade to a proof shape that existing tests already cover. The pattern: watchpoint → test-name in inventory in the SAME patch.

---

**Round 20 (R20) — user follow-up doctrine review of Round 19 patches (3×P2 + 1×P3; all patched into plan)**

R20 surfaces ripple effects from R19's new T7 storage seam: task criticality, missing actor-tenant failure semantics, and doctrine/test inventory drift. Pre-T5 still; no code touched.

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **R20 P2 #1** | P2 | **Incomplete R19 P2 #4 fix** — R19 added `packs/storage.py` Modify row for `list_for_tenant` but Task 7 still said NOT-CC + "Standard TDD steps; no halt" at the trailing block. `packs/storage.py` is already a CC module per AGENTS.md; the new tenant-scoped read seam is the AUTHORITATIVE enforcement boundary for `GET /api/v1/packs` (the only inspection endpoint without `{pack_id}`). Same CC-ADJ + halt-YES discipline as T5's `list_by_status` touch (which DOES halt). | T7 class line updated to **"NOT-CC endpoint work + CC-ADJ storage touch"** + **"Halt: YES"**. New §"Why CC-ADJ / Halt-YES" rationale paragraph explicitly mirrors the T5 R11 P2 #1 precedent. Trailing block reworded from "Standard TDD steps; no halt" to a halt-summary watchpoint set (a) coverage ≥95/90 on the new method; (b) two-tenant fixture authoritativeness; (c) `ix_packs_tenant_state` index used; (d) actor_tenant_id_missing semantics preserved at route level (per R20 P2 #2); (e) no Doctrine Lock D touch. Plan updated in 2 sites: T7 task-header class line + T7 trailing watchpoint block. |
| **R20 P2 #2** | P2 | **Newly surfaced** — `GET /api/v1/packs` bypasses `RequireTenantOwnership` (no `{pack_id}` path-param to drive it) which ALSO bypasses the existing `tenant_isolation.py:144-152` `actor_tenant_id_missing` 500 emission. R19's storage test even pinned "empty tenant returns empty list" as a success case — that hides a kernel binder misconfig (actor.tenant_id missing/empty) as a 200 empty-list response, breaking the wire-protocol-public symmetry with every path-param tenant-isolated endpoint where this axis is fail-loud 500. | **Route-level preflight guard added to the list handler:** before calling `store.list_for_tenant(actor.tenant_id, ...)`, the handler asserts `bool(actor.tenant_id)` and on falsy emits the SAME structured log via the existing `tenant_isolation._emit_isolation_log(reason="actor_tenant_id_missing", actor_subject=actor.subject, pack_id=None)` (the helper accepts None pack_id per its existing signature) AND raises `HTTPException(500, detail={"reason": "actor_tenant_id_missing"})` — wire-protocol-identical to the path-param-tenant-isolated endpoints. R19's misleading "empty-tenant storage success" test renamed to `test_list_for_tenant_with_no_packs_returns_empty_list` (legit happy-path empty-result-set behaviour); the actor-tenant-missing axis lands at the route-level via new test `test_list_returns_500_when_actor_tenant_id_missing` (covers both `tenant_id=""` and `tenant_id=None` paths + caplog assertion). Plan updated in 3 sites: T7 §"Files" inspection storage row trailing paragraph (NEW preflight-guard implementer-pattern code block) + T7 watchpoint (d) + §"Tests" inspection-routes-test row. |
| **R20 P2 #3** | P2 | **Incomplete R19 P2 #4 fix** — R19 added T7 storage touch to the §"CC promotions" entry but missed three downstream doctrine surfaces: (a) T12 §"Why CC-doctrine" paragraph (enumerates "T5 + T9 + T11" storage touches; T7 missing); (b) T12 watchpoint (e) numbered list of CC-source touches (T5 storage at item 2; T9 at item 3; no item for T7); (c) T13 reference table sub-section (e) (lists T5 + T9 storage; no T7). AGENTS.md uplift + closeout navigation table would have shipped stale immediately after R19. | T7 storage touch added to all 3 doctrine surfaces: (a) T12 §"Why CC-doctrine" paragraph now enumerates "T4 + T5 + **T7** + T9 + T11" with parenthetical "T7 (`packs/storage.py` `list_for_tenant` NEW method — Round 19 P2 #4 + Round 20 P2 #3)"; (b) T12 watchpoint (e) item **2a** inserted between the existing T5 (item 2) + T9 (item 3) entries — full rationale with 4 test names; (c) T13 reference table sub-section (e) item **(2a)** inserted with same rationale + cross-reference to R20 P2 #1 halt-YES + R20 P2 #2 route-level guard. Plan updated in 3 sites; all 3 doctrine surfaces now name the T7 touch. |
| **R20 P3 #4** | P3 | **Incomplete R19 P2 #4 fix** — R19 added `tests/unit/packs/test_storage_list_for_tenant.py` to the T7 §"Files" row but the top-level §"Tests" inventory still jumped from `test_inspection_routes.py` to `test_rbac_enforcement_e2e.py` with no mention of the new storage-test module. Implementer reading the plan from the top would miss the CC-ADJ storage proof. | `test_storage_list_for_tenant.py` added to the top-level §"Tests" inventory with all 4 regression names enumerated + cross-reference to R20 P2 #1 halt-summary coverage requirement + R20 P2 #2 corrected test name (was misleading "empty-tenant returns empty list"). Plan updated in 1 site: top-level §"Tests" inventory. |

**Round 20 reviewer notes recorded for execution:**

1. **CC-ADJ touch to a critical-controls module bumps task class regardless of task surface** — T7's endpoints are read-only NOT-CC, but the storage-modify row touches a live CC module (`packs/storage.py`); the task class becomes "NOT-CC endpoint work + CC-ADJ storage touch" with halt-YES discipline. R-round lesson: when adding ANY storage-modify row to ANY task, audit the task's halt-discipline against the source module's CC status; bump halt + add halt-summary watchpoints in the same patch.
2. **Tenant-isolation invariants must be wire-protocol-symmetric across ALL endpoints** — the 4-value `TenantIsolationFailure` enum (`pack_not_found` / `tenant_id_mismatch` / `actor_tenant_id_missing` / `pack_store_not_configured`) is the wire-protocol-public contract for tenant denials. ANY endpoint that bypasses `RequireTenantOwnership` (because no `{pack_id}`) MUST reimplement the equivalent guards at the route level, emitting the SAME structured log via the SAME helper. R-round lesson: future endpoints that touch tenant-scoped data without a `{pack_id}` need an explicit route-level tenant-actor-presence preflight guard.
3. **Every storage-modify row needs an entry across all 3 doctrine surfaces** — §"CC promotions" + T12 §"Why CC-doctrine" + T12 watchpoint (e) + T13 reference table (e). R-round lesson: when adding a storage extension to a task, the same plan-edit pass MUST also update all 3 doctrine surfaces; otherwise the closeout + AGENTS.md uplift ship stale.
4. **Top-level §"Tests" inventory is the implementer's READ-FROM-THE-TOP surface** — every new test module declared in a task's §"Files" must appear in the top-level §"Tests" inventory in the same patch. R-round lesson: the inventory is the canonical test-discovery surface; per-task §"Files" rows are supplementary detail.

---

**Round 19 (R19) — user follow-up doctrine review of Round 18 patches (3×P2 + 2×P3; all patched into plan)**

R19 surfaces an internal contradiction in the new approve log matrix, a wrong-logger attribution for allow-list service denial, a misstated prefix-length count, a missing tenant-scoped inspection storage seam, and a stale review-round count in T13. Pre-T5 still; no code touched.

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **R19 P2 #1** | P2 | **Incomplete R18 P2 #2 fix** — R18 patched the caplog regression contradiction (reject accepted vs claim accepted) but introduced a NEW contradiction in the approve row: "Approve any axis" → EXACTLY ONE `portal.packs.approve_fail_loud_503` record fires, then the closing note says "dependency-cascade short-circuits emit NO 503 log because the handler never runs." The 4-axis matrix INCLUDES short-circuit axes (a no-scope, b cross-tenant, c author-of-pack); the row would either fail caplog tests on axes a-c or encourage bypassing the dependency ordering. | Approve row split into 4 rows mirroring the 4-axis matrix: (1) **Approve handler reached** (axis d only — scope + same-tenant + different-actor) → EXACTLY ONE `portal.packs.approve_fail_loud_503` record fires; (2) **Approve short-circuited axis (a) no scope** → EXACTLY ONE RBAC `enforcement._emit_denial_log` record + NO 503 log; (3) **Approve short-circuited axis (b) cross-tenant** → EXACTLY ONE `tenant_isolation._emit_isolation_log` record + NO 503 log; (4) **Approve short-circuited axis (c) author-of-pack** → EXACTLY ONE `role_separation._LOG.warning("portal.rbac.role_separation_refused"…)` record + NO 503 log. Each axis now has an explicit, mutually-exclusive log expectation that pins the dependency-cascade-ordering invariant. Plan updated in 1 site: T5 §"Files" review_routes.py Create row caplog regression table. |
| **R19 P2 #2** | P2 | **Newly surfaced** — R18 P2 #4's operator-route structured-log contract listed `actor_type_must_be_human` as a possible `reason` value on `portal.packs.allow_list_refused`, but `RequireHumanActor()` is a FastAPI sub-dependency: a service-token denial happens BEFORE the operator handler body executes. The `human_actor._LOG.warning(...)` at `human_actor.py:68` (introduced T2 R1 P2 #2) ALREADY emits its own log on that axis; operator_routes.py cannot — and must not — re-emit on the same axis without reimplementing or catching the guard. The plan's vocabulary would force implementer to either invent a guard-catching anti-pattern OR fail caplog assertions on accurate handler code. | `actor_type_must_be_human` removed from the operator-route refusal-event vocabulary. T6 §"Files" operator_routes.py Create row updated to explicitly call out: "RequireHumanActor() is a FastAPI sub-dependency that runs BEFORE the operator handler body; a service-token denial short-circuits there and human_actor._LOG emits its own log; the operator handler never executes on that axis, so it cannot — and must not — emit `portal.packs.allow_list_refused` for that reason." New caplog test `test_allow_list_service_actor_emits_human_actor_log_only` asserts a service-actor allow-list request produces EXACTLY ONE `cognic_agentos.portal.rbac.human_actor` log record AND ZERO `portal.packs.allow_list_refused` records. Plan updated in 1 site: T6 §"Files" operator_routes.py Create row structured-log contract section. |
| **R19 P3 #3** | P3 | **Newly surfaced** — R18 P2 #4 claimed all 5 T6 operator prefixes are 12 chars and produce 44-char total request IDs, but the actual prefix strings (`pack-alowlst-`, `pack-install-`, `pack-disable-`, `pack-revoke--`, `pack-uninstal`) are 13 chars each (T4 + T5 prefixes ARE 12 chars each; T6 drifted to 13). The `<=64` invariant still holds (13 + 32 = 45 ≤ 64) but exact-prefix/length tests would be confusing or brittle. | Prefix-length claim corrected. Plan now explicitly says: T4+T5 are 12 chars (44 char IDs); T6 are 13 chars (45 char IDs); what IS uniform is the **invariant `len(prefix) + 32 <= 64`** that the module-foot build-time `assert` pins. Caplog + regression tests assert the invariant `len(request_id) <= 64` AND the expected prefix string per verb, NOT a specific total-length count — eliminates false-uniformity coupling. Plan updated in 1 site: T6 §"Files" operator_routes.py Create row request-id minter section. |
| **R19 P2 #4** | P2 | **Newly surfaced** — T7's `GET /api/v1/packs` inspection endpoint promises "list packs scoped to actor.tenant_id; cross-tenant rows filtered server-side" but: (a) there is no `{pack_id}` so `RequireTenantOwnership` cannot enforce row-level tenant filtering (the dependency's path-params lookup fails); (b) the live store has no list-all-by-tenant read seam (`list_by_status(state, ..., tenant_id=...)` requires a state filter; T5 wired it for the reviewer queue only); (c) without a tenant-scoped storage seam, the handler would either in-handler-filter (pagination-skew bug — `limit=50` returns <50 rows when other tenants' rows occupy slots) or leak cross-tenant rows. | T7 §"Files" extended with NEW `Modify: packs/storage.py` row: add `list_for_tenant(tenant_id: str, *, limit: int = 50, cursor: uuid.UUID | None = None, state: PackState | None = None)` method with REQUIRED `tenant_id` filter + OPTIONAL `state` AND-clause; uses the existing `ix_packs_tenant_state` composite index per migration L129. Pure-read; no Doctrine Lock D touch. T7 itself stays NOT-CC at task-level; the storage touch is CC-ADJ to `packs/storage.py` (same shape as T5's list_by_status extension). 4 new regressions at `tests/unit/packs/test_storage_list_for_tenant.py`: tenant-only filter + optional state + cursor pagination + empty-tenant. T7 endpoint table row 1 updated to reference the new seam explicitly. §"CC promotions of existing modules" `packs/storage.py` entry extended with the T7 CC-ADJ touch. Plan updated in 3 sites: T7 §"Files" (NEW Modify row) + T7 endpoint table row 1 + §"CC promotions" storage.py entry. |
| **R19 P3 #5** | P3 | **Incomplete R18 refresh** — T13 final reference table preamble at L1318 still said "consolidates the 12-review-round patch surface" but the plan is now through R18 (19 rounds total: R0 + R0.5 + R0.6 + R1–R18). Future R-rounds would stale this line again on every reviewer pass. | Wording future-proofed: "consolidates the R-round patch surface" (no exact count) + parenthetical "current state through R18 = R0 + R0.5 + R0.6 + R1–R18, with R-round count growing on every subsequent reviewer pass". Plan updated in 1 site: T13 closeout section 7 preamble. |

**Round 19 reviewer notes recorded for execution:**

1. **Approve-endpoint caplog assertions MUST mirror the 4-axis matrix structure** — a blanket "approve emits X" claim is wrong because three axes never reach the handler. R-round lesson: every log-event expectation that depends on dependency-ordering must enumerate the per-axis expectation explicitly.
2. **FastAPI sub-dependency guards emit their own logs; handlers MUST NOT shadow them** — `RequireHumanActor()` runs BEFORE the operator handler body; `tenant_isolation` runs BEFORE; `role_separation` runs BEFORE. The handler-side refusal-event vocabulary covers ONLY the refusals the handler itself produces (state-machine refusal + PackNotFound race). Guard-layer denials emit guard-layer logs. R-round lesson: when adding refusal events to a handler module, audit the dependency chain for any guard that short-circuits BEFORE the handler — those reasons belong to the guard's log, not the handler's.
3. **Storage-seam coverage check for read endpoints** — every read endpoint that promises tenant-scoped or filter-scoped output needs a corresponding storage-side seam that enforces the filter server-side. R-round lesson: when adding a new read endpoint to the plan, audit the live storage API for an exact-match seam; if absent, declare a NEW seam + tests in the same task.
4. **Round counts age fast — avoid embedding them in living narrative** — every R-round adds 1 to the count, so any text that names a specific round number goes stale immediately. R-round lesson: T13-style summary surfaces use future-proof phrasing ("R-round patch surface", "current state through R<N>") with an explicit "subject to growth" parenthetical.

---

**Round 18 (R18) — user follow-up doctrine review of Round 17 patches (4×P2; all patched into plan)**

R18 surfaces a residual `{id}` path-param sweep miss, a contradicting log expectation in the new structured-log contract, and two missing T6/T7 parity surfaces (production-wiring + transition-handler-parity with T4/T5). Pre-T5 still; no code touched.

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **R18 P2 #1** | P2 | **Incomplete R17 P2 #1 fix** — R17 said "live forecast surface has zero `{id}` paths" but the sweep was narrow (endpoint-table cells only). 9 residual `{id}` live mentions remained: §"Architecture" L7 narrative + §"Tests" L134 reject-evidence test name reference + scope-frozenset code-sample comment L261 + T4 endpoint table L672/L673/L674 + T4 doctrine bullets L682/L683/L684 + T4 watchpoint (d) L709 + T5 §"Files" router.py-docstring-update language L734 + T5 caveat L856 + T7 inspection test bullets L963/L964/L965. R17 left these live surfaces stale, recreating the path-param-mismatch risk the R17 patch was supposed to fix. | Repo-plan-wide grep `grep -n '{id}' …` swept ALL live surfaces (left only Round 0.6 ADR-§59-literal-quotation at L614/L1367 + the R17 P2 #1 patch-log finding-text at L1572 untouched per "leave ADR spec quotations + patch-log narrative as historical record" rule). Total: 9 live sites updated to `{pack_id}` (L7 + L134 + L261 + L672 + L673 + L674 + L682 + L683 + L684 + L709 + L734 + L856 + L963 + L964 + L965). Plan now consistent: every live forecast surface that names a path-param uses `{pack_id}`. |
| **R18 P2 #2** | P2 | **Newly surfaced** — R17 P2 #2's new structured-log contract table correctly declares `portal.packs.review.reject` fires when a reject body is accepted (load-bearing T5 evidence surface for categorised reason+comments per Round 11 P2 #3), but the caplog regression sentence wrote "on the green-path admit, NO log record fires" — which would fail OR discourage the accepted-reject evidence log. The two statements contradict each other; implementer would either skip the evidence log (regress observability) or fail the caplog test on green reject. | Caplog regression expectations split per event-type via a 5-row table: (a) **Reject accepted (green)** → EXACTLY ONE `portal.packs.review.reject` record fires; (b) **Reject refused** → EXACTLY ONE `portal.packs.reject_refused` record + NO accepted log (mutually exclusive); (c) **Claim accepted (green)** → NO log record (claim has no T5 evidence surface — the chain row IS the evidence); (d) **Claim refused** → EXACTLY ONE `portal.packs.claim_refused` record; (e) **Approve any axis** → EXACTLY ONE `portal.packs.approve_fail_loud_503` record (no green-path exists; the 503 IS the only handler-reachable path); plus a note that dependency-cascade short-circuits (RBAC/tenant/role-separation) emit their own sibling-guard logs but NO `approve_fail_loud_503` (handler never executes). Plan updated in 1 site: T5 §"Files" review_routes.py Create row, replacing the misleading single-sentence regression spec with the per-event-type table. |
| **R18 P2 #3** | P2 | **Incomplete R16 P2 #1 carry-forward** — R16 added the T5 `router.py` Modify step + production-wiring regression, AND captured a reviewer-note "Future T6 + T7 need the same pattern", BUT T6 §"Files" + T7 §"Files" still only listed `Create: operator_routes.py` / `inspection_routes.py` + test. If followed literally, T6/T7 routes would create their sub-routers but never wire them into the parent `build_packs_router` — same half-wired-surface failure mode R16 P2 #1 caught for T5. | T6 §"Files" + T7 §"Files" each extended with explicit `router.py` Modify rows: T6 includes `build_operator_routes(store=store)` alongside T5/T4 inclusions; T7 includes `build_inspection_routes(store=store)` completing the four-sub-router wire-up. New T6 watchpoint (f) `test_build_packs_router_includes_operator_routes` regression + new T7 test `test_build_packs_router_includes_inspection_routes` (also lands the Round 13 P2 #1 carry-forward `test_review_queue_and_inspection_list_both_reachable` shared assertion). Plan updated in 4 sites: T6 §"Files" + T7 §"Files" + T6 watchpoints + T7 §"Tests" entry. |
| **R18 P2 #4** | P2 | **Newly surfaced** — All 5 T6 operator endpoints call `PackRecordStore.transition(...)` but T6 had ZERO of the four transition-handler guards T4 + T5 already established: (a) bounded request-id prefixes via `_mint_request_id(<prefix>)`; (b) `PackNotFound` race translation → 404 `pack_not_found`; (c) structured refusal log events (`portal.packs.<verb>_refused`); (d) module-foot build-time invariants for prefix lengths. Leaving T6 implicit pushes security-relevant design into implementation; the 5 operator endpoints would either invent prefixes ad-hoc, leak 500s on the PackNotFound race, AND/OR ship without parity caplog regressions. | T6 §"Files" operator_routes.py Create row extended with: (1) 5 module-scoped `_PACK_<VERB>_REQUEST_ID_PREFIX` constants for allow_list / install / disable / revoke / uninstall (each 12 chars; 12+32=44 ≤ 64); cross-imports `_mint_request_id` from `author_routes.py`; module-foot build-time invariant for all 5 prefixes; (2) module-scoped `_LOG = logging.getLogger(__name__)` + 5 canonical `portal.packs.<verb>_refused` events with the standard reason+actor_subject+pack_id+from_state extras; (3) `PackNotFound` race translation in all 5 handlers — same 404 + `_PACK_NOT_FOUND_REASON` translation as T4/T5. T6 endpoint table cells extended per-row with the request-id minter call + race translation + refusal log event. T6 watchpoints (g)/(h)/(i) added for the three new parity regressions (request-id bounded length, PackNotFound race, structured refusal log emission). Plan updated in 4 sites: T6 §"Files" Create row + 5 T6 endpoint table cells + T6 watchpoints (3 new) + (implicit) tests parametrized over all 5 operator verbs. |

**Round 18 reviewer notes recorded for execution:**

1. **Path-param sweeps must run repo-plan-wide, not narrow-scope** — R17's endpoint-table-only sweep missed 9 residual live surfaces. R-round lesson: when renaming a wire-protocol-public name (path param / closed-enum value / log message), the sweep MUST grep the entire plan and update every non-historical occurrence in the same pass; leave ONLY ADR-literal-quotations and patch-log finding-text untouched.
2. **Caplog regression specs MUST distinguish accepted-path-with-evidence-log from green-path-no-log** — R17's "green-path admit emits no log" wording conflated two distinct semantics (reject's accepted-body log IS evidence; claim's accepted path emits nothing; approve has no accepted path). R-round lesson: every structured-log regression spec needs per-event-type assertions, not blanket "happy path emits nothing".
3. **Production-wiring + transition-handler-parity guards apply to EVERY task that adds endpoint surfaces** — R16's T5 patch + R18's T6/T7 patches established the four-pillar pattern: (i) `router.py` Modify + production-factory regression; (ii) bounded request-id prefixes; (iii) `PackNotFound` race translation; (iv) structured refusal log events. R-round lesson: future task-additions of endpoint surfaces (any sprint after 7B.2) follow this pattern by default; reviewers can apply the four-pillar checklist mechanically.

---

**Round 17 (R17) — user follow-up doctrine review of Round 16 patches (3×P2; all patched into plan)**

R17 surfaces a path-param convention mismatch, an underspecified review-route structured-log contract, and a prefix-ownership drift across two live forecast surfaces. Pre-T5 still; no code touched.

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **R17 P2 #1** | P2 | **Newly surfaced** — T5 endpoint table used `{id}` path param (`/api/v1/packs/{id}/claim` etc) but the shared dependency `_require_tenant_ownership = RequireTenantOwnership(pack_id_param="pack_id")` at `author_routes.py:388` reads `request.path_params.get("pack_id")` and the dependency at `tenant_isolation.py:122-129` raises `RuntimeError("path-param mismatch: no 'pack_id' in request.path_params")` if absent. T4 author routes use `{pack_id}` convention (`/drafts/{pack_id}/submit` etc); T5-T7 drift to `{id}` would cause claim/approve/reject/evidence + all operator + all inspection endpoints to fail with a 500 routing-bug `RuntimeError` instead of the expected RBAC/tenant/role-separation semantics. | All `{id}` paths renamed to `{pack_id}` across T5/T6/T7 endpoint tables (14 sites total: 4 in T5 review + 5 in T6 operator + 3 in T7 inspection + 2 already-correct in T5). Adopted T4's existing convention as the source of truth — `_require_tenant_ownership = RequireTenantOwnership(pack_id_param="pack_id")` stays unchanged. **NEW regression `test_review_routes_path_param_name_matches_dependency`** (parametrized over claim / approve / reject / evidence) asserts route's compiled path string contains `"{pack_id}"` AND issuing a request with a malformed UUID returns 404 `pack_not_found` (NEVER 500 — would be the path-param-mismatch fingerprint). Same regression carry-forward declared at T6 (`test_operator_routes_path_param_name_matches_dependency`) + T7 (`test_inspection_routes_path_param_name_matches_dependency`). Updated T5 watchpoint (e) to record the convention + the regression. |
| **R17 P2 #2** | P2 | **Newly surfaced** — Round 11 P2 #3's "reject ships as bare transition + structured-log only" + Round 16 P2 #2's "structured-log emission for the race" both made structured logs the load-bearing evidence surface in T5, but the plan never specified the logger name, message strings, or `extra` keys for the review_routes events. Implementer would invent these at code-write time → wire-protocol-fingerprint drift between T5 ship and any later T9 carry-forward parity test. The T4 author_routes module already established a canonical pattern (`portal.packs.<verb>_refused` log names at `:432` + `:476` + `:584` + `:662` etc) but the plan never told T5 to mirror it. | T5 §"Files" review_routes.py Create row extended with a **4-row structured-log contract table** declaring the canonical events: `portal.packs.review.reject` (categorised reject body received; extra=actor_subject+pack_id+reason+comments) + `portal.packs.claim_refused` (claim transition refused via state-machine OR race; extra=reason+actor_subject+pack_id+from_state) + `portal.packs.reject_refused` (reject transition refused; same extra shape) + `portal.packs.approve_fail_loud_503` (no-transition path; extra=reason+actor_subject+pack_id+next_sprint). Module-scoped `_LOG = logging.getLogger(__name__)` mirrors T4's `author_routes._LOG` at `:66`. **Caplog regressions** (one per event, parametrized) assert exactly one record fires at WARNING level with the canonical message + closed-enum reason. Plan updated in 1 site: T5 §"Files" review_routes.py Create row. |
| **R17 P2 #3** | P2 | **Incomplete Round 14 fix** — R14 P2 #2 correctly moved `_PACK_CLAIM_REQUEST_ID_PREFIX` + `_PACK_REJECT_REQUEST_ID_PREFIX` ownership to T5 in the T5 §"Files" review_routes.py Create row, but TWO live forecast surfaces still drifted: (a) the T9 wire-design paragraph at L1119 listed "T5 adds `_PACK_REJECT_REQUEST_ID_PREFIX`" with NO mention of the claim prefix; (b) the T13 reference table sub-section (e) item #5 at L1269 still attributed `_PACK_REJECT_REQUEST_ID_PREFIX` introduction to T9 (was Round 12 P2 #2's pre-correction language; Round 14 P2 #2 only patched the T9 §"Files" prose row, not the T13 reference table). | Both live forecast surfaces updated: (a) T9 wire-design paragraph at L1119 — explicitly enumerates "T5 adds BOTH `_PACK_CLAIM_REQUEST_ID_PREFIX` AND `_PACK_REJECT_REQUEST_ID_PREFIX` at review_routes.py" + "T9 introduces NO new prefix"; (b) T13 reference table sub-section (e) item #5 — reworded so "T5 creates the module + declares BOTH prefixes; T9 only reuses the reject prefix". Plan updated in 2 sites; consistent across all 5 surfaces now (T5 §"Files" Create row + T5 endpoint table cells + T9 §"Files" review_routes Modify row + T9 wire-design paragraph + T13 reference table). |

**Round 17 reviewer notes recorded for execution:**

1. **Path-param convention is a wire-protocol-public contract** — the OpenAPI spec exports `{pack_id}` as the parameter name; downstream SDK / portal-UI / docs all consume that name. T4 set the precedent; T5-T7 must follow. Renaming a path param post-ship is a wire-protocol break.
2. **Structured-log event names are wire-protocol-public for observability** — log aggregation tooling (Splunk / Datadog / Langfuse) buckets on the `message` field; renaming a log event post-ship invalidates every dashboard / alert / SLI built on the old name. Plan-time enumeration of the canonical event-name set is essential, mirroring closed-enum vocabulary discipline.
3. **Multi-surface forecast drift on doctrine claims** — every claim that "X is added at T5/T9" needs grep verification across ALL forecast tiers (CC promotions / Modify list / detailed task section / wire-design / reference table) in the same compose pass. R-round lesson: future forecast claims about cross-task ownership should be verified via `grep -n "<claim-string>"` post-patch with the writer reading EVERY hit before halting.

---

**Round 16 (R16) — user follow-up doctrine review of Round 15 patches (3×P2; all patched into plan)**

R16 surfaces three newly-introduced issues against the Round 11-15 patches — missing production-wiring, missing race-handling parity with T4, and missing structured-log emission parity with sibling RBAC guards. Pre-T5 still; no code touched.

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **R16 P2 #1** | P2 | **Newly surfaced** — T5 §"Files" creates `review_routes.py` (lots of detail) and adds route-ownership tests, but never says to extend `portal/api/packs/router.py:build_packs_router` to actually INCLUDE the new review sub-router. The T3-shipped `router.py:39-56` only calls `router.include_router(build_author_routes(store=store))`. As written, T5's `test_review_routes_does_not_register_inspection_list_path` (which mounts the review sub-router on a test-fabricated parent) would pass while the production `build_packs_router` still ships ONLY the author surface — silently shipping a half-wired review API. | **Add `src/cognic_agentos/portal/api/packs/router.py` to T5 §"Files" Modify list** with an explicit spec: add `from cognic_agentos.portal.api.packs.review_routes import build_review_routes` import at `router.py:31` alongside the existing `build_author_routes` import + add `router.include_router(build_review_routes(store=store))` at `router.py:55` immediately after the existing author-route inclusion; update module docstring at `:1-24` to narrow the "T5-T7 will add" placeholder to "T5 wires review-routes; T6-T7 add operator + inspection". **NEW production-wiring regression `test_build_packs_router_includes_review_routes`** asserting that calling the actual production `build_packs_router(store=stub_store)` factory produces a router whose compiled `app.routes` includes `GET /api/v1/packs/review-queue` (T5 wired) + `POST /api/v1/packs/drafts` (T4 still wired) but does NOT include `GET /api/v1/packs` (T7 unwired). This regression catches the "review_routes.py created but never wired" failure mode where the manual-mount test passes while production ships only author routes. Plan updated in 2 sites: T5 §"Files" + §"Tests" line 130. |
| **R16 P2 #2** | P2 | **Newly surfaced** — T5's claim + reject handlers both call `PackRecordStore.transition(...)` after `RequireTenantOwnership` preloads the `PackRecord` — same shape as T4's submit + cancel handlers, which already needed the `PackNotFound` race translation per T4 R1 P2 #3 (a concurrent deleter between the tenant-isolation preload and the transition's `SELECT ... FOR UPDATE` raises `PackNotFound` inside the storage precondition; without an `except PackNotFound` clause the exception leaks as a generic 500). The T5 plan never specifies the race handling for claim/reject, so those paths would leak 500s. | **Both claim + reject endpoint table cells extended** with explicit `PackNotFound` race translation: handler MUST catch `PackNotFound` and translate to 404 + `detail={"reason": _PACK_NOT_FOUND_REASON}` (mirrors T4 R1 P2 #3 at `author_routes.py:579-594` for submit + `:658-672` for cancel). The `_PACK_NOT_FOUND_REASON: Final[Literal["pack_not_found"]]` constant is either imported from `author_routes.py` or redeclared at `review_routes.py` module scope (implementer's choice — the constant value lives in the `TenantIsolationFailure` 4-value Literal so both reuses are correctness-equivalent). **NEW stub-store race regressions** `test_claim_handles_pack_not_found_race` + `test_reject_handles_pack_not_found_race` — stub stores where `transition()` raises `PackNotFound`; assert handlers translate to 404 + structured body, no 500 leak, structured-log emission for the race. Plan updated in 3 sites: T5 endpoint table claim row + reject row + §"Tests" line 130. |
| **R16 P2 #3** | P2 | **Newly surfaced** — R14 P2 #3 + R15 P2 #1 defined the `RequireDifferentActorThanCreator` closure-factory to raise an `HTTPException(403, detail={"reason": "actor_cannot_review_own_pack"})` but never added the matching structured-log emission. Sibling RBAC guards ALL emit before raising: `tenant_isolation._LOG = logging.getLogger(__name__)` at `:50` + `_emit_isolation_log` at `:75-94` (called 5+ times across the dependency); `human_actor._LOG` at `:37` + `.warning(...)` at `:68`; `enforcement._emit_denial_log` at `:60-86`. T2 R1 P2 #2 explicitly added caplog parity for all three sibling modules. role_separation would regress observability silently while HTTP-response tests stay green. | **Closure updated** to emit `_LOG.warning("portal.rbac.role_separation_refused", extra={"reason": "actor_cannot_review_own_pack", "actor_subject": …, "pack_id": …, "pack_created_by": …})` immediately BEFORE the `raise HTTPException(403, ...)` line. Module-scoped `_LOG = logging.getLogger(__name__)` + `import logging` added to the code sample header (mirroring sibling-module pattern). **NEW caplog regression `test_role_separation_emits_structured_log`** asserts: (a) on the author-of-pack denial path, exactly ONE log record fires at WARNING level for logger `cognic_agentos.portal.rbac.role_separation`; (b) its `message` is `"portal.rbac.role_separation_refused"`; (c) its `extra` dict carries the closed-enum reason + actor_subject + pack_id + pack_created_by; (d) on the happy admit path, NO log record fires. Plan updated in 4 sites: §"Critical-controls forecast" role_separation.py row + §"File structure → Create" role_separation.py entry (3rd invariant) + T5 §"Files" role_separation.py Create row (full code sample with `_LOG = logging.getLogger(__name__)` + `import logging` + `_LOG.warning(...)` block) + §test_role_separation.py Test row (test #7 added). |

**Round 16 reviewer notes recorded for execution:**

1. **Every new endpoint sub-router needs an explicit production-wiring step + regression** — creating `<surface>_routes.py` is necessary but not sufficient; the parent `router.py:build_packs_router` MUST be extended to include it, AND a regression against the actual production factory call (not a test-fabricated mount) MUST prove the wire landed. R-round lesson: future-T6 (operator) + future-T7 (inspection) need the same pattern.
2. **Race-handling parity across siblings** — every handler that follows the `RequireTenantOwnership` preload + `store.transition()` shape needs the same `PackNotFound` race translation T4 established. R-round lesson: the parity is the contract, not a per-task discovery. T6 operator routes + T7 inspection (where applicable) get the same translation pattern.
3. **Structured-log parity across RBAC sibling guards** — every dependency in `portal/rbac/` that raises a denial `HTTPException` MUST emit a matching structured log BEFORE the raise. T2 R1 P2 #2 added caplog parity for the original three guards (enforcement / tenant_isolation / human_actor); R16 P2 #3 extends parity to the fourth (role_separation). R-round lesson: any future RBAC-style guard introduced in a downstream sprint follows the same parity rule.

---

**Round 15 (R15) — user follow-up doctrine review of Round 14 patches (2×P2; all patched into plan)**

R15 surfaces two FastAPI / Python-annotation-semantics edges introduced by Round 14's closure-factory pattern + a Round-13 test-shape bug. Pre-T5 still; no code touched.

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **R15 P2 #1** | P2 | **Newly surfaced** — R14 P2 #3's closure-factory `RequireDifferentActorThanCreator(*, tenant_ownership: RequireTenantOwnership)` has two latent bugs verified against the live RBAC sibling modules: (a) **`from __future__ import annotations`** is used by `tenant_isolation.py:37` + `human_actor.py:26` + `enforcement.py:26` — if `role_separation.py` follows the convention naively, PEP 563 string-deferred annotations would make FastAPI's `typing.get_type_hints()` / `inspect.signature()` unable to resolve `Annotated[PackRecord, Depends(tenant_ownership)]` in the inner closure (closure-bound `tenant_ownership` is NOT a module-global symbol; the lazy string evaluation would NameError or silently treat `record` + `actor` as query params — the T4-era query-param-leakage bug); (b) **typing `tenant_ownership: RequireTenantOwnership`** is wrong — `RequireTenantOwnership` is a factory FUNCTION (`def RequireTenantOwnership(...) -> Callable[..., Awaitable[PackRecord]]` at `tenant_isolation.py:96-98`), NOT a class — its NAME as a type annotation refers to the function object itself, not instances. | Two module-header invariants pinned at three plan sites: (1) **`role_separation.py` MUST OMIT `from __future__ import annotations`** — sibling-module convention does NOT extend here; annotations stay live so FastAPI resolves against the function's `__closure__` cells. (2) **Type alias `TenantOwnershipDep: TypeAlias = Callable[..., Awaitable[PackRecord]]`** at module scope; factory parameter typed `tenant_ownership: TenantOwnershipDep` per the real `RequireTenantOwnership` return signature. (3) Full updated code sample with no-future-import header + type-alias + explicit docstring rationale per `feedback_security_regression_hardening.md`. Two new tests pinned load-bearingly: `test_module_must_not_import_future_annotations` (AST self-test asserts no `ImportFrom(module="__future__", names=[alias(name="annotations")])` node in the module's AST) + `test_role_separation_resolves_under_fastapi_introspection` (builds tiny `FastAPI()` app, forces full introspection via `app.openapi()`, asserts `record` + `actor` do NOT appear as `query` parameters in the OpenAPI spec + asserts 403 on author-of-pack integration). Plan updated in 4 sites: §"Critical-controls forecast" role_separation.py row + §"File structure → Create" role_separation.py entry + T5 §"Files" role_separation.py Create row (full code sample with header rationale) + T5 §"Files" test_role_separation.py test entry. |
| **R15 P2 #2** | P2 | **Incomplete R13 fix** — R13 P2 #1's `test_review_routes_does_not_register_inspection_list_path` was specified to walk the review-only sub-router and assert: (1) `GET /api/v1/packs/review-queue` exists; (2) no route's path equals `/api/v1/packs`. Both assertions are vacuously / wrongly stated against an un-mounted `APIRouter`: (1) an un-mounted sub-router exposes only relative path `/review-queue` (NOT the full prefixed path); (2) the un-mounted sub-router never has a route at `/api/v1/packs` so the "does not equal" assertion always passes. R13 split the proof to T5+T7 correctly but the T5-narrow proof shape was vacuous. | **Two correct test shapes specified** (Shape A recommended): **Shape A — mount under a test parent (recommended):** build `_review_router = build_review_routes(store=stub_store)`, then mount onto a fresh `FastAPI()` test app via a parent `APIRouter(prefix="/api/v1/packs")` (mirrors `build_packs_router` production behaviour); walk `app.routes` and assert the COMPILED full path `/api/v1/packs/review-queue` exists with `methods={"GET"}` + `pack.review.claim` dependency, AND assert NO route's compiled path equals `/api/v1/packs`. **Shape B — test raw sub-router with relative paths:** walk the un-mounted `_review_router.routes` and assert relative `/review-queue` exists + relative `/` does NOT exist. Shape A is preferred because it tests the actually-deployed compiled-path shape; the test fixture builds the full prefix-mount the production code path uses. Plan updated in 3 sites: §"Tests" line 130 (rewording) + §T5 watchpoint (h) (rewording + both shapes documented) + §T13 sub-section (g) (R15 P2 #2 mount-prefix correction note). |

**Round 15 reviewer notes recorded for execution:**

1. **`from __future__ import annotations` is module-by-module, not codebase-wide** — sibling-module convention applies UNLESS a module uses a Python construct (FastAPI closure-factory) that PEP 563 breaks. R-round lesson: every NEW module that exports a FastAPI dependency factory needs an explicit module-header invariant decision documented in the plan, NOT inherited silently from sibling modules.
2. **Type annotations for FastAPI dependency factory-parameters should describe the RETURN value, not the factory function** — `RequireTenantOwnership` (the function) ≠ `Callable[..., Awaitable[PackRecord]]` (its return value). Use a named type alias for readability; the alias documents the shape AND avoids brittle cross-module type coupling.
3. **Route-table assertions must test the actually-deployed compiled path** — un-mounted `APIRouter` routes carry only relative paths; the compiled full path comes from the parent's `prefix=`. Mount under a test parent (Shape A) or assert relative paths only (Shape B) — never claim un-mounted routes carry the full prefixed path.
4. **AST self-tests + FastAPI-introspection tests are the load-bearing pair for closure-factory invariants** — per `feedback_security_regression_hardening.md`. AST test catches the "someone added `from __future__ import annotations`" regression; OpenAPI introspection test catches the "FastAPI silently treats record/actor as query params" runtime bug.

---

**Round 14 (R14) — user follow-up doctrine review of Round 13 patches (3×P2; all patched into plan)**

R14 surfaces three newly-introduced API-contract / seam-design issues against the Round 11-13 patches. Pre-T5 still; no code touched.

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **R14 P2 #1** | P2 | **Newly surfaced** — Round 11 P2 #1's `list_by_status(state, *, tenant_id=None, limit, cursor)` signature drops the pre-T5 default values: in that form `limit` and `cursor` are KEYWORD-ONLY-WITHOUT-DEFAULTS, so existing call-sites `store.list_by_status("submitted")` or `store.list_by_status("submitted", limit=10)` would either raise `TypeError` or silently change pagination semantics. The live `packs/storage.py:797` signature is `list_by_status(state, limit: int = 50, cursor: uuid.UUID | None = None)` — defaults must be preserved. | **Exact compatibility-preserving signature** declared in 3 sites: `list_by_status(state, limit: int = 50, cursor: uuid.UUID | None = None, *, tenant_id: str | None = None)` — keeps `limit` + `cursor` positional-or-keyword with their existing defaults; adds `tenant_id` BEHIND the `*` as keyword-only-with-default (additive; existing call-sites stay green). Plan updated in 3 sites: §"CC promotions" L69 + §"Modify (existing files)" L109 + T5 §"Files" storage.py modify row. New regression-test triplet pinned at `tests/unit/packs/test_storage_list_by_status.py`: (1) `test_list_by_status_state_only_backward_compatible`; (2) `test_list_by_status_existing_pagination_signature`; (3) `test_list_by_status_tenant_filtered_pagination`. |
| **R14 P2 #2** | P2 | **Newly surfaced** — T5 claim + reject handlers both call `PackRecordStore.transition(..., request_id=...)`, which requires a caller-supplied bounded ID per the Round 13 P2 #3 wire-design contract. R12 P2 #2 / R12 P2 #3 already established that T4 owns the `_mint_request_id` helper + `_PACK_SUBMIT_REQUEST_ID_PREFIX` / `_PACK_CANCEL_REQUEST_ID_PREFIX` at `author_routes.py`, but R12 left two gaps for T5: (a) `_PACK_CLAIM_REQUEST_ID_PREFIX` has no defined site at all; (b) `_PACK_REJECT_REQUEST_ID_PREFIX` was referenced as "added at T5" in the T9 narrative but T5 never declared it. T5 would invent these prefixes at code-write time without a plan-pinned spec. | T5 owns BOTH new prefix constants at `review_routes.py` module scope: `_PACK_CLAIM_REQUEST_ID_PREFIX: Final[str] = "pack-claim--"` (double-dash distinguishes from `pack-cancel-` to keep prefixes prefix-unique) + `_PACK_REJECT_REQUEST_ID_PREFIX: Final[str] = "pack-reject-"`. T5 shares the `_mint_request_id` helper from T4 via `from cognic_agentos.portal.api.packs.author_routes import _mint_request_id` cross-import — single source of truth for the minter. Module-foot build-time invariant asserts `len(<prefix>) + 32 <= 64` for both new prefixes (mirrors T4 R3 P2 #1). T9 reuses `_PACK_REJECT_REQUEST_ID_PREFIX` when amending the reject handler — NO new prefix at T9. The approve handler does NOT mint a request_id in T5 because the fail-loud 503 short-circuits before `store.transition()`. New tests `test_claim_request_id_bounded_to_64_chars` + `test_reject_request_id_bounded_to_64_chars` pin `len(request_id) <= 64` + expected prefix. Plan updated in 4 sites: T5 §"Files" review_routes.py Create row + T5 endpoint table rows 2 (claim) and 4 (reject) + T5 §"Tests" + T9 §"Files" review_routes.py modify row (prefix-ownership clarification — T5 declares; T9 reuses). |
| **R14 P2 #3** | P2 | **Newly surfaced** — Round 11 P2 #4 declared `RequireDifferentActorThanCreator(pack_id_param: str)` as a `RequireHumanActor()`-shape class-based dependency, but: (a) the dependency must compare `actor.subject` to `record.created_by`, so it needs the `PackRecord` from somewhere; (b) the plan never specified whether role_separation re-loads the pack (race + duplicate `store.load`) or consumes the tenant-checked record; (c) a `RequireHumanActor`-shape class with `__call__(actor, record)` can't reference `self.tenant_ownership` in an `Annotated[PackRecord, Depends(...)]` annotation because `self` isn't a class-time symbol. The patched plan would have implementers either duplicate the pack load OR construct a broken class-based dependency that wouldn't type-check. | **Closure-factory pattern (function, NOT class):** `RequireDifferentActorThanCreator(*, tenant_ownership: RequireTenantOwnership)` is a factory function that returns a FastAPI-compatible dependency closure. The inner closure declares `Annotated[PackRecord, Depends(tenant_ownership)]` — referring to the captured `tenant_ownership` closure variable. At T5 `build_review_routes(store=...)` time, the router builds ONE `_require_tenant_ownership` instance, constructs `_require_different_actor_than_creator = RequireDifferentActorThanCreator(tenant_ownership=_require_tenant_ownership)`, and each review endpoint declares BOTH `Depends(_require_tenant_ownership)` (yielding the PackRecord) AND `Depends(_require_different_actor_than_creator)`. FastAPI's per-request sub-dependency cache (keyed by callable identity) deduplicates the PackRecord load → ONE `store.load` call on the happy path. Refusal-cascade ordering pinned: RBAC fail → 403 BEFORE tenant; cross-tenant → 404 BEFORE role; author-of-pack → 403 actor_cannot_review_own_pack. Plan updated in 4 sites: §"Critical-controls forecast" role_separation.py row + §"File structure → Create" role_separation.py entry + T5 §"Files" role_separation.py Create row (full code sample + router-build pattern) + T5 endpoint table rows 2/3/4 (shared-instance dependency declarations). New tests in `test_role_separation.py` (closure-factory shape introspection) + `test_review_routes.py` (`test_dependency_order_rbac_then_tenant_then_role_separation` + `test_role_separation_does_not_duplicate_pack_load`). |

**Round 14 reviewer notes recorded for execution:**

1. **Compatibility-preserving signature on storage extensions** — any extension to a pre-existing storage seam (`list_by_status`, `transition`, `update_draft`, etc) MUST preserve the existing parameter order + defaults. New args land BEHIND a `*` as keyword-only-with-default. Pinned by backward-compat regression tests that exercise the pre-extension call shape literally.
2. **Request-id ownership goes where the transition is called** — the handler module that calls `store.transition()` owns the `_PACK_<verb>_REQUEST_ID_PREFIX` declaration. T4 owns submit + cancel; T5 owns claim + reject. T9 reuses the T5 reject prefix when amending the handler — no new prefix introduced at T9.
3. **Closure-factory vs class-with-`__call__` for FastAPI dependencies** — when a dependency needs to reference a specific instance of another dependency in its `Annotated[..., Depends(...)]` annotation, use a **closure-factory function** (function returning the inner async closure), NOT a class-with-`__call__`. The class shape can't reference `self.x` in an `Annotated[..., Depends(...)]` annotation because `self` isn't bound at class-creation time. R-round lesson: every FastAPI dependency mention in the plan should explicitly call out its shape (factory closure vs class vs simple function).
4. **FastAPI's per-request callable-identity cache deduplicates sub-dependencies** — when an endpoint and a role-separation dependency both `Depends(_require_tenant_ownership)` with the SAME instance, FastAPI computes the value once per request. Pinned via a counting-stub store regression that asserts EXACTLY ONE `store.load` call on the happy claim/reject path.

---

**Round 13 (R13) — user follow-up doctrine review of Round 12 patches (3×P2 + 2×P3; all patched into plan)**

R13 surfaces newly-introduced issues + incomplete R12 fixes against the patched plan. Pre-T5 still; no code touched.

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **R13 P2 #1** | P2 | **Newly surfaced** — Round 12 P2 #1 added `test_review_queue_and_inspection_list_both_reachable` under T5 §"Tests" + T5 watchpoint (h). But at T5-execution time `inspection_routes.py` does NOT yet exist (T7 owns it), so the test either fails RED for the wrong reason OR forces T5 to implement T7 early, breaking the TDD task boundary. | **Split the proof across T5 + T7:** T5 owns the narrow assertion `test_review_routes_does_not_register_inspection_list_path` — asserts the review sub-router carries `GET /api/v1/packs/review-queue` AND does NOT register `GET /api/v1/packs`; runs against the review-only sub-router at T5-execution time. T7 owns the full assertion `test_review_queue_and_inspection_list_both_reachable` — asserts the fully-composed `build_packs_router(store=…)` route table contains BOTH paths without shadow; runs once `inspection_routes.py` exists. Plan updated in 4 sites: §T5 §"Tests" line 130 (split rename) + §T5 watchpoint (h) (split rename + cross-reference) + §T7 §"Tests" (NEW carry-forward bullet) + §T13 sub-section (g) (note the split). |
| **R13 P2 #2** | P2 | **Incomplete R12 fix** — Round 12 P2 #2 bumped the T9 §"Wire design" section to "THREE new optional keyword-only kwargs" and added Files-section rows for author_routes + review_routes, but the **live file-structure forecast** at §"Modify (existing files)" L109 still listed only TWO storage kwargs (`payload_conformance` + `expected_manifest_digest`), AND the top **§"CC promotions of existing modules"** L69 row mirrored the same two-kwarg view. R12 left two stale forecast surfaces that future implementers would follow despite the corrected detailed T9 surface. | Both forecast rows updated to **THREE** kwargs with the new `evidence_attachments` value called out. Plan updated in 2 sites: §"Modify (existing files)" L109 storage.py row + §"CC promotions of existing modules" L69 storage.py row. All three live forecast surfaces (top CC promotions + Modify list + T9 §Files) now consistent on the three-kwarg surface. |
| **R13 P2 #3** | P2 | **Incomplete R12 fix** — Round 12 P2 #3 added a "DO NOT use request.state.request_id" warning to the T9 pseudocode comments but left the **prose paragraph just before the pseudocode** still saying "the `request_id` is the FastAPI per-request UUID (already bound by `RequestIdMiddleware` in `portal/observability/`)". The pseudocode + the prose paragraph contradicted each other. Future implementer reading the prose first would still wire `request.state.request_id` and only catch the contradiction inside the pseudocode comments. | Prose paragraph rewritten to declare: (1) `request_id` is **caller-supplied** per the `PackRecordStore.transition()` contract; (2) pack routes mint bounded IDs via the T4 `_mint_request_id(<prefix>)` helper at `author_routes.py:98-108`; (3) prefixes today are `_PACK_SUBMIT_REQUEST_ID_PREFIX` / `_PACK_CANCEL_REQUEST_ID_PREFIX`, with T5 adding `_PACK_REJECT_REQUEST_ID_PREFIX`; (4) bounded length pinned at prefix + uuid hex ≤ 64 by module-foot invariant; (5) **NO middleware request-state dependency** — Round 2 P2 #7's earlier `RequestIdMiddleware` claim was wrong (Round 12 P2 #3 verified) and is explicitly retracted. |
| **R13 P3 #4** | P3 | **Incomplete R12 fix** — T12 §"Why CC-doctrine" paragraph (Round 12 P2 #2 update) mentioned the T5 `list_by_status` + T9 `evidence_attachments` extensions, but T12 watchpoint (e) "CC-source touches in 7B.1 modules" still summarised only `lifecycle.py` from T4, `storage.py` from T9, and `cli/test_harness.py` from T11. Watchpoint (e) is the closeout-checklist surface — missing T5 storage + T9 author/review carry-forward leaves the closeout completeness check blind to those touches. | Watchpoint (e) refreshed from a single-line 3-touch summary to a **numbered 6-item list** covering: (1) lifecycle.py from T4 + T9; (2) **NEW** storage.py from T5 (list_by_status); (3) storage.py from T9 (full three-kwarg surface); (4) **NEW** author_routes.py from T9 (T9 extension reuses T4 minter); (5) **NEW** review_routes.py from T9 (T5 reject carry-forward via evidence_attachments); (6) test_harness.py from T11. T12 closeout completeness check now enumerates each of the 6 touches by file path + owning task + Round-N reference. |
| **R13 P3 #5** | P3 | **Incomplete R12 fix** — Round 12 P2 #1 added sub-section (g) "Route-table collision resolution" to the T13 final reference table (now 7 sub-sections), but T13 watchpoint (e) "Final reference table completeness" still cited "all 6 sub-sections (a–f)" AND the pre-R11 ~1286-line plan size. Future closeout author would silently drop sub-section (g) thinking only (a–f) was required, AND the plan-size citation would mislead about how big the navigation map needs to cover. | Watchpoint (e) refreshed: cites **7 sub-sections (a–g)** with sub-section (g) "Route-table collision resolution" explicitly named in the closeout completeness check; plan-size citation updated to "~1500-line plan" (post-R12+R13 size) without committing to an exact line count (since R-rounds keep growing it). |

**Round 13 reviewer notes recorded for execution:**

1. **T5/T7 route-table proof split is the right scope** — R12 conflated TDD-task boundaries by asserting both routes at T5 when T7 hadn't created `inspection_routes.py` yet. Narrow T5 proof + carry-forward T7 proof preserves TDD red-test honesty per `superpowers:test-driven-development` doctrine. R-round lesson: when a regression depends on a yet-to-exist module, split the proof.
2. **All three live forecast surfaces (top CC promotions + Modify list + detailed task section) must agree** — R12 fixed only the detailed task section's kwarg surface; R13 caught the two stale forecast surfaces. Future R-round patches against `transition()` (or any multi-kwarg seam) must update ALL three surfaces in the same pass per `feedback_verify_code_citations_at_doc_write.md` — a "every cited line verified" sweep across the live forecast TLM.
3. **Prose paragraphs AND pseudocode comments are both authoritative surfaces** — R12 fixed the pseudocode but left the contradicting prose; R-round patches need to update both. The four readability tiers (Files-list summary, Wire-design prose, pseudocode, watchpoints) must all carry the same story.
4. **T12 + T13 watchpoint (e) are the closeout-checklist surfaces** — they need to enumerate every change, not just the largest ones. Future implementer reads watchpoint (e) as the "did I cite all of this?" checklist at closeout-compose time; under-enumeration silently lets touches slip past the closeout review surface.
5. **Sub-section count + plan size citations need refresh on every R-round that adds either** — R13 P3 #5 caught the (g) sub-section + ~1500-line plan-size omission. Future R-round patches that add a new sub-section to the T13 reference table OR materially grow the plan need to refresh the watchpoint (e) citation in the same pass.

---

**Round 12 (R12) — user follow-up doctrine review of Round 11 patches (3×P2 + 1×P3; all patched into plan)**

R12 surfaces newly-introduced issues + incomplete R11 fixes against the patched plan. Pre-T5 still; no code touched.

| # | Priority | Finding | Resolution |
|---|---|---|---|
| **R12 P2 #1** | P2 | **Newly surfaced** — T5 reviewer queue at `GET /api/v1/packs?status=submitted` (per ADR-012 §62 sketch) and T7 inspection list at `GET /api/v1/packs` (per ADR-012 §75) collide on the same path. FastAPI dispatches by path+method, NOT query string — whichever sub-router registers first shadows the other. R2 P3 #8 (different scopes per surface) ruled out a single-handler-with-scope-dispatch; R11 did not catch the path collision when patching tenant-isolation. | T5 reviewer queue moves to **distinct path `GET /api/v1/packs/review-queue`** (still gated by `pack.review.claim`); T7 inspection list stays at `GET /api/v1/packs` (gated by `pack.audit.read`). ADR-012 §62 sketch is impl-deviation; rationale documented in §T5 endpoint table cell + §T5 watchpoint (h) NEW. New route-table regression `test_review_queue_and_inspection_list_both_reachable` walks `app.routes`, asserts BOTH routes exist + distinct `name` + `methods` + `path` + dependency-set. Plan updated in 5 sites: §T5 endpoint table row 1 + §T5 watchpoint (e) + new §T5 watchpoint (h) + §Tests line 130 + new §T13 final reference table sub-section (g). |
| **R12 P2 #2** | P2 | **Incomplete R11 fix** — R11 P2 #3 added `evidence_attachments` to T9's "Wire design" section but T9's §"Files" `storage.py` modify still said "TWO new optional keyword-only kwargs". T9 §"Files" also omitted `portal/api/packs/review_routes.py` + `tests/unit/portal/api/packs/test_review_routes.py` despite T5 watchpoint (g) explicitly promising T9 amends the reject handler + T9 tests pin the new payload contract. R11 left half the carry-forward implicit. | T9 §"Files" `storage.py` modify bumped to **"THREE new optional keyword-only kwargs"** (explicitly including `evidence_attachments`). T9 §"Files" extended with two new "Modify" rows for `portal/api/packs/author_routes.py` (T9 conformance + manifest-digest wiring; Round 12 P2 #3 also pins the `_mint_request_id` reuse) AND `portal/api/packs/review_routes.py` (T9 reject categorised-payload write replacing structured-log-only emission; introduces `_PACK_REJECT_REQUEST_ID_PREFIX` per T4 R3 P2 #1 bounded-request-id invariant). T9 §"Tests" extended with: (1) new `test_storage_transition_payload_schema.py` assertion for `evidence_attachments` kwarg behavior on reject transitions; (2) `test_reject_persists_categorised_payload_to_chain_row_post_t9` (T5 carry-forward test rename + extension); (3) `test_reject_request_id_bounded_to_64_chars`. The T5-era `test_reject_categorised_reason_logged_only_in_t5` test renames to `test_reject_categorised_reason_logged_in_t5_and_persisted_post_t9` with explicit pre-T9/post-T9 fixture split. |
| **R12 P2 #3** | P2 | **Newly surfaced** — T9 pseudocode at L1010-1036 passed `request_id=request.state.request_id` despite T4 R3 P2 #1 already establishing `decision_history.request_id` is `String(64)` and the existing `RequestIdMiddleware` does NOT expose `request.state.request_id` today. T4 mints bounded IDs via `_mint_request_id(_PACK_SUBMIT_REQUEST_ID_PREFIX)` at `author_routes.py:98-108`; the T9 pseudocode would either (a) crash with `AttributeError` or (b) overflow the column on a longer middleware-bound ID. | T9 pseudocode rewritten: reuses the existing T4-era `_mint_request_id(_PACK_SUBMIT_REQUEST_ID_PREFIX)` minter at `author_routes.py:98-108` + the prefix constant at `:93`. T9 is a same-file extension of the T4 `submit_draft` handler — no cross-module import gymnastics. New test `test_submit_request_id_bounded_to_64_chars_after_t9` pins the runtime contract holds post-T9 extension. New "Round 12 P2 #3 invariant" subsection added to §T9 documenting the rationale. The build-time invariant at module foot (T4 R3 P2 #1) carries forward unchanged. |
| **R12 P3 #4** | P3 | **Incomplete R11 fix** — T13 §"Final reference table" sub-sections (a) (d) (e) listed pre-Round-11 vocabulary set + "New CC modules (11)" + omitted T5 storage `list_by_status` CC-ADJ touch from sub-section (e) cross-sprint CC source touches. Future implementer reading T13 would not see the Round 11 + Round 12 deltas. | T13 sub-section (a) extended from 6 to **8 closed-enum vocabularies** (added `RoleSeparationFailure` 1-value at position 6 + `RejectionReason` 7-value at position 7; OWASPCheckCategory moves to position 8); sub-section (d) bumped from "New CC modules (11)" to **"12"** with role_separation.py explicitly called out; sub-section (e) extended with **6 cross-sprint CC source touches** (added T5 storage `list_by_status` CC-ADJ + T9 `transition()` triple-kwarg extension + T9 author_routes.py extension + T9 review_routes.py reject carry-forward); new sub-section (g) added for the Round 12 P2 #1 route-collision resolution. |

**Round 12 reviewer notes recorded for execution:**

1. **Distinct path for reviewer queue at `GET /api/v1/packs/review-queue` is the right call** — single-handler-with-scope-dispatch was ruled out by R2 P3 #8 (different scopes per surface); distinct paths keep RBAC + tenant + scope-set rules orthogonal per the four-axis enforcement design (scope / tenant / actor-type / role-separation).
2. **T9 must consistently own the third kwarg `evidence_attachments`** — R11 added it to the Wire design narrative but left T9 §"Files" + §"Tests" listing 2 kwargs; this kind of partial-application is exactly the gap that R12 P2 #2 surfaced. Future R-rounds should always verify the §"Files" + §"Tests" parity against the §"Wire design" claim within the same compose pass per `feedback_verify_code_citations_at_doc_write.md`.
3. **Reuse the existing T4 `_mint_request_id` minter** — keeps the bounded-request-id invariant single-source-of-truth at `author_routes.py:98-108`. The T4 build-time invariant at module foot pins the cap; the T9 runtime test re-verifies post-extension. No middleware request-state plumbing added.
4. **T13 final reference table refreshed cross-round** — vocabularies + CC modules + CC source touches all reflect the cumulative R11 + R12 patches. Future implementer reads T13 as the authoritative navigation map per R8 reviewer-answer #5.

---

**Round 11 reviewer notes recorded for execution:**

1. **CC-ADJ for storage at T5 in addition to T9 is the right call** — `list_by_status` is a pure read; no Doctrine Lock D touch; the existing `ix_packs_tenant_state` index was built exactly for this query shape per migration L129. T5 halt-before-commit summary must explicitly cite that no chain-row interaction occurs and the row-locked transition path is untouched.
2. **7-value `RejectionReason` vocabulary anchored to ADR-012 §41 5-gate composition** — user accepted; vocabulary mirrors the gate-categories the future T7B.3 composer will refuse on, plus 2 operational categories + free-form fallback. `comments` required when `reason == "other"` enforces the "free-form fallback IS the diagnostic" contract.
3. **T5 ships reject as bare-transition + structured-log; T9 wires the chain-payload migration via `evidence_attachments`** — generic kwarg shape on T9's `transition()` extension keeps the storage seam stable for future transitions (e.g. approve attachments in 7B.3). The two-phase rollout means examiners reading pre-T9 chain rows see only the bare transition; post-T9 chain rows carry categorised payload.
4. **`portal/rbac/role_separation.py` is a NEW critical-controls module, not an `enforcement.py` / `tenant_isolation.py` extension** — keeping the four orthogonal enforcement axes (scope membership / tenant boundary / actor-type / role-separation) in separate modules mirrors the Sprint-7B.2 T2 design choice that put tenant-isolation in its own module rather than extending `RBACDenialReason`. Same precedent applies here.
5. **4-axis approve fail-loud test matrix forces dependency ordering** — each axis exercises a different short-circuit path; the matrix's ordering is the wire-protocol-public contract for "what does a forbidden-vs-not-yet-implemented approve look like on the wire?" The 503 path NEVER reaches an audit-chain emission (no state transition occurs), so the chain-row-count assertion is the deterministic green-path-skipping proof.

---

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
