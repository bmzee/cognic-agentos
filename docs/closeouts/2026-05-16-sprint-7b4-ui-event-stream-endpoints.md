# Sprint 7B.4 — UI Event-Stream Endpoints + RBAC Denial Chain Events (per ADR-020) — Closeout Note

**Date:** 2026-05-16
**Sprints closed:** 7B.4 (3 SSE GET endpoints + POST /actions + portable JSON schema + submit_elicitation 5-step gate + `policy.rbac_denied` chain events promotion + `UIEventBroker` primitive + deterministic chain-derived event_id cursor + `ElicitationAdapter` Protocol + `elicitation.rego` stop-rule + `UIRBACScope` 8-value peer Literal + 5 new closed-enum vocabularies + 3 CC promotions).
**State:** READY-FOR-GATE on `feat/sprint-7b4-ui-event-stream-endpoints`. No push, no PR, no merge until explicit user authorization.
**Pre-T14 tip:** `04d680e` (T13 commit).
**Stack base:** `c53de7a` on `main` — Sprint 7B.3 PR #24. 7B.4 branches directly off merged main (not stacked).
**14 Sprint-7B.4 commits after T14 lands** atop `c53de7a`: T1 design spec (`6762cbc`), T2 plan-of-record (`3424ecf`), T3 protocol foundation (`32bd852`), T4 UIEventBroker primitive (`34c7779`), T5 UIRBACScope (`d36bb30`), T6 async RBAC + middleware + broker wiring (`ddcb9c9`), T7 ElicitationAdapter Protocol (`292bb84`), T8 elicitation.rego + elicitation_gate (`3fce364`), T9 dto.py (`69bd4ac`), T10 stream_routes.py (`a7d518b`), T11 action_routes.py (`3d70e90`), T12 well_known + router + create_app (`6eccf9b`), T13 AGENTS.md + gate 60→63 + AST regressions (`04d680e`), T14 closeout (this commit).

## What ships in `feat/sprint-7b4-ui-event-stream-endpoints` after Sprint 7B.4

### UI event-stream protocol primitive extensions (Sprint-7B.4 T3 + T4)
- `protocol/ui_events.py` extensions: 16-byte chain cursor encoder/decoder (`_chain_derived_event_id` + `_decode_chain_cursor` + `CursorMalformed` + `CursorChainUnsupported`); `RBACDenialType` 9-value protocol-owned Literal; `_SSE_WAVE_1_STREAMED_FAMILIES` 9-value Final (Wave-1 audit-event-backed families `tool_call.*` + `artifact.*` deliberately excluded — Wave-2 audit-event SSE surface); `AppendResult` frozen + slotted dataclass; `UIEventBroker` FastAPI-free in-memory pub/sub primitive; `_PENDING_TYPED_EVENT_ID` task-scoped ContextVar bridging typed-projector emission to broker's `append_*` return; 4-entry `_DECISION_HISTORY_TYPED_PROJECTORS` table + `_project_policy_rbac_denied` rbac-prefix projector; `PolicyRBACDenied` event class.

### Replay-side snapshot type (Sprint-7B.4 T10)
- `protocol/ui_events.py` `_DHReplaySnapshot` frozen dataclass: 9-field structural mirror of `AppendedDecisionSnapshot` for the SSE replay path; module-private; consumed by typed projectors via `cast(AppendedDecisionSnapshot, ...)`. Drift between dataclass fields + projector access surface pinned by 4 structural regressions + 26 parametrized runtime drives in `tests/unit/protocol/test_ui_events_dh_replay_snapshot.py`.

### ElicitationAdapter Protocol (Sprint-7B.4 T7)
- `protocol/elicitation_adapter.py`: narrow `@runtime_checkable` Protocol + `ElicitationContext` (7-field frozen dataclass) + `ElicitationResult` + `ElicitationBackendError` + `KernelDefaultElicitationAdapter` fail-loud scaffold (`NotImplementedError` pointing at ADR-020 §69-77 per the production-grade rule — no silent in-process fallback).

### 5-step elicitation policy boundary (Sprint-7B.4 T8)
- `policies/_default/elicitation.rego`: Rego v1 default-deny bundle at `data.cognic.ui.elicitation_submit.allow`; stop-rule artifact per ADR-015 + ADR-020 §69-77.
- `portal/api/ui/elicitation_gate.py`: pure-async `evaluate_elicitation_submission(...) -> GateOutcome` 5-step gate (adapter wired → ctx lookup → mode parity → restricted-data-class → Rego eval); 10-value `ActionRejectionReason` Literal; 3-value `_RESTRICTED_DATA_CLASSES` frozenset (three-way lockstep with the Rego bundle + `protocol/mcp_capabilities._RESTRICTED_DATA_CLASSES` via test-only drift detector per the `feedback_drift_detector_test_only_no_runtime_import` user-locked doctrine). On the durable critical-controls gate from T13.

### Action POST surface (Sprint-7B.4 T9 + T11)
- `portal/api/ui/dto.py`: 6-class Pydantic v2 discriminated-union DTOs (`ApproveActionRequest` / `DenyActionRequest` / `CancelRunActionRequest` / `InterruptActionRequest` / `ResumeActionRequest` / `SubmitElicitationActionRequest`); 6-value `ActionClass` + 2-value `ActionOutcome` + 10-value `ActionRejectionReason` Literals; `ActionResponse` per spec §4.4a; frozen `UIActionContext` dataclass; `SubmitElicitationActionRequest.@model_validator(mode="after")` enforces exact mode/payload parity at parse time (422 before any chain row appended). Pure type-only — off-gate.
- `portal/api/ui/action_routes.py`: `RequireUIAction(broker)` closure-factory dep (P1 #2 — lives here, NOT in dto.py); 7-step pipeline (dep → submitted append → per-class dispatch → outcome append → typed projection → response); 5 stub paths (approve/deny → `action_backend_deferred_to_sprint_13_5`; cancel_run/interrupt → `action_backend_deferred_no_run_primitive`; resume → `action_backend_deferred_sandbox_unwired`); submit_elicitation routes through T8 gate + `adapter.handle_submission` (green → `frontend_action.accepted`; exception → `frontend_action.rejected` with `elicitation_backend_failed`); deterministic `submitted_event_id` + `resolution_event_id` cursors; T7 forward watchpoint honored (no isinstance on `@runtime_checkable` ElicitationAdapter). On the durable critical-controls gate from T13.

### SSE transport (Sprint-7B.4 T10)
- `portal/api/ui/stream_routes.py`: 3 SSE GET endpoints (`/runs/{run_id}/events` + `/tenants/{tenant_id}/events` + `/events/since/{event_id}`); 4-value `CursorRefusalReason` Literal (cursor_malformed / cursor_chain_unsupported / cursor_not_found / cursor_projection_drift_detected — `cursor_tenant_mismatch` deliberately NOT in vocab per cross-tenant-invisible doctrine); 1-value `FamilyFilterRefusalReason`; Last-Event-ID header WINS over URL cursor; malformed fails closed 422 (no silent fall-back); cross-tenant cursor returns 404 `pack_not_found` (cross-tenant invisible); type_hash drift detection runs PRE-STREAM in `_validate_cursor_tenant` so the 500 reaches the client cleanly; broker/generator-owned heartbeat at `ui_event_stream_heartbeat_interval_s` (sse-starlette internal ping set to 86400s sentinel); send_timeout half-open client cleanup; per-tenant 429 `tenant_connection_cap_exceeded`. Closure-captures `broker` + `settings` + `decision_history_store` (T10 plan-vs-reality drift #1 — `create_app` populates `app.state.decision_history_store` but NOT `app.state.settings`). On the durable critical-controls gate from T13.

### Schema publication (Sprint-7B.4 T12)
- `portal/api/ui/well_known_routes.py`: public unauth `GET /.well-known/cognic-ui-events.json` (RFC 8615 root-mount); `schema_version: "1.0"`; sorted `families` + `wave_1_sse_streamed`; per-family JSON Schema via `pydantic.TypeAdapter(union).json_schema()` over the 11 Wave-1 family discriminated unions; `Cache-Control: public, max-age=300, immutable`; 38KB committed snapshot pinned by drift regression at `tests/unit/portal/api/ui/well_known_schema_snapshot.json`.
- `portal/api/ui/router.py`: `build_ui_routes(broker, settings, decision_history_store, elicitation_adapter, rego_engine)` composition factory under `/api/v1/ui`.
- `portal/api/app.py` CC-ADJ extension: 3 new optional `create_app` kwargs (`broker` injection seam + `elicitation_adapter` + `rego_engine`); broker construction respects pre-injected `broker=` (test-fixture seam) OR auto-builds from T6 deps; UI router auto-mount + .well-known root-registration gated on `portal_broker is not None`; pack-only callers unchanged (R3 #3 backward-compat invariant pinned by `TestCreateAppPackOnlyDeploymentStillWorks`).

### RBAC denial dual-surface emission (Sprint-7B.4 T6)
- `portal/rbac/enforcement.py` (already on gate from 7B.2): added `_emit_denial_or_500` dual-surface helper (log FIRST, broker chain row SECOND, fail-closed 500 `rbac_denial_emit_failed` on broker exception); async `_bind_actor` wrapper around sync `ActorBinder.bind` (P1 #4 — sync binder Protocol contract preserved); plus `tenant_isolation.py` + `human_actor.py` + `role_separation.py` route into the same helper.
- `portal/rbac/scopes.py`: NEW 8-value `UIRBACScope` peer Literal (`ui.run_stream` + `ui.tenant_stream` + 6 × `ui.action.<class>`).
- `portal/rbac/actor.py`: `Actor.scopes` widened to `frozenset[PackRBACScope | UIRBACScope]`.

### Settings (Sprint-7B.4 T4)
- `core/config.py`: 5 new UI-stream Settings fields with documented defaults (`ui_event_stream_per_tenant_cap=50`, `ui_event_stream_queue_maxsize=1000`, `ui_event_stream_idle_timeout_s=90`, `ui_event_stream_heartbeat_interval_s=15`, `ui_event_stream_send_timeout_s=30`).

### Critical-controls gate uplift (Sprint-7B.4 T13)
- `tools/check_critical_coverage.py`: +3 entries (`portal/api/ui/action_routes.py` + `stream_routes.py` + `elicitation_gate.py` at the canonical 95%/90% floor); gate inventory **60 → 63 modules**; new "Sprint 7B.4 — UI event-stream endpoints" docstring section block.
- `AGENTS.md`: NEW "Authoring — UI event-stream (Sprint 7B.4)" subsection + 3 new "Stop rules" policy-bundle entries (`policies/_default/sampling.rego` + `supply_chain.rego` + `elicitation.rego`).

### AST architectural-arrow regressions (Sprint-7B.4 T13)
- `tests/architecture/test_ui_architectural_arrow.py`: 6 AST-walk invariants + 1 runtime cross-check (8 test methods after parametrization). (1) protocol/ui_events.py no FastAPI/portal imports; (2) elicitation_adapter.py no portal/mcp_host; (3) elicitation_gate.py no HTTPException + no mcp_host (pure-functional gate); (4) action_routes.py blocks DH-append-seam under all 3 import shapes (R5 P1 #1 — bare-import / submodule-import / symbol-import all forbidden via module-level block); (5) FastAPI route modules don't carry `from __future__ import annotations` (AST detection, not substring — docstring NOTEs don't false-positive); (6) per-type projector set DERIVED from live `_DECISION_HISTORY_TYPED_PROJECTORS` dispatcher dict + rbac-prefix (R4 P1 #2 — no hand-maintained constant) + every projector passes `event_id=_chain_derived_event_id(chain_id="decision_history", ordinal=0, ...)` as Constants (R4 P1 #3) + bidirectional source-vs-dispatcher sentinel catches dead-code projectors; (6b) runtime cross-validation by re-projection + recomputed event_id equality (R5 P1 #2 — catches wrong `family=` / `type_=` arguments to `_chain_derived_event_id`).

### Closeout + BUILD_PLAN §602 (Sprint-7B.4 T14 — this commit)
- `docs/closeouts/2026-05-16-sprint-7b4-ui-event-stream-endpoints.md` (NEW): this note.
- `docs/BUILD_PLAN.md` §602: 7B.4 CLOSED status row; Sprint 7B closed in aggregate (all 4 sub-sprints shipped).

## CI / production-grade gates

| Gate | Workflow | Trigger | Behaviour |
|---|---|---|---|
| Lint + types + tests | `python.yml` → `lint + test` | push / PR | unchanged — `ruff` + `ruff format --check` + `mypy` strict + `pytest -v` |
| Per-file critical-controls coverage gate | `python.yml` → `lint + test` | push / PR | `tools/check_critical_coverage.py` against `coverage.json` — fails CI if any of the **63** critical-controls modules drops below 95% line OR 90% branch (extended in Sprint-7B.4 T13 by 3: T11 `portal/api/ui/action_routes.py`; T10 `portal/api/ui/stream_routes.py`; T8 `portal/api/ui/elicitation_gate.py`). T13 added a `_SPRINT_7B4_GATE_MODULES` + `_SPRINT_7B4_OFF_GATE_MODULES` count-guard self-test pinning the entry count + the 3 7B.4 promoted modules + the 4 off-gate carve-outs. |
| MCP / A2A / image-size budget gates | `python.yml` | push / PR | unchanged — Sprint-5/6 floors stay |
| Live Postgres / Oracle integration | `python.yml` | push / PR | unchanged — Sprint-7B.1 canaries unchanged; Sprint-7B.4 ships no new integration tests (UI surface exercised at unit scope via uvicorn-in-loop for streaming + ASGITransport for refusals) |
| Architecture-arrow AST regressions | `python.yml` → `lint + test` | push / PR | NEW — `tests/architecture/test_ui_architectural_arrow.py` enforces 6 layer-isolation invariants + 1 runtime event_id recompute cross-check |

## Doctrine adherence

- **AGENTS.md per-edit halt-before-commit on critical-controls modules.** Every CC + CC-ADJ commit paused for explicit user authorization. T3 (cursor encoder + RBACDenialType + AppendResult — halt-reviewed). T4 (UIEventBroker primitive + ContextVar capture + typed projectors + Settings fields — halt-reviewed). T5 (UIRBACScope + Actor.scopes union widening — halt-reviewed). T6 (broker wiring + request-id middleware + async RBAC + dual-surface emission — halt-reviewed). T8 (elicitation.rego + elicitation_gate.py CC + stop-rule — halt-reviewed across R0 + R1). T10 (stream_routes.py CC across R0 + R1 + R2 — 4 plan-vs-reality drifts patched + 5 root-cause discoveries + uvicorn `AppStatus` cross-test leak fixed + ASGITransport-buffer-can't-stream limitation found + Hybrid test-strategy doctrine established). T11 (action_routes.py CC across R0 + R1 + R3 — 2 P1 + 1 P2 reviewer findings addressed). T12 (create_app CC-ADJ via the broker= injection seam — halt-reviewed). T13 (AGENTS.md doctrine + coverage gate tool + AST architectural-arrow regressions — halt-reviewed across R3 + R4 + R5; 5 P1s + 2 P2s closed).
- **AGENTS.md `core/canonical.py` per-edit stop rule.** Not touched in Sprint 7B.4. The 4 broker `append_*` seams' `_payload_digest` SHA-256 implementation calls `canonical_bytes(body.model_dump(mode="json"))` from `core/canonical` unchanged.
- **Closed-enum vocabulary doctrine.** Sprint-7B.4 added **5 new closed-enum vocabularies** (`ActionClass` 6-value + `ActionOutcome` 2-value + `ActionRejectionReason` 10-value + `CursorRefusalReason` 4-value + `FamilyFilterRefusalReason` 1-value) + extended 2 cross-sprint ones (`UIRBACScope` peer-Literal of `PackRBACScope` at 8 new values; `RBACDenialType` 9-value protocol-owned union backing the existing `portal/rbac` 4-value union via the AGENTS.md stop rule). The cross-module drift between `dto.py::ActionRejectionReason` + `elicitation_gate.py::ActionRejectionReason` is pinned by a test-only equality regression (no runtime cross-module import per `feedback_drift_detector_test_only_no_runtime_import`).
- **Production-grade rule.** Every Sprint-7B.4 module ships real integrations: `UIEventBroker` uses the real `DecisionHistoryStore.append` Postgres-backed primitive (no in-process synthetic chain); the elicitation gate calls a real `OPAEngine.evaluate()` against the real `elicitation.rego` bundle (the unit-test layer uses `AsyncMock(OPAEngine)` per the layered-test pattern; `tests/unit/policies/test_elicitation_rego.py` shells out to the real `opa` binary when present); `KernelDefaultElicitationAdapter` is a fail-loud `NotImplementedError` scaffold (no silent in-process fallback); the SSE transport opens real TCP sockets in the uvicorn-fixture-driven tests (per the user-locked Hybrid doctrine — ASGITransport buffers full-body responses and can't stream, so streaming tests run against real uvicorn on a free localhost port).
- **Hybrid SSE test-strategy doctrine (T10 user-locked, 2026-05-16).** httpx 0.28.1's `ASGITransport.handle_async_request` accumulates `body_parts: list = []` and only returns after `more_body=False`, so it cannot stream infinite SSE responses + cannot propagate `http.disconnect`. Split: ASGITransport for the 7 refusal tests that return synchronously (RBAC 403, cross-tenant 404, malformed-cursor 422, etc.); uvicorn-in-loop for the 13 streaming tests (real TCP, real heartbeat, real cap enforcement, real disconnect propagation); direct-broker for 2 supplemental tests (`reap_idle`, `last_activity_at`). Threading-based uvicorn was rejected because the SQLAlchemy AsyncEngine bound to pytest's loop cannot be safely read from a uvicorn-thread loop (cross-loop aiosqlite usage); `AppStatus.should_exit` class-level state must be reset at fixture entry (R0 root-cause: the 2nd uvicorn invocation per pytest process saw `should_exit=True` from the previous test's teardown and the exit-signal-listener returned immediately, cancelling the streaming task group → 200 OK + empty body).
- **T7/T8 forward watchpoint preserved.** `@runtime_checkable` Protocol's `isinstance` check covers method-presence ONLY (not signature/asyncness). The action handler does NOT isinstance-check the `ElicitationAdapter`; authoritative shape check is at the `await adapter.handle_submission(...)` call site (TypeError/AttributeError translate to `elicitation_backend_failed`). Honored across T11 + T12.
- **Append-seam centralisation doctrine.** All chain writes from the UI surface go through `UIEventBroker.append_frontend_action_{submitted,accepted,rejected}` + `broker.emit_rbac_denial`. Route handlers NEVER construct `DecisionRecord` instances OR call `DecisionHistoryStore.append` directly. Enforced by AST regression invariant 4 (blocks all 3 import shapes of `cognic_agentos.core.decision_history` from `action_routes.py`).
- **Doctrine F gate-counting rule.** Critical-controls floor extension at T13 adds 3 modules to the 95/90 floor. Modules deliberately OFF the gate carry documented rationale in `tools/check_critical_coverage.py`'s 7B.4 docstring section + the test-file off-gate set: `dto.py` (pure type-only DTOs — Pydantic parse + static types catch drift; same precedent as `portal/api/packs/dto.py`); `router.py` (composition factory — carrier file only); `well_known_routes.py` (schema publication — load-bearing regression is the snapshot-pinned drift test, not coverage); `protocol/elicitation_adapter.py` (pure type-contract module; runtime invariants enforced at the on-floor `elicitation_gate.py` call site).
- **Cite-from-source-at-doc-write-time depth doctrine.** Continued from 7B.2 + 7B.3's `feedback_verify_code_citations_at_doc_write.md`. T13's AGENTS.md 7B.4 subsection + this closeout had every code citation (closed-enum value counts, file:line locations, function signatures, commit hashes, suite counts) verified at file:line via `Read` / `grep` in the same compose pass.

## New doctrines established Sprint-7B.4

- **ContextVar-based broker append seam.** `_PENDING_TYPED_EVENT_ID` task-scoped ContextVar bridges typed-projector emission (during the awaited `DecisionHistoryStore.append`) back to the broker's `append_*` return. The broker's `_fanout_hook` calls `_PENDING_TYPED_EVENT_ID.set(event.event_id)` synchronously inside the awaited DH-store append; the `_append` method reads the ContextVar after the await returns and packages it into `AppendResult(event_id=...)`. This lets the action handler reference the row's deterministic event_id without `core/decision_history` knowing anything about the UI event-stream surface (no portal arrow into core).
- **Wave-1 SSE = decision-history-only.** Audit-event-backed event families (`tool_call.*` + `artifact.*`) reach the UI emitter but are filtered out at the broker before SSE fan-out per the `_SSE_WAVE_1_STREAMED_FAMILIES` 9-value Final set. Those families ship via the Wave-2 audit-event SSE surface (deferred). The closed-enum + the in-broker filter + the .well-known snapshot all agree on the 9-family streamed subset.
- **Cursor type_hash drift detection runs PRE-STREAM.** Raising `HTTPException` from inside the SSE body generator after `http.response.start` has been sent leaves clients with a broken stream + opaque connection drop (the 500 status never reaches them). T10 R0 discovery: the drift check MUST live in `_validate_cursor_tenant` (route-handler body) so the 500 fires before `EventSourceResponse` opens. AST invariant 3 enforces the corollary: `elicitation_gate.py` never references `HTTPException` either — the gate is pure-functional + returns `GateOutcome`, and HTTP mapping happens at the call site.
- **Mode parity check is bidirectional.** The T8 gate's Step 3 enforces `request.mode in ctx.elicitation_modes` AND `ctx.elicitation_modes` covers `request.mode`. Pinned by `feedback_strict_review_off_gate` precedent — single-direction parity allows a downgrade (request for `form` while adapter only supports `url`) to silently degrade to the available mode.
- **Two-IDs-per-pack-POST contract.** Middleware mints `portal-req-<uuid4.hex>` (43 chars; T6) onto `request.state.request_id` for every `/api/v1/*` path so the RBAC denial helpers always have a stable correlation id; the action handler also surfaces this in the response body's `request_id` field. Per-verb handler request-id prefixes (Sprint-7B.2 precedent) STAY on pack routes; UI routes use the middleware-minted id directly.
- **`@runtime_checkable` Protocol isinstance is NOT a complete bootstrap validator.** Documented in T7 + carried forward through T8/T11. Bank overlays implementing `ElicitationAdapter` get duck-typed at the `await adapter.handle_submission(...)` call site; the authoritative shape check is the actual call (TypeError/AttributeError translate to `elicitation_backend_failed`). isinstance against the runtime_checkable Protocol covers method-presence only, not signature/asyncness.
- **Test-only drift detector with NO runtime cross-module import.** `dto.py::ActionRejectionReason` and `elicitation_gate.py::ActionRejectionReason` are parallel 10-value Literals; equality enforced by a test-only `get_args` comparison (no runtime cross-module import). Saved as `feedback_drift_detector_test_only_no_runtime_import.md` per the user's architectural-arrow lock; also applied to the `gate ↔ Rego bundle ↔ mcp_capabilities` three-way restricted-data-class lockstep.
- **AST regression with bidirectional sentinel + runtime cross-check.** T13 R4 + R5 established the pattern: AST-walk pins static drift (e.g. `event_id=_chain_derived_event_id(...)` as a Call to that specific helper, with `chain_id="decision_history"` + `ordinal=0` as Constants); runtime cross-check pins semantic correctness the AST cannot reach (each projector produces an event whose `event_id` MUST equal `_chain_derived_event_id(...)` recomputed from the projected event's own `family` + `type` Literals). Bidirectional sentinels between source defs + production dispatcher dict catch dead-code projectors + missing wiring symmetrically.
- **Hybrid SSE test strategy (covered above under "Doctrine adherence").** User-locked 2026-05-16; codified in `tests/unit/portal/api/ui/sse_test_helpers.py` docstrings + the `uvicorn_app_factory` conftest fixture.
- **Snapshot-pinned schema drift detector for wire-protocol-public Pydantic schemas.** T12 ships `/.well-known/cognic-ui-events.json` + a committed 38KB snapshot at `tests/unit/portal/api/ui/well_known_schema_snapshot.json`. Any Pydantic-model change that affects the serialized JSON Schema fails `TestSchemaSnapshotPinned` with an actionable regenerate-via-`rm <path>` message. Same precedent as the 7B.2 `conformance_matrix.json` static schema.

## Test + coverage state

- **Suite size:** **6031 passed / 55 skipped / 651.32s** at the T14 pre-commit baseline (run at HEAD `04d680e` + the T14 R0 coverage-repair extension, sourced from the full `uv run pytest --cov` run). Delta from the Sprint-7B.3 baseline (5744 passed / 48 skipped): **+287 passed / +7 skipped** — driven by the Sprint-7B.4 T3-T12 unit coverage of the new event-stream surface (protocol primitives + broker + cursor + elicitation gate + DTOs + action routes + stream routes + well-known + create_app wiring + Hybrid SSE test pattern), T13's architectural-arrow AST regressions + gate self-tests, T13 R5's runtime event_id recompute cross-check, and T14 R0's 8 coverage-repair branch tests on `stream_routes.py`.
- **Per-file critical-controls coverage gate (63 modules at 95/90):** `tools/check_critical_coverage.py` against the fresh `coverage.json` — **gate passed**; all 60 pre-Sprint-7B.4 modules unchanged + 3 Sprint-7B.4 promotions, each at 100% line / 100% branch:

| Module | Sprint owner | Line% | Branch% | Status |
|---|---|---|---|---|
| (60 modules unchanged from `2026-05-15-sprint-7b3-reviewer-evidence-panels-5-gate.md`) | up to 7B.3 | ≥95 | ≥90 | PASS |
| `portal/api/ui/action_routes.py` | 7B.4 T11 | 100.00 | 100.00 | PASS |
| `portal/api/ui/stream_routes.py` | 7B.4 T10 | 100.00 | 100.00 | PASS |
| `portal/api/ui/elicitation_gate.py` | 7B.4 T8 | 100.00 | 100.00 | PASS |

**T14 R0 coverage repair (post-T13 finding):** the T13 critical-controls promotion of `portal/api/ui/stream_routes.py` was made before the coverage repair landed; the initial post-T13 gate run showed `stream_routes.py` at 91.71% line / 82.50% branch — below the 95/90 floor. User-locked verdict (`feedback_strict_review_off_gate` precedent): the module IS correctly classified CC (SSE resume / cursor refusal / cross-tenant invisibility / replay filtering / heartbeat are all wire/security behavior); coverage gap is test-suite incompleteness, NOT off-gate justification. T14 R0 added 8 focused tests at `tests/unit/portal/api/ui/test_stream_routes_coverage_branches.py` covering the 8 uncovered lines + 7 uncovered branches: `CursorChainUnsupported` 422 (Wave-2 reserved chain_disc=0x02); `run_stream` cursor validation via `Last-Event-ID` (run_stream has no `?since=`); type_hash drift via projector-swap (the other-than-`boundary is None` drift path); 4 replay-loop `continue` paths (subscriber `run_id_filter` mismatch; subscriber `family_filter` mismatch; `decision_audit` mirror with wrong `chain_id`; family not in `_SSE_WAVE_1_STREAMED_FAMILIES`); dispatcher returns `None` for unrecognised `decision_type` during replay (`policy.bundle_loaded`). Each test names the production branch it covers + the doctrine that branch implements. Post-repair: 100% line / 100% branch.

## ADR validation

| ADR | Title | Sprint-7B.4 relevance | Status |
|---|---|---|---|
| ADR-002 | MCP plugin protocol | The 4-value `CursorRefusalReason` Literal + the 16-byte chain-cursor `chain_disc=0x01` byte slot honor the existing MCP wire-format contract; `chain_disc=0x02` is reserved for the Wave-2 audit-event SSE chain (refuses fail-closed via `CursorChainUnsupported`) | ✅ |
| ADR-006 | ISO 42001 control mapping | RBAC denial chain events tagged `A.5.31` via the existing `decision_history` rows; chain-derived `event_id` is wire-protocol-public for evidence-pack export | ✅ |
| ADR-014 | Runtime tool approval / risk tiers | T11 `_STUB_REASONS` map ties approve/deny to the deferred-to-Sprint-13.5 approval-engine primitive per ADR-014; submit_elicitation routes through the runtime gate today | ✅ (stub for approve/deny) |
| ADR-015 | Policy-as-code | `elicitation.rego` bundle at `data.cognic.ui.elicitation_submit.allow` is the Step 5 Rego decision-point for submit_elicitation; default `allow := false`; URL-mode always-allow + form-mode-restricted-data-class refusal | ✅ |
| ADR-017 | Data governance contracts | The T8 gate's Step 4 restricted-data-class intersection + the Rego bundle's `restricted_classes` set + `protocol/mcp_capabilities._RESTRICTED_DATA_CLASSES` form a three-way lockstep pinned by a test-only drift detector | ✅ |
| ADR-020 | UI event-stream contract | Full Sprint-7B.4 scope: 3 SSE GET endpoints + POST /actions + `.well-known` schema publication + 11-family Wave-1 typed-event taxonomy + 9-family SSE-streamed subset + cursor-based reconnect + per-tenant connection cap + RBAC denial chain events promotion | ✅ |

## Final reference table (navigation map)

(a) **5 new closed-enum vocabularies + 2 extended cross-sprint:**

| Vocabulary | Module:line | Values |
|---|---|---|
| `ActionClass` | `portal/api/ui/dto.py:51` | `approve` / `deny` / `cancel_run` / `interrupt` / `resume` / `submit_elicitation` |
| `ActionOutcome` | `portal/api/ui/dto.py:64` | `accepted` / `rejected` |
| `ActionRejectionReason` | `portal/api/ui/dto.py:95` + `portal/api/ui/elicitation_gate.py:109` (parallel, test-pinned lockstep) | 10 values: 4 `action_backend_deferred_*` + 6 `elicitation_*` |
| `CursorRefusalReason` | `portal/api/ui/stream_routes.py:103` | `cursor_malformed` / `cursor_chain_unsupported` / `cursor_not_found` / `cursor_projection_drift_detected` (4 — `cursor_tenant_mismatch` excluded per cross-tenant-invisible doctrine) |
| `FamilyFilterRefusalReason` | `portal/api/ui/stream_routes.py:112` | `family_filter_unknown` |
| `UIRBACScope` (NEW peer-Literal) | `portal/rbac/scopes.py:90` | 8 values: 2 stream (`ui.run_stream` / `ui.tenant_stream`) + 6 action (`ui.action.{approve,deny,cancel_run,interrupt,resume,submit_elicitation}`) |
| `RBACDenialType` (extended) | `protocol/ui_events.py:189` | 9 values (existing 4-portal + 5 protocol-owned additions for the UI-event-stream surface) |

(b) **Sweeps / extensions:**
- `Actor.scopes` widened to `frozenset[PackRBACScope | UIRBACScope]` (T5).
- `core/config.py` +5 UI-stream Settings fields (T4).
- `portal/rbac/{enforcement, tenant_isolation, human_actor, role_separation}.py` async sync→async conversion + dual-surface emit via `_emit_denial_or_500` (T6).
- `create_app` +3 optional kwargs (`broker` injection seam + `elicitation_adapter` + `rego_engine`) (T12).
- Request-id middleware on `/api/v1/*` paths (T6).

(c-d) **3 new CC modules (T13 promotions) + 4 off-gate carve-outs:**

| Module | Promotion task | Owner sprint | On-gate? | Rationale |
|---|---|---|---|---|
| `portal/api/ui/action_routes.py` | T13 | 7B.4 T11 | YES | Wire-protocol-public POST /actions surface |
| `portal/api/ui/stream_routes.py` | T13 | 7B.4 T10 | YES | Reconnect-safe SSE transport |
| `portal/api/ui/elicitation_gate.py` | T13 | 7B.4 T8 | YES | Substantive policy boundary |
| `portal/api/ui/dto.py` | n/a | 7B.4 T9 | NO | Pure type-only DTOs; Pydantic parse + static types catch drift |
| `portal/api/ui/router.py` | n/a | 7B.4 T12 | NO | Composition factory — carrier file only |
| `portal/api/ui/well_known_routes.py` | n/a | 7B.4 T12 | NO | Schema publication — load-bearing regression is the snapshot-pinned drift test |
| `protocol/elicitation_adapter.py` | n/a | 7B.4 T7 | NO | Pure type-contract module; runtime invariants enforced at the on-floor `elicitation_gate.py` call site |

(e) **Cross-sprint touches:**
- `portal/api/app.py` (CC-ADJ — T6 + T12 extensions).
- `portal/rbac/{actor, enforcement, scopes, tenant_isolation, human_actor, role_separation}.py` (T5 + T6).
- `core/config.py` (T4 — 5 UI-stream Settings fields).
- `protocol/ui_events.py` (T3 + T4 + T10 extensions to the Sprint-6 module already on the gate via the ADR-020 stop rule).

(f) **Deferred items (10 from spec §9):**
- Wave-2 audit-event SSE surface (the `chain_disc=0x02` byte slot in cursors is reserved for it).
- `tool_call.*` + `artifact.*` event-family runtime emission paths (the Pydantic models ship at Sprint-6; SSE fan-out is Wave-2).
- Frontend-action `cancel_run` / `interrupt` / `resume` backend wiring (Sprint-11.5 agent_run primitive + Sprint-8 sandbox resume primitive).
- `approve` / `deny` backend dispatch (Sprint-13.5 approval-engine primitive per ADR-014).
- Real `OPAEngine` wiring in `create_app` production path (currently injected only via test fixtures; the bank-overlay launcher wires it).
- Real `ElicitationAdapter` implementation (bank overlays implement the Protocol; kernel ships only `KernelDefaultElicitationAdapter` fail-loud scaffold).
- `PolicyBundleLoaded` typed projector wiring (the Pydantic model + the `policy.bundle_loaded` decision_type ship at Sprint-4; T4 typed-projector dispatch dict doesn't yet include it).
- Tenant data-governance policy store (the elicitation gate's restricted-data-class set is kernel-global; per-tenant policy override is bank-overlay).
- Real `TrustRootResolver` implementation (Sprint-7B.3 carry-forward; kernel ships only the fail-loud scaffold).
- Studio UI authoring (ADR-008 Phase B; explicitly deferred per ADR-008 + ADR-021 reservation).

(g) **R-rounds across Sprint-7B.4:**

| Task | Rounds | Findings closed | Notable doctrine |
|---|---|---|---|
| T2 plan-of-record | R1-R6 (23 findings) | drift across spec details | doctrine for 4-fixture Hybrid app pattern + decision_history `event_type` not `decision_type` column-name |
| T6 broker wiring | R1-R3 | dual-surface emit-failure fail-closed; sync binder Protocol | `_emit_denial_or_500` shared helper |
| T8 gate | R0-R1 | adapter→ctx→mode→data→Rego step ordering + 10-value Literal | three-way restricted-data-class lockstep doctrine |
| T9 dto | R1 | exact-set Literal pin + scope-lock AST regression | cross-module Literal equality test-only |
| T10 stream | R0-R2 | drift × 4 + uvicorn AppStatus root-cause + ASGITransport-buffer + Hybrid doctrine + DH-replay snapshot regression strengthening | Hybrid SSE test strategy user-locked |
| T11 action | R1 + R3 | P2 outcome typing + P1 green-path + backend-exception coverage | parametrized runtime smoke over live dispatcher dict |
| T12 wiring | (clean review) | n/a | broker= injection seam + auto-mount gate |
| T13 doctrine | R3-R5 (5 P1s + 2 P2s) | symbol-pair check + derived projector set + event_id expression + 3-shape DH-import block + family/type runtime recompute + off-floor rationale alignment | AST + runtime cross-check pattern |

## Sprint 8 hand-off checklist

Sprint 8 picks up the **Resumable Session API per ADR-004 amendment**.

- [ ] **Resumable Session API per ADR-004 amendment.** Sandbox primitive `checkpoint() / suspend() / wake()` with audit-chain integrity per ADR-004 amendment. Unlocks the action handler's `resume` backend dispatch (currently emits `action_backend_deferred_sandbox_unwired`).
- [ ] **`PolicyBundleLoaded` typed projector wiring.** The Pydantic model ships at Sprint-4; T4 typed-projector dispatch dict at `_DECISION_HISTORY_TYPED_PROJECTORS` does NOT yet include `policy.bundle_loaded`. Wave-1 carry-forward.
- [ ] **Wave-2 audit-event SSE surface.** The `chain_disc=0x02` byte slot in the cursor encoder is reserved + refuses fail-closed via `CursorChainUnsupported` today. Wave-2 wires the audit-event chain into the SSE fan-out path (`tool_call.*` + `artifact.*` typed projection).
- [ ] **Real elicitation adapter (bank-overlay).** Sprint-7B.4 ships the `ElicitationAdapter` Protocol + the `KernelDefaultElicitationAdapter` fail-loud scaffold; bank overlays implement against the Protocol when their elicitation backend wiring lands.
- [ ] **Runtime approval engine (Sprint 13.5).** The action handler's approve/deny paths emit `action_backend_deferred_to_sprint_13_5` today; Sprint-13.5 wires ADR-014's runtime approval-engine primitive.
- [ ] **Tenant data-governance policy store.** The T8 gate's Step 4 reads a kernel-global `_RESTRICTED_DATA_CLASSES` frozenset; per-tenant policy override is bank-overlay + 7B-followup concern.
- [ ] **Real `TrustRootResolver` implementation.** Sprint-7B.3 carry-forward; kernel ships only the Protocol + fail-loud scaffold.
- [ ] **`fail_open_exception` build-time manifest shape per ADR-017 amendment A4.** Sprint-7A2 carry-forward.
- [ ] **Realtime auto-attestation API + compliance helper emit path.** Sprint-7A carry-forward.
- [ ] **ADR-012 §114-122 fixture-AgentOS instance test harness.** Deferred post-7B per the prior plan §1280.
- [ ] **Pre-7B sprint rows' stale "READY-FOR-GATE awaiting" text in BUILD_PLAN §602-and-earlier.** A docs-hygiene pass should sweep the Sprint 2.5 / 3 / 4 / 5 / 6 / 7A / 7A2 status lines (those sprints are merged).

## Carryover

None. All T2-T13 deliverables landed.

## Out of scope (Sprint-7B.4 intentionally did NOT ship)

- **Wave-2 audit-event SSE surface** — the `chain_disc=0x02` byte slot is reserved + refuses fail-closed.
- **Runtime emission of `tool_call.*` + `artifact.*` event families** — Pydantic models ship; SSE fan-out is Wave-2.
- **Backend dispatch for the 5 non-submit_elicitation action_classes** — approve/deny → Sprint-13.5; cancel_run/interrupt → Sprint-11.5; resume → Sprint-8.
- **Real `ElicitationAdapter` implementation** — bank-overlay concern.
- **Real `OPAEngine` wiring in production `create_app`** — test fixtures inject; production launcher wires.
- **`PolicyBundleLoaded` typed projector wiring** — Wave-1 carry-forward to Sprint-8.
- **Tenant data-governance policy store** — bank-overlay + 7B-followup.
- **Real `TrustRootResolver`** — Sprint-7B.3 carry-forward.
- **`fail_open_exception` build-time manifest shape per ADR-017 amendment A4** — Sprint-7A2 carry-forward.
- **Studio UI authoring** — ADR-008 Phase B; explicitly deferred per ADR-008 + ADR-021 reservation.

## Next sprint

**Sprint 8 — Resumable Session API per ADR-004 amendment.** Sprint 7B is now CLOSED in aggregate (all 4 sub-sprints 7B.1 → 7B.4 shipped). Sprint 7B.4's `UIEventBroker` + the 3 SSE endpoints + the POST /actions surface + the chain-derived event_id cursors are the UI substrate Sprint-8's resumable-session work renders state through (`AgentRunPaused` / `AgentRunResumed` event families ship in the Sprint-6 model surface; Sprint-8 wires their runtime emission).
