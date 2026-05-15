# Sprint 7B.4 — UI Event-Stream Endpoints + RBAC Denial Chain Events — Design Spec

**Status:** APPROVED (brainstorming locked across Sections 1-6; awaiting user review of this written spec before transitioning to `writing-plans`).
**Date:** 2026-05-15.
**Scope:** ADR-020 implementation (SSE + POST `/actions` + portable JSON schema + RBAC + connection caps + `submit_elicitation` MCP-rules gate) + the 7B.3 carry-forward `policy.rbac_denied` chain events.
**Successor sprint:** Sprint 7B is closed by 7B.4. Sprint 8 (Resumable Session API per ADR-004 amendment) is next.
**Predecessor:** Sprint 7B.3 (PR #24, merged at `c53de7a` on `main` 2026-05-15).
**Plan size estimate:** ~1 wu per BUILD_PLAN §1148.

## 1. Goal

Ship the **UI event-stream contract** per ADR-020 as a first-class AgentOS protocol surface peer to MCP and A2A. Banks plug their portal UI (Cognic portal, bank portal, third-party dashboard, examiner viewer) into a stable wire-protocol contract that:
- Streams typed events from agent runtime to UI via Server-Sent Events (Wave 1) without losing events across reconnects;
- Accepts frontend-initiated actions (approve / deny / cancel_run / interrupt / resume / submit_elicitation) over a paired POST endpoint with per-class RBAC;
- Gates `submit_elicitation` by the same MCP elicitation rules that govern manifest-time elicitation declarations (mode parity + restricted-data-class refusal + Rego);
- Publishes a portable JSON schema at `/.well-known/cognic-ui-events.json` so any UI in any language can implement the contract.

Plus the 7B.3 carry-forward: promote the 4 portal RBAC denial structured-log sites to **dual-surface** emission — `_LOG.warning(...)` first, then `decision_history.append(...)` of a `policy.rbac_denied` chain row reaching SSE subscribers via the existing emit-hook layer.

## 2. Architecture overview

```
                   ┌──────────────────────────────────────────────────────┐
                   │  Bank UI / Portal UI / Examiner viewer / etc.        │
                   │  EventSource('/api/v1/ui/...')                       │
                   │  POST '/api/v1/ui/actions'                           │
                   └────────────────────┬─────────────────────────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────────────┐
              │       portal/api/ui/  (HTTP adapter layer; FastAPI)       │
              │                                                            │
              │  router.py            stream_routes.py    action_routes.py│
              │  well_known_routes.py dto.py              elicitation_gate.py│
              │                                                            │
              │  Depends on: UIEventBroker, ElicitationAdapter (Protocol), │
              │              OPAEngine                                     │
              │  (Chain appends route THROUGH UIEventBroker — route       │
              │   modules do NOT import DecisionHistoryStore directly.)   │
              └─────────────────────────┬─────────────────────────────────┘
                                        │  (architectural arrow points down)
              ┌─────────────────────────┼─────────────────────────────────┐
              │     protocol/  (FastAPI-free wire-protocol primitives)    │
              │                                                            │
              │  ui_events.py (extended)              elicitation_adapter.py│
              │  - UIEventBroker                      - ElicitationAdapter │
              │  - _chain_derived_event_id            - ElicitationContext │
              │  - typed projector table              - KernelDefault scaffold│
              │  - RBACDenialType (protocol-owned)                         │
              └─────────────────────────┬─────────────────────────────────┘
                                        │
              ┌─────────────────────────┼─────────────────────────────────┐
              │  core/  +  policies/_default/                              │
              │  - decision_history.py (unchanged; new chain-row types    │
              │                          consume via DecisionHistoryStore.append)│
              │  - policy/engine.py (OPAEngine — existing Sprint-4 surface)│
              │  - elicitation.rego (new policy-of-record stop-rule)      │
              └────────────────────────────────────────────────────────────┘
```

**Architectural arrow (pinned by AST-walk regressions):** `portal/api/ui/* → protocol/ui_events.py → core/decision_history`. `protocol/ui_events.py` MUST NOT import `fastapi`, `starlette`, `sse_starlette`, or any `portal/*` module.

## 3. Module layout

### New modules

| Path | Role | CC |
|---|---|---|
| `src/cognic_agentos/protocol/elicitation_adapter.py` | `ElicitationAdapter` Protocol + `ElicitationContext` / `ElicitationResult` frozen dataclasses + `KernelDefaultElicitationAdapter` fail-loud scaffold | NOT-CC (Protocol + scaffold; mirrors 7B.3 T9 `trust_root_resolver.py`) |
| `src/cognic_agentos/portal/api/ui/__init__.py` | Package marker | NOT-CC |
| `src/cognic_agentos/portal/api/ui/router.py` | `build_ui_routes(*, broker, elicitation_adapter, rego_engine)` composition | NOT-CC (scaffolding; mirrors `portal/api/packs/router.py`) |
| `src/cognic_agentos/portal/api/ui/stream_routes.py` | 3 SSE GET endpoints | **CC** (reconnect-safe transport + cursor validation + cross-tenant invisibility) |
| `src/cognic_agentos/portal/api/ui/action_routes.py` | POST `/actions` + `RequireUIAction` dep | **CC** (wire-protocol-public action POST + 6-class dispatch) |
| `src/cognic_agentos/portal/api/ui/well_known_routes.py` | `GET /.well-known/cognic-ui-events.json` | NOT-CC (schema publication; snapshot-pinned drift regression covers it) |
| `src/cognic_agentos/portal/api/ui/dto.py` | Pydantic DTOs + Literals (`ActionClass`, `ActionOutcome`, `ActionRejectionReason`, etc.) | NOT-CC (type-only) |
| `src/cognic_agentos/portal/api/ui/elicitation_gate.py` | Pure-async `evaluate_elicitation_submission(...)` 5-step gate | **CC** (policy boundary; precedent: 7B.3 T7 `packs/approval_gates.py`) |
| `policies/_default/elicitation.rego` | Default-deny Rego bundle for `submit_elicitation` (Rego v1 syntax) | **Stop-rule artifact** (CC-adjacent; not Python so not coverage-tracked; added to AGENTS.md "Stop rules") |
| `tests/architecture/test_ui_architectural_arrow.py` | 6 AST-walk arrow regressions | (test) |
| `tests/unit/protocol/test_ui_events_broker.py` | Broker primitive tests | (test) |
| `tests/unit/protocol/test_ui_events_chain_cursor.py` | Cursor encoder + decoder + drift | (test) |
| `tests/unit/protocol/test_ui_events_typed_projectors.py` | 5-entry typed-projector table | (test) |
| `tests/unit/protocol/test_ui_events_rbac_denial_type.py` | RBACDenialType union + disjointness | (test) |
| `tests/unit/protocol/test_elicitation_adapter.py` | Protocol + KernelDefault scaffold | (test) |
| `tests/unit/portal/rbac/test_rbac_denial_chain_emission.py` | Async dep + denial emit + fail-closed | (test) |
| `tests/unit/portal/rbac/test_actor_scope_widening.py` | Actor.scopes union type | (test) |
| `tests/unit/portal/api/ui/test_dto_action.py` | DTOs + closed-enum counts | (test) |
| `tests/unit/portal/api/ui/test_action_routes.py` | POST /actions + RequireUIAction | (test) |
| `tests/unit/portal/api/ui/test_action_routes_correlation_latency.py` | Deterministic asyncio.wait_for(0.2s) correlation | (test) |
| `tests/unit/portal/api/ui/test_stream_routes.py` | 3 SSE GETs | (test) |
| `tests/unit/portal/api/ui/test_stream_routes_last_event_id.py` | Last-Event-ID precedence | (test) |
| `tests/unit/portal/api/ui/test_stream_routes_reconnect.py` | Replay-then-live boundary | (test) |
| `tests/unit/portal/api/ui/test_stream_headers_and_timeout.py` | SSE headers + send_timeout | (test) |
| `tests/unit/portal/api/ui/test_heartbeat.py` | Broker/generator-owned heartbeat | (test) |
| `tests/unit/portal/api/ui/test_well_known_routes.py` | Schema publication + drift | (test) |
| `tests/unit/portal/api/ui/test_elicitation_gate.py` | Gate matrix + fail-closed paths | (test) |
| `tests/unit/policies/test_elicitation_rego.py` | Direct OPA test (`@pytest.mark.opa_required`) | (test) |

### Modified modules

| Path | Change | CC |
|---|---|---|
| `src/cognic_agentos/protocol/ui_events.py` | NEW `UIEventBroker` class (FastAPI-free), `_chain_derived_event_id` + `_decode_chain_cursor`, 5-entry `_DECISION_HISTORY_TYPED_PROJECTORS` table (`frontend_action.{submitted,accepted,rejected}` + `policy.decision_evaluated` + `rbac.<denial_type>` prefix-match), `RBACDenialType` 9-value protocol-owned Literal, `PolicyRBACDenied` event class, `_SSE_WAVE_1_STREAMED_FAMILIES` (9 families). | CC (already on durable gate from Sprint 6) |
| `src/cognic_agentos/portal/rbac/scopes.py` | NEW 8-value `UIRBACScope` peer Literal (`ui.run_stream`, `ui.tenant_stream`, `ui.action.<class>` × 6). | CC (already on durable gate from 7B.2 T12) |
| `src/cognic_agentos/portal/rbac/actor.py` | `Actor.scopes: frozenset[PackRBACScope \| UIRBACScope]` (additive union; runtime-compatible). | CC (already on durable gate from 7B.2 T12) |
| `src/cognic_agentos/portal/rbac/enforcement.py` | `_bind_actor` sync → async; new `broker` reference; dual-surface denial emission (log → `broker.emit_rbac_denial` → fail-closed 500 on emit failure). | CC (already on durable gate from 7B.2 T12) |
| `src/cognic_agentos/portal/rbac/tenant_isolation.py` | Sync → async; same dual-surface pattern. | CC (already on durable gate from 7B.2 T12) |
| `src/cognic_agentos/portal/rbac/human_actor.py` | Sync → async; same. | CC (already on durable gate from 7B.2 T12) |
| `src/cognic_agentos/portal/rbac/role_separation.py` | Sync → async; same. | CC (already on durable gate from 7B.2 T12) |
| `src/cognic_agentos/portal/api/app.py` | `create_app(*, broker, elicitation_adapter=None, rego_engine=None, ...)` wires the UI router + middleware that mints `request.state.request_id` for **ALL `/api/v1/*` portal routes** (not just `/ui/*` — RBAC denials fire from pack-route deps too); registers `well_known_routes` at root. | NOT-CC (already off-gate) |
| `AGENTS.md` | NEW "Authoring — UI event-stream (Sprint 7B.4)" subsection + extend "Stop rules" with `policies/_default/elicitation.rego`. | (doctrine) |
| `tools/check_critical_coverage.py` | +3 `_CRITICAL_FILES` entries; docstring section block 60 → 63. | CC (gate tool itself) |
| `tests/unit/tools/test_check_critical_coverage.py` | Count guard 60 → 63 + new 7B.4 modules present + new off-gate set extended. | (test) |
| `docs/BUILD_PLAN.md` §602 | NEW 7B.4 CLOSED status row; close Sprint 7B as a whole. | (doctrine) |

### Out of repo / explicitly not touched

- `core/decision_history.py` — UNCHANGED. New chain-row decision_types (`frontend_action.*`, `rbac.<denial_type>`, `policy.decision_evaluated` already exists from Sprint 4) consume `DecisionHistoryStore.append` from new emit seams in the RBAC/portal layer per the 7B.3 T8/T10 precedent.
- `protocol/mcp_host.py` — UNCHANGED. The elicitation adapter is a peer Protocol module; `MCPHost` doesn't gain an elicitation method in 7B.4.

## 4. Section-by-section design

### 4.1 · `UIEventBroker` primitive (in `protocol/ui_events.py`)

FastAPI-free in-memory pub/sub:

- **Construction:** `UIEventBroker(*, decision_history_store, settings)`. Holds a `DecisionHistoryStore` reference (core/ primitive) + Settings-backed connection cap (default 50/tenant) + queue maxsize (default 1000) + idle timeout (default 90s) + heartbeat interval (default 15s).
- **At startup:** registers ONE `UIEventHook` with the existing `UIEventEmitter.register_hook(...)` (the Sprint-6 emit-hook layer fired post-commit from `DecisionHistoryStore.append`). All event fan-out flows through this single hook.
- **Fan-out filter:** event reaches subscribers ONLY if `event.family in _SSE_WAVE_1_STREAMED_FAMILIES` AND (if family is `decision_audit`) `event.data["chain_id"] == "decision_history"`. Audit-event-backed `tool_call.*` / `artifact.*` / audit-chain `decision_audit.event_appended` mirrors are EXCLUDED — Wave-1 SSE is decision-history-only (ADR-020 amendment recorded in closeout).
- **`register_subscriber(*, tenant_id, run_id_filter=None, family_filter=...)`** — validates per-tenant cap; returns a `Subscriber` with bounded async-queue + `unregister()`. Refuses with `tenant_connection_cap_exceeded` (429) on cap hit.
- **`emit_rbac_denial(*, denial_type, ...)`** — appends a `rbac.<denial_type>` chain row via the held `DecisionHistoryStore.append` (ISO `A.5.31`). Post-commit fires the emitter hook chain → reaches SSE. Same shape as 7B.3 T8 `append_override_event` / T10 `append_evidence_read_event`.
- **`append_frontend_action_submitted(*, request_id, action_class, actor_subject, client_correlation_id, payload_digest, elicitation_mode=None) -> AppendResult`** — appends a `frontend_action.submitted` chain row via the held `DecisionHistoryStore.append` (ISO `A.5.31`). Returns `AppendResult` (the frozen dataclass defined further down in this section — carries `record_id`, `chain_hash`, AND the deterministic typed-event `event_id` resolved via the ContextVar mechanism below). The action handler pipeline (Section 4.4d step 2) calls this BEFORE the gate/dispatch step and uses `result.event_id` as the response's `submitted_event_id`. Centralizes chain emit through the broker so `action_routes.py` does NOT depend on `DecisionHistoryStore` directly — preserves the architectural arrow + matches the `emit_rbac_denial` precedent.
- **`append_frontend_action_accepted(*, request_id, action_class, actor_subject, client_correlation_id, submitted_event_id, elicitation_mode=None, originating_decision_record_id=None) -> AppendResult`** — accepted-outcome chain row; same ISO `A.5.31`. Returns `AppendResult` whose `event_id` becomes the response's `resolution_event_id`.
- **`append_frontend_action_rejected(*, request_id, action_class, actor_subject, client_correlation_id, submitted_event_id, reason: ActionRejectionReason, elicitation_mode=None, originating_decision_record_id=None) -> AppendResult`** — rejected-outcome chain row with closed-enum `reason`. Returns `AppendResult` whose `event_id` becomes the response's `resolution_event_id`. Same shape; same ISO control.
- **`reap_idle(now)`** — closes subscribers idle > `idle_timeout_s`. "Idle" = `now - subscriber.last_activity_at > idle_timeout_s`; `last_activity_at` is updated on every successful generator yield (heartbeat OR event), per Section 3a.1.

**Append seam centralization (P2 consistency edit):** all chain emits from `portal/api/ui/*` flow through broker methods. The broker owns the single `DecisionHistoryStore` reference. `action_routes.py` does NOT take or import `DecisionHistoryStore` — keeps the architectural arrow `portal/api/ui/* → protocol/ui_events.py → core/decision_history` strict at the route-module boundary. AST-walk regression `test_ui_architectural_arrow.py::test_action_routes_does_not_import_decision_history_store` pins this.

**How `AppendResult.event_id` is resolved without changing `core/decision_history.py`:**

`DecisionHistoryStore.append()` returns `(record_id: uuid.UUID, chain_hash: bytes)` — it does NOT return the assigned `sequence`. The deterministic chain-derived `event_id` per Section 4.2c requires the sequence in its payload. The spec keeps `core/decision_history.py` UNCHANGED (stop-rule module; no edit). The broker resolves `event_id` via the existing in-process projection hook chain — fired synchronously by `DecisionHistoryStore.append()`'s post-commit phase BEFORE `append()` returns to the caller:

```python
# protocol/ui_events.py (broker primitive)
_PENDING_TYPED_EVENT_ID: ContextVar[str | None] = ContextVar(
    "ui_broker_pending_typed_event_id", default=None
)

# Set of event Pydantic classes the broker treats as "typed projections"
# of a chain-row append (NOT the DecisionAuditEventAppended mirror).
_TYPED_PROJECTION_CLASSES: frozenset[type[_BaseEvent]] = frozenset({
    FrontendActionSubmitted, FrontendActionAccepted, FrontendActionRejected,
    PolicyRBACDenied, PolicyDecisionEvaluated,
    # PolicyBundleLoaded deferred (Section 4.4f)
})

class UIEventBroker:
    async def _fanout_hook(self, event: _BaseEvent) -> None:
        # 1) Capture event_id for the wrapping append_* method to read.
        #    Runs FIRST + UNCONDITIONALLY of the subscriber-set state —
        #    this branch is independent of subscriber fan-out, so a
        #    POST /actions with ZERO live SSE subscribers still resolves
        #    submitted_event_id / resolution_event_id correctly.
        #    Only typed events from _TYPED_PROJECTION_CLASSES — NOT the
        #    decision_audit.event_appended mirror (which fires AFTER the
        #    typed event per canonical projection order at Section 4.2c).
        if type(event) in _TYPED_PROJECTION_CLASSES:
            _PENDING_TYPED_EVENT_ID.set(event.event_id)
        # 2) Subscriber fan-out — filter + enqueue. The empty-subscribers
        #    case short-circuits here without affecting step 1's capture.
        ...

    async def append_frontend_action_submitted(self, ...) -> AppendResult:
        _PENDING_TYPED_EVENT_ID.set(None)            # clear before await
        record = DecisionRecord(
            decision_type="frontend_action.submitted",
            payload=safe_metadata_payload,
            ...,
        )
        record_id, chain_hash = await self._history.append(record)
        # Hooks have fired synchronously during the awaited append.
        # Broker's _fanout_hook ran on the same task; ContextVar is set.
        event_id = _PENDING_TYPED_EVENT_ID.get()
        if event_id is None:
            # Invariant violation — typed projector not wired for this decision_type.
            raise RuntimeError(
                f"broker append seam: no typed event projected for "
                f"decision_type={record.decision_type!r}; check "
                f"_DECISION_HISTORY_TYPED_PROJECTORS routing table"
            )
        return AppendResult(record_id=record_id, chain_hash=chain_hash, event_id=event_id)
```

**Why this is race-safe:**
1. **`ContextVar` is task-scoped.** Each FastAPI request runs on its own asyncio task; `await store.append(...)` runs on the same task as the calling broker method; the broker's fan-out hook (`_fanout_hook`) is awaited inside the post-commit phase on the same task. No cross-task interleaving.
2. **Synchronous post-commit hook chain.** `DecisionHistoryStore.append()`'s existing Sprint-6 invariant: "Stores fire hooks AFTER the chain-write commits + BEFORE `append()` returns" (per `protocol/ui_events.py:25-26`). The hook fire is `await`-sequenced inside `append()`; by the time `append()` returns, the broker's hook has executed.
3. **Typed-event filter.** The fan-out hook stores `event_id` ONLY when `type(event) in _TYPED_PROJECTION_CLASSES`. The canonical projection order (Section 4.2c) emits typed first (ordinal 0), `DecisionAuditEventAppended` mirror second (ordinal 1). Since the mirror is NOT in the filter set, the ContextVar holds the typed event's id after both fire.
4. **Invariant check.** If `_PENDING_TYPED_EVENT_ID.get()` is `None` after `append()`, the typed projector wasn't wired — `RuntimeError` raised; fail-loud. Pinned by `TestBrokerAppendRaisesWhenTypedProjectorMissing` (parametrize over the 5 decision_types in `_DECISION_HISTORY_TYPED_PROJECTORS`; monkey-patch the table to remove one entry; assert the broker's matching `append_*` method raises).

**Trade-off acknowledged:** the broker's hook-side capture couples to the canonical-projection-order invariant (typed fires before mirror). If a future schema-version change ever flips that order, the broker's filter set provides a structural guard (it only captures typed events) — the ContextVar wouldn't pick up the mirror by accident. Drift detector at `tests/unit/protocol/test_ui_events_typed_projectors.py::TestCanonicalProjectionOrderHoldsForBroker` re-asserts the typed-first ordering as part of the broker's contract.

**Alternative considered + rejected:** extending `DecisionHistoryStore.append()` to return `AppendedDecisionSnapshot` (including `sequence`) would be a small typed core seam but a STOP-RULE edit per AGENTS.md. The ContextVar approach achieves the same goal entirely within `protocol/ui_events.py` (already on the durable critical-controls gate from Sprint 6). Core stays untouched.

`AppendResult` shape (NEW frozen dataclass in `protocol/ui_events.py`):
```python
@dataclasses.dataclass(frozen=True)
class AppendResult:
    record_id: uuid.UUID
    chain_hash: bytes
    event_id: str    # deterministic chain-derived cursor — usable as submitted_event_id / resolution_event_id
```

Test classes (new in `test_ui_events_broker.py`):
- `TestBrokerAppendReturnsEventIdMatchingProjectedEvent` — happy path; assert returned `event_id` equals `_chain_derived_event_id(sequence=<actual>, ordinal=0, ...)`.
- `TestBrokerAppendRaisesWhenTypedProjectorMissing` — monkey-patch projector table to remove one entry; broker.append_*() raises `RuntimeError` with the missing-projector diagnostic.
- `TestBrokerAppendIsTaskScoped` — fire 2 concurrent appends from different tasks; assert each gets the correct event_id (ContextVar isolation pinning).
- `TestBrokerCaptureFiltersOutDecisionAuditMirror` — verify the mirror's event_id does NOT overwrite the typed event's id in the ContextVar.
- `TestBrokerAppendReturnsEventIdWithNoSubscribers` — register the broker with zero subscribers, fire each of the 3 `append_frontend_action_*` methods, assert each returns an `AppendResult` with a valid non-null `event_id` matching `_chain_derived_event_id(...)`. Pins that capture is independent of subscriber fan-out (the POST `/actions` correlation cursor is always emitted, even when no UI is currently watching).
- **Subscriber overflow:** queue full → `subscriber.overflow_count += 1` + `_LOG.warning("ui.subscriber.queue_overflow", ...)`. Backpressure is visible to operators, not silent.

### 4.2 · Event flow + RBAC denial chain events + reconnect cursor

#### 2a. End-to-end event flow

```
domain op (e.g. pack.lifecycle.submitted)
   │
   ▼
DecisionHistoryStore.append(record)
   │  (chain-head row lock; canonical-form-write; sequence assigned)
   ▼
post-commit fires UIEventEmitter hooks
   │  (Sprint-6 invariant: AFTER commit + BEFORE append() returns)
   ▼
UIEventEmitter._on_decision_append(snapshot):
   │  ordinal 0: typed projector (if matched in _DECISION_HISTORY_TYPED_PROJECTORS)
   │  ordinal 1: decision_audit.event_appended mirror (ALWAYS)
   ▼
For each emitted event:
   UIEventBroker._fanout_hook(event)
     • family filter (_SSE_WAVE_1_STREAMED_FAMILIES) + chain_id filter
     • walk subscribers; per-subscriber match: tenant_id + run_id_filter + family_filter
     • subscriber.queue.put_nowait(event)
   ▼
Subscriber.aiter() — yielded by sse-starlette EventSourceResponse generator
   ▼
client (UI)
```

**Ordering guarantee:** within one subscriber's stream, events appear in `decision_history.sequence` order. Pinned by (a) `append`'s single-writer chain-head lock, (b) deterministic UIEventEmitter hook order, (c) per-subscriber FIFO queue.

#### 2b. RBAC denial chain events (the 7B.3 carry-forward)

**`policy.rbac_denied`** — NEW `PolicyRBACDenied(_BaseEvent)` Pydantic model in `protocol/ui_events.py` with `family: Literal["policy"] = "policy"` + `type: Literal["rbac_denied"] = "rbac_denied"`. **Uses the reserved `policy.*` slot — `_WAVE_1_FAMILIES` stays at 11.** Adding a 12th family is an ADR-020 schema-version decision, not 7B.4 scope.

**`RBACDenialType`** — 9-value Literal **defined IN `protocol/ui_events.py`** as protocol-owned wire schema (NOT imported from `portal/rbac/*`). Values: `actor_unauthenticated` / `scope_not_held` / `actor_binder_not_configured` / `tenant_id_mismatch` / `pack_not_found` / `actor_tenant_id_missing` / `pack_store_not_configured` / `actor_type_must_be_human` / `actor_cannot_review_own_pack`. **Test-layer union-equality regression** imports the 4 portal RBAC Literals + asserts `set(get_args(RBACDenialType)) == union(get_args of 4 portal Literals)` + pairwise disjointness.

**Dual-surface emission contract:** each of the 4 RBAC modules' refusal sites — IMMEDIATELY AFTER existing `_LOG.warning(...)` — calls `await broker.emit_rbac_denial(...)`. Mirrors 7B.2 T9 Slice 3.

**Async dep conversion:** `_bind_actor` + `RequireScope` + `RequireTenantOwnership` + `RequireHumanActor` + `RequireDifferentActorThanCreator` all become async. Pattern at each denial site:

```python
_LOG.warning("portal.rbac.<key>", extra=extra)        # structured log first — guaranteed
try:
    await broker.emit_rbac_denial(...)
except Exception as exc:
    _LOG.error("portal.rbac.denial_emit_failed", exc_info=True)
    raise HTTPException(500, detail={"reason": "rbac_denial_emit_failed"}) from exc
raise HTTPException(403, detail={"reason": "scope_not_held", ...})
```

**NO fire-and-forget. NO silent audit loss.** Chain-append failure raises 500, masks the normal 403/404.

**`RBACDenialEmitFailure` = Literal["rbac_denial_emit_failed"]** — 1-value closed-enum for the 500 path.

**Safe-context payload** (verified at existing log sites):

| Field | Source | Notes |
|---|---|---|
| `denial_type` | `RBACDenialType` (required) | Mirrors `reason` |
| `actor_subject` | `str \| None` | `None` for `actor_unauthenticated` |
| `denied_at` | `datetime` UTC ISO | Append-time |
| `request_id` | `str` (required) | From `request.state.request_id` (middleware) |
| `required_scope` | `str \| None` | Set for `scope_not_held` only. **Typed as bare `str` in the protocol model** to preserve the `portal → protocol` arrow (`protocol/ui_events.py` cannot import portal-owned `PackRBACScope` / `UIRBACScope`). Test-layer regression `TestRBACDenialEventEmittedFieldsStayInPortalVocab` asserts the emitted string value is always a member of `get_args(PackRBACScope) | get_args(UIRBACScope)`. |
| `pack_id` | `uuid.UUID \| None` | Set at tenant_isolation + role_separation sites |
| `actor_type` | `str \| None` | Set at human_actor site. **Typed as bare `str` in the protocol model** (same arrow rationale — `ActorType` is portal-owned). Test-layer regression asserts the emitted string is always in `get_args(ActorType)`. |
| `pack_created_by` | `str \| None` | Set at role_separation site |
| `http_status` | `int \| None` | 403 / 404 / 500 |
| `resource_type` | `Literal["pack"] \| None` | Future-proof |

**NO** request headers, body, query params, or auth-material fields. PII-safe.

#### 2c. Reconnect cursor

**`event_id` = `evt_<26 base32>` wrapping a self-describing 16-byte payload** (replaces Sprint-6's random ULID for chain-derived events; `_new_event_id()` random ULID retained for non-chain ad-hoc events).

Payload layout:

| Offset | Width | Field | Notes |
|---|---|---|---|
| 0 | 1 byte | `chain_disc` | `0x01` = decision_history; `0x02` = audit_event (reserved for Wave-2 SSE) |
| 1-8 | 8 bytes | `sequence` (uint64 BE) | `decision_history.sequence` |
| 9 | 1 byte | `ordinal` (uint8) | `0x00` = typed event; `0x01` = `decision_audit.event_appended` mirror |
| 10-15 | 6 bytes | `type_hash` | `sha256(f"{family}.{type}").digest()[:6]` |

**Canonical projection order per row:** typed event = ordinal 0 (when row has a typed projector match); `decision_audit.event_appended` mirror = ordinal 1 (always).

**Helpers (in `protocol/ui_events.py`):**
- `_chain_derived_event_id(*, chain_id, sequence, ordinal, family, type_) -> str` — encodes the 16-byte payload via `ULID.from_bytes(...)`.
- `_decode_chain_cursor(event_id) -> ChainCursor` — decodes; raises `CursorMalformed` on prefix/length mismatch; `CursorChainUnsupported` if `chain_disc != 0x01` (Wave-1 only).

**Cursor-driven replay at `/events/since/{event_id}`:**
1. `_decode_chain_cursor(cursor)` → `(chain_disc, seq_N, ordinal_K, type_hash_H)`.
2. **Boundary row pre-load:** `SELECT * FROM decision_history WHERE sequence = seq_N`. If not found → 422 `cursor_not_found`. If `row.tenant_id != actor.tenant_id` → 404 with closed-enum `cursor_tenant_mismatch` (cross-tenant-invisible — same shape as `pack_not_found`).
3. Snapshot current chain-head sequence → `tip`.
4. Read rows `seq_N <= sequence <= tip AND tenant_id == actor.tenant_id AND <family filter>`.
5. Project each row → typed (ordinal 0, if matched) + decision_audit mirror (ordinal 1). For boundary row (sequence == seq_N): yield events with `ordinal > ordinal_K`. For rows sequence > seq_N: yield all.
6. **Type-hash assertion** at boundary: when re-projecting the boundary row's event whose ordinal == ordinal_K, recompute `type_hash` and assert equality with cursor.`type_hash_H`. Mismatch → 500 `cursor_projection_drift_detected` (routing table changed since cursor was issued; client must resubscribe fresh).
7. Transition to live tail via the existing broker registration; dedup-by-event_id at snapshot-to-live boundary.

**Idempotency property:** same chain row + same family+type → byte-identical cursor → byte-identical `event_id`. Live emission and replay emission produce the SAME id for the same event. Pinned by `TestReplayProducesSameEventIdAsLive` (threat-model-revert verified).

### 4.3 · HTTP surfaces

#### 3a. 3 SSE GET endpoints

All three return `EventSourceResponse` (from sse-starlette 2.1.0).

**Endpoint 1 — `GET /api/v1/ui/runs/{run_id}/events`**
- **`run_id` is an opaque tenant-scoped filter** (no run registry exists per ADR-001 — verified).
- **RBAC:** `ui.run_stream` scope; tenant from `actor.tenant_id`. NO `run_not_found` (no run registry to look it up). NO "run.tenant_id must match" check.
- **Mode:** live-only on first connect; with `Last-Event-ID` header → replay-then-live scoped by path `run_id`.
- **Refusal set:** `tenant_connection_cap_exceeded` (429), `family_filter_unknown` (422), RBAC set (403 via async dep — fires `policy.rbac_denied`).

**Endpoint 2 — `GET /api/v1/ui/tenants/{tenant_id}/events?families=...&since=evt_id`**
- **RBAC:** `ui.tenant_stream` + `path.tenant_id == actor.tenant_id` (cross-tenant → 404).
- **Mode:** combined replay-then-live when `Last-Event-ID` OR `?since=` present; live-only otherwise.
- **`families` filter** applies to BOTH replay and live.

**Endpoint 3 — `GET /api/v1/ui/events/since/{event_id}?run_id=...`**
- **RBAC:** `ui.tenant_stream`; cursor implicitly tenant-bound by validation.
- **Mode:** replay-then-live, cursor-first.

**Effective-cursor precedence** (uniform across endpoints): `Last-Event-ID` header WINS over URL cursor (`?since=` or path `{event_id}`). Malformed header does NOT silently fall back → 422 `cursor_malformed`.

**Heartbeat:** broker/generator-owned. Generator yields `ServerSentEvent(comment="keepalive")` every `heartbeat_interval_s` (default 15s); updates `subscriber.last_activity_at` on yield success. sse-starlette's internal ping interval is set to a long sentinel (`ping=86400`) — generator-owned heartbeat is authoritative.

**`send_timeout`:** 30s default on `EventSourceResponse`; bounds half-open client cleanup. Stalled clients raise in the generator → `finally` runs → `subscriber.unregister()`.

**Required SSE response headers** on all 3 endpoints:
```
Content-Type: text/event-stream     (sse-starlette default)
Cache-Control: no-cache             (prevents browser/intermediary caching)
X-Accel-Buffering: no               (prevents nginx-like reverse-proxy buffering)
Connection: keep-alive              (explicit; some proxies need it)
```

**Cursor refusals (5-value closed-enum in `stream_routes.py`):** `cursor_malformed`, `cursor_chain_unsupported`, `cursor_not_found`, `cursor_tenant_mismatch`, `cursor_projection_drift_detected`.

#### 3b. `GET /.well-known/cognic-ui-events.json`

- Unauthenticated public endpoint (schema is a contract publication, not data).
- Body: `schema_version` (pinned constant), full **11-family** schema via `pydantic.TypeAdapter(...).json_schema()`, plus the **9-family `wave_1_sse_streamed`** subset tag.
- Headers: `Cache-Control: public, max-age=300, immutable`.
- Registered DIRECTLY on the FastAPI app at root (NOT under `/api/v1/ui/`; `.well-known` is reserved per RFC 8615).
- **Schema-drift regression:** snapshot-pinned byte-equality assertion. Any Pydantic model change that affects the schema requires a deliberate version bump + snapshot update.

### 4.4 · POST `/api/v1/ui/actions`

#### 4a. Request shape — Pydantic discriminated union

```python
ActionClass = Literal["approve", "deny", "cancel_run", "interrupt", "resume", "submit_elicitation"]

class _BaseActionRequest(PackBaseModel):
    action_class: ActionClass
    client_correlation_id: str | None = None   # echoed back; ≤ 64 chars

class ApproveActionRequest(_BaseActionRequest):
    action_class: Literal["approve"] = "approve"
    approval_id: str
    decision: Literal["grant", "grant_second"]

class DenyActionRequest(_BaseActionRequest): ...
class CancelRunActionRequest(_BaseActionRequest): ...
class InterruptActionRequest(_BaseActionRequest): ...
class ResumeActionRequest(_BaseActionRequest): ...
class SubmitElicitationActionRequest(_BaseActionRequest):
    action_class: Literal["submit_elicitation"] = "submit_elicitation"
    elicitation_id: str
    mode: Literal["url", "form"]
    url_completion_signal: dict[str, Any] | None = None
    form_payload: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _enforce_payload_matches_mode(self) -> "SubmitElicitationActionRequest":
        """Exact payload/mode parity per P2 review — at Pydantic-parse time → 422.

        Rejects (a) mode='form' without form_payload; (b) mode='form' with
        url_completion_signal also present; (c) mode='url' without
        url_completion_signal; (d) mode='url' with form_payload also present.
        Catches ill-formed requests BEFORE pipeline step 2 (chain emit) —
        Pydantic ValidationError → FastAPI 422 → NO chain row written.
        Request-shape rejection is not a frontend_action outcome, so it
        does NOT need an ActionRejectionReason value.
        """
        if self.mode == "form":
            if self.form_payload is None:
                raise ValueError("mode='form' requires form_payload")
            if self.url_completion_signal is not None:
                raise ValueError("mode='form' must not include url_completion_signal")
        else:  # mode == "url"
            if self.url_completion_signal is None:
                raise ValueError("mode='url' requires url_completion_signal")
            if self.form_payload is not None:
                raise ValueError("mode='url' must not include form_payload")
        return self

ActionRequest = Annotated[<6-union>, Field(discriminator="action_class")]
```

**Response:**

```python
class ActionResponse(PackBaseModel):
    request_id: str
    action_class: ActionClass
    outcome: ActionOutcome                    # accepted | rejected
    reason: ActionRejectionReason | None      # closed-enum when outcome=rejected
    submitted_at: datetime
    submitted_event_id: str                   # cursor for the submitted chain row
    resolution_event_id: str | None           # cursor for accepted/rejected (None if async)
    client_correlation_id: str | None
```

#### 4b. `RequireUIAction` combined dep

Replaces dynamic `RequireScope` (existing `RequireScope` is factory-static — verified). Parses body + binds actor (async) + maps `action_class → UIRBACScope` + enforces + returns `UIActionContext(body, actor, request_id)`.

```python
def RequireUIAction(broker: UIEventBroker) -> Callable[..., Awaitable[UIActionContext]]:
    async def _resolve(
        request: Request,                            # NEW per P1 review — needed for request.state.request_id
        body: ActionRequest = Body(...),
        actor: Actor = Depends(_bind_actor),         # async
    ) -> UIActionContext:
        request_id = request.state.request_id        # middleware guarantees this is set on /api/v1/*
        required_scope = cast(UIRBACScope, f"ui.action.{body.action_class}")
        if required_scope not in actor.scopes:
            _LOG.warning("portal.rbac.denied", extra={
                "reason": "scope_not_held",
                "actor_subject": actor.subject,
                "required_scope": required_scope,
                "request_id": request_id,
            })
            try:
                await broker.emit_rbac_denial(
                    denial_type="scope_not_held",
                    actor_subject=actor.subject,
                    required_scope=required_scope,
                    request_id=request_id,           # from the same Request object — no getattr defensive read needed
                    http_status=403,
                )
            except Exception as exc:
                _LOG.error("portal.rbac.denial_emit_failed", exc_info=True)
                raise HTTPException(500, detail={"reason": "rbac_denial_emit_failed"}) from exc
            raise HTTPException(403, detail={"reason": "scope_not_held",
                                             "required_scope": required_scope})
        return UIActionContext(
            body=body,
            actor=actor,
            request_id=request_id,
        )
    return _resolve
```

#### 4c. 8-value `UIRBACScope` peer Literal (in `portal/rbac/scopes.py`)

```python
UIRBACScope = Literal[
    "ui.run_stream",
    "ui.tenant_stream",
    "ui.action.approve",
    "ui.action.deny",
    "ui.action.cancel_run",
    "ui.action.interrupt",
    "ui.action.resume",
    "ui.action.submit_elicitation",
]
```

**`Actor.scopes` widening:** `frozenset[PackRBACScope | UIRBACScope]` — additive union; runtime-backward-compatible.

#### 4d. 7-step handler pipeline (submitted-before-gate)

1. `RequireUIAction` dep: Pydantic parse (422) → `_bind_actor` (403 unauth + `policy.rbac_denied`) → scope map+enforce (403 + `policy.rbac_denied`).
2. **`await broker.append_frontend_action_submitted(...)`** — ALWAYS regardless of dispatch. Audit completeness. Returns the `submitted_event_id` cursor used in step 5's resolution row + step 7's response.
3. Per-class pre-dispatch validation (only `submit_elicitation`: Section 5 gate).
4. Backend dispatch per the routing matrix (4e).
5. **`await broker.append_frontend_action_accepted(...)` OR `broker.append_frontend_action_rejected(...)`** — outcome chain row with the resolution reason; returns the `resolution_event_id` cursor for step 7's response.
6. Typed projectors fire `FrontendActionSubmitted` + `Accepted`/`Rejected` events → broker → SSE.
7. Return `ActionResponse` with both event-id cursors.

#### 4e. Backend routing matrix

| Action class | Backend | 7B.4 behavior |
|---|---|---|
| `approve` | Runtime approval engine (ADR-014 / Sprint 13.5) | Stub: emit submitted + rejected with `action_backend_deferred_to_sprint_13_5` |
| `deny` | Same | Same |
| `cancel_run` | Run registry (per ADR-001, Layer-C agent territory) | Stub: rejected with `action_backend_deferred_no_run_primitive` |
| `interrupt` | Sandbox checkpoint/suspend | Stub: rejected with `action_backend_deferred_sandbox_unwired` |
| `resume` | Sandbox wake | Same |
| `submit_elicitation` | Section 5 gate + elicitation adapter | Full E2E when adapter wired; fail-closed `elicitation_backend_unwired` otherwise |

**Wire-protocol-stability claim:** all 6 action classes are wire-protocol-correct in 7B.4. Banks plug a UI in today with a complete contract surface. As backend primitives land in later sprints, stubs swap for real dispatch; request/response DTOs + chain-row schema STAY UNCHANGED.

#### 4f. Typed projectors (extending `_DECISION_HISTORY_TYPED_PROJECTORS`)

5 entries in 7B.4:
- `frontend_action.submitted` → `_project_frontend_action_submitted`
- `frontend_action.accepted` → `_project_frontend_action_accepted`
- `frontend_action.rejected` → `_project_frontend_action_rejected`
- `policy.decision_evaluated` → `_project_policy_decision_evaluated` (Pydantic class exists from Sprint 6; this wires the routing)
- `rbac.<denial_type>` → `_project_policy_rbac_denied` (via prefix-match; 9 RBACDenialType suffixes)

`policy.bundle_loaded` has its Pydantic model in `protocol/ui_events.py` (schema-shipped Sprint 6) but its typed projector wiring is deferred (out of 7B.4 scope; bundle hot-reload lands in Sprint 13.5).

#### 4g. Chain row safe-metadata payload

**`frontend_action.submitted` (5 keys, +1 for submit_elicitation):**

```python
{
    "request_id":            "<server-minted via request.state>",
    "action_class":          "<ActionClass>",
    "actor_subject":         "<actor.subject>",
    "client_correlation_id": "<echoed or null>",
    "payload_digest":        "sha256:<hex of canonical_bytes(body.model_dump(mode='json'))>",
    # submit_elicitation only:
    "elicitation_mode":      "<url|form>",
}
```

**`frontend_action.accepted` / `.rejected` (6/7 keys, +1 or +2 for submit_elicitation):**

```python
{
    "request_id":            "<same as submitted>",
    "action_class":          "<ActionClass>",
    "actor_subject":         "<actor.subject>",
    "client_correlation_id": "<echoed>",
    "outcome":               "accepted" | "rejected",
    "submitted_event_id":    "<deterministic cursor of the submitted row>",
    "reason":                "<ActionRejectionReason>",   # rejected only
    # submit_elicitation only (when ctx known — i.e. gate step 2+ succeeded):
    "elicitation_mode":      "<url|form>",
    "originating_decision_record_id": "<UUID of the tool call chain row>",
}
```

**`payload_digest`** is `sha256:<hex>` of `canonical_bytes(body.model_dump(mode="json"))` — the VALIDATED DTO post-Pydantic-parse, NOT the raw HTTP body. Sensitive fields (`form_payload`, `url_completion_signal`) enter the digest computation (audit-trail) but never appear in chain plaintext.

**Closed-keyset shape** is route-owned; storage stays a thin dict passthrough (mirrors 7B.2 T9 Slice 3).

#### 4h. `request_id` middleware

NEW FastAPI middleware mounted in `create_app` for **all routes matching `/api/v1/*`** (extended scope per P1 review — the async-converted `_bind_actor` + 4 `Require*` deps fire from PACK routes too, and their RBAC denial chain rows require a `request_id`; UI-only middleware scope would leave pack-route denials without a request_id source). Mints `request.state.request_id = "portal-req-" + uuid4().hex` (42 chars ≤ 64) at request entry. Read by `_bind_actor` (for early denial paths like `actor_unauthenticated`) AND `RequireUIAction` (for the action chain rows). Single ID per portal API request lifecycle. **Defensive fallback** at `_bind_actor`: if `request.state.request_id` is unset (non-portal-route caller; should never happen on `/api/v1/*` but defends against future routes outside the middleware scope), mints `portal-rbac-denial-<uuid>` (20 chars + 32 hex = 52 chars ≤ 64) inline. Existing pack handlers' per-verb minters (`_PACK_<VERB>_REQUEST_ID_PREFIX`) are NOT refactored — they continue to mint their handler-level chain-row request_ids; the middleware-minted ID is reserved for the dep-chain (RBAC denial) emit path. Two IDs per pack POST in the steady state — middleware-minted for any denial chain rows, handler-minted for the handler's own chain rows. Documented in the closeout.

#### 4i. `ActionRejectionReason` — 10 values

```python
ActionRejectionReason = Literal[
    "action_backend_deferred_to_sprint_13_5",
    "action_backend_deferred_no_run_primitive",
    "action_backend_deferred_sandbox_unwired",
    "elicitation_mode_not_permitted",
    "elicitation_restricted_data_class",
    "elicitation_rego_denied",
    "elicitation_unwired_evaluator",
    "elicitation_backend_failed",
    "elicitation_backend_unwired",
    "elicitation_unknown_id",
]
```

### 4.5 · `submit_elicitation` gate

#### 5a. `ElicitationAdapter` Protocol (in `protocol/elicitation_adapter.py`)

```python
ElicitationMode = Literal["url", "form"]

@dataclass(frozen=True)
class ElicitationContext:
    elicitation_id: str
    tenant_id: str
    originating_pack_id: str
    originating_decision_record_id: uuid.UUID
    elicitation_modes: tuple[ElicitationMode, ...]
    data_classes: tuple[str, ...]
    expires_at: datetime | None

@dataclass(frozen=True)
class ElicitationResult:
    delivered_at: datetime
    backend_correlation_id: str | None

class ElicitationBackendError(RuntimeError): pass

@runtime_checkable
class ElicitationAdapter(Protocol):
    async def get_context(self, *, elicitation_id: str, tenant_id: str) -> ElicitationContext | None: ...
    async def handle_submission(self, *, ctx: ElicitationContext, mode: ElicitationMode, payload: dict[str, Any]) -> ElicitationResult: ...

class KernelDefaultElicitationAdapter:
    async def get_context(self, **kw): raise NotImplementedError("ADR-020 §69 elicitation adapter not wired")
    async def handle_submission(self, **kw): raise NotImplementedError(...)
```

#### 5b. `evaluate_elicitation_submission(...)` 5-step gate (in `portal/api/ui/elicitation_gate.py`)

1. **Adapter wired?** `adapter is None` → `elicitation_backend_unwired`.
2. **Context lookup.** `adapter.get_context(...)` raises `NotImplementedError` → `elicitation_backend_unwired`. Returns `None` → `elicitation_unknown_id`.
3. **Mode parity (both modes).** `if request.mode not in ctx.elicitation_modes:` → `elicitation_mode_not_permitted`.
4. **Restricted-data-class refusal (form-mode only).** `if request.mode == "form" and _RESTRICTED_DATA_CLASSES.intersection(ctx.data_classes):` → `elicitation_restricted_data_class`.
5. **Rego eval.** `await rego_engine.evaluate(decision_point="data.cognic.ui.elicitation_submit.allow", input={...})`. `rego_engine is None` OR `OpaNotInstalledError` → `elicitation_unwired_evaluator`. Bundle/eval errors → `elicitation_rego_denied`. `decision.allow == False` → `elicitation_rego_denied`. All green → `GateOutcome(allowed=True, ctx=...)`.

OPA decision_point string is `"data.cognic.ui.elicitation_submit.allow"` — verified at `engine.py:282` precedent (`"data.cognic.supply_chain.allow"`).

#### 5c. `policies/_default/elicitation.rego` (Rego v1 syntax — matches `supply_chain.rego`)

```rego
# policies/_default/elicitation.rego
# Sprint-7B.4 — ADR-020 §69-77; default-deny form-mode on restricted classes.

package cognic.ui.elicitation_submit

default allow := false

# URL completion always permitted (after mode-parity passed in Python)
allow if {
    input.mode == "url"
}

# Form-mode allowed only when no restricted data class is declared
allow if {
    input.mode == "form"
    not has_restricted_class
}

restricted_classes := {"customer_pii", "payment_action", "regulator_communication"}

has_restricted_class if {
    some c in input.data_classes
    restricted_classes[c]
}
```

**Stop-rule:** added to AGENTS.md "Stop rules" section. Halt-before-commit on every edit.

#### 5d. Three-way drift detector on `_RESTRICTED_DATA_CLASSES`

Test `test_elicitation_rego.py::TestRestrictedClassesThreeWayLockstep` asserts:

```python
from cognic_agentos.portal.api.ui.elicitation_gate import _RESTRICTED_DATA_CLASSES as py_set
from cognic_agentos.cli._governance_vocab import RestrictedDataClass     # canonical
rego_set = _parse_restricted_classes_from_rego("policies/_default/elicitation.rego")
expected = frozenset({"customer_pii", "payment_action", "regulator_communication"})
assert py_set == rego_set == frozenset(get_args(RestrictedDataClass)) == expected
```

Three-way lockstep prevents vocabulary drift across Python source / Rego source / canonical doctrine.

## 5. Closed-enum vocabulary register (consolidated)

| Literal / Final | Values | Module | Drift detector |
|---|---|---|---|
| `_WAVE_1_FAMILIES` | 11 | `protocol/ui_events.py` | Pinned at 11; 12th is ADR-amendment |
| `_SSE_WAVE_1_STREAMED_FAMILIES` | 9 | `protocol/ui_events.py` | excludes `tool_call`, `artifact` |
| `RBACDenialType` | 9 | `protocol/ui_events.py` | union over 4 portal Literals + disjointness |
| `UIRBACScope` | 8 | `portal/rbac/scopes.py` | count guard |
| `ActionClass` | 6 | `portal/api/ui/dto.py` | count guard |
| `ActionOutcome` | 2 | `portal/api/ui/dto.py` | count guard |
| `ActionRejectionReason` | 10 | `portal/api/ui/dto.py` | count + disjointness from `RBACDenialType` + `RejectionReason` |
| `ElicitationMode` | 2 | `protocol/elicitation_adapter.py` | count guard |
| `_RESTRICTED_DATA_CLASSES` | 3 | `portal/api/ui/elicitation_gate.py` | three-way Python/Rego/governance_vocab |
| Cursor refusal reasons | 5 | `portal/api/ui/stream_routes.py` | count guard |
| `RBACDenialEmitFailure` | 1 | `portal/rbac/enforcement.py` | count guard |

## 6. Architectural-arrow AST regressions (`tests/architecture/test_ui_architectural_arrow.py`)

1. `protocol/ui_events.py` does NOT import `cognic_agentos.portal.*`, `fastapi`, `starlette`, or `sse_starlette`.
2. `protocol/elicitation_adapter.py` does NOT import `cognic_agentos.portal.*`, `fastapi`, `starlette`, `sse_starlette`, OR `cognic_agentos.protocol.mcp_host`.
3. `portal/api/ui/elicitation_gate.py` does NOT import `fastapi.HTTPException` OR `cognic_agentos.protocol.mcp_host`.
4. `portal/api/ui/action_routes.py` does NOT import `cognic_agentos.protocol.mcp_host`.
5. `from __future__ import annotations` is absent in **FastAPI route modules only**: `action_routes.py`, `stream_routes.py`, `well_known_routes.py`, `router.py`. NOT enforced on `dto.py` or `elicitation_gate.py` (pure-helper modules).
6. Every entry in `_DECISION_HISTORY_TYPED_PROJECTORS` (and the rbac.* prefix-matcher) calls `event_id=_chain_derived_event_id(...)` explicitly — AST walks each projector function body asserting the keyword argument is present.

## 7. Testing strategy

### 7a. BUILD_PLAN §668-674 mapping

| BUILD_PLAN spec | Owning test module |
|---|---|
| §668 SSE run stream + ordering + RBAC | `test_stream_routes.py::TestRunStreamOrdering` + `TestRunStreamTenantRBAC` |
| §669 reconnect catch-up + cursor-based no-loss | `test_stream_routes_reconnect.py::TestNoEventsLostOnReconnect` + `test_stream_routes_last_event_id.py::TestEndpoint1AutomaticReconnect` |
| §670 frontend action ≤200ms + RBAC + unknown class refused | `test_action_routes_correlation_latency.py` + `test_action_routes.py::TestPerClassScopeEnforcement` + Pydantic 422 |
| §671 elicitation mode parity | `test_elicitation_gate.py::TestModeParityBothModes` + `test_action_routes.py::TestSubmitElicitationModeParity` |
| §672 elicitation data-class refusal + Rego gate proven | `test_action_routes.py::TestSubmitElicitationDataClassRefusal` (no `policy.decision_evaluated` row) + `test_elicitation_rego.py::TestRegoDefaultDenyFormWithRestrictedClass` (direct OPA) |
| §673 elicitation audit linkage | `test_elicitation_gate.py::TestAuditLinkage` (caplog + chain-row scan) |
| §674 schema published with version pin | `test_well_known_routes.py::TestSchemaSnapshotPinned` |

### 7b. Latency test design

**Deterministic** rather than P99 over many iterations:

```python
async def test_action_post_correlation_event_delivered_within_200ms(...):
    async with httpx.AsyncClient(...) as client:
        # subscribe SSE client
        async with client.stream("GET", "/api/v1/ui/tenants/t1/events?families=frontend_action") as sse:
            # fire the POST
            await client.post("/api/v1/ui/actions", json={...})
            # await the correlation event with a deterministic timeout
            event = await asyncio.wait_for(_next_event(sse), timeout=0.2)
            assert event.data["action_class"] == "approve"
```

Single test (optionally parametrized over a small set of action classes — 2-3 cases — for breadth). **P99 over 50 iterations is OPTIONAL diagnostic output** (a separate `pytest.mark.benchmark` test that prints percentile distribution but does NOT fail on percentile thresholds — those are CI-flaky).

### 7c. Threat-model-revert verification list

Per `feedback_security_regression_hardening`, every load-bearing fail-closed/guard is paired with a temporary-revert test that proves the regression catches the failure mode:

| Guard | Revert produces | Test |
|---|---|---|
| Async RBAC denial emit fail-closed | Silent audit loss + bogus 403 | `test_rbac_denial_chain_emission.py::TestFailClosedOnEmitFailure` |
| Boundary dedup-by-event_id | Double-delivery | `test_stream_routes_reconnect.py::TestBoundaryDedup` |
| Deterministic event_id parity live-vs-replay | Replay re-issues different ID | `test_ui_events_chain_cursor.py::TestReplayProducesSameEventIdAsLive` |
| Cursor type_hash assertion at boundary | Silent routing-table drift | `test_ui_events_chain_cursor.py::TestCursorTypeHashDriftDetected` |
| Last-Event-ID malformed fail-closed | Silent URL-cursor fallback | `test_stream_routes_last_event_id.py::TestMalformedLastEventIdFailsClosed` |
| `send_timeout` cleanup | Stalled clients pin slots forever | `test_stream_headers_and_timeout.py::TestSendTimeoutCleansUpHalfOpenClient` |
| `RequireUIAction` emit-failure 500 | Silent audit loss + 403 with no chain row | `test_action_routes.py::TestRequireUIActionFailClosedOnEmitFailure` |
| Chain payload closed-keyset | Unconstrained payload schema; PII leak risk | `test_action_routes.py::TestChainPayloadKeysetClosed` |
| Cursor cross-tenant invisibility | Cross-tenant cursor probe distinguishable from "not found" | `test_stream_routes.py::TestCursorTenantMismatchIs404InvisibleSameAsNotFound` |
| Elicitation gate fail-closed paths (each of 9) | Each branch covered | `test_elicitation_gate.py::test_each_fail_closed_path` (parametrized) |

### 7d. Live-integration boundaries

- **Direct OPA Rego test** — `tests/unit/policies/test_elicitation_rego.py` — `@pytest.mark.opa_required`; skipped without `opa` binary.
- **Postgres + Oracle integration lanes** — existing `python.yml` lanes cover `DecisionHistoryStore.append` for new decision_types (`frontend_action.*`, `rbac.<denial_type>`); no new integration tests beyond SQLite tmp-path unit coverage (mirrors 7B.3 stance).
- **SSE end-to-end** via `httpx.AsyncClient` against a test FastAPI app in unit tests.

## 8. CC promotion + governance inventory

**Critical-controls floor:** 60 (Sprint 7B.3 close) → **63 Python CC modules** at Sprint 7B.4 close (+3: `action_routes.py`, `stream_routes.py`, `elicitation_gate.py`). The typed-projector + cursor encoder + RBACDenialType extensions are absorbed into the already-on-gate `protocol/ui_events.py` so they don't add a separate entry.

**+ stop-rule policy bundles:** `policies/_default/elicitation.rego` (NEW) is added as an explicit stop-rule in AGENTS.md. **The existing `policies/_default/sampling.rego` + `supply_chain.rego` are promoted to explicit stop-rules in the same commit** — their stop-rule status was implicit doctrine pre-7B.4 (per the existing ADR-015 + ADR-002 policy-of-record framing); making it explicit alongside elicitation locks the pattern. Not Python (no CI coverage tracking).

**Final governance inventory** at 7B.4 close: **63 Python CC modules + 3 explicit stop-rule policy bundles** (`sampling.rego` + `supply_chain.rego` + `elicitation.rego`).

## 9. Out of scope / deferred

- **WebSocket transport (ADR-020 Wave-2)** — Wave-1 ships SSE only.
- **Audit-event-backed SSE delivery** (`tool_call.*`, `artifact.*`) — Wave-1 SSE is decision-history-only; combined-cursor / cross-chain ordering deferred to Wave-2.
- **`policy.bundle_loaded` typed projector wiring** — Pydantic model exists; projector entry deferred until Rego hot-reload (Sprint 13.5).
- **Real elicitation adapter implementation** — 7B.4 ships the Protocol + fail-loud kernel scaffold; bank overlays plug in concrete adapters.
- **Run registry / agent-run primitive** — per ADR-001 runs live in Layer-C agent packs; AgentOS doesn't gain a run registry.
- **Runtime approval engine (ADR-014)** — Sprint 13.5; the `approve` / `deny` action POST stubs in 7B.4 swap to live dispatch when it lands.
- **Sandbox checkpoint/wake** — `interrupt` / `resume` stubs similar story; sandbox lands in its owning sprint.
- **Tenant data-governance policy store** — 7B.3 hand-off carry-forward; not 7B.4 per the locked scope decision.
- **`fail_open_exception` build-time manifest shape** — Sprint-7A2 carry-forward; not 7B.4.
- **Realtime auto-attestation API + compliance helper emit path** — Sprint-7A carry-forward.
- **Pre-7B BUILD_PLAN stale-row sweep** — separate docs-hygiene pass.

## 10. References

- **ADR-020** — UI Event-Stream Contract (APPROVED 2026-04-27).
- **ADR-015** — Policy-as-code (`policies/_default/elicitation.rego` follows the bundle structure).
- **ADR-014** — Runtime tool approval (Sprint 13.5; `approve`/`deny` action stubs reference it).
- **ADR-017** — Data governance contracts (`_RESTRICTED_DATA_CLASSES` is the form-mode-refusal class set).
- **BUILD_PLAN.md §602** — Sprint 7B status table; 7B.4 row added at sprint close.
- **BUILD_PLAN.md §640-674** — Sprint 7B deliverables + test specs (including §668-674 the 7 UI-event-stream tests).
- **Predecessor closeouts:**
  - `docs/closeouts/2026-05-15-sprint-7b3-reviewer-evidence-panels-5-gate.md` (Sprint 7B.3 — composer + reviewer evidence panels; 7B.4 hand-off checklist).
  - `docs/closeouts/2026-05-13-sprint-7b2-portal-api-rbac-owasp.md` (portal RBAC primitives + OWASP conformance; the 4 RBAC dep modules 7B.4 async-converts).
- **`feedback_security_regression_hardening`** — threat-model-revert doctrine for the load-bearing guards in Section 7c.
- **`feedback_patch_plan_against_doctrine`** — verify per-task specs against codebase + git reality before executing.
- **`feedback_verify_code_citations_at_doc_write`** — every code citation in this spec verified at file:line via grep/Read in the same compose pass (cite-from-memory forbidden).
