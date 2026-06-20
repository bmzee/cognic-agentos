# ADR-020 — UI Event-Stream Contract (AgentOS Frontend Channel)

## Status
**APPROVED for implementation** on 2026-04-27.

## Context

Per ADR-001 the portal UI is an external artefact, not bundled into AgentOS. But agent-app frontends across the industry (LangGraph SDK, Pydantic AI, OpenAI Agents SDK, Anthropic Managed Agents, AG-UI, CopilotKit) have converged on a **standardised stream of events** between agent runtime and any UI: run-state transitions, tool calls, sub-agent spawns, streamed content, approvals, interrupts, cancellation, resume, artifacts, frontend-initiated actions.

If AgentOS doesn't declare a stable contract for this stream, every UI (Cognic portal, bank portal, third-party dashboard, examiner viewer, ticket-system embed) will invent its own, and the OS/UI boundary degrades into a one-off integration problem per consumer.

The de-facto reference is **AG-UI** (Agent UI) — a draft specification originating from the LangGraph community. AgentOS does not adopt AG-UI verbatim (the spec is still moving) but uses its event taxonomy as the starting point for a Cognic-stable contract.

## Decision

Add a **UI event-stream contract** as a first-class AgentOS protocol, peer to MCP and A2A. The contract:

1. Defines a **typed event schema** (`agent_run.*`, `tool_call.*`, `subagent.*`, `approval.*`, `artifact.*`, `interrupt.*`, `frontend_action.*`)
2. Exposes the stream over **Server-Sent Events (SSE) by default**, with WebSocket as an optional Wave-2 transport
3. Authorises every subscriber via the same per-tenant token + RBAC scopes that gate the rest of the portal API
4. Emits every event into `decision_history` as well as the live stream, so a UI that disconnects + reconnects can pull missed events from the audit log (no event loss across reconnects)
5. Supports **frontend-initiated actions** (approve / cancel / interrupt / resume / submit-form-elicitation) over a paired POST endpoint, with per-action RBAC
6. Bundles a **portable JSON schema** (published at `/.well-known/cognic-ui-events.json`) so any UI in any language can implement the contract without reading our Python source

### Event taxonomy (Wave 1)

| Event family | Events | Purpose |
|---|---|---|
| `agent_run` | `started`, `progress`, `completed`, `failed`, `cancelled`, `paused`, `resumed` | Run-level state machine |
| `tool_call` | `requested`, `approved`, `denied`, `started`, `progress`, `completed`, `failed` | MCP tool invocation lifecycle |
| `subagent` | `spawned`, `completed`, `failed`, `pending`, `recursion_capped` | Sub-agent lifecycle (per ADR-005; `pending` added 2026-06-20 for child approval-retry) |
| `approval` | `pending`, `granted`, `granted_second`, `denied`, `expired` | Runtime tool approval (per ADR-014) |
| `artifact` | `started`, `chunk`, `completed` | Streamed artifact (per A2A artifacts; per ADR-003) |
| `interrupt` | `requested_by_agent`, `requested_by_operator`, `acknowledged` | Mid-run pause for human input |
| `frontend_action` | `submitted`, `accepted`, `rejected` | UI → agent action (approve, cancel, form-fill) |
| `memory` | `recall_started`, `recall_completed`, `forget`, `redact` (per ADR-019) | Memory-aware UIs surface what was recalled |
| `decision_audit` | `event_appended` | Live mirror of decision_history append (subscribers with `audit.read` scope) |
| `policy` | `decision_evaluated`, `bundle_loaded` (per ADR-015) | Policy decisions surfaced for compliance dashboards |
| `kill_switch` | `flipped`, `reverted` (per ADR-018) | Operator console gets emergency state changes |

### Wire format

```json
{
  "event_id": "evt_01HV...",
  "ts": "2026-04-27T14:23:11.123Z",
  "tenant": "bank-a",
  "run_id": "run_01HV...",
  "trace_id": "trace_01HV...",
  "family": "tool_call",
  "type": "approved",
  "data": { ... family-specific ... },
  "audit_chain_hash": "sha256:..."
}
```

`audit_chain_hash` lets a subscribing UI verify the event corresponds to a real decision_history record without trusting the SSE channel alone.

### Subscription endpoints

- `GET /api/v1/ui/runs/{run_id}/events` — SSE stream of events for a single run (bounded by RBAC on the run)
- `GET /api/v1/ui/tenants/{tenant_id}/events?families=...&since=evt_id` — multi-run stream for operator dashboards (RBAC: `ui.tenant_stream`)
- `GET /api/v1/ui/events/since/{event_id}?run_id=...` — cursor-based catch-up endpoint for reconnect scenarios; pulls from `decision_history` (no events lost)

### Frontend action endpoint

- `POST /api/v1/ui/actions` — typed action payload (`approve`, `deny`, `cancel_run`, `interrupt`, `resume`, `submit_elicitation`); RBAC scope per action class; correlation event emitted on the stream within 200ms

#### `submit_elicitation` — must obey MCP elicitation rules

The UI's `submit_elicitation` action is **not** a back door around the MCP elicitation restrictions in `MCP-CONFORMANCE.md`. When the originating server requested an elicitation, the action submission is gated by the **same** rules that govern the underlying MCP server's allowed elicitation modes:

1. **Mode parity** — if the MCP server's manifest declares `elicitation_modes = ["url"]` (Wave 1 default), then `submit_elicitation` accepts only the URL completion signal; submitting a form payload through the UI action is **refused** with `elicitation_mode_not_permitted`. Form-mode action submission requires `elicitation_modes = ["url", "form"]` declared and tenant Rego permitting.
2. **Data-class restriction** — even when form mode is enabled at the manifest layer, `submit_elicitation` form payloads are refused if the originating tool's `data_classes` (per ADR-017) include `customer_pii` / `payment_action` / `regulator_communication`. This is the **same Wave 1 forbidden-classes list** that gates manifest-level form-mode declarations; the UI cannot smuggle around it.
3. **Rego policy** — every `submit_elicitation` is evaluated against `policies/_default/elicitation.rego` with the tenant + originating tool + data classes + payload shape as inputs. Default-deny for form-mode payloads on restricted classes; explicit tenant override is the only path.
4. **Audit linkage** — every `submit_elicitation` action emits an `elicitation.submission` event chain-linked to the originating tool call's `decision_history` record, with the elicitation mode, data classes, payload digest (NOT the payload), and gate outcome.

In short: the UI action surface inherits MCP elicitation policy rather than exposing a parallel surface that bypasses it.

### Auth

Same per-tenant token + RBAC stack as the rest of the portal API. Subscriber identity attached to every received event for filtering. Unauthenticated subscriptions refused (no anonymous event streams).

### What this is NOT

- Not a chat protocol. The event stream carries machine-typed events; chat UI is built on top.
- Not a UI rendering spec. Cards, panels, themes are UI-side concerns.
- Not a replacement for A2A or MCP. Those are agent-to-agent and agent-to-tool wire protocols. UI events are agent-to-frontend.
- Not bundled with any UI. The event stream is exposed by AgentOS; UIs are external (per ADR-001).

## Consequences

### Positive
- **UI / OS boundary stable** — Cognic portal, bank portals, examiner viewers, third-party dashboards all consume the same contract
- **Reconnect-safe** — events mirror to `decision_history`; UIs pull what they missed from the audit log
- **Compliance-aligned** — every event is already in `decision_history`, so the UI surface is automatically auditable
- **Aligned with industry direction** — AG-UI / LangGraph / Pydantic AI / OpenAI Agents SDK frontends will translate cleanly
- **Multi-UI support** — one bank can run a portal for ops + a different dashboard for examiners + a third surface for the ticketing system, all subscribed to the same stream

### Negative
- **New API surface** — versioning + deprecation policy needed; events become a public contract once any external UI consumes them
- **Schema-evolution risk** — adding event types is safe, removing/renaming is a breaking change
- **SSE overhead** — long-lived connections cost; mitigated by per-tenant connection caps + idle-timeout reaping

### Neutral
- AG-UI may evolve faster than Wave 1 plans for. AgentOS event taxonomy intentionally diverges where AG-UI is unstable; we re-converge in Wave 2 if/when AG-UI stabilises

## Implementation phases

| Sprint | Work |
|---|---|
| **Sprint 6 (extends A2A endpoint sprint, explicit +0.5 wu in BUILD_PLAN, Sprint 6 now 2 wu)** | Stub `protocol/ui_events.py` — event-emit hooks at the harness boundary so every existing audit event mirrors to a typed UI event in-process; no SSE endpoint yet |
| **Sprint 7B (extends, explicit +0.5 wu in BUILD_PLAN, Sprint 7B now 3.5 wu)** | SSE endpoints (`GET /api/v1/ui/runs/{run_id}/events`, tenant stream, catch-up); RBAC scopes; `frontend_action` POST endpoint; portable JSON schema published at `/.well-known/cognic-ui-events.json` |
| **Sprint 11.5 (absorbed inside existing 2 wu envelope; not a separate budget line)** | Memory event family (`recall_started`, `recall_completed`, `forget`, `redact`) wired — small enough to fit alongside the memory primitive itself |
| **Sprint 13.5 (absorbed inside existing 3 wu envelope; not a separate budget line)** | Policy + kill-switch + approval event families wired (these all ship in 13.5 anyway, so the typed-event mirroring slots in alongside the audit emit) |
| **Sprint 14 (absorbed inside existing 2 wu envelope; not a separate budget line)** | Operator runbook section: how a bank UI subscribes; sample subscriber; reconnect-cursor playbook |
| **Wave 2** | WebSocket transport optional alternative; AG-UI parity layer if AG-UI stabilises; per-event signing (JWS) for high-sensitivity streams |

Total Wave 1 work added explicitly to the budget: **+1.0 wu** (Sprint 6 +0.5, Sprint 7B +0.5). The remaining ~0.75 wu (Sprint 11.5, 13.5, 14 increments) is absorbed inside those sprints' existing envelopes — they push those sprints further into the optimistic floor (already flagged in the BUILD_PLAN schedule-risk table) but do NOT add to the Phases 1-4 total. No new sub-sprint introduced.

### Schedule impact

Phases 1-4 total is **52.5 work-units** (BUILD_PLAN.md is the authoritative arithmetic; ADR-020 figures match BUILD_PLAN). Calendar per the BUILD_PLAN schedule-floor disclaimer:
- **Floor**: 52.5 wu / 13-14 weeks focused / **18-22 calendar**
- **Midpoint**: ~57 wu / 14-16 weeks focused / **20-25 calendar**
- **Ceiling**: ~62.5 wu / 16-18 weeks focused / **24-29 calendar**

The +1.0 wu from this ADR is already included in the 52.5 floor; the absorbed ~0.75 wu makes Sprints 11.5 / 13.5 / 14 more likely to overrun (they're already on the optimistic-sprint list).

## Sprint 10.5 amendment (2026-05-27) — Wave-1 contract upheld; no new typed `scheduler.*` UI event family

Per ADR-022 §"Cross-ADR amendments / ADR-020" + §"What this is NOT / Not coupled to UI event-stream emission":

> The scheduler emits audit events; the UI event broker (Sprint 7B.4) mirrors them onto its typed streams via the existing decision_history → broker projection — no new emission seam.

Sprint 10.5 (merged via PR #40, squash `6791eec`) implemented this contract verbatim:

### What landed

- The 8-event `scheduler.*` audit-event taxonomy from ADR-022 §"Audit event taxonomy" (`admission_accepted` / `admission_refused` / `task_started` / `task_completed` / `task_failed` / `task_cancelled` / `task_preempted` / `task_expired`) flows through `core/scheduler/storage.py` → `DecisionHistoryStore.append_with_precondition` → `decision_history` rows.
- The Sprint 7B.4 `UIEventBroker` (already on the durable critical-controls coverage gate as part of `protocol/ui_events.py`) mirrors **every** `decision_history` append onto the **existing** `decision_audit.event_appended` typed event via the projection wired in Sprint 6 — same seam every other audit-emitting subsystem uses.
- **Wave-1 family count stays at 11** (the Sprint 7B.4 11-family closed-enum at `protocol/ui_events.py::_WAVE_1_FAMILIES`): `agent_run` / `tool_call` / `subagent` / `approval` / `artifact` / `interrupt` / `frontend_action` / `memory` / `decision_audit` / `policy` / `kill_switch`. No 12th family added for `scheduler`.

### What did NOT land — deliberately

- No new top-level `scheduler` family on the `_WAVE_1_FAMILIES` Final. A first-class typed UI event family with per-event-type Pydantic models for `admission_accepted` / `admission_refused` / `task_started` / `task_completed` / `task_failed` / `task_cancelled` / `task_preempted` / `task_expired` is a **Wave-2 concern** per ADR-022's original §"Cross-ADR amendments / ADR-020" wording. UIs that want scheduler-level observability today filter `decision_audit.event_appended` events by `event.payload.decision_type` matching the `scheduler.*` namespace.
- No new SSE endpoint for scheduler-only streams; tenant + run streams already carry the mirrored `decision_audit.event_appended` events under existing RBAC (`ui.tenant_stream` + `ui.run_stream`).
- No public `.well-known/cognic-ui-events.json` schema change — drift detector at `tests/unit/portal/api/ui/test_well_known_routes.py` was unchanged across Sprint 10.5.

### Bank-overlay consumer contract (carried forward)

UI consumers that need to surface scheduler state today walk the existing `decision_audit.event_appended` stream and dispatch on `payload.decision_type`. The 8 `scheduler.*` decision types are wire-protocol-public via the ADR-022 taxonomy + the `core/scheduler/storage.py` emit sites. When the Wave-2 typed family lands, the existing `decision_audit.event_appended` surface stays — the new typed family is an additive narrowing, not a replacement.

### Reconnect safety upheld

Per this ADR's §"Decision / Reconnect-safe" + Sprint 7B.4's `_DHReplaySnapshot` shape: scheduler-emitted `decision_audit.event_appended` events are replayable from the cursor-based catch-up endpoint identical to every other family. A UI that drops + reconnects pulls missed scheduler events from `decision_history` exactly the same way it pulls missed `policy.decision_evaluated` events.

### Wave-2 follow-up tracked

A future ADR-020 amendment (post-Phase-4 telemetry or bank demand) will introduce the typed `scheduler.*` family with the 8 per-event-type Pydantic models. Open question for that amendment: whether `scheduler.admission_refused` should split into 5 typed sub-events keyed by `payload.reason` (one per refusal closed-enum value) or stay as one event with the discriminated-payload union. Deferred until then.

**No semantic change to ADR-020's existing decisions** — Sprint 10.5 is a confirmation of the original cross-ADR amendment contract, not a renegotiation.

## Sub-agent child approval-retry amendment (2026-06-20) — additive `subagent.pending` event

A new backward-compatible `SubagentPending` event (`type="pending"`) is added to the **subagent** family (per ADR-005's child approval-retry amendment). `_project_subagent_return` routes a `subagent.return` chain row whose `payload['outcome'] == "pending_approval"` to it, carrying the `approval_request_id` + child `run_id` so a UI can render "awaiting approval" + a deep link; the conservative `completed`/`failed`/unknown-→-`failed` projections are byte-for-byte unchanged.

- **Wave-1 family count stays at 11** — `pending` is a new event TYPE within the existing `subagent` family, NOT a 12th family. The `_WAVE_1_FAMILIES` Final is untouched.
- **Backward-compatible-additive** per the stop-rule: a new `$defs.SubagentPending` + a new `discriminator.mapping.pending` + an appended `oneOf` arm in `.well-known/cognic-ui-events.json` (the snapshot diff is purely these 3 additive entries); existing entries unchanged. The replay-snapshot drift test stays green (the projector always returns a typed event). `SubagentPending` is registered in `_TYPED_PROJECTION_CLASSES` + `__all__` (mirroring its siblings).

## References
- ADR-001 (UI is external — this contract is the interface)
- ADR-003 (A2A artifacts → mirror to artifact events on the UI stream)
- ADR-005 (sub-agent → spawn events on the UI stream)
- ADR-014 (runtime tool approval → approval event family)
- ADR-015 (policy → policy event family)
- ADR-017 (data governance → event payloads carry data-class metadata so UIs can render redaction badges)
- ADR-018 (emergency controls → kill-switch event family)
- ADR-019 (memory → memory event family)
- ADR-022 (runtime scheduler — Sprint 10.5 confirmed: no new typed UI event family; scheduler audit flows through `decision_audit.event_appended`; Wave-2 deferred)
- [AG-UI specification (draft)](https://github.com/ag-ui-protocol/ag-ui)
- [LangGraph streaming docs](https://langchain-ai.github.io/langgraph/concepts/streaming/)
- [OpenAI Agents SDK — streaming events](https://openai.github.io/openai-agents-python/)
- [Anthropic Managed Agents — durable session events](https://www.anthropic.com/engineering/managed-agents)
- [Server-Sent Events spec](https://html.spec.whatwg.org/multipage/server-sent-events.html)
- [RFC 6750 — Bearer token usage on SSE](https://datatracker.ietf.org/doc/html/rfc6750)
