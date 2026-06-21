# A2A Inbound Reachability (receiver-only, Wave-1) — Design Spec

> **Status:** DRAFT — pending user review before writing-plans.

## Problem

The entire A2A inbound stack is production-grade *logic* but **unreachable**: no HTTP route is mounted, and `portal/api/app.py:1540-1552` explicitly defers the mounts ("T9 will mount `routes.a2a`…"). A bank deploying AgentOS today cannot receive a single A2A request — every Wave-1 A2A capability is present in code and absent from the wire.

This slice makes the **receiver core** reachable: a route around the ready `A2AEndpoint.handle()` for the `message/send` method, plus the one endpoint safety-gate that a correct receiver requires. It is the first cut of the "Protocol Reachability" epic; **MCP startup discovery is the immediately-following slice**, and the A2A auxiliary surfaces are a **follow-on**.

## Scope

**IN:**
1. A new receiver route `POST /api/v1/a2a/{target_agent}` (`portal/api/a2a/`, off-gate).
2. A Wave-1 method gate inside `A2AEndpoint.handle()` (on-gate `protocol/a2a_endpoint.py`).
3. Two new closed-enum reasons in `protocol/a2a_errors.py` (on-gate).
4. SDK-gated lifespan construction + mount in `portal/api/app.py` (off-gate).

**OUT (deferred, documented non-goals):**
- The auxiliary A2A methods/surfaces — `tasks/get`, `tasks/cancel`, `message/stream`, artifacts, capabilities — all refused `unsupported_operation` until their own follow-on slice (their handler/emitter/store logic already exists but is off `handle()`'s path; mounting each is fresh route design, not adapter work).
- Host-based tenancy (a later resolver-implementation swap).
- MCP startup discovery / trust-registration (the next slice).

## Design

### 1. The receiver route — `portal/api/a2a/` (NEW, off-gate)

Three files mirroring `portal/api/runs/` + `portal/api/subagents/`: `__init__.py`, `dto.py`, `routes.py`. `from __future__ import annotations` is **INTENTIONALLY OMITTED** (the FastAPI `Annotated[..., Depends(...)]` resolution invariant).

- `build_a2a_routes() -> APIRouter` registers `POST /api/v1/a2a/{target_agent}`, mounted **UNCONDITIONALLY** by `create_app` (eval/runs/subagents pattern). **No portal `RequireScope`** — the A2A pinned token is the auth axis, validated inside `handle()` (Gate 2).
- **Dumb raw-body adapter.** The handler: reads the raw body (`await request.body()` → `bytes`), the `Authorization` and `A2A-Version` headers, mints/propagates `request_id` + `parent_trace_id` (standard correlation), resolves the claimed tenant via the seam (below), then calls `endpoint.handle(target_agent=<path param>, payload=<raw bytes>, authorization_header=…, a2a_version_header=…, parent_trace_id=…, tenant_id=<claimed>, request_id=…)`. **The route never parses the JSON-RPC body** (the `X-Cognic-Tenant` header is the only thing it reads beyond the raw passthrough).
- **Tenant-source seam** `resolve_a2a_tenant(request) -> str`, route-local. Wave-1 implementation reads the `X-Cognic-Tenant` header. Missing/empty → the route raises an A2A-shaped refusal carrying the new closed reason `a2a_tenant_header_missing` (→ `invalid_request`), serialized through the `a2a_errors` envelope builder — **never a raw 500**. Later host-based tenancy swaps ONLY this function; `handle()` and the route contract are untouched. (Security note: the claimed tenant is *not trusted* — `A2AAuthzClient` validates the token against it and rejects forged claims, so the seam is conveyance, not a trust boundary.)
- **`_require_a2a_endpoint(request)` dep** returns the `A2AEndpoint` off `app.state.a2a_endpoint`, or raises `503` `a2a_endpoint_unavailable` when the SDK-gated lifespan did not populate it (mirrors `_require_managed_run_executor` / `_require_mcp_host`).
- **Request DTO** (`dto.py`): the route body is raw bytes (no Pydantic model for the JSON-RPC payload — `handle()` owns decoding). A small response-shaping helper serializes `handle()`'s `dict` + the chosen HTTP status.

### 2. The Wave-1 method gate — `protocol/a2a_endpoint.py` (ON-gate, critical control)

`handle()` today has **no `message/send` method gate**: its only `method_not_found` sites (`:532,538`) are the unknown-*target-agent* routing gate (Gate 4). A non-send method (`tasks/cancel`, `tasks/get`, `message/stream`) therefore passes Gates 1-4 and **mis-dispatches at Gate 5** (mints a task + calls `agent.handle()`) — a protocol-boundary bug that mounting the route would expose.

Add a Wave-1 method-allow-list gate inside `handle()`:
- **Placement (LOCKED):** after the version gate (Gate 1), the authz gate (Gate 2), and the Wave-2 feature-refusal gate (Gate 3) — and **before any task-id mint, any `TaskState` transition, the routing/target resolution (Gate 4), or the `agent.handle()` dispatch (Gate 5)**. It piggybacks on the JSON-RPC method already decoded by the Wave-2 scan.
- **Behaviour:** permit only `message/send`. Anything else → `A2AEndpointError(method_not_supported_wave1)` (→ `unsupported_operation`), emitting the same refusal-evidence chain row (audit + decision_history, carrying parent/child trace + payload digest + target + code) the other gate refusals emit.
- **Side-effect contract (LOCKED, test-pinned):** when the gate fires, there are **NO** side effects except the single refusal-evidence row — no task id minted, no task transition, no routing dispatch, no `agent.handle()` call.

### 3. The error taxonomy — `protocol/a2a_errors.py` (ON-gate, critical control)

Two additive closed-enum reasons on `A2APolicyRefusalReason`, each added to the `_POLICY_REASON_TO_SPEC_CODE` mapping (codomain into `A2AErrorCode`):
- `method_not_supported_wave1` → `unsupported_operation` (the wave-honest code, consistent with the existing `streaming_not_supported`/`wave2_feature_refused → unsupported_operation`; means a future auxiliary slice merely *lifts the gate*, never flips a "not found" into a "found").
- `a2a_tenant_header_missing` → `invalid_request` (a *request-shape* failure, deliberately distinct from the *auth* failures `tenant_token_invalid`/`anonymous_refused` so audits can tell "no claimed tenant header" apart from "token rejected").

The closed-enum-completeness + codomain drift detectors in `tests/unit/protocol/test_a2a_errors*.py` extend to both new values.

### 4. Auth / tenant / trace flow

`POST /api/v1/a2a/{agent}` with `Authorization` (A2A pinned token) + `A2A-Version` + `X-Cognic-Tenant` → route resolves the claimed tenant → `handle()` runs the gate stack in fixed order: **version → authz (validates the token *against* the claimed tenant, `a2a_authz:243-255`) → Wave-2 refusal → [NEW] method gate → routing → dispatch** → returns the JSON-RPC `dict` → the route maps it to an HTTP response.

### 5. Lifespan wiring — `portal/api/app.py` (off-gate)

SDK-gated (the `a2a-sdk` is an optional `adapters` extra; `is_a2a_available()` already gates the startup log at `:1553`). Inside the lifespan, when available: construct `A2AAuthzClient` (Vault-backed per-tenant token store) + `A2AEndpoint` (needs `runtime.audit_store` / `decision_history_store` + the authz client + the agent-resolving `PluginRegistry`), store on `app.state.a2a_endpoint`, fail-soft (a construction failure leaves it `None` + an ERROR log; the route then 503s). `build_a2a_routes()` is mounted unconditionally regardless. (Exact constructor deps are a harness-verify point for the plan.)

## Dependency: agent registration (interaction with the MCP-discovery slice)

`handle()` resolves `target_agent` via the `PluginRegistry` under the `agents` PluginKind and dispatches to the registered pack's `agent.handle()` (`a2a_endpoint.py:9-10`). That **same registry is empty at default startup** until discovery/trust-registration is wired — which is the *next* slice's concern (the registry is shared with MCP). So this slice makes the **endpoint + full gate stack reachable and correct**: version, authz, Wave-2, the new method gate, and the routing gate's `unknown_target` path all return their proper A2A responses **with no registered agent**. A *successful* `message/send` dispatch to a registered agent is exercised in tests via an injected/stub-registered agent (the existing endpoint-test pattern); end-to-end successful dispatch **in a default production deploy** follows once the registry is populated by the next slice. This coupling is exactly why the two reachability slices are sequenced back-to-back — and it means the honest closeout claim for *this* slice is "the A2A receiver + gate stack is reachable and correct," not "A2A end-to-end works in a default deploy" (that lands with the registry slice).

## Error / status contract

| Outcome | HTTP status | Body |
|---|---|---|
| `message/send` success | `200` | `handle()`'s JSON-RPC response dict |
| Any `A2AEndpointError` (version / authz / Wave-2 / method gate / routing / dispatch) | `error.http_status` from the `a2a_errors` taxonomy (e.g. `invalid_request`→400, `method_not_found`→404, `internal_error`→500) | the JSON-RPC error envelope |
| Missing/empty `X-Cognic-Tenant` (route, pre-`handle()`) | `400` (`invalid_request`) | A2A envelope, reason `a2a_tenant_header_missing` |
| `app.state.a2a_endpoint` unset (SDK-gated) | `503` | `{"reason": "a2a_endpoint_unavailable"}` |

The route owns **no bespoke code→status map** — it reads `http_status` off the taxonomy.

## Testing

- **Route (off-gate, thorough):** unconditional mount; `503` when the endpoint is unwired; `200` + envelope passthrough on success; `A2AEndpointError` → the taxonomy `http_status` (parametrized across version/authz/method-gate/routing codes); tenant resolver — header present → claimed tenant threaded into `handle()`; missing/empty → A2A-shaped `invalid_request` (`a2a_tenant_header_missing`), **not 500**; raw-body passthrough (route does not parse JSON-RPC).
- **Endpoint method gate (on-gate, CC discipline, negative-path):** `message/send` proceeds to dispatch; `tasks/cancel` / `tasks/get` / `message/stream` / a garbage method → refused with `method_not_supported_wave1` **before** task creation/dispatch — assert **no task minted, no transition, no `agent.handle()` call**, exactly **one** refusal-evidence chain row.
- **`a2a_errors` (on-gate):** both new reasons in the closed enum + the codomain mapping; drift detectors updated.
- **Conformance:** one A2A-conformance test pinning the Wave-1 receiver posture (accepts `message/send`, refuses the other methods `unsupported_operation`).

## CC / ADR / migration posture

- **No new gate module** — the route + DTO + tenant seam are off-gate (the `runs`/`subagents` precedent: trust is upstream in the on-gate endpoint + authz). **CC count unchanged.**
- The two on-gate edits (`a2a_endpoint.py` method gate, `a2a_errors.py` reasons) are **additive** and ride critical-control discipline (≥95% line / 90% branch, negative-path, drift) under **ADR-003**. Requires `core-controls-engineer` + `/critical-module-mode`.
- **ADR-003 amendment:** the inbound receiver route + the Wave-1 method gate + the `unsupported_operation`-for-deferred-methods posture. **AS_BUILT** update. **No migration.**

## Harness-verify points (for the plan — don't guess)

- The exact `A2AEndpoint` + `A2AAuthzClient` constructor dependencies (mirror the MCP-host lifespan build; confirm against `a2a_endpoint.py:378` + `app.py` MCP block).
- The precise insertion point + decode reuse for the method gate inside `handle()` (confirm the Wave-2 scan's decoded `method` is reachable there).
- Whether `request_id` / `parent_trace_id` have standard route-level sources elsewhere in `portal/api/` to mirror.
- The existing `a2a_errors` envelope-builder signature the route reuses for the route-level `a2a_tenant_header_missing` refusal.
