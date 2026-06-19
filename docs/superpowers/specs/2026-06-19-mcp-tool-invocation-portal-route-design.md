# MCP tool-invocation portal route — live-exercise `call_tool` + the approval seam — Design

**Date:** 2026-06-19
**Status:** DRAFT — design approved in brainstorming (2026-06-19); awaiting spec review before planning.
**ADRs:** amends **ADR-002** (MCP plugin protocol) — adds the production MCP-invocation surface deferred at Sprint 13.8 ("Fork D"). Consumes **ADR-014** (runtime tool approval) via the existing `_approval_gate`.

## Context

Sprint 13.8 production-constructed `MCPHost` in the `create_app` lifespan (SDK-gated, fail-soft, seeded with `MCPServerEntry` from the registered packs), but left it **dormant** — the lifespan comment reads *"Dormant until a caller invokes call_tool (Fork D)."* The host's two public methods are **fully built + unit-tested**:
- `call_tool(*, server_id, tool_name, arguments, request_id, tenant_id, originator_subject="", approval_request_id=None) -> CallResult` — owns the ADR-014 risk-tier gate, the **engine-authoritative `_approval_gate`** (mint-pending / verify-grant), auth-retry semantics, the transport send, and full audit + decision-history evidence.
- `list_tools(*, server_id, request_id, tenant_id) -> list[Any]` — token→open→SDK-list→close, returning the **fully-walked flat catalogue** (server-side pagination, cycle detection, page cap, opaque-cursor fingerprinting, and TTL caching are all internal; no pagination contract leaks to the caller).

What is missing is the **production caller**. This slice adds a standalone portal MCP-invocation surface (`portal/api/mcp/`) that live-exercises `call_tool` + `list_tools` and **closes the dormant approval path** end-to-end (first call → `202 + approval_request_id`; grant via the existing approvals surface; re-call with `approval_request_id` → proceed). It mirrors the proven 14A run-route pattern.

**Locked in brainstorming (2026-06-19):** Fork A — a standalone portal route (NOT managed-run integration; B/C deferred). The route contract, the two-route surface (list + call), the scopes, and the status map are all locked below.

## Goal

A new `portal/api/mcp/` module (`dto.py` + `routes.py`, mirroring `portal/api/runs/`) with **two routes**, each a thin production caller of `app.state.mcp_host`:

- `GET /api/v1/mcp/servers/{server_id}/tools` — list (scope `mcp.tool.list`).
- `POST /api/v1/mcp/servers/{server_id}/tools/call` — invoke (scope `mcp.tool.invoke`).

This turns already-built substrate into a live-exercised surface + consumes the wired-but-dormant approval seam, fully in-session-verifiable.

## Non-goals (guards — locked)

- **No managed-run MCP integration** (Fork B/C deferred — *which* tool an agent invokes is pack/agent-loop territory).
- **No change to `call_tool` / `list_tools` / `_approval_gate` / the host itself** — they are built; this slice is the caller + the scopes + the mount. `protocol/mcp_host.py` (critical-controls) is **consumed, not modified**.
- **No startup MCP discovery / trust-registration change** — the host is already seeded with `MCPServerEntry` from the registered packs; this slice operates on whatever servers are registered (a fresh deployment with no registered MCP packs returns `404` per the contract).
- **`tool_name` stays raw in the request body, NEVER in a URL path segment.** The host preserves raw tool identity for canonical audit (its tests cover control-character / log-injection tool names preserved verbatim, with operator-facing sanitization defended separately). Imposing URL-segment decoding on it would be a latent corruption bug.
- **CC count stays at its current value (131).** No new on-gate module (the route module is off the durable coverage gate, like `portal/api/runs/routes.py`); the RBAC edits are additive to already-on-gate modules.

## Design

### 1. The two routes

Both live under `/api/v1/mcp`, served by a single `build_mcp_routes() -> APIRouter` factory; `from __future__ import annotations` is **omitted** (the standing FastAPI `inspect.signature()` invariant for closure-local `Annotated[..., Depends(...)]`). Both take the actor from the `RequireScope` dependency (tenant_id = `actor.tenant_id`, originator_subject = `actor.subject`) and the host from a shared request-time dependency.

**`GET /api/v1/mcp/servers/{server_id}/tools`** (scope `mcp.tool.list`)
- No body. `request_id` server-minted `mcp-list-<uuid4.hex>`.
- Calls `host.list_tools(server_id=…, request_id=…, tenant_id=actor.tenant_id)`.
- `200` → `{ "tools": [<descriptor>, …] }` (the flat catalogue). No approval path.
- Statuses: `200` / `403` / `404` / `502` / `503` / `504`.

**`POST /api/v1/mcp/servers/{server_id}/tools/call`** (scope `mcp.tool.invoke`)
- Body `CallToolRequest`: `{ "tool_name": str, "arguments": dict, "approval_request_id": str | null }` (`extra="forbid"`; `tool_name` non-empty; `arguments` defaults to an empty dict via `Field(default_factory=dict)`; `approval_request_id` parsed to `uuid.UUID` when non-null). `request_id` server-minted `mcp-call-<uuid4.hex>`.
- Calls `host.call_tool(server_id=…, tool_name=body.tool_name, arguments=body.arguments, request_id=…, tenant_id=actor.tenant_id, originator_subject=actor.subject, approval_request_id=<parsed|None>)`.
- Statuses: `200` / `202` / `403` / `409` / `404` / `502` / `503` / `504`.

### 2. The status map (exception → HTTP), grounded in the closed enums

| Status | Trigger | Source |
|---|---|---|
| **200** | `CallResult` (call) / the tool list (list) | success |
| **202** | `MCPToolInvocationRefused("tool_approval_pending")` → body `{ "reason": "tool_approval_pending", "approval_request_id": <minted id> }` | call only |
| **403** | RBAC `scope_not_held`; `MCPToolInvocationRefused("tool_approval_denied" \| "tool_approval_engine_not_available")` | RBAC / call |
| **409** | `MCPToolInvocationRefused("tool_approval_expired" \| "tool_approval_binding_mismatch" \| "tool_approval_request_not_found")` | call (re-request conflicts) |
| **404** | `_lookup_server` `LookupError` → `server_not_found` (server_id not registered / not visible to this tenant) | both |
| **503** | `app.state.mcp_host is None` (MCP SDK absent / construction failed) — the request-time dep | both |
| **504** | **timeout** reasons — `MCPTransportError("mcp_call_tool_timeout" \| "mcp_session_open_timeout")` and `MCPAuthzError("mcp_oauth_request_timeout")`, i.e. the closed `_TIMEOUT_REASONS` set | both |
| **502** | **every other** `MCPTransportError` reason (`mcp_transport_send_failed`, `mcp_session_open_failed`, `mcp_session_close_failed`, `mcp_session_closed`), **every other** `MCPAuthzError` reason (`mcp_authorisation_lost`, `mcp_step_up_unauthorised`, `mcp_as_not_allowlisted`, `mcp_token_audience_mismatch`, `mcp_token_scope_overgrant`, `mcp_anonymous_refused`, `mcp_oauth_transport_failure`, `mcp_oauth_credentials_missing`, `mcp_oauth_as_discovery_invalid`, …), and the generic `mcp_orchestrator_error` | both |

**Mapped by exception class, not by enumerating reasons (drift-proof).** The route catches `MCPTransportError` and `MCPAuthzError` and returns `504` iff `.reason` is in the closed `_TIMEOUT_REASONS = {"mcp_call_tool_timeout", "mcp_session_open_timeout", "mcp_oauth_request_timeout"}`, else `502`; the generic catch-all → `502`. So a future *non-timeout* transport/authz reason auto-maps to `502` — a **deliberate** `5xx`, never a leaked `500` — and a future *timeout* reason is a one-line addition to `_TIMEOUT_REASONS` (test-pinned). This is what makes the pre-dispatch token/discovery `MCPAuthzError` reasons (`mcp_as_not_allowlisted`, `mcp_oauth_as_discovery_invalid`, …) that `call_tool` re-raises at its dispatch site (`mcp_host.py:1395`) map correctly instead of leaking. The full `MCPTransportReason` (6) and `AuthzReason` (11+) enums live in `protocol/mcp_transports.py` + `protocol/mcp_authz.py` and are wire-public there — the route consumes them by class + the timeout set; it does NOT redefine them.

**The 4xx split is principled:** `4xx` = the caller's problem (missing scope; bad/stale approval state; unknown server); `5xx` = the kernel→upstream problem (no host; upstream transport/timeout; upstream auth rejected after retry). The wire-public closed-enum **`reason`** rides the `4xx`/`5xx` body, mirroring the run route's `reason` field. The `MCPToolInvocationRefused` 6-value enum is wire-protocol-public + drift-pinned (`test_mcp_approval_seam.py::test_tool_invocation_refusal_reason_has_exactly_six_values`) — the status map consumes it but does NOT redefine it.

### 3. The approval flow (202 → grant → re-call) is a real production path

`call_tool`'s `_approval_gate` already implements the exact run/sandbox pattern:
- **First call** (`approval_request_id=None`), tool needs approval → the engine **mints a request** and `call_tool` raises `MCPToolInvocationRefused("tool_approval_pending")` carrying the minted `approval_request_id`. The route returns **202** + that id.
- The operator **grants** via the **existing approvals surface** (`portal/api/approvals/routes.py`, `ToolApprovalRBACScope` — e.g. `tool.approve.customer_data`). This slice adds NO approval-grant surface; it reuses what exists.
- The caller **re-calls** with the **same** `server_id` / `tool_name` / `arguments` + the granted `approval_request_id`. The gate verifies the grant (tenant-scoped, binding-checked) → proceed → `200`. A mismatched binding → `409 tool_approval_binding_mismatch`; an expired grant → `409 tool_approval_expired`; an unknown id → `409 tool_approval_request_not_found`.

### 4. DTOs (`portal/api/mcp/dto.py`)

- `CallToolRequest` — `{ tool_name: str, arguments: dict[str, Any] = Field(default_factory=dict), approval_request_id: str | None = None }`, `extra="forbid"`, `tool_name` `min_length=1` (the explicit `default_factory` for the mutable field per the repo's recent convention, not a bare `= {}`). `tool_name` is **passed through raw** to `call_tool` (never path-encoded, never sanitized at the route — the host owns audit-canonical raw identity).
- `CallToolResponse` (200) — projects `CallResult`: `{ payload, request_id, server_id, tool_name, mcp_session_id, as_issuer, scopes, client_id }` (the correlation IDs examiners replay against the audit chain per MCP-CONFORMANCE §Authorization item 9).
- `ListToolsResponse` (200) — `{ tools: list[Any] }` (the flat catalogue; descriptors pass through as the host returns them — already deep-copy-isolated from the cache).
- The refusal/error body is the minimal `{ reason: <closed-enum>, … }` (202 adds `approval_request_id`).

### 5. Actor-binding, server-minted `request_id`, host dependency

- `RequireScope("mcp.tool.invoke" | "mcp.tool.list")` returns the bound `Actor`; `tenant_id` + `originator_subject` come **only** from the actor (never the body/path) — the run-route discipline.
- `request_id` is **server-minted** (`mcp-call-<uuid4.hex>` / `mcp-list-<uuid4.hex>`), bounded ≤64 to fit the `decision_history.request_id` `String(64)` cap (module-foot `assert` like the pack routes; the prefix is 9 chars + 32 hex = 41 ≤ 64). NOT client-supplied.
- A shared request-time dependency `_require_mcp_host(request) -> MCPHost` raises `HTTPException(503, {"reason": "mcp_host_unavailable"})` when `request.app.state.mcp_host is None` (mirrors the run route's `_require_managed_run_executor` → 503 `sandbox_runtime_unavailable`).

### 6. Scopes wiring (3 spots — the run-route precedent)

- `portal/rbac/scopes.py`: `MCPRBACScope = Literal["mcp.tool.list", "mcp.tool.invoke"]` (plain `= Literal[...]`, value-disjoint from the other scope Literals) + `MCP_SCOPES` frozenset (1:1) + the `← route` doc-comment block. A drift-detector test pins the exact 2-value set + disjointness (mirroring the run/tool-approval scope tests).
- `portal/rbac/actor.py`: widen `Actor.scopes`'s union with `| MCPRBACScope`.
- `portal/rbac/enforcement.py`: widen the `RequireScope` `scope` param union with `| MCPRBACScope`.

`portal/rbac/{scopes,actor,enforcement}.py` are critical-controls (on the durable gate) — the edits are **additive** and must keep coverage (the new scope-partition drift test carries it). No new gate module; CC count unchanged.

### 7. Mounting + import-cleanliness

- `app.py` mounts `build_mcp_routes()` **unconditionally** under `/api/v1/mcp` (the run-route eval-router pattern at `app.py:1328`); the request-time 503 dep handles the SDK-absent / construction-failed case. No `is_mcp_available()` gate at mount time.
- **Import-cleanliness (verified):** `protocol/mcp_host.py` has **zero module-level `mcp`-SDK imports** (the `require_mcp()` gate is constructor-only), so `routes.py` imports `MCPToolInvocationRefused`, `MCPTransportError`, `CallResult`, `ToolInvocationRefusalReason` (and `MCPAuthzError` from `protocol/mcp_authz.py`) **kernel-image-clean** for the status mapping. Confirmed by a simulated-kernel-image import probe during recon.

### 8. Testing (in-session, fully verifiable)

FastAPI `TestClient` + `create_app` with a **registered fixture MCP pack** (so the host has an `MCPServerEntry`), a **mock transport** (the SDK `ClientSession.call_tool` / `list_tools` as `AsyncMock`), and a **real `ApprovalEngine`** for the approval proof:
- `list` → `200` flat catalogue; `call` success → `200` `CallResult` projection.
- **The approval proof** — a high-risk-tier tool: first `POST …/call` → `202` + `approval_request_id`; `grant()` (real engine, distinct human + `tool.approve.*` scope); re-`POST` with `approval_request_id` → `200`.
- The status mappings, **exercising the map-by-class split** — `404` (unknown server_id); `504` (mock raises `MCPTransportError("mcp_session_open_timeout")` — a timeout reason beyond `mcp_call_tool_timeout`); `502` (mock raises `MCPTransportError("mcp_transport_send_failed")` **and** a non-listed `MCPAuthzError("mcp_as_not_allowlisted")` — proving the pre-dispatch authz class maps deliberately, not a leaked `500`); `503` (`app.state.mcp_host = None`); `403` (scope miss); `409` (approval-state — expired/mismatch/not-found). A drift test pins `_TIMEOUT_REASONS` against the live `MCPTransportReason` + `AuthzReason` enums (a new non-timeout reason must NOT silently become `504`).
- The `request_id` bounded-invariant (≤64) + the **`tool_name`-raw-preservation** test (a control-character `tool_name` reaches `call_tool` verbatim and is never path-encoded/sanitized by the route).

## Tasks (high-level; the plan expands each)

- **T1** — scopes wiring: `MCPRBACScope` + `MCP_SCOPES` in `scopes.py`; the `Actor.scopes` + `RequireScope` union widenings; the scope-partition drift test (RBAC stop-rule edit; keep coverage).
- **T2** — `portal/api/mcp/dto.py`: `CallToolRequest` / `CallToolResponse` / `ListToolsResponse` + the refusal envelope.
- **T3** — `portal/api/mcp/routes.py`: `build_mcp_routes()` + the two handlers + `_require_mcp_host` (503) + the actor-binding + the server-minted `request_id` + the full exception→status mapping (`from __future__` omitted; the request-id bounded-invariant assert).
- **T4** — `app.py`: unconditional mount under `/api/v1/mcp`.
- **T5** — tests: the list/call success paths, the 202→grant→re-call approval proof, every status mapping, the `request_id` + `tool_name`-raw invariants.
- **T6** — docs: ADR-002 amendment (the Fork-D production surface), AS_BUILT (the dormant→live transition for the MCP host), AGENTS (the new route + scopes), MCP-CONFORMANCE if the public invocation surface needs a note.
- **T7** — closeout gate (ruff/format/mypy + full suite + the critical-controls gate on fresh `--cov-branch`; confirm the route module is off-gate + the RBAC modules keep coverage + CC count unchanged).

## Posture

CC count stays **131** (no new on-gate module — the `portal/api/mcp/` route module is off the durable coverage gate, the run-route precedent; the `portal/rbac/` edits are additive to already-on-gate modules and keep coverage). `protocol/mcp_host.py` + the approval engine are **consumed, not modified**. No migration. No new dependency (the `mcp` SDK stays an optional `adapters` extra; the route is SDK-free and degrades to `503` when the host is absent). This slice turns the 13.8-constructed MCP host from dormant into a **live-exercised production surface** and closes the wired-but-dormant approval path.
