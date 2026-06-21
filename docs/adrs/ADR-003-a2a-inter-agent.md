# ADR-003 — A2A Protocol for Inter-Agent Communication

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

Per ADR-001 + ADR-002 agents are plugin packs. They need a standardised way to talk to each other — orchestrator-worker spawning (per ADR-005) and cross-pack delegation are both inter-agent calls.

Custom Cognic-specific RPC would work but locks the architecture into a Cognic-only world. Industry has converged on A2A.

## Decision

Adopt **A2A (Agent2Agent) Protocol** as the inter-agent communication standard.

### Inbound A2A
`cognic_agentos.protocol.a2a_endpoint.A2AEndpoint` exposes the A2A receiver. Incoming messages identify the target agent by entry-point name; the endpoint resolves via the plugin registry and dispatches to the agent pack's `handle(message)` method.

### Outbound A2A
The harness exposes `spawn_subagent(target_agent, prompt, policy)` which constructs an A2A message addressed to the target pack and dispatches via the local A2A endpoint (or a remote A2A endpoint if the target lives in a different process / pod).

### Message envelope (illustrative only — actual wire format is A2A 1.0)

> ⚠️ **The Python dict below is illustrative.** It shows the *fields we depend on at the application layer* — sender identity, target agent, capability, payload, parent trace id, policy. **The actual wire format is the official A2A 1.0 specification** ([https://a2a-protocol.org/dev/specification/](https://a2a-protocol.org/dev/specification/)).
>
> **Canonical data model:** A2A 1.0 declares its canonical data model in **Protocol Buffers (protobuf)**. JSON Schema and other bindings are spec-published derivations of the protobuf source. AgentOS treats the protobuf schemas as the source of truth; `protocol/a2a_schema.py` is generated from those `.proto` files (or pulled as Pydantic from spec-published JSON-schema bindings, with a parity check against protobuf). `test_a2a_schema_drift.py` validates **both** — the protobuf source and the JSON-schema binding — against upstream.
>
> AgentOS implementation follows the spec's data model, error codes, message structure, and capability negotiation — not this Python sketch. Sprint 6 ships `protocol/a2a_schema.py` plus `tests/fixtures/a2a-conformance/` running official conformance fixtures. This dict survives in the ADR only to communicate *what semantic data flows through* an A2A call; nothing in it is a wire-protocol commitment.

```python
# Application-layer view of an A2A message (NOT the wire format):
{
    "sender": "urn:cognic:agent:rm_copilot:0.5.0",
    "target_agent": "aml_investigation",
    "capability": "verify_customer",
    "payload": {"customer_id": "...", "context_summary": "..."},
    "parent_trace_id": "<workflow_trace_id>",  # for chain hash
    "policy": {  # negotiated per ADR-005
        "max_token_budget": 16000,
        "wall_time_s": 60,
        "tool_allow_list": [...]
    }
}
```

### A2A 1.0 feature scope (Wave 1 vs Wave 2 vs deferred)

A2A 1.0 spec includes more than just message envelopes. Each feature category has explicit Wave 1 / Wave 2 / Deferred classification (full matrix in `docs/A2A-CONFORMANCE.md`):

| Feature | Wave 1 | Wave 2 | Deferred |
|---|---|---|---|
| **Agent Cards** (publishable agent identity descriptors) | Required — every agent pack ships an AgentCard JSON, **JWS-signed** by the same trust root that signs the wheel; outbound calls verify the target's card signature before dispatch | — | — |
| **Tasks** (request/response unit) | Required | — | — |
| **Streaming messages** (server-sent events to caller) | Required | — | — |
| **Artifacts** (output blobs > inline JSON, e.g. PDFs, evidence packs) | Required | — | — |
| **Push notification config** (caller subscribes for completion) | Optional | Required | — |
| **Multi-modal payloads** (audio/video) | — | Required | — |
| **Long-running task resumption** (caller reconnects to in-flight task) | Optional | Required | — |
| **Federated A2A across organisations** (cross-bank agent calls) | — | — | Wave 3 |
| **Anonymous/unauthenticated A2A** | — | — | Out of scope |

Banks consuming or producing A2A traffic must check `docs/A2A-CONFORMANCE.md` for the per-feature Wave-status matrix.

### Version negotiation (`A2A-Version` header)

A2A 1.0 specifies version negotiation via the `A2A-Version` HTTP header on every request. AgentOS conforms to the spec's behaviour exactly:

| Inbound header | AgentOS behaviour |
|---|---|
| `A2A-Version: 1.0` (matches our pinned version) | Accepted; processing continues |
| `A2A-Version` header absent (caller doesn't declare a version) | **Per A2A 1.0 spec, an absent header is interpreted as version `0.3`.** AgentOS does not bundle a 0.3 implementation, so the request is **rejected** with `VersionNotSupportedError` and a `Supported-A2A-Versions: 1.0` response header — pushing the caller to declare 1.0 explicitly. A warning is logged so operators can spot non-conforming callers. (We do not silently upgrade absent-header to `1.x`; the spec is explicit and we honour it.) |
| `A2A-Version: 0.x` (legacy spec versions) | Rejected with `VersionNotSupportedError`; response includes `Supported-A2A-Versions: 1.0` |
| `A2A-Version: 1.<minor>` where minor > our pinned minor | Accepted with feature-degradation warning if the call uses a feature only available in the higher minor; otherwise processed |
| `A2A-Version: 2.x` (or any other version we do not support) | **Rejected** with `VersionNotSupportedError` per spec; response includes `Supported-A2A-Versions` header listing the versions AgentOS speaks |
| Header malformed | Rejected with spec-defined parse error |

Outbound calls always include `A2A-Version: 1.0` (our pinned version). When AgentOS bumps the pinned version, this is a deliberate reviewed change tied to the schema-drift CI gate.

### Audit chain linkage
Every A2A message creates a child decision_history record linked to the parent's chain hash. The `chain_verifier` walks the cross-agent chain to prove no message was injected, dropped, or re-ordered.

### Why A2A specifically
- 150+ organisations in production by April 2026
- Deep integration on Google, Microsoft, AWS clouds
- Linux Foundation governance (handed over from Google)
- Vertical adoption in financial services already proven
- Open spec, multi-vendor implementations

## Consequences

### Positive
- **Future-proof inter-agent comms**: standard, not Cognic-specific
- **Cross-organisation interop**: a Cognic agent can be invoked by a bank-written agent on a different stack
- **Bank-side extensibility**: banks can write A2A-speaking agents that integrate with their internal systems
- **Audit chain integrity**: cross-agent chains verifiable via A2A's parent_trace_id field

### Negative
- **A2A SDK dependency**: pinning to A2A commits Cognic to that protocol's evolution
- **Authentication**: A2A spec evolution around mTLS / OIDC for agent identity is still maturing — Wave-1 implementation uses pinned per-tenant tokens; Wave-2 moves to mTLS

### Neutral
- A2A and MCP are complementary: MCP is for tool/resource calls (agent → tool), A2A is for agent calls (agent → agent)

## Implementation
- **Phase 2**: `A2AEndpoint.handle(message)` routing + parent_trace_id chain linkage
- **Phase 4**: outbound `spawn_subagent` (depends on ADR-005 sub-agent primitive)

## A2A inbound reachability amendment (2026-06-21) — receiver-only Wave-1, the receiver core is on the wire

The entire A2A inbound stack was production-grade *logic* but **unreachable** — no HTTP route was mounted (`portal/api/app.py` deferred the mounts). This amendment makes the **receiver core** reachable — the first cut of the "Protocol Reachability" epic (the MCP startup-discovery slice follows; the A2A auxiliary surfaces are a follow-on).

1. **The route** (`portal/api/a2a/`, off-gate). `POST /api/v1/a2a/{target_agent}` — a dumb raw-body adapter around `A2AEndpoint.handle()`, mounted UNCONDITIONALLY by `create_app` (503 `a2a_endpoint_unavailable` until the SDK-gated lifespan builds the endpoint). **No portal RBAC** — the A2A pinned token is the auth axis, validated inside `handle()` (Gate 2). The route reads the raw body + `Authorization` + `A2A-Version` + a claimed tenant (the `resolve_a2a_tenant` seam reads `X-Cognic-Tenant`; host-based tenancy is a later resolver swap; the claim is not trusted — authz validates the token against it). Status: success → 200 + the handler's JSON-RPC dict; refusal → the `a2a_errors` taxonomy `http_status` + the JSON-RPC error envelope; missing tenant → 400 `tenant_header_missing`.
2. **The Wave-1 method gate** (`protocol/a2a_endpoint.py`, on-gate). A new gate inside `handle()` — after version/authz/Wave-2, **before any task-id mint / `TaskState` transition / routing / `agent.handle()` dispatch** — refuses any method but `message/send` with `method_not_supported_wave1` → `unsupported_operation`. Closes the mis-dispatch hole (a `tasks/cancel` would otherwise create a task + invoke the agent). The deferred methods (`tasks/get`, `tasks/cancel`, `message/stream`, artifacts, capabilities) refuse `unsupported_operation` until their follow-on slice merely *lifts the gate*.
3. **The deferred JSON-RPC route-integration serializer** (`protocol/a2a_errors.py`, on-gate). `handle()` *raises* `A2AEndpointError`; a2a_errors had no envelope serializer, so a *correct* receiver required building it: `from_endpoint_error(exc)` + `A2AErrorResponse.to_jsonrpc(...)` + `_SPEC_CODE_TO_JSONRPC_INT` (the integer `error.code` JSON-RPC 2.0 mandates, sourced from the pinned `a2a-sdk`'s `JSON_RPC_ERROR_CODE_MAP`, drift-pinned under `COGNIC_RUN_A2A_UPSTREAM=1`) + `_SPEC_CODE_TO_HTTP_STATUS`. Two new `A2APolicyRefusalReason` values: `method_not_supported_wave1` → `unsupported_operation` and `tenant_header_missing` → `invalid_request` (the latter honours the no-`a2a_`-prefix invariant).
4. **The lifespan wiring** (`portal/api/app.py`, off-gate). SDK-gated `A2AEndpoint` construction (`A2AAuthzClient` + `A2AAgentCardVerifier`[`TrustGate` + a dedicated `a2a_http_client`] + the audit/decision-history stores), fail-soft, mirroring the MCP-host block; the `create_prod_app` presence-log is kept (the dual-location pattern).
5. **Honest scope.** This slice makes the **receiver + the full gate stack reachable and correct** (version, authz, Wave-2, the method gate, the routing `unknown_target` path). A *successful* `message/send` dispatch resolves the target via the same `PluginRegistry` that is empty at default startup — so **end-to-end successful dispatch in a default deploy follows the MCP/A2A startup-discovery slice** (the next slice; sequenced back-to-back). Auxiliary surfaces, host-based tenancy, and outbound A2A remain forward. **CC count unchanged** (no new gate module — route/DTOs off-gate; the on-gate `a2a_endpoint.py`/`a2a_errors.py` edits are additive). No migration. Conformance pinned by `tests/conformance/a2a/test_receiver_wave1_posture.py`.

## References
- [A2A Protocol home](https://a2a-protocol.org/latest/)
- [A2A — IBM Think](https://www.ibm.com/think/topics/agent2agent-protocol)
- [A2A — 150 orgs production milestone](https://www.prnewswire.com/news-releases/a2a-protocol-surpasses-150-organizations-lands-in-major-cloud-platforms-and-sees-enterprise-production-use-in-first-year-302737641.html)
- ADR-005 (sub-agent — uses A2A for outbound spawning)
