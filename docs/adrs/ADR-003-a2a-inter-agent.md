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

## References
- [A2A Protocol home](https://a2a-protocol.org/latest/)
- [A2A — IBM Think](https://www.ibm.com/think/topics/agent2agent-protocol)
- [A2A — 150 orgs production milestone](https://www.prnewswire.com/news-releases/a2a-protocol-surpasses-150-organizations-lands-in-major-cloud-platforms-and-sees-enterprise-production-use-in-first-year-302737641.html)
- ADR-005 (sub-agent — uses A2A for outbound spawning)
