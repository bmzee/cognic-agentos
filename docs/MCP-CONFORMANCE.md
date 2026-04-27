# MCP Conformance Matrix

**Status:** Authoritative reference for which MCP features Cognic AgentOS supports, restricts, or defers per wave.

This document complements [`docs/adrs/ADR-002-mcp-plugin-protocol.md`](adrs/ADR-002-mcp-plugin-protocol.md). Pack authors and bank operators use it to know what they can rely on; reviewers (Sprint 7B) use it to enforce manifest declarations against the conformance matrix.

## Transport conformance

| Transport | Wave 1 | Notes |
|---|---|---|
| **Streamable HTTP** | ✅ Production default | Required for all production deployments. OAuth/PRM auth (see "Authorization" below). |
| **STDIO** | ⚠️ Restricted escape hatch | Disabled in production profile by default. When enabled, requires all four gates from ADR-002 §"MCP STDIO threat model" + sandbox availability (ADR-004). Hard-blocked if any gate fails. |
| **WebSocket** | ❌ Deferred | Not on the official MCP roadmap as a primary transport; revisit when spec mandates it. |
| **In-process Python** | ❌ Forbidden | Would defeat the OS/pack boundary. Plugin packs must run cross-process. |

## Capability conformance (per MCP spec category)

| Capability | Wave 1 | Wave 2 | Forbidden |
|---|---|---|---|
| **Tools** — invocation, list, schema, call | ✅ Required | — | — |
| **Resources** — list, read, subscribe | ✅ Optional | — | A pure tool-only MCP server is conformant. Servers that DO declare resources MUST publish list / read; subscribe is optional. |
| **Prompts** — list, get | ✅ Optional | Optional (no Wave-2 promotion) | — |
| **Roots** — workspace declarations | ⚠️ Bounded — only roots inside the sandbox filesystem are exposed; bank-tenant filesystem access never exposed | — | Cross-tenant root exposure |
| **Sampling** — server requests LLM completion via the host | ⚠️ Default-deny per tenant + per pack; allowed only when tenant Rego policy (ADR-015) explicitly permits + pack manifest declares + model tier is consistent with declared cloud-policy | **Stays default-deny.** No "default-on" promotion. Wave 2 may add per-tier policy templates but the default never flips. | Sampling against cloud models when tenant `ALLOW_EXTERNAL_LLM=false`; sampling against any model when pack lacks an explicit `sampling_supported = true` declaration |
| **Elicitation** (server prompts user mid-call) | ⚠️ URL-mode only | Form-mode after security review | Form-mode for sensitive data classes (ADR-017 PII / payment / regulator classes) |
| **Logging** — server emits structured logs to host | ✅ Required | — | — |
| **Progress notifications** — long-running call updates | ✅ Required | — | — |
| **Cancellation** — host cancels in-flight call | ✅ Required | — | — |
| **Caching** — host caches tool/resource responses | ✅ Optional, per-tool manifest declaration | Required | Caching of `customer_pii` / `payment_action` / `regulator_communication` data class results |

### Why `elicitation` URL-mode only in Wave 1

The MCP elicitation feature lets a server (tool pack) prompt the user mid-call (e.g. "I need a confirmation code"). Two modes:
- **URL mode** — server returns a URL the user visits in their own session
- **Form mode** — server returns a form schema the host renders inline

Form mode is dangerous for sensitive data (PII, payment confirmations) because the form fields can be designed by the server to extract more than the user thinks they're providing. Wave 1 supports URL mode only. Wave 2 will support form mode for non-sensitive classes after a dedicated security review + Rego policy (per ADR-015) gating it.

## Authorization

### OAuth / Protected Resource Metadata (PRM) — Wave 1 mandatory for HTTP transport

Per ADR-002 §"MCP Authorization" + the MCP authorization spec:

1. **Resource-metadata discovery — three paths in priority order** (spec mandates all three):
   - **Primary**: server returns `401 WWW-Authenticate: Bearer resource_metadata="..."` and the client follows that URL
   - **Endpoint-specific well-known fallback**: when the 401 lacks `WWW-Authenticate`, client probes the endpoint-specific path first — for an MCP endpoint at `https://server.example/public/mcp`, that's `https://server.example/.well-known/oauth-protected-resource/public/mcp` (the spec's per-resource convention). This lets a single host serve multiple MCP servers under different paths each with their own PRM.
   - **Root well-known fallback**: if the endpoint-specific path 404s, client falls back to `https://server.example/.well-known/oauth-protected-resource` (the host-level PRM)
   - All three paths produce the same Protected Resource Metadata document; whichever returns first wins; the discovered document is cached per `Cache-Control` directives
2. AgentOS as MCP host parses PRM (from either path) and requests minimum-scope tokens
3. Per-tenant authorization-server allow-list in Vault
4. **RFC 8707 resource indicator** (`resource=<server URL>`) on every token request — tokens are bound to the specific MCP server
5. **Audience validation**: every received token's `aud` claim MUST match the MCP server's resource indicator; mismatched audience → token rejected, server treated as 401, fresh discovery + token request triggered. Tokens are NEVER reused across servers.
6. **Insufficient-scope step-up**: per the MCP authorization spec, **runtime insufficient-scope returns `403 Forbidden`** with `WWW-Authenticate: Bearer error="insufficient_scope", scope="<wider>"` (initial missing/invalid auth is `401`; runtime authenticated-but-under-scoped is `403`). On `403 insufficient_scope`, client requests fresh token with wider scope IF (a) manifest declares the wider scope AND (b) tenant policy permits. Step-up is audit-logged with prior + requested-additional scopes. If manifest does not declare the wider scope, call fails closed with `mcp_step_up_unauthorised`.
7. Tokens cached + refreshed; every refresh emits an audit event with AS issuer + scopes + resource indicator (no token contents)
8. Failed auth at registration → pack stays in `proposed` state
9. Every MCP call records `client_id` + scopes + AS issuer + resource indicator in `decision_history`

### API-key fallback — Wave 1 escape hatch

For MCP servers that don't yet publish PRM (older revisions), AgentOS supports a manifest-declared API-key sourced from per-tenant Vault path. Deprecated in Wave 2.

### Anonymous / unauthenticated MCP — forbidden

No production tenant may register an MCP server lacking either OAuth/PRM or API-key auth. Wave 1 trust gate refuses such packs.

## Caching

Host-side caching is optional per tool, declared in the pack manifest:

```toml
[tool.cognic.cache]
strategy = "ttl"  # ttl | none | content-hash
ttl_s = 300       # for ttl strategy
key_inputs = ["query", "top_k"]  # which call args participate in the cache key
```

**Forbidden cache scopes:**
- Any tool whose `data_classes` (per ADR-017) include `customer_pii`, `payment_action`, or `regulator_communication`
- Any tool flagged `risk_tier: payment_action` or higher (per ADR-014)

Trust gate (Sprint 4) refuses pack registration if cache declarations violate these rules.

## Approval flows (per ADR-014 runtime tool approval)

| Tier | Pre-call action | Notes |
|---|---|---|
| `read_only` | None — auto-run | Audit-logged like any call |
| `internal_write` | None — auto-run with audit emphasis | |
| `customer_data_read` | Just-in-time single-approver | 300s expiry default |
| `customer_data_write` | Just-in-time + reason code | |
| `payment_action` | 4-eyes (two distinct approvers) | 60s expiry |
| `regulator_communication` | 4-eyes + categorised reason + audit-record reference | |
| `cross_tenant` | 4-eyes + bank legal sign-off | Default-disabled per tenant |

Pack manifest declares the tier; reviewer (Sprint 7B) verifies it; trust gate (Sprint 4) enforces it.

**Approval-engine availability (sequencing rule):** the runtime approval engine ships in Sprint 13.5 (per ADR-014). Until then, the harness operates under a **fail-closed transitional rule**:

| From | Until | Behaviour |
|---|---|---|
| **Sprint 5 (MCP host lands)** | **Sprint 13.5 (approval engine lands)** | Only `read_only` and `internal_write` tiers are callable. Tools declaring `customer_data_read` / `customer_data_write` / `payment_action` / `regulator_communication` / `cross_tenant` / `high_risk_custom` register successfully but **the harness refuses every invocation** with `tool_approval_engine_not_available` error. Refusal is audit-logged with the declared tier so banks can plan rollout. |
| **Sprint 13.5 onward** | — | Full approval flows per the table above. |

This rule is enforced in `protocol/mcp_host.call_tool` (Sprint 5), validated by `test_mcp_high_risk_tier_refused_pre_13_5.py`, and explicitly removed in Sprint 13.5 once `core/approval` is wired in. Banks that need high-risk tools earlier must wait for Sprint 13.5 — there is no "approve via config" escape hatch.

## Observability

| Feature | Wave 1 | Notes |
|---|---|---|
| MCP `Mcp-Session-Id` propagation | ✅ Required | Every MCP call's session ID is recorded in `decision_history` linked to the parent agent invocation |
| Tracing — OpenTelemetry context | ✅ Required | OTel context propagates through MCP envelope; spans link host ↔ server |
| Structured logs from server | ✅ Required | Server logs flow through host's structured log pipeline |
| MCP error codes — full taxonomy | ✅ Required | Errors map to specific audit reason codes |

## What pack authors must declare

Every MCP server pack must declare the following in its `pyproject.toml` for trust gate verification:

```toml
[tool.cognic.mcp]
transport = "streamable-http"          # or "stdio" if approved
auth = "oauth-prm"                     # or "api-key" (Wave 1 fallback)
required_scopes = ["read:circulars"]   # OAuth scopes the server needs
resources_supported = true
prompts_supported = false
sampling_supported = false             # if true, declare which model tier
elicitation_modes = ["url"]            # or ["url", "form"] in Wave 2 (sensitive classes still forbidden)
caching_strategy = "ttl"               # see Caching section
caching_ttl_s = 300
```

`agentos validate` (Sprint 7A SDK CLI) checks declarations against this conformance doc; reviewer (Sprint 7B) sees them in the evidence view.

## Versioning + drift

This conformance matrix is **versioned alongside the AgentOS release** (e.g. `cognic-agentos:1.0` ships matrix v1; `cognic-agentos:1.1` may extend it). Pack manifests declare which conformance version they target via `[tool.cognic.mcp].conformance_version`. Trust gate refuses packs targeting a higher conformance version than the host supports.

## References

- [`docs/adrs/ADR-002-mcp-plugin-protocol.md`](adrs/ADR-002-mcp-plugin-protocol.md) — STDIO threat model + OAuth/PRM
- [`docs/adrs/ADR-014-runtime-tool-approval.md`](adrs/ADR-014-runtime-tool-approval.md) — risk tiers + approval flows
- [`docs/adrs/ADR-017-data-governance-contracts.md`](adrs/ADR-017-data-governance-contracts.md) — data-class restrictions on caching
- [Model Context Protocol Spec](https://spec.modelcontextprotocol.io/)
- [MCP Authorization Spec](https://spec.modelcontextprotocol.io/specification/server/authorization/)
