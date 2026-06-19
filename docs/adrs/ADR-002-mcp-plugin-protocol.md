# ADR-002 — MCP-based Plugin Protocol for Tools / Skills / Agents

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

Per ADR-001 this repo ships AgentOS only; tools, skills, and agents are separately-versioned plugin packs. We need a discovery + invocation protocol that:

- Doesn't require Cognic-specific glue per pack
- Is signature-verifiable for bank trust requirements
- Interoperates with the wider agent ecosystem (Claude, ChatGPT, Cursor, etc.)
- Survives architectural drift (the standard outlives the implementation)

## Decision

Adopt **MCP (Model Context Protocol)** as the tool/resource invocation protocol and **Python entry points** as the discovery mechanism.

### Discovery

A pack registers in its `pyproject.toml`:

```toml
[project.entry-points."cognic.tools"]
search_circulars = "cognic_tool_search:SearchCircularsTool"

[project.entry-points."cognic.skills"]
kyc_expiry = "cognic_skill_kyc:KYCExpirySkill"

[project.entry-points."cognic.agents"]
policy_qa = "cognic_agent_policyqa:PolicyQAAgent"
```

`cognic_agentos.protocol.plugin_registry.discover()` walks `importlib.metadata.entry_points` for the three groups, populates the registry, and exposes `require(kind, name)` and `load(kind, name)`.

### Invocation

- **Tools**: ship as MCP servers. **Streamable HTTP is the production default transport.** STDIO is a restricted escape hatch — see "MCP STDIO threat model" below.
- **Skills**: MCP-composing services that call tools deterministically (no LLM).
- **Agents**: A2A-speaking services (see ADR-003).

The `cognic_agentos.protocol.mcp_host.MCPHost` opens sessions and routes calls. Every call is audit-logged via the governance kernel.

### MCP STDIO threat model (mandatory before MCPHost is implemented)

Per the April 2026 MCP supply-chain disclosures (OX Security and others), unsafe STDIO command configuration in MCP hosts has been demonstrated to become **remote code execution** in real deployments. Any string controlled by a model, a remote pack, a config file, or a user input that flows into a process-launch command is an RCE vector.

AgentOS therefore enforces:

1. **Streamable HTTP MCP is the production default.** Production deployments treat STDIO as opt-in only.
2. **STDIO is allowed only when ALL of the following are true:**
   - Pack ships a **signed static manifest** declaring its launch command + arguments + env vars
   - The launch command is on a **per-tenant static command allow-list** (operator-curated, RBAC-gated to change)
   - The launch happens inside a **sandbox profile** (per ADR-004) with bounded filesystem, bounded egress, bounded resource caps
   - **Bounded environment variables** — no `os.environ` passthrough; only the explicit allow-list from the manifest
   - **Audit event emitted for every launch** — pack identity, command, arguments, sandbox-id, outcome — chained into `decision_history`
3. **No user-, model-, or remote-pack-controlled command or argument may reach process execution.** The host validates the manifest against the allow-list at registration, then ignores any subsequent attempt to override.
4. **Any STDIO launch failing any of (1)-(3) is refused at registration.** No silent fallback to permissive behavior.

The threat model document `docs/MCP-STDIO-THREAT-MODEL.md` accompanies the implementation. Negative-path tests prove that user-controllable inputs cannot reach a process launch.

OWASP Agentic Top 10 / Agentic Skills supply-chain checks (per PROJECT_PLAN.md §5) are part of pack conformance — covered in the Sprint 7B pack lifecycle workflow.

### MCP Authorization (Streamable HTTP transport)

The MCP spec (April 2026 revision) defines OAuth-based authorization for HTTP transports including **Protected Resource Metadata (PRM)** discovery. AgentOS implements this for all production-default Streamable HTTP MCP traffic:

1. **Resource-metadata discovery via three paths in priority order** (the spec mandates supporting all three):
   - **Primary signal** — `WWW-Authenticate: Bearer resource_metadata="<url>"` header on a 401 response; client follows the URL the server advertises
   - **Endpoint-specific well-known fallback** — when the 401 lacks `WWW-Authenticate`, client probes the endpoint-specific PRM path first. For an MCP endpoint at `https://server.example/public/mcp`, that's `https://server.example/.well-known/oauth-protected-resource/public/mcp`. This per-resource convention lets a single host expose multiple MCP servers under different paths each with their own PRM (and their own AS allow-list / scopes).
   - **Root well-known fallback** — if the endpoint-specific path 404s, the client falls back to host-level `/.well-known/oauth-protected-resource`
   - All three paths produce the same Protected Resource Metadata document (authorization servers + supported scopes); whichever returns first wins
2. **AgentOS as MCP host** acts as an OAuth resource client: discovers PRM at first contact (via either path), requests tokens with the minimum scopes the manifest declares, includes `Authorization: Bearer ...` on every MCP request
3. **Per-tenant authorization-server allow-list** in Vault — only AS endpoints on the list will be contacted (prevents an attacker-controlled MCP server from redirecting AgentOS to a malicious AS)
4. **RFC 8707 resource indicator** (`resource=<server URL>`) on every token request — the AS binds the issued token to the specific MCP server; tokens are never reused across servers
5. **Audience validation** on every received token — `aud` claim MUST match the MCP server's resource indicator. Mismatched audience → token rejected, server treated as 401, fresh discovery + token request triggered
6. **Insufficient-scope step-up** — per the MCP authorization spec, **runtime insufficient scope is signalled by `403 Forbidden`** (not 401). The server returns `403 WWW-Authenticate: Bearer error="insufficient_scope", scope="<wider>"`; the client requests a fresh token covering the wider scope **only if** (a) the manifest declares the wider scope AND (b) tenant policy permits. The step-up is audit-logged with prior + requested-additional scopes. Manifest does not declare the wider scope → call fails closed with `mcp_step_up_unauthorised`. This forbids servers from silently widening their privilege footprint at runtime. (Initial missing/invalid auth still returns `401`; the 401-vs-403 distinction matters because clients treat 401 as "discover + acquire token" and 403 as "step up the scope of the token I already have".)
7. **Token cache + refresh** — tokens cached per (server, scope, resource) tuple; refreshed before expiry; `audit.mcp_token_refresh` event per refresh
8. **Failed auth = registration refused** — at pack registration time, AgentOS performs a probe MCP request; if auth fails, the pack stays in `proposed` state with the auth failure as evidence
9. **Audit linkage** — every MCP call records the token's `client_id` + scopes used + AS issuer + resource indicator in `decision_history` so examiners can prove which authorisation context performed which tool call against which resource

For backward compatibility with MCP servers that don't declare PRM (older revisions), AgentOS supports a manifest-declared API-key fallback (key sourced from per-tenant Vault path). This is a **Wave 1 escape hatch**; Wave 2 deprecates the fallback path.

### AGNTCY/OASF-compatible manifest fields

AGNTCY (Cisco → Linux Foundation Internet of Agents) and OASF (Open Agent Service Framework) define identity + directory-publication schemas for agent packs that AgentOS will integrate in Wave 2. To avoid a manifest migration, **Wave 1 manifests must already declare the AGNTCY/OASF-compatible fields**:

```toml
[tool.cognic.identity]  # AGNTCY/OASF compat — lives in pack manifest, NOT in the A2A AgentCard
agent_id = "urn:cognic:agent:policy_qa:0.5.0"  # URN form per AGNTCY
display_name = "Policy QA"
provider_organization = "Cognic"  # populates the A2A AgentCard `provider.organization` (spec-optional, AgentOS-profile mandatory)
provider_url = "https://cognic.ai"  # populates the A2A AgentCard `provider.url`
agent_card_url = "https://packs.cognic.ai/agent_cards/policy_qa.json"  # URL of the published A2A AgentCard (validated against upstream A2A schema + AgentOS profile)
agent_card_jws_path = "agent_cards/policy_qa.jws"  # detached JWS signature over the card (mandatory, per A2A-CONFORMANCE.md)
verifiable_credentials_path = "credentials/policy_qa.vc.jsonld"  # for Wave 2 VC publication
oasf_capability_set = ["regulatory_qa", "citation_grounded"]  # OASF capability vocabulary
```

**Important: the manifest's identity block is Cognic-specific governance metadata; the published A2A AgentCard at `agent_card_url` is validated in two passes** — first against the **upstream A2A 1.0 schema** (a card that fails this isn't A2A at all), then against the **AgentOS bank-grade profile** that requires several spec-optional fields to be populated (`provider`, `securitySchemes`, `securityRequirements`, `signatures`, at least one `supportedInterfaces` entry). **Endpoint URLs live inside `supportedInterfaces[].url`, NOT as a top-level AgentCard field.** Cognic-specific fields like `agent_id` URN and `oasf_capability_set` do NOT appear at the AgentCard top level — the AgentOS profile requires *more* of the spec's existing optional fields, never adds non-spec fields, so any A2A 1.0 caller can still consume the card. The trust gate consumes the manifest; the card stays consumable by any A2A-conformant caller. Sprint 7A `agentos validate` enforces both passes (and the manifest); Sprint 6 verifies card spec-shape against upstream schema and AgentOS profile separately.

### Wave 1 identity-field strictness (mandatory vs deferred)

| Field | Wave 1 status |
|---|---|
| `agent_id` (URN) | **Mandatory** — registration refused without it |
| `display_name` | **Mandatory** — registration refused without it |
| `provider_organization` + `provider_url` | **Mandatory** (both) — needed to populate the AgentCard's `provider` object, which is spec-optional but AgentOS-profile mandatory |
| `agent_card_url` | **Mandatory** — Sprint 6 outbound A2A and trust gate need it to fetch + verify the card |
| `agent_card_jws_path` | **Mandatory for agent packs** — signed cards are mandatory per A2A-CONFORMANCE.md; no JWS path → registration refused. (Tool/skill packs that don't publish A2A cards skip this.) |
| `oasf_capability_set` | **Optional** in Wave 1 (warning logged if absent); becomes mandatory in Wave 2 |
| `verifiable_credentials_path` | **Optional / reserved** — Wave 3 VC sprint flips this mandatory. Wave 1 registration accepts manifests without it; the field, if present, is validated for path resolvability only |

`agentos validate` (Sprint 7A) enforces this matrix; Wave 2 / Wave 3 sprint headers will tighten the optional fields to mandatory with explicit migration windows.

### Trust

Every pack distribution is **cosign-verified** against the per-tenant trust root before the registry registers it. Verification result is recorded with the pack identity (signature digest) and surfaced in evidence packs.

Per-tenant **allow-list** is loaded from a Vault path (`secret/cognic/<tenant>/plugin-allowlist`). A signed pack that is not on the tenant's allow-list is **not** registered. AgentOS startup logs every (registered, unregistered, rejected) outcome.

### Why MCP specifically

- 97M+ installs by April 2026
- Adopted by Anthropic, OpenAI, Google DeepMind, Microsoft, Cloudflare, Salesforce, ServiceNow, Workday, Accenture, Deloitte
- Open standard, Linux Foundation governance candidate (per 2026 roadmap)
- Adopting it means every tool a Cognic-installed bank writes is interoperable with the wider ecosystem; conversely every MCP-spec tool from the ecosystem is installable on Cognic AgentOS

## Consequences

### Positive
- **Future-proof**: betting on the standard, not a Cognic-specific invention
- **Interop**: bank-written tools work with Claude Code, Cursor, ChatGPT
- **Independent release**: each pack ships at its own velocity
- **Bank-extensible**: banks can write their own MCP server packs (CBS adapters, internal-data tools)
- **Signature-verified**: cosign + Vault allow-list means banks audit one pack once

### Negative
- **MCP SDK dependency**: pinning to MCP commits Cognic to the Anthropic ecosystem direction
- **CI cost**: every pack needs cosign signing in its build pipeline; trust-root rotation playbook
- **Schema drift**: MCP protocol updates may force AgentOS host upgrade
- **Plugin debugging**: cross-process boundaries make traces harder; mitigated by OpenTelemetry trace context propagation through MCP envelope

### Neutral
- Skills (Layer B) are an internal abstraction; whether they ship as separate MCP servers or as stdlib helpers inside agent packs is a tactical choice — the registry supports both

## Implementation phases

1. **Phase 2.1**: implement `plugin_registry.discover()` (entry-point walker; no signature verification yet)
2. **Phase 2.2**: implement `mcp_host.MCPHost` (session management, tool listing, call routing)
3. **Phase 2.3**: extract `tools/search/` from this repo into a separate `cognic-tool-search` pack as POC
4. **Phase 2.4**: cosign signing in CI, trust-root provisioning, per-tenant allow-list config schema
5. **Phase 2.5**: extract remaining tool categories (`tools/documents`, `tools/document_intel`, `tools/bank_readiness`, `tools/urdu_*`)
6. **Phase 2.6**: CI test that confirms zero `from cognic_agentos.tools.X` imports remain in OS-tier code (replaces parent's ADR-009 import-discipline test)

## Sprint 13.8 amendment (2026-06-13) — MCP host production-constructed at the composition root

Sprint 13.8 lands the long-deferred **"Sprint-5 T9"**: `MCPHost` is now
production-constructed so a deployed AgentOS reaches a real, approval-wired host on
`app.state.mcp_host`. All protocol primitives already existed (Phase 2.2's
`MCPHost`, `MCPAuthzClient`, `StreamableHTTPTransport`, the signed-manifest
extractor); 13.8 builds only the construction wiring + the
manifest→`MCPServerEntry` mapper + one read-only registry accessor.

1. **Construction site — the `create_app` LIFESPAN, NOT `build_runtime`.** The host
   needs `runtime.audit_store` / `decision_history_store` / `approval_engine`
   (post-`build_runtime`), and its transport ctor calls `require_mcp()`, so it is
   constructed in the FastAPI lifespan, **SDK-gated on `is_mcp_available()`** (the
   `mcp` SDK is an optional `adapters` extra; the kernel image lacks it).
   `build_runtime` stays SDK-free. `create_prod_app` is superseded to an
   availability-LOG-only path (it does not construct the host).
2. **Read-only registry accessor.** `PluginRegistry.iter_registered_pack_candidates()`
   yields the **trusted/registered** set (excludes `refused_at_registration`) as
   `RegisteredPackCandidate(distribution_name, package_name, signature_digest)`,
   deriving `package_name` from `record.entry_point_value` (the `_mcp_admit`
   doctrine at `plugin_registry.py:852`) **without** `EntryPoint.load()` — the
   deferred-load invariant holds. It does NOT filter MCP intent (the mapper does).
   Trust stays upstream: 13.8 consumes the registered set; it does not run
   discovery/trust registration at startup.
3. **The mapper (`harness/mcp_host.py`, off-gate).** Per candidate it re-extracts
   the manifest and mirrors the admission contract: `PackManifestNotFoundError` /
   absent `[tool.cognic.mcp]` block → **silent skip** (no MCP intent);
   `PackManifestMalformedError` / present-but-malformed block → **skip + structured
   warning**; the existing `mcp_capabilities._mcp_block` accessor collapses absent +
   malformed, so the mapper does its OWN tri-state walk. Field reads mirror
   `validate_mcp_manifest`: `server_url` must be a non-empty `http`/`https` URL (the
   SSRF pre-filter), `transport` must be in the Wave-1 HTTP family
   (`_MCP_HTTP_SERVED_TRANSPORTS`, drift-pinned vs `_HTTP_TRANSPORT_VALUES`; `stdio`
   not served), `scopes` is required, and `data_classes` is fail-closed on malformed
   (it flows into the value-free approval envelope). `pack_signature_digest` is
   carried from the registration outcome.
4. **Approval seam WIRED but DORMANT (the 13.7 honesty pattern).** `build_mcp_host`
   threads `approval_engine=runtime.approval_engine`, so the 13.5b2 MCP approval seam
   is now bound into the constructed host (any `call_tool` consults the engine instead
   of the `tool_approval_engine_not_available` fallback). But **no portal route
   consumes `app.state.mcp_host` today**, so the seam stays dormant until a future
   MCP-invocation surface (or the 14A managed-runtime caller) exercises `call_tool`.
5. **Lifecycle + fail-soft.** A dedicated lifespan-owned `httpx.AsyncClient` backs
   the authz client, closed on shutdown AND on a fail-soft construction failure
   (`app.state.mcp_host` stays `None` + ERROR log; the app still boots). The client
   is predeclared so a `build_runtime` failure before assignment cannot
   `UnboundLocalError` in cleanup. `app.state.mcp_host` is pre-seeded `None`.
6. **CC / scope.** `protocol/plugin_registry.py` (the read-only accessor) is the one
   CC stop-rule modification — additive, deferred-load-preserving, ≥ 95/90 verified
   in-commit. `harness/mcp_host.py` + `portal/api/app.py` are off-gate (composition
   wiring consuming the trusted accessor; trust is upstream). No CC promotion (count
   stays 129). OUT of 13.8: any MCP-invocation/list route, the 14A managed-runtime
   caller, startup discovery/trust registration.

## MCP tool-invocation portal route amendment (2026-06-19) — the Fork-D production surface (dormant → LIVE)

Sprint 13.8 production-constructed `app.state.mcp_host` but left it **dormant** ("no
portal route consumes `app.state.mcp_host` today"). This amendment lands that route —
the FIRST production consumer of the host — closing the Fork-D gap for the
MCP-invocation lane (the `portal/api/runs/` equivalent for MCP).

1. **The surface.** A new off-gate module `portal/api/mcp/` mirrors the
   `portal/api/runs/` caller pattern. Two routes, mounted UNCONDITIONALLY under
   `/api/v1/mcp` (a request-time dep returns `503 mcp_host_unavailable` until the
   SDK-gated lifespan populates the host):
   - `GET /api/v1/mcp/servers/{server_id}/tools` (scope `mcp.tool.list`) →
     `MCPHost.list_tools`; `200 {tools: [...]}`.
   - `POST /api/v1/mcp/servers/{server_id}/tools/call` (scope `mcp.tool.invoke`) →
     `MCPHost.call_tool`; `200` the `CallResult` projection. `tool_name` rides the
     BODY (raw caller-supplied identity — the host owns audit-canonical raw tool
     identity; NEVER copied to a URL path segment); `arguments` + an optional
     `approval_request_id` complete the body. tenant + originator come ONLY from the
     bound `Actor`.
2. **The approval seam goes LIVE.** The 13.5b2 MCP approval seam — WIRED but DORMANT
   since 13.8 (`approval_engine=runtime.approval_engine`) — is now exercised by
   `call_tool`. A first invocation of an approval-gated tool returns `202` carrying a
   minted `approval_request_id`; the operator grants via the EXISTING
   `portal/api/approvals/` surface (`ToolApprovalRBACScope`, e.g.
   `tool.approve.customer_data`); a re-`POST` with that `approval_request_id` clears
   the gate → `200`.
3. **Status map (map-by-class — no 500 leaks).** `MCPToolInvocationRefused.reason` →
   `202` (`tool_approval_pending`, body adds `approval_request_id`) / `403`
   (`tool_approval_denied`, `…_engine_not_available`) / `409` (`…_expired`,
   `…_binding_mismatch`, `…_request_not_found`). `LookupError` (unknown `server_id`)
   → `404`. `MCPTransportError`/`MCPAuthzError` → `504` if the reason is in the closed
   `_TIMEOUT_REASONS` set (`mcp_call_tool_timeout` / `mcp_session_open_timeout` /
   `mcp_oauth_request_timeout`), else a DELIBERATE `502` (drift-pinned ⊆ the live
   `MCPTransportReason`+`AuthzReason` enums). Any other exception → `502`
   `mcp_orchestrator_error` (the generic catch-all — `call_tool` re-raises its
   generic-Exception path after auditing it). No path leaks a `500`.
4. **CC / scope.** CC stays **131** — the route module + DTOs are off-gate (mirroring
   `portal/api/runs/`; trust is upstream in the on-gate host + admission). The three
   `portal/rbac/` edits (`scopes.py` `MCPRBACScope` + the `actor.py` / `enforcement.py`
   union widenings) are additive to already-on-gate modules. `protocol/mcp_host.py` is
   CONSUMED, not modified. No migration. Tests use a stub host (route mapping +
   approval-id threading); the host's real `ApprovalEngine` seam stays covered by
   `tests/unit/protocol/test_mcp_approval_seam.py`. Spec + plan:
   `docs/superpowers/specs/2026-06-19-mcp-tool-invocation-portal-route-design.md` +
   `docs/superpowers/plans/2026-06-19-mcp-tool-invocation-portal-route.md`.

## References
- [Model Context Protocol — 2026 roadmap](https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/)
- [MCP — Wikipedia](https://en.wikipedia.org/wiki/Model_Context_Protocol)
- ADR-001 (this repo's OS-only premise)
- ADR-003 (A2A for inter-agent comms — complements this)
- Parent repo `bmzee/cognic` ADR-009 (import-discipline test as foundation)
