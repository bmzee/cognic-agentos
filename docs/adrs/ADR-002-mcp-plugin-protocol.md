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

## MCP/A2A startup discovery + trust-registration amendment (2026-06-21) — the shared registry is populated at boot

The MCP host (`build_mcp_host`) and the A2A receiver (`A2AEndpoint`) resolved packs against a `PluginRegistry` that was **empty at default startup** — `discover()` was never called, and each surface built its own empty registry. This slice (the second "Protocol Reachability" cut, sequenced right after A2A inbound reachability) populates **one shared registry at boot** by running the full `register_with_full_attestation_check` supply-chain trust pipeline per installed pack, and feeds it to both surfaces. Single-tenant `_default` boot only.

- **The deployment convention.** Installed packs do not self-carry their attestations (`cli/sign.py` writes them next to the wheel), so the operator places each pack's **signed wheel + attestations** at `<Settings.pack_attestation_root_path>/<distribution_name>/<version>/` (the LOCKED layout: `cosign.sig` + the single `*.whl` cosign blob + `bundle.sigstore` + `sbom.cdx.json` + `slsa-provenance.intoto.json` required; in-toto/vuln/license optional grace-period). The cosign trust anchor is the LOCKED `<Settings.trust_root_prefix>/_default/cosign.pub`. Unset `pack_attestation_root_path` (or no installed packs, or no object-store sink) → an empty **reachable** registry; a missing/non-file/empty `cosign.pub` OR a missing/malformed `_default` allow-list → **fail-closed** (`RegistryBootError` → `app.state.plugin_registry = None` → both surfaces 503).
- **The resolver** `protocol/pack_attestation_resolver.py` (NEW, on the durable critical-controls gate — **CC 133 → 134**) is a trust-input primitive: it locates each pack's artefacts from the deployment root with canonical path-containment (`realpath`+`relative_to`, replicating `trust_gate._canonicalise_under_root`), resolves the single `*.whl` as `cosign_blob_path`, sources the required `sbom_signed_digest` from the SLSA provenance, and fails closed on a 6-value closed enum; it never calls `EntryPoint.load()`.
- **The boot-builder** `harness/registry_boot.py` (off-gate) discovers → resolves → full-registers each pack under `_default`, **per-pack fail-soft**. The **trapdoor**: it builds its OWN `registration_trust_gate` (a `settings.model_copy(signature_root_path=pack_attestation_root_path)` so `verify_pack_signature` canonicalises sig+wheel under the resolver's root) — it accepts NO `trust_gate` param; the A2A endpoint keeps its OWN `a2a_trust_gate` (distinct — agent-card JWS verification uses `trust_root_prefix`, not `signature_root_path`).
- **The lifespan unification** (`portal/api/app.py`): one shared `registry` (the injected `create_app(plugin_registry=...)` wins → no discovery; else the boot) is threaded into both `build_mcp_host(registry=...)` and `A2AEndpoint(plugin_registry=...)` and exposed on `app.state.plugin_registry`. **The `mcp_admission` seam:** the lifespan builds `MCPAdmissionDeps` (SDK-free, built unconditionally on the adapter path) and threads it into registration so `[tool.cognic.mcp]` packs are admittable (no `mcp_admission_deps_required` refusal). `opa_engine=None` (accepted) keeps the boot off the OPA-binary path → **non-sampling MCP packs register; sampling-capable packs default-deny** (also `tenant_sampling_permitted=False` today) — wiring a real sampling `OPAEngine(bundle_path=settings.mcp_sampling_policy_bundle)` is a documented extension; the closeout does NOT claim sampling-capable MCP registration.
- **Honest scope.** Both the MCP host AND the A2A receiver now resolve against a real catalog (this closes the A2A "successful dispatch follows the startup-discovery slice" deferral). A bare image / no installed packs / no `pack_attestation_root_path` → empty catalog (correct). Per-tenant pack trust/visibility (the global `_records` re-key) + the sampling `OPAEngine` remain deferred. Headline-join conformance: `tests/conformance/startup_discovery/test_headline_join.py` (REAL `discover()` → boot → shared registry → both consumers, thin trust boundary, no live cosign). **No migration.** See the **ADR-016** "first production caller of the full attestation pipeline" cross-ref + the **ADR-003** startup-discovery follow-up. Spec + plan: `docs/superpowers/specs/2026-06-21-startup-discovery-trust-registration-design.md` + `docs/superpowers/plans/2026-06-21-startup-discovery-trust-registration.md`.

## Boot-time registration vs MCP discovery probe — decoupling (Proof 1b-1 resolution, 2026-06-24)

**Decision: trust-register-then-defer.** This resolves a finding from the deployed Proof 1b-1: a kind-deployed kernel reached boot-time pack registration and **verified the pack's signature + attestations**, but **refused** the pack with `mcp_discovery_url_refused` — registration ran an OAuth/PRM discovery probe of the pack's manifest `server_url` (a loopback URL, valid in-process but correctly rejected by the prod SSRF guard). A **trust-valid** pack was thus blocked by a **runtime-endpoint** concern. Full finding + model comparison + security analysis: `docs/superpowers/specs/2026-06-24-adr-002-registration-discovery-decoupling-design.md`.

**The decision:**
- **Registration is trust-only.** Boot-time `register_with_full_attestation_check` admits a pack on its offline checks (cosign signature, SBOM, Sigstore bundle, in-toto/SLSA attestations, policy grade) **plus offline MCP manifest-shape validation**. The MCP discovery/OAuth **network** probe is **removed from registration**; it remains at invoke (`list_tools`/`call_tool`, which already performs it). **This supersedes the §"MCP Authorization (Streamable HTTP transport)" item 8 ("Failed auth = registration refused") for the OAuth-PRM path** — a pack's registration status now reflects **trust**, not endpoint reachability.
- **A new `discovery_status` axis** (`unprobed` / `auth_ready` / `refused` / `unreachable`) carries endpoint reachability, set at invoke via a narrow injected `DiscoveryStatusRecorder` (so `MCPHost` gains no raw-registry dependency). `auth_ready` means PRM discovery + token acquisition succeeded — **not** that a session/tools are reachable; a true endpoint-health axis is a later addition.
- **`RefusalReason` is unchanged** — `mcp_discovery_url_refused` / `mcp_oauth_*` values **stay** (no wire break; historical chain rows remain valid); registration simply stops emitting them on this path. The discovery axis surfaces refusals via the separate `MCPAuthzReason` vocabulary.

**Security invariants (unchanged guard):** the MCP SSRF guard is **not weakened** and still fires at invoke; invocation stays **fail-closed** on SSRF / AS-allow-list / unreachable; a trust `registered` status never implies a reachable endpoint.

**`server_url` override policy (defined here; implemented in PR 2 with its own threat-model pass):** the signed manifest `server_url` is a signed default. An operator may supply a per-`(tenant, pack)` override as runtime configuration (never a manifest edit). The resolved URL passes the same SSRF guard at **every** discovery fetch (`server_url`, `WWW-Authenticate: resource_metadata`, well-known PRM); permitting an in-cluster (private-IP) service requires an **explicit, per-tenant, default-deny internal-host allow-list** (specific hosts / narrow CIDRs, never wildcards / `*.svc.cluster.local` / blanket RFC1918).

**Rollout:** PR 1 = registration decoupling + the `discovery_status` axis; PR 2 = the operator URL override + internal-host allow-list (separate workstream). Plan: `docs/superpowers/plans/2026-06-24-adr-002-registration-discovery-decoupling.md`.

## OAuth/discovery-leg SSRF hardening (PR-2a, 2026-06-25)

PR-1 moved the OAuth/PRM discovery probe to invoke. The prefetch SSRF guard
(`_refuse_non_public_discovery_url`) covered the three discovery fetches
(server_url, WWW-Authenticate PRM, well-known PRM) but NOT the two OAuth fetches
in `_request_token` — the AS-metadata discovery GET and the credential-bearing
`token_endpoint` POST. The token endpoint is the sharp gap: its URL comes from
the AS discovery document, so an allow-listed-but-compromised AS could steer the
OAuth client credentials to an internal address (SSRF + credential exfiltration).

PR-2a extends the SAME DNS-resolve-and-check guard to all five legs,
default-deny, with the token_endpoint validated BEFORE any credential material
is built. The refusal reuses `mcp_discovery_url_refused` (semantically widened
to "MCP auth-or-discovery URL refused") and gains a closed-enum `leg`
discriminator (`server_url`/`prm_metadata`/`well_known_prm`/`as_metadata`/
`token_endpoint`) alongside the kept `refused_component` failure-type axis. A
refusal surfaces as `discovery_status=refused` at the MCPHost call sites
(acquire / retry-reacquire / step-up); `refresh_token` is guarded but
unrecorded (no host call site / no key), pinned by a drift test. An AST drift
detector keeps every `_http` fetch guarded.

This is NOT complete SSRF prevention: the DNS-rebinding TOCTOU, the
unresolvable-host pass-through, and the dev-profile skip remain (tracked).
PR-2b adds the per-tenant internal-host allow-list + the operator server_url
override + the deployed Proof 1b-2, and never merges without 2a.

## token_endpoint issuer-origin binding (PR-2b-0, 2026-06-25)

PR-2a guards every discovery/OAuth leg against non-public (SSRF) targets, but the
SSRF guard is necessary, not sufficient, for the credential-bearing
`token_endpoint`: a compromised-but-allow-listed AS can return a `token_endpoint`
at an arbitrary PUBLIC host the guard happily passes, exfiltrating the operator
OAuth `client_secret` (threat-model AS-3b). PR-2b-0 is the tight first slice of
PR-2b — the override store, the internal-host allow-list, and Proof 1b-2 remain
PR-2b proper.

`_request_token` now binds the resolved `token_endpoint` to the selected AS
issuer's origin: AFTER the Leg-5 SSRF guard and BEFORE any credential material is
assembled, `_refuse_token_endpoint_origin_mismatch` refuses unless the
token_endpoint's canonical origin equals the issuer's. Origin canonicalization
(`_canonical_origin`) is identical on both sides — scheme + host + port only;
host lowercased + IDNA A-label + trailing-dot stripped; default ports normalized
(`https`->443, `http`->80); IP literals canonicalized; **userinfo-bearing URLs
rejected outright** (`https://issuer@evil` must never read as the issuer); and
non-http(s) / no-host / malformed-port fail closed. The token POST also sets
`follow_redirects=False`, so a 3xx redirect response cannot replay the credential
to another origin (a 3xx falls through to the existing non-200 refusal).

The refusal REUSES `mcp_oauth_as_discovery_invalid` with a
`validation_failure="token_endpoint_issuer_origin_mismatch"` payload tag — no new
public refusal enum, no `plugin_registry` ripple — and maps to
`discovery_status=refused`. The payload carries only `as_issuer` (allow-listed,
non-secret); it never echoes the raw `token_endpoint` or the secret. A structural
AST pin enforces the order SSRF guard < origin binding < credential assembly.

Residual: the stdlib `idna` codec is IDNA2003; an `idna`-package IDNA2008 upgrade
is a tracked follow-up. The override store, the per-tenant internal-host
allow-list, and the deployed Proof 1b-2 are PR-2b proper, not this slice.

## per-tenant internal-host allow-list + operator server_url override (PR-2b-1, 2026-06-25)

**Scope honesty.** PR-2b-1 is the **code / security-control surface**: the operator
`server_url` override + the per-tenant exact-IP internal-host allow-list that let an
operator point a `(tenant, pack)` at a real in-cluster MCP Service — a private host the
strict-profile SSRF guard (PR-2a/PR-2b-0) refuses today — **without weakening the guard**.
The **deployed Proof 1b-2** — a real in-cluster MCP `Service` reached over this surface,
verified end-to-end (a `discovery_status=auth_ready` probe + a live `list_tools`/`call_tool`
against the override-pinned ClusterIP) — is a **separate, deferred workstream: PR-2b-2**.
PR-2b-1 lands and proves the surface by unit/integration tests only; it makes **no
deployed-reachability claim**. The override store, the allow-list, the guard carve-out, the
`prm_metadata` pin, the resolve-per-use host read, the RBAC family, and the audit event are
all here; the in-cluster exercise is Proof 1b-2 (PR-2b-2).

**Two decision-history-audited stores** (`core/mcp_config/storage.py`, CC; Postgres/Oracle;
`append_with_precondition`-atomic, chain-payload-is-evidence-snapshot, mirroring
`config_overlay`; migration `0012`):

- `MCPServerUrlOverrideStore` — a per-`(tenant, pack)` `server_url` override. The override
  grammar is an **`http://`-IP-literal** (`validate_override_url`): scheme must be `http`
  (an internal `https://<ClusterIP>` is refused — internal legs are HTTP-only), the host
  must be an **IP literal** (a hostname is refused so **no DNS is reintroduced** on the
  MCP-SDK leg, closing the rebinding surface), and the IP must pass the internal floor
  (`ip_passes_internal_floor` — a public host IP like `8.8.8.8` is refused: PR-2b-1 is
  internal-only; public-server repointing is a deferred follow-up). **The signed manifest
  object is never mutated** — the override is read at server_url *use*.
- `MCPInternalHostAllowlistStore` — a per-tenant **default-deny** set of **exact** internal
  IPs (ClusterIPs). The allow-list grammar (`validate_allowlist_ip`) rejects CIDR/range/prefix
  forms (`allowlist_ip_not_exact`), FQDN/garbage (`allowlist_ip_malformed`), and the
  hard-block floor (metadata/loopback/link-local/multicast/unspecified/reserved + the
  canonical IMDS IPs → `allowlist_ip_hard_blocked` — never listable).

Both validators raise the closed-enum `MCPConfigRejected(reason)` (a **9-value**
`MCPConfigRefusalReason` Literal: 5 override + 4 allow-list) **from inside** the audited
`append_with_precondition` closure, so a refusal rolls back the chain row + state row
atomically. The shared `ip_passes_internal_floor(ip)` predicate (True **only** for a private
internal IP, requiring `ip.is_private`) is consumed at **set-time** (the validators) **and**
**read-time** (the guard, defense-in-depth against a corrupted allow-list).

**The guard carve-out (`protocol/mcp_authz.py`, CC).** `_refuse_non_public_discovery_url` is
widened to `-> str | None` and consulted on the **three MCP-resource legs only**
(`_RESOURCE_LEGS = {server_url, prm_metadata, well_known_prm}`) — **never** the OAuth legs
(`as_metadata`, `token_endpoint`, which stay hard-public-only per PR-2b-0). For an internal
host it resolves once and permits the leg **iff** every conjunct holds: the leg ∈
`_RESOURCE_LEGS`, the scheme is `http`, an injected `internal_host_allowlist_store` is wired,
and **every** resolved IP is an allow-listed exact IP that **also** re-passes
`ip_passes_internal_floor` (the read-time floor catches a metadata/loopback entry that
bypassed set-time validation). On a permit it returns the **pinned validated IP** (the
fetch connects there) and emits the audit event; **any** miss / scheme violation / floor
failure / store-unreachable is the **default-deny** `mcp_discovery_url_refused`
(`refused_component="host_address"`). A public host returns `None` (no allow-list consult,
no permit event) and proceeds. A drift-pin AST test gates the carve-out on
`leg in _RESOURCE_LEGS` AND `scheme == "http"`.

**The `prm_metadata` resolve-and-pin (Option-A url-rebind).** `server_url`/`well_known_prm`
are IP-literal (override grammar / IP-derived) so their resolve-to-self pin is trivial; the
`prm_metadata` URL comes from the pack's `WWW-Authenticate` header and may be a **hostname** —
the one kernel-owned hostname leg. `_fetch_prm` captures the guard's returned pinned IP and
**rebinds `url`** to `http://<pinned-ip>[:port]/...` (IPv6 bracketed) with the **original
authority preserved as the `Host` header**, closing the TOCTOU rebinding window. The fetch's
first positional arg stays `url` (the security AST detector that requires every `_http` fetch
to be guarded is untouched — Option A); `timeout` is preserved; HTTP-only ⇒ no SNI/cert
concern.

**Resolve-per-use override on `MCPHost` (`protocol/mcp_host.py`, CC).** An injected
`override_store` is consulted at the `server_url` read sites via async
`_effective_server_url(*, tenant_id, server_id, manifest_url)` — a **post-construction**
override change is observed on the next call, and a store-unreachable read **fails safe to
the signed manifest value**. The **`list_tools` cache key includes the effective URL**
(`(tenant_id, server_id, manifest_scopes, effective_url)`) so a changed override is a cache
**miss** → re-fetch (the P1 stale-cache fix — a prior override-A-computed tool list never
leaks for an override-B caller).

**The audit event (DD-2).** When the guard permits a host **because of an allow-list hit**,
it emits a **dedicated** `audit.mcp_allowlist_permitted` `AuditEvent` carrying `tenant_id` +
`request_id` (top-level fields) and a payload of `{leg, host, resolved_ips}` — **no
`pack_id`** is threaded through the authz stack (the pack is correlated via the MCPHost call
path + request evidence; pack-identity threading is a deferred follow-up). `discovery_status`
stays a pure **reachability** signal; the permit is **not** a new `discovery_status` value.
The spec §9 evidence-requirements section is synced to this one spelling (no `pack`).

**RBAC + Human-only write boundary.** A new family `MCPInternalAccessRBACScope`
(`mcp.override.{read,write}` + `mcp.allowlist.{read,write}`) is value-disjoint from
`mcp.tool.*` and `mcp.`-prefixed (pinned). The operator endpoints (`portal/api/mcp_config/`,
CC) — PUT/DELETE/GET `…/mcp-overrides/{pack_id}` + PUT/DELETE/GET `…/mcp-allowlist[/{ip}]`
under `/api/v1` — gate **both write surfaces** behind `RequireHumanActor` per the AGENTS.md
"Per-tenant allow-list changes" / "Per-tenant … changes" human-only-decisions rule (a service
token holding the write scope is refused at the dep chain, `actor_type=human` threaded onto
the chain row); the GET reads permit service actors. Grammar is enforced in the store; the
route maps `MCPConfigRejected.reason` → 422 and never validates or touches the DB itself.

**Wiring + fail-closed posture.** `build_runtime` constructs both stores next to the overlay
store (pure engine constructors) and holds them on `Runtime`; `build_mcp_host` threads
`override_store` into the `MCPHost` and `internal_host_allowlist_store` into its
`MCPAuthzClient` (the SAME instances; identity pinned by a wiring/integration test);
`create_app` mounts the override + allow-list operator routers via a 3-state block
(both stores → mount + flags True; partial → one fail-loud warning; neither → silent
pack-only default). Fail-closed throughout: allow-list store unreachable → empty allow-list →
default-deny; override store unreachable → the signed manifest `server_url`. Residual: an
operator who allow-lists a **cross-tenant** ClusterIP is the audited **AS-9** residual
(detectable/attributable via the set-time chain rows, not prevented); the attacker-driven
cross-tenant case (AS-5) **is** closed by exact-IP matching + the pin. **No deployed-cluster
claim — Proof 1b-2 is PR-2b-2.** Threat model: the merged spec
`docs/superpowers/specs/2026-06-25-pr2b-mcp-internal-host-override-allowlist-design.md`; plan:
`docs/superpowers/plans/2026-06-25-pr2b-1-mcp-override-allowlist.md`.

## References
- [Model Context Protocol — 2026 roadmap](https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/)
- [MCP — Wikipedia](https://en.wikipedia.org/wiki/Model_Context_Protocol)
- ADR-001 (this repo's OS-only premise)
- ADR-003 (A2A for inter-agent comms — complements this)
- Parent repo `bmzee/cognic` ADR-009 (import-discipline test as foundation)
