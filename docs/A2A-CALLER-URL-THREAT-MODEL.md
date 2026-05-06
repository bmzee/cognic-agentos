# A2A Caller-Controlled URL Threat Model

**Status:** Authoritative reference for why outbound A2A dispatch URLs in Cognic AgentOS MUST come from JWS-verified Agent Cards or operator-controlled `Settings` fields, never from caller input or model output. This document complements [`ADR-003`](adrs/ADR-003-a2a-inter-agent.md) (A2A inter-agent protocol) and the Sprint-6 plan-of-record's §"Doctrine Decision B".

Pack authors and bank operators read this to know why outbound A2A URLs are gated; reviewers consult it when evaluating any pack that emits A2A traffic. Mirrors the structure of [`docs/MCP-STDIO-THREAT-MODEL.md`](MCP-STDIO-THREAT-MODEL.md) (Sprint 5 T3).

## 1. Background — April 2026 outbound-URL disclosures

The same April-2026 disclosure cycle that produced the OX Security MCP STDIO command-injection findings (corroborated by Cloud Security Alliance's systemic-risk analysis) identified **caller-controlled outbound URLs** as the LLM-era equivalent for network-only protocols like A2A. The pattern:

> A model-controlled string (or a string from a remote pack manifest, an inbound A2A envelope's `target_url` field, or a configuration file) flows into the host process's `httpx.AsyncClient.{get,post,put,delete}(url=...)` argument. Because the URL is attacker-shaped, the call becomes **arbitrary HTTP egress** in the AgentOS process — data exfiltration; SSRF into internal endpoints; chain hijack into a malicious downstream agent.

**AgentOS's response** (codified in the Sprint-6 plan §"Doctrine Decision B"): every outbound A2A dispatch URL MUST come from a **JWS-verified Agent Card's `supportedInterfaces[].url`** OR from an operator-controlled `Settings.a2a_*_url` field. Caller-controlled URLs are refused at every reachable surface.

## 2. Threat model

### Adversary capability

The adversary controls **at least one** of:

- **A model output** — string content the LLM produces that flows through the agent into A2A dispatch.
- **An inbound A2A envelope field** — caller-supplied data on a received A2A request (e.g., a hostile `target_url` field, a malicious `agent_card.url` claim).
- **A remote agent's published Agent Card** — fetched from a non-allow-listed signer, claiming a hostile `supportedInterfaces[].url`.
- **A configuration file** — operator-readable config (`.env`, Vault entries) that an attacker has tampered with via a separate vector.

### Defended asset

- **AgentOS host process integrity** — the bank-deployed process running the kernel + (optionally) default-adapters image.
- **Tenant data isolation** — preventing exfiltration of customer PII / payment authority / regulator communications inside the AgentOS process.
- **Network-egress posture** — preventing SSRF into internal endpoints (cloud-metadata, sidecar admin APIs, intra-cluster services) reachable from the AgentOS process.
- **Cross-agent chain integrity** — preventing redirector attacks that hijack the audit chain into a malicious downstream agent.

### Out-of-scope

- **Network-perimeter egress controls** — covered by the bank's network security perimeter (egress proxies, DLP appliances), not this threat model.
- **A2A 1.0 spec wire-format compliance** — covered by [`docs/A2A-CONFORMANCE.md`](A2A-CONFORMANCE.md) and the schema-drift CI gate.
- **Authentication of the caller making an inbound A2A request** — covered by `protocol/a2a_authz.py` (Sprint-6 T5: per-tenant pinned-token validation); this threat model assumes the caller has authenticated and focuses on what data fields are trustworthy *given* that authentication.
- **Push-notification webhook URLs** — refused at the wave gate in Wave 1 (`A2APolicyRefusalReason.wave2_feature_refused`); the threat model amendment for that surface lands when push-notification support lifts the refusal.

## 3. The four reachable URL-source surfaces

Restated from the Sprint-6 plan-of-record §"Doctrine Decision B":

### 3.1 Inbound `target_agent` field on a received A2A envelope

This is an **entry-point name** (string of the form `cognic_agent_<name>`), NEVER a URL. The endpoint resolves the name through the plugin registry to a registered pack, then calls `pack.handle(message)` in-process.

**No URL is ever constructed from this field.** Refusal vector: any reachable code path that tries to interpret `target_agent` as a URL is an architecture-test failure (T4) AND a runtime-canary failure (T14). Closed-enum reason on attempted URL-shaped value: spec wire code `method_not_found` + `policy_reason="unknown_target"` (the registry has no entry-point under URL-shaped names; mapping unknown-target to JSON-RPC's `method_not_found` is the spec-correct semantic). The runtime canary additionally asserts the HTTP-client sentinel records ZERO method calls — the URL never leaks past routing into a constructor.

### 3.2 Outbound `spawn_subagent(target_agent, ...)` (ADR-005, Sprint 8)

Sprint 6 ships only the *outbound transport* layer. The orchestration semantics ship with the sub-agent primitive in Sprint 8 (per Doctrine Decision D in the Sprint-6 plan).

When `spawn_subagent` lands, the `target_agent` argument is again an entry-point name; the sub-agent module resolves it through the plugin registry, fetches the registered pack's signed Agent Card, verifies the JWS via Sprint-4's per-tenant trust root, and dispatches to the URL inside the verified `supportedInterfaces[].url` array.

**`spawn_subagent` MUST NOT accept a `target_url` kwarg.** **T14 covers this surface INDIRECTLY in Sprint 6** — `TestSubagentTargetIsEntryPointName` feeds URL-shaped target_agents to `A2AEndpoint.handle` and asserts they're refused as unknown targets (same `method_not_found` + `unknown_target` posture as §3.1) and never reach an outbound URL constructor. The direct `spawn_subagent(target_url=...)` canary lands alongside the Sprint 8 sub-agent primitive (the production stub does not exist yet — Sprint 6 deliberately does not introduce production scaffolding ahead of Sprint 8).

### 3.3 Agent Card discovery URL

When AgentOS calls a remote agent, it constructs the discovery URL as:

```python
f"{origin}/.well-known/agent-card.json"
```

where `origin` is derived from the registered pack's `[tool.cognic.identity].agent_card_origin` field — a manifest-declared, cosign-signed value, NOT a caller input.

The well-known suffix `.well-known/agent-card.json` is **constant, not parameterisable** — no caller can override the suffix.

The architecture test (T4) asserts: every Agent Card fetch in `protocol/a2a_agent_cards.py` constructs the URL via the constant suffix; no `format()` / f-string interpolation of caller-controlled strings into the suffix slot. The runtime canary (T14) `TestOutboundDispatchURLFromVerifiedCard` complements the static check by driving the **real** `A2AAgentCardVerifier.fetch_and_verify_outbound_card` against 13 non-origin `target_origin` shapes (path / query / fragment / userinfo / non-`http(s)` scheme / non-string) and asserting each is refused with `agent_card_jws_blob_unreadable` carrying `rejected_component` ∈ `{not_string, scheme, netloc, path, query_or_fragment, userinfo}` BEFORE `httpx.AsyncClient.get` is awaited (the spy on `http_client.get` is asserted never-awaited).

### 3.4 Push-notification webhooks (Wave-2 feature)

Push-notification subscribe is spec-valid in A2A 1.0 but Wave-2 in AgentOS — refused in Wave-1 at the inbound endpoint Wave-2 gate with spec wire code `unsupported_operation` + `policy_reason="wave2_feature_refused"` + sub-tag `wave2_feature="push_notification_subscribe"`. The `_classify_wave2_feature` walker matches both `tasks/pushNotificationConfig/set` and `tasks/pushNotificationConfig/get` to this sub-tag.

The webhook URL inside `params` would be caller-controlled by definition; refusing at the method-name gate (BEFORE any URL parsing) means no caller-controlled webhook URL ever reaches `httpx`. When push-notification support lands, the caller-URL threat model amendment lands alongside it with explicit per-tenant URL allow-list + Vault-stored signing-key + outbound mTLS — same shape Sprint-5 T13's args-side validation will get when Sprint 8 lifts the STDIO umbrella.

## 4. Sprint-6 enforcement (this sprint)

Sprint 6 enforces the full doctrine across two layers:

### 4.1 Architecture-test backstop (T4)

**`tests/architecture/test_a2a_no_caller_controlled_url.py`** is the static-AST analog of Sprint-5's `test_mcp_stdio_no_subprocess.py`. It walks every module under `protocol/a2a_*` and refuses any `httpx.AsyncClient.{get,post,put,patch,delete,request,send}(url=<expression>)` where `<expression>` traces to a forbidden source. The full ban list (per the R1-R6 reviewer-correction lineage):

- **Function parameters** of the call site (caller-supplied URL flowing through the function signature).
- **Function-parameter-rooted attribute chains** (R2 P2): even card-shaped chains like `target_card.supported_interfaces[0].url` are refused when `target_card` is a function parameter; the chain root is by definition caller-controlled. **Exception:** `self` and `cls` (Python-convention method receivers) are NOT treated as caller-supplied — `self.settings.a2a_*_url` chains are allowed via the settings allow path.
- **Inbound-request attribute chains** with root in `{request, message, payload, envelope, body, task}` (R1 P2 #2): refused **before** the AgentCard allow-list heuristics, so chains like `request.supported_interfaces[0].url` (which LOOK card-shaped) are correctly refused.
- **Concatenations** including any of the above as a component.

URL-extraction is **method-aware** (R1 P2 #1):

- `get` / `post` / `put` / `patch` / `delete` — URL at positional arg 0 OR keyword `url=`.
- `request` — URL at positional arg **1** (after the method name) OR keyword `url=`. Without method-awareness, `client.request("POST", target_url)` would have classified the literal `"POST"` as the URL and the actual caller-controlled URL would have slipped past.
- `send` — first positional arg is a `httpx.Request` object, not a URL. Static AST cannot trace into Request construction; flagged as "no statically-identifiable URL argument" and the runtime canary takes over.

The httpx-call detector is **narrowed to actual httpx receivers** (R3 P2): bare names + attribute leaves containing `client` / `http` / `httpx` fragments, OR `httpx`-rooted attribute chains, OR `httpx.AsyncClient(...)` constructor receivers. Unrelated `.get()` / `.post()` calls on dict-like objects (`self._tasks.get(task_id)`, `headers.get(name)`, `cache.get(key)`, `store.get(id)`) are NOT flagged — preventing false-positives on T9/T11 task-store / header-dict / cache-lookup code.

A **binding pre-pass** (R4 P2 + R5 P2) tracks every name bound to an httpx client constructor, so renamed bindings are recognised even when the name doesn't match a receiver fragment:

- `transport = httpx.AsyncClient(); await transport.get(url)` — bound name `transport`.
- `self.session = httpx.Client()` in `__init__`; `self.session.get(url)` in any other method — class-attribute leaf `session`.
- `async with httpx.AsyncClient() as session:` — context-manager binding `session`.
- `import httpx as hx; transport = hx.AsyncClient()` — alias-tracked module name `hx`.
- `from httpx import AsyncClient; transport = AsyncClient()` — alias-tracked bare-constructor name `AsyncClient`.
- `from httpx import AsyncClient as Async; transport = Async()` — renamed bare-constructor.

Binding visibility is **scope-aware** (R5 P3): module-scope bindings are visible everywhere; function-scope bindings are visible only within the same function; class-scope instance-attribute bindings (`self.X = httpx...`) are visible to all methods of the same class but NOT to other classes or to module-scope code. This prevents a `session = httpx.AsyncClient()` in one function from making unrelated `session.get(...)` calls in other functions wrongly flagged as httpx.

**Direct alias-constructor receivers** (R6 P2) are also caught — these don't go through the binding pre-pass because no name is bound, but they're recognised by threading the alias sets into `_is_httpx_receiver`'s Call-receiver branch (which delegates to the alias-aware `_is_httpx_constructor_call` matcher):

- `import httpx as hx; await hx.AsyncClient().get(target_url)` — direct module-aliased constructor receiver.
- `from httpx import AsyncClient; await AsyncClient().get(target_url)` — direct bare-Name constructor receiver.
- `from httpx import AsyncClient as Async; await Async().get(target_url)` — renamed bare-Name constructor receiver.
- `import httpx as hx; hx.Client().get(target_url)` — sync-Client variant.
- `httpx.AsyncClient().get(target_url)` — canonical (non-aliased) form, still recognised after the R6 alias-aware refactor.

The **allowed URL sources** that pass the test:

1. String literal.
2. `Settings.a2a_*_url` attribute access where the chain root is NOT a function parameter (e.g., `self.settings.a2a_outbound_url`, `settings.a2a_outbound_url` with a module-scope `settings`).
3. Hardcoded well-known suffix concatenated to a non-caller-controlled origin via f-string (`f"{verified_card.origin}/.well-known/agent-card.json"`).
4. Attribute access rooted at a **verifier-output** name (`verified_card` / `verified_agent_card` — the tight allow-list of names that signal "this came out of `TrustGate.verify_jws_blob`") with chain containing `supported_interfaces` or ending with `.url`. **Generic `card` / `agent_card` chain roots are NOT in the allow-list** (R2 P2) and fall through to "unknown" — implementations MUST rebind verifier output through `verified_card` / `verified_agent_card` before constructing dispatch URLs.

The test ships with self-tests pinning the collector + the URL-source classifier + the httpx-call detector + the URL extractor + the binding pre-pass + the import-alias pre-pass + the scope-aware lookup + the direct alias-constructor receiver detector, plus end-to-end module scenarios for every R1-R6 false-negative class.

### 4.2 Runtime canary (T14)

**`tests/unit/protocol/test_a2a_no_caller_controlled_url.py`** (T14 — same filename as the architecture test but lives under `tests/unit/protocol/`; separate module). Drives the **real** `A2AEndpoint` + `A2AAgentCardVerifier` + `A2AAuthzClient` (only audit / decision-history / registry / secret-adapter mocked) — every adversary-controlled URL surface MUST produce the correct closed-enum refusal at the correct entry point. Specifically:

- `TestCallerURLRefusedAtEndpoint` — every `target_agent` shape that resembles a URL (`https://...`, `//...`, `file://`, `javascript:`, `data:`, plus path-shaped names like `agent_with/slash`) is refused at the routing gate (gate 4) with spec wire code `method_not_found` + `policy_reason="unknown_target"` (the registry has no entry-point under those names). The fixture verifies an HTTP-client sentinel records ZERO method calls — the URL never leaks past routing into a constructor. **Spec rationale:** unknown target names map to JSON-RPC `method_not_found` semantically; `parse_error` / `invalid_request` are reserved for malformed JSON-RPC payloads.
- `TestOutboundDispatchURLFromVerifiedCard` — every non-origin `target_origin` (path / query / fragment / userinfo / non-`http(s)` scheme / non-string) is refused inside `A2AAgentCardVerifier.fetch_and_verify_outbound_card` BEFORE `httpx.AsyncClient.get` is called. Spy on `http_client.get` confirms it was never awaited. Pinned reason: `agent_card_jws_blob_unreadable` carrying `rejected_component` ∈ `{not_string, scheme, netloc, path, query_or_fragment, userinfo}`.
- `TestSubagentTargetIsEntryPointName` — **indirect coverage only** for Sprint 6. Sub-agent dispatch (whose primitive ships in Sprint 8 per ADR-005) takes entry-point names, not URLs. The Sprint-6 transport-side invariant pinned here is INDIRECT: URL-shaped target_agents fed to `A2AEndpoint.handle` are refused as unknown targets and never reach an outbound URL constructor. The direct `spawn_subagent(target_url=...)` canary lands alongside the Sprint 8 sub-agent primitive.
- `TestPushNotificationWebhookRefusedWave1` — `tasks/pushNotificationConfig/{set,get}` methods are refused at the Wave-2 gate with spec wire code `unsupported_operation` + `policy_reason="wave2_feature_refused"` + sub-tag `wave2_feature="push_notification_subscribe"` BEFORE the caller-supplied webhook URL in the params is ever parsed.
- `TestThreatModelInvariants` — pin the four closed-enum vocabularies (`A2AAuthzReason` 8 values, `AgentCardValidationReason` 11 values, `A2AErrorCode` 14 values, `A2APolicyRefusalReason` 11 values). Drift = wire-protocol-public; any addition trips a test and forces an explicit doctrine-update PR.

Companion canary modules: **`test_a2a_anonymous_refused.py`** (drives the real `A2AAuthzClient.validate_inbound_token` against 7 adversarial Authorization-header shapes; pinned to closed-enum `A2AAuthzReason` values), **`test_a2a_wave2_features_refused.py`** (drives `A2AEndpoint._classify_wave2_feature` via `handle` against 11 Wave-2 traffic shapes — push-notification methods, multimodal `Part` raw/url fields, image/audio/video media-type prefixes, deeply-nested unscannable payloads, mTLS-in-card via `A2AAgentCardVerifier.validate_card`), **`test_a2a_outbound_version.py`** (instance-level mock on `_http` capturing every outbound `.get()` and asserting `A2A-Version: 1.0` on each).

### 4.3 JWS verification (T7)

Outbound dispatch never sends to a URL the caller supplied — every URL traces to a JWS-verified Agent Card's `supportedInterfaces[].url`. The verification step is owned by `protocol/a2a_agent_cards.py` Pass 3 (T1 R1 P2 added the JWS pass to the validator) using `joserfc` against Sprint-4's per-tenant trust root. Cards from non-allow-listed signers → call refused with `a2a_agent_card_signer_not_allowlisted`.

## 5. Sprint-6 explicit non-enforcement

These items are NOT enforced in Sprint 6:

- **Outbound mTLS** — Wave-2 per ADR-003 + `docs/A2A-CONFORMANCE.md`. Wave-1 uses per-tenant pinned tokens for caller authentication; Wave-2 adds mTLS for cross-pod / cross-pack auth within a single tenant.
- **Verifiable Credentials for cross-organisation A2A** — Wave-3 per ADR-003. Federated A2A across organisations is deferred until AGNTCY identity adoption matures.
- **Push-notification webhook URL allow-listing** — refused entirely in Wave-1 (`wave2_feature_refused`); the allow-list mechanism lands when push-notification support lifts the refusal.

## 6. The architecture test as backstop

Even if a future maintainer accidentally passes a caller-controlled URL to `httpx.AsyncClient.{get,post,put,patch,delete,request,send}` somewhere under `protocol/a2a_*`, the architecture test at `tests/architecture/test_a2a_no_caller_controlled_url.py` (Sprint-6 T4) trips and CI fails. §4.1 above enumerates the full ban list, the method-aware URL extraction, the receiver narrowing, the binding pre-pass, the import-alias tracking, and the scope-aware binding visibility — all of which together guarantee that a caller-controlled URL cannot reach `httpx` regardless of how the call shape, the receiver name, or the import is spelled.

The test is mechanical, fast, and lives at the architecture-doctrine boundary — it expresses "outbound A2A URLs MUST come from verified-card or operator-controlled sources" as code, not as a docstring promise.

## 7. The runtime canary as runtime backstop

If a future maintainer somehow evades the static-AST check (e.g., via dynamic dispatch through a wrapper that obscures the call shape), the runtime canary (`tests/unit/protocol/test_a2a_no_caller_controlled_url.py`, T14) trips on the resulting refusal vector. Specifically: every reachable path that could construct a URL from caller-controlled input fails closed at runtime.

Both must hold for the threat model to be intact. If either fails, the threat model is breached; CI fails the build; the offending change is reverted before merge.

## Cross-reference

- [`ADR-003`](adrs/ADR-003-a2a-inter-agent.md) — A2A inter-agent protocol; doctrine source-of-truth
- [`ADR-005`](adrs/ADR-005-subagent-primitive.md) — sub-agent primitive (Sprint-8 dependency for outbound `spawn_subagent`)
- [`ADR-016`](adrs/ADR-016-supply-chain-controls.md) — supply-chain controls (cosign verification of the wheel that ships the manifest)
- [`docs/A2A-CONFORMANCE.md`](A2A-CONFORMANCE.md) — A2A 1.0 capability matrix Sprint 6 enforces
- [`docs/MCP-STDIO-THREAT-MODEL.md`](MCP-STDIO-THREAT-MODEL.md) — Sprint 5's parallel threat-model doc (4-gate doctrine; the structural template this document mirrors)
- [`docs/superpowers/plans/2026-05-04-sprint-6-a2a-endpoint.md`](superpowers/plans/2026-05-04-sprint-6-a2a-endpoint.md) — Sprint-6 plan-of-record (§"Doctrine Decision B")
- `tests/architecture/test_a2a_no_caller_controlled_url.py` (Sprint-6 T4) — architecture-test backstop
- `tests/unit/protocol/test_a2a_no_caller_controlled_url.py` (Sprint-6 T14) — runtime canary
