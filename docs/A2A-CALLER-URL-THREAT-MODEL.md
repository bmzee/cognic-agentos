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

**No URL is ever constructed from this field.** Refusal vector: any reachable code path that tries to interpret `target_agent` as a URL is an architecture-test failure (T4) AND a runtime-canary failure (T14). Closed-enum reason on attempted URL-shaped value: `a2a_target_must_be_entrypoint_name`.

### 3.2 Outbound `spawn_subagent(target_agent, ...)` (ADR-005, Sprint 8)

Sprint 6 ships only the *outbound transport* layer. The orchestration semantics ship with the sub-agent primitive in Sprint 8 (per Doctrine Decision D in the Sprint-6 plan).

When `spawn_subagent` lands, the `target_agent` argument is again an entry-point name; the sub-agent module resolves it through the plugin registry, fetches the registered pack's signed Agent Card, verifies the JWS via Sprint-4's per-tenant trust root, and dispatches to the URL inside the verified `supportedInterfaces[].url` array.

**`spawn_subagent` MUST NOT accept a `target_url` kwarg.** The runtime canary asserts this. Closed-enum reason if a future caller tries: `a2a_dispatch_url_not_from_verified_card`.

### 3.3 Agent Card discovery URL

When AgentOS calls a remote agent, it constructs the discovery URL as:

```python
f"{origin}/.well-known/agent-card.json"
```

where `origin` is derived from the registered pack's `[tool.cognic.identity].agent_card_origin` field — a manifest-declared, cosign-signed value, NOT a caller input.

The well-known suffix `.well-known/agent-card.json` is **constant, not parameterisable** — no caller can override the suffix.

The architecture test (T4) asserts: every Agent Card fetch in `protocol/a2a_agent_cards.py` constructs the URL via the constant suffix; no `format()` / f-string interpolation of caller-controlled strings into the suffix slot. Closed-enum reason on violation: `a2a_agent_card_discovery_path_not_constant`.

### 3.4 Push-notification webhooks (Wave-2 feature)

Push-notification subscribe is spec-valid in A2A 1.0 but Wave-2 in AgentOS — refused in Wave-1 with `A2APolicyRefusalReason.wave2_feature_refused` (closed-enum sub-tag `push_notification`).

The webhook URL would be caller-controlled by definition; refusing the entire feature in Wave-1 means no caller-controlled webhook URL ever reaches `httpx`. When push-notification support lands, the caller-URL threat model amendment lands alongside it with explicit per-tenant URL allow-list + Vault-stored signing-key + outbound mTLS — same shape Sprint-5 T13's args-side validation will get when Sprint 8 lifts the STDIO umbrella.

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

**`tests/unit/protocol/test_a2a_no_caller_controlled_url.py`** (T14 — same filename as the architecture test but lives under `tests/unit/protocol/`; separate module). Mirrors Sprint-5 T13's class shape. Specifically:

- `TestInboundTargetAgentIsEntrypointName` — every `target_agent` shape that resembles a URL (`https://...`, `//...`, `file://`, `javascript:`, `data:`) is refused at envelope validation with closed-enum `a2a_target_must_be_entrypoint_name`.
- `TestOutboundSpawnSubagentNeverAcceptsURL` — `A2AEndpoint.dispatch_outbound(target_agent="...")` reachable via every API surface refuses any kwarg matching `*_url` (TypeError-typed at the boundary).
- `TestAgentCardDiscoverySuffixIsConstant` — `protocol/a2a_agent_cards.py` discovery code never interpolates a caller value into the well-known suffix. Module-shape assertion: the constant `_AGENT_CARD_WELL_KNOWN_SUFFIX = "/.well-known/agent-card.json"` is pinned.
- `TestWave2WebhookRefused` — push-notification subscribe is refused with closed-enum `A2APolicyRefusalReason.wave2_feature_refused`, observable end-to-end through the audit + decision-history chain.

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
