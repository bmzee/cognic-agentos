# M8.5-C — Cognic Harness v1 + HP-4 kernel slice — design

**Status:** design ratified through three review chunks (2026-07-11); implements the recon locks committed at `07327fb1` (ADR-028 spec §0.2 HP-1..HP-5 + §0.3 naming lock + §0.4). This spec never relitigates a lock; where it repeats one, the lock text governs.

**Deliverables:** (T1) the HP-4 kernel slice in `cognic-agentos`; (T2) the `cognic-harness` repository (v1 product); (T3) the M8.5-C live proof (`infra/proof-m85c/`, this repo). No implementation precedes the plan gate.

---

## 1. Scope and decomposition

Three sequenced tracks:

- **T1 — HP-4 kernel slice** (this repo; blocks the live proof, lands first): paginated approval queue + actor-bound grant replay. A migration/engine slice, not merely route plumbing (§2).
- **T2 — `cognic-harness` repo**: FastAPI BFF + Jinja2 + plain CSS + progressively enhanced HTML (vendored, checksum-pinned htmx only where it removes real friction), three screens (§3), Keycloak OIDC per the identity topology (§4).
- **T3 — live proof** on kind (§5) with the `cognic-tool-approval-probe` pack (§6).

**Excluded from M8.5-C** (locks; listed for the plan's fence): SSE/projectors (M8.5-F), erasure (M8.5-F), HP-3 entitlement admin, **database/data-source credentials, credential brokerage, and credential forms** (custody lock — brokerage is designed at M8.5-D, live-proven at M8.5-E; the harness has no DB client and no data-source secret handling of any kind), the operator console, HP-5 conversational approval resume (the approvals screen shows MCP-surface requests only; chat stays auto-tier), and any `401 + WWW-Authenticate` wire slice (deferred; M8.5-C preserves the kernel's existing `403 actor_unauthenticated` mapping). **Explicitly IN scope** (not "secrets" in the excluded sense): the BFF's OIDC client secret and the session/token custody it exists to perform — §3.3's contract governs them.

## 2. T1 — HP-4 kernel slice

### 2.1 Paginated approval queue

- **Migration 0017:** composite index on `approval_requests (created_at, request_id)`; guarded + re-runnable per the 0016 discipline (inspector-guarded DDL, shape validation, runtime-table parity pinned); live PostgreSQL + Oracle migration/query tests in the marker-gated lanes.
- **Storage:** `(created_at ASC, request_id ASC)` keyset with Oracle-portable tuple expansion (`created_at > :c OR (created_at = :c AND request_id > :r)`); typed cursor position + strict bounded decoder (versioned, base64url `validate=True`, bool-guarded exact-int version, tz-aware timestamps — the M8.5-B finding-5 lessons from birth); `limit+1` probe; a shared statement builder consumed by the SQL-shape regression.
- **Route:** `GET /api/v1/approvals/` gains `limit` (1..200, default 50) + `cursor` query params. The response body **stays `list[ApprovalSummaryResponse]`** (pinned consumers exist); pagination rides a **relative** `Link: </api/v1/approvals/?cursor=…&limit=…>; rel="next"` response header, documented in OpenAPI. No envelope, no versioning, no absolute URLs.
- **Cursor wire-error contract:** every decode failure — malformed base64url, wrong/non-int version, invalid field types, over-length, naive/unparseable timestamp — returns `422 {"detail": {"reason": "cursor_invalid"}}` (the M8.5-B closed reason reused). A maximum encoded cursor length is pinned and enforced BEFORE decoding.
- **No `state` filter.** The live queue is a fixed actionable projection over `pending | awaiting_second`; terminal history belongs to evidence surfaces. **ADR-014 receives a dated amendment** retiring the advertised `?status=` filter and recording this projection contract.

### 2.2 Actor-bound grant replay

- Owned by **`ApprovalEngine.verify_grant_for_action()`**: a required `expected_originator_subject` parameter compared against the persisted `originator_subject` of the granted request. **All four replay consumers are audited and updated** — MCP host, sandbox admission, scheduler, memory. No post-return consumer-local comparison anywhere.
- **Vocabulary (drift-pinned), ALL FOUR consumers:** core `approval_originator_mismatch`; MCP wire `tool_approval_originator_mismatch` (portal 403); sandbox `sandbox_approval_originator_mismatch`; scheduler `refused_approval_originator_mismatch`; memory `memory_approval_originator_mismatch`. The sandbox/scheduler/memory verify-paths currently re-raise every verify-time refusal except `approval_binding_mismatch` — each gains its explicit mapping, with owning ADR amendments (ADR-004/ADR-022/ADR-019) where the value is wire-visible. Subjects never appear in wire details or logs — request ID + the bounded reason only.
- **Verification precedence (locked):** tenant-not-found collapse → originator check → args/tool binding → state projection. Pinned by ordering tests in the engine suite.
- **Sandbox wake passthrough:** `sandbox/protocol.py`'s `_APPROVAL_WAKE_PASSTHROUGH_REASONS` closed set expands 5 → 6 to carry `sandbox_approval_originator_mismatch` — otherwise the wake wrapper would collapse the new reason to `sandbox_wake_policy_revalidation_failed`. Docker + Kubernetes backends stay lockstep, pinned by the existing cross-backend drift tests.
- **Semantics distinction (lock):** actor-binding restricts *replay* to the original requesting subject; the *approver* remains a distinct human for four-eyes. Two identities, two roles, one request.

### 2.3 Gate posture

`core/approval/engine.py`, `core/approval/storage.py`, approval types, every replay consumer, and the MCP wire mapping are the blast radius — existing CC surfaces extended under full CC discipline (fresh-coverage 95/90 at the promoting commit, TM-revert pins on the binding + keyset arms, closed-enum drift detectors). No new gate module expected; the route/DTO layer follows the established off-gate portal pattern with its own contract tests.

## 3. T2 — the `cognic-harness` repository

### 3.1 Stack and discipline

Python 3.12 · FastAPI/Starlette · Jinja2 (autoescape on) · plain CSS · progressively enhanced HTML · vendored checksum-pinned htmx where it removes friction (chat turn append, queue refresh, transcript paging) · Authlib for OIDC (never hand-rolled OAuth) · `httpx` for the typed AgentOS client · Playwright (Python) for e2e. Repo discipline mirrors `cognic-agentos`: uv, ruff, mypy strict, pytest, guard-staged commits, the same CI shape.

React was rejected for M8.5-C because three request/response screens do not justify its complexity and npm supply chain — not because a SPA behind a BFF would expose tokens (it would not). v2 ADK is the **same product/repo**; the module boundaries below keep the rendering layer replaceable so a richer UI can later sit behind the same Python BFF.

### 3.2 Module boundaries

```text
bootstrap/        composition root — the ONLY module importing all four below
auth/             OIDC (Authlib), cookies, CSRF, SessionStore + backends, token lifecycle
agentos_client/   typed, allow-listed AgentOS calls (httpx); outbound credential provider
application/      ports + use cases; per-screen view models; ZERO authorization decisions
web/              Jinja templates, static assets, htmx wiring, security middleware
```

Import-lint pins: `web` and `application` never import `auth` internals or `httpx`; `application` owns the ports that `auth` and `agentos_client` implement; `web` consumes public `application`/`auth` facades only. **Raw-token boundary (tightened):** ID and refresh tokens exist **exclusively** inside `auth/` + the `SessionStore`; `agentos_client` receives **only the access token**, through a narrow per-call provider, holds it only while constructing and sending the request, and never persists it. No token of any kind in view models, templates, logs, or exception payloads (leak tests pin this).

### 3.3 Sessions (ruled contract, verbatim-binding)

- `SessionStore` protocol with atomic security semantics: create (high-entropy opaque ID); consume one-time OIDC state/nonce/PKCE material; atomic rotate old-ID → new-ID; get + touch idle expiry without extending absolute expiry; immediate delete/revoke; compare-and-swap token updates; per-session refresh lock (concurrent requests cannot reuse a rotated refresh token); versioned serialization with unknown versions refused; revoke-all-for-subject/session-family.
- **Profiles:** `MemorySessionStore` = dev/test only. `RedisSessionStore` **required** for the M8.5-C live proof, stage, and production — startup fails closed if absent; never a fallback from Redis to memory after startup or an outage (Redis unavailable ⇒ re-authentication/503).
- **Redis posture:** TLS, BFF-only ACLs, short TTLs, bank-approved encryption at rest where mandated; persistence disabled for the proof (losing the cache logs users out rather than weakening authorization). Lookup key = HMAC-SHA-256 of the cookie identifier (keyed with a BFF-held secret).
- **Cookie:** `__Host-` prefixed, `Secure`, `HttpOnly`, `Path=/`, no `Domain`, `SameSite=Lax` (Strict would drop the cookie on the top-level IdP→BFF callback redirect; Lax admits it while blocking cross-site subrequests). Contains only the opaque random session ID. Rotate on login **and privilege change**; logout revokes the session family and clears the cookie (no rotation-into-new).
- **CSRF:** synchronizer tokens, server-validated, on every unsafe BFF/htmx request; OIDC state/nonce handled separately by the OIDC flow.
- One **backend-conformance suite** runs against Memory and real Redis (marker-selected, required in CI).
- No tokens, session IDs, authorization codes, or PKCE verifiers in logs.

**The ten session proof cases (durable enumeration — Bar A references THIS table):**

| # | Case |
|---|---|
| S1 | Login rotates the pre-authentication session; the old cookie is unusable. |
| S2 | Two BFF replicas share one session successfully. |
| S3 | Logout invalidates the session on both replicas. |
| S4 | Idle and absolute TTLs behave independently. |
| S5 | OIDC state/nonce can be consumed only once. |
| S6 | Concurrent refresh has exactly one winner and preserves the rotated token. |
| S7 | Redis outage fails closed (re-authentication/503; never memory continuation). |
| S8 | Cookie inspection proves it contains no OAuth material. |
| S9 | Restarting either BFF replica does not lose the session. |
| S10 | Unknown session-record schema versions refuse. |

### 3.4 The AgentOS client (11 methods, closed)

Conversation commands: `create_conversation`, `post_turn`, `close_conversation`. Conversation reads: `list_conversations`, `read_transcript`, `read_turn_chain`. Approvals: `list_queue`, `get_approval`, `grant`, `grant_second`, `deny`. `GET conversation detail` is deliberately omitted — `TranscriptResponse.conversation` carries the summary, and chat reloads from the transcript because the BFF stores no history. No generic `request()`, no URL pass-through, no arbitrary forwarding proxy.

**`Link` discipline:** the client accepts exactly one well-formed relative `rel="next"` link, validates the fixed path/query shape, extracts only the opaque cursor, and reconstructs the allow-listed request itself; absolute, off-origin, duplicate, or conflicting links are rejected. The client never follows a URL.

Every call attaches the user's AgentOS-audience access token; TLS with the deployment CA, hostname verification, bounded timeouts, no `verify=False`; **`follow_redirects=False`** — any 3xx is a typed upstream failure, and `Authorization` is never forwarded to a redirected location.

### 3.5 Rendering and headers

Chat/model/user text renders as **plaintext** (escaped, `white-space: pre-wrap`) in v1 — no Markdown pipeline, no sanitizer dependency; `|safe` is banned with zero exceptions (lint pin) and hostile-output XSS tests must render inert. Strict CSP (self-only, no CDN, no inline scripts, no `eval`); `Cache-Control: no-store` on authenticated pages and fragments.

### 3.6 Screens

- **Chat:** conversation list sidebar (`list_conversations`), create, post-turn (form POST + fragment append), close; reload renders from `read_transcript`; kernel refusals render as governed answers.
- **Approvals (approver-only):** queue via `list_queue` + `Link` pagination; detail; grant / grant-second / deny. A non-observer receives the kernel's 403 **rendered as a refusal view** — never a hidden-empty state.
- **Evidence:** conversation list → transcript → per-turn chain join; digests and identifiers rendered read-only.

The harness renders scope names returned by AgentOS; it never derives them (lock).

## 4. Identity topology (ruled; recorded here for the plan)

- **Keycloak** is the reference proof IdP — an **exact pinned version (26.2 is the floor for the header-type setting) + immutable image digest**, both recorded in the proof manifests, with the explicit realm setting issuing access tokens whose **header `typ` is `at+jwt`** (this pins the RFC 9068 header type — NOT automatically the entire RFC 9068 claim profile; never rely on defaults). Two OIDC entities: `cognic-harness` (confidential client, Authorization Code + PKCE S256) and `cognic-agentos` (resource-server audience; never performs browser login). The ID token serves only the BFF's login/session processing; **only the access token crosses BFF→AgentOS**.
- **Reference binder** (`infra/proof-m85c/overlay_reference/`, injected via `create_app(actor_binder=…)`; not `KernelDefaultActorBinder`, not a proof-header binder, not shipped in the kernel package): validates exact issuer + discovery metadata; JWKS signature with an explicit algorithm allow-list; access-token header `typ == at+jwt`; **`aud` normalized (string-or-array) and required to equal EXACTLY the set `{cognic-agentos}`**; the authorized-party claim validated against **the exact claim contract the pinned Keycloak configuration emits** (established at implementation time from the pinned realm export, then pinned in tests — not assumed from folklore); `exp`/`nbf`/`iat` with bounded clock skew; nonempty stable `sub`; closed-shape tenant claim; closed/allow-listed portal RBAC scope claims; JWKS rotation with unknown-`kid` → refresh once (single-flight) then fail closed — never refresh on an ordinary bad signature. **Structural ID-token rejection rests on the two mandatory checks — `typ` and audience** (an ID token's `aud` is the harness client and its header `typ` is not `at+jwt`; it MAY carry the same client identifier in `azp`, so `azp` is NOT claimed as a rejector); the substitution test uses the real ID token from the same login flow.
- **Human identity derivation (`Actor.actor_type`):** approvals independently require `actor_type == "human"`, so the binder must establish it. The Keycloak **proof grant profile is locked**: the proof realm permits Authorization Code and refresh-token grants for `cognic-harness`; refresh may mint tokens only within an existing human-authenticated session. Non-user initial grants, including client credentials and Direct Access Grants, are disabled or unauthorized. That posture is **pinned from the realm export**. A token accepted under that profile maps to `actor_type="human"`; **caller-supplied actor-type claims never decide it**. Bar B proves the negative space: client-credentials and direct-access-grant attempts against the client fail, and the approvers bind as human.
- **I/O model:** `ActorBinder.bind()` is synchronous and performs **local verification only**; discovery + JWKS live in a lifecycle-owned cache built at startup and refreshed outside the request path. Unknown `kid` fails the current request closed and triggers a single-flight background refresh for later retries. No transparent same-request refresh.
- **Status mapping:** the binder raises `ActorBinderUnauthenticated` (never `HTTPException`); the kernel's existing `403 actor_unauthenticated` mapping is preserved, so RBAC denial evidence flows unchanged. Internal refusal reasons are value-free-logged.
- **Scope semantics:** the token binds **portal RBAC scopes only**; database data-scope entitlements remain in `EntitlementStore`, rechecked at dispatch. IdP groups are never translated into database-object authority inside the BFF.
- **No fallback:** no actor headers, no shared-secret user impersonation, no "accept unverified claims in proof mode." The `X-Proof-Role` binder is absent from the M8.5-C proof entirely.
- HP-2 remains open per real bank (issuer, claim mapping, assurance level, accepted FAPI profile). The reference binder proves the contract and supplies the adaptation example; it does not claim a bank overlay has shipped.

## 5. T3 — the live proof (`infra/proof-m85c/`)

### 5.1 Topology

The proven M8.5 conversational stack (kernel proof app, oracle pack + XE + AS, LiteLLM → cloud tier, Postgres) **plus**: Keycloak (per-run realm import; generated users/credentials — `analyst.amir` requester; `analyst.sara` same tenant with the SAME MCP invocation authority as amir but a different subject — the identity that isolates the originator check from scope/tenant effects; `approver.dana` + `approver.erin` distinct four-eyes humans; `analyst.zara` foreign tenant; nothing committed), Redis (TLS, BFF-only ACL, persistence off), **two** harness BFF replicas behind one Service, and the `cognic-tool-approval-probe` MCP service. The kernel proof app injects the reference binder and mounts the approvals router via `create_app(approval_store=…, approval_engine=…)`. The harness ships from its repo as a **cosign-signed, digest-pinned image**; the runner verifies the signature before load. Playwright drives a real browser.

**TLS matrix (the HUMAN/SESSION-token boundary — named narrowly on purpose):** browser→BFF HTTPS (required for `__Host-`); BFF→AgentOS HTTPS with the fixed proof CA, hostname verification, bounded timeouts, no `verify=False`; BFF→Keycloak, **proof-driver→Keycloak, proof-driver→AgentOS, and binder-JWKS-cache→Keycloak** all HTTPS under the same CA rules; BFF→Redis TLS. **Disclosed exception (service-token boundary):** kernel→MCP-pack transport inside the cluster remains plaintext HTTP in this proof, as in every prior M-series proof, and it carries the per-tenant MCP OAuth SERVICE token — this is disclosed here and in the proof README as a named exception, never folded into the human-identity claim; securing in-cluster MCP transport is a future slice.

**Proof driver token acquisition:** the runner's direct-MCP calls happen outside the BFF via Authorization Code + PKCE against the **same `cognic-harness` client** using a proof-only loopback redirect URI (preserving `azp=cognic-harness`). No password/direct-access grants, no hidden BFF MCP endpoint, no Redis scraping, no tokens to browser JavaScript. Driver tokens live only in the private per-run directory and are removed at cleanup. The same token pair supplies the real-ID-token substitution test.

**Four-eyes TTL:** the proof pins the approval TTL above the worst-case browser-bar duration (the 60-second default is insufficient for Playwright-paced grant + grant-second).

### 5.2 Bars

- **Bar A — session/BFF custody (replicas exercised, not merely deployed):** the ten session cases S1–S10 (the §3.3 table), plus: cross-replica callback/session continuity; concurrent refresh with exactly one winner **across replicas**; session survives killing one pod; Redis outage fails closed with no memory fallback; cookie-content inspection (no OAuth material); CSRF refusal; hostile-output XSS inert. Value-free proof logs record which pod served each step.
- **Bar B — identity:** the ten ruled identity requirements verbatim — real browser login; no tokens in the cookie; only the AgentOS-audience access token crosses; the expected `Actor` binds (**including `actor_type="human"` — the approvers bind as human**); wrong-audience / expired / malformed / unknown-key / **real-ID-token substitution** all refuse; **client-credentials and direct-access-grant attempts against `cognic-harness` fail** (the locked grant profile's negative space); manipulated UI still refused by AgentOS RBAC; requester/approver/foreign-tenant as distinct Keycloak identities; two replicas share the Redis session; logout/revocation effective across replicas; structural scan proves no actor-header path in the production harness or the proof flow.
- **Bar C — chat:** a governed multi-turn conversation through the UI; one entitlement-revoked turn whose refusal renders in the UI **and** correlates to the chain row by exact ID, digest, sequence, and refusal fields.
- **Bar D — approvals (the ledger proves refusal, not just success):**
  1. amir's initial probe call → `202 tool_approval_pending`, **ledger 0**; the inbox renders it.
  2. **Denial leg:** dana denies → amir's exact-shape recall returns `tool_approval_denied`, **ledger stays 0**.
  3. Fresh request → **first grant only** (dana) → amir's exact-shape recall **remains pending**, **ledger stays 0**.
  4. **Four-eyes enforcement:** dana attempts `grant-second` on her own grant and is **refused**; erin (distinct human) succeeds.
  5. amir's exact-shape re-call now executes — **ledger exactly 1**.
  6. **Originator isolation:** `analyst.sara` (same tenant, same MCP invocation authority, different subject) replays the granted request-id with the exact shape → `tool_approval_originator_mismatch`, **ledger stays 1** — the refusal cannot be explained by scope or tenant invisibility.
  7. 51 requests minted through the **real MCP path** (each leaving the ledger unchanged) walk via `Link` pagination: exact ID-set equality across pages, no duplicates or omissions, correct ordering, a `Link` on page one and none on the last.
  8. A non-observer gets a rendered 403 (never hidden-empty); the under-scoped manipulated-UI POST (valid session + CSRF, hidden button bypassed) returns the kernel's governed 403; the foreign-tenant observer sees an empty queue of their own.
- **Bar E — evidence:** transcript + chain screens rendered; Playwright extracts the rendered IDs/digests; **the runner's PSQL helper** performs every DB comparison. The BFF image retains zero DB driver, DSN, or database connectivity.
- **Bar F — structural:** exactly three screens; no DB client; no operator APIs; no pack builder; no proof-header code in the production bundle; no `|safe`; CSP headers present; vendored htmx checksum verified.

## 6. The high-risk pack — `cognic-tool-approval-probe@v0.1.0`

Separately released and cosign-signed like every proof pack. One MCP tool, `probe_write`: **business-side-effect-free** but appends a per-call nonce to a **proof-local invocation ledger** readable only by the runner (`kubectl exec`) — the independent observer that makes "zero execution" provable. Manifest `risk_tier = high_risk_custom` → the ADR-014 **four-eyes** flow (`tools.rego` maps four-eyes to `payment_action` / `regulator_communication` / `cross_tenant` / `high_risk_custom`; `customer_data_*` are single-approval). Approver scope: `tool.approve.high_risk_custom`. The single-approval UI state machine is covered by the strict-fake/unit suite, not a second live tier. The pack is never presented as chat-originated and never a requirement of the read-only analytical agent (lock sentence in the proof README).

## 7. Harness CI

- Unit + the SessionStore conformance suite over Memory and **real Redis** (marker-selected, required).
- `agentos_client` contract tests against recorded kernel responses (respx).
- Playwright e2e against BFF + Redis + Keycloak with a **strict kernel fake**: pinned to an AgentOS OpenAPI/contract digest, allow-listed routes only, exact status/body/header vocabulary, unexpected calls refused. The fake is harness-PR-CI-only and **never milestone evidence** — the real-kernel kind proof is the milestone/release authority.
- Coverage floor 95/90 on `auth/`, `agentos_client/`, **and the `web/` security middleware** (CSRF, cookie, CSP/no-store, forwarding).
- ruff / mypy-strict / format gates; the production-bundle structural scan job (three screens, no proof code, no `|safe`, htmx checksum).

## 8. Honesty boundaries (mandatory in the proof README)

1. **Grants are deliberately not single-use** (ADR-014): the same requester may replay the same granted shape until expiry. "Exact re-call" means actor/tenant/tool/args-bound, not exactly-once execution. **Single-use `consume`/transaction idempotency is mandatory before any real high-risk business action or pilot** — recorded as a named prerequisite, not implemented here.
2. The kernel fake never counts as milestone evidence.
3. HP-2 remains open per bank; the reference binder is a worked example, not a shipped overlay.
4. HP-5 is untouched: chat is auto-tier; the approvals screen proves the MCP surface only.
5. Any plaintext proof-internal MCP transport is disclosed explicitly.
6. The M8.5-C baseline is RFC 9700; **full FAPI 2.0 is the bank-deployment target** (§0.4 profile ladder) — nothing here is called FAPI conformant.
7. **NOT PILOT-READY.** M8.5-C proves the harness boundary and the approvals surface only. Still outstanding before any pilot: HP-5 (conversational approval resume), erasure, content-safety/escalation hooks, data-access brokerage (M8.5-D/E), full FAPI 2.0 or a formally accepted bank-equivalent profile (M8.5-F/M15–M16), and single-use grant consumption for real high-risk actions (item 1).

## 9. Documentation deliverables

The dated **ADR-014 amendment** (queue = fixed actionable projection over `pending | awaiting_second`; `?status=` retired; actor-bound replay + the new refusal values; the raised proof TTL noted as configuration, not a default change) **plus the consumer-side amendments §2.2 requires: ADR-004** (the sandbox reason + the wake-passthrough 5→6 expansion), **ADR-019** (the memory reason), and **ADR-022** (the scheduler reason) — each dated, each owning its wire-visible value. Checklist M8.5-C stays unchecked until the proof passes. VALIDATION-RESULTS gains the M8.5-C section on pass, with the run ledger and these honesty boundaries.

## 10. Standards references (primary sources only — the §0.4 discipline)

FAPI 2.0 Security Profile (final); RFC 9700; the IETF Browser-Based Applications document (**draft**); RFC 8693; RFC 9068; RFC 9396; NIST SP 800-207A; SPIFFE Workload API / X.509-SVID; Vault Oracle database-secrets documentation; Oracle proxy-authentication + VPD documentation; Keycloak 26.2 release notes (the `at+jwt` header-type setting). Do-not-claim list per §0.4 (SCIM, Vault-as-standard, Transaction-Tokens-as-RFC, query-context-as-RFC-9068).
