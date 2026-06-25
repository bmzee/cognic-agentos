# PR 2a — MCP OAuth/discovery-leg SSRF hardening (threat model + design)

> **Status: DESIGN — for review before implementation.** Sub-project **2a** of PR 2 (the ADR-002
> trust-register-then-defer follow-up). PR 2a is **pure security hardening** and lands **first**;
> PR 2b (the per-tenant internal-host allow-list + the operator `server_url` override + Proof 1b-2)
> builds the controlled-exception path on top and **never merges without 2a**.

## 1. Context + scope

PR 1 (merged @ `e9c6446`) made registration trust-only, moved the OAuth/PRM discovery probe to
invoke, and added the `discovery_status` axis (`unprobed` / `auth_ready` / `refused` /
`unreachable`). At invoke, `MCPHost.list_tools` / `call_tool` run `MCPAuthzClient.acquire_token`,
which performs PRM discovery → AS metadata discovery → token acquisition.

The prod SSRF guard `protocol/mcp_authz.py::_refuse_non_public_discovery_url` (a real
DNS-resolve-and-check, strict-profile only) is wired at **two** sites and covers the three
**discovery** fetches — but **two OAuth fetches inside `_request_token` are unguarded**, and one of
them (`token_endpoint`) carries the OAuth **client credentials**. A guard that protects the pack
`server_url` while leaving the credential-bearing token POST steerable by AS metadata is a
misleading boundary — "safe in docs, bites in prod."

**PR 2a invariant:** *no credential-bearing OAuth fetch may go to a non-public / internal URL unless
a later allow-list (PR 2b) explicitly permits it.* PR 2a establishes the default-deny across **all
five legs**; PR 2b adds the controlled exception.

## 2. Threat model

### Assets
- **The OAuth client credentials** (`client_secret` in the body, or HTTP Basic `Authorization`)
  sent in the `token_endpoint` POST.
- **Internal network reachability** — the cluster's private services (link-local `169.254.169.254`
  cloud metadata, RFC1918 services, loopback) that the SSRF guard exists to keep unreachable.

### The SSRF surface — five legs (ground truth, `mcp_authz.py`)
| # | Leg | Fetch | URL source | Guarded today |
|---|---|---|---|---|
| 1 | `server_url` | `GET` probe (`:439`) | pack manifest `[tool.cognic.mcp].server_url` | **Yes** (`:433`) |
| 2 | `prm_metadata` | `GET` PRM (`_fetch_prm :1050`) | the `resource_metadata="<url>"` param parsed from the 401 `WWW-Authenticate` header — **fully server-controlled** | **Yes** (`:1048`) |
| 3 | `well_known_prm` | `GET` (`:477`, `:483`) | derived from `server_url` netloc | **Yes** (`:1048`) |
| 4 | `as_metadata` | `GET` (`_request_token :1321`) | PRM `authorization_servers` — allow-list-filtered (`:627`) but **not SSRF-checked** | **No** |
| 5 | `token_endpoint` | **`POST` with credentials** (`_request_token :1398`) | the AS discovery JSON document | **No** (and **not** allow-list-gated) |

There is **no JWKS fetch** in this flow — `_validate_token_audience` decodes the JWT without
signature verification, so no `jwks_uri` outbound fetch exists to consider.

### Threats
- **T1 — SSRF to internal services** via the unguarded leg-4 (`as_metadata`) and leg-5
  (`token_endpoint`) fetches. An invoke against a pack whose AS chain resolves to an internal host
  reaches that host from inside the cluster.
- **T2 — Credential exfiltration (the sharp one).** Leg 5 is the worst: a **compromised or malicious
  AS that is in the per-tenant AS allow-list** returns a discovery document with
  `token_endpoint = http://169.254.169.254/...` (or any private/internal URL); the code then POSTs
  the **OAuth client credentials** to that address. Precondition: an allow-listed AS (the `as_issuer`
  is allow-list-gated, but the `token_endpoint` *inside its discovery JSON* is not).

### Mitigation (this PR — PR 2a)
Apply the **same** DNS-resolve-and-check policy (`_refuse_non_public_discovery_url`) to **all five
legs**, **default-deny** — including, critically, validating leg-5's `token_endpoint` **before any
credential material is built** (not merely before the POST) and leg-4's `as_metadata` URL **before**
its GET. A refusal becomes a closed-enum `MCPAuthzError("mcp_discovery_url_refused")` and surfaces as
**`discovery_status = refused`** at every **host-invoked** path that can trigger it (`acquire`, the
retry reacquire, `step_up`); `refresh_token` is **guarded but unrecorded** by deliberate design — it
has no `server_id`/pack key and no `MCPHost` call site (§3.3).

### Residual risks — explicitly NOT fixed by PR 2a
PR 2a's claim is narrow and honest: **"the same prefetch URL/IP classification guard now runs on
every OAuth/discovery leg."** It is **NOT** "complete SSRF prevention." Three residuals remain:

1. **DNS-rebinding TOCTOU.** The guard resolves the host, then `httpx` independently re-resolves at
   connect time — no IP pinning between check and connect. An attacker who flips DNS in that window
   can still reach an internal IP. Closing this requires pinning the resolved IP into the HTTP
   transport (connect-time IP-pinning), which is **out of scope for 2a** and a tracked follow-up.
2. **Unresolvable-host pass-through.** A host that fails `getaddrinfo` is **not** refused (the fetch
   simply fails later at the transport). Unchanged by 2a.
3. **dev-profile skip.** In the `dev` runtime profile the guard does scheme+host only (the DNS/IP
   check is skipped); a literal internal URL passes. **2a preserves this profile behavior** (the
   strict-vs-dev distinction is deliberate, mirroring the rest of the kernel) and tests the **strict
   profile hard**. Tightening dev is a separate decision, not 2a.

## 3. Design

### 3.1 Extend the guard to the two OAuth legs
Call `_refuse_non_public_discovery_url` at the two currently-unguarded `_request_token` sites:
- **leg 4** — validate the `as_metadata` discovery URL **before** `self._http.get(...)` at `:1321`.
- **leg 5** — validate the `token_endpoint` URL **immediately after** confirming it is a non-empty
  string and **before constructing any credential material** — i.e. before `body`, `headers`, or the
  HTTP Basic `Authorization` are built (not merely before `self._http.post(...)` at `:1398`).
  Ordering the guard ahead of credential construction makes the "no serialized secret" claim
  **structurally** true — the client secret is never assembled into a request object for an internal
  URL — rather than dependent on a mock never being awaited.

The guard remains the single DNS-resolve-and-check function; the same `_STRICT_PROFILES` gate and IP
classification (`is_private/is_loopback/is_link_local/is_reserved/is_multicast/is_unspecified`)
apply. No relaxation, no allow-list (that is PR 2b).

### 3.2 Refusal vocabulary — leg traceability + documented semantic widening
- **Reuse** the existing closed-enum reason **`mcp_discovery_url_refused`**, with a **documented
  semantic widening**: it no longer means only "the registration/discovery probe URL was refused" —
  it now means **"an MCP auth-or-discovery URL was refused by the non-public-URL guard,"** covering
  all five legs. This widening is recorded in the module docstring + the `AuthzReason` comment +
  ADR-002 so the rename-free reuse is intentional, not accidental.
- **Add a separate closed-enum `leg` discriminator** to the refusal payload —
  `{server_url, prm_metadata, well_known_prm, as_metadata, token_endpoint}` — identifying *which*
  fetch was refused (for audit + operator triage). **Decided:** the existing `refused_component`
  discriminator (`{not_string, scheme, host, host_address}` — *why* it failed) is **kept as the
  failure-type axis and NOT repurposed** — the two axes are orthogonal (a `token_endpoint` leg can
  fail on `host_address`) and both are useful. Every refusal therefore carries **both** `leg` (which
  fetch) and `refused_component` (why).

### 3.3 `discovery_status` recording — at the `MCPHost` call sites, keyed by `(tenant_id, server_id)`
The `discovery_status` axis is keyed by `(tenant_id, pack_id/server_id)`; recording must therefore
happen **where the `server_id` is known — at the `MCPHost` call sites** (`entry.server_id`), **not**
inside `MCPAuthzClient` (which carries no pack/server identity — only `tenant_id` +
`token.resource_indicator`). **Decided:** the recorder is **not** threaded into `MCPAuthzClient` in
PR 2a — doing so would either couple the auth client back to registry/host identity or risk recording
under the wrong key.

- **`acquire_token`** (incl. the `call_tool` 401-retry reacquire) — already records via PR-1's
  wrapping at the `MCPHost` probe sites (`list_tools`, `call_tool` initial, the retry reacquire). A
  leg-4/leg-5 refusal raised from `_request_token` propagates up and is recorded as `refused` there
  unchanged. ✔
- **`step_up_token`** — `MCPHost` invokes it with `entry.server_id` in scope, so PR 2a records
  `discovery_status` at that **`MCPHost` call site** via the shared
  `discovery_status_for_authz_reason(exc.reason)` mapper (refused/unreachable) for any
  **endpoint/OAuth reachability failure** reached through `step_up_token`'s `_request_token` call
  (SSRF refusal, timeout, transport, AS-discovery / token errors). The one **excluded** reason is
  `mcp_step_up_unauthorised` — an **authorization denial** (the original token is fine, only the
  wider scope was denied), NOT endpoint reachability. (PR-1 did not wrap step-up; PR 2a adds it.)
- **`refresh_token`** — its token-leg fetches **are guarded** (the SSRF refusal fires, and the
  existing fail-closed / decision-history behavior is preserved), **but it does NOT record
  `discovery_status`**: it carries no `server_id`/pack key (only `tenant_id` +
  `token.resource_indicator`), and **`MCPHost` has no `refresh_token` invoke path today** — so there
  is no production call site that holds the key, and inventing one would risk recording under the
  wrong key. A **drift pin** asserts `MCPHost` has no `refresh_token` call path; if a future host
  path adds one, the pin fails and forces the recording decision to be revisited.

**Requirement (revised):** no **host-invoked** reachability path may fail silently — `acquire`, the
retry reacquire, and `step_up` each record `discovery_status` via the mapper (refused/unreachable) on
an endpoint/OAuth reachability failure; `mcp_step_up_unauthorised` is the one excluded reason (an
authorization denial, not reachability). `refresh_token` is **guarded but unrecorded by deliberate
design** (no host call site, no key), pinned by the drift test.

### 3.4 AST-level drift detector (not a text grep)
A test that **parses `mcp_authz.py` with `ast`** and asserts the guarded-fetch invariant: **every**
`self._http.get(...)` / `self._http.post(...)` call node is either (a) preceded within its enclosing
function by a `_refuse_non_public_discovery_url(...)` call, or (b) routed through a **named,
AST-visible exemption construct** — a dedicated wrapper/helper (e.g. `_unguarded_public_fetch(...)`)
or an explicit module-level registration the AST can match **by name** — for a deliberately-public
fetch. The exemption MUST be a **real syntactic node**, never a sentinel comment: comments are
invisible to `ast`, so a comment marker would be silently unenforceable. The test **fails** if a new
`_http` fetch is added without a guard or the named exemption — so the "unguarded fetch" gap class
cannot silently recur. Text-grep is rejected as brittle (string-built URLs, line wrapping, aliasing).

### 3.5 The credential-exfil negative test (the headline assertion)
Under the **strict** profile: a malicious **allow-listed** AS returns a discovery document with
`token_endpoint = http://127.0.0.1/...` (and a variant with an RFC1918 / link-local host). Assert:
1. The guard refuses (`mcp_discovery_url_refused`, `leg=token_endpoint`) **before any credential
   material is constructed** (the §3.1 ordering).
2. **No POST is issued** to the token endpoint (`self._http.post` not awaited).
3. **The OAuth client secret is never even assembled** — because the guard runs before `body` /
   `headers` / Basic-auth are built, no request object carrying the credential exists for that URL.
   This is a **structural** assertion (no credential is constructed), not "the mock was not awaited".
4. The refusal surfaces as `discovery_status = refused` (via the `acquire` / `step_up` host path).

A parallel negative test covers leg 4 (`as_metadata` → internal) → refused before its GET.

### 3.6 Profile behavior — preserved deliberately
Strict (`stage`/`prod`): all five legs refuse internal/private/loopback/link-local. Dev: the guard
skips the DNS/IP check exactly as today (the deliberate distinction). All negative tests run under
the **strict** profile; a dev-profile test pins that 2a did **not** silently start refusing in dev.

## 4. Testing
- **Per-leg coverage:** each of the five legs refuses an internal URL under strict (parametrized).
- **Credential-exfil (§3.5):** the headline negative tests for leg 5 + leg 4 — no POST, no secret.
- **Host-invoked-path recording (§3.3):** `step_up` records `discovery_status` via the mapper for
  reachability reasons (tested: `mcp_discovery_url_refused`→`refused`,
  `mcp_oauth_request_timeout`→`unreachable`) and does NOT record `mcp_step_up_unauthorised` (auth
  denial); `acquire` / the retry-reacquire already record via PR-1. `refresh_token` is **guarded but
  unrecorded** (no host call site / no `server_id` key), pinned by a **drift test that `MCPHost` has
  no `refresh_token` invoke path** today.
- **AST drift detector (§3.4):** a synthetic added-unguarded-`_http`-fetch fails it; the real tree
  passes; an exempted fetch passes.
- **Profile (§3.6):** strict refuses; dev preserves prior behavior.
- **Semantic-widening doc:** a doc/string assertion that the widened meaning is recorded.
- **Critical controls:** `protocol/mcp_authz.py` is on the durable 95/90 gate; the new branches +
  the `leg` discriminator must hold the floor. No new CC module (the change is inside an on-gate file).

## 5. Scope boundary (what 2a is NOT)
- **PR 2a (this):** guard all five legs, default-deny, leg-traceable refusals, all-invoke-path
  recording, AST drift detector, credential-exfil negative tests, profile preserved. **No allow-list,
  no operator override, no Proof 1b-2.**
- **PR 2b (next):** the per-tenant, default-deny internal-host allow-list (the controlled exception,
  applied uniformly to all five legs, mirroring the Vault-template `_load_as_allowlist` pattern), the
  operator `server_url` override (per `(tenant, pack)`, never mutating the signed manifest), and the
  deployed Proof 1b-2 (an in-cluster MCP Service reaching `discovery_status = auth_ready` + a real
  `list_tools` / `call_tool`). **2b's allow-list never merges without 2a.**
- **Honesty boundary:** PR 2a claims "the same prefetch URL/IP classification guard on every
  OAuth/discovery leg." It does **not** claim "complete SSRF prevention" — the DNS-rebinding TOCTOU,
  the unresolvable-host pass-through, and the dev-profile skip remain (§2 residuals).
