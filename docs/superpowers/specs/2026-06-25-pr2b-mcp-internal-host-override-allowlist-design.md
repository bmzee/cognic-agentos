# PR-2b — MCP per-(tenant,pack) `server_url` override + per-tenant internal-host allow-list — Threat Model & Design DRAFT

> **Status: DRAFT for review.** Deliverable is this threat model + the open decisions at the end. **No implementation** until Codex reviews and approves the threat model. Follow-up to PR-1 (trust-register-then-defer, #99 @ e9c6446) and PR-2a (five-leg OAuth/discovery SSRF hardening, #100 @ 78eb477).
>
> **Narrowed (rounds 2–3) for a first, provable PR-2b:** exact-IP/ClusterIP allow-list only (no FQDN/CIDR); **three** MCP-resource carve-out legs only (`server_url`, `prm_metadata`, `well_known_prm`); public OAuth legs only (`as_metadata`, `token_endpoint`); HTTP-only internal MCP Service; `token_endpoint` hard-public-only **plus mandatory** issuer-origin binding; runtime carve-out provenance as a dedicated audit event; tenant-Service IP-ownership recorded as an explicit residual.

---

## 1. Goal & scope

Let an operator point a specific `(tenant, pack)` at a real **in-cluster MCP Service** — a private host the PR-2a SSRF guard refuses today — **without weakening that guard**. Three pieces:

1. **Operator `server_url` override**, per `(tenant, pack)`, **runtime config only** — the signed manifest's `server_url` is **never mutated**. An internal-targeting override must be an **`http://` IP literal (the ClusterIP)** (§6, §7).
2. **Per-tenant, default-deny internal-host allow-list of exact IPs (ClusterIPs)** — a narrow, audited carve-out that the *same* `_refuse_non_public_discovery_url` guard consults on the **three MCP-resource legs** (`server_url`, `prm_metadata`, `well_known_prm`), matching on the **resolved/connected IP**. The two OAuth legs (`as_metadata`, `token_endpoint`) are **public-only** — §7a.
3. **Deployed Proof 1b-2** — an in-cluster MCP Service reaches `discovery_status=auth_ready`, then a real `list_tools` / `call_tool`, with the override + allow-list in place and a **public** AS.

### Hard guardrails (carried verbatim from the user, non-negotiable)
- PR-2a's five-leg SSRF guard remains in force.
- The allow-list is a **narrow audited carve-out, not a bypass**.
- **No wildcards, no `*.svc.cluster.local`, no blanket RFC1918 / private-range entries** — and **no FQDN and no CIDR entries at all**: exact IPs only.
- The SSRF guard still covers all five legs (PR-2a, unchanged). The internal-host carve-out applies to **three** MCP-resource legs (`server_url`, `prm_metadata`, `well_known_prm`). The two OAuth legs are **public-only** (PR-2b is public-AS only): `as_metadata` is public + convention-derived; **`token_endpoint`** is hard-public-only and carries a **mandatory** issuer-origin rule — §7a.
- Internal carve-out legs are **HTTP-only** in PR-2b — an internal `https://<ClusterIP>` is refused (§7, §10).
- `token_endpoint` gets extra scrutiny — operator OAuth credentials are POSTed there (§7a).
- The signed manifest is never mutated; the override is runtime config per `(tenant, pack)`.

### Non-goals (explicitly out of scope for PR-2b)
- **Internal-hostname (FQDN) or CIDR allow-list entries** — exact IPs only. (FQDN/CIDR would reintroduce the DNS-rebinding + cross-tenant-IP surface §7/§8 close.)
- **An in-cluster authorization server / a private `token_endpoint`** — PR-2b is **public-AS only** (§7a). An internal token endpoint would require a separately-modeled, audited exception.
- **Internal HTTPS-to-IP** for the carve-out legs — internal legs are HTTP-only; internal TLS-to-an-IP (SNI/cert handling) is a separately-modeled decision.
- **Programmatic tenant-Service IP-ownership validation** — PR-2b records operator mis-allow-listing as an audited residual (AS-9, OD-13), it does not prove IP ownership.
- Changes to the **AS allow-list mechanism**, the **OAuth credential storage**, or the **manifest signing/trust chain**. *(Note: PR-2b **does** add issuer-origin validation on the `token_endpoint` *destination* per §7a(ii) — that is the only OAuth-path change, and it is in scope.)*
- A UI; a non-operator (self-service) override path; allow-list entry expiry/auto-review (OD-9).

---

## 2. Code-grounded baseline (what exists today)

| Surface | Reality (file:line) | Consequence for PR-2b |
|---|---|---|
| The guard | `_refuse_non_public_discovery_url(url, *, leg)` `mcp_authz.py:997-1060`; strict-profile gate `:1034` (`_STRICT_PROFILES={"stage","prod"}` `config.py:68`); refusal `mcp_discovery_url_refused` + `refused_component` + `leg` | The single enforcement point; **no per-tenant exception hook today** — PR-2b adds one |
| Five legs call it | `server_url` `:459`; `prm_metadata`+`well_known_prm` `:1076`; `as_metadata` `:1352`; `token_endpoint` `:1394` (pre-credential) | Carve-out threaded into the **three resource** call sites (`:459`, `:1076`); the two OAuth legs (`as_metadata` `:1352`, `token_endpoint` `:1394`) are public-only (§7a) but keep their guard |
| `server_url` source | signed manifest `[tool.cognic.mcp].server_url` → `harness/mcp_host.py:99` → `MCPServerEntry.server_url` `mcp_host.py:270`; `_map_registered_packs_to_servers` reads **only the manifest** (`harness/mcp_host.py:99-171`) | No override path exists; override applied at server_url *resolution* time, manifest untouched |
| `as_metadata` is convention-derived | `f"{as_issuer}/.well-known/oauth-authorization-server"` `mcp_authz.py:1350`; `as_issuer` ∈ per-tenant AS allow-list | Its host **is** the allow-listed public issuer's host — public + not attacker-supplied, so it needs **no** carve-out and **no** origin-binding (only `token_endpoint` does) |
| AS issuer selection | PRM-advertised `authorization_servers` ∩ per-tenant Vault AS allow-list; `candidate_as[0]` `mcp_authz.py:653-663`; loader `_load_as_allowlist` `:1145-1223` | §7a(ii) binds the `token_endpoint` origin to **this selected issuer's** origin |
| AS allow-list (storage precedent) | Vault, per-tenant, `secret/cognic/{tenant}/mcp-as-allowlist` `config.py:1004`; `{"servers":[...]}`→`frozenset[str]`; fail-closed | A *membership/storage* precedent for the internal-IP allow-list |
| Config-overlay (governance precedent) | per-`(tenant, field_key)`, **numeric tighten-only**, closed registry `config_overlay/registry.py:41-107`; `RequireHumanActor` + `config.tenant_overlay.write` scope `routes.py:75-175`; decision-history audited `storage.py:184` | Closest governance template; does **not** fit a string value — needs a new store |
| Human-only + scope | `RequireHumanActor` `human_actor.py:58-105` on the pack allow-list `operator_routes.py:174,183`; scope Literal `scopes.py:401-414`; mutually-exclusive log `operator_routes.py:214-226` | PR-2b write surfaces are **Human-only decisions** per AGENTS.md |
| Isolation models | (a) `RequireTenantOwnership` 404-not-403 `tenant_isolation.py:205-220`; (b) operator-for-a-tenant, **scope is the boundary** `config_overlay/routes.py:1-7` | Operator surfaces use (b); the read surface keeps cross-tenant invisibility |
| Audit primitive | `append_with_precondition` atomic chain row + state row `decision_history.py:409-480`; chain-payload-is-evidence-snapshot; constant-derived ISO tags `lifecycle.py:327-339` | Every override/allow-list change emits a hash-chained, human-attributed, ISO-tagged row |
| Deploy reality | Helm `runtimeProfile` default `prod` `values.yaml:11` → strict guard; pack registered at boot; `list_tools` records `auth_ready` after `acquire_token` `mcp_host.py:886-889` then opens the SDK session against `entry.server_url` `:889` | Proof 1b-2 = `http://`-IP override → in-cluster ClusterIP + that IP allow-listed + public AS; the strict guard must then pass |

---

## 3. Assets (what we protect)

- **A1 — The kernel's outbound-request capability.** It can reach the pod network: cloud metadata (`169.254.169.254`), the cluster API, **other tenants' Services (private ClusterIPs)**, databases, Vault. A cross-tenant ClusterIP is *private but not reserved*, so a "not-metadata" floor alone does **not** stop it (§7).
- **A2 — The operator OAuth client secret.** Vault-stored, POSTed to `token_endpoint`. Exfiltration to an attacker-chosen host — internal **or public** — is a credential breach; §7a is its defense.
- **A3 — Tenant isolation.** Tenant A's override/allow-list MUST NOT influence tenant B's discovery, nor leak B's existence/config to A. (Bounded — see AS-9 ownership residual.)
- **A4 — Audit/evidence integrity.** An examiner must read, from the hash chain alone, *which* IP was permitted for *which* `(tenant, pack)`, *who* (a human) authorized it, and *when*.
- **A5 — The signed-manifest trust chain.** The override is runtime config; the manifest is never mutated.

---

## 4. Trust boundaries

1. **Pack ↔ kernel.** Trust-admitted but **runtime-untrusted**: it controls the manifest `server_url` (today), the live `WWW-Authenticate` header (→ `prm_metadata`), and the documents it serves.
2. **AS ↔ kernel.** Allow-listed per tenant but **may be compromised**: it controls the AS discovery document, hence `token_endpoint` (→ A2), which may point at an arbitrary internal **or public** host (§7a).
3. **Operator ↔ kernel.** A human sets the override + allow-list (Human-only). Trusted-but-fallible — the exact-IP grammar guards against *broad* error (AS-4); *wrong-but-exact* IP entries are a residual (AS-9).
4. **Tenant ↔ tenant.** Hard isolation; per-tenant keys; the guard loads the invoking tenant's allow-list.
5. **DNS resolver ↔ kernel.** Resolution is time-of-check vs the fetch's time-of-use — a rebinding gap (§8), bounded by exact-IP matching + pinning + IP-based overrides.
6. **The strict-profile gate.** The IP check runs only in `{stage,prod}`; `dev` skips it (PR-2a residual, unchanged; the allow-list is inert in `dev`).

---

## 5. Attacker stories

- **AS-1 — Cloud-metadata SSRF via `server_url`.** Override/pack sets `…169.254.169.254…`. **Stopped by:** default-deny exact-IP allow-list; `169.254.169.254` is hard-blocked even as an explicit entry (§7); the guard refuses (link-local). Override-set is necessary-not-sufficient (AS-7).
- **AS-2 — PRM redirect via `WWW-Authenticate`.** Malicious pack returns `resource_metadata="http://<internal>/…"`. **Stopped by:** the carve-out is consulted on `prm_metadata`; the resolved IP must be an allow-listed exact IP, else refused.
- **AS-3 — Credential exfil via `token_endpoint` (extra scrutiny).** A compromised-but-allow-listed AS returns a crafted `token_endpoint`.
  - **AS-3a — internal target.** **Stopped by:** the shared guard refuses non-public `token_endpoint` **before** credential assembly (PR-2a), and §7a(i) means the allow-list **never** carves out `token_endpoint`.
  - **AS-3b — public attacker target** (`http://evil.example.com/…`). **NOT stopped by the SSRF guard** (a public host passes). **Stopped by §7a(ii) mandatory issuer-origin binding** — the `token_endpoint` origin must equal the selected AS issuer's origin, else refused, no secret sent. A known credential-exfil, so its defense is **mandatory** (OD-11 is only *sequencing*).
- **AS-4 — Operator misconfiguration (broad).** Operator tries `10.0.0.0/8` / `*.svc.cluster.local` / an FQDN. **Stopped by:** the exact-IP grammar rejects every non-exact-IP entry at set-time (closed-enum refusal).
- **AS-5 — Cross-tenant ClusterIP via rebinding / PRM redirect (attacker-driven).** A `prm_metadata` hostname resolves to an allow-listed IP at check, then a cross-tenant ClusterIP at fetch; or a redirect targets another tenant's Service. A cross-tenant ClusterIP is private-but-not-reserved. **Stopped by:** matching on the **resolved IP against the exact-IP allow-list** (a cross-tenant IP the operator did **not** allow-list is not an entry → refused) **plus resolve-and-pin** (§7, §8). This closes the *attacker-driven* case — the attacker cannot make the operator allow-list a cross-tenant IP. The *operator* allow-listing a cross-tenant IP is a separate residual (AS-9). An FQDN+floor model would not even close the attacker-driven case.
- **AS-6 — Cross-tenant influence/leak.** **Stopped by:** per-tenant keys; the guard loads the invoking tenant's allow-list; the `/system/plugins` read surface keeps PR-1 cross-tenant-invisibility (`?tenant_id=` is observation-only).
- **AS-7 — Override-without-allow-list.** Operator overrides to an internal IP but doesn't allow-list it. **Result:** still refused (default-deny). Two independent human-only actions to reach an internal host — a deliberate two-key design.
- **AS-8 — Allow-list outlives its purpose.** A stale IP entry is later reused by an attacker. **Mitigated by:** audit visibility (chain row with actor + timestamp) + OD-9 (expiry, deferred). Flagged, not auto-closed.
- **AS-9 — Operator allow-lists a cross-tenant / wrong IP (ownership residual).** The exact-IP grammar bounds the *range* (no broad CIDRs) but does **not** prove the IP is an Endpoint of the intended `(tenant, pack)`'s **own** Service — an operator could mistakenly or maliciously allow-list another tenant's ClusterIP, granting cross-tenant reach. **Bounded (not prevented) by:** the Human-only audited write surface (the chain row attributes the entry to a human + timestamp — detectable + attributable) + the operator-for-a-tenant scope model. **Not programmatically prevented in PR-2b** — K8s-API tenant-Service ownership validation is **OD-13**. Recorded as an explicit audited residual; the cross-tenant-protection claim in §7/§13 is scoped to the attacker-driven case (AS-5), not operator error/malice.

---

## 6. The override design (per-`(tenant,pack)` `server_url`)

- **A new store** (config-overlay does not fit — §2). Per-`(tenant, pack)` row: `tenant_id`, `pack_id` (OD-6), `server_url_override` (string), `set_by_actor`, `set_at`, `last_request_id`. Decision-history-audited via `append_with_precondition`, mirroring `config_overlay/storage.py`.
- **Internal target ⇒ `http://` IP literal.** A `server_url_override` whose host is non-public must be an **IP literal (the ClusterIP)** with scheme **`http`**; a hostname override targeting an internal host, or an internal `https://<ClusterIP>`, is **rejected at set-time** (closed-enum). This removes the `server_url`/`well_known_prm`-leg DNS entirely (the SDK connects to the IP — no rebinding) and the internal-TLS/SNI surface (a non-goal). **PR-2b-1 scope (narrowed):** the override validator accepts **only** the `http://`-IP-literal form. A public-host override (a hostname over HTTPS, which would repoint a pack to a different *public* server and never touches the allow-list) is a **separate capability deferred to a follow-up**, out of PR-2b-1's internal-reachability scope — every non-`http://`-IP-literal override is rejected at set-time.
- **Resolution point:** at server_url *use*, not registration. The `MCPServerEntry` read path consults the override store for `(tenant, pack)`; if present the resolved `server_url` is the override, else the manifest value. **The manifest object is never mutated** (A5).
- **Override lifecycle / observation (OD-12).** The boot-built `MCPServerEntry` set is constructed once at lifespan start; PR-2b resolves the override at **server_url use** (each `list_tools`/`call_tool`, or a short-TTL per-(tenant,pack) cache) so a post-boot change is observed **without a restart** — required for Proof 1b-2.
- **The override is subject to the same guard + allow-list** as any other `server_url` (AS-7).
- **Write surface:** Human-only (`RequireHumanActor`), new RBAC scope pair (`mcp.override.write` / `.read`), operator-for-a-tenant isolation (no `RequireTenantOwnership`), audited.

---

## 7. The allow-list grammar (per-tenant, default-deny, **exact IPs only**)

**Entry type permitted (closed grammar) — exactly one:**
- An **exact IP literal** (v4 or v6) — intended to be an in-cluster **ClusterIP**.

**Rejected at set-time (closed-enum refusals, enforced *before* storage):**
- Any **hostname / FQDN** (incl. `*.svc.cluster.local`) — no DNS-trust entries in PR-2b.
- Any **CIDR / range / wildcard / glob**.
- Blanket RFC1918 as a class (only specific exact IPs, never a range).
- **Cloud-metadata / link-local / reserved / multicast / unspecified** addresses (`169.254.169.254`, `fd00:ec2::254`, `0.0.0.0`, …) — **never** allow-listable even as an exact entry (AS-1). This is the **hard-block floor**.
- Malformed / empty.

**Enforcement at the guard (precise matching + HTTP-only).** The allow-list is consulted **only when the existing guard would otherwise refuse** (the resolved host is private/loopback/link-local/reserved). Public hosts never touch it. The carve-out permits a leg **iff**: (1) the URL scheme is **`http`** (an internal `https://` → refused — PR-2b internal legs are HTTP-only); **and** (2) **every** resolved IP of the requested host equals an allow-listed exact IP **and** passes the hard-block floor; then the fetch connects to that validated IP (§8 pin). Because entries are exact IPs, a **cross-tenant ClusterIP the operator did not allow-list is refused** (AS-5, attacker-driven); an operator who *does* allow-list a cross-tenant IP is the AS-9 residual. A match is permitted **and audited** (§9); any miss, scheme violation, or floor failure is the default-deny refusal. Applies to the **three MCP-resource legs** only (`server_url`, `prm_metadata`, `well_known_prm`); never the OAuth legs (`as_metadata`, `token_endpoint`) — §7a.

---

## 7a. The OAuth legs (`as_metadata`, `token_endpoint`) — public-only

PR-2b is **public-AS only**, so neither OAuth leg ever uses the internal-IP carve-out:

- **`as_metadata`** — its URL is **convention-derived** (`{as_issuer}/.well-known/oauth-authorization-server`) from the issuer already selected from the per-tenant AS allow-list, so its host **is** that public, allow-listed issuer's host. It is not an attacker-supplied URL: the shared guard simply confirms it is public. No carve-out, no origin-binding needed.
- **`token_endpoint`** — the only leg the kernel POSTs the operator OAuth `client_secret` to (A2). It carries two rules **beyond** the shared guard, **both mandatory** for PR-2b:
  - **(i) No internal carve-out — hard-public-only.** The internal-IP allow-list does **not** apply; it must resolve to a public host (credentials never travel to an internal host).
  - **(ii) Mandatory issuer-origin binding.** Passing the public-host guard is **not sufficient** (AS-3b): a compromised-but-allow-listed AS can return a `token_endpoint` at an arbitrary public host. So the resolved `token_endpoint` MUST be **origin-bound to the selected AS issuer** — its origin must equal the issuer's origin (`candidate_as[0]`, `mcp_authz.py:653-663`). Any other origin → refused, **no secret assembled or sent** (PR-2a pre-credential placement preserved). There is **no** "explicit token-endpoint allow-list" escape hatch in PR-2b.
  - **Origin canonicalization (both sides normalized identically before comparison):** scheme lowercased; host lowercased + IDNA/punycode-normalized to its A-label + any trailing dot stripped; port default-normalized (`https`→443, `http`→80, so `https://issuer.example` ≡ `https://issuer.example:443`); the origin is **scheme + host + port only** (userinfo/path/query ignored). The token POST **does not follow cross-origin redirects** — a 3xx `Location` to any other origin → refused (no secret re-sent).

(ii) is the *substantive* credential-exfil defense and is **mandatory** — a known exfil cannot have an optional control. The only open question is **sequencing** (OD-11): land (ii) as a standalone **PR-2b-0** before the allow-list work, or bundle it.

---

## 8. DNS / rebinding — how it is closed (and the named residual)

With exact-IP entries + `http://`-IP-literal internal overrides, the rebinding surface shrinks to one leg:
- **`server_url` + `well_known_prm`:** the internal override is an **IP literal**, so there is **no DNS** — the MCP SDK connects to the ClusterIP directly; no rebinding, no internal-TLS.
- **`prm_metadata`:** the URL comes from the pack's `WWW-Authenticate` header and may be a **hostname**. The **kernel owns this fetch** (`mcp_authz._fetch_prm`, kernel httpx). PR-2b implements **resolve-and-pin** with a **kernel-owned custom resolver/transport**: resolve once, require **every** resolved IP to be an allow-listed exact IP passing the floor, require scheme `http`, then connect to the **pinned** validated IP with the original Host header preserved. Internal targets are HTTP-only, so there is **no SNI/cert complication**.
- **`as_metadata` + `token_endpoint`:** public hosts (§7a); standard public DNS + TLS (hostname-verified); not pinned, not allow-listed.

**Result:** no MCP-SDK-internal rebinding residual (the SDK leg is IP-based), and the one kernel-owned hostname leg is pinned. The pin mechanism is **named** (kernel httpx custom resolver, HTTP-only internal) — the plan can proceed. The only residuals are the deliberately-excluded internal-HTTPS / internal-FQDN / in-cluster-AS cases (non-goals) and the AS-9 IP-ownership residual.

---

## 9. Audit / evidence requirements

- **Set-time (governance):** every override-set/clear and allow-list add/remove emits a hash-chained decision-history row via `append_with_precondition` — `tenant_id`, the pack/IP, before/after value, `actor_id` + `actor_type=human`, `request_id`, constant-derived ISO controls (proposal `A.5.31` + `A.6.2.4`). Chain-payload-is-evidence-snapshot. (This audit trail is what makes the AS-9 ownership residual *detectable/attributable*.)
- **Run-time (carve-out provenance):** keep `discovery_status=auth_ready` as a pure **reachability** signal. When the guard permits a host **because of an allow-list hit**, emit a **dedicated** `audit.mcp_allowlist_permitted` audit event carrying `tenant_id`, **leg**, **resolved/pinned IP**, `request_id`, and the **host** — **no `pack_id`** (DD-2: threading pack identity through the authz stack is deferred to a targeted follow-up; the pack is correlated via the MCPHost call path + request evidence). (OD-8, resolved — not a new `discovery_status` value.)
- **Mutually-exclusive log contract** (mirror `operator_routes.py:214-226`): one accepted log on green; one refused log on refusal; zero override/allow-list logs on a sibling-gate (RBAC/human-actor) refusal.

---

## 10. Failure semantics (all fail-closed)

- **Allow-list store unreachable** → empty allow-list → default-deny. Mirrors AS-allow-list + kill-switch posture (`kill_switches.py:238-265`). Never fail-open.
- **Override store unreachable** → fall back to the **manifest `server_url`** (signed), never an arbitrary/cached host.
- **Resolved IP not an allow-listed exact IP (or fails the floor)** → refuse.
- **Internal carve-out leg with `https://` scheme** → refuse (PR-2b internal legs are HTTP-only; internal HTTPS-to-IP is a non-goal, §7/§8).
- **`token_endpoint` origin mismatch, cross-origin redirect, or issuer-origin data unavailable** → refuse (never POST the secret on an unverifiable destination).
- **Grammar-invalid entry** → refused at set-time, never stored.
- **`dev` profile** → guard inert (unchanged); allow-list has no effect.

---

## 11. Tests / proof gates

**Unit (mcp_authz + new modules, CC 95/90):**
- Per-leg allow-list **hit** (resolved IP == allow-listed exact IP) and **miss** for the **three MCP-resource legs** — parametrized; plus a test asserting the allow-list does **not** carve out the OAuth legs (`as_metadata`, `token_endpoint`) (§7a).
- **AS-5 cross-tenant IP**: a resolved IP private but **not** an allow-listed entry → refused (core exact-IP regression).
- **Internal HTTPS refused**: an internal-targeting `https://<ClusterIP>` override → rejected at set-time; a carve-out leg resolving to an allow-listed IP over `https` → refused at the guard.
- **AS-7**: internal override without an allow-list entry → still refused.
- **AS-3a (internal)**: compromised-AS internal `token_endpoint` → refused, **no secret sent**.
- **AS-3b (public attacker) — mandatory**: `token_endpoint` at a non-issuer public origin → refused by §7a(ii), **no secret sent**; the negative test proves the SSRF guard alone *would* have allowed it (fails if origin-binding is removed).
- **Origin canonicalization**: `https://issuer.example` ≡ `https://issuer.example:443`; case/trailing-dot/IDNA-equivalent hosts compare equal; a cross-origin redirect on the token POST → refused.
- **AS-4 grammar**: every rejected entry type (FQDN, `*.svc.cluster.local`, CIDR/range, RFC1918 blanket, `169.254.169.254`, malformed) → closed-enum set-time refusal; an exact IP → stored.
- **Rebinding/pin (§8)**: a `prm_metadata` hostname resolving to an allow-listed IP at check then a different IP at fetch → connection still goes to the pinned allow-listed IP (and a resolution to a non-allow-listed IP → refused).
- **Override observation (OD-12)**: a post-boot override change is observed on the next invoke, no restart.
- **Fail-closed**: store-unreachable → default-deny / manifest-fallback; origin data unavailable → refuse.
- **Drift pin**: the allow-list is consulted at the **three MCP-resource** call sites and **not** at the OAuth legs; §7a(ii) origin-binding runs on every `token_endpoint` (AST/structural pins, mirroring PR-2a's URL-paired detector).

**Integration — Proof 1b-2 (deployed):** a real in-cluster MCP Service (stable ClusterIP, HTTP); an operator **`http://`-IP** override pointing `(tenant, pack)` at that ClusterIP; that exact IP on the per-tenant allow-list; a **public** AS; the deployed strict-profile kernel reaches `discovery_status=auth_ready` then a real `list_tools`/`call_tool`. The pack's loopback manifest URL is **not** edited. Env-gated, mirroring the existing deployed-proof harness.

---

## 12. Open decisions (for Codex / user resolution — implementation gated on these)

**Resolved in rounds 2–3 (reviewer's narrowing):**
- **OD-3 — CIDR floor → RESOLVED:** exact-IP only, no CIDRs.
- **OD-4 — host-match basis → RESOLVED:** match on the resolved IP against exact-IP entries; no FQDN entries.
- **OD-5 — rebinding/pin → RESOLVED (§8):** `http://`-IP-literal internal overrides remove DNS on the SDK legs; the kernel-owned `prm_metadata` leg uses a named kernel-httpx resolve-and-pin (HTTP-only internal). No unscoped residual.
- **OD-7 — `token_endpoint` in allow-list → RESOLVED:** never; hard-public-only (§7a(i)).
- **OD-8 — runtime evidence → RESOLVED:** dedicated `audit.mcp_allowlist_permitted` audit event (§9, no `pack_id` per DD-2).
- **OD-10 — in-cluster AS → RESOLVED:** public AS only (§7a). `as_metadata` is also public (convention-derived) → the carve-out is **three** resource legs, not four.
- **OD-11 — issuer-origin binding → RESOLVED to MANDATORY** (§7a(ii)). *Open part is only sequencing* (below).

**Still open:**
- **OD-1 — Allow-list storage.** (a) **New DB table, decision-history-audited** [rec — a per-tenant allow-list change is a Human-only *decision* per AGENTS.md]; (b) Vault, mirroring the AS allow-list [not chain-audited].
- **OD-2 — Override storage.** New DB table (audited) [rec]; confirm override + allow-list are **two stores** (override per-`(tenant,pack)`, allow-list per-`tenant`).
- **OD-6 — Override pack-identity key.** Reuse the registry/`MCPServerEntry` join key (PR-1's `distribution_name`) [rec, avoids a join mismatch] vs `pack_id` UUID.
- **OD-9 — Allow-list entry lifecycle (AS-8).** None in PR-2b, expiry/review as a follow-up [rec].
- **OD-11 — Sequencing of the (mandatory) issuer-origin binding.** Land it as a standalone **PR-2b-0** before the allow-list work [rec — independent credential-exfil fix, lands fast, de-risks AS-3b immediately] vs bundle it. Mandatory either way.
- **OD-12 — Override observation model.** Resolve-per-use vs short-TTL per-(tenant,pack) cache vs invalidation-on-write [rec: resolve-per-use / short-TTL].
- **OD-13 — Tenant-Service IP-ownership validation (AS-9).** Record operator mis-allow-listing as an **explicit audited residual** for PR-2b [rec — the Human-only audit trail makes it attributable] vs add **K8s-API ownership validation** now (confirm the allow-listed IP is an Endpoint of the tenant's own Service) [heavier; cluster-API dependency]. Recommendation: residual for PR-2b, validation as a follow-up.

---

## 13. What stays true to PR-2a

The five-leg guard is **unchanged in posture** — still default-deny, strict-profile-gated, refusing every non-allow-listed private host at every leg. PR-2b adds a **single, narrow, audited, per-tenant exception of exact ClusterIPs**, consulted only on the refuse path, only on the **three MCP-resource legs**, HTTP-only. The credential-bearing `token_endpoint` keeps its pre-credential guard placement, stays **hard-public-only** (§7a(i)), and gains a **mandatory** issuer-origin rule (§7a(ii)) — the real defense against credential redirection (the SSRF guard alone defends only the internal AS-3a case). As with PR-2a, the spec **names its residuals** — the deliberately-excluded internal-FQDN / internal-HTTPS / in-cluster-AS cases; the AS-9 tenant-Service IP-ownership residual (cross-tenant protection is scoped to the attacker-driven AS-5 case, not operator error/malice); the `dev`-profile inertness — and makes **no "complete SSRF prevention" claim**.
