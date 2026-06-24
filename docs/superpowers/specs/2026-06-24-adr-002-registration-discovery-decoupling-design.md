# ADR-002 amendment — boot-time registration vs MCP discovery-probe coupling (design)

> **Status: DESIGN DRAFT — for Codex review. No implementation. No decision finalized.**
> Origin: Proof 1b-1 finding (`docs/VALIDATION-RESULTS.md`). This spec proposes the ADR-002
> amendment text + an execution plan; it does not edit ADR-002 or any code.

## 1. Problem statement (from Proof 1b-1)

A deployed kernel (kind, prod profile) now boots cleanly, runs migrations, loads the OPA
policy bundles, and reaches boot-time pack registration. The signed pack `cognic-tool-search`
is **discovered and its signature + attestations verified**, but it is **refused at
registration** with `status="refused_at_registration"`, `attestation_grade=null`,
`refusal_reason="mcp_discovery_url_refused"`.

Root cause: boot-time registration runs an OAuth/PRM **discovery probe** of the pack's MCP
`server_url`. The pack's signed manifest advertises `server_url = http://127.0.0.1:8765/mcp`
(a loopback URL, correct for the in-process Proof 1a). Under the prod profile, the MCP SSRF
guard correctly rejects loopback. So a **trust-valid** pack cannot register because of a
**runtime-endpoint** concern.

## 2. Current behavior — verified against the code (and why it failed *correctly*)

Traced in this pass (file:line):

- **Registration** `protocol/plugin_registry.py::register_with_full_attestation_check`
  (def `:1049`) runs, in order: tenant allow-list → cosign verify (`signature_digest`) →
  SBOM → Sigstore-bundle persist → **Step 5 MCP admission** (`:1261`) → policy grade →
  register. Step 5 delegates to `_mcp_admit` (def `:801`).
- **`_mcp_admit` Step C** (`:1011-1035`) is the probe: for `auth = "oauth-prm"` it builds a
  **throwaway** authz client (`make_authz_client_for_probe()`), calls
  `acquire_token(server_url=...)` purely as a "could-acquire" pre-flight, **discards the
  token**, and on `MCPAuthzError` maps the reason 1:1 to a `RefusalReason` (`:1035`).
- That refusal flows back to `register_with_full_attestation_check:1267` → `register(...,
  refusal_reason=...)` → `register()` refusal branch (`:615-626`) → the **closed 2-value**
  `status` Literal (`:381`) lands on `refused_at_registration`.
- **The SSRF guard** `protocol/mcp_authz.py::_refuse_non_public_discovery_url` (def `:971`)
  rejects loopback/private/link-local/reserved/etc. **gated only on**
  `runtime_profile ∈ {"stage","prod"}` (`:1007`). There is **no host allow-list**; the only
  "allow" is public + resolvable + not in the private classes, scheme ∈ {http,https}.
- **The probe already runs at runtime too.** `acquire_token` (`mcp_authz.py:497`) →
  `discover_resource_metadata` (`:416`) → the SSRF guard. Its callers are: **registration**
  (`plugin_registry._mcp_admit:1021`) **and runtime** (`mcp_host.list_tools:840`,
  `mcp_host.call_tool:1673` + the 401/403 reacquire `:1706`). The registration probe uses a
  throwaway client and **warms no cache the runtime client reads** (per-instance token cache,
  `mcp_authz.py:400`; runtime host owns its own long-lived `self._authz`).
- **Status surface** `portal/api/system_routes.py::_plugin_record_dict` (`:138-163`, inline
  dict, no Pydantic DTO) reads `status / attestation_grade / signature_digest /
  refusal_reason / registered_at` straight off `RegistrationOutcome` (`:363-389`).
- **No existing** "endpoint-health" / "discovery-deferred" / "unprobed" concept anywhere in
  `protocol/`.

**Why this is correct, not a bug:** the SSRF guard refusing a loopback discovery URL in prod
is a security control working as designed (the 2026-06-07 remediation §4.1). The finding is
not "the guard is wrong" — it is "registration is *coupled* to a runtime-endpoint probe, so a
trust-valid pack with an environment-specific `server_url` cannot register."

## 3. The two models

### Model 1 — Require-at-registration (current, fail-closed)
A pack registers only after a live, SSRF-safe discovery/OAuth probe of its `server_url`
succeeds at boot. **Pro:** a `registered` pack is immediately invokable; the registry never
advertises a pack with an unreachable/unsafe endpoint. **Con:** registration is coupled to
runtime endpoint health; a trust-valid pack whose MCP Service is not-yet-deployed or whose
`server_url` is environment-specific is refused outright (`refused_at_registration`), even
though its signature + attestations are valid. Deployment ordering is forced
(MCP Service must be up + reachable + SSRF-safe *before* the kernel boots/registers).

### Model 2 — Trust-register-then-defer (recommended)
Boot registration admits the pack on the **offline** trust checks (cosign signature, SBOM,
Sigstore bundle, in-toto/SLSA attestations, policy grade) **plus the offline MCP
manifest-shape validation** (`validate_mcp_manifest`, `_mcp_admit` Step B — no network). The
**network discovery/OAuth probe (Step C) is removed from registration**; it already runs at
invoke (`list_tools`/`call_tool`). The pack's endpoint reachability becomes a **separate,
dynamic status axis**, and invoke **stays fail-closed** (the SSRF guard + AS allow-list still
fire there). **Pro:** trust standing and endpoint reachability become independent; a
trust-verified pack can register before its MCP Service is up or while its `server_url` is
being made environment-appropriate; registration does no redundant network I/O (it warmed no
cache anyway). **Con:** the registry can advertise a trust-verified pack that is **not yet
invokable**; consumers MUST consult the endpoint status before assuming invocability.

### The insight that constrains BOTH models
Deferring the probe **does not make a loopback `server_url` work** — the SSRF guard is
profile-gated, so it fires at `list_tools`/`call_tool` too. Model 2 changes **when** the
refusal surfaces (boot → first invoke) and **what it blocks** (invocation, not registration);
it does **not** make the deployed pack invokable. A deployed pack still needs an
**environment-appropriate, SSRF-safe `server_url`** to be invokable — see §7 (URL override).

## 4. Recommendation

**Adopt Model 2 (trust-register-then-defer), paired with the §7 URL-override policy.**

Rationale:
1. **Orthogonal concerns.** Cryptographic trust (is this the pack the bank approved?) and
   endpoint health (is its MCP Service reachable + SSRF-safe *here*?) are independent. Model 1
   conflates them; a valid signature should not be voided by a runtime-endpoint URL.
2. **The runtime probe already exists.** Model 2 needs **no new probe code** — `list_tools`/
   `call_tool` already discover + OAuth + SSRF-check. Registration's probe is redundant work
   that warms no cache.
3. **Deployment ordering.** A bank deploys the kernel and the pack's MCP Service as separate
   workloads; Model 2 lets the pack trust-register at boot and become invokable when its
   Service + `server_url` are ready, instead of forcing a brittle boot-time ordering.
4. **Fail-closed is preserved.** Invocation still refuses on SSRF/AS-allow-list/unreachable —
   a trust-registered pack with a refused/unreachable endpoint cannot be invoked.

**This is a recommendation for Codex review, not a final decision.**

## 5. Security invariants (non-negotiable)

1. **The SSRF guard is not weakened.** `_refuse_non_public_discovery_url` keeps rejecting
   loopback/private/link-local/reserved/multicast/unspecified in strict profiles. Model 2
   removes the *registration* call site only; the *runtime* call site stays.
2. **Fail-closed at invoke.** A pack whose endpoint probe fails (SSRF, AS-not-allow-listed,
   unreachable) is **not invokable** — `list_tools`/`call_tool` continue to raise.
3. **Trust ≠ endpoint.** A `registered` (trust) status never implies a healthy endpoint. The
   two axes are surfaced separately.
4. **No broad internal DNS.** §7's override must NOT permit `*.svc.cluster.local` or any
   internal range by default. Any internal host is **explicit, per-tenant, default-deny**.
5. **No manifest mutation.** The signed `server_url` is a signed *default*; overrides are
   runtime/operator configuration, never edits to the signed manifest (which would break the
   signature + the ADR-016 attestation chain).
6. **Offline checks stay at registration.** Manifest-shape validation (`validate_mcp_manifest`)
   is offline and STAYS at registration — only the *network* probe defers.

## 6. Data / status implications

Current: `RegistrationOutcome.status: Literal["registered", "refused_at_registration"]`
(`plugin_registry.py:381`) — a closed 2-value enum, no intermediate state.

**Proposed two-axis model:**

- **Trust axis = the existing `status`**, re-scoped. `refused_at_registration` now fires ONLY
  for **trust/offline** failures (tenant-allow-list, signature, SBOM, Sigstore, attestation,
  policy grade, **manifest-shape**). It NO LONGER fires for the network discovery/OAuth probe.
  `registered` means "trust-verified + admitted." (Backward-compatible: the enum is unchanged;
  its *meaning* narrows — see §8.)
- **Discovery axis = a new `discovery_status`**, default-`unprobed`. Proposed closed enum:
  `unprobed` (registered, never probed) / `auth_ready` (last probe completed PRM discovery +
  acquired a token) / `refused` (last probe hit SSRF / AS-allow-list refusal) / `unreachable`
  (network/timeout). Set/updated at **invoke time** by `list_tools`/`call_tool`, not at
  registration. **`auth_ready` is NOT "healthy"** — it proves PRM/OAuth succeeded, NOT that a
  transport session opened or `list_tools` returned tools. A true **endpoint-health** axis
  (session/tools actually reachable) is a deliberate **later** addition if needed; Slice 2 ships
  the discovery axis only, so the name stays `discovery_status`.

**`RefusalReason` (registration enum) is kept intact.** The `mcp_discovery_url_refused` /
`mcp_oauth_*` values **stay** in `RefusalReason` (no removal → no wire break; historical chain
rows that carry them remain valid) — registration simply **stops emitting** them on the Model-2
path. The discovery axis surfaces its own refusals via a **separate** vocabulary: reuse the
existing `MCPAuthzReason` (`protocol/mcp_authz.py`), kept distinct from registration
`RefusalReason`.

**Where `discovery_status` lives (decided, Codex Run 2):** it is *dynamic* (changes as probes
succeed/fail), so it does NOT live on the frozen, registration-time `RegistrationOutcome`. The
host writes it through a **narrow injected `DiscoveryStatusRecorder` protocol** (e.g.
`record(tenant, pack, status)`); `MCPHost` does **not** gain a raw-registry dependency — the
backing store (a separate per-`(tenant, pack)` map, registry-backed or standalone) is hidden
behind the protocol, preserving the existing MCPHost↔registry decoupling. `/system/plugins`
joins the recorder's status into the per-plugin dict.

## 7. URL override policy (and non-goals)

The manifest `server_url` is a **signed default**. To make a deployed pack invokable without
mutating the manifest, an operator may supply a per-`(tenant, pack)` **`server_url` override**
as runtime configuration. Resolution at invoke: `resolved_url = override(tenant, pack) ??
manifest.server_url`. The resolved URL goes through the **same** SSRF guard + AS allow-list.

Because a real in-cluster MCP Service resolves to a **private** IP (which the SSRF guard
rejects by default), permitting it requires an **explicit per-tenant internal-host allow-list**
— a narrow, default-deny exception consumed by the SSRF guard:
- Stored like the existing per-tenant AS allow-list (Vault `secret/cognic/{tenant}/...`,
  mirroring `_load_as_allowlist`, `mcp_authz.py:1115`).
- Entries are **specific hosts or narrow CIDRs only** — never wildcards, never
  `*.svc.cluster.local`, never a blanket RFC1918 range (`10.0.0.0/8` etc.).
- The SSRF guard, when a resolved host is private, refuses UNLESS the host matches a
  tenant-scoped allow-list entry; even then scheme/shape checks still apply.

**The allow-list governs EVERY discovery fetch, not just `server_url`/the override.** PRM
discovery follows `WWW-Authenticate: resource_metadata` + well-known URLs that can resolve to a
**different host** than `server_url` — the SSRF guard already re-checks at both
`discover_resource_metadata` (`mcp_authz.py:433`) and `_fetch_prm` (`:1048`). So the
tenant-scoped internal-host validation MUST apply at **every** SSRF-guard call site: each
fetch's resolved host is independently validated, and a PRM / `WWW-Authenticate` URL that
resolves to a private address must ALSO be explicitly tenant-allow-listed or it is refused. A
tenant+pack context threads to every guard call so the correct allow-list applies.

**Non-goals (explicit):**
- Do **not** weaken the default SSRF guard or permit broad internal DNS.
- Do **not** edit the pack's `127.0.0.1` `server_url` to force Proof 1b green.
- Do **not** require the override to register — registration is trust-only (Model 2); the
  override + allow-list only affect **invocability**.
- The override resolution + internal allow-list MAY be split into a later slice; the ADR
  amendment defines the policy shape, the plan sequences the implementation.

## 8. Migration / backward-compat

- **`status` enum unchanged** (no wire break for readers of `status`); its *semantics* narrow
  (`refused_at_registration` = trust/offline failure only). Document this in ADR-002 + the
  `/system/plugins` consumers.
- **`discovery_status` is additive** (new field, default `unprobed`). Existing consumers that
  do not read it are unaffected; the `/system/plugins` dict gains a key.
- **`RefusalReason` enum is unchanged** — the `mcp_discovery_url_refused` / `mcp_oauth_*` values
  **stay** (no removal → no wire break; historical chain rows that carry them remain valid).
  Registration just stops EMITTING them on the Model-2 path; the discovery axis surfaces its
  refusals via the separate `MCPAuthzReason` vocabulary.
- **Behavior change:** a pack that *was* `refused_at_registration` for a discovery-URL reason
  now `registered` + `discovery_status` ∈ {`unprobed`,`refused`}. This is the intended effect.
- **Proof 1b-1 harness:** under Model 2 the pack would `registered` + `discovery_status=unprobed`
  (or `refused` once invoked). The harness's current assertion (`status==registered` +
  `attestation_grade=="full"`) needs re-framing to the chosen semantics (1b-1 = trust axis; see
  the plan's split) — but **not** by hacking the URL.

## 9. Tests required later (summary; the plan expands)

- **Registry:** a pack with `auth="oauth-prm"` + a loopback/unsafe `server_url` now
  `registered` (trust path) — NOT `refused_at_registration`; the offline manifest-shape failure
  still refuses; `discovery_status` defaults `unprobed`; `RefusalReason` keeps its values
  (drift-pin) while registration stops emitting the network ones.
- **MCP host runtime discovery:** `list_tools`/`call_tool` still fail closed on SSRF / AS-refusal
  / unreachable; the probe outcome updates `discovery_status` via the `DiscoveryStatusRecorder`
  (`auth_ready` on token acquire — NOT "healthy"); a tenant-allow-listed override acquires a token.
- **URL override policy:** override resolves at invoke; SSRF guard still applies; an internal
  host is refused UNLESS tenant-allow-listed; wildcards/broad ranges rejected; signed manifest
  is never mutated.
- **Portal `/system/plugins` status:** surfaces `status` (trust) + `discovery_status`
  (auth/discovery, NOT health); summary counts reflect both axes.
- **Docs:** ADR-002 amendment + (if attestation wording is touched) an ADR-016 cross-ref;
  `VALIDATION-RESULTS` / `PROJECT_STATUS` updated to the chosen model.

## 10. The ADR-002 amendment draft (proposed text — to append after the decision)

> ## Boot-time registration vs MCP discovery probe — decoupling (Proof 1b-1 resolution, <date>)
>
> **Decision: trust-register-then-defer.** Boot-time pack registration admits a pack on its
> offline trust checks (cosign signature, SBOM, Sigstore bundle, in-toto/SLSA attestations,
> policy grade) plus offline MCP manifest-shape validation. The MCP discovery/OAuth **network**
> probe is **removed from registration** and remains at invoke (`list_tools`/`call_tool`),
> which already performs it. A pack's `status` reflects **trust only**; a new `discovery_status`
> axis (`unprobed`/`auth_ready`/`refused`/`unreachable`) reflects the PRM/OAuth **discovery**
> outcome (`auth_ready` ≠ endpoint-healthy), set at invoke via a narrow injected
> `DiscoveryStatusRecorder`. The `RefusalReason` registration enum is **unchanged** — its
> `mcp_discovery_url_refused`/`mcp_oauth_*` values stay (no wire break; historical rows valid),
> and registration simply stops emitting them; the discovery axis uses the separate
> `MCPAuthzReason` vocabulary.
>
> **Security invariants (unchanged guard):** the MCP SSRF guard is not weakened and still fires
> at invoke; invocation stays fail-closed on SSRF / AS-allow-list / unreachable; a trust
> `registered` status never implies a reachable endpoint.
>
> **`server_url` override policy:** the signed manifest `server_url` is a signed default. An
> operator may supply a per-`(tenant, pack)` override as runtime configuration (never a manifest
> edit). The resolved URL passes the same SSRF guard; permitting an in-cluster (private-IP)
> service requires an **explicit, per-tenant, default-deny internal-host allow-list** (specific
> hosts/narrow CIDRs, never wildcards/broad internal DNS) applied to **every** discovery fetch
> (`server_url`, `WWW-Authenticate: resource_metadata`, well-known PRM URLs), each independently
> host-validated.
>
> **Supersedes** the "boot-time registration discovery-probe coupling — open design question"
> amendment (2026-06-24): the question is now decided as above.

(If the alternative — Model 1 / require-at-registration — is chosen on review, this section
instead documents keeping the current coupling and treats the deployed `server_url` purely as
the §7 override problem.)
