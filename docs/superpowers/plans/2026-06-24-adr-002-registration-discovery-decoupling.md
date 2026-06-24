# Implementation plan (DRAFT) — registration / MCP discovery-probe decoupling

> **Status: PLAN DRAFT — for Codex review. Do NOT execute.** Depends on the design decision in
> `docs/superpowers/specs/2026-06-24-adr-002-registration-discovery-decoupling-design.md` being
> approved (Model 2 + the URL-override policy). If Model 1 is chosen instead, only Slice 3
> (override policy) + Slice 5 (docs) survive.

**Goal:** Decouple boot-time pack registration (trust axis) from the MCP discovery/OAuth
network probe (endpoint axis), add an operator `server_url` override + explicit internal-host
allow-list, and surface both axes — without weakening the SSRF guard or mutating signed
manifests.

## Critical-controls posture (read before any slice)

- `protocol/plugin_registry.py` and `protocol/mcp_authz.py` are **critical-controls** modules
  (plugin trust gate + MCP authorization). Use `core-controls-engineer` + `/critical-module-mode`;
  **95% line / 90% branch**, negative-path tests required, no casual refactors, strict
  halt-before-commit review on every commit.
- **Wire-protocol surfaces touched:** the `RegistrationOutcome.status` Literal, the
  `RefusalReason` closed-enum (kept intact; registration stops emitting network reasons), the
  new `discovery_status` enum, and the `/system/plugins`
  response dict are all wire-protocol-public. Per AGENTS.md these need explicit review + a
  drift-pinned test; treat enum changes as the documented "closed-enum N-step change."
- Per-action authorization for every commit/push/PR/merge; protected docs never staged.

## Two-PR split (Codex Run 2)

The SSRF-sensitive override work is split OUT of the first arc:
- **PR 1 — registration decoupling + discovery status** (this arc): **Slices 0, 1, 2, 4a.**
  Lands the trust/discovery decoupling + the `discovery_status` axis + the 1b-1 (trust-axis)
  re-frame. **No SSRF-policy changes** — the guard's *registration* call site is removed; no new
  allow-list, no override resolution.
- **PR 2 — operator URL overrides + internal-host allow-list** (SEPARATE later workstream):
  **Slice 3 + 4b.** The SSRF-policy work (override resolution + the narrow per-tenant
  internal-host allow-list applied to every discovery fetch + the 1b-2 endpoint/invoke proof).
  The ADR (Slice 0) defines the policy shape now; the implementation lands here, on its own
  review + threat-model pass.

## Slice 0 — ADR decision lands (docs only)

- [ ] Finalize the ADR-002 amendment text (from the spec §10) into
      `docs/adrs/ADR-002-mcp-plugin-protocol.md`, marking the 2026-06-24 "open design question"
      amendment **superseded/decided**.
- [ ] If trust-registration wording is touched, add an ADR-016 cross-ref (attestation chain is
      unchanged — registration still verifies signature + attestations; only the network probe
      moves).
- [ ] Review halt: Codex confirms the decision text before any code.

## Slice 1 — Decouple registration from the network probe (CC)

**Files:** `src/cognic_agentos/protocol/plugin_registry.py` (`_mcp_admit` Step C `:1011-1035`;
`RefusalReason` `:81-126`; `register()` refusal branch `:615`).

- [ ] **RED:** test — an `auth="oauth-prm"` pack with a loopback/unsafe `server_url`, given
      valid signature + attestations + valid manifest shape, now returns
      `status="registered"` (NOT `refused_at_registration`); `attestation_grade` is the policy
      grade (not null). Today this is RED (it refuses).
- [ ] **RED:** test — an `auth="oauth-prm"` pack with a **malformed manifest shape** (offline
      `validate_mcp_manifest` failure) still returns `refused_at_registration` (Step B stays).
- [ ] **GREEN:** remove the Step C network probe (`acquire_token` call + the
      `_authz_reason_to_refusal` mapping) from `_mcp_admit`; keep Step A (extraction) + Step B
      (manifest-shape). The `mcp_discovery_url_refused` / `mcp_oauth_*` reasons no longer reach
      `register()`'s refusal branch from registration.
- [ ] **GREEN:** `RefusalReason` enum **kept intact** (decided, Codex Run 2) — the
      `mcp_discovery_url_refused`/`mcp_oauth_*` values STAY for backward-compat + historical chain
      rows; registration simply stops emitting them on the Model-2 path. Drift-pin the closed enum
      (value count unchanged). The discovery axis (Slice 2) uses the separate `MCPAuthzReason`.
- [ ] Full CC gate (mypy src tests, ruff, 95/90 on the touched module) + review halt.

## Slice 2 — The `discovery_status` axis via a narrow recorder (CC)

**Files:** a NEW narrow `DiscoveryStatusRecorder` protocol + backing store (a separate per-`(tenant,
pack)` mutable map — NOT a field on the frozen `RegistrationOutcome`; the host writes via the
protocol so it gains NO raw-registry dependency, preserving the MCPHost↔registry decoupling),
`protocol/mcp_host.py` (`list_tools:840` / `call_tool:1673,1706` — record the probe outcome
through the injected recorder), `portal/api/system_routes.py` (`_plugin_record_dict:138` —
surface `discovery_status`).

- [ ] **RED:** test — a freshly trust-registered pack has `discovery_status="unprobed"`.
- [ ] **RED:** test — after a `list_tools`/`call_tool` that hits the SSRF guard,
      `discovery_status="refused"`; after a successful token acquire, `discovery_status="auth_ready"`
      (NOT "healthy" — token ≠ session/tools); on network timeout, `unreachable`.
- [ ] **RED:** test — `/system/plugins` surfaces both `status` (trust) and `discovery_status`;
      summary counts both axes.
- [ ] **GREEN:** add the `DiscoveryStatusRecorder` protocol + backing store + the 4-value enum
      (`unprobed`/`auth_ready`/`refused`/`unreachable`, drift-pinned); inject the recorder into
      `MCPHost`; thread updates from the host's probe outcomes; surface in the route dict; keep
      `list_tools`/`call_tool` fail-closed (they still raise — `discovery_status` is observational,
      not a bypass). The recorder is the ONLY new host↔status coupling.
- [ ] Full CC gate + review halt.

## Slice 3 — `server_url` override + explicit internal-host allow-list (CC) — **PR 2 (separate workstream + threat-model pass)**

**Files:** `protocol/mcp_authz.py` (the SSRF guard `_refuse_non_public_discovery_url:971` — the
per-tenant internal-host allow-list exception threaded to **BOTH** guard call sites
[`discover_resource_metadata:433` + `_fetch_prm:1048`]; the override resolution at the
`acquire_token`/`discover_resource_metadata` entry), `core/config.py` (Settings for the override
source + allow-list source), a per-tenant allow-list loader mirroring `_load_as_allowlist`
(`mcp_authz.py:1115`).

- [ ] **RED:** test — a per-`(tenant, pack)` override resolves at invoke; the manifest default
      is used when no override; the signed manifest object is never mutated.
- [ ] **RED:** test — the override URL passes the SAME SSRF guard; an internal/private host is
      **refused** UNLESS it matches a tenant-scoped allow-list entry; wildcards / broad RFC1918
      ranges / `*.svc.cluster.local` are rejected even when supplied as allow-list entries.
- [ ] **RED:** test — **every** discovery fetch is validated: a `WWW-Authenticate`/well-known PRM
      URL that resolves to a DIFFERENT private host than `server_url` is ALSO refused unless
      tenant-allow-listed (BOTH guard call sites honor the tenant+pack context).
- [ ] **RED:** test — default-deny: with no allow-list, a private-IP override (or a private PRM
      URL) is refused.
- [ ] **GREEN:** implement override resolution + the narrow, default-deny, per-tenant internal-host
      allow-list inside the SSRF guard, threading the tenant+pack context to BOTH guard call sites;
      keep all other guard checks intact (no broad internal DNS, no blanket RFC1918).
- [ ] Full CC gate + review halt.

## Slice 4 — Harness re-frame + docs (off-gate) — SPLIT: 4a (PR 1) + 4b (PR 2)

**Files:** `infra/proof-1b/run-proof-1b-1.sh` + `tests/integration/proof_1b/`,
`docs/VALIDATION-RESULTS.md`, `docs/PROJECT_STATUS.md`.

The 1b-1 / 1b-2 split is **decided** (Codex Run 2): 1b-1 = registration trust axis; 1b-2 =
endpoint health/invoke axis.

- [ ] **(4a, PR 1) 1b-1 = registration trust axis.** Re-frame the Proof 1b-1 assertion to
      `status=="registered"` + `discovery_status=="unprobed"` (the trust axis is proven; discovery
      deferred). Update `VALIDATION-RESULTS` / `PROJECT_STATUS` (no overclaim). **Not** by hacking
      the URL.
- [ ] **(4b, PR 2) 1b-2 = endpoint/invoke axis.** A separate proof: deploy a real in-cluster MCP
      Service + the operator override + the internal-host allow-list, assert
      `discovery_status=="auth_ready"` + a real `list_tools`/`call_tool` invoke. Lands with PR 2.
- [ ] **Do not** rerun live Proof 1b in this implementation arc (operator-run, env-gated).

## Tests required (consolidated)

- **Registry:** loopback-`server_url` oauth-prm pack registers (trust); manifest-shape failure
  still refuses; `discovery_status` defaults `unprobed`; `RefusalReason` kept (drift-pin, count
  unchanged) while registration stops emitting the network reasons.
- **MCP host runtime discovery:** `list_tools`/`call_tool` stay fail-closed on SSRF / AS-refusal
  / unreachable; probe outcome updates `discovery_status` (`auth_ready`, not "healthy") via the
  `DiscoveryStatusRecorder`; a tenant-allow-listed override acquires a token.
- **URL override policy:** override resolution; SSRF guard still applies; internal host refused
  unless tenant-allow-listed; default-deny; no wildcard/broad DNS; manifest never mutated.
- **Portal `/system/plugins` status:** both axes surfaced; summary counts both; DTO/dict drift.
- **Docs:** ADR-002 (decision) + ADR-016 cross-ref; VALIDATION-RESULTS / PROJECT_STATUS.

## Non-goals (explicit)

- **No live Proof 1b rerun** in the implementation arc (operator-run, env-gated).
- **No URL hack** — never edit the pack's `127.0.0.1` `server_url` to force green.
- **No broad internal DNS allow** — no `*.svc.cluster.local`, no blanket private ranges; the
  internal allow-list is explicit, per-tenant, default-deny.
- **No SSRF-guard weakening** — the guard's checks are unchanged; only the registration call
  site is removed (Slice 1) and a narrow tenant-scoped exception is added (Slice 3).
- **No push/PR/merge, no memory update** without an explicit token.
- **No manifest mutation** — the signed `server_url` is a signed default.
