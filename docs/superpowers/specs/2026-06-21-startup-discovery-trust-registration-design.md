# MCP/A2A Startup Discovery + Trust-Registration (single-tenant `_default`) — Design Spec

> **Status:** DRAFT — pending user review before writing-plans.

## Problem

Both the MCP host (`build_mcp_host`) and the A2A receiver (`A2AEndpoint`) resolve packs against a `PluginRegistry` that is **empty at default startup** — `discover()` is never called, and the two surfaces each build their **own** `PluginRegistry(...)` (`app.py:646` for MCP, `:689` for A2A). So in a default deploy MCP `list_tools`/`call_tool` return 404 (empty catalog) and A2A `message/send` to any agent → `unknown_target` (no agents registered), **even when trusted pack wheels are installed**.

This slice (the second cut of the "Protocol Reachability" epic, sequenced right after A2A inbound reachability) populates **one shared registry at boot** — running the real trust gate (signature + `_default` allow-list, per pack) — and feeds **both** surfaces from it.

## Scope

**IN:**
1. A boot discovery + trust-registration builder (off-gate `harness/registry_boot.py`).
2. The shared-registry unification — one registry → both `build_mcp_host` and `A2AEndpoint`.
3. `app.state.plugin_registry` exposure (preseed `None`; lifespan assigns).
4. The `_default` allow-list load (explicit, **fail-closed**).

**OUT (deferred, documented non-goals):**
- **Multi-tenant per-tenant pack trust/visibility** — the registry `_records` is global `(PluginKind, name)`-keyed and the consumers don't re-filter per calling tenant, so true per-tenant trust needs the registry re-keyed `(kind, name, tenant)` **or** call-time allow-list filtering — a registry/consumer **redesign**, its own slice.
- Outbound A2A; the auxiliary A2A surfaces (capabilities/cancellation/artifacts).

## Design

### 1. The boot-builder `harness/registry_boot.py` (off-gate)

`build_and_populate_registry(*, settings, audit_store, decision_history_store, trust_gate) -> PluginRegistry` — mirrors the existing `harness/mcp_host.py` / `harness/sandbox.py` builder pattern. It:
- **loads the `_default` allow-list** from `policies/_default/plugin_allowlist.json` → the `_default` `frozenset[str]` (the path resolution is a harness-verify — `Settings` value vs the hard `policies/_default/` path),
- constructs a fresh `PluginRegistry(audit_store=…)`,
- `discover()` → for each `DiscoveredPack`, `await registry.register_with_full_attestation_check(pack, trust_gate=…, tenant_id="_default", tenant_allowlist=<_default frozenset>, …)` — **always the explicit frozenset, never `None`** (no accidental allow-all boot),
- returns the populated registry. The registry's own `plugin.registration_succeeded` / `plugin.registration_refused` chain events ARE the boot evidence (no extra audit surface).

### 2. The shared-registry unification (lifespan, off-gate `app.py`)

Build one shared `trust_gate` (the slice already builds an `a2a_trust_gate`/`TrustGate` in the A2A block — promote it to a single shared instance), then resolve the registry ONCE:
- `plugin_registry` injected (non-`None`) → **caller owns pre-population; no discovery** (the bank-overlay seam),
- `plugin_registry is None` → `build_and_populate_registry(...)` (boot discovers + full-attestation-registers under `_default`).

Thread that **single** `registry` into **both** `build_mcp_host(registry=…)` and `A2AEndpoint(plugin_registry=…)`, replacing the two `or PluginRegistry(...)` fallbacks. Expose it on **`app.state.plugin_registry`** (preseeded `None` in the body, like `mcp_host`/`a2a_endpoint`) so it's inspectable + testable at app state.

### 3. The `_default` allow-list (fail-closed)

The allow-list is loaded explicitly and passed as a frozenset. **Missing file / missing `_default` key / malformed JSON → the builder raises a clear typed error** (fail-closed for registration — no allow-all). The plan VERIFIES the `register_with_full_attestation_check` `tenant_allowlist=None` semantics, but the landed code never relies on `None`.

### 4. Failure-state + observability (the locked choices)

| Failure | Behaviour |
|---|---|
| Per-pack registration **refusal** (bad signature / `not_in_tenant_allowlist`) | Stored as a refusal in the registry + logged. Fail-soft — the pack is simply absent from the catalog; boot continues. |
| Per-pack registration **exception** (e.g. cosign binary unavailable) | Caught per-pack, the pack skipped + logged. Boot continues → a **partially** populated registry on `app.state.plugin_registry`. |
| **Allow-list load failure** (missing/malformed) | The builder raises → the lifespan's fail-soft catch logs ERROR + leaves `app.state.plugin_registry = None`, and the MCP host + A2A endpoint stay `None` → **both surfaces 503** (fail-closed, *distinguishable* from an empty-but-healthy catalog). The app still boots. |

### 5. Honest scope (drives the closeout language)

This registers **whatever packs are installed** (entry-point-discovered). A bare kernel/default-adapters image with **no pack wheels installed** → `discover()` returns `[]` → **empty catalog, correctly** (not a failure). The slice's value: *when* trusted packs are installed, they're discovered + trust-verified + registered at boot, instead of the catalog being empty regardless. The closeout updates BOTH surfaces' language from "registry empty by default" → **"registry is populated when trusted pack wheels are installed; empty remains correct when none are installed."**

## Testing

- **Boot loop populates** — with a stub/installed discoverable pack (allow-listed + trust-passing), `build_and_populate_registry` yields a registry whose registered set the MCP `list_tools` + the A2A routing both resolve against (the unification — one registry feeds both).
- **Per-pack fail-soft** — a bad-signature / non-allow-listed pack → a refusal stored, the other packs still registered; a per-pack exception → that pack skipped, others registered (partial registry).
- **Allow-list fail-closed** — missing file / missing `_default` key / malformed → the builder raises; the lifespan leaves `app.state.plugin_registry = None` → both surfaces 503 (NOT an empty allow-all catalog).
- **Injection seam** — an injected `plugin_registry` → no `discover()` call (caller owns pre-population); pinned by spying `discover`.
- **Bare-no-packs** — `discover()` `[]` → empty registry, both surfaces healthy-but-empty (correct).
- **`app.state.plugin_registry`** is the injected-or-boot-populated instance (and is the SAME object `build_mcp_host` + `A2AEndpoint` received).

## CC / ADR / migration posture

- **Off-gate** — the boot-builder (`harness/registry_boot.py`) + the lifespan wiring mirror the 13.8/14A off-gate builders. `protocol/plugin_registry.py` (on-gate) is **consumed, not modified** — `discover()` + `register_with_full_attestation_check()` already exist. **No new gate module → CC stays 133.** No migration.
- **ADR-002 amendment** (MCP startup discovery/trust-registration) + the cross-reference in the ADR-003 A2A amendment (the registry that now feeds the receiver) + AS_BUILT milestone + the closeout-language update for both surfaces.

## Harness-verify points (for the plan — don't guess)

- The exact `register_with_full_attestation_check(...)` parameters beyond `tenant_id`/`tenant_allowlist` (`signature_digest`, `license_allowlist`, `attestation_grade` — and how a "full attestation" run sources them from the discovered pack); and the `tenant_allowlist=None` semantics (VERIFY only — the landed code passes the explicit frozenset).
- The allow-list path: a `Settings` value vs the hard `policies/_default/plugin_allowlist.json` — and whether a loader already exists elsewhere to reuse.
- The exact `build_mcp_host` / `A2AEndpoint` registry kwargs to thread the shared instance into (confirm against the `app.py:646`/`:689` blocks).
- The `TrustGate` construction already in the A2A block (`a2a_trust_gate`) — promote to one shared instance the registration + the A2A endpoint both use.
