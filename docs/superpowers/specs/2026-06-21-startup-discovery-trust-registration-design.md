# MCP/A2A Startup Discovery + Trust-Registration (single-tenant `_default`) — Design Spec

> **Status:** LANDED 2026-06-21 (rev. 4 — signed-wheel blob + dual-`TrustGate` root reconciliation). Merged across 5 subagent-driven sprints (the setting → the on-gate resolver → the boot-builder + `mcp_admission` seam → the lifespan unification → the headline-join conformance). See the ADR-002 "MCP/A2A startup discovery + trust-registration amendment (2026-06-21)" + AS_BUILT milestone 6l. **AS-BUILT note:** `opa_engine=None` was accepted for the boot's `mcp_admission` — non-sampling MCP packs register; sampling-capable packs default-deny (the real sampling `OPAEngine` is a documented extension).
>
> **Scope corrections from plan-grounding:** (1) the full `register_with_full_attestation_check` path needs a `PackAttestations` + `SupplyChainPipeline` + `ObjectStore` (a runtime resolver — on-gate trust primitive). (2) Installed packs **don't carry their attestations** (`cli/sign.py` writes them next to the wheel), so there's no `locate_file` sourcing — this slice defines a deployment `Settings.pack_attestation_root_path` (`core/config.py` stop-rule touch). (3) `TrustGate.verify_pack_signature` cosign-verifies the **signed wheel** as the blob, canonicalizing `signature_path`+`blob_path` under `signature_root_path` and `trust_root` under `trust_root_prefix` — so the wheel is a 5th required artefact and the boot needs its **own** `registration_trust_gate` whose `signature_root_path` is the attestation root.

## Problem

The MCP host (`build_mcp_host`) and A2A receiver (`A2AEndpoint`) resolve packs against a `PluginRegistry` **empty at default startup** — `discover()` is never called, and each surface builds its **own** `PluginRegistry(...)` (`app.py:646` MCP, `:689` A2A). So MCP 404s and A2A → `unknown_target`, **even when trusted pack wheels are installed**. This slice (the second "Protocol Reachability" cut) populates **one shared registry at boot** via the full `register_with_full_attestation_check` pipeline per pack, feeding both surfaces.

## Scope

**IN:** (1) `Settings.pack_attestation_root_path` (`core/config.py`); (2) a runtime **`PackAttestations` resolver** (on-gate trust primitive) resolving from `<root>/<distribution_name>/<version>/`; (3) an off-gate boot-builder running the **full** registration path with a **registration-specific `TrustGate`**; (4) the shared-registry unification on `app.state.plugin_registry`; (5) the `_default` allow-list (fail-closed).

**OUT (deferred):** multi-tenant per-tenant trust/visibility (registry re-key or call-time filter); bundling attestations inside wheels (a `cli/sign.py` change); outbound A2A; auxiliary A2A surfaces.

## Design

### 1. The setting `Settings.pack_attestation_root_path: str | None` (`core/config.py` — stop-rule touch)

Default `None`. The operator places each installed pack's signed artefacts at `<pack_attestation_root_path>/<distribution_name>/<version>/`. Additive nullable field; focused settings tests pin default + env override.

### 2. The `PackAttestations` resolver — `protocol/pack_attestation_resolver.py` (NEW, **on-gate**, critical control)

**Exact signature:** `resolve_pack_attestations(pack: DiscoveredPack, *, pack_attestation_root: Path, cosign_trust_root: Path) -> PackAttestations`. Pure (reads no settings; the boot-builder passes both roots). Trust-input primitive → on-gate (95/90, negative-path). For `base = pack_attestation_root / record.distribution_name / record.distribution_version`:
- resolve the **5 required** artefacts + 3 optional under `base`, each real-path **canonical-contained under `pack_attestation_root`** (`distribution_name`/`version` are pack-controlled entry-point metadata; a crafted `../` is rejected),
- the **signed wheel** is the cosign blob: glob `<base>/*.whl` — exactly one → `cosign_blob_path`; **zero → `attestation_required_artefact_missing`; multiple → `attestation_wheel_ambiguous`**,
- read the **required** `sbom_signed_digest` from `slsa-provenance.intoto.json` → `predicate.buildDefinition.externalParameters.sbom_digest_sha256`; absent/malformed → `sbom_digest_unsourced`,
- `cosign_trust_root` passes through to `PackAttestations.cosign_trust_root`,
- closed-enum `PackAttestationResolutionError.reason` (**6 values**): `attestation_distribution_unidentified`, `attestation_path_escapes_root`, `attestation_required_artefact_missing`, `attestation_required_artefact_empty`, `attestation_wheel_ambiguous`, `sbom_digest_unsourced`. NEVER `EntryPoint.load()`.

**The contract (required / deployment / optional):**

| Item | Kind | Source | Fail-closed (typed) |
|---|---|---|---|
| `cosign.sig` | required pack artefact | `<base>/cosign.sig` | `…_missing` / `…_empty` |
| **signed wheel `*.whl`** (= `cosign_blob_path`) | **required pack artefact (the cosign blob)** | `<base>/*.whl` — **exactly one** | 0 → `…_missing` ; **>1 → `attestation_wheel_ambiguous`** ; empty → `…_empty` |
| `bundle.sigstore` | required pack artefact | `<base>/bundle.sigstore` | `…_missing` / `…_empty` |
| `sbom.cdx.json` | required pack artefact | `<base>/sbom.cdx.json` | `…_missing` / `…_empty` |
| `slsa-provenance.intoto.json` | required pack artefact | `<base>/slsa-provenance.intoto.json` | `…_missing` / `…_empty` |
| `sbom_signed_digest` | required derived | SLSA `…externalParameters.sbom_digest_sha256` | `sbom_digest_unsourced` |
| `pack_attestation_root` | deployment input | `Settings.pack_attestation_root_path` | unset → empty registry (§5) |
| `cosign_trust_root` | deployment input | **`Path(Settings.trust_root_prefix) / "_default" / "cosign.pub"`** (boot-builder; LOCKED convention) | missing / non-file / empty → boot raises (§5 → 503) |
| path-containment | invariant | resolved real-path under the root | `attestation_path_escapes_root` |
| distribution identity | invariant | `record.distribution_name` ≠ `"<unknown>"` | `attestation_distribution_unidentified` |
| `intoto-layout.json` / `vuln-scan.json` / `license-audit.json` | optional grace-period | `<base>/<name>` | absent → `None` |

(`slsa-provenance.intoto.json` is required at the resolver because it carries the required digest, even though the registration *grade* treats SLSA as optional. HARNESS-VERIFY no existing supply-chain policy promotes an "optional" file to mandatory.)

### 3. The boot-builder `harness/registry_boot.py` (off-gate) — owns the `registration_trust_gate`

`build_and_populate_registry(*, settings, audit_store, decision_history_store, supply_chain, object_store) -> PluginRegistry`. **It constructs its own `registration_trust_gate`** (NOT a passed-in shared one — see §4 trapdoor):
```python
registration_settings = settings.model_copy(
    update={"signature_root_path": Path(settings.pack_attestation_root_path)})
registration_trust_gate = TrustGate(settings=registration_settings, ...)
```
so `verify_pack_signature` canonicalizes the resolver's `cosign.sig`+wheel under the *same* root the resolver used. It resolves `cosign_trust_root = Path(settings.trust_root_prefix) / "_default" / "cosign.pub"` (the LOCKED deployment convention this slice defines — no production helper exists; it formalizes the test-only file-layout precedent; **NOT `signing_trust_root_path`**) and **fail-closes if it is missing / not a file / empty** (raise → §5 503); it is under `trust_root_prefix` by construction. It loads the `_default` allow-list (fail-closed); fresh `PluginRegistry(audit_store=…)`; `discover()` → per pack: `resolve_pack_attestations(pack, pack_attestation_root=…, cosign_trust_root=…)` → `await registry.register_with_full_attestation_check(pack, attestations, trust_gate=registration_trust_gate, supply_chain=…, object_store=…, tenant_id="_default", tenant_allowlist=<frozenset>)`. **Per-pack fail-soft.** Returns the registry. `plugin.registration_*` chain rows are the boot evidence.

### 4. The shared-registry unification (lifespan, off-gate `app.py`) — two named `TrustGate`s

`registry = plugin_registry or build_and_populate_registry(...)`; thread the **single** `registry` into **both** `build_mcp_host(registry=…)` and `A2AEndpoint(plugin_registry=…)`; expose on **`app.state.plugin_registry`** (preseed `None`).

**TRAPDOOR (locked):** the boot's `registration_trust_gate` (`signature_root_path` = `pack_attestation_root_path`) and the endpoint's `a2a_trust_gate` (normal settings, for agent-card JWS under `trust_root_prefix`) are **named separately and never silently shared**. The boot-builder constructs its own; the injected/A2A `trust_gate` MUST NOT be reused for boot registration. (Agent-card JWS verification uses `trust_root_prefix`, not `signature_root_path`, so the two roles are genuinely distinct — HARNESS-VERIFY the A2A card path does not read `signature_root_path`.)

### 5. Failure-state (locked)

| Condition | Behaviour |
|---|---|
| `pack_attestation_root_path` **unset** | Boot builds a **shared but EMPTY** registry → both surfaces **reachable, resolve no packs**; log `pack_attestation_root_unconfigured` (WARN; **not 503**). |
| Per-pack **resolution failure** (`PackAttestationResolutionError`) or **registration exception** | Caught per-pack, skipped + logged → **partially** populated registry. |
| Per-pack **registration refusal** (allow-list / cosign / SBOM / SLSA / policy) | Stored as a refusal + logged; absent from the catalog. |
| **`_default` allow-list load failure** (missing/malformed) | Builder raises → `app.state.plugin_registry = None` + host/endpoint `None` → **both surfaces 503** + ERROR (broken config, distinct from benign unset-root). |
| **`_default` trust root** (`<trust_root_prefix>/_default/cosign.pub`) **missing / not-a-file / empty** | Builder raises → `app.state.plugin_registry = None` → **both surfaces 503** + ERROR (broken config; distinct from the benign unset-attestation-root). |
| **No SDK** | `app.state.plugin_registry` stays `None` → 503 on the SDK gate (unchanged). |

### 6. Honest scope (closeout language)

Registers **installed signed packs whose signed wheel + attestations the operator placed under `pack_attestation_root_path`**. A bare image, no installed packs, or no `pack_attestation_root_path` → empty catalog, **correctly**. Closeout updates both surfaces → **"populated when trusted signed pack wheels + attestations are present under `pack_attestation_root_path`; empty remains correct otherwise."**

## Testing

- **Resolver (on-gate, concrete negatives):** happy path (5 required incl. exactly-one wheel + optionals → `PackAttestations`, 64-hex digest, `cosign_blob_path` == the wheel) + each typed case: required missing, required empty, **zero wheels → `attestation_required_artefact_missing`**, **two wheels → `attestation_wheel_ambiguous`**, `../`-escape, `sbom_digest_unsourced`, `<unknown>`-distribution.
- **Settings:** `pack_attestation_root_path` default `None` + env override.
- **Boot-builder:** constructs `registration_trust_gate` with `signature_root_path == pack_attestation_root_path` (pinned); discover→resolve→full-register spied (`trust_gate is registration_trust_gate`, tenant_id `_default`, explicit frozenset); unset-root → empty + `pack_attestation_root_unconfigured`; per-pack failure → skip+partial; allow-list missing/malformed → raises.
- **Unification:** `app.state.plugin_registry` predeclared `None`; one registry = SAME object both surfaces receive; injected registry → no `discover()`; allow-list failure → `None` → both 503; unset-root → empty → both reachable. **The A2A `trust_gate` is NOT the boot `registration_trust_gate` (distinct objects — pinned).**

## CC / ADR / migration posture

- **CC 133 → 134** — `protocol/pack_attestation_resolver.py` on the gate (`_CRITICAL_FILES` + `_EXPECTED_ENTRY_COUNT` bump). `core/config.py` stop-rule (one nullable field; off the per-file gate, halt-before-commit scrutiny + settings tests). Boot-builder + lifespan off-gate; `plugin_registry.py` consumed, not modified. No migration.
- **ADR-002 amendment** (startup discovery/trust-registration + `pack_attestation_root_path` + the dual-`TrustGate` root split) + **ADR-016 cross-ref** (first production caller of the full attestation pipeline) + ADR-003 cross-ref + AS_BUILT milestone + closeout-language update.

## Harness-verify points (for the plan — don't guess)

- **LOCKED (not harness-verify):** `cosign_trust_root = Path(Settings.trust_root_prefix) / "_default" / "cosign.pub"` — this slice defines the convention (no production helper exists; it formalizes the test-only file-layout precedent); the boot fail-closes if it is missing / not-a-file / empty.
- `Settings.model_copy(update={"signature_root_path": …})` is the right override mechanism (pydantic v2; no re-validation surprise on the `Path` field).
- The A2A agent-card verification path does **not** read `signature_root_path` (confirms the dual-`TrustGate` roles are independent).
- The exact `PackAttestations` fields (`plugin_registry.py:462`) + full `register_with_full_attestation_check` deps (`require_full_grade`, `license_allowlist`, `vuln_thresholds`, `mcp_admission`) + `tenant_allowlist=None` semantics (VERIFY only); `protocol/mcp_manifest.py` path-containment helper (`:176-203`) to reuse; `SupplyChainPipeline(settings=…)` + the `object_store` adapter; the `build_mcp_host`/`A2AEndpoint` registry kwargs; the `DiscoveredPack`/`PluginRecord` constructor for the resolver fixture.
