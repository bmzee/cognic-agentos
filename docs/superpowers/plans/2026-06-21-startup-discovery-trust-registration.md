# MCP/A2A Startup Discovery + Trust-Registration (single-tenant `_default`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Each **Sprint** is one cohesive, TDD, commit-gated unit (fresh subagent, controller two-stage review, per-sprint commit token). The subagent implements + tests but does **NOT** stage/commit; the controller commits on the user's token. **The resolver (Sprint 2) is a trust-input primitive: spec/contract review THEN security/negative-path review before commit. The user inspects diffs + runs fresh focused gates before each token.**

**Goal:** Populate one shared `PluginRegistry` at boot — running the full `register_with_full_attestation_check` supply-chain pipeline per installed pack whose attestations sit under a deployment `pack_attestation_root_path` — so both `build_mcp_host()` and `A2AEndpoint` resolve against a real catalog in a default (`_default`-tenant) deployment.

**Architecture:** Five sprints: (1) the `core/config.py` `pack_attestation_root_path` setting (stop-rule); (2) a NEW on-gate `PackAttestations` resolver (deployment-attestation-root resolution + path-containment + SLSA-sourced digest); (3) an off-gate boot-builder (discover → resolve → full-register, `_default` allow-list, per-pack fail-soft, unset-root → empty registry); (4) the shared-registry unification on `app.state.plugin_registry`; (5) closeout. CC **133 → 134** (the resolver). No migration.

**Tech Stack:** Python 3.12, `uv`, pytest-asyncio, strict mypy, ruff; `protocol/plugin_registry.py` (`discover()` + `register_with_full_attestation_check()` + `PackAttestations` `:462`), `protocol/supply_chain.py`, `protocol/trust_gate.py` (its `_canonicalise_under_root` `realpath`+`relative_to` containment logic is replicated by the resolver — AS-BUILT, see Sprint 2), `cli/verify.py` (the digest/trust-root sources, reference only).

**Whole-project gates every sprint:** `uv run pytest <touched> -q` ; `uv run ruff check <touched> && uv run ruff format --check <touched>` ; **`uv run mypy src tests`** (whole-project).

---

## File Structure

| File | On gate? | Responsibility | Sprint |
|---|---|---|---|
| `src/cognic_agentos/core/config.py` | no (but **stop-rule**) | add `pack_attestation_root_path: str | None = None` | 1 |
| `tests/unit/test_config.py` (or `core/`) | n/a | default + env-override settings tests | 1 |
| `src/cognic_agentos/protocol/pack_attestation_resolver.py` | **NEW — YES (95/90)** | `resolve_pack_attestations(...)` + `PackAttestationResolutionError` | 2 |
| `tests/unit/protocol/test_pack_attestation_resolver.py` | n/a | happy path + 7 concrete negative cases | 2 |
| `tools/check_critical_coverage.py` + `tests/unit/tools/test_check_critical_coverage.py` | n/a | `_CRITICAL_FILES` + `_EXPECTED_ENTRY_COUNT` 133→134 | 2 |
| `src/cognic_agentos/harness/registry_boot.py` | NEW — no (off-gate) | `build_and_populate_registry(...)` | 3 |
| `src/cognic_agentos/portal/api/app.py` | no | shared-registry unification + `app.state.plugin_registry` | 4 |
| `docs/adrs/ADR-002-*.md` / `ADR-016-*.md` / `AS_BUILT` | n/a | amendments + milestone | 5 |

---

## Sprint 1: the `pack_attestation_root_path` setting (`core/config.py` — stop-rule)

**Files:** Modify `src/cognic_agentos/core/config.py` ; Test `tests/unit/test_config.py`.

> **STOP-RULE:** `core/config.py` is a stop-rule module — additive only (one nullable field); do NOT touch any existing field. Halt-before-commit scrutiny.

- [ ] **Step 1: Write the failing settings tests.** In `tests/unit/test_config.py` (mirror the existing `Settings` field tests — HARNESS-VERIFY the `Settings` construction helper + the `COGNIC_` env-prefix convention):
```python
def test_pack_attestation_root_path_defaults_none() -> None:
    from cognic_agentos.core.config import Settings
    assert Settings().pack_attestation_root_path is None

def test_pack_attestation_root_path_env_override(monkeypatch) -> None:
    from cognic_agentos.core.config import Settings
    monkeypatch.setenv("COGNIC_PACK_ATTESTATION_ROOT_PATH", "/srv/attestations")
    assert Settings().pack_attestation_root_path == "/srv/attestations"
```
Run → FAIL (field absent).

- [ ] **Step 2: Add the field.** In `core/config.py`'s `Settings`, additive (mirror the existing `signing_trust_root_path: str | None` field's style/placement):
```python
    pack_attestation_root_path: str | None = None
    """Deployment root under which the operator places installed packs' signed
    attestations at <root>/<distribution_name>/<version>/<basename>. None = boot
    registration is skipped (empty shared registry); the runtime never fabricates
    attestations."""
```

- [ ] **Step 3: Run + whole-project gates.** `uv run pytest tests/unit/test_config.py -q` (PASS) ; ruff/format ; `uv run mypy src tests` (Success).

---

## Sprint 2: the `PackAttestations` resolver (NEW, on-gate trust-input primitive)

**Files:** Create `src/cognic_agentos/protocol/pack_attestation_resolver.py` ; Test `tests/unit/protocol/test_pack_attestation_resolver.py` ; Modify `tools/check_critical_coverage.py` + `tests/unit/tools/test_check_critical_coverage.py`.

**Contract (exact):** `resolve_pack_attestations(pack: DiscoveredPack, *, pack_attestation_root: Path, cosign_trust_root: Path) -> PackAttestations`. The required/optional table + the typed `PackAttestationResolutionError` reasons are §2 of the spec. The resolver reads NO settings (pure; the boot-builder passes both roots).

**HARNESS-VERIFY before writing:** the `DiscoveredPack` / `PluginRecord` constructor (`plugin_registry.py` — the fixture `_make_pack` below needs `record.distribution_name` / `record.distribution_version`); the exact `PackAttestations` field names (`:462`); the path-containment helper.

**AS-BUILT CORRECTION (Sprint 2 — landed):** the `protocol/mcp_manifest.py:176-203` containment-helper pointer was **WRONG** — those lines are `_validate_package_name` (a regex identifier guard), NOT a path-containment guard. The codebase's canonical containment helper is `protocol/trust_gate.py::_canonicalise_under_root` (`:219-245`, `os.path.realpath` + `Path.relative_to`), but it is module-private and carries a `PathTraversalError` (`TrustGateError`-subclass) taxonomy. The resolver therefore **replicates its EXACT `realpath`+`relative_to` logic** in a local `_require_under_root` (rather than importing the private symbol), so it stays a self-contained trust primitive and maps every escape onto its own closed-enum `attestation_path_escapes_root`. A `realpath`-following **symlink-escape** negative test pins this (distinct from the lexical `../` test).

- [ ] **Step 1: Write the failing tests (happy path + 7 concrete negatives).** In `tests/unit/protocol/test_pack_attestation_resolver.py`:
```python
import hashlib
import json
from pathlib import Path

import pytest

from cognic_agentos.protocol.pack_attestation_resolver import (
    PackAttestationResolutionError,
    resolve_pack_attestations,
)


def _make_pack(dist_name: str = "cognic-tool-x", version: str = "1.0.0"):
    # HARNESS-VERIFY the DiscoveredPack/PluginRecord constructor; this returns a
    # DiscoveredPack whose record.distribution_name/version are dist_name/version.
    ...


def _write_attestations(root: Path, *, dist: str = "cognic-tool-x", version: str = "1.0.0",
                        sbom_digest: str | None = None) -> Path:
    base = root / dist / version
    base.mkdir(parents=True)
    (base / "cosign.sig").write_text("sig")
    (base / "bundle.sigstore").write_text("{}")
    sbom = b'{"bomFormat":"CycloneDX"}'
    (base / "sbom.cdx.json").write_bytes(sbom)
    digest = sbom_digest if sbom_digest is not None else hashlib.sha256(sbom).hexdigest()
    (base / "slsa-provenance.intoto.json").write_text(json.dumps(
        {"predicate": {"buildDefinition": {"externalParameters": {"sbom_digest_sha256": digest}}}}))
    (base / "cognic_tool_x-1.0.0-py3-none-any.whl").write_text("wheel-bytes")  # the cosign blob
    return base


def test_happy_path_resolves_required_and_digest(tmp_path: Path) -> None:
    root = tmp_path / "attestations"
    _write_attestations(root)
    att = resolve_pack_attestations(_make_pack(), pack_attestation_root=root,
                                    cosign_trust_root=tmp_path / "trust-root")
    assert att.cosign_signature_path == root / "cognic-tool-x" / "1.0.0" / "cosign.sig"
    assert att.sbom_path.name == "sbom.cdx.json"
    assert att.sigstore_bundle_path.name == "bundle.sigstore"
    assert len(att.sbom_signed_digest) == 64
    assert att.cosign_trust_root == tmp_path / "trust-root"
    assert att.cosign_blob_path == root / "cognic-tool-x" / "1.0.0" / "cognic_tool_x-1.0.0-py3-none-any.whl"


def test_zero_wheels_fails_closed(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    next(base.glob("*.whl")).unlink()
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(_make_pack(), pack_attestation_root=tmp_path / "attestations",
                                  cosign_trust_root=tmp_path)
    assert ei.value.reason == "attestation_required_artefact_missing"


def test_multiple_wheels_fails_closed_ambiguous(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    (base / "cognic_tool_x-1.0.0-py3-none-any2.whl").write_text("wheel-2")
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(_make_pack(), pack_attestation_root=tmp_path / "attestations",
                                  cosign_trust_root=tmp_path)
    assert ei.value.reason == "attestation_wheel_ambiguous"


def test_missing_required_artefact_fails_closed(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    (base / "cosign.sig").unlink()
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(_make_pack(), pack_attestation_root=tmp_path / "attestations",
                                  cosign_trust_root=tmp_path)
    assert ei.value.reason == "attestation_required_artefact_missing"


def test_empty_required_artefact_fails_closed(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    (base / "cosign.sig").write_text("")
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(_make_pack(), pack_attestation_root=tmp_path / "attestations",
                                  cosign_trust_root=tmp_path)
    assert ei.value.reason == "attestation_required_artefact_empty"


def test_path_traversal_escapes_root_fails_closed(tmp_path: Path) -> None:
    _write_attestations(tmp_path / "attestations")
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(_make_pack(dist_name="../escape"),
                                  pack_attestation_root=tmp_path / "attestations",
                                  cosign_trust_root=tmp_path)
    assert ei.value.reason == "attestation_path_escapes_root"


def test_sbom_digest_unsourced_when_slsa_missing_field(tmp_path: Path) -> None:
    base = _write_attestations(tmp_path / "attestations")
    (base / "slsa-provenance.intoto.json").write_text(json.dumps({"predicate": {"buildDefinition": {}}}))
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(_make_pack(), pack_attestation_root=tmp_path / "attestations",
                                  cosign_trust_root=tmp_path)
    assert ei.value.reason == "sbom_digest_unsourced"


def test_distribution_unidentified_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(PackAttestationResolutionError) as ei:
        resolve_pack_attestations(_make_pack(dist_name="<unknown>"),
                                  pack_attestation_root=tmp_path / "attestations",
                                  cosign_trust_root=tmp_path)
    assert ei.value.reason == "attestation_distribution_unidentified"
```
Run → FAIL (module absent). (Fill `_make_pack` per the harness-verified `DiscoveredPack` constructor — it is the ONLY fixture detail, not a test-body placeholder.)

- [ ] **Step 2: Implement the resolver.** `PackAttestationResolutionError(Exception)` carrying a closed-enum **6-value** `reason: Literal["attestation_distribution_unidentified", "attestation_path_escapes_root", "attestation_required_artefact_missing", "attestation_required_artefact_empty", "attestation_wheel_ambiguous", "sbom_digest_unsourced"]`. `resolve_pack_attestations`: (a) refuse `record.distribution_name == "<unknown>"` → `attestation_distribution_unidentified`; (b) `base = pack_attestation_root / record.distribution_name / record.distribution_version`, resolve each path's real-path, assert canonical-under-`pack_attestation_root` via a local `_require_under_root` that replicates `trust_gate._canonicalise_under_root`'s `realpath`+`relative_to` logic (NOT `mcp_manifest` — see the AS-BUILT note above) → else `attestation_path_escapes_root`; (c) the **4 fixed-name** required basenames (`cosign.sig`, `bundle.sigstore`, `sbom.cdx.json`, `slsa-provenance.intoto.json`) must exist + be non-empty → `attestation_required_artefact_missing` / `…_empty`; (d) **the signed wheel** — `wheels = sorted(base.glob("*.whl"))`: `len == 0` → `attestation_required_artefact_missing`; `len > 1` → `attestation_wheel_ambiguous`; the single wheel must be non-empty (`…_empty`) and IS `cosign_blob_path`; (e) the 3 optional basenames → `Path` if present else `None`; (f) parse `slsa-provenance.intoto.json` → `predicate.buildDefinition.externalParameters.sbom_digest_sha256` (KeyError/JSONDecodeError/non-str → `sbom_digest_unsourced`); (g) return `PackAttestations(cosign_signature_path=<base/cosign.sig>, cosign_blob_path=<the one wheel>, cosign_trust_root=cosign_trust_root, sbom_path=…, sbom_signed_digest=…, sigstore_bundle_path=…, slsa_provenance_path=…, intoto_layout_path=…, vuln_scan_path=…, license_audit_path=…)`. NEVER `EntryPoint.load()`.

- [ ] **Step 3: Register on the CC gate (133→134).** Add `("src/cognic_agentos/protocol/pack_attestation_resolver.py", 0.95, 0.90)` to `_CRITICAL_FILES`; bump `_EXPECTED_ENTRY_COUNT` 133→134.

- [ ] **Step 4: Run + whole-project gates + fresh focused coverage.** `uv run pytest tests/unit/protocol/test_pack_attestation_resolver.py tests/unit/tools/test_check_critical_coverage.py -q` (PASS) ; ruff/format ; `uv run mypy src tests` (Success) ; `uv run pytest tests/unit/protocol/test_pack_attestation_resolver.py -q --cov=cognic_agentos.protocol.pack_attestation_resolver --cov-branch --cov-report=term-missing` → ≥95/90 (meet the floor IN this sprint).

---

## Sprint 3: the boot-builder `harness/registry_boot.py` (off-gate)

**Files:** Create `src/cognic_agentos/harness/registry_boot.py` ; Test `tests/unit/harness/test_registry_boot.py`.

**LOCKED (not harness-verify):** `cosign_trust_root = Path(settings.trust_root_prefix) / "_default" / "cosign.pub"` — the deployment convention this slice DEFINES (no production helper exists; this formalizes the test-only file-layout precedent). **HARNESS-VERIFY:** `Settings.model_copy(update={"signature_root_path": …})` (pydantic v2; no `Path`-field re-validation surprise); the `TrustGate(...)` ctor args beyond `settings`; the full `register_with_full_attestation_check` deps (`supply_chain`, `object_store`, `require_full_grade`, `license_allowlist`, `vuln_thresholds`, `mcp_admission`); the `_default` allow-list path (`policies/_default/plugin_allowlist.json` vs a loader); `SupplyChainPipeline(settings=...)`.

- [ ] **Step 1: Write the failing tests.** Over an in-memory `PluginRegistry`; stub `resolve_pack_attestations` + the trust pipeline:
```python
async def test_boot_discovers_resolves_full_registers(monkeypatch, ...) -> None:
    # settings.pack_attestation_root_path set; discover() -> 2 packs; resolve stubbed;
    # register_with_full_attestation_check spied: 2 calls, tenant_id="_default",
    # tenant_allowlist == frozenset({"cognic-test-pack"}) (NOT None), and the spied
    # trust_gate IS the boot-built registration_trust_gate.
async def test_registration_trust_gate_signature_root_is_attestation_root(...) -> None: ...
    # the boot-built registration_trust_gate's settings.signature_root_path == pack_attestation_root_path
    # (the model_copy override — pinned).
async def test_cosign_trust_root_is_default_cosign_pub_under_prefix(...) -> None: ...
    # the cosign_trust_root threaded into resolve/register ==
    # Path(settings.trust_root_prefix) / "_default" / "cosign.pub" (the LOCKED path — pinned exactly).
async def test_missing_default_trust_root_raises_fail_closed(...) -> None: ...
    # <trust_root_prefix>/_default/cosign.pub missing / not-a-file / empty -> builder RAISES
    # (→ §5 503), distinct from the benign unset-attestation-root empty-registry path.
async def test_unset_attestation_root_returns_empty_registry_logged(caplog, ...) -> None:
    # settings.pack_attestation_root_path is None -> empty registry, NO register call,
    # "pack_attestation_root_unconfigured" logged; returns a real (empty) PluginRegistry, not None.
async def test_allowlist_missing_or_malformed_raises(...) -> None: ...   # fail-closed, no tenant_allowlist=None
async def test_per_pack_resolution_failure_is_fail_soft(...) -> None: ... # one PackAttestationResolutionError -> skip, other registered
async def test_per_pack_registration_exception_is_fail_soft(...) -> None: ...
async def test_bare_no_packs_returns_empty_registry(...) -> None: ...
```
Run → FAIL.

- [ ] **Step 2: Implement `build_and_populate_registry`.** Signature `build_and_populate_registry(*, settings, audit_store, decision_history_store, supply_chain, object_store) -> PluginRegistry` — **NO `trust_gate` param; the boot owns the `registration_trust_gate`**. Read `root = settings.pack_attestation_root_path`; if `None` → log `pack_attestation_root_unconfigured` + return a fresh empty `PluginRegistry(audit_store=…)` (NO discovery loop). Else: `registration_settings = settings.model_copy(update={"signature_root_path": Path(root)})` → `registration_trust_gate = TrustGate(settings=registration_settings, ...)`; resolve `cosign_trust_root = Path(settings.trust_root_prefix) / "_default" / "cosign.pub"` (the LOCKED convention — **NOT `signing_trust_root_path`**) and **fail-close if it is missing / not a file / empty** (raise a boot-builder error → §5 both-503, distinct from the benign unset-root); it is under `trust_root_prefix` by construction (`verify_pack_signature` re-canonicalizes there as defence-in-depth); load the `_default` allow-list (fail-closed typed error on missing/malformed); fresh `PluginRegistry(audit_store=…)`; `for pack in registry.discover():` → `try: att = resolve_pack_attestations(pack, pack_attestation_root=Path(root), cosign_trust_root=cosign_trust_root); await registry.register_with_full_attestation_check(pack, att, trust_gate=registration_trust_gate, supply_chain=…, object_store=…, tenant_id="_default", tenant_allowlist=<frozenset>) except (PackAttestationResolutionError, Exception) as exc: log + skip`. Return the registry.

- [ ] **Step 3: Run + whole-project gates.** `uv run pytest tests/unit/harness/test_registry_boot.py -q` (PASS) ; ruff/format ; `uv run mypy src tests` (Success).

---

## Sprint 4: the shared-registry unification (lifespan, off-gate `app.py`)

**Files:** Modify `src/cognic_agentos/portal/api/app.py` (the `:646` MCP block + `:689` A2A block + the predeclare region) ; Test `tests/unit/portal/api/test_app_registry_unification.py`.

**HARNESS-VERIFY:** the `build_mcp_host(registry=…)` + `A2AEndpoint(plugin_registry=…)` kwargs; the lifespan `supply_chain`/`object_store` scope; that the A2A agent-card path does **NOT** read `signature_root_path` (so a distinct `a2a_trust_gate` ≠ `registration_trust_gate` is correct, per §4 trapdoor); the predeclare pattern.

- [ ] **Step 1: Write the failing tests.**
```python
def test_app_state_plugin_registry_predeclared_none() -> None:
    assert create_app().state.plugin_registry is None

async def test_one_registry_feeds_both_surfaces(...) -> None: ...     # same object to build_mcp_host + A2AEndpoint + app.state
async def test_injected_registry_skips_discovery(...) -> None: ...    # create_app(plugin_registry=...) -> build_and_populate_registry NOT called
async def test_unset_root_empty_registry_both_reachable(...) -> None: ... # empty registry, both reachable (NOT 503)
async def test_allowlist_failure_registry_none_both_503(...) -> None: ... # builder raises -> None -> both 503
async def test_a2a_trust_gate_is_not_the_boot_registration_trust_gate(...) -> None: ...
    # TRAPDOOR: the A2A endpoint's a2a_trust_gate is a DISTINCT object from the boot's
    # registration_trust_gate; the boot is never handed the a2a_trust_gate.
```
Run → FAIL.

- [ ] **Step 2: Implement the unification.** Predeclare `app.state.plugin_registry = None` (body). In the SDK-capable lifespan path, BEFORE the MCP + A2A blocks: build `supply_chain = SupplyChainPipeline(settings=settings)` + `object_store`; `registry = plugin_registry or await build_and_populate_registry(settings=settings, audit_store=…, decision_history_store=…, supply_chain=supply_chain, object_store=object_store)` inside the fail-soft try (allow-list-failure exception → `registry = None` + ERROR). **The boot builds its OWN `registration_trust_gate` internally — do NOT pass the `a2a_trust_gate` (the §4 trapdoor).** Set `app.state.plugin_registry = registry`. Replace `mcp_registry = plugin_registry or PluginRegistry(...)` (`:646`) + `a2a_registry = …` (`:689`) with the shared `registry`; if `registry is None`, skip both host/endpoint construction (→ both `None` → 503).

- [ ] **Step 3: Run + whole-project gates.** `uv run pytest tests/unit/portal/api/test_app_registry_unification.py tests/unit/portal/api/test_app_a2a_wiring.py -q` (PASS — no A2A-wiring regression) ; ruff/format ; `uv run mypy src tests` (Success).

---

## Sprint 5: closeout

- [ ] **Step 1: Integration/conformance proof.** A fixture attestation-root + an allow-listed trust-passing pack → boot populates the registry → `app.state.plugin_registry` non-empty → MCP `list_tools` + A2A routing resolve it. Env-gate if real cosign is needed (HARNESS-VERIFY the cosign-shim / `COGNIC_USE_LOCAL_FIXTURE_*` pattern in `protocol/trust_gate` tests).
- [ ] **Step 2: Full quality gate.** `uv run ruff check . && uv run ruff format --check .` ; `uv run mypy src tests` (Success).
- [ ] **Step 3: Full suite + CC gate.** `uv run pytest -q --cov=cognic_agentos --cov-branch --cov-report=json:coverage.json` ; `uv run python tools/check_critical_coverage.py` (PASS; resolver ≥95/90 on fresh data; **CC 134**).
- [ ] **Step 4: Docs.** ADR-002 amendment (startup discovery/trust-registration + `pack_attestation_root_path`) + ADR-016 cross-ref (first production caller of the full attestation pipeline) + ADR-003 cross-ref + AS_BUILT milestone + spec→LANDED + the both-surfaces closeout-language update.

---

## Self-Review (controller, before execution)

- **Spec coverage:** §1 setting → Sprint 1 ; §2 resolver → Sprint 2 ; §3 boot-builder → Sprint 3 ; §4 unification → Sprint 4 ; §5 failure-state → Sprints 3-4 ; §6 honest scope → Sprint 5 ; CC 134 → Sprint 2 + Sprint 5.
- **Type consistency:** `pack_attestation_root_path` / `resolve_pack_attestations` / `PackAttestationResolutionError.reason` (the **6-value** Literal) / `build_and_populate_registry` (no `trust_gate` param) / `registration_trust_gate` vs `a2a_trust_gate` / `app.state.plugin_registry` — identical across sprints.
- **Harness-verify (don't guess):** the `Settings` test helper + env prefix (S1); the `DiscoveredPack`/`PluginRecord` constructor + `PackAttestations` fields + the containment logic replicated from `trust_gate._canonicalise_under_root` (S2 — AS-BUILT: the `mcp_manifest:176-203` pointer was wrong; the wheel = `cosign_blob_path` is LOCKED, not a harness-verify); the `_default` trust-root path (`<trust_root_prefix>/_default/cosign.pub`) is **LOCKED, not a harness-verify** — harness-verify only the `model_copy` override + the `TrustGate` ctor args + the full register deps + the allow-list path + `SupplyChainPipeline` (S3); the registry kwargs + the A2A-card-does-not-read-`signature_root_path` confirmation (S4); the cosign-shim pattern (S5).
- **Trust-primitive discipline:** Sprint 2 gets the two-stage review (contract then security/negative-path) + the on-gate floor met IN-sprint; the user inspects diffs + runs fresh focused gates before each token. In the **trust-critical Sprint 2 resolver, every test BODY is concrete** — the sole `...` there is `_make_pack` (the harness-verified `DiscoveredPack` fixture constructor). The Sprint 3 boot-builder + Sprint 4 unification tests are **named skeletons** (glue, per the "tolerable for glue" framing) — flesh on request.
