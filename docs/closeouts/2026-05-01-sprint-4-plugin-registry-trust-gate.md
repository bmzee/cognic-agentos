# Sprint 4 — Plugin Registry + Trust Gate + Supply-Chain Attestations + Policy-Engine Seed — Closeout Note

**Date:** 2026-05-01
**Sprints closed:** 4 (plugin discovery, cosign trust gate, full Sprint-4 attestation pipeline per ADR-016, OPA Rego policy-engine seed per ADR-015, default policy bundles, ObjectStoreAdapter, registry integration, system/plugins endpoint, fixture pack, Dockerfile binary pinning, pack-author docs, critical-controls gate extension).
**State:** **READY-FOR-GATE** on `feat/sprint-4-plugin-registry-trust-gate`. No push, no PR, no merge until the human authorises per the AGENTS.md per-action rule.
**Pre-T16 tip:** `cc0dd26 chore(sprint-4): extend critical-controls gate to plugin/policy quartet (T15)`.
**Branch base:** `cc0cb57` on `main` — the chore(meta) short-circuit-Stop-hook merge head; the Sprint-4 plan-of-record had already merged at `a84ec85` (PR #12, after 3 doctrine-review rounds) and this branch roots at the subsequent main tip.
**17 commits total after T16 lands** atop the merged plan-of-record: T1, T1-followup (env-prefix re-align), T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16 closeout.

## What ships in `feat/sprint-4-plugin-registry-trust-gate` after Sprint 4

### Four new critical-controls modules

- **`src/cognic_agentos/protocol/plugin_registry.py`** — entry-point discovery + admission orchestrator. `PluginRegistry.discover()` walks the `cognic.tools` / `cognic.skills` / `cognic.agents` entry-point groups WITHOUT importing them (the §1 deferred-load invariant: T10 admission MUST NOT call `EntryPoint.load()`). `register_with_full_attestation_check(pack, artefacts, *, trust_gate, supply_chain, object_store, tenant_allowlist=None, license_allowlist=())` is the single integration method — it sequences the eight admission phases (allow-list → cosign → SBOM digest → SLSA → in-toto → vuln → license → Sigstore-bundle persist) and emits exactly one of the eight closed-enum `RefusalReason` values on any deny path. Allow-list keying is the **signed distribution name** (`record.distribution_name`), NOT the entry-point alias (`record.name`) — fixed in T10 R1 P2 after a reviewer flagged that the original `record.name` keying would let an entry-point alias bypass the cosign-signed identity. Per-file coverage: 100% line / 100% branch.
- **`src/cognic_agentos/protocol/trust_gate.py`** — cosign verification with the eight §2 secure-subprocess invariants: explicit `subprocess.run(argv, shell=False, …)` list-form (never a shell string); `COSIGN_BIN` resolved once via `shutil.which("cosign")` then frozen; per-tenant trust root canonicalised via `os.path.realpath()` and asserted to live under an operator-approved prefix (rejects path-traversal); pack identity / version / signature blob validated against strict regex before any argv composition; explicit minimal `env` dict (no `os.environ` passthrough); strict 30s timeout with SIGKILL on timeout (timeout itself is an audit event); exit-code semantics (R1 P1 — cosign verify-blob does NOT support `--output json`, that flag belongs to OCI `cosign verify`); exhaustive negative-path coverage proves no input vector can smuggle an extra arg or shell metacharacter. Per-file coverage: 100/100.
- **`src/cognic_agentos/protocol/supply_chain.py`** — Wave-1 attestation pipeline per ADR-016 with two-grade verification + Sigstore bundle persister. **Mandatory floor (registration refused if missing):** cosign signature (delegated to `trust_gate.py`), SBOM digest pinned to pack signature, Sigstore bundle persisted under `attestations/<pack_id>/<version>/bundle.sigstore` with 7-year retention metadata at the adapter level. **Grace-period tier (`attestation_grade: partial` if missing):** SLSA L3+ provenance with strict `predicateType` prefix matching (R4 P2 — `https://slsa.dev/provenance/` with trailing slash for path-boundary safety), in-toto layout step well-formed-ness check (R6 P2 — every step must be well-formed, not "at least one"), vulnerability scan (Grype/Trivy JSON consumed; CVSS parsed via `parse_constant` hook that rejects NaN/inf — R4 P2), license audit. SBOM read TOCTOU-safe via single-buffer read (R2 P2). Per-file coverage: 100/100.
- **`src/cognic_agentos/core/policy/engine.py`** — minimal OPA Rego decision engine seed per ADR-015. Sync `__init__` loads + sha256-pins the bundle on disk; async `OPAEngine.create()` factory is the production caller (emits `policy.bundle_loaded` into `decision_history` after successful construction). Async `evaluate(decision_point: str, input_doc: dict) -> Decision` shells out to the pinned OPA binary via secure subprocess (list-form argv, explicit timeout, exit-code semantics). `Decision` is a frozen-slotted dataclass with `decision_data` slot per Q8 lock. Fail-closed posture: every engine-error path (subprocess raise, timeout, JSON-decode failure, malformed Rego output) maps to a deny `Decision`, never to allow-by-default. Per-file coverage: 97.78/100.

### One additive primitive on the persistence layer

- **`src/cognic_agentos/db/adapters/local_object_store_adapter.py`** — production filesystem `ObjectStoreAdapter` per ADR-009. `put(bucket, key, body, *, retention_seconds=None)` writes atomically (temp-file → fsync → rename); `get(bucket, key)` returns the bytes verbatim; retention metadata is a sidecar JSON document the adapter consults on `delete()` to enforce the 7-year minimum from ADR-016. **Path traversal protected:** every (bucket, key) tuple resolved via `os.path.realpath()` and asserted to live under the configured root; rejects `..` segments + symlink escapes. **No silent fallback:** missing root → fail-fast at adapter construction with `ObjectStoreUnavailableError`; not initialised → `RetentionWindowActiveError` raised on premature deletion attempt within retention window. Used by T9 to persist Sigstore bundles + by Sprint 5+ for any other "must-retain-for-N-years" object stream.

### Two default policy bundles

- **`policies/_default/supply_chain.rego`** — Sprint-4 admission Rego. Default-deny posture; two allow paths (full-grade unconditional; partial-grade unless tenant requires `require_full = true`). Bundle file's content stability is pinned by `tests/unit/core/policy/test_engine.py::TestDefaultSupplyChainBundle::test_real_bundle_content_stability`.
- **`policies/_default/plugin_allowlist.json`** — default per-tenant allow-list. Wave-1 ships with `_default: ["cognic-test-pack"]` only — keyed off the **signed distribution identity**, NOT the entry-point alias (T12 R1 P2 — fixed after the reviewer flagged that the original alias-keying would refuse the fixture under the real default startup path despite the inline-override smoke passing).

### One operator-facing portal endpoint

- **`GET /api/v1/system/plugins`** — registered packs read-only view. Returns `{"packs": [...]}` where each entry is `{name, distribution_name, distribution_version, attestation_grade, signature_digest, sigstore_bundle_path}`. Dynamic read over registry outcomes — NOT a hard-coded plugin list. Lifespan-startup-aware: TestClient `__enter__()` is required to populate `app.state.plugin_registry` (the lifespan factory) — pinned in the test via the documented startup pattern.

### One installable test fixture pack with full attestation set

- **`tests/fixtures/cognic_test_pack/`** — installable Hatchling pack with `pyproject.toml` declaring `cognic.tools` entry point; distribution name (`cognic-test-pack`, kebab-case) deliberately differs from entry-point alias (`cognic_test_pack`, snake-case) so the T9 / T10 distribution-name-vs-alias divergence is exercised end-to-end. Ships seven attestation files: CycloneDX 1.5 SBOM, SLSA v1.0 in-toto Statement (level=3, populated configSource + builder.id), in-toto layout (well-formed `steps`), Grype-shape vuln scan (clean), MIT-only license audit, cosign signature placeholder, Sigstore bundle placeholder. The two opaque files ride the cosign-real integration path; unit tests use the shimmed-cosign pipeline.
- **`tests/fixtures/_signing_kit/build_test_attestations.sh`** — idempotent regen kit. Default mode validates fixture state (CI runs this); `--regenerate` mode signs an ephemeral keypair via real `cosign sign-blob` for the cosign-real arm.

### Dockerfile binary pinning (T13 + T13-followup)

- **`infra/agentos/Dockerfile`** — default-adapters builder gains pinned cosign + OPA binary fetches, sha256-verified at build time, then COPY'd into the runtime stage. Kernel image deliberately UNTOUCHED — kernel `runtime` factory (`create_app`) doesn't invoke trust gate or policy engine, so kernel ≤120 MiB budget is unaffected.
  - **cosign v3.0.6** — `c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74`
  - **OPA v1.16.1** — `dc00b1c32c52f1557f7f127940bc3f1de6c507fdfbe0446f19d3b19ca5786494`
  - Pin coverage triangulated: (1) Dockerfile `sha256sum -c` gates the build; (2) `tests/unit/protocol/test_dockerfile_binary_pins.py` asserts ARG defaults at unit-test time (catches drift on every push, not just on docker-build lanes); (3) CI step at `.github/workflows/python.yml` runs `cosign version` + `opa version` inside the built default-adapters image as the non-root cognic UID 10001 — proves PATH + executability for the user the trust gate + policy engine actually run as.
- **T13-followup — image budget revised from ≤220 → ≤370 MiB** (CI run `25222785857` against the original 220 MiB budget surfaced the gap; T13's plan estimate of "+16 MiB net after layer overlap" turned out to be wrong by ~150 MiB). Investigation (this branch, post-T16): `strip --strip-unneeded` fails with `Unable to recognise the format of the input file` on **both** cosign-linux-amd64 and opa_linux_amd64_static under alpine's binutils. Both ship as Go PIE binaries with embedded sections that alpine's binutils does not parse. Reaching for sstrip / llvm-strip / UPX would add a build-time toolchain dependency on the verifier binaries for a marginal win and risk supply-chain weirdness on bytes the trust gate is meant to verify; instead, both binaries land at upstream-shipped size and the budget absorbs the cost. Local measurement: **356 MiB**; CI measurement: **359 MiB**; budget set to **370 MiB** (measured + small buffer). Kernel ≤120 MiB budget unchanged. Documented in the Dockerfile header + BUILD_PLAN Sprint-4 deliverables.

### Pack-author documentation

- **`docs/HOW-TO-WRITE-A-PACK.md`** — pack-author entry point covering manifest shape (per ADR-002), AGNTCY/OASF identity matrix (Wave 1 mandatory vs deferred), Sprint-4 attestation requirements (mandatory floor + grace-period tier), Wave-1 escape-hatch recipes for the cosign / syft / grype generation that `agentos sign --bundle` (Sprint 7A) will eventually wrap, and a file table mapping each verifier in `src/cognic_agentos/protocol/` to its enforced contract. Names the cognic_test_pack fixture as the canonical worked example; explicitly walks through the kebab-case distribution-name vs snake-case entry-point-alias divergence to prevent the most common cause of confused `not_in_tenant_allowlist` refusals.

### Critical-controls coverage gate extension

- **`tools/check_critical_coverage.py`** — extended in T15 with the Sprint-4 plugin-trust / supply-chain / policy quartet (`plugin_registry`, `trust_gate`, `supply_chain`, `core/policy/engine`) at the same single strict floor (`0.95 line / 0.90 branch`) as the Sprint-2/2.5/3 modules. Gate now enforces **16 modules** (was 12 after Sprint 3); all PASS at current coverage. CI step at `.github/workflows/python.yml:74` already invokes the gate script — no workflow edit needed.

## CI / production-grade gates

| Gate | Workflow | Trigger | Behaviour |
|---|---|---|---|
| Lint + types + tests | `python.yml` → `lint + test` | push / PR | `ruff` + `ruff format --check` + `mypy` strict + `pytest -v` (unit) |
| Per-file critical-controls coverage gate | `python.yml` → `lint + test` | push / PR | `tools/check_critical_coverage.py` against `coverage.json` — fails CI if any of the **16** critical-controls modules drops below 95% line OR 90% branch (extended in T15 to add plugin_registry / trust_gate / supply_chain / core/policy/engine) |
| Image-size budget + boot smoke (kernel) | `python.yml` → `image size budget` | push / PR | unchanged — kernel still ≤120 MiB |
| Image-size budget + boot smoke (default-adapters) | `python.yml` → `image size budget` | push / PR | extended in T13 to additionally run `cosign version` + `opa version` inside the built image as cognic UID 10001 |
| Live Postgres integration | `python.yml` → `postgres integration` | push / PR | unchanged — Sprint-2.5 chain integration tests still gate |
| Live Oracle integration | `python.yml` → `oracle integration` | push / PR | unchanged |

## Doctrine adherence

- **AGENTS.md per-edit halt-before-commit on critical-controls modules.** Every commit that touched `protocol/plugin_registry.py`, `protocol/trust_gate.py`, `protocol/supply_chain.py`, or `core/policy/engine.py` paused for explicit user authorization. T6 (trust gate) went through 6 reviewer rounds (R1 P1 cosign --output json removal; R2 P2 SBOM TOCTOU; R3 P2 empty SLSA configSource / invalid predicateType; R4 P2 SLSA prefix path-boundary + CVSS NaN/inf; R5 P2 blank-field stripping; R6 P2 well-formed step requirement). T7 (supply chain) and T9 (Sigstore persister) folded reviewer findings inline. T10 R1 P2 surfaced three reviewer findings (allowlist used `record.name` not `record.distribution_name`; Sigstore bundle key mismatch; policy-engine exception path bypassed closed enum) — all closed before commit.
- **AGENTS.md `core/canonical.py` per-edit stop rule.** Not touched in Sprint 4.
- **Production-grade rule.** No mocks in runtime paths. The trust gate dispatches via real `subprocess.run` to the pinned cosign binary; the policy engine dispatches via real `subprocess.run` to the pinned OPA binary; only test paths use cosign-shim or OPA-shim helpers. The fixture-pack admission smoke uses an in-test MagicMock TrustGate so the fixture's bytes don't need a real signature, but the real cosign verifier ships in the built image and runs end-to-end on the env-gated `@pytest.mark.cosign_real` arm. The placeholder cosign.sig and bundle.sigstore in the fixture are explicitly non-cryptographic per their documented contract; the regen kit signs them with an ephemeral keypair when the cosign-real integration path runs.
- **Plugin discipline (ADR-001).** No agents, tools, skills, UI, or bank overlays added. All work sits under platform-primitive (`protocol/*`, `core/policy/*`, `db/adapters/*`, `portal/api/*` surfaces) layer. The fixture pack lives under `tests/fixtures/`, clearly separated from production code paths.
- **Per-action authorization rule.** All 17 commits (including this T16 closeout) sit on the feature branch with **no push, no PR, no merge** until the human authorises post-READY-FOR-GATE. Each task's commit was a discrete authorization (full-word `commit` after halt-before-commit summary).

## Test + coverage state

- **Tests:** Sprint 4 ready state is **1441 passed + 29 skipped = 1470 collected** locally (skips are env-gated PG/Oracle integration — unchanged from Sprint 3). The Sprint-3 merge baseline measured at the Sprint-4 branch base (`cc0cb57`) was **945 passed + 29 skipped = 974 collected**. **Delta: +496 passed / +496 collected** vs the Sprint-3 baseline. The actual ratio reflects the depth of plan-review-driven regression tests across T6/T7/T9/T10; see "Plan-review findings closed" below. Both metrics stated to avoid the passed-vs-collected ambiguity.
- **Coverage:** **96% global** with `db/migrations/env.py` excluded from rollup (alembic CLI subprocess; same exclusion as Sprint 2/3). Per-file gate now enforces 16 modules:
  - `core/audit.py` — 100/100
  - `core/canonical.py` — 95.7/94.4
  - `core/chain_verifier.py` — 97.9/95.5
  - `core/decision_history.py` — 100/100
  - `core/sla.py` — 100/100
  - `core/escalation.py` — 100/100
  - `core/guardrails.py` — 100/100
  - `llm/gateway.py` — 99.1/100
  - `llm/policy.py` — 100/100
  - `llm/preflight.py` — 100/100
  - `llm/ledger.py` — 100/100
  - `llm/concurrency.py` — 100/100
  - **`protocol/plugin_registry.py` — 100/100** *(new)*
  - **`protocol/trust_gate.py` — 100/100** *(new)*
  - **`protocol/supply_chain.py` — 100/100** *(new)*
  - **`core/policy/engine.py` — 97.78/100** *(new)*
- **Negative-path coverage highlights:** cosign secure-subprocess negative paths (8 invariants × multiple smuggling vectors); SBOM TOCTOU race closed by single-buffer read; SLSA `predicateType` prefix-with-trailing-slash path-boundary; CVSS NaN/inf rejection via `parse_constant` hook; in-toto every-step-well-formed (vs at-least-one); allow-list keyed on `distribution_name` not `record.name` (T10 R1 P2); Sigstore bundle persisted under `distribution_name` not `record.name` (T10 R1 P2); policy-engine exception path mapped to closed-enum `policy_denied_partial_grade` deny instead of bypassing enum (T10 R1 P2); deferred-load invariant pinned by MagicMock entry-point with `side_effect=AssertionError` on `.load()`; default-allowlist file content keyed off signed distribution identity (T12 R1 P2); ObjectStoreAdapter retention-window-active rejection of premature delete; ObjectStoreAdapter path-traversal rejection across symlink escapes; OPA engine fail-closed on subprocess timeout / JSON-decode / malformed Rego output / missing bundle.

## Plan-review findings closed

Sprint 4's plan-PR went through **3 reviewer rounds** before any code landed; **6 additional reviewer rounds during execution** surfaced findings that were folded inline before each commit. All findings produced regression tests pinning the fix:

- **Plan-PR rounds 1-3 (PR #12):** Round-1 closed three doctrine conflicts (BUILD_PLAN T15 vs ADR-009 dep packaging; Langfuse readiness contradicting BUILD_PLAN; MemoryAdapter scope creep into Sprint 11.5). Round-2 closed eight implementation traps (plan file untracked breaks preflight; Dockerfile missed `--extra adapters`; bundled adapters never auto-registered at runtime; loader must be kernel-resilient on missing optional deps; `memory_adapters.py` violated AGENTS.md test-fixture-placement rule; PostgresAdapter.run_migrations was a silent no-op; Qdrant filter accepted but ignored; Langfuse adapter claim too thin). Round-3 closed one P3 (plan setting names had to align with the COGNIC env prefix — landed as `f72f676 docs(sprint-4): align plan setting names with COGNIC env prefix`).
- **R1 reviewer P1 (T6 cosign --output json):** cosign verify-blob does NOT support `--output json` (that flag belongs to OCI `cosign verify`). Closed by removing the flag, switching to exit-code semantics, removing JSON parsing branches.
- **R2 reviewer P2 (T7 SBOM TOCTOU):** SBOM was opened twice (once for digest, once for content), creating a race where a concurrent writer could change bytes between reads. Closed by single-buffer read + sha256 over the same buffer.
- **R3 reviewer P2 (T7 SLSA empty configSource / invalid predicateType):** empty `invocation.configSource` was accepted; `predicateType` prefix match was substring-based (`https://slsa.dev/provenance/v1` would also match `https://slsa.dev/provenance/v1-malicious`). Closed by requiring non-empty configSource AND requiring `predicateType` to start with `https://slsa.dev/provenance/` (trailing slash forces path boundary).
- **R4 reviewer P2 (T7 CVSS NaN/inf + SLSA prefix):** CVSS values from upstream Grype JSON could be `NaN` or `inf`, which silently passed any `>= threshold` numeric check. Closed by parsing CVSS via `json.loads(parse_constant=...)` hook that rejects NaN / inf at parse time. SLSA prefix tightened in same patch.
- **R5 reviewer P2 (T7 blank-field stripping):** several attestation fields accepted whitespace-only strings as valid. Closed by stripping then asserting non-empty for all required fields.
- **R6 reviewer P2 (T7 every-step well-formed):** in-toto layout's `steps` accepted as long as at least one step was well-formed. Closed by requiring every step to be well-formed (so a single malicious well-formed step couldn't smuggle malformed siblings).
- **R1 reviewer P2 (T9 version regex too loose for object-key):** T6's argv-safe `_validate_version` accepted `.`, `..`, `+`, uppercase — these would alias the object-store path or fail in the adapter. Closed by adding `_validate_version_for_object_key` with regex `^[a-z0-9][a-z0-9._-]{0,63}$` plus explicit `.` / `..` rejection.
- **R1 reviewer P2 (T10, three findings):** P2-1 allow-list used `record.name` (entry-point alias) instead of `record.distribution_name` (signed identity); fixed. P2-2 Sigstore bundle persisted under `record.name` while `RegistrationOutcome.pack_id == record.distribution_name`; fixed. P2-3 policy engine `evaluate()` exceptions could bypass the closed-enum vocabulary; wrapped in `try/except Exception → fail-closed deny → policy_denied_partial_grade`.
- **R1 reviewer P2 (T12 default allow-list):** the default file at `policies/_default/plugin_allowlist.json` was keyed off entry-point alias (`cognic_test_pack`), but T10 R1 P2 had changed allow-list checks to `record.distribution_name`. Without this fix the fixture would be refused under real production startup despite the T12 inline-override smoke passing. Closed by updating the JSON file to `cognic-test-pack`, updating the `TestDefaultPluginAllowlist` assertion, and adding a regression that admits the fixture against the real default allow-list file (no inline override).

## ADR-016 / ADR-015 / ADR-002 Validation

**Sprint 4 implements the Wave-1 mandatory floor + grace-period tier of ADR-016, the policy-engine seed of ADR-015, and the trust-gate / per-tenant-allow-list / discovery sections of ADR-002 — NOT the full programs.** This section maps each concern to what Sprint 4 actually delivered vs what remains carryover.

| Concern | Sprint-4 status | Notes |
|---|---|---|
| **Pack discovery via Python entry points** (ADR-002) | **Delivered.** | `PluginRegistry.discover()` walks `cognic.tools` / `cognic.skills` / `cognic.agents`. The §1 deferred-load invariant is enforced (admission MUST NOT call `EntryPoint.load()`); first `load()` happens on explicit runtime `PluginRegistry.load(kind, name)` only. |
| **cosign signature verification** (ADR-002) | **Delivered.** | All 8 §2 secure-subprocess invariants pinned by negative-path tests. cosign binary pinned at v3.0.6 in the default-adapters image with sha256 verification. |
| **Per-tenant allow-list** (ADR-002) | **Delivered.** | Allow-list keyed off signed distribution identity (post-T10 R1 P2 fix). Default bundle ships in `policies/_default/plugin_allowlist.json`; production deployments overwrite or swap to a Vault-backed list at Sprint 10. |
| **Mandatory attestation floor** (ADR-016 Wave-1) | **Delivered.** | cosign + SBOM + Sigstore bundle. Missing any of these → registration refused regardless of tenant policy. |
| **Grace-period tier** (ADR-016 Wave-1) | **Delivered.** | SLSA L3+ + in-toto + vuln + license. Missing any of these → register with `attestation_grade: partial`; tenant can require `full` via Rego policy. |
| **Sigstore bundle 7-year retention** (ADR-016) | **Delivered.** | Persisted under `attestations/<distribution_name>/<version>/bundle.sigstore` with retention metadata; ObjectStoreAdapter rejects premature delete with `RetentionWindowActiveError`. |
| **Policy-engine seed** (ADR-015) | **Delivered.** | OPA Rego decision engine (`core/policy/engine.py`); fail-closed posture; bundle loaded once at startup with sha256 pinning; default `supply_chain.rego` published. |
| **Reproducibility manifest** (ADR-016) | **Delivered (informational only).** | `protocol/reproducibility.py` verifies the manifest's digest is signed but does NOT re-build the pack — rebuild is a Sprint 7B reviewer concern per the plan. |
| **`/system/plugins` operator endpoint** | **Delivered.** | Read-only view over registry outcomes. Lifespan-startup populates `app.state.plugin_registry`; TestClient `__enter__()` triggers the lifespan factory. |
| **Critical-controls coverage gate** | **Delivered.** | Gate grows from 12 → 16 modules at the same strict 95/90 floor. |
| **Hot-reload of policy bundles** | **Carryover (Sprint 13.5).** | Sprint 4 seed loads bundles at startup only; reload requires restart. ADR-015 explicitly defers hot-reload to Sprint 13.5. |
| **Full Rego decision-trail API** (`GET /api/v1/policy/decisions/{trace_id}`) | **Carryover (Sprint 13.5).** | Sprint 4 emits `policy.decision_evaluated` chain-linked audit events but does not expose the trail-query endpoint. |
| **Pack data-governance contract enforcement** (ADR-017) | **Carryover (Sprint 5+).** | The `[tool.cognic.data_governance]` block declared in pack manifests is documented in `HOW-TO-WRITE-A-PACK.md` but the runtime DLP enforcement substrate lands alongside MCP host (Sprint 5). |
| **`agentos sign --bundle` SDK** (ADR-016 §"Pack-side tooling") | **Carryover (Sprint 7A).** | T14 docs name the Wave-1 escape-hatch recipe (manual `cosign sign-blob` + `syft` + `grype`); Sprint 7A wraps this as a single command. |
| **`agentos verify <pack-path>` local check** (ADR-016) | **Carryover (Sprint 7A).** | Wave-1 fallback documented in T14: adapt `tests/unit/protocol/test_fixture_pack_admission.py` against your pack. |
| **Annual integrity sweep job** (ADR-016 §"Retention + offline re-verification") | **Carryover (Wave 2 — P3-G reviewer fix).** | Scheduled job that picks 1% of registered packs at random + re-verifies their persisted Sigstore bundles + alerts on bundle-verification failure. Requires Sprint 5+ scheduling primitive. |
| **Vuln-drift alerting** (ADR-016 §"Negative") | **Carryover (Wave 2 — P3-H reviewer fix).** | `pack.vuln_drift` audit event when a registered pack's deps gain a new CVE that exceeds tenant policy threshold post-registration. Consumes Sprint 4's persisted SBOM + the future scheduled scan substrate. |
| **MCP host (Streamable HTTP + STDIO threat model)** (ADR-002) | **Carryover (Sprint 5).** | Sprint 4 lands the *registration* gate; Sprint 5 lands the *invocation* path. |
| **A2A endpoint + AgentCard validation** (ADR-003) | **Carryover (Sprint 6).** | The `[tool.cognic.identity]` block's `agent_card_url` + `agent_card_jws_path` fields are accepted today; verification of the card itself lands Sprint 6. |
| **Reviewer evidence panel** (ADR-012 §pack lifecycle) | **Carryover (Sprint 7B).** | Attestation grade is exposed via `/system/plugins` for examiner replay; the full reviewer dashboard lands Sprint 7B. |

**The shorthand:** Sprint 4 ships **the admission gate the rest of the platform sits behind**. Banks deploying AgentOS post-Sprint-4 get fail-closed plugin discovery, cosign signature verification, the full Wave-1 attestation pipeline (cosign + SBOM + Sigstore mandatory; SLSA + in-toto + vuln + license grace-period), 7-year Sigstore bundle retention, an OPA Rego policy seed they can extend with their own bundles, and a `/system/plugins` endpoint operators can read in real-time. They do NOT yet get MCP / A2A invocation paths (Sprint 5/6), the `agentos sign --bundle` SDK (Sprint 7A), or the reviewer evidence dashboard (Sprint 7B).

## Doctrine amendments accepted in Sprint 4

- **AGENTS.md critical-controls list** already named `protocol/plugin_registry.py`, `protocol/trust_gate.py`, `protocol/supply_chain.py`, and `core/policy/engine.py` (per the Sprint-4 ADR-002 / ADR-015 / ADR-016 amendments). Sprint 4 T15 extends the per-file coverage gate with all four at the same strict floor — no AGENTS.md edit required (the gate config IS the enforcement of the doctrine).
- **`policies/_default/plugin_allowlist.json` keying** — pinned to signed distribution name (T12 R1 P2) with explicit assertion in `TestDefaultPluginAllowlist::test_default_tenant_present` that the entry-point alias would NOT match. Future operators editing this file get an immediate test failure if they regress to alias-keying.
- **BUILD_PLAN Sprint 4 deliverables list** — extended in T16 (this commit) to surface the LocalObjectStoreAdapter, the Dockerfile binary pins, the critical-controls gate extension, the fixture pack, and the pack-author docs as load-bearing artifacts. No scope change; clearer accounting.
- **Plan-of-record (`docs/superpowers/plans/2026-05-01-sprint-4-plugin-registry-trust-gate.md`)** — already absorbed all R1/R2 doctrine-review patches before any code landed; R3 setting-name alignment landed as `f72f676` and the rest of execution rode the merged plan.

## Carryover for Sprint 5 / 5-onwards

Stored in Sprint 4 / wired in later sprints:

- **Sprint 5 MCP host** — registers via the same `cognic.tools` entry-point group; `MCPHost.call_tool` wraps the registry's load path. The Sprint-4 deferred-load invariant is what makes the Sprint-5 MCP-server-spawn flow safe (no cross-tenant leakage at admission time).
- **Sprint 5 STDIO threat model** — manifest declares `[tool.cognic.mcp]` with `transport`, `auth`, `required_scopes`, etc.; T14 docs already point pack authors at the conformance matrix. STDIO refused at registration unless ADR-002 §"MCP STDIO threat model" four-gate criteria pass.
- **Sprint 6 A2A endpoint + AgentCard** — agent packs declare `agent_card_url` + `agent_card_jws_path` in `[tool.cognic.identity]` already; trust gate's per-tenant trust root verifies the JWS at registration once Sprint 6 wires the path.
- **Sprint 7A `agentos sign --bundle`** — wraps the manual cosign / syft / grype recipe documented in T14 §4.4 Wave-1 escape hatch. T16 fixture pack at `tests/fixtures/cognic_test_pack/` is the canonical reference output the SDK targets.
- **Sprint 7A `agentos verify`** — runs the same checks the trust gate runs at registration time, locally. Wave-1 fallback in T14 §5: adapt `tests/unit/protocol/test_fixture_pack_admission.py` against your pack.
- **Sprint 7B reviewer evidence dashboard** — consumes the `attestation_grade` + `signature_digest` + `sigstore_bundle_path` fields the `/system/plugins` endpoint exposes today.
- **Sprint 9.5 model registry per ADR-013** — first writer of `decision_history` rows for plugin-registration state-machine emissions backed by `model_id`. Sprint 4 emits `audit_event` rows (hash-chained) on every admission outcome but does NOT emit `decision_history` rows for plugin-registration; that requires the Sprint 9.5 lifecycle linkage.
- **Sprint 10 Vault-backed allow-list** — `policies/_default/plugin_allowlist.json` is the in-tree default; production deployments at Sprint 10 swap to a Vault-backed list per ADR-002 §Trust. The keying contract (signed distribution identity) is fixed; the storage layer is what changes.
- **Sprint 13.5 OPA-Rego full policy engine** — bundles for `packs.rego`, `models.rego`, `tools.rego`, `sandbox.rego`, `subagent.rego`, `lifecycle.rego`. Sprint 4 ships the `policies/_default/supply_chain.rego` seed only; the migration anchor is `core/policy/engine.OPAEngine` itself (no API change expected).
- **Wave 2 annual integrity sweep job** (P3-G reviewer fix) — picks 1% of registered packs at random + re-verifies their persisted Sigstore bundles + alerts on bundle-verification failure. Requires Sprint 5+ scheduling primitive.
- **Wave 2 vuln-drift alerting** (P3-H reviewer fix) — `pack.vuln_drift` audit event when a registered pack's deps gain a new CVE post-registration that exceeds tenant policy. Consumes Sprint 4's persisted SBOM + the future scheduled scan substrate.

## Out of Sprint 4 scope (deferred per plan)

- MCP host invocation path (Streamable HTTP transport, OAuth/PRM, STDIO threat model, manifest validation) — Sprint 5 per ADR-002.
- A2A endpoint + AgentCard JWS verification — Sprint 6 per ADR-003.
- `agentos sign --bundle` SDK — Sprint 7A per ADR-016.
- `agentos verify <pack-path>` local check — Sprint 7A per ADR-016.
- Reviewer evidence panel + lifecycle approval gates — Sprint 7B per ADR-012.
- Hot-reload of policy bundles + decision-trail API — Sprint 13.5 per ADR-015.
- Full Rego bundle library (packs/models/tools/sandbox/subagent/lifecycle) — Sprint 13.5.
- Pack data-governance runtime DLP enforcement — Sprint 5+ per ADR-017.
- Annual integrity sweep job + vuln-drift alerting — Wave 2.
- Push, PR, merge — per per-action rule. This closeout is the READY-FOR-GATE checkpoint.

## Next sprint

**Sprint 5 — MCP host (Streamable HTTP first; STDIO restricted; OAuth/PRM authorization)** ([BUILD_PLAN.md](../BUILD_PLAN.md) Sprint 5). Begins after Sprint 4 merges to `main`:

- `protocol/mcp_host.py` — Streamable HTTP transport (production default); per-tenant OAuth/PRM token cache + refresh; minimum-scope per manifest declaration.
- `protocol/mcp_authz.py` — token cache + refresh + AS allow-list per ADR-002 amendment.
- `protocol/mcp_stdio.py` — restricted STDIO transport; four-gate threat model enforced at registration; sandbox-required (Sprint 8 dependency).
- Manifest validation extended to enforce `[tool.cognic.mcp]` block per `docs/MCP-CONFORMANCE.md`.

Sprint 4 ships the admission gate the rest of the platform sits behind; Sprint 5 starts gating what tools registered packs can actually invoke.
