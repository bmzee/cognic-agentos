# Sprint 7A — `agentos-sdk` + `agentos-cli` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cognic AgentOS ships a public Python SDK (`agentos-sdk`) + a `agentos-cli` command-line tool that any pack author can pip-install to scaffold, validate, test, sign, and verify Cognic-compatible plugin packs **without forking AgentOS**, per ADR-008 Phase A. The Wave-1 surface covers (a) SDK base classes for tools / skills / agents + a `ToolRegistry` Protocol + testing + ISO-42001 compliance helpers; (b) `agentos init-{tool,skill,agent}` scaffolders with starter templates; (c) `agentos validate` orchestrator that enforces the AGNTCY/OASF identity matrix + A2A conformance + MCP conformance + ADR-017 data-governance contract + ADR-014 risk-tier consistency + ADR-016 supply-chain attestations, with a severity-aware finding model (refusals fail CI; warnings render but exit 0); (d) `agentos test-harness` hybrid runner (real manifest parsing + dry-run dispatch through fixture adapters, no live transports); (e) `agentos sign-blob` (narrow cosign wrapper) AND `agentos sign --bundle` (full Wave-1 attestation generator: cosign + syft SBOM + grype vuln scan + license audit + SLSA provenance template + in-toto layout template + AgentCard JWS via joserfc); fail-loud closed-enum refusal if any external tool / signing key is missing; (f) `agentos verify <pack-path>` (offline trust gate per ADR-016 — mirrors the Sprint-4 runtime trust-gate verification path so authors catch tampered bundles before submission). Three minimal-but-valid reference packs ship under `examples/` to demonstrate the scaffold-validate-sign-verify green-path. Critical-controls gate grows from 28 → ≥34 modules.

**Architecture:** Two top-level packages added to `src/cognic_agentos/`: `sdk/` (public Python API; semver-stable surface; halts-before-commit on every base-class change) and `cli/` (Typer-based command app registered in `pyproject.toml` `project.scripts`). The `cli/validators/` sub-package decomposes `agentos validate` into one file per concern (identity / a2a / mcp / data_governance / risk_tier / supply_chain) so future sprints can extend without touching unrelated validators. **Six** modules on the critical-controls floor at the strict 95% line / 90% branch threshold: `cli/validate.py` (orchestrator), `cli/validators/identity.py` (AGNTCY/OASF Wave-1 — wire-protocol-public for cross-org agent discovery), `cli/validators/data_governance.py` (ADR-017 — runtime DLP enforcement depends on the contract), `cli/validators/supply_chain.py` (ADR-016 — feeds the runtime trust gate), `cli/sign.py` (full bundle generator — security-critical), `cli/verify.py` (offline trust gate per ADR-016 Sprint-7A mandate; mirrors the runtime trust-gate verification path; R2 P2 #5). Validator promotion rule: any validator that owns non-trivial allow/deny logic joins the gate; pure-delegation wrappers stay off (a2a.py / mcp.py / risk_tier.py evaluated at T7-T11 closeout based on actual implementation depth).

**Tech Stack:** Typer (CLI framework — modern, type-hint-driven, plays well with Pydantic; tested via `typer.testing.CliRunner`; pinned in **base** `[project].dependencies` per R1 P2 #1 — the `agentos` / `agentos-cli` console scripts are mandatory, so their imports must resolve from a plain `pip install -e .`); cosign + syft + grype + pip-licenses-or-cyclonedx-py (real bundle generation path — `agentos sign --bundle` orchestrates each external tool via real `asyncio.create_subprocess_exec`, fail-loud closed-enum refusal if any binary is missing); joserfc (already a Sprint-6 dep — drives AgentCard JWS signing in `sign --bundle` and verification in `verify`); jinja2 (template rendering for `init-*` scaffolders + the SLSA / in-toto provenance templates — pinned in **base** `[project].dependencies` per R1 P2 #1, NOT a transitive dep); tomllib (stdlib — manifest TOML parsing); pytest + CliRunner (test surface).

---

## Doctrine Decisions (locked before any code)

### Doctrine Decision A — CLI framework: Typer (with explicit pin)

**Decision:** `cli/__init__.py` builds the command app via `typer.Typer()`. All commands declared as type-hinted functions; nested commands via sub-apps (`init`, `validate`, `test-harness`, `sign`). Tests drive the app via `typer.testing.CliRunner` so we exercise the real entry-point function — not a unit-tested helper.

**Why Typer over Click / argparse:**
- Typer is built on Click, so the migration burden is low if we ever need to switch.
- Type-hint-driven argument parsing matches the rest of the codebase's Pydantic + mypy strict posture (the same type tells the CLI parser AND mypy what's expected).
- `CliRunner` is the canonical test surface for both Typer and Click; no bespoke harness needed.
- argparse would force us to write our own type-coercion + validation layer, duplicating Pydantic.

**Pin:** `typer >= 0.12, < 0.13` in `pyproject.toml` (the project already uses this idiom for SDK + adapter pins). Loose enough to absorb patch-level fixes; tight enough that a Typer 0.13 API shift trips the test suite at lock-bump time, not at first author-CLI invocation.

**Test posture:** Every CLI command has at least one `CliRunner`-driven arm exercising the success path + at least one arm exercising the most common failure mode (e.g., missing manifest, malformed TOML, validator failure). The reviewer-rounds expectation is to add per-failure-mode arms as production code surfaces new closed-enum exit reasons.

### Doctrine Decision B — Validator architecture: `cli/validators/` sub-package

**Decision:** `agentos validate` is implemented as `cli/validate.py` (the orchestrator) plus a `cli/validators/` sub-package with one file per concern: `identity.py`, `a2a.py`, `mcp.py`, `data_governance.py`, `risk_tier.py`, `supply_chain.py`. The orchestrator loads the manifest TOML once, then dispatches each parsed sub-block to its corresponding validator; each validator returns a `list[ValidatorFinding]` (R2 P2 #1 reviewer correction — earlier draft used a refusal-only `ValidatorOk()` / `ValidatorRefusal(...)` pair, which lost the warning channel introduced in R1 P2 #3). The orchestrator concatenates per-validator findings, renders all of them to stderr (refusals + warnings), and computes exit code via `any(f.affects_exit_code for f in findings)` so warning-severity findings do NOT cause exit 1. See the `ValidatorFinding` dataclass definition in T1.

**Why sub-package over single file:**
- Mirrors the Sprint-6 `protocol/a2a_*.py` shape — one concern per file, one closed-enum vocabulary per concern, one test file per concern.
- Per-concern test scoping: `test_validator_identity.py` only loads the identity manifest fixtures, not the full pack tree.
- Future sprints (data-governance hot-reload, risk-tier ML scoring) extend by adding files, not by growing a 2000-line monolith.
- Keeps the critical-controls promotion rule cleanly scoped — `cli/validators/identity.py` is on the gate; `cli/validators/a2a.py` may or may not be (depending on whether T8 wraps Sprint-6's `a2a_capability_negotiation.read_pack_capabilities` thinly or implements its own decision logic).

**Closed-enum vocabulary:** A single `ValidatorReason` Literal lives in `cli/__init__.py` (or `cli/_reasons.py` if it grows past ~25 values) and aggregates the per-concern reasons. Each per-concern validator can only emit reasons from its declared subset (enforced by a `_VALIDATOR_REASON_OWNERSHIP` Final dict that maps each reason to its owning validator file ONLY — severity is derived separately from `_WARNING_REASONS` per R3 P2 #2, NOT from this ownership map; drift-detector pins both axes independently).

### Doctrine Decision C — Test-harness scope: hybrid

**Decision:** `agentos test-harness <pack-path>` does:
1. Parse the pack's `cognic-pack-manifest.toml` via the same shared loader the validate command uses.
2. Walk the full validate pipeline (every validator runs; every refusal surfaces).
3. **Dry-run dispatch** against fixture adapters: load the pack's tool/skill/agent entry-points, instantiate them with `agentos_sdk.testing.fixture_settings()` (a real `Settings` instance pointed at `tmp_path`-rooted in-memory adapters), invoke each declared method with the pack-author-supplied fixture inputs (defaults provided for stubs), capture the response shape, validate it against the pack's declared output schema.
4. **No live transports**: HTTP clients are `httpx.MockTransport`; SecretAdapter returns a fixture keyring; AuditStore writes to an in-memory SQLAlchemy engine; LangfuseAdapter is a no-op stub. Pack code that tries to hit a real network surface fails the harness with a closed-enum `harness_unsupported_live_transport` refusal.
5. Emit a conformance report (TOML or JSON) covering: identity completeness, A2A/MCP declarations vs ran behavior, data-governance contract presence, risk-tier consistency, supply-chain attestation reachability, dispatch dry-run outcome.

**Why hybrid over mock-everything or real-AgentOS:**
- Mock-everything would let a pack pass harness checks while failing on first registry admission; we want the harness to surface the same refusals the runtime trust gate would.
- Real-AgentOS would require a live Vault, a live Postgres, a live MCP server — too heavy for `pip install agentos-cli && agentos test-harness`. The "fixture adapters with real lifespan" middle ground exercises the lifespan + adapter wiring without external dependencies.

**Out of scope for the harness:**
- Live MCP server / live A2A endpoint integration — that's the pre-go-live integration lane.
- Live cosign verification — `sign` command does that, not `test-harness`.
- Multi-pack interaction (sub-agent dispatch crossing pack boundaries) — Sprint 8 sub-agent primitive territory.

### Doctrine Decision D — Reference pack scope: minimal-but-valid, neutral names

**Decision:** Three reference packs ship under `examples/` (NOT `src/cognic_agentos/` — they are **not** plugins, they are templates pack authors copy):
- `examples/cognic-tool-example-minimal/` — a no-op MCP tool that returns `{"echo": <input>}`.
- `examples/cognic-skill-example-minimal/` — a no-op skill that composes the example tool deterministically.
- `examples/cognic-agent-example-minimal/` — a no-op A2A-speaking agent whose `handle()` returns a single Wave-1 text Part `{"text": "ok"}`.

Each pack ships with:
- A complete `cognic-pack-manifest.toml` carrying ALL Wave-1 mandatory blocks (`[tool.cognic.identity]`, `[tool.cognic.a2a]` (agent only) OR `[tool.cognic.mcp]` (tool/skill), `[tool.cognic.data_governance]`, `[tool.cognic.runtime]`, `[tool.cognic.supply_chain]`).
- A signed AgentCard JSON + detached JWS + public-key PEM (agent pack only).
- The seven Sprint-4 attestation files (sbom.cdx.json, slsa-provenance.intoto.json, intoto-layout.json, vuln-scan.json, license-audit.json, cosign.sig, bundle.sigstore).
- A `pyproject.toml` declaring the right entry-point group (`cognic.tools`, `cognic.skills`, or `cognic.agents`).
- A README pointing at `docs/HOW-TO-WRITE-A-PACK.md` for deeper context.

**Why minimal-but-valid + neutral names:**
- The packs exist to demonstrate the **full Wave-1 author lifecycle** green-path — scaffold → validate → harness → sign → verify (R10 P3 #3 reviewer correction — earlier draft said "scaffold → validate green-path"; R6 P2 #3 promoted T15 to the full-lifecycle gate so this doctrine line MUST match). NOT to ship Layer C agent behavior. Neutral names (`example-minimal` not `policyqa`) prevent reviewers / banks from mistaking them for production templates with domain-specific assumptions.
- Per AGENTS.md plugin discipline: agent / domain logic ships in `cognic-agent-<name>` repos, not here. Reference packs in this repo are inert examples for SDK/CLI demonstration.
- A future Sprint-7B (or a separate `cognic-pack-examples` repo) can grow these into demo-ready packs once the SDK stabilises.

### Doctrine Decision E — SDK halt-before-commit policy (broader than critical-controls)

**Decision:** Every commit that touches `src/cognic_agentos/sdk/__init__.py`, `sdk/tool.py`, `sdk/skill.py`, `sdk/agent.py`, `sdk/testing.py`, or `sdk/compliance.py` halts-before-commit even though these modules are NOT on the per-file critical-controls coverage floor. The SDK base classes form a public API contract that banks build packs against — once shipped, semver-stability matters more than coverage percentages. Halt rationale: a base-class signature change is wire-protocol-public for the bank's pack code; the test gate doesn't catch the API contract, only the user does at first compile error.

**Why broader than the critical-controls list:**
- Critical-controls modules are about **runtime security**: trust gate, JWS verifier, version negotiator, etc. Failure mode = "an attacker breaches the gate."
- SDK base classes are about **public API stability**: Tool / Skill / Agent / fixture surfaces. Failure mode = "every bank's pack code breaks after `pip install --upgrade agentos-sdk`."
- Both deserve halt-before-commit, but for different reasons. Lumping them under one umbrella loses the distinction; keeping the SDK halt as a separate doctrine clause flags it for reviewers as "API contract" not "security gate."

**How to apply:** Every PR touching a SDK base-class signature surfaces the change in the halt-before-commit summary; the diff includes the before/after signature so the reviewer evaluates compatibility before authorising the commit token. New methods (additive) are normally green; renames / removed methods / changed positional-arg orders trip a Plan-PR-style discussion before any code lands.

### Doctrine Decision F — `agentos sign --bundle` doctrine: full bundle generator, real signing or fail-loud

**Decision (R1 P2 #5 reviewer correction).** An earlier draft scoped
`cli/sign.py` to a thin cosign-blob wrapper over an existing wheel +
existing attestation files. That contradicts:
- **ADR-016**: Sprint-7A `agentos sign --bundle` produces the full
  attestation set (SBOM + provenance + vuln scan + license audit +
  Sigstore bundle).
- **Sprint-6 closeout hand-off checklist item 1**: "wraps the
  Wave-1 escape-hatch recipe (manual cosign + syft + grype + Agent
  Card JWS signing)".

The plan adopts the **expanded scope**: `agentos sign --bundle`
orchestrates the full Wave-1 recipe and produces the seven
attestation files the runtime trust gate verifies. The two
sub-commands:

- **`agentos sign-blob <wheel-path>`** — narrow cosign wrapper.
  Signs the supplied wheel + emits `.sig` + `.bundle`. Used when
  the bundle pieces already exist (CI re-sign of an unchanged
  wheel; key rotation).
- **`agentos sign --bundle <pack-path>`** — full orchestrator.
  Generates EVERY attestation file from scratch:
  1. SBOM via `syft <pack-path> -o cyclonedx-json` → `attestations/sbom.cdx.json`.
  2. Vuln scan via `grype <wheel> -o json` → `attestations/vuln-scan.json`.
  3. License audit via `pip-licenses --with-system --format=json` (or `cyclonedx-py`) → `attestations/license-audit.json`.
  4. SLSA provenance generation (Wave-1 simplified — emits a static `attestations/slsa-provenance.intoto.json` from a template that captures the cosign call's argv + the SBOM digest; full slsa-generator integration lands when GitHub Actions OIDC matures in a later sprint per ADR-016).
  5. in-toto layout — emits `attestations/intoto-layout.json` from a template that lists the artifact set + the signing identity.
  6. AgentCard JWS signing (agent packs only) — uses `joserfc` to produce a detached compact JWS over the AgentCard JSON; writes `agent_cards/<card-name>.jws`.
  7. Cosign sign-blob over the wheel — emits `attestations/cosign.sig` + `attestations/bundle.sigstore` via the same path `agentos sign-blob` uses.
  Each sub-step fails loud if its tool is missing; per-step closed-enum reason carries the missing-tool identity so CI parsers can match.

**Production behaviour (every external tool):**
- `shutil.which("<tool>")` resolves the binary; missing → closed-enum
  refusal naming the missing tool with a remediation pointer.
- All subprocess invocations use real `asyncio.create_subprocess_exec`
  (no `subprocess.run` mocking; tests use the Sprint-4 shim pattern).
- Signing key resolution from a `vault://` URI via `SecretAdapter`
  (production) or local file path (`--dev-mode-skip-cosign` flag).
- Non-zero exit on any sub-step failure; the closed-enum reason is
  the last word in the structured stderr line.

**Closed-enum sign reasons (T14 grows the literal):**

```python
# Added during T14 implementation:
"sign_cosign_not_installed",
"sign_syft_not_installed",         # NEW (R1 P2 #5)
"sign_grype_not_installed",        # NEW (R1 P2 #5)
"sign_license_auditor_not_installed",  # NEW (R1 P2 #5) — pip-licenses or cyclonedx-py
"sign_signing_key_unavailable",
"sign_subprocess_failed",          # generic catch — payload carries which tool
"sign_agent_card_jws_signing_failed",  # NEW (R1 P2 #5) — joserfc errors
"sign_provenance_template_render_failed",  # NEW (R1 P2 #5) — template render errors
"sign_intoto_layout_template_render_failed",  # NEW (R1 P2 #5)
```

**Test posture:**
- Per-tool shim arms (mirroring `_make_cosign_shim`) — one shim per external tool; controllable `argv` / `exit_code` / `stdout`. Real `asyncio.create_subprocess_exec` runs against each.
- One arm per missing-tool refusal (`shutil.which` returns None → closed-enum reason).
- One arm pins the signing-key-unavailable refusal.
- One arm pins the agent-pack JWS-signing path: uses `joserfc` + the **task-local test-only signing keypair** committed at `tests/fixtures/cli_sign_target_pack/attestations/test-signing/test_signing_key.{private,public}.pem` (R9 P2 #1 reviewer correction — earlier draft said "fixture RSA keypair generated at test-author time + discarded" which left T14 + T15 unable to deterministically verify the regenerated JWS; resolution is the explicit test-only keypair fixture pattern documented in T15's lifecycle note). Test sets `Settings.signing_key_path` to the fixture's private PEM and `Settings.signing_trust_root_path` to the public PEM via override; signs the agent card; verifies the resulting detached JWS against the public PEM (assert detached form per Sprint-6 doctrine).
- One arm pins the **full happy-path orchestration**: invoke against a **task-local fixture** at `tests/fixtures/cli_sign_target_pack/` (R6 P2 #2 reviewer correction — earlier draft pointed at `examples/cognic-agent-example-minimal/`, but that pack is created in T15 which runs AFTER T14; a task runner following the plan would hit a missing fixture). The task-local fixture is a minimal-but-valid synthetic pack synthesized at test-author time (mirrors the Sprint-6 fixture-pack JWS generation pattern, with the regeneration script preserved in T14's commit message footer). T15's reference packs under `examples/` are the **separate** end-to-end author-workflow surface; T14's task-local fixture is the unit-test-of-the-sign-pipeline surface. After invoking `agentos sign --bundle` against the task-local fixture clone in `tmp_path`: assert all 7 attestation files exist + are non-empty + match expected shapes.
- `--dev-mode-skip-cosign` is intentionally gated behind a flag that prints a security warning to stderr; the `prod` profile rejects the flag at startup (a separate `tests/architecture/test_cli_sign_no_dev_skip_in_prod.py` self-test pins this).

**Why fail-loud over silent skip on each tool:**
- Silent skip would let pack authors ship a wheel with `bundle.sigstore` referencing a non-existent SBOM, only failing at the runtime trust gate (Sprint 4) — far from the author's IDE.
- Fail-loud at the missing-tool detection keeps the failure local to the author's CI; the production trust gate stays the last line of defence, not the first detection point.

**Out-of-scope for T14 (Wave-1 simplifications):**
- Full slsa-generator integration with GitHub Actions OIDC (ADR-016 mandates SLSA L3+ for production; Wave-1 ships a template-based simplification that names the signing identity + the artifact digest, satisfying the manifest-shape requirement; full L3 integration lands when the GitHub Actions OIDC reusable workflow upstream matures).
- Hardware-token signing (HSM / YubiKey / TPM) — Wave-1 supports `vault://` keys; HSM-backed signing lands alongside the model-registry trust path per ADR-013.
- Multi-signature attestations (n-of-m signers) — single-signer Wave-1; multi-sig lands with ADR-014 4-eyes-on-pack-build in Sprint 13.5.

### Doctrine Decision G — Critical-controls gate floor + promotion rule

**Decision:** **Six** Sprint-7A modules join the critical-controls gate at the same strict 95/90 floor as Sprint-2/2.5/3/4/5/6 modules:
- `cli/validate.py` (orchestrator)
- `cli/validators/identity.py` (AGNTCY/OASF Wave-1)
- `cli/validators/data_governance.py` (ADR-017 contract)
- `cli/validators/supply_chain.py` (ADR-016 attestations)
- `cli/sign.py` (full bundle generator: cosign + syft + grype + license + AgentCard JWS)
- `cli/verify.py` (R2 P2 #5 — offline trust gate per ADR-016 Sprint-7A mandate; mirrors the Sprint-4 runtime trust-gate verification path)

Gate size: **28 → 34 modules** (was 33 in R0; R2 P2 #5 added `cli/verify.py`).

**Promotion rule (T7-T11 closeout decision):** any validator that ends up owning **non-trivial allow/deny logic** joins the gate. Pure-delegation wrappers stay off. Specifically:
- If `cli/validators/a2a.py` only calls `protocol.a2a_capability_negotiation.read_pack_capabilities` and surfaces its result, it's a wrapper → stays off the gate.
- If `cli/validators/a2a.py` adds AgentOS-specific build-time refusals on top of the runtime reader (e.g., refusing manifests that declare `streaming = true` without a corresponding `agent_card_url`), it's owning policy → joins the gate.
- Same rule applies to `mcp.py` and `risk_tier.py`.

The T7-T11 closeout commits explicitly state which validators join the gate and which stay off, with rationale. The T16 critical-controls gate-extension commit lands the final list; AGENTS.md amendment in T17 mirrors it.

**Out-of-scope from the gate (explicit non-promotions):**
- SDK base classes (`sdk/tool.py`, `sdk/skill.py`, `sdk/agent.py`) — public API stability concern, not security gate. Halt-before-commit per Doctrine Decision E covers the contract; coverage gate would be cargo-cult here.
- `cli/init.py` — scaffolding output is what matters, not the path. Tests assert the produced pack tree shape, not the scaffolder's internal helpers.
- `cli/test_harness.py` — authoring / dev-only command (R4 P3 #5 reviewer correction — earlier draft said "test-only path"; that mislabels a **public CLI surface** as disposable test infrastructure). The command IS public (`agentos test-harness <pack-path>` is part of the documented Wave-1 author workflow per HOW-TO-WRITE-A-PACK.md), but it stays off the critical-controls floor because: (a) every gate it surfaces is already enforced upstream by `agentos validate` (which IS on the floor); (b) it does NOT touch the runtime trust gate or wire-protocol surfaces — it's a fixture-driven dry-run runner, not a security-policy decision point; (c) if a future maintainer breaks the harness output format, pack authors notice immediately at their CI; the runtime trust gate is the load-bearing security backstop, not the harness. Coverage of the harness is exercised end-to-end by `tests/unit/cli/test_cli_test_harness.py` driving `agentos test-harness` against the **T13 task-local fixture** at `tests/fixtures/cli_harness_target_pack/` (R8 P3 #4 reviewer correction — earlier draft said "the example packs"; T13's task-local fixture and T15's `examples/` reference packs are separate surfaces per the R6 P2 #2 / R7 P2 #1 task-decoupling pattern). T15 separately exercises the harness against the committed `examples/` packs as part of the full-lifecycle gate.

---

## File Structure

**Created (~30 files):**

```
src/cognic_agentos/sdk/__init__.py                     — public Python API re-exports
src/cognic_agentos/sdk/tool.py                         — Tool base class for MCP tool implementations
src/cognic_agentos/sdk/skill.py                        — Skill composition helpers (no LLM)
src/cognic_agentos/sdk/agent.py                        — Agent base class for A2A handlers
src/cognic_agentos/sdk/registry.py                     — ToolRegistry Protocol (R3 P2 #4)
src/cognic_agentos/sdk/testing.py                      — pytest fixtures + assertions for pack tests
src/cognic_agentos/sdk/compliance.py                   — ISO 42001 control-declaration helpers
src/cognic_agentos/cli/__init__.py                     — Typer app + ValidatorReason + ValidatorFinding
src/cognic_agentos/cli/_governance_vocab.py            — DataClass / Purpose / RetentionPolicy literals (R1 P2 #4)
src/cognic_agentos/cli/init.py                         — `agentos init-{tool,skill,agent}` scaffolders
src/cognic_agentos/cli/templates/                      — Jinja2 starter templates
src/cognic_agentos/cli/templates/tool/                 — tool pack starter
src/cognic_agentos/cli/templates/skill/                — skill pack starter
src/cognic_agentos/cli/templates/agent/                — agent pack starter
src/cognic_agentos/cli/validate.py                     — orchestrator (CRITICAL CONTROLS)
src/cognic_agentos/cli/validators/__init__.py
src/cognic_agentos/cli/validators/identity.py          — AGNTCY/OASF Wave-1 (CRITICAL CONTROLS)
src/cognic_agentos/cli/validators/a2a.py               — A2A conformance declarations
src/cognic_agentos/cli/validators/mcp.py               — MCP conformance declarations
src/cognic_agentos/cli/validators/data_governance.py   — ADR-017 contract (CRITICAL CONTROLS)
src/cognic_agentos/cli/validators/risk_tier.py         — ADR-014 consistency
src/cognic_agentos/cli/validators/supply_chain.py      — ADR-016 (CRITICAL CONTROLS)
src/cognic_agentos/cli/test_harness.py                 — hybrid runner
src/cognic_agentos/cli/sign.py                         — sign-blob + sign --bundle full generator (CRITICAL CONTROLS)
src/cognic_agentos/cli/verify.py                       — agentos verify offline trust gate (CRITICAL CONTROLS, R2 P2 #5)
src/cognic_agentos/cli/sign_templates/                 — SLSA provenance + in-toto layout templates (Wave-1 simplification)
docs/HOW-TO-WRITE-A-PACK.md
docs/SDK-REFERENCE.md
docs/PACK-MANIFEST-SPEC.md
tests/fixtures/cli_harness_target_pack/                — T13 task-local fixture pack (R7 P2 #1 — same decoupling pattern as T14)
tests/fixtures/cli_sign_target_pack/                   — T14 task-local fixture pack (R6 P2 #2 — decoupled from T15 examples to avoid ordering blocker)
examples/cognic-tool-example-minimal/                  — T15 reference pack (full author-workflow demo)
examples/cognic-skill-example-minimal/                 — T15 reference pack
examples/cognic-agent-example-minimal/                 — T15 reference pack
```

**Modified (~9 files):**

```
.gitignore                                              — R10 P2 #1: narrow !-exceptions for the test-only signing keypairs T14 + T15 ship under attestations/test-signing/ (the global *.pem rule from line 68 already excludes these PEMs by default; without explicit exceptions, `git add` silently skips them and lifecycle tests can't deterministically verify, re-creating the Sprint-6-public-PEM `git check-ignore` blocker pattern)
pyproject.toml                                          — `agentos-cli` entry point under [project.scripts]; typer + jinja2 in base [project].dependencies (R1 P2 #1)
uv.lock
.env.example                                            — seven new CLI settings (R4 P3 #3 + R9 P2 #1): COGNIC_COSIGN_PATH / SYFT_PATH / GRYPE_PATH / LICENSE_AUDITOR_PATH / SIGNING_KEY_PATH / SIGNING_TRUST_ROOT_PATH / DEV_MODE_SKIP_COSIGN
src/cognic_agentos/core/config.py                      — CLI-side settings (cosign_path, syft_path, grype_path, license_auditor_path, signing_key_path, signing_trust_root_path, dev_mode_skip_cosign — seven new fields + prod-profile guard rejecting test-fixture-tree paths)
src/cognic_agentos/protocol/__init__.py                — re-export shared types if SDK consumers need them
tools/check_critical_coverage.py                       — extend gate 28 → 34+ (R2 P2 #5 added cli/verify.py)
AGENTS.md                                               — Sprint-7A critical-controls section (T17 closeout)
docs/BUILD_PLAN.md                                     — Sprint-7A status flip (T17 closeout)
```

**Test modules (~17 files):**

```
tests/unit/sdk/test_tool_base.py
tests/unit/sdk/test_skill_base.py
tests/unit/sdk/test_agent_base.py
tests/unit/sdk/test_agent_dispatches_through_endpoint.py  — R1 P2 #2 alignment test
tests/unit/sdk/test_registry_protocol.py               — R3 P2 #4 ToolRegistry Protocol smoke
tests/unit/sdk/test_testing_fixtures.py
tests/unit/sdk/test_compliance_helpers.py
tests/unit/cli/test_cli_smoke.py                       — R5 P3 #5 mandatory-console-script smoke (--help)
tests/unit/cli/test_cli_init.py                        — `agentos init-{tool,skill,agent}` produces valid scaffolds
tests/unit/cli/test_cli_validate.py                    — orchestrator dispatch + manifest TOML loading
tests/unit/cli/validators/test_validator_identity.py
tests/unit/cli/validators/test_validator_a2a.py
tests/unit/cli/validators/test_validator_mcp.py
tests/unit/cli/validators/test_validator_data_governance.py
tests/unit/cli/validators/test_data_governance_vocab_consolidation.py  — R1 P2 #4 migration guard
tests/unit/cli/validators/test_validator_risk_tier.py
tests/unit/cli/validators/test_validator_supply_chain.py
tests/unit/cli/test_cli_test_harness.py
tests/unit/cli/test_cli_sign.py                        — cosign-shim driven, mirrors test_trust_gate pattern
tests/unit/cli/test_cli_verify.py                      — verify offline trust gate (R2 P2 #5)
tests/architecture/test_cli_sign_no_dev_skip_in_prod.py — static-AST scan
tests/unit/cli/test_reference_packs_full_lifecycle_green.py  — R6 P2 #3 — all 3 examples pass scaffold-fixture-on-disk + validate + harness + sign + verify
```

---

## Task 1: Sprint-7A settings + closed-enum vocabulary scaffolding

**Files:**
- Modify: `src/cognic_agentos/core/config.py` — add `cosign_path: str | None`, `syft_path: str | None`, `grype_path: str | None`, `license_auditor_path: str | None`, `signing_key_path: str | None`, `signing_trust_root_path: str | None` (R9 P2 #1 — used by T15's verify lane to point at the committed test-only public PEM in unit-lane testing; in production this points at the per-tenant Vault trust-root path; field-shape lets both consumers share one settings axis), `dev_mode_skip_cosign: bool` (default False; `prod` profile enforces False), **plus a prod-profile guard** (R9 P2 #1): `prod` profile rejects any `signing_key_path` whose resolved absolute path lies under `examples/` or `tests/fixtures/` at startup → fail-fast with closed-enum settings-validation error `signing_key_path_under_test_fixture_tree_in_prod`. Mirrors `dev_mode_skip_cosign`'s prod-profile rejection.
- Modify: `.env.example` (R5 P3 #4 — was in top Modified inventory but missing here; R9 P2 #1 expanded count 6 → 7) — add the seven new `COGNIC_*` env-vars matching the Settings fields (`COSIGN_PATH` / `SYFT_PATH` / `GRYPE_PATH` / `LICENSE_AUDITOR_PATH` / `SIGNING_KEY_PATH` / `SIGNING_TRUST_ROOT_PATH` / `DEV_MODE_SKIP_COSIGN`) + ADR-008 / ADR-016 / Doctrine F comment block. Step 5 below is the explicit-path edit.
- Create: `src/cognic_agentos/cli/__init__.py` — Typer `app`, `ValidatorReason` Literal, `ValidatorFinding` dataclass (per R1 P2 #3 — severity-aware), `_VALIDATOR_REASON_OWNERSHIP` Final dict, `_WARNING_REASONS` Final frozenset (R3 P2 #2 — closed warning set; everything not in it is a refusal by definition), `severity_for(reason)` helper.
- Create: `src/cognic_agentos/cli/_governance_vocab.py` (R1 P2 #4) — `DataClass` / `Purpose` / `RetentionPolicy` Literals; build-time owner of the data-governance vocabulary; future runtime DLP module per ADR-017 MUST consolidate against this rather than duplicate.
- Modify: `tests/unit/test_config.py` — Sprint-7A settings count test + closed-enum vocabulary tests for `ValidatorReason` + **drift detector** for `_WARNING_REASONS` (R3 P2 #2): assert `_WARNING_REASONS ⊆ ValidatorReason` AND `set(get_args(ValidatorReason)) - _WARNING_REASONS == _EXPECTED_REFUSAL_REASONS` (an inline frozenset that pins the exhaustive split). Adding a new literal value without explicitly placing it in either set trips the drift-detector. + smoke test that `_governance_vocab` imports cleanly + each literal set is non-empty.

**Halt-before-commit:** No (settings + closed-enum scaffolding is mechanical).

**R1 P2 #3 reviewer correction — separate warning channel.** An earlier
draft mixed `identity_oasf_capability_set_missing_warning` into the
refusal vocabulary, but the orchestrator only aggregates refusals →
exit 1. A Wave-1 warning that should keep exit code 0 needs its own
channel. The plan adopts the **unified `ValidatorFinding(severity, reason)`
shape** (over a parallel `ValidatorWarningReason` literal) so the
orchestrator can render both in one stream while the exit-code
calculation looks at severity:

```python
# cli/__init__.py
@dataclass(frozen=True, slots=True)
class ValidatorFinding:
    severity: Literal["refusal", "warning"]
    reason: ValidatorReason
    message: str
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def affects_exit_code(self) -> bool:
        return self.severity == "refusal"
```

Orchestrator aggregates `list[ValidatorFinding]`; exit code is non-zero
iff `any(f.affects_exit_code for f in findings)`. Per-validator helpers
return a flat list of findings. The `_VALIDATOR_REASON_OWNERSHIP` Final
dict (R4 P2 #1 reviewer correction — earlier draft said this dict
also carried default severity, which would have re-introduced the
two-source severity model R3 P2 #2 fixed) maps each `ValidatorReason`
literal to its owning validator file ONLY. Severity is derived
**solely** from `_WARNING_REASONS` (the closed warning frozenset
declared earlier in this section); the `severity_for(reason)`
helper is the single source-of-truth. The drift-detector test
verifies this two-axis split (ownership × severity) without
collapsing them into one map.

`ValidatorReason` initial set (~25 values; grows during **T7-T14** per R6 P3 #5 — earlier draft said T7-T12. By the end of T14 the literal block holds (R7 P3 #4 reviewer correction — earlier wording said "7 sign-side reasons + 7 verify-side reasons" which conflated total vs newly-added; the literal block's actual final shape is): **9 sign-side reasons total** (the 3 baseline `sign_cosign_not_installed` / `sign_signing_key_unavailable` / `sign_subprocess_failed` from the original draft + 6 added when `sign --bundle` expanded per R2 P2 #5: `sign_syft_not_installed`, `sign_grype_not_installed`, `sign_license_auditor_not_installed`, `sign_agent_card_jws_signing_failed`, `sign_provenance_template_render_failed`, `sign_intoto_layout_template_render_failed`) + **7 verify-side reasons total** (all newly added by R2 P2 #5: `verify_cosign_signature_invalid`, `verify_sbom_digest_mismatch`, `verify_provenance_invalid`, `verify_intoto_layout_invalid`, `verify_attestation_path_unresolvable`, `verify_agent_card_jws_invalid`, `verify_trust_root_path_unresolvable`). Whenever the literal grows, both `_VALIDATOR_REASON_OWNERSHIP` and `_WARNING_REASONS` (or the `_EXPECTED_REFUSAL_REASONS` test-side complement) MUST be updated in the same commit, pinned by the drift detector):

```python
# T1 SEED literal — the shape that lands when T1's settings + closed-
# enum vocabulary scaffolding commit ships. This is NOT the T14-final
# state; the per-task list below shows growth points (T7 identity,
# T8 A2A, T9 MCP, T10 data governance, T11 risk tier, T12 supply
# chain, T14 sign + verify). R8 P3 #3 reviewer correction — earlier
# draft labelled this block "the literal block holds 9 sign-side
# reasons + 7 verify-side reasons" but the block itself only showed
# the original 3 sign reasons + 0 verify reasons, contradicting the
# inline note. The T14-final shape is now spelled out inline above
# (every sign-side and verify-side literal value listed by name);
# THIS code block is the T1-commit-time seed.
ValidatorReason = Literal[
    # Manifest shape (T6 orchestrator) — all refusals
    "manifest_not_found",
    "manifest_unparseable_toml",
    "manifest_missing_pack_id",
    "manifest_missing_required_block",
    # Identity (T7) — refusals
    "identity_agent_id_missing",
    "identity_display_name_missing",
    "identity_provider_organization_missing",
    "identity_provider_url_missing",
    "identity_agent_card_url_missing",
    "identity_agent_card_jws_path_missing",
    "identity_agent_card_jws_path_unresolvable",
    # Identity (T7) — warning (severity="warning"; exit 0)
    "identity_oasf_capability_set_missing",
    # A2A (T8) — refusals
    "a2a_wave2_feature_in_wave1_manifest",
    # MCP (T9) — refusals
    "mcp_wave2_feature_in_wave1_manifest",
    "mcp_caching_restricted_data_class",
    "mcp_elicitation_form_restricted_data_class",
    # Data governance (T10) — refusals
    "data_governance_contract_missing",
    "data_governance_contract_inconsistent_with_risk_tier",
    "data_governance_contract_inconsistent_with_mcp_caching",
    # Risk tier (T11) — refusals
    "risk_tier_inconsistent_with_data_classes",
    # Supply chain (T12) — refusals
    "supply_chain_attestation_path_missing",
    "supply_chain_attestation_path_unresolvable",
    # Sign (T14) — refusals (full bundle generator; see T14 for the
    # extended set covering syft / grype / license / AgentCard JWS)
    "sign_cosign_not_installed",
    "sign_signing_key_unavailable",
    "sign_subprocess_failed",
]

# R3 P2 #2 reviewer correction — severity is determined by a
# closed WARNING_REASONS frozenset, NOT a default-to-refusal dict
# (which would silently miscategorise any future warning-shaped
# reason added to the literal but forgotten in the table). Every
# ValidatorReason is EITHER in WARNING_REASONS or — by definition
# — a refusal. Drift detector pins the exhaustive split.
_WARNING_REASONS: Final[frozenset[ValidatorReason]] = frozenset({
    "identity_oasf_capability_set_missing",  # Wave-1 only; Wave-2 promotes to refusal
})

def severity_for(reason: ValidatorReason) -> Literal["refusal", "warning"]:
    return "warning" if reason in _WARNING_REASONS else "refusal"
```

**Test posture:** every per-validator test class adds:
- One arm per refusal reason: assert `Finding(severity="refusal", reason=<X>)` is in the orchestrator's findings + assert exit code is 1.
- One arm per warning reason: assert `Finding(severity="warning", reason=<X>)` is in the findings + assert exit code is 0.
- **Drift-detector arms** in `test_config.py` (R3 P2 #2):
  - Every value in `_WARNING_REASONS` MUST be a member of `ValidatorReason` (frozenset is a subset of the literal).
  - The complement set `set(get_args(ValidatorReason)) - _WARNING_REASONS` MUST be the **explicit refusal set** declared in the test (an inline `_EXPECTED_REFUSAL_REASONS` frozenset). Adding a new value to `ValidatorReason` without explicitly placing it in either `_WARNING_REASONS` (in production) or `_EXPECTED_REFUSAL_REASONS` (in test) trips the drift-detector. This is the closed-enum doctrine pattern from Sprint-5 / Sprint-6 (`SPRINT_5_REFUSAL_REASONS` / `_EXPECTED_VALIDATION_REASONS`); inheriting it here keeps the vocabulary surface auditable.

- [ ] **Step 1: Write the failing tests** (`tests/unit/test_config.py`):
  - `TestSprint7ASettings` class with arms for each new setting: presence + default + parse-from-env-var.
  - `TestSprint7AClosedEnumVocabulary` with literal-set drift detector for `ValidatorReason` + `_WARNING_REASONS` + `_VALIDATOR_REASON_OWNERSHIP` (per R3 P2 #2 + R4 P2 #1).
  - **R10 P2 #2 — prod-profile rejection regressions** for the R9 test-fixture-tree guard:
    - **Refusal arm** — `Settings(profile="prod", signing_key_path="/abs/path/to/examples/cognic-agent-example-minimal/attestations/test-signing/test_signing_key.private.pem")` raises `SettingsValidationError` with closed-enum reason `signing_key_path_under_test_fixture_tree_in_prod` at instantiation time. Pin the reason literal + the rejected-path payload field.
    - **Refusal arm** — same shape but path under `tests/fixtures/cli_sign_target_pack/...` → same closed-enum refusal.
    - **Allowed arm (non-prod)** — `Settings(profile="dev", signing_key_path="<examples-tree-path>")` succeeds without error; same for `profile="test"`. The guard is prod-profile-only by design (unit-lane testing under `dev`/`test` profile MUST be able to use the test-fixture keys, otherwise T14 + T15 lifecycle tests cannot run).
    - **Allowed arm (prod, real path)** — `Settings(profile="prod", signing_key_path="/etc/cognic/signing-keys/prod.pem")` (or any path NOT under `examples/` / `tests/fixtures/`) succeeds. Pin both prod-profile-allowed paths AND prod-profile-rejected paths so the guard is enforced at the path-shape boundary, not by accident.
    - **Drift detector** — assert `signing_key_path_under_test_fixture_tree_in_prod` is in the closed-enum settings-validation refusal vocabulary (whatever Final dict / Literal owns it; if a future settings refactor moves the reason elsewhere, this drift detector trips).
- [ ] **Step 2: Run; expect FAIL.**
- [ ] **Step 3: Implement Settings additions + ValidatorReason literal.**
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Update `.env.example`** (R4 P3 #3 was "three fields"; R9 P2 #1 expanded actual T1 settings count to **seven**) with the seven new fields (`COGNIC_COSIGN_PATH`, `COGNIC_SYFT_PATH`, `COGNIC_GRYPE_PATH`, `COGNIC_LICENSE_AUDITOR_PATH`, `COGNIC_SIGNING_KEY_PATH`, `COGNIC_SIGNING_TRUST_ROOT_PATH`, `COGNIC_DEV_MODE_SKIP_COSIGN`) + a comment block referencing ADR-008 + ADR-016 + the per-tool fail-loud doctrine from Doctrine Decision F + the R9 P2 #1 doctrine (test-only signing keys live under `examples/` / `tests/fixtures/` only; prod profile rejects those paths at startup).
- [ ] **Step 6: Commit.**

---

## Task 2: SDK base — `sdk/__init__.py` + `sdk/tool.py` + `sdk/skill.py` + `sdk/agent.py` + `sdk/registry.py`

**Files:**
- Create: `src/cognic_agentos/sdk/__init__.py` — public Python API re-exports (Tool, Skill, Agent, ToolRegistry + fixture helpers + compliance helpers).
- Create: `src/cognic_agentos/sdk/tool.py` — `Tool` base class for MCP tool implementations.
- Create: `src/cognic_agentos/sdk/skill.py` — `Skill` composition helpers (no LLM in skill code per ADR-001 three-pool rule).
- Create: `src/cognic_agentos/sdk/agent.py` — `Agent` base class for A2A handlers.
- Create: `src/cognic_agentos/sdk/registry.py` (R3 P2 #4) — `ToolRegistry` Protocol; the public type referenced by `Skill.execute(*, tools: ToolRegistry, ...)` and the `fixture_tool_registry()` helper. Without this file the prior draft left `ToolRegistry` as an unresolved symbol that test fixtures + Skill subclasses would invent ad hoc.

**Halt-before-commit:** Yes (Doctrine Decision E — SDK base classes are bank/pack-author public API contract).

The contract surface of each base class:

```python
# Tool — MCP tool implementation
#
# R2 P2 #4 reviewer correction: schema validation is enforced by the
# SDK base class via the **template method** pattern, NOT by trusting
# subclasses to remember to call validation themselves. The earlier
# draft made ``invoke()`` directly abstract while the docstring
# claimed the base would validate — leaving subclasses with no
# enforcement seam. The corrected shape: ``invoke()`` is a final
# public method on the base; subclasses override the abstract
# ``_invoke()`` for the actual work. The base wraps the call with
# pre-validation + post-validation so authors CANNOT skip them,
# even if they forget.
#
# R4 P2 #2 reviewer correction: the SDK base class deliberately does
# NOT emit audit events. Audit emission belongs to the runtime MCP
# host (Sprint 5 ``mcp_host._emit_call_evidence``) which has the
# AuditStore + DecisionHistoryStore + tenant context the bare Tool
# instance does not. Mixing audit emission into the SDK base would
# (a) require every pack-author test fixture to wire AuditStore,
# (b) drag the audit-chain hash discipline into a public API surface
# bank-pack authors can break, and (c) duplicate the host's
# emission on every invocation. The seam stays: SDK base validates
# input/output schemas; host emits audit. Earlier R2 prose claimed
# the base also "wraps with audit-emission" — that was incorrect
# and is removed.
class Tool(abc.ABC):
    """Base class for cognic.tools entry-point implementations.

    Subclass + register under the `cognic.tools` entry-point group
    in pyproject.toml. The SDK's testing fixtures + the runtime MCP
    host both consume this contract."""

    name: ClassVar[str]  # tool identifier; matches manifest [tool.cognic.identity].pack_id
    input_schema: ClassVar[dict[str, Any]]  # JSON-Schema for invoke kwargs
    output_schema: ClassVar[dict[str, Any]]  # JSON-Schema for the return shape

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """R3 P2 #1 reviewer correction — runtime enforcement of the
        validation seam. ``typing.final`` is mypy-only; Python
        runtime allows a subclass to override ``invoke`` despite the
        decorator. Without this guard, a pack author who shadows
        ``invoke`` (intentionally or by accident) bypasses the
        SDK's input/output schema validation — exactly the failure
        mode the template-method pattern is meant to prevent.

        R8 P2 #1 reviewer correction — earlier draft only inspected
        ``cls.__dict__``, which let a mixin placed before ``Tool`` in
        the MRO smuggle in an ``invoke`` override (e.g.
        ``class Bypass: async def invoke(...): ...; class Sub(Bypass, Tool): pass``).
        ``Sub.__dict__`` is empty so the simpler check passed; the
        subclass-side ``invoke`` resolution then routed to ``Bypass``,
        skipping the SDK's validation seam.

        Walk ``cls.__mro__`` and refuse any ancestor (other than
        ``Tool`` itself and ``object``) that defines ``invoke``
        directly in its ``__dict__``. Subclasses MUST override
        ``_invoke`` instead.
        """
        super().__init_subclass__(**kwargs)
        for ancestor in cls.__mro__:
            if ancestor is Tool or ancestor is object:
                continue
            if "invoke" in ancestor.__dict__:
                raise TypeError(
                    f"{cls.__qualname__} resolves Tool.invoke() to a non-base "
                    f"override defined in {ancestor.__qualname__} (in MRO before "
                    "Tool). The Tool template-method contract pins ``invoke`` as "
                    "final; the only allowed owner is the SDK's Tool base. "
                    "Either remove the override from "
                    f"{ancestor.__qualname__} or refactor it to override "
                    "_invoke instead so the SDK's input/output schema validation "
                    "seam cannot be bypassed via mixin smuggling."
                )

    @typing.final
    async def invoke(self, **kwargs: Any) -> dict[str, Any]:
        """Public entry point. Validates ``kwargs`` against
        ``input_schema`` BEFORE delegating to the subclass's
        ``_invoke``; validates the returned dict against
        ``output_schema`` AFTER. Subclasses MUST NOT override
        this method — the SDK pins it both via ``@typing.final``
        (mypy-side enforcement at lint time) AND via
        ``__init_subclass__`` above (runtime enforcement at
        class-creation time). Both layers together close the
        validation-seam-bypass attack surface.

        Raises ``ToolInputSchemaError`` if kwargs fail input
        validation; ``ToolOutputSchemaError`` if the subclass's
        return value fails output validation. Both subclass
        ``ToolError`` (which the runtime MCP host catches per
        ADR-002).
        """
        _validate_against_schema(kwargs, self.input_schema, kind="input")
        result = await self._invoke(**kwargs)
        _validate_against_schema(result, self.output_schema, kind="output")
        return result

    @abc.abstractmethod
    async def _invoke(self, **kwargs: Any) -> dict[str, Any]:
        """Subclass-specific behaviour. The base class has already
        validated ``kwargs`` against ``input_schema`` by the time
        this is called; the base will validate the return value
        against ``output_schema`` afterwards. Subclasses focus on
        the actual work, not the validation discipline."""

    # Plus: declared_data_classes() / declared_risk_tier() / declared_dlp_pre_hooks() etc. —
    # mirrors the manifest [tool.cognic.data_governance] + [tool.cognic.runtime] blocks
    # so authors don't have to keep two copies in sync. Validate command cross-checks.
```

```python
# ToolRegistry — public Protocol for runtime + fixture tool registries.
#
# R3 P2 #4 reviewer correction: ``Skill.execute(*, tools, ...)`` and
# ``fixture_tool_registry()`` both expose this type, but the prior
# draft left it undefined. Subclasses + fixtures would have invented
# it ad hoc, breaking type-checking discipline. Defining it as a
# PEP 544 Protocol lets the runtime registry (eventually owned by
# the MCP host or a future ``protocol/tool_registry.py``) AND the
# fixture registry conform structurally without an inheritance
# coupling.
class ToolRegistry(Protocol):
    """Runtime + fixture tool-registry contract."""

    def get(self, name: str) -> Tool:
        """Return the registered Tool by pack_id; raise KeyError
        if not registered (mirrors ``dict[str, Tool].__getitem__``
        for predictable error semantics)."""
        ...

    def list_tools(self) -> list[str]:
        """Return the pack_ids of every registered tool. Used by
        ``Skill.__init__(*, tools)`` (R5 P2 #3 — instantiation-time
        cross-check seam) to validate ``declared_tools`` against
        the supplied registry BEFORE any ``execute()`` call."""
        ...
```

```python
# Skill — composition helper, no LLM
#
# R5 P2 #3 reviewer correction: the prior draft said
# "ToolRegistry.list_tools() is used by Skill instantiation to
# cross-check declared_tools" but the shown API had no constructor
# accepting a registry — the registry only appeared as an
# execute(*, tools=...) kwarg, so the cross-check had nowhere to
# fire at instantiation time. Two valid resolutions: (a) bind the
# registry at __init__ so the cross-check fires before any
# execute() call; (b) move the check into the execute() wrapper
# (similar to the Tool template-method pattern) so each call
# validates fresh. We adopt **(a)** — the constructor binds the
# registry once; declared_tools cross-check fires at __init__;
# execute(**kwargs) becomes the abstract method (no tools= kwarg
# needed at the call site since the bound registry is on the
# instance). This matches how the runtime harness wires skills
# (a Skill is instantiated once per session against a Skill-
# specific tool subset, not per-call).
class Skill(abc.ABC):
    """Base class for cognic.skills entry-point implementations.

    Skills compose tools deterministically — NO LLM call in skill
    code. The SDK enforces this by checking the skill's declared
    tool list against AgentOS's per-tenant cloud-policy at admission
    time (Sprint 4 trust gate already in place; SDK side just
    surfaces the contract)."""

    name: ClassVar[str]
    declared_tools: ClassVar[tuple[str, ...]]  # tool pack_ids this skill composes

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """R6 P2 #1 reviewer correction — runtime enforcement of the
        ``__init__`` cross-check seam. The earlier R5 draft moved
        ``declared_tools`` validation into ``__init__``, but unlike
        the Tool ``invoke`` seam there was no guard against a
        subclass overriding ``__init__`` and skipping
        ``super().__init__()``. That bypass would skip the
        cross-check while the SDK contract still claimed the SDK
        enforced it before any ``execute()`` call.

        R8 P2 #1 reviewer correction — same MRO-bypass concern as
        ``Tool.__init_subclass__``. Walk ``cls.__mro__`` and refuse
        any ancestor (other than ``Skill`` itself and ``object``)
        that defines ``__init__`` directly. Subclasses that need
        pack-specific construction logic override ``setup()``
        instead — the base's ``__init__`` calls ``setup()`` AFTER
        the cross-check, so subclass-side state lands without
        bypassing the registry guard.
        """
        super().__init_subclass__(**kwargs)
        for ancestor in cls.__mro__:
            if ancestor is Skill or ancestor is object:
                continue
            if "__init__" in ancestor.__dict__:
                raise TypeError(
                    f"{cls.__qualname__} resolves Skill.__init__() to a non-base "
                    f"override defined in {ancestor.__qualname__} (in MRO before "
                    "Skill). The Skill template-method contract pins ``__init__`` "
                    "as final; the only allowed owner is the SDK's Skill base. "
                    "Override Skill.setup() instead so the SDK's declared_tools "
                    "cross-check seam cannot be bypassed via mixin smuggling."
                )

    @typing.final
    def __init__(self, *, tools: ToolRegistry) -> None:
        """Bind a tool registry at instantiation; cross-check
        ``declared_tools`` against ``tools.list_tools()`` BEFORE
        any ``execute()`` call. Subclasses MUST NOT override this
        method — pinned both via ``@typing.final`` (mypy-side
        enforcement at lint time) AND via ``__init_subclass__``
        above (runtime enforcement at class-creation time). For
        pack-specific construction logic, override ``setup()``
        instead.

        Raises ``SkillUnregisteredToolError`` (subclass of
        ``SkillError``) if any name in ``declared_tools`` is missing
        from the registry. Pinned by the T2 Step-1 instantiation-time
        regression in test_skill_base.py.
        """
        registered = set(tools.list_tools())
        missing = [name for name in self.declared_tools if name not in registered]
        if missing:
            raise SkillUnregisteredToolError(
                f"{type(self).__qualname__} declares tools {missing!r} "
                f"that are not in the supplied ToolRegistry. Either "
                f"register the missing tools before instantiating the "
                f"skill, or remove them from declared_tools."
            )
        self._tools = tools
        self.setup()

    def setup(self) -> None:
        """Subclass hook for pack-specific construction logic.
        Called by the base ``__init__`` AFTER the registry
        cross-check has passed. Default is a no-op; subclasses
        override as needed.

        ``self._tools`` is bound by the time this is called, so
        subclass setup logic can reference it (e.g., to pre-resolve
        a Tool instance and cache it on ``self``)."""
        pass

    @abc.abstractmethod
    async def execute(self, **kwargs: Any) -> dict[str, Any]:
        """Skill-specific composition. ``self._tools`` (bound at
        ``__init__`` time per R5 P2 #3) is the runtime registry the
        skill calls into; the SDK's testing fixtures provide a
        fixture-only registry that mirrors the production shape.
        R6 P2 #1 doctrine: this docstring previously said ``tools``
        was a kwarg; the registry now lives on the instance after
        the constructor's cross-check. Subclasses use
        ``self._tools.get(<pack_id>)`` to resolve a Tool, then
        ``await tool.invoke(**...)`` to call it."""
```

```python
# Agent — A2A handler base
#
# R1 P2 #2 reviewer correction: the SDK base class signature MUST
# match what the shipped Sprint-6 ``A2AEndpoint`` actually invokes
# at dispatch time (see protocol/a2a_endpoint.py:568 — the dispatch
# is ``await agent.handle(payload, task=task)``: ``payload: bytes``
# positional, ``task: TaskRecord`` keyword-only). An earlier draft
# of this plan used ``handle(*, message, context)`` which would
# have produced an SDK base whose subclasses fail at first runtime
# dispatch with ``TypeError: handle() got unexpected keyword
# argument 'message'``. The SDK and the runtime endpoint share ONE
# contract — pinned by an alignment test (below) that wires a
# subclass through a real ``A2AEndpoint.handle`` invocation.
from cognic_agentos.protocol.a2a_endpoint import TaskRecord

class Agent(abc.ABC):
    """Base class for cognic.agents entry-point implementations.

    Subclass receives Wave-1 A2A task envelopes via ``handle()``;
    the SDK and the runtime ``A2AEndpoint`` share the contract."""

    name: ClassVar[str]
    declared_capabilities: ClassVar[A2ACapabilities]  # mirrors manifest [tool.cognic.a2a]

    @abc.abstractmethod
    async def handle(
        self,
        payload: bytes,
        *,
        task: TaskRecord,
    ) -> dict[str, Any]:
        """Agent-specific behaviour. ``payload`` is the raw inbound
        JSON-RPC 2.0 envelope bytes (already authn-validated +
        Wave-2-feature-refusal-checked + version-negotiated by the
        endpoint's gates 1-3 before dispatch reaches here).
        ``task`` is the :class:`TaskRecord` minted at the endpoint's
        gate 5; subclasses read ``task.task_id`` /
        ``task.tenant_id`` / ``task.parent_trace_id`` /
        ``task.child_trace_id`` for cross-agent chain linkage. The
        agent's response is wrapped by the endpoint's lifecycle
        machinery into a ``StreamResponse`` envelope; agent code
        returns a Wave-1 dict per A2A 1.0 spec.

        The sub-agent dispatcher (Sprint 8 per ADR-005) is NOT a
        kwarg here — when Sprint 8 lands, sub-agent dispatch is
        accessed via a context-var pattern that the harness sets
        up before calling ``handle``, NOT by extending this
        signature (which would break every shipped pack)."""
```

**Alignment test** (load-bearing per the SDK halt-before-commit
doctrine). New file `tests/unit/sdk/test_agent_dispatches_through_endpoint.py`:

```python
"""Pin the SDK ``Agent.handle`` signature against the shipped
``A2AEndpoint`` dispatch contract. If the runtime endpoint's
dispatch shape changes (or the SDK base signature drifts), this
test trips before pack code does."""

class _StubAgent(Agent):
    name = "stub"
    declared_capabilities = ...  # Wave-1 minimal
    captured: list[tuple[bytes, TaskRecord]] = []

    async def handle(self, payload: bytes, *, task: TaskRecord) -> dict[str, Any]:
        self.captured.append((payload, task))
        return {"echo": "ok"}

async def test_sdk_agent_dispatches_through_real_a2a_endpoint(...):
    # Wire the stub through a real A2AEndpoint with mocked authz +
    # registry that returns the stub. Drive endpoint.handle with a
    # minimal valid Wave-1 task envelope. Assert: stub.captured has
    # one (payload_bytes, TaskRecord) entry; payload bytes match
    # the inbound envelope; TaskRecord carries task_id / tenant_id
    # / parent_trace_id / child_trace_id; endpoint returned the
    # stub's ``{"echo": "ok"}`` verbatim.
```

- [ ] **Step 1: Write failing tests** across **four** files (R2 P2 #3 reviewer correction added the alignment test + replaced the stale "context shape" arm):
  - `tests/unit/sdk/test_tool_base.py` — (a) abstract method enforcement on `_invoke`; (b) ClassVar declaration; (c) the public `invoke()` wrapper validates kwargs against `input_schema` BEFORE delegating to `_invoke`; (d) the public `invoke()` wrapper validates the returned dict against `output_schema` AFTER `_invoke` returns; (e) schema-validation-failure exception types are deterministic; (f) **runtime override-rejection** (R3 P2 #1) — defining a subclass with its own `invoke` method raises `TypeError` at class-creation time via `__init_subclass__`; defining a subclass that only overrides `_invoke` succeeds. Pin the exact error message so a future refactor that removes the guard trips this test; (g) **mixin-bypass rejection** (R8 P2 #1) — defining a class hierarchy `class Bypass: async def invoke(...): ...; class Sub(Bypass, Tool): pass` raises `TypeError` at `Sub`'s class-creation time (the MRO walk finds `Bypass.invoke`); pin the error message includes the offending mixin's `__qualname__`. Multi-level inheritance arm: `class Mid(Tool): async def _invoke(...): ...; class Bypass: async def invoke(...): ...; class Sub(Bypass, Mid): pass` ALSO raises (the walk inspects every MRO ancestor, not just `cls.__bases__`).
  - `tests/unit/sdk/test_skill_base.py` — abstract method enforcement on `execute`; ClassVar declaration; **`declared_tools` instantiation-time cross-check** (R5 P2 #3): `Skill(tools=fixture_registry_missing_a_declared_tool)` raises `SkillUnregisteredToolError` BEFORE any `execute()` call; `Skill(tools=fixture_registry_with_all_declared_tools)` succeeds; `execute()` calls have access to `self._tools` after instantiation. Pin the exact error message + the subclass-of-SkillError invariant. **`__init__` runtime override-rejection** (R6 P2 #1): defining a subclass with its own `__init__` raises `TypeError` at class-creation time via `__init_subclass__`; defining a subclass that only overrides `setup()` succeeds, AND `setup()` runs AFTER the registry cross-check (subclass setup logic can reference `self._tools`). Pin the exact error message so a future refactor that removes the `__init_subclass__` guard trips this test. **Mixin-bypass rejection** (R8 P2 #1): same MRO-bypass arms as Tool's — `class Bypass: def __init__(...): ...; class Sub(Bypass, Skill): pass` raises at `Sub`'s class-creation time; multi-level inheritance arm pins the full MRO walk.
  - `tests/unit/sdk/test_agent_base.py` — abstract method enforcement on `handle`; ClassVar declaration; the `handle(payload, *, task)` signature matches the shipped runtime endpoint contract (positional `payload: bytes`, keyword-only `task: TaskRecord`).
  - `tests/unit/sdk/test_agent_dispatches_through_endpoint.py` (R1 P2 #2 + R2 P2 #3) — load-bearing alignment test: wires a stub agent through a **real** `A2AEndpoint.handle` invocation with mocked authz / registry / audit / decision-history; asserts the endpoint dispatches `(payload_bytes, task=TaskRecord)` to `Agent.handle`; asserts `task.task_id` / `tenant_id` / `parent_trace_id` / `child_trace_id` are populated; asserts the endpoint returns the agent's response verbatim. If the runtime endpoint's dispatch shape changes (or the SDK base signature drifts), this test trips before pack code does.
- [ ] **Step 2: Run; expect FAIL** (no SDK module exists).
- [ ] **Step 3: Implement Tool / Skill / Agent base classes.**
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Halt-before-commit summary** — surface every base-class method signature in the diff for reviewer evaluation; per Doctrine Decision E.
- [ ] **Step 6: Commit on full-word authorization.**

---

## Task 3: SDK testing + compliance helpers

**Files:**
- Create: `src/cognic_agentos/sdk/testing.py` — pytest fixtures + assertion helpers.
- Create: `src/cognic_agentos/sdk/compliance.py` — ISO 42001 control-declaration helpers.

**Halt-before-commit:** Yes (Doctrine Decision E — SDK testing helpers are part of the pack-author API surface; banks build their own pack tests against this).

`testing.py` exposes:

```python
@pytest.fixture
def fixture_settings(tmp_path: Path) -> Settings:
    """Build a real Settings instance pointed at tmp_path-rooted
    in-memory adapters. Used by pack-author tests AND by
    `agentos test-harness` (Doctrine Decision C)."""

@pytest.fixture
def fixture_tool_registry() -> ToolRegistry:
    """Return a ToolRegistry pre-populated with the calling pack's
    declared tools (resolved from the local entry-point group), all
    instantiated with ``fixture_settings``."""

@pytest.fixture
def fixture_audit_capture() -> Callable[[], list[AuditEvent]]:
    """Returns a callable that flushes captured audit events from
    the in-memory store and returns them as a list. Useful for
    "this tool emitted the right audit row" assertions."""

def assert_manifest_validates(pack_path: Path) -> None:
    """Run the agentos validate pipeline against pack_path; fail
    the calling test if any validator raises a refusal."""

def assert_a2a_envelope_well_formed(envelope: dict[str, Any]) -> None:
    """Parse envelope through cognic_agentos.protocol.a2a_schema's
    SDK re-export; fail if the envelope is not a valid A2A 1.0
    StreamResponse / Task / Message shape."""
```

`compliance.py` exposes:

```python
@dataclass(frozen=True)
class ControlDeclaration:
    iso_42001_clause: str  # e.g., "A.6.4 Information security in supplier relationships"
    declaration: str       # what the pack does to honor the clause
    evidence_path: Path | None  # path inside the pack to the supporting artifact

def declare_iso_42001_controls(*controls: ControlDeclaration) -> None:
    """Decorator-or-call helper that registers controls in a
    module-level registry. The validate command's identity validator
    cross-checks declared controls against the manifest's claimed
    coverage and fails-closed on mismatch."""
```

- [ ] **Step 1: Write failing tests** (`tests/unit/sdk/test_testing_fixtures.py` + `test_compliance_helpers.py`).
- [ ] **Step 2: Run; expect FAIL.**
- [ ] **Step 3: Implement testing + compliance modules.**
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Halt-before-commit summary** per Doctrine Decision E.
- [ ] **Step 6: Commit on full-word authorization.**

---

## Task 4: CLI entry point — `cli/__init__.py` (Typer app) + `pyproject.toml` `[project.scripts]`

**Files:**
- Modify: `src/cognic_agentos/cli/__init__.py` — extend the T1 file with the Typer app (the literal lives there, the app object also lives there).
- Modify: `pyproject.toml` — add `agentos-cli` and (alias) `agentos` under `[project.scripts]`; pin `typer >= 0.12, < 0.13` and `jinja2 >= 3.1, < 4` in **base** `[project].dependencies` per R1 P2 #1.
- Create: `tests/unit/cli/test_cli_smoke.py` (R5 P3 #5 — was missing from this Files list and the top test inventory) — mandatory-console-script regression that pins `agentos --help` works after `pip install -e .`. Without this file in the explicit-path list, future maintainers who add a new optional dep + accidentally move Typer back under `[project.optional-dependencies]` lose the regression that catches the resulting `ModuleNotFoundError`.

**Halt-before-commit:** No (CLI scaffolding; T5+ adds the actual commands).

```python
# cli/__init__.py
import typer
from typer.testing import CliRunner  # re-export for pack-author convenience

app = typer.Typer(
    name="agentos",
    help="AgentOS pack-author CLI — scaffold, validate, test, sign, and verify Cognic-compatible plugin packs.",
    no_args_is_help=True,
)

# Sub-apps; commands wired in T5-T14
init_app = typer.Typer(help="Scaffold a new pack repo.")
app.add_typer(init_app, name="init")

# Validate / test-harness / sign-blob / sign --bundle / verify attach
# as direct commands on the root app (R6 P3 #4 — earlier draft omitted
# verify from the wiring comment; the smoke test in T4 Step 1 will pin
# the full public command surface so any future addition or removal
# trips a regression).
# (single-command verbs don't need their own sub-app).
```

```toml
# pyproject.toml additions

# Base dependencies — Typer + Jinja2 ship with the kernel because
# the `agentos` / `agentos-cli` console scripts (registered below)
# are mandatory per ADR-008 Phase A. R1 P2 #1 reviewer correction:
# putting these under [project.optional-dependencies].sdk would
# leave a `pip install -e .` install with the script entry point
# wired but the imports unresolvable — first invocation of
# `agentos --help` would raise ModuleNotFoundError before Typer's
# help-renderer ran. The CLI is part of the AgentOS public surface;
# its dependencies are part of the base install.
[project]
dependencies = [
    # ... existing entries preserved ...
    "typer>=0.12,<0.13",
    "jinja2>=3.1,<4",  # for cli/templates rendering
]

[project.scripts]
agentos = "cognic_agentos.cli:app"
agentos-cli = "cognic_agentos.cli:app"  # alias
```

- [ ] **Step 1: Write a smoke test** (`tests/unit/cli/test_cli_smoke.py`) — `CliRunner().invoke(app, ["--help"])` returns exit 0 + help text contains:
  - The generic title token "AgentOS pack-author CLI".
  - The five-verb surface in the help line: "scaffold", "validate", "test", "sign", "verify" (R7 P3 #3 — earlier draft only checked for the generic title; pinning the verb surface catches a future refactor that drops a command from the help text without removing the implementation).
  - The full public command names listed in the help output: `init` / `validate` / `test-harness` / `sign-blob` / `sign` / `verify` (one assertion per name; pinned individually so a future Typer-app reorganisation that hides one command from the help surface trips a single failure with the offending command's name in the error message).
  - **Plus a separate arm**: `CliRunner().invoke(app, [<command>, "--help"])` for each of the six commands above returns exit 0 (every command has a working --help; pack authors who can't read the help text can't use the CLI). Failure mode this catches: a missing or malformed `typer.Argument` / `typer.Option` declaration on any command would raise on the per-command --help invocation.
- [ ] **Step 2: Run; expect FAIL.**
- [ ] **Step 3: Implement Typer app + pyproject.toml entry point.**
- [ ] **Step 4: Run; expect PASS. Run `uv pip install -e .` then `agentos --help` to confirm the entry point is discoverable.**
- [ ] **Step 5: Commit.**

---

## Task 5: `agentos init-{tool,skill,agent}` + `cli/templates/`

**Files:**
- Create: `src/cognic_agentos/cli/init.py` — three commands.
- Create: `src/cognic_agentos/cli/templates/{tool,skill,agent}/` — Jinja2 starter templates.

**Halt-before-commit:** No.

Each `init-*` command produces a working pack repo:

```
cognic-tool-{name}/
├── pyproject.toml                      # project.entry-points.cognic.tools = {name = "cognic_tool_{name}:Main"}
├── cognic-pack-manifest.toml          # all Wave-1 mandatory blocks; placeholders for author values
├── README.md                           # author entry point with manifest-shape pointers
├── src/cognic_tool_{name}/__init__.py
├── src/cognic_tool_{name}/tool.py     # Subclass of Tool with declared input/output schemas + _invoke() stub (R5 P2 #2 — NOT invoke(); the SDK's __init_subclass__ rejects subclasses that override the public invoke method per R3 P2 #1)
├── src/cognic_tool_{name}/agent_cards/  # agent only: empty placeholder
├── tests/test_tool.py                  # uses agentos_sdk.testing fixtures
├── tests/conftest.py                   # imports the SDK fixtures
├── attestations/                       # placeholders + comment pointing at agentos sign --bundle
└── .github/workflows/sign-and-publish.yml  # GitHub Actions reference workflow
```

Each generated pyproject.toml + manifest TOML carries a `# AUTHOR-FILL: ...` comment at every author-customizable site so the green-path of `agentos validate` after `init-tool foo` produces validator failures with explicit "fill in this field" remediation.

- [ ] **Step 1: Write tests** (`tests/unit/cli/test_cli_init.py`):
  - `agentos init-tool example` produces tree → assert tree shape.
  - The produced pyproject.toml parses cleanly.
  - The produced manifest TOML carries all Wave-1 mandatory blocks.
  - Running `agentos validate` against the produced pack fails with explicit remediation messages (NOT panics) for the AUTHOR-FILL placeholders.
  - **Scaffold-SDK-contract regression** (R5 P2 #2): the generated `src/cognic_tool_{name}/tool.py` defines a `_invoke()` method (NOT `invoke()`); importing the generated module + instantiating the subclass succeeds without raising `TypeError` from `Tool.__init_subclass__`. Pin the AST shape: the class body has `_invoke` as a member but does NOT have `invoke` (which would trip the SDK's runtime override-rejection per R3 P2 #1). Repeat the assertion for the agent and skill scaffolds (Agent's `handle()` IS the public abstract — its scaffold defines `handle`, not `_handle`; Skill's `execute()` is similarly the public abstract). The shape is per-base-class.
  - Repeat for `init-skill` + `init-agent`.
- [ ] **Step 2: Run; expect FAIL.**
- [ ] **Step 3: Implement Jinja2 templates + the init commands.**
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Commit.**

---

## Task 6: `agentos validate` orchestrator (`cli/validate.py`) — CRITICAL CONTROLS

**Files:**
- Create: `src/cognic_agentos/cli/validate.py` — orchestrator + `validate` Typer command.
- Create: `tests/unit/cli/test_cli_validate.py` — orchestrator-level test surface.

**Halt-before-commit:** Yes — critical-controls module per Doctrine Decision G.

The orchestrator's contract:

```python
@app.command("validate")
def validate(
    pack_path: Path = typer.Argument(..., help="Pack repo root."),
    *,
    json_output: bool = typer.Option(False, "--json", help="Emit refusals as JSON for CI parsers."),
) -> None:
    """Run all six per-concern validators against pack_path's
    cognic-pack-manifest.toml. Exit code is non-zero if any
    validator emits a refusal; the closed-enum reason appears as
    the last word in the structured stderr line.
    """
    manifest_path = pack_path / "cognic-pack-manifest.toml"
    if not manifest_path.is_file():
        typer.echo(f"::error file={manifest_path}::manifest_not_found", err=True)
        raise typer.Exit(code=1)
    try:
        data = tomllib.loads(manifest_path.read_text())
    except tomllib.TOMLDecodeError as exc:
        typer.echo(
            f"::error file={manifest_path}::manifest_unparseable_toml ({type(exc).__name__})",
            err=True,
        )
        raise typer.Exit(code=1)

    # R2 P2 #1 reviewer correction: aggregate ValidatorFinding (not
    # ValidatorRefusal) so the warning channel introduced in R1 P2 #3
    # propagates end-to-end. Each per-validator helper returns
    # ``list[ValidatorFinding]``; the orchestrator concatenates them.
    findings: list[ValidatorFinding] = []
    findings.extend(validators.identity.validate(data, pack_path))
    findings.extend(validators.a2a.validate(data, pack_path))
    findings.extend(validators.mcp.validate(data, pack_path))
    findings.extend(validators.data_governance.validate(data, pack_path))
    findings.extend(validators.risk_tier.validate(data, pack_path))
    findings.extend(validators.supply_chain.validate(data, pack_path))

    # Render every finding to stderr (warnings + refusals); exit code
    # is non-zero ONLY if at least one finding has affects_exit_code.
    for f in findings:
        typer.echo(_format_finding(f, json_output=json_output), err=True)

    if any(f.affects_exit_code for f in findings):
        raise typer.Exit(code=1)

    # Warning-only findings (severity="warning") still surface above
    # but exit 0 here — pack authors see the diagnostic without
    # failing CI on Wave-1 optional fields like
    # ``identity_oasf_capability_set_missing``.
    typer.echo(f"validate: PASS ({pack_path})", err=False)
```

- [ ] **Step 1: Write orchestrator tests** (R3 P2 #3 reviewer correction added the warning-only arm + refreshed wording from "refusals serialise" to "findings serialise"):
  - manifest_not_found → exit 1; finding `severity="refusal"`, `reason="manifest_not_found"`.
  - manifest_unparseable_toml → exit 1; finding `severity="refusal"`, `reason="manifest_unparseable_toml"`.
  - Empty manifest with no validators wired (T7+ wires validators; this commit ships orchestrator + stub-validator surface) → all six validators called once, no findings, exit 0.
  - **Warning-only path** (load-bearing per R3 P2 #3): a stub validator returns `[ValidatorFinding(severity="warning", reason="identity_oasf_capability_set_missing", ...)]`; orchestrator renders the warning to stderr; **exit code is 0** (the warning is visible but does NOT fail CI). Pin the assertion that warning rendering went to `stderr` not `stdout` (CI parsers MUST treat both refusals + warnings as diagnostic, but exit code distinguishes "fix this before merge" from "consider this before merge").
  - **Mixed warnings + refusals** (load-bearing): a stub returns one warning + one refusal; orchestrator renders BOTH to stderr in deterministic order; exit code is 1 (any refusal trumps any number of warnings).
  - JSON output mode: findings serialise as one-JSON-per-line for CI parsers; the JSON shape carries `{"severity": "refusal" | "warning", "reason": "<literal>", "message": "...", "payload": {...}}` so parsers can split refusals from warnings programmatically.
- [ ] **Step 2: Run; expect FAIL.**
- [ ] **Step 3: Implement orchestrator with stub validators that always return empty list.**
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Halt-before-commit summary** — flag the orchestrator as a new critical-controls module; coverage measurement vs. 95/90 floor before the commit.
- [ ] **Step 6: Commit on full-word authorization.**

---

## Task 7: `cli/validators/identity.py` — AGNTCY/OASF Wave-1 — CRITICAL CONTROLS

**Files:**
- Create: `src/cognic_agentos/cli/validators/__init__.py`.
- Create: `src/cognic_agentos/cli/validators/identity.py`.
- Create: `tests/unit/cli/validators/test_validator_identity.py`.

**Halt-before-commit:** Yes — critical-controls module per Doctrine Decision G (wire-protocol-public for cross-org agent discovery).

`identity.py` exports:

```python
def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Validate the manifest's [tool.cognic.identity] block per
    the AGNTCY/OASF Wave-1 strictness matrix (BUILD_PLAN line 522).
    Returns a list of findings (refusal-severity + warning-severity);
    empty on full pass. The orchestrator concatenates findings
    across validators and computes exit code via affects_exit_code.

      Mandatory: agent_id (URN), display_name, provider_organization,
        provider_url, agent_card_url, agent_card_jws_path (agent
        packs only).
      Wave-1 optional / Wave-2 mandatory: oasf_capability_set
        (warning-not-refusal in Wave 1).
      Wave-3 reserved: verifiable_credentials_path (succeeds
        silently; if present, validator only checks that the path
        resolves to a file the cosign-signed wheel includes).

    Returns a list of refusals (empty on success). Each refusal
    carries a closed-enum identity_* reason from ValidatorReason.
    """
```

Per-arm test coverage (one arm per closed-enum reason + one happy-path arm + one Wave-1 warning arm):

- agent_id missing → `identity_agent_id_missing`.
- display_name missing → `identity_display_name_missing`.
- provider_organization missing → `identity_provider_organization_missing`.
- provider_url missing → `identity_provider_url_missing`.
- agent_card_url missing (agent pack only) → `identity_agent_card_url_missing`.
- agent_card_jws_path missing (agent pack only) → `identity_agent_card_jws_path_missing`.
- agent_card_jws_path resolves to non-existent file → `identity_agent_card_jws_path_unresolvable`.
- oasf_capability_set missing (Wave-1) → warning, NOT refusal.
- All Wave-1 mandatory present → empty refusal list.

- [ ] **Step 1-7: TDD per arm** (one fail/pass cycle per closed-enum reason).
- [ ] **Step 8: Halt-before-commit summary** — coverage vs 95/90 floor; halt for review.
- [ ] **Step 9: Commit on full-word authorization.**

---

## Task 8: `cli/validators/a2a.py` — A2A conformance declarations

**Files:**
- Create: `src/cognic_agentos/cli/validators/a2a.py`.
- Create: `tests/unit/cli/validators/test_validator_a2a.py`.

**Halt-before-commit:** Conditional — depends on whether the validator is a pure-delegation wrapper or owns AgentOS-specific build-time policy.

**Promotion rule (Doctrine Decision G):**
- If `a2a.py` only delegates to `protocol.a2a_capability_negotiation.read_pack_capabilities` and surfaces the result, it stays off the critical-controls gate (NOT halt-before-commit).
- If `a2a.py` adds AgentOS-specific build-time refusals on top of the runtime reader (e.g., refusing manifests that declare `streaming = true` without a corresponding `agent_card_url`, refusing `push_notification_config = true` outright since Wave 1 doesn't support it, etc.), it joins the gate (halt-before-commit applies).

Expected initial scope (Wave 1 build-time refusals on top of the runtime reader):
- `push_notification_config = true` in the manifest → `a2a_wave2_feature_in_wave1_manifest` (the runtime reader already filters this; the build-time validator catches it earlier so authors fix the manifest before shipping).
- Any Wave-2-only `capabilities_supported` entry (the closed-enum list comes from `docs/A2A-CONFORMANCE.md`) → `a2a_wave2_feature_in_wave1_manifest`.
- `streaming = true` without `agent_card_url` declared → `a2a_streaming_requires_agent_card_url` (a new closed-enum reason added to the literal during this task).

Given these add real allow/deny logic, **expected promotion to the critical-controls gate** at T16; halt-before-commit applies.

- [ ] **Step 1-N: TDD per arm.**
- [ ] **Halt-before-commit decision at end of task** — either "non-trivial logic, joining gate" (halt + reviewer pass) or "pure wrapper, staying off" (commit normally with rationale in commit message).

---

## Task 9: `cli/validators/mcp.py` — MCP conformance declarations

**Files:**
- Create: `src/cognic_agentos/cli/validators/mcp.py`.
- Create: `tests/unit/cli/validators/test_validator_mcp.py`.

**Halt-before-commit:** Conditional per Doctrine Decision G promotion rule.

Expected initial scope (Wave 1 build-time refusals on top of the runtime reader):
- `caching_strategy != "none"` AND `data_classes` includes any restricted class → `mcp_caching_restricted_data_class`.
- `elicitation_modes` includes `"form"` AND `data_classes` includes any restricted class → `mcp_elicitation_form_restricted_data_class`.
- Any Wave-2-only `mcp` block field present → `mcp_wave2_feature_in_wave1_manifest`.

Given these add real allow/deny logic that cross-references the runtime data-class registry, **expected promotion to the critical-controls gate** at T16.

- [ ] **Step 1-N: TDD per arm.**
- [ ] **Halt-before-commit decision at end of task.**

---

## Task 10: `cli/validators/data_governance.py` — ADR-017 contract — CRITICAL CONTROLS

**Files:**
- Create: `src/cognic_agentos/cli/validators/data_governance.py`.
- Create: `tests/unit/cli/validators/test_validator_data_governance.py`.

**Halt-before-commit:** Yes — explicit nominee per Doctrine Decision G (runtime DLP enforcement depends on the contract; bad declarations propagate to runtime mis-handling).

**R1 P2 #4 reviewer correction — vocabulary source.** An earlier draft
referenced `DataClass` / `Purpose` / `RetentionPolicy` literals at
`core/dataclasses.py` (a name that also collides with the stdlib
`dataclasses` module) — that module does not exist on the current
tree and is not part of the runtime DLP substrate (which lands per
ADR-017 Sprint 5+, currently absent). Implementation following that
reference would either import a missing module or invent a duplicate
vocabulary in the validator.

**Resolution:** define the three literals in **T1's vocabulary
scaffolding** at `cli/_governance_vocab.py` (NOT under `core/` — the
build-time vocab is owned by the CLI; the runtime DLP module per
ADR-017 will merge against this when it lands). The validator
imports from there:

```python
# cli/_governance_vocab.py — created in T1 alongside ValidatorReason.
DataClass = Literal[
    "public", "internal", "customer_pii", "payment_data", "credentials",
    "regulator_communication", "audit_trail", "model_inputs", "model_outputs",
    # Wave-1 closed-enum; new classes land in their owning sprint per ADR-017
]
Purpose = Literal[
    "transaction_processing", "regulatory_reporting", "fraud_detection",
    "customer_support", "audit_evidence", "operational_telemetry",
]
RetentionPolicy = Literal[
    "none", "session_only", "task_only", "purpose_window",
    "regulator_floor", "indefinite_with_legal_basis",
]
```

These are **build-time** literals (consumed by `agentos validate`).
The runtime DLP enforcement substrate per ADR-017 lands in a future
sprint and MUST consolidate against this same source-of-truth — when
`packs/evidence/data_governance.py` (or wherever runtime DLP lives)
ships, it imports from `cli/_governance_vocab.py` directly OR the
literals migrate to a shared location with both consumers updated in
the same commit. The Sprint-7A validator's docstring flags this:

```python
# cli/validators/data_governance.py top-of-file:
#
# Data-governance vocabulary lives at ``cli/_governance_vocab.py``
# (build-time owner). When the runtime DLP enforcement substrate
# ships per ADR-017, the literals MUST be either imported from
# here directly OR migrated to a shared module in the same commit
# that lights up runtime DLP — the build-time validator and the
# runtime enforcer cannot diverge on what counts as "customer_pii"
# without producing pack-author confusion + audit gaps. This is
# load-bearing; future maintainers, do not duplicate.
```

A migration test (added in T10 alongside the validator):

```python
# tests/unit/cli/validators/test_data_governance_vocab_consolidation.py
def test_governance_vocab_owner_documented():
    """Pin the build-time vocabulary's location + the future-merge
    contract so a Sprint-N edit that adds a parallel literal in
    ``packs/evidence/data_governance.py`` trips this test before
    diverging."""
    from cli._governance_vocab import DataClass, Purpose, RetentionPolicy
    # Assert the literal sets are non-empty + each value is a non-
    # empty string. The actual consolidation check fires when the
    # runtime DLP module exists; until then, this test pins the
    # build-time vocab location.
```

Validates the `[tool.cognic.data_governance]` block per ADR-017:
- `data_classes`: present + non-empty list of strings, each from the closed-enum `DataClass` literal in `cli/_governance_vocab.py`.
- `purpose`: present + matches a closed-enum `Purpose` literal.
- `retention_policy`: present + matches `RetentionPolicy` literal.
- `retention_max_window`: required if `retention_policy != "none"`.
- `egress_allow_list`: present + each entry is a parseable URI.
- `dlp_pre_hooks` / `dlp_post_hooks`: lists of pack-internal hook names; cross-checked against the pack's declared exports.
- `requires_consent`: bool; when True, the runtime consent gate fires before invocation.
- `regulator_retention_required`: bool; when True, retention_max_window MUST be ≥ regulator floor (per per-tenant config).

Cross-validation:
- contract.data_classes vs runtime.risk_tier consistency (fed back to T11 risk_tier validator via the closed-enum mapping `_RISK_TIER_TO_MIN_DATA_CLASSES` at module level — pinned by drift-detector test).
- contract.data_classes vs mcp.caching_strategy consistency (fed back to T9 mcp validator via the same module-level mapping).

- [ ] **Step 1-N: TDD per arm + per cross-validation rule.**
- [ ] **Halt-before-commit summary** — coverage vs 95/90 floor.
- [ ] **Commit on full-word authorization.**

---

## Task 11: `cli/validators/risk_tier.py` — ADR-014 consistency

**Files:**
- Create: `src/cognic_agentos/cli/validators/risk_tier.py`.
- Create: `tests/unit/cli/validators/test_validator_risk_tier.py`.

**Halt-before-commit:** Conditional per Doctrine Decision G promotion rule.

Validates the `[tool.cognic.runtime].risk_tier` field per ADR-014:
- Closed-enum check: tier is one of `read_only` / `internal_write` / `customer_data_read` / `customer_data_write` / `payment_action` / `regulator_communication` / `cross_tenant` / `high_risk_custom`.
- Cross-consistency with declared data classes: a tool reading PII MUST declare at least `customer_data_read`; a tool writing PII MUST declare at least `customer_data_write`; etc. The mapping `_RISK_TIER_TO_MIN_DATA_CLASSES` lives in `data_governance.py` (T10) and is read here.

Given the cross-consistency logic is the validator's primary job, **expected promotion to the critical-controls gate** at T16.

- [ ] **Step 1-N: TDD per arm.**
- [ ] **Halt-before-commit decision at end of task.**

---

## Task 12: `cli/validators/supply_chain.py` — ADR-016 attestations — CRITICAL CONTROLS

**Files:**
- Create: `src/cognic_agentos/cli/validators/supply_chain.py`.
- Create: `tests/unit/cli/validators/test_validator_supply_chain.py`.

**Halt-before-commit:** Yes — explicit nominee per Doctrine Decision G (feeds the runtime trust gate).

Validates the `[tool.cognic.supply_chain]` block per ADR-016:
- `slsa_level`: integer ∈ {1, 2, 3, 4} (Wave-1 minimum: 3).
- `provenance_url`: parseable URI; resolves to a file the cosign-signed wheel includes (path traversal pre-check).
- `sbom_path`: resolvable to a CycloneDX-shaped JSON file.
- `vuln_scan_report`: resolvable; declared scanner ∈ closed-enum `VulnScanner` set.
- `license_audit_report`: resolvable; declared licenser ∈ closed-enum `LicenseAuditor` set.
- `reproducibility_manifest`: resolvable.
- `sigstore_bundle_path`: resolvable to a `.bundle` file.

Each missing/unresolvable path → `supply_chain_attestation_path_missing` or `supply_chain_attestation_path_unresolvable`.

Cross-validation: paths feed the runtime trust gate's verification step (Sprint 4); the validate command runs `core.canonical.canonical_bytes` over the manifest to surface any path that points outside the wheel's declared layout.

- [ ] **Step 1-N: TDD per arm.**
- [ ] **Halt-before-commit summary** — coverage vs 95/90 floor.
- [ ] **Commit on full-word authorization.**

---

## Task 13: `agentos test-harness` — hybrid runner (`cli/test_harness.py`)

**Files:**
- Create: `src/cognic_agentos/cli/test_harness.py`.
- Create: `tests/unit/cli/test_cli_test_harness.py`.
- Create: `tests/fixtures/cli_harness_target_pack/` (R7 P2 #1) — task-local fixture pack used by T13 harness tests; minimal-but-valid synthetic tool pack synthesized at test-author time. Decoupled from the T15 `examples/` reference packs so T13 can run without T15 having landed (mirrors the R6 P2 #2 `cli_sign_target_pack` decoupling pattern for T14).

**Halt-before-commit:** No (authoring/dev-only command per Doctrine Decision G non-promotion list — R4 P3 #5; not "test-only path", which would mislabel a public CLI surface).

Per Doctrine Decision C, `agentos test-harness <pack-path>`:
1. Run the full validate pipeline (every refusal surfaces).
2. Load the pack's tool/skill/agent entry-points; instantiate with `agentos_sdk.testing.fixture_settings()`.
3. Invoke each declared method with pack-author-supplied fixture inputs (defaults provided for stubs); capture response shape; validate against declared output schema.
4. No live transports — `httpx.MockTransport` everywhere; SecretAdapter returns fixture keyring; AuditStore is in-memory; LangfuseAdapter is no-op.
5. Emit a conformance report (TOML or JSON) covering: identity completeness, A2A/MCP declarations vs ran behavior, data-governance contract, risk-tier consistency, supply-chain attestation reachability, dispatch dry-run outcome.

- [ ] **Step 1: Write the harness tests** (R7 P2 #1 reviewer correction — earlier draft drove against `examples/cognic-tool-example-minimal/` which is created in T15 AFTER T13; same task-ordering blocker R6 fixed for T14) — drive `agentos test-harness tests/fixtures/cli_harness_target_pack/` and assert the conformance report shape. The task-local fixture is a minimal-but-valid synthetic tool pack synthesized at test-author time (mirrors the R6 P2 #2 `cli_sign_target_pack` decoupling pattern). T15's reference packs under `examples/` are the **separate** end-to-end author-workflow surface gated by `test_reference_packs_full_lifecycle_green.py`; T13's task-local fixture is the unit-test-of-the-harness-pipeline surface.
- [ ] **Step 2: Run; expect FAIL.**
- [ ] **Step 3: Implement the harness.**
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Commit.**

---

## Task 14: `agentos sign` (full bundle generator) + `agentos verify` (offline trust gate) — CRITICAL CONTROLS

**Files:**
- Create: `src/cognic_agentos/cli/sign.py` — `sign-blob` + `sign --bundle` per Doctrine Decision F.
- Create: `src/cognic_agentos/cli/verify.py` (R2 P2 #5 reviewer correction) — `agentos verify <pack-path>` runs the offline trust-gate checks.
- Create: `tests/unit/cli/test_cli_sign.py`.
- Create: `tests/unit/cli/test_cli_verify.py`.
- Create: `tests/fixtures/cli_sign_target_pack/` (R6 P2 #2) — task-local fixture pack used by T14 sign + verify tests; minimal-but-valid synthetic pack synthesized at test-author time (mirrors Sprint-6 fixture-pack pattern). Decoupled from the T15 `examples/` reference packs so T14 can run without T15 having landed. **R9 P2 #1**: ships its own test-only signing keypair at `attestations/test-signing/test_signing_key.{private,public}.pem`; T14's JWS-signing arm uses these files via `Settings.signing_key_path` + `signing_trust_root_path` overrides.
- Modify: `.gitignore` (R10 P2 #1) — add the **explicit exception lines** for T14's fixture keypair (the global `*.pem` rule from line 68 silently excludes these otherwise; mirrors the Sprint-6 fixture-pack public-PEM pattern). The exact lines T14 commits:
  ```
  !tests/fixtures/cli_sign_target_pack/attestations/test-signing/test_signing_key.private.pem
  !tests/fixtures/cli_sign_target_pack/attestations/test-signing/test_signing_key.public.pem
  ```
- Create: `tests/architecture/test_cli_sign_no_dev_skip_in_prod.py` — static-AST scan banning the dev-skip override from the production code path.
- Create: `src/cognic_agentos/cli/sign_templates/` — template files for the SLSA provenance + in-toto layout (Wave-1 simplification per Doctrine F's out-of-scope notes).

**Halt-before-commit:** Yes — explicit nominee per Doctrine Decision G (security-critical) + Doctrine Decision F (real signing or fail-loud, full bundle generator).

**R1 P2 #5 reviewer correction:** T14 expanded from a thin cosign-blob
wrapper to the full Wave-1 bundle generator. Per ADR-016 +
Sprint-6 hand-off, `agentos sign --bundle` produces all seven
attestation files (SBOM via syft, vuln scan via grype, license audit
via pip-licenses-or-cyclonedx-py, SLSA provenance via template, in-toto
layout via template, cosign sign-blob, AgentCard JWS via joserfc).
`agentos sign-blob` is the narrow sub-command for re-sign / key-rotation
scenarios where the bundle pieces already exist.

Per Doctrine Decision F:
- Each external tool gets its own `shutil.which()` check + closed-enum missing-tool refusal.
- All subprocess invocations use real `asyncio.create_subprocess_exec`.
- Vault-resolved signing key via `SecretAdapter`; missing → `sign_signing_key_unavailable`.
- AgentCard JWS signing via `joserfc` (already a Sprint-6 dep); detached compact form.
- `--dev-mode-skip-cosign` is gated behind a flag that prints a security warning; `prod` profile's settings reject the flag at startup.

Test posture mirrors `test_trust_gate.py`'s cosign-shim pattern, extended per-tool: one shim per external binary (cosign / syft / grype / pip-licenses); each shim is a Python script the real subprocess exec runs against, recording argv/env/cwd to JSON; controllable exit code, stdout, stderr.

- [ ] **Step 1: Write `sign-blob` tests** — happy path (shim returns 0), missing-cosign, missing-key, subprocess failure, `--dev-mode-skip-cosign` prints warning + skips, prod profile rejects the flag.
- [ ] **Step 2: Run; expect FAIL.**
- [ ] **Step 3: Implement `sign-blob` (the narrow path).**
- [ ] **Step 4: Run; expect PASS.**
- [ ] **Step 5: Write `sign --bundle` tests** — per-tool missing-binary arms (syft / grype / license auditor); per-step shim happy paths; full-orchestration arm (invoke against a tmp_path clone of `tests/fixtures/cli_sign_target_pack/` — the task-local fixture, NOT the T15 reference pack per R6 P2 #2; assert all 7 attestation files exist + match expected shapes); AgentCard JWS arm (uses the **committed task-local test-only signing keypair** at `tests/fixtures/cli_sign_target_pack/attestations/test-signing/` per R9 P2 #1; assert detached form per Sprint-6 doctrine; assert the regenerated JWS verifies against the committed public PEM deterministically); template-render-failure arms for SLSA + in-toto.
- [ ] **Step 6: Run; expect FAIL.**
- [ ] **Step 7: Implement `sign --bundle` orchestrator + the SLSA + in-toto templates.**
- [ ] **Step 8: Run; expect PASS.**

**`agentos verify <pack-path>` — offline trust-gate checks (R2 P2 #5
reviewer correction; ADR-016 Sprint-7A mandate).** The inverse of
`sign --bundle`: takes a built+signed pack, re-runs the same
verification the runtime trust gate (Sprint 4) would run at
admission, surfacing every check before the pack is submitted to a
registry.

Verification steps (each fail-loud with closed-enum reason):
1. `cosign verify-blob <wheel> --signature attestations/cosign.sig --bundle attestations/bundle.sigstore` against the per-tenant trust root supplied via `--trust-root <path>` (or `vault://...` URI). Failure → `verify_cosign_signature_invalid`.
2. SBOM digest in the sigstore bundle matches the on-disk SBOM at `attestations/sbom.cdx.json`. Failure → `verify_sbom_digest_mismatch`.
3. SLSA provenance + in-toto layout files parse cleanly + reference the same artifact identity. Failure → `verify_provenance_invalid` / `verify_intoto_layout_invalid`.
4. Vuln scan + license audit files are reachable + non-empty. Failure → `verify_attestation_path_unresolvable`.
5. AgentCard JWS verifies against the supplied trust root (agent packs only) — uses the same `joserfc` detached-payload path as Sprint-6's `TrustGate.verify_jws_blob`. Failure → `verify_agent_card_jws_invalid`.
6. Manifest re-validates via the full `agentos validate` pipeline (every refusal surfaces). Failure → orchestrator already exits non-zero.

**Test posture:**
- Per-step shim arms (mirroring sign-blob's cosign-shim pattern) for cosign verify-blob + JWS verification.
- Full happy-path arm: invoke `agentos verify` against a freshly `sign --bundle`-ed clone of `tests/fixtures/cli_sign_target_pack/` in tmp_path (R6 P2 #2 — task-local fixture; T15 examples are not yet on disk at T14 execution time); expect exit 0 + all **7** verifier reasons absent from output (R7 P2 #2 — count was incorrectly stated as 6 in the earlier draft; the closed-enum literal block below lists 7).
- Tampered-attestation arms: mutate one byte in `attestations/sbom.cdx.json` between sign and verify; expect `verify_sbom_digest_mismatch` + exit 1.
- Tampered-AgentCard-JWS arm (agent packs only): mutate one byte in the card JSON between sign and verify; expect `verify_agent_card_jws_invalid` (mirrors the Sprint-6 T14 fixture-pack tampered-payload regression at the runtime trust gate).
- **Trust-root-unresolvable arm** (R7 P2 #2 — was missing from the test posture): pass `--trust-root <nonexistent-path>` (or a `vault://` URI that the mocked `SecretAdapter` returns `None` for); expect `verify_trust_root_path_unresolvable` + exit 1. Without this arm, the closed-enum reason `verify_trust_root_path_unresolvable` would have a fire-path in production code but no test that pins it — exactly the kind of un-pinned-refusal-reason gap the per-arm-coverage doctrine in Sprint-2/3/4/5/6 forbade. This arm closes it.
- **Per-step-failure arms covering the remaining verify reasons** (R7 P2 #2): `verify_provenance_invalid` (mutate `attestations/slsa-provenance.intoto.json` to malformed JSON between sign and verify); `verify_intoto_layout_invalid` (mutate `attestations/intoto-layout.json` similarly); `verify_attestation_path_unresolvable` (delete one of the seven attestation files between sign and verify). One arm per closed-enum reason; the test posture now covers all 7 verify refusal reasons explicitly.
- Closed-enum verify reasons added to `ValidatorReason` literal in T1 (with severity="refusal" each):

```python
"verify_cosign_signature_invalid",
"verify_sbom_digest_mismatch",
"verify_provenance_invalid",
"verify_intoto_layout_invalid",
"verify_attestation_path_unresolvable",
"verify_agent_card_jws_invalid",
"verify_trust_root_path_unresolvable",
```

- [ ] **Step 9: Write `verify` tests** (the per-step + happy-path + tampered-attestation + tampered-JWS arms above).
- [ ] **Step 10: Run; expect FAIL.**
- [ ] **Step 11: Implement `verify` orchestrator** (reuses sign's cosign / joserfc / `core.canonical.canonical_bytes` invocations; trust-root resolution via `SecretAdapter`).
- [ ] **Step 12: Run; expect PASS.**
- [ ] **Step 13: Halt-before-commit summary** — coverage vs 95/90 floor for sign.py + verify.py both; halt-for-review.
- [ ] **Step 14: Commit on full-word authorization.**

**Out-of-scope (Wave-1 simplifications, per Doctrine Decision F):**
- Full slsa-generator with GitHub Actions OIDC reusable workflow — template-based simplification ships in T14; full L3 integration lands later.
- HSM / YubiKey / TPM hardware-token signing — Wave-1 supports `vault://` keys only.
- Multi-signature attestations (n-of-m signers) — single-signer Wave-1.
- `agentos verify` against a remote pack URL (download + verify in one shot) — Wave-1 takes a local pack path; URL-fetch lands with `agentos publish` in Sprint 7B.

---

## Task 15: Three reference packs in `examples/`

**Files:**
- Create: `examples/cognic-tool-example-minimal/` — minimal-but-valid tool pack.
- Create: `examples/cognic-skill-example-minimal/` — minimal-but-valid skill pack.
- Create: `examples/cognic-agent-example-minimal/` — minimal-but-valid agent pack. **R9 P2 #1**: ships `attestations/test-signing/test_signing_key.{private,public}.pem` + `NOTE.md`; T15's lifecycle test (Steps 4 + 5 below) uses this fixture keypair via `Settings.signing_key_path` + `signing_trust_root_path` overrides for deterministic sign-then-verify.
- Modify: `.gitignore` (R10 P2 #1) — add the **explicit exception lines** for the agent example pack's keypair. Tool + skill example packs do NOT need a signing keypair (no AgentCard JWS to sign), so only the agent pack gets the exception lines. The exact lines T15 commits:
  ```
  !examples/cognic-agent-example-minimal/attestations/test-signing/test_signing_key.private.pem
  !examples/cognic-agent-example-minimal/attestations/test-signing/test_signing_key.public.pem
  ```
- Create: `tests/unit/cli/test_reference_packs_full_lifecycle_green.py` (R6 P2 #3 — renamed from `test_reference_packs_validate_green.py`; the reference packs gate the **full author lifecycle** scaffold → validate → harness → sign → verify, NOT just validate).

**Halt-before-commit:** No.

Per Doctrine Decision D, each pack ships with:
- Complete manifest (all Wave-1 mandatory blocks).
- Signed AgentCard JSON + JWS + public-key PEM (agent pack only).
- Seven attestation files.
- `pyproject.toml` with the right entry-point group.
- README pointing at `docs/HOW-TO-WRITE-A-PACK.md`.

Each pack is **inert**: tool returns `{"echo": <input>}`; skill composes the example tool deterministically; agent's `handle()` returns `{"text": "ok"}`.

**R9 P2 #1 reviewer correction — explicit test-only signing-key
fixture.** An earlier draft said the example pack's private key is
"generated at author-time and discarded" (mirroring the Sprint-6
fixture-pack pattern), but T15 then required `agentos sign --bundle`
to **regenerate** the AgentCard JWS and `agentos verify` to check it
against the committed public-key PEM — that path needs a matching
private key at test/runtime, which the discarded-after-author-time
shape can't provide. The lifecycle test would either be
non-deterministic or require live signing infrastructure.

**Resolution:** each agent example pack ships an explicit test-only
keypair under `attestations/test-signing/`:

  - `attestations/test-signing/test_signing_key.private.pem` — RSA
    private key in PKCS8 format. Committed via narrow `.gitignore`
    exception (`!examples/cognic-agent-example-minimal/attestations/test-signing/test_signing_key.private.pem`)
    matching the Sprint-6 public-key pattern but on the private side.
    File header carries a NOTE comment + the `test_signing_key`
    naming makes the test-only intent unmissable.
  - `attestations/test-signing/test_signing_key.public.pem` — RSA
    public key (matching half). Used as the verifier's trust-root
    target during T15 lifecycle.
  - `attestations/test-signing/NOTE.md` — explicit doctrine: "this
    keypair is test-only, synthetic, generated at author-time;
    `prod` profile rejects this path at startup; do NOT reuse
    outside of the T15 lifecycle test or the regeneration script
    in T15's commit message footer."

T15 lifecycle test (Steps 4 + 5 below) overrides
`Settings.signing_key_path` to point at the committed test-only
private PEM; `Settings.signing_trust_root_path` (a new Sprint-7A
setting added in T1 alongside the existing five) points at the
matching public PEM. Sign produces a JWS that verify accepts
deterministically. The `prod` profile's settings layer rejects any
`signing_key_path` under the `examples/` tree at startup (a new
guard added to T1; mirrors `dev_mode_skip_cosign`'s prod-profile
rejection).

**Same pattern applies to T14's task-local fixture**
(`tests/fixtures/cli_sign_target_pack/`): ships its own
`test_signing_key.private.pem` + matching public PEM via the same
`.gitignore` exception pattern. T14's JWS-signing arm sets
`Settings.signing_key_path` to that fixture's private PEM
(no separate keypair-generation-at-test-time path); R8 P2 #2's shim
infrastructure plus this fixture key together make T14 + T15 fully
deterministic in the unit lane.

**Why commit the private key (a security smell at first glance):**
- The keypair is **synthetic** (no production trust root anywhere
  trusts it; no operator could deploy with it).
- The key is bound to the `examples/` / `tests/fixtures/` tree;
  `prod` profile's settings layer rejects `signing_key_path`
  pointing inside those trees at startup.
- This is the same pattern as Sprint-6's fixture pack public PEM
  (`!.../test_agent.pub.pem`); Sprint-7A extends it to the private
  side with explicit production-profile rejection.
- Alternative (generate-keypair-at-test-time) would require T14 +
  T15 to hold a non-deterministic regeneration step on every test
  run — making CI flake on RSA-generation timing AND making the
  committed JWS in the example pack a documentation-only artifact
  (since the test never verifies against it).

The agent pack's AgentCard JWS is regenerable via the same author
script the Sprint-6 fixture pack used (preserved in this task's
commit message footer); regeneration uses the **committed test-only
private key** (R9 P2 #1) — not a fresh keypair — so the regenerated
JWS verifies deterministically against the committed public PEM.

**R6 P2 #3 reviewer correction — full lifecycle green-path.** The
sprint goal claims the examples demonstrate scaffold → validate →
sign → verify, but an earlier T15 only gated `agentos validate` +
`agentos test-harness`. That would let committed example
attestations or AgentCard JWS files drift while the reference-pack
CI stays green. The full lifecycle below is now the gate.

**R8 P2 #2 reviewer correction — shim infrastructure required, NOT
live binaries.** Steps 4 + 5 below invoke `agentos sign --bundle`
and `agentos verify` against each example pack. Without explicit
shim wiring, those steps would call the real `cosign` / `syft` /
`grype` / `pip-licenses` binaries — failing CI on machines without
those tools. The lifecycle test **MUST reuse T14's shim
infrastructure**: the per-test `Settings` instance has
`cosign_path` / `syft_path` / `grype_path` / `license_auditor_path`
overridden to point at the same Python shims T14 uses (each shim
records argv + env + cwd to JSON; controllable exit code; produces
deterministic-shape output bytes that match committed-state
attestations within reasonable per-file tolerances). The
reference-pack lifecycle test stays in the **unit lane**; live-tool
verification is a separate (env-gated) integration concern, mirroring
the Sprint-4 `cosign_real` lane pattern (env-var
`COGNIC_RUN_SIGN_REAL=1` would gate a future live-binary lane).

The full lifecycle below is now the gate:

- [ ] **Step 1: Generate the three packs** (manifest + entry-point pyproject + minimal source + the seven attestation files + AgentCard JWS for the agent pack).
- [ ] **Step 2: Run `agentos validate` against each → expect PASS for all three** (zero refusals; warnings allowed since they exit 0 by design).
- [ ] **Step 3: Run `agentos test-harness` against each → expect PASS for all three** (conformance report shape valid; dispatch dry-run succeeds).
- [ ] **Step 4: Run `agentos sign --bundle` against each in tmp_path** — expect all 7 attestation files to regenerate cleanly + match the committed-state shapes byte-for-byte (or reasonable-tolerance-per-file: SBOM digest must match; vuln scan output may have timestamp drift, so compare on shape + scanner identity, not byte-level). For the agent pack, the AgentCard JWS regenerates and verifies against the committed public-key PEM.
- [ ] **Step 5: Run `agentos verify` against each (using the freshly signed bundle from Step 4)** — expect exit 0 + all 7 verifier reasons absent (R7 P2 #2 — was 6).
- [ ] **Step 6: Add `tests/unit/cli/test_reference_packs_full_lifecycle_green.py`** to make the full lifecycle (scaffold-fixture-on-disk + validate + harness + sign + verify) a CI gate. The test wires Steps 2-5 against the committed `examples/` tree; if any committed attestation drifts (tampered SBOM, expired AgentCard JWS, missing template), the gate fires.
- [ ] **Step 7: Commit.**

---

## Task 16: Critical-controls coverage gate extension + 3 docs

**Files:**
- Modify: `tools/check_critical_coverage.py` — extend gate from 28 to **34+** modules (final count depends on T8/T9/T11 promotion decisions; baseline 34 covers the six explicit nominees including `cli/verify.py` per R2 P2 #5).
- Create: `docs/HOW-TO-WRITE-A-PACK.md` — author tutorial.
- Create: `docs/SDK-REFERENCE.md` — Python API reference.
- Create: `docs/PACK-MANIFEST-SPEC.md` — stable manifest format + versioning policy.

**Halt-before-commit:** Yes — gate config is executable single-source-of-truth for the per-file coverage floor.

Per Doctrine Decision G, the gate-extension lands these **six** at minimum:
- `cli/validate.py` (orchestrator)
- `cli/validators/identity.py`
- `cli/validators/data_governance.py`
- `cli/validators/supply_chain.py`
- `cli/sign.py`
- `cli/verify.py` (R2 P2 #5)

Plus, per the T8/T9/T11 promotion-rule decisions made during execution, any of `validators/a2a.py`, `validators/mcp.py`, `validators/risk_tier.py` that ended up owning non-trivial allow/deny logic.

- [ ] **Step 1: Generate fresh `coverage.json`** against the post-T15 branch.
- [ ] **Step 2: Probe coverage on each candidate module; report line + branch percentages.**
- [ ] **Step 3: If any module short of 95/90: halt + report uncovered themes. Add tests; do NOT lower the floor.**
- [ ] **Step 4: Extend the gate; run; expect 34+ modules PASS** (R4 P3 #4 — was 33+; baseline 34 covers the six explicit nominees including `cli/verify.py` per R2 P2 #5; +1 for each of `validators/a2a.py` / `mcp.py` / `risk_tier.py` that promotes per the Doctrine Decision G rule).
- [ ] **Step 5: Write the three docs** (each a single coherent file).
- [ ] **Step 6: Halt-before-commit summary.**
- [ ] **Step 7: Commit on full-word authorization.**

---

## Task 17: Closeout

**Files:**
- Create: `docs/closeouts/2026-05-XX-sprint-7a-agentos-sdk-cli.md` (date filled at commit time).
- Modify: `docs/BUILD_PLAN.md` — Sprint-7A status flip to **CLOSED**.
- Modify: `AGENTS.md` — new "Authoring — SDK + CLI (Sprint 7A)" critical-controls section listing the modules that joined the gate at T16.

**Halt-before-commit:** Yes — AGENTS.md is a doctrine document.

Closeout structure mirrors Sprint-5 / Sprint-6:
- Header (parent SHA, branch state, commit count).
- What ships (SDK base classes + testing/compliance helpers + 3 init scaffolders + validate orchestrator + 6 per-concern validators + test-harness + sign + 3 reference packs + 3 docs + critical-controls gate extension).
- CI matrix.
- Doctrine adherence.
- Test + coverage state (34+ module gate table).
- Plan-review findings closed (round-by-round T1-T17).
- ADR-008 / ADR-014 / ADR-016 / ADR-017 validation table.
- Doctrine amendments accepted.
- Sprint-7B hand-off checklist (load-bearing).
- Carryover.
- Out-of-scope.
- Next sprint.

**AGENTS.md amendment text (illustrative; final list depends on T8/T9/T11 promotions):**

```markdown
*Authoring — SDK + CLI (Sprint 7A):*
- `cli/validate.py` (per ADR-008 — orchestrator; build-time half of the trust gate)
- `cli/validators/identity.py` (per ADR-002 amendment + AGNTCY/OASF Wave-1 strictness — wire-protocol-public for cross-org agent discovery)
- `cli/validators/data_governance.py` (per ADR-017 — runtime DLP enforcement depends on the contract)
- `cli/validators/supply_chain.py` (per ADR-016 — feeds the runtime trust gate)
- `cli/sign.py` (per ADR-016 — full bundle generator: cosign + syft + grype + license audit + AgentCard JWS; security-critical signing path)
- `cli/verify.py` (per ADR-016 — offline trust gate; mirrors the Sprint-4 runtime trust-gate verification path; R2 P2 #5)
[+ any T8/T9/T11 promotions]
```

- [ ] **Step 1: Write the closeout note.**
- [ ] **Step 2: Update BUILD_PLAN status.**
- [ ] **Step 3: Update AGENTS.md.**
- [ ] **Step 4: Run full release-gate set: full sweep + arch tests + critical-controls gate (against fresh coverage.json) + lint + types.**
- [ ] **Step 5: Halt-before-commit summary.**
- [ ] **Step 6: Commit on full-word authorization.**

---

## Self-Review

After writing the complete plan, looked at the BUILD_PLAN deliverables / tests / exit criteria with fresh eyes:

**Spec coverage:**
- ✅ All 11 BUILD_PLAN deliverables (line 511-535) map to tasks T2-T17.
- ✅ All 10 BUILD_PLAN test files (line 537-548) map to tasks T2-T15.
- ✅ All 4 BUILD_PLAN exit criteria (line 550-554) are pinned by tests in T15 (reference packs **full-lifecycle green** per R6 P2 #3 — scaffold-fixture-on-disk + validate + harness + sign + verify, NOT just validate; R7 P3 #5 refresh — earlier wording said "validate-green" which would have understated the closeout evidence) + T6 (orchestrator) + T13 (test-harness produces conformance report).
- ✅ ADR-008 Phase A scope (line 28-38 of the ADR) covered: `init-tool / init-skill / init-agent / validate / sign` are all delivered. `register --local` and `publish --registry` deliberately deferred (Sprint 7B per the per-action rule's "no scope creep" lock).
- ✅ ADR-016 Sprint-7A scope (R2 P2 #5 fix): `agentos sign --bundle` (full bundle generator) AND `agentos verify <pack-path>` (offline trust gate) both ship in T14, mirroring the matched-pair contract in ADR-016.

**Placeholder scan:** No "TBD" / "implement later" / "fill in details" / "similar to Task N (without code)" in the plan. Every task has either explicit code shown OR a closed-enum reason list with per-arm test mappings.

**Type consistency:** Function signatures shown in T2 (`Tool.invoke`, `Skill.execute`, `Agent.handle`) are referenced consistently in T3 (testing fixtures), T6 (validator orchestrator dispatches by manifest, not by class), T15 (reference packs subclass these). `ValidatorFinding` shape declared in T1 (per R2 P2 #1 — superseded the earlier `ValidatorRefusal` shape so the warning channel propagates end-to-end), consumed by the orchestrator in T6 and every per-concern validator in T7-T12 (each returns `list[ValidatorFinding]`); T14 also consumes the shape via the sign + verify reasons it adds to the literal (R6 P3 #5).

**Doctrine-lock fold-in:** All 10 user-locked decisions from the planning brief are reflected:
1. Plan PR shape — this plan file lives on `chore/sprint-7a-plan-of-record`.
2. 17 tasks — exactly that count.
3. 5 → 6 critical-controls nominees (R4 P3 #4 — R2 P2 #5 added `cli/verify.py`) + promotion rule — Doctrine Decision G; gate grows 28 → ≥34.
4. Typer pinned — Doctrine Decision A.
5. `cli/validators/` sub-package — Doctrine Decision B.
6. Hybrid test-harness — Doctrine Decision C.
7. Minimal-but-valid reference packs, neutral names — Doctrine Decision D.
8. SDK halt-before-commit policy — Doctrine Decision E.
9. Real-or-fail-loud sign — Doctrine Decision F.
10. Out of scope (no publish, no register, no Studio, no promotion workflow) — confirmed in T16 carryover + the plan title's "Wave-1 surface covers" enumeration.

**Open questions for plan-PR review (likely reviewer focus areas):**
- T8/T9/T11 promotion-rule decisions are deferred to execution time (per Doctrine Decision G). The plan flags this as conditional halt-before-commit; the closeout T17 records the final list. Reviewer may want a tighter prediction at plan-review time vs. accepting the runtime-decision posture.
- The `_VALIDATOR_REASON_OWNERSHIP` Final dict is named in T1 but not fully enumerated — it grows during T7-T14 (per R6 P3 #5; T14 adds sign + verify ownership entries). Reviewer may want the full table at plan-PR time.
- The reference packs' AgentCard JWS regeneration script (T15) — whether to embed it in the plan-PR or leave for the T15 commit message footer.

---

## Execution handoff

Plan complete. Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task, review between tasks, fast iteration. Best for the SDK base classes (T2-T3) and critical-controls validators (T7, T10, T12, T14) where reviewer rounds are expected to be deeper.

**2. Inline Execution** — execute tasks in this session using executing-plans, batch execution with checkpoints for review.

**Halt-before-commit on the plan file itself** (this commit on `chore/sprint-7a-plan-of-record`) — pending the user's `commit` token to land it, then plan PR for doctrine review, then merge to main, then implementation branch.
