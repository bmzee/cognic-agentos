# Sprint 7A — Authoring SDK + CLI (per ADR-008 Phase A) — Closeout Note

**Date:** 2026-05-09
**Sprints closed:** 7A (authoring platform — SDK base classes for Tool / Skill / Agent + ToolRegistry protocol + testing pytest fixtures + ISO 42001 control-declaration helpers + `agentos` CLI entry point + three init scaffolders + `agentos validate` orchestrator + six per-concern validators + `agentos test-harness` Wave-1-narrow runner + `agentos sign --bundle` full bundle generator + `agentos verify` offline trust gate per ADR-016 with the R15 PIVOT replacing static-AST loadability with an isolated-subprocess `EntryPoint.load()` probe + three `examples/` reference packs gated by a full-lifecycle CI test + critical-controls coverage gate extended to 37 modules + three Wave-1 author docs).
**State:** **READY-FOR-GATE** on `feat/sprint-7a-agentos-sdk-cli`. No push, no PR, no merge until the human authorises per the AGENTS.md per-action rule.
**Pre-T17 tip:** `a2761a3 feat(sprint-7a): T16 — critical-controls coverage gate +9 modules + 3 docs`.
**Branch base:** `35e9016` on `main` — the merged Sprint-6 plan-of-record (PR #19).
**20 commits total after T17 lands** atop the merged Sprint-6 plan-of-record: T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T13 hotfix (mypy gate), T14.A (cosign sign-blob), T14.B (sign --bundle full orchestrator), T14 (verify offline trust gate + load_probe + wheel_integrity + R15 PIVOT), T15, T16, T17 closeout.

## What ships in `feat/sprint-7a-agentos-sdk-cli` after Sprint 7A

### SDK base classes (Sprint-7A T2 + T3)

- **`src/cognic_agentos/sdk/tool.py`** — `Tool` base class. Subclasses declare `name` + `input_schema` + `output_schema` as ClassVar fields, override `_invoke()`, and let the SDK's template-method validation seam handle JSON-Schema validation of input/output. `Tool.invoke()` is `@final` (mypy) AND guarded at runtime via `__init_subclass__` walking `cls.__mro__` — any class defining `invoke` directly in a non-base ancestor raises `TypeError` at class-creation time so mixin-smuggling cannot bypass the schema validation seam (R3 P2 #1 + R8 P2 #1).
- **`src/cognic_agentos/sdk/skill.py`** — `Skill` base class. Subclasses declare `name` + `declared_tools` ClassVars, override `execute()`, optionally override `setup()`. The SDK's `__init__(*, tools: ToolRegistry)` is `@final` AND `__init_subclass__`-guarded; cross-checks `declared_tools` against `tools.list_tools()` BEFORE any `execute()` call — missing names raise `SkillUnregisteredToolError` at instantiation time (R5 P2 #3 + R6 P2 #1 + R8 P2 #1).
- **`src/cognic_agentos/sdk/agent.py`** — `Agent` base class. Subclasses declare `name` + `declared_capabilities: A2ACapabilities` ClassVars; override `handle(payload, *, task: TaskRecord)`. Endpoint-side construction means no SDK `__init__` template; agent code returns a Wave-1 dict per A2A 1.0 spec which the endpoint's lifecycle machinery wraps into a `StreamResponse` envelope.
- **`src/cognic_agentos/sdk/registry.py`** — `ToolRegistry` PEP-544 protocol with `get(name) -> Tool` + `list_tools() -> list[str]`. Runtime-supplied; pack-author tests use the in-tree `fixture_tool_registry` pytest fixture for fixture-only adapters.
- **`src/cognic_agentos/sdk/testing.py`** — pytest fixtures: `fixture_settings(tmp_path)` returns a memory-adapter Settings instance; `fixture_tool_registry()` returns a `ToolRegistry` pre-populated from `importlib.metadata.entry_points()`. **No transport interception** (R33 P2 #1 narrow contract — pack code runs against unmodified host runtime; no `httpx.MockTransport`, no environment-variable scoping, no filesystem/network sandbox; pack authors who need adapter isolation wire it themselves in their pack test suite).
- **`src/cognic_agentos/sdk/compliance.py`** — ISO 42001 control declaration helpers: `ControlDeclaration` frozen dataclass, `declare_iso_42001_controls(*controls)` append-only registration, `declared_iso_42001_controls()` tuple snapshot accessor. Wave-1 ships the declaration shape so operators can audit each pack's claimed control coverage at install time; per-event emission into the audit chain lands in a follow-up sprint alongside the runtime auto-attestation API.

### CLI surface (Sprint-7A T4 + T5 + T6 + T13 + T14 + T15)

- **`src/cognic_agentos/cli/__init__.py`** — `agentos` Typer entry point (registered as `[project.scripts]` in pyproject.toml). Exposes the closed-enum `ValidatorReason` literal that every per-concern validator surfaces refusals through (drift detector at `tests/unit/test_config.py::TestSprint7AClosedEnumVocabulary`).
- **`src/cognic_agentos/cli/init.py`** — `agentos init-{tool,skill,agent} <name>` scaffolders. Renders the corresponding template tree at `cli/templates/{tool,skill,agent}/` via Jinja2; each template carries `AUTHOR-FILL:` placeholders the validator refuses on until the author replaces them with real values.
- **`src/cognic_agentos/cli/templates/`** — three template trees (one per kind). Each ships a complete pack: manifest + pyproject + inert source + tests/conftest.py + tests/test_*.py + README. The agent template additionally ships an empty `agent_cards/` directory the operator's signing pipeline populates.
- **`src/cognic_agentos/cli/validate.py`** — orchestrator that coordinates the six per-concern validators + the shape gate. Dual-path lookup (canonical top-level [block] vs. legacy `[tool.cognic.block]`) per R23 doctrine across every per-concern validator. JSON output (one finding per stderr line) + human "PASS"/"FAIL" stdout summary.
- **`src/cognic_agentos/cli/validators/identity.py`** — AGNTCY/OASF Wave-1 strictness on `[identity]` (T7).
- **`src/cognic_agentos/cli/validators/a2a.py`** — Wave-2 capability-feature refusal on `[a2a]` (T8). Promoted to critical-controls at T16 closeout per the deferred-call decision.
- **`src/cognic_agentos/cli/validators/mcp.py`** — caching + elicitation refusals cross-referencing `[data_governance].data_classes` (T9). Off-gate per pure-delegation rule.
- **`src/cognic_agentos/cli/validators/data_governance.py`** — ADR-017 contract validation on `[data_governance]` (T10).
- **`src/cognic_agentos/cli/validators/risk_tier.py`** — closed-enum `RiskTier` check + per-data-class minimum-tier cross-consistency (T11). Off-gate per pure-delegation rule. Doctrine-fix included: T7 dual-path retro-fitted at T11.
- **`src/cognic_agentos/cli/validators/supply_chain.py`** — ADR-016 attestation-paths declaration validator (T12).
- **`src/cognic_agentos/cli/test_harness.py`** — `agentos test-harness` Wave-1 narrow runner (T13). `_HARNESS_SUPPORTED_KINDS = frozenset({"tool"})` per T13/R31; skill + agent dispatch land in Sprint-7B. R31-R34 reviewer rounds folded into the original commit; the Wave-1 narrow contract is pinned by `test_run_harness_wave1_narrow_contract_no_transport_interception` (no transport interception, no fixture_settings injection, no env scoping, no sandbox; pack code runs against unmodified host runtime).
- **`src/cognic_agentos/cli/sign.py`** — `agentos sign --bundle` full bundle generator (T14.A + T14.B). Real `asyncio.create_subprocess_exec` for cosign sign-blob (T14.A) + syft SBOM + grype vuln scan + license auditor (pip-licenses) + AgentCard JWS (joserfc, agent packs only) + SLSA provenance template render + in-toto layout template render + 7-attestation persister. Closed-enum `SignReason` covers every refusal taxonomy.
- **`src/cognic_agentos/cli/verify.py`** — `agentos verify` offline trust gate (T14). **11-step orchestrator** mirroring the Sprint-4 runtime trust-gate verification path; R15 PIVOT moved the load probe from step 5c to **step 11 (FINAL gate)** so pack code never executes until every non-executing trust check has passed (R15 follow-up round 2 P2 #1).
- **`src/cognic_agentos/cli/_load_probe.py`** — isolated-subprocess `EntryPoint.load()` probe (T14, R15 PIVOT). Replaces 14 rounds of static-AST loadability whack-a-mole with a real load attempt. `sys.executable -I` + minimal PATH+HOME env + asyncio timeout + SIGKILL + reap. **Result-channel hardened five layers deep** (R15 follow-up round 2 P2 #2): fd inheritance via `pass_fds` (no path in argv/env); per-invocation 256-bit hex success token via env that the child pops to a local before any imported-module code runs; all probe state in `_run_probe()` locals (NOT `__main__` globals); `sys.argv` stripped after capture; token written by probe-owned code only after `ep.load()` returns; parent enforces token match — mismatch routes to closed-enum `load_probe_success_token_mismatch` (refusal, fail-closed). Stdout/stderr redirected to `os.devnull` file objects (bounded discard, NOT `io.StringIO()`).
- **`src/cognic_agentos/cli/_wheel_integrity.py`** — wheel identity + dist-info + METADATA + entry-point shape validator (T14, R15 follow-up round 1 P2 #1). Helper threads the validated `(module_path, object_path)` tuples to verify via 4-tuple return so the load probe operates on exactly the source the integrity helper validated — eliminates the path-suffix re-discovery anti-pattern that would otherwise let a decoy `aaa/entry_points.txt` redirect the probe.

### Reference packs (Sprint-7A T15)

- **`examples/cognic-tool-example-minimal/`** + **`examples/cognic-skill-example-minimal/`** + **`examples/cognic-agent-example-minimal/`** — three minimal-but-valid reference packs. Inert by design (tool returns `{"echo": <input>}`; skill round-trips through the bound `ToolRegistry`; agent's `handle()` returns `{"text": "ok"}`). The agent pack ships an explicit test-only RSA-2048 keypair under `attestations/test-signing/` + a `NOTE.md` spelling out the test-only doctrine + the `prod`-profile rejection guard at `core/config.py::_validate_signing_key_path_prod_profile_guard`.
- **`tests/unit/cli/test_reference_packs_full_lifecycle_green.py`** — full-lifecycle CI gate. Per-kind expectation matrix locked in: tool harness PASSES, skill + agent harness REFUSE with `harness_unsupported_pack_kind`. The committed reference packs stay STATIC; all sign/verify outputs (the seven attestations + agent-card.jws) are generated under `tmp_path` during the lifecycle test and never reach disk in `examples/`.

### Critical-controls coverage gate extension (Sprint-7A T16)

- **`tools/check_critical_coverage.py`** — extended in T16 with the Sprint-7A authoring SDK + CLI **nonet** at the same single strict 95% line / 90% branch floor: `cli/validate.py`, `cli/validators/identity.py`, `cli/validators/a2a.py` (T8 deferred call resolved at T16), `cli/validators/data_governance.py`, `cli/validators/supply_chain.py`, `cli/sign.py`, `cli/verify.py`, `cli/_load_probe.py`, `cli/_wheel_integrity.py`. Off-gate per the pure-delegation rule: `cli/validators/mcp.py` + `cli/validators/risk_tier.py` (author calls at T9 + T11 commit time stand on T16 review). Gate now enforces **37 modules**; all PASS at current coverage.

### Three Wave-1 author docs (Sprint-7A T16)

- **`docs/HOW-TO-WRITE-A-PACK.md`** — author tutorial. Section 0 (Sprint-7A `agentos` CLI quickstart) prepended to the existing Sprint-4 plumbing detail (Sections 1-7). Canonical workflow order locked in throughout: **`init → build wheel → sign --bundle → validate → test-harness → verify`** (sign-before-validate per the static-only-committed-state doctrine since `agentos validate` checks every declared `supply_chain.attestation_paths` is present on disk + non-empty). Wave-1 narrow harness contract correctly documented (no transport interception; pack code runs against unmodified host runtime).
- **`docs/SDK-REFERENCE.md`** (NEW) — Tool/Skill/Agent base-class API + `ToolRegistry` protocol + testing pytest fixtures (correctly documented as pytest fixtures, NOT standalone callables — `fixture_settings(tmp_path)` + `fixture_tool_registry()`) + ISO 42001 control-declaration helpers (`declare_iso_42001_controls` Wave-1 append-only semantics correctly documented; idempotency + conflict-detection deferred to a follow-up sprint) + stability and versioning policy.
- **`docs/PACK-MANIFEST-SPEC.md`** (NEW) — full schema for `cognic-pack-manifest.toml`. Every block, every closed-enum, every cross-check, the schema-version-bump policy.

## CI / production-grade gates

| Gate | Workflow | Trigger | Behaviour |
|---|---|---|---|
| Lint + types + tests | `python.yml` → `lint + test` | push / PR | unchanged — `ruff` + `ruff format --check` + `mypy` strict + `pytest -v` |
| Per-file critical-controls coverage gate | `python.yml` → `lint + test` | push / PR | `tools/check_critical_coverage.py` against `coverage.json` — fails CI if any of the **37** critical-controls modules drops below 95% line OR 90% branch (extended in Sprint-7A T16 to add the authoring SDK + CLI nonet) |
| MCP STDIO architecture test | `python.yml` → `lint + test` | push / PR | unchanged — Sprint-5 floor of `>= 5` stays |
| A2A no-subprocess architecture test | `python.yml` → `lint + test` | push / PR | unchanged — Sprint-6 closeout's `>= 9` floor stays |
| A2A caller-URL architecture test | `python.yml` → `lint + test` | push / PR | unchanged — Sprint-6 |
| A2A spec-drift CI gate | `python.yml` → `a2a-spec-drift` (env-gated `COGNIC_RUN_A2A_UPSTREAM=1`) | push / PR | unchanged — Sprint-6 |
| Image-size budget + boot smoke (kernel) | `python.yml` → `image size budget` | push / PR | unchanged — kernel still ≤120 MiB; Typer + Jinja2 + joserfc all under existing extras |
| Image-size budget + boot smoke (default-adapters) | `python.yml` → `image size budget` | push / PR | unchanged |
| Live Postgres / Oracle integration | `python.yml` → `postgres integration` / `oracle integration` | push / PR | unchanged |

## Doctrine adherence

- **AGENTS.md per-edit halt-before-commit on critical-controls modules.** Every commit that touched a critical-controls module paused for explicit user authorization. T6 (validate orchestrator) was halt-reviewed; T7 (identity) was halt-reviewed; T8 (a2a) halt-reviewed (off-gate at T8 commit, promoted at T16); T9 (mcp) halt-reviewed (off-gate per pure-delegation); T10 (data_governance) halt-reviewed; T11 (risk_tier) halt-reviewed (off-gate per pure-delegation); T12 (supply_chain) halt-reviewed; T13 (test-harness) halt-reviewed across **R31-R34** (4 behavioral reviewer rounds folding the Wave-1 narrow contract); T14.A (cosign sign-blob) halt-reviewed across R1 P2 #1+#2 (behavioral); T14.B (sign --bundle full orchestrator) halt-reviewed across **R1-R11** (11 behavioral reviewer rounds). **T14 (verify + load_probe + wheel_integrity + R15 PIVOT)** owns ALL R15 load-probe integration-seam findings — halt-reviewed across **R1-R15 PIVOT** (replacing the static-AST loadability analyzer with the isolated-subprocess load probe; behavioral) plus **R15 follow-up rounds 1-4** (11 findings total, mix of behavioral + doc-only):

  - Round 1 (3 behavioral): decoy `entry_points.txt` redirect; single-EP probe (only first cognic entry-point was load-tested); unbounded `io.StringIO()` redirect sink.
  - Round 2 (2 behavioral): step-ordering (load probe moved from step 5c to step 11 — FINAL gate); result-channel hardening (5-layer fd inheritance + per-invocation success token).
  - Round 3 (3 mixed): stray `14` repo-root artifact + fd-vs-path mismatch in the unparseable-output test (test-fix, behavioral); `_wheel_integrity.py` module-level contract docstring drift (doc-only); "step 5c" test-comment drift in 2 sites (doc-only).
  - Round 4 (3 doc-only): "step 5c" production-comment drift in `verify.py` adapter docstring + `sign.py` 4-tuple-unpack comment + `_wheel_integrity.py` validated-entry-points local comment.

  **T15 (three reference packs + full-lifecycle CI gate)** halt-reviewed across one **R-round (doc-only)** — README command order + manifest header comments + agent-card.json description all corrected from the aspirational `validate → harness → sign` ordering to the realistic `sign → validate → harness → verify` ordering required by the static-only-committed-state doctrine. **T16 (critical-controls coverage gate +9 modules + 3 docs)** had Section AD coverage tests landed during the planned T16 Step 3 ("if any module short of 95/90, add tests") to lift `verify.py` + `_load_probe.py` to the 95/90 floor — that's planned T16 deliverable, not a reviewer-round response. T16's two **R-rounds were both doc-only**: round 1 corrected `HOW-TO-WRITE-A-PACK` Section 0 workflow order + the harness-isolated-subprocess overstatement + `SDK-REFERENCE` pytest-fixture signature wrongness + the non-existent `emit_compliance_event` API; round 2 corrected residual workflow-order drift in the HOW-TO banner + the SDK-REFERENCE intro + the false `declare_iso_42001_controls` idempotency/conflict-detection claim. T17 (this closeout) halts before commit on AGENTS.md (doctrine document) + BUILD_PLAN.md (sprint status), with one R-round-1 ledger correction itself. **Behavioral findings produced regression tests pinning the fix; doc-only findings were closed by text edits + drift / static-gate audits.**
- **AGENTS.md `core/canonical.py` per-edit stop rule.** Not touched in Sprint 7A.
- **Closed-enum vocabulary doctrine.** Every refusal vocabulary is a `Literal[...]` pinned by a drift detector. `ValidatorReason` (orchestrator-side, ~38 values across the six validators); `HarnessReason` (7 values inc. `harness_unsupported_pack_kind`); `SignReason` (~28 values across the bundle pipeline); `VerifyReason` (~17 values inc. the closed-enum `verify_entry_point_load_failed` with 8 sub-cases via `payload.failure_mode`: `load_probe_module_import_failed` / `load_probe_object_not_found` / `load_probe_module_runtime_error` / `load_probe_timeout` / `load_probe_subprocess_error` / `load_probe_unparseable_output` / `load_probe_no_validated_entry_points` / `load_probe_success_token_mismatch`). Drift detectors live in `tests/unit/test_config.py::TestSprint7AClosedEnumVocabulary`.
- **R15 PIVOT — load probe over static analysis (Sprint-7A doctrine).** When a static AST loadability guard hits whack-a-mole reviewer findings (R13 R14 R15 each closed named cases while adjacent Python import-time constructs slipped through), replace it with a real isolated-subprocess load probe (minimal env, timeout, isolation) and keep the static check narrow (identity + dist-info + entry-point syntax + basic module/object declaration). Documented in memory: `feedback_load_probe_over_static_analysis.md`.
- **Static-only-committed-state doctrine (T15).** Reference packs commit only static artifacts (manifest + pyproject + inert source + README + agent-card.json seed + agent test-only keypair); ALL sign/verify outputs land in `tmp_path` during the lifecycle test, never in `examples/`. Eliminates drift risk that pre-generated committed attestations would carry.
- **Sign-before-validate flow doctrine (T15 + T16).** `agentos validate` checks every declared `supply_chain.attestation_paths` file is present on disk + non-empty. The realistic author flow is `scaffold → fill manifest → build wheel → sign → validate → harness → publish`; running `agentos validate` on a fresh checkout (before any sign) refuses with `supply_chain_attestation_path_unresolvable` — that's the expected shape. Pinned across the canonical author tutorial + reference-pack READMEs + lifecycle test docstrings + SDK-REFERENCE intro.
- **Wave-1 narrow harness contract (T13 R31-R34, surfaced in T16 docs).** `agentos test-harness` runs tool `_invoke()` against the **unmodified host runtime** — no `httpx.MockTransport`, no `fixture_settings` injection, no env scoping, no sandbox. Pack authors who need fixture-adapter isolation wire it themselves in their pack test suite. Pinned by `test_run_harness_wave1_narrow_contract_no_transport_interception`.
- **Test-only keypair pattern (T14 + T15).** RSA-2048 PKCS8 PEM committed under `attestations/test-signing/` with explicit `NOTE.md` rationale. Two protections: (1) `prod` settings profile rejects any `signing_key_path` pointing inside `tests/fixtures/` or `examples/` at startup; (2) the `test_signing_key` naming + the NOTE alongside both PEMs make the test-only intent unmissable. Mirrored across the T14 fixture pack at `tests/fixtures/cli_sign_target_pack/` + the T15 agent reference pack at `examples/cognic-agent-example-minimal/`.

## Test + coverage state

- **Suite size:** 3849 passed + 30 skipped (skips are live-Postgres / live-Oracle / live-A2A-upstream integration opt-ins gated on env vars).
- **Sprint-7A delta:** Sprint-6 merge baseline at `35e9016` was 3013 passed + 30 skipped → Sprint-7A ready state 3849 + 30 = **+836 passed**.
- **Global coverage:** ~96% (cognic_agentos package).
- **Per-file critical-controls coverage gate (37 modules at 95/90):**

| Module | Sprint | Line% | Branch% | Status |
|---|---|---|---|---|
| `core/audit.py` | 2 | ≥95 | ≥90 | PASS |
| `core/canonical.py` | 2 | ≥95 | ≥90 | PASS |
| `core/chain_verifier.py` | 2 | ≥95 | ≥90 | PASS |
| `core/decision_history.py` | 2 | ≥95 | ≥90 | PASS |
| `core/sla.py` | 2.5 | ≥95 | ≥90 | PASS |
| `core/escalation.py` | 2.5 | ≥95 | ≥90 | PASS |
| `core/guardrails.py` | 2.5 | ≥95 | ≥90 | PASS |
| `llm/gateway.py` | 3 | ≥95 | ≥90 | PASS |
| `llm/policy.py` | 3 | ≥95 | ≥90 | PASS |
| `llm/preflight.py` | 3 | ≥95 | ≥90 | PASS |
| `llm/ledger.py` | 3 | ≥95 | ≥90 | PASS |
| `llm/concurrency.py` | 3 | ≥95 | ≥90 | PASS |
| `protocol/plugin_registry.py` | 4 | ≥95 | ≥90 | PASS |
| `protocol/trust_gate.py` | 4 | ≥95 | ≥90 | PASS |
| `protocol/supply_chain.py` | 4 | ≥95 | ≥90 | PASS |
| `core/policy/engine.py` | 4 | ≥95 | ≥90 | PASS |
| `protocol/mcp_authz.py` | 5 | ≥95 | ≥90 | PASS |
| `protocol/mcp_capabilities.py` | 5 | ≥95 | ≥90 | PASS |
| `protocol/mcp_manifest.py` | 5 | ≥95 | ≥90 | PASS |
| `protocol/mcp_transports.py` | 5 | ≥95 | ≥90 | PASS |
| `protocol/mcp_host.py` | 5 | ≥95 | ≥90 | PASS |
| `protocol/a2a_authz.py` | 6 | 100 | 100 | PASS |
| `protocol/a2a_agent_cards.py` | 6 | 95.27 | 100 | PASS |
| `protocol/a2a_endpoint.py` | 6 | 96.14 | 92.42 | PASS |
| `protocol/a2a_schema.py` | 6 | 100 | 100 | PASS |
| `protocol/a2a_version.py` | 6 | 100 | 100 | PASS |
| `protocol/a2a_errors.py` | 6 | 100 | 100 | PASS |
| `protocol/ui_events.py` | 6 | 100 | 100 | PASS |
| `cli/validate.py` | 7A | 100 | 100 | PASS |
| `cli/validators/identity.py` | 7A | 100 | 100 | PASS |
| `cli/validators/a2a.py` | 7A | 100 | 100 | PASS |
| `cli/validators/data_governance.py` | 7A | 100 | 100 | PASS |
| `cli/validators/supply_chain.py` | 7A | 100 | 100 | PASS |
| `cli/sign.py` | 7A | 100 | 100 | PASS |
| `cli/verify.py` | 7A | 95.75 | 95.09 | PASS |
| `cli/_load_probe.py` | 7A | 100 | 100 | PASS |
| `cli/_wheel_integrity.py` | 7A | 95.19 | 95.45 | PASS |

## ADR validation

| ADR | Title | Sprint-7A relevance | Status |
|---|---|---|---|
| ADR-008 | Authoring platform — SDK + CLI now, Studio UI deferred | Phase A — SDK base classes + `agentos` CLI + init scaffolders + validate orchestrator + test-harness + sign + verify shipped | ✅ |
| ADR-014 | Runtime tool approval — per-tool risk tiers | Build-time half — `cli/validators/risk_tier.py` enforces tier-to-data-class consistency at validate time | ✅ |
| ADR-016 | Supply-chain controls — cosign + SLSA L3+ + in-toto + SBOM + vuln + license + Sigstore retention | Build-time half — `cli/sign.py` produces the full bundle; `cli/verify.py` is the offline trust gate mirroring runtime; both modules added to critical-controls gate | ✅ |
| ADR-017 | Data-governance contracts | Build-time half — `cli/validators/data_governance.py` enforces the contract at validate time; runtime DLP enforcement consumes the same closed-enum vocabulary | ✅ |

## Doctrine amendments accepted (Sprint-7A)

- **R23 doctrine: dual-path lookup** (canonical top-level [block] + legacy `[tool.cognic.block]`). Every per-concern validator + the runtime A2A/MCP capability readers walk both shapes; the canonical shape wins on conflict; `payload.block_path` carries the source for diagnosis.
- **Doctrine Decision G — Critical-controls gate floor + promotion rule.** Validators that own non-trivial allow/deny logic join the gate; pure-delegation wrappers stay off. T8 (a2a) had a "deferred to T16" promotion call — resolved at T16 closeout as on-gate (refusal paths runtime reader does not have qualify as policy). T9 (mcp) + T11 (risk_tier) author-call off-gate stands on T16 review.
- **R15 PIVOT doctrine.** Replace static-AST loadability with isolated-subprocess load probe when whack-a-mole rounds expose adjacent uncovered constructs; keep the static check narrow.
- **Sign-before-validate flow doctrine.** Static-only-committed-state means validate cannot pass on a clean checkout; sign produces the attestations validate then verifies present. Pinned across author docs + reference-pack READMEs + lifecycle test.
- **Test-only keypair pattern.** Committed RSA-2048 PEM pair under `attestations/test-signing/` with explicit NOTE + `prod`-profile rejection guard.
- **Wave-1 narrow harness contract.** Harness runs against unmodified host runtime; no sandboxing.

## Sprint-7A2 hand-off checklist (load-bearing)

Sprint-7A2 picks up **hook packs + the runtime hook engine** before Sprint-7B freezes the bank lifecycle API around pack-kind storage and workflow contracts. This keeps Sprint-7B's existing lifecycle scope intact while ensuring it supports all four authoring pack kinds (`tool | skill | agent | hook`) from day one.

- [ ] `sdk/hook.py` — first-class `Hook` base/protocol plus `HookContext` and `HookResult`.
- [ ] `agentos init-hook` + inert `examples/cognic-hook-example-minimal/` reference pack.
- [ ] Manifest + entry-point support for `kind = "hook"` and `[project.entry-points."cognic.hooks"]`.
- [ ] `agentos validate`, `agentos sign --bundle`, and `agentos verify` support hook packs under the same identity, supply-chain, wheel-integrity, and isolated-load-probe discipline as tools/skills/agents.
- [ ] Runtime hook registry + deterministic dispatcher with ordering, timeout, fail-closed default for governed-data phases, and audit evidence.
- [ ] ADR-017 DLP wiring: pre-hooks run before governed input reaches pack code; post-hooks run before governed output leaves AgentOS.
- [ ] Sprint-7B forward-compat constraint: pack lifecycle storage/API must treat pack kind as `tool | skill | agent | hook`, not a hard-coded three-kind enum.

## Sprint-7B hand-off checklist (after 7A2)

Sprint-7B then picks up the **bank pack lifecycle API + workflow + UI event-stream endpoints** track per ADR-012 + PROJECT_PLAN §7-8.

- [ ] `packs/lifecycle.py` — pack-record lifecycle state machine consuming the Sprint-7A / Sprint-7A2 SDK + CLI surface (`agentos sign --bundle` produces the artefacts; lifecycle binds them to a Postgres record).
- [ ] **Harness expansion to skill + agent dispatch.** Sprint-7A T13 narrowed `_HARNESS_SUPPORTED_KINDS = frozenset({"tool"})`. Sprint-7B grows the dispatch table to `{"tool", "skill", "agent"}` AND routes via a kind-aware `_dispatch_one` that handles Skill's `ToolRegistry` instantiation requirement + Agent's `handle(payload, *, task)` signature. Hook dispatch remains owned by the Sprint-7A2 hook dispatcher, not the test harness. The skill + agent reference packs at `examples/` already exercise the `harness_unsupported_pack_kind` refusal path; the Sprint-7B expansion lands the green-path.
- [ ] **UI event-stream endpoints (ADR-020).** Sprint-6 seeded all 11 Wave-1 event-family models + wired 3 emit hooks (`tool_call.*`, `artifact.*`, `decision_audit.event_appended`). Sprint-7B lands the SSE endpoint at `GET /api/v1/runs/{run_id}/events`. Reconnect-safe via `decision_history` mirror per ADR-020.
- [ ] **Realtime auto-attestation API.** Sprint-7A's `cli/sign.py` produces the bundle at sign time; the runtime equivalent (auto-attestation as the pack runs) ships in Sprint-7B alongside the lifecycle API.
- [ ] **Compliance helper emit path.** Sprint-7A ships the declaration shape (`declare_iso_42001_controls`); per-event emission into the audit chain lands in a follow-up sprint with the runtime auto-attestation API.

## Carryover

None. Every plan §1503-1530 deliverable for T16 + every plan §1533-1574 deliverable for T17 landed.

## Out of scope (Sprint-7A intentionally did NOT ship)

- **Bank pack lifecycle state machine + Postgres record store** — Sprint-7B per ADR-012 + PROJECT_PLAN §7-8.
- **Hook packs + runtime hook engine** — Sprint-7A2 per the post-closeout sequencing amendment; hooks are authoring/platform primitives, not productized bank-specific packs.
- **Studio UI authoring** — ADR-008 Phase B; explicitly deferred per ADR-008 + ADR-021 reservation.
- **Skill + agent harness dispatch** — Sprint-7B per the harness expansion task in the hand-off checklist above.
- **Compliance per-event emit path** — follow-up sprint alongside runtime auto-attestation.
- **Realtime SSE endpoint** — Sprint-7B per ADR-020.

## Next sprint

**Sprint 7A2 — Hook packs + runtime hook engine** *(2.5 work-units)*. See `docs/BUILD_PLAN.md` §"Sprint 7A2". Sprint 7B remains the bank pack lifecycle API + workflow + UI event-stream sprint and must consume `tool | skill | agent | hook` from day one.
