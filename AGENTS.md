# Cognic AgentOS — Operating Model

## Core principle

This repo ships **AgentOS only**: the hardened governance + runtime + protocol kernel that banks deploy once and run forever. Agents, tools, and skills are out of scope here — they ship as separately-versioned plugin packs that install on top of AgentOS.

## What lives where

| Lives in cognic-agentos (this repo) | Lives elsewhere |
|---|---|
| Governance kernel (`core/`) | Layer C agents (`cognic-agent-<name>` repos) |
| Harness (`harness/base_agent.py`) | Per-agent workflows (ship in agent packs) |
| LLM gateway, retrieval orchestrator, persistence, observability | Per-agent eval scorers (ship in agent packs) |
| Channels, RBAC, portal API + workbench | UI (`cognic-portal-ui` separate artefact) |
| Plugin registry + MCP host + A2A endpoint | Tool packs (`cognic-tool-<name>` MCP servers) |
| Sandbox + sub-agent primitives | Skill packs (`cognic-skill-<name>` MCP-composing services) |
| ISO 42001 compliance evidence | Bank-specific overlays (themes, OIDC, custom CBS adapters) |

If you find yourself adding a Layer C agent or persona-specific workflow inside this repo, **stop**. It belongs in its own pack repo.

## Operating modes

### Autonomous low-risk build
Scaffolding, boilerplate, OS-tier tests, mock data inside test paths only, docs, and integration glue.

### Pair-engineering
Critical controls — anything in `core/`, `compliance/`, `protocol/plugin_registry`, `sandbox/`, `subagent/`, or that touches RBAC / cloud-policy / decision-history. Use `core-controls-engineer`.

### Review-and-hardening
Refactors, PR cleanup, negative-path tests, ADRs, evidence docs, RCA notes, release checks.

## Session protocol

1. Identify what you're touching: governance kernel? protocol layer? plugin discovery? portal API? OS subpackage?
2. Read the relevant ADR before editing
3. Keep changes inside declared scope
4. Run tests and document remaining risks
5. Update ADR / evidence if the change requires it

## Stop rules

Stop for human review when touching:
- Anything in `core/` (governance primitives, including `core/approval`, `core/policy`, `core/emergency`, `core/memory`)
- **Hash-chain canonical-form** (`core/canonical.py` — `canonical_bytes`, `hash_record`, `_json_default`, `ZERO_HASH`). Canonical form is the wire-format for evidence-pack export per ADR-006; any change is a wire-protocol change that breaks past evidence verification. Requires human review on **every** edit, not just non-trivial ones, plus an explicit `schema_version` bump in `audit_event` + `decision_history` migrations. (Sprint 2 amendment, 2026-04-28.)
- Plugin trust gate / signature verification (`protocol/plugin_registry.py`, `protocol/trust_gate.py`, `protocol/supply_chain.py`)
- MCP / A2A authorization paths (`protocol/mcp_authz.py`, `protocol/a2a_authz.py`)
- Sandbox or sub-agent enforcement boundaries (including resumable-session checkpoint/wake)
- Cloud-policy enforcement (`llm/gateway.py`)
- ISO 42001 control mapping
- RBAC (`portal/rbac/`)
- Wire-protocol contracts (MCP / A2A schemas, including A2A protobuf source + version-negotiation)
- Evidence-pack format (changes how examiners audit)
- Model registry lifecycle transitions (`models/` + `models/trust.py`)
- Pack data-governance contracts (`packs/evidence/data_governance.py`, runtime DLP enforcement)
- Kill-switch / quota enforcement (`core/emergency/kill_switches.py`, `core/emergency/quotas.py`)
- Policy-as-code engine (`core/policy/engine.py` + Rego bundles in `policies/_default/`)
- Memory governance enforcement (`core/memory/` per ADR-019)
- UI event-stream contract (`protocol/ui_events.py` per ADR-020 — public event schema, must remain backward-compatible across versions)

## Critical-controls rule

The following modules are **critical controls**. They get extra scrutiny — 95%+ test coverage, negative-path tests required, no casual refactors:

*Core governance:*
- `core/audit.py`
- `core/canonical.py` (Sprint 2 — single source of truth for canonical form + SHA-256 framing; wire-format for evidence-pack export)
- `core/decision_history.py` + `core/chain_verifier.py`
- `core/guardrails.py`
- `core/escalation.py`
- `core/sla.py`
- `core/auto_degradation.py`
- `core/citation.py`
- `retrieval/citation_verifier.py`

*Runtime authority + emergency (Sprint 13.5):*
- `core/approval/engine.py` (per ADR-014 — runtime tool approval; 4-eyes; risk-tier enforcement)
- `core/policy/engine.py` (per ADR-015 — Rego decision engine for admission, routing, approval, egress, sub-agent spawn, lifecycle)
- `core/emergency/kill_switches.py` + `core/emergency/quotas.py` (per ADR-018 — fail-closed kill switches with ≤30s P99 propagation)

*Plugin trust + supply chain:*
- `protocol/plugin_registry.py` (entry-point discovery)
- `protocol/trust_gate.py` (cosign verification)
- `protocol/supply_chain.py` (per ADR-016 — SLSA + in-toto + SBOM + vuln + license + Sigstore bundle retention)

*Protocol authorization:*
- `protocol/mcp_authz.py` (per ADR-002 amendment — OAuth/PRM token cache + refresh + AS allow-list; also listed under "Protocol — MCP host (Sprint 5)" below)
- `protocol/a2a_authz.py` (per ADR-003 — per-tenant token authorization + Wave 2 mTLS hook + Wave 3 VC hook; also listed under "Protocol — A2A endpoint (Sprint 6)" below)

*Protocol — MCP host (Sprint 5):*
- `protocol/mcp_authz.py` (per ADR-002 amendment — already in critical-controls list pre-Sprint-5; gate enforcement extended in Sprint 5)
- `protocol/mcp_capabilities.py` (per ADR-002 + MCP-CONFORMANCE.md — manifest validation, capability default-deny enforcement, STDIO four-gate + Decision Lock umbrella, sampling four-condition gate via OPA Rego)
- `protocol/mcp_manifest.py` (per Sprint-5 R1 P2 #2 — signed-manifest extractor; deferred-load invariant via `Distribution.locate_file()` without importing pack code per ADR-002 §gate 1)
- `protocol/mcp_transports.py` (per Sprint-5 Decision Lock — Streamable HTTP transport with per-event hook-failure semantics + STDIO refusal-only stub; Sprint-8 launcher is a separate critical-controls module added then)
- `protocol/mcp_host.py` (per ADR-002 — admission-to-invocation orchestrator; ADR-014 transitional risk-tier gate; audit + decision-history correlation via `_emit_call_evidence`; per-tenant `list_tools` cache + bounded pagination + opaque cursor fingerprints + deep-copy descriptors)

*Protocol — A2A endpoint (Sprint 6):*
- `protocol/a2a_authz.py` (per ADR-003 — already in critical-controls list pre-Sprint-6 under "Protocol authorization"; gate enforcement extended in Sprint 6 T15. Per-tenant pinned-token validation with closed-enum 8-value `A2AAuthzReason`; Vault-rotated; anonymous-A2A forbidden Wave-1; Vault-read exception mapping per Sprint-5 T15 R1 P2 #2 doctrine)
- `protocol/a2a_agent_cards.py` (per ADR-003 + A2A-CONFORMANCE.md — three-pass card validator: Pass 1 upstream A2A 1.0 schema + Pass 2 AgentOS bank-grade profile (provider, securitySchemes, securityRequirements, signatures, ≥1 supportedInterfaces entry, **+ T14 Wave-2 auth refusal — any `mtlsSecurityScheme` declared anywhere in `securitySchemes` refused under Wave-1 bearer-token policy with closed-enum reason `agent_card_profile_wave2_auth_required`**) + Pass 3 JWS verification against Sprint-4 `TrustGate` per-tenant trust root. Identity-routing critical: a forged or tampered card routes outbound traffic to attacker-controlled endpoints. 11-value `AgentCardValidationReason` literal. Outbound dispatch path also pins `A2A-Version: 1.0` header on every `_http.get` per T14 Fix #2)
- `protocol/a2a_endpoint.py` (per ADR-003 — inbound receiver + task lifecycle state machine (created → running → succeeded / failed / cancelled) + cross-agent chain linkage via parent-trace + child-trace propagation. Anonymous-refusal gate + Wave-2-refusal gate + caller-URL refusal at the routing gate (URL-shaped `target_agent` → spec wire code `method_not_found` + `policy_reason="unknown_target"`) live here. Single-writer for `TaskState` transitions via `_transition`; pinned by an AST-walk regression in `a2a_cancellation.py`)
- `protocol/a2a_schema.py` (per ADR-003 — pinned A2A 1.0 wire-format types via `a2a-sdk == 1.0.2` re-exported through PEP 562 lazy `__getattr__` so the module imports cleanly without the SDK installed; first attribute access fires `require_a2a()`. Wire-format drift = wire-protocol break; the schema-drift CI gate in `tests/unit/protocol/test_a2a_schema_drift.py` (env-gated on `COGNIC_RUN_A2A_UPSTREAM=1`) catches upstream movement before it reaches us. Pinned digest constants + the upstream URL constants live here)
- `protocol/a2a_version.py` (per ADR-003 + AGENTS.md §"Wire-protocol contracts" — A2A-Version header negotiation; closed-enum 6-case `A2AVersionOutcome` matrix (`accepted` / `absent_rejected` / `legacy_rejected` / `higher_minor_degraded` / `unsupported_rejected` / `malformed_rejected`); rejecting absent-header per spec — the spec interprets absent as A2A 0.3 which AgentOS does not implement. Module is small + pure-functional but the doctrinal surface is wire-protocol-public; promoted from non-critical at Sprint-6 T15 R0 P2 #4 + R2 P2 #4. Source-of-truth for `PINNED_VERSION = "1.0"` shared between inbound negotiator + outbound `a2a_agent_cards._http.get` callers)
- `protocol/a2a_errors.py` (per ADR-003 — owns the spec wire `A2AErrorCode` literal (14 spec-defined codes) + the AgentOS `A2APolicyRefusalReason` literal (11 policy reasons including `unknown_target` / `wave2_feature_refused` / `agent_card_signer_not_allowlisted`) + the `_POLICY_REASON_TO_SPEC_CODE` mapping that drives the error-response builder. Drift in any of these changes what remote A2A callers see; promoted from non-critical at Sprint-6 T15 R3 P2 #2 — earlier draft kept this non-critical because the module is "just enums"; reviewer correctly flagged that the mapping IS wire-protocol contract)
- `protocol/ui_events.py` (per ADR-020 stop rule — Wave-1 typed event taxonomy + emit-hook layer. Public event schema; MUST remain backward-compatible across versions. All 11 Wave-1 Pydantic event-family models seeded in Sprint 6 (agent_run / tool_call / subagent / approval / artifact / interrupt / frontend_action / memory / decision_audit / policy / kill_switch); two-level discriminated union (per-family inner on `type`, top-level on `family`); 3 families wired with emit hooks in Sprint 6 (`tool_call.*`, `artifact.*`, `decision_audit.event_appended`); per-hook deep-copy isolation + tuple-snapshot at dispatch entry to defend against self-registering hooks. Other 8 families have model-only stubs; their emit hooks land in their owning sprints per the ADR-020 phase table)

*Authoring — SDK + CLI (Sprint 7A):*
- `cli/validate.py` (per ADR-008 — orchestrator that coordinates the six per-concern validators + the shape gate against the canonical [pack] / [identity] / [a2a] / [mcp] / [data_governance] / [risk_tier] / [supply_chain] block layout; build-time half of the trust gate; mirrors the runtime `protocol/plugin_registry.py` admission orchestrator. Closed-enum `ValidatorReason` literal at `cli/__init__.py` carries every refusal taxonomy across the six per-concern validators.)
- `cli/validators/identity.py` (per ADR-002 amendment + AGNTCY/OASF Wave-1 strictness — three-tier identity matrix: mandatory fields (agent_id / display_name / provider_organization / provider_url / agent_card_url; agent_card_jws_path agent-only) refuse on missing; optional Wave-1-only-in-Wave-2 fields (oasf_capability_set) warn on missing; Wave-3-reserved fields (verifiable_credentials_path) refuse only if present + path malformed. Wire-protocol-public for cross-org agent discovery.)
- `cli/validators/a2a.py` (per ADR-003 — Wave-2 capability-feature refusal on the [a2a] block. Single Wave-2 refusal mirroring the runtime `read_pack_capabilities` filter; runtime silently filters, validator REFUSES manifest at build time. Dual-path lookup via R23 doctrine. Promoted to critical-controls at Sprint-7A T16 closeout — T8 author's deferred call resolved on the rule "non-trivial allow/deny logic" since refusal paths runtime does not have qualify as policy.)
- `cli/validators/data_governance.py` (per ADR-017 — runtime DLP enforcement depends on this contract being well-formed at build time. Validates closed-enum `data_classes` / `purpose` / `retention_policy` / `egress_allow_list` shapes + `retention_max_window` conditional requirement when `retention_policy != "none"` + cross-validation against `[risk_tier].tier`. Closed-enum vocabularies live at `cli/_governance_vocab.py`.)
- `cli/validators/supply_chain.py` (per ADR-016 — feeds the runtime trust gate. Validates `[supply_chain].attestation_paths` is non-empty + every declared file is reachable + non-empty + path-traversal-safe + AUTHOR-FILL-free. Closed-enum `supply_chain_attestation_path_unresolvable` carries five sub-cases via `payload.failure_mode`.)
- `cli/sign.py` (per ADR-016 — full bundle generator: cosign sign-blob + syft SBOM + grype vuln scan + license audit (pip-licenses) + AgentCard JWS (joserfc, agent packs only) + SLSA provenance template render + in-toto layout template render + 7-attestation persister. Security-critical signing path; the path that produces the cosign signature the runtime trust gate verifies. T14.A landed cosign sign-blob; T14.B landed the orchestrator + the four other supply-chain binaries + JWS + SLSA + in-toto.)
- `cli/verify.py` (per ADR-016 — offline trust gate; mirrors the Sprint-4 runtime trust-gate verification path. **11 numbered steps** (substeps 3b + 5b carry related setup off the main spine): Step 1 trust-root resolution → Step 2 manifest pack-kind → Step 3 attestation-file existence probes (7 files) [substep 3b reads pyproject metadata for the wheel cross-check] → Step 4 wheel discovery → Step 5 cosign verify-blob [substep 5b wheel-anchored integrity check: kind / name / version / entry-points 4-tuple] → Step 6 SBOM digest match → Step 7 SLSA provenance shape + wheel-subject match → Step 8 in-toto layout shape + expected-artifact-set → Step 9 AgentCard JWS (agent packs only) → Step 10 manifest re-validation via the full validate pipeline → **Step 11 load probe (FINAL gate)**. R15 follow-up round 2 P2 #1: load probe was originally step 5c; promoted to step 11 so pack code never executes until every non-executing trust check has passed.)
- `cli/_load_probe.py` (per ADR-016 + R15 follow-up round 2 P2 #2 — isolated-subprocess `EntryPoint.load()` probe. Step 11 of the verify trust pipeline. Probe runs under `sys.executable -I` with minimal PATH+HOME env, asyncio timeout + SIGKILL + reap. **Result-channel hardened five layers deep**: fd inheritance via pass_fds (no path in argv/env); per-invocation 256-bit hex success token via env that the child pops to a local before any imported-module code runs; all probe state in `_run_probe()` locals (NOT __main__ globals); sys.argv stripped after capture; token written by probe-owned code only after `ep.load()` returns; parent enforces token match — mismatch routes to closed-enum `load_probe_success_token_mismatch` (refusal, fail-closed). Stdout/stderr redirected to `os.devnull` file objects (bounded discard, NOT `io.StringIO()` — R15 follow-up round 1 P3 fix prevents print-in-loop OOM in child).)
- `cli/_wheel_integrity.py` (per ADR-016 + R15 follow-up round 1 P2 #1 — wheel identity + dist-info + METADATA + entry-point shape validator. Helper threads the validated `(module_path, object_path)` tuples to verify via 4-tuple return so the load probe operates on exactly the source the integrity helper validated. Eliminates the path-suffix re-discovery anti-pattern that would otherwise let a decoy `aaa/entry_points.txt` redirect the probe. Sprint-7A2 T9 amendment: kind-derivation table extended to map `cognic.hooks` → `"hook"` so hook-pack wheels flow through the same identity + dist-info + entry-point integrity checks as tool / skill / agent packs.)

*Authoring — Hook packs (Sprint 7A2):*
- `packs/hooks/registry.py` (per ADR-008 + ADR-017 — verified-hook admission gate. Keys hook entries by hook ID + phase + pack identity + signed-artefact digest; refuses fail-closed on duplicate-ID across packs, stale digest vs the trust gate's verified bundle, and cross-pack-conflict scenarios. The build-time `HookDeclaration` dataclass enforces the Wave-1 fail-policy invariant (`fail_policy="fail_open"` requires a non-empty `fail_open_exception`) at construction time so a malformed registration cannot reach the dispatcher's MRO-walk carve-out path. `cli/validators/hooks.py` refuses every `fail_open` declaration at the build-time boundary; `fail_open_exception` is wired but unreachable through the manifest pipeline until the matching build-time shape lands in a follow-up sprint per ADR-017 §"DLP hook failure policy".)
- `packs/hooks/dispatcher.py` (per ADR-008 + ADR-017 — runtime decision engine + 5-value closed-enum `HookFailureMode` (`hook_timeout` / `hook_exception` / `hook_malformed_result` / `hook_policy_refused` / `hook_payload_unscannable`). Deterministic phase dispatch with explicit ordering, per-hook timeout clamped against `Settings.hook_max_timeout_s`, payload-budget pre-check (over-budget routes to `hook_payload_unscannable` BEFORE any hook runs), and audit linkage via `policy_input_digest` of the ORIGINAL governed payload (transformations never enter the audit chain). Symmetric exception ordering — pre-instantiation `except HookContractError` matches BEFORE generic `except Exception` so a malicious declaration cannot smuggle a contract violation past the malformed-result gate by naming `HookContractError` (or any subclass name) as `fail_open_exception` and expecting the carve-out's MRO walk to catch it. Pinned by AST self-tests + threat-model-revert verification per `feedback_security_regression_hardening.md`. Operator runbook: `docs/operator-runbooks/hook-pack-failure-policy.md`.)
- `packs/hooks/dlp_integration.py` (per ADR-017 — DLPGuard adapter wrapping `dispatch_for_pack` with `dlp_pre` / `dlp_post` phase semantics. Closed-enum 3-value `DLPRefusalReason` (`dlp_hook_id_unresolved` / `dlp_dispatcher_failed` / `dlp_dispatcher_refused`); ADR-017 line 97 enforcement boundary. T8 commit explicitly tagged `(CRITICAL CONTROLS)`; the refusal-payload-contract-divergence and delegate-first-preserves-precedence doctrine memories were both born from T8 R1 P2 fixes on this module — wrapper's contract for "what payload to return on refusal" diverges from the engine's last-seen-payload contract (DLPGuard returns the ORIGINAL governed payload on every refusal, never a partial-redaction leak); pre-validation passes are forbidden because they break engine precedence (oversized + unknown-id MUST surface as `hook_payload_unscannable` / `dlp_dispatcher_failed`, not `dlp_hook_id_unresolved`).)
- `cli/validators/hooks.py` (per ADR-008 + ADR-017 — `[hooks]`-block manifest validator. Validates the `[hooks]` block declarations (`hook_id` / `phase` / `ordering_class` / `timeout_seconds` / `fail_policy`) + cross-checks declared `hook_id`s against pyproject `[project.entry-points."cognic.hooks"]` keys (in-pack consistency; both directions — every declaration has an entry-point and every entry-point has a declaration). Does NOT cross-resolve `[data_governance].dlp_pre_hooks` / `dlp_post_hooks` against installed hook packs — that contract is split: `cli/validators/data_governance.py` validates the calling pack's reference list as snake_case strings only (shape + identifier syntax + intra-list dedupe; `<field>_invalid_shape` / `<field>_invalid_hook_id` / `<field>_duplicate`); cross-pack hook-id resolution is RUNTIME concern owned by the registry's admission gate + `DLPGuard` (`dlp_hook_id_unresolved` is a runtime closed-enum, never a build-time reason). Wave-1 fail-closed-only — every `fail_policy="fail_open"` declaration refused with closed-enum `hook_fail_policy_invalid` / `fail_open_without_exception`. The orchestrator-owned `hook_pack_kind_constraint_violated` (covers `[a2a]` / `[mcp]` block-presence on hook packs; `payload.failure_mode` ∈ {`a2a_block_forbidden`, `mcp_block_forbidden`}) lives in `cli/validate.py`, NOT here, per the one-validator-owns-each-refusal invariant. Promoted to critical-controls at Sprint-7A2 T12 closeout via Doctrine Decision G's "non-trivial allow/deny logic" rule alongside the runtime registry + dispatcher + DLP integration; `sdk/hook.py` stays off-floor per Doctrine E (public-API stability halt-before-commit).)

*Isolation boundaries:*
- `sandbox/` (isolation boundary, including `checkpoint/suspend/wake` audit-chain integrity per ADR-004)
- `subagent/` (privilege de-escalation boundary)

*Model + data governance:*
- `models/registry.py` + `models/trust.py` (per ADR-013 — lifecycle state machine + signature verification)
- `packs/evidence/data_governance.py` + the manifest-driven DLP enforcement runtime (per ADR-017)
- `core/memory/` (per ADR-019 — what an agent may remember/forget/export/redact/reuse across sessions)

*LLM gateway:*
- `llm/gateway.py` (cloud-policy enforcer; provider-honesty ledger feed)

Use `core-controls-engineer` and `/critical-module-mode` when working on these.

## Production-grade implementation rule

AgentOS is built as a production-grade system. The product should be deployable largely as implemented, not rewritten later.

Rules:
- Do not implement mock, fake, placeholder, or synthetic behavior in the main runtime path.
- Do not replace real integrations with mock generators just because CI or local setup is harder.
- If an external dependency is difficult to use in CI, implement the real integration for runtime and use fixtures or recorded responses only in tests.
- Test-only mocks, fixtures, and demo-safe sample data are allowed only under clearly separated test/demo paths.
- Production code paths must remain real, swappable, and deployable.

Plugin stubs (e.g. `protocol/mcp_host.MCPHost.call_tool`) that raise `NotImplementedError` referencing an ADR are explicit scaffolding, not mocks — they fail loudly when called, document the contract, and protect against silent fallback.

## Code layers

The three-pool rule (tools / skills / agents) governs **agent internals** outside this repo. Inside this repo:

- **Platform primitive.** Deterministic system module — peers of `cognic_agentos.core.*`. Includes governance, persistence, observability, channels, RBAC, plugin registry, sandbox, subagent.
- **Persistence adapter.** Database / external-store implementation of a platform contract.
- **Portal surface.** HTTP endpoints + DTOs.
- **Protocol layer.** MCP host, A2A endpoint, plugin registry.
- **Compliance evidence.** ISO 42001 control mapping + audit emission.

All Layer A/B/C (tools/skills/agents) live in plugin pack repos, not here.

## Human-only decisions

Do not finalise:
- Threshold changes
- Production deployments
- Model promotions / rollbacks
- Compliance sign-off
- Release gates
- Incident severity
- Bank communications
- Certification commitments
- Plugin-pack trust-root rotation
- Per-tenant allow-list changes

## Compaction

When compacting or stopping, preserve:
- Current task / subsystem
- Files changed
- Tests run + results
- Open risks / blockers
- ADR status
- Whether governance, sandbox, sub-agent, plugin trust, RBAC, or wire protocol were touched
- Next concrete step
