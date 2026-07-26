# Cognic AgentOS — Operating Model

## Core principle

This repo ships **AgentOS only**: the hardened governance + runtime + protocol kernel that banks deploy once and run forever. Agents, tools, and skills are out of scope here — they ship as separately-versioned plugin packs that install on top of AgentOS.

## What lives where

| Lives in cognic-agentos (this repo) | Lives elsewhere |
|---|---|
| Governance kernel (`core/`) | Layer C agents (`cognic-agent-<name>` repos) |
| Harness (`harness/base_agent.py`) | Per-agent workflows (ship in agent packs) |
| LLM gateway, retrieval orchestrator, persistence, observability | Per-agent eval scorers (ship in agent packs) |
| RBAC, portal API + workbench | Cognic Harness (`cognic-harness` separate product repo — the v1 three-screen runtime client as a browser + same-origin BFF, growing into the v2 ADK; no independent authorization or governance authority — security-sensitive for the OIDC flow, session/token custody, CSRF, and request forwarding, non-authoritative for identity and authorization; distinct from the kernel-internal `harness/` composition layer) |
| Plugin registry + MCP host + A2A endpoint | Tool packs (`cognic-tool-<name>` MCP servers) |
| Sandbox + sub-agent primitives | Skill packs (`cognic-skill-<name>` — a `SKILL.md` package, optionally carrying one governed action) |
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
- Model registry lifecycle transitions (`models/` + `models/trust.py` + `portal/api/models/lifecycle_routes.py` — register/promote/retire route module added at Sprint 9.5 B4 owns the cosign path-containment helper `_resolve_under_tenant_root` per the resolve-then-validate doctrine, the cosign-OUTSIDE-transaction `_verify_record_signature` with the B4 R2 P1 bundle-digest recompute-before-cosign evidence-integrity gate, the body-aware promote-scope resolution + HumanActor gate when `target_state="serving"`, the state-aware HumanActor gate at `/retire` when current state is `serving`, and the wire-body-collapse cross-tenant invisibility contract (`portal/rbac/model_tenant_isolation.py` — model module ships the stronger wire-collapse than the pack equivalent: cross-tenant + unknown both render as 404 `model_not_found` so a probe cannot distinguish; internal log retains `tenant_id_mismatch` for ops + SIEM correlation))
- Pack data-governance contracts (`packs/evidence/data_governance.py`, runtime DLP enforcement)
- Kill-switch / quota enforcement (`core/emergency/kill_switches.py` — the full 8-class matrix landed Sprint 13.6a; `core/emergency/quotas.py` — the token quota meter landed Sprint 13.6b, on the CC gate)
- Policy-as-code engine (`core/policy/engine.py` + Rego bundles in `policies/_default/`)
- Memory governance enforcement (`core/memory/` per ADR-019)
- UI event-stream contract (`protocol/ui_events.py` per ADR-020 — public event schema, must remain backward-compatible across versions)
- Policy bundle: `policies/_default/sampling.rego` (per ADR-015 + ADR-002 §"MCP sampling" — sampling decision-point bundle invoked by `protocol/mcp_capabilities.py`; refusal-vocab change is a wire-protocol break for sampling-enabled tool packs)
- Policy bundle: `policies/_default/supply_chain.rego` (per ADR-015 + ADR-016 — supply-chain decision-point bundle invoked by `protocol/trust_gate.py` for attestation-grade evaluation; drift breaks the runtime trust-gate's evidence reading)
- Policy bundle: `policies/_default/elicitation.rego` (per ADR-015 + ADR-020 §69-77 — Step 5 of the T8 elicitation gate at `data.cognic.ui.elicitation_submit.allow`; default `allow := false` + URL-always-allows + form-mode-restricted-data-class refusal is the wire-protocol-public Rego contract bank overlays cannot override without coordinated kernel + rego update)
- Policy bundle: `policies/_default/sandbox.rego` (per ADR-015 + ADR-004 + Sprint-8A spec §13 — Wave-1 sandbox admission bundle at `data.cognic.sandbox.admit.allow`; default `allow := false` + 5 rules: (1) allow only if the tier is admissible via `_tier_admissible` (arm 1 = the 2 safe tiers `{read_only, internal_write}`; arm 2 = a high-risk tier on strict Python-attested `input.approval_verified == true` — the Sprint-13.5c1 CONVERT) AND tenant-max satisfied AND credential precondition satisfied AND runtime-image authorised AND egress HTTP/HTTPS-only (a verified high-risk grant does NOT bypass these — every conjunct still applies); (2) refuse the 6 high-risk tiers `{customer_data_read, customer_data_write, payment_action, regulator_communication, cross_tenant, high_risk_custom}` with `sandbox_high_risk_tier_refused_pre_13_5` when `approval_verified` is NOT attested — the value name is KEPT as the engine-absent / unverified reason (the Python seam always threads `approval_verified`, `False` on unwired/auto paths; the seam is production-wired for cold-create at 14A-A2 + wake at 14A-A3c); (3) refuse on `vault_path` set + `credential_adapter_wired=false` (defence-in-depth with Stage-2 §6.1 step 3); (4) refuse on runtime image not in canonical catalog AND not in tenant allow-list (defence-in-depth with Stage-2 §6.1 step 6); (5) refuse on any `egress_allow_list` entry carrying a non-HTTP/HTTPS scheme OR malformed shape — PURE Rego guard with `is_array` + `is_string` type checks so the bundle catches Stage-1 bypass independently per the Sprint-8A T11 R2-R3 defence-in-depth contract. Wire-protocol-public stop-rule precedent identical to `sampling.rego` / `supply_chain.rego` / `elicitation.rego`; bank overlays may tighten; loosening kernel defaults requires coordinated kernel + ADR amendment)
- Policy bundle: `policies/_default/scheduler.rego` (per ADR-015 + ADR-022 + Sprint-10.5b spec §4.8 — Wave-1 scheduler admission bundle exposing TWO wire-protocol-public decision points: `data.cognic.scheduler.admit.allow` (bool) + `data.cognic.scheduler.admit.refusal_reason` (string, 3-value closed-enum). Default `allow := false` + **3 allow arms** (post-Sprint-13.5c2 + Sprint-14A-A4a): arm 1 = safe tiers (`class ∈ {interactive, background}` AND `pack_risk_tier ∈ {read_only, internal_write}` AND tier NOT in the 6-value high-risk set — safe + high-risk sets disjoint by construction); arm 2 (Sprint-13.5c2 CONVERT) = a high-risk tier on strict `input.approval_verified == true`; arm 3 (Sprint-14A-A4a) = a high-risk tier on strict `input.approval_delegated_to == "sandbox_admission"` (the downstream sandbox admission gate owns the human checkpoint; the scheduler mints no grant of its own — **live-exercised at Sprint 14A-A4b: the managed-run executor sets the signal with a pack's real manifest tier**). Refusal-reason if/else chain with **deterministic precedence** per plan §1090: `scheduler_class_unknown` (FIRST — admission cannot evaluate tier semantics until class is in vocabulary) → `scheduler_high_risk_tier_refused_pre_13_5` (mirrors sandbox.rego's 6-tier set; the high-risk arm fires ONLY when NEITHER `input.approval_verified == true` (Sprint-13.5c2 guard) NOR `input.approval_delegated_to == "sandbox_admission"` (Sprint-14A-A4a guard) — the value name is KEPT as the engine-absent / unverified / undelegated reason; no wire rename) → bare-else `scheduler_default_deny` (fall-through; also the `default refusal_reason` for shape-mismatched/missing-input cases the chain cannot evaluate). 3-value closed-enum refusal vocabulary is wire-protocol-public + drift-detector-pinned at `tests/unit/policies/test_scheduler_rego.py::TestSchedulerRegoVocabularyClosed`. Consumed by `core/scheduler/policy.py` via the **10-key** `_build_rego_input` projection (the spec §4.8 8-key set `tenant_id` / `pack_id` / `actor_subject` / `class` / `pack_kind` / `pack_risk_tier` / `current_tenant_concurrent_count` / `requested_estimated_tokens` + `approval_verified` per Sprint-13.5c2 + `approval_delegated_to` per Sprint-14A-A4a, both always-threaded/nullable); the Python policy layer SUPPRESSES the raw bundle `refusal_reason` to `policy_reason=None` on the allow path per plan §1179 (propagating `scheduler_default_deny` on an allow row would be audit/SIEM misleading). Wire-protocol-public stop-rule precedent identical to `sampling.rego` / `supply_chain.rego` / `elicitation.rego` / `sandbox.rego`; bank overlays may tighten; loosening kernel defaults requires coordinated kernel + ADR amendment)
- Policy bundle: `policies/_default/agents.rego` (per ADR-027 + ADR-015 + M8 A5 + M8.5-D S1 — Wave-1 agent-dispatch bundle exposing ONE wire-protocol-public decision point: `data.cognic.agents.dispatch.allow` (bool). **BOOL-ONLY by design** — deliberately NO string `refusal_reason` document: the Python dispatcher owns the closed 8-value `AgentDispatchRefusalReason` vocabulary at `core/agent/_types.py:30` and a bundle deny surfaces on the wire as `agent_policy_denied`; adding a reason document here would fork the refusal vocabulary across two owners. `default allow := false` + a SINGLE allow rule with 5 conjuncts (`agents.rego:77-83`): strict `input.assignment_verified == true` AND strict `input.entitlement_verified == true` AND `input.capability_kind in {"skill","tool","builtin"}` AND `input.capability_class in {"data_query","action","unscoped"}` AND `input.step_index < input.max_steps`. The class conjunct is independent defense in depth over the Task-5 Python gate: unknown/reserved non-empty values refuse if that gate is bypassed, and a missing policy-input key refuses by default; built-ins/skills deliberately ride as `unscoped`. Consumed by `core/agent/policy.py` via the 12-key identical-names `_build_rego_input` projection at `:168` (no key translations); fail-closed `opa_unavailable` on engine absence. Wire-protocol-public stop-rule precedent identical to `sampling.rego` / `supply_chain.rego` / `elicitation.rego` / `sandbox.rego` / `scheduler.rego`; bank overlays MAY TIGHTEN (more refusal conditions, tighter kind/class sets, per-capability allow-listing); LOOSENING kernel defaults requires coordinated kernel + ADR-027 amendment)

## Critical-controls rule

Some modules are **critical controls**: a defect in them silently weakens a
governance guarantee instead of producing a visible failure. They get extra
scrutiny.

**What qualifies.** A module is a critical control when it owns any of:

- a trust or authorization decision — who may do what, under whose identity;
- a fail-closed default that a bug could turn fail-open;
- a wire-protocol-public contract — a closed-enum vocabulary, an evidence
  schema, or a response shape that external consumers or examiners read;
- hash-chain, canonical-form, or evidence-pack integrity;
- an isolation or privilege boundary (sandbox, sub-agent, tenant separation).

Thin wiring that delegates to one of the above is **not** critical. The
enforcement it delegates to is.

**What the gate requires.**

- ≥95% line and ≥90% branch coverage, enforced by
  `tools/check_critical_coverage.py`.
- Negative-path tests are mandatory — the refusal arms, not only the happy path.
- Load-bearing guards carry a mutation proof: revert the guard, show the test
  goes red, restore byte-exact.
- No casual refactors.
- Halt before commit for human review on **every** critical-controls commit,
  regardless of size.

**Before you edit.** Confirm whether the file is gated by grepping
`_CRITICAL_FILES` in `tools/check_critical_coverage.py` — never trust a plan's
claim that a file is off-gate. If it is gated, read its entry in the inventory
first, and run the coverage gate against fresh `--cov-branch` data at the
commit that changes it.

**When promoting a module onto the gate**, verify it meets the floor at
promotion time against fresh full-suite data, not against numbers quoted
earlier in a plan. Sibling regressions are common and the promotion commit is
where they surface.

**The gate is a budget, not a ratchet.** The count has only ever grown — 129
to 156 with no removal — because promotion has a procedure and demotion does
not. Every promotion permanently raises the cost of touching that file, so the
set must be curated rather than accumulated.

- A promotion commit states **which of the five criteria** the module meets.
  "It felt important" is not one of them.
- A promotion commit also records a **demotion review**: does any existing
  entry no longer qualify? Recording "none" is a valid outcome; skipping the
  question is not.
- **Demotion is a normal action, not a weakening.** Demote when a module has
  become thin wiring, when the enforcement it owned moved elsewhere, or when
  its contract stopped being wire-protocol-public. The enforcement that
  replaced it stays gated; the shell does not.
- Removing an entry needs the same scrutiny as adding one — human review,
  and a statement of where the guarantee now lives.

Net growth is expected while the kernel is still acquiring trust boundaries.
Growth without review is not.

**The inventory** — every gated module, why it is gated, and its load-bearing
invariants — lives in `docs/source-of-truth/CRITICAL-CONTROLS.md`. Consult it
per-module when you touch that module. It is deliberately not part of the
per-session preamble.

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

**Deployment substrate (Sprint 14B-Z1a, ADR-024).** The kernel ships an OpenShift-compatible **Helm chart** at `infra/charts/agentos/` that packages the existing `default-adapters` prod image (`create_prod_app`) — validated by an always-on Helm-4 lint/template/kubeconform/byte-snapshot-drift CI gate + a pinned Helm-3 compatibility lane, plus an env-gated `kind` Ready-smoke against six real credential-free backends. **Helm is the only in-repo manifest source** — banks needing Kustomize render `helm template` and overlay in their own repos (the OS / bank-overlay boundary above). Z1a is pure additive infra-as-code: **CC count stays 131, no kernel change, no migration** (the only Python added is the rendered-YAML snapshot test); AKS/cloud bring-up, external-secrets depth, Ingress/Route + TLS, and observability wiring are deferred to Z1b. **Sprint 14B-Z1b-a** then added the three conditional, default-off external-access/scrape templates (`ingress.yaml` / `route.yaml` / `servicemonitor.yaml`) + a four-scenario byte-snapshot + kubeconform CI gate (Route's CRD schema is absent from the `datreeio/CRDs-catalog`, so the gate uses the scoped `-skip Route` fallback) — still **CC 131, no kernel change, no migration**; the live cloud/ingress exercise is Z1b-d. **Sprint 14B-Z1b-b** then added the conditional, default-off ESO `ExternalSecret` template (`externalsecret.yaml`, `external-secrets.io/v1`, populating the existing 2-key bootstrap Secret from an operator-owned `SecretStore`/`ClusterSecretStore` the chart never creates) + a 3-mode mutually-exclusive secret source (`secrets.create` XOR `secrets.existingSecret` XOR `externalSecrets.enabled`, enforced by the `agentos.validateSecretSource` Helm `fail` + a root-level schema `allOf`) + a fifth snapshot/kubeconform scenario (ExternalSecret is schema-validated; the gate keeps the narrow `-skip Route`) — still **CC 131, no kernel change, no migration**; the live cloud/ESO exercise is Z1b-d. **Sprint 14B-Z1b-c** then added the generic OTLP exporter primitive (`observability/otel.py` `_build_otlp_exporter` branches `grpc`/`http` + threads `headers` into both; http reuses the mTLS triple as file-path kwargs, `insecure` is gRPC-only) behind two new `core/config.py` Settings (`otel_exporter_protocol` + `otel_exporter_headers`) + the endpoint-gated chart wiring (`values.otel.exporter.{endpoint,protocol,insecure,headersSecretKey}`; the Basic-auth header rides a `secretKeyRef` passthrough, `existingSecret`-only) + a sixth `otel-http` snapshot scenario (core kinds — no CRD change) — **CC 131, no migration, no new dependency**; `core/config.py` is a `core/` stop-rule edit (the off-coverage-gate kernel change carried halt-before-commit scrutiny). The standalone env-gated Langfuse ingestion proof (`COGNIC_RUN_LANGFUSE_OTEL=1`) ships in Z1b-c; the live cloud/cluster exercise (AKS + the chart path in-cluster, incl. ServiceMonitor → Prometheus) is Z1b-d. **Sprint 14B-Z1b-d-1** then added the two **generic, cloud-agnostic** chart workload-identity hooks — `serviceAccount.annotations` (→ the SA's `metadata.annotations`) + `podLabels` (→ the Deployment's pod **template** labels `.spec.template.metadata.labels` ONLY, **never** `.spec.selector.matchLabels`: the selector-stability invariant that keeps `helm upgrade` working) — so the chart SA can federate to any cloud IAM identity (Azure WI / GKE WI / AWS IRSA, named only in the runbook examples + one Azure-WI test fixture; the chart values/schema stay plain `type: object` maps), default-empty → render nothing (the default + 6 existing snapshots byte-UNCHANGED), validated by a 7th `workload-identity` snapshot (core kinds — ServiceAccount + Deployment — no CRD change) — still **CC 131, no kernel change, no migration**; the live AKS exercise is Z1b-d-2. **Sprint 14B-Z1b-d-2** then shipped the live-cloud capstone — an always-on 8th `all-surfaces` byte-snapshot scenario (every Z1b conditional surface in one dedicated ESO-mode render; `-skip Route` unchanged) + operator-run reference Bicep (`infra/azure/aks-smoke/main.bicep`: AKS OIDC+WI, UAMI, empty Key Vault, federated credential, KV roles) + a self-contained env-gated AKS smoke (`run-aks-smoke.sh`: ESO-from-Key-Vault + workload identity + Ready; namespace-pinned to the Bicep `agentosNamespace`; migrations-off + a post-gate non-hook migration Job to avoid the pre-install-hook-vs-ESO-secret deadlock; an auxiliary `Merge` ExternalSecret for the OTLP header preserving the chart's fixed 2-key contract, behind a fail-loud 3-key gate with a first-class `ENABLE_OTLP=0` 2-key fallback). **No AKS CI job** (a deliberate security posture); still **CC 131, no kernel change, no migration**. With Z1b-d-2 the whole 14B Deployment Substrate (Z1a + Z1b-a/b/c/d-1/d-2) is **complete**.

## Code layers

The three-pool rule (tools / skills / agents) governs **agent internals** outside this repo. What each noun means is fixed by `docs/source-of-truth/VOCABULARY.md` — notably: a **skill** is a `SKILL.md` package, and the no-LLM composer is its optional **governed action**, not a second species of skill. Inside this repo:

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
