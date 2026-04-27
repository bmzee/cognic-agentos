# Cognic AgentOS — Project Plan

**Status:** Active baseline  
**Date:** 2026-04-26  
**Purpose:** This is the working execution plan for this repo. We are building a production-grade, bank-deployable AgentOS that banks install once and extend with signed tool, skill, and agent packs, including packs they create themselves.

## 1. Repo Scope and Guardrails

- This repo ships **AgentOS only**: governance kernel, runtime primitives, protocol layer, portal API surface, persistence adapters, observability, and compliance evidence.
- This repo does **not** ship Layer A tools, Layer B skills, Layer C agents, bank overlays, or the portal UI as bundled product code.
- Banks must be able to extend the platform by installing **signed plugin packs**, not by forking or editing AgentOS.
- Production runtime paths must stay real and deployable. Test fixtures, mocks, and sample data belong only in clearly separated test or demo paths.
- Critical controls are never casual refactors. They require negative-path tests, high coverage, and explicit review.
- Human-only decisions remain human-only: threshold changes, production promotions, trust-root rotation, tenant allow-list changes, compliance sign-off, and deployment approvals are outside autonomous scope.

## 2. How We Resolve Source-of-Truth Conflicts

This repo inherits product truth from the broader Cognic document set, but it applies that truth through an AgentOS-only boundary.

Use this order:

1. `docs/source-of-truth/Cognic_Master_Strategy_v5.0.md` for product principles and end-state architecture.
2. `README.md`, `docs/source-of-truth/ARCHITECTURE.md`, `AGENTS.md`, and `docs/adrs/*.md` for the AgentOS-only translation of that strategy inside this repo.
3. `docs/ROADMAP.md`, `docs/source-of-truth/Cognic_Enterprise_Development_Plan_v1.2_updated.md`, `docs/source-of-truth/Cognic_AgentOps_Implementation_Guide_v5_sync.md`, and `docs/source-of-truth/Cognic_Development_Stack.md` for execution detail where they do not violate the OS-only boundary.

Translation rule:

- If older execution docs describe in-repo agents, tools, skills, or bank overlays, reinterpret those items as **separate pack repos** or separate artefacts per ADR-001 and ADR-002.
- If a convenience shortcut weakens the governance boundary, the governance boundary wins.

## 3. The 1.0 Outcome We Are Building Toward

AgentOS 1.0 is complete only when a bank can:

1. Deploy a single-tenant AgentOS instance on bank-controlled infrastructure.
2. Install, verify, and allow-list signed tool, skill, and agent packs without changing AgentOS code.
3. Create new tool, skill, and agent packs through AgentOS-supported developer functionality, then ship them independently of the AgentOS release cycle.
4. Run every pack through a governed kernel that enforces guardrails, audit, decision history, citation verification, RBAC, escalation, SLA, cloud policy, and auto-degradation.
5. Execute risky or untrusted actions inside an isolated sandbox with bounded credentials, bounded egress, and bounded resources.
6. Spawn sub-agents through a controlled A2A boundary with privilege de-escalation, depth caps, budget caps, and complete audit linkage.
7. Export examiner-ready evidence packs aligned to ISO 42001, with tamper-evident integrity proofs.
8. Operate in a self-hosted-first posture and report any routing drift honestly through the provider-audit surface.

## 4. Project Principles

- **Governance first:** trust-bearing controls live in the kernel and cannot be bypassed by packs.
- **Plugin boundary first:** anything that can live in a pack should live in a pack.
- **Production-grade from day one:** no fake runtime paths in the main system.
- **Bank extensibility is a product requirement:** third-party and bank-authored packs are first-class, not an afterthought.
- **Single-tenant by default:** the deployment model must match bank data residency and operational review expectations.
- **Self-hosted-first, provider-honest:** posture claims must be backed by runtime evidence.
- **Auditability over convenience:** every meaningful action must be attributable, queryable, and exportable.
- **Human accountability preserved:** the platform supports human-governed AI work, not unbounded autonomy.

## 5. SOTA Framework Recheck — 2026-04-26

This plan was rechecked against the current agent-framework and protocol landscape on 2026-04-26. The result is **not** a framework rewrite. The chosen stack remains aligned with current SOTA because the market is converging on the same primitives already in this plan: typed agent definitions, graph/workflow orchestration, durable execution, MCP tools, A2A interoperability, sandboxed execution, human approval, tracing, evals, and agentic security controls.

Framework posture:

- **Keep Pydantic AI as the internal Python agent-definition layer.** Its current docs explicitly cover model-agnostic agents, type-safe dependencies and outputs, evals, MCP, A2A, human-in-the-loop approval, durable execution, and graph support.
- **Keep LangGraph as the low-level stateful orchestration layer.** Current LangGraph guidance positions it around durable execution, human-in-the-loop, memory, streaming, and production deployment for long-running stateful agents.
- **Keep Temporal for Wave 2+ durable workflows.** Temporal remains the right runtime for long-running, retryable, human-waiting, and auditable workflows that must survive crashes and resumptions.
- **Keep MCP and A2A as protocol boundaries, not framework dependencies.** Google ADK, Microsoft Agent Framework, OpenAI Agents SDK, CrewAI, Pydantic AI, and others now expose or converge around MCP/A2A-style interop. AgentOS should host packs through standards, not absorb another agent framework into the kernel.
- **Do not migrate AgentOS internals to Google ADK, Microsoft Agent Framework, CrewAI, OpenAI Agents SDK, or AutoGen-style runtimes.** Those are valid pack-author ecosystems and comparison references; they are not OS kernel dependencies. Packs written on those frameworks should interoperate through MCP or A2A.
- **Treat OpenAI Agents SDK sandbox agents as a design reference, not a dependency.** Its manifest, permissions, sandbox-client, snapshots, resumable-session, and capability model validate ADR-004. AgentOS implements the same bank-controlled primitive under its own governance and audit boundary.
- **Adopt OpenTelemetry GenAI semantic conventions carefully.** The GenAI semantic conventions are still marked Development, so AgentOS should emit stable internal audit fields first and provide an OTel mapping adapter rather than making experimental attribute names the audit source of truth.

Protocol and security deltas from the recheck:

- **MCP remains correct, but STDIO is high risk.** April 2026 MCP supply-chain disclosures show that unsafe STDIO command configuration can become remote code execution in real deployments. AgentOS must therefore prefer Streamable HTTP MCP for production packs and treat local STDIO as a restricted escape hatch only for signed, static, allow-listed pack manifests.
- **MCP host implementation must include transport hardening before general tool invocation.** No user-, model-, or remote-pack-controlled command or argument may reach process execution. Local process launches require a static command allow-list, signed pack metadata, sandbox containment, bounded environment variables, and audit events for every launch.
- **A2A should be pinned to the released spec line before code lands.** Current A2A docs identify 1.0.0 as the latest released version. AgentOS Phase 2 should add protocol conformance tests rather than freezing a bespoke Python dict envelope as the actual wire contract.
- **OWASP agentic security guidance is now a required conformance input.** Pack conformance should include checks inspired by OWASP Top 10 for Agentic Applications 2026 and OWASP Agentic Skills Top 10: tool misuse, goal hijacking, identity abuse, prompt-injected skills, rogue autonomous behavior, dependency poisoning, secret exfiltration, and unsafe filesystem/network access.

Sources reviewed:

- [Pydantic AI docs](https://pydantic.dev/docs/ai/overview/)
- [LangGraph docs](https://docs.langchain.com/oss/python/langgraph/overview)
- [Temporal docs](https://docs.temporal.io/)
- [OpenAI Agents SDK docs](https://openai.github.io/openai-agents-python/)
- [Google ADK docs](https://adk.dev/)
- [Microsoft Agent Framework docs](https://learn.microsoft.com/en-us/agent-framework/overview/)
- [MCP 2026 roadmap](https://blog.modelcontextprotocol.io/posts/2026-mcp-roadmap/)
- [A2A protocol specification](https://a2a-protocol.org/dev/specification/)
- [AGNTCY docs](https://docs.agntcy.org/)
- [OpenTelemetry GenAI semantic conventions](https://opentelemetry.io/docs/specs/semconv/gen-ai/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/)
- [OX Security MCP supply-chain research](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-technical-deep-dive/)

## 6. Core Workstreams

### Workstream A — Kernel Hardening

Build and harden the governance kernel, harness, gateway, persistence, observability hooks, and HTTP surfaces that every pack depends on.

Primary areas:

- `core/`
- `harness/`
- `llm/`
- `retrieval/`
- `portal/`
- persistence and observability adapters

### Workstream B — Pack Ecosystem and Bank Extensibility

Make AgentOS genuinely extensible so banks can create and install their own tools, skills, and agents without touching the kernel.

Primary areas:

- `protocol/plugin_registry.py`
- `protocol/mcp_host.py`
- `protocol/a2a_endpoint.py`
- pack discovery, trust verification, and tenant allow-listing
- pack conformance tooling, templates, and compatibility documentation
- bank-facing pack developer functionality: scaffold, manifest validation, local test harness, conformance runner, signing workflow, submission workflow, install/remove/revoke APIs, and registry inspection
- MCP transport hardening: Streamable HTTP first; STDIO only from signed static manifests, static command allow-lists, sandbox containment, and full audit
- A2A spec conformance testing against the currently released protocol version before any production inter-agent routing
- OWASP agentic security and skill-supply-chain checks in pack conformance gates

### Workstream C — Compliance and Operational Trust

Deliver the controls that make the system deployable in regulated banking environments.

Primary areas:

- audit and decision history integrity
- citation verification
- ISO 42001 evidence mapping and export
- provider-honesty runtime audit
- incident and rollback readiness
- security pipeline and SBOM discipline

### Workstream D — Execution Isolation and Delegation

Add the "hands" and "worker" primitives that move AgentOS from governed inference to governed action.

Primary areas:

- `sandbox/`
- `subagent/`
- A2A-backed spawning
- privilege de-escalation
- budget, depth, and policy enforcement

### Workstream E — Bank Deployment Kit

Turn the platform into something a bank can actually install, operate, audit, and recover.

Primary areas:

- Docker and local orchestration
- Helm and production deployment assets
- Vault, OIDC, and tenant configuration hooks
- operator runbooks
- backup, restore, rollback, and smoke verification flows

## 7. Phase Plan

> **Authoritative sprint sheet:** [`docs/BUILD_PLAN.md`](./BUILD_PLAN.md) is authoritative for sprint-level execution (sprint numbering, work-units, deliverables, exit criteria). The phase narrative below sets *intent and exit gates*; BUILD_PLAN translates those into the actual sub-sprint sequence (1A/1B/1C/1D/2/3 in Phase 1; 4/5/6/7A/7B in Phase 2; 8/9/9.5/10 in Phase 3; 11-15 in Phase 4; 16-21 in Phase 5). Where phase narrative below disagrees with BUILD_PLAN sprint mapping, **BUILD_PLAN wins**. The narrative remains useful for procurement / examiner briefing where sprint detail is noise.

### Phase 0 — Doctrine Lock and Scope Discipline

**Status:** In progress from the current docs baseline.

Goals:

- Freeze the repo boundary around AgentOS-only scope.
- Capture the non-negotiable architectural contracts in ADRs.
- Make the stop rules and critical-controls rules operational.

Exit gate:

- README, architecture, ADRs, roadmap, and operating rules all align on the OS-only boundary.
- No planning artifact in this repo assumes that agents, tools, or skills ship inside AgentOS.

### Phase 1 — Production Scaffold and Hardening Baseline

Goals:

- Convert the current doctrine-first repo into a production-grade code scaffold with quality gates from day one.

Deliverables:

- `pyproject.toml`, `.python-version`, `uv.lock`, package namespace, and source layout.
- CI pipeline with Ruff, mypy, pytest, coverage enforcement, Bandit, pip-audit, gitleaks, Trivy, hadolint, Syft, and image build.
- Dockerfile and local compose stack.
- architecture-import-discipline tests proving OS code does not depend on pack code.
- OpenAPI export discipline for downstream consumers.
- provider-honesty API surface and runtime classification logic.

Exit gate:

- repeatable local bootstrap works.
- CI is green.
- architecture boundary tests exist.
- provider-audit surface can report effective routing honestly.

### Phase 2 — Plugin Protocol and Pack Runtime

Goals:

- Make pack creation, discovery, trust verification, submission, installation, and invocation real for both Cognic-authored and bank-authored packs.

Deliverables:

- `plugin_registry.discover()`, `require()`, and `load()` using Python entry points.
- MCP host session management and tool routing, with Streamable HTTP as the production default and STDIO restricted to signed static manifests.
- MCP transport threat model and tests proving no user-, model-, or remote-pack-controlled command or argument reaches process execution.
- inbound A2A endpoint and target resolution, pinned to the current released A2A specification with conformance fixtures.
- cosign verification and tenant allow-list schema.
- pack metadata and compatibility contract docs.
- bank pack SDK/CLI with commands to scaffold, validate, test, sign, package, and submit tool, skill, and agent packs.
- portal API endpoints for bank pack lifecycle: draft, submit, review, approve, allow-list, install, disable, revoke, uninstall, and inspect evidence.
- local pack test harness that runs bank-authored tools/skills/agents against the same governance envelope used in AgentOS, using only test fixtures.
- pack conformance suite covering OWASP Agentic Top 10 / Agentic Skills supply-chain risks.
- separate proof-of-boundary pack repos for one tool pack and one agent pack.
- conformance tests proving zero OS-tier imports from pack implementations.

Exit gate:

- a bank engineering team can scaffold a new tool pack, skill pack, and agent pack; validate them locally; sign them; submit them to AgentOS; route them through review/approval; allow-list them; install them; invoke them; inspect their audit/evidence; and revoke them without any AgentOS code change.

### Phase 3 — Governance and Compliance Hardening

Goals:

- Move the trust boundary from architectural intent to production-enforced behavior.

Deliverables:

- hardened audit chain, decision history, chain verifier, guardrails, citation verifier, escalation lifecycle, SLA hooks, auto-degradation, and cloud-policy enforcement.
- ISO 42001 control registry and tagged governance hooks.
- evidence-pack export with signed manifest and Merkle-root integrity proof.
- negative-path tests for critical controls.
- 95%+ coverage on critical control modules.

Exit gate:

- a seven-day evidence bundle can be generated from a test deployment and independently verified for integrity and control mapping.

### Phase 4 — Sandbox and Sub-Agent Primitives

Goals:

- Add isolated execution and governed delegation without breaking the audit boundary.

Deliverables:

- `SandboxBackend` protocol and Wave 1 reference backend.
- per-call sandbox policy validation, resource limits, egress allow-listing, image pinning, filesystem mount policy, and Vault-backed credential scoping.
- sandbox manifest, permissions, snapshot, and resumable-session contracts inspired by current managed-agent runtimes but implemented under AgentOS governance.
- warm-pool and lifecycle metrics.
- `SubAgent.invoke()` over A2A.
- parent-child privilege de-escalation, recursion depth caps, token and wall-time budgets.
- cross-agent audit chain integrity tests.

Exit gate:

- a cross-agent workflow can spawn a worker, enforce narrower privileges, complete within budget, and produce a verifiable audit chain with no gaps.

### Phase 5 — Bank Deployment Kit and Operational Readiness

Goals:

- Make AgentOS deployable and operable in bank-like environments.

Deliverables:

- production deployment kit with Docker Compose and Helm.
- tenant config schemas for trust roots, allow-lists, routing policy, sandbox policy, and environment thresholds.
- hooks for OIDC, Vault, SIEM, and reviewer operations.
- operator runbooks for install, register pack, smoke verify, export evidence, rollback, and recover.
- backup and restore procedures with evidence.
- production-readiness checks for latency, throughput, retention, cost, RTO, and RPO.

Exit gate:

- a clean environment can install AgentOS, register a signed pack, run a smoke flow, export evidence, and recover from a controlled rollback test.

## 8. Bank-Created Pack Enablement Plan

Supporting bank-created tools, skills, and agents is not finished when MCP/A2A exists. It is finished only when the full pack lifecycle is usable by non-Cognic bank engineering teams from inside the AgentOS operating model.

Required outputs:

1. A stable pack contract for `cognic.tools`, `cognic.skills`, and `cognic.agents`.
2. A documented pack manifest, versioning policy, and compatibility matrix.
3. A bank pack SDK/CLI with scaffold commands for tool, skill, and agent packs.
4. Starter templates for tool, skill, and agent pack repos with CI, tests, SBOM generation, and cosign signing.
5. A local governance test harness so bank teams can run a pack against fixture-based guardrails, audit, decision history, sandbox policy, and A2A/MCP conformance before submission.
6. Portal API surfaces for pack lifecycle management: draft, submit, review, approve, allow-list, install, disable, revoke, uninstall, evidence export, and registry inspection.
7. RBAC-scoped approval workflow so bank developers can submit packs, security/compliance reviewers can approve or reject them, and operators can install or revoke them.
8. A trust onboarding flow covering bank trust roots, tenant allow-lists, revocation, rejection behavior, and rejected-pack evidence.
9. A conformance suite that a bank can run before attempting installation.
10. Example documentation for common bank extension patterns, especially CBS adapter tools, deterministic workflow skills, and bank-specific agent packs.
11. Operator documentation showing how a bank installs a pack, verifies it, inspects it in the registry, and removes or blocks it safely.

Minimum in-platform functionality:

- **Pack creation:** generate repo scaffold, manifest, typed schemas, test skeleton, SBOM/signing workflow, and transport defaults.
- **Pack validation:** validate manifest, semantic version, declared tools/skills/agents, required permissions, sandbox policy, model tier, RBAC scopes, egress needs, and compatibility with the installed AgentOS version.
- **Pack testing:** run tools through MCP fixtures, skills through deterministic fixture workflows, and agents through A2A/harness fixtures with mocked test-only data.
- **Pack submission:** submit a signed artefact and metadata bundle to the AgentOS registry for review.
- **Pack review:** expose evidence for signature, SBOM, dependency scan, requested permissions, sandbox profile, external egress, and governance hooks.
- **Pack installation:** register approved packs into the tenant registry without code changes or AgentOS redeploy beyond the documented restart/hot-reload mode.
- **Pack operation:** route every invocation through audit, decision history, tracing, guardrails, sandbox, RBAC, provider policy, and escalation as applicable.
- **Pack retirement:** disable, revoke, uninstall, and preserve all historical audit/evidence records.

Success criterion:

- A bank engineering team can create its own signed tool pack, deterministic skill pack, and A2A-speaking agent pack; install them on AgentOS; and have them operate under the same governance controls as Cognic-authored packs.

## 9. Definition of Done for Every Significant Deliverable

No major deliverable is considered complete unless:

- the code path is real, not placeholder behavior in the main runtime;
- tests cover happy paths and negative paths;
- critical modules meet the stricter coverage bar;
- tracing, audit, and decision-history behavior are verified where applicable;
- ADRs are updated for non-trivial design decisions;
- operator-facing or examiner-facing docs are updated where behavior changes;
- remaining risks are written down explicitly rather than implied away.

## 10. What We Will Not Do in This Repo

- ship packaged Layer A/B/C business capabilities as part of AgentOS;
- rebuild the monolith inside a new folder;
- use bank-specific logic as a shortcut for unfinished platform contracts;
- hide cloud routing behind static labels;
- rely on mocks in production paths because real integrations are harder;
- treat compliance evidence as a post-processing exercise instead of a runtime responsibility.

## 11. Immediate Ordered Backlog

This is the sequence to follow from the current pre-code state:

1. Stand up the repo scaffold, package layout, CI, and container baseline.
2. Add architecture-boundary tests and critical-control test structure.
3. Update ADR-002 implementation notes with the MCP STDIO threat model, production transport policy, and command-launch restrictions before writing `MCPHost`.
4. Implement the protocol layer skeletons for plugin registry, MCP host, and A2A endpoint.
5. Add provider-honesty reporting so routing posture is auditable from the start.
6. Harden the governance kernel and evidence-tagging hooks before broad feature expansion.
7. Implement the bank pack SDK/CLI, pack manifest validator, local governance test harness, and portal API lifecycle endpoints.
8. Implement pack trust verification, tenant allow-list controls, and OWASP agentic supply-chain checks.
9. Prove the boundary with separate bank-authored-style tool-pack, skill-pack, and agent-pack POCs.
10. Add sandbox execution and policy enforcement.
11. Add A2A-backed sub-agent spawning with privilege controls.
12. Package the bank deployment kit, runbooks, and production-readiness verification.

## 12. Project Success Gate

We should not call this project production-grade AgentOS until all of the following are true:

- the kernel is deployable without bundled packs;
- a non-Cognic bank team can build, test, sign, submit, approve, install, operate, and revoke signed tool, skill, and agent packs successfully;
- critical controls are tested, hardened, and evidenced;
- sandbox and sub-agent boundaries are enforced, not promised;
- provider posture is measured honestly;
- deployment, rollback, backup, and evidence export are rehearsed;
- the system can survive bank procurement, security review, compliance review, and operator handoff without requiring architectural exceptions.
