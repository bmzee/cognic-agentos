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
- `protocol/mcp_authz.py` (per ADR-002 amendment — OAuth/PRM token cache + refresh + AS allow-list)
- `protocol/a2a_authz.py` (per ADR-003 — per-tenant token authorization + Wave 2 mTLS hook + Wave 3 VC hook)

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
