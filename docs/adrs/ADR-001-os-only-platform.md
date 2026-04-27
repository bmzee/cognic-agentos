# ADR-001 — Cognic AgentOS as OS-Only Platform

## Status
**ACCEPTED** on 2026-04-26 (foundational decision for this repo).

## Context

The parent `bmzee/cognic` monorepo holds OS-tier code, Layer C agents, and the React UI in a single repository. ADR-009 in that repo proved (with a CI test) that OS-tier code can run without `cognic.agents.*` — the OS-only SKU is technically deployable. However:

- Adding a new agent requires redeploying the entire AgentOS process
- Adding a new tool requires redeploying AgentOS
- Bank-side procurement audit must traverse the agents subtree even for an OS-only buy
- Independent release cadence is impossible: UI hotfix, OS bump, and agent pack ship together
- Bank teams that should only have OS access can't be cleanly scoped to a path subset

## Decision

Create a separate repo (`cognic2` → renamed `cognic-agentos` on push) hosting **only**:
- Governance kernel (`core/`, `compliance/`)
- Runtime primitives (`harness/`, `sandbox/`, `subagent/`, `llm/`, `workflows/` runtime, retrieval orchestrator)
- Persistence + observability adapters
- Channels
- Portal API + Workbench DTOs + RBAC vocabulary
- Protocol layer (`protocol/mcp_host`, `protocol/a2a_endpoint`, `protocol/plugin_registry`)

Layer C agents, per-agent workflows, per-agent eval scorers, the UI, and bank-specific overlays live in **separate repositories** that install on top of AgentOS as plugin packs.

## Consequences

### Positive
- Bank-side OS-only deployment is physically clean: clone the repo, you cannot accidentally see Layer C code
- Per-pack release cadence: tool / skill / agent packs version independently
- Adding a new tool / agent does not redeploy AgentOS (after ADR-002 plugin packaging lands)
- Per-team permissions: OS team owns this repo; agent teams own their pack repos
- Procurement clarity: bank legal audits one repo for the OS-only SKU
- Forces the OS to keep a clean public API at the protocol boundary

### Negative
- Cross-repo coordination cost: a feature touching OS + an agent now needs two PRs
- Schema drift risk between OS HTTP DTOs and consumer packs (mitigated by OpenAPI codegen — to land per future ADR)
- Local dev now requires multiple repos cloned; mitigated by docker-compose orchestration that pulls the latest pack images
- Atomic refactors across OS + pack require careful semver discipline

### Neutral
- The parent `cognic` repo continues hosting agents, UI, and the legacy bundled monolith until the plugin migration completes (Phase 2-4 per ARCHITECTURE.md §7)
- Existing ADRs from the parent repo are renumbered starting from ADR-001 here; the new numbering reflects this repo's architectural decisions, not the parent's history

## Alternatives considered

1. **Keep monorepo with import-discipline** (parent repo's ADR-009 path): proven to work but doesn't physically separate procurement / permission boundaries. Long-term operational coupling persists.
2. **Three-way split** (OS / agents / UI in separate repos, splitting agents into one repo): possible but doesn't solve the agent-as-bundle problem (adding an agent still rebuilds the agents image). Plugin packaging is the actual fix.
3. **Plugin packaging in monorepo** (each agent gets its own `pyproject.toml` inside the same git repo): solves bundling but doesn't solve procurement / permission isolation.

The chosen approach (separate OS repo + per-pack repos) gets all three benefits.

## Implementation

This ADR is satisfied by the initial commit creating this repo from the parent's OS-tier source. Subsequent ADRs (002-006) cover the protocol, plugin packaging, sandbox, sub-agent, and ISO 42001 mapping needed for the architecture to be complete.

## References
- Parent repo ADR-009 (OS↔Agents separation in monorepo) — superseded by this approach
- `docs/source-of-truth/ARCHITECTURE.md` — canonical architecture
- ADR-002 (MCP plugin protocol) — how packs install
