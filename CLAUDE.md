@AGENTS.md

# Cognic AgentOS — Claude Code Project Memory

You are operating inside the **Cognic AgentOS** repo — the OS-only platform. Agents, tools, skills, and UI live elsewhere; do not add them here.

## Project truth hierarchy
1. `docs/source-of-truth/ARCHITECTURE.md` (canonical architecture)
2. ADRs in `docs/adrs/`
3. `AGENTS.md` (operating model)
4. Strategy docs from the parent cognic repo (carried forward where still relevant)

## Non-negotiable delivery rules

- AgentOS = governance kernel + runtime + protocol + harness. Nothing else.
- Tools, skills, agents, UI → separate repos / packs. **Do not add them here.**
- Three-pool architecture is enforced for **plugin packs** (when they ship): tools (no LLM), skills (no LLM), agents (LLM only). Inside this repo we have platform primitives, persistence adapters, portal surfaces, protocol layer, and compliance evidence.
- Build against the 20 approved ADRs in `docs/adrs/`:
  - ADR-001 OS-only platform (ACCEPTED)
  - ADR-002 MCP plugin protocol — Streamable HTTP first, STDIO restricted by 4-gate threat model + OAuth/PRM authorization + AGNTCY/OASF identity fields (APPROVED, amended)
  - ADR-003 A2A inter-agent — pinned to A2A 1.0 spec with conformance fixtures + Wave 1 feature scope (Agent Cards, tasks, streaming, artifacts) (APPROVED, amended)
  - ADR-004 sandbox primitive — including resumable session API (`checkpoint() / suspend() / wake()`) (APPROVED, amended)
  - ADR-005 sub-agent primitive (APPROVED)
  - ADR-006 ISO 42001 control mapping (APPROVED)
  - ADR-007 provider honesty — runtime-audited self-hosted posture (APPROVED)
  - ADR-008 authoring platform — SDK + CLI now, Studio UI deferred (APPROVED)
  - ADR-009 pluggable infrastructure adapters — Postgres + Oracle + Qdrant + Vault + Ollama + OpenAI-compat + Langfuse-OTel + Dynatrace bundled (APPROVED)
  - ADR-010 evaluation harness — bulk + simulated + replay + LLM-judge (APPROVED)
  - ADR-011 adversarial testing — auto-generated red-team gate (APPROVED)
  - ADR-012 bank pack lifecycle — portal API + 5-gate approval (cosign + allow-list + eval + adversarial + OWASP) (APPROVED)
  - ADR-013 model lifecycle & fine-tuning boundary — Model Registry primitive in OS; Cognic Forge as Wave 2 separate repo (APPROVED)
  - ADR-014 runtime tool approval — per-tool risk tiers; single-approval / 4-eyes / categorised-reason gates with expiry (APPROVED)
  - ADR-015 policy-as-code — OPA / Rego bundles for admission, routing, approval, egress, sub-agent spawn, lifecycle (APPROVED)
  - ADR-016 supply-chain controls — cosign + SLSA L3+ + in-toto + SBOM + vuln scan + license audit + 7-year Sigstore bundle retention (APPROVED)
  - ADR-017 data governance contracts — pack manifest declares data classes, purpose, retention, egress allow-list, DLP hooks, consent (APPROVED)
  - ADR-018 emergency controls — kill switches (pack/tool/model/tenant/cloud/feature) + quotas; ≤30s P99 propagation; fail-closed (APPROVED)
  - ADR-019 agent memory governance — governed memory API (remember/recall/forget/redact/export); three tiers (scratch/task/long_term); default-deny long-term; regulator-erasure pathway (APPROVED)
  - ADR-020 UI event-stream contract — typed events (run state / tool calls / sub-agent / approvals / interrupts / artifacts / frontend actions); SSE default; reconnect-safe via decision_history mirror (APPROVED)
- ADR-021 (Studio trust model) is reserved for Phase 5 entry; do not implement against it yet.
- Conformance docs: `docs/MCP-CONFORMANCE.md` and `docs/A2A-CONFORMANCE.md` are authoritative for which protocol features are supported, restricted, or forbidden per wave.
- No hardcoded secrets; no hardcoded model checkpoint names; aliases only via the LLM gateway.
- Every LLM call must trace to Langfuse with `agent_workforce_id` (when an agent is involved).
- No direct threshold, consent, audit, deployment, incident, or release-gate shortcuts.
- If a path falls under the critical-controls rule, use `core-controls-engineer` and `/critical-module-mode`.
- Plugin trust gate is critical control — signature verification + per-tenant allow-list MUST run before any pack is registered.

## Working style
- Start every session by identifying the subsystem (governance / runtime / protocol / portal / observability / persistence) you're touching
- Read the relevant ADR before editing
- Explore before editing; edit narrowly; run relevant tests after changes
- Update ADRs, evidence, and docs when the change requires them
- Flag uncertainty instead of inventing architecture

## Git workflow discipline
- Work on one feature branch per subsystem change
- Commit at logical checkpoints: subsystem milestone, tests green for touched scope, ADR update complete, READY FOR GATE candidate state
- Do not create a commit for broken work unless the human explicitly asks for a WIP snapshot
- Before stopping, check whether there are meaningful tested changes that should be committed; propose or create a commit with a conventional message if appropriate
- Do not merge, rebase, push, force-push, or rewrite history unless the human explicitly asks
- Do not auto-commit unrelated files

## Production-grade implementation rule

Cognic AgentOS is being built as a production-grade system. The product should be deployable largely as implemented, not rewritten later.

Rules:
- Do not implement mock, fake, placeholder, or synthetic behavior in the main runtime path.
- Do not replace real integrations with mock generators just because CI or local setup is harder.
- Stub modules that raise `NotImplementedError` pointing at an ADR are acceptable scaffolding (they fail loudly and document the contract); silent in-process fallbacks that pretend to work are not.
- Test-only mocks, fixtures, and demo-safe sample data are allowed only under clearly separated test/demo paths.
- Production code paths must remain real, swappable, and deployable.

## Plugin discipline (the OS / pack boundary)

This is the most-frequently-violated rule:

- Do **not** add an agent, agent identity, agent-specific schema, agent-specific workflow, or persona-specific evaluation scorer here. They belong in `cognic-agent-<name>` plugin pack repos.
- Do **not** add bank-specific CBS adapters, bank-specific themes, or bank-specific OIDC config here. They belong in bank-overlay repos.
- Do **not** import from a hypothetical `cognic_agentos.agents.*` — there is no such package. Use the plugin registry (`cognic_agentos.protocol.plugin_registry`) for any agent-pack interaction.
- Do **not** bundle a tool inside `cognic_agentos.tools.*` long-term. The bundled tools today are debt; new tools ship as MCP server packs per ADR-002.

When in doubt, ask: "would a bank deploying AgentOS without this pack still get value?" If yes, it's OS. If no, it's a pack.

## Human-only decisions
Do not finalise: threshold changes, production deployments, model promotions/rollbacks, compliance sign-off, release gates, evaluation dataset acceptance, incident severity, bank communications, certification commitments, plugin trust-root rotation, per-tenant allow-list changes.

## Compaction

When compacting or stopping, preserve:
- Current subsystem and objective
- Files changed
- Tests run and results
- Open risks / blockers
- ADR status
- Whether governance, sandbox, sub-agent, plugin trust, RBAC, cloud-policy, wire-protocol contracts, or compliance-evidence schema were touched
- Next concrete step
