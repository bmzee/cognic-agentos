# ADR-008 — Authoring Platform: SDK Now, Studio Later

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

Per ADR-001 + ADR-002, AgentOS hosts plugin packs (tools / skills / agents / **hooks**) that ship as separately-versioned distributions. The original assumption was that packs are authored *externally* — engineers write them in their own IDE, sign with cosign, push to a registry, and AgentOS discovers them via Python entry points. (The `hooks` kind was added to the enumeration in the Sprint-7A2 amendment — see "Sprint-7A2 amendments" below.)

Real-world authorship spans three audiences:

1. **Cognic platform team** — writes the first ~10 packs by extracting them from the parent cognic monorepo (PolicyQA, RegIntel, AML, Credit, Shariah, RM Copilot, AI Governance, SBP Evidence, Compliance Checker, plus tool packs).
2. **Bank engineers** — write bank-specific packs (CBS adapters, internal-data tools, custom agents) without forking AgentOS.
3. **Wider MCP ecosystem** — third-party MCP server authors who want to package as cognic-compatible.

All three need scaffolding, signing, and registration tooling. Without this, every author re-invents the pack layout, the cosign integration, the entry-point declaration, and the test harness.

A second tier of authorship exists: **non-engineer business users** (compliance officers, ops leads) who want to compose a new tool / skill / agent from existing primitives without writing code. This requires a UI inside AgentOS — significant scope, different trust model.

## Decision

Ship authoring in **two phases**:

### Phase A — SDK + CLI (mandatory, lands in build Phase 2)

`cognic-agentos` ships an `agentos-sdk` Python library + `agentos-cli` command:

```
agentos init-tool my-tool       → scaffolds cognic-tool-my-tool/ pack repo
agentos init-skill my-skill     → scaffolds cognic-skill-my-skill/ pack
agentos init-agent my-agent     → scaffolds cognic-agent-my-agent/ pack
agentos init-hook my-hook       → scaffolds cognic-hook-my-hook/ pack (Sprint 7A2)
agentos validate                → schema check + lint + test the pack
agentos sign --key vault://...  → cosign-sign the wheel
agentos register --local        → install into local AgentOS dev instance
agentos publish --registry ...  → push to OCI / pip registry
```

Each `init-*` produces a working skeleton: `pyproject.toml` with the right entry-point group declared, MCP server scaffold (for tools/skills) or A2A handler scaffold (for agents), Dockerfile, signing CI workflow, smoke tests.

The SDK exposes Python helpers any pack author can import:

- `agentos_sdk.tool` — base classes for MCP tool implementations
- `agentos_sdk.skill` — composition helpers for skills (no LLM)
- `agentos_sdk.agent` — base class for A2A-speaking agents with the harness contract baked in
- `agentos_sdk.hook` — base class for governance hook packs (Sprint 7A2 — DLP pre/post phases Wave-1; deterministic `Hook` ABC + `HookContext` + `HookResult` + closed-enum `HookPhase`)
- `agentos_sdk.testing` — fixtures + assertions for pack tests
- `agentos_sdk.compliance` — ISO 42001 control declaration helpers (per ADR-006)

This phase satisfies the engineering audience — Cognic team, bank engineers, ecosystem.

### Phase B — Studio UI (deferred, lands as build Phase 5)

AgentOS hosts a web UI panel at `/studio/` where authorized users can:

- Define new tools by choosing input/output schemas + composing from existing primitives (database query, HTTP call, regex, etc.) — no code
- Compose skills by chaining tools deterministically
- Author agents by declaring prompts + allowed tool list + sub-agent permissions
- Save → AgentOS Studio compiler generates the equivalent pack code, signs with the **AgentOS instance key** (different trust root from externally-published packs), registers
- Promote packs through dev → stage → prod via a 4-eyes RBAC-gated workflow

Studio-authored packs are **first-class plugins** — same MCP / A2A protocols, same audit, same governance. The only difference: they're signed by the AgentOS instance, not by an external author. This requires a separate trust gate decision (see ADR-002 amendment in Phase 5).

This phase satisfies the non-engineer audience and accelerates iteration for power users.

## Consequences

### Positive (Phase A)
- Three audiences serviced from day one with minimal scope addition
- `init-*` scaffolds enforce conventions automatically — no per-author divergence
- The cognic team itself uses the SDK to extract packs from the parent monorepo, dogfooding before any third party touches it
- MCP ecosystem authors get a clear "make your tool cognic-compatible" recipe
- SDK is a Python package; banks pip-install it, no infra change

### Positive (Phase B)
- Bank business users can author packs without engineering tickets — order-of-magnitude faster iteration
- Pack composition from primitives reduces the surface area an author can break (vs. writing arbitrary Python)
- Studio audit captures author identity per pack — full accountability
- Promotion workflow gates production rollout

### Negative (Phase A)
- SDK becomes part of AgentOS's public API surface — breaking changes need semver discipline
- CLI tool needs cross-platform packaging (Windows, macOS, Linux)
- Documentation burden — every primitive AgentOS exposes needs a "how to use from a pack" example

### Negative (Phase B)
- Significant scope: ~6 sprints / 10-12 weeks
- Trust model gets more complex — Studio-signed packs need their own per-tenant allow-list policy
- Composition primitives become a public API — adding/removing them is a breaking change
- "It works in Studio" vs "it works as a published pack" can drift if the compiler isn't bit-exact

### Neutral
- Studio is deferrable indefinitely. If banks express no demand, Phase B never ships. Phase A alone is a complete answer.
- The SDK can later be used to *generate* Studio's UI (since the SDK already declares what the primitives are) — no duplication of effort

## Implementation reference

Phase A lives in:
- `src/cognic_agentos/sdk/` — Python helpers
- `src/cognic_agentos/cli/` — `agentos-cli` entry point (added to pyproject.toml `project.scripts`)
- `docs/HOW-TO-WRITE-A-PACK.md` — author tutorial
- `docs/SDK-REFERENCE.md` — API reference

Phase B (deferred) will add:
- `src/cognic_agentos/studio/` — Studio API endpoints
- `studio-ui/` — separate React artefact (mirrors portal-ui pattern)
- `docs/adrs/ADR-021-studio-trust-model.md` — Studio-specific trust decisions (ADR-009 was claimed by pluggable infrastructure adapters; ADR-012 by bank pack lifecycle; ADR-013 by model lifecycle & fine-tuning; ADR-014 by runtime tool approval; ADR-015 by policy-as-code; ADR-016 by supply-chain controls; ADR-017 by data governance; ADR-018 by emergency controls; ADR-019 by agent memory governance; ADR-020 by UI event-stream contract; Studio trust takes ADR-021 when Phase 5 is approved)

## Sprint-7A2 amendments (descriptive — codifying what shipped, 2026-05-10)

Sprint 7A2 (`feat/sprint-7a2-hook-packs-runtime`) added **first-class governance hook packs** as a fourth authoring kind alongside tools / skills / agents. The amendment is **additive** — no existing decision changes; the original three-kind decision was written before the hook taxonomy firmed up. Amendments captured at this ADR:

- **Context line 8** — kind enumeration extended from `tools / skills / agents` to `tools / skills / agents / hooks`.
- **Phase A CLI section line 32** — added `agentos init-hook my-hook → scaffolds cognic-hook-my-hook/ pack (Sprint 7A2)` to the Phase A command surface.
- **Phase A SDK section lines 42-46** — added `agentos_sdk.hook` exposing `Hook` ABC + `HookContext` + `HookResult` + closed-enum `HookPhase` (Wave-1 phases: `dlp_pre` + `dlp_post`).

Hook packs follow the same trust model as the three pre-existing kinds: the ADR-002 trust gate verifies the cosigned wheel before the runtime registry admits the hook; the ADR-016 supply-chain bundle (cosign + SBOM + SLSA + in-toto + JWS Wave-1 agent-only) is unchanged for hook packs except that JWS-signing is conditioned on `kind == "agent"` (hooks are not A2A-speaking and ship no AgentCard).

## References
- ADR-001 (OS-only platform — defines what packs are)
- ADR-002 (MCP plugin protocol — defines the contract Phase A SDK satisfies)
- ADR-003 (A2A inter-agent — defines the agent pack contract)
- ADR-017 (data governance — defines the DLP pre/post hook phases the Sprint-7A2 amendment formalises)
- Parent cognic monorepo's existing agent/tool implementations — source material for Phase A SDK extraction
