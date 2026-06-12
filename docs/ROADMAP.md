# Cognic AgentOS — Roadmap (retired pointer)

**Retired 2026-06-12** at the Build Plan Reconciliation. This file's sprint checklist froze at "Pre-code (2026-04-26)" while execution moved into `docs/BUILD_PLAN.md`'s in-place status blocks; maintaining two roadmaps guaranteed divergence, so the checklist is retired rather than refreshed.

Authoritative surfaces now:

- **What v1 IS (as-built capability map + forward sequence):** [`docs/AS_BUILT_CAPABILITY_MAP.md`](AS_BUILT_CAPABILITY_MAP.md)
- **Sprint-level execution record (status/reconciliation blocks per sprint):** [`docs/BUILD_PLAN.md`](BUILD_PLAN.md)
- **Doctrine + repo guardrails:** [`docs/PROJECT_PLAN.md`](PROJECT_PLAN.md) and [`docs/source-of-truth/ARCHITECTURE.md`](source-of-truth/ARCHITECTURE.md)

The retired pre-code checklist is preserved in git history (`git log -- docs/ROADMAP.md`).

## Long-horizon items carried forward (no other doc holds these)

**Phase 5 — AgentOS Studio (deferred; only if a bank explicitly demands no-code authoring):** Studio API + pack-definition store + compiler; instance-key trust model (ADR-021 drafted at Phase-5 entry); React `studio-ui/` artefact; promotion workflow reusing the Sprint-13 gate machinery. See `docs/BUILD_PLAN.md` Phase 5.

**Wave 2 (post-1.0):** Cognic Forge (separate repo/product per ADR-013); AGNTCY adoption (identity + observability + group communication over MCP+A2A); gVisor / Firecracker sandbox backends; AIUC-1 mapping when the schema stabilises; EU AI Act high-risk control mapping; multi-region active-active topology; AGNTCY identity for cross-bank federated agent calls.

**Wave 3 (later):** DPO / RLHF / RLAIF post-training in Cognic Forge; cross-tenant federated training (privacy-preserving); model-cost reconciliation dashboard.

**Out of scope (forever):** Layer C agents (separate pack repos); portal UI (separate artefact); per-agent workflows (agent-pack repos); per-bank overlays (bank-overlay repos); anything tools/skills/agents could ship as a pack themselves.
