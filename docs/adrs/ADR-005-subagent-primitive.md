# ADR-005 — Sub-Agent Primitive (Orchestrator-Worker Spawning)

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

Per Anthropic's Managed Agents pattern: a "lead" agent dynamically spawns specialised "worker" sub-agents — each runs in its own isolated context window, with a tool allow-list narrower than the parent's. The orchestrator stays slim by delegating; the worker context is discarded after returning a result to the parent.

This is **different from** `workflows/`'s composed-flow pattern:
- Composed flow = pre-defined Temporal choreography (deterministic, workflow author owns sequence)
- Sub-agent = dynamic delegation (LLM owns the spawn decision)

Today AgentOS has no sub-agent primitive. Multi-agent flows must be hard-coded as composed Temporal workflows. For real banking use:
- RM Copilot mid-brief realises "STR flag spotted, need AML verification" → cannot dynamically spawn
- PolicyQA realises "this needs Shariah opinion" → cannot dynamically spawn
- Long investigations blow up the parent's context window because there's no way to delegate

## Decision

Add a `subagent/` primitive providing `SubAgent.invoke(prompt)`. Sub-agents spawn via the A2A endpoint (per ADR-003). Each sub-agent gets:

- **Own context window** — no parent context inherited unless explicitly passed
- **Narrowed tool allow-list** — sub-agent's allowed tools ⊆ parent's allowed tools (privilege de-escalation)
- **Capped budget** — max tokens, wall-time, recursion depth (per-tenant max + per-call request)
- **Linked decision-history record** — child decision row references parent's chain hash (audit chain integrity)
- **Discardable context** — after returning, sub-agent context is destroyed; only the result + decision record persist

### Recursion depth
Per-tenant configurable; default `max_depth = 3`. Sub-agent attempting to spawn beyond depth raises `SubAgentDepthExceeded` and is escalated to a reviewer.

### Privilege de-escalation rule
The harness enforces `sub_agent.tool_allow_list ⊆ parent.tool_allow_list`. Sub-agent cannot escalate to a tool the parent didn't have. Configurable per-tenant override (with audit) for cases where a specialist sub-agent needs an additional tool the parent shouldn't.

### Audit
Every spawn → execute → return cycle emits four events on the parent's chain:
- `subagent.spawn(target, policy, parent_trace_id)`
- `subagent.start(child_trace_id)`
- `subagent.return(child_trace_id, result_summary)`
- `subagent.budget(tokens_used, wall_time_used)`

Plus the sub-agent's own decision_history record (chained to the parent).

### ISO 42001 mapping
Sub-agent spawn + return events map to ISO 42001 Annex A controls around **delegation accountability** and **action traceability**. Per ADR-006 each event is tagged with applicable control IDs.

## Consequences

### Positive
- **Dynamic delegation** without context-window blow-up
- **Privilege containment** — sub-agents can't escalate beyond parent
- **Audit chain integrity** — full cross-agent traceability
- **Token budget control** — per-call cap prevents runaway spawning

### Negative
- **Wire-protocol complexity** — A2A spawn + return + audit linkage is non-trivial
- **Test-coverage burden** — every sub-agent spawn path needs negative-path tests (depth, budget, privilege escalation, parent-cancellation)
- **Reasoning cost** — agents that don't currently do delegation will need explicit prompt engineering to use the primitive

### Neutral
- Sub-agent spawn overhead is comparable to a tool call (~50-200ms for in-process; more for cross-pod)
- Composed flows (Temporal) and sub-agents (dynamic A2A) coexist — same audit chain semantics

## Implementation phases
1. **Phase 4.1**: A2A-backed `SubAgent.invoke()` (depends on ADR-003)
2. **Phase 4.2**: Privilege de-escalation enforcement at the harness boundary
3. **Phase 4.3**: Budget + depth caps + escalation on exceed
4. **Phase 4.4**: Audit chain integrity test (Merkle proof over cross-agent events)

## References
- [Anthropic — Sub-agents in Claude Code](https://docs.anthropic.com/en/docs/claude-code/sub-agents)
- [The Architecture of Scale: Anthropic's Sub-Agents — Medium](https://medium.com/@jiten.p.oswal/the-architecture-of-scale-a-deep-dive-into-anthropics-sub-agents-6c4faae1abda)
- ADR-003 (A2A — substrate for sub-agent spawning)
- ADR-004 (sandbox — sub-agents may run in their own sandbox)
