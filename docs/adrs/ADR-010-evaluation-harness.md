# ADR-010 — Evaluation Harness (Bulk Testing, Simulated Scenarios, Live Case Replay, LLM-Judged Verdicts)

## Status
**APPROVED for implementation** on 2026-04-26.

## Context

Banks evaluating an agent platform — Cognic vs Sprinklr / Salesforce / etc. — will ask in week 2 of procurement: *"How do I test a new agent version against my last 6 months of cases before promoting it to production?"*

Sprinklr AI+ Studio answers this with **bulk testing**, **simulated conversations**, **live case replay**, and **Autonomous Evaluation** (LLM-as-judge with explainable verdicts). As of April 2026 these are central to their offering.

Cognic AgentOS today has unit tests + integration tests + a strong audit chain (`decision_history`), but **no first-class evaluation harness**. A bank evaluating PolicyQA today would have to script their own test runner against the audit corpus.

This is a procurement gap, but it's also a *quality* gap: without an evaluation harness baked into the platform, agent packs can drift in production with no automated catching mechanism. The audit chain captures *what happened*; the evaluation harness answers *whether it should have happened*.

## Decision

Add a first-class **Evaluation Harness** to AgentOS. Four capabilities, all hash-chain-audited and ISO 42001-tagged for governance:

### 1. Bulk test runner

Run an agent pack against a corpus of test cases (declared via JSON/YAML or pulled from `decision_history`). Reports per-case pass/fail + aggregate accuracy, latency P50/P95, citation faithfulness, regulatory verdict distribution.

```python
# CLI invocation
agentos eval bulk \
  --pack cognic-agent-policyqa:0.5.0 \
  --corpus tests/fixtures/policy_qa_eval_v1.yaml \
  --judge cognic-tier1-vllm \
  --report-out reports/policyqa-0.5.0.json
```

API surface (for CI integration):
```
POST /api/v1/eval/bulk-run
  { pack, corpus_ref, judge_model, parallelism }
  → { run_id, started_at }

GET /api/v1/eval/runs/{run_id}
  → { status, progress, summary, per_case_results }
```

### 2. Simulated conversations

Declarative scenario specs (YAML) describe multi-turn interactions. The harness runs them against an installed agent pack:

```yaml
scenario: rm_copilot_str_handoff
description: RM Copilot mid-brief realises STR flag, spawns AML sub-agent
turns:
  - actor: customer
    text: "Tell me about Acme Industries' payment history."
  - actor: agent
    expects:
      - tool_call: query_account_history
      - response_includes: "Acme"
  - actor: customer
    text: "There's a $5M wire to a Cayman shell company that looks suspicious."
  - actor: agent
    expects:
      - subagent_spawn: aml_investigation
      - escalation_triggered: true
assertions:
  - decision_history_chain_valid: true
  - iso_controls: [A.6.2.5, A.7.4]
  - max_total_tokens: 8000
```

### 3. Live case replay

Take a real `decision_history` row from production, re-run it against a candidate agent version, **diff the outcome**.

```
agentos eval replay \
  --case-id abc123-... \
  --pack cognic-agent-policyqa:0.5.0 \
  --baseline cognic-agent-policyqa:0.4.0
```

Output highlights:
- Was the answer materially different?
- Did the citation set change?
- Did the compliance score change?
- Did the chain of tool calls change?

This is the critical "regression test against production traffic" capability. Banks will use it before every promotion.

### 4. LLM-as-judge with explainable verdicts

Sprinklr's "Autonomous Evaluation" — an LLM scores agent outputs against a rubric and **explains its reasoning**. Cognic's version runs through the same governed gateway as production calls (so the judge model itself is audited):

```yaml
rubric:
  - dimension: factual_accuracy
    description: "Does the answer correctly state the SBP CTR threshold?"
    weight: 0.4
  - dimension: citation_relevance
    description: "Are cited sources actually about CTR reporting?"
    weight: 0.3
  - dimension: regulatory_compliance
    description: "Does the answer avoid prescriptive legal advice?"
    weight: 0.3
```

Each judge verdict produces:
- Score per dimension (0-1)
- One-paragraph explanation per dimension
- Aggregate score
- A hash-chained `eval.judge_verdict` event in `decision_history` linked to the case under test

Cognic differentiator vs Sprinklr: **the judge's reasoning itself is audited**. Banks can prove which model judged which case with what reasoning. Sprinklr's audit chain stops at the judge boundary; ours doesn't.

### Storage + corpus management

- Eval corpora: YAML files in pack-author repos (`cognic-agent-<name>/eval/corpora/*.yaml`); reusable across versions
- Eval runs: stored in Postgres `eval_runs` table; per-case results in `eval_case_results`
- Production-replay cases: pulled live from `decision_history`; replay runs reference the source case by `decision_record_id`
- Reports: exported as JSON + Markdown summary for human review; uploaded to object storage (per ADR-009 ObjectStoreAdapter — Sprint 8)

### Integration with promotion workflow

Phase 4 deployment kit (Sprint 14, formerly Sprint 12) declares "an agent pack cannot promote dev → stage → prod without:
- Bulk test pass-rate ≥ tenant threshold (default 0.85)
- Live replay regression count ≤ tenant threshold (default 0)
- Judge-verdict aggregate ≥ tenant threshold (default 0.80)"

Promotion is gated by the harness. Bank operators can override with explicit RBAC scope + audit reason.

## Consequences

### Positive
- **Procurement parity** with Sprinklr / Salesforce / Microsoft on the testing-tooling dimension
- **Promotion confidence** — banks know they're not regressing on production cases when they upgrade an agent pack
- **Continuous improvement loop** — eval results feed back into pack authors' iteration
- **Audited judge** — Sprinklr's judge isn't audited; Cognic's is. Defensible to regulators.
- **Reusable corpora** — pack authors ship reference corpora; banks fork + extend with their own cases

### Negative
- **Significant scope addition** — ~2 work-units for the harness + ~0.5 for promotion-gate integration
- **Judge model cost** — every bulk run consumes LLM tokens. Banks need budget visibility (Langfuse already covers this; surface it in eval reports)
- **Corpus drift** — corpora become stale as regulations evolve. Need a "corpus freshness" metric in the eval report
- **False-positive judge verdicts** — LLM judges are imperfect. Mitigation: ship a calibration tool that compares judge verdicts against human spot-checks; report agreement rate

### Neutral
- The harness is **bundled with AgentOS** (not a plugin pack) because every bank deployment needs it from day 1 — same logic as the audit chain
- Live case replay reuses the same governed pipeline as production — no shadow paths

## Implementation phases

| Sprint | Work |
|---|---|
| **Sprint 12** (was unallocated; new in Phase 4) | Bulk test runner + simulated scenarios + storage tables + CLI commands |
| **Sprint 13** (was unallocated; new in Phase 4) | Live case replay + LLM-judge with explainable verdicts + promotion-gate integration |

Total: ~3.5 work-units (across the two sprints).

## References
- [Sprinklr AI+ Studio (Spring '26 release)](https://www.sprinklr.com/products/platform/ai-plus-studio/) — competitor benchmark
- [Anthropic — Building Effective AI Agents](https://www.anthropic.com/research/building-effective-agents) — eval principles for agent systems
- ADR-006 (ISO 42001) — eval verdicts emit ISO-tagged events
- ADR-007 (provider-honesty) — eval judge model uses the same audited gateway as production
- ADR-009 (pluggable adapters) — eval reports stored via ObjectStoreAdapter (S3 / Azure Blob / GCS)
