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

---

## Sprint 12 amendment — bulk evaluation harness (2026-06-08)

This amendment records the decisions taken when Sprint 12 built the **bulk-test substrate** on top of the merged LLM-as-judge slice. It supersedes nothing in the original decision; it narrows the Sprint-12 scope to what an OS-only repo (no Layer-C agent packs) can ship, and records every piece deliberately deferred to Sprint 13.

### Scope

New modules: `evaluation/{types,corpus,target,scorers,runner,storage}.py`, `portal/api/evaluation/{dto.py (extended with the bulk DTOs), bulk_routes.py}`, `cli/eval.py` + the `agentos eval-bulk` command, Alembic migration `0008` (`eval_runs` + `eval_case_results`), and a neutral reference corpus at `evaluation/corpora/example/generic-completion-smoke.yaml`.

### Plug-in seams (the Sprint-13 extension points)

- **`EvaluationTarget`** Protocol — `async run_case(case, *, request_id, tenant_id) -> CandidateOutput` (`evaluation/target.py`).
- **`CaseScorer`** Protocol — `async score(case, output, *, request_id, tenant_id) -> ScorerResult` (`evaluation/scorers.py`).
- **`EvalRunner.run(...)`** is target- AND scorer-agnostic — it takes the target + scorer list as arguments and never names a concrete implementation.

### `GatewayTarget` is the only Wave-1 target

This OS-only repo has no Layer-C agent packs, so the only working system-under-test is the governed `LLMGateway`. `GatewayTarget` dispatches a case's message list through one `completion()` at the operator-configured tier and converts the closed set of known gateway exceptions into an `errored` `CandidateOutput`. MCP / A2A / replay targets are Sprint 13.

### Scorers + pass semantics

- Deterministic **`AssertionScorer`** (`contains` / `not_contains` / `regex` / `json_path`) — no tokens.
- **`JudgeScorer`** reuses the merged `run_judge(...)` primitive (no duplicated judge logic); it passes iff `verdict == "pass"`.
- **A case passes iff every DECLARED scorer block is scored and passes.**
- **Fail-closed:** a case whose declared scorer block has no scorer that ran is `outcome="errored"` (harness misconfiguration, never a vacuous `all(())` pass). The production route always injects both scorers, so this is defence-in-depth.
- **Deliberate Sprint-12 limitation:** the runner's scorer-coverage check (`_applicable_scorers` / `_declared_blocks_covered`) keys off the two built-in scorer CLASS NAMES (`AssertionScorer` / `JudgeScorer`). A scorer-declared `block` attribute that decouples the runner from specific scorer classes is DEFERRED to Sprint 13 (when additional scorers land).

### Per-case error isolation

A target/scorer exception, or a target-returned `errored` output, marks only that case `errored` (`_errored_case`); the run continues and never aborts. Per-case isolation is the governing rule of `EvalRunner._run_case`.

### Case + corpus contract

Single-shot message-list `completion` cases. The loader is strict and fail-closed: `extra="forbid"` Pydantic models, the closed-enum `CorpusLoadReason`, and duplicate-case-id / unknown-key / unsupported-schema-version are all rejected. `case_kind` is a reserved discriminator (currently `Literal["completion"]`) for the Sprint-13 kinds (`replay` / `tool_invocation` / `a2a_agent`).

### Single execution path + raw-output posture

- The portal is the only execution path. `POST /api/v1/eval/bulk-run` runs the corpus synchronously under `eval_bulk_max_cases` (over-cap ⇒ `413 eval_corpus_too_large`; an explicitly-empty corpus ⇒ `400 eval_corpus_empty`). `GET /api/v1/eval/runs/{run_id}` is tenant-scoped — cross-tenant and unknown both collapse to `404 eval_run_not_found`. The route-owned refusal vocabulary is the closed-enum `EvalBulkRefusalReason`.
- The CLI (`agentos eval-bulk`) is a thin portal client plus a local `--dry-run`; it never constructs the runtime or the gateway.
- `persist_raw_output` is opt-in (`pydantic.StrictBool`, default `false`; `"true"` / `1` are rejected `422`). When true, each case's candidate text is stored truncated to `eval_bulk_max_raw_output_chars`, flagged with `raw_output_persisted` / `output_truncated`.
- `eval_bulk_target_tier` (the model under test) is distinct from `eval_judge_tier` (the evaluator); both are operator-configured and callers cannot choose the tier.

### Evidence + ISO

- One aggregate, **VALUE-FREE** `eval.bulk_run` `decision_history` chain row per run — counts plus a per-case projection `{case_id, passed, output_digest}`, never raw text.
- Operational per-run / per-case rows live in `eval_runs` / `eval_case_results`.
- The chain back-link is by **`chain_request_id`** (there is NO `chain_record_id` column): `record_id` is minted *after* the `append_with_precondition` precondition closure runs, which is the ADR-023 atomicity class — so the request-id is the only identity available at row-build time.
- ISO controls: **A.7.6** (flipped `deferred → implemented` — a bulk eval run IS a real AI-system risk-evaluation emission surface) **+ A.9.2**, stamped via `_EVAL_ISO_CONTROLS` (the constant carries the prefixed forms `ISO42001.A.7.6` / `ISO42001.A.9.2`) in `evaluation/storage.py`.

### File-placement refinements vs the design spec

- The strict `EvalCase` / `Corpus` models live in **`corpus.py`** (the CC module that owns the corpus contract), NOT in `types.py` (which holds only the pure runtime-result dataclasses).
- `EvalRunStore` takes a `DecisionHistoryStore` (`EvalRunStore(history)`) — no separate engine handle.
- `EvalRunner.run(...)` RECEIVES `run_id` / `chain_request_id` from the caller; it does not mint identity (the portal mints both; `mint_eval_request_id()` lives in `storage.py`).

### Critical-controls gate

`corpus.py` + `scorers.py` + `runner.py` + `storage.py` are promoted to the per-file critical-controls coverage gate (count **117 → 121**, 95% line / 90% branch floor). `target.py` / `types.py` and the portal route/DTO modules stay off-gate per the R32 precedent (thin wiring / pure type modules; the substantive enforcement rides the four on-gate modules). `judge.py` was already on the gate from the merged judge slice.

### Deferred to Sprint 13

- `McpToolTarget` / `A2AAgentTarget` / replay targets;
- citation / refusal / replay-diff / promotion-gate scorers;
- the reserved case kinds (`replay` / `tool_invocation` / `a2a_agent`);
- multi-turn scenarios;
- weighted aggregate scoring (the `weight` field on `JudgeCriterionSpec` is recorded but non-gating in Sprint 12);
- a background async large-corpus queue;
- the scorer-`block`-attribute decoupling noted under *Scorers + pass semantics*;
- a corpus-taxonomy polish — an empty-clauses `assertions` block currently maps to `corpus_case_messages_invalid` via the `_reason_for_validation_error` fallback, which is semantically odd ("no clauses" is not a message error); a sharper reason is a Sprint-13 item.

### Harness-design alignment

Per the Sprint-12 spec §8 and Anthropic's "Building harnesses for long-running agentic applications" (2026-03-24):

- **Generator/evaluator separation** — the target generates, the scorer evaluates; the two are independent Protocols.
- **Gradable quality** — per-criterion critiques are carried on `ScorerResult` (`CriterionDetail`), so a failure is actionable.
- **Durable structured artifacts** — corpus YAML, the `EvalRunResult`, the relational rows, and the value-free chain row.
- **Deliberate simplicity** — portal-only execution, synchronous + capped, no CLI-side gateway, no async queue.

Each deferred piece above is recorded, not built — the simplicity is a deliberate Sprint-12 choice, with the extension seams (`EvaluationTarget` / `CaseScorer`) already in place for Sprint 13.
