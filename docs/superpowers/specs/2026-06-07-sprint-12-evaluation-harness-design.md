# Sprint 12 — Evaluation Harness — Design

**Date:** 2026-06-07
**ADR:** ADR-010 (Evaluation harness) — this sprint ships an **ADR-010 amendment**, not a new ADR.
**Status:** Design approved (brainstorm); pending implementation plan.
**Phase:** Phase 4 (Sub-agent + Memory + Quality gates + Deploy). Sprint 12 is the next canonical BUILD_PLAN sprint after Sprint 11.5.

---

## Goal

Build the bulk-test evaluation substrate that the already-merged LLM-as-judge slice (`evaluation/judge.py` + `POST /api/v1/eval/judge`, PR #51) is waiting on: a target-agnostic, scorer-agnostic **bulk runner**, a strict versioned **corpus loader**, **Postgres-backed eval storage** with a value-free decision-history chain row, a **portal API** (`bulk-run` + `runs/{id}`), a thin **CLI** (`agentos eval bulk`), and a **generic reference corpus**. AgentOS-only. Reuse `run_judge(...)`; do not duplicate judge logic. Design the seams so Sprint 13 (replay / adversarial / promotion gate) plugs in without rework.

## Architecture (one sentence each)

- A pure-library **`EvalRunner`** runs a loaded **`Corpus`** against an injected **`EvaluationTarget`** (Wave-1: `GatewayTarget` over the governed `LLMGateway`), scoring each case with one or more injected **`CaseScorer`** implementations (Wave-1: deterministic `AssertionScorer` + `JudgeScorer` that delegates to `run_judge`).
- The **portal** is the single execution path: it owns the gateway, the decision-history store, and settings, runs the corpus synchronously under a size cap, and persists the run + per-case results + a value-free `eval.bulk_run` chain row **atomically** via `DecisionHistoryStore.append_with_precondition`.
- The **CLI** never constructs the runtime or gateway: it is a thin client to the portal plus a genuinely-local `--dry-run` that loads and strict-validates a corpus and prints the plan.

## Tech stack

Python 3.12 · FastAPI · Pydantic v2 (strict) · SQLAlchemy Core + Alembic (per ADR-009 `RelationalAdapter`) · Typer (CLI) · PyYAML (corpus) · `uv` for all Python.

---

## §1 Package layout

The merged judge lives in `cognic_agentos.evaluation` (**not** the BUILD_PLAN's prospective `eval/` path, which predates the judge slice). Sprint 12 extends `evaluation/` to stay consistent. **The BUILD_PLAN `eval/...` references are corrected to `evaluation/...` in the same plan** (per `feedback_patch_plan_against_doctrine` — fix the source-of-truth claim in the commit that contradicts it).

```
src/cognic_agentos/evaluation/
  __init__.py            (exists, empty)
  judge.py               (exists — REUSED, untouched)
  types.py               NEW — EvalCase, Corpus, CandidateOutput, ScorerResult, CriterionDetail,
                                CaseResult, EvalRunResult + closed enums
  corpus.py              NEW — strict versioned YAML loader (fail-closed)            [CC gate]
  target.py              NEW — EvaluationTarget Protocol + GatewayTarget
  scorers.py             NEW — CaseScorer Protocol + AssertionScorer + JudgeScorer   [CC gate]
  runner.py              NEW — EvalRunner (pure library)                             [CC gate]
  storage.py             NEW — EvalRunStore (append_with_precondition consumer)      [CC gate]
  corpora/example/       NEW — generic reference corpus (format demo)

src/cognic_agentos/portal/api/evaluation/
  __init__.py            (exists, empty)
  dto.py                 (exists — judge DTOs; EXTEND with bulk-run DTOs)
  routes.py              (exists — judge route; untouched)
  bulk_routes.py         NEW — build_eval_bulk_routes(*, store, settings)

migrations/<rev>_eval_runs_and_case_results.py   NEW — eval_runs + eval_case_results (rev after 0007)

src/cognic_agentos/cli/
  __init__.py            (EXTEND — add `eval` Typer sub-app / command)
  eval.py                NEW — corpus load + thin portal client + dry-run renderer
```

Each module has one responsibility; `target.py` and `scorers.py` are the Sprint-13 plug-in surfaces and stay independent of `runner.py`.

---

## §2 Core seams (the Sprint-13 plug-in points)

```python
class EvaluationTarget(Protocol):
    async def run_case(
        self, case: EvalCase, *, request_id: str, tenant_id: str
    ) -> CandidateOutput: ...

class CaseScorer(Protocol):
    async def score(
        self, case: EvalCase, output: CandidateOutput, *, request_id: str, tenant_id: str
    ) -> ScorerResult: ...
```

**`GatewayTarget`** (the only Wave-1 target):
- Maps `case.messages` → `LLMGateway.completion(tier=…, messages=…, request_id=…, tenant_id=…)`.
- Returns `CandidateOutput(text, model, tier, latency_ms, outcome)` where `outcome` is a closed enum (`"succeeded" | "errored"`). A gateway exception is caught and surfaced as `CandidateOutput(text="", outcome="errored", …)` carrying the error category — it never aborts the run.
- `tier` is the operator-configured **`eval_bulk_target_tier`** setting (§4) — the tier of the model **under test**, distinct from the judge's `eval_judge_tier` (the evaluator). The caller cannot choose either tier (cost/abuse guard, consistent with the judge). This separation is the generator/evaluator split made operational (§8).

**`AssertionScorer`** (deterministic, no tokens):
- Closed assertion set: `contains` (list[str], all must appear), `not_contains` (list[str], none may appear), `regex` (list[str], each must match), `json_path` (list of `{path, equals}`; only valid when the case declares its output is JSON — otherwise refuses that case's json_path assertion fail-closed).
- Emits a `ScorerResult` with one `CriterionDetail` per assertion clause carrying `passed` + a human-readable `critique` (e.g. `'expected substring "capital adequacy" not found'`).

**`JudgeScorer`** (reuses the merged primitive — zero duplicated judge logic):
- Maps the case `judge` block → `JudgeRequest(candidate_output=output.text, candidate_input=<first user message content, optional>, criteria=[{name, description}])`.
- Calls `run_judge(request=…, gateway=…, request_id=…, tenant_id=…, tier=…)`.
- **Pass semantics: passes iff `verdict == "pass"`.** A `JudgeUnparseable` outcome → scorer fails with `critique` carrying the closed `parse_reason`.
- The judge dispatch uses the **`eval_judge_tier`** setting (the evaluator tier), not `eval_bulk_target_tier`.
- Emits a `ScorerResult` whose `CriterionDetail` tuple is the judge's per-criterion `criteria_results` (`name`, `passed`, `note→critique`), plus the verdict, score, and rationale recorded on the result.
- `weight` (if present on a criterion) is **recorded but non-gating** in Sprint 12; weighted aggregate scoring is a Sprint-13 promotion-gate concern.

**`EvalRunner.run(corpus, target, scorers, *, request_id, tenant_id) -> EvalRunResult`**:
- Target- and scorer-agnostic; iterates cases, calls the target once per case, then every declared scorer.
- **Pass semantics: a case passes iff every declared scorer passes.** A case with no declared scorers is a corpus-load error (rejected at load time, §3).
- **Per-case error isolation is the governing rule — a single failed case never aborts the run.** If the target returns `outcome="errored"` (a gateway exception during generation, which `GatewayTarget` catches internally), the case is `CaseResult(outcome="errored")` and **scorers are skipped**. If any scorer raises (including a gateway exception inside `run_judge` during `JudgeScorer.score`), the runner's per-case `try/except` captures it as `CaseResult(outcome="errored")` carrying the error category. Either way the run continues to the next case. An `errored` case counts toward `total` and `errored`, never toward `passed`/`failed`. Aggregate counts: `total = passed + failed + errored`.
- Computes per-run latency P50/P95 from per-case latencies.
- Pure library: no I/O, no DB, no FastAPI. Fully unit-testable with fakes.

### Result types

```python
@dataclass(frozen=True, slots=True)
class CriterionDetail:
    name: str        # assertion clause label, or judge criterion name
    passed: bool
    critique: str    # why it passed/failed — actionable, capped length

@dataclass(frozen=True, slots=True)
class ScorerResult:
    scorer: Literal["assertions", "judge"]
    passed: bool
    detail: tuple[CriterionDetail, ...]
    # judge-only, None for assertions:
    verdict: Literal["pass", "fail", "inconclusive"] | None
    score: float | None
    rationale: str | None

@dataclass(frozen=True, slots=True)
class CaseResult:
    case_id: str
    passed: bool
    outcome: Literal["succeeded", "errored"]
    scorer_results: tuple[ScorerResult, ...]
    latency_ms: int
    model: str
    input_digest: str
    output_digest: str
    candidate_output_text: str | None   # only when persist_raw_output (bounded)
    raw_output_persisted: bool
    output_truncated: bool

@dataclass(frozen=True, slots=True)
class EvalRunResult:
    run_id: uuid.UUID
    corpus_id: str
    corpus_digest: str
    target_kind: str            # "gateway"
    tier: str
    total: int
    passed: int
    failed: int
    errored: int
    latency_p50_ms: int
    latency_p95_ms: int
    cases: tuple[CaseResult, ...]
    chain_request_id: str       # caller-minted bounded request_id, also on the DecisionRecord
```

---

## §3 Corpus schema (strict, versioned, fail-closed)

`--corpus path/` loads every `*.yaml`/`*.yml` under the directory in **deterministic sorted order**. Each document:

```yaml
schema_version: 1
corpus_id: generic-completion-smoke
description: Generic completion smoke corpus demonstrating the schema.
cases:
  - id: car-definition
    case_kind: completion        # required; reserved discriminator for Sprint-13 kinds
    messages:
      - role: system
        content: "Answer as a precise assistant."
      - role: user
        content: "Define capital adequacy ratio."
    assertions:
      contains:
        - "capital adequacy"
      not_contains:
        - "current account ratio"
    judge:
      rubric: "Answer defines capital adequacy ratio correctly."
      criteria:
        - name: correctness
          description: "States that CAR is the ratio of a bank's capital to its risk-weighted assets."
          weight: 1.0
```

Loader contract (`load_corpus(path) -> Corpus`), strict Pydantic v2, **fail-closed**:
- Unknown key anywhere → reject (`extra="forbid"`).
- `schema_version != 1` → reject (`corpus_schema_version_unsupported`).
- Directory contains no `*.yaml`/`*.yml` → reject (`corpus_no_documents`).
- Duplicate `case.id` across all loaded files → reject (`corpus_duplicate_case_id`).
- A case with neither `assertions` nor `judge` → reject (`corpus_case_no_scorer`).
- `case_kind` must equal `"completion"` in v1 (other kinds reserved) → else reject (`corpus_case_kind_unsupported`).
- `messages` must be non-empty with valid roles (`system`/`user`/`assistant`) → else reject (`corpus_case_messages_invalid`).
- `judge.criteria[].description` is **required** (the judge needs it).

Loader failures carry a closed `CorpusLoadReason` enum (drift-pinned, ownership-mapped). The **same Pydantic `Corpus` model** is the single source of truth for corpus validity: `load_corpus(path) -> Corpus` is the file/directory wrapper used by the CLI `--dry-run`, and the portal validates its inline (already-parsed) body against the **same model** — so a corpus that is valid for the CLI is valid for the portal and vice versa, with no second validator to drift.

---

## §4 Portal API + execution

**`POST /api/v1/eval/bulk-run`** — RBAC scope `eval.bulk.run`.
- Body: corpus document(s) (inline, already-parsed JSON-equivalent of the YAML) + `target: "gateway"` + `persist_raw_output: bool = false`.
- **Synchronous** execution. Refuses over the cap with `413` + closed reason `eval_corpus_too_large`; empty corpus → `400 eval_corpus_empty`; malformed corpus → `400` + the `CorpusLoadReason`.
- **Fail-closed DI** (mirrors the judge route at `portal/api/evaluation/routes.py`): resolve `app.state.llm_gateway` and the decision-history store **before** any execution → `503 {"reason": "llm_gateway_unavailable" | "decision_history_unavailable"}`.
- **Endpoint status codes are bounded to request/infrastructure problems — never to a model's per-case behavior.** The only statuses the handler emits are: `403` (RBAC), `503` (gateway/store DI unavailable), `413 eval_corpus_too_large` (over cap), `400 eval_corpus_empty` / `400` + `CorpusLoadReason` (malformed corpus), and `200` for any run that executed — **including a run where some or all cases errored**. The bulk-run handler does **not** reuse the judge route's `429`/`502` gateway-exception mapping: a per-case gateway failure (concurrency, guardrail, cloud-policy, transport) is captured as an `errored` case result inside the runner (§2), so it surfaces in the `200` body's per-case detail, not as an endpoint 4xx/5xx. The run is governance evidence even when cases error.
- Returns the persisted `EvalRunResult` (DTO), including `run_id`, `chain_request_id`, and aggregate counts. `--json` on the CLI surfaces this verbatim.

**`GET /api/v1/eval/runs/{run_id}`** — RBAC scope `eval.runs.read`.
- **Tenant-scoped**: the row is loaded `WHERE run_id = :id AND tenant_id = :actor_tenant`. Cross-tenant **and** unknown both collapse to `404` with identical body (`feedback_wire_body_collapse_cross_tenant_invisibility`); internal log records `tenant_id_mismatch` vs `not_found` for ops/SIEM.
- Returns the run + per-case results (raw output only if it was persisted).

**Module conventions:** `bulk_routes.py` **omits** `from __future__ import annotations` (closure-local `Depends`, per `feedback_pep563_breaks_closure_local_depends`); pinned by an AST no-future-import self-test mirroring the existing route modules. Mounted under `/api/v1/eval` in `portal/api/app.py` alongside the judge router.

**Settings** (`core/config.py`, `gt=0` Pydantic constraints):
- `eval_bulk_max_cases: int = 50` — the synchronous-endpoint corpus cap (chosen low because a synchronous request with judge scoring can otherwise run long).
- `eval_bulk_max_raw_output_chars: int = 50_000` — truncation bound for persisted raw output (matches the judge's candidate bound).
- `eval_bulk_target_tier: str` — the LLM tier the `GatewayTarget` (the model **under test**) dispatches against; operator-configured, caller cannot override. Distinct from the existing `eval_judge_tier` (the evaluator). Default mirrors `eval_judge_tier`'s `Literal["tier1","tier2"]` shape with default `"tier1"`.

---

## §5 Storage + chain + ISO

**Atomicity:** `EvalRunStore.persist_run(...)` drives a single `DecisionHistoryStore.append_with_precondition(*, record_builder, precondition)` call. The `precondition(conn, sequence, prev_hash)` closure INSERTs the `eval_runs` row and all `eval_case_results` rows **on the same connection/transaction** that writes the chain row, then returns the aggregate snapshot; `record_builder` mints the `DecisionRecord`. This mirrors `packs/storage.py` and `core/scheduler/storage.py` — relational rows + chain row + chain-head update commit atomically; any failure rolls back all of them (fail-closed, no orphan rows). `EvalRunStore` is constructed from the same engine the `DecisionHistoryStore` uses (same Postgres), wrapping that store.

**Chain back-link (no `record_id` inside the closure).** `append_with_precondition` mints the chain row's `record_id` **after** the precondition closure returns, so the closure cannot write a `chain_record_id` onto `eval_runs` and still be atomic (the exact class fixed in ADR-023). Instead, the caller mints a **bounded `request_id`** up front (prefix + `uuid4().hex`, `≤ 64` chars to fit the `decision_history.request_id` `String(64)` column — mirrors the operator-route `_mint_request_id` pattern), stores it on `eval_runs.chain_request_id` **inside** the closure, and passes the **same** `request_id` to the `DecisionRecord` built by `record_builder`. The chain row and the `eval_runs` row are therefore back-linked by `request_id`. A direct `record_id` foreign key is **deferred** — it would require a new `append` primitive that surfaces the minted `record_id` to the precondition, which is out of scope for Sprint 12.

**`eval_runs`** (index `(tenant_id, created_at)`):
`run_id` (uuid PK), `tenant_id`, `corpus_id`, `corpus_digest` (sha256 of canonical corpus), `target_kind`, `tier`, `actor_subject`, `status`, `total`, `passed`, `failed`, `errored`, `latency_p50_ms`, `latency_p95_ms`, `chain_request_id` (the caller-minted bounded `request_id` shared with the `eval.bulk_run` chain row — back-link by `request_id`, written inside the precondition closure; see the Chain back-link note above), `created_at`.

**`eval_case_results`** (index `(run_id)`; FK `run_id → eval_runs.run_id`):
`result_id` (uuid PK), `run_id`, `case_id`, `passed`, `outcome`, `scorer_results` (JSONB — the per-scorer `ScorerResult` tuple incl. `CriterionDetail` critiques), `latency_ms`, `model`, `input_digest`, `output_digest`, `candidate_output_text` (nullable text — populated only when `persist_raw_output` is true, truncated to `eval_bulk_max_raw_output_chars`), `raw_output_persisted` (bool), `output_truncated` (bool).

**Raw-output posture (locked Option C):** digests + scorer detail + metadata are **always** stored; `candidate_output_text` is stored **only** when the request sets `persist_raw_output: true`, bounded/truncated, within the tenant boundary. `raw_output_persisted` and `output_truncated` are recorded per case so an examiner knows whether operational text existed and whether it was clipped. Default `persist_raw_output = false` (eval corpora may contain customer-like cases; gateway outputs may echo sensitive content).

**Chain row:** exactly **one aggregate `eval.bulk_run` decision_history row per run** (the run is the governance unit — not per-case rows). **Value-free** payload: `run_id`, `corpus_id`, `corpus_digest`, `target_kind`, `tier`, `total/passed/failed/errored`, and a per-case list `[{case_id, passed, output_digest}]` (digests only, no raw text). ISO controls: **`ISO42001.A.7.6`** (performance/quality evaluation) + **`ISO42001.A.9.2`** (validation/verification). Recorded in `compliance/iso42001/controls.py` by appending `eval.bulk_run` to the A.7.6 + A.9.2 `intended_hooks` (stop-rule edit — halt-before-commit).

---

## §6 CLI

`agentos eval bulk` (Typer, registered in `cli/__init__.py`, logic in `cli/eval.py`):
- `--corpus path/` (required) — directory of corpus YAML docs.
- `--url` + `--token` — POST the loaded corpus to `POST /api/v1/eval/bulk-run`; render the returned `EvalRunResult`.
- `--dry-run` — load + strict-validate the corpus and print the plan (case count, per-case scorer summary); **no** model call, **no** portal call. Genuinely local.
- `--json` — emit the result/plan as JSON (one object), matching the existing CLI `--json` convention.
- Exit codes: `0` = success (run completed or dry-run valid), `1` = corpus invalid / run reported failures over a `--fail-under` style threshold (Sprint 12: `1` on any corpus-load refusal; run-result pass/fail thresholds for gating are a Sprint-13 promotion-gate concern, not a CLI exit gate here), `2` = invocation error (bad args, portal unreachable).
- **No runtime/gateway construction in the CLI** (preserves the CLI-never-builds-the-runtime precedent; avoids a governed-gateway-with-audit-off footgun).

---

## §7 Cross-cutting

**Closed enums** (drift-pinned via `typing.get_args`, ownership-mapped, count-guarded):
- `CorpusLoadReason` (loader): `corpus_schema_version_unsupported`, `corpus_no_documents`, `corpus_duplicate_case_id`, `corpus_case_no_scorer`, `corpus_case_kind_unsupported`, `corpus_case_messages_invalid`, `corpus_unparseable_yaml`, `corpus_unknown_key`.
- `EvalBulkRefusalReason` (portal request): `eval_corpus_too_large`, `eval_corpus_empty`.
- `CandidateOutputOutcome` / `CaseOutcome`: `succeeded` | `errored`.

**RBAC** (`portal/rbac/scopes.py`, stop-rule — halt-before-commit): extend `EvalRBACScope` Literal and `EVAL_SCOPES` with `eval.bulk.run` (execute) and `eval.runs.read` (read). **Neither is Human-only** — CI/service actors must run evals. `eval.judge.run` is untouched.

**Critical-controls coverage gate** (`tools/check_critical_coverage.py` `_CRITICAL_FILES`): promote **four** modules — `evaluation/corpus.py` (corpus contract), `evaluation/scorers.py` (evaluator/pass-fail logic), `evaluation/runner.py` (run orchestration), `evaluation/storage.py` (evidence storage + tenant boundary + chain emission). Count **117 → 121**. Verified against **fresh `--cov-branch coverage.json` in the promotion commit** per `feedback_verify_promotion_meets_floor_at_promotion_time` (95% line / 90% branch floor); `tests/unit/tools/test_check_critical_coverage.py` `_EXPECTED_ENTRY_COUNT` bumped + a `_SPRINT_12_GATE_MODULES` set-pin. `target.py` / `types.py` stay off-gate (pure types / thin gateway mapping covered by tests + the on-gate `runner`/`judge`).

**ADR:** an **ADR-010 amendment** records: the `EvaluationTarget` / `CaseScorer` seams; `GatewayTarget` as the only Wave-1 target (OS-only — no Layer-C agent packs in this repo); the `persist_raw_output` opt-in posture + the `raw_output_persisted`/`output_truncated` evidence flags; the value-free aggregate `eval.bulk_run` chain row + A.7.6/A.9.2; the deferred Sprint-13 plug-ins. No new ADR.

**Reference corpus:** `evaluation/corpora/example/generic-completion-smoke.yaml` — fully neutral/generic format-demonstration corpus (assertions + judge), explicitly **not** a persona/bank-specific agent corpus, to respect the OS/pack boundary and avoid blurring into the later `cognic-agent-policyqa` pack.

**Deferred to Sprint 13 (recorded, not built):** `McpToolTarget` / `A2AAgentTarget` / replay targets; citation / refusal / replay-diff / promotion-gate scorers; `replay` / `tool_invocation` / `a2a_agent` case kinds; multi-turn interactive scenarios; weighted aggregate scoring; background async large-corpus queue. **OpenShift/AKS** noted only as **Sprint 14** deployment constraints — no deployment code here.

**Testing (TDD throughout):**
- Storage tests against the **Alembic-migrated DB** (not `create_all`), with cross-tenant / wrong-tenant negatives and atomic-rollback-on-failure pins, per `feedback_storage_test_migrated_db_not_create_all`.
- Loader tests: every `CorpusLoadReason` fail-closed path (unknown key, bad version, duplicate id, no-scorer case, bad kind, empty dir).
- Runner tests: fake target + fake scorers; pass = all-scorers-pass; per-case `errored` isolation; P50/P95 computation.
- Scorer tests: each assertion clause (pass + fail critique); JudgeScorer maps to `run_judge` and respects `verdict=="pass"`; `JudgeUnparseable` → scorer fail with parse_reason critique.
- Route tests: fail-closed DI (503), RBAC denial (403), cap (413), tenant-scoped read (cross-tenant 404 wire-collapse), value-free chain row shape, `persist_raw_output` on/off behavior, and **a per-case gateway failure returns `200` with that case `errored`** (never an endpoint 4xx/5xx) — pins the patch-2 contract. A storage test pins `eval_runs.chain_request_id == DecisionRecord.request_id` for the same run (patch-1 back-link).
- CLI tests: `--dry-run` validates + prints without network; thin-client posts + renders; exit codes.

---

## §8 Harness-Design Alignment

This design follows Anthropic's guidance on building harnesses for long-running agentic apps ([Anthropic, "Building harnesses for long-running agentic applications," Mar 24 2026](https://www.anthropic.com/engineering/harness-design-long-running-apps)):

- **Generator/evaluator separation.** `EvaluationTarget` produces candidate output; `CaseScorer` judges it. Self-evaluation is weak; a separate evaluator gives a stronger feedback loop. The runner is target- *and* scorer-agnostic precisely so the two roles never collapse into one.
- **Make quality gradable.** Deterministic assertions + rubric criteria make pass/fail explicit and inspectable rather than subjective. `ScorerResult` carries **criterion-level detail and a critique** for every clause/criterion, so a failure is actionable — matching the article's "make quality gradable" framing and its QA-feedback spirit.
- **Durable, structured artifacts.** The corpus YAML, `EvalRunResult`, relational `eval_runs`/`eval_case_results` rows, and the value-free `eval.bulk_run` chain row are durable handoff artifacts that survive the run and feed downstream consumers (Sprint-13 replay/promotion gate, examiner evidence export).
- **Keep the harness simple until complexity is load-bearing.** Portal-only execution, synchronous with a low cap, no CLI-side gateway construction, no async queue — each omission is a deliberate strip of non-load-bearing complexity. The pieces deferred to Sprint 13 are recorded but not built.
- **Predeclared done-contract per unit.** Each case's `assertions`/`judge` criteria are the predeclared "done contract" for that case — the runner checks the candidate output against a contract written before execution, not after.

---

## Open items resolved during brainstorm (for traceability)

| Decision | Locked choice |
|---|---|
| What the runner invokes | Pluggable `EvaluationTarget` + built-in `GatewayTarget` |
| Scoring model | Both scorers, deterministic-first, `CaseScorer` Protocol |
| Corpus shape | Single-shot message-list cases; directory of strict versioned YAML; `case_kind: completion` reserved discriminator |
| CLI execution | Portal-only execution; CLI = thin client + local `--dry-run`; no local gateway |
| Execution model | Synchronous + `413 eval_corpus_too_large` cap |
| Raw-output storage | Opt-in per run (`persist_raw_output`, default false) + `raw_output_persisted`/`output_truncated` flags |
| Chain row | One aggregate value-free `eval.bulk_run` row per run; A.7.6 + A.9.2 |
| Chain back-link | `eval_runs.chain_request_id` = caller-minted bounded `request_id` shared with the `DecisionRecord` (no `chain_record_id` — `record_id` is minted after the precondition closure; direct FK deferred) |
| Gateway exception semantics | Per-case failures → `errored` case results (run continues, `200`); endpoint statuses limited to `403`/`503`/`413`/`400`; no judge-route `429`/`502` reuse in bulk-run |
| Cap default | `eval_bulk_max_cases = 50`; `eval_bulk_max_raw_output_chars = 50_000` |
| CC promotion | `corpus.py` + `scorers.py` + `runner.py` + `storage.py` (117 → 121) |
| ADR | ADR-010 amendment |
| Reference corpus | Fully neutral `generic-completion-smoke` |
