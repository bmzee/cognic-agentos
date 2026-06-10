# Sprint 13c — Adversarial Promotion Gate (design)

**Goal:** Wire the Sprint-13b adversarial evidence into the existing 5-gate pack-approval composer — a submit-time, reference-based producer that resolves a 13b adversarial eval-run, verifies it, computes baseline regression, and freezes a mapped snapshot into `payload["adversarial"]` so gate-3 of `compose_approval_gates` becomes live.

**Phase:** Phase 4. **Third and final** of three Sprint-13 sub-projects: 13a live replay (merged, PR #56) → 13b adversarial testing (merged, PR #57, main @ `3cd19b8`) → **13c promotion gate** (this).

**ADR:** ADR-011 (adversarial testing) × ADR-012 (bank-pack lifecycle §41 5-gate approval) × ADR-010 (eval harness — reuses 13a's `compute_replay_diff`). AgentOS-only; value-free chain.

---

## §0 Scope reconciliation (what is already built; what 13c is NOT)

The "promotion gate" the BUILD_PLAN §1101 imagines as a standalone `evaluation/promotion_gate.py` **does not exist and will not be built.** It was superseded by the **5-gate pack-approval composer** shipped in Sprint 7B.3 (`packs/approval_gates.py`), which already composes signature · evaluation · **adversarial** · OWASP · reviewer-ack at the `under_review → approved` transition (ADR-012 §41). That composer **is** the promotion gate.

Already built (13c reuses, does not rebuild):
- `packs/approval_gates.py` — `compose_approval_gates(...)`; gate-3 = adversarial, with `AdversarialGateInput(outcome, red_reason, pass_rate, high_severity_failures)` + `AdversarialRedReason` (3 values) + the `green`/`red`/`evidence_not_attached` outcomes.
- `portal/api/packs/review_routes.py:221` `_build_adversarial_gate_input` — reads `submit_row.payload["adversarial"]` as `{pass_rate, high_severity_failures}`, fail-closed.
- `adversarial_pass_rate_floor` Settings (tighten-only `ge`, default 0.99; Wave-1 deploy-safety).
- The override path `evaluate_override_decision` + the `pack.override.approval_gate` scope (ADR-012 §110; signature non-overridable, adversarial overridable).
- 13b `AdversarialVerdict` + the value-free `eval.adversarial_run` chain row (`evaluation/storage.append_adversarial_event`).
- 13a `compute_replay_diff` / `DriftKind` (`evaluation/replay.py`) — `regression` = baseline-passed → candidate-failed, with `errored` classified **separately**.

The gap 13c closes: **nothing populates `payload["adversarial"]`** (OWASP conformance is auto-run at submit → `payload["conformance"]`, but the adversarial equivalent was never wired — every approval today sees gate-3 = `evidence_not_attached`); **no baseline regression**; and a small `AdversarialVerdict` → `AdversarialGateInput` mapping.

Locked boundary calls (from the reconciliation):
- **BC-1 (reference, not auto-run):** there is no OS-only "pack as LLM target"; 13c references an existing 13b adversarial eval-run by id and verifies the linked `eval.adversarial_run` evidence before populating `payload["adversarial"]`. No auto-run-at-submit. "run id" = the queryable candidate eval-run id (the one `persist_run` created), NOT a new standalone promotion-gate run.
- **BC-2 (reuse the override scope):** `pack.override.approval_gate` already overrides the adversarial gate. `override.adversarial_gate` is superseded BUILD_PLAN shorthand — **no new RBAC scope.** Recorded in the ADR-011/ADR-012 reconciliation amendment.
- **BC-3 (model gate out of scope):** the ADR-013 model-promotion adversarial gate (`models/storage.adversarial_pass_rate`, live gate deferred) is a separate surface; it may reuse 13c's mechanism later but is **not** in 13c.

---

## §1 Submit-time evidence flow (reference-based producer)

The author's `submit_draft` request gains two optional fields; the producer runs OUTSIDE the storage transaction (mirroring the OWASP-conformance auto-run), and its mapped snapshot is threaded onto the submit chain row via a new `payload_adversarial` kwarg on `store.transition("submit", …)` (parallel to the existing `payload_conformance`).

```
POST /api/v1/packs/{id}/submit
  body: SubmitDraftRequest{ manifest, adversarial_run_id?: str, baseline_adversarial_run_id?: str }
     │
     ├─ (existing) manifest-digest precheck + run_owasp_conformance_for_chain_payload → payload_conformance
     │
     └─ if adversarial_run_id is None:
     │      payload_adversarial = None        # snapshot absent → gate-3 reports adversarial_evidence_not_attached
     │  else:
     │      payload_adversarial = await build_adversarial_evidence(
     │          store, tenant_id=actor.tenant_id,
     │          adversarial_run_id=…, baseline_adversarial_run_id=…)   # NEW CC producer (§3)
     │
     └─ store.transition("submit", …, payload_conformance=…, payload_adversarial=payload_adversarial)
```

**No new chain row.** The adversarial snapshot rides the existing `pack.lifecycle.submitted` payload; its `candidate_run_id` / `baseline_run_id` are the audit linkage back to the 13b eval-runs. The approve transition is unchanged — `compose_approval_gates` stays read-only over the submit row.

`adversarial_run_id` is **optional** (locked spec pin): omitted → `payload["adversarial"]` absent → gate-3 reports the existing `adversarial_evidence_not_attached` (non-green, overrideable) — preserving current submit semantics while still blocking green approval. Supplied → verify / map / freeze.

---

## §2 The `payload["adversarial"]` snapshot + verification + submit refusals

### Snapshot shape (frozen on the submit row)

Extends the current `{pass_rate, high_severity_failures}`:

```json
{
  "pass_rate": 0.97,
  "high_severity_failures": 0,
  "regressions": 0,
  "regression_evaluated": true,
  "candidate_run_id": "…",
  "baseline_run_id": "…"  // or null when no baseline supplied
}
```

Exact-key-set on the chain row (chain-payload-as-evidence-snapshot doctrine — an examiner verifies from the row alone). The 7B.3 reviewer evidence panels + gate-3 reader read this shape.

### Verification at submit (fail-closed BEFORE populating)

Route-level 4xx refusals (a NEW route-owned closed-enum, distinct from the gate's `AdversarialRedReason`):

| Condition | Status | Reason |
|---|---|---|
| `adversarial_run_id` references a missing / cross-tenant run | **404** | `adversarial_run_not_found` (cross-tenant collapses to not-found — invisibility doctrine) |
| referenced run exists but is not an adversarial run (no `eval.adversarial_run` row for it) | **400** | `adversarial_run_not_adversarial` |
| `baseline_adversarial_run_id` supplied but missing / cross-tenant | **404** | `adversarial_baseline_run_not_found` |
| baseline run exists but is not an adversarial run (no `eval.adversarial_run` row) | **400** | `adversarial_baseline_run_not_adversarial` (symmetric with the candidate check — same `corpus_digest` proves same corpus, NOT same `passed == refused` run semantics) |
| candidate / baseline `corpus_digest` mismatch | **400** | `adversarial_baseline_corpus_digest_mismatch` (13a `replay_corpus_digest_mismatch` precedent) |

Tenant scoping is enforced by `EvalRunStore.get_run` / the new `load_adversarial_verdict` (both `WHERE tenant_id = …`); `None` → the 404 refusals above.

---

## §3 Baseline regression (reuse `compute_replay_diff`) + the producer

`build_adversarial_evidence(store, *, tenant_id, adversarial_run_id, baseline_adversarial_run_id) -> dict` (new CC module `evaluation/adversarial/evidence.py`). It performs store reads and **raises a typed `AdversarialEvidenceError(reason)`** carrying the §2 closed-enum on any verification failure; `author_routes` catches it and maps `reason → (status, body)` (mirroring how the eval routes map `CorpusLoadError`). The green path returns the §2 snapshot dict.

0. **Verify the referenced run (order is load-bearing — distinguishes 404 from 400).** `verdict = store.load_adversarial_verdict(adversarial_run_id, tenant_id=…)` (NEW read seam — the `eval.adversarial_run` decision-history row whose `payload["candidate_run_id"]` == the referenced run id; tenant-scoped). If `verdict is None`, disambiguate: `store.get_run(adversarial_run_id, tenant_id=…)` is also `None` → `adversarial_run_not_found` (404, also the cross-tenant-invisible path since both reads are `WHERE tenant_id`); else the run exists but is a non-adversarial (bulk/replay) run → `adversarial_run_not_adversarial` (400).
1. **Aggregates from the verdict row.** `pass_rate = verdict["overall_pass_rate"]`; `high_severity_failures = count(per_case where severity == "high" and not passed)`. (Derived at the mapping site — no change to the frozen 13b verdict/row.)
2. **Regression via the 13a differ.** If `baseline_adversarial_run_id` is supplied, verify the baseline in this order (existence → adversarial-ness → corpus pairing), each a §2 refusal:
   - `cand = store.get_run(adversarial_run_id, tenant_id=…)` (non-None — step 0 already proved the candidate resolves); `base = store.get_run(baseline_adversarial_run_id, tenant_id=…)`. `base is None` → `adversarial_baseline_run_not_found` (404; cross-tenant-invisible).
   - `store.load_adversarial_verdict(baseline_adversarial_run_id, tenant_id=…) is None` (baseline eval-run exists but carries no `eval.adversarial_run` verdict row) → `adversarial_baseline_run_not_adversarial` (400). **Required because same `corpus_digest` proves same corpus, NOT same run semantics:** a non-13b eval-run (e.g. a bulk run over the same YAML) could share the digest while its `passed` does not mean "refused", which would corrupt the "new attacks succeeded" regression claim. Symmetric with the candidate's step-0 `adversarial_run_not_adversarial`.
   - `cand["run"]["corpus_digest"] != base["run"]["corpus_digest"]` → the §2 digest-mismatch refusal.
   - Reconstruct the candidate `EvalRunResult` from `cand` (a NEW `_eval_run_from_get_run(mapping)` reconstruction helper — the candidate cases come back as `_eval_case_results` mappings; rebuild `CaseResult`s carrying `case_id` (= `expanded_case_id`), `passed`, `outcome`, `output_digest`, `model`).
   - `diff = compute_replay_diff(baseline_run_id=…, candidate=cand_result, baseline_cases=base["cases"], baseline_tier=base["run"]["tier"])`.
   - `regressions = diff.regressions` (keyed by `case_id` = `expanded_case_id`; **errored cases excluded** by `_classify`); `regression_evaluated = True`.
   - Else: `regressions = 0`, `regression_evaluated = False` (absent-baseline skip — first submissions get a legitimate green path on pass-rate + high-severity alone).
3. Return the §2 snapshot dict.

**Why reuse the differ, not the verdict per-case:** `compute_replay_diff` classifies `errored` separately from `regression`, so a candidate case that errored (flaky gateway) against a baseline that passed is **not** miscounted as a new successful attack. The verdict's `per_case` carries no `outcome`, so a verdict-only regression count would false-positive on errored cases. Both candidate and baseline are already first-class eval-runs (13b `persist_run`), so `get_run` provides real `CaseResult` data; same `corpus_digest` guarantees shared `expanded_case_id` keys.

---

## §4 Gate-3 mapping + the composer extension

### `AdversarialGateInput` (extended)

```python
@dataclass(frozen=True)
class AdversarialGateInput:
    outcome: ApprovalGateOutcome
    red_reason: AdversarialRedReason | None
    pass_rate: float | None
    high_severity_failures: int
    regressions: int                 # NEW
    regression_evaluated: bool        # NEW
    candidate_run_id: str | None      # NEW — threaded to the gate evidence_pointer
```

- New `AdversarialRedReason` value: **`adversarial_baseline_regression`** (4 values total).
- The composer's `adversarial_result.evidence_pointer` (currently hardcoded `None` at `approval_gates.py:463`) reads `adversarial_input.candidate_run_id` — so the composition/override snapshot points directly at the eval-run, mirroring gate-1's `signature_digest` pointer (locked spec pin). The submit `payload["adversarial"]` remains the full evidence snapshot.

### `_build_adversarial_gate_input` reader (regression branch + locked precedence)

Fail-closed validation extends: `regressions` must be a non-negative `int` (not `bool`), `regression_evaluated` a `bool` — else `evidence_not_attached`. Then the **locked red-reason precedence** (each condition independently forces `red`; precedence only picks the reported reason):

1. `high_severity_failures > 0` → `adversarial_high_severity_failure`
2. `regression_evaluated and regressions > 0` → `adversarial_baseline_regression`
3. `pass_rate < floor` → `adversarial_corpus_pass_rate_below_threshold`
4. else → `green`

`candidate_run_id` is read from the snapshot and threaded into the `AdversarialGateInput` regardless of outcome (so even a red/green gate carries the evidence pointer).

---

## §5 Module surface + CC + RBAC + ADR

- **New CC module:** `evaluation/adversarial/evidence.py` — `build_adversarial_evidence` + the `_eval_run_from_get_run` reconstruction helper. **CC gate 124 → 125** (verify-at-promotion against fresh `--cov-branch`).
- **CC extended (already on-gate):**
  - `evaluation/storage.py` — new `load_adversarial_verdict(run_id, *, tenant_id)` read of the `eval.adversarial_run` row.
  - `packs/storage.py` — new optional keyword-only `payload_adversarial` kwarg on `transition()` (mirrors `payload_conformance`; additive — omitted adds no key).
  - `packs/approval_gates.py` — `AdversarialGateInput` 3 new fields + 4th `AdversarialRedReason` + the `evidence_pointer` line.
- **Off-gate:** `portal/api/packs/author_routes.py` (`SubmitDraftRequest` two optional fields + the submit-handler producer call + the 5 route refusals), `portal/api/packs/review_routes.py` (`_build_adversarial_gate_input` regression branch + validation).
- **RBAC:** none new (BC-2).
- **No Alembic migration, no new Settings** (reuses `adversarial_pass_rate_floor`; the snapshot is additive payload).
- **ADR work:** an ADR-011 + ADR-012 reconciliation amendment recording: the 5-gate composer IS the promotion gate (no `evaluation/promotion_gate.py`); `override.adversarial_gate` superseded by `pack.override.approval_gate`; model-promotion gate out of scope; the new `payload["adversarial"]` snapshot shape + the regression term.

---

## §6 Testing + locked pins

- **Regression-reuse correctness (the (B) point):** `build_adversarial_evidence` regression count == `compute_replay_diff(...).regressions` over the same two runs; an **errored** candidate case vs a **passed** baseline case is NOT counted as a regression.
- **Absent baseline:** `adversarial_run_id` supplied, `baseline_adversarial_run_id` omitted → snapshot `regression_evaluated: false`, `regressions: 0`; gate-3 green when pass-rate ≥ floor + high-severity == 0.
- **Optional run id:** `adversarial_run_id` omitted → `payload["adversarial"]` absent → gate-3 `adversarial_evidence_not_attached` (non-green, overrideable).
- **Digest mismatch:** baseline with a different `corpus_digest` → 400 `adversarial_baseline_corpus_digest_mismatch` (not a silent skip).
- **Submit verification matrix:** each of the 5 §2 refusals pinned (missing/cross-tenant candidate; non-adversarial candidate; missing/cross-tenant baseline; **non-adversarial baseline** — a baseline eval-run sharing the `corpus_digest` but lacking an `eval.adversarial_run` verdict row → 400 `adversarial_baseline_run_not_adversarial`; digest mismatch).
- **Precedence:** high-severity beats regression beats pass-rate — each in isolation AND combined (e.g. high-severity + regression both present → `adversarial_high_severity_failure`).
- **evidence_pointer:** gate-3 `ApprovalGateResult.evidence_pointer == candidate_run_id`.
- **Snapshot exact-key-set** on the submit row; gate-3 reader consumes it unchanged from the existing path.
- **Composition end-to-end:** a submit with a clean adversarial run + no regressions → gate-3 green; a submit referencing a run with a high-severity failure → gate-3 red, approval blocked, overrideable via `pack.override.approval_gate`.
- **Threshold:** values stay Settings-driven (Human-only) — tests use the configured floor, never a baked literal beyond the kernel default.
- **CC verify-at-promotion:** fresh full-suite `--cov-branch coverage.json`; all 125 entries ≥ floor; `evidence.py` at/above floor in the same commit.

---

## §7 Deferred / out of scope

- **`evaluation/promotion_gate.py`** — superseded by the 5-gate composer; not built unless a real need surfaces.
- **Auto-run-at-submit** of a pack's adversarial corpus — no OS-only pack-as-LLM target (BC-1).
- **Model-promotion adversarial live gate** (ADR-013) — separate surface (BC-3).
- **A gate-specific `override.adversarial_gate` scope** — superseded by `pack.override.approval_gate` (BC-2).
- **Multi-baseline / historical-trend regression** — 13c diffs against a single supplied baseline run; trend analysis is a later concern.
- **Auto-resolving the baseline** from the prior approved pack version — 13c takes an explicit `baseline_adversarial_run_id`; implicit baseline resolution is deferred.

---

## §8 Locked decisions (Q-table)

| # | Decision | Lock |
|---|---|---|
| Q1 | Evidence attach point | **A** — submit-time population (author supplies the run id; handler resolves/verifies/freezes into `payload["adversarial"]`); composer read-only over the submit row |
| Q2 | Absent-baseline gate semantics | **A** — skip the regression term, record `regression_evaluated: false`; supplied baseline requires `corpus_digest` match (submit refusal on mismatch); zero-tolerance regression → `adversarial_baseline_regression` |
| Q3 | Regression computation | **B** — reuse `compute_replay_diff` over the two persisted eval-runs (errored-correct); verdict row for pass-rate + high-severity |
| BC-1 | Reference vs auto-run | reference existing 13b eval-run; no auto-run-at-submit |
| BC-2 | Override scope | reuse `pack.override.approval_gate`; `override.adversarial_gate` superseded |
| BC-3 | Model gate | out of scope (ADR-013 separate surface) |
| Pin-1 | `adversarial_run_id` optionality | optional; omitted → absent payload → `adversarial_evidence_not_attached` |
| Pin-2 | `evidence_pointer` | thread `candidate_run_id` through `AdversarialGateInput` → gate-3 `evidence_pointer` |
| Pin-3 | Red-reason precedence | high-severity → regression → pass-rate-floor |
| Pin-4 | Module surface | new `evaluation/adversarial/evidence.py` CC; gate 124→125; no `evaluation/promotion_gate.py` |
