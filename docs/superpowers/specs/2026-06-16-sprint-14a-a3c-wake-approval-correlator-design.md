# Sprint 14A-A3c — Wake Approval Correlator — Design

**Status:** design (brainstorm-locked) · **Date:** 2026-06-16 · **ADRs:** ADR-022 (runtime scheduler / managed run) + ADR-004 (sandbox resumable session) + ADR-014 (runtime tool approval) · **Arc:** checkpoint→wake / run-persistence, slice **3/3** (A3a foundation → A3b resolver/resume → **A3c wake approval correlator**).

A3c crosses the fence A3b deliberately held: it threads the 13.5c1 sandbox approval engine into the **wake-path** `admit_policy` so a resume that re-admits a high-risk session pends for a human grant — the wake mirror of the 14A-A2 cold-create approval seam. A3c **completes the checkpoint→wake arc**.

---

## 1. Scope

**In:** thread `approval_engine` + a request-time `approval_request_id` into the wake-path `admit_policy` (both backends); let the approval-family refusals escape the wake refusal-collapse wrapper; add a `pending_approval` arm + a no-re-mint guard to `executor.resume()`; expand the run-transition matrix with the wake-pending pairs; carry `approval_request_id` on `RunResumeRequest`; flip the `test_approval_threading.py` fence. The seam is **unit-proven** (stub/forced pending) end-to-end: `suspended → (wake-pending) → pending_approval → (operator grant) → (re-resume) → woken → completed`.

**Out (deferred, honestly recorded):**
- **No `CheckpointMetadata` wire-format change** (F1-A). The grant binding inputs (`policy`, `pack_context`) are already persisted + immutable; `approval_request_id` is a request-time correlator; `approval_verified` is transient inside wake admission. Durable approval evidence lives on the run record + `run.*`/`run.lifecycle.*`, not the checkpoint.
- **No manifest-driven high-risk run shape** (F4-A). The executor still hardcodes `risk_tier="read_only"` (auto-tier, never pends), so the wake-approval seam is **WIRED + unit-proven but not live-exercised in production** for the read_only path — exactly the 14A-A2 cold-create posture. The real high-risk run shape (manifest risk tiers) is a later slice that live-exercises this seam.
- The leaked-orphaned-backend-resource reconciliation (A3b forward item) and quota-on-resume stay deferred — unchanged by A3c.

---

## 2. Locked forks (brainstorm)

- **F1 — A: no `CheckpointMetadata` extension.** `approval_request_id` rides `RunResumeRequest`; `approval_verified` is transient inside wake admission; the grant re-verifies against the already-persisted immutable `metadata.policy`/`metadata.pack_context`.
- **F2 — A: durable run-record `pending_approval`.** Expand the matrix over the existing 9-value vocab (suspended→pending_approval + pending_approval→{woken,refused,failed}). The run record reflects wake-pending rather than diverging from the HTTP terminal state.
  - **F2 pin (no silent re-mint):** first resume from `suspended` may create a `sandbox_approval_pending` (admission Arm A → mint). Re-resume from `pending_approval` **requires** the supplied `approval_request_id`, threads it to wake (admission Arm B → verify), and either verifies (→woken), remains pending with the **same** id (no transition), or terminally refuses/fails. A `pending_approval` run never re-enters Arm A.
- **F3 — A: exempt the approval family from the wake refusal-collapse wrapper.** The 5 `sandbox_approval_*` reasons (+ the `approval_request_id` attr) pass through un-rewrapped; only non-approval revalidation refusals collapse to `sandbox_wake_policy_revalidation_failed`.
- **F4 — A: high-risk run shape is a live-proof follow-up**, not an A3c dependency.

---

## 3. Recon-grounded starting point (what already exists)

All line numbers verified against HEAD `14c9f53` at design time (treat as anchors; the plan re-grounds before editing).

- **Backend approval plumbing already wired.** Both backends store `self._approval_engine` (`docker_sibling.py:972`, `kubernetes_pod.py:994`; `__init__` param at `:958`/`:979`); `harness/sandbox.py` already threads `approval_engine=runtime.approval_engine` into `get_backend`. **No `__init__` change needed** — `self._approval_engine` is reachable inside `wake()` today; it is simply not passed.
- **The admission consult is backend-agnostic + complete.** `sandbox/admission.py::admit_policy(...) -> None`; `_consult_approval_engine` (`admission.py:337-450`) already implements Arm A (mint→`sandbox_approval_pending`) / Arm B (`verify_grant_for_action` → granted / pending / denied / expired / not-found / binding-mismatch). `approval_verified` is threaded into the Step-9 Rego input (`admission.py:857`) and discarded — **no caller-visible attestation object**. **`admission.py` is unchanged by A3c** (consumed, not edited).
- **The grant binding is free at wake.** `args_digest = sha256(canonical_bytes(_policy_binding_projection(policy) + pack_context fields))` + `tool_identity = sandbox:sha256({pack_id, pack_artifact_digest})` (`admission.py:277-370`). `CheckpointMetadata.policy`/`.pack_context` (`checkpoint_store.py:423-424`) are exactly those inputs and are immutable on the frozen checkpoint, so first-wake (Arm A) and re-resume (Arm B) compute **byte-identical** digests — the grant binds to the resumed session's policy/pack identity with zero new persistence.
- **The wake admit_policy is the deliberately-untouched seam.** Both backends are byte-identical here: `wake(self, session_id, *, actor, tenant_id) -> SandboxSession` (`docker_sibling.py:2382`, `kubernetes_pod.py:2250`); the `admit_policy(...)` call (`docker_sibling.py:2559-2568`, `kubernetes_pod.py:2429-2438`) passes 8 kwargs (`metadata.policy`, `tenant_id`, `actor`, `pack_context=metadata.pack_context`, `catalog`, `credential_adapter`, `rego_engine`, `settings`) and **NO `approval_engine`/`approval_request_id`**. The Q3 wake-time revalidation comes from feeding the persisted policy/pack_context into the LIVE backend collaborators.
- **The refusal-collapse wrapper (the F3 trap).** The wake `admit_policy` is wrapped (`docker_sibling.py:2569-2573`, `kubernetes_pod.py:2439-2443`): `except SandboxLifecycleRefused as original: raise SandboxLifecycleRefused("sandbox_wake_policy_revalidation_failed", detail=f"original={original.reason}: {original.detail}") from original`. This blanket catch would swallow `sandbox_approval_pending` (+ the `approval_request_id` attr).
- **The executor + route + DTO already carry the pending machinery.** `RunResult` has `terminal_state="pending_approval"` + `approval_request_id` (executor.py); the resume route already returns `_run_response_from_result` + `_STATUS_BY_TERMINAL` with `pending_approval → 202`; `RunResponse` already carries `approval_request_id`. The cold-create executor branch (`executor.py:439-476`) is the template: `exc.reason == sandbox_approval_pending` → cancel + transition → pending RunResult + 202.
- **Storage + decision-types already exist.** `runs` table has the `approval_request_id` column (A3a); `RunRecordStore.transition(...)` already accepts the `approval_request_id` kwarg; `_STATE_TO_DECISION_TYPE` already maps `pending_approval` + `woken` (A3b). **`storage.py` is unchanged by A3c** — only the matrix (`_types.py`) gains the new legal pairs.

---

## 4. Component design

### 4.1 `sandbox/protocol.py` — `wake()` signature (CC / wire-protocol stop-rule)
Extend the `SandboxBackend.wake` Protocol (`:730`) with a trailing `approval_request_id: uuid.UUID | None = None`, mirroring `create()` (`:651-660`). This is a wire-protocol-contract change to the backend Protocol — every backend conforms.

### 4.2 `sandbox/backends/{docker_sibling,kubernetes_pod}.py` — wake admit_policy threading + wrapper exemption (CC / sandbox isolation stop-rule; byte-identical lockstep)
1. Add `approval_request_id: uuid.UUID | None = None` to both `wake()` signatures.
2. In the wake `admit_policy(...)` call, append `approval_engine=self._approval_engine` + `approval_request_id=approval_request_id` — mirroring the cold-create call (`docker_sibling.py:1130-1131`, `kubernetes_pod.py:1160-1161`). Do **not** thread `requires_credentials` (vault-bearing wakes are already caught by the engine-absent precondition; out of approval scope).
3. **F3 wrapper exemption:** the `except SandboxLifecycleRefused` re-wrap must NOT collapse the approval family. The exemption set is the closed `sandbox_approval_*` group: `sandbox_approval_pending`, `sandbox_approval_denied`, `sandbox_approval_expired`, `sandbox_approval_request_not_found`, `sandbox_approval_binding_mismatch`. For an exempt reason, re-raise the original `SandboxLifecycleRefused` **preserving `reason` + `detail` + `approval_request_id`**; for any other reason, keep the existing collapse to `sandbox_wake_policy_revalidation_failed`. The exemption set is derived from a single shared constant (no per-backend drift) — pinned by the cross-backend lockstep test.

### 4.3 `core/run/_types.py` — transition matrix expansion (off-gate; vocab fixed at 9)
Add a `_A3C_VALID_TRANSITIONS` delta unioned into `_VALID_TRANSITIONS` (the A3a/A3b expand-the-matrix-never-the-vocab doctrine):
- `("suspended", "pending_approval")` — first resume hits wake-pending.
- `("pending_approval", "woken")` — granted re-resume, wake succeeds.
- `("pending_approval", "refused")` — denied/expired/binding-mismatch grant, or a non-approval wake-revalidation refusal on re-resume.
- `("pending_approval", "failed")` — wake/exec infra-fail on re-resume.

`woken→completed`/`woken→failed` already exist (A3b). **No `pending_approval→pending_approval` self-loop** — a still-pending re-resume is a no-op (no transition). Doctrine pin updated: these were reserved-and-refusing before A3c; they're legal now.

### 4.4 `core/run/executor.py` — `resume()` pending arm + no-re-mint guard (CC)
`resume(*, run_id, actor, argv, approval_request_id: uuid.UUID | None = None)` gains the new param (threaded to `backend.wake(..., approval_request_id=approval_request_id)`).

**Resolve-state guard (widened):** `record.state` must be in `{suspended, pending_approval}` — else `RunNotResumable(record.state)` (unchanged 409 `run_not_suspended` for `completed`/`failed`/`refused`/etc.).

**No-re-mint guard (the F2 pin):** when `record.state == "pending_approval"`:
- the request **must** supply `approval_request_id` — absent → a new typed refusal `RunResumePendingApprovalRequired` → route 409 `run_resume_approval_id_required` (no `wake()` call, so admission Arm A is never reached → no re-mint).
- the supplied `approval_request_id` **must** equal the run row's stored `approval_request_id` (set on the `suspended→pending_approval` transition) — mismatch → a new typed refusal `RunResumeApprovalMismatch` → route 409 `run_resume_approval_id_mismatch` (defends against threading a valid-but-foreign grant to this run).
- on match, thread it to `wake()` → admission Arm B (verify). (When `record.state == "suspended"` and the request omits `approval_request_id`, `wake()` runs Arm A — the first-pending path.)

**Wake outcome handling** (the wake `try/except SandboxLifecycleRefused`, post-F3 exemption):
- `exc.reason == "sandbox_approval_pending"` → **pending arm:**
  - from `suspended`: `transition(suspended→pending_approval, approval_request_id=exc.approval_request_id)`; emit `run.pending_approval`; return `RunResult(terminal_state="pending_approval", approval_request_id=exc.approval_request_id)`.
  - from `pending_approval` (still pending, e.g. 4-eyes `awaiting_second`): **no transition** (run stays `pending_approval`); emit `run.pending_approval` (re-pending evidence, same id); return the pending `RunResult` with the same `approval_request_id`. resume() must NOT call `transition(pending_approval→pending_approval)` (not a legal pair).
  - resume makes **no scheduler calls** (the A3b invariant holds — `task_id` is always `None` on resume).
- `exc.reason ∈ {sandbox_approval_denied, sandbox_approval_expired, sandbox_approval_request_not_found, sandbox_approval_binding_mismatch}` → `transition(<from>→refused)` + `run.refused` (reason = `exc.reason`) → `RunResult(refused)` → 409.
- any other `SandboxLifecycleRefused` (incl. `sandbox_wake_policy_revalidation_failed`, `sandbox_wake_session_tombstoned`, `sandbox_wake_checkpoint_corrupt`) → existing `transition(<from>→refused)` → 409 (unchanged A3b behavior).
- generic `wake()`/`session.exec()` exception → `transition(<from>→failed)` → 502 (unchanged).

`<from>` is the loaded `record.state` (`suspended` on first resume, `pending_approval` on re-resume) — the transition's `from_state` is always the current row state, so the matrix pairs in §4.3 cover every arm.

The **claim-gated teardown (A3b) is unchanged** — `claimed_woken` still gates destroy; the pending/refused/failed arms never claim, so they never destroy (no tombstone of a still-resumable session). The pending arm is a return-before-claim path.

### 4.5 `portal/api/runs/dto.py` + `routes.py` — request correlator + status (off-gate)
- `RunResumeRequest` gains `approval_request_id: uuid.UUID | None = None` (mirror `RunSubmitRequest`).
- `resume_run` threads `approval_request_id=body.approval_request_id` into `executor.resume(...)`, and maps the two new typed refusals: `RunResumePendingApprovalRequired → 409 {"reason":"run_resume_approval_id_required"}`, `RunResumeApprovalMismatch → 409 {"reason":"run_resume_approval_id_mismatch"}` (alongside the existing `RunNotFound`/`RunNotResumable`/`RunResumeConflict`). The `pending_approval → 202` status entry already exists (A3b) — `_run_response_from_result` already carries `approval_request_id`, so the **retry contract is automatic**: a 202 hands back `approval_request_id`; the operator grants via the 13.5b1 portal approval API; the caller re-POSTs `POST /runs/{run_id}/resume` with that `approval_request_id`.

### 4.6 `tests/unit/sandbox/backends/test_approval_threading.py` — fence flip
The fence currently asserts the wake path is deliberately un-threaded. A3c flips it: assert the wake `admit_policy` now threads `approval_engine` + `approval_request_id` (cross-backend lockstep), and that the approval-family reasons survive the wrapper while non-approval reasons still collapse.

---

## 5. The wake-approval lifecycle (end-to-end)

```
POST /runs/{run_id}/resume {argv}                     # run row: suspended
  → resume() → wake(approval_request_id=None)
  → admit_policy Arm A → engine.create_request → sandbox_approval_pending(id=R)
  → [F3] R escapes the wrapper
  → suspended→pending_approval (store approval_request_id=R) + run.pending_approval
  ← 202 {terminal_state: pending_approval, approval_request_id: R}

operator grants R via the 13.5b1 portal approval API (out-of-band)

POST /runs/{run_id}/resume {argv, approval_request_id: R}   # run row: pending_approval
  → resume() no-re-mint guard: R present + matches stored R ✓
  → wake(approval_request_id=R)
  → admit_policy Arm B → verify_grant_for_action(R, digest, identity) → granted
     (digest binds metadata.policy/pack_context — byte-identical to Arm A)
  → approval_verified=True → Rego Step-9 admits → session woken
  → pending_approval→woken→completed (claim-gated) + run.completed
  ← 200 {terminal_state: completed, run_id}
```

**Status map (resume route, all via `_STATUS_BY_TERMINAL`):** `completed→200`, `pending_approval→202`, `refused→409` (incl. denied/expired/mismatch/not-found grants + non-approval revalidation refusals), `failed→502`. Route-level pre-flight refusals: `RunNotFound→404`, `RunNotResumable→409 run_not_suspended`, `RunResumeConflict→409 run_resume_conflict`, `RunResumePendingApprovalRequired→409 run_resume_approval_id_required`, `RunResumeApprovalMismatch→409 run_resume_approval_id_mismatch`.

---

## 6. Evidence model (F1-A — no checkpoint change)

Approval correlation is durable **without** touching `CheckpointMetadata`:
- the run row stores `approval_request_id` (set on `suspended→pending_approval`);
- `run.lifecycle.pending_approval` / `run.lifecycle.woken` / `run.lifecycle.completed` (store) + the executor's direct `run.pending_approval` / `run.completed` (output evidence) record the lifecycle;
- the approval engine's own `approval.*` chain rows (13.5a) record the grant decision;
- `approval_verified` stays transient (computed in `_consult_approval_engine`, consumed by the Rego Step-9 gate, discarded) — identical to cold-create, which persists no `approval_verified` either.

`CheckpointMetadata`'s 9-field wire shape, its drift detectors, and its no-schema-version additive-only doctrine are **untouched**.

---

## 7. Critical-controls surface + count

On-gate modules edited: `sandbox/protocol.py` (wake() wire contract), `sandbox/backends/docker_sibling.py` + `kubernetes_pod.py` (wake threading + wrapper exemption), `core/run/executor.py` (resume pending arm + guards). Off-gate: `core/run/_types.py` (matrix), `portal/api/runs/{dto,routes}.py`. **`sandbox/admission.py`, `sandbox/checkpoint_store.py`, `core/run/storage.py` are NOT edited** (consumed). **No new on-gate module → CC count stays 131** (`tools/check_critical_coverage.py` `_CRITICAL_FILES` + the self-test `_EXPECTED_ENTRY_COUNT` unchanged). Verify-at-promotion applies to every on-gate edit; the two boundary-ish checkpoints are the backend-threading commit and the executor-resume commit.

This sprint **crosses the A3c fence** A3b held — that is the intended deliverable, recorded in the ADR-022/004 amendments.

---

## 8. Test strategy

- **Backend wake threading (both, lockstep):** the wake `admit_policy` receives `approval_engine` + `approval_request_id`; the approval-family reasons survive the wrapper (parametrized over the 5 reasons, preserving `approval_request_id`); non-approval reasons still collapse to `sandbox_wake_policy_revalidation_failed`. Cross-backend drift detector on the exemption set.
- **`_types` matrix:** the 4 new pairs are legal; the reserved set still refuses; vocab still exactly 9.
- **`executor.resume()` (real `RunRecordStore` + real `DecisionHistoryStore`, stub backend whose `wake()` is forced through admission outcomes):** first-resume-from-suspended → pending (suspended→pending_approval, id stored, 202-shaped result); re-resume-with-matching-id → granted → woken→completed; re-resume still-pending (awaiting_second) → no transition + same id; re-resume denied/expired/binding-mismatch/not-found → refused; **no-re-mint guard:** re-resume from pending_approval without an id → `RunResumePendingApprovalRequired` (and `wake()` is never called — assert zero wake calls → proves no Arm-A re-mint); re-resume with a mismatched id → `RunResumeApprovalMismatch`; the claim-gated teardown is unbroken (pending/refused arms never destroy).
- **Route:** 202 on pending (+ `approval_request_id` echoed), 200 on granted-completed, 409 for the two new guard refusals + the grant-refusal reasons, the retry round-trip (202 → re-POST with id → 200).
- **Env-gated docker e2e (extends the A3b e2e or a sibling):** prove `suspend → resume(pending) → grant → re-resume → woken → completed` against real docker driven by a **stub/conformer approval engine** that forces the pending→grant cycle. The read_only run shape auto-tiers under a *real* `ApprovalEngine` (`create_request` raises `auto_tier_no_approval_required` → no pending), so this e2e proves the **wake/resume mechanics + the threading**, NOT real-approval-engine live behaviour — that needs the high-risk run shape (deferred per F4). Default-skip; operator pre-merge.
- **CC verify-at-promotion** on every on-gate edit (protocol/backends/executor ≥95/90; count 131).

---

## 9. Self-review

**Placeholder scan:** none — every component names the file, the seam, and the on/off-gate posture.

**Internal consistency:** the matrix pairs (§4.3) cover every `resume()` transition arm (§4.4); the status map (§5) covers every `RunResult.terminal_state` + every route pre-flight refusal; the evidence model (§6) is consistent with F1-A (no checkpoint change) and with the A3b run.lifecycle/run.* distinction.

**Scope check:** single implementation plan — the seam is 90% pre-built; A3c is bounded wiring (one Protocol field, two byte-identical backend edits, one matrix delta, one executor arm + two guards, one DTO field + route threading, one fence flip).

**Ambiguity check resolved:** (a) the no-re-mint guard is explicit — pending_approval re-resume REQUIRES + cross-checks the id and never reaches Arm A; (b) the still-pending re-resume is explicitly a no-op (no self-loop transition); (c) the F3 exemption set is a closed 5-reason group from a shared constant; (d) the args_digest binds the immutable checkpoint policy/pack_context, so the grant binding is drift-free across the first-wake/re-resume pair (the only drift surface is the LIVE catalog/rego/settings revalidation, which is a separate gate surfacing as `sandbox_wake_policy_revalidation_failed`).

**A3c completes the arc's wiring** — after this slice, the checkpoint→wake resumable-session vertical has its wake-approval seam **wired + governed** (resolver + resume route in A3b; wake approval correlation wired + unit-proven in A3c), with the **high-risk live exercise deferred per F4** (consistent with §1's "WIRED + unit-proven but not live-exercised in production" posture — the read_only shape never pends under a real engine). The remaining run-runtime items (manifest-driven high-risk run shape, orphaned-backend-resource reconciliation, quota-on-resume, the real `LocalParentBudgetResolver`, live sub-agent dispatch, MCP `call_tool` route) are independent forward tracks, not arc dependencies.
