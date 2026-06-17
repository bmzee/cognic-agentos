# Sprint 14A-A4c — High-Risk WAKE Live Exercise — Design

**Date:** 2026-06-17
**Status:** DRAFT — recon-gated; the read-only recon (2026-06-17) PROVED the slice small (e2e-only, zero production-code gap).
**ADRs:** ADR-004 (sandbox primitive), ADR-022 (scheduler/run), ADR-014 (runtime approval)

## Context

Sprint 14A-A4b closed the "F4" caveat for the **cold-create** high-risk path: the managed-run executor sources a pack's validated manifest risk tier and threads it into both the scheduler submit and the sandbox `PackAdmissionContext`, so a high-risk run pends at the sandbox cold-create human checkpoint (pend → grant → re-POST → complete), proven by an env-gated real-`ApprovalEngine` e2e.

The **remaining** F4 piece is the **WAKE** path: a high-risk run that suspends, then resumes, must pend again at wake-revalidation (the A3c wake-approval correlator), then grant → re-resume → complete. A3c wired the full wake lifecycle, but it was only ever live-exercised for `read_only` — which auto-tiers and never pends — so the high-risk WAKE flow has never been walked end-to-end under a real engine.

## Recon verdict (the gate)

A read-only recon traced the full high-risk WAKE flow in `core/run/executor.py` and confirmed it is **e2e-only — zero production-code gap**:

- **Two independent approval cycles, both already wired:** (1) **cold-create** (A4b) gets the run to `suspended` after a grant; (2) **wake** (A3c) re-runs `admit_policy` against the persisted high-risk checkpoint, mints a *fresh* pending (Arm A), and the resume lifecycle (`suspended → pending_approval → woken` + the no-re-mint guard) drives the second grant → re-resume → complete.
- The suspend path (`executor.py:639`) has **no guard** blocking a granted high-risk run from suspending; the high-risk `pack_context` is persisted into the checkpoint at suspend and re-read at wake (no fresh manifest load — the F1 immutable-metadata pin).
- Every transition pair (`running→suspended`, `suspended→pending_approval`, `pending_approval→woken`, `woken→completed`) is already in the matrix; the wake-pend lifecycle is A3c production code; the **unit** lifecycle is already covered by A3c's resume tests (the stub backend's wake-pend is tier-agnostic).

So A4c adds **no production code and no new unit tests** — it is purely the **live integration proof** (a real `ApprovalEngine` + a high-risk tier that pends naturally at both cold-create and wake).

## Goal

Prove the full high-risk WAKE vertical end-to-end under a REAL `ApprovalEngine`, closing F4 entirely — high-risk **cold-create AND wake** both live-exercised.

## Non-goals (guards — user-locked)

- **No production-code changes** unless the recon is proven wrong by the e2e.
- **No matrix / state-machine work** (the transitions already exist).
- **No `CheckpointMetadata` change** (the wake binds the already-persisted immutable `metadata.policy` / `metadata.pack_context`).
- **No quota / scheduler-on-resume work** (resume makes no scheduler calls — a separate forward track).
- **If the e2e exposes a production gap, STOP and re-scope** before coding through it (re-evaluate against 14B Deployment Substrate).

## Design — the e2e (T1)

A single env-gated (`COGNIC_RUN_DOCKER_SANDBOX=1`) real-docker e2e proving the two-cycle flow:

1. `run(RunRequest(<high-risk pack>, suspend_after_exec=True))` → `terminal_state="pending_approval"` + `id1` (cold-create pend, A4b).
2. `approval_engine.grant(request_id=id1, …)` — a distinct human holding the tier's grant scope (`customer_data_read` → `tool.approve.customer_data`).
3. `run(RunRequest(…, suspend_after_exec=True, approval_request_id=id1))` → `terminal_state="suspended"` (cold-create Arm-B verify → admit → exec → `session.suspend()`).
4. `resume(run_id, …)` → `terminal_state="pending_approval"` + `id2` (wake re-runs `admit_policy` against the persisted high-risk checkpoint → Arm A mints a fresh pending).
5. `approval_engine.grant(request_id=id2, …)`.
6. `resume(run_id, …, approval_request_id=id2)` → `terminal_state="completed"` (no-re-mint guard passes → wake Arm-B verify → `pending_approval → woken` → exec → complete).

Asserts the suspending run's run-record walk `pending → running → suspended → pending_approval → woken → completed` and the run-evidence chain rows (`run.suspended`, `run.pending_approval`, `run.completed`).

**Modeling:** a synthesis of the A4b high-risk cold-create e2e (`tests/integration/run/test_managed_run_high_risk_e2e.py` — real `ApprovalEngine`, high-risk pack seed via a `pack.lifecycle.submitted` chain row, real `grant()`) + the A3c resume e2e (`tests/integration/run/test_managed_run_resume_approval_e2e.py` — suspend → resume → wake-pend lifecycle). **No conformer** — a high-risk tier pends naturally at *both* gates under a real engine (the A3c conformer existed only because `read_only` auto-tiers). The catalog cosign + sandbox-admission Rego are stubbed allow (the z3 / A4b pattern); the approval engine's `tools.rego` classification is REAL.

**The two-`run_id` shape (carried from A4b, not new):** the first `run()` that pends at cold-create mints `run_id_A` (abandoned at `pending_approval`); the re-POST is a fresh `run()` minting `run_id_B`, and `run_id_B` is the one that suspends + resumes. The `approval_request_id` correlates the grant, not the run. The dangling `run_id_A` is the existing A4b cold-create posture (run-record reconciliation is a separate forward item), not introduced by A4c.

## Tasks

- **T1** — the env-gated real-`ApprovalEngine` high-risk WAKE e2e (above) + its non-env-gated skip-contract (mirrors A4b/A3c).
- **T2** — docs only: ADR-004 / ADR-014 / ADR-022 `## Sprint 14A-A4c amendment` + `AGENTS.md` + `docs/AS_BUILT_CAPABILITY_MAP.md`. State that high-risk **cold-create AND wake** are now live-exercised; **F4 fully closed**; CC 131, no migration.
- **T3** — closeout only (full-suite-under-coverage + the full 131-module gate + ruff/format/mypy/architecture; the e2e collects-then-skips without the env var; no new on-gate module).

## Posture

CC count stays **131**; no migration; no new on-gate module. The e2e is env-gated (verified-by-reading + operator-pre-merge-audit-runnable, exactly the A4b/A3c posture). This slice closes the high-risk **suspend→resume/WAKE** forward track; the other forward tracks (orphaned-backend-resource reconciliation, quota/scheduler-on-resume, MCP `call_tool`, the real `LocalParentBudgetResolver` + sub-agent dispatch, resumption UX) and **14B Deployment Substrate** (forward item 7) remain. With A4c, the managed-runtime governance story has zero asterisks on the high-risk path before the 14B pivot.
