# Sprint 14A-A4c — High-Risk WAKE Live Exercise — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Prove the full high-risk WAKE vertical end-to-end under a REAL `ApprovalEngine` — closing the "F4" caveat entirely (high-risk **cold-create AND wake** both live-exercised).

**Architecture:** Recon-proven **e2e-only — zero production-code gap** (A4b wired the high-risk cold-create pend + the persisted high-risk checkpoint; A3c wired the wake-pend → re-resume → woken lifecycle + the no-re-mint guard). A4c adds one env-gated real-docker e2e walking the two-approval-cycle flow + docs. **No production code, no new unit tests, no new on-gate module; CC stays 131; no migration.**

**Spec:** `docs/superpowers/specs/2026-06-17-sprint-14a-a4c-high-risk-wake-live-exercise-design.md`

**Tech stack:** Python 3.12, `uv`, pytest (`asyncio_mode=auto`), real `DockerSiblingSandboxBackend` + real `ApprovalEngine` + real `CheckpointStore` (env-gated `COGNIC_RUN_DOCKER_SANDBOX=1`).

---

## Execution discipline (project-specific)

- **Commits are controller-owned + token-gated.** Each task's "Commit" step is a HALT: halt summary (watchpoint→pin + fresh gate evidence; "files modified", not "staged") and wait for the explicit full-word commit token. Subagents implement only — never `git add`/commit/stage.
- **Gate ladder:** A4c touches NO gated code, so per-task CC coverage is **not** run (the speed-up rule). T1 (e2e) gate = the module collects-then-skips without the env var + `ruff check .` + `ruff format --check .` + full-tree `mypy src tests`. T2 (docs) gate = citation verification (no test parses these docs). T3 closeout = the **one** authoritative full-suite-under-coverage + full 131-module `check_critical_coverage` (expected unchanged at 131/131 since no gated module changed) + ruff/format/mypy/architecture.
- **Never stage** `docs/reviews/` or `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md`.
- Footer `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Git user `bmzee`. One `uv run` at a time. Branch already exists: `feat/sprint-14a-a4c-high-risk-wake-live-exercise` (spec at `feb7a82`).
- **THE GUARD (spec §Non-goals):** if T1's e2e — when reasoned through or run — exposes a need for ANY production-code change (a missing transition pair, a `CheckpointMetadata` field, a suspend-after-granted-cold-create guard, etc.), **STOP and re-scope** (the recon was wrong); do NOT code through it. Also: no matrix/state work, no `CheckpointMetadata` change, no quota/scheduler-on-resume work.

## File structure

| File | Layer | A4c responsibility |
|---|---|---|
| `tests/integration/run/test_managed_run_high_risk_wake_e2e.py` | test (env-gated) | The two-cycle high-risk WAKE proof. Copy of the A4b high-risk e2e setup + the A3c suspend/resume flow. |
| `docs/adrs/ADR-004-sandbox-primitive.md`, `docs/adrs/ADR-014-runtime-tool-approval.md`, `docs/adrs/ADR-022-runtime-scheduler.md`, `AGENTS.md`, `docs/AS_BUILT_CAPABILITY_MAP.md` | docs | High-risk cold-create AND wake now live-exercised; F4 fully closed. |

**Verified bases (the e2e synthesizes these — both committed):** `tests/integration/run/test_managed_run_high_risk_e2e.py` (A4b — the real `ApprovalEngine` construction, the high-risk `pack.lifecycle.submitted` seed, the real `grant()`, the shared `CheckpointStore` + `run_record_store` already threaded into backend + executor) and `tests/integration/run/test_managed_run_resume_approval_e2e.py` (A3c — the suspend→resume→wake-pend flow + the `run_record_store.load(run_id, tenant_id)` per-step state assertions + the 6-state chain-row walk). Verified executor signatures: `RunRequest(..., suspend_after_exec: bool = False, approval_request_id: uuid.UUID | None = None)`; `executor.resume(*, run_id, actor, argv, approval_request_id=None)`.

---

### Task 1: the env-gated high-risk WAKE e2e

**Files:**
- Create: `tests/integration/run/test_managed_run_high_risk_wake_e2e.py`

- [ ] **Step 1: Create the file by copying the A4b high-risk e2e, then replace the flow.** `cp tests/integration/run/test_managed_run_high_risk_e2e.py tests/integration/run/test_managed_run_high_risk_wake_e2e.py`. **Keep the entire SETUP verbatim** — the module-level env-gate preamble + imports, the docker/image preconditions, the schema + chain-heads seed, the `_packs.insert(...state="installed"...)` + the `pack.lifecycle.submitted` high-risk-manifest `dh_store.append(...)`, the `SchedulerEngine` (stub interrogators + `_allow_policy`), the shared `audit_store` + `CheckpointStore`, the REAL `ApprovalEngine` (OPAEngine over `tools.rego` + `ApprovalPolicy` + `ApprovalRequestStore`), the `DockerSiblingSandboxBackend` (stubbed catalog/rego, `approval_engine=approval_engine`, the shared `checkpoint_store`), the `run_record_store = RunRecordStore(engine)`, the `ManagedRunExecutor` (shared `checkpoint_store` + `run_record_store`). Rename the test to `test_high_risk_wake_pends_then_grants_in_real_container` and rewrite the module docstring for the WAKE two-cycle flow (the suspend-then-resume high-risk path; no conformer — the high-risk tier pends naturally at BOTH cold-create and wake). **Then replace the A4b flow section** (the `actor = Actor(...)` block + steps 1-4, the last ~62 lines before `finally:`) with:
```python
        actor = Actor(subject="svc-a", tenant_id=_TENANT, scopes=frozenset(), actor_type="service")

        async def _grant(approval_request_id: uuid.UUID) -> None:
            # the out-of-band human grant (portal approval in production); single-
            # approval tier -> one grant() -> granted; a DISTINCT human holding scope.
            await approval_engine.grant(
                request_id=approval_request_id,
                tenant_id=_TENANT,
                approver=ApprovalActor(
                    subject="rev@bank.example",
                    tenant_id=_TENANT,
                    scopes=frozenset({"tool.approve.customer_data"}),
                    actor_type="human",
                ),
            )

        # === CYCLE 1 — cold-create (A4b): pend -> grant -> re-POST(suspend) -> suspended ===
        # 1a) first run with suspend_after_exec=True. The cold create() pends on the
        #     high-risk tier BEFORE exec (so suspend is never reached) -> pending_approval
        #     + id1. This run_id is abandoned at pending_approval (the re-POST is fresh).
        cold_pending = await executor.run(
            RunRequest(
                tenant_id=_TENANT,
                pack_id=_PACK_ID,
                pack_uuid=pack_uuid,
                pack_version="1.0.0",
                argv=("printf", "cognic-14a-a4c-suspend"),
                actor=actor,
                suspend_after_exec=True,
            )
        )
        assert cold_pending.terminal_state == "pending_approval", cold_pending
        assert cold_pending.approval_request_id is not None
        await _grant(uuid.UUID(cold_pending.approval_request_id))

        # 1b) re-POST with the granted id1 + suspend_after_exec=True -> cold-create
        #     Arm-B verify -> admit -> exec -> session.suspend() -> SUSPENDED. This is
        #     the durable run that suspends + resumes (a NEW run_id).
        suspended = await executor.run(
            RunRequest(
                tenant_id=_TENANT,
                pack_id=_PACK_ID,
                pack_uuid=pack_uuid,
                pack_version="1.0.0",
                argv=("printf", "cognic-14a-a4c-suspend"),
                actor=actor,
                suspend_after_exec=True,
                approval_request_id=uuid.UUID(cold_pending.approval_request_id),
            )
        )
        assert suspended.terminal_state == "suspended", suspended
        assert suspended.exit_code == 0
        assert suspended.run_id
        run_id = uuid.UUID(suspended.run_id)
        rec_suspended = await run_record_store.load(run_id, tenant_id=_TENANT)
        assert rec_suspended is not None
        assert rec_suspended.state == "suspended"
        assert rec_suspended.session_id is not None
        assert rec_suspended.checkpoint_id is not None

        # === CYCLE 2 — wake (A3c): resume -> wake pends -> grant -> re-resume -> completed ===
        # 2a) first resume (NO id) -> wake re-runs admit_policy against the persisted
        #     HIGH-RISK checkpoint -> Arm A mints a fresh pending -> pending_approval + id2.
        wake_pending = await executor.resume(
            run_id=run_id,
            actor=actor,
            argv=("printf", "ignored-while-pending"),
        )
        assert wake_pending.terminal_state == "pending_approval", wake_pending
        assert wake_pending.run_id == suspended.run_id  # same durable run
        assert wake_pending.task_id is None  # resume makes no scheduler call
        assert wake_pending.approval_request_id is not None
        wake_id = uuid.UUID(wake_pending.approval_request_id)
        rec_pending = await run_record_store.load(run_id, tenant_id=_TENANT)
        assert rec_pending is not None
        assert rec_pending.state == "pending_approval"
        assert rec_pending.approval_request_id == wake_id  # the no-re-mint guard reads it

        # 2b) grant id2, then re-resume carrying it -> wake Arm-B verify -> woken -> exec
        #     -> COMPLETED.
        await _grant(wake_id)
        resume_marker = "cognic-14a-a4c-resume-ok"
        completed = await executor.resume(
            run_id=run_id,
            actor=actor,
            argv=("printf", resume_marker),
            approval_request_id=wake_id,
        )
        assert completed.terminal_state == "completed", completed
        assert completed.exit_code == 0
        assert resume_marker.encode() in completed.stdout
        assert completed.run_id == suspended.run_id
        rec_completed = await run_record_store.load(run_id, tenant_id=_TENANT)
        assert rec_completed is not None
        assert rec_completed.state == "completed"

        # === chain rows: the durable run walked the full high-risk wake path ===
        async with engine.connect() as conn:
            types = [
                r[0]
                for r in (
                    await conn.execute(
                        select(_decision_history.c.event_type).order_by(
                            _decision_history.c.sequence
                        )
                    )
                ).all()
            ]
        # store-side run-lifecycle audit trail — the suspending run's full 6-state
        # walk (pending -> running -> suspended -> pending_approval -> woken ->
        # completed); all six exist in the chain (run_B walks the full path).
        for lifecycle_event in (
            "run.lifecycle.pending",
            "run.lifecycle.running",
            "run.lifecycle.suspended",
            "run.lifecycle.pending_approval",
            "run.lifecycle.woken",
            "run.lifecycle.completed",
        ):
            assert lifecycle_event in types, types
        # executor-side per-terminal output-evidence rows.
        assert "run.suspended" in types, types
        assert "run.pending_approval" in types, types
        assert "run.completed" in types, types
```
(`ApprovalActor`, `RunRequest`, `Actor`, `RunRecordStore`, `select`, `_decision_history`, `uuid` are all already imported in the copied A4b base; `run_record_store` is already a named local there. The `_grant` closure is a tiny `async` DRY helper for the two real grants — `await _grant(id)` at each call site, matching the existing `await approval_engine.grant(...)` shape.)

- [ ] **Step 2: Verify the gate behavior (env-gated — no red-green).** `uv run pytest tests/integration/run/test_managed_run_high_risk_wake_e2e.py -q` → **exit 5** with **1 skipped** (the module-level `allow_module_level=True` skip fires BEFORE collection, so pytest reports "no tests ran" / exit code 5 — this is EXPECTED for a module-level-skipped file, identical to the A4b/A3c e2es, NOT a failure; do not treat exit 5 here as a gate fail). `--collect-only -q` on the single file ALSO exits 5 ("no tests collected"). The **exit-0** clean-collection signal is the PACKAGE run `uv run pytest tests/integration/run/ -q` (the sibling integration/run files collect-then-skip via `skipif`, so the package exits 0 — that is the real "module imports cleanly + nothing broke collection" check). The structural correctness is reasoned (the recon trace) + read-review; live execution is the operator pre-merge audit.

- [ ] **Step 3: THE GUARD checkpoint.** Re-read the flow against `executor.py` `run()`/`resume()` (the recon trace): confirm NO production-code change is implied — every step lands on an existing path (cold-create pend `:500`, suspend `:639`, wake-pend `:815`, no-re-mint `:790`, `from_state→woken` `:910`) and every transition pair is already in `_types.py`. If anything requires a production edit → **STOP, report, re-scope** (do not proceed to commit).

- [ ] **Step 4: Gate ladder + HALT for the commit token.** `uv run ruff check tests/integration/run/test_managed_run_high_risk_wake_e2e.py` + `uv run ruff format --check .` + `uv run mypy src tests` (full tree — the e2e body is type-checked here; single-file mypy's `import-untyped` notes are the known spurious artifact).
```bash
git add tests/integration/run/test_managed_run_high_risk_wake_e2e.py
git commit -m "test(run): Sprint 14A-A4c T1 — env-gated real-engine high-risk WAKE e2e (two approval cycles) (ADR-022/004/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: docs — high-risk cold-create AND wake live-exercised; F4 fully closed

**Files:**
- Modify: `docs/adrs/ADR-004-sandbox-primitive.md`, `docs/adrs/ADR-014-runtime-tool-approval.md`, `docs/adrs/ADR-022-runtime-scheduler.md`, `AGENTS.md`, `docs/AS_BUILT_CAPABILITY_MAP.md`

- [ ] **Step 1: ADR amendments** — a `## Sprint 14A-A4c amendment` section in ADR-004 / ADR-014 / ADR-022 (each before its `## References`, amend-by-addition): the high-risk WAKE path is now live-exercised by an env-gated real-`ApprovalEngine` e2e (two approval cycles — cold-create + wake — both pend naturally for a high-risk tier); this closes the A4b/A3c "F4 deferred (wake)" caveat ENTIRELY; **e2e-only — no production code** (A4b + A3c had already wired the full path); CC 131, no migration. ADR-004 owns the sandbox wake-revalidation angle; ADR-022 the run-lifecycle/two-cycle angle; ADR-014 the double-checkpoint approval angle.

- [ ] **Step 2: AGENTS.md** — extend the `core/run/executor.py` / managed-run section with a short "Sprint 14A-A4c" note (the high-risk WAKE is now live-exercised; F4 fully closed; e2e-only). **Patch the present-tense forward-claims** that say the high-risk WAKE / suspend→resume live exercise is still pending — grep WIDE: `grep -niE "high-risk (suspend|wake)|WAKE live|F4|suspend.resume.WAKE" AGENTS.md` and update each that is now stale (the A3c/A4b entries are amend-by-addition history — leave those; patch the present-tense "forward" lists, e.g. the A4b extension's "high-risk suspend→resume/WAKE live exercise" forward item).

- [ ] **Step 3: AS_BUILT_CAPABILITY_MAP.md** — update Pillar 2 + Pillar 6 (the current-state table: drop "high-risk WAKE forward"; both cold-create + wake now live) and add a forward-sequence **`6f`** 14A-A4c DONE entry (amend-by-addition, mirroring 6e). Remove the high-risk WAKE item from the "remaining forward tracks" lists (quota/scheduler-on-resume, orphaned-resource, MCP `call_tool`, `LocalParentBudgetResolver`/sub-agent, resumption UX stay).

- [ ] **Step 4: Verify citations + HALT.** `grep -niE "high-risk (suspend|wake)|F4|live-exercise" AGENTS.md docs/AS_BUILT_CAPABILITY_MAP.md docs/adrs/ADR-004-sandbox-primitive.md docs/adrs/ADR-014-runtime-tool-approval.md docs/adrs/ADR-022-runtime-scheduler.md` — confirm every present-tense claim matches the landed e2e + no stale "WAKE forward" remains on a current-state surface. Self-review accuracy (subagent doc-reviewers have died on transient API both prior arcs).
```bash
git add docs/adrs/ADR-004-sandbox-primitive.md docs/adrs/ADR-014-runtime-tool-approval.md docs/adrs/ADR-022-runtime-scheduler.md AGENTS.md docs/AS_BUILT_CAPABILITY_MAP.md
git commit -m "docs: Sprint 14A-A4c — high-risk cold-create + wake live-exercised; F4 fully closed (ADR-022/004/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: closeout

**Files:** none (verification only)

- [ ] **Step 1: full-suite (clean record)** — `uv run pytest tests/unit -q` → all pass (the new e2e is in `tests/integration`, not `tests/unit`; this confirms no unit regression).
- [ ] **Step 2: authoritative CC gate** — `uv run coverage run --branch -m pytest tests/unit` → `uv run coverage json -o coverage.json` → `uv run python tools/check_critical_coverage.py`. Expected **131/131 unchanged** (no gated module touched). (This is the one full-suite-under-coverage run for the sprint.)
- [ ] **Step 3: integration collect + lint/types** — `uv run pytest tests/integration/run -q` (expect all skipped, clean collection) + `uv run ruff check .` + `uv run ruff format --check .` + `uv run mypy src tests`.
- [ ] **Step 4: architecture fences** — `uv run pytest tests/unit/architecture -q`.
- [ ] **Step 5: reconciliation + HALT** — `git status --short` (only intended files; the two protected docs untracked). No commit of its own. Proceed to `finishing-a-development-branch` (push + PR) only on explicit tokens.

---

## Self-Review (against the spec)

**Spec coverage:** §Goal → T1 (the two-cycle e2e). §Design (the 6-step flow) → T1 Step 1 (concrete code, grounded in the A4b setup + A3c flow). §Non-goals/guards → the execution-discipline GUARD + T1 Step 3 (the guard checkpoint). §Tasks → T1/T2/T3. §Posture (CC 131, no migration, e2e-only, F4 closed) → T2 docs + T3 closeout. ✔

**Placeholder scan:** T1 ships concrete, grounded code using real symbols (`executor.run`/`resume`, `RunRequest` fields, `approval_engine.grant`, `ApprovalActor`, `run_record_store.load`, `_decision_history`) — all verified present in the copied A4b base + the A3c flow. No `...`. T2's doc edits are described with exact grep anchors (no invented text). ✔

**Type/shape consistency:** the two-`run_id` shape (cold-create-pend run abandoned; the re-POST run suspends+resumes) is handled — `run_id` is taken from `suspended.run_id` (the durable run), and all rec-assertions + the resume calls use that `run_id`. The two grants (`cold_pending.approval_request_id` for cold-create, `wake_id` for wake) are distinct, each `uuid.UUID(...)`-wrapped for `grant(request_id: uuid.UUID)`. ✔
