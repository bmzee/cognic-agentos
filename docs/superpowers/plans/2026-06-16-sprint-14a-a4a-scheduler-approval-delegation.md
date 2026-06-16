# Sprint 14A-A4a — Scheduler `approval-delegated-to-sandbox` Affordance — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit, audited scheduler admission affordance — `SubmitInput.approval_delegated_to="sandbox_admission"` — that admits a high-risk task because the downstream sandbox admission gate owns the human checkpoint, without minting its own approval and without faking `approval_verified`. Ships **additive + dormant**; no production caller sets it (A4b is the activator).

**Architecture:** A named delegate signal flows `SubmitInput` → engine (skip the Step-3.5 consult, leave `approval_verified=False`) → policy (10th rego-input key) → `scheduler.rego` (a third high-risk allow arm) → storage (honest conditional chain-row evidence). The signal stays **out** of the scheduler approval binding digest (routing/evidence, not grant-binding).

**Tech Stack:** Python 3.12, `uv`, pytest (`asyncio_mode=auto`), SQLAlchemy async (in-memory sqlite unit DB), OPA/Rego (`opa` binary via `OPAEngine` + direct subprocess), the `core/approval` engine.

**Spec:** `docs/superpowers/specs/2026-06-16-sprint-14a-a4a-scheduler-approval-delegation-design.md`

---

## Execution discipline (project-specific — overrides the generic template)

- **Commits are controller-owned and token-gated.** Each task's "Commit" step is a HALT: the controller produces a halt summary (watchpoint→pin map + fresh gate evidence; "files modified", not "staged") and waits for the user's explicit full-word commit token. Subagents **implement only** — they never `git add`/`git commit`/stage.
- **Gate ladder before every halt:** focused pytest → neighborhood suite (include `tests/unit/architecture/`) → `uv run ruff check .` → `uv run ruff format --check .` → full-tree `uv run mypy src tests`. Full suite runs at the commit token (or when a shared/CC/policy module changed).
- **CC edits** (`engine.py`, `policy.py`, `storage.py`) run the coverage gate on **fresh `--cov-branch`** data: `uv run coverage run --branch -m pytest tests/unit` → `uv run coverage json -o coverage.json` (NOT `--cov-report=json`) → `uv run python tools/check_critical_coverage.py`. **CC count stays 131** — do NOT edit `tools/check_critical_coverage.py` `_CRITICAL_FILES` or the `_EXPECTED_ENTRY_COUNT` self-test.
- **Never stage** `docs/reviews/` or `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md`.
- **Commit footer:** `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Git user `bmzee`. One `uv run` at a time (venv lock).
- Branch already exists: `feat/sprint-14a-a4a-scheduler-approval-delegation` (spec committed at `8dc4666`).

## File structure (what each touched file owns)

| File | Layer | Responsibility for A4a |
|---|---|---|
| `src/cognic_agentos/core/scheduler/_types.py` | off-gate | The `SchedulerApprovalDelegate` Literal + the `SubmitInput.approval_delegated_to` field. |
| `src/cognic_agentos/core/scheduler/engine.py` | **CC** | Boundary validation (unknown + mutual-exclusion precedence); Step-3.5 skip-consult-when-delegated; `SchedulerSubmitInputInvalidField` 2→3. |
| `src/cognic_agentos/core/scheduler/policy.py` | **CC** | `_build_rego_input` 9→10 keys (nullable `approval_delegated_to`, always threaded). |
| `policies/_default/scheduler.rego` | **stop-rule** | Allow arm 3 (high-risk + delegated, strict) + the refusal-arm honesty guard. |
| `src/cognic_agentos/core/scheduler/storage.py` | **CC** | `scheduler.admission_accepted` conditional `approval_delegated_to` evidence key. |
| `docs/adrs/ADR-022-runtime-scheduler.md`, `docs/adrs/ADR-014-runtime-tool-approval.md`, `AGENTS.md` | docs | The amendments + the active-operating-model patch. |
| `tests/unit/core/scheduler/test_approval_seam.py` | test | Field default, vocab, disposition+exclusion, engine validation + skip-consult. |
| `tests/unit/core/scheduler/test_policy.py` | test | The 10-key contract + threading. |
| `tests/unit/policies/test_scheduler_rego.py` | test | Arm 3 + strict + refusal-guard + arms 1/2 regression. |
| `tests/unit/core/scheduler/test_storage.py` | test | The accepted-row evidence (set / unset / no-correlator). |

---

### Task 1: `_types.py` — the delegate enum + `SubmitInput` field + its drift tests

**Files:**
- Modify: `src/cognic_agentos/core/scheduler/_types.py` (Literal block ~`:79`; `SubmitInput` ~`:114`)
- Test: `tests/unit/core/scheduler/test_approval_seam.py`

Adding the field changes `dataclasses.fields(SubmitInput)`, which immediately breaks the existing disposition-map drift test (`test_args_digest_disposition_map_covers_every_submit_input_field`) — so this task updates that test in the same unit, plus the behavioral digest-exclusion pin and a default-value test.

- [ ] **Step 1: Write the failing tests** in `tests/unit/core/scheduler/test_approval_seam.py`.

Add a default-value test + a 1-value enum drift test (place near `test_submit_input_carries_three_new_defaulted_fields`):
```python
def test_submit_input_approval_delegated_to_defaults_none() -> None:
    # Sprint 14A-A4a — additive, defaulted so every existing constructor stays green.
    from cognic_agentos.core.scheduler._types import SubmitInput, TaskActor

    base = SubmitInput(
        tenant_id="t-1",
        pack_id="pack-x",
        actor=TaskActor(subject="svc-a", tenant_id="t-1", actor_type="service"),
        class_="interactive",
        pack_kind="tool",
        pack_risk_tier="internal_write",
        requested_estimated_tokens=500,
    )
    assert base.approval_delegated_to is None
    rich = dataclasses.replace(base, approval_delegated_to="sandbox_admission")
    assert rich.approval_delegated_to == "sandbox_admission"


def test_scheduler_approval_delegate_is_one_value_enum() -> None:
    # Sprint 14A-A4a — closed enum; drift detector. Canonical home per the
    # module docstring is test_closed_enums.py, pinned here alongside the other
    # A4a vocab tests for locality.
    from cognic_agentos.core.scheduler._types import SchedulerApprovalDelegate

    assert set(typing.get_args(SchedulerApprovalDelegate)) == {"sandbox_admission"}
```

Update the disposition-map test (`:135-142`) to add the `routing_or_evidence` bucket:
```python
    digested = {"class_", "pack_risk_tier", "requested_estimated_tokens", "parent_task_id"}
    digested_via_actor = {"actor"}  # as actor.subject + actor.actor_type
    identity = {"pack_id", "pack_kind"}
    envelope_first_class = {"tenant_id", "data_classes"}
    carrier_or_attestation = {"approval_request_id", "approval_verified"}
    routing_or_evidence = {"approval_delegated_to"}  # Sprint 14A-A4a — excluded from the digest
    assert {f.name for f in dataclasses.fields(SubmitInput)} == (
        digested | digested_via_actor | identity | envelope_first_class
        | carrier_or_attestation | routing_or_evidence
    )
```

Add the behavioral exclusion pin at the end of `test_args_digest_binds_actor_tokens_and_parent` (`:169-181`):
```python
    # Sprint 14A-A4a — routing/evidence signal, NOT grant-binding: setting it
    # MUST NOT change the digest (the helper cannot silently start binding it).
    assert _submit_args_digest(_seam_submit_input(approval_delegated_to="sandbox_admission")) == base  # type: ignore[arg-type]
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/core/scheduler/test_approval_seam.py -q`
Expected: FAIL — `AttributeError`/`TypeError` on `approval_delegated_to` and the import of `SchedulerApprovalDelegate`; the disposition assert fails (LHS lacks the new field).

- [ ] **Step 3: Implement** in `src/cognic_agentos/core/scheduler/_types.py`.

Add the Literal after `ActorType` (`:79`):
```python
ActorType = Literal["human", "service"]

#: Sprint 14A-A4a (ADR-022 + ADR-014) — named delegate authority. When set on a
#: SubmitInput, the scheduler admits a high-risk task because the named downstream
#: gate owns the human checkpoint; the scheduler mints/verifies no grant of its own.
#: Wave-1: the only authority is the sandbox admission gate. See the setter
#: obligation in the A4a spec §3.8 — only the A4b managed-run executor sets it.
SchedulerApprovalDelegate = Literal["sandbox_admission"]
```

Add the field to `SubmitInput`, after `data_classes` (`:114`):
```python
    data_classes: tuple[str, ...] = ()  # manifest [data_governance].data_classes
    # Sprint 14A-A4a (ADR-022 + ADR-014) — routing/evidence signal (NOT a grant
    # carrier, NOT in the approval binding digest). Default None = no delegation.
    approval_delegated_to: SchedulerApprovalDelegate | None = None
```

**Sweep the `SubmitInput` class docstring** (`:95-101`) — it currently states the only non-standard fields are the "Two Sprint-13.5c2 exceptions (ADR-014)" (`approval_request_id` + `approval_verified`). Add a sentence naming `approval_delegated_to` as the Sprint-14A-A4a routing/evidence signal the engine reads but never binds into the approval digest. Verify no stale "two ... fields" phrasing remains: `grep -n "Two Sprint\|two .*field\|approval_verified" src/cognic_agentos/core/scheduler/_types.py`.

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/core/scheduler/test_approval_seam.py -q`
Expected: PASS (all, including the updated disposition + exclusion pins).

- [ ] **Step 5: Neighborhood + lint + types, then HALT for the commit token**

Run: `uv run pytest tests/unit/core/scheduler tests/unit/architecture -q` → `uv run ruff check .` → `uv run ruff format --check .` → `uv run mypy src tests`
Then produce the halt summary. On the token:
```bash
git add src/cognic_agentos/core/scheduler/_types.py tests/unit/core/scheduler/test_approval_seam.py
git commit -m "feat(scheduler): Sprint 14A-A4a T1 — SchedulerApprovalDelegate + SubmitInput.approval_delegated_to (dormant) (ADR-022/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `engine.py` — boundary validation + `SchedulerSubmitInputInvalidField` 2→3

**Files:**
- Modify: `src/cognic_agentos/core/scheduler/engine.py` (`:157` Literal; `:163-165` frozenset; insert after the `approval_request_id` parse at `:444`)
- Test: `tests/unit/core/scheduler/test_approval_seam.py`

Pins the §3.2/§3.3 precedence: parse `approval_request_id` first (malformed → `field="approval_request_id"`); then unknown-value; then mutual-exclusion only on a syntactically valid UUID.

- [ ] **Step 1: Write the failing tests** (append to `test_approval_seam.py`):
```python
class TestA4aDelegationValidation:
    async def test_unknown_delegate_value_is_invalid(self, tmp_path: object) -> None:
        from cognic_agentos.core.scheduler.engine import SchedulerSubmitInputInvalid

        db = await _mk_migrated_db(tmp_path)
        engine = _mk_scheduler_engine(db)
        with pytest.raises(SchedulerSubmitInputInvalid) as exc:
            await engine.submit(  # type: ignore[attr-defined]
                submit_input=_seam_submit_input(approval_delegated_to="kitchen"),
                request_id="req-1",
            )
        assert exc.value.field == "approval_delegated_to"

    async def test_delegated_plus_valid_request_id_is_mutually_exclusive(
        self, tmp_path: object
    ) -> None:
        from cognic_agentos.core.scheduler.engine import SchedulerSubmitInputInvalid

        db = await _mk_migrated_db(tmp_path)
        engine = _mk_scheduler_engine(db)
        with pytest.raises(SchedulerSubmitInputInvalid) as exc:
            await engine.submit(  # type: ignore[attr-defined]
                submit_input=_seam_submit_input(
                    approval_delegated_to="sandbox_admission",
                    approval_request_id="11111111-1111-1111-1111-111111111111",
                ),
                request_id="req-1",
            )
        assert exc.value.field == "approval_delegated_to"

    async def test_malformed_request_id_wins_over_mutual_exclusion(
        self, tmp_path: object
    ) -> None:
        # Precedence (§3.2): the unconditional UUID parse fires FIRST, so a
        # malformed id surfaces field="approval_request_id" even when delegated.
        from cognic_agentos.core.scheduler.engine import SchedulerSubmitInputInvalid

        db = await _mk_migrated_db(tmp_path)
        engine = _mk_scheduler_engine(db)
        with pytest.raises(SchedulerSubmitInputInvalid) as exc:
            await engine.submit(  # type: ignore[attr-defined]
                submit_input=_seam_submit_input(
                    approval_delegated_to="sandbox_admission",
                    approval_request_id="not-a-uuid",
                ),
                request_id="req-1",
            )
        assert exc.value.field == "approval_request_id"
```

Update the vocabulary test (`:77-91`) — rename + assert 3 values:
```python
def test_submit_input_invalid_field_vocabulary_three_values() -> None:
    # Sprint 14A-A4a: 2 → 3 (+ approval_delegated_to); Literal + frozenset lockstep.
    from cognic_agentos.core.scheduler.engine import (
        _VALID_SUBMIT_INPUT_INVALID_FIELDS,
        SchedulerSubmitInputInvalidField,
    )

    assert set(typing.get_args(SchedulerSubmitInputInvalidField)) == {
        "parent_task_id",
        "approval_request_id",
        "approval_delegated_to",
    }
    assert (
        frozenset({"parent_task_id", "approval_request_id", "approval_delegated_to"})
        == _VALID_SUBMIT_INPUT_INVALID_FIELDS
    )
```
Also update `tests/unit/core/scheduler/test_engine.py::test_t10_invalid_field_literal_in_lockstep_with_constant` if it independently asserts the 2-value set (grep it: `grep -n "approval_request_id" tests/unit/core/scheduler/test_engine.py`; extend any frozenset/`get_args` assertion to the 3-value set).

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/core/scheduler/test_approval_seam.py -k "A4aDelegationValidation or vocabulary_three" -q`
Expected: FAIL — no validation raised (submit proceeds / wrong field); the 3-value assert fails on the 2-value Literal.

- [ ] **Step 3: Implement** in `engine.py`.

Grow the Literal (`:157`) and frozenset (`:163-165`):
```python
SchedulerSubmitInputInvalidField = Literal[
    "parent_task_id", "approval_request_id", "approval_delegated_to"
]
```
```python
_VALID_SUBMIT_INPUT_INVALID_FIELDS: Final[frozenset[str]] = frozenset(
    {"parent_task_id", "approval_request_id", "approval_delegated_to"}
)
```

**Sweep the stale "2 values / 2-value vocabulary" comments** describing this enum: the `SchedulerSubmitInputInvalidField` comment block (`:150-157`, "2 values: ...") and the `SchedulerSubmitInputInvalid` class docstring (`:183-193`, "2-value vocabulary"). Update both to **3 values** and add `approval_delegated_to` (unknown-value + mutual-exclusion-with-a-valid-`approval_request_id`) to the coverage prose. Verify: `grep -n "2 values\|2-value\|two value" src/cognic_agentos/core/scheduler/engine.py` returns nothing stale.

Insert the validation block immediately after the `approval_request_id` parse (after `:444`, before "Step 2: pack installed?"):
```python
        # Sprint 14A-A4a (ADR-022 + ADR-014) — approval_delegated_to validated at
        # the engine boundary (the approval_request_id mirror). Unknown value fails
        # closed; mutual-exclusion fires only on a VALID parsed UUID — the parse
        # above already owns the malformed-id outcome (precedence §3.2), so a
        # malformed id surfaces field="approval_request_id", not this branch.
        if submit_input.approval_delegated_to is not None:
            if submit_input.approval_delegated_to != "sandbox_admission":
                raise SchedulerSubmitInputInvalid(
                    field="approval_delegated_to",
                    reason=f"unknown delegate target: {submit_input.approval_delegated_to!r}",
                )
            if approval_request_uuid is not None:
                raise SchedulerSubmitInputInvalid(
                    field="approval_delegated_to",
                    reason="mutually exclusive with approval_request_id",
                )
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/core/scheduler/test_approval_seam.py tests/unit/core/scheduler/test_engine.py -q`
Expected: PASS.

- [ ] **Step 5: Gate ladder (CC module) + HALT for commit token**

Run the neighborhood + lint + format + mypy. Because `engine.py` is CC, also run the coverage gate (Step in Task 8 covers the full fresh-data run; a focused `uv run pytest tests/unit/core/scheduler --cov=cognic_agentos.core.scheduler.engine --cov-branch -q` confirms the new branches are hit). On the token:
```bash
git add src/cognic_agentos/core/scheduler/engine.py tests/unit/core/scheduler/test_approval_seam.py tests/unit/core/scheduler/test_engine.py
git commit -m "feat(scheduler): Sprint 14A-A4a T2 — engine boundary validation for approval_delegated_to (ADR-022/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `engine.py` — Step-3.5 skip-consult-when-delegated

**Files:**
- Modify: `src/cognic_agentos/core/scheduler/engine.py` (`:482-507` Step-3.5 block)
- Test: `tests/unit/core/scheduler/test_approval_seam.py`

When delegated, the engine must NOT consult the approval engine (no mint), leave `approval_verified=False`, and thread `approval_delegated_to` to the policy. Proven at the engine level with the capturing policy stub (the rego admission is Task 5).

- [ ] **Step 1: Write the failing test** (append to `test_approval_seam.py`):
```python
class TestA4aDelegationSkipsConsult:
    async def test_delegated_high_tier_skips_consult_and_admits(
        self, tmp_path: object
    ) -> None:
        # approval engine WIRED + a high-risk tier that would normally pend; with
        # delegation the engine mints NO request, leaves approval_verified False,
        # and (capturing policy allow=True) admits immediately.
        from cognic_agentos.core.approval.storage import ApprovalRequestStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore

        db = await _mk_migrated_db(tmp_path)
        policy = _CapturingPolicy(allow=True)
        engine = _mk_scheduler_engine(
            db,
            approval_engine=_mk_approval_engine(db, flow="require_4_eyes"),
            policy=policy,
        )
        decision = await engine.submit(  # type: ignore[attr-defined]
            submit_input=_seam_submit_input(approval_delegated_to="sandbox_admission"),
            request_id="req-1",
        )
        assert decision.outcome == "accepted_immediate"
        # NO scheduler approval request minted (the consult was skipped):
        assert await ApprovalRequestStore(DecisionHistoryStore(db)).list_pending("t-1") == []  # type: ignore[arg-type]
        # The policy saw approval_verified False AND the delegate signal:
        seen = policy.seen[0]
        assert seen.approval_verified is False  # type: ignore[attr-defined]
        assert seen.approval_delegated_to == "sandbox_admission"  # type: ignore[attr-defined]
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/core/scheduler/test_approval_seam.py -k A4aDelegationSkipsConsult -q`
Expected: FAIL — today the wired engine consults and returns `refused_approval_pending` (decision.outcome != "accepted_immediate"; a pending request is minted).

- [ ] **Step 3: Implement** — restructure the Step-3.5 block (`:482-507`) so delegation short-circuits the consult:
```python
        approval_verified = False
        if submit_input.approval_delegated_to is not None:
            # Sprint 14A-A4a (ADR-022 + ADR-014) — delegation: the downstream
            # sandbox admission gate owns the human checkpoint, so the scheduler
            # mints/verifies NO grant of its own. approval_verified stays False
            # (honest — the scheduler verified nothing); the rego admits the
            # high-risk tier via its delegated allow arm. No consult.
            pass
        elif self._approval_engine is not None:
            consult = await self._consult_approval(
                original_submit_input=submit_input,
                approval_request_uuid=approval_request_uuid,
                request_id=request_id,
            )
            if consult.refusal_reason is not None:
                await self._emit_admission_refused(
                    refused_task_id=task_id,
                    submit_input=effective_submit_input,
                    reason=consult.refusal_reason,
                    request_id=request_id,
                    approval_request_id=consult.approval_request_id,
                    approval_flow=consult.approval_flow,
                )
                return AdmissionDecision(
                    outcome=consult.refusal_reason,
                    task_id=None,
                    approval_request_id=(
                        consult.approval_request_id
                        if consult.refusal_reason == "refused_approval_pending"
                        else None
                    ),
                )
            approval_verified = consult.verified
        # F1 LOCK: ENGINE-OWNED attestation — ALWAYS overwrite.
        effective_submit_input = dataclasses.replace(
            effective_submit_input, approval_verified=approval_verified
        )
```
(`approval_delegated_to` is preserved on `effective_submit_input` automatically — `dataclasses.replace` only changes `approval_verified` / `requested_estimated_tokens`.)

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/core/scheduler/test_approval_seam.py -q`
Expected: PASS (the existing wired-pending tests still pass — they set no `approval_delegated_to`, so they take the `elif` consult path unchanged).

- [ ] **Step 5: Gate ladder + HALT for commit token**
```bash
git add src/cognic_agentos/core/scheduler/engine.py tests/unit/core/scheduler/test_approval_seam.py
git commit -m "feat(scheduler): Sprint 14A-A4a T3 — Step-3.5 skips consult when delegated (no mint; approval_verified stays False) (ADR-022/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: `policy.py` — `_build_rego_input` 9 → 10 keys

**Files:**
- Modify: `src/cognic_agentos/core/scheduler/policy.py` (`:208-250` `_build_rego_input`)
- Test: `tests/unit/core/scheduler/test_policy.py`

- [ ] **Step 1: Update the failing test** (`test_policy.py::test_build_rego_input_includes_all_spec_keys`, `:274`) to assert the 10-key set + add a threading test:
```python
    def test_build_rego_input_includes_all_spec_keys(self) -> None:
        """10-key contract: the spec §4.8 8-key set + approval_verified (13.5c2)
        + approval_delegated_to (Sprint 14A-A4a, ADR-022/014 — ALWAYS threaded,
        nullable)."""
        rego_input = SchedulerPolicy._build_rego_input(_make_submit_input())
        assert set(rego_input.keys()) == {
            "tenant_id",
            "pack_id",
            "actor_subject",
            "class",
            "pack_kind",
            "pack_risk_tier",
            "current_tenant_concurrent_count",
            "requested_estimated_tokens",
            "approval_verified",
            "approval_delegated_to",
        }

    def test_build_rego_input_threads_approval_delegated_to(self) -> None:
        import dataclasses

        assert SchedulerPolicy._build_rego_input(_make_submit_input())["approval_delegated_to"] is None
        delegated = dataclasses.replace(_make_submit_input(), approval_delegated_to="sandbox_admission")
        assert (
            SchedulerPolicy._build_rego_input(delegated)["approval_delegated_to"]
            == "sandbox_admission"
        )
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/core/scheduler/test_policy.py -k "all_spec_keys or approval_delegated_to" -q`
Expected: FAIL — 9-key set lacks `approval_delegated_to`; `KeyError` on the threading test.

- [ ] **Step 3: Implement** — add the 10th key in `_build_rego_input`'s returned dict (after `approval_verified`, `:249`) and **sweep every stale "9-key" / "9th key" mention** in `policy.py` (the `_build_rego_input` docstring at `:211`, plus any module-level or other method docstring): `grep -n "9-key\|9th key\|9 key\|9th" src/cognic_agentos/core/scheduler/policy.py` and update each to "10-key" / "the 10th key (`approval_delegated_to`)":
```python
            "approval_verified": submit_input.approval_verified,
            # Sprint 14A-A4a (ADR-022 + ADR-014): routing/evidence signal — ALWAYS
            # threaded (nullable). The bundle's delegated allow arm reads it
            # strictly (== "sandbox_admission"); None/absent fails closed.
            "approval_delegated_to": submit_input.approval_delegated_to,
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/core/scheduler/test_policy.py -q`
Expected: PASS.

- [ ] **Step 5: Gate ladder (CC module) + HALT for commit token**
```bash
git add src/cognic_agentos/core/scheduler/policy.py tests/unit/core/scheduler/test_policy.py
git commit -m "feat(scheduler): Sprint 14A-A4a T4 — policy threads approval_delegated_to (9->10 rego keys) (ADR-022/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: `scheduler.rego` — allow arm 3 + refusal-arm honesty guard

**Files:**
- Modify: `policies/_default/scheduler.rego` (refusal chain `:97-102`; allow arms after `:125`)
- Test: `tests/unit/policies/test_scheduler_rego.py`

This is the **stop-rule** edit — halt-before-commit, full review. It LOOSENS the bundle (a new way for high-risk to admit), so the ADR amendment (Task 7) is part of the same sprint.

- [ ] **Step 1: Write the failing tests** in `test_scheduler_rego.py`.

First extend the shared input builder `_safe_allow_input` (`:161-189`) to always thread the key (mirrors `approval_verified`):
```python
def _safe_allow_input(
    *,
    pack_risk_tier: str = "internal_write",
    class_: str = "interactive",
    tenant_id: str = "tenant-a",
    pack_id: str = "pack-x",
    actor_subject: str = "svc-a",
    pack_kind: str = "tool",
    requested_estimated_tokens: int = 500,
    current_tenant_concurrent_count: int = 0,
    approval_verified: bool = False,
    approval_delegated_to: str | None = None,
) -> dict[str, Any]:
    return {
        "tenant_id": tenant_id,
        "pack_id": pack_id,
        "actor_subject": actor_subject,
        "class": class_,
        "pack_kind": pack_kind,
        "pack_risk_tier": pack_risk_tier,
        "current_tenant_concurrent_count": current_tenant_concurrent_count,
        "requested_estimated_tokens": requested_estimated_tokens,
        "approval_verified": approval_verified,
        "approval_delegated_to": approval_delegated_to,
    }
```
(Adding the null-default key leaves every existing test's outcome unchanged — `null != "sandbox_admission"`, so high-risk still denies and arms 1/2 are untouched.)

Add an A4a allow + refusal class (use the module's `_HIGH_RISK_TIERS` constant + `@opa_required`):
```python
@opa_required
class TestSchedulerRegoA4aDelegation:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("tier", _HIGH_RISK_TIERS)
    @pytest.mark.parametrize("class_", ["interactive", "background"])
    async def test_delegated_high_risk_admits(self, engine, tier, class_) -> None:
        d = await engine.evaluate(
            decision_point=SCHEDULER_DECISION_POINT_ALLOW,
            input=_safe_allow_input(
                pack_risk_tier=tier, class_=class_, approval_delegated_to="sandbox_admission"
            ),
        )
        assert d.allow is True

    @pytest.mark.asyncio
    @pytest.mark.parametrize("bad", [None, "", "sandbox", "SANDBOX_ADMISSION", "scheduler"])
    async def test_delegated_strict_fail_closed(self, engine, bad) -> None:
        d = await engine.evaluate(
            decision_point=SCHEDULER_DECISION_POINT_ALLOW,
            input=_safe_allow_input(pack_risk_tier="payment_action", approval_delegated_to=bad),
        )
        assert d.allow is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("class_", ["interactive", "background"])
    async def test_delegated_high_risk_absent_key_fails_closed(self, engine, class_) -> None:
        # "Absent fails closed" stop-rule contract: a high-risk input with NO
        # approval_delegated_to key AT ALL (not merely null) must still deny —
        # arm 3 reads it strictly, so a missing key never admits.
        inp = _safe_allow_input(pack_risk_tier="payment_action", class_=class_)
        inp.pop("approval_delegated_to")
        d = await engine.evaluate(decision_point=SCHEDULER_DECISION_POINT_ALLOW, input=inp)
        assert d.allow is False

    @pytest.mark.asyncio
    async def test_delegated_refusal_reason_is_default_deny(self) -> None:
        # The refusal arm is unread on an allow path, but must stay honest: for a
        # class-KNOWN delegated high-risk input the guard SUPPRESSES arm 2, so the
        # deterministic fall-through is EXACTLY scheduler_default_deny. Pinning the
        # exact value proves the guard fired — without it, arm 2 would label this
        # scheduler_high_risk_tier_refused_pre_13_5.
        reason = _opa_eval_string_value(
            _safe_allow_input(pack_risk_tier="payment_action", approval_delegated_to="sandbox_admission"),
            SCHEDULER_DECISION_POINT_REASON,
        )
        assert reason == "scheduler_default_deny"
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/policies/test_scheduler_rego.py -k A4aDelegation -q`
Expected: the RED tests are `test_delegated_high_risk_admits` (denies — no arm 3 yet) and `test_delegated_refusal_reason_is_default_deny` (arm 2 unguarded still returns `scheduler_high_risk_tier_refused_pre_13_5`, not `scheduler_default_deny`). The `test_delegated_strict_fail_closed` + `test_delegated_high_risk_absent_key_fails_closed` cases already PASS pre-impl — they pin denial and stand as regression guards that arm 3's strictness never admits a null/absent/wrong key.

- [ ] **Step 3: Implement** in `policies/_default/scheduler.rego`.

Update the high-risk refusal arm (`:99-102`) — add the delegated guard:
```rego
refusal_reason := "scheduler_class_unknown" if {
	not input.class in _known_classes
} else := "scheduler_high_risk_tier_refused_pre_13_5" if {
	input.pack_risk_tier in _high_risk_tiers
	not input.approval_verified == true
	not input.approval_delegated_to == "sandbox_admission"
} else := "scheduler_default_deny"
```
Add allow arm 3 after arm 2 (`:125`):
```rego
# Allow arm 3 — Sprint 14A-A4a (ADR-022 + ADR-014 amendment): a high-risk tier
# admits when the Python seam attests approval is DELEGATED to the downstream
# sandbox admission gate, which owns the human checkpoint. The scheduler mints no
# grant of its own; approval_verified stays false (honest). STRICT string match —
# absent / null / any other value fails closed (mirrors arm 2's strict ==).
# NORMATIVE setter obligation (A4a spec §3.8): any caller setting this MUST route
# the same work through sandbox admission with the real manifest tier. A4b (the
# managed-run executor) is the only authorized production setter.
allow if {
	input.class in _known_classes
	input.pack_risk_tier in _high_risk_tiers
	input.approval_delegated_to == "sandbox_admission"
}
```

- [ ] **Step 4: Run to verify they pass + no regression**

Run: `uv run pytest tests/unit/policies/test_scheduler_rego.py -q`
Expected: PASS — arm 3 admits; strict denies; refusal honest; the existing 12 high-risk-deny cases + arms 1/2 + the refusal-vocabulary-closed test all still pass.

- [ ] **Step 5: Gate ladder (stop-rule) + HALT for commit token**
```bash
git add policies/_default/scheduler.rego tests/unit/policies/test_scheduler_rego.py
git commit -m "feat(policy): Sprint 14A-A4a T5 — scheduler.rego delegated high-risk allow arm + honest refusal guard (ADR-022/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: `storage.py` — honest accepted-row evidence

**Files:**
- Modify: `src/cognic_agentos/core/scheduler/storage.py` (`_build_record` in `submit()`, after `:275`)
- Test: `tests/unit/core/scheduler/test_storage.py`

- [ ] **Step 1: Write the failing test** (append to `test_storage.py`, mirroring `test_submit_inserts_pending_row_and_genesis_chain_event`):
```python
async def test_submit_records_approval_delegated_to_when_set(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    import dataclasses

    task_id = uuid.uuid4()
    submit = dataclasses.replace(
        _make_submit_input(),
        pack_risk_tier="payment_action",
        approval_delegated_to="sandbox_admission",
    )
    await store.submit(task_id=task_id, submit_input=submit, request_id="req-a4a-1")
    payload = (await _read_latest_chain_row(engine))["payload"]
    assert isinstance(payload, dict)
    assert payload["approval_delegated_to"] == "sandbox_admission"
    assert payload["approval_verified"] is False  # honest: no fake grant
    assert "approval_request_id" not in payload  # no scheduler correlator


async def test_submit_omits_approval_delegated_to_when_none(
    store: SchedulerStorage, engine: AsyncEngine
) -> None:
    task_id = uuid.uuid4()
    await store.submit(task_id=task_id, submit_input=_make_submit_input(), request_id="req-a4a-2")
    payload = (await _read_latest_chain_row(engine))["payload"]
    assert isinstance(payload, dict)
    assert "approval_delegated_to" not in payload
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run pytest tests/unit/core/scheduler/test_storage.py -k approval_delegated_to -q`
Expected: FAIL — `KeyError: 'approval_delegated_to'` (storage doesn't write the key yet).

- [ ] **Step 3: Implement** — in `_build_record` (`submit()`), add the conditional key after the `approval_request_id` block (`:274-275`):
```python
            if submit_input.approval_verified and submit_input.approval_request_id is not None:
                payload["approval_request_id"] = submit_input.approval_request_id
            # Sprint 14A-A4a (ADR-022 + ADR-014): honest delegation evidence —
            # present ONLY when non-None, alongside approval_verified=False and NO
            # scheduler approval_request_id (the sandbox owns the checkpoint).
            if submit_input.approval_delegated_to is not None:
                payload["approval_delegated_to"] = submit_input.approval_delegated_to
```

- [ ] **Step 4: Run to verify it passes**

Run: `uv run pytest tests/unit/core/scheduler/test_storage.py -q`
Expected: PASS.

- [ ] **Step 5: Gate ladder (CC module) + HALT for commit token**
```bash
git add src/cognic_agentos/core/scheduler/storage.py tests/unit/core/scheduler/test_storage.py
git commit -m "feat(scheduler): Sprint 14A-A4a T6 — admission_accepted records approval_delegated_to (honest evidence) (ADR-022/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: ADR-022 + ADR-014 amendments + AGENTS.md patch

**Files:**
- Modify: `docs/adrs/ADR-022-runtime-scheduler.md`, `docs/adrs/ADR-014-runtime-tool-approval.md`, `AGENTS.md`

No code; doc-only. Verify every claim against the landed code (per the verify-citations-at-doc-write rule).

- [ ] **Step 1: Amend ADR-022** — add a "Sprint 14A-A4a amendment" subsection: the `approval_delegated_to` affordance (named `SchedulerApprovalDelegate` signal); the engine skips its Step-3.5 consult and admits high-risk via `scheduler.rego` allow arm 3; honest evidence (`approval_verified=false` + `approval_delegated_to` on the chain row, no scheduler `approval_request_id`); the signal is excluded from the binding digest; **dormant** (A4b is the only setter). Note the **normative setter obligation** (spec §3.8).

- [ ] **Step 2: Amend ADR-014** — add the "approval delegated downstream" routing mode: the scheduler admits while the downstream sandbox admission gate owns the human checkpoint; this is a coordinated kernel + ADR loosening of `scheduler.rego` (allow arm 3); approval is neither minted nor verified at the scheduler on the delegated path.

- [ ] **Step 3: Patch AGENTS.md** — update the `scheduler.rego` stop-rule entry (now **3 allow arms**, the 10th `approval_delegated_to` input key, the `SchedulerApprovalDelegate` enum, the refusal-vocabulary still 3-value/unchanged) and the `core/scheduler/{engine,policy,storage}.py` CC entries (the `SchedulerSubmitInputInvalidField` 2→3 growth + the `SchedulerApprovalDelegate` 1-value enum + the dormant-affordance posture). Patch present-tense operating-model claims per the active-model doctrine; do NOT bump the CC count (stays 131).

- [ ] **Step 4: Verify** — `grep -n "approval_delegated_to\|SchedulerApprovalDelegate\|allow arm 3" docs/adrs/ADR-022-runtime-scheduler.md docs/adrs/ADR-014-runtime-tool-approval.md AGENTS.md` and confirm each prose claim matches the code at the cited file:line.

- [ ] **Step 5: HALT for commit token**
```bash
git add docs/adrs/ADR-022-runtime-scheduler.md docs/adrs/ADR-014-runtime-tool-approval.md AGENTS.md
git commit -m "docs(adr): Sprint 14A-A4a — ADR-022/014 delegation amendment + AGENTS.md scheduler stop-rule patch" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Closeout — CC coverage on fresh data + full gate ladder

**Files:** none (verification only)

- [ ] **Step 1: Full suite (clean record run)**

Run: `uv run pytest tests/unit -q`
Expected: all pass, 0 failures. (Re-run once on a clean record if any flake appears — no remote action on a nonzero run.)

- [ ] **Step 2: CC coverage on fresh `--cov-branch` data**

Run: `uv run coverage run --branch -m pytest tests/unit` → `uv run coverage json -o coverage.json` → `uv run python tools/check_critical_coverage.py`
Expected: PASS — `engine.py` / `policy.py` / `storage.py` at ≥ 95% line / 90% branch with the new branches covered; **CC count 131** (the count-guard self-test green). If any of the three is below floor, add a focused negative-path test in the SAME task and re-run.

- [ ] **Step 3: Lint / format / types (full tree)**

Run: `uv run ruff check .` → `uv run ruff format --check .` → `uv run mypy src tests`
Expected: clean.

- [ ] **Step 4: Architecture fences**

Run: `uv run pytest tests/unit/core/scheduler/test_architecture_no_emergency_import.py tests/unit/core/scheduler/test_architecture_no_sandbox_import.py -q`
Expected: PASS (A4a adds no cross-substrate import).

- [ ] **Step 5: Plan reconciliation + HALT**

`git status --short` (confirm only intended files changed; the two protected docs remain untracked). Produce the final halt summary; the closeout has no commit of its own (Tasks 1-7 carry the changes). Proceed to `finishing-a-development-branch` (push + PR) only on explicit tokens.

---

## Self-Review (against the spec)

**Spec coverage:**
- §3.1 named enum + field → Task 1. ✔
- §3.2 boundary validation + precedence → Task 2. ✔
- §3.3 skip-consult → Task 3. ✔
- §3.4 10-key policy input → Task 4. ✔
- §3.5 rego arm 3 + refusal guard → Task 5. ✔
- §3.6 honest accepted-row evidence → Task 6. ✔
- §3.7 digest exclusion (disposition + behavioral pin) → Task 1. ✔
- §3.8 normative setter obligation → encoded in the ADRs + rego header (Tasks 5, 7). ✔
- §4 components / §6 error handling / §7 testing → Tasks 1-8. ✔
- §8 scope fence (no executor flip / no migration / dormant) → honored (no `executor.py`, no migration in any task). ✔

**Placeholder scan:** every code + test step carries exact code; no "TBD"/"handle edge cases"/"similar to". The one cross-file check (Task 2 `test_engine.py` lockstep) names the exact grep + the exact 3-value set. ✔

**Type consistency:** `SchedulerApprovalDelegate = Literal["sandbox_admission"]`, `approval_delegated_to: SchedulerApprovalDelegate | None`, the rego key `approval_delegated_to`, the digest-excluded bucket `routing_or_evidence`, and `SchedulerSubmitInputInvalidField(field="approval_delegated_to")` are used identically across Tasks 1-8. The `_seam_submit_input` / `_safe_allow_input` / `_make_submit_input` helpers are the real fixtures (verified). ✔
