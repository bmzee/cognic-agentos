# Sprint 14A-A4b — Manifest-Driven High-Risk Managed-Run Path — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Source the trusted manifest risk tier (+ `data_classes`) for a managed run, fail-closed-validate it, thread it into both the scheduler submit and the sandbox `PackAdmissionContext`, and set `approval_delegated_to="sandbox_admission"` — activating A4a so a high-risk run is admitted by the scheduler and pends at the sandbox cold-create human checkpoint (closing the A3c F4 caveat).

**Architecture:** A thin off-gate loader (`harness/sandbox.py`) reads the manifest off the submit chain row and shape-extracts; the on-gate executor (`core/run/executor.py`) owns the fail-closed governance gate (two new `RunRefusalReason`s) and the flip. The local `RiskTier` vocab lives in `executor.py` (drift-pinned). No migration; CC stays 131.

**Tech Stack:** Python 3.12, `uv`, pytest (`asyncio_mode=auto`), SQLAlchemy async (in-memory sqlite unit DB), OPA/Rego (`opa` via `OPAEngine`), the `core/approval` engine, the resumable-session sandbox.

**Spec:** `docs/superpowers/specs/2026-06-17-sprint-14a-a4b-manifest-driven-high-risk-run-design.md`

---

## Execution discipline (project-specific)

- **Commits are controller-owned + token-gated.** Each task's "Commit" step is a HALT: produce a halt summary (watchpoint→pin map + fresh gate evidence; "files modified", not "staged") and wait for the user's explicit full-word commit token. Subagents **implement only** — never `git add`/`git commit`/stage.
- **Gate ladder before every halt:** focused pytest → neighborhood (`tests/unit/core/run tests/unit/harness tests/unit/architecture`) → `uv run ruff check .` → `uv run ruff format --check .` → full-tree `uv run mypy src tests`. Full `tests/unit` suite runs at the commit token (CC/shared modules).
- **CC edits** (`core/run/executor.py`) run `check_critical_coverage` on **fresh `--cov-branch`**: `uv run coverage run --branch -m pytest tests/unit` → `uv run coverage json -o coverage.json` (NOT `--cov-report=json`) → `uv run python tools/check_critical_coverage.py`. **CC count stays 131** — do NOT edit `tools/check_critical_coverage.py`.
- **Never stage** `docs/reviews/` or `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md`.
- Footer: `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Git user `bmzee`. One `uv run` at a time. Branch already exists: `feat/sprint-14a-a4b-manifest-driven-high-risk-run` (spec at `58daa63`).

## File structure

| File | Layer | Responsibility for A4b |
|---|---|---|
| `src/cognic_agentos/core/run/executor.py` | **CC** | Local `RiskTier` + `_CANONICAL_RISK_TIERS`; `RunRefusalReason` 4→6; `LoadedPackRecord` +`risk_tier`/`data_classes`; `_validate_pack_record` +2 fail-closed checks; the `:334`/`:989` flip + the delegation flag. |
| `src/cognic_agentos/harness/sandbox.py` | off-gate | `PackRecordStoreLoader.load_for_run` reads the manifest off the submit chain row and shape-extracts `risk_tier` / `data_classes`. |
| `docs/adrs/ADR-022-runtime-scheduler.md`, `docs/adrs/ADR-004-sandbox-primitive.md`, `docs/adrs/ADR-014-runtime-tool-approval.md`, `AGENTS.md` | docs | A4a is now live-exercised (dormant→active); the run lane resolves the manifest tier fail-closed. |
| `tests/unit/core/run/test_executor.py`, `tests/unit/harness/test_sandbox.py`, `tests/integration/run/test_managed_run_high_risk_e2e.py` | test | The vocab/drift, loader extraction, fail-closed refusals, the flip + threading, the A4a↔A4b OPA integration, the env-gated real-engine e2e. |

**Real test helpers (verified — use these, do NOT invent):** in `tests/unit/core/run/test_executor.py` — fixtures `db` (`:45`, migrated `AsyncEngine`) + `settings` (`:371`, `Settings`); `_executor(db, *, backend, loader, settings, installed=True, checkpoint_store=None, run_record_store=None)` (`:323`); `_make_scheduler(db, *, installed=True)` (`:94`, uses the stub `_allow_policy()`); `_StubBackend` (`:153`, its `create(...)` captures `last_approval_request_id` + `created`); `_StubLoader(record)` (`:248`); `_record(*, ..., risk_tier=..., data_classes=...)` (`:256`, updated in T2); `_request(...)` (`:273`); `select` + `_decision_history` are already imported (used by `_count_lifecycle` at `:344`). In `tests/unit/harness/test_sandbox.py` — `_StubPackRecord(**kw)` (`:50`) + `_StubStore(record)` (`:55`, extended in T2). The real-OPA pattern: `OPAEngine.create(bundle_path=Path("policies/_default/scheduler.rego"), audit_store=, decision_history_store=)` + `SchedulerPolicy(opa_engine=opa_engine)` — copy the `opa_engine` fixture body verbatim from `tests/unit/core/scheduler/test_policy.py:76-102`.

---

### Task 1: `executor.py` — local `RiskTier` vocab + `RunRefusalReason` 4→6 + drift pin

**Files:**
- Modify: `src/cognic_agentos/core/run/executor.py` (`RunRefusalReason` at `:73`)
- Test: `tests/unit/core/run/test_executor.py`

- [ ] **Step 1: Write the failing tests** (append to `test_executor.py`):
```python
def test_run_refusal_reason_has_the_two_a4b_values() -> None:
    import typing
    from cognic_agentos.core.run.executor import RunRefusalReason

    vals = set(typing.get_args(RunRefusalReason))
    assert "pack_record_risk_tier_unresolved" in vals
    assert "pack_record_data_classes_malformed" in vals
    assert len(vals) == 6


def test_run_risk_tier_drift_pinned_to_cli_canonical() -> None:
    import typing
    from cognic_agentos.cli._governance_vocab import RiskTier as CliRiskTier
    from cognic_agentos.core.run.executor import RiskTier as RunRiskTier

    assert set(typing.get_args(RunRiskTier)) == set(typing.get_args(CliRiskTier))
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/core/run/test_executor.py -k "a4b_values or drift_pinned" -q`
Expected: FAIL — `RunRefusalReason` has 4 values; `RiskTier` not importable from `core/run/executor`.

- [ ] **Step 3: Implement** in `executor.py`. Grow `RunRefusalReason` (`:73`) and add the local vocab directly beneath it (confirm `Final`, `Literal`, and `get_args` are imported at the top — add `from typing import get_args` / `Final` if missing):
```python
RunRefusalReason = Literal[
    "pack_record_not_found",
    "pack_record_tenant_mismatch",
    "pack_record_pack_id_mismatch",
    "pack_record_not_installed",
    # Sprint 14A-A4b (ADR-022/004/014) — fail-closed manifest-tier gate:
    "pack_record_risk_tier_unresolved",
    "pack_record_data_classes_malformed",
]

#: Sprint 14A-A4b — local copy of the ADR-014 canonical 8-value risk-tier set
#: (the core/run -> cli architectural arrow forbids importing it; the
#: sandbox/policy.py:28 + packs/conformance/owasp_agentic.py:115 precedent).
#: Drift-pinned test-only against cli._governance_vocab.RiskTier.
RiskTier = Literal[
    "read_only",
    "internal_write",
    "customer_data_read",
    "customer_data_write",
    "payment_action",
    "regulator_communication",
    "cross_tenant",
    "high_risk_custom",
]
_CANONICAL_RISK_TIERS: Final[frozenset[str]] = frozenset(get_args(RiskTier))
```

- [ ] **Step 4: Run to verify they pass**

Run: `uv run pytest tests/unit/core/run/test_executor.py -k "a4b_values or drift_pinned" -q`
Expected: PASS.

- [ ] **Step 5: Gate ladder (CC) + HALT for the commit token**
```bash
git add src/cognic_agentos/core/run/executor.py tests/unit/core/run/test_executor.py
git commit -m "feat(run): Sprint 14A-A4b T1 — local RiskTier vocab + RunRefusalReason 4->6 (ADR-022/004/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: `LoadedPackRecord` +2 fields + the off-gate loader manifest read

**Files:**
- Modify: `src/cognic_agentos/core/run/executor.py` (`LoadedPackRecord` at `:96`)
- Modify: `src/cognic_agentos/harness/sandbox.py` (`PackRecordStoreLoader.load_for_run` at `:42-61`)
- Test: `tests/unit/harness/test_sandbox.py` + the `_record` helper in `tests/unit/core/run/test_executor.py`

- [ ] **Step 1: Extend `_StubStore` + write the failing loader tests** in `tests/unit/harness/test_sandbox.py`. First extend the existing `_StubStore` (`:55`) to add a configurable lifecycle history + a duck-typed submit row, and add a record helper:
```python
class _StubSubmitRow:
    # find_latest_submit_row only reads .decision_type + .payload (pure-functional, no isinstance).
    def __init__(self, manifest: object | None) -> None:
        self.decision_type = "pack.lifecycle.submitted"
        self.payload = {} if manifest is None else {"manifest": manifest}


class _StubStore:  # REPLACES the existing _StubStore at :55 — adds load_lifecycle_history
    def __init__(self, record: Any, *, history: list[Any] | None = None) -> None:
        self._record = record
        self._history = history if history is not None else []
        self.loaded: list[uuid.UUID] = []

    async def load(self, pack_id: uuid.UUID) -> Any:
        self.loaded.append(pack_id)
        return self._record

    async def load_lifecycle_history(self, pack_id: uuid.UUID) -> list[Any]:
        return self._history


def _installed_pack_record() -> _StubPackRecord:
    return _StubPackRecord(
        tenant_id="tenant-a", pack_id="cognic-tool-foo", kind="tool",
        signed_artefact_digest=b"\xab" * 32, state="installed",
    )
```
Update the EXISTING `test_pack_record_store_loader_projects_record` (`:65-84`): its `_StubStore(rec)` now has an empty history → no submit manifest → `risk_tier=None` / `data_classes=()`. Change its expected `LoadedPackRecord(...)` to add `risk_tier=None, data_classes=()`. Then add the new tests:
```python
async def test_loader_extracts_high_risk_tier_and_data_classes() -> None:
    manifest = {"risk_tier": {"tier": "customer_data_read"},
                "data_governance": {"data_classes": ["customer_pii", "payment_action"]}}
    store = _StubStore(_installed_pack_record(), history=[_StubSubmitRow(manifest)])
    rec = await PackRecordStoreLoader(store=store).load_for_run(pack_uuid=uuid.uuid4())  # type: ignore[arg-type]
    assert rec is not None
    assert rec.risk_tier == "customer_data_read"
    assert rec.data_classes == ("customer_pii", "payment_action")


async def test_loader_absent_data_classes_is_empty_tuple() -> None:
    manifest = {"risk_tier": {"tier": "internal_write"}}  # no data_governance block
    store = _StubStore(_installed_pack_record(), history=[_StubSubmitRow(manifest)])
    rec = await PackRecordStoreLoader(store=store).load_for_run(pack_uuid=uuid.uuid4())  # type: ignore[arg-type]
    assert rec.risk_tier == "internal_write"
    assert rec.data_classes == ()  # absent -> () (NOT the None malformed sentinel)


async def test_loader_malformed_data_classes_is_none_sentinel() -> None:
    manifest = {"risk_tier": {"tier": "internal_write"},
                "data_governance": {"data_classes": "customer_pii"}}  # str, not a list
    store = _StubStore(_installed_pack_record(), history=[_StubSubmitRow(manifest)])
    rec = await PackRecordStoreLoader(store=store).load_for_run(pack_uuid=uuid.uuid4())  # type: ignore[arg-type]
    assert rec.data_classes is None  # malformed sentinel


async def test_loader_no_submit_manifest_yields_none_tier() -> None:
    store = _StubStore(_installed_pack_record(), history=[_StubSubmitRow(None)])  # submit row, no manifest
    rec = await PackRecordStoreLoader(store=store).load_for_run(pack_uuid=uuid.uuid4())  # type: ignore[arg-type]
    assert rec.risk_tier is None  # unresolved -> the executor refuses (T3)
    assert rec.data_classes == ()
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/harness/test_sandbox.py -q`
Expected: FAIL — `LoadedPackRecord` has no `risk_tier`/`data_classes`; the loader does not call `load_lifecycle_history`.

- [ ] **Step 3a: Implement the `LoadedPackRecord` fields** (`executor.py:96`). Add after `state`:
```python
    state: str
    # Sprint 14A-A4b — the trusted manifest risk tier (str = raw extracted value;
    # None = unresolved/absent/non-string — the executor refuses). The executor
    # validates membership in _CANONICAL_RISK_TIERS (the fail-closed gate, T3).
    risk_tier: str | None
    # Sprint 14A-A4b — manifest [data_governance].data_classes, shape-resolved by
    # the loader: () = absent/empty; (str, ...) = valid; None = present-but-malformed
    # (the executor refuses on None).
    data_classes: tuple[str, ...] | None
```

- [ ] **Step 3b: Implement the loader** (`harness/sandbox.py`, `load_for_run`):
```python
    async def load_for_run(self, *, pack_uuid: uuid.UUID) -> LoadedPackRecord | None:
        from cognic_agentos.packs._lifecycle_helpers import find_latest_submit_row

        record = await self._store.load(pack_uuid)
        if record is None:
            return None
        history = await self._store.load_lifecycle_history(pack_uuid)
        submit_row = find_latest_submit_row(history)
        raw_manifest = submit_row.payload.get("manifest") if submit_row is not None else None
        manifest = raw_manifest if isinstance(raw_manifest, dict) else {}
        rt_block = manifest.get("risk_tier")
        rt_block = rt_block if isinstance(rt_block, dict) else {}
        raw_tier = rt_block.get("tier")
        risk_tier: str | None = raw_tier if isinstance(raw_tier, str) else None
        dg_block = manifest.get("data_governance")
        dg_block = dg_block if isinstance(dg_block, dict) else {}
        raw_dc = dg_block.get("data_classes")
        data_classes: tuple[str, ...] | None
        if raw_dc is None:
            data_classes = ()
        elif isinstance(raw_dc, (list, tuple)) and all(isinstance(x, str) for x in raw_dc):
            data_classes = tuple(raw_dc)
        else:
            data_classes = None
        return LoadedPackRecord(
            tenant_id=record.tenant_id,
            pack_id=record.pack_id,
            kind=record.kind,
            signed_artefact_digest=record.signed_artefact_digest,
            state=record.state,
            risk_tier=risk_tier,
            data_classes=data_classes,
        )
```

- [ ] **Step 3c: Update the `_record` test helper** (`test_executor.py:256-270`) — add the two fields, defaulting to a valid tier + `()` so the existing tests stay green through T3:
```python
def _record(
    *,
    tenant_id: str | None = "tenant-a",
    pack_id: str = "cognic-tool-foo",
    kind: str = "tool",
    signed_artefact_digest: bytes = b"\xab" * 32,
    state: str = "installed",
    risk_tier: str | None = "read_only",
    data_classes: tuple[str, ...] | None = (),
) -> LoadedPackRecord:
    return LoadedPackRecord(
        tenant_id=tenant_id,
        pack_id=pack_id,
        kind=kind,
        signed_artefact_digest=signed_artefact_digest,
        state=state,
        risk_tier=risk_tier,
        data_classes=data_classes,
    )
```

- [ ] **Step 4: Run to verify they pass + no regression**

Run: `uv run pytest tests/unit/harness/test_sandbox.py tests/unit/core/run/test_executor.py -q`
Expected: PASS (the loader tests + every existing executor test — the `_record` default keeps them green; the fields are populated but not yet consumed).

- [ ] **Step 5: Gate ladder + HALT for the commit token**
```bash
git add src/cognic_agentos/core/run/executor.py src/cognic_agentos/harness/sandbox.py tests/unit/harness/test_sandbox.py tests/unit/core/run/test_executor.py
git commit -m "feat(run): Sprint 14A-A4b T2 — LoadedPackRecord risk_tier/data_classes + loader manifest read (ADR-022/004)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: `_validate_pack_record` — the two fail-closed checks (I1 + F2)

**Files:**
- Modify: `src/cognic_agentos/core/run/executor.py` (`_validate_pack_record` at `:165`)
- Test: `tests/unit/core/run/test_executor.py`

- [ ] **Step 1: Write the failing tests** (append; module-level async functions taking the `db`/`settings` fixtures, mirroring the existing refusal tests, e.g. `:542`):
```python
async def test_a4b_unresolved_tier_refuses_never_read_only(db: AsyncEngine, settings: Settings) -> None:
    ex = _executor(db, backend=_StubBackend(), loader=_StubLoader(_record(risk_tier=None)), settings=settings)
    result = await ex.run(_request())
    assert result.terminal_state == "refused"
    assert result.refusal_reason == "pack_record_risk_tier_unresolved"


async def test_a4b_unknown_tier_refuses(db: AsyncEngine, settings: Settings) -> None:
    ex = _executor(
        db, backend=_StubBackend(), loader=_StubLoader(_record(risk_tier="legacy_unknown")), settings=settings
    )
    result = await ex.run(_request())
    assert result.refusal_reason == "pack_record_risk_tier_unresolved"


async def test_a4b_malformed_data_classes_refuses_sibling(db: AsyncEngine, settings: Settings) -> None:
    ex = _executor(
        db, backend=_StubBackend(),
        loader=_StubLoader(_record(risk_tier="read_only", data_classes=None)), settings=settings,
    )
    result = await ex.run(_request())
    assert result.refusal_reason == "pack_record_data_classes_malformed"


async def test_a4b_absent_data_classes_is_not_a_refusal(db: AsyncEngine, settings: Settings) -> None:
    ex = _executor(
        db, backend=_StubBackend(),
        loader=_StubLoader(_record(risk_tier="read_only", data_classes=())), settings=settings,
    )
    result = await ex.run(_request())
    assert result.refusal_reason not in (
        "pack_record_risk_tier_unresolved", "pack_record_data_classes_malformed",
    )


async def test_a4b_tier_check_precedes_data_classes(db: AsyncEngine, settings: Settings) -> None:
    ex = _executor(
        db, backend=_StubBackend(),
        loader=_StubLoader(_record(risk_tier=None, data_classes=None)), settings=settings,
    )
    result = await ex.run(_request())
    assert result.refusal_reason == "pack_record_risk_tier_unresolved"  # tier is the primary gate
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/core/run/test_executor.py -k a4b -q`
Expected: FAIL — the executor does not yet validate the tier/data_classes.

- [ ] **Step 3: Implement** — add the two checks at the end of `_validate_pack_record` (`:165`), AFTER the `installed` check, tier first:
```python
    if record.state != "installed":
        return "pack_record_not_installed"
    # Sprint 14A-A4b (I1) — fail-closed manifest tier: None (unresolved) or a
    # non-canonical value refuses; NEVER a silent downgrade to read_only.
    if record.risk_tier not in _CANONICAL_RISK_TIERS:
        return "pack_record_risk_tier_unresolved"
    # Sprint 14A-A4b (F2) — data_classes shape: the loader's None sentinel means
    # present-but-malformed; () (absent/empty) is legitimate and proceeds.
    if record.data_classes is None:
        return "pack_record_data_classes_malformed"
    return None
```

- [ ] **Step 4: Run to verify they pass + no regression**

Run: `uv run pytest tests/unit/core/run/test_executor.py -q`
Expected: PASS (the new refusals + every existing test — the `_record` default `risk_tier="read_only"` / `data_classes=()` passes the gate).

- [ ] **Step 5: Gate ladder (CC) + CC coverage spot-check + HALT**

Run the ladder; `uv run pytest tests/unit/core/run --cov=cognic_agentos.core.run.executor --cov-branch -q` to confirm the new branches are hit. On the token:
```bash
git add src/cognic_agentos/core/run/executor.py tests/unit/core/run/test_executor.py
git commit -m "feat(run): Sprint 14A-A4b T3 — fail-closed manifest-tier + data_classes gate (ADR-022/004/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: The flip — thread the real tier + `data_classes` + the delegation flag (I2)

**Files:**
- Modify: `src/cognic_agentos/core/run/executor.py` (`SubmitInput` build `:328-336`; `_build_pack_context` `:985-992`)
- Test: `tests/unit/core/run/test_executor.py` (extend `_StubBackend` to capture `pack_context`; add the threading test + the OPA arm-3 integration test)

- [ ] **Step 1: Write the failing tests.** Three concrete edits to `test_executor.py`, all using REAL helpers (every name verified to exist):

  **(a) Extend `_StubBackend` (`:153`) to capture the `pack_context`** — in `__init__` add `self.created_contexts: list[Any] = []`; in `create(...)` (`:180`) add `self.created_contexts.append(pack_context)` as the first statement of the body (before `self.last_approval_request_id = approval_request_id`).

  **(b) Add an optional `scheduler` param to the existing `_executor` helper (`:323`)** so the OPA test injects a real-rego scheduler — every current call site is unchanged (the param defaults to `_make_scheduler`):
```python
def _executor(
    db: AsyncEngine,
    *,
    backend: _StubBackend,
    loader: _StubLoader,
    installed: bool = True,
    settings: Settings,
    checkpoint_store: _StubCheckpointStore | None = None,
    run_record_store: RunRecordStore | None = None,
    scheduler: SchedulerEngine | None = None,  # A4b — OPA-integration test injects a real-rego scheduler
) -> ManagedRunExecutor:
    return ManagedRunExecutor(
        scheduler=scheduler if scheduler is not None else _make_scheduler(db, installed=installed),
        sandbox_backend=backend,  # type: ignore[arg-type]
        pack_loader=loader,
        decision_history_store=DecisionHistoryStore(db),
        settings=settings,
        run_record_store=run_record_store or RunRecordStore(db),
        checkpoint_store=checkpoint_store or _StubCheckpointStore(),  # type: ignore[arg-type]
    )
```

  **(c) Add the two tests.** The threading test reuses the EXISTING `_latest_payload(db, decision_type)` helper (`:357` — returns the newest chain payload as a dict). Confirmed real keys: `scheduler.admission_accepted` always carries `payload["pack_risk_tier"]` (`storage.py:264`) and carries `payload["approval_delegated_to"]` only when non-None (`storage.py:279-280`):
```python
async def test_a4b_threads_real_tier_data_classes_and_delegation(
    db: AsyncEngine, settings: Settings
) -> None:
    rec = _record(risk_tier="customer_data_read", data_classes=("customer_pii",))
    backend = _StubBackend()
    ex = _executor(db, backend=backend, loader=_StubLoader(rec), settings=settings)
    await ex.run(_request())
    # Sandbox side — the PackAdmissionContext the backend received (direct object assert):
    ctx = backend.created_contexts[0]
    assert ctx.risk_tier == "customer_data_read"
    assert ctx.data_classes == ("customer_pii",)
    # Scheduler side — the honest admission_accepted chain row (A4a evidence; I2):
    accepted = await _latest_payload(db, "scheduler.admission_accepted")
    assert accepted["pack_risk_tier"] == "customer_data_read"
    assert accepted["approval_delegated_to"] == "sandbox_admission"
```
The OPA integration test proves the executor's delegated-high-risk `SubmitInput` is admitted by the REAL `scheduler.rego` arm 3 (catches executor→`SchedulerPolicy` projection drift). Add at module scope (mirror `test_policy.py:66`): `import shutil` + `opa_required = pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not installed")`; and the imports `from cognic_agentos.core.audit import AuditStore`, `from cognic_agentos.core.policy.engine import OPAEngine`, `from cognic_agentos.core.scheduler.policy import SchedulerPolicy` (`Path` + `select` + `_decision_history` + `SchedulerEngine`/`SchedulerStorage`/`ConcurrencyCaps` are already imported). The `db` fixture already seeds the `audit_event` + `decision_history` chain heads, so `OPAEngine.create` builds over it directly (mirror `test_policy.py:76-102`):
```python
@opa_required
async def test_a4b_delegated_high_risk_admitted_by_real_rego_arm3(
    db: AsyncEngine, settings: Settings
) -> None:
    opa_engine = await OPAEngine.create(
        bundle_path=Path("policies/_default/scheduler.rego"),
        audit_store=AuditStore(db),
        decision_history_store=DecisionHistoryStore(db),
    )
    policy = SchedulerPolicy(opa_engine=opa_engine)
    scheduler = SchedulerEngine(
        storage=SchedulerStorage(db),
        caps=ConcurrencyCaps(
            per_tenant_interactive=4, per_tenant_background=4, per_pack=4, per_actor=4
        ),
        class_settings={"interactive": (4, 5.0), "background": (4, 5.0)},
        quota_interrogator=_StubQuota(),
        kill_switch_interrogator=_StubKill(),
        pack_state_interrogator=_StubPackState(installed=True),
        policy_evaluator=policy.evaluate,
    )
    backend = _StubBackend()
    ex = _executor(
        db,
        backend=backend,
        loader=_StubLoader(_record(risk_tier="customer_data_read")),
        settings=settings,
        scheduler=scheduler,
    )
    await ex.run(_request())
    # real rego arm 3 admitted the delegated high-risk submit -> the backend was reached:
    assert len(backend.created) == 1
```
Finally `grep -n 'pack_risk_tier' tests/unit/core/run/test_executor.py`: the only pre-A4b mention of a scheduler-seen tier is the `_submit_input` helper default (`:305`, NOT on the run path) — no existing test asserts the executor forced `read_only`, so none needs changing; the `_record()` default `risk_tier="read_only"` keeps every existing run test green.

- [ ] **Step 2: Run to verify they fail**

Run: `uv run pytest tests/unit/core/run/test_executor.py -k "threads_real_tier or admitted_by_real_rego" -q`
Expected: FAIL — the executor still hardcodes `read_only`, sets no `approval_delegated_to`/`data_classes`, and `_StubBackend` has no `created_contexts`.

- [ ] **Step 3: Implement the flip.** SubmitInput build (`:328-336`) — replace the `pack_risk_tier` line + add two fields (T3's validation guarantees `record.risk_tier`/`record.data_classes` are sound):
```python
        submit_input = SubmitInput(
            tenant_id=request.tenant_id,
            pack_id=request.pack_id,
            actor=task_actor,
            class_="interactive",
            pack_kind=record.kind,
            pack_risk_tier=record.risk_tier,          # validated canonical (T3); SubmitInput.pack_risk_tier is str
            requested_estimated_tokens=_DEFAULT_ESTIMATED_TOKENS,
            data_classes=record.data_classes or (),   # validated non-None (T3)
            approval_delegated_to="sandbox_admission", # activates A4a arm 3
        )
```
`_build_pack_context` (`:985-992`) — thread the tier (cast to the sandbox `RiskTier`) + `data_classes` (extend the existing function-local import line):
```python
    def _build_pack_context(self, record, request):
        from typing import cast
        from cognic_agentos.sandbox.policy import PackAdmissionContext, RiskTier

        return PackAdmissionContext(
            pack_id=request.pack_id,
            pack_version=request.pack_version,
            pack_artifact_digest=record.signed_artefact_digest.hex(),
            risk_tier=cast(RiskTier, record.risk_tier),  # validated canonical (T3)
            data_classes=record.data_classes or (),
            declares_dynamic_install=False,
            profile="production",
        )
```

- [ ] **Step 4: Run to verify they pass + no regression**

Run: `uv run pytest tests/unit/core/run/test_executor.py -q`
Expected: PASS. If any env-gated integration fixture (`tests/integration/run/test_managed_run_e2e.py`) installs a pack with **no** manifest tier, give its fixture pack a `read_only` `[risk_tier]` manifest so it stays green under `COGNIC_RUN_DOCKER_SANDBOX=1` (no effect on normal CI — those tests skip).

- [ ] **Step 5: Gate ladder (CC) + HALT for the commit token**
```bash
git add src/cognic_agentos/core/run/executor.py tests/unit/core/run/test_executor.py
git commit -m "feat(run): Sprint 14A-A4b T4 — thread manifest tier + data_classes + delegation flag (activates A4a) (ADR-022/004/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: The F5 env-gated real-engine high-risk e2e

**Files:**
- Create: `tests/integration/run/test_managed_run_high_risk_e2e.py`

- [ ] **Step 1: Write the e2e by copying the A3c e2e + enumerated diffs.** Start from the VERIFIED A3c real-docker e2e `tests/integration/run/test_managed_run_resume_approval_e2e.py` — copy it to `tests/integration/run/test_managed_run_high_risk_e2e.py`, then apply EXACTLY these diffs. Every signature below is verified against the named module (no "read it later" delegation). Add these imports to the opt-in block (alongside the existing A3c imports): `from cognic_agentos.core.approval.engine import ApprovalEngine`, `from cognic_agentos.core.approval.policy import ApprovalPolicy`, `from cognic_agentos.core.approval.storage import ApprovalRequestStore`, `from cognic_agentos.core.approval._types import ApprovalActor`, `from cognic_agentos.core.policy.engine import OPAEngine`, `from cognic_agentos.core.decision_history import DecisionRecord` (the A3c file already imports `AuditStore`, `DecisionHistoryStore`, `_decision_history`, `UTC`, `datetime`, `Settings`, `Actor`, `select`, `uuid`).

  1. **Keep the module-level env-gate preamble verbatim** (`:87-97`): the module skips unless `COGNIC_RUN_DOCKER_SANDBOX=1`; the opt-in path uses plain imports (NOT `importorskip`). Keep the docker-reachability + image-present fail-loud preconditions (`:278-288`) and the schema + chain-heads seed (`:292-302`).

  2. **Seed an installed HIGH-RISK pack WITH a manifest submit row.** The A3c seed is a bare `_packs.insert(...state="installed"...)` (`:303-319`) with NO submit chain row — insufficient for A4b because the loader reads the tier off `find_latest_submit_row(load_lifecycle_history(...))`. KEEP the `_packs.insert(...)`, and ADDITIONALLY append a `pack.lifecycle.submitted` chain row. Verified contract: `PackRecordStore.load_lifecycle_history(pack_uuid)` selects `event_type LIKE 'pack.lifecycle.%'` then client-side-filters `payload["pack_id"] == str(pack_uuid)` (`packs/storage.py`), and `find_latest_submit_row` (`packs/_lifecycle_helpers.py:49`) matches `decision_type == "pack.lifecycle.submitted"`. So the `payload["pack_id"]` MUST be `str(pack_uuid)` (the UUID, NOT the human `_PACK_ID`). Append it AFTER the `async with engine.begin()` seed block (so the chain-head rows exist), right after `dh_store = DecisionHistoryStore(engine)` is bound (A3c `:321`) — `DecisionHistoryStore.append` (`decision_history.py:361`, takes a `DecisionRecord` positionally) opens its own transaction:
```python
await dh_store.append(
    DecisionRecord(
        decision_type="pack.lifecycle.submitted",
        request_id="a4b-high-risk-submit",
        tenant_id=_TENANT,
        actor_id="svc-a",
        payload={
            "pack_id": str(pack_uuid),
            "manifest": {
                "risk_tier": {"tier": "customer_data_read"},
                "data_governance": {"data_classes": ["customer_pii"]},
            },
        },
    )
)
```

  3. **Drop the conformer; wire a REAL `ApprovalEngine`.** DELETE `_PendingThenGrantApprovalEngine` + the `_Conformer*` dataclasses (`:164-252`) and their docstring block. No call-count trick is needed — the A3c conformer existed ONLY because `read_only` auto-tiers; `customer_data_read` classifies to `require_single_approval` in `tools.rego` (`_single_tiers := {"customer_data_read", "customer_data_write"}`), so it genuinely pends + completes on a SINGLE grant. Bind a named `audit_store` (the A3c file builds `AuditStore(engine)` inline at `:343` — extract it to a local) and construct the real engine. Verified signatures: `OPAEngine.create` (`policy/engine.py:239`, kwargs `bundle_path`/`audit_store`/`decision_history_store`/`opa_path`/`eval_timeout_s`); `ApprovalPolicy(*, opa_engine)` (`policy.py:45`); `ApprovalRequestStore(history)` positional (`storage.py:253`); `ApprovalEngine.__init__` keyword-only `policy`/`store`/`settings`/`clock` (`engine.py:101`); Settings fields `tools_policy_bundle`/`opa_path`/`opa_eval_timeout_s` (`config.py:1980`/`883`/`891`):
```python
audit_store = AuditStore(engine)  # extract the local the A3c e2e built inline at :343
approval_opa = await OPAEngine.create(
    bundle_path=settings.tools_policy_bundle,
    audit_store=audit_store,
    decision_history_store=dh_store,
    opa_path=settings.opa_path,
    eval_timeout_s=settings.opa_eval_timeout_s,
)
approval_engine = ApprovalEngine(
    policy=ApprovalPolicy(opa_engine=approval_opa),
    store=ApprovalRequestStore(dh_store),
    settings=settings,
    clock=lambda: datetime.now(UTC),
)
```
Thread `approval_engine=approval_engine` into the `DockerSiblingSandboxBackend(...)` constructor (the SAME slot the conformer occupied at `:380`) and DROP the `# type: ignore[arg-type]` (a real `ApprovalEngine` now, not a duck-typed double). NOTE: this e2e needs `opa` installed (the real `ApprovalPolicy.classify` runs `opa eval`) — already true under the operator-provisioned `COGNIC_RUN_DOCKER_SANDBOX=1` environment.

  4. **Keep the backend + executor construction otherwise verbatim** — the real `DockerSiblingSandboxBackend` with stubbed catalog/rego (`:356-381`) and the `ManagedRunExecutor` (`:383-394`), changing ONLY the `approval_engine=` argument per (3).

  5. **The flow is COLD-CREATE pend (NOT suspend→wake).** Replace the A3c suspend/resume body (`:400-510`) with the genuine pend→grant→re-POST cycle below. The re-POST is a FRESH `run()` (new `run_id`; the `approval_request_id` correlates the GRANT, not the run — do NOT assert run_id equality, unlike the A3c wake path which reused the suspended run). `ApprovalEngine.grant` (`engine.py:183`) is keyword-only with `request_id: uuid.UUID`, and `RunResult.approval_request_id` is a `str` → wrap `uuid.UUID(...)`. `_TIER_GRANT_SCOPE["customer_data_read"] == "tool.approve.customer_data"` (verified at `engine.py`):
```python
actor = Actor(subject="svc-a", tenant_id=_TENANT, scopes=frozenset(), actor_type="service")

# 1) cold-create high-risk run -> GENUINE Arm-A pend under the real engine
#    (the production POST /api/v1/runs path; NO suspend_after_exec, NO stub, NO bypass).
pending = await executor.run(
    RunRequest(
        tenant_id=_TENANT, pack_id=_PACK_ID, pack_uuid=pack_uuid,
        pack_version="1.0.0", argv=("printf", "cognic-14a-a4b"), actor=actor,
    )
)
assert pending.terminal_state == "pending_approval", pending
assert pending.approval_request_id is not None

# 2) out-of-band human grant (the portal approval in production). single-approval
#    tier -> one grant() -> granted; approver is a DISTINCT human holding the tier scope.
await approval_engine.grant(
    request_id=uuid.UUID(pending.approval_request_id),
    tenant_id=_TENANT,
    approver=ApprovalActor(
        subject="rev@bank.example",
        tenant_id=_TENANT,
        scopes=frozenset({"tool.approve.customer_data"}),
        actor_type="human",
    ),
)

# 3) re-POST carrying the granted id -> cold-create admit Arm-B verify -> execute -> completed.
completed = await executor.run(
    RunRequest(
        tenant_id=_TENANT, pack_id=_PACK_ID, pack_uuid=pack_uuid,
        pack_version="1.0.0", argv=("printf", "cognic-14a-a4b"), actor=actor,
        approval_request_id=uuid.UUID(pending.approval_request_id),
    )
)
assert completed.terminal_state == "completed", completed
assert completed.exit_code == 0

# 4) both run-evidence rows exist (cold-create pend + the granted completion).
async with engine.connect() as conn:
    types = [
        r[0]
        for r in (
            await conn.execute(
                select(_decision_history.c.event_type).order_by(_decision_history.c.sequence)
            )
        ).all()
    ]
assert "run.pending_approval" in types, types
assert "run.completed" in types, types
```
(Rationale: A4b's headline is the cold-create high-risk pend closing F4; the suspend→wake mechanics are already proven by the A3c conformer e2e — no need to re-prove them here.)

- [ ] **Step 2: Verify the gate behavior**

Run: `uv run pytest tests/integration/run/test_managed_run_high_risk_e2e.py -q`
Expected: SKIPPED (no `COGNIC_RUN_DOCKER_SANDBOX`). The module-level `pytest.skip(..., allow_module_level=True)` IS the gate-wiring proof (same as the A3c e2e — which has no separate contract test); `pytest --collect-only -q` on the file should report it collected-then-skipped, confirming the import-doctrine preamble keeps the kernel image clean.

- [ ] **Step 3: Gate ladder + HALT for the commit token**
```bash
git add tests/integration/run/test_managed_run_high_risk_e2e.py
git commit -m "test(run): Sprint 14A-A4b T5 — env-gated real-engine high-risk run e2e (no route shortcut) (ADR-022/004/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Docs — A4a dormant→live-exercised

**Files:**
- Modify: `docs/adrs/ADR-022-runtime-scheduler.md`, `docs/adrs/ADR-004-sandbox-primitive.md`, `docs/adrs/ADR-014-runtime-tool-approval.md`, `AGENTS.md`

- [ ] **Step 1: Amend the ADRs** — a `## Sprint 14A-A4b amendment` section in each: A4a's `approval_delegated_to` is now **live-exercised** (the managed-run executor is the production setter); the run lane resolves the manifest tier fail-closed (`pack_record_risk_tier_unresolved` / `pack_record_data_classes_malformed`, never `read_only`); the sandbox cold-create now pends on the real tier (Arm A → 202 → grant → re-POST), closing the A3c F4 caveat; the A3c wake re-admits against the persisted checkpoint `PackAdmissionContext` (no wake-code/schema change); CC 131, no migration.

- [ ] **Step 2: Patch AGENTS.md** — update the `core/run/executor.py` CC entry (the local `RiskTier`, `RunRefusalReason` 4→6, the fail-closed manifest-tier gate, the flip + delegation activation) and patch any present-tense "A4a is dormant / not live-exercised / `read_only` run shape" forward-claims to the active posture (the active-model doctrine; ADRs amend-by-addition). Do NOT bump the CC count.

- [ ] **Step 3: Verify citations** — `grep -n "approval_delegated_to\|pack_record_risk_tier_unresolved\|live-exercised" docs/adrs/ADR-022-runtime-scheduler.md docs/adrs/ADR-004-sandbox-primitive.md docs/adrs/ADR-014-runtime-tool-approval.md AGENTS.md` and confirm each claim matches the landed code.

- [ ] **Step 4: HALT for the commit token**
```bash
git add docs/adrs/ADR-022-runtime-scheduler.md docs/adrs/ADR-004-sandbox-primitive.md docs/adrs/ADR-014-runtime-tool-approval.md AGENTS.md
git commit -m "docs(adr): Sprint 14A-A4b — A4a live-exercised; manifest-driven high-risk run lane (ADR-022/004/014)" -m "Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Closeout — full-suite + `check_critical_coverage` + gate ladder

**Files:** none (verification only)

- [ ] **Step 1: Full suite (clean record)** — `uv run pytest tests/unit -q` → all pass (re-run once on a clean record on any flake before remote actions).
- [ ] **Step 2: CC coverage on fresh `--cov-branch`** — `uv run coverage run --branch -m pytest tests/unit` → `uv run coverage json -o coverage.json` → `uv run python tools/check_critical_coverage.py`. Expected: PASS — `core/run/executor.py` ≥ 95/90 with the new branches covered; **131 PASS / 0 FAIL**.
- [ ] **Step 3: Lint / format / types (full tree)** — `uv run ruff check .` → `uv run ruff format --check .` → `uv run mypy src tests`.
- [ ] **Step 4: Architecture fences** — `uv run pytest tests/unit/architecture -q` (the `core/run` → no-`packs`/`cli` import fence still holds; the loader's `find_latest_submit_row` import is in off-gate `harness/sandbox.py`, not `core/run`).
- [ ] **Step 5: Plan reconciliation + HALT** — `git status --short` (only intended files; the two protected docs untracked). The closeout has no commit of its own. Proceed to `finishing-a-development-branch` (push + PR) only on explicit tokens.

---

## Self-Review (against the spec)

**Spec coverage:** §2 forks → F1 (T2 thin loader / T3 executor gate), F2 (T2 fields + extraction / T3 data_classes refusal / T4 threading), F3 (T1 local RiskTier + drift), F4 (T2 loader per-run history read), F5 (T5 e2e). §3 components → T1–T4 (executor) + T2 (loader) + T6 (docs). §5 failure modes → T3 (refusals) + T2 (loader absent/malformed/None resolution). §6 watchpoints → no DLP (T2/T3 shape only), tier-is-the-gate (T3 order + T4 flip). §7 testing → T1 (drift), T2 (loader), T3 (refusals), T4 (threading + real-OPA arm-3), T5 (e2e). ✔

**Placeholder scan:** every unit task (T1–T4) ships concrete, real-helper code — all names verified to exist: the `db`/`settings` fixtures + `_executor(:323)` (extended with an optional `scheduler=` param, every current call site unchanged) + `_make_scheduler(:94)` + `_StubBackend(:153)` (extended with `created_contexts`) + `_StubLoader(:248)` + `_record(:256)` (extended with `risk_tier`/`data_classes`) + `_request(:273)` + `_latest_payload(:357)` (reused, not invented) + `_StubQuota`/`_StubKill`/`_StubPackState` (`:64-85`); and in `test_sandbox.py` the `_StubStore(:55)` extended with `load_lifecycle_history`. No bare `...`, no `_mk_executor`/`_Capturing*`/`_install_pack_with_manifest`. T5 (the env-gated e2e) is "copy the VERIFIED A3c e2e + 5 enumerated diffs, each citing a real source line", and the formerly-delegated seams are now PINNED with verified signatures read from source: the submit-row `DecisionRecord(...)` direct append (the `payload["pack_id"] == str(pack_uuid)` filter confirmed at `packs/storage.py` `load_lifecycle_history`), the real `ApprovalEngine`/`ApprovalPolicy`/`ApprovalRequestStore`/`OPAEngine.create` construction (signatures confirmed at `engine.py:101`/`policy.py:45`/`storage.py:253`/`policy/engine.py:239`; Settings fields at `config.py:1980`/`883`/`891`), and the `grant(request_id=uuid.UUID(...), approver=ApprovalActor(...))` call (`engine.py:183`; `customer_data_read`→`require_single_approval` per `tools.rego`, scope `tool.approve.customer_data` per `_TIER_GRANT_SCOPE`). Nothing in T5 is "read it later". ✔

**Type consistency:** `RiskTier`/`_CANONICAL_RISK_TIERS`/`RunRefusalReason` (executor.py), `LoadedPackRecord.risk_tier: str | None` / `data_classes: tuple[str, ...] | None`, `()`-vs-`None` data_classes (absent vs malformed), `pack_risk_tier=record.risk_tier` (str) vs `risk_tier=cast(RiskTier, record.risk_tier)` (sandbox Literal), `approval_delegated_to="sandbox_admission"`, and `_StubBackend.created_contexts` are used identically across T1–T6. ✔
