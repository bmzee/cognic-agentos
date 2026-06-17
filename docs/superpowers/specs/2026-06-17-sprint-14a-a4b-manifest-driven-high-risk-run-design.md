# Sprint 14A-A4b — Manifest-Driven High-Risk Managed-Run Path (Design)

**Status:** Design (brainstorm-approved 2026-06-17; pending written spec review)
**ADRs:** ADR-022 (runtime scheduler) + ADR-004 (sandbox) + ADR-014 (runtime tool approval) — referenced; A4b is an activation of A4a's affordance, no new policy loosening.
**CC count:** expected to stay **131** (the on-gate edit is `core/run/executor.py`; the off-gate edit is `harness/sandbox.py`; `core/run/_types.py` is **untouched**; no new gate module). **No migration.**

---

## 1. Goal

A4b is **the activator** for the Sprint-14A-A4a scheduler `approval-delegated-to-sandbox` affordance: it sources the **trusted manifest risk tier** for a managed run, threads it (plus the manifest `data_classes`) into **both** the scheduler submit and the sandbox `PackAdmissionContext`, and sets `approval_delegated_to="sandbox_admission"` so A4a's `scheduler.rego` arm 3 fires. The result: a high-risk managed run is **admitted by the scheduler and pends at the sandbox cold-create human checkpoint** (admission Arm A → `202` → grant → re-POST → run) — closing the **A3c F4 caveat** ("the wake/cold-create approval seam is wired but production `read_only` runs never pend"). It also flips the dormant A4a affordance into a live, production-exercised path.

**Two invariants (pinned to the wall):**
- **(I1) Fail-closed on the tier.** An unresolved or malformed manifest risk tier (no submit row / no `payload["manifest"]` / missing `[risk_tier]` block / non-string / unknown value) **refuses the run** with a typed reason. **Never** a silent downgrade to `read_only` (a security downgrade); **never** a silent treat-as-high-risk. The run proceeds **only** on a positively-resolved, canonical tier.
- **(I2) Evidence honesty end-to-end.** The scheduler row carries the **real** tier + `approval_delegated_to="sandbox_admission"` (no `read_only` lie), and the sandbox `PackAdmissionContext` carries the **same** real tier; neither fabricates a grant. Per the F2 override, the same honesty applies to `data_classes` (thread the manifest-declared classes; don't leave the sandbox approval envelope visibly empty when the manifest gives us the data).

## 2. Locked design decisions (the fork map)

| Fork | Decision |
|---|---|
| **F1 — where the strict resolver lives** | **Thin off-gate loader + on-gate executor gate.** `PackRecordStoreLoader` (`harness/sandbox.py`) extracts the raw manifest values; `core/run/executor.py` (CC) owns the fail-closed validation + the typed `RunRefusalReason`s. `core/run` never imports `packs`/`cli`. |
| **F2 — `LoadedPackRecord` fields** | **`risk_tier` AND `data_classes`** (override). Strict-but-narrow `data_classes` (evidence/context threading only — NOT a DLP sprint). |
| **F3 — canonical tier vocabulary** | **Local `RiskTier` Literal + test-only drift pin** in `core/run/executor.py` (the `sandbox/policy.py:28` / `packs/conformance/owasp_agentic.py:115` precedent). |
| **F4 — submit-history lookup cost** | **Accept one `load_lifecycle_history` + `find_latest_submit_row` read per managed run.** No migration, no materialization. |
| **F5 — production live-proof** | **Env-gated real-docker e2e** with the real route + a **real `ApprovalEngine`** + a **high-risk fixture pack** — no route shortcut (the high-risk shape pends naturally under a real engine; no stub needed). |

## 3. Components

| File | Layer | Change |
|---|---|---|
| `src/cognic_agentos/core/run/executor.py` | **CC** | Local `RiskTier = Literal[...]` (the canonical 8, ADR-014) + `_CANONICAL_RISK_TIERS = frozenset(get_args(RiskTier))`, **beside the existing `RunRefusalReason` at `:73`**; `RunRefusalReason` 4 → 6 (`+pack_record_risk_tier_unresolved`, `+pack_record_data_classes_malformed`); `LoadedPackRecord` (`:96`) gains `risk_tier: str \| None` + `data_classes: tuple[str, ...] \| None`; `_validate_pack_record` (`:165`) gains the two fail-closed checks; the inline `SubmitInput` build (`:334`) + `_build_pack_context` (`:989`) thread `record.risk_tier` / `record.data_classes` and set `approval_delegated_to="sandbox_admission"`. |
| `src/cognic_agentos/core/run/_types.py` | — | **Untouched** — the run-lifecycle types (`RunState` / `validate_transition` / `RunRecord`) need no change; the high-risk run uses the existing states + the A2/A3c `pending_approval` lifecycle. |
| `src/cognic_agentos/harness/sandbox.py` | off-gate | `PackRecordStoreLoader.load_for_run` additionally calls `store.load_lifecycle_history` → `find_latest_submit_row` → `payload["manifest"]`, safe-extracts `risk_tier` (→ `str \| None`) + `data_classes` (→ `tuple \| None`), and projects them onto `LoadedPackRecord`. |
| `docs/adrs/ADR-022/004/014` + `AGENTS.md` | docs | Amendment: A4a is now live-exercised (the dormant→active flip); the run lane resolves the manifest tier fail-closed; CC 131. |
| tests | test | Unit (the 2 refusals, absent-vs-malformed, the threading, the drift pin) + the F5 env-gated e2e. |

### 3.1 `core/run/executor.py` — the local vocab + the two refusals (on-gate)
The local tier vocab lives in `executor.py` next to the existing `RunRefusalReason` (`:73`), matching this file's established convention (the run-gate's vocab is co-located with the gate):
```python
RiskTier = Literal[
    "read_only", "internal_write", "customer_data_read", "customer_data_write",
    "payment_action", "regulator_communication", "cross_tenant", "high_risk_custom",
]
_CANONICAL_RISK_TIERS: Final[frozenset[str]] = frozenset(get_args(RiskTier))
```
`RunRefusalReason` (`executor.py:73`, currently 4 values) gains `"pack_record_risk_tier_unresolved"` (I1) and `"pack_record_data_classes_malformed"` (F2). A test-only drift detector pins `set(get_args(RiskTier)) == set(get_args(cli._governance_vocab.RiskTier))` (no runtime cross-import — the `feedback_drift_detector_test_only_no_runtime_import` doctrine).

### 3.2 `harness/sandbox.py` — the thin extractor (F1)
`load_for_run` keeps the cheap `store.load(pack_uuid)` for the existing 5 fields, then (F4) reads the manifest off the submit chain row and safe-extracts. **It performs shape resolution only — never the governance gate** (that is the executor's job):
```python
record = await self._store.load(pack_uuid)
if record is None:
    return None
history = await self._store.load_lifecycle_history(pack_uuid)
submit_row = find_latest_submit_row(history)               # packs/_lifecycle_helpers
manifest = submit_row.payload.get("manifest") if submit_row else None
manifest = manifest if isinstance(manifest, dict) else {}
# tier: str | None  (None = absent / non-string / no manifest)
rt_block = manifest.get("risk_tier")
rt_block = rt_block if isinstance(rt_block, dict) else {}
raw_tier = rt_block.get("tier")
risk_tier = raw_tier if isinstance(raw_tier, str) else None
# data_classes: tuple[str,...] | None  (() = absent/empty; tuple = valid; None = malformed)
dg_block = manifest.get("data_governance")
dg_block = dg_block if isinstance(dg_block, dict) else {}
raw_dc = dg_block.get("data_classes")
if raw_dc is None:
    data_classes: tuple[str, ...] | None = ()
elif isinstance(raw_dc, (list, tuple)) and all(isinstance(x, str) for x in raw_dc):
    data_classes = tuple(raw_dc)
else:
    data_classes = None   # present-but-malformed sentinel
return LoadedPackRecord(..., risk_tier=risk_tier, data_classes=data_classes)
```
Rationale for the split: the tier has a **value** constraint (∈ canonical 8), so the executor owns the membership gate; `data_classes` has only a **shape** constraint (list of strings), so the loader fully resolves the shape to `tuple | None` and the executor only refuses on the `None` sentinel. Both stay shape-only in the loader; the **refusal decisions** are on-gate.

### 3.3 `core/run/executor.py` — the on-gate fail-closed gate (F1/I1/F2)
`_validate_pack_record` (currently 4 checks: not_found / tenant_mismatch / pack_id_mismatch / not_installed) gains two more, **after** the `installed` check and in tier-before-data_classes order:
```python
    if record.risk_tier not in _CANONICAL_RISK_TIERS:   # None or unknown → refuse (I1)
        return "pack_record_risk_tier_unresolved"
    if record.data_classes is None:                      # malformed sentinel → refuse (F2)
        return "pack_record_data_classes_malformed"
```
On the green path the executor threads the validated values (a `cast(RiskTier, record.risk_tier)` is sound because membership was just checked) into both surfaces, and sets the delegation flag:
- `SubmitInput(..., pack_risk_tier=record.risk_tier, data_classes=record.data_classes, approval_delegated_to="sandbox_admission")` (replaces the `pack_risk_tier="read_only"` at `:334`; `SubmitInput.data_classes` + `approval_delegated_to` are the A4a/13.5c2 fields).
- `PackAdmissionContext(..., risk_tier=record.risk_tier, data_classes=record.data_classes)` (replaces the `risk_tier="read_only"` / defaulted `data_classes=()` at `:989`).

## 4. Data flow (the live high-risk run)

POST `/api/v1/runs` (existing route) → `ManagedRunExecutor.run` → `load_for_run` (cheap load + manifest read, safe-extract) → `_validate_pack_record` (the 6 fail-closed checks; **I1** refuses an unresolved tier here) → submit `SubmitInput(real tier, real data_classes, approval_delegated_to="sandbox_admission")` → **scheduler admits via A4a arm 3** (high-risk + delegated; the scheduler mints no grant, `approval_verified=False`; honest `scheduler.admission_accepted` evidence) → `mark_running` → `backend.create(PackAdmissionContext(real tier, real data_classes))` → **sandbox cold-create `admit_policy` pends** (Arm A under the real `ApprovalEngine`) → `sandbox_approval_pending` → executor maps to **202** + `run.pending_approval` (the A2 contract) → operator grants → re-POST with `approval_request_id` → Arm B verify → run executes → `run.completed`. The A3c **wake** path needs no A4b change: on suspend the checkpoint persists the sandbox `PackAdmissionContext` (which now carries the real tier, because A4b set it at cold-create), and the wake re-admits against that persisted context — so the wake sees the real tier with no A4b wake-code or checkpoint-schema change.

## 5. Error handling / failure modes

| Condition | Result |
|---|---|
| no submit row / no `payload["manifest"]` / missing `[risk_tier]` / non-string / unknown tier value | `pack_record_risk_tier_unresolved` (I1 — refuse; never `read_only`) |
| `data_classes` present but malformed (not a list/tuple, or any non-string element) | `pack_record_data_classes_malformed` (F2 sibling) |
| `data_classes` **absent** (no `[data_governance]` block / no key) | `()` — **NOT a refusal** (the pack legitimately declares no classes) |
| `data_classes` present + well-formed (list/tuple of strings) | coerced to a tuple, threaded to both surfaces |
| tier resolved + canonical | run proceeds; admission is driven **solely** by the tier (A4a arm 3 + the sandbox pend) |

## 6. F2 watchpoints (locked)

1. **Not a DLP sprint.** A4b does **zero** data-governance logic — no tenant-policy diff, no allow-list check, no DLP enforcement, no retention/egress/purpose evaluation. It only **extracts → shape-validates → threads** the manifest-declared classes. The governance machinery (`packs/evidence/data_governance`, the DLP hooks) is untouched. A future `data_classes` governance enrichment is out of scope (call it A4c if ever).
2. **The tier remains THE gate.** `data_classes` **values** never admit or block a run. The only `data_classes` fail-closed point is the **shape** check (malformed → refuse). A well-formed `data_classes`, whatever its values, never gates admission. The fail-closed **tier** rule (I1) is authoritative and unchanged.

## 7. Testing

- **Unit — fail-closed (`tests/unit/core/run/`):** an unresolved tier (None / unknown / no-submit-row / no-manifest / non-string) → `pack_record_risk_tier_unresolved` (NEVER admitted, NEVER `read_only`); a malformed `data_classes` (non-list, list-with-int) → `pack_record_data_classes_malformed`; **absent** `data_classes` → `()` and the run proceeds (not a refusal); the tier-before-data_classes precedence.
- **Unit — threading:** a high-risk fixture record → the executor sets `SubmitInput.pack_risk_tier` + `data_classes` + `approval_delegated_to="sandbox_admission"` and `PackAdmissionContext.risk_tier` + `data_classes` to the real values (assert via a stub scheduler/backend capturing the inputs); a delegated high-risk submit reaches `accepted_immediate` against a REAL `SchedulerPolicy`/OPA (arm 3 fires) — the A4a↔A4b integration pin.
- **Unit — loader (`tests/unit/harness/` or the loader's home):** safe extraction over a migrated DB with a real submit-row manifest; the malformed/absent/valid `data_classes` resolution; an installed pack with no manifest → `risk_tier=None`.
- **Drift pin:** `core/run/executor.py`'s local `RiskTier` == `cli._governance_vocab.RiskTier` (test-only `get_args` equality, no runtime cross-import).
- **Architecture fence:** `core/run` still imports no `packs`/`cli` (the existing `test_run_no_sdk_import.py`-style fence extended).
- **CC coverage:** `check_critical_coverage` on fresh `--cov-branch` — `core/run/executor.py` stays ≥ 95/90 with the new branches covered; CC count 131.
- **F5 e2e (`tests/integration/run/`, env-gated `COGNIC_RUN_DOCKER_SANDBOX=1`):** install a high-risk fixture pack (real submit-row manifest with `[risk_tier].tier="customer_data_read"`), real `ApprovalEngine`, real route → POST run → assert **202** (genuine Arm-A pend, no stub) → grant via the **real** approval engine → re-POST with `approval_request_id` → run completes. The only test-only surface is the fixture pack + the env-gate — **no route shortcut**.

## 8. Scope fence / non-goals

- **No migration** (the manifest is read off the existing submit chain row).
- **No new gate module** — `executor.py` is already on the gate; CC stays **131**.
- **No `data_classes` governance** (no tenant-policy diff / DLP / retention / egress) — shape-validate + thread only.
- **No scheduler/quota change** — A4a's arm 3 already admits high-risk-when-delegated; the other admission gates (pack-state / kill-switch / quota / caps) are unchanged.
- **No new `scheduler.rego` / `sandbox.rego` loosening** — A4b only *sets* the A4a signal + the real tier; the bundles are unchanged.
- **No `data_classes` materialization / caching** (F4 accepts the per-run history read).
- The A3c **wake** path is consumed unchanged — it re-validates against the suspend checkpoint's persisted sandbox `PackAdmissionContext` (the real tier rides along because A4b set it at cold-create); A4b touches no wake code, no checkpoint-metadata schema, and no run-record tier field.
