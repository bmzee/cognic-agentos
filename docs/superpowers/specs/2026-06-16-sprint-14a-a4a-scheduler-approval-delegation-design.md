# Sprint 14A-A4a — Scheduler `approval-delegated-to-sandbox` Affordance (Design)

**Status:** Design (brainstorm-approved 2026-06-16; pending written spec review)
**ADRs:** ADR-022 (runtime scheduler) + ADR-014 (runtime tool approval) — both amended by this sprint
**Stop-rule surfaces touched:** `policies/_default/scheduler.rego` (wire-protocol-public policy bundle); `core/scheduler/{engine,policy,storage}.py` (critical-controls)
**CC count:** stays **131** (no new gate module — edits land in modules already on the gate; the rego carries its own drift/vocab test suite, not the Python coverage gate)

---

## 1. Goal

Give the runtime scheduler an explicit, audited way to admit a **high-risk** task *because a downstream sandbox admission gate owns the human checkpoint* — without minting its own approval request and without faking `approval_verified=true`. The affordance ships **additive and dormant on `main`**: A4a adds the field + engine/policy/rego/storage plumbing and its tests, but **no production caller sets it**. Sprint 14A-A4b is the only future activator.

## 2. Background — why this exists, and why it is split out

The managed-run lane (`core/run/executor.py`) consults approval **twice**, both keyed off the risk tier:

1. **Scheduler submit** — `executor.py:337` → `core/scheduler/engine.py` Step-3.5 (`:478`), live since 14A-A2.
2. **Sandbox cold-create** — `sandbox/admission.py` Step-4 `_consult_approval_engine`, the A2/A3c human checkpoint (`202 → grant → re-POST → wake`).

Today both receive a hardcoded `"read_only"` (`executor.py:334` and `:989`), so neither ever pends in production. The arc goal (14A-A4) is to make the **sandbox** cold-create/wake checkpoint fire on a real manifest-driven high-risk tier.

The blocking fact: a scheduler `refused_approval_pending` outcome carries **no `task_id` and admits no concurrency slot** (`engine.py:498-506`; consumed at `executor.py:385`), and `scheduler.rego` admits a high-risk tier **only** when `input.approval_verified == true` (allow arm 2, `scheduler.rego:121-125`) — with the engine's Step-3.5 consult minting its own request *before* the rego is reached (`engine.py:482-507`). So passing the real high-risk tier to the scheduler **refuses the run before the sandbox is ever reached**, and the scheduler + sandbox use **different approval identities** (`scheduler:` name-hash `engine.py:231-239` vs `sandbox:`+artifact-sha256), so one grant cannot satisfy both.

**Chosen architecture (Z):** the trusted manifest tier flows to **both** scheduler and sandbox; **only the sandbox owns the human checkpoint**; the scheduler gains an explicit "approval delegated to sandbox" admission path so it can admit high-risk work **honestly** (real tier on the evidence row, not a `read_only` lie) without pending itself.

**Why A4a is its own sprint:** the scheduler delegation is a **coordinated kernel + ADR loosening of a stop-rule policy bundle** (a new way for *any* high-risk task to clear the scheduler — `scheduler.rego:17` requires coordinated kernel + ADR for loosening). It earns an isolated review unit + ADR amendment + tests, merged **dormant**, before A4b's executor flip activates it. This keeps `main` honest at every commit: until A4b, the executor still passes `read_only` everywhere, so `read_only` evidence is honestly `read_only` and the new rego arm is rego/unit-tested but never live.

## 3. The affordance contract

### 3.1 Named delegate signal (not a bool, not fake `approval_verified`)

- New closed enum in `core/scheduler/_types.py`:
  ```python
  SchedulerApprovalDelegate = Literal["sandbox_admission"]
  ```
- New `SubmitInput` field (additive, defaulted → byte-compatible with every existing call site):
  ```python
  approval_delegated_to: SchedulerApprovalDelegate | None = None
  ```

The named target (`"sandbox_admission"`) is the evidence shape: a bool would prove only "some delegation happened"; the named target proves the scheduler admitted high-risk work *because the sandbox admission gate owns the checkpoint*.

### 3.2 Engine boundary validation (`core/scheduler/engine.py`, CC)

Mirrors the unconditional `approval_request_id` parse (`engine.py:432-444`), evaluated regardless of `approval_engine` wiring:

- **Unknown value:** `approval_delegated_to is not None and approval_delegated_to != "sandbox_admission"` → `SchedulerSubmitInputInvalid(field="approval_delegated_to", reason=...)`. (`SubmitInput` is a frozen dataclass with no runtime Literal enforcement, so the engine must guard.)
- **Mutual exclusion (precedence-pinned):** the existing unconditional `approval_request_id` UUID parse runs **first** (`engine.py:432-444`) — a malformed id fails with `field="approval_request_id"` regardless of delegation. The mutual-exclusion check fires **only after** `approval_request_id` parses to a syntactically valid UUID: `approval_delegated_to is not None and approval_request_uuid is not None` (the *parsed* UUID, not the raw string) → `SchedulerSubmitInputInvalid(field="approval_delegated_to", reason="mutually exclusive with approval_request_id")`. Delegation means the scheduler verifies no grant of its own; an `approval_request_id` means it has one. Contradictory → fail closed. (Defensive: the run lane never sets the scheduler `approval_request_id`.) Rationale: the engine already owns the malformed-UUID outcome at the parse boundary, so binding mutual-exclusion to the *valid* parsed id yields one unambiguous precedence (parse → unknown-value → mutual-exclusion) when both are set and the id is malformed — `field="approval_request_id"` wins.
- `SchedulerSubmitInputInvalidField` (`engine.py:157`) grows `["parent_task_id", "approval_request_id"]` → `+ "approval_delegated_to"` (2 → 3 values); the lockstep frozenset `_VALID_SUBMIT_INPUT_INVALID_FIELDS` (`engine.py:164`) grows in step.

### 3.3 Engine Step-3.5 — skip the consult when delegated (`core/scheduler/engine.py`, CC)

Ordering (precedence-pinned, §3.2): **(1)** parse `approval_request_id` → valid UUID or `SchedulerSubmitInputInvalid(field="approval_request_id")` (existing, unconditional) → **(2)** validate `approval_delegated_to` unknown-value (new) → **(3)** mutual-exclusion on the *parsed valid* id (new) → Step-3.5.

When `approval_delegated_to is not None`: **skip `_consult_approval` entirely** — no request minted, no engine consult. `approval_verified` stays **False** (the F1-LOCK overwrite at `engine.py:508-512` already always sets it; the delegated path leaves it `False` because no consult ran). `approval_delegated_to` rides on `effective_submit_input` (it is an unmodified `SubmitInput` field; the `dataclasses.replace` at `:510` preserves it), so it reaches both the rego input (§3.4) and the chain row (§3.6).

### 3.4 Policy input — 9 → 10 keys (`core/scheduler/policy.py`, CC)

`_build_rego_input` (`policy.py:208-249`) gains a 10th key, **always threaded** (nullable):
```python
"approval_delegated_to": submit_input.approval_delegated_to,
```
The `test_build_rego_input_includes_all_spec_keys` contract grows 9 → 10.

### 3.5 Rego — third allow arm + honest refusal guard (`policies/_default/scheduler.rego`, STOP-RULE)

New **allow arm 3** (strict; absent/null/wrong value fails closed, mirroring arm 2's strict `== true`):
```rego
# Allow arm 3 — Sprint 14A-A4a (ADR-022 + ADR-014 amendment): a high-risk tier
# admits when the Python seam attests approval is delegated to the downstream
# sandbox admission gate (which owns the human checkpoint). STRICT string match;
# absent / null / any other value fails closed.
allow if {
	input.class in _known_classes
	input.pack_risk_tier in _high_risk_tiers
	input.approval_delegated_to == "sandbox_admission"
}
```

**Refusal-arm honesty guard** (the one refinement beyond the original field list, approved 2026-06-16): the existing high-risk refusal branch (`scheduler.rego:99-101`) gains a third conjunct so it never labels a delegated-admitted input as "high-risk refused" — even though `refusal_reason` is unread on allow paths (`policy.py` reads it only when `allow=false`):
```rego
} else := "scheduler_high_risk_tier_refused_pre_13_5" if {
	input.pack_risk_tier in _high_risk_tiers
	not input.approval_verified == true
	not input.approval_delegated_to == "sandbox_admission"
} else := "scheduler_default_deny"
```

**Refusal vocabulary is unchanged** — delegation only *adds* an allow path. The 3-value closed refusal enum (`scheduler_class_unknown` / `scheduler_high_risk_tier_refused_pre_13_5` / `scheduler_default_deny`) and `SchedulerAdmissionOutcome` (12 values) are both untouched. Safe tiers keep admitting via arm 1 (`scheduler.rego:109-113`); delegation is a harmless no-op for them.

### 3.6 Evidence — honest accepted chain row (`core/scheduler/storage.py`, CC)

`submit()`'s `_build_record` (`storage.py:255-286`) already records `payload["approval_verified"]` (`:272`) with a conditional `approval_request_id` (`:274-275`). A4a adds a parallel conditional key, present **only when non-None**:
```python
if submit_input.approval_delegated_to is not None:
    payload["approval_delegated_to"] = submit_input.approval_delegated_to
```
So a delegated high-risk admission writes `scheduler.admission_accepted` with `approval_delegated_to="sandbox_admission"`, `approval_verified=false`, and **no** scheduler `approval_request_id` — an examiner reads "high-risk, admitted because approval is delegated to the sandbox admission gate," with no fake grant.

### 3.7 Digest exclusion — `approval_delegated_to` is routing/evidence, not grant-binding

`approval_delegated_to` MUST stay out of the scheduler approval binding digest `_submit_args_digest` (`engine.py:242-263`, the 6-key partition `class_` / `pack_risk_tier` / `requested_estimated_tokens` / `parent_task_id` / `actor.subject` / `actor.actor_type`). It is a routing/evidence signal, not a grant-binding input, and a delegated submit never verifies a scheduler grant anyway — so it joins the **excluded** side of the disposition map alongside `approval_request_id` / `approval_verified`.

The disposition-map drift pin (`tests/unit/core/scheduler/test_approval_seam.py:129-142`) enumerates every `SubmitInput` field into exactly one bucket and asserts the union equals `dataclasses.fields(SubmitInput)`; a new undispositioned field fails it. A4a adds a distinct bucket naming the new field's disposition honestly (it is neither a carrier of a grant nor an attestation of verification — it is a routing directive):
```python
routing_or_evidence = {"approval_delegated_to"}
assert {f.name for f in dataclasses.fields(SubmitInput)} == (
    digested | digested_via_actor | identity | envelope_first_class
    | carrier_or_attestation | routing_or_evidence
)
```
plus a behavioral exclusion pin in `test_args_digest_binds_actor_tokens_and_parent` (`:169-181`) proving the helper does not silently start binding it:
```python
assert _submit_args_digest(_seam_submit_input(approval_delegated_to="sandbox_admission")) == base
```

> Design note: a distinct `routing_or_evidence` bucket (vs. folding into `carrier_or_attestation`) is the honest disposition and matches the field's stated nature — a routing directive, not a grant carrier or verification attestation. **Approved 2026-06-16.** Behaviorally identical to the other excluded buckets (out of the digest).

### 3.8 Setter obligation (normative caller contract)

A4a cannot verify that a delegating caller actually routes the work through sandbox admission — the scheduler has no handle on the downstream gate. The affordance is therefore governed by a **normative contract on the setter**, audited per-admission on the chain row (§3.6) rather than enforced at the scheduler:

> **MUST:** any caller that sets `approval_delegated_to="sandbox_admission"` MUST route the same unit of work through **sandbox admission** (`sandbox/admission.py`) carrying the **real manifest risk tier**, so the human checkpoint is genuinely owned downstream. Setting the signal *without* a real downstream sandbox approval gate is a contract violation — it would turn the affordance into a scheduler high-risk **bypass**.

**Sprint 14A-A4b is the only authorized production setter** — the managed-run executor, which constructs `PackAdmissionContext` with the same real manifest tier (`executor.py:_build_pack_context`) and routes through `sandbox.create → admit_policy`. No other caller (sub-agent dispatch, MCP, background tasks) sets it in Wave-1. The contract is documented here, in the ADR-022/014 amendments, and in the `scheduler.rego` arm-3 header comment so the obligation travels with the bundle; every delegated admission stays independently auditable via the `approval_delegated_to` chain-row evidence.

## 4. Components

| File | Layer | Change |
|---|---|---|
| `core/scheduler/_types.py` | off-gate | `SchedulerApprovalDelegate = Literal["sandbox_admission"]`; `SubmitInput.approval_delegated_to: SchedulerApprovalDelegate \| None = None` (additive, defaulted). |
| `core/scheduler/engine.py` | **CC** | Boundary validation (unknown value + mutual exclusion → `SchedulerSubmitInputInvalid(field="approval_delegated_to")`); Step-3.5 skips `_consult_approval` when delegated (no mint; `approval_verified` stays False); thread `approval_delegated_to` through `effective_submit_input`. `SchedulerSubmitInputInvalidField` + `_VALID_SUBMIT_INPUT_INVALID_FIELDS` 2 → 3. |
| `core/scheduler/policy.py` | **CC** | `_build_rego_input` 9 → 10 keys; always threads nullable `approval_delegated_to`. |
| `policies/_default/scheduler.rego` | **stop-rule** | Allow arm 3 (high-risk + `approval_delegated_to == "sandbox_admission"`, strict); refusal-arm honesty guard; header documents the ADR-022/014 amendment. |
| `core/scheduler/storage.py` | **CC** | `scheduler.admission_accepted` payload gains conditional `approval_delegated_to` key (non-None only), alongside `approval_verified=false`; never a scheduler `approval_request_id`. |
| `docs/adrs/ADR-022-runtime-scheduler.md` | docs | Amendment: the `approval-delegated-to-sandbox` admission affordance (named signal, dormant, A4b activates). |
| `docs/adrs/ADR-014-runtime-tool-approval.md` | docs | Amendment: "approval delegated downstream" routing mode (the scheduler admits, the downstream sandbox owns the checkpoint). |
| `AGENTS.md` | docs | Patch the `scheduler.rego` stop-rule entry (now 3 allow arms + the 10th input key + the delegation enum) and the engine/policy/storage CC entries (the two closed-enum growths). Present-tense operating-model claims patched per the active-model doctrine. |

**No migration** (chain payload is additive JSON). **No executor change.** **No `data_classes` change.** **No new closed-enum refusal value.**

## 5. Data flow

**A4a (tested, not live):** a test/hypothetical caller submits `SubmitInput(..., pack_risk_tier=<high-risk>, approval_delegated_to="sandbox_admission")` → engine validates → **skips Step-3.5 consult** (no mint, `approval_verified=False`) → policy builds the 10-key rego input → **rego arm 3 admits** → `accepted_immediate` → storage writes `scheduler.admission_accepted` with `approval_delegated_to="sandbox_admission"`, `approval_verified=false`, no `approval_request_id`.

**Production today (unchanged):** the executor still passes `pack_risk_tier="read_only"`, `approval_delegated_to=None` → rego arm 1 → behavior byte-identical to pre-A4a.

## 6. Error handling

| Condition | Result |
|---|---|
| `approval_delegated_to` not in `{None, "sandbox_admission"}` | `SchedulerSubmitInputInvalid(field="approval_delegated_to")` (fail-closed input contract) |
| `approval_delegated_to` set **and** a **valid** `approval_request_id` | `SchedulerSubmitInputInvalid(field="approval_delegated_to", reason="mutually exclusive ...")` (mutual exclusion, §3.2) |
| `approval_delegated_to` set **and** a **malformed** `approval_request_id` | `SchedulerSubmitInputInvalid(field="approval_request_id")` — the unconditional UUID parse wins (precedence §3.2) |
| high-risk + not-delegated + not-verified | existing `scheduler_high_risk_tier_refused_pre_13_5` (unchanged) |
| `approval_delegated_to == "sandbox_admission"` but tier is safe | admits via arm 1 (delegation is a no-op) |

## 7. Testing

- **Rego** (`tests/unit/policies/test_scheduler_rego.py`): arm 3 admits (high-risk + delegated); strict fail-closed (`null` / absent / wrong value → not allowed); refusal arm honest for a delegated input (never `scheduler_high_risk_tier_refused_pre_13_5`); refusal-vocabulary-closed assertion unchanged; arms 1 & 2 regression intact.
- **Engine** (`tests/unit/core/scheduler/test_approval_seam.py` + `test_engine*.py`): delegated → `_consult_approval` **not** called (no mint; assert via the approval-engine stub call count) and `accepted_immediate`; `approval_verified` stays False on the delegated path; unknown `approval_delegated_to` value → `SchedulerSubmitInputInvalid(field="approval_delegated_to")`; **precedence** — delegated + a *valid* `approval_request_id` UUID → `SchedulerSubmitInputInvalid(field="approval_delegated_to")` (mutual exclusion), while delegated + a *malformed* `approval_request_id` → `SchedulerSubmitInputInvalid(field="approval_request_id")` (the unconditional parse fires first, §3.2).
- **Policy** (`test_policy.py`): `_build_rego_input` 10 keys; `approval_delegated_to` threaded for both `None` and `"sandbox_admission"`; `_MINIMAL_SUBPROCESS_ENV` parity unaffected.
- **Storage** (scheduler storage tests): accepted row carries `approval_delegated_to` when set, omits when None, `approval_verified=false`, no `approval_request_id`.
- **Disposition / drift** (`test_approval_seam.py`): the disposition-map union grows by `routing_or_evidence`; the behavioral exclusion pin proves the digest is unchanged by `approval_delegated_to`; `SchedulerApprovalDelegate` is a 1-value enum; `SchedulerSubmitInputInvalidField` is a 3-value enum (Literal + frozenset lockstep).
- **Architecture fences** (`tests/unit/core/scheduler/test_architecture_no_emergency_import.py`, `test_architecture_no_sandbox_import.py`): still pass — A4a adds no cross-substrate import (the delegate enum is a scheduler-owned Literal; the scheduler never imports `sandbox`).
- **CC coverage:** `tools/check_critical_coverage.py` on fresh `--cov-branch coverage.json` for `engine.py` / `policy.py` / `storage.py` — the new branches covered, all three stay ≥ 95% line / 90% branch. CC count stays 131 (verified via the count-guard self-test, unchanged).

## 8. Scope fence / non-goals

- **No executor flip** — `executor.py:334` and `:989` stay `"read_only"`; nothing sets `approval_delegated_to` in production. A4a is dormant.
- **No manifest-risk sourcing** — `LoadedPackRecord` / `PackRecordStoreLoader` untouched; `find_latest_submit_row` not yet read by the run lane. (A4b.)
- **No `data_classes` threading** — sandbox-side concern. (A4b.)
- **No migration**, **no new refusal reason**, **no sandbox/admission change**, **no wake-path change** (A3c stays untouched).

## 9. A4b preview (the activator — documented, not in this spec)

**Sprint 14A-A4b: manifest-driven high-risk managed-run path** — loads the trusted manifest risk tier (off-gate `PackRecordStoreLoader` reading `payload["manifest"]["risk_tier"]["tier"]` off the submit chain row via `find_latest_submit_row`; **no migration**), adds `LoadedPackRecord.risk_tier` (+ fail-closed validation), flips `executor.py:334` (scheduler submit, **and sets `approval_delegated_to="sandbox_admission"`**, activating A4a) and `executor.py:989` (sandbox `PackAdmissionContext.risk_tier` → real tier, + `data_classes`), so the sandbox cold-create pends on the real tier (`202 → grant → re-POST → Arm B`). The A3c wake path follows naturally. A4b is the **only** production setter of `approval_delegated_to`.
