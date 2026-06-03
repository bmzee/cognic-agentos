# Hand-off: Memory approval routing → Sprint 13.5 (ADR-014)

**Status:** Forward-looking hand-off record. **No engine and no code ship in Sprint 11.5c** — this documents the Sprint-13.5 cutover so the runtime-approval sprint inherits the seam without re-discovering it.

**Produced by:** Sprint 11.5c — Agent Memory Governance Surfaces (ADR-019).
**Consumed by:** Sprint 13.5 — runtime tool approval (ADR-014).

---

## 1. The current transitional refusal (shipped 11.5a, unchanged through 11.5c)

`MemoryGate.check_write` (the §7.1 per-write governance gate) runs an approval-transitional refusal at **Step 7** — `src/cognic_agentos/core/memory/gate.py:272-274`:

```python
# Step 7 — approval-transitional refusal (skipped for scratch).
if tier == "long_term" and ctx.risk_tier in _APPROVAL_REQUIRED_RISK_TIERS:
    raise MemoryOperationRefused("memory_approval_engine_not_available")
```

A `long_term` memory write whose caller `risk_tier` is one of the **five ADR-014 high-risk tiers** is refused **fail-closed** with the wire-public closed-enum reason `memory_approval_engine_not_available`. The five tiers — `src/cognic_agentos/core/memory/gate.py:103-111`:

- `customer_data_write`
- `payment_action`
- `regulator_communication`
- `cross_tenant`
- `high_risk_custom`

The three low tiers (`read_only` / `internal_write` / `customer_data_read`) write through without approval; `scratch` and `task` never reach Step 7's `long_term` condition.

`_APPROVAL_REQUIRED_RISK_TIERS` is a **deliberate inline mirror** of the canonical 8-value `RiskTier` vocabulary (`core/` must not import `cli/*`); the lockstep with the canonical set is pinned test-only in `tests/unit/core/memory/test_write_gate.py` per the drift-detector doctrine.

**Why a refusal, not a silent allow:** per the production-grade rule, the memory-governance kernel fails closed — a high-risk `long_term` write cannot be persisted until a real approval decision exists. There is **no permissive default**.

---

## 2. What Sprint 13.5 wires

Sprint 13.5 is the runtime-approval sprint (ADR-014: per-tool risk tiers; single-approval / 4-eyes / categorised-reason gates with expiry). It lands `core/approval/engine.py` — **not present in the tree today** (confirming this hand-off is forward-looking, not a description of existing code).

At cutover, the Step-7 refusal becomes a **consult** of the approval engine: a high-risk `long_term` write is routed through `core/approval/engine.py` (ADR-014) instead of being refused outright. A write that clears its tier's approval gate (single-approval / 4-eyes) proceeds to Step 8 (descriptor resolution, `gate.py:276-278`); one that does not is held or refused per the engine's verdict.

---

## 3. The seam (no gate restructuring required at 13.5)

The gate already **isolates** the approval decision at a single point — Step 7 (`gate.py:272-274`). The 13.5 change is therefore narrow:

1. Replace the `raise MemoryOperationRefused("memory_approval_engine_not_available")` with an `await approval.require(...)` consult (the exact call shape is ADR-014's to define).
2. Thread the approval engine into `MemoryGate` as a **constructor seam**, mirroring the existing injected `kill_switch` / `policy` / `consent` seams — no new construction pattern.
3. **No other gate step changes.** The preceding write-gate checks (Steps 1–6) and Step 8 (descriptor resolution, `gate.py:276-278`) are untouched.

The closed-enum `memory_approval_engine_not_available` **stays**. It is part of `MemoryRefusalReason`'s wire-public closed vocabulary — both count-pinned (`== 17`) and exact-set-pinned in `tests/unit/core/memory/test_refusal_vocab.py`, and read by bank-overlay consumers — so it is **retained as the compatibility / fail-closed fallback** for when the approval engine itself is unavailable (e.g. OPA / engine outage). Removing the value is a **wire-protocol break**, not a local 13.5 implementation choice: it would require a coordinated ADR + `MemoryRefusalReason` wire-vocab amendment (and the matching drift-test bump), which is explicitly out of scope for this hand-off.

---

## 4. RBAC interaction (the two paths are complementary, not duplicative)

- **Erasure (already shipped, 11.5c T5):** `memory.regulator_erasure` is the **human-only** scope gating `forget(reason="regulator_erasure")` — enforced at the portal `/memory` surface via `RequireHumanActor` + a body-aware scope check (`portal/api/memory/routes.py`). This is a *delete-time* human-only gate.
- **Write approval (13.5):** the approval engine adds the orthogonal **4-eyes (or single-approval) path for high-risk `long_term` writes** — the Step-7 tiers above. This is a *write-time* authorization.

Erasure = human-only delete; approval = multi-eyes write authorization for high-risk tiers. They sit at different lifecycle points and do not overlap.

---

## 5. Scope note

**No spec or ADR amendment is made in Sprint 11.5c.** This is a hand-off record only. The transitional `memory_approval_engine_not_available` refusal that shipped in 11.5a is the **sole approval surface** for memory writes until 13.5 wires the engine. ADR-019 (memory governance) and ADR-014 (runtime approval) both stand as-is.
