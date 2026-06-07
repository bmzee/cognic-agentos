# Per-Tenant Configuration Overlay — Design (2026-06-06)

**Status:** Design (approved in brainstorming; pending spec review → implementation plan)
**Workstream:** Wave-2 per-tenant config overlay — closes the Pre-GA Configurability Audit §9 gate.
**Deliverables:** this spec · **ADR-023 "Per-tenant configuration overlay"** · an implementation plan (next).
**Relates to:** ADR-004 (sandbox caps), ADR-019 (memory retention), ADR-006 (ISO mapping + evidence chain), ADR-012/§40 governance precedents.

---

## 1. Context & motivation

The Pre-GA Configurability Audit (PR #48) found there is **no general per-tenant `Settings`-overlay mechanism** today — the only per-tenant config surfaces are Vault path templates (`secret/cognic/{tenant}/…`) and `plugin_allowlist.json`. §9 explicitly deferred the overlay to "a downstream sub-project with its own spec, informed by the candidate set the sweep produces (the shape of the mechanism should follow the real list of things that need overlaying, not be guessed up front)." Wave-2 depends on it.

This design builds the **mechanism** (substrate) and proves it through **two already-shaped, production-real consumers** — deliberately avoiding both the "guess all ~10 candidates now" trap and the "memory-only one-off we later unwind" trap.

### Architectural reality that shapes the design

`Settings` is a pydantic-settings `BaseSettings` singleton (`@lru_cache get_settings()`, stashed on `app.state.settings`, `config.py`). Router factories **close over settings values at app construction** (`build_*_router(settings)`); handlers deliberately do **not** re-read `get_settings()` per request ("captured `settings`, never `get_settings()`"). Therefore a per-tenant override **cannot** be a swap of the global — overridable settings must be **resolved at the point of use, with tenant context**. Tenant context is already explicit at both chosen consumers (`admit_policy(..., tenant_id)`; `MemoryAPI` via its `MemoryCallerContext`), so resolution is opt-in and surgical (Approach ① — explicit point resolution).

## 2. Scope

**In (phase-1):**
- The substrate: field registry · request-time resolver · governed DB storage · human-only mutation endpoint · decision-history evidence · kernel-locked never-overlay list.
- Two proven candidates: **sandbox per-tenant resource caps** (ceiling) and **memory export retention** (floor).

**Out (explicit non-scope):** the other ~8 audit candidates (quotas, DLP rework, scheduler/emergency seams, credential-TTL cap, Qdrant collection); sub-agent recursion depth (deferred — no production dispatch path yet, and the cap is read at facade construction before `tenant_id` is available); tenant **self-service** mutation; **loosening** overlays ("premium tenant gets *more*" is a deliberate Wave-2.1 decision, never silently baked in); the two-ISO-vocabulary reconciliation (pre-existing, separate ADR-006 item); secrets/`runtime_profile`/strict guards/cosign/export-retention floor (kernel-locked).

### The crisp invariant

> **Effective tenant config = base settings + optional tenant overlay, where overlays may only _tighten_ the base posture** — ceilings only go down (`tenant ≤ base`), floors only go up (`tenant ≥ base`, and `≥` any kernel floor). The base value is the loosest a tenant can ever be.

## 3. §1 — Field registry & tighten-only semantics

A single closed, in-code registry is the source of truth for *what is overridable and how it tightens*. **Default-deny:** absence = kernel-locked.

```
OverlayDirection = Literal["ceiling", "floor"]      # closed enum

OverridableField = { key: str, direction: OverlayDirection, value_type: type, kernel_floor: <value>|None }

_REGISTRY (phase-1 — exactly 4 entries):
  sandbox_per_tenant_max_cpu       → ceiling, float, kernel_floor=None
  sandbox_per_tenant_max_memory    → ceiling, int,   kernel_floor=None
  sandbox_per_tenant_max_walltime  → ceiling, float, kernel_floor=None
  memory_export_retention_seconds  → floor,   int,   kernel_floor=<7yr const at config.py:39>
```

**Tighten-only check** — one pure function, used at **both** write-time (primary) and read-time (defense-in-depth):
1. coerce proposed → `value_type` (non-coercible ⇒ reject);
2. `ceiling`: proposed must be `≤ base` **and** `> 0`;
3. `floor`: proposed must be `≥ base` **and** `≥ kernel_floor` (when set).

**Closed-enum refusal reasons** (wire-public, drift-pinned):
`tenant_overlay_field_not_overridable`, `tenant_overlay_value_not_coercible`, `tenant_overlay_loosens_ceiling`, `tenant_overlay_below_base_floor`, `tenant_overlay_below_kernel_floor`.

Home: `core/config_overlay/registry.py` (new CC module).

## 4. §2 — Overlay storage + chain event shape

Current state in a table, immutable history in the chain (mirrors pack/model tenant-isolation + decision-history).

```sql
tenant_config_overlay (
  id                  uuid primary key,
  tenant_id           text not null,                 -- cross-tenant boundary (indexed)
  field_key           text not null,                 -- must be a _REGISTRY key
  value               jsonb,                          -- the tightened, coerced value
  set_by_actor        text,                           -- actor.subject
  set_at              timestamptz,
  last_request_id     text,                           -- request_id of the mutation that set this value (== DecisionRecord.request_id; back-link)
  unique (tenant_id, field_key)                       -- one overlay per (tenant,field); change = upsert + new chain row
);
```

**Atomicity — the table mutation happens _inside_ the `append_with_precondition` precondition closure** (mirrors `packs/storage.py` / `core/scheduler/storage.py`). `set_overlay()` / `clear_overlay()`:
- **inside** the closure (under the chain-head `FOR UPDATE` lock): `SELECT … FOR UPDATE` the current row → re-validate tighten-only against the live base → perform the **upsert** (set) or **delete** (clear) → return the `(previous_value, new_value, base_value)` snapshot;
- **outside:** `_build_record` mints the `DecisionRecord` from that captured snapshot. One transaction commits overlay-row + chain-row + chain-head together. **No separate "upsert then append."**

**Back-link via `request_id`, not `record_id`.** `append_with_precondition` mints the chain `record_id` *after* the closure returns, so it is **not available** where the in-closure upsert runs — writing it would require a post-append `UPDATE`, breaking the atomic single-transaction guarantee. Instead the caller mints a bounded `request_id` (`cfg-overlay-set-<uuid4.hex>` / `cfg-overlay-clear-<uuid4.hex>`, ≤64 chars per the `decision_history.request_id` column, mirroring the pack-routes per-verb prefix pattern) **before** opening the transaction, and threads it as **both** `DecisionRecord.request_id` **and** the overlay row's `last_request_id` (written in the same in-closure upsert). The overlay row back-links to its setting event by `request_id`. Direct `record_id` back-linking would require a new append primitive — out of phase-1 scope.

**Chain event:**

```
decision_type = "config.tenant_overlay.set"  |  "config.tenant_overlay.cleared"
payload = { tenant_id, field_key, direction, base_value, overlay_value,
            previous_overlay_value|null, actor_subject, actor_type="human" }
iso_controls = ("ISO42001.A.6.2.5",)   # Operational responsibilities — canonical registry
```

The payload carries `direction + base_value + overlay_value` so an examiner verifies the tighten-only invariant **from the chain row alone** (chain-payload-is-evidence-snapshot doctrine).

Home: `core/config_overlay/storage.py` (new CC module).

## 5. §3 — Resolver API & failure behavior

```
TenantConfigResolver.effective_many(field_keys, tenant_id) -> dict[str, value]   # PRIMITIVE
TenantConfigResolver.effective(field_key, tenant_id) -> value                     # thin wrapper over effective_many
```

`effective_many` issues **one** store read (`WHERE tenant_id=:t AND field_key IN :keys`) → **one consistent overlay snapshot** → applies tighten-only per key against base. This guarantees a multi-field consumer (the 3 sandbox caps) resolves against a single point-in-time snapshot — no interleaving with a concurrent mutation mid-resolve.

| Case | Effective value | Signal |
|---|---|---|
| **Absent** (no row) | `base` setting | none (normal) |
| Key **not in registry** (consumer bug) | — | raise `TenantConfigKeyError` (fail-closed) |
| Stored value **invalid** (non-coercible / loosens ceiling / below base floor / below kernel floor) | — (**posture R: refuse**) | **LOUD**: `config.tenant_overlay.invalid_at_read` on the **audit** chain + structured log; then raise `TenantConfigOverlayInvalid` |
| Valid tightened value | the stored value | none |

**Failure posture = (R) refuse.** Invalid-at-read means tampering, migration drift, or a write-path bug; falling back to base would loosen a **ceiling** to kernel-max (the footgun). So the resolver raises a typed refusal and the consumer fails closed. This branch is near-impossible in practice (write-time validation rejects loosening before storage); it is defense-in-depth.

**Incident, not mutation.** `config.tenant_overlay.invalid_at_read` is a **read-time, system-actor incident** emitted via plain `audit.append` (ISO **A.9.2**, System & operational logging) — a *separate* path that never touches the set/cleared mutation closure and never touches the overlay table.

**Throttle boundary (explicit):** the audit-chain incident row is suppressed for repeated detections of the **same `(tenant_id, field_key, reason)`** for a bounded time window **or** until the stored value changes (whichever first); the **refusal always fires** on every read, and the **structured log is unthrottled** (it carries the high-frequency signal). This prevents a hot corrupt row from flooding the audit chain while preserving live alerting.

**Injection:** `admit_policy` takes the resolver as a dep (threaded from the composition root → sandbox create path); `MemoryAPI` gets it via the harness `_factory(ctx)` (`runtime.py:150`).

**Resolver dependencies:** the overlay store + base `Settings` + an audit sink (for the `invalid_at_read` incident). **No `ObservabilityAdapter` in phase-1** — metric emission is deferred (the phase-1 surface is audit + structured log only); a fail-open metric sink is a deliberate follow-up if observability is later threaded in.

Home: `core/config_overlay/resolver.py` (new CC module).

## 6. §4 — Mutation endpoint + RBAC / human-only gate

New route module `portal/api/config_overlay/routes.py` (`build_config_overlay_routes(*, store)`; **no** `from __future__ import annotations` per the closure-local `Depends` gotcha). **Operator-administered** (not tenant self-service).

| Verb + path (under `/api/v1`) | Gates | Action |
|---|---|---|
| `PUT /tenants/{tenant_id}/config-overlay/{field_key}` body `{value}` | `RequireScope("config.tenant_overlay.write")` + `RequireHumanActor()` | `store.set_overlay(...)` → in-closure upsert + `.set` A.6.2.5 chain row |
| `DELETE /tenants/{tenant_id}/config-overlay/{field_key}` | same | `store.clear_overlay(...)` → in-closure delete + `.cleared` A.6.2.5 chain row |
| `GET /tenants/{tenant_id}/config-overlay` | `RequireScope("config.tenant_overlay.read")` (no human-only) | list current overlays |

- **New RBAC scopes** (closed-enum in `portal/rbac/scopes.py`): `ConfigOverlayRBACScope` = `config.tenant_overlay.write`, `config.tenant_overlay.read`.
- **Human-only** on set/clear (per AGENTS.md "per-tenant allow-list / threshold changes are human-only"); `actor.actor_type` threads onto `payload["actor_type"]`.
- **Operator-administered:** an elevated platform operator sets config *for* a tenant; we do **not** require `actor.tenant_id == {tenant_id}` and **must not** apply `RequireTenantOwnership` here (that would make it tenant self-service).
- **Write-time validation:** cheap pre-check in the handler (fast 4xx) **then** authoritative re-validate inside the precondition closure against the row-locked state (mirrors the packs/storage manifest-digest precondition). Reject → 4xx `{reason: <§1 closed-enum>}`, no chain row; accept → 200 + stored record.

### The five enforcement pins (carried into §8 tests)
1. service actor + write scope → refused by `RequireHumanActor()` **before** mutation;
2. cross-tenant actor allowed **iff** holding the operator scope — **no** `RequireTenantOwnership`;
3. invalid write → **zero** chain rows;
4. accepted write/delete → table mutation **+** decision-history append **atomically**;
5. corrupt stored row → `config.tenant_overlay.invalid_at_read` on the **audit** chain, never decision-history.

## 7. §5 — Sandbox cap consumer wiring

The cap is enforced in **two** layers of `admit_policy` — both must consume the effective value or they diverge:

```
caps = await resolver.effective_many(
    ("sandbox_per_tenant_max_cpu", "sandbox_per_tenant_max_memory", "sandbox_per_tenant_max_walltime"),
    tenant_id,
)   # one consistent snapshot
```

- **Step 5 (Python, `admission.py:462-484`):** compare `policy.cpu_cores/memory_mb/walltime_s` against `caps[…]` (not `settings.*`). Refusal reasons unchanged (`sandbox_policy_exceeds_tenant_max_*`), now reflecting the tightened cap.
- **Step 9 (Rego input, `admission.py:575-579`):** the `tenant_max` dict feeds the same `caps[…]` to `data.cognic.sandbox.admit.allow`. **`policies/_default/sandbox.rego` is untouched** — it already consumes `tenant_max`.
- **Invalid overlay** → resolver emits `invalid_at_read` (audit/A.9.2) + raises; `admit_policy` maps it to a **new** `SandboxRefusalReason` value `sandbox_tenant_config_overlay_invalid` (wire-public closed-enum → drift-pinned) → admission fails closed.
- **Backward-compatible:** no overlay ⇒ base values ⇒ identical behavior.

CC: `sandbox/admission.py` is a stop-rule edit + one new closed-enum value.

## 8. §6 — Memory export retention consumer wiring

`MemoryAPI` gains the resolver via the harness `_factory(ctx)` (`runtime.py:150`). In `MemoryAPI.export` (`core/memory/api.py:316-324`), `ctx.tenant_id` is already in scope:

```
retention_seconds = await self._resolver.effective("memory_export_retention_seconds", ctx.tenant_id)
```

- **Invalid overlay** → `invalid_at_read` (audit/A.9.2) + raise → export fails closed (new memory closed-enum `memory_export_tenant_config_overlay_invalid`, drift-pinned).
- The **7-year kernel floor** stays enforced by the registry's `kernel_floor` (write-time reject below floor; read-time re-check `≥ kernel_floor`). Backward-compatible: no overlay ⇒ base retention.

CC: `core/memory/api.py` is a stop-rule edit; harness-factory injection is off-gate.

## 9. §7 — Kernel-locked never-overlay list

Two distinct mechanisms:
- **Mechanical (default-deny):** the never-overlay set is the *exhaustive complement* of the §1 registry. The mutation endpoint refuses any non-registry field (`tenant_overlay_field_not_overridable`); the resolver only ever consults registry keys.
- **Readable (positive lock assertion):** a test enumerating the audit's do-not-configure invariants and asserting **none** are registry keys — `require_cosign`, `runtime_profile`, all four `_SECRET_VAULT_FIELDS` (`litellm_master_key`, `langfuse_secret_key`, `embedding_api_key`, `dynatrace_api_token`), and the G1–G10 strict-guard fields (cosign/signing/evidence-key paths).

**`memory_export_retention_seconds` is _not_ on the never-overlay list** — it is overridable upward; its 7-year kernel floor is the *kernel-floor* mechanism, a separate safety layer. "Never-overlay" (excluded) and "kernel floor" (bounded-overridable) are kept deliberately distinct.

## 10. §8 — Test / CC-gate plan

**New CC modules → durable per-file coverage gate (95% line / 90% branch):**

| Module | Why CC |
|---|---|
| `core/config_overlay/registry.py` | tighten-only validator + closed-enum reasons (policy boundary) |
| `core/config_overlay/resolver.py` | read-time enforcement + fail-closed + `invalid_at_read` emit |
| `core/config_overlay/storage.py` | `append_with_precondition` consumer; tenant-isolation + atomic mutation |
| `portal/api/config_overlay/routes.py` | Human-only-decisions enforcement boundary (mirrors `operator_routes.py`) |

`_EXPECTED_ENTRY_COUNT` moves **113 → 117** for the four modules — **provisional; verify at plan time after final file names settle**, and verify the floor at the promoting commit against fresh full-package coverage (`feedback_verify_promotion_meets_floor_at_promotion_time`).

**Edited CC stop-rule modules (re-verify coverage at the touching commit):** `sandbox/admission.py`, `core/memory/api.py`, `portal/rbac/scopes.py`, `compliance/iso42001/controls.py` (add `config.tenant_overlay.{set,cleared}` to A.6.2.5 `intended_hooks`; `test_control_mapping` must stay green). **Off-gate:** `harness/runtime.py` (resolver injection; Doctrine F). **New:** Alembic migration for `tenant_config_overlay`.

### Test matrix — the five §4 pins mapped explicitly

| Pin | Test |
|---|---|
| ① service+write scope refused before mutation | endpoint: service actor + write scope → 403 `RequireHumanActor`, **zero** chain rows (caplog) |
| ② cross-tenant iff operator scope, no `RequireTenantOwnership` | **behavior proof (primary):** cross-tenant operator with write scope → **200**; same actor **without** scope → **403**. **AST pin (supplement):** no `RequireTenantOwnership` dep registered on these routes |
| ③ invalid write → no chain row | storage: loosening value hits precondition → in-closure reject, **zero** chain + **zero** table mutation (rollback); endpoint: 4xx closed-enum, zero chain |
| ④ accepted write → atomic table + chain | storage (migrated DB, not `create_all`): upsert + decision-history append in one txn; chain payload exact-key-set (`base_value`/`overlay_value`/`direction`) + `A.6.2.5` |
| ⑤ corrupt row → `invalid_at_read` on **audit**, not decision-history | resolver: each invalid kind → raises typed error + emits on **audit** chain (assert decision-history untouched) + throttle per `(tenant_id, field_key, reason)` |

**Plus:** registry tighten-only (ceiling/floor/kernel-floor/coercion + closed-enum reasons); **default-deny** + the **positive lock-assertion**; `effective_many` single-snapshot consistency; consumer wiring (sandbox overlay tightens → both Python **and** Rego `tenant_max` see it; memory overlay raises retention → export uses it; no-overlay ⇒ unchanged; corrupt ⇒ fail-closed); compliance `test_control_mapping` stays green with the A.6.2.5 hook additions.

**Closed-enum drift pins:** `sandbox_tenant_config_overlay_invalid` (in `SandboxRefusalReason`), `memory_export_tenant_config_overlay_invalid`, `ConfigOverlayRBACScope`, the §1 overlay-reason Literal, the registry 4-key set, `OverlayDirection`.

**Storage tests run against the Alembic-migrated DB** (not `create_all`) and drive wrong-tenant negatives, per `feedback_storage_test_migrated_db_not_create_all`.

## 11. ADR-023 — Per-tenant configuration overlay

A **new ADR** ratifies the durable governance contract so future workstreams don't reinterpret the overlay model casually. It records: the tighten-only invariant; the closed overridable-field registry + default-deny never-overlay rule + the explicit kernel-locked invariant list; the human-only, operator-administered mutation model; the wire-public `ConfigOverlayRBACScope` + `config.tenant_overlay.*` chain-event names + closed-enum refusal vocabularies; the resolver fail-closed (refuse) read-time contract + the `invalid_at_read` audit-incident separation; and the A.6.2.5 ISO mapping. It threads ADR-004 (sandbox caps), ADR-019 (memory retention), ADR-006 (ISO/evidence chain). **ADR acceptance is human-only.**

## 12. OS / pack boundary

This is **OS** (governance/config kernel): tenant-scoped platform config (sandbox caps, memory retention), valuable to a bank deploying AgentOS **without any packs**. It belongs in `cognic-agentos`. No agent/pack/persona-specific surface is introduced.

## 13. Deferred / open items (tracked, not in phase-1)

- **Wave-2.1 — loosening overlays** ("premium tenant gets *more*") — a deliberate future policy decision with its own ADR amendment, never silently baked into phase-1.
- **Sub-agent recursion depth** — re-evaluate as an overlay candidate once a production sub-agent dispatch path exists and the cap is resolved per-request (the facade reads it at construction today; `subagent/_facade.py:50` / D1 "not a deployable production path").
- **Two-ISO-vocabulary reconciliation** — `compliance/iso42001/controls.py` (canonical, prefixed, 8 controls) vs `packs/lifecycle.py` `_KNOWN_ISO_CONTROL_CODES` (bare `A.5.31/A.5.32/A.6.2.4`) — pre-existing inconsistency; a separate ADR-006 reconciliation, out of scope here.
- The remaining audit overlay candidates (quotas, DLP, scheduler/emergency, credential-TTL cap, Qdrant collection) — added incrementally to the registry as their primitives mature; **no re-architecting required** (the registry + resolver substrate is the extension point).

## 14. Success criteria

- A platform operator can, under human-only + RBAC + audit, set/clear a per-tenant overlay for the 4 registry fields; loosening is rejected at write time with a precise closed-enum reason and zero chain row.
- A sandbox admission and a memory export honor the tenant's tightened value (both the Python and Rego sandbox layers agree); absent overlay ⇒ identical pre-feature behavior.
- A corrupt/loosening stored overlay fails the governed operation closed, surfaces an `invalid_at_read` audit incident (throttled) + unthrottled structured log, and never silently relaxes a ceiling.
- Every governed mutation is a hash-chained, examiner-verifiable `config.tenant_overlay.{set,cleared}` event tagged `ISO42001.A.6.2.5`, with the tighten-only invariant verifiable from the chain payload alone.
- The four new CC modules ride the per-file coverage gate; the never-overlay invariants are proven both mechanically (default-deny) and readably (positive lock assertion).
