# M4 — Operator-Grade Pack Install Flow — Design

**Status:** DRAFT (brainstorming output; pending user review → implementation plan)
**Milestone:** M4 (production-grade milestone checklist, B-track pack ecosystem)
**Date:** 2026-06-30
**Requires ADR:** **ADR-026** — "Operator-grade pack install: lifecycle-governed runtime configuration (desired/derived state)" (next free number; ADR-021 reserved for Studio, ADR-025 earmarked for Agent Skills/M7).
**Builds on:** M2 (Proof 1b-2 deployed tool invoke, PR #103) + M3 (Proof 2 deployed external pack, PR #110); the proof-1b-2c harness; PR-2b-1/2b-2 (the MCP server-url override + per-tenant internal-host allow-list).

---

## 1. Goal

Replace the **proof-harness direct DB/Vault seeding** of pack runtime configuration with the **real operator lifecycle**: `submit → review → approve → allow-list → configure → install → disable → revoke`. The load-bearing proof is that the governance controls *matter* — a pack becomes callable **only** through the governed operator path, and `disable`/`revoke` make a previously-callable pack refused.

**Non-goal (explicit, locked):** M4 does **not** build a runtime live-code-install API. Pack *code* registration stays **boot-time / baked / cosign-trusted** (the immutable-runtime-image posture proven in M3). Live code loading is a much larger product + security surface — a possible future milestone, not M4.

## 2. Background — what exists vs the gap

A read-only scouting pass (2026-06-30) established the current state:

**Built — the governance state machine.** The full operator API exists under `/api/v1/packs` (`portal/api/packs/{author,review,operator,inspection,evidence}_routes.py`): `save_draft/update_draft → submit → claim → approve → reject` and `allow-list → install → disable → revoke → uninstall`. Each endpoint drives a `packs/lifecycle.py` transition through a `PackRecordStore.transition(...)` `SELECT … FOR UPDATE` audited row flip. RBAC + `RequireTenantOwnership` are per-endpoint; review uses `RequireDifferentActorThanCreator`; allow-list uses `RequireHumanActor`. The **5-gate approval composer** (`packs/approval_gates.py`: signature/evaluation/adversarial/owasp_conformance/reviewer_acknowledgement; signature non-overridable) runs at `approve`.

**Exists but not wired.** The MCP **override** + **internal-host-allowlist** operator endpoints (`portal/api/mcp_config/routes.py`, human-actor-gated, audited; stores `core/mcp_config/storage.py`) are real but **not mounted** in `create_prod_app`/`create_proof_app` (the stores aren't threaded into `create_app`). This is the only reason the proof seeds those rows via SQL.

**No operator API.** The per-tenant Vault **OAuth client creds + AS allow-list** (`secret/cognic/{tenant}/mcp-oauth/{as_host}`, `secret/cognic/{tenant}/mcp-as-allowlist`) are read-only from Vault (`protocol/mcp_authz.py`), written only by `seed-vault.sh`.

**The decoupling (the crux).** The packs-lifecycle DB state (`approved/installed/revoked`) is **completely decoupled** from callability. The `install` endpoint only flips a DB row — no trust/registry/MCP side effect. Real callability is gated by: **boot-time** `harness/registry_boot.py` → `protocol/plugin_registry.register_with_full_attestation_check` (cosign + the `_default` JSON allow-list; baked tree + pod restart), and **runtime** `protocol/mcp_authz.py` (the override + internal-host allow-list carve-outs at call time — the surface Bar 1 exercises). There is **no runtime install API**; registering a pack is boot-only.

## 3. Design decisions (locked in brainstorming)

| # | Decision | Rationale |
|---|---|---|
| D1 | **Approach A** — no runtime code-load; pack code stays boot-registered + cosign-trusted | preserves the immutable-image posture; reuses the proven MCP authz gate |
| D2 | The lifecycle drives a first-class **runtime-config record** (the provisioning abstraction), not raw carve-out rows | leaves room for future install outputs without turning the lifecycle into a row-writer |
| D3 | **Desired-state vs derived-state**: the record is authoritative *desired* state; the override/allow-list rows are *derived* projections | makes install idempotent, disable/revoke clean, and a future reconcile loop possible |
| D4 | **`configure` is a dedicated step** (new endpoint) writing the record, required *before* `install` | runtime config becomes a first-class governed object; "configured X" and "activated X" are separate audit events |
| D5 | **OAuth by reference** — the record *references* operator-pre-provisioned Vault material; `install` *validates presence/shape*, does not write secrets | M4 is not a secret-management API project; secrets stay in operator/Vault custody |
| D6 | **Remove-derived** for both `disable` and `revoke` — retract the derived rows; differ only in whether the desired record survives | zero change to `mcp_authz` (a critical control); reuses Bar 1's live-proven refusal; single source of truth |
| D7 | **Standalone override/allow-list *write* endpoints are superseded** — the materializer is the sole writer of those tables; the operator's only write path is `configure` | avoids two write paths / two sources of truth |
| D8 | The **materializer is idempotent + transactional/recoverable + retry-safe**, and audits **both** the lifecycle transition and the materialization result | install/disable/revoke are operationally safe to retry; partial materialization is detectable/recoverable |

## 4. Architecture — the desired/derived provisioning model

```text
            operator                          materializer                 runtime
  ┌───────────────────────┐         ┌──────────────────────────┐     ┌───────────────┐
  │ configure  (writes)   │  ───►   │ project / retract         │ ──► │ mcp_authz     │
  │  runtime-config record│ desired │  derived rows (override,  │ der.│ reads derived │
  │  (authoritative)      │  state  │  internal-host-allowlist) │ rows│ → callable /  │
  └───────────────────────┘         │  + validate Vault refs    │     │   refused     │
            ▲                       └──────────────────────────┘     └───────────────┘
            │ install → project ; disable/revoke → retract
            │ (triggered by lifecycle transitions; transactional + audited)
```

**The invariant:** `mcp_authz` (the critical-control gate) is **never changed**. It continues to read the derived override + internal-host-allowlist rows. Callability changes only because the materializer projects or retracts those rows under operator-governed lifecycle transitions. The record is the one authoritative description; the rows are a recomputable projection.

## 5. Lifecycle spine

```text
submit pack
review / approve / allow-list pack
configure runtime install record
  - server_url_override
  - internal_host_allowlist entries
  - oauth credential reference / AS allow-list reference
install
  - verify lifecycle state (allow_listed on first install; disabled on re-enable)
  - verify boot-registered/trusted pack exists (PluginRegistry)
  - verify runtime config complete
  - validate Vault references exist + shaped correctly
  - materialize override + internal-host-allowlist  (transactional)
  - transition → installed ; activation_status = active
disable
  - activation_status = disabled ; remove derived rows ; record retained (re-installable)
  - pack becomes refused through existing mcp_authz path
revoke
  - activation_status = revoked (terminal) ; remove derived rows ; record cannot reactivate
  - pack becomes refused through existing mcp_authz path
```

## 6. Components

### 6.1 Runtime-config record + store (new)
A new table (Alembic migration) + store, keyed by `(tenant_id, pack_id)`, holding the **desired** runtime config:
- `server_url_override: str` (the MCP server URL the operator pins, e.g. a ClusterIP URL)
- `internal_host_allowlist: list[str]` (the IPs to permit for the override target)
- `oauth_credential_ref` + `as_allowlist_ref` (references to the operator-provisioned Vault material — *not* the secret values)
- `activation_status: Literal["configured", "active", "disabled", "revoked"]`
- provenance/audit columns (set_by_actor, timestamps) consistent with the existing `core/mcp_config/storage.py` pattern
- a **materialization status / generation** marker enabling detect/recover of partial materialization (D8)

Style: follow the existing store conventions (`core/mcp_config/storage.py`, `packs/storage.py`) — typed store, fail-closed, audited. The shape/closed-enums are wire-protocol-adjacent (operator API + audit) so they get the usual closed-enum discipline.

### 6.2 `configure` endpoint (new)
`PUT /api/v1/packs/{pack_id}/runtime-config` (final shape TBD in plan) — writes/updates the desired record. **`RequireHumanActor`** + a new RBAC scope **`pack.configure`** + `RequireTenantOwnership`. Emits a distinct `pack.runtime_config.configured` audit/chain event. Validates the *shape* of the config (well-formed URL, RFC-1123 hosts, non-empty refs) but does **not** materialize and does **not** require the pack to be installed yet (config can precede install). Idempotent for non-active records (re-configure overwrites the desired record + bumps the generation marker). **M4 refuses re-configure while `activation_status=active`** to avoid desired/derived drift without a reconcile loop; the operator must `disable → configure → install` to change live runtime config. `revoked` is terminal.

### 6.3 Materializer (new)
A pure-ish provisioning function that **projects** the desired record into the derived rows and **validates** the Vault refs:
- `materialize(record)` → writes the override row + the internal-host-allowlist rows via the existing stores; validates `oauth_credential_ref` + `as_allowlist_ref` resolve in Vault and are shaped correctly (the same shapes `mcp_authz` reads).
- `retract(record)` → removes the derived override + allow-list rows.
- **Idempotent**: `materialize` is safe to re-run (upsert to the exact desired projection); `retract` is safe to re-run (delete-if-exists). Re-install re-materializes from current desired state (re-validates).
- **Transactional/recoverable (D8)**: the derived-row writes happen under a DB transaction; the Vault *validation* (read-only) runs *before* the transaction commits so a missing/misshaped ref fails install *before* any derived row is written. Partial materialization (e.g. crash mid-write) is detectable via the generation marker and recoverable by re-running `materialize` (idempotent).
- **Audit (D8)**: the materialization *result* (success/failure, what was projected/retracted) is recorded alongside the lifecycle-transition chain row — two facts, both on the evidence trail.

### 6.4 `install` extension
The existing `install` endpoint (`operator_routes.py`) gains the 5 verification gates *before* the transition commits. M4 also makes the re-enable path explicit: today's lifecycle table only permits `allow_listed → installed`; M4 extends the `install` transition to additionally permit `disabled → installed` so a retained desired record can be re-materialized after `disable` without a new approval flow. This is a critical-controls lifecycle-table change and belongs in ADR-026 (and likely an ADR-012 amendment note) with drift tests.
1. lifecycle-state valid (`allow_listed → installed` for first install; `disabled → installed` for re-enable)
2. the pack is **boot-registered + trusted** — consult `app.state.plugin_registry` (the cosign-verified registry from `registry_boot`); refuse if absent
3. the runtime-config record exists + is **complete** (all required desired fields)
4. the Vault references **resolve + are shaped correctly** (read-only validation)
5. **materialize** the derived rows (transactional), set `activation_status = active`, then commit the lifecycle transition

Gates 2–4 are the new negative-proof surface (install refused on untrusted / unconfigured / unresolved-ref).

### 6.5 `disable` / `revoke` extension
Both retract the derived rows (D6):
- `disable` (`installed → disabled`): `activation_status = disabled`; `retract`; the desired record is **retained** (a later `install` re-materializes from it).
- `revoke` (`installed/disabled → revoked`): `activation_status = revoked` (terminal); `retract`; the record cannot reactivate without a new approval/config flow.

Both land the pack as refused through the unchanged `mcp_authz` carve-out-absent path — the Bar 1 mechanism, now driven by a governed transition.

### 6.6 RBAC
A new closed-enum scope **`pack.configure`** added to `portal/rbac/scopes.py` (`PackRBACScope`), with the partition-invariant test updated. `configure` is human-actor-gated. The existing `pack.install/disable/revoke` scopes are unchanged.

### 6.7 Wiring (composition root)
The runtime-config store + the materializer are threaded through `build_runtime` / `create_app` so the operator path is live in the deployed image — the gap that left the proof seeding rows. The standalone override/allow-list *write* endpoints stay **unmounted** (D7); their stores are reused as the derived-state tables, written only by the materializer. (A read-only/diagnostic surface over derived state may be added later but is not required for M4.)

## 7. Boot-registration ↔ lifecycle reconciliation

Boot-registration (`registry_boot`) remains the **code-trust** gate: it discovers baked packs, cosign-verifies them, checks the `_default` allow-list, and populates the live `PluginRegistry`. The lifecycle DB + runtime-config record are the **per-tenant activation + configuration** layer. A pack is callable iff: **(boot-registered + cosign-trusted)** AND **(lifecycle `installed` + materialized carve-outs present)** AND **(Vault OAuth/AS material present)**. `install` gate #2 is the explicit reconciliation point: you cannot `install` (activate) a pack whose code is not boot-present + trusted.

This keeps the two systems honestly separated: code provenance is a build/boot concern; per-tenant activation + runtime config is the governed operator concern.

## 8. Error handling

- **Incomplete config at install** → 409/422 refusal (closed-enum reason), no transition, no derived write.
- **Unresolved/misshaped Vault ref at install** → refusal *before* any derived row is written (validation precedes the transaction).
- **Pack not boot-registered/trusted at install** → refusal (closed-enum reason).
- **Partial materialization** (crash mid-write) → detectable via the generation marker; `materialize` is idempotent, so a retry converges; `install` is safe to retry.
- **Re-configure while active** → refused in M4. Without a continuous reconcile loop, accepting active desired-state edits would create intentional desired/derived drift. Operators change live runtime config by `disable → configure → install`; the new `disabled → installed` path re-materializes from the retained desired record. A future reconcile loop may relax this.
- All refusals use closed-enum reasons consistent with the existing pack-API refusal vocabularies; audit records the attempt.

## 9. Load-bearing proofs

**Happy path:** the released signed `cognic-tool-oracle-schema` pack driven through the *real* operator API — `submit → approve → allow-list → configure → install` — reaches `discovery_status=auth_ready` + a real `call_tool(describe_table)`, with **no direct DB override/allow-list seeding** (the override + allow-list rows are *materialized* by the operator path).

**Negative paths (governance controls matter):**
1. `install` refused when the pack is **not approved/allow-listed** (existing lifecycle precondition).
2. `install` refused when the pack is **not boot-registered/trusted** (new gate #2).
3. `install` refused when the **runtime config is incomplete** or a **Vault ref does not resolve** (new gates #3/#4).
4. `approve` refused when the pack is **signature-red** (existing 5-gate signature gate — trust at approve time).

**Disable/revoke path:** a previously-callable pack (post-install) → `disable` (or `revoke`) → the override/allow-list rows are retracted → the next governed probe is **refused** (`mcp_discovery_url_refused` / `discovery_status=refused`) through the unchanged `mcp_authz` path. Re-`install` after `disable` (M4's explicit `disabled → installed` path) re-materializes and restores callability; after `revoke` it cannot.

## 10. Deployed proof harness

Extends the proof-1b-2c kind topology (released oracle-schema pack + in-cluster Oracle XE + RS256 AS). Two changes from M3-E2c:
- **Multi-actor binder** — the proof must mint *distinct* actors with the right scopes: a **creator/submitter**, a **reviewer (≠ creator)**, an **operator (human actor)** for configure/allow-list/install/disable/revoke, and an **MCP caller** for list/call. This proves the lifecycle gates (reviewer≠creator, human-actor) are load-bearing, not nominal. (M3-E2c used a single `mcp.tool.invoke` actor.)
- **Drive the operator API, not SQL** — `seed-db.sh`'s direct `mcp_server_url_override` + `mcp_internal_host_allowlist` INSERTs are **removed**; those rows are now materialized by the operator path. The **OAuth Vault material stays operator-provisioned** out-of-band (`seed-vault.sh` or a documented operator-migration step) since it is by-reference (D5); the `configure` record references it and `install` validates presence.

The proof remains env-gated + operator-run (Docker/kind), recorded in `docs/VALIDATION-RESULTS.md`, with the same honesty discipline (no AKS claim).

## 11. Scope boundary / honesty

- **kind, not AKS.** M4 proves the operator install flow on kind; the AKS bar is M15/M24.
- **No runtime code-load.** Pack code is boot-baked + cosign-trusted; `install` activates a boot-present pack under governance, it does not load new code.
- **OAuth stays operator-provisioned (by reference).** M4 adds no secret-write API; the per-tenant Vault OAuth/AS material is operator/Vault custody.
- **No continuous reconcile loop in M4.** The desired/derived split *enables* it; M4 materializes on transition only.
- M4 is *not* the LLM-agent loop (M8) and *not* the operator UI (Studio).

## 12. ADR-026

The architectural decision recorded by ADR-026: **pack lifecycle state governs runtime callability through a desired/derived runtime-config provisioning model.** It spans the pack lifecycle, the MCP runtime config, and the trust/callability seam. Key positions: lifecycle is the per-tenant activation+config authority; the record is authoritative desired state; the materializer is the sole writer of derived MCP carve-outs; `mcp_authz` is untouched; code trust stays boot-time; OAuth is by-reference for this milestone.

## 13. Open questions for the plan

- Exact endpoint path/shape for `configure` (sub-resource of the pack vs a tenant-scoped resource like the existing override endpoints).
- The record's migration + whether the materialization-generation marker lives on the record or a sibling table.
- Exact lifecycle-vocabulary edits for the new `disabled → installed` re-enable path, including refusal reasons and ADR-012/ADR-026 wording.
- The multi-actor proof binder mechanism (test-only header-driven binder vs a small proof-only multi-actor map).
- Whether a minimal read-only derived-state diagnostic endpoint is worth including now (default: no, defer).

## 14. Critical-controls / stop-rule awareness

M4 touches governance-adjacent surfaces. Expected stop-rule / critical-controls scrutiny: `packs/storage.py` + `packs/lifecycle.py` (lifecycle transitions), `portal/rbac/scopes.py` (new scope), the new runtime-config store, and the materializer (it gates what becomes callable). `mcp_authz.py` is **deliberately not modified** (D6) — a key safety property of this design. The `core-controls-engineer` + `/critical-module-mode` path applies to the lifecycle/RBAC/materializer changes per AGENTS.md.
