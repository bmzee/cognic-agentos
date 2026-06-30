# M4 — Operator-Grade Pack Install Flow — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the pack lifecycle state govern runtime callability through a desired/derived runtime-config provisioning model, so a pack becomes callable only through the governed operator path (`submit → review → approve → allow-list → configure → install`), and `disable`/`revoke` make a previously-callable pack refused — with no change to `mcp_authz` and no runtime code-load.

**Architecture:** A new per-`(tenant, pack)` **runtime-config record** (authoritative desired state) is written by a new `configure` step. A **materializer** orchestrates the EXISTING audited `MCPServerUrlOverrideStore` + `MCPInternalHostAllowlistStore` (the derived state) — projecting on `install`, retracting on `disable`/`revoke` — and validates the operator-pre-provisioned Vault OAuth/AS references. `install` gains 5 verification gates + a `disabled → installed` re-enable transition. `mcp_authz` reads the derived rows exactly as today (untouched).

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy async + Alembic, Pydantic v2, pytest, `uv run`. Postgres/Oracle via the bundled adapters. kind/Helm for the deployed proof.

**Decision records (read first):** `docs/superpowers/specs/2026-06-30-m4-operator-pack-install-flow-design.md` (the design, esp. §3 D1–D8 and §6 components) · `docs/adrs/ADR-026-operator-pack-install-runtime-config.md` · `docs/adrs/ADR-012-bank-pack-lifecycle.md` "M4 amendment".

## Global Constraints

- **Locked decisions (ADR-026 §Decision, D1–D8):** Approach A (no runtime code-load); a first-class runtime-config record (desired) materialized into the MCP carve-outs (derived); `configure` is a dedicated step before `install`; OAuth by reference (validate-presence, no secret-write API); **remove-derived** for `disable`+`revoke`; the materializer is the **sole writer** of the carve-out tables (standalone override/allow-list write endpoints stay unmounted); the materializer is idempotent + transactional/recoverable + retry-safe and audits both the lifecycle transition and the materialization.
- **`src/cognic_agentos/protocol/mcp_authz.py` MUST NOT be modified.** This is a safety property of the design (D6). Pin it with an AST/path guard test (Task 7).
- **Reconfigure-while-`active` is refused** (the record is `active` once installed). A live config change is `disable → configure → install`.
- **Critical controls.** `packs/lifecycle.py`, `packs/storage.py`, `portal/rbac/scopes.py`, the new runtime-config store, and the materializer are governance-path code: use `core-controls-engineer` + `/critical-module-mode`, halt-before-commit on EVERY commit, ≥95% line / ≥90% branch where the per-file coverage gate applies, negative-path tests required, map each watchpoint to ≥1 pinning regression (per AGENTS.md + `[[feedback_strict_review_off_gate]]`, `[[feedback_security_regression_hardening]]`).
- **Store/audit pattern:** every mutator runs the in-closure `DecisionHistoryStore.append_with_precondition` pattern (SELECT … FOR UPDATE → validate → upsert/delete → chain row, all in one transaction; a raise rolls back all three). Model EXACTLY on `core/mcp_config/storage.py`.
- **No `from __future__ import annotations`** in any portal route module with closure-local `Depends(...)` (the FastAPI `inspect.signature` invariant, `[[feedback_pep563_breaks_closure_local_depends]]`).
- **Branch:** one feature branch `feat/m4-operator-install` off `main`. Per-task commit token (the human reviews + tightens each task; `[[feedback_explicit_authorization_per_action]]`). `uv run` for all Python; full gate at commit per the gate ladder.
- **No mock/placeholder in the runtime path** (production-grade rule); test-only fixtures under clearly separated test paths.

## File Structure

| File | Create/Modify | Responsibility |
|---|---|---|
| `src/cognic_agentos/core/mcp_config/runtime_config.py` | Create | The runtime-config record store (desired state) + the closed-enum `RuntimeConfigActivationStatus` + refusal vocab; mirrors `core/mcp_config/storage.py` |
| `src/cognic_agentos/db/migrations/versions/<rev>_pack_runtime_config.py` | Create | Alembic migration for the `pack_runtime_config` table |
| `src/cognic_agentos/core/mcp_config/materializer.py` | Create | Projects/retracts the derived carve-outs by orchestrating the existing override+allowlist stores; validates Vault refs; idempotent/transactional/audited |
| `src/cognic_agentos/portal/rbac/scopes.py` | Modify | Add `pack.configure` to `PackRBACScope` + the role partition |
| `src/cognic_agentos/portal/api/packs/configure_routes.py` | Create | The `configure` endpoint (PUT/GET the runtime-config record); human-actor-gated |
| `src/cognic_agentos/portal/api/packs/operator_routes.py` | Modify | `install` 5-gate + materialize; `disable`/`revoke` retract; thread the materializer + registry + config store |
| `src/cognic_agentos/packs/lifecycle.py` | Modify | Add the `disabled → installed` re-enable transition |
| `src/cognic_agentos/packs/storage.py` | Modify | Map the re-enable transition target; (no schema change) |
| `src/cognic_agentos/harness/runtime.py` + `portal/api/app.py` | Modify | Composition-root: build + thread the runtime-config store + materializer; mount `configure_routes` |
| `infra/proof-m4/` + `tests/integration/proof_m4/` | Create | The deployed proof: multi-actor binder + drive the operator API (no direct override/allow-list seeding) |
| `tests/unit/architecture/test_mcp_authz_untouched.py` | Create | Guard: `mcp_authz.py` byte-unchanged vs `main` for the M4 diff (or an AST/no-new-condition guard) |

---

### Task 1: Runtime-config record store + migration

**Files:**
- Create: `src/cognic_agentos/core/mcp_config/runtime_config.py`
- Create: `src/cognic_agentos/db/migrations/versions/<rev>_pack_runtime_config.py`
- Test: `tests/unit/core/mcp_config/test_runtime_config_store.py`

**Interfaces:**
- Produces: `PackRuntimeConfigStore(engine)` with `get(*, tenant_id, pack_id) -> PackRuntimeConfigRecord | None`, `set_config(*, tenant_id, pack_id, server_url_override, internal_host_allowlist, oauth_credential_ref, as_allowlist_ref, actor_subject, actor_type, request_id) -> None`, `set_activation_status(*, tenant_id, pack_id, status, actor_subject, actor_type, request_id) -> None`; the frozen `PackRuntimeConfigRecord`; the closed-enum `RuntimeConfigActivationStatus = Literal["configured","active","disabled","revoked"]`; a closed-enum `RuntimeConfigRefusalReason`.
- Consumes: `DecisionHistoryStore.append_with_precondition`, `validate_override_url` + `validate_allowlist_ip` (reuse from `core/mcp_config/storage.py`).

**Design notes:** the record is the DESIRED state. `server_url_override` reuses `validate_override_url`; each `internal_host_allowlist` entry reuses `validate_allowlist_ip`; the OAuth/AS refs are opaque strings validated for shape only here (Vault resolution is the materializer's job, Task 4). `set_config` is refused when the current `activation_status == "active"` (reconfigure-while-active; closed-enum reason `runtime_config_reconfigure_while_active`). Include a `generation` integer bumped on every `set_config` (the partial-materialization marker, D8). Table: `(tenant_id, pack_id)` unique; columns for the four config fields (allow-list as a JSON/array column or a child table — pick the simplest that round-trips on Postgres+Oracle; a JSON `internal_host_allowlist` array is acceptable since it is desired-state config, not a queried index), `activation_status`, `generation`, provenance columns. Mirror the `sa.TIMESTAMP(timezone=True)` + named-unique-constraint conventions of `core/mcp_config/storage.py`.

- [ ] **Step 1: Write the failing test** — `tests/unit/core/mcp_config/test_runtime_config_store.py`: against a migrated in-memory engine (use the project's standard migrated-DB fixture, `[[feedback_storage_test_migrated_db_not_create_all]]`): `set_config` then `get` round-trips the desired fields + `activation_status == "configured"` + `generation == 1`; a second `set_config` bumps `generation`; `set_config` while `active` raises with `runtime_config_reconfigure_while_active`; an invalid `server_url_override` raises the override grammar reason; a cross-tenant `get` reads `None`; `set_config`/`set_activation_status` each append exactly one chain row.
- [ ] **Step 2: Run it — expect fail** (`uv run --all-extras pytest tests/unit/core/mcp_config/test_runtime_config_store.py -q`) — ImportError/AttributeError.
- [ ] **Step 3: Write the migration** — model on the latest `db/migrations/versions/*.py` (read one for the exact header/`down_revision` chaining); create `pack_runtime_config`. Add the migration drift test if the repo pattern requires one (grep `tests/unit/db/test_migration_*`).
- [ ] **Step 4: Implement `runtime_config.py`** — the store + record + enums, mirroring `core/mcp_config/storage.py`'s `append_with_precondition` mutator pattern.
- [ ] **Step 5: Run tests — expect pass**; then the full `tests/unit/core/mcp_config` + `tests/unit/db` scope.
- [ ] **Step 6: HALT for commit token** (critical-controls: new governance store + migration → full gate `mypy src tests` + ruff + full pytest at commit). Commit `feat(m4): pack runtime-config record store + migration`.

---

### Task 2: `pack.configure` RBAC scope

**Files:**
- Modify: `src/cognic_agentos/portal/rbac/scopes.py`
- Test: `tests/unit/portal/rbac/test_pack_configure_scope.py` (+ the existing partition-invariant test)

**Interfaces:** Produces: `pack.configure` as a `PackRBACScope` Literal value; added to the operator role-group frozenset; the `PACK_LIFECYCLE_SCOPES` partition still holds.

- [ ] **Step 1: Failing test** — assert `"pack.configure"` ∈ `get_args(PackRBACScope)`; ∈ `OPERATOR_SCOPES`; the role-group union still equals `PACK_LIFECYCLE_SCOPES` (extend the BUILD_PLAN partition-invariant test). Count-guard the enum via `get_args`, `[[feedback_count_enum_values_via_ast_not_regex]]`.
- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** — add the Literal value + the operator-group membership; update the partition test's expected count.
- [ ] **Step 4: Run — expect pass** (full `tests/unit/portal/rbac`).
- [ ] **Step 5: HALT for commit token** (CC — RBAC scope is wire-protocol-public). Commit `feat(m4): pack.configure RBAC scope`.

---

### Task 3: The `configure` endpoint

**Files:**
- Create: `src/cognic_agentos/portal/api/packs/configure_routes.py`
- Test: `tests/unit/portal/api/packs/test_configure_routes.py`

**Interfaces:** `build_configure_routes(*, store: PackRuntimeConfigStore) -> APIRouter`. `PUT /api/v1/packs/{pack_id}/runtime-config` (body: `server_url_override`, `internal_host_allowlist[]`, `oauth_credential_ref`, `as_allowlist_ref`) → writes the record; `GET /api/v1/packs/{pack_id}/runtime-config` → reads it. Scope `pack.configure`; `RequireHumanActor`; `RequireTenantOwnership(pack_id_param="pack_id")`. `from __future__ import annotations` **OMITTED**. Model on `portal/api/mcp_config/routes.py:build_mcp_override_routes` (human-actor gate, request-id minter, closed-enum-reason mapping) + the packs route factories.

- [ ] **Step 1: Failing test** — PUT writes + GET reads back (200); a service-token actor is refused (`actor_type_must_be_human`, human-actor log only); an invalid `server_url_override` → 422 with the closed-enum reason; cross-tenant `pack_id` → 404 (cross-tenant-invisible); PUT while `active` → 409 `runtime_config_reconfigure_while_active`. Pin the `from __future__` omission via the AST self-test (`[[feedback_security_regression_hardening]]`).
- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** the factory + handlers.
- [ ] **Step 4: Run — expect pass** (full `tests/unit/portal/api/packs`).
- [ ] **Step 5: HALT for commit token.** Commit `feat(m4): configure endpoint (runtime-config record write/read)`.

---

### Task 4: The materializer

**Files:**
- Create: `src/cognic_agentos/core/mcp_config/materializer.py`
- Test: `tests/unit/core/mcp_config/test_materializer.py`

**Interfaces:** `RuntimeConfigMaterializer(*, override_store, allowlist_store, vault_reader)` with `async def materialize(*, record, actor_subject, actor_type, request_id) -> MaterializeResult` and `async def retract(*, tenant_id, pack_id, actor_subject, actor_type, request_id) -> None`. `materialize`: (1) read-only **validate** the Vault OAuth/AS refs resolve + are shaped correctly (the same shapes `mcp_authz` reads — `secret/cognic/{tenant}/mcp-oauth/{as_host}` keys + the `mcp-as-allowlist` `servers` list) BEFORE any write — refuse with a closed-enum `materialize_vault_ref_unresolved`/`_malformed` if absent; (2) project the desired override via `override_store.set_override(...)`; (3) project each desired allow-list IP via `allowlist_store.add_ip(...)` and remove any derived IPs no longer desired via `remove_ip` (idempotent reconcile to exactly the desired set). `retract`: `override_store.clear_override(...)` + `remove_ip` for each derived IP. **Idempotent** (re-run converges); **the underlying store mutators are already transactional + audited** (each emits its `mcp.override.*` / `mcp.allowlist.*` chain row — that IS the materialization audit, D8). `vault_reader` is a narrow consumer-owned Protocol (`[[feedback_consumer_owned_protocol_for_unlanded_dep]]`) over the existing Vault read path.

**Design note:** the materializer NEVER writes the carve-out tables directly — it calls the existing stores, so it cannot drift from their grammar/audit. It MUST NOT import or touch `mcp_authz`.

- [ ] **Step 1: Failing test** (stub override/allowlist stores + a stub vault_reader): `materialize` with all refs present projects the override + the exact desired IP set; a missing Vault OAuth ref refuses with `materialize_vault_ref_unresolved` and projects NOTHING (validate-before-write); re-`materialize` is idempotent (no duplicate rows, converges to desired); `retract` clears the override + all derived IPs; `retract` is idempotent (safe on already-empty); changing the desired IP set + re-materialize converges (adds new, removes dropped). AST-guard: the module does not import `cognic_agentos.protocol.mcp_authz`.
- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: HALT for commit token** (CC — the materializer gates what becomes callable; negative-path coverage required). Commit `feat(m4): runtime-config materializer (project/retract derived MCP carve-outs)`.

---

### Task 5: Lifecycle `disabled → installed` re-enable transition

**Files:**
- Modify: `src/cognic_agentos/packs/lifecycle.py`
- Modify: `src/cognic_agentos/packs/storage.py`
- Test: `tests/unit/packs/test_lifecycle.py` (+ `test_storage*`)

**Interfaces:** `validate_transition(from_state="disabled", to_state="installed", kind=…, transition="install")` is now legal; `_TRANSITION_TO_TARGET_STATE`/`_VALID_TRANSITIONS` updated. RBAC scope unchanged (`pack.install`).

**Design note:** this is the ADR-012-amendment lifecycle change — **canonical-form / stop-rule scrutiny** per AGENTS.md (lifecycle table is a wire-protocol-public state machine). Add the re-enable pair to `_VALID_TRANSITIONS` (currently `install` is `allow_listed → installed` only). Pin both legs: first-install (`allow_listed → installed`) AND re-enable (`disabled → installed`). Confirm `revoke` stays terminal (no `revoked → installed`). Verify the closed-enum `LifecycleRefusalReason` count is unchanged (no new reason — `disabled → installed` is now legal, not a new refusal).

- [ ] **Step 1: Failing test** — `validate_transition` permits `disabled → installed`; still permits `allow_listed → installed`; still refuses `revoked → installed` (`lifecycle_transition_invalid_state_pair`); the storage `transition("install")` from `disabled` succeeds end-to-end on the migrated DB; the count-guard for `_VALID_TRANSITIONS` legal-pair count is bumped by exactly 1.
- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** the table change.
- [ ] **Step 4: Run — expect pass** (full `tests/unit/packs`).
- [ ] **Step 5: HALT for commit token** (CC — lifecycle state machine; ADR-012 amendment already committed; map to the pinning tests). Commit `feat(m4): lifecycle disabled->installed re-enable transition`.

---

### Task 6: `install` 5-gate + materialize; `disable`/`revoke` retract

**Files:**
- Modify: `src/cognic_agentos/portal/api/packs/operator_routes.py`
- Test: `tests/unit/portal/api/packs/test_operator_routes_m4.py`

**Interfaces:** the `install` handler gains, before `store.transition("install")` commits: (1) lifecycle-state valid (already enforced by the transition); (2) the pack is boot-registered/trusted — consult `app.state.plugin_registry` (refuse 409 `install_pack_not_registered`); (3) the runtime-config record exists + complete (refuse 409 `install_runtime_config_missing`/`_incomplete`); (4) `materializer.materialize(...)` — its Vault-ref validation refuses (409 `install_runtime_config_vault_ref_unresolved`) BEFORE the transition; (5) on success set `activation_status = active` + commit the transition. `disable`/`revoke` call `materializer.retract(...)` + `set_activation_status("disabled"/"revoked")` in addition to `store.transition(...)`.

**Route-level saga constraint:** the existing MCP config stores and pack lifecycle store each own their own audited `append_with_precondition` transaction, so Task 6 MUST NOT claim a single DB transaction across lifecycle + derived rows. Implement a small, explicit compensation contract and pin it: install validates every gate before writes; if `materialize` succeeds but a later lifecycle/status write fails, the handler retracts the just-materialized rows and leaves the record non-active; disable/revoke must likewise avoid a half-callable state by either completing `retract + transition + status` or compensating back to the prior callable projection. These are production safety tests, not just comments.

**Design note:** the operator route already threads `actor_type` onto the chain row. Add the materializer + registry + config-store dependencies via the route factory (composition root, Task 7). Closed-enum install-refusal reasons added to the route-owned vocab. Keep the existing delegate-to-storage refusal pattern (`PackNotFound`/`LifecycleTransitionRefused`).

- [ ] **Step 1: Failing test** (stub materializer + a fake registry + the real stores on a migrated DB): happy `install` after `configure` → materialized override+allow-list rows present + `activation_status=active` + `installed`; install refused when not boot-registered (gate 2); install refused when no runtime-config record (gate 3); install refused when the materializer raises the Vault-ref reason (gate 4) AND no lifecycle transition committed AND no derived rows; if `materializer.materialize` succeeds but the lifecycle transition/status update then raises, `materializer.retract` is called and no derived rows remain; `disable` → retract called → derived rows gone + `activation_status=disabled` + state `disabled`; if disable/revoke loses the lifecycle race after retract, the handler compensates by re-materializing and leaves the pack callable rather than silently half-disabled; re-`install` from `disabled` re-materializes (gate path) → callable again; `revoke` → retract + terminal.
- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** the gates + materialize/retract wiring.
- [ ] **Step 4: Run — expect pass** (full `tests/unit/portal/api/packs`).
- [ ] **Step 5: HALT for commit token** (CC — operator routes own the install governance boundary). Commit `feat(m4): install 5-gate + materialize; disable/revoke retract`.

---

### Task 7: Composition-root wiring + `mcp_authz` guard

**Files:**
- Modify: `src/cognic_agentos/harness/runtime.py`, `src/cognic_agentos/portal/api/app.py`
- Create: `tests/unit/architecture/test_mcp_authz_untouched.py`
- Test: `tests/unit/portal/api/test_app_m4_wiring.py`

**Interfaces:** `build_runtime` builds the `PackRuntimeConfigStore` + the `RuntimeConfigMaterializer` (wired to the existing override/allowlist stores + the Vault read path) and exposes them; `create_app` mounts `build_configure_routes` and threads the materializer + config store + `plugin_registry` into `build_operator_routes`/the packs router. The standalone `build_mcp_override_routes`/`build_mcp_allowlist_routes` stay **unmounted** (D7) — assert they are not in the app's routes.

- [ ] **Step 1: Failing tests** — the app exposes the `configure` routes; the standalone override/allow-list write routes are NOT mounted; `app.state` carries the runtime-config store + materializer. The `mcp_authz` guard: assert `protocol/mcp_authz.py` is unchanged on this branch (compare against `git show main:…/mcp_authz.py`, or an AST guard that the public gate functions + the carve-out read logic are byte-identical) — `[[feedback_security_regression_hardening]]` (the guard must FAIL if someone edits mcp_authz).
- [ ] **Step 2: Run — expect fail.**
- [ ] **Step 3: Implement** the wiring.
- [ ] **Step 4: Run — expect pass.**
- [ ] **Step 5: HALT for commit token** (off-gate composition root, but the mcp_authz guard is a key safety pin). Commit `feat(m4): composition-root wiring + mcp_authz-untouched guard`.

---

### Task 8: Deployed proof — multi-actor operator install (extends proof-1b-2c)

**Files:**
- Create: `infra/proof-m4/` (runner + a multi-actor proof app + values; reuse the proof-1b-2c oracle-pack/XE/AS images + manifests)
- Create: `tests/integration/proof_m4/` (the multi-actor binder + structural pins)
- Test: `tests/unit/proof_m4/*` (structural pins, mirroring `tests/unit/proof_1b_2c/*`)

**Interfaces:** a multi-actor binder yielding distinct actors per role (creator/submitter `pack.submit`; reviewer `pack.review.*` ≠ creator; operator `pack.configure`+`pack.allow_list`+`pack.install`+`pack.disable`+`pack.revoke`, human-actor; MCP caller `mcp.tool.invoke`) — test-only, header-driven or a small proof-only map (decide in implementation; pin it). The runner drives the REAL operator API: `submit → claim → approve → allow-list → configure (the override+allow-list+OAuth-ref) → install`, then proves `discovery_status=auth_ready` + `call_tool(describe_table)`. **`seed-db.sh` no longer INSERTs the override/allow-list rows** — they are materialized by `install`. `seed-vault.sh` (or a documented migration step) still provisions the OAuth Vault material (by-reference, D5).

**Proofs (BARs):**
- **BAR 1 (happy):** the full operator lifecycle via the API → the override+allow-list rows are materialized (assert via audit `mcp.override.set` + `mcp.allowlist.add` events) → `discovery_status=auth_ready` → `call_tool(describe_table owner=COGNIC table=EMPLOYEES)` returns `FULL_NAME`.
- **BAR 2 (negatives):** `install` refused when not approved/allow-listed; when not configured; when the Vault OAuth ref is absent; `approve` refused on a signature-red pack (existing 5-gate). Each via the API, asserting the closed-enum reason.
- **BAR 3 (disable/revoke):** post-install `disable` → the next governed probe is refused (`discovery_status=refused`); re-`install` restores callability; `revoke` → refused + terminal.

- [ ] **Step 1: Structural pins** (`tests/unit/proof_m4/`, mirror `tests/unit/proof_1b_2c/`): the runner drives the operator API (not direct override/allow-list INSERTs — assert `INSERT INTO mcp_server_url_override` NOT in `seed-db.sh`); the multi-actor binder yields ≥4 distinct role actors; the BAR sequence asserts auth_ready + the disable→refused delta + the negatives. `bash -n` clean; runner `chmod +x`.
- [ ] **Step 2: Implement** the runner + the multi-actor app + the manifests/values (reuse proof-1b-2c images; env-gated `COGNIC_RUN_PROOF_M4`).
- [ ] **Step 3: Structural gate** (the unit pins + ruff/mypy on the test).
- [ ] **Step 4: HALT for commit token** (the proof harness is the milestone gate's vehicle). Commit `feat(m4): deployed operator-install proof harness (multi-actor, API-driven)`.
- [ ] **Step 5 (operator-gated, separate token):** the live `COGNIC_RUN_PROOF_M4=1 …` run (your machine, Docker/kind); record evidence in `docs/VALIDATION-RESULTS.md`; flip **M4 → [x]** in `docs/PRODUCTION_GRADE_MILESTONE_CHECKLIST.md` (human-only release gate); confirm ADR-026 remains `APPROVED for M4 implementation`.

---

## Self-review

- **Spec coverage:** D1 (Task 6 install — no code-load; consults registry) · D2/D3 (Task 1 record + Task 4 materializer) · D4 (Task 3 configure) · D5 (Task 4 Vault validate-only) · D6 (Task 6 retract; Task 7 mcp_authz guard) · D7 (Task 7 standalone endpoints unmounted) · D8 (Task 4 idempotent + the stores' transactional audit) · the `disabled → installed` extension (Task 5) · the multi-actor + API-driven proof (Task 8). All §6 components mapped.
- **Type consistency:** `PackRuntimeConfigStore`/`PackRuntimeConfigRecord`/`RuntimeConfigActivationStatus`/`RuntimeConfigMaterializer`/`MaterializeResult` used consistently across Tasks 1/3/4/6/7.
- **Critical-controls:** Tasks 1,2,4,5,6 are governance-path; each ends in a HALT-for-token with full-gate; the mcp_authz guard (Task 7) is the headline safety pin.
- **Open items deferred to implementation (spec §13):** the exact allow-list column shape (JSON vs child table); whether `revoke` requires re-`configure` before a future re-approve (default: terminal, no re-enable); the multi-actor binder mechanism.

## Execution Handoff

Recommended: **subagent-driven** (fresh subagent per task + two-stage review), with the human commit-token gate after each task and `core-controls-engineer` on the governance-path tasks. Tasks 1–7 are kernel; Task 8 is the proof harness; Task 8 Step 5 is the operator-gated live run + the M4 checkbox flip.
