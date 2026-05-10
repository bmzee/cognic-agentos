# Sprint 7B.1 — Bank Pack Lifecycle: State Machine + Storage + Harness 4-Kind Expansion — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal.** Land the lifecycle state machine + Postgres-backed pack-record store + per-transition hash-chained `pack.lifecycle.*` event emission + harness 4-kind dispatch expansion. After Sprint 7B.1, a pack record can move through every state transition end-to-end programmatically (no portal API yet — that lands in Sprint 7B.2). Foundation that the 7B.2 portal endpoints + 7B.3 evidence panels + 7B.4 UI events all sit on top of.

**Architecture.** Two new modules, both critical-controls:
- `packs/lifecycle.py` — pure-functional state machine: closed-enum `PackKind` (4-tuple) × `PackState` (11-tuple) × `_VALID_TRANSITIONS` table; `validate_transition(from_state, to_state, kind, transition) -> LifecycleRefusalReason | None` is I/O-free + dialect-free.
- `packs/storage.py` — `PackRecord` Pydantic model + `PackRecordStore` async API. Constructor takes `AsyncEngine` + a `DecisionHistoryStore(engine)` (mirrors `core/escalation.py:463-465`). State transitions go through `DecisionHistoryStore.append_with_precondition` (Sprint-2.5 T2 atomic primitive); the precondition does `SELECT ... FOR UPDATE` on the pack row, validates the transition via `lifecycle.validate_transition`, and `UPDATE`s `packs.state`. The `record_builder` constructs a `pack.lifecycle.<to_state>` `DecisionRecord`. Chain `INSERT` + `packs.state` `UPDATE` + `governance_chain_heads` `UPDATE` all commit atomically. Non-chain reads (`load`, `list_by_status`, `load_lifecycle_history`) use `async with self._engine.connect() as conn` directly (mirrors `core/escalation.py:690+719`).

Plus one Alembic migration:
- `src/cognic_agentos/db/migrations/versions/20260510_0003_packs_lifecycle.py` — dialect-portable SQLAlchemy types; CHECK constraints on `kind ∈ {tool,skill,agent,hook}` and `state ∈ {draft,…,uninstalled}`; PG/Oracle compile tests.

Plus the harness 4-kind expansion in `cli/test_harness.py` — extends `_HARNESS_SUPPORTED_KINDS` from 1-narrow `frozenset({"tool"})` to 4-full `frozenset({"tool","skill","agent","hook"})` and adds `"hook" → "cognic.hooks"` to `_KIND_TO_ENTRY_POINT_GROUP`. Per-kind dry-run dispatch impls go through public SDK seams: Skill `execute(...)` after instantiation w/ ToolRegistry fixture; Agent `await agent.handle(payload, task=TaskRecord)`; Hook `Hook.invoke(context, payload)` (the public seam at `sdk/hook.py:347`, **not** `_invoke` at `:373`) so SDK validation runs.

**Tech stack.** Python 3.12; `pydantic` (PackRecord shape + closed-enum validation); existing `core.decision_history.DecisionHistoryStore.append_with_precondition` (Sprint-2.5 T2 primitive); existing SQLAlchemy-Core `AsyncEngine` setup; existing Alembic infrastructure at `src/cognic_agentos/db/migrations/` (env.py, alembic_config.py, oracle/, script.py.mako, two prior versions: `20260428_0001_initial_governance_schema.py` + `20260430_0002_gateway_call_ledger.py`); existing reference packs at `examples/cognic-{tool,skill,agent,hook}-example-minimal/` (Sprint-7A + Sprint-7A2).

**Planning-format note.** This plan follows the Sprint-7A / Sprint-7A2 plan-of-record style (paragraph-per-task with doctrine locks at the top, ADR amendment slate, and reviewer-strict halt-before-commit annotations). Implementation agents must still decompose each task into micro-steps during execution — the paragraph format describes the contract; the executing agent breaks it down into Red → Verify-Red → Green → Verify-Green → Refactor → Commit cycles.

---

## Sprint 7B program preamble (this is sub-sprint 7B.1 of 4)

Sprint 7B is the largest single sprint in BUILD_PLAN.md (3.5–5.5 wu) per the schedule-risk acknowledgement table at line 1142. The split-fallback documented there is now the up-front structure:

| Sub-sprint | Scope | Carry-forward into | Est. wu |
|---|---|---|---|
| **7B.1** (this plan) | Lifecycle state machine + Postgres-backed storage + per-transition hash-chained audit (via `DecisionHistoryStore.append_with_precondition`) + Alembic migration + harness 4-kind dispatch expansion | Sprint-7A2 carry-forward: harness 4-kind | ~1 |
| **7B.2** | ~24 portal API endpoints (author / review / operator / inspection) + 14 RBAC scopes + OWASP Agentic Top 10 conformance + `agentos conformance` CLI + `agentos test-harness` CLI extension | — | ~1.5 |
| **7B.3** | 4 reviewer evidence panels (data-governance / risk-tier / supply-chain / conformance-matrix) + 5-gate approval composition (cosign + allow-list + eval ≥ threshold + adversarial ≥ 0.99 + OWASP green) + override path + per-panel-access audit + server-side acknowledgement-required-before-approval | — | ~1 |
| **7B.4** | UI event-stream SSE endpoints (per ADR-020) + frontend-action POST + portable JSON schema + per-tenant connection caps + elicitation gate | Sprint-7A carry-forward: realtime auto-attestation API + compliance helper emit path. Sprint-7A2 carry-forward: `fail_open_exception` build-time manifest shape | ~1 |

Sub-sprint allocation locked at brainstorming session 2026-05-10 with three placement decisions:
1. Harness 4-kind expansion → 7B.1 (couples with the state machine since it enforces the 4-kind constraint at storage time).
2. `fail_open_exception` build-time manifest shape → 7B.4 (groups with the carry-forward batch).
3. `agentos test-harness` CLI extension → 7B.2 (co-locates with `agentos conformance` CLI and the OWASP server-side conformance run).

Each sub-sprint ships its own feature branch + PR + closeout. Sub-sprints 7B.2 / 7B.3 / 7B.4 will get their own plan-of-record files written at the start of each sub-sprint.

---

## Doctrine Locks (locked before any code)

These seven items are locked at plan-of-record; reviewer rounds may amend them but no implementation begins until each is settled.

### Doctrine Lock A — PackKind closed-enum is canonical for lifecycle/storage in 7B.1, drift-pinned against existing pack-kind surfaces

**Decision.** `PackKind: TypeAlias = Literal["tool", "skill", "agent", "hook"]` lives at `packs/lifecycle.py`. It is **canonical for lifecycle and storage** — the migration's `kind` CHECK constraint, the storage-layer Pydantic Literal, and the harness's `_HARNESS_SUPPORTED_KINDS` (post-T6a) all derive from it conceptually. It is **not** the source-of-truth for pre-existing pack-kind surfaces — those landed in earlier sprints and continue to own their own constants.

**Pre-existing pack-kind surfaces** (verified at file:line):
- `cli/init.py:73` `_SUPPORTED_KINDS: Final[frozenset[str]] = frozenset({"tool", "skill", "agent", "hook"})`
- `cli/sign.py:197` `_VALID_PACK_KINDS: Final[frozenset[str]] = frozenset({"tool", "skill", "agent", "hook"})`
- `cli/test_harness.py:145` `_HARNESS_SUPPORTED_KINDS: Final[frozenset[str]] = frozenset({"tool"})` — narrowed Wave-1, expanded post-T6a to the full 4-set
- `cli/test_harness.py:173` `_KIND_TO_ENTRY_POINT_GROUP` (3-kind dict, no hook entry) — extended post-T6a to add `"hook" → "cognic.hooks"`

**Drift-pinning.** Single drift-detector test at `tests/unit/test_config.py::TestSprint7B1PackKindVocabulary` (mirrors Sprint-7A2's `TestSprint7A2HookVocabulary` pattern at `test_config.py:1602`). The detector asserts:

- `set(typing.get_args(PackKind)) == _SUPPORTED_KINDS == _VALID_PACK_KINDS == _HARNESS_SUPPORTED_KINDS == set(_KIND_TO_ENTRY_POINT_GROUP) == {"tool","skill","agent","hook"}`

Adding a 5th pack kind in a future sprint requires updating every site or this test fails — by design.

### Doctrine Lock B — PackState closed-enum is the canonical 11-tuple per ADR-012

**Decision.** `PackState: TypeAlias = Literal["draft", "submitted", "under_review", "approved", "rejected", "withdrawn", "allow_listed", "installed", "disabled", "revoked", "uninstalled"]` per ADR-012 §"Lifecycle states" (lines 25-32). The migration's `state` CHECK constraint mirrors this set.

**Drift-pinning.** Same drift-detector test at `TestSprint7B1PackKindVocabulary` extends to assert PackState set equality across the Literal + the migration CHECK constraint (parsed from the version file's DDL).

### Doctrine Lock C — Lifecycle transitions are pure-functional in `packs/lifecycle.py`

**Decision.** The `validate_transition(from_state: PackState, to_state: PackState, kind: PackKind, transition: TransitionName) -> LifecycleRefusalReason | None` function in `packs/lifecycle.py` is **I/O-free and dialect-free**. It consumes only its arguments and returns a closed-enum refusal reason or `None` (transition is valid). The storage layer (`packs/storage.py`) wires it into the `append_with_precondition` precondition closure.

**Why pure.** Decouples state-machine correctness tests from database tests. Sprint-7A2's hook dispatcher took the same approach — the closed-enum decision logic is independently testable from the runtime that consumes it. Mirrors the pattern at `core/escalation.py:_LEGAL_TRANSITIONS`.

**LifecycleRefusalReason closed-enum (provisional 12 values, finalised at T2; state/transition/kind-only — Doctrine Lock G excludes RBAC and evidence checks from the 7B.1 signature):**
- `lifecycle_transition_invalid_state_pair` — from-state has no edge to to-state
- `lifecycle_transition_state_unknown` — from-state or to-state not in the canonical 11-tuple
- `lifecycle_transition_kind_unknown` — kind not in the canonical 4-tuple
- `lifecycle_transition_terminal_state` — from-state is `uninstalled` (no outgoing edges)
- `lifecycle_transition_kind_state_combination_forbidden` — reserved for future kind-specific transition rules
- `lifecycle_transition_double_install` — `installed → installed` attempted on the same tenant
- `lifecycle_transition_revoke_already_revoked` — already-revoked pack
- `lifecycle_transition_uninstall_not_revoked_or_disabled` — uninstall attempted from a state other than `disabled` / `revoked`
- `lifecycle_transition_withdraw_post_review` — withdraw attempted after `under_review` (only `submitted → withdrawn` is allowed)
- `lifecycle_transition_approve_without_review_claim` — `submitted → approved` attempted without claim (must go through `under_review`)
- `lifecycle_transition_disable_not_installed` — disable attempted on a non-installed pack
- `lifecycle_transition_allow_list_not_approved` — `approved → allow_listed` is the only legal entry; refuses `submitted → allow_listed` etc.

**Refusal reasons deferred to later sub-sprints (do NOT belong in 7B.1's pure signature):**
- `actor_role_mismatch` (e.g., `pack.review.approve` requested by an author actor) — needs an `actor` input + role-policy semantics; lands in **Sprint 7B.2** alongside the 14 RBAC scopes per ADR-012 §"RBAC scopes".
- `evidence_required` (e.g., `submitted → approved` requires conformance-suite report) — needs an `evidence` input + evidence-presence semantics; lands in **Sprint 7B.3** alongside the 5-gate approval composition per ADR-012 §"Approval gate composition".

(Full list and exact wording finalised at T2; the count may grow or shrink as the transition table is enumerated.)

### Doctrine Lock D — Lifecycle transitions are atomic via `DecisionHistoryStore.append_with_precondition` (Sprint-2.5 T2 primitive; mirrored at `core/escalation.py:571`)

**Decision.** `PackRecordStore.transition(...)` invokes `DecisionHistoryStore.append_with_precondition(record_builder=..., precondition=...)`.

**Precondition closure does** (under the FOR UPDATE lock on `governance_chain_heads`):
1. `SELECT ... FOR UPDATE` on the pack row in `packs` (locks the row even though the chain-head lock already serialises chain appends — documents future-writer safety; e.g., a Sprint-7B.2 portal endpoint that updates a non-state column on the pack record will need this lock to coexist safely with concurrent transitions).
2. Read current `packs.state` value.
3. Call `lifecycle.validate_transition(...)`. If it returns a non-None `LifecycleRefusalReason`, raise `LifecycleTransitionRefused(reason=...)` → entire transaction rolls back, no chain row, no state update.
4. `UPDATE packs SET state = :new_state, updated_at = :now WHERE id = :pack_id` — preconditions MAY write to non-chain tables under the same transaction per `core/decision_history.py:461-462` ("MUST be SELECT-only against any chain table" — chain table = `decision_history` + `governance_chain_heads`; `packs` is not a chain table).
5. Return captured `from_state` to the `record_builder`.

**`record_builder` builds the DecisionRecord** synchronously, side-effect-free, with:
- `decision_type = f"pack.lifecycle.{to_state}"`
- `request_id = transition_request_id`
- `actor_id = actor_id` (recorded; no RBAC enforcement in 7B.1 per Doctrine Lock G)
- `tenant_id = tenant_id`
- `payload = {"pack_id": ..., "kind": ..., "from_state": ..., "to_state": ..., "transition_name": ..., "evidence_pointer": ..., "iso_controls": [...]}`

**Atomicity guarantee.** Chain `INSERT` + `packs.state` `UPDATE` + `governance_chain_heads` `UPDATE` all commit in a single `engine.begin()` transaction owned by `append_with_precondition`. Failure at any step rolls back all three — fail-closed.

**Chain is the source of truth.** `packs.state` is a denormalized atomically-maintained cache for O(1) state reads (mirrors the `governance_chain_heads` denormalisation doctrine).

**No separate `AuditStore.append` call.** The chain row IS the load-bearing audit primitive per Sprint-2.5 T2 doctrine (cf. `core/escalation.py` which also does not call `AuditStore.append`). `core/audit.py:298 AuditStore.append` owns its own `engine.begin()` (line 334) — caller cannot wrap; so even if we wanted both writes in one transaction, the API doesn't allow it. The chain-only doctrine resolves this by making the chain row the audit event.

### Doctrine Lock E — 4-kind constraint enforced at four layers; single drift detector

**Decision.** Pack kind correctness is enforced at:
1. **Pydantic Literal** at write-time (`PackRecord.kind: PackKind` rejects unknown kinds at construction).
2. **Postgres CHECK constraint** in the migration (`CHECK (kind IN ('tool','skill','agent','hook'))`).
3. **Oracle CHECK constraint** in the migration (same).
4. **Harness frozenset** at dispatch-time (`_HARNESS_SUPPORTED_KINDS` after T6a).

The Sprint-7B1 drift detector covers all four (Doctrine Lock A enumerates the test contract).

### Doctrine Lock F — No portal API in Sprint 7B.1

**Decision.** State machine + storage are exposed only as Python functions / async methods. No HTTP endpoints, no FastAPI routers, no DTO classes. Portal endpoints land in Sprint 7B.2.

**Why.** Decouples lifecycle correctness from HTTP-layer plumbing. Lets reviewer rounds focus on the state machine + storage contracts independently.

### Doctrine Lock G — No RBAC enforcement in Sprint 7B.1

**Decision.** Actor identity is captured in the `DecisionRecord` payload (`actor_id` field) and in the `packs.created_by` / `packs.last_actor` columns. Actor role is **recorded but not gate-checked**. Any caller can request any transition; only the state-machine validity rules apply.

**Why.** RBAC scopes (14 of them per ADR-012 §"RBAC scopes") are tightly coupled to portal API endpoints; both land in Sprint 7B.2. Enforcing role gates inside the state machine would either duplicate or pre-commit the 7B.2 RBAC design.

**Trade-off acknowledged.** A 7B.1 caller that hand-builds a `transition()` call with `actor_id="some-author"` requesting `submitted → approved` will succeed if the state-machine table allows it. This is fine for 7B.1 because there is no production caller — only tests + 7B.2 code that lands afterward. The first 7B.2 endpoint will gate with the matching RBAC scope before calling `transition()`.

---

## ADR amendment slate

**Sprint 7B.1 lands no ADR amendments.** ADR-012 already specifies the state machine (lines 25-32), the storage approach (lines 38-50 evidence-capture column list), and the audit-emission contract (line 82 "All endpoints RBAC-gated. All state transitions emit hash-chained audit events"). The atomic-primitive choice (`DecisionHistoryStore.append_with_precondition`) is consistent with Sprint-2.5 T2 doctrine and `core/escalation.py` precedent — no doctrinal novelty.

Sub-sprints 7B.2 / 7B.3 / 7B.4 may land ADR amendments as their portal-API + evidence-panels + UI-events contracts solidify; those plan-files will enumerate them.

---

## Critical-controls floor extension (gate 41 → 43)

**Sprint 7B.1 promotes two new modules to the 95% line / 90% branch coverage floor:**

- `packs/lifecycle.py` — pure-functional state machine + closed-enum vocabularies; analogous to Sprint-7A2 `packs/hooks/dispatcher.py` doctrine (closed-enum + fail-closed + drift-detector pinning).
- `packs/storage.py` — single point that touches the database for pack records and writes chain events; per-transition transactional integrity.

**Sprint 7B.1 does NOT promote:**
- `cli/test_harness.py` — already a CC-adjacent module; T6a + T6b touch it but the dispatch table was always Wave-1-narrow and the expansion is a planned doctrine evolution, not a critical-controls change to the harness boundary itself.
- The Alembic migration version file — DDL is doctrine-critical (gates kind / state correctness at the database layer) but Alembic versions are not on the 95/90 floor by convention. T4 is marked "CC-adjacent / doctrine-critical DDL; Halt: YES; Gate counted?: NO".

The critical-controls gate count after T7: **41 → 43**.

---

## Tasks

### T1 — Plan-of-record commit + branch creation + BUILD_PLAN.md §611 patch

**Halt: YES** (BUILD_PLAN patch is doctrine).

Land this plan file as a commit on `main` (chore-plan style, mirroring Sprint-7A2's `2ff4336` pre-execution commit). Patch BUILD_PLAN.md §611:

> *Before:* `db/migrations/001_packs_lifecycle.sql (Postgres) and db/migrations/oracle/001_packs_lifecycle.sql (Oracle)`
> *After:* `Alembic version src/cognic_agentos/db/migrations/versions/20260510_0003_packs_lifecycle.py with dialect-portable SQLAlchemy types + PG/Oracle compile tests (raw .sql files were stale doctrine; Alembic infrastructure landed in Sprint 2)`

After the chore-plan commit, create branch `feat/sprint-7b1-lifecycle-state-machine`. T2 onward lands on this branch.

**Files modified:** plan file (new), BUILD_PLAN.md §611.

### T2 — `packs/lifecycle.py` state machine

**Halt: YES** (CRITICAL CONTROLS — new module on the floor).

Create `src/cognic_agentos/packs/lifecycle.py`:
- `PackKind: TypeAlias = Literal["tool", "skill", "agent", "hook"]`
- `PackState: TypeAlias = Literal["draft", ..., "uninstalled"]` (canonical 11-tuple per ADR-012)
- `LifecycleRefusalReason: TypeAlias = Literal[...]` (closed-enum per Doctrine Lock C; final list emerges from the transition-table enumeration)
- `TransitionName: TypeAlias = Literal["submit", "claim", "approve", "reject", "withdraw", "allow_list", "install", "disable", "revoke", "uninstall"]` (10 transitions per ADR-012's transition table)
- `_VALID_TRANSITIONS: Final[Mapping[TransitionName, tuple[PackState, frozenset[PackState]]]]` — keys the transition name to `(from_state, set_of_legal_to_states)` per ADR-012 §"State transitions" table
- `validate_transition(*, from_state: PackState, to_state: PackState, kind: PackKind, transition: TransitionName) -> LifecycleRefusalReason | None` — pure-functional; returns the closed-enum refusal reason or None for valid transitions

Tests at `tests/unit/packs/test_lifecycle.py`:
- All 10 valid transitions succeed (one positive case per transition).
- 12+ representative invalid transitions (one per `LifecycleRefusalReason` — count tracks the closed-enum size finalised at Doctrine Lock C; updated from the pre-R1 14-value enum after `actor_role_mismatch` and `evidence_required` were deferred to Sprint 7B.2 / 7B.3 respectively): `submitted → installed` skipping review; `installed → uninstalled` without going through disabled/revoked; `uninstalled → *` (terminal state); etc.
- Closed-enum drift sanity: `set(get_args(PackKind))` and `set(get_args(PackState))` and `set(get_args(LifecycleRefusalReason))` are non-empty + disjoint.

**Files created:** `src/cognic_agentos/packs/lifecycle.py`, `tests/unit/packs/__init__.py`, `tests/unit/packs/test_lifecycle.py`.

### T3 — `packs/storage.py` PackRecord + PackRecordStore

**Halt: YES** (CRITICAL CONTROLS — new module on the floor).

Create `src/cognic_agentos/packs/storage.py`:
- `class PackRecord(BaseModel)` — Pydantic model: `id: uuid.UUID`, `kind: PackKind`, `pack_id: str` (manifest-declared identifier), `display_name: str`, `state: PackState`, `manifest_digest: bytes`, `signed_artefact_digest: bytes`, `sbom_pointer: str | None`, `tenant_id: str | None`, `created_by: str`, `last_actor: str`, `created_at: datetime`, `updated_at: datetime`. Frozen + extra=forbid.
- `class PackRecordStore` — async API:
  - `__init__(self, engine: AsyncEngine) -> None: self._engine = engine; self._history = DecisionHistoryStore(engine)` (mirrors `core/escalation.py:463-465`)
  - `async def save_draft(self, record: PackRecord) -> uuid.UUID` — inserts a `draft`-state pack record, returns id; emits no chain event (draft creation is not a transition; it is the entry point to the state machine).
  - `async def transition(self, *, pack_id: uuid.UUID, transition: TransitionName, actor_id: str, tenant_id: str | None, evidence_pointer: str | None, iso_controls: tuple[str, ...]) -> tuple[uuid.UUID, bytes]` — wires `DecisionHistoryStore.append_with_precondition` per Doctrine Lock D. Returns `(record_id, hash)` from the chain insert.
  - `async def load(self, pack_id: uuid.UUID) -> PackRecord | None` — non-chain read via `async with self._engine.connect() as conn` (mirrors `core/escalation.py:690+719`).
  - `async def list_by_status(self, state: PackState, limit: int = 50, cursor: uuid.UUID | None = None) -> list[PackRecord]` — paginated state-filter read.
  - `async def load_lifecycle_history(self, pack_id: uuid.UUID) -> list[DecisionRecord]` — walks `decision_history.event_type LIKE 'pack.lifecycle.%'` filtered to `payload['pack_id'] == str(pack_id)` (mirrors `core/escalation.py:_read_current_state_within_txn` JSON-key extraction approach).
- Closed-enum exception class `LifecycleTransitionRefused(Exception)` carrying the `LifecycleRefusalReason`.

Tests are split into **shape tests** (SQLite, unit) and **integration tests** (live Postgres + Oracle) — mirroring the Sprint 2.5 escalation pattern. SQLite cannot prove `SELECT ... FOR UPDATE` row-locking serialisation because SQLite uses database-level locks, not row locks; the in-memory adapter at `tests/support/adapter_fixtures.py:30-60` is `InMemoryRelationalAdapter` (`sqlite+aiosqlite:///:memory:` per `:45`), so concurrency invariants must be proven against real PG / Oracle.

**SQLite/unit shape tests** at `tests/unit/packs/test_storage.py` (using `InMemoryRelationalAdapter` from `tests/support/adapter_fixtures.py`):
- `save_draft` then `load` round-trips a `PackRecord` with `state="draft"`.
- `transition(submit)` moves state from `draft → submitted`; chain row inserted with `event_type="pack.lifecycle.submitted"`; `packs.state="submitted"` after transition (atomicity is asserted at the API contract level here; the lock-serialisation proof lives in the integration tests below).
- `transition(submit)` from a non-draft state raises `LifecycleTransitionRefused(reason="lifecycle_transition_invalid_state_pair")`; **no chain row inserted** (chain count before + after); **no state cache mutation** (`packs.state` unchanged).
- `list_by_status("submitted")` returns only `submitted`-state packs.
- `load_lifecycle_history(pack_id)` returns the chain rows in `sequence` order.
- Pydantic validation rejects `kind="other"` at `PackRecord` construction.

**PG/Oracle integration tests** at `tests/integration/packs/test_storage_lock_serialisation.py` (live Postgres + Oracle; gated on the same env-vars existing PG/Oracle integration suites use; mirrors Sprint 2.5 escalation T3 lock-serialisation tests):
- **`SELECT ... FOR UPDATE` proof:** Pin that the precondition acquires a row-level lock on the pack row before reading state, so a concurrent writer to a non-state column (e.g., a Sprint-7B.2 portal endpoint updating `last_actor`) blocks until the transition commits. Pattern: open two `engine.begin()` transactions; T1 calls `transition()` (which holds the row lock under `append_with_precondition`); T2 attempts a `SELECT ... FOR UPDATE` on the same pack row and must block; T1 commits; T2 unblocks.
- **Competing-transition serialisation:** Two `transition()` calls fired concurrently via `asyncio.gather(...)` for the same pack record — exactly one wins; the loser's `validate_transition` runs against the new (already-advanced) head state and raises `LifecycleTransitionRefused`. The losing transaction rolls back cleanly; chain count incremented exactly once.
- **Cross-dialect schema verification:** Migration upgrade + downgrade cycle on real Postgres + real Oracle (not just compile-test) confirms CHECK constraints reject `kind='other'` and `state='quarantined'` inserts at the database layer.

**Files created:** `src/cognic_agentos/packs/storage.py`, `tests/unit/packs/test_storage.py`, `tests/integration/packs/test_storage_lock_serialisation.py`.

### T4 — Alembic migration `20260510_0003_packs_lifecycle.py`

**Halt: YES** (CC-adjacent / doctrine-critical DDL). **Gate counted?: NO** — DDL is not on the 95/90 floor by convention.

Create `src/cognic_agentos/db/migrations/versions/20260510_0003_packs_lifecycle.py` mirroring the prior versions' style (`20260428_0001_initial_governance_schema.py` + `20260430_0002_gateway_call_ledger.py`):

Schema for `packs` table — types follow existing migration helpers (verified against `20260428_0001_initial_governance_schema.py:61` import line + per-column usages at lines 87 / 138-139 / 152-153 / `20260430_0002_gateway_call_ledger.py:73`):

- `id sa.Uuid()` PRIMARY KEY (mirrors `20260430_0002_gateway_call_ledger.py:73` and `20260428_0001_*.py:123` — **not** `sa.dialects.postgresql.UUID(as_uuid=True)`; `sa.Uuid()` is the dialect-portable seam used throughout this repo)
- `kind sa.String(16)` NOT NULL with CHECK constraint `kind IN ('tool', 'skill', 'agent', 'hook')`
- `pack_id sa.String(256)` NOT NULL (manifest-declared identifier; not unique across tenants per ADR-012 §"Cross-tenant complications")
- `display_name sa.String(256)` NOT NULL
- `state sa.String(32)` NOT NULL with CHECK constraint `state IN ('draft', 'submitted', 'under_review', 'approved', 'rejected', 'withdrawn', 'allow_listed', 'installed', 'disabled', 'revoked', 'uninstalled')`
- `manifest_digest chain_hash_column_type()` NOT NULL — fixed 32-byte SHA-256 digest material; the helper at `cognic_agentos.db.types.chain_hash_column_type` compiles to **Postgres BYTEA / Oracle RAW(32) / SQLite BLOB** per the cross-dialect comment at `20260428_0001_*.py:35-38`. Sprint-7A1 ships SHA-256 manifest digests; this column reuses the chain-integrity-material type.
- `signed_artefact_digest chain_hash_column_type()` NOT NULL — same shape; cosign-signed-blob digest is also 32-byte SHA-256.
- `sbom_pointer sa.Text()` NULL — opaque object-store key; `sa.Text()` is dialect-portable.
- `tenant_id sa.String(256)` NULL
- `created_by sa.String(256)` NOT NULL
- `last_actor sa.String(256)` NOT NULL
- `created_at sa.TIMESTAMP(timezone=True)` NOT NULL — **NOT** `sa.DateTime(timezone=True)`; per the existing migration doctrine at `20260430_0002_gateway_call_ledger.py:49+65-67` (`GATEWAY_LEDGER_TS_TYPE = sa.TIMESTAMP(timezone=True)` with the explicit comment "`sa.DateTime(timezone=True)` here causes Oracle compile output to" lose offsets / compile to plain `DATE`). `sa.TIMESTAMP(timezone=True)` compiles to `TIMESTAMP WITH TIME ZONE` on both Oracle and Postgres, matching the Sprint 2 `audit_event.created_at` + `decision_history.created_at` convention at `20260428_0001_initial_governance_schema.py:90+142`.
- `updated_at sa.TIMESTAMP(timezone=True)` NOT NULL — same Oracle-safe type as `created_at`.

**Type-helper imports** (mirror `20260428_0001_*.py:61`):
```python
from cognic_agentos.db.types import chain_hash_column_type
```

`GovernanceJSON` is **not** needed for this migration — the packs table has no JSON-payload columns; structured manifest content lives in object storage referenced by `sbom_pointer` and (in 7B.3) in evidence-panel records keyed by pack id.

Indexes:
- `(kind, state)` — supports `list_by_status` filter
- `(tenant_id, state)` — supports per-tenant queue queries (for Sprint 7B.2 portal API)

Use `op.create_check_constraint(...)` for the kind / state CHECK constraints so the migration is dialect-portable.

Tests are split into **unit compile/type tests** and **integration live-DB tests** — mirroring the existing repo pattern (`tests/unit/db/test_run_migrations.py` is unit; `tests/integration/db/test_alembic_migrations.py` is live-DB). Normal unit runs MUST NOT require a live database.

**Unit compile/type tests** at `tests/unit/db/test_migration_20260510_0003.py` (no live DB) — use the existing direct-dialect-compile seam mirrored from `tests/unit/db/test_run_migrations.py:395-419` and `tests/unit/db/test_types.py:25-35`:

```python
from sqlalchemy.dialects import oracle, postgresql

# Pattern A — column-type compilation (per test_run_migrations.py:408-409):
oracle_compiled = some_column_type.compile(dialect=oracle.dialect())  # type: ignore[no-untyped-call]
postgres_compiled = some_column_type.compile(dialect=postgresql.dialect())  # type: ignore[no-untyped-call]

# Pattern B — full table DDL compilation (per test_types.py:35):
ddl = str(sa.schema.CreateTable(packs_table).compile(dialect=postgresql.dialect()))  # type: ignore[attr-defined]
```

`sa.create_mock_engine(...)` is **not** the right seam — its actual signature is `(url, executor, **kw)` (the dialect comes from the URL), and existing repo tests do not use it for compile-only checks.

Test bullets (using the patterns above):
- Postgres compile (`postgresql.dialect()`): emit the full `packs` table DDL via `CreateTable.compile(...)`; verify the rendered DDL contains `TIMESTAMP WITH TIME ZONE` for `created_at` + `updated_at` (NOT plain `TIMESTAMP` or `DATE`); verify it contains `BYTEA` for `manifest_digest` + `signed_artefact_digest`; verify CHECK constraints on `kind` and `state` are present in the rendered DDL.
- Oracle compile (`oracle.dialect()`): same DDL render; verify `TIMESTAMP WITH TIME ZONE` for the timestamp columns (the doctrine pin from R2); verify `RAW(32)` for the digest columns; verify CHECK constraint syntax is Oracle-portable.
- Per-column type drift detector: compile the bare `chain_hash_column_type()` instance under both dialects (mirror `test_run_migrations.py:408-409`); assert `"RAW(32)"` on Oracle and `"BYTEA"` on Postgres — pins regression-against-`sa.LargeBinary` or `sa.DateTime(timezone=True)` substitutions.
- Schema-shape assertions on the `Table` object (no compile required): column names, types, nullability, CHECK constraint definitions present in `packs_table.c[...]` and `packs_table.constraints`.
- Type-helper import drift detector: the migration imports `chain_hash_column_type` from `cognic_agentos.db.types` (not redefined inline) — pinned via `inspect.getsource(...)` on the migration module.

**Integration live-DB tests** at `tests/integration/db/test_alembic_migration_20260510_0003.py` (env-gated on the same flags `tests/integration/db/test_alembic_migrations.py` already uses):
- Migration upgrade runs against live Postgres; `packs` table exists with all columns + CHECK constraints (verified via `information_schema` queries).
- Migration downgrade reverses cleanly.
- CHECK constraint enforcement on Postgres: insert with `kind='other'` raises an `IntegrityError`; insert with `state='quarantined'` raises.
- Migration upgrade runs against live Oracle (when the Oracle env-gate is set); same shape assertions; CHECK constraints enforce on Oracle insert.

**Files created:** `src/cognic_agentos/db/migrations/versions/20260510_0003_packs_lifecycle.py`, `tests/unit/db/test_migration_20260510_0003.py`, `tests/integration/db/test_alembic_migration_20260510_0003.py`.

### T5 — ISO 42001 control mapping + fail-closed semantics tests

**Halt: YES** (CRITICAL CONTROLS — touches the chain-emission contract).

Per ADR-006 ISO 42001 control mapping and ADR-012 §"All state transitions emit hash-chained audit events tagged with applicable ISO 42001 controls":

Map each `pack.lifecycle.<state>` event type to the relevant ISO 42001 controls and pin the mapping in code:
- `pack.lifecycle.submitted` → `("A.5.31", "A.6.2.4")` — system-acquisition + governance-overrides preparation
- `pack.lifecycle.approved` → `("A.5.31", "A.6.2.4")` — approval is a governance gate
- `pack.lifecycle.rejected` → `("A.5.31",)` — rejection is documented but not an override
- `pack.lifecycle.installed` → `("A.5.31", "A.5.32")` — install activates the pack on a tenant
- `pack.lifecycle.disabled` → `("A.5.32",)` — operational control
- `pack.lifecycle.revoked` → `("A.5.32", "A.6.2.4")` — security-incident path

(Exact control codes finalised at T5 against the ADR-006 mapping table.)

Add the `iso_controls` tuple to the `DecisionRecord.payload` for every transition.

Tests at `tests/unit/packs/test_lifecycle_audit.py`:
- Fail-closed: precondition-raises (`LifecycleTransitionRefused`) → no chain row written + no state cache mutation (verified by querying both before + after the call).
- Fail-closed: state-machine table mismatch on chain head advance (concurrent test) → both writers' `validate_transition` runs; loser's transaction rolls back cleanly.
- Concurrent-transition test (two `asyncio.gather(...)` calls) → exactly one wins; chain insert + state UPDATE atomic; loser raises.
- ISO control tags appear in the `DecisionRecord.payload['iso_controls']` field for every transition type.
- Chain integrity: `core/chain_verifier.verify_chain(...)` over the full lifecycle slice succeeds (Merkle proof valid).

**Files created:** `tests/unit/packs/test_lifecycle_audit.py`.

### T6a — Harness vocabulary + refusal expectation flips

**Halt: YES** (touches harness boundary).

Edit `src/cognic_agentos/cli/test_harness.py`:
- Line 145: `_HARNESS_SUPPORTED_KINDS: Final[frozenset[str]] = frozenset({"tool"})` → `frozenset({"tool", "skill", "agent", "hook"})`.
- Lines 173-177: extend `_KIND_TO_ENTRY_POINT_GROUP` to add `"hook": "cognic.hooks"` (currently absent — only the 3-kind dict).
- Update the docstring at lines 130-145 to remove the "Wave-1 narrow" caveat now that the harness supports all 4 kinds.

Tests at `tests/unit/cli/test_harness_vocabulary.py`:
- The four reference packs at `examples/cognic-{tool,skill,agent,hook}-example-minimal/` no longer trigger `harness_unsupported_pack_kind`. (Green-path lands in T6b; this test only asserts the refusal stops happening — it expects either green-path or a different refusal.)
- A synthetic 5th pack kind (`workflow`, made-up) still triggers `harness_unsupported_pack_kind` — unknown-kind refusal path retained.
- `_KIND_TO_ENTRY_POINT_GROUP["hook"] == "cognic.hooks"`.
- The drift-detector test from Doctrine Lock A asserts `_HARNESS_SUPPORTED_KINDS == set(_KIND_TO_ENTRY_POINT_GROUP) == set(get_args(PackKind))`.

**Files modified:** `src/cognic_agentos/cli/test_harness.py`.
**Files created:** `tests/unit/cli/test_harness_vocabulary.py`.

### T6b — Per-kind dry-run dispatch impls (public SDK seams)

**Halt: YES** (extends harness dispatch beyond Tool-only).

Implement per-kind dispatch in `cli/test_harness.py` using **public SDK seams** (verified at `sdk/agent.py:41-77` + `sdk/hook.py:221-289+347`):

- **Tool** (existing): unchanged.
- **Skill**: instantiate the loaded skill class with a `ToolRegistry` fixture (test-only fixture from `tests/support/`); dry-run via the public `execute(...)` method.
- **Agent**: instantiate the loaded agent class — `Agent` is `abc.ABC` (per `sdk/agent.py:41`) with `name: ClassVar[str]` + `declared_capabilities: ClassVar[A2ACapabilities]` (`:48-49`); the `__init__` takes no LLM-gateway / no constructor parameters beyond what `abc.ABC` provides. Dry-run via `await agent.handle(payload, task=TaskRecord(...))` (the abstract method declared at `:51-77`) — NOT a private method.
- **Hook**: instantiate the loaded hook class; dry-run via the **public `Hook.invoke(context, payload)` seam** at `sdk/hook.py:347` (NOT the abstract `_invoke` at `sdk/hook.py:373`). The public `invoke` runs three SDK validation phases:
  1. **`_validate_hook_context`** at `sdk/hook.py:221-231` — fires BEFORE `_invoke`; raises `HookContextError` if context is None or non-`HookContext`.
  2. **`_validate_hook_payload`** at `sdk/hook.py:234-241` — fires BEFORE `_invoke`; raises `HookPayloadError` if payload is None or non-`bytes`.
  3. **`_validate_hook_result`** at `sdk/hook.py:244-288` — fires AFTER `_invoke` returns; raises `HookResultShapeError` on non-`HookResult` shape, on `decision=pass/refuse` with non-None `redacted_payload`, on `decision=redact/mask` with None / non-bytes `redacted_payload`, on `decision=refuse` with empty / whitespace `policy_reason`, or on `decision in {pass,redact,mask}` with non-None `policy_reason`.

  Calling `_invoke` directly would bypass all three validation phases and let SDK contract violations slip past the dry-run.

Add per-kind fixture adapters under `tests/support/harness_dispatch_fixtures.py`:
- `make_tool_registry_fixture()` — returns a `ToolRegistry` populated with a no-op tool for skill dispatch.
- `make_task_record_fixture(payload: bytes) -> TaskRecord` — returns a synthetic A2A `TaskRecord`.
- `make_hook_context_fixture() -> HookContext` — returns a synthetic `HookContext` with audit + tenant fields populated.

Tests at `tests/unit/cli/test_harness_dispatch.py` use the existing harness public shape (verified at `cli/test_harness.py:240-282`): `DispatchResult.status: Literal["pass", "fail"]` (`:257`); `HarnessReport.overall_status: Literal["pass", "fail"]` (`:278`); on dispatch failure `failure_reason: HarnessReason | None` carries a closed-enum `HarnessReason` value (`:259`; full vocabulary at `:123-137`) AND `failure_message: str | None` carries the human-readable detail including the exception type / message (`:260`). Hook SDK validation raises EXCEPTION CLASSES (`HookContextError` / `HookPayloadError` / `HookResultShapeError` per `sdk/hook.py:90+97+103`), NOT closed-enum reason strings. The harness dispatch path catches these exceptions and routes them via `failure_reason="harness_dispatch_failed"` (existing closed-enum value at `cli/test_harness.py:129`) + the exception class name surfaced in `failure_message`.

Green-path tests:
- Tool reference pack: dry-run succeeds; `HarnessReport.overall_status == "pass"`; the matching `DispatchResult.status == "pass"`.
- Skill reference pack: instantiate w/ ToolRegistry fixture, `execute(...)` dry-run succeeds; `overall_status == "pass"`.
- Agent reference pack: `await agent.handle(payload, task=TaskRecord)` dry-run succeeds; `overall_status == "pass"`.
- Hook reference pack: `Hook.invoke(context, payload)` dry-run succeeds; `overall_status == "pass"`.

**Hook public-seam validation pinning** — three pinning regressions, one per `Hook.invoke` validator phase. None of these test a hook whose `_invoke` raises `HookContextError` directly (that would only prove the subclass raises, not that the SDK validator ran):
- **Pre-`_invoke` context validation:** the harness passes an invalid context value (None or non-`HookContext`) into a hook whose `_invoke` would otherwise return a valid `HookResult`; `Hook.invoke` raises `HookContextError` BEFORE `_invoke` runs (verified by the subclass's `_invoke` not being called — assert via instrumented mock counter); `DispatchResult.status == "fail"`, `failure_reason == "harness_dispatch_failed"`, `failure_message` contains `"HookContextError"` so the SDK validator's intent is provable through the exception type name.
- **Pre-`_invoke` payload validation:** same shape for payload — pass `None` or non-`bytes` into a green-`_invoke` hook; `Hook.invoke` raises `HookPayloadError` BEFORE `_invoke` runs; same instrumented-mock pinning; `failure_message` contains `"HookPayloadError"`.
- **Post-`_invoke` result-shape validation:** load a hook whose `_invoke` returns a malformed `HookResult` (e.g., `decision="redact"` with `redacted_payload=None`, or returns a non-`HookResult` object); `Hook.invoke` raises `HookResultShapeError` AFTER `_invoke` returns; `DispatchResult.status == "fail"`, `failure_reason == "harness_dispatch_failed"`, `failure_message` contains `"HookResultShapeError"`.

T6b does NOT add new `HarnessReason` closed-enum values — the existing `harness_dispatch_failed` reason at `:129` already covers "Instantiation / invoke raised" per the docstring at `:563`. If reviewer rounds want hook-specific reasons (e.g., `harness_hook_dispatch_context_invalid`), that would land as an explicit closed-enum extension; for the initial T6b landing, exception type discrimination through `failure_message` is sufficient.

**Files modified:** `src/cognic_agentos/cli/test_harness.py` (dispatch impls).
**Files created:** `tests/support/harness_dispatch_fixtures.py`, `tests/unit/cli/test_harness_dispatch.py`.

### T7 — Critical-controls floor extension: AGENTS.md subsection + coverage gate 41 → 43

**Halt: YES** (AGENTS.md is doctrine).

Edit `AGENTS.md`:
- New "Authoring — Bank pack lifecycle (Sprint 7B.1)" subsection naming the **2 promoted modules**:
  - `packs/lifecycle.py` (per Doctrine Lock C — pure-functional state machine; closed-enum vocabularies; LifecycleRefusalReason)
  - `packs/storage.py` (per Doctrine Lock D — `DecisionHistoryStore.append_with_precondition` consumer; row-locked precondition; atomic chain-insert + state-cache UPDATE)

Edit the critical-controls coverage gate at **`tools/check_critical_coverage.py`** (the 41-module enumeration lives here per `tools/check_critical_coverage.py:160` "gate size grows from 37 modules to 41" comment from the Sprint-7A2 T12 promotion; runs against `coverage.json` produced by `pytest --cov-report=json`):
- Add `packs/lifecycle.py` + `packs/storage.py` to the 95% line / 90% branch floor list (the new gate size grows from 41 modules to 43).
- Update the module-grouping comment at the head of the file to add a "Sprint 7B.1 — Bank pack lifecycle (state machine + storage)" group, mirroring the Sprint-7A2 group at lines 120-160.
- Run `uv run pytest --cov=src/cognic_agentos/packs/lifecycle --cov=src/cognic_agentos/packs/storage --cov-report=term-missing` to confirm both modules clear the floor.
- Run `uv run python tools/check_critical_coverage.py` to confirm the full 43-module gate is green.

Run full local gate per `feedback_full_gate_pre_commit.md`:
- `uv run mypy src tests` (full-tree)
- `uv run ruff check . && uv run ruff format --check .`
- `uv run pytest -q` (full-suite at commit-time per `feedback_gate_ladder_per_microfix.md`)

**Files modified:** `AGENTS.md` (new subsection); `tools/check_critical_coverage.py` (coverage gate floor list).

### T8 — Closeout doc + BUILD_PLAN.md §602 status flip + Sprint 7B.2 hand-off checklist

**Halt: YES** (doctrine documents).

Create `docs/closeouts/2026-05-XX-sprint-7b1-lifecycle-state-machine.md` (date set at closeout; mirrors Sprint-7A2 closeout style):
- Sprint 7B.1 deliverables landed (state machine + storage + Alembic migration + ISO control mapping + harness 4-kind expansion).
- Per-task summary with commit hashes.
- ADR amendments (none for 7B.1 per slate above).
- Critical-controls promotion: 2 modules + gate count 41 → 43.
- 14 doctrine entries (or however many emerged from reviewer rounds).
- Sprint 7B.2 hand-off checklist:
  - [ ] Portal API endpoints: 4 surfaces × ~24 endpoints
  - [ ] 14 RBAC scopes per ADR-012
  - [ ] OWASP Agentic Top 10 + Agentic Skills Top 10 conformance suite
  - [ ] `agentos conformance` CLI extension
  - [ ] `agentos test-harness` CLI extension (per ADR-012 §"Local governance test harness")
  - [ ] Auto-run conformance on `submit` transition; attach failure to evidence

Patch BUILD_PLAN.md §602 status:
- *Before:* `### Sprint 7B — Bank pack lifecycle API + workflow + UI event-stream endpoints *(3.5 work-units)*`
- *After:* `### Sprint 7B — Bank pack lifecycle API + workflow + UI event-stream endpoints *(3.5 work-units; pre-split per BUILD_PLAN §1142 schedule-risk fallback into 7B.1 + 7B.2 + 7B.3 + 7B.4)*`
- Add status row: `**7B.1 (Lifecycle state machine + storage + harness 4-kind expansion):** CLOSED — landed at <commit-sha> on <date>; gate 41 → 43; 2 CC modules promoted (`packs/lifecycle.py`, `packs/storage.py`).`

**Files created:** closeout doc.
**Files modified:** BUILD_PLAN.md §602.

---

## Self-Review

After writing the complete plan, looked at ADR-012 deliverables / BUILD_PLAN.md §602 / Sprint-7A2 carry-forward checklist with fresh eyes:

**Spec coverage (Sprint 7B.1 scope only):**
- ✅ ADR-012 §"Lifecycle states" 11-state taxonomy → Doctrine Lock B + T2 transition table.
- ✅ ADR-012 §"State transitions" table (10 transitions) → T2 `_VALID_TRANSITIONS` table + T3 transition() API.
- ✅ ADR-012 §"All state transitions emit hash-chained audit events tagged with applicable ISO 42001 controls" → T5.
- ✅ Sprint-7A2 closeout hand-off "Harness expansion to skill + agent + hook dispatch" → T6a + T6b.
- ✅ BUILD_PLAN.md §609 `packs/lifecycle.py` state machine → T2.
- ✅ BUILD_PLAN.md §610 `packs/storage.py` Postgres-backed pack-record store → T3.
- ✅ BUILD_PLAN.md §611 migrations (Postgres + Oracle) → T4 (with §611 patch in T1 to switch from raw .sql to Alembic).
- ✅ BUILD_PLAN.md §637 `pack.lifecycle` event emission → T3 (via `append_with_precondition`) + T5 (ISO controls).

**Spec gaps (deliberate; deferred to 7B.2/3/4 by Doctrine Locks F + G):**
- Portal API endpoints (BUILD_PLAN §613-617) → 7B.2.
- RBAC scopes (BUILD_PLAN §619-623) → 7B.2.
- OWASP conformance integration (BUILD_PLAN §625-628) → 7B.2.
- Reviewer evidence panels (BUILD_PLAN §630-634) → 7B.3.
- 5-gate approval composition → 7B.3.
- UI event-stream endpoints (BUILD_PLAN §640-645) → 7B.4.
- 7A/7A2 carry-forward (auto-attestation API + compliance helper emit + fail_open_exception build-time shape) → 7B.4.

**Doctrine touchpoints flagged for explicit halt-before-commit:**
- BUILD_PLAN.md §611 (T1 patch).
- AGENTS.md "Authoring — Bank pack lifecycle (Sprint 7B.1)" subsection (T7).
- BUILD_PLAN.md §602 status flip (T8).
- Closeout doc (T8).

**Critical-controls promotion (Doctrine Decision G inheritance from Sprint-7A2 T16):**
- 2 modules promote at T7: `packs/lifecycle.py`, `packs/storage.py`.
- Alembic migration version file stays off the 95/90 floor (DDL doctrine-critical but not coverage-tracked by convention; T4 marked Halt: YES + Gate counted?: NO).
- `cli/test_harness.py` stays off the floor (already CC-adjacent; T6a + T6b are doctrine evolutions of an existing harness boundary).

**Halt-before-commit map (per-task):**

| Task | Halt? | CC? | Why |
|---|---|---|---|
| T1 | YES | — | BUILD_PLAN.md §611 patch is doctrine |
| T2 | YES | YES | New CC module (`packs/lifecycle.py`) |
| T3 | YES | YES | New CC module (`packs/storage.py`) |
| T4 | YES | NO (CC-adjacent) | Doctrine-critical DDL; Gate counted?: NO |
| T5 | YES | YES | Touches chain-emission contract |
| T6a | YES | NO | Harness boundary doctrine evolution |
| T6b | YES | NO | Per-kind dispatch impls; SDK-seam-correctness load-bearing |
| T7 | YES | YES | AGENTS.md + coverage gate config |
| T8 | YES | — | AGENTS.md + BUILD_PLAN + closeout (all doctrine) |

---

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-05-10-sprint-7b1-lifecycle-state-machine.md`.

**Next:** halt for plan review against doctrine. Specifically requesting confirmation of:

1. **The 7 doctrine locks A-G** — any adjustments before T1 begins?
2. **The ADR amendment slate** (none for 7B.1) — agreed?
3. **Critical-controls promotion list** (2 modules: `packs/lifecycle.py` + `packs/storage.py`; Alembic migration off-floor per Doctrine F gate-counting rule) — adjust?
4. **Sub-sprint allocation** (7B.1 lifecycle/storage/harness; 7B.2 portal/RBAC/OWASP; 7B.3 evidence/5-gate; 7B.4 UI events + carry-forward) — agreed?
5. **Atomic-primitive choice** (`DecisionHistoryStore.append_with_precondition` mirroring `core/escalation.py:571` pattern) — agreed, or prefer adding a new `AuditStore.append_with_precondition` primitive instead?

No code begins until each lock is confirmed.
