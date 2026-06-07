# Per-Tenant Config Overlay (Wave-2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a governed, human-only, tighten-only per-tenant configuration overlay (substrate + 2 proven consumers — sandbox resource caps and memory export retention) per the committed spec `docs/superpowers/specs/2026-06-06-per-tenant-config-overlay-design.md`.

**Architecture:** A closed in-code registry declares which `Settings` fields are overridable and in which direction (ceiling/floor); a Postgres-backed store mutates overlays through `DecisionHistoryStore.append_with_precondition` (in-closure upsert/delete + chain row, atomic); a request-time resolver applies the tighten-only merge at the two consumer call-sites (explicit point resolution — both already hold `tenant_id`); a human-only, operator-administered FastAPI endpoint is the only mutation surface. Default-deny: anything not in the registry is kernel-locked.

**Tech Stack:** Python 3.12, pydantic-settings, SQLAlchemy async + Alembic, FastAPI, pytest (`uv run`), OPA/Rego (unchanged — the sandbox bundle already consumes `tenant_max`).

> **PLAN STATUS (2026-06-06):** This is the saved Wave-2 plan-of-record. Per the post-review decision, **execution is paused** until a short review-remediation sprint closes the verified kernel defects from `docs/reviews/2026-06-06-multiagent-code-review.md` (MCP SSRF §4.1, scheduler tenant-blind counters §4.2, memory agent-kind erasure §4.3, pack override-audit invisibility §4.4, and the `sampling.rego` v0-syntax bundle). Return to this plan on the cleaner base.

---

## Commit & CC discipline (READ FIRST — applies to every task)

- **Halt-before-commit on EVERY task** below — all are critical-controls (new `core/config_overlay/*`, `portal/api/config_overlay/routes.py`, or edits to stop-rule modules `sandbox/*`, `core/memory/*`, `portal/rbac/*`, `compliance/*`, `core/config.py`, the migration, the CC-gate tool). Use `/critical-module-mode` + `core-controls-engineer`. The "Commit" step is **"produce the halt-before-commit summary and STOP for the user's commit token"** — never self-commit.
- **Explicit-path staging only.** `git add <exact .py/.md paths>` — never `git add .`/`-A`/directories. **Never stage** `docs/reviews/2026-06-06-multiagent-code-review.md` or `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md` (both intentionally untracked).
- **Gate ladder at commit:** targeted tests + affected slice + `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests` + the focused regressions; **full suite (`uv run pytest`) at commit for any shared-surface / CC-gate / storage / sandbox / RBAC / composition-root task.**
- **Commit footer:** `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`. Branch: `feat/per-tenant-config-overlay` (spec + closeout already committed at `6900b4e`/`fd38591`).
- **CC-gate count is provisional `113 → 117`** — verify the four promoted modules meet the floor against FRESH full-package `--cov` coverage **at the Task 11 commit** (`feedback_verify_promotion_meets_floor_at_promotion_time`), and reconcile final file names then.

---

## File Structure

**New (4 CC modules + package inits + migration + ADR):**
- `src/cognic_agentos/core/config_overlay/__init__.py` — package re-exports.
- `src/cognic_agentos/core/config_overlay/registry.py` *(CC)* — `OverlayDirection`, `OverridableField`, `REGISTRY` (4 entries), `validate_tighten_only`, `coerce_value` (strict), the `OverlayRefusalReason` Literal (6 values), `TenantOverlayRejected`.
- `src/cognic_agentos/core/config_overlay/storage.py` *(CC)* — `TenantConfigOverlayStore` + the `_tenant_config_overlay` Table + `TenantConfigOverlayRow`.
- `src/cognic_agentos/core/config_overlay/resolver.py` *(CC)* — `TenantConfigResolver` (`effective_many`/`effective`) + `_OverlayStore` Protocol + `TenantConfigOverlayInvalid`/`TenantConfigKeyError` + the `invalid_at_read` audit emit + throttle.
- `src/cognic_agentos/portal/api/config_overlay/__init__.py`.
- `src/cognic_agentos/portal/api/config_overlay/routes.py` *(CC)* — `build_config_overlay_routes(*, store, resolver, settings)` + PUT/DELETE/GET + DTOs + request-id minters.
- `src/cognic_agentos/db/migrations/versions/20260606_0007_tenant_config_overlay.py` *(CC)* — the table + unique index.
- `docs/adrs/ADR-023-per-tenant-config-overlay.md` — the ADR.

**Modified (stop-rule + composition + gate):**
- `src/cognic_agentos/core/config.py` *(CC)* — add `config_overlay_invalid_at_read_throttle_s: int`.
- `src/cognic_agentos/portal/rbac/scopes.py` *(CC)* — `ConfigOverlayRBACScope` + `CONFIG_OVERLAY_SCOPES`.
- `src/cognic_agentos/portal/rbac/actor.py` *(CC)* — add `ConfigOverlayRBACScope` to the `Actor.scopes` union.
- `src/cognic_agentos/portal/rbac/enforcement.py` *(CC)* — add `ConfigOverlayRBACScope` to the `RequireScope` param union.
- `src/cognic_agentos/sandbox/protocol.py` *(CC)* — add `sandbox_tenant_config_overlay_invalid` to `SandboxRefusalReason`.
- `src/cognic_agentos/sandbox/admission.py` *(CC)* — `admit_policy` gains `resolver`; Step 5 + Step 9 use `effective_many`.
- `src/cognic_agentos/core/memory/tiers.py` *(CC)* — add `memory_export_tenant_config_overlay_invalid` to `MemoryRefusalReason`.
- `src/cognic_agentos/core/memory/api.py` *(CC)* — `MemoryAPI.__init__` gains `resolver`; `export()` resolves retention.
- `src/cognic_agentos/compliance/iso42001/controls.py` *(CC)* — add `config.tenant_overlay.set`/`.cleared` to `A.6.2.5` `intended_hooks`.
- `src/cognic_agentos/harness/runtime.py` *(off-gate)* — build store+resolver; inject into MemoryAPI factory; expose on `Runtime`; mount the endpoint via app.py.
- `src/cognic_agentos/portal/api/app.py` *(off-gate)* — mount `build_config_overlay_routes` under `/api/v1`.
- `tests/unit/core/memory/conftest.py` *(test)* — `_build_api` threads a default resolver (ripple from the MemoryAPI ctor change — see Task 8).
- `tools/check_critical_coverage.py` + `tests/unit/tools/test_check_critical_coverage.py` — add the 4 modules, bump count to 117.

**SEAM HONESTY (sandbox):** `admit_policy` is the resolver seam and is **unit-proven**. There is **no** production `get_backend(...)` caller and `build_runtime()` does **not** own a sandbox backend today, so the sandbox overlay is wired at the admission seam, **not** consumed end-to-end through `Runtime`. Tasks 7 & 10 reflect this (no overclaim of a Runtime→sandbox production path). The memory overlay **is** production-wired through the `Runtime` MemoryAPI factory.

**Dependency order:** registry → migration → storage → resolver → RBAC scope → endpoint → sandbox wiring → memory wiring → ISO hooks → composition root → CC-gate → ADR.

---

### Task 1: Field registry + strict tighten-only validator

**Files:**
- Create: `src/cognic_agentos/core/config_overlay/__init__.py`, `src/cognic_agentos/core/config_overlay/registry.py`, `tests/unit/core/config_overlay/__init__.py` (empty package marker — **required**, not optional)
- Test: `tests/unit/core/config_overlay/test_registry.py`

- [ ] **Step 1: Write failing tests** (strict coercion is load-bearing — `int(2.5)` truncates and `bool` coerces through `int`/`float`)

```python
# tests/unit/core/config_overlay/test_registry.py
import typing
import pytest
from cognic_agentos.core.config_overlay.registry import (
    OverlayDirection, OverlayRefusalReason, TenantOverlayRejected,
    REGISTRY, overridable_field, validate_tighten_only,
)
from cognic_agentos.core.config import Settings, _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS

def test_registry_has_exactly_four_keys():
    assert set(REGISTRY) == {
        "sandbox_per_tenant_max_cpu", "sandbox_per_tenant_max_memory",
        "sandbox_per_tenant_max_walltime", "memory_export_retention_seconds"}

def test_overlay_direction_closed_enum():
    assert set(typing.get_args(OverlayDirection)) == {"ceiling", "floor"}

def test_refusal_reason_closed_enum_six_values():
    assert set(typing.get_args(OverlayRefusalReason)) == {
        "tenant_overlay_field_not_overridable", "tenant_overlay_value_not_coercible",
        "tenant_overlay_loosens_ceiling", "tenant_overlay_below_base_floor",
        "tenant_overlay_below_kernel_floor", "tenant_overlay_ceiling_not_positive"}

def test_unknown_field_rejected():
    with pytest.raises(TenantOverlayRejected) as e:
        overridable_field("require_cosign")
    assert e.value.reason == "tenant_overlay_field_not_overridable"

def test_ceiling_accepts_le_base_rejects_gt():
    f = REGISTRY["sandbox_per_tenant_max_cpu"]  # ceiling, float
    assert validate_tighten_only(f, base_value=4.0, proposed="2.0") == 2.0
    with pytest.raises(TenantOverlayRejected) as e:
        validate_tighten_only(f, base_value=4.0, proposed="8.0")
    assert e.value.reason == "tenant_overlay_loosens_ceiling"

def test_ceiling_rejects_non_positive():
    f = REGISTRY["sandbox_per_tenant_max_cpu"]
    for bad in ("0", "-1"):
        with pytest.raises(TenantOverlayRejected) as e:
            validate_tighten_only(f, base_value=4.0, proposed=bad)
        assert e.value.reason == "tenant_overlay_ceiling_not_positive"

def test_floor_kernel_floor_checked_BEFORE_base_floor():
    # When base == kernel_floor, a sub-floor value MUST report below_kernel_floor (more fundamental).
    f = REGISTRY["memory_export_retention_seconds"]  # floor, int, kernel_floor=7yr
    base = _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS
    assert validate_tighten_only(f, base_value=base, proposed=str(base + 1)) == base + 1
    with pytest.raises(TenantOverlayRejected) as e:   # below base (raised base) but >= kernel floor
        validate_tighten_only(f, base_value=base + 100, proposed=str(base + 50))
    assert e.value.reason == "tenant_overlay_below_base_floor"
    with pytest.raises(TenantOverlayRejected) as e2:  # below BOTH; kernel floor wins
        validate_tighten_only(f, base_value=base, proposed=str(base - 1))
    assert e2.value.reason == "tenant_overlay_below_kernel_floor"

def test_strict_coercion_rejects_bool():
    f = REGISTRY["sandbox_per_tenant_max_memory"]  # int
    with pytest.raises(TenantOverlayRejected) as e:
        validate_tighten_only(f, base_value=2048, proposed=True)  # bool is an int subclass — reject
    assert e.value.reason == "tenant_overlay_value_not_coercible"

def test_strict_coercion_rejects_fractional_for_int_field():
    f = REGISTRY["sandbox_per_tenant_max_memory"]  # int — 2.5 must NOT silently truncate to 2
    with pytest.raises(TenantOverlayRejected) as e:
        validate_tighten_only(f, base_value=2048, proposed=2.5)
    assert e.value.reason == "tenant_overlay_value_not_coercible"

def test_non_coercible_string_rejected():
    f = REGISTRY["sandbox_per_tenant_max_memory"]
    with pytest.raises(TenantOverlayRejected) as e:
        validate_tighten_only(f, base_value=2048, proposed="not-a-number")
    assert e.value.reason == "tenant_overlay_value_not_coercible"

def test_lock_assertion_do_not_configure_invariants_absent_from_registry():
    from cognic_agentos.core.config import _SECRET_VAULT_FIELDS
    locked = {"require_cosign", "runtime_profile", "cosign_path",
              "evidence_pack_signing_key_path", *_SECRET_VAULT_FIELDS}
    assert locked.isdisjoint(set(REGISTRY))

def test_every_registry_key_is_a_real_settings_field():
    s = Settings(runtime_profile="dev")
    for key in REGISTRY:
        assert hasattr(s, key)
```

- [ ] **Step 2: Run to verify they fail** — `uv run pytest tests/unit/core/config_overlay/test_registry.py -v` → FAIL (`ModuleNotFoundError`).

- [ ] **Step 3: Implement** — create `tests/unit/core/config_overlay/__init__.py` (empty) + `src/cognic_agentos/core/config_overlay/__init__.py` (`"""Per-tenant config overlay (ADR-023)."""`) + the registry:

```python
# src/cognic_agentos/core/config_overlay/registry.py
"""ADR-023 — closed, default-deny registry + STRICT tighten-only validator.
Strictness matters: bool is an int subclass and int(2.5) truncates, so coercion must
reject bool and reject fractional values for int fields rather than silently accept them."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from cognic_agentos.core.config import _MEMORY_EXPORT_RETENTION_FLOOR_SECONDS

OverlayDirection = Literal["ceiling", "floor"]

OverlayRefusalReason = Literal[
    "tenant_overlay_field_not_overridable",
    "tenant_overlay_value_not_coercible",
    "tenant_overlay_loosens_ceiling",
    "tenant_overlay_below_base_floor",
    "tenant_overlay_below_kernel_floor",
    "tenant_overlay_ceiling_not_positive",
]


class TenantOverlayRejected(Exception):
    def __init__(self, reason: OverlayRefusalReason) -> None:
        super().__init__(reason)
        self.reason: OverlayRefusalReason = reason


@dataclass(frozen=True, slots=True)
class OverridableField:
    key: str
    direction: OverlayDirection
    value_type: type[int] | type[float]
    kernel_floor: int | float | None


REGISTRY: dict[str, OverridableField] = {
    "sandbox_per_tenant_max_cpu": OverridableField("sandbox_per_tenant_max_cpu", "ceiling", float, None),
    "sandbox_per_tenant_max_memory": OverridableField("sandbox_per_tenant_max_memory", "ceiling", int, None),
    "sandbox_per_tenant_max_walltime": OverridableField("sandbox_per_tenant_max_walltime", "ceiling", float, None),
    "memory_export_retention_seconds": OverridableField(
        "memory_export_retention_seconds", "floor", int, kernel_floor=_MEMORY_EXPORT_RETENTION_FLOOR_SECONDS),
}


def overridable_field(field_key: str) -> OverridableField:
    field = REGISTRY.get(field_key)
    if field is None:
        raise TenantOverlayRejected("tenant_overlay_field_not_overridable")
    return field


def coerce_value(field: OverridableField, proposed: object) -> int | float:
    if isinstance(proposed, bool):                       # bool is an int subclass — never accept
        raise TenantOverlayRejected("tenant_overlay_value_not_coercible")
    try:
        as_float = float(proposed)                       # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise TenantOverlayRejected("tenant_overlay_value_not_coercible") from None
    if field.value_type is int:
        if as_float != int(as_float):                    # reject fractional for int fields (no silent truncation)
            raise TenantOverlayRejected("tenant_overlay_value_not_coercible")
        return int(as_float)
    return as_float


def validate_tighten_only(
    field: OverridableField, *, base_value: int | float, proposed: object
) -> int | float:
    value = coerce_value(field, proposed)
    if field.direction == "ceiling":
        if value <= 0:
            raise TenantOverlayRejected("tenant_overlay_ceiling_not_positive")
        if value > base_value:
            raise TenantOverlayRejected("tenant_overlay_loosens_ceiling")
    else:  # floor — check kernel floor FIRST (more fundamental than base)
        if field.kernel_floor is not None and value < field.kernel_floor:
            raise TenantOverlayRejected("tenant_overlay_below_kernel_floor")
        if value < base_value:
            raise TenantOverlayRejected("tenant_overlay_below_base_floor")
    return value
```

- [ ] **Step 4: Run to verify pass** — `uv run pytest tests/unit/core/config_overlay/test_registry.py -v` → PASS (11 tests). `uv run ruff check src/cognic_agentos/core/config_overlay tests/unit/core/config_overlay && uv run mypy src/cognic_agentos/core/config_overlay`.

- [ ] **Step 5: Halt-before-commit** (CC). On token: `git add src/cognic_agentos/core/config_overlay/__init__.py src/cognic_agentos/core/config_overlay/registry.py tests/unit/core/config_overlay/__init__.py tests/unit/core/config_overlay/test_registry.py && git commit` (`feat(config-overlay): strict tighten-only field registry + validator (ADR-023)`).

---

### Task 2: Alembic migration + overlay table

**Files:**
- Create: `src/cognic_agentos/db/migrations/versions/20260606_0007_tenant_config_overlay.py`
- Test: `tests/integration/db/test_tenant_config_overlay_migration.py`

First `Read` the newest file in `src/cognic_agentos/db/migrations/versions/` and use its `revision` as `down_revision` (grounding shows `0006`; if newer exists, chain from it).

- [ ] **Step 1: Write the failing (env-gated) migration test — assert the table EXISTS after upgrade (a bare `upgrade head` is a false RED because head is already `0006`)**

```python
# tests/integration/db/test_tenant_config_overlay_migration.py
import os
import subprocess
import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

POSTGRES_URL = os.environ.get(
    "COGNIC_DATABASE_URL_POSTGRES_TEST",
    "postgresql+asyncpg://cognic:cognic_dev_only@localhost:5432/cognic")

pytestmark = pytest.mark.skipif(
    not os.environ.get("COGNIC_RUN_POSTGRES_INTEGRATION"),
    reason="live Postgres required; set COGNIC_RUN_POSTGRES_INTEGRATION=1")

def _alembic(url, *args):
    subprocess.run(["uv", "run", "alembic", *args], check=True,
                   env={**os.environ, "COGNIC_DATABASE_URL": url})

async def _table_exists(url) -> bool:
    eng = create_async_engine(url)
    try:
        async with eng.connect() as conn:
            names = await conn.run_sync(lambda c: sa.inspect(c).get_table_names())
        return "tenant_config_overlay" in names
    finally:
        await eng.dispose()

async def test_overlay_table_created_and_roundtrips():
    _alembic(POSTGRES_URL, "upgrade", "head")
    assert await _table_exists(POSTGRES_URL)        # true RED: table absent before 0007
    _alembic(POSTGRES_URL, "downgrade", "-1")
    assert not await _table_exists(POSTGRES_URL)
    _alembic(POSTGRES_URL, "upgrade", "head")
    assert await _table_exists(POSTGRES_URL)
```

- [ ] **Step 2: Run to verify it fails** (opted in): `COGNIC_RUN_POSTGRES_INTEGRATION=1 uv run pytest tests/integration/db/test_tenant_config_overlay_migration.py -v` → FAIL (no `0007`). Without the env var it SKIPS.

- [ ] **Step 3: Implement the migration** (mirror `20260531_0006_memory.py` — **`db.types.GovernanceJSON`** and **`sa.TIMESTAMP`**)

```python
# src/cognic_agentos/db/migrations/versions/20260606_0007_tenant_config_overlay.py
"""tenant_config_overlay — per-tenant tighten-only config overrides (ADR-023)."""
import sqlalchemy as sa
from alembic import op
from cognic_agentos.db.types import GovernanceJSON

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        "tenant_config_overlay",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(length=128), nullable=False),
        sa.Column("field_key", sa.String(length=128), nullable=False),
        sa.Column("value", GovernanceJSON(), nullable=False),
        sa.Column("set_by_actor", sa.String(length=256), nullable=False),
        sa.Column("set_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_request_id", sa.String(length=64), nullable=False),
        sa.UniqueConstraint("tenant_id", "field_key", name="uq_tenant_config_overlay_tenant_field"),
    )
    op.create_index("ix_tenant_config_overlay_tenant_id", "tenant_config_overlay", ["tenant_id"])

def downgrade() -> None:
    op.drop_index("ix_tenant_config_overlay_tenant_id", table_name="tenant_config_overlay")
    op.drop_table("tenant_config_overlay")
```

> **Implementer:** confirm `db.types.GovernanceJSON` is the live import (grounding: review §persistence and `_0006_memory.py` use `cognic_agentos.db.types`). Verify `_0006`'s timestamp type is `sa.TIMESTAMP(timezone=True)` and match it exactly.

- [ ] **Step 4: Run to verify pass** (opted in) → PASS. ruff/mypy on the migration.

- [ ] **Step 5: Halt-before-commit** (CC — migration). On token: `git add` the migration + test + commit (`feat(config-overlay): tenant_config_overlay table migration (ADR-023)`).

---

### Task 3: Overlay storage (in-closure atomic mutation)

**Files:**
- Create: `src/cognic_agentos/core/config_overlay/storage.py`
- Test: `tests/unit/core/config_overlay/test_storage.py` (SQLite + `_metadata.create_all`) **and** `tests/integration/core/config_overlay/test_storage_pg.py` (migrated PG, env-gated — unique-constraint + cross-tenant invariants per `feedback_storage_test_migrated_db_not_create_all`).

- [ ] **Step 1: Write failing unit tests** (atomic set; loosening → zero rows + zero chain; clear; tenant-scoped)

```python
# tests/unit/core/config_overlay/test_storage.py
from datetime import UTC, datetime
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.config_overlay.registry import TenantOverlayRejected
from cognic_agentos.core.config_overlay.storage import TenantConfigOverlayStore, _tenant_config_overlay

@pytest.fixture
async def engine(tmp_path):
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path/'ovl.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(_chain_heads.insert().values(chain_id="decision_history",
            latest_sequence=0, latest_hash=ZERO_HASH, updated_at=datetime.now(UTC)))
    yield eng
    await eng.dispose()

@pytest.fixture
def store(engine):
    return TenantConfigOverlayStore(engine)

async def test_set_overlay_writes_row_and_chain_atomically(store, engine):
    await store.set_overlay(tenant_id="t1", field_key="sandbox_per_tenant_max_cpu",
        base_value=4.0, proposed="2.0", actor_subject="op@bank", actor_type="human",
        request_id="cfg-overlay-set-deadbeef")
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_tenant_config_overlay))).fetchall())
        chain = list((await conn.execute(select(_decision_history).where(
            _decision_history.c.event_type == "config.tenant_overlay.set"))).fetchall())
    assert len(rows) == 1 and rows[0].value == 2.0 and rows[0].last_request_id == "cfg-overlay-set-deadbeef"
    assert len(chain) == 1
    payload = chain[0].payload
    assert set(payload) >= {"tenant_id","field_key","direction","base_value","overlay_value",
                            "previous_overlay_value","actor_subject","actor_type"}
    assert payload["direction"] == "ceiling" and payload["base_value"] == 4.0 and payload["overlay_value"] == 2.0
    assert list(chain[0].iso_controls) == ["ISO42001.A.6.2.5"]

async def test_loosening_set_writes_zero_rows_and_zero_chain(store, engine):
    with pytest.raises(TenantOverlayRejected) as e:
        await store.set_overlay(tenant_id="t1", field_key="sandbox_per_tenant_max_cpu",
            base_value=4.0, proposed="8.0", actor_subject="op", actor_type="human", request_id="cfg-overlay-set-x")
    assert e.value.reason == "tenant_overlay_loosens_ceiling"
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_tenant_config_overlay))).fetchall())
        chain = list((await conn.execute(select(_decision_history))).fetchall())
    assert rows == [] and chain == []

async def test_get_many_one_snapshot_returns_overrides_and_absent(store):
    await store.set_overlay(tenant_id="t1", field_key="sandbox_per_tenant_max_cpu",
        base_value=4.0, proposed="2.0", actor_subject="op", actor_type="human", request_id="cfg-overlay-set-y")
    got = await store.get_many("t1", ("sandbox_per_tenant_max_cpu", "sandbox_per_tenant_max_memory"))
    assert got == {"sandbox_per_tenant_max_cpu": 2.0}

async def test_clear_deletes_row_and_emits_cleared_chain(store, engine):
    await store.set_overlay(tenant_id="t1", field_key="sandbox_per_tenant_max_cpu",
        base_value=4.0, proposed="2.0", actor_subject="op", actor_type="human", request_id="cfg-overlay-set-z")
    await store.clear_overlay(tenant_id="t1", field_key="sandbox_per_tenant_max_cpu",
        actor_subject="op", actor_type="human", request_id="cfg-overlay-clear-z")
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_tenant_config_overlay))).fetchall())
        chain = list((await conn.execute(select(_decision_history).where(
            _decision_history.c.event_type == "config.tenant_overlay.cleared"))).fetchall())
    assert rows == [] and len(chain) == 1

async def test_get_many_is_tenant_scoped(store):
    await store.set_overlay(tenant_id="t1", field_key="sandbox_per_tenant_max_cpu",
        base_value=4.0, proposed="2.0", actor_subject="op", actor_type="human", request_id="cfg-overlay-set-t1")
    assert await store.get_many("t2", ("sandbox_per_tenant_max_cpu",)) == {}
```

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement the store** — mirror `packs/storage.py` `transition()` in-closure pattern; `append_with_precondition(*, record_builder, precondition)` per grounding; **`db.types.GovernanceJSON`** + **`sa.TIMESTAMP`**:

```python
# src/cognic_agentos/core/config_overlay/storage.py
"""ADR-023 storage — current state in a table, immutable history in the chain.
Mutation is the in-closure append_with_precondition pattern (mirrors packs/storage.py):
the upsert/delete runs INSIDE the precondition closure so overlay-row + chain-row +
chain-head commit in one transaction. The chain record_id is minted AFTER the closure,
so the row back-links by `last_request_id` (== DecisionRecord.request_id), not record_id."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import delete, insert, select, update
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.audit import _metadata
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.config_overlay.registry import overridable_field, validate_tighten_only
from cognic_agentos.db.types import GovernanceJSON

_ISO_A_6_2_5 = "ISO42001.A.6.2.5"

_tenant_config_overlay = sa.Table(
    "tenant_config_overlay", _metadata,
    sa.Column("id", sa.Uuid(), primary_key=True),
    sa.Column("tenant_id", sa.String(length=128), nullable=False),
    sa.Column("field_key", sa.String(length=128), nullable=False),
    sa.Column("value", GovernanceJSON(), nullable=False),
    sa.Column("set_by_actor", sa.String(length=256), nullable=False),
    sa.Column("set_at", sa.TIMESTAMP(timezone=True), nullable=False),
    sa.Column("last_request_id", sa.String(length=64), nullable=False),
    sa.UniqueConstraint("tenant_id", "field_key", name="uq_tenant_config_overlay_tenant_field"),
    sa.Index("ix_tenant_config_overlay_tenant_id", "tenant_id"),
)


@dataclass(frozen=True, slots=True)
class TenantConfigOverlayRow:
    tenant_id: str
    field_key: str
    value: int | float
    set_by_actor: str
    set_at: datetime
    last_request_id: str


class TenantConfigOverlayStore:
    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._dh = DecisionHistoryStore(engine)

    async def get_many(self, tenant_id: str, field_keys: tuple[str, ...]) -> dict[str, int | float]:
        if not field_keys:
            return {}
        async with self._engine.connect() as conn:
            rows = (await conn.execute(
                select(_tenant_config_overlay.c.field_key, _tenant_config_overlay.c.value)
                .where(_tenant_config_overlay.c.tenant_id == tenant_id)
                .where(_tenant_config_overlay.c.field_key.in_(field_keys)))).fetchall()
        return {r.field_key: r.value for r in rows}

    async def list_for_tenant(self, tenant_id: str) -> list[TenantConfigOverlayRow]:
        async with self._engine.connect() as conn:
            rows = (await conn.execute(select(_tenant_config_overlay)
                .where(_tenant_config_overlay.c.tenant_id == tenant_id))).fetchall()
        return [TenantConfigOverlayRow(r.tenant_id, r.field_key, r.value,
                    r.set_by_actor, r.set_at, r.last_request_id) for r in rows]

    async def set_overlay(self, *, tenant_id: str, field_key: str, base_value: int | float,
            proposed: object, actor_subject: str, actor_type: str, request_id: str) -> None:
        field = overridable_field(field_key)                                   # preflight default-deny
        accepted = validate_tighten_only(field, base_value=base_value, proposed=proposed)  # cheap pre-check

        async def _precondition(conn: AsyncConnection, prev_seq: int, prev_hash: bytes) -> dict[str, Any]:
            row = (await conn.execute(
                select(_tenant_config_overlay.c.value)
                .where(_tenant_config_overlay.c.tenant_id == tenant_id)
                .where(_tenant_config_overlay.c.field_key == field_key)
                .with_for_update())).first()
            previous = row.value if row is not None else None
            validate_tighten_only(field, base_value=base_value, proposed=proposed)  # authoritative re-check (TOCTOU)
            now = datetime.now(UTC)
            if row is None:
                await conn.execute(insert(_tenant_config_overlay).values(
                    id=uuid.uuid4(), tenant_id=tenant_id, field_key=field_key, value=accepted,
                    set_by_actor=actor_subject, set_at=now, last_request_id=request_id))
            else:
                await conn.execute(update(_tenant_config_overlay)
                    .where(_tenant_config_overlay.c.tenant_id == tenant_id)
                    .where(_tenant_config_overlay.c.field_key == field_key)
                    .values(value=accepted, set_by_actor=actor_subject, set_at=now, last_request_id=request_id))
            return {"previous": previous}

        def _build(captured: dict[str, Any]) -> DecisionRecord:
            return DecisionRecord(decision_type="config.tenant_overlay.set", request_id=request_id,
                tenant_id=tenant_id, actor_id=actor_subject, iso_controls=(_ISO_A_6_2_5,),
                payload={"tenant_id": tenant_id, "field_key": field_key, "direction": field.direction,
                         "base_value": base_value, "overlay_value": accepted,
                         "previous_overlay_value": captured["previous"],
                         "actor_subject": actor_subject, "actor_type": actor_type})

        await self._dh.append_with_precondition(record_builder=_build, precondition=_precondition)

    async def clear_overlay(self, *, tenant_id: str, field_key: str,
            actor_subject: str, actor_type: str, request_id: str) -> None:
        field = overridable_field(field_key)

        async def _precondition(conn: AsyncConnection, prev_seq: int, prev_hash: bytes) -> dict[str, Any]:
            row = (await conn.execute(
                select(_tenant_config_overlay.c.value)
                .where(_tenant_config_overlay.c.tenant_id == tenant_id)
                .where(_tenant_config_overlay.c.field_key == field_key)
                .with_for_update())).first()
            previous = row.value if row is not None else None
            await conn.execute(delete(_tenant_config_overlay)
                .where(_tenant_config_overlay.c.tenant_id == tenant_id)
                .where(_tenant_config_overlay.c.field_key == field_key))
            return {"previous": previous}

        def _build(captured: dict[str, Any]) -> DecisionRecord:
            return DecisionRecord(decision_type="config.tenant_overlay.cleared", request_id=request_id,
                tenant_id=tenant_id, actor_id=actor_subject, iso_controls=(_ISO_A_6_2_5,),
                payload={"tenant_id": tenant_id, "field_key": field_key, "direction": field.direction,
                         "previous_overlay_value": captured["previous"],
                         "actor_subject": actor_subject, "actor_type": actor_type})

        await self._dh.append_with_precondition(record_builder=_build, precondition=_precondition)
```

> **Implementer notes:** confirm `append_with_precondition`'s chain id is `"decision_history"` (the test seeds that head). `GovernanceJSON` value round-trip type fidelity (int vs float) is authoritatively checked by the migrated-PG test, not SQLite.

- [ ] **Step 4: Run to verify pass** + add `tests/integration/core/config_overlay/test_storage_pg.py` (env-gated: the `uq_tenant_config_overlay_tenant_field` constraint blocks a duplicate `(tenant,field)` insert; wrong-tenant `get_many` returns `{}`). ruff/mypy.

- [ ] **Step 5: Halt-before-commit** (CC — storage). **Full suite.** On token: `git add` storage + both tests + commit (`feat(config-overlay): governed in-closure overlay storage (ADR-023)`).

---

### Task 4: Resolver (typed store, fail-closed, invalid_at_read)

**Files:**
- Create: `src/cognic_agentos/core/config_overlay/resolver.py`
- Modify: `src/cognic_agentos/core/config.py` (add `config_overlay_invalid_at_read_throttle_s: int = Field(default=300, gt=0, ...)`)
- Test: `tests/unit/core/config_overlay/test_resolver.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/core/config_overlay/test_resolver.py
import pytest
from cognic_agentos.core.config import Settings
from cognic_agentos.core.config_overlay.resolver import (
    TenantConfigResolver, TenantConfigOverlayInvalid, TenantConfigKeyError)

class _FakeStore:
    def __init__(self, data): self._data = data; self.calls = 0
    async def get_many(self, tenant_id, field_keys):
        self.calls += 1
        return {k: v for k, v in self._data.get(tenant_id, {}).items() if k in field_keys}

class _RecordingAudit:
    def __init__(self): self.events = []
    async def append(self, event): self.events.append(event); return (None, b"")

def _settings(): return Settings(runtime_profile="dev")

async def test_absent_returns_base():
    r = TenantConfigResolver(store=_FakeStore({}), base=_settings(), audit=_RecordingAudit(), throttle_s=300)
    got = await r.effective_many(("sandbox_per_tenant_max_cpu",), "t1")
    assert got["sandbox_per_tenant_max_cpu"] == _settings().sandbox_per_tenant_max_cpu

async def test_valid_tightened_returned():
    s = _settings()
    store = _FakeStore({"t1": {"sandbox_per_tenant_max_cpu": s.sandbox_per_tenant_max_cpu - 1.0}})
    r = TenantConfigResolver(store=store, base=s, audit=_RecordingAudit(), throttle_s=300)
    assert await r.effective("sandbox_per_tenant_max_cpu", "t1") == s.sandbox_per_tenant_max_cpu - 1.0

async def test_effective_many_single_store_read():
    store = _FakeStore({})
    r = TenantConfigResolver(store=store, base=_settings(), audit=_RecordingAudit(), throttle_s=300)
    await r.effective_many(("sandbox_per_tenant_max_cpu","sandbox_per_tenant_max_memory","sandbox_per_tenant_max_walltime"), "t1")
    assert store.calls == 1

async def test_invalid_loosening_refuses_and_audits_not_decision_history():
    s = _settings()
    store = _FakeStore({"t1": {"sandbox_per_tenant_max_cpu": s.sandbox_per_tenant_max_cpu + 99.0}})
    audit = _RecordingAudit()
    r = TenantConfigResolver(store=store, base=s, audit=audit, throttle_s=300)
    with pytest.raises(TenantConfigOverlayInvalid):
        await r.effective("sandbox_per_tenant_max_cpu", "t1")
    assert len(audit.events) == 1
    assert audit.events[0].event_type == "config.tenant_overlay.invalid_at_read"
    assert audit.events[0].request_id                       # minted, non-empty (AuditEvent requires it)
    assert list(audit.events[0].iso_controls) == ["ISO42001.A.9.2"]

async def test_key_not_in_registry_raises_key_error():
    r = TenantConfigResolver(store=_FakeStore({}), base=_settings(), audit=_RecordingAudit(), throttle_s=300)
    with pytest.raises(TenantConfigKeyError):
        await r.effective("require_cosign", "t1")

async def test_invalid_audit_throttled_per_tenant_field_reason():
    s = _settings()
    store = _FakeStore({"t1": {"sandbox_per_tenant_max_cpu": s.sandbox_per_tenant_max_cpu + 99.0}})
    audit = _RecordingAudit()
    r = TenantConfigResolver(store=store, base=s, audit=audit, throttle_s=300)
    for _ in range(3):
        with pytest.raises(TenantConfigOverlayInvalid):
            await r.effective("sandbox_per_tenant_max_cpu", "t1")
    assert len(audit.events) == 1                           # refusal fired 3×, audit row throttled to 1
```

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement** — add the Setting (CC edit to `core/config.py`), then the resolver with a **typed `_OverlayStore` Protocol** (mypy requires it in `src/`):

```python
# src/cognic_agentos/core/config_overlay/resolver.py
"""ADR-023 resolver — request-time tighten-only resolution, fail-closed (posture R).
Invalid stored overlay -> raise (consumer fails closed) + throttled
`config.tenant_overlay.invalid_at_read` AUDIT incident (A.9.2), never decision-history,
never a silent base-fallback. Absent -> base. No ObservabilityAdapter (audit + log only)."""
from __future__ import annotations

import logging
import time
import uuid
from typing import TYPE_CHECKING, Protocol

from cognic_agentos.core.audit import AuditEvent
from cognic_agentos.core.config_overlay.registry import (
    REGISTRY, TenantOverlayRejected, overridable_field, validate_tighten_only)

if TYPE_CHECKING:
    from cognic_agentos.core.audit import AuditStore
    from cognic_agentos.core.config import Settings

_LOG = logging.getLogger("cognic_agentos.core.config_overlay.resolver")
_ISO_A_9_2 = "ISO42001.A.9.2"
_INVALID_REQUEST_ID_PREFIX = "cfg-ovl-inv-"          # 12 + 32 hex = 44 <= 64
assert len(_INVALID_REQUEST_ID_PREFIX) + 32 <= 64


class _OverlayStore(Protocol):
    async def get_many(self, tenant_id: str, field_keys: tuple[str, ...]) -> dict[str, int | float]: ...


class TenantConfigKeyError(Exception):
    """A consumer asked for a non-overridable field (programming error, fail-closed)."""


class TenantConfigOverlayInvalid(Exception):
    def __init__(self, field_key: str, reason: str) -> None:
        super().__init__(f"{field_key}: {reason}")
        self.field_key = field_key
        self.reason = reason


class TenantConfigResolver:
    def __init__(self, *, store: _OverlayStore, base: Settings, audit: AuditStore, throttle_s: int) -> None:
        self._store = store
        self._base = base
        self._audit = audit
        self._throttle_s = throttle_s
        self._last_emit: dict[tuple[str, str, str], tuple[float, object]] = {}

    async def effective(self, field_key: str, tenant_id: str) -> int | float:
        return (await self.effective_many((field_key,), tenant_id))[field_key]

    async def effective_many(self, field_keys: tuple[str, ...], tenant_id: str) -> dict[str, int | float]:
        for fk in field_keys:
            if fk not in REGISTRY:
                raise TenantConfigKeyError(fk)
        snapshot = await self._store.get_many(tenant_id, field_keys)           # ONE read -> one snapshot
        out: dict[str, int | float] = {}
        for fk in field_keys:
            field = overridable_field(fk)
            base_value = getattr(self._base, fk)
            if fk not in snapshot:
                out[fk] = base_value
                continue
            stored = snapshot[fk]
            try:
                out[fk] = validate_tighten_only(field, base_value=base_value, proposed=stored)
            except TenantOverlayRejected as exc:
                await self._emit_invalid_at_read(tenant_id, fk, base_value, stored, exc.reason)
                raise TenantConfigOverlayInvalid(fk, exc.reason) from exc
        return out

    async def _emit_invalid_at_read(self, tenant_id: str, field_key: str,
            base_value: object, stored: object, reason: str) -> None:
        _LOG.warning("config.tenant_overlay.invalid_at_read", extra={                 # unthrottled
            "tenant_id": tenant_id, "field_key": field_key, "reason": reason,
            "base_value": base_value, "stored_value": stored})
        key = (tenant_id, field_key, reason)
        now = time.monotonic()
        prev = self._last_emit.get(key)
        if prev is not None and (now - prev[0]) < self._throttle_s and prev[1] == stored:
            return                                                                    # chain row throttled
        self._last_emit[key] = (now, stored)
        await self._audit.append(AuditEvent(
            event_type="config.tenant_overlay.invalid_at_read",
            request_id=f"{_INVALID_REQUEST_ID_PREFIX}{uuid.uuid4().hex}",
            tenant_id=tenant_id, iso_controls=(_ISO_A_9_2,),
            payload={"tenant_id": tenant_id, "field_key": field_key, "reason": reason,
                     "base_value": base_value, "stored_value": stored}))
```

> In-process throttle (per-instance dict). Multi-instance dedup is Wave-2 (note inline).

- [ ] **Step 4: Run to verify pass** + ruff/mypy on `core/config_overlay` + `core/config.py`.

- [ ] **Step 5: Halt-before-commit** (CC — `core/config.py` stop-rule). **Full suite.** On token: `git add` resolver + config.py + test + commit (`feat(config-overlay): fail-closed request-time resolver + invalid_at_read audit (ADR-023)`).

---

### Task 5: RBAC scope family

*(Unchanged from the prior revision.)* Add `ConfigOverlayRBACScope` Literal + `CONFIG_OVERLAY_SCOPES` to `scopes.py`; add `| ConfigOverlayRBACScope` to the `Actor.scopes` union (`actor.py`) and the `RequireScope` param union (`enforcement.py`). Tests: `tests/unit/portal/rbac/test_config_overlay_scopes.py` (2-value enum + group match + Actor accepts) + run the existing `test_scopes.py` partition test. **Halt-before-commit** (CC — RBAC). Commit (`feat(config-overlay): ConfigOverlayRBACScope (ADR-023)`).

---

### Task 6: Mutation endpoint (human-only, operator-administered, `settings` as factory arg)

**Files:**
- Create: `src/cognic_agentos/portal/api/config_overlay/__init__.py`, `src/cognic_agentos/portal/api/config_overlay/routes.py`
- Test: `tests/unit/portal/api/config_overlay/test_routes.py`

> **No `from __future__ import annotations`** (closure-local `Depends` gotcha). **`settings` is a REQUIRED factory arg** — `build_config_overlay_routes(*, store, resolver, settings)` — the handler reads `getattr(settings, field_key)` (closure-captured, NEVER `Settings()` per request).

- [ ] **Step 1: Write failing tests — the five pins + DELETE + GET + the no-`RequireTenantOwnership` AST supplement**

```python
# tests/unit/portal/api/config_overlay/test_routes.py
import ast
import inspect
from datetime import UTC, datetime
import logging
import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine
from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.core.config_overlay.storage import TenantConfigOverlayStore, _tenant_config_overlay
from cognic_agentos.core.config_overlay.resolver import TenantConfigResolver
from cognic_agentos.portal.api.config_overlay import routes as routes_mod
from cognic_agentos.portal.api.config_overlay.routes import build_config_overlay_routes
from cognic_agentos.portal.rbac.actor import Actor

class _StubBinder:
    def __init__(self, actor): self._actor = actor
    def bind(self, *, request): return self._actor

def _actor(*, scopes, actor_type="human", tenant_id="t1"):
    return Actor(subject="op@bank", tenant_id=tenant_id, scopes=frozenset(scopes), actor_type=actor_type)

@pytest.fixture
async def engine(tmp_path):
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path/'ovl.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(_chain_heads.insert().values(chain_id="decision_history",
            latest_sequence=0, latest_hash=ZERO_HASH, updated_at=datetime.now(UTC)))
    yield eng
    await eng.dispose()

def _app(engine, actor):
    settings = Settings(runtime_profile="dev")
    store = TenantConfigOverlayStore(engine)
    resolver = TenantConfigResolver(store=store, base=settings, audit=AuditStore(engine),
                                    throttle_s=settings.config_overlay_invalid_at_read_throttle_s)
    app = FastAPI()
    app.state.actor_binder = _StubBinder(actor)
    app.include_router(build_config_overlay_routes(store=store, resolver=resolver, settings=settings),
                       prefix="/api/v1")
    return app, settings

async def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://x")

async def _put(app, tenant, field, value):
    async with await _client(app) as c:
        return await c.put(f"/api/v1/tenants/{tenant}/config-overlay/{field}", json={"value": value})

# PIN 1
async def test_service_actor_refused_before_mutation(engine):
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}, actor_type="service"))
    resp = await _put(app, "t1", "sandbox_per_tenant_max_cpu", 2.0)
    assert resp.status_code == 403 and resp.json()["detail"]["reason"] == "actor_type_must_be_human"
    async with engine.connect() as conn:
        assert list((await conn.execute(select(_decision_history))).fetchall()) == []

# PIN 2 — behaviour proof
async def test_cross_tenant_operator_with_scope_succeeds(engine):
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}, tenant_id="OTHER"))
    assert (await _put(app, "t1", "sandbox_per_tenant_max_cpu", 2.0)).status_code == 200

async def test_actor_without_scope_refused(engine):
    app, _ = _app(engine, _actor(scopes=set()))
    resp = await _put(app, "t1", "sandbox_per_tenant_max_cpu", 2.0)
    assert resp.status_code == 403 and resp.json()["detail"]["reason"] == "scope_not_held"

def test_routes_do_not_use_require_tenant_ownership():  # AST supplement to the behaviour proof
    src = inspect.getsource(routes_mod)
    names = {n.id for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Name)}
    assert "RequireTenantOwnership" not in names  # operator-administered: NO tenant-ownership gate

# PIN 3
async def test_loosening_write_refused_zero_chain(engine):
    app, settings = _app(engine, _actor(scopes={"config.tenant_overlay.write"}))
    resp = await _put(app, "t1", "sandbox_per_tenant_max_cpu", settings.sandbox_per_tenant_max_cpu + 10)
    assert resp.status_code == 422 and resp.json()["detail"]["reason"] == "tenant_overlay_loosens_ceiling"
    async with engine.connect() as conn:
        assert list((await conn.execute(select(_decision_history))).fetchall()) == []

# PIN 4
async def test_accepted_write_emits_chain(engine):
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}))
    assert (await _put(app, "t1", "sandbox_per_tenant_max_cpu", 2.0)).status_code == 200
    async with engine.connect() as conn:
        chain = list((await conn.execute(select(_decision_history).where(
            _decision_history.c.event_type == "config.tenant_overlay.set"))).fetchall())
    assert len(chain) == 1 and chain[0].payload["actor_type"] == "human"

# DELETE
async def test_delete_clears_and_emits_cleared(engine):
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}))
    await _put(app, "t1", "sandbox_per_tenant_max_cpu", 2.0)
    async with await _client(app) as c:
        resp = await c.delete("/api/v1/tenants/t1/config-overlay/sandbox_per_tenant_max_cpu")
    assert resp.status_code == 204
    async with engine.connect() as conn:
        rows = list((await conn.execute(select(_tenant_config_overlay))).fetchall())
        cleared = list((await conn.execute(select(_decision_history).where(
            _decision_history.c.event_type == "config.tenant_overlay.cleared"))).fetchall())
    assert rows == [] and len(cleared) == 1

async def test_delete_requires_human(engine):
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}, actor_type="service"))
    async with await _client(app) as c:
        resp = await c.delete("/api/v1/tenants/t1/config-overlay/sandbox_per_tenant_max_cpu")
    assert resp.status_code == 403 and resp.json()["detail"]["reason"] == "actor_type_must_be_human"

# GET
async def test_get_lists_overlays_read_scope_no_human(engine):
    app, _ = _app(engine, _actor(scopes={"config.tenant_overlay.write"}))
    await _put(app, "t1", "sandbox_per_tenant_max_cpu", 2.0)
    app_read, _ = _app(engine, _actor(scopes={"config.tenant_overlay.read"}, actor_type="service"))
    async with await _client(app_read) as c:                       # service actor OK for read
        resp = await c.get("/api/v1/tenants/t1/config-overlay")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1 and body[0]["field_key"] == "sandbox_per_tenant_max_cpu"

async def test_get_refused_without_read_scope(engine):
    app, _ = _app(engine, _actor(scopes=set()))
    async with await _client(app) as c:
        resp = await c.get("/api/v1/tenants/t1/config-overlay")
    assert resp.status_code == 403 and resp.json()["detail"]["reason"] == "scope_not_held"

def test_no_future_import():  # PEP 563 invariant guard
    src = inspect.getsource(routes_mod)
    assert "from __future__ import annotations" not in src
```

- [ ] **Step 2: Run to verify fail.**

- [ ] **Step 3: Implement the routes** — *same as the prior revision but with `settings` as a required factory arg and `getattr(settings, field_key)` (no `Settings()` per request):*

```python
# src/cognic_agentos/portal/api/config_overlay/routes.py  (NO `from __future__ import annotations`)
"""ADR-023 — operator-administered, human-only per-tenant config overlay endpoints.
NO RequireTenantOwnership (operator sets config FOR a tenant; cross-tenant allowed iff the
operator scope is held). future-import OMITTED per the FastAPI closure-local Depends gotcha."""
import logging
import uuid
from typing import Annotated, Final

import pydantic
from fastapi import APIRouter, Body, HTTPException
from fastapi.params import Depends

from cognic_agentos.core.config import Settings
from cognic_agentos.core.config_overlay.registry import TenantOverlayRejected, overridable_field
from cognic_agentos.core.config_overlay.resolver import TenantConfigResolver
from cognic_agentos.core.config_overlay.storage import TenantConfigOverlayStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.human_actor import RequireHumanActor

_LOG = logging.getLogger("cognic_agentos.portal.api.config_overlay")
_SET_PREFIX: Final[str] = "cfg-overlay-set-"     # 16 + 32 = 48 <= 64
_CLR_PREFIX: Final[str] = "cfg-overlay-clr-"
assert len(_SET_PREFIX) + 32 <= 64 and len(_CLR_PREFIX) + 32 <= 64


def _mint(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"


class SetOverlayRequest(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(extra="forbid")
    value: float | int


class OverlayResponse(pydantic.BaseModel):
    tenant_id: str
    field_key: str
    value: float | int
    set_by_actor: str
    last_request_id: str


def build_config_overlay_routes(*, store: TenantConfigOverlayStore,
        resolver: TenantConfigResolver, settings: Settings) -> APIRouter:
    router = APIRouter()
    _write = RequireScope("config.tenant_overlay.write")
    _read = RequireScope("config.tenant_overlay.read")
    _human = RequireHumanActor()

    @router.put("/tenants/{tenant_id}/config-overlay/{field_key}", response_model=OverlayResponse)
    async def set_overlay(tenant_id: str, field_key: str,
            body: Annotated[SetOverlayRequest, Body(...)],
            actor: Annotated[Actor, Depends(_write)],
            _h: Annotated[Actor, Depends(_human)]) -> OverlayResponse:
        try:
            overridable_field(field_key)
            base_value = getattr(settings, field_key)                 # closure-captured base
            await store.set_overlay(tenant_id=tenant_id, field_key=field_key, base_value=base_value,
                proposed=body.value, actor_subject=actor.subject, actor_type=actor.actor_type,
                request_id=_mint(_SET_PREFIX))
        except TenantOverlayRejected as exc:
            _LOG.warning("portal.config_overlay.set_refused", extra={"reason": exc.reason,
                "tenant_id": tenant_id, "field_key": field_key, "actor_subject": actor.subject})
            raise HTTPException(status_code=422, detail={"reason": exc.reason})
        row = next(r for r in await store.list_for_tenant(tenant_id) if r.field_key == field_key)
        return OverlayResponse(tenant_id=row.tenant_id, field_key=row.field_key, value=row.value,
            set_by_actor=row.set_by_actor, last_request_id=row.last_request_id)

    @router.delete("/tenants/{tenant_id}/config-overlay/{field_key}", status_code=204)
    async def clear_overlay(tenant_id: str, field_key: str,
            actor: Annotated[Actor, Depends(_write)],
            _h: Annotated[Actor, Depends(_human)]) -> None:
        try:
            overridable_field(field_key)
            await store.clear_overlay(tenant_id=tenant_id, field_key=field_key,
                actor_subject=actor.subject, actor_type=actor.actor_type, request_id=_mint(_CLR_PREFIX))
        except TenantOverlayRejected as exc:
            _LOG.warning("portal.config_overlay.clear_refused", extra={"reason": exc.reason,
                "tenant_id": tenant_id, "field_key": field_key})
            raise HTTPException(status_code=422, detail={"reason": exc.reason})

    @router.get("/tenants/{tenant_id}/config-overlay", response_model=list[OverlayResponse])
    async def list_overlays(tenant_id: str,
            actor: Annotated[Actor, Depends(_read)]) -> list[OverlayResponse]:
        return [OverlayResponse(tenant_id=r.tenant_id, field_key=r.field_key, value=r.value,
            set_by_actor=r.set_by_actor, last_request_id=r.last_request_id)
            for r in await store.list_for_tenant(tenant_id)]

    return router
```

> `resolver` is accepted by the factory for symmetry / future read-time use even though the mutation handlers use `store` + `settings` directly; keep it in the signature so the app-mount and tests pass it (it is the same resolver the consumers use).

- [ ] **Step 4: Run to verify pass** (12 tests) + ruff/mypy.

- [ ] **Step 5: Halt-before-commit** (CC — endpoint / Human-only boundary). **Full suite.** On token: `git add` package init + routes + test + commit (`feat(config-overlay): human-only operator mutation endpoint (ADR-023)`).

---

### Task 7: Sandbox cap consumer wiring (dual-layer; SEAM-wired + unit-proven)

> **SEAM HONESTY:** `admit_policy` is the resolver seam, unit-proven here. No production `get_backend(...)` caller exists and `build_runtime()` owns no sandbox backend, so this does **not** add a Runtime→sandbox production path. Wiring `resolver` into `admit_policy` (+ keeping the backend constructors able to receive one) is the correct, honest scope.

**Files:**
- Modify: `src/cognic_agentos/sandbox/protocol.py` (refusal value), `src/cognic_agentos/sandbox/admission.py` (resolver param + `effective_many` at Step 5 + Step 9)
- Test: `tests/unit/sandbox/test_admission_overlay.py` + bump the `SandboxRefusalReason` count guard in `tests/unit/sandbox/test_policy_shape.py`

- [ ] **Step 1: Write failing tests** (grounded in the live `test_admission_pipeline.py` builders)

```python
# tests/unit/sandbox/test_admission_overlay.py
import typing
from unittest.mock import AsyncMock, MagicMock
import pytest
from cognic_agentos.core.policy.engine import Decision
from cognic_agentos.sandbox import PackAdmissionContext, SandboxLifecycleRefused, SandboxPolicy
from cognic_agentos.sandbox.admission import CredentialAdapter, admit_policy
from cognic_agentos.sandbox.protocol import SandboxRefusalReason
from cognic_agentos.core.config_overlay.resolver import TenantConfigOverlayInvalid

def _policy(**ov):
    base = {"cpu_cores": 1.0, "cpu_time_budget_s": None, "memory_mb": 256, "walltime_s": 30.0,
        "runtime_image": "cognic/sandbox-runtime-python:v1@sha256:" + "a"*64,
        "egress_allow_list": ("api.example.com",), "vault_path": None}
    base.update(ov); return SandboxPolicy(**base)

def _pack_ctx():
    return PackAdmissionContext(pack_id="cognic.t", pack_version="v1.0.0",
        pack_artifact_digest="sha256:"+"b"*64, risk_tier="internal_write",
        declares_dynamic_install=False, profile="production")

def _settings():  # caps here are NO LONGER the cap source once the resolver is wired
    return MagicMock(sandbox_per_tenant_max_cpu=4.0, sandbox_per_tenant_max_memory=1024,
        sandbox_per_tenant_max_walltime=300.0, sandbox_kernel_default_max_credential_ttl_s=900)

def _catalog():
    c = MagicMock(); c.is_canonical.return_value = True; c.is_tenant_allow_listed.return_value = True
    c.verify_cosign_or_refuse = AsyncMock(return_value=None)
    c.verify_sbom_policy_or_refuse = AsyncMock(return_value=None); return c

def _rego():
    r = MagicMock(); r.evaluate = AsyncMock(return_value=Decision(
        allow=True, rule_matched="data.cognic.sandbox.admit.allow", reasoning="ok", decision_data=None))
    return r

class _FakeResolver:
    def __init__(self, caps=None, invalid=False): self._caps = caps or {}; self._invalid = invalid
    async def effective_many(self, field_keys, tenant_id):
        if self._invalid:
            raise TenantConfigOverlayInvalid("sandbox_per_tenant_max_cpu", "tenant_overlay_loosens_ceiling")
        return {k: self._caps[k] for k in field_keys}
    async def effective(self, field_key, tenant_id):
        return (await self.effective_many((field_key,), tenant_id))[field_key]

_TIGHT = {"sandbox_per_tenant_max_cpu": 1.0, "sandbox_per_tenant_max_memory": 1024,
          "sandbox_per_tenant_max_walltime": 300.0}

async def _admit(policy, resolver, rego=None):
    rego = rego or _rego()
    await admit_policy(policy, tenant_id="t-1", actor=MagicMock(), pack_context=_pack_ctx(),
        catalog=_catalog(), credential_adapter=AsyncMock(spec=CredentialAdapter),
        rego_engine=rego, settings=_settings(), resolver=resolver)
    return rego

def test_refusal_enum_has_overlay_invalid_value():
    assert "sandbox_tenant_config_overlay_invalid" in typing.get_args(SandboxRefusalReason)

async def test_tightened_overlay_drives_python_refusal():
    with pytest.raises(SandboxLifecycleRefused) as e:        # policy 2.0 > tightened 1.0
        await _admit(_policy(cpu_cores=2.0), _FakeResolver(_TIGHT))
    assert e.value.reason == "sandbox_policy_exceeds_tenant_max_cpu"
    assert "1.0" in e.value.detail                            # tightened cap, not base 4.0

async def test_tightened_overlay_reaches_rego_tenant_max():
    rego = await _admit(_policy(cpu_cores=0.5), _FakeResolver(_TIGHT))  # under tightened cap -> reaches Step 9
    tenant_max = rego.evaluate.call_args.kwargs["input"]["tenant_max"]
    assert tenant_max == {"cpu_cores": 1.0, "memory_mb": 1024, "walltime_s": 300.0}

async def test_no_overlay_uses_base_caps():
    base = {"sandbox_per_tenant_max_cpu": 4.0, "sandbox_per_tenant_max_memory": 1024,
            "sandbox_per_tenant_max_walltime": 300.0}
    rego = await _admit(_policy(cpu_cores=3.0), _FakeResolver(base))  # 3.0 < base 4.0 -> admits
    assert rego.evaluate.call_args.kwargs["input"]["tenant_max"]["cpu_cores"] == 4.0

async def test_corrupt_overlay_fails_closed():
    with pytest.raises(SandboxLifecycleRefused) as e:
        await _admit(_policy(), _FakeResolver(invalid=True))
    assert e.value.reason == "sandbox_tenant_config_overlay_invalid"
```

- [ ] **Step 2: Run to verify fail** (admit_policy has no `resolver` kwarg yet; enum missing the value).

- [ ] **Step 3: Implement** — `protocol.py`: append `"sandbox_tenant_config_overlay_invalid",` to `SandboxRefusalReason` + bump the count guard in `test_policy_shape.py`. `admission.py`:
```python
from cognic_agentos.core.config_overlay.resolver import TenantConfigResolver, TenantConfigOverlayInvalid

async def admit_policy(policy, *, tenant_id, actor, pack_context, catalog,
        credential_adapter, rego_engine, settings, resolver: TenantConfigResolver,
        requires_credentials=()):
    ...
    # Step 5 — resolve once, feed BOTH layers:
    try:
        caps = await resolver.effective_many(
            ("sandbox_per_tenant_max_cpu", "sandbox_per_tenant_max_memory",
             "sandbox_per_tenant_max_walltime"), tenant_id)
    except TenantConfigOverlayInvalid as exc:
        raise SandboxLifecycleRefused("sandbox_tenant_config_overlay_invalid", detail=str(exc)) from exc
    eff_cpu, eff_mem, eff_wall = (caps["sandbox_per_tenant_max_cpu"],
        caps["sandbox_per_tenant_max_memory"], caps["sandbox_per_tenant_max_walltime"])
    if policy.cpu_cores > eff_cpu:
        raise SandboxLifecycleRefused("sandbox_policy_exceeds_tenant_max_cpu",
            detail=f"cpu_cores={policy.cpu_cores} > tenant max {eff_cpu}")
    if policy.memory_mb > eff_mem:
        raise SandboxLifecycleRefused("sandbox_policy_exceeds_tenant_max_memory",
            detail=f"memory_mb={policy.memory_mb} > tenant max {eff_mem}")
    if policy.walltime_s > eff_wall:
        raise SandboxLifecycleRefused("sandbox_policy_exceeds_tenant_max_walltime",
            detail=f"walltime_s={policy.walltime_s} > tenant max {eff_wall}")
    ...
    # Step 9 — Rego input tenant_max uses the SAME effective values:
            "tenant_max": {"cpu_cores": eff_cpu, "memory_mb": eff_mem, "walltime_s": eff_wall},
```
Update every existing `admit_policy(...)` call-site in `tests/unit/sandbox/test_admission_pipeline.py` to pass `resolver=_FakeResolver({...base caps...})` (or a tiny shared base-returning fake) so the existing suite stays green. The backend constructors (`docker_sibling.py`, `kubernetes_pod.py`) gain an optional `resolver` attribute they would pass to `admit_policy` **if/when** a production create path is wired (out of scope here — do NOT claim a Runtime path).

- [ ] **Step 4: Run to verify pass** — new tests + `uv run pytest tests/unit/sandbox -v` (no admission regression). ruff/mypy.

- [ ] **Step 5: Halt-before-commit** (CC — sandbox stop-rule + new closed-enum). **Full suite.** On token: `git add` sandbox protocol + admission + the two test files + commit (`feat(config-overlay): sandbox cap overlay wiring — Python + Rego, seam-proven (ADR-023)`).

---

### Task 8: Memory export retention consumer wiring

> **Ripple:** adding a required `resolver` to `MemoryAPI.__init__` breaks every existing `MemoryAPI(...)` construction. Contain it by updating the shared test builder `tests/unit/core/memory/conftest.py::_build_api` (and `_build_api_with_store`) to accept/pass a default base-returning resolver, and the harness `_factory` (Task 10).

**Files:**
- Modify: `src/cognic_agentos/core/memory/tiers.py` (refusal value), `src/cognic_agentos/core/memory/api.py` (resolver param + `export()` resolve), `tests/unit/core/memory/conftest.py` (thread default resolver)
- Test: `tests/unit/core/memory/test_export_overlay.py`

- [ ] **Step 1: Write failing tests** (grounded in the live memory harness — `_build_api_with_store`, `_ctx`, `SUBJECT`, `_task_record`, `decision_history_rows`)

```python
# tests/unit/core/memory/test_export_overlay.py
import typing
import pytest
from cognic_agentos.core.config import Settings
from cognic_agentos.core.memory._context import MemoryCallerContext
from cognic_agentos.core.memory.api import MemoryAPI
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, MemoryRefusalReason
from cognic_agentos.core.config_overlay.resolver import TenantConfigOverlayInvalid
from cognic_agentos.core.dlp.scanner import ChecksumRegexGazetteerScanner
from cognic_agentos.core.memory.consent import ConsentValidator
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter
from ._builders import SUBJECT, _task_record
from .conftest import _AllowAllPolicy, _ctx, _InactiveKillSwitch

class _FakeResolver:
    def __init__(self, value=None, invalid=False): self._v = value; self._invalid = invalid
    async def effective(self, field_key, tenant_id):
        if self._invalid:
            raise TenantConfigOverlayInvalid("memory_export_retention_seconds", "tenant_overlay_below_kernel_floor")
        return self._v

def _api(ctx, adapter, dh, obj, resolver, settings=None):
    return MemoryAPI(context=ctx, adapter=adapter, dlp=ChecksumRegexGazetteerScanner(),
        consent=ConsentValidator(audit=dh), policy=_AllowAllPolicy(), kill_switch=_InactiveKillSwitch(),
        audit=dh, settings=settings or Settings(), object_store=obj, resolver=resolver)

def test_refusal_enum_has_overlay_invalid_value():
    assert "memory_export_tenant_config_overlay_invalid" in typing.get_args(MemoryRefusalReason)

async def test_resolved_retention_reaches_export(memory_adapter, dh_store, tmp_path, decision_history_rows):
    obj = LocalObjectStoreAdapter(root=tmp_path)
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    ten_years = 10*365*24*3600
    api = _api(ctx, memory_adapter, dh_store, obj, _FakeResolver(value=ten_years))
    await memory_adapter.put(_task_record(value="payload"))
    await api.export(SUBJECT)
    export_rows = [r for r in await decision_history_rows() if r.event_type == "memory.export"]
    assert len(export_rows) == 1 and export_rows[0].payload["retention_seconds"] == ten_years

async def test_corrupt_overlay_export_fails_closed(memory_adapter, dh_store, tmp_path):
    obj = LocalObjectStoreAdapter(root=tmp_path)
    ctx = _ctx(served_subject=SUBJECT, agent_id="kyc")
    api = _api(ctx, memory_adapter, dh_store, obj, _FakeResolver(invalid=True))
    await memory_adapter.put(_task_record(value="payload"))
    with pytest.raises(MemoryOperationRefused) as e:
        await api.export(SUBJECT)
    assert e.value.reason == "memory_export_tenant_config_overlay_invalid"
```

- [ ] **Step 2: Run to verify fail** (MemoryAPI has no `resolver` kwarg; enum missing the value).

- [ ] **Step 3: Implement** — `tiers.py`: add `"memory_export_tenant_config_overlay_invalid",` to `MemoryRefusalReason`. `api.py`: add `resolver: TenantConfigResolver` to `MemoryAPI.__init__` (store `self._resolver`); in `export()`:
```python
        try:
            retention = await self._resolver.effective("memory_export_retention_seconds", ctx.tenant_id)
        except TenantConfigOverlayInvalid as exc:
            raise MemoryOperationRefused("memory_export_tenant_config_overlay_invalid") from exc
        return await _export.export_memory(..., retention_seconds=retention)
```
Update `tests/unit/core/memory/conftest.py::_build_api` (+ `_build_api_with_store`) to construct with `resolver=<base-returning fake>` so the existing memory suite stays green.

- [ ] **Step 4: Run to verify pass** — new tests + `uv run pytest tests/unit/core/memory -v` (the conftest ripple keeps the suite green). ruff/mypy.

- [ ] **Step 5: Halt-before-commit** (CC — memory stop-rule + closed-enum). **Full suite.** On token: `git add` tiers + api + conftest + test + commit (`feat(config-overlay): memory export retention overlay wiring (ADR-023)`).

---

### Task 9: Compliance ISO hooks (A.6.2.5)

*(Unchanged from the prior revision.)* Append `"config.tenant_overlay.set"`, `"config.tenant_overlay.cleared"` to the `A.6.2.5` `ControlEntry.intended_hooks` in `compliance/iso42001/controls.py`; test `tests/unit/compliance/test_config_overlay_iso.py` asserts both hooks present + `hook_status == "implemented"`; run the existing `test_control_mapping`/coverage suite green. **Halt-before-commit** (CC — compliance). Commit (`feat(config-overlay): tag A.6.2.5 with config.tenant_overlay hooks (ADR-023)`).

---

### Task 10: Composition-root wiring + router mount (memory production-wired; sandbox seam-only)

> **SEAM HONESTY (repeat):** the **memory** overlay is production-wired through the `Runtime` MemoryAPI factory. The **sandbox** overlay is **not** wired through `Runtime` (no Runtime-owned backend); `build_runtime()` builds the resolver and exposes it, but does NOT thread it into a sandbox create path (none exists). Do not add a fake one.

**Files:**
- Modify: `src/cognic_agentos/harness/runtime.py` (build `TenantConfigOverlayStore` + `TenantConfigResolver`; thread `resolver` into the `MemoryAPI(...)` in `_factory`; expose `config_overlay_store`/`config_overlay_resolver` on `Runtime`), `src/cognic_agentos/portal/api/app.py` (mount `build_config_overlay_routes(store=..., resolver=..., settings=settings)` under `/api/v1` when the store is wired)
- Test: extend `tests/unit/harness/test_runtime.py` + an app-mount test

- [ ] **Step 1: Write failing tests** — `runtime.memory_api_factory(ctx)._resolver is runtime.config_overlay_resolver`; `create_app(...)` mounts `PUT /api/v1/tenants/{tenant_id}/config-overlay/{field_key}` (assert in `app.routes`).
- [ ] **Step 2: Run to verify fail.**
- [ ] **Step 3: Implement** — `runtime.py`: `overlay_store = TenantConfigOverlayStore(engine)`; `overlay_resolver = TenantConfigResolver(store=overlay_store, base=settings, audit=audit_store, throttle_s=settings.config_overlay_invalid_at_read_throttle_s)`; pass `resolver=overlay_resolver` into the `MemoryAPI(...)` in `_factory`; add both to the `Runtime` dataclass. `app.py`: include `build_config_overlay_routes(store=overlay_store, resolver=overlay_resolver, settings=settings)` under `/api/v1` (3-state mount mirroring the packs router: store present → mount + `app.state.config_overlay_router_mounted = True`).
- [ ] **Step 4: Run to verify pass** — harness + app-mount tests + `uv run pytest tests/unit/harness tests/unit/portal/api/test_app*.py -v`. ruff/mypy.
- [ ] **Step 5: Halt-before-commit** (composition root — shared-surface). **Full suite.** On token: `git add src/cognic_agentos/harness/runtime.py src/cognic_agentos/portal/api/app.py tests/unit/harness/test_runtime.py <app-mount test> && git commit` (`feat(config-overlay): wire store+resolver into composition root + mount routes (ADR-023)`).

---

### Task 11: CC-gate promotion (113 → 117)

*(Unchanged from the prior revision.)* Update `_EXPECTED_ENTRY_COUNT` 113→117 first (TDD RED); append the 4 modules to `_CRITICAL_FILES` (verify FINAL file names); **verify the floor against FRESH full-package `--cov` coverage in THIS commit** (`uv run pytest --cov=cognic_agentos --cov-branch --cov-report=json -q` → `uv run python tools/check_critical_coverage.py`); land focused negative-path tests in the same commit if any module is below floor (do not lower the floor). **Halt-before-commit** (CC-gate). Commit (`feat(config-overlay): promote 4 overlay modules to CC coverage gate 113→117 (ADR-023)`).

---

### Task 12: ADR-023

*(Unchanged from the prior revision.)* Create `docs/adrs/ADR-023-per-tenant-config-overlay.md` (Status PROPOSED — human acceptance pending) following the existing ADR template (`Read` `docs/adrs/ADR-022-*.md`); record the tighten-only invariant, the closed registry + default-deny + kernel-locked list, the human-only operator-administered model, the wire-public `ConfigOverlayRBACScope` + `config.tenant_overlay.{set,cleared,invalid_at_read}` events + closed-enum vocabularies, the resolver fail-closed posture R + the A.9.2 audit-incident separation, the A.6.2.5 mapping, the ADR-004/019/006 threads, and the deferred items. **Do not self-accept.** **Halt-before-commit.** Commit (`docs(adr): ADR-023 per-tenant configuration overlay`).

---

## After all tasks

Use `superpowers:finishing-a-development-branch` — verify the full suite + the CC gate green, then present push/PR options (push + PR are **separate explicit tokens**; `--squash --delete-branch`; never `gh pr merge --auto`).

## Self-Review

**Spec coverage:** §1→Task 1 (incl. strict coercion + non-positive ceiling + kernel-floor-first + lock assertion); §2→Tasks 2+3; §3→Task 4; §4→Tasks 5+6 (5 pins + DELETE/GET + AST no-`RequireTenantOwnership`); §5→Task 7 (seam-honest); §6→Task 8 (ripple-contained); §7→Task 1 lock-assertion; §8→every task's tests + Task 11. Caveats: invalid_at_read minted request-id + payload→Task 4; gate 113→117 verify-fresh→Task 11; throttle per (tenant,field,reason)→Task 4; explicit-path + untracked-doc exclusion→discipline block.

**Review-pass fixes incorporated:** strict coercion (P1.1); kernel-floor-first order (P1.2); migration table-exists assertion (P1.3); `db.types.GovernanceJSON` (P1.4); `sa.TIMESTAMP` (P1.5); typed `_OverlayStore` Protocol (P1.6); `settings` as required factory arg (P1.7); sandbox seam-honesty no Runtime overclaim (P1.8); fleshed Tasks 7/8 behavioral tests (P2.1); DELETE/GET/AST tests (P2.2); Task 11 reference fix (P2.3); required `__init__.py` (P2.4).

**Type consistency:** `effective_many`/`effective`, `validate_tighten_only(field, *, base_value, proposed)`, `coerce_value`, `TenantOverlayRejected.reason`, the store methods, `ConfigOverlayRBACScope`, `sandbox_tenant_config_overlay_invalid`, `memory_export_tenant_config_overlay_invalid`, `build_config_overlay_routes(*, store, resolver, settings)` — used identically across tasks.

**Remaining implementer flags (confirm against live code at execution):** `db.types.GovernanceJSON` exact symbol; the `_export.export_memory` retention-payload key name (`retention_seconds`); the exact existing `admit_policy` call-sites to update with `resolver=`; final file names before the Task 11 gate bump.
