# ADR-028 Conversational Sessions — Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the kernel-owned conversation primitive — a durable transcript store plus a turn loop that wraps the existing M8 `AgentLoop` with bounded-replay context — and prove it on `kind` with BARs 1–3.

**Architecture:** Two new tables (`conversations`, `conversation_turns`) behind a `ConversationStore` that mirrors the `core/run/storage.py` chain-atomicity pattern. A `ConversationTurnExecutor` claims a single-writer lock, enforces lifecycle + bounds, assembles bounded-replay context **from the kernel store only**, invokes `AgentLoop.ask` through one new additive `prior_context` parameter, persists the turn, and appends one `conversation.turn_completed` chain row correlating to that turn's `agent_run_id`. The M8 dispatch chokepoint is untouched — every turn re-runs assignment → entitlement → policy against *current* state, which is what BAR 3 pins.

**Tech Stack:** Python 3.12, SQLAlchemy 2 async Core, Alembic, FastAPI, Pydantic v2, pytest + pytest-asyncio, `uv` for all Python invocation, `kind` + Helm for the deployed proof.

---

## Global Constraints

Copied verbatim from the spec and the repo's operating rules. **Every task's requirements implicitly include this section.**

- **OS-only rule.** Nothing in this slice places an agent, a persona, a bank schema, or UI inside `cognic-agentos` (spec §12). Content-safety scanners are hook packs (out of slice). The harness is a separate artifact.
- **Vocabulary.** Follow `docs/source-of-truth/VOCABULARY.md`. The primitive is a **conversation**, never a "session" (collision hygiene: `sandbox` already owns "session").
- **I-1 (record integrity).** "Model context derives exclusively from the kernel store. The turn API has no history-accepting field; a crafted payload attempting one fails closed-enum validation (`extra="forbid"`)."
- **I-2 (per-turn envelope).** "The envelope is evaluated against the actor's **current** entitlements on **every turn** — and per-dispatch inside the turn — never snapshot-at-creation, never cached across turns."
- **I-3 (v1 envelope form).** `allowed = agent pack's assigned capability set ∩ current actor's data-scope entitlements ∩ policy`.
- **Doctrine wording (binding).** "Authoring validates and constrains; dispatch remains the final authority." Never write "governance is only dispatch-time."
- **Plaintext placement.** Plaintext lives ONLY in `conversation_turns`. Hash-chain rows carry **digests only** (`question_sha256`, `answer_sha256`). Reconstruction is possible **until erasure**; never claim "always reconstructable".
- **Terminal-state refusal.** Posting a turn to a `closed`/`expired`/`erased` conversation refuses with `conversation_not_active` and **never invokes the AgentLoop** — the refusal fires before context assembly or any gateway activity.
- **Cross-tenant + cross-actor invisibility.** Reads and turn-posts are tenant-scoped AND creator-bound; both collapse to a 404 byte-identical to genuine not-found.
- **Single-writer via atomic DB claim**, not in-process locks (turn POSTs may land on any replica). Concurrent POST → 409, does not queue.
- **`context_strategy` v1 vocabulary is exactly one value: `bounded_replay`.** No summarization.
- **`core/` is a stop-rule subsystem.** Every commit touching it is halt-before-commit with `core-controls-engineer` scrutiny.
- **Critical-controls gate.** `tools/check_critical_coverage.py` currently carries **149** entries. Any module promoted onto it must meet **95% line / 90% branch** measured against **fresh `--cov-branch` `coverage.json` generated in the promoting commit itself**, and the count guard must be bumped in that same commit.
- **`src/cognic_agentos/protocol/mcp_authz.py` must remain byte-identical.** Verify with `git diff --stat main -- src/cognic_agentos/protocol/mcp_authz.py` (must be empty) at every commit.
- **Guard-staged commits.** `git reset -q` → `git add <exact paths>` → assert the staged set equals the expected set → commit. Never stage `.claude/settings.json`, `docs/handoffs/`, `docs/reviews/`, `infra/proof-1b/`, `scratchpad/`.
- **No auto-commit.** Halt for maintainer review + an explicit commit token after each task's self-review. Push/PR/merge each require their own separate token.
- **All Python runs under `uv`:** `uv run pytest ...`, `uv run mypy src tests`, `uv run ruff check .`, `uv run ruff format --check .`.
- **Gate ladder.** Pre-commit for a task: targeted tests + affected tests + `ruff check` + `ruff format --check` + `mypy`. Full suite (`uv run pytest`) at the commit token, and mandatorily for any task that touches `core/`, storage, or promotes a module onto the coverage gate.

---

## Scope

**In this slice:** conversation store; turn loop wrapping `AgentLoop`; bounded-replay context assembly; RBAC scopes `conversation.{create,read,post_turn,close}`; HTTP surface; migration `0015`; proof BARs 1–3 on `kind`.

**Deliberately out, with rationale:**

| Out | Owner | Why not here |
|---|---|---|
| BARs 4–7 (bounds proof, erasure, safety+escalation, SSE continuity) | full M8.5 program | The slice is the *gate*; BAR 4's bounds are **implemented** here (see below) but only proof-barred later |
| `conversation.escalated` / `.expired` / `.erased` chain rows; `escalate_to_human`; the reaper | later slices | BARs 5–6 |
| `conversation.export` / `conversation.redact` scopes | erasure slice | `RunRBACScope` grew 1→2 additively; the same pattern applies |
| `conversation_input` / `conversation_output` hook phases | safety slice | BAR 6; needs hook packs |
| ADR-020 typed projectors + SSE | harness slice | BAR 7 |
| The `[conversation]` agent-manifest block + tenant tighten-only ceilings | full program | Slice uses kernel `Settings` defaults; the manifest block is a `cli/validators/agents.py` change with its own review |
| Summarization | ADR-028 v1.1 | spec §5 |

**Bounds are implemented, not deferred.** `max_turns` and `cumulative_token_budget` refusals ship in Task 5. Only their *proof bar* (BAR 4) is deferred. Shipping an unbounded conversation primitive and promising bounds "later" is precisely the anti-pattern the production-grade rule forbids.

---

## Maintainer rulings (settled 2026-07-09 — do not relitigate)

1. **`core/conversation/_context.py` is OFF-gate.** It is pure selection over rows already scoped by `ConversationStore.load_replay_turns`; `storage.py` and `turn.py` own the enforcement boundaries. Precedent: `core/scheduler/_seams.py`, `packs/_lifecycle_helpers.py`, `sandbox/audit.py`. Its correctness is pinned by a dedicated unit suite plus BAR 2. **Count target for the whole slice is 149 → 151.**

2. **Token budget: Option 1 only.** `AgentAskResult` gains real `prompt_tokens` / `completion_tokens` in Task 4. Dropping the budget is not permitted; shipping zero counters is not permitted.

3. **No `ui_events.py` escalation.** `AgentRunStarted` projects payload via `data={**snapshot.payload}` and does not set `extra="forbid"`, so the two additive `agent.run.started` payload keys are safe. Task 4 still *verifies* this with the grep before editing — the ruling removes the escalation branch, not the check.

---

## File Structure

**New package `src/cognic_agentos/core/conversation/`:**

| File | Responsibility | Gate |
|---|---|---|
| `__init__.py` | re-export only | off |
| `_types.py` | closed enums, frozen records, pure `validate_transition`, typed exceptions | off (mirrors `core/run/_types.py`) |
| `_context.py` | pure bounded-replay selection → `tuple[PriorTurn, ...]` | off (see open decision) |
| `storage.py` | `ConversationStore`: tenant+creator isolation, atomic claim, chain-atomic writes | **ON — CC 149 → 150** |
| `turn.py` | `ConversationTurnExecutor`: claim → lifecycle → bounds → assemble → `AgentLoop.ask` → persist → chain row → release | **ON — CC 150 → 151** |

**Modified:**

| File | Change | Gate status |
|---|---|---|
| `core/agent/_types.py` | `+ PriorTurn` frozen dataclass | off (unchanged) |
| `core/agent/loop.py` | `+ prior_context` kwarg on `ask`; 2 additive `agent.run.started` payload keys | **already ON** — must stay ≥95/90 |
| `core/config.py` | `+ 4` conversation Settings | off; `core/` stop-rule |
| `portal/rbac/scopes.py` | `+ ConversationRBACScope`, `+ CONVERSATION_SCOPES` | already ON |
| `portal/rbac/actor.py` | widen `Actor.scopes` union | already ON |
| `portal/rbac/enforcement.py` | widen `RequireScope` union | already ON |
| `portal/api/app.py` | mount router; build executor in lifespan | off |
| `tools/check_critical_coverage.py` | `+2` entries, count guard 149 → 151 | n/a |

**New (off-gate):** `portal/api/conversations/{__init__,dto,routes}.py`, `db/migrations/versions/20260709_0015_conversations.py`, `infra/proof-m85/`.

**Interfaces produced by this slice** (later tasks depend on these exact names):

```python
# core/agent/_types.py
@dataclass(frozen=True, slots=True)
class PriorTurn:
    role: Literal["user", "assistant"]
    content: str

# core/conversation/_types.py
ConversationState = Literal["active", "closed", "expired", "erased"]
ConversationTurnRefusalReason = Literal[
    "conversation_not_active",
    "conversation_turn_in_progress",
    "conversation_max_turns_exceeded",
    "conversation_token_budget_exceeded",
]
class ConversationNotFound(Exception): ...
class ConversationTransitionRefused(Exception):  # .reason: str
class ConversationTurnRefused(Exception):        # .reason: ConversationTurnRefusalReason; .current_state: ConversationState
def validate_transition(*, from_state: ConversationState, to_state: ConversationState) -> None: ...

@dataclass(frozen=True, slots=True)
class ConversationRecord:
    conversation_id: uuid.UUID; tenant_id: str; agent_id: str; creator_subject: str
    state: ConversationState; turn_count: int; cumulative_tokens: int
    created_at: datetime; last_turn_at: datetime | None

@dataclass(frozen=True, slots=True)
class TurnRecord:
    turn_id: uuid.UUID; seq: int; user_message: str | None; answer: str | None
    agent_run_id: str; prompt_tokens: int; completion_tokens: int; created_at: datetime

# core/conversation/_context.py
def assemble_prior_context(
    turns: Sequence[TurnRecord], *, replay_last_n: int, token_ceiling: int
) -> tuple[PriorTurn, ...]: ...

# core/conversation/storage.py
class ConversationStore:
    def __init__(self, engine: AsyncEngine) -> None: ...
    async def create_conversation(self, *, conversation_id: uuid.UUID, tenant_id: str, agent_id: str,
                                  creator_subject: str, request_id: str) -> tuple[uuid.UUID, bytes]: ...
    async def load(self, conversation_id: uuid.UUID, *, tenant_id: str,
                   creator_subject: str) -> ConversationRecord | None: ...
    async def claim_turn(self, conversation_id: uuid.UUID, *, tenant_id: str, creator_subject: str,
                         now: datetime, claim_ttl_s: float) -> ConversationRecord: ...
    async def release_claim(self, conversation_id: uuid.UUID, *, tenant_id: str) -> None: ...
    async def load_replay_turns(self, conversation_id: uuid.UUID, *, tenant_id: str,
                                last_n: int) -> list[TurnRecord]: ...
    # Returns the turn_id it minted and inserted -- NOT a chain tuple. The caller
    # surfaces this exact id on the wire; a freshly-generated uuid would name a row
    # that does not exist.
    async def append_turn(self, *, conversation_id: uuid.UUID, tenant_id: str, seq: int,
                          user_message: str, answer: str, agent_run_id: str, prompt_tokens: int,
                          completion_tokens: int, actor_id: str, request_id: str) -> uuid.UUID: ...
    # from_state is NOT a parameter: the precondition reads it under the row lock and
    # projects it to the record_builder, so the chain row's from_state is the locked
    # truth rather than a caller's stale read.
    async def transition(self, *, conversation_id: uuid.UUID, tenant_id: str,
                         to_state: ConversationState,
                         actor_id: str, request_id: str) -> tuple[uuid.UUID, bytes]: ...

# core/conversation/turn.py
@dataclass(frozen=True, slots=True)
class TurnResult:
    turn_id: uuid.UUID; seq: int; answer: str; agent_run_id: str
    terminal_state: AgentRunTerminalState; refusal_reason: AgentDispatchRefusalReason | None

class ConversationTurnExecutor:
    def __init__(self, *, store: ConversationStore, loop: AgentLoop, max_turns: int,
                 cumulative_token_budget: int, replay_last_n: int, replay_token_ceiling: int,
                 claim_ttl_s: float, agent_run_wall_clock_s: float,
                 clock: Callable[[], datetime] = ...) -> None: ...
    async def post_turn(self, *, conversation_id: uuid.UUID, tenant_id: str, actor_subject: str,
                        user_message: str) -> TurnResult: ...

# portal/api/conversations/routes.py
# NO constructor args: routes mount at app-construction time, before the lifespan
# has built an engine. Both the store and the executor are read from app.state by
# request-time dependencies that fail closed with 503 until the lifespan populates
# them (the portal/api/runs/routes.py precedent).
def build_conversation_routes() -> APIRouter: ...
```

---

## Task 1: Conversation closed enums, records, and the pure state validator

**Files:**
- Create: `src/cognic_agentos/core/conversation/__init__.py`
- Create: `src/cognic_agentos/core/conversation/_types.py`
- Test: `tests/unit/core/conversation/__init__.py` (empty), `tests/unit/core/conversation/test_types.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `ConversationState`, `ConversationTurnRefusalReason`, `ConversationRecord`, `TurnRecord`, `ConversationNotFound`, `ConversationTransitionRefused`, `ConversationTurnRefused`, `validate_transition` — exactly as in the File Structure block above.

**Doctrine (locked here, per the `core/run/_types.py` A3a precedent):** the 4-value `ConversationState` vocabulary is **fixed now**. Later slices may only **expand the legal-transition matrix** (adding `active→expired`, `*→erased`); they must never add a state value, because `state` is a stored column and a vocabulary change is a migration.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/conversation/test_types.py
"""ADR-028 slice — closed-enum + state-machine drift detectors."""
import typing
import uuid
from datetime import UTC, datetime

import pytest

from cognic_agentos.core.conversation._types import (
    ConversationRecord,
    ConversationState,
    ConversationTransitionRefused,
    ConversationTurnRefusalReason,
    validate_transition,
)


def test_conversation_state_has_exactly_four_values() -> None:
    assert set(typing.get_args(ConversationState)) == {
        "active", "closed", "expired", "erased",
    }


def test_turn_refusal_reason_has_exactly_four_values() -> None:
    assert set(typing.get_args(ConversationTurnRefusalReason)) == {
        "conversation_not_active",
        "conversation_turn_in_progress",
        "conversation_max_turns_exceeded",
        "conversation_token_budget_exceeded",
    }


def test_active_to_closed_is_the_only_legal_pair_in_this_slice() -> None:
    validate_transition(from_state="active", to_state="closed")  # no raise


@pytest.mark.parametrize(
    ("frm", "to"),
    [
        ("active", "expired"),   # reserved — reaper slice
        ("active", "erased"),    # reserved — erasure slice
        ("closed", "active"),    # no reopen in v1 (spec §3)
        ("closed", "closed"),    # no self-loop
        ("erased", "closed"),
    ],
)
def test_reserved_pairs_refuse_until_expanded(frm: ConversationState, to: ConversationState) -> None:
    with pytest.raises(ConversationTransitionRefused) as exc:
        validate_transition(from_state=frm, to_state=to)
    assert exc.value.reason == "conversation_transition_invalid_state_pair"


def test_conversation_record_is_frozen() -> None:
    rec = ConversationRecord(
        conversation_id=uuid.uuid4(), tenant_id="t1", agent_id="a1",
        creator_subject="s1", state="active", turn_count=0, cumulative_tokens=0,
        created_at=datetime.now(UTC), last_turn_at=None,
    )
    with pytest.raises(Exception):
        rec.state = "closed"  # type: ignore[misc]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/core/conversation/test_types.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'cognic_agentos.core.conversation'`

- [ ] **Step 3: Write the implementation**

```python
# src/cognic_agentos/core/conversation/__init__.py
"""ADR-028 conversational sessions — kernel-owned conversation primitive."""
```

```python
# src/cognic_agentos/core/conversation/_types.py
"""ADR-028 — conversation closed enums + frozen records + the pure-functional
state validator. Re-export surface for core/conversation/storage.py.

Mirrors core/run/_types.py. OFF the critical-controls gate (pure types + a
pure-functional validator; the drift detectors at
tests/unit/core/conversation/test_types.py cover the surface). No I/O.

DOCTRINE (locked at the vertical slice): the ConversationState VOCABULARY is
fixed here at 4 values. Later slices (reaper expiry, erasure) may only EXPAND
the legal-transition matrix over these states — NEVER add a state value, which
would be a stored-column-vocabulary migration.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal

#: Full forward-compatible lifecycle vocabulary (4 values). ACTIVE in the
#: slice: active (genesis) / closed. RESERVED: expired (reaper slice),
#: erased (erasure slice).
ConversationState = Literal["active", "closed", "expired", "erased"]

#: Closed-enum refusal vocabulary for a turn POST. Wire-protocol-public: it is
#: the ``reason`` field of the 409 response body.
ConversationTurnRefusalReason = Literal[
    "conversation_not_active",
    "conversation_turn_in_progress",
    "conversation_max_turns_exceeded",
    "conversation_token_budget_exceeded",
]

#: Slice legal-transition subset. EXPAND ONLY; never change the vocabulary.
_SLICE_VALID_TRANSITIONS: Final[frozenset[tuple[ConversationState, ConversationState]]] = frozenset(
    {("active", "closed")}
)

_VALID_TRANSITIONS: Final[frozenset[tuple[ConversationState, ConversationState]]] = (
    _SLICE_VALID_TRANSITIONS
)


class ConversationNotFound(Exception):
    """Absent OR cross-tenant OR cross-actor. The route collapses all three to
    a 404 byte-identical to genuine not-found (cross-tenant-invisibility)."""


class ConversationTransitionRefused(Exception):
    """Illegal state pair. ``reason`` is the closed-enum wire value."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ConversationTurnRefused(Exception):
    """Governed turn refusal raised BEFORE the AgentLoop is invoked."""

    def __init__(self, reason: ConversationTurnRefusalReason, *, current_state: ConversationState) -> None:
        super().__init__(reason)
        self.reason: ConversationTurnRefusalReason = reason
        self.current_state: ConversationState = current_state


def validate_transition(*, from_state: ConversationState, to_state: ConversationState) -> None:
    """Pure-functional validator. No I/O. Keyword-only args eliminate the
    positional-misuse bug class. Raises on an illegal pair; returns None on a
    legal pair."""
    if (from_state, to_state) not in _VALID_TRANSITIONS:
        raise ConversationTransitionRefused("conversation_transition_invalid_state_pair")


@dataclass(frozen=True, slots=True)
class ConversationRecord:
    conversation_id: uuid.UUID
    tenant_id: str
    agent_id: str
    creator_subject: str
    state: ConversationState
    turn_count: int
    cumulative_tokens: int
    created_at: datetime
    last_turn_at: datetime | None


@dataclass(frozen=True, slots=True)
class TurnRecord:
    """``user_message``/``answer`` are ``None`` after erasure (tombstoned);
    ``seq`` and ``agent_run_id`` survive so the chain join stays reconstructable."""

    turn_id: uuid.UUID
    seq: int
    user_message: str | None
    answer: str | None
    agent_run_id: str
    prompt_tokens: int
    completion_tokens: int
    created_at: datetime
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/core/conversation/test_types.py -v`
Expected: PASS — 9 passed (5 parametrized + 4)

- [ ] **Step 5: Lint, type-check, verify the byte-identical guard**

```bash
uv run ruff check src/cognic_agentos/core/conversation tests/unit/core/conversation
uv run ruff format --check src/cognic_agentos/core/conversation tests/unit/core/conversation
uv run mypy src tests
git diff --stat main -- src/cognic_agentos/protocol/mcp_authz.py   # must print nothing
```

- [ ] **Step 6: HALT for maintainer review + commit token**

Report: files created, tests run and results, that `core/` was touched (stop-rule), that no module was promoted onto the coverage gate. Do not commit without the token. On token:

```bash
git reset -q
git add src/cognic_agentos/core/conversation/__init__.py \
        src/cognic_agentos/core/conversation/_types.py \
        tests/unit/core/conversation/__init__.py \
        tests/unit/core/conversation/test_types.py
# assert staged set == the 4 paths above, then:
git commit -m "feat(adr-028): conversation closed enums + frozen records + pure state validator"
```

---

## Task 2: Migration 0015 — `conversations` + `conversation_turns`

**Files:**
- Create: `src/cognic_agentos/db/migrations/versions/20260709_0015_conversations.py`
- Test: `tests/unit/db/test_migration_20260709_0015.py`

**Interfaces:**
- Consumes: `ConversationState` (for the CHECK constraint values).
- Produces: tables `conversations`, `conversation_turns`; indexes `ix_conversations_tenant_creator_state`, `uq_conversation_turns_conversation_seq`.

**Why `turn_claimed_at` exists:** the atomic claim (Task 3) sets `turn_in_progress`. A process crash mid-turn would otherwise wedge the conversation permanently. `turn_claimed_at` lets the claim predicate treat a stale claim as reclaimable. This is a **known, bounded hazard**: a claim older than `claim_ttl_s` is stolen, so a pathologically slow turn could be double-run. `claim_ttl_s` must therefore exceed `agent_run_wall_clock_s` (default 120.0). Task 5 asserts this at construction.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/db/test_migration_20260709_0015.py
"""Migration 0015 shape drift detector — ADR-028 conversation substrate."""
import pathlib
import re

MIGRATION = (
    pathlib.Path(__file__).parents[3]
    / "src/cognic_agentos/db/migrations/versions/20260709_0015_conversations.py"
)


def test_migration_exists_and_chains_to_0014() -> None:
    src = MIGRATION.read_text()
    assert re.search(r'^revision: str = "0015"', src, re.M)
    assert re.search(r'^down_revision: str \| None = "0014"', src, re.M)


def test_creates_both_tables() -> None:
    src = MIGRATION.read_text()
    assert 'op.create_table(\n        "conversations"' in src
    assert 'op.create_table(\n        "conversation_turns"' in src


def test_tenant_id_is_not_nullable_on_conversations() -> None:
    """tenant_id IS the isolation boundary (spec section 3)."""
    src = MIGRATION.read_text()
    assert 'sa.Column("tenant_id", sa.String(255), nullable=False)' in src


def test_seq_is_unique_per_conversation() -> None:
    src = MIGRATION.read_text()
    assert "uq_conversation_turns_conversation_seq" in src


def test_plaintext_columns_are_nullable_for_erasure() -> None:
    """Erasure sets plaintext to NULL; the row itself survives (spec section 3)."""
    src = MIGRATION.read_text()
    assert 'sa.Column("user_message", sa.Text(), nullable=True)' in src
    assert 'sa.Column("answer", sa.Text(), nullable=True)' in src


def test_downgrade_drops_both_tables() -> None:
    src = MIGRATION.read_text()
    assert 'op.drop_table("conversation_turns")' in src
    assert 'op.drop_table("conversations")' in src
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/db/test_migration_20260709_0015.py -v`
Expected: FAIL — `FileNotFoundError` on `MIGRATION.read_text()`

- [ ] **Step 3: Write the implementation**

```python
# src/cognic_agentos/db/migrations/versions/20260709_0015_conversations.py
"""conversations + conversation_turns — ADR-028 conversational sessions.

The conversation substrate for the M8.5 vertical slice. Mirrors the runs
substrate (migration 0011).

Plaintext lives ONLY in conversation_turns.user_message / .answer, both
NULLABLE so the erasure pathway can tombstone content while preserving the
row -- seq integrity and the agent_run_id chain correlation survive erasure.

conversations.tenant_id is NOT NULL: it is the isolation boundary. Every read
and every turn-post is scoped by (tenant_id, creator_subject).

turn_in_progress + turn_claimed_at implement the atomic single-writer claim
(PT-6): turn POSTs may land on any replica, so the claim is a DB predicate,
never an in-process lock.

Revision ID: 0015
Revises: 0014
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | None = None
depends_on: str | None = None

_CONVERSATION_STATES = ("active", "closed", "expired", "erased")


def upgrade() -> None:
    op.create_table(
        "conversations",
        sa.Column("conversation_id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.String(255), nullable=False),
        sa.Column("agent_id", sa.String(255), nullable=False),
        sa.Column("creator_subject", sa.String(255), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("turn_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cumulative_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("turn_in_progress", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("turn_claimed_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("retention_class", sa.String(64), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("last_turn_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("erased_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('" + "', '".join(_CONVERSATION_STATES) + "')",
            name="ck_conversations_state",
        ),
    )
    op.create_index(
        "ix_conversations_tenant_creator_state",
        "conversations",
        ["tenant_id", "creator_subject", "state"],
    )

    op.create_table(
        "conversation_turns",
        sa.Column("turn_id", sa.Uuid(), primary_key=True),
        sa.Column("conversation_id", sa.Uuid(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("user_message", sa.Text(), nullable=True),
        sa.Column("answer", sa.Text(), nullable=True),
        sa.Column("agent_run_id", sa.String(64), nullable=False),
        sa.Column("prompt_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("completion_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("erased_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["conversation_id"],
            ["conversations.conversation_id"],
            name="fk_conversation_turns_conversation_id",
        ),
        sa.UniqueConstraint(
            "conversation_id", "seq", name="uq_conversation_turns_conversation_seq"
        ),
    )


def downgrade() -> None:
    op.drop_table("conversation_turns")
    op.drop_index("ix_conversations_tenant_creator_state", table_name="conversations")
    op.drop_table("conversations")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/db/test_migration_20260709_0015.py -v`
Expected: PASS — 6 passed

- [ ] **Step 5: Prove the migration actually runs against a real DB**

Per `feedback_storage_test_migrated_db_not_create_all`: `create_all` omits migration-only constraints. Run the real Alembic chain.

```bash
COGNIC_RUN_POSTGRES_INTEGRATION=1 uv run alembic upgrade head
COGNIC_RUN_POSTGRES_INTEGRATION=1 uv run alembic downgrade 0014
COGNIC_RUN_POSTGRES_INTEGRATION=1 uv run alembic upgrade head
```
Expected: three clean runs, no error. The down-then-up proves `downgrade()` is real.

- [ ] **Step 6: Lint, type-check, byte-identical guard**

```bash
uv run ruff check src/cognic_agentos/db/migrations/versions/20260709_0015_conversations.py tests/unit/db/test_migration_20260709_0015.py
uv run ruff format --check src/cognic_agentos/db/migrations/versions/20260709_0015_conversations.py tests/unit/db/test_migration_20260709_0015.py
uv run mypy src tests
git diff --stat main -- src/cognic_agentos/protocol/mcp_authz.py   # must print nothing
```

- [ ] **Step 7: HALT for maintainer review + commit token**

Report the alembic up/down/up output verbatim. On token, guard-stage the 2 paths and commit:

```
feat(adr-028): migration 0015 — conversations + conversation_turns substrate
```

---

## Task 3: `ConversationStore` — tenant+creator isolation, atomic claim, chain-atomic writes

**Files:**
- Create: `src/cognic_agentos/core/conversation/storage.py`
- Test: `tests/unit/core/conversation/test_storage.py`
- Modify: `tools/check_critical_coverage.py` (add entry; count guard **149 → 150**)

**Interfaces:**
- Consumes: `_types.py` (all); `core.decision_history.DecisionHistoryStore.append_with_precondition`, `.append`, `DecisionRecord`.
- Produces: `ConversationStore` with exactly the eight methods in the File Structure block.

**This module is ON the critical-controls gate.** It owns two enforcement boundaries: (a) the `tenant_id` + `creator_subject` WHERE clause *is* the cross-tenant/cross-actor boundary — a cross-tenant `conversation_id` must read as absent; (b) chain-row + state-cache atomicity under one transaction (Doctrine Lock D).

**Chain evidence written here:**
- `create_conversation` → `conversation.created` (payload: `conversation_id`, `agent_id`, `creator_subject`)
- `append_turn` → `conversation.turn_completed` (payload: `conversation_id`, `seq`, `agent_run_id`, `question_sha256`, `question_bytes`, `answer_sha256`, `answer_bytes`, `prompt_tokens`, `completion_tokens`) — **digests only, never plaintext**
- `transition` → `conversation.<to_state>` i.e. `conversation.closed`

- [ ] **Step 1: Write the failing tests (isolation + claim + digest-only)**

```python
# tests/unit/core/conversation/test_storage.py
"""ConversationStore — REAL DecisionHistoryStore over in-memory sqlite.
Mirrors tests/unit/core/run/test_executor.py's engine fixture."""
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine

from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationTurnRefused,
)
from cognic_agentos.core.conversation.storage import ConversationStore, _conversations, _conversation_turns
from cognic_agentos.core.decision_history import _decision_history


@pytest_asyncio.fixture
async def store(tmp_path):
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'conv.db'}")
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    async with eng.begin() as conn:
        await conn.run_sync(_decision_history.metadata.create_all)
        await conn.run_sync(_conversations.metadata.create_all)
    yield ConversationStore(eng)
    await eng.dispose()


async def _new(store: ConversationStore, *, tenant="t1", subject="s1") -> uuid.UUID:
    cid = uuid.uuid4()
    await store.create_conversation(
        conversation_id=cid, tenant_id=tenant, agent_id="analyst",
        creator_subject=subject, request_id="req-1",
    )
    return cid


@pytest.mark.asyncio
async def test_cross_tenant_read_is_absent(store) -> None:
    cid = await _new(store, tenant="tenant-a")
    assert await store.load(cid, tenant_id="tenant-a", creator_subject="s1") is not None
    assert await store.load(cid, tenant_id="tenant-b", creator_subject="s1") is None


@pytest.mark.asyncio
async def test_cross_actor_read_is_absent(store) -> None:
    cid = await _new(store, subject="alice")
    assert await store.load(cid, tenant_id="t1", creator_subject="bob") is None


@pytest.mark.asyncio
async def test_claim_is_exclusive_second_claim_refuses(store) -> None:
    cid = await _new(store)
    now = datetime.now(UTC)
    await store.claim_turn(cid, tenant_id="t1", creator_subject="s1", now=now, claim_ttl_s=300.0)
    with pytest.raises(ConversationTurnRefused) as exc:
        await store.claim_turn(cid, tenant_id="t1", creator_subject="s1", now=now, claim_ttl_s=300.0)
    assert exc.value.reason == "conversation_turn_in_progress"


@pytest.mark.asyncio
async def test_release_allows_reclaim(store) -> None:
    cid = await _new(store)
    now = datetime.now(UTC)
    await store.claim_turn(cid, tenant_id="t1", creator_subject="s1", now=now, claim_ttl_s=300.0)
    await store.release_claim(cid, tenant_id="t1")
    await store.claim_turn(cid, tenant_id="t1", creator_subject="s1", now=now, claim_ttl_s=300.0)


@pytest.mark.asyncio
async def test_stale_claim_is_reclaimable_after_ttl(store) -> None:
    cid = await _new(store)
    t0 = datetime.now(UTC)
    await store.claim_turn(cid, tenant_id="t1", creator_subject="s1", now=t0, claim_ttl_s=60.0)
    later = t0 + timedelta(seconds=61)
    await store.claim_turn(cid, tenant_id="t1", creator_subject="s1", now=later, claim_ttl_s=60.0)


@pytest.mark.asyncio
async def test_claim_on_closed_conversation_refuses_not_active(store) -> None:
    cid = await _new(store)
    await store.transition(
        conversation_id=cid, tenant_id="t1", to_state="closed",
        actor_id="s1", request_id="req-2",
    )
    with pytest.raises(ConversationTurnRefused) as exc:
        await store.claim_turn(
            cid, tenant_id="t1", creator_subject="s1", now=datetime.now(UTC), claim_ttl_s=300.0
        )
    assert exc.value.reason == "conversation_not_active"
    assert exc.value.current_state == "closed"


@pytest.mark.asyncio
async def test_claim_on_missing_conversation_raises_not_found(store) -> None:
    with pytest.raises(ConversationNotFound):
        await store.claim_turn(
            uuid.uuid4(), tenant_id="t1", creator_subject="s1",
            now=datetime.now(UTC), claim_ttl_s=300.0,
        )


@pytest.mark.asyncio
async def test_turn_chain_row_carries_digests_never_plaintext(store) -> None:
    cid = await _new(store)
    await store.append_turn(
        conversation_id=cid, tenant_id="t1", seq=1,
        user_message="what is the top depositor", answer="Acme Corp",
        agent_run_id="agent-run-abc", prompt_tokens=10, completion_tokens=5,
        actor_id="s1", request_id="req-3",
    )
    async with store._engine.connect() as conn:  # noqa: SLF001 - evidence assertion
        rows = (
            await conn.execute(
                sa.select(_decision_history.c.decision_type, _decision_history.c.payload)
            )
        ).fetchall()
    turn_rows = [r for r in rows if r.decision_type == "conversation.turn_completed"]
    assert len(turn_rows) == 1
    payload = turn_rows[0].payload
    assert payload["agent_run_id"] == "agent-run-abc"
    assert payload["seq"] == 1
    assert set(payload) >= {"question_sha256", "answer_sha256", "question_bytes", "answer_bytes"}
    blob = str(payload)
    assert "top depositor" not in blob
    assert "Acme Corp" not in blob


@pytest.mark.asyncio
async def test_append_turn_returns_the_id_it_actually_inserted(store) -> None:
    """The returned turn_id must name a real row. A freshly-minted uuid
    downstream would surface an id that resolves to nothing."""
    cid = await _new(store)
    turn_id = await store.append_turn(
        conversation_id=cid, tenant_id="t1", seq=1, user_message="q", answer="a",
        agent_run_id="r1", prompt_tokens=1, completion_tokens=1,
        actor_id="s1", request_id="req-t",
    )
    async with store._engine.connect() as conn:  # noqa: SLF001
        found = (
            await conn.execute(
                sa.select(_conversation_turns.c.turn_id).where(
                    _conversation_turns.c.turn_id == turn_id
                )
            )
        ).first()
    assert found is not None


@pytest.mark.asyncio
async def test_turn_chain_payload_carries_the_same_turn_id(store) -> None:
    cid = await _new(store)
    turn_id = await store.append_turn(
        conversation_id=cid, tenant_id="t1", seq=1, user_message="q", answer="a",
        agent_run_id="r1", prompt_tokens=1, completion_tokens=1,
        actor_id="s1", request_id="req-t2",
    )
    async with store._engine.connect() as conn:  # noqa: SLF001
        rows = (await conn.execute(sa.select(_decision_history.c.decision_type,
                                             _decision_history.c.payload))).fetchall()
    turn_row = next(r for r in rows if r.decision_type == "conversation.turn_completed")
    assert turn_row.payload["turn_id"] == str(turn_id)


@pytest.mark.asyncio
async def test_transition_records_the_locked_from_state(store) -> None:
    cid = await _new(store)
    await store.transition(
        conversation_id=cid, tenant_id="t1", to_state="closed",
        actor_id="s1", request_id="req-c",
    )
    async with store._engine.connect() as conn:  # noqa: SLF001
        rows = (await conn.execute(sa.select(_decision_history.c.decision_type,
                                             _decision_history.c.payload))).fetchall()
    closed = next(r for r in rows if r.decision_type == "conversation.closed")
    assert closed.payload["from_state"] == "active"
    assert closed.payload["to_state"] == "closed"


@pytest.mark.asyncio
async def test_append_turn_bumps_counters(store) -> None:
    cid = await _new(store)
    await store.append_turn(
        conversation_id=cid, tenant_id="t1", seq=1, user_message="q", answer="a",
        agent_run_id="r1", prompt_tokens=7, completion_tokens=3,
        actor_id="s1", request_id="req-4",
    )
    rec = await store.load(cid, tenant_id="t1", creator_subject="s1")
    assert rec is not None and rec.turn_count == 1 and rec.cumulative_tokens == 10


@pytest.mark.asyncio
async def test_replay_turns_returns_first_then_last_n_in_seq_order(store) -> None:
    cid = await _new(store)
    for i in range(1, 6):
        await store.append_turn(
            conversation_id=cid, tenant_id="t1", seq=i, user_message=f"q{i}", answer=f"a{i}",
            agent_run_id=f"r{i}", prompt_tokens=1, completion_tokens=1,
            actor_id="s1", request_id=f"req-{i}",
        )
    turns = await store.load_replay_turns(cid, tenant_id="t1", last_n=2)
    assert [t.seq for t in turns] == [1, 4, 5]


@pytest.mark.asyncio
async def test_replay_turns_is_tenant_scoped(store) -> None:
    cid = await _new(store, tenant="tenant-a")
    await store.append_turn(
        conversation_id=cid, tenant_id="tenant-a", seq=1, user_message="q", answer="a",
        agent_run_id="r1", prompt_tokens=1, completion_tokens=1,
        actor_id="s1", request_id="req-9",
    )
    assert await store.load_replay_turns(cid, tenant_id="tenant-b", last_n=5) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/core/conversation/test_storage.py -v`
Expected: FAIL — `ImportError: cannot import name 'ConversationStore'`

- [ ] **Step 3: Write the implementation**

```python
# src/cognic_agentos/core/conversation/storage.py
"""ADR-028 — Postgres/Oracle-backed conversation store.

CRITICAL CONTROLS. Two enforcement boundaries live here:

1. Tenant + creator isolation. Every read and every claim carries
   ``WHERE tenant_id = :tenant_id AND creator_subject = :creator_subject``.
   A cross-tenant or cross-actor conversation_id reads as ABSENT (None /
   ConversationNotFound), never as a permission error -- the route collapses
   it to a 404 byte-identical to genuine not-found.

2. Chain atomicity (Doctrine Lock D). Every write drives
   DecisionHistoryStore.append_with_precondition so the chain row, the
   state-cache UPDATE and the chain-head UPDATE commit in ONE transaction.
   A refusal inside the precondition rolls all three back.

Plaintext NEVER enters a chain payload. conversation.turn_completed carries
question_sha256 / answer_sha256 + byte counts (the M8 digest-only doctrine
extended to conversations, spec section 3).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any, Final

import sqlalchemy as sa
from sqlalchemy import (
    Boolean,
    Column,
    ForeignKeyConstraint,
    Integer,
    MetaData,
    String,
    TIMESTAMP,
    Table,
    Text,
    Uuid,
    UniqueConstraint,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationRecord,
    ConversationState,
    ConversationTurnRefused,
    TurnRecord,
    validate_transition,
)
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord

_metadata = MetaData()

#: ISO 42001 controls stamped on every conversation lifecycle chain row.
_CONVERSATION_ISO_CONTROLS: Final[tuple[str, ...]] = ("A.5.31", "A.6.2.4")

_conversations = Table(
    "conversations",
    _metadata,
    Column("conversation_id", Uuid(), primary_key=True),
    Column("tenant_id", String(255), nullable=False),
    Column("agent_id", String(255), nullable=False),
    Column("creator_subject", String(255), nullable=False),
    Column("state", String(32), nullable=False),
    Column("turn_count", Integer(), nullable=False, server_default="0"),
    Column("cumulative_tokens", Integer(), nullable=False, server_default="0"),
    Column("turn_in_progress", Boolean(), nullable=False, server_default=sa.false()),
    Column("turn_claimed_at", TIMESTAMP(timezone=True), nullable=True),
    Column("retention_class", String(64), nullable=True),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False),
    Column("last_turn_at", TIMESTAMP(timezone=True), nullable=True),
    Column("erased_at", TIMESTAMP(timezone=True), nullable=True),
)

_conversation_turns = Table(
    "conversation_turns",
    _metadata,
    Column("turn_id", Uuid(), primary_key=True),
    Column("conversation_id", Uuid(), nullable=False),
    Column("seq", Integer(), nullable=False),
    Column("user_message", Text(), nullable=True),
    Column("answer", Text(), nullable=True),
    Column("agent_run_id", String(64), nullable=False),
    Column("prompt_tokens", Integer(), nullable=False, server_default="0"),
    Column("completion_tokens", Integer(), nullable=False, server_default="0"),
    Column("created_at", TIMESTAMP(timezone=True), nullable=False),
    Column("erased_at", TIMESTAMP(timezone=True), nullable=True),
    ForeignKeyConstraint(["conversation_id"], ["conversations.conversation_id"]),
    UniqueConstraint("conversation_id", "seq", name="uq_conversation_turns_conversation_seq"),
)


def _digest(text: str) -> tuple[str, int]:
    raw = text.encode("utf-8")
    return hashlib.sha256(raw).hexdigest(), len(raw)


class ConversationStore:
    """Async; raises on every refusal/failure (no silent-skip)."""

    def __init__(self, engine: AsyncEngine) -> None:
        self._engine = engine
        self._history = DecisionHistoryStore(engine)

    # -- genesis ------------------------------------------------------------

    async def create_conversation(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        agent_id: str,
        creator_subject: str,
        request_id: str,
    ) -> tuple[uuid.UUID, bytes]:
        now = datetime.now(UTC)

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> None:
            await conn.execute(
                sa.insert(_conversations).values(
                    conversation_id=conversation_id,
                    tenant_id=tenant_id,
                    agent_id=agent_id,
                    creator_subject=creator_subject,
                    state="active",
                    turn_count=0,
                    cumulative_tokens=0,
                    turn_in_progress=False,
                    turn_claimed_at=None,
                    created_at=now,
                    last_turn_at=None,
                )
            )

        def _build(_: None) -> DecisionRecord:
            return DecisionRecord(
                decision_type="conversation.created",
                request_id=request_id,
                payload={
                    "conversation_id": str(conversation_id),
                    "agent_id": agent_id,
                    "creator_subject": creator_subject,
                    "created_at": now.isoformat(),
                },
                actor_id=creator_subject,
                tenant_id=tenant_id,
                iso_controls=_CONVERSATION_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build, precondition=_precondition
        )

    # -- reads (tenant + creator scoped) ------------------------------------

    async def load(
        self, conversation_id: uuid.UUID, *, tenant_id: str, creator_subject: str
    ) -> ConversationRecord | None:
        stmt = select(_conversations).where(
            _conversations.c.conversation_id == conversation_id,
            _conversations.c.tenant_id == tenant_id,
            _conversations.c.creator_subject == creator_subject,
        )
        async with self._engine.connect() as conn:
            row = (await conn.execute(stmt)).mappings().first()
        if row is None:
            return None
        return ConversationRecord(
            conversation_id=row["conversation_id"],
            tenant_id=row["tenant_id"],
            agent_id=row["agent_id"],
            creator_subject=row["creator_subject"],
            state=row["state"],
            turn_count=row["turn_count"],
            cumulative_tokens=row["cumulative_tokens"],
            created_at=row["created_at"],
            last_turn_at=row["last_turn_at"],
        )

    async def load_replay_turns(
        self, conversation_id: uuid.UUID, *, tenant_id: str, last_n: int
    ) -> list[TurnRecord]:
        """Bounded replay source: the FIRST turn (grounding) + the LAST n turns,
        de-duplicated, in ascending seq order. Tenant-scoped via a join on the
        parent conversation -- a foreign tenant reads as an empty list."""
        joined = _conversation_turns.join(
            _conversations,
            _conversation_turns.c.conversation_id == _conversations.c.conversation_id,
        )
        base = (
            select(_conversation_turns)
            .select_from(joined)
            .where(
                _conversation_turns.c.conversation_id == conversation_id,
                _conversations.c.tenant_id == tenant_id,
            )
        )
        first_stmt = base.order_by(_conversation_turns.c.seq.asc()).limit(1)
        last_stmt = base.order_by(_conversation_turns.c.seq.desc()).limit(last_n)
        async with self._engine.connect() as conn:
            first = (await conn.execute(first_stmt)).mappings().all()
            last = (await conn.execute(last_stmt)).mappings().all()
        by_seq: dict[int, Any] = {r["seq"]: r for r in [*first, *last]}
        return [
            TurnRecord(
                turn_id=r["turn_id"],
                seq=r["seq"],
                user_message=r["user_message"],
                answer=r["answer"],
                agent_run_id=r["agent_run_id"],
                prompt_tokens=r["prompt_tokens"],
                completion_tokens=r["completion_tokens"],
                created_at=r["created_at"],
            )
            for _, r in sorted(by_seq.items())
        ]

    # -- the atomic single-writer claim (PT-6) ------------------------------

    async def claim_turn(
        self,
        conversation_id: uuid.UUID,
        *,
        tenant_id: str,
        creator_subject: str,
        now: datetime,
        claim_ttl_s: float,
    ) -> ConversationRecord:
        """Atomically claim the conversation for one turn. DB predicate, never
        an in-process lock -- turn POSTs may land on any replica.

        Stale-claim detection compares ``turn_claimed_at`` against ``now`` in
        Python, under the row lock -- portable across Postgres / Oracle / sqlite.
        Do NOT reach for ``sa.func.make_interval`` (Postgres-only).

        Raises ConversationNotFound (absent / cross-tenant / cross-actor) or
        ConversationTurnRefused ('conversation_not_active' with the current
        state, or 'conversation_turn_in_progress')."""
        async with self._engine.begin() as conn:
            row = (
                await conn.execute(
                    select(_conversations)
                    .where(
                        _conversations.c.conversation_id == conversation_id,
                        _conversations.c.tenant_id == tenant_id,
                        _conversations.c.creator_subject == creator_subject,
                    )
                    .with_for_update()
                )
            ).mappings().first()
            if row is None:
                raise ConversationNotFound(str(conversation_id))
            if row["state"] != "active":
                raise ConversationTurnRefused(
                    "conversation_not_active", current_state=row["state"]
                )
            claimed_at = row["turn_claimed_at"]
            claim_is_live = bool(row["turn_in_progress"]) and (
                claimed_at is not None and (now - claimed_at).total_seconds() < claim_ttl_s
            )
            if claim_is_live:
                raise ConversationTurnRefused(
                    "conversation_turn_in_progress", current_state=row["state"]
                )
            await conn.execute(
                update(_conversations)
                .where(_conversations.c.conversation_id == conversation_id)
                .values(turn_in_progress=True, turn_claimed_at=now)
            )
        return ConversationRecord(
            conversation_id=row["conversation_id"],
            tenant_id=row["tenant_id"],
            agent_id=row["agent_id"],
            creator_subject=row["creator_subject"],
            state=row["state"],
            turn_count=row["turn_count"],
            cumulative_tokens=row["cumulative_tokens"],
            created_at=row["created_at"],
            last_turn_at=row["last_turn_at"],
        )

    async def release_claim(self, conversation_id: uuid.UUID, *, tenant_id: str) -> None:
        async with self._engine.begin() as conn:
            await conn.execute(
                update(_conversations)
                .where(
                    _conversations.c.conversation_id == conversation_id,
                    _conversations.c.tenant_id == tenant_id,
                )
                .values(turn_in_progress=False, turn_claimed_at=None)
            )

    # -- turn persistence (chain-atomic, digest-only) -----------------------

    async def append_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        seq: int,
        user_message: str,
        answer: str,
        agent_run_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        actor_id: str,
        request_id: str,
    ) -> uuid.UUID:
        """Persist the turn + append conversation.turn_completed atomically.

        Returns the turn_id THIS METHOD minted and inserted. The caller surfaces
        that exact id on the wire -- minting a fresh uuid downstream would name a
        row that does not exist.
        """
        now = datetime.now(UTC)
        turn_id = uuid.uuid4()
        q_sha, q_bytes = _digest(user_message)
        a_sha, a_bytes = _digest(answer)

        async def _precondition(conn: AsyncConnection, _seq: int, _hash: bytes) -> None:
            await conn.execute(
                sa.insert(_conversation_turns).values(
                    turn_id=turn_id,
                    conversation_id=conversation_id,
                    seq=seq,
                    user_message=user_message,
                    answer=answer,
                    agent_run_id=agent_run_id,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    created_at=now,
                )
            )
            await conn.execute(
                update(_conversations)
                .where(
                    _conversations.c.conversation_id == conversation_id,
                    _conversations.c.tenant_id == tenant_id,
                )
                .values(
                    turn_count=_conversations.c.turn_count + 1,
                    cumulative_tokens=_conversations.c.cumulative_tokens
                    + prompt_tokens
                    + completion_tokens,
                    last_turn_at=now,
                )
            )

        def _build(_: None) -> DecisionRecord:
            return DecisionRecord(
                decision_type="conversation.turn_completed",
                request_id=request_id,
                payload={
                    "conversation_id": str(conversation_id),
                    "turn_id": str(turn_id),
                    "seq": seq,
                    "agent_run_id": agent_run_id,
                    "question_sha256": q_sha,
                    "question_bytes": q_bytes,
                    "answer_sha256": a_sha,
                    "answer_bytes": a_bytes,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                },
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=_CONVERSATION_ISO_CONTROLS,
            )

        await self._history.append_with_precondition(
            record_builder=_build, precondition=_precondition
        )
        return turn_id

    # -- lifecycle ----------------------------------------------------------

    async def transition(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        to_state: ConversationState,
        actor_id: str,
        request_id: str,
    ) -> tuple[uuid.UUID, bytes]:
        """State-machine transition (tenant-scoped, atomic).

        ``from_state`` is NOT a parameter. The precondition reads it under the
        row lock and PROJECTS it to the record_builder, so the chain row records
        the locked truth -- a caller's stale read can never enter evidence.
        """

        async def _precondition(
            conn: AsyncConnection, _seq: int, _hash: bytes
        ) -> ConversationState:
            row = (
                await conn.execute(
                    select(_conversations.c.state)
                    .where(
                        _conversations.c.conversation_id == conversation_id,
                        _conversations.c.tenant_id == tenant_id,
                    )
                    .with_for_update()
                )
            ).first()
            if row is None:
                raise ConversationNotFound(str(conversation_id))
            from_state: ConversationState = row[0]
            validate_transition(from_state=from_state, to_state=to_state)
            await conn.execute(
                update(_conversations)
                .where(_conversations.c.conversation_id == conversation_id)
                .values(state=to_state, turn_in_progress=False, turn_claimed_at=None)
            )
            return from_state

        def _build(from_state: ConversationState) -> DecisionRecord:
            return DecisionRecord(
                decision_type=f"conversation.{to_state}",
                request_id=request_id,
                payload={
                    "conversation_id": str(conversation_id),
                    "from_state": from_state,
                    "to_state": to_state,
                },
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=_CONVERSATION_ISO_CONTROLS,
            )

        return await self._history.append_with_precondition(
            record_builder=_build, precondition=_precondition
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/core/conversation/test_storage.py -v`
Expected: PASS — 14 passed

- [ ] **Step 5: Add negative-path coverage until the module clears 95/90**

The gate is **95% line / 90% branch**. The tests above miss: `transition` on a missing conversation; `transition` on an illegal pair; `load_replay_turns` when `last_n` exceeds the turn count. Write those three, then measure:

```bash
uv run pytest tests/unit/core/conversation --cov=src/cognic_agentos/core/conversation/storage.py --cov-branch --cov-report=term-missing
```
Expected: `storage.py` ≥ 95% line, ≥ 90% branch. If not, add tests for the uncovered lines named in the report. **Do not lower the floor.**

- [ ] **Step 6: Promote onto the coverage gate**

In `tools/check_critical_coverage.py`, append to `_CRITICAL_FILES`:

```python
    # ADR-028 vertical slice — the conversation tenant+creator isolation
    # boundary and the chain-atomic write path. Gate 149 -> 150.
    ("src/cognic_agentos/core/conversation/storage.py", 95.0, 90.0),
```

and bump the count guard from 149 to 150.

- [ ] **Step 7: Run the gate against FRESH coverage data generated in this commit**

Per `feedback_verify_promotion_meets_floor_at_promotion_time` — a stale `coverage.json` has caught sibling regressions before. Generate it fresh:

```bash
uv run pytest --cov=src/cognic_agentos --cov-branch --cov-report=json
uv run python tools/check_critical_coverage.py
```
Expected: `150/150 PASS`. If any *other* module regressed, fix it in this same commit.

- [ ] **Step 8: Full gate ladder**

```bash
uv run pytest                                    # full suite - mandatory: core/ + storage + gate promotion
uv run ruff check . && uv run ruff format --check .
uv run mypy src tests
git diff --stat main -- src/cognic_agentos/protocol/mcp_authz.py   # must print nothing
```

- [ ] **Step 9: HALT for maintainer review + commit token**

Tag the commit subject `(CRITICAL CONTROLS)`. Report: the fresh `150/150` output verbatim, the coverage percentages for `storage.py`, and confirmation that `mcp_authz.py` is byte-identical. On token, guard-stage and commit:

```
feat(adr-028): ConversationStore — tenant+creator isolation, atomic claim, chain-atomic digest-only writes (CRITICAL CONTROLS)
```

---

## Task 4: Additive `prior_context` on the M8 `AgentLoop`

**Files:**
- Modify: `src/cognic_agentos/core/agent/_types.py` (add `PriorTurn`)
- Modify: `src/cognic_agentos/core/agent/loop.py` (`ask` signature; message assembly at `loop.py:319-327`; `agent.run.started` payload)
- Test: `tests/unit/core/agent/test_loop_prior_context.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `PriorTurn`; `AgentAskResult.prompt_tokens` / `.completion_tokens`; `AgentLoop.ask(..., prior_context: tuple[PriorTurn, ...] = ())`.

**`core/agent/loop.py` is already ON the coverage gate.** It must still clear 95/90 after this change. It is also a `core/` stop-rule module.

**Two additive changes, both required (maintainer ruling 2):**

1. `prior_context` on `ask`, and two additive `agent.run.started` payload keys.
2. **Real token counts on `AgentAskResult`.** The loop already tracks `prompt_tokens_total` / `completion_tokens_total` locally (`loop.py:330-331`) but discards them. Surfacing them is what makes Task 6's `cumulative_token_budget` a real bound instead of a bound that never fires. This lands **here**, in Task 4, not later.

**Verify (ruling 3 says this will pass — check anyway, don't assume):** the two new `agent.run.started` payload keys are safe only if `AgentRunStarted` tolerates unknown keys.

```bash
grep -n "class AgentRunStarted" -A 12 src/cognic_agentos/protocol/ui_events.py
grep -n 'extra="forbid"' src/cognic_agentos/protocol/ui_events.py | head
```
Expected: `AgentRunStarted` projects `data={**snapshot.payload}` and sets no `extra="forbid"`. If that has changed since 2026-07-09, `protocol/ui_events.py` is an ADR-020 wire-protocol stop rule — **stop and escalate**, do not edit a frozen family.

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/core/agent/test_loop_prior_context.py
"""ADR-028 — the additive prior_context input to the M8 loop.

Pins the two properties BAR 1 and BAR 2 depend on:
  * prior turns precede the new question, after the system prompt
  * the default is empty, so every M8 call site is byte-behaviour unchanged
"""
import pytest

from cognic_agentos.core.agent._types import PriorTurn


def test_prior_turn_is_frozen_and_role_constrained() -> None:
    t = PriorTurn(role="user", content="hello")
    assert t.role == "user"
    with pytest.raises(Exception):
        t.content = "x"  # type: ignore[misc]


@pytest.mark.asyncio
async def test_prior_context_messages_sit_between_system_and_new_question(agent_loop_probe) -> None:
    """agent_loop_probe is the existing test double that captures the messages
    handed to the gateway (see tests/unit/core/agent/test_loop.py)."""
    loop, captured = agent_loop_probe
    await loop.ask(
        agent_id="analyst",
        question="and the second largest?",
        actor_tenant_id="t1",
        actor_subject="s1",
        prior_context=(
            PriorTurn(role="user", content="who is the largest depositor?"),
            PriorTurn(role="assistant", content="Acme Corp"),
        ),
    )
    roles = [m["role"] for m in captured.messages]
    assert roles == ["system", "user", "assistant", "user"]
    assert captured.messages[1]["content"] == "who is the largest depositor?"
    assert captured.messages[2]["content"] == "Acme Corp"
    assert captured.messages[3]["content"] == "and the second largest?"


@pytest.mark.asyncio
async def test_default_prior_context_is_empty_m8_shape_unchanged(agent_loop_probe) -> None:
    loop, captured = agent_loop_probe
    await loop.ask(
        agent_id="analyst", question="q", actor_tenant_id="t1", actor_subject="s1"
    )
    assert [m["role"] for m in captured.messages] == ["system", "user"]


@pytest.mark.asyncio
async def test_started_row_records_prior_context_count_and_digest(agent_loop_probe, chain_rows) -> None:
    loop, _ = agent_loop_probe
    await loop.ask(
        agent_id="analyst", question="q", actor_tenant_id="t1", actor_subject="s1",
        prior_context=(PriorTurn(role="user", content="earlier"),),
    )
    started = [r for r in await chain_rows() if r.decision_type == "agent.run.started"]
    assert started[0].payload["prior_context_turns"] == 1
    assert len(started[0].payload["prior_context_sha256"]) == 64
    assert "earlier" not in str(started[0].payload)   # digest-only doctrine
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/core/agent/test_loop_prior_context.py -v`
Expected: FAIL — `ImportError: cannot import name 'PriorTurn'`

- [ ] **Step 3: Add `PriorTurn` and the token fields to `core/agent/_types.py`**

Append after `GrantedCapabilities`:

```python
@dataclass(frozen=True, slots=True)
class PriorTurn:
    """One replayed conversation turn handed to :meth:`AgentLoop.ask` as prior
    context (ADR-028). The loop consumes this shape so ``core/agent`` never
    imports ``core/conversation`` -- the arrow runs conversation -> agent."""

    role: Literal["user", "assistant"]
    content: str
```

Extend `AgentAskResult` (`core/agent/_types.py:79`) with two fields. Give them
defaults so every existing construction site stays valid — the loop is the only
producer, and it will set them:

```python
    prompt_tokens: int = 0
    completion_tokens: int = 0
```

Add the matching test to `tests/unit/core/agent/test_loop_prior_context.py`:

```python
@pytest.mark.asyncio
async def test_ask_result_surfaces_real_token_counts(agent_loop_probe) -> None:
    """ADR-028: without these, conversation cumulative_token_budget is a bound
    that never fires."""
    loop, captured = agent_loop_probe
    captured.usage = {"prompt_tokens": 11, "completion_tokens": 7}
    result = await loop.ask(
        agent_id="analyst", question="q", actor_tenant_id="t1", actor_subject="s1"
    )
    assert result.prompt_tokens == 11
    assert result.completion_tokens == 7
```

- [ ] **Step 4: Extend `AgentLoop.ask`**

In `core/agent/loop.py`, add the keyword-only parameter (default `()` keeps every M8 call site unchanged):

```python
    async def ask(
        self,
        *,
        agent_id: str,
        question: str,
        actor_tenant_id: str,
        actor_subject: str,
        prior_context: tuple[PriorTurn, ...] = (),
    ) -> AgentAskResult:
```

Compute the digest before the `agent.run.started` append (digest-only doctrine — the plaintext never enters the payload):

```python
        prior_context_encoded = "\n".join(
            f"{t.role}:{t.content}" for t in prior_context
        ).encode("utf-8")
        prior_context_sha256 = hashlib.sha256(prior_context_encoded).hexdigest()
```

Add to the `agent.run.started` payload dict (at `loop.py:300-311`):

```python
                    "prior_context_turns": len(prior_context),
                    "prior_context_sha256": prior_context_sha256,
```

Replace the message assembly at `loop.py:319-327`:

```python
        # --- 3. The conversation + the advertised capability surface.
        #
        # ADR-028: replayed prior turns sit BETWEEN the system prompt and the
        # new question. They come only from the kernel conversation store --
        # the turn API accepts no client-supplied history (invariant I-1).
        messages: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": _build_system_prompt(
                    record=record, granted=granted, reader=self._skill_reader
                ),
            },
            *({"role": t.role, "content": t.content} for t in prior_context),
            {"role": "user", "content": question},
        ]
```

Finally, surface the token totals. There is exactly **one** `AgentAskResult(...)`
construction in the loop, at `loop.py:511`, inside `_finish` (`loop.py:457`).
`_finish` **already receives** `prompt_tokens_total` / `completion_tokens_total`
as parameters (they are passed at `loop.py:354`), so no plumbing is needed — only
two extra kwargs on the construction:

```python
        return AgentAskResult(
            ...,
            prompt_tokens=prompt_tokens_total,
            completion_tokens=completion_tokens_total,
        )
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
uv run pytest tests/unit/core/agent/test_loop_prior_context.py -v
uv run pytest tests/unit/core/agent -v          # every M8 loop test must still pass unchanged
```
Expected: new file PASS; the existing M8 suite PASS with zero modifications. **If any existing M8 test needed editing, the change was not additive — revert and rethink.**

- [ ] **Step 6: Confirm `loop.py` still clears the gate**

```bash
uv run pytest --cov=src/cognic_agentos --cov-branch --cov-report=json
uv run python tools/check_critical_coverage.py
```
Expected: `150/150 PASS` (count unchanged — no new promotion in this task).

- [ ] **Step 7: Full gate ladder + byte-identical guard**

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy src tests
git diff --stat main -- src/cognic_agentos/protocol/mcp_authz.py   # must print nothing
```

- [ ] **Step 8: HALT for maintainer review + commit token**

Tag `(CRITICAL CONTROLS)`. Report the `ui_events.py` watchpoint finding explicitly — whether `AgentRunStarted` tolerated the additive keys, or whether you escalated. On token:

```
feat(adr-028): additive prior_context on the governed agent loop (CRITICAL CONTROLS)
```

---

## Task 5: Bounded-replay context assembly

**Files:**
- Create: `src/cognic_agentos/core/conversation/_context.py`
- Test: `tests/unit/core/conversation/test_context.py`

**Interfaces:**
- Consumes: `TurnRecord` (Task 1), `PriorTurn` (Task 4).
- Produces: `assemble_prior_context(turns, *, replay_last_n, token_ceiling) -> tuple[PriorTurn, ...]`.

**Contract.** Input is the already-scoped output of `ConversationStore.load_replay_turns` (first turn + last N, ascending `seq`). The function converts each turn into a `user` message and an `assistant` message, drops **erased** turns (`user_message is None or answer is None`) entirely, and trims from the **oldest non-grounding** end while the estimated token count exceeds `token_ceiling`. The grounding turn (lowest `seq`) is never trimmed — it is the reason bounded replay includes it.

**Token estimation is an estimate, and says so.** `len(content) // 4` characters-per-token. It is a pre-filter only; the authoritative bound is the loop's own `token_budget` round-top check, which counts real usage from the gateway. Do not pretend otherwise in a docstring.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/core/conversation/test_context.py
"""Bounded-replay selection — the I-1 surface BAR 2 pins."""
import uuid
from datetime import UTC, datetime

from cognic_agentos.core.agent._types import PriorTurn
from cognic_agentos.core.conversation._context import assemble_prior_context
from cognic_agentos.core.conversation._types import TurnRecord


def _turn(seq: int, q: str = "q", a: str = "a") -> TurnRecord:
    return TurnRecord(
        turn_id=uuid.uuid4(), seq=seq, user_message=q, answer=a,
        agent_run_id=f"r{seq}", prompt_tokens=1, completion_tokens=1,
        created_at=datetime.now(UTC),
    )


def test_empty_history_yields_empty_context() -> None:
    assert assemble_prior_context([], replay_last_n=10, token_ceiling=1000) == ()


def test_each_turn_becomes_a_user_then_assistant_pair() -> None:
    out = assemble_prior_context([_turn(1, "who?", "Acme")], replay_last_n=10, token_ceiling=1000)
    assert out == (PriorTurn(role="user", content="who?"), PriorTurn(role="assistant", content="Acme"))


def test_erased_turns_are_dropped_entirely() -> None:
    erased = TurnRecord(
        turn_id=uuid.uuid4(), seq=2, user_message=None, answer=None,
        agent_run_id="r2", prompt_tokens=0, completion_tokens=0, created_at=datetime.now(UTC),
    )
    out = assemble_prior_context([_turn(1), erased, _turn(3)], replay_last_n=10, token_ceiling=1000)
    assert len(out) == 4          # two surviving turns x 2 messages
    assert all(m.content for m in out)


def test_ceiling_trims_oldest_non_grounding_turn_first() -> None:
    turns = [_turn(1, "GROUND" * 2, "g"), _turn(2, "X" * 400, "x"), _turn(3, "Y" * 40, "y")]
    out = assemble_prior_context(turns, replay_last_n=10, token_ceiling=40)
    contents = [m.content for m in out]
    assert "GROUND" in contents[0]              # grounding turn survives
    assert not any(c.startswith("XXXX") for c in contents)   # oldest non-grounding dropped
    assert any(c.startswith("YYYY") for c in contents)       # newest retained


def test_grounding_turn_never_trimmed_even_if_alone_over_ceiling() -> None:
    out = assemble_prior_context([_turn(1, "Z" * 4000, "z")], replay_last_n=10, token_ceiling=1)
    assert len(out) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/unit/core/conversation/test_context.py -v`
Expected: FAIL — `ModuleNotFoundError: ... _context`

- [ ] **Step 3: Write the implementation**

```python
# src/cognic_agentos/core/conversation/_context.py
"""ADR-028 -- bounded-replay context selection. Pure-functional, no I/O.

v1 ``context_strategy`` vocabulary has exactly one value: ``bounded_replay``
(spec section 5). Summarization is deferred to v1.1.

The input is ALWAYS the output of ConversationStore.load_replay_turns, which
is already tenant- and conversation-scoped. This module performs no isolation
of its own -- that boundary is upstream and on the coverage gate.
"""

from __future__ import annotations

from collections.abc import Sequence

from cognic_agentos.core.agent._types import PriorTurn
from cognic_agentos.core.conversation._types import TurnRecord

#: Characters per token. A coarse PRE-FILTER estimate, not an authoritative
#: count -- the loop's own token_budget round-top check counts real gateway
#: usage and is the binding bound.
_CHARS_PER_TOKEN = 4


def _estimate_tokens(text: str) -> int:
    return len(text) // _CHARS_PER_TOKEN


def assemble_prior_context(
    turns: Sequence[TurnRecord], *, replay_last_n: int, token_ceiling: int
) -> tuple[PriorTurn, ...]:
    """Select the replay window and flatten it to alternating user/assistant
    messages in ascending ``seq`` order.

    Erased turns (tombstoned plaintext) are dropped entirely -- replaying a
    tombstone would leak the fact of erasure into the model context and add
    nothing. Trimming removes the OLDEST NON-GROUNDING turn first; the
    grounding turn (lowest surviving ``seq``) is never trimmed, since carrying
    it is the entire point of bounded replay.
    """
    surviving = [
        t
        for t in sorted(turns, key=lambda t: t.seq)
        if t.user_message is not None and t.answer is not None
    ]
    if not surviving:
        return ()

    grounding, rest = surviving[0], surviving[1:]
    window = rest[-replay_last_n:] if replay_last_n > 0 else []

    def _cost(t: TurnRecord) -> int:
        return _estimate_tokens(t.user_message or "") + _estimate_tokens(t.answer or "")

    budget = token_ceiling - _cost(grounding)
    kept: list[TurnRecord] = []
    for turn in reversed(window):          # newest first; drop oldest on overflow
        cost = _cost(turn)
        if cost > budget:
            break
        budget -= cost
        kept.append(turn)
    kept.reverse()

    messages: list[PriorTurn] = []
    for turn in [grounding, *kept]:
        messages.append(PriorTurn(role="user", content=turn.user_message or ""))
        messages.append(PriorTurn(role="assistant", content=turn.answer or ""))
    return tuple(messages)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/core/conversation/test_context.py -v`
Expected: PASS — 5 passed

- [ ] **Step 5: Lint, type-check, byte-identical guard**

```bash
uv run pytest tests/unit/core/conversation -v
uv run ruff check . && uv run ruff format --check .
uv run mypy src tests
git diff --stat main -- src/cognic_agentos/protocol/mcp_authz.py   # must print nothing
```

- [ ] **Step 6: HALT for maintainer review + commit token**

Restate the **open gate-fit decision** from the top of this plan: this module ships off-gate. If the maintainer rules on-gate, add the entry and bump the count guard 150 → 151 in this same commit, with fresh coverage data. On token:

```
feat(adr-028): bounded-replay context assembly (pure-functional)
```

---

## Task 6: `ConversationTurnExecutor` — the turn loop

**Files:**
- Create: `src/cognic_agentos/core/conversation/turn.py`
- Test: `tests/unit/core/conversation/test_turn.py`
- Modify: `src/cognic_agentos/core/config.py` (4 Settings)
- Modify: `tools/check_critical_coverage.py` (add entry; count guard **150 → 151**)

**Interfaces:**
- Consumes: `ConversationStore` (Task 3), `assemble_prior_context` (Task 5), `AgentLoop.ask(..., prior_context=...)` (Task 4), `AgentAskResult`, `AgentRunTerminalState`, `AgentDispatchRefusalReason`.
- Produces: `TurnResult`, `ConversationTurnExecutor.post_turn(...)`.

**ON the critical-controls gate.** It owns the terminal-state refusal contract — *"the refusal fires at the lifecycle gate, before context assembly or any model/gateway activity"* — and the bounds enforcement. A bug here invokes an LLM on a closed conversation.

**Settings to add to `core/config.py`** (mirroring the `agent_*` block at `core/config.py:2099`):

```python
    conversation_max_turns: int = Field(
        default=20,
        gt=0,
        description="ADR-028 spec section 5. Max turns per conversation before "
        "conversation_max_turns_exceeded. Analytical conversations are short; "
        "low defaults are the point.",
    )
    conversation_replay_last_n: int = Field(
        default=10,
        ge=0,
        description="Bounded replay window: the grounding turn + the last N turns.",
    )
    conversation_replay_token_ceiling: int = Field(
        default=8_000,
        gt=0,
        description="Estimated-token pre-filter on the replayed window.",
    )
    conversation_claim_ttl_s: float = Field(
        default=300.0,
        gt=0,
        description="Stale single-writer claims older than this are reclaimable. "
        "MUST exceed agent_run_wall_clock_s or a slow turn can be double-run.",
    )
```

**`cumulative_token_budget`** is derived, not configured: `settings.agent_run_token_budget * settings.conversation_max_turns` (spec §5: "cumulative budget derived from the agent's per-turn budget × max_turns").

- [ ] **Step 1: Write the failing tests**

```python
# tests/unit/core/conversation/test_turn.py
"""ConversationTurnExecutor — REAL ConversationStore + REAL DecisionHistoryStore
(in-memory sqlite) + a STUB AgentLoop that records whether it was invoked."""
import uuid
from datetime import UTC, datetime

import pytest

from cognic_agentos.core.agent._types import AgentAskResult
from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationTurnRefused,
)
from cognic_agentos.core.conversation.turn import ConversationTurnExecutor, TurnResult


class _SpyLoop:
    def __init__(self, *, prompt_tokens: int = 3, completion_tokens: int = 2) -> None:
        self.calls: list[dict] = []
        self._pt = prompt_tokens
        self._ct = completion_tokens

    async def ask(self, **kw) -> AgentAskResult:
        self.calls.append(kw)
        return AgentAskResult(
            run_id="agent-run-1", terminal_state="completed",
            answer="Acme Corp", steps_used=1, refusal_reason=None,
            prompt_tokens=self._pt, completion_tokens=self._ct,
        )


@pytest.mark.asyncio
async def test_happy_path_persists_turn_and_returns_answer(executor_env) -> None:
    ex, store, loop, cid = executor_env
    result = await ex.post_turn(
        conversation_id=cid, tenant_id="t1", actor_subject="s1", user_message="who?"
    )
    assert isinstance(result, TurnResult)
    assert result.seq == 1 and result.answer == "Acme Corp" and result.agent_run_id == "agent-run-1"
    rec = await store.load(cid, tenant_id="t1", creator_subject="s1")
    assert rec is not None and rec.turn_count == 1


@pytest.mark.asyncio
async def test_returned_turn_id_names_a_real_row(executor_env) -> None:
    """The wire-returned turn_id must resolve in conversation_turns."""
    import sqlalchemy as sa

    from cognic_agentos.core.conversation.storage import _conversation_turns

    ex, store, _loop, cid = executor_env
    result = await ex.post_turn(
        conversation_id=cid, tenant_id="t1", actor_subject="s1", user_message="who?"
    )
    async with store._engine.connect() as conn:  # noqa: SLF001
        found = (
            await conn.execute(
                sa.select(_conversation_turns.c.turn_id).where(
                    _conversation_turns.c.turn_id == result.turn_id
                )
            )
        ).first()
    assert found is not None


@pytest.mark.asyncio
async def test_real_token_counts_accumulate_into_the_conversation(executor_env) -> None:
    """Ruling 2: the cumulative budget must be fed by real usage, not zeros."""
    ex, store, _loop, cid = executor_env
    await ex.post_turn(conversation_id=cid, tenant_id="t1", actor_subject="s1", user_message="q")
    rec = await store.load(cid, tenant_id="t1", creator_subject="s1")
    assert rec is not None and rec.cumulative_tokens == 5   # _SpyLoop: 3 + 2


@pytest.mark.asyncio
async def test_token_budget_exhaustion_refuses_without_invoking_the_loop(
    executor_env_tiny_budget,
) -> None:
    ex, _store, loop, cid = executor_env_tiny_budget   # cumulative_token_budget=4
    await ex.post_turn(conversation_id=cid, tenant_id="t1", actor_subject="s1", user_message="q1")
    loop.calls.clear()
    with pytest.raises(ConversationTurnRefused) as exc:
        await ex.post_turn(conversation_id=cid, tenant_id="t1", actor_subject="s1", user_message="q2")
    assert exc.value.reason == "conversation_token_budget_exceeded"
    assert loop.calls == []


@pytest.mark.asyncio
async def test_second_turn_replays_the_first(executor_env) -> None:
    ex, _store, loop, cid = executor_env
    await ex.post_turn(conversation_id=cid, tenant_id="t1", actor_subject="s1", user_message="who?")
    await ex.post_turn(
        conversation_id=cid, tenant_id="t1", actor_subject="s1", user_message="and second?"
    )
    prior = loop.calls[1]["prior_context"]
    assert [p.role for p in prior] == ["user", "assistant"]
    assert prior[0].content == "who?"
    assert prior[1].content == "Acme Corp"


@pytest.mark.asyncio
async def test_first_turn_has_empty_prior_context(executor_env) -> None:
    ex, _store, loop, cid = executor_env
    await ex.post_turn(conversation_id=cid, tenant_id="t1", actor_subject="s1", user_message="q")
    assert loop.calls[0]["prior_context"] == ()


@pytest.mark.asyncio
async def test_closed_conversation_refuses_WITHOUT_invoking_the_loop(executor_env) -> None:
    """The BAR-4 terminal-state pin, enforced here even though BAR 4 is proved later."""
    ex, store, loop, cid = executor_env
    await store.transition(
        conversation_id=cid, tenant_id="t1", to_state="closed",
        actor_id="s1", request_id="r",
    )
    with pytest.raises(ConversationTurnRefused) as exc:
        await ex.post_turn(conversation_id=cid, tenant_id="t1", actor_subject="s1", user_message="q")
    assert exc.value.reason == "conversation_not_active"
    assert exc.value.current_state == "closed"
    assert loop.calls == []          # <-- zero AgentLoop invocation


@pytest.mark.asyncio
async def test_cross_actor_post_is_not_found(executor_env) -> None:
    ex, _store, loop, cid = executor_env
    with pytest.raises(ConversationNotFound):
        await ex.post_turn(conversation_id=cid, tenant_id="t1", actor_subject="mallory", user_message="q")
    assert loop.calls == []


@pytest.mark.asyncio
async def test_max_turns_exceeded_refuses_without_invoking_the_loop(executor_env_max_turns_1) -> None:
    ex, _store, loop, cid = executor_env_max_turns_1
    await ex.post_turn(conversation_id=cid, tenant_id="t1", actor_subject="s1", user_message="q1")
    loop.calls.clear()
    with pytest.raises(ConversationTurnRefused) as exc:
        await ex.post_turn(conversation_id=cid, tenant_id="t1", actor_subject="s1", user_message="q2")
    assert exc.value.reason == "conversation_max_turns_exceeded"
    assert loop.calls == []


@pytest.mark.asyncio
async def test_claim_is_released_when_the_loop_raises(executor_env_raising_loop) -> None:
    """A crashed turn must not wedge the conversation."""
    ex, store, _loop, cid = executor_env_raising_loop
    with pytest.raises(RuntimeError):
        await ex.post_turn(conversation_id=cid, tenant_id="t1", actor_subject="s1", user_message="q")
    # the claim was released, so a fresh claim succeeds
    await store.claim_turn(
        cid, tenant_id="t1", creator_subject="s1", now=datetime.now(UTC), claim_ttl_s=300.0
    )


@pytest.mark.asyncio
async def test_claim_ttl_must_exceed_agent_wall_clock(conversation_store, spy_loop) -> None:
    with pytest.raises(ValueError, match="claim_ttl_s"):
        ConversationTurnExecutor(
            store=conversation_store, loop=spy_loop, max_turns=20,
            cumulative_token_budget=1000, replay_last_n=10, replay_token_ceiling=100,
            claim_ttl_s=1.0, agent_run_wall_clock_s=120.0,
        )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/core/conversation/test_turn.py -v`
Expected: FAIL — `ModuleNotFoundError: ... turn`

- [ ] **Step 3: Write the implementation**

```python
# src/cognic_agentos/core/conversation/turn.py
"""ADR-028 -- the governed conversation turn loop.

CRITICAL CONTROLS. Owns the terminal-state refusal contract: posting a turn to
a closed/expired/erased conversation refuses with ``conversation_not_active``
and NEVER invokes the AgentLoop. The refusal fires at the lifecycle gate,
before context assembly and before any model/gateway activity.

Flow (spec section 4):

    claim (atomic, single-writer)
      -> bounds (max_turns, cumulative budget)
      -> context assembly (bounded replay, kernel store ONLY -- invariant I-1)
      -> AgentLoop.ask(prior_context=...)   [dispatch chokepoint re-runs the
                                             CURRENT envelope -- invariant I-2]
      -> persist turn + digests, bump counters, append conversation.turn_completed
      -> release claim (finally-guarded)

The envelope is NEVER cached across turns. This module holds no entitlement
state at all: it hands the actor's identity to the loop, and the M8 dispatcher
re-resolves assignment -> entitlement -> policy on every dispatch of every
turn. That absence is the I-2 enforcement, and BAR 3 pins it.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

from cognic_agentos.core.agent._types import (
    AgentDispatchRefusalReason,
    AgentRunTerminalState,
)
from cognic_agentos.core.agent.loop import AgentLoop
from cognic_agentos.core.conversation._context import assemble_prior_context
from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationTurnRefused,
)
from cognic_agentos.core.conversation.storage import ConversationStore

_TURN_REQUEST_ID_PREFIX = "conv-turn-"


@dataclass(frozen=True, slots=True)
class TurnResult:
    turn_id: uuid.UUID
    seq: int
    answer: str
    agent_run_id: str
    terminal_state: AgentRunTerminalState
    refusal_reason: AgentDispatchRefusalReason | None


class ConversationTurnExecutor:
    def __init__(
        self,
        *,
        store: ConversationStore,
        loop: AgentLoop,
        max_turns: int,
        cumulative_token_budget: int,
        replay_last_n: int,
        replay_token_ceiling: int,
        claim_ttl_s: float,
        agent_run_wall_clock_s: float,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if claim_ttl_s <= agent_run_wall_clock_s:
            raise ValueError(
                "claim_ttl_s must exceed agent_run_wall_clock_s, else a slow turn "
                "has its claim stolen and can be double-run"
            )
        self._store = store
        self._loop = loop
        self._max_turns = max_turns
        self._cumulative_token_budget = cumulative_token_budget
        self._replay_last_n = replay_last_n
        self._replay_token_ceiling = replay_token_ceiling
        self._claim_ttl_s = claim_ttl_s
        self._clock = clock

    async def post_turn(
        self,
        *,
        conversation_id: uuid.UUID,
        tenant_id: str,
        actor_subject: str,
        user_message: str,
    ) -> TurnResult:
        """Raises ConversationNotFound (404 wire-collapse) or
        ConversationTurnRefused (409, closed-enum reason)."""
        now = self._clock()

        # 1. Atomic claim. Raises ConversationNotFound / ConversationTurnRefused
        #    ('conversation_not_active' | 'conversation_turn_in_progress') BEFORE
        #    any context assembly or gateway activity.
        record = await self._store.claim_turn(
            conversation_id,
            tenant_id=tenant_id,
            creator_subject=actor_subject,
            now=now,
            claim_ttl_s=self._claim_ttl_s,
        )
        try:
            # 2. Conversation-level bounds. Still no loop invocation.
            if record.turn_count >= self._max_turns:
                raise ConversationTurnRefused(
                    "conversation_max_turns_exceeded", current_state=record.state
                )
            if record.cumulative_tokens >= self._cumulative_token_budget:
                raise ConversationTurnRefused(
                    "conversation_token_budget_exceeded", current_state=record.state
                )

            # 3. Context assembly -- kernel store ONLY (invariant I-1).
            turns = await self._store.load_replay_turns(
                conversation_id, tenant_id=tenant_id, last_n=self._replay_last_n
            )
            prior_context = assemble_prior_context(
                turns,
                replay_last_n=self._replay_last_n,
                token_ceiling=self._replay_token_ceiling,
            )

            # 4. The M8 governed loop. Its dispatch chokepoint re-checks the
            #    CURRENT envelope on every dispatch (invariant I-2).
            result = await self._loop.ask(
                agent_id=record.agent_id,
                question=user_message,
                actor_tenant_id=tenant_id,
                actor_subject=actor_subject,
                prior_context=prior_context,
            )

            # 5. Persist + chain row (digest-only). append_turn returns the
            #    turn_id it actually inserted -- surface THAT, never a fresh uuid.
            seq = record.turn_count + 1
            request_id = f"{_TURN_REQUEST_ID_PREFIX}{uuid.uuid4().hex}"
            turn_id = await self._store.append_turn(
                conversation_id=conversation_id,
                tenant_id=tenant_id,
                seq=seq,
                user_message=user_message,
                answer=result.answer,
                agent_run_id=result.run_id,
                prompt_tokens=result.prompt_tokens,
                completion_tokens=result.completion_tokens,
                actor_id=actor_subject,
                request_id=request_id,
            )
            return TurnResult(
                turn_id=turn_id,
                seq=seq,
                answer=result.answer,
                agent_run_id=result.run_id,
                terminal_state=result.terminal_state,
                refusal_reason=result.refusal_reason,
            )
        finally:
            # 6. Always release. A crashed turn must never wedge the conversation.
            await self._store.release_claim(conversation_id, tenant_id=tenant_id)
```

**Depends on Task 4's token fields.** `result.prompt_tokens` / `result.completion_tokens` come from the `AgentAskResult` extension landed in Task 4 (maintainer ruling 2). If Task 4 is not complete, this task cannot start — a `cumulative_token_budget` fed by zeros is a bound that never fires, which reads as *enforced* in the evidence and is therefore worse than no bound at all.

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/unit/core/conversation/test_turn.py -v`
Expected: PASS — 10 passed

- [ ] **Step 5: Add negative-path coverage until `turn.py` clears 95/90**

```bash
uv run pytest tests/unit/core/conversation --cov=src/cognic_agentos/core/conversation/turn.py --cov-branch --cov-report=term-missing
```
Expected: ≥95% line, ≥90% branch. Uncovered branches will likely be the `cumulative_token_budget` refusal and the `ValueError` constructor guard — cover both.

- [ ] **Step 6: Promote onto the gate + run it against FRESH coverage**

Append to `_CRITICAL_FILES` and bump the count guard 150 → 151:

```python
    # ADR-028 vertical slice — the terminal-state refusal contract (no loop
    # invocation on a closed conversation) + conversation bounds. Gate 150 -> 151.
    ("src/cognic_agentos/core/conversation/turn.py", 95.0, 90.0),
```

```bash
uv run pytest --cov=src/cognic_agentos --cov-branch --cov-report=json
uv run python tools/check_critical_coverage.py
```
Expected: `151/151 PASS`.

- [ ] **Step 7: Full gate ladder + byte-identical guard**

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy src tests
git diff --stat main -- src/cognic_agentos/protocol/mcp_authz.py   # must print nothing
```

- [ ] **Step 8: HALT for maintainer review + commit token**

Tag `(CRITICAL CONTROLS)`. Report the fresh `151/151`, which token-budget option you took and why, and the caplog evidence that `test_closed_conversation_refuses_WITHOUT_invoking_the_loop` actually asserts zero loop calls. On token:

```
feat(adr-028): ConversationTurnExecutor — claim, bounds, bounded replay, governed turn (CRITICAL CONTROLS)
```

---

## Task 7: RBAC scopes, HTTP surface, and lifespan wiring

**Files:**
- Modify: `src/cognic_agentos/portal/rbac/scopes.py`, `actor.py`, `enforcement.py`
- Create: `src/cognic_agentos/portal/api/conversations/{__init__.py,dto.py,routes.py}`
- Modify: `src/cognic_agentos/portal/api/app.py`
- Test: `tests/unit/portal/rbac/test_conversation_scopes.py`, `tests/unit/portal/api/conversations/test_routes.py`

**Interfaces:**
- Consumes: `ConversationTurnExecutor`, `ConversationStore`, `TurnResult`, all `_types.py` exceptions.
- Produces: `ConversationRBACScope`, `CONVERSATION_SCOPES`, `build_conversation_routes(...)`.

**`from __future__ import annotations` is INTENTIONALLY OMITTED from `routes.py`.** PEP 563 string-deferred annotations break FastAPI's `inspect.signature()` / `typing.get_type_hints()` resolution of `Annotated[..., Depends(<closure-local>)]`, and the dependency instances here are closure-locals inside `build_conversation_routes`. Add an AST self-test pinning the omission, per the `portal/api/runs/` precedent.

**Scope set (4 values).** `conversation.export` / `conversation.redact` land with the erasure slice — the `RunRBACScope` 1→2 growth is the precedent for additive widening.

```python
ConversationRBACScope = Literal[
    "conversation.create", "conversation.read", "conversation.post_turn", "conversation.close"
]
CONVERSATION_SCOPES: frozenset[ConversationRBACScope] = frozenset(
    {"conversation.create", "conversation.read", "conversation.post_turn", "conversation.close"}
)
```

Widen the `Actor.scopes` union (`portal/rbac/actor.py:163`) and the `RequireScope` parameter union (`portal/rbac/enforcement.py:253`) with `| ConversationRBACScope`. Both are additive and `conversation.*`-namespace-disjoint.

**Status map (no 500 leaks):**

| Condition | Status | Body `reason` |
|---|---|---|
| `ConversationNotFound` | 404 | `conversation_not_found` |
| `ConversationTurnRefused` (any of the 4) | 409 | the closed-enum reason |
| `ConversationTransitionRefused` | 409 | `conversation_transition_invalid_state_pair` |
| body has an unknown field | 422 | Pydantic (`extra="forbid"`) |
| `LookupError` from the loop (unknown agent) | 404 | `agent_not_found` |
| `AgentAskResult.terminal_state == "failed"` | 502 | `agent_run_failed` |
| store absent from `app.state` (lifespan not run) | 503 | `conversation_store_unavailable` |
| executor absent from `app.state` (no agent loop) | 503 | `conversation_executor_unavailable` |

`terminal_state == "refused"` returns **200** — a governed refusal is a governed answer (the M8 `/ask` precedent).

- [ ] **Step 1: Write the failing tests — BAR 2's schema pin lives here**

```python
# tests/unit/portal/api/conversations/test_routes.py
import uuid

import pytest


def test_post_turn_rejects_a_client_supplied_history_field(client, conversation_id) -> None:
    """BAR 2 (record integrity): the API accepts NO client-supplied history."""
    r = client.post(
        f"/api/v1/conversations/{conversation_id}/turns",
        json={"user_message": "q", "messages": [{"role": "user", "content": "forged"}]},
    )
    assert r.status_code == 422


@pytest.mark.parametrize("field", ["history", "prior_context", "context", "transcript"])
def test_post_turn_rejects_every_history_shaped_field(client, conversation_id, field) -> None:
    r = client.post(
        f"/api/v1/conversations/{conversation_id}/turns",
        json={"user_message": "q", field: ["forged"]},
    )
    assert r.status_code == 422


def test_post_turn_happy_path_returns_200_with_answer(client, conversation_id) -> None:
    r = client.post(
        f"/api/v1/conversations/{conversation_id}/turns", json={"user_message": "who?"}
    )
    assert r.status_code == 200
    assert r.json()["answer"] == "Acme Corp"
    assert r.json()["seq"] == 1


def test_cross_tenant_conversation_is_404_byte_identical_to_unknown(client_tenant_b, conversation_id) -> None:
    """Cross-tenant invisibility: the probe cannot distinguish."""
    cross = client_tenant_b.get(f"/api/v1/conversations/{conversation_id}")
    unknown = client_tenant_b.get(f"/api/v1/conversations/{uuid.uuid4()}")
    assert cross.status_code == unknown.status_code == 404
    assert cross.json() == unknown.json()


def test_post_turn_to_closed_conversation_is_409_not_active(client, closed_conversation_id) -> None:
    r = client.post(
        f"/api/v1/conversations/{closed_conversation_id}/turns", json={"user_message": "q"}
    )
    assert r.status_code == 409
    assert r.json()["reason"] == "conversation_not_active"


def test_missing_scope_is_403(client_no_scopes, conversation_id) -> None:
    r = client_no_scopes.post(
        f"/api/v1/conversations/{conversation_id}/turns", json={"user_message": "q"}
    )
    assert r.status_code == 403


def test_executor_absent_is_503(client_no_executor, conversation_id) -> None:
    r = client_no_executor.post(
        f"/api/v1/conversations/{conversation_id}/turns", json={"user_message": "q"}
    )
    assert r.status_code == 503
    assert r.json()["reason"] == "conversation_executor_unavailable"
```

```python
# tests/unit/portal/rbac/test_conversation_scopes.py
import typing

from cognic_agentos.portal.rbac.scopes import CONVERSATION_SCOPES, ConversationRBACScope


def test_scope_literal_and_frozenset_agree() -> None:
    assert set(typing.get_args(ConversationRBACScope)) == CONVERSATION_SCOPES


def test_scope_namespace_is_disjoint_from_agent_scopes() -> None:
    from cognic_agentos.portal.rbac.scopes import AGENT_SCOPES
    assert CONVERSATION_SCOPES.isdisjoint(AGENT_SCOPES)
    assert all(s.startswith("conversation.") for s in CONVERSATION_SCOPES)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/unit/portal/api/conversations tests/unit/portal/rbac/test_conversation_scopes.py -v`
Expected: FAIL — `ImportError: cannot import name 'ConversationRBACScope'`

- [ ] **Step 3: Write the DTOs**

```python
# src/cognic_agentos/portal/api/conversations/dto.py
"""ADR-028 wire DTOs. extra='forbid' on every request model is invariant I-1:
the turn API has NO history-accepting field, and a crafted payload attempting
one fails closed-enum validation with a 422."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field


class CreateConversationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    agent_id: str = Field(min_length=1, max_length=255)


class PostTurnRequest(BaseModel):
    """The ONLY field is the new message. Tenant + subject come from the bound
    Actor. There is deliberately no `messages` / `history` / `context` field --
    prior turns come exclusively from the kernel store."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    user_message: str = Field(min_length=1, max_length=32_000)


class ConversationResponse(BaseModel):
    model_config = ConfigDict(frozen=True)
    conversation_id: uuid.UUID
    agent_id: str
    state: str
    turn_count: int


class TurnResponse(BaseModel):
    model_config = ConfigDict(frozen=True)
    turn_id: uuid.UUID
    seq: int
    answer: str
    agent_run_id: str
    terminal_state: str
    refusal_reason: str | None
```

- [ ] **Step 4: Write the routes**

```python
# src/cognic_agentos/portal/api/conversations/routes.py
"""ADR-028 conversation surface.

Routes are mounted at APP-CONSTRUCTION time, before the lifespan has built an
engine. Both the ConversationStore and the ConversationTurnExecutor are read
from app.state by request-time dependencies that fail closed with 503 until the
lifespan populates them. This mirrors portal/api/runs/routes.py exactly --
app.include_router() is NEVER called from inside the lifespan (verified: zero
include_router calls appear inside portal/api/app.py's lifespan, lines 486-1133).

`from __future__ import annotations` is INTENTIONALLY OMITTED: PEP 563
string-deferred annotations break FastAPI's inspect.signature() /
typing.get_type_hints() resolution of Annotated[..., Depends(<closure-local>)],
and the dependency instances below are closure-locals. Pinned by an AST
self-test. See portal/api/runs/routes.py for the precedent.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from cognic_agentos.core.conversation._types import (
    ConversationNotFound,
    ConversationTransitionRefused,
    ConversationTurnRefused,
)
from cognic_agentos.core.conversation.storage import ConversationStore
from cognic_agentos.core.conversation.turn import ConversationTurnExecutor
from cognic_agentos.portal.api.conversations.dto import (
    ConversationResponse,
    CreateConversationRequest,
    PostTurnRequest,
    TurnResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope

_NOT_FOUND = {"reason": "conversation_not_found"}

# NOTE: RequireScope(scope) returns Callable[..., Awaitable[Actor]]
# (enforcement.py:270). The scope dependency IS the actor binder -- there is no
# separate _bind_actor dependency at the route layer. Verified against the live
# pattern at portal/api/agents/routes.py:56,63.


def _require_store(request: Request) -> ConversationStore:
    store: ConversationStore | None = getattr(request.app.state, "conversation_store", None)
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason": "conversation_store_unavailable"},
        )
    return store


def _require_executor(request: Request) -> ConversationTurnExecutor:
    executor: ConversationTurnExecutor | None = getattr(
        request.app.state, "conversation_executor", None
    )
    if executor is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason": "conversation_executor_unavailable"},
        )
    return executor


def build_conversation_routes() -> APIRouter:
    """No constructor args: the store does not exist at construction time."""
    router = APIRouter()
    _require_create = RequireScope("conversation.create")
    _require_read = RequireScope("conversation.read")
    _require_post_turn = RequireScope("conversation.post_turn")
    _require_close = RequireScope("conversation.close")

    @router.post("", response_model=ConversationResponse, status_code=201)
    async def create_conversation(
        body: CreateConversationRequest,
        actor: Annotated[Actor, Depends(_require_create)],
        store: Annotated[ConversationStore, Depends(_require_store)],
    ) -> ConversationResponse:
        conversation_id = uuid.uuid4()
        await store.create_conversation(
            conversation_id=conversation_id,
            tenant_id=actor.tenant_id,
            agent_id=body.agent_id,
            creator_subject=actor.subject,
            request_id=f"conv-create-{uuid.uuid4().hex}",
        )
        return ConversationResponse(
            conversation_id=conversation_id, agent_id=body.agent_id, state="active", turn_count=0
        )

    @router.get("/{conversation_id}", response_model=ConversationResponse)
    async def read_conversation(
        conversation_id: uuid.UUID,
        actor: Annotated[Actor, Depends(_require_read)],
        store: Annotated[ConversationStore, Depends(_require_store)],
    ) -> ConversationResponse:
        record = await store.load(
            conversation_id, tenant_id=actor.tenant_id, creator_subject=actor.subject
        )
        if record is None:
            raise HTTPException(status_code=404, detail=_NOT_FOUND)
        return ConversationResponse(
            conversation_id=record.conversation_id, agent_id=record.agent_id,
            state=record.state, turn_count=record.turn_count,
        )

    @router.post("/{conversation_id}/turns", response_model=TurnResponse)
    async def post_turn(
        conversation_id: uuid.UUID,
        body: PostTurnRequest,
        actor: Annotated[Actor, Depends(_require_post_turn)],
        executor: Annotated[ConversationTurnExecutor, Depends(_require_executor)],
    ) -> TurnResponse:
        try:
            result = await executor.post_turn(
                conversation_id=conversation_id,
                tenant_id=actor.tenant_id,
                actor_subject=actor.subject,
                user_message=body.user_message,
            )
        except ConversationNotFound:
            raise HTTPException(status_code=404, detail=_NOT_FOUND) from None
        except ConversationTurnRefused as exc:
            raise HTTPException(
                status_code=409,
                detail={"reason": exc.reason, "current_state": exc.current_state},
            ) from None
        except LookupError:
            raise HTTPException(status_code=404, detail={"reason": "agent_not_found"}) from None

        if result.terminal_state == "failed":
            raise HTTPException(status_code=502, detail={"reason": "agent_run_failed"})
        return TurnResponse(
            turn_id=result.turn_id, seq=result.seq, answer=result.answer,
            agent_run_id=result.agent_run_id, terminal_state=result.terminal_state,
            refusal_reason=result.refusal_reason,
        )

    @router.post("/{conversation_id}/close", response_model=ConversationResponse)
    async def close_conversation(
        conversation_id: uuid.UUID,
        actor: Annotated[Actor, Depends(_require_close)],
        store: Annotated[ConversationStore, Depends(_require_store)],
    ) -> ConversationResponse:
        record = await store.load(
            conversation_id, tenant_id=actor.tenant_id, creator_subject=actor.subject
        )
        if record is None:
            raise HTTPException(status_code=404, detail=_NOT_FOUND)
        try:
            # No from_state kwarg: the store reads it under the row lock, so a
            # concurrent close cannot race a stale value into the chain row.
            await store.transition(
                conversation_id=conversation_id, tenant_id=actor.tenant_id,
                to_state="closed",
                actor_id=actor.subject, request_id=f"conv-close-{uuid.uuid4().hex}",
            )
        except ConversationTransitionRefused as exc:
            raise HTTPException(status_code=409, detail={"reason": exc.reason}) from None
        return ConversationResponse(
            conversation_id=conversation_id, agent_id=record.agent_id,
            state="closed", turn_count=record.turn_count,
        )

    return router
```

- [ ] **Step 5: Mount at construction; populate state in the lifespan**

Two separate edits to `portal/api/app.py`. **`app.include_router` is never called from inside the lifespan** — verified by AST walk: `portal/api/app.py`'s lifespan spans lines 486–1133 and contains **zero** `include_router` calls. Every mount happens during construction.

**(a) Construction — mount unconditionally** (the eval-router pattern at `app.py:1713-1720`), so the request-time deps can return 503 until state is populated:

```python
    # ADR-028 conversation surface. Unconditional mount: the store + executor
    # are lifespan-built, and the route's DI fails closed 503 until
    # app.state.conversation_store / .conversation_executor are populated.
    from cognic_agentos.portal.api.conversations.routes import build_conversation_routes

    app.include_router(
        build_conversation_routes(),
        prefix="/api/v1/conversations",
        tags=["conversations"],
    )
```

Pre-seed both slots to `None` at module scope, mirroring `app.state.agent_loop`:

```python
    app.state.conversation_store = None
    app.state.conversation_executor = None
```

**(b) Lifespan — populate state only**, beside the M8 `build_agent_loop` block (`app.py:1017-1024`). The executor is gated on `agent_loop` being non-None; the store is not, because reads and closes work without a loop:

```python
                from cognic_agentos.core.conversation.storage import ConversationStore
                from cognic_agentos.core.conversation.turn import ConversationTurnExecutor

                app.state.conversation_store = ConversationStore(engine)
                if agent_loop is not None:
                    app.state.conversation_executor = ConversationTurnExecutor(
                        store=app.state.conversation_store,
                        loop=agent_loop,
                        max_turns=settings.conversation_max_turns,
                        cumulative_token_budget=settings.agent_run_token_budget
                        * settings.conversation_max_turns,
                        replay_last_n=settings.conversation_replay_last_n,
                        replay_token_ceiling=settings.conversation_replay_token_ceiling,
                        claim_ttl_s=settings.conversation_claim_ttl_s,
                        agent_run_wall_clock_s=settings.agent_run_wall_clock_s,
                    )
```

Add a regression pinning the boundary — this is the defect class the maintainer caught:

```python
# tests/unit/portal/api/conversations/test_routes.py
def test_conversation_router_is_mounted_at_construction_not_in_lifespan() -> None:
    """include_router inside a lifespan re-mounts on every startup and is
    invisible to a constructed-but-never-started app."""
    import ast
    import pathlib

    src = pathlib.Path("src/cognic_agentos/portal/api/app.py").read_text()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and "lifespan" in node.name:
            calls = [
                n for n in ast.walk(node)
                if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "include_router"
            ]
            assert calls == [], f"include_router inside lifespan at lines {[c.lineno for c in calls]}"


def test_conversation_routes_are_reachable_before_lifespan_populates_state(unstarted_client) -> None:
    """503, not 404 -- the route exists even with no store/executor."""
    r = unstarted_client.get(f"/api/v1/conversations/{uuid.uuid4()}")
    assert r.status_code == 503
    assert r.json()["reason"] == "conversation_store_unavailable"
```

- [ ] **Step 6: Run tests to verify they pass**

```bash
uv run pytest tests/unit/portal/api/conversations tests/unit/portal/rbac/test_conversation_scopes.py -v
uv run pytest tests/unit/portal -v      # no existing RBAC test may break
```
Expected: PASS.

- [ ] **Step 7: Full gate ladder**

`portal/rbac/{scopes,actor,enforcement}.py` are already on the gate — the union widenings are additive but the gate must still pass.

```bash
uv run pytest --cov=src/cognic_agentos --cov-branch --cov-report=json
uv run python tools/check_critical_coverage.py         # expect 151/151 PASS (no new promotion)
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy src tests
git diff --stat main -- src/cognic_agentos/protocol/mcp_authz.py   # must print nothing
```

- [ ] **Step 8: HALT for maintainer review + commit token**

Tag `(CRITICAL CONTROLS)` — `portal/rbac/` is a stop rule. On token:

```
feat(adr-028): conversation RBAC scopes + HTTP surface + lifespan wiring (CRITICAL CONTROLS)
```

---

## Task 8: Proof BARs 1–3 on `kind`

**Files:**
- Create: `infra/proof-m85/README.md`, `infra/proof-m85/run-proof-m85.sh`, `infra/proof-m85/kind-config.yaml`, `infra/proof-m85/seed-db.sh`, `infra/proof-m85/proof-m85-values.yaml`
- Test: `tests/integration/conversation/test_conversation_e2e.py` (env-gated on `COGNIC_RUN_CONVERSATION_E2E=1`)

**Interfaces:**
- Consumes: the full HTTP surface from Task 7.
- Produces: the vertical-slice gate verdict.

**Mirror `infra/proof-m8/` exactly** — same `kind-config.yaml`, `seed-db.sh`, `stage-packs.sh` shape, same numbered-BAR structure in `run-proof-m85.sh` (see `infra/proof-m8/run-proof-m8.sh:46-74`). Reuse the M8 agent pack, oracle pack, and LiteLLM/Azure-OpenAI wiring unchanged. The only new surface under test is `/api/v1/conversations`.

**The three bars, stated so they cannot be redefined downward:**

- [ ] **BAR 1 — governed multi-turn e2e.** Create a conversation. Turn 1: *"Who is our largest depositor?"* → answer names an entity. Turn 2: *"And what is their total balance?"* — **containing no entity name**, so a correct answer is only possible if turn 1's answer was replayed. Then assert the three-hop chain join:

```bash
# hop 1: conversation.turn_completed -> agent_run_id
AGENT_RUN_ID=$(psql -tAc "SELECT payload->>'agent_run_id' FROM decision_history
  WHERE decision_type='conversation.turn_completed'
    AND payload->>'conversation_id'='$CONV_ID' AND payload->>'seq'='2'")
# hop 2: agent_run_id -> the run's own evidence
psql -tAc "SELECT 1 FROM decision_history
  WHERE decision_type='agent.run.completed' AND payload->>'run_id'='$AGENT_RUN_ID'" | grep -q 1
# hop 3: agent_run_id -> its dispatch rows
test "$(psql -tAc "SELECT count(*) FROM decision_history
  WHERE decision_type='agent.run.dispatch' AND payload->>'run_id'='$AGENT_RUN_ID'")" -ge 1
```
Also assert **dual identity** on every turn row: `actor_id` is the originator subject and `payload->>'agent_id'` is the agent.

**Honesty boundary to state in the README:** turn 2's context dependence is *model-driven*. Assert the mechanical facts (`prior_context_turns == 2` on the `agent.run.started` row for turn 2; the chain join resolves) as the load-bearing pins, and treat the natural-language answer as corroborating, not as the proof. The M8 proof learned this the hard way — model-driven escape probes were flaky and BAR 4 had to be made deterministic.

- [ ] **BAR 2 — record integrity (deterministic).** No model call. Four probes, each must return **422**:

```bash
for FIELD in messages history prior_context transcript; do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    "$AS/api/v1/conversations/$CONV_ID/turns" -H "$AUTH" \
    -d "{\"user_message\":\"q\",\"$FIELD\":[{\"role\":\"user\",\"content\":\"forged\"}]}")
  test "$CODE" = "422" || { echo "BAR2 FAIL: $FIELD accepted ($CODE)"; exit 1; }
done
```
Then prove the positive half — the assembled context came from the store — by asserting the turn-2 `agent.run.started` row carries `prior_context_sha256` equal to the SHA-256 of the kernel-store-derived string, recomputed independently by the proof script from `conversation_turns`.

- [ ] **BAR 3 — mid-conversation revocation (the I-2 pin).** Turn 1 succeeds using an entitled data scope. Between turns, `DELETE FROM entitlements WHERE subject=... AND scope_id=...`. Turn 2 asks the same question. Assert:

```bash
psql -tAc "SELECT payload->>'refusal_reason' FROM decision_history
  WHERE decision_type='agent.run.dispatch' AND payload->>'run_id'='$RUN_2'" \
  | grep -q agent_scope_not_entitled
```
The HTTP response is **200** — a dispatch refusal feeds back to the model as a tool message and does not terminate the run (`core/agent/_types.py:41`). BAR 3 asserts the **chain row**, never the status code. Also assert no `conversation.turn_completed` row for turn 2 carries any content from the now-unentitled scope.

- [ ] **Step 1: Write the env-gated e2e first, run it red**

```bash
uv run pytest tests/integration/conversation/test_conversation_e2e.py -v
```
Expected: SKIP (no `COGNIC_RUN_CONVERSATION_E2E=1`). Then with the env var and a running stack: FAIL until the stack is seeded.

- [ ] **Step 2: Stand up `kind` and run the proof**

```bash
kind create cluster --config infra/proof-m85/kind-config.yaml
bash infra/proof-m85/run-proof-m85.sh 2>&1 | tee /tmp/proof-m85.log
```
Expected final line: `PROOF M8.5 SLICE (BARS 1-3) PASS`

- [ ] **Step 3: Record the honest posture in `infra/proof-m85/README.md`**

State plainly: which bars are model-driven vs deterministic; that BARs 4–7 are **not** run here; that this is the vertical-slice gate, not the M8.5 production proof. Do not write "conversational agent production-proven."

- [ ] **Step 4: Full gate ladder + byte-identical guard**

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy src tests
git diff --stat main -- src/cognic_agentos/protocol/mcp_authz.py   # must print nothing
```

- [ ] **Step 5: HALT for maintainer review + commit token**

Report the tee'd proof log with the BAR verdicts. On token:

```
proof(adr-028): vertical-slice BARs 1-3 green on kind — governed multi-turn, record integrity, mid-conversation revocation
```

---

## Self-Review

**1. Spec coverage.**

| Spec section | Covered by |
|---|---|
| §3 data model, erasure shape, terminal-state refusal, decision types | T1, T2, T3, T6 |
| §4 turn flow (claim → bounds → assembly → loop → persist → chain → release) | T6 |
| §4 loop extension is additive | T4 |
| §5 bounded replay only, Settings defaults | T5, T6 |
| §6 I-1 (`extra="forbid"`, no history field) | T7 DTOs, BAR 2 |
| §6 I-2 (per-turn envelope, never cached) | T6 (holds no entitlement state), BAR 3 |
| §6 I-3 (v1 envelope form) | inherited unchanged from M8 dispatch |
| §6 RBAC `conversation.*` disjoint namespace | T7 |
| §3/§7 digest-only chain payloads | T3 |
| §10 BARs 1–3 | T8 |
| §2 `[conversation]` manifest block | **NOT covered — explicitly deferred** (Scope table) |
| §7 retention/DLP/export/erasure; §8 escalation + safety hooks; §9 SSE | **NOT covered — explicitly deferred** (Scope table) |

No unintended gaps: every uncovered spec section appears in the Scope table with an owner.

**2. Placeholder scan.** No "TBD"/"TODO"/"handle edge cases". Two items are *deliberately* flagged as decisions rather than placeholders, because guessing them would be worse than surfacing them: the `_context.py` gate-fit ruling (top of plan) and the token-budget option in Task 6. Both name the choices, the trade-off, and a recommendation. Task 4 carries a hard **stop-and-escalate** if `AgentRunStarted` forbids extra payload keys.

**3. Type consistency.** `PriorTurn` is defined in T4 and consumed by T5/T6 with identical field names. `TurnRecord` / `ConversationRecord` are defined in T1 and consumed unchanged by T3/T5/T6. `ConversationStore`'s eight method signatures in the File Structure block match every call site in T6 and T7. `ConversationTurnRefused` carries `.reason` + `.current_state` at every raise and catch site. `assemble_prior_context(turns, *, replay_last_n, token_ceiling)` is called with exactly those keywords in T6.

**Five real defects found and fixed before this plan was committed.** Two by the author's own citation-verification pass, three by maintainer review — a useful ratio to remember.

1. **Dead token budget (author).** T6's `append_turn` passed `prompt_tokens=0, completion_tokens=0`, because `AgentAskResult` carries `steps_used` but no token usage (`core/agent/_types.py:79`). `cumulative_token_budget` would have been a bound that never fires — which reads as *enforced* in the evidence and is therefore worse than no bound. **Resolved by ruling 2:** Task 4 adds real `prompt_tokens` / `completion_tokens`, sourced from the loop's existing `prompt_tokens_total` / `completion_tokens_total` (`loop.py:330-331`), surfaced at the single `AgentAskResult(...)` construction (`loop.py:511`).

2. **Wrong actor-binding idiom (author).** T7's `routes.py` imported the private `_bind_actor` and used a separate `_: Annotated[None, Depends(require_*)]`. `RequireScope(scope)` returns `Callable[..., Awaitable[Actor]]` (`portal/rbac/enforcement.py:270`) — the scope dependency **is** the actor binder (`portal/api/agents/routes.py:56,63`). Corrected in all four handlers.

3. **Wrong `append_with_precondition` shape (maintainer).** The plan used the positional `append_with_precondition(record, precondition)`. The live API is keyword-only with a *record builder*: `append_with_precondition(*, record_builder: Callable[[T], DecisionRecord], precondition: Callable[[AsyncConnection, int, bytes], Awaitable[T]])` (`core/decision_history.py:409`). The precondition **projects** a captured value into the builder. As written, Task 3 would not have compiled. All three call sites rewritten against the `core/run/storage.py:196-243` idiom — and `transition` now exploits the projection properly: it drops the `from_state` parameter and reads it under the row lock, so a caller's stale read can never enter a chain row.

4. **Fabricated `turn_id` (maintainer).** `append_turn` minted a `turn_id` inside its INSERT and discarded it; `TurnResult` then returned a *different* `uuid.uuid4()`. The API would have handed clients an id naming no row. `append_turn` now mints before insert, puts it in the chain payload, and returns it; `TurnResult` surfaces that exact id. Pinned by three tests (store-level row existence, chain-payload equality, executor-level round-trip).

5. **`include_router` inside the lifespan (maintainer).** Task 7 mounted the router during startup. Verified by AST walk that `portal/api/app.py`'s lifespan (lines 486–1133) contains **zero** `include_router` calls — every mount is at construction. Rewritten: `build_conversation_routes()` takes no args, mounts unconditionally at construction, and both the store and executor arrive via request-time `app.state` dependencies that fail closed with 503 (`portal/api/runs/routes.py` states this pattern verbatim in its own module docstring). Pinned by an AST regression that fails if anyone re-introduces a lifespan mount.

**Every `file:line` citation was verified against source at authoring time** (`packs/lifecycle.py:111`, `cli/validators/skills.py:135`, `core/agent/_types.py:41,79`, `core/agent/loop.py:319-327,330-331,354,457,511`, `core/decision_history.py:409`, `core/run/storage.py:196-243`, `core/config.py:2099`, `portal/rbac/actor.py:163`, `portal/rbac/enforcement.py:253,270`, `portal/api/agents/routes.py:56,63`, `portal/api/app.py:486-1133,1017-1024,1713-1720`, `infra/proof-m8/run-proof-m8.sh:46-74`). An implementer should still re-verify before relying on any of them — see the open `AGENTS.md` citation-drift follow-up.

---

## Execution Handoff

Plan complete. Two execution options:

**1. Subagent-Driven (recommended)** — a fresh subagent per task, two-stage review between tasks, fast iteration. Given the CC-gate density here (three stop-rule modules, two coverage promotions), every task still returns to the controller for the full gate ladder + maintainer commit token; subagents never commit.

**2. Inline Execution** — execute tasks in this session with checkpoints.

Either way: **no auto-commit**, and `core/` tasks (1, 3, 4, 5, 6) plus `portal/rbac/` (7) carry halt-before-commit scrutiny.
