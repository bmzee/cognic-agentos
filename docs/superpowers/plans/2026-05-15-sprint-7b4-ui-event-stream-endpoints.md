# Sprint 7B.4 — UI Event-Stream Endpoints + RBAC Denial Chain Events Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the UI event-stream contract (3 SSE GET endpoints + POST /actions + portable JSON schema + connection caps + submit_elicitation MCP-rules gate) per ADR-020, plus promote the 4 portal RBAC denial structured-log sites to dual-surface emission (log + `policy.rbac_denied` chain row reaching SSE subscribers).

**Architecture:** New `portal/api/ui/` package houses the FastAPI route adapters; extended `protocol/ui_events.py` houses the FastAPI-free `UIEventBroker` primitive + cursor encoder + typed projector table; new `protocol/elicitation_adapter.py` houses the Protocol + fail-loud kernel scaffold; new `policies/_default/elicitation.rego` is the policy-of-record stop-rule. Architectural arrow `portal/api/ui/* → protocol/ui_events.py → core/decision_history` pinned by AST-walk regressions. The broker centralizes all chain-row emits (RBAC denials + frontend_action.*) so route modules never import `DecisionHistoryStore`.

**Tech Stack:** FastAPI + Pydantic v2 (existing) · sse-starlette 2.1.0 (transitive, made explicit in T3) · existing `OPAEngine` (Sprint 4) for the elicitation Rego gate · existing `DecisionHistoryStore.append` (unchanged; consumed via new broker methods).

**Source spec:** `docs/superpowers/specs/2026-05-15-sprint-7b4-ui-event-stream-design.md` (788 lines, committed at `6762cbc`, approved across 3 review rounds).

**Ladder shape:** T1 = spec commit (DONE at `6762cbc`); T2 = plan-of-record commit (this file); T3-T12 = substantive; T13 = AGENTS.md + coverage gate + AST regressions; T14 = closeout. 14 tasks total.

**Branch base:** `c53de7a` on `main` (Sprint 7B.3 merge / PR #24). `feat/sprint-7b4-ui-event-stream-endpoints` branches directly off merged main (NOT a stacked branch).

**Critical-controls floor projected:** 60 → **63** Python CC modules at sprint close (+3: `portal/api/ui/action_routes.py`, `portal/api/ui/stream_routes.py`, `portal/api/ui/elicitation_gate.py`) **+ 1 new stop-rule policy bundle** (`policies/_default/elicitation.rego`). Final inventory: 63 Python CC + 3 explicit stop-rule policy bundles (sampling + supply_chain + elicitation).

---

## File Structure

### New files

| Path | Role | CC | Owning task |
|---|---|---|---|
| `src/cognic_agentos/protocol/elicitation_adapter.py` | ElicitationAdapter Protocol + ElicitationContext + KernelDefault | NOT-CC | T7 |
| `src/cognic_agentos/portal/api/ui/__init__.py` | Package marker | NOT-CC | T9 |
| `src/cognic_agentos/portal/api/ui/dto.py` | Action DTOs + Literals + UIActionContext (P1 #2: NO RequireUIAction here — that lives in action_routes.py) | NOT-CC | T9 |
| `src/cognic_agentos/portal/api/ui/elicitation_gate.py` | Pure-async 5-step gate | **CC** | T8 |
| `src/cognic_agentos/portal/api/ui/stream_routes.py` | 3 SSE GET endpoints | **CC** | T10 |
| `src/cognic_agentos/portal/api/ui/action_routes.py` | POST `/actions` + **`RequireUIAction` dep factory (P1 #2 — lives here)** + 6-class dispatch + submit_elicitation gate routing | **CC** | T11 |
| `src/cognic_agentos/portal/api/ui/well_known_routes.py` | JSON schema publication | NOT-CC | T12 |
| `src/cognic_agentos/portal/api/ui/router.py` | build_ui_routes composition | NOT-CC | T12 |
| `policies/_default/elicitation.rego` | Default-deny Rego bundle (Rego v1) | **Stop-rule** | T8 |
| `tests/architecture/test_ui_architectural_arrow.py` | 6 AST-walk arrow regressions | (test) | T13 |
| `tests/unit/protocol/test_ui_events_broker.py` | Broker primitive tests | (test) | T4 |
| `tests/unit/protocol/test_ui_events_chain_cursor.py` | Cursor encoder + decoder | (test) | T3 |
| `tests/unit/protocol/test_ui_events_typed_projectors.py` | 5-entry typed-projector table | (test) | T4 |
| `tests/unit/protocol/test_ui_events_rbac_denial_type.py` | RBACDenialType union + disjointness | (test) | T3 |
| `tests/unit/protocol/test_elicitation_adapter.py` | Protocol + KernelDefault scaffold | (test) | T7 |
| `tests/unit/portal/rbac/test_rbac_denial_chain_emission.py` | Async dep + denial emit + fail-closed | (test) | T6 |
| `tests/unit/portal/rbac/test_actor_scope_widening.py` | Actor.scopes union type | (test) | T5 |
| `tests/unit/portal/api/ui/__init__.py` | Package marker | (test) | T9 |
| `tests/unit/portal/api/ui/test_dto_action.py` | DTOs + Literals + UIActionContext + model_validator parity + AST no-runtime-imports | (test) | T9 |
| `tests/unit/portal/api/ui/test_elicitation_gate.py` | Gate matrix + fail-closed paths | (test) | T8 |
| `tests/unit/portal/api/ui/test_stream_routes.py` | 3 SSE GETs | (test) | T10 |
| `tests/unit/portal/api/ui/test_stream_routes_last_event_id.py` | Last-Event-ID precedence | (test) | T10 |
| `tests/unit/portal/api/ui/test_stream_routes_reconnect.py` | Replay-then-live boundary | (test) | T10 |
| `tests/unit/portal/api/ui/test_stream_headers_and_timeout.py` | SSE headers + send_timeout | (test) | T10 |
| `tests/unit/portal/api/ui/test_heartbeat.py` | Broker/generator-owned heartbeat | (test) | T10 |
| `tests/unit/portal/api/ui/test_action_routes.py` | POST /actions + RequireUIAction | (test) | T11 |
| `tests/unit/portal/api/ui/test_action_routes_correlation_latency.py` | Deterministic wait_for(0.2s) | (test) | T11 |
| `tests/unit/portal/api/ui/test_well_known_routes.py` | Schema publication + snapshot drift | (test) | T12 |
| `tests/unit/policies/__init__.py` | Package marker | (test) | T8 |
| `tests/unit/policies/test_elicitation_rego.py` | Direct OPA test (`@pytest.mark.opa_required`) | (test) | T8 |
| `docs/closeouts/2026-MM-DD-sprint-7b4-ui-event-stream-endpoints.md` | Closeout (date set at T14) | (doc) | T14 |

### Modified files

| Path | Change | CC | Owning task |
|---|---|---|---|
| `pyproject.toml` | Explicit `sse-starlette>=2.1.0` runtime dep | (build) | T3 |
| `uv.lock` | Lockfile churn from T3 | (build) | T3 |
| `src/cognic_agentos/core/config.py` | NEW 5 UI-stream Settings fields (P1 #6 ownership) | NOT-CC (not on durable gate) | T4 |
| (test) `tests/unit/core/test_config_ui_event_stream_fields.py` | Settings field count + default-value drift | (test) | T4 |
| (test) `tests/unit/portal/api/ui/sse_test_helpers.py` | NEW shared plain-callables helper module (R5 #1; created at T6 per R6 #1 so T6's RBAC conftest can import it; reused by T10/T11/T12) | (test) | T6 |
| (test) `tests/unit/portal/rbac/conftest.py` | NEW RBAC test fixtures (R5 #2) | (test) | T6 |
| (test) `tests/unit/portal/api/ui/conftest.py` | NEW UI test fixtures (R5 #1) | (test) | T6 (created early so dep ordering works; T10 extends if needed) |
| `src/cognic_agentos/protocol/ui_events.py` | UIEventBroker + cursor + RBACDenialType + AppendResult + typed projectors + PolicyRBACDenied | CC | T3+T4 |
| `src/cognic_agentos/portal/rbac/scopes.py` | NEW UIRBACScope 8-value Literal | CC | T5 |
| `src/cognic_agentos/portal/rbac/actor.py` | Actor.scopes union widening | CC | T5 |
| `src/cognic_agentos/portal/rbac/enforcement.py` | _bind_actor sync→async + broker.emit_rbac_denial | CC | T6 |
| `src/cognic_agentos/portal/rbac/tenant_isolation.py` | sync→async + broker.emit_rbac_denial | CC | T6 |
| `src/cognic_agentos/portal/rbac/human_actor.py` | sync→async + broker.emit_rbac_denial | CC | T6 |
| `src/cognic_agentos/portal/rbac/role_separation.py` | sync→async + broker.emit_rbac_denial | CC | T6 |
| `src/cognic_agentos/portal/api/app.py` | create_app wires broker + adapter + rego_engine; request-id middleware on /api/v1/* | NOT-CC | T12 |
| `AGENTS.md` | NEW "Authoring — UI event-stream (Sprint 7B.4)" subsection + 3 stop-rule entries | (doctrine) | T13 |
| `tools/check_critical_coverage.py` | +3 _CRITICAL_FILES entries; docstring section 60→63 | CC | T13 |
| `tests/unit/tools/test_check_critical_coverage.py` | Count guard 60→63 + new 7B.4 modules present | (test) | T13 |
| `docs/BUILD_PLAN.md` §602 | NEW 7B.4 CLOSED status row | (doctrine) | T14 |

---

## Reviewer round flags (carried into R-rounds before T3 commit)

Open doctrine flags the user may decide during R-rounds:

1. **PolicyBundleLoaded typed projector wiring** — spec defers it; reviewer-round confirm or scope into 7B.4.
2. **sampling.rego + supply_chain.rego promotion to explicit AGENTS.md stop-rules** — spec locks this at T13 alongside elicitation.rego; confirm or defer.
3. **Two-IDs-per-pack-POST contract** — spec accepts middleware-minted `portal-req-` ID for RBAC denials AND handler-minted per-verb IDs for pack handler chain rows. Closeout documents the contract; confirm framing.
4. **Direct OPA test marker name** — spec uses `@pytest.mark.opa_required`; confirm or rename for CI consistency.

---

## T1 — Design spec (DONE)

**Files modified:** `docs/superpowers/specs/2026-05-15-sprint-7b4-ui-event-stream-design.md` (NEW, 788 lines).
**Commit:** `6762cbc chore(sprint-7b4): T1 design spec`.
**CC classification:** NOT-CC (doc-only).
**Halt-before-commit:** N/A (already shipped).

---

## T2 — Plan-of-record commit

**Files (modify):** `docs/superpowers/plans/2026-05-15-sprint-7b4-ui-event-stream-endpoints.md` (NEW; this file).

**CC classification:** NOT-CC (chore docs). **Halt-before-commit:** NO.

**Acceptance:**
- This plan file lands as a chore commit on `feat/sprint-7b4-ui-event-stream-endpoints`.
- Self-review passes (spec coverage + placeholder scan + type consistency).

**Steps:**

- [ ] **Step 1:** Verify spec doc is committed at `6762cbc` on the current branch.

```bash
git log -1 --format='%H %s' -- docs/superpowers/specs/2026-05-15-sprint-7b4-ui-event-stream-design.md
# Expected: 6762cbc chore(sprint-7b4): T1 design spec
```

- [ ] **Step 2:** Verify this plan file is fully written + self-review-clean.

```bash
wc -l docs/superpowers/plans/2026-05-15-sprint-7b4-ui-event-stream-endpoints.md
grep -nE "TBD|TODO|FIXME|XXX" docs/superpowers/plans/2026-05-15-sprint-7b4-ui-event-stream-endpoints.md || echo "clean"
```

- [ ] **Step 3:** Stage + commit.

```bash
git add docs/superpowers/plans/2026-05-15-sprint-7b4-ui-event-stream-endpoints.md
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -m "chore(sprint-7b4): T2 plan-of-record"
```

---

## T3 — Foundation: sse-starlette dep + cursor encoder + RBACDenialType + AppendResult

**Files:**
- Modify: `pyproject.toml` (NEW explicit `sse-starlette>=2.1.0` runtime dep)
- Modify: `uv.lock` (regenerated)
- Modify: `src/cognic_agentos/protocol/ui_events.py` (NEW `_chain_derived_event_id`, `_decode_chain_cursor`, `RBACDenialType`, `PolicyRBACDenied` event class, `AppendResult` frozen dataclass, `_SSE_WAVE_1_STREAMED_FAMILIES` Final)
- Create: `tests/unit/protocol/test_ui_events_chain_cursor.py`
- Create: `tests/unit/protocol/test_ui_events_rbac_denial_type.py`

**CC classification:** **CC** (touches `protocol/ui_events.py` — already on durable gate from Sprint 6). **Halt-before-commit:** YES.

**Acceptance:**
- `sse-starlette>=2.1.0` is a declared runtime dep (was transitive).
- `_chain_derived_event_id(*, chain_id, sequence, ordinal, family, type_) -> str` encodes the 16-byte cursor payload via `ULID.from_bytes(...)`.
- `_decode_chain_cursor(event_id) -> ChainCursor` returns `(chain_id, sequence, ordinal, type_hash)`; raises `CursorMalformed` or `CursorChainUnsupported`.
- `RBACDenialType` is a 9-value `Literal` defined in `protocol/ui_events.py` (NOT imported from `portal/rbac/*`).
- `PolicyRBACDenied(_BaseEvent)` has `family: Literal["policy"] = "policy"` + `type: Literal["rbac_denied"] = "rbac_denied"` + safe-context fields (all bare `str | None` for portal-typed fields per the architectural-arrow invariant).
- `AppendResult` frozen dataclass = `(record_id: UUID, chain_hash: bytes, event_id: str)`.
- `_SSE_WAVE_1_STREAMED_FAMILIES: Final[frozenset[str]]` = 9 families (excludes `tool_call`, `artifact`).
- Test-layer union-equality regression imports the 4 portal RBAC Literals + asserts `set(get_args(RBACDenialType)) == union(get_args of 4 portal Literals)` + pairwise disjointness + count == 9.
- Cursor encode/decode roundtrip + `chain_disc=0x02` refusal + malformed-evt prefix refusal regressions.

**Steps:**

- [ ] **Step 1:** Add `sse-starlette>=2.1.0` to `pyproject.toml` runtime deps.

```toml
# pyproject.toml — under [project] dependencies = [
"sse-starlette>=2.1.0,<3.0.0",
```

- [ ] **Step 2:** Regenerate lockfile.

```bash
uv lock
```

- [ ] **Step 3:** Write failing cursor encoder/decoder tests at `tests/unit/protocol/test_ui_events_chain_cursor.py`.

```python
"""Sprint 7B.4 T3 — cursor encoder + decoder regressions."""
from __future__ import annotations
import pytest
from cognic_agentos.protocol.ui_events import (
    _chain_derived_event_id,
    _decode_chain_cursor,
    CursorMalformed,
    CursorChainUnsupported,
)


class TestChainDerivedEventIdRoundtrip:
    def test_encode_decode_typed_event(self) -> None:
        event_id = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=12345,
            ordinal=0,
            family="policy",
            type_="rbac_denied",
        )
        assert event_id.startswith("evt_")
        assert len(event_id) == 30  # "evt_" + 26-char base32
        cursor = _decode_chain_cursor(event_id)
        assert cursor.chain_id == "decision_history"
        assert cursor.sequence == 12345
        assert cursor.ordinal == 0
        # type_hash is sha256(family.type)[:6]
        import hashlib
        assert cursor.type_hash == hashlib.sha256(b"policy.rbac_denied").digest()[:6]

    def test_encode_is_deterministic(self) -> None:
        a = _chain_derived_event_id(chain_id="decision_history", sequence=1, ordinal=0,
                                    family="frontend_action", type_="submitted")
        b = _chain_derived_event_id(chain_id="decision_history", sequence=1, ordinal=0,
                                    family="frontend_action", type_="submitted")
        assert a == b

    def test_different_sequences_yield_different_ids(self) -> None:
        a = _chain_derived_event_id(chain_id="decision_history", sequence=1, ordinal=0,
                                    family="policy", type_="rbac_denied")
        b = _chain_derived_event_id(chain_id="decision_history", sequence=2, ordinal=0,
                                    family="policy", type_="rbac_denied")
        assert a != b

    def test_different_ordinals_yield_different_ids(self) -> None:
        a = _chain_derived_event_id(chain_id="decision_history", sequence=1, ordinal=0,
                                    family="frontend_action", type_="submitted")
        b = _chain_derived_event_id(chain_id="decision_history", sequence=1, ordinal=1,
                                    family="decision_audit", type_="event_appended")
        assert a != b


class TestCursorRefusals:
    def test_malformed_prefix_refused(self) -> None:
        with pytest.raises(CursorMalformed):
            _decode_chain_cursor("notanevt_0123456789ABCDEFGHIJK")

    def test_audit_chain_disc_unsupported_wave_1(self) -> None:
        # chain_disc=0x02 reserved for Wave-2 audit-event SSE
        bogus = _chain_derived_event_id(
            chain_id="audit_event", sequence=1, ordinal=0,
            family="tool_call", type_="approved",
        )
        with pytest.raises(CursorChainUnsupported):
            _decode_chain_cursor(bogus)
```

- [ ] **Step 4:** Run tests → verify FAIL (helpers don't exist yet).

```bash
uv run pytest tests/unit/protocol/test_ui_events_chain_cursor.py -v
# Expected: ImportError or NameError on _chain_derived_event_id
```

- [ ] **Step 5:** Implement the cursor helpers + `ChainCursor` dataclass + custom exceptions in `protocol/ui_events.py`.

```python
# protocol/ui_events.py — add at module scope after _new_event_id

import hashlib
import dataclasses
from typing import Literal
from ulid import ULID

ChainId = Literal["decision_history", "audit_event"]
_CHAIN_DISCRIMINATOR_BYTES: dict[ChainId, int] = {"decision_history": 0x01, "audit_event": 0x02}
_CHAIN_DISCRIMINATOR_REVERSE: dict[int, ChainId] = {0x01: "decision_history", 0x02: "audit_event"}

class CursorMalformed(ValueError):
    """Cursor event_id has wrong prefix / length / base32 decoding."""

class CursorChainUnsupported(ValueError):
    """Cursor's chain_disc byte not supported in this Wave (Wave-1 = decision_history only)."""

@dataclasses.dataclass(frozen=True)
class ChainCursor:
    chain_id: ChainId
    sequence: int
    ordinal: int
    type_hash: bytes  # 6 bytes

def _chain_derived_event_id(
    *, chain_id: ChainId, sequence: int, ordinal: int, family: str, type_: str,
) -> str:
    """Encode 16-byte cursor payload into evt_<26 base32>."""
    chain_disc = _CHAIN_DISCRIMINATOR_BYTES[chain_id].to_bytes(1, "big")
    seq_bytes = sequence.to_bytes(8, "big")
    ordinal_byte = ordinal.to_bytes(1, "big")
    type_hash = hashlib.sha256(f"{family}.{type_}".encode()).digest()[:6]
    payload = chain_disc + seq_bytes + ordinal_byte + type_hash
    assert len(payload) == 16
    return f"evt_{ULID.from_bytes(payload)}"

def _decode_chain_cursor(event_id: str) -> ChainCursor:
    """Decode evt_<26 base32> → ChainCursor."""
    if not event_id.startswith("evt_") or len(event_id) != 30:
        raise CursorMalformed(f"invalid event_id format: {event_id!r}")
    try:
        payload = bytes(ULID.from_str(event_id[4:]))
    except (ValueError, TypeError) as exc:
        raise CursorMalformed(f"base32 decode failed for {event_id!r}") from exc
    chain_disc = payload[0]
    if chain_disc not in _CHAIN_DISCRIMINATOR_REVERSE:
        raise CursorChainUnsupported(f"chain_disc=0x{chain_disc:02x} not supported in Wave-1")
    if chain_disc != 0x01:  # Wave-1: only decision_history
        raise CursorChainUnsupported(f"chain_disc=0x{chain_disc:02x} reserved for Wave-2")
    return ChainCursor(
        chain_id=_CHAIN_DISCRIMINATOR_REVERSE[chain_disc],
        sequence=int.from_bytes(payload[1:9], "big"),
        ordinal=payload[9],
        type_hash=payload[10:16],
    )
```

- [ ] **Step 6:** Run cursor tests → verify PASS.

```bash
uv run pytest tests/unit/protocol/test_ui_events_chain_cursor.py -v
# Expected: 7 passed
```

- [ ] **Step 7:** Write failing RBACDenialType + PolicyRBACDenied tests at `tests/unit/protocol/test_ui_events_rbac_denial_type.py`.

```python
"""Sprint 7B.4 T3 — RBACDenialType union + disjointness + PolicyRBACDenied shape."""
from typing import get_args
from cognic_agentos.protocol.ui_events import RBACDenialType, PolicyRBACDenied
from cognic_agentos.portal.rbac.enforcement import RBACDenialReason
from cognic_agentos.portal.rbac.tenant_isolation import TenantIsolationFailure
from cognic_agentos.portal.rbac.human_actor import HumanActorDenialReason
from cognic_agentos.portal.rbac.role_separation import RoleSeparationFailure


class TestRBACDenialTypeUnionEquality:
    def test_count_is_9(self) -> None:
        assert len(get_args(RBACDenialType)) == 9

    def test_union_equals_4_portal_literals(self) -> None:
        protocol_set = set(get_args(RBACDenialType))
        portal_union = (
            set(get_args(RBACDenialReason))
            | set(get_args(TenantIsolationFailure))
            | set(get_args(HumanActorDenialReason))
            | set(get_args(RoleSeparationFailure))
        )
        assert protocol_set == portal_union

    def test_4_portal_literals_pairwise_disjoint(self) -> None:
        a = set(get_args(RBACDenialReason))
        b = set(get_args(TenantIsolationFailure))
        c = set(get_args(HumanActorDenialReason))
        d = set(get_args(RoleSeparationFailure))
        assert a.isdisjoint(b)
        assert a.isdisjoint(c)
        assert a.isdisjoint(d)
        assert b.isdisjoint(c)
        assert b.isdisjoint(d)
        assert c.isdisjoint(d)


class TestPolicyRBACDeniedShape:
    def test_family_and_type_literals(self) -> None:
        # Construct an event; assert field literals
        from datetime import datetime, UTC
        evt = PolicyRBACDenied(
            event_id="evt_0123456789ABCDEFGHIJKLMNOP",
            ts=datetime.now(UTC),
            tenant="t1",
            audit_chain_hash="sha256:abcd",
            data={
                "denial_type": "scope_not_held",
                "actor_subject": "u1",
                "denied_at": datetime.now(UTC).isoformat(),
                "request_id": "portal-req-aabbcc",
                "required_scope": "ui.action.approve",
            },
        )
        assert evt.family == "policy"
        assert evt.type == "rbac_denied"

    def test_payload_required_scope_typed_as_bare_str(self) -> None:
        # Architectural-arrow invariant: protocol model does NOT type
        # required_scope as PackRBACScope | UIRBACScope (those are portal-owned).
        import inspect
        sig = inspect.signature(PolicyRBACDenied)
        # data is dict[str, Any]; runtime check is at test layer (TestRBACDenialEventEmittedFieldsStayInPortalVocab)
        # which lands in T6 with the emit-path tests.
```

- [ ] **Step 8:** Run RBAC type tests → verify FAIL.

```bash
uv run pytest tests/unit/protocol/test_ui_events_rbac_denial_type.py -v
# Expected: ImportError on RBACDenialType / PolicyRBACDenied
```

- [ ] **Step 9:** Implement `RBACDenialType` + `PolicyRBACDenied` + `_SSE_WAVE_1_STREAMED_FAMILIES` + `AppendResult` in `protocol/ui_events.py`.

```python
# protocol/ui_events.py — after the existing 11-family Pydantic models

RBACDenialType = Literal[
    "actor_unauthenticated",
    "scope_not_held",
    "actor_binder_not_configured",
    "tenant_id_mismatch",
    "pack_not_found",
    "actor_tenant_id_missing",
    "pack_store_not_configured",
    "actor_type_must_be_human",
    "actor_cannot_review_own_pack",
]
"""Sprint-7B.4 T3: protocol-owned 9-value union over the 4 portal RBAC denial vocabularies.
NOT imported from portal/rbac/* — preserves the portal → protocol arrow.
Test-layer regression asserts union equality with the 4 source Literals."""

class PolicyRBACDenied(_BaseEvent):
    """Sprint-7B.4 T3 — new typed event for the policy.rbac_denied decision_type.
    Uses the reserved policy.* family slot per ADR-020 (_WAVE_1_FAMILIES stays at 11)."""
    family: Literal["policy"] = "policy"
    type: Literal["rbac_denied"] = "rbac_denied"

# Wave-1 SSE-streamed families: 9 families (excludes tool_call, artifact — audit-event-backed).
_SSE_WAVE_1_STREAMED_FAMILIES: Final[frozenset[str]] = frozenset({
    "policy",
    "decision_audit",
    "agent_run",
    "subagent",
    "approval",
    "interrupt",
    "frontend_action",
    "memory",
    "kill_switch",
})

@dataclasses.dataclass(frozen=True)
class AppendResult:
    """Sprint-7B.4 T3 — broker chain-append return shape.
    The deterministic event_id is resolved by the broker from the typed event
    that fires synchronously during the awaited DecisionHistoryStore.append().
    See T4 for the ContextVar capture mechanism."""
    record_id: uuid.UUID
    chain_hash: bytes
    event_id: str
```

- [ ] **Step 10:** Run RBAC tests → verify PASS.

```bash
uv run pytest tests/unit/protocol/test_ui_events_chain_cursor.py tests/unit/protocol/test_ui_events_rbac_denial_type.py -v
# Expected: all green
```

- [ ] **Step 11:** Halt-before-commit summary + commit.

```bash
# Halt summary covers: cursor encoder/decoder roundtrip; RBACDenialType union eq;
#   PolicyRBACDenied family/type literals; AppendResult shape; no portal imports in protocol.
# Targeted slice + ruff + mypy clean.
git add pyproject.toml uv.lock src/cognic_agentos/protocol/ui_events.py \
        tests/unit/protocol/test_ui_events_chain_cursor.py \
        tests/unit/protocol/test_ui_events_rbac_denial_type.py
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -F - <<'EOF'
feat(sprint-7b4): T3 — protocol foundation: cursor encoder + RBACDenialType + AppendResult (CRITICAL CONTROLS)

- Explicit sse-starlette>=2.1.0 runtime dep (was transitive)
- _chain_derived_event_id + _decode_chain_cursor with 16-byte cursor payload
  (chain_disc + sequence + ordinal + type_hash); CursorMalformed +
  CursorChainUnsupported closed-enum refusals
- RBACDenialType 9-value protocol-owned Literal (NOT imported from portal/rbac/*);
  union equality + pairwise disjointness pinned at test layer
- PolicyRBACDenied event class uses reserved policy.* family slot
  (_WAVE_1_FAMILIES stays at 11)
- _SSE_WAVE_1_STREAMED_FAMILIES Final = 9 families (excludes tool_call/artifact)
- AppendResult frozen dataclass = (record_id, chain_hash, event_id)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
```

---

## T4 — UIEventBroker primitive + ContextVar capture + typed projector table + Settings fields

**Files:**
- Modify: `src/cognic_agentos/core/config.py` (NEW 5 UI-stream Settings fields — P1 #6 ownership)
- Modify: `src/cognic_agentos/protocol/ui_events.py` (NEW `UIEventBroker` class; `_PENDING_TYPED_EVENT_ID` ContextVar; `_TYPED_PROJECTION_CLASSES` frozenset; `_DECISION_HISTORY_TYPED_PROJECTORS` table + 4 projector functions + rbac.* prefix matcher; extended `_on_decision_append` to call typed projectors at ordinal 0)
- Create: `tests/unit/protocol/test_ui_events_broker.py`
- Create: `tests/unit/protocol/test_ui_events_typed_projectors.py`
- Create: `tests/unit/core/test_config_ui_event_stream_fields.py` (Settings-field count + default-value pinning)

**CC classification:** **CC** for `protocol/ui_events.py`. `core/config.py` is NOT on the durable gate (verified) — Settings additions are NOT-CC but on the same commit. **Halt-before-commit:** YES.

**Acceptance:**
- `core/config.py` `Settings` gains 5 NEW fields with documented defaults (P1 #6 ownership): `ui_event_stream_per_tenant_cap: int = 50`, `ui_event_stream_queue_maxsize: int = 1000`, `ui_event_stream_idle_timeout_s: int = 90`, `ui_event_stream_heartbeat_interval_s: int = 15`, `ui_event_stream_send_timeout_s: int = 30`. Each field uses `pydantic.Field(default=..., description="...")` per the existing module pattern.
- Settings drift detector pins the 5 field names + their default values (`test_config_ui_event_stream_fields.py`).
- `UIEventBroker(*, decision_history_store, settings)` — FastAPI-free; holds `DecisionHistoryStore` reference + reads the 5 fields from Settings.
- `register_subscriber(*, tenant_id, run_id_filter, family_filter) -> Subscriber` — validates cap; returns `Subscriber` with bounded queue + `unregister()`.
- `_fanout_hook(event)` — registers ONE hook on the existing `UIEventEmitter.register_hook(...)`; (1) captures `event.event_id` via `_PENDING_TYPED_EVENT_ID.set(...)` BEFORE subscriber fan-out, filtered to `_TYPED_PROJECTION_CLASSES`; (2) family + chain_id filter; (3) per-subscriber tenant/run_id/family-filter match; (4) enqueue.
- `emit_rbac_denial(*, denial_type, ...) -> AppendResult` — appends `rbac.<denial_type>` chain row + ISO `A.5.31`; returns full `AppendResult` with deterministic event_id.
- `append_frontend_action_submitted/accepted/rejected(...) -> AppendResult` — three methods; same shape; centralize chain emits.
- `reap_idle(now) -> int` — closes subscribers idle past timeout.
- `_DECISION_HISTORY_TYPED_PROJECTORS` registers 4 exact-match entries (`frontend_action.{submitted,accepted,rejected}` + `policy.decision_evaluated`) + 1 prefix-match (`rbac.<denial_type>`).
- `_on_decision_append` extended: ordinal 0 = typed projector (if matched), ordinal 1 = decision_audit mirror (always).
- Test classes: `TestBrokerAppendReturnsEventIdMatchingProjectedEvent`, `TestBrokerAppendRaisesWhenTypedProjectorMissing`, `TestBrokerAppendIsTaskScoped`, `TestBrokerCaptureFiltersOutDecisionAuditMirror`, `TestBrokerAppendReturnsEventIdWithNoSubscribers`, `TestSubscriberOverflowDoesNotSilentlyDrop`, `TestReapIdleClosesStaleSubscribers`.
- Test classes for typed projectors: `TestDecisionHistoryTypedRoutingCoversAll5DecisionTypes`, `TestDecisionHistoryTypedRoutingUnknownDecisionTypeOnlyMirror`, `TestTypedProjectorEventIdDeterministic`, `TestCanonicalProjectionOrderHoldsForBroker`.

**Steps:**

- [ ] **Step 1:** Write the broker happy-path test first.

```python
# tests/unit/protocol/test_ui_events_broker.py
"""Sprint 7B.4 T4 — UIEventBroker primitive regressions."""
import asyncio
import pytest
from cognic_agentos.protocol.ui_events import UIEventBroker, _chain_derived_event_id


class TestBrokerAppendReturnsEventIdMatchingProjectedEvent:
    @pytest.mark.asyncio
    async def test_append_frontend_action_submitted_returns_resolved_event_id(
        self, broker: UIEventBroker, sqlite_store
    ) -> None:
        result = await broker.append_frontend_action_submitted(
            request_id="portal-req-aabbcc",
            action_class="approve",
            actor_subject="u1",
            client_correlation_id="cli-1",
            payload_digest="sha256:dead",
            tenant_id="t1",
        )
        assert result.record_id is not None
        assert result.chain_hash is not None
        assert result.event_id.startswith("evt_")
        # event_id must match what the projector emitted (deterministic from sequence)
        assert len(result.event_id) == 30


class TestBrokerAppendReturnsEventIdWithNoSubscribers:
    """Pin that capture is independent of subscriber state — POST /actions
    must always emit submitted/resolution cursors even with zero UIs watching."""
    @pytest.mark.asyncio
    async def test_zero_subscribers_still_returns_valid_event_id(
        self, broker_with_no_subscribers: UIEventBroker
    ) -> None:
        result = await broker_with_no_subscribers.append_frontend_action_submitted(
            request_id="portal-req-noop", action_class="cancel_run",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:00", tenant_id="t1",
        )
        assert result.event_id and result.event_id.startswith("evt_")


class TestBrokerAppendRaisesWhenTypedProjectorMissing:
    @pytest.mark.asyncio
    async def test_raises_runtime_error_when_projector_unwired(
        self, broker: UIEventBroker, monkeypatch
    ) -> None:
        from cognic_agentos.protocol import ui_events
        empty_table = {}
        monkeypatch.setattr(ui_events, "_DECISION_HISTORY_TYPED_PROJECTORS", empty_table)
        with pytest.raises(RuntimeError, match="no typed event projected"):
            await broker.append_frontend_action_submitted(
                request_id="portal-req-z", action_class="approve",
                actor_subject="u1", client_correlation_id=None,
                payload_digest="sha256:11", tenant_id="t1",
            )
```

- [ ] **Step 2:** Run → verify FAIL.

```bash
uv run pytest tests/unit/protocol/test_ui_events_broker.py -v
# Expected: ImportError / AttributeError on UIEventBroker.append_frontend_action_*
```

- [ ] **Step 2.5 (NEW per P1 #6):** Add 5 UI-stream Settings fields to `core/config.py` + the drift-detector test:

```python
# core/config.py — inside class Settings(BaseSettings):

    # ────────────────────────────────────────────────────────────────────
    # UI event-stream knobs (Sprint 7B.4 per ADR-020)
    # ────────────────────────────────────────────────────────────────────
    ui_event_stream_per_tenant_cap: int = Field(
        default=50,
        ge=1,
        description="Max concurrent SSE subscribers per tenant; the broker refuses "
                    "register_subscriber with tenant_connection_cap_exceeded when hit.",
    )
    ui_event_stream_queue_maxsize: int = Field(
        default=1000,
        ge=16,
        description="Per-subscriber asyncio.Queue maxsize; QueueFull increments "
                    "subscriber.overflow_count and logs ui.subscriber.queue_overflow.",
    )
    ui_event_stream_idle_timeout_s: int = Field(
        default=90,
        ge=15,
        description="Seconds of no successful generator yield (heartbeat or event) "
                    "before reap_idle closes the subscriber.",
    )
    ui_event_stream_heartbeat_interval_s: int = Field(
        default=15,
        ge=1,
        description="Broker/generator-owned heartbeat interval (yields "
                    'ServerSentEvent(comment="keepalive")).',
    )
    ui_event_stream_send_timeout_s: int = Field(
        default=30,
        ge=1,
        description="sse-starlette EventSourceResponse send_timeout; bounds "
                    "half-open client cleanup.",
    )
```

```python
# tests/unit/core/test_config_ui_event_stream_fields.py
import pytest                                # R4 #5: needed for pytest.raises
import pydantic                              # R4 #5: needed for pydantic.ValidationError
from cognic_agentos.core.config import Settings


class TestUIStreamSettingsFields:
    def test_all_5_fields_present_with_defaults(self) -> None:
        s = Settings()
        assert s.ui_event_stream_per_tenant_cap == 50
        assert s.ui_event_stream_queue_maxsize == 1000
        assert s.ui_event_stream_idle_timeout_s == 90
        assert s.ui_event_stream_heartbeat_interval_s == 15
        assert s.ui_event_stream_send_timeout_s == 30

    def test_per_tenant_cap_rejects_zero(self) -> None:
        import pydantic
        with pytest.raises(pydantic.ValidationError):
            Settings(ui_event_stream_per_tenant_cap=0)

    def test_field_count_pinned_at_5(self) -> None:
        # Sentinel: extending this set is a deliberate plan-of-record edit.
        ui_fields = {n for n in Settings.model_fields if n.startswith("ui_event_stream_")}
        assert len(ui_fields) == 5
```

- [ ] **Step 3:** Implement `UIEventBroker` + ContextVar capture + the 3 `append_frontend_action_*` methods + `emit_rbac_denial` + `register_subscriber` + `reap_idle`.

```python
# protocol/ui_events.py — after AppendResult

from contextvars import ContextVar

_PENDING_TYPED_EVENT_ID: ContextVar[str | None] = ContextVar(
    "ui_broker_pending_typed_event_id", default=None
)

_TYPED_PROJECTION_CLASSES: frozenset[type] = frozenset({
    # Set in T4 after PolicyRBACDenied / FrontendAction* / PolicyDecisionEvaluated all defined
    PolicyRBACDenied, FrontendActionSubmitted, FrontendActionAccepted,
    FrontendActionRejected, PolicyDecisionEvaluated,
})

class UIEventBroker:
    """FastAPI-free in-memory pub/sub primitive per Sprint 7B.4 T4."""

    def __init__(self, *, decision_history_store, settings) -> None:
        self._history = decision_history_store
        self._settings = settings
        self._subscribers: list[Subscriber] = []
        self._per_tenant_count: dict[str, int] = {}

    def register_with_emitter(self, emitter) -> None:
        emitter.register_hook(self._fanout_hook)

    async def _fanout_hook(self, event) -> None:
        # 1) Capture event_id FIRST — independent of subscriber fan-out
        if type(event) in _TYPED_PROJECTION_CLASSES:
            _PENDING_TYPED_EVENT_ID.set(event.event_id)
        # 2) Family filter + chain_id filter
        if event.family not in _SSE_WAVE_1_STREAMED_FAMILIES:
            return
        if event.family == "decision_audit" and event.data.get("chain_id") != "decision_history":
            return
        # 3) Per-subscriber match + enqueue
        for sub in self._subscribers:
            if sub.tenant_id != event.tenant:
                continue
            if sub.run_id_filter and event.run_id != sub.run_id_filter:
                continue
            if sub.family_filter and event.family not in sub.family_filter:
                continue
            try:
                sub.queue.put_nowait(event)
            except asyncio.QueueFull:
                sub.overflow_count += 1
                _LOG.warning("ui.subscriber.queue_overflow",
                            extra={"tenant": sub.tenant_id, "overflow": sub.overflow_count})

    async def append_frontend_action_submitted(
        self, *, request_id, action_class, actor_subject, client_correlation_id,
        payload_digest, tenant_id, elicitation_mode=None,
    ) -> AppendResult:
        return await self._append_frontend_action(
            decision_type="frontend_action.submitted",
            tenant_id=tenant_id,
            request_id=request_id,
            payload={
                "request_id": request_id,
                "action_class": action_class,
                "actor_subject": actor_subject,
                "client_correlation_id": client_correlation_id,
                "payload_digest": payload_digest,
                **({"elicitation_mode": elicitation_mode} if elicitation_mode is not None else {}),
            },
        )

    async def append_frontend_action_accepted(
        self, *, request_id, action_class, actor_subject, client_correlation_id,
        submitted_event_id, tenant_id, elicitation_mode=None, originating_decision_record_id=None,
    ) -> AppendResult:
        payload = {
            "request_id": request_id, "action_class": action_class,
            "actor_subject": actor_subject, "client_correlation_id": client_correlation_id,
            "outcome": "accepted", "submitted_event_id": submitted_event_id,
        }
        # P1 #5 (R2): when this is a submit_elicitation row (elicitation_mode set),
        # ALWAYS include BOTH elicitation_mode AND originating_decision_record_id
        # in the keyset — even if originating_decision_record_id is None. Closed-keyset
        # contract: submit_elicitation resolution row has exactly 8 keys (or 7 for accepted
        # paths without ctx — but those never reach accepted; submit_elicitation accepted
        # always has ctx). Test pinned by TestSubmitElicitationChainPayloadKeysetClosed.
        if elicitation_mode is not None:
            payload["elicitation_mode"] = elicitation_mode
            payload["originating_decision_record_id"] = originating_decision_record_id  # may be None
        return await self._append_frontend_action(
            decision_type="frontend_action.accepted",
            tenant_id=tenant_id, request_id=request_id, payload=payload,
        )

    async def append_frontend_action_rejected(
        self, *, request_id, action_class, actor_subject, client_correlation_id,
        submitted_event_id, reason, tenant_id,
        elicitation_mode=None, originating_decision_record_id=None,
    ) -> AppendResult:
        payload = {
            "request_id": request_id, "action_class": action_class,
            "actor_subject": actor_subject, "client_correlation_id": client_correlation_id,
            "outcome": "rejected", "submitted_event_id": submitted_event_id, "reason": reason,
        }
        # P1 #5 (R2): same closed-keyset contract as accepted above. When
        # elicitation_mode is set, include originating_decision_record_id even if None
        # (elicitation_backend_unwired / elicitation_unknown_id paths don't know ctx).
        # Keeps the closed-keyset invariant stable across all submit_elicitation
        # resolution paths.
        if elicitation_mode is not None:
            payload["elicitation_mode"] = elicitation_mode
            payload["originating_decision_record_id"] = originating_decision_record_id  # may be None
        return await self._append_frontend_action(
            decision_type="frontend_action.rejected",
            tenant_id=tenant_id, request_id=request_id, payload=payload,
        )

    async def emit_rbac_denial(
        self, *, denial_type, actor_subject, request_id, http_status,
        tenant_id: str | None,                  # P1 #5: EXPLICIT, no default
        required_scope=None, pack_id=None, actor_type=None, pack_created_by=None,
        resource_type=None,
    ) -> AppendResult:
        """Sprint-7B.4 T4 — append a rbac.<denial_type> chain row.

        tenant_id contract (P1 #5 fix):
          - When actor IS resolved at the call site → pass actor.tenant_id.
          - When actor is UNRESOLVED (actor_unauthenticated /
            actor_binder_not_configured) → pass tenant_id=None. The chain
            row goes to audit only; SSE subscribers filter by event.tenant
            so unauth denials never reach any tenant's stream by design.
            Documented in the closeout's "Out of scope" section.
        """
        decision_type = f"rbac.{denial_type}"
        payload: dict[str, Any] = {
            "denial_type": denial_type,
            "actor_subject": actor_subject,
            "denied_at": datetime.now(UTC).isoformat(),
            "request_id": request_id,
            "http_status": http_status,
        }
        for k, v in {
            "required_scope": required_scope, "pack_id": pack_id, "actor_type": actor_type,
            "pack_created_by": pack_created_by, "resource_type": resource_type,
        }.items():
            if v is not None:
                payload[k] = str(v) if k != "pack_id" else str(v)
        return await self._append(
            decision_type=decision_type, tenant_id=tenant_id,
            request_id=request_id, payload=payload, iso_controls=("A.5.31",),
        )

    async def _append_frontend_action(self, *, decision_type, tenant_id, request_id, payload) -> AppendResult:
        return await self._append(
            decision_type=decision_type, tenant_id=tenant_id,
            request_id=request_id, payload=payload, iso_controls=("A.5.31",),
        )

    async def _append(self, *, decision_type, tenant_id, request_id, payload, iso_controls) -> AppendResult:
        _PENDING_TYPED_EVENT_ID.set(None)
        record = DecisionRecord(
            decision_type=decision_type, tenant_id=tenant_id,
            request_id=request_id, payload=payload, iso_controls=iso_controls,
        )
        record_id, chain_hash = await self._history.append(record)
        event_id = _PENDING_TYPED_EVENT_ID.get()
        if event_id is None:
            raise RuntimeError(
                f"broker append seam: no typed event projected for "
                f"decision_type={decision_type!r}; check _DECISION_HISTORY_TYPED_PROJECTORS"
            )
        return AppendResult(record_id=record_id, chain_hash=chain_hash, event_id=event_id)

    def register_subscriber(self, *, tenant_id, run_id_filter=None, family_filter=None):
        cap = self._settings.ui_event_stream_per_tenant_cap
        if self._per_tenant_count.get(tenant_id, 0) >= cap:
            raise TenantConnectionCapExceeded(tenant_id=tenant_id, cap=cap)
        sub = Subscriber(
            tenant_id=tenant_id, run_id_filter=run_id_filter, family_filter=family_filter,
            queue=asyncio.Queue(maxsize=self._settings.ui_event_stream_queue_maxsize),
        )
        self._subscribers.append(sub)
        self._per_tenant_count[tenant_id] = self._per_tenant_count.get(tenant_id, 0) + 1
        return sub

    def unregister_subscriber(self, sub) -> None:
        if sub in self._subscribers:
            self._subscribers.remove(sub)
            self._per_tenant_count[sub.tenant_id] -= 1

    def reap_idle(self, now) -> int:
        idle_s = self._settings.ui_event_stream_idle_timeout_s
        reaped = 0
        for sub in list(self._subscribers):
            if (now - sub.last_activity_at).total_seconds() > idle_s:
                self.unregister_subscriber(sub)
                reaped += 1
        return reaped
```

- [ ] **Step 4:** Add `_DECISION_HISTORY_TYPED_PROJECTORS` table + the 4 projector functions + `_on_decision_append` extension.

```python
# protocol/ui_events.py — after _TYPED_PROJECTION_CLASSES

def _project_frontend_action_submitted(snapshot) -> FrontendActionSubmitted:
    return FrontendActionSubmitted(
        event_id=_chain_derived_event_id(
            chain_id="decision_history", sequence=snapshot.sequence,
            ordinal=0, family="frontend_action", type_="submitted",
        ),
        ts=snapshot.created_at, tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )

def _project_frontend_action_accepted(snapshot) -> FrontendActionAccepted:
    return FrontendActionAccepted(
        event_id=_chain_derived_event_id(
            chain_id="decision_history", sequence=snapshot.sequence,
            ordinal=0, family="frontend_action", type_="accepted",
        ),
        ts=snapshot.created_at, tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


def _project_frontend_action_rejected(snapshot) -> FrontendActionRejected:
    return FrontendActionRejected(
        event_id=_chain_derived_event_id(
            chain_id="decision_history", sequence=snapshot.sequence,
            ordinal=0, family="frontend_action", type_="rejected",
        ),
        ts=snapshot.created_at, tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )


def _project_policy_decision_evaluated(snapshot) -> PolicyDecisionEvaluated:
    return PolicyDecisionEvaluated(
        event_id=_chain_derived_event_id(
            chain_id="decision_history", sequence=snapshot.sequence,
            ordinal=0, family="policy", type_="decision_evaluated",
        ),
        ts=snapshot.created_at, tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )

def _project_policy_rbac_denied(snapshot) -> PolicyRBACDenied:
    """Prefix-matched: snapshot.decision_type starts with 'rbac.'."""
    return PolicyRBACDenied(
        event_id=_chain_derived_event_id(
            chain_id="decision_history", sequence=snapshot.sequence,
            ordinal=0, family="policy", type_="rbac_denied",
        ),
        ts=snapshot.created_at, tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data=snapshot.payload,
    )

_DECISION_HISTORY_TYPED_PROJECTORS: Final[dict[str, Callable]] = {
    "frontend_action.submitted": _project_frontend_action_submitted,
    "frontend_action.accepted":  _project_frontend_action_accepted,
    "frontend_action.rejected":  _project_frontend_action_rejected,
    "policy.decision_evaluated": _project_policy_decision_evaluated,
}

def _project_typed_decision_history(snapshot):
    dt = snapshot.decision_type
    if dt in _DECISION_HISTORY_TYPED_PROJECTORS:
        return _DECISION_HISTORY_TYPED_PROJECTORS[dt](snapshot)
    if dt.startswith("rbac."):
        return _project_policy_rbac_denied(snapshot)
    return None


def _build_decision_audit_for_dh_snapshot(snapshot) -> "DecisionAuditEventAppended":
    """R3 #2: shared decision_audit.event_appended projection for the
    decision_history chain — used BOTH by _on_decision_append (live emit
    at ordinal 1) AND by _replay_from_decision_history (replay path).
    Mirrors the inline construction at the current Sprint-6 code
    (ui_events.py:660) — extracted as a helper to keep the live and
    replay paths byte-identical."""
    return DecisionAuditEventAppended(
        event_id=_chain_derived_event_id(
            chain_id="decision_history", sequence=snapshot.sequence,
            ordinal=1, family="decision_audit", type_="event_appended",
        ),
        ts=snapshot.created_at,
        tenant=snapshot.tenant_id,
        trace_id=snapshot.trace_id,
        audit_chain_hash=_format_chain_hash(snapshot.new_hash),
        data={
            "event_type":      snapshot.decision_type,
            "payload_digest":  _payload_digest(snapshot.payload),
            "request_id":      snapshot.request_id,
            "sequence":        snapshot.sequence,
            "chain_id":        snapshot.chain_id,
            "tenant_id":       snapshot.tenant_id,
        },
    )
```

Step 4b (refactor `_on_decision_append`): replace the inline `DecisionAuditEventAppended(...)` construction with a call to the new helper, so the live and replay paths share the projection:

```python
# protocol/ui_events.py — replace existing _on_decision_append body
async def _on_decision_append(self, snapshot: AppendedDecisionSnapshot) -> None:
    # Ordinal 0: typed projector (if matched)
    typed = _project_typed_decision_history(snapshot)
    if typed is not None:
        await self._safe_emit(typed)
    # Ordinal 1: generic decision_audit mirror (always) — shared helper
    await self._safe_emit(_build_decision_audit_for_dh_snapshot(snapshot))
```

A test in `test_ui_events_typed_projectors.py` pins live + replay parity: project the same `snapshot` twice (once via `_on_decision_append`, once via the replay helper) → assert byte-equal event_id + byte-equal `data` keyset.

- [ ] **Step 5:** Extend `UIEventEmitter._on_decision_append`:

```python
# Replace existing _on_decision_append body with:
async def _on_decision_append(self, snapshot) -> None:
    typed = _project_typed_decision_history(snapshot)
    if typed is not None:
        await self._safe_emit(typed)
    # Always emit the decision_audit mirror at ordinal 1 — shared helper (R3 #2)
    await self._safe_emit(_build_decision_audit_for_dh_snapshot(snapshot))
```

- [ ] **Step 6:** Write typed-projector tests + run; verify PASS.

```bash
uv run pytest tests/unit/protocol/test_ui_events_typed_projectors.py tests/unit/protocol/test_ui_events_broker.py -v
# Expected: all green
```

- [ ] **Step 7:** Halt-before-commit + commit.

```bash
# P1 #4 fix: stage ALL T4 files including the Settings additions + their test
git add src/cognic_agentos/core/config.py \
        src/cognic_agentos/protocol/ui_events.py \
        tests/unit/core/test_config_ui_event_stream_fields.py \
        tests/unit/protocol/test_ui_events_broker.py \
        tests/unit/protocol/test_ui_events_typed_projectors.py
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -F - <<'EOF'
feat(sprint-7b4): T4 — UIEventBroker primitive + ContextVar capture + typed projectors + Settings fields (CRITICAL CONTROLS)

- UIEventBroker class: in-memory pub/sub primitive; per-tenant cap + bounded
  queues + reap_idle; 3 append_frontend_action_* methods + emit_rbac_denial
  centralize chain emits; ContextVar capture resolves AppendResult.event_id
  from the typed event projected during the awaited DecisionHistoryStore.append
- _DECISION_HISTORY_TYPED_PROJECTORS table extended (4 exact-match entries +
  rbac.* prefix matcher); _on_decision_append emits ordinal 0 typed + ordinal
  1 decision_audit mirror per canonical projection order
- Pinning regressions: TestBrokerAppendReturnsEventIdWithNoSubscribers,
  TestBrokerAppendRaisesWhenTypedProjectorMissing, TestBrokerAppendIsTaskScoped,
  TestBrokerCaptureFiltersOutDecisionAuditMirror

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
```

---

## T5 — UIRBACScope + Actor.scopes union widening

**Files:**
- Modify: `src/cognic_agentos/portal/rbac/scopes.py` (NEW 8-value `UIRBACScope` Literal)
- Modify: `src/cognic_agentos/portal/rbac/actor.py` (`scopes: frozenset[PackRBACScope | UIRBACScope]`)
- Create: `tests/unit/portal/rbac/test_actor_scope_widening.py`

**CC classification:** **CC** (both modules on durable gate from 7B.2 T12). **Halt-before-commit:** YES.

**Acceptance:**
- `UIRBACScope = Literal[ui.run_stream, ui.tenant_stream, ui.action.{approve,deny,cancel_run,interrupt,resume,submit_elicitation}]` — 8 values.
- `Actor.scopes` widened to `frozenset[PackRBACScope | UIRBACScope]` — additive; existing bank-overlay code still works (Pydantic doesn't enforce Literal at runtime).
- Count guard + existence tests for the 8 new values.
- Drift detector: `UIRBACScope` is disjoint from `PackRBACScope`.

**Steps:**

- [ ] **Step 1:** Write failing tests.

```python
# tests/unit/portal/rbac/test_actor_scope_widening.py
from typing import get_args
from cognic_agentos.portal.rbac.scopes import UIRBACScope, PackRBACScope
from cognic_agentos.portal.rbac.actor import Actor


class TestUIRBACScopeShape:
    def test_count_is_8(self) -> None:
        assert len(get_args(UIRBACScope)) == 8

    def test_disjoint_from_pack_rbac_scope(self) -> None:
        assert set(get_args(UIRBACScope)).isdisjoint(set(get_args(PackRBACScope)))

    def test_expected_values(self) -> None:
        assert set(get_args(UIRBACScope)) == {
            "ui.run_stream", "ui.tenant_stream",
            "ui.action.approve", "ui.action.deny", "ui.action.cancel_run",
            "ui.action.interrupt", "ui.action.resume", "ui.action.submit_elicitation",
        }


class TestActorScopesAcceptsUnion:
    def test_actor_accepts_ui_scopes(self) -> None:
        actor = Actor(subject="u1", tenant_id="t1", actor_type="human",
                      scopes=frozenset({"ui.run_stream", "ui.action.approve"}))
        assert "ui.run_stream" in actor.scopes
```

- [ ] **Step 2:** Run → FAIL on `UIRBACScope` not defined.
- [ ] **Step 3:** Add the Literal to `portal/rbac/scopes.py`:

```python
UIRBACScope = Literal[
    "ui.run_stream", "ui.tenant_stream",
    "ui.action.approve", "ui.action.deny", "ui.action.cancel_run",
    "ui.action.interrupt", "ui.action.resume", "ui.action.submit_elicitation",
]
```

- [ ] **Step 4:** Widen `Actor.scopes` in `portal/rbac/actor.py`:

```python
# Change:
scopes: frozenset[PackRBACScope]
# To:
scopes: frozenset[PackRBACScope | UIRBACScope]
```

- [ ] **Step 5:** Run targeted slice + full RBAC slice → verify PASS.
- [ ] **Step 6:** Halt-before-commit + commit.

```bash
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -m "feat(sprint-7b4): T5 — UIRBACScope 8-value Literal + Actor.scopes union widening (CRITICAL CONTROLS)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>"
```

---

## T6 — Broker app-state wiring + request-id middleware + async RBAC deps + dual-surface denial emission

**Files:**
- Modify: `src/cognic_agentos/portal/api/app.py` (NEW: request-id middleware on `/api/v1/*` + broker construction + `app.state.ui_event_broker` attach + broker emitter-registration + `reap_idle` lifespan task — the **minimal** wiring needed before T6's RBAC deps reference it; T12 EXTENDS this with elicitation_adapter + rego_engine + UI router include)
- Modify: `src/cognic_agentos/portal/rbac/enforcement.py` (`_bind_actor` sync→async + 4 `Require*` deps async; broker.emit_rbac_denial calls; sync `binder.bind()` call preserved)
- Modify: `src/cognic_agentos/portal/rbac/tenant_isolation.py` (sync→async + emit)
- Modify: `src/cognic_agentos/portal/rbac/human_actor.py` (sync→async + emit)
- Modify: `src/cognic_agentos/portal/rbac/role_separation.py` (sync→async + emit)
- Create: `tests/unit/portal/rbac/test_rbac_denial_chain_emission.py`

**CC classification:** **CC** (4 RBAC modules on durable gate). **Halt-before-commit:** YES.

**Acceptance:**
- Middleware on `/api/v1/*` mints `request.state.request_id = "portal-req-" + uuid4().hex` (42 chars ≤ 64).
- `create_app` constructs the `UIEventBroker(decision_history_store=..., settings=...)` BEFORE registering RBAC routes; attaches to `app.state.ui_event_broker`; calls `broker.register_with_emitter(emitter)`; mounts a periodic-asyncio `reap_idle` lifespan task. (T12 EXTENDS this with `elicitation_adapter` + `rego_engine` + UI router include.)
- **Sync binder preserved** (per P1 #4): `_bind_actor` is `async def` (so it can `await broker.emit_rbac_denial`), but it calls `binder.bind(request=request)` synchronously — no `await` (the existing `ActorBinder` Protocol at `portal/rbac/actor.py:112` is sync `def bind(...)`; broadening it is out of scope for 7B.4).
- Each of 4 RBAC modules' refusal sites: `_LOG.warning("portal.rbac.<key>", extra=...)` FIRST, then `await broker.emit_rbac_denial(...)` with **explicit `tenant_id=` argument** (per P1 #5):
  - When actor IS resolved → `tenant_id=actor.tenant_id`.
  - When actor is NOT resolved (the 2 `_bind_actor` failure paths — `actor_unauthenticated`, `actor_binder_not_configured`) → `tenant_id=None` (chain row has NULL tenant_id; SSE subscribers filter by tenant so unauth denials are audit-only by design — they don't belong to any tenant's stream). Documented explicitly in the helper + the closeout's "Out of scope (unauth denials never reach SSE — Wave-1 contract)" section.
- Append-failure path: `_LOG.error(...) + raise HTTPException(500, detail={"reason": "rbac_denial_emit_failed"})`.
- Defensive fallback at `_bind_actor`: if `request.state.request_id` unset, mint `portal-rbac-denial-<uuid>` (52 chars ≤ 64). Should never fire under normal `/api/v1/*` traffic (middleware always mints) — covers non-portal callers that bypass middleware.
- 9 fail-closed regressions per denial_type + 1 threat-model-revert test (remove try/except around emit → audit-loss test FAILS → restore → passes).
- All 4 dep factories now async; FastAPI handles async deps transparently for existing pack-route callers (no callsite changes).

**Steps:**

- [ ] **Step 1 (REVISED per R6 #1):** Add THREE files at T6 (BEFORE T10 needs them — R6 #1 task-ordering fix):

  1. `tests/unit/portal/api/ui/sse_test_helpers.py` — shared plain-callables module (originally R5 #1; moved to T6 so the RBAC conftest's cross-directory import resolves at T6 execution time, NOT only after T10 ships). Reused by T10/T11/T12 unchanged.
  2. `tests/unit/portal/api/ui/conftest.py` — UI test fixtures (skeleton; T10 may extend with SSE-specific fixtures but the shared ones live here).
  3. `tests/unit/portal/rbac/conftest.py` — RBAC test fixtures.

T6 creates all three so T6 is self-contained (R6 #1: doesn't import from a future task). T10's git-add block stages additions/extensions to the conftest files but the core skeleton already exists at T6 close.

**File (1) — sse_test_helpers.py** (R8 #2 — concrete code inlined at T6 since T6 owns it per R6 #1; T10 reuses unchanged):

```python
# tests/unit/portal/api/ui/sse_test_helpers.py
"""Plain helper functions used by T10/T11/T12 SSE tests + the T6 RBAC tests.
NOT fixtures — imported explicitly via:
  from tests.unit.portal.api.ui.sse_test_helpers import _next_sse_event, ...
Per pytest's documented behavior, plain callables in conftest.py are NOT
auto-injected into test module globals; only fixtures requested as test
parameters are.

R9 #1 + R9 #4 additions: `_async_client(app)` (ASGITransport wrapper for
httpx 0.28+ which dropped `AsyncClient(app=...)`) + `emit_audit_tool_call_event`
(audit-chain helper used by the TestAuditBackedFamiliesExcludedFromSSE class)."""
from __future__ import annotations

import json
from typing import Any
import httpx

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.ui_events import UIEventBroker


class _FixtureActorBinder:
    """Sync ActorBinder returning a fixture-provided actor (preserves R2 #4
    sync-binder contract on ActorBinder.bind)."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request) -> Actor:
        return self._actor


def _async_client(app, *, base_url: str = "http://t") -> httpx.AsyncClient:
    """R9 #1 — ASGI transport wrapper.

    httpx 0.28+ dropped the legacy `AsyncClient(app=app, ...)` shortcut;
    callers must wrap the ASGI app in an `httpx.ASGITransport` and pass it
    as the `transport=` kwarg. This helper centralises the wrapping so test
    bodies stay terse:

        async with _async_client(app_with_ui_routes) as c:
            r = await c.get("/api/v1/ui/...")

    Verified against `uv.lock` httpx 0.28.1 pin + the repo's existing httpx
    usage at `tests/unit/protocol/test_a2a_schema_drift.py:72`."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base_url)


async def _next_sse_event(response: httpx.Response) -> dict[str, Any]:
    """Parse the next ServerSentEvent off a streaming httpx response.
    Returns {id, event, data}. Skips comment lines (`:` keepalives)."""
    pending: dict[str, str] = {}
    async for raw in response.aiter_lines():
        if raw.startswith(":"):
            continue
        if raw == "":
            if "data" in pending:
                return {
                    "id": pending.get("id"),
                    "event": pending.get("event"),
                    "data": json.loads(pending["data"]),
                }
            pending = {}
            continue
        if ":" in raw:
            key, _, val = raw.partition(":")
            pending[key.strip()] = val.lstrip(" ")
    raise RuntimeError("SSE stream ended without an event")


async def _iter_sse_events(response: httpx.Response, *, max_events: int):
    """Yield up to max_events ServerSentEvents off response."""
    for _ in range(max_events):
        yield await _next_sse_event(response)


async def _read_recent_decision_history_rows(broker_or_app) -> list:
    """Direct SQLAlchemy read of recent _decision_history rows newest-first.
    Returns raw SQLAlchemy Row objects — callers read `row.event_type`,
    `row.tenant_id`, `row.payload`, etc. (NOT `row.decision_type` — that's
    the DecisionRecord dataclass field; SQL column is event_type per R4 #1)."""
    from sqlalchemy import select
    from fastapi import FastAPI
    from cognic_agentos.core.decision_history import _decision_history
    if isinstance(broker_or_app, FastAPI):
        engine = broker_or_app.state.decision_history_store._engine
    else:
        engine = broker_or_app._history._engine
    async with engine.begin() as conn:
        result = await conn.execute(
            select(_decision_history)
            .order_by(_decision_history.c.sequence.desc())
            .limit(50)
        )
        return list(result.fetchall())


async def emit_test_policy_event_and_memory_event(broker: UIEventBroker) -> None:
    """Helper for TestFamilyFilter — emits a policy.rbac_denied chain event.
    R5 #4: tests MUST `await` this — it's async because the broker append seam is async."""
    await broker.emit_rbac_denial(
        denial_type="scope_not_held", actor_subject="u_test",
        tenant_id="t1", request_id="portal-req-test-policy", http_status=403,
        required_scope="ui.action.approve",
    )


async def emit_audit_tool_call_event(audit_store: AuditStore, *, tenant_id: str) -> None:
    """R9 #4 + R10 #4 — audit-chain helper used by TestAuditBackedFamiliesExcludedFromSSE.

    Appends a synthetic `tool_call.started` event to the audit chain so the
    Wave-1-SSE family-filter regression can assert that audit-backed events
    DO NOT reach SSE subscribers (Wave-1 SSE = decision-history-only).

    **R10 #4 fix:** `AuditStore.append` takes a SINGLE `AuditEvent` object,
    NOT keyword args; `AuditEvent` has fields `event_type / request_id /
    payload / tenant_id / trace_id / span_id / langfuse_trace_id /
    provider_label / iso_controls` (no `actor_subject` field — actor identity
    travels inside `payload` when needed). Verified at
    `src/cognic_agentos/core/audit.py:156-164` (AuditEvent fields) +
    `src/cognic_agentos/core/audit.py:298` (`async def append(self, event: AuditEvent)`).

    Test request_id is fixed (`portal-req-test-tool-call`) so the
    family-filter regression can assert on the row by request_id without
    coordinating on a random UUID. The `actor_subject` field is folded into
    the payload as `payload["actor_subject"] = "u_test"`."""
    from cognic_agentos.core.audit import AuditEvent  # R10 #4: import on call to keep top-level imports terse
    await audit_store.append(
        AuditEvent(
            event_type="tool_call.started",
            request_id="portal-req-test-tool-call",
            tenant_id=tenant_id,
            payload={
                "tool_name": "echo",
                "tool_call_id": "tc_test",
                "actor_subject": "u_test",
            },
        )
    )
```

**File (2) — UI conftest.py** at `tests/unit/portal/api/ui/conftest.py` (R8 #2 — concrete code inlined at T6; T10 may extend with SSE-specific fixtures but the skeleton ships here):

```python
# tests/unit/portal/api/ui/conftest.py
"""Sprint 7B.4 T6/T10 — pytest fixtures for SSE/action tests. Plain helpers
live in sse_test_helpers.py (R5 #1); test files import them explicitly. This
module holds ONLY fixtures that pytest auto-discovers under the directory tree."""
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from fastapi import FastAPI

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.ui_events import UIEventBroker, UIEventEmitter

from tests.unit.portal.api.ui.sse_test_helpers import _FixtureActorBinder


@pytest.fixture
async def sqlite_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """Per-test sqlite engine with both chain heads seeded (R4 #2 columns)."""
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'ui_test.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id, latest_sequence=0,
                    latest_hash=ZERO_HASH, updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.fixture
def settings() -> Settings:
    return Settings()


@pytest.fixture
def settings_low_cap() -> Settings:
    return Settings(ui_event_stream_per_tenant_cap=1)


@pytest.fixture
def settings_short_send_timeout() -> Settings:
    return Settings(ui_event_stream_send_timeout_s=1)


@pytest.fixture
async def audit_store(sqlite_engine) -> AuditStore:
    return AuditStore(sqlite_engine)


@pytest.fixture
async def decision_history_store(sqlite_engine) -> DecisionHistoryStore:
    return DecisionHistoryStore(sqlite_engine)


@pytest.fixture
async def ui_event_emitter(audit_store, decision_history_store) -> UIEventEmitter:
    return UIEventEmitter(audit_store=audit_store,
                          decision_history_store=decision_history_store)


@pytest.fixture
async def broker(decision_history_store, ui_event_emitter, settings) -> UIEventBroker:
    b = UIEventBroker(decision_history_store=decision_history_store, settings=settings)
    b.register_with_emitter(ui_event_emitter)
    return b


@pytest.fixture
def actor_t1() -> Actor:
    """UI-test actor: tenant t1; holds all 8 UI scopes."""
    return Actor(
        subject="u1", tenant_id="t1", actor_type="human",
        scopes=frozenset({
            "ui.run_stream", "ui.tenant_stream",
            "ui.action.approve", "ui.action.deny", "ui.action.cancel_run",
            "ui.action.interrupt", "ui.action.resume", "ui.action.submit_elicitation",
        }),
    )


@pytest.fixture
async def app_with_broker(
    broker, decision_history_store, audit_store, ui_event_emitter,
    settings, actor_t1,
) -> FastAPI:
    """UI-test app: broker + UI routes + actor binder mocked to actor_t1."""
    from cognic_agentos.portal.api.app import create_app
    return create_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        actor_binder=_FixtureActorBinder(actor_t1),
    )


@pytest.fixture
async def app_with_broker_low_cap(
    settings_low_cap, decision_history_store, audit_store, ui_event_emitter, actor_t1,
) -> FastAPI:
    """R13 #2 — settings_low_cap-wired app_with_broker variant.

    The default `app_with_broker` fixture depends on `settings` (default cap = 50)
    and threads that into create_app → broker construction. A test that requests
    `settings_low_cap` AS A SEPARATE PARAMETER on the test signature does NOT
    re-thread it into the broker — the mounted broker still uses the default cap,
    so the cap-exceeded test would never reliably 429. This sibling fixture rebuilds
    create_app from `settings_low_cap` so the broker honors the per-tenant cap of 1."""
    from cognic_agentos.portal.api.app import create_app
    return create_app(
        settings=settings_low_cap,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        actor_binder=_FixtureActorBinder(actor_t1),
    )


@pytest.fixture
async def broker_low_cap(decision_history_store, ui_event_emitter, settings_low_cap) -> UIEventBroker:
    """R13 #2 — settings_low_cap-wired broker sibling to the default `broker` fixture.
    The `app_low_cap` fixture below depends on this so the broker the route uses
    AND the broker the test inspects (via `broker._subscribers`) are the SAME instance."""
    b = UIEventBroker(decision_history_store=decision_history_store, settings=settings_low_cap)
    b.register_with_emitter(ui_event_emitter)
    return b


@pytest.fixture
async def app_low_cap(app_with_broker_low_cap, broker_low_cap) -> FastAPI:
    """R13 #2 — UI-mounted app fixture wired to settings_low_cap.
    Mirror of the default `app` fixture below but rooted at the low-cap settings
    instance — every component in the dep chain (settings → broker → app) uses
    the SAME low-cap settings, eliminating the silent-default-cap bug class."""
    from cognic_agentos.portal.api.ui.stream_routes import build_stream_routes
    app_with_broker_low_cap.include_router(
        build_stream_routes(broker=broker_low_cap), prefix="/api/v1/ui",
    )
    return app_with_broker_low_cap


@pytest.fixture
async def app_with_broker_short_send_timeout(
    settings_short_send_timeout, decision_history_store, audit_store, ui_event_emitter, actor_t1,
) -> FastAPI:
    """R13 #2 — settings_short_send_timeout-wired app_with_broker variant.
    Same shape as `app_with_broker_low_cap`; rooted at the short-timeout settings."""
    from cognic_agentos.portal.api.app import create_app
    return create_app(
        settings=settings_short_send_timeout,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        actor_binder=_FixtureActorBinder(actor_t1),
    )


@pytest.fixture
async def broker_short_send_timeout(
    decision_history_store, ui_event_emitter, settings_short_send_timeout,
) -> UIEventBroker:
    """R13 #2 — settings_short_send_timeout-wired broker; sibling to `broker_low_cap`."""
    b = UIEventBroker(
        decision_history_store=decision_history_store, settings=settings_short_send_timeout,
    )
    b.register_with_emitter(ui_event_emitter)
    return b


@pytest.fixture
async def app_short_send_timeout(
    app_with_broker_short_send_timeout, broker_short_send_timeout,
) -> FastAPI:
    """R13 #2 — UI-mounted app fixture wired to settings_short_send_timeout.
    The send-timeout cleanup test requests this fixture instead of `app` so the
    mounted broker actually uses the 1s send_timeout (rather than the 30s default)."""
    from cognic_agentos.portal.api.ui.stream_routes import build_stream_routes
    app_with_broker_short_send_timeout.include_router(
        build_stream_routes(broker=broker_short_send_timeout),
        prefix="/api/v1/ui",
    )
    return app_with_broker_short_send_timeout


@pytest.fixture
async def app(app_with_broker, broker) -> FastAPI:
    """R9 #2 — UI-mounted app fixture.

    Mounts `build_stream_routes(broker=broker)` on top of `app_with_broker`
    via lazy import. The lazy import lets this fixture coexist in the T6
    conftest WITHOUT breaking T6's RBAC test collection: the import only
    fires when a test requests `app`, and T6 RBAC tests use `app_with_broker`
    directly (no UI routes needed). T10 SSE tests request `app` — by then
    `portal/api/ui/stream_routes.py` exists (T10 creates it) and the import
    resolves.

    Production-grade: NO silent fallback. If a test requests `app` and the
    stream_routes module is missing (e.g. running T10 tests before T10 ships
    the module), the lazy import raises ImportError — that IS the TDD RED.

    T11 / T12 fixtures (`app_with_scopes`, `app_with_only_approve`,
    `app_with_well_known`) extend this same pattern by additionally mounting
    `build_action_routes` and `build_well_known_route`."""
    from cognic_agentos.portal.api.ui.stream_routes import build_stream_routes
    app_with_broker.include_router(
        build_stream_routes(broker=broker), prefix="/api/v1/ui",
    )
    return app_with_broker
```

Note: the T10 section below previously contained these same code blocks for context. Since R6 #1 / R8 #2 move ownership to T6, T10's Step 1 is now: "the helpers + UI conftest already shipped at T6; T10 only adds the SSE test files."

**File (3) — RBAC conftest.py** (R6 fixes folded in):

```python
# tests/unit/portal/rbac/conftest.py  (R5 #2 + R6 fixes)
"""Sprint 7B.4 T6 — pytest fixtures for the RBAC denial chain emission tests.

R6 fixes:
  - R6 #1: this file + sse_test_helpers + ui/conftest all created at T6 so
           the cross-directory import resolves when T6 executes.
  - R6 #2: _setup_denial_path spells out every RBACDenialType branch
           (no `pass` placeholders).
  - R6 #3: NEW pack_record_store fixture wires a real (in-memory-backed)
           PackRecordStore so create_app mounts pack routes.
  - R6 #4: denial paths swap app.state.actor_binder (so the REAL _bind_actor
           runs + catches the exception + emits the chain row); NOT
           dependency_overrides[_bind_actor] (which bypasses the dep entirely).
"""
from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from fastapi import FastAPI

from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.packs.storage import PackRecordStore, PackRecord       # R8 #1: PackState/PackKind are Literals, accessed as string values; no import needed (ruff F401)
from cognic_agentos.protocol.ui_events import UIEventBroker, UIEventEmitter

from tests.unit.portal.api.ui.sse_test_helpers import _FixtureActorBinder


@pytest.fixture
async def sqlite_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """Per-test sqlite engine with both chain heads seeded (R4 #2 columns)."""
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'rbac_test.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id, latest_sequence=0,
                    latest_hash=ZERO_HASH, updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.fixture
def settings() -> Settings:
    return Settings()


@pytest.fixture
async def audit_store(sqlite_engine) -> AuditStore:
    return AuditStore(sqlite_engine)


@pytest.fixture
async def decision_history_store(sqlite_engine) -> DecisionHistoryStore:
    return DecisionHistoryStore(sqlite_engine)


@pytest.fixture
async def ui_event_emitter(audit_store, decision_history_store) -> UIEventEmitter:
    return UIEventEmitter(
        audit_store=audit_store, decision_history_store=decision_history_store,
    )


@pytest.fixture
async def broker(decision_history_store, ui_event_emitter, settings) -> UIEventBroker:
    b = UIEventBroker(decision_history_store=decision_history_store, settings=settings)
    b.register_with_emitter(ui_event_emitter)
    return b


@pytest.fixture
async def pack_record_store(sqlite_engine) -> PackRecordStore:
    """R7 #1: PackRecordStore.__init__ takes only `engine: AsyncEngine`
    (verified at packs/storage.py:491 — single-arg). Drops the bogus
    `history=` kwarg from R6 — DecisionHistoryStore wiring happens via
    a different seam inside the store (chain-write goes through the
    engine, not a separately injected history reference)."""
    return PackRecordStore(sqlite_engine)


@pytest.fixture
async def seeded_pack_t1(pack_record_store, actor_t1_with_pack_submit) -> PackRecord:
    """A pack in tenant t1 created by u1 — used for role_separation tests.

    R7 #1: save_draft(record: PackRecord) takes a PackRecord object, NOT
    kwargs (verified at packs/storage.py:495). PackKind is a `Literal`
    (no Enum) so `PackKind.TOOL` doesn't exist — use string literal `"tool"`.
    Mirrors the existing pattern at tests/unit/portal/api/packs/test_operator_routes.py:204-219."""
    import uuid
    record = PackRecord(
        id=uuid.uuid4(),
        kind="tool",                                  # R7 #1: Literal, not Enum
        pack_id="example-tool",
        display_name="Example Tool",
        state="draft",                                # required by save_draft genesis guard
        manifest_digest=b"\x00" * 32,
        signed_artefact_digest=b"\x02" * 32,            # R8 #1: bytes, not None (field type is `bytes` at storage.py:378)
        sbom_pointer=None,
        tenant_id="t1",
        created_by="u1",
        last_actor="u1",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    await pack_record_store.save_draft(record)
    return record


@pytest.fixture
async def seeded_pack_t2(pack_record_store) -> PackRecord:
    """A pack in tenant t2 — used for cross-tenant tenant_id_mismatch tests."""
    import uuid
    record = PackRecord(
        id=uuid.uuid4(),
        kind="tool",
        pack_id="t2-tool",
        display_name="T2 Tool",
        state="draft",
        manifest_digest=b"\x00" * 32,
        signed_artefact_digest=b"\x02" * 32,            # R8 #1: bytes, not None (field type is `bytes` at storage.py:378)
        sbom_pointer=None,
        tenant_id="t2",
        created_by="other-user",
        last_actor="other-user",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    await pack_record_store.save_draft(record)
    return record


@pytest.fixture
def actor_t1_with_pack_submit() -> Actor:
    """Default RBAC-test actor: tenant t1, holds pack.submit + pack.audit.read.
    Lacks pack.allow_list, pack.review.claim → forces scope_not_held on those."""
    return Actor(
        subject="u1", tenant_id="t1", actor_type="human",
        scopes=frozenset({"pack.submit", "pack.audit.read"}),
    )


@pytest.fixture
async def app_with_broker(
    broker, decision_history_store, audit_store, ui_event_emitter,
    pack_record_store, settings, actor_t1_with_pack_submit,
) -> FastAPI:
    """Full app with broker + pack routes wired (R6 #3: pack_record_store added
    so POST /api/v1/packs/* routes mount)."""
    from cognic_agentos.portal.api.app import create_app
    return create_app(
        settings=settings,
        actor_binder=_FixtureActorBinder(actor_t1_with_pack_submit),
        pack_record_store=pack_record_store,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
    )


@pytest.fixture
def _setup_denial_path(seeded_pack_t1, seeded_pack_t2):
    """R6 #2: 9-branch concrete setup for every RBACDenialType.

    Returns a callable `setup(app, denial_type) -> (request_method, request_path, request_kwargs)`
    that swaps app.state.actor_binder (R6 #4: NOT dependency_overrides[_bind_actor],
    which would bypass the real _bind_actor's exception-catch path) + returns
    the (method, path, kwargs) tuple the test should use to trigger this denial."""
    from cognic_agentos.portal.rbac.actor import (
        ActorBinderUnauthenticated, KernelDefaultActorBinder,
    )

    class _RaisesUnauthBinder:
        def bind(self, *, request):
            raise ActorBinderUnauthenticated("no token")

    class _FixedActor:
        def __init__(self, actor):
            self._a = actor

        def bind(self, *, request):
            return self._a

    def setup(app: FastAPI, denial_type: str) -> tuple[str, str, dict]:
        if denial_type == "actor_unauthenticated":
            # R6 #4: swap the BINDER (real _bind_actor catches the exception);
            # POST /api/v1/packs/drafts requires _bind_actor → unauth fires there.
            app.state.actor_binder = _RaisesUnauthBinder()
            return ("POST", "/api/v1/packs/drafts", {"json": {"manifest": {}}})

        if denial_type == "actor_binder_not_configured":
            # KernelDefaultActorBinder.bind raises NotImplementedError → real
            # _bind_actor catches + emits actor_binder_not_configured chain row.
            app.state.actor_binder = KernelDefaultActorBinder()
            return ("POST", "/api/v1/packs/drafts", {"json": {"manifest": {}}})

        if denial_type == "scope_not_held":
            # Actor lacks pack.allow_list; route /allow-list requires it →
            # RequireScope fires scope_not_held.
            actor = Actor(subject="u1", tenant_id="t1", actor_type="human",
                          scopes=frozenset({"pack.submit"}))
            app.state.actor_binder = _FixedActor(actor)
            return ("POST", f"/api/v1/packs/{seeded_pack_t1.id}/allow-list", {"json": {}})

        if denial_type == "tenant_id_mismatch":
            # Actor in t1; request a pack in t2 → RequireTenantOwnership
            # fires tenant_id_mismatch (rendered 404 cross-tenant-invisible
            # at the wire, but the chain row + log emit tenant_id_mismatch).
            actor = Actor(subject="u1", tenant_id="t1", actor_type="human",
                          scopes=frozenset({"pack.audit.read"}))
            app.state.actor_binder = _FixedActor(actor)
            return ("GET", f"/api/v1/packs/{seeded_pack_t2.id}", {})

        if denial_type == "pack_not_found":
            # Bogus pack_id UUID under the actor's tenant → RequireTenantOwnership
            # fires pack_not_found.
            actor = Actor(subject="u1", tenant_id="t1", actor_type="human",
                          scopes=frozenset({"pack.audit.read"}))
            app.state.actor_binder = _FixedActor(actor)
            return ("GET", f"/api/v1/packs/{uuid.uuid4()}", {})

        if denial_type == "actor_tenant_id_missing":
            # Actor has empty tenant_id (the only Pydantic-reachable falsy
            # case per actor.py:71); the GET /api/v1/packs/ list endpoint's
            # preflight catches this.
            actor = Actor(subject="u1", tenant_id="", actor_type="human",
                          scopes=frozenset({"pack.audit.read"}))
            app.state.actor_binder = _FixedActor(actor)
            return ("GET", "/api/v1/packs/", {})

        if denial_type == "pack_store_not_configured":
            # Defensive 500: simulate the configuration regression by
            # clearing pack_record_store from app.state at request time.
            actor = Actor(subject="u1", tenant_id="t1", actor_type="human",
                          scopes=frozenset({"pack.audit.read"}))
            app.state.actor_binder = _FixedActor(actor)
            app.state.pack_record_store = None    # simulate misconfig
            return ("GET", f"/api/v1/packs/{seeded_pack_t1.id}", {})

        if denial_type == "actor_type_must_be_human":
            # Service-token actor holding pack.allow_list scope; RequireHumanActor
            # on the allow-list endpoint fires actor_type_must_be_human.
            actor = Actor(subject="svc-bot", tenant_id="t1", actor_type="service",
                          scopes=frozenset({"pack.submit", "pack.allow_list"}))
            app.state.actor_binder = _FixedActor(actor)
            return ("POST", f"/api/v1/packs/{seeded_pack_t1.id}/allow-list", {"json": {}})

        if denial_type == "actor_cannot_review_own_pack":
            # Same actor as the pack's created_by + tries to claim review →
            # RequireDifferentActorThanCreator fires actor_cannot_review_own_pack.
            # Actor needs pack.review.claim scope to reach the role_separation
            # dep (which runs after RequireScope).
            actor = Actor(subject="u1",   # SAME as seeded_pack_t1.created_by
                          tenant_id="t1", actor_type="human",
                          scopes=frozenset({"pack.review.claim"}))
            app.state.actor_binder = _FixedActor(actor)
            return ("POST", f"/api/v1/packs/{seeded_pack_t1.id}/claim", {"json": {}})

        raise AssertionError(f"unknown RBACDenialType: {denial_type!r}")

    return setup
```

The parametrized test consumes this fixture, gets back the (method, path, kwargs) tuple, and fires the request:

```python
@pytest.mark.asyncio
@pytest.mark.parametrize("denial_type", list(get_args(RBACDenialType)))
async def test_each_denial_type_emits_log_then_chain_row(
    self, app_with_broker, caplog, denial_type, _setup_denial_path,
):
    method, path, kwargs = _setup_denial_path(app_with_broker, denial_type)
    async with _async_client(app_with_broker) as c:
        await c.request(method, path, **kwargs)
    # ... dual-surface assertions ...
```

- [ ] **Step 2:** Write the dual-surface + fail-closed + tenant-routing tests at `tests/unit/portal/rbac/test_rbac_denial_chain_emission.py`. The test file imports the plain helpers explicitly (per R5 #1):

```python
# tests/unit/portal/rbac/test_rbac_denial_chain_emission.py
from tests.unit.portal.api.ui.sse_test_helpers import (
    _async_client,                          # R10 #1: needed by every request path (httpx 0.28+ ASGITransport wrapper)
    _read_recent_decision_history_rows,
)
```

```python
"""Sprint 7B.4 T6 — async RBAC + dual-surface denial emission + tenant routing."""
import pytest
from unittest.mock import AsyncMock
# R10 #2: `import httpx` removed — test bodies route ALL request setup through
# `_async_client(...)` after the R9 #1 sweep; the bare module name is no longer
# referenced in this file (ruff F401 would refuse).
from cognic_agentos.protocol.ui_events import RBACDenialType
from typing import get_args


class TestRBACDenialDualSurfaceEmission:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("denial_type", list(get_args(RBACDenialType)))
    async def test_each_denial_type_emits_log_then_chain_row(
        self, app_with_broker, caplog, denial_type, _setup_denial_path,
    ) -> None:
        # R7 #2: dispatcher returns (method, path, kwargs) per the R6 dispatcher
        # contract; use it to fire the request that triggers THIS denial type.
        # Hardcoding POST /api/v1/packs/drafts would only exercise 1/9 branches.
        method, path, kwargs = _setup_denial_path(app_with_broker, denial_type)
        async with _async_client(app_with_broker) as c:
            await c.request(method, path, **kwargs)
        # Surface 1: structured log
        log_key = f"portal.rbac.{denial_type}"
        assert any(rec.message == log_key or
                   getattr(rec, "reason", None) == denial_type
                   for rec in caplog.records)
        # Surface 2: chain row (R4 #1: SQL column is event_type, NOT decision_type)
        rows = await _read_recent_decision_history_rows(app_with_broker)
        assert any(row.event_type == f"rbac.{denial_type}" for row in rows)


class TestRBACDenialTenantRouting:
    """R2 #5 — explicit tenant_id on every emit_rbac_denial call.
    When actor resolved: tenant_id=actor.tenant_id; when actor unresolved
    (actor_unauthenticated / actor_binder_not_configured): tenant_id=None
    (chain row goes to audit-only, NOT SSE-routable)."""

    @pytest.mark.asyncio
    async def test_resolved_actor_passes_tenant_to_emit(
        self, app_with_broker, broker, _setup_denial_path,
    ) -> None:
        # R7 #2: use the dispatcher's scope_not_held branch — actor is resolved
        # (tenant_id="t1") + route requires pack.allow_list which actor lacks.
        method, path, kwargs = _setup_denial_path(app_with_broker, "scope_not_held")
        spy = AsyncMock(wraps=broker.emit_rbac_denial)
        broker.emit_rbac_denial = spy
        async with _async_client(app_with_broker) as c:
            await c.request(method, path, **kwargs)
        spy.assert_awaited_once()
        assert spy.await_args.kwargs["tenant_id"] == "t1"

    @pytest.mark.asyncio
    async def test_unauthenticated_emits_with_tenant_none(
        self, app_with_broker, broker, _setup_denial_path,
    ) -> None:
        # R7 #2: dispatcher's actor_unauthenticated branch — binder raises
        # ActorBinderUnauthenticated; no actor → tenant_id=None on emit.
        method, path, kwargs = _setup_denial_path(app_with_broker, "actor_unauthenticated")
        spy = AsyncMock(wraps=broker.emit_rbac_denial)
        broker.emit_rbac_denial = spy
        async with _async_client(app_with_broker) as c:
            await c.request(method, path, **kwargs)
        spy.assert_awaited_once()
        assert spy.await_args.kwargs["tenant_id"] is None


class TestRBACDenialFailClosedOnEmitFailure:
    @pytest.mark.asyncio
    async def test_emit_failure_raises_500_not_silent(
        self, app_with_broker, broker, monkeypatch, _setup_denial_path,
    ) -> None:
        # R7 #2: use the dispatcher's scope_not_held branch — guaranteed to
        # reach the broker.emit_rbac_denial call site (which the monkeypatch
        # forces to raise → fail-closed 500).
        method, path, kwargs = _setup_denial_path(app_with_broker, "scope_not_held")
        monkeypatch.setattr(broker, "emit_rbac_denial",
                            AsyncMock(side_effect=RuntimeError("simulated DB outage")))
        async with _async_client(app_with_broker) as c:
            r = await c.request(method, path, **kwargs)
        assert r.status_code == 500
        assert r.json()["detail"]["reason"] == "rbac_denial_emit_failed"


class TestRequestIdMiddleware:
    @pytest.mark.asyncio
    async def test_middleware_mints_portal_req_id_for_api_v1(
        self, app_with_broker, request_id_capture_helper,
    ) -> None:
        async with _async_client(app_with_broker) as c:
            await c.get("/api/v1/packs/")
        captured = request_id_capture_helper()
        assert captured.startswith("portal-req-")
        assert 42 <= len(captured) <= 64


class TestSyncBinderContractPreserved:
    """P1 #4 — ActorBinder.bind stays sync; only _bind_actor wrapper is async."""

    def test_actor_binder_protocol_bind_is_sync(self) -> None:
        from cognic_agentos.portal.rbac.actor import ActorBinder
        import inspect
        assert not inspect.iscoroutinefunction(ActorBinder.bind)
```

- [ ] **Step 3:** Run → verify FAIL (deps still sync; no broker on app.state; no middleware).

```bash
uv run pytest tests/unit/portal/rbac/test_rbac_denial_chain_emission.py -v
# Expected: AttributeError on app.state.ui_event_broker / async dep issues
```

- [ ] **Step 4:** Add the request-id middleware + broker construction in `portal/api/app.py` (P1 #3 — backward-compatible optional-deps pattern; mirrors how 7B.3 T9 added `trust_gate` / `trust_root_resolver`):

**Design lock — `create_app` extension follows the 7B.3 T9 precedent:** add NEW optional keyword-only deps with `None`-default. Existing callers (test fixtures that omit them) continue working — the broker is simply not constructed and UI routes are not mounted. Production deployments pass them in. Fail-loud at runtime if a UI request reaches a route that needs an unwired dep (handled by Section 2b.5's `app.state.ui_event_broker` defensive read + the broker None check at registration sites).

```python
# portal/api/app.py — extend create_app signature
import asyncio                                                # R4 #5: needed for asyncio.sleep/create_task/CancelledError
import uuid
from cognic_agentos.protocol.ui_events import UIEventBroker
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.decision_history import DecisionHistoryStore
# (UIEventEmitter is already imported in Sprint 6's code)

def create_app(
    settings: Settings | None = None,
    *,
    # ... existing optional deps (adapter_registry, gateway_ledger,
    # plugin_registry, actor_binder, pack_record_store, trust_gate,
    # trust_root_resolver) UNCHANGED ...
    # NEW Sprint-7B.4 T6 optional deps (backward-compatible — None-default):
    decision_history_store: DecisionHistoryStore | None = None,
    audit_store: AuditStore | None = None,
    ui_event_emitter: "UIEventEmitter | None" = None,
) -> FastAPI:
    app = FastAPI()
    # ... existing setup ...

    # Sprint-7B.4 T6: request-id middleware on ALL /api/v1/* portal routes
    @app.middleware("http")
    async def _portal_request_id_middleware(request: Request, call_next):
        if request.url.path.startswith("/api/v1/"):
            if not getattr(request.state, "request_id", None):
                request.state.request_id = f"portal-req-{uuid.uuid4().hex}"
        return await call_next(request)

    # Sprint-7B.4 T6: broker construction — only when its mandatory deps are wired.
    # Backward-compatible: existing tests that omit these new deps still work;
    # the broker stays None and the UI routes simply aren't mounted at T12.
    broker: UIEventBroker | None = None
    if decision_history_store is not None and ui_event_emitter is not None and settings is not None:
        broker = UIEventBroker(
            decision_history_store=decision_history_store,
            settings=settings,
        )
        broker.register_with_emitter(ui_event_emitter)

        # Periodic reap_idle lifespan task — only registered when broker is constructed
        async def _reap_task():
            from datetime import datetime, UTC
            while True:
                await asyncio.sleep(settings.ui_event_stream_idle_timeout_s / 3)
                broker.reap_idle(datetime.now(UTC))

        @app.on_event("startup")
        async def _start_reap():
            app.state._reap_task = asyncio.create_task(_reap_task())

        @app.on_event("shutdown")
        async def _stop_reap():
            t = getattr(app.state, "_reap_task", None)
            if t is not None:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass

    app.state.ui_event_broker = broker      # may be None — RBAC deps must None-check
    app.state.decision_history_store = decision_history_store
    app.state.settings = settings

    # ... rest of existing setup (route includes, etc.) UNCHANGED ...
```

**RBAC dep None-check:** `_bind_actor` and the 4 `Require*` deps must handle `broker is None` defensively. When broker is None, denial paths SKIP the `emit_rbac_denial` call (the structured log still fires — operations surface preserved) and raise the normal `HTTPException(403/...)`. This keeps existing tests (which omit the new deps) green; production deployments wire the broker and get the full dual-surface contract.

```python
# enforcement.py — concrete _emit_denial_or_500 implementation (R4 #4)
import logging
import uuid
from typing import Any
from fastapi import HTTPException
from cognic_agentos.protocol.ui_events import UIEventBroker, RBACDenialType

_LOG = logging.getLogger(__name__)


async def _emit_denial_or_500(
    broker: UIEventBroker | None,
    *,
    denial_type: RBACDenialType,
    actor_subject: str | None,
    tenant_id: str | None,
    request_id: str,
    http_status: int,
    required_scope: str | None = None,
    pack_id: str | None = None,
    actor_type: str | None = None,
    pack_created_by: str | None = None,
    resource_type: str | None = None,
) -> None:
    """Shared dual-surface emission helper used by _bind_actor + the 4 Require*
    deps. The kwargs match the broker.emit_rbac_denial signature 1:1.

    Always emits the structured log first (operations surface; guaranteed).
    Then awaits the chain-row append if a broker is wired:
      - broker is None  → log-only (backward-compat for callers that omit
                          the new optional deps to create_app — pack-only
                          deployments stay green)
      - broker raises   → fail-closed 500 with rbac_denial_emit_failed
                          (no silent audit loss)
    """
    log_extra: dict[str, Any] = {
        "reason": denial_type,
        "actor_subject": actor_subject,
        "tenant_id": tenant_id,
        "request_id": request_id,
        "http_status": http_status,
    }
    if required_scope is not None:
        log_extra["required_scope"] = required_scope
    if pack_id is not None:
        log_extra["pack_id"] = pack_id
    if actor_type is not None:
        log_extra["actor_type"] = actor_type
    if pack_created_by is not None:
        log_extra["pack_created_by"] = pack_created_by
    if resource_type is not None:
        log_extra["resource_type"] = resource_type
    _LOG.warning(f"portal.rbac.{denial_type}", extra=log_extra)

    if broker is None:        # R3 #3 backward-compat: pack-only deployments
        return

    try:
        await broker.emit_rbac_denial(
            denial_type=denial_type,
            actor_subject=actor_subject,
            tenant_id=tenant_id,
            request_id=request_id,
            http_status=http_status,
            required_scope=required_scope,
            pack_id=pack_id,
            actor_type=actor_type,
            pack_created_by=pack_created_by,
            resource_type=resource_type,
        )
    except Exception as exc:
        _LOG.error("portal.rbac.denial_emit_failed", exc_info=True)
        raise HTTPException(
            500, detail={"reason": "rbac_denial_emit_failed"}
        ) from exc
```

**T12 extends this pattern** by adding 2 more None-default optional deps (`elicitation_adapter` + `rego_engine`) and conditionally including the UI router only when `broker is not None`. Existing pack-only deployments stay green; full-stack deployments mount the UI surface.

- [ ] **Step 5:** Convert `_bind_actor` to async + add denial emission (KEEPING `binder.bind()` sync):

```python
# portal/rbac/enforcement.py

async def _bind_actor(request: Request) -> Actor:
    """Sprint-7B.4 T6: async wrapper around the existing SYNC ActorBinder.bind
    so denial paths can await broker.emit_rbac_denial. The binder.bind call
    itself stays synchronous — the ActorBinder Protocol is unchanged."""
    binder = request.app.state.actor_binder
    broker = request.app.state.ui_event_broker
    request_id = (
        getattr(request.state, "request_id", None)
        or f"portal-rbac-denial-{uuid.uuid4().hex}"
    )
    try:
        # SYNC call — preserves the existing ActorBinder contract (P1 #4 fix)
        actor = binder.bind(request=request)
    except ActorBinderUnauthenticated:
        await _emit_denial_or_500(
            broker, denial_type="actor_unauthenticated",
            actor_subject=None, tenant_id=None,   # P1 #5: unauth → tenant=None
            request_id=request_id, http_status=403,
        )
        raise HTTPException(403, detail={"reason": "actor_unauthenticated"})
    except NotImplementedError as exc:
        await _emit_denial_or_500(
            broker, denial_type="actor_binder_not_configured",
            actor_subject=None, tenant_id=None,   # P1 #5: unauth → tenant=None
            request_id=request_id, http_status=500,
        )
        raise HTTPException(500,
                            detail={"reason": "actor_binder_not_configured"}) from exc
    return actor

# R11 #1: The earlier code block (lines ~1905-1981) is the SINGLE SOURCE OF
# TRUTH for `_emit_denial_or_500` — it carries the `if broker is None: return`
# log-only fallback (R3 #3 backward-compat for pack-only deployments). A prior
# draft of this Step 5 redefined the helper here as a "simplified" version
# WITHOUT that guard; the duplicate has been removed because it would have
# turned pack-only RBAC denials into 500s by calling `broker.emit_rbac_denial`
# on `None`. Step 6 below uses the helper defined at line ~1916.
```

- [ ] **Step 6:** Convert the 4 `Require*` dep factories to async returning Actor / Pack / etc.; each refusal site uses `_emit_denial_or_500(broker, denial_type=..., tenant_id=actor.tenant_id, ...)` (actor IS resolved at this point — tenant_id is always known here).

- [ ] **Step 7:** Run tests → verify PASS.

```bash
uv run pytest tests/unit/portal/rbac/test_rbac_denial_chain_emission.py -v
# Expected: 13+ passed (9 denial-type parametrized + tenant routing + fail-closed + middleware + sync-binder-contract)
```

- [ ] **Step 8:** **Threat-model-revert verification** (per `feedback_security_regression_hardening`):
  - Back up `enforcement.py`: `cp src/cognic_agentos/portal/rbac/enforcement.py /tmp/enf_backup.py`
  - Remove the `try/except` around `broker.emit_rbac_denial` in `_emit_denial_or_500`.
  - Re-run the regression: `uv run pytest tests/unit/portal/rbac/test_rbac_denial_chain_emission.py::TestRBACDenialFailClosedOnEmitFailure -v`
  - Confirm FAIL.
  - Restore from `/tmp/enf_backup.py`; rerun; confirm PASS.

- [ ] **Step 9:** Halt-before-commit summary + commit.

```bash
git add src/cognic_agentos/portal/api/app.py \
        src/cognic_agentos/portal/rbac/enforcement.py \
        src/cognic_agentos/portal/rbac/tenant_isolation.py \
        src/cognic_agentos/portal/rbac/human_actor.py \
        src/cognic_agentos/portal/rbac/role_separation.py \
        tests/unit/portal/api/ui/__init__.py \
        tests/unit/portal/api/ui/conftest.py \
        tests/unit/portal/api/ui/sse_test_helpers.py \
        tests/unit/portal/rbac/conftest.py \
        tests/unit/portal/rbac/test_rbac_denial_chain_emission.py
# R6 #5: the 3 NEW test-support files (sse_test_helpers + 2 conftests) are
# created at T6 so T6 is self-contained (R6 #1). T10/T11/T12 extend the UI
# conftest if needed but the skeleton ships here.
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -F - <<'EOF'
feat(sprint-7b4): T6 — broker wiring + request-id middleware + async RBAC + dual-surface denial emission + RBAC/UI test-support skeleton (CRITICAL CONTROLS)

- create_app constructs UIEventBroker and attaches to app.state BEFORE RBAC
  deps reference it (P1 #3 ordering); registers broker hook on the existing
  UIEventEmitter; mounts periodic reap_idle lifespan task
- Request-id middleware mints "portal-req-<uuid4>" on app.state for every
  /api/v1/* request — covers BOTH UI and pack denial paths (P1 #2 scope)
- _bind_actor is async (to await broker.emit_rbac_denial) but calls the
  existing SYNC ActorBinder.bind() unchanged (P1 #4 — Protocol preserved)
- Every emit_rbac_denial call passes explicit tenant_id (P1 #5):
  resolved actor → actor.tenant_id; unauth paths → None (chain-only, never
  SSE-routable; Wave-1 unauth-not-on-stream contract)
- All 4 Require* deps async; FastAPI transparent for callers
- Threat-model-revert verified for the fail-closed 500 contract

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
```

---

## T7 — ElicitationAdapter Protocol + KernelDefault scaffold

**Files:**
- Create: `src/cognic_agentos/protocol/elicitation_adapter.py`
- Create: `tests/unit/protocol/test_elicitation_adapter.py`

**CC classification:** NOT-CC (Protocol + fail-loud scaffold; mirrors 7B.3 T9 `trust_root_resolver.py`). **Halt-before-commit:** NO.

**Acceptance:**
- `ElicitationMode = Literal["url", "form"]`; `ElicitationContext` + `ElicitationResult` frozen dataclasses; `ElicitationBackendError` exception.
- `ElicitationAdapter` Protocol with `get_context` + `handle_submission` methods.
- `KernelDefaultElicitationAdapter` raises `NotImplementedError` from both methods.
- Module imports nothing from `portal/`, `fastapi`, `core/`.
- 6 tests: Protocol structural shape, ElicitationContext frozen + fields, ElicitationResult frozen + fields, kernel-default `get_context` raises with ADR pointer, kernel-default `handle_submission` raises with ADR pointer, module imports clean (no portal/FastAPI/core).

**Steps:**

- [ ] **Step 1:** Write failing tests at `tests/unit/protocol/test_elicitation_adapter.py`:

```python
"""Sprint 7B.4 T7 — ElicitationAdapter Protocol + KernelDefault fail-loud scaffold."""
import ast
import dataclasses
import inspect
import uuid
from datetime import datetime, UTC
from pathlib import Path
from typing import get_args, runtime_checkable
import pytest


class TestElicitationModeLiteral:
    def test_2_value_url_form(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import ElicitationMode
        assert set(get_args(ElicitationMode)) == {"url", "form"}


class TestElicitationContextShape:
    def test_frozen_dataclass(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import ElicitationContext
        assert dataclasses.is_dataclass(ElicitationContext)
        ctx = ElicitationContext(
            elicitation_id="elc_1", tenant_id="t1",
            originating_pack_id="pkg_1", originating_decision_record_id=uuid.uuid4(),
            elicitation_modes=("url",), data_classes=("public",), expires_at=None,
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.tenant_id = "t2"

    def test_required_fields(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import ElicitationContext
        field_names = {f.name for f in dataclasses.fields(ElicitationContext)}
        assert field_names == {
            "elicitation_id", "tenant_id", "originating_pack_id",
            "originating_decision_record_id", "elicitation_modes",
            "data_classes", "expires_at",
        }


class TestElicitationResultShape:
    def test_frozen_dataclass(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import ElicitationResult
        assert dataclasses.is_dataclass(ElicitationResult)
        r = ElicitationResult(delivered_at=datetime.now(UTC), backend_correlation_id="b_1")
        with pytest.raises(dataclasses.FrozenInstanceError):
            r.backend_correlation_id = "other"


class TestElicitationAdapterProtocol:
    def test_runtime_checkable(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import ElicitationAdapter

        class Stub:
            async def get_context(self, *, elicitation_id, tenant_id): pass
            async def handle_submission(self, *, ctx, mode, payload): pass

        # @runtime_checkable Protocol
        assert isinstance(Stub(), ElicitationAdapter)

    def test_missing_method_fails_isinstance(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import ElicitationAdapter

        class Incomplete:
            async def get_context(self, *, elicitation_id, tenant_id): pass
            # missing handle_submission

        assert not isinstance(Incomplete(), ElicitationAdapter)


class TestKernelDefaultElicitationAdapter:
    @pytest.mark.asyncio
    async def test_get_context_raises_not_implemented_pointing_at_adr(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import (
            KernelDefaultElicitationAdapter,
        )
        adapter = KernelDefaultElicitationAdapter()
        with pytest.raises(NotImplementedError, match="ADR-020"):
            await adapter.get_context(elicitation_id="elc_1", tenant_id="t1")

    @pytest.mark.asyncio
    async def test_handle_submission_raises_not_implemented_pointing_at_adr(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import (
            KernelDefaultElicitationAdapter, ElicitationContext,
        )
        adapter = KernelDefaultElicitationAdapter()
        ctx = ElicitationContext(
            elicitation_id="elc_1", tenant_id="t1",
            originating_pack_id="pkg_1", originating_decision_record_id=uuid.uuid4(),
            elicitation_modes=("url",), data_classes=("public",), expires_at=None,
        )
        with pytest.raises(NotImplementedError, match="ADR-020"):
            await adapter.handle_submission(ctx=ctx, mode="url", payload={})


class TestElicitationBackendError:
    def test_is_runtime_error_subclass(self) -> None:
        from cognic_agentos.protocol.elicitation_adapter import ElicitationBackendError
        assert issubclass(ElicitationBackendError, RuntimeError)


class TestModuleImportsClean:
    """Architectural-arrow invariant — protocol/elicitation_adapter must NOT
    import portal/, fastapi/starlette/sse_starlette, or core/."""

    def test_no_forbidden_imports(self) -> None:
        src = Path("src/cognic_agentos/protocol/elicitation_adapter.py").read_text()
        tree = ast.parse(src)
        forbidden_roots = {"fastapi", "starlette", "sse_starlette"}
        forbidden_prefixes = ("cognic_agentos.portal", "cognic_agentos.protocol.mcp_host")
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                mod = node.module or ""
                root = mod.split(".")[0]
                assert root not in forbidden_roots, f"forbidden import: {mod}"
                assert not any(mod.startswith(p) for p in forbidden_prefixes), \
                    f"forbidden import: {mod}"
            elif isinstance(node, ast.Import):
                for n in node.names:
                    root = n.name.split(".")[0]
                    assert root not in forbidden_roots, f"forbidden import: {n.name}"
```

- [ ] **Step 2:** Run → verify FAIL.

```bash
uv run pytest tests/unit/protocol/test_elicitation_adapter.py -v
# Expected: ImportError on elicitation_adapter module
```

- [ ] **Step 3:** Implement `src/cognic_agentos/protocol/elicitation_adapter.py`:

```python
"""Sprint-7B.4 T7 — ElicitationAdapter Protocol + KernelDefault fail-loud scaffold.

Per ADR-020 §69-77 + the production-grade rule: the kernel-shipped
default adapter raises NotImplementedError pointing at the ADR rather
than returning a synthetic result. Bank overlays plug in real adapter
implementations against this Protocol.

Architectural arrow: this module is FastAPI-free + portal-free + core-free.
Pinned by tests/unit/protocol/test_elicitation_adapter.py::TestModuleImportsClean.
"""
from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime
from typing import Any, Literal, Protocol, runtime_checkable

__all__ = [
    "ElicitationMode",
    "ElicitationContext",
    "ElicitationResult",
    "ElicitationBackendError",
    "ElicitationAdapter",
    "KernelDefaultElicitationAdapter",
]


ElicitationMode = Literal["url", "form"]


@dataclasses.dataclass(frozen=True)
class ElicitationContext:
    """Tenant-scoped context for an in-flight elicitation, resolved by the
    adapter at gate step 2 (Section 5b of the design spec)."""
    elicitation_id: str
    tenant_id: str
    originating_pack_id: str
    originating_decision_record_id: uuid.UUID
    elicitation_modes: tuple[ElicitationMode, ...]
    data_classes: tuple[str, ...]
    expires_at: datetime | None


@dataclasses.dataclass(frozen=True)
class ElicitationResult:
    """Returned by ElicitationAdapter.handle_submission on the green path."""
    delivered_at: datetime
    backend_correlation_id: str | None


class ElicitationBackendError(RuntimeError):
    """Raised by ElicitationAdapter.handle_submission when the backend
    rejected the payload AFTER the gate passed. Maps to the
    elicitation_backend_failed ActionRejectionReason at T11's action handler."""


@runtime_checkable
class ElicitationAdapter(Protocol):
    """Narrow elicitation seam — bank overlays plug in a concrete adapter
    against this Protocol; AgentOS ships the fail-loud KernelDefault
    scaffold below."""

    async def get_context(
        self, *, elicitation_id: str, tenant_id: str,
    ) -> ElicitationContext | None:
        ...

    async def handle_submission(
        self, *, ctx: ElicitationContext, mode: ElicitationMode,
        payload: dict[str, Any],
    ) -> ElicitationResult:
        ...


class KernelDefaultElicitationAdapter:
    """Production-grade fail-loud scaffold per ADR-020 §69 + the AGENTS.md
    production-grade rule (no silent in-process fallback). Mirrors the
    7B.3 T9 KernelDefaultTrustRootResolver precedent."""

    async def get_context(
        self, *, elicitation_id: str, tenant_id: str,
    ) -> ElicitationContext | None:
        raise NotImplementedError(
            "ADR-020 §69 elicitation adapter is not wired; the kernel "
            "default fails closed. Bank overlays plug in a concrete "
            "ElicitationAdapter against this Protocol."
        )

    async def handle_submission(
        self, *, ctx: ElicitationContext, mode: ElicitationMode,
        payload: dict[str, Any],
    ) -> ElicitationResult:
        raise NotImplementedError(
            "ADR-020 §69 elicitation adapter is not wired; the kernel "
            "default fails closed."
        )
```

- [ ] **Step 4:** Run tests → verify PASS.

```bash
uv run pytest tests/unit/protocol/test_elicitation_adapter.py -v
# Expected: 9 passed (2-value Literal + 2 frozen dataclasses + 2 Protocol shape + 2 kernel-default raises + 1 ElicitationBackendError + 1 imports clean)
```

- [ ] **Step 5:** ruff/format/mypy clean on the new module + test.

```bash
uv run ruff check src/cognic_agentos/protocol/elicitation_adapter.py \
                  tests/unit/protocol/test_elicitation_adapter.py
uv run ruff format src/cognic_agentos/protocol/elicitation_adapter.py \
                   tests/unit/protocol/test_elicitation_adapter.py
uv run mypy src tests
```

- [ ] **Step 6:** Commit.

```bash
git add src/cognic_agentos/protocol/elicitation_adapter.py \
        tests/unit/protocol/test_elicitation_adapter.py
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -F - <<'EOF'
feat(sprint-7b4): T7 — ElicitationAdapter Protocol + KernelDefault fail-loud scaffold

- protocol/elicitation_adapter.py (NEW, NOT-CC): 2-value ElicitationMode Literal,
  frozen ElicitationContext + ElicitationResult dataclasses, ElicitationBackendError
  exception, @runtime_checkable ElicitationAdapter Protocol, KernelDefault scaffold
  whose both methods raise NotImplementedError pointing at ADR-020 §69 per the
  AGENTS.md production-grade rule (no silent fallback)
- 9 regressions: Literal arity, frozen dataclasses + field sets, Protocol
  structural shape + isinstance behavior, kernel-default ADR-pointing raises,
  ElicitationBackendError inheritance, module-imports-clean AST scan
- Mirrors Sprint 7B.3 T9 KernelDefaultTrustRootResolver precedent for the
  Protocol + fail-loud-scaffold pattern; becomes CC when a real adapter lands

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
```

---

## T8 — elicitation.rego + elicitation_gate.py (5-step gate)

**Files:**
- Create: `policies/_default/elicitation.rego` (Rego v1 syntax)
- Create: `src/cognic_agentos/portal/api/ui/__init__.py`
- Create: `src/cognic_agentos/portal/api/ui/elicitation_gate.py`
- Create: `tests/unit/portal/api/ui/test_elicitation_gate.py`
- Create: `tests/unit/policies/__init__.py`
- Create: `tests/unit/policies/test_elicitation_rego.py`

**CC classification:** **CC** for `elicitation_gate.py` (policy boundary; precedent: 7B.3 T7 `packs/approval_gates.py`); **Stop-rule** for the Rego bundle. **Halt-before-commit:** YES.

**Acceptance:**
- `policies/_default/elicitation.rego` per spec §5c — Rego v1 syntax (`allow if { ... }`).
- `evaluate_elicitation_submission(*, request, actor, adapter, rego_engine) -> GateOutcome` per spec §5b — 5 numbered steps + 10 fail-closed reasons + green-path.
- `_RESTRICTED_DATA_CLASSES: Final[frozenset[str]] = frozenset({"customer_pii", "payment_action", "regulator_communication"})`.
- Three-way drift detector `TestRestrictedClassesThreeWayLockstep` (Python + Rego + canonical).
- Direct OPA test `tests/unit/policies/test_elicitation_rego.py` marked `@pytest.mark.opa_required`.

**Steps:**

- [ ] **Step 1:** Create `policies/_default/elicitation.rego` with Rego v1 syntax (matches `supply_chain.rego` precedent):

```rego
# policies/_default/elicitation.rego
# Sprint-7B.4 T8 — ADR-020 §69-77 + ADR-015 default-deny.

package cognic.ui.elicitation_submit

default allow := false

allow if {
    input.mode == "url"
}

allow if {
    input.mode == "form"
    not has_restricted_class
}

restricted_classes := {"customer_pii", "payment_action", "regulator_communication"}

has_restricted_class if {
    some c in input.data_classes
    restricted_classes[c]
}
```

- [ ] **Step 2:** Write failing gate tests at `tests/unit/portal/api/ui/test_elicitation_gate.py`:

```python
"""Sprint 7B.4 T8 — evaluate_elicitation_submission 5-step gate matrix."""
import dataclasses                           # R4 #5: needed for dataclasses.replace in tests
import pytest
from unittest.mock import AsyncMock
from cognic_agentos.portal.api.ui.elicitation_gate import (
    evaluate_elicitation_submission, GateOutcome, _RESTRICTED_DATA_CLASSES,
)
from cognic_agentos.protocol.elicitation_adapter import (
    ElicitationAdapter, ElicitationContext, KernelDefaultElicitationAdapter,
)


@pytest.fixture
def url_request():
    from cognic_agentos.portal.api.ui.dto import SubmitElicitationActionRequest
    return SubmitElicitationActionRequest(
        elicitation_id="elc_1", mode="url",
        url_completion_signal={"ok": True}, form_payload=None,
    )


@pytest.fixture
def form_request():
    from cognic_agentos.portal.api.ui.dto import SubmitElicitationActionRequest
    return SubmitElicitationActionRequest(
        elicitation_id="elc_1", mode="form",
        url_completion_signal=None, form_payload={"answer": "42"},
    )


@pytest.fixture
def safe_ctx():
    import uuid
    return ElicitationContext(
        elicitation_id="elc_1", tenant_id="t1",
        originating_pack_id="pkg_1", originating_decision_record_id=uuid.uuid4(),
        elicitation_modes=("url", "form"), data_classes=("public",), expires_at=None,
    )


class TestGateStep1AdapterUnwired:
    @pytest.mark.asyncio
    async def test_adapter_None_returns_backend_unwired(self, url_request, actor):
        outcome = await evaluate_elicitation_submission(
            request=url_request, actor=actor, adapter=None, rego_engine=AsyncMock(),
        )
        assert outcome.allowed is False
        assert outcome.reason == "elicitation_backend_unwired"
        assert outcome.ctx is None


class TestGateStep1KernelDefaultAdapter:
    @pytest.mark.asyncio
    async def test_kernel_default_raises_NotImplemented_returns_backend_unwired(
        self, url_request, actor,
    ):
        outcome = await evaluate_elicitation_submission(
            request=url_request, actor=actor,
            adapter=KernelDefaultElicitationAdapter(), rego_engine=AsyncMock(),
        )
        assert outcome.reason == "elicitation_backend_unwired"


class TestGateStep2UnknownId:
    @pytest.mark.asyncio
    async def test_get_context_returns_None_yields_unknown_id(self, url_request, actor):
        adapter = AsyncMock(spec=ElicitationAdapter)
        adapter.get_context = AsyncMock(return_value=None)
        outcome = await evaluate_elicitation_submission(
            request=url_request, actor=actor, adapter=adapter, rego_engine=AsyncMock(),
        )
        assert outcome.reason == "elicitation_unknown_id"


class TestGateStep3ModeParityBothModes:
    @pytest.mark.asyncio
    async def test_form_mode_rejected_when_manifest_url_only(
        self, form_request, actor, safe_ctx,
    ):
        ctx = dataclasses.replace(safe_ctx, elicitation_modes=("url",))
        adapter = AsyncMock(); adapter.get_context = AsyncMock(return_value=ctx)
        outcome = await evaluate_elicitation_submission(
            request=form_request, actor=actor, adapter=adapter, rego_engine=AsyncMock(),
        )
        assert outcome.reason == "elicitation_mode_not_permitted"

    @pytest.mark.asyncio
    async def test_url_mode_rejected_when_manifest_form_only(
        self, url_request, actor, safe_ctx,
    ):
        # P1 from Section 5 review: mode parity applies to BOTH modes
        ctx = dataclasses.replace(safe_ctx, elicitation_modes=("form",))
        adapter = AsyncMock(); adapter.get_context = AsyncMock(return_value=ctx)
        outcome = await evaluate_elicitation_submission(
            request=url_request, actor=actor, adapter=adapter, rego_engine=AsyncMock(),
        )
        assert outcome.reason == "elicitation_mode_not_permitted"


class TestGateStep4RestrictedDataClass:
    @pytest.mark.parametrize("restricted", list(_RESTRICTED_DATA_CLASSES))
    @pytest.mark.asyncio
    async def test_form_mode_rejected_on_restricted_class(
        self, form_request, actor, safe_ctx, restricted,
    ):
        ctx = dataclasses.replace(safe_ctx, data_classes=(restricted,))
        adapter = AsyncMock(); adapter.get_context = AsyncMock(return_value=ctx)
        outcome = await evaluate_elicitation_submission(
            request=form_request, actor=actor, adapter=adapter, rego_engine=AsyncMock(),
        )
        assert outcome.reason == "elicitation_restricted_data_class"


class TestGateStep5RegoEngineUnwired:
    @pytest.mark.asyncio
    async def test_rego_None_yields_unwired_evaluator(
        self, url_request, actor, safe_ctx,
    ):
        adapter = AsyncMock(); adapter.get_context = AsyncMock(return_value=safe_ctx)
        outcome = await evaluate_elicitation_submission(
            request=url_request, actor=actor, adapter=adapter, rego_engine=None,
        )
        assert outcome.reason == "elicitation_unwired_evaluator"


class TestGateStep5OpaMissing:
    @pytest.mark.asyncio
    async def test_OpaNotInstalledError_yields_unwired_evaluator(
        self, url_request, actor, safe_ctx,
    ):
        from cognic_agentos.core.policy.engine import OpaNotInstalledError
        adapter = AsyncMock(); adapter.get_context = AsyncMock(return_value=safe_ctx)
        rego = AsyncMock(); rego.evaluate = AsyncMock(side_effect=OpaNotInstalledError("no opa"))
        outcome = await evaluate_elicitation_submission(
            request=url_request, actor=actor, adapter=adapter, rego_engine=rego,
        )
        assert outcome.reason == "elicitation_unwired_evaluator"


class TestGateStep5RegoDeny:
    @pytest.mark.asyncio
    async def test_rego_decision_allow_False_yields_rego_denied(
        self, form_request, actor, safe_ctx,
    ):
        from cognic_agentos.core.policy.engine import Decision
        adapter = AsyncMock(); adapter.get_context = AsyncMock(return_value=safe_ctx)
        rego = AsyncMock()
        rego.evaluate = AsyncMock(return_value=Decision(allow=False, rule_matched="...", reasoning="", decision_data=None))
        outcome = await evaluate_elicitation_submission(
            request=form_request, actor=actor, adapter=adapter, rego_engine=rego,
        )
        assert outcome.reason == "elicitation_rego_denied"


class TestGateGreenPath:
    @pytest.mark.asyncio
    async def test_all_green_returns_allowed_True_with_ctx(
        self, url_request, actor, safe_ctx,
    ):
        from cognic_agentos.core.policy.engine import Decision
        adapter = AsyncMock(); adapter.get_context = AsyncMock(return_value=safe_ctx)
        rego = AsyncMock()
        rego.evaluate = AsyncMock(return_value=Decision(allow=True, rule_matched="...", reasoning="", decision_data=None))
        outcome = await evaluate_elicitation_submission(
            request=url_request, actor=actor, adapter=adapter, rego_engine=rego,
        )
        assert outcome.allowed is True
        assert outcome.reason is None
        assert outcome.ctx is safe_ctx


class TestRegoDecisionPointFormat:
    @pytest.mark.asyncio
    async def test_decision_point_is_full_rego_query_string(
        self, url_request, actor, safe_ctx,
    ):
        from cognic_agentos.core.policy.engine import Decision
        adapter = AsyncMock(); adapter.get_context = AsyncMock(return_value=safe_ctx)
        rego = AsyncMock()
        rego.evaluate = AsyncMock(return_value=Decision(allow=True, rule_matched="...", reasoning="", decision_data=None))
        await evaluate_elicitation_submission(
            request=url_request, actor=actor, adapter=adapter, rego_engine=rego,
        )
        assert rego.evaluate.await_args.kwargs["decision_point"] == "data.cognic.ui.elicitation_submit.allow"


class TestRestrictedClassesThreeWayLockstep:
    """Three-way drift detector per spec §5d."""

    def test_python_constant_matches_canonical(self):
        from cognic_agentos.cli._governance_vocab import RestrictedDataClass
        from typing import get_args
        assert set(_RESTRICTED_DATA_CLASSES) == set(get_args(RestrictedDataClass))

    def test_rego_bundle_set_matches_python(self):
        from pathlib import Path
        rego_text = Path("policies/_default/elicitation.rego").read_text()
        # Parse restricted_classes := { ... }
        import re
        m = re.search(r'restricted_classes := \{([^}]+)\}', rego_text)
        assert m is not None
        rego_set = frozenset(s.strip().strip('"') for s in m.group(1).split(","))
        assert rego_set == _RESTRICTED_DATA_CLASSES
```

- [ ] **Step 3:** Run → verify FAIL on `elicitation_gate` import.

```bash
uv run pytest tests/unit/portal/api/ui/test_elicitation_gate.py -v
# Expected: ImportError on evaluate_elicitation_submission / GateOutcome
```

- [ ] **Step 4:** Implement `src/cognic_agentos/portal/api/ui/elicitation_gate.py`:

```python
"""Sprint-7B.4 T8 — submit_elicitation 5-step gate per ADR-020 §69-77."""
from __future__ import annotations
import dataclasses
import logging
from typing import Literal
from cognic_agentos.protocol.elicitation_adapter import ElicitationAdapter, ElicitationContext
from cognic_agentos.core.policy.engine import (
    OPAEngine, OpaNotInstalledError, RegoBundleNotFoundError,
    RegoBundleInvalidError, RegoEvaluationError,
)

_LOG = logging.getLogger(__name__)

#: Inlined from cli/_governance_vocab.RestrictedDataClass per the R45 architectural-arrow
#: doctrine (cli → packs/portal arrow forbids reverse import). Three-way drift detector
#: at test_elicitation_gate.py::TestRestrictedClassesThreeWayLockstep enforces equality
#: across this Python constant, the Rego bundle, and the canonical Literal.
_RESTRICTED_DATA_CLASSES: frozenset[str] = frozenset({
    "customer_pii", "payment_action", "regulator_communication",
})

ActionRejectionReason = Literal[
    "action_backend_deferred_to_sprint_13_5",
    "action_backend_deferred_no_run_primitive",
    "action_backend_deferred_sandbox_unwired",
    "elicitation_mode_not_permitted",
    "elicitation_restricted_data_class",
    "elicitation_rego_denied",
    "elicitation_unwired_evaluator",
    "elicitation_backend_failed",
    "elicitation_backend_unwired",
    "elicitation_unknown_id",
]


@dataclasses.dataclass(frozen=True)
class GateOutcome:
    allowed: bool
    reason: ActionRejectionReason | None
    ctx: ElicitationContext | None


async def evaluate_elicitation_submission(
    *,
    request,
    actor,
    adapter: ElicitationAdapter | None,
    rego_engine: OPAEngine | None,
) -> GateOutcome:
    # Step 1 — adapter wired?
    if adapter is None:
        return GateOutcome(False, "elicitation_backend_unwired", None)

    # Step 2 — context lookup (tenant-scoped)
    try:
        ctx = await adapter.get_context(
            elicitation_id=request.elicitation_id, tenant_id=actor.tenant_id,
        )
    except NotImplementedError:
        return GateOutcome(False, "elicitation_backend_unwired", None)
    if ctx is None:
        return GateOutcome(False, "elicitation_unknown_id", None)

    # Step 3 — mode parity (BOTH modes — per spec §5b)
    if request.mode not in ctx.elicitation_modes:
        return GateOutcome(False, "elicitation_mode_not_permitted", ctx)

    # Step 4 — restricted-data-class refusal (form-mode only)
    if request.mode == "form" and _RESTRICTED_DATA_CLASSES.intersection(ctx.data_classes):
        return GateOutcome(False, "elicitation_restricted_data_class", ctx)

    # Step 5 — Rego eval
    if rego_engine is None:
        return GateOutcome(False, "elicitation_unwired_evaluator", ctx)
    try:
        decision = await rego_engine.evaluate(
            decision_point="data.cognic.ui.elicitation_submit.allow",
            input={
                "tenant_id": actor.tenant_id,
                "elicitation_id": request.elicitation_id,
                "originating_pack_id": ctx.originating_pack_id,
                "mode": request.mode,
                "data_classes": list(ctx.data_classes),
                "has_form_payload": request.form_payload is not None,
            },
        )
    except OpaNotInstalledError:
        return GateOutcome(False, "elicitation_unwired_evaluator", ctx)
    except (RegoBundleNotFoundError, RegoBundleInvalidError, RegoEvaluationError):
        _LOG.error("ui.elicitation.rego_evaluation_failed", exc_info=True)
        return GateOutcome(False, "elicitation_rego_denied", ctx)

    if not decision.allow:
        return GateOutcome(False, "elicitation_rego_denied", ctx)
    return GateOutcome(True, None, ctx)
```

- [ ] **Step 5:** Run gate tests → verify PASS.

```bash
uv run pytest tests/unit/portal/api/ui/test_elicitation_gate.py -v
# Expected: 12+ passed
```

- [ ] **Step 6:** Write the direct-OPA test at `tests/unit/policies/test_elicitation_rego.py`:

```python
"""Sprint 7B.4 T8 — direct OPA invocation against policies/_default/elicitation.rego."""
import pytest
import shutil
from pathlib import Path
from cognic_agentos.core.policy.engine import OPAEngine

opa_required = pytest.mark.skipif(
    shutil.which("opa") is None, reason="opa binary not installed"
)


@pytest.fixture
async def engine(tmp_path):
    """Build a real OPAEngine over an in-memory SQLite audit + decision_history.

    R4 #2: mirrors `tests/unit/core/policy/conftest.py` exactly — the verified
    `_chain_heads` columns are `chain_id` + `latest_sequence` + `latest_hash` +
    `updated_at` (NOT `last_hash` / `last_sequence`). Uses `ZERO_HASH` from
    `core.canonical` for the initial chain-head value. Per Sprint-4 T15 + Sprint-5 T6
    precedent."""
    from datetime import UTC, datetime
    from sqlalchemy.ext.asyncio import create_async_engine
    from cognic_agentos.core.audit import AuditStore, _chain_heads, _metadata
    from cognic_agentos.core.canonical import ZERO_HASH
    from cognic_agentos.core.decision_history import DecisionHistoryStore

    url = f"sqlite+aiosqlite:///{tmp_path / 'elicitation_rego_test.db'}"
    sa_engine = create_async_engine(url)
    async with sa_engine.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        # Seed both chain heads with the canonical columns (R4 #2 fix)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="decision_history",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
    audit = AuditStore(sa_engine)
    dh = DecisionHistoryStore(sa_engine)
    yield OPAEngine(
        bundle_path=Path("policies/_default/elicitation.rego"),
        audit_store=audit,
        decision_history_store=dh,
    )
    await sa_engine.dispose()


@opa_required
class TestRegoDefaultDeny:
    @pytest.mark.asyncio
    async def test_url_mode_with_clean_classes_allows(self, engine):
        d = await engine.evaluate(
            decision_point="data.cognic.ui.elicitation_submit.allow",
            input={"mode": "url", "data_classes": ["public"]},
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_url_mode_with_restricted_class_still_allows(self, engine):
        # URL completion is safe regardless of data classes
        d = await engine.evaluate(
            decision_point="data.cognic.ui.elicitation_submit.allow",
            input={"mode": "url", "data_classes": ["customer_pii"]},
        )
        assert d.allow is True

    @pytest.mark.asyncio
    async def test_form_mode_with_clean_classes_allows(self, engine):
        d = await engine.evaluate(
            decision_point="data.cognic.ui.elicitation_submit.allow",
            input={"mode": "form", "data_classes": ["public", "internal"]},
        )
        assert d.allow is True

    @pytest.mark.parametrize("restricted", ["customer_pii", "payment_action", "regulator_communication"])
    @pytest.mark.asyncio
    async def test_form_mode_with_restricted_class_denies(self, engine, restricted):
        d = await engine.evaluate(
            decision_point="data.cognic.ui.elicitation_submit.allow",
            input={"mode": "form", "data_classes": [restricted]},
        )
        assert d.allow is False
```

- [ ] **Step 7:** Run direct-OPA test (skip without OPA, PASS with OPA installed).

```bash
uv run pytest tests/unit/policies/test_elicitation_rego.py -v
# Expected: skipped (or passed if opa is installed)
```

- [ ] **Step 8:** Run full slice → verify PASS.

```bash
uv run pytest tests/unit/portal/api/ui/test_elicitation_gate.py tests/unit/policies/test_elicitation_rego.py -v
```

- [ ] **Step 9:** Halt-before-commit summary (CC + stop-rule) + commit.

```bash
git add policies/_default/elicitation.rego \
        src/cognic_agentos/portal/api/ui/__init__.py \
        src/cognic_agentos/portal/api/ui/elicitation_gate.py \
        tests/unit/portal/api/ui/test_elicitation_gate.py \
        tests/unit/policies/__init__.py \
        tests/unit/policies/test_elicitation_rego.py
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -F - <<'EOF'
feat(sprint-7b4): T8 — elicitation_gate.py + elicitation.rego (CRITICAL CONTROLS + stop-rule)

- policies/_default/elicitation.rego: Rego v1 syntax, default-deny form-mode
  on restricted data classes per ADR-020 §69-77 + ADR-015. Stop-rule artifact.
- portal/api/ui/elicitation_gate.py: pure-async 5-step gate per spec §5b
  (adapter wired? → ctx lookup → mode parity (both modes per P1) → restricted
  data class → Rego eval at data.cognic.ui.elicitation_submit.allow); 10
  fail-closed reasons; CC promotion (substantive policy boundary)
- Three-way drift detector pins _RESTRICTED_DATA_CLASSES across Python /
  Rego / cli/_governance_vocab canonical
- Direct OPA test @pytest.mark.opa_required; skips without opa installed

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
```

---

## T9 — portal/api/ui/dto.py (Action DTOs + Literals — pure type-only)

**Files:**
- Create: `src/cognic_agentos/portal/api/ui/dto.py`
- Create: `tests/unit/portal/api/ui/__init__.py`
- Create: `tests/unit/portal/api/ui/test_dto_action.py`

**CC classification:** NOT-CC (type-only; mirrors `portal/api/packs/dto.py`). **Halt-before-commit:** NO.

**P1 #2 SCOPE LOCK:** `RequireUIAction` is **NOT** in this task. The locked spec keeps DTOs pure type-only. `RequireUIAction` is FastAPI/RBAC/broker-coupled and lives in `action_routes.py` (T11). Placing it in `dto.py` would drag route/runtime dependencies into the DTO module and break the NOT-CC classification.

**Acceptance:**
- `ActionClass` 6-value Literal · `ActionOutcome` 2-value · `ActionRejectionReason` 10-value (matches the elicitation_gate.py Literal from T8 — pinned by a disjointness test in `test_dto_action.py`).
- 6 per-class request DTOs + `ActionRequest` discriminated union per spec §4.4a.
- `SubmitElicitationActionRequest` has `@model_validator(mode="after")` enforcing payload/mode parity per the P2 lock in the spec (`form` requires `form_payload` + rejects `url_completion_signal`; `url` symmetric). Rejection at Pydantic-parse → 422 → NO chain row.
- `ActionResponse` shape per spec §4.4a (`request_id`, `action_class`, `outcome`, `reason`, `submitted_at`, `submitted_event_id`, `resolution_event_id`, `client_correlation_id`).
- `UIActionContext` frozen dataclass = (`body`, `actor`, `request_id`) — declared HERE because T11's `RequireUIAction` needs to return it. The dataclass is type-only (no FastAPI/broker imports).
- Closed-enum count + disjointness regressions: `ActionClass`==6, `ActionOutcome`==2, `ActionRejectionReason`==10; `ActionRejectionReason` disjoint from `RBACDenialType` (T3) + `RejectionReason` (7B.2 T5).

**Steps:**

- [ ] **Step 1:** Write failing tests at `tests/unit/portal/api/ui/test_dto_action.py`:

```python
"""Sprint 7B.4 T9 — Action DTOs + Literals + model_validator parity."""
import pytest
import pydantic
from typing import get_args
from cognic_agentos.portal.api.ui.dto import (
    ActionClass, ActionOutcome, ActionRejectionReason,
    ApproveActionRequest, DenyActionRequest, CancelRunActionRequest,
    InterruptActionRequest, ResumeActionRequest, SubmitElicitationActionRequest,
    ActionRequest, ActionResponse, UIActionContext,
)
from cognic_agentos.protocol.ui_events import RBACDenialType


class TestActionClassLiteral:
    def test_count_is_6(self):
        assert len(get_args(ActionClass)) == 6

    def test_values(self):
        assert set(get_args(ActionClass)) == {
            "approve", "deny", "cancel_run", "interrupt", "resume", "submit_elicitation",
        }


class TestActionRejectionReasonLiteral:
    def test_count_is_10(self):
        assert len(get_args(ActionRejectionReason)) == 10

    def test_disjoint_from_rbac_denial_type(self):
        assert set(get_args(ActionRejectionReason)).isdisjoint(set(get_args(RBACDenialType)))

    def test_disjoint_from_pack_rejection_reason(self):
        from cognic_agentos.portal.api.packs.dto import RejectionReason
        assert set(get_args(ActionRejectionReason)).isdisjoint(set(get_args(RejectionReason)))


class TestActionOutcomeLiteral:
    def test_count_is_2(self):
        assert len(get_args(ActionOutcome)) == 2
        assert set(get_args(ActionOutcome)) == {"accepted", "rejected"}


class TestDiscriminatedUnion:
    def test_approve_parses(self):
        body = pydantic.TypeAdapter(ActionRequest).validate_python({
            "action_class": "approve", "approval_id": "ap_1", "decision": "grant",
        })
        assert isinstance(body, ApproveActionRequest)
        assert body.approval_id == "ap_1"

    def test_unknown_action_class_422_at_parse(self):
        with pytest.raises(pydantic.ValidationError):
            pydantic.TypeAdapter(ActionRequest).validate_python({
                "action_class": "frobnicate",
            })


class TestSubmitElicitationPayloadModeParity:
    """P2 lock from spec — exact mode/payload parity at Pydantic parse."""

    def test_form_mode_without_form_payload_rejected(self):
        with pytest.raises(pydantic.ValidationError, match="form.*requires.*form_payload"):
            SubmitElicitationActionRequest(
                elicitation_id="elc_1", mode="form",
                form_payload=None, url_completion_signal=None,
            )

    def test_form_mode_with_url_signal_rejected(self):
        with pytest.raises(pydantic.ValidationError, match="must not include url_completion_signal"):
            SubmitElicitationActionRequest(
                elicitation_id="elc_1", mode="form",
                form_payload={"a": 1}, url_completion_signal={"x": True},
            )

    def test_url_mode_without_completion_signal_rejected(self):
        with pytest.raises(pydantic.ValidationError, match="url.*requires.*url_completion_signal"):
            SubmitElicitationActionRequest(
                elicitation_id="elc_1", mode="url",
                form_payload=None, url_completion_signal=None,
            )

    def test_url_mode_with_form_payload_rejected(self):
        with pytest.raises(pydantic.ValidationError, match="must not include form_payload"):
            SubmitElicitationActionRequest(
                elicitation_id="elc_1", mode="url",
                form_payload={"a": 1}, url_completion_signal={"x": True},
            )

    def test_form_mode_with_form_payload_parses(self):
        body = SubmitElicitationActionRequest(
            elicitation_id="elc_1", mode="form",
            form_payload={"a": 1}, url_completion_signal=None,
        )
        assert body.mode == "form"

    def test_url_mode_with_completion_signal_parses(self):
        body = SubmitElicitationActionRequest(
            elicitation_id="elc_1", mode="url",
            form_payload=None, url_completion_signal={"x": True},
        )
        assert body.mode == "url"


class TestUIActionContextFrozen:
    def test_construction(self, actor):
        body = ApproveActionRequest(approval_id="ap_1", decision="grant")
        ctx = UIActionContext(body=body, actor=actor, request_id="portal-req-abc")
        assert ctx.request_id == "portal-req-abc"

    def test_frozen(self, actor):
        body = ApproveActionRequest(approval_id="ap_1", decision="grant")
        ctx = UIActionContext(body=body, actor=actor, request_id="portal-req-abc")
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.request_id = "other"


class TestDTOModuleHasNoRuntimeImports:
    """P1 #2 — dto.py is type-only; NO FastAPI / broker / RBAC dep injection."""

    def test_no_fastapi_imports(self):
        import ast
        from pathlib import Path
        src = Path("src/cognic_agentos/portal/api/ui/dto.py").read_text()
        tree = ast.parse(src)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imports.append(node.module or "")
            elif isinstance(node, ast.Import):
                imports.extend(n.name for n in node.names)
        # dto.py must not depend on fastapi / starlette / sse_starlette /
        # broker primitives — those belong to action_routes.py
        forbidden = {"fastapi", "starlette", "sse_starlette",
                     "cognic_agentos.protocol.ui_events"}
        for imp in imports:
            base = imp.split(".")[0] if imp else ""
            assert imp not in forbidden, f"dto.py must not import {imp}"
            # Allow fastapi.Body / typing for OpenAPI shape, but NOT broker types
```

- [ ] **Step 2:** Run → verify FAIL.

```bash
uv run pytest tests/unit/portal/api/ui/test_dto_action.py -v
# Expected: ImportError on dto module
```

- [ ] **Step 3:** Implement `src/cognic_agentos/portal/api/ui/dto.py`:

```python
"""Sprint-7B.4 T9 — Action DTOs + Literals (pure type-only, no FastAPI deps)."""
from __future__ import annotations
import dataclasses
from datetime import datetime
from typing import Annotated, Any, Literal, TYPE_CHECKING
import pydantic
from pydantic import Field, model_validator

if TYPE_CHECKING:
    # Forward-only — does NOT import at runtime.
    from cognic_agentos.portal.rbac.actor import Actor

ActionClass = Literal[
    "approve", "deny", "cancel_run", "interrupt", "resume", "submit_elicitation",
]

ActionOutcome = Literal["accepted", "rejected"]

ActionRejectionReason = Literal[
    "action_backend_deferred_to_sprint_13_5",
    "action_backend_deferred_no_run_primitive",
    "action_backend_deferred_sandbox_unwired",
    "elicitation_mode_not_permitted",
    "elicitation_restricted_data_class",
    "elicitation_rego_denied",
    "elicitation_unwired_evaluator",
    "elicitation_backend_failed",
    "elicitation_backend_unwired",
    "elicitation_unknown_id",
]


class PackBaseModel(pydantic.BaseModel):
    """Frozen + extra=forbid base for all UI DTOs (mirrors portal/api/packs/dto.py)."""
    model_config = pydantic.ConfigDict(frozen=True, extra="forbid")


class _BaseActionRequest(PackBaseModel):
    action_class: ActionClass
    client_correlation_id: str | None = Field(default=None, max_length=64)


class ApproveActionRequest(_BaseActionRequest):
    action_class: Literal["approve"] = "approve"
    approval_id: str
    decision: Literal["grant", "grant_second"]


class DenyActionRequest(_BaseActionRequest):
    action_class: Literal["deny"] = "deny"
    approval_id: str
    reason: str | None = None


class CancelRunActionRequest(_BaseActionRequest):
    action_class: Literal["cancel_run"] = "cancel_run"
    run_id: str
    reason: str | None = None


class InterruptActionRequest(_BaseActionRequest):
    action_class: Literal["interrupt"] = "interrupt"
    run_id: str
    message_to_agent: str | None = None


class ResumeActionRequest(_BaseActionRequest):
    action_class: Literal["resume"] = "resume"
    run_id: str
    payload: dict[str, Any] | None = None


class SubmitElicitationActionRequest(_BaseActionRequest):
    action_class: Literal["submit_elicitation"] = "submit_elicitation"
    elicitation_id: str
    mode: Literal["url", "form"]
    url_completion_signal: dict[str, Any] | None = None
    form_payload: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _enforce_payload_matches_mode(self) -> "SubmitElicitationActionRequest":
        """P2 LOCK from spec — exact mode/payload parity at Pydantic-parse time → 422.
        Rejects ill-formed requests BEFORE any chain row is appended."""
        if self.mode == "form":
            if self.form_payload is None:
                raise ValueError("mode='form' requires form_payload")
            if self.url_completion_signal is not None:
                raise ValueError("mode='form' must not include url_completion_signal")
        else:  # mode == "url"
            if self.url_completion_signal is None:
                raise ValueError("mode='url' requires url_completion_signal")
            if self.form_payload is not None:
                raise ValueError("mode='url' must not include form_payload")
        return self


ActionRequest = Annotated[
    ApproveActionRequest | DenyActionRequest | CancelRunActionRequest
    | InterruptActionRequest | ResumeActionRequest | SubmitElicitationActionRequest,
    Field(discriminator="action_class"),
]


class ActionResponse(PackBaseModel):
    request_id: str
    action_class: ActionClass
    outcome: ActionOutcome
    reason: ActionRejectionReason | None
    submitted_at: datetime
    submitted_event_id: str
    resolution_event_id: str | None
    client_correlation_id: str | None


@dataclasses.dataclass(frozen=True)
class UIActionContext:
    """Returned by T11's RequireUIAction dependency. Type-only — no FastAPI imports."""
    body: ActionRequest
    actor: "Actor"
    request_id: str
```

- [ ] **Step 4:** Run tests → verify PASS.

```bash
uv run pytest tests/unit/portal/api/ui/test_dto_action.py -v
# Expected: 14+ passed
```

- [ ] **Step 5:** ruff/format/mypy clean on the new files; commit.

```bash
uv run ruff check src/cognic_agentos/portal/api/ui/dto.py tests/unit/portal/api/ui/
uv run ruff format src/cognic_agentos/portal/api/ui/dto.py tests/unit/portal/api/ui/
git add src/cognic_agentos/portal/api/ui/__init__.py \
        src/cognic_agentos/portal/api/ui/dto.py \
        tests/unit/portal/api/ui/__init__.py \
        tests/unit/portal/api/ui/test_dto_action.py
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -F - <<'EOF'
feat(sprint-7b4): T9 — portal/api/ui/dto.py: action DTOs + closed enums (pure type-only)

- 6-class discriminated-union request shape; mode/payload parity via
  @model_validator on SubmitElicitationActionRequest (P2 lock — 422 at parse,
  no chain row written for ill-formed requests)
- 3 closed-enum Literals: ActionClass (6) + ActionOutcome (2) +
  ActionRejectionReason (10); disjointness from RBACDenialType + RejectionReason
- UIActionContext frozen dataclass declared here for T11's RequireUIAction
  to return (type-only; no FastAPI imports)
- AST regression pins dto.py free of FastAPI / broker imports — RequireUIAction
  lives in action_routes.py (T11), NOT here (P1 #2 scope lock)

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
```

---

## T10 — stream_routes.py (3 SSE endpoints + Last-Event-ID + headers + send_timeout)

**Files:**
- Create: `src/cognic_agentos/portal/api/ui/stream_routes.py`
- Create: `tests/unit/portal/api/ui/test_stream_routes.py`
- Create: `tests/unit/portal/api/ui/test_stream_routes_last_event_id.py`
- Create: `tests/unit/portal/api/ui/test_stream_routes_reconnect.py`
- Create: `tests/unit/portal/api/ui/test_stream_headers_and_timeout.py`
- Create: `tests/unit/portal/api/ui/test_heartbeat.py`

**CC classification:** **CC** (reconnect-safe transport + cursor validation + cross-tenant invisibility). **Halt-before-commit:** YES.

**Acceptance per spec §4.3:**
- 3 endpoints: `GET /runs/{run_id}/events` · `GET /tenants/{tenant_id}/events` · `GET /events/since/{event_id}`.
- `Last-Event-ID` header WINS over URL cursor; malformed header → 422 `cursor_malformed` (no silent fallback).
- Cursor pre-load + cross-tenant 404 (cursor_tenant_mismatch invisible) + cursor_not_found 422 + cursor_projection_drift_detected 500.
- SSE headers: `Cache-Control: no-cache`, `X-Accel-Buffering: no`, `Connection: keep-alive`.
- `send_timeout=30s` on `EventSourceResponse`.
- Broker/generator-owned heartbeat (15s); sse-starlette internal ping set to long sentinel (`ping=86400`); `last_activity_at` updated on yield success.
- 7 test classes covering each surface.

**Steps:**

- [ ] **Step 1 (R9 #3 — REUSE T6 files, NO new helper modules):** `tests/unit/portal/api/ui/sse_test_helpers.py` and `tests/unit/portal/api/ui/conftest.py` already exist from T6 (per R6 #1 / R8 #2 task-ownership). T10 does NOT recreate them. The T6-shipped conftest already defines:
  - All fixtures T10 needs (`sqlite_engine`, `audit_store`, `decision_history_store`, `ui_event_emitter`, `broker`, `settings`, `settings_low_cap`, `settings_short_send_timeout`, `actor_t1`, `app_with_broker`).
  - The R9 #2 **`app` fixture**: mounts `build_stream_routes(broker=broker)` on top of `app_with_broker` via lazy import of `cognic_agentos.portal.api.ui.stream_routes`. The lazy import doesn't break T6 collection (T6 RBAC tests use `app_with_broker` without UI routes). T10 SSE tests request `app` — by then `stream_routes.py` exists (T10 Step 2-3 creates it) and the import resolves.

  And the T6-shipped helpers module already defines:
  - `_FixtureActorBinder` · `_next_sse_event` · `_iter_sse_events` · `_read_recent_decision_history_rows` · `emit_test_policy_event_and_memory_event`.
  - The R9 #1 **`_async_client(app)` helper** (httpx 0.28+ ASGITransport wrapper — repo's httpx pin dropped `AsyncClient(app=...)`).
  - The R9 #4 **`emit_audit_tool_call_event(audit_store, *, tenant_id)` helper** for the `TestAuditBackedFamiliesExcludedFromSSE` regression.

  See the T6 section above (`# tests/unit/portal/api/ui/sse_test_helpers.py` and `# tests/unit/portal/api/ui/conftest.py` code blocks) for the source-of-truth contents — DO NOT duplicate them here.

**R5 #3 + R6 #4 (`_app_unauth` mismatch + correct binder swap):** the per-test "unauthenticated request" pattern uses **`app.state.actor_binder` swap** (R6 #4) on the existing `app_with_broker` fixture instead of (a) a separate `_app_unauth` helper (R5 #3 removed it) or (b) `dependency_overrides[_bind_actor]` (R6 #4 — that bypasses the REAL `_bind_actor` whose exception-catch + chain-emit IS the code under test). The state-swap pattern:

```python
# Inside a test that wants unauthenticated behavior:
from cognic_agentos.portal.rbac.actor import ActorBinderUnauthenticated

class _RaisesUnauthBinder:
    def bind(self, *, request):
        raise ActorBinderUnauthenticated("no token")

async def test_unauth_returns_403_with_chain_row(app_with_broker, ...):
    original_binder = app_with_broker.state.actor_binder
    app_with_broker.state.actor_binder = _RaisesUnauthBinder()
    try:
        async with _async_client(app_with_broker) as c:
            r = await c.get("/api/v1/ui/runs/run_1/events")
        assert r.status_code == 403
        # Real _bind_actor caught the exception → policy.rbac_denied chain row emitted
        # ...
    finally:
        app_with_broker.state.actor_binder = original_binder
```

This keeps UI routes mounted (because `app_with_broker` has all the deps from R3 #3) AND lets the REAL `_bind_actor` run, catch `ActorBinderUnauthenticated`, emit the chain row, and raise the 403. Tests that need to force a specific denial path use this pattern directly (mirrored by the T6 `_setup_denial_path` fixture which swaps `app.state.actor_binder` per denial type — R6 #4).

- [ ] **Step 1b:** Write failing tests for the 3 SSE endpoints. Each test file imports the plain helpers explicitly per R5 #1 (only fixtures auto-discover from conftest.py; plain callables must be imported):

**R12 #4 — Per-file imports (NOT a shared boilerplate).** Each of the 5 T10 test files has its OWN exact import block matching ONLY the symbols its body uses. Ruff F401 is enabled in this repo and would refuse a copy-paste shared block of unused names. The per-file blocks appear inline at each test file header below. Fixtures (`broker`, `app`, `app_with_broker`, `actor_t1`, `settings_low_cap`, etc.) auto-discover from the T6-shipped conftest — never imported. `app` is the UI-routes-mounted variant (per R9 #2); `app_with_broker` is the bare variant (T6-only, RBAC denial tests on pack routes).

```python
# tests/unit/portal/api/ui/test_stream_routes.py — basic endpoint shape + RBAC + family filter
# R12 #4: exact per-file imports (ruff F401-safe).
import asyncio
import pytest
from tests.unit.portal.api.ui.sse_test_helpers import (
    _async_client,
    _iter_sse_events,
    _next_sse_event,
    emit_audit_tool_call_event,
    emit_test_policy_event_and_memory_event,
)


class TestEndpoint1RunStreamShape:
    @pytest.mark.asyncio
    async def test_run_stream_returns_text_event_stream(self, app):
        async with _async_client(app) as c:
            async with c.stream("GET", "/api/v1/ui/runs/run_1/events") as r:
                assert r.status_code == 200
                assert r.headers["content-type"].startswith("text/event-stream")

    @pytest.mark.asyncio
    async def test_run_stream_rbac_required(self, app):
        """R9 #2: this test exercises a UI route (/api/v1/ui/runs/.../events)
        so it MUST use the UI-routes-mounted `app` fixture (R9 #2), NOT the
        bare `app_with_broker`. R6 #4: swap app.state.actor_binder so the REAL
        _bind_actor runs and catches ActorBinderUnauthenticated → maps to 403
        + emits policy.rbac_denied chain row; NOT dependency_overrides[_bind_actor]
        which would bypass the dep entirely + skip the chain-row emit we're testing."""
        from cognic_agentos.portal.rbac.actor import ActorBinderUnauthenticated

        class _RaisesUnauthBinder:
            def bind(self, *, request):
                raise ActorBinderUnauthenticated("no token")

        original_binder = app.state.actor_binder
        app.state.actor_binder = _RaisesUnauthBinder()
        try:
            async with _async_client(app) as c:
                r = await c.get("/api/v1/ui/runs/run_1/events")
            assert r.status_code == 403
            # Real _bind_actor caught the exception → chain row emitted
        finally:
            app.state.actor_binder = original_binder


class TestEndpoint2TenantStreamCrossTenant404:
    @pytest.mark.asyncio
    async def test_cross_tenant_returns_404_invisible(self, app, actor_t1):  # R9 #4: actor_t1 (not actor_in_tenant_t1)
        async with _async_client(app) as c:
            r = await c.get("/api/v1/ui/tenants/t2/events")
        # Cross-tenant returns 404 with body matching pack_not_found shape (invisible)
        assert r.status_code == 404
        assert r.json()["detail"]["reason"] == "pack_not_found"


class TestEndpoint3SinceCursorReplay:
    @pytest.mark.asyncio
    async def test_replay_then_live(self, app, broker, decision_history_store, actor_t1):
        # Append 3 chain rows
        r1 = await broker.append_frontend_action_submitted(
            request_id="portal-req-1", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:11", tenant_id="t1",
        )
        r2 = await broker.append_frontend_action_submitted(
            request_id="portal-req-2", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:22", tenant_id="t1",
        )
        r3 = await broker.append_frontend_action_submitted(
            request_id="portal-req-3", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:33", tenant_id="t1",
        )
        # Subscribe with cursor=r1.event_id; expect r2 + r3 in replay, then live tail
        events_received = []
        async with _async_client(app) as c:
            async with c.stream("GET", f"/api/v1/ui/events/since/{r1.event_id}") as resp:
                async for chunk in _iter_sse_events(resp, max_events=2):
                    events_received.append(chunk)
        assert [e["id"] for e in events_received] == [r2.event_id, r3.event_id]


class TestFamilyFilter:
    @pytest.mark.asyncio
    async def test_families_query_param_filters_replay_and_live(self, app, broker, actor_t1):
        async with _async_client(app) as c:
            async with c.stream(
                "GET",
                "/api/v1/ui/runs/run_1/events?families=frontend_action,policy",
            ) as resp:
                assert resp.status_code == 200
                # Emit a policy.rbac_denied (matches filter) + a memory event (doesn't)
                # via a helper, then read the next event from the stream
                await emit_test_policy_event_and_memory_event(broker)   # R5 #4: must be awaited
                got = await asyncio.wait_for(_next_sse_event(resp), timeout=0.5)
                assert got["event"].startswith("policy.") or got["event"].startswith("frontend_action.")

    @pytest.mark.asyncio
    async def test_family_filter_unknown_422(self, app, actor_t1):
        async with _async_client(app) as c:
            r = await c.get("/api/v1/ui/runs/run_1/events?families=bogus")
        assert r.status_code == 422
        assert r.json()["detail"]["reason"] == "family_filter_unknown"


class TestTenantConnectionCapExceeded:
    @pytest.mark.asyncio
    async def test_429_when_per_tenant_cap_hit(self, app_low_cap, actor_t1):
        # R13 #2: use `app_low_cap` (NOT `app` + parameter `settings_low_cap`)
        # — the latter would resolve settings_low_cap as a sibling fixture but
        # the broker mounted in `app` was built from the DEFAULT `settings` (cap=50)
        # so the second stream would never 429. `app_low_cap` re-roots create_app
        # + broker construction at settings_low_cap (cap=1) so the cap actually fires.
        async with _async_client(app_low_cap) as c:
            async with c.stream("GET", "/api/v1/ui/tenants/t1/events"):
                r2 = await c.get("/api/v1/ui/tenants/t1/events")
        assert r2.status_code == 429
        assert r2.json()["detail"]["reason"] == "tenant_connection_cap_exceeded"


class TestAuditBackedFamiliesExcludedFromSSE:
    """Wave-1 SSE = decision-history-only. tool_call.* / artifact.* never reach subscribers."""
    @pytest.mark.asyncio
    async def test_tool_call_event_not_delivered_to_sse(self, app, broker, audit_store, actor_t1):
        # Fire an audit-chain tool_call event; subscribe; assert NO event reaches subscriber
        # (broker filter rejects events whose family is NOT in _SSE_WAVE_1_STREAMED_FAMILIES)
        async with _async_client(app) as c:
            async with c.stream("GET", "/api/v1/ui/tenants/t1/events") as resp:
                await emit_audit_tool_call_event(audit_store, tenant_id="t1")
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(_next_sse_event(resp), timeout=0.3)
```

```python
# tests/unit/portal/api/ui/test_stream_routes_last_event_id.py — Last-Event-ID precedence
# R12 #4: exact per-file imports (ruff F401-safe).
import asyncio
import pytest
from tests.unit.portal.api.ui.sse_test_helpers import _async_client, _next_sse_event


class TestLastEventIdPrecedence:
    @pytest.mark.asyncio
    async def test_header_wins_over_url_since_query(self, app, broker, actor_t1):
        # Append 3 events; r_a/r_b/r_c
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-a", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:aa", tenant_id="t1")
        r_b = await broker.append_frontend_action_submitted(
            request_id="portal-req-b", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:bb", tenant_id="t1")
        r_c = await broker.append_frontend_action_submitted(
            request_id="portal-req-c", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:cc", tenant_id="t1")
        # Send BOTH ?since=evt_A AND Last-Event-ID: evt_B → expect replay starts after B
        async with _async_client(app) as c:
            async with c.stream(
                "GET", f"/api/v1/ui/tenants/t1/events?since={r_a.event_id}",
                headers={"Last-Event-ID": r_b.event_id},
            ) as resp:
                got = await asyncio.wait_for(_next_sse_event(resp), timeout=0.5)
        assert got["id"] == r_c.event_id

    @pytest.mark.asyncio
    async def test_header_wins_over_path_cursor_endpoint_3(self, app, broker, actor_t1):
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-a", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:aa", tenant_id="t1")
        r_b = await broker.append_frontend_action_submitted(
            request_id="portal-req-b", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:bb", tenant_id="t1")
        r_c = await broker.append_frontend_action_submitted(
            request_id="portal-req-c", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:cc", tenant_id="t1")
        async with _async_client(app) as c:
            async with c.stream(
                "GET", f"/api/v1/ui/events/since/{r_a.event_id}",
                headers={"Last-Event-ID": r_b.event_id},
            ) as resp:
                got = await asyncio.wait_for(_next_sse_event(resp), timeout=0.5)
        assert got["id"] == r_c.event_id

    @pytest.mark.asyncio
    async def test_endpoint_1_browser_reconnect_with_last_event_id(self, app, broker, actor_t1):
        # First connect (no header) → live-only; receive evt_X
        async with _async_client(app) as c:
            async with c.stream("GET", "/api/v1/ui/runs/run_1/events") as resp:
                emitted = await broker.append_frontend_action_submitted(
                    request_id="portal-req-x", action_class="approve",
                    actor_subject="u1", client_correlation_id=None,
                    payload_digest="sha256:xx", tenant_id="t1",
                    # note: typed projector populates event.run_id from snapshot.trace_id
                )
                # subscriber filter `run_id == "run_1"` — assume helper rigging matches.
                # R13 #3: consume + assert on the live event (ruff F841 forbids the
                # bare `first = ...` assigned-but-unread bind that earlier drafts had).
                first = await asyncio.wait_for(_next_sse_event(resp), timeout=0.5)
                assert first["id"] == emitted.event_id
            # Reconnect with Last-Event-ID: emitted.event_id
            r_y = await broker.append_frontend_action_submitted(
                request_id="portal-req-y", action_class="approve",
                actor_subject="u1", client_correlation_id=None,
                payload_digest="sha256:yy", tenant_id="t1",
            )
            async with c.stream(
                "GET", "/api/v1/ui/runs/run_1/events",
                headers={"Last-Event-ID": emitted.event_id},
            ) as resp2:
                replayed = await asyncio.wait_for(_next_sse_event(resp2), timeout=0.5)
        assert replayed["id"] == r_y.event_id

    @pytest.mark.asyncio
    async def test_malformed_last_event_id_does_NOT_fall_back(self, app, broker, actor_t1):
        # Last-Event-ID: garbage + ?since=<valid> → 422 cursor_malformed (no silent fallback)
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-a", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:aa", tenant_id="t1")
        async with _async_client(app) as c:
            r = await c.get(
                f"/api/v1/ui/tenants/t1/events?since={r_a.event_id}",
                headers={"Last-Event-ID": "garbage-cursor"},
            )
        assert r.status_code == 422
        assert r.json()["detail"]["reason"] == "cursor_malformed"
```

```python
# tests/unit/portal/api/ui/test_stream_routes_reconnect.py — replay-then-live boundary
# R12 #4: exact per-file imports (ruff F401-safe).
import asyncio
import pytest
from tests.unit.portal.api.ui.sse_test_helpers import _async_client, _next_sse_event


class TestReplayThenLiveBoundary:
    @pytest.mark.asyncio
    async def test_no_events_lost_on_reconnect(self, app, broker, actor_t1):
        rows = []
        for n in range(5):
            r = await broker.append_frontend_action_submitted(
                request_id=f"portal-req-{n}", action_class="approve",
                actor_subject="u1", client_correlation_id=None,
                payload_digest=f"sha256:{n:02x}", tenant_id="t1")
            rows.append(r)
        # Cursor at row 2 → expect rows 3, 4 (events 4, 5)
        cursor = rows[2].event_id
        received_ids = []
        async with _async_client(app) as c:
            async with c.stream("GET", f"/api/v1/ui/events/since/{cursor}") as resp:
                for _ in range(2):
                    e = await asyncio.wait_for(_next_sse_event(resp), timeout=0.5)
                    received_ids.append(e["id"])
        assert received_ids == [rows[3].event_id, rows[4].event_id]

    @pytest.mark.asyncio
    async def test_boundary_dedup_by_event_id(self, app, broker, actor_t1):
        # One submit produces ordinal 0 (typed) + ordinal 1 (decision_audit mirror).
        # Cursor at (seq=N, ordinal=0) → reconnect delivers only (seq=N, ordinal=1)
        r = await broker.append_frontend_action_submitted(
            request_id="portal-req-1", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:11", tenant_id="t1")
        # r.event_id encodes ordinal=0 (the typed event)
        async with _async_client(app) as c:
            async with c.stream("GET", f"/api/v1/ui/events/since/{r.event_id}") as resp:
                got = await asyncio.wait_for(_next_sse_event(resp), timeout=0.5)
        # The next event for the same row is the decision_audit mirror at ordinal 1
        assert got["event"] == "decision_audit.event_appended"

    @pytest.mark.asyncio
    async def test_cursor_not_found_422(self, app, broker, actor_t1):
        # Cursor with sequence way beyond tip
        from cognic_agentos.protocol.ui_events import _chain_derived_event_id
        bogus_cursor = _chain_derived_event_id(
            chain_id="decision_history", sequence=999_999_999, ordinal=0,
            family="frontend_action", type_="submitted",
        )
        async with _async_client(app) as c:
            r = await c.get(f"/api/v1/ui/events/since/{bogus_cursor}")
        assert r.status_code == 422
        assert r.json()["detail"]["reason"] == "cursor_not_found"

    @pytest.mark.asyncio
    async def test_cursor_tenant_mismatch_404_invisible(self, app, broker, actor_t1):
        # Append a row as tenant t2; build cursor from it; query as actor t1
        r_t2 = await broker.append_frontend_action_submitted(
            request_id="portal-req-t2", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:11", tenant_id="t2")
        async with _async_client(app) as c:
            r = await c.get(f"/api/v1/ui/events/since/{r_t2.event_id}")
        # Cross-tenant returns 404 invisible (same shape as pack_not_found)
        assert r.status_code == 404
        assert r.json()["detail"]["reason"] == "pack_not_found"

    @pytest.mark.asyncio
    async def test_cursor_projection_drift_detected_500(self, app, broker, actor_t1, monkeypatch):
        r_a = await broker.append_frontend_action_submitted(
            request_id="portal-req-1", action_class="approve",
            actor_subject="u1", client_correlation_id=None,
            payload_digest="sha256:11", tenant_id="t1")
        # Monkey-patch the routing table to remove the typed projector for this decision_type
        from cognic_agentos.protocol import ui_events
        patched = {k: v for k, v in ui_events._DECISION_HISTORY_TYPED_PROJECTORS.items()
                   if k != "frontend_action.submitted"}
        monkeypatch.setattr(ui_events, "_DECISION_HISTORY_TYPED_PROJECTORS", patched)
        async with _async_client(app) as c:
            r = await c.get(f"/api/v1/ui/events/since/{r_a.event_id}")
        assert r.status_code == 500
        assert r.json()["detail"]["reason"] == "cursor_projection_drift_detected"
```

```python
# tests/unit/portal/api/ui/test_stream_headers_and_timeout.py — SSE headers + send_timeout
# R12 #4: exact per-file imports (ruff F401-safe).
import asyncio
import pytest
from tests.unit.portal.api.ui.sse_test_helpers import _async_client


class TestSSEHeaders:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("endpoint", [
        "/api/v1/ui/runs/run_1/events",
        "/api/v1/ui/tenants/t1/events",
        # endpoint 3 needs a real cursor; build it via fixture
    ])
    async def test_required_headers(self, app, endpoint, actor_t1):
        async with _async_client(app) as c:
            async with c.stream("GET", endpoint) as r:
                assert r.headers["cache-control"] == "no-cache"
                assert r.headers["x-accel-buffering"] == "no"
                assert r.headers.get("connection", "").lower() == "keep-alive"


class TestSendTimeoutCleansUpHalfOpenClient:
    @pytest.mark.asyncio
    async def test_stalled_client_unregistered_past_send_timeout(
        self, app_short_send_timeout, broker_short_send_timeout, actor_t1,
    ):
        # R13 #2: use `app_short_send_timeout` + `broker_short_send_timeout` so
        # the broker the route uses AND the broker the test inspects are the
        # SAME settings_short_send_timeout-wired instance (mirrors the
        # `app_low_cap` / `broker_low_cap` pairing for the cap test).
        before_count = len(broker_short_send_timeout._subscribers)
        async with _async_client(app_short_send_timeout) as c:
            # R13 #3: drop the `as resp` binding — the response object is never
            # referenced inside the block (ruff F841 would flag the unused name).
            # open SSE stream + immediately close on client side without draining queue
            async with c.stream("GET", "/api/v1/ui/tenants/t1/events"):
                # Force a write by emitting a heartbeat that won't drain client-side
                await asyncio.sleep(0.05)  # let subscriber register
            # Client closed → server-side generator's finally should fire
        # Allow the broker to clean up
        await asyncio.sleep(0.1)
        assert len(broker_short_send_timeout._subscribers) == before_count
```

```python
# tests/unit/portal/api/ui/test_heartbeat.py — broker/generator-owned heartbeat
# R12 #4: exact per-file imports (ruff F401-safe).
import asyncio
import pytest
from datetime import datetime, UTC
from tests.unit.portal.api.ui.sse_test_helpers import _async_client


class TestHeartbeat:
    @pytest.mark.asyncio
    async def test_broker_emits_keepalive_every_n_seconds(self, app, broker, actor_t1, monkeypatch):
        # Reduce heartbeat to 50ms for the test; collect 3 keepalives in ~200ms
        monkeypatch.setattr(broker._settings, "ui_event_stream_heartbeat_interval_s", 0.05)
        keepalive_count = 0
        async with _async_client(app) as c:
            async with c.stream("GET", "/api/v1/ui/tenants/t1/events") as resp:
                async for raw_line in resp.aiter_lines():
                    if raw_line.startswith(": keepalive"):
                        keepalive_count += 1
                        if keepalive_count >= 3:
                            break
        assert keepalive_count >= 3

    @pytest.mark.asyncio
    async def test_last_activity_at_updated_on_heartbeat_yield(self, broker):
        sub = broker.register_subscriber(tenant_id="t1")
        original = sub.last_activity_at
        # Simulate the generator yielding a keepalive (calling the hook directly)
        sub.last_activity_at = datetime.now(UTC)
        assert sub.last_activity_at > original

    @pytest.mark.asyncio
    async def test_reap_idle_closes_stale_subscribers(self, broker):
        """R11 #5: `freezer` fixture removed — pytest-freezer / freezegun are
        NOT pyproject deps (verified). `broker.reap_idle` already takes the
        evaluation timestamp as an explicit argument, so the frozen-clock
        rebase was dead code — the test only needs to set the subscriber's
        last_activity_at to a stale absolute timestamp and pass an evaluation
        timestamp 1 hour later. No wall-clock manipulation needed."""
        sub = broker.register_subscriber(tenant_id="t1")
        sub.last_activity_at = datetime(2026, 5, 15, 11, 0, 0, tzinfo=UTC)  # 1 hour idle
        reaped = broker.reap_idle(datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC))
        assert reaped == 1
        assert sub not in broker._subscribers
```

- [ ] **Step 2:** Run all 5 test files → verify FAIL (stream_routes doesn't exist).

- [ ] **Step 3:** Implement `src/cognic_agentos/portal/api/ui/stream_routes.py`:

```python
"""Sprint-7B.4 T10 — 3 SSE GET endpoints per ADR-020 §60-63.
NOTE: from __future__ import annotations DELIBERATELY OMITTED — PEP 563
string-deferred annotations break FastAPI's inspect.signature() on
Annotated[..., Depends(closure-local)] (standing-offer invariant)."""
import asyncio                                                       # R3 #6: needed for asyncio.wait_for / asyncio.TimeoutError
from datetime import datetime, UTC
from typing import Literal
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request  # R3 #6: Depends added
from sse_starlette.sse import EventSourceResponse, ServerSentEvent
from cognic_agentos.protocol.ui_events import (
    UIEventBroker, ChainCursor, CursorMalformed, CursorChainUnsupported,
    _decode_chain_cursor, _SSE_WAVE_1_STREAMED_FAMILIES,
    TenantConnectionCapExceeded,
)
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.actor import Actor

CursorRefusalReason = Literal[
    "cursor_malformed", "cursor_chain_unsupported",
    "cursor_not_found", "cursor_tenant_mismatch",
    "cursor_projection_drift_detected",
]

FamilyFilterRefusalReason = Literal["family_filter_unknown"]


def build_stream_routes(*, broker: UIEventBroker) -> APIRouter:
    router = APIRouter()

    async def _resolve_effective_cursor(
        last_event_id: str | None, url_cursor: str | None,
    ) -> ChainCursor | None:
        # P1: Last-Event-ID wins over URL cursor; malformed header DOES NOT silently fall back
        chosen = last_event_id if last_event_id else url_cursor
        if not chosen:
            return None
        try:
            return _decode_chain_cursor(chosen)
        except CursorMalformed as exc:
            raise HTTPException(422, detail={"reason": "cursor_malformed"}) from exc
        except CursorChainUnsupported as exc:
            raise HTTPException(422, detail={"reason": "cursor_chain_unsupported"}) from exc

    async def _validate_cursor_tenant(
        cursor: ChainCursor, actor_tenant_id: str, store,
    ) -> None:
        """R3 #1: validate cursor's boundary row via direct SQLAlchemy select
        against the exported `_decision_history` Table — the same read seam
        the replay path uses. NO nonexistent DecisionHistoryStore methods."""
        from sqlalchemy import select
        from cognic_agentos.core.decision_history import _decision_history
        async with store._engine.begin() as conn:
            row = (await conn.execute(
                select(_decision_history.c.tenant_id)
                .where(_decision_history.c.sequence == cursor.sequence)
            )).first()
        if row is None:
            raise HTTPException(422, detail={"reason": "cursor_not_found"})
        if row.tenant_id != actor_tenant_id:
            # Cross-tenant invisible — same body shape as pack_not_found
            raise HTTPException(404, detail={"reason": "pack_not_found"})

    def _parse_family_filter(families: str | None) -> frozenset[str] | None:
        if not families:
            return None
        requested = frozenset(s.strip() for s in families.split(",") if s.strip())
        unknown = requested - _SSE_WAVE_1_STREAMED_FAMILIES
        if unknown:
            raise HTTPException(422, detail={
                "reason": "family_filter_unknown",
                "unknown_families": sorted(unknown),
            })
        return requested

    @router.get("/runs/{run_id}/events")
    async def run_stream(
        request: Request,
        run_id: str,
        actor: Actor = Depends(RequireScope("ui.run_stream")),
        families: str | None = Query(default=None),
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    ) -> EventSourceResponse:
        family_filter = _parse_family_filter(families)
        cursor = await _resolve_effective_cursor(last_event_id, url_cursor=None)
        if cursor is not None:
            await _validate_cursor_tenant(cursor, actor.tenant_id, request.app.state.decision_history_store)
        try:
            subscriber = broker.register_subscriber(
                tenant_id=actor.tenant_id, run_id_filter=run_id, family_filter=family_filter,
            )
        except TenantConnectionCapExceeded as exc:
            raise HTTPException(429, detail={"reason": "tenant_connection_cap_exceeded"}) from exc
        return EventSourceResponse(
            _sse_generator(broker, subscriber, cursor, request.app.state.decision_history_store, request.app.state.settings),
            ping=86400,  # long sentinel; broker/generator-owned heartbeat is authoritative
            send_timeout=request.app.state.settings.ui_event_stream_send_timeout_s,
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    @router.get("/tenants/{tenant_id}/events")
    async def tenant_stream(
        request: Request,
        tenant_id: str,
        actor: Actor = Depends(RequireScope("ui.tenant_stream")),
        families: str | None = Query(default=None),
        since: str | None = Query(default=None),
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    ) -> EventSourceResponse:
        if tenant_id != actor.tenant_id:
            raise HTTPException(404, detail={"reason": "pack_not_found"})  # cross-tenant invisible
        family_filter = _parse_family_filter(families)
        cursor = await _resolve_effective_cursor(last_event_id, since)
        if cursor is not None:
            await _validate_cursor_tenant(cursor, actor.tenant_id, request.app.state.decision_history_store)
        try:
            subscriber = broker.register_subscriber(
                tenant_id=actor.tenant_id, run_id_filter=None, family_filter=family_filter,
            )
        except TenantConnectionCapExceeded as exc:
            raise HTTPException(429, detail={"reason": "tenant_connection_cap_exceeded"}) from exc
        return EventSourceResponse(
            _sse_generator(broker, subscriber, cursor, request.app.state.decision_history_store, request.app.state.settings),
            ping=86400, send_timeout=request.app.state.settings.ui_event_stream_send_timeout_s,
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
        )

    @router.get("/events/since/{event_id}")
    async def since_cursor_stream(
        request: Request,
        event_id: str,
        actor: Actor = Depends(RequireScope("ui.tenant_stream")),
        run_id: str | None = Query(default=None),
        families: str | None = Query(default=None),
        last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
    ) -> EventSourceResponse:
        family_filter = _parse_family_filter(families)
        cursor = await _resolve_effective_cursor(last_event_id, url_cursor=event_id)
        # cursor is non-None here because path always provides event_id
        await _validate_cursor_tenant(cursor, actor.tenant_id, request.app.state.decision_history_store)
        try:
            subscriber = broker.register_subscriber(
                tenant_id=actor.tenant_id, run_id_filter=run_id, family_filter=family_filter,
            )
        except TenantConnectionCapExceeded as exc:
            raise HTTPException(429, detail={"reason": "tenant_connection_cap_exceeded"}) from exc
        return EventSourceResponse(
            _sse_generator(broker, subscriber, cursor, request.app.state.decision_history_store, request.app.state.settings),
            ping=86400, send_timeout=request.app.state.settings.ui_event_stream_send_timeout_s,
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
        )

    return router


async def _sse_generator(broker, subscriber, cursor, store, settings):
    """Replay-then-live SSE generator. Yields ServerSentEvent for each event;
    yields comment=keepalive every heartbeat_interval_s; updates
    subscriber.last_activity_at on every successful yield."""
    try:
        # 1. Replay historical events if cursor provided
        if cursor is not None:
            async for hist_event in _replay_from_decision_history(store, cursor, subscriber):
                yield _encode(hist_event)
                subscriber.last_activity_at = datetime.now(UTC)
        # 2. Transition to live tail
        last_heartbeat = datetime.now(UTC)
        while True:
            try:
                event = await asyncio.wait_for(
                    subscriber.queue.get(),
                    timeout=settings.ui_event_stream_heartbeat_interval_s,
                )
                yield _encode(event)
                subscriber.last_activity_at = datetime.now(UTC)
            except asyncio.TimeoutError:
                yield ServerSentEvent(comment="keepalive")
                subscriber.last_activity_at = datetime.now(UTC)
    finally:
        broker.unregister_subscriber(subscriber)


def _encode(event) -> ServerSentEvent:
    return ServerSentEvent(
        id=event.event_id,
        event=f"{event.family}.{event.type}",
        data=event.model_dump_json(),
    )


async def _replay_from_decision_history(store, cursor: ChainCursor, subscriber):
    """Yield events for chain rows with sequence >= cursor.sequence;
    for the boundary row (sequence == cursor.sequence), yield ordinals > cursor.ordinal;
    apply type_hash drift detection at boundary.

    R3 #1 — read seam: replay queries the exported `_decision_history` SQLAlchemy
    Table from `core.decision_history` directly (the Table IS the supported public
    surface — `__all__` at core/decision_history.py:632 exports it). This avoids
    a stop-rule edit to `DecisionHistoryStore` while keeping the replay path
    self-contained in protocol/ui_events.py. The broker holds the AsyncEngine
    via `store._engine` (existing Sprint-6 attribute used by AuditStore's hook chain).

    The `_DH_CHAIN_ID = "decision_history"` constant is also exported from
    core.decision_history for chain-discriminator parity with the broker's
    cursor encoder.
    """
    import hashlib
    from sqlalchemy import select
    from cognic_agentos.core.decision_history import _decision_history    # exported Table
    from cognic_agentos.protocol.ui_events import (
        _project_typed_decision_history, _build_decision_audit_for_dh_snapshot,
        _SSE_WAVE_1_STREAMED_FAMILIES, _DHReplaySnapshot,
    )

    # Snapshot the chain tip at replay start (per Section 2c step 2).
    # Reuses the existing tip query pattern from AuditStore's append-with-precondition.
    engine = store._engine
    async with engine.begin() as conn:
        # 1) Snapshot tip sequence (read-only).
        tip_stmt = select(_decision_history.c.sequence).order_by(
            _decision_history.c.sequence.desc()
        ).limit(1)
        tip_row = (await conn.execute(tip_stmt)).first()
        tip = tip_row.sequence if tip_row is not None else 0

        # 2) Read rows in [cursor.sequence, tip] for the actor's tenant,
        # ordered by sequence ASC. Build a _DHReplaySnapshot per row that
        # carries the same fields as AppendedDecisionSnapshot so the existing
        # projector callsites work unchanged.
        rows_stmt = (
            select(_decision_history)
            .where(_decision_history.c.sequence >= cursor.sequence)
            .where(_decision_history.c.sequence <= tip)
            .where(_decision_history.c.tenant_id == subscriber.tenant_id)
            .order_by(_decision_history.c.sequence.asc())
        )
        result = await conn.execute(rows_stmt)
        rows = result.fetchall()

    # 3) Project + yield outside the DB transaction.
    # R4 #1: _decision_history table columns are `event_type` + `hash`, NOT
    # decision_type / new_hash. Map them onto _DHReplaySnapshot's projector-facing
    # field names explicitly so the same projector functions work in live + replay.
    for row in rows:
        snapshot = _DHReplaySnapshot(
            sequence=row.sequence,
            decision_type=row.event_type,             # R4 #1: column is event_type
            tenant_id=row.tenant_id,
            trace_id=row.trace_id,
            request_id=row.request_id,
            payload=row.payload,
            new_hash=row.hash,                         # R4 #1: column is hash
            chain_id="decision_history",
            created_at=row.created_at,
        )
        # Build the (ordinal-0 typed if matched, ordinal-1 decision_audit) sequence
        ordered_events: list[tuple[int, object]] = []
        typed = _project_typed_decision_history(snapshot)
        if typed is not None:
            ordered_events.append((0, typed))
        ordered_events.append((1, _build_decision_audit_for_dh_snapshot(snapshot)))

        for ord_n, event in ordered_events:
            # Boundary row: skip events the client already saw
            if row.sequence == cursor.sequence and ord_n <= cursor.ordinal:
                # Type-hash drift assertion (Section 2c step 6)
                if ord_n == cursor.ordinal:
                    recomputed = hashlib.sha256(
                        f"{event.family}.{event.type}".encode()
                    ).digest()[:6]
                    if recomputed != cursor.type_hash:
                        raise HTTPException(
                            500, detail={"reason": "cursor_projection_drift_detected"}
                        )
                continue

            # Apply broker's Wave-1 family filter (audit-event-backed events excluded)
            if event.family not in _SSE_WAVE_1_STREAMED_FAMILIES:
                continue
            if (event.family == "decision_audit"
                    and event.data.get("chain_id") != "decision_history"):
                continue
            if subscriber.run_id_filter and event.run_id != subscriber.run_id_filter:
                continue
            if subscriber.family_filter and event.family not in subscriber.family_filter:
                continue
            yield event
```

**R3 #1 supporting addition to T4** (`protocol/ui_events.py`): define `_DHReplaySnapshot` as a frozen dataclass mirroring the public surface of `AppendedDecisionSnapshot` — the projector functions receive either type since they only access fields (`sequence`, `decision_type`, `tenant_id`, `trace_id`, `request_id`, `payload`, `new_hash`, `chain_id`, `created_at`). This keeps the replay path FastAPI-free and avoids cross-importing the audit-store snapshot type from `core/`:

```python
# protocol/ui_events.py — co-located with the typed-projector helpers

@dataclasses.dataclass(frozen=True)
class _DHReplaySnapshot:
    """R3 #1: replay-side snapshot shape compatible with AppendedDecisionSnapshot
    field access. Constructed by _replay_from_decision_history from raw SQLAlchemy
    rows; consumed by the existing typed projectors + _build_decision_audit_for_dh_snapshot."""
    sequence: int
    decision_type: str
    tenant_id: str | None
    trace_id: str | None
    request_id: str
    payload: dict
    new_hash: bytes
    chain_id: str
    created_at: "datetime"
```

**T4 acceptance gains 1 test:** `TestReplaySnapshotShapeMatchesAppendedDecisionSnapshot` — `set(dataclasses.fields(_DHReplaySnapshot)) == subset_of(AppendedDecisionSnapshot)` for the fields the projector functions read. Pins live + replay parity at the type level.

**T13 architectural-arrow regression updates:** the new SQLAlchemy import in `_replay_from_decision_history` (`from cognic_agentos.core.decision_history import _decision_history`) is core-bound (allowed under the arrow `protocol → core`). The AST test confirms `protocol/ui_events.py` imports `_decision_history` Table (allowed) but does NOT import any `cognic_agentos.portal.*` (forbidden).

- [ ] **Step 4:** Run tests → iterate until PASS.

```bash
uv run pytest tests/unit/portal/api/ui/test_stream_routes.py \
              tests/unit/portal/api/ui/test_stream_routes_last_event_id.py \
              tests/unit/portal/api/ui/test_stream_routes_reconnect.py \
              tests/unit/portal/api/ui/test_stream_headers_and_timeout.py \
              tests/unit/portal/api/ui/test_heartbeat.py -v
# Expected: all green
```

- [ ] **Step 5:** **Threat-model-revert verifications** (4 guards):
  1. Remove boundary dedup → `TestBoundaryDedupByEventId` fails → restore.
  2. Remove type_hash assertion → `TestCursorProjectionDriftDetected500` fails → restore.
  3. Remove Last-Event-ID malformed fail-closed → `TestMalformedLastEventIdDoesNOTFallBack` fails → restore.
  4. Remove send_timeout from `EventSourceResponse` → `TestSendTimeoutCleansUpHalfOpenClient` times out → restore.

- [ ] **Step 6:** ruff/format/mypy clean; halt-before-commit + commit.

```bash
git add src/cognic_agentos/portal/api/ui/stream_routes.py \
        tests/unit/portal/api/ui/test_stream_routes.py \
        tests/unit/portal/api/ui/test_stream_routes_last_event_id.py \
        tests/unit/portal/api/ui/test_stream_routes_reconnect.py \
        tests/unit/portal/api/ui/test_stream_headers_and_timeout.py \
        tests/unit/portal/api/ui/test_heartbeat.py
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -F - <<'EOF'
feat(sprint-7b4): T10 — stream_routes.py: 3 SSE endpoints + Last-Event-ID + reconnect + heartbeat (CRITICAL CONTROLS)

- 3 SSE GETs: /runs/{run_id}/events · /tenants/{tenant_id}/events · /events/since/{event_id}
- Last-Event-ID header WINS over URL cursor; malformed fails closed with
  422 cursor_malformed (no silent fall-back)
- Cross-tenant cursor returns 404 same shape as pack_not_found (invisible)
- Boundary dedup by (sequence, ordinal) cursor; type_hash drift detector
- SSE headers: Cache-Control no-cache + X-Accel-Buffering no + Connection
  keep-alive; send_timeout 30s for half-open cleanup
- Broker/generator-owned heartbeat every 15s; sse-starlette internal ping
  set to long sentinel (broker heartbeat authoritative)
- 4 threat-model-revert verifications

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
```

---

## T11 — action_routes.py (POST /actions + RequireUIAction + 6-class dispatch + submit_elicitation gate)

**Files:**
- Create: `src/cognic_agentos/portal/api/ui/action_routes.py`
- Create: `tests/unit/portal/api/ui/test_action_routes.py`
- Create: `tests/unit/portal/api/ui/test_action_routes_correlation_latency.py`

**CC classification:** **CC** (wire-protocol-public action POST). **Halt-before-commit:** YES.

**Acceptance per spec §4.4d-i:**
- POST `/api/v1/ui/actions` with `RequireUIAction(broker)` dep.
- 7-step pipeline: dep → submitted append → gate (submit_elicitation) → backend dispatch → outcome append → typed projection → response.
- 5 stub paths (approve/deny/cancel_run/interrupt/resume) return 200 + outcome=rejected + `action_backend_deferred_<...>`.
- submit_elicitation routes through Section 5 gate; full E2E when adapter wired.
- `ActionResponse` carries `submitted_event_id` + `resolution_event_id` deterministic cursors.
- Deterministic correlation-latency test: `asyncio.wait_for(_next_event(sse), timeout=0.2)`.

**P1 #2 SCOPE:** `RequireUIAction` lives HERE in `action_routes.py`, NOT in `dto.py`. The dep is FastAPI + broker + RBAC coupled; placing it in dto.py would drag route deps into the type module (broken NOT-CC classification).

**Steps:**

- [ ] **Step 1:** Write failing tests at `tests/unit/portal/api/ui/test_action_routes.py`:

```python
"""Sprint 7B.4 T11 — POST /api/v1/ui/actions: dispatch + RequireUIAction + 5 stubs + submit_elicitation gate routing."""
# R12 #3: imports trimmed to ONLY symbols used in this file body.
# Removed (ruff F401 would refuse):
#   - import asyncio               (asyncio.* only used in test_action_routes_correlation_latency.py)
#   - ActionRequest, ActionResponse (dto types not referenced in test bodies; deps + responses go through HTTP)
#   - _next_sse_event              (used only in the correlation-latency file)
# Kept: pytest (every @pytest.mark.asyncio decorator + parametrize)
#       Actor (constructed in the two actor fixtures)
#       _async_client (every _async_client(app_with_*) call)
#       _FixtureActorBinder (constructed by _build_t11_app)
#       _read_recent_decision_history_rows (chain-row assertions)
import pytest
from cognic_agentos.portal.rbac.actor import Actor
from tests.unit.portal.api.ui.sse_test_helpers import (
    _async_client,
    _FixtureActorBinder,
    _read_recent_decision_history_rows,
)

# ---------------------------------------------------------------------------
# R11 #2 — T11 app fixtures (mount build_action_routes + actor-scope variants)
# ---------------------------------------------------------------------------
# Defined at module scope (T11-local, not in the T6-shipped UI conftest) so
# T11 OWNS them and they don't leak fixture names into T10/T12 test discovery.
# Pattern mirrors the T6 conftest's R9 #2 `app` fixture: wrap app_with_broker
# (already includes broker + decision_history_store + audit_store + ui_event_emitter
# + actor_binder via create_app) and additionally include the action router via
# lazy import (so this module imports cleanly before T11 ships action_routes.py).
#
# 4 fixtures, distinguished by (scope set, elicitation_adapter wired?):
#   - app_with_scopes              : actor holds ALL 8 UI scopes; elicitation_adapter wired
#   - app_with_only_approve        : actor holds ONLY ui.action.approve; elicitation_adapter wired
#   - app_no_adapter               : actor holds ALL UI scopes; elicitation_adapter = None
#                                    (tests the BackendUnwired path per spec §5.5)
#   - app_with_scopes_and_broker   : SAME as app_with_scopes; alias retained for
#                                    the correlation-latency test which also subscribes
#                                    to the SSE stream (the broker dependency is the
#                                    same instance the action route emits to)
# Each fixture builds a fresh app per test (pytest scope=function, default).
# The fail-loud `from cognic_agentos.portal.api.ui.action_routes import build_action_routes`
# raises ImportError at fixture-resolution time if T11 hasn't shipped the module
# yet — that IS the TDD RED for Step 1.


@pytest.fixture
def actor_t1_all_ui_scopes() -> Actor:
    """8 UI action scopes + 2 stream scopes (matches the T6-shipped actor_t1)."""
    return Actor(
        subject="u1", tenant_id="t1", actor_type="human",
        scopes=frozenset({
            "ui.run_stream", "ui.tenant_stream",
            "ui.action.approve", "ui.action.deny", "ui.action.cancel_run",
            "ui.action.interrupt", "ui.action.resume", "ui.action.submit_elicitation",
        }),
    )


@pytest.fixture
def actor_t1_only_approve() -> Actor:
    """Actor holding ONLY ui.action.approve (used to test per-class scope enforcement)."""
    return Actor(
        subject="u1", tenant_id="t1", actor_type="human",
        scopes=frozenset({"ui.action.approve"}),
    )


class _StubElicitationAdapter:
    """R12 #1 — T11 stub satisfying the locked `ElicitationAdapter` Protocol
    at `protocol/elicitation_adapter.py:2292`. The Protocol declares EXACTLY
    two methods (`get_context` + `handle_submission`), NOT a single `submit`
    method. Each submit_elicitation test that needs adapter-specific behavior
    monkeypatches these methods per-test."""

    async def get_context(
        self, *, elicitation_id: str, tenant_id: str,
    ) -> "ElicitationContext | None":
        # Returns a minimal ElicitationContext so the gate's tenant + originating-pack
        # checks proceed. Tests that probe gate-refusal paths monkeypatch this to
        # return None (→ elicitation_context_not_found) or a context with a
        # different tenant_id (→ elicitation_tenant_mismatch).
        from cognic_agentos.protocol.elicitation_adapter import ElicitationContext
        import uuid
        return ElicitationContext(
            elicitation_id=elicitation_id,
            tenant_id=tenant_id,
            originating_pack_id="pack-test",
            originating_decision_record_id=uuid.UUID(int=0),
            elicitation_modes=("url", "form"),
            data_classes=(),
            expires_at=None,  # R13 #1: required 7th field per ElicitationContext at line ~2273 (datetime | None)
        )

    async def handle_submission(
        self, *, ctx: "ElicitationContext", mode: "ElicitationMode",
        payload: dict,
    ) -> "ElicitationResult":
        # Green-path stub: synthesises a fresh delivered_at + a deterministic
        # backend_correlation_id derived from elicitation_id so tests can assert
        # on the cursor. Failure-path tests monkeypatch this to raise
        # ElicitationBackendError.
        from cognic_agentos.protocol.elicitation_adapter import ElicitationResult
        from datetime import datetime, UTC
        return ElicitationResult(
            delivered_at=datetime.now(UTC),
            backend_correlation_id=f"stub-backend-{ctx.elicitation_id}",
        )


def _build_t11_app(
    *,
    settings,
    decision_history_store,
    audit_store,
    ui_event_emitter,
    broker,
    actor: Actor,
    elicitation_adapter,
):
    """Shared builder for the 4 T11 app fixtures. Wraps create_app's output
    with the action router (lazy import → TDD RED before T11 ships the module).
    Threads broker + elicitation_adapter into app.state so RequireUIAction
    can look them up at request time."""
    from cognic_agentos.portal.api.app import create_app
    from cognic_agentos.portal.api.ui.action_routes import build_action_routes  # R11 #2: lazy import (TDD RED)
    app = create_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        actor_binder=_FixtureActorBinder(actor),
    )
    app.state.elicitation_adapter = elicitation_adapter  # None for app_no_adapter
    app.include_router(
        # R12 #1: thread the adapter THROUGH build_action_routes — the route
        # factory captures its own `elicitation_adapter` param at closure-build
        # time (see signature at line ~4452); placing it only on app.state would
        # leave every submit_elicitation route resolving to None.
        build_action_routes(broker=broker, elicitation_adapter=elicitation_adapter),
        prefix="/api/v1/ui",
    )
    return app


@pytest.fixture
async def app_with_scopes(
    settings, decision_history_store, audit_store, ui_event_emitter,
    broker, actor_t1_all_ui_scopes,
):
    return _build_t11_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        broker=broker,
        actor=actor_t1_all_ui_scopes,
        elicitation_adapter=_StubElicitationAdapter(),
    )


@pytest.fixture
async def app_with_only_approve(
    settings, decision_history_store, audit_store, ui_event_emitter,
    broker, actor_t1_only_approve,
):
    return _build_t11_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        broker=broker,
        actor=actor_t1_only_approve,
        elicitation_adapter=_StubElicitationAdapter(),
    )


@pytest.fixture
async def app_no_adapter(
    settings, decision_history_store, audit_store, ui_event_emitter,
    broker, actor_t1_all_ui_scopes,
):
    """elicitation_adapter=None — exercises the BackendUnwired path per spec §5.5."""
    return _build_t11_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        broker=broker,
        actor=actor_t1_all_ui_scopes,
        elicitation_adapter=None,
    )


@pytest.fixture
async def app_with_scopes_and_broker(
    settings, decision_history_store, audit_store, ui_event_emitter,
    broker, actor_t1_all_ui_scopes,
):
    """Alias of app_with_scopes used by the correlation-latency test
    (which ALSO subscribes to the SSE stream via the SAME broker instance —
    fixture-scope=function guarantees stream + action share that broker).

    R12 #1: stream router included BEFORE action router so that include order
    matches the production wiring in `create_app` (T12); the adapter is
    threaded through `build_action_routes` via the shared `_build_t11_app`."""
    from cognic_agentos.portal.api.ui.stream_routes import build_stream_routes  # R11 #2: also mount stream router
    app = _build_t11_app(
        settings=settings,
        decision_history_store=decision_history_store,
        audit_store=audit_store,
        ui_event_emitter=ui_event_emitter,
        broker=broker,
        actor=actor_t1_all_ui_scopes,
        elicitation_adapter=_StubElicitationAdapter(),
    )
    app.include_router(build_stream_routes(broker=broker), prefix="/api/v1/ui")
    return app


class TestRequireUIActionParsesDiscriminatedUnion:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("action_class,body_extra", [
        ("approve", {"approval_id": "ap_1", "decision": "grant"}),
        ("deny", {"approval_id": "ap_1"}),
        ("cancel_run", {"run_id": "run_1"}),
        ("interrupt", {"run_id": "run_1"}),
        ("resume", {"run_id": "run_1"}),
        ("submit_elicitation", {"elicitation_id": "elc_1", "mode": "url",
                                "url_completion_signal": {"ok": True}}),
    ])
    async def test_each_class_parses(self, app_with_scopes, action_class, body_extra):
        async with _async_client(app_with_scopes) as c:
            r = await c.post("/api/v1/ui/actions",
                             json={"action_class": action_class, **body_extra})
            assert r.status_code == 200, r.text


class TestRequireUIActionEnforcesPerClassScope:
    """An actor with ui.action.approve but NOT ui.action.deny:
    approve passes the dep; deny is refused with policy.rbac_denied + 403."""

    @pytest.mark.asyncio
    async def test_approve_passes_when_actor_has_approve_scope(self, app_with_only_approve):
        async with _async_client(app_with_only_approve) as c:
            r = await c.post("/api/v1/ui/actions",
                             json={"action_class": "approve",
                                   "approval_id": "ap_1", "decision": "grant"})
            assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_deny_refused_with_scope_not_held(self, app_with_only_approve, broker):
        async with _async_client(app_with_only_approve) as c:
            r = await c.post("/api/v1/ui/actions",
                             json={"action_class": "deny", "approval_id": "ap_1"})
            assert r.status_code == 403
            assert r.json()["detail"]["reason"] == "scope_not_held"
            assert r.json()["detail"]["required_scope"] == "ui.action.deny"
        # Verify chain row emitted
        rows = await _read_recent_decision_history_rows(broker)
        assert any(row.event_type == "rbac.scope_not_held" for row in rows)   # R4 #1: column is event_type


class TestRequireUIActionFailClosedOnEmitFailure:
    @pytest.mark.asyncio
    async def test_emit_failure_500_not_silent_403(self, app_with_only_approve, broker, monkeypatch):
        from unittest.mock import AsyncMock
        monkeypatch.setattr(broker, "emit_rbac_denial",
                            AsyncMock(side_effect=RuntimeError("simulated")))
        async with _async_client(app_with_only_approve) as c:
            r = await c.post("/api/v1/ui/actions",
                             json={"action_class": "deny", "approval_id": "ap_1"})
            assert r.status_code == 500
            assert r.json()["detail"]["reason"] == "rbac_denial_emit_failed"


class TestStubsReturn200WithDeferredReason:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("action_class,expected_reason", [
        ("approve", "action_backend_deferred_to_sprint_13_5"),
        ("deny", "action_backend_deferred_to_sprint_13_5"),
        ("cancel_run", "action_backend_deferred_no_run_primitive"),
        ("interrupt", "action_backend_deferred_sandbox_unwired"),
        ("resume", "action_backend_deferred_sandbox_unwired"),
    ])
    async def test_stub_emits_2_chain_rows(self, app_with_scopes, broker, action_class, expected_reason):
        body_extra = {
            "approve": {"approval_id": "ap_1", "decision": "grant"},
            "deny": {"approval_id": "ap_1"},
            "cancel_run": {"run_id": "run_1"},
            "interrupt": {"run_id": "run_1"},
            "resume": {"run_id": "run_1"},
        }[action_class]
        async with _async_client(app_with_scopes) as c:
            r = await c.post("/api/v1/ui/actions", json={"action_class": action_class, **body_extra})
        assert r.status_code == 200
        body = r.json()
        assert body["outcome"] == "rejected"
        assert body["reason"] == expected_reason
        # 2 chain rows: submitted + rejected
        rows = await _read_recent_decision_history_rows(broker)
        assert any(r.event_type == "frontend_action.submitted" for r in rows)   # R4 #1: column name
        assert any(r.event_type == "frontend_action.rejected" for r in rows)


class TestSubmitElicitationRoutedThroughGate:
    @pytest.mark.asyncio
    async def test_submit_elicitation_unwired_adapter_returns_backend_unwired(self, app_no_adapter):
        async with _async_client(app_no_adapter) as c:
            r = await c.post("/api/v1/ui/actions", json={
                "action_class": "submit_elicitation",
                "elicitation_id": "elc_1", "mode": "url",
                "url_completion_signal": {"ok": True},
            })
        assert r.status_code == 200
        assert r.json()["outcome"] == "rejected"
        assert r.json()["reason"] == "elicitation_backend_unwired"


class TestActionResponseEventIdCursorsMatchSSE:
    @pytest.mark.asyncio
    async def test_submitted_event_id_matches_chain_derived_cursor(self, app_with_scopes, broker):
        async with _async_client(app_with_scopes) as c:
            r = await c.post("/api/v1/ui/actions", json={
                "action_class": "approve", "approval_id": "ap_1", "decision": "grant",
            })
        body = r.json()
        # event_id is deterministic; reconstruct and assert
        rows = await _read_recent_decision_history_rows(broker)
        submitted_row = next(r for r in rows if r.event_type == "frontend_action.submitted")  # R10 #5: _decision_history column is event_type, not decision_type
        from cognic_agentos.protocol.ui_events import _chain_derived_event_id
        expected = _chain_derived_event_id(
            chain_id="decision_history", sequence=submitted_row.sequence, ordinal=0,
            family="frontend_action", type_="submitted",
        )
        assert body["submitted_event_id"] == expected
```

```python
# tests/unit/portal/api/ui/test_action_routes_correlation_latency.py — deterministic
# R10 #2: this is a SEPARATE test file; pytest treats each file independently,
# so it needs its OWN import block (does NOT inherit from test_action_routes.py).
import asyncio
import pytest
from tests.unit.portal.api.ui.sse_test_helpers import _async_client, _next_sse_event


class TestActionPOSTCorrelationEventDeliveredWithin200ms:
    @pytest.mark.asyncio
    async def test_correlation_event_arrives_within_200ms(self, app_with_scopes_and_broker):
        """Deterministic asyncio.wait_for(timeout=0.2) — not a flaky P99-over-N test."""
        async with _async_client(app_with_scopes_and_broker) as c:
            # subscribe SSE first
            async with c.stream("GET", "/api/v1/ui/tenants/t1/events?families=frontend_action") as sse:
                # fire POST
                post_task = asyncio.create_task(
                    c.post("/api/v1/ui/actions", json={"action_class": "approve",
                                                       "approval_id": "ap_1", "decision": "grant"})
                )
                # await SSE event with deterministic 200ms timeout
                event = await asyncio.wait_for(_next_sse_event(sse), timeout=0.2)
                await post_task
            # R11 #3 + R12 #2: `_next_sse_event` returns the SSE wrapper
            # {id, event, data} NOT the raw event payload.
            #
            #   event["event"]                 — SSE event-name header = "<family>.<type>"
            #   event["data"]                  — parsed JSON of the SSE `data:` line
            #                                    (the full Pydantic typed-event after
            #                                    model_dump_json — has family, type,
            #                                    event_id, ts, tenant, …, AND its own
            #                                    nested `data` field carrying the
            #                                    typed business payload)
            #   event["data"]["data"]          — the business payload (from
            #                                    `snapshot.payload` per
            #                                    `_project_frontend_action_submitted`
            #                                    at line ~858; contains action_class,
            #                                    actor_subject, etc.)
            #
            # The R11 #3 fix correctly moved family/type to event["data"];
            # R12 #2 follows the same path one level deeper for action_class.
            assert event["event"] == "frontend_action.submitted"
            assert event["data"]["family"] == "frontend_action"
            assert event["data"]["type"] == "submitted"
            assert event["data"]["data"]["action_class"] == "approve"
```

- [ ] **Step 2:** Run → verify FAIL.

- [ ] **Step 3:** Implement `src/cognic_agentos/portal/api/ui/action_routes.py` — `RequireUIAction` (per P1 #2 lives here) + `build_action_routes` factory + per-class dispatch:

```python
"""Sprint-7B.4 T11 — POST /api/v1/ui/actions per ADR-020 §22.
NOTE: from __future__ import annotations DELIBERATELY OMITTED (standing-offer
invariant for FastAPI route modules with Annotated[..., Depends(closure-local)] deps)."""
from datetime import datetime, UTC
from typing import Awaitable, Callable
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from cognic_agentos.portal.api.ui.dto import (
    ActionRequest, ActionResponse, ActionClass, ActionRejectionReason,
    UIActionContext, SubmitElicitationActionRequest,
)
from cognic_agentos.portal.api.ui.elicitation_gate import (
    evaluate_elicitation_submission, GateOutcome,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import _bind_actor, _emit_denial_or_500
from cognic_agentos.protocol.ui_events import UIEventBroker, AppendResult
from cognic_agentos.protocol.elicitation_adapter import ElicitationAdapter
from cognic_agentos.core.policy.engine import OPAEngine
from cognic_agentos.core.canonical import canonical_bytes   # P1 #6: correct import path
import hashlib
import logging

_LOG = logging.getLogger(__name__)


def RequireUIAction(broker: UIEventBroker) -> Callable[..., Awaitable[UIActionContext]]:
    """P1 #2: RequireUIAction LIVES HERE (action_routes.py), NOT in dto.py.
    The dep parses the body + binds actor + maps action_class → ui.action.<class>
    + enforces + emits policy.rbac_denied + returns UIActionContext."""
    async def _resolve(
        request: Request,                                # P1 #3: explicit Request param
        body: ActionRequest = Body(...),                 # Pydantic discriminated-union parse
        actor: Actor = Depends(_bind_actor),             # async, sync binder.bind preserved
    ) -> UIActionContext:
        request_id = request.state.request_id            # middleware-guaranteed on /api/v1/*
        required_scope = f"ui.action.{body.action_class}"
        if required_scope not in actor.scopes:
            _LOG.warning(
                "portal.rbac.scope_not_held",
                extra={"reason": "scope_not_held", "actor_subject": actor.subject,
                       "required_scope": required_scope, "request_id": request_id,
                       "tenant_id": actor.tenant_id},
            )
            await _emit_denial_or_500(
                broker, denial_type="scope_not_held",
                actor_subject=actor.subject, tenant_id=actor.tenant_id,    # P1 #5
                request_id=request_id, http_status=403, required_scope=required_scope,
            )
            raise HTTPException(403, detail={"reason": "scope_not_held",
                                             "required_scope": required_scope})
        return UIActionContext(body=body, actor=actor, request_id=request_id)
    return _resolve


_STUB_REASONS: dict[ActionClass, ActionRejectionReason] = {
    "approve":   "action_backend_deferred_to_sprint_13_5",
    "deny":      "action_backend_deferred_to_sprint_13_5",
    "cancel_run": "action_backend_deferred_no_run_primitive",
    "interrupt": "action_backend_deferred_sandbox_unwired",
    "resume":    "action_backend_deferred_sandbox_unwired",
}


def _payload_digest(body: ActionRequest) -> str:
    """sha256 of canonical_bytes of the VALIDATED DTO (post-Pydantic-parse)
    per spec §4.4g. Sensitive fields enter the hash but never appear plaintext."""
    return f"sha256:{hashlib.sha256(canonical_bytes(body.model_dump(mode='json'))).hexdigest()}"


def build_action_routes(
    *, broker: UIEventBroker,
    elicitation_adapter: ElicitationAdapter | None = None,
    rego_engine: OPAEngine | None = None,
) -> APIRouter:
    router = APIRouter()

    @router.post("/actions", response_model=ActionResponse, status_code=200)
    async def submit_action(
        ctx: UIActionContext = Depends(RequireUIAction(broker)),
    ) -> ActionResponse:
        body = ctx.body
        actor = ctx.actor
        request_id = ctx.request_id
        digest = _payload_digest(body)

        # Step 2: append frontend_action.submitted (always — audit completeness)
        submitted = await broker.append_frontend_action_submitted(
            request_id=request_id,
            action_class=body.action_class,
            actor_subject=actor.subject,
            client_correlation_id=body.client_correlation_id,
            payload_digest=digest,
            tenant_id=actor.tenant_id,
            elicitation_mode=body.mode if body.action_class == "submit_elicitation" else None,
        )

        # Step 3-4: per-class dispatch
        if body.action_class == "submit_elicitation":
            gate = await evaluate_elicitation_submission(
                request=body, actor=actor,
                adapter=elicitation_adapter, rego_engine=rego_engine,
            )
            if not gate.allowed:
                resolution = await broker.append_frontend_action_rejected(
                    request_id=request_id, action_class=body.action_class,
                    actor_subject=actor.subject, client_correlation_id=body.client_correlation_id,
                    submitted_event_id=submitted.event_id, reason=gate.reason,
                    tenant_id=actor.tenant_id, elicitation_mode=body.mode,
                    originating_decision_record_id=(
                        str(gate.ctx.originating_decision_record_id) if gate.ctx else None
                    ),
                )
                return _build_response(
                    request_id, body, "rejected", gate.reason,
                    submitted.event_id, resolution.event_id,
                )
            # Gate green → call adapter.handle_submission
            try:
                payload = body.form_payload if body.mode == "form" else body.url_completion_signal
                await elicitation_adapter.handle_submission(
                    ctx=gate.ctx, mode=body.mode, payload=payload or {},
                )
            except Exception:
                _LOG.error("ui.elicitation.handle_submission_failed", exc_info=True)
                resolution = await broker.append_frontend_action_rejected(
                    request_id=request_id, action_class=body.action_class,
                    actor_subject=actor.subject, client_correlation_id=body.client_correlation_id,
                    submitted_event_id=submitted.event_id, reason="elicitation_backend_failed",
                    tenant_id=actor.tenant_id, elicitation_mode=body.mode,
                    originating_decision_record_id=str(gate.ctx.originating_decision_record_id),
                )
                return _build_response(
                    request_id, body, "rejected", "elicitation_backend_failed",
                    submitted.event_id, resolution.event_id,
                )
            resolution = await broker.append_frontend_action_accepted(
                request_id=request_id, action_class=body.action_class,
                actor_subject=actor.subject, client_correlation_id=body.client_correlation_id,
                submitted_event_id=submitted.event_id, tenant_id=actor.tenant_id,
                elicitation_mode=body.mode,
                originating_decision_record_id=str(gate.ctx.originating_decision_record_id),
            )
            return _build_response(
                request_id, body, "accepted", None,
                submitted.event_id, resolution.event_id,
            )

        # 5 stub paths
        stub_reason = _STUB_REASONS[body.action_class]
        resolution = await broker.append_frontend_action_rejected(
            request_id=request_id, action_class=body.action_class,
            actor_subject=actor.subject, client_correlation_id=body.client_correlation_id,
            submitted_event_id=submitted.event_id, reason=stub_reason,
            tenant_id=actor.tenant_id,
        )
        return _build_response(
            request_id, body, "rejected", stub_reason,
            submitted.event_id, resolution.event_id,
        )

    return router


def _build_response(
    request_id, body, outcome, reason, submitted_event_id, resolution_event_id,
) -> ActionResponse:
    return ActionResponse(
        request_id=request_id,
        action_class=body.action_class,
        outcome=outcome,
        reason=reason,
        submitted_at=datetime.now(UTC),
        submitted_event_id=submitted_event_id,
        resolution_event_id=resolution_event_id,
        client_correlation_id=body.client_correlation_id,
    )
```

- [ ] **Step 4:** Run tests → iterate until PASS.

```bash
uv run pytest tests/unit/portal/api/ui/test_action_routes.py \
              tests/unit/portal/api/ui/test_action_routes_correlation_latency.py -v
# Expected: 20+ passed (6 discriminated-union + per-class scope + fail-closed + 5 stubs + submit_elic + event_id cursor + latency)
```

- [ ] **Step 5:** Threat-model-revert verifications:
  1. Remove try/except in `RequireUIAction`'s `_emit_denial_or_500` call → `TestRequireUIActionFailClosedOnEmitFailure` fails → restore.
  2. Comment out the `frontend_action.submitted` append before gate → `TestStubsReturn200WithDeferredReason` (which asserts 2 chain rows) fails → restore.

- [ ] **Step 6:** Halt-before-commit + commit.

```bash
git add src/cognic_agentos/portal/api/ui/action_routes.py \
        tests/unit/portal/api/ui/test_action_routes.py \
        tests/unit/portal/api/ui/test_action_routes_correlation_latency.py
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -F - <<'EOF'
feat(sprint-7b4): T11 — action_routes.py: POST /actions + RequireUIAction + 6-class dispatch (CRITICAL CONTROLS)

- RequireUIAction LIVES HERE (P1 #2): FastAPI dep parses body → binds actor →
  maps action_class → ui.action.<class> → enforces → emits policy.rbac_denied
  (with explicit tenant_id from actor) → returns UIActionContext. Fail-closed
  500 on emit failure (P1 #4 sync binder preserved).
- 7-step handler pipeline: dep → submitted append (always — audit completeness)
  → gate (submit_elicitation) → backend dispatch → resolution append → typed
  projection → response with deterministic event_id cursors
- 5 stub paths return 200 + outcome=rejected + closed-enum deferred reason;
  submit_elicitation full E2E when adapter wired (else elicitation_backend_unwired)
- payload_digest = sha256(canonical_bytes(body.model_dump)) over VALIDATED DTO
- Deterministic correlation-latency test (asyncio.wait_for 0.2s), not P99-of-N

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
```

---

## T12 — well_known_routes.py + router.py + create_app wiring

**Files:**
- Create: `src/cognic_agentos/portal/api/ui/well_known_routes.py`
- Create: `src/cognic_agentos/portal/api/ui/router.py`
- Modify: `src/cognic_agentos/portal/api/app.py` (create_app wires broker + adapter + rego_engine)
- Create: `tests/unit/portal/api/ui/test_well_known_routes.py`

**CC classification:** NOT-CC (scaffolding + schema publication; snapshot-pinned drift regression covers it). **Halt-before-commit:** NO.

**Acceptance:**
- `GET /.well-known/cognic-ui-events.json` returns `schema_version` + 11-family JSON schema + 9-family `wave_1_sse_streamed` subset tag.
- `Cache-Control: public, max-age=300, immutable` header.
- Snapshot-pinned drift regression.
- `build_ui_routes(*, broker, elicitation_adapter, rego_engine)` composes stream + action routes under `/api/v1/ui`.
- `register_well_known_routes(parent_app)` mounts at root (NOT under `/api/v1/ui/`).
- `create_app(*, broker, elicitation_adapter=None, rego_engine=None, ...)` threads the new deps + the request-id middleware.

**Steps:**

- [ ] **Step 1:** Write failing tests at `tests/unit/portal/api/ui/test_well_known_routes.py`:

```python
"""Sprint 7B.4 T12 — /.well-known/cognic-ui-events.json publication + snapshot drift."""
# R13 #4: `import json` removed — every JSON-decode in this file uses the
# httpx Response `r.json()` method (not the `json` module); the only literal
# "json" string is the URL path. Ruff F401 would refuse the unused import.
import pytest
from pathlib import Path
# R10 #3: `import httpx` removed — every request path uses `_async_client(...)`
# after the R9 #1 sweep; bare `httpx` not referenced in this file.
from tests.unit.portal.api.ui.sse_test_helpers import _async_client  # R10 #3: ASGITransport wrapper


class TestWellKnownEndpoint:
    @pytest.mark.asyncio
    async def test_returns_200_unauth(self, app):
        async with _async_client(app) as c:
            r = await c.get("/.well-known/cognic-ui-events.json")  # no auth header
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_cache_control_immutable(self, app):
        async with _async_client(app) as c:
            r = await c.get("/.well-known/cognic-ui-events.json")
        assert r.headers["cache-control"] == "public, max-age=300, immutable"

    @pytest.mark.asyncio
    async def test_body_has_schema_version(self, app):
        async with _async_client(app) as c:
            r = await c.get("/.well-known/cognic-ui-events.json")
        body = r.json()
        assert body["schema_version"] == "1.0"

    @pytest.mark.asyncio
    async def test_body_has_11_families(self, app):
        from cognic_agentos.protocol.ui_events import _WAVE_1_FAMILIES
        async with _async_client(app) as c:
            r = await c.get("/.well-known/cognic-ui-events.json")
        body = r.json()
        assert set(body["families"]) == _WAVE_1_FAMILIES

    @pytest.mark.asyncio
    async def test_body_has_9_family_wave_1_sse_streamed_subset(self, app):
        from cognic_agentos.protocol.ui_events import _SSE_WAVE_1_STREAMED_FAMILIES
        async with _async_client(app) as c:
            r = await c.get("/.well-known/cognic-ui-events.json")
        body = r.json()
        assert set(body["wave_1_sse_streamed"]) == _SSE_WAVE_1_STREAMED_FAMILIES


class TestSchemaSnapshotPinned:
    """Drift detector — any Pydantic model change that affects the schema
    requires a deliberate snapshot update."""

    @pytest.mark.asyncio
    async def test_schema_matches_committed_snapshot(self, app):
        snapshot_path = Path("tests/unit/portal/api/ui/well_known_schema_snapshot.json")
        async with _async_client(app) as c:
            r = await c.get("/.well-known/cognic-ui-events.json")
        live = r.text
        if not snapshot_path.exists():
            snapshot_path.write_text(live)
            pytest.fail("snapshot created — commit and re-run")
        assert live == snapshot_path.read_text()


class TestNotUnderApiV1UI:
    """RFC 8615 — .well-known must register at root, not under /api/v1/ui/."""

    @pytest.mark.asyncio
    async def test_route_not_under_api_v1_ui_prefix(self, app):
        paths = [r.path for r in app.routes]
        assert "/.well-known/cognic-ui-events.json" in paths
        assert "/api/v1/ui/.well-known/cognic-ui-events.json" not in paths
```

- [ ] **Step 2:** Run → FAIL.

- [ ] **Step 3:** Implement `well_known_routes.py`:

```python
"""Sprint-7B.4 T12 — portable JSON schema publication per ADR-020 §6."""
from fastapi import APIRouter, FastAPI
from fastapi.responses import JSONResponse
import pydantic
from typing import Any
from cognic_agentos.protocol.ui_events import (
    _WAVE_1_FAMILIES, _SSE_WAVE_1_STREAMED_FAMILIES,
    # the 11 Wave-1 family models
    AgentRunStarted, AgentRunCompleted, ToolCallRequested, ArtifactStarted,
    ApprovalPending, InterruptRequestedByAgent, FrontendActionSubmitted,
    MemoryRecallStarted, DecisionAuditEventAppended, PolicyDecisionEvaluated,
    PolicyRBACDenied, # ...all model classes for schema generation
)

_SCHEMA_VERSION = "1.0"


def register_well_known_routes(app: FastAPI) -> None:
    """Register the .well-known endpoint DIRECTLY at root (NOT under /api/v1/ui/)."""

    @app.get("/.well-known/cognic-ui-events.json", include_in_schema=False)
    async def cognic_ui_events_schema() -> JSONResponse:
        schema = _build_schema()
        return JSONResponse(
            content=schema,
            headers={"Cache-Control": "public, max-age=300, immutable"},
        )


def _build_schema() -> dict[str, Any]:
    return {
        "schema_version": _SCHEMA_VERSION,
        "families": sorted(_WAVE_1_FAMILIES),
        "wave_1_sse_streamed": sorted(_SSE_WAVE_1_STREAMED_FAMILIES),
        "events": _build_events_schema(),
    }


def _build_events_schema() -> dict[str, Any]:
    """Produce JSON Schema for each Wave-1 event-family discriminated union.
    Uses pydantic.TypeAdapter(...).json_schema() per family — the 11 family-union
    types live in protocol/ui_events.py (`_AgentRunEvent`, `_ToolCallEvent`, ...).
    Returns {family_name: <JSON-schema-dict>}."""
    from cognic_agentos.protocol.ui_events import (
        _AgentRunEvent, _ToolCallEvent, _SubagentEvent, _ApprovalEvent,
        _ArtifactEvent, _InterruptEvent, _FrontendActionEvent, _MemoryEvent,
        _DecisionAuditEvent, _PolicyEvent, _KillSwitchEvent,
    )
    family_unions = {
        "agent_run": _AgentRunEvent,
        "tool_call": _ToolCallEvent,
        "subagent": _SubagentEvent,
        "approval": _ApprovalEvent,
        "artifact": _ArtifactEvent,
        "interrupt": _InterruptEvent,
        "frontend_action": _FrontendActionEvent,
        "memory": _MemoryEvent,
        "decision_audit": _DecisionAuditEvent,
        "policy": _PolicyEvent,
        "kill_switch": _KillSwitchEvent,
    }
    return {
        family_name: pydantic.TypeAdapter(union_type).json_schema()
        for family_name, union_type in family_unions.items()
    }
```

- [ ] **Step 4:** Implement `router.py` (composition factory):

```python
"""Sprint-7B.4 T12 — build_ui_routes factory composes stream + action sub-routers."""
from fastapi import APIRouter
from cognic_agentos.portal.api.ui.stream_routes import build_stream_routes
from cognic_agentos.portal.api.ui.action_routes import build_action_routes
from cognic_agentos.protocol.ui_events import UIEventBroker
from cognic_agentos.protocol.elicitation_adapter import ElicitationAdapter
from cognic_agentos.core.policy.engine import OPAEngine


def build_ui_routes(
    *, broker: UIEventBroker,
    elicitation_adapter: ElicitationAdapter | None = None,
    rego_engine: OPAEngine | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/api/v1/ui")
    router.include_router(build_stream_routes(broker=broker))
    router.include_router(
        build_action_routes(broker=broker,
                            elicitation_adapter=elicitation_adapter,
                            rego_engine=rego_engine),
    )
    return router
```

- [ ] **Step 5:** Extend `portal/api/app.py` `create_app` to thread the new deps + include router:

```python
# R3 #3: keep ALL T6+T12 deps as None-default optional, mirroring the
# Sprint 7B.3 T9 trust_gate / trust_root_resolver precedent. Existing pack-only
# callers that omit the new deps still construct a valid app; UI routes simply
# don't mount.
def create_app(
    settings: Settings | None = None,
    *,
    # ... existing optional deps (adapter_registry, gateway_ledger, plugin_registry,
    # actor_binder, pack_record_store, trust_gate, trust_root_resolver) UNCHANGED ...
    # Sprint-7B.4 T6 deps (added there; UNCHANGED here):
    decision_history_store: DecisionHistoryStore | None = None,
    audit_store: AuditStore | None = None,
    ui_event_emitter: "UIEventEmitter | None" = None,
    # NEW Sprint-7B.4 T12 deps (same None-default pattern):
    elicitation_adapter: ElicitationAdapter | None = None,
    rego_engine: OPAEngine | None = None,
) -> FastAPI:
    app = FastAPI()
    # ... existing setup unchanged ...

    # T6 already constructed the broker IF its mandatory deps are all wired
    # (decision_history_store + ui_event_emitter + settings). T12 only adds
    # the elicitation_adapter + rego_engine attachments + the UI router mount —
    # and ONLY when the broker actually exists. Pack-only deployments (or test
    # fixtures that omit the new deps) get app.state.ui_event_broker = None and
    # NO UI router mount; pack routes continue working unchanged.
    app.state.elicitation_adapter = elicitation_adapter
    app.state.rego_engine = rego_engine
    app.state.decision_history_store = decision_history_store
    app.state.settings = settings

    broker: UIEventBroker | None = app.state.ui_event_broker   # may be None for pack-only callers
    if broker is not None:
        ui_router = build_ui_routes(
            broker=broker,
            elicitation_adapter=elicitation_adapter,
            rego_engine=rego_engine,
        )
        app.include_router(ui_router)
        register_well_known_routes(app)        # mounts /.well-known at root (only when UI mounted)

    return app
```

**Backward-compat regression** at `tests/unit/portal/api/test_create_app_backward_compat.py`:

```python
class TestCreateAppPackOnlyDeploymentStillWorks:
    """R3 #3 — existing pack-only callers omit T6+T12's new optional deps;
    create_app must still construct a valid FastAPI app with NO UI routes mounted."""

    def test_pack_only_app_omits_ui_routes(self):
        app = create_app(
            settings=Settings(),
            # No decision_history_store / ui_event_emitter / elicitation_adapter / rego_engine
        )
        paths = [r.path for r in app.routes]
        # UI routes should NOT be mounted
        assert not any(p.startswith("/api/v1/ui/") for p in paths)
        assert "/.well-known/cognic-ui-events.json" not in paths
        # Pack routes (if any wired via pack_record_store) still mount


class TestCreateAppWithUIDepsMountsUIRoutes:
    def test_full_ui_app_mounts_ui_routes(self, sqlite_engine):
        from cognic_agentos.core.audit import AuditStore
        from cognic_agentos.core.decision_history import DecisionHistoryStore
        from cognic_agentos.protocol.ui_events import UIEventEmitter
        audit = AuditStore(sqlite_engine)
        dh = DecisionHistoryStore(sqlite_engine)
        emitter = UIEventEmitter(audit_store=audit, decision_history_store=dh)
        app = create_app(
            settings=Settings(),
            decision_history_store=dh,
            audit_store=audit,
            ui_event_emitter=emitter,
        )
        paths = [r.path for r in app.routes]
        assert any(p.startswith("/api/v1/ui/") for p in paths)
        assert "/.well-known/cognic-ui-events.json" in paths
```

- [ ] **Step 6:** Run → PASS.

- [ ] **Step 7:** Commit.

```bash
git add src/cognic_agentos/portal/api/ui/well_known_routes.py \
        src/cognic_agentos/portal/api/ui/router.py \
        src/cognic_agentos/portal/api/app.py \
        tests/unit/portal/api/ui/test_well_known_routes.py \
        tests/unit/portal/api/ui/well_known_schema_snapshot.json
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -F - <<'EOF'
feat(sprint-7b4): T12 — well_known_routes + router + create_app full UI wiring

- /.well-known/cognic-ui-events.json: public unauth endpoint; schema_version
  1.0; 11-family JSON schema via pydantic.TypeAdapter; 9-family
  wave_1_sse_streamed subset tag; Cache-Control public/max-age=300/immutable
- Snapshot-pinned drift regression at well_known_schema_snapshot.json
- build_ui_routes(*, broker, elicitation_adapter, rego_engine) composition
  factory; mounted at /api/v1/ui by create_app
- create_app extended with elicitation_adapter + rego_engine threading;
  .well-known registered DIRECTLY on parent app at root (NOT under /api/v1/ui)
- T6's broker construction + middleware reused; T12 wires the rest

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
```

---

## T13 — AGENTS.md + critical-controls gate uplift 60 → 63 + AST architectural-arrow regressions

**Files:**
- Modify: `AGENTS.md` (NEW "Authoring — UI event-stream (Sprint 7B.4)" subsection + 3 stop-rule entries: `sampling.rego`, `supply_chain.rego`, `elicitation.rego`)
- Modify: `tools/check_critical_coverage.py` (+3 `_CRITICAL_FILES` entries + docstring section 60 → 63)
- Modify: `tests/unit/tools/test_check_critical_coverage.py` (count guard 60 → 63 + 7B.4 modules present + off-gate set extended)
- Create: `tests/architecture/test_ui_architectural_arrow.py` (6 AST-walk arrow regressions per spec §6)

**CC classification:** **CC** (touches `AGENTS.md` doctrine + critical-controls gate tool). **Halt-before-commit:** YES.

**Acceptance:**
- `_CRITICAL_FILES` gains 3 entries: `portal/api/ui/action_routes.py`, `portal/api/ui/stream_routes.py`, `portal/api/ui/elicitation_gate.py`.
- Docstring section block 60 → 63 mirroring 7B.3 T11 precedent.
- Count-guard self-test updated: `len(_CRITICAL_FILES) == 63`; 7B.4 modules present at `(0.95, 0.90)`; off-gate set extended with all the new NOT-CC modules.
- AGENTS.md 7B.4 subsection per spec §4 module-by-module; each bullet cites file:line.
- AGENTS.md "Stop rules" section gains 3 policy-bundle entries.
- `test_ui_architectural_arrow.py` 6 invariants per spec §6.

**Steps:**

- [ ] **Step 1:** Write the AST architectural-arrow regression suite at `tests/architecture/test_ui_architectural_arrow.py` (6 invariants per spec §6):

```python
"""Sprint 7B.4 T13 — AST-walk architectural-arrow regressions per spec §6."""
import ast
from pathlib import Path
import pytest


def _imports_of(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                out.add(node.module)
        elif isinstance(node, ast.Import):
            for n in node.names:
                out.add(n.name)
    return out


def _has_future_annotations(path: Path) -> bool:
    src = path.read_text()
    return "from __future__ import annotations" in src


class TestUIArchitecturalArrowInvariants:

    def test_invariant_1_protocol_ui_events_no_portal_or_fastapi(self):
        imports = _imports_of(Path("src/cognic_agentos/protocol/ui_events.py"))
        for forbidden in ("fastapi", "starlette", "sse_starlette"):
            assert not any(i.startswith(forbidden) for i in imports), \
                f"protocol/ui_events.py imports {forbidden}"
        assert not any(i.startswith("cognic_agentos.portal") for i in imports), \
            "protocol/ui_events.py imports portal"

    def test_invariant_2_protocol_elicitation_adapter_clean(self):
        imports = _imports_of(Path("src/cognic_agentos/protocol/elicitation_adapter.py"))
        for forbidden in ("fastapi", "starlette", "sse_starlette",
                          "cognic_agentos.portal", "cognic_agentos.protocol.mcp_host"):
            assert not any(i.startswith(forbidden) for i in imports), \
                f"protocol/elicitation_adapter.py imports {forbidden}"

    def test_invariant_3_elicitation_gate_no_httpexception_no_mcp_host(self):
        imports = _imports_of(Path("src/cognic_agentos/portal/api/ui/elicitation_gate.py"))
        # Allow fastapi types but NOT HTTPException-raising surface (gate is pure-functional)
        gate_src = Path("src/cognic_agentos/portal/api/ui/elicitation_gate.py").read_text()
        assert "HTTPException" not in gate_src, \
            "elicitation_gate.py must not raise HTTPException; HTTP mapping is in action_routes.py"
        assert not any(i.startswith("cognic_agentos.protocol.mcp_host") for i in imports)

    def test_invariant_4_action_routes_no_mcp_host_no_decision_history_store(self):
        imports = _imports_of(Path("src/cognic_agentos/portal/api/ui/action_routes.py"))
        assert not any(i.startswith("cognic_agentos.protocol.mcp_host") for i in imports)
        # Append seam centralization: action_routes does NOT import DecisionHistoryStore
        assert "DecisionHistoryStore" not in {i.split(".")[-1] for i in imports}, \
            "action_routes.py must NOT import DecisionHistoryStore — append goes through broker"

    @pytest.mark.parametrize("route_module", [
        "src/cognic_agentos/portal/api/ui/action_routes.py",
        "src/cognic_agentos/portal/api/ui/stream_routes.py",
        "src/cognic_agentos/portal/api/ui/well_known_routes.py",
        "src/cognic_agentos/portal/api/ui/router.py",
    ])
    def test_invariant_5_no_future_annotations_in_fastapi_route_modules(self, route_module):
        """Per P1 #1 fix in Section 6 — invariant applies ONLY to FastAPI route
        modules (NOT dto.py, NOT elicitation_gate.py which are pure helpers)."""
        assert not _has_future_annotations(Path(route_module)), \
            f"{route_module} must NOT have 'from __future__ import annotations' " \
            "(breaks FastAPI's inspect.signature on Annotated[..., Depends])"

    def test_invariant_6_every_chain_projector_passes_event_id_explicitly(self):
        """Every entry in _DECISION_HISTORY_TYPED_PROJECTORS must pass
        event_id=_chain_derived_event_id(...) explicitly, NOT default factory."""
        src = Path("src/cognic_agentos/protocol/ui_events.py").read_text()
        tree = ast.parse(src)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name.startswith("_project_"):
                # Find the event-class call and ensure event_id= keyword present
                returns_call = next(
                    (n for n in ast.walk(node) if isinstance(n, ast.Return) and
                     isinstance(n.value, ast.Call)),
                    None,
                )
                if returns_call:
                    kwargs = {kw.arg for kw in returns_call.value.keywords}
                    assert "event_id" in kwargs, \
                        f"_project_*: {node.name} must pass event_id=_chain_derived_event_id(...)"
```

- [ ] **Step 2:** Run AST regressions → verify they GUARD (all pass if T3-T12 are clean).

- [ ] **Step 3:** Add 3 new `_CRITICAL_FILES` entries to `tools/check_critical_coverage.py`:

```python
# tools/check_critical_coverage.py — _CRITICAL_FILES tuple

    # Sprint 7B.4 T13 — UI event-stream durable critical-controls modules.
    # action_routes.py: wire-protocol-public POST /actions + RequireUIAction.
    # stream_routes.py: reconnect-safe SSE transport + cursor validation +
    #                   cross-tenant invisibility.
    # elicitation_gate.py: substantive policy boundary (5-step gate +
    #                     10 fail-closed reasons + Rego eval bridge).
    ("src/cognic_agentos/portal/api/ui/action_routes.py", 0.95, 0.90),
    ("src/cognic_agentos/portal/api/ui/stream_routes.py", 0.95, 0.90),
    ("src/cognic_agentos/portal/api/ui/elicitation_gate.py", 0.95, 0.90),
```

- [ ] **Step 4:** Add the 7B.4 docstring section block to `tools/check_critical_coverage.py` mirroring the 7B.3 section block precedent (gate 55→60 → gate 60→63).

- [ ] **Step 5:** Extend `tests/unit/tools/test_check_critical_coverage.py` count guard:

```python
# tests/unit/tools/test_check_critical_coverage.py — update

_EXPECTED_ENTRY_COUNT = 63                       # was 60 at 7B.3 close
_SPRINT_7B4_GATE_MODULES = (
    "src/cognic_agentos/portal/api/ui/action_routes.py",
    "src/cognic_agentos/portal/api/ui/stream_routes.py",
    "src/cognic_agentos/portal/api/ui/elicitation_gate.py",
)
_SPRINT_7B4_OFF_GATE_MODULES = (
    "src/cognic_agentos/portal/api/ui/dto.py",
    "src/cognic_agentos/portal/api/ui/router.py",
    "src/cognic_agentos/portal/api/ui/well_known_routes.py",
    "src/cognic_agentos/protocol/elicitation_adapter.py",
)


def test_critical_files_count_is_63(gate_tool):
    assert len(gate_tool._CRITICAL_FILES) == 63


def test_sprint_7b4_modules_present(gate_tool):
    by_path = {p: (l, b) for p, l, b in gate_tool._CRITICAL_FILES}
    for m in _SPRINT_7B4_GATE_MODULES:
        assert m in by_path
        assert by_path[m] == (0.95, 0.90)


@pytest.mark.parametrize("off", _SPRINT_7B4_OFF_GATE_MODULES)
def test_sprint_7b4_off_gate_modules_absent(gate_tool, off):
    paths = {p for p, _, _ in gate_tool._CRITICAL_FILES}
    assert off not in paths
```

- [ ] **Step 6:** Threat-model-revert: temporarily drop one of the 3 7B.4 entries → count guard FAILS → restore → PASS.

- [ ] **Step 7:** Add the "Authoring — UI event-stream (Sprint 7B.4)" subsection to `AGENTS.md` after the 7B.3 subsection. Each bullet cites the module's role + closed-enum vocab + file:line — verified via `Read`/`grep` at compose time per `feedback_verify_code_citations_at_doc_write`.

```markdown
*Authoring — UI event-stream (Sprint 7B.4):*

- `protocol/ui_events.py` Sprint 7B.4 extension (per ADR-020 — extends the Sprint-6 typed event taxonomy with `UIEventBroker` primitive [FastAPI-free in-memory pub/sub], cursor encoder/decoder, 5-entry `_DECISION_HISTORY_TYPED_PROJECTORS` table, `RBACDenialType` 9-value protocol-owned Literal, `PolicyRBACDenied` event class, `_SSE_WAVE_1_STREAMED_FAMILIES` 9-family Final, `AppendResult` frozen dataclass with deterministic event_id resolved via task-scoped ContextVar capture from typed-event projection during awaited DecisionHistoryStore.append). ...)

- `portal/api/ui/elicitation_gate.py` (per ADR-020 §69-77 — pure-async `evaluate_elicitation_submission(...)` 5-step gate; ...)

- `portal/api/ui/action_routes.py` (per ADR-020 §22 — POST /api/v1/ui/actions; `RequireUIAction` dep [P1 #2 — lives here, NOT in dto.py]; ...)

- `portal/api/ui/stream_routes.py` (per ADR-020 §60-63 — 3 SSE GET endpoints; ...)
```

Plus AGENTS.md "Stop rules" gains 3 entries:

```markdown
- Stop rules (added at Sprint 7B.4 close):
  - `policies/_default/sampling.rego` (per ADR-015 + ADR-002 §"MCP sampling")
  - `policies/_default/supply_chain.rego` (per ADR-015 + ADR-016)
  - `policies/_default/elicitation.rego` (per ADR-015 + ADR-020 §69-77)
```

- [ ] **Step 8:** Run the full gate-tool + AST + count-guard slice → verify PASS.

```bash
uv run pytest tests/unit/tools/test_check_critical_coverage.py \
              tests/architecture/test_ui_architectural_arrow.py -v
# Expected: all green; count guard says 63
```

- [ ] **Step 9:** Halt-before-commit + commit.

```bash
git add AGENTS.md \
        tools/check_critical_coverage.py \
        tests/unit/tools/test_check_critical_coverage.py \
        tests/architecture/test_ui_architectural_arrow.py
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -F - <<'EOF'
feat(sprint-7b4): T13 — AGENTS.md 7B.4 subsection + critical-controls gate 60→63 + AST arrow regressions (CRITICAL CONTROLS)

- 3 new _CRITICAL_FILES entries: portal/api/ui/{action_routes,stream_routes,
  elicitation_gate}.py — final inventory 63 Python CC + 3 stop-rule policy
  bundles (sampling + supply_chain + elicitation)
- AGENTS.md: new "Authoring — UI event-stream (Sprint 7B.4)" subsection;
  Stop rules section gains the 3 policy-bundle entries
- 6 AST architectural-arrow regressions:
  1. protocol/ui_events.py no portal/fastapi/sse_starlette imports
  2. protocol/elicitation_adapter.py no portal/fastapi/mcp_host
  3. elicitation_gate.py no HTTPException + no mcp_host
  4. action_routes.py no mcp_host + no DecisionHistoryStore
  5. from __future__ import annotations forbidden ONLY in FastAPI route
     modules (NOT dto.py / elicitation_gate.py per P1 scope tighten)
  6. every chain projector passes event_id=_chain_derived_event_id(...)
- Count-guard self-test bumped 60→63; threat-model-revert verified

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
```

---

## T14 — Closeout + BUILD_PLAN §602 7B.4 CLOSED status flip

**Files:**
- Create: `docs/closeouts/2026-MM-DD-sprint-7b4-ui-event-stream-endpoints.md` (date set at commit time)
- Modify: `docs/BUILD_PLAN.md` §602 (NEW 7B.4 status row; mark Sprint 7B as a whole CLOSED)

**CC classification:** NOT-CC (chore docs). **Halt-before-commit:** NO.

**Acceptance:**
- Closeout mirrors 7B.3 closeout structure (13 sections).
- Records final state: 63 Python CC + 3 stop-rule policy bundles; suite size; 5 new closed-enum vocabularies + extensions; 10 deferred items.
- BUILD_PLAN §602: 7B.4 row CLOSED with branch tip + critical-controls floor 60 → 63 + 3 stop-rule additions.
- Sprint 7B closed in aggregate.

**Steps:**

- [ ] **Step 1:** Run the full suite + coverage to source the closeout's "Test + coverage state" numbers:

```bash
uv run pytest -q --cov=cognic_agentos --cov-branch --cov-report=json
# Capture: total passed/skipped/duration; per-module coverage for the 3 new CC entries
uv run python tools/check_critical_coverage.py
# Expected: gate passes; 63 modules at 95/90 floor
```

- [ ] **Step 2:** Write `docs/closeouts/2026-MM-DD-sprint-7b4-ui-event-stream-endpoints.md` mirroring the 7B.3 closeout structure (13 sections):

```markdown
# Sprint 7B.4 — UI Event-Stream Endpoints + RBAC Denial Chain Events (per ADR-020) — Closeout Note

**Date:** 2026-MM-DD (set at commit time)
**Sprints closed:** 7B.4 (3 SSE GET endpoints + POST /actions + portable JSON schema + submit_elicitation MCP-rules gate + policy.rbac_denied chain events promotion + UIEventBroker primitive + deterministic chain-derived event_id cursor + ElicitationAdapter Protocol + elicitation.rego stop-rule + UIRBACScope 8-value peer Literal + 5 new closed-enum vocabularies + 3 CC promotions).
**State:** READY-FOR-GATE on `feat/sprint-7b4-ui-event-stream-endpoints`. No push, no PR, no merge until explicit user authorization.
**Pre-T14 tip:** `<hash>` of T13 commit.
**Stack base:** `c53de7a` on `main` — Sprint 7B.3 PR #24. 7B.4 branches directly off merged main (not stacked).
**14 Sprint-7B.4 commits after T14 lands** atop `c53de7a`: T1 spec (6762cbc), T2 plan-of-record, T3 protocol foundation, T4 UIEventBroker primitive, T5 UIRBACScope, T6 async RBAC + middleware + broker wiring, T7 ElicitationAdapter Protocol, T8 elicitation.rego + elicitation_gate, T9 dto.py, T10 stream_routes.py, T11 action_routes.py, T12 well_known + router + create_app, T13 AGENTS.md + gate 60→63 + AST regressions, T14 closeout (this commit).

## What ships in `feat/sprint-7b4-ui-event-stream-endpoints` after Sprint 7B.4

### UI event-stream protocol primitive extensions (Sprint-7B.4 T3 + T4)
- `protocol/ui_events.py` extensions: cursor encoder/decoder; `RBACDenialType` 9-value Literal; `_SSE_WAVE_1_STREAMED_FAMILIES`; `AppendResult`; `UIEventBroker` class; ContextVar-based event_id capture; 5-entry `_DECISION_HISTORY_TYPED_PROJECTORS` table; `PolicyRBACDenied` event class.

### ElicitationAdapter Protocol (Sprint-7B.4 T7)
- `protocol/elicitation_adapter.py`: Protocol + `ElicitationContext` frozen dataclass + `KernelDefaultElicitationAdapter` fail-loud scaffold.

### 5-gate elicitation policy boundary (Sprint-7B.4 T8)
- `policies/_default/elicitation.rego`: Rego v1 default-deny; stop-rule artifact.
- `portal/api/ui/elicitation_gate.py`: pure-async 5-step gate (CC promotion).

### Action POST surface (Sprint-7B.4 T9 + T11)
- `portal/api/ui/dto.py`: 6-class discriminated-union DTOs + `ActionRejectionReason` 10-value Literal + `UIActionContext` + `SubmitElicitationActionRequest` model_validator.
- `portal/api/ui/action_routes.py`: `RequireUIAction` + 7-step pipeline + 5 stub paths + submit_elicitation gate routing.

### SSE transport (Sprint-7B.4 T10)
- `portal/api/ui/stream_routes.py`: 3 SSE GET endpoints + Last-Event-ID precedence + cursor validation + broker/generator-owned heartbeat + send_timeout half-open cleanup.

### Schema publication (Sprint-7B.4 T12)
- `portal/api/ui/well_known_routes.py`: public `/.well-known/cognic-ui-events.json` + snapshot drift detector.
- `portal/api/ui/router.py`: `build_ui_routes` factory.
- `portal/api/app.py`: extended `create_app`; request-id middleware on `/api/v1/*`.

### RBAC denial dual-surface emission (Sprint-7B.4 T6)
- `portal/rbac/{enforcement,tenant_isolation,human_actor,role_separation}.py`: sync→async conversion; `broker.emit_rbac_denial` dual-surface emit alongside the existing `_LOG.warning` (P1 #4 sync binder preserved; P1 #5 explicit tenant routing).
- `portal/rbac/scopes.py`: NEW 8-value `UIRBACScope` peer Literal.
- `portal/rbac/actor.py`: `Actor.scopes` widened to `frozenset[PackRBACScope | UIRBACScope]`.

### Settings (Sprint-7B.4 T4)
- `core/config.py`: 5 new UI-stream Settings fields with documented defaults.

### Critical-controls gate uplift (Sprint-7B.4 T13)
- `tools/check_critical_coverage.py`: +3 entries; 60 → 63; new docstring section block.
- AGENTS.md: new "Authoring — UI event-stream (Sprint 7B.4)" subsection + 3 stop-rule entries.

### AST architectural-arrow regressions (Sprint-7B.4 T13)
- `tests/architecture/test_ui_architectural_arrow.py`: 6 invariants per spec §6.

### Closeout + BUILD_PLAN §602 (Sprint-7B.4 T14 — this commit)

## CI / production-grade gates
[Table mirroring 7B.3 closeout]

## Doctrine adherence
[Per-task halt-before-commit log]

## New doctrines established Sprint-7B.4
- ContextVar-based broker append seam — event_id resolved from typed-event projection during awaited append without touching core/decision_history.
- Wave-1 SSE = decision-history-only (audit-event-backed events deferred to Wave-2).
- Mode parity for both modes (URL + form) in elicitation gate.
- Two-IDs-per-pack-POST contract: middleware-minted `portal-req-` for denials; handler-minted per-verb for handler chain rows.

## Test + coverage state
- Suite size: <SUITE_SIZE> (sourced from Step 1's pytest run)
- Per-file CC gate (63 modules at 95/90): all pass
- 3 new 7B.4 modules at 100% / 100%.

## ADR validation
[ADR-020 / ADR-015 / ADR-014 / ADR-017 / ADR-001 — implementation status]

## Final reference table
[Closed enums (a) + sweeps (b) + new CC (c-d) + cross-sprint touches (e) + deferred (f) + R-rounds (g)]

## Sprint 8 hand-off checklist
- Resumable Session API per ADR-004 amendment.
- The 7B.4 deferred items: PolicyBundleLoaded typed projector wiring; audit-event-backed SSE; real elicitation adapter; runtime approval engine (ADR-014 = Sprint 13.5); tenant data-governance policy store; real TrustRootResolver.

## Carryover
None. All T2-T13 deliverables landed.

## Out of scope (Sprint-7B.4 intentionally did NOT ship)
[10 items per spec §9]

## Next sprint
**Sprint 8 — Resumable Session API per ADR-004 amendment.** Sprint 7B is now closed in aggregate.
```

- [ ] **Step 3:** Update `docs/BUILD_PLAN.md` §602:
  - Add NEW 7B.4 CLOSED status row pointing to the T14 commit hash.
  - Remove the existing trailing "7B.4 (...) reserved for the owning sub-sprint" clause from the 7B.2 row (no longer reserved).
  - Mark Sprint 7B as a whole CLOSED.

```markdown
**7B.4 (UI event-stream endpoints + RBAC denial chain events):** **CLOSED** on `feat/sprint-7b4-ui-event-stream-endpoints` (2026-MM-DD; tip `<hash>`); critical-controls floor 60 → 63; 3 CC modules promoted (`portal/api/ui/action_routes.py` + `stream_routes.py` + `elicitation_gate.py`) + 1 new stop-rule policy bundle (`policies/_default/elicitation.rego`). Plus the 7B.3 carry-forward `policy.rbac_denied` chain events. Stacked directly on the merged Sprint-7B.2 / 7B.3 base (`c53de7a` on `main`). See [closeout note](closeouts/2026-MM-DD-sprint-7b4-ui-event-stream-endpoints.md). Branch READY-FOR-GATE awaiting push/PR/merge authorization.

**Sprint 7B is now CLOSED.** All 4 sub-sprints (7B.1 → 7B.4) shipped.
```

- [ ] **Step 4:** Stage + commit.

```bash
git add docs/closeouts/2026-MM-DD-sprint-7b4-ui-event-stream-endpoints.md \
        docs/BUILD_PLAN.md
git -c user.name=bmzee -c user.email=zaighum@msn.com commit -F - <<'EOF'
docs(sprint-7b4): T14 — Sprint 7B.4 closeout + BUILD_PLAN §602 status flip + Sprint 7B CLOSED

Sprint 7B.4 CLOSED on feat/sprint-7b4-ui-event-stream-endpoints
(14 commits T1-T14; READY-FOR-GATE).

- docs/closeouts/2026-MM-DD-sprint-7b4-ui-event-stream-endpoints.md (NEW):
  mirrors 7B.3 closeout structure (13 sections).
- docs/BUILD_PLAN.md §602: 7B.4 CLOSED row; Sprint 7B closed in aggregate
  (all 4 sub-sprints shipped).

Sprint state:
- critical-controls floor 60 → 63 + 3 stop-rule policy bundles
  (sampling + supply_chain + elicitation)
- 5 new closed-enum vocabularies; UIRBACScope 8-value peer Literal;
  RBACDenialType 9-value protocol-owned union
- full suite <N> passed / <M> skipped; gate passes (63 modules)

Next sprint: Sprint 8 (Resumable Session API per ADR-004 amendment).

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
```

---

## Self-Review patch log

This section appended per reviewer round during R-rounds (T2 → T3 onwards) following the 7B.3 plan-of-record precedent. Each round = numbered findings + patch applied to plan body + file-size delta.

### Round 0 — Initial draft

Initial 14-task plan-of-record drafted, mirroring the 7B.1/7B.2/7B.3 pattern. Spec source = `6762cbc`. T1 = spec commit (DONE). T2 = this plan commit. T3-T12 = substantive. T13 = AGENTS.md + gate uplift + AST regressions. T14 = closeout.

### Round 1 — User halt review (2026-05-15)

User identified 6 P1 blockers; all verified against the codebase before patching; all patched into the plan body above:

- **R1 #1 — Expand abbreviated task bodies before T2 (T8-T14).** Initial T8 said "abbreviated; full skeleton per spec §5b-d"; T9-T14 collapsed to "TDD per pattern; ~N steps." That's not a plan-of-record, especially after the spec went through 3 review rounds. **Patched:** every T8-T14 task now has concrete test code, failing-test command, implementation code, verification command, and explicit commit gate. Plan size grew from 1294 → ~2400 LoC.

- **R1 #2 — Keep RequireUIAction out of dto.py.** T9 originally placed `RequireUIAction` in `dto.py` while classifying the task as NOT-CC/type-only. `RequireUIAction` is FastAPI + RBAC + broker-coupled — placing it in dto.py would drag route/runtime dependencies into the DTO module and break the NOT-CC classification. **Patched:** `RequireUIAction` definitively lives in `portal/api/ui/action_routes.py` (T11). T9's body adds an explicit P1 #2 scope lock + an AST test (`TestDTOModuleHasNoRuntimeImports`) pinning that `dto.py` does NOT import `fastapi.Depends` / `broker primitives` / `Request`. The `UIActionContext` frozen dataclass stays in dto.py (type-only); RequireUIAction returns it.

- **R1 #3 — Wire broker before RBAC starts using it.** T6's `_bind_actor` reads `request.app.state.ui_event_broker`, but the original plan deferred all create_app wiring to T12. Executing in order means T6 tests / runtime would hit an unwired app state. **Patched:** T6 now includes the minimal broker construction + `app.state.ui_event_broker` attach + emitter registration + `reap_idle` lifespan task. T12 EXTENDS create_app with `elicitation_adapter` + `rego_engine` + UI router include + .well-known registration. T6's commit message records the split.

- **R1 #4 — Preserve sync ActorBinder contract.** Original T6 pseudocode changed `binder.bind(...)` to `await binder.bind(...)`, but `ActorBinder.bind` is sync (verified at `portal/rbac/actor.py:112`). Broadening the binder Protocol is out of scope for 7B.4 + would TypeError at runtime against existing test fixtures. **Patched:** `_bind_actor` itself is `async def` (so it can `await broker.emit_rbac_denial`), but it calls `binder.bind(request=request)` **synchronously — no `await`**. The existing `ActorBinder` Protocol is preserved. New test `TestSyncBinderContractPreserved` pins `inspect.iscoroutinefunction(ActorBinder.bind) is False`.

- **R1 #5 — RBAC denial events need explicit tenant routing.** Original `emit_rbac_denial` had `tenant_id="<unknown>"` default; T6 helper called it without passing a tenant. Result: tenant-filtered SSE subscribers would NOT receive RBAC denial events even when the actor tenant was known — defeats the Section 2/3 live-denial stream contract. **Patched:** `emit_rbac_denial` signature changed to `tenant_id: str | None` (EXPLICIT, no default). Each call site passes (a) `actor.tenant_id` when actor is resolved, OR (b) `tenant_id=None` when actor is unresolved (`actor_unauthenticated` / `actor_binder_not_configured`) — chain row carries NULL tenant; SSE filter rejects (Wave-1 unauth-not-on-stream contract; documented as a closeout "Out of scope" item). New `TestRBACDenialTenantRouting` regression pins both branches.

- **R1 #6 — Add Settings ownership for UI stream knobs.** The broker depends on `ui_event_stream_per_tenant_cap`, `ui_event_stream_queue_maxsize`, `ui_event_stream_idle_timeout_s`, `ui_event_stream_heartbeat_interval_s`, `ui_event_stream_send_timeout_s`, but no task owned adding those fields to Settings, with docs + tests. **Patched:** T4 expanded to include the 5 Settings field additions in `core/config.py` (NOT-CC — not on durable gate; verified), each with `Field(default=..., description=...)` per the module's existing pattern; new test file `tests/unit/core/test_config_ui_event_stream_fields.py` pins field count + default values + Pydantic validation (cap ≥ 1, etc.). File Structure table updated with the new core/config.py modification row + the new test file row.

**File size delta (R1):** plan grows from 1294 → ~2400 LoC. Every R1 finding has at least one new regression test or AST guard.

### Round 2 — User halt review (2026-05-16)

User identified 6 additional P1 blockers in the R1-expanded plan; all verified against the codebase before patching; all patched into the plan body above:

- **R2 #1 — Placeholder scan missed `...` ellipsis (T4/T8/T10/T12).** R1's self-review grep only checked TBD/TODO/FIXME/XXX, missing Python's ellipsis-as-placeholder pattern. Concrete sites: T4 had 3 stub projector functions (`_project_frontend_action_accepted/_rejected/_decision_evaluated` each `: ...`); T8's OPA fixture used `audit = ...` / `dh = ...`; T10 had 19 test bodies as `...` plus `_replay_from_decision_history` as `...`; T12's `_build_events_schema` was `...`. **Patched:** every `...` placeholder replaced with concrete implementation — T4 projectors mirror the established `_project_frontend_action_submitted` shape; T8 OPA fixture uses real `InMemoryAdapter` + `AuditStore` + `DecisionHistoryStore` construction (Sprint-4 T15 + Sprint-5 T6 precedent); T10 test bodies have concrete HTTP/SSE/broker exercise code; `_replay_from_decision_history` has full impl including ordinal walk + type-hash drift assertion + Wave-1 family filter; `_build_events_schema` uses `pydantic.TypeAdapter` over the 11 family-union types. The only remaining `...` (2 lines inside `ElicitationAdapter` Protocol) are idiomatic Python Protocol abstract-method markers, not placeholders.

- **R2 #2 — T7 remained skeletal under the writing-plans rubric.** R1 focused on T8-T14 expansion; T7 (`ElicitationAdapter` Protocol) still said "Write tests / Implement per spec / Commit" without test code, impl code, or verification commands. **Patched:** T7 expanded to full TDD form — 6 named test classes with concrete bodies (`TestElicitationModeLiteral` / `TestElicitationContextShape` / `TestElicitationResultShape` / `TestElicitationAdapterProtocol` / `TestKernelDefaultElicitationAdapter` / `TestModuleImportsClean`); concrete `elicitation_adapter.py` implementation; ruff/format/mypy verification commands; explicit git-add + commit message.

- **R2 #3 — `create_app` wiring assumed missing mandatory deps + would break existing callers.** T6's create_app extension referenced `decision_history_store` and `ui_event_emitter` as if they were already parameters, but the existing `create_app(settings: Settings | None = None, *, adapter_registry=None, gateway_ledger=None, plugin_registry=None, actor_binder=None, pack_record_store=None, trust_gate=None, trust_root_resolver=None)` does NOT accept them (verified). T12's signature rewrite would break every existing caller that omits the new deps. **Patched:** T6 now defines the backward-compatible seam explicitly — new keyword-only deps (`decision_history_store: DecisionHistoryStore | None = None`, `audit_store: AuditStore | None = None`, `ui_event_emitter: UIEventEmitter | None = None`) follow the Sprint 7B.3 T9 `trust_gate`/`trust_root_resolver` precedent (all None-default optional); broker construction is conditional on all 3 being provided; RBAC `_emit_denial_or_500` has a `broker is None` guard that skips the chain emit (log-only fallback) so existing test fixtures continue working; UI router only mounts when broker is non-None; T12 extends with `elicitation_adapter` + `rego_engine` using the same pattern.

- **R2 #4 — T4 commit omitted Settings changes.** T4's git-add block staged only `protocol/ui_events.py` + protocol tests; the new `core/config.py` Settings fields + `tests/unit/core/test_config_ui_event_stream_fields.py` would have been left uncommitted while the commit message claimed they shipped. **Patched:** T4 git-add block extended to include both files; commit subject extended to mention Settings fields explicitly.

- **R2 #5 — submit_elicitation resolution row keyset broke when ctx unknown.** Broker's `append_frontend_action_accepted/_rejected` conditionally included `originating_decision_record_id` only when non-None — meaning rows for `elicitation_backend_unwired` / `elicitation_unknown_id` paths (where ctx is None) silently dropped the field. That violates the closed-keyset contract from spec §5e + the `TestSubmitElicitationChainPayloadKeysetClosed` test would fail. **Patched:** when `elicitation_mode` is present in the call, BOTH `elicitation_mode` AND `originating_decision_record_id` are always added to the payload (the latter may be `None` literal — Python `None` serializes to JSON `null` per the chain row's canonical_form contract). Keyset stays closed across all 4 submit_elicitation resolution paths.

- **R2 #6 — `canonical_bytes` import was wrong syntactically.** T11's action_routes.py code block had `import canonical_bytes` which would import a top-level `canonical_bytes` module that doesn't exist; the function actually lives at `cognic_agentos.core.canonical.canonical_bytes`. Plan-as-written would TypeError at import time. **Patched:** corrected to `from cognic_agentos.core.canonical import canonical_bytes`.

**File size delta (R2):** plan grows from ~2400 → ~4200 LoC (concrete T7/T10 expansions + projector + OPA-fixture + replay + schema-builder concrete implementations dominate the increase). Plan is now executable end-to-end.

### Round 3 — User halt review (2026-05-16)

User identified 6 P1 execution-time API mismatches in the R2-expanded plan; all verified against the codebase before patching; all patched into the plan body above:

- **R3 #1 — Replay called nonexistent `DecisionHistoryStore` methods.** T10's `_replay_from_decision_history` used `store.load_at_sequence`, `store.current_chain_head_sequence`, `store.iter_rows_in_sequence_range` — none of which exist on the current `DecisionHistoryStore` (which exposes only `append`, `append_with_precondition`, `register_append_hook`, `_fire_append_hooks` per `core/decision_history.py:297-329`). **Patched:** rewrote `_replay_from_decision_history` to query the **exported `_decision_history` SQLAlchemy Table** (`core/decision_history.py:185` + `__all__` :632 — the supported public surface) directly via `select(...).where(sequence >= cursor).where(tenant_id == ...).order_by(sequence)`. No `core/decision_history.py` modification — pure consumer of the existing exported Table symbol. New `_DHReplaySnapshot` frozen dataclass mirrors the field shape `AppendedDecisionSnapshot` exposes to projector functions (live + replay snapshot-shape parity pinned by `TestReplaySnapshotShapeMatchesAppendedDecisionSnapshot`). T13 AST architectural-arrow regression updated: protocol→core import of `_decision_history` allowed; no portal imports remain forbidden.

- **R3 #2 — `_build_decision_audit_event_for_decision_history` was undefined.** R2 introduced calls to a helper that doesn't exist; the current Sprint-6 module builds the mirror inline at `ui_events.py:660` + `:684` within `_emit_generic_decision_audit_for_audit` / `_on_decision_append` bodies. Both replay AND live emit needed the same projection. **Patched:** defined `_build_decision_audit_for_dh_snapshot(snapshot) -> DecisionAuditEventAppended` in T4 as a small DRY helper; `_on_decision_append`'s inline `DecisionAuditEventAppended(...)` construction is replaced with a call to the new helper; `_replay_from_decision_history` calls the same helper → live + replay projection paths byte-identical (pinned by a new typed-projector test).

- **R3 #3 — T12 regressed `create_app` to mandatory keyword-only deps.** R2 fixed T6's signature with all-optional None-default deps; T12 then rewrote the signature with mandatory `store` / `decision_history_store` / `audit_store` / `ui_event_emitter` / `actor_binder` (no defaults) — reintroducing the exact caller-breakage R2 had fixed. **Patched:** T12 now strictly EXTENDS T6's signature by ADDING `elicitation_adapter: ElicitationAdapter | None = None` + `rego_engine: OPAEngine | None = None` (same None-default pattern as the 7B.3 T9 `trust_gate` / `trust_root_resolver` precedent). UI router mount + `.well-known` registration are both conditional on `broker is not None`; pack-only callers continue working with NO UI routes mounted. NEW `TestCreateAppPackOnlyDeploymentStillWorks` regression in `tests/unit/portal/api/test_create_app_backward_compat.py` pins the contract.

- **R3 #4 — Direct OPA fixture used a nonexistent adapter + wrong store constructor.** T8's fixture imported `cognic_agentos.db.adapters.in_memory_postgres.InMemoryAdapter` (doesn't exist — verified via `find src/cognic_agentos/db/adapters`: no `in_memory_postgres` file) and called `DecisionHistoryStore(engine=..., audit_store=...)` even though the verified constructor at `core/decision_history.py:309` is single-arg `def __init__(self, engine: AsyncEngine)`. **Patched:** rewrote the OPA fixture using the established Sprint-4 T15 + Sprint-5 T6 pattern from `tests/unit/core/policy/conftest.py`: `create_async_engine("sqlite+aiosqlite:///:memory:")` → `_metadata.create_all` → seed `_chain_heads` for both chains → `AuditStore(engine)` + `DecisionHistoryStore(engine)` (single-arg) → `OPAEngine(bundle_path=..., audit_store=audit, decision_history_store=dh)`.

- **R3 #5 — T8 `Decision(...)` calls omitted required `decision_data` field.** The verified `core.policy.engine.Decision` frozen dataclass at `:133-150` requires `decision_data: dict[str, Any] | None` as a 4th field; my T8 tests at lines 1866 / 1881 / 1898 instantiated with only `allow / rule_matched / reasoning` — would raise `TypeError: missing 1 required positional argument` at test setup. **Patched:** `decision_data=None` appended to all 3 `Decision(...)` constructions via `replace_all` edit; future Decision constructions in the plan body all carry the field.

- **R3 #6 — T10 `stream_routes.py` impl was missing imports it used.** Code block imported `APIRouter, Header, HTTPException, Query, Request` but route signatures used `Depends(...)` and the generator body used `asyncio.wait_for` / `asyncio.TimeoutError`. **Patched:** added `Depends` to the FastAPI import + added `import asyncio` at module top.

**File size delta (R3):** ~120 LoC additions across the affected sections (the SQLAlchemy replay impl + the OPA fixture rewrite + the helper definition + the backward-compat regression class are the biggest). Plan grows from ~4200 → ~4350 LoC.

### Round 4 — User halt review (2026-05-16)

User identified 5 P1/P2 execution-time blockers in the R3-patched plan; all verified against the codebase before patching; all patched into the plan body above:

- **R4 #1 — Replay used wrong `_decision_history` column names.** R3's read-seam direction was right, but the planned mapper read `row.decision_type` and `row.new_hash`. **Verified at `core/decision_history.py:185-203`:** the table columns are `event_type` (NOT `decision_type`) and `hash` (NOT `new_hash`). `decision_type` is the **DecisionRecord dataclass field name** which `DecisionHistoryStore.append` maps onto the `event_type` SQL column at write-time. **Patched:** the `_DHReplaySnapshot(...)` construction in `_replay_from_decision_history` now uses `decision_type=row.event_type` + `new_hash=row.hash` (the dataclass keeps its `decision_type` field for projector compatibility; mapping happens at the row→snapshot boundary). Also swept 3 test assertion sites (`TestRBACDenialDualSurfaceEmission`, `TestRequireUIActionEnforcesPerClassScope::test_deny_refused`, `TestStubsReturn200WithDeferredReason`) that asserted `row.decision_type == "..."` — updated to `row.event_type == "..."`.

- **R4 #2 — Direct OPA fixture seeded wrong `_chain_heads` columns.** Plan used `last_hash` / `last_sequence` + raw zero bytes. **Verified at `core/audit.py:100` + `tests/unit/core/policy/conftest.py:42-58`:** the canonical columns are `chain_id` / `latest_sequence` / `latest_hash` / `updated_at`; the canonical zero-hash constant is `ZERO_HASH` from `core.canonical`; `updated_at` is `datetime.now(UTC)`. **Patched:** rewrote the fixture to mirror `tests/unit/core/policy/conftest.py` exactly — `_chain_heads.insert().values(chain_id=..., latest_sequence=0, latest_hash=ZERO_HASH, updated_at=datetime.now(UTC))` for both `audit_event` + `decision_history` chains. Tested-against-precedent design — same shape that already works for sampling/supply_chain Rego tests.

- **R4 #3 — T10 test helpers + fixtures were undefined.** Several names (`_app_unauth`, `_iter_sse_events`, `_next_sse_event`, `emit_test_policy_event_and_memory_event`, `_read_recent_decision_history_rows`, `settings_low_cap`, `settings_short_send_timeout`, `actor_t1`, `app_with_broker`, `app`, `audit_store`, `decision_history_store`, `ui_event_emitter`, `broker`, `sqlite_engine`, `_FixtureActorBinder`) were referenced from test bodies but not defined anywhere. **Patched:** NEW `tests/unit/portal/api/ui/conftest.py` (a Step 1 prerequisite for T10) defines all 16 fixtures + helpers with concrete implementations — per-test sqlite engine + seeded chain heads, AuditStore + DecisionHistoryStore + UIEventEmitter + UIEventBroker construction, an Actor fixture wired to tenant `t1` with all 8 UI scopes, a `_FixtureActorBinder` that returns the actor (preserves the sync `ActorBinder.bind` contract from R2 #4), an `_app_unauth` helper that constructs a FastAPI app with an `ActorBinderUnauthenticated`-raising binder, async `_next_sse_event` / `_iter_sse_events` parsers for the streaming responses (handles the `id:` / `event:` / `data:` field framing + skips `:` comment keepalives), `_read_recent_decision_history_rows` SQLAlchemy direct-read helper using the same `_decision_history` Table seam as the production replay path (R3 #1 + R4 #1), and the `emit_test_policy_event_and_memory_event` test helper exercising `broker.emit_rbac_denial`. ~120 LoC of concrete fixture code.

- **R4 #4 — Executable ellipses in RBAC helper snippet.** The `_emit_denial_or_500` shown in T6 had `...` literally in its signature, log extras, broker call, and `HTTPException(500, ...)` — contradicting the R2/R3 claim that only Protocol abstract-method ellipses remained. **Patched:** rewrote the helper as concrete code with the FULL parameter list (`broker`, `denial_type`, `actor_subject`, `tenant_id`, `request_id`, `http_status`, plus optional `required_scope` / `pack_id` / `actor_type` / `pack_created_by` / `resource_type`) — matches the kwargs the 4 `Require*` deps actually need to pass. `log_extra` dict built incrementally with conditional optional keys; full `broker.emit_rbac_denial(...)` call with all kwargs threaded through; `HTTPException(500, detail={"reason": "rbac_denial_emit_failed"})` body explicit; R3 #3 backward-compat `if broker is None: return` log-only fallback preserved.

- **R4 #5 — Missing imports in test/snippet code (P2).** Plan had 3 copy-paste compile gaps: (1) `tests/unit/core/test_config_ui_event_stream_fields.py` used `pytest.raises` + `pydantic.ValidationError` without importing `pytest` (only imported `Settings`); (2) `tests/unit/portal/api/ui/test_elicitation_gate.py` used `dataclasses.replace(safe_ctx, ...)` at lines 1905/1917/1931 without importing `dataclasses`; (3) `portal/api/app.py` create_app snippet used `asyncio.sleep` / `asyncio.create_task` / `asyncio.CancelledError` without `import asyncio`. **Patched:** all 3 missing imports added at the top of their respective code blocks with inline `# R4 #5` comments documenting which symbols they enable.

**File size delta (R4):** ~155 LoC added (the new `conftest.py` definitions dominate; column-name corrections + import-fix lines are smaller). Plan grows from ~4350 → ~4500 LoC.

### Round 5 — User halt review (2026-05-16)

User identified 4 P1 pytest-scoping + test-mechanics blockers in the R4-patched plan; all verified against pytest documented behavior + the codebase before patching; all patched into the plan body above:

- **R5 #1 — conftest plain helpers are not in test module globals.** R4 claimed helpers in `conftest.py` were "available without explicit import." That's wrong — pytest only injects fixtures requested as test parameters; plain helper functions (`_next_sse_event`, `_iter_sse_events`, `_app_unauth`, `_read_recent_decision_history_rows`, `emit_test_policy_event_and_memory_event`, `_FixtureActorBinder`) defined at conftest.py module scope do NOT auto-inject into test files' namespace. **Patched:** split the plain helpers into a NEW dedicated module `tests/unit/portal/api/ui/sse_test_helpers.py` (per user's suggested route); each T10/T11/T12 test file now imports them explicitly via `from tests.unit.portal.api.ui.sse_test_helpers import _next_sse_event, ...`. The conftest.py is refactored to hold **only fixtures** (which DO auto-discover under pytest's normal directory-scoped fixture discovery).

- **R5 #2 — RBAC tests cannot see UI-local fixtures.** `tests/unit/portal/rbac/test_rbac_denial_chain_emission.py` is under a **sibling** directory from `tests/unit/portal/api/ui/conftest.py`; pytest's fixture-scoping is path-based (conftest.py applies to its directory + subdirs, NOT siblings). The T6 tests referenced `app_with_broker`, `_setup_denial_path`, `_read_recent_decision_history_rows` — none of which would resolve. **Patched:** NEW `tests/unit/portal/rbac/conftest.py` (~110 LoC) defines the T6-specific fixture block — `sqlite_engine`, `audit_store`, `decision_history_store`, `ui_event_emitter`, `broker`, `settings`, `actor_t1_with_pack_submit` (RBAC tests exercise pack-route denial paths; actor holds `pack.submit` / `pack.audit.read` NOT UI scopes — those are T10's UI actor's), `app_with_broker`, `_setup_denial_path`. Plain helpers come from the shared `sse_test_helpers` module via cross-directory absolute import (`from tests.unit.portal.api.ui.sse_test_helpers import _FixtureActorBinder, _read_recent_decision_history_rows`).

- **R5 #3 — `_app_unauth` signature mismatch + UI routes wouldn't mount.** Defined as `_app_unauth(broker, settings)` but called as `_app_unauth()` with no args — would TypeError. Even if signature were fixed, the body called `create_app(settings=settings, actor_binder=...)` without `decision_history_store` / `ui_event_emitter` — so R3 #3 backward-compat guards would skip the UI router mount → request to `/api/v1/ui/runs/run_1/events` 404s instead of exercising the intended 403 RBAC path. **Patched:** removed `_app_unauth` entirely. Replaced with **FastAPI `app.dependency_overrides` pattern**: tests use the existing `app_with_broker` fixture (which DOES have all UI deps wired → UI router IS mounted) + override `_bind_actor` per-test with a stub that raises `ActorBinderUnauthenticated`. The override is cleared in a `finally` block so it doesn't leak across tests. Concrete pattern documented inline in T10 + applied to `test_run_stream_rbac_required`.

- **R5 #4 — Async emit helper called without await.** `emit_test_policy_event_and_memory_event(broker)` is declared `async def` (it awaits `broker.emit_rbac_denial`) but the `TestFamilyFilter::test_families_query_param_filters_replay_and_live` test called it as `emit_test_policy_event_and_memory_event(broker)` (no `await`) — would produce an unawaited-coroutine warning, the chain row would never be appended, the SSE wait_for would time out. **Patched:** added `await` to the call site — `await emit_test_policy_event_and_memory_event(broker)`.

**Plus a T6 step-renumbering side-effect:** the new R5 #2 Step 1 (conftest) + Step 2 (write tests) means the old Steps 2-8 (run-FAIL → middleware → bind_actor → Require* → run-PASS → threat-model-revert → halt-and-commit) become Steps 3-9. Renumbered in place.

**File size delta (R5):** ~250 LoC added (the new `tests/unit/portal/rbac/conftest.py` block + the helper-module split duplication ~120 LoC + the `dependency_overrides` rewrite of `test_run_stream_rbac_required` + a few step renumberings). Plan grows from ~4500 → ~4750 LoC.

### Round 6 — User halt review (2026-05-16)

User identified 5 P1 task-ordering + fixture-ownership + test-mechanics blockers in the R5-patched plan; all verified against pytest documented behavior + the codebase before patching; all patched into the plan body above:

- **R6 #1 — T6 imported a helper module created only in T10.** R5 #1's split moved plain helpers to `tests/unit/portal/api/ui/sse_test_helpers.py` and had T10 create that file; R5 #2's new RBAC conftest at T6 imported from that module. Executing in order (T6 before T10) → ImportError at T6 test collection. **Patched:** moved the creation of `sse_test_helpers.py` + the UI conftest skeleton to T6 (alongside the RBAC conftest). T6 is now self-contained — creates all 3 test-support files (UI conftest + RBAC conftest + sse_test_helpers module) so the cross-directory import resolves at T6 execution. T10 may extend the UI conftest later if it needs SSE-specific fixtures, but the skeleton ships at T6.

- **R6 #2 — RBAC denial fixture had placeholder branches.** `_setup_denial_path` had `pass` branches for `scope_not_held` / `tenant_id_mismatch` + a `# ... other denial types similarly` placeholder, while the parametrized test iterated all 9 `RBACDenialType` values. **Patched:** rewrote the fixture as a 9-branch concrete dispatcher. Each branch sets up the specific app state (actor binder + scopes + tenant_id + actor_type) AND returns the `(method, path, kwargs)` tuple the test fires to trigger that denial path. The test consumes the return tuple and issues `c.request(method, path, **kwargs)`. Each branch is verified executable against the real RBAC dep chain (RequireScope / RequireTenantOwnership / RequireHumanActor / RequireDifferentActorThanCreator).

- **R6 #3 — RBAC app fixture missing `pack_record_store`.** `app_with_broker` called `create_app(...)` without `pack_record_store`. The existing `create_app` mounts pack routes only when both `actor_binder` and `pack_record_store` are provided. Tests would POST to `/api/v1/packs/drafts` and get 404 BEFORE hitting any RBAC denial path. **Patched:** NEW `pack_record_store` fixture in the RBAC conftest constructs a real `PackRecordStore(engine=sqlite_engine, history=decision_history_store)` against the same in-memory sqlite engine + threads it into `create_app(...)`. Also added 2 seeded-pack fixtures (`seeded_pack_t1` / `seeded_pack_t2`) so cross-tenant + role-separation denial paths have real pack records to operate on.

- **R6 #4 — `dependency_overrides[_bind_actor]` bypassed the exception mapping under test.** R5 #3 had tests override `_bind_actor` directly with a stub that raises `ActorBinderUnauthenticated`. But the REAL `_bind_actor` IS the code under test — its job is to CATCH that exception + map to 403 + emit the chain row. Replacing it entirely with the raising stub means none of that ran. **Patched (both sites — the T10 `test_run_stream_rbac_required` AND the T6 `_setup_denial_path`):** swap **`app.state.actor_binder`** with a binder whose `.bind()` raises the target exception. The real `_bind_actor` runs, calls `binder.bind(request=request)`, catches the exception, calls `_emit_denial_or_500`, and raises HTTPException(403). Both the binder swap and the actor_binder restore happen in the test's setup/teardown.

- **R6 #5 — New R5 files were not in File Structure table or commit gates.** `tests/unit/portal/rbac/conftest.py` + `tests/unit/portal/api/ui/sse_test_helpers.py` + `tests/unit/portal/api/ui/conftest.py` were defined in T6's body but not listed in the File Structure table at the top of the plan, nor in T6's git-add stage block. Following the plan literally would leave the files untracked. **Patched:** added all 3 files to the File Structure table (NEW rows under "Modified files" pointing to T6 ownership per R6 #1). T6's git-add block extended with the 3 new test-support files + a `tests/unit/portal/api/ui/__init__.py` marker.

**File size delta (R6):** ~200 LoC added (the 9-branch `_setup_denial_path` expansion + `pack_record_store` + seeded-pack fixtures + the actor-binder swap rewrites + the File Structure rows + the commit-stage updates). Plan grows from ~4750 → ~4950 LoC.

### Round 7 — User halt review (2026-05-16)

User identified 2 P1 storage-API + dispatcher-contract blockers in the R6-patched plan; all verified against the codebase before patching; all patched into the plan body above:

- **R7 #1 — Pack store fixture didn't match the real `PackRecordStore` API.** Verified at `src/cognic_agentos/packs/storage.py:491`: `PackRecordStore.__init__(self, engine: AsyncEngine)` is single-arg — NOT `PackRecordStore(engine=..., history=...)` as the R6 fixture had it. Verified at `:495`: `save_draft(self, record: PackRecord) -> uuid.UUID` takes a `PackRecord` OBJECT, not keyword fields. Also `PackKind` is a `Literal` (no Enum) so `PackKind.TOOL` doesn't exist — the string literal `"tool"` is correct. **Patched:** the `pack_record_store` fixture now calls `PackRecordStore(sqlite_engine)` single-arg. `seeded_pack_t1` + `seeded_pack_t2` fixtures now construct a `PackRecord(...)` with the full field set (`id=uuid.uuid4()`, `kind="tool"`, `pack_id=...`, `display_name=...`, `state="draft"` per the genesis guard at `save_draft`, `manifest_digest`, `signed_artefact_digest=None`, `sbom_pointer=None`, `tenant_id`, `created_by`, `last_actor`, `created_at`/`updated_at`), then `await pack_record_store.save_draft(record)` and return the record. Mirrors the established pattern at `tests/unit/portal/api/packs/test_operator_routes.py:204-219`.

- **R7 #2 — Test block didn't consume the dispatcher's `(method, path, kwargs)` return tuple.** R6 #2's `_setup_denial_path` returns the tuple, but the parametrized test (`TestRBACDenialDualSurfaceEmission`) and the 3 sibling tests (`TestRBACDenialTenantRouting::test_resolved_actor_passes_tenant_to_emit` + `test_unauthenticated_emits_with_tenant_none` + `TestRBACDenialFailClosedOnEmitFailure::test_emit_failure_raises_500_not_silent`) all called `_setup_denial_path(...)` ignoring the return value and hardcoded `c.post("/api/v1/packs/drafts", ...)`. That meant 8 of 9 denial branches were never exercised (the unauth/binder-unset cases — both pointing to `/packs/drafts` — would fire, but the 7 others that target different routes like `/packs/{id}/allow-list`, `/packs/{id}`, `/packs/{id}/claim`, `/packs/` would all 404 before reaching the denial dep). **Patched:** all 4 affected test methods updated to (a) capture `method, path, kwargs = _setup_denial_path(app_with_broker, denial_type)` and (b) issue `await c.request(method, path, **kwargs)` — exercising the actual denial path the dispatcher set up. Two of the tenant-routing tests had referenced separate (`_setup_scope_not_held_for_tenant_t1` / `_setup_unauthenticated` / `_setup_scope_not_held`) fixtures that R6 collapsed into the unified `_setup_denial_path`; those references now resolve correctly to the unified dispatcher.

**File size delta (R7):** ~70 LoC net (pack_record_store + 2 seeded-pack fixtures expanded with concrete PackRecord construction; 4 test methods refactored to use the dispatcher tuple). Plan grows from ~4950 → ~5020 LoC.

### Round 8 — User halt review (2026-05-16)

User identified 2 P1 blockers in the R7-patched plan; both verified against the codebase before patching; both patched into the plan body above:

- **R8 #1 — Seeded `PackRecord` still fails Pydantic validation; unused imports remain.** Verified at `src/cognic_agentos/packs/storage.py:378`: `signed_artefact_digest: bytes` (no Optional). The R7-fixed seeded-pack fixtures set `signed_artefact_digest=None` — that fails the model's field-type contract at construction time, so the `await pack_record_store.save_draft(record)` line in the fixture would raise `ValidationError` before any test body executes. Additionally, R7's import line `from cognic_agentos.packs.storage import PackRecordStore, PackRecord, PackState, PackKind` reached for `PackState` + `PackKind` symbols that R7's own fix made unnecessary (since `kind="tool"` and `state="draft"` are written as string literals, not Enum members) — ruff F401 would refuse the file on the unused symbols. **Patched** via two Edit operations: (a) `replace_all=true` on both `signed_artefact_digest=None` occurrences → `signed_artefact_digest=b"\x02" * 32,  # R8 #1: bytes, not None (field type is `bytes` at storage.py:378)`; (b) import line shortened to `from cognic_agentos.packs.storage import PackRecordStore, PackRecord  # R8 #1: PackState/PackKind are Literals, accessed as string values; no import needed (ruff F401)`.

- **R8 #2 — T6-owned helper files lacked task-local concrete code (pointed forward to T10).** Per R6 #1 the helper module + UI conftest are T6-owned files (T6 imports `_FixtureActorBinder` from `sse_test_helpers.py`; the UI conftest sits next to it so pytest auto-loads it for the T6 RBAC suite). The R7-patched T6 body still said "See R5 entry in patch-log for the full code" + "See the T10 section + R5 patch-log for full code" — that's a forward-reference / task-hunting anti-pattern: T6 cannot be executed standalone without reading the patch-log and T10. **Patched** by inlining both files' full content at T6 (replacing the prose pointers with the ~120-LoC `sse_test_helpers.py` module + the ~100-LoC `tests/unit/portal/api/ui/conftest.py` fixture module). Added a brief note at T10 clarifying that the helpers + UI conftest already shipped at T6 and T10 only adds the SSE test files — no duplication of the same code at T10.

**File size delta (R8):** ~220 LoC net (T6 body absorbs the two concrete code blocks that previously lived only at T10 / patch-log; the two `signed_artefact_digest` line replacements + one import line are byte-neutral). Plan grows from ~5020 → ~5240 LoC.

### Round 9 — User halt review (2026-05-16)

User identified 4 P1 blockers in the R8-patched plan; all verified against the codebase / git reality before patching; all patched into the plan body above:

- **R9 #1 — `httpx.AsyncClient(app=...)` does not work on httpx 0.28+.** Verified `uv.lock` line 571 pins `httpx == 0.28.1`; the `app` kwarg was removed in httpx 0.28 in favour of explicit transport wrapping (`httpx.AsyncClient(transport=httpx.ASGITransport(app=app), ...)`). The R8-patched plan contained **43 sites** using the legacy `httpx.AsyncClient(app=X, base_url="http://t")` form (T6 RBAC suite + T10 SSE suite + T11 action suite + T12 well-known suite). Every one would fail at test-collection with `TypeError: AsyncClient.__init__() got an unexpected keyword argument 'app'` BEFORE exercising any route. **Patched:** added a `_async_client(app, *, base_url="http://t")` helper at `tests/unit/portal/api/ui/sse_test_helpers.py` (T6-owned per R6 #1 / R8 #2) returning `httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base_url)`; ran 6 `replace_all=true` Edit operations on the 6 variable variants (`app` / `app_with_broker` / `app_with_scopes` / `app_with_only_approve` / `app_no_adapter` / `app_with_scopes_and_broker`) to replace `httpx.AsyncClient(app=X, base_url="http://t")` → `_async_client(X)`. Post-patch scan: 0 leftover sites; `_async_client(` appears 43+ times in code-block bodies. Added `_async_client` to the T10 test-file import list at line 3344.

- **R9 #2 — T10 `app_with_broker` fixture lacks UI routes; T10 SSE tests would 404 before exercising any handler.** Verified at the T6 conftest body: `app_with_broker` (and the previous `app` alias) called `create_app(...)` only — and `create_app` does not include `build_ui_routes(...)` until T12. T10 stream tests would receive `404 Not Found` for every `GET /api/v1/ui/runs/*/events` / `GET /api/v1/ui/tenants/*/events` / `GET /api/v1/ui/events/since/*` call. **Patched:** redefined the T6 `app` fixture body so it (a) depends on `app_with_broker` + `broker`, (b) lazy-imports `cognic_agentos.portal.api.ui.stream_routes.build_stream_routes` (lazy so T6 collection succeeds before T10 creates the module), and (c) `app_with_broker.include_router(build_stream_routes(broker=broker), prefix="/api/v1/ui")`. T6 RBAC tests continue using `app_with_broker` directly (no UI routes needed; they exercise pack-route denial paths). T10 SSE tests use `app` (UI routes mounted). Per the production-grade rule: NO silent fallback — if `app` is requested before T10 ships `stream_routes.py`, the lazy import raises `ImportError` (that IS the TDD RED). Updated the one `test_run_stream_rbac_required` test that was using `app_with_broker` on a UI route to use `app` instead.

- **R9 #3 — T10 Step 1 re-owned the T6 helper files (~210 LoC duplication contradicted the file table + commit gates).** R6 #1 + R8 #2 moved ownership of `sse_test_helpers.py` + `tests/unit/portal/api/ui/conftest.py` to T6; the R8 patches inlined their concrete code at T6. But the R8-patched T10 Step 1 (lines 3171-3387) ALSO contained the same ~210 LoC of code AGAIN — directly contradicting the "T6 owns these files" gate. The duplicate would have either (a) been written twice in two commits, or (b) silently dropped at T10 commit time creating a stale-doc / executable-drift hazard. **Patched:** replaced the entire T10 Step 1 prose + the two duplicate code blocks (`# tests/unit/portal/api/ui/sse_test_helpers.py` and `# tests/unit/portal/api/ui/conftest.py`) with a 7-line "REUSE T6-shipped files; NO new helper modules" Step 1. Source-of-truth pointer to the T6 section (and the R9 #1 `_async_client` + R9 #4 `emit_audit_tool_call_event` + R9 #2 `app` fixture additions baked in there). Post-patch scan: 0 occurrences of either filename header in the T10 Step-1 range (lines 3170-3300).

- **R9 #4 — T10 test block referenced two undefined names: `actor_in_tenant_t1` (fixture) + `emit_audit_tool_call_event` (helper).** Verified at line 3466 (now ~3325) — `test_cross_tenant_returns_404_invisible(self, app, actor_in_tenant_t1)` parameter name doesn't match any defined fixture; `actor_t1` IS defined in the T6 conftest. Verified at line 3544 (now ~3395) — `await emit_audit_tool_call_event(audit_store, tenant_id="t1")` references a helper that was never defined. Both would fail at pytest collection / first-execution: `fixture 'actor_in_tenant_t1' not found` + `NameError: name 'emit_audit_tool_call_event' is not defined`. **Patched:** (a) renamed the parameter `actor_in_tenant_t1` → `actor_t1` (matching the T6 conftest's defined fixture; inline `# R9 #4` comment kept for traceability); (b) added a concrete `emit_audit_tool_call_event(audit_store, *, tenant_id)` helper to the T6-shipped `sse_test_helpers.py` code block — body delegates to the audit-store append seam with fixed test request_id `portal-req-test-tool-call` + `actor_subject="u_test"`, payload `{"tool_name": "echo", "tool_call_id": "tc_test"}`, family/type pinned to `tool_call.started` per the protocol/ui_events Wave-1 family registry. Added `emit_audit_tool_call_event` to the T10 test-file import list at line 3349.

**File size delta (R9):** ~130 LoC net (T6 helpers block grows by ~40 LoC for two new helpers; T6 conftest `app` fixture grows by ~15 LoC for the lazy-mount; T10 Step 1 shrinks by ~210 LoC after removing the duplicate code blocks; six `replace_all` Edits and one import-list extension are byte-neutral except for the slight contraction of `httpx.AsyncClient(app=X, base_url="http://t")` → `_async_client(X)`). Plan moves from ~5240 → ~5170 LoC (NET CONTRACTION due to R9 #3 dedup).

**R9 verification scan (post-patch):**
- `grep -c "httpx.AsyncClient(app=" docs/superpowers/plans/2026-05-15-sprint-7b4-ui-event-stream-endpoints.md` → 3 hits, ALL in prose/docstrings (lines 1143 / 1170 / 3240) explaining the deprecation rationale. **0 hits in code-block bodies.**
- `grep -c "_async_client(" docs/superpowers/plans/2026-05-15-sprint-7b4-ui-event-stream-endpoints.md` → 43+ hits (T6 helper definition + T10/T11/T12 call sites).
- `grep -c "ASGITransport" docs/superpowers/plans/2026-05-15-sprint-7b4-ui-event-stream-endpoints.md` → 5 hits (1 helper body + 4 doc/comment references).
- `grep -c "actor_in_tenant_t1" docs/superpowers/plans/...` → 1 hit, the R9 patch-log comment + the inline traceability `# R9 #4: actor_t1 (not actor_in_tenant_t1)` only. **0 hits as a fixture parameter name.**
- `grep -c "emit_audit_tool_call_event" docs/superpowers/plans/...` → 5+ hits (1 helper definition at T6 + 1 import-list addition at T10 + 1 call site at T10 + R9 patch-log narrative + helper module docstring).
- `awk 'NR>=3170 && NR<=3300' docs/superpowers/plans/... | grep -c "^# tests/unit/portal/api/ui/sse_test_helpers"` → **0** (R9 #3 dedup confirmed).
- `awk 'NR>=3170 && NR<=3300' docs/superpowers/plans/... | grep -c "^# tests/unit/portal/api/ui/conftest"` → **0** (R9 #3 dedup confirmed).

### Round 10 — User halt review (2026-05-16)

User identified 5 P1 follow-on compile/API gaps from the R9 sweep; all verified against the codebase / git reality before patching; all patched into the plan body above:

- **R10 #1 — T6 RBAC test bodies use `_async_client(app_with_broker)` but the test file only imports `_read_recent_decision_history_rows`.** Verified at the T6 RBAC test file's two-code-block import header (lines ~1695-1707): after R9 #1's sweep replaced `httpx.AsyncClient(app=...)` → `_async_client(...)`, every `async with _async_client(app_with_broker) as c:` site in the T6 RBAC test bodies would raise `NameError: _async_client is not defined` at first execution. **Patched:** extended the import block to import BOTH helpers explicitly: `from tests.unit.portal.api.ui.sse_test_helpers import (_async_client, _read_recent_decision_history_rows)`. Also removed the now-dead `import httpx` from the second code block — after the R9 #1 sweep no test body references `httpx.X` directly (ruff F401 would refuse the unused import); replaced with a `# R10 #2: import httpx removed` traceability comment.

- **R10 #2 — T11 action-route test imports stale + missing.** Verified at lines 4040-4044: the planned imports were only `import pytest / import httpx / from cognic_agentos.portal.api.ui.dto import ActionRequest, ActionResponse`. But the T11 test bodies use `_async_client` (10+ sites), `_read_recent_decision_history_rows` (3 sites), `_next_sse_event` (1 site in the correlation-latency test at line 141 of T11 section), AND `asyncio.wait_for / asyncio.create_task` (the deterministic asyncio.wait_for(timeout=0.2) test). Test collection would fail with `NameError` before any assertion ran. **Patched:** added `import asyncio` to the top of the import block; added an explicit `from tests.unit.portal.api.ui.sse_test_helpers import (_async_client, _next_sse_event, _read_recent_decision_history_rows)` block beneath the dto import; removed dead `import httpx` (no `httpx.X` references remain in T11 test bodies post-R9 #1).

- **R10 #3 — T12 well-known test imports missing `_async_client`.** Verified at lines 4431-4436: planned imports were `import json / import httpx / import pytest / from pathlib import Path` only. After the R9 #1 sweep, every T12 test body uses `_async_client(app)` (6 sites). Test collection would fail with `NameError`. **Patched:** added `from tests.unit.portal.api.ui.sse_test_helpers import _async_client` to the import block; removed dead `import httpx` (no direct `httpx.X` references remain in T12 test bodies post-R9 #1).

- **R10 #4 — `emit_audit_tool_call_event` helper body called `AuditStore.append` with kwargs; the real seam takes a single `AuditEvent` object and `AuditEvent` has no `actor_subject` field.** Verified at `src/cognic_agentos/core/audit.py:298` — `async def append(self, event: AuditEvent) -> tuple[uuid.UUID, bytes]`. Verified at `src/cognic_agentos/core/audit.py:156-164` — `AuditEvent` fields are `event_type / request_id / payload / tenant_id / trace_id / span_id / langfuse_trace_id / provider_label / iso_controls`. No `actor_subject` at the row schema level — actor identity travels inside `payload` per the standard pattern in this repo. R9 #4's helper body would raise `TypeError: AuditStore.append() got an unexpected keyword argument 'event_type'` (or similar) at the first call site. **Patched:** rewrote the helper body to `from cognic_agentos.core.audit import AuditEvent` (lazy on-call import to keep top-level imports terse) and `await audit_store.append(AuditEvent(event_type="tool_call.started", request_id="portal-req-test-tool-call", tenant_id=tenant_id, payload={"tool_name": "echo", "tool_call_id": "tc_test", "actor_subject": "u_test"}))`. The `actor_subject` lookup moves from a top-level `AuditEvent` kwarg (doesn't exist) to a `payload` key (matches every other audit-emission site in the codebase).

- **R10 #5 — Stale `r.decision_type` on a SQLAlchemy row.** Verified at line 4156: `submitted_row = next(r for r in rows if r.decision_type == "frontend_action.submitted")`. Verified at `src/cognic_agentos/core/decision_history.py:195` — the `_decision_history` table column is named `event_type` (NOT `decision_type`). `_read_recent_decision_history_rows` returns raw SQLAlchemy rows whose attribute names match the column names; reading `r.decision_type` returns `None` on every dialect (SQLAlchemy Row uses `__getattr__` to project column labels, and there is no `decision_type` column). The `next(... if r.decision_type == "...")` chain would raise `StopIteration` because no row matches, and the test would fail with a misleading "no submitted row" error. **Patched:** changed to `r.event_type == "frontend_action.submitted"` with an inline `# R10 #5` comment citing the table-column source. R4 #1's prior pass swept three OTHER assertion sites for the same shape; this site escaped because it's an iteration-filter rather than a direct equality assertion. Full-plan sweep confirmed all other `.decision_type` references are legitimate `snapshot.decision_type` accesses on the `_DHReplaySnapshot` dataclass (which deliberately keeps that field name for projector compatibility per R4 #1, with the row→snapshot mapping at the boundary).

**File size delta (R10):** ~50 LoC net (5 import-block extensions sum to ~25 LoC; `emit_audit_tool_call_event` body grows by ~10 LoC for the AuditEvent construction + lazy import + docstring update; 1-line edit for `.decision_type` → `.event_type`; minor R10-traceability comments). Plan moves from ~5170 → ~5220 LoC.

**R10 verification scan (post-patch):**
- `grep -nE "AsyncClient\(app=" docs/superpowers/plans/...` → 5 hits, ALL in patch-log / docstring narrative; 0 in code-block bodies (carried over from R9 verification).
- `grep -n "decision_type" docs/superpowers/plans/...` → exactly 4 hits in code-block bodies, all legitimate `snapshot.decision_type` on the _DHReplaySnapshot dataclass (lines 900 / 920 / 945) + 1 docstring comment (line 1214). **0 SQL-row `.decision_type` reads remain.**
- `grep -n "audit_store.append" docs/superpowers/plans/...` → 1 call site in `emit_audit_tool_call_event` body, now passing `AuditEvent(...)`; 0 kwarg-form calls.
- T6 RBAC test imports: `_async_client` + `_read_recent_decision_history_rows` BOTH imported (R10 #1).
- T11 test imports: `asyncio` + `_async_client` + `_next_sse_event` + `_read_recent_decision_history_rows` all imported (R10 #2).
- T12 test imports: `_async_client` imported (R10 #3).
- Dead `import httpx` removed from T6 / T11 / T12 test files (R10 #2/#3 cleanup).

### Round 11 — User halt review (2026-05-16)

User identified 5 P1 executable-plan blockers in the R10-patched plan; all verified against the codebase / plan body before patching; all patched into the plan body above:

- **R11 #1 — Duplicate `_emit_denial_or_500` in Step 5 lacked the `broker is None` backward-compat guard.** The earlier code block at lines ~1905-1981 carries the canonical implementation with `if broker is None: return` log-only fallback (R3 #3 backward-compat for pack-only deployments). Step 5 at lines 2021-2043 redefined the helper as a "simplified" version that omitted the guard — the duplicate would have OVERRIDDEN the canonical version (last-def-wins in Python module namespace) AND turned every pack-only RBAC denial into a 500 by calling `broker.emit_rbac_denial` on `None` → `AttributeError` → caught by `except Exception` → 500 to client. **Patched:** removed the duplicate definition entirely; replaced with a 7-line traceability comment pointing Step 6 callers at the canonical helper at line ~1916. The Step 5 code block now contains ONLY `_bind_actor` (which the step header announces as its scope).

- **R11 #2 — T11 fixtures (`app_with_scopes`, `app_with_only_approve`, `app_no_adapter`, `app_with_scopes_and_broker`) never defined.** Verified that the 4 fixture names appear in 12+ test-method parameter lists across T11 (lines 4083, 4095, 4103, 4117, 4137, 4159, 4173, 4201, etc.) but NO `@pytest.fixture` definition exists anywhere in the plan. Tests would fail at collection with `fixture 'app_with_scopes' not found`. **Patched:** added a T11-local fixture block at the top of `test_action_routes.py` (after the imports) defining: (a) two `Actor` fixtures (`actor_t1_all_ui_scopes` + `actor_t1_only_approve`); (b) `_StubElicitationAdapter` class satisfying the Section-5 Protocol shape; (c) a shared `_build_t11_app` helper that lazy-imports `build_action_routes` (TDD RED before T11 ships the module), threads `elicitation_adapter` into `app.state`, and includes the action router at the `/api/v1/ui` prefix; (d) the 4 named fixtures wiring (scope set, elicitation_adapter wired?) variants. The `app_with_scopes_and_broker` variant additionally mounts `build_stream_routes` so the correlation-latency test's SSE subscription + action POST share the SAME broker instance (fixture scope=function guarantees that). All 4 fixtures defined T11-local (NOT in the T6-shipped UI conftest) so they don't leak fixture names into T10/T12 discovery.

- **R11 #3 — Correlation-latency test asserted `event["family"]` + `event["type"]` but `_next_sse_event` returns wrapper-shape `{id, event, data}`.** Verified at `sse_test_helpers._next_sse_event` (T6 code block, lines 1196-1208): the helper returns the SSE wrapper dict with keys `id` (SSE event-id header), `event` (SSE event-name header, the canonical `"<family>.<type>"` string per ADR-020), and `data` (parsed JSON payload). Reading `event["family"]` / `event["type"]` raises `KeyError` immediately at the assertion site — the test fails with a misleading "KeyError: 'family'" rather than the actual latency failure under test. **Patched:** rewrote lines 4214-4216 to `assert event["event"] == "frontend_action.submitted"` + `assert event["data"]["family"] == "frontend_action"` + `assert event["data"]["type"] == "submitted"` (kept the action_class assertion which was already correctly reading `event["data"]["action_class"]`). The 3-axis assertion covers BOTH the SSE event-name header AND the JSON body discriminators per spec §4.3. Full-plan sweep confirmed line 4214 was the ONLY site with this bug class (no other `event["family"]` / `event["type"]` top-level access).

- **R11 #4 — T10 shared boilerplate missing standard imports (`pytest`, `asyncio`, `from datetime import datetime, UTC`).** Verified at the T10 boilerplate block (line 3290-3303 → now 3293-3309): only the sse_test_helpers import was present. But T10 test bodies use `pytest.mark.asyncio` (every test), `pytest.parametrize` (lines 3614-3618 of T10 headers test), `pytest.raises(asyncio.TimeoutError)` (line 3415), `datetime.now(UTC)` (line 3655 of the heartbeat test), and `asyncio.wait_for` (line 3573 of the last-event-id test). Test collection / first-execution would fail with `NameError: pytest is not defined` (or asyncio/datetime/UTC) before any route is exercised. **Patched:** extended the shared-boilerplate block to `import asyncio` + `import pytest` + `from datetime import datetime, UTC` BEFORE the sse_test_helpers `from` import. Block now reads as a copy-paste-ready 4-line preamble + the helper-import block — matches the "Each T10 test file starts with this import block" header.

- **R11 #5 — Heartbeat test referenced nonexistent `freezer` fixture.** Verified at `pyproject.toml` + `uv.lock`: no `freezegun` / `pytest-freezer` dependency anywhere in the repo. Verified at line 3658 (now ~3678): test parameter `freezer` would fail at collection with `fixture 'freezer' not found`. Examined the test body: `freezer.move_to("2026-05-15T12:00:00Z")` would advance the wall clock, but the immediately-following line passes an EXPLICIT `datetime(2026, 5, 15, 12, 0, 0, tzinfo=UTC)` to `broker.reap_idle(...)` — `reap_idle` evaluates against that explicit argument, NOT wall clock. The `freezer.move_to` call was dead code (the test never reads wall clock again). **Patched:** removed the `freezer` parameter from the method signature; removed the `freezer.move_to(...)` call; added a 5-line docstring explaining why the frozen-clock rebase was dead. Test still uses absolute timestamps on `sub.last_activity_at` + the `broker.reap_idle(...)` argument to express "1 hour idle"; no wall-clock manipulation needed because `reap_idle` takes the evaluation timestamp as an explicit arg per its signature.

**File size delta (R11):** ~270 LoC net (T11 fixture block adds ~170 LoC concrete code; R11 #4 boilerplate adds ~3 LoC; R11 #3 grows by ~5 LoC for the doc comment + extra assertion; R11 #1 shrinks by ~20 LoC after dedup; R11 #5 shrinks by ~3 LoC). Plan moves from ~5220 → ~5490 LoC.

**R11 verification scan (post-patch):**
- `grep -cE "def _emit_denial_or_500" docs/superpowers/plans/...` → **1** (R11 #1 — only the canonical guarded definition at line ~1916).
- `grep -nE "def app_with_scopes\(|def app_with_only_approve\(|def app_no_adapter\(|def app_with_scopes_and_broker\(" docs/superpowers/plans/...` → 4 hits, all `@pytest.fixture`-decorated (R11 #2).
- `grep -c 'event\["family"\]' docs/superpowers/plans/...` → 0 top-level usages; `event\["data"\]\["family"\]` is correct nested access (R11 #3).
- `grep -c "import asyncio" docs/superpowers/plans/...` for T10 boilerplate → 1 hit at line ~3293 (R11 #4).
- `grep -c "freezer" docs/superpowers/plans/...` → 0 hits in test bodies; remaining hits are in the R11 #5 patch-log narrative only.

### Round 12 — User halt review (2026-05-16)

User identified 4 P1 follow-on executable mismatches in the R11-patched plan; all verified against the codebase / plan body before patching; all patched into the plan body above:

- **R12 #1 — `_build_t11_app` didn't wire the elicitation_adapter through the route factory, and `_StubElicitationAdapter` violated the locked Protocol shape.** Verified at line ~4452: `build_action_routes(*, broker, elicitation_adapter=None, rego_engine=None)` captures `elicitation_adapter` as a kwarg parameter — the factory closes over it at build-time. R11 #2's `_build_t11_app` body stored the adapter only on `app.state.elicitation_adapter` and called `build_action_routes(broker=broker)` (no adapter), so every submit_elicitation route resolved its captured `elicitation_adapter` to `None`. The `app_with_scopes` and `app_with_only_approve` fixtures appeared to wire the adapter but the route never saw it; only `app_no_adapter` (which intentionally passes `None`) behaved correctly. Separately verified at line 2292: the locked `ElicitationAdapter(Protocol)` declares EXACTLY two methods — `async def get_context(*, elicitation_id, tenant_id) -> ElicitationContext | None` and `async def handle_submission(*, ctx, mode, payload) -> ElicitationResult`. R11 #2's stub defined a single `submit(...)` method with the wrong signature; isinstance-against-runtime_checkable would refuse it. **Patched both:** (a) added `elicitation_adapter=elicitation_adapter` to the `build_action_routes(...)` call inside `_build_t11_app`; (b) rewrote `_StubElicitationAdapter` to implement BOTH locked Protocol methods — `get_context` returns a minimal `ElicitationContext` (verified field list at line 2266-2274: `elicitation_id`, `tenant_id`, `originating_pack_id`, `originating_decision_record_id: uuid.UUID`, `elicitation_modes: tuple[ElicitationMode, ...]`, `data_classes: tuple[str, ...]`); `handle_submission` returns a fresh `ElicitationResult(delivered_at=datetime.now(UTC), backend_correlation_id=f"stub-backend-{ctx.elicitation_id}")`. Tests that probe gate-refusal paths (`elicitation_context_not_found`, `elicitation_tenant_mismatch`) monkeypatch these methods per-test rather than relying on stub specialisation. Both `ElicitationContext` and `ElicitationResult` are imported lazily inside the methods so the stub's class body doesn't trip on T7's not-yet-shipped module at fixture-resolution time before T7 runs (Step-by-step ordering: T6 ships sse_test_helpers/conftest; T7 ships ElicitationAdapter Protocol + ElicitationContext + ElicitationResult; T11 wires the stub — the per-method lazy imports keep T11 fixture-module-import green at T6 collection time).

- **R12 #2 — Correlation-latency assertion read `event["data"]["action_class"]` but the business payload is nested one level deeper.** Verified at line ~858: the `_project_frontend_action_submitted` projector builds the typed event with `data=snapshot.payload` — meaning the Pydantic typed event has its OWN `data` field carrying the original `_decision_history` payload (action_class, actor_subject, etc.). Verified at line ~3856: `_encode(event)` writes `data=event.model_dump_json()` into the SSE `data:` line — this serialises the FULL Pydantic event, so after `_next_sse_event` parses it, `event["data"]` carries `{family, type, event_id, ts, tenant, trace_id, audit_chain_hash, data: {action_class, ...}}`. The R11 #3 fix correctly moved `family`/`type` to `event["data"]["family"]`/`event["data"]["type"]`; R12 #2 follows the SAME path one level deeper for the business payload. **Patched:** changed `event["data"]["action_class"] == "approve"` → `event["data"]["data"]["action_class"] == "approve"`; expanded the inline comment to document the 3-level nesting (SSE wrapper → typed event → business payload) so future readers don't lose context.

- **R12 #3 — T11 `test_action_routes.py` imported 4 unused symbols; ruff F401 would refuse the file.** Verified by line-counting each suspected-unused symbol across the test_action_routes.py boundary (lines 4055-4343, BEFORE the correlation-latency file starts at line 4344): `asyncio` 1 hit = the import line only, no `asyncio.*` body usage; `ActionRequest` 1 hit = import only; `ActionResponse` 1 hit = import only; `_next_sse_event` 1 hit = import only. The correlation-latency file at line 4344 has its OWN imports (R10 #2's per-file fix) which DO use these symbols; this file does not. **Patched:** rewrote the import block to keep ONLY the 5 actually-used symbols — `pytest`, `Actor`, `_async_client`, `_FixtureActorBinder`, `_read_recent_decision_history_rows`. Added a 6-line comment block enumerating which imports were removed + why, per the verify-code-citations doctrine.

- **R12 #4 — T10 shared boilerplate would have copied unused imports into every file; ruff F401 would refuse all 5 files.** Per-file usage audit across the 5 T10 test files revealed sharp variation: `test_stream_routes.py` uses asyncio + pytest + _async_client + _next_sse_event + _iter_sse_events + emit_audit_tool_call_event + emit_test_policy_event_and_memory_event (NO datetime/UTC, NO _read_recent_decision_history_rows); `test_stream_routes_last_event_id.py` uses asyncio + pytest + _async_client + _next_sse_event only; `test_stream_routes_reconnect.py` uses asyncio + pytest + _async_client + _next_sse_event only; `test_stream_headers_and_timeout.py` uses asyncio + pytest + _async_client only; `test_heartbeat.py` uses asyncio + pytest + _async_client + datetime + UTC only. R11 #4's shared boilerplate would have injected 4-7 unused symbols per file. **Patched:** removed the shared `"Each T10 test file starts with..."` boilerplate block; replaced with a 1-sentence "R12 #4 — Per-file imports (NOT a shared boilerplate)" notice; added explicit per-file import blocks (each prefixed with `# R12 #4: exact per-file imports (ruff F401-safe)`) at each of the 5 test file headers, importing ONLY the symbols that file actually uses. Pinned to the per-file usage audit table embedded in the patch-log narrative.

**File size delta (R12):** ~115 LoC net (R12 #1 stub-rewrite +30 LoC; R12 #1 adapter-threading comment +5 LoC; R12 #2 comment expansion +12 LoC; R12 #3 trim −2 LoC; R12 #4 boilerplate-to-per-file ~+70 LoC across 5 files). Plan moves from ~5490 → ~5605 LoC.

**R12 verification scan (post-patch):**
- `grep -nE "build_action_routes\(broker=broker\)" docs/superpowers/plans/...` → 0 hits in T11 fixture block (all call sites now include `elicitation_adapter=...`).
- `grep -nE "async def submit\(" docs/superpowers/plans/...` → 0 hits in `_StubElicitationAdapter`; the stub has `async def get_context` + `async def handle_submission` matching the locked Protocol.
- `grep -c 'event\["data"\]\["action_class"\]' docs/superpowers/plans/...` → 0 hits (R12 #2: the wrong shallow path is gone).
- `grep -c 'event\["data"\]\["data"\]\["action_class"\]' docs/superpowers/plans/...` → ≥1 hit (the corrected nested path).
- `grep -nE "^import asyncio|^from cognic_agentos.portal.api.ui.dto import|^from tests.unit.portal.api.ui.sse_test_helpers import" docs/superpowers/plans/...` for T11 test_action_routes.py boundary (lines 4055-4343): asyncio removed; dto removed; sse_test_helpers includes 3 symbols (down from 4).
- Per-file imports landed at each T10 test file header (5 separate `# R12 #4: exact per-file imports (ruff F401-safe)` markers).

### Round 13 — User halt review (2026-05-16)

User identified 4 P1 follow-on executable / ruff-F-rule blockers in the R12-patched plan; all verified against the codebase / plan body before patching; all patched into the plan body above:

- **R13 #1 — Stub `get_context` returned `ElicitationContext` without the required 7th field `expires_at`.** Verified at line ~2273: `ElicitationContext` is a `frozen=True` dataclass declaring 7 positional fields (`elicitation_id`, `tenant_id`, `originating_pack_id`, `originating_decision_record_id: uuid.UUID`, `elicitation_modes: tuple[ElicitationMode, ...]`, `data_classes: tuple[str, ...]`, `expires_at: datetime | None`) — none with defaults. R12 #1's stub omitted `expires_at`; the first submit_elicitation test invoking the fixture would raise `TypeError: __init__() missing 1 required positional argument: 'expires_at'` before any route assertion ran. **Patched:** added `expires_at=None` to the stub's `ElicitationContext(...)` construction. Inline comment cites the field at line ~2273.

- **R13 #2 — `settings_low_cap` / `settings_short_send_timeout` parameters were ornamental — the broker mounted in `app` still used default settings.** Verified the dep chain: T6 `app` fixture depends on `app_with_broker`, which depends on `broker`, which depends on `settings` (default). Requesting `settings_low_cap` as an ADDITIONAL test parameter resolves the sibling fixture but never re-roots the broker construction — the cap-exceeded test at line 3386 would never reliably 429 (the broker honors cap=50, not cap=1). Same bug class for the send-timeout test at line 3614 (broker honors timeout=30s, not 1s). **Patched:** added 6 new fixtures to the T6 conftest as siblings of the default `app` / `broker` chain — `app_with_broker_low_cap`, `broker_low_cap`, `app_low_cap`, `app_with_broker_short_send_timeout`, `broker_short_send_timeout`, `app_short_send_timeout` — each re-rooting create_app + broker construction at the respective non-default settings instance. Rewired `test_429_when_per_tenant_cap_hit` to request `app_low_cap` instead of `app` + `settings_low_cap`; rewired `test_stalled_client_unregistered_past_send_timeout` to request `app_short_send_timeout` + `broker_short_send_timeout` (so the broker the route uses AND the broker the test inspects via `broker._subscribers` are the SAME settings-rooted instance).

- **R13 #3 — Two ruff F841 "assigned but never used" patterns in T10 tests.** Verified at line 3475 (now 3559): `first = await asyncio.wait_for(_next_sse_event(resp), timeout=0.5)` bound `first` but never read it. Verified at line 3622 (now ~3724, fixed in R13 #2 pass): `async with c.stream("GET", "/api/v1/ui/tenants/t1/events") as resp:` bound `resp` but the block body only called `await asyncio.sleep(0.05)` — `resp` was unread. Ruff F841 (which covers both regular assignment AND `with`-as bindings) would refuse both at the lint gate. **Patched both:** (a) added `assert first["id"] == emitted.event_id` immediately after the `first = ...` bind so the live event is both consumed AND verified (stronger than dropping the bind to `_ = ...`); (b) dropped the `as resp` clause from the send-timeout test's `c.stream(...)` context manager.

- **R13 #4 — `import json` in `test_well_known_routes.py` was unused; ruff F401 would fail.** Verified by symbol-level audit across the T12 test body (lines 4700-4790): the only `json` substring hits were (a) inside URL paths like `"/.well-known/cognic-ui-events.json"` (string literal, not the module) and (b) the httpx Response method `r.json()` (method on the response object, not the module). The `json` module itself is never imported with a `.dumps` / `.loads` call. **Patched:** removed `import json`; added a 3-line traceability comment explaining the removal rationale per the verify-code-citations doctrine.

**File size delta (R13):** ~120 LoC net (R13 #2 adds 6 new conftest fixtures at ~70 LoC plus 4 LoC of comment updates at the 2 test signatures; R13 #1/#3/#4 each add 1-3 LoC of comment + the actual fix). Plan moves from ~5605 → ~5725 LoC.

**R13 verification scan (post-patch):**
- `grep -nE "ElicitationContext\(" docs/superpowers/plans/...` in `_StubElicitationAdapter`: exactly 1 hit, includes `expires_at=None` (R13 #1).
- `grep -nE "^async def app_low_cap\(|^async def broker_low_cap\(|^async def app_short_send_timeout\(|^async def broker_short_send_timeout\(" docs/superpowers/plans/...` → 4 hits, all `@pytest.fixture`-decorated (R13 #2).
- `grep -nE "self, app, settings_low_cap" docs/superpowers/plans/...` → 0 hits (R13 #2 — the ornamental-parameter pattern is gone).
- `grep -nE "self, app, broker, settings_short_send_timeout" docs/superpowers/plans/...` → 0 hits (R13 #2).
- `grep -c "first = await" docs/superpowers/plans/...` → 1 hit (at line ~3559); the immediately-following `assert first["id"] == emitted.event_id` line consumes the bind (R13 #3).
- `grep -c '"/api/v1/ui/tenants/t1/events") as resp:' docs/superpowers/plans/...` for the send-timeout test block: 0 hits (R13 #3 — `as resp` clause removed).
- `grep -c "^import json" docs/superpowers/plans/...` for T12 test body (lines 4695-4790): 0 hits (R13 #4).

**R8 verification scan (post-patch):**
- `grep -n "signed_artefact_digest=None" docs/superpowers/plans/2026-05-15-sprint-7b4-ui-event-stream-endpoints.md` → 0 hits.
- `grep -n "signed_artefact_digest=b" docs/superpowers/plans/2026-05-15-sprint-7b4-ui-event-stream-endpoints.md` → 2 hits (both seeded-pack fixtures).
- `grep -n "PackState, PackKind" docs/superpowers/plans/2026-05-15-sprint-7b4-ui-event-stream-endpoints.md` → 0 hits.
- `grep -n "See R5 entry in patch-log for the full code" docs/superpowers/plans/2026-05-15-sprint-7b4-ui-event-stream-endpoints.md` → 0 hits.
- `grep -n "See the T10 section + R5 patch-log for full code" docs/superpowers/plans/2026-05-15-sprint-7b4-ui-event-stream-endpoints.md` → 0 hits.

---

## References

- **Source spec:** `docs/superpowers/specs/2026-05-15-sprint-7b4-ui-event-stream-design.md` (committed at `6762cbc`).
- **ADR-020** — UI Event-Stream Contract.
- **BUILD_PLAN.md §602 + §640-674** — Sprint 7B status + 7 UI-event-stream tests.
- **Predecessor plan-of-record:** `docs/superpowers/plans/2026-05-13-sprint-7b3-reviewer-evidence-panels-5-gate.md` (Sprint 7B.3 — pattern this plan mirrors).
- **Predecessor closeouts:** 7B.3 (`c53de7a` merge) + 7B.2 (`a9631ff` merge; portal RBAC + the 4 dep modules T6 async-converts).
- **`feedback_security_regression_hardening`** — threat-model-revert doctrine for the load-bearing guards.
- **`feedback_patch_plan_against_doctrine`** — verify per-task specs against codebase + git reality before each R-round patch.
- **`feedback_verify_code_citations_at_doc_write`** — file:line citations in this plan verified at compose time.
- **`feedback_explicit_authorization_per_action`** — every commit + push + merge needs an explicit user token.
- **`feedback_gate_ladder_per_microfix`** — full pytest is commit-gate only; halt summary produced without full-suite proof.
