"""Sprint 7B.4 T3 — RBACDenialType union + portal-vocab disjointness +
PolicyRBACDenied event shape regressions.

Architectural-arrow invariant (locked at the 7B.4 design spec §2):
``protocol/ui_events.py`` MUST NOT import from ``portal/rbac/*`` —
the protocol layer is upstream of portal. `RBACDenialType` is
protocol-owned (defined HERE, not in portal); union-equality with
the 4 portal RBAC denial vocabularies is enforced AT THE TEST LAYER
so the protocol module stays import-clean.

Drift in either direction (a value added to a portal Literal but not
mirrored here, OR vice versa) trips this regression before merge.
The portal RBAC denial vocabularies are themselves wire-protocol-public
(403 response body's `reason` field per ADR-012 §40 + AGENTS.md
"Wire-protocol contracts" stop rule); any drift here = wire-protocol
drift.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, get_args

import pytest

from cognic_agentos.portal.rbac.enforcement import RBACDenialReason
from cognic_agentos.portal.rbac.human_actor import HumanActorDenialReason
from cognic_agentos.portal.rbac.role_separation import RoleSeparationFailure
from cognic_agentos.portal.rbac.tenant_isolation import TenantIsolationFailure
from cognic_agentos.protocol.ui_events import (
    _SSE_WAVE_1_STREAMED_FAMILIES,
    AppendResult,
    PolicyRBACDenied,
    RBACDenialType,
)


class TestRBACDenialTypeUnionEquality:
    """The protocol-owned `RBACDenialType` MUST equal the union of the
    4 portal RBAC denial vocabularies. This is the single source of
    drift-detection for the rbac.* chain-event type vocabulary."""

    def test_count_is_9(self) -> None:
        """Hard count — verified against portal RBAC sources at sprint plan
        check time: enforcement.RBACDenialReason (3) + tenant_isolation.
        TenantIsolationFailure (4) + human_actor.HumanActorDenialReason (1)
        + role_separation.RoleSeparationFailure (1) = 9."""
        assert len(get_args(RBACDenialType)) == 9

    def test_union_equals_4_portal_literals(self) -> None:
        protocol_set = set(get_args(RBACDenialType))
        portal_union = (
            set(get_args(RBACDenialReason))
            | set(get_args(TenantIsolationFailure))
            | set(get_args(HumanActorDenialReason))
            | set(get_args(RoleSeparationFailure))
        )
        assert protocol_set == portal_union, (
            f"RBACDenialType drift: protocol={protocol_set ^ portal_union} differ from portal union"
        )

    def test_4_portal_literals_pairwise_disjoint(self) -> None:
        """Defence-in-depth — the protocol-side union equality test would
        still pass even if two portal vocabularies shared a value (the
        protocol set would just be smaller). The pairwise disjointness
        check pins the orthogonal-axis invariant explicitly."""
        a = set(get_args(RBACDenialReason))
        b = set(get_args(TenantIsolationFailure))
        c = set(get_args(HumanActorDenialReason))
        d = set(get_args(RoleSeparationFailure))
        assert a.isdisjoint(b), f"enforcement ∩ tenant_isolation: {a & b}"
        assert a.isdisjoint(c), f"enforcement ∩ human_actor: {a & c}"
        assert a.isdisjoint(d), f"enforcement ∩ role_separation: {a & d}"
        assert b.isdisjoint(c), f"tenant_isolation ∩ human_actor: {b & c}"
        assert b.isdisjoint(d), f"tenant_isolation ∩ role_separation: {b & d}"
        assert c.isdisjoint(d), f"human_actor ∩ role_separation: {c & d}"


class TestProtocolImportsDoNotReachPortal:
    """Architectural-arrow regression: protocol/ui_events.py MUST NOT
    import from portal/rbac/*. A forgotten convenience import would
    silently violate the architectural arrow and create a circular-
    dependency time bomb when portal/rbac modules import from protocol/
    (which they do, e.g. for the `_BaseEvent` event family models)."""

    def test_protocol_ui_events_module_does_not_import_portal(self) -> None:
        import ast
        import pathlib

        module_path = pathlib.Path(__file__).resolve()
        # tests/unit/protocol/test_ui_events_rbac_denial_type.py
        # → repo root → src/cognic_agentos/protocol/ui_events.py
        repo_root = module_path.parents[3]
        target = repo_root / "src" / "cognic_agentos" / "protocol" / "ui_events.py"
        tree = ast.parse(target.read_text())

        forbidden_prefixes = ("cognic_agentos.portal",)
        offenders: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if any(node.module.startswith(p) for p in forbidden_prefixes):
                    offenders.append(f"from {node.module} import ...")
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if any(alias.name.startswith(p) for p in forbidden_prefixes):
                        offenders.append(f"import {alias.name}")
        assert not offenders, (
            "protocol/ui_events.py imports from portal/* "
            f"(architectural-arrow violation): {offenders}"
        )


class TestPolicyRBACDeniedShape:
    """`PolicyRBACDenied` uses the reserved `policy.*` family slot per
    ADR-020 + the design spec — `_WAVE_1_FAMILIES` stays at 11, the
    `rbac.<denial_type>` decision_type collapses onto the existing
    `policy` family rather than introducing a 12th family."""

    def test_family_and_type_literals(self) -> None:
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

    def test_family_in_wave_1_families_set(self) -> None:
        """`policy` MUST already be in the 11-family Wave-1 set —
        confirms the design decision to reuse the reserved slot rather
        than mint a 12th family."""
        from cognic_agentos.protocol.ui_events import _WAVE_1_FAMILIES

        assert "policy" in _WAVE_1_FAMILIES
        assert len(_WAVE_1_FAMILIES) == 11  # unchanged from Sprint 6


class TestPolicyRBACDeniedIsInUIEventUnion:
    """R1 regression: `PolicyRBACDenied` MUST be a branch of the
    `_PolicyEvent` discriminated union AND therefore reachable through
    the top-level `UIEvent` TypeAdapter. The class existing in module
    scope is NECESSARY but NOT SUFFICIENT — until the union literally
    includes it, `TypeAdapter(UIEvent).validate_python(...)` refuses
    with `union_tag_invalid` on `type='rbac_denied'` and downstream
    consumers (T4 typed-projector dispatch, T12 well-known schema
    publication) cannot treat `rbac_denied` as a real UIEvent.

    Drift-detection: if a future change re-narrows `_PolicyEvent` and
    drops PolicyRBACDenied, this test fails with the same
    `union_tag_invalid` error before merge."""

    def test_typeadapter_validates_policy_rbac_denied_payload(self) -> None:
        from pydantic import TypeAdapter

        from cognic_agentos.protocol.ui_events import UIEvent

        original = PolicyRBACDenied(
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
        payload = original.model_dump(mode="json")
        # Round-trip through the TypeAdapter — exactly the call path T4
        # typed-projector dispatch + T12 well-known schema publication use.
        # `TypeAdapter[Any]` matches the existing repo convention at
        # tests/unit/protocol/test_ui_event_taxonomy_completeness.py:198
        # (mypy can't bind to the `Annotated[Union[...], ...]` UIEvent alias).
        adapter: TypeAdapter[Any] = TypeAdapter(UIEvent)
        roundtrip = adapter.validate_python(payload)
        assert isinstance(roundtrip, PolicyRBACDenied)
        assert roundtrip.family == "policy"
        assert roundtrip.type == "rbac_denied"
        # Defence-in-depth: confirm the union accepts the policy.rbac_denied
        # discriminator pair — not just a generic match on `family="policy"`
        # that could silently route to PolicyDecisionEvaluated or
        # PolicyBundleLoaded if the union were misordered.
        assert roundtrip.data["denial_type"] == "scope_not_held"

    def test_policy_rbac_denied_exported_in_all(self) -> None:
        """The class MUST be in `__all__` so `from cognic_agentos.protocol.ui_events
        import *` (used by T12's well-known schema publication helper) picks
        it up. Without this, T12 emits a schema with `rbac_denied` referenced
        as a union branch but the class itself missing from the export
        manifest — silent omission, not a hard error."""
        from cognic_agentos.protocol import ui_events as _mod

        assert "PolicyRBACDenied" in _mod.__all__


class TestSSEWave1StreamedFamilies:
    """`_SSE_WAVE_1_STREAMED_FAMILIES` filters the 11 Wave-1 families
    down to the 9 that flow over SSE — `tool_call` + `artifact` are
    audit-event-backed (not decision-history-backed) and intentionally
    excluded from Wave-1 SSE per the design spec §4.2."""

    def test_count_is_9(self) -> None:
        assert len(_SSE_WAVE_1_STREAMED_FAMILIES) == 9

    def test_excludes_audit_backed_families(self) -> None:
        assert "tool_call" not in _SSE_WAVE_1_STREAMED_FAMILIES
        assert "artifact" not in _SSE_WAVE_1_STREAMED_FAMILIES

    def test_includes_all_9_decision_history_backed_families(self) -> None:
        expected = frozenset(
            {
                "policy",
                "decision_audit",
                "agent_run",
                "subagent",
                "approval",
                "interrupt",
                "frontend_action",
                "memory",
                "kill_switch",
            }
        )
        assert expected == _SSE_WAVE_1_STREAMED_FAMILIES

    def test_is_strict_subset_of_wave_1_families(self) -> None:
        from cognic_agentos.protocol.ui_events import _WAVE_1_FAMILIES

        assert _SSE_WAVE_1_STREAMED_FAMILIES < _WAVE_1_FAMILIES
        # The 2 excluded families are exactly the audit-backed ones.
        assert (
            frozenset({"tool_call", "artifact"}) == _WAVE_1_FAMILIES - _SSE_WAVE_1_STREAMED_FAMILIES
        )


class TestAppendResultShape:
    """`AppendResult` is the broker chain-append return shape — wire-
    protocol-public to T4 broker consumers (Sprint 7B.4) + T10 SSE
    route handlers. Field additions are wire-extensions; field removals
    or renames are wire-breaking."""

    def test_is_frozen_dataclass(self) -> None:
        """Behavioral frozen check (preferred over inspecting
        `__dataclass_params__` which is a runtime-only attribute not in
        the typeshed stubs): construct an instance + assert that field
        assignment raises FrozenInstanceError."""
        import dataclasses as _dc
        import uuid

        assert _dc.is_dataclass(AppendResult)
        instance = AppendResult(
            record_id=uuid.uuid4(),
            chain_hash=b"\x00" * 32,
            event_id="evt_0123456789ABCDEFGHIJKLMNOP",
        )
        with pytest.raises(_dc.FrozenInstanceError):
            instance.event_id = "evt_mutation_attempt"  # type: ignore[misc]

    def test_has_exactly_3_fields(self) -> None:
        import dataclasses as _dc

        fields = {f.name: f for f in _dc.fields(AppendResult)}
        assert set(fields.keys()) == {"record_id", "chain_hash", "event_id"}

    def test_field_types(self) -> None:
        # Resolve string annotations via typing.get_type_hints because
        # `from __future__ import annotations` is active in the source
        # (protocol/ui_events.py line 85) — without this resolution the
        # `__annotations__` dict would hold strings, not concrete types.
        import typing
        import uuid

        hints = typing.get_type_hints(AppendResult)
        assert hints["record_id"] is uuid.UUID
        assert hints["chain_hash"] is bytes
        assert hints["event_id"] is str

    def test_construct_roundtrip(self) -> None:
        import uuid

        result = AppendResult(
            record_id=uuid.uuid4(),
            chain_hash=b"\x00" * 32,
            event_id="evt_0123456789ABCDEFGHIJKLMNOP",
        )
        assert isinstance(result.record_id, uuid.UUID)
        assert result.chain_hash == b"\x00" * 32
        assert result.event_id == "evt_0123456789ABCDEFGHIJKLMNOP"
