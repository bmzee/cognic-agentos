"""Governance vocabulary — `CognicAction` / `ComplianceVerdict` / `FieldStatus`
enums + `FieldMeta` frozen dataclass.

Wire-format contract: every enum value here is persisted into audit_event +
decision_history payloads. Values are append-only; renaming or repurposing a
value requires a `schema_version` bump + a migration plan. Adding new values
is fine.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from cognic_agentos.core.schemas import (
    CognicAction,
    ComplianceVerdict,
    FieldMeta,
    FieldStatus,
)


class TestCognicAction:
    def test_values_are_stable(self) -> None:
        assert CognicAction.CALL_TOOL.value == "call_tool"
        assert CognicAction.COMPLETE.value == "complete"
        assert CognicAction.ESCALATE.value == "escalate"


class TestComplianceVerdict:
    def test_values_are_stable(self) -> None:
        assert ComplianceVerdict.APPROVED.value == "approved"
        assert ComplianceVerdict.DENIED.value == "denied"
        assert ComplianceVerdict.NEEDS_REVIEW.value == "needs_review"


class TestFieldStatus:
    def test_values_are_stable(self) -> None:
        assert FieldStatus.OPEN.value == "open"
        assert FieldStatus.PENDING.value == "pending"
        assert FieldStatus.CLOSED.value == "closed"


class TestFieldMeta:
    def test_construct_minimum(self) -> None:
        meta = FieldMeta(name="customer_score", status=FieldStatus.OPEN)
        assert meta.name == "customer_score"
        assert meta.status is FieldStatus.OPEN
        assert meta.last_changed_by is None
        assert meta.last_changed_at is None

    def test_construct_full(self) -> None:
        ts = datetime(2026, 4, 28, 10, 0, 0, tzinfo=UTC)
        meta = FieldMeta(
            name="customer_score",
            status=FieldStatus.PENDING,
            last_changed_by="agent-onboarding",
            last_changed_at=ts,
        )
        assert meta.last_changed_by == "agent-onboarding"
        assert meta.last_changed_at == ts

    def test_immutable(self) -> None:
        meta = FieldMeta(name="x", status=FieldStatus.OPEN)
        with pytest.raises(dataclasses.FrozenInstanceError):
            meta.status = FieldStatus.CLOSED  # type: ignore[misc]
