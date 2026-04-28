"""Governance vocabulary — enums + typed metadata records.

Layer classification: **platform primitive** (governance kernel).

Wire-format contract: every enum value here is persisted into
``audit_event`` + ``decision_history`` payloads. Values are append-only;
renaming or repurposing a value requires a ``schema_version`` bump in the
governance migrations + a documented canonical-form decision. Adding new
values is fine.

``FieldMeta`` is a frozen dataclass describing a governance-relevant field
on a domain object. Sprint 2 introduces the type so downstream sprints
(escalation, ticket events, evidence-pack export) can reuse a consistent
shape rather than ad-hoc dicts.
"""

from __future__ import annotations

import dataclasses
from datetime import datetime
from enum import StrEnum


class CognicAction(StrEnum):
    """Top-level action verbs an agent can take.

    Persisted as the canonical action label on decision_history rows.
    Wire-format-stable; never rename a value — add new ones instead.
    """

    CALL_TOOL = "call_tool"
    COMPLETE = "complete"
    ESCALATE = "escalate"


class ComplianceVerdict(StrEnum):
    """Outcome of a compliance check on a decision.

    Persisted on decision_history rows that ran through compliance
    evaluation. Wire-format-stable.
    """

    APPROVED = "approved"
    DENIED = "denied"
    NEEDS_REVIEW = "needs_review"


class FieldStatus(StrEnum):
    """Lifecycle status of a governance-tracked field on a domain object.

    Wire-format-stable.
    """

    OPEN = "open"
    PENDING = "pending"
    CLOSED = "closed"


@dataclasses.dataclass(frozen=True, slots=True)
class FieldMeta:
    """Typed metadata record for a governance-tracked field.

    Frozen so callers cannot mutate the record after emission — the
    record may already have been hashed into the decision-history
    chain by the time it's read. Mutation would silently desync the
    in-memory view from the persisted hash.
    """

    name: str
    status: FieldStatus
    last_changed_by: str | None = None
    last_changed_at: datetime | None = None
