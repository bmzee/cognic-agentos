"""Sprint 11.5a — consent token validator + chain-linked consent ledger (ADR-019).

CRITICAL CONTROL (core/ stop-rule per AGENTS.md — Memory governance
enforcement, ADR-019). This module owns the runtime consent gate for a
restricted-class memory write:

  * ``ConsentToken`` — frozen, slotted caller-side representation of a
    subject-issued consent grant (canonical ``SubjectRef`` string + covered
    data classes + issued/expiry timestamps + an opaque signature).
  * ``ConsentValidator`` — validates a token against the served subject + the
    restricted data classes a write declares, and chain-links exactly one
    ``memory.consent`` ``DecisionRecord`` (digest-only) on the valid path.

**Ledger doctrine (locked, 11.5a).** The consent LEDGER *is* the
``decision_history`` chain — there is NO physical ``memory_consent_ledger``
table in 11.5a (deferred to 11.5b). A ``memory.consent`` event is emitted
ONLY on a valid restricted-consent path:

  * no restricted data class declared  -> no token required -> NO event;
  * a refusal (missing token / invalid token) -> raise + NO event.

**Digest-only invariant.** The raw token value + the ``signature`` field
NEVER enter the chain. The payload carries a ``consent_token_digest``
(SHA-256 over ``subject_ref|signature``) only — same posture as the
``memory.write`` value digest in ``core/memory/storage.py``.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib

from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, SubjectRef

#: ISO 42001 control tuple stamped on every ``memory.consent`` chain row.
#: A.7.4 (impact assessment) / A.8.2 (data quality) per ADR-019 + ADR-006.
#: Tuple at the boundary; ``DecisionHistoryStore`` converts to a list before
#: ``canonical_bytes`` (which rejects tuples).
_MEMORY_CONSENT_ISO_CONTROLS: tuple[str, ...] = ("A.7.4", "A.8.2")


@dataclasses.dataclass(frozen=True, slots=True)
class ConsentToken:
    """Subject-issued consent grant presented at a restricted-class write.

    Frozen + slotted: bindings cannot be reassigned after construction. The
    raw token + ``signature`` are never persisted to the chain — only a
    digest (see :class:`ConsentValidator`)."""

    subject_ref: str  # canonical SubjectRef string, e.g. "human:cust-7"
    data_classes: frozenset[str]
    issued_at: dt.datetime
    expires_at: dt.datetime
    signature: str


class ConsentValidator:
    """Validates a ConsentToken against the served subject + the restricted
    data classes a write declares, and chain-links a ``memory.consent`` event
    (digest-only) on success. The consent LEDGER is the decision_history chain
    — there is NO physical consent table in 11.5a (deferred to 11.5b)."""

    def __init__(self, *, audit: DecisionHistoryStore) -> None:
        self._audit = audit

    async def validate(
        self,
        token: ConsentToken | None,
        *,
        served_subject: SubjectRef,
        restricted_declared: frozenset[str],
        tenant_id: str,
        actor_id: str,
    ) -> None:
        """Gate a memory write on consent.

        Branches (each pinned by ``tests/unit/core/memory/test_consent.py``):

          1. ``restricted_declared`` empty -> no consent needed; return
             without emitting any event.
          2. ``token is None`` (but restricted classes declared) -> raise
             ``MemoryOperationRefused("memory_consent_required")``; NO event.
          3. token present but invalid (expired / subject mismatch / declared
             restricted classes not covered) -> raise
             ``MemoryOperationRefused("memory_consent_invalid")``; NO event.
          4. token present + valid -> append exactly one ``memory.consent``
             ``DecisionRecord`` carrying the token DIGEST (never the raw token
             or signature) and return.
        """

        if not restricted_declared:
            return  # no restricted class declared -> no consent needed, no event
        if token is None:
            raise MemoryOperationRefused("memory_consent_required")
        now = dt.datetime.now(dt.UTC)  # wall-clock expiry; not a chain timestamp
        if (
            token.expires_at <= now
            or token.subject_ref != served_subject.canonical
            or not restricted_declared <= token.data_classes
        ):
            raise MemoryOperationRefused("memory_consent_invalid")
        # Digest only — the raw token/signature NEVER enter the chain.
        digest = hashlib.sha256(f"{token.subject_ref}|{token.signature}".encode()).hexdigest()
        await self._audit.append(
            DecisionRecord(
                decision_type="memory.consent",
                request_id=f"memory-consent-{digest[:16]}",
                payload={
                    "subject_ref": token.subject_ref,
                    "data_classes": sorted(token.data_classes),
                    "consent_token_digest": digest,
                },
                actor_id=actor_id,
                tenant_id=tenant_id,
                iso_controls=_MEMORY_CONSENT_ISO_CONTROLS,
            )
        )


__all__: tuple[str, ...] = (
    "ConsentToken",
    "ConsentValidator",
)
