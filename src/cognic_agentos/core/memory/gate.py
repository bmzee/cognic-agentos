"""Sprint 11.5a — the per-write / per-recall memory enforcement gate (ADR-019 §7).

CRITICAL CONTROL (``core/`` stop-rule per AGENTS.md — Memory governance
enforcement, ADR-019). This module owns THE substantive per-operation
governance boundary for the memory substrate. Both gates ship in 11.5a so the
write path is *safe at first commit*: every danger-preventing refusal is
present even though the lifecycle ops (forget / redact / export) are deferred
to 11.5b.

**Ordered precedence IS the contract** (spec §7.1 / §7.2). The first applicable
failure short-circuits and raises the typed
:class:`~cognic_agentos.core.memory.tiers.MemoryOperationRefused` carrying the
wire-public closed-enum reason; a Layer C caller always receives a typed
exception, never a silent drop. Each refusal therefore WINS over every
later-step failure that may also hold in the same input — the regression suite
proves the earliest applicable reason wins by stacking later failures into the
same call.

**Identity is read from the bound** :class:`MemoryCallerContext` **only.** The
gate never accepts a caller-supplied ``tenant_id`` / ``agent_id`` / ``actor_id``
/ subject scope — a Layer C caller cannot smuggle a different identity. The
resolved descriptor is the existing
:class:`~cognic_agentos.core.memory._context.MemoryWriteRecord` (no new public
shape is minted here).

**Fail-loud kill-switch.** Step 0 calls ``kill_switch.is_write_frozen(...)``;
the unwired ``_NullMemoryKillSwitchInterrogator`` raises ``NotImplementedError``
which PROPAGATES out of :meth:`MemoryGate.check_write` unchanged — only an
actual ``is_write_frozen(...) is True`` maps to ``memory_write_frozen``. A
production deployment that forgets to wire the real kill-switch fails loud on
the first write, never silently allows during a compliance freeze.

**OPA fail-closed is PER decision point.** Each Rego ``opa.evaluate(...)`` call
is wrapped individually; an ``OpaNotInstalledError`` / ``RegoEvaluationError``
at one decision point maps to deny with the reason for THAT step
(``long_term`` → ``memory_long_term_write_denied``; cross-subject →
``memory_cross_subject_access_refused``; purpose-matrix →
``memory_purpose_mismatch``) and never leaks the wrong reason.

**Retention is a CLAMP, never a refusal** (step 6). ``retention_until`` is the
``min`` of the caller-declared window and the tenant maximum, converted to an
absolute UTC datetime via ``now() + window_seconds``. ``scratch`` writes skip
steps 2/3b/5/6/7 (step 1b is block-only, so N/A for ``scratch``); DLP (step 3)
and purpose (step 4) still run for hygiene.

**Restricted-class admission (step 3b, durable tiers only).** A write that
DECLARES a restricted data class must clear the
``restricted_class_write.allow`` Rego point (default-deny; the tenant permits
via a local Rego override) or it is refused with
``memory_restricted_class_write_denied`` — an OPA error fails closed to the
same reason. Pairs with consent (step 5): durable restricted memory requires
BOTH tenant policy allow AND valid consent. ``scratch`` is exempt (ephemeral;
DLP hygiene at step 3 still applies).

**Blocks are long_term-only** (locked rule). ``check_write`` refuses a
``block_kind`` write whose ``tier`` is not ``long_term`` with a ``ValueError``
precondition — before any governance step or descriptor build — matching the
storage-layer guard.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.dlp.scanner import DLP_RESTRICTED_CLASSES
from cognic_agentos.core.memory._context import MemoryCallerContext, MemoryWriteRecord
from cognic_agentos.core.memory._seams import (
    MemoryKillSwitchInterrogator,
    _NullMemoryKillSwitchInterrogator,
)
from cognic_agentos.core.memory.storage import _value_digest
from cognic_agentos.core.memory.tiers import (
    BlockKind,
    MemoryOperationRefused,
    MemoryTier,
    SubjectRef,
)
from cognic_agentos.core.policy.engine import (
    OPAEngine,
    OpaNotInstalledError,
    RegoEvaluationError,
)

if TYPE_CHECKING:
    from cognic_agentos.core.dlp.scanner import DLPScanner
    from cognic_agentos.core.memory.consent import ConsentToken, ConsentValidator

# --- Rego decision points (compile-time constants; never pack-controlled) ----
_LONG_TERM_DECISION_POINT = "data.cognic.memory.long_term.allow"
_CROSS_SUBJECT_DECISION_POINT = "data.cognic.memory.cross_subject.allow"
_RESTRICTED_CLASS_WRITE_DECISION_POINT = "data.cognic.memory.restricted_class_write.allow"
_PURPOSE_COMPATIBLE_DECISION_POINT = "data.cognic.memory.recall.purpose_compatible.allow"

#: The five ADR-014 high-risk tiers that gate a ``long_term`` write behind the
#: (pre-13.5 unavailable) approval engine at §7.1 step 7. A DELIBERATE inline
#: mirror of the canonical 8-value ``RiskTier`` vocabulary (the 3 low tiers —
#: ``read_only`` / ``internal_write`` / ``customer_data_read`` — are excluded).
#: ``core/`` MUST NOT import ``cli/*`` (architectural arrow runs ``cli -> core``)
#: nor ``packs/*``; the lockstep with the canonical set is pinned test-only in
#: ``tests/unit/core/memory/test_write_gate.py`` per
#: ``feedback_drift_detector_test_only_no_runtime_import``.
_APPROVAL_REQUIRED_RISK_TIERS: frozenset[str] = frozenset(
    {
        "customer_data_write",
        "payment_action",
        "regulator_communication",
        "cross_tenant",
        "high_risk_custom",
    }
)

#: Durable tiers a sub-agent may NOT touch (§7.3 I2 — children get scratch only).
_SUBAGENT_REFUSED_TIERS: frozenset[str] = frozenset({"task", "long_term"})


def _memory_tool_identity(*, agent_id: str) -> str:
    """Collision-proof canonical tool identity for the approval seam (c3 spec
    §3.3). The agent is the acting identity for governed memory writes."""
    return (
        "memory:"
        + hashlib.sha256(
            canonical_bytes({"agent_id": agent_id, "operation": "memory_write"})
        ).hexdigest()
    )


def _memory_args_digest(
    *,
    tier: str,
    purpose: str,
    data_classes: tuple[str, ...],
    key: str | None,
    block_kind: str | None,
    subject_canonical: str,
    actor_id: str,
    risk_tier: str,
    value: object,
) -> bytes:
    """Approval binding digest over the approved WRITE SHAPE incl. content
    (c3 spec §3.3 / F4). The engine NEVER sees the raw value — only
    ``_value_digest(value)`` (the same helper the memory.write chain row
    uses; single digest definition, no drift). ``tenant_id`` is
    envelope-first-class; consent/retention are RE-VALIDATED by Steps 0-6
    on every attempt and therefore deliberately unbound."""
    return hashlib.sha256(
        canonical_bytes(
            {
                "tier": tier,
                "purpose": purpose,
                "data_classes": sorted(data_classes),
                "key": key,
                "block_kind": block_kind,
                "subject": subject_canonical,
                "actor_id": actor_id,
                "risk_tier": risk_tier,
                "value_digest": _value_digest(value),
            }
        )
    ).digest()


class MemoryGate:
    """Per-write / per-recall enforcement gate for the memory substrate.

    Construction binds the caller :class:`MemoryCallerContext` and the four
    governance seams (kill-switch, DLP scanner, consent validator, OPA engine).
    A single ``MemoryGate`` instance is bound to one Layer C caller context by
    the harness — identity is never taken from the per-call arguments.
    """

    def __init__(
        self,
        *,
        context: MemoryCallerContext,
        dlp: DLPScanner,
        consent: ConsentValidator,
        policy: OPAEngine,
        kill_switch: MemoryKillSwitchInterrogator | None = None,
    ) -> None:
        self._context = context
        self._dlp = dlp
        self._consent = consent
        self._policy = policy
        # Fail-loud default: when no kill-switch is wired we bind the
        # _NullMemoryKillSwitchInterrogator sentinel (raises NotImplementedError
        # on is_write_frozen) — a production deployment that forgets to wire the
        # real kill-switch fails loud on the first write, never silently allows.
        # `= None` + bind-here mirrors core/scheduler/engine.py and avoids B008.
        self._kill_switch: MemoryKillSwitchInterrogator = (
            kill_switch if kill_switch is not None else _NullMemoryKillSwitchInterrogator()
        )

    # -- Write gate (§7.1) -------------------------------------------------

    async def check_write(
        self,
        *,
        value: object,
        tier: MemoryTier,
        purpose: str,
        data_classes: tuple[str, ...],
        key: str | None = None,
        block_kind: BlockKind | None = None,
        subject: SubjectRef | None = None,
        consent_token: ConsentToken | None = None,
        retention_window_s: int | None = None,
        tenant_retention_max_s: int | None = None,
    ) -> MemoryWriteRecord:
        """Run the §7.1 ordered write-gate chain and return the resolved record.

        First applicable failure raises ``MemoryOperationRefused(reason)``.
        Identity (``tenant_id`` / ``agent_id`` / ``actor_id`` / served subject)
        is read from the bound context — NOT from the call arguments. On the
        success path returns the resolved :class:`MemoryWriteRecord` with the
        retention window clamped to ``retention_until``.

        Args:
            value: The value being written (DLP-scanned at step 3; never logged
                raw by this gate).
            tier: Target :data:`MemoryTier` (``scratch`` skips steps 2/5/6/7).
            purpose: Caller-declared purpose; must be in
                ``context.declared_purposes`` (step 4).
            data_classes: Caller-declared data classes (drives the consent
                requirement at step 5; passed through onto the record).
            key: General-memory key (mutually exclusive with ``block_kind``).
            block_kind: Block kind for an ``upsert_block`` write (mutually
                exclusive with ``key``); presence drives the block-only
                subject-scope check at step 1b.
            subject: Explicit subject for a block write; compared to
                ``context.served_subject`` at step 1b. For a non-block
                (``remember``) write this is ignored and the resolved record's
                subject is ``context.served_subject``.
            consent_token: Optional subject-issued consent grant (step 5).
            retention_window_s: Caller-declared retention window in seconds
                (``None`` → no caller cap).
            tenant_retention_max_s: Tenant maximum retention window in seconds
                (``None`` → no tenant cap). The effective window is the
                ``min`` of the two when both are set (step 6 clamp).
        """
        ctx = self._context
        is_block_write = block_kind is not None

        # Precondition — blocks are long_term-only (locked rule). A malformed
        # block write is a caller contract violation; refuse with ValueError
        # BEFORE any governance step or descriptor build (matches storage.py).
        if is_block_write and tier != "long_term":
            raise ValueError(f"blocks are long_term-only; got tier={tier!r}")

        # Step 0 — kill-switch (fail-loud sentinel propagates NotImplementedError).
        if await self._kill_switch.is_write_frozen(tenant_id=ctx.tenant_id) is True:
            raise MemoryOperationRefused("memory_write_frozen")

        # Step 1 — sub-agent durable-access guard (§7.3 I2).
        if ctx.is_subagent and tier in _SUBAGENT_REFUSED_TIERS:
            raise MemoryOperationRefused("memory_subagent_durable_access_refused")

        # Step 1b — subject scope (block writes only).
        if is_block_write:
            requested_subject = subject if subject is not None else ctx.served_subject
            if requested_subject.canonical != ctx.served_subject.canonical:
                await self._require_cross_subject_allowed()
            resolved_subject = requested_subject
        else:
            resolved_subject = ctx.served_subject

        # Step 2 — long_term admission (skipped for scratch).
        if tier == "long_term":
            if not ctx.long_term_writes_allowed:
                raise MemoryOperationRefused("memory_long_term_write_denied")
            if not await self._long_term_rego_allows():
                raise MemoryOperationRefused("memory_long_term_write_denied")

        # Step 3 — DLP (defense-in-depth; runs for every tier incl. scratch).
        verdict = self._dlp.scan(value)
        detected_restricted = verdict.detected_classes & DLP_RESTRICTED_CLASSES
        if detected_restricted - set(data_classes):
            raise MemoryOperationRefused("memory_dlp_undeclared_restricted_class")

        # Step 3b — restricted-class admission (durable tiers only; default-deny).
        # When the write DECLARES a restricted class the tenant must permit
        # restricted-class memory via the restricted_class_write.allow Rego point
        # (default-deny unless tenant override; OPA error fails closed). Pairs
        # with consent (step 5): durable restricted memory needs BOTH tenant
        # policy allow AND valid consent. Scratch is exempt (DLP at step 3 still
        # ran for hygiene above).
        if tier != "scratch":
            declared_restricted = frozenset(data_classes) & DLP_RESTRICTED_CLASSES
            if declared_restricted and not await self._restricted_class_rego_allows():
                raise MemoryOperationRefused("memory_restricted_class_write_denied")

        # Step 4 — purpose declaration.
        if purpose not in ctx.declared_purposes:
            raise MemoryOperationRefused("memory_purpose_not_declared")

        # Step 5 — consent (skipped for scratch). Delegates to ConsentValidator,
        # which raises memory_consent_required / memory_consent_invalid and
        # chain-links the memory.consent event itself on the valid path.
        if tier != "scratch":
            restricted_declared = frozenset(data_classes) & DLP_RESTRICTED_CLASSES
            await self._consent.validate(
                consent_token,
                served_subject=resolved_subject,
                restricted_declared=restricted_declared,
                tenant_id=ctx.tenant_id,
                actor_id=ctx.actor_id,
            )

        # Step 6 — retention clamp (skipped for scratch; CLAMP, never refuse).
        if tier == "scratch":
            retention_until = None
        else:
            retention_until = self._resolve_retention_until(
                retention_window_s=retention_window_s,
                tenant_retention_max_s=tenant_retention_max_s,
            )

        # Step 7 — approval-transitional refusal (skipped for scratch).
        if tier == "long_term" and ctx.risk_tier in _APPROVAL_REQUIRED_RISK_TIERS:
            raise MemoryOperationRefused("memory_approval_engine_not_available")

        # Step 8 — success: resolve the descriptor. Identity from context only;
        # T10 (MemoryAPI) calls adapter.put + emits memory.write — not here.
        return MemoryWriteRecord(
            tenant_id=ctx.tenant_id,
            agent_id=ctx.agent_id,
            actor_id=ctx.actor_id,
            subject=resolved_subject,
            tier=tier,
            purpose=purpose,
            data_classes=tuple(data_classes),
            value=value,
            request_id=f"memory-write-{uuid.uuid4().hex}",
            key=key,
            block_kind=block_kind,
            retention_until=retention_until,
        )

    # -- Recall gate (§7.2) ------------------------------------------------

    async def check_recall(
        self,
        *,
        tier: MemoryTier,
        recall_purpose: str,
        write_purpose: str | None = None,
        subject: SubjectRef | None = None,
    ) -> None:
        """Composed §7.2 recall gate (steps 1-4) — equivalent to
        :meth:`check_recall_preread` followed by :meth:`check_recall_purpose`.

        First applicable failure raises ``MemoryOperationRefused(reason)``; on
        success returns ``None`` (the API emits ``memory.read`` — not here).

        **This composed form is for a caller that ALREADY knows the stored
        write purpose.** ``MemoryAPI.recall`` / ``read_block`` do NOT use it —
        they cannot know the stored write purpose until AFTER the read, so they
        run :meth:`check_recall_preread` (pre-read authz), read the record, then
        run :meth:`check_recall_purpose` against ``hit.purpose``. Passing
        ``write_purpose=None`` here against the real default-deny
        ``memory_purpose_matrix.rego`` refuses an otherwise-compatible recall —
        the stored purpose MUST be threaded. Retained for callers holding the
        write purpose + the gate test-suite.

        Args:
            tier: Target :data:`MemoryTier` being recalled.
            recall_purpose: The purpose the recall is performed under (compared
                to ``write_purpose`` via the purpose-matrix Rego at step 4).
            write_purpose: The purpose the target memory was written under
                (``None`` → the matrix decides on a ``None`` pair, which the
                default-deny bundle refuses; pass the STORED ``hit.purpose``).
            subject: Explicit subject for a block / explicit-subject read;
                compared to ``context.served_subject`` at step 3. ``None`` means
                an implicit (``recall``) read scoped to the served subject —
                step 3 is N/A.
        """
        await self.check_recall_preread(tier=tier, subject=subject)
        await self.check_recall_purpose(recall_purpose=recall_purpose, write_purpose=write_purpose)
        return None

    async def check_recall_preread(
        self, *, tier: MemoryTier, subject: SubjectRef | None = None
    ) -> None:
        """Pre-read recall authz (§7.2 steps 1-3): sub-agent durable guard, read
        capability, subject scope. Runs BEFORE the adapter read so an
        unauthorized caller never triggers a stored-record read — a cross-subject
        ``read_block`` is refused before subject B's row is fetched. Does NOT run
        the purpose matrix (step 4): the stored write purpose is only known after
        the read; the caller runs :meth:`check_recall_purpose` against
        ``hit.purpose``. First applicable failure raises
        ``MemoryOperationRefused(reason)``; identity is read from the bound
        context, never the arguments."""
        ctx = self._context

        # Step 1 — sub-agent durable-access guard (§7.3 I2).
        if ctx.is_subagent and tier in _SUBAGENT_REFUSED_TIERS:
            raise MemoryOperationRefused("memory_subagent_durable_access_refused")

        # Step 2 — read capability for the tier.
        if f"memory_read.{tier}" not in ctx.memory_read_capabilities:
            raise MemoryOperationRefused("memory_recall_capability_missing")

        # Step 3 — subject scope (explicit-subject reads only).
        if subject is not None and subject.canonical != ctx.served_subject.canonical:
            await self._require_cross_subject_allowed()

    async def check_recall_purpose(self, *, recall_purpose: str, write_purpose: str | None) -> None:
        """Purpose-compatibility matrix (§7.2 step 4). Refuse with
        ``memory_purpose_mismatch`` when ``recall_purpose`` is incompatible with
        the stored ``write_purpose`` per ``memory_purpose_matrix.rego`` (an OPA
        error fails closed to the same refusal). Run AFTER the read with
        ``write_purpose=hit.purpose`` — passing ``None`` against the default-deny
        bundle refuses every recall."""
        if not await self._purpose_matrix_allows(
            recall_purpose=recall_purpose, write_purpose=write_purpose
        ):
            raise MemoryOperationRefused("memory_purpose_mismatch")

    # -- Lifecycle gate (§7.3 I2 — forget/redact authz) -------------------

    async def check_lifecycle(self) -> None:
        """Forget/redact authz (§7.3 I2): a sub-agent may not mutate durable
        memory — children are scratch-only. Identity is read from the bound
        context; there is no per-call argument (the op layer passes the gate,
        not a separate identity)."""
        if self._context.is_subagent:
            raise MemoryOperationRefused("memory_subagent_durable_access_refused")

    # -- Enumerate gate (§7.2 minus the keyed-record steps) ----------------

    async def check_enumerate(
        self, subject: SubjectRef, *, tiers: tuple[MemoryTier, ...] = ("task", "long_term")
    ) -> None:
        """Enumerate-family recall gate (§7.2 minus the keyed-record steps) for
        list_for_subject / list_blocks. Ordered precedence; first failure raises.

        Unlike :meth:`check_recall` there is no purpose-matrix step (an
        enumerate returns record IDs / block refs, not a keyed value under a
        recall purpose). Enumeration is NOT a capability bypass — the read
        capability is required for EVERY enumerated tier. On success returns
        ``None``; the caller decides the audit — ``list_for_subject`` emits one
        ``memory.read`` (enumerate shape), while ``list_blocks`` emits none (a
        structural block listing, governed at the later ``read_block``).

        Args:
            subject: The subject whose records are being enumerated; compared to
                ``context.served_subject`` at step 3 (cross-subject leak guard).
            tiers: The tiers spanned by the enumeration (default the two durable
                tiers ``("task", "long_term")``); each must be readable.
        """
        ctx = self._context

        # Step 1 — sub-agent durable-access guard (§7.3 I2).
        if ctx.is_subagent and any(t in _SUBAGENT_REFUSED_TIERS for t in tiers):
            raise MemoryOperationRefused("memory_subagent_durable_access_refused")

        # Step 2 — read capability for EVERY enumerated tier (enumeration is not
        # a capability bypass).
        for t in tiers:
            if f"memory_read.{t}" not in ctx.memory_read_capabilities:
                raise MemoryOperationRefused("memory_recall_capability_missing")

        # Step 3 — subject scope (cross-subject leak guard; reuses the T9 helper).
        if subject.canonical != ctx.served_subject.canonical:
            await self._require_cross_subject_allowed()

        # Step 4 — success. Per-caller audit: list_for_subject emits one
        # memory.read (enumerate shape); list_blocks emits none.
        return None

    # -- Per-decision-point Rego helpers (fail-closed each, step-specific) --

    async def _long_term_rego_allows(self) -> bool:
        """Evaluate the long_term decision point; OPA error → fail-closed deny."""
        try:
            decision = await self._policy.evaluate(
                decision_point=_LONG_TERM_DECISION_POINT,
                input={
                    "tenant_id": self._context.tenant_id,
                    "agent_id": self._context.agent_id,
                    "risk_tier": self._context.risk_tier,
                },
            )
        except (OpaNotInstalledError, RegoEvaluationError):
            return False
        return decision.allow

    async def _restricted_class_rego_allows(self) -> bool:
        """Evaluate the restricted-class-write decision point; OPA error →
        fail-closed deny (mapped by the caller to
        ``memory_restricted_class_write_denied``)."""
        try:
            decision = await self._policy.evaluate(
                decision_point=_RESTRICTED_CLASS_WRITE_DECISION_POINT,
                input={
                    "tenant_id": self._context.tenant_id,
                    "agent_id": self._context.agent_id,
                    "risk_tier": self._context.risk_tier,
                },
            )
        except (OpaNotInstalledError, RegoEvaluationError):
            return False
        return decision.allow

    async def _require_cross_subject_allowed(self) -> None:
        """Refuse unless the pack declares ``cross_subject_recall`` AND the
        cross-subject Rego allows. An OPA error fails closed to the
        cross-subject refusal for THIS step only."""
        if not self._context.cross_subject_recall:
            raise MemoryOperationRefused("memory_cross_subject_access_refused")
        try:
            decision = await self._policy.evaluate(
                decision_point=_CROSS_SUBJECT_DECISION_POINT,
                input={
                    "tenant_id": self._context.tenant_id,
                    "agent_id": self._context.agent_id,
                    "served_subject": self._context.served_subject.canonical,
                },
            )
        except (OpaNotInstalledError, RegoEvaluationError):
            raise MemoryOperationRefused("memory_cross_subject_access_refused") from None
        if not decision.allow:
            raise MemoryOperationRefused("memory_cross_subject_access_refused")

    async def _purpose_matrix_allows(
        self, *, recall_purpose: str, write_purpose: str | None
    ) -> bool:
        """Evaluate the purpose-matrix decision point; OPA error → fail-closed
        deny (mapped by the caller to ``memory_purpose_mismatch``)."""
        try:
            decision = await self._policy.evaluate(
                decision_point=_PURPOSE_COMPATIBLE_DECISION_POINT,
                input={
                    "tenant_id": self._context.tenant_id,
                    "recall_purpose": recall_purpose,
                    "write_purpose": write_purpose,
                },
            )
        except (OpaNotInstalledError, RegoEvaluationError):
            return False
        return decision.allow

    # -- Retention clamp ---------------------------------------------------

    @staticmethod
    def _resolve_retention_until(
        *,
        retention_window_s: int | None,
        tenant_retention_max_s: int | None,
    ) -> datetime | None:
        """Resolve the effective ``retention_until`` (CLAMP, never refuse).

        Convention: the effective window (seconds) is the ``min`` of the
        caller-declared window and the tenant maximum, whichever are set; the
        result is ``now(UTC) + window``. ``None`` for BOTH → ``None`` (no
        expiry is set on the record).
        """
        windows = [w for w in (retention_window_s, tenant_retention_max_s) if w is not None]
        if not windows:
            return None
        effective = min(windows)
        return datetime.now(UTC) + timedelta(seconds=effective)


__all__ = ("MemoryGate",)
