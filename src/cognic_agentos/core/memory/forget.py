"""Sprint 11.5b — forget op (soft-delete + regulator-erasure). core/ stop-rule.

CRITICAL CONTROL (``core/`` stop-rule per AGENTS.md — Memory governance
enforcement, ADR-019 §"Forget + redact"). This module owns the
``forget()`` operation: soft-delete via tombstone OR immediate physical purge
(regulator-erasure) plus the regulator-erasure command-metadata contract
(locked decision #4).

**Ordered precedence IS the contract.**  ``check_lifecycle()`` runs FIRST (the
sub-agent durable-access guard per §7.3 I2); a sub-agent refusal WINS over
any later failure — including a missing or malformed regulator-erasure command
— because the gate short-circuits before the metadata check runs.

**Identity is read from the bound** :class:`MemoryGate` **only.** ``forget``
never accepts a caller-supplied ``tenant_id`` / ``agent_id`` / ``actor_id``;
the bound ``gate._context`` is the SOLE identity source. A Layer C caller
cannot smuggle a different identity through the op layer.

**RBAC is the 11.5c portal's job.** ``core/`` has no ``Actor``/scope set.
Core enforces only the sub-agent guard (via ``check_lifecycle()``) and the
regulator-erasure command-metadata contract (``requester_scope`` equality).
The ``memory.regulator_erasure`` RBAC scope is validated at the portal
boundary, not here.

**Value-never-in-chain invariant.** ``forget()`` delegates entirely to T4
storage primitives (``tombstone_record`` / ``purge_record``), which themselves
emit the ``memory.forget`` / ``memory.regulator_erasure`` chain rows carrying
only metadata (``record_id`` / ``reason`` / ``tenant_id`` / ``agent_id`` /
chain-of-custody fields). The op layer adds NO ``value`` or
``redacted_value_digest`` to the chain — the invariant is owned by the
storage layer, but this module's contract is to pass only ``MemoryRecordId``
and metadata, never the record's value.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from cognic_agentos.core.memory._context import ForgetReceipt
from cognic_agentos.core.memory.tiers import MemoryOperationRefused

if TYPE_CHECKING:
    from cognic_agentos.core.memory._context import MemoryRecordId, RegulatorErasureCommand
    from cognic_agentos.core.memory.gate import MemoryGate
    from cognic_agentos.core.memory.storage import MemoryAdapter
    from cognic_agentos.core.memory.tiers import ForgetReason

#: The only accepted ``requester_scope`` for a regulator-erasure command (locked
#: decision #4 — core validates this string; RBAC enforcement of who may HOLD
#: this scope is the 11.5c portal's job).
_REGULATOR_ERASURE_SCOPE = "memory.regulator_erasure"


async def forget(
    record_id: MemoryRecordId,
    *,
    reason: ForgetReason,
    gate: MemoryGate,
    adapter: MemoryAdapter,
    erasure_command: RegulatorErasureCommand | None = None,
) -> ForgetReceipt:
    """Soft-delete or physically purge a memory record.

    **Ordered precedence (first applicable failure short-circuits):**

    1. ``gate.check_lifecycle()`` — sub-agent durable-access guard (§7.3 I2).
       A sub-agent gate raises ``memory_subagent_durable_access_refused``
       BEFORE any metadata or storage check runs.
    2. Regulator-erasure metadata gate — when ``reason == "regulator_erasure"``,
       ``erasure_command`` MUST be non-``None`` and its ``requester_scope``
       MUST equal ``"memory.regulator_erasure"``; otherwise raises
       ``memory_regulator_erasure_metadata_required``.
    3. Storage delegation — soft reasons delegate to ``adapter.tombstone_record``;
       ``regulator_erasure`` delegates to ``adapter.purge_record`` (physical DELETE
       inside an atomic ``append_with_precondition`` transaction that also emits
       the chain row).

    Identity (``tenant_id`` / ``agent_id`` / ``actor_id``) is read from the
    bound ``gate._context`` — never from caller arguments.

    Args:
        record_id: The UUID of the memory record to forget.
        reason: The :data:`~cognic_agentos.core.memory.tiers.ForgetReason`
            that initiated the forget. ``"regulator_erasure"`` requires a
            valid ``erasure_command``.
        gate: The bound :class:`~cognic_agentos.core.memory.gate.MemoryGate`
            providing identity + authz. ``check_lifecycle()`` is the first
            step.
        adapter: The :class:`~cognic_agentos.core.memory.storage.MemoryAdapter`
            backend that owns the storage mutation + chain emission.
        erasure_command: Required when ``reason == "regulator_erasure"``;
            must carry ``requester_scope == "memory.regulator_erasure"`` and
            the chain-of-custody ``regulator_order_id`` / ``subject_id``.
            Ignored for all other reasons.

    Returns:
        :class:`~cognic_agentos.core.memory._context.ForgetReceipt` with
        ``tombstoned=True`` always on the success path.  ``purged=True`` only
        on the ``regulator_erasure`` physical-DELETE path.

    Raises:
        MemoryOperationRefused: With reason
            ``"memory_subagent_durable_access_refused"`` (step 1),
            ``"memory_regulator_erasure_metadata_required"`` (step 2),
            ``"memory_record_not_found"`` (step 3 — raised inside the storage
            precondition), or ``"memory_record_already_tombstoned"`` (step 3).
    """
    # Step 1 — lifecycle gate (sub-agent durable guard). MUST run FIRST so a
    # sub-agent refusal wins over every later failure (metadata gate, storage).
    await gate.check_lifecycle()

    # Identity from the bound context ONLY — never caller arguments.
    ctx = gate._context  # same-package access; no public accessor in 11.5a

    # Step 2 — regulator-erasure metadata gate.
    if reason == "regulator_erasure":
        if erasure_command is None or erasure_command.requester_scope != _REGULATOR_ERASURE_SCOPE:
            raise MemoryOperationRefused("memory_regulator_erasure_metadata_required")
        # Step 3a — physical purge (DELETE + memory.regulator_erasure chain row).
        await adapter.purge_record(
            tenant_id=ctx.tenant_id,
            agent_id=ctx.agent_id,
            record_id=record_id,
            erasure_command=erasure_command,
            actor_id=ctx.actor_id,
        )
        return ForgetReceipt(record_id=record_id, tombstoned=True, purged=True)

    # Step 3b — soft-delete (tombstone + memory.forget chain row).
    await adapter.tombstone_record(
        tenant_id=ctx.tenant_id,
        agent_id=ctx.agent_id,
        record_id=record_id,
        reason=reason,
        actor_id=ctx.actor_id,
    )
    return ForgetReceipt(record_id=record_id, tombstoned=True, purged=False)


__all__ = ("forget",)
