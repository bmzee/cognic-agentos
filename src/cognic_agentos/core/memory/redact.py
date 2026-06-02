"""Sprint 11.5b — redact op (new sealed version). core/ stop-rule.

CRITICAL CONTROL (core/ stop-rule per AGENTS.md — Memory governance, ADR-019
§"Forget + redact"). Thin forwarder: check_lifecycle() (sub-agent durable guard)
runs FIRST — a sub-agent refusal wins before any storage access — then delegates
ONCE to the T4 adapter.redact_record (which owns the field-path redaction, the
seal-old-then-insert-new block ordering, the tenant/agent scoping, and the
memory.redact chain row). Identity is read from the bound gate._context ONLY;
no caller-supplied identity. The op adds NO chain/value logic and does NOT catch
storage refusals (memory_redaction_path_invalid / memory_record_not_found
propagate).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cognic_agentos.core.memory._context import MemoryRecordId, RedactionReceipt, RedactionSpan
    from cognic_agentos.core.memory.gate import MemoryGate
    from cognic_agentos.core.memory.storage import MemoryAdapter
    from cognic_agentos.core.memory.tiers import RedactionReason


async def redact(
    record_id: MemoryRecordId,
    *,
    span: RedactionSpan,
    reason: RedactionReason,
    gate: MemoryGate,
    adapter: MemoryAdapter,
) -> RedactionReceipt:
    """Create a new sealed version of a memory record with a redacted field.

    **Ordered precedence (first applicable failure short-circuits):**

    1. ``gate.check_lifecycle()`` — sub-agent durable-access guard (§7.3 I2).
       A sub-agent gate raises ``memory_subagent_durable_access_refused``
       BEFORE any storage access.
    2. Storage delegation — ``adapter.redact_record`` owns the field-path
       walk, the seal-old-then-insert-new ordering, the tenant/agent scoping,
       and the ``memory.redact`` chain row emission. Storage refusals
       (``memory_redaction_path_invalid`` / ``memory_record_not_found``)
       propagate unchanged — this op does NOT catch them.

    Identity (``tenant_id`` / ``agent_id`` / ``actor_id``) is read from the
    bound ``gate._context`` — never from caller arguments.

    Args:
        record_id: The UUID of the memory record to redact.
        span: The :class:`~cognic_agentos.core.memory._context.RedactionSpan`
            describing the field path and replacement value.
        reason: The :data:`~cognic_agentos.core.memory.tiers.RedactionReason`
            carried on the ``memory.redact`` chain row.
        gate: The bound :class:`~cognic_agentos.core.memory.gate.MemoryGate`
            providing identity + authz. ``check_lifecycle()`` is the first step.
        adapter: The :class:`~cognic_agentos.core.memory.storage.MemoryAdapter`
            backend that owns the storage mutation + chain emission.

    Returns:
        :class:`~cognic_agentos.core.memory._context.RedactionReceipt` with
        ``record_id`` (the original, now sealed), ``new_version_id`` (the new
        active row), and ``redaction_version`` (monotonically increasing).

    Raises:
        MemoryOperationRefused: With reason
            ``"memory_subagent_durable_access_refused"`` (step 1),
            ``"memory_redaction_path_invalid"`` (step 2 — absent or
            non-mapping path segment inside the stored value), or
            ``"memory_record_not_found"`` (step 2 — no active row exists).
    """
    # Step 1 — lifecycle gate (sub-agent durable guard). MUST run FIRST so a
    # sub-agent refusal wins over every later failure (storage).
    await gate.check_lifecycle()

    # Identity from the bound context ONLY — never caller arguments.
    ctx = gate._context  # same-package access; no public accessor in 11.5a

    # Step 2 — delegate to storage (owns path-walk, seal-then-insert, chain row).
    return await adapter.redact_record(
        tenant_id=ctx.tenant_id,
        agent_id=ctx.agent_id,
        record_id=record_id,
        span=span,
        reason=reason,
        actor_id=ctx.actor_id,
    )


__all__ = ("redact",)
