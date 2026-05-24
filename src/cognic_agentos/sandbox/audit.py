"""Sprint 8A T4 — sandbox lifecycle event emitters.

NOT on the durable critical-controls coverage gate (thin chain-row
converter; the substantive audit-chain invariants are enforced upstream
by the on-gate ``core/audit.py`` + ``core/decision_history.py`` +
``core/canonical.py``). Per spec §17 critical-controls-scope rationale.

Verified against ``core/decision_history.py:206`` ``DecisionRecord``
shape + ``:409`` ``append_with_precondition`` signature at session
compose time per ``feedback_verify_code_citations_at_doc_write``:

* ``DecisionRecord`` is ``frozen=True, slots=True`` with **exactly 10
  constructor fields** (3 required: ``decision_type`` / ``request_id`` /
  ``payload``; 7 optional: ``actor_id`` / ``tenant_id`` / ``trace_id`` /
  ``span_id`` / ``langfuse_trace_id`` / ``provider_label`` /
  ``iso_controls``). ``session_id`` lives on ``payload`` (per the
  established ``escalation.py:560`` pattern) — NOT as a top-level
  ``DecisionRecord`` field. The fields ``record_id`` / ``chain_id`` /
  ``sequence`` / ``new_hash`` / ``created_at`` live on the SEPARATE
  ``AppendedDecisionSnapshot`` dataclass at
  ``core/decision_history.py:252`` (post-commit hook surface) — NOT
  fields the implementor passes to the ``DecisionRecord`` constructor.
* ``append_with_precondition`` signature: ``precondition`` is
  ``async (conn, prev_sequence, prev_hash) -> T``; ``record_builder``
  is ``sync (captured: T) -> DecisionRecord``. The precondition runs
  INSIDE the chain-head ``FOR UPDATE`` lock; for audit-only events with
  no state precondition, the closure is a no-op that returns ``None``.

ISO 42001 mapping: every chain row tagged with the canonical
``("ISO42001.A.6.2.5",)`` per ADR-006 amendment (sandbox lifecycle audit).
"""

from __future__ import annotations

import typing
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy.ext.asyncio import AsyncConnection

from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    DecisionRecord,
)
from cognic_agentos.core.vault import CredentialLease
from cognic_agentos.sandbox.protocol import CheckpointId, SandboxLifecycleEvent

_VALID_EVENTS: frozenset[str] = frozenset(typing.get_args(SandboxLifecycleEvent))

# Sprint 8.5 T2 — closed-enum for checkpoint-purge reasons per spec §4.3
# P3.r4 (4 values; UNCHANGED — invariant pinned in the spec patch log).
# Validated at the ``sandbox_lifecycle_checkpoint_purged`` helper
# boundary per ``feedback_evidence_boundary_runtime_validation``
# ("unknown Literal values fail-loud").
PurgeReason = Literal[
    "explicit_destroy",
    "max_per_session_cap",
    "retention_expired",
    "tenant_revocation",
]
_VALID_PURGE_REASONS: frozenset[str] = frozenset(typing.get_args(PurgeReason))


# Per-event payload shape contracts (informational; the emit signature
# accepts any dict and the runtime callers MUST match these per spec §4.3
# + Sprint 8.5 §5.1):
#
# Sprint 8A (8 events):
#   sandbox.lifecycle.created        → {"warm_pool_hit": bool}
#   sandbox.lifecycle.exec_completed → {"exit_code": int, "proxy_log": list[dict]}
#   sandbox.lifecycle.destroyed      → {"duration_s": float, ...}
#       Sprint 8.5 P1.r4 destroy() extension: when the destroyed session
#       had persisted checkpoints, payload additionally carries TWO
#       conditional keys:
#         "retained_until": <iso-string>      (= now + sandbox_checkpoint_retention_s
#                                              at destroy() time)
#         "tombstone_object_key": <storage-key>  (= the
#                                              <tenant>/<session>/_tombstoned.json
#                                              key returned by
#                                              CheckpointStore.tombstone_session())
#       Presence of these 2 keys is the wire-public marker that retention
#       is in effect for this session's checkpoints (per spec §5.1); absence
#       means immediate physical destroy (no tombstone needed because there
#       was nothing to retain). Existing 8A callers pass {"duration_s": ...}
#       unchanged — extension is additive + caller-controlled.
#   sandbox.lifecycle.refused        → {"reason": SandboxRefusalReason}
#   sandbox.policy.violated          → {"reason": SandboxPolicyViolationReason}
#   sandbox.warm_pool.precreated     → {"pool_key": str, "pool_size_after": int}
#   sandbox.warm_pool.checked_out    → {"pool_key": str, "pool_size_after": int}
#   sandbox.warm_pool.drained        → {"pool_key": str, "drained_count": int}
#
# Sprint 8.5 T2 (4 NEW events per spec §5.1) — emitted via the typed
# helper functions below (sandbox_lifecycle_checkpointed / _suspended
# / _woken / _checkpoint_purged), which wrap emit_sandbox_event with
# the canonical payload shape. T6/T7 backend wake/checkpoint/suspend
# impls call these helpers rather than emit_sandbox_event directly so
# the payload shape stays locked at one site:
#   sandbox.lifecycle.checkpointed   → {"checkpoint_id": str, "label": str,
#                                       "created_at": <iso-string-tz-aware>,
#                                       "policy_digest": str}
#   sandbox.lifecycle.suspended      → {"final_checkpoint_id": str}
#       — final_checkpoint_id IS the linkage target the wake-time chain
#       verifier walks back to per spec §5.2.
#   sandbox.lifecycle.woken          → {"restored_from_checkpoint_id": str,
#                                       "suspend_event_id": <uuid-str>}
#       — payload-key NAME `suspend_event_id` is wire-public per ADR-006
#       for examiner-readability; its VALUE is the UUID returned as the
#       first tuple element from the suspend-time emit call (i.e. the
#       suspended row's primary-key record_id column at
#       decision_history.py:188). NO new DecisionRecord column added;
#       the chain-verifier walker (spec §5.2) looks up
#       decision_history WHERE record_id = payload["suspend_event_id"].
#   sandbox.lifecycle.checkpoint_purged → {"checkpoint_id": str,
#                                          "purge_reason": PurgeReason}
#       — purge_reason is the 4-value closed enum
#       (explicit_destroy / max_per_session_cap / retention_expired /
#       tenant_revocation; UNCHANGED 4-value set per spec §4.3 P3.r4).
#       Helper validates fail-loud against the closed set.
#
# ``session_id`` is threaded onto every payload by ``emit_sandbox_event``
# (NOT a top-level DR field per the verified DecisionRecord shape).


async def emit_sandbox_event(
    decision_history_store: DecisionHistoryStore,
    *,
    event: SandboxLifecycleEvent,
    tenant_id: str,
    actor_id: str,
    trace_id: str,
    session_id: str,
    payload: dict[str, Any],
) -> tuple[uuid.UUID, bytes]:
    """Emit one sandbox lifecycle event into the chain.

    Tagged with the canonical ISO 42001 ID ``ISO42001.A.6.2.5`` per ADR-006.

    Returns the ``(record_id, new_hash)`` tuple from
    ``DecisionHistoryStore.append_with_precondition`` per
    ``core/decision_history.py:414``.

    Audit-only events have no transactional precondition (no state
    machine; nothing to read+lock before insert), so the precondition
    closure is a no-op returning ``None``. The ``record_builder``
    receives the captured value (``None``) and builds the
    ``DecisionRecord``.

    ``actor_id`` matches the ``DecisionRecord.actor_id`` constructor
    field; the store-side ``_validate_and_normalize_record`` (per
    ``core/decision_history.py:432``) merges it into the canonicalised
    persisted payload under the key ``"actor_id"`` before hashing.
    ``session_id`` is threaded onto the caller's payload dict before
    handoff (NOT a top-level DR field — session-scoped values follow
    the ``escalation.py:560`` payload-merge pattern).
    """

    if event not in _VALID_EVENTS:
        raise ValueError(
            f"{event!r} is not a valid SandboxLifecycleEvent; "
            f"expected one of {sorted(_VALID_EVENTS)}"
        )

    # Merge session_id into payload — NOT a top-level DR field per the
    # verified core/decision_history.py:206 shape.
    full_payload = {**payload, "session_id": session_id}
    request_id = f"sandbox-evt-{uuid.uuid4().hex}"

    async def _precondition(
        _conn: AsyncConnection,
        _prev_sequence: int,
        _prev_hash: bytes,
    ) -> None:
        # Audit-only — no state to project; no validator to run inside
        # the chain-head lock; returns None which flows into _build_record.
        return None

    def _build_record(_captured: None) -> DecisionRecord:
        # Constructs the 10-field DecisionRecord per
        # core/decision_history.py:206. record_id / chain_id / sequence /
        # new_hash / created_at live on the SEPARATE
        # AppendedDecisionSnapshot (post-commit, hook-only) — NOT on
        # DecisionRecord; the store assigns those snapshot fields after
        # commit and passes the snapshot to hooks.
        return DecisionRecord(
            decision_type=event,
            request_id=request_id,
            payload=full_payload,
            actor_id=actor_id,
            tenant_id=tenant_id,
            trace_id=trace_id,
            iso_controls=("ISO42001.A.6.2.5",),
        )

    return await decision_history_store.append_with_precondition(
        record_builder=_build_record,
        precondition=_precondition,
    )


# ---------------------------------------------------------------------------
# Sprint 8.5 T2 — typed helper functions for the 4 new lifecycle events.
#
# Each helper wraps ``emit_sandbox_event`` with the canonical payload
# shape per spec §5.1. T6/T7 backend wake/checkpoint/suspend impls call
# these helpers (rather than ``emit_sandbox_event`` directly) so the
# payload-key set stays pinned at ONE site + drift in field names is
# caught at the helper boundary instead of scattered across backend
# call sites.
#
# Per the user's T2 brief: helpers preserve the ``emit_sandbox_event``
# seam unchanged — they only add canonical payload-shape bundling on
# top.
#
# Per ``feedback_evidence_boundary_runtime_validation``:
#   - tz-aware datetimes generated INSIDE the helper (where applicable)
#     so callers can't accidentally pass naive datetime.
#   - list-shape only in payloads (no tuples; canonical_bytes rejects).
#   - unknown closed-enum values fail-loud at the helper boundary.
# ---------------------------------------------------------------------------


async def sandbox_lifecycle_checkpointed(
    decision_history_store: DecisionHistoryStore,
    *,
    tenant_id: str,
    actor_id: str,
    trace_id: str,
    session_id: str,
    checkpoint_id: CheckpointId,
    label: str,
    policy_digest: str,
) -> tuple[uuid.UUID, bytes]:
    """Emit ``sandbox.lifecycle.checkpointed`` per spec §5.1.

    Called from ``SandboxSession.checkpoint()`` after the workspace-tar
    snapshot is successfully persisted via
    ``CheckpointStore.persist()``. Payload-shape contract:
    ``{checkpoint_id, label, created_at (tz-aware ISO string),
    policy_digest}`` per spec §5.1.

    ``created_at`` is generated INSIDE the helper as
    ``datetime.now(UTC).isoformat()`` to enforce tz-awareness
    consistently across callers (per
    ``feedback_evidence_boundary_runtime_validation``). ``policy_digest``
    is a caller-supplied hash (typically
    ``sha256(canonical_bytes(policy.to_storage_payload()))``) for the
    chain-verifier's cross-verify against the admit_policy decision.
    """
    created_at = datetime.now(UTC).isoformat()
    return await emit_sandbox_event(
        decision_history_store,
        event="sandbox.lifecycle.checkpointed",
        tenant_id=tenant_id,
        actor_id=actor_id,
        trace_id=trace_id,
        session_id=session_id,
        payload={
            "checkpoint_id": str(checkpoint_id),
            "label": label,
            "created_at": created_at,
            "policy_digest": policy_digest,
        },
    )


async def sandbox_lifecycle_suspended(
    decision_history_store: DecisionHistoryStore,
    *,
    tenant_id: str,
    actor_id: str,
    trace_id: str,
    session_id: str,
    final_checkpoint_id: CheckpointId,
) -> tuple[uuid.UUID, bytes]:
    """Emit ``sandbox.lifecycle.suspended`` per spec §5.1.

    Called from ``SandboxSession.suspend()`` after the final
    (label=``__suspend__``) checkpoint is persisted + the container/Pod
    is released. Payload-shape contract: ``{final_checkpoint_id}``.

    ``final_checkpoint_id`` IS the linkage target the wake-time chain
    verifier walks back to per spec §5.2 — wake() emits
    ``restored_from_checkpoint_id`` matching this value, and the
    verifier asserts the suspended row's ``final_checkpoint_id`` equals
    the woken row's ``restored_from_checkpoint_id``.
    """
    return await emit_sandbox_event(
        decision_history_store,
        event="sandbox.lifecycle.suspended",
        tenant_id=tenant_id,
        actor_id=actor_id,
        trace_id=trace_id,
        session_id=session_id,
        payload={
            "final_checkpoint_id": str(final_checkpoint_id),
        },
    )


async def sandbox_lifecycle_woken(
    decision_history_store: DecisionHistoryStore,
    *,
    tenant_id: str,
    actor_id: str,
    trace_id: str,
    session_id: str,
    restored_from_checkpoint_id: CheckpointId,
    suspend_event_id: uuid.UUID,
) -> tuple[uuid.UUID, bytes]:
    """Emit ``sandbox.lifecycle.woken`` per spec §5.1.

    Called from ``SandboxBackend.wake()`` after the fresh backend
    resource is created + the workspace-tar snapshot is restored.
    Payload-shape contract: ``{restored_from_checkpoint_id,
    suspend_event_id}``.

    The payload-key NAME ``suspend_event_id`` is wire-public per ADR-006
    for examiner-readability; its VALUE is the UUID returned as the
    first tuple element from the suspend-time
    ``sandbox_lifecycle_suspended`` call (i.e. the suspended row's
    primary-key ``record_id`` column at ``decision_history.py:188``).

    NO new ``DecisionRecord`` column added — the chain-verifier walker
    (spec §5.2) looks up ``decision_history WHERE record_id =
    payload["suspend_event_id"]`` to find the matching suspend row.
    Serialised to string in the payload so canonical_bytes round-trips
    cleanly (UUID is not in the canonical-bytes-allowed type set per
    the Sprint-2 doctrine; the chain verifier parses back via
    ``uuid.UUID(value)``).
    """
    return await emit_sandbox_event(
        decision_history_store,
        event="sandbox.lifecycle.woken",
        tenant_id=tenant_id,
        actor_id=actor_id,
        trace_id=trace_id,
        session_id=session_id,
        payload={
            "restored_from_checkpoint_id": str(restored_from_checkpoint_id),
            "suspend_event_id": str(suspend_event_id),
        },
    )


async def sandbox_lifecycle_checkpoint_purged(
    decision_history_store: DecisionHistoryStore,
    *,
    tenant_id: str,
    session_id: str,
    checkpoint_id: CheckpointId,
    purge_reason: PurgeReason,
    actor_id: str = "reaper",
    trace_id: str = "reaper",
) -> tuple[uuid.UUID, bytes]:
    """Emit ``sandbox.lifecycle.checkpoint_purged`` per spec §5.1.

    Called from ``CheckpointStore.purge_by_id()`` (reaper sweep + the
    persist() cap-eviction path; T3 wires both). Payload-shape contract:
    ``{checkpoint_id, purge_reason}`` per spec §5.1.

    ``purge_reason`` is the 4-value closed enum
    (``PurgeReason`` literal above per spec §4.3 P3.r4 — UNCHANGED
    4-value set; NO ``retention_window_active`` value invented; that
    configuration-tension surface is signalled via the
    ``CheckpointMaxPerSessionRetentionLocked`` typed exception at the
    persist() call site, NOT via this audit event). Helper validates
    fail-loud against the closed set per
    ``feedback_evidence_boundary_runtime_validation`` ("unknown Literal
    values fail-loud").

    ``actor_id`` defaults to ``"reaper"`` — the typical caller is the
    background ``CheckpointReaper`` (T4); operator-driven
    ``tenant_revocation`` purges can override.
    """
    if purge_reason not in _VALID_PURGE_REASONS:
        raise ValueError(
            f"{purge_reason!r} is not a valid PurgeReason; "
            f"expected one of {sorted(_VALID_PURGE_REASONS)}"
        )
    return await emit_sandbox_event(
        decision_history_store,
        event="sandbox.lifecycle.checkpoint_purged",
        tenant_id=tenant_id,
        actor_id=actor_id,
        trace_id=trace_id,
        session_id=session_id,
        payload={
            "checkpoint_id": str(checkpoint_id),
            "purge_reason": purge_reason,
        },
    )


# ---------------------------------------------------------------------------
# Sprint 10 T9 — 3 typed helpers for lease lifecycle events per spec §6.2.
#
# Payload-shape contract per spec §6.2:
#   - 10 always-fields on lease_minted + lease_revoked:
#       lease_id, secret_path, scope_label, tenant_id, actor_subject,
#       actor_type, ttl_s, ttl_s_granted, minted_at (tz-aware ISO),
#       expires_at (tz-aware ISO)
#   - lease_revoke_failed adds 2 conditional keys:
#       vault_error (Vault HTTP error string; caller-supplied, the only
#         field that cannot be derived from CredentialLease), auto_expiry_at
#         (== expires_at per spec §6.2; derived inside the helper)
#   - session_id threaded by emit_sandbox_event = 11 / 13 total keys
#
# Helper input-shape lock — single-source-of-truth derive:
#   - lease: CredentialLease (single positional) — all request + lease
#     projections derived from one frozen dataclass.
#   - ``DecisionRecord.tenant_id`` AND ``DecisionRecord.actor_id`` are
#     also DERIVED from ``lease.request.tenant_id`` +
#     ``lease.request.actor_ref.actor_subject`` (NOT accepted as
#     separate kwargs). This closes the contradictory-evidence bug
#     class by construction: a caller cannot pass a chain-metadata
#     tenant/actor that disagrees with the lease-payload tenant/actor,
#     because there is no caller-supplied channel for those values.
#     Sprint 8.5 T2 helpers couldn't use this pattern because their
#     inputs were unrelated values (checkpoint_id + label +
#     policy_digest); the Sprint-10 helpers naturally share one
#     dataclass that already carries the canonical tenant_id +
#     actor_subject.
#   - ``trace_id`` + ``session_id`` remain caller-supplied — they are
#     session-scoped + trace-scoped (NOT lease-scoped), so they
#     cannot live on the lease dataclass.
#   - ``vault_error: str`` on revoke_failed — the only field not
#     derivable from CredentialLease (it carries the Vault HTTP error
#     string the backend captured during the failed revoke). Per spec
#     §6.2, ``auto_expiry_at`` is derived from ``lease.expires_at`` —
#     accepting it as a caller string would re-open the silent-lie bug
#     class (caller could pass an arbitrary string disagreeing with
#     ``expires_at``; spec §6.2 line 624 explicitly says
#     ``auto_expiry_at`` equals ``expires_at``, just surfaced
#     separately for the examiner's "this lease should auto-expire on
#     its own" claim).
#
# Per spec §6.2 + AGENTS.md "Wire-protocol contracts": token contents
# NEVER appear on the chain row. Examiners trace by lease_id +
# secret_path + scope_label. The projection helper below DELIBERATELY
# does not surface ``lease.token`` — defence-in-depth pinned by
# regression tests at
# ``tests/unit/sandbox/test_audit_event_taxonomy.py`` that scan all
# payload values for a sentinel token string.
# ---------------------------------------------------------------------------


def _project_lease_evidence_payload(lease: CredentialLease) -> dict[str, Any]:
    """spec §6.2 10-key always-projection from CredentialLease.

    Single source of truth for the lease_minted / lease_revoked /
    lease_revoke_failed payload base. revoke_failed adds 2 conditional
    keys (``vault_error`` + ``auto_expiry_at``) at its helper boundary.

    Pins the shape against drift in CredentialLease /
    VaultLeaseRequest / VaultLeaseActorRef field names at one site —
    the regression tests assert ``set(payload.keys())`` against the
    expected key set so a future field rename in the source dataclass
    surfaces here instead of silently changing the chain-row shape.

    Token contents are DELIBERATELY NOT projected — banks trace leases
    by lease_id + secret_path + scope_label; the bearer token is the
    actual Vault credential and stays out of the audit chain per spec
    §6.2 + AGENTS.md "Wire-protocol contracts".

    ``minted_at`` + ``expires_at`` rendered as ISO 8601 strings
    (the dataclass fields are ``datetime`` per ``core/vault.py:170-172``;
    the chain canonical-bytes layer rejects ``datetime`` per Sprint-2
    doctrine, so serialisation is mandatory). The source datetimes are
    tz-aware (constructed via ``datetime.now(UTC)`` in
    ``core/vault.lease_credential``), so ``.isoformat()`` produces
    tz-aware ISO strings that round-trip back to tz-aware datetimes —
    pinned by the evidence-boundary regression in the typed-helper
    test classes.
    """
    return {
        "lease_id": lease.lease_id,
        "secret_path": lease.request.secret_path,
        "scope_label": lease.request.scope_label,
        "tenant_id": lease.request.tenant_id,
        "actor_subject": lease.request.actor_ref.actor_subject,
        "actor_type": lease.request.actor_ref.actor_type,
        "ttl_s": lease.request.ttl_s,
        "ttl_s_granted": lease.ttl_s_granted,
        "minted_at": lease.minted_at.isoformat(),
        "expires_at": lease.expires_at.isoformat(),
    }


async def sandbox_lifecycle_lease_minted(
    decision_history_store: DecisionHistoryStore,
    *,
    lease: CredentialLease,
    trace_id: str,
    session_id: str,
) -> tuple[uuid.UUID, bytes]:
    """Emit ``sandbox.lifecycle.lease_minted`` per spec §6.2.

    Called from ``SandboxBackend.create()`` (T10) after each successful
    ``mint_lease()`` round-trip per spec §7.1. Payload-shape contract:
    10 always-fields (lease_id + 6 request projections + 3 lease
    projections) + ``session_id`` threaded by ``emit_sandbox_event``.

    ``DecisionRecord.tenant_id`` AND ``DecisionRecord.actor_id`` are
    DERIVED from ``lease.request.tenant_id`` +
    ``lease.request.actor_ref.actor_subject`` — NOT accepted as
    separate kwargs. The derive closes the contradictory-evidence
    bug class by construction: chain-metadata tenant/actor and
    lease-payload tenant/actor share one source.

    On any mint failure mid-batch, the caller revokes any leases
    already minted in the same ``create()`` attempt (best-effort,
    per spec §7.1) before raising the closed-enum refusal — the
    backend MUST emit ``sandbox.lifecycle.lease_minted`` only for
    leases that successfully landed in Vault.
    """
    return await emit_sandbox_event(
        decision_history_store,
        event="sandbox.lifecycle.lease_minted",
        tenant_id=lease.request.tenant_id,
        actor_id=lease.request.actor_ref.actor_subject,
        trace_id=trace_id,
        session_id=session_id,
        payload=_project_lease_evidence_payload(lease),
    )


async def sandbox_lifecycle_lease_revoked(
    decision_history_store: DecisionHistoryStore,
    *,
    lease: CredentialLease,
    trace_id: str,
    session_id: str,
) -> tuple[uuid.UUID, bytes]:
    """Emit ``sandbox.lifecycle.lease_revoked`` per spec §6.2.

    Called from ``SandboxBackend.destroy()`` (T10) per successful
    revoke round-trip per spec §4.3 + §7.2. Same 10-key always-payload
    as ``lease_minted`` — the destroy path emits the same lease
    projection so examiners can correlate mint + revoke rows by
    ``lease_id`` (the chain rows form a per-lease lifecycle audit
    trail).

    ``DecisionRecord.tenant_id`` AND ``DecisionRecord.actor_id`` are
    DERIVED from the lease (same derive as ``lease_minted`` above) so
    every emitted row carries identical tenant/actor evidence
    end-to-end — examiners can correlate the per-lease mint→revoke
    pair without cross-referencing caller intent.
    """
    return await emit_sandbox_event(
        decision_history_store,
        event="sandbox.lifecycle.lease_revoked",
        tenant_id=lease.request.tenant_id,
        actor_id=lease.request.actor_ref.actor_subject,
        trace_id=trace_id,
        session_id=session_id,
        payload=_project_lease_evidence_payload(lease),
    )


async def sandbox_lifecycle_lease_revoke_failed(
    decision_history_store: DecisionHistoryStore,
    *,
    lease: CredentialLease,
    trace_id: str,
    session_id: str,
    vault_error: str,
) -> tuple[uuid.UUID, bytes]:
    """Emit ``sandbox.lifecycle.lease_revoke_failed`` per spec §6.2 + §7.2.

    Called from ``SandboxBackend.destroy()`` (T10) per FAILED revoke
    per spec §7.2 fail-soft policy: single attempt, on failure emit +
    continue destroy() (do NOT raise; do NOT block cleanup). The
    lease's own Vault-side TTL is the operational safety net — every
    revoke-failed lease auto-expires at its ``expires_at`` deadline
    enforced by Vault server-side; banks have audit evidence here for
    SOC out-of-band retry if they want a tighter window than the
    lease's TTL.

    Payload extends the 10-key base with 2 conditional keys:

    * ``vault_error`` — the Vault HTTP error string (e.g. ``"Vault HTTP
      503: service unavailable"``). Forensic evidence for SOC + bank
      compliance review. The only field not derivable from
      ``CredentialLease``; caller-supplied.
    * ``auto_expiry_at`` — DERIVED from ``lease.expires_at`` per spec
      §6.2 line 624 ("same as expires_at but surfaced separately for
      the examiner's 'this lease should auto-expire' claim"). NOT
      caller-supplied — accepting it as a caller string would re-open
      the silent-lie bug class (a caller could pass an arbitrary string
      disagreeing with ``expires_at``).

    ``DecisionRecord.tenant_id`` AND ``DecisionRecord.actor_id`` are
    DERIVED from the lease (same derive as ``lease_minted`` /
    ``lease_revoked`` above) so the per-lease chain row trail carries
    identical tenant/actor evidence whether the revoke succeeded or
    failed.

    Token contents are NOT projected (defence-in-depth: even on
    revoke-failed where the lease is unrevoked + the token is still
    valid in Vault, the token contents stay off the chain row).
    """
    payload = _project_lease_evidence_payload(lease)
    payload["vault_error"] = vault_error
    payload["auto_expiry_at"] = lease.expires_at.isoformat()
    return await emit_sandbox_event(
        decision_history_store,
        event="sandbox.lifecycle.lease_revoke_failed",
        tenant_id=lease.request.tenant_id,
        actor_id=lease.request.actor_ref.actor_subject,
        trace_id=trace_id,
        session_id=session_id,
        payload=payload,
    )
