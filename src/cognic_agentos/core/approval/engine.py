"""Sprint 13.5a (ADR-014/015) — ApprovalEngine: the non-blocking runtime-
approval decision core. ``core/`` stop-rule + critical-controls.

Designed as the generic Sprint-14 human-checkpoint primitive: ``classify`` /
``create_request`` / ``check`` / ``verify_grant_for_action`` / ``grant`` /
``grant_second`` / ``deny`` — NEVER a wait loop. Value-free: the engine computes
``envelope_digest`` and never sees raw tool args (the caller supplies a redacted
envelope + ``args_digest``). This module ships the create-side surface
(classify/create/check/verify + envelope validation + lazy expiry); the grant-side
(``grant``/``grant_second``/``deny``) is appended at Sprint 13.5a T6.
"""

from __future__ import annotations

import dataclasses
import hashlib
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any, Final, cast

from cognic_agentos.core.approval._types import (
    _DIGEST_LEN,
    _REASON_MANDATING_TIERS,
    _RISK_TIERS,
    APPROVAL_REDACTED_CONTEXT_MAX_LEN,
    ApprovalActor,
    ApprovalCheckResult,
    ApprovalEnvelope,
    ApprovalEnvelopeInvalid,
    ApprovalFlow,
    ApprovalRequest,
    ApprovalRequestNotFound,
    ApprovalState,
    ApprovalTransitionRefused,
)
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.config import Settings

#: Inline mirror of the canonical 9-value data-governance class vocab. ``core/``
#: MUST NOT import ``cli/_governance_vocab`` (architectural arrow) — lockstep is
#: test-only drift-pinned (``test_engine_create_side.py::
#: test_data_class_mirror_matches_canonical``).
_DATA_CLASSES: Final[frozenset[str]] = frozenset(
    {
        "public",
        "internal",
        "customer_pii",
        "payment_data",
        "credentials",
        "regulator_communication",
        "audit_trail",
        "model_inputs",
        "model_outputs",
    }
)

#: Flow -> the Settings field that supplies its TTL (spec §8).
_FLOW_TO_TTL_SETTING: Final[dict[str, str]] = {
    "require_single_approval": "approval_single_ttl_s",
    "require_4_eyes": "approval_four_eyes_ttl_s",
}

#: Tier -> the single RBAC scope that may grant it (spec §6). ``tool.approve.observe``
#: is read-only (examiner) and grants nothing — it appears in no value here.
_TIER_GRANT_SCOPE: Final[dict[str, str]] = {
    "customer_data_read": "tool.approve.customer_data",
    "customer_data_write": "tool.approve.customer_data_write",
    "payment_action": "tool.approve.payment",
    "regulator_communication": "tool.approve.regulator",
    "cross_tenant": "tool.approve.cross_tenant",
    "high_risk_custom": "tool.approve.high_risk_custom",
}

_APPROVAL_REQUEST_ID_PREFIX: Final[str] = "appr-"  # 5 + 32 hex = 37 <= 64


def _mint_request_id() -> str:
    return f"{_APPROVAL_REQUEST_ID_PREFIX}{uuid.uuid4().hex}"


class ApprovalEngine:
    """Non-blocking runtime-approval decision orchestrator. Constructor-injected
    ``ApprovalPolicy`` (duck: async ``classify``) + ``ApprovalRequestStore`` +
    ``Settings`` + an injectable ``clock`` seam."""

    def __init__(
        self,
        *,
        policy: Any,
        store: ApprovalRequestStore,
        settings: Settings,
        clock: Callable[[], datetime],
    ) -> None:
        self._policy = policy
        self._store = store
        self._settings = settings
        self._clock = clock

    async def classify(self, *, risk_tier: str) -> ApprovalFlow:
        """tools.rego tier->flow consult (the seam branches auto-vs-approval)."""
        return cast(ApprovalFlow, await self._policy.classify(risk_tier=risk_tier))

    async def create_request(self, *, envelope: ApprovalEnvelope) -> ApprovalRequest:
        """Validate the envelope (§7, pre-persist), classify the flow, and persist
        a ``pending`` request + emit ``approval.requested``. Refuses an ``auto_run``
        tier (the seam handles auto tiers without a record)."""
        self._validate_envelope(envelope)
        flow = await self._policy.classify(risk_tier=envelope.risk_tier)
        if flow == "auto_run":
            raise ApprovalTransitionRefused("auto_tier_no_approval_required")
        envelope_digest = self._envelope_digest(envelope)
        ttl_s = getattr(self._settings, _FLOW_TO_TTL_SETTING[flow])
        now = self._clock()
        request_id = uuid.uuid4()
        await self._store.create_request_row(
            request_id=request_id,
            tenant_id=envelope.tenant_id,
            flow=flow,
            risk_tier=envelope.risk_tier,
            tool_identity=envelope.tool_identity,
            originator_subject=envelope.originator_subject,
            envelope_digest=envelope_digest,
            args_digest=envelope.args_digest,
            redacted_context=envelope.redacted_context,
            data_classes=list(envelope.data_classes),
            required_refs=dict(envelope.required_refs),
            request_request_id=_mint_request_id(),
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_s),
        )
        return ApprovalRequest(
            request_id=request_id,
            tenant_id=envelope.tenant_id,
            flow=flow,
            risk_tier=envelope.risk_tier,
            tool_identity=envelope.tool_identity,
            originator_subject=envelope.originator_subject,
            state="pending",
            envelope_digest=envelope_digest,
            args_digest=envelope.args_digest,
        )

    async def check(self, *, request_id: uuid.UUID, tenant_id: str) -> ApprovalCheckResult:
        """Lazy-expire if past TTL, then return the structured result (state + the
        bound facts). The display / queue / Sprint-14 path."""
        return await self._lazy_expire_and_project(request_id=request_id, tenant_id=tenant_id)

    async def verify_grant_for_action(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        expected_args_digest: bytes,
        expected_tool_identity: str,
    ) -> ApprovalCheckResult:
        """The seam REPLAY gate: lazy-expire, then if the request is ``granted`` but
        its persisted ``args_digest`` / ``tool_identity`` do not match the
        invocation, raise ``approval_binding_mismatch`` (a granted request_id cannot
        be replayed against a different invocation shape). The seam proceeds ONLY on
        a returned ``state == "granted"``."""
        res = await self._lazy_expire_and_project(request_id=request_id, tenant_id=tenant_id)
        if res.state == "granted" and (
            res.args_digest != expected_args_digest or res.tool_identity != expected_tool_identity
        ):
            raise ApprovalTransitionRefused("approval_binding_mismatch")
        return res

    async def grant(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        approver: ApprovalActor,
        reason: str | None = None,
    ) -> ApprovalState:
        """First grant. ``require_single_approval`` -> granted; ``require_4_eyes``
        -> awaiting_second (NOT executable until ``grant_second``)."""
        return await self._do_decision(
            request_id=request_id,
            tenant_id=tenant_id,
            approver=approver,
            action="grant_first",
            reason=reason,
        )

    async def grant_second(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        approver: ApprovalActor,
        reason: str | None = None,
    ) -> ApprovalState:
        """Second 4-eyes grant -> granted. Requires ``awaiting_second`` + a
        distinct approver (!= first approver, != originator)."""
        return await self._do_decision(
            request_id=request_id,
            tenant_id=tenant_id,
            approver=approver,
            action="grant_second",
            reason=reason,
        )

    async def deny(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        approver: ApprovalActor,
        reason: str,
    ) -> ApprovalState:
        """Refuse the request -> denied."""
        return await self._do_decision(
            request_id=request_id,
            tenant_id=tenant_id,
            approver=approver,
            action="deny",
            reason=reason,
        )

    # ---- helpers ------------------------------------------------------------

    async def _do_decision(
        self,
        *,
        request_id: uuid.UUID,
        tenant_id: str,
        approver: ApprovalActor,
        action: str,
        reason: str | None,
    ) -> ApprovalState:
        # 0. Human-only guard FIRST (AGENTS.md core-boundary; T-4). Enforced in the
        #    engine, NOT only the 13.5b portal RequireHumanActor (defense-in-depth).
        if approver.actor_type != "human":
            raise ApprovalTransitionRefused("approver_not_human")
        # 0b. Tenant binding (P1): the approver MUST belong to the target tenant —
        #     a cross-tenant approver holds NO grant authority here, even with the
        #     tier scope. Enforced in the CORE engine, not only the 13.5b portal
        #     seam. Fires BEFORE any DB work (no lazy-expire on another tenant's
        #     request). Reuses approver_scope_not_held (no new wire reason): the
        #     actor does not hold that grant authority in this tenant.
        if approver.tenant_id != tenant_id:
            raise ApprovalTransitionRefused("approver_scope_not_held")
        # 1. Lazy-expire (a post-TTL decision refuses, never resurrects).
        res = await self._lazy_expire_and_project(request_id=request_id, tenant_id=tenant_id)
        if res.state == "expired":
            raise ApprovalTransitionRefused("approval_expired")
        # 2. RBAC scope-per-tier (grant / grant_second / deny all require the tier
        #    scope; observe never grants — it appears in no _TIER_GRANT_SCOPE value).
        required_scope = _TIER_GRANT_SCOPE.get(res.risk_tier)
        if required_scope is not None and required_scope not in approver.scopes:
            raise ApprovalTransitionRefused("approver_scope_not_held")
        # 3. Reason policy (grant/grant_second on a reason-mandating tier need a
        #    reason; deny's reason is required at the signature).
        if (
            action in ("grant_first", "grant_second")
            and res.risk_tier in _REASON_MANDATING_TIERS
            and not reason
        ):
            raise ApprovalTransitionRefused("grant_reason_required")
        # 4. 4-eyes distinctness (grant_second only): second != first != originator.
        if action == "grant_second":
            first = await self._store.first_approver(request_id=request_id, tenant_id=tenant_id)
            if approver.subject in (first, res.originator_subject):
                raise ApprovalTransitionRefused("four_eyes_approver_not_distinct")
        # 5. Atomic transition (validate_transition against the row-locked flow; no
        #    caller-supplied flow per the T4 P1 fix).
        return await self._store.transition(
            request_id=request_id,
            tenant_id=tenant_id,
            action=action,
            actor_subject=approver.subject,
            reason=reason,
            request_request_id=_mint_request_id(),
        )

    def _validate_envelope(self, e: ApprovalEnvelope) -> None:
        if e.risk_tier not in _RISK_TIERS:
            raise ApprovalEnvelopeInvalid("risk_tier_unknown")
        if any(dc not in _DATA_CLASSES for dc in e.data_classes):
            raise ApprovalEnvelopeInvalid("data_class_unknown")
        if not e.tool_identity:
            raise ApprovalEnvelopeInvalid("tool_identity_missing")
        if not e.originator_subject:
            raise ApprovalEnvelopeInvalid("originator_subject_missing")
        if not e.tenant_id:
            raise ApprovalEnvelopeInvalid("tenant_id_missing")
        if len(e.args_digest) != _DIGEST_LEN:
            raise ApprovalEnvelopeInvalid("args_digest_malformed")
        if len(e.redacted_context) > APPROVAL_REDACTED_CONTEXT_MAX_LEN:
            raise ApprovalEnvelopeInvalid("redacted_context_too_large")
        if e.risk_tier == "regulator_communication" and "audit_record_ref" not in e.required_refs:
            raise ApprovalEnvelopeInvalid("regulator_audit_ref_missing")

    def _envelope_digest(self, e: ApprovalEnvelope) -> bytes:
        # Canonical, value-free form: digests are hex, no raw args.
        canonical = {
            "risk_tier": e.risk_tier,
            "tool_identity": e.tool_identity,
            "originator_subject": e.originator_subject,
            "tenant_id": e.tenant_id,
            "data_classes": list(e.data_classes),
            "args_digest": e.args_digest.hex(),
            "redacted_context": e.redacted_context,
            "required_refs": dict(e.required_refs),
        }
        return hashlib.sha256(canonical_bytes(canonical)).digest()

    async def _lazy_expire_and_project(
        self, *, request_id: uuid.UUID, tenant_id: str
    ) -> ApprovalCheckResult:
        row = await self._store.load(request_id=request_id, tenant_id=tenant_id)
        if row is None:
            raise ApprovalRequestNotFound(str(request_id))
        if row.state in ("pending", "awaiting_second") and self._clock() >= row.expires_at:
            new_state = await self._store.transition(
                request_id=request_id,
                tenant_id=tenant_id,
                action="expire",
                actor_subject=None,
                request_request_id=_mint_request_id(),
            )
            row = dataclasses.replace(row, state=new_state)
        return ApprovalCheckResult(
            state=row.state,
            request_id=request_id,
            flow=cast(ApprovalFlow, row.flow),
            risk_tier=row.risk_tier,
            tool_identity=row.tool_identity,
            args_digest=row.args_digest,
            envelope_digest=row.envelope_digest,
            originator_subject=row.originator_subject,
        )
