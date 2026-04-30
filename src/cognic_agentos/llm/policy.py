"""Cloud-policy enforcer (Sprint 3) — pure function over a
:class:`ResolvedUpstream` + :class:`Settings`.

Layer classification: **platform primitive** (critical control per
AGENTS.md — cloud-policy enforcer).

Operates on the api_base-aware
:class:`cognic_agentos.llm.preflight.ResolvedUpstream` rather than a
bare model string (Round-2 reviewer-P1#2). Audit payload carries
alias, model_string, api_base, external, provenance, plus the
``post_response`` flag distinguishing pre-dispatch denials from the
post-response policy recheck (Round-2 reviewer-P1#1).

Per ADR-015 §"Sprint 13.5 (full)": this static enforcer is replaced
by an OPA-Rego query when the policy engine seed lands in Sprint 4
+ the full engine in Sprint 13.5. Sprint 3 ships the static check
only.

Decision tree (Plan §2; first match wins; fail-closed default):

  1. ``provenance != "resolved"``           → DENY (Rounds 4+5+6 P1)
  2. ``not external``                       → ALLOW (self-hosted pass)
  3. ``not allow_external_llm``             → DENY
  4. ``provider not in allowed_providers``  → DENY
  5. ``policy_mode == "self_hosted"``       → DENY (mode/flag mismatch)
  6. otherwise                              → ALLOW

References:
- Plan Decision-Locking §1 (provider alias semantics).
- Plan Decision-Locking §2 (decision tree priority).
- Plan Decision-Locking §5 (audit emission shape — privacy: no
  prompt content / messages / PII in payload).
- ADR-007 (Provider-Honesty Enforcement).
- ADR-015 (Policy-as-Code — replaces this static check at 13.5).
"""

from __future__ import annotations

import dataclasses
from typing import Any

from cognic_agentos.core.config import Settings
from cognic_agentos.llm.preflight import ResolvedUpstream

#: Vocabulary of provider prefixes the gateway recognises as external.
#: Documentation-only at this layer — :func:`enforce_cloud_policy`
#: derives the provider from the upstream's ``model_string`` head and
#: checks it against :class:`Settings.allowed_providers`. Sprint 13.5
#: OPA-Rego refactor will consult this set + per-tenant overrides.
_KNOWN_EXTERNAL_PROVIDERS: tuple[str, ...] = (
    "openai",
    "azure",
    "anthropic",
    "bedrock",
    "cohere",
)


@dataclasses.dataclass(frozen=True, slots=True)
class PolicyDecision:
    """Outcome of one ``enforce_cloud_policy`` evaluation.

    Frozen + slotted: callers must not mutate the decision after
    receipt; the ``audit_payload`` is the wire-format view that the
    gateway hands to ``AuditStore.append``.

    Attributes:
        allowed: ``True`` iff the call may proceed.
        resolved: The :class:`ResolvedUpstream` the decision
            classified.
        reason: Operator-friendly denial reason or pass justification.
        policy_mode: Snapshot of ``settings.policy_mode`` at decision
            time.
        post_response: ``True`` if this decision was made on the
            post-response recheck path (Round-2 reviewer-P1#1).
            Distinguishes pre-dispatch denials from post-response
            denials in audit logs.
        audit_payload: Pre-built dict for ``AuditStore.append``
            payload — alias / model_string / api_base / external /
            provenance / policy_mode / allow_external_llm /
            allowed_providers / post_response / reason. **No prompt
            content, ever** (Plan §5 privacy contract).
    """

    allowed: bool
    resolved: ResolvedUpstream
    reason: str
    policy_mode: str
    post_response: bool
    audit_payload: dict[str, Any]


class CloudPolicyViolationError(RuntimeError):
    """Raised by :class:`LLMGateway` (T6) when a denied call is
    attempted.

    Carries the :class:`PolicyDecision` object so request-path
    callers can introspect the decision (e.g. surface the operator-
    friendly reason in a 4xx response body, log the audit payload).
    Subclass of :class:`RuntimeError` so generic 500-handlers still
    trip on it.
    """

    def __init__(self, message: str, decision: PolicyDecision) -> None:
        super().__init__(message)
        self.decision = decision

    @classmethod
    def from_decision(cls, decision: PolicyDecision) -> CloudPolicyViolationError:
        """Construct from a :class:`PolicyDecision`.

        Round-2 reviewer-P1#1: append a ``(post-response recheck)``
        suffix when the decision came from the post-response path so
        log readers can distinguish pre-dispatch from post-response
        denials at a glance.
        """
        suffix = " (post-response recheck)" if decision.post_response else ""
        return cls(
            f"cloud-policy denial: {decision.reason} "
            f"(upstream={decision.resolved.model_string}){suffix}",
            decision,
        )


class GuardrailViolationError(RuntimeError):
    """Raised by :class:`LLMGateway` (T6) when an INPUT or OUTPUT
    guardrail trip halts the call.

    ``direction`` is ``"input"`` or ``"output"``; ``trip_summary`` is
    a comma-joined list of guardrail names that tripped (sourced from
    the Sprint-2.5 ``GuardrailPipeline`` ``results`` tuple). The
    pipeline emits the per-trip ``audit_event(guardrail.trip)`` rows
    BEFORE the gateway raises this; this exception is the caller-
    facing halt signal, not the evidence carrier.
    """

    def __init__(self, direction: str, trip_summary: str) -> None:
        super().__init__(f"guardrail.{direction} trip: {trip_summary}")
        self.direction = direction
        self.trip_summary = trip_summary


def enforce_cloud_policy(
    *,
    resolved: ResolvedUpstream,
    settings: Settings,
    post_response: bool,
) -> PolicyDecision:
    """Decision tree per Plan §2 (api_base-aware).

    Order matters — first match wins. Every code path that does not
    reach an explicit ALLOW returns DENY (fail-closed).

    Args:
        resolved: The api_base-aware
            :class:`cognic_agentos.llm.preflight.ResolvedUpstream`.
        settings: Process settings carrying ``allow_external_llm`` /
            ``policy_mode`` / ``allowed_providers``.
        post_response: ``True`` if this is the post-response policy
            recheck (Round-2 reviewer-P1#1). Propagates into the
            decision + audit payload so the gateway can emit two
            distinct ``gateway.cloud_policy_denied`` event variants.

    Returns:
        :class:`PolicyDecision` carrying ``allowed`` + the pre-built
        audit payload.
    """
    payload_base: dict[str, Any] = {
        "alias": resolved.alias,
        "model_string": resolved.model_string,
        "api_base": resolved.api_base,
        "external": resolved.external,
        "provenance": resolved.provenance,
        "policy_mode": settings.policy_mode,
        "allow_external_llm": settings.allow_external_llm,
        "allowed_providers": list(settings.allowed_providers),
        "post_response": post_response,
    }

    # Round-4 + Round-5 + Round-6 reviewer-P1: any provenance gap DENIES
    # unconditionally, before any allow_external_llm / allowed_providers
    # check. Reason: we cannot prove which upstream LiteLLM dispatched
    # against, and ADR-007's authoritativeness contract requires per-call
    # provenance. An operator who legitimately allows cloud OpenAI must
    # NOT silently get the call when the YAML has a colliding self-hosted
    # alias for the same model_string, or when the response model field
    # was missing, or when the actual model isn't declared in any route.
    if resolved.provenance != "resolved":
        reason = (
            f"provenance gap ({resolved.provenance}): cannot truthfully "
            "report which upstream LiteLLM dispatched against"
        )
        return PolicyDecision(
            allowed=False,
            resolved=resolved,
            reason=reason,
            policy_mode=settings.policy_mode,
            post_response=post_response,
            audit_payload={**payload_base, "reason": reason},
        )

    if not resolved.external:
        return PolicyDecision(
            allowed=True,
            resolved=resolved,
            reason="self-hosted upstream (api_base-aware); cloud-policy not applicable",
            policy_mode=settings.policy_mode,
            post_response=post_response,
            audit_payload={**payload_base, "reason": "self-hosted-pass"},
        )

    if not settings.allow_external_llm:
        reason = "external upstream blocked: allow_external_llm=False"
        return PolicyDecision(
            allowed=False,
            resolved=resolved,
            reason=reason,
            policy_mode=settings.policy_mode,
            post_response=post_response,
            audit_payload={**payload_base, "reason": reason},
        )

    provider = resolved.provider()
    if provider not in settings.allowed_providers:
        reason = f"provider {provider!r} not in allowed_providers"
        return PolicyDecision(
            allowed=False,
            resolved=resolved,
            reason=reason,
            policy_mode=settings.policy_mode,
            post_response=post_response,
            audit_payload={**payload_base, "reason": reason},
        )

    if settings.policy_mode == "self_hosted":
        reason = (
            "policy_mode=self_hosted but external upstream attempted (operator misconfiguration)"
        )
        return PolicyDecision(
            allowed=False,
            resolved=resolved,
            reason=reason,
            policy_mode=settings.policy_mode,
            post_response=post_response,
            audit_payload={**payload_base, "reason": reason},
        )

    return PolicyDecision(
        allowed=True,
        resolved=resolved,
        reason="external upstream allowed by policy",
        policy_mode=settings.policy_mode,
        post_response=post_response,
        audit_payload={**payload_base, "reason": "external-pass"},
    )


__all__ = (
    "CloudPolicyViolationError",
    "GuardrailViolationError",
    "PolicyDecision",
    "enforce_cloud_policy",
)
