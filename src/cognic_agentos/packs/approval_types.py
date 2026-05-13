"""Sprint 7B.3 T2 Slice A — neutral domain vocabulary for approval-gate
override semantics per ADR-012 §107.

This module declares the closed-enum :data:`ApprovalOverrideReason`
Literal that is wire-protocol-public on the approve endpoint's request
body. It lives at ``packs/`` (not at ``portal/api/packs/``) so the
architectural arrow ``portal → packs`` (consumer → declarer) holds
for ALL three consumers:

- :mod:`cognic_agentos.portal.api.packs.dto` — request-body typing
  for ``ApproveRequest.override_reason``
- :mod:`cognic_agentos.packs.approval_gates` — composer signature
  typing for ``evaluate_override_decision(*, ..., override_reason)``
- :mod:`cognic_agentos.packs.storage` — override-event payload typing
  for ``append_override_event(*, ..., override_reason)``

R5 P2 #1 doctrinal fix — earlier drafts placed the vocabulary in
``portal/api/packs/dto.py`` (R4) and ``packs/approval_gates.py`` (R3),
both of which reversed the layer dependency (domain importing portal,
or task-order inversion where T2's ``ApproveRequest`` references a
symbol T8 declares). The neutral-domain-module pattern resolves both:
the vocabulary lives ABOVE the three consumers in the import graph;
no consumer imports portal; T2 has the vocabulary before T8 needs it.

R7 P3 #5 — module stays OFF the durable critical-controls coverage
gate (per-file 95/90 floors are meaningless for type-only modules
with no executable logic). The drift detector at
``tests/unit/packs/test_approval_types_drift.py`` pins the closed-enum
vocabulary against ADR-012 §107 doctrine via three regressions
(exact-set / count guard / AST scan); the AST scan asserts this module
declares ONLY the Literal so any future addition of executable logic
re-opens the on-gate decision.
"""

from __future__ import annotations

from typing import Literal

__all__ = ["ApprovalOverrideReason"]


ApprovalOverrideReason = Literal[
    "security_exception",
    "prerelease_validation",
    "legacy_grandfather",
    "other",
]
"""Closed-enum 4-value vocabulary for approval-gate override reasons.

Per ADR-012 §107: when a privileged operator with the
``pack.override.approval_gate`` scope force-approves a pack despite a
red gate, they MUST attach one of these four categorised reasons.
The override-event chain row's ``payload["override_reason"]`` carries
the value verbatim; examiners trace override patterns by reason
category across packs / reviewers / tenants.

Value semantics (per ADR-012 §107):

- ``"security_exception"`` — security-relevant policy gate failure
  outside Gate 1 (cosign signature) that the operator has time-bounded
  mitigation for; expected to be re-reviewed. Examples: ADR-011
  adversarial pass-rate red on a non-high-severity category; OWASP
  conformance yellow on a non-critical checker. **Does NOT cover
  cosign / signature-gate failures**: per ADR-012 §110 + R10 LOCK
  Flag #4, Gate 1 (signature) is non-overridable; a signature-red
  pack cannot reach the approve path at all under any
  ApprovalOverrideReason. Operators with signature failures must
  restage the bundle + re-submit (or use the documented
  ``settings.require_cosign = False`` dev mode); the override path
  does NOT bypass the signature gate.
- ``"prerelease_validation"`` — pre-production deploy of a pack
  whose eval/adversarial harnesses haven't run yet; intended for
  fixture / pre-launch validation.
- ``"legacy_grandfather"`` — pack signed under an older trust root or
  attestation policy that no longer meets the current gate threshold;
  grandfathered for backward compat. **Limited to non-Gate-1 gates**
  — the signature gate's non-overridability applies even to legacy
  packs (the trust-root rotation pathway covers genuinely-grandfathered
  trust roots without invoking the override path).
- ``"other"`` — any reason not fitting the three categorical buckets;
  operator MUST supply a free-form description in the override-event
  payload (recorded separately from the closed-enum reason).

Drift between this Literal and ADR-012 §107 is wire-protocol-public
regression — pinned by ``test_approval_types_drift.py``.
"""
