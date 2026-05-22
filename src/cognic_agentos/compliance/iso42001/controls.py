"""ISO/IEC 42001 control registry — Sprint 9 (ADR-006).

Single source of truth mapping the 8 ADR-006 Wave-1 Annex-A controls to
their intended Cognic governance hooks. The canonical control ID — the
value emitted into ``iso_controls`` and the registry's identity — is the
``ISO42001.``-prefixed form (e.g. ``ISO42001.A.6.2.5``); ``display``
carries the bare ``A.x.y`` for human-facing surfaces.

Each entry also records ``hook_status`` (Sprint-9 T8 audit): ``implemented``
when a built governance surface already tags the control today,
``deferred`` — with a non-empty ``deferred_reason`` — when the intended
hook surface does not exist yet. ``hook_status`` + ``deferred_reason`` are
registry-only; they are NOT added to the evidence-pack ``manifest.json``.

Dependency arrow: ``compliance/`` -> ``core/``, never the reverse. This
module is imported by the evidence-pack exporter and by tests; it is
NEVER imported by ``core/``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ComplianceControlId = Literal[
    "ISO42001.A.6.2.5",
    "ISO42001.A.6.2.6",
    "ISO42001.A.7.4",
    "ISO42001.A.7.6",
    "ISO42001.A.8.2",
    "ISO42001.A.8.5",
    "ISO42001.A.9.2",
    "ISO42001.A.10.2",
]

#: Whether a control has a built governance emission surface today.
HookStatus = Literal["implemented", "deferred"]


@dataclass(frozen=True, slots=True)
class ControlEntry:
    """One ADR-006 control and the Cognic hook(s) intended to tag it.

    ``hook_status`` is ``implemented`` when a built emission surface tags
    the control today, ``deferred`` when the intended hook surface does
    not exist yet. ``deferred_reason`` carries the reason on every
    ``deferred`` entry and is ``""`` on every ``implemented`` entry.
    """

    control_id: ComplianceControlId
    display: str
    title: str
    intended_hooks: tuple[str, ...]
    hook_status: HookStatus
    deferred_reason: str = ""


@dataclass(frozen=True, slots=True)
class ControlCoverage:
    """One control's coverage record — the value type of :func:`audit_coverage`."""

    control_id: ComplianceControlId
    hook_status: HookStatus
    emitted: bool
    deferred_reason: str


ISO42001_CONTROLS: tuple[ControlEntry, ...] = (
    ControlEntry(
        "ISO42001.A.6.2.5",
        "A.6.2.5",
        "Operational responsibilities",
        ("escalation.transition", "rbac.check_scope", "sandbox.lifecycle.*"),
        "implemented",
    ),
    ControlEntry(
        "ISO42001.A.6.2.6",
        "A.6.2.6",
        "Roles and responsibilities",
        ("rbac.role_scopes",),
        "deferred",
        "no audit_event / decision_history chain emission in portal/rbac/",
    ),
    ControlEntry(
        "ISO42001.A.7.4",
        "A.7.4",
        "AI system impact assessment",
        ("decision_history.append",),
        "implemented",
    ),
    ControlEntry(
        "ISO42001.A.7.6",
        "A.7.6",
        "AI system risk evaluation",
        ("auto_degradation.evaluate", "compliance_checker.score"),
        "deferred",
        "core/auto_degradation.py and a compliance_checker do not exist yet",
    ),
    ControlEntry(
        "ISO42001.A.8.2",
        "A.8.2",
        "Data quality for AI systems",
        ("citation_verifier.verify",),
        "deferred",
        "retrieval/citation_verifier.py does not exist yet",
    ),
    ControlEntry(
        "ISO42001.A.8.5",
        "A.8.5",
        "AI system development",
        ("gateway.completion",),
        "deferred",
        "no A.8.5 emission on the gateway completion path",
    ),
    ControlEntry(
        "ISO42001.A.9.2",
        "A.9.2",
        "System and operational logging",
        ("audit.append", "chain_verifier.walk"),
        "implemented",
    ),
    ControlEntry(
        "ISO42001.A.10.2",
        "A.10.2",
        "Stakeholder transparency",
        ("decision_history.export_for_subject",),
        "deferred",
        "no decision_history.export_for_subject regulator-export method",
    ),
)


def control_ids() -> frozenset[str]:
    """The 8 canonical control-ID strings."""
    return frozenset(entry.control_id for entry in ISO42001_CONTROLS)


def audit_coverage(emitted: set[str]) -> dict[str, ControlCoverage]:
    """Per-control coverage honouring the implemented/deferred model.

    ``emitted`` is the set of canonical control IDs observed across the
    real governance emission sites (built by the T9 ``test_control_mapping``
    suite from the actual emission-site source — NOT from this registry).
    The result carries one :class:`ControlCoverage` per registry control:
    an ``implemented`` control is correctly covered iff its canonical ID
    is in ``emitted``; a ``deferred`` control is correctly recorded iff it
    is NOT in ``emitted`` and carries a non-empty ``deferred_reason``.
    """
    return {
        entry.control_id: ControlCoverage(
            control_id=entry.control_id,
            hook_status=entry.hook_status,
            emitted=entry.control_id in emitted,
            deferred_reason=entry.deferred_reason,
        )
        for entry in ISO42001_CONTROLS
    }
