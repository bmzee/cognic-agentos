"""ISO/IEC 42001 control registry — Sprint 9 (ADR-006).

Single source of truth mapping the 8 ADR-006 Wave-1 Annex-A controls to
their intended Cognic governance hooks. The canonical control ID — the
value emitted into ``iso_controls`` and the registry's identity — is the
``ISO42001.``-prefixed form (e.g. ``ISO42001.A.6.2.5``); ``display``
carries the bare ``A.x.y`` for human-facing surfaces.

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


@dataclass(frozen=True, slots=True)
class ControlEntry:
    """One ADR-006 control and the Cognic hook(s) intended to tag it."""

    control_id: ComplianceControlId
    display: str
    title: str
    intended_hooks: tuple[str, ...]


ISO42001_CONTROLS: tuple[ControlEntry, ...] = (
    ControlEntry(
        "ISO42001.A.6.2.5",
        "A.6.2.5",
        "Operational responsibilities",
        ("escalation.transition", "rbac.check_scope", "sandbox.lifecycle.*"),
    ),
    ControlEntry(
        "ISO42001.A.6.2.6",
        "A.6.2.6",
        "Roles and responsibilities",
        ("rbac.role_scopes",),
    ),
    ControlEntry(
        "ISO42001.A.7.4",
        "A.7.4",
        "AI system impact assessment",
        ("decision_history.append",),
    ),
    ControlEntry(
        "ISO42001.A.7.6",
        "A.7.6",
        "AI system risk evaluation",
        ("auto_degradation.evaluate", "compliance_checker.score"),
    ),
    ControlEntry(
        "ISO42001.A.8.2",
        "A.8.2",
        "Data quality for AI systems",
        ("citation_verifier.verify",),
    ),
    ControlEntry(
        "ISO42001.A.8.5",
        "A.8.5",
        "AI system development",
        ("gateway.completion",),
    ),
    ControlEntry(
        "ISO42001.A.9.2",
        "A.9.2",
        "System and operational logging",
        ("audit.append", "chain_verifier.walk"),
    ),
    ControlEntry(
        "ISO42001.A.10.2",
        "A.10.2",
        "Stakeholder transparency",
        ("decision_history.export_for_subject",),
    ),
)


def control_ids() -> frozenset[str]:
    """The 8 canonical control-ID strings."""
    return frozenset(entry.control_id for entry in ISO42001_CONTROLS)


def audit_coverage(emitted: set[str]) -> dict[str, bool]:
    """Map each registry control_id -> whether ``emitted`` contains it.

    ``emitted`` is the set of canonical control IDs observed across the
    governance hooks (built by the T9 ``test_control_mapping`` suite from
    the real emission sites). A control is covered iff >=1 hook emits it.
    """
    return {entry.control_id: entry.control_id in emitted for entry in ISO42001_CONTROLS}
