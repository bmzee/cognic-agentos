"""ISO/IEC 42001 control registry — Sprint 9 (ADR-006); 9.5 A6 + Sprint 12 (ADR-010) updates.

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

Sprint 9.5 A6 promoted 4 controls from ``deferred`` to ``implemented``
once the model registry primitive (ADR-013) landed real
``model.lifecycle.*`` chain emission tagging them: ``A.6.2.6`` (roles +
responsibilities), ``A.8.2`` (data quality), ``A.8.5`` (AI system
development), ``A.10.2`` (stakeholder transparency). That moved the
count from 3 implemented / 5 deferred → 7 implemented / 1 deferred,
leaving only ``A.7.6`` (AI system risk evaluation) deferred.

Sprint 12 (ADR-010) flipped ``A.7.6`` from ``deferred`` to
``implemented`` once the bulk evaluation harness landed the real
``eval.bulk_run`` emission surface tagging it (the harness IS an
AI-system risk-evaluation surface); the same hook also tags ``A.9.2``
(system and operational logging). The count is now 8 implemented /
0 deferred.

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
        # ADR-023 (Wave-2) — config.tenant_overlay.{set,cleared} chain rows
        # (operator changing a per-tenant config ceiling/floor IS an
        # operational-responsibility event; emitted by core/config_overlay/
        # storage.py tagged A.6.2.5). The resolver's invalid_at_read incident
        # is tagged A.9.2 + flows through the existing audit.append hook there.
        (
            "escalation.transition",
            "rbac.check_scope",
            "sandbox.lifecycle.*",
            "config.tenant_overlay.set",
            "config.tenant_overlay.cleared",
        ),
        "implemented",
    ),
    ControlEntry(
        "ISO42001.A.6.2.6",
        "A.6.2.6",
        "Roles and responsibilities",
        # Sprint 9.5 A6 flip — every ``model.lifecycle.*`` chain row
        # tags A.6.2.6 (lifecycle transitions encode role responsibility
        # for model registration / promotion / retirement decisions).
        ("model.lifecycle.*",),
        "implemented",
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
        (
            "auto_degradation.evaluate",
            "compliance_checker.score",
            "eval.bulk_run",  # Sprint 12 (ADR-010) — bulk eval IS a risk-evaluation surface.
        ),
        "implemented",
    ),
    ControlEntry(
        "ISO42001.A.8.2",
        "A.8.2",
        "Data quality for AI systems",
        # Sprint 9.5 A6 flip — every ``model.lifecycle.*`` chain row
        # tags A.8.2 (a model IS a data-quality control: knowing
        # which model produced which output is data-quality
        # provenance for AI systems).
        ("model.lifecycle.*",),
        "implemented",
    ),
    ControlEntry(
        "ISO42001.A.8.5",
        "A.8.5",
        "AI system development",
        # Sprint 9.5 A6 flip — every ``model.lifecycle.*`` chain row
        # tags A.8.5 (model registration / promotion / retirement IS
        # AI system development lifecycle evidence).
        ("model.lifecycle.*",),
        "implemented",
    ),
    ControlEntry(
        "ISO42001.A.9.2",
        "A.9.2",
        "System and operational logging",
        ("audit.append", "chain_verifier.walk", "eval.bulk_run"),
        "implemented",
    ),
    ControlEntry(
        "ISO42001.A.10.2",
        "A.10.2",
        "Stakeholder transparency",
        # Sprint 9.5 A6 flip — every ``model.lifecycle.*`` chain row
        # tags A.10.2 (lifecycle transitions are stakeholder-visible
        # facts about which models are in service for a tenant).
        ("model.lifecycle.*",),
        "implemented",
    ),
)


def control_ids() -> frozenset[str]:
    """The 8 canonical control-ID strings (8 implemented + 0 deferred
    post-Sprint-12; was 7 + 1 at Sprint 9.5 A6, 3 + 5 at Sprint 9 close)."""
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
