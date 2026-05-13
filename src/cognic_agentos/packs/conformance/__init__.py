"""OWASP conformance check matrix (Sprint 7B.2 T8 — CRITICAL CONTROLS).

Per ADR-012 §119 + BUILD_PLAN §628 + plan-of-record §1021-1059. Wire-protocol-
public per ADR-006 — the surfaces re-exported below are consumed by T9 chain-
payload writers (``payload.conformance``), 7B.3 reviewer evidence panels, and
evidence-pack export readers.

This module is the public re-export surface for the completed T8 conformance
matrix. The behaviour lives in two modules under this package:

- :mod:`cognic_agentos.packs.conformance.checks` — shared wire types: the
  10-value :data:`OWASPCheckCategory` Literal, the 3-value
  :data:`ConformanceCheckStatus` (per-check: ``pass`` / ``fail`` /
  ``not_applicable``), the 3-value :data:`ConformanceOverallStatus`
  (composite: ``green`` / ``red`` / ``yellow``), and the frozen
  :class:`ConformanceCheckResult` + :class:`ConformanceReport` dataclasses.
- :mod:`cognic_agentos.packs.conformance.owasp_agentic` — 10 deterministic
  manifest-shape check functions, the per-pack-kind ``_APPLICABILITY`` matrix,
  the ordered ``_CHECK_REGISTRY`` (1:1 with the Literal), and the
  :func:`run_owasp_conformance` dispatcher (applicability-aware: consults the
  matrix BEFORE invoking a body; wraps body invocation in ``try / except``
  and maps any exception to a synthesised ``not_applicable`` result +
  ``errored_categories`` append + ``yellow`` overall status — yellow takes
  precedence over red because an incomplete suite means the red/green verdict
  is not trustworthy).

Both behaviour modules are on the durable critical-controls coverage gate at
95% line / 90% branch per ``tools/check_critical_coverage.py``. This
``__init__.py`` stays off-gate per Doctrine F because it carries no
behaviour — only the re-export list.
"""

from __future__ import annotations

from cognic_agentos.packs.conformance.checks import (
    ConformanceCheckResult,
    ConformanceCheckStatus,
    ConformanceOverallStatus,
    ConformanceReport,
    OWASPCheckCategory,
)
from cognic_agentos.packs.conformance.owasp_agentic import (
    check_dependency_poisoning,
    check_goal_hijacking,
    check_identity_abuse,
    check_prompt_injected_skills,
    check_secret_exfiltration,
    check_skills_top_10,
    check_supply_chain_integrity,
    check_tool_misuse,
    check_unsafe_filesystem,
    check_unsafe_network,
    run_owasp_conformance,
)
from cognic_agentos.packs.conformance.runner import (
    run_owasp_conformance_for_chain_payload,
)

__all__ = [
    "ConformanceCheckResult",
    "ConformanceCheckStatus",
    "ConformanceOverallStatus",
    "ConformanceReport",
    "OWASPCheckCategory",
    "check_dependency_poisoning",
    "check_goal_hijacking",
    "check_identity_abuse",
    "check_prompt_injected_skills",
    "check_secret_exfiltration",
    "check_skills_top_10",
    "check_supply_chain_integrity",
    "check_tool_misuse",
    "check_unsafe_filesystem",
    "check_unsafe_network",
    "run_owasp_conformance",
    "run_owasp_conformance_for_chain_payload",
]
