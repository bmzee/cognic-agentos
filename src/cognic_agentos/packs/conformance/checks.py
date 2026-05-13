"""Shared types for the OWASP conformance check matrix (Sprint 7B.2 T8 — CRITICAL CONTROLS).

Closed-enum Literals + frozen-dataclass result types per ADR-012 §119 +
BUILD_PLAN §628. Wire-protocol-public for evidence-pack export per ADR-006 — drift
in :data:`OWASPCheckCategory` or :data:`ConformanceOverallStatus` breaks downstream
chain-payload readers in T9 + 7B.3.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

OWASPCheckCategory = Literal[
    "tool_misuse",
    "goal_hijacking",
    "identity_abuse",
    "prompt_injected_skills",
    "dependency_poisoning",
    "secret_exfiltration",
    "unsafe_filesystem",
    "unsafe_network",
    "supply_chain_integrity",
    "skills_top_10",
]
"""Closed-enum 10-value Literal for OWASP Top 10 for Agentic Applications 2026 +
Agentic Skills Top 10 (composite at ``skills_top_10``).

Doctrine Lock — wire-protocol contract for reviewer evidence per ADR-012 §119 +
BUILD_PLAN §628. T9 attaches per-category results to ``payload.conformance`` in the
chain row; 7B.3 reviewers consume the same set. Drift breaks evidence-pack export
readers per ADR-006."""


ConformanceCheckStatus = Literal["pass", "fail", "not_applicable"]
"""Per-check status. ``not_applicable`` covers cross-pack-kind cases (e.g.
``check_skills_top_10`` against a non-skill pack)."""


ConformanceOverallStatus = Literal["green", "red", "yellow"]
"""Composite report status — T8 user-locked semantics:

- ``green`` — every check returned ``pass`` or ``not_applicable``
- ``red`` — at least one check returned ``fail``
- ``yellow`` — runner-level incompleteness ONLY (a checker raised an exception OR
  a result is missing). ``yellow`` is **never** a ``pass`` + ``not_applicable`` mix.

The runner maps checker-exception → ``yellow`` via the wrapper at the dispatch loop."""


@dataclass(frozen=True)
class ConformanceCheckResult:
    """Result of a single OWASP conformance check.

    ``findings`` is a ``list[str]`` per the T8 user lock; each entry uses a
    stable field-path prefix, e.g. ``manifest.permissions.network: wildcard egress
    is not allowed``. Structured-dict findings are out of scope for 7B.2."""

    category: OWASPCheckCategory
    status: ConformanceCheckStatus
    findings: list[str]


@dataclass(frozen=True)
class ConformanceReport:
    """Composite report from :func:`run_owasp_conformance`.

    ``results`` keys are :data:`OWASPCheckCategory` literal values (each key is one
    of the 10 closed-enum strings); values are per-category
    :class:`ConformanceCheckResult` records. ``summary`` is a human-readable count
    phrase like ``"8 pass / 1 fail / 1 not_applicable"`` (formatted by the
    runner; an ``" (N errored)"`` suffix is appended when
    ``errored_categories`` is non-empty).

    ``errored_categories`` (T8 wire-shape extension) lists the categories
    whose check function raised an exception during dispatch. When non-empty,
    the runner sets ``overall_status = "yellow"`` per the user-locked
    incompleteness-doctrine: yellow takes precedence over red because a checker
    exception means the suite is incomplete and the red/green verdict is not
    trustworthy. Ordering is preserved relative to ``_CHECK_REGISTRY`` /
    :data:`OWASPCheckCategory` Literal order.

    **Field order is wire-protocol-public** per ADR-006 — drift breaks
    evidence-pack export consumers reading positional / keyword-by-name."""

    overall_status: ConformanceOverallStatus
    results: dict[OWASPCheckCategory, ConformanceCheckResult]
    summary: str
    errored_categories: tuple[OWASPCheckCategory, ...] = ()
