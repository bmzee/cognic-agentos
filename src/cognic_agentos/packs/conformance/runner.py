"""OWASP conformance chain-payload serialization adapter (Sprint 7B.2 T9).

Per ADR-012 §119 + ADR-006 evidence-pack export — this module is the WIRE-
SHAPE boundary between the :mod:`packs.conformance.owasp_agentic` check
matrix and the :data:`DecisionRecord.payload["conformance"]` chain-row key.

The single public seam :func:`run_owasp_conformance_for_chain_payload`
consumes a manifest dict and returns a JSON-serialisable ``dict[str, Any]``
whose top-level keys EXACTLY match the
:class:`cognic_agentos.packs.conformance.checks.ConformanceReport` 4-field
shape: ``overall_status`` / ``results`` / ``summary`` /
``errored_categories``.

T9 submit handler (``portal/api/packs/author_routes.submit_draft``) calls
this adapter OUTSIDE the storage closure + threads the result through
:meth:`PackRecordStore.transition` 's ``payload_conformance`` kwarg.  The
serialisation is intentionally separated from the check matrix so the
chain-payload byte-shape is testable independently — drift in either
direction (missing key, extra key, type mismatch) is pinned by
``tests/unit/packs/conformance/test_runner.py``.

**Module is CRITICAL CONTROLS** per the Sprint-7B.2 T9 plan-of-record + the
user-locked Slice-2 advice (durable-gate promotion lands at Slice 4
alongside the same 95% line / 90% branch floor as the T8 conformance
modules).  T9 chain-payload byte-shape stability is wire-protocol-public
for evidence-pack export readers per ADR-006.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from cognic_agentos.packs.conformance.owasp_agentic import run_owasp_conformance


def run_owasp_conformance_for_chain_payload(
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Run the OWASP conformance suite + serialise the report into the
    JSON-friendly dict shape the chain row's ``payload.conformance`` key
    expects.

    Implementation strategy (per T9 Slice-2 user lock): delegate to
    :func:`run_owasp_conformance` for the check matrix, then convert the
    returned :class:`ConformanceReport` via :func:`dataclasses.asdict`.
    The recursive ``asdict`` walk converts nested
    :class:`ConformanceCheckResult` dataclasses into plain dicts.

    **Tuple → list explicit conversion**: Python's :func:`dataclasses.asdict`
    PRESERVES tuple-typed fields (it recurses INTO tuples but reconstructs
    them as tuples, per CPython implementation).  ``ConformanceReport.errored_categories``
    is typed as ``tuple[OWASPCheckCategory, ...]``, so the raw ``asdict``
    output carries a tuple there.  The Sprint-2 canonical-form rejects
    tuples in :func:`cognic_agentos.core.canonical.canonical_bytes` to
    prevent the silent list/tuple ambiguity bug class — every chain-row
    payload value MUST be a list, dict, str, int, float, bool, or None.
    We explicitly convert the ``errored_categories`` tuple to a list here
    so downstream chain insert (which canonicalises the payload via
    :func:`canonical_bytes`) accepts it; the wire-shape contract pinned
    by ``test_runner.py::test_errored_categories_is_list_after_asdict_conversion``
    encodes this list-not-tuple invariant.

    The 4-key top-level shape is wire-protocol-public per ADR-006 and
    pinned at ``tests/unit/packs/conformance/test_runner.py``.  Drift in
    either direction breaks T9 chain-payload consumers + 7B.3 reviewer
    evidence panels.
    """
    report = run_owasp_conformance(manifest)
    serialised = asdict(report)
    # Tuple-to-list conversion — see docstring.  ``ConformanceReport`` only
    # has one tuple-typed field (``errored_categories``); explicit per-
    # field conversion avoids a deep recursive walk + keeps the contract
    # readable.
    serialised["errored_categories"] = list(serialised["errored_categories"])
    return serialised
