"""Sprint 7B.3 T2 Slice B — pure-functional lifecycle helpers (module-private).

This module exposes the AUTHORITATIVE seam for reading the most recent
submit chain row out of a pack's lifecycle history. Consumed by:

- :mod:`cognic_agentos.packs.evidence.*` panel projectors (T3-T6) —
  reading the persisted manifest at ``payload["manifest"]`` per
  R1 P2 #1's manifest-evidence-source seam.
- The approve route handler (T9) — reading the persisted manifest +
  ``payload["conformance"]`` (OWASP verdict from 7B.2 T9) +
  ``payload["signed_artefact_root"]`` (R6 P2 #4 bundle root) to drive
  the 5-gate composer.

Module-private (``_`` prefix) because the helper is implementation
detail of the panel + composer paths; bank overlays should not depend
on this surface directly.

Pure-functional: no I/O, no DB access. The caller fetches the chain
history via :meth:`PackRecordStore.load_lifecycle_history` and passes
the list in.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cognic_agentos.core.decision_history import DecisionRecord


__all__ = ["find_latest_submit_row"]


_SUBMIT_DECISION_TYPE: str = "pack.lifecycle.submitted"
"""Submit-transition ``decision_type`` constant.

Mirrors the f-string output at ``packs/storage.py:866`` where the
submit transition writes ``decision_type=f"pack.lifecycle.{target_state}"``
with ``target_state = _TRANSITION_TO_TARGET_STATE["submit"]`` (= ``"submitted"``).

Drift between this constant and storage's f-string output is pinned
by ``tests/unit/packs/test_lifecycle_helpers.py::
TestSprint7B3T2SliceBSubmitNamespaceDriftDetector`` — the test imports
``_TRANSITION_TO_TARGET_STATE`` from storage + reconstructs the
expected f-string + asserts equality with this constant.
"""


def find_latest_submit_row(history: list[DecisionRecord]) -> DecisionRecord | None:
    """Return the most recent submit chain row in ``history``, or None.

    Walks the history newest-first and returns the first record whose
    ``decision_type`` matches the submit-transition namespace. If no
    submit row exists (pack still in draft, or only withdrawn rows),
    returns ``None``.

    The caller (T3-T6 panels / T9 approve) maps ``None`` to a 409
    Conflict with closed-enum ``pack_not_yet_submitted`` per R1 P2 #1
    + R9 evidence-routes refusal vocabulary.

    Inputs:
      history: list of :class:`DecisionRecord` ordered by chain
        sequence (oldest first → newest last). The caller fetches this
        via :meth:`PackRecordStore.load_lifecycle_history` which
        returns records ORDER BY sequence ASC per the chain semantics
        at ``core/decision_history.py``.

    Returns:
      The most recent :class:`DecisionRecord` with
      ``decision_type == "pack.lifecycle.submitted"`` (per the drift-
      detector-pinned constant ``_SUBMIT_DECISION_TYPE``), or ``None``
      if no such record exists. Re-submit-after-withdraw scenarios
      correctly return the newest submit (not the original first one).
    """
    for record in reversed(history):
        if record.decision_type == _SUBMIT_DECISION_TYPE:
            return record
    return None
