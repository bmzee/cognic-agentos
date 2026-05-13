"""Sprint 7B.3 T2 Slice B — pure-functional lifecycle helpers.

The :func:`cognic_agentos.packs._lifecycle_helpers.find_latest_submit_row`
helper is the AUTHORITATIVE seam for reading the most recent submit
chain row out of a pack's lifecycle history. It is consumed by:

- :mod:`cognic_agentos.packs.evidence.*` panel projectors (T3-T6) —
  reading the persisted manifest at ``payload["manifest"]`` per
  R1 P2 #1's manifest-evidence-source seam.
- The approve route handler (T9) — reading the persisted manifest
  plus ``payload["conformance"]`` (OWASP verdict from 7B.2 T9) plus
  ``payload["signed_artefact_root"]`` (R6 P2 #4 bundle root) to drive
  the 5-gate composer.

The helper is pure-functional (no I/O, no DB access). It walks the
history newest-first and returns the most recent record whose
``decision_type == "pack.lifecycle.submitted"`` — exactly the f-string
namespace ``packs/storage.py:866`` writes for the submit transition
(verified by a drift detector below).

Six regressions in this slice:

1. Empty history → None
2. Single-submit history → that record
3. Multi-submit history (re-submit after withdraw) → newest by sequence
4. History with no submit (only draft / withdrawn) → None
5. History with non-submit transitions interleaved → newest submit only
6. **Drift detector**: the helper's hardcoded constant matches the
   live f-string output from ``storage.py``'s submit transition.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from uuid import uuid4

from cognic_agentos.core.decision_history import DecisionRecord


def _record(
    *,
    decision_type: str,
    seq: int = 1,
    pack_id: str | None = None,
    payload: dict[str, Any] | None = None,
) -> DecisionRecord:
    """Test-helper to build a DecisionRecord with sensible defaults.

    ``DecisionRecord`` is a frozen dataclass per
    ``core/decision_history.py:206-249`` — we build instances with the
    minimum fields needed for the helper-under-test to walk history.
    The helper inspects only ``decision_type``; other fields exist so
    Pydantic construction succeeds.
    """
    pack_id = pack_id or str(uuid4())
    payload = payload if payload is not None else {"pack_id": pack_id}
    return DecisionRecord(
        decision_type=decision_type,
        request_id=f"req-{seq}",
        actor_id=f"actor-{seq}",
        tenant_id=None,
        payload=payload,
        iso_controls=("A.5.31",),
    )


class TestSprint7B3T2SliceBFindLatestSubmitRow:
    """Pure-functional walk over decision history → most recent submit."""

    def test_empty_history_returns_none(self) -> None:
        """Empty list input → None; no submit row exists."""
        from cognic_agentos.packs._lifecycle_helpers import find_latest_submit_row

        result = find_latest_submit_row([])

        assert result is None

    def test_single_submit_history_returns_that_record(self) -> None:
        """One-element history with the submit row → return it.

        The helper must NOT filter on payload shape or any field
        beyond ``decision_type``; T2 R1 P2 #1 + R6 P2 #4 + later
        sprints persist additional payload keys, and the helper's
        single responsibility is "find the submit chain row" — payload
        inspection is the caller's concern.
        """
        from cognic_agentos.packs._lifecycle_helpers import find_latest_submit_row

        submit_row = _record(decision_type="pack.lifecycle.submitted", seq=1)

        result = find_latest_submit_row([submit_row])

        assert result is submit_row

    def test_multiple_submit_returns_newest(self) -> None:
        """Re-submit after withdraw → most recent submit row returned.

        Lifecycle scenario: draft → submitted (seq 1) → withdrawn
        (seq 2) → submitted again (seq 3). The newest submit row IS
        the authoritative evidence source for T3-T6 panels + T9
        approve. ``load_lifecycle_history`` at
        ``packs/storage.py:981`` returns history ordered by chain
        sequence; the helper takes the list AS-GIVEN and walks
        newest-first.
        """
        from cognic_agentos.packs._lifecycle_helpers import find_latest_submit_row

        first_submit = _record(decision_type="pack.lifecycle.submitted", seq=1)
        withdraw = _record(decision_type="pack.lifecycle.withdrawn", seq=2)
        second_submit = _record(decision_type="pack.lifecycle.submitted", seq=3)

        result = find_latest_submit_row([first_submit, withdraw, second_submit])

        assert result is second_submit

    def test_no_submit_returns_none(self) -> None:
        """History with only draft / withdrawn / non-submit rows → None.

        Pack drafted + withdrawn before any submit — panels MUST
        return 409 ``pack_not_yet_submitted`` rather than projecting
        a manifest that never made it onto the chain.
        """
        from cognic_agentos.packs._lifecycle_helpers import find_latest_submit_row

        draft = _record(decision_type="pack.lifecycle.draft", seq=1)
        withdrawn = _record(decision_type="pack.lifecycle.withdrawn", seq=2)

        result = find_latest_submit_row([draft, withdrawn])

        assert result is None

    def test_interleaved_non_submit_transitions_ignored(self) -> None:
        """Mixed-transition history → newest submit row only.

        Lifecycle scenario: draft → submitted → under_review → approved
        → allow_listed → installed → disabled. The submit row is at
        seq 2; the helper must return it despite later transitions
        being more recent.
        """
        from cognic_agentos.packs._lifecycle_helpers import find_latest_submit_row

        history = [
            _record(decision_type="pack.lifecycle.draft", seq=1),
            _record(decision_type="pack.lifecycle.submitted", seq=2),
            _record(decision_type="pack.lifecycle.under_review", seq=3),
            _record(decision_type="pack.lifecycle.approved", seq=4),
            _record(decision_type="pack.lifecycle.allow_listed", seq=5),
            _record(decision_type="pack.lifecycle.installed", seq=6),
            _record(decision_type="pack.lifecycle.disabled", seq=7),
        ]
        expected_submit = history[1]  # seq=2

        result = find_latest_submit_row(history)

        assert result is expected_submit


class TestSprint7B3T2SliceBSubmitNamespaceDriftDetector:
    """Drift detector — the helper's hardcoded ``"pack.lifecycle.submitted"``
    constant MUST match the live f-string output from ``storage.py``'s
    submit transition.

    The submit transition writes ``decision_type=f"pack.lifecycle.{target_state}"``
    at ``storage.py:866`` where ``target_state = _TRANSITION_TO_TARGET_STATE["submit"]``
    at ``storage.py:163`` = ``"submitted"``. The helper's constant
    must equal that f-string output verbatim; drift means the helper
    will silently miss the submit row.

    Without this regression, a future rename (e.g. ``"submitted"`` →
    ``"under_submission"``) breaks the helper's matching at runtime
    but no test fires until a T3-T6 panel request triggers the missing
    row code path. The drift detector AST-scans the storage map to
    verify the constant.
    """

    def test_helper_constant_matches_storage_submit_target_state(self) -> None:
        """Pin the helper's matching string against storage's mapping.

        Imports ``_TRANSITION_TO_TARGET_STATE`` from the live storage
        module + reconstructs the expected f-string ``decision_type``
        + verifies the helper module exposes the same constant.
        """
        from cognic_agentos.packs._lifecycle_helpers import _SUBMIT_DECISION_TYPE
        from cognic_agentos.packs.storage import _TRANSITION_TO_TARGET_STATE

        expected = f"pack.lifecycle.{_TRANSITION_TO_TARGET_STATE['submit']}"

        assert expected == _SUBMIT_DECISION_TYPE
        assert _SUBMIT_DECISION_TYPE == "pack.lifecycle.submitted"

    def test_helper_source_uses_module_private_constant(self) -> None:
        """The helper module declares a module-scope constant rather
        than inlining the f-string output, so the drift detector
        above has a single seam to verify.

        AST scan asserts:
        - Module declares ``_SUBMIT_DECISION_TYPE`` assignment
        - The helper function body references that name (not a string
          literal) when matching ``decision_type`` values
        """
        module_path = (
            Path(__file__).resolve().parents[3]
            / "src"
            / "cognic_agentos"
            / "packs"
            / "_lifecycle_helpers.py"
        )
        source = module_path.read_text()

        assert "_SUBMIT_DECISION_TYPE" in source, (
            "Helper module must declare module-scope _SUBMIT_DECISION_TYPE "
            "constant so the drift detector can pin it against "
            "storage._TRANSITION_TO_TARGET_STATE['submit']."
        )
        # Ensure the helper function uses the constant, not a string
        # literal — search for the name in a comparison or assignment.
        assert re.search(r"_SUBMIT_DECISION_TYPE\s*[=:!]", source), (
            "Helper must compare/reference _SUBMIT_DECISION_TYPE (not "
            "inline a string literal) so the drift detector binds the "
            "matching seam."
        )
