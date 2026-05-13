"""Sprint 7B.1 T2 — :mod:`cognic_agentos.packs.lifecycle` unit tests.

Pins the closed-enum vocabularies (PackKind / PackState / TransitionName /
LifecycleRefusalReason) + the per-transition ADR-012 §"State transitions"
legal-pair table + the per-emit-reason refusal precedence inside
:func:`validate_transition`.

The state machine is **CRITICAL CONTROLS** per AGENTS.md "Authoring — Bank
pack lifecycle (Sprint 7B.1)". 95% line / 90% branch coverage required by
the gate at ``tools/check_critical_coverage.py`` (T7 promotion).
"""

from __future__ import annotations

from typing import get_args

import pytest

from cognic_agentos.packs.lifecycle import (
    _VALID_TRANSITIONS,
    LifecycleRefusalReason,
    PackKind,
    PackState,
    TransitionName,
    validate_transition,
)


class TestSprint7B1ClosedEnumVocabulary:
    """Closed-enum shape pinning. Adding a value (PackKind / PackState /
    TransitionName / LifecycleRefusalReason) without updating the matching
    surface (migration CHECK constraint, transition table, refusal reason
    emit path) MUST fail one of these tests."""

    def test_pack_kind_is_canonical_4_tuple(self) -> None:
        assert set(get_args(PackKind)) == {"tool", "skill", "agent", "hook"}

    def test_pack_state_is_canonical_11_tuple_per_adr_012(self) -> None:
        # ADR-012 §"Lifecycle states" lines 25-32.
        assert set(get_args(PackState)) == {
            "draft",
            "submitted",
            "under_review",
            "approved",
            "rejected",
            "withdrawn",
            "allow_listed",
            "installed",
            "disabled",
            "revoked",
            "uninstalled",
        }

    def test_transition_name_is_canonical_10_tuple_per_adr_012(self) -> None:
        # ADR-012 §"State transitions" 10-row table at lines 38-48.
        assert set(get_args(TransitionName)) == {
            "submit",
            "claim",
            "approve",
            "reject",
            "withdraw",
            "allow_list",
            "install",
            "disable",
            "revoke",
            "uninstall",
        }

    def test_lifecycle_refusal_reason_is_canonical_13_value_closed_enum(self) -> None:
        # Doctrine Lock C — 13 values, finalised at T2 R1 P2 (the
        # plan-of-record's provisional 12-value count grew by one when the
        # transition-name runtime guard was added to close the
        # KeyError-leak contract bug). ``actor_role_mismatch`` deferred to
        # 7B.2 (RBAC), ``evidence_required`` deferred to 7B.3 (5-gate);
        # ``kind_state_combination_forbidden`` reserved for future kind
        # rules with no emit path in 7B.1.
        assert set(get_args(LifecycleRefusalReason)) == {
            "lifecycle_transition_invalid_state_pair",
            "lifecycle_transition_state_unknown",
            "lifecycle_transition_kind_unknown",
            "lifecycle_transition_name_unknown",
            "lifecycle_transition_terminal_state",
            "lifecycle_transition_kind_state_combination_forbidden",
            "lifecycle_transition_double_install",
            "lifecycle_transition_revoke_already_revoked",
            "lifecycle_transition_uninstall_not_revoked_or_disabled",
            "lifecycle_transition_withdraw_post_review",
            "lifecycle_transition_approve_without_review_claim",
            "lifecycle_transition_disable_not_installed",
            "lifecycle_transition_allow_list_not_approved",
        }

    def test_kind_state_combination_forbidden_is_reserved_doctrine_value(self) -> None:
        """``lifecycle_transition_kind_state_combination_forbidden`` is included
        in the closed-enum but has NO emit path in 7B.1 — reserved for future
        kind-specific transition rules. Future sprints adding such a rule MUST
        add an emit path AND a corresponding regression test in the same commit."""
        assert "lifecycle_transition_kind_state_combination_forbidden" in get_args(
            LifecycleRefusalReason
        )

    def test_kind_state_pack_state_refusal_reasons_are_disjoint(self) -> None:
        """No string overlap between the three closed-enums — sanity guard
        against accidental cross-vocabulary collision (e.g. a refactor that
        renames a refusal reason to match a state name)."""
        kinds = set(get_args(PackKind))
        states = set(get_args(PackState))
        reasons = set(get_args(LifecycleRefusalReason))
        transitions = set(get_args(TransitionName))
        assert kinds.isdisjoint(states)
        assert kinds.isdisjoint(reasons)
        assert kinds.isdisjoint(transitions)
        assert states.isdisjoint(reasons)
        assert states.isdisjoint(transitions)
        # transitions and reasons both use snake_case; deliberately allow no
        # overlap. (e.g. "submit" is a transition; "lifecycle_transition_*"
        # is a reason — disjoint by construction.)
        assert transitions.isdisjoint(reasons)


class TestSprint7B1ValidTransitionsTable:
    """Pin the ``_VALID_TRANSITIONS`` table contents verbatim against ADR-012
    §"State transitions". A drift in the table is a doctrinal change that
    must be flagged at review."""

    def test_every_transition_name_is_a_table_key(self) -> None:
        assert set(_VALID_TRANSITIONS.keys()) == set(get_args(TransitionName))

    def test_every_table_entry_uses_canonical_pack_states(self) -> None:
        states = set(get_args(PackState))
        for transition_name, pairs in _VALID_TRANSITIONS.items():
            for from_state, to_state in pairs:
                assert from_state in states, (
                    f"transition {transition_name!r}: from_state {from_state!r} "
                    f"not in canonical PackState 11-tuple"
                )
                assert to_state in states, (
                    f"transition {transition_name!r}: to_state {to_state!r} "
                    f"not in canonical PackState 11-tuple"
                )

    def test_table_pairs_match_adr_012_state_transitions_table(self) -> None:
        """Pin the exact 13 legal ``(from, to)`` pairs across the 10 transitions
        per ADR-012 lines 38-48 (3 transitions are multi-from: withdraw,
        revoke, uninstall — each contributing 2 pairs; the other 7 are
        single-from)."""
        assert _VALID_TRANSITIONS["submit"] == frozenset({("draft", "submitted")})
        assert _VALID_TRANSITIONS["claim"] == frozenset({("submitted", "under_review")})
        assert _VALID_TRANSITIONS["approve"] == frozenset({("under_review", "approved")})
        assert _VALID_TRANSITIONS["reject"] == frozenset({("under_review", "rejected")})
        assert _VALID_TRANSITIONS["withdraw"] == frozenset(
            {
                ("submitted", "withdrawn"),
                ("under_review", "withdrawn"),
            }
        )
        assert _VALID_TRANSITIONS["allow_list"] == frozenset({("approved", "allow_listed")})
        assert _VALID_TRANSITIONS["install"] == frozenset({("allow_listed", "installed")})
        assert _VALID_TRANSITIONS["disable"] == frozenset({("installed", "disabled")})
        assert _VALID_TRANSITIONS["revoke"] == frozenset(
            {
                ("installed", "revoked"),
                ("disabled", "revoked"),
            }
        )
        assert _VALID_TRANSITIONS["uninstall"] == frozenset(
            {
                ("disabled", "uninstalled"),
                ("revoked", "uninstalled"),
            }
        )

    def test_table_has_13_legal_pairs_total(self) -> None:
        """Aggregate cross-check: across all 10 transitions, exactly 13 legal
        ``(from, to)`` pairs are encoded.

        Breakdown per ADR-012 §"State transitions" (lines 38-48):

        - 7 single-from transitions: submit, claim, approve, reject,
          allow_list, install, disable → 7 pairs.
        - 3 multi-from transitions (2 from-states each): withdraw
          (submitted/under_review), revoke (installed/disabled), uninstall
          (disabled/revoked) → 6 pairs.

        Total = 7 + 6 = 13."""
        total_pairs = sum(len(pairs) for pairs in _VALID_TRANSITIONS.values())
        assert total_pairs == 13


class TestSprint7B1ValidTransitionsReturnNone:
    """One positive pass case per legal ``(from, to, transition)`` triple
    crossed with the canonical 4-tuple of pack kinds — proves the kind
    parameter does NOT affect transition validity in 7B.1 (Doctrine Lock G)."""

    @pytest.mark.parametrize(
        "from_state,to_state,transition",
        [
            ("draft", "submitted", "submit"),
            ("submitted", "under_review", "claim"),
            ("under_review", "approved", "approve"),
            ("under_review", "rejected", "reject"),
            ("submitted", "withdrawn", "withdraw"),
            ("under_review", "withdrawn", "withdraw"),
            ("approved", "allow_listed", "allow_list"),
            ("allow_listed", "installed", "install"),
            ("installed", "disabled", "disable"),
            ("installed", "revoked", "revoke"),
            ("disabled", "revoked", "revoke"),
            ("disabled", "uninstalled", "uninstall"),
            ("revoked", "uninstalled", "uninstall"),
        ],
    )
    @pytest.mark.parametrize("kind", ["tool", "skill", "agent", "hook"])
    def test_valid_transition_returns_none(
        self,
        from_state: str,
        to_state: str,
        transition: str,
        kind: str,
    ) -> None:
        result = validate_transition(
            from_state=from_state,  # type: ignore[arg-type]
            to_state=to_state,  # type: ignore[arg-type]
            kind=kind,  # type: ignore[arg-type]
            transition=transition,  # type: ignore[arg-type]
        )
        assert result is None, (
            f"expected None for valid transition ({from_state} -> {to_state}, "
            f"transition={transition}, kind={kind}); got {result!r}"
        )


class TestSprint7B1InvalidTransitionsEmitClosedEnum:
    """One negative case per emittable :data:`LifecycleRefusalReason` (12
    emit reasons after T2 R1 P2 added ``lifecycle_transition_name_unknown``;
    the 13th value, ``lifecycle_transition_kind_state_combination_forbidden``,
    is reserved per
    :class:`TestSprint7B1ClosedEnumVocabulary.test_kind_state_combination_forbidden_is_reserved_doctrine_value`).

    Per the plan-of-record T2 §"Tests": "12+ representative invalid transitions"
    — exceeded here with explicit per-reason tests + precedence-ordering tests.
    """

    def test_kind_unknown_returns_kind_unknown_reason(self) -> None:
        # ``workflow`` is not in the canonical 4-tuple; future kind expansion
        # would require updating PackKind + the multi-surface drift-detector
        # in lock-step. The kind check fires FIRST per the validator's
        # precedence ordering (before state validation, transition-name
        # guard, terminal-state guard, per-transition reasons, and the
        # generic fallthrough).
        result = validate_transition(
            from_state="draft",
            to_state="submitted",
            kind="workflow",  # type: ignore[arg-type]
            transition="submit",
        )
        assert result == "lifecycle_transition_kind_unknown"

    def test_state_unknown_from_state_returns_state_unknown_reason(self) -> None:
        result = validate_transition(
            from_state="quarantined",  # type: ignore[arg-type]
            to_state="submitted",
            kind="tool",
            transition="submit",
        )
        assert result == "lifecycle_transition_state_unknown"

    def test_state_unknown_to_state_returns_state_unknown_reason(self) -> None:
        result = validate_transition(
            from_state="draft",
            to_state="quarantined",  # type: ignore[arg-type]
            kind="tool",
            transition="submit",
        )
        assert result == "lifecycle_transition_state_unknown"

    def test_transition_name_unknown_returns_name_unknown_reason(self) -> None:
        # T2 R1 P2 regression — without the transition-name runtime guard,
        # a caller passing an out-of-vocabulary transition (here:
        # ``archive``, never declared in TransitionName) would raise
        # ``KeyError`` at the ``_VALID_TRANSITIONS[transition]`` lookup at
        # the generic fallthrough step, leaking an unstructured exception
        # past the closed-enum contract that downstream T3 storage code
        # relies on. Storage does NOT catch ``LifecycleTransitionRefused``
        # — the exception propagates up through
        # ``append_with_precondition`` and ``transition()`` while
        # ``engine.begin()`` at ``core/decision_history.py:482`` rolls
        # back the precondition's transaction (established at T7 R7).
        result = validate_transition(
            from_state="draft",
            to_state="submitted",
            kind="tool",
            transition="archive",  # type: ignore[arg-type]
        )
        assert result == "lifecycle_transition_name_unknown"

    def test_transition_name_unknown_does_not_leak_keyerror_for_uninstall_archive(
        self,
    ) -> None:
        """A second transition-name-unknown regression to broaden the
        no-KeyError-leak invariant beyond the canonical example. Any
        out-of-vocabulary transition string MUST flow through the
        closed-enum reason path."""
        result = validate_transition(
            from_state="installed",
            to_state="archived",  # type: ignore[arg-type]
            kind="tool",
            transition="archive",  # type: ignore[arg-type]
        )
        # Note: to_state="archived" is also out-of-vocabulary. Per the
        # precedence chain, state-unknown fires BEFORE transition-unknown,
        # so this returns ``state_unknown`` — the precedence ordering is
        # pinned independently in TestSprint7B1RefusalPrecedence.
        assert result == "lifecycle_transition_state_unknown"

    def test_terminal_state_uninstalled_has_no_outgoing_edges(self) -> None:
        # ADR-012 §"Lifecycle states" makes uninstalled terminal — historical
        # audit/evidence records are never deleted (line 50). No transition
        # whatsoever is permitted from this state.
        result = validate_transition(
            from_state="uninstalled",
            to_state="installed",
            kind="tool",
            transition="install",
        )
        assert result == "lifecycle_transition_terminal_state"

    def test_double_install_from_installed_returns_double_install(self) -> None:
        result = validate_transition(
            from_state="installed",
            to_state="installed",
            kind="tool",
            transition="install",
        )
        assert result == "lifecycle_transition_double_install"

    def test_revoke_from_already_revoked_returns_revoke_already_revoked(self) -> None:
        result = validate_transition(
            from_state="revoked",
            to_state="revoked",
            kind="tool",
            transition="revoke",
        )
        assert result == "lifecycle_transition_revoke_already_revoked"

    def test_uninstall_from_approved_returns_uninstall_not_revoked_or_disabled(
        self,
    ) -> None:
        # ADR-012 line 48: "disabled/revoked → uninstalled". From any other
        # state, uninstall is refused with a specific reason — better
        # operator diagnostics than a generic ``invalid_state_pair``.
        result = validate_transition(
            from_state="approved",
            to_state="uninstalled",
            kind="tool",
            transition="uninstall",
        )
        assert result == "lifecycle_transition_uninstall_not_revoked_or_disabled"

    def test_withdraw_from_approved_returns_withdraw_post_review(self) -> None:
        # ADR-012 line 43: "submitted/under_review → withdrawn". Withdraw is
        # only legal from those two states; ``approved`` (post-approval) +
        # ``allow_listed`` etc. cannot withdraw.
        result = validate_transition(
            from_state="approved",
            to_state="withdrawn",
            kind="tool",
            transition="withdraw",
        )
        assert result == "lifecycle_transition_withdraw_post_review"

    def test_approve_from_submitted_returns_approve_without_review_claim(self) -> None:
        # ADR-012 line 41: approve requires ``under_review`` from-state — i.e.
        # a reviewer must have ``claimed`` the submission first. Skipping the
        # claim step is a common operator mistake; gets a specific reason.
        result = validate_transition(
            from_state="submitted",
            to_state="approved",
            kind="tool",
            transition="approve",
        )
        assert result == "lifecycle_transition_approve_without_review_claim"

    def test_disable_from_approved_returns_disable_not_installed(self) -> None:
        # ADR-012 line 46: "installed → disabled". Disable from any other
        # state (e.g. approved, allow_listed) is refused.
        result = validate_transition(
            from_state="approved",
            to_state="disabled",
            kind="tool",
            transition="disable",
        )
        assert result == "lifecycle_transition_disable_not_installed"

    def test_allow_list_from_submitted_returns_allow_list_not_approved(self) -> None:
        # ADR-012 line 44: "approved → allow_listed". Allow-listing a pack
        # before it has been approved would skip the approval gate — refused.
        result = validate_transition(
            from_state="submitted",
            to_state="allow_listed",
            kind="tool",
            transition="allow_list",
        )
        assert result == "lifecycle_transition_allow_list_not_approved"

    def test_invalid_state_pair_generic_fallthrough(self) -> None:
        """Generic fallthrough — when no per-transition specific reason
        matches but the (from, to) pair is not in the legal-pair table.

        Example: ``submit`` from ``approved`` to ``submitted`` — neither
        kind/state/terminal-state checks fire, no per-transition specific
        reason fires (no ``submit_*`` reason exists), so the generic
        invalid-state-pair fallthrough returns it."""
        result = validate_transition(
            from_state="approved",
            to_state="submitted",
            kind="tool",
            transition="submit",
        )
        assert result == "lifecycle_transition_invalid_state_pair"

    def test_invalid_state_pair_install_from_draft(self) -> None:
        """A second invalid-state-pair regression — installing a draft pack
        without going through submit/claim/approve/allow_list. No specific
        per-transition reason matches (from is not installed → no
        double_install; transition is install, not allow_list → no
        allow_list_not_approved). Returns generic fallthrough."""
        result = validate_transition(
            from_state="draft",
            to_state="installed",
            kind="tool",
            transition="install",
        )
        assert result == "lifecycle_transition_invalid_state_pair"


class TestSprint7B1RefusalPrecedence:
    """Pin the precedence ordering inside :func:`validate_transition`.
    Reordering the checks would change which reason fires for ambiguous
    inputs (e.g. unknown kind + unknown state) — these tests catch that."""

    def test_kind_unknown_takes_precedence_over_state_unknown(self) -> None:
        # Both kind ``workflow`` and from_state ``quarantined`` are invalid;
        # kind check fires first.
        result = validate_transition(
            from_state="quarantined",  # type: ignore[arg-type]
            to_state="submitted",
            kind="workflow",  # type: ignore[arg-type]
            transition="submit",
        )
        assert result == "lifecycle_transition_kind_unknown"

    def test_state_unknown_takes_precedence_over_terminal_state(self) -> None:
        # to_state is invalid; state-unknown fires before terminal-state
        # check (which only inspects from_state).
        result = validate_transition(
            from_state="uninstalled",
            to_state="quarantined",  # type: ignore[arg-type]
            kind="tool",
            transition="install",
        )
        assert result == "lifecycle_transition_state_unknown"

    def test_state_unknown_takes_precedence_over_transition_name_unknown(self) -> None:
        # Both from_state and transition are out-of-vocabulary; state-unknown
        # fires first per precedence step 2 vs step 3.
        result = validate_transition(
            from_state="quarantined",  # type: ignore[arg-type]
            to_state="submitted",
            kind="tool",
            transition="archive",  # type: ignore[arg-type]
        )
        assert result == "lifecycle_transition_state_unknown"

    def test_transition_name_unknown_takes_precedence_over_terminal_state(self) -> None:
        # T2 R1 P2 regression — both from_state=uninstalled (terminal) and
        # transition=archive (out-of-vocabulary). Transition-unknown fires
        # at step 3 BEFORE the terminal-state check at step 4. Pinning this
        # ordering matters because if transition-unknown were placed after
        # terminal-state, callers from non-terminal states with bad
        # transition names would still flow through the per-transition
        # reasons path and could expose subtle behavior changes.
        result = validate_transition(
            from_state="uninstalled",
            to_state="installed",
            kind="tool",
            transition="archive",  # type: ignore[arg-type]
        )
        assert result == "lifecycle_transition_name_unknown"

    def test_transition_name_unknown_takes_precedence_over_per_transition_reasons(
        self,
    ) -> None:
        # An unknown transition combined with a from_state that would
        # otherwise trigger a per-transition specific reason (e.g.
        # from_state=installed, which would trip ``double_install`` if
        # transition were "install"). Transition-unknown fires first;
        # per-transition reasons never get a chance to evaluate against
        # an out-of-vocabulary transition.
        result = validate_transition(
            from_state="installed",
            to_state="installed",
            kind="tool",
            transition="archive",  # type: ignore[arg-type]
        )
        assert result == "lifecycle_transition_name_unknown"

    def test_kind_unknown_takes_precedence_over_transition_name_unknown(self) -> None:
        # Both kind=workflow and transition=archive are out-of-vocabulary;
        # kind-unknown fires first per precedence step 1 vs step 3.
        result = validate_transition(
            from_state="draft",
            to_state="submitted",
            kind="workflow",  # type: ignore[arg-type]
            transition="archive",  # type: ignore[arg-type]
        )
        assert result == "lifecycle_transition_kind_unknown"

    def test_terminal_state_takes_precedence_over_per_transition_reasons(self) -> None:
        # from_state=uninstalled + transition=install would otherwise fall
        # through to ``invalid_state_pair`` (since (uninstalled, installed)
        # is not legal); terminal-state fires first.
        result = validate_transition(
            from_state="uninstalled",
            to_state="installed",
            kind="tool",
            transition="install",
        )
        assert result == "lifecycle_transition_terminal_state"

    def test_per_transition_specific_reason_takes_precedence_over_invalid_state_pair(
        self,
    ) -> None:
        # ``approve`` from ``submitted`` would fall through to
        # ``invalid_state_pair`` if the per-transition specific check were
        # not present; ``approve_without_review_claim`` fires instead for
        # better diagnostics.
        result = validate_transition(
            from_state="submitted",
            to_state="approved",
            kind="tool",
            transition="approve",
        )
        assert result == "lifecycle_transition_approve_without_review_claim"


class TestSprint7B1NoKeyErrorLeakInvariant:
    """T2 R1 P2 — pin the closed-enum contract: ``validate_transition`` MUST
    return either a closed-enum :data:`LifecycleRefusalReason` or ``None``
    for any **string** input combination, never raise an unstructured
    exception. (The signature is typed as :data:`PackKind` /
    :data:`PackState` / :data:`TransitionName`, all of which narrow to
    ``str`` at runtime; type-discipline violations such as ``kind=[]``
    raise ``TypeError`` at the ``in frozenset`` membership check and are
    mypy's job to prevent, not the runtime guard's. Adding type guards for
    non-string inputs would be defensive over-engineering of an SDK
    contract that is already statically typed.)

    The original failure mode was ``KeyError`` at
    ``_VALID_TRANSITIONS[transition]`` for out-of-vocabulary transition
    names; the regression target is broader — any future refactor that
    introduces another dict-lookup or attribute access on user-supplied
    string input MUST guard the lookup with the closed-enum reason path.
    """

    def test_unknown_transition_does_not_raise_keyerror(self) -> None:
        """The exact failure mode from the reviewer report — ``archive``
        is a string but not in :data:`TransitionName`. Should return a
        closed-enum reason, NOT raise."""
        # Use a dedicated assertion that is explicit about the no-raise
        # requirement (a `try / except KeyError` with a fail in except).
        try:
            result = validate_transition(
                from_state="draft",
                to_state="submitted",
                kind="tool",
                transition="archive",  # type: ignore[arg-type]
            )
        except KeyError as exc:
            pytest.fail(f"validate_transition leaked KeyError for unknown transition: {exc!r}")
        assert result == "lifecycle_transition_name_unknown"

    @pytest.mark.parametrize(
        "transition",
        ["", "ARCHIVE", "Archive", "submit ", " submit", "publish", "delete"],
    )
    def test_various_unknown_transitions_all_route_to_closed_enum(self, transition: str) -> None:
        """A broader sweep — empty string, case-mismatch (case-sensitive
        Literal), whitespace-padded valid name, and assorted plausible
        operator typos. All MUST route to the closed-enum reason path."""
        result = validate_transition(
            from_state="draft",
            to_state="submitted",
            kind="tool",
            transition=transition,  # type: ignore[arg-type]
        )
        assert result == "lifecycle_transition_name_unknown", (
            f"transition={transition!r} should return name_unknown; got {result!r}"
        )


class TestSprint7B1KeywordOnlyArgumentSignature:
    """Doctrine Lock C requires keyword-only arguments per the plan signature
    ``validate_transition(*, from_state, to_state, kind, transition)``. Pin
    against accidental refactor that drops the keyword-only marker."""

    def test_positional_arguments_are_rejected(self) -> None:
        with pytest.raises(TypeError):
            validate_transition(
                "draft",  # type: ignore[misc]
                "submitted",
                "tool",
                "submit",
            )
