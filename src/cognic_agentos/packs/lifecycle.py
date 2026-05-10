"""Sprint 7B.1 T2 — bank pack lifecycle state machine (per ADR-012).

This module is **CRITICAL CONTROLS** per AGENTS.md "Authoring — Bank pack
lifecycle (Sprint 7B.1)". 95% line / 90% branch coverage required by the
gate at ``tools/check_critical_coverage.py`` (T7 promotion). It is the
source-of-truth for :data:`PackKind`, :data:`PackState`, the
``_VALID_TRANSITIONS`` legal-pair table, and the
:func:`validate_transition` decision function.

Consumers
---------

- :class:`cognic_agentos.packs.storage.PackRecordStore` (T3) wires
  :func:`validate_transition` into the precondition closure of
  :meth:`cognic_agentos.core.decision_history.DecisionHistoryStore.append_with_precondition`
  per Sprint-2.5 T2 atomic-primitive doctrine. The closure does
  ``SELECT ... FOR UPDATE`` on the pack row, calls this validator under
  the chain-head lock, and either raises ``LifecycleTransitionRefused``
  (transaction rolls back) or proceeds with the chain INSERT + state
  cache UPDATE atomically.
- :mod:`cognic_agentos.cli.test_harness` (T6a) extends
  ``_HARNESS_SUPPORTED_KINDS`` to the canonical 4-tuple defined here.
- The Alembic migration ``20260510_0003_packs_lifecycle.py`` (T4)
  encodes :data:`PackKind` and :data:`PackState` as CHECK constraints at
  the database layer.

Doctrine
--------

**Pure-functional contract** (Doctrine Lock C in the plan-of-record).
:func:`validate_transition` is I/O-free and dialect-free. It consumes only
its arguments and returns a closed-enum :data:`LifecycleRefusalReason`
naming the failure mode, or ``None`` if the transition is valid. The
storage layer wires it into the database precondition; this module never
touches a database.

**No RBAC / evidence checks** (Doctrine Lock G). Actor identity + evidence
presence land in Sprint 7B.2 (RBAC scopes per ADR-012 §"RBAC scopes") +
Sprint 7B.3 (5-gate approval composition per ADR-012 §"Approval gate
composition"). The 7B.1 signature is state/transition/kind-only;
``actor_role_mismatch`` and ``evidence_required`` are deliberately NOT in
:data:`LifecycleRefusalReason`.

Refusal precedence (more-specific reasons fire BEFORE generic fallthrough):

1. ``lifecycle_transition_kind_unknown`` — ``kind`` not in the canonical
   4-tuple.
2. ``lifecycle_transition_state_unknown`` — ``from_state`` or ``to_state``
   not in the canonical 11-tuple.
3. ``lifecycle_transition_name_unknown`` — ``transition`` not in the
   canonical 10-tuple. Steps 1-3 form the input-vocabulary block; if any
   fires, no semantic check runs.
4. ``lifecycle_transition_terminal_state`` — ``from_state == "uninstalled"``
   has no outgoing edges per ADR-012.
5. Per-transition specific reasons (``double_install``,
   ``revoke_already_revoked``, ``uninstall_not_revoked_or_disabled``,
   ``withdraw_post_review``, ``approve_without_review_claim``,
   ``disable_not_installed``, ``allow_list_not_approved``) — provide
   specific operator diagnostics for the most-common mistake patterns.
6. ``lifecycle_transition_invalid_state_pair`` — generic fallthrough when
   the ``(from, to)`` pair is not in ``_VALID_TRANSITIONS[transition]``
   and no specific reason matched.

``lifecycle_transition_kind_state_combination_forbidden`` is reserved for
future kind-specific transition rules and has NO emit path in 7B.1.
Future sprints adding such a rule MUST add an emit path AND a
corresponding regression test in the same commit.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Literal, get_args

#: Canonical 4-tuple of pack kinds. Source-of-truth for build-time + runtime
#: + storage + harness vocabularies. See Doctrine Lock A in the
#: plan-of-record for the full multi-surface drift-detector contract.
#:
#: Style note: assigned as a plain ``= Literal[...]`` (without
#: ``TypeAlias`` annotation) to match the Sprint-7A2 repo convention at
#: ``packs/hooks/registry.py:100`` + ``packs/hooks/dispatcher.py:93``.
PackKind = Literal["tool", "skill", "agent", "hook"]

#: Canonical 11-tuple of lifecycle states per ADR-012 §"Lifecycle states"
#: (lines 25-32). The migration's ``state`` CHECK constraint mirrors this
#: set verbatim.
PackState = Literal[
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
]

#: Canonical 10-tuple of transition names per ADR-012 §"State transitions"
#: (lines 38-48). ``withdraw`` / ``revoke`` / ``uninstall`` each have
#: multiple legal from-states — see :data:`_VALID_TRANSITIONS`.
TransitionName = Literal[
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
]

#: 13-value closed-enum refusal reasons (Doctrine Lock C, finalised at T2 —
#: the plan-of-record anticipated +/- 1 vs. its provisional 12-value count
#: as the transition table was enumerated). ``actor_role_mismatch`` and
#: ``evidence_required`` are deferred to Sprint 7B.2 / 7B.3 respectively per
#: the plan-of-record. ``lifecycle_transition_kind_state_combination_forbidden``
#: is reserved for future kind-specific rules and has no emit path in 7B.1.
#:
#: ``lifecycle_transition_name_unknown`` was added at T2 R1 P2 to close the
#: KeyError-leak contract bug — the public function MUST return a closed-enum
#: reason for ANY out-of-vocabulary input, not just kind / state. Without
#: this, a caller passing ``transition="archive"`` would raise
#: ``KeyError("archive")`` at ``_VALID_TRANSITIONS[transition]`` lookup,
#: breaking the contract that downstream T3 storage code relies on (it
#: catches ``LifecycleTransitionRefused``, not arbitrary exceptions).
LifecycleRefusalReason = Literal[
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
]

#: Per-transition legal ``(from_state, to_state)`` pairs, mirroring the
#: ADR-012 §"State transitions" table verbatim. Keyed by transition name;
#: value is the frozenset of legal ``(from, to)`` pairs.
#:
#: Most transitions have a single legal from-state. ``withdraw`` / ``revoke``
#: / ``uninstall`` each have two legal from-states per ADR-012:
#:
#: - ``withdraw``: submitted/under_review → withdrawn (line 43)
#: - ``revoke``: installed/disabled → revoked (line 47)
#: - ``uninstall``: disabled/revoked → uninstalled (line 48)
#:
#: 13 legal pairs in total across the 10 transitions (7 single-from + 3
#: multi-from x 2 from-states each = 7 + 6 = 13). Pinned by
#: ``tests/unit/packs/test_lifecycle.py::TestSprint7B1ValidTransitionsTable
#: ::test_table_has_13_legal_pairs_total``.
_VALID_TRANSITIONS: Final[Mapping[TransitionName, frozenset[tuple[PackState, PackState]]]] = {
    "submit": frozenset({("draft", "submitted")}),
    "claim": frozenset({("submitted", "under_review")}),
    "approve": frozenset({("under_review", "approved")}),
    "reject": frozenset({("under_review", "rejected")}),
    "withdraw": frozenset(
        {
            ("submitted", "withdrawn"),
            ("under_review", "withdrawn"),
        }
    ),
    "allow_list": frozenset({("approved", "allow_listed")}),
    "install": frozenset({("allow_listed", "installed")}),
    "disable": frozenset({("installed", "disabled")}),
    "revoke": frozenset(
        {
            ("installed", "revoked"),
            ("disabled", "revoked"),
        }
    ),
    "uninstall": frozenset(
        {
            ("disabled", "uninstalled"),
            ("revoked", "uninstalled"),
        }
    ),
}

#: Runtime canonical kind set, derived from the :data:`PackKind` Literal at
#: module load time. Used by the kind-validation step inside
#: :func:`validate_transition` since Python does not enforce ``Literal`` at
#: runtime.
_KNOWN_KINDS: Final[frozenset[str]] = frozenset(get_args(PackKind))

#: Runtime canonical state set, derived from the :data:`PackState` Literal
#: at module load time. Same rationale as :data:`_KNOWN_KINDS`.
_KNOWN_STATES: Final[frozenset[str]] = frozenset(get_args(PackState))

#: Runtime canonical transition set, derived from the :data:`TransitionName`
#: Literal at module load time. Same rationale as :data:`_KNOWN_KINDS` —
#: Python does not enforce ``Literal`` at runtime, so the validator must
#: runtime-check the transition name to avoid leaking a ``KeyError`` from
#: the ``_VALID_TRANSITIONS[transition]`` lookup at the generic fallthrough
#: (T2 R1 P2).
_KNOWN_TRANSITIONS: Final[frozenset[str]] = frozenset(get_args(TransitionName))


def validate_transition(
    *,
    from_state: PackState,
    to_state: PackState,
    kind: PackKind,
    transition: TransitionName,
) -> LifecycleRefusalReason | None:
    """Validate a lifecycle transition.

    Pure-functional and I/O-free per Doctrine Lock C in the plan-of-record.
    Returns a closed-enum :data:`LifecycleRefusalReason` naming the failure
    mode, or ``None`` if the transition is valid.

    The keyword-only signature is intentional — positional misuse (e.g.
    swapping ``from_state`` and ``to_state``) is a load-bearing correctness
    bug class for a state machine; forcing keyword arguments at the call
    site eliminates that risk.

    Refusal precedence is documented in the module docstring. Most-specific
    reasons fire BEFORE the generic ``lifecycle_transition_invalid_state_pair``
    fallthrough so operator diagnostics name the actual mistake (e.g.
    ``approve_without_review_claim``) rather than the generic envelope.

    Parameters
    ----------
    from_state, to_state
        The current and requested lifecycle states. Must be members of the
        canonical 11-tuple :data:`PackState`. Out-of-set values return
        ``lifecycle_transition_state_unknown``.
    kind
        The pack kind. Must be a member of the canonical 4-tuple
        :data:`PackKind`. Out-of-set values return
        ``lifecycle_transition_kind_unknown``. Note: in 7B.1 the kind does
        not influence transition validity (Doctrine Lock G); future
        kind-specific rules will surface as
        ``lifecycle_transition_kind_state_combination_forbidden``.
    transition
        The named lifecycle transition. Must be a member of the canonical
        10-tuple :data:`TransitionName`. Out-of-set values return
        ``lifecycle_transition_name_unknown``. The transition name carries
        the action semantics (``submit`` vs. ``approve`` vs. ``reject``)
        that ``(from, to)`` alone does not capture — e.g. for ``withdraw``
        the same pair could be reached by ``reject`` if reject targeted
        ``withdrawn``.

    Returns
    -------
    LifecycleRefusalReason | None
        ``None`` if the transition is valid; otherwise the closed-enum
        reason naming the failure mode.
    """
    # 1. Kind validation. Python does not enforce Literal at runtime, so
    # the validator must runtime-check inputs. Closed-enum drift on
    # PackKind would be caught at the build-time multi-surface drift
    # detector test.
    if kind not in _KNOWN_KINDS:
        return "lifecycle_transition_kind_unknown"

    # 2. State validation (both endpoints). Same rationale as kind
    # validation.
    if from_state not in _KNOWN_STATES or to_state not in _KNOWN_STATES:
        return "lifecycle_transition_state_unknown"

    # 3. Transition-name validation. Same rationale as kind / state —
    # without this guard, an out-of-vocabulary transition (e.g. ``archive``)
    # would raise ``KeyError`` at the ``_VALID_TRANSITIONS[transition]``
    # lookup at step 6 (generic fallthrough), leaking an unstructured
    # exception past the closed-enum contract that downstream T3 storage
    # code (catching ``LifecycleTransitionRefused``) relies on. T2 R1 P2
    # added this guard + the matching closed-enum reason.
    if transition not in _KNOWN_TRANSITIONS:
        return "lifecycle_transition_name_unknown"

    # 4. Terminal-state guard. ``uninstalled`` has no outgoing edges per
    # ADR-012 §"Lifecycle states" — historical audit/evidence records are
    # never deleted (line 50). Precedence over per-transition reasons
    # because a caller targeting a transition FROM uninstalled is making a
    # different category of mistake than (e.g.) targeting "install" from a
    # non-allow_listed state.
    if from_state == "uninstalled":
        return "lifecycle_transition_terminal_state"

    # 5. Per-transition specific reasons. These provide better diagnostics
    # than the generic ``lifecycle_transition_invalid_state_pair`` fallthrough
    # for the most-common operator-mistake scenarios.
    if transition == "install" and from_state == "installed":
        return "lifecycle_transition_double_install"
    if transition == "revoke" and from_state == "revoked":
        return "lifecycle_transition_revoke_already_revoked"
    if transition == "uninstall" and from_state not in {"disabled", "revoked"}:
        return "lifecycle_transition_uninstall_not_revoked_or_disabled"
    if transition == "withdraw" and from_state not in {"submitted", "under_review"}:
        return "lifecycle_transition_withdraw_post_review"
    if transition == "approve" and from_state == "submitted":
        return "lifecycle_transition_approve_without_review_claim"
    if transition == "disable" and from_state != "installed":
        return "lifecycle_transition_disable_not_installed"
    if transition == "allow_list" and from_state != "approved":
        return "lifecycle_transition_allow_list_not_approved"

    # 6. Generic fallthrough — (from, to) not in the legal-pairs set for
    # this transition. The ``transition not in _KNOWN_TRANSITIONS`` guard
    # at step 3 makes this lookup KeyError-safe; by this point all
    # per-transition specific reasons have been exhausted, so any
    # remaining mismatch is an uncategorised invalid pair.
    legal_pairs = _VALID_TRANSITIONS[transition]
    if (from_state, to_state) not in legal_pairs:
        return "lifecycle_transition_invalid_state_pair"

    # 7. Valid transition.
    return None


__all__ = [
    "LifecycleRefusalReason",
    "PackKind",
    "PackState",
    "TransitionName",
    "validate_transition",
]
