"""Sprint 7B.3 T7 + T8 — :func:`compose_approval_gates` 5-gate composer
+ override-path helper tests (CRITICAL CONTROLS).

Per the plan-of-record
``docs/superpowers/plans/2026-05-13-sprint-7b3-reviewer-evidence-panels-5-gate.md``
§358-396, the composer is the substantive enforcement boundary for
ADR-012 §41's ``under_review → approved`` transition. It is a pure
function — no I/O, no DB, no time, no random — that assembles four
PRE-COMPUTED gate inputs (built by the T9 route handler) plus the
reviewer-acknowledgement request body into a frozen
:class:`ApprovalGateComposition`. T8 (§398-436) adds the override path:
``evaluate_override_decision`` + the canonical-safe ``composition_snapshot``
serialiser.

The module owns **10** wire-protocol-public closed-enum Literals — the
9 T7 composer Literals (pinned by Slice A) + the T8
``OverrideRefusalReason`` (pinned by Slice J).

Test slices:

- **Slice A** — closed-enum vocab drift detectors for the 9 T7 composer
  Literals (exact-set + count for each). The vocab IS the wire-protocol
  contract for the 412 ``ApproveRefusalResponse`` body.
- **Slice B** — frozen dataclass shape drift detectors (4 input
  dataclasses + 2 output dataclasses).
- **Slice C** — per-gate outcome pass-through for the 4 pre-computed
  gates: signature across its BINARY 2 outcomes (ADR-012 §110 — no
  ``evidence_not_attached``), evaluation / adversarial / owasp across
  all 3; signature ``evidence_pointer`` carries ``signature_digest``.
- **Slice D** — gate-5 ``reviewer_acknowledgement`` DERIVATION: the
  composer is the single owner of gate 5's outcome (the other 4 are
  pre-computed). All-four-True → green; any False / missing / non-True
  → red + ``reviewer_acknowledgement_incomplete`` (fail-closed).
- **Slice E** — composition aggregation: ``all_green`` and
  ``non_overridable_red_gates`` (the dynamic intersection of red gates
  with the ``{"signature"}`` policy set per R10 LOCK Flag #4).
- **Slice F** — ``pack_kind`` echoed unchanged; ``gates`` tuple in
  canonical ``_GATE_ORDER``.
- **Slice G** — determinism (same inputs → equal output) + frozen
  immutability.
- **Slice H** — ``_REVIEWER_ACK_KEYS`` drift detector against the
  portal :class:`ReviewerAcknowledgement` DTO field set (this test
  module MAY import portal; the domain composer MUST NOT — R11).
- **Slice I** — ``_NON_OVERRIDABLE_GATES`` pinned to
  ``frozenset({"signature"})`` per ADR-012 §110 + R10 LOCK Flag #4.
- **Slice J** (T8) — ``evaluate_override_decision``: the
  ``OverrideRefusalReason`` 4-value vocab drift detector + the 4 refusal
  branches + the allowed path + refusal precedence
  (``composition_already_all_green`` → ``non_overridable_red_gate`` →
  ``override_scope_not_held`` → ``override_reason_missing``) + the R12
  blocking-not-red ``evidence_not_attached``-overrideable case.
- **Slice K** (T8) — ``composition_snapshot``: the canonical-safe
  serialiser (``gates`` → list, ``non_overridable_red_gates`` → sorted
  list) + the load-bearing ``canonical_bytes``-survival test.
"""

from __future__ import annotations

import dataclasses
import typing

import pytest

from cognic_agentos.packs.approval_gates import (
    _GATE_ORDER as GATE_ORDER,
)
from cognic_agentos.packs.approval_gates import (
    _NON_OVERRIDABLE_GATES as NON_OVERRIDABLE_GATES,
)
from cognic_agentos.packs.approval_gates import (
    _REVIEWER_ACK_KEYS as REVIEWER_ACK_KEYS,
)
from cognic_agentos.packs.approval_gates import (
    AdversarialGateInput,
    AdversarialRedReason,
    ApprovalGateComposition,
    ApprovalGateName,
    ApprovalGateOutcome,
    ApprovalGateRedReason,
    ApprovalGateResult,
    EvaluationGateInput,
    EvaluationRedReason,
    OverrideDecision,
    OverrideRefusalReason,
    OwaspGateInput,
    OwaspRedReason,
    ReviewerAckRedReason,
    SignatureGateInput,
    SignatureGateOutcome,
    SignatureRedReason,
    compose_approval_gates,
    composition_snapshot,
    evaluate_override_decision,
)

# ---------------------------------------------------------------------------
# Shared fixtures — green pre-computed inputs for the 4 non-derived gates.
# A test that wants a red/evidence_not_attached gate replaces just that one.
# ---------------------------------------------------------------------------

_GREEN_SIGNATURE = SignatureGateInput(outcome="green", red_reason=None, signature_digest="a" * 64)
_GREEN_EVALUATION = EvaluationGateInput(
    outcome="green", red_reason=None, pass_rate=0.97, threshold=0.95
)
_GREEN_ADVERSARIAL = AdversarialGateInput(
    outcome="green", red_reason=None, pass_rate=1.0, high_severity_failures=0
)
_GREEN_OWASP = OwaspGateInput(outcome="green", red_reason=None, owasp_overall_status="green")
_FULL_ACK: dict[str, bool] = {
    "data_governance_acknowledged": True,
    "risk_tier_acknowledged": True,
    "supply_chain_acknowledged": True,
    "conformance_acknowledged": True,
}


def _compose(
    *,
    signature: SignatureGateInput = _GREEN_SIGNATURE,
    evaluation: EvaluationGateInput = _GREEN_EVALUATION,
    adversarial: AdversarialGateInput = _GREEN_ADVERSARIAL,
    owasp: OwaspGateInput = _GREEN_OWASP,
    pack_kind: str = "agent",
    acknowledgement: dict[str, bool] | None = None,
) -> ApprovalGateComposition:
    """Compose with all-green defaults; callers override one axis."""
    return compose_approval_gates(
        signature_input=signature,
        evaluation_input=evaluation,
        adversarial_input=adversarial,
        owasp_input=owasp,
        pack_kind=pack_kind,  # type: ignore[arg-type]
        reviewer_acknowledgement=_FULL_ACK if acknowledgement is None else acknowledgement,
    )


def _flatten_literal_union(union: object) -> frozenset[str]:
    """Flatten a ``Union[Literal[...], Literal[...], ...]`` to its value set.

    ``typing.get_args`` on a union of Literals returns the Literal types,
    not the string values — this helper unions the inner ``get_args`` of
    each member Literal.
    """
    members = typing.get_args(union)
    flat: set[str] = set()
    for member in members:
        flat.update(typing.get_args(member))
    return frozenset(flat)


# ---------------------------------------------------------------------------
# Slice A — closed-enum vocab drift detectors
# ---------------------------------------------------------------------------


class TestSprint7B3T7SliceAVocabDrift:
    """The 9 T7 composer closed-enum Literals ARE the wire-protocol
    contract for the 412 refusal body. Drift in either direction is a
    wire-protocol-public regression — pinned exact-set + count,
    independently, for crisp drift diagnosis. (The module's 10th
    wire-protocol-public Literal — the T8 ``OverrideRefusalReason`` — is
    pinned by Slice J, not here.)"""

    def test_approval_gate_name_exact_set(self) -> None:
        assert frozenset(typing.get_args(ApprovalGateName)) == frozenset(
            {
                "signature",
                "evaluation",
                "adversarial",
                "owasp_conformance",
                "reviewer_acknowledgement",
            }
        )

    def test_approval_gate_name_count(self) -> None:
        assert len(typing.get_args(ApprovalGateName)) == 5

    def test_approval_gate_outcome_exact_set(self) -> None:
        assert frozenset(typing.get_args(ApprovalGateOutcome)) == frozenset(
            {"green", "red", "evidence_not_attached"}
        )

    def test_approval_gate_outcome_count(self) -> None:
        assert len(typing.get_args(ApprovalGateOutcome)) == 3

    def test_signature_gate_outcome_is_binary(self) -> None:
        """ADR-012 §110 — the cosign trust gate is verified at approve
        time, never deferred. ``SignatureGateOutcome`` is BINARY
        (``green`` / ``red``); ``evidence_not_attached`` is an illegal
        signature state, made unrepresentable so it cannot evade
        ``non_overridable_red_gates`` tracking (reviewer P2)."""
        assert frozenset(typing.get_args(SignatureGateOutcome)) == frozenset({"green", "red"})

    def test_signature_gate_outcome_count_is_two(self) -> None:
        assert len(typing.get_args(SignatureGateOutcome)) == 2

    def test_signature_gate_outcome_excludes_evidence_not_attached(self) -> None:
        """Crisp negative — ``evidence_not_attached`` is NOT a legal
        signature outcome (it IS legal for gates 2-5 via
        ``ApprovalGateOutcome``)."""
        assert "evidence_not_attached" not in typing.get_args(SignatureGateOutcome)
        assert "evidence_not_attached" in typing.get_args(ApprovalGateOutcome)

    def test_signature_red_reason_exact_set(self) -> None:
        assert frozenset(typing.get_args(SignatureRedReason)) == frozenset(
            {
                "signature_attestation_missing",
                "signature_bundle_path_unreachable",
                "signature_verifier_not_configured",
                "signature_trust_root_not_configured",
                "signature_cosign_verify_failed",
                "signature_cosign_sig_not_in_attestation_paths",
                "signature_multiple_cosign_sig_entries_ambiguous",
                "signature_blob_path_not_declared_in_manifest",
                "signature_path_must_be_relative",
                "signature_blob_path_must_be_relative",
                "signature_signed_artefact_root_not_declared_at_submit",
                "signature_path_traversal_rejected",
                "signature_blob_path_traversal_rejected",
            }
        )

    def test_signature_red_reason_count_is_thirteen(self) -> None:
        """R7 P2 #1 folded the 8 resolver values into SignatureRedReason
        (5 original R5 + 8 resolver) → 13 total."""
        assert len(typing.get_args(SignatureRedReason)) == 13

    def test_evaluation_red_reason_exact_set(self) -> None:
        assert frozenset(typing.get_args(EvaluationRedReason)) == frozenset(
            {"evaluation_pass_rate_below_threshold", "evaluation_evidence_not_attached"}
        )

    def test_evaluation_red_reason_count(self) -> None:
        assert len(typing.get_args(EvaluationRedReason)) == 2

    def test_adversarial_red_reason_exact_set(self) -> None:
        assert frozenset(typing.get_args(AdversarialRedReason)) == frozenset(
            {
                "adversarial_corpus_pass_rate_below_threshold",
                "adversarial_high_severity_failure",
                "adversarial_evidence_not_attached",
            }
        )

    def test_adversarial_red_reason_count(self) -> None:
        assert len(typing.get_args(AdversarialRedReason)) == 3

    def test_owasp_red_reason_exact_set(self) -> None:
        assert frozenset(typing.get_args(OwaspRedReason)) == frozenset(
            {
                "owasp_conformance_red",
                "owasp_evidence_not_attached",
                "owasp_yellow_blocks_approval",
            }
        )

    def test_owasp_red_reason_count(self) -> None:
        assert len(typing.get_args(OwaspRedReason)) == 3

    def test_reviewer_ack_red_reason_exact_set(self) -> None:
        assert frozenset(typing.get_args(ReviewerAckRedReason)) == frozenset(
            {"reviewer_acknowledgement_incomplete"}
        )

    def test_reviewer_ack_red_reason_count(self) -> None:
        assert len(typing.get_args(ReviewerAckRedReason)) == 1

    def test_approval_gate_red_reason_union_is_22_values(self) -> None:
        """The consolidated union IS the wire-protocol-public refusal
        vocabulary — 13 sig + 2 eval + 3 adv + 3 owasp + 1 ack = 22."""
        assert len(_flatten_literal_union(ApprovalGateRedReason)) == 22

    def test_approval_gate_red_reason_union_is_disjoint(self) -> None:
        """No red-reason value appears in two per-gate Literals — the
        union has no collisions, so a 22-value flat set proves it."""
        per_gate_total = (
            len(typing.get_args(SignatureRedReason))
            + len(typing.get_args(EvaluationRedReason))
            + len(typing.get_args(AdversarialRedReason))
            + len(typing.get_args(OwaspRedReason))
            + len(typing.get_args(ReviewerAckRedReason))
        )
        assert per_gate_total == 22
        assert len(_flatten_literal_union(ApprovalGateRedReason)) == per_gate_total


# ---------------------------------------------------------------------------
# Slice B — frozen dataclass shape drift detectors
# ---------------------------------------------------------------------------


class TestSprint7B3T7SliceBDataclassShapes:
    """The 4 input dataclasses + 2 output dataclasses are the data-layer
    contract between the T9 route handler and the composer. Field-set
    drift breaks the wiring silently — pinned here."""

    def test_signature_gate_input_field_set(self) -> None:
        assert {f.name for f in dataclasses.fields(SignatureGateInput)} == {
            "outcome",
            "red_reason",
            "signature_digest",
        }

    def test_evaluation_gate_input_field_set(self) -> None:
        assert {f.name for f in dataclasses.fields(EvaluationGateInput)} == {
            "outcome",
            "red_reason",
            "pass_rate",
            "threshold",
        }

    def test_adversarial_gate_input_field_set(self) -> None:
        assert {f.name for f in dataclasses.fields(AdversarialGateInput)} == {
            "outcome",
            "red_reason",
            "pass_rate",
            "high_severity_failures",
        }

    def test_owasp_gate_input_field_set(self) -> None:
        assert {f.name for f in dataclasses.fields(OwaspGateInput)} == {
            "outcome",
            "red_reason",
            "owasp_overall_status",
        }

    def test_approval_gate_result_field_set(self) -> None:
        assert {f.name for f in dataclasses.fields(ApprovalGateResult)} == {
            "gate",
            "outcome",
            "red_reason",
            "evidence_pointer",
        }

    def test_approval_gate_composition_field_set(self) -> None:
        assert {f.name for f in dataclasses.fields(ApprovalGateComposition)} == {
            "pack_kind",
            "gates",
            "all_green",
            "non_overridable_red_gates",
        }

    def test_input_dataclasses_are_frozen(self) -> None:
        """Behavioural frozen check on the 4 pre-computed input
        dataclasses — attempting to mutate any field raises
        ``FrozenInstanceError``. (The 2 output dataclasses get their
        own behavioural frozen checks in Slice G.)"""
        for instance in (
            _GREEN_SIGNATURE,
            _GREEN_EVALUATION,
            _GREEN_ADVERSARIAL,
            _GREEN_OWASP,
        ):
            with pytest.raises(dataclasses.FrozenInstanceError):
                instance.outcome = "red"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Slice C — per-gate pre-computed-outcome pass-through
# ---------------------------------------------------------------------------


def _gate(composition: ApprovalGateComposition, name: str) -> ApprovalGateResult:
    """Look up one gate result by name from a composition."""
    matches = [g for g in composition.gates if g.gate == name]
    assert len(matches) == 1, f"expected exactly one {name!r} gate, got {len(matches)}"
    return matches[0]


class TestSprint7B3T7SliceCSignatureGate:
    """Signature gate outcome + red_reason are PRE-COMPUTED by the route
    handler; the composer copies them verbatim. ``evidence_pointer``
    carries ``signature_digest`` per plan §382."""

    def test_green_signature_passes_through(self) -> None:
        comp = _compose(signature=_GREEN_SIGNATURE)
        sig = _gate(comp, "signature")
        assert sig.outcome == "green"
        assert sig.red_reason is None
        assert sig.evidence_pointer == "a" * 64

    def test_red_signature_passes_through_with_reason(self) -> None:
        comp = _compose(
            signature=SignatureGateInput(
                outcome="red",
                red_reason="signature_cosign_verify_failed",
                signature_digest=None,
            )
        )
        sig = _gate(comp, "signature")
        assert sig.outcome == "red"
        assert sig.red_reason == "signature_cosign_verify_failed"
        assert sig.evidence_pointer is None

    # NOTE: there is deliberately no ``evidence_not_attached`` signature
    # pass-through test — ADR-012 §110 makes that an illegal signature
    # state, made unrepresentable by the binary ``SignatureGateOutcome``
    # (see ``TestSprint7B3T7SliceAVocabDrift.test_signature_gate_outcome_is_binary``).

    def test_signature_digest_is_the_evidence_pointer(self) -> None:
        comp = _compose(
            signature=SignatureGateInput(
                outcome="green", red_reason=None, signature_digest="deadbeef"
            )
        )
        assert _gate(comp, "signature").evidence_pointer == "deadbeef"


class TestSprint7B3T7SliceCEvaluationGate:
    def test_green_evaluation_passes_through(self) -> None:
        ev = _gate(_compose(evaluation=_GREEN_EVALUATION), "evaluation")
        assert ev.outcome == "green"
        assert ev.red_reason is None

    def test_red_evaluation_passes_through(self) -> None:
        comp = _compose(
            evaluation=EvaluationGateInput(
                outcome="red",
                red_reason="evaluation_pass_rate_below_threshold",
                pass_rate=0.80,
                threshold=0.95,
            )
        )
        ev = _gate(comp, "evaluation")
        assert ev.outcome == "red"
        assert ev.red_reason == "evaluation_pass_rate_below_threshold"

    def test_evidence_not_attached_evaluation_passes_through(self) -> None:
        comp = _compose(
            evaluation=EvaluationGateInput(
                outcome="evidence_not_attached",
                red_reason="evaluation_evidence_not_attached",
                pass_rate=None,
                threshold=None,
            )
        )
        ev = _gate(comp, "evaluation")
        assert ev.outcome == "evidence_not_attached"
        assert ev.red_reason == "evaluation_evidence_not_attached"


class TestSprint7B3T7SliceCAdversarialGate:
    def test_green_adversarial_passes_through(self) -> None:
        adv = _gate(_compose(adversarial=_GREEN_ADVERSARIAL), "adversarial")
        assert adv.outcome == "green"
        assert adv.red_reason is None

    def test_red_adversarial_high_severity_passes_through(self) -> None:
        comp = _compose(
            adversarial=AdversarialGateInput(
                outcome="red",
                red_reason="adversarial_high_severity_failure",
                pass_rate=0.99,
                high_severity_failures=2,
            )
        )
        adv = _gate(comp, "adversarial")
        assert adv.outcome == "red"
        assert adv.red_reason == "adversarial_high_severity_failure"

    def test_evidence_not_attached_adversarial_passes_through(self) -> None:
        comp = _compose(
            adversarial=AdversarialGateInput(
                outcome="evidence_not_attached",
                red_reason="adversarial_evidence_not_attached",
                pass_rate=None,
                high_severity_failures=0,
            )
        )
        adv = _gate(comp, "adversarial")
        assert adv.outcome == "evidence_not_attached"
        assert adv.red_reason == "adversarial_evidence_not_attached"


class TestSprint7B3T7SliceCOwaspGate:
    def test_green_owasp_passes_through(self) -> None:
        ow = _gate(_compose(owasp=_GREEN_OWASP), "owasp_conformance")
        assert ow.outcome == "green"
        assert ow.red_reason is None

    def test_red_owasp_passes_through(self) -> None:
        comp = _compose(
            owasp=OwaspGateInput(
                outcome="red",
                red_reason="owasp_conformance_red",
                owasp_overall_status="red",
            )
        )
        ow = _gate(comp, "owasp_conformance")
        assert ow.outcome == "red"
        assert ow.red_reason == "owasp_conformance_red"

    def test_yellow_blocks_approval_owasp_passes_through(self) -> None:
        """R10 LOCK Flag #2 — yellow verdict → red. The route handler
        pre-computes the mapping; the composer copies it verbatim."""
        comp = _compose(
            owasp=OwaspGateInput(
                outcome="red",
                red_reason="owasp_yellow_blocks_approval",
                owasp_overall_status="yellow",
            )
        )
        ow = _gate(comp, "owasp_conformance")
        assert ow.outcome == "red"
        assert ow.red_reason == "owasp_yellow_blocks_approval"

    def test_evidence_not_attached_owasp_passes_through(self) -> None:
        comp = _compose(
            owasp=OwaspGateInput(
                outcome="evidence_not_attached",
                red_reason="owasp_evidence_not_attached",
                owasp_overall_status=None,
            )
        )
        ow = _gate(comp, "owasp_conformance")
        assert ow.outcome == "evidence_not_attached"
        assert ow.red_reason == "owasp_evidence_not_attached"


# ---------------------------------------------------------------------------
# Slice D — gate-5 reviewer_acknowledgement DERIVATION
# ---------------------------------------------------------------------------


class TestSprint7B3T7SliceDReviewerAckDerivation:
    """Gate 5 is the ONLY gate the composer derives — the other 4 are
    pre-computed. All-four-True → green; anything else → fail-closed
    red + ``reviewer_acknowledgement_incomplete``."""

    def test_all_four_acknowledged_is_green(self) -> None:
        ack = _gate(_compose(acknowledgement=_FULL_ACK), "reviewer_acknowledgement")
        assert ack.outcome == "green"
        assert ack.red_reason is None
        assert ack.evidence_pointer is None

    @pytest.mark.parametrize(
        "missing_key",
        [
            "data_governance_acknowledged",
            "risk_tier_acknowledged",
            "supply_chain_acknowledged",
            "conformance_acknowledged",
        ],
    )
    def test_one_panel_false_is_red_incomplete(self, missing_key: str) -> None:
        ack_dict = dict(_FULL_ACK)
        ack_dict[missing_key] = False
        ack = _gate(_compose(acknowledgement=ack_dict), "reviewer_acknowledgement")
        assert ack.outcome == "red"
        assert ack.red_reason == "reviewer_acknowledgement_incomplete"

    def test_all_false_is_red_incomplete(self) -> None:
        ack = _gate(
            _compose(acknowledgement={k: False for k in _FULL_ACK}),
            "reviewer_acknowledgement",
        )
        assert ack.outcome == "red"
        assert ack.red_reason == "reviewer_acknowledgement_incomplete"

    def test_empty_dict_is_red_incomplete(self) -> None:
        """Fail-closed: a missing key reads as not-acknowledged."""
        ack = _gate(_compose(acknowledgement={}), "reviewer_acknowledgement")
        assert ack.outcome == "red"
        assert ack.red_reason == "reviewer_acknowledgement_incomplete"

    @pytest.mark.parametrize("dropped", list(_FULL_ACK))
    def test_one_key_absent_is_red_incomplete(self, dropped: str) -> None:
        """A dict missing one of the 4 keys (the other 3 True) is still
        incomplete — the composer reads the 4 KNOWN keys, not whatever
        keys happen to be present."""
        ack_dict = {k: True for k in _FULL_ACK if k != dropped}
        ack = _gate(_compose(acknowledgement=ack_dict), "reviewer_acknowledgement")
        assert ack.outcome == "red"
        assert ack.red_reason == "reviewer_acknowledgement_incomplete"

    def test_extra_keys_are_ignored(self) -> None:
        """Extra keys beyond the 4 known panels do not affect the
        verdict — the composer reads only the 4 known keys."""
        ack_dict = dict(_FULL_ACK)
        ack_dict["smuggled_fifth_panel"] = False
        ack = _gate(_compose(acknowledgement=ack_dict), "reviewer_acknowledgement")
        assert ack.outcome == "green"

    @pytest.mark.parametrize("truthy_non_true", [1, "true", "yes"])
    def test_truthy_non_true_value_is_fail_closed_red(self, truthy_non_true: object) -> None:
        """Fail-closed: only the literal ``True`` counts as acknowledged.
        A truthy-but-not-True smuggled value (int 1, string) does NOT
        satisfy the gate."""
        ack_dict: dict[str, object] = dict(_FULL_ACK)
        ack_dict["conformance_acknowledged"] = truthy_non_true
        ack = _gate(
            _compose(acknowledgement=ack_dict),  # type: ignore[arg-type]
            "reviewer_acknowledgement",
        )
        assert ack.outcome == "red"
        assert ack.red_reason == "reviewer_acknowledgement_incomplete"


# ---------------------------------------------------------------------------
# Slice E — composition aggregation (all_green + non_overridable_red_gates)
# ---------------------------------------------------------------------------


class TestSprint7B3T7SliceEAggregation:
    def test_all_five_green_is_all_green_true(self) -> None:
        comp = _compose()
        assert comp.all_green is True
        assert comp.non_overridable_red_gates == frozenset()

    def test_any_red_gate_makes_all_green_false(self) -> None:
        comp = _compose(
            evaluation=EvaluationGateInput(
                outcome="red",
                red_reason="evaluation_pass_rate_below_threshold",
                pass_rate=0.5,
                threshold=0.95,
            )
        )
        assert comp.all_green is False

    def test_evidence_not_attached_gate_makes_all_green_false(self) -> None:
        """``evidence_not_attached`` is NOT green — it blocks approval
        just like red (the green path requires every gate green)."""
        comp = _compose(
            adversarial=AdversarialGateInput(
                outcome="evidence_not_attached",
                red_reason="adversarial_evidence_not_attached",
                pass_rate=None,
                high_severity_failures=0,
            )
        )
        assert comp.all_green is False

    def test_red_acknowledgement_makes_all_green_false(self) -> None:
        comp = _compose(acknowledgement={k: False for k in _FULL_ACK})
        assert comp.all_green is False

    def test_red_signature_populates_non_overridable_red_gates(self) -> None:
        """Signature is the ONLY non-overridable gate per ADR-012 §110 /
        R10 LOCK Flag #4 — a red signature surfaces in
        ``non_overridable_red_gates`` so T8's override path can refuse."""
        comp = _compose(
            signature=SignatureGateInput(
                outcome="red",
                red_reason="signature_cosign_verify_failed",
                signature_digest=None,
            )
        )
        assert comp.non_overridable_red_gates == frozenset({"signature"})
        assert comp.all_green is False

    def test_red_non_signature_gates_do_not_populate_non_overridable(self) -> None:
        """A red evaluation / adversarial / owasp / reviewer_ack gate is
        OVERRIDABLE — it stays out of ``non_overridable_red_gates``."""
        comp = _compose(
            evaluation=EvaluationGateInput(
                outcome="red",
                red_reason="evaluation_pass_rate_below_threshold",
                pass_rate=0.1,
                threshold=0.95,
            ),
            owasp=OwaspGateInput(
                outcome="red",
                red_reason="owasp_yellow_blocks_approval",
                owasp_overall_status="yellow",
            ),
            acknowledgement={k: False for k in _FULL_ACK},
        )
        assert comp.non_overridable_red_gates == frozenset()
        assert comp.all_green is False

    def test_binary_signature_outcome_makes_non_overridable_complete(self) -> None:
        """ADR-012 §110 — EVERY non-green signature state must surface in
        ``non_overridable_red_gates`` so the T8 override path cannot
        bypass the cosign gate. Because ``SignatureGateOutcome`` is
        binary (no ``evidence_not_attached``), "non-green signature" ==
        "red signature", and a red signature ALWAYS populates the set.
        This is the replacement for the deleted test that blessed an
        overridable ``evidence_not_attached`` signature (reviewer P2)."""
        # The type-level guarantee: signature has exactly 2 outcomes.
        assert frozenset(typing.get_args(SignatureGateOutcome)) == frozenset({"green", "red"})
        # The only non-green signature outcome (red) lands in the set.
        red_sig = _compose(
            signature=SignatureGateInput(
                outcome="red",
                red_reason="signature_attestation_missing",
                signature_digest=None,
            )
        )
        assert red_sig.non_overridable_red_gates == frozenset({"signature"})
        # The green signature outcome does not.
        assert _compose().non_overridable_red_gates == frozenset()


# ---------------------------------------------------------------------------
# Slice F — pack_kind echo + gate order
# ---------------------------------------------------------------------------


class TestSprint7B3T7SliceFPackKindAndOrder:
    @pytest.mark.parametrize("kind", ["tool", "skill", "agent", "hook"])
    def test_pack_kind_echoed_unchanged(self, kind: str) -> None:
        """R9 — ``pack_kind`` is wire-visible; carried through verbatim
        from the route handler's authoritative ``PackRecord.kind``. It
        does NOT change gate weighting in 7B.3."""
        comp = _compose(pack_kind=kind)
        assert comp.pack_kind == kind

    def test_gates_tuple_in_canonical_order(self) -> None:
        comp = _compose()
        assert tuple(g.gate for g in comp.gates) == GATE_ORDER

    def test_gate_order_matches_approval_gate_name_literal(self) -> None:
        """``_GATE_ORDER`` is a permutation-free 1:1 with the
        ``ApprovalGateName`` Literal — drift detector."""
        assert frozenset(GATE_ORDER) == frozenset(typing.get_args(ApprovalGateName))
        assert len(GATE_ORDER) == 5

    def test_composition_has_exactly_five_gates(self) -> None:
        assert len(_compose().gates) == 5


# ---------------------------------------------------------------------------
# Slice G — determinism + immutability
# ---------------------------------------------------------------------------


class TestSprint7B3T7SliceGDeterminismAndImmutability:
    def test_same_inputs_produce_equal_compositions(self) -> None:
        """Pure-functional: no time / random / I/O. Same inputs twice →
        equal frozen output."""
        first = _compose()
        second = _compose()
        assert first == second

    def test_distinct_inputs_produce_distinct_compositions(self) -> None:
        green = _compose()
        red = _compose(acknowledgement={k: False for k in _FULL_ACK})
        assert green != red

    def test_composition_is_frozen(self) -> None:
        comp = _compose()
        with pytest.raises(dataclasses.FrozenInstanceError):
            comp.all_green = False  # type: ignore[misc]

    def test_gate_result_is_frozen(self) -> None:
        comp = _compose()
        with pytest.raises(dataclasses.FrozenInstanceError):
            comp.gates[0].outcome = "red"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Slice H — _REVIEWER_ACK_KEYS drift detector vs the portal DTO
# ---------------------------------------------------------------------------


class TestSprint7B3T7SliceHReviewerAckKeyDrift:
    """``_REVIEWER_ACK_KEYS`` is the domain-side mirror of the portal
    :class:`ReviewerAcknowledgement` DTO's 4 boolean field names. The
    domain composer MUST NOT import portal (R11 architectural-arrow
    invariant), so the names are string-coupled — this drift detector
    (which MAY import portal) pins them in lockstep."""

    def test_reviewer_ack_keys_match_portal_dto_field_set(self) -> None:
        from cognic_agentos.portal.api.packs.dto import ReviewerAcknowledgement

        assert frozenset(REVIEWER_ACK_KEYS) == frozenset(
            ReviewerAcknowledgement.model_fields.keys()
        )

    def test_reviewer_ack_keys_count_is_four(self) -> None:
        assert len(REVIEWER_ACK_KEYS) == 4

    def test_reviewer_ack_keys_exact_set(self) -> None:
        assert frozenset(REVIEWER_ACK_KEYS) == frozenset(
            {
                "data_governance_acknowledged",
                "risk_tier_acknowledged",
                "supply_chain_acknowledged",
                "conformance_acknowledged",
            }
        )

    def test_composer_does_not_import_portal(self) -> None:
        """AST scan — the domain composer module MUST NOT import
        ``portal`` (the R11 architectural-arrow invariant; the reason
        the composer takes a ``dict`` rather than the
        ``ReviewerAcknowledgement`` portal DTO)."""
        import ast
        import pathlib

        import cognic_agentos.packs.approval_gates as mod

        source = pathlib.Path(mod.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        offending: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                offending.extend(alias.name for alias in node.names if "portal" in alias.name)
            elif (
                isinstance(node, ast.ImportFrom)
                and node.module is not None
                and "portal" in node.module
            ):
                offending.append(node.module)
        assert offending == [], f"composer imports portal: {offending}"


# ---------------------------------------------------------------------------
# Slice I — _NON_OVERRIDABLE_GATES policy lock
# ---------------------------------------------------------------------------


class TestSprint7B3T7SliceINonOverridablePolicy:
    """``_NON_OVERRIDABLE_GATES`` is the ADR-012 §110 / R10 LOCK Flag #4
    policy constant — cosign signature is the SINGLE non-overridable
    gate. Drift here changes which gates the T8 override path can
    bypass — a governance-doctrine regression."""

    def test_non_overridable_gates_is_signature_only(self) -> None:
        assert frozenset({"signature"}) == NON_OVERRIDABLE_GATES

    def test_non_overridable_gates_is_a_subset_of_gate_names(self) -> None:
        assert frozenset(typing.get_args(ApprovalGateName)) >= NON_OVERRIDABLE_GATES


# ---------------------------------------------------------------------------
# Slice J — T8 evaluate_override_decision (the override-aware composer helper)
# ---------------------------------------------------------------------------

# A blocking-but-overrideable composition: gate 2 (evaluation) is
# ``evidence_not_attached`` — non-green/blocking, zero ``red`` gates,
# ``non_overridable_red_gates`` empty. This is the EXPECTED pre-Sprint-11
# state for gates 2/3 (R12 blocking-not-red doctrine).
_EVIDENCE_NOT_ATTACHED_EVALUATION = EvaluationGateInput(
    outcome="evidence_not_attached",
    red_reason="evaluation_evidence_not_attached",
    pass_rate=None,
    threshold=None,
)
_EVIDENCE_NOT_ATTACHED_ADVERSARIAL = AdversarialGateInput(
    outcome="evidence_not_attached",
    red_reason="adversarial_evidence_not_attached",
    pass_rate=None,
    high_severity_failures=0,
)
# A red-signature composition: gate 1 is ``red`` → ``signature`` lands in
# ``non_overridable_red_gates`` → override path MUST refuse (ADR-012 §110).
_RED_SIGNATURE = SignatureGateInput(
    outcome="red",
    red_reason="signature_cosign_verify_failed",
    signature_digest=None,
)


class TestSprint7B3T8SliceJEvaluateOverrideDecision:
    """``evaluate_override_decision`` — the pure-functional override-aware
    helper consumed by the T9 approve endpoint's override path. Refusal
    precedence (most-fundamental blocker first):
    ``composition_already_all_green`` → ``non_overridable_red_gate`` →
    ``override_scope_not_held`` → ``override_reason_missing``."""

    def test_override_refusal_reason_exact_set(self) -> None:
        """Closed-enum 4-value vocabulary — wire-protocol-public for the
        412 refusal body's override-path branch."""
        assert frozenset(typing.get_args(OverrideRefusalReason)) == frozenset(
            {
                "composition_already_all_green",
                "override_scope_not_held",
                "override_reason_missing",
                "non_overridable_red_gate",
            }
        )

    def test_override_refusal_reason_count_is_four(self) -> None:
        assert len(typing.get_args(OverrideRefusalReason)) == 4

    def test_blocking_composition_with_scope_and_reason_is_allowed(self) -> None:
        """Not-all-green + no non-overridable red + scope held + reason
        given → override allowed."""
        comp = _compose(evaluation=_EVIDENCE_NOT_ATTACHED_EVALUATION)
        decision = evaluate_override_decision(
            composition=comp,
            override_scope_held=True,
            override_reason="security_exception",
        )
        assert decision == OverrideDecision(allowed=True, refusal_reason=None)

    def test_evidence_not_attached_only_composition_is_overrideable(self) -> None:
        """R12 blocking-not-red — a composition whose ONLY non-green gates
        are ``evidence_not_attached`` (zero ``red``, ``non_overridable_red_gates``
        empty) IS overrideable; it is not stranded with no override path."""
        comp = _compose(
            evaluation=_EVIDENCE_NOT_ATTACHED_EVALUATION,
            adversarial=_EVIDENCE_NOT_ATTACHED_ADVERSARIAL,
        )
        assert comp.all_green is False
        assert comp.non_overridable_red_gates == frozenset()
        decision = evaluate_override_decision(
            composition=comp,
            override_scope_held=True,
            override_reason="prerelease_validation",
        )
        assert decision.allowed is True
        assert decision.refusal_reason is None

    def test_all_green_composition_refused_already_all_green(self) -> None:
        """An all-green composition has nothing to override — refused even
        with scope + reason."""
        decision = evaluate_override_decision(
            composition=_compose(),
            override_scope_held=True,
            override_reason="other",
        )
        assert decision == OverrideDecision(
            allowed=False, refusal_reason="composition_already_all_green"
        )

    def test_red_signature_refused_non_overridable(self) -> None:
        """A red signature gate populates ``non_overridable_red_gates`` —
        ADR-012 §110 makes it absolutely non-overridable; refused even
        with scope + reason."""
        comp = _compose(signature=_RED_SIGNATURE)
        assert comp.non_overridable_red_gates == frozenset({"signature"})
        decision = evaluate_override_decision(
            composition=comp,
            override_scope_held=True,
            override_reason="security_exception",
        )
        assert decision == OverrideDecision(
            allowed=False, refusal_reason="non_overridable_red_gate"
        )

    def test_blocking_composition_without_scope_refused_scope_not_held(self) -> None:
        comp = _compose(evaluation=_EVIDENCE_NOT_ATTACHED_EVALUATION)
        decision = evaluate_override_decision(
            composition=comp,
            override_scope_held=False,
            override_reason="security_exception",
        )
        assert decision == OverrideDecision(allowed=False, refusal_reason="override_scope_not_held")

    def test_blocking_composition_without_reason_refused_reason_missing(self) -> None:
        comp = _compose(evaluation=_EVIDENCE_NOT_ATTACHED_EVALUATION)
        decision = evaluate_override_decision(
            composition=comp,
            override_scope_held=True,
            override_reason=None,
        )
        assert decision == OverrideDecision(allowed=False, refusal_reason="override_reason_missing")

    def test_precedence_all_green_beats_scope_not_held(self) -> None:
        """An all-green composition is refused ``composition_already_all_green``
        even when scope is ALSO not held — the no-op precondition is the
        most fundamental blocker."""
        decision = evaluate_override_decision(
            composition=_compose(),
            override_scope_held=False,
            override_reason=None,
        )
        assert decision.refusal_reason == "composition_already_all_green"

    def test_precedence_non_overridable_beats_scope_not_held(self) -> None:
        """A red signature is refused ``non_overridable_red_gate`` even
        when scope is ALSO not held — the ADR-012 §110 absolute stop wins
        over the authority check (no override is possible here, period)."""
        decision = evaluate_override_decision(
            composition=_compose(signature=_RED_SIGNATURE),
            override_scope_held=False,
            override_reason=None,
        )
        assert decision.refusal_reason == "non_overridable_red_gate"

    def test_precedence_scope_not_held_beats_reason_missing(self) -> None:
        """An overrideable composition with neither scope nor reason is
        refused ``override_scope_not_held`` — authority is checked before
        the categorised-reason requirement."""
        comp = _compose(evaluation=_EVIDENCE_NOT_ATTACHED_EVALUATION)
        decision = evaluate_override_decision(
            composition=comp,
            override_scope_held=False,
            override_reason=None,
        )
        assert decision.refusal_reason == "override_scope_not_held"

    def test_override_decision_is_frozen(self) -> None:
        decision = evaluate_override_decision(
            composition=_compose(),
            override_scope_held=True,
            override_reason="other",
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            decision.allowed = True  # type: ignore[misc]

    def test_evaluate_override_decision_is_deterministic(self) -> None:
        comp = _compose(evaluation=_EVIDENCE_NOT_ATTACHED_EVALUATION)
        first = evaluate_override_decision(
            composition=comp, override_scope_held=True, override_reason="security_exception"
        )
        second = evaluate_override_decision(
            composition=comp, override_scope_held=True, override_reason="security_exception"
        )
        assert first == second


# ---------------------------------------------------------------------------
# Slice K — T8 composition_snapshot (canonical-safe serialiser)
# ---------------------------------------------------------------------------


class TestSprint7B3T8SliceKCompositionSnapshot:
    """``composition_snapshot`` converts the frozen ``ApprovalGateComposition``
    (a ``@dataclasses.dataclass`` with a ``tuple`` ``gates`` field + a
    ``frozenset`` ``non_overridable_red_gates`` field) into a canonical-safe
    ``dict`` — ``core.canonical.canonical_bytes`` REJECTS tuples and has no
    rule for frozensets, so a raw ``dataclasses.asdict`` would fail the
    override-event chain insert. Mirrors the load-bearing tuple→list fix at
    ``packs/conformance/runner.py``."""

    def test_snapshot_gates_is_list_not_tuple(self) -> None:
        snap = composition_snapshot(_compose())
        assert isinstance(snap["gates"], list)
        assert not isinstance(snap["gates"], tuple)

    def test_snapshot_non_overridable_red_gates_is_sorted_list(self) -> None:
        snap = composition_snapshot(_compose(signature=_RED_SIGNATURE))
        value = snap["non_overridable_red_gates"]
        assert isinstance(value, list)
        assert value == sorted(value)
        assert value == ["signature"]

    def test_snapshot_empty_non_overridable_red_gates_is_empty_list(self) -> None:
        snap = composition_snapshot(_compose())
        assert snap["non_overridable_red_gates"] == []

    def test_snapshot_survives_canonical_bytes(self) -> None:
        """THE load-bearing test — the snapshot of a realistic composition
        (red signature + evidence_not_attached gates) must pass through
        ``canonical_bytes`` without the tuple/frozenset ``TypeError`` that
        a raw ``dataclasses.asdict`` would trigger."""
        from cognic_agentos.core.canonical import canonical_bytes

        comp = _compose(
            signature=_RED_SIGNATURE,
            adversarial=_EVIDENCE_NOT_ATTACHED_ADVERSARIAL,
        )
        snap = composition_snapshot(comp)
        # Wrapped in a dict mirroring the override-event chain payload.
        canonical_bytes({"gate_composition_snapshot": snap})

    def test_snapshot_preserves_gate_order(self) -> None:
        snap = composition_snapshot(_compose())
        assert [g["gate"] for g in snap["gates"]] == list(GATE_ORDER)

    def test_snapshot_round_trips_every_gate_field(self) -> None:
        comp = _compose(signature=_RED_SIGNATURE)
        snap = composition_snapshot(comp)
        for result, gate_dict in zip(comp.gates, snap["gates"], strict=True):
            assert gate_dict == {
                "gate": result.gate,
                "outcome": result.outcome,
                "red_reason": result.red_reason,
                "evidence_pointer": result.evidence_pointer,
            }

    def test_snapshot_includes_top_level_fields(self) -> None:
        comp = _compose(pack_kind="tool")
        snap = composition_snapshot(comp)
        assert snap["pack_kind"] == "tool"
        assert snap["all_green"] is True

    def test_snapshot_is_deterministic(self) -> None:
        comp = _compose(signature=_RED_SIGNATURE)
        assert composition_snapshot(comp) == composition_snapshot(comp)
