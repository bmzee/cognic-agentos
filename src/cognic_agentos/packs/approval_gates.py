"""Sprint 7B.3 T7 — ADR-012 §41 five-gate approval composer
(CRITICAL CONTROLS).

Per the plan-of-record
``docs/superpowers/plans/2026-05-13-sprint-7b3-reviewer-evidence-panels-5-gate.md``
§358-396, this module ships :func:`compose_approval_gates` — the
substantive enforcement boundary for the ``under_review → approved``
lifecycle transition. The composer decides whether a separately
shipped plugin pack (``agent`` / ``tool`` / ``skill`` / ``hook``) is
trusted enough to be approved, against the 5 orthogonal ADR-012 §41
gates:

1. ``signature`` — cosign signature verification (ADR-016).
2. ``evaluation`` — ADR-010 evaluation-harness pass-rate threshold.
3. ``adversarial`` — ADR-011 adversarial-corpus pass-rate + zero
   high-severity failures.
4. ``owasp_conformance`` — the 7B.2 OWASP agentic conformance verdict.
5. ``reviewer_acknowledgement`` — server-side panel-ack; all 4 reviewer
   evidence panels (T3-T6) explicitly acknowledged.

**Pure-functional — no I/O, no DB, no time, no random.** The composer
is a pure function with NO ``TrustGate`` / ``DecisionHistoryStore`` /
``PackRecordStore`` parameters. The T9 route handler owns the wiring
(TrustGate construction, manifest path resolution, lifecycle-history
fetch); it PRE-COMPUTES each of the first 4 gate inputs and passes
them in. This keeps the composer testable without I/O fixtures and
locks the gate-state contract at the data layer (R1 P2 #3).

**Gate 5 is the single DERIVED gate.** Gates 1-4 arrive pre-computed
in their ``*GateInput`` dataclasses; the composer copies their
``outcome`` + ``red_reason`` verbatim. Gate 5
(``reviewer_acknowledgement``) is the ONE gate the composer itself
decides — from the request-body acknowledgement dict. All four panel
booleans must be exactly ``True`` (fail-closed: a missing key, a
``False``, or a truthy-but-not-``True`` value all read as
not-acknowledged → ``reviewer_acknowledgement_incomplete``).

**Architectural-arrow invariant (R11).** This module lives in
``packs/`` (domain) and MUST NOT import ``portal/``. The reviewer-
acknowledgement input is the ``model_dump()`` wire shape
``dict[str, bool]`` — NOT the portal :class:`ReviewerAcknowledgement`
DTO. The 4 expected ack keys are mirrored here as
:data:`_REVIEWER_ACK_KEYS` (string-coupled, not import-coupled); the
drift detector at ``tests/unit/packs/test_approval_gates.py::
TestSprint7B3T7SliceHReviewerAckKeyDrift`` (which MAY import portal)
pins them in lockstep against ``ReviewerAcknowledgement.model_fields``.

**Override path (Sprint 7B.3 T8).** Alongside the T7 composer this
module also ships :func:`evaluate_override_decision` — the pure-
functional override-aware helper the T9 approve endpoint's override
path consumes — and :func:`composition_snapshot` — the canonical-safe
serialiser that converts the frozen :class:`ApprovalGateComposition`
(``tuple`` ``gates`` + ``frozenset`` ``non_overridable_red_gates``)
into a ``dict`` the override-event chain payload can carry past
``core.canonical.canonical_bytes`` (which rejects tuples and has no
frozenset rule). :data:`_NON_OVERRIDABLE_GATES` (= ``{"signature"}``
per ADR-012 §110 + R10 LOCK Flag #4 — cosign signature is the single
non-overridable gate) drives the override helper's
``non_overridable_red_gate`` refusal via
:attr:`ApprovalGateComposition.non_overridable_red_gates`.

**Closed-enum vocabulary IS the wire-protocol contract.** The module
owns **10** wire-protocol-public closed-enum Literals. The 9 in the
closed-enum block immediately below (5 per-gate red-reason Literals +
the consolidated :data:`ApprovalGateRedReason` union +
:data:`ApprovalGateName` + :data:`ApprovalGateOutcome` + the binary
:data:`SignatureGateOutcome`) are pinned by the Slice-A drift
detectors; the 10th — :data:`OverrideRefusalReason` (T8, in the
override-path section at the foot of the module) — is pinned by the
Slice-J drift detector. All 10 render into the 412
``ApproveRefusalResponse`` body the T9 endpoint returns; drift in
either direction is a wire-protocol-public regression class.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Literal

from cognic_agentos.packs.approval_types import ApprovalOverrideReason
from cognic_agentos.packs.conformance.checks import ConformanceOverallStatus
from cognic_agentos.packs.lifecycle import PackKind

__all__ = [
    "AdversarialGateInput",
    "AdversarialRedReason",
    "ApprovalGateComposition",
    "ApprovalGateName",
    "ApprovalGateOutcome",
    "ApprovalGateRedReason",
    "ApprovalGateResult",
    "EvaluationGateInput",
    "EvaluationRedReason",
    "OverrideDecision",
    "OverrideRefusalReason",
    "OwaspGateInput",
    "OwaspRedReason",
    "ReviewerAckRedReason",
    "SignatureGateInput",
    "SignatureGateOutcome",
    "SignatureRedReason",
    "compose_approval_gates",
    "composition_snapshot",
    "evaluate_override_decision",
]


# ---------------------------------------------------------------------------
# Closed-enum vocabularies — wire-protocol-public per ADR-012 §41.
# ---------------------------------------------------------------------------

ApprovalGateName = Literal[
    "signature",
    "evaluation",
    "adversarial",
    "owasp_conformance",
    "reviewer_acknowledgement",
]
"""The 5 ADR-012 §41 gates, in canonical order (mirrored by
:data:`_GATE_ORDER`)."""


ApprovalGateOutcome = Literal["green", "red", "evidence_not_attached"]
"""Per-gate outcome.

- ``green`` — the gate passed.
- ``red`` — the gate ran and FAILED (a ``red_reason`` is attached).
- ``evidence_not_attached`` — the gate's evidence harness has not run
  yet (distinct from ``red``: "harness hasn't run" vs "harness ran and
  failed"). Like ``red``, it is NOT ``green`` — it blocks the green
  approval path. Unlike ``red`` it does NOT populate
  :attr:`ApprovalGateComposition.non_overridable_red_gates` (that set
  keys strictly off ``red``).

This 3-value outcome applies to gates 2-5. Gate 1 (signature) uses the
narrower binary :data:`SignatureGateOutcome` — see below.
"""


SignatureGateOutcome = Literal["green", "red"]
"""Gate-1 (signature) outcome — BINARY, no ``evidence_not_attached``.

ADR-012 §110 makes the cosign trust gate absolutely non-overridable.
The signature gate is verified at approve time, never deferred: the T9
route handler ALWAYS resolves it to ``green`` or ``red`` (every failure
mode — missing verifier, unreachable bundle, unresolved trust root,
cosign-verify failure, every signature-path-resolver failure — maps to
a :data:`SignatureRedReason` → ``red``). Typing
:attr:`SignatureGateInput.outcome` as this 2-value Literal makes the
illegal ``evidence_not_attached`` signature state UNREPRESENTABLE —
which is what guarantees :attr:`ApprovalGateComposition.non_overridable_red_gates`
(keyed off ``outcome == "red"``) captures EVERY non-green signature
state. A 3-value signature outcome would let an
``evidence_not_attached`` signature evade non-overridable tracking and
slip through the T8 override path (reviewer P2 — pre-T7-commit fix).
"""


SignatureRedReason = Literal[
    # 5 original gate-1 red-reasons (R5 P2 #4 trigger mappings).
    "signature_attestation_missing",
    "signature_bundle_path_unreachable",
    "signature_verifier_not_configured",
    "signature_trust_root_not_configured",
    "signature_cosign_verify_failed",
    # 8 signature-path-resolver red-reasons folded in at R7 P2 #1
    # (was a standalone ``SignaturePathRedReason`` Literal at R6 P2 #4;
    # DELETED at R7 — implementers MUST NOT recreate it). The resolver
    # at ``packs/_signature_path_resolver.py`` returns
    # ``SignatureRedReason | None`` directly so resolver failures fit
    # ``SignatureGateInput.red_reason`` with no translation table.
    "signature_cosign_sig_not_in_attestation_paths",
    "signature_multiple_cosign_sig_entries_ambiguous",
    "signature_blob_path_not_declared_in_manifest",
    "signature_path_must_be_relative",
    "signature_blob_path_must_be_relative",
    "signature_signed_artefact_root_not_declared_at_submit",
    "signature_path_traversal_rejected",
    "signature_blob_path_traversal_rejected",
]
"""Closed-enum 13-value gate-1 (signature) red-reason vocabulary."""


EvaluationRedReason = Literal[
    "evaluation_pass_rate_below_threshold",
    "evaluation_evidence_not_attached",
]
"""Closed-enum 2-value gate-2 (evaluation) red-reason vocabulary."""


AdversarialRedReason = Literal[
    "adversarial_corpus_pass_rate_below_threshold",
    "adversarial_high_severity_failure",
    "adversarial_evidence_not_attached",
]
"""Closed-enum 3-value gate-3 (adversarial) red-reason vocabulary."""


OwaspRedReason = Literal[
    "owasp_conformance_red",
    "owasp_evidence_not_attached",
    "owasp_yellow_blocks_approval",
]
"""Closed-enum 3-value gate-4 (OWASP conformance) red-reason vocabulary.

R10 LOCK Flag #2 — ``owasp_yellow_blocks_approval`` covers a yellow
verdict: yellow means the OWASP matrix did not complete (a checker
raised), so the verdict is not trustworthy → blocks approval. The T9
route handler maps ``payload["conformance"]["overall_status"] ==
"yellow"`` to ``outcome="red"`` + this reason BEFORE calling the
composer; the composer copies it verbatim.
"""


ReviewerAckRedReason = Literal["reviewer_acknowledgement_incomplete"]
"""Closed-enum 1-value gate-5 (reviewer acknowledgement) red-reason."""


ApprovalGateRedReason = (
    SignatureRedReason
    | EvaluationRedReason
    | AdversarialRedReason
    | OwaspRedReason
    | ReviewerAckRedReason
)
"""Consolidated 22-value union of every per-gate red-reason — the
wire-protocol-public refusal vocabulary the 412 ``ApproveRefusalResponse``
body carries. The 5 per-gate Literals are pairwise disjoint (13 + 2 +
3 + 3 + 1 = 22, no collisions); pinned by the Slice-A drift detector.
"""


# ---------------------------------------------------------------------------
# Module constants.
# ---------------------------------------------------------------------------

_GATE_ORDER: tuple[ApprovalGateName, ...] = (
    "signature",
    "evaluation",
    "adversarial",
    "owasp_conformance",
    "reviewer_acknowledgement",
)
"""Canonical gate order — 1:1 with :data:`ApprovalGateName`. The
:attr:`ApprovalGateComposition.gates` tuple is always in this order so
consumers (the T9 refusal body, examiners) read a stable layout."""


_NON_OVERRIDABLE_GATES: frozenset[ApprovalGateName] = frozenset({"signature"})
"""ADR-012 §110 + R10 LOCK Flag #4 — cosign signature is the SINGLE
non-overridable gate. A red signature gate cannot be bypassed by the
T8 override path; the other 4 gates CAN. Drift here changes which
gates the override path may skip — a governance-doctrine regression.
"""


_REVIEWER_ACK_KEYS: tuple[str, ...] = (
    "data_governance_acknowledged",
    "risk_tier_acknowledged",
    "supply_chain_acknowledged",
    "conformance_acknowledged",
)
"""The 4 reviewer-evidence-panel acknowledgement keys — the domain-side
mirror of the portal :class:`ReviewerAcknowledgement` DTO's boolean
field names (one per T3-T6 panel). String-coupled, NOT import-coupled
(R11 architectural-arrow invariant — the domain composer must not
import portal); the drift detector at
``tests/unit/packs/test_approval_gates.py`` pins these against
``ReviewerAcknowledgement.model_fields``.
"""


# ---------------------------------------------------------------------------
# Pre-computed gate inputs (built by the T9 route handler).
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SignatureGateInput:
    """Pre-computed gate-1 (signature) input.

    ``outcome`` is the BINARY :data:`SignatureGateOutcome` (``green`` /
    ``red``), NOT the 3-value :data:`ApprovalGateOutcome` the other 4
    gates use — ADR-012 §110: the cosign trust gate is verified at
    approve time, never deferred, so ``evidence_not_attached`` is an
    illegal signature state. The binary type makes it unrepresentable.

    ``signature_digest`` matches ``CosignVerificationResult.signature_digest``
    at ``protocol/trust_gate.py`` (R2 P2 #2) — the SHA-256 hex of the
    signature file; it becomes the gate result's ``evidence_pointer``.
    """

    outcome: SignatureGateOutcome
    red_reason: SignatureRedReason | None
    signature_digest: str | None


@dataclasses.dataclass(frozen=True)
class EvaluationGateInput:
    """Pre-computed gate-2 (evaluation) input. The route handler sets
    ``outcome="red"`` + ``red_reason="evaluation_pass_rate_below_threshold"``
    when ``pass_rate < threshold``."""

    outcome: ApprovalGateOutcome
    red_reason: EvaluationRedReason | None
    pass_rate: float | None
    threshold: float | None


@dataclasses.dataclass(frozen=True)
class AdversarialGateInput:
    """Pre-computed gate-3 (adversarial) input. The route handler sets
    ``outcome="red"`` when ``pass_rate < 0.99`` OR
    ``high_severity_failures > 0``."""

    outcome: ApprovalGateOutcome
    red_reason: AdversarialRedReason | None
    pass_rate: float | None
    high_severity_failures: int


@dataclasses.dataclass(frozen=True)
class OwaspGateInput:
    """Pre-computed gate-4 (OWASP conformance) input.
    ``owasp_overall_status`` is read from the submit chain row's
    ``payload["conformance"]["overall_status"]`` (7B.2 T9)."""

    outcome: ApprovalGateOutcome
    red_reason: OwaspRedReason | None
    owasp_overall_status: ConformanceOverallStatus | None


# ---------------------------------------------------------------------------
# Composer output.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ApprovalGateResult:
    """One gate's result in an :class:`ApprovalGateComposition`.

    ``evidence_pointer`` carries a gate-specific evidence identifier
    where one exists (gate 1: the cosign ``signature_digest``); it is
    ``None`` for the other gates in 7B.3.
    """

    gate: ApprovalGateName
    outcome: ApprovalGateOutcome
    red_reason: ApprovalGateRedReason | None
    evidence_pointer: str | None


@dataclasses.dataclass(frozen=True)
class ApprovalGateComposition:
    """The frozen 5-gate composition — the composer's sole output.

    - ``pack_kind`` — wire-visible plugin-pack kind (R9), echoed
      verbatim from the route handler's authoritative
      ``PackRecord.kind``. Does NOT change gate weighting in 7B.3.
    - ``gates`` — the 5 :class:`ApprovalGateResult` entries in
      :data:`_GATE_ORDER`.
    - ``all_green`` — ``True`` iff every gate ``outcome == "green"``.
      The T9 green approval path requires this.
    - ``non_overridable_red_gates`` — the DYNAMIC intersection of the
      gates whose ``outcome == "red"`` with the :data:`_NON_OVERRIDABLE_GATES`
      policy set. Empty when no non-overridable gate is red;
      ``{"signature"}`` when the signature gate is red. The T8 override
      path refuses when this set is non-empty (ADR-012 §110). Because
      :attr:`SignatureGateInput.outcome` is the BINARY
      :data:`SignatureGateOutcome` (no ``evidence_not_attached``), the
      ``outcome == "red"`` key captures EVERY non-green signature state
      — there is no signature outcome that escapes this set.
    """

    pack_kind: PackKind
    gates: tuple[ApprovalGateResult, ...]
    all_green: bool
    non_overridable_red_gates: frozenset[ApprovalGateName]


# ---------------------------------------------------------------------------
# The composer.
# ---------------------------------------------------------------------------


def _reviewer_acknowledgement_result(
    reviewer_acknowledgement: dict[str, bool],
) -> ApprovalGateResult:
    """Derive the gate-5 result from the request-body ack dict.

    Fail-closed: every one of the 4 :data:`_REVIEWER_ACK_KEYS` must be
    exactly ``True``. A missing key, a ``False``, or a truthy-but-not-
    ``True`` value (e.g. ``1`` or ``"yes"``) all count as
    not-acknowledged. Extra keys beyond the 4 known panels are ignored.
    """
    all_acknowledged = all(reviewer_acknowledgement.get(key) is True for key in _REVIEWER_ACK_KEYS)
    if all_acknowledged:
        return ApprovalGateResult(
            gate="reviewer_acknowledgement",
            outcome="green",
            red_reason=None,
            evidence_pointer=None,
        )
    return ApprovalGateResult(
        gate="reviewer_acknowledgement",
        outcome="red",
        red_reason="reviewer_acknowledgement_incomplete",
        evidence_pointer=None,
    )


def compose_approval_gates(
    *,
    signature_input: SignatureGateInput,
    evaluation_input: EvaluationGateInput,
    adversarial_input: AdversarialGateInput,
    owasp_input: OwaspGateInput,
    pack_kind: PackKind,
    reviewer_acknowledgement: dict[str, bool],
) -> ApprovalGateComposition:
    """Compose the 5 ADR-012 §41 approval gates into a frozen verdict.

    Pure-functional — no I/O, no DB, no time, no random. The first 4
    gates arrive PRE-COMPUTED in their ``*GateInput`` dataclasses (the
    T9 route handler owns that wiring); the composer copies their
    ``outcome`` + ``red_reason`` verbatim. Gate 5
    (``reviewer_acknowledgement``) is the single gate the composer
    derives — from ``reviewer_acknowledgement`` (the ``model_dump()``
    wire shape of the portal ``ReviewerAcknowledgement`` DTO; the
    domain composer never imports portal, per R11).

    Args:
      signature_input: pre-computed gate-1 input.
      evaluation_input: pre-computed gate-2 input.
      adversarial_input: pre-computed gate-3 input.
      owasp_input: pre-computed gate-4 input.
      pack_kind: authoritative ``PackRecord.kind``; echoed onto the
        composition verbatim (R9). Does not affect gate weighting.
      reviewer_acknowledgement: the 4-boolean panel-ack dict; gate 5 is
        green iff every :data:`_REVIEWER_ACK_KEYS` entry is ``True``.

    Returns:
      A frozen :class:`ApprovalGateComposition` carrying the 5 gate
      results in :data:`_GATE_ORDER`, the ``all_green`` verdict, and
      the ``non_overridable_red_gates`` set for the T8 override path.
    """
    signature_result = ApprovalGateResult(
        gate="signature",
        outcome=signature_input.outcome,
        red_reason=signature_input.red_reason,
        evidence_pointer=signature_input.signature_digest,
    )
    evaluation_result = ApprovalGateResult(
        gate="evaluation",
        outcome=evaluation_input.outcome,
        red_reason=evaluation_input.red_reason,
        evidence_pointer=None,
    )
    adversarial_result = ApprovalGateResult(
        gate="adversarial",
        outcome=adversarial_input.outcome,
        red_reason=adversarial_input.red_reason,
        evidence_pointer=None,
    )
    owasp_result = ApprovalGateResult(
        gate="owasp_conformance",
        outcome=owasp_input.outcome,
        red_reason=owasp_input.red_reason,
        evidence_pointer=None,
    )
    acknowledgement_result = _reviewer_acknowledgement_result(reviewer_acknowledgement)

    # Constructed in _GATE_ORDER — the canonical layout contract. A
    # future reorder of this block is caught by the Slice-F regression
    # ``test_gates_tuple_in_canonical_order`` (asserts the produced
    # tuple's gate names equal _GATE_ORDER).
    gates: tuple[ApprovalGateResult, ...] = (
        signature_result,
        evaluation_result,
        adversarial_result,
        owasp_result,
        acknowledgement_result,
    )

    all_green = all(result.outcome == "green" for result in gates)
    # ``outcome == "red"`` is the complete non-green test for the only
    # gate in _NON_OVERRIDABLE_GATES (signature): SignatureGateInput's
    # outcome is the binary SignatureGateOutcome, so a signature gate is
    # green or red — never evidence_not_attached. No non-green signature
    # state escapes this set (reviewer P2 — pre-T7-commit fix).
    non_overridable_red_gates = frozenset(
        result.gate
        for result in gates
        if result.outcome == "red" and result.gate in _NON_OVERRIDABLE_GATES
    )

    return ApprovalGateComposition(
        pack_kind=pack_kind,
        gates=gates,
        all_green=all_green,
        non_overridable_red_gates=non_overridable_red_gates,
    )


# ---------------------------------------------------------------------------
# Sprint 7B.3 T8 — override path: vocabulary + decision helper + snapshot.
# ---------------------------------------------------------------------------


OverrideRefusalReason = Literal[
    "composition_already_all_green",
    "override_scope_not_held",
    "override_reason_missing",
    "non_overridable_red_gate",
]
"""Closed-enum 4-value vocabulary for why :func:`evaluate_override_decision`
refused an override. Wire-protocol-public — the T9 approve endpoint
renders it into the 412 refusal body's override-path branch.

- ``composition_already_all_green`` — the composition is all-green; there
  is nothing to override (renamed from the pre-R12
  ``no_red_gates_to_override``, which mis-described the trigger — the
  trigger is ``composition.all_green``, not "zero red gates", because an
  ``evidence_not_attached``-only composition has zero red gates yet IS
  overrideable).
- ``non_overridable_red_gate`` — a gate in :data:`_NON_OVERRIDABLE_GATES`
  (cosign signature, per ADR-012 §110) is ``red``; no override is
  possible regardless of who asks.
- ``override_scope_not_held`` — the caller does not hold the
  ``pack.override.approval_gate`` RBAC scope.
- ``override_reason_missing`` — no categorised :data:`ApprovalOverrideReason`
  was supplied.
"""


@dataclasses.dataclass(frozen=True)
class OverrideDecision:
    """The frozen verdict of :func:`evaluate_override_decision`.

    ``allowed`` is ``True`` iff the override path may proceed;
    ``refusal_reason`` carries the closed-enum :data:`OverrideRefusalReason`
    when ``allowed`` is ``False`` and is ``None`` when ``allowed`` is
    ``True`` (the two fields are mutually constrained — pinned by the
    Slice-J tests).
    """

    allowed: bool
    refusal_reason: OverrideRefusalReason | None


def evaluate_override_decision(
    *,
    composition: ApprovalGateComposition,
    override_scope_held: bool,
    override_reason: ApprovalOverrideReason | None,
) -> OverrideDecision:
    """Decide whether the ADR-012 §107 override path may force-approve.

    Pure-functional — no I/O, no DB, no time, no random. The T9 approve
    endpoint calls this AFTER :func:`compose_approval_gates` when the
    composition is not all-green: it passes the composition, whether the
    caller holds the ``pack.override.approval_gate`` scope, and the
    categorised override reason from the request body.

    An override is **allowed** iff ALL of:

    - ``not composition.all_green`` — there is a blocking gate to
      override. "Blocking" = ``red`` OR ``evidence_not_attached`` (R12
      blocking-not-red doctrine); ``all_green`` already treats both as
      non-green, so an ``evidence_not_attached``-only composition (zero
      ``red`` gates — the EXPECTED pre-Sprint-11 state for gates 2/3) IS
      overrideable.
    - ``composition.non_overridable_red_gates`` is empty — no gate in
      :data:`_NON_OVERRIDABLE_GATES` (cosign signature) is ``red``.
      ADR-012 §110 makes the signature gate absolutely non-overridable.
    - ``override_scope_held`` — the caller holds the override RBAC scope.
    - ``override_reason is not None`` — a categorised reason was supplied.

    Otherwise the override is refused with exactly one
    :data:`OverrideRefusalReason`. **Refusal precedence — most-fundamental
    blocker first:** (1) ``composition_already_all_green`` (is there even
    something to override?) → (2) ``non_overridable_red_gate`` (is an
    override legal here AT ALL, regardless of caller?) → (3)
    ``override_scope_not_held`` (does the caller have authority?) → (4)
    ``override_reason_missing`` (did they supply the required reason?).
    (1) and (2) are mutually exclusive — an all-green composition has no
    red gates — so their relative order is moot, but (2) is checked
    before the caller-specific gates (3)/(4) so the wire response always
    surfaces the ADR-012 §110 absolute stop ahead of the authority check.
    """
    if composition.all_green:
        return OverrideDecision(allowed=False, refusal_reason="composition_already_all_green")
    if composition.non_overridable_red_gates:
        return OverrideDecision(allowed=False, refusal_reason="non_overridable_red_gate")
    if not override_scope_held:
        return OverrideDecision(allowed=False, refusal_reason="override_scope_not_held")
    if override_reason is None:
        return OverrideDecision(allowed=False, refusal_reason="override_reason_missing")
    return OverrideDecision(allowed=True, refusal_reason=None)


def composition_snapshot(composition: ApprovalGateComposition) -> dict[str, Any]:
    """Serialise an :class:`ApprovalGateComposition` into a canonical-safe
    ``dict`` for the ``pack.approval_override`` chain-event payload.

    :class:`ApprovalGateComposition` is a ``@dataclasses.dataclass`` whose
    ``gates`` field is a ``tuple`` and whose ``non_overridable_red_gates``
    field is a ``frozenset``. ``core.canonical.canonical_bytes`` REJECTS
    tuples with ``TypeError`` (they would silently become JSON arrays,
    losing the list/tuple distinction) and has no serialisation rule for
    ``frozenset`` — so a raw ``dataclasses.asdict(composition)`` would
    fail the override-event chain insert. This helper converts ``gates``
    to a ``list`` of plain ``dict``s and ``non_overridable_red_gates`` to
    a **sorted** ``list`` (deterministic ordering — the gate names are
    examiner-visible). Mirrors the load-bearing tuple→list conversion
    doctrine at ``packs/conformance/runner.py``.

    The T9 override path builds the snapshot via this helper and passes
    the result as ``append_override_event``'s ``gate_composition_snapshot``
    kwarg so examiners can reconstruct WHICH gates were red / blocking at
    override time.
    """
    return {
        "pack_kind": composition.pack_kind,
        "gates": [
            {
                "gate": result.gate,
                "outcome": result.outcome,
                "red_reason": result.red_reason,
                "evidence_pointer": result.evidence_pointer,
            }
            for result in composition.gates
        ],
        "all_green": composition.all_green,
        "non_overridable_red_gates": sorted(composition.non_overridable_red_gates),
    }
