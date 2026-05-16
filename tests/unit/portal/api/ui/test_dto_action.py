"""Sprint 7B.4 T9 — Action DTOs + Literals + model_validator parity.

`portal/api/ui/dto.py` is NOT-CC (pure type-only module; mirrors
`portal/api/packs/dto.py` precedent — no FastAPI / broker / RBAC
runtime dependencies). The wire types here ARE wire-protocol-public
per ADR-020 + AGENTS.md "Wire-protocol contracts" stop rule (the
discriminated-union request shape is the body of POST /api/v1/ui/actions);
drift breaks every UI client consuming the action surface.

Test surface:

  - `ActionClass` 6-value Literal vocabulary (canonical action verbs)
  - `ActionOutcome` 2-value Literal (`accepted` / `rejected`)
  - `ActionRejectionReason` 10-value Literal, with **equality** against
    `portal.api.ui.elicitation_gate.ActionRejectionReason` (the T8 R1
    forward watchpoint — the two Literals MUST stay lockstep) AND
    disjointness from `RBACDenialType` (T3) + `RejectionReason`
    (7B.2 T5 packs DTO)
  - 6 per-class request DTOs + `ActionRequest` discriminated union
    (Pydantic v2 `Field(discriminator="action_class")`)
  - `SubmitElicitationActionRequest` mode/payload parity via
    `@model_validator(mode="after")` — the P2 LOCK from the design
    spec: ill-formed requests refuse at Pydantic-parse time → 422 →
    NO chain row written
  - `ActionResponse` shape per spec §4.4a
  - `UIActionContext` frozen dataclass (returned by T11's
    RequireUIAction dep)
  - Architectural-arrow invariant — dto.py imports nothing from
    fastapi / starlette / sse_starlette / `protocol/ui_events` (broker
    primitives belong to action_routes.py at T11)
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path
from typing import get_args

import pydantic
import pytest

from cognic_agentos.portal.api.ui.dto import (
    ActionClass,
    ActionOutcome,
    ActionRejectionReason,
    ActionRequest,
    ActionResponse,
    ApproveActionRequest,
    CancelRunActionRequest,
    DenyActionRequest,
    InterruptActionRequest,
    ResumeActionRequest,
    SubmitElicitationActionRequest,
    UIActionContext,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.ui_events import RBACDenialType


class TestActionClassLiteral:
    def test_count_is_6(self) -> None:
        assert len(get_args(ActionClass)) == 6

    def test_values(self) -> None:
        assert set(get_args(ActionClass)) == {
            "approve",
            "deny",
            "cancel_run",
            "interrupt",
            "resume",
            "submit_elicitation",
        }


class TestActionOutcomeLiteral:
    def test_count_is_2(self) -> None:
        assert len(get_args(ActionOutcome)) == 2
        assert set(get_args(ActionOutcome)) == {"accepted", "rejected"}


class TestActionRejectionReasonLiteral:
    def test_count_is_10(self) -> None:
        assert len(get_args(ActionRejectionReason)) == 10

    def test_exact_10_value_set(self) -> None:
        """Sentinel — full-set assertion catches both rename + add/remove
        drift. T9 (here) + T8 (elicitation_gate.py) hold parallel
        Literals; the cross-module equality test below pins their
        lockstep."""
        assert set(get_args(ActionRejectionReason)) == {
            "action_backend_deferred_to_sprint_13_5",
            "action_backend_deferred_no_run_primitive",
            "action_backend_deferred_sandbox_unwired",
            "elicitation_mode_not_permitted",
            "elicitation_restricted_data_class",
            "elicitation_rego_denied",
            "elicitation_unwired_evaluator",
            "elicitation_backend_failed",
            "elicitation_backend_unwired",
            "elicitation_unknown_id",
        }


class TestActionRejectionReasonCrossModuleEquality:
    """T8 R1 forward watchpoint (user-locked): the parallel Literal at
    `portal.api.ui.elicitation_gate.ActionRejectionReason` MUST stay
    lockstep with the DTO's Literal here. A rename or value drift in
    either module would land silently — the T8 gate body emits 6 of
    the 10 values + T11 action handler emits the other 4 + the DTO
    publishes all 10 to the wire body; all 3 sources MUST agree.

    Per the user-locked architectural doctrine
    (feedback_drift_detector_test_only_no_runtime_import), NO runtime
    cross-module import enforces equality — each module declares its
    OWN local copy + this test imports BOTH at test time only +
    asserts equality via `get_args`."""

    def test_dto_literal_matches_elicitation_gate_literal(self) -> None:
        from cognic_agentos.portal.api.ui.elicitation_gate import (
            ActionRejectionReason as GateActionRejectionReason,
        )

        dto_values = set(get_args(ActionRejectionReason))
        gate_values = set(get_args(GateActionRejectionReason))
        assert dto_values == gate_values, (
            f"ActionRejectionReason drift between portal/api/ui/dto.py "
            f"and portal/api/ui/elicitation_gate.py: dto={dto_values} "
            f"gate={gate_values}; symmetric difference="
            f"{dto_values ^ gate_values}"
        )


class TestActionRejectionReasonDisjointness:
    """Refusal-axis disjointness — `ActionRejectionReason` (the
    chain-row payload.reason value when a POST /actions rejects) MUST
    be value-disjoint from `RBACDenialType` (T3, the 4-portal-RBAC
    union) and `RejectionReason` (7B.2 T5, the pack-review reject
    vocabulary). Overlap would create wire-protocol ambiguity: an
    examiner reading a chain row's `reason` field couldn't tell
    which surface emitted the refusal."""

    def test_disjoint_from_rbac_denial_type(self) -> None:
        assert set(get_args(ActionRejectionReason)).isdisjoint(set(get_args(RBACDenialType)))

    def test_disjoint_from_pack_rejection_reason(self) -> None:
        from cognic_agentos.portal.api.packs.dto import RejectionReason

        assert set(get_args(ActionRejectionReason)).isdisjoint(set(get_args(RejectionReason)))


class TestDiscriminatedUnion:
    """Pydantic v2 `Field(discriminator="action_class")` resolves the
    request body to the correct per-class DTO at parse time. Unknown
    `action_class` values reject at parse with 422 — NO chain row
    written for malformed requests."""

    def test_approve_parses(self) -> None:
        body: ActionRequest = pydantic.TypeAdapter(ActionRequest).validate_python(
            {
                "action_class": "approve",
                "approval_id": "ap_1",
                "decision": "grant",
            }
        )
        assert isinstance(body, ApproveActionRequest)
        assert body.approval_id == "ap_1"
        assert body.decision == "grant"

    def test_deny_parses(self) -> None:
        body: ActionRequest = pydantic.TypeAdapter(ActionRequest).validate_python(
            {"action_class": "deny", "approval_id": "ap_1"}
        )
        assert isinstance(body, DenyActionRequest)

    def test_cancel_run_parses(self) -> None:
        body: ActionRequest = pydantic.TypeAdapter(ActionRequest).validate_python(
            {"action_class": "cancel_run", "run_id": "run_1"}
        )
        assert isinstance(body, CancelRunActionRequest)

    def test_interrupt_parses(self) -> None:
        body: ActionRequest = pydantic.TypeAdapter(ActionRequest).validate_python(
            {"action_class": "interrupt", "run_id": "run_1"}
        )
        assert isinstance(body, InterruptActionRequest)

    def test_resume_parses(self) -> None:
        body: ActionRequest = pydantic.TypeAdapter(ActionRequest).validate_python(
            {"action_class": "resume", "run_id": "run_1"}
        )
        assert isinstance(body, ResumeActionRequest)

    def test_submit_elicitation_parses(self) -> None:
        body: ActionRequest = pydantic.TypeAdapter(ActionRequest).validate_python(
            {
                "action_class": "submit_elicitation",
                "elicitation_id": "elc_1",
                "mode": "url",
                "url_completion_signal": {"ok": True},
            }
        )
        assert isinstance(body, SubmitElicitationActionRequest)

    def test_unknown_action_class_422_at_parse(self) -> None:
        with pytest.raises(pydantic.ValidationError):
            pydantic.TypeAdapter(ActionRequest).validate_python({"action_class": "frobnicate"})


class TestSubmitElicitationPayloadModeParity:
    """P2 LOCK from the design spec — exact mode/payload parity at
    Pydantic parse. Rejects ill-formed requests BEFORE any chain
    row is appended."""

    def test_form_mode_without_form_payload_rejected(self) -> None:
        with pytest.raises(pydantic.ValidationError, match=r"form.*requires.*form_payload"):
            SubmitElicitationActionRequest(
                elicitation_id="elc_1",
                mode="form",
                form_payload=None,
                url_completion_signal=None,
            )

    def test_form_mode_with_url_signal_rejected(self) -> None:
        with pytest.raises(
            pydantic.ValidationError, match="must not include url_completion_signal"
        ):
            SubmitElicitationActionRequest(
                elicitation_id="elc_1",
                mode="form",
                form_payload={"a": 1},
                url_completion_signal={"x": True},
            )

    def test_url_mode_without_completion_signal_rejected(self) -> None:
        with pytest.raises(pydantic.ValidationError, match=r"url.*requires.*url_completion_signal"):
            SubmitElicitationActionRequest(
                elicitation_id="elc_1",
                mode="url",
                form_payload=None,
                url_completion_signal=None,
            )

    def test_url_mode_with_form_payload_rejected(self) -> None:
        with pytest.raises(pydantic.ValidationError, match="must not include form_payload"):
            SubmitElicitationActionRequest(
                elicitation_id="elc_1",
                mode="url",
                form_payload={"a": 1},
                url_completion_signal={"x": True},
            )

    def test_form_mode_with_form_payload_parses(self) -> None:
        body = SubmitElicitationActionRequest(
            elicitation_id="elc_1",
            mode="form",
            form_payload={"a": 1},
            url_completion_signal=None,
        )
        assert body.mode == "form"

    def test_url_mode_with_completion_signal_parses(self) -> None:
        body = SubmitElicitationActionRequest(
            elicitation_id="elc_1",
            mode="url",
            form_payload=None,
            url_completion_signal={"x": True},
        )
        assert body.mode == "url"


class TestActionResponseShape:
    """ActionResponse is wire-protocol-public per spec §4.4a. The
    UI consumes the response body to render the optimistic submit
    state + reconcile the resolution_event_id with the SSE stream."""

    def test_construct_with_required_fields(self) -> None:
        from datetime import UTC, datetime

        resp = ActionResponse(
            request_id="portal-req-abc",
            action_class="approve",
            outcome="accepted",
            reason=None,
            submitted_at=datetime.now(UTC),
            submitted_event_id="evt_01ABC",
            resolution_event_id="evt_01DEF",
            client_correlation_id="cli_1",
        )
        assert resp.request_id == "portal-req-abc"
        assert resp.outcome == "accepted"
        assert resp.reason is None


class TestUIActionContextFrozen:
    """`UIActionContext` is returned by T11's RequireUIAction
    dependency. Type-only — declared HERE because T11's dep needs to
    construct it WITHOUT a runtime dep on FastAPI/broker types
    leaking back into dto.py. Frozen so the action handler can pass
    the same context value through the chain-row append path without
    aliasing risk."""

    def test_construction(self, actor_t1: Actor) -> None:
        body = ApproveActionRequest(approval_id="ap_1", decision="grant")
        ctx = UIActionContext(body=body, actor=actor_t1, request_id="portal-req-abc")
        assert ctx.request_id == "portal-req-abc"
        assert ctx.body is body
        assert ctx.actor is actor_t1

    def test_frozen(self, actor_t1: Actor) -> None:
        body = ApproveActionRequest(approval_id="ap_1", decision="grant")
        ctx = UIActionContext(body=body, actor=actor_t1, request_id="portal-req-abc")
        with pytest.raises(dataclasses.FrozenInstanceError):
            ctx.request_id = "other"  # type: ignore[misc]


#: P1 #2 SCOPE LOCK forbidden-runtime-import prefixes. ANY import of one
#: of these modules at MODULE-LEVEL (i.e. outside an ``if TYPE_CHECKING:``
#: block) is a scope-lock violation.
#:
#: - ``fastapi`` / ``starlette`` / ``sse_starlette`` — the DTO module
#:   stays Pydantic-only; the T11 ``action_routes.py`` owns FastAPI +
#:   SSE wiring.
#: - ``cognic_agentos.protocol.ui_events`` — broker primitives +
#:   ContextVar runtime; T11 ``action_routes.py`` owns that arrow.
#: - ``cognic_agentos.portal.rbac`` — :class:`Actor` is referenced from
#:   :class:`UIActionContext` ONLY under ``TYPE_CHECKING`` (string-only
#:   forward ref). A future refactor that moves ``from ... import Actor``
#:   to module level would silently couple dto.py to the RBAC runtime;
#:   this prefix in the forbidden list catches that the moment it's
#:   introduced.
_DTO_FORBIDDEN_RUNTIME_PREFIXES: tuple[str, ...] = (
    "fastapi",
    "starlette",
    "sse_starlette",
    "cognic_agentos.protocol.ui_events",
    "cognic_agentos.portal.rbac",
)


def _matches_forbidden_prefix(module_name: str, prefixes: tuple[str, ...]) -> bool:
    """A module ``"cognic_agentos.portal.rbac.actor"`` matches the prefix
    ``"cognic_agentos.portal.rbac"`` via either exact equality OR a
    dotted-segment continuation. The dotted check prevents accidental
    false positives on something like ``cognic_agentos.portal.rbac_other``
    that the bare ``startswith()`` would over-match."""
    return any(module_name == p or module_name.startswith(p + ".") for p in prefixes)


def _scan_runtime_imports(source: str, forbidden_prefixes: tuple[str, ...]) -> list[str]:
    """Walk ``source`` as Python AST + return any module-level imports
    that match a forbidden prefix. Imports nested inside an
    ``if TYPE_CHECKING:`` block are EXEMPT (string-only forward refs;
    not evaluated at runtime). All other locations — module-level,
    ``if sys.version_info:`` branches, function bodies — count as
    runtime imports for this scope-lock check."""
    tree = ast.parse(source)

    type_checking_node_ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        is_type_checking_guard = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
            isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
        )
        if is_type_checking_guard:
            for child in node.body:
                for sub in ast.walk(child):
                    type_checking_node_ids.add(id(sub))

    offenders: list[str] = []
    for node in ast.walk(tree):
        if id(node) in type_checking_node_ids:
            continue
        if isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if _matches_forbidden_prefix(mod, forbidden_prefixes):
                offenders.append(f"from {mod} import ...")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if _matches_forbidden_prefix(alias.name, forbidden_prefixes):
                    offenders.append(f"import {alias.name}")
    return offenders


class TestDTOModuleHasNoRuntimeImports:
    """P1 #2 SCOPE LOCK — dto.py is pure type-only. NO FastAPI /
    Starlette / sse_starlette / broker / RBAC runtime imports.
    `RequireUIAction` is FastAPI + RBAC + broker-coupled and lives
    in `action_routes.py` (T11), NOT here. AST scan catches a
    forward-reference convenience import that would silently violate
    the NOT-CC classification + add a runtime dependency arrow into
    the wire-types module.

    Per ``feedback_security_regression_hardening``, the AST detector
    is load-bearing — pinned by the parametrized self-tests in
    :class:`TestDTOImportScanDetectorLoadBearing` below proving the
    detector fires on each known-bad input shape (top-level
    ``from ... import``, top-level ``import ...``, RBAC import promoted
    out of ``TYPE_CHECKING``) AND that the TYPE_CHECKING-guarded import
    does NOT trigger a false positive."""

    def test_no_forbidden_runtime_imports(self) -> None:
        src = Path("src/cognic_agentos/portal/api/ui/dto.py").read_text()
        offenders = _scan_runtime_imports(src, _DTO_FORBIDDEN_RUNTIME_PREFIXES)
        assert not offenders, (
            f"portal/api/ui/dto.py P1 #2 scope-lock violation — forbidden "
            f"runtime imports: {offenders}"
        )


class TestDTOImportScanDetectorLoadBearing:
    """Threat-model self-tests for ``_scan_runtime_imports``. If the
    detector silently stops firing on any of these shapes, the
    scope-lock above becomes a vacuous proof. Parametrized so each
    known-bad shape pins independently."""

    @pytest.mark.parametrize(
        "bad_source,expected_substring",
        [
            (
                # Top-level `from ... import` — the most likely
                # refactor that would slip past the original test.
                "from cognic_agentos.portal.rbac.actor import Actor\n",
                "cognic_agentos.portal.rbac.actor",
            ),
            (
                # Top-level `import ...` form — symmetric check that
                # both ImportFrom and Import branches catch RBAC.
                "import cognic_agentos.portal.rbac.actor\n",
                "cognic_agentos.portal.rbac.actor",
            ),
            (
                # FastAPI runtime import — sentinel that the
                # pre-existing forbidden prefixes still fire.
                "import fastapi\n",
                "fastapi",
            ),
            (
                # Broker import — sentinel for the
                # `protocol.ui_events` prefix.
                "from cognic_agentos.protocol.ui_events import UIEventBroker\n",
                "cognic_agentos.protocol.ui_events",
            ),
            (
                # If TYPE_CHECKING block is the GUARD; an import inside
                # a DIFFERENT if-block (e.g. `if sys.version_info:`)
                # must still count as runtime.
                "import sys\n"
                "if sys.version_info >= (3, 12):\n"
                "    from cognic_agentos.portal.rbac.actor import Actor\n",
                "cognic_agentos.portal.rbac.actor",
            ),
        ],
    )
    def test_detector_fires_on_known_bad_input(
        self, bad_source: str, expected_substring: str
    ) -> None:
        offenders = _scan_runtime_imports(bad_source, _DTO_FORBIDDEN_RUNTIME_PREFIXES)
        assert offenders, f"detector failed to fire on: {bad_source!r}"
        assert any(expected_substring in o for o in offenders), (
            f"detector fired but missed expected module {expected_substring!r}; "
            f"offenders={offenders}"
        )

    @pytest.mark.parametrize(
        "good_source",
        [
            # The actual dto.py shape: `Actor` under TYPE_CHECKING.
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    from cognic_agentos.portal.rbac.actor import Actor\n",
            # FastAPI symbol imported only at type-check time — same
            # exemption applies (though dto.py never needs this; the
            # case is here to prove the TYPE_CHECKING guard is general).
            "from typing import TYPE_CHECKING\n"
            "if TYPE_CHECKING:\n"
            "    from fastapi import Depends\n",
            # Nested TYPE_CHECKING block recognised via attribute form
            # (`typing.TYPE_CHECKING`) — the detector should pick up
            # either Name- or Attribute-shaped guards.
            "import typing\n"
            "if typing.TYPE_CHECKING:\n"
            "    from cognic_agentos.portal.rbac.actor import Actor\n",
            # Module that imports nothing forbidden — baseline negative
            # control.
            "from datetime import datetime\nimport pydantic\n",
        ],
    )
    def test_detector_does_not_fire_on_type_checking_guarded_or_clean(
        self, good_source: str
    ) -> None:
        offenders = _scan_runtime_imports(good_source, _DTO_FORBIDDEN_RUNTIME_PREFIXES)
        assert not offenders, (
            f"detector false-positive on TYPE_CHECKING-guarded or clean "
            f"source: {good_source!r}; offenders={offenders}"
        )

    def test_forbidden_prefix_list_pins_portal_rbac(self) -> None:
        """Independent sentinel: if a future refactor drops
        ``cognic_agentos.portal.rbac`` from the forbidden list, the
        TYPE_CHECKING-only guard on Actor becomes unenforceable. This
        test fails at the prefix level rather than waiting for the
        compound check above to silently regress."""
        assert "cognic_agentos.portal.rbac" in _DTO_FORBIDDEN_RUNTIME_PREFIXES
