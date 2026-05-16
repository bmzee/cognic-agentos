"""Sprint 7B.4 T8 — `evaluate_elicitation_submission` 5-step gate matrix.

`portal/api/ui/elicitation_gate.py` is on the AGENTS.md critical-controls
list (policy boundary; precedent: 7B.3 T7 `packs/approval_gates.py`).
These regressions defend the 5-step refusal contract:

  Step 1 — adapter wired? (kernel-default adapter raises
           NotImplementedError → maps to `elicitation_backend_unwired`)
  Step 2 — `adapter.get_context(...)` returns None →
           `elicitation_unknown_id`
  Step 3 — mode parity (`request.mode in ctx.elicitation_modes`) — BOTH
           modes per spec §5b; either-direction mismatch yields
           `elicitation_mode_not_permitted`
  Step 4 — form-mode + restricted-data-class intersection →
           `elicitation_restricted_data_class`
  Step 5 — Rego eval: missing engine / missing OPA binary →
           `elicitation_unwired_evaluator`; allow=False →
           `elicitation_rego_denied`; allow=True → green path

Plus a three-way drift detector pinning the
`_RESTRICTED_DATA_CLASSES` frozenset across:

  (a) the gate module's local copy
  (b) the parsed `policies/_default/elicitation.rego` `restricted_classes` set
  (c) the existing runtime canonical
      `protocol/mcp_capabilities._RESTRICTED_DATA_CLASSES`

Per the user-locked architectural doctrine, NO runtime cross-module
import enforces equality — the gate inlines its own local copy + this
test imports both (and the rego file) at test time only.
"""

from __future__ import annotations

import dataclasses
import re
import uuid
from pathlib import Path
from typing import get_args
from unittest.mock import AsyncMock

import pytest

from cognic_agentos.portal.api.ui.elicitation_gate import (
    _RESTRICTED_DATA_CLASSES,
    ActionRejectionReason,
    evaluate_elicitation_submission,
)
from cognic_agentos.protocol.elicitation_adapter import (
    ElicitationAdapter,
    ElicitationContext,
    KernelDefaultElicitationAdapter,
)

# ---------------------------------------------------------------------------
# Minimal request stub — duck-typed against the gate's attribute reads.
# The real `SubmitElicitationActionRequest` Pydantic DTO ships at T9; T8
# stays self-contained by stubbing the request with a frozen dataclass
# that exposes the 3 attributes the gate reads: `elicitation_id`, `mode`,
# `form_payload`.
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _StubRequest:
    elicitation_id: str
    mode: str
    form_payload: dict[str, object] | None
    url_completion_signal: dict[str, object] | None = None


@dataclasses.dataclass(frozen=True)
class _StubActor:
    tenant_id: str


@pytest.fixture
def url_request() -> _StubRequest:
    return _StubRequest(
        elicitation_id="elc_1",
        mode="url",
        form_payload=None,
        url_completion_signal={"ok": True},
    )


@pytest.fixture
def form_request() -> _StubRequest:
    return _StubRequest(
        elicitation_id="elc_1",
        mode="form",
        form_payload={"answer": "42"},
        url_completion_signal=None,
    )


@pytest.fixture
def actor() -> _StubActor:
    return _StubActor(tenant_id="t1")


@pytest.fixture
def safe_ctx() -> ElicitationContext:
    """Adapter-returned context that satisfies every gate step (both
    modes permitted, only public data class, no expiry). Tests narrow
    via `dataclasses.replace` to exercise specific refusal branches."""
    return ElicitationContext(
        elicitation_id="elc_1",
        tenant_id="t1",
        originating_pack_id="pkg_1",
        originating_decision_record_id=uuid.uuid4(),
        elicitation_modes=("url", "form"),
        data_classes=("public",),
        expires_at=None,
    )


# ---------------------------------------------------------------------------
# Step 1 — adapter wired?
# ---------------------------------------------------------------------------


class TestGateStep1AdapterUnwired:
    @pytest.mark.asyncio
    async def test_adapter_None_returns_backend_unwired(
        self, url_request: _StubRequest, actor: _StubActor
    ) -> None:
        outcome = await evaluate_elicitation_submission(
            request=url_request,
            actor=actor,
            adapter=None,
            rego_engine=AsyncMock(),
        )
        assert outcome.allowed is False
        assert outcome.reason == "elicitation_backend_unwired"
        assert outcome.ctx is None


class TestGateStep1KernelDefaultAdapter:
    """The kernel-default adapter (T7) raises `NotImplementedError`
    pointing at ADR-020 — the gate catches it + maps to
    `elicitation_backend_unwired` (operator runbook: a bank overlay
    forgot to inject a real adapter via `create_app(elicitation_adapter=...)`)."""

    @pytest.mark.asyncio
    async def test_kernel_default_raises_NotImplemented_returns_backend_unwired(
        self, url_request: _StubRequest, actor: _StubActor
    ) -> None:
        outcome = await evaluate_elicitation_submission(
            request=url_request,
            actor=actor,
            adapter=KernelDefaultElicitationAdapter(),
            rego_engine=AsyncMock(),
        )
        assert outcome.allowed is False
        assert outcome.reason == "elicitation_backend_unwired"
        assert outcome.ctx is None


# ---------------------------------------------------------------------------
# Step 2 — adapter.get_context returns None
# ---------------------------------------------------------------------------


class TestGateStep2UnknownId:
    @pytest.mark.asyncio
    async def test_get_context_returns_None_yields_unknown_id(
        self, url_request: _StubRequest, actor: _StubActor
    ) -> None:
        adapter = AsyncMock(spec=ElicitationAdapter)
        adapter.get_context = AsyncMock(return_value=None)
        outcome = await evaluate_elicitation_submission(
            request=url_request,
            actor=actor,
            adapter=adapter,
            rego_engine=AsyncMock(),
        )
        assert outcome.allowed is False
        assert outcome.reason == "elicitation_unknown_id"
        assert outcome.ctx is None


# ---------------------------------------------------------------------------
# Step 3 — mode parity (BOTH directions per spec §5b P1)
# ---------------------------------------------------------------------------


class TestGateStep3ModeParityBothModes:
    """Per the spec §5b P1 review note: mode parity applies in BOTH
    directions. A `form`-mode submission against a `url`-only manifest
    refuses; a `url`-mode submission against a `form`-only manifest
    also refuses. Drift in either direction is a wire-protocol break."""

    @pytest.mark.asyncio
    async def test_form_mode_rejected_when_manifest_url_only(
        self,
        form_request: _StubRequest,
        actor: _StubActor,
        safe_ctx: ElicitationContext,
    ) -> None:
        ctx = dataclasses.replace(safe_ctx, elicitation_modes=("url",))
        adapter = AsyncMock()
        adapter.get_context = AsyncMock(return_value=ctx)
        outcome = await evaluate_elicitation_submission(
            request=form_request,
            actor=actor,
            adapter=adapter,
            rego_engine=AsyncMock(),
        )
        assert outcome.allowed is False
        assert outcome.reason == "elicitation_mode_not_permitted"
        assert outcome.ctx is ctx

    @pytest.mark.asyncio
    async def test_url_mode_rejected_when_manifest_form_only(
        self,
        url_request: _StubRequest,
        actor: _StubActor,
        safe_ctx: ElicitationContext,
    ) -> None:
        ctx = dataclasses.replace(safe_ctx, elicitation_modes=("form",))
        adapter = AsyncMock()
        adapter.get_context = AsyncMock(return_value=ctx)
        outcome = await evaluate_elicitation_submission(
            request=url_request,
            actor=actor,
            adapter=adapter,
            rego_engine=AsyncMock(),
        )
        assert outcome.allowed is False
        assert outcome.reason == "elicitation_mode_not_permitted"


# ---------------------------------------------------------------------------
# Step 4 — restricted-data-class intersection (form-mode only)
# ---------------------------------------------------------------------------


class TestGateStep4RestrictedDataClass:
    @pytest.mark.parametrize("restricted", sorted(_RESTRICTED_DATA_CLASSES))
    @pytest.mark.asyncio
    async def test_form_mode_rejected_on_restricted_class(
        self,
        form_request: _StubRequest,
        actor: _StubActor,
        safe_ctx: ElicitationContext,
        restricted: str,
    ) -> None:
        ctx = dataclasses.replace(safe_ctx, data_classes=(restricted,))
        adapter = AsyncMock()
        adapter.get_context = AsyncMock(return_value=ctx)
        outcome = await evaluate_elicitation_submission(
            request=form_request,
            actor=actor,
            adapter=adapter,
            rego_engine=AsyncMock(),
        )
        assert outcome.allowed is False
        assert outcome.reason == "elicitation_restricted_data_class"

    @pytest.mark.parametrize("restricted", sorted(_RESTRICTED_DATA_CLASSES))
    @pytest.mark.asyncio
    async def test_url_mode_PASSES_step4_with_restricted_class(
        self,
        url_request: _StubRequest,
        actor: _StubActor,
        safe_ctx: ElicitationContext,
        restricted: str,
    ) -> None:
        """URL-mode submissions are safe regardless of data_classes —
        the user completes the elicitation off-system at the
        bank-overlay's URL surface; no restricted data crosses the
        portal HTTP boundary. Step 4 ONLY applies to form-mode."""
        from cognic_agentos.core.policy.engine import Decision

        ctx = dataclasses.replace(safe_ctx, data_classes=(restricted,))
        adapter = AsyncMock()
        adapter.get_context = AsyncMock(return_value=ctx)
        rego = AsyncMock()
        rego.evaluate = AsyncMock(
            return_value=Decision(allow=True, rule_matched="...", reasoning="", decision_data=None)
        )
        outcome = await evaluate_elicitation_submission(
            request=url_request,
            actor=actor,
            adapter=adapter,
            rego_engine=rego,
        )
        assert outcome.allowed is True
        assert outcome.reason is None


# ---------------------------------------------------------------------------
# Step 5 — Rego eval
# ---------------------------------------------------------------------------


class TestGateStep5RegoEngineUnwired:
    @pytest.mark.asyncio
    async def test_rego_None_yields_unwired_evaluator(
        self,
        url_request: _StubRequest,
        actor: _StubActor,
        safe_ctx: ElicitationContext,
    ) -> None:
        adapter = AsyncMock()
        adapter.get_context = AsyncMock(return_value=safe_ctx)
        outcome = await evaluate_elicitation_submission(
            request=url_request,
            actor=actor,
            adapter=adapter,
            rego_engine=None,
        )
        assert outcome.allowed is False
        assert outcome.reason == "elicitation_unwired_evaluator"
        assert outcome.ctx is safe_ctx


class TestGateStep5OpaMissing:
    """If OPA binary isn't installed at the bank-overlay deployment,
    the Rego engine raises `OpaNotInstalledError`. Gate maps to
    `elicitation_unwired_evaluator` (same closed-enum reason as
    rego_engine=None — operators read either as "Rego subsystem not
    available")."""

    @pytest.mark.asyncio
    async def test_OpaNotInstalledError_yields_unwired_evaluator(
        self,
        url_request: _StubRequest,
        actor: _StubActor,
        safe_ctx: ElicitationContext,
    ) -> None:
        from cognic_agentos.core.policy.engine import OpaNotInstalledError

        adapter = AsyncMock()
        adapter.get_context = AsyncMock(return_value=safe_ctx)
        rego = AsyncMock()
        rego.evaluate = AsyncMock(side_effect=OpaNotInstalledError("no opa"))
        outcome = await evaluate_elicitation_submission(
            request=url_request,
            actor=actor,
            adapter=adapter,
            rego_engine=rego,
        )
        assert outcome.allowed is False
        assert outcome.reason == "elicitation_unwired_evaluator"


class TestGateStep5RegoDeny:
    """Rego decision.allow=False → `elicitation_rego_denied`."""

    @pytest.mark.asyncio
    async def test_rego_decision_allow_False_yields_rego_denied(
        self,
        form_request: _StubRequest,
        actor: _StubActor,
        safe_ctx: ElicitationContext,
    ) -> None:
        from cognic_agentos.core.policy.engine import Decision

        adapter = AsyncMock()
        adapter.get_context = AsyncMock(return_value=safe_ctx)
        rego = AsyncMock()
        rego.evaluate = AsyncMock(
            return_value=Decision(allow=False, rule_matched="...", reasoning="", decision_data=None)
        )
        outcome = await evaluate_elicitation_submission(
            request=form_request,
            actor=actor,
            adapter=adapter,
            rego_engine=rego,
        )
        assert outcome.allowed is False
        assert outcome.reason == "elicitation_rego_denied"


class TestGateStep5RegoEvaluationError:
    """Rego engine internal failure (bundle invalid / evaluation error /
    bundle missing) → `elicitation_rego_denied` (fail-closed). Distinct
    from `elicitation_unwired_evaluator` (which means OPA itself is
    unavailable — recoverable by installing the binary); evaluation
    errors mean the gate cannot complete its Step 5 check + refuses
    to admit."""

    @pytest.mark.asyncio
    async def test_RegoEvaluationError_yields_rego_denied(
        self,
        url_request: _StubRequest,
        actor: _StubActor,
        safe_ctx: ElicitationContext,
    ) -> None:
        from cognic_agentos.core.policy.engine import RegoEvaluationError

        adapter = AsyncMock()
        adapter.get_context = AsyncMock(return_value=safe_ctx)
        rego = AsyncMock()
        rego.evaluate = AsyncMock(side_effect=RegoEvaluationError("opa crashed"))
        outcome = await evaluate_elicitation_submission(
            request=url_request,
            actor=actor,
            adapter=adapter,
            rego_engine=rego,
        )
        assert outcome.allowed is False
        assert outcome.reason == "elicitation_rego_denied"


# ---------------------------------------------------------------------------
# Green path + decision-point format
# ---------------------------------------------------------------------------


class TestGateGreenPath:
    @pytest.mark.asyncio
    async def test_all_green_returns_allowed_True_with_ctx(
        self,
        url_request: _StubRequest,
        actor: _StubActor,
        safe_ctx: ElicitationContext,
    ) -> None:
        from cognic_agentos.core.policy.engine import Decision

        adapter = AsyncMock()
        adapter.get_context = AsyncMock(return_value=safe_ctx)
        rego = AsyncMock()
        rego.evaluate = AsyncMock(
            return_value=Decision(allow=True, rule_matched="...", reasoning="", decision_data=None)
        )
        outcome = await evaluate_elicitation_submission(
            request=url_request,
            actor=actor,
            adapter=adapter,
            rego_engine=rego,
        )
        assert outcome.allowed is True
        assert outcome.reason is None
        assert outcome.ctx is safe_ctx


class TestRegoDecisionPointFormat:
    """The decision_point string is wire-protocol-public — the Rego
    bundle is keyed at the SAME path. Drift breaks the engine lookup."""

    @pytest.mark.asyncio
    async def test_decision_point_is_full_rego_query_string(
        self,
        url_request: _StubRequest,
        actor: _StubActor,
        safe_ctx: ElicitationContext,
    ) -> None:
        from cognic_agentos.core.policy.engine import Decision

        adapter = AsyncMock()
        adapter.get_context = AsyncMock(return_value=safe_ctx)
        rego = AsyncMock()
        rego.evaluate = AsyncMock(
            return_value=Decision(allow=True, rule_matched="...", reasoning="", decision_data=None)
        )
        await evaluate_elicitation_submission(
            request=url_request,
            actor=actor,
            adapter=adapter,
            rego_engine=rego,
        )
        assert rego.evaluate.call_count == 1
        kwargs = rego.evaluate.await_args.kwargs
        assert kwargs["decision_point"] == "data.cognic.ui.elicitation_submit.allow"
        # Input shape — verifies the gate threads the 6 documented keys
        # per the Rego bundle's documented input shape comment.
        assert set(kwargs["input"].keys()) == {
            "tenant_id",
            "elicitation_id",
            "originating_pack_id",
            "mode",
            "data_classes",
            "has_form_payload",
        }


# ---------------------------------------------------------------------------
# Three-way drift detector — Python (gate) ↔ Rego (bundle) ↔
#   protocol/mcp_capabilities._RESTRICTED_DATA_CLASSES (runtime canonical)
# ---------------------------------------------------------------------------


class TestRestrictedClassesThreeWayLockstep:
    """Per the user-locked Path B architectural doctrine: no runtime
    cross-module import enforces equality (gate stays self-contained;
    importing from `protocol/mcp_capabilities` in production code would
    introduce a portal → protocol-internal arrow that's not currently
    permitted). Each module declares its OWN local copy; this test
    imports from BOTH (and parses the Rego bundle) at test time only
    + asserts equality.

    Three legs:
      (a) `portal/api/ui/elicitation_gate._RESTRICTED_DATA_CLASSES`
      (b) `policies/_default/elicitation.rego` (`restricted_classes := {...}`)
      (c) `protocol/mcp_capabilities._RESTRICTED_DATA_CLASSES`
    """

    def test_gate_constant_matches_mcp_capabilities_canonical(self) -> None:
        from cognic_agentos.protocol.mcp_capabilities import (
            _RESTRICTED_DATA_CLASSES as MCP_CANONICAL,
        )

        assert _RESTRICTED_DATA_CLASSES == MCP_CANONICAL, (
            f"gate _RESTRICTED_DATA_CLASSES drift vs mcp_capabilities canonical: "
            f"gate={_RESTRICTED_DATA_CLASSES} vs canonical={MCP_CANONICAL}"
        )

    def test_rego_bundle_restricted_classes_matches_gate(self) -> None:
        rego_text = Path("policies/_default/elicitation.rego").read_text()
        # Parse `restricted_classes := {"a", "b", ...}` — single-line literal.
        match = re.search(r"restricted_classes\s*:=\s*\{([^}]+)\}", rego_text)
        assert match is not None, (
            "could not locate `restricted_classes := { ... }` in elicitation.rego"
        )
        rego_set = frozenset(s.strip().strip('"') for s in match.group(1).split(","))
        assert rego_set == _RESTRICTED_DATA_CLASSES, (
            f"Rego bundle restricted_classes drift vs gate _RESTRICTED_DATA_CLASSES: "
            f"rego={rego_set} vs gate={_RESTRICTED_DATA_CLASSES}"
        )

    def test_count_is_3(self) -> None:
        """Sentinel — extending this set is a deliberate plan-of-record
        edit + requires updating all 3 legs in the same commit. Pinning
        the count separately from the per-value assertions gives crisp
        drift-diagnosis."""
        assert len(_RESTRICTED_DATA_CLASSES) == 3


# ---------------------------------------------------------------------------
# ActionRejectionReason Literal pin — wire-protocol-public closed-enum
# ---------------------------------------------------------------------------


class TestActionRejectionReasonLiteralPinned:
    """`ActionRejectionReason` is wire-protocol-public per ADR-020 +
    AGENTS.md "Wire-protocol contracts" stop rule (carried in the
    `frontend_action.rejected` chain row's ``payload.reason`` field
    AND in the T11 POST /actions HTTP refusal body).

    The T8 gate body only emits 6 of the 10 values (`elicitation_*`
    refusals from Steps 1-5); the other 4 — `action_backend_deferred_*`
    (3 stub-path reasons for the non-submit_elicitation action_classes)
    + `elicitation_backend_failed` (raised from
    `adapter.handle_submission` AFTER the gate passes) — are emitted
    by the T11 action handler, NOT by this gate.

    Without an exact-set pin, a typo or accidental removal of one of
    the 4 non-gate values would land silently AND would later drift
    from the parallel Literal in the T9 DTO (which the T11 handler
    consumes). This pin catches the drift at T8 time; the T9 DTO will
    add a cross-module equality check (Literal-vs-Literal) that
    pins the two Literals lockstep.
    """

    def test_exact_10_value_set(self) -> None:
        assert set(get_args(ActionRejectionReason)) == {
            # Step 1 — adapter not wired (None OR kernel-default raises)
            "elicitation_backend_unwired",
            # Step 2 — adapter returned None for the elicitation_id
            "elicitation_unknown_id",
            # Step 3 — mode parity
            "elicitation_mode_not_permitted",
            # Step 4 — restricted-data-class intersection (form-mode only)
            "elicitation_restricted_data_class",
            # Step 5 — Rego refusal OR evaluation error
            "elicitation_rego_denied",
            # Step 5 — Rego subsystem unavailable
            "elicitation_unwired_evaluator",
            # Adapter backend failure AFTER gate passes (T11)
            "elicitation_backend_failed",
            # T11 stub paths for the 5 non-submit_elicitation action_classes
            "action_backend_deferred_to_sprint_13_5",
            "action_backend_deferred_no_run_primitive",
            "action_backend_deferred_sandbox_unwired",
        }

    def test_count_is_10(self) -> None:
        """Sentinel — extending this Literal is a deliberate plan-of-
        record edit + requires updating the T9 DTO's parallel Literal +
        the T11 action handler's stub-path branches in the same commit.
        Pinning the count separately from the per-value set gives
        crisp drift-diagnosis between "value added/removed" (count
        mismatch) and "value renamed" (count matches but set differs)."""
        assert len(get_args(ActionRejectionReason)) == 10
