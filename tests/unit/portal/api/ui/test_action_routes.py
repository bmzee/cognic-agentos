"""Sprint 7B.4 T11 — POST /api/v1/ui/actions: dispatch + RequireUIAction
+ 5 stubs + submit_elicitation gate routing.

Per ADR-020 §22 + spec §4.4d-i. Tests cover:

  - Discriminated-union body parsing for all 6 action_class values
  - Per-class scope enforcement (``ui.action.<class>``) via RequireUIAction
  - Fail-closed on broker emit failure (500 ``rbac_denial_emit_failed``
    surfaces; NO silent 403)
  - 5 stub paths return 200 + outcome=rejected + closed-enum reason
    + chain-row pair (submitted + rejected)
  - submit_elicitation routes through the T8 elicitation_gate
  - ActionResponse ``submitted_event_id`` matches the chain-derived
    deterministic cursor

T11 fixtures (``app_with_scopes`` / ``app_with_only_approve`` /
``app_no_adapter`` / ``app_with_scopes_and_broker`` /
``actor_t1_all_ui_scopes`` / ``actor_t1_only_approve``) live in
:file:`conftest.py` so the sibling correlation-latency test file can
share them (pytest fixtures defined in a test module are only visible
within that module; cross-file sharing requires conftest)."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI

from cognic_agentos.protocol.ui_events import UIEventBroker
from tests.unit.portal.api.ui.sse_test_helpers import (
    _async_client,
    _read_recent_decision_history_rows,
)


class TestRequireUIActionParsesDiscriminatedUnion:
    """Pydantic v2 ``Field(discriminator="action_class")`` resolves the
    body to the correct per-class DTO; all 6 classes parse to 200."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("action_class", "body_extra"),
        [
            ("approve", {"approval_id": "ap_1", "decision": "grant"}),
            ("deny", {"approval_id": "ap_1"}),
            ("cancel_run", {"run_id": "run_1"}),
            ("interrupt", {"run_id": "run_1"}),
            ("resume", {"run_id": "run_1"}),
            (
                "submit_elicitation",
                {
                    "elicitation_id": "elc_1",
                    "mode": "url",
                    "url_completion_signal": {"ok": True},
                },
            ),
        ],
    )
    async def test_each_class_parses(
        self, app_with_scopes: FastAPI, action_class: str, body_extra: dict[str, Any]
    ) -> None:
        async with _async_client(app_with_scopes) as c:
            r = await c.post(
                "/api/v1/ui/actions",
                json={"action_class": action_class, **body_extra},
            )
        assert r.status_code == 200, r.text


class TestRequireUIActionEnforcesPerClassScope:
    """Per-class scope mapping ``ui.action.<class>`` — actor with
    ``ui.action.approve`` but NOT ``ui.action.deny``: approve passes
    the dep; deny refuses with ``policy.rbac_denied`` + 403."""

    @pytest.mark.asyncio
    async def test_approve_passes_when_actor_has_approve_scope(
        self, app_with_only_approve: FastAPI
    ) -> None:
        async with _async_client(app_with_only_approve) as c:
            r = await c.post(
                "/api/v1/ui/actions",
                json={
                    "action_class": "approve",
                    "approval_id": "ap_1",
                    "decision": "grant",
                },
            )
        assert r.status_code == 200

    @pytest.mark.asyncio
    async def test_deny_refused_with_scope_not_held(
        self, app_with_only_approve: FastAPI, broker: UIEventBroker
    ) -> None:
        async with _async_client(app_with_only_approve) as c:
            r = await c.post(
                "/api/v1/ui/actions",
                json={"action_class": "deny", "approval_id": "ap_1"},
            )
        assert r.status_code == 403
        assert r.json()["detail"]["reason"] == "scope_not_held"
        assert r.json()["detail"]["required_scope"] == "ui.action.deny"
        # Chain row emitted via _emit_denial_or_500 → broker.emit_rbac_denial
        rows = await _read_recent_decision_history_rows(broker)
        assert any(row.event_type == "rbac.scope_not_held" for row in rows)


class TestRequireUIActionFailClosedOnEmitFailure:
    """Threat-model-revert pin: broker.emit_rbac_denial raising MUST
    surface as 500 ``rbac_denial_emit_failed``, NOT a silent 403 with
    no chain row. The fail-closed contract lives inside the shared
    ``_emit_denial_or_500`` helper in ``portal/rbac/enforcement.py`` —
    if a future RequireUIAction refactor stops routing through that
    helper, this test catches the regression."""

    @pytest.mark.asyncio
    async def test_emit_failure_500_not_silent_403(
        self,
        app_with_only_approve: FastAPI,
        broker: UIEventBroker,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from unittest.mock import AsyncMock

        monkeypatch.setattr(
            broker,
            "emit_rbac_denial",
            AsyncMock(side_effect=RuntimeError("simulated emit failure")),
        )
        async with _async_client(app_with_only_approve) as c:
            r = await c.post(
                "/api/v1/ui/actions",
                json={"action_class": "deny", "approval_id": "ap_1"},
            )
        assert r.status_code == 500
        assert r.json()["detail"]["reason"] == "rbac_denial_emit_failed"


class TestStubsReturn200WithDeferredReason:
    """5 non-submit_elicitation action_classes route to a deferred-stub
    rejected response. Body shape: 200 + outcome=rejected + closed-enum
    reason. Chain rows: BOTH ``frontend_action.submitted`` (audit
    completeness) AND ``frontend_action.rejected`` (resolution)."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("action_class", "expected_reason"),
        [
            ("approve", "action_backend_deferred_to_sprint_13_5"),
            ("deny", "action_backend_deferred_to_sprint_13_5"),
            ("cancel_run", "action_backend_deferred_no_run_primitive"),
            ("interrupt", "action_backend_deferred_no_run_primitive"),
            ("resume", "action_backend_deferred_sandbox_unwired"),
        ],
    )
    async def test_stub_emits_2_chain_rows(
        self,
        app_with_scopes: FastAPI,
        broker: UIEventBroker,
        action_class: str,
        expected_reason: str,
    ) -> None:
        body_extra = {
            "approve": {"approval_id": "ap_1", "decision": "grant"},
            "deny": {"approval_id": "ap_1"},
            "cancel_run": {"run_id": "run_1"},
            "interrupt": {"run_id": "run_1"},
            "resume": {"run_id": "run_1"},
        }[action_class]
        async with _async_client(app_with_scopes) as c:
            r = await c.post(
                "/api/v1/ui/actions",
                json={"action_class": action_class, **body_extra},
            )
        assert r.status_code == 200
        body = r.json()
        assert body["outcome"] == "rejected"
        assert body["reason"] == expected_reason
        # 2 chain rows: submitted + rejected. Order matters for
        # examiner trace assembly (submitted FIRST so resolution can
        # reference its event_id as the ``submitted_event_id`` cursor).
        rows = await _read_recent_decision_history_rows(broker)
        assert any(row.event_type == "frontend_action.submitted" for row in rows)
        assert any(row.event_type == "frontend_action.rejected" for row in rows)


class TestSubmitElicitationRoutedThroughGate:
    """submit_elicitation requests route through the T8
    ``evaluate_elicitation_submission`` gate.

    Three paths exercised here:

      - ``adapter=None`` → Step 1 gate refusal
        (``elicitation_backend_unwired``).
      - ``adapter`` + ``rego_engine`` (allow=True) + adapter green →
        ``frontend_action.accepted`` row + 200/outcome=accepted/reason=None.
      - ``adapter`` + ``rego_engine`` (allow=True) + adapter raises →
        ``frontend_action.rejected`` row with
        ``elicitation_backend_failed`` (distinguishes "gate refused"
        from "backend rejected" in audit logs).

    R3 P1 #1 fix: T11's original test set only covered the
    adapter-unwired path; the gate-green adapter dispatch + the
    backend-exception translation were untested — a regression that
    skipped backend dispatch or stopped emitting accepted rows would
    have passed. The 2 new tests below close that gap."""

    @pytest.mark.asyncio
    async def test_submit_elicitation_unwired_adapter_returns_backend_unwired(
        self, app_no_adapter: FastAPI
    ) -> None:
        async with _async_client(app_no_adapter) as c:
            r = await c.post(
                "/api/v1/ui/actions",
                json={
                    "action_class": "submit_elicitation",
                    "elicitation_id": "elc_1",
                    "mode": "url",
                    "url_completion_signal": {"ok": True},
                },
            )
        assert r.status_code == 200
        assert r.json()["outcome"] == "rejected"
        assert r.json()["reason"] == "elicitation_backend_unwired"

    @pytest.mark.asyncio
    async def test_submit_elicitation_green_path_emits_accepted(
        self,
        app_with_scopes_and_allow_rego: FastAPI,
        broker: UIEventBroker,
    ) -> None:
        """Green path — gate passes (adapter + allow-rego both wired);
        ``adapter.handle_submission`` runs successfully; route emits
        ``frontend_action.accepted`` chain row + returns 200 with
        ``outcome=accepted`` + ``reason=None``."""
        async with _async_client(app_with_scopes_and_allow_rego) as c:
            r = await c.post(
                "/api/v1/ui/actions",
                json={
                    "action_class": "submit_elicitation",
                    "elicitation_id": "elc_green",
                    "mode": "url",
                    "url_completion_signal": {"ok": True},
                },
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["outcome"] == "accepted"
        assert body["reason"] is None
        # Chain rows: submitted + accepted (NOT rejected — gate-green
        # path doesn't emit a rejection).
        rows = await _read_recent_decision_history_rows(broker)
        assert any(row.event_type == "frontend_action.submitted" for row in rows)
        assert any(row.event_type == "frontend_action.accepted" for row in rows)
        assert not any(row.event_type == "frontend_action.rejected" for row in rows)

    @pytest.mark.asyncio
    async def test_submit_elicitation_backend_exception_returns_backend_failed(
        self,
        app_with_scopes_and_allow_rego: FastAPI,
        broker: UIEventBroker,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Backend-exception path — gate passes; adapter's
        ``handle_submission`` raises (simulating a backend connectivity
        or business failure AFTER the gate green-lit the request); the
        action handler catches the exception + emits
        ``frontend_action.rejected`` with closed-enum
        ``elicitation_backend_failed`` (distinct from gate refusals so
        examiners can tell "backend rejected" apart from "gate refused"
        in audit logs without re-running the gate)."""
        from cognic_agentos.protocol.elicitation_adapter import ElicitationBackendError

        # Monkey-patch the stub adapter's handle_submission to raise.
        # Reach the adapter via the closure-captured factory args is
        # awkward; instead, monkey-patch the import site so any
        # _StubElicitationAdapter instance's bound method raises.
        from tests.unit.portal.api.ui import conftest as _ui_conftest

        async def _raising_handle_submission(
            self: Any, *, ctx: Any, mode: Any, payload: dict[str, Any]
        ) -> Any:
            raise ElicitationBackendError("simulated backend rejection")

        monkeypatch.setattr(
            _ui_conftest._StubElicitationAdapter,
            "handle_submission",
            _raising_handle_submission,
        )
        async with _async_client(app_with_scopes_and_allow_rego) as c:
            r = await c.post(
                "/api/v1/ui/actions",
                json={
                    "action_class": "submit_elicitation",
                    "elicitation_id": "elc_backend_fail",
                    "mode": "url",
                    "url_completion_signal": {"ok": True},
                },
            )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["outcome"] == "rejected"
        assert body["reason"] == "elicitation_backend_failed"
        # Chain rows: submitted + rejected (with elicitation_backend_failed
        # reason on the rejected row's payload).
        rows = await _read_recent_decision_history_rows(broker)
        assert any(row.event_type == "frontend_action.submitted" for row in rows)
        rejected_rows = [row for row in rows if row.event_type == "frontend_action.rejected"]
        assert rejected_rows
        assert rejected_rows[0].payload["reason"] == "elicitation_backend_failed"


class TestActionResponseEventIdCursorsMatchSSE:
    """The ``submitted_event_id`` on the response body MUST equal the
    deterministic ``_chain_derived_event_id`` for the
    ``frontend_action.submitted`` chain row that the request appended.
    SSE consumers use this to reconcile the POST response with the
    stream event without a round-trip cursor."""

    @pytest.mark.asyncio
    async def test_submitted_event_id_matches_chain_derived_cursor(
        self, app_with_scopes: FastAPI, broker: UIEventBroker
    ) -> None:
        async with _async_client(app_with_scopes) as c:
            r = await c.post(
                "/api/v1/ui/actions",
                json={
                    "action_class": "approve",
                    "approval_id": "ap_1",
                    "decision": "grant",
                },
            )
        body = r.json()
        rows = await _read_recent_decision_history_rows(broker)
        submitted_row = next(row for row in rows if row.event_type == "frontend_action.submitted")
        from cognic_agentos.protocol.ui_events import _chain_derived_event_id

        expected = _chain_derived_event_id(
            chain_id="decision_history",
            sequence=submitted_row.sequence,
            ordinal=0,
            family="frontend_action",
            type_="submitted",
        )
        assert body["submitted_event_id"] == expected
