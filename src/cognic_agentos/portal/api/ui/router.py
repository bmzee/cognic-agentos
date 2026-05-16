"""Sprint-7B.4 T12 — UI router composition factory.

Composes the T10 stream router + T11 action router into a single
:class:`APIRouter` mounted at ``/api/v1/ui``. Threads the closure-
capture deps (``broker`` + ``settings`` + ``decision_history_store``
for stream routes; ``broker`` + ``elicitation_adapter`` +
``rego_engine`` for action routes).

The factory is the SINGLE production wiring point — ``create_app``
calls it; tests inject the same broker via the ``broker=`` kwarg on
``create_app`` so the routes use the SAME broker the tests inspect.

NOTE: ``from __future__ import annotations`` is DELIBERATELY OMITTED
per the standing FastAPI invariant."""

from fastapi import APIRouter

from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.policy.engine import OPAEngine
from cognic_agentos.portal.api.ui.action_routes import build_action_routes
from cognic_agentos.portal.api.ui.stream_routes import build_stream_routes
from cognic_agentos.protocol.elicitation_adapter import ElicitationAdapter
from cognic_agentos.protocol.ui_events import UIEventBroker


def build_ui_routes(
    *,
    broker: UIEventBroker,
    settings: Settings,
    decision_history_store: DecisionHistoryStore,
    elicitation_adapter: ElicitationAdapter | None = None,
    rego_engine: OPAEngine | None = None,
) -> APIRouter:
    """Build the composed UI router.

    T12 plan-vs-reality drift: the plan §4964 omitted ``settings=`` +
    ``decision_history_store=`` from the ``build_stream_routes(...)``
    call — they're REQUIRED per T10's closure-capture pattern (drift #1
    on T10). Threaded here so the stream router can resolve them
    without reading ``request.app.state.*``.

    ``elicitation_adapter`` + ``rego_engine`` are optional — actions
    that need them surface the matching
    ``elicitation_backend_unwired`` / ``elicitation_unwired_evaluator``
    closed-enum refusal when absent.
    """
    router = APIRouter(prefix="/api/v1/ui")
    router.include_router(
        build_stream_routes(
            broker=broker,
            settings=settings,
            decision_history_store=decision_history_store,
        ),
    )
    router.include_router(
        build_action_routes(
            broker=broker,
            elicitation_adapter=elicitation_adapter,
            rego_engine=rego_engine,
        ),
    )
    return router


__all__ = [
    "build_ui_routes",
]
