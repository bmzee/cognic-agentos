"""P2 — the lifespan must publish app.state.run_record_store (2026-06-20, ADR-005)."""

from cognic_agentos.portal.api.app import create_app


def test_app_state_preseeds_run_record_store_to_none() -> None:
    # Before any lifespan runs, the attribute exists and is None (so the
    # request-time dep can `getattr(..., None)` without AttributeError).
    app = create_app()
    assert getattr(app.state, "run_record_store", "MISSING") is None
