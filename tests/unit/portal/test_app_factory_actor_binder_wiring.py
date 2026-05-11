"""Sprint 7B.2 T3 — ``create_app(actor_binder=..., pack_record_store=...)`` wiring.

Plan §"Task 3: Pack DTOs + sub-router scaffolding + app factory wiring"
mounts the pack router only when BOTH ``actor_binder`` and
``pack_record_store`` are provided. Pin all four wiring outcomes
(T3-R1 P2 closed the symmetric-warning gap so both partial-config
branches now emit closed-enum fail-loud warnings):

+----------+----------+---------+--------------------------------------+
| binder   | store    | mount?  | structured warning?                  |
+==========+==========+=========+======================================+
| None     | None     | NO      | NO (kernel default)                  |
+----------+----------+---------+--------------------------------------+
| set      | set      | YES     | NO                                   |
+----------+----------+---------+--------------------------------------+
| None     | set      | NO      | YES (actor_binder_required_…)        |
+----------+----------+---------+--------------------------------------+
| set      | None     | NO      | YES (pack_record_store_required_…)   |
+----------+----------+---------+--------------------------------------+

Both fail-loud branches emit structured warnings at the
``cognic_agentos.portal.api.app`` logger; mirrors the
``mcp.host_unavailable_in_image`` pattern in ``create_prod_app`` at
``portal/api/app.py:421-435``. Distinct ``reason`` enum values per
branch so operators can fingerprint WHICH half of the wiring boundary
is missing.

Watchpoints from the plan + T3-R1 P2 closure:

- (a) Fail-loud wiring on missing kwargs — pinned by caplog
  assertions on BOTH partial-config branches: ``actor_binder=None &&
  pack_record_store=set`` AND its T3-R1 P2 symmetric reciprocal
  ``actor_binder=set && pack_record_store=None``.
- (b) Router NOT mounted when wiring incomplete — pinned by the four
  test cases covering each row of the wiring table.
- (c) ``app.state`` attribute names stable across the test fixture
  pattern — every endpoint test in T4-T7 will read
  ``app.state.actor_binder`` and ``app.state.pack_record_store``
  by these exact names; a rename here breaks the downstream suite.
- (d) Defensive isolation — the binder is a singleton per-process;
  pinned by ``test_binder_identity_preserved_across_requests``.
"""

import logging
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor, ActorBinder

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


class _StubBinder:
    """Test-only :class:`ActorBinder` returning a fixed :class:`Actor`."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


class _StubStore:
    """Test-only :class:`PackRecordStore` stand-in. T3 does not invoke any
    storage method; T4-T7 will pin real interactions."""


def _human_actor() -> Actor:
    return Actor(
        subject="alice@bank.example",
        tenant_id="t1",
        scopes=frozenset({"pack.submit"}),
        actor_type="human",
    )


def _pack_router_is_mounted(app: FastAPI) -> bool:
    """T3 ships an EMPTY router (T4-T7 will populate); an empty router
    contributes zero entries to ``app.routes`` when included via
    ``app.include_router``, so we cannot detect the mount by grepping
    paths. Source-side sets ``app.state.pack_router_mounted: bool`` at
    factory-body time as the introspection flag instead — this helper
    reads that flag. Forward-compatible: T4-T7 sub-route additions do
    not change the flag's source of truth."""
    return bool(getattr(app.state, "pack_router_mounted", False))


# ---------------------------------------------------------------------------
# Wiring outcomes (4 rows of the table in the docstring)
# ---------------------------------------------------------------------------


def test_create_app_neither_binder_nor_store_no_mount_no_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Kernel default: both None → no pack router mounted; no warning
    emitted (this is the expected baseline, not a misconfig)."""
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app()
    # Force lifespan startup so app.state.* is populated.
    with TestClient(app):
        assert getattr(app.state, "actor_binder", "MISSING") is None
        assert getattr(app.state, "pack_record_store", "MISSING") is None
    assert not _pack_router_is_mounted(app)
    warnings = [r for r in caplog.records if "packs_router" in r.message]
    assert warnings == []


def test_create_app_both_binder_and_store_mounts_pack_router(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Happy path: both provided → pack router mounted at
    ``/api/v1/packs``; ``app.state`` carries both objects identically;
    no warning emitted."""
    binder: ActorBinder = _StubBinder(_human_actor())
    store = _StubStore()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(actor_binder=binder, pack_record_store=store)  # type: ignore[arg-type]
    with TestClient(app):
        assert app.state.actor_binder is binder
        assert app.state.pack_record_store is store
    assert _pack_router_is_mounted(app)
    warnings = [r for r in caplog.records if "packs_router" in r.message]
    assert warnings == []


def test_create_app_store_without_binder_warns_and_does_not_mount(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Fail-loud misconfig: pack store provided but no actor binder →
    pack router NOT mounted (cannot enforce RBAC without a binder);
    structured warning emitted at the
    ``cognic_agentos.portal.api.app`` logger with closed-enum
    ``reason`` field. Mirrors the ``mcp.host_unavailable_in_image``
    pattern in :func:`create_prod_app`."""
    store = _StubStore()
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(pack_record_store=store)  # type: ignore[arg-type]
    with TestClient(app):
        assert app.state.actor_binder is None
        assert app.state.pack_record_store is store
    assert not _pack_router_is_mounted(app)
    warnings = [
        r
        for r in caplog.records
        if "portal.packs_router_unmounted_actor_binder_missing" in r.message
    ]
    assert len(warnings) == 1
    record = warnings[0]
    assert getattr(record, "reason", None) == "actor_binder_required_for_pack_router"
    # Remediation text must call out the explicit kwarg name so an
    # operator reading the log knows where to wire the binder.
    assert "actor_binder" in getattr(record, "remediation", "")


def test_create_app_binder_without_store_warns_and_does_not_mount(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Symmetric fail-loud misconfig (T3-R1 P2 closure): actor binder
    provided but no pack store → pack router NOT mounted (cannot serve
    endpoints without backing storage); structured warning emitted at
    the ``cognic_agentos.portal.api.app`` logger with closed-enum
    ``reason`` field. Mirrors the reciprocal
    ``actor_binder_required_for_pack_router`` branch so operators can
    fingerprint WHICH half of the wiring boundary is missing.

    Pre-R1 doctrine: this branch was silent; reviewer found that a
    half-wired deployment (binder configured, store missing) would
    silently disable the pack API in production with no operator
    signal. Symmetric coverage closes the gap."""
    binder: ActorBinder = _StubBinder(_human_actor())
    with caplog.at_level(logging.WARNING, logger="cognic_agentos.portal.api.app"):
        app = create_app(actor_binder=binder)
    with TestClient(app):
        assert app.state.actor_binder is binder
        assert app.state.pack_record_store is None
    assert not _pack_router_is_mounted(app)
    warnings = [
        r
        for r in caplog.records
        if "portal.packs_router_unmounted_pack_record_store_missing" in r.message
    ]
    assert len(warnings) == 1
    record = warnings[0]
    assert getattr(record, "reason", None) == "pack_record_store_required_for_pack_router"
    # Remediation text must call out the explicit kwarg name so an
    # operator reading the log knows where to wire the store.
    assert "pack_record_store" in getattr(record, "remediation", "")


# ---------------------------------------------------------------------------
# Watchpoint (d) — binder identity preserved across requests
# ---------------------------------------------------------------------------


def test_binder_identity_preserved_across_requests() -> None:
    """Plan watchpoint (d) — the binder is a singleton per-process;
    ``app.state.actor_binder`` MUST return the SAME object across
    requests. Pin via two consecutive requests against the same app."""
    binder: ActorBinder = _StubBinder(_human_actor())
    store = _StubStore()
    app = create_app(actor_binder=binder, pack_record_store=store)  # type: ignore[arg-type]
    # Add a lightweight probe route that reflects the binder identity
    # back to the test. T3 ships an empty pack router so we cannot use
    # a real endpoint yet; the probe lives on the test app only.
    captured: list[Any] = []

    @app.get("/_test_probe")
    def probe(request: Request) -> dict[str, str]:
        captured.append(request.app.state.actor_binder)
        return {"ok": "true"}

    # TestClient as context manager so lifespan startup fires and the
    # binder attaches to ``app.state.actor_binder``. Without the
    # ``with`` block, lifespan does NOT run and the probe sees an
    # AttributeError on ``request.app.state.actor_binder``.
    with TestClient(app) as client:
        client.get("/_test_probe")
        client.get("/_test_probe")
    assert len(captured) == 2
    # Identity preserved — not just equal, but the same Python object.
    assert captured[0] is captured[1] is binder


# ---------------------------------------------------------------------------
# Watchpoint (c) — app.state attribute name stability
# ---------------------------------------------------------------------------


def test_app_state_attribute_names_are_actor_binder_and_pack_record_store() -> None:
    """Pin the exact attribute names. Every T4-T7 endpoint test reads
    ``app.state.actor_binder`` and ``app.state.pack_record_store`` by
    these names; a rename here propagates as a wide-blast-radius break."""
    binder: ActorBinder = _StubBinder(_human_actor())
    store = _StubStore()
    app = create_app(actor_binder=binder, pack_record_store=store)  # type: ignore[arg-type]
    with TestClient(app):
        assert hasattr(app.state, "actor_binder")
        assert hasattr(app.state, "pack_record_store")
