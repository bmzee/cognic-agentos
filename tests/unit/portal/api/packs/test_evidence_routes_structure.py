"""Sprint 7B.3 T3 Slice D — :func:`build_evidence_routes` structure tests.

Pins the route-factory shape contract WITHOUT spinning up a full
FastAPI :class:`TestClient` (the end-to-end behavioural tests live in
``test_evidence_panel_routes.py`` per plan §292). This module covers:

- :data:`EvidencePanelRefusalReason` closed-enum 3-value vocabulary
  (drift detector + count guard + disjointness against upstream
  RBAC / tenant-isolation literals).
- :func:`build_evidence_routes` factory shape (returns
  :class:`APIRouter`, no prefix, single GET route at the T3 path).
- Module-header invariant pin: NO ``from __future__ import annotations``
  (FastAPI dependency-injection compatibility — string-deferred
  annotations break ``inspect.signature`` resolution on
  ``Annotated[..., Depends(<closure-local>)]`` parameters).

The route-level integration tests (RBAC denial, tenant-isolation 404,
cross-tenant 404, 409 refusal reasons, happy-path projection) ship in
``test_evidence_panel_routes.py`` at Slice F.
"""

from __future__ import annotations

import ast
import typing
from pathlib import Path

import pytest
from fastapi import APIRouter

from cognic_agentos.packs.storage import PackRecordStore
from cognic_agentos.portal.api.packs import build_packs_router
from cognic_agentos.portal.api.packs import evidence_routes as _module
from cognic_agentos.portal.api.packs.evidence_routes import (
    EvidencePanelRefusalReason,
    build_evidence_routes,
)
from cognic_agentos.portal.rbac.enforcement import RBACDenialReason
from cognic_agentos.portal.rbac.tenant_isolation import TenantIsolationFailure


class TestSprint7B3T3SliceDEvidencePanelRefusalReason:
    """Drift detectors for :data:`EvidencePanelRefusalReason`."""

    _EXPECTED_VALUES: frozenset[str] = frozenset(
        {
            "pack_not_yet_submitted",
            "manifest_evidence_not_persisted",
            "pack_kind_mismatch",
        }
    )

    def test_exact_value_set(self) -> None:
        """Lock the exact 3-value vocabulary per plan §300."""
        assert frozenset(typing.get_args(EvidencePanelRefusalReason)) == self._EXPECTED_VALUES

    def test_exact_count(self) -> None:
        """Count guard pinned independently for crisp drift-diagnosis."""
        assert len(typing.get_args(EvidencePanelRefusalReason)) == 3

    def test_disjoint_from_rbac_denial_reason(self) -> None:
        """Route-owned vocab MUST NOT collide with the RBAC layer's
        denial reasons (a single response body's ``reason`` field
        carries either an RBAC reason on 403/500 OR an evidence-panel
        reason on 409 — they must not share string values)."""
        ours = frozenset(typing.get_args(EvidencePanelRefusalReason))
        upstream = frozenset(typing.get_args(RBACDenialReason))
        assert ours & upstream == frozenset()

    def test_disjoint_from_tenant_isolation_failure(self) -> None:
        """Route-owned vocab MUST NOT collide with the tenant-isolation
        layer's failure reasons (404 ``tenant_id_mismatch`` /
        ``pack_not_found`` / etc. must be disambiguatable from the 409
        evidence-panel reasons)."""
        ours = frozenset(typing.get_args(EvidencePanelRefusalReason))
        upstream = frozenset(typing.get_args(TenantIsolationFailure))
        assert ours & upstream == frozenset()


class TestSprint7B3T3SliceDBuildEvidenceRoutesShape:
    """Factory shape pins."""

    def test_returns_apirouter(self) -> None:
        """Factory MUST return a :class:`fastapi.APIRouter` (mirrors
        the T5 :func:`build_review_routes` + T6
        :func:`build_operator_routes` pattern)."""
        # Factory does NOT call store at construct time — None-cast is safe.
        store = typing.cast(PackRecordStore, object())
        router = build_evidence_routes(store=store)
        assert isinstance(router, APIRouter)

    def test_registers_data_governance_panel_route(self) -> None:
        """The T3 route ``GET /{pack_id}/evidence/data-governance`` MUST
        be present on the returned router. Wire-protocol-public path
        per plan §299; renaming breaks every bank-overlay's evidence-
        panel consumer."""
        store = typing.cast(PackRecordStore, object())
        router = build_evidence_routes(store=store)
        compiled_paths = {
            (route.path, frozenset(route.methods))
            for route in router.routes
            if hasattr(route, "path") and hasattr(route, "methods")
        }
        assert ("/{pack_id}/evidence/data-governance", frozenset({"GET"})) in compiled_paths

    def test_t3_registers_exactly_one_route(self) -> None:
        """Slice D ships ONE handler — the data-governance panel.
        T4-T6 extend the SAME factory with risk-tier / supply-chain /
        conformance panels per plan §294. Pin the T3 count so a
        future slice extension flips this test on visibility."""
        store = typing.cast(PackRecordStore, object())
        router = build_evidence_routes(store=store)
        route_count = sum(
            1 for route in router.routes if hasattr(route, "path") and hasattr(route, "methods")
        )
        assert route_count == 1


class TestSprint7B3T3SliceERouterWiring:
    """Pin the production wiring at :func:`build_packs_router` so the
    full path ``GET /api/v1/packs/{pack_id}/evidence/data-governance``
    is exposed by the deployed app (not just at the un-mounted
    sub-router shape level)."""

    def test_packs_router_includes_data_governance_panel_path(self) -> None:
        store = typing.cast(PackRecordStore, object())
        parent = build_packs_router(store=store)
        compiled_paths = {
            (route.path, frozenset(route.methods))
            for route in parent.routes
            if hasattr(route, "path") and hasattr(route, "methods")
        }
        assert (
            "/api/v1/packs/{pack_id}/evidence/data-governance",
            frozenset({"GET"}),
        ) in compiled_paths


class TestSprint7B3T3SliceDModuleHeaderInvariant:
    """Pin the no-future-annotations invariant per AGENTS.md doctrine.

    The T6 / T7 portal-pack route modules carry the same constraint
    documented at ``operator_routes.py`` + ``inspection_routes.py``
    module headers — PEP 563 string-deferred annotations would break
    FastAPI's ``inspect.signature()`` / ``typing.get_type_hints()``
    resolution on ``Annotated[..., Depends(<closure-local>)]`` for the
    closure-local ``RequireScope(...)`` + ``RequireTenantOwnership(...)``
    instances inside :func:`build_evidence_routes`.

    Pin via AST scan rather than runtime check — runtime symptoms
    (FastAPI treating handler params as query params) are subtle +
    test-coverage-resistant.
    """

    def test_module_does_not_carry_future_annotations_import(self) -> None:
        module_source = Path(_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(module_source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                imported = {alias.name for alias in node.names}
                if "annotations" in imported:
                    pytest.fail(
                        "evidence_routes.py MUST NOT `from __future__ import "
                        "annotations` — PEP 563 string-deferred annotations "
                        "break FastAPI dep-injection resolution on closure-"
                        "local Depends(...) parameters; mirrors operator_routes.py "
                        "+ inspection_routes.py doctrine."
                    )
