"""Sprint 7B.2 T6 — operator surface test surface (post-slice-4 final shape).

Plan §"Task 6: Operator surface endpoints" — pins the 5 operator
endpoints behind ``/api/v1/packs``:

- ``POST   /api/v1/packs/{pack_id}/allow-list`` (gated by
  :func:`RequireHumanActor` per Round 1 P3 #8)
- ``POST   /api/v1/packs/{pack_id}/install``
- ``POST   /api/v1/packs/{pack_id}/disable``
- ``POST   /api/v1/packs/{pack_id}/revoke`` (multi-from:
  installed/disabled → revoked)
- ``DELETE /api/v1/packs/{pack_id}/install`` (uninstall — multi-from:
  disabled/revoked → uninstalled)

Test surface organised into 6 test classes + 1 top-level AST self-test
(52 tests total post-slice-4):

1. ``test_module_must_not_import_future_annotations`` (Standing-offer
   §30 — AST self-test load-bearing for FastAPI closure-cell
   resolution; paired with the per-verb invocation tests below per
   ``feedback_security_regression_hardening.md`` — threat-model-revert
   verified at slice-1 + slice-2 + slice-4 boundaries).
2. :class:`TestSprint7B2OperatorRoutesProductionWiring` (Plan R18 P2 #3
   — `build_packs_router` includes all 5 operator paths AND the
   `/install` path carries BOTH POST + DELETE methods).
3. :class:`TestSprint7B2OperatorRoutesPathParamConvention` (parametrized
   over 4 distinct paths — every operator endpoint uses ``{pack_id}``
   matching the shared ``RequireTenantOwnership(pack_id_param="pack_id")``
   dependency).
4. :class:`TestSprint7B2OperatorRequestIdPrefixBounded` (Plan R18 P2 #4
   / Round 19 P3 #3 — parametrized over 5 prefixes; invariant
   ``len(prefix) + 32 <= 64`` pinned by module-foot build-time assert).
5. Per-endpoint handler test classes:

   - :class:`TestSprint7B2AllowListEndpoint` — happy path + green-path
     ``portal.packs.allow_list`` structured log carrying
     ``actor_type="human"`` + chain row ``payload["actor_type"]``
     primary surface (R24 Path B + B2 watchpoint (d) closure) +
     :class:`RequireHumanActor` admit/refuse pair (mutually-exclusive
     log contract R19 P2 #2) + scope/tenant siblings + state-machine
     refusal + R27-hardened :class:`PackNotFound` race (caplog
     assertion on ``portal.packs.allow_list_refused``).
   - :class:`TestSprint7B2InstallEndpoint` + :class:`TestSprint7B2DisableEndpoint`
     — symmetric single-from-state pair (``allow_listed → installed``
     + ``installed → disabled``); each verb pins the chain-row
     ``actor_type`` (R24 carry-forward) + request-id prefix + scope/
     tenant siblings + state-machine refusal with per-transition vs
     legal-pair-fallback closed-enum reasons + R27-hardened race.
   - :class:`TestSprint7B2RevokeEndpoint` — multi-from happy paths
     (``installed`` AND ``disabled`` → revoked, both legs explicit)
     + idempotency-409 (re-revoke surfaces closed-enum
     ``lifecycle_transition_revoke_already_revoked``) + actor_type +
     request-id + scope/tenant siblings + R27-hardened race.
   - :class:`TestSprint7B2UninstallEndpoint` — DELETE method on the
     ``/install`` path; multi-from happy paths (``disabled`` AND
     ``revoked`` → uninstalled, both legs explicit) + per-transition
     refusal (``lifecycle_transition_uninstall_not_revoked_or_disabled``
     when from-state is ``installed``) + actor_type + request-id +
     scope/tenant siblings + R27-hardened race.

R24 amendments to :meth:`PackRecordStore.transition` (the
``actor_type: str | None = None`` keyword-only kwarg threaded into
``payload["actor_type"]`` conditionally) live in ``tests/unit/packs/
test_storage.py`` — 3 storage-level regressions pin the additive-
schema contract (omission when not supplied; persistence as ``"human"``;
persistence as ``"service"``).
"""

from __future__ import annotations

import ast
import logging
import pathlib
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.packs.storage import PackNotFound, PackRecord, PackRecordStore
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.api.packs import build_packs_router, operator_routes
from cognic_agentos.portal.rbac.actor import Actor

# ---------------------------------------------------------------------------
# Stub store for route-table inspection tests
# ---------------------------------------------------------------------------


class _StubStore:
    """Test-only :class:`PackRecordStore` stand-in for route-table
    assertions (those tests don't invoke store methods). Mirrors
    ``test_review_routes.py::_StubStore``. Real SQLite-backed store
    via the ``store`` fixture below is used for per-verb endpoint
    invocation tests."""


# ---------------------------------------------------------------------------
# Stub actor binder + fixtures (mirrors test_review_routes.py:73-209)
# ---------------------------------------------------------------------------


class _StubBinder:
    """Test-only :class:`ActorBinder` returning a configured actor.
    Mirrors ``test_review_routes.py::_StubBinder``."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_operator_actor(
    *,
    subject: str = "operator@bank.example",
    tenant_id: str = "t1",
    scopes: frozenset[str] | None = None,
    actor_type: str = "human",
) -> Actor:
    """Build a fixture :class:`Actor` carrying all 5 operator-surface
    scopes by default. The allow-list endpoint additionally requires
    ``actor_type == "human"`` (override to ``"service"`` for the
    slice-2 service-actor refusal test).
    """
    if scopes is None:
        scopes = frozenset(
            {
                "pack.allow_list",
                "pack.install",
                "pack.disable",
                "pack.revoke",
                "pack.uninstall",
            }
        )
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=scopes,  # type: ignore[arg-type]
        actor_type=actor_type,  # type: ignore[arg-type]
    )


@pytest.fixture
async def engine(tmp_path: Any) -> AsyncIterator[AsyncEngine]:
    """SQLite engine seeded with governance schema + chain heads —
    mirrors ``test_review_routes.py::engine``."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'operator_routes.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="decision_history",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=datetime.now(UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
async def store(engine: AsyncEngine) -> PackRecordStore:
    return PackRecordStore(engine)


def _build_app(*, actor: Actor, store: PackRecordStore) -> FastAPI:
    """Build a portal app via :func:`create_app` with the given
    binder + store; mirrors ``test_review_routes.py::_build_app``."""
    return create_app(
        actor_binder=_StubBinder(actor),
        pack_record_store=store,
    )


async def _seed_draft_pack(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    created_by: str = "alice@bank.example",
) -> PackRecord:
    """Save a draft pack at the actor's tenant — used by the state-
    machine refusal tests (e.g. install on draft, disable on draft)
    that need a pack whose from-state is OUTSIDE the verb's legal
    from-state set so the closed-enum reason fires. Per-verb green-
    path tests use the matching ``_seed_<state>_pack`` helper instead."""
    now = datetime.now(UTC)
    record = PackRecord(
        id=uuid.uuid4(),
        kind="tool",
        pack_id=f"cognic-tool-{uuid.uuid4().hex[:8]}",
        display_name="Seed Pack",
        state="draft",
        manifest_digest=b"\x01" * 32,
        signed_artefact_digest=b"\x02" * 32,
        sbom_pointer=None,
        tenant_id=tenant_id,
        created_by=created_by,
        last_actor=created_by,
        created_at=now,
        updated_at=now,
    )
    await store.save_draft(record)
    return record


async def _seed_allow_listed_pack(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
    reviewer: str = "carol@bank.example",
    approver: str = "dave@bank.example",
    allow_lister: str = "elena@bank.example",
) -> PackRecord:
    """Walk a pack through draft → submitted → under_review → approved
    → allow_listed — the from-state for the ``install`` transition
    per ``packs/lifecycle.py:222``. Mirrors ``_seed_approved_pack``
    + one extra ``allow_list`` step."""
    record = await _seed_approved_pack(
        store,
        tenant_id=tenant_id,
        created_by=created_by,
        reviewer=reviewer,
        approver=approver,
    )
    await store.transition(
        pack_id=record.id,
        transition="allow_list",
        actor_id=allow_lister,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"allowl-seed-{record.id.hex[:8]}",
    )
    return record.model_copy(update={"state": "allow_listed"})


async def _seed_installed_pack(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
    reviewer: str = "carol@bank.example",
    approver: str = "dave@bank.example",
    allow_lister: str = "elena@bank.example",
    installer: str = "frank@bank.example",
) -> PackRecord:
    """Walk a pack through draft → submitted → under_review → approved
    → allow_listed → installed — the from-state for the ``disable``
    transition per ``packs/lifecycle.py:223`` AND one of the two
    multi-from states for ``revoke`` per ``packs/lifecycle.py:224-228``."""
    record = await _seed_allow_listed_pack(
        store,
        tenant_id=tenant_id,
        created_by=created_by,
        reviewer=reviewer,
        approver=approver,
        allow_lister=allow_lister,
    )
    await store.transition(
        pack_id=record.id,
        transition="install",
        actor_id=installer,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"instll-seed-{record.id.hex[:8]}",
    )
    return record.model_copy(update={"state": "installed"})


async def _seed_disabled_pack(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    disabler: str = "george@bank.example",
) -> PackRecord:
    """Walk a pack to ``disabled`` — one of two multi-from states for
    both ``revoke`` (per ``packs/lifecycle.py:224-228``) AND ``uninstall``
    (per ``packs/lifecycle.py:230-234``)."""
    record = await _seed_installed_pack(store, tenant_id=tenant_id)
    await store.transition(
        pack_id=record.id,
        transition="disable",
        actor_id=disabler,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"disabl-seed-{record.id.hex[:8]}",
    )
    return record.model_copy(update={"state": "disabled"})


async def _seed_revoked_pack(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    revoker: str = "helen@bank.example",
) -> PackRecord:
    """Walk a pack to ``revoked`` via ``installed → revoked`` — one of
    two multi-from states for ``uninstall`` (per
    ``packs/lifecycle.py:230-234``) AND the idempotency-409 from-state
    for ``revoke`` (already-revoked → ``revoke_already_revoked`` per
    ``packs/lifecycle.py:183``)."""
    record = await _seed_installed_pack(store, tenant_id=tenant_id)
    await store.transition(
        pack_id=record.id,
        transition="revoke",
        actor_id=revoker,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"revoke-seed-{record.id.hex[:8]}",
    )
    return record.model_copy(update={"state": "revoked"})


async def _seed_approved_pack(
    store: PackRecordStore,
    *,
    tenant_id: str = "t1",
    created_by: str = "bob@bank.example",
    reviewer: str = "carol@bank.example",
    approver: str = "dave@bank.example",
) -> PackRecord:
    """Walk a pack through the full lifecycle to ``approved`` state —
    the from-state for the allow-list transition per
    ``packs/lifecycle.py:221``.

    Path: draft → submitted (submit) → under_review (claim) → approved
    (approve). Three different actors for the three transitions so the
    same actor can later allow-list without tripping any cross-role
    constraint (role-separation is endpoint-level, not storage-level —
    storage accepts any ``actor_id`` per ``packs/storage.py:617``).
    """
    record = await _seed_draft_pack(store, tenant_id=tenant_id, created_by=created_by)
    await store.transition(
        pack_id=record.id,
        transition="submit",
        actor_id=created_by,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"submit-seed-{record.id.hex[:8]}",
    )
    await store.transition(
        pack_id=record.id,
        transition="claim",
        actor_id=reviewer,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"claim-seed-{record.id.hex[:8]}",
    )
    await store.transition(
        pack_id=record.id,
        transition="approve",
        actor_id=approver,
        tenant_id=tenant_id,
        evidence_pointer=None,
        request_id=f"approv-seed-{record.id.hex[:8]}",
    )
    return record.model_copy(update={"state": "approved"})


# ---------------------------------------------------------------------------
# Module-header invariant — no `from __future__ import annotations`
# (Standing-offer §30 from T5 closeout; mirrors role_separation.py:86 +
#  review_routes.py + author_routes.py)
# ---------------------------------------------------------------------------


def test_module_must_not_import_future_annotations() -> None:
    """Standing-offer §30 — AST self-test pinning the no-future-import
    invariant for FastAPI handler modules.

    ``operator_routes.py`` MUST OMIT ``from __future__ import annotations``.
    PEP 563 string-deferred annotations would prevent FastAPI's
    ``inspect.signature()`` / ``typing.get_type_hints()`` introspection
    from resolving ``Annotated[..., Depends(<local-var>)]`` in the
    inner endpoint handlers — the shared dependency instances
    (``_require_pack_allow_list``, ``_require_tenant_ownership``,
    ``_require_human_actor``) are LOCAL variables inside
    :func:`build_operator_routes`, NOT module globals; a lazy string
    evaluation against module globals would ``NameError`` or silently
    treat handler parameters as query params — exactly the bug
    R15 P2 #1 pinned for ``role_separation.py``, then again caught
    mid-cycle in T5 slice 2a when ``review_routes.py`` shipped with
    the future-import.

    Per ``feedback_security_regression_hardening.md`` this AST
    self-test is one half of the load-bearing regression pair — the
    OTHER half is the per-verb handler invocation tests below
    (FastAPI OpenAPI introspection through :class:`TestClient`).
    Together they pin the invariant: AST self-test catches "someone
    added the future-import" regression; invocation tests catch
    "FastAPI silently treats handler params as query params" runtime
    bug. Threat-model-revert verified across slices 1 + 2 + 4 (drop
    the future-import → tests pass; add it back → 422 fingerprint
    fires on every per-verb invocation test).

    Implementation: parse the live ``operator_routes.py`` source via
    ``ast.parse(Path(operator_routes.__file__).read_text())`` and
    assert no module-level node matches
    ``ImportFrom(module="__future__", names=[alias(name="annotations", ...)])``.
    """
    source_path = pathlib.Path(operator_routes.__file__)
    tree = ast.parse(source_path.read_text())

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            for alias_node in node.names:
                assert alias_node.name != "annotations", (
                    "operator_routes.py MUST OMIT `from __future__ import annotations` "
                    "per Standing-offer §30 — PEP 563 string-deferred annotations "
                    "break the FastAPI closure-cell resolution in build_operator_routes's "
                    "inner handlers (shared dependency instances are local-scope, "
                    "not module-global)."
                )


# ---------------------------------------------------------------------------
# Production-wiring regression (Plan R18 P2 #3 — mirrors R16 P2 #1 for T5)
# ---------------------------------------------------------------------------


class TestSprint7B2OperatorRoutesProductionWiring:
    """Plan R18 P2 #3 — the actual production ``build_packs_router``
    factory output MUST include the T6 operator paths. Without this
    test, a regression that creates ``operator_routes.py`` but never
    wires it into the parent router would silently ship a half-wired
    operator surface (manual-mount test passes; production missing
    operator endpoints). Mirrors T5's R16 P2 #1 production-wiring
    regression at ``test_review_routes.py::test_build_packs_router_includes_review_routes``.
    """

    def test_build_packs_router_includes_operator_routes(self) -> None:
        """``build_packs_router(store=stub)`` produces a router whose
        compiled ``app.routes`` includes the 4 distinct operator paths
        (install + allow-list + disable + revoke; the uninstall verb
        shares the install path with method=DELETE) AND preserves the
        T4 author + T5 review paths.
        """
        router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
        app = FastAPI()
        app.include_router(router)
        compiled_paths = {getattr(route, "path", "") for route in app.routes}

        assert "/api/v1/packs/{pack_id}/allow-list" in compiled_paths, (
            "T6 allow-list path not wired into production build_packs_router "
            f"— got {compiled_paths}"
        )
        assert "/api/v1/packs/{pack_id}/install" in compiled_paths, (
            f"T6 install path not wired into production build_packs_router — got {compiled_paths}"
        )
        assert "/api/v1/packs/{pack_id}/disable" in compiled_paths, (
            f"T6 disable path not wired into production build_packs_router — got {compiled_paths}"
        )
        assert "/api/v1/packs/{pack_id}/revoke" in compiled_paths, (
            f"T6 revoke path not wired into production build_packs_router — got {compiled_paths}"
        )
        # T5 review-queue + T4 drafts MUST survive
        assert "/api/v1/packs/review-queue" in compiled_paths, (
            f"T5 review-queue path lost — regression in router wiring; got {compiled_paths}"
        )
        assert "/api/v1/packs/drafts" in compiled_paths, (
            f"T4 author-drafts path lost — regression in router wiring; got {compiled_paths}"
        )
        # T7 carry-forward — inspection list at EXACTLY
        # ``/api/v1/packs`` (no trailing slash per R33 P2 doctrine —
        # registered directly on the parent via
        # ``register_inspection_list`` with path=""; the slashless
        # form IS the wire-protocol contract per plan §997 +
        # ADR-012 §75). Was a negative "T7 not yet wired" temporal
        # pin pre-T7; flipped to a positive presence assertion now.
        assert "/api/v1/packs" in compiled_paths, (
            f"T7 examiner-list path missing from composed build_packs_router — got {compiled_paths}"
        )

    def test_install_path_carries_both_post_and_delete(self) -> None:
        """The ``/install`` path is shared between POST (install verb)
        and DELETE (uninstall verb) per the plan's endpoint table. The
        compiled router MUST expose BOTH methods on the same path."""
        router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
        app = FastAPI()
        app.include_router(router)
        install_methods: set[str] = set()
        for route in app.routes:
            if getattr(route, "path", "") == "/api/v1/packs/{pack_id}/install":
                install_methods.update(getattr(route, "methods", set()) or set())
        assert install_methods >= {"POST", "DELETE"}, (
            "/install path MUST expose BOTH POST (install) and DELETE (uninstall) "
            f"— got methods={install_methods}"
        )


# ---------------------------------------------------------------------------
# Path-param convention regression — every operator endpoint uses {pack_id}
# (mirrors test_review_routes.py::TestSprint7B2ReviewRoutesPathParamConvention)
# ---------------------------------------------------------------------------


class TestSprint7B2OperatorRoutesPathParamConvention:
    """Every operator endpoint with a path UUID MUST use ``{pack_id}``
    (NOT ``{id}``) matching T4/T5's convention + the shared
    ``RequireTenantOwnership(pack_id_param="pack_id")`` dependency.
    Mirrors T5's R17 P2 #1 path-param convention regression."""

    @pytest.mark.parametrize(
        "expected_path",
        [
            "/api/v1/packs/{pack_id}/allow-list",
            "/api/v1/packs/{pack_id}/install",
            "/api/v1/packs/{pack_id}/disable",
            "/api/v1/packs/{pack_id}/revoke",
        ],
    )
    def test_operator_route_uses_pack_id_path_param(self, expected_path: str) -> None:
        """Each operator path MUST appear verbatim in the compiled
        route set with ``{pack_id}`` (not ``{id}``). The uninstall
        verb shares ``/install`` with DELETE method, so its path is
        covered by the install assertion above."""
        router = build_packs_router(store=_StubStore())  # type: ignore[arg-type]
        app = FastAPI()
        app.include_router(router)
        compiled_paths = {getattr(route, "path", "") for route in app.routes}
        assert expected_path in compiled_paths, (
            f"T6 path {expected_path} MUST use {{pack_id}} matching the "
            f"shared RequireTenantOwnership(pack_id_param='pack_id') dependency "
            f"— got {compiled_paths}"
        )


# ---------------------------------------------------------------------------
# Request-id prefix bounded-length invariant (Plan R18 P2 #4 + R19 P3 #3 +
# Standing watchpoint (g))
# ---------------------------------------------------------------------------


class TestSprint7B2OperatorRequestIdPrefixBounded:
    """Plan R18 P2 #4 + R19 P3 #3 — every operator request-id prefix
    MUST satisfy ``len(prefix) + 32 (uuid4().hex) <= 64`` so the minted
    request_id fits the ``decision_history.request_id`` String(64)
    column cap. Module-foot build-time assert in ``operator_routes.py``
    pins this at import; this test pins the invariant in test surface
    too so a future drift surfaces cleanly under pytest collection.
    Mirrors T4's invariant at ``author_routes.py:770-775``."""

    @pytest.mark.parametrize(
        "prefix",
        [
            operator_routes._PACK_ALLOW_LIST_REQUEST_ID_PREFIX,
            operator_routes._PACK_INSTALL_REQUEST_ID_PREFIX,
            operator_routes._PACK_DISABLE_REQUEST_ID_PREFIX,
            operator_routes._PACK_REVOKE_REQUEST_ID_PREFIX,
            operator_routes._PACK_UNINSTALL_REQUEST_ID_PREFIX,
        ],
    )
    def test_operator_request_id_prefix_bounded_to_64_chars(self, prefix: str) -> None:
        """``len(prefix) + 32 <= 64`` per the ``decision_history.request_id``
        String(64) column cap. Test asserts the invariant via
        ``len()`` rather than a specific total-length count — Plan
        R19 P3 #3 explicitly rejected false-uniformity coupling
        (T4/T5 prefixes are 12 chars; T6 prefixes are 13 chars; the
        invariant is the cap, not the count)."""
        assert len(prefix) + 32 <= 64, (
            f"operator request-id prefix {prefix!r} ({len(prefix)} chars) + "
            f"uuid4().hex (32 chars) = {len(prefix) + 32} > 64; "
            "would overflow decision_history.request_id String(64) column cap"
        )


# ---------------------------------------------------------------------------
# Per-verb handler invocation tests (5 endpoints) — load-bearing PAIR
# for the AST self-test above per feedback_security_regression_hardening.md.
# The pair: AST half catches "someone added `from __future__ import
# annotations` to operator_routes.py" regression; invocation half catches
# the FastAPI-treats-handler-params-as-query-params runtime symptom (the
# silent-failure mode the future-import would trigger).
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# POST /api/v1/packs/{pack_id}/allow-list (real handler)
# (Plan watchpoints (b) human-actor, (d) audit-chain actor_type=="human",
#  (h) PackNotFound race translation, (i) structured-log mutual exclusion)
# ---------------------------------------------------------------------------


_OPERATOR_ROUTES_LOGGER = "cognic_agentos.portal.api.packs.operator_routes"
_HUMAN_ACTOR_LOGGER = "cognic_agentos.portal.rbac.human_actor"


class TestSprint7B2AllowListEndpoint:
    """``POST /api/v1/packs/{pack_id}/allow-list`` — slice-2 handler.

    Dependency chain (resolution order):
    1. :class:`RequireScope("pack.allow_list")` — 403 ``scope_not_held``
       for missing scope; emits ``portal.rbac.denied`` log.
    2. :class:`RequireTenantOwnership` — 404 ``tenant_id_mismatch`` /
       ``pack_not_found`` for cross-tenant / missing pack; emits
       ``portal.rbac.tenant_isolation`` log.
    3. :class:`RequireHumanActor` — 403 ``actor_type_must_be_human``
       for service-token actors; emits
       ``portal.rbac.human_actor_required`` log per
       ``portal/rbac/human_actor.py:69``. Plan R1 P3 #8 — AGENTS.md
       "Human-only decisions" ↔ "Per-tenant allow-list changes"
       doctrine pin.

    Handler-body refusals:
    - :class:`PackNotFound` race (R18 P2 #4) — concurrent delete between
      tenant-isolation preload + ``transition()`` SELECT FOR UPDATE →
      404 ``pack_not_found`` + ``portal.packs.allow_list_refused`` log.
    - :class:`LifecycleTransitionRefused` — state-machine refusal (e.g.
      allow-list on draft pack) → 409 + closed-enum reason +
      ``portal.packs.allow_list_refused`` log.

    Plan R19 P2 #2 mutually-exclusive log contract: a dep-chain
    refusal emits its own sibling-guard log (``portal.rbac.denied`` /
    ``portal.rbac.tenant_isolation`` / ``portal.rbac.human_actor_required``)
    AND zero ``portal.packs.allow_list_refused`` records — the
    operator-vocab refused-event fires ONLY when the handler body
    runs and refuses (state-machine or race). The green-path
    ``portal.packs.allow_list`` event (carrying actor_type +
    actor_subject + pack_id) is mutually-exclusive with the refused
    event — the watchpoint (d) examiner-traceability surface.
    """

    # -- Happy path -----------------------------------------------------

    async def test_allow_list_happy_path_advances_state_to_allow_listed(
        self,
        store: PackRecordStore,
    ) -> None:
        """Human actor with ``pack.allow_list`` scope + matching tenant
        + pack in ``approved`` state → 200 + state advances to
        ``allow_listed`` per ``packs/lifecycle.py:221``.
        ``PackResponse`` body reflects the post-transition state."""
        record = await _seed_approved_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1", actor_type="human")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/allow-list")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["state"] == "allow_listed", (
            f"state did not advance to allow_listed; got {body['state']}"
        )

        # Storage-side state verification
        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "allow_listed"

    async def test_allow_list_happy_path_emits_structured_log_with_actor_type(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan watchpoint (d) — green path emits
        ``portal.packs.allow_list`` structured log carrying
        ``actor_type == "human"`` for examiner traceability. The
        ``RequireHumanActor()`` dep chain guarantees actor_type is
        ``"human"`` at this point; the log records that guarantee on
        the audit surface (mirrors T5 reject's
        ``portal.packs.review.reject`` green-path log)."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_approved_pack(store, tenant_id="t1")
        actor = _make_operator_actor(
            subject="operator@bank.example",
            tenant_id="t1",
            actor_type="human",
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/allow-list")
        assert response.status_code == 200

        allow_list_records = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.allow_list"
        ]
        assert len(allow_list_records) == 1, (
            f"expected EXACTLY 1 portal.packs.allow_list record on green path; "
            f"got {len(allow_list_records)}"
        )
        rec = allow_list_records[0]
        assert rec.actor_type == "human"  # type: ignore[attr-defined]
        assert rec.actor_subject == "operator@bank.example"  # type: ignore[attr-defined]
        assert rec.pack_id == str(record.id)  # type: ignore[attr-defined]

    async def test_allow_list_chain_row_carries_actor_type_human_and_subject(
        self,
        engine: AsyncEngine,
        store: PackRecordStore,
    ) -> None:
        """**R24 P2 Path B + B2** — watchpoint (d) primary closure.

        The chain row's ``payload["actor_type"]`` MUST equal ``"human"``
        AND ``payload["actor_id"]`` MUST be the human actor's subject.
        This pins the plan-of-record's literal watchpoint (d) contract:
        the allow-list audit row records ``actor.actor_type == "human"``
        in the chain payload for examiner traceability. An examiner
        walking ``decision_history`` rows alone can verify the
        human-actor invariant without cross-correlating to the
        structured log surface.

        Queries the raw ``decision_history`` table directly —
        ``actor_id`` lives in ``payload["actor_id"]`` per the storage
        seam at ``core/decision_history.py:223-233`` (DecisionRecord
        merges actor_id into payload before hashing); ``actor_type``
        is the new top-level payload key added by
        ``packs/storage.py:transition()``'s slice-2 amendment.
        """
        from sqlalchemy import select

        from cognic_agentos.core.decision_history import _decision_history

        record = await _seed_approved_pack(store, tenant_id="t1")
        actor = _make_operator_actor(
            subject="operator@bank.example",
            tenant_id="t1",
            actor_type="human",
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/allow-list")
        assert response.status_code == 200

        # Raw chain-row inspection.
        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.payload,
                    ).where(_decision_history.c.event_type == "pack.lifecycle.allow_listed")
                )
            ).all()
        allow_listed_rows = [r for r in rows if (r.payload or {}).get("pack_id") == str(record.id)]
        assert len(allow_listed_rows) == 1, (
            f"expected EXACTLY 1 pack.lifecycle.allow_listed chain row for "
            f"this pack; got {len(allow_listed_rows)}"
        )
        chain_payload = allow_listed_rows[0].payload or {}

        # Primary watchpoint (d) closure: actor_type flat in payload.
        assert chain_payload.get("actor_type") == "human", (
            f"chain row payload['actor_type'] MUST equal 'human' on the "
            f"allow-list audit row (R24 P2 Path B + B2 watchpoint (d) "
            f"closure); got payload={chain_payload!r}"
        )

        # Secondary cross-surface: actor_id is the human's subject.
        assert chain_payload.get("actor_id") == "operator@bank.example", (
            f"chain row payload['actor_id'] MUST be the human actor's "
            f"subject; got {chain_payload.get('actor_id')!r}"
        )

        # Tertiary cross-surface: packs.last_actor cache mirrors the
        # chain row's actor_id (same write under the row-locked
        # transaction per packs/storage.py:777).
        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.last_actor == "operator@bank.example"

    async def test_allow_list_pre_slice_2_audit_rows_omit_actor_type(
        self,
        engine: AsyncEngine,
        store: PackRecordStore,
    ) -> None:
        """**R24 P2 backward-compat guardrail** — only the allow-list
        chain row carries ``payload["actor_type"]``; the pre-allow-list
        rows (submit / claim / approve) MUST NOT carry the key (those
        seed transitions are written via ``_seed_approved_pack`` without
        the new kwarg, simulating every pre-slice-2 chain row +
        every T4/T5 chain row in production). Pins that the storage
        amendment is additive + opt-in, NOT a blanket schema bump."""
        from sqlalchemy import select

        from cognic_agentos.core.decision_history import _decision_history

        record = await _seed_approved_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1", actor_type="human")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/allow-list")
        assert response.status_code == 200

        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.payload,
                    ).order_by(_decision_history.c.sequence)
                )
            ).all()
        pack_rows = [r for r in rows if (r.payload or {}).get("pack_id") == str(record.id)]
        # 3 seed transitions (submit/claim/approve) + 1 allow-list = 4
        # rows total. Only the allow-list row carries actor_type.
        actor_type_rows = [r for r in pack_rows if "actor_type" in (r.payload or {})]
        assert len(actor_type_rows) == 1
        assert actor_type_rows[0].event_type == "pack.lifecycle.allow_listed"
        non_allow_list_rows = [
            r for r in pack_rows if r.event_type != "pack.lifecycle.allow_listed"
        ]
        for r in non_allow_list_rows:
            assert "actor_type" not in (r.payload or {}), (
                f"pre-allow-list chain row {r.event_type} MUST NOT carry "
                f"'actor_type' (additive-only schema contract); "
                f"got payload={r.payload!r}"
            )

    async def test_allow_list_request_id_uses_pack_alowlst_prefix(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R18 P2 #4 — minted request_id MUST use
        :data:`operator_routes._PACK_ALLOW_LIST_REQUEST_ID_PREFIX`
        (``pack-alowlst-``) and stay under the 64-char
        ``decision_history.request_id`` String cap. Inspects the
        actual chain row's ``request_id`` field — mirrors T5 claim's
        bounded-length regression."""
        record = await _seed_approved_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1", actor_type="human")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/allow-list")
        assert response.status_code == 200

        history = await store.load_lifecycle_history(record.id)
        allow_listed_rows = [r for r in history if r.decision_type == "pack.lifecycle.allow_listed"]
        assert len(allow_listed_rows) == 1
        request_id = allow_listed_rows[0].request_id
        assert len(request_id) <= 64, (
            f"allow_list request_id exceeds String(64) cap: len={len(request_id)}, "
            f"value={request_id!r}"
        )
        assert request_id.startswith("pack-alowlst-"), (
            f"allow_list request_id must use _PACK_ALLOW_LIST_REQUEST_ID_PREFIX; got {request_id!r}"
        )

    # -- Service-actor refused — mutually-exclusive log (R19 P2 #2) -----

    async def test_allow_list_refuses_service_actor_with_human_actor_log_only(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan R19 P2 #2 — a service-token actor with
        ``pack.allow_list`` scope is refused at the
        :func:`RequireHumanActor` dep BEFORE the handler body runs.
        Two assertions pin the mutually-exclusive log contract:

        1. EXACTLY ONE ``portal.rbac.human_actor_required`` log record
           (the sibling-guard log).
        2. ZERO ``portal.packs.allow_list_refused`` records (the
           operator-vocab refused-event log MUST NOT fire on this
           axis — handler body did not run).

        AGENTS.md "Human-only decisions" + "Per-tenant allow-list
        changes" doctrine carry-forward.
        """
        caplog.set_level(logging.WARNING, logger=_HUMAN_ACTOR_LOGGER)
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)

        record = await _seed_approved_pack(store, tenant_id="t1")
        # Service-actor with ALL operator scopes — only the actor_type
        # axis triggers the refusal.
        actor = _make_operator_actor(
            subject="ci@bank.example",
            tenant_id="t1",
            actor_type="service",
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/allow-list")
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "actor_type_must_be_human"

        # Sibling-guard log fires EXACTLY ONCE
        human_actor_records = [
            r
            for r in caplog.records
            if r.name == _HUMAN_ACTOR_LOGGER and r.message == "portal.rbac.human_actor_required"
        ]
        assert len(human_actor_records) == 1, (
            f"expected EXACTLY 1 portal.rbac.human_actor_required record; "
            f"got {len(human_actor_records)}"
        )

        # Operator-vocab refused-event MUST NOT fire — R19 P2 #2
        # mutually-exclusive contract.
        allow_list_refused_records = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.allow_list_refused"
        ]
        assert len(allow_list_refused_records) == 0, (
            "portal.packs.allow_list_refused MUST NOT fire when refusal is at "
            "the human-actor dep axis (sibling-guard log carries the refusal); "
            f"got {len(allow_list_refused_records)} records"
        )

        # No state change
        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "approved"

    async def test_allow_list_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """RBAC refusal (R19 P2 #2 sibling) — actor without
        ``pack.allow_list`` scope is refused at :class:`RequireScope`
        BEFORE other deps fire. ZERO ``portal.packs.allow_list_refused``
        records (mutually-exclusive contract)."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_approved_pack(store, tenant_id="t1")
        actor = _make_operator_actor(
            tenant_id="t1",
            actor_type="human",
            scopes=frozenset(),  # no scopes
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/allow-list")
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

        allow_list_refused_records = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.allow_list_refused"
        ]
        assert len(allow_list_refused_records) == 0

    async def test_allow_list_refuses_cross_tenant_with_404(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Tenant-isolation refusal (R19 P2 #2 sibling) — actor's
        ``tenant_id`` differs from pack's ``tenant_id`` → 404
        ``tenant_id_mismatch`` at :class:`RequireTenantOwnership`.
        ZERO ``portal.packs.allow_list_refused`` records."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_approved_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t2", actor_type="human")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/allow-list")
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"

        allow_list_refused_records = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.allow_list_refused"
        ]
        assert len(allow_list_refused_records) == 0

    # -- Handler-body refusals — operator-vocab log fires ---------------

    async def test_allow_list_refuses_when_state_not_approved_with_409(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """State-machine refusal (R19 P2 #1 ordering) — allow-list on a
        draft pack → 409 ``lifecycle_transition_allow_list_not_approved``
        per ``packs/lifecycle.py:526``. EXACTLY ONE
        ``portal.packs.allow_list_refused`` log record (operator-vocab
        log fires because handler body ran)."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_draft_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1", actor_type="human")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/allow-list")
        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == (
            "lifecycle_transition_allow_list_not_approved"
        )

        refused_records = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.allow_list_refused"
        ]
        assert len(refused_records) == 1, (
            f"expected EXACTLY 1 portal.packs.allow_list_refused record on "
            f"state-machine refusal; got {len(refused_records)}"
        )
        rec = refused_records[0]
        assert rec.reason == (  # type: ignore[attr-defined]
            "lifecycle_transition_allow_list_not_approved"
        )
        assert rec.actor_subject == "operator@bank.example"  # type: ignore[attr-defined]
        assert rec.pack_id == str(record.id)  # type: ignore[attr-defined]
        assert rec.from_state == "draft"  # type: ignore[attr-defined]

        # No state change
        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "draft"

    def test_allow_list_handles_pack_not_found_race(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan R18 P2 #4 — concurrent delete between
        :class:`RequireTenantOwnership` preload + ``store.transition()``
        SELECT FOR UPDATE raises :class:`PackNotFound` inside the
        storage precondition; handler MUST translate to 404
        ``pack_not_found`` (NOT 500). Mirrors T5 claim/reject pattern
        at ``test_review_routes.py::test_claim_handles_pack_not_found_race``.

        **R27 hardening**: the race path is a handler-body refusal, so
        the operator-vocab structured log
        ``portal.packs.allow_list_refused`` MUST fire on this axis
        (same as the state-machine refusal axis at
        ``test_allow_list_refuses_when_state_not_approved_with_409``).
        Without the caplog pin a future regression that drops the
        ``_LOG.warning(...)`` from the :class:`PackNotFound` except
        branch would stay green on just the 404 assertion. Mutually-
        exclusive log contract (R19 P2 #2): EXACTLY ONE
        ``portal.packs.allow_list_refused`` record carrying
        ``reason == "pack_not_found"`` + ``actor_subject`` +
        ``pack_id`` + ``from_state``.
        """
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)

        class _RaceStore:
            """Stub store: ``load()`` returns a valid PackRecord (so
            the tenant-ownership preload succeeds) but ``transition()``
            raises :class:`PackNotFound` (simulating the race)."""

            def __init__(self, record: PackRecord) -> None:
                self._record = record

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                if pack_id == self._record.id:
                    return self._record
                return None

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise PackNotFound(self._record.id)

        record = PackRecord(
            id=uuid.uuid4(),
            kind="tool",
            pack_id="cognic-tool-race",
            display_name="Race Pack",
            state="approved",
            manifest_digest=b"\x01" * 32,
            signed_artefact_digest=b"\x02" * 32,
            sbom_pointer=None,
            tenant_id="t1",
            created_by="bob@bank.example",
            last_actor="bob@bank.example",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        race_store: PackRecordStore = _RaceStore(record)  # type: ignore[assignment]
        actor = _make_operator_actor(
            subject="operator@bank.example",
            tenant_id="t1",
            actor_type="human",
        )
        app = _build_app(actor=actor, store=race_store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/allow-list")

        # Race produces structured 404 (not 500); wire-protocol-public
        # body identical to the tenant-isolation pack_not_found reason.
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"

        # R27 — operator-vocab refused log MUST fire on the race path.
        refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.allow_list_refused"
        ]
        assert len(refused) == 1, (
            f"PackNotFound race MUST emit EXACTLY 1 "
            f"portal.packs.allow_list_refused record; got {len(refused)}"
        )
        rec = refused[0]
        assert rec.reason == "pack_not_found"  # type: ignore[attr-defined]
        assert rec.actor_subject == "operator@bank.example"  # type: ignore[attr-defined]
        assert rec.pack_id == str(record.id)  # type: ignore[attr-defined]
        assert rec.from_state == "approved"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Slice 3 — POST /api/v1/packs/{pack_id}/install (real handler)
# (Plan watchpoints (c) tenant-isolation, (h) PackNotFound race,
#  (i) structured-log emission; R24 actor_type payload carry-forward)
# ---------------------------------------------------------------------------


class TestSprint7B2InstallEndpoint:
    """``POST /api/v1/packs/{pack_id}/install`` — slice-3 handler.

    Single-from-state transition: ``allow_listed → installed`` per
    ``packs/lifecycle.py:222``. Symmetric with the disable handler
    (same dependency chain shape: RBAC + tenant + no human-actor,
    no role-separation).

    R24 carry-forward: install handler threads
    ``actor_type=actor.actor_type`` so the chain row's
    ``payload["actor_type"]`` records the actor type for examiner
    parity with the allow-list audit row (slices 3-4 thread the
    same kwarg per the Path B + B2 user-authorized contract).

    Plan R19 P2 #2 mutually-exclusive log contract: dep-chain
    refusal (RBAC / tenant) emits its own sibling-guard log; handler-
    body refusal (state-machine / PackNotFound race) emits EXACTLY
    ONE ``portal.packs.install_refused`` record.
    """

    async def test_install_happy_path_advances_state_to_installed(
        self,
        store: PackRecordStore,
    ) -> None:
        """Actor with ``pack.install`` scope + matching tenant + pack
        in ``allow_listed`` state → 200 + state advances to
        ``installed``."""
        record = await _seed_allow_listed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "installed"

        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "installed"

    async def test_install_chain_row_carries_actor_type_in_payload(
        self,
        engine: AsyncEngine,
        store: PackRecordStore,
    ) -> None:
        """R24 carry-forward — install chain row payload['actor_type']
        records the actor's type (Path B + B2)."""
        from sqlalchemy import select

        from cognic_agentos.core.decision_history import _decision_history

        record = await _seed_allow_listed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(
            subject="operator@bank.example",
            tenant_id="t1",
            actor_type="human",
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 200

        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.payload,
                    ).where(_decision_history.c.event_type == "pack.lifecycle.installed")
                )
            ).all()
        installed_rows = [r for r in rows if (r.payload or {}).get("pack_id") == str(record.id)]
        assert len(installed_rows) == 1
        assert (installed_rows[0].payload or {}).get("actor_type") == "human"

    async def test_install_request_id_uses_pack_install_prefix(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R18 P2 #4 — minted request_id uses
        ``_PACK_INSTALL_REQUEST_ID_PREFIX`` (``pack-install-``)."""
        record = await _seed_allow_listed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 200

        history = await store.load_lifecycle_history(record.id)
        installed_rows = [r for r in history if r.decision_type == "pack.lifecycle.installed"]
        assert len(installed_rows) == 1
        request_id = installed_rows[0].request_id
        assert len(request_id) <= 64
        assert request_id.startswith("pack-install-"), (
            f"install request_id must use _PACK_INSTALL_REQUEST_ID_PREFIX; got {request_id!r}"
        )

    async def test_install_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan R19 P2 #2 — RBAC refusal sibling; ZERO operator-vocab
        log."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_allow_listed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(
            tenant_id="t1",
            scopes=frozenset(),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

        install_refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.install_refused"
        ]
        assert len(install_refused) == 0

    async def test_install_refuses_cross_tenant_with_404(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan watchpoint (c) — cross-tenant 404; ZERO operator-vocab log."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_allow_listed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t2")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"

        install_refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.install_refused"
        ]
        assert len(install_refused) == 0

    async def test_install_refuses_when_state_not_allow_listed_with_409(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan watchpoint (i) — install on a draft pack → 409
        ``lifecycle_transition_invalid_state_pair`` per the state-
        machine refusal. EXACTLY ONE
        ``portal.packs.install_refused`` record."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_draft_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == ("lifecycle_transition_invalid_state_pair")

        refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.install_refused"
        ]
        assert len(refused) == 1
        rec = refused[0]
        assert rec.reason == "lifecycle_transition_invalid_state_pair"  # type: ignore[attr-defined]
        assert rec.actor_subject == "operator@bank.example"  # type: ignore[attr-defined]
        assert rec.pack_id == str(record.id)  # type: ignore[attr-defined]
        assert rec.from_state == "draft"  # type: ignore[attr-defined]

        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "draft"

    def test_install_handles_pack_not_found_race(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan watchpoint (h) — concurrent delete between
        tenant-ownership preload + ``transition()`` SELECT FOR
        UPDATE raises :class:`PackNotFound`; handler MUST translate
        to 404 ``pack_not_found`` (NOT 500). Mirrors slice 2 +
        T5 pattern.

        **R27 hardening**: race path is a handler-body refusal; the
        operator-vocab structured log
        ``portal.packs.install_refused`` MUST fire here (mutually-
        exclusive R19 P2 #2 contract — same shape as state-machine
        refusal). Without the caplog pin a future regression that
        drops the ``_LOG.warning(...)`` from the PackNotFound except
        branch would silently pass on the 404 assertion alone.
        """
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)

        class _RaceStore:
            def __init__(self, record: PackRecord) -> None:
                self._record = record

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                if pack_id == self._record.id:
                    return self._record
                return None

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise PackNotFound(self._record.id)

        record = PackRecord(
            id=uuid.uuid4(),
            kind="tool",
            pack_id="cognic-tool-race",
            display_name="Race Pack",
            state="allow_listed",
            manifest_digest=b"\x01" * 32,
            signed_artefact_digest=b"\x02" * 32,
            sbom_pointer=None,
            tenant_id="t1",
            created_by="bob@bank.example",
            last_actor="bob@bank.example",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        race_store: PackRecordStore = _RaceStore(record)  # type: ignore[assignment]
        actor = _make_operator_actor(
            subject="operator@bank.example",
            tenant_id="t1",
        )
        app = _build_app(actor=actor, store=race_store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"

        # R27 — operator-vocab refused log MUST fire on the race path.
        refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.install_refused"
        ]
        assert len(refused) == 1, (
            f"PackNotFound race MUST emit EXACTLY 1 "
            f"portal.packs.install_refused record; got {len(refused)}"
        )
        rec = refused[0]
        assert rec.reason == "pack_not_found"  # type: ignore[attr-defined]
        assert rec.actor_subject == "operator@bank.example"  # type: ignore[attr-defined]
        assert rec.pack_id == str(record.id)  # type: ignore[attr-defined]
        assert rec.from_state == "allow_listed"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Slice 3 — POST /api/v1/packs/{pack_id}/disable (real handler)
# ---------------------------------------------------------------------------


class TestSprint7B2DisableEndpoint:
    """``POST /api/v1/packs/{pack_id}/disable`` — slice-3 handler.

    Single-from-state transition: ``installed → disabled`` per
    ``packs/lifecycle.py:223``. Symmetric with the install handler.
    """

    async def test_disable_happy_path_advances_state_to_disabled(
        self,
        store: PackRecordStore,
    ) -> None:
        """Actor with ``pack.disable`` scope + matching tenant + pack
        in ``installed`` state → 200 + state advances to ``disabled``."""
        record = await _seed_installed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "disabled"

        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "disabled"

    async def test_disable_chain_row_carries_actor_type_in_payload(
        self,
        engine: AsyncEngine,
        store: PackRecordStore,
    ) -> None:
        """R24 carry-forward — disable chain row payload['actor_type']."""
        from sqlalchemy import select

        from cognic_agentos.core.decision_history import _decision_history

        record = await _seed_installed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(
            subject="operator@bank.example",
            tenant_id="t1",
            actor_type="human",
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")
        assert response.status_code == 200

        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.payload,
                    ).where(_decision_history.c.event_type == "pack.lifecycle.disabled")
                )
            ).all()
        disabled_rows = [r for r in rows if (r.payload or {}).get("pack_id") == str(record.id)]
        assert len(disabled_rows) == 1
        assert (disabled_rows[0].payload or {}).get("actor_type") == "human"

    async def test_disable_request_id_uses_pack_disable_prefix(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R18 P2 #4 — minted request_id uses
        ``_PACK_DISABLE_REQUEST_ID_PREFIX`` (``pack-disable-``)."""
        record = await _seed_installed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")
        assert response.status_code == 200

        history = await store.load_lifecycle_history(record.id)
        disabled_rows = [r for r in history if r.decision_type == "pack.lifecycle.disabled"]
        assert len(disabled_rows) == 1
        request_id = disabled_rows[0].request_id
        assert len(request_id) <= 64
        assert request_id.startswith("pack-disable-"), (
            f"disable request_id must use _PACK_DISABLE_REQUEST_ID_PREFIX; got {request_id!r}"
        )

    async def test_disable_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan R19 P2 #2 — RBAC refusal sibling; ZERO operator-vocab log."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_installed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(
            tenant_id="t1",
            scopes=frozenset(),
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

        disable_refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.disable_refused"
        ]
        assert len(disable_refused) == 0

    async def test_disable_refuses_cross_tenant_with_404(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan watchpoint (c) — cross-tenant 404; ZERO operator-vocab log."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_installed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t2")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"

        disable_refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.disable_refused"
        ]
        assert len(disable_refused) == 0

    async def test_disable_refuses_when_state_not_installed_with_409(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan watchpoint (i) — disable on a draft pack → 409
        ``lifecycle_transition_disable_not_installed`` per the
        per-transition reason at ``packs/lifecycle.py``. EXACTLY ONE
        ``portal.packs.disable_refused`` record."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_draft_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")
        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == ("lifecycle_transition_disable_not_installed")

        refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.disable_refused"
        ]
        assert len(refused) == 1
        rec = refused[0]
        assert rec.reason == "lifecycle_transition_disable_not_installed"  # type: ignore[attr-defined]
        assert rec.actor_subject == "operator@bank.example"  # type: ignore[attr-defined]
        assert rec.pack_id == str(record.id)  # type: ignore[attr-defined]
        assert rec.from_state == "draft"  # type: ignore[attr-defined]

        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "draft"

    def test_disable_handles_pack_not_found_race(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan watchpoint (h) — PackNotFound race → 404
        ``pack_not_found``.

        **R27 hardening**: race path is a handler-body refusal; the
        operator-vocab structured log
        ``portal.packs.disable_refused`` MUST fire here (mutually-
        exclusive R19 P2 #2 contract). Slice 4 revoke + uninstall
        race tests inherit this same pattern.
        """
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)

        class _RaceStore:
            def __init__(self, record: PackRecord) -> None:
                self._record = record

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                if pack_id == self._record.id:
                    return self._record
                return None

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise PackNotFound(self._record.id)

        record = PackRecord(
            id=uuid.uuid4(),
            kind="tool",
            pack_id="cognic-tool-race",
            display_name="Race Pack",
            state="installed",
            manifest_digest=b"\x01" * 32,
            signed_artefact_digest=b"\x02" * 32,
            sbom_pointer=None,
            tenant_id="t1",
            created_by="bob@bank.example",
            last_actor="bob@bank.example",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        race_store: PackRecordStore = _RaceStore(record)  # type: ignore[assignment]
        actor = _make_operator_actor(
            subject="operator@bank.example",
            tenant_id="t1",
        )
        app = _build_app(actor=actor, store=race_store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/disable")
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"

        # R27 — operator-vocab refused log MUST fire on the race path.
        refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.disable_refused"
        ]
        assert len(refused) == 1, (
            f"PackNotFound race MUST emit EXACTLY 1 "
            f"portal.packs.disable_refused record; got {len(refused)}"
        )
        rec = refused[0]
        assert rec.reason == "pack_not_found"  # type: ignore[attr-defined]
        assert rec.actor_subject == "operator@bank.example"  # type: ignore[attr-defined]
        assert rec.pack_id == str(record.id)  # type: ignore[attr-defined]
        assert rec.from_state == "installed"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Slice 4 — POST /api/v1/packs/{pack_id}/revoke (real handler)
# (Plan watchpoints (a) multi-from-state, (e) idempotency 409,
#  (h) PackNotFound race [R27-hardened], (i) structured-log emission;
#  R24 actor_type payload carry-forward)
# ---------------------------------------------------------------------------


class TestSprint7B2RevokeEndpoint:
    """``POST /api/v1/packs/{pack_id}/revoke`` — slice-4 handler.

    **Multi-from-state transition** per ``packs/lifecycle.py:224-228``:
    ``revoke`` accepts BOTH ``installed → revoked`` AND ``disabled →
    revoked``. Slice 4 explicitly exercises both legal from-states
    (watchpoint (a)) so a future regression that narrows
    ``_VALID_TRANSITIONS["revoke"]`` to a single from-state fails
    cleanly.

    **Idempotency closure** per ``packs/lifecycle.py:183``:
    re-revoking an already-revoked pack returns 409
    ``lifecycle_transition_revoke_already_revoked`` (closed-enum
    per-transition reason — distinct from the generic
    ``lifecycle_transition_invalid_state_pair`` legal-pair fallback).

    R24 carry-forward (Path B + B2): chain row's
    ``payload["actor_type"]`` records the actor's type for examiner
    parity with allow-list + install + disable.

    Race tests inherit the **R27-hardened pattern**: response 404 +
    EXACTLY 1 ``portal.packs.revoke_refused`` log carrying
    ``reason == "pack_not_found"`` + ``actor_subject`` + ``pack_id``
    + ``from_state``.
    """

    # -- Multi-from happy paths (watchpoint (a)) ------------------------

    async def test_revoke_happy_path_from_installed_advances_state_to_revoked(
        self,
        store: PackRecordStore,
    ) -> None:
        """Multi-from leg 1: ``installed → revoked`` per
        ``packs/lifecycle.py:225``."""
        record = await _seed_installed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "revoked"

        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "revoked"

    async def test_revoke_happy_path_from_disabled_advances_state_to_revoked(
        self,
        store: PackRecordStore,
    ) -> None:
        """Multi-from leg 2: ``disabled → revoked`` per
        ``packs/lifecycle.py:226``. Same handler + same closed-enum
        wire shape; the from-state alone differs."""
        record = await _seed_disabled_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "revoked"

        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "revoked"

    async def test_revoke_chain_row_carries_actor_type_in_payload(
        self,
        engine: AsyncEngine,
        store: PackRecordStore,
    ) -> None:
        """R24 carry-forward — revoke chain row payload['actor_type']."""
        from sqlalchemy import select

        from cognic_agentos.core.decision_history import _decision_history

        record = await _seed_installed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(
            subject="operator@bank.example",
            tenant_id="t1",
            actor_type="human",
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")
        assert response.status_code == 200

        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.payload,
                    ).where(_decision_history.c.event_type == "pack.lifecycle.revoked")
                )
            ).all()
        revoked_rows = [r for r in rows if (r.payload or {}).get("pack_id") == str(record.id)]
        assert len(revoked_rows) == 1
        assert (revoked_rows[0].payload or {}).get("actor_type") == "human"

    async def test_revoke_request_id_uses_pack_revoke_prefix(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R18 P2 #4 — minted request_id uses
        ``_PACK_REVOKE_REQUEST_ID_PREFIX`` (``pack-revoke--`` —
        double-dash for prefix-uniqueness against ``pack-revoke``
        substring matches)."""
        record = await _seed_installed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")
        assert response.status_code == 200

        history = await store.load_lifecycle_history(record.id)
        revoked_rows = [r for r in history if r.decision_type == "pack.lifecycle.revoked"]
        assert len(revoked_rows) == 1
        request_id = revoked_rows[0].request_id
        assert len(request_id) <= 64
        assert request_id.startswith("pack-revoke--"), (
            f"revoke request_id must use _PACK_REVOKE_REQUEST_ID_PREFIX; got {request_id!r}"
        )

    # -- Refusal axes ----------------------------------------------------

    async def test_revoke_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan R19 P2 #2 — RBAC refusal sibling; ZERO operator-vocab log."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_installed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1", scopes=frozenset())
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

        revoke_refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.revoke_refused"
        ]
        assert len(revoke_refused) == 0

    async def test_revoke_refuses_cross_tenant_with_404(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan watchpoint (c) — cross-tenant 404; ZERO operator-vocab log."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_installed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t2")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"

        revoke_refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.revoke_refused"
        ]
        assert len(revoke_refused) == 0

    async def test_revoke_idempotency_already_revoked_returns_409(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """**Plan watchpoint (e) idempotency-409 closure** — re-revoke
        on an already-revoked pack returns 409 with closed-enum
        ``lifecycle_transition_revoke_already_revoked`` (per-transition
        reason per ``packs/lifecycle.py:183``; distinct from the
        generic legal-pair fallback). EXACTLY ONE
        ``portal.packs.revoke_refused`` log carrying reason +
        actor_subject + pack_id + from_state."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_revoked_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")
        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == (
            "lifecycle_transition_revoke_already_revoked"
        )

        refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.revoke_refused"
        ]
        assert len(refused) == 1
        rec = refused[0]
        assert rec.reason == "lifecycle_transition_revoke_already_revoked"  # type: ignore[attr-defined]
        assert rec.actor_subject == "operator@bank.example"  # type: ignore[attr-defined]
        assert rec.pack_id == str(record.id)  # type: ignore[attr-defined]
        assert rec.from_state == "revoked"  # type: ignore[attr-defined]

        # No state change — still revoked.
        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "revoked"

    def test_revoke_handles_pack_not_found_race(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan watchpoint (h) — PackNotFound race → 404
        ``pack_not_found``. R27-hardened: EXACTLY 1
        ``portal.packs.revoke_refused`` log carrying reason +
        actor_subject + pack_id + from_state."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)

        class _RaceStore:
            def __init__(self, record: PackRecord) -> None:
                self._record = record

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                if pack_id == self._record.id:
                    return self._record
                return None

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise PackNotFound(self._record.id)

        record = PackRecord(
            id=uuid.uuid4(),
            kind="tool",
            pack_id="cognic-tool-race",
            display_name="Race Pack",
            state="installed",
            manifest_digest=b"\x01" * 32,
            signed_artefact_digest=b"\x02" * 32,
            sbom_pointer=None,
            tenant_id="t1",
            created_by="bob@bank.example",
            last_actor="bob@bank.example",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        race_store: PackRecordStore = _RaceStore(record)  # type: ignore[assignment]
        actor = _make_operator_actor(
            subject="operator@bank.example",
            tenant_id="t1",
        )
        app = _build_app(actor=actor, store=race_store)

        with TestClient(app) as client:
            response = client.post(f"/api/v1/packs/{record.id}/revoke")
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"

        refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.revoke_refused"
        ]
        assert len(refused) == 1
        rec = refused[0]
        assert rec.reason == "pack_not_found"  # type: ignore[attr-defined]
        assert rec.actor_subject == "operator@bank.example"  # type: ignore[attr-defined]
        assert rec.pack_id == str(record.id)  # type: ignore[attr-defined]
        assert rec.from_state == "installed"  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Slice 4 — DELETE /api/v1/packs/{pack_id}/install (uninstall — real handler)
# (Multi-from-state: disabled/revoked → uninstalled)
# ---------------------------------------------------------------------------


class TestSprint7B2UninstallEndpoint:
    """``DELETE /api/v1/packs/{pack_id}/install`` — slice-4 handler.
    The uninstall verb shares the ``/install`` path with method=DELETE
    per the plan endpoint table.

    **Multi-from-state transition** per ``packs/lifecycle.py:230-234``:
    ``uninstall`` accepts BOTH ``disabled → uninstalled`` AND
    ``revoked → uninstalled``.

    State-machine refusal at this verb: from-state outside
    ``{disabled, revoked}`` → 409
    ``lifecycle_transition_uninstall_not_revoked_or_disabled``
    (closed-enum per-transition reason per ``packs/lifecycle.py:184``).

    R24 carry-forward + R27-hardened race contract — same shape as
    the revoke endpoint.
    """

    # -- Multi-from happy paths (watchpoint (a)) ------------------------

    async def test_uninstall_happy_path_from_disabled_advances_state_to_uninstalled(
        self,
        store: PackRecordStore,
    ) -> None:
        """Multi-from leg 1: ``disabled → uninstalled`` per
        ``packs/lifecycle.py:231``."""
        record = await _seed_disabled_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "uninstalled"

        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "uninstalled"

    async def test_uninstall_happy_path_from_revoked_advances_state_to_uninstalled(
        self,
        store: PackRecordStore,
    ) -> None:
        """Multi-from leg 2: ``revoked → uninstalled`` per
        ``packs/lifecycle.py:232``."""
        record = await _seed_revoked_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "uninstalled"

        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "uninstalled"

    async def test_uninstall_chain_row_carries_actor_type_in_payload(
        self,
        engine: AsyncEngine,
        store: PackRecordStore,
    ) -> None:
        """R24 carry-forward — uninstall chain row payload['actor_type']."""
        from sqlalchemy import select

        from cognic_agentos.core.decision_history import _decision_history

        record = await _seed_disabled_pack(store, tenant_id="t1")
        actor = _make_operator_actor(
            subject="operator@bank.example",
            tenant_id="t1",
            actor_type="human",
        )
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 200

        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    select(
                        _decision_history.c.event_type,
                        _decision_history.c.payload,
                    ).where(_decision_history.c.event_type == "pack.lifecycle.uninstalled")
                )
            ).all()
        uninstalled_rows = [r for r in rows if (r.payload or {}).get("pack_id") == str(record.id)]
        assert len(uninstalled_rows) == 1
        assert (uninstalled_rows[0].payload or {}).get("actor_type") == "human"

    async def test_uninstall_request_id_uses_pack_uninstal_prefix(
        self,
        store: PackRecordStore,
    ) -> None:
        """Plan R18 P2 #4 — minted request_id uses
        ``_PACK_UNINSTALL_REQUEST_ID_PREFIX`` (``pack-uninstal``,
        13 chars; no trailing dash — fits the prefix budget without
        breaking the bounded invariant)."""
        record = await _seed_disabled_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 200

        history = await store.load_lifecycle_history(record.id)
        uninstalled_rows = [r for r in history if r.decision_type == "pack.lifecycle.uninstalled"]
        assert len(uninstalled_rows) == 1
        request_id = uninstalled_rows[0].request_id
        assert len(request_id) <= 64
        assert request_id.startswith("pack-uninstal"), (
            f"uninstall request_id must use _PACK_UNINSTALL_REQUEST_ID_PREFIX; got {request_id!r}"
        )

    # -- Refusal axes ----------------------------------------------------

    async def test_uninstall_refuses_when_scope_missing(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan R19 P2 #2 — RBAC refusal sibling; ZERO operator-vocab log."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_disabled_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1", scopes=frozenset())
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 403
        assert response.json()["detail"]["reason"] == "scope_not_held"

        uninstall_refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.uninstall_refused"
        ]
        assert len(uninstall_refused) == 0

    async def test_uninstall_refuses_cross_tenant_with_404(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan watchpoint (c) — cross-tenant 404; ZERO operator-vocab log."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_disabled_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t2")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 404
        assert response.json()["detail"]["reason"] == "tenant_id_mismatch"

        uninstall_refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.uninstall_refused"
        ]
        assert len(uninstall_refused) == 0

    async def test_uninstall_refuses_not_revoked_or_disabled_returns_409(
        self,
        store: PackRecordStore,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """**Plan watchpoint (i) state-machine closure** — uninstall on
        an ``installed`` pack (out-of-vocab from-state for this verb)
        returns 409 with closed-enum
        ``lifecycle_transition_uninstall_not_revoked_or_disabled`` per
        ``packs/lifecycle.py:184``. EXACTLY ONE
        ``portal.packs.uninstall_refused`` log with all 4 extra
        fields."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)
        record = await _seed_installed_pack(store, tenant_id="t1")
        actor = _make_operator_actor(tenant_id="t1")
        app = _build_app(actor=actor, store=store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 409
        assert response.json()["detail"]["reason"] == (
            "lifecycle_transition_uninstall_not_revoked_or_disabled"
        )

        refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.uninstall_refused"
        ]
        assert len(refused) == 1
        rec = refused[0]
        assert rec.reason == "lifecycle_transition_uninstall_not_revoked_or_disabled"  # type: ignore[attr-defined]
        assert rec.actor_subject == "operator@bank.example"  # type: ignore[attr-defined]
        assert rec.pack_id == str(record.id)  # type: ignore[attr-defined]
        assert rec.from_state == "installed"  # type: ignore[attr-defined]

        # No state change.
        reloaded = await store.load(record.id)
        assert reloaded is not None
        assert reloaded.state == "installed"

    def test_uninstall_handles_pack_not_found_race(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Plan watchpoint (h) — PackNotFound race → 404. R27-hardened:
        EXACTLY 1 ``portal.packs.uninstall_refused`` log."""
        caplog.set_level(logging.WARNING, logger=_OPERATOR_ROUTES_LOGGER)

        class _RaceStore:
            def __init__(self, record: PackRecord) -> None:
                self._record = record

            async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
                if pack_id == self._record.id:
                    return self._record
                return None

            async def transition(self, **kwargs: Any) -> tuple[uuid.UUID, bytes]:
                raise PackNotFound(self._record.id)

        record = PackRecord(
            id=uuid.uuid4(),
            kind="tool",
            pack_id="cognic-tool-race",
            display_name="Race Pack",
            state="disabled",
            manifest_digest=b"\x01" * 32,
            signed_artefact_digest=b"\x02" * 32,
            sbom_pointer=None,
            tenant_id="t1",
            created_by="bob@bank.example",
            last_actor="bob@bank.example",
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        race_store: PackRecordStore = _RaceStore(record)  # type: ignore[assignment]
        actor = _make_operator_actor(
            subject="operator@bank.example",
            tenant_id="t1",
        )
        app = _build_app(actor=actor, store=race_store)

        with TestClient(app) as client:
            response = client.delete(f"/api/v1/packs/{record.id}/install")
        assert response.status_code == 404, response.text
        assert response.json()["detail"]["reason"] == "pack_not_found"

        refused = [
            r
            for r in caplog.records
            if r.name == _OPERATOR_ROUTES_LOGGER and r.message == "portal.packs.uninstall_refused"
        ]
        assert len(refused) == 1
        rec = refused[0]
        assert rec.reason == "pack_not_found"  # type: ignore[attr-defined]
        assert rec.actor_subject == "operator@bank.example"  # type: ignore[attr-defined]
        assert rec.pack_id == str(record.id)  # type: ignore[attr-defined]
        assert rec.from_state == "disabled"  # type: ignore[attr-defined]
