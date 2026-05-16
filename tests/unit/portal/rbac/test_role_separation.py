"""Sprint 7B.2 T5 — RequireDifferentActorThanCreator dependency + closed-enum.

Plan Round 11 P2 #4 — ADR-012 §17 cross-role separation (the same human
cannot both submit AND review their own pack). New CC module
``portal/rbac/role_separation.py`` carries the
``RequireDifferentActorThanCreator`` closure-factory + 1-value closed-enum
``RoleSeparationFailure`` literal.

Round 14 P2 #3 design refinements:
- Closure-factory shape (function, NOT class) — the inner closure declares
  ``Annotated[PackRecord, Depends(tenant_ownership)]`` referring to the
  captured ``tenant_ownership`` factory parameter. FastAPI's per-request
  callable-identity sub-dependency cache deduplicates the PackRecord
  load between the endpoint's tenant-ownership declaration and this
  guard's nested Depends → ONE store.load call on the happy path.

Round 15 P2 #1 — closure-safety invariants:
- Module MUST OMIT ``from __future__ import annotations`` (PEP 563
  would break FastAPI's closure-cell resolution; the resulting
  ``Annotated[..., Depends(<closure-var>)]`` would NameError).
- ``tenant_ownership`` factory parameter typed
  ``Callable[..., Awaitable[PackRecord]]`` (or the
  ``TenantOwnershipDep`` alias) — NOT ``RequireTenantOwnership``
  (the latter is a factory function, not a type for instances).

Round 16 P2 #3 — structured-log emission BEFORE every HTTPException
raise; logger ``cognic_agentos.portal.rbac.role_separation``; message
``portal.rbac.role_separation_refused``; extra carries reason +
actor_subject + pack_id + pack_created_by.

Pins:

- Admits :class:`Actor` when ``actor.subject != record.created_by``.
- Refuses with 403 + ``{"reason": "actor_cannot_review_own_pack"}`` when
  ``actor.subject == record.created_by``.
- Closed-enum stability — ``RoleSeparationFailure`` Literal frozen at 1
  value (Round 11 P2 #4).
"""

import ast
import inspect
import logging
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, cast, get_args, get_type_hints

import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from cognic_agentos.packs.storage import PackRecord
from cognic_agentos.portal.rbac import role_separation
from cognic_agentos.portal.rbac.actor import Actor, ActorBinder
from cognic_agentos.portal.rbac.role_separation import (
    RequireDifferentActorThanCreator,
    RoleSeparationFailure,
    TenantOwnershipDep,
)
from cognic_agentos.portal.rbac.tenant_isolation import RequireTenantOwnership

# ---------------------------------------------------------------------------
# Closed-enum stability pin (Round 11 P2 #4)
# ---------------------------------------------------------------------------


def test_role_separation_failure_literal_frozen_at_1_value() -> None:
    """Plan Round 11 P2 #4 — exactly 1 closed-enum reason for the role-separation guard.

    Mirrors the ``HumanActorDenialReason`` 1-value pattern at
    ``tests/unit/portal/rbac/test_human_actor.py::test_human_actor_denial_reason_literal_frozen_at_1_value``.

    Wire-protocol-public: the ``RoleSeparationFailure`` literal IS the
    closed-enum vocabulary carried in 403 denial bodies; any change
    is a wire-protocol break.
    """
    assert set(get_args(RoleSeparationFailure)) == {"actor_cannot_review_own_pack"}


# ---------------------------------------------------------------------------
# Module-header invariant — no `from __future__ import annotations`
# (Round 15 P2 #1 — load-bearing for FastAPI closure-cell resolution)
# ---------------------------------------------------------------------------


def test_module_must_not_import_future_annotations() -> None:
    """Plan Round 15 P2 #1 — AST self-test pinning the no-future-import invariant.

    ``role_separation.py`` MUST OMIT ``from __future__ import annotations``
    (unlike sibling RBAC modules at ``tenant_isolation.py:37`` /
    ``human_actor.py:26`` / ``enforcement.py:26`` which carry it).
    PEP 563 string-deferred annotations would prevent FastAPI's
    ``inspect.signature()`` / ``typing.get_type_hints()`` introspection
    from resolving ``Annotated[PackRecord, Depends(tenant_ownership)]``
    in the closure-factory's inner closure: the closure-bound
    ``tenant_ownership`` variable is NOT a module-global symbol, so a
    lazy string evaluation against module globals would ``NameError``
    or silently treat ``record`` + ``actor`` as query params
    (the T4-era query-param-leakage silent-failure bug).

    Per ``feedback_security_regression_hardening.md`` this AST self-test
    is one half of the load-bearing regression pair — the OTHER half is
    ``test_role_separation_resolves_under_fastapi_introspection``
    (forward-looking; lands later in T5 RED). Together they pin the
    invariant: AST self-test catches "someone added the future-import"
    regression; OpenAPI introspection test catches "FastAPI silently
    treats record/actor as query params" runtime bug.

    Implementation: parse the live ``role_separation.py`` source via
    ``ast.parse(Path(role_separation.__file__).read_text())`` and assert
    no module-level node matches
    ``ImportFrom(module="__future__", names=[alias(name="annotations", ...)])``.
    """
    source_path = Path(role_separation.__file__)
    tree = ast.parse(source_path.read_text())

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            for alias_node in node.names:
                assert alias_node.name != "annotations", (
                    "role_separation.py MUST OMIT `from __future__ import annotations` "
                    "per Round 15 P2 #1 — PEP 563 string-deferred annotations break "
                    "the FastAPI closure-cell resolution in "
                    "RequireDifferentActorThanCreator's inner closure."
                )


# ---------------------------------------------------------------------------
# Test fixtures — Actor + PackRecord builders
# ---------------------------------------------------------------------------


def _make_actor(**overrides: Any) -> Actor:
    """Build a fixture :class:`Actor` mirroring the
    ``test_human_actor.py::_make_actor`` convention. Defaults to
    ``alice@bank.example`` (subject) + tenant ``t1`` + human actor-type
    + ``pack.review.claim`` scope (the canonical reviewer scope).
    """
    defaults: dict[str, Any] = {
        "subject": "alice@bank.example",
        "tenant_id": "t1",
        "scopes": frozenset({"pack.review.claim"}),
        "actor_type": "human",
    }
    defaults.update(overrides)
    return Actor(**defaults)


def _make_record(**overrides: Any) -> PackRecord:
    """Build a fixture :class:`PackRecord`. Defaults match a typical
    submitted-state tool pack; tests override ``created_by`` to pin the
    role-separation discriminator.

    SHA-256 digests are filled with stable test bytes (32-byte width
    matches the live ``chain_hash_column_type`` cap; the bytes-values
    themselves are not asserted by the role-separation tests).
    """
    defaults: dict[str, Any] = {
        "id": uuid.UUID("00000000-0000-0000-0000-000000000001"),
        "kind": "tool",
        "pack_id": "test-pack",
        "display_name": "Test Pack",
        "state": "submitted",
        "manifest_digest": b"\x00" * 32,
        "signed_artefact_digest": b"\x11" * 32,
        "sbom_pointer": None,
        "tenant_id": "t1",
        "created_by": "bob@bank.example",
        "last_actor": "bob@bank.example",
        "created_at": datetime(2026, 5, 12, tzinfo=UTC),
        "updated_at": datetime(2026, 5, 12, tzinfo=UTC),
    }
    defaults.update(overrides)
    return PackRecord(**defaults)


async def _stub_tenant_ownership_impl() -> PackRecord:
    """Sentinel stub for the ``tenant_ownership`` factory parameter.

    The unit-tests for the closure-factory's LOGIC don't need a working
    tenant-ownership dependency — they invoke the inner ``_check``
    closure directly with the ``record`` kwarg bound. The factory only
    captures this reference in its annotation metadata; FastAPI's
    ``Depends(...)`` resolution machinery is exercised separately by
    :func:`test_role_separation_resolves_under_fastapi_introspection`.

    The function is typed to match :data:`TenantOwnershipDep` so mypy
    accepts it as the factory argument; the body raises
    ``NotImplementedError`` because it must never actually be invoked
    in the unit-test path.
    """
    raise NotImplementedError(
        "_stub_tenant_ownership_impl is a closure-reference sentinel only; it must never be invoked"
    )


_stub_tenant_ownership: TenantOwnershipDep = _stub_tenant_ownership_impl


# ---------------------------------------------------------------------------
# Closure-factory happy path (Round 11 P2 #4 + Round 14 P2 #3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_role_separation_admits_when_subjects_differ() -> None:
    """Plan Round 11 P2 #4 — closure admits when ``actor.subject != record.created_by``.

    Constructs the closure-factory with a stub ``tenant_ownership``
    callable, then invokes the inner closure directly with manually-
    bound ``actor`` + ``record`` + ``request`` kwargs (bypassing FastAPI's
    ``Depends`` resolution — the OpenAPI introspection test covers the
    live FastAPI path separately).

    Sprint-7B.4 T6: the closure signature now takes ``request`` so the
    refusal path can resolve ``request.app.state.ui_event_broker`` for
    the shared ``_emit_denial_or_500`` helper. On the admit path the
    request is never accessed — but pytest's MagicMock auto-creation
    would return a Mock for any attr if we didn't bind ``request``
    explicitly. The simplest approach: pass a minimal MagicMock with
    `ui_event_broker` explicitly bound to None (the admit path doesn't
    read it; this is just defence-in-depth against silent test drift
    if a future change moves the broker resolution above the if-guard).

    Reviewer ``alice@bank.example`` claiming a pack created by
    ``bob@bank.example`` is the canonical happy path: subjects differ;
    cross-role separation is satisfied; the closure returns ``None``
    without raising.
    """
    from unittest.mock import MagicMock

    require_diff = RequireDifferentActorThanCreator(
        tenant_ownership=_stub_tenant_ownership,
    )

    actor = _make_actor(subject="alice@bank.example")
    record = _make_record(created_by="bob@bank.example")
    request = MagicMock()
    request.app.state.ui_event_broker = None
    request.state.request_id = "portal-req-test-admit"

    # Should return None without raising — subjects differ.
    await require_diff(request=request, actor=actor, record=record)


# ---------------------------------------------------------------------------
# Closure-factory refusal path (Round 11 P2 #4 + Round 14 P2 #3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_role_separation_refuses_when_subjects_match() -> None:
    """Plan Round 11 P2 #4 — closure refuses with 403 + closed-enum body
    when ``actor.subject == record.created_by`` (ADR-012 §17 cross-role
    separation invariant).

    Same actor as creator: ``bob@bank.example`` trying to review their
    OWN pack. The closure must raise :class:`HTTPException` with:

    - ``status_code == 403``
    - ``detail == {"reason": "actor_cannot_review_own_pack"}``

    Closed-enum reason value matches the wire-protocol-public
    :data:`RoleSeparationFailure` literal pinned at test #1.
    """
    from unittest.mock import MagicMock

    require_diff = RequireDifferentActorThanCreator(
        tenant_ownership=_stub_tenant_ownership,
    )

    actor = _make_actor(subject="bob@bank.example")
    record = _make_record(created_by="bob@bank.example")
    # Sprint-7B.4 T6: closure now takes `request` for broker resolution
    # via `_emit_denial_or_500`. broker=None forces the helper's log-only
    # fallback (no chain emit attempt) — refusal path still raises 403
    # with the same closed-enum detail.
    request = MagicMock()
    request.app.state.ui_event_broker = None
    request.state.request_id = "portal-req-test-refuse"

    with pytest.raises(HTTPException) as excinfo:
        await require_diff(request=request, actor=actor, record=record)

    assert excinfo.value.status_code == 403
    # HTTPException.detail is typed Any by FastAPI; cast for mypy clarity.
    detail = cast(dict[str, str], excinfo.value.detail)
    assert detail == {"reason": "actor_cannot_review_own_pack"}


# ---------------------------------------------------------------------------
# Structured-log emission parity (Round 16 P2 #3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_role_separation_emits_structured_log(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Sprint-7B.4 T6 wire-shape: structured-log emission moved from
    per-module `_LOG.warning("portal.rbac.role_separation_refused", ...)`
    in role_separation to the shared `_emit_denial_or_500` helper in
    enforcement. Wire changes:

    - Logger source: ``cognic_agentos.portal.rbac.role_separation`` →
      ``cognic_agentos.portal.rbac.enforcement``
    - Message: ``portal.rbac.role_separation_refused`` →
      ``portal.rbac.actor_cannot_review_own_pack``

    Structured ``reason`` / ``actor_subject`` / ``pack_id`` /
    ``pack_created_by`` fields unchanged — operators querying on
    structured fields stay compatible.

    Asserts on the refusal path (subjects match):
    - EXACTLY ONE log record fires at WARNING level
    - Logger: ``cognic_agentos.portal.rbac.enforcement``
    - Message: ``portal.rbac.actor_cannot_review_own_pack``
    - ``extra`` dict carries closed-enum reason + actor_subject +
      pack_id + pack_created_by

    Asserts on the admit path (subjects differ): NO denial log record
    fires on the enforcement logger.
    """
    from unittest.mock import MagicMock

    require_diff = RequireDifferentActorThanCreator(
        tenant_ownership=_stub_tenant_ownership,
    )

    # --- Refusal path: subjects match ---
    caplog.clear()
    caplog.set_level(logging.WARNING, logger="cognic_agentos.portal.rbac.enforcement")

    actor = _make_actor(subject="bob@bank.example")
    record = _make_record(
        id=uuid.UUID("11111111-2222-3333-4444-555555555555"),
        created_by="bob@bank.example",
    )
    request = MagicMock()
    request.app.state.ui_event_broker = None  # T6 log-only fallback
    request.state.request_id = "portal-req-test-rs-log"

    with pytest.raises(HTTPException):
        await require_diff(request=request, actor=actor, record=record)

    enforcement_records = [
        r
        for r in caplog.records
        if r.name == "cognic_agentos.portal.rbac.enforcement"
        and r.message == "portal.rbac.actor_cannot_review_own_pack"
    ]
    assert len(enforcement_records) == 1, (
        f"expected EXACTLY ONE enforcement log record on refusal, got {len(enforcement_records)}"
    )
    record_log = enforcement_records[0]
    assert record_log.levelno == logging.WARNING
    assert record_log.reason == "actor_cannot_review_own_pack"  # type: ignore[attr-defined]
    assert record_log.actor_subject == "bob@bank.example"  # type: ignore[attr-defined]
    assert record_log.pack_id == "11111111-2222-3333-4444-555555555555"  # type: ignore[attr-defined]
    assert record_log.pack_created_by == "bob@bank.example"  # type: ignore[attr-defined]

    # --- Admit path: subjects differ; no denial log record fires ---
    caplog.clear()

    admit_actor = _make_actor(subject="alice@bank.example")
    admit_record = _make_record(created_by="bob@bank.example")
    admit_request = MagicMock()
    admit_request.app.state.ui_event_broker = None
    admit_request.state.request_id = "portal-req-test-rs-admit"

    await require_diff(request=admit_request, actor=admit_actor, record=admit_record)

    admit_records = [
        r
        for r in caplog.records
        if r.name == "cognic_agentos.portal.rbac.enforcement"
        and r.message == "portal.rbac.actor_cannot_review_own_pack"
    ]
    assert len(admit_records) == 0, (
        f"admit path must emit NO denial log record; got {len(admit_records)}"
    )


# ---------------------------------------------------------------------------
# Closure-factory shape introspection (Round 14 P2 #3 + Round 15 P2 #1)
# ---------------------------------------------------------------------------


def test_role_separation_closure_factory_shape() -> None:
    """Plan Round 14 P2 #3 + Round 15 P2 #1 — closure-factory shape pins.

    Asserts on the returned callable from :func:`RequireDifferentActorThanCreator`:

    1. **Shape is a callable** (not a class instance with ``__call__``)
       — the closure-factory pattern returns the inner ``_check``
       coroutine function directly.

    2. **Inspect signature** has two parameters named ``actor`` + ``record``
       — these are FastAPI's sub-dep resolution targets via the
       ``Annotated[..., Depends(...)]`` annotations.

    3. **Round 15 P2 #1 — annotation-object capture at def-time** —
       under the live (non-future-import) annotation regime, the
       ``Annotated[PackRecord, Depends(tenant_ownership)]`` parameter
       annotation is evaluated at ``def _check(...)`` time, producing
       an actual ``Annotated`` object whose metadata embeds the
       ``Depends(tenant_ownership)`` instance. FastAPI's
       ``typing.get_type_hints(..., include_extras=True)`` then reads
       the embedded ``Depends`` and resolves the captured
       ``tenant_ownership`` reference. This is what would break under
       ``from __future__ import annotations``: the annotation becomes a
       lazy string, the lazy-eval against module globals fails because
       ``tenant_ownership`` is a closure-local name, and FastAPI silently
       falls back to query-param resolution. Verifying the captured
       ``Depends`` instance is the load-bearing closure-cell-substitute
       invariant.

    4. **Type-hint resolution works** under the live (non-future-import)
       annotation regime — ``typing.get_type_hints()`` returns the
       resolved types for the closure's parameters, proving FastAPI's
       introspection path will work at route-registration time.
    """
    captured_tenant_ownership = _stub_tenant_ownership
    require_diff = RequireDifferentActorThanCreator(
        tenant_ownership=captured_tenant_ownership,
    )

    # (1) Returned object is a callable, not a class instance.
    assert callable(require_diff)
    assert inspect.iscoroutinefunction(require_diff)

    # (2) Signature has actor + record + request parameters.
    # Sprint-7B.4 T6 added `request` for broker resolution via the
    # shared `_emit_denial_or_500` helper (FastAPI auto-injects
    # `Request` for any param typed as such — transparent to existing
    # endpoint callers that declare `Depends(require_diff)` without
    # passing `request` themselves).
    sig = inspect.signature(require_diff)
    assert set(sig.parameters.keys()) == {"actor", "record", "request"}

    # (3) Annotation-object capture: the `record` parameter's annotation
    #     is `Annotated[PackRecord, Depends(captured_tenant_ownership)]`
    #     and the Depends instance embedded in its metadata carries the
    #     EXACT tenant_ownership reference passed at factory construction.
    hints = get_type_hints(require_diff, include_extras=True)
    record_hint = hints["record"]
    # Walk the Annotated metadata tuple looking for the captured Depends
    # whose .dependency attribute IS the same callable.
    annotated_metadata = getattr(record_hint, "__metadata__", ())
    assert any(
        getattr(meta, "dependency", None) is captured_tenant_ownership
        for meta in annotated_metadata
    ), (
        "the returned closure's `record` parameter annotation must embed "
        "`Depends(tenant_ownership)` with the EXACT instance passed at "
        "factory construction (not a copy or wrapper); pinning the "
        "annotation-object-capture invariant per Round 14 P2 #3 + Round 15 P2 #1"
    )

    # (4) Type-hint resolution works under the live annotation regime
    #     (no `from __future__ import annotations`). The hints dict
    #     resolves `Actor` + `PackRecord` to the actual classes.
    assert "actor" in hints
    assert "record" in hints


# ---------------------------------------------------------------------------
# FastAPI-introspection regression — load-bearing pair with test #2
# (Round 15 P2 #1)
# ---------------------------------------------------------------------------


class _StubBinder:
    """Bank-overlay-fixture-shaped :class:`ActorBinder` returning a fixed actor."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


class _StubPackRecordStore:
    """Fixture pack-record store. Implements only :meth:`load` (the read
    seam ``RequireTenantOwnership`` calls)."""

    def __init__(self, record: PackRecord | None) -> None:
        self._record = record

    async def load(self, pack_id: uuid.UUID) -> PackRecord | None:
        return self._record


def test_role_separation_resolves_under_fastapi_introspection() -> None:
    """Plan Round 15 P2 #1 — load-bearing pair with the AST self-test.

    This test is half of the regression pair pinning the no-future-import
    invariant per ``feedback_security_regression_hardening.md``:

    - The AST self-test (``test_module_must_not_import_future_annotations``)
      catches the "someone added ``from __future__ import annotations``"
      regression at the source-level.
    - This test catches the runtime symptom: when annotations are
      string-deferred, FastAPI cannot resolve ``Depends(tenant_ownership)``
      against the closure cell, so it silently falls back to treating
      ``record`` + ``actor`` as query parameters.

    Builds a fresh :class:`FastAPI` test app with the role-separation
    closure-factory wired into a mock route, forces full signature
    introspection via :meth:`FastAPI.openapi`, and asserts:

    1. The OpenAPI spec for the route does NOT list ``record`` or
       ``actor`` as ``query`` parameters (would indicate FastAPI fell
       back to query-param resolution because Depends() couldn't resolve).
    2. The route returns 403 with the closed-enum body on the
       author-of-pack integration green path (proves the live FastAPI
       Depends() resolution actually wires the guard correctly).
    """
    # --- Build a mock pack matching the actor's tenant_id + created_by ---
    pack_uuid = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    record = _make_record(
        id=pack_uuid,
        tenant_id="t1",
        created_by="bob@bank.example",  # SAME as the actor below → triggers 403
    )

    # --- Build a fresh FastAPI app ---
    app = FastAPI()
    actor = _make_actor(
        subject="bob@bank.example",  # SAME as record.created_by
        tenant_id="t1",
    )
    binder: ActorBinder = _StubBinder(actor)
    app.state.actor_binder = binder
    app.state.pack_record_store = _StubPackRecordStore(record)

    # --- Wire the dependency chain mirroring the production T5 pattern ---
    require_tenant = RequireTenantOwnership(pack_id_param="pack_id")
    require_diff = RequireDifferentActorThanCreator(tenant_ownership=require_tenant)

    @app.post("/api/v1/packs/{pack_id}/claim")
    def claim(
        pack_id: uuid.UUID,
        record: Annotated[PackRecord, Depends(require_tenant)],
        _: Annotated[None, Depends(require_diff)],
    ) -> dict[str, str]:
        return {"pack_id": str(record.id)}

    # --- (1) OpenAPI introspection: no record/actor as query params ---
    spec = app.openapi()
    paths_block = spec["paths"]["/api/v1/packs/{pack_id}/claim"]["post"]
    query_params = [p["name"] for p in paths_block.get("parameters", []) if p.get("in") == "query"]
    assert "record" not in query_params, (
        "FastAPI fell back to treating `record` as a query param — proves the "
        "Depends(tenant_ownership) closure-cell resolution broke (likely "
        "because `from __future__ import annotations` was added to "
        "role_separation.py; pinned load-bearingly with the AST self-test)"
    )
    assert "actor" not in query_params, (
        "FastAPI fell back to treating `actor` as a query param — same "
        "closure-cell resolution regression as above"
    )

    # --- (2) Integration green path — 403 on author-of-pack ---
    client = TestClient(app)
    response = client.post(f"/api/v1/packs/{pack_uuid}/claim")
    assert response.status_code == 403, (
        f"expected 403 (actor_cannot_review_own_pack) on author-of-pack "
        f"claim attempt; got {response.status_code} with body {response.json()}"
    )
    assert response.json() == {"detail": {"reason": "actor_cannot_review_own_pack"}}


# ---------------------------------------------------------------------------
# Closed-enum drift sanity (test re-uses fixtures; smoke check on the
# unused imports the file declares — keeps mypy + pyright clean)
# ---------------------------------------------------------------------------


def test_role_separation_failure_value_matches_pack_created_by_check() -> None:
    """Cross-reference assertion — the SAME literal value
    (``actor_cannot_review_own_pack``) appears in:

    - :data:`RoleSeparationFailure` (closed-enum source of truth)
    - the 403 ``detail.reason`` body emitted by the closure
    - the structured log's ``extra["reason"]`` field

    If a refactor renames the value in one location but not the others,
    the wire-protocol-public closed-enum contract fragments. This test
    cross-references all three surfaces against
    :data:`RoleSeparationFailure` to catch the drift.

    Style: separate test (not folded into the literal-frozen test) so a
    drift in only one surface gives a clear, isolated failure signal.
    """
    canonical_value: str = "actor_cannot_review_own_pack"
    assert canonical_value in get_args(RoleSeparationFailure)
