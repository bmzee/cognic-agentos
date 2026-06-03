"""Sprint 11.5c T5 — portal /memory route test surface.

Tests the 4-endpoint ``/api/v1/memory`` router via a lightweight test harness
that mirrors ``tests/unit/portal/api/packs/test_operator_routes.py``:

- A ``_StubBinder`` injects a configurable :class:`Actor` (subject / tenant /
  scopes / actor_type) per test.
- A ``_FakeMemoryAPI`` stub captures the last ``MemoryCallerContext`` the
  factory was called with (for operator-context assertions) and returns canned
  receipts or raises ``MemoryOperationRefused`` depending on configuration.
- Tests build a TestClient via ``create_app(memory_api_factory=...,
  actor_binder=...)`` — real FastAPI routing, real RBAC deps, no mocking of
  the dep chain.

Test classes:
1. ``test_routes_module_must_not_import_future_annotations`` — AST self-test
   (Standing-offer §30 — load-bearing for FastAPI closure-cell resolution).
2. :class:`TestListRecords` — 200 response shape (no ``value`` key), 409 on
   MemoryOperationRefused.
3. :class:`TestForget` — happy path (user_request), regulator_erasure gate
   (service actor → 403 actor_type_must_be_human; missing scope → 403
   scope_not_held; human + scope + command → 200), 404 on record_not_found,
   409 on lifecycle refusal.
4. :class:`TestRedact` — 200 shape, 404 on record_not_found, 409 on lifecycle.
5. :class:`TestExport` — service actor → 403 actor_type_must_be_human; human
   + scope → 200 shape; 409 on MemoryOperationRefused.
6. :class:`TestOperatorContext` — asserts the context built by the route has
   is_subagent=False, tenant_id from actor, agent_id from body/query.
"""

from __future__ import annotations

import ast
import pathlib
import uuid
from typing import Any

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from cognic_agentos.core.memory._context import (
    ExportReceipt,
    ForgetReceipt,
    MemoryCallerContext,
    MemoryRecordMetadata,
    RedactionReceipt,
)
from cognic_agentos.core.memory.api import MemoryAPI, MemoryApiFactory
from cognic_agentos.core.memory.tiers import MemoryOperationRefused, SubjectRef
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor

# ---------------------------------------------------------------------------
# Helpers / stubs
# ---------------------------------------------------------------------------

_ROUTES_MODULE_PATH = (
    pathlib.Path(__file__).resolve().parents[5]
    / "src"
    / "cognic_agentos"
    / "portal"
    / "api"
    / "memory"
    / "routes.py"
)


class _StubBinder:
    """Test-only ActorBinder returning a configured actor (mirrors operator_routes tests)."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_memory_actor(
    *,
    subject: str = "operator@bank.example",
    tenant_id: str = "tenant-1",
    scopes: frozenset[str] | None = None,
    actor_type: str = "human",
) -> Actor:
    """Build a fixture Actor with all memory scopes by default."""
    if scopes is None:
        scopes = frozenset(
            {
                "memory.read",
                "memory.forget",
                "memory.redact",
                "memory.regulator_erasure",
                "memory.export.read",
            }
        )
    return Actor(
        subject=subject,
        tenant_id=tenant_id,
        scopes=scopes,  # type: ignore[arg-type]
        actor_type=actor_type,  # type: ignore[arg-type]
    )


class _FakeMemoryAPI:
    """Lightweight fake MemoryAPI that captures call context + returns canned data.

    ``raise_on_*`` kwargs configure specific method calls to raise
    ``MemoryOperationRefused`` with the given reason.
    """

    def __init__(
        self,
        *,
        raise_on_list: str | None = None,
        raise_on_forget: str | None = None,
        raise_on_redact: str | None = None,
        raise_on_export: str | None = None,
    ) -> None:
        self._raise_on_list = raise_on_list
        self._raise_on_forget = raise_on_forget
        self._raise_on_redact = raise_on_redact
        self._raise_on_export = raise_on_export

    async def list_records(self, subject: SubjectRef) -> list[MemoryRecordMetadata]:
        if self._raise_on_list:
            raise MemoryOperationRefused(self._raise_on_list)  # type: ignore[arg-type]
        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        return [
            MemoryRecordMetadata(
                record_id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
                agent_id="agent-1",
                tier="task",
                data_classes=("internal",),
                purpose="transaction_processing",
                created_at=now,
                block_kind=None,
            )
        ]

    async def forget(
        self,
        record_id: Any,
        *,
        reason: Any,
        erasure_command: Any = None,
    ) -> ForgetReceipt:
        if self._raise_on_forget:
            raise MemoryOperationRefused(self._raise_on_forget)  # type: ignore[arg-type]
        return ForgetReceipt(
            record_id=record_id,
            tombstoned=True,
            purged=(reason == "regulator_erasure"),
        )

    async def redact(self, record_id: Any, *, span: Any, reason: Any) -> RedactionReceipt:
        if self._raise_on_redact:
            raise MemoryOperationRefused(self._raise_on_redact)  # type: ignore[arg-type]
        new_id = uuid.UUID("00000000-0000-0000-0000-000000000002")
        return RedactionReceipt(
            record_id=record_id,
            new_version_id=new_id,
            redaction_version=1,
        )

    async def export(self, subject: SubjectRef) -> ExportReceipt:
        if self._raise_on_export:
            raise MemoryOperationRefused(self._raise_on_export)  # type: ignore[arg-type]
        return ExportReceipt(
            object_key="tenant-1/export-001.tar.gz",
            archive_sha256="abc123",
            record_count=3,
        )


class _CapturingFactory:
    """Factory that captures the MemoryCallerContext passed at construction time."""

    def __init__(self, api: _FakeMemoryAPI) -> None:
        self._api = api
        self.last_context: MemoryCallerContext | None = None

    def __call__(self, ctx: MemoryCallerContext) -> MemoryAPI:
        self.last_context = ctx
        return self._api  # type: ignore[return-value]


def _build_app(*, actor: Actor, factory: MemoryApiFactory) -> FastAPI:
    """Build a portal app via create_app with the given actor binder + memory factory."""
    return create_app(
        actor_binder=_StubBinder(actor),
        memory_api_factory=factory,
    )


# ---------------------------------------------------------------------------
# 1. AST self-test — routes.py must NOT import from __future__ annotations
# ---------------------------------------------------------------------------


def test_routes_module_must_not_import_future_annotations() -> None:
    """Standing-offer §30: ``routes.py`` MUST NOT have ``from __future__ import
    annotations``. PEP 563 string-deferred annotations break FastAPI's
    ``inspect.signature()`` for ``Annotated[..., Depends(<closure-local>)]``
    handlers — the dep would silently become a query param.

    This is the same AST guard that protects operator_routes.py, review_routes.py,
    and other closure-factory route modules."""
    source = _ROUTES_MODULE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(_ROUTES_MODULE_PATH))

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "__future__":
            names = [alias.name for alias in node.names]
            assert "annotations" not in names, (
                "routes.py must NOT import 'annotations' from '__future__' — "
                "PEP 563 breaks FastAPI closure-local Depends resolution. "
                "See Standing-offer §30 in the module docstring."
            )


# ---------------------------------------------------------------------------
# 2. list_records tests
# ---------------------------------------------------------------------------


class TestListRecords:
    def _client(self, *, actor: Actor, factory: MemoryApiFactory) -> TestClient:
        return TestClient(_build_app(actor=actor, factory=factory))

    def test_returns_200_with_metadata_list(self) -> None:
        actor = _make_memory_actor()
        factory = _CapturingFactory(_FakeMemoryAPI())
        client = self._client(actor=actor, factory=factory)

        resp = client.get(
            "/api/v1/memory/records",
            params={"subject_kind": "human", "subject_id": "user-1", "agent_id": "agent-1"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) == 1

    def test_response_items_have_no_value_key(self) -> None:
        actor = _make_memory_actor()
        factory = _CapturingFactory(_FakeMemoryAPI())
        client = self._client(actor=actor, factory=factory)

        resp = client.get(
            "/api/v1/memory/records",
            params={"subject_kind": "human", "subject_id": "user-1", "agent_id": "agent-1"},
        )

        assert resp.status_code == 200
        for item in resp.json():
            assert "value" not in item, (
                f"MemoryRecordMetadataResponse must NOT expose 'value' — "
                f"got keys: {list(item.keys())}"
            )

    def test_scope_not_held_returns_403(self) -> None:
        actor = _make_memory_actor(scopes=frozenset({"memory.forget"}))
        factory = _CapturingFactory(_FakeMemoryAPI())
        client = self._client(actor=actor, factory=factory)

        resp = client.get(
            "/api/v1/memory/records",
            params={"subject_kind": "human", "subject_id": "user-1", "agent_id": "agent-1"},
        )

        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "scope_not_held"

    def test_memory_operation_refused_returns_409(self) -> None:
        actor = _make_memory_actor()
        factory = _CapturingFactory(
            _FakeMemoryAPI(raise_on_list="memory_subagent_durable_access_refused")
        )
        client = self._client(actor=actor, factory=factory)

        resp = client.get(
            "/api/v1/memory/records",
            params={"subject_kind": "human", "subject_id": "user-1", "agent_id": "agent-1"},
        )

        assert resp.status_code == 409
        assert resp.json()["detail"]["reason"] == "memory_subagent_durable_access_refused"


# ---------------------------------------------------------------------------
# 3. forget tests
# ---------------------------------------------------------------------------


class TestForget:
    _RECORD_ID = str(uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"))

    def _client(self, *, actor: Actor, factory: MemoryApiFactory) -> TestClient:
        return TestClient(_build_app(actor=actor, factory=factory))

    def test_user_request_forget_returns_200(self) -> None:
        actor = _make_memory_actor()
        factory = _CapturingFactory(_FakeMemoryAPI())
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            f"/api/v1/memory/records/{self._RECORD_ID}/forget",
            json={
                "reason": "user_request",
                "agent_id": "agent-1",
                "subject_kind": "human",
                "subject_id": "user-1",
            },
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["tombstoned"] is True
        assert body["purged"] is False
        assert "record_id" in body

    def test_regulator_erasure_refuses_service_actor_holding_scope(self) -> None:
        """A SERVICE actor holding memory.regulator_erasure must get 403
        actor_type_must_be_human — the body-aware human gate fires."""
        actor = _make_memory_actor(actor_type="service")
        factory = _CapturingFactory(_FakeMemoryAPI())
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            f"/api/v1/memory/records/{self._RECORD_ID}/forget",
            json={
                "reason": "regulator_erasure",
                "agent_id": "agent-1",
                "subject_kind": "human",
                "subject_id": "user-1",
                "erasure_command": {
                    "regulator_order_id": "ORDER-001",
                    "requester_scope": "memory.regulator_erasure",
                    "subject_id": "user-1",
                },
            },
        )

        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "actor_type_must_be_human"

    def test_regulator_erasure_refuses_human_missing_erasure_scope(self) -> None:
        """A HUMAN actor lacking memory.regulator_erasure must get 403
        scope_not_held — the body-aware scope check fires before the
        human check."""
        actor = _make_memory_actor(
            actor_type="human",
            scopes=frozenset({"memory.forget"}),  # missing memory.regulator_erasure
        )
        factory = _CapturingFactory(_FakeMemoryAPI())
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            f"/api/v1/memory/records/{self._RECORD_ID}/forget",
            json={
                "reason": "regulator_erasure",
                "agent_id": "agent-1",
                "subject_kind": "human",
                "subject_id": "user-1",
                "erasure_command": {
                    "regulator_order_id": "ORDER-001",
                    "requester_scope": "memory.regulator_erasure",
                    "subject_id": "user-1",
                },
            },
        )

        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "scope_not_held"

    def test_regulator_erasure_succeeds_for_human_with_scope_and_command(self) -> None:
        """A HUMAN actor holding memory.regulator_erasure + valid erasure_command → 200."""
        actor = _make_memory_actor(actor_type="human")
        capturing = _CapturingFactory(_FakeMemoryAPI())
        client = self._client(actor=actor, factory=capturing)

        resp = client.post(
            f"/api/v1/memory/records/{self._RECORD_ID}/forget",
            json={
                "reason": "regulator_erasure",
                "agent_id": "agent-1",
                "subject_kind": "human",
                "subject_id": "user-1",
                "erasure_command": {
                    "regulator_order_id": "ORDER-001",
                    "requester_scope": "memory.regulator_erasure",
                    "subject_id": "user-1",
                },
            },
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["tombstoned"] is True
        assert body["purged"] is True  # regulator_erasure path

    def test_record_not_found_returns_404(self) -> None:
        actor = _make_memory_actor()
        factory = _CapturingFactory(_FakeMemoryAPI(raise_on_forget="memory_record_not_found"))
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            f"/api/v1/memory/records/{self._RECORD_ID}/forget",
            json={
                "reason": "user_request",
                "agent_id": "agent-1",
                "subject_kind": "human",
                "subject_id": "user-1",
            },
        )

        assert resp.status_code == 404
        assert resp.json()["detail"]["reason"] == "memory_record_not_found"

    def test_lifecycle_refusal_returns_409(self) -> None:
        actor = _make_memory_actor()
        factory = _CapturingFactory(
            _FakeMemoryAPI(raise_on_forget="memory_subagent_durable_access_refused")
        )
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            f"/api/v1/memory/records/{self._RECORD_ID}/forget",
            json={
                "reason": "user_request",
                "agent_id": "agent-1",
                "subject_kind": "human",
                "subject_id": "user-1",
            },
        )

        assert resp.status_code == 409
        assert resp.json()["detail"]["reason"] == "memory_subagent_durable_access_refused"


# ---------------------------------------------------------------------------
# 4. redact tests
# ---------------------------------------------------------------------------


class TestRedact:
    _RECORD_ID = str(uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"))

    def _client(self, *, actor: Actor, factory: MemoryApiFactory) -> TestClient:
        return TestClient(_build_app(actor=actor, factory=factory))

    def test_redact_returns_200_with_receipt_shape(self) -> None:
        actor = _make_memory_actor()
        factory = _CapturingFactory(_FakeMemoryAPI())
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            f"/api/v1/memory/records/{self._RECORD_ID}/redact",
            json={
                "span_path": ["account", "number"],
                "replacement": "[REDACTED]",
                "reason": "pii_minimization",
                "agent_id": "agent-1",
                "subject_kind": "human",
                "subject_id": "user-1",
            },
        )

        assert resp.status_code == 200
        body = resp.json()
        assert "record_id" in body
        assert "new_version_id" in body
        assert body["redaction_version"] == 1

    def test_scope_not_held_returns_403(self) -> None:
        actor = _make_memory_actor(scopes=frozenset({"memory.read"}))
        factory = _CapturingFactory(_FakeMemoryAPI())
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            f"/api/v1/memory/records/{self._RECORD_ID}/redact",
            json={
                "span_path": ["field"],
                "reason": "pii_minimization",
                "agent_id": "agent-1",
                "subject_kind": "human",
                "subject_id": "user-1",
            },
        )

        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "scope_not_held"

    def test_record_not_found_returns_404(self) -> None:
        actor = _make_memory_actor()
        factory = _CapturingFactory(_FakeMemoryAPI(raise_on_redact="memory_record_not_found"))
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            f"/api/v1/memory/records/{self._RECORD_ID}/redact",
            json={
                "span_path": ["field"],
                "reason": "pii_minimization",
                "agent_id": "agent-1",
                "subject_kind": "human",
                "subject_id": "user-1",
            },
        )

        assert resp.status_code == 404
        assert resp.json()["detail"]["reason"] == "memory_record_not_found"

    def test_lifecycle_refusal_returns_409(self) -> None:
        actor = _make_memory_actor()
        factory = _CapturingFactory(
            _FakeMemoryAPI(raise_on_redact="memory_record_already_tombstoned")
        )
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            f"/api/v1/memory/records/{self._RECORD_ID}/redact",
            json={
                "span_path": ["field"],
                "reason": "pii_minimization",
                "agent_id": "agent-1",
                "subject_kind": "human",
                "subject_id": "user-1",
            },
        )

        assert resp.status_code == 409
        assert resp.json()["detail"]["reason"] == "memory_record_already_tombstoned"


# ---------------------------------------------------------------------------
# 5. export tests
# ---------------------------------------------------------------------------


class TestExport:
    def _client(self, *, actor: Actor, factory: MemoryApiFactory) -> TestClient:
        return TestClient(_build_app(actor=actor, factory=factory))

    def test_service_actor_returns_403_actor_type_must_be_human(self) -> None:
        """Even with memory.export.read scope, a SERVICE actor must be refused."""
        actor = _make_memory_actor(actor_type="service")
        factory = _CapturingFactory(_FakeMemoryAPI())
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            "/api/v1/memory/export",
            json={"agent_id": "agent-1", "subject_kind": "human", "subject_id": "user-1"},
        )

        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "actor_type_must_be_human"

    def test_human_with_export_scope_returns_200(self) -> None:
        actor = _make_memory_actor(actor_type="human")
        factory = _CapturingFactory(_FakeMemoryAPI())
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            "/api/v1/memory/export",
            json={"agent_id": "agent-1", "subject_kind": "human", "subject_id": "user-1"},
        )

        assert resp.status_code == 200
        body = resp.json()
        assert body["object_key"] == "tenant-1/export-001.tar.gz"
        assert body["archive_sha256"] == "abc123"
        assert body["record_count"] == 3

    def test_export_scope_not_held_returns_403(self) -> None:
        actor = _make_memory_actor(
            actor_type="human",
            scopes=frozenset({"memory.read"}),  # missing memory.export.read
        )
        factory = _CapturingFactory(_FakeMemoryAPI())
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            "/api/v1/memory/export",
            json={"agent_id": "agent-1", "subject_kind": "human", "subject_id": "user-1"},
        )

        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "scope_not_held"

    def test_memory_operation_refused_returns_409(self) -> None:
        actor = _make_memory_actor(actor_type="human")
        factory = _CapturingFactory(
            _FakeMemoryAPI(raise_on_export="memory_subagent_durable_access_refused")
        )
        client = self._client(actor=actor, factory=factory)

        resp = client.post(
            "/api/v1/memory/export",
            json={"agent_id": "agent-1", "subject_kind": "human", "subject_id": "user-1"},
        )

        assert resp.status_code == 409
        assert resp.json()["detail"]["reason"] == "memory_subagent_durable_access_refused"


# ---------------------------------------------------------------------------
# 6. Operator context assertions
# ---------------------------------------------------------------------------


class TestOperatorContext:
    """Assert the MemoryCallerContext built by the route has the correct shape."""

    def test_list_records_context_has_is_subagent_false_and_correct_identity(self) -> None:
        actor = _make_memory_actor(
            subject="ops@bank.example",
            tenant_id="tenant-x",
        )
        capturing = _CapturingFactory(_FakeMemoryAPI())
        app = _build_app(actor=actor, factory=capturing)
        client = TestClient(app)

        client.get(
            "/api/v1/memory/records",
            params={"subject_kind": "human", "subject_id": "user-99", "agent_id": "my-agent"},
        )

        ctx = capturing.last_context
        assert ctx is not None
        assert ctx.is_subagent is False, "Portal surface must always set is_subagent=False"
        assert ctx.tenant_id == "tenant-x", "tenant_id must come from Actor, not caller body"
        assert ctx.agent_id == "my-agent", "agent_id must come from query param"
        assert ctx.actor_id == "ops@bank.example"

    def test_forget_context_has_is_subagent_false_and_correct_identity(self) -> None:
        actor = _make_memory_actor(
            subject="ops@bank.example",
            tenant_id="tenant-y",
        )
        capturing = _CapturingFactory(_FakeMemoryAPI())
        app = _build_app(actor=actor, factory=capturing)
        client = TestClient(app)
        record_id = str(uuid.uuid4())

        client.post(
            f"/api/v1/memory/records/{record_id}/forget",
            json={
                "reason": "user_request",
                "agent_id": "forget-agent",
                "subject_kind": "human",
                "subject_id": "user-50",
            },
        )

        ctx = capturing.last_context
        assert ctx is not None
        assert ctx.is_subagent is False
        assert ctx.tenant_id == "tenant-y"
        assert ctx.agent_id == "forget-agent"

    def test_memory_router_mounted_flag_is_true_when_factory_wired(self) -> None:
        actor = _make_memory_actor()
        factory = _CapturingFactory(_FakeMemoryAPI())
        app = _build_app(actor=actor, factory=factory)
        assert getattr(app.state, "memory_router_mounted", False) is True

    def test_memory_router_not_mounted_when_factory_is_none(self) -> None:
        app = create_app()
        assert getattr(app.state, "memory_router_mounted", False) is False


# ---------------------------------------------------------------------------
# 7. Required-selector validation (P1 — subject_id + agent_id non-empty)
# ---------------------------------------------------------------------------


class TestSelectorValidation:
    """``subject_id`` + ``agent_id`` are REQUIRED non-empty selectors on every
    endpoint. A missing or empty selector is a 422 wire refusal that NEVER
    invokes the MemoryAPI factory — an empty subject means "tenant-wide/unscoped
    memory" (refused by SubjectRef) and an empty agent_id would call the adapter
    under an empty agent namespace. Both must fail at the wire, not as a 500 from
    a downstream ValueError. Each test asserts the capturing factory's
    ``last_context`` is None — the handler body never ran."""

    _RECORD_ID = str(uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc"))

    def _client(self, *, factory: MemoryApiFactory) -> TestClient:
        actor = _make_memory_actor(actor_type="human")
        return TestClient(_build_app(actor=actor, factory=factory))

    # -- GET /records --
    def test_get_missing_subject_id_returns_422_no_factory(self) -> None:
        factory = _CapturingFactory(_FakeMemoryAPI())
        resp = self._client(factory=factory).get(
            "/api/v1/memory/records", params={"subject_kind": "human", "agent_id": "agent-1"}
        )
        assert resp.status_code == 422
        assert factory.last_context is None

    def test_get_missing_agent_id_returns_422_no_factory(self) -> None:
        factory = _CapturingFactory(_FakeMemoryAPI())
        resp = self._client(factory=factory).get(
            "/api/v1/memory/records", params={"subject_kind": "human", "subject_id": "user-1"}
        )
        assert resp.status_code == 422
        assert factory.last_context is None

    def test_get_empty_subject_id_returns_422_no_factory(self) -> None:
        factory = _CapturingFactory(_FakeMemoryAPI())
        resp = self._client(factory=factory).get(
            "/api/v1/memory/records",
            params={"subject_kind": "human", "subject_id": "", "agent_id": "agent-1"},
        )
        assert resp.status_code == 422
        assert factory.last_context is None

    def test_get_empty_agent_id_returns_422_no_factory(self) -> None:
        factory = _CapturingFactory(_FakeMemoryAPI())
        resp = self._client(factory=factory).get(
            "/api/v1/memory/records",
            params={"subject_kind": "human", "subject_id": "user-1", "agent_id": ""},
        )
        assert resp.status_code == 422
        assert factory.last_context is None

    # -- POST /records/{id}/forget --
    def test_forget_empty_subject_id_returns_422_no_factory(self) -> None:
        factory = _CapturingFactory(_FakeMemoryAPI())
        resp = self._client(factory=factory).post(
            f"/api/v1/memory/records/{self._RECORD_ID}/forget",
            json={
                "reason": "user_request",
                "agent_id": "agent-1",
                "subject_kind": "human",
                "subject_id": "",
            },
        )
        assert resp.status_code == 422
        assert factory.last_context is None

    def test_forget_empty_agent_id_returns_422_no_factory(self) -> None:
        factory = _CapturingFactory(_FakeMemoryAPI())
        resp = self._client(factory=factory).post(
            f"/api/v1/memory/records/{self._RECORD_ID}/forget",
            json={
                "reason": "user_request",
                "agent_id": "",
                "subject_kind": "human",
                "subject_id": "user-1",
            },
        )
        assert resp.status_code == 422
        assert factory.last_context is None

    # -- POST /records/{id}/redact --
    def test_redact_empty_subject_id_returns_422_no_factory(self) -> None:
        factory = _CapturingFactory(_FakeMemoryAPI())
        resp = self._client(factory=factory).post(
            f"/api/v1/memory/records/{self._RECORD_ID}/redact",
            json={
                "span_path": ["field"],
                "reason": "pii_minimization",
                "agent_id": "agent-1",
                "subject_kind": "human",
                "subject_id": "",
            },
        )
        assert resp.status_code == 422
        assert factory.last_context is None

    def test_redact_empty_agent_id_returns_422_no_factory(self) -> None:
        factory = _CapturingFactory(_FakeMemoryAPI())
        resp = self._client(factory=factory).post(
            f"/api/v1/memory/records/{self._RECORD_ID}/redact",
            json={
                "span_path": ["field"],
                "reason": "pii_minimization",
                "agent_id": "",
                "subject_kind": "human",
                "subject_id": "user-1",
            },
        )
        assert resp.status_code == 422
        assert factory.last_context is None

    # -- POST /export --
    def test_export_empty_subject_id_returns_422_no_factory(self) -> None:
        factory = _CapturingFactory(_FakeMemoryAPI())
        resp = self._client(factory=factory).post(
            "/api/v1/memory/export",
            json={"agent_id": "agent-1", "subject_kind": "human", "subject_id": ""},
        )
        assert resp.status_code == 422
        assert factory.last_context is None

    def test_export_empty_agent_id_returns_422_no_factory(self) -> None:
        factory = _CapturingFactory(_FakeMemoryAPI())
        resp = self._client(factory=factory).post(
            "/api/v1/memory/export",
            json={"agent_id": "", "subject_kind": "human", "subject_id": "user-1"},
        )
        assert resp.status_code == 422
        assert factory.last_context is None
