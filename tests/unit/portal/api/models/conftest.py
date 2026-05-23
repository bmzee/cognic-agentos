"""Sprint 9.5 B4 — fixtures for model-registry route tests.

Per AGENTS.md test-fixture-placement rule, conftest fixtures live
under the test tree, not the production tree. The fixtures here mount
``build_model_lifecycle_routes`` on a bare FastAPI app (NOT
``create_app``) so the B4 tests run independently of B5's app-mount
wiring; B5 will exercise the full ``create_app`` path.

Standing-offer §30 invariant: ``from __future__ import annotations`` is
safe here because no route is defined inline with closure-local
:func:`Depends` references — the conftest only includes the
pre-built router from ``build_model_lifecycle_routes`` and the test
functions invoke routes via httpx, never declaring FastAPI routes
themselves.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import _chain_heads, _metadata
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings
from cognic_agentos.llm.ledger import GatewayCallLedger, _ledger_table
from cognic_agentos.models.storage import ModelRecordStore
from cognic_agentos.models.trust import ModelTrustGate
from cognic_agentos.portal.api.models import build_models_router
from cognic_agentos.portal.rbac.actor import Actor

# Sprint 9.5b C3 — sentinel for the ``gateway_ledger`` kwarg.
# ``make_app(gateway_ledger=_LEDGER_DEFAULT)`` (the implicit default)
# mints a real ``GatewayCallLedger(engine)`` backed by the test
# engine, so the 4 pre-existing test files that call ``make_app(...)``
# without the kwarg stay backward-compat. Explicit
# ``gateway_ledger=None`` overrides to the D7 503-path scenario; an
# explicit instance overrides to a custom-wired ledger.
_LEDGER_DEFAULT: Any = object()


class _StubBinder:
    """Returns a fixed :class:`Actor` per the SYNC ``ActorBinder.bind``
    Protocol contract."""

    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Any) -> Actor:
        return self._actor


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'b4.db'}")
    async with eng.begin() as conn:
        await conn.run_sync(_metadata.create_all)
        # Sprint 9.5b C3 — also create the gateway_call_ledger table
        # so ``make_app``'s default ``GatewayCallLedger(engine)`` has
        # somewhere to write. ``_ledger_table`` lives on a SEPARATE
        # ``MetaData()`` instance from ``_metadata`` (per
        # ``llm/ledger.py:133``) so both creates are needed.
        await conn.run_sync(_ledger_table.metadata.create_all)
        for chain_id in ("audit_event", "decision_history"):
            await conn.execute(
                _chain_heads.insert().values(
                    chain_id=chain_id,
                    latest_sequence=0,
                    latest_hash=ZERO_HASH,
                    updated_at=datetime.now(UTC),
                )
            )
    yield eng
    await eng.dispose()


@pytest.fixture
async def store(engine: AsyncEngine) -> ModelRecordStore:
    return ModelRecordStore(engine)


@pytest.fixture
def artefact_tree(tmp_path: Path) -> Path:
    """A per-tenant artefact tree with a per-tenant trust-root, a
    sigstore bundle, and a signed artefact. The tenant subtree
    matches the default ``tenant-acme`` actor used by most tests; the
    path-containment-failure tests build additional structures under
    the same root.
    """
    root = tmp_path / "artifacts"
    tenant_dir = root / "tenant-acme"
    tenant_dir.mkdir(parents=True)
    (tenant_dir / "trust-root.pub").write_text("PUBKEY\n")
    (tenant_dir / "bundle.sigstore").write_text("BUNDLE\n")
    (tenant_dir / "artefact.bin").write_text("ARTEFACT\n")
    return root


@pytest.fixture
def make_cosign(tmp_path: Path) -> Callable[[bool], Path]:
    """Build a stub cosign binary that exits 0 (clean verify) or 1
    (clean negative verdict). Two-file caching so a single test can
    flip between verdicts mid-run."""
    ok = tmp_path / "cosign-ok"
    ok.write_text("#!/bin/sh\nexit 0\n")
    ok.chmod(0o755)
    fail = tmp_path / "cosign-fail"
    fail.write_text("#!/bin/sh\nexit 1\n")
    fail.chmod(0o755)

    def _pick(exit_zero: bool) -> Path:
        return ok if exit_zero else fail

    return _pick


@pytest.fixture
def make_app(
    store: ModelRecordStore,
    engine: AsyncEngine,
    artefact_tree: Path,
    make_cosign: Callable[[bool], Path],
) -> Callable[..., FastAPI]:
    """Build a bare FastAPI app with the model lifecycle router
    direct-mounted under ``/api/v1/models`` (NOT ``create_app`` — that
    integration lands in B5). The factory accepts overrides for actor
    identity / tenant / scopes / actor_type, the cosign verdict, and
    the C3 ``gateway_ledger`` (default: real instance backed by the
    test engine; explicit ``None`` for the D7 503-path tests).
    """

    def _build(
        *,
        subject: str = "test-user",
        tenant_id: str = "tenant-acme",
        scopes: frozenset[str] = frozenset(),
        actor_type: str = "human",
        cosign_exit_zero: bool = True,
        cosign_missing: bool = False,
        gateway_ledger: Any = _LEDGER_DEFAULT,
    ) -> FastAPI:
        # Z1 coverage-floor extension: cosign_missing=True points
        # settings.cosign_path at a non-existent binary so
        # ModelTrustGate.__init__'s ``which(configured)`` returns None,
        # exercising the ``ModelSignatureVerificationError`` early-
        # return branch of ``_verify_record_signature`` (lifecycle_routes
        # lines 309-310).
        cosign_path = (
            "/no/such/cosign-binary-z1-floor-test"
            if cosign_missing
            else str(make_cosign(cosign_exit_zero))
        )
        settings = Settings(
            model_artifact_root=str(artefact_tree),
            cosign_path=cosign_path,
        )
        trust_gate = ModelTrustGate(settings)
        actor = Actor(
            subject=subject,
            tenant_id=tenant_id,
            scopes=scopes,  # type: ignore[arg-type]
            actor_type=actor_type,  # type: ignore[arg-type]
        )
        # Sprint 9.5b C3 — sentinel-pattern resolution of the
        # ``gateway_ledger`` kwarg. The implicit default mints a real
        # ledger backed by the test engine so the 4 pre-existing test
        # files (test_dto.py, test_inspection_routes.py,
        # test_lifecycle_routes.py, the integration test) stay
        # backward-compat without any signature surgery; explicit
        # ``None`` overrides to the D7 503-path scenario; an explicit
        # instance overrides to a custom-wired ledger.
        ledger: GatewayCallLedger | None = (
            GatewayCallLedger(engine) if gateway_ledger is _LEDGER_DEFAULT else gateway_ledger
        )
        app = FastAPI()
        app.state.model_registry_store = store
        app.state.actor_binder = _StubBinder(actor)
        # B5: mount the COMPOSED router (lifecycle + inspection) via
        # build_models_router. The router carries the MODEL_ROUTER_PREFIX
        # internally — no extra prefix on include_router. C3 threads
        # the optional ``ledger`` kwarg through; ``None`` (the D7
        # opt-in) yields the 503 ``gateway_ledger_not_configured``
        # surface on /usage while keeping the other 5 model endpoints
        # mounted and functional.
        app.include_router(
            build_models_router(
                store=store,
                trust_gate=trust_gate,
                settings=settings,
                ledger=ledger,
            )
        )
        return app

    return _build


@pytest.fixture
async def client_register(make_app: Callable[..., FastAPI]) -> AsyncIterator[AsyncClient]:
    """Pre-built async client with ``model.register`` scope held —
    used by every test that needs to seed a registered model first."""
    app = make_app(scopes=frozenset({"model.register"}))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
