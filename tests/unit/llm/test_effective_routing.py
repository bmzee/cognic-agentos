"""Sprint 3 T9 — ``GET /api/v1/system/effective-routing`` contract.

Pins the provider-honesty outcome surface per ADR-007. The endpoint
reads the ``gateway_call_ledger`` as authoritative; settings as
intent; Langfuse as opportunistic enrichment with a fallback flag.

Tests cover:
- Ledger-authoritative aggregation (counts by upstream_model).
- ``recent_calls_window_minutes`` reflects settings.
- Per-row detail surfaces ``upstream_api_base`` + ``provenance`` from
  the persisted row (Round-6 reviewer-P1: NOT re-resolved at
  request-time from current YAML).
- Langfuse-down → ``langfuse_available: false`` + endpoint still 200.
- PROFILE chip drift: external row + ``allow_external_llm=False`` →
  ``self-hosted (DRIFT)``.
- Round-7 reviewer-P1 regression: drift detection includes rows with
  ``provenance="unresolved"`` (post-dispatch, even though the model
  field was missing/unknown).
- ``no_dispatch`` rows excluded from drift count (pre-dispatch best-
  effort rows reflect intended preflight identity, not actual
  upstream contact).
- No ledger attached → 200 with empty aggregates (per ADR-007 the
  honesty surface NEVER fails closed on missing data).
"""

from __future__ import annotations

import datetime as _dt
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.config import Settings
from cognic_agentos.db.adapters import Adapters
from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.llm.ledger import GatewayCallLedger, GatewayCallRow, _ledger_table
from cognic_agentos.portal.api.app import create_app
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)


@pytest.fixture
async def ledger_engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 'effective_routing.db'}"
    engine = create_async_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(_ledger_table.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
async def empty_ledger(ledger_engine: AsyncEngine) -> GatewayCallLedger:
    return GatewayCallLedger(ledger_engine)


def _row(
    *,
    upstream_model: str,
    external: bool,
    provenance: str = "resolved",
    outcome: str = "ok",
    upstream_api_base: str | None = None,
    age_minutes: int = 1,
    request_id: str | None = None,
    tier: str = "tier1",
    litellm_alias: str = "cognic-tier1-dev",
) -> GatewayCallRow:
    return GatewayCallRow(
        id=uuid.uuid4(),
        ts=_dt.datetime.now(_dt.UTC) - _dt.timedelta(minutes=age_minutes),
        request_id=request_id or f"req-{uuid.uuid4().hex[:8]}",
        tenant_id=None,
        tier=tier,  # type: ignore[arg-type]
        litellm_alias=litellm_alias,
        upstream_model=upstream_model,
        upstream_api_base=upstream_api_base,
        external=external,
        provenance=provenance,
        latency_ms=42,
        outcome=outcome,
        model_id=None,
    )


def _client(settings: Settings, ledger: GatewayCallLedger | None = None) -> TestClient:
    return TestClient(create_app(settings, gateway_ledger=ledger))


class TestEffectiveRoutingHappy:
    async def test_aggregates_counts_by_upstream_model(
        self, empty_ledger: GatewayCallLedger
    ) -> None:
        """Ledger has 2x ollama + 1x openai in window -> counts surface."""
        await empty_ledger.write_row(_row(upstream_model="ollama/qwen3:8b", external=False))
        await empty_ledger.write_row(_row(upstream_model="ollama/qwen3:8b", external=False))
        await empty_ledger.write_row(_row(upstream_model="openai/gpt-5.4", external=True))
        client = _client(
            Settings(
                runtime_profile="prod",
                allow_external_llm=True,
                policy_mode="cloud_mixed",
                allowed_providers=["openai"],
            ),
            ledger=empty_ledger,
        )
        with client:
            body = client.get("/api/v1/system/effective-routing").json()
        assert body["recent_calls_window_minutes"] == 60
        assert body["recent_calls"]["ollama/qwen3:8b"] == 2
        assert body["recent_calls"]["openai/gpt-5.4"] == 1
        assert body["profile"]["post_dispatch_count"] == 3
        assert body["profile"]["drift_count"] == 0  # cloud intent + flag on
        assert body["profile"]["chip"] == "cloud"

    async def test_window_minutes_reflects_settings(self, empty_ledger: GatewayCallLedger) -> None:
        client = _client(
            Settings(
                runtime_profile="prod",
                provider_honesty_ledger_window_minutes=120,
            ),
            ledger=empty_ledger,
        )
        with client:
            body = client.get("/api/v1/system/effective-routing").json()
        assert body["recent_calls_window_minutes"] == 120

    async def test_recent_call_details_use_persisted_api_base_and_provenance(
        self, empty_ledger: GatewayCallLedger
    ) -> None:
        """Round-6 reviewer-P1: per-row detail comes from the
        persisted ledger row, NOT re-resolved against current YAML."""
        await empty_ledger.write_row(
            _row(
                upstream_model="openai/gpt-4o",
                external=True,
                provenance="ambiguous",
                upstream_api_base=None,  # ambiguous → api_base nulled at write
                request_id="req-ambig",
            )
        )
        client = _client(
            Settings(runtime_profile="prod", allow_external_llm=True),
            ledger=empty_ledger,
        )
        with client:
            body = client.get("/api/v1/system/effective-routing").json()
        details = body["recent_call_details"]
        assert len(details) == 1
        row = details[0]
        assert row["request_id"] == "req-ambig"
        assert row["upstream_model"] == "openai/gpt-4o"
        assert row["upstream_api_base"] is None
        assert row["provenance"] == "ambiguous"
        assert row["external"] is True


class TestProfileChipDrift:
    async def test_external_row_with_flag_off_flips_chip_to_drift(
        self, empty_ledger: GatewayCallLedger
    ) -> None:
        """ADR-007 PROFILE drift: operator declared self-hosted but
        the ledger has post-dispatch external rows → DRIFT chip."""
        await empty_ledger.write_row(
            _row(upstream_model="openai/gpt-5.4", external=True, provenance="resolved")
        )
        client = _client(Settings(runtime_profile="prod"), ledger=empty_ledger)
        with client:
            body = client.get("/api/v1/system/effective-routing").json()
        assert body["profile"]["intent"] == "self-hosted"
        assert body["profile"]["drift_count"] == 1
        assert body["profile"]["chip"] == "self-hosted (DRIFT)"

    async def test_unresolved_external_row_counts_toward_drift(
        self, empty_ledger: GatewayCallLedger
    ) -> None:
        """Round-7 reviewer-P1 regression: ``provenance="unresolved"``
        is a POST-dispatch state (LiteLLM responded but the model
        field was missing or not declared in the YAML). It must
        count toward drift even though the resolver couldn't
        identify the alias."""
        await empty_ledger.write_row(
            _row(
                upstream_model="openai/gpt-7",  # not in any YAML
                external=True,
                provenance="unresolved",
                outcome="upstream_error",
            )
        )
        client = _client(Settings(runtime_profile="prod"), ledger=empty_ledger)
        with client:
            body = client.get("/api/v1/system/effective-routing").json()
        assert body["profile"]["drift_count"] == 1
        assert body["profile"]["chip"] == "self-hosted (DRIFT)"

    async def test_ambiguous_external_row_counts_toward_drift(
        self, empty_ledger: GatewayCallLedger
    ) -> None:
        """Round-7 reviewer-P1: ``ambiguous`` is also a post-dispatch
        state — must count toward drift."""
        await empty_ledger.write_row(
            _row(
                upstream_model="openai/gpt-4o",
                external=True,
                provenance="ambiguous",
                outcome="denied",
            )
        )
        client = _client(Settings(runtime_profile="prod"), ledger=empty_ledger)
        with client:
            body = client.get("/api/v1/system/effective-routing").json()
        assert body["profile"]["drift_count"] == 1
        assert body["profile"]["chip"] == "self-hosted (DRIFT)"

    async def test_no_dispatch_external_row_excluded_from_drift(
        self, empty_ledger: GatewayCallLedger
    ) -> None:
        """``no_dispatch`` rows reflect INTENDED preflight identity
        from a pre-dispatch denial / guardrail trip. The actual
        upstream was never contacted, so they must not count toward
        drift (ADR-007 Round-7 reviewer-P1)."""
        await empty_ledger.write_row(
            _row(
                upstream_model="openai/gpt-5.4",  # preflight intent only
                external=True,
                provenance="no_dispatch",
                outcome="denied",
            )
        )
        client = _client(Settings(runtime_profile="prod"), ledger=empty_ledger)
        with client:
            body = client.get("/api/v1/system/effective-routing").json()
        assert body["profile"]["drift_count"] == 0
        assert body["profile"]["chip"] == "self-hosted"
        assert body["profile"]["post_dispatch_count"] == 0

    async def test_self_hosted_only_no_drift(self, empty_ledger: GatewayCallLedger) -> None:
        """Self-hosted intent + ledger has only self-hosted rows →
        clean chip."""
        await empty_ledger.write_row(_row(upstream_model="ollama/qwen3:8b", external=False))
        client = _client(Settings(runtime_profile="prod"), ledger=empty_ledger)
        with client:
            body = client.get("/api/v1/system/effective-routing").json()
        assert body["profile"]["chip"] == "self-hosted"
        assert body["profile"]["drift_count"] == 0


class _StubObservabilityAdapter:
    """Test double for the observability protocol so the
    ``langfuse_available`` contract can be pinned end-to-end without
    a live Langfuse instance.

    Constructor accepts a ``health_response`` callable returning an
    ``AdapterHealth`` (use this for the healthy / unreachable cases)
    OR an exception class to raise (use this to pin the
    catch-all-doesn't-leak posture inside ``_probe_langfuse``).
    """

    driver = "stub-langfuse"

    def __init__(self, *, health_response: AdapterHealth | type[BaseException]) -> None:
        self._health_response = health_response
        self.health_check_calls = 0

    async def emit_trace(self, name: str, attributes: dict[str, Any]) -> None:
        return None

    async def emit_metric(self, name: str, value: float, attributes: dict[str, Any]) -> None:
        return None

    async def flush(self) -> None:
        return None

    async def health_check(self) -> AdapterHealth:
        self.health_check_calls += 1
        if isinstance(self._health_response, type) and issubclass(
            self._health_response, BaseException
        ):
            raise self._health_response("simulated langfuse probe failure")
        assert isinstance(self._health_response, AdapterHealth)
        return self._health_response


def _adapters_with_observability(observability: _StubObservabilityAdapter) -> Adapters:
    """Build an Adapters container with in-memory drivers for the
    four non-observability slots and the supplied stub for
    observability. The four others are filler so the dataclass type-
    checks; the route handler only consults ``observability`` for
    Langfuse availability."""
    return Adapters(
        relational=InMemoryRelationalAdapter(),
        vector=InMemoryVectorAdapter(),
        secret=InMemorySecretAdapter(),
        embedding=InMemoryEmbeddingAdapter(),
        observability=observability,
    )


class TestLangfuseAvailability:
    def test_no_adapters_reports_langfuse_unavailable(
        self,
    ) -> None:
        """No adapter_registry attached → no Langfuse probe possible →
        ``langfuse_available: false``. Endpoint still 200 per ADR-007
        (honesty NEVER fails closed on enrichment outage)."""
        client = _client(Settings(runtime_profile="prod"), ledger=None)
        with client:
            resp = client.get("/api/v1/system/effective-routing")
        assert resp.status_code == 200
        assert resp.json()["langfuse_available"] is False

    def test_healthy_observability_reports_langfuse_available_true(self) -> None:
        """Round-9 reviewer-P2: pin the positive arm of the contract.
        Observability adapter reports ``status="ok"`` →
        ``langfuse_available: true`` AND the probe was actually
        called (regression-proofs against a literal-False return)."""
        stub = _StubObservabilityAdapter(
            health_response=AdapterHealth(status="ok", driver="stub-langfuse", latency_ms=1.2)
        )
        app = create_app(Settings(runtime_profile="prod"))
        with TestClient(app) as client:
            # Lifespan ran with adapter_registry=None and set
            # adapters=None; inject the stub directly so we exercise
            # the probe path without booting the full registry.
            app.state.adapters = _adapters_with_observability(stub)
            resp = client.get("/api/v1/system/effective-routing")
        assert resp.status_code == 200
        assert resp.json()["langfuse_available"] is True
        assert stub.health_check_calls == 1, "health_check must actually be invoked"

    def test_unreachable_observability_reports_langfuse_available_false(self) -> None:
        """Negative arm: observability reports ``status="unreachable"``
        (Langfuse instance down) → ``langfuse_available: false`` and
        the endpoint still 200. Pins that any non-``ok`` status maps
        to false — operators get an honest enrichment-down signal."""
        stub = _StubObservabilityAdapter(
            health_response=AdapterHealth(
                status="unreachable",
                driver="stub-langfuse",
                detail="connection refused",
            )
        )
        app = create_app(Settings(runtime_profile="prod"))
        with TestClient(app) as client:
            app.state.adapters = _adapters_with_observability(stub)
            resp = client.get("/api/v1/system/effective-routing")
        assert resp.status_code == 200
        assert resp.json()["langfuse_available"] is False
        assert stub.health_check_calls == 1

    def test_observability_health_check_raises_reports_langfuse_available_false(
        self,
    ) -> None:
        """Round-9 reviewer-P2: pin that ``health_check`` exceptions
        do NOT leak into the response. ADR-007 §"two layers" — the
        honesty surface NEVER fails closed on enrichment outage. A
        regression that removed the ``except Exception`` arm or
        re-raised would leak a 500 here."""
        stub = _StubObservabilityAdapter(health_response=RuntimeError)
        app = create_app(Settings(runtime_profile="prod"))
        with TestClient(app) as client:
            app.state.adapters = _adapters_with_observability(stub)
            resp = client.get("/api/v1/system/effective-routing")
        assert resp.status_code == 200, "probe exception must not surface as 5xx"
        assert resp.json()["langfuse_available"] is False
        assert stub.health_check_calls == 1


class TestEmptyLedger:
    def test_no_ledger_attached_returns_empty_aggregates(self) -> None:
        """Per ADR-007 §"two layers" the honesty surface NEVER fails
        closed on missing ledger. Operators see an honest empty
        picture, not a 5xx."""
        client = _client(Settings(runtime_profile="prod"), ledger=None)
        with client:
            resp = client.get("/api/v1/system/effective-routing")
        assert resp.status_code == 200
        body = resp.json()
        assert body["recent_calls"] == {}
        assert body["recent_call_details"] == []
        assert body["profile"]["post_dispatch_count"] == 0
        assert body["profile"]["drift_count"] == 0
        assert body["profile"]["chip"] == "self-hosted"

    async def test_empty_ledger_returns_empty_aggregates(
        self, empty_ledger: GatewayCallLedger
    ) -> None:
        client = _client(Settings(runtime_profile="prod"), ledger=empty_ledger)
        with client:
            body = client.get("/api/v1/system/effective-routing").json()
        assert body["recent_calls"] == {}
        assert body["recent_call_details"] == []


class TestStableShape:
    def test_response_has_stable_top_level_keys(self) -> None:
        """Lock the public top-level key set so portal consumers see
        a stable contract."""
        client = _client(Settings(runtime_profile="prod"), ledger=None)
        with client:
            body = client.get("/api/v1/system/effective-routing").json()
        assert set(body.keys()) == {
            "recent_calls_window_minutes",
            "recent_calls",
            "recent_call_details",
            "profile",
            "langfuse_available",
        }
        assert set(body["profile"].keys()) == {
            "intent",
            "post_dispatch_count",
            "drift_count",
            "chip",
        }
