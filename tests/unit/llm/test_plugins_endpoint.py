"""Sprint 4 T11 — ``GET /api/v1/system/plugins`` contract.

Pins the read-only operator-facing plugin-registration surface per the
user's T11 guardrails:

  > Read-only endpoint, no registration side effects, no pack loading,
  > response shape mirrors RegistrationOutcome fields, and include
  > enough metadata for operators to see pack_id, entry-point name,
  > kind, version, status, attestation_grade, signature_digest,
  > refusal_reason, and registered_at.

Tests cover:

  * ``TestEmptyRegistry`` — endpoint serves 200 with empty list when
    no plugin_registry is attached (Sprint-1A/1B test mode).
  * ``TestPopulatedRegistry`` — registered + refused outcomes render
    with the documented response shape; summary counts are correct.
  * ``TestNoSideEffects`` — a GET on the endpoint never invokes
    EntryPoint.load() and never mutates registry state. The
    deferred-load invariant is preserved at the operator boundary.
  * ``TestResponseShapeStability`` — every documented field is
    present on every plugin entry; pack_id and name are reported
    separately so a single distribution exposing several entry
    points renders correctly.
"""

from __future__ import annotations

import datetime as _dt
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, ClassVar

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.protocol.plugin_registry import (
    DiscoveredPack,
    PluginRecord,
    PluginRegistry,
)
from tests.support.settings_fixtures import prod_settings

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 't11.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_audit_event.metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=_dt.datetime.now(_dt.UTC),
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
def audit_store(engine: AsyncEngine) -> AuditStore:
    return AuditStore(engine)


@pytest.fixture
def registry(audit_store: AuditStore) -> PluginRegistry:
    return PluginRegistry(audit_store=audit_store)


# ---------------------------------------------------------------------------
# Fake-EntryPoint helpers (mirrors the T10 test pattern)
# ---------------------------------------------------------------------------


class _FakeEntryPoint:
    def __init__(
        self,
        *,
        name: str,
        value: str,
        dist: Any,
        load_returns: Any = None,
    ) -> None:
        self.name = name
        self.value = value
        self.dist = dist
        self._load_returns = load_returns
        self.load_count = 0

    def load(self) -> Any:
        self.load_count += 1
        return self._load_returns


class _FakeDistribution:
    def __init__(self, *, name: str, version: str) -> None:
        self._name = name
        self.version = version

    @property
    def metadata(self) -> dict[str, str]:
        return {"Name": self._name}


def _make_pack(
    *,
    name: str,
    distribution_name: str,
    version: str = "1.0.0",
) -> tuple[DiscoveredPack, _FakeEntryPoint]:
    record = PluginRecord(
        kind="tools",
        name=name,
        distribution_name=distribution_name,
        distribution_version=version,
        entry_point_value=f"{distribution_name.replace('-', '_')}:Plugin",
    )
    ep = _FakeEntryPoint(
        name=name,
        value=record.entry_point_value,
        dist=_FakeDistribution(name=distribution_name, version=version),
    )
    return DiscoveredPack(record=record, entry_point=ep), ep  # type: ignore[arg-type]


def _make_client(plugin_registry: PluginRegistry | None = None) -> TestClient:
    """Build a TestClient bound to a fresh app with the given
    plugin_registry. Tests then call ``client.__enter__()`` (or use
    ``with TestClient(app) as client:``) to run the ASGI lifespan
    startup and populate ``app.state.plugin_registry``. Direct
    ``TestClient(app)`` construction does NOT run the lifespan; only
    the context-manager protocol does.
    """
    settings = prod_settings()
    app = create_app(settings, plugin_registry=plugin_registry)
    return TestClient(app)


# ---------------------------------------------------------------------------
# TestEmptyRegistry — 200 with empty list (NOT 503).
# ---------------------------------------------------------------------------


class TestEmptyRegistry:
    def test_no_plugin_registry_attached_returns_empty_list(self) -> None:
        """When no plugin_registry is attached (Sprint-1A/1B test
        mode), the endpoint serves 200 with an empty list + zero
        counts. Per ADR-007's two-layers convention, the operator-
        facing surface stays honest about empty state — never 503s."""
        client = _make_client(plugin_registry=None)
        client.__enter__()
        resp = client.get("/api/v1/system/plugins")
        assert resp.status_code == 200
        body = resp.json()
        assert body["plugins"] == []
        assert body["summary"] == {
            "total_discovered": 0,
            "registered": 0,
            "refused_at_registration": 0,
            "by_grade": {"full": 0, "partial": 0},
        }

    def test_empty_plugin_registry_returns_empty_list(self, registry: PluginRegistry) -> None:
        """A populated app.state.plugin_registry that hasn't been
        registered against yet still returns 200 + empty list."""
        client = _make_client(plugin_registry=registry)
        client.__enter__()
        resp = client.get("/api/v1/system/plugins")
        assert resp.status_code == 200
        assert resp.json()["plugins"] == []


# ---------------------------------------------------------------------------
# TestPopulatedRegistry — registered + refused render correctly.
# ---------------------------------------------------------------------------


class TestPopulatedRegistry:
    async def test_registered_pack_renders_full_response_shape(
        self, registry: PluginRegistry
    ) -> None:
        pack, _ = _make_pack(name="search", distribution_name="cognic-tool-search")
        await registry.register(
            pack,
            attestation_grade="full",
            signature_digest="sha256:" + "a" * 64,
        )
        client = _make_client(plugin_registry=registry)
        client.__enter__()
        resp = client.get("/api/v1/system/plugins")
        assert resp.status_code == 200
        body = resp.json()
        assert len(body["plugins"]) == 1
        plugin = body["plugins"][0]
        assert plugin["kind"] == "tools"
        assert plugin["name"] == "search"
        assert plugin["pack_id"] == "cognic-tool-search"
        assert plugin["version"] == "1.0.0"
        assert plugin["status"] == "registered"
        assert plugin["attestation_grade"] == "full"
        assert plugin["signature_digest"] == "sha256:" + "a" * 64
        assert plugin["refusal_reason"] is None
        assert plugin["registered_at"] is not None
        # Summary counts.
        assert body["summary"] == {
            "total_discovered": 1,
            "registered": 1,
            "refused_at_registration": 0,
            "by_grade": {"full": 1, "partial": 0},
        }

    async def test_refused_pack_renders_with_nulls(self, registry: PluginRegistry) -> None:
        pack, _ = _make_pack(name="kyc", distribution_name="cognic-tool-kyc")
        await registry.register(pack, refusal_reason="cosign_verification_failed")
        client = _make_client(plugin_registry=registry)
        client.__enter__()
        body = client.get("/api/v1/system/plugins").json()
        plugin = body["plugins"][0]
        assert plugin["status"] == "refused_at_registration"
        assert plugin["attestation_grade"] is None
        assert plugin["registered_at"] is None
        assert plugin["refusal_reason"] == "cosign_verification_failed"
        # signature_digest may be None on refusal paths where the
        # cosign step never produced one. Default register() doesn't
        # supply one for refusals.
        assert plugin["signature_digest"] is None

    async def test_mixed_outcomes_summary_counts(self, registry: PluginRegistry) -> None:
        """Registered (full) + registered (partial) + refused → counts
        match the plan-of-record example."""
        pack_full, _ = _make_pack(name="alpha", distribution_name="cognic-tool-alpha")
        await registry.register(
            pack_full,
            attestation_grade="full",
            signature_digest="sha256:" + "a" * 64,
        )
        pack_partial, _ = _make_pack(name="bravo", distribution_name="cognic-tool-bravo")
        await registry.register(
            pack_partial,
            attestation_grade="partial",
            signature_digest="sha256:" + "b" * 64,
        )
        pack_refused, _ = _make_pack(name="charlie", distribution_name="cognic-tool-charlie")
        await registry.register(pack_refused, refusal_reason="sbom_missing")
        client = _make_client(plugin_registry=registry)
        client.__enter__()
        body = client.get("/api/v1/system/plugins").json()
        assert len(body["plugins"]) == 3
        assert body["summary"] == {
            "total_discovered": 3,
            "registered": 2,
            "refused_at_registration": 1,
            "by_grade": {"full": 1, "partial": 1},
        }

    async def test_status_uses_operator_vocabulary(self, registry: PluginRegistry) -> None:
        """Per the plan: status MUST use ``registered`` /
        ``refused_at_registration`` (operator vocabulary), NOT
        internal lifecycle states (``submitted`` / ``approved`` /
        etc.). The full ADR-012 lifecycle is Sprint 7B."""
        pack, _ = _make_pack(name="x", distribution_name="cognic-tool-x")
        await registry.register(pack, refusal_reason="not_in_tenant_allowlist")
        client = _make_client(plugin_registry=registry)
        client.__enter__()
        body = client.get("/api/v1/system/plugins").json()
        assert body["plugins"][0]["status"] == "refused_at_registration"
        # Internal-vocabulary leakage check.
        for forbidden in ("submitted", "approved", "installed", "revoked"):
            assert all(p["status"] != forbidden for p in body["plugins"]), (
                f"internal lifecycle state {forbidden} leaked into the operator surface"
            )

    async def test_insertion_order_preserved_across_repeat_reads(
        self, registry: PluginRegistry
    ) -> None:
        """The plan requires deterministic ordering across repeat
        reads — Python ``dict`` insertion order guarantees this on
        the registry side. The endpoint must not re-sort."""
        for letter in ("a", "b", "c", "d"):
            pack, _ = _make_pack(
                name=f"pack_{letter}",
                distribution_name=f"cognic-tool-{letter}",
            )
            await registry.register(
                pack,
                attestation_grade="full",
                signature_digest="sha256:" + letter * 64,
            )
        client = _make_client(plugin_registry=registry)
        client.__enter__()
        first = client.get("/api/v1/system/plugins").json()
        second = client.get("/api/v1/system/plugins").json()
        assert first == second
        names = [p["name"] for p in first["plugins"]]
        assert names == ["pack_a", "pack_b", "pack_c", "pack_d"]


# ---------------------------------------------------------------------------
# TestNoSideEffects — read-only contract.
# ---------------------------------------------------------------------------


class TestNoSideEffects:
    async def test_get_does_not_invoke_entry_point_load(self, registry: PluginRegistry) -> None:
        """Per the user's T11 guardrail: NO pack loading. Even though
        each registered outcome carries a captured EntryPoint
        reference, the endpoint MUST NOT call ``load()``. This is the
        operator-portal counterpart to the §1 deferred-load
        invariant — admission code never imports packs, and the
        observability surface doesn't either."""
        pack, ep = _make_pack(name="no-load-1", distribution_name="cognic-tool-1")
        await registry.register(
            pack,
            attestation_grade="full",
            signature_digest="sha256:" + "a" * 64,
        )
        client = _make_client(plugin_registry=registry)
        client.__enter__()
        # Three reads to be safe — even a single eager load would
        # accumulate.
        client.get("/api/v1/system/plugins")
        client.get("/api/v1/system/plugins")
        client.get("/api/v1/system/plugins")
        assert ep.load_count == 0, (
            "GET /api/v1/system/plugins invoked EntryPoint.load() — "
            "violates the read-only T11 contract"
        )

    async def test_get_does_not_mutate_registry_state(self, registry: PluginRegistry) -> None:
        """A GET MUST not register / refuse / change any
        outcomes. ``known_packs()`` before and after must be
        identical."""
        pack, _ = _make_pack(name="immutable", distribution_name="cognic-tool-immutable")
        await registry.register(
            pack,
            attestation_grade="full",
            signature_digest="sha256:" + "a" * 64,
        )
        before = list(registry.known_packs())
        client = _make_client(plugin_registry=registry)
        client.__enter__()
        for _ in range(5):
            client.get("/api/v1/system/plugins")
        after = list(registry.known_packs())
        assert before == after


# ---------------------------------------------------------------------------
# TestResponseShapeStability — every documented field present.
# ---------------------------------------------------------------------------


class TestResponseShapeStability:
    REQUIRED_PLUGIN_FIELDS: ClassVar[set[str]] = {
        "kind",
        "name",
        "pack_id",
        "version",
        "status",
        "attestation_grade",
        "signature_digest",
        "refusal_reason",
        "registered_at",
    }

    REQUIRED_SUMMARY_FIELDS: ClassVar[set[str]] = {
        "total_discovered",
        "registered",
        "refused_at_registration",
        "by_grade",
    }

    async def test_every_plugin_entry_has_all_required_fields(
        self, registry: PluginRegistry
    ) -> None:
        # Mix of registered + refused so both shapes are exercised.
        pack_ok, _ = _make_pack(name="ok", distribution_name="cognic-tool-ok")
        await registry.register(
            pack_ok,
            attestation_grade="full",
            signature_digest="sha256:" + "a" * 64,
        )
        pack_refused, _ = _make_pack(name="bad", distribution_name="cognic-tool-bad")
        await registry.register(pack_refused, refusal_reason="sbom_tampered")
        client = _make_client(plugin_registry=registry)
        client.__enter__()
        body = client.get("/api/v1/system/plugins").json()
        for plugin in body["plugins"]:
            assert set(plugin.keys()) == self.REQUIRED_PLUGIN_FIELDS, (
                f"plugin entry shape drifted: got {set(plugin.keys())!r}, "
                f"expected {self.REQUIRED_PLUGIN_FIELDS!r}"
            )

    async def test_summary_has_all_required_fields(self, registry: PluginRegistry) -> None:
        client = _make_client(plugin_registry=registry)
        client.__enter__()
        body = client.get("/api/v1/system/plugins").json()
        assert set(body["summary"].keys()) == self.REQUIRED_SUMMARY_FIELDS
        assert set(body["summary"]["by_grade"].keys()) == {"full", "partial"}

    async def test_pack_id_and_name_reported_separately(self, registry: PluginRegistry) -> None:
        """Critical: the entry-point alias and the signed-distribution
        identity are different fields. T10's allow-list + T9's
        bundle key both use the distribution identity; the endpoint
        surfaces both so operators can correlate them."""
        # Three packs with distinct (name, distribution) pairs to
        # demonstrate the field independence.
        for name, dist in [
            ("demo-pack", "cognic-tool-demo"),
            ("search", "cognic-tool-search-engine"),
            ("kyc-lookup", "cognic-tool-kyc"),
        ]:
            pack, _ = _make_pack(name=name, distribution_name=dist)
            await registry.register(
                pack,
                attestation_grade="full",
                signature_digest="sha256:" + "a" * 64,
            )
        client = _make_client(plugin_registry=registry)
        client.__enter__()
        plugins = client.get("/api/v1/system/plugins").json()["plugins"]
        for plugin in plugins:
            assert plugin["name"] != plugin["pack_id"], (
                f"pack {plugin['name']!r}: name and pack_id collapsed to "
                f"the same value — T9 bundle key + T10 allow-list both key "
                f"on pack_id, so the distinction must surface here"
            )

    async def test_registered_at_is_iso8601(self, registry: PluginRegistry) -> None:
        """``registered_at`` is serialised as an ISO-8601 string
        (matching T5's audit payload shape) for any registered pack;
        ``None`` for refusals."""
        pack, _ = _make_pack(name="iso", distribution_name="cognic-tool-iso")
        await registry.register(
            pack,
            attestation_grade="full",
            signature_digest="sha256:" + "a" * 64,
        )
        client = _make_client(plugin_registry=registry)
        client.__enter__()
        plugin = client.get("/api/v1/system/plugins").json()["plugins"][0]
        # Round-trip via fromisoformat to confirm it's a valid
        # ISO-8601 representation.
        parsed = _dt.datetime.fromisoformat(plugin["registered_at"])
        assert parsed.tzinfo is not None
