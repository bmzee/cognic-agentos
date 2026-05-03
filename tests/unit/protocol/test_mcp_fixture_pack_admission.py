"""Sprint-5 T12 — fixture HTTP MCP pack admission + MCPHost smoke test.

End-to-end check that exercises the Sprint-5 MCP wire-up against a
real on-disk fixture pack:

  1. The fixture at ``tests/fixtures/cognic_test_mcp_pack/`` admits
     through the full Sprint-4 admission pipeline
     (:meth:`PluginRegistry.register_with_full_attestation_check`)
     PLUS the Sprint-5 ``MCPAdmissionDeps`` (T6.1 manifest
     extraction → T6.2 capability validation → T6.3 auth probe)
     with cosign / OPA / Vault / authz mocked at the boundary.
  2. The validated MCP block resolves into an
     :class:`MCPServerEntry` shape the orchestrator can dispatch
     against.
  3. :meth:`MCPHost.list_tools` and :meth:`MCPHost.call_tool` walk
     the orchestrator end-to-end against the admitted fixture
     (with a mocked HTTP transport — the unit-test path mocks the
     SDK to avoid spinning up a real OAuth AS + MCP server; the
     ``@pytest.mark.cosign_real`` integration path that lands
     post-Sprint-5 will exercise a real server).
  4. The tamper-evident ``audit_event`` chain receives the expected
     ``audit.tool_invocation`` row, correlated to the admitted
     pack's identity.

The fixture's import-poisoned ``__init__.py`` is preserved
deliberately — admission MUST NOT load pack code (deferred-load
invariant per ADR-002 §"MCP STDIO threat model" gate 1 + Sprint-4
discover→register→load doctrine). The smoke test verifies this
holds end-to-end: if T6 admission ever regresses to importing the
package, the AssertionError fires and the test fails loudly.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import time
import tomllib
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import (
    DecisionHistoryStore,
    _decision_history,
)
from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
)
from cognic_agentos.protocol.mcp_authz import Token
from cognic_agentos.protocol.mcp_host import MCPServerEntry
from cognic_agentos.protocol.mcp_transports import MCPSession
from cognic_agentos.protocol.plugin_registry import (
    DiscoveredPack,
    MCPAdmissionDeps,
    PackAttestations,
    PluginRecord,
    PluginRegistry,
)
from cognic_agentos.protocol.supply_chain import SupplyChainPipeline
from cognic_agentos.protocol.trust_gate import CosignVerificationResult

# ---------------------------------------------------------------------------
# Fixture-state validation (mirrors Sprint-4 test_fixture_pack_admission)
# ---------------------------------------------------------------------------


_REPO_ROOT = Path(__file__).resolve().parents[3]
_FIXTURE_ROOT = _REPO_ROOT / "tests" / "fixtures" / "cognic_test_mcp_pack"
_ATTESTATIONS = _FIXTURE_ROOT / "attestations"
_MANIFEST_PATH = _FIXTURE_ROOT / "cognic_test_mcp_pack" / "cognic-pack-manifest.toml"

REQUIRED_ATTESTATION_FILES = (
    "sbom.cdx.json",
    "slsa-provenance.intoto.json",
    "intoto-layout.json",
    "vuln-scan.json",
    "license-audit.json",
    "cosign.sig",
    "bundle.sigstore",
)


class TestFixturePackBytesPresent:
    """Fixture-state guards: every required attestation file is on
    disk + the manifest is parseable. If a future commit deletes
    one of these accidentally, this test fails BEFORE the
    end-to-end admission test runs (clearer failure mode)."""

    def test_attestation_files_exist(self) -> None:
        for name in REQUIRED_ATTESTATION_FILES:
            assert (_ATTESTATIONS / name).is_file(), f"missing fixture attestation file: {name!r}"

    def test_pack_manifest_parses_with_mcp_block(self) -> None:
        manifest = tomllib.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
        mcp = manifest["tool"]["cognic"]["mcp"]
        assert mcp["transport"] == "http"
        assert mcp["auth"] == "oauth-prm"
        assert mcp["server_url"] == "https://server.example/mcp"
        assert mcp["scopes"] == ["mcp:tools"]
        # Sprint-4 identity block + Sprint-5 runtime block
        assert manifest["tool"]["cognic"]["identity"]["pack_id"] == "cognic-test-mcp-pack"
        assert manifest["tool"]["cognic"]["runtime"]["risk_tier"] == "read_only"


# ---------------------------------------------------------------------------
# Real-store + real-registry scaffolding (mirrors Sprint-4 pattern)
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    """In-memory SQLite engine with both audit_event + decision_history
    chain tables initialized — same shape Sprint-4's T12 fixture
    test uses for the audit chain."""
    url = f"sqlite+aiosqlite:///{tmp_path / 't12-mcp.db'}"
    eng: AsyncEngine = create_async_engine(url)
    async with eng.begin() as conn:
        await conn.run_sync(_audit_event.metadata.create_all)
        await conn.run_sync(_decision_history.metadata.create_all)
        now = _dt.datetime.now(_dt.UTC)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=now,
            )
        )
        # decision_history shares the same _chain_heads table as
        # audit_event (Sprint-2 substrate co-locates the chain heads).
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="decision_history",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=now,
            )
        )
    yield eng
    await eng.dispose()


@pytest.fixture
def audit_store(engine: AsyncEngine) -> AuditStore:
    return AuditStore(engine)


@pytest.fixture
def decision_history_store(engine: AsyncEngine) -> DecisionHistoryStore:
    return DecisionHistoryStore(engine)


@pytest.fixture
def registry(audit_store: AuditStore) -> PluginRegistry:
    return PluginRegistry(audit_store=audit_store)


@pytest.fixture
def object_store(tmp_path: Path) -> LocalObjectStoreAdapter:
    root = tmp_path / "object-store"
    root.mkdir()
    return LocalObjectStoreAdapter(root)


@pytest.fixture
def supply_chain() -> SupplyChainPipeline:
    settings = build_settings_without_env_file().model_copy(
        update={"local_object_store_root": Path("/tmp/cognic-agentos-fixture-mcp")}
    )
    return SupplyChainPipeline(settings=settings)


def _fixture_pack() -> DiscoveredPack:
    """Construct a DiscoveredPack matching what
    ``PluginRegistry.discover()`` would produce after a real
    ``uv pip install -e tests/fixtures/cognic_test_mcp_pack/``.
    EntryPoint stub raises if loaded — admission MUST NOT call
    .load() per the deferred-load invariant."""
    record = PluginRecord(
        kind="tools",
        name="cognic_test_mcp_pack",
        distribution_name="cognic-test-mcp-pack",
        distribution_version="0.1.0",
        entry_point_value="cognic_test_mcp_pack:Plugin",
    )
    ep_stub = MagicMock()
    ep_stub.name = record.name
    ep_stub.value = record.entry_point_value
    ep_stub.load = MagicMock(side_effect=AssertionError("T12 admission MUST NOT load fixture pack"))
    return DiscoveredPack(record=record, entry_point=ep_stub)


def _fixture_artefacts() -> PackAttestations:
    """Build PackAttestations from the on-disk fixture files."""
    sbom_path = _ATTESTATIONS / "sbom.cdx.json"
    sbom_digest = hashlib.sha256(sbom_path.read_bytes()).hexdigest()
    return PackAttestations(
        cosign_signature_path=_ATTESTATIONS / "cosign.sig",
        cosign_blob_path=_ATTESTATIONS / "bundle.sigstore",
        cosign_trust_root=_ATTESTATIONS / "cosign.sig",
        sbom_path=sbom_path,
        sbom_signed_digest=sbom_digest,
        sigstore_bundle_path=_ATTESTATIONS / "bundle.sigstore",
        slsa_provenance_path=_ATTESTATIONS / "slsa-provenance.intoto.json",
        intoto_layout_path=_ATTESTATIONS / "intoto-layout.json",
        vuln_scan_path=_ATTESTATIONS / "vuln-scan.json",
        license_audit_path=_ATTESTATIONS / "license-audit.json",
    )


def _mock_trust_gate() -> MagicMock:
    """T6 trust gate is exhaustively unit-tested (cosign subprocess
    / privacy / fail-closed). T12's smoke mocks it so the fixture's
    bytes don't need a real cosign run; the @pytest.mark.cosign_real
    path runs against real cosign."""
    mock = MagicMock()
    mock.verify_pack_signature = AsyncMock(
        return_value=CosignVerificationResult(
            verified=True,
            pack_id="cognic-test-mcp-pack",
            version="0.1.0",
            signature_digest="b" * 64,  # distinct from the Sprint-4 fixture's "a"*64
        )
    )
    return mock


def _make_authz_factory_for_probe() -> tuple[Any, MagicMock]:
    """T6.3 registration auth probe — successful path. The factory
    pattern keeps the probe's token cache isolated from the runtime
    client per ADR-002 §"MCP Authorization" step 8."""
    client = MagicMock()
    client.acquire_token = AsyncMock(
        return_value=Token(
            value="probe-token-bytes",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="cognic-mcp-bank_a",
        )
    )
    client._token_cache = {}
    client._inflight_acquires = {}
    return (lambda: client), client


def _make_admission_deps(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[MCPAdmissionDeps, MagicMock]:
    """Build MCPAdmissionDeps wired with mocked Vault + a successful
    authz probe. Monkeypatches ``extract_pack_manifest`` to read the
    real on-disk fixture manifest — no need to install the fixture
    pack in the test venv."""
    from cognic_agentos.protocol import mcp_manifest as _mm

    real_manifest = tomllib.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))

    def _extract(**_kw: Any) -> dict[str, Any]:
        return real_manifest

    monkeypatch.setattr(_mm, "extract_pack_manifest", _extract)

    authz_factory, authz_client = _make_authz_factory_for_probe()
    settings = build_settings_without_env_file()
    vault_client = MagicMock()
    # MCP STDIO command-allowlist Vault path: the fixture isn't
    # STDIO so this is unused, but T6 still resolves it with an
    # empty default for safety.
    vault_client.read = AsyncMock(return_value={"servers": []})

    deps = MCPAdmissionDeps(
        settings=settings,
        vault_client=vault_client,
        opa_engine=None,  # fixture manifest does NOT declare sampling
        make_authz_client_for_probe=authz_factory,
    )
    return deps, authz_client


# ---------------------------------------------------------------------------
# T12.1 — admission via the full Sprint-4 + Sprint-5 pipeline
# ---------------------------------------------------------------------------


class TestFixturePackAdmission:
    """End-to-end admission of the MCP fixture pack."""

    async def test_admits_at_full_grade(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The MCP fixture pack's complete attestation set + valid
        manifest + successful auth probe MUST clear the full
        admission pipeline at grade=full."""
        admission_deps, _authz_client = _make_admission_deps(monkeypatch)
        outcome = await registry.register_with_full_attestation_check(
            _fixture_pack(),
            _fixture_artefacts(),
            trust_gate=_mock_trust_gate(),
            supply_chain=supply_chain,
            object_store=object_store,
            license_allowlist=("MIT",),
            mcp_admission=admission_deps,
        )
        assert outcome.status == "registered", (
            f"expected registered; got {outcome.status} (refusal_reason={outcome.refusal_reason})"
        )
        assert outcome.attestation_grade == "full"
        assert outcome.refusal_reason is None
        assert outcome.pack_id == "cognic-test-mcp-pack"
        assert outcome.name == "cognic_test_mcp_pack"

    async def test_t6_3_auth_probe_called_with_manifest_scopes(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """T6.3 contract: the auth probe ``acquire_token`` MUST be
        called with the manifest's declared scopes + server_url."""
        admission_deps, authz_client = _make_admission_deps(monkeypatch)
        await registry.register_with_full_attestation_check(
            _fixture_pack(),
            _fixture_artefacts(),
            trust_gate=_mock_trust_gate(),
            supply_chain=supply_chain,
            object_store=object_store,
            license_allowlist=("MIT",),
            mcp_admission=admission_deps,
        )
        authz_client.acquire_token.assert_awaited_once()
        call = authz_client.acquire_token.await_args
        assert call.kwargs["server_url"] == "https://server.example/mcp"
        assert call.kwargs["manifest_scopes"] == ("mcp:tools",)

    async def test_admission_does_not_load_fixture_module(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Deferred-load invariant: admission MUST NOT call
        ``EntryPoint.load()``. The fixture's
        :file:`__init__.py` is import-poisoned (``raise
        AssertionError``) so a regression that loaded the package
        would trip the assertion."""
        admission_deps, _ = _make_admission_deps(monkeypatch)
        # The DiscoveredPack's entry_point.load() side_effect is
        # AssertionError; if admission ever calls it the AssertionError
        # propagates and the test fails loudly.
        await registry.register_with_full_attestation_check(
            _fixture_pack(),
            _fixture_artefacts(),
            trust_gate=_mock_trust_gate(),
            supply_chain=supply_chain,
            object_store=object_store,
            license_allowlist=("MIT",),
            mcp_admission=admission_deps,
        )

    async def test_admission_emits_plugin_registration_succeeded_audit_row(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        engine: AsyncEngine,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The registry's audit emission writes the
        ``plugin.registration_succeeded`` row to the chain. Read it
        back from the in-memory SQLite engine to verify the chain
        is populated correctly (per the audit-chain integrity
        contract — Sprint-2 substrate)."""
        admission_deps, _ = _make_admission_deps(monkeypatch)
        await registry.register_with_full_attestation_check(
            _fixture_pack(),
            _fixture_artefacts(),
            trust_gate=_mock_trust_gate(),
            supply_chain=supply_chain,
            object_store=object_store,
            license_allowlist=("MIT",),
            mcp_admission=admission_deps,
        )
        async with engine.begin() as conn:
            result = await conn.execute(select(_audit_event))
            rows = result.fetchall()
        event_types = {r.event_type for r in rows}
        assert "plugin.registration_succeeded" in event_types, (
            f"expected plugin.registration_succeeded in audit chain; got {event_types!r}"
        )


# ---------------------------------------------------------------------------
# T12.2 — MCPHost orchestration against the admitted fixture
# ---------------------------------------------------------------------------


def _make_session(server_url: str, session_id: str = "fixture-sess-1") -> MCPSession:
    sdk_session = MagicMock()
    sdk_session.call_tool = AsyncMock(return_value={"content": "ok"})
    sdk_session.list_tools = AsyncMock(return_value=[])
    return MCPSession(
        server_url=server_url,
        sdk_session=sdk_session,
        exit_stack=AsyncExitStack(),
        get_session_id=lambda: session_id,
        token_scopes=("mcp:tools",),
        token_client_id="cognic-mcp-bank_a",
    )


def _build_mcp_server_entry_from_fixture() -> MCPServerEntry:
    """Translate the on-disk fixture manifest into the
    MCPServerEntry shape MCPHost dispatches against. In production
    the portal lifespan wiring (T13/T14 follow-up) does this from
    the registry walk; for the smoke test we do it inline so the
    fixture's manifest values flow through to the orchestrator."""
    manifest = tomllib.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
    mcp = manifest["tool"]["cognic"]["mcp"]
    runtime = manifest["tool"]["cognic"]["runtime"]
    identity = manifest["tool"]["cognic"]["identity"]
    return MCPServerEntry(
        server_id=identity["pack_id"],
        server_url=mcp["server_url"],
        transport_kind=mcp["transport"],
        manifest_scopes=tuple(mcp["scopes"]),
        risk_tier=runtime["risk_tier"],
        pack_signature_digest="b" * 64,
    )


@pytest.fixture
def mock_http_transport() -> MagicMock:
    """Mocked HTTP transport — keeps the smoke test in-process
    (no real OAuth AS, no real MCP server) while still walking the
    full MCPHost orchestration code path."""
    transport = MagicMock()
    transport.open_session = AsyncMock(return_value=_make_session("https://server.example/mcp"))
    transport.send = AsyncMock(return_value={"content": "ok"})
    transport.close_session = AsyncMock(return_value=None)
    return transport


@pytest.fixture
def mock_runtime_authz() -> MagicMock:
    """Runtime MCPAuthzClient — mocked so the smoke test doesn't
    hit a real AS. Returns a fresh Token on each acquire."""
    from cognic_agentos.protocol.mcp_authz import MCPAuthzClient

    client = MagicMock(spec=MCPAuthzClient)
    client.acquire_token = AsyncMock(
        return_value=Token(
            value="runtime-token",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="cognic-mcp-bank_a",
        )
    )
    client.invalidate_cached_token = AsyncMock(return_value=None)
    client.step_up_token = AsyncMock()
    return client


@pytest.fixture
def host_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Mocked require_mcp so MCPHost can be constructed without
    the SDK actually being importable in test envs."""
    from cognic_agentos.protocol import mcp_host

    monkeypatch.setattr(mcp_host, "require_mcp", MagicMock())
    return mcp_host


@pytest.fixture
def mcp_host(
    host_module: Any,
    mock_http_transport: MagicMock,
    mock_runtime_authz: MagicMock,
    audit_store: AuditStore,
    decision_history_store: DecisionHistoryStore,
) -> Any:
    """Returns the constructed MCPHost. Typed as ``Any`` because
    ``host_module.MCPHost`` resolves through the dynamically-mocked
    ``host_module`` fixture (mypy can't track the attribute through
    monkeypatch)."""
    entry = _build_mcp_server_entry_from_fixture()
    settings = build_settings_without_env_file()
    return host_module.MCPHost(
        servers={entry.server_id: entry},
        transports={"http": mock_http_transport},
        authz=mock_runtime_authz,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
        settings=settings,
    )


class TestMCPHostSmokeAgainstFixture:
    """MCPHost orchestration against the admitted fixture pack —
    proves the manifest-side server entry flows through call_tool
    end-to-end (with mocked transport)."""

    async def test_discover_returns_fixture_server(self, mcp_host: Any) -> None:
        servers = await mcp_host.discover_servers()
        assert len(servers) == 1
        assert servers[0].server_id == "cognic-test-mcp-pack"
        assert servers[0].server_url == "https://server.example/mcp"
        assert servers[0].transport_kind == "http"
        assert servers[0].risk_tier == "read_only"
        assert servers[0].manifest_scopes == ("mcp:tools",)

    async def test_call_tool_emits_audit_invocation_row_in_real_chain(
        self,
        mcp_host: Any,
        engine: AsyncEngine,
    ) -> None:
        """The successful call_tool path emits an
        ``audit.tool_invocation`` row to the REAL audit chain (in-
        memory SQLite). Verifies T11's wiring against a real
        AuditStore — not just MagicMock assertions."""
        result = await mcp_host.call_tool(
            server_id="cognic-test-mcp-pack",
            tool_name="lookup",
            arguments={"q": "x"},
            request_id="t12-smoke-req-1",
            tenant_id="bank-a",
        )
        assert result.payload == {"content": "ok"}
        # Read back from the audit chain
        async with engine.begin() as conn:
            audit_rows = (await conn.execute(select(_audit_event))).fetchall()
        invocation_rows = [r for r in audit_rows if r.event_type == "audit.tool_invocation"]
        assert len(invocation_rows) == 1
        row = invocation_rows[0]
        assert row.request_id == "t12-smoke-req-1"
        assert row.tenant_id == "bank-a"
        # Payload schema (T11 contract)
        payload = row.payload
        assert payload["pack_id"] == "cognic-test-mcp-pack"
        assert payload["tool_name"] == "lookup"
        assert payload["mcp_session_id"] == "fixture-sess-1"
        assert payload["outcome"] == "ok"
        # Token-free invariant
        assert "runtime-token" not in str(payload)

    async def test_call_tool_emits_decision_history_row_in_real_chain(
        self,
        mcp_host: Any,
        engine: AsyncEngine,
    ) -> None:
        """Parallel decision_history surface (T11 R1 P2 #6 — separate
        evidence surface, queryable by request_id for examiner
        replay)."""
        await mcp_host.call_tool(
            server_id="cognic-test-mcp-pack",
            tool_name="lookup",
            arguments={},
            request_id="t12-smoke-req-2",
            tenant_id="bank-a",
        )
        async with engine.begin() as conn:
            dh_rows = (await conn.execute(select(_decision_history))).fetchall()
        mcp_call_rows = [r for r in dh_rows if r.event_type == "mcp_call"]
        assert len(mcp_call_rows) == 1
        row = mcp_call_rows[0]
        assert row.request_id == "t12-smoke-req-2"
        assert row.tenant_id == "bank-a"
        payload = row.payload
        assert payload["pack_id"] == "cognic-test-mcp-pack"
        assert payload["decision"] == "invoked"
        assert payload["decision_reason"] is None

    async def test_high_risk_call_against_fixture_refused(
        self,
        host_module: Any,
        mock_http_transport: MagicMock,
        mock_runtime_authz: MagicMock,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        engine: AsyncEngine,
    ) -> None:
        """ADR-014 transitional gate is observable end-to-end against
        the fixture: replace the entry's risk_tier with a high-risk
        value and verify the gate refuses, emits the
        ``audit.tool_invocation_refused`` row to the real audit
        chain, AND emits the parallel ``mcp_call`` decision row to
        the real decision_history table — same chain-readback shape
        as the success-path tests above. Without this, T12's value
        (real-store smoke) is half-realised on the high-risk path.
        """
        # Build an MCPServerEntry with a high-risk tier (mutating
        # the fixture's manifest tier by reconstruction)
        entry = host_module.MCPServerEntry(
            server_id="cognic-test-mcp-pack",
            server_url="https://server.example/mcp",
            transport_kind="http",
            manifest_scopes=("mcp:tools",),
            risk_tier="payment_action",  # high-risk override
            pack_signature_digest="b" * 64,
        )
        settings = build_settings_without_env_file()
        host = host_module.MCPHost(
            servers={entry.server_id: entry},
            transports={"http": mock_http_transport},
            authz=mock_runtime_authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        with pytest.raises(host_module.MCPToolInvocationRefused) as exc:
            await host.call_tool(
                server_id="cognic-test-mcp-pack",
                tool_name="transfer_funds",
                arguments={},
                request_id="t12-high-risk-req",
                tenant_id="bank-a",
            )
        assert exc.value.reason == "tool_approval_engine_not_available"
        # Gate fires before any token / session work
        mock_runtime_authz.acquire_token.assert_not_called()
        mock_http_transport.open_session.assert_not_called()

        # R1 P3 #1: read back the parallel evidence rows from the
        # REAL chains (in-memory SQLite). Mirrors the success-path
        # tests' chain-readback shape.
        async with engine.begin() as conn:
            audit_rows = (await conn.execute(select(_audit_event))).fetchall()
            dh_rows = (await conn.execute(select(_decision_history))).fetchall()

        refused_rows = [r for r in audit_rows if r.event_type == "audit.tool_invocation_refused"]
        assert len(refused_rows) == 1
        ar = refused_rows[0]
        assert ar.request_id == "t12-high-risk-req"
        assert ar.tenant_id == "bank-a"
        ap = ar.payload
        assert ap["pack_id"] == "cognic-test-mcp-pack"
        assert ap["tool_name"] == "transfer_funds"
        assert ap["refusal_reason"] == "tool_approval_engine_not_available"
        assert ap["declared_risk_tier"] == "payment_action"
        assert ap["sprint_13_5_followup"] is True
        # Pre-dispatch refusal: no session was opened
        assert ap["mcp_session_id"] is None
        assert ap["as_issuer"] is None

        mcp_call_rows = [r for r in dh_rows if r.event_type == "mcp_call"]
        assert len(mcp_call_rows) == 1
        dr = mcp_call_rows[0]
        assert dr.request_id == "t12-high-risk-req"
        assert dr.tenant_id == "bank-a"
        dp = dr.payload
        assert dp["pack_id"] == "cognic-test-mcp-pack"
        assert dp["tool_name"] == "transfer_funds"
        assert dp["decision"] == "refused"
        assert dp["decision_reason"] == "tool_approval_engine_not_available"
        assert dp["declared_risk_tier"] == "payment_action"
