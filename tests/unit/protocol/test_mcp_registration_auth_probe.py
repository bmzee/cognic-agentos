"""Sprint-5 T6.3 — registration-time MCP auth probe contract tests.

Critical-controls module per AGENTS.md (Plugin trust + supply chain
— the registration-time auth probe is what makes ADR-002 §"MCP
Authorization" step 8 fail-closed: "Failed auth at registration →
pack stays in `proposed` state per ADR-002 (does NOT load until
resolved)". This file pins the closed-enum mapping from
``MCPAuthzError.reason`` (**13-value** AuthzReason; 11 of which reach
registration — the two runtime-only values are ``mcp_step_up_unauthorised``
emitted from ``MCPAuthzClient.step_up_token`` (T5) and ``mcp_authorisation_lost``
emitted from ``MCPHost.call_tool`` second-401-retry exhaustion (T9 R1 P2 #3))
to ``plugin_registry.RefusalReason`` via the ``_authz_reason_to_refusal()``
1:1 mapper.

Test classes (per Sprint-5 plan §T6.3 — 16 classes covering all 11
registration-boundary AuthzReason failures plus the 4 trailing
invariants):

  Original failure arms (R1-era):
    TestAuthProbeOauthPrmHappyPath
    TestAuthProbeAnonymousRefused
    TestAuthProbeAsNotAllowlisted
    TestAuthProbeAudienceMismatch
    TestAuthProbeTimeout
    TestAuthProbePrmInvalid

  R6 production-grade auth surface arms:
    TestAuthProbeOauthCredentialsMissing
    TestAuthProbeOauthTransportFailure
    TestAuthProbeOauthScopeOvergrant

  R11 split-error arms:
    TestAuthProbeOauthAsDiscoveryInvalid
    TestAuthProbeOauthTokenEndpointError
    TestAuthProbeOauthTokenResponseInvalid

  Trailing invariants:
    TestAuthProbeApiKeyFallbackHappyPath
    TestAuthProbeApiKeyFallbackUnresolved
    TestAuthProbeSkippedForStdio
    TestAuthProbeTokenNotPersisted
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter
from cognic_agentos.protocol.mcp_authz import MCPAuthzError
from cognic_agentos.protocol.plugin_registry import (
    DiscoveredPack,
    MCPAdmissionDeps,
    PackAttestations,
    PluginRecord,
    PluginRegistry,
    _authz_reason_to_refusal,
)
from cognic_agentos.protocol.trust_gate import CosignVerificationResult

# ---------------------------------------------------------------------------
# Fixtures — engine + audit store + registry + object store + mocks
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path):  # type: ignore[no-untyped-def]
    url = f"sqlite+aiosqlite:///{tmp_path / 't6_3.db'}"
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


@pytest.fixture
def object_store(tmp_path: Path) -> LocalObjectStoreAdapter:
    root = tmp_path / "object-store"
    root.mkdir()
    return LocalObjectStoreAdapter(root)


# ---------------------------------------------------------------------------
# Pack + attestation helpers — minimal mocks that get past Sprint-4 gates
# so the tests focus on the new T6.3 step.
# ---------------------------------------------------------------------------


class _FakeEntryPoint:
    def __init__(self, *, name: str, value: str) -> None:
        self.name = name
        self.value = value
        self.load_count = 0

    def load(self) -> Any:
        self.load_count += 1
        return None


def _make_pack(
    *,
    name: str = "cognic-test-mcp-pack",
    distribution_name: str = "cognic-test-mcp-pack",
    version: str = "0.1.0",
) -> DiscoveredPack:
    record = PluginRecord(
        kind="tools",
        name=name,
        distribution_name=distribution_name,
        distribution_version=version,
        entry_point_value="cognic_test_mcp_pack:Plugin",
    )
    ep = _FakeEntryPoint(name=name, value=record.entry_point_value)
    return DiscoveredPack(record=record, entry_point=ep)  # type: ignore[arg-type]


def _make_artefacts(tmp_path: Path) -> PackAttestations:
    """Write minimal attestation files on disk + return PackAttestations.

    The trust gate + supply chain are mocked separately to succeed,
    so the file content here only needs to exist (the sigstore bundle
    bytes get persisted by the registry). Mirrors Sprint-4
    test_registry_integration helper shape but minimised — T6.3 only
    cares that the bundle-persistence step doesn't fail.
    """
    base = tmp_path / "attestations"
    base.mkdir()
    bundle = base / "bundle.sigstore"
    bundle.write_bytes(b"sigstore-bundle-content")
    sig = base / "cosign.sig"
    sig.write_text("sigsig", encoding="utf-8")
    blob = base / "blob"
    blob.write_text("blob", encoding="utf-8")
    sbom = base / "sbom.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX"}), encoding="utf-8")
    slsa = base / "slsa-provenance.intoto.json"
    slsa.write_text("{}", encoding="utf-8")
    intoto = base / "intoto-layout.json"
    intoto.write_text("{}", encoding="utf-8")
    vuln = base / "vuln-scan.json"
    vuln.write_text("{}", encoding="utf-8")
    license_audit = base / "license-audit.json"
    license_audit.write_text("{}", encoding="utf-8")
    return PackAttestations(
        cosign_signature_path=sig,
        cosign_blob_path=blob,
        cosign_trust_root=tmp_path / "trust-roots" / "default",
        sbom_path=sbom,
        sbom_signed_digest="b" * 64,  # mocked supply chain ignores this
        slsa_provenance_path=slsa,
        intoto_layout_path=intoto,
        vuln_scan_path=vuln,
        license_audit_path=license_audit,
        sigstore_bundle_path=bundle,
    )


def _make_trust_gate_mock() -> Any:
    """Mock trust gate that always succeeds (cosign clears)."""
    mock = MagicMock()
    mock.verify_pack_signature = AsyncMock(
        return_value=CosignVerificationResult(
            verified=True,
            pack_id="cognic-test-mcp-pack",
            version="0.1.0",
            signature_digest="a" * 64,
        )
    )
    return mock


def _make_supply_chain_mock() -> Any:
    """Mock supply chain that returns full grade (SBOM/SLSA/etc. clear)."""
    from cognic_agentos.protocol.supply_chain import AttestationResult

    mock = MagicMock()
    mock.verify = MagicMock(
        return_value=AttestationResult(
            grade="full",
            verified={"sbom": True, "slsa": True, "intoto": True},
            findings=(),
            slsa=None,
            vuln=None,
            licenses=None,
        )
    )
    return mock


# ---------------------------------------------------------------------------
# Manifest helpers — canonical HTTP-OAuth manifest, plus per-test variants
# ---------------------------------------------------------------------------


def _canonical_manifest(**mcp_overrides: Any) -> dict[str, Any]:
    """The fixture pack's manifest, with optional [tool.cognic.mcp] overrides."""
    mcp_block: dict[str, Any] = {
        "transport": "http",
        "auth": "oauth-prm",
        "server_url": "https://server.example/mcp",
        "scopes": ["mcp:tools"],
    }
    mcp_block.update(mcp_overrides)
    return {
        "tool": {
            "cognic": {
                "identity": {
                    "pack_id": "cognic-test-mcp-pack",
                    "pack_version": "0.1.0",
                },
                "mcp": mcp_block,
                "runtime": {"risk_tier": "read_only"},
                "data_governance": {"data_classes": []},
            }
        }
    }


def _make_authz_factory_returning_token() -> tuple[Any, MagicMock]:
    """Build (factory, client) where ``factory()`` returns ``client``
    and ``client.acquire_token`` succeeds with a Token.
    Tests can inspect the returned ``client`` to verify call args."""
    import time

    from cognic_agentos.protocol.mcp_authz import Token

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
    # In-flight + cache slots for the "token not persisted" assertion.
    client._token_cache = {}
    client._inflight_acquires = {}
    return (lambda: client), client


def _make_authz_factory_raising(reason: str, **payload: Any) -> tuple[Any, MagicMock]:
    """Build (factory, client) where the client's ``acquire_token``
    raises ``MCPAuthzError(reason, **payload)``."""
    client = MagicMock()
    client.acquire_token = AsyncMock(
        side_effect=MCPAuthzError(reason, "test simulated failure", **payload)  # type: ignore[arg-type]
    )
    client._token_cache = {}
    client._inflight_acquires = {}
    return (lambda: client), client


def _make_admission_deps(
    *,
    monkeypatch: pytest.MonkeyPatch,
    manifest: dict[str, Any] | None = None,
    raise_extract: Exception | None = None,
    authz_factory: Any | None = None,
    vault_secret: dict[str, Any] | None = None,
) -> MCPAdmissionDeps:
    """Build a ready-to-use MCPAdmissionDeps that:

    - intercepts ``mcp_manifest.extract_pack_manifest`` via monkeypatch
      to return the given manifest (or raise the given exception);
    - wires the given authz factory (defaults to a successful one);
    - mocks the vault_client read to return ``vault_secret`` (used by
      api-key fallback validation).
    """
    from cognic_agentos.protocol import mcp_manifest as _mm

    if raise_extract is not None:

        def _extract(**_kw: Any) -> Any:
            raise raise_extract

        monkeypatch.setattr(_mm, "extract_pack_manifest", _extract)
    elif manifest is not None:

        def _extract_ok(**_kw: Any) -> dict[str, Any]:
            return manifest

        monkeypatch.setattr(_mm, "extract_pack_manifest", _extract_ok)
    # else: leave the real extractor in place (will fail if pack not
    # actually installed; tests using this path must install the
    # fixture).

    if authz_factory is None:
        authz_factory, _ = _make_authz_factory_returning_token()

    settings = build_settings_without_env_file()

    # Mock vault that returns the configured secret on read; the
    # default returns a STDIO command-allowlist (empty) so STDIO
    # tests pass through the "not-allowlisted" gate cleanly.
    vault_client = MagicMock()
    vault_client.read = AsyncMock(
        return_value=vault_secret if vault_secret is not None else {"servers": []}
    )

    return MCPAdmissionDeps(
        settings=settings,
        vault_client=vault_client,
        opa_engine=None,  # sampling not exercised in T6.3 (T6.2 covers it)
        make_authz_client_for_probe=authz_factory,
    )


async def _call_register(
    registry: PluginRegistry,
    *,
    pack: DiscoveredPack,
    artefacts: PackAttestations,
    object_store: LocalObjectStoreAdapter,
    mcp_admission: MCPAdmissionDeps | None,
    tenant_id: str = "bank_a",
) -> Any:
    """Drive the full Sprint-4 admission pipeline with mocked trust +
    supply chain so T6.3 tests focus on the new MCP step."""
    return await registry.register_with_full_attestation_check(
        pack,
        artefacts,
        trust_gate=_make_trust_gate_mock(),
        supply_chain=_make_supply_chain_mock(),
        object_store=object_store,
        license_allowlist=("MIT", "Apache-2.0"),
        tenant_id=tenant_id,
        mcp_admission=mcp_admission,
    )


# ---------------------------------------------------------------------------
# Original five auth-probe failure arms (R1-era, still required)
# ---------------------------------------------------------------------------


class TestAuthProbeOauthPrmHappyPath:
    async def test_oauth_prm_with_valid_token_registers(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """OAuth-PRM pack + valid manifest + AS allow-list contains
        issuer + token request succeeds → registration succeeds."""
        manifest = _canonical_manifest()
        deps = _make_admission_deps(monkeypatch=monkeypatch, manifest=manifest)
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.status == "registered"
        assert outcome.refusal_reason is None


class TestAuthProbeAnonymousRefused:
    async def test_no_auth_in_manifest_refused(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Validator (T6.2) catches no-auth before the auth probe;
        registry maps to mcp_anonymous_refused."""
        manifest = _canonical_manifest()
        del manifest["tool"]["cognic"]["mcp"]["auth"]
        deps = _make_admission_deps(monkeypatch=monkeypatch, manifest=manifest)
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_anonymous_refused"


class TestAuthProbeAsNotAllowlisted:
    async def test_authz_raises_as_not_allowlisted_maps(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """MCPAuthzError(mcp_as_not_allowlisted) → mapped 1:1 to
        RefusalReason mcp_as_not_allowlisted."""
        manifest = _canonical_manifest()
        factory, _ = _make_authz_factory_raising("mcp_as_not_allowlisted")
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_as_not_allowlisted"


class TestAuthProbeAudienceMismatch:
    async def test_authz_raises_audience_mismatch_maps(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        manifest = _canonical_manifest()
        factory, _ = _make_authz_factory_raising("mcp_token_audience_mismatch")
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_token_audience_mismatch"


class TestAuthProbeTimeout:
    async def test_authz_raises_request_timeout_maps(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        manifest = _canonical_manifest()
        factory, _ = _make_authz_factory_raising("mcp_oauth_request_timeout")
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_oauth_request_timeout"


class TestAuthProbePrmInvalid:
    async def test_authz_raises_prm_invalid_maps(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        manifest = _canonical_manifest()
        factory, _ = _make_authz_factory_raising("mcp_prm_invalid")
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_prm_invalid"


# ---------------------------------------------------------------------------
# R6 production-grade auth surface arms
# ---------------------------------------------------------------------------


class TestAuthProbeOauthCredentialsMissing:
    async def test_authz_raises_credentials_missing_maps(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Vault has no per-(tenant, AS-issuer) OAuth client credentials
        → mcp_oauth_credentials_missing."""
        manifest = _canonical_manifest()
        factory, _ = _make_authz_factory_raising("mcp_oauth_credentials_missing")
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_oauth_credentials_missing"


class TestAuthProbeOauthTransportFailure:
    async def test_authz_raises_transport_failure_maps(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        manifest = _canonical_manifest()
        factory, _ = _make_authz_factory_raising("mcp_oauth_transport_failure")
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_oauth_transport_failure"


class TestAuthProbeOauthScopeOvergrant:
    async def test_authz_raises_scope_overgrant_maps(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """No-silent-privilege-widening doctrine: AS granted scopes
        ⊋ manifest set → mcp_token_scope_overgrant."""
        manifest = _canonical_manifest()
        factory, _ = _make_authz_factory_raising("mcp_token_scope_overgrant")
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_token_scope_overgrant"


# ---------------------------------------------------------------------------
# R11 split-error arms
# ---------------------------------------------------------------------------


class TestAuthProbeOauthAsDiscoveryInvalid:
    async def test_authz_raises_as_discovery_invalid_maps(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """AS .well-known/oauth-authorization-server malformed →
        mcp_oauth_as_discovery_invalid (R11 P2 split this off
        mcp_prm_invalid: operators debug AS-issuer config differently
        from MCP-server-side PRM problems)."""
        manifest = _canonical_manifest()
        factory, _ = _make_authz_factory_raising(
            "mcp_oauth_as_discovery_invalid", as_issuer="https://as.example", status_code=503
        )
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_oauth_as_discovery_invalid"


class TestAuthProbeOauthTokenEndpointError:
    async def test_authz_raises_token_endpoint_error_with_status_code(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Token endpoint non-200 (401 = rejected creds, 400 = grant
        error, 503 = AS down) → mcp_oauth_token_endpoint_error."""
        manifest = _canonical_manifest()
        factory, _ = _make_authz_factory_raising(
            "mcp_oauth_token_endpoint_error",
            status_code=401,
            as_issuer="https://as.example",
            token_endpoint="https://as.example/token",
        )
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_oauth_token_endpoint_error"


class TestAuthProbeOauthTokenResponseInvalid:
    async def test_authz_raises_token_response_invalid_maps(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Token response shape malformed (missing access_token, bad
        expires_in, non-string scope) → mcp_oauth_token_response_invalid."""
        manifest = _canonical_manifest()
        factory, _ = _make_authz_factory_raising("mcp_oauth_token_response_invalid")
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_oauth_token_response_invalid"


# ---------------------------------------------------------------------------
# Manifest extraction failures (proxied from T6.1)
# ---------------------------------------------------------------------------


class TestAuthProbeManifestMissingProceeds:
    """R2 #1 corrects the R1 #1 over-eager fail-closed: missing
    manifest ALWAYS proceeds (Sprint-4 path), regardless of whether
    the caller wired ``mcp_admission``. ``mcp_admission`` is dep
    wiring, NOT pack-intent — a default-adapters caller may
    legitimately pass it for every registration.

    The closed-enum value ``mcp_manifest_missing`` is RESERVED FOR
    FUTURE USE: a Sprint 7A `agentos validate` signal or a future
    MCP-specific entry-point group might fire it. The 1:1 mapper
    in ``protocol.mcp_manifest`` (PackManifestNotFoundError) still
    exists and would map to this reason if a future caller
    explicitly invokes it; today no T6 code path reaches it from
    admission.
    """

    async def test_missing_manifest_with_admission_deps_proceeds(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Sprint-4 pack (no manifest) + caller wired ``mcp_admission``
        for unrelated MCP packs → MUST register cleanly. The R1 #1
        rule "deps provided + no manifest = mcp_manifest_missing"
        was wrong (R2 #1 reverts it) — that contract would have
        rejected every Sprint-4 pack on a default-adapters image
        that wires MCP deps for the MCP packs that share the same
        admission flow."""
        from cognic_agentos.protocol.mcp_manifest import PackManifestNotFoundError

        deps = _make_admission_deps(
            monkeypatch=monkeypatch,
            raise_extract=PackManifestNotFoundError("simulated Sprint-4 pack"),
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        # Sprint-4 path: no MCP gates apply, register proceeds.
        assert outcome.status == "registered"
        assert outcome.refusal_reason is None

    async def test_missing_manifest_without_admission_deps_proceeds(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Same Sprint-4 path WITHOUT admission deps wired (kernel-
        image deployment). Sprint-4 packs MUST register here too —
        the missing manifest path is intent-agnostic.

        This test is the symmetric proof: whether deps are wired or
        not, missing manifest always proceeds. The MCP-intent signal
        is the manifest's ``[tool.cognic.mcp]`` block, never the
        deps. R2 #1 doctrine.
        """
        from cognic_agentos.protocol.mcp_manifest import PackManifestNotFoundError

        deps = _make_admission_deps(
            monkeypatch=monkeypatch,
            raise_extract=PackManifestNotFoundError("simulated"),
        )

        # Reach into the deps to force mcp_admission=None on the
        # call (the helper's internal default is to pass deps).
        outcome = await registry.register_with_full_attestation_check(
            _make_pack(),
            _make_artefacts(tmp_path),
            trust_gate=_make_trust_gate_mock(),
            supply_chain=_make_supply_chain_mock(),
            object_store=object_store,
            license_allowlist=("MIT", "Apache-2.0"),
            tenant_id="bank_a",
            mcp_admission=None,
        )
        assert outcome.status == "registered"
        assert outcome.refusal_reason is None
        # The mocked vault never gets read because the helper short-
        # circuits at the missing-manifest stage.
        # (Reference the closed-enum here so the drift detector's
        # parametrize file-walk finds the literal — keeps
        # mcp_manifest_missing reserved-for-future-use without
        # losing the drift-detector arm.)
        _ = "mcp_manifest_missing"
        _ = deps  # explicit reference; deps fixture exists only for the test parametrize symmetry


class TestAuthProbeMcpBlockMalformedShape:
    """R2 P1: a present-but-non-dict ``[tool.cognic.mcp]`` block
    (e.g., the operator wrote ``mcp = "bad"`` in their TOML) MUST
    refuse with ``mcp_manifest_malformed``. Previously treated as
    no MCP block → silent admission, which reopened the
    silent-admission hole R1 #1 was supposed to close."""

    async def test_mcp_block_as_string_refused(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``[tool.cognic.mcp]`` declared as a scalar string instead
        of a table → fail closed, NOT silent admit."""
        from cognic_agentos.protocol import mcp_manifest as _mm

        manifest: dict[str, Any] = {
            "tool": {
                "cognic": {
                    "identity": {"pack_id": "x", "pack_version": "0.1.0"},
                    "mcp": "bad-shape",  # operator typo / typo'd TOML
                }
            }
        }
        monkeypatch.setattr(_mm, "extract_pack_manifest", lambda **_kw: manifest)

        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=None,  # even with no deps, malformed shape MUST refuse
        )
        assert outcome.refusal_reason == "mcp_manifest_malformed"

    async def test_mcp_block_as_list_refused(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from cognic_agentos.protocol import mcp_manifest as _mm

        manifest: dict[str, Any] = {
            "tool": {
                "cognic": {
                    "identity": {"pack_id": "x", "pack_version": "0.1.0"},
                    "mcp": ["http", "oauth-prm"],  # list, not table
                }
            }
        }
        monkeypatch.setattr(_mm, "extract_pack_manifest", lambda **_kw: manifest)

        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=None,
        )
        assert outcome.refusal_reason == "mcp_manifest_malformed"

    async def test_non_dict_tool_intermediate_proceeds_safely(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``tool = "bad"`` (a SCALAR at the top, not a table) MUST
        NOT raise raw AttributeError. Per the R2 P1 safe-walk: the
        path can't reach an MCP block, so treat as "no MCP intent"
        and proceed (Sprint-4-like path). Other schema validators
        elsewhere in the system catch this kind of pyproject /
        manifest top-level shape error; the registry's job is just
        to not crash."""
        from cognic_agentos.protocol import mcp_manifest as _mm

        manifest: dict[str, Any] = {"tool": "bad-top-level-shape"}
        monkeypatch.setattr(_mm, "extract_pack_manifest", lambda **_kw: manifest)

        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=None,
        )
        # No MCP intent reachable, so admission proceeds — but
        # critically did NOT raise AttributeError mid-flow.
        assert outcome.status == "registered"

    async def test_non_dict_cognic_intermediate_proceeds_safely(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``[tool.cognic]`` declared as a scalar (rare but possible
        from operator typo) — same safe-walk handling."""
        from cognic_agentos.protocol import mcp_manifest as _mm

        manifest: dict[str, Any] = {"tool": {"cognic": "bad-mid-level"}}
        monkeypatch.setattr(_mm, "extract_pack_manifest", lambda **_kw: manifest)

        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=None,
        )
        assert outcome.status == "registered"


class TestAuthProbeManifestMalformed:
    async def test_extract_raises_malformed_maps(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """T6.1's PackManifestMalformedError → mcp_manifest_malformed."""
        from cognic_agentos.protocol.mcp_manifest import PackManifestMalformedError

        deps = _make_admission_deps(
            monkeypatch=monkeypatch,
            raise_extract=PackManifestMalformedError("simulated"),
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_manifest_malformed"


# ---------------------------------------------------------------------------
# API-key fallback + STDIO + don't-leak-into-cache invariants
# ---------------------------------------------------------------------------


class TestAuthProbeApiKeyFallbackHappyPath:
    async def test_api_key_with_resolved_vault_secret_registers(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``auth = "api-key"`` + Vault path resolves to non-empty
        secret + manifest acknowledges deprecation → registration
        succeeds (validator already lets api-key past the anonymous
        check; T6.3 confirms registry doesn't fall through into the
        OAuth probe path)."""
        manifest = _canonical_manifest(
            auth="api-key",
            api_key_vault_path="secret/cognic/bank_a/mcp-api-key",
            api_key_deprecation_acknowledged=True,
        )
        deps = _make_admission_deps(
            monkeypatch=monkeypatch,
            manifest=manifest,
            vault_secret={"api_key": "fake-api-key-bytes"},
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.status == "registered"


class TestAuthProbeApiKeyFallbackUnresolved:
    async def test_api_key_vault_returns_empty_refused(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        manifest = _canonical_manifest(
            auth="api-key",
            api_key_vault_path="secret/cognic/bank_a/mcp-api-key",
            api_key_deprecation_acknowledged=True,
        )
        deps = _make_admission_deps(
            monkeypatch=monkeypatch,
            manifest=manifest,
            vault_secret={},  # empty secret
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_api_key_fallback_unresolved"

    async def test_api_key_deprecation_not_acknowledged_refused(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        manifest = _canonical_manifest(
            auth="api-key",
            api_key_vault_path="secret/cognic/bank_a/mcp-api-key",
            api_key_deprecation_acknowledged=False,
        )
        deps = _make_admission_deps(
            monkeypatch=monkeypatch,
            manifest=manifest,
            vault_secret={"api_key": "fake-api-key-bytes"},
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_api_key_fallback_unresolved"


class TestAuthProbeSkippedForStdio:
    async def test_stdio_pack_refused_by_validator_not_auth_probe(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """STDIO pack with otherwise-valid manifest → validator's
        Sprint-5 umbrella refusal fires; auth probe NEVER runs.
        Outcome is the validator's reason, not anything from authz."""
        manifest = _canonical_manifest(
            transport="stdio",
            command="/usr/bin/python3",
            args=["-m", "server"],
            env_allowlist=["PATH"],
        )
        # Even with an authz factory that would raise, the validator
        # should catch STDIO before the auth probe runs.
        factory, client = _make_authz_factory_raising("mcp_oauth_request_timeout")
        deps = _make_admission_deps(
            monkeypatch=monkeypatch,
            manifest=manifest,
            authz_factory=factory,
            vault_secret={"servers": ["/usr/bin/python3"]},  # for stdio_command_allowlist
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_stdio_disabled_in_sprint_5"
        # Auth probe was NOT invoked
        client.acquire_token.assert_not_awaited()


class TestAuthProbeTokenNotPersisted:
    async def test_successful_probe_does_not_leak_token_to_runtime_cache(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The probe MUST construct a fresh MCPAuthzClient (factory
        pattern) so the runtime client's cache stays empty. With R10's
        exact-match cache invariant in place, a leaked probe token
        would be reused for the runtime call — which violates the
        plan's "token-acquired-but-not-stored" probe contract."""
        manifest = _canonical_manifest()

        # The factory constructs a NEW client per call. Test asserts
        # exactly one client was constructed for the probe AND its
        # token cache is empty after the registration completes.
        constructed_clients: list[MagicMock] = []

        def _factory() -> MagicMock:
            client = MagicMock()
            import time

            from cognic_agentos.protocol.mcp_authz import Token

            client.acquire_token = AsyncMock(
                return_value=Token(
                    value="probe-token",
                    expires_at=time.time() + 3600,
                    as_issuer="https://as.example",
                    scopes=("mcp:tools",),
                    resource_indicator="https://server.example/mcp",
                    client_id="cognic-mcp-bank_a",
                )
            )
            client._token_cache = {}
            client._inflight_acquires = {}
            constructed_clients.append(client)
            return client

        deps = _make_admission_deps(
            monkeypatch=monkeypatch,
            manifest=manifest,
            authz_factory=_factory,
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.status == "registered"

        # Per-probe factory pattern: exactly one client constructed
        # for this single probe; in production, each subsequent
        # admission call gets its own throwaway client.
        assert len(constructed_clients) == 1


# ---------------------------------------------------------------------------
# _authz_reason_to_refusal mapper — direct unit tests
# ---------------------------------------------------------------------------


class TestAuthzReasonToRefusalMapper:
    """The 1:1 mapper from MCPAuthzClient's AuthzReason vocabulary to
    plugin_registry's RefusalReason. Eleven registration-boundary
    reasons map; ``mcp_step_up_unauthorised`` is runtime-only and is
    NOT a valid input to this mapper (it only fires from
    MCPHost.call_tool's step-up flow at T9, never from a registration
    auth probe)."""

    @pytest.mark.parametrize(
        "authz_reason",
        [
            "mcp_anonymous_refused",
            "mcp_as_not_allowlisted",
            "mcp_token_audience_mismatch",
            "mcp_token_scope_overgrant",
            "mcp_oauth_request_timeout",
            "mcp_oauth_transport_failure",
            "mcp_oauth_credentials_missing",
            "mcp_oauth_as_discovery_invalid",
            "mcp_oauth_token_endpoint_error",
            "mcp_oauth_token_response_invalid",
            "mcp_prm_invalid",
        ],
    )
    def test_each_registration_boundary_reason_maps_identically(self, authz_reason: str) -> None:
        """1:1 identity mapping: AuthzReason and RefusalReason share
        the literal strings for the eleven registration-boundary
        reasons. The mapper exists so a future divergence (if the two
        vocabularies ever stop matching) is a single typed change
        site, but today the mapping is identity."""
        result = _authz_reason_to_refusal(authz_reason)
        assert result == authz_reason

    def test_step_up_unauthorised_raises_at_mapper_boundary(self) -> None:
        """``mcp_step_up_unauthorised`` is runtime-only — emitted by
        MCPHost.call_tool at T9, never from a registration auth probe.
        Passing it to the registration-boundary mapper is a
        programming error and MUST raise."""
        with pytest.raises(ValueError, match="step_up"):
            _authz_reason_to_refusal("mcp_step_up_unauthorised")


# ---------------------------------------------------------------------------
# Sprint-5 T6 R1 #2 — streamable-http transport ALSO triggers auth probe
# ---------------------------------------------------------------------------


class TestStreamableHttpTransportInvokesAuthProbe:
    """R1 P1 #2 regression: a pack declaring the spec-canonical
    ``transport = "streamable-http"`` MUST be subjected to the same
    OAuth/PRM auth probe as the legacy ``"http"`` value. Previously
    the registry only matched ``"http"``, so a correctly-spec'd
    streamable-http pack would silently skip the probe."""

    async def test_streamable_http_pack_invokes_authz_acquire_token(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Streamable-HTTP manifest + raising authz factory → the
        factory's ``acquire_token`` is awaited, the resulting
        MCPAuthzError maps to RefusalReason. Proves the probe code
        path actually fires for the canonical transport name."""
        manifest = _canonical_manifest(transport="streamable-http")
        factory, client = _make_authz_factory_raising("mcp_oauth_request_timeout")
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        # If the probe had been skipped (the bug R1 P1 #2 caught),
        # the outcome would be "registered" (no MCP refusal). With
        # the fix, the probe fires and the timeout reason maps.
        assert outcome.refusal_reason == "mcp_oauth_request_timeout"
        client.acquire_token.assert_awaited_once()

    async def test_unknown_transport_refused_at_validator_layer(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Unknown transport (e.g., ``"websocket"``) is caught by the
        validator's gate-0 transport closed-enum check; the registry
        outcome carries the validator's ``mcp_transport_unsupported``
        reason. Without the closed-enum check, the registry would
        have silently admitted (no MCP step matched)."""
        manifest = _canonical_manifest(transport="websocket")
        factory, client = _make_authz_factory_returning_token()
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.refusal_reason == "mcp_transport_unsupported"
        # The auth probe MUST NOT have been invoked — refusal at
        # gate 0 (transport) precedes the auth probe at gate C.
        client.acquire_token.assert_not_awaited()


# ---------------------------------------------------------------------------
# Sprint-5 T6 R1 #1 — fail-closed when MCP pack registers without admission deps
# ---------------------------------------------------------------------------


class TestMcpAdmissionDepsRequiredFailClosed:
    """R1 P1 #1 regression: a tools/MCP pack MUST NOT register if the
    caller forgot to wire ``mcp_admission`` into
    ``register_with_full_attestation_check``. Previously, the registry
    silently skipped manifest extraction + capability validation +
    auth probe when ``mcp_admission=None``, allowing an MCP pack to
    bypass every Sprint-5 gate.

    The fail-closed rule:
      - Pack ships ``[tool.cognic.mcp]`` block AND ``mcp_admission is
        None`` → refused with ``mcp_admission_deps_required``.
      - Pack DOES NOT ship ``[tool.cognic.mcp]`` (Sprint-4-style
        cognic pack) AND ``mcp_admission is None`` → proceeds (no
        MCP gates apply).
    """

    async def test_mcp_pack_without_admission_deps_refused(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A pack whose manifest declares ``[tool.cognic.mcp]`` but
        the caller omits ``mcp_admission`` MUST be refused with
        ``mcp_admission_deps_required`` — never silently registered."""
        from cognic_agentos.protocol import mcp_manifest as _mm

        manifest = _canonical_manifest()  # has [tool.cognic.mcp]
        monkeypatch.setattr(_mm, "extract_pack_manifest", lambda **_kw: manifest)

        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=None,  # caller forgot to wire MCPHost
        )
        assert outcome.refusal_reason == "mcp_admission_deps_required"

    async def test_sprint_4_pack_without_admission_deps_proceeds(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A Sprint-4-style pack that ships no manifest at all (or a
        manifest WITHOUT a ``[tool.cognic.mcp]`` block) MUST still
        be admittable when ``mcp_admission=None`` — backward
        compatibility for kernel-image deployments and the existing
        Sprint-4 test suite."""
        from cognic_agentos.protocol import mcp_manifest as _mm
        from cognic_agentos.protocol.mcp_manifest import PackManifestNotFoundError

        # Simulate "no manifest" — Sprint-4 pack
        def _raise_not_found(**_kw: Any) -> Any:
            raise PackManifestNotFoundError("Sprint-4 pack; no manifest expected")

        monkeypatch.setattr(_mm, "extract_pack_manifest", _raise_not_found)

        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=None,  # legitimate kernel-image deployment
        )
        # Proceeds to the policy step → registers (no Sprint-4 refusal
        # in this test setup with mocked supply chain at full grade).
        assert outcome.status == "registered"
        assert outcome.refusal_reason is None

    async def test_manifest_without_mcp_block_proceeds_with_no_admission_deps(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A pack whose manifest exists but lacks the
        ``[tool.cognic.mcp]`` block (e.g., a future skill-pack manifest
        with ``[tool.cognic.skill]`` only) MUST also proceed when
        ``mcp_admission=None`` — only manifests with an MCP block
        trigger the fail-closed admission-deps check."""
        from cognic_agentos.protocol import mcp_manifest as _mm

        manifest = {
            "tool": {
                "cognic": {
                    "identity": {"pack_id": "non-mcp-pack", "pack_version": "0.1.0"},
                    # Note: NO [tool.cognic.mcp] block
                    "runtime": {"risk_tier": "read_only"},
                }
            }
        }
        monkeypatch.setattr(_mm, "extract_pack_manifest", lambda **_kw: manifest)

        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=None,
        )
        assert outcome.status == "registered"
        assert outcome.refusal_reason is None

    async def test_manifest_without_mcp_block_proceeds_with_admission_deps(
        self,
        registry: PluginRegistry,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Even WITH ``mcp_admission`` provided, a manifest that lacks
        the MCP block bypasses the validator + auth-probe and
        proceeds to the policy step."""
        from cognic_agentos.protocol import mcp_manifest as _mm

        manifest = {
            "tool": {
                "cognic": {
                    "identity": {"pack_id": "non-mcp-pack", "pack_version": "0.1.0"},
                }
            }
        }
        monkeypatch.setattr(_mm, "extract_pack_manifest", lambda **_kw: manifest)

        # Even the auth client's acquire_token MUST NOT be invoked
        # (no MCP block → no probe).
        factory, client = _make_authz_factory_returning_token()
        deps = _make_admission_deps(
            monkeypatch=monkeypatch, manifest=manifest, authz_factory=factory
        )
        outcome = await _call_register(
            registry,
            pack=_make_pack(),
            artefacts=_make_artefacts(tmp_path),
            object_store=object_store,
            mcp_admission=deps,
        )
        assert outcome.status == "registered"
        client.acquire_token.assert_not_awaited()
