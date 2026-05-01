"""Sprint 4 T12 — cognic_test_pack fixture smoke test.

End-to-end check that the fixture pack at
``tests/fixtures/cognic_test_pack/`` carries an attestation set that
clears T10's full admission pipeline. Per the Sprint-4 plan §"T12
fixture": this is the unit-test path that runs against shimmed cosign;
the env-gated ``@pytest.mark.cosign_real`` integration path (Sprint
4+ work) runs against real cosign + Sigstore.dev.

The smoke test pins three contracts:

  1. Every required attestation file is present + JSON-parseable
     (the regeneration script's validation, expressed as a Python
     test).
  2. Each verifier (T6 trust gate / T7 supply chain / T9 persister)
     accepts the fixture's attestation shapes.
  3. The full T10 ``register_with_full_attestation_check`` call admits
     the fixture pack at ``grade=full`` — proves the fixture ships
     a complete clean attestation set, not a half-complete one.

If a verifier contract changes (e.g. a new mandatory field), this
test fails first — well before the @pytest.mark.cosign_real
integration path runs in CI — and the fixture files get updated as
part of the same commit.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
)
from cognic_agentos.protocol.plugin_registry import (
    DiscoveredPack,
    PackAttestations,
    PluginRecord,
    PluginRegistry,
)
from cognic_agentos.protocol.supply_chain import SupplyChainPipeline
from cognic_agentos.protocol.trust_gate import CosignVerificationResult

#: Filesystem root of the T12 fixture pack.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_FIXTURE_ROOT = _REPO_ROOT / "tests" / "fixtures" / "cognic_test_pack"
_ATTESTATIONS = _FIXTURE_ROOT / "attestations"
#: Default plugin allow-list — same file the production startup path
#: loads at portal lifespan (per ``core/config.plugin_allowlist_path``).
_DEFAULT_ALLOWLIST = _REPO_ROOT / "policies" / "_default" / "plugin_allowlist.json"


# ---------------------------------------------------------------------------
# Fixture-state validation (mirrors build_test_attestations.sh)
# ---------------------------------------------------------------------------


REQUIRED_FILES = (
    "sbom.cdx.json",
    "slsa-provenance.intoto.json",
    "intoto-layout.json",
    "vuln-scan.json",
    "license-audit.json",
    "cosign.sig",
    "bundle.sigstore",
)

JSON_ATTESTATIONS = (
    "sbom.cdx.json",
    "slsa-provenance.intoto.json",
    "intoto-layout.json",
    "vuln-scan.json",
    "license-audit.json",
)


class TestFixtureFilesPresent:
    @pytest.mark.parametrize("filename", REQUIRED_FILES)
    def test_required_attestation_present(self, filename: str) -> None:
        path = _ATTESTATIONS / filename
        assert path.is_file(), (
            f"T12 fixture missing required attestation file: {path}. "
            f"Run `bash tests/fixtures/_signing_kit/build_test_attestations.sh` "
            f"to revalidate; if regenerating, add --regenerate."
        )

    @pytest.mark.parametrize("filename", JSON_ATTESTATIONS)
    def test_json_attestation_parses(self, filename: str) -> None:
        path = _ATTESTATIONS / filename
        # Raises JSONDecodeError → test fails with the message.
        json.loads(path.read_text(encoding="utf-8"))


class TestFixturePackageInstallable:
    def test_pyproject_declares_entry_point(self) -> None:
        """The Sprint-4 plan calls for an installable test pack with
        a ``cognic.tools`` entry point. Parse the pyproject directly
        rather than installing — the install path is exercised by
        the optional ``uv pip install -e`` workflow documented in
        the plan."""
        # ``tomllib`` is stdlib on Python ≥ 3.11; project pins
        # requires-python ≥ 3.11 so no fallback needed.
        import tomllib

        pyproject = (_FIXTURE_ROOT / "pyproject.toml").read_bytes()
        data = tomllib.loads(pyproject.decode("utf-8"))
        assert data["project"]["name"] == "cognic-test-pack"
        entry_points = data["project"]["entry-points"]["cognic.tools"]
        # Entry-point alias != distribution name (T9 / T10 both key
        # off distribution name; this fixture exercises the divergence).
        assert "cognic_test_pack" in entry_points
        assert entry_points["cognic_test_pack"] == "cognic_test_pack.tool:Plugin"


# ---------------------------------------------------------------------------
# T10 admission against the fixture (with mocked cosign)
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    url = f"sqlite+aiosqlite:///{tmp_path / 't12.db'}"
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


@pytest.fixture
def supply_chain() -> SupplyChainPipeline:
    settings = build_settings_without_env_file().model_copy(
        update={"local_object_store_root": Path("/tmp/cognic-agentos-fixture")}
    )
    return SupplyChainPipeline(settings=settings)


def _fixture_pack() -> DiscoveredPack:
    """Construct a DiscoveredPack matching what
    ``PluginRegistry.discover()`` would produce after a real
    ``uv pip install -e tests/fixtures/cognic_test_pack/``.
    The entry-point alias (``cognic_test_pack``) is deliberately
    different from the distribution name (``cognic-test-pack``) so
    T10's pack_id-vs-name handling is exercised end-to-end."""
    record = PluginRecord(
        kind="tools",
        name="cognic_test_pack",
        distribution_name="cognic-test-pack",
        distribution_version="0.1.0",
        entry_point_value="cognic_test_pack.tool:Plugin",
    )
    # The ``EntryPoint`` field on ``DiscoveredPack`` is duck-typed at
    # runtime (T5 only invokes ``.load()`` from the explicit
    # ``PluginRegistry.load`` call site, never during admission). We
    # use a stub to keep T12 from depending on the fixture pack being
    # installed via ``uv pip install -e`` first.
    ep_stub = MagicMock()
    ep_stub.name = record.name
    ep_stub.value = record.entry_point_value
    ep_stub.load = MagicMock(side_effect=AssertionError("T12 admission MUST NOT load"))
    return DiscoveredPack(record=record, entry_point=ep_stub)


def _fixture_artefacts() -> PackAttestations:
    """Build a PackAttestations from the on-disk fixture files.
    SBOM-signed digest is computed live so the SHA-256 round-trip
    proves the fixture's SBOM body matches what the cosign signature
    would have pinned in production."""
    sbom_path = _ATTESTATIONS / "sbom.cdx.json"
    sbom_digest = hashlib.sha256(sbom_path.read_bytes()).hexdigest()
    return PackAttestations(
        cosign_signature_path=_ATTESTATIONS / "cosign.sig",
        cosign_blob_path=_ATTESTATIONS / "bundle.sigstore",  # placeholder blob
        cosign_trust_root=_ATTESTATIONS / "cosign.sig",  # placeholder; trust gate is mocked
        sbom_path=sbom_path,
        sbom_signed_digest=sbom_digest,
        sigstore_bundle_path=_ATTESTATIONS / "bundle.sigstore",
        slsa_provenance_path=_ATTESTATIONS / "slsa-provenance.intoto.json",
        intoto_layout_path=_ATTESTATIONS / "intoto-layout.json",
        vuln_scan_path=_ATTESTATIONS / "vuln-scan.json",
        license_audit_path=_ATTESTATIONS / "license-audit.json",
    )


def _mock_trust_gate() -> MagicMock:
    """T6 is exhaustively tested at the unit level (62 tests covering
    cosign subprocess / privacy / fail-closed). T12 mocks it so the
    fixture's bytes don't need to be signed by a real cosign run.
    The @pytest.mark.cosign_real path (separate file, env-gated)
    runs against real cosign."""
    mock = MagicMock()
    mock.verify_pack_signature = AsyncMock(
        return_value=CosignVerificationResult(
            verified=True,
            pack_id="cognic-test-pack",
            version="0.1.0",
            signature_digest="a" * 64,
        )
    )
    return mock


class TestFixtureAdmission:
    async def test_t10_admits_fixture_pack_at_full_grade(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
    ) -> None:
        """The fixture's complete attestation set MUST clear T10's
        admission pipeline at grade=full. If a verifier contract
        changes (new mandatory field, tightened regex), this test
        breaks BEFORE the @pytest.mark.cosign_real integration path
        runs and the fixture files get updated in the same commit."""
        outcome = await registry.register_with_full_attestation_check(
            _fixture_pack(),
            _fixture_artefacts(),
            trust_gate=_mock_trust_gate(),
            supply_chain=supply_chain,
            object_store=object_store,
            license_allowlist=("MIT",),
        )
        assert outcome.status == "registered"
        assert outcome.attestation_grade == "full"
        assert outcome.refusal_reason is None
        # pack_id is the SIGNED distribution identity, not the entry-
        # point alias. The fixture exercises this divergence so any
        # regression to ``record.name`` would fail here.
        assert outcome.pack_id == "cognic-test-pack"
        assert outcome.name == "cognic_test_pack"
        assert outcome.pack_id != outcome.name
        # Sigstore bundle persisted under the signed identity, NOT
        # the entry-point alias.
        bundle_key = f"attestations/{outcome.pack_id}/{outcome.version}/bundle.sigstore"
        retrieved = await object_store.get("cognic-attestations", bundle_key)
        assert retrieved == (_ATTESTATIONS / "bundle.sigstore").read_bytes()

    async def test_t10_admits_fixture_against_real_default_allowlist(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
    ) -> None:
        """R1 P2 regression — the default allow-list file at
        ``policies/_default/plugin_allowlist.json`` is what production
        startup loads (per ``core/config.plugin_allowlist_path``). T10
        step 1 keys the lookup off ``record.distribution_name``, so
        the file MUST list the signed distribution identity
        (``cognic-test-pack``), not the entry-point alias
        (``cognic_test_pack``). This test loads the real file from
        disk and admits the fixture against it — if a future edit
        regresses the keying, this fails BEFORE production startup
        refuses the fixture as ``not_in_tenant_allowlist``."""
        data = json.loads(_DEFAULT_ALLOWLIST.read_text(encoding="utf-8"))
        tenant_allowlist = frozenset(data["_default"])

        outcome = await registry.register_with_full_attestation_check(
            _fixture_pack(),
            _fixture_artefacts(),
            trust_gate=_mock_trust_gate(),
            supply_chain=supply_chain,
            object_store=object_store,
            tenant_allowlist=tenant_allowlist,
            license_allowlist=("MIT",),
        )
        assert outcome.status == "registered"
        assert outcome.refusal_reason is None
        assert outcome.pack_id == "cognic-test-pack"

    async def test_admission_does_not_load_fixture_module(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
    ) -> None:
        """The §1 deferred-load invariant — even with a real on-disk
        fixture pack, T10 admission MUST NOT call ``EntryPoint.load()``.
        The fixture's MagicMock entry-point raises AssertionError if
        load() is touched."""
        # If load() runs, the fixture's side_effect AssertionError
        # propagates and the test fails with a clear message.
        await registry.register_with_full_attestation_check(
            _fixture_pack(),
            _fixture_artefacts(),
            trust_gate=_mock_trust_gate(),
            supply_chain=supply_chain,
            object_store=object_store,
            license_allowlist=("MIT",),
        )
