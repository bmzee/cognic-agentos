"""Sprint 4 T10 — registry assembly integration tests.

End-to-end pack admission: discover → trust → SBOM → bundle-persist →
grace-period verifiers → policy → register. Per the user's T10
guardrails:

  > T10 is the real "system comes alive" step: it should connect
  > discovery, cosign verification, SBOM/SLSA/in-toto/vuln/license
  > checks, Sigstore bundle persistence, policy evaluation, and
  > final registry outcome. The biggest thing to watch is clean
  > refusal mapping: every failure should become the right closed
  > refusal_reason, with no pack load before trust succeeds.

Test design:

  * Real PluginRegistry + AuditStore (in-memory SQLite) — exercises
    the chain emission of T5.
  * Real SupplyChainPipeline + LocalObjectStoreAdapter — exercises
    the T7 pipeline + T9 persister + T4 retention sidecar
    end-to-end.
  * Mock TrustGate — T6's 62 tests already cover its subprocess /
    privacy / fail-closed contracts. Mocking here keeps T10 fast
    and lets us inject specific failure classes deterministically.
  * Mock OPAEngine — T2's tests already cover the OPA subprocess.
    Sprint-4 T10 also runs the local-fallback path when
    ``policy_engine`` is None; one test class covers each.

Test classes:

  * ``TestHappyPathFullGrade`` — every attestation present + clean
    → grade=full, registered.
  * ``TestHappyPathPartialGrade`` — SLSA absent (or below L3) →
    grade=partial, registered when require_full_grade=False.
  * ``TestRefusalEnumMapping`` — parametrized over EVERY closed
    refusal_reason in T5's enum. Each test forces the matching
    failure class and asserts the outcome's refusal_reason.
  * ``TestNoEagerLoad`` — the user's load-bearing guardrail:
    ``EntryPoint.load()`` is NEVER called during T10, regardless
    of outcome. A sentinel-flipping fake EntryPoint pins this.
  * ``TestPolicyEnginePath`` — explicit OPA-engine path (mocked)
    plus the local fallback path; both produce identical
    decisions for the (full, partial * require_full) cases.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.policy.engine import Decision
from cognic_agentos.db.adapters.local_object_store_adapter import (
    LocalObjectStoreAdapter,
)
from cognic_agentos.protocol.plugin_registry import (
    DiscoveredPack,
    PackAttestations,
    PluginRecord,
    PluginRegistry,
)
from cognic_agentos.protocol.supply_chain import (
    SupplyChainPipeline,
)
from cognic_agentos.protocol.trust_gate import (
    CosignVerificationFailed,
    CosignVerificationResult,
    PathTraversalError,
)

# ---------------------------------------------------------------------------
# Fixtures — registry, audit store, supply-chain pipeline, object store
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path):  # type: ignore[no-untyped-def]
    url = f"sqlite+aiosqlite:///{tmp_path / 't10.db'}"
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
        update={"local_object_store_root": Path("/tmp/cognic-agentos-supply-chain")}
    )
    return SupplyChainPipeline(settings=settings)


# ---------------------------------------------------------------------------
# Fake-EntryPoint helpers
# ---------------------------------------------------------------------------


class _FakeEntryPoint:
    """Records every ``load()`` invocation so ``TestNoEagerLoad`` can
    assert T10 never imports pack code (the §1 deferred-load
    invariant). Otherwise behaves like a real EntryPoint shape."""

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
    name: str = "demo-pack",
    distribution_name: str = "cognic-tool-demo",
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


# ---------------------------------------------------------------------------
# Attestation-fixture helpers — produce a complete on-disk attestation set.
# ---------------------------------------------------------------------------


def _write_attestation_files(
    tmp_path: Path,
    *,
    sbom_body: bytes | None = None,
    write_sbom: bool = True,
    slsa_present: bool = True,
    slsa_level: int = 3,
    slsa_overrides: dict[str, Any] | None = None,
    intoto_present: bool = True,
    intoto_overrides: dict[str, Any] | None = None,
    vuln_present: bool = True,
    vuln_matches: list[dict[str, Any]] | None = None,
    license_present: bool = True,
    license_list: list[str] | None = None,
    bundle_present: bool = True,
    bundle_body: bytes = b"sigstore-bundle-content",
) -> dict[str, Any]:
    """Lay out a complete attestation directory at ``tmp_path``.

    Returns a dict with all paths + the cosign-signed SBOM digest so
    tests can build a ``PackAttestations`` from it.
    """
    sbom_path = tmp_path / "sbom.cdx.json"
    sbom_bytes = sbom_body or b'{"bomFormat": "CycloneDX", "specVersion": "1.5"}'
    digest = ""
    if write_sbom:
        sbom_path.write_bytes(sbom_bytes)
        digest = hashlib.sha256(sbom_bytes).hexdigest()

    slsa_path = tmp_path / "slsa.json"
    if slsa_present:
        statement: dict[str, Any] = {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {
                "buildDefinition": {
                    "buildType": "https://github.com/actions/runner/v1",
                    "externalParameters": {"configSource": "git+https://example/v1"},
                },
                "runDetails": {"builder": {"id": "https://github.com/actions/runner"}},
                "slsaLevel": slsa_level,
            },
        }
        if slsa_overrides:
            for dotted, value in slsa_overrides.items():
                parts = dotted.split(".")
                cursor: Any = statement
                for part in parts[:-1]:
                    cursor = cursor[part]
                cursor[parts[-1]] = value
        slsa_path.write_text(json.dumps(statement))

    intoto_path = tmp_path / "layout.json"
    if intoto_present:
        layout: dict[str, Any] = {
            "_type": "https://in-toto.io/Layout/v1",
            "expires": "2027-01-01T00:00:00Z",
            "steps": [{"name": "build"}, {"name": "sign"}],
        }
        if intoto_overrides:
            for dotted, value in intoto_overrides.items():
                parts = dotted.split(".")
                cursor = layout
                for part in parts[:-1]:
                    cursor = cursor[part]
                cursor[parts[-1]] = value
        intoto_path.write_text(json.dumps(layout))

    vuln_path = tmp_path / "vuln.json"
    if vuln_present:
        vuln_path.write_text(json.dumps({"matches": vuln_matches or []}))

    license_path = tmp_path / "license.json"
    if license_present:
        license_path.write_text(json.dumps({"licenses": license_list or ["MIT", "Apache-2.0"]}))

    bundle_path = tmp_path / "bundle.sigstore"
    if bundle_present:
        bundle_path.write_bytes(bundle_body)

    # Cosign-input files (the trust gate's signature + blob inputs).
    # T10 tests use a mocked TrustGate so the file content is opaque
    # — we just need the paths to canonicalise under the trust gate's
    # configured signature_root_path.
    cosign_sig = tmp_path / "cosign.sig"
    cosign_sig.write_bytes(b"fake-sig")
    cosign_blob = tmp_path / "blob.whl"
    cosign_blob.write_bytes(b"fake-wheel")
    trust_root = tmp_path / "trust-root.pem"
    trust_root.write_bytes(b"fake-key")

    return {
        "sbom_path": sbom_path,
        "sbom_signed_digest": digest,
        "slsa_provenance_path": slsa_path if slsa_present else None,
        "intoto_layout_path": intoto_path if intoto_present else None,
        "vuln_scan_path": vuln_path if vuln_present else None,
        "license_audit_path": license_path if license_present else None,
        "bundle_path": bundle_path if bundle_present else tmp_path / "absent.sigstore",
        "cosign_signature_path": cosign_sig,
        "cosign_blob_path": cosign_blob,
        "cosign_trust_root": trust_root,
    }


def _to_artefacts(files: dict[str, Any]) -> PackAttestations:
    return PackAttestations(
        cosign_signature_path=files["cosign_signature_path"],
        cosign_blob_path=files["cosign_blob_path"],
        cosign_trust_root=files["cosign_trust_root"],
        sbom_path=files["sbom_path"],
        sbom_signed_digest=files["sbom_signed_digest"],
        sigstore_bundle_path=files["bundle_path"],
        slsa_provenance_path=files["slsa_provenance_path"],
        intoto_layout_path=files["intoto_layout_path"],
        vuln_scan_path=files["vuln_scan_path"],
        license_audit_path=files["license_audit_path"],
    )


def _make_trust_gate_mock(
    *,
    raises: BaseException | None = None,
    signature_digest: str = "sha256:" + "a" * 64,
) -> Any:
    """Mock TrustGate — verify_pack_signature either raises or returns
    a synthetic CosignVerificationResult. T6 already covers the real
    subprocess + privacy contracts; T10 only orchestrates."""
    mock = MagicMock()
    if raises is not None:
        mock.verify_pack_signature = AsyncMock(side_effect=raises)
    else:
        mock.verify_pack_signature = AsyncMock(
            return_value=CosignVerificationResult(
                verified=True,
                pack_id="pack",
                version="1.0.0",
                signature_digest=signature_digest.removeprefix("sha256:"),
            )
        )
    return mock


# ---------------------------------------------------------------------------
# TestHappyPathFullGrade
# ---------------------------------------------------------------------------


class TestHappyPathFullGrade:
    async def test_all_attestations_clean_registers_full(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        files = _write_attestation_files(tmp_path)
        artefacts = _to_artefacts(files)
        pack, ep = _make_pack()
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            license_allowlist=("MIT", "Apache-2.0"),
        )
        assert outcome.status == "registered"
        assert outcome.attestation_grade == "full"
        assert outcome.refusal_reason is None
        assert outcome.signature_digest == "a" * 64
        # No pack load happened during admission.
        assert ep.load_count == 0
        # R1 reviewer-P2 fix: the persisted bundle's key MUST match
        # ``outcome.pack_id`` (== ``record.distribution_name``), NOT
        # ``record.name`` (the entry-point alias). Examiners walking
        # /api/v1/system/plugins must find the bundle at the same
        # path the API reports.
        expected_key = (
            f"attestations/{outcome.pack_id}/{pack.record.distribution_version}/bundle.sigstore"
        )
        retrieved = await object_store.get("cognic-attestations", expected_key)
        assert retrieved == b"sigstore-bundle-content"
        # Belt-and-suspenders: the entry-point alias is a different
        # string here, so a regression to ``record.name`` would not
        # match this assertion.
        assert outcome.pack_id == pack.record.distribution_name
        assert pack.record.name != pack.record.distribution_name


# ---------------------------------------------------------------------------
# TestHappyPathPartialGrade
# ---------------------------------------------------------------------------


class TestHappyPathPartialGrade:
    async def test_slsa_l2_demotes_to_partial_default_tenant_allows(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        """Default tenant policy doesn't require_full_grade; a SLSA L2
        provenance demotes to partial but registers."""
        files = _write_attestation_files(tmp_path, slsa_level=2)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack(name="partial-l2")
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            license_allowlist=("MIT", "Apache-2.0"),
        )
        assert outcome.status == "registered"
        assert outcome.attestation_grade == "partial"

    async def test_slsa_absent_demotes_to_partial_default_tenant_allows(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        files = _write_attestation_files(tmp_path, slsa_present=False)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack(name="partial-no-slsa")
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            license_allowlist=("MIT", "Apache-2.0"),
        )
        assert outcome.status == "registered"
        assert outcome.attestation_grade == "partial"

    async def test_partial_with_require_full_refused_policy_denied(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        files = _write_attestation_files(tmp_path, slsa_level=2)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack(name="partial-strict")
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            require_full_grade=True,
            license_allowlist=("MIT", "Apache-2.0"),
        )
        assert outcome.status == "refused_at_registration"
        assert outcome.refusal_reason == "policy_denied_partial_grade"


# ---------------------------------------------------------------------------
# TestRefusalEnumMapping — every closed reason hit by the matching failure.
# ---------------------------------------------------------------------------


class TestRefusalEnumMapping:
    async def test_not_in_tenant_allowlist(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        """Tenant allow-list miss refuses BEFORE any cosign / SBOM /
        bundle work. The mock trust gate would fail loudly if called;
        we assert it wasn't."""
        files = _write_attestation_files(tmp_path)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack(name="unwanted-pack")
        trust_gate = _make_trust_gate_mock()
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=trust_gate,
            supply_chain=supply_chain,
            object_store=object_store,
            tenant_allowlist=frozenset({"some-other-distribution"}),
        )
        assert outcome.refusal_reason == "not_in_tenant_allowlist"
        trust_gate.verify_pack_signature.assert_not_called()

    async def test_allowlist_uses_distribution_name_not_entry_point_name(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        """R1 reviewer-P2 fix: a real allow-list entry for the SIGNED
        DISTRIBUTION (e.g. ``cognic-tool-demo``) must admit the pack,
        regardless of the entry-point alias (``demo-pack``). And the
        reverse: an allow-list of the entry-point alias must NOT
        admit when the distribution name is different. The allow-list
        gate keys off pack identity, not the entry-point name.
        """
        files = _write_attestation_files(tmp_path)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack(
            name="demo-pack",  # entry-point alias
            distribution_name="cognic-tool-demo",  # signed identity
        )
        # Allow-list of the DISTRIBUTION → admits.
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            tenant_allowlist=frozenset({"cognic-tool-demo"}),
            license_allowlist=("MIT", "Apache-2.0"),
        )
        assert outcome.status == "registered"

    async def test_allowlist_with_only_entry_point_name_refuses(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        """R1 reviewer-P2 fix: counterpart — allow-list with only the
        entry-point alias (NOT the distribution) refuses. Without the
        fix, an attacker could craft a malicious distribution whose
        entry-point name matched a legitimate pack's alias and slip
        through allow-list enforcement."""
        files = _write_attestation_files(tmp_path)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack(
            name="demo-pack",
            distribution_name="cognic-tool-impostor",
        )
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            # Only the entry-point alias is on the list — distribution
            # is not.
            tenant_allowlist=frozenset({"demo-pack"}),
        )
        assert outcome.refusal_reason == "not_in_tenant_allowlist"

    async def test_cosign_verification_failed(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        files = _write_attestation_files(tmp_path)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack()
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(raises=CosignVerificationFailed("cosign refused")),
            supply_chain=supply_chain,
            object_store=object_store,
        )
        assert outcome.refusal_reason == "cosign_verification_failed"

    async def test_cosign_path_traversal_also_maps_to_cosign_verification_failed(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        """Any TrustGateError subclass — including PathTraversalError
        — collapses to the single closed-enum cosign reason."""
        files = _write_attestation_files(tmp_path)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack()
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(raises=PathTraversalError("path outside root")),
            supply_chain=supply_chain,
            object_store=object_store,
        )
        assert outcome.refusal_reason == "cosign_verification_failed"

    async def test_sbom_missing(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        files = _write_attestation_files(tmp_path, write_sbom=False)
        # Patch in a non-empty digest so SBOMTampered doesn't fire on
        # empty-string validation; the missing-file check fires first.
        files["sbom_signed_digest"] = "sha256:" + "a" * 64
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack()
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
        )
        assert outcome.refusal_reason == "sbom_missing"

    async def test_sbom_tampered(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        files = _write_attestation_files(tmp_path)
        # Force a digest mismatch.
        files["sbom_signed_digest"] = hashlib.sha256(b"different").hexdigest()
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack()
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
        )
        assert outcome.refusal_reason == "sbom_tampered"

    async def test_slsa_tampered(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        files = _write_attestation_files(
            tmp_path,
            slsa_overrides={"predicate.buildDefinition.buildType": ""},
        )
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack()
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
        )
        assert outcome.refusal_reason == "slsa_tampered"

    async def test_intoto_tampered(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        files = _write_attestation_files(
            tmp_path,
            intoto_overrides={"steps": [123, "non-dict-entry"]},
        )
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack()
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
        )
        assert outcome.refusal_reason == "intoto_tampered"

    async def test_sigstore_bundle_persistence_failed_file_missing(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        files = _write_attestation_files(tmp_path, bundle_present=False)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack()
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
        )
        assert outcome.refusal_reason == "sigstore_bundle_persistence_failed"

    async def test_sigstore_bundle_persistence_failed_adapter_oserror(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Adapter put() raises OSError mid-write → T9 wraps as
        SigstoreBundlePersistenceFailed → T10 maps to the closed
        reason."""
        files = _write_attestation_files(tmp_path)
        artefacts = _to_artefacts(files)

        async def _failing_put(self: Any, *args: Any, **kwargs: Any) -> None:
            raise OSError(28, "ENOSPC")

        monkeypatch.setattr(LocalObjectStoreAdapter, "put", _failing_put)
        pack, _ = _make_pack(name="bundle-fail")
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
        )
        assert outcome.refusal_reason == "sigstore_bundle_persistence_failed"

    async def test_policy_denied_partial_grade_local_fallback(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        """Already covered in TestHappyPathPartialGrade; included here
        so the parametrized enum-completeness check finds every
        closed reason."""
        files = _write_attestation_files(tmp_path, slsa_present=False)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack(name="strict-tenant")
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            require_full_grade=True,
            license_allowlist=("MIT", "Apache-2.0"),
        )
        assert outcome.refusal_reason == "policy_denied_partial_grade"


# ---------------------------------------------------------------------------
# TestNoEagerLoad — the user's load-bearing guardrail.
# ---------------------------------------------------------------------------


class TestNoEagerLoad:
    async def test_load_never_called_on_success_path(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        files = _write_attestation_files(tmp_path)
        artefacts = _to_artefacts(files)
        pack, ep = _make_pack(name="no-load-success")
        await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            license_allowlist=("MIT", "Apache-2.0"),
        )
        assert ep.load_count == 0, (
            "EntryPoint.load() was called during T10 admission — "
            "violates the §1 deferred-load invariant. The trust gate "
            "must finish before any pack code is imported."
        )

    @pytest.mark.parametrize(
        "failure_class",
        [
            "cosign_verification_failed",
            "sbom_missing",
            "sbom_tampered",
            "slsa_tampered",
            "intoto_tampered",
            "sigstore_bundle_persistence_failed",
        ],
    )
    async def test_load_never_called_on_refusal_paths(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
        failure_class: str,
    ) -> None:
        """For EVERY refusal path, EntryPoint.load() must stay
        un-called — the user's load-bearing guardrail."""
        # Compose the file set + trust-gate stub for the chosen
        # failure class.
        if failure_class == "cosign_verification_failed":
            files = _write_attestation_files(tmp_path)
            trust_gate = _make_trust_gate_mock(raises=CosignVerificationFailed("refused"))
        elif failure_class == "sbom_missing":
            files = _write_attestation_files(tmp_path, write_sbom=False)
            files["sbom_signed_digest"] = "sha256:" + "a" * 64
            trust_gate = _make_trust_gate_mock()
        elif failure_class == "sbom_tampered":
            files = _write_attestation_files(tmp_path)
            files["sbom_signed_digest"] = hashlib.sha256(b"different").hexdigest()
            trust_gate = _make_trust_gate_mock()
        elif failure_class == "slsa_tampered":
            files = _write_attestation_files(
                tmp_path,
                slsa_overrides={"predicate.buildDefinition.buildType": ""},
            )
            trust_gate = _make_trust_gate_mock()
        elif failure_class == "intoto_tampered":
            files = _write_attestation_files(tmp_path, intoto_overrides={"steps": [123]})
            trust_gate = _make_trust_gate_mock()
        else:  # sigstore_bundle_persistence_failed
            files = _write_attestation_files(tmp_path, bundle_present=False)
            trust_gate = _make_trust_gate_mock()
        artefacts = _to_artefacts(files)
        pack, ep = _make_pack(name=f"refuse-{failure_class}")
        await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=trust_gate,
            supply_chain=supply_chain,
            object_store=object_store,
        )
        assert ep.load_count == 0


# ---------------------------------------------------------------------------
# TestPolicyEnginePath — explicit OPA engine invocation + local fallback.
# ---------------------------------------------------------------------------


class TestPolicyEnginePath:
    async def test_explicit_opa_engine_called_for_partial_grade(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        """When ``policy_engine`` is supplied, T10 calls
        ``evaluate(decision_point='data.cognic.supply_chain.allow',
        input={attestation_grade, tenant_policy.require_full})``
        instead of the local fallback."""
        files = _write_attestation_files(tmp_path, slsa_level=2)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack(name="opa-partial")

        policy_engine = MagicMock()
        policy_engine.evaluate = AsyncMock(
            return_value=Decision(
                allow=True,
                rule_matched="data.cognic.supply_chain.allow",
                reasoning="partial grade allowed",
                decision_data=None,
            )
        )

        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            policy_engine=policy_engine,
            license_allowlist=("MIT", "Apache-2.0"),
        )
        assert outcome.status == "registered"
        assert outcome.attestation_grade == "partial"
        # OPA engine WAS called, with the documented input shape.
        policy_engine.evaluate.assert_called_once()
        kwargs = policy_engine.evaluate.call_args.kwargs
        assert kwargs["decision_point"] == "data.cognic.supply_chain.allow"
        assert kwargs["input"]["attestation_grade"] == "partial"
        assert kwargs["input"]["tenant_policy"]["require_full"] is False

    async def test_explicit_opa_engine_deny_refuses(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        files = _write_attestation_files(tmp_path, slsa_level=2)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack(name="opa-deny")
        policy_engine = MagicMock()
        policy_engine.evaluate = AsyncMock(
            return_value=Decision(
                allow=False,
                rule_matched="data.cognic.supply_chain.allow",
                reasoning="tenant requires full",
                decision_data=None,
            )
        )
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            policy_engine=policy_engine,
            license_allowlist=("MIT", "Apache-2.0"),
        )
        assert outcome.refusal_reason == "policy_denied_partial_grade"

    async def test_policy_engine_exception_maps_to_policy_denied(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        """R1 reviewer-P2 fix: any exception from the policy engine's
        ``evaluate()`` (T2's ``OpaNotInstalledError`` /
        ``RegoEvaluationError`` / unexpected ``RuntimeError``) MUST
        produce a closed-enum refusal_reason — NOT propagate up and
        leave T10 with no RegistrationOutcome / no audit row.
        Per the user's contract: every failure becomes a closed
        refusal_reason.

        Sprint 4 reuses ``policy_denied_partial_grade`` rather than
        extending the closed enum; the operator-facing semantics are
        the same (pack refused on policy grounds).
        """
        files = _write_attestation_files(tmp_path, slsa_level=2)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack(name="opa-error")
        policy_engine = MagicMock()
        policy_engine.evaluate = AsyncMock(side_effect=RuntimeError("OPA subprocess crashed"))
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            policy_engine=policy_engine,
            license_allowlist=("MIT", "Apache-2.0"),
        )
        # Closed-enum refusal, not a raw RuntimeError.
        assert outcome.status == "refused_at_registration"
        assert outcome.refusal_reason == "policy_denied_partial_grade"
        # Engine WAS called.
        policy_engine.evaluate.assert_called_once()

    async def test_policy_engine_exception_only_demotes_partial(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        """When a ``policy_engine`` is supplied, ``_admit_grade``
        consults it for EVERY grade (full and partial) — so an engine
        error fails closed even on a full-grade pack. Operators who
        want full-grade-bypass-engine can opt out by passing
        ``policy_engine=None``; the local fallback then admits
        full-grade unconditionally.
        """
        files = _write_attestation_files(tmp_path)  # full grade
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack(name="opa-error-full")
        policy_engine = MagicMock()
        policy_engine.evaluate = AsyncMock(side_effect=RuntimeError("OPA subprocess crashed"))
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            policy_engine=policy_engine,
            license_allowlist=("MIT", "Apache-2.0"),
        )
        # Even full-grade fails closed when the engine errors —
        # T10's design treats the engine as a hard gate when supplied.
        assert outcome.refusal_reason == "policy_denied_partial_grade"

    async def test_local_fallback_full_grade_always_admits(
        self,
        registry: PluginRegistry,
        supply_chain: SupplyChainPipeline,
        object_store: LocalObjectStoreAdapter,
        tmp_path: Path,
    ) -> None:
        """No policy_engine + full grade → local fallback admits."""
        files = _write_attestation_files(tmp_path)
        artefacts = _to_artefacts(files)
        pack, _ = _make_pack(name="fallback-full")
        outcome = await registry.register_with_full_attestation_check(
            pack,
            artefacts,
            trust_gate=_make_trust_gate_mock(),
            supply_chain=supply_chain,
            object_store=object_store,
            policy_engine=None,
            license_allowlist=("MIT", "Apache-2.0"),
        )
        assert outcome.attestation_grade == "full"


# ---------------------------------------------------------------------------
# TestEnumCompleteness — every closed reason has at least one test arm.
# ---------------------------------------------------------------------------


class TestEnumCompleteness:
    """Lock the closed-enum coverage contract: every value in T5's
    ``RefusalReason`` Literal MUST be exercised by at least one test
    arm. The Sprint-4 plan explicitly calls out enum extension as a
    4-step change requiring a new test arm — this self-test catches
    anyone adding a refusal reason without a test.

    Cross-sprint scope (Sprint-5 T6 amendment): Sprint-4 reasons are
    covered by tests in THIS file (TestRefusalEnumMapping). Sprint-5
    additions (manifest extraction + capability validator + auth
    probe + registry configuration — **24 values** after T6 R1
    grew the count 22 → 24 with ``mcp_transport_unsupported`` and
    ``mcp_admission_deps_required``) are covered by:

      - ``tests/unit/protocol/test_mcp_capabilities.py`` (**10
        capability reasons** — original 9 plus
        ``mcp_transport_unsupported`` from T6 R1 P1 #2; one test
        class per reason).
      - ``tests/unit/protocol/test_mcp_registration_auth_probe.py``
        (11 auth-probe reasons + 2 manifest-extraction reasons +
        1 registry-configuration reason
        ``mcp_admission_deps_required`` from T6 R1 P1 #1; one test
        class per reason).
      - ``tests/unit/protocol/test_refusal_reason_completeness.py``
        (cross-cutting drift detector that walks the whole
        Sprint-5 vocabulary; the load-bearing regression).

    This file's test pins the union — accepting that the Sprint-5
    reasons are tested in their dedicated files. If a Sprint-5 reason
    is added to the Literal but missing from the Sprint-5 drift
    detector, ``test_refusal_reason_completeness.py`` catches it
    first.
    """

    def test_every_refusal_reason_has_a_test(self) -> None:
        from cognic_agentos.protocol.plugin_registry import _VALID_REFUSAL_REASONS

        # Sprint 4 — each reason covered by a TestRefusalEnumMapping arm
        # in this file.
        covered_sprint_4 = {
            "not_in_tenant_allowlist",
            "cosign_verification_failed",
            "sbom_missing",
            "sbom_tampered",
            "slsa_tampered",
            "intoto_tampered",
            "sigstore_bundle_persistence_failed",
            "policy_denied_partial_grade",
        }
        # Sprint 5 — covered by dedicated test files (see class
        # docstring). Listed explicitly so adding a NEW Sprint-5
        # reason without updating one of those files surfaces here too.
        covered_sprint_5 = {
            # T6.1 manifest extraction (2)
            "mcp_manifest_missing",
            "mcp_manifest_malformed",
            # T6.2 capability validator (12 — T15 R1 P2 #6 added
            # mcp_http_manifest_shape_invalid; T15 R2 P2 added
            # mcp_tool_data_classes_shape_invalid)
            "mcp_anonymous_refused",
            "mcp_resources_declared_but_no_list",
            "mcp_sampling_default_denied",
            "mcp_elicitation_form_restricted_data_class",
            "mcp_caching_ttl_restricted_data_class",
            "mcp_stdio_manifest_incomplete",
            "mcp_stdio_manifest_shell_metacharacter",
            "mcp_stdio_command_not_allowlisted",
            "mcp_stdio_disabled_in_sprint_5",
            "mcp_transport_unsupported",  # R1 P1 #2
            "mcp_http_manifest_shape_invalid",  # T15 R1 P2 #6
            "mcp_tool_data_classes_shape_invalid",  # T15 R2 P2
            # T6.3 registration auth probe (11)
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
            "mcp_api_key_fallback_unresolved",
            # T6.3 registry configuration (1)
            "mcp_admission_deps_required",  # R1 P1 #1
        }
        covered = covered_sprint_4 | covered_sprint_5
        assert covered == _VALID_REFUSAL_REASONS, (
            f"closed-enum coverage gap. Missing: "
            f"{_VALID_REFUSAL_REASONS - covered}; "
            f"unexpected: {covered - _VALID_REFUSAL_REASONS}"
        )
