"""Sprint 3 (ADR-002 + ADR-016) — startup plugin-registry boot-builder tests.

Exercises ``harness/registry_boot.build_and_populate_registry``: the off-gate
composition seam that discovers installed packs, resolves each pack's signed
attestations, and runs the full trust pipeline — returning ONE populated
``PluginRegistry``.

Design (mirrors ``tests/unit/protocol/test_registry_integration.py``):

  * A REAL in-memory ``PluginRegistry`` (the builder constructs its own, so the
    two collaborator methods it calls — ``discover`` /
    ``register_with_full_attestation_check`` — are monkeypatched at the CLASS
    level; a Mock set as a class attribute is NOT a descriptor, so it records
    calls WITHOUT ``self``).
  * The module-level ``resolve_pack_attestations`` is monkeypatched in the
    builder's namespace so we can capture the threaded roots and inject
    per-pack failures.
  * Real ``TrustGate`` (the builder constructs it — construction needs NO cosign
    binary; the missing-binary error is deferred to ``verify_pack_signature``),
    real ``SupplyChainPipeline`` / ``LocalObjectStoreAdapter`` / ``AuditStore``
    (never exercised because register is stubbed, but constructed honestly).
"""

from __future__ import annotations

import datetime as _dt
import importlib.metadata as _im
import json
import logging
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from cognic_agentos.core.audit import AuditStore, _audit_event, _chain_heads
from cognic_agentos.core.canonical import ZERO_HASH
from cognic_agentos.core.config import Settings, build_settings_without_env_file
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter
from cognic_agentos.harness.registry_boot import (
    RegistryBootError,
    build_and_populate_registry,
)
from cognic_agentos.protocol.mcp_authz import Token
from cognic_agentos.protocol.pack_attestation_resolver import (
    PackAttestationResolutionError,
)
from cognic_agentos.protocol.plugin_registry import (
    DiscoveredPack,
    MCPAdmissionDeps,
    PackAttestations,
    PluginRecord,
    PluginRegistry,
)
from cognic_agentos.protocol.supply_chain import AttestationResult, SupplyChainPipeline
from cognic_agentos.protocol.trust_gate import CosignVerificationResult, TrustGate

#: The real production allow-list ships ``{"_default": ["cognic-test-pack"]}``;
#: the happy-path tests load it via an ABSOLUTE path (hermetic + real-file).
_REPO_ROOT = Path(__file__).resolve().parents[3]
_REAL_ALLOWLIST = _REPO_ROOT / "policies" / "_default" / "plugin_allowlist.json"

_BOOT_MODULE = "cognic_agentos.harness.registry_boot"


# --------------------------------------------------------------------------- #
# Builders / fixtures
# --------------------------------------------------------------------------- #


def _make_discovered_pack(*, name: str, distribution_name: str) -> DiscoveredPack:
    """A discovered pack with a real (never-loaded) EntryPoint. The builder
    never inspects ``entry_point``; the stubs differentiate packs by
    ``distribution_name``."""
    record = PluginRecord(
        kind="tools",
        name=name,
        distribution_name=distribution_name,
        distribution_version="1.0.0",
        entry_point_value=f"{name}:Plugin",
    )
    entry_point = _im.EntryPoint(name=name, value=f"{name}:Plugin", group="cognic.tools")
    return DiscoveredPack(record=record, entry_point=entry_point)


def _stub_attestations(cosign_trust_root: Path) -> PackAttestations:
    """A shape-valid ``PackAttestations`` — register is stubbed, so the paths
    are never read; only ``cosign_trust_root`` threading is asserted."""
    return PackAttestations(
        cosign_signature_path=Path("/nonexistent/cosign.sig"),
        cosign_blob_path=Path("/nonexistent/pack-1.0.0.whl"),
        cosign_trust_root=cosign_trust_root,
        sbom_path=Path("/nonexistent/sbom.cdx.json"),
        sbom_signed_digest="deadbeef",
        sigstore_bundle_path=Path("/nonexistent/bundle.sigstore"),
    )


def _write_cosign_pub(trust_root_prefix: Path) -> Path:
    """Create a non-empty ``<prefix>/_default/cosign.pub`` and return its path."""
    default_dir = trust_root_prefix / "_default"
    default_dir.mkdir(parents=True, exist_ok=True)
    cosign_pub = default_dir / "cosign.pub"
    cosign_pub.write_text("-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----\n")
    return cosign_pub


def _make_settings(
    *,
    pack_attestation_root_path: str | None,
    trust_root_prefix: Path,
    plugin_allowlist_path: Path,
) -> Settings:
    return build_settings_without_env_file().model_copy(
        update={
            "pack_attestation_root_path": pack_attestation_root_path,
            "trust_root_prefix": trust_root_prefix,
            "plugin_allowlist_path": plugin_allowlist_path,
        }
    )


@pytest.fixture
async def _engine(tmp_path: Path) -> AsyncIterator[AsyncEngine]:
    # register is stubbed in every test → AuditStore.append is never called, so
    # no tables / chain-head row are needed; the store is constructed honestly.
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'boot.db'}")
    yield engine
    await engine.dispose()


@pytest.fixture
def audit_store(_engine: AsyncEngine) -> AuditStore:
    return AuditStore(_engine)


@pytest.fixture
def supply_chain() -> SupplyChainPipeline:
    return SupplyChainPipeline(settings=build_settings_without_env_file())


@pytest.fixture
def object_store(tmp_path: Path) -> LocalObjectStoreAdapter:
    root = tmp_path / "object-store"
    root.mkdir()
    return LocalObjectStoreAdapter(root)


def _install_registry_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    discovered: list[DiscoveredPack],
    register_spy: AsyncMock,
) -> None:
    """Patch the two collaborator methods on the REAL ``PluginRegistry`` class so
    the builder's internally-constructed instance uses them. ``discover`` is a
    plain function (descriptor → bound, receives ``self``); ``register_*`` is an
    AsyncMock (non-descriptor → records calls WITHOUT ``self``)."""
    monkeypatch.setattr(PluginRegistry, "discover", lambda self: list(discovered), raising=True)
    monkeypatch.setattr(
        PluginRegistry,
        "register_with_full_attestation_check",
        register_spy,
        raising=True,
    )


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


async def test_boot_discovers_resolves_full_registers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_store: AuditStore,
    supply_chain: SupplyChainPipeline,
    object_store: LocalObjectStoreAdapter,
) -> None:
    trust_root_prefix = tmp_path / "trust-roots"
    _write_cosign_pub(trust_root_prefix)
    settings = _make_settings(
        pack_attestation_root_path=str(tmp_path / "attestations"),
        trust_root_prefix=trust_root_prefix,
        plugin_allowlist_path=_REAL_ALLOWLIST,
    )
    packs = [
        _make_discovered_pack(name="pack_one", distribution_name="pack-one"),
        _make_discovered_pack(name="pack_two", distribution_name="pack-two"),
    ]
    register_spy = AsyncMock()
    _install_registry_stubs(monkeypatch, discovered=packs, register_spy=register_spy)
    produced: list[PackAttestations] = []

    def _resolve(
        pack: DiscoveredPack, *, pack_attestation_root: Path, cosign_trust_root: Path
    ) -> PackAttestations:
        attestations = _stub_attestations(cosign_trust_root)
        produced.append(attestations)
        return attestations

    monkeypatch.setattr(f"{_BOOT_MODULE}.resolve_pack_attestations", _resolve)

    registry = await build_and_populate_registry(
        settings=settings,
        audit_store=audit_store,
        supply_chain=supply_chain,
        object_store=object_store,
    )

    assert isinstance(registry, PluginRegistry)
    assert register_spy.call_count == 2
    calls = register_spy.call_args_list
    for call in calls:
        assert call.kwargs["tenant_id"] == "_default"
        assert call.kwargs["tenant_allowlist"] == frozenset({"cognic-test-pack"})
        assert call.kwargs["tenant_allowlist"] is not None
        assert isinstance(call.kwargs["trust_gate"], TrustGate)
    # The SAME boot-built trust gate threads into every register call.
    assert calls[0].kwargs["trust_gate"] is calls[1].kwargs["trust_gate"]
    # The attestations returned by resolve are the exact object handed to register.
    assert len(produced) == 2
    for register_call, attestations in zip(calls, produced, strict=True):
        assert register_call.args[1] is attestations


async def test_registration_trust_gate_signature_root_is_attestation_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_store: AuditStore,
    supply_chain: SupplyChainPipeline,
    object_store: LocalObjectStoreAdapter,
) -> None:
    attestation_root = str(tmp_path / "attestations")
    trust_root_prefix = tmp_path / "trust-roots"
    _write_cosign_pub(trust_root_prefix)
    settings = _make_settings(
        pack_attestation_root_path=attestation_root,
        trust_root_prefix=trust_root_prefix,
        plugin_allowlist_path=_REAL_ALLOWLIST,
    )
    register_spy = AsyncMock()
    _install_registry_stubs(
        monkeypatch,
        discovered=[_make_discovered_pack(name="p", distribution_name="pack-one")],
        register_spy=register_spy,
    )
    monkeypatch.setattr(
        f"{_BOOT_MODULE}.resolve_pack_attestations",
        lambda pack, *, pack_attestation_root, cosign_trust_root: _stub_attestations(
            cosign_trust_root
        ),
    )

    await build_and_populate_registry(
        settings=settings,
        audit_store=audit_store,
        supply_chain=supply_chain,
        object_store=object_store,
    )

    trust_gate = register_spy.call_args.kwargs["trust_gate"]
    assert isinstance(trust_gate, TrustGate)
    # The override the boot applied: signature_root_path is pinned to the
    # attestation root so verify_pack_signature canonicalises the resolver's
    # sig+wheel under the SAME root the resolver located them under.
    assert trust_gate._settings.signature_root_path == Path(attestation_root)
    # And the builder must NOT mutate the caller's Settings in place.
    assert settings.signature_root_path != Path(attestation_root)


async def test_cosign_trust_root_is_default_cosign_pub_under_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_store: AuditStore,
    supply_chain: SupplyChainPipeline,
    object_store: LocalObjectStoreAdapter,
) -> None:
    trust_root_prefix = tmp_path / "trust-roots"
    _write_cosign_pub(trust_root_prefix)
    settings = _make_settings(
        pack_attestation_root_path=str(tmp_path / "attestations"),
        trust_root_prefix=trust_root_prefix,
        plugin_allowlist_path=_REAL_ALLOWLIST,
    )
    register_spy = AsyncMock()
    _install_registry_stubs(
        monkeypatch,
        discovered=[_make_discovered_pack(name="p", distribution_name="pack-one")],
        register_spy=register_spy,
    )
    resolve_mock = MagicMock(
        side_effect=lambda pack, *, pack_attestation_root, cosign_trust_root: _stub_attestations(
            cosign_trust_root
        )
    )
    monkeypatch.setattr(f"{_BOOT_MODULE}.resolve_pack_attestations", resolve_mock)

    await build_and_populate_registry(
        settings=settings,
        audit_store=audit_store,
        supply_chain=supply_chain,
        object_store=object_store,
    )

    expected = trust_root_prefix / "_default" / "cosign.pub"
    # Threaded identically into resolve AND register (the LOCKED convention).
    assert resolve_mock.call_args.kwargs["cosign_trust_root"] == expected
    assert resolve_mock.call_args.kwargs["pack_attestation_root"] == tmp_path / "attestations"


async def test_bare_no_packs_returns_empty_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_store: AuditStore,
    supply_chain: SupplyChainPipeline,
    object_store: LocalObjectStoreAdapter,
) -> None:
    trust_root_prefix = tmp_path / "trust-roots"
    _write_cosign_pub(trust_root_prefix)
    settings = _make_settings(
        pack_attestation_root_path=str(tmp_path / "attestations"),
        trust_root_prefix=trust_root_prefix,
        plugin_allowlist_path=_REAL_ALLOWLIST,
    )
    register_spy = AsyncMock()
    _install_registry_stubs(monkeypatch, discovered=[], register_spy=register_spy)
    monkeypatch.setattr(
        f"{_BOOT_MODULE}.resolve_pack_attestations",
        MagicMock(side_effect=AssertionError("resolve must not run with zero packs")),
    )

    registry = await build_and_populate_registry(
        settings=settings,
        audit_store=audit_store,
        supply_chain=supply_chain,
        object_store=object_store,
    )

    assert isinstance(registry, PluginRegistry)
    assert registry.known_packs() == []
    assert register_spy.call_count == 0


# --------------------------------------------------------------------------- #
# Unset attestation root → benign empty registry
# --------------------------------------------------------------------------- #


async def test_unset_attestation_root_returns_empty_registry_logged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    audit_store: AuditStore,
    supply_chain: SupplyChainPipeline,
    object_store: LocalObjectStoreAdapter,
) -> None:
    settings = _make_settings(
        pack_attestation_root_path=None,
        trust_root_prefix=tmp_path / "trust-roots",  # no cosign.pub created
        plugin_allowlist_path=_REAL_ALLOWLIST,
    )
    register_spy = AsyncMock()
    _install_registry_stubs(monkeypatch, discovered=[], register_spy=register_spy)
    # If the builder ever reached the discover loop, this would raise.
    monkeypatch.setattr(
        f"{_BOOT_MODULE}.resolve_pack_attestations",
        MagicMock(side_effect=AssertionError("resolve must not run on unset root")),
    )

    with caplog.at_level(logging.WARNING, logger=_BOOT_MODULE):
        registry = await build_and_populate_registry(
            settings=settings,
            audit_store=audit_store,
            supply_chain=supply_chain,
            object_store=object_store,
        )

    assert isinstance(registry, PluginRegistry)  # a real (empty) registry, NOT None
    assert registry.known_packs() == []
    assert register_spy.call_count == 0
    assert any(
        "pack_attestation_root_unconfigured" in record.getMessage() for record in caplog.records
    )


# --------------------------------------------------------------------------- #
# Fail-closed: cosign trust root + allow-list
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("scenario", "expected_reason"),
    [
        ("missing", "cosign_trust_root_missing"),
        ("directory", "cosign_trust_root_not_a_file"),
        ("empty", "cosign_trust_root_empty"),
    ],
)
async def test_missing_default_trust_root_raises_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_store: AuditStore,
    supply_chain: SupplyChainPipeline,
    object_store: LocalObjectStoreAdapter,
    scenario: str,
    expected_reason: str,
) -> None:
    trust_root_prefix = tmp_path / "trust-roots"
    cosign_pub = trust_root_prefix / "_default" / "cosign.pub"
    if scenario == "missing":
        pass  # never create it
    elif scenario == "directory":
        cosign_pub.mkdir(parents=True)  # a dir where a file is expected
    elif scenario == "empty":
        cosign_pub.parent.mkdir(parents=True)
        cosign_pub.touch()  # zero-byte
    settings = _make_settings(
        pack_attestation_root_path=str(tmp_path / "attestations"),
        trust_root_prefix=trust_root_prefix,
        plugin_allowlist_path=_REAL_ALLOWLIST,
    )
    register_spy = AsyncMock()
    _install_registry_stubs(monkeypatch, discovered=[], register_spy=register_spy)

    with pytest.raises(RegistryBootError) as excinfo:
        await build_and_populate_registry(
            settings=settings,
            audit_store=audit_store,
            supply_chain=supply_chain,
            object_store=object_store,
        )

    assert excinfo.value.reason == expected_reason
    assert register_spy.call_count == 0  # never reached the discover loop


@pytest.mark.parametrize(
    ("payload", "expected_reason"),
    [
        (None, "tenant_allowlist_unreadable"),  # missing file
        ("{ not json", "tenant_allowlist_malformed"),  # invalid JSON
        ('["not", "an", "object"]', "tenant_allowlist_malformed"),  # top-level non-object
        ('{"bank_a": ["x"]}', "tenant_allowlist_default_key_missing"),  # no _default
        ('{"_default": "cognic-test-pack"}', "tenant_allowlist_malformed"),  # not a list
        ('{"_default": ["ok", 123]}', "tenant_allowlist_malformed"),  # non-string entry
    ],
)
async def test_allowlist_missing_or_malformed_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_store: AuditStore,
    supply_chain: SupplyChainPipeline,
    object_store: LocalObjectStoreAdapter,
    payload: str | None,
    expected_reason: str,
) -> None:
    trust_root_prefix = tmp_path / "trust-roots"
    _write_cosign_pub(trust_root_prefix)  # cosign root is VALID — isolate the allow-list
    allowlist_path = tmp_path / "allowlist.json"
    if payload is not None:
        allowlist_path.write_text(payload)
    settings = _make_settings(
        pack_attestation_root_path=str(tmp_path / "attestations"),
        trust_root_prefix=trust_root_prefix,
        plugin_allowlist_path=allowlist_path,
    )
    register_spy = AsyncMock()
    _install_registry_stubs(monkeypatch, discovered=[], register_spy=register_spy)

    with pytest.raises(RegistryBootError) as excinfo:
        await build_and_populate_registry(
            settings=settings,
            audit_store=audit_store,
            supply_chain=supply_chain,
            object_store=object_store,
        )

    assert excinfo.value.reason == expected_reason
    # Fail-closed: NO register call slipped through with tenant_allowlist=None.
    assert register_spy.call_count == 0


def test_allowlist_loader_empty_default_is_frozenset_not_none(tmp_path: Path) -> None:
    """Belt-and-braces: a present-but-empty ``_default`` is accept-no-packs
    (``frozenset()``), NEVER ``None`` — ``None`` would silently disable
    allow-list enforcement in ``register_with_full_attestation_check``."""
    from cognic_agentos.harness.registry_boot import _load_default_tenant_allowlist

    allowlist_path = tmp_path / "empty-default.json"
    allowlist_path.write_text(json.dumps({"_default": []}))

    result = _load_default_tenant_allowlist(allowlist_path)

    assert result == frozenset()
    assert result is not None


# --------------------------------------------------------------------------- #
# Per-pack fail-soft
# --------------------------------------------------------------------------- #


async def test_per_pack_resolution_failure_is_fail_soft(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    audit_store: AuditStore,
    supply_chain: SupplyChainPipeline,
    object_store: LocalObjectStoreAdapter,
) -> None:
    trust_root_prefix = tmp_path / "trust-roots"
    _write_cosign_pub(trust_root_prefix)
    settings = _make_settings(
        pack_attestation_root_path=str(tmp_path / "attestations"),
        trust_root_prefix=trust_root_prefix,
        plugin_allowlist_path=_REAL_ALLOWLIST,
    )
    packs = [
        _make_discovered_pack(name="bad", distribution_name="pack-one"),
        _make_discovered_pack(name="good", distribution_name="pack-two"),
    ]
    register_spy = AsyncMock()
    _install_registry_stubs(monkeypatch, discovered=packs, register_spy=register_spy)

    def _resolve(
        pack: DiscoveredPack, *, pack_attestation_root: Path, cosign_trust_root: Path
    ) -> PackAttestations:
        if pack.record.distribution_name == "pack-one":
            raise PackAttestationResolutionError(
                "attestation_required_artefact_missing", "pack-one is broken"
            )
        return _stub_attestations(cosign_trust_root)

    monkeypatch.setattr(f"{_BOOT_MODULE}.resolve_pack_attestations", _resolve)

    with caplog.at_level(logging.WARNING, logger=_BOOT_MODULE):
        registry = await build_and_populate_registry(
            settings=settings,
            audit_store=audit_store,
            supply_chain=supply_chain,
            object_store=object_store,
        )

    assert isinstance(registry, PluginRegistry)  # boot did not abort
    assert register_spy.call_count == 1  # only pack-two registered
    assert register_spy.call_args.args[0].record.distribution_name == "pack-two"
    # The skipped pack was logged (with its closed-enum resolution reason).
    assert any(
        "attestation_required_artefact_missing" in record.getMessage() for record in caplog.records
    )


async def test_per_pack_registration_exception_is_fail_soft(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_store: AuditStore,
    supply_chain: SupplyChainPipeline,
    object_store: LocalObjectStoreAdapter,
) -> None:
    trust_root_prefix = tmp_path / "trust-roots"
    _write_cosign_pub(trust_root_prefix)
    settings = _make_settings(
        pack_attestation_root_path=str(tmp_path / "attestations"),
        trust_root_prefix=trust_root_prefix,
        plugin_allowlist_path=_REAL_ALLOWLIST,
    )
    packs = [
        _make_discovered_pack(name="bad", distribution_name="pack-one"),
        _make_discovered_pack(name="good", distribution_name="pack-two"),
    ]

    async def _register(pack: DiscoveredPack, *args: Any, **kwargs: Any) -> Any:
        if pack.record.distribution_name == "pack-one":
            raise RuntimeError("transient registration boom")
        return MagicMock()

    register_spy = AsyncMock(side_effect=_register)
    _install_registry_stubs(monkeypatch, discovered=packs, register_spy=register_spy)
    monkeypatch.setattr(
        f"{_BOOT_MODULE}.resolve_pack_attestations",
        lambda pack, *, pack_attestation_root, cosign_trust_root: _stub_attestations(
            cosign_trust_root
        ),
    )

    registry = await build_and_populate_registry(
        settings=settings,
        audit_store=audit_store,
        supply_chain=supply_chain,
        object_store=object_store,
    )

    assert isinstance(registry, PluginRegistry)  # pack-one's raise did NOT abort boot
    assert register_spy.call_count == 2  # both attempted; pack-one raised inside
    assert {c.args[0].record.distribution_name for c in register_spy.call_args_list} == {
        "pack-one",
        "pack-two",
    }


# --------------------------------------------------------------------------- #
# MCP-intent packs through the REAL register gate
#
# The orchestration tests above STUB ``register_with_full_attestation_check``.
# These two tests instead exercise the REAL register gate through the boot
# path to prove the new ``mcp_admission`` seam reaches the
# ``mcp_admission_deps_required`` decision point. The setup mirrors
# ``tests/unit/protocol/test_mcp_registration_auth_probe.py``:
#
#   * ``TrustGate.verify_pack_signature`` is class-monkeypatched to succeed —
#     the boot builds its OWN trust gate (the trapdoor); construction needs no
#     cosign binary (the missing-binary error is deferred to verify), so we
#     stub only the one method that would shell out to cosign.
#   * ``supply_chain`` is a full-grade mock (passed INTO the builder — it is a
#     real injectable dependency, unlike the boot-built trust gate).
#   * ``mcp_manifest.extract_pack_manifest`` is monkeypatched to return the
#     MCP-intent manifest (the local import inside ``_mcp_admit`` re-fetches it
#     from the source module at call time).
#   * Real on-disk Sigstore bundle so the Step-4 persist runs against the real
#     ``LocalObjectStoreAdapter``; trust + supply chain mocked → the other
#     artefact paths are never opened.
# --------------------------------------------------------------------------- #

#: Distribution name of the MCP-intent pack; matches the bespoke ``_default``
#: allow-list each test writes so Step-1 (tenant allow-list) passes.
_MCP_PACK_DISTRIBUTION = "cognic-test-mcp-pack"


@pytest.fixture
async def chained_audit_store(tmp_path: Path) -> AsyncIterator[AuditStore]:
    """An ``AuditStore`` whose engine has the ``audit_event`` table + chain-head
    row created — the MCP-intent tests drive the REAL register, which appends a
    chained audit event. The plain ``audit_store`` fixture above never creates
    tables because the orchestration tests stub register."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'boot-chained.db'}")
    async with engine.begin() as conn:
        await conn.run_sync(_audit_event.metadata.create_all)
        await conn.execute(
            _chain_heads.insert().values(
                chain_id="audit_event",
                latest_sequence=0,
                latest_hash=ZERO_HASH,
                updated_at=_dt.datetime.now(_dt.UTC),
            )
        )
    yield AuditStore(engine)
    await engine.dispose()


def _make_mcp_pack() -> DiscoveredPack:
    """An MCP-intent discovered pack — its (monkeypatched) manifest declares
    ``[tool.cognic.mcp]``. ``distribution_name`` matches the bespoke allow-list."""
    record = PluginRecord(
        kind="tools",
        name="cognic_test_mcp_pack",
        distribution_name=_MCP_PACK_DISTRIBUTION,
        distribution_version="0.1.0",
        entry_point_value="cognic_test_mcp_pack:Plugin",
    )
    entry_point = _im.EntryPoint(
        name="cognic_test_mcp_pack",
        value="cognic_test_mcp_pack:Plugin",
        group="cognic.tools",
    )
    return DiscoveredPack(record=record, entry_point=entry_point)


def _canonical_mcp_manifest() -> dict[str, Any]:
    """The MCP-intent pack's manifest — a well-shaped ``[tool.cognic.mcp]``
    HTTP-OAuth block (mirrors the auth-probe file's canonical manifest)."""
    return {
        "tool": {
            "cognic": {
                "identity": {"pack_id": _MCP_PACK_DISTRIBUTION, "pack_version": "0.1.0"},
                "mcp": {
                    "transport": "http",
                    "auth": "oauth-prm",
                    "server_url": "https://server.example/mcp",
                    "scopes": ["mcp:tools"],
                },
                "runtime": {"risk_tier": "read_only"},
                "data_governance": {"data_classes": []},
            }
        }
    }


def _make_real_mcp_artefacts(tmp_path: Path, *, cosign_trust_root: Path) -> PackAttestations:
    """Real on-disk attestation artefacts. Only ``sigstore_bundle_path`` is
    actually read (Step 4 persists it to the real object store); trust gate +
    supply chain are mocked, so the other paths are never opened."""
    base = tmp_path / "mcp-attestations"
    base.mkdir(parents=True, exist_ok=True)
    bundle = base / "bundle.sigstore"
    bundle.write_bytes(b"sigstore-bundle-content")
    return PackAttestations(
        cosign_signature_path=base / "cosign.sig",
        cosign_blob_path=base / "blob",
        cosign_trust_root=cosign_trust_root,
        sbom_path=base / "sbom.cdx.json",
        sbom_signed_digest="b" * 64,
        sigstore_bundle_path=bundle,
    )


def _full_grade_supply_chain_mock() -> Any:
    """A supply-chain pipeline whose ``verify`` clears at full grade (SBOM /
    SLSA / in-toto all pass) so the real register reaches the MCP step."""
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


def _make_mcp_admission_deps() -> MCPAdmissionDeps:
    """A real (minimal) ``MCPAdmissionDeps``: a Vault stub (empty STDIO command
    allow-list — never reached on the HTTP-OAuth path) and an authz factory
    whose ``acquire_token`` succeeds so the registration auth probe clears.
    No ``mcp`` SDK needed — ``MCPAdmissionDeps`` / ``Token`` are SDK-free and
    the factory returns a ``MagicMock`` client (no real ``MCPAuthzClient``)."""
    vault_client = MagicMock()
    vault_client.read = AsyncMock(return_value={"servers": []})

    authz_client = MagicMock()
    authz_client.acquire_token = AsyncMock(
        return_value=Token(
            value="probe-token-bytes",
            expires_at=time.time() + 3600,
            as_issuer="https://as.example",
            scopes=("mcp:tools",),
            resource_indicator="https://server.example/mcp",
            client_id="cognic-mcp-_default",
        )
    )
    authz_client._token_cache = {}
    authz_client._inflight_acquires = {}

    return MCPAdmissionDeps(
        settings=build_settings_without_env_file(),
        vault_client=vault_client,
        opa_engine=None,  # the canonical manifest requests no sampling
        make_authz_client_for_probe=lambda: authz_client,
    )


async def _run_mcp_intent_boot(
    *,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    audit_store: AuditStore,
    object_store: LocalObjectStoreAdapter,
    mcp_admission: MCPAdmissionDeps | None,
) -> PluginRegistry:
    """Drive ``build_and_populate_registry`` over ONE MCP-intent pack through
    the REAL ``register_with_full_attestation_check`` — parametrised only on
    whether ``mcp_admission`` is wired."""
    from cognic_agentos.protocol import mcp_manifest as _mm

    trust_root_prefix = tmp_path / "trust-roots"
    _write_cosign_pub(trust_root_prefix)
    allowlist_path = tmp_path / "mcp-allowlist.json"
    allowlist_path.write_text(json.dumps({"_default": [_MCP_PACK_DISTRIBUTION]}))
    settings = _make_settings(
        pack_attestation_root_path=str(tmp_path / "attestations"),
        trust_root_prefix=trust_root_prefix,
        plugin_allowlist_path=allowlist_path,
    )

    # discover → the single MCP-intent pack (register stays REAL — only
    # discover is stubbed here, unlike the orchestration ``_install_registry_stubs``).
    monkeypatch.setattr(PluginRegistry, "discover", lambda self: [_make_mcp_pack()], raising=True)
    # TrustGate.verify_pack_signature: class-stubbed to clear (boot builds its
    # own gate; we only replace the cosign-shelling method).
    monkeypatch.setattr(
        TrustGate,
        "verify_pack_signature",
        AsyncMock(
            return_value=CosignVerificationResult(
                verified=True,
                pack_id=_MCP_PACK_DISTRIBUTION,
                version="0.1.0",
                signature_digest="a" * 64,
            )
        ),
        raising=True,
    )
    # resolve_pack_attestations → real on-disk artefacts (threads the locked
    # cosign_trust_root through exactly as the production resolver would).
    monkeypatch.setattr(
        f"{_BOOT_MODULE}.resolve_pack_attestations",
        lambda pack, *, pack_attestation_root, cosign_trust_root: _make_real_mcp_artefacts(
            tmp_path, cosign_trust_root=cosign_trust_root
        ),
    )
    # extract_pack_manifest → the MCP-intent manifest (local import in
    # _mcp_admit re-fetches from the source module at call time).
    monkeypatch.setattr(_mm, "extract_pack_manifest", lambda **_kw: _canonical_mcp_manifest())

    return await build_and_populate_registry(
        settings=settings,
        audit_store=audit_store,
        supply_chain=_full_grade_supply_chain_mock(),
        object_store=object_store,
        mcp_admission=mcp_admission,
    )


async def test_mcp_intent_pack_registers_when_mcp_admission_wired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    chained_audit_store: AuditStore,
    object_store: LocalObjectStoreAdapter,
) -> None:
    """An MCP-intent pack (manifest declares ``[tool.cognic.mcp]``) booted with
    ``mcp_admission`` wired clears the Sprint-5 MCP admission gates: the stored
    outcome is NOT ``mcp_admission_deps_required`` — it registers."""
    registry = await _run_mcp_intent_boot(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        audit_store=chained_audit_store,
        object_store=object_store,
        mcp_admission=_make_mcp_admission_deps(),
    )

    outcomes = registry.known_packs()
    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.pack_id == _MCP_PACK_DISTRIBUTION
    # The MCP gate cleared — the fail-closed deps-required refusal did NOT fire.
    assert outcome.refusal_reason != "mcp_admission_deps_required"
    assert outcome.status == "registered"
    assert outcome.refusal_reason is None


async def test_mcp_intent_pack_refused_when_mcp_admission_omitted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    chained_audit_store: AuditStore,
    object_store: LocalObjectStoreAdapter,
) -> None:
    """The SAME MCP-intent pack booted with the default ``mcp_admission=None``
    is refused fail-closed with ``mcp_admission_deps_required`` — the preserved
    kernel-image doctrine (MCP packs cannot register without the deps wired)."""
    registry = await _run_mcp_intent_boot(
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        audit_store=chained_audit_store,
        object_store=object_store,
        mcp_admission=None,
    )

    outcomes = registry.known_packs()
    assert len(outcomes) == 1
    outcome = outcomes[0]
    assert outcome.pack_id == _MCP_PACK_DISTRIBUTION
    assert outcome.status == "refused_at_registration"
    assert outcome.refusal_reason == "mcp_admission_deps_required"
