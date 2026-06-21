"""Sprint 5 (ADR-002 + ADR-003 + ADR-016) — startup discovery → trust boot →
ONE shared PluginRegistry → BOTH consumers: the headline JOIN, end-to-end.

The four-sprint slice landed each piece with its own unit test:

  * Sprint 1 — ``Settings.pack_attestation_root_path``.
  * Sprint 2 — ``protocol/pack_attestation_resolver.resolve_pack_attestations``.
  * Sprint 3 — ``harness/registry_boot.build_and_populate_registry`` (the
    off-gate boot-builder; ``tests/unit/harness/test_registry_boot.py``).
  * Sprint 4 — the ``portal/api/app.py`` lifespan unification so ONE shared
    ``PluginRegistry`` feeds BOTH the MCP host and the A2A endpoint
    (``tests/unit/portal/api/test_app_registry_unification.py``).

The ONE untested boundary is the JOIN of all four through the REAL lifespan:

    REAL discover() → REAL build_and_populate_registry → app.state.plugin_registry
                    → build_mcp_host(registry=…) AND A2AEndpoint(plugin_registry=…)
                      receive the SAME object.

This conformance test proves exactly that join with ONE real discovered +
trust-registered pack flowing all the way through.

THIN trust boundary (no heavyweight environment dependency):

  * REAL ``discover()`` is exercised — the entry-point SOURCE
    (``importlib.metadata.entry_points``, the singleton module ``discover()``
    reads as ``_im.entry_points``) is monkeypatched so a single fixture pack is
    discovered. ``discover()`` itself is NEVER stubbed — the whole point is to
    drive the real discovery→boot link.
  * REAL ``build_and_populate_registry`` (the off-gate boot-builder) and the
    REAL ``resolve_pack_attestations`` resolver run against a REAL on-disk
    attestation tree.
  * The CRYPTOGRAPHIC trust boundary is mocked at the class level (the boot +
    lifespan build their own collaborators, so a class attribute — which is NOT
    a descriptor — records calls without ``self``): ``TrustGate.
    verify_pack_signature`` clears, ``SupplyChainPipeline.verify`` returns full
    grade, and the registration OAuth probe (``MCPAuthzClient.acquire_token``)
    succeeds. ``mcp_manifest.extract_pack_manifest`` returns a non-sampling
    ``[tool.cognic.mcp]`` manifest. This is the SAME shimming the Sprint-3
    harness suite and the Sprint-5 ``test_mcp_registration_auth_probe`` suite use
    — NO live cosign, NO wheel install.

The fixture pack is a NON-SAMPLING MCP pack: it declares ``[tool.cognic.mcp]``
WITHOUT a sampling capability. The lifespan wires ``MCPAdmissionDeps`` with the
accepted Sprint-4 ``opa_engine=None`` posture, under which sampling-capable
packs default-deny — so this test asserts the non-sampling pack REGISTERS and
does NOT claim a sampling-capable registration (out of scope).

The SDK-gated MCP/A2A constructors (``build_mcp_host`` / ``A2AEndpoint``) are
spied so the join is deterministic regardless of which optional adapter extras
are installed; ``is_mcp_available`` / ``is_a2a_available`` are forced True so
both blocks run. Un-gated — runs in the default suite (mirrors the
``tests/conformance/a2a`` posture; unlike ``tests/conformance/sandbox`` it needs
no live runtime).
"""

from __future__ import annotations

import hashlib
import importlib.metadata as _im
import json
import time
from typing import TYPE_CHECKING, Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

from cognic_agentos.portal.api.app import create_app
from cognic_agentos.protocol import mcp_manifest
from cognic_agentos.protocol.mcp_authz import MCPAuthzClient, Token
from cognic_agentos.protocol.plugin_registry import PluginRegistry
from cognic_agentos.protocol.supply_chain import AttestationResult, SupplyChainPipeline
from cognic_agentos.protocol.trust_gate import CosignVerificationResult, TrustGate

if TYPE_CHECKING:
    from pathlib import Path

    import pytest

    from cognic_agentos.core.config import Settings
    from cognic_agentos.db.adapters import AdapterRegistry

# --------------------------------------------------------------------------- #
# Fixture-pack identity. Matches the Sprint-3 harness MCP-intent pack so the
# REAL discover() yields a DiscoveredPack byte-identical to that suite's
# ``_make_mcp_pack()`` — which the harness already proves registers when
# mcp_admission is wired. Here the SAME shape flows through the REAL lifespan.
# --------------------------------------------------------------------------- #
_DIST_NAME = "cognic-test-mcp-pack"
_DIST_VERSION = "0.1.0"
_PACK_NAME = "cognic_test_mcp_pack"
_ENTRY_POINT_VALUE = "cognic_test_mcp_pack:Plugin"

#: The genuine stdlib ``entry_points``, captured before any monkeypatch so the
#: fake can DELEGATE every non-cognic group to it (keeps the blast radius to the
#: three cognic pack groups ``discover()`` actually reads).
_REAL_ENTRY_POINTS = _im.entry_points


# --------------------------------------------------------------------------- #
# REAL discover() seam — monkeypatch the entry-point SOURCE (NOT discover()).
# --------------------------------------------------------------------------- #


class _FixtureDistribution:
    """Minimal stand-in for the owning distribution that real
    ``importlib.metadata`` attaches to a discovered EntryPoint. ``discover()``
    reads only ``dist.metadata["Name"]`` + ``dist.version`` to fill the
    PluginRecord identity (``plugin_registry.py`` ``discover``)."""

    version: ClassVar[str] = _DIST_VERSION
    metadata: ClassVar[dict[str, str]] = {"Name": _DIST_NAME}


def _fixture_entry_point() -> _im.EntryPoint:
    """A REAL ``importlib.metadata.EntryPoint`` with its owning distribution
    bound, so ``discover()`` reads ``ep.dist.metadata["Name"]`` /
    ``ep.dist.version`` exactly as it would for a genuinely installed pack.

    ``EntryPoint._for(dist)`` binds the distribution; the method exists on
    CPython but is absent from typeshed, so it is reached via ``getattr`` to
    stay mypy-clean (the call site is the only place that touches it)."""
    ep = _im.EntryPoint(name=_PACK_NAME, value=_ENTRY_POINT_VALUE, group="cognic.tools")
    bound: _im.EntryPoint = getattr(ep, "_for")(_FixtureDistribution())  # noqa: B009
    return bound


def _fake_entry_points(*args: Any, **kwargs: Any) -> Any:
    """Drop-in for ``importlib.metadata.entry_points`` that yields the single
    fixture pack for the ``cognic.tools`` group, nothing for the other two
    cognic groups, and DELEGATES every other group (``console_scripts`` etc.)
    to the genuine stdlib so unrelated lifespan code is unaffected.

    This is the SEAM ``discover()`` reads (``_im.entry_points``) — patching it
    drives the REAL discovery walk; ``discover()`` is never stubbed."""
    group = kwargs.get("group")
    if group == "cognic.tools":
        return [_fixture_entry_point()]
    if group in ("cognic.skills", "cognic.agents"):
        return []
    return _REAL_ENTRY_POINTS(*args, **kwargs)


# --------------------------------------------------------------------------- #
# REAL on-disk attestation tree (mirrors tests/unit/protocol/
# test_pack_attestation_resolver.py::_write_attestations) so the REAL resolver
# locates the artefacts. The cryptographic verifiers are mocked, so only the
# Sigstore-bundle read (Step 4) + the SLSA-digest parse touch real bytes.
# --------------------------------------------------------------------------- #


def _write_full_attestation_tree(root: Path, *, dist: str, version: str) -> Path:
    base = root / dist / version
    base.mkdir(parents=True)
    (base / "cosign.sig").write_text("sig")
    (base / "bundle.sigstore").write_text("{}")
    sbom = b'{"bomFormat":"CycloneDX"}'
    (base / "sbom.cdx.json").write_bytes(sbom)
    digest = hashlib.sha256(sbom).hexdigest()
    slsa = {
        "predicate": {"buildDefinition": {"externalParameters": {"sbom_digest_sha256": digest}}}
    }
    (base / "slsa-provenance.intoto.json").write_text(json.dumps(slsa))
    (base / f"{_PACK_NAME}-{version}-py3-none-any.whl").write_text("wheel-bytes")
    return base


def _write_cosign_pub(trust_root_prefix: Path) -> Path:
    """Create a non-empty ``<prefix>/_default/cosign.pub`` (the LOCKED cosign
    trust-root convention the boot fail-closed-verifies before any pack
    registers)."""
    default_dir = trust_root_prefix / "_default"
    default_dir.mkdir(parents=True, exist_ok=True)
    cosign_pub = default_dir / "cosign.pub"
    cosign_pub.write_text("-----BEGIN PUBLIC KEY-----\nMOCK\n-----END PUBLIC KEY-----\n")
    return cosign_pub


def _canonical_mcp_manifest() -> dict[str, Any]:
    """The fixture pack's manifest — a well-shaped NON-SAMPLING
    ``[tool.cognic.mcp]`` HTTP-OAuth block (mirrors the harness +
    auth-probe suites' canonical manifest; no ``sampling`` capability)."""
    return {
        "tool": {
            "cognic": {
                "identity": {"pack_id": _DIST_NAME, "pack_version": _DIST_VERSION},
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


# --------------------------------------------------------------------------- #
# Lifespan driver + surface spies (mirror tests/unit/portal/api/
# test_app_registry_unification.py).
# --------------------------------------------------------------------------- #


def _litellm_yaml(tmp_path: Path) -> Path:
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n"
        "  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n"
        "      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return cfg


def _boot_settings(
    memory_settings: Settings,
    tmp_path: Path,
    *,
    attestation_root: Path,
    trust_root_prefix: Path,
    allowlist_path: Path,
) -> Settings:
    """memory_settings + a litellm config + memory cache (so build_runtime and
    the scheduler construct on the adapter path) + the three boot inputs SET so
    the boot takes the REAL discovery path (not the benign unset-root empty
    path)."""
    return memory_settings.model_copy(
        update={
            "litellm_config_path": _litellm_yaml(tmp_path),
            "cache_driver": "memory",
            "pack_attestation_root_path": str(attestation_root),
            "trust_root_prefix": trust_root_prefix,
            "plugin_allowlist_path": allowlist_path,
        }
    )


def _force_sdk_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cognic_agentos.portal.api.app.is_mcp_available", lambda: True)
    monkeypatch.setattr("cognic_agentos.portal.api.app.is_a2a_available", lambda: True)


def _spy_surfaces(monkeypatch: pytest.MonkeyPatch, captured: dict[str, Any]) -> None:
    """Replace the two SDK-gated constructors with identity-capturing spies.

    ``build_mcp_host(registry=...)`` and ``A2AEndpoint(plugin_registry=...)`` are
    the ONLY consumers of the shared registry; capturing their kwarg by identity
    is how the JOIN is proven. Each returns a unique sentinel so
    ``app.state.mcp_host`` / ``app.state.a2a_endpoint`` read non-None."""

    def _spy_build_mcp_host(**kwargs: Any) -> object:
        captured["mcp_registry"] = kwargs["registry"]
        captured["mcp_host"] = object()
        return captured["mcp_host"]

    def _spy_a2a_endpoint(**kwargs: Any) -> object:
        captured["a2a_registry"] = kwargs["plugin_registry"]
        captured["a2a_endpoint"] = object()
        return captured["a2a_endpoint"]

    monkeypatch.setattr("cognic_agentos.harness.mcp_host.build_mcp_host", _spy_build_mcp_host)
    monkeypatch.setattr("cognic_agentos.protocol.a2a_endpoint.A2AEndpoint", _spy_a2a_endpoint)


def _mock_trust_boundary(monkeypatch: pytest.MonkeyPatch) -> None:
    """The THIN trust boundary — class-level so the boot's + lifespan's own
    collaborator instances pick the mocks up (a class attr is NOT a descriptor,
    so it records calls without ``self``). NO live cosign, NO wheel install."""
    monkeypatch.setattr(
        TrustGate,
        "verify_pack_signature",
        AsyncMock(
            return_value=CosignVerificationResult(
                verified=True,
                pack_id=_DIST_NAME,
                version=_DIST_VERSION,
                signature_digest="a" * 64,
            )
        ),
        raising=True,
    )
    monkeypatch.setattr(
        SupplyChainPipeline,
        "verify",
        MagicMock(
            return_value=AttestationResult(
                grade="full",
                verified={"sbom": True, "slsa": True, "intoto": True},
                findings=(),
                slsa=None,
                vuln=None,
                licenses=None,
            )
        ),
        raising=True,
    )
    # The registration OAuth probe (Step C of _mcp_admit). The lifespan builds a
    # REAL MCPAuthzClient for the probe; class-mock acquire_token so the probe
    # clears (the returned token is discarded — registration only validates
    # "could acquire", not "use").
    monkeypatch.setattr(
        MCPAuthzClient,
        "acquire_token",
        AsyncMock(
            return_value=Token(
                value="probe-token-bytes",
                expires_at=time.time() + 3600,
                as_issuer="https://as.example",
                scopes=("mcp:tools",),
                resource_indicator="https://server.example/mcp",
                client_id="cognic-mcp-_default",
            )
        ),
        raising=True,
    )
    # Manifest extraction (Step A). The local import inside _mcp_admit re-fetches
    # this from the source module at call time, so patching the module attr wins.
    monkeypatch.setattr(
        mcp_manifest, "extract_pack_manifest", lambda **_kw: _canonical_mcp_manifest()
    )


# --------------------------------------------------------------------------- #
# The headline JOIN.
# --------------------------------------------------------------------------- #


async def test_discover_to_boot_to_shared_registry_to_both_consumers(
    memory_settings: Settings,
    memory_registry: AdapterRegistry,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ONE real discovered + trust-registered pack flows through the REAL boot
    into the ONE shared registry that BOTH consumers receive."""
    # 1. Real on-disk trust inputs: attestation tree + cosign trust anchor +
    #    a _default allow-list naming the fixture distribution.
    attestation_root = tmp_path / "attestations"
    _write_full_attestation_tree(attestation_root, dist=_DIST_NAME, version=_DIST_VERSION)
    trust_root_prefix = tmp_path / "trust-roots"
    _write_cosign_pub(trust_root_prefix)
    allowlist_path = tmp_path / "plugin_allowlist.json"
    allowlist_path.write_text(json.dumps({"_default": [_DIST_NAME]}))

    # 2. REAL discover() yields the ONE fixture non-sampling MCP pack — by
    #    monkeypatching the entry-point SOURCE, NOT discover() itself.
    monkeypatch.setattr(_im, "entry_points", _fake_entry_points)

    # 3. THIN trust boundary (class-level mocks + manifest).
    _mock_trust_boundary(monkeypatch)

    # 4. REAL lifespan: force the SDK-gated blocks to run + spy both surfaces.
    captured: dict[str, Any] = {}
    _force_sdk_available(monkeypatch)
    _spy_surfaces(monkeypatch, captured)
    settings = _boot_settings(
        memory_settings,
        tmp_path,
        attestation_root=attestation_root,
        trust_root_prefix=trust_root_prefix,
        allowlist_path=allowlist_path,
    )
    app = create_app(settings, adapter_registry=memory_registry)
    async with app.router.lifespan_context(app):
        # 5a. The REAL app.state registry is a populated PluginRegistry (NOT
        #     None, NOT empty) — the fixture pack REGISTERED.
        registry = app.state.plugin_registry
        assert isinstance(registry, PluginRegistry)
        outcomes = registry.known_packs()
        assert len(outcomes) == 1
        outcome = outcomes[0]
        assert outcome.pack_id == _DIST_NAME
        assert outcome.status == "registered"
        # The non-sampling MCP gate cleared — the fail-closed deps-required
        # refusal did NOT fire (and no other refusal did either).
        assert outcome.refusal_reason != "mcp_admission_deps_required"
        assert outcome.refusal_reason is None
        assert outcome.attestation_grade == "full"

        # 5b. The JOIN — the spied MCP host received registry= that IS the very
        #     object on app.state.
        assert captured["mcp_registry"] is registry
        # 5c. … and the spied A2A endpoint received plugin_registry= that IS the
        #     SAME object.
        assert captured["a2a_registry"] is registry
        # 5d. Both surfaces were constructed (non-None) from that ONE registry.
        assert app.state.mcp_host is captured["mcp_host"]
        assert app.state.a2a_endpoint is captured["a2a_endpoint"]
