"""#477 T3 — behaviour tests for the `_FixtureOnlySandboxCatalog` test double.

Pins the digest-axis CatalogProtocol surface: both fixture digests
allowlisted via `is_canonical`, any other digest refused; cosign/SBOM
no-op-pass for the two fixture digests and raise the matching
closed-enum `SandboxRefusalReason` for anything else.
"""

import pytest

from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused
from tests.conformance.sandbox.fixture_catalog import _FixtureOnlySandboxCatalog

_RUNTIME_REF = "reg.example/cognic-sandbox-runtime-fixture@sha256:" + "a" * 64
_PROXY_REF = "reg.example/cognic-sandbox-egress-proxy-fixture@sha256:" + "b" * 64
_RUNTIME_DIGEST = "sha256:" + "a" * 64
_PROXY_DIGEST = "sha256:" + "b" * 64
_OTHER_DIGEST = "sha256:" + "c" * 64


def _catalog() -> _FixtureOnlySandboxCatalog:
    return _FixtureOnlySandboxCatalog(runtime_ref=_RUNTIME_REF, proxy_ref=_PROXY_REF)


def test_is_canonical_true_for_both_fixture_digests() -> None:
    cat = _catalog()
    assert cat.is_canonical(_RUNTIME_DIGEST) is True
    assert cat.is_canonical(_PROXY_DIGEST) is True


def test_is_canonical_false_for_any_other_digest() -> None:
    assert _catalog().is_canonical(_OTHER_DIGEST) is False


def test_is_tenant_allow_listed_always_false() -> None:
    cat = _catalog()
    assert cat.is_tenant_allow_listed(_RUNTIME_DIGEST, "t-1") is False
    assert cat.is_tenant_allow_listed(_OTHER_DIGEST, "t-1") is False


@pytest.mark.asyncio
async def test_verify_cosign_passes_for_fixture_digests() -> None:
    cat = _catalog()
    await cat.verify_cosign_or_refuse(_RUNTIME_DIGEST, tenant_id="t-1")
    await cat.verify_cosign_or_refuse(_PROXY_DIGEST, tenant_id="t-1")


@pytest.mark.asyncio
async def test_verify_cosign_refuses_other_digest() -> None:
    with pytest.raises(SandboxLifecycleRefused) as excinfo:
        await _catalog().verify_cosign_or_refuse(_OTHER_DIGEST, tenant_id="t-1")
    assert excinfo.value.reason == "sandbox_image_cosign_verification_failed"


@pytest.mark.asyncio
async def test_verify_sbom_passes_for_fixture_digests_refuses_other() -> None:
    cat = _catalog()
    await cat.verify_sbom_policy_or_refuse(_RUNTIME_DIGEST, tenant_id="t-1")
    await cat.verify_sbom_policy_or_refuse(_PROXY_DIGEST, tenant_id="t-1")
    with pytest.raises(SandboxLifecycleRefused) as excinfo:
        await cat.verify_sbom_policy_or_refuse(_OTHER_DIGEST, tenant_id="t-1")
    assert excinfo.value.reason == "sandbox_image_sbom_check_failed"
