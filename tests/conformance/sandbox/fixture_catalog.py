"""TEST-ONLY catalog double for the #477 fixture-image live-proof path.

Active only under ``COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES=1`` (the
conformance conftest wires it; see #477 spec §7). Allowlists exactly the
two named fixture image digests — one runtime fixture + one egress-proxy
fixture — and no-op-passes cosign / SBOM verification for those two
digests only.

This is NOT a supply-chain proof. The cosign / SBOM no-op-pass here
exercises only the runtime mechanics of the digest-axis admission path;
supply-chain admission of the real canonical images has its own
dedicated tests and stays Sprint 14 deploy-kit scope — see the #477
spec §1.

MUST NOT be imported or referenced by any ``src/`` module — pinned by
``tests/unit/architecture/test_fixture_path_not_in_src.py``.
"""

from __future__ import annotations

from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused


def _digest_of(ref: str) -> str:
    """Extract the ``sha256:<digest>`` from a digest-pinned OCI ref."""
    if "@" not in ref:
        raise ValueError(f"fixture ref is not digest-pinned: {ref!r}")
    return ref.rsplit("@", 1)[1]


class _FixtureOnlySandboxCatalog:
    """``CatalogProtocol``-conformant test double — see module docstring.

    Structurally conforms to the digest-axis ``CatalogProtocol`` at
    ``cognic_agentos.sandbox.admission`` (4 methods, every one keyed on
    ``image_digest: str``), so it is substitutable wherever the runtime
    ``CanonicalImageCatalog`` is consumed.
    """

    def __init__(self, *, runtime_ref: str, proxy_ref: str) -> None:
        self._allowed = frozenset({_digest_of(runtime_ref), _digest_of(proxy_ref)})

    def is_canonical(self, image_digest: str) -> bool:
        return image_digest in self._allowed

    def is_tenant_allow_listed(self, image_digest: str, tenant_id: str) -> bool:
        # Fixtures pass via the canonical path, not the per-tenant
        # escape hatch.
        return False

    async def verify_cosign_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        if image_digest not in self._allowed:
            raise SandboxLifecycleRefused("sandbox_image_cosign_verification_failed")

    async def verify_sbom_policy_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        if image_digest not in self._allowed:
            raise SandboxLifecycleRefused("sandbox_image_sbom_check_failed")
