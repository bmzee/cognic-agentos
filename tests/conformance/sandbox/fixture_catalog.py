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

import os

from cognic_agentos.sandbox.policy import _validate_image_ref
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

# ``_validate_image_ref`` is the SOURCE-OF-TRUTH Stage-1 OCI-ref
# validator (repository shape via ``_OCI_REPO_TAG_RE`` + digest via
# ``_SHA256_DIGEST_RE``). Importing this underscore-prefixed src helper
# into test-support code is intentional: test code MAY import src
# internals — the forbidden direction is src -> test (pinned by T3's
# architecture guard). Reusing it means the conftest boundary rejects
# EXACTLY what admission rejects, with zero drift, and a bare
# ``"@sha256:" in val`` substring check (which would accept
# ``reg/p@sha256:bad``) is avoided.
#
# ``SandboxLifecycleRefused`` is imported from ``sandbox.protocol`` —
# its definition home — NOT from ``sandbox.admission`` (which only
# re-imports it without re-exporting; importing it from there triggers
# a mypy ``attr-defined`` error). Matches the existing import below.

_FLAG = "COGNIC_USE_LOCAL_FIXTURE_SANDBOX_IMAGES"
_RUNTIME_VAR = "COGNIC_FIXTURE_RUNTIME_IMAGE_REF"
_PROXY_VAR = "COGNIC_FIXTURE_PROXY_IMAGE_REF"


def resolve_fixture_refs() -> tuple[str, str] | None:
    """Return ``(runtime_ref, proxy_ref)`` when fixture mode is on, else None.

    Fail-fast (``RuntimeError``) if the flag is set but a ref env var is
    missing or not a valid digest-pinned OCI ref (#477 §4.3). Ref shape
    is validated by the source-of-truth Stage-1 validator
    ``cognic_agentos.sandbox.policy._validate_image_ref`` — the same
    check admission runs. No silent skip, no placeholder fallback.
    """
    if os.environ.get(_FLAG) != "1":
        return None
    refs: list[str] = []
    for var in (_RUNTIME_VAR, _PROXY_VAR):
        val = os.environ.get(var, "").strip()
        if not val:
            raise RuntimeError(
                f"{_FLAG}=1 but {var} is unset — see docs/runbooks/477-live-sandbox-proof.md"
            )
        try:
            _validate_image_ref(val)
        except SandboxLifecycleRefused as exc:
            raise RuntimeError(
                f"{var}={val!r} is not a valid digest-pinned OCI ref "
                "(repository[:tag]@sha256:<64 lowercase hex>)"
            ) from exc
        refs.append(val)
    return refs[0], refs[1]


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
