"""T14 Step 2b — real-catalog admission proof (closes the Z3/Z4 MagicMock gap).

The Z3/Z4 credential-projection proofs stub ``image_catalog`` with a ``MagicMock``
(``is_canonical -> True``, ``verify_*_or_refuse -> None``), so they would stay
green even if the production catalog wiring (T10/T10b/T11/T12) or the trust-gate
fixes (T8.5 SBOM carve-out, T8.6 cosign argv) were broken. THIS proof drives the
**real** ``CanonicalImageCatalog`` — constructed by the production
``get_backend(settings)`` factory (T11) from the canonical Settings (T10) — so
``is_canonical`` + the real ``cosign verify`` (against the canonical trust root,
T8.6/T10b) + the canonical SBOM carve-out (T8.5) all run against the REAL signed
images.

**Env-gated** on ``COGNIC_RUN_REAL_CATALOG_ADMISSION_PROOF=1``. Requires (opt-in
implies these are present — fail LOUD, never skip):
  * ``COGNIC_SANDBOX_CANONICAL_IMAGE_TRUST_ROOT_PATH`` = the canonical AgentOS
    cosign PUBLIC key (the real signed images verify against it);
  * the canonical image refs — the Settings defaults are the real signed refs
    (T10/T12); override via ``COGNIC_SANDBOX_CANONICAL_*`` if re-homed;
  * ``cosign`` on PATH + registry auth to pull the signed images' signatures.

**Backend coverage:** the canonical image catalog is built by the factory
*backend-agnostically* (same catalog object for docker_sibling AND
kubernetes_pod — pinned by T11), and ``admit_policy`` is the shared
backend-agnostic Stage-2 seam. So one admission proof covers both backends'
catalog gate; the backend-SPECIFIC ``create()`` launch (Docker sibling / K8s
Pod) is exercised by the Z3 / Z4 credential-projection targets respectively. The
``rego_engine`` is mocked-allow here — it is the ADR-015 policy gate, orthogonal
to the canonical-image trust gate this proof targets.
"""

from __future__ import annotations

import os

import pytest

# Env-gate FIRST (Sprint-10.1 Finding #3): env unset → skip by design; env SET →
# the plain imports below fail LOUD on a missing extra, never importorskip-skip.
if os.environ.get("COGNIC_RUN_REAL_CATALOG_ADMISSION_PROOF") != "1":
    pytest.skip(
        "real-catalog admission proof; opt in via "
        "COGNIC_RUN_REAL_CATALOG_ADMISSION_PROOF=1 (requires cosign + registry "
        "auth + COGNIC_SANDBOX_CANONICAL_IMAGE_TRUST_ROOT_PATH)",
        allow_module_level=True,
    )

import shutil
from unittest.mock import AsyncMock, MagicMock

try:
    import cognic_agentos.sandbox.catalog as _catalog_mod
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.policy.engine import Decision
    from cognic_agentos.sandbox import PackAdmissionContext, SandboxPolicy
    from cognic_agentos.sandbox.admission import CredentialAdapter, admit_policy
    from cognic_agentos.sandbox.backend_factory import get_backend
    from cognic_agentos.sandbox.catalog import CanonicalImageCatalog
except ImportError as exc:  # pragma: no cover - opted-in-but-missing-extra path
    raise AssertionError(
        "COGNIC_RUN_REAL_CATALOG_ADMISSION_PROOF=1 but a required import failed "
        "(sandbox extras unavailable) — failing loud rather than skipping."
    ) from exc

_TENANT = "t-real-catalog-proof"


def _digest(ref: str) -> str:
    return ref.rsplit("@", 1)[1]


def _settings() -> Settings:
    trust_root = os.environ.get("COGNIC_SANDBOX_CANONICAL_IMAGE_TRUST_ROOT_PATH", "").strip()
    assert trust_root, (
        "COGNIC_SANDBOX_CANONICAL_IMAGE_TRUST_ROOT_PATH unset/empty; opt-in "
        "implies it points at the canonical cosign public key — failing loud."
    )
    # Settings reads COGNIC_SANDBOX_CANONICAL_* + the trust-root path from env.
    return Settings()


@pytest.fixture
def real_catalog(monkeypatch: pytest.MonkeyPatch) -> tuple[Settings, CanonicalImageCatalog]:
    """The REAL CanonicalImageCatalog the production factory builds (NOT a
    MagicMock). cosign is on the host's PATH but the catalog's minimal
    ``_SUBPROCESS_ENV`` PATH is the in-image location; prepend the host cosign
    dir so the real ``cosign verify`` argv executes (the T8.6 pattern — the argv
    itself is unchanged)."""
    cosign = shutil.which("cosign")
    assert cosign is not None, (
        "cosign not on PATH; opt-in COGNIC_RUN_REAL_CATALOG_ADMISSION_PROOF=1 "
        "implies cosign is available — failing loud."
    )
    monkeypatch.setattr(
        _catalog_mod,
        "_SUBPROCESS_ENV",
        {
            **_catalog_mod._SUBPROCESS_ENV,
            "PATH": f"{os.path.dirname(cosign)}:{_catalog_mod._SUBPROCESS_ENV['PATH']}",
            # Test-host registry-auth adaptation: the canonical signed images are
            # PRIVATE on GHCR, so cosign needs registry creds to pull their
            # signatures. The catalog's minimal HOME=/tmp hides ~/.docker/config.json,
            # so point cosign at the host docker config (where `docker login
            # ghcr.io` stored the token) via DOCKER_CONFIG. The verify ARGV + the
            # canonical trust root are unchanged; production provisions registry
            # creds into the sandbox host's env separately (a deployment concern,
            # not part of the catalog's trust-gate logic).
            "DOCKER_CONFIG": os.path.expanduser("~/.docker"),
        },
    )
    settings = _settings()
    # The factory is AUTHORITATIVE for image_catalog (T11); the other deps are
    # irrelevant to the catalog object, so they are mocked. docker_sibling is the
    # default backend; its catalog is identical to the K8s backend's (T11).
    backend = get_backend(
        settings,
        docker_client=MagicMock(),
        credential_adapter=MagicMock(),
        rego_engine=MagicMock(),
        audit_store=MagicMock(),
        decision_history_store=MagicMock(),
        warm_pool=None,
    )
    catalog = backend._catalog  # type: ignore[attr-defined]
    assert isinstance(catalog, CanonicalImageCatalog), "factory did not build the real catalog"
    return settings, catalog


async def test_real_catalog_recognises_and_cosign_verifies_both_canonical_images(
    real_catalog: tuple[Settings, CanonicalImageCatalog],
) -> None:
    """is_canonical + the REAL ``cosign verify --key <canonical-trust-root>``
    pass for BOTH signed canonical images — proving T10b (canonical trust root)
    + T8.6 (key-based argv) end-to-end against the real artifacts."""
    settings, catalog = real_catalog
    rp_digest = _digest(settings.sandbox_canonical_runtime_python_image)
    ep_digest = _digest(settings.sandbox_canonical_egress_proxy_image)

    assert catalog.is_canonical(rp_digest)
    assert catalog.is_canonical(ep_digest)
    # No raise == the real cosign verify against the real canonical trust root
    # succeeded (the images are signed by the canonical key).
    await catalog.verify_cosign_or_refuse(rp_digest, tenant_id=_TENANT)
    await catalog.verify_cosign_or_refuse(ep_digest, tenant_id=_TENANT)


async def test_admit_policy_admits_canonical_runtime_through_real_catalog(
    real_catalog: tuple[Settings, CanonicalImageCatalog],
) -> None:
    """The full Stage-2 admission seam with the REAL catalog admits the canonical
    runtime image: step-6 is_canonical (real) + step-7 cosign (real, vs the
    canonical trust root) + step-8 SBOM license gate SKIPPED for canonical
    (T8.5 carve-out — the GPL/LGPL platform base would otherwise refuse) +
    step-9 rego (mocked-allow, orthogonal). No raise == admitted."""
    settings, catalog = real_catalog
    policy = SandboxPolicy(
        cpu_cores=0.5,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image=settings.sandbox_canonical_runtime_python_image,
        egress_allow_list=(),
        vault_path=None,
    )
    pack_ctx = PackAdmissionContext(
        pack_id="cognic.real_catalog_proof",
        pack_version="v1.0.0",
        pack_artifact_digest="sha256:" + "1" * 64,
        risk_tier="internal_write",
        declares_dynamic_install=False,
        profile="production",
    )
    rego = MagicMock()
    rego.evaluate = AsyncMock(
        return_value=Decision(
            allow=True,
            rule_matched="data.cognic.sandbox.admit.allow",
            reasoning="ok",
            decision_data=None,
        )
    )
    # No vault_path + no requires_credentials → the adapter is not exercised.
    await admit_policy(
        policy,
        tenant_id=_TENANT,
        actor=MagicMock(),
        pack_context=pack_ctx,
        catalog=catalog,
        credential_adapter=AsyncMock(spec=CredentialAdapter),
        rego_engine=rego,
        settings=settings,
    )
