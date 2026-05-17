"""Sprint 8A T10 — shared fixtures for env-gated backend tests.

The 3 env-gated test files (test_docker_sibling_lifecycle.py +
test_docker_sibling_resource_caps.py [T10b] +
test_docker_sibling_egress.py [T10c]) share the same Docker-daemon
+ catalog + backend wiring. The fixtures live here so each test
file can request them by name without duplication.

The autouse ``_canonical_artifact_preflight`` fixture probes each
canonical Sprint-8A image via the host Docker daemon; on miss it
skips the test with a structured message naming the missing ref
(per ``feedback_canonical_artifact_not_oss_substitute`` — NEVER
silent OSS substitution). The autouse pattern means every test in
this directory gets the preflight without each test opting in.
"""

from __future__ import annotations

import pytest

pytest.importorskip("aiodocker")

from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

if TYPE_CHECKING:
    pass


#: The 4 canonical Sprint-8A images. Until the supply-chain pipeline
#: at Sprint 14 publishes the real cosign-signed digests, these are
#: PLACEHOLDER refs that can never resolve in a real Docker daemon.
#: The autouse preflight below skips with a structured message naming
#: the missing ref. Updating these to real digests is a Sprint-14
#: deployment-kit task, NOT a T10 sub-task workaround.
_CANONICAL_SPRINT_8A_IMAGES = (
    "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    "cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
    "cognic/sandbox-runtime-data:v1@sha256:" + "c" * 64,
    "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
)


@pytest.fixture
async def docker_client():
    """Real Docker AsyncClient against host daemon. Auto-closed on
    fixture teardown so the asyncio event loop releases the
    connection cleanly between tests."""
    import aiodocker

    client = aiodocker.Docker()
    try:
        yield client
    finally:
        await client.close()


@pytest.fixture(autouse=True)
async def _canonical_artifact_preflight(request: pytest.FixtureRequest) -> None:
    """Per ``feedback_canonical_artifact_not_oss_substitute``:
    canonical artifacts MUST be real shippable images at the sprint
    that declares them canonical. A missing canonical image at
    env-gated test time → ``pytest.skip`` with a structured message
    naming the missing ref, NEVER silent OSS substitution.

    Probes each canonical image via ``docker_client.images.inspect``
    (no-op on hit; raises DockerError on miss). On first miss, skips
    the test with the exact ref + a pointer to the Sprint-14 deploy
    kit that publishes the real digests.

    Autouse=True so every test in this directory gets the preflight
    without each test having to opt in. **Short-circuits without
    opening a Docker connection** when
    ``COGNIC_RUN_DOCKER_SANDBOX`` is unset — non-env-gated unit tests
    (cap_derivation / exec_classification / pure_helpers) share this
    conftest but must NOT trigger a daemon-pull every test. The
    env-gated test FILES carry their own pytestmark skipif as the
    primary gate; this autouse is the secondary canonical-image
    gate for tests that do reach it.
    """
    import os

    if os.environ.get("COGNIC_RUN_DOCKER_SANDBOX") != "1":
        return

    # Lazy-acquire docker_client only when the env-gated lane is
    # active. Without the env flag, non-env-gated tests in this
    # directory must NOT pay the cost of opening a Docker connection.
    import aiodocker

    docker_client = request.getfixturevalue("docker_client")
    for ref in _CANONICAL_SPRINT_8A_IMAGES:
        try:
            await docker_client.images.inspect(ref)
        except aiodocker.exceptions.DockerError as e:
            pytest.skip(
                f"canonical artifact {ref!r} not pullable from local "
                f"docker daemon ({e}); env-gated T10 integration test "
                f"requires the canonical Sprint-8A image catalog to be "
                f"pre-pulled. Real cosign-signed digests are published "
                f"by the Sprint-14 deployment kit; until then this test "
                f"correctly skips fail-loud. Do NOT substitute an OSS "
                f"image (mitmproxy/tinyproxy/etc) masquerading as the "
                f"canonical name — that would break the chain of trust "
                f"per feedback_canonical_artifact_not_oss_substitute. "
                f"Set COGNIC_USE_LOCAL_FIXTURE_PROXY=1 ONLY for "
                f"clearly-named local fixtures."
            )


@pytest.fixture
def catalog(tmp_path):
    """In-memory catalog preloaded with the 4 canonical Sprint-8A images.

    Per ``feedback_canonical_artifact_not_oss_substitute``, the digests
    are PLACEHOLDERS until Sprint 14. The
    ``_canonical_artifact_preflight`` autouse fixture above probes
    each ref + skips with a structured message when any is missing.
    """
    from cognic_agentos.sandbox.catalog import CanonicalImageCatalog

    trust_root = tmp_path / "cognic-cosign.pub"
    trust_root.write_text("# fixture trust root for env-gated DockerSibling tests")
    return CanonicalImageCatalog(
        canonical_refs=frozenset(_CANONICAL_SPRINT_8A_IMAGES),
        tenant_trust_roots={"t-1": trust_root},
        tenant_allow_lists={"t-1": frozenset()},
    )


@pytest.fixture
async def backend(docker_client, catalog):
    """Real DockerSiblingSandboxBackend wired against host Docker
    daemon + the fixture catalog + in-memory audit + decision-history
    stores. Tests assume cosign + syft are mocked at the catalog
    seam via monkeypatch.setattr in each test method so the
    env-gated tests don't actually shell out to cosign + syft
    binaries."""
    from sqlalchemy.ext.asyncio import create_async_engine

    from cognic_agentos.core.audit import AuditStore
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    from cognic_agentos.sandbox import KernelDefaultCredentialAdapter
    from cognic_agentos.sandbox.backends.docker_sibling import (
        DockerSiblingSandboxBackend,
    )

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    rego = AsyncMock()
    decision = MagicMock()
    decision.allow = True
    decision.reasoning = ""
    rego.evaluate = AsyncMock(return_value=decision)
    settings = MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
    )
    return DockerSiblingSandboxBackend(
        docker_client=docker_client,
        image_catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        audit_store=AuditStore(engine=engine),
        decision_history_store=DecisionHistoryStore(engine=engine),
        settings=settings,
        warm_pool=None,
    )
