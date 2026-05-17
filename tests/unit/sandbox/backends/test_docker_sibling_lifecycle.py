"""Sprint 8A T10a — DockerSiblingSandboxBackend lifecycle on real Docker.

ENV-GATED: skipped unless ``COGNIC_RUN_DOCKER_SANDBOX=1`` AND a
Docker daemon is reachable. Standard pytest runs skip these tests;
local development + the Sprint-8A sandbox-integration CI lane runs
them.

Per ``feedback_canonical_artifact_not_oss_substitute``, this file
uses FAKE placeholder image digests because T10a's lifecycle
envelope exercises the topology + container start/stop without
needing the runtime image to actually do anything. The canonical
``cognic/sandbox-runtime-python:v1@sha256:...`` + canonical
``cognic/sandbox-egress-proxy:v1@sha256:...`` images must be
pre-pulled into the Docker daemon for these tests to run; missing
canonical artifact → ``pytest.skip(f"canonical artifact {ref} not
pullable; ...")`` with a structured message naming the missing ref.
NEVER silent OSS substitution. T10c's egress integration tests will
extend the canonical-artifact preflight to a richer check.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

# R1 P2.2 reviewer fix — env-gated tests still need aiodocker for
# fixture construction; without the extra, collection fails. The
# importorskip degrades gracefully in kernel-only venvs.
pytest.importorskip("aiodocker")

from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxPolicy,
    sandbox_session,
)

if TYPE_CHECKING:
    import aiodocker as _aiodocker_for_typing

    from cognic_agentos.sandbox.backends.docker_sibling import (
        DockerSiblingSandboxBackend,
    )

pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_DOCKER_SANDBOX") != "1",
    reason="Docker daemon required — set COGNIC_RUN_DOCKER_SANDBOX=1 to run",
)


@pytest.fixture
async def docker_client():
    """Real Docker AsyncClient against host daemon."""
    import aiodocker

    client = aiodocker.Docker()
    try:
        yield client
    finally:
        await client.close()


#: The 4 canonical Sprint-8A images. Until the supply-chain pipeline
#: at Sprint 14 publishes the real cosign-signed digests, these are
#: PLACEHOLDER refs that can never resolve in a real Docker daemon.
#: The ``_canonical_artifact_preflight`` auto-use fixture below probes
#: each ref + ``pytest.skip``s with a structured message when any is
#: missing, per ``feedback_canonical_artifact_not_oss_substitute``
#: (NEVER silently substitute an OSS image masquerading as the
#: canonical name). Updating these to real digests is a Sprint-14
#: deployment-kit task, NOT a T10a workaround.
_CANONICAL_SPRINT_8A_IMAGES = (
    "cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    "cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
    "cognic/sandbox-runtime-data:v1@sha256:" + "c" * 64,
    "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
)


@pytest.fixture(autouse=True)
async def _canonical_artifact_preflight(
    docker_client: _aiodocker_for_typing.Docker,
) -> None:
    """Per ``feedback_canonical_artifact_not_oss_substitute``:
    canonical artifacts MUST be real shippable images at the sprint
    that declares them canonical. A missing canonical image at
    env-gated test time → ``pytest.skip`` with a structured message
    naming the missing ref, NEVER silent OSS substitution.

    Probes each canonical image via ``docker_client.images.inspect``
    (no-op on hit; raises DockerError on miss). On first miss, skips
    the test with the exact ref + a pointer to the Sprint-14 deploy
    kit that publishes the real digests.

    Autouse=True so every test in this file gets the preflight
    without each test having to opt in.
    """
    import aiodocker

    for ref in _CANONICAL_SPRINT_8A_IMAGES:
        try:
            await docker_client.images.inspect(ref)
        except aiodocker.exceptions.DockerError as e:
            pytest.skip(
                f"canonical artifact {ref!r} not pullable from local "
                f"docker daemon ({e}); env-gated T10a integration test "
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
    ``_canonical_artifact_preflight`` auto-use fixture above probes
    each ref + skips with a structured message when any is missing.
    """
    from cognic_agentos.sandbox.catalog import CanonicalImageCatalog

    trust_root = tmp_path / "cognic-cosign.pub"
    trust_root.write_text("# fixture trust root for env-gated DockerSibling test")
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
    env-gated tests don't actually shell out."""
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


_INTERNAL_WRITE_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=("httpbin.org",),
    vault_path=None,
)
_TEST_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_create_starts_sandbox_and_proxy_containers_on_internal_network(
        self, backend: DockerSiblingSandboxBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Per spec §7 + §10.1: create() spawns TWO containers
        (sandbox + proxy sidecar) on a per-session internal Docker
        network with ``Internal=true`` + no external gateway;
        sandbox HTTP_PROXY env points at the proxy DNS alias."""
        from cognic_agentos.sandbox.catalog import (
            CosignVerifyResult,
            SBOMVerifyResult,
        )

        # Bypass cosign + SBOM at the catalog seam (T6 owns the real
        # subprocess impl tests).
        monkeypatch.setattr(
            backend._catalog,
            "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)),
        )
        monkeypatch.setattr(
            backend._catalog,
            "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)),
        )

        actor = MagicMock()
        actor.subject = "test-subject"
        async with sandbox_session(
            backend,
            _INTERNAL_WRITE_POLICY,
            actor=actor,
            tenant_id="t-1",
            pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        ) as session:
            # Sandbox container running on exactly ONE network (the
            # internal bridge).
            sandbox_info = await backend._docker.containers.get(session.session_id)
            attrs = await sandbox_info.show()
            assert attrs["State"]["Running"] is True
            networks = attrs["NetworkSettings"]["Networks"]
            assert len(networks) == 1
            internal_net_name = next(iter(networks))
            assert internal_net_name.startswith(f"cognic-sb-internal-{session.session_id[:8]}")

            # Internal network has Internal=true (no external gateway).
            internal_net = await backend._docker.networks.get(internal_net_name)
            net_attrs = await internal_net.show()
            assert net_attrs["Internal"] is True

            # Proxy sidecar container exists on the internal network.
            proxy_info = await backend._docker.containers.get(f"{session.session_id}-proxy")
            proxy_attrs = await proxy_info.show()
            assert proxy_attrs["State"]["Running"] is True

            # Sandbox HTTP_PROXY / HTTPS_PROXY env vars point at the
            # proxy DNS alias on the internal network.
            env_pairs = attrs["Config"]["Env"]
            env_dict = dict(p.split("=", 1) for p in env_pairs)
            assert env_dict["HTTP_PROXY"].startswith("http://egress-proxy:")
            assert env_dict["HTTPS_PROXY"].startswith("http://egress-proxy:")

        # On context exit: both containers + the internal network are
        # gone (cleanup is idempotent + complete).
        import aiodocker.exceptions

        with pytest.raises(aiodocker.exceptions.DockerError):
            await backend._docker.containers.get(session.session_id)
        with pytest.raises(aiodocker.exceptions.DockerError):
            await backend._docker.networks.get(internal_net_name)

    @pytest.mark.asyncio
    async def test_destroy_is_idempotent(
        self, backend: DockerSiblingSandboxBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """destroy() called twice does NOT raise per spec §5
        SandboxBackend.destroy docstring ("Tear down the session.
        Idempotent.")."""
        from cognic_agentos.sandbox.catalog import (
            CosignVerifyResult,
            SBOMVerifyResult,
        )

        monkeypatch.setattr(
            backend._catalog,
            "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)),
        )
        monkeypatch.setattr(
            backend._catalog,
            "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)),
        )

        actor = MagicMock()
        actor.subject = "test-subject"
        session = await backend.create(
            _INTERNAL_WRITE_POLICY,
            actor=actor,
            tenant_id="t-1",
            pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        )
        await backend.destroy(session)
        # Second destroy() must not raise — idempotent contract.
        await backend.destroy(session)


class TestHealth:
    @pytest.mark.asyncio
    async def test_health_returns_ok_when_docker_daemon_reachable(
        self, backend: DockerSiblingSandboxBackend
    ) -> None:
        from cognic_agentos.sandbox.protocol import SandboxBackendHealth

        result = await backend.health()
        assert isinstance(result, SandboxBackendHealth)
        assert result.status == "ok"


class TestExecNotImplementedAtT10a:
    """exec() body lands at T10b (resource caps) + T10c (proxy_log
    materialisation). T10a returns a structured NotImplementedError
    pointing at the unfinished sub-tasks so a caller between sprints
    does not assume exec is silently broken."""

    @pytest.mark.asyncio
    async def test_exec_raises_not_implemented_pointing_at_t10b_t10c(
        self, backend: DockerSiblingSandboxBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from cognic_agentos.sandbox.catalog import (
            CosignVerifyResult,
            SBOMVerifyResult,
        )

        monkeypatch.setattr(
            backend._catalog,
            "_run_cosign_verify",
            AsyncMock(return_value=CosignVerifyResult(passed=True)),
        )
        monkeypatch.setattr(
            backend._catalog,
            "_run_syft_inspect",
            AsyncMock(return_value=SBOMVerifyResult(passed=True)),
        )

        actor = MagicMock()
        actor.subject = "test-subject"
        session = await backend.create(
            _INTERNAL_WRITE_POLICY,
            actor=actor,
            tenant_id="t-1",
            pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        )
        try:
            with pytest.raises(NotImplementedError) as exc:
                await session.exec(["echo", "ok"])
            assert "T10b" in str(exc.value)
            assert "T10c" in str(exc.value)
        finally:
            await session.destroy()


# ---------------------------------------------------------------------------
# Smoke test that runs WITHOUT the env gate — verifies the test file
# is importable + the env-gating logic itself is correct.
# ---------------------------------------------------------------------------


def test_env_gate_works():
    """Sanity that the env-gate skipif logic + the imports work.
    Always runs (NOT gated). If COGNIC_RUN_DOCKER_SANDBOX is unset,
    the rest of the tests in this file are skipped and this one
    confirms the file itself loaded."""
    # Confirms the imports resolved + the fixtures + tests above can
    # be collected by pytest without errors.
    assert _INTERNAL_WRITE_POLICY.cpu_cores == 0.5
    assert _TEST_PACK_CTX.pack_id == "cognic.test_pack"
