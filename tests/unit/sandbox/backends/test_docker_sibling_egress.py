"""Sprint 8A T10c — env-gated egress integration against real Docker
daemon + the canonical proxy image.

ENV-GATED: skipped unless ``COGNIC_RUN_DOCKER_SANDBOX=1`` AND a
Docker daemon is reachable AND the canonical Sprint-8A image
catalog is pre-pulled (autouse preflight in conftest.py).

Per spec §10.2-10.4 + the canonical-artifact doctrine: the
production proxy image is the cosign-signed canonical
``cognic/sandbox-egress-proxy:v1@sha256:...``. OSS substitutes
(tinyproxy / mitmproxy / etc.) are allowed only INSIDE the
canonical image OR as clearly-named local fixtures behind
``COGNIC_USE_LOCAL_FIXTURE_PROXY=1`` env flag (deferred to
Sprint 14 deployment kit). The conftest preflight skips
fail-loud if the canonical image is not pullable.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock

import pytest

pytest.importorskip("aiodocker")

from cognic_agentos.sandbox import (
    PackAdmissionContext,
    SandboxPolicy,
    SandboxPolicyViolated,
    sandbox_session,
)

if TYPE_CHECKING:
    from cognic_agentos.sandbox.backends.docker_sibling import (
        DockerSiblingSandboxBackend,
    )

pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_DOCKER_SANDBOX") != "1",
    reason=(
        "Docker daemon + cognic/sandbox-egress-proxy image required — "
        "set COGNIC_RUN_DOCKER_SANDBOX=1 to run"
    ),
)


_TEST_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)


def _mock_catalog_verify(monkeypatch: pytest.MonkeyPatch, backend: object) -> None:
    """Bypass cosign + SBOM at the catalog seam — T6 owns the real
    subprocess impl tests."""
    from cognic_agentos.sandbox.catalog import CosignVerifyResult, SBOMVerifyResult

    monkeypatch.setattr(
        backend._catalog,  # type: ignore[attr-defined]
        "_run_cosign_verify",
        AsyncMock(return_value=CosignVerifyResult(passed=True)),
    )
    monkeypatch.setattr(
        backend._catalog,  # type: ignore[attr-defined]
        "_run_syft_inspect",
        AsyncMock(return_value=SBOMVerifyResult(passed=True)),
    )


class TestEgressEnforcement:
    @pytest.mark.asyncio
    async def test_allow_listed_host_returns_2xx(
        self,
        backend: DockerSiblingSandboxBackend,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """allow_list=('httpbin.org',) → curl httpbin.org/status/200
        in the runtime-shell image returns exit code 0; proxy_log
        on the exec_completed chain row carries an ``allowed``
        record per spec §10.3."""
        _mock_catalog_verify(monkeypatch, backend)
        policy = SandboxPolicy(
            cpu_cores=0.5,
            cpu_time_budget_s=None,
            memory_mb=128,
            walltime_s=15.0,
            runtime_image="cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
            egress_allow_list=("httpbin.org",),
            vault_path=None,
        )
        actor = MagicMock()
        actor.subject = "test-subject"
        async with sandbox_session(
            backend,
            policy,
            actor=actor,
            tenant_id="t-1",
            pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        ) as s:
            result = await s.exec(
                [
                    "curl",
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "https://httpbin.org/status/200",
                ]
            )
        assert result.exit_code == 0
        assert b"200" in result.stdout
        # proxy_log carries the allow record per spec §10.3
        assert any(
            rec.host == "httpbin.org" and rec.outcome == "allowed" for rec in result.proxy_log
        )

    @pytest.mark.asyncio
    async def test_non_allow_listed_host_refused_via_proxy(
        self,
        backend: DockerSiblingSandboxBackend,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """allow_list=('only-this.example',) → curl evil.example.com
        → proxy refuses with 403; AgentOS reads the refusal record
        from proxy_log + raises SandboxPolicyViolated per spec §7
        line 501 + §10.4."""
        _mock_catalog_verify(monkeypatch, backend)
        policy = SandboxPolicy(
            cpu_cores=0.5,
            cpu_time_budget_s=None,
            memory_mb=128,
            walltime_s=15.0,
            runtime_image="cognic/sandbox-runtime-shell:v1@sha256:" + "b" * 64,
            egress_allow_list=("only-this.example",),
            vault_path=None,
        )
        actor = MagicMock()
        actor.subject = "test-subject"
        with pytest.raises(SandboxPolicyViolated) as exc:
            async with sandbox_session(
                backend,
                policy,
                actor=actor,
                tenant_id="t-1",
                pack_context=_TEST_PACK_CTX,
                use_warm_pool=False,
            ) as s:
                await s.exec(["curl", "-sS", "https://evil.example.com/get"])
        assert exc.value.reason == "egress_host_not_allow_listed"

    @pytest.mark.asyncio
    async def test_raw_tcp_blocked_at_network_layer_no_proxy_log(
        self,
        backend: DockerSiblingSandboxBackend,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Per spec §10.4: raw TCP attempts (NOT through the HTTP
        proxy) get ENETUNREACH from the kernel because the internal
        network has no gateway. The proxy never sees the attempt →
        NO proxy_log entry, NO sandbox.policy.violated event in
        Wave-1. Workload exits with user code reflecting the
        connection failure."""
        _mock_catalog_verify(monkeypatch, backend)
        policy = SandboxPolicy(
            cpu_cores=0.5,
            cpu_time_budget_s=None,
            memory_mb=128,
            walltime_s=10.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=("httpbin.org",),
            vault_path=None,
        )
        actor = MagicMock()
        actor.subject = "test-subject"
        async with sandbox_session(
            backend,
            policy,
            actor=actor,
            tenant_id="t-1",
            pack_context=_TEST_PACK_CTX,
            use_warm_pool=False,
        ) as s:
            # Raw TCP to port 6379 (Redis) — bypasses HTTP proxy
            result = await s.exec(
                [
                    "python",
                    "-c",
                    (
                        "import socket, sys\n"
                        "s = socket.socket(); s.settimeout(3)\n"
                        "try:\n"
                        "    s.connect(('8.8.8.8', 6379))\n"
                        "    print('CONNECTED')\n"
                        "except OSError as e:\n"
                        "    print(f'BLOCKED: {e.errno}')\n"
                        "    sys.exit(1)\n"
                    ),
                ]
            )
        # Network-layer block surfaces as user-code exit; NOT a
        # SandboxPolicyViolated raise (per spec §10.4 Wave-1 stance
        # — raw-protocol attempts are blocked but not per-attempt
        # audited).
        assert result.exit_code == 1
        assert b"BLOCKED" in result.stdout
        # No proxy_log entry for this attempt (proxy never saw it)
        assert not any("8.8.8.8" in r.host for r in result.proxy_log)
