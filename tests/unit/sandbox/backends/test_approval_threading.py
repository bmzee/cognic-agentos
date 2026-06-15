"""Sprint 14A-A2b — both backends thread approval_engine + approval_request_id
into the COLD-CREATE admit_policy (cross-backend lockstep). The wake path is
deliberately NOT threaded in this slice (checkpoint->wake is deferred).

admit_policy is patched to capture-and-raise so create() short-circuits right at
the admission call — with use_warm_pool=False + warm_pool=None + no credentials,
create() reaches admit_policy without touching the (MagicMock) client.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy

pytestmark = pytest.mark.asyncio

_ACTOR = Actor(subject="svc", tenant_id="t-1", scopes=frozenset(), actor_type="service")
_POLICY = SandboxPolicy(
    cpu_cores=1.0,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=(),
    vault_path=None,
)
_PACK_CTX = PackAdmissionContext(
    pack_id="cognic-tool-foo",
    pack_version="1.0.0",
    pack_artifact_digest="ab" * 32,
    risk_tier="read_only",
    declares_dynamic_install=False,
    profile="production",
)


class _StopCreate(Exception):
    """Sentinel raised by the patched admit_policy to short-circuit create()
    right after admission (no post-admission topology work)."""


def _settings() -> Any:
    return MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
    )


def _make_docker_backend(approval_engine: Any) -> Any:
    from cognic_agentos.sandbox.backends.docker_sibling import DockerSiblingSandboxBackend

    return DockerSiblingSandboxBackend(
        docker_client=MagicMock(),
        image_catalog=MagicMock(),
        credential_adapter=MagicMock(),
        rego_engine=MagicMock(),
        audit_store=MagicMock(),
        decision_history_store=MagicMock(),
        settings=_settings(),
        warm_pool=None,
        approval_engine=approval_engine,
    )


def _make_k8s_backend(approval_engine: Any) -> Any:
    from cognic_agentos.sandbox.backends.kubernetes_pod import KubernetesPodSandboxBackend

    return KubernetesPodSandboxBackend(
        kube_api_client=MagicMock(),
        namespace="cognic-sandbox",
        image_catalog=MagicMock(),
        credential_adapter=MagicMock(),
        rego_engine=MagicMock(),
        audit_store=MagicMock(),
        decision_history_store=MagicMock(),
        settings=_settings(),
        warm_pool=None,
        approval_engine=approval_engine,
    )


@pytest.mark.parametrize(
    "module_path,make_backend",
    [
        ("cognic_agentos.sandbox.backends.docker_sibling", _make_docker_backend),
        ("cognic_agentos.sandbox.backends.kubernetes_pod", _make_k8s_backend),
    ],
)
async def test_create_threads_approval_into_cold_admit_policy(
    module_path: str, make_backend: Any
) -> None:
    sentinel_engine = object()
    backend = make_backend(sentinel_engine)
    arid = uuid.uuid4()
    admit_mock = AsyncMock(side_effect=_StopCreate())

    with patch(f"{module_path}.admit_policy", new=admit_mock), pytest.raises(_StopCreate):
        await backend.create(
            _POLICY,
            actor=_ACTOR,
            tenant_id="t-1",
            pack_context=_PACK_CTX,
            use_warm_pool=False,
            approval_request_id=arid,
        )

    admit_mock.assert_awaited_once()
    await_args = admit_mock.await_args
    assert await_args is not None
    kwargs = await_args.kwargs
    assert kwargs["approval_engine"] is sentinel_engine
    assert kwargs["approval_request_id"] == arid
