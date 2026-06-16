"""Sprint 14A-A2b — both backends thread approval_engine + approval_request_id
into the COLD-CREATE admit_policy (cross-backend lockstep).

Sprint 14A-A3c (T2) extends the threading to the WAKE path: ``wake()`` now also
threads ``approval_engine`` + ``approval_request_id`` into its Step-4
``admit_policy`` revalidation, AND the wake refusal-collapse wrapper exempts the
approval family (``_APPROVAL_WAKE_PASSTHROUGH_REASONS``) so the executor sees
``sandbox_approval_pending`` + the ``approval_request_id`` un-rewrapped, while
genuine revalidation refusals still collapse to
``sandbox_wake_policy_revalidation_failed``. The earlier "wake is deliberately
NOT threaded" fence is INVERTED by this slice.

admit_policy is patched to capture-and-raise so create() / wake() short-circuit
right at the admission call. For cold-create: use_warm_pool=False + warm_pool=None
+ no credentials reaches admit_policy without touching the (MagicMock) client. For
wake: a stub checkpoint_store (load_tombstone→None, load_latest→(metadata, bytes))
drives the pipeline to Step 4 (admit_policy) without any backend resource work.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.protocol import (
    _APPROVAL_WAKE_PASSTHROUGH_REASONS,
    CheckpointId,
    SandboxLifecycleRefused,
    SandboxRefusalReason,
)

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


# ===========================================================================
# Sprint 14A-A3c (T2) — WAKE-path approval threading + wrapper exemption.
# ===========================================================================
#
# The wake pipeline reaches its Step-4 ``admit_policy`` revalidation through a
# checkpoint-store lookup (load_tombstone→None, load_latest→(metadata, bytes)).
# We stub that store with AsyncMocks + a REAL ``CheckpointMetadata`` (so wake's
# ``metadata.policy`` / ``.pack_context`` / ``.tenant_id`` / ``.created_at`` /
# ``.retention_window_s`` field accesses exercise the genuine attribute surface)
# then patch the module-level ``admit_policy`` to record-and-raise (threading
# test) or raise a refusal (passthrough / collapse tests).

# The five approval-family reasons that MUST pass through the wake wrapper
# un-rewrapped (mirror of the protocol.py single-source constant). Typed as the
# closed Literal so the SandboxLifecycleRefused(reason, ...) call site is
# type-clean under mypy.
_APPROVAL_REASONS: list[SandboxRefusalReason] = [
    "sandbox_approval_pending",
    "sandbox_approval_denied",
    "sandbox_approval_expired",
    "sandbox_approval_request_not_found",
    "sandbox_approval_binding_mismatch",
]


class _StopWake(Exception):
    """Sentinel raised by the recording admit_policy so wake() short-circuits
    right after the Step-4 admission call (no post-admission resource work)."""


def _make_metadata() -> Any:
    """A REAL CheckpointMetadata (tenant t-1, fresh, 1-day retention) so wake's
    field accesses are genuine, not MagicMock auto-attributes."""
    from cognic_agentos.sandbox.checkpoint_store import CheckpointMetadata

    return CheckpointMetadata(
        checkpoint_id=CheckpointId(uuid.uuid4().hex),
        session_id="s",
        tenant_id="t-1",
        label="__suspend__",
        created_at=datetime.now(UTC),
        policy=_POLICY,
        pack_context=_PACK_CTX,
        retention_window_s=86_400,
    )


def _stub_checkpoint_store() -> Any:
    """A checkpoint store whose tombstone/latest lookups drive wake() straight
    to Step 4 (no tombstone; valid fresh same-tenant metadata)."""
    store = AsyncMock()
    store.load_tombstone = AsyncMock(return_value=None)
    store.load_latest = AsyncMock(return_value=(_make_metadata(), b"tar-bytes"))
    return store


def _make_docker_backend_wake(approval_engine: Any) -> Any:
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
        checkpoint_store=_stub_checkpoint_store(),
        approval_engine=approval_engine,
    )


def _make_k8s_backend_wake(approval_engine: Any) -> Any:
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
        checkpoint_store=_stub_checkpoint_store(),
        approval_engine=approval_engine,
    )


_WAKE_BACKENDS = [
    ("cognic_agentos.sandbox.backends.docker_sibling", _make_docker_backend_wake),
    ("cognic_agentos.sandbox.backends.kubernetes_pod", _make_k8s_backend_wake),
]


@pytest.mark.parametrize("module_path,make_backend", _WAKE_BACKENDS)
async def test_wake_threads_approval_engine_and_request_id(
    module_path: str, make_backend: Any
) -> None:
    """wake() Step-4 admit_policy is threaded with self._approval_engine +
    the request-time approval_request_id (lockstep with cold-create)."""
    sentinel_engine = object()
    backend = make_backend(sentinel_engine)
    req_id = uuid.uuid4()
    admit_mock = AsyncMock(side_effect=_StopWake())

    with patch(f"{module_path}.admit_policy", new=admit_mock), pytest.raises(_StopWake):
        await backend.wake("s", actor=_ACTOR, tenant_id="t-1", approval_request_id=req_id)

    admit_mock.assert_awaited_once()
    await_args = admit_mock.await_args
    assert await_args is not None
    kwargs = await_args.kwargs
    assert kwargs["approval_engine"] is sentinel_engine
    assert kwargs["approval_request_id"] == req_id


@pytest.mark.parametrize("module_path,make_backend", _WAKE_BACKENDS)
@pytest.mark.parametrize("reason", _APPROVAL_REASONS)
async def test_wake_approval_refusal_passes_through_uncollapsed(
    module_path: str, make_backend: Any, reason: SandboxRefusalReason
) -> None:
    """An approval-family refusal raised by Step-4 admit_policy passes through
    the wake wrapper un-rewrapped — reason + approval_request_id intact — so the
    executor can map sandbox_approval_pending → 202 (and read the correlator)."""
    backend = make_backend(object())
    admit_mock = AsyncMock(side_effect=SandboxLifecycleRefused(reason, approval_request_id="R"))
    with (
        patch(f"{module_path}.admit_policy", new=admit_mock),
        pytest.raises(SandboxLifecycleRefused) as exc,
    ):
        await backend.wake("s", actor=_ACTOR, tenant_id="t-1", approval_request_id=uuid.uuid4())
    assert exc.value.reason == reason  # NOT collapsed
    assert exc.value.approval_request_id == "R"


@pytest.mark.parametrize("module_path,make_backend", _WAKE_BACKENDS)
async def test_wake_nonapproval_refusal_still_collapses(
    module_path: str, make_backend: Any
) -> None:
    """A genuine (non-approval) revalidation refusal STILL collapses to
    sandbox_wake_policy_revalidation_failed, with the original reason in detail."""
    backend = make_backend(object())
    admit_mock = AsyncMock(
        side_effect=SandboxLifecycleRefused("sandbox_image_digest_not_in_canonical_catalog")
    )
    with (
        patch(f"{module_path}.admit_policy", new=admit_mock),
        pytest.raises(SandboxLifecycleRefused) as exc,
    ):
        await backend.wake("s", actor=_ACTOR, tenant_id="t-1", approval_request_id=None)
    assert exc.value.reason == "sandbox_wake_policy_revalidation_failed"  # still collapsed
    assert "sandbox_image_digest_not_in_canonical_catalog" in (exc.value.detail or "")


async def test_both_backends_import_the_same_passthrough_constant() -> None:
    """Cross-backend lockstep: both backends bind the SAME exemption-set object
    from protocol.py (the single source of truth — no per-backend drift).

    ``async`` only to satisfy the module-level ``pytestmark = asyncio``; the body
    is a pure-synchronous identity + equality assertion."""
    from cognic_agentos.sandbox.backends import docker_sibling as _ds
    from cognic_agentos.sandbox.backends import kubernetes_pod as _kp

    # Both backends import the private constant from protocol.py; accessing it via
    # the module is a cross-module private name, which mypy's re-export rule flags
    # (attr-defined). Capture into locals — the `is` identity check below IS the
    # lockstep assertion (one shared frozenset object, no per-backend drift).
    ds_const = _ds._APPROVAL_WAKE_PASSTHROUGH_REASONS  # type: ignore[attr-defined]
    kp_const = _kp._APPROVAL_WAKE_PASSTHROUGH_REASONS  # type: ignore[attr-defined]
    assert ds_const is _APPROVAL_WAKE_PASSTHROUGH_REASONS
    assert kp_const is _APPROVAL_WAKE_PASSTHROUGH_REASONS
    # The constant is exactly the five approval-family reasons.
    assert frozenset(_APPROVAL_REASONS) == _APPROVAL_WAKE_PASSTHROUGH_REASONS
