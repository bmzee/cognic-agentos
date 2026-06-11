"""Sprint 13.5c1 — sandbox seam cross-surface e2e on a migrated DB.

Admission pending -> 13.5b1 HTTP grant -> re-admission admits, with
``approval_verified=True`` attested into the Step-9 Rego input. The
REAL-bundle Rego arm lives in tests/unit/policies/test_sandbox_rego.py
(opa-gated); this e2e mocks Rego to assert the attested input contract.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine
from starlette.requests import Request

from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.core.policy.engine import Decision
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox.admission import KernelDefaultCredentialAdapter, admit_policy
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

# -- helpers (copied: test_approval_seam.py fixtures + test_mcp_seam_e2e.py binder) --


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Request) -> Actor:
        return self._actor


def _make_actor(*, scopes: frozenset[str]) -> Actor:
    return Actor(
        subject="rev@bank.example",
        tenant_id="t-1",
        scopes=scopes,  # type: ignore[arg-type]
        actor_type="human",
    )


class _StubApprovalPolicy:
    def __init__(self, flow: str = "require_single_approval") -> None:
        self._flow = flow

    async def classify(self, *, risk_tier: str) -> str:
        return self._flow


_VALID_IMAGE_REF = "ghcr.io/cognic/sandbox-runtime-python@sha256:" + "c" * 64


def _valid_policy() -> SandboxPolicy:
    return SandboxPolicy(
        cpu_cores=1.0,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image=_VALID_IMAGE_REF,
        egress_allow_list=("api.example.com",),
        vault_path=None,
    )


def _valid_pack_context() -> PackAdmissionContext:
    return PackAdmissionContext(
        pack_id="cognic.test_pack",
        pack_version="v1.0.0",
        pack_artifact_digest="sha256:" + "a" * 64,
        risk_tier="payment_action",
        declares_dynamic_install=False,
        profile="production",
        data_classes=("payment_data",),
    )


def _passing_settings() -> Any:
    return MagicMock(
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=1024,
        sandbox_per_tenant_max_walltime=300.0,
        sandbox_kernel_default_max_credential_ttl_s=900,
    )


async def _mk_approval_store(tmp_path: Any) -> ApprovalRequestStore:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'sandbox-e2e.db'}"
    cfg = make_alembic_config(url)
    await asyncio.to_thread(command.upgrade, cfg, "head")
    return ApprovalRequestStore(DecisionHistoryStore(create_async_engine(url)))


def _mk_approval_engine(store: ApprovalRequestStore, *, flow: str) -> ApprovalEngine:
    return ApprovalEngine(
        policy=_StubApprovalPolicy(flow),
        store=store,
        settings=build_settings_without_env_file(),
        clock=lambda: datetime(2026, 6, 11, 12, 0, tzinfo=UTC),
    )


def _admit_kwargs() -> dict[str, Any]:
    """All-green admit_policy kwargs; actor carries a REAL str subject — the
    envelope digests it."""
    rego = MagicMock()
    rego.evaluate = AsyncMock(
        return_value=Decision(
            allow=True,
            rule_matched="data.cognic.sandbox.admit.allow",
            reasoning="ok",
            decision_data=None,
        )
    )
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.is_tenant_allow_listed.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    return dict(
        tenant_id="t-1",
        actor=MagicMock(subject="agent-1"),
        pack_context=_valid_pack_context(),
        catalog=catalog,
        credential_adapter=KernelDefaultCredentialAdapter(),
        rego_engine=rego,
        settings=_passing_settings(),
    )


async def test_admission_pending_http_grant_readmit_admits(tmp_path: Any) -> None:
    # The cross-surface e2e (spec §7): seam pending -> 13.5b1 portal grant
    # over HTTP -> re-admission admits and attests the verified grant into
    # the Step-9 Rego input.
    store = await _mk_approval_store(tmp_path)
    engine = _mk_approval_engine(store, flow="require_single_approval")
    kwargs = _admit_kwargs()
    with pytest.raises(SandboxLifecycleRefused) as exc:
        await admit_policy(_valid_policy(), **kwargs, approval_engine=engine)
    assert exc.value.reason == "sandbox_approval_pending"
    assert exc.value.approval_request_id is not None
    rid = uuid.UUID(exc.value.approval_request_id)

    reviewer = _make_actor(scopes=frozenset({"tool.approve.payment"}))
    app = create_app(
        actor_binder=_StubBinder(reviewer), approval_store=store, approval_engine=engine
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
        resp = await client.post(f"/api/v1/approvals/{rid}/grant", json={})
        assert resp.status_code == 200
        assert resp.json()["state"] == "granted"

    await admit_policy(_valid_policy(), **kwargs, approval_engine=engine, approval_request_id=rid)
    sent = kwargs["rego_engine"].evaluate.await_args.kwargs["input"]
    assert sent["approval_verified"] is True
