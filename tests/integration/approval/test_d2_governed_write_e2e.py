"""M8.5-D D2 Phase-C governed-write walk on a migrated database."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from contextlib import AsyncExitStack
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine
from starlette.requests import Request

from cognic_agentos.core.agent._types import LoadedAgentRecord
from cognic_agentos.core.agent.action_context import (
    ACTION_CONTEXT_ARGUMENT,
    verify_action_context,
)
from cognic_agentos.core.agent.assignments import AssignmentStore, _agent_assignments
from cognic_agentos.core.agent.dispatch import AgentDispatcher
from cognic_agentos.core.agent.loop import AgentLoop
from cognic_agentos.core.agent.policy import AgentDispatchPolicy
from cognic_agentos.core.approval.assignments import ApprovalAssignmentStore
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.approval.executor import ApprovalExecutionService
from cognic_agentos.core.approval.replay import ApprovalReplayStore
from cognic_agentos.core.approval.storage import ApprovalRequestStore
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.conversation.read_model import ConversationReadModel
from cognic_agentos.core.conversation.storage import ConversationStore, _conversation_turns
from cognic_agentos.core.conversation.turn import ConversationTurnExecutor
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history
from cognic_agentos.core.entitlements.store import EntitlementStore, _action_entitlements
from cognic_agentos.core.policy.engine import Decision
from cognic_agentos.harness.agent_host import _MCPHostAgentToolProxy
from cognic_agentos.llm.gateway import GatewayResponse, GatewayToolCall
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.mcp_authz import MCPAuthzClient, Token
from cognic_agentos.protocol.mcp_transports import MCPSession, MCPToolCallRequest

_TENANT = "tenant-a"
_AGENT = "bank-agent"
_ORIGINATOR = "analyst.amir"
_ASSIGNMENT_ADMIN = "admin.zoe"
_APPROVERS = ("approver.dana", "approver.erin", "approver.zara")
_SERVER = "cognic-tool-approval-probe"
_TOOL = "probe_write"
_TOOL_REF = f"{_SERVER}/{_TOOL}"
_NOW = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)
_ARGUMENTS = {"account_id": "acct-7", "amount": 125}


class _SingleApprovalPolicy:
    async def classify(self, *, risk_tier: str) -> str:
        assert risk_tier == "high_risk_custom"
        return "require_single_approval"


class _AllowOPA:
    async def evaluate(self, *, decision_point: str, input: dict[str, Any]) -> Decision:
        return Decision(
            allow=True,
            rule_matched=decision_point,
            reasoning="phase-c integration allow",
            decision_data=None,
        )


class _RecordLoader:
    async def load_for_agent(self, *, agent_id: str, tenant_id: str) -> LoadedAgentRecord | None:
        if (agent_id, tenant_id) != (_AGENT, _TENANT):
            return None
        persona = "You are a governed bank agent."
        return LoadedAgentRecord(
            agent_id=_AGENT,
            persona_body=persona,
            persona_sha256=hashlib.sha256(persona.encode()).hexdigest(),
            requested_skills=(),
            requested_tools=(_TOOL_REF,),
            max_steps=2,
            risk_tier="high_risk_custom",
            pack_version="0.1.0",
            signed_artefact_digest="sha256:phase-c",
            registered=True,
        )


class _OneActionGateway:
    def __init__(self) -> None:
        self.calls = 0

    async def completion(self, **kwargs: Any) -> GatewayResponse:
        self.calls += 1
        assert self.calls == 1
        assert {tool.name for tool in kwargs["tools"]} >= {_TOOL}
        return GatewayResponse(
            content="",
            upstream_model="test/model",
            api_base=None,
            external=False,
            request_id="gateway-phase-c",
            tier="tier1",
            latency_ms=1,
            tool_calls=(GatewayToolCall(id="call-1", name=_TOOL, arguments=dict(_ARGUMENTS)),),
            usage={"prompt_tokens": 7, "completion_tokens": 3},
        )


class _NoSkills:
    def read(self, skill_id: str) -> None:
        return None


class _MemoryAPI:
    async def remember(self, *args: Any, **kwargs: Any) -> uuid.UUID:
        return uuid.uuid4()


class _MemoryFactory:
    def __call__(self, context: Any) -> _MemoryAPI:
        return _MemoryAPI()


class _HeaderActorBinder:
    def bind(self, *, request: Request) -> Actor:
        subject = request.headers["x-test-subject"]
        if subject == _ORIGINATOR:
            scopes = frozenset(
                {
                    "conversation.create",
                    "conversation.read",
                    "conversation.post_turn",
                    "mcp.tool.invoke",
                    "tool.approve.high_risk_custom",
                }
            )
        elif subject in _APPROVERS:
            scopes = frozenset({"tool.approve.high_risk_custom"})
        elif subject == _ASSIGNMENT_ADMIN:
            scopes = frozenset({"tool.approve.assign"})
        else:  # pragma: no cover - test setup guard
            raise AssertionError(f"unknown test subject: {subject}")
        return Actor(
            subject=subject,
            tenant_id=_TENANT,
            scopes=scopes,  # type: ignore[arg-type]
            actor_type="human",
        )


class _RecordingTransport:
    def __init__(self) -> None:
        self.requests: list[MCPToolCallRequest] = []

    async def open_session(self, *, server_url: str, token: Token) -> MCPSession:
        return MCPSession(
            server_url=server_url,
            sdk_session=object(),
            exit_stack=AsyncExitStack(),
            get_session_id=lambda: "phase-c-session",
            token_scopes=token.scopes,
            token_client_id=token.client_id,
        )

    async def send(self, session: MCPSession, request: Any) -> dict[str, Any]:
        assert isinstance(request, MCPToolCallRequest)
        self.requests.append(request)
        return {"structuredContent": {"status": "applied", "write_id": "write-1"}}

    async def close_session(self, session: MCPSession) -> None:
        session.closed = True


def _keypair() -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


async def _migrated_engine(tmp_path: Path) -> AsyncEngine:
    from alembic import command

    from cognic_agentos.db.migrations.alembic_config import make_alembic_config

    url = f"sqlite+aiosqlite:///{tmp_path / 'd2-phase-c.db'}"
    await asyncio.to_thread(command.upgrade, make_alembic_config(url), "head")
    return create_async_engine(url)


async def _seed_authority(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            insert(_agent_assignments).values(
                id=uuid.uuid4(),
                tenant_id=_TENANT,
                agent_id=_AGENT,
                capability_kind="tool",
                capability_ref=_TOOL_REF,
                created_at=_NOW,
            )
        )
        await conn.execute(
            insert(_action_entitlements).values(
                id=uuid.uuid4(),
                tenant_id=_TENANT,
                subject=_ORIGINATOR,
                tool_identity=_TOOL_REF,
                created_at=_NOW,
            )
        )


async def test_governed_write_pending_grant_execute_and_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cognic_agentos.protocol import mcp_host as host_module

    monkeypatch.setattr(host_module, "require_mcp", MagicMock())
    engine = await _migrated_engine(tmp_path)
    try:
        await _seed_authority(engine)
        settings = build_settings_without_env_file()
        history = DecisionHistoryStore(engine)
        approval_store = ApprovalRequestStore(history)
        approval_assignments = ApprovalAssignmentStore(history)
        approval_engine = ApprovalEngine(
            policy=_SingleApprovalPolicy(),
            store=approval_store,
            settings=settings,
            clock=lambda: _NOW,
            assignments=approval_assignments,
        )

        authz = MagicMock(spec=MCPAuthzClient)
        authz.acquire_token = AsyncMock(
            return_value=Token(
                value="phase-c-token",
                expires_at=_NOW.timestamp() + 3600,
                as_issuer="https://as.example",
                scopes=("probe:write",),
                resource_indicator="https://probe.example/mcp",
                client_id="phase-c-client",
            )
        )
        transport = _RecordingTransport()
        entry = host_module.MCPServerEntry(
            server_id=_SERVER,
            server_url="https://probe.example/mcp",
            transport_kind="http",
            manifest_scopes=("probe:write",),
            risk_tier="high_risk_custom",
            pack_signature_digest="sha256:probe",
            data_classes=("internal",),
        )
        host = host_module.MCPHost(
            servers={_SERVER: entry},
            transports={"http": cast(Any, transport)},
            authz=authz,
            audit_store=AuditStore(engine),
            decision_history_store=history,
            settings=settings,
            approval_engine=approval_engine,
        )

        gateway = _OneActionGateway()
        reader = _NoSkills()
        memory = _MemoryFactory()
        dispatcher = AgentDispatcher(
            entitlements=EntitlementStore(engine),
            policy=AgentDispatchPolicy(opa_engine=cast(Any, _AllowOPA())),
            tool_proxy=_MCPHostAgentToolProxy(host),
            skill_reader=reader,
            memory_factory=memory,
            decision_history=history,
            query_context_signing_key_pem=None,
            query_context_ttl_s=300,
            tool_capability_classes={_TOOL_REF: "action"},
        )
        loop = AgentLoop(
            record_loader=_RecordLoader(),
            assignments=AssignmentStore(engine),
            gateway=cast(Any, gateway),
            dispatcher=dispatcher,
            tool_capability_classes={_TOOL_REF: "action"},
            skill_reader=reader,
            memory_factory=memory,
            decision_history=history,
            default_max_steps=2,
            run_token_budget=1000,
            run_wall_clock_s=30,
        )
        conversation_store = ConversationStore(engine)
        conversation_executor = ConversationTurnExecutor(
            store=conversation_store,
            loop=loop,
            max_turns=10,
            cumulative_token_budget=10_000,
            replay_last_n=10,
            replay_token_ceiling=10_000,
            claim_ttl_s=60,
            agent_run_wall_clock_s=30,
            clock=lambda: _NOW,
        )
        private_key, public_key = _keypair()
        approval_executor = ApprovalExecutionService(
            engine=approval_engine,
            replay_store=ApprovalReplayStore(engine),
            tool_proxy=host,
            conversation_completer=conversation_executor,
            decision_history=history,
            signing_key=private_key,
            settings=settings,
            clock=lambda: _NOW,
        )

        app = create_app(
            settings=settings,
            actor_binder=_HeaderActorBinder(),
            approval_store=approval_store,
            approval_engine=approval_engine,
            approval_assignment_store=approval_assignments,
            approval_executor=approval_executor,
        )
        app.state.conversation_store = conversation_store
        app.state.conversation_executor = conversation_executor
        app.state.mcp_host = host
        app.state.conversation_read_model = ConversationReadModel(
            engine,
            chain_candidate_limit=100,
        )
        app.state.hosted_agents = [{"agent_id": _AGENT}]

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://phase-c",
        ) as client:
            originator_headers = {"x-test-subject": _ORIGINATOR}
            tool_identity = host_module._canonical_tool_identity(
                server_id=_SERVER,
                tool_name=_TOOL,
            )
            assigned = await client.put(
                f"/api/v1/approvals/assignments/{tool_identity}",
                headers={"x-test-subject": _ASSIGNMENT_ADMIN},
                json={"approver_subjects": list(_APPROVERS)},
            )
            assert assigned.status_code == 200
            assert assigned.json()["required_count"] == 3

            created = await client.post(
                "/api/v1/conversations",
                headers=originator_headers,
                json={"agent_id": _AGENT},
            )
            assert created.status_code == 201
            conversation_id = uuid.UUID(created.json()["conversation_id"])

            pending = await client.post(
                f"/api/v1/conversations/{conversation_id}/turns",
                headers=originator_headers,
                json={"user_message": "Apply the approved account update."},
            )
            assert pending.status_code == 200
            assert pending.json()["terminal_state"] == "pending_approval"
            approval_request_id = uuid.UUID(pending.json()["approval_request_id"])
            assert gateway.calls == 1
            assert transport.requests == []

            originator_first = await client.post(
                f"/api/v1/approvals/{approval_request_id}/grant",
                headers=originator_headers,
                json={},
            )
            assert originator_first.status_code == 409
            assert originator_first.json()["detail"]["reason"] == "originator_cannot_approve"

            first = await client.post(
                f"/api/v1/approvals/{approval_request_id}/grant",
                headers={"x-test-subject": _APPROVERS[0]},
                json={},
            )
            assert first.status_code == 200
            assert first.json() == {
                "request_id": str(approval_request_id),
                "state": "awaiting_second",
            }
            assert transport.requests == []

            originator_later = await client.post(
                f"/api/v1/approvals/{approval_request_id}/grant",
                headers=originator_headers,
                json={},
            )
            assert originator_later.status_code == 409
            assert originator_later.json()["detail"]["reason"] == "four_eyes_approver_not_distinct"

            second = await client.post(
                f"/api/v1/approvals/{approval_request_id}/grant",
                headers={"x-test-subject": _APPROVERS[1]},
                json={},
            )
            assert second.status_code == 200
            assert second.json() == {
                "request_id": str(approval_request_id),
                "state": "awaiting_second",
            }
            assert transport.requests == []

            granted = await client.post(
                f"/api/v1/approvals/{approval_request_id}/grant",
                headers={"x-test-subject": _APPROVERS[2]},
                json={},
            )
            assert granted.status_code == 200
            assert granted.json()["state"] == "granted"
            assert granted.json()["execution"] == "executed"
            assert len(transport.requests) == 1

            sent = transport.requests[0]
            assert sent.name == _TOOL
            assert sent.arguments is not None
            sent_arguments = dict(sent.arguments)
            action_token = sent_arguments.pop(ACTION_CONTEXT_ARGUMENT)
            assert canonical_bytes(sent_arguments) == canonical_bytes(_ARGUMENTS)
            claims = verify_action_context(
                token=action_token,
                public_keys_pem=[public_key],
                expected_aud=_TOOL_REF,
                now=int(_NOW.timestamp()),
            )
            assert claims.approval_request_id == str(approval_request_id)
            assert claims.args_sha256 == hashlib.sha256(canonical_bytes(_ARGUMENTS)).hexdigest()
            assert claims.sub == _ORIGINATOR
            assert claims.act == _AGENT
            assert claims.tenant_id == _TENANT
            assert claims.action_id == _TOOL_REF

            transcript = await client.get(
                f"/api/v1/conversations/{conversation_id}/transcript",
                headers=originator_headers,
            )
            assert transcript.status_code == 200
            assert [row["turn_kind"] for row in transcript.json()["turns"]] == [
                "exchange",
                "system",
            ]
            assert transcript.json()["turns"][1]["answer"].startswith("Approved and executed.")

            retried = await client.post(
                f"/api/v1/approvals/{approval_request_id}/grant",
                headers={"x-test-subject": _APPROVERS[2]},
                json={},
            )
            assert retried.status_code == 200
            assert retried.json()["execution"] == "already_executed"
            assert len(transport.requests) == 1

            consumed = await client.post(
                f"/api/v1/mcp/servers/{_SERVER}/tools/call",
                headers=originator_headers,
                json={
                    "tool_name": _TOOL,
                    "arguments": _ARGUMENTS,
                    "approval_request_id": str(approval_request_id),
                },
            )
            assert consumed.status_code == 409
            assert consumed.json()["detail"]["reason"] == "tool_approval_consumed"
            assert len(transport.requests) == 1

        replayed = await conversation_store.load_replay_turns(
            conversation_id,
            tenant_id=_TENANT,
            last_n=10,
        )
        assert len(replayed) == 1
        assert replayed[0].turn_kind == "exchange"

        async with engine.connect() as conn:
            turns = (
                (
                    await conn.execute(
                        select(_conversation_turns)
                        .where(_conversation_turns.c.conversation_id == conversation_id)
                        .order_by(_conversation_turns.c.seq)
                    )
                )
                .mappings()
                .all()
            )
            decision_rows = (
                (
                    await conn.execute(
                        select(
                            _decision_history.c.event_type,
                            _decision_history.c.payload,
                        )
                        .where(_decision_history.c.tenant_id == _TENANT)
                        .order_by(_decision_history.c.sequence)
                    )
                )
                .mappings()
                .all()
            )
        assert [row["turn_kind"] for row in turns] == ["exchange", "system"]
        event_types = {str(row["event_type"]) for row in decision_rows}
        assert {
            "approval.requested",
            "approval.granted_first",
            "approval.granted_second",
            "approval.grant_recorded",
            "approval.consumed",
            "approval.executed",
            "agent.run.pending_approval",
            "conversation.turn_completed",
            "conversation.system_turn_appended",
        } <= event_types
        approval_execution_events = [
            row
            for row in decision_rows
            if row["event_type"]
            in {
                "approval.requested",
                "approval.granted_first",
                "approval.granted_second",
                "approval.grant_recorded",
                "approval.consumed",
                "approval.executed",
            }
        ]
        assert [row["event_type"] for row in approval_execution_events] == [
            "approval.requested",
            "approval.granted_first",
            "approval.granted_second",
            "approval.grant_recorded",
            "approval.consumed",
            "approval.executed",
        ]
        grant_recorded = approval_execution_events[3]["payload"]
        assert grant_recorded["decision_index"] == 2
        assert grant_recorded["required_count"] == 3
    finally:
        await engine.dispose()
