"""Governed dispatch conformance — the gates, refusal feedback, and evidence.

Package scope discipline is in :mod:`tests.integration.agent_loop` — every
PROVEN bullet below is backed by an assertion in this module.

PROVEN:

* the REAL dispatch chokepoint runs through ``build_agent_loop``'s composed
  ``AgentDispatcher``, over the REAL ``AssignmentStore`` / ``EntitlementStore``
  on a migrated database seeded through the real tables;
* **gate 1** — a capability the bank never assigned refuses
  ``agent_capability_not_assigned``, BEFORE any policy consult (so this runs
  without opa);
* **gate 2** — an assigned capability whose data scope is not entitled refuses
  ``agent_scope_not_entitled``, also pre-policy;
* **refusals do not terminate the run** — they return to the model as tool
  messages and the loop continues, which is the ADR-027 shape;
* **evidence** — exactly ONE ``agent.run.dispatch`` row per dispatch, carrying
  digests and never the question, answer, or raw arguments;
* the decision-history chain VERIFIES after the run.

SUBSTITUTED (inherited from the package, plus):

* the model is a ``ScriptedGateway`` — determinism is the point;
* the MCP tool proxy is a recording stub: an allowed dispatch's *execution* is
  not a real tool call. What is real is every governed decision before it.

NOT PROVEN HERE: the allow path's end-to-end tool execution, and query-context
minting (no signing key is configured in these fixtures).
"""

from __future__ import annotations

import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncEngine

import cognic_agentos.harness.agent_host as agent_host
from cognic_agentos.core.agent.assignments import _agent_assignments
from cognic_agentos.core.agent.loop import AgentLoop
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.chain_verifier import ChainVerifier
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history
from cognic_agentos.core.entitlements.store import _data_scopes, _entitlements
from cognic_agentos.llm.gateway import GatewayResponse, GatewayToolCall

from ._synthetic import (
    DEFAULT_AGENT_ID,
    DEFAULT_DIST,
    DEFAULT_PACKAGE,
    DEFAULT_VERSION,
    TOOL_DIST,
    TOOL_NAME,
    TOOL_REF,
    FakeDist,
    LoopRuntime,
    LoopSettings,
    Registry,
    ScriptedGateway,
    candidate,
    pack_record_files,
    tool_candidate,
    tool_pack_record_files,
    write_agent_pack,
    write_tool_pack,
)

opa_required = pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not installed")

TENANT = "t-conformance"
SUBJECT = "analyst.conformance"
QUESTION = "PLAINTEXT-QUESTION-MUST-NOT-APPEAR-IN-EVIDENCE"
ANSWER = "PLAINTEXT-ANSWER-MUST-NOT-APPEAR-IN-EVIDENCE"
SCOPE_ID = "conformance-scope"


def _response(content: str, *, tool_calls: tuple[GatewayToolCall, ...] = ()) -> GatewayResponse:
    return GatewayResponse(
        content=content,
        upstream_model="scripted/none",
        api_base=None,
        external=False,
        request_id="req-conformance",
        tier="tier1",
        latency_ms=0,
        tool_calls=tool_calls,
        usage={"prompt_tokens": 1, "completion_tokens": 1},
    )


class _RecordingMemoryApi:
    """Task-tier memory sink. The loop writes a best-effort digest note at the
    end of a run; a non-callable factory would only log a warning and leave
    that path silently unexercised."""

    def __init__(self) -> None:
        self.remembered: list[dict[str, Any]] = []

    async def remember(self, **kwargs: Any) -> None:
        self.remembered.append(dict(kwargs))


class _RecordingToolProxy:
    """Records governed tool invocations. Nothing here executes a real tool —
    the point is to observe whether a dispatch reached execution AT ALL."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def call_tool(self, **kwargs: Any) -> Any:
        self.calls.append(dict(kwargs))
        return {"ok": True, "rows": []}


async def _seed_assignment(engine: AsyncEngine, *, kind: str, ref: str) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sa.insert(_agent_assignments).values(
                id=uuid.uuid4(),
                tenant_id=TENANT,
                agent_id=DEFAULT_AGENT_ID,
                capability_kind=kind,
                capability_ref=ref,
                created_at=datetime.now(UTC),
            )
        )


async def _seed_scope_and_entitlement(engine: AsyncEngine, *, entitled: bool) -> None:
    async with engine.begin() as conn:
        await conn.execute(
            sa.insert(_data_scopes).values(
                tenant_id=TENANT,
                scope_id=SCOPE_ID,
                schema_name="CONFORMANCE",
                objects=["THINGS"],
                proxy_db_identity="conformance_proxy",
                created_at=datetime.now(UTC),
            )
        )
        if entitled:
            await conn.execute(
                sa.insert(_entitlements).values(
                    id=uuid.uuid4(),
                    tenant_id=TENANT,
                    subject=SUBJECT,
                    scope_id=SCOPE_ID,
                    created_at=datetime.now(UTC),
                )
            )


async def _build(
    engine: AsyncEngine,
    dists: list[Any],
    tmp_path: Path,
    gateway: ScriptedGateway,
    proxy: _RecordingToolProxy,
) -> AgentLoop:
    root = tmp_path / "site-packages"
    write_agent_pack(root)
    write_tool_pack(root)
    dists.append(
        FakeDist(
            name=DEFAULT_DIST,
            version=DEFAULT_VERSION,
            root=root,
            files=pack_record_files(DEFAULT_PACKAGE),
        )
    )
    # The TOOL pack supplies the signed capability-class map entry
    # ``conformance-server/conformance_query -> data_query``; without it the
    # dispatcher fail-closes on a missing declaration rather than reaching the
    # entitlement gate.
    dists.append(
        FakeDist(
            name=TOOL_DIST,
            version=DEFAULT_VERSION,
            root=root,
            files=tool_pack_record_files(),
        )
    )
    loop, warnings, _ = await agent_host.build_agent_loop(
        runtime=LoopRuntime(
            llm_gateway=gateway,
            memory_api_factory=lambda _ctx: _RecordingMemoryApi(),
            audit_store=AuditStore(engine),
            decision_history_store=DecisionHistoryStore(engine),
        ),
        settings=LoopSettings(),
        registry=Registry([candidate(), tool_candidate()]),
        mcp_host=proxy,
        engine=engine,
    )
    assert isinstance(loop, AgentLoop) and warnings == []
    # Substitute the tool proxy so an ALLOWED dispatch is observable without a
    # live MCP server. Every gate under test runs BEFORE this is reached.
    loop._dispatcher._tool_proxy = proxy
    return loop


async def _dispatch_rows(engine: AsyncEngine) -> list[Any]:
    async with engine.begin() as conn:
        return list(
            (
                await conn.execute(
                    sa.select(_decision_history).where(
                        _decision_history.c.event_type == "agent.run.dispatch"
                    )
                )
            ).all()
        )


class TestPrePolicyGates:
    """Gate 1 and gate 2 refuse BEFORE the Rego consult, so these run
    unconditionally — a deployment without opa still gets them."""

    async def test_unassigned_capability_refuses_and_does_not_execute(
        self, engine: AsyncEngine, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        await _seed_scope_and_entitlement(engine, entitled=True)
        # NOTE: no assignment seeded — the bank never granted this capability.
        proxy = _RecordingToolProxy()
        gateway = ScriptedGateway(
            [
                _response(
                    "",
                    tool_calls=(
                        GatewayToolCall(id="c1", name="read_skill", arguments={"skill_id": "x"}),
                    ),
                ),
                _response(ANSWER),
            ]
        )
        loop = await _build(engine, metadata_env, tmp_path, gateway, proxy)

        result = await loop.ask(
            agent_id=DEFAULT_AGENT_ID,
            question=QUESTION,
            actor_tenant_id=TENANT,
            actor_subject=SUBJECT,
        )

        rows = await _dispatch_rows(engine)
        assert len(rows) == 1, "exactly one dispatch row per dispatch"
        assert rows[0].payload["refusal_reason"] == "agent_capability_not_assigned"
        assert proxy.calls == [], "a refused dispatch must never reach execution"
        # The run CONTINUES — a refusal is feedback to the model, not a kill.
        assert result.terminal_state == "completed"

    async def test_refusal_is_fed_back_to_the_model_as_a_tool_message(
        self, engine: AsyncEngine, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        """ADR-027 shape: the model must SEE the refusal and get another round."""
        await _seed_scope_and_entitlement(engine, entitled=True)
        proxy = _RecordingToolProxy()
        gateway = ScriptedGateway(
            [
                _response(
                    "",
                    tool_calls=(
                        GatewayToolCall(id="c1", name="read_skill", arguments={"skill_id": "x"}),
                    ),
                ),
                _response(ANSWER),
            ]
        )
        loop = await _build(engine, metadata_env, tmp_path, gateway, proxy)

        await loop.ask(
            agent_id=DEFAULT_AGENT_ID,
            question=QUESTION,
            actor_tenant_id=TENANT,
            actor_subject=SUBJECT,
        )

        assert len(gateway.calls) == 2, "the loop must take a second round after a refusal"
        second_round = gateway.calls[1]["messages"]
        tool_messages = [m for m in second_round if m.get("role") == "tool"]
        assert tool_messages, "the refusal must be visible to the model"
        assert any(
            "agent_capability_not_assigned" in str(m.get("content", "")) for m in tool_messages
        )

    async def test_assigned_tool_without_entitlement_refuses_at_gate_two(
        self, engine: AsyncEngine, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        """Assignment is necessary but NOT sufficient.

        The bank assigned the tool, and the data scope exists — but this
        subject holds no entitlement to it. Gate 2 must refuse, and it must do
        so before execution. This is the arm that separates "the agent may use
        this capability" from "this human may see this data".
        """
        await _seed_assignment(engine, kind="tool", ref=TOOL_REF)
        await _seed_scope_and_entitlement(engine, entitled=False)
        proxy = _RecordingToolProxy()
        gateway = ScriptedGateway(
            [
                _response(
                    "",
                    tool_calls=(
                        GatewayToolCall(
                            id="c1",
                            name=TOOL_NAME,
                            arguments={"scope_id": SCOPE_ID, "sql": "select 1", "max_rows": 5},
                        ),
                    ),
                ),
                _response(ANSWER),
            ]
        )
        loop = await _build(engine, metadata_env, tmp_path, gateway, proxy)

        await loop.ask(
            agent_id=DEFAULT_AGENT_ID,
            question=QUESTION,
            actor_tenant_id=TENANT,
            actor_subject=SUBJECT,
        )

        rows = await _dispatch_rows(engine)
        assert len(rows) == 1
        assert rows[0].payload["refusal_reason"] == "agent_scope_not_entitled"
        assert proxy.calls == [], "an unentitled dispatch must never execute"


class TestEvidenceIsDigestOnly:
    """ADR-027 §f — chain rows carry digests, never plaintext."""

    async def test_dispatch_row_carries_no_plaintext_and_the_chain_verifies(
        self, engine: AsyncEngine, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        await _seed_scope_and_entitlement(engine, entitled=True)
        proxy = _RecordingToolProxy()
        gateway = ScriptedGateway(
            [
                _response(
                    "",
                    tool_calls=(
                        GatewayToolCall(
                            id="c1",
                            name="read_skill",
                            arguments={"skill_id": "SECRET-ARGUMENT-VALUE"},
                        ),
                    ),
                ),
                _response(ANSWER),
            ]
        )
        loop = await _build(engine, metadata_env, tmp_path, gateway, proxy)

        await loop.ask(
            agent_id=DEFAULT_AGENT_ID,
            question=QUESTION,
            actor_tenant_id=TENANT,
            actor_subject=SUBJECT,
        )

        async with engine.begin() as conn:
            blob = "".join(
                str(r.payload) for r in (await conn.execute(sa.select(_decision_history))).all()
            )
        assert QUESTION not in blob, "question plaintext leaked into evidence"
        assert ANSWER not in blob, "answer plaintext leaked into evidence"
        assert "SECRET-ARGUMENT-VALUE" not in blob, "raw tool arguments leaked into evidence"

        rows = await _dispatch_rows(engine)
        assert len(rows[0].payload["args_sha256"]) == 64

        report = await ChainVerifier(engine, chain_id="decision_history").walk()
        assert report.is_clean is True, report.detail
        assert report.records_checked > 0, "a vacuous walk proves nothing"
