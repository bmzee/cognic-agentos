"""Governed dispatch conformance — the gates, refusal feedback, and evidence.

Package scope discipline is in :mod:`tests.integration.agent_loop` — every
PROVEN bullet below is backed by an assertion in this module.

PROVEN:

* the REAL dispatch chokepoint runs through ``build_agent_loop``'s composed
  ``AgentDispatcher``, over the REAL ``AssignmentStore`` / ``EntitlementStore``
  on a migrated database seeded through the real tables;
* **gate 1** — a manifest-requested capability the bank never assigned refuses
  ``agent_capability_not_assigned``, BEFORE any policy consult (so this runs
  without opa);
* **gate 2** — an assigned tool refuses when its scope is not entitled or
  cannot resolve; an entitled, resolvable scope reaches policy and execution,
  proving both EntitlementStore reads are live;
* **gate 3** — the composed dispatcher receives both an allow and a deny from
  the shipped ``agents.rego`` under real OPA; the allow reaches execution and
  the step-bound deny returns ``agent_policy_denied``;
* **refusals do not terminate the run** — they return to the model as tool
  messages and the loop continues, which is the ADR-027 shape;
* **evidence** — exactly ONE ``agent.run.dispatch`` row per dispatch, carrying
  the exact canonical argument digest and never the question, answer, or raw
  arguments;
* the decision-history chain VERIFIES after the run.
* the production ``LLMGateway`` rejects a non-finite model-authored argument
  before the composed dispatcher is awaited, leaving a chain-valid failed run
  and no dispatch row.

SUBSTITUTED (inherited from the package, plus):

* dispatch-gate tests use a ``ScriptedGateway`` — determinism is the point.
  The non-finite ingress test below is the exception and constructs the real
  ``LLMGateway`` over a mock HTTP transport;
* the MCP tool proxy is a recording stub. A positive dispatch reaches that
  proxy, proving the execution arm is wired, but no real MCP server executes;
* a generated RSA private key exists only under ``tmp_path`` so the positive
  data-query dispatch can exercise the real query-context mint. Key custody,
  downstream token verification, and a real governed query are not claimed.

NOT PROVEN HERE: a real MCP invocation, tool-side query-context verification,
or database query.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy.ext.asyncio import AsyncEngine

import cognic_agentos.harness.agent_host as agent_host
from cognic_agentos.core.agent.assignments import _agent_assignments
from cognic_agentos.core.agent.dispatch import (
    _QUERY_CONTEXT_ARG,
    AgentRunContext,
)
from cognic_agentos.core.agent.loop import AgentLoop
from cognic_agentos.core.agent.query_context import verify_query_context
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.chain_verifier import ChainVerifier
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore, _decision_history
from cognic_agentos.core.entitlements.store import _data_scopes, _entitlements
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import GatewayResponse, GatewayToolCall, LLMGateway
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.preflight import PreflightResolver

from ._synthetic import (
    DEFAULT_AGENT_ID,
    DEFAULT_DIST,
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
    tool_candidate,
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

    def __init__(self, *, result: Any = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._result = {"ok": True, "rows": []} if result is None else result

    async def call_tool(self, **kwargs: Any) -> Any:
        self.calls.append(dict(kwargs))
        return self._result


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


async def _seed_scope_and_entitlement(
    engine: AsyncEngine,
    *,
    entitled: bool,
    include_scope: bool = True,
    objects: Any = None,
) -> None:
    async with engine.begin() as conn:
        if include_scope:
            await conn.execute(
                sa.insert(_data_scopes).values(
                    tenant_id=TENANT,
                    scope_id=SCOPE_ID,
                    schema_name="CONFORMANCE",
                    objects=["THINGS"] if objects is None else objects,
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
    gateway: Any,
    proxy: _RecordingToolProxy,
    *,
    capability_class: str = "data_query",
    signing_key_path: str | None = None,
) -> AgentLoop:
    root = tmp_path / "site-packages"
    write_agent_pack(root)
    write_tool_pack(root, capability_class=capability_class)
    dists.append(
        FakeDist(
            name=DEFAULT_DIST,
            version=DEFAULT_VERSION,
            root=root,
        )
    )
    # The TOOL fixture supplies the post-trust capability-class map entry
    # ``conformance-server/conformance_query -> data_query``; without it the
    # dispatcher fail-closes on a missing declaration rather than reaching the
    # entitlement gate.
    dists.append(
        FakeDist(
            name=TOOL_DIST,
            version=DEFAULT_VERSION,
            root=root,
        )
    )
    loop, warnings, _ = await agent_host.build_agent_loop(
        runtime=LoopRuntime(
            llm_gateway=gateway,
            memory_api_factory=lambda _ctx: _RecordingMemoryApi(),
            audit_store=AuditStore(engine),
            decision_history_store=DecisionHistoryStore(engine),
        ),
        settings=LoopSettings(
            agent_query_context_signing_key_path=signing_key_path,
        ),
        registry=Registry([candidate(), tool_candidate()]),
        mcp_host=proxy,
        engine=engine,
    )
    assert isinstance(loop, AgentLoop) and warnings == []
    # ``build_agent_loop`` wrapped the recorder through the production
    # _MCPHostAgentToolProxy adapter. Do not replace that collaborator here:
    # the positive control must prove the composed execute seam is live.
    return loop


def _real_gateway_with_response(
    engine: AsyncEngine,
    tmp_path: Path,
    *,
    response_body: dict[str, Any],
) -> tuple[LLMGateway, httpx.AsyncClient, GatewayCallLedger]:
    """Construct the production gateway with only HTTP transport substituted."""
    config = tmp_path / "litellm-d1.yaml"
    config.write_text(
        "\n".join(
            [
                "model_list:",
                "  - model_name: cognic-tier1-dev",
                "    litellm_params:",
                "      model: ollama/qwen3:8b",
                "      api_base: http://ollama:11434",
                "litellm_settings: {}",
                "general_settings: {}",
                "",
            ]
        )
    )

    def _respond(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response_body)

    client = httpx.AsyncClient(transport=httpx.MockTransport(_respond))
    ledger = GatewayCallLedger(engine)
    gateway = LLMGateway(
        settings=Settings(
            allow_external_llm=False,
            policy_mode="self_hosted",
            allowed_providers=[],
            llm_guardrail_scope="all",
            llm_concurrency_per_profile=4,
            llm_concurrency_mode="queued",
            litellm_base_url="http://litellm.test:4000",
            litellm_master_key="sk-test-key",
        ),
        ledger=ledger,
        audit_store=AuditStore(engine),
        rate_limiter=ProfileRateLimiter(per_profile=4, mode="queued"),
        preflight=PreflightResolver.from_yaml(config),
        sla_policy=SLAPolicy(
            name="default",
            total_budget=timedelta(seconds=30),
            warning_threshold=timedelta(seconds=20),
        ),
        http_client=client,
    )
    return gateway, client, ledger


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


async def _event_rows(engine: AsyncEngine, event_type: str) -> list[Any]:
    async with engine.begin() as conn:
        return list(
            (
                await conn.execute(
                    sa.select(_decision_history).where(_decision_history.c.event_type == event_type)
                )
            ).all()
        )


async def _one_dispatch_row(engine: AsyncEngine) -> Any:
    rows = await _dispatch_rows(engine)
    assert len(rows) == 1, "exactly one agent.run.dispatch row per dispatch"
    return rows[0]


async def _run_context(loop: AgentLoop) -> AgentRunContext:
    record = await loop._record_loader.load_for_agent(
        agent_id=DEFAULT_AGENT_ID,
        tenant_id=TENANT,
    )
    assert record is not None
    granted = await loop._assignments.load_for_agent(
        tenant_id=TENANT,
        agent_id=DEFAULT_AGENT_ID,
        record=record,
    )
    return AgentRunContext(
        run_id=f"run-direct-{uuid.uuid4().hex}",
        tenant_id=TENANT,
        originator_subject=SUBJECT,
        agent_id=DEFAULT_AGENT_ID,
        granted=granted,
        max_steps=record.max_steps if record.max_steps is not None else loop._default_max_steps,
        record=record,
    )


@pytest.fixture
def signing_key(tmp_path: Path) -> tuple[str, bytes]:
    """A per-test RSA key so data-query dispatch can reach the execution arm."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path = tmp_path / "query-context-private.pem"
    path.write_bytes(private_pem)
    return str(path), public_pem


async def _policy_must_not_run(*_args: Any, **_kwargs: Any) -> Any:
    pytest.fail("pre-policy refusal consulted AgentDispatchPolicy.evaluate")


class TestPrePolicyGates:
    """Gate 1 and gate 2 refuse BEFORE the Rego consult, so these run
    unconditionally — a deployment without opa still gets them."""

    async def test_unassigned_capability_refuses_and_does_not_execute(
        self,
        engine: AsyncEngine,
        metadata_env: list[Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        await _seed_scope_and_entitlement(engine, entitled=True)
        # The manifest requests TOOL_REF, but no assignment row grants it.
        proxy = _RecordingToolProxy()
        gateway = ScriptedGateway(
            [
                _response(
                    "",
                    tool_calls=(
                        GatewayToolCall(
                            id="c1",
                            name=TOOL_NAME,
                            arguments={"scope_id": SCOPE_ID, "sql": "select 1"},
                        ),
                    ),
                ),
                _response(ANSWER),
            ]
        )
        loop = await _build(engine, metadata_env, tmp_path, gateway, proxy)
        monkeypatch.setattr(loop._dispatcher._policy, "evaluate", _policy_must_not_run)

        result = await loop.ask(
            agent_id=DEFAULT_AGENT_ID,
            question=QUESTION,
            actor_tenant_id=TENANT,
            actor_subject=SUBJECT,
        )

        row = await _one_dispatch_row(engine)
        assert row.payload["capability_ref"] == TOOL_NAME
        assert row.payload["refusal_reason"] == "agent_capability_not_assigned"
        assert proxy.calls == [], "a refused dispatch must never reach execution"
        # The run CONTINUES — a refusal is feedback to the model, not a kill.
        assert result.terminal_state == "completed"

    async def test_refusal_is_fed_back_to_the_model_as_a_tool_message(
        self,
        engine: AsyncEngine,
        metadata_env: list[Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """ADR-027 shape: the model must SEE the refusal and get another round."""
        await _seed_scope_and_entitlement(engine, entitled=True)
        proxy = _RecordingToolProxy()
        gateway = ScriptedGateway(
            [
                _response(
                    "",
                    tool_calls=(
                        GatewayToolCall(
                            id="c1",
                            name=TOOL_NAME,
                            arguments={"scope_id": SCOPE_ID, "sql": "select 1"},
                        ),
                    ),
                ),
                _response(ANSWER),
            ]
        )
        loop = await _build(engine, metadata_env, tmp_path, gateway, proxy)
        monkeypatch.setattr(loop._dispatcher._policy, "evaluate", _policy_must_not_run)

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
        self,
        engine: AsyncEngine,
        metadata_env: list[Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
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
        monkeypatch.setattr(loop._dispatcher._policy, "evaluate", _policy_must_not_run)

        await loop.ask(
            agent_id=DEFAULT_AGENT_ID,
            question=QUESTION,
            actor_tenant_id=TENANT,
            actor_subject=SUBJECT,
        )

        row = await _one_dispatch_row(engine)
        assert row.payload["refusal_reason"] == "agent_scope_not_entitled"
        assert proxy.calls == [], "an unentitled dispatch must never execute"

    async def test_entitled_but_unresolvable_scope_refuses_before_policy(
        self,
        engine: AsyncEngine,
        metadata_env: list[Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The entitlement ID alone is not authority: the scope must resolve."""
        await _seed_assignment(engine, kind="tool", ref=TOOL_REF)
        await _seed_scope_and_entitlement(
            engine,
            entitled=True,
            include_scope=False,
        )
        proxy = _RecordingToolProxy()
        gateway = ScriptedGateway()
        loop = await _build(engine, metadata_env, tmp_path, gateway, proxy)
        monkeypatch.setattr(loop._dispatcher._policy, "evaluate", _policy_must_not_run)

        outcome = await loop._dispatcher.dispatch(
            call=GatewayToolCall(
                id="c1",
                name=TOOL_NAME,
                arguments={"scope_id": SCOPE_ID, "sql": "select 1"},
            ),
            step_index=0,
            run=await _run_context(loop),
        )

        assert outcome.refused is True
        assert outcome.reason == "agent_scope_not_entitled"
        assert proxy.calls == []
        row = await _one_dispatch_row(engine)
        assert row.payload["scope_id"] == SCOPE_ID

    async def test_malformed_scope_objects_fail_closed_before_policy_or_execution(
        self,
        engine: AsyncEngine,
        metadata_env: list[Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Malformed persisted scope evidence raises; it never becomes a grant."""
        await _seed_assignment(engine, kind="tool", ref=TOOL_REF)
        await _seed_scope_and_entitlement(
            engine,
            entitled=True,
            objects={"unexpected": "mapping"},
        )
        proxy = _RecordingToolProxy()
        gateway = ScriptedGateway()
        loop = await _build(engine, metadata_env, tmp_path, gateway, proxy)
        monkeypatch.setattr(loop._dispatcher._policy, "evaluate", _policy_must_not_run)

        with pytest.raises(ValueError, match="must be a JSON list"):
            await loop._dispatcher.dispatch(
                call=GatewayToolCall(
                    id="c1",
                    name=TOOL_NAME,
                    arguments={"scope_id": SCOPE_ID, "sql": "select 1"},
                ),
                step_index=0,
                run=await _run_context(loop),
            )

        assert proxy.calls == []
        assert await _dispatch_rows(engine) == []


class TestRealPolicyGateAndExecution:
    """Gate 3 against the shipped bundle, after both upstream gates clear."""

    @opa_required
    async def test_entitled_data_query_is_allowed_stamped_and_executed(
        self,
        engine: AsyncEngine,
        metadata_env: list[Any],
        tmp_path: Path,
        signing_key: tuple[str, bytes],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        key_path, public_pem = signing_key
        await _seed_assignment(engine, kind="tool", ref=TOOL_REF)
        await _seed_scope_and_entitlement(engine, entitled=True)
        proxy = _RecordingToolProxy()
        loop = await _build(
            engine,
            metadata_env,
            tmp_path,
            ScriptedGateway(),
            proxy,
            signing_key_path=key_path,
        )
        real_resolve = loop._dispatcher._entitlements.resolve_scope
        resolve_spy = AsyncMock(wraps=real_resolve)
        monkeypatch.setattr(loop._dispatcher._entitlements, "resolve_scope", resolve_spy)
        raw_arguments = {
            "scope_id": SCOPE_ID,
            "sql": "select 'ALLOW-MARKER'",
            "max_rows": 5,
        }

        outcome = await loop._dispatcher.dispatch(
            call=GatewayToolCall(
                id="allow-call",
                name=TOOL_NAME,
                arguments=raw_arguments,
            ),
            step_index=0,
            run=await _run_context(loop),
        )

        assert outcome.refused is False
        assert outcome.reason is None
        assert outcome.result == {"ok": True, "rows": []}
        resolve_spy.assert_awaited_once_with(tenant_id=TENANT, scope_id=SCOPE_ID)

        assert len(proxy.calls) == 1, "the positive control must reach execution"
        proxied = proxy.calls[0]
        assert proxied["server_id"] == TOOL_DIST
        assert proxied["tool_name"] == TOOL_NAME
        assert proxied["tenant_id"] == TENANT
        assert proxied["originator_subject"] == SUBJECT
        assert proxied["approval_request_id"] is None
        assert proxied["request_id"].startswith("agent-tool-")
        assert raw_arguments == {
            "scope_id": SCOPE_ID,
            "sql": "select 'ALLOW-MARKER'",
            "max_rows": 5,
        }, "dispatch must not mutate the LLM-authored argument object"
        assert set(proxied["arguments"]) == {*raw_arguments, _QUERY_CONTEXT_ARG}
        stripped = {
            key: value for key, value in proxied["arguments"].items() if key != _QUERY_CONTEXT_ARG
        }
        assert stripped == raw_arguments

        claims = verify_query_context(
            token=proxied["arguments"][_QUERY_CONTEXT_ARG],
            public_keys_pem=[public_pem],
            expected_aud=TOOL_REF,
            now=int(time.time()),
        )
        expected_digest = hashlib.sha256(canonical_bytes(raw_arguments)).hexdigest()
        assert claims.sub == SUBJECT
        assert claims.act == DEFAULT_AGENT_ID
        assert claims.tenant_id == TENANT
        assert claims.scope_id == SCOPE_ID
        assert claims.objects == ("THINGS",)
        assert claims.proxy_db_identity == "conformance_proxy"
        assert claims.args_sha256 == expected_digest

        policy_rows = await _event_rows(engine, "policy.decision_evaluated")
        assert len(policy_rows) == 1
        assert policy_rows[0].payload["decision_point"] == ("data.cognic.agents.dispatch.allow")
        assert policy_rows[0].payload["outcome"] == "allow"
        assert (
            policy_rows[0].payload["bundle_sha256"]
            == hashlib.sha256(Path("policies/_default/agents.rego").read_bytes()).hexdigest()
        )

        row = await _one_dispatch_row(engine)
        assert row.payload["outcome"] == "ok"
        assert row.payload["refusal_reason"] is None
        assert row.payload["args_sha256"] == expected_digest

    @opa_required
    async def test_non_finite_tool_result_becomes_one_evidenced_safe_refusal(
        self,
        engine: AsyncEngine,
        metadata_env: list[Any],
        tmp_path: Path,
        signing_key: tuple[str, bytes],
    ) -> None:
        """A side effect may finish, but its uncanonicalizable result may not
        escape before the single digest-only refusal row is committed."""
        key_path, _public_pem = signing_key
        await _seed_assignment(engine, kind="tool", ref=TOOL_REF)
        await _seed_scope_and_entitlement(engine, entitled=True)
        proxy = _RecordingToolProxy(result={"value": float("nan")})
        gateway = ScriptedGateway(
            [
                _response(
                    "",
                    tool_calls=(
                        GatewayToolCall(
                            id="non-finite-result",
                            name=TOOL_NAME,
                            arguments={"scope_id": SCOPE_ID, "sql": "select 1"},
                        ),
                    ),
                ),
                _response(ANSWER),
            ]
        )
        loop = await _build(
            engine,
            metadata_env,
            tmp_path,
            gateway,
            proxy,
            signing_key_path=key_path,
        )

        result = await loop.ask(
            agent_id=DEFAULT_AGENT_ID,
            question=QUESTION,
            actor_tenant_id=TENANT,
            actor_subject=SUBJECT,
        )

        assert result.terminal_state == "completed"
        assert len(proxy.calls) == 1, (
            "the proxy invocation completed exactly once before returning the noncanonical result"
        )
        assert len(gateway.calls) == 2, "the safe refusal must return to the model"
        tool_messages = [
            message for message in gateway.calls[1]["messages"] if message.get("role") == "tool"
        ]
        assert len(tool_messages) == 1
        assert json.loads(tool_messages[0]["content"]) == {
            "refused": True,
            "reason": "agent_tool_dispatch_failed",
            "message": "the tool call failed (ValueError)",
        }
        assert "NaN" not in tool_messages[0]["content"]
        assert '"value"' not in tool_messages[0]["content"]

        row = await _one_dispatch_row(engine)
        assert row.payload["outcome"] == "refused"
        assert row.payload["refusal_reason"] == "agent_tool_dispatch_failed"
        assert row.payload["result_sha256"] is None
        assert row.payload["result_bytes"] is None

        report = await ChainVerifier(engine, chain_id="decision_history").walk()
        assert report.is_clean is True, report.detail
        assert report.records_checked > 0

    @opa_required
    async def test_step_bound_is_denied_by_shipped_rego_before_execution(
        self,
        engine: AsyncEngine,
        metadata_env: list[Any],
        tmp_path: Path,
        signing_key: tuple[str, bytes],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        key_path, _public_pem = signing_key
        await _seed_assignment(engine, kind="tool", ref=TOOL_REF)
        await _seed_scope_and_entitlement(engine, entitled=True)
        proxy = _RecordingToolProxy()
        loop = await _build(
            engine,
            metadata_env,
            tmp_path,
            ScriptedGateway(),
            proxy,
            signing_key_path=key_path,
        )
        real_resolve = loop._dispatcher._entitlements.resolve_scope
        resolve_spy = AsyncMock(wraps=real_resolve)
        monkeypatch.setattr(loop._dispatcher._entitlements, "resolve_scope", resolve_spy)
        run = await _run_context(loop)
        raw_arguments = {
            "scope_id": SCOPE_ID,
            "sql": "select 'DENY-MARKER'",
            "max_rows": 7,
        }

        outcome = await loop._dispatcher.dispatch(
            call=GatewayToolCall(
                id="deny-call",
                name=TOOL_NAME,
                arguments=raw_arguments,
            ),
            step_index=run.max_steps,
            run=run,
        )

        resolve_spy.assert_awaited_once_with(tenant_id=TENANT, scope_id=SCOPE_ID)
        assert outcome.refused is True
        assert outcome.reason == "agent_policy_denied"
        assert proxy.calls == []

        policy_rows = await _event_rows(engine, "policy.decision_evaluated")
        assert len(policy_rows) == 1
        assert policy_rows[0].payload["decision_point"] == ("data.cognic.agents.dispatch.allow")
        assert policy_rows[0].payload["outcome"] == "deny"
        assert (
            policy_rows[0].payload["bundle_sha256"]
            == hashlib.sha256(Path("policies/_default/agents.rego").read_bytes()).hexdigest()
        )

        row = await _one_dispatch_row(engine)
        assert row.payload["outcome"] == "refused"
        assert row.payload["refusal_reason"] == "agent_policy_denied"
        assert (
            row.payload["args_sha256"] == hashlib.sha256(canonical_bytes(raw_arguments)).hexdigest()
        )


class TestProductionGatewayIngress:
    async def test_non_finite_model_argument_fails_before_dispatch_and_chain_stays_clean(
        self,
        engine: AsyncEngine,
        metadata_env: list[Any],
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        response_body = {
            "id": "resp-non-finite",
            "object": "chat.completion",
            "model": "ollama/qwen3:8b",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "bad-arguments",
                                "type": "function",
                                "function": {
                                    "name": TOOL_NAME,
                                    "arguments": '{"scope_id":"x","value":NaN}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }
        gateway, client, ledger = _real_gateway_with_response(
            engine,
            tmp_path,
            response_body=response_body,
        )
        proxy = _RecordingToolProxy()
        loop = await _build(engine, metadata_env, tmp_path, gateway, proxy)
        dispatcher_spy = AsyncMock(wraps=loop._dispatcher.dispatch)
        monkeypatch.setattr(loop._dispatcher, "dispatch", dispatcher_spy)

        try:
            result = await loop.ask(
                agent_id=DEFAULT_AGENT_ID,
                question=QUESTION,
                actor_tenant_id=TENANT,
                actor_subject=SUBJECT,
            )
        finally:
            await client.aclose()

        assert result.terminal_state == "failed"
        dispatcher_spy.assert_not_awaited()
        assert proxy.calls == []
        assert await _dispatch_rows(engine) == []

        started = await _event_rows(engine, "agent.run.started")
        failed = await _event_rows(engine, "agent.run.failed")
        assert len(started) == 1
        assert len(failed) == 1
        assert failed[0].payload["error_class"] == "_MalformedToolCall"
        ledger_rows = await ledger.read_recent_calls(window_minutes=60)
        assert len(ledger_rows) == 1
        assert ledger_rows[0].outcome == "upstream_error"

        report = await ChainVerifier(engine, chain_id="decision_history").walk()
        assert report.is_clean is True, report.detail
        assert report.records_checked > 0


class TestEvidenceIsDigestOnly:
    """ADR-027 §f — chain rows carry digests, never plaintext."""

    async def test_dispatch_row_carries_no_plaintext_and_the_chain_verifies(
        self, engine: AsyncEngine, metadata_env: list[Any], tmp_path: Path
    ) -> None:
        await _seed_scope_and_entitlement(engine, entitled=True)
        raw_arguments = {"skill_id": "SECRET-ARGUMENT-VALUE"}
        proxy = _RecordingToolProxy()
        gateway = ScriptedGateway(
            [
                _response(
                    "",
                    tool_calls=(
                        GatewayToolCall(
                            id="c1",
                            name="read_skill",
                            arguments=raw_arguments,
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

        row = await _one_dispatch_row(engine)
        observed_digest = row.payload["args_sha256"]
        assert isinstance(observed_digest, str)
        assert re.fullmatch(r"[0-9a-f]{64}", observed_digest)
        assert observed_digest == hashlib.sha256(canonical_bytes(raw_arguments)).hexdigest()

        report = await ChainVerifier(engine, chain_id="decision_history").walk()
        assert report.is_clean is True, report.detail
        assert report.records_checked > 0, "a vacuous walk proves nothing"
