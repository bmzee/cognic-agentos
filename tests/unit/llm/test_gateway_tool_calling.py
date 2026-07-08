"""M8 A2 — gateway typed tool-calling (ADR-027 governed agent loop).

Critical-controls posture (gateway.py is on the CC coverage gate):
- Wire-body discipline: ``tools=None`` produces a byte-identical body to the
  pre-A2 gateway (no ``"tools"`` key); ``tools=[GatewayToolSpec(...)]``
  serializes into the OpenAI function-calling shape.
- Response parse: LiteLLM-normalized ``choices[0].message.tool_calls`` across
  the three provider families (openai str-arguments, anthropic
  content+tool_calls coexist, ollama dict-arguments + missing id).
- Fail-closed: malformed arguments JSON raises ``_MalformedToolCall``
  (ledgered as the ALLOWED ``upstream_error``; span records the NEW precise
  ``malformed_tool_call`` — the deliberate ledger/span vocabulary divergence).
- Both-directions null-content pin: ``content: null`` is accepted ONLY
  alongside tool_calls; null content with no tool_calls stays refused.
- Guardrail input-join tolerates ``content: None`` messages (assistant
  tool_calls turns + tool-role results).

Uses ``respx`` to mock the LiteLLM HTTP shape — hermetic, no live LiteLLM.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.guardrails import GuardrailPipeline
from cognic_agentos.core.sla import SLAPolicy
from cognic_agentos.db.adapters.protocols import AdapterHealth
from cognic_agentos.llm.concurrency import ProfileRateLimiter
from cognic_agentos.llm.gateway import (
    GatewayToolCall,
    GatewayToolSpec,
    LLMGateway,
    _MalformedResponseContent,
    _MalformedToolCall,
)
from cognic_agentos.llm.ledger import GatewayCallLedger
from cognic_agentos.llm.preflight import PreflightResolver

_LITELLM_URL = "http://litellm.test:4000/chat/completions"


class _RecordingObservability:
    """Hermetic ObservabilityAdapter double — mirrors
    test_gateway_observability.py; only emit_trace is exercised."""

    def __init__(self) -> None:
        self.captured: list[tuple[str, dict[str, object]]] = []

    async def emit_trace(self, name: str, attributes: dict[str, object]) -> None:
        self.captured.append((name, attributes))

    async def emit_metric(self, name: str, value: float, attributes: dict[str, object]) -> None: ...
    async def flush(self) -> None: ...
    async def health_check(self) -> AdapterHealth:
        return AdapterHealth(status="ok", driver="recording", latency_ms=0.0)


def _build_gateway(
    *,
    settings: Settings,
    ledger: GatewayCallLedger,
    audit_store: AuditStore,
    rate_limiter: ProfileRateLimiter,
    preflight: PreflightResolver,
    sla_policy: SLAPolicy,
    input_pipeline: GuardrailPipeline | None = None,
    observability: _RecordingObservability | None = None,
) -> LLMGateway:
    return LLMGateway(
        settings=settings,
        ledger=ledger,
        audit_store=audit_store,
        rate_limiter=rate_limiter,
        preflight=preflight,
        sla_policy=sla_policy,
        input_pipeline=input_pipeline,
        observability=observability,
        # Default httpx.AsyncClient — respx patches transport-side.
    )


def _ok_text_response(model: str = "ollama/qwen3:8b") -> httpx.Response:
    """Plain text completion — no tool_calls key anywhere."""
    return httpx.Response(
        200,
        json={
            "id": "resp-test",
            "object": "chat.completion",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "hello"},
                    "finish_reason": "stop",
                }
            ],
        },
    )


def _tool_call_response(
    *,
    content: Any,
    tool_calls: list[dict[str, Any]] | None,
    model: str = "ollama/qwen3:8b",
) -> httpx.Response:
    """LiteLLM-normalized response carrying a tool-calling message."""
    message: dict[str, Any] = {"role": "assistant", "content": content}
    if tool_calls is not None:
        message["tool_calls"] = tool_calls
    return httpx.Response(
        200,
        json={
            "id": "resp-test",
            "object": "chat.completion",
            "model": model,
            "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls"}],
        },
    )


_USER_MESSAGES: list[dict[str, Any]] = [{"role": "user", "content": "hi"}]


# ---------------------------------------------------------------------------
# TestOutboundWireBody — tools serialization + the no-tools byte-identity pin.
# ---------------------------------------------------------------------------


class TestOutboundWireBody:
    @respx.mock
    async def test_no_tools_wire_body_byte_identical(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """tools omitted → the wire body is EXACTLY {model, messages} —
        full-dict equality proves no "tools" key rides the request."""
        route = respx.post(_LITELLM_URL).mock(return_value=_ok_text_response())
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        resp = await gw.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-no-tools",
        )
        # Additive-field default on the response dataclass.
        assert resp.tool_calls == ()
        assert route.call_count == 1
        assert json.loads(route.calls.last.request.content) == {
            "model": "cognic-tier1-dev",
            "messages": [{"role": "user", "content": "hi"}],
        }

    @respx.mock
    async def test_tools_present_serialized_into_body(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        route = respx.post(_LITELLM_URL).mock(return_value=_ok_text_response())
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        parameters = {
            "type": "object",
            "properties": {"sql": {"type": "string"}},
            "required": ["sql"],
        }
        spec = GatewayToolSpec(
            name="run_readonly_query",
            description="Run a read-only SQL query",
            parameters=parameters,
        )
        await gw.completion(
            tier="tier1",
            messages=[{"role": "user", "content": "hi"}],
            request_id="req-with-tools",
            tools=[spec],
        )
        body = json.loads(route.calls.last.request.content)
        assert body["tools"] == [
            {
                "type": "function",
                "function": {
                    "name": "run_readonly_query",
                    "description": "Run a read-only SQL query",
                    "parameters": parameters,
                },
            }
        ]
        # model + messages still ride the body alongside tools.
        assert body["model"] == "cognic-tier1-dev"
        assert body["messages"] == [{"role": "user", "content": "hi"}]


# ---------------------------------------------------------------------------
# TestToolCallParse — the three LiteLLM-normalized provider families.
# ---------------------------------------------------------------------------


class TestToolCallParse:
    @respx.mock
    async def test_openai_family_tool_call_parsed(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """OpenAI family: null content + str JSON-object arguments + call_* id.
        Null content is accepted ALONGSIDE tool_calls (spec delta b)."""
        respx.post(_LITELLM_URL).mock(
            return_value=_tool_call_response(
                content=None,
                tool_calls=[
                    {
                        "id": "call_abc",
                        "type": "function",
                        "function": {
                            "name": "run_readonly_query",
                            "arguments": '{"scope_id": "retail_analytics", "sql": "SELECT 1"}',
                        },
                    }
                ],
            )
        )
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        resp = await gw.completion(
            tier="tier1",
            messages=list(_USER_MESSAGES),
            request_id="req-openai-family",
        )
        assert resp.content == ""
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0] == GatewayToolCall(
            id="call_abc",
            name="run_readonly_query",
            arguments={"scope_id": "retail_analytics", "sql": "SELECT 1"},
        )

    @respx.mock
    async def test_anthropic_family_content_and_tool_calls_coexist(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Anthropic family: BOTH non-empty text content AND a toolu_* call —
        the text is preserved verbatim, not clobbered by the parse."""
        respx.post(_LITELLM_URL).mock(
            return_value=_tool_call_response(
                content="I will run the query now.",
                tool_calls=[
                    {
                        "id": "toolu_01AbCdEf",
                        "type": "function",
                        "function": {
                            "name": "run_readonly_query",
                            "arguments": '{"sql": "SELECT 1"}',
                        },
                    }
                ],
            )
        )
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        resp = await gw.completion(
            tier="tier1",
            messages=list(_USER_MESSAGES),
            request_id="req-anthropic-family",
        )
        assert resp.content == "I will run the query now."
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].id == "toolu_01AbCdEf"
        assert resp.tool_calls[0].name == "run_readonly_query"
        assert resp.tool_calls[0].arguments == {"sql": "SELECT 1"}

    @respx.mock
    async def test_ollama_family_dict_args_and_missing_id_synthesized(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Ollama family: arguments arrive as a DICT (not a JSON string) and
        the entry has NO id → id synthesized as call_<index>."""
        respx.post(_LITELLM_URL).mock(
            return_value=_tool_call_response(
                content=None,
                tool_calls=[
                    {
                        "type": "function",
                        "function": {
                            "name": "run_readonly_query",
                            "arguments": {"scope_id": "retail_analytics", "sql": "SELECT 1"},
                        },
                    }
                ],
            )
        )
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        resp = await gw.completion(
            tier="tier1",
            messages=list(_USER_MESSAGES),
            request_id="req-ollama-family",
        )
        assert len(resp.tool_calls) == 1
        assert resp.tool_calls[0].arguments == {
            "scope_id": "retail_analytics",
            "sql": "SELECT 1",
        }
        assert resp.tool_calls[0].id == "call_0"


# ---------------------------------------------------------------------------
# TestFailClosed — malformed tool_calls + the both-directions null-content pin.
# ---------------------------------------------------------------------------


class TestFailClosed:
    @respx.mock
    async def test_malformed_arguments_json_fails_closed(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        """Invalid arguments JSON → _MalformedToolCall raised. The ledger and
        span vocabularies DIVERGE deliberately: exactly ONE ledger row with the
        ALLOWED outcome "upstream_error" (no double-ledger through the generic
        except) while the span records the precise NEW "malformed_tool_call"."""
        respx.post(_LITELLM_URL).mock(
            return_value=_tool_call_response(
                content=None,
                tool_calls=[
                    {
                        "id": "call_bad",
                        "type": "function",
                        "function": {
                            "name": "run_readonly_query",
                            "arguments": "{not json",
                        },
                    }
                ],
            )
        )
        rec = _RecordingObservability()
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            observability=rec,
        )
        with pytest.raises(_MalformedToolCall):
            await gw.completion(
                tier="tier1",
                messages=list(_USER_MESSAGES),
                request_id="req-malformed-args",
            )
        # Ledger: exactly one row, on the ALLOWED ledger vocabulary.
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "upstream_error"
        assert rows[0].provenance == "resolved"
        # Span: the precise NEW 14th outcome value.
        assert len(rec.captured) == 1
        name, attrs = rec.captured[0]
        assert name == "llm.gateway.completion"
        assert attrs["llm.gateway.outcome"] == "malformed_tool_call"

    @pytest.mark.parametrize(
        "tool_calls",
        [
            pytest.param(None, id="no-tool-calls-key"),
            pytest.param([], id="empty-tool-calls-list"),
        ],
    )
    @respx.mock
    async def test_null_content_without_tool_calls_still_refused(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        tool_calls: list[dict[str, Any]] | None,
    ) -> None:
        """The BOTH-DIRECTIONS pin paired with the openai-family test: null
        content WITHOUT tool_calls stays refused (malformed-content path)."""
        respx.post(_LITELLM_URL).mock(
            return_value=_tool_call_response(content=None, tool_calls=tool_calls)
        )
        gw = _build_gateway(
            settings=settings_for_gateway,
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
        )
        with pytest.raises(_MalformedResponseContent):
            await gw.completion(
                tier="tier1",
                messages=list(_USER_MESSAGES),
                request_id="req-null-no-tools",
            )
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "upstream_error"


# ---------------------------------------------------------------------------
# TestGuardrailJoinToleratesNone — tool-loop message shapes survive the join.
# ---------------------------------------------------------------------------


class TestGuardrailJoinToleratesNone:
    @respx.mock
    async def test_tool_role_and_none_content_messages_survive_guardrail_join(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        pass_pipeline: GuardrailPipeline,
    ) -> None:
        """Tool-loop transcript shapes — an assistant tool_calls turn with
        content: None and a tool-role result with content: None — must not
        TypeError the input-guardrail join; the guardrail runs and the call
        succeeds."""
        respx.post(_LITELLM_URL).mock(return_value=_ok_text_response())
        gw = _build_gateway(
            settings=settings_for_gateway,  # llm_guardrail_scope="all"
            ledger=gateway_ledger,
            audit_store=audit_store,
            rate_limiter=rate_limiter,
            preflight=dev_resolver,
            sla_policy=default_sla_policy,
            input_pipeline=pass_pipeline,
        )
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": "run the query"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_x",
                        "type": "function",
                        "function": {"name": "run_readonly_query", "arguments": "{}"},
                    }
                ],
            },
            {"role": "tool", "content": None, "tool_call_id": "call_x"},
        ]
        resp = await gw.completion(
            tier="tier1",
            messages=messages,
            request_id="req-join-none",
        )
        assert resp.content == "hello"
        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "ok"
