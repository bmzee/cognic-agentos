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

import cognic_agentos.llm.gateway as gateway_module
import cognic_agentos.protocol.supply_chain as supply_chain_module
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


def _permissive_tool_call_response(
    *,
    content: Any,
    tool_calls: list[dict[str, Any]],
    model: str = "ollama/qwen3:8b",
) -> httpx.Response:
    """Raw provider bytes containing Python's non-standard JSON floats.

    ``httpx.Response(json=...)`` deliberately refuses these values before the
    gateway can see them.  Real provider/SDK decoders may already have turned
    them into ``float`` objects, so this fixture supplies the corresponding
    wire bytes and lets the production response decoder construct that dict.
    """
    payload = {
        "id": "resp-test",
        "object": "chat.completion",
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content,
                    "tool_calls": tool_calls,
                },
                "finish_reason": "tool_calls",
            }
        ],
    }
    return httpx.Response(
        200,
        content=json.dumps(payload, allow_nan=True).encode(),
        headers={"content-type": "application/json"},
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
    @pytest.mark.parametrize(
        "constant",
        [
            pytest.param("NaN", id="nan"),
            pytest.param("Infinity", id="positive-infinity"),
            pytest.param("-Infinity", id="negative-infinity"),
            pytest.param("1e999", id="overflow-to-infinity"),
        ],
    )
    @respx.mock
    async def test_non_finite_string_arguments_fail_closed(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        constant: str,
    ) -> None:
        """Python's permissive JSON extensions never enter GatewayToolCall."""
        respx.post(_LITELLM_URL).mock(
            return_value=_tool_call_response(
                content=None,
                tool_calls=[
                    {
                        "id": "call_non_finite",
                        "type": "function",
                        "function": {
                            "name": "run_readonly_query",
                            "arguments": f'{{"value": {constant}}}',
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
                request_id=f"req-non-finite-{constant}",
            )

        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "upstream_error"
        assert rows[0].provenance == "resolved"
        assert len(rec.captured) == 1
        assert rec.captured[0][1]["llm.gateway.outcome"] == "malformed_tool_call"

    @pytest.mark.parametrize(
        "arguments",
        [
            pytest.param({"outer": [float("nan")]}, id="nested-list"),
            pytest.param({"outer": {"value": float("inf")}}, id="nested-object"),
        ],
    )
    @respx.mock
    async def test_non_finite_dict_arguments_fail_closed(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        arguments: dict[str, Any],
    ) -> None:
        """Provider-SDK-decoded dicts receive the same recursive guard."""
        respx.post(_LITELLM_URL).mock(
            return_value=_permissive_tool_call_response(
                content=None,
                tool_calls=[
                    {
                        "id": "call_non_finite",
                        "type": "function",
                        "function": {
                            "name": "run_readonly_query",
                            "arguments": arguments,
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
                request_id="req-non-finite-dict",
            )

        rows = await gateway_ledger.read_recent_calls(window_minutes=60)
        assert len(rows) == 1
        assert rows[0].outcome == "upstream_error"
        assert len(rec.captured) == 1
        assert rec.captured[0][1]["llm.gateway.outcome"] == "malformed_tool_call"

    @respx.mock
    async def test_finite_nested_dict_arguments_remain_accepted(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        arguments = {
            "outer": [-1.5, 0.0, 1e308],
            "object": {"value": -2.25},
        }
        respx.post(_LITELLM_URL).mock(
            return_value=_tool_call_response(
                content=None,
                tool_calls=[
                    {
                        "id": "call_finite",
                        "type": "function",
                        "function": {
                            "name": "run_readonly_query",
                            "arguments": arguments,
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

        response = await gw.completion(
            tier="tier1",
            messages=list(_USER_MESSAGES),
            request_id="req-finite-dict",
        )

        assert response.tool_calls == (
            GatewayToolCall(
                id="call_finite",
                name="run_readonly_query",
                arguments=arguments,
            ),
        )

    @respx.mock
    async def test_finite_numeric_string_arguments_remain_accepted(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
    ) -> None:
        respx.post(_LITELLM_URL).mock(
            return_value=_tool_call_response(
                content=None,
                tool_calls=[
                    {
                        "id": "call_finite_string",
                        "type": "function",
                        "function": {
                            "name": "run_readonly_query",
                            "arguments": '{"value":1.25,"nested":[-2.0,0.0]}',
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

        response = await gw.completion(
            tier="tier1",
            messages=list(_USER_MESSAGES),
            request_id="req-finite-string",
        )

        assert response.tool_calls == (
            GatewayToolCall(
                id="call_finite_string",
                name="run_readonly_query",
                arguments={"value": 1.25, "nested": [-2.0, 0.0]},
            ),
        )

    def test_non_finite_decoded_dict_key_fails_closed(self) -> None:
        """The recursive walk covers the complete decoded mapping, including
        a programmatic SDK mapping key that ordinary JSON cannot express."""
        with pytest.raises(_MalformedToolCall):
            gateway_module._parse_tool_calls(
                [
                    {
                        "function": {
                            "name": "run_readonly_query",
                            "arguments": {float("nan"): "value"},
                        }
                    }
                ]
            )

    @respx.mock
    async def test_string_parse_constant_guard_is_independent_of_recursive_walk(
        self,
        settings_for_gateway: Settings,
        gateway_ledger: GatewayCallLedger,
        audit_store: AuditStore,
        rate_limiter: ProfileRateLimiter,
        dev_resolver: PreflightResolver,
        default_sla_policy: SLAPolicy,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Removing parse_constant must fail even if the shared walk survives."""
        calls: list[str] = []
        reject_constant = gateway_module._reject_non_finite_json_constant

        def _recording_rejector(value: str) -> Any:
            calls.append(value)
            return reject_constant(value)

        monkeypatch.setattr(
            gateway_module,
            "_reject_non_finite_json_constant",
            _recording_rejector,
        )
        respx.post(_LITELLM_URL).mock(
            return_value=_tool_call_response(
                content=None,
                tool_calls=[
                    {
                        "id": "call_non_finite",
                        "type": "function",
                        "function": {
                            "name": "run_readonly_query",
                            "arguments": '{"value": NaN}',
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

        with pytest.raises(_MalformedToolCall):
            await gw.completion(
                tier="tier1",
                messages=list(_USER_MESSAGES),
                request_id="req-parse-constant-independent",
            )
        assert calls == ["NaN"]

    @pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
    def test_non_finite_constant_rejector_matches_supply_chain_copy(self, constant: str) -> None:
        gateway_rejector = gateway_module._reject_non_finite_json_constant
        supply_chain_rejector = supply_chain_module._reject_non_finite_json_constant

        def _fingerprint(function: Any) -> tuple[Any, ...]:
            code = function.__code__
            return (
                code.co_argcount,
                code.co_code,
                code.co_names,
                code.co_consts[1:],
            )

        assert _fingerprint(gateway_rejector) == _fingerprint(supply_chain_rejector)
        with pytest.raises(ValueError) as gateway_exc:
            gateway_rejector(constant)
        with pytest.raises(ValueError) as supply_chain_exc:
            supply_chain_rejector(constant)
        assert gateway_exc.value.args == supply_chain_exc.value.args

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
