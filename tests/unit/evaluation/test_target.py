from __future__ import annotations

from typing import Any

import pytest

from cognic_agentos.evaluation.corpus import EvalCase
from cognic_agentos.evaluation.target import GatewayTarget
from cognic_agentos.llm.concurrency import LLMConcurrencyExceeded
from cognic_agentos.llm.gateway import GatewayResponse


def _case() -> EvalCase:
    return EvalCase.model_validate(
        {
            "id": "c1",
            "case_kind": "completion",
            "messages": [{"role": "user", "content": "hi"}],
            "assertions": {"contains": ["x"]},
        }
    )


class _FakeGateway:
    def __init__(self, *, content: str | None = None, raise_exc: Exception | None = None) -> None:
        self._content = content
        self._raise = raise_exc
        self.calls: list[dict[str, Any]] = []

    async def completion(
        self,
        *,
        tier: str,
        messages: list[dict[str, str]],
        request_id: str,
        tenant_id: str | None = None,
    ) -> GatewayResponse:
        self.calls.append({"tier": tier, "messages": messages})
        if self._raise is not None:
            raise self._raise
        return GatewayResponse(
            content=self._content or "",
            upstream_model="m",
            api_base=None,
            external=False,
            request_id=request_id,
            tier=tier,
            latency_ms=7,
        )


@pytest.mark.asyncio
async def test_gateway_target_succeeds_and_maps_messages() -> None:
    gw = _FakeGateway(content="capital adequacy ratio")
    target = GatewayTarget(gateway=gw, tier="tier1")  # type: ignore[arg-type]
    assert target.tier == "tier1"
    out = await target.run_case(_case(), request_id="r1", tenant_id="t1")
    assert out.outcome == "succeeded"
    assert out.text == "capital adequacy ratio"
    assert out.model == "m"
    assert gw.calls[0]["messages"] == [{"role": "user", "content": "hi"}]


@pytest.mark.asyncio
async def test_gateway_target_catches_gateway_exception_as_errored() -> None:
    gw = _FakeGateway(raise_exc=LLMConcurrencyExceeded("no slot"))
    target = GatewayTarget(gateway=gw, tier="tier1")  # type: ignore[arg-type]
    out = await target.run_case(_case(), request_id="r1", tenant_id="t1")
    assert out.outcome == "errored"
    assert out.error_category == "LLMConcurrencyExceeded"
    assert out.text == ""
