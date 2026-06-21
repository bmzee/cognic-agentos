"""Sprint 3 — POST /api/v1/a2a/{target_agent} route. Stub A2AEndpoint on
app.state.a2a_endpoint (the route is a dumb raw-body adapter; the real endpoint
is exercised in test_a2a_endpoint.py). The request-time dep returns 503 when
the endpoint is absent. Mirrors the run-route harness (tests/unit/portal/api/
runs/test_run_routes.py)."""

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cognic_agentos.portal.api.a2a.routes import build_a2a_routes
from cognic_agentos.protocol.a2a_endpoint import A2AEndpointError


class _StubEndpoint:
    def __init__(
        self, *, result: dict[str, Any] | None = None, raises: A2AEndpointError | None = None
    ):
        self._result, self._raises = result, raises
        self.seen: dict[str, Any] | None = None

    async def handle(self, **kw: Any) -> dict[str, Any]:
        self.seen = kw
        if self._raises is not None:
            raise self._raises
        return self._result or {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}


def _app(endpoint: Any | None) -> FastAPI:
    app = FastAPI()
    app.state.a2a_endpoint = endpoint
    app.include_router(build_a2a_routes(), prefix="/api/v1/a2a")
    return app


def _post(
    app: FastAPI,
    agent: str = "policy_qa",
    *,
    tenant: str | None = "bank_a",
    parent_trace: str | None = None,
    body: bytes = b'{"method":"message/send"}',
) -> Any:
    headers = {"Authorization": "Bearer t", "A2A-Version": "1.0"}
    if tenant is not None:
        headers["X-Cognic-Tenant"] = tenant
    if parent_trace is not None:
        headers["X-Cognic-Parent-Trace-Id"] = parent_trace
    return TestClient(app).post(f"/api/v1/a2a/{agent}", content=body, headers=headers)


def test_503_when_endpoint_unwired() -> None:
    r = _post(_app(None))
    # The bare FastAPI default HTTPException handler nests detail under "detail"
    # (confirmed against the run-route harness: resp.json()["detail"]["reason"]).
    assert r.status_code == 503 and r.json()["detail"]["reason"] == "a2a_endpoint_unavailable"


def test_success_passthrough_200() -> None:
    ep = _StubEndpoint(result={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
    r = _post(_app(ep), parent_trace="trace-sentinel-abc")
    assert r.status_code == 200 and r.json()["result"] == {"ok": True}
    # dumb adapter threaded path target + headers + claimed tenant + raw body:
    assert ep.seen is not None
    assert ep.seen["target_agent"] == "policy_qa"
    assert ep.seen["tenant_id"] == "bank_a"
    assert ep.seen["payload"] == b'{"method":"message/send"}'
    assert ep.seen["authorization_header"] == "Bearer t"
    # the rest of the adapter contract: A2A-Version, parent-trace, minted request_id:
    assert ep.seen["a2a_version_header"] == "1.0"
    assert ep.seen["parent_trace_id"] == "trace-sentinel-abc"
    req_id = ep.seen["request_id"]
    assert isinstance(req_id, str) and req_id and all(c in "0123456789abcdef" for c in req_id)


def test_missing_tenant_header_is_a2a_invalid_request_not_500() -> None:
    r = _post(_app(_StubEndpoint()), tenant=None)
    assert r.status_code == 400
    body = r.json()
    assert body["jsonrpc"] == "2.0" and body["error"]["code"] == -32600
    assert body["error"]["data"]["policy_reason"] == "tenant_header_missing"


def test_endpoint_error_maps_to_taxonomy_status_and_envelope() -> None:
    exc = A2AEndpointError(
        "unsupported_operation", "refused", policy_reason="method_not_supported_wave1"
    )
    r = _post(_app(_StubEndpoint(raises=exc)))
    assert r.status_code == 400  # _SPEC_CODE_TO_HTTP_STATUS["unsupported_operation"]
    assert r.json()["error"]["data"]["policy_reason"] == "method_not_supported_wave1"
