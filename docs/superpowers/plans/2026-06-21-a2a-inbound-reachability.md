# A2A Inbound Reachability (receiver-only, Wave-1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan sprint-by-sprint. Steps use checkbox (`- [ ]`) syntax. Each **Sprint** is one cohesive, TDD, commit-gated unit (executed by a fresh subagent, controller-reviewed, per-sprint commit token — the same cadence we used for tasks). The subagent implements + tests but does **NOT** stage/commit; the controller commits on the user's token.

**Goal:** Make the A2A inbound receiver core reachable — a `POST /api/v1/a2a/{target_agent}` route around `A2AEndpoint.handle()` for `message/send`, a Wave-1 method gate that refuses everything else *before* dispatch, and the deferred JSON-RPC error-serialization layer that makes the receiver's error envelopes spec-valid.

**Architecture:** Five sprints, dependency-ordered: (1) the `a2a_errors` wire-integration layer + 2 new reasons (foundation — everyone consumes it); (2) the Wave-1 method gate inside `handle()`; (3) the off-gate route module; (4) SDK-gated lifespan construction + mount; (5) conformance + closeout. The route is a dumb raw-body adapter (no portal RBAC; A2A token auth lives in `handle()`); the on-gate `a2a_endpoint.py`/`a2a_errors.py` edits ride critical-control discipline. **CC count unchanged** (no new gate module). **No migration.**

**Tech Stack:** Python 3.12, `uv`, pytest-asyncio, FastAPI, strict mypy, ruff; `a2a-sdk==1.0.2` (SDK-gated, optional `adapters` extra). ADR-003 critical-control discipline (`core-controls-engineer` + `/critical-module-mode`).

**Whole-project gates every sprint:** `uv run pytest <touched paths> -q` ; `uv run ruff check <touched> && uv run ruff format --check <touched>` ; **`uv run mypy src tests`** (whole-project — `cognic_agentos` is first-party; single-file mypy emits false import-untyped AND misses real errors).

---

## File Structure

| File | On gate? | Responsibility | Sprint |
|---|---|---|---|
| `src/cognic_agentos/protocol/__init__.py` | no (literals; covered via a2a_errors codomain test) | add the 2 new `A2APolicyRefusalReason` literal values (`:463`) | 1 |
| `src/cognic_agentos/protocol/a2a_errors.py` | **YES (95/90)** | the 2 mapping entries + the deferred JSON-RPC route-integration layer (`from_endpoint_error`, `to_jsonrpc`, `_SPEC_CODE_TO_JSONRPC_INT`, `_SPEC_CODE_TO_HTTP_STATUS`) | 1 |
| `src/cognic_agentos/protocol/a2a_endpoint.py` | **YES (95/90)** | the Wave-1 method gate inside `handle()` (between Gate 3 `:518` and Gate 4 `:520`) | 2 |
| `src/cognic_agentos/portal/api/a2a/__init__.py` | no | re-export `build_a2a_routes` | 3 |
| `src/cognic_agentos/portal/api/a2a/routes.py` | no | the dumb raw-body receiver route + tenant seam + error mapping + 503 dep | 3 |
| `src/cognic_agentos/portal/api/app.py` | no | SDK-gated `A2AEndpoint` construction + `build_a2a_routes()` mount | 4 |
| `docs/adrs/ADR-003-a2a-inter-agent.md` + `docs/AS_BUILT_CAPABILITY_MAP.md` | n/a | amendment + milestone | 5 |

**No `dto.py`** (deviation from the spec's "dto.py" mention): the receiver takes raw bytes and returns a `dict` — there are no Pydantic request/response models; the wire shapes are owned by `handle()` (success) and `a2a_errors` (error). The route module is `__init__.py` + `routes.py` only.

---

## Sprint 1: `a2a_errors` wire-integration layer + the 2 new reasons (on-gate)

**Files:**
- Modify: `src/cognic_agentos/protocol/__init__.py:463` (the `A2APolicyRefusalReason = Literal[...]`)
- Modify: `src/cognic_agentos/protocol/a2a_errors.py` (the `_POLICY_REASON_TO_SPEC_CODE` map `:80` + new module-level maps + `from_endpoint_error` + `A2AErrorResponse.to_jsonrpc`)
- Test: `tests/unit/protocol/test_a2a_errors.py` (extend) + the drift test (see Step 6)

- [ ] **Step 1: Add the two literal values.** In `protocol/__init__.py`, inside `A2APolicyRefusalReason = Literal[...]` (`:463`), add `"method_not_supported_wave1",` and `"a2a_tenant_header_missing",` (preserve existing values; additive only).

- [ ] **Step 2: Add the two mapping entries.** In `a2a_errors.py`, inside `_POLICY_REASON_TO_SPEC_CODE` (`:80`):
```python
    "method_not_supported_wave1": "unsupported_operation",
    "a2a_tenant_header_missing": "invalid_request",
```

- [ ] **Step 3: Write the failing tests for the maps + serializer.** In `tests/unit/protocol/test_a2a_errors.py`:
```python
import typing

from cognic_agentos.protocol import A2AErrorCode, A2APolicyRefusalReason
from cognic_agentos.protocol.a2a_endpoint import A2AEndpointError
from cognic_agentos.protocol import a2a_errors


def test_new_policy_reasons_present_and_mapped() -> None:
    reasons = set(typing.get_args(A2APolicyRefusalReason))
    assert {"method_not_supported_wave1", "a2a_tenant_header_missing"} <= reasons
    assert a2a_errors._POLICY_REASON_TO_SPEC_CODE["method_not_supported_wave1"] == "unsupported_operation"
    assert a2a_errors._POLICY_REASON_TO_SPEC_CODE["a2a_tenant_header_missing"] == "invalid_request"


def test_http_status_and_jsonrpc_int_maps_are_complete() -> None:
    codes = set(typing.get_args(A2AErrorCode))
    assert set(a2a_errors._SPEC_CODE_TO_HTTP_STATUS) == codes  # every code mapped
    assert set(a2a_errors._SPEC_CODE_TO_JSONRPC_INT) == codes
    # JSON-RPC 2.0 inherited codes are fixed by the base spec:
    assert a2a_errors._SPEC_CODE_TO_JSONRPC_INT["parse_error"] == -32700
    assert a2a_errors._SPEC_CODE_TO_JSONRPC_INT["invalid_request"] == -32600
    assert a2a_errors._SPEC_CODE_TO_JSONRPC_INT["method_not_found"] == -32601
    assert a2a_errors._SPEC_CODE_TO_JSONRPC_INT["invalid_params"] == -32602
    assert a2a_errors._SPEC_CODE_TO_JSONRPC_INT["internal_error"] == -32603


def test_from_endpoint_error_carries_code_reason_and_status() -> None:
    exc = A2AEndpointError(
        "unsupported_operation", "refused", policy_reason="method_not_supported_wave1"
    )
    resp = a2a_errors.from_endpoint_error(exc)
    assert resp.code == "unsupported_operation"
    assert resp.policy_reason == "method_not_supported_wave1"
    assert resp.http_status == a2a_errors._SPEC_CODE_TO_HTTP_STATUS["unsupported_operation"]


def test_to_jsonrpc_is_spec_shaped_with_int_code_and_data() -> None:
    resp = a2a_errors.from_policy_reason(
        "a2a_tenant_header_missing", message="missing X-Cognic-Tenant"
    )
    env = resp.to_jsonrpc(jsonrpc_id=None)
    assert env["jsonrpc"] == "2.0"
    assert env["id"] is None
    assert env["error"]["code"] == -32600  # invalid_request
    assert isinstance(env["error"]["message"], str)
    assert env["error"]["data"]["policy_reason"] == "a2a_tenant_header_missing"
```
Run: `uv run pytest tests/unit/protocol/test_a2a_errors.py -q` → FAIL (`_SPEC_CODE_TO_HTTP_STATUS` / `_SPEC_CODE_TO_JSONRPC_INT` / `from_endpoint_error` / `to_jsonrpc` undefined).

- [ ] **Step 4: Implement the two maps.** In `a2a_errors.py` (after `_POLICY_REASON_TO_SPEC_CODE`). **HARNESS-VERIFY the 9 A2A-specific integers against the pinned `a2a-sdk`** (read `a2a.types` / the SDK's JSON-RPC error-code definitions — do NOT guess; the 5 JSON-RPC-inherited ones below are fixed by JSON-RPC 2.0). Every value of the `A2AErrorCode` Literal (`__init__.py:426`) MUST appear in both maps (the Step-3 completeness test pins this):
```python
# JSON-RPC 2.0 reserved codes are fixed by the base spec; the A2A-specific
# codes are sourced from the pinned a2a-sdk wire authority (drift-pinned in
# Step 6). error.code is an INTEGER per JSON-RPC 2.0 — string A2AErrorCode -> int.
_SPEC_CODE_TO_JSONRPC_INT: Final[dict[A2AErrorCode, int]] = {
    "parse_error": -32700,
    "invalid_request": -32600,
    "method_not_found": -32601,
    "invalid_params": -32602,
    "internal_error": -32603,
    # A2A-specific (verify each against a2a-sdk before committing):
    "task_not_found": <int from a2a-sdk>,
    "task_not_cancelable": <int from a2a-sdk>,
    "content_type_not_supported": <int from a2a-sdk>,
    "unsupported_operation": <int from a2a-sdk>,
    "invalid_agent_response": <int from a2a-sdk>,
    "push_notification_not_supported": <int from a2a-sdk>,
    "extended_agent_card_not_configured": <int from a2a-sdk>,
    "extension_support_required": <int from a2a-sdk>,
    "version_not_supported": <int from a2a-sdk>,
}

#: HTTP status the route stamps per spec code. Mirrors the per-factory choices
#: (default 400; internal_error 500; task_not_found 404). Single source for the
#: route's from_endpoint_error path.
_SPEC_CODE_TO_HTTP_STATUS: Final[dict[A2AErrorCode, int]] = {
    code: (500 if code == "internal_error" else 404 if code == "task_not_found" else 400)
    for code in typing.get_args(A2AErrorCode)
}
```
(Add `import typing` + `from typing import Final` if not already imported.)

- [ ] **Step 5: Implement `from_endpoint_error` + `to_jsonrpc`.** Add `from_endpoint_error` as a module function and `to_jsonrpc` as a method on `A2AErrorResponse` (frozen+slots permits methods):
```python
def from_endpoint_error(exc: "A2AEndpointError") -> A2AErrorResponse:
    """Build the wire response from an A2AEndpoint refusal. The endpoint raises
    A2AEndpointError(code, message, **payload); policy_reason (when present)
    rides in payload. http_status comes from _SPEC_CODE_TO_HTTP_STATUS."""
    policy_reason = exc.payload.get("policy_reason")
    extra = {k: str(v) for k, v in exc.payload.items() if k != "policy_reason"}
    return A2AErrorResponse(
        code=exc.code,
        message=str(exc),
        spec_section="A2A-1.0 §error-codes",
        policy_reason=policy_reason,
        payload=extra or None,
        http_status=_SPEC_CODE_TO_HTTP_STATUS[exc.code],
    )
```
```python
    # method on A2AErrorResponse:
    def to_jsonrpc(self, *, jsonrpc_id: str | int | None = None) -> dict[str, Any]:
        """Serialise to the JSON-RPC 2.0 error envelope. error.code is the
        integer spec code; policy_reason/feature_subtag/payload ride in data.
        jsonrpc_id is None for Wave-1 (echoing the request's JSON-RPC id needs
        body parsing the dumb route deliberately avoids)."""
        data: dict[str, Any] = {}
        if self.policy_reason is not None:
            data["policy_reason"] = self.policy_reason
        if self.feature_subtag is not None:
            data["feature_subtag"] = self.feature_subtag
        if self.payload:
            data.update(self.payload)
        error_obj: dict[str, Any] = {
            "code": _SPEC_CODE_TO_JSONRPC_INT[self.code],
            "message": self.message,
        }
        if data:
            error_obj["data"] = data
        return {"jsonrpc": "2.0", "id": jsonrpc_id, "error": error_obj}
```
Import `A2AEndpointError` lazily INSIDE `from_endpoint_error` (or under `TYPE_CHECKING` + a string annotation) to avoid an import cycle (`a2a_endpoint` imports `a2a_errors`). Add `from_endpoint_error` + `to_jsonrpc` are NOT in `__all__` unless the existing convention requires it — verify; `from_endpoint_error` likely belongs in `__all__` next to `from_policy_reason`.

- [ ] **Step 6: The integer-code drift test (SDK-gated).** In `tests/unit/protocol/test_a2a_errors.py` (or a new `test_a2a_errors_drift.py`), env-gated on `COGNIC_RUN_A2A_UPSTREAM=1` (mirror `test_a2a_schema_drift.py`'s skip pattern), assert every `_SPEC_CODE_TO_JSONRPC_INT` value equals the `a2a-sdk`'s authoritative integer for that code. Skips without the env.

- [ ] **Step 7: Run + whole-project gates.** `uv run pytest tests/unit/protocol/test_a2a_errors.py -q` (PASS) ; `uv run ruff check src/cognic_agentos/protocol/a2a_errors.py src/cognic_agentos/protocol/__init__.py tests/unit/protocol/test_a2a_errors.py && uv run ruff format --check <same>` ; `uv run mypy src tests` (Success). Report CC posture: `a2a_errors.py` stays ≥95/90.

---

## Sprint 2: the Wave-1 method gate inside `handle()` (on-gate, critical control)

**Files:**
- Modify: `src/cognic_agentos/protocol/a2a_endpoint.py` (insert between Gate 3 end `:518` and Gate 4 start `:520`)
- Test: `tests/unit/protocol/test_a2a_endpoint.py` (extend)

- [ ] **Step 1: Write the failing negative-path tests.** Mirror the existing `_good_call_kwargs(...)` helper (`test_a2a_endpoint.py:90,257`). The Wave-1 receiver serves only `message/send`; a `tasks/cancel` etc. payload must refuse BEFORE any task/dispatch side effect:
```python
import json
import pytest

from cognic_agentos.protocol.a2a_endpoint import A2AEndpointError


def _payload(method: str) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": {}}).encode()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["tasks/cancel", "tasks/get", "message/stream", "bogus/method"])
async def test_non_send_methods_refused_before_dispatch(endpoint, method: str) -> None:
    # endpoint fixture: an A2AEndpoint whose registry would resolve the target,
    # so a refusal here proves the METHOD gate fires before routing/dispatch.
    with pytest.raises(A2AEndpointError) as ei:
        await endpoint.handle(**_good_call_kwargs(payload=_payload(method)))
    assert ei.value.code == "unsupported_operation"
    assert ei.value.payload.get("policy_reason") == "method_not_supported_wave1"
    # No task minted, no agent.handle() call (assert via the fixture's spies):
    assert endpoint._tasks == {}
    assert endpoint._registry.load_call_count == 0  # routing never reached


@pytest.mark.asyncio
async def test_message_send_passes_the_method_gate(endpoint) -> None:
    # message/send proceeds past the gate to routing/dispatch (the existing
    # happy-path fixture with a registered agent returns its response dict).
    result = await endpoint.handle(**_good_call_kwargs(payload=_payload("message/send")))
    assert isinstance(result, dict)
```
Run: `uv run pytest tests/unit/protocol/test_a2a_endpoint.py -k method -q` → FAIL (gate not present; `tasks/cancel` currently mis-dispatches).

> HARNESS-VERIFY: confirm the existing `_good_call_kwargs` payload + the `endpoint` fixture's registry-spy shape; adapt the "no routing" assertion to whatever the fixture exposes (it may stub `registry.load`). The contract to pin is **no task minted + routing/dispatch not reached + exactly one refusal-evidence row**.

- [ ] **Step 2: Implement the method gate.** In `a2a_endpoint.py`, insert AFTER the Gate-3 `raise A2AEndpointError(...)` block (`:518`) and BEFORE `# Gate 4 — routing.` (`:520`):
```python
        # Gate 3.5 — Wave-1 method allow-list. Refuse any method but
        # message/send BEFORE routing/task-creation/dispatch. tasks/get,
        # tasks/cancel, message/stream, ... are real A2A methods this Wave-1
        # receiver does not yet serve; the auxiliary slice lifts this gate.
        method = self._decode_method(payload)
        if method != "message/send":
            await self._emit_refusal_evidence(
                event_type="a2a.task_refused",
                request_id=request_id,
                tenant_id=tenant_id,
                target_agent=target_agent,
                parent_trace_id=effective_parent_trace_id,
                child_trace_id=child_trace_id,
                payload_digest=payload_digest,
                error_code="unsupported_operation",
                policy_reason="method_not_supported_wave1",
                gate="method",
                extra={"method": str(method)},
            )
            raise A2AEndpointError(
                "unsupported_operation",
                f"Wave-1 receiver serves only message/send; refused method: {method!r}",
                policy_reason="method_not_supported_wave1",
            )
```
Add a small static decode helper (the Wave-2 scan at `:969` already does `json.loads(payload)`; the payload is guaranteed scannable here because Gate 3 refuses unscannable payloads as a Wave-2 `payload_unscannable` feature first):
```python
    @staticmethod
    def _decode_method(payload: bytes) -> str | None:
        try:
            decoded = json.loads(payload)
        except (ValueError, TypeError):
            return None
        if isinstance(decoded, dict):
            method = decoded.get("method")
            return method if isinstance(method, str) else None
        return None
```

- [ ] **Step 3: Run + whole-project gates.** `uv run pytest tests/unit/protocol/test_a2a_endpoint.py -q` (PASS — new + all existing) ; ruff/format on `a2a_endpoint.py` + the test ; `uv run mypy src tests` (Success). Confirm `a2a_endpoint.py` stays ≥95/90 (negative-path tests cover the new branch).

---

## Sprint 3: the route module `portal/api/a2a/` (off-gate)

**Files:**
- Create: `src/cognic_agentos/portal/api/a2a/__init__.py`
- Create: `src/cognic_agentos/portal/api/a2a/routes.py`
- Test: `tests/unit/portal/api/a2a/test_routes.py` (new)

- [ ] **Step 1: Write the failing route tests.** Use a stub `A2AEndpoint` on `app.state.a2a_endpoint` (the route is dumb; the real endpoint is exercised in `test_a2a_endpoint.py`). Mirror the run-route test harness (`tests/unit/portal/api/runs/test_routes.py`):
```python
import json
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cognic_agentos.portal.api.a2a.routes import build_a2a_routes
from cognic_agentos.protocol.a2a_endpoint import A2AEndpointError


class _StubEndpoint:
    def __init__(self, *, result: dict[str, Any] | None = None, raises: A2AEndpointError | None = None):
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


def _post(app: FastAPI, agent: str = "policy_qa", *, tenant: str | None = "bank_a", body: bytes = b'{"method":"message/send"}') -> Any:
    headers = {"Authorization": "Bearer t", "A2A-Version": "1.0"}
    if tenant is not None:
        headers["X-Cognic-Tenant"] = tenant
    return TestClient(app).post(f"/api/v1/a2a/{agent}", content=body, headers=headers)


def test_503_when_endpoint_unwired() -> None:
    r = _post(_app(None))
    assert r.status_code == 503 and r.json()["reason"] == "a2a_endpoint_unavailable"


def test_success_passthrough_200() -> None:
    ep = _StubEndpoint(result={"jsonrpc": "2.0", "id": 1, "result": {"ok": True}})
    r = _post(_app(ep))
    assert r.status_code == 200 and r.json()["result"] == {"ok": True}
    # dumb adapter threaded path target + headers + claimed tenant + raw body:
    assert ep.seen["target_agent"] == "policy_qa"
    assert ep.seen["tenant_id"] == "bank_a"
    assert ep.seen["payload"] == b'{"method":"message/send"}'
    assert ep.seen["authorization_header"] == "Bearer t"


def test_missing_tenant_header_is_a2a_invalid_request_not_500() -> None:
    r = _post(_app(_StubEndpoint()), tenant=None)
    assert r.status_code == 400
    body = r.json()
    assert body["jsonrpc"] == "2.0" and body["error"]["code"] == -32600
    assert body["error"]["data"]["policy_reason"] == "a2a_tenant_header_missing"


def test_endpoint_error_maps_to_taxonomy_status_and_envelope() -> None:
    exc = A2AEndpointError("unsupported_operation", "refused", policy_reason="method_not_supported_wave1")
    r = _post(_app(_StubEndpoint(raises=exc)))
    assert r.status_code == 400  # _SPEC_CODE_TO_HTTP_STATUS["unsupported_operation"]
    assert r.json()["error"]["data"]["policy_reason"] == "method_not_supported_wave1"
```
Run: `uv run pytest tests/unit/portal/api/a2a/test_routes.py -q` → FAIL (module absent).

- [ ] **Step 2: Implement the route.** Create `src/cognic_agentos/portal/api/a2a/routes.py`. `from __future__ import annotations` is **INTENTIONALLY OMITTED** (FastAPI `Annotated[..., Depends(...)]` invariant — mirror `runs/routes.py`):
```python
"""POST /api/v1/a2a/{target_agent} — the A2A inbound receiver (ADR-003).

A dumb raw-body adapter around A2AEndpoint.handle(): the A2A pinned token is
the auth axis (validated inside handle(), NOT portal RBAC). Mounted
UNCONDITIONALLY; the request-time dep returns 503 until the SDK-gated lifespan
populates app.state.a2a_endpoint. `from __future__ import annotations` OMITTED.
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from cognic_agentos.protocol import a2a_errors
from cognic_agentos.protocol.a2a_endpoint import A2AEndpoint, A2AEndpointError

#: Wave-1 tenant source. Host-based tenancy is a later swap of THIS function
#: only (handle()/route contract untouched). The claimed tenant is not trusted:
#: A2AAuthzClient validates the token against it; a forged claim is refused.
_TENANT_HEADER = "X-Cognic-Tenant"
_PARENT_TRACE_HEADER = "X-Cognic-Parent-Trace-Id"


def resolve_a2a_tenant(request: Request) -> str | None:
    return (request.headers.get(_TENANT_HEADER) or "").strip() or None


def _require_a2a_endpoint(request: Request) -> A2AEndpoint:
    endpoint: A2AEndpoint | None = getattr(request.app.state, "a2a_endpoint", None)
    if endpoint is None:
        raise HTTPException(status_code=503, detail={"reason": "a2a_endpoint_unavailable"})
    return endpoint


def build_a2a_routes() -> APIRouter:
    router = APIRouter()

    @router.post("/{target_agent}")
    async def receive_a2a(
        target_agent: str,
        request: Request,
        response: Response,
        endpoint: Annotated[A2AEndpoint, Depends(_require_a2a_endpoint)],
    ) -> dict[str, Any]:
        request_id = uuid.uuid4().hex
        tenant_id = resolve_a2a_tenant(request)
        if tenant_id is None:
            err = a2a_errors.from_policy_reason(
                "a2a_tenant_header_missing",
                message="missing or empty X-Cognic-Tenant header",
            )
            response.status_code = err.http_status
            return err.to_jsonrpc(jsonrpc_id=None)
        raw = await request.body()
        try:
            result = await endpoint.handle(
                target_agent=target_agent,
                payload=raw,
                authorization_header=request.headers.get("Authorization"),
                a2a_version_header=request.headers.get("A2A-Version"),
                parent_trace_id=request.headers.get(_PARENT_TRACE_HEADER),
                tenant_id=tenant_id,
                request_id=request_id,
            )
        except A2AEndpointError as exc:
            err = a2a_errors.from_endpoint_error(exc)
            response.status_code = err.http_status
            return err.to_jsonrpc(jsonrpc_id=None)
        response.status_code = 200
        return result

    return router
```
And `src/cognic_agentos/portal/api/a2a/__init__.py`:
```python
"""A2A inbound receiver portal surface (ADR-003)."""

from cognic_agentos.portal.api.a2a.routes import build_a2a_routes

__all__ = ["build_a2a_routes"]
```

- [ ] **Step 3: Run + whole-project gates.** `uv run pytest tests/unit/portal/api/a2a/ -q` (PASS) ; ruff/format on the new files + test ; `uv run mypy src tests` (Success). Confirm no new gate module (route is off-gate).

---

## Sprint 4: SDK-gated lifespan construction + mount (off-gate, `app.py`)

**Files:**
- Modify: `src/cognic_agentos/portal/api/app.py` (the lifespan A2A block near `:1540` + the router-mount block near `:1350`)
- Test: `tests/unit/portal/api/test_app_a2a_wiring.py` (new) — assert the route is mounted + 503 without the SDK/endpoint

- [ ] **Step 1: Write the failing wiring test.** Assert `build_a2a_routes()` is mounted unconditionally and returns 503 when `app.state.a2a_endpoint` is unset (the default kernel-image / no-SDK path):
```python
from fastapi.testclient import TestClient

from cognic_agentos.portal.api.app import create_app


def test_a2a_route_mounted_and_503_without_endpoint() -> None:
    app = create_app()  # default: no a2a_endpoint wired
    # the route exists (mounted unconditionally) and 503s, not 404:
    paths = {r.path for r in app.routes}
    assert "/api/v1/a2a/{target_agent}" in paths
    r = TestClient(app).post("/api/v1/a2a/policy_qa", content=b"{}",
                             headers={"X-Cognic-Tenant": "bank_a"})
    assert r.status_code == 503 and r.json()["reason"] == "a2a_endpoint_unavailable"
```
Run: `uv run pytest tests/unit/portal/api/test_app_a2a_wiring.py -q` → FAIL (route not mounted).

> HARNESS-VERIFY: confirm `create_app()`'s exact construction signature + that the test can build it without live adapters (mirror the existing `test_app_*` harness). If `create_app` needs args, mirror the closest existing app-wiring test.

- [ ] **Step 2: Mount the router (unconditional).** In `app.py`, in the route-mount block near `:1350` (next to `build_run_routes` / `build_subagent_routes`):
```python
    from cognic_agentos.portal.api.a2a import build_a2a_routes

    app.include_router(
        build_a2a_routes(),
        prefix="/api/v1/a2a",
        tags=["a2a"],
    )
```

- [ ] **Step 3: SDK-gated endpoint construction in the lifespan.** Replace the T2 SDK-presence-only A2A block (`app.py:1540-1567`, the `if is_a2a_available(): logger.info(...)` log-only stub) with real construction, fail-soft, mirroring the MCP-host block (`:638-660`):
```python
        if is_a2a_available():
            from cognic_agentos.protocol.a2a_authz import A2AAuthzClient
            from cognic_agentos.protocol.a2a_agent_cards import A2AAgentCardVerifier
            from cognic_agentos.protocol.a2a_endpoint import A2AEndpoint
            from cognic_agentos.protocol.plugin_registry import PluginRegistry

            a2a_registry = plugin_registry or PluginRegistry(audit_store=runtime.audit_store)
            try:
                a2a_authz = A2AAuthzClient(
                    settings=settings,
                    vault_client=adapters.secret,
                    audit_store=runtime.audit_store,
                    decision_history_store=runtime.decision_history_store,
                )
                a2a_cards = A2AAgentCardVerifier(...)  # HARNESS-VERIFY ctor at a2a_agent_cards.py:203
                app.state.a2a_endpoint = A2AEndpoint(
                    settings=settings,
                    plugin_registry=a2a_registry,
                    authz_client=a2a_authz,
                    agent_card_verifier=a2a_cards,
                    audit_store=runtime.audit_store,
                    decision_history_store=runtime.decision_history_store,
                )
            except Exception:
                logger.error("a2a.endpoint_construction_failed", exc_info=True)
                app.state.a2a_endpoint = None
        else:
            app.state.a2a_endpoint = None
            logger.warning("a2a.endpoint_unavailable_in_image", extra={"missing_module": "a2a"})
```
> HARNESS-VERIFY (do NOT guess): the exact `A2AAgentCardVerifier.__init__` params (`a2a_agent_cards.py:203`) + whether `app.state.a2a_endpoint` should be predeclared before the `try` (mirror how the MCP block predeclares `app.state.mcp_host`). Confirm `adapters.secret` is the `SecretAdapter` the MCP block uses as `vault_client`.

- [ ] **Step 4: Run + whole-project gates.** `uv run pytest tests/unit/portal/api/test_app_a2a_wiring.py tests/unit/portal/api/a2a/ -q` (PASS) ; ruff/format on `app.py` + the test ; `uv run mypy src tests` (Success).

---

## Sprint 5: conformance + closeout

**Files:**
- Test: `tests/conformance/a2a/test_receiver_wave1_posture.py` (new) OR extend the existing A2A conformance suite
- Modify: `docs/adrs/ADR-003-a2a-inter-agent.md` (amendment) + `docs/AS_BUILT_CAPABILITY_MAP.md` (milestone) + `docs/superpowers/specs/2026-06-21-...md` (status → LANDED)

- [ ] **Step 1: Conformance test for the Wave-1 receiver posture.** Over a real `A2AEndpoint` (with a stub-registered agent for the success path), assert: `message/send` to a registered agent succeeds; `message/send` to an unknown agent → `method_not_found` (`unknown_target`); `tasks/cancel`/`tasks/get`/`message/stream` → `unsupported_operation` (`method_not_supported_wave1`). HARNESS-VERIFY the existing A2A conformance harness location (`docs/A2A-CONFORMANCE.md` + `tests/conformance/a2a/` if present) and follow its fixture conventions.
Run: `uv run pytest tests/conformance/a2a/ -q` (PASS).

- [ ] **Step 2: Full quality gate.** `uv run ruff check . && uv run ruff format --check .` ; `uv run mypy src tests` (Success).

- [ ] **Step 3: Full suite on fresh coverage + CC gate.** `uv run pytest -q --cov=cognic_agentos --cov-branch --cov-report=json:coverage.json` (record pass count) ; `uv run python tools/check_critical_coverage.py` (PASS; `a2a_endpoint.py` + `a2a_errors.py` ≥95/90 on fresh data; **CC count unchanged** — no new gate module).

- [ ] **Step 4: Docs.** ADR-003 amendment (the inbound receiver route + the Wave-1 method gate + the `unsupported_operation`-for-deferred-methods posture + the deferred-JSON-RPC-serializer-now-built + the registry-coupling-to-the-next-slice honesty). AS_BUILT milestone. Spec status → LANDED. No migration.

---

## Self-Review (controller, before execution)

- **Spec coverage:** §1 route → Sprint 3 ; §2 method gate → Sprint 2 ; §3 reasons + (corrected) serializer → Sprint 1 ; §4 flow → Sprints 2-3 ; §5 lifespan → Sprint 4 ; testing → every sprint + Sprint 5 ; registry-coupling honesty → Sprint 5 docs.
- **Type consistency:** `from_endpoint_error` / `to_jsonrpc` / `_SPEC_CODE_TO_JSONRPC_INT` / `_SPEC_CODE_TO_HTTP_STATUS` / `resolve_a2a_tenant` / `build_a2a_routes` / `_require_a2a_endpoint` — names used identically across sprints.
- **Harness-verify points (don't guess):** the 9 A2A-specific JSON-RPC integers (a2a-sdk) ; the `endpoint` test fixture's registry-spy shape ; `A2AAgentCardVerifier.__init__` params ; `create_app()` test-construction ; the A2A conformance harness location.
- **No placeholders** except the explicitly-flagged `<int from a2a-sdk>` (a deliberate read-the-pinned-SDK step, drift-pinned in Sprint 1 Step 6) and the `A2AAgentCardVerifier(...)` ctor (Sprint 4 harness-verify).
