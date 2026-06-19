# MCP tool-invocation portal route — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `portal/api/mcp/` module with two routes (`GET …/servers/{server_id}/tools` + `POST …/servers/{server_id}/tools/call`) that live-exercise the dormant `MCPHost.list_tools` + `call_tool` + the approval seam, mirroring the proven `portal/api/runs/` caller.

**Architecture:** A thin production caller. `call_tool`/`list_tools` are already built + tested; this slice adds the route + the RBAC scopes + the unconditional mount + a request-time 503 dep. Exception→HTTP mapping is by class (4xx = caller / 5xx = kernel→upstream), with a closed `_TIMEOUT_REASONS` set splitting 504-vs-502.

**Tech Stack:** Python 3.12, uv, FastAPI, Pydantic v2, pytest. Spec: `docs/superpowers/specs/2026-06-19-mcp-tool-invocation-portal-route-design.md`.

---

## Execution discipline (controller-owned — overrides the skill's default commit step)

- **The controller commits, not the subagents.** Each task's subagent implements + verifies + reports "files modified" (NOT staged). The controller runs the halt-before-commit reviewer gate, requests the user's per-action token, stages by explicit path, runs `git diff --cached --check`, and commits.
- **Per-action tokens**, restated before executing. Branch already exists (`feat/mcp-tool-invocation-portal-route`); the spec is committed (`4a5a45c`).
- **Subagents on Opus 4.8** (`model: opus` every dispatch).
- **Protected untracked docs — NEVER stage:** `docs/reviews/` and `docs/superpowers/specs/2026-05-26-agentos-local-managed-agents-gap-analysis.md`.
- **Commit footer:** `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
- **Posture invariant (verify at T7):** CC stays **131**; no new on-gate module (the route module is off-gate like `portal/api/runs/routes.py`); the `portal/rbac/` edits are additive to already-on-gate modules and must keep coverage; no migration.

## File Structure

**Created:**
- `src/cognic_agentos/portal/api/mcp/__init__.py` — empty package marker.
- `src/cognic_agentos/portal/api/mcp/dto.py` — `CallToolRequest` / `CallToolResponse` / `ListToolsResponse`.
- `src/cognic_agentos/portal/api/mcp/routes.py` — `build_mcp_routes()` + the deps + the status mapping.
- `tests/unit/portal/rbac/test_mcp_scopes.py` — the scope drift test.
- `tests/unit/portal/api/mcp/__init__.py` + `tests/unit/portal/api/mcp/test_mcp_dto.py` + `tests/unit/portal/api/mcp/test_mcp_routes.py`.

**Modified:**
- `src/cognic_agentos/portal/rbac/scopes.py` — `MCPRBACScope` + `MCP_SCOPES` + doc-comment.
- `src/cognic_agentos/portal/rbac/actor.py` — widen `Actor.scopes` union with `| MCPRBACScope`.
- `src/cognic_agentos/portal/rbac/enforcement.py` — widen the `RequireScope` param union with `| MCPRBACScope`.
- `src/cognic_agentos/portal/api/app.py` — unconditional mount under `/api/v1/mcp`.
- Docs (T6): `docs/adrs/ADR-002-*.md`, `docs/AS_BUILT_CAPABILITY_MAP.md`, `AGENTS.md`.

---

## Task 1: RBAC scopes wiring (`mcp.tool.list` + `mcp.tool.invoke`)

**Files:**
- Modify: `src/cognic_agentos/portal/rbac/scopes.py`
- Modify: `src/cognic_agentos/portal/rbac/actor.py`
- Modify: `src/cognic_agentos/portal/rbac/enforcement.py`
- Test: `tests/unit/portal/rbac/test_mcp_scopes.py`

- [ ] **Step 1: Write the failing drift test**

Create `tests/unit/portal/rbac/test_mcp_scopes.py` (mirrors `test_run_scopes.py`):

```python
"""MCP tool-invocation RBAC scopes (ADR-002). Mirrors the RunRBACScope
additive-widening pattern (14A-A2a)."""

from __future__ import annotations

from typing import get_args

from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.portal.rbac.scopes import (
    MCP_SCOPES,
    ComplianceRBACScope,
    ConfigOverlayRBACScope,
    EmergencyRBACScope,
    EvalRBACScope,
    MCPRBACScope,
    MemoryRBACScope,
    ModelRBACScope,
    PackRBACScope,
    QuotaRBACScope,
    RunRBACScope,
    ToolApprovalRBACScope,
    UIRBACScope,
)


def test_mcp_scopes_has_exactly_two_values() -> None:
    assert set(get_args(MCPRBACScope)) == {"mcp.tool.list", "mcp.tool.invoke"}
    assert frozenset({"mcp.tool.list", "mcp.tool.invoke"}) == MCP_SCOPES


def test_mcp_scopes_frozenset_matches_literal() -> None:
    assert frozenset(get_args(MCPRBACScope)) == MCP_SCOPES


def test_mcp_scope_namespace_disjoint_from_every_other_family() -> None:
    mcp = set(get_args(MCPRBACScope))
    others: set[str] = set()
    for fam in (
        PackRBACScope,
        UIRBACScope,
        ComplianceRBACScope,
        ModelRBACScope,
        MemoryRBACScope,
        EmergencyRBACScope,
        QuotaRBACScope,
        EvalRBACScope,
        ConfigOverlayRBACScope,
        ToolApprovalRBACScope,
        RunRBACScope,
    ):
        others |= set(get_args(fam))
    assert mcp.isdisjoint(others)
    assert all(s.startswith("mcp.") for s in mcp)


def test_actor_accepts_mcp_invoke_scope() -> None:
    actor = Actor(
        subject="svc", tenant_id="t", scopes=frozenset({"mcp.tool.invoke"}), actor_type="service"
    )
    assert "mcp.tool.invoke" in actor.scopes


def test_require_scope_accepts_mcp_scopes() -> None:
    # Pins the enforcement.py RequireScope union widening — mypy enforces the
    # Literal membership; this also smoke-constructs the dependency factory.
    assert RequireScope("mcp.tool.list") is not None
    assert RequireScope("mcp.tool.invoke") is not None
```

- [ ] **Step 2: Run it → fails (ImportError: MCPRBACScope)**

Run: `uv run pytest tests/unit/portal/rbac/test_mcp_scopes.py -x`
Expected: FAIL — `ImportError: cannot import name 'MCPRBACScope'`.

- [ ] **Step 3: Add `MCPRBACScope` + `MCP_SCOPES` to `scopes.py`**

In `src/cognic_agentos/portal/rbac/scopes.py`, immediately after the `RUN_SCOPES` frozenset definition (the `RunRBACScope` block near line 337-340), add:

```python
#: ADR-002 ("Fork D") — MCP tool-invocation RBAC family. 2 scopes in the
#: ``mcp.*`` namespace:
#:
#:   - ``mcp.tool.list`` ← ``GET /api/v1/mcp/servers/{server_id}/tools``.
#:   - ``mcp.tool.invoke`` ← ``POST /api/v1/mcp/servers/{server_id}/tools/call``.
#:
#: Read-only discovery (``list``) is a lower privilege than invocation
#: (``invoke``); a caller may hold ``list`` without ``invoke``. The sandbox/MCP
#: approval seam owns the per-tier human checkpoint, so the MCP routes do NOT
#: also gate on :class:`RequireHumanActor`. Value-disjoint from every other
#: family by the ``mcp.*`` namespace. Wire-protocol-public — the 403
#: ``scope_not_held`` body carries it. Pinned by
#: ``tests/unit/portal/rbac/test_mcp_scopes.py``.
#:
#: Style note: plain ``= Literal[...]`` (no ``TypeAlias``) per the repo
#: convention at ``packs/lifecycle.py:111`` + the families above.
MCPRBACScope = Literal["mcp.tool.list", "mcp.tool.invoke"]

#: All 2 MCP scopes as a frozenset (1:1 with :data:`MCPRBACScope`) for
#: bank-overlay binders. Pinned by ``tests/unit/portal/rbac/test_mcp_scopes.py``.
MCP_SCOPES: frozenset[MCPRBACScope] = frozenset({"mcp.tool.list", "mcp.tool.invoke"})
```

- [ ] **Step 4: Widen the `Actor.scopes` union**

In `src/cognic_agentos/portal/rbac/actor.py`: add `MCPRBACScope` to the scopes import block (alongside `RunRBACScope`), and add `| MCPRBACScope` as the last arm of the `scopes: frozenset[ … ]` union (after `| RunRBACScope` at ~line 143):

```python
    scopes: frozenset[
        PackRBACScope
        | UIRBACScope
        | ComplianceRBACScope
        | ModelRBACScope
        | MemoryRBACScope
        | EmergencyRBACScope
        | QuotaRBACScope
        | EvalRBACScope
        | ConfigOverlayRBACScope
        | ToolApprovalRBACScope
        | RunRBACScope
        | MCPRBACScope
    ]
```

- [ ] **Step 5: Widen the `RequireScope` param union**

In `src/cognic_agentos/portal/rbac/enforcement.py`: add `MCPRBACScope` to the scopes import block, and add `| MCPRBACScope` as the last arm of the `RequireScope(scope: …)` union (after `| RunRBACScope` at ~line 259):

```python
def RequireScope(
    scope: PackRBACScope
    | UIRBACScope
    | ComplianceRBACScope
    | ModelRBACScope
    | MemoryRBACScope
    | EmergencyRBACScope
    | QuotaRBACScope
    | EvalRBACScope
    | ConfigOverlayRBACScope
    | ToolApprovalRBACScope
    | RunRBACScope
    | MCPRBACScope,
) -> Callable[..., Awaitable[Actor]]:
```

- [ ] **Step 6: Run → passes; lint + types**

Run: `uv run pytest tests/unit/portal/rbac/test_mcp_scopes.py -x && uv run ruff check src/cognic_agentos/portal/rbac/ tests/unit/portal/rbac/test_mcp_scopes.py && uv run mypy src/cognic_agentos/portal/rbac/`
Expected: PASS + clean.

- [ ] **Step 7: Commit (controller-owned, token-gated)** — `feat(protocol): MCP route RBAC scopes mcp.tool.list/invoke (ADR-002)`

---

## Task 2: DTOs (`portal/api/mcp/dto.py`)

**Files:**
- Create: `src/cognic_agentos/portal/api/mcp/__init__.py` (empty)
- Create: `src/cognic_agentos/portal/api/mcp/dto.py`
- Test: `tests/unit/portal/api/mcp/__init__.py` (empty) + `tests/unit/portal/api/mcp/test_mcp_dto.py`

- [ ] **Step 1: Write the failing DTO tests**

Create `tests/unit/portal/api/mcp/test_mcp_dto.py`:

```python
"""MCP route DTOs (ADR-002)."""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from cognic_agentos.portal.api.mcp.dto import CallToolRequest


def test_call_request_defaults_empty_arguments() -> None:
    req = CallToolRequest(tool_name="lookup")
    assert req.arguments == {}
    assert req.approval_request_id is None


def test_call_request_parses_approval_request_id_to_uuid() -> None:
    rid = uuid.uuid4()
    req = CallToolRequest(tool_name="lookup", approval_request_id=str(rid))
    assert req.approval_request_id == rid


def test_call_request_rejects_empty_tool_name() -> None:
    with pytest.raises(ValidationError):
        CallToolRequest(tool_name="")


def test_call_request_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        CallToolRequest(tool_name="lookup", tenant_id="t")


def test_call_request_preserves_raw_tool_name() -> None:
    # Control chars stay verbatim — the route NEVER sanitizes / path-encodes.
    raw = "look\tup\n; rm -rf"
    assert CallToolRequest(tool_name=raw).tool_name == raw
```

- [ ] **Step 2: Run → fails (no module)**

Run: `uv run pytest tests/unit/portal/api/mcp/test_mcp_dto.py -x`
Expected: FAIL — `ModuleNotFoundError: cognic_agentos.portal.api.mcp.dto`.

- [ ] **Step 3: Create the package + the DTOs**

Create empty `src/cognic_agentos/portal/api/mcp/__init__.py` and empty `tests/unit/portal/api/mcp/__init__.py`. Create `src/cognic_agentos/portal/api/mcp/dto.py`:

```python
"""MCP tool-invocation route request/response DTOs (ADR-002)."""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class CallToolRequest(BaseModel):
    """Body for POST /api/v1/mcp/servers/{server_id}/tools/call. tenant_id +
    originator come ONLY from the bound Actor (extra='forbid' rejects them).
    ``tool_name`` is caller-supplied RAW identity — passed verbatim to
    ``call_tool`` (the host owns audit-canonical raw tool identity); the route
    NEVER sanitizes or path-encodes it. ``arguments`` uses an explicit
    ``default_factory`` (not a bare ``= {}``) per the repo convention."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    approval_request_id: uuid.UUID | None = None


class CallToolResponse(BaseModel):
    """200 envelope — the ``CallResult`` projection (payload + the correlation
    IDs examiners replay against the audit chain + decision-history rows)."""

    model_config = ConfigDict(frozen=True)

    payload: Any
    request_id: str
    server_id: str
    tool_name: str
    mcp_session_id: str | None
    as_issuer: str
    scopes: list[str]
    client_id: str


class ListToolsResponse(BaseModel):
    """200 envelope for the list route — the flat host-provided tool catalogue
    (already deep-copy-isolated from the host's per-tenant cache)."""

    model_config = ConfigDict(frozen=True)

    tools: list[Any]
```

- [ ] **Step 4: Run → passes; lint + types**

Run: `uv run pytest tests/unit/portal/api/mcp/test_mcp_dto.py -x && uv run ruff check src/cognic_agentos/portal/api/mcp/ tests/unit/portal/api/mcp/ && uv run mypy src/cognic_agentos/portal/api/mcp/dto.py`
Expected: PASS + clean.

- [ ] **Step 5: Commit** — `feat(portal): MCP route DTOs (ADR-002)`

---

## Task 3: The route module (`portal/api/mcp/routes.py`)

**Files:**
- Create: `src/cognic_agentos/portal/api/mcp/routes.py`

(Behavioral tests are T5 — they need the create_app mount from T4. This task implements the module + a structural smoke; T5 verifies behavior via TestClient.)

- [ ] **Step 1: Write the route module**

Create `src/cognic_agentos/portal/api/mcp/routes.py`:

```python
"""MCP tool-invocation portal route — the production caller of MCPHost
(ADR-002 "Fork D" + ADR-014). Mounted UNCONDITIONALLY; the request-time
``_require_mcp_host`` dep returns 503 when ``app.state.mcp_host`` is None (the
``mcp`` SDK is absent / construction failed). Live-exercises ``call_tool`` +
``list_tools`` + the approval seam.

``from __future__ import annotations`` is INTENTIONALLY OMITTED so FastAPI can
resolve the closure-local ``Depends(...)`` annotations eagerly. The MCPHost
exception classes import SDK-free (``require_mcp`` is constructor-only), so this
module is kernel-image-clean.
"""

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from cognic_agentos.portal.api.mcp.dto import (
    CallToolRequest,
    CallToolResponse,
    ListToolsResponse,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.portal.rbac.enforcement import RequireScope
from cognic_agentos.protocol.mcp_authz import MCPAuthzError
from cognic_agentos.protocol.mcp_host import (
    CallResult,
    MCPHost,
    MCPToolInvocationRefused,
    MCPTransportError,
)

#: ``MCPToolInvocationRefused.reason`` -> HTTP status. The 6-value enum is
#: wire-public + drift-pinned at its definition; this map consumes it.
#: 202 = approval pending (the body adds approval_request_id); 403 = terminal
#: forbidden (denied / no-engine); 409 = re-request conflicts.
_REFUSAL_STATUS: dict[str, int] = {
    "tool_approval_pending": 202,
    "tool_approval_denied": 403,
    "tool_approval_engine_not_available": 403,
    "tool_approval_expired": 409,
    "tool_approval_binding_mismatch": 409,
    "tool_approval_request_not_found": 409,
}

#: Transport/authz reasons that map to 504 (gateway timeout). EVERY OTHER
#: MCPTransportError / MCPAuthzError reason maps to 502 (bad gateway) — so a
#: future non-timeout reason is a DELIBERATE 502, never a leaked 500. Pinned
#: against the live MCPTransportReason + AuthzReason enums in the route tests.
_TIMEOUT_REASONS: frozenset[str] = frozenset(
    {"mcp_call_tool_timeout", "mcp_session_open_timeout", "mcp_oauth_request_timeout"}
)

#: Server-minted request-id prefixes. len(prefix) + 32 (uuid4 hex) <= 64 (the
#: decision_history.request_id String(64) cap). Asserted at module foot.
_CALL_REQUEST_ID_PREFIX = "mcp-call-"
_LIST_REQUEST_ID_PREFIX = "mcp-list-"


def _require_mcp_host(request: Request) -> MCPHost:
    host: MCPHost | None = getattr(request.app.state, "mcp_host", None)
    if host is None:
        raise HTTPException(status_code=503, detail={"reason": "mcp_host_unavailable"})
    return host


def _mint_request_id(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex}"


def _transport_status(reason: str) -> int:
    return 504 if reason in _TIMEOUT_REASONS else 502


def _call_result_to_response(result: CallResult) -> CallToolResponse:
    return CallToolResponse(
        payload=result.payload,
        request_id=result.request_id,
        server_id=result.server_id,
        tool_name=result.tool_name,
        mcp_session_id=result.mcp_session_id,
        as_issuer=result.as_issuer,
        scopes=list(result.scopes),
        client_id=result.client_id,
    )


def build_mcp_routes() -> APIRouter:
    router = APIRouter()
    _require_list = RequireScope("mcp.tool.list")
    _require_invoke = RequireScope("mcp.tool.invoke")

    @router.get("/servers/{server_id}/tools", response_model=ListToolsResponse)
    async def list_tools(
        server_id: str,
        actor: Annotated[Actor, Depends(_require_list)],
        host: Annotated[MCPHost, Depends(_require_mcp_host)],
    ) -> ListToolsResponse:
        try:
            tools = await host.list_tools(
                server_id=server_id,
                request_id=_mint_request_id(_LIST_REQUEST_ID_PREFIX),
                tenant_id=actor.tenant_id,
            )
        except LookupError:
            raise HTTPException(status_code=404, detail={"reason": "server_not_found"}) from None
        except (MCPTransportError, MCPAuthzError) as exc:
            raise HTTPException(
                status_code=_transport_status(exc.reason), detail={"reason": exc.reason}
            ) from None
        except Exception:
            # LAST arm (the specific types win first). A generic host-call failure
            # maps to a DELIBERATE 502, never a leaked 500 (the spec's
            # mcp_orchestrator_error row). The repo does not enable ruff BLE001.
            raise HTTPException(
                status_code=502, detail={"reason": "mcp_orchestrator_error"}
            ) from None
        return ListToolsResponse(tools=list(tools))

    @router.post("/servers/{server_id}/tools/call", response_model=CallToolResponse)
    async def call_tool(
        server_id: str,
        body: CallToolRequest,
        response: Response,
        actor: Annotated[Actor, Depends(_require_invoke)],
        host: Annotated[MCPHost, Depends(_require_mcp_host)],
    ) -> CallToolResponse:
        try:
            result = await host.call_tool(
                server_id=server_id,
                tool_name=body.tool_name,
                arguments=body.arguments,
                request_id=_mint_request_id(_CALL_REQUEST_ID_PREFIX),
                tenant_id=actor.tenant_id,
                originator_subject=actor.subject,
                approval_request_id=body.approval_request_id,
            )
        except LookupError:
            raise HTTPException(status_code=404, detail={"reason": "server_not_found"}) from None
        except MCPToolInvocationRefused as exc:
            detail: dict[str, Any] = {"reason": exc.reason}
            if exc.reason == "tool_approval_pending":
                detail["approval_request_id"] = exc.payload.get("approval_request_id")
            raise HTTPException(status_code=_REFUSAL_STATUS[exc.reason], detail=detail) from None
        except (MCPTransportError, MCPAuthzError) as exc:
            raise HTTPException(
                status_code=_transport_status(exc.reason), detail={"reason": exc.reason}
            ) from None
        except Exception:
            # LAST arm — MCPToolInvocationRefused inherits RuntimeError, so the
            # specific arms above MUST precede this. call_tool re-raises generic
            # errors after auditing them; map to a DELIBERATE 502, never a leaked
            # 500 (the spec's mcp_orchestrator_error row). Repo has no ruff BLE001.
            raise HTTPException(
                status_code=502, detail={"reason": "mcp_orchestrator_error"}
            ) from None
        return _call_result_to_response(result)

    return router


# Module-foot bounded-request-id invariant (the decision_history.request_id String(64) cap).
assert len(_CALL_REQUEST_ID_PREFIX) + 32 <= 64
assert len(_LIST_REQUEST_ID_PREFIX) + 32 <= 64
```

- [ ] **Step 2: Structural smoke (the module imports + builds a 2-route router)**

Run:
```bash
uv run python -c "
from cognic_agentos.portal.api.mcp.routes import build_mcp_routes
r = build_mcp_routes()
methods = {route.path: set(route.methods) for route in r.routes}
print({p: sorted(m) for p, m in methods.items()})
assert 'GET' in methods['/servers/{server_id}/tools']
assert 'POST' in methods['/servers/{server_id}/tools/call']
print('OK: 2 routes')
"
```
Expected: `OK: 2 routes`. (Also proves SDK-free import.)

- [ ] **Step 3: Lint + types**

Run: `uv run ruff check src/cognic_agentos/portal/api/mcp/routes.py && uv run ruff format --check src/cognic_agentos/portal/api/mcp/routes.py && uv run mypy src/cognic_agentos/portal/api/mcp/routes.py`
Expected: clean.

- [ ] **Step 4: Commit** — `feat(portal): MCP tool-invocation route module (ADR-002/ADR-014)`

---

## Task 4: Mount under `/api/v1/mcp` (`app.py`)

**Files:**
- Modify: `src/cognic_agentos/portal/api/app.py` (after the run-route mount at ~line 1336)

- [ ] **Step 1: Add the unconditional mount**

In `src/cognic_agentos/portal/api/app.py`, immediately after the `build_run_routes()` `app.include_router(...)` block (~line 1336), add:

```python
    # MCP tool-invocation surface (ADR-002 "Fork D"). Unconditional mount: the
    # host is populated by the lifespan only when is_mcp_available(); the route's
    # request-time dep returns 503 mcp_host_unavailable until then. Lazy import
    # (the module is SDK-free, so this is safe in the kernel image).
    from cognic_agentos.portal.api.mcp.routes import build_mcp_routes

    app.include_router(
        build_mcp_routes(),
        prefix="/api/v1/mcp",
        tags=["mcp"],
    )
```

- [ ] **Step 2: Verify the app still constructs + mounts the routes**

Run:
```bash
uv run python -c "
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.core.config import build_settings_without_env_file
app = create_app(build_settings_without_env_file())
paths = {r.path for r in app.routes}
assert '/api/v1/mcp/servers/{server_id}/tools' in paths
assert '/api/v1/mcp/servers/{server_id}/tools/call' in paths
print('OK: MCP routes mounted')
"
```
Expected: `OK: MCP routes mounted`.

- [ ] **Step 3: Lint** — `uv run ruff check src/cognic_agentos/portal/api/app.py`

- [ ] **Step 4: Commit** — `feat(portal): mount MCP routes under /api/v1/mcp (ADR-002)`

---

## Task 5: Route behavioral tests (`test_mcp_routes.py`)

**Files:**
- Create: `tests/unit/portal/api/mcp/test_mcp_routes.py`

Uses the run-route test harness: `create_app(memory_settings, adapter_registry=memory_registry)` + `TestClient`; the actor binder + the host are stubbed on `app.state` AFTER lifespan startup. A **stub host** unit-tests the route's mapping + threading (the host's real approval seam is already tested in `test_mcp_approval_seam.py`). The `memory_settings` + `memory_registry` fixtures come from the repo conftest (used by `test_run_routes.py`).

- [ ] **Step 1: Write the tests**

```python
"""POST/GET /api/v1/mcp routes (ADR-002). Stub host + stub binder on app.state
(after lifespan startup); the route is mounted unconditionally; the request-time
dep returns 503 when the host is absent."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.mcp_authz import MCPAuthzError
from cognic_agentos.protocol.mcp_host import (
    CallResult,
    MCPToolInvocationRefused,
    MCPTransportError,
)

_SERVER = "pack.demo"


class _StubBinder:
    def __init__(self, actor: Actor) -> None:
        self._actor = actor

    def bind(self, *, request: Any) -> Actor:
        return self._actor


class _StubHost:
    def __init__(
        self, *, call_return: Any = None, raises: Exception | None = None, list_return: Any = None
    ) -> None:
        self._call_return = call_return
        self._raises = raises
        self._list_return = [] if list_return is None else list_return
        self.calls: list[dict[str, Any]] = []

    async def call_tool(self, **kw: Any) -> Any:
        self.calls.append(kw)
        if self._raises is not None:
            raise self._raises
        return self._call_return

    async def list_tools(self, **kw: Any) -> Any:
        self.calls.append({"op": "list", **kw})
        if self._raises is not None:
            raise self._raises
        return self._list_return


def _actor(scopes: frozenset[Any] = frozenset({"mcp.tool.list", "mcp.tool.invoke"})) -> Actor:
    return Actor(subject="svc", tenant_id="t", scopes=scopes, actor_type="service")


def _call_result(tool_name: str = "lookup") -> CallResult:
    return CallResult(
        payload={"content": "ok"},
        request_id="mcp-call-xyz",
        server_id=_SERVER,
        tool_name=tool_name,
        mcp_session_id="sess-1",
        as_issuer="https://as.example",
        scopes=("mcp:tools",),
        client_id="client-a",
    )


def _make_app(memory_settings: Any, memory_registry: Any, tmp_path: Any) -> Any:
    cfg = tmp_path / "litellm.yaml"
    cfg.write_text(
        "model_list:\n  - model_name: cognic-tier1-dev\n"
        "    litellm_params:\n      model: ollama/qwen\n"
        "      api_base: http://localhost:11434\n"
    )
    return create_app(
        memory_settings.model_copy(update={"litellm_config_path": cfg, "cache_driver": "memory"}),
        adapter_registry=memory_registry,
    )


def _call(memory_settings, memory_registry, tmp_path, *, host, actor=None, json=None):
    """POST .../tools/call. The stubs are set AFTER lifespan startup (so they
    survive any pre-seed) and the request is made INSIDE the with-block so the
    lifespan shutdown runs cleanly on exit (the test_run_routes.py pattern)."""
    app = _make_app(memory_settings, memory_registry, tmp_path)
    with TestClient(app) as client:
        app.state.actor_binder = _StubBinder(actor if actor is not None else _actor())
        app.state.mcp_host = host
        return client.post(
            f"/api/v1/mcp/servers/{_SERVER}/tools/call", json=json or {"tool_name": "lookup"}
        )


def _list(memory_settings, memory_registry, tmp_path, *, host, actor=None):
    """GET .../tools — same harness as _call (with-block, clean shutdown)."""
    app = _make_app(memory_settings, memory_registry, tmp_path)
    with TestClient(app) as client:
        app.state.actor_binder = _StubBinder(actor if actor is not None else _actor())
        app.state.mcp_host = host
        return client.get(f"/api/v1/mcp/servers/{_SERVER}/tools")


def test_list_success(memory_settings, memory_registry, tmp_path) -> None:
    host = _StubHost(list_return=[{"name": "lookup"}])
    r = _list(memory_settings, memory_registry, tmp_path, host=host)
    assert r.status_code == 200
    assert r.json() == {"tools": [{"name": "lookup"}]}


def test_call_success(memory_settings, memory_registry, tmp_path) -> None:
    host = _StubHost(call_return=_call_result())
    r = _call(memory_settings, memory_registry, tmp_path, host=host)
    assert r.status_code == 200
    body = r.json()
    assert body["payload"] == {"content": "ok"}
    assert body["server_id"] == _SERVER


def test_call_pending_returns_202_with_approval_request_id(
    memory_settings, memory_registry, tmp_path
) -> None:
    rid = str(uuid.uuid4())
    host = _StubHost(
        raises=MCPToolInvocationRefused("tool_approval_pending", approval_request_id=rid)
    )
    r = _call(memory_settings, memory_registry, tmp_path, host=host, json={"tool_name": "pay"})
    assert r.status_code == 202
    assert r.json()["detail"]["reason"] == "tool_approval_pending"
    assert r.json()["detail"]["approval_request_id"] == rid


def test_call_recall_threads_approval_request_id(
    memory_settings, memory_registry, tmp_path
) -> None:
    host = _StubHost(call_return=_call_result())
    rid = str(uuid.uuid4())
    r = _call(
        memory_settings,
        memory_registry,
        tmp_path,
        host=host,
        json={"tool_name": "pay", "approval_request_id": rid},
    )
    assert r.status_code == 200
    assert str(host.calls[0]["approval_request_id"]) == rid
    # tenant + originator come from the actor, not the body.
    assert host.calls[0]["tenant_id"] == "t"
    assert host.calls[0]["originator_subject"] == "svc"


@pytest.mark.parametrize(
    ("exc", "status"),
    [
        (MCPToolInvocationRefused("tool_approval_denied"), 403),
        (MCPToolInvocationRefused("tool_approval_engine_not_available"), 403),
        (MCPToolInvocationRefused("tool_approval_expired"), 409),
        (MCPToolInvocationRefused("tool_approval_binding_mismatch"), 409),
        (MCPToolInvocationRefused("tool_approval_request_not_found"), 409),
        (MCPTransportError("mcp_call_tool_timeout"), 504),
        (MCPTransportError("mcp_session_open_timeout"), 504),
        (MCPTransportError("mcp_transport_send_failed"), 502),
        (MCPTransportError("mcp_session_open_failed"), 502),
        (MCPAuthzError("mcp_oauth_request_timeout"), 504),
        (MCPAuthzError("mcp_as_not_allowlisted"), 502),
        (MCPAuthzError("mcp_authorisation_lost"), 502),
        (LookupError("unknown server"), 404),
    ],
)
def test_call_status_mapping(memory_settings, memory_registry, tmp_path, exc, status) -> None:
    r = _call(memory_settings, memory_registry, tmp_path, host=_StubHost(raises=exc))
    assert r.status_code == status


def test_call_generic_exception_maps_502(memory_settings, memory_registry, tmp_path) -> None:
    # The catch-all: any non-typed error (here a bare RuntimeError, as call_tool
    # re-raises its generic-Exception path) maps to 502 mcp_orchestrator_error.
    r = _call(memory_settings, memory_registry, tmp_path, host=_StubHost(raises=RuntimeError("boom")))
    assert r.status_code == 502
    assert r.json()["detail"]["reason"] == "mcp_orchestrator_error"


@pytest.mark.parametrize(
    ("exc", "status"),
    [
        (LookupError("unknown server"), 404),
        (MCPTransportError("mcp_session_open_timeout"), 504),
        (MCPTransportError("mcp_transport_send_failed"), 502),
        (MCPAuthzError("mcp_as_not_allowlisted"), 502),
        (RuntimeError("boom"), 502),
    ],
)
def test_list_status_mapping(memory_settings, memory_registry, tmp_path, exc, status) -> None:
    # The GET list route maps the same exception classes (no approval path).
    r = _list(memory_settings, memory_registry, tmp_path, host=_StubHost(raises=exc))
    assert r.status_code == status
    if status == 502 and isinstance(exc, RuntimeError):
        assert r.json()["detail"]["reason"] == "mcp_orchestrator_error"


def test_list_scope_miss_returns_403(memory_settings, memory_registry, tmp_path) -> None:
    # An actor without mcp.tool.list -> RequireScope refuses 403 on the GET route.
    r = _list(
        memory_settings, memory_registry, tmp_path, host=_StubHost(), actor=_actor(frozenset())
    )
    assert r.status_code == 403


def test_no_host_returns_503(memory_settings, memory_registry, tmp_path) -> None:
    r = _call(memory_settings, memory_registry, tmp_path, host=None)
    assert r.status_code == 503
    assert r.json()["detail"]["reason"] == "mcp_host_unavailable"


def test_scope_miss_returns_403(memory_settings, memory_registry, tmp_path) -> None:
    # An actor without mcp.tool.invoke -> RequireScope refuses 403 on the POST route.
    r = _call(
        memory_settings,
        memory_registry,
        tmp_path,
        host=_StubHost(call_return=_call_result()),
        actor=_actor(frozenset()),
    )
    assert r.status_code == 403


def test_request_id_minted_and_bounded(memory_settings, memory_registry, tmp_path) -> None:
    host = _StubHost(call_return=_call_result())
    _call(memory_settings, memory_registry, tmp_path, host=host)
    rid = host.calls[0]["request_id"]
    assert rid.startswith("mcp-call-")
    assert len(rid) <= 64


def test_tool_name_raw_preserved(memory_settings, memory_registry, tmp_path) -> None:
    host = _StubHost(call_return=_call_result())
    raw = "look\tup\n; rm -rf"
    _call(memory_settings, memory_registry, tmp_path, host=host, json={"tool_name": raw})
    assert host.calls[0]["tool_name"] == raw  # never sanitized / path-encoded
```

- [ ] **Step 2: Run → all pass**

Run: `uv run pytest tests/unit/portal/api/mcp/test_mcp_routes.py -x`
Expected: all PASS.

- [ ] **Step 3: Drift test — pin `_TIMEOUT_REASONS` ⊆ the live enums**

Append to `test_mcp_routes.py`:

```python
def test_timeout_reasons_are_subset_of_live_enums() -> None:
    from typing import get_args

    from cognic_agentos.portal.api.mcp.routes import _TIMEOUT_REASONS
    from cognic_agentos.protocol.mcp_authz import AuthzReason
    from cognic_agentos.protocol.mcp_transports import MCPTransportReason

    live = set(get_args(MCPTransportReason)) | set(get_args(AuthzReason))
    assert _TIMEOUT_REASONS <= live  # a renamed/removed timeout reason fails here
```

Run: `uv run pytest tests/unit/portal/api/mcp/test_mcp_routes.py -x` → all PASS.

- [ ] **Step 4: Lint + types**

Run: `uv run ruff check tests/unit/portal/api/mcp/ && uv run ruff format --check tests/unit/portal/api/mcp/ && uv run mypy tests/unit/portal/api/mcp/`
Expected: clean.

- [ ] **Step 5: Commit** — `test(portal): MCP route behavioral + status-map drift tests (ADR-002)`

---

## Task 6: Docs

**Files:**
- Modify: `docs/adrs/ADR-002-*.md` — append a "Fork-D production MCP-invocation surface" amendment (the two routes, the scopes, the status map, the dormant→live transition; consumes the existing approvals surface for grants).
- Modify: `docs/AS_BUILT_CAPABILITY_MAP.md` — mark the MCP host dormant→live (the protocol/MCP-host Pillar row + any forward item that named "the MCP-invocation route / Fork D").
- Modify: `AGENTS.md` — add the `portal/api/mcp/` route module + the `mcp.tool.*` scopes to the MCP-host section (note the route module is OFF the durable gate, like `portal/api/runs/`; the RBAC edits are additive).

- [ ] **Step 1** — write the ADR-002 amendment (the production surface; CC stays 131; route module off-gate; RBAC additive).
- [ ] **Step 2** — update AS_BUILT (both surfaces — the current-state row + any "Fork D / MCP-invocation route" forward item → DONE).
- [ ] **Step 3** — update AGENTS.md (the MCP-host section: the new route + scopes).
- [ ] **Step 4** — verify: `grep` each amendment anchor; confirm no stale "Fork D … deferred / no caller" current-state phrasing remains.
- [ ] **Step 5: Commit** — `docs(protocol): MCP tool-invocation route — Fork-D production surface (ADR-002)`

---

## Task 7: Closeout gate

**Files:** none (verification; a fixup commit only if the gate surfaces an issue).

- [ ] **Step 1** — `uv run ruff check . && uv run ruff format --check . && uv run mypy src tests`
- [ ] **Step 2** — full suite on fresh coverage: `uv run pytest -q --cov=cognic_agentos --cov-branch --cov-report=json:coverage.json`
- [ ] **Step 3** — `uv run python tools/check_critical_coverage.py` → **131/131** (the `portal/rbac/` edits keep coverage; no new on-gate module).
- [ ] **Step 4** — `git diff --stat origin/main...HEAD` shows only `portal/api/mcp/` (new, off-gate) + the additive `portal/rbac/` + `app.py` + tests + docs; **no new on-gate module**; `git status --porcelain` shows only the 2 protected untracked docs.
- [ ] **Step 5** — finish-the-branch (push + PR, controller-owned + token-gated; `--squash --delete-branch`).

---

## Self-Review (controller, after writing — fix inline)

- **Spec coverage:** §1 routes → T3/T4; §2 status map → T3 (`_REFUSAL_STATUS` + `_transport_status`/`_TIMEOUT_REASONS`) + T5 (the parametrized mapping + the drift test); §3 approval flow → T5 (the 202 + the re-call threading); §4 DTOs → T2; §5 actor-binding + request_id → T3 + T5; §6 scopes → T1; §7 mount + import-cleanliness → T4 + T3 Step 2; §8 testing → T5; posture → T7.
- **Type consistency:** `MCPRBACScope` / `MCP_SCOPES` (T1) used by T1's test + the unions; `CallToolRequest`/`CallToolResponse`/`ListToolsResponse` (T2) used by T3 + T5; `_TIMEOUT_REASONS` / `_REFUSAL_STATUS` / `_mint_request_id` (T3) used by T5; `CallResult` fields match `_call_result_to_response` + the test's `_call_result`.
- **Placeholders:** none — every step has complete code/commands.
- **Test-design (RESOLVED 2026-06-19 — user chose stub-host):** the route tests use a **stub host** — the correct route-unit-test design (unit-test the mapper; the host's real approval seam is already proven in `test_mcp_approval_seam.py`), matching the run-route precedent. The route's 202→re-call threading IS proven (T5 `test_call_recall_threads_approval_request_id`). The spec's `§8` was synced to this design (committed alongside this plan).
