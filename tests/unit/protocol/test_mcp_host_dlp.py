"""M5 (ADR-017) — MCPHost DLP wiring contract tests.

Critical-controls module (``protocol/mcp_host.py``). Task 3 pins the optional
``dlp_guard`` construction seam; Task 4 pins the ``_dlp_pre_scan`` gate +
its ``call_tool`` insertion. Deps are self-contained (there is no
``conftest.py`` in ``tests/unit/protocol/``); ``require_mcp`` is
monkeypatched so the host constructs without the SDK check firing.

Task-4 watchpoints (M5 spec §4.1 invariants, each pinned below):

* Empty ``dlp_pre_hooks`` is a TRUE no-op — no serialization, no guard
  call, no evidence rows (byte-identical for every pre-M5 pack).
* ``dlp_pre_hooks`` declared + no guard wired → fail CLOSED
  (``dlp_pre_guard_unavailable``), never silent skip.
* Reason mapping: hook policy refusal → ``dlp_pre_refused`` (carries the
  hook's ``policy_reason``); hook exception → ``dlp_pre_failed``;
  unresolved declared hook_id → ``dlp_pre_failed``.
* A DLP-refused call reaches NEITHER ``authz.acquire_token`` NOR
  ``transport.open_session`` NOR ``transport.send``.
* Digest-only evidence: the raw argument plaintext appears in NO evidence
  surface (audit row, decision row, logs, exception text); the digest is
  sha256 of ``canonical_bytes(dict(arguments))`` — the §4.1 canonical-
  serialization invariant, pinned by exact-digest equality.
* Exactly ONE audit row + ONE decision row per refused call (the
  ``except MCPToolInvocationRefused: raise`` arm guards double-emit).

The behaviour tests build a REAL ``DLPGuard`` over a REAL
``HookDispatcher`` + ``HookRegistry`` (mirroring
``tests/unit/packs/hooks/test_dlp_hook_integration.py``) with two
arg-gated hooks shaped like the M5 proof pack
(``cognic-hook-schema-guard``): ``refuse_forbidden_schema_arg`` +
``explode_schema_guard``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import logging
import time
from collections.abc import Callable
from typing import Any, ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.cli._governance_vocab import HookPhase
from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.packs.hooks.dispatcher import HookDispatcher
from cognic_agentos.packs.hooks.dlp_integration import DLPGuard
from cognic_agentos.packs.hooks.registry import (
    HookDeclaration,
    HookRegistry,
    VerifiedHookPack,
)
from cognic_agentos.protocol.mcp_authz import MCPAuthzClient, Token
from cognic_agentos.sdk.hook import Hook, HookContext, HookResult


@pytest.fixture
def host_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    from cognic_agentos.protocol import mcp_host

    monkeypatch.setattr(mcp_host, "require_mcp", MagicMock())
    return mcp_host


def _host(host_module: Any, **kwargs: Any) -> Any:
    return host_module.MCPHost(
        servers={},
        transports={},
        authz=MagicMock(),
        audit_store=MagicMock(),
        decision_history_store=MagicMock(),
        settings=build_settings_without_env_file(),
        **kwargs,
    )


# ---------------------------------------------------------------------------
# Task-4 helpers — real hook kernel (registry + dispatcher + guard)
# ---------------------------------------------------------------------------

#: Sentinel argument values the arg-gated test hooks key on. Mirrors the
#: M5 proof-pack shape: the SAME deployed hook passes a permitted value
#: and refuses / explodes on its sentinel.
_FORBIDDEN_SENTINEL = b"__FORBIDDEN__"
_EXPLODE_SENTINEL = b"__EXPLODE__"


class _RefuseHook(Hook):
    """Arg-gated dlp_pre hook: refuses when the forbidden sentinel is
    present in the canonical-serialized arguments; passes otherwise."""

    hook_id: ClassVar[str] = "refuse_forbidden_schema_arg"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        if _FORBIDDEN_SENTINEL in payload:
            return HookResult(
                decision="refuse",
                redacted_payload=None,
                policy_reason="forbidden_schema_arg",
            )
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


class _ExplodeHook(Hook):
    """Arg-gated dlp_pre hook: raises (hook infrastructure failure) when
    its sentinel is present; passes otherwise."""

    hook_id: ClassVar[str] = "explode_schema_guard"
    phase: ClassVar[HookPhase] = "dlp_pre"

    async def _invoke(self, context: HookContext, payload: bytes) -> HookResult:
        if _EXPLODE_SENTINEL in payload:
            raise RuntimeError("simulated hook crash")
        return HookResult(decision="pass", redacted_payload=None, policy_reason=None)


def _make_loader(cls: type[Hook]) -> Callable[[], type[Hook]]:
    return lambda: cls


def _seed_registry_with(
    hooks: list[tuple[type[Hook], HookPhase, str]],
) -> HookRegistry:
    """Seed a registry with one verified pack carrying the given hooks
    (mirrors ``test_dlp_hook_integration.py``)."""
    registry = HookRegistry(max_timeout_seconds=30.0)
    decls = tuple(
        HookDeclaration(
            hook_id=cls.hook_id,
            phase=phase,
            ordering_class=oc,  # type: ignore[arg-type]
            timeout_seconds=1.0,
            fail_policy="fail_closed",
            fail_open_exception=None,
            callable_loader=_make_loader(cls),
        )
        for cls, phase, oc in hooks
    )
    pack = VerifiedHookPack(
        distribution_name="cognic-hook-schema-guard",
        distribution_version="0.1.0",
        signature_digest="sha256:" + "c" * 64,
        declarations=decls,
    )
    registry.register_pack(pack)
    return registry


def _build_guard(registry: HookRegistry) -> DLPGuard:
    dispatcher = HookDispatcher(
        registry=registry,
        max_payload_bytes=10_000,
        max_timeout_seconds_runtime=30.0,
        audit_emitter=None,
    )
    return DLPGuard(dispatcher=dispatcher)


def _token(value: str = "secret-token") -> Token:
    return Token(
        value=value,
        expires_at=time.time() + 3600,
        as_issuer="https://as.example",
        scopes=("mcp:tools",),
        resource_indicator="https://server.example/mcp",
        client_id="client-a",
    )


def _make_session(server_url: str, session_id: str = "sess-1") -> Any:
    """Build a real MCPSession dataclass instance (mirrors
    ``test_mcp_host.py``)."""
    from contextlib import AsyncExitStack

    from cognic_agentos.protocol.mcp_transports import MCPSession

    sdk_session = MagicMock()
    sdk_session.call_tool = AsyncMock(return_value={"content": "ok"})
    return MCPSession(
        server_url=server_url,
        sdk_session=sdk_session,
        exit_stack=AsyncExitStack(),
        get_session_id=lambda: session_id,
        token_scopes=("mcp:tools",),
        token_client_id="client-a",
    )


@dataclasses.dataclass
class _Deps:
    """Spy-instrumented host dependencies for the Task-4 behaviour tests."""

    transport: MagicMock
    authz: MagicMock
    audit_store: MagicMock
    dh_store: MagicMock
    settings: Any


@pytest.fixture
def mcp_test_deps() -> _Deps:
    transport = MagicMock()
    transport.open_session = AsyncMock(return_value=_make_session("https://server.example/mcp"))
    transport.send = AsyncMock(return_value={"content": "ok"})
    transport.close_session = AsyncMock(return_value=None)
    authz = MagicMock(spec=MCPAuthzClient)
    authz.acquire_token = AsyncMock(return_value=_token())
    authz.invalidate_cached_token = AsyncMock(return_value=None)
    authz.step_up_token = AsyncMock(return_value=_token("stepped-up"))
    audit_store = MagicMock(spec=AuditStore)
    audit_store.append = AsyncMock(return_value=("uuid", b"hash"))
    dh_store = MagicMock(spec=DecisionHistoryStore)
    dh_store.append = AsyncMock(return_value=("uuid", b"hash"))
    return _Deps(
        transport=transport,
        authz=authz,
        audit_store=audit_store,
        dh_store=dh_store,
        settings=build_settings_without_env_file(),
    )


def _entry(host_module: Any, **overrides: Any) -> Any:
    kwargs: dict[str, Any] = dict(
        server_id="oracle.schema",
        server_url="https://server.example/mcp",
        transport_kind="http",
        manifest_scopes=("mcp:tools",),
        risk_tier="read_only",
        pack_signature_digest="sha256:deadbeef",
    )
    kwargs.update(overrides)
    return host_module.MCPServerEntry(**kwargs)


def _wired_host(host_module: Any, *, entry: Any, deps: _Deps, dlp_guard: Any) -> Any:
    return host_module.MCPHost(
        servers={entry.server_id: entry},
        transports={"http": deps.transport},
        authz=deps.authz,
        audit_store=deps.audit_store,
        decision_history_store=deps.dh_store,
        settings=deps.settings,
        dlp_guard=dlp_guard,
    )


# ---------------------------------------------------------------------------
# Task 3 — construction seam
# ---------------------------------------------------------------------------


class TestMCPHostDLPGuardConstruction:
    """M5: ``MCPHost`` accepts an optional ``dlp_guard``. ``None`` (the default)
    keeps the pre-M5 construction byte-for-byte; a wired guard is stored for
    ``call_tool``'s dlp_pre scan (Task 4)."""

    def test_dlp_guard_defaults_none(self, host_module: Any) -> None:
        host = _host(host_module)
        assert host._dlp_guard is None

    def test_dlp_guard_is_stored(self, host_module: Any) -> None:
        guard = MagicMock()
        host = _host(host_module, dlp_guard=guard)
        assert host._dlp_guard is guard


# ---------------------------------------------------------------------------
# Task 4 — _dlp_pre_scan contract
# ---------------------------------------------------------------------------


class TestDLPPreScan:
    """The ``_dlp_pre_scan`` gate: no-op / fail-closed / reason-mapping /
    digest-only evidence contracts (M5 spec §4.1)."""

    @pytest.mark.asyncio
    async def test_empty_dlp_pre_hooks_is_noop_scan_not_called(
        self, host_module: Any, mcp_test_deps: _Deps
    ) -> None:
        d = mcp_test_deps

        class _SpyGuard:
            async def scan_pre(self, **kwargs: Any) -> Any:
                raise AssertionError("scan_pre must not run for empty dlp_pre_hooks")

        entry = _entry(host_module)  # dlp_pre_hooks defaults to ()
        host = _wired_host(host_module, entry=entry, deps=d, dlp_guard=_SpyGuard())
        await host._dlp_pre_scan(
            entry=entry,
            arguments={"table": "EMPLOYEES"},
            request_id="req-1",
            tenant_id="tenant-1",
            declared_risk_tier="read_only",
            tool_name="describe_table",
        )
        # TRUE no-op: no scan (the spy would have raised), no evidence rows
        assert d.audit_store.append.await_count == 0
        assert d.dh_store.append.await_count == 0

    @pytest.mark.asyncio
    async def test_non_empty_hooks_absent_guard_fails_closed(
        self, host_module: Any, mcp_test_deps: _Deps
    ) -> None:
        d = mcp_test_deps
        entry = _entry(host_module, dlp_pre_hooks=("refuse_forbidden_schema_arg",))
        host = _wired_host(host_module, entry=entry, deps=d, dlp_guard=None)
        with pytest.raises(host_module.MCPToolInvocationRefused) as ei:
            await host._dlp_pre_scan(
                entry=entry,
                arguments={"table": "EMPLOYEES"},
                request_id="req-1",
                tenant_id="tenant-1",
                declared_risk_tier="read_only",
                tool_name="describe_table",
            )
        assert ei.value.reason == "dlp_pre_guard_unavailable"
        # refusal evidence emitted at the refusal site, digest-only
        assert d.audit_store.append.await_count == 1
        row = d.audit_store.append.await_args_list[-1].args[0]
        assert row.event_type == "audit.tool_invocation_refused"
        assert row.payload["refusal_reason"] == "dlp_pre_guard_unavailable"
        expected_digest = hashlib.sha256(canonical_bytes({"table": "EMPLOYEES"})).hexdigest()
        assert row.payload["dlp_policy_input_digest"] == expected_digest
        assert row.payload["declared_dlp_pre_hooks"] == ["refuse_forbidden_schema_arg"]
        decision_row = d.dh_store.append.await_args_list[-1].args[0]
        assert decision_row.payload["decision"] == "refused"
        assert decision_row.payload["decision_reason"] == "dlp_pre_guard_unavailable"

    @pytest.mark.asyncio
    async def test_policy_refuse_maps_to_dlp_pre_refused_digest_only(
        self,
        host_module: Any,
        mcp_test_deps: _Deps,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        d = mcp_test_deps
        registry = _seed_registry_with([(_RefuseHook, "dlp_pre", "input_validation")])
        guard = _build_guard(registry)
        entry = _entry(
            host_module,
            data_classes=("internal",),
            dlp_pre_hooks=("refuse_forbidden_schema_arg",),
            manifest_purpose="operational_telemetry",
        )
        host = _wired_host(host_module, entry=entry, deps=d, dlp_guard=guard)
        with (
            caplog.at_level(logging.DEBUG),
            pytest.raises(host_module.MCPToolInvocationRefused) as ei,
        ):
            await host._dlp_pre_scan(
                entry=entry,
                arguments={"table": "__FORBIDDEN__"},
                request_id="req-1",
                tenant_id="tenant-1",
                declared_risk_tier="read_only",
                tool_name="describe_table",
            )
        exc = ei.value
        assert exc.reason == "dlp_pre_refused"
        # 403 surface (Task 5) reads the hook's closed-enum policy reason
        assert exc.payload.get("policy_reason") == "forbidden_schema_arg"
        # exactly ONE audit row + ONE decision row
        assert d.audit_store.append.await_count == 1
        assert d.dh_store.append.await_count == 1
        row = d.audit_store.append.await_args_list[-1].args[0]
        decision_row = d.dh_store.append.await_args_list[-1].args[0]
        # digest-only: the raw argument plaintext appears in NO evidence
        # surface — audit row, decision row, logs, exception text
        assert "__FORBIDDEN__" not in repr(row)
        assert "__FORBIDDEN__" not in repr(row.payload)
        assert "__FORBIDDEN__" not in repr(decision_row)
        assert "__FORBIDDEN__" not in repr(decision_row.payload)
        assert "__FORBIDDEN__" not in caplog.text
        assert "__FORBIDDEN__" not in str(exc)
        # ...while the CANONICAL digest of the original arguments is present
        # (pins the canonical_bytes(dict(arguments)) serialization invariant)
        expected_digest = hashlib.sha256(canonical_bytes({"table": "__FORBIDDEN__"})).hexdigest()
        assert row.payload["refusal_reason"] == "dlp_pre_refused"
        assert row.payload["dlp_policy_input_digest"] == expected_digest
        assert row.payload["dlp_failed_hook_id"] == "refuse_forbidden_schema_arg"
        assert row.payload["dlp_failed_pack_distribution_name"] == "cognic-hook-schema-guard"
        assert decision_row.payload["decision"] == "refused"
        assert decision_row.payload["decision_reason"] == "dlp_pre_refused"
        assert decision_row.payload["dlp_refusal"] is True

    @pytest.mark.asyncio
    async def test_hook_exception_maps_to_dlp_pre_failed(
        self, host_module: Any, mcp_test_deps: _Deps
    ) -> None:
        d = mcp_test_deps
        registry = _seed_registry_with([(_ExplodeHook, "dlp_pre", "input_validation")])
        guard = _build_guard(registry)
        entry = _entry(
            host_module,
            dlp_pre_hooks=("explode_schema_guard",),
            manifest_purpose="operational_telemetry",
        )
        host = _wired_host(host_module, entry=entry, deps=d, dlp_guard=guard)
        with pytest.raises(host_module.MCPToolInvocationRefused) as ei:
            await host._dlp_pre_scan(
                entry=entry,
                arguments={"table": "__EXPLODE__"},
                request_id="req-1",
                tenant_id="tenant-1",
                declared_risk_tier="read_only",
                tool_name="describe_table",
            )
        assert ei.value.reason == "dlp_pre_failed"
        row = d.audit_store.append.await_args_list[-1].args[0]
        assert row.payload["refusal_reason"] == "dlp_pre_failed"
        assert row.payload["dlp_failed_hook_id"] == "explode_schema_guard"

    @pytest.mark.asyncio
    async def test_unresolved_hook_id_maps_to_dlp_pre_failed(
        self, host_module: Any, mcp_test_deps: _Deps
    ) -> None:
        d = mcp_test_deps
        registry = _seed_registry_with([(_RefuseHook, "dlp_pre", "input_validation")])
        guard = _build_guard(registry)
        entry = _entry(
            host_module,
            dlp_pre_hooks=("no_such_hook",),
            manifest_purpose="operational_telemetry",
        )
        host = _wired_host(host_module, entry=entry, deps=d, dlp_guard=guard)
        with pytest.raises(host_module.MCPToolInvocationRefused) as ei:
            await host._dlp_pre_scan(
                entry=entry,
                arguments={"table": "EMPLOYEES"},
                request_id="req-1",
                tenant_id="tenant-1",
                declared_risk_tier="read_only",
                tool_name="describe_table",
            )
        assert ei.value.reason == "dlp_pre_failed"
        row = d.audit_store.append.await_args_list[-1].args[0]
        assert row.payload["refusal_reason"] == "dlp_pre_failed"

    @pytest.mark.asyncio
    async def test_passed_scan_returns_none_without_evidence(
        self, host_module: Any, mcp_test_deps: _Deps
    ) -> None:
        d = mcp_test_deps
        registry = _seed_registry_with([(_RefuseHook, "dlp_pre", "input_validation")])
        guard = _build_guard(registry)
        entry = _entry(
            host_module,
            dlp_pre_hooks=("refuse_forbidden_schema_arg",),
            manifest_purpose="operational_telemetry",
        )
        host = _wired_host(host_module, entry=entry, deps=d, dlp_guard=guard)
        result = await host._dlp_pre_scan(
            entry=entry,
            arguments={"table": "EMPLOYEES"},
            request_id="req-1",
            tenant_id="tenant-1",
            declared_risk_tier="read_only",
            tool_name="describe_table",
        )
        assert result is None
        assert d.audit_store.append.await_count == 0
        assert d.dh_store.append.await_count == 0


# ---------------------------------------------------------------------------
# Task 4 — call_tool insertion (after approval gate, before token/session)
# ---------------------------------------------------------------------------


class TestCallToolDLPGate:
    """``call_tool`` runs ``_dlp_pre_scan`` INSIDE the evidence-emitting
    try, after the approval gate and BEFORE any token / session /
    transport work."""

    @pytest.mark.asyncio
    async def test_refusal_reaches_no_token_session_or_transport(
        self, host_module: Any, mcp_test_deps: _Deps
    ) -> None:
        d = mcp_test_deps
        registry = _seed_registry_with([(_RefuseHook, "dlp_pre", "input_validation")])
        guard = _build_guard(registry)
        entry = _entry(
            host_module,
            dlp_pre_hooks=("refuse_forbidden_schema_arg",),
            manifest_purpose="operational_telemetry",
        )
        host = _wired_host(host_module, entry=entry, deps=d, dlp_guard=guard)
        with pytest.raises(host_module.MCPToolInvocationRefused) as ei:
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="describe_table",
                arguments={"table": "__FORBIDDEN__"},
                request_id="req-1",
                tenant_id="tenant-1",
            )
        assert ei.value.reason == "dlp_pre_refused"
        # the refusal fired BEFORE any token / session / transport work
        assert d.authz.acquire_token.await_count == 0
        assert d.transport.open_session.await_count == 0
        assert d.transport.send.await_count == 0
        # single-emit: the except MCPToolInvocationRefused: raise arm
        # prevents the generic-Exception arm from double-emitting
        assert d.audit_store.append.await_count == 1
        assert d.dh_store.append.await_count == 1

    @pytest.mark.asyncio
    async def test_passing_guard_call_tool_reaches_transport(
        self, host_module: Any, mcp_test_deps: _Deps
    ) -> None:
        d = mcp_test_deps
        registry = _seed_registry_with([(_RefuseHook, "dlp_pre", "input_validation")])
        guard = _build_guard(registry)
        entry = _entry(
            host_module,
            dlp_pre_hooks=("refuse_forbidden_schema_arg",),
            manifest_purpose="operational_telemetry",
        )
        host = _wired_host(host_module, entry=entry, deps=d, dlp_guard=guard)
        result = await host.call_tool(
            server_id=entry.server_id,
            tool_name="describe_table",
            arguments={"table": "EMPLOYEES"},
            request_id="req-1",
            tenant_id="tenant-1",
        )
        # permitted arg → scan passes → the ORIGINAL arguments dispatch
        assert d.authz.acquire_token.await_count == 1
        assert d.transport.send.await_count == 1
        assert result.payload == {"content": "ok"}
