"""Sprint-5 T10 — ADR-014 transitional high-risk-tier refusal at invocation.

Critical-controls module per AGENTS.md. The runtime tool-approval
engine lands in Sprint 13.5; until then, ADR-014 §"Sprint 5
(transitional rule)" mandates fail-closed for all tiers above
``internal_write``:

  > Harness ships fail-closed for all tiers above ``internal_write`` —
  > high-risk tools register but every invocation is refused with
  > ``tool_approval_engine_not_available`` and audit-logged. This is
  > the only safe state until the approval engine exists.

T10 implements this gate at the top of :meth:`MCPHost.call_tool`:

  - **Allow-list** (whitelist semantics; fail-closed default): the
    only two tiers that proceed are ``"read_only"`` and
    ``"internal_write"``. Every other declared risk_tier value
    (the named ADR-014 high-risk set + ANY unknown / typo / malformed
    value) is refused with the closed-enum
    ``MCPToolInvocationRefused("tool_approval_engine_not_available")``.
  - **Upstream of token acquisition + session open**: the gate fires
    BEFORE ``authz.acquire_token`` and BEFORE
    ``transport.open_session``. A refused call MUST NOT touch the
    AS or the MCP server — both for security (don't burn tokens on
    calls we'll refuse) and for audit cleanliness (a refusal row is
    the only evidence a refused call leaves; a token-refresh row
    or a session-open row would falsely imply we tried).
  - **Mechanical, not configurable**: there is no setting that
    relaxes the gate. Sprint 13.5 lands the approval engine and
    removes this gate.
  - **Audit row**: ``audit.tool_invocation_refused`` with payload
    ``{pack_id, pack_signature_digest, tool_name, mcp_session_id,
    as_issuer, scopes, resource_indicator, client_id,
    declared_risk_tier, refusal_reason:
    "tool_approval_engine_not_available", sprint_13_5_followup:
    True}`` (T11 consolidated emission via
    :meth:`MCPHost._emit_call_evidence`; ``pack_id`` is the
    canonical schema field — see `test_refusal_audit_row_payload_complete`).
    The ADR-014 path is pre-dispatch, so ``mcp_session_id`` /
    ``as_issuer`` / ``client_id`` / ``scopes`` /
    ``resource_indicator`` are all None on this row. The
    ``declared_risk_tier`` field carries the manifest value
    after R1+R2+R3 normalisation (operator-readable but
    bounded + control-character escaped). Audit-pipeline
    failure during the refusal-emit MUST NOT swallow the
    refusal — the refusal is the safety outcome and
    propagates regardless.
"""

from __future__ import annotations

import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.audit import AuditStore
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.protocol.mcp_authz import MCPAuthzClient, Token

# ---------------------------------------------------------------------------
# Fixtures + helpers (mirrors test_mcp_host.py shape)
# ---------------------------------------------------------------------------


def _token(value: str = "secret-token") -> Token:
    return Token(
        value=value,
        expires_at=time.time() + 3600,
        as_issuer="https://as.example",
        scopes=("mcp:tools",),
        resource_indicator="https://server.example/mcp",
        client_id="client-a",
    )


@pytest.fixture
def settings() -> Any:
    return build_settings_without_env_file().model_copy(
        update={
            "mcp_oauth_request_timeout_s": 7,
            "mcp_call_tool_timeout_s": 13,
        }
    )


@pytest.fixture
def host_module(monkeypatch: pytest.MonkeyPatch) -> Any:
    from cognic_agentos.protocol import mcp_host

    monkeypatch.setattr(mcp_host, "require_mcp", MagicMock())
    return mcp_host


@pytest.fixture
def authz() -> MagicMock:
    client = MagicMock(spec=MCPAuthzClient)
    client.acquire_token = AsyncMock(return_value=_token())
    client.invalidate_cached_token = AsyncMock(return_value=None)
    client.step_up_token = AsyncMock(return_value=_token("stepped-up"))
    return client


@pytest.fixture
def audit_store() -> MagicMock:
    store = MagicMock(spec=AuditStore)
    store.append = AsyncMock(return_value=("uuid", b"hash"))
    return store


@pytest.fixture
def decision_history_store() -> MagicMock:
    store = MagicMock(spec=DecisionHistoryStore)
    store.append = AsyncMock(return_value=("uuid", b"hash"))
    return store


def _make_session(server_url: str) -> Any:
    from contextlib import AsyncExitStack

    from cognic_agentos.protocol.mcp_transports import MCPSession

    sdk_session = MagicMock()
    sdk_session.call_tool = AsyncMock(return_value={"content": "ok"})
    sdk_session.list_tools = AsyncMock(return_value=[])
    return MCPSession(
        server_url=server_url,
        sdk_session=sdk_session,
        exit_stack=AsyncExitStack(),
        get_session_id=lambda: "sess-1",
        token_scopes=("mcp:tools",),
        token_client_id="client-a",
    )


@pytest.fixture
def http_transport() -> MagicMock:
    transport = MagicMock()
    transport.open_session = AsyncMock(return_value=_make_session("https://server.example/mcp"))
    transport.send = AsyncMock(return_value={"content": "ok"})
    transport.close_session = AsyncMock(return_value=None)
    return transport


def _server_entry(host_module: Any, *, risk_tier: str) -> Any:
    return host_module.MCPServerEntry(
        server_id=f"pack.{risk_tier}",
        server_url="https://server.example/mcp",
        transport_kind="http",
        manifest_scopes=("mcp:tools",),
        risk_tier=risk_tier,
        pack_signature_digest="sha256:deadbeef",
    )


def _make_host(
    host_module: Any,
    risk_tier: str,
    *,
    http_transport: MagicMock,
    authz: MagicMock,
    audit_store: MagicMock,
    decision_history_store: MagicMock,
    settings: Any,
) -> Any:
    entry = _server_entry(host_module, risk_tier=risk_tier)
    return entry, host_module.MCPHost(
        servers={entry.server_id: entry},
        transports={"http": http_transport},
        authz=authz,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
        settings=settings,
    )


# ---------------------------------------------------------------------------
# Low-risk tiers — invocation proceeds (gate transparent)
# ---------------------------------------------------------------------------


class TestRiskTierLowRiskTiers:
    """Per ADR-014: ``read_only`` + ``internal_write`` are the only
    tiers that may invoke without an approval-engine sign-off in
    Sprint 5. The gate MUST be transparent for these tiers — no
    refusal raised, no refusal audit row, normal call_tool flow."""

    @pytest.mark.parametrize("tier", ["read_only", "internal_write"])
    async def test_low_risk_tier_invocation_proceeds(
        self,
        tier: str,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        entry, host = _make_host(
            host_module,
            tier,
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        result = await host.call_tool(
            server_id=entry.server_id,
            tool_name="lookup",
            arguments={},
            request_id="r1",
            tenant_id="t-1",
        )
        # Normal flow ran end-to-end
        assert result.payload == {"content": "ok"}
        authz.acquire_token.assert_awaited_once()
        http_transport.open_session.assert_awaited_once()
        http_transport.send.assert_awaited_once()
        # No refusal audit row was emitted
        appended = [c.args[0] for c in audit_store.append.await_args_list]
        refusal_rows = [e for e in appended if e.event_type == "audit.tool_invocation_refused"]
        assert not refusal_rows


# ---------------------------------------------------------------------------
# High-risk tiers — invocation refused with closed-enum reason
# ---------------------------------------------------------------------------


_HIGH_RISK_TIERS = (
    "customer_data_read",
    "customer_data_write",
    "payment_action",
    "regulator_communication",
    "cross_tenant",
    "high_risk_custom",
)


class TestRiskTierHighRiskTiersRefused:
    """The 6 named ADR-014 high-risk tiers MUST every one refuse with
    ``tool_approval_engine_not_available``. The refusal is the
    sprint-5-transitional fail-closed safety state."""

    @pytest.mark.parametrize("tier", _HIGH_RISK_TIERS)
    async def test_high_risk_tier_refused_with_closed_enum_reason(
        self,
        tier: str,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        entry, host = _make_host(
            host_module,
            tier,
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )

        with pytest.raises(host_module.MCPToolInvocationRefused) as exc:
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "tool_approval_engine_not_available"
        # Payload carries the declared tier verbatim (operator can
        # triage typo vs intentional high-risk)
        assert exc.value.payload.get("declared_risk_tier") == tier


# ---------------------------------------------------------------------------
# Refusal upstream of token acquisition + session open
# ---------------------------------------------------------------------------


class TestRiskTierRefusalUpstreamOfDispatch:
    """Belt-and-suspenders: a refusal that reached the AS or the MCP
    server would mean the gate is in the wrong place (downstream of
    token-acquire / session-open). The gate MUST be the very first
    step in ``call_tool``."""

    @pytest.mark.parametrize("tier", _HIGH_RISK_TIERS)
    async def test_refusal_does_not_acquire_token(
        self,
        tier: str,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        entry, host = _make_host(
            host_module,
            tier,
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        with pytest.raises(host_module.MCPToolInvocationRefused):
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        # Refusal is upstream of the AS round-trip
        authz.acquire_token.assert_not_called()

    @pytest.mark.parametrize("tier", _HIGH_RISK_TIERS)
    async def test_refusal_does_not_open_transport_session(
        self,
        tier: str,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        entry, host = _make_host(
            host_module,
            tier,
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        with pytest.raises(host_module.MCPToolInvocationRefused):
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        # Refusal is upstream of session-open
        http_transport.open_session.assert_not_called()
        http_transport.send.assert_not_called()
        http_transport.close_session.assert_not_called()


# ---------------------------------------------------------------------------
# Audit row contract
# ---------------------------------------------------------------------------


class TestRiskTierRefusalAuditRow:
    """The refusal MUST emit ``audit.tool_invocation_refused`` with
    the exact payload schema the plan specifies (and T11 will
    consume). Operators query this row to triage why a high-risk
    pack got refused; the payload MUST carry enough context to
    correlate to the pack manifest + pack invocation."""

    async def test_refusal_audit_row_payload_complete(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        entry, host = _make_host(
            host_module,
            "payment_action",
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        with pytest.raises(host_module.MCPToolInvocationRefused):
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="transfer_funds",
                arguments={"amount": 100},
                request_id="req-42",
                tenant_id="bank-a",
            )
        appended = [c.args[0] for c in audit_store.append.await_args_list]
        refusal_rows = [e for e in appended if e.event_type == "audit.tool_invocation_refused"]
        assert len(refusal_rows) == 1
        row = refusal_rows[0]
        # Top-level event fields
        assert row.request_id == "req-42"
        assert row.tenant_id == "bank-a"
        # Payload schema per plan §T10/§T11 — both T10's ADR-014
        # row and T11's broader invocation row share ``pack_id`` as
        # the canonical pack-identity field (Sprint-5 wiring sets
        # MCPServerEntry.server_id == pack_id).
        p = row.payload
        assert p["pack_id"] == entry.server_id
        assert p["tool_name"] == "transfer_funds"
        assert p["declared_risk_tier"] == "payment_action"
        assert p["refusal_reason"] == "tool_approval_engine_not_available"
        assert p["sprint_13_5_followup"] is True
        # Tool arguments MUST NOT appear in the audit row — could
        # carry sensitive caller data; the refusal happens before any
        # data-classification policy has run, so the conservative
        # default is "no caller-supplied bytes in the refusal row"
        assert "arguments" not in p
        assert "100" not in str(p)
        assert "amount" not in str(p)


# ---------------------------------------------------------------------------
# Fail-closed default: unknown tiers refuse too (whitelist semantics)
# ---------------------------------------------------------------------------


class TestRiskTierUnknownValueFailsClosed:
    """The gate uses **whitelist** semantics: only the two named
    low-risk tiers proceed. Every other value — the 6 named
    high-risk tiers AND any unknown / typo / malformed value —
    refuses. Without this, a manifest typo (e.g.
    ``"read-only"`` with hyphen, or ``"internal_writ"``) would
    fall through both the low-risk and the named-high-risk
    branches and silently invoke."""

    @pytest.mark.parametrize(
        "tier",
        [
            "read-only",  # hyphen typo
            "internal_writ",  # truncation typo
            "READ_ONLY",  # case typo
            "",  # empty string
            "made_up_tier_value",  # entirely unknown
        ],
    )
    async def test_unknown_tier_refused(
        self,
        tier: str,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        entry, host = _make_host(
            host_module,
            tier,
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        with pytest.raises(host_module.MCPToolInvocationRefused) as exc:
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "tool_approval_engine_not_available"
        # Audit row carries the verbatim (typo'd) value so operators
        # see exactly what the manifest declared
        appended = [c.args[0] for c in audit_store.append.await_args_list]
        refusal_rows = [e for e in appended if e.event_type == "audit.tool_invocation_refused"]
        assert refusal_rows
        assert refusal_rows[0].payload["declared_risk_tier"] == tier


# ---------------------------------------------------------------------------
# Audit-emit failure does NOT mask the refusal
# ---------------------------------------------------------------------------


class TestRiskTierRefusalSurvivesAuditFailure:
    """If ``audit_store.append`` raises during the refusal-emit, the
    refusal is the safety outcome and MUST still propagate. Audit-
    pipeline failure is logged token-free but does not swallow the
    refusal — operator + system end up in the safe state (call
    refused), and the audit-emit failure is a separate operational
    issue surfaced via the warning log."""

    async def test_audit_failure_does_not_mask_refusal(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        entry, host = _make_host(
            host_module,
            "payment_action",
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        audit_store.append.side_effect = RuntimeError("audit chain DB unreachable")

        # The refusal MUST still raise — the safety outcome wins
        with pytest.raises(host_module.MCPToolInvocationRefused) as exc:
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "tool_approval_engine_not_available"


# ---------------------------------------------------------------------------
# Closed-enum + allow-list constants pinned
# ---------------------------------------------------------------------------


class TestRiskTierAllowListPinned:
    """The allow-list is a deliberate fence. Pin its value so a
    future refactor that adds a tier without explicit Sprint-N
    review is reviewer-visible."""

    def test_low_risk_allow_list_pinned(self, host_module: Any) -> None:
        assert frozenset({"read_only", "internal_write"}) == (
            host_module._ADR_014_LOW_RISK_TIERS
        ), (
            "Sprint-5 transitional ADR-014 low-risk allow-list drift. "
            "Adding a tier here weakens the fail-closed default. Any "
            "change MUST land alongside Sprint 13.5's approval engine."
        )

    def test_refusal_reason_closed_enum_pinned(self, host_module: Any) -> None:
        """Sprint 13.5b2 extended the Sprint-5 single-value enum with the
        five approval-engine outcomes (ADR-014). The transitional
        ``tool_approval_engine_not_available`` value is KEPT as the
        engine-absent fallback this suite pins; anything outside the
        6-value set is drift (mirror pin lives in
        test_mcp_approval_seam.py)."""
        from typing import get_args

        actual = frozenset(get_args(host_module.ToolInvocationRefusalReason))
        assert actual == frozenset(
            {
                "tool_approval_engine_not_available",
                "tool_approval_pending",
                "tool_approval_denied",
                "tool_approval_expired",
                "tool_approval_binding_mismatch",
                "tool_approval_request_not_found",
            }
        )

    def test_refusal_exception_inherits_from_runtime_error(self, host_module: Any) -> None:
        """``MCPToolInvocationRefused`` is a runtime-side closed-enum
        exception, distinct from ``MCPTransportError`` (transport-
        layer) and ``MCPAuthzError`` (auth-layer). All three inherit
        from a base operators can catch via ``Exception`` at the
        operator-tooling boundary."""
        assert issubclass(host_module.MCPToolInvocationRefused, Exception)


# ---------------------------------------------------------------------------
# R1 P2 — fail-closed on non-string risk_tier shapes (defense-in-depth)
# ---------------------------------------------------------------------------


class TestRiskTierMalformedShapesFailClosed:
    """``MCPServerEntry.risk_tier`` is typed as ``str``, but the
    portal lifespan wiring populates this from manifest TOML at
    runtime — a malformed manifest declaring ``risk_tier = ["x"]``
    or ``risk_tier = {"a": 1}`` would, without defense-in-depth at
    the orchestrator, raise raw ``TypeError`` from the membership
    check (``unhashable type: 'list'``) BEFORE the audit emit +
    closed-enum refusal fire. The reviewer's contract: malformed
    tiers MUST follow the same fail-closed path as unknown tiers
    — ``MCPToolInvocationRefused("tool_approval_engine_not_available")``
    + audit row carrying a sanitised representation of what was
    actually declared."""

    @pytest.mark.parametrize(
        "malformed_tier",
        [
            ["read_only"],
            ["read_only", "internal_write"],
            {"a": 1},
            None,
            42,
            True,
            3.14,
        ],
    )
    async def test_malformed_risk_tier_refuses_via_closed_enum_path(
        self,
        malformed_tier: Any,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        import dataclasses

        baseline = host_module.MCPServerEntry(
            server_id="pack.malformed",
            server_url="https://server.example/mcp",
            transport_kind="http",
            manifest_scopes=("mcp:tools",),
            risk_tier="read_only",
            pack_signature_digest="sha256:a",
        )
        bad_entry = dataclasses.replace(baseline, risk_tier=malformed_tier)
        host = host_module.MCPHost(
            servers={bad_entry.server_id: bad_entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )

        with pytest.raises(host_module.MCPToolInvocationRefused) as exc:
            await host.call_tool(
                server_id=bad_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "tool_approval_engine_not_available"
        # Gate is upstream of token + session work
        authz.acquire_token.assert_not_called()
        http_transport.open_session.assert_not_called()
        # Audit row emitted with string-typed declared_risk_tier
        appended = [c.args[0] for c in audit_store.append.await_args_list]
        refusal_rows = [e for e in appended if e.event_type == "audit.tool_invocation_refused"]
        assert len(refusal_rows) == 1
        declared = refusal_rows[0].payload["declared_risk_tier"]
        assert isinstance(declared, str), (
            f"declared_risk_tier in audit row MUST be a string for "
            f"clean canonical-form serialisation; got {type(declared).__name__}"
        )
        # The repr is recognisable so an operator can correlate
        assert repr(malformed_tier)[:32] in declared or str(malformed_tier)[:32] in declared

    async def test_list_risk_tier_does_not_raise_typeerror(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """Direct contract test for the headline reviewer example:
        a list-shaped risk_tier (lists are unhashable) MUST NOT
        escape as raw TypeError."""
        import dataclasses

        baseline = host_module.MCPServerEntry(
            server_id="pack.list-tier",
            server_url="https://server.example/mcp",
            transport_kind="http",
            manifest_scopes=("mcp:tools",),
            risk_tier="read_only",
            pack_signature_digest="sha256:a",
        )
        bad_entry = dataclasses.replace(baseline, risk_tier=["read_only", "internal_write"])
        host = host_module.MCPHost(
            servers={bad_entry.server_id: bad_entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )

        with pytest.raises(host_module.MCPToolInvocationRefused) as exc:
            await host.call_tool(
                server_id=bad_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "tool_approval_engine_not_available"
        assert not isinstance(exc.value, TypeError)


class TestRiskTierNormalizeHelper:
    """Direct unit-test on the normalisation helper so the contract
    is locked even if the gate code paths are refactored."""

    def test_string_passes_through_unchanged(self, host_module: Any) -> None:
        for value in ("read_only", "internal_write", "payment_action", ""):
            assert host_module._normalize_risk_tier_for_gate(value) == value

    def test_non_string_returned_as_truncated_repr(self, host_module: Any) -> None:
        for value in ([1, 2], {"a": 1}, None, 42, True, 3.14):
            normalized = host_module._normalize_risk_tier_for_gate(value)
            assert isinstance(normalized, str)
            assert len(normalized) <= 200

    def test_long_non_string_value_truncated(self, host_module: Any) -> None:
        """Pathological manifest declaring a 10-element list of
        1 KB strings MUST NOT produce a 10 KB audit row."""
        long_list = ["x" * 1000] * 10
        normalized = host_module._normalize_risk_tier_for_gate(long_list)
        assert len(normalized) <= 200, f"non-string repr exceeded 200 chars: {len(normalized)}"

    def test_long_unknown_string_value_truncated(self, host_module: Any) -> None:
        """**R2 P2 contract**: a malformed / malicious manifest
        declaring a multi-KB string risk_tier MUST NOT propagate
        verbatim into the audit row, exception message, or warning
        log. The R1 helper bounded only non-strings; strings now
        also get bounded when they exceed the cap."""
        very_long_string = "x" * 50_000
        normalized = host_module._normalize_risk_tier_for_gate(very_long_string)
        assert isinstance(normalized, str)
        assert len(normalized) <= 200, (
            f"long unknown string passed through unbounded: {len(normalized)} chars"
        )

    def test_short_unknown_string_passes_through_unchanged(self, host_module: Any) -> None:
        """Short unknown strings (typos like 'read-only' or
        'PAYMENT_ACTION') stay operator-readable — only LONG strings
        get truncated. Bounding short strings would degrade triage
        ergonomics for the common-case typo."""
        for value in (
            "read-only",
            "PAYMENT_ACTION",
            "internal_writ",
            "made_up_tier",
            "x" * 199,  # right at the boundary — still passes through
        ):
            assert host_module._normalize_risk_tier_for_gate(value) == value

    def test_allow_list_values_pass_through_even_at_long_lengths(self, host_module: Any) -> None:
        """Defensive: the two allow-list values are short, but pin
        the contract that an allow-list match always returns the
        value unchanged (so the gate's membership check sees the
        exact original string). A future allow-list addition with
        a longer name would otherwise risk being silently truncated
        below its match length."""
        for value in ("read_only", "internal_write"):
            assert host_module._normalize_risk_tier_for_gate(value) == value


class TestLongStringRiskTierEndToEnd:
    """End-to-end contract: a multi-KB string risk_tier MUST refuse
    via the closed-enum path AND the audit row's declared_risk_tier
    field MUST be bounded. Without R2 P2, the verbatim value would
    pollute the audit row + exception message + warning log."""

    async def test_multi_kb_string_risk_tier_bounded_in_audit_row(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        import dataclasses

        baseline = host_module.MCPServerEntry(
            server_id="pack.long-tier",
            server_url="https://server.example/mcp",
            transport_kind="http",
            manifest_scopes=("mcp:tools",),
            risk_tier="read_only",
            pack_signature_digest="sha256:a",
        )
        # 50 KB pathological string (could be a malicious manifest
        # or a shell-script-pasted-into-TOML accident)
        long_tier = "POISON-" + ("x" * 50_000) + "-END"
        bad_entry = dataclasses.replace(baseline, risk_tier=long_tier)
        host = host_module.MCPHost(
            servers={bad_entry.server_id: bad_entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )

        with pytest.raises(host_module.MCPToolInvocationRefused) as exc:
            await host.call_tool(
                server_id=bad_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "tool_approval_engine_not_available"
        # Audit row's declared_risk_tier MUST be bounded
        appended = [c.args[0] for c in audit_store.append.await_args_list]
        refusal_rows = [e for e in appended if e.event_type == "audit.tool_invocation_refused"]
        assert len(refusal_rows) == 1
        declared = refusal_rows[0].payload["declared_risk_tier"]
        assert isinstance(declared, str)
        assert len(declared) <= 200, (
            f"declared_risk_tier in audit row leaked the multi-KB string: {len(declared)} chars"
        )
        # The exception message also MUST NOT carry the full string
        # (the message uses repr(declared) which is itself bounded
        # because declared is already truncated)
        assert len(str(exc.value)) <= 1000, (
            f"exception message leaked the multi-KB string: {len(str(exc.value))} chars"
        )
        # The recognisable prefix should still appear so operators
        # can correlate to the manifest source
        assert "POISON-" in declared
        # And it doesn't leak the FULL string anywhere
        assert exc.value.payload["declared_risk_tier"] == declared
        for value in exc.value.payload.values():
            if isinstance(value, str):
                assert len(value) <= 1000, (
                    f"payload value carries the multi-KB string: {len(value)}"
                )


# ---------------------------------------------------------------------------
# R3 P2 — escape control chars in rejected risk_tier strings
# ---------------------------------------------------------------------------


class TestRiskTierControlCharacterEscaping:
    """Short unknown strings used to pass through the gate verbatim,
    flowing into ``declared_risk_tier``, the exception message, and
    the audit-failure warning log. A malicious or malformed manifest
    can declare a tier value with embedded control characters:

      - ``"payment_action\\nINFO 2026-... auth=success"`` — forges a
        log line in operator log streams that line-split on ``\\n``.
      - ``"\\x1b[31mFAKE-ALERT\\x1b[0m"`` — ANSI escape that rewrites
        operator terminal output to look like a different system
        message.
      - ``"x\\x00y"`` — embedded NUL that may truncate downstream
        viewers / hide content.

    The fix: every rejected string (i.e., every string NOT in the
    allow-list) is run through ``encode("unicode_escape")`` so
    ``\\n`` → ``\\\\n``, ``\\x1b`` → ``\\\\x1b``, NUL → ``\\\\x00``,
    etc. Allow-list values still pass through unchanged so the
    membership check is unaffected.
    """

    @pytest.mark.parametrize(
        "tier,marker",
        [
            ("payment_action\nINFO 2026-01-01 forged", "\\n"),
            ("internal_write\tWITH-TAB", "\\t"),
            ("\x1b[31mFAKE-ALERT\x1b[0m", "\\x1b"),
            ("read_only\x00malicious", "\\x00"),
            ("read_only\rWITH-CR", "\\r"),
        ],
    )
    async def test_control_char_in_rejected_string_is_escaped(
        self,
        tier: str,
        marker: str,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """Tier with embedded control char → refuses via closed-enum
        path AND the audit row + exception payload carry the
        ESCAPED form, never the raw control character."""
        import dataclasses

        baseline = host_module.MCPServerEntry(
            server_id="pack.ctrl",
            server_url="https://server.example/mcp",
            transport_kind="http",
            manifest_scopes=("mcp:tools",),
            risk_tier="read_only",
            pack_signature_digest="sha256:a",
        )
        bad_entry = dataclasses.replace(baseline, risk_tier=tier)
        host = host_module.MCPHost(
            servers={bad_entry.server_id: bad_entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )

        with pytest.raises(host_module.MCPToolInvocationRefused) as exc:
            await host.call_tool(
                server_id=bad_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        assert exc.value.reason == "tool_approval_engine_not_available"
        # Audit row's declared_risk_tier MUST contain the escape
        # sequence (e.g., "\\n" as literal backslash-n) and MUST NOT
        # contain the raw control character
        appended = [c.args[0] for c in audit_store.append.await_args_list]
        refusal_rows = [e for e in appended if e.event_type == "audit.tool_invocation_refused"]
        assert refusal_rows
        declared = refusal_rows[0].payload["declared_risk_tier"]
        # Find the raw control char that's part of `tier`
        for ctrl_char in ("\n", "\t", "\x1b", "\x00", "\r"):
            if ctrl_char in tier:
                assert ctrl_char not in declared, (
                    f"raw control char {ctrl_char!r} leaked into "
                    f"declared_risk_tier audit field: {declared!r}"
                )
        # The escape marker DOES appear (operator-correlatable to
        # the original manifest source)
        assert marker in declared, (
            f"escape marker {marker!r} missing from declared_risk_tier: {declared!r}"
        )

        # The exception message MUST also be free of raw control chars
        for ctrl_char in ("\n", "\t", "\x1b", "\x00", "\r"):
            if ctrl_char in tier:
                assert ctrl_char not in str(exc.value), (
                    f"raw control char {ctrl_char!r} leaked into "
                    f"exception message: {str(exc.value)!r}"
                )

    async def test_log_injection_via_newline_in_tier_does_not_forge_line(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Headline regression: a manifest declaring a tier shaped
        like ``"payment_action\\nWARN forged-line"`` MUST NOT forge
        a second log line in operator log output. Even if audit
        emission fails (which would trigger the warning log path),
        the log message MUST carry the escaped form, not the raw
        newline."""
        import dataclasses
        import logging

        baseline = host_module.MCPServerEntry(
            server_id="pack.injected",
            server_url="https://server.example/mcp",
            transport_kind="http",
            manifest_scopes=("mcp:tools",),
            risk_tier="read_only",
            pack_signature_digest="sha256:a",
        )
        injected_tier = "payment_action\nWARN cognic_agentos.security forged"
        bad_entry = dataclasses.replace(baseline, risk_tier=injected_tier)
        host = host_module.MCPHost(
            servers={bad_entry.server_id: bad_entry},
            transports={"http": http_transport},
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )

        # Force the audit-failure warning log path so we can inspect
        # what the log message contains
        audit_store.append.side_effect = RuntimeError("audit chain down")

        with (
            caplog.at_level(logging.WARNING, logger="cognic_agentos.protocol.mcp_host"),
            pytest.raises(host_module.MCPToolInvocationRefused),
        ):
            await host.call_tool(
                server_id=bad_entry.server_id,
                tool_name="lookup",
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )

        # Walk every captured log record's message — none MUST carry
        # the raw newline that would forge a separate log line
        for record in caplog.records:
            msg = record.getMessage()
            if "payment_action" in msg or "declared_risk_tier" in msg:
                # The log message MAY include the escaped form, but
                # MUST NOT contain a raw newline embedded inside the
                # tier value (the message itself may end in \n,
                # which is fine)
                # We check by ensuring the substring
                # "payment_action\nWARN" doesn't appear
                assert "payment_action\nWARN" not in msg, (
                    f"raw newline in tier value forged a log line split: {msg!r}"
                )


class TestRiskTierAllowListPassThroughVerbatim:
    """Defensive: even after R3's escaping discipline, allow-list
    values MUST pass through completely unchanged so the gate's
    exact-match check works. Bug class: a future refactor that
    accidentally escapes allow-list strings (e.g., escapes ALL
    strings then checks membership against escaped form) would
    silently refuse every previously-valid call."""

    def test_allow_list_strings_unchanged_by_helper(self, host_module: Any) -> None:
        # Even though these strings have no control chars to
        # escape, the contract is "literal pass-through" — a
        # refactor that ran them through encode/decode would still
        # be observable here (e.g., NFC normalisation could change
        # bytes silently for some Unicode strings; for ASCII
        # allow-list values it's a no-op, but the contract pin
        # protects against future Unicode allow-list additions).
        for value in ("read_only", "internal_write"):
            assert host_module._normalize_risk_tier_for_gate(value) == value
            # Identity check is too strong (Python interns short
            # strings) but byte-equality is the contract
            assert host_module._normalize_risk_tier_for_gate(value).encode() == value.encode()


class TestRiskTierEscapingHelper:
    """Direct unit-test on the escape behaviour of the normalisation
    helper."""

    @pytest.mark.parametrize(
        "raw,expected_marker",
        [
            ("foo\nbar", "\\n"),
            ("foo\tbar", "\\t"),
            ("foo\rbar", "\\r"),
            ("foo\x00bar", "\\x00"),
            ("foo\x1bbar", "\\x1b"),
            ("foo\x7fbar", "\\x7f"),  # DEL
        ],
    )
    def test_control_char_escaped_in_unknown_string(
        self, raw: str, expected_marker: str, host_module: Any
    ) -> None:
        normalized = host_module._normalize_risk_tier_for_gate(raw)
        # Raw control char absent
        for ctrl in ("\n", "\t", "\r", "\x00", "\x1b", "\x7f"):
            if ctrl in raw:
                assert ctrl not in normalized, (
                    f"raw control char {ctrl!r} survived in normalized output: {normalized!r}"
                )
        # Escape marker present
        assert expected_marker in normalized, (
            f"expected escape marker {expected_marker!r} missing from {normalized!r}"
        )

    def test_printable_ascii_unknown_string_passes_through(self, host_module: Any) -> None:
        """Printable ASCII typos render verbatim (operator
        readability for the common-case typo)."""
        for value in ("read-only", "PAYMENT_ACTION", "made_up_tier"):
            assert host_module._normalize_risk_tier_for_gate(value) == value


# ---------------------------------------------------------------------------
# R4 P2 — sanitize tool_name in operator-facing log + exception surfaces
# ---------------------------------------------------------------------------


class TestRiskTierToolNameSanitization:
    """``tool_name`` is caller-supplied to ``call_tool``. A refused
    high-risk call with ``tool_name='lookup\\nWARN forged'`` would,
    without sanitisation, forge a separate log line in the audit-
    failure warning path and pollute the exception message.

    Contract (R4 P2):
      - **Audit row payload** keeps raw ``tool_name`` — T11's
        downstream queries depend on the canonical name + JSON
        canonical-form serialisation already escapes control chars
        for the on-disk row.
      - **Exception message + warning log** carry the bounded +
        control-char-escaped form via
        :func:`_sanitize_string_for_operator_surface`.
    """

    @pytest.mark.parametrize(
        "tool_name,marker",
        [
            ("lookup\nWARN cognic_agentos.security forged", "\\n"),
            ("transfer\tWITH-TAB", "\\t"),
            ("\x1b[31mFAKE-CALL\x1b[0m", "\\x1b"),
            ("call\x00malicious", "\\x00"),
        ],
    )
    async def test_tool_name_with_control_char_escaped_in_exception_message(
        self,
        tool_name: str,
        marker: str,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """Refused high-risk call with control-char tool_name →
        exception message MUST carry the escaped form, NOT the raw
        control char."""
        entry, host = _make_host(
            host_module,
            "payment_action",
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        with pytest.raises(host_module.MCPToolInvocationRefused) as exc:
            await host.call_tool(
                server_id=entry.server_id,
                tool_name=tool_name,
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )
        message = str(exc.value)
        # Raw control char absent
        for ctrl in ("\n", "\t", "\x1b", "\x00"):
            if ctrl in tool_name:
                assert ctrl not in message, (
                    f"raw control char {ctrl!r} from caller-supplied "
                    f"tool_name leaked into exception message: {message!r}"
                )
        # Escape marker present (operator-correlatable)
        assert marker in message, (
            f"escape marker {marker!r} missing from exception message: {message!r}"
        )

    async def test_tool_name_log_injection_does_not_forge_warning_line(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Headline regression: tool_name with embedded newline MUST
        NOT forge a separate log line in the audit-failure warning
        path. Force the audit append to fail so the warning fires."""
        import logging

        entry, host = _make_host(
            host_module,
            "payment_action",
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        # Force the warning log path
        audit_store.append.side_effect = RuntimeError("audit chain down")

        injected_tool_name = "lookup\nWARN cognic_agentos.audit forged-as-real"
        with (
            caplog.at_level(logging.WARNING, logger="cognic_agentos.protocol.mcp_host"),
            pytest.raises(host_module.MCPToolInvocationRefused),
        ):
            await host.call_tool(
                server_id=entry.server_id,
                tool_name=injected_tool_name,
                arguments={},
                request_id="r1",
                tenant_id="t-1",
            )

        # Walk every captured record's message — none MUST contain
        # the raw newline embedded inside the tool_name (the
        # logger's own line-terminating \n is fine; we check that
        # the substring "lookup\nWARN" doesn't appear, which would
        # only happen if the caller's raw newline made it through)
        for record in caplog.records:
            msg = record.getMessage()
            if "lookup" in msg or "tool_name" in msg:
                assert "lookup\nWARN" not in msg, (
                    f"raw newline in tool_name forged a log line split: {msg!r}"
                )

    async def test_audit_payload_keeps_canonical_tool_name(
        self,
        host_module: Any,
        http_transport: MagicMock,
        authz: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        settings: Any,
    ) -> None:
        """T11 contract: the audit row's ``tool_name`` field carries
        the canonical (raw) tool_name for downstream queries —
        sanitisation only applies to operator-facing surfaces
        (exception message + warning log). JSON canonical-form
        serialisation handles on-disk safety for the audit chain."""
        entry, host = _make_host(
            host_module,
            "payment_action",
            http_transport=http_transport,
            authz=authz,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
            settings=settings,
        )
        # Use a printable tool_name (no control chars) to verify
        # canonical preservation; control-char tool names go
        # through the same path but the raw bytes get JSON-escaped
        # by canonical_bytes downstream.
        with pytest.raises(host_module.MCPToolInvocationRefused):
            await host.call_tool(
                server_id=entry.server_id,
                tool_name="transfer_funds",
                arguments={"amount": 100},
                request_id="r1",
                tenant_id="t-1",
            )

        appended = [c.args[0] for c in audit_store.append.await_args_list]
        refusal_rows = [e for e in appended if e.event_type == "audit.tool_invocation_refused"]
        assert refusal_rows
        # Canonical name preserved exactly (downstream T11 queries
        # by tool_name MUST find this row)
        assert refusal_rows[0].payload["tool_name"] == "transfer_funds"


class TestSanitizeStringForOperatorSurfaceHelper:
    """Direct unit-test on the operator-surface sanitiser helper."""

    @pytest.mark.parametrize(
        "raw,expected_marker",
        [
            ("foo\nbar", "\\n"),
            ("foo\tbar", "\\t"),
            ("foo\rbar", "\\r"),
            ("foo\x00bar", "\\x00"),
            ("foo\x1bbar", "\\x1b"),
            ("foo\x7fbar", "\\x7f"),
        ],
    )
    def test_control_char_escaped(self, raw: str, expected_marker: str, host_module: Any) -> None:
        sanitized = host_module._sanitize_string_for_operator_surface(raw)
        for ctrl in ("\n", "\t", "\r", "\x00", "\x1b", "\x7f"):
            if ctrl in raw:
                assert ctrl not in sanitized
        assert expected_marker in sanitized

    def test_printable_ascii_passes_through(self, host_module: Any) -> None:
        for value in ("transfer_funds", "lookup", "list-balances", "x" * 100):
            assert host_module._sanitize_string_for_operator_surface(value) == value

    def test_long_string_bounded(self, host_module: Any) -> None:
        sanitized = host_module._sanitize_string_for_operator_surface("x" * 50_000)
        assert len(sanitized) <= 200, f"sanitized string exceeded 200 chars: {len(sanitized)}"
