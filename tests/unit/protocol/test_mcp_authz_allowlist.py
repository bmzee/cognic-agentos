"""PR-2b-1 Task 2 — MCP per-tenant internal-host allow-list carve-out (CC).

The strict-profile SSRF guard (``_refuse_non_public_discovery_url``) refuses a
private/internal resolved host by default. For the THREE resource legs
(``server_url`` / ``prm_metadata`` / ``well_known_prm``) over ``http`` it consults
the invoking tenant's exact-IP allow-list (the Task-1 DB store): a hit where EVERY
resolved IP is in the allow-list AND passes the internal floor → permitted +
audited (``audit.mcp_allowlist_permitted``) + returns the pinned validated IP for
Task 3. The OAuth legs (``as_metadata`` / ``token_endpoint``) are NEVER carved out;
``https`` is NEVER carved out; a corrupted allow-list entry (metadata / loopback)
is caught by the guard-time floor; an unreachable store fails closed (deny); a
public host returns ``None`` without consulting the allow-list.

Hermetic: the module-level ``_resolve_host_addresses`` seam is monkeypatched so an
internal hostname resolves to a private IP with no real DNS.
"""

from __future__ import annotations

import ast
import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import cast
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.mcp_config.storage import MCPInternalHostAllowlistStore
from cognic_agentos.protocol import mcp_authz
from cognic_agentos.protocol.mcp_authz import DiscoveryLeg, MCPAuthzClient, MCPAuthzError

_RESOURCE_LEGS = ("server_url", "prm_metadata", "well_known_prm")
_OAUTH_LEGS = ("as_metadata", "token_endpoint")


class _StubAllowlistStore:
    """Minimal ``MCPInternalHostAllowlistStore`` stand-in. ``get_allowlist`` returns
    a fixed frozenset (or raises ``raise_exc``, to exercise fail-closed +
    cancellation). Records the tenant_ids it was consulted for."""

    def __init__(
        self,
        *,
        allowlist: frozenset[str] = frozenset(),
        raise_exc: BaseException | None = None,
    ) -> None:
        self._allowlist = allowlist
        self._raise_exc = raise_exc
        self.calls: list[str] = []

    async def get_allowlist(self, *, tenant_id: str) -> frozenset[str]:
        self.calls.append(tenant_id)
        if self._raise_exc is not None:
            raise self._raise_exc
        return self._allowlist


def _make_client(
    *,
    profile: str = "prod",
    allowlist_store: _StubAllowlistStore | None = None,
) -> tuple[MCPAuthzClient, MagicMock]:
    settings = build_settings_without_env_file().model_copy(update={"runtime_profile": profile})
    audit = MagicMock()
    audit.append = AsyncMock()
    client = MCPAuthzClient(
        settings=settings,
        vault_client=MagicMock(),
        # The guard never fetches; a MagicMock http client suffices.
        http_client=cast(httpx.AsyncClient, MagicMock()),
        audit_store=audit,
        decision_history_store=MagicMock(),
        internal_host_allowlist_store=cast(MCPInternalHostAllowlistStore | None, allowlist_store),
    )
    return client, audit


def _resolver(mapping: dict[str, list[str]]) -> Callable[[str], Awaitable[list[str]]]:
    async def _resolve(host: str) -> list[str]:
        return mapping[host]

    return _resolve


def _patch_resolve(monkeypatch: pytest.MonkeyPatch, mapping: dict[str, list[str]]) -> None:
    monkeypatch.setattr(mcp_authz, "_resolve_host_addresses", _resolver(mapping))


# ---------------------------------------------------------------------------
# carve-out HIT — all three resource legs, http, every IP allow-listed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("leg", _RESOURCE_LEGS)
async def test_carve_out_hit_returns_pinned_ip_and_emits_permit(
    leg: DiscoveryLeg, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_resolve(monkeypatch, {"internal.svc": ["10.42.0.7"]})
    store = _StubAllowlistStore(allowlist=frozenset({"10.42.0.7"}))
    client, audit = _make_client(allowlist_store=store)

    result = await client._refuse_non_public_discovery_url(
        "http://internal.svc:8080/mcp", leg=leg, tenant_id="bank_a", request_id="r1"
    )

    assert result == "10.42.0.7"  # pinned validated IP for Task 3
    assert store.calls == ["bank_a"]
    assert audit.append.await_count == 1
    event = audit.append.await_args.args[0]
    assert event.event_type == "audit.mcp_allowlist_permitted"
    assert event.tenant_id == "bank_a"  # top-level AuditEvent field
    assert event.request_id == "r1"  # top-level AuditEvent field
    assert event.payload == {
        "leg": leg,
        "host": "internal.svc",
        "resolved_ips": ["10.42.0.7"],
    }
    assert "pack_id" not in event.payload  # DD-2 — no pack thread through authz


async def test_carve_out_hit_multi_ip_all_listed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, {"internal.svc": ["10.42.0.7", "10.42.0.9"]})
    store = _StubAllowlistStore(allowlist=frozenset({"10.42.0.7", "10.42.0.9"}))
    client, audit = _make_client(allowlist_store=store)

    result = await client._refuse_non_public_discovery_url(
        "http://internal.svc/mcp", leg="server_url", tenant_id="bank_a", request_id="r1"
    )

    assert result == "10.42.0.7"  # FIRST resolved IP is the pin
    event = audit.append.await_args.args[0]
    assert event.payload["resolved_ips"] == ["10.42.0.7", "10.42.0.9"]


# ---------------------------------------------------------------------------
# carve-out MISS — not listed / empty / partial → refused, no permit event
# ---------------------------------------------------------------------------


async def test_carve_out_miss_ip_not_listed_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, {"internal.svc": ["10.42.0.7"]})
    store = _StubAllowlistStore(allowlist=frozenset({"10.42.0.9"}))  # different IP
    client, audit = _make_client(allowlist_store=store)

    with pytest.raises(MCPAuthzError) as exc:
        await client._refuse_non_public_discovery_url(
            "http://internal.svc/mcp", leg="server_url", tenant_id="bank_a", request_id="r1"
        )
    assert exc.value.reason == "mcp_discovery_url_refused"
    assert exc.value.payload.get("refused_component") == "host_address"
    assert exc.value.payload.get("leg") == "server_url"
    assert audit.append.await_count == 0


async def test_carve_out_miss_empty_allowlist_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, {"internal.svc": ["10.42.0.7"]})
    store = _StubAllowlistStore(allowlist=frozenset())
    client, audit = _make_client(allowlist_store=store)

    with pytest.raises(MCPAuthzError) as exc:
        await client._refuse_non_public_discovery_url(
            "http://internal.svc/mcp", leg="server_url", tenant_id="bank_a", request_id="r1"
        )
    assert exc.value.reason == "mcp_discovery_url_refused"
    assert audit.append.await_count == 0


async def test_multi_ip_partial_listing_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    # both resolved IPs must be listed; only ...7 is → refused (all-or-nothing).
    _patch_resolve(monkeypatch, {"internal.svc": ["10.42.0.7", "10.42.0.9"]})
    store = _StubAllowlistStore(allowlist=frozenset({"10.42.0.7"}))
    client, audit = _make_client(allowlist_store=store)

    with pytest.raises(MCPAuthzError) as exc:
        await client._refuse_non_public_discovery_url(
            "http://internal.svc/mcp", leg="server_url", tenant_id="bank_a", request_id="r1"
        )
    assert exc.value.reason == "mcp_discovery_url_refused"
    assert audit.append.await_count == 0


async def test_mixed_public_private_only_private_listed_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_resolve(monkeypatch, {"internal.svc": ["10.42.0.7", "8.8.8.8"]})
    store = _StubAllowlistStore(allowlist=frozenset({"10.42.0.7"}))
    client, audit = _make_client(allowlist_store=store)

    with pytest.raises(MCPAuthzError) as exc:
        await client._refuse_non_public_discovery_url(
            "http://internal.svc/mcp", leg="server_url", tenant_id="bank_a", request_id="r1"
        )
    assert exc.value.reason == "mcp_discovery_url_refused"
    assert audit.append.await_count == 0


async def test_mixed_public_private_both_listed_floor_rejects_public(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Even if a buggy operator listed the public IP too, the guard-time floor
    # (ip_passes_internal_floor) rejects the non-private member → refused.
    _patch_resolve(monkeypatch, {"internal.svc": ["10.42.0.7", "8.8.8.8"]})
    store = _StubAllowlistStore(allowlist=frozenset({"10.42.0.7", "8.8.8.8"}))
    client, audit = _make_client(allowlist_store=store)

    with pytest.raises(MCPAuthzError) as exc:
        await client._refuse_non_public_discovery_url(
            "http://internal.svc/mcp", leg="server_url", tenant_id="bank_a", request_id="r1"
        )
    assert exc.value.reason == "mcp_discovery_url_refused"
    assert audit.append.await_count == 0


# ---------------------------------------------------------------------------
# HTTP-only — internal https is never carved out
# ---------------------------------------------------------------------------


async def test_internal_https_refused_even_when_ip_listed(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, {"internal.svc": ["10.42.0.7"]})
    store = _StubAllowlistStore(allowlist=frozenset({"10.42.0.7"}))
    client, audit = _make_client(allowlist_store=store)

    with pytest.raises(MCPAuthzError) as exc:
        await client._refuse_non_public_discovery_url(
            "https://internal.svc/mcp", leg="server_url", tenant_id="bank_a", request_id="r1"
        )
    assert exc.value.reason == "mcp_discovery_url_refused"
    assert store.calls == []  # scheme gate short-circuits BEFORE the allow-list consult
    assert audit.append.await_count == 0


# ---------------------------------------------------------------------------
# OAuth legs — never carved out (leg not in _RESOURCE_LEGS)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("leg", _OAUTH_LEGS)
async def test_oauth_leg_never_carved_out(
    leg: DiscoveryLeg, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_resolve(monkeypatch, {"as.internal.example": ["10.0.0.5"]})
    store = _StubAllowlistStore(allowlist=frozenset({"10.0.0.5"}))  # would match — but OAuth leg
    client, audit = _make_client(allowlist_store=store)

    with pytest.raises(MCPAuthzError) as exc:
        await client._refuse_non_public_discovery_url(
            "http://as.internal.example/x", leg=leg, tenant_id="bank_a", request_id="r1"
        )
    assert exc.value.reason == "mcp_discovery_url_refused"
    assert exc.value.payload.get("leg") == leg
    assert store.calls == []  # leg gate short-circuits BEFORE the allow-list consult
    assert audit.append.await_count == 0


# ---------------------------------------------------------------------------
# Fail-closed — store unreachable → deny
# ---------------------------------------------------------------------------


async def test_fail_closed_store_raises_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, {"internal.svc": ["10.42.0.7"]})
    store = _StubAllowlistStore(raise_exc=RuntimeError("db unreachable"))
    client, audit = _make_client(allowlist_store=store)

    with pytest.raises(MCPAuthzError) as exc:
        await client._refuse_non_public_discovery_url(
            "http://internal.svc/mcp", leg="server_url", tenant_id="bank_a", request_id="r1"
        )
    assert exc.value.reason == "mcp_discovery_url_refused"
    assert store.calls == ["bank_a"]  # consulted, raised → empty set → deny
    assert audit.append.await_count == 0


# ---------------------------------------------------------------------------
# Guard-time floor — a corrupted allow-list entry is still refused
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_ip", ["169.254.169.254", "127.0.0.1"])
async def test_guard_time_floor_catches_corrupted_allowlist(
    bad_ip: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_resolve(monkeypatch, {"internal.svc": [bad_ip]})
    store = _StubAllowlistStore(allowlist=frozenset({bad_ip}))  # corrupted: metadata/loopback
    client, audit = _make_client(allowlist_store=store)

    with pytest.raises(MCPAuthzError) as exc:
        await client._refuse_non_public_discovery_url(
            "http://internal.svc/mcp", leg="server_url", tenant_id="bank_a", request_id="r1"
        )
    assert exc.value.reason == "mcp_discovery_url_refused"
    assert audit.append.await_count == 0


# ---------------------------------------------------------------------------
# Public host — return None, no consult, no permit
# ---------------------------------------------------------------------------


async def test_public_host_returns_none_no_consult(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, {"public.example": ["93.184.216.34"]})
    # A store that would RAISE if consulted — proves the all-public path never consults.
    store = _StubAllowlistStore(raise_exc=AssertionError("must not consult on a public host"))
    client, audit = _make_client(allowlist_store=store)

    result = await client._refuse_non_public_discovery_url(
        "http://public.example/mcp", leg="server_url", tenant_id="bank_a", request_id="r1"
    )

    assert result is None
    assert store.calls == []
    assert audit.append.await_count == 0


# ---------------------------------------------------------------------------
# No store wired — internal resource leg still refuses (back-compat default-deny)
# ---------------------------------------------------------------------------


async def test_no_store_internal_resource_leg_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_resolve(monkeypatch, {"internal.svc": ["10.42.0.7"]})
    client, audit = _make_client(allowlist_store=None)

    with pytest.raises(MCPAuthzError) as exc:
        await client._refuse_non_public_discovery_url(
            "http://internal.svc/mcp", leg="server_url", tenant_id="bank_a", request_id="r1"
        )
    assert exc.value.reason == "mcp_discovery_url_refused"
    assert audit.append.await_count == 0


# ---------------------------------------------------------------------------
# Loader fail-closed unit coverage (directly drives the helper branches)
# ---------------------------------------------------------------------------


async def test_load_allowlist_none_store_returns_empty() -> None:
    client, _ = _make_client(allowlist_store=None)
    assert await client._load_internal_host_allowlist("bank_a") == frozenset()


async def test_load_allowlist_generic_exception_fails_closed() -> None:
    store = _StubAllowlistStore(raise_exc=RuntimeError("db down"))
    client, _ = _make_client(allowlist_store=store)
    assert await client._load_internal_host_allowlist("bank_a") == frozenset()


async def test_load_allowlist_propagates_cancelled_error() -> None:
    store = _StubAllowlistStore(raise_exc=asyncio.CancelledError())
    client, _ = _make_client(allowlist_store=store)
    with pytest.raises(asyncio.CancelledError):
        await client._load_internal_host_allowlist("bank_a")


async def test_load_allowlist_passes_through_store_value() -> None:
    store = _StubAllowlistStore(allowlist=frozenset({"10.42.0.7", "10.42.0.9"}))
    client, _ = _make_client(allowlist_store=store)
    assert await client._load_internal_host_allowlist("bank_a") == frozenset(
        {"10.42.0.7", "10.42.0.9"}
    )
    assert store.calls == ["bank_a"]


# ---------------------------------------------------------------------------
# _maybe_ip helper — both branches
# ---------------------------------------------------------------------------


def test_maybe_ip_parses_and_rejects() -> None:
    parsed = mcp_authz._maybe_ip("10.0.0.5")
    assert parsed is not None and str(parsed) == "10.0.0.5"
    assert mcp_authz._maybe_ip("not-an-ip") is None


# ---------------------------------------------------------------------------
# Drift pin (Step 4) — the carve-out branch is gated on BOTH
# `leg in _RESOURCE_LEGS` AND `parsed.scheme == "http"`, joined by `and`.
# ---------------------------------------------------------------------------


def _carve_out_if(fn: ast.AsyncFunctionDef) -> ast.If:
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.If)
            and "_emit_allowlist_permitted" in ast.dump(node)
            and "_RESOURCE_LEGS" in ast.dump(node.test)
        ):
            return node
    raise AssertionError("carve-out `if` (the one that emits the permit event) not found")


def _guard_fn() -> ast.AsyncFunctionDef:
    src = Path(mcp_authz.__file__).read_text()
    tree = ast.parse(src)
    return next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "_refuse_non_public_discovery_url"
    )


def test_carve_out_gated_on_resource_leg_membership() -> None:
    carve_if = _carve_out_if(_guard_fn())
    has_leg_in_resource_legs = any(
        isinstance(cmp, ast.Compare)
        and isinstance(cmp.left, ast.Name)
        and cmp.left.id == "leg"
        and any(isinstance(op, ast.In) for op in cmp.ops)
        and any(isinstance(c, ast.Name) and c.id == "_RESOURCE_LEGS" for c in cmp.comparators)
        for cmp in ast.walk(carve_if.test)
    )
    assert has_leg_in_resource_legs, "carve-out must be gated on `leg in _RESOURCE_LEGS`"


def test_carve_out_gated_on_http_scheme() -> None:
    carve_if = _carve_out_if(_guard_fn())
    has_http_eq = any(
        isinstance(cmp, ast.Compare)
        and isinstance(cmp.left, ast.Attribute)
        and cmp.left.attr == "scheme"
        and any(isinstance(op, ast.Eq) for op in cmp.ops)
        and any(isinstance(c, ast.Constant) and c.value == "http" for c in cmp.comparators)
        for cmp in ast.walk(carve_if.test)
    )
    assert has_http_eq, 'carve-out must be gated on `parsed.scheme == "http"`'


def test_carve_out_conditions_joined_by_and() -> None:
    carve_if = _carve_out_if(_guard_fn())
    assert any(
        isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And)
        for node in ast.walk(carve_if.test)
    ), "carve-out leg + scheme gates must be joined by `and` (single conjunction)"


def test_resource_legs_excludes_oauth_legs() -> None:
    assert set(mcp_authz._RESOURCE_LEGS) == {"server_url", "prm_metadata", "well_known_prm"}
    assert "as_metadata" not in mcp_authz._RESOURCE_LEGS
    assert "token_endpoint" not in mcp_authz._RESOURCE_LEGS
