"""Slice-2 discovery-status contract tests (ADR-002 trust-register-then-defer, PR-1 Slice 2).

The pure contract — the 4-value enum + the reason→axis mapping + the in-memory recorder — is
tested here. The host-side recording (MCPHost) + the /system/plugins surface are exercised in
test_mcp_host.py / test_plugins_endpoint.py.
"""

from __future__ import annotations

import typing
from typing import cast

import pytest

from cognic_agentos.protocol.discovery_status import (
    _UNREACHABLE_AUTHZ_REASONS,
    DiscoveryStatus,
    DiscoveryStatusRecorder,
    InMemoryDiscoveryStatusRecorder,
    discovery_status_for_authz_reason,
)


class TestDiscoveryStatusEnum:
    def test_exactly_four_values(self) -> None:
        assert set(typing.get_args(DiscoveryStatus)) == {
            "unprobed",
            "auth_ready",
            "refused",
            "unreachable",
        }

    def test_unreachable_reason_set_is_the_two_network_failures(self) -> None:
        assert {
            "mcp_oauth_request_timeout",
            "mcp_oauth_transport_failure",
        } == _UNREACHABLE_AUTHZ_REASONS


class TestReasonMapping:
    @pytest.mark.parametrize("reason", ["mcp_oauth_request_timeout", "mcp_oauth_transport_failure"])
    def test_network_reasons_map_to_unreachable(self, reason: str) -> None:
        assert discovery_status_for_authz_reason(reason) == "unreachable"

    @pytest.mark.parametrize(
        "reason",
        [
            "mcp_discovery_url_refused",  # SSRF guard
            "mcp_as_not_allowlisted",
            "mcp_token_audience_mismatch",
            "mcp_token_scope_overgrant",
            "mcp_oauth_credentials_missing",
            "mcp_oauth_as_discovery_invalid",
            "mcp_oauth_token_endpoint_error",
            "mcp_oauth_token_response_invalid",
            "mcp_prm_invalid",
            "mcp_anonymous_refused",
        ],
    )
    def test_policy_auth_reasons_map_to_refused(self, reason: str) -> None:
        assert discovery_status_for_authz_reason(reason) == "refused"

    def test_every_acquire_token_authz_reason_maps_to_a_failure_status(self) -> None:
        """Drift guard: every ``AuthzReason`` that can reach ``acquire_token`` (the probe)
        maps to ``refused`` / ``unreachable`` — never crashes, never returns ``auth_ready`` /
        ``unprobed``. Cross-checked against the LIVE ``AuthzReason`` literal (test-only import,
        no runtime cross-module dependency)."""
        from cognic_agentos.protocol.mcp_authz import AuthzReason

        # Runtime-only reasons are emitted by MCPHost.call_tool / step_up_token, never by
        # acquire_token, so they never reach the discovery-status recorder.
        runtime_only = {"mcp_step_up_unauthorised", "mcp_authorisation_lost"}
        for reason in typing.get_args(AuthzReason):
            if reason in runtime_only:
                continue
            assert discovery_status_for_authz_reason(reason) in {"refused", "unreachable"}


class TestInMemoryRecorder:
    def test_conforms_to_protocol(self) -> None:
        assert isinstance(InMemoryDiscoveryStatusRecorder(), DiscoveryStatusRecorder)

    def test_default_is_unprobed(self) -> None:
        rec = InMemoryDiscoveryStatusRecorder()
        assert rec.get(tenant_id="t1", pack_id="p1") == "unprobed"

    @pytest.mark.parametrize("status", ["auth_ready", "refused", "unreachable", "unprobed"])
    def test_record_then_get_round_trips(self, status: str) -> None:
        rec = InMemoryDiscoveryStatusRecorder()
        rec.record(tenant_id="t1", pack_id="p1", status=cast(DiscoveryStatus, status))
        assert rec.get(tenant_id="t1", pack_id="p1") == status

    def test_last_write_wins(self) -> None:
        rec = InMemoryDiscoveryStatusRecorder()
        rec.record(tenant_id="t1", pack_id="p1", status="refused")
        rec.record(tenant_id="t1", pack_id="p1", status="auth_ready")
        assert rec.get(tenant_id="t1", pack_id="p1") == "auth_ready"

    def test_per_tenant_pack_isolation(self) -> None:
        """The no-leak invariant: a status for (t1, p1) is invisible to a different tenant or
        pack. This is the recorder-level half of the /system/plugins no-leak contract."""
        rec = InMemoryDiscoveryStatusRecorder()
        rec.record(tenant_id="t1", pack_id="p1", status="auth_ready")
        assert rec.get(tenant_id="t2", pack_id="p1") == "unprobed"
        assert rec.get(tenant_id="t1", pack_id="p2") == "unprobed"
