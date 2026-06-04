"""Sprint 3 T8 — ``GET /api/v1/system/policy`` contract.

Pins the operator-facing cloud-policy posture endpoint per ADR-007.
The endpoint reflects ``Settings`` directly (intent surface); the
authoritative outcome surface is ``/api/v1/system/effective-routing``
(T9, separate test file).

Tests cover:
- Self-hosted-first defaults (the secure-by-default shape AgentOS
  ships) → ``allow_external_llm=False``, ``mode="self_hosted"``,
  empty allow-list.
- Operator-declared cloud-mixed posture surfaces correctly.
- Field naming uses ``mode`` (operator vocabulary), not the internal
  ``policy_mode`` Settings name.
- Allowed-provider list values pass through unchanged.
- Alias contract + guardrail-scope + ledger-window all surfaced so
  operators can verify the intent surface end-to-end.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from cognic_agentos.core.config import Settings
from cognic_agentos.portal.api.app import create_app
from tests.support.settings_fixtures import prod_settings


def _client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))


class TestSystemPolicyEndpoint:
    def test_self_hosted_defaults_returned(self) -> None:
        """Default Settings → secure self-hosted-first posture per
        ADR-007."""
        client = _client(prod_settings())
        resp = client.get("/api/v1/system/policy")
        assert resp.status_code == 200
        body = resp.json()
        assert body["allow_external_llm"] is False
        assert body["mode"] == "self_hosted"
        assert body["allowed_providers"] == []
        assert body["llm_guardrail_scope"] == "all"

    def test_cloud_mixed_posture_surfaces_correctly(self) -> None:
        """Operator-declared cloud posture: flag on, mode cloud_mixed,
        allow-list populated."""
        client = _client(
            prod_settings(
                allow_external_llm=True,
                policy_mode="cloud_mixed",
                allowed_providers=["openai", "anthropic"],
                llm_guardrail_scope="external_only",
            )
        )
        body = client.get("/api/v1/system/policy").json()
        assert body["allow_external_llm"] is True
        assert body["mode"] == "cloud_mixed"
        assert body["allowed_providers"] == ["openai", "anthropic"]
        assert body["llm_guardrail_scope"] == "external_only"

    def test_response_uses_operator_vocabulary_field_names(self) -> None:
        """Operator-facing field is ``mode``, not the internal
        ``policy_mode``. Pinning the rename so a casual rename in
        Settings doesn't silently break portal consumers."""
        body = _client(prod_settings()).get("/api/v1/system/policy").json()
        assert "mode" in body
        assert "policy_mode" not in body

    def test_alias_and_window_surfaced(self) -> None:
        """Tier alias contract + ledger window are part of the intent
        surface so operators can verify them without reading config."""
        client = _client(
            prod_settings(
                tier1_alias="cognic-tier1-cloud-openai",
                tier2_alias="cognic-tier2-dev",
                provider_honesty_ledger_window_minutes=120,
            )
        )
        body = client.get("/api/v1/system/policy").json()
        assert body["tier1_alias"] == "cognic-tier1-cloud-openai"
        assert body["tier2_alias"] == "cognic-tier2-dev"
        assert body["provider_honesty_ledger_window_minutes"] == 120

    def test_response_keys_are_stable_set(self) -> None:
        """Lock the public key set so future additions are intentional
        + reviewed (portal contract)."""
        body = _client(prod_settings()).get("/api/v1/system/policy").json()
        assert set(body.keys()) == {
            "allow_external_llm",
            "mode",
            "allowed_providers",
            "llm_guardrail_scope",
            "tier1_alias",
            "tier2_alias",
            "provider_honesty_ledger_window_minutes",
        }
