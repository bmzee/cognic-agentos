"""Sprint-6 T14 — runtime canary for the anonymous-A2A refusal posture.

Per Sprint-6 Decision Lock #3 + ADR-003 §"Authentication": every
inbound A2A request MUST present a per-tenant pinned bearer token.
Anonymous-A2A traffic is forbidden Wave-1 (mTLS lands in Wave-2; VC
lands in Wave-3 per A2A-CONFORMANCE.md).

Canaries here drive the **real** :class:`A2AAuthzClient` — every gate
in the validator runs, and every adversarial Authorization-header
shape MUST refuse with the closed-enum :data:`A2AAuthzReason` value
the gate is meant to fire. The only mocks are the audit / decision-
history / vault adapters (not the subject of this canary; the
subject is the validator's gate logic).

If any arm passes when it shouldn't refuse, the anonymous-refusal
posture has been breached and the build must be reverted.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.protocol.a2a_authz import (
    A2AAuthzClient,
    A2AAuthzError,
)

# ---------------------------------------------------------------------------
# Real-A2AAuthzClient fixture — the validator IS the subject; only the
# audit / decision-history / vault adapters are mocked.
# ---------------------------------------------------------------------------


def _make_authz_client(
    *,
    vault_response: dict[str, Any] | Exception | None = None,
) -> A2AAuthzClient:
    """Construct a real :class:`A2AAuthzClient` for the canary.

    The vault read is mocked because the subject of the canary is
    the validator's gate logic, not the secret-store integration.
    Every other code path inside the validator runs verbatim.
    """
    secret_adapter = MagicMock()
    if isinstance(vault_response, Exception):
        secret_adapter.read = AsyncMock(side_effect=vault_response)
    elif vault_response is None:
        # Default: a happy-path secret with a known active token.
        # Used by arms that don't need to fail at the Vault gate.
        secret_adapter.read = AsyncMock(return_value={"token": "the-active-token"})
    else:
        secret_adapter.read = AsyncMock(return_value=vault_response)
    audit_store = MagicMock()
    audit_store.append = AsyncMock(return_value=(None, b""))
    decision_history_store = MagicMock()
    decision_history_store.append = AsyncMock(return_value=(None, b""))
    return A2AAuthzClient(
        settings=build_settings_without_env_file(),
        vault_client=secret_adapter,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
    )


# ---------------------------------------------------------------------------
# TestAnonymousRefused — six adversarial header shapes.
# ---------------------------------------------------------------------------


class TestAnonymousRefused:
    """Six adversarial Authorization-header shapes, each pinned to
    its closed-enum :data:`A2AAuthzReason`. Drives the real
    :class:`A2AAuthzClient.validate_inbound_token`."""

    async def test_missing_authorization_header_refused_anonymous(self) -> None:
        client = _make_authz_client()
        with pytest.raises(A2AAuthzError) as excinfo:
            await client.validate_inbound_token(
                authorization_header=None,
                tenant_id="bank_a",
                request_id="rid-anon-1",
            )
        assert excinfo.value.reason == "a2a_anonymous_refused"

    async def test_empty_authorization_header_refused_anonymous(self) -> None:
        # Empty-string header is falsy and falls into the anonymous
        # gate (same as ``None``) — the validator treats them
        # identically per the truthy check at validate_inbound_token
        # gate 1.
        client = _make_authz_client()
        with pytest.raises(A2AAuthzError) as excinfo:
            await client.validate_inbound_token(
                authorization_header="",
                tenant_id="bank_a",
                request_id="rid-anon-2",
            )
        assert excinfo.value.reason == "a2a_anonymous_refused"

    async def test_non_bearer_scheme_refused_token_missing(self) -> None:
        # "Basic dXNlcjpwd2Q=" — basic-auth scheme; no Bearer prefix.
        client = _make_authz_client()
        with pytest.raises(A2AAuthzError) as excinfo:
            await client.validate_inbound_token(
                authorization_header="Basic dXNlcjpwd2Q=",
                tenant_id="bank_a",
                request_id="rid-anon-3",
            )
        assert excinfo.value.reason == "a2a_token_missing"

    async def test_non_scheme_garbage_refused_token_missing(self) -> None:
        client = _make_authz_client()
        with pytest.raises(A2AAuthzError) as excinfo:
            await client.validate_inbound_token(
                authorization_header="this-is-not-a-scheme",
                tenant_id="bank_a",
                request_id="rid-anon-4",
            )
        assert excinfo.value.reason == "a2a_token_missing"

    async def test_empty_bearer_token_refused_token_malformed(self) -> None:
        client = _make_authz_client()
        with pytest.raises(A2AAuthzError) as excinfo:
            await client.validate_inbound_token(
                authorization_header="Bearer ",
                tenant_id="bank_a",
                request_id="rid-anon-5",
            )
        assert excinfo.value.reason == "a2a_token_malformed"

    async def test_whitespace_only_bearer_token_refused_token_malformed(self) -> None:
        client = _make_authz_client()
        with pytest.raises(A2AAuthzError) as excinfo:
            await client.validate_inbound_token(
                authorization_header="Bearer    \t   ",
                tenant_id="bank_a",
                request_id="rid-anon-6",
            )
        assert excinfo.value.reason == "a2a_token_malformed"

    async def test_inactive_token_refused_token_malformed(self) -> None:
        # Vault returns a different active token than the one the
        # caller presents — the constant-time compare fails and the
        # validator refuses with token_malformed (per the validator's
        # current closed-enum mapping, distinct from token_revoked
        # which is the digest-on-revocation-list case).
        client = _make_authz_client(vault_response={"token": "a-DIFFERENT-active-token"})
        with pytest.raises(A2AAuthzError) as excinfo:
            await client.validate_inbound_token(
                authorization_header="Bearer the-callers-token-not-the-active-one",
                tenant_id="bank_a",
                request_id="rid-anon-7",
            )
        assert excinfo.value.reason == "a2a_token_malformed"
