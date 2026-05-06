"""Sprint 6 T5 — protocol/a2a_authz.py contract tests.

Tests the per-tenant pinned-token validator. The 8-value
:class:`A2AAuthzReason` closed enum lives in
:mod:`cognic_agentos.protocol`; every fire-path of
:meth:`A2AAuthzClient.validate_inbound_token` maps to exactly one
literal value. Mirrors Sprint-5 ``test_mcp_authz.py`` shape — same
audit-emission pattern (chain row per outcome), same token-free
invariant (raw bytes never reach audit / repr / log surfaces),
same Vault-read exception-mapping discipline (T15 R1 P2 #2 + #3
from Sprint 5).

Per A2A-CONFORMANCE.md §"Authorization": Wave 1 uses per-tenant
pinned tokens stored at ``secret/cognic/<tenant>/a2a-pinned-token``.
mTLS lands in Wave 2; VC in Wave 3.
"""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from cognic_agentos.core.audit import AuditEvent
from cognic_agentos.core.config import build_settings_without_env_file
from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.protocol.a2a_authz import (
    A2AAuthzClient,
    A2AAuthzError,
    A2APinnedToken,
)


@pytest.fixture
def vault_client() -> MagicMock:
    """Mock SecretAdapter — the production interface only requires
    ``async read(path) -> dict[str, Any]``."""
    mock = MagicMock()
    mock.read = AsyncMock()
    return mock


@pytest.fixture
def audit_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock()
    return mock


@pytest.fixture
def decision_history_store() -> MagicMock:
    mock = MagicMock()
    mock.append = AsyncMock()
    return mock


@pytest.fixture
def authz(
    vault_client: MagicMock,
    audit_store: MagicMock,
    decision_history_store: MagicMock,
) -> A2AAuthzClient:
    return A2AAuthzClient(
        settings=build_settings_without_env_file(),
        vault_client=vault_client,
        audit_store=audit_store,
        decision_history_store=decision_history_store,
    )


def _good_secret(token: str = "active-token", **overrides: Any) -> dict[str, Any]:
    """Construct a Vault secret payload for the happy path; tests
    override individual fields to exercise specific failure paths."""
    base: dict[str, Any] = {
        "token": token,
        "tenant_id": "bank_a",
        "issued_at": 1_700_000_000.0,
        "expires_at": None,
    }
    base.update(overrides)
    return base


# =============================================================================
# Closed-enum reason fire-paths (8 reasons x ~2-3 arms each)
# =============================================================================


class TestAnonymousRefused:
    """Reason: ``a2a_anonymous_refused`` — the inbound request carries
    no Authorization header at all. Per A2A-CONFORMANCE.md, anonymous
    A2A is refused outright in every Wave."""

    async def test_none_authorization_header_refused(self, authz: A2AAuthzClient) -> None:
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header=None,
                tenant_id="bank_a",
                request_id="rid-anon-1",
            )
        assert exc.value.reason == "a2a_anonymous_refused"
        # Tenant + request id propagate into the payload for audit
        # correlation.
        assert exc.value.payload["tenant_id"] == "bank_a"
        assert exc.value.payload["request_id"] == "rid-anon-1"

    async def test_empty_string_authorization_header_refused(self, authz: A2AAuthzClient) -> None:
        """Empty-string header is treated identically to None — the
        spec requires a Bearer scheme, and empty doesn't carry one."""
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="",
                tenant_id="bank_a",
                request_id="rid-anon-2",
            )
        assert exc.value.reason == "a2a_anonymous_refused"


class TestTokenMissing:
    """Reason: ``a2a_token_missing`` — Authorization header present
    but does not start with ``Bearer ``. Defends against Basic /
    Digest / custom schemes that the Wave-1 spec does not honour."""

    async def test_basic_auth_scheme_refused(self, authz: A2AAuthzClient) -> None:
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Basic dXNlcjpwYXNz",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_token_missing"

    async def test_digest_auth_scheme_refused(self, authz: A2AAuthzClient) -> None:
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header='Digest username="u", realm="r"',
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_token_missing"

    async def test_lowercase_bearer_refused(self, authz: A2AAuthzClient) -> None:
        """RFC 6750 says scheme matching is case-insensitive but
        AgentOS's Wave-1 contract (per the plan-of-record) pins the
        exact ``Bearer `` prefix to keep the validator deterministic.
        A future spec amendment can relax this; until then, only the
        canonical capitalisation is honoured."""
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="bearer some-token",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_token_missing"


class TestTokenMalformed:
    """Reason: ``a2a_token_malformed`` — Bearer scheme present but the
    token bytes are unusable (empty / whitespace-only / mismatched
    against the active per-tenant token)."""

    async def test_bearer_with_empty_token_refused(self, authz: A2AAuthzClient) -> None:
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer ",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_token_malformed"

    async def test_bearer_with_whitespace_only_token_refused(self, authz: A2AAuthzClient) -> None:
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer    \t  ",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_token_malformed"

    async def test_bearer_with_token_not_matching_active_refused(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """Vault holds the active token; the inbound bytes don't match.
        Treated as malformed (the inbound bytes are not the per-tenant
        pinned token), distinct from ``a2a_token_revoked`` (which fires
        only when the digest is on the explicit revocation list)."""
        vault_client.read.return_value = _good_secret(token="active-token")
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer different-token",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_token_malformed"


class TestTenantMismatch:
    """Reason: ``a2a_tenant_mismatch`` — Vault secret declares a
    ``tenant_id`` that does not match the request's claimed tenant.
    Defends against cross-tenant token reuse where Vault routes the
    read but the secret carries a different tenant."""

    async def test_secret_tenant_id_does_not_match_request_refused(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        vault_client.read.return_value = _good_secret(tenant_id="bank_b")
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer active-token",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_tenant_mismatch"
        assert exc.value.payload["token_tenant_id"] == "bank_b"
        assert exc.value.payload["tenant_id"] == "bank_a"

    async def test_secret_without_tenant_id_field_passes_check(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """Defensive: Vault secrets without a ``tenant_id`` field
        skip the cross-tenant check (the Vault path itself encodes
        the tenant). Subsequent revocation + token-match checks still
        run; happy-path returns the pinned token."""
        secret = _good_secret()
        secret.pop("tenant_id")
        vault_client.read.return_value = secret
        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert isinstance(result, A2APinnedToken)
        assert result.tenant_id == "bank_a"


class TestVaultReadFailedMaps:
    """Reason: ``a2a_vault_read_failed`` — the Vault adapter raised
    an exception (RuntimeError, ValueError, custom adapter error)
    OR returned a non-mapping payload. Per Sprint-5 T15 R1 P2 #2 +
    #3 doctrine: raw exception text MUST NOT leak into the wrapped
    error message; ``type(exc).__name__`` lands in payload only."""

    async def test_runtime_error_maps(self, authz: A2AAuthzClient, vault_client: MagicMock) -> None:
        vault_client.read.side_effect = RuntimeError("vault: permission denied")
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer x",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_vault_read_failed"
        # Sprint-5 T15 R1 P2 #3: raw text never leaks.
        assert "permission denied" not in str(exc.value)
        assert exc.value.payload["vault_error_class"] == "RuntimeError"

    async def test_value_error_maps(self, authz: A2AAuthzClient, vault_client: MagicMock) -> None:
        vault_client.read.side_effect = ValueError("vault: malformed key")
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer x",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_vault_read_failed"
        assert "malformed key" not in str(exc.value)
        assert exc.value.payload["vault_error_class"] == "ValueError"

    async def test_non_mapping_secret_maps(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """Vault returned a value but it's not a dict (e.g., a list
        from a misconfigured secret). Maps to vault-read-failed
        (the secret shape is unusable)."""
        vault_client.read.return_value = ["not", "a", "dict"]
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer x",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_vault_read_failed"


class TestVaultReadCancellationPropagates:
    """Sprint-5 T15 R1 P2 #2 doctrine: ``asyncio.CancelledError``
    MUST propagate unwrapped — wrapping it in ``A2AAuthzError``
    would mask cooperative-cancellation semantics."""

    async def test_cancelled_error_propagates(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        async def _cancel(path: str) -> dict[str, Any]:
            raise asyncio.CancelledError

        vault_client.read.side_effect = _cancel
        with pytest.raises(asyncio.CancelledError):
            await authz.validate_inbound_token(
                authorization_header="Bearer x",
                tenant_id="bank_a",
                request_id="rid",
            )


class TestTokenRevoked:
    """Reason: ``a2a_token_revoked`` — token bytes match a digest
    on the per-tenant revocation list. Distinct from
    ``a2a_token_malformed`` (which fires when bytes don't match the
    active token at all): a revoked token MAY have been valid earlier
    but is explicitly rejected now."""

    async def test_token_digest_in_revocation_list_refused(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        revoked_token = "previously-active-token"
        revoked_digest = hashlib.sha256(revoked_token.encode()).hexdigest()
        vault_client.read.return_value = _good_secret(
            token="new-active-token",
            revoked_digests=[revoked_digest],
        )
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header=f"Bearer {revoked_token}",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_token_revoked"

    async def test_token_not_in_revocation_list_passes_to_match_check(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """Negative control: a token not on the revocation list flows
        into the active-match check. Here the bytes don't match the
        active token, so it falls through to ``a2a_token_malformed``
        (NOT ``a2a_token_revoked``) — the literals are precisely
        targeted."""
        vault_client.read.return_value = _good_secret(
            token="new-active-token",
            revoked_digests=[hashlib.sha256(b"some-other").hexdigest()],
        )
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer non-matching-token",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_token_malformed"


class TestAudienceMismatch:
    """Reason: ``a2a_audience_mismatch`` — Vault secret declares an
    ``audience`` and the request's expected audience (the AgentOS
    instance / pack receiving the call) does not match. Wave-1 use:
    pinned tokens issued for a specific receiver pack must not be
    replayed against a different receiver."""

    async def test_audience_in_secret_does_not_match_expected_refused(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        vault_client.read.return_value = _good_secret(
            audience="cognic_agent_alpha",
        )
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer active-token",
                tenant_id="bank_a",
                request_id="rid",
                expected_audience="cognic_agent_beta",
            )
        assert exc.value.reason == "a2a_audience_mismatch"
        assert exc.value.payload["expected_audience"] == "cognic_agent_beta"
        assert exc.value.payload["token_audience"] == "cognic_agent_alpha"

    async def test_audience_check_skipped_when_expected_is_none(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """When the caller passes no ``expected_audience`` (default),
        the check is skipped — backwards-compatible with code paths
        that don't yet wire audience validation."""
        vault_client.read.return_value = _good_secret(
            audience="cognic_agent_alpha",
        )
        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert isinstance(result, A2APinnedToken)


class TestScopeInsufficient:
    """Reason: ``a2a_scope_insufficient`` — Vault secret declares
    ``required_scopes`` and the request's claimed scopes do not cover
    them. Forward-reserved for Wave-2 mTLS/scope claims; Wave-1 path
    skips the check unless the secret carries ``required_scopes``."""

    async def test_required_scopes_not_subset_of_claimed_refused(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        vault_client.read.return_value = _good_secret(
            required_scopes=["a2a:invoke", "a2a:streaming"],
        )
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer active-token",
                tenant_id="bank_a",
                request_id="rid",
                claimed_scopes=("a2a:invoke",),
            )
        assert exc.value.reason == "a2a_scope_insufficient"
        assert "a2a:streaming" in exc.value.payload["missing_scopes"]

    async def test_required_scopes_satisfied_passes(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        vault_client.read.return_value = _good_secret(
            required_scopes=["a2a:invoke"],
        )
        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
            claimed_scopes=("a2a:invoke", "a2a:streaming"),
        )
        assert isinstance(result, A2APinnedToken)

    async def test_no_required_scopes_skips_check(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """Vault secret without ``required_scopes`` (the Wave-1
        default) skips the scope check entirely."""
        vault_client.read.return_value = _good_secret()
        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert isinstance(result, A2APinnedToken)


# =============================================================================
# Happy path + token-free invariant
# =============================================================================


class TestTokenAccepted:
    """Happy-path: a valid Bearer token returns an
    :class:`A2APinnedToken`. The bytes never escape via ``__repr__``,
    audit payloads, or decision-history payloads."""

    async def test_valid_token_returns_pinned_token(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        vault_client.read.return_value = _good_secret(
            token="active-token",
            issued_at=1_700_000_000.0,
            expires_at=1_800_000_000.0,
        )
        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert isinstance(result, A2APinnedToken)
        assert result.tenant_id == "bank_a"
        assert result.issued_at == 1_700_000_000.0
        assert result.expires_at == 1_800_000_000.0

    async def test_pinned_token_repr_redacts_value(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        vault_client.read.return_value = _good_secret(token="secret-bytes-xyz")
        result = await authz.validate_inbound_token(
            authorization_header="Bearer secret-bytes-xyz",
            tenant_id="bank_a",
            request_id="rid",
        )
        rendered = repr(result)
        assert "secret-bytes-xyz" not in rendered
        assert "<redacted>" in rendered
        assert "bank_a" in rendered  # non-secret fields still visible

    async def test_pinned_token_str_redacts_value(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """``str()`` on a frozen+slotted dataclass falls through to
        ``__repr__`` by default. Defensive sanity that the
        token-free invariant covers ``str()`` too."""
        vault_client.read.return_value = _good_secret(token="secret-bytes-xyz")
        result = await authz.validate_inbound_token(
            authorization_header="Bearer secret-bytes-xyz",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert "secret-bytes-xyz" not in str(result)


# =============================================================================
# Audit + decision-history emission
# =============================================================================


class TestAuditEmissionOnAccept:
    """Every accepted call emits ``audit.a2a_token_validated`` into
    the audit chain. Token bytes NEVER appear in the payload."""

    async def test_accept_emits_audit_event(
        self,
        authz: A2AAuthzClient,
        vault_client: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        vault_client.read.return_value = _good_secret(token="active-token")
        await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid-accept",
        )
        audit_store.append.assert_called_once()
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "audit.a2a_token_validated"
        assert event.tenant_id == "bank_a"
        assert event.request_id == "rid-accept"
        # Token bytes MUST NOT appear anywhere in the payload.
        assert "active-token" not in str(event.payload)

    async def test_accept_does_not_emit_decision_history(
        self,
        authz: A2AAuthzClient,
        vault_client: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        """Accepted calls land in audit only; decision-history is
        reserved for refusals (the policy-relevant decision)."""
        vault_client.read.return_value = _good_secret(token="active-token")
        await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
        )
        decision_history_store.append.assert_not_called()


class TestAuditEmissionOnRefusal:
    """Every refusal emits BOTH an audit event and a decision-history
    row. Operators can correlate refusals via ``request_id``."""

    async def test_anonymous_refusal_emits_audit_and_decision(
        self,
        authz: A2AAuthzClient,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
    ) -> None:
        with pytest.raises(A2AAuthzError):
            await authz.validate_inbound_token(
                authorization_header=None,
                tenant_id="bank_a",
                request_id="rid-refusal",
            )
        audit_store.append.assert_called_once()
        decision_history_store.append.assert_called_once()
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.event_type == "audit.a2a_token_rejected"
        assert event.payload["reason"] == "a2a_anonymous_refused"
        record: DecisionRecord = decision_history_store.append.call_args.args[0]
        assert record.decision_type == "a2a_token_rejected"
        assert record.payload["reason"] == "a2a_anonymous_refused"

    async def test_vault_read_failure_emits_audit_without_raw_text(
        self,
        authz: A2AAuthzClient,
        vault_client: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        vault_client.read.side_effect = RuntimeError("vault: leaky text")
        with pytest.raises(A2AAuthzError):
            await authz.validate_inbound_token(
                authorization_header="Bearer x",
                tenant_id="bank_a",
                request_id="rid",
            )
        audit_store.append.assert_called_once()
        event: AuditEvent = audit_store.append.call_args.args[0]
        # Per Sprint-5 T15 R1 P2 #3: raw exception text never reaches
        # the audit payload; only the class name does.
        assert "leaky text" not in str(event.payload)
        assert event.payload["vault_error_class"] == "RuntimeError"

    async def test_token_revoked_refusal_emits_audit_without_token(
        self,
        authz: A2AAuthzClient,
        vault_client: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        revoked = "compromised-token"
        vault_client.read.return_value = _good_secret(
            token="active-token",
            revoked_digests=[hashlib.sha256(revoked.encode()).hexdigest()],
        )
        with pytest.raises(A2AAuthzError):
            await authz.validate_inbound_token(
                authorization_header=f"Bearer {revoked}",
                tenant_id="bank_a",
                request_id="rid",
            )
        event: AuditEvent = audit_store.append.call_args.args[0]
        # Neither the active nor the revoked token bytes appear in
        # the payload — only digests / metadata.
        assert "compromised-token" not in str(event.payload)
        assert "active-token" not in str(event.payload)


# =============================================================================
# Per-tenant cache (TTL-driven)
# =============================================================================


class TestPerTenantCache:
    """The validator caches the decoded Vault secret per tenant for
    ``settings.a2a_token_cache_ttl_s`` seconds. A subsequent request
    inside the TTL reuses the cached secret; after the TTL elapses,
    the cache is dropped and Vault is re-read."""

    async def test_two_requests_inside_ttl_share_one_vault_read(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        vault_client.read.return_value = _good_secret(token="active-token")
        await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid-1",
        )
        await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid-2",
        )
        # Single Vault read shared across both requests.
        assert vault_client.read.call_count == 1

    async def test_different_tenants_do_not_share_cache(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        vault_client.read.side_effect = [
            _good_secret(token="bank-a-token", tenant_id="bank_a"),
            _good_secret(token="bank-b-token", tenant_id="bank_b"),
        ]
        await authz.validate_inbound_token(
            authorization_header="Bearer bank-a-token",
            tenant_id="bank_a",
            request_id="rid",
        )
        await authz.validate_inbound_token(
            authorization_header="Bearer bank-b-token",
            tenant_id="bank_b",
            request_id="rid",
        )
        # One read per tenant — no cache cross-pollination.
        assert vault_client.read.call_count == 2

    async def test_ttl_expiry_triggers_fresh_vault_read(
        self,
        vault_client: MagicMock,
        audit_store: MagicMock,
        decision_history_store: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """After ``a2a_token_cache_ttl_s`` elapses, the cache entry is
        dropped and a fresh Vault read happens. Patches ``time.monotonic``
        via the module-attribute path so the test doesn't sleep."""
        clock = {"now": 1000.0}

        def _monotonic() -> float:
            return clock["now"]

        # Patch the ``time`` module attribute that
        # ``cognic_agentos.protocol.a2a_authz`` imported at module
        # load. String-target form so mypy doesn't try to introspect
        # the ``time`` re-export.
        monkeypatch.setattr(
            "cognic_agentos.protocol.a2a_authz.time.monotonic",
            _monotonic,
        )

        settings = build_settings_without_env_file()
        # Default TTL is 3600s per T1.
        ttl = settings.a2a_token_cache_ttl_s
        client = A2AAuthzClient(
            settings=settings,
            vault_client=vault_client,
            audit_store=audit_store,
            decision_history_store=decision_history_store,
        )
        vault_client.read.return_value = _good_secret(token="active-token")
        await client.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid-1",
        )
        assert vault_client.read.call_count == 1
        # Advance past TTL.
        clock["now"] = 1000.0 + ttl + 1.0
        await client.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid-2",
        )
        assert vault_client.read.call_count == 2


# =============================================================================
# Drift detector — pin the 8-value reason enum so a future edit that
# adds/drops a reason must also update the test surface.
# =============================================================================


class TestConstantTimeTokenComparison:
    """**T5 R1 P2 #1 contract tests:** the active-token match MUST
    use :func:`hmac.compare_digest`, not Python's ``==`` / ``!=``,
    to avoid leaking prefix-match timing on the bearer token.

    ``str.__eq__`` short-circuits at the first differing byte —
    measurable timing differences over the network reveal how many
    leading bytes of the candidate token match the active token.
    On a critical auth boundary that's a non-trivial token-recovery
    primitive."""

    async def test_active_token_match_calls_hmac_compare_digest(
        self,
        authz: A2AAuthzClient,
        vault_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Spy on ``hmac.compare_digest`` to confirm the active-token
        check is routed through it. Without this regression a future
        edit could swap back to ``==`` / ``!=`` and the timing-leak
        would be reintroduced silently."""
        import hmac as hmac_module

        calls: list[tuple[str, str]] = []
        original = hmac_module.compare_digest

        def _spy(a: str, b: str) -> bool:
            calls.append((a, b))
            return original(a, b)

        monkeypatch.setattr("cognic_agentos.protocol.a2a_authz.hmac.compare_digest", _spy)
        vault_client.read.return_value = _good_secret(token="active-token")
        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert isinstance(result, A2APinnedToken)
        # The active-token check fired through hmac.compare_digest with
        # both sides being strings.
        assert calls, (
            "hmac.compare_digest was not called for the active-token "
            "match — timing-leak fix not in place"
        )
        active, candidate = calls[0]
        assert active == "active-token"
        assert candidate == "active-token"

    async def test_active_token_mismatch_still_routed_through_hmac(
        self,
        authz: A2AAuthzClient,
        vault_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Negative-case version: a mismatching token also flows
        through ``hmac.compare_digest`` (returning False)."""
        import hmac as hmac_module

        calls: list[tuple[str, str]] = []
        original = hmac_module.compare_digest

        def _spy(a: str, b: str) -> bool:
            calls.append((a, b))
            return original(a, b)

        monkeypatch.setattr("cognic_agentos.protocol.a2a_authz.hmac.compare_digest", _spy)
        vault_client.read.return_value = _good_secret(token="active-token")
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer different-token",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_token_malformed"
        # Even on the mismatch path, the comparison MUST flow through
        # hmac.compare_digest so the mismatch leaks no timing info.
        assert calls
        active, candidate = calls[0]
        assert active == "active-token"
        assert candidate == "different-token"


class TestSecretShapeFailClosed:
    """**T5 R1 P2 #2 + R1 P3 contract tests:** malformed Vault
    security fields fail closed via ``a2a_vault_read_failed``.

    Silently dropping a malformed ``revoked_digests`` would re-enable
    a revoked token; a malformed ``required_scopes`` would skip the
    scope gate; a malformed ``issued_at`` would raise raw
    ``ValueError`` at audit-emission time, escaping the closed-enum
    audit path. The shape-validation gate fires after the Vault read
    + before caching so malformed shapes never poison the cache."""

    @pytest.mark.parametrize(
        "malformed_value,malformed_type",
        [
            ("not-a-list", "str"),
            ({"hash": "abc"}, "dict"),
            (["valid", 42], "list"),  # list with non-str element
            (42, "int"),
            (None, "NoneType"),  # explicit null is still malformed —
            #                      use omission to disable the check
        ],
    )
    async def test_revoked_digests_non_list_str_fails_closed(
        self,
        authz: A2AAuthzClient,
        vault_client: MagicMock,
        malformed_value: Any,
        malformed_type: str,
    ) -> None:
        secret = _good_secret(token="active-token", revoked_digests=malformed_value)
        vault_client.read.return_value = secret
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer active-token",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_vault_read_failed"
        assert exc.value.payload["malformed_field"] == "revoked_digests"
        assert exc.value.payload["field_type"] == malformed_type

    @pytest.mark.parametrize(
        "malformed_value,malformed_type",
        [
            ("a2a:invoke", "str"),
            ({"scope": "a2a:invoke"}, "dict"),
            (["valid", 99], "list"),  # list with non-str element
        ],
    )
    async def test_required_scopes_non_list_str_fails_closed(
        self,
        authz: A2AAuthzClient,
        vault_client: MagicMock,
        malformed_value: Any,
        malformed_type: str,
    ) -> None:
        secret = _good_secret(token="active-token", required_scopes=malformed_value)
        vault_client.read.return_value = secret
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer active-token",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_vault_read_failed"
        assert exc.value.payload["malformed_field"] == "required_scopes"
        assert exc.value.payload["field_type"] == malformed_type

    @pytest.mark.parametrize(
        "field,malformed_value,malformed_type",
        [
            ("token", 42, "int"),
            ("token", ["bytes"], "list"),
            ("tenant_id", 42, "int"),
            ("tenant_id", ["bank_a"], "list"),
            ("audience", 42, "int"),
            ("audience", ["a"], "list"),
        ],
    )
    async def test_string_fields_non_str_fail_closed(
        self,
        authz: A2AAuthzClient,
        vault_client: MagicMock,
        field: str,
        malformed_value: Any,
        malformed_type: str,
    ) -> None:
        """``token`` / ``tenant_id`` / ``audience`` fields all require
        ``str``. A non-str value (int / list / dict) fails closed."""
        secret = _good_secret(token="active-token")
        secret[field] = malformed_value
        vault_client.read.return_value = secret
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer active-token",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_vault_read_failed"
        assert exc.value.payload["malformed_field"] == field
        assert exc.value.payload["field_type"] == malformed_type

    @pytest.mark.parametrize(
        "field,malformed_value,malformed_type",
        [
            ("issued_at", "yesterday", "str"),
            ("issued_at", True, "bool"),  # bool excluded even though int-subclass
            ("issued_at", [1700000000], "list"),
            ("expires_at", "tomorrow", "str"),
            ("expires_at", False, "bool"),
            ("expires_at", {"ts": 1700000000}, "dict"),
        ],
    )
    async def test_timestamp_fields_non_numeric_fail_closed(
        self,
        authz: A2AAuthzClient,
        vault_client: MagicMock,
        field: str,
        malformed_value: Any,
        malformed_type: str,
    ) -> None:
        """**T5 R1 P3 contract test:** ``issued_at`` / ``expires_at``
        with non-numeric value fails closed at the shape gate
        BEFORE the happy-path ``float()`` call could raise raw
        ``ValueError``."""
        secret = _good_secret(token="active-token")
        secret[field] = malformed_value
        vault_client.read.return_value = secret
        with pytest.raises(A2AAuthzError) as exc:
            await authz.validate_inbound_token(
                authorization_header="Bearer active-token",
                tenant_id="bank_a",
                request_id="rid",
            )
        assert exc.value.reason == "a2a_vault_read_failed"
        assert exc.value.payload["malformed_field"] == field
        assert exc.value.payload["field_type"] == malformed_type

    async def test_revoked_digests_omitted_disables_check(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """Negative control: omitting ``revoked_digests`` entirely is
        still valid — the check is skipped and the validator falls
        through to the active-token match."""
        secret = _good_secret(token="active-token")
        secret.pop("revoked_digests", None)
        vault_client.read.return_value = secret
        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert isinstance(result, A2APinnedToken)

    async def test_revoked_digests_empty_list_is_valid(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """Negative control: an explicit empty list is shape-valid —
        no digests are revoked and the check passes through."""
        vault_client.read.return_value = _good_secret(token="active-token", revoked_digests=[])
        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert isinstance(result, A2APinnedToken)

    async def test_required_scopes_empty_list_skips_check(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """Negative control: an explicit empty list is shape-valid —
        no scopes required → check is skipped."""
        vault_client.read.return_value = _good_secret(token="active-token", required_scopes=[])
        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
            claimed_scopes=(),
        )
        assert isinstance(result, A2APinnedToken)

    async def test_malformed_secret_does_not_poison_cache(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """**T5 R1 P2 #2 contract test:** a malformed Vault secret
        that fails the shape gate MUST NOT enter the cache. A
        subsequent request that reads (a corrected) Vault secret
        triggers a fresh read."""
        # First request: malformed secret → fail closed.
        vault_client.read.return_value = _good_secret(
            token="active-token", revoked_digests="malformed"
        )
        with pytest.raises(A2AAuthzError):
            await authz.validate_inbound_token(
                authorization_header="Bearer active-token",
                tenant_id="bank_a",
                request_id="rid-1",
            )
        # Second request: operator has corrected the Vault entry.
        vault_client.read.return_value = _good_secret(token="active-token")
        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid-2",
        )
        assert isinstance(result, A2APinnedToken)
        # Two Vault reads — the malformed first read did NOT pollute
        # the cache; the second request fetched fresh.
        assert vault_client.read.call_count == 2

    async def test_malformed_secret_emits_audit_with_field_metadata(
        self,
        authz: A2AAuthzClient,
        vault_client: MagicMock,
        audit_store: MagicMock,
    ) -> None:
        """Operators reading the audit log can identify WHICH field
        was malformed + WHAT type it had — actionable diagnostic
        without re-reading Vault."""
        vault_client.read.return_value = _good_secret(token="active-token", revoked_digests="bad")
        with pytest.raises(A2AAuthzError):
            await authz.validate_inbound_token(
                authorization_header="Bearer active-token",
                tenant_id="bank_a",
                request_id="rid",
            )
        event: AuditEvent = audit_store.append.call_args.args[0]
        assert event.payload["reason"] == "a2a_vault_read_failed"
        assert event.payload["malformed_field"] == "revoked_digests"
        assert event.payload["field_type"] == "str"

    async def test_explicit_null_issued_at_treated_as_unset(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """**T5 R2 P2 contract test:** a Vault secret with explicit
        ``"issued_at": null`` MUST be accepted (the shape gate permits
        ``None`` for ``issued_at``) AND the happy-path coercion MUST
        treat explicit-null as the unset-default (0.0), NOT raise raw
        ``TypeError`` from ``float(None)``. Without this fix the
        terminal ``float()`` call escapes the closed-enum / audit
        path post-shape-validation."""
        secret = _good_secret(token="active-token")
        secret["issued_at"] = None
        vault_client.read.return_value = secret
        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert isinstance(result, A2APinnedToken)
        # Explicit-null is normalised to 0.0 (treat-as-unset).
        assert result.issued_at == 0.0

    async def test_explicit_null_expires_at_preserved(
        self, authz: A2AAuthzClient, vault_client: MagicMock
    ) -> None:
        """Negative control: ``"expires_at": null`` IS a legitimate
        value (non-expiring tokens — Wave-1 default). The shape gate
        permits None, and the happy-path preserves None as None
        (NOT coerced to 0.0)."""
        secret = _good_secret(token="active-token")
        secret["expires_at"] = None
        vault_client.read.return_value = secret
        result = await authz.validate_inbound_token(
            authorization_header="Bearer active-token",
            tenant_id="bank_a",
            request_id="rid",
        )
        assert isinstance(result, A2APinnedToken)
        assert result.expires_at is None


class TestClosedEnumReasonsExhaustive:
    """The reason enum is a wire-protocol-public Literal in
    :mod:`cognic_agentos.protocol`. Drift detector: every reason MUST
    be reachable via an explicit fire-path in this test file. If a
    future edit adds or drops a value without updating the test set,
    this trips."""

    def test_reason_set_matches_protocol_literal(self) -> None:
        from typing import get_args

        from cognic_agentos.protocol import A2AAuthzReason

        expected = {
            "a2a_anonymous_refused",
            "a2a_token_missing",
            "a2a_token_malformed",
            "a2a_tenant_mismatch",
            "a2a_token_revoked",
            "a2a_vault_read_failed",
            "a2a_audience_mismatch",
            "a2a_scope_insufficient",
        }
        actual = set(get_args(A2AAuthzReason))
        assert actual == expected, (
            f"A2AAuthzReason literal drift: extra={actual - expected}, missing={expected - actual}"
        )
