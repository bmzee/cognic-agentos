"""Sprint 10 T4 — `core/vault.py` dynamic credential leasing.

CRITICAL CONTROL — `core/vault.py` is on the gate from day 1 by the
``core/`` stop-rule (AGENTS.md L48). Tests pin:

* The 3 new frozen dataclasses (``VaultLeaseActorRef`` /
  ``VaultLeaseRequest`` / ``CredentialLease``) — shape, frozen
  semantics, validation, architectural-arrow contract (NO
  ``portal.rbac.actor.Actor`` import in ``core/vault.py``).
* The 4-value exception taxonomy (``VaultUnavailable`` /
  ``VaultPathNotFound`` / ``VaultAuthDenied`` /
  ``VaultProtocolError``) — distinct types so callers (T6
  ``VaultCredentialAdapter`` at the sandbox boundary) can map each
  to the matching ``sandbox_credential_mint_failed_*`` closed-enum
  refusal reason per spec §7.1. ``VaultProtocolError`` is
  intentionally distinct in ``core/vault.py`` — the sandbox boundary
  at T6 collapses it to ``sandbox_credential_mint_failed_vault_unavailable``
  for closed-enum stability per spec §6.1 / §7.1 last row.
* ``lease_credential`` calls ``transport.lease(secret_path, ttl_s)``
  — the read-style dynamic-secret lease path per the Z2 Gap Q
  amendment (Sprint 10 round-9, 2026-05-24). ``ttl_s`` is informational
  at Wave 1 (Vault's role-side ``default_ttl`` / ``max_ttl`` are
  authoritative). T4 IS the consumer the T3 ``transport.lease``
  carve-out was reserved for — the Sprint-1C ``VaultAdapter.lease``
  funnels through ``transport.read`` (Sprint-1C ``SecretLease``
  consumer shape) while T4's ``lease_credential`` funnels through
  ``transport.lease`` (``CredentialLease`` consumer shape). Post-
  Gap-Q both transport methods delegate to ``client.read(path)`` at
  the hvac level; the carve-out remains load-bearing because the two
  distinct consumer-shape contracts evolve independently.
* ``revoke_credential`` calls ``transport.revoke(lease_id)``.
* Token shape stays ``dict[str, str]`` passthrough — kernel does NOT
  normalise across backends (DB vs cloud vs PKI all surface their
  raw key-set).

The matching three-dataclass landscape pin lives at
``tests/unit/sandbox/test_lease_dataclass_landscape.py`` so a future
refactor that accidentally consolidates ``SecretLease`` /
``VaultLeaseRef`` / ``CredentialLease`` is caught at import time.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import hvac
import hvac.exceptions
import pytest
import requests.exceptions  # type: ignore[import-untyped]  # transitive via hvac

import cognic_agentos
from cognic_agentos.core._vault_transport import VaultTransport
from cognic_agentos.core.config import Settings
from cognic_agentos.core.vault import (
    CredentialLease,
    VaultAuthDenied,
    VaultLeaseActorRef,
    VaultLeaseRequest,
    VaultPathNotFound,
    VaultProtocolError,
    VaultUnavailable,
    lease_credential,
    revoke_credential,
)


def _actor_ref() -> VaultLeaseActorRef:
    return VaultLeaseActorRef(actor_subject="test-user", actor_type="human")


def _request(**overrides: object) -> VaultLeaseRequest:
    """Build a VaultLeaseRequest with valid defaults; overrides win."""
    defaults: dict[str, object] = {
        "secret_path": "database/creds/payment-readonly",
        "ttl_s": 900,
        "tenant_id": "tenant-acme",
        "actor_ref": _actor_ref(),
        "scope_label": "payment-readonly-test",
    }
    defaults.update(overrides)
    return VaultLeaseRequest(**defaults)  # type: ignore[arg-type]


def _settings() -> Settings:
    return Settings(_env_file=None)  # type: ignore[call-arg]


def _mock_transport(
    *,
    lease_return: object = None,
    lease_side_effect: object = None,
    revoke_side_effect: object = None,
) -> MagicMock:
    """Build a VaultTransport mock with configurable lease/revoke responses."""
    transport = MagicMock(spec=VaultTransport)
    if lease_side_effect is not None:
        transport.lease = AsyncMock(side_effect=lease_side_effect)
    else:
        transport.lease = AsyncMock(return_value=lease_return)
    if revoke_side_effect is not None:
        transport.revoke = AsyncMock(side_effect=revoke_side_effect)
    else:
        transport.revoke = AsyncMock(return_value=None)
    return transport


def _happy_lease_payload() -> dict[str, object]:
    """Canonical hvac.write response shape for a dynamic-secret lease."""
    return {
        "lease_id": "database/creds/payment-readonly/lease-abc-123",
        "lease_duration": 900,
        "data": {"username": "u-001", "password": "p-001"},
    }


# ──────────────────────────────────────────────────────────────────────
# 1. VaultLeaseActorRef — core-owned Actor projection.
# ──────────────────────────────────────────────────────────────────────


class TestVaultLeaseActorRef:
    def test_constructs_with_valid_fields(self) -> None:
        """T4 #1 — VaultLeaseActorRef carries actor_subject (str) +
        actor_type (Literal["human", "service"])."""
        ref = VaultLeaseActorRef(actor_subject="u-001", actor_type="human")
        assert ref.actor_subject == "u-001"
        assert ref.actor_type == "human"

    def test_frozen(self) -> None:
        """T4 #2 — VaultLeaseActorRef is frozen — instance attrs cannot
        be reassigned. dataclass(frozen=True) raises FrozenInstanceError."""
        import dataclasses

        ref = _actor_ref()
        with pytest.raises(dataclasses.FrozenInstanceError):
            ref.actor_subject = "other"  # type: ignore[misc]

    def test_accepts_service_actor_type(self) -> None:
        """T4 #3 — both Literal values ('human' + 'service') accepted.
        The Literal is a runtime hint, not enforced; we pin both values
        construct cleanly so consumers can rely on the documented
        2-value set."""
        ref = VaultLeaseActorRef(actor_subject="service-001", actor_type="service")
        assert ref.actor_type == "service"


# ──────────────────────────────────────────────────────────────────────
# 2. VaultLeaseRequest — wire-public; 5 fields; construction-time
#    validation; architectural-arrow contract (actor_ref NOT actor).
# ──────────────────────────────────────────────────────────────────────


class TestVaultLeaseRequest:
    def test_constructs_with_valid_fields(self) -> None:
        """T4 #4 — VaultLeaseRequest carries the 5-field shape per
        spec §3.1."""
        req = _request()
        assert req.secret_path == "database/creds/payment-readonly"
        assert req.ttl_s == 900
        assert req.tenant_id == "tenant-acme"
        assert req.actor_ref.actor_subject == "test-user"
        assert req.scope_label == "payment-readonly-test"

    def test_frozen(self) -> None:
        """T4 #5 — VaultLeaseRequest is frozen."""
        import dataclasses

        req = _request()
        with pytest.raises(dataclasses.FrozenInstanceError):
            req.secret_path = "other"  # type: ignore[misc]

    def test_has_actor_ref_field_not_actor_field(self) -> None:
        """T4 #6 — ARCHITECTURAL-ARROW PIN. The request MUST carry
        ``actor_ref: VaultLeaseActorRef`` (core-owned projection),
        NOT ``actor: Actor`` (portal type). Pins the spec §3.1 +
        R1 P2 patch contract that ``core/vault.py`` does NOT
        depend on ``portal/rbac/``."""
        import dataclasses

        fields = {f.name: f.type for f in dataclasses.fields(VaultLeaseRequest)}
        assert "actor_ref" in fields, (
            "VaultLeaseRequest MUST have actor_ref field (core-owned projection)"
        )
        assert "actor" not in fields, (
            "VaultLeaseRequest MUST NOT carry actor (full portal.rbac.Actor) — "
            "that would re-introduce the architectural-arrow violation patched at R1 P2"
        )

    def test_rejects_empty_secret_path(self) -> None:
        """T4 #7 — secret_path validation: non-empty per spec §3.1."""
        with pytest.raises(ValueError, match="secret_path"):
            _request(secret_path="")

    def test_rejects_traversal_in_secret_path(self) -> None:
        """T4 #8 — secret_path validation: no ``..`` traversal segments."""
        with pytest.raises(ValueError, match="secret_path"):
            _request(secret_path="database/creds/../etc/passwd")

    def test_rejects_uri_scheme_secret_path(self) -> None:
        """T4 #9 — secret_path validation: no URI scheme (no ``://``).
        Vault paths are path-only; scheme-bearing input is misconfig."""
        with pytest.raises(ValueError, match="secret_path"):
            _request(secret_path="http://evil/leak")

    def test_rejects_invalid_secret_path_chars(self) -> None:
        """T4 #10 — secret_path validation: matches
        ``^[a-z0-9_/\\-]+$`` per spec §3.1 — lowercase + digits +
        underscore + forward-slash + hyphen only. Uppercase or
        whitespace is misconfig."""
        with pytest.raises(ValueError, match="secret_path"):
            _request(secret_path="Database/Creds/X")
        with pytest.raises(ValueError, match="secret_path"):
            _request(secret_path="database/creds/with space")

    def test_rejects_zero_or_negative_ttl_s(self) -> None:
        """T4 #11 — ttl_s validation: must be > 0 (a 0-or-negative TTL
        is meaningless; misconfigured at the call site)."""
        with pytest.raises(ValueError, match="ttl_s"):
            _request(ttl_s=0)
        with pytest.raises(ValueError, match="ttl_s"):
            _request(ttl_s=-1)

    def test_rejects_overlong_scope_label(self) -> None:
        """T4 #12 — scope_label validation: bounded to 64 chars per
        spec §3.1 (operator-facing audit label; not a Vault role)."""
        with pytest.raises(ValueError, match="scope_label"):
            _request(scope_label="x" * 65)


# ──────────────────────────────────────────────────────────────────────
# 3. CredentialLease — wire-public; 6 fields; token passthrough.
# ──────────────────────────────────────────────────────────────────────


class TestCredentialLease:
    def test_constructs_with_all_six_fields(self) -> None:
        """T4 #13 — CredentialLease carries the 6-field shape per
        spec §3.2."""
        now = _dt.datetime.now(_dt.UTC)
        lease = CredentialLease(
            lease_id="L-001",
            request=_request(),
            token={"username": "u", "password": "p"},
            minted_at=now,
            ttl_s_granted=900,
            expires_at=now + _dt.timedelta(seconds=900),
        )
        assert lease.lease_id == "L-001"
        assert lease.request.secret_path == "database/creds/payment-readonly"
        assert lease.token == {"username": "u", "password": "p"}
        assert lease.ttl_s_granted == 900
        assert lease.minted_at == now

    def test_frozen(self) -> None:
        """T4 #14 — CredentialLease is frozen."""
        import dataclasses

        now = _dt.datetime.now(_dt.UTC)
        lease = CredentialLease(
            lease_id="L-001",
            request=_request(),
            token={"k": "v"},
            minted_at=now,
            ttl_s_granted=60,
            expires_at=now + _dt.timedelta(seconds=60),
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            lease.lease_id = "other"  # type: ignore[misc]

    def test_token_is_dict_str_str_passthrough(self) -> None:
        """T4 #15 — TOKEN PASSTHROUGH PIN. token field is the raw
        ``dict[str, str]`` hvac response data — NOT normalised across
        backends. DB creds expose ``{username, password}``; cloud
        creds expose ``{access_key, secret_key, session_token}``; etc.
        The kernel does NOT enforce a schema (per spec §3.4)."""
        now = _dt.datetime.now(_dt.UTC)
        # DB-shape token
        db_lease = CredentialLease(
            lease_id="L-db",
            request=_request(),
            token={"username": "u", "password": "p"},
            minted_at=now,
            ttl_s_granted=60,
            expires_at=now,
        )
        assert isinstance(db_lease.token, dict)
        # Cloud-shape token (different keys; same passthrough type)
        cloud_lease = CredentialLease(
            lease_id="L-cloud",
            request=_request(),
            token={
                "access_key": "AKIA...",
                "secret_key": "wJal...",
                "session_token": "FQoG...",
            },
            minted_at=now,
            ttl_s_granted=60,
            expires_at=now,
        )
        assert set(cloud_lease.token) == {
            "access_key",
            "secret_key",
            "session_token",
        }


# ──────────────────────────────────────────────────────────────────────
# 4. lease_credential — happy path + transport.lease() routing.
# ──────────────────────────────────────────────────────────────────────


class TestLeaseCredentialHappyPath:
    async def test_lease_credential_returns_credential_lease(self) -> None:
        """T4 #16 — happy path: transport.lease returns a valid hvac
        response → ``lease_credential`` composes ``CredentialLease``
        with the response data."""
        transport = _mock_transport(lease_return=_happy_lease_payload())
        lease = await lease_credential(_request(), transport=transport, settings=_settings())
        assert isinstance(lease, CredentialLease)
        assert lease.lease_id == "database/creds/payment-readonly/lease-abc-123"
        assert lease.token == {"username": "u-001", "password": "p-001"}
        assert lease.ttl_s_granted == 900
        assert lease.request.secret_path == "database/creds/payment-readonly"

    async def test_calls_transport_lease_with_secret_path_and_ttl_s(self) -> None:
        """T4 #17 — ``lease_credential`` calls
        ``transport.lease(secret_path, ttl_s)`` — the read-style
        dynamic-secret lease path per Z2 Gap Q (Sprint 10 round-9,
        2026-05-24). T4 IS the consumer the T3 ``transport.lease``
        carve-out was reserved for: Sprint-1C ``VaultAdapter.lease``
        funnels through ``transport.read`` (Sprint-1C ``SecretLease``
        consumer shape); ``lease_credential`` funnels through
        ``transport.lease`` (``CredentialLease`` consumer shape).
        Post-Gap-Q both transport methods delegate to
        ``client.read(path)`` at the hvac level; the distinct
        method names persist so the two consumer-shape contracts can
        evolve independently."""
        transport = _mock_transport(lease_return=_happy_lease_payload())
        await lease_credential(_request(ttl_s=1800), transport=transport, settings=_settings())
        transport.lease.assert_awaited_once_with("database/creds/payment-readonly", 1800)

    async def test_minted_at_is_utc_aware(self) -> None:
        """T4 #18 — minted_at is a tz-aware UTC datetime (Sprint-2 R3
        canonical-form contract — naive datetimes never enter the
        chain)."""
        transport = _mock_transport(lease_return=_happy_lease_payload())
        lease = await lease_credential(_request(), transport=transport, settings=_settings())
        assert lease.minted_at.tzinfo is not None
        assert lease.minted_at.utcoffset() == _dt.timedelta(0)

    async def test_expires_at_equals_minted_at_plus_ttl_s_granted(self) -> None:
        """T4 #19 — expires_at = minted_at + ttl_s_granted (Vault is
        authoritative for the actual TTL; expires_at is a derived
        convenience for sandbox-side timer logic)."""
        transport = _mock_transport(lease_return=_happy_lease_payload())
        lease = await lease_credential(_request(), transport=transport, settings=_settings())
        assert lease.expires_at - lease.minted_at == _dt.timedelta(seconds=lease.ttl_s_granted)

    async def test_uses_vault_granted_ttl_not_requested_ttl(self) -> None:
        """T4 #20 — ``ttl_s_granted`` is the value Vault actually
        returned (which may be less than the requested ``ttl_s`` if
        the backend caps at e.g. 1 hour). Examiners audit the
        granted TTL, not the requested."""
        # Request 3600s but Vault grants only 600s
        capped_payload = dict(_happy_lease_payload())
        capped_payload["lease_duration"] = 600
        transport = _mock_transport(lease_return=capped_payload)
        lease = await lease_credential(
            _request(ttl_s=3600), transport=transport, settings=_settings()
        )
        assert lease.ttl_s_granted == 600
        assert lease.request.ttl_s == 3600


# ──────────────────────────────────────────────────────────────────────
# 5. lease_credential — exception mapping (hvac → core/vault.py taxonomy).
# ──────────────────────────────────────────────────────────────────────


class TestLeaseCredentialExceptionMapping:
    """Sprint 10 T4 — maps hvac exceptions to the 4-value
    ``core/vault.py`` exception taxonomy per spec §7.1. T6's
    ``VaultCredentialAdapter`` then collapses these to the
    matching ``sandbox_credential_mint_failed_*`` closed-enum
    refusal reasons at the sandbox boundary."""

    async def test_vault_down_maps_to_vault_unavailable(self) -> None:
        """T4 #21 — hvac.exceptions.VaultDown (503) → VaultUnavailable."""
        transport = _mock_transport(lease_side_effect=hvac.exceptions.VaultDown("503"))
        with pytest.raises(VaultUnavailable):
            await lease_credential(_request(), transport=transport, settings=_settings())

    async def test_internal_server_error_maps_to_vault_unavailable(self) -> None:
        """T4 #22 — hvac.exceptions.InternalServerError (500) →
        VaultUnavailable."""
        transport = _mock_transport(lease_side_effect=hvac.exceptions.InternalServerError("500"))
        with pytest.raises(VaultUnavailable):
            await lease_credential(_request(), transport=transport, settings=_settings())

    async def test_connection_error_maps_to_vault_unavailable(self) -> None:
        """T4 #23 — network-level ConnectionError → VaultUnavailable.
        hvac surfaces underlying transport errors uncaught when they
        bypass hvac's own exception wrapping. The builtin
        ``ConnectionError`` inherits ``OSError`` so the ``OSError``
        catch in the production code matches it."""
        transport = _mock_transport(lease_side_effect=ConnectionError("nope"))
        with pytest.raises(VaultUnavailable):
            await lease_credential(_request(), transport=transport, settings=_settings())

    async def test_requests_timeout_maps_to_vault_unavailable(self) -> None:
        """T4 #23a — ``requests.exceptions.Timeout`` (the canonical
        Vault HTTP-timeout exception via hvac's underlying ``requests``
        client) → ``VaultUnavailable``. Spec §7.1 puts timeouts in
        the unavailable bucket, NOT protocol-error. The fix relies on
        the fact that ``requests.exceptions.Timeout`` inherits
        ``OSError`` via ``IOError``; a plain builtin ``ConnectionError``
        catch would MISS it and route to the catch-all VaultProtocolError
        — exact bug-class the second-round review caught."""
        transport = _mock_transport(lease_side_effect=requests.exceptions.Timeout("read timed out"))
        with pytest.raises(VaultUnavailable):
            await lease_credential(_request(), transport=transport, settings=_settings())

    async def test_requests_connection_error_maps_to_vault_unavailable(self) -> None:
        """T4 #23b — ``requests.exceptions.ConnectionError`` (DNS
        failure / connection refused at the requests layer) →
        ``VaultUnavailable``. Companion to the timeout pin —
        ``requests.exceptions.ConnectionError`` also inherits
        ``OSError`` via ``IOError`` and is what hvac surfaces for
        DNS / TCP-level failures."""
        transport = _mock_transport(
            lease_side_effect=requests.exceptions.ConnectionError("DNS lookup failed")
        )
        with pytest.raises(VaultUnavailable):
            await lease_credential(_request(), transport=transport, settings=_settings())

    async def test_invalid_path_maps_to_vault_path_not_found(self) -> None:
        """T4 #24 — hvac.exceptions.InvalidPath (404) →
        VaultPathNotFound. Distinct from VaultUnavailable so T6 can
        map to ``sandbox_credential_mint_failed_secret_path_unknown``."""
        transport = _mock_transport(lease_side_effect=hvac.exceptions.InvalidPath("404"))
        with pytest.raises(VaultPathNotFound):
            await lease_credential(_request(), transport=transport, settings=_settings())

    async def test_forbidden_maps_to_vault_auth_denied(self) -> None:
        """T4 #25 — hvac.exceptions.Forbidden (403) → VaultAuthDenied.
        Distinct from VaultUnavailable so T6 can map to
        ``sandbox_credential_mint_failed_auth_denied``."""
        transport = _mock_transport(lease_side_effect=hvac.exceptions.Forbidden("403"))
        with pytest.raises(VaultAuthDenied):
            await lease_credential(_request(), transport=transport, settings=_settings())

    async def test_unauthorized_maps_to_vault_auth_denied(self) -> None:
        """T4 #26 — hvac.exceptions.Unauthorized (401) →
        VaultAuthDenied (same closed-enum bucket as Forbidden —
        both are auth failures; 401 = missing creds, 403 = creds
        rejected; either way the sandbox refusal is the same)."""
        transport = _mock_transport(lease_side_effect=hvac.exceptions.Unauthorized("401"))
        with pytest.raises(VaultAuthDenied):
            await lease_credential(_request(), transport=transport, settings=_settings())

    async def test_none_response_maps_to_vault_protocol_error(self) -> None:
        """T4 #27 — transport.lease returns None (Vault 2xx with no
        body) → VaultProtocolError. Distinct exception in the core
        taxonomy; T6 collapses to
        ``sandbox_credential_mint_failed_vault_unavailable`` for
        closed-enum stability per spec §6.1 / §7.1 last row."""
        transport = _mock_transport(lease_return=None)
        with pytest.raises(VaultProtocolError):
            await lease_credential(_request(), transport=transport, settings=_settings())

    async def test_missing_lease_id_maps_to_vault_protocol_error(self) -> None:
        """T4 #28 — transport.lease returns a dict without ``lease_id``
        key → VaultProtocolError. Vault accepted the request but
        minted no lease (malformed response shape; rare but possible
        with future Vault API changes)."""
        # Drop lease_id from the happy payload
        bad_payload = dict(_happy_lease_payload())
        del bad_payload["lease_id"]
        transport = _mock_transport(lease_return=bad_payload)
        with pytest.raises(VaultProtocolError):
            await lease_credential(_request(), transport=transport, settings=_settings())

    async def test_non_integer_lease_duration_maps_to_vault_protocol_error(
        self,
    ) -> None:
        """T4 #28a — Vault returned a non-integer ``lease_duration``
        (e.g., string or None) → VaultProtocolError. Defensive against
        a future Vault API shape drift; pinned per
        ``[[feedback_evidence_boundary_runtime_validation]]`` (chain-row
        materialisers cannot trust input types)."""
        bad_payload = dict(_happy_lease_payload())
        bad_payload["lease_duration"] = "not-an-int"
        transport = _mock_transport(lease_return=bad_payload)
        with pytest.raises(VaultProtocolError, match="lease_duration"):
            await lease_credential(_request(), transport=transport, settings=_settings())

    async def test_non_dict_data_maps_to_vault_protocol_error(self) -> None:
        """T4 #28b — Vault returned non-dict ``data`` field (e.g., a
        non-empty list) → VaultProtocolError. Defensive against
        future shape drift; pinned per
        ``[[feedback_evidence_boundary_runtime_validation]]``. Without
        this guard the ``dict(raw_data)`` coercion below would raise
        a bare TypeError that escapes the closed-enum taxonomy."""
        bad_payload = dict(_happy_lease_payload())
        bad_payload["data"] = ["wrong", "shape"]
        transport = _mock_transport(lease_return=bad_payload)
        with pytest.raises(VaultProtocolError, match="not a dict"):
            await lease_credential(_request(), transport=transport, settings=_settings())

    @pytest.mark.parametrize(
        "falsy_data",
        [
            pytest.param([], id="empty_list"),
            pytest.param("", id="empty_string"),
            pytest.param(None, id="explicit_None"),
            pytest.param(0, id="zero_int"),
        ],
    )
    async def test_falsy_non_dict_data_maps_to_vault_protocol_error(
        self, falsy_data: object
    ) -> None:
        """T4 #28b2 — FALSY-NON-DICT GUARD. ``data=[]`` / ``data=""``
        / ``data=None`` / ``data=0`` are all distinct malformed
        responses that must surface as VaultProtocolError, NOT
        silently collapse to an empty token.

        The production code reads ``response.get("data", {})``
        (default-on-MISSING) — NOT the bug-pattern
        ``response.get("data") or {}`` (default-on-FALSY) which would
        coerce every falsy non-dict to ``{}`` BEFORE the isinstance
        guard fires, vacuously passing the check and returning a
        synthetic empty-token CredentialLease. With the correct
        ``get("data", {})`` form, the default fires ONLY when the
        key is absent entirely — an explicit ``data: None`` (key
        present, value None) returns ``None`` and trips the
        ``isinstance(dict)`` guard. Pinned per
        ``[[feedback_evidence_boundary_runtime_validation]]`` —
        chain-row materialisers cannot trust input types AND must
        distinguish missing-from-falsy. The genuine missing-key
        case (Vault returns no ``data`` field at all) is the
        legitimate empty-token path; that's pinned by the separate
        ``test_missing_data_key_returns_empty_token`` test."""
        bad_payload = dict(_happy_lease_payload())
        bad_payload["data"] = falsy_data
        transport = _mock_transport(lease_return=bad_payload)
        with pytest.raises(VaultProtocolError, match="not a dict"):
            await lease_credential(_request(), transport=transport, settings=_settings())

    async def test_missing_data_key_returns_empty_token(self) -> None:
        """T4 #28b3 — MISSING-KEY LEGITIMATE PATH. If Vault returns a
        2xx response with ``lease_id`` + ``lease_duration`` but NO
        ``data`` key at all, the ``get("data", {})`` default fires
        and ``token`` is an empty dict — a valid happy-path
        response, NOT a protocol error. Distinct from the
        ``data=None`` case in the falsy-data test above (key
        present + value None → protocol error). Pin this distinction
        explicitly per
        ``[[feedback_evidence_boundary_runtime_validation]]``'s
        missing-vs-falsy doctrine."""
        no_data_payload = dict(_happy_lease_payload())
        del no_data_payload["data"]
        transport = _mock_transport(lease_return=no_data_payload)
        lease = await lease_credential(_request(), transport=transport, settings=_settings())
        assert lease.token == {}
        assert lease.lease_id == "database/creds/payment-readonly/lease-abc-123"

    async def test_unexpected_exception_maps_to_vault_protocol_error(self) -> None:
        """T4 #28c — CLOSED-TAXONOMY GUARANTEE per spec §7.1 "anything
        else" row. An unforeseen exception class from the transport
        (e.g., a future hvac subclass not in the 4-class specific
        catch, a bare ``RuntimeError`` from a transport-layer fault)
        MUST map to ``VaultProtocolError`` — never escape the 4-value
        taxonomy. Without the ``except Exception`` catch-all at the
        function foot, an unknown exception would propagate raw and
        the T6 sandbox boundary would have no closed-enum to surface."""
        transport = _mock_transport(lease_side_effect=RuntimeError("boom"))
        with pytest.raises(VaultProtocolError, match="unexpected error"):
            await lease_credential(_request(), transport=transport, settings=_settings())


# ──────────────────────────────────────────────────────────────────────
# 6. revoke_credential — happy path + exception mapping.
# ──────────────────────────────────────────────────────────────────────


class TestRevokeCredential:
    async def test_revoke_credential_happy_path(self) -> None:
        """T4 #29 — revoke_credential calls transport.revoke(lease_id);
        returns None on success. The signature is declared ``-> None``;
        mypy's ``func-returns-value`` rule would refuse a captured
        ``result = await revoke_credential(...)`` assignment, so we
        only assert the side-effect (the transport call)."""
        transport = _mock_transport()
        await revoke_credential("L-001", transport=transport)
        transport.revoke.assert_awaited_once_with("L-001")

    async def test_revoke_maps_vault_down_to_vault_unavailable(self) -> None:
        """T4 #30 — revoke exception mapping mirrors lease's
        exception mapping. Caller (T10 sandbox destroy()) wraps
        revoke_credential in fail-soft try/except per spec §7.2 —
        but the underlying exception class still needs to be the
        taxonomy type for diagnostic surface."""
        transport = _mock_transport(revoke_side_effect=hvac.exceptions.VaultDown("503"))
        with pytest.raises(VaultUnavailable):
            await revoke_credential("L-001", transport=transport)

    async def test_revoke_maps_invalid_path_to_vault_path_not_found(self) -> None:
        """T4 #31 — hvac.exceptions.InvalidPath on revoke (e.g.,
        lease_id no longer valid) → VaultPathNotFound."""
        transport = _mock_transport(
            revoke_side_effect=hvac.exceptions.InvalidPath("lease not found")
        )
        with pytest.raises(VaultPathNotFound):
            await revoke_credential("L-001", transport=transport)

    async def test_revoke_maps_forbidden_to_vault_auth_denied(self) -> None:
        """T4 #32 — hvac.exceptions.Forbidden on revoke → VaultAuthDenied.
        Mirrors lease_credential's 401/403 mapping so the closed-enum
        taxonomy stays symmetric across both API surfaces."""
        transport = _mock_transport(revoke_side_effect=hvac.exceptions.Forbidden("403"))
        with pytest.raises(VaultAuthDenied):
            await revoke_credential("L-001", transport=transport)

    async def test_revoke_unexpected_exception_maps_to_vault_protocol_error(self) -> None:
        """T4 #33 — CLOSED-TAXONOMY GUARANTEE on revoke per spec §7.1
        "anything else" row. Mirrors
        ``test_unexpected_exception_maps_to_vault_protocol_error`` on
        the lease path — an unforeseen transport-layer exception MUST
        map to ``VaultProtocolError`` rather than escape the 4-value
        taxonomy. Symmetric to the lease catch-all so the closed
        contract holds for both API surfaces."""
        transport = _mock_transport(revoke_side_effect=RuntimeError("boom"))
        with pytest.raises(VaultProtocolError, match="unexpected error"):
            await revoke_credential("L-001", transport=transport)


# ──────────────────────────────────────────────────────────────────────
# 7. Architectural arrow — core/vault.py does NOT import portal/rbac/.
# ──────────────────────────────────────────────────────────────────────


class TestArchitecturalArrow:
    def test_core_vault_does_not_import_portal_rbac_actor(self) -> None:
        """T4 #32 — ARCHITECTURAL-ARROW PIN. ``core/vault.py`` MUST
        NOT import from ``portal/rbac/`` (per the spec §3.1 R1 P2
        patch contract). The ``VaultLeaseActorRef`` projection lives
        in ``core/vault.py`` precisely to keep ``core/`` independent
        of ``portal/``. AST-style source-grep — drift detector is
        test-only per ``[[feedback_drift_detector_test_only_no_runtime_import]]``."""
        root = Path(cognic_agentos.__file__).resolve().parent
        src = (root / "core" / "vault.py").read_text(encoding="utf-8")
        # Catch direct imports of portal.rbac.actor.Actor or any portal.rbac.*
        # symbol. Both forbidden — core/ MUST stay portal-independent.
        assert "from cognic_agentos.portal" not in src, (
            "core/vault.py MUST NOT import from cognic_agentos.portal/* — "
            "architectural-arrow violation per spec §3.1 R1 P2"
        )
        assert "import cognic_agentos.portal" not in src, (
            "core/vault.py MUST NOT import cognic_agentos.portal/* — "
            "architectural-arrow violation per spec §3.1 R1 P2"
        )
