"""Sprint 10 T4 — `core/vault.py` dynamic credential leasing.

CRITICAL CONTROL — `core/vault.py` is on the gate from day 1 by the
``core/`` stop-rule (AGENTS.md L48). Tests pin:

* The 3 new frozen dataclasses (``VaultLeaseActorRef`` /
  ``VaultLeaseRequest`` / ``CredentialLease``) — shape, frozen
  semantics, validation, architectural-arrow contract (NO
  ``portal.rbac.actor.Actor`` import in ``core/vault.py``).
* The 5-value exception taxonomy (``VaultUnavailable`` /
  ``VaultPathNotFound`` / ``VaultAuthDenied`` /
  ``VaultProtocolError`` / ``VaultLeaseGrantExceedsRequest``,
  Sprint 10.1 amendment per ADR-004 §25 — post-mint
  granted-vs-requested TTL enforcement with best-effort
  ``transport.revoke`` before raise) — distinct types so callers
  (T6 ``VaultCredentialAdapter`` at the sandbox boundary) can map
  each to the matching ``sandbox_credential_*`` closed-enum refusal
  reason per spec §7.1 — the hvac-mapping subset goes to
  ``sandbox_credential_mint_failed_*`` and the post-mint TTL refusal
  goes to ``sandbox_credential_lease_ttl_grant_exceeds_request``.
  ``VaultProtocolError`` is intentionally distinct in ``core/vault.py``
  — the sandbox boundary at T6 collapses it to
  ``sandbox_credential_mint_failed_vault_unavailable`` for closed-enum
  stability per spec §6.1 / §7.1 last row.
* ``lease_credential`` calls ``transport.lease(secret_path, ttl_s)``
  — the read-style dynamic-secret lease path per the Z2 Gap Q
  amendment (Sprint 10 round-9, 2026-05-24). ``ttl_s`` is NOT passed
  to Vault on the wire (Vault's role-side ``default_ttl`` /
  ``max_ttl`` are authoritative for what the wire returns); Sprint
  10.1 amendment to ADR-004 §25 makes ``ttl_s`` load-bearing as
  the kernel-side cap that ``lease_credential`` enforces post-mint
  via the new :class:`VaultLeaseGrantExceedsRequest` exception
  (with best-effort revoke before raise) when
  ``ttl_s_granted > request.ttl_s``. T4 IS the consumer the T3
  ``transport.lease`` carve-out was reserved for — the Sprint-1C
  ``VaultAdapter.lease`` funnels through ``transport.read``
  (Sprint-1C ``SecretLease`` consumer shape) while T4's
  ``lease_credential`` funnels through ``transport.lease``
  (``CredentialLease`` consumer shape). Post-Gap-Q both transport
  methods delegate to ``client.read(path)`` at the hvac level; the
  carve-out remains load-bearing because the two distinct
  consumer-shape contracts evolve independently.
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
    VaultLeaseGrantExceedsRequest,
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
    """Sprint 10 T4 — maps hvac exceptions to the hvac-derived subset
    of the 5-value ``core/vault.py`` exception taxonomy per spec §7.1
    (the 4 hvac-mapped values ``VaultUnavailable`` /
    ``VaultPathNotFound`` / ``VaultAuthDenied`` / ``VaultProtocolError``;
    the 5th value ``VaultLeaseGrantExceedsRequest`` is added by
    Sprint 10.1 amendment per ADR-004 §25 and is exercised in the
    dedicated ``TestLeaseCredentialTTLGrantEnforcement`` class below
    because it is raised by the post-mint enforcement check, not by
    hvac mapping). T6's ``VaultCredentialAdapter`` then collapses
    these to the matching ``sandbox_credential_*`` closed-enum refusal
    reasons at the sandbox boundary —
    ``sandbox_credential_mint_failed_*`` for the hvac-mapped set,
    ``sandbox_credential_lease_ttl_grant_exceeds_request`` for the
    post-mint TTL refusal."""

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
        MUST map to ``VaultProtocolError`` — never escape the closed
        ``core/vault`` taxonomy. Unexpected errors still map to
        ``VaultProtocolError``, while over-grant uses
        ``VaultLeaseGrantExceedsRequest`` (Sprint 10.1 amendment per
        ADR-004 §25). Without the ``except Exception`` catch-all at
        the function foot, an unknown exception would propagate raw
        and the T6 sandbox boundary would have no closed-enum to
        surface."""
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
        map to ``VaultProtocolError`` rather than escape the closed
        ``core/vault`` taxonomy. Unexpected errors still map to
        ``VaultProtocolError``, while over-grant on the lease path
        uses ``VaultLeaseGrantExceedsRequest`` (Sprint 10.1 amendment
        per ADR-004 §25); ``revoke_credential`` itself has no
        granted-vs-requested concept so the over-grant arm does not
        apply on this API surface. Symmetric to the lease catch-all
        so the closed contract holds for both API surfaces."""
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


# ──────────────────────────────────────────────────────────────────────
# 6. lease_credential — granted-vs-requested TTL enforcement (Sprint 10.1).
# ──────────────────────────────────────────────────────────────────────
#
# Reuses the existing module-level ``_happy_lease_payload`` helper at the
# top of the file (canonical hvac response shape for a dynamic-secret
# lease); the lease_id from that helper is the same one the new tests
# assert against in the formatted message string + revoke argument.


class TestLeaseCredentialTTLGrantEnforcement:
    """Sprint 10.1 — finding #2 from post-merge review of PR #38.

    Vault MAY return ``lease_duration`` greater than the requested
    ``ttl_s`` when the role's ``default_ttl`` / ``max_ttl`` exceed
    AgentOS' cap. Pre-Sprint-10.1, ``lease_credential`` accepted the
    grant unchanged, allowing over-cap leases to silently pass while
    the Rego rule-6 cap (which only gates the REQUESTED ttl) appears
    to be enforcement.

    Sprint 10.1 fix: ``lease_credential`` raises
    :class:`VaultLeaseGrantExceedsRequest` when
    ``ttl_s_granted > request.ttl_s``, AND performs a best-effort
    ``transport.revoke(lease_id)`` before raising so Vault does not
    keep an over-cap dynamic credential active (closes Finding A of
    the 2026-05-24 plan-review round 1). Revoke failure does NOT mask
    the TTL refusal — the exception still raises, carrying
    ``lease_id`` + ``revoke_outcome`` attributes for audit traceability
    and chaining the revoke exception via ``__cause__``.

    The sandbox boundary maps the exception to the new
    ``SandboxRefusalReason("sandbox_credential_lease_ttl_grant_exceeds_request")``
    closed-enum value via
    ``_shared_credentials._mint_exception_to_refusal_reason`` (Sprint
    10.1 Task 2 — landing in the next commit on this branch).
    """

    async def test_grant_exceeding_request_raises_grant_exceeds_request(
        self,
    ) -> None:
        """Sprint 10.1 #1 — grant > request → VaultLeaseGrantExceedsRequest."""
        over_cap_payload = dict(_happy_lease_payload())
        over_cap_payload["lease_duration"] = 3600  # Vault role default_ttl=1h
        transport = _mock_transport(lease_return=over_cap_payload)
        with pytest.raises(VaultLeaseGrantExceedsRequest) as exc_info:
            await lease_credential(
                _request(ttl_s=900),  # requested 15 minutes
                transport=transport,
                settings=_settings(),
            )
        # Message names both numbers + the secret_path + the lease_id
        # for examiner traceability. Per Finding 3 of the 2026-05-24
        # plan-review round 2 — backends raise
        # ``SandboxLifecycleRefused(detail=str(exc))`` which only carries
        # exception ATTRIBUTES if they appear in the message string. The
        # lease_id must therefore live in the formatted message so the
        # chain row's payload preserves the dangling-lease correlator
        # when ``revoke_outcome="revoke_failed"``.
        msg = str(exc_info.value)
        assert "3600" in msg
        assert "900" in msg
        assert _request().secret_path in msg
        # _happy_lease_payload() declares dict[str, object]; cast to str
        # so mypy is happy on the ``in str`` check.
        assert str(_happy_lease_payload()["lease_id"]) in msg

    async def test_grant_equal_to_request_allows(self) -> None:
        """Sprint 10.1 #2 — grant == request → success (<= boundary)."""
        boundary_payload = dict(_happy_lease_payload())
        boundary_payload["lease_duration"] = 900
        transport = _mock_transport(lease_return=boundary_payload)
        lease = await lease_credential(
            _request(ttl_s=900),
            transport=transport,
            settings=_settings(),
        )
        assert lease.ttl_s_granted == 900

    async def test_grant_less_than_request_allows(self) -> None:
        """Sprint 10.1 #3 — grant < request → success (Vault tightening)."""
        tighter_payload = dict(_happy_lease_payload())
        tighter_payload["lease_duration"] = 300
        transport = _mock_transport(lease_return=tighter_payload)
        lease = await lease_credential(
            _request(ttl_s=900),
            transport=transport,
            settings=_settings(),
        )
        assert lease.ttl_s_granted == 300

    async def test_grant_exceeds_request_exception_inherits_exception(
        self,
    ) -> None:
        """Sprint 10.1 #4 — VaultLeaseGrantExceedsRequest inherits Exception,
        NOT BaseException. Catchable by generic ``except Exception`` arms;
        asyncio.CancelledError still passes through (modern Python MRO)."""
        assert issubclass(VaultLeaseGrantExceedsRequest, Exception)
        # Defensive — not a BaseException-only class (would skip generic Exception arms).
        assert VaultLeaseGrantExceedsRequest.__mro__[1] is Exception

    async def test_grant_exceeding_request_revokes_lease_before_raising(
        self,
    ) -> None:
        """Sprint 10.1 #5 — best-effort revoke fires BEFORE raise so Vault
        does not keep the over-cap dynamic credential active. Closes
        Finding A of the 2026-05-24 plan-review round 1."""
        over_cap_payload = dict(_happy_lease_payload())
        over_cap_payload["lease_duration"] = 3600
        transport = _mock_transport(lease_return=over_cap_payload)
        # _mock_transport already wires transport.revoke as AsyncMock
        # returning None. The assertion verifies the call happened with
        # the lease_id from the over-cap payload.
        with pytest.raises(VaultLeaseGrantExceedsRequest) as exc_info:
            await lease_credential(
                _request(ttl_s=900),
                transport=transport,
                settings=_settings(),
            )
        transport.revoke.assert_awaited_once_with(_happy_lease_payload()["lease_id"])
        assert exc_info.value.lease_id == _happy_lease_payload()["lease_id"]
        assert exc_info.value.revoke_outcome == "revoked"

    async def test_grant_at_or_below_request_does_not_revoke(self) -> None:
        """Sprint 10.1 #6 — green path does NOT call revoke. The kernel
        only revokes when refusing the lease for over-grant; a normal
        successful lease is the caller's to manage (revoked via the
        existing destroy()/sandbox-lifecycle path)."""
        boundary_payload = dict(_happy_lease_payload())
        boundary_payload["lease_duration"] = 900
        transport = _mock_transport(lease_return=boundary_payload)
        await lease_credential(_request(ttl_s=900), transport=transport, settings=_settings())
        transport.revoke.assert_not_awaited()

    async def test_grant_exceeding_request_with_revoke_failure_still_raises(
        self,
    ) -> None:
        """Sprint 10.1 #7 — revoke failure does NOT mask the TTL refusal.
        Exception's ``revoke_outcome="revoke_failed"`` + ``__cause__``
        chains the revoke exception for examiner traceability + downstream
        operator paging. The TTL refusal is the load-bearing security
        finding; cleanup failure is a separate operational concern."""
        over_cap_payload = dict(_happy_lease_payload())
        over_cap_payload["lease_duration"] = 3600
        transport = _mock_transport(lease_return=over_cap_payload)
        revoke_failure = ConnectionError("vault unreachable on revoke")
        transport.revoke = AsyncMock(side_effect=revoke_failure)
        with pytest.raises(VaultLeaseGrantExceedsRequest) as exc_info:
            await lease_credential(
                _request(ttl_s=900),
                transport=transport,
                settings=_settings(),
            )
        assert exc_info.value.revoke_outcome == "revoke_failed"
        assert exc_info.value.lease_id == _happy_lease_payload()["lease_id"]
        # __cause__ chains the revoke exception so Vault diagnostics can
        # trace the revoke failure separately from the TTL refusal.
        assert exc_info.value.__cause__ is revoke_failure


# ──────────────────────────────────────────────────────────────────────
# 7. core/vault.py module surface — __all__ membership (Sprint 10.1).
# ──────────────────────────────────────────────────────────────────────


class TestCoreVaultModuleSurface:
    def test_vault_lease_grant_exceeds_request_in_all(self) -> None:
        """Sprint 10.1 #8 — new exception MUST be in core/vault.__all__
        so ``from cognic_agentos.core.vault import *`` consumers receive
        it. Closes Finding E of the 2026-05-24 plan-review round 1."""
        import cognic_agentos.core.vault as vault_module

        assert "VaultLeaseGrantExceedsRequest" in vault_module.__all__
