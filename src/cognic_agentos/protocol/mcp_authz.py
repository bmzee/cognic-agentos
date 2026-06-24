"""protocol/mcp_authz.py — OAuth + Protected Resource Metadata client for MCP.

Critical-controls module per AGENTS.md (Protocol authorization — MCP
authz is on the doctrine list). Per Sprint-5 R3 P1 doctrine, this
module is **admission-side**: it imports + constructs cleanly without
the ``mcp`` SDK installed. PRM discovery + token acquisition use
httpx + json + OAuth/PRM URL conventions (RFC 8707, OAuth 2.1) —
pure HTTP standards, NOT MCP-spec wire format. **Does NOT call
``require_mcp()`` at construction.**

(Note: "imports + constructs without the SDK" does not mean "full
Sprint-4 signed-pack admission runs end-to-end on the kernel image".
That path still depends on cosign + OPA which Sprint 4 ships in the
default-adapters image only. The MCP layer's contribution to the
admission boundary is "no NEW default-adapters-only requirement";
end-to-end admission of HTTP MCP packs requires either the
default-adapters image or an explicitly-documented local fallback
that brings cosign + OPA into PATH — out of Sprint 5 scope.)

The MCP authorization spec (April 2026 revision) defines OAuth-based
authorization for HTTP transports. AgentOS implements this for all
production-default Streamable HTTP MCP traffic. Per ADR-002 §"MCP
Authorization":

  1. Resource-metadata discovery — three paths in priority order
     (the spec mandates supporting all three):

     a. **Primary signal** — ``WWW-Authenticate: Bearer
        resource_metadata="<url>"`` header on a 401 response;
        client follows the URL the server advertises.
     b. **Endpoint-specific well-known fallback** — when the 401
        lacks ``WWW-Authenticate``, client probes the endpoint-
        specific PRM path first. For an MCP endpoint at
        ``https://server.example/public/mcp``, that's
        ``https://server.example/.well-known/oauth-protected-resource/public/mcp``.
        This per-resource convention lets a single host expose
        multiple MCP servers under different paths each with their
        own PRM.
     c. **Root well-known fallback** — if the endpoint-specific
        path 404s, the client falls back to host-level
        ``/.well-known/oauth-protected-resource``.

     All three paths produce the same Protected Resource Metadata
     document (authorization servers + supported scopes); whichever
     returns first wins.

  2. **Per-tenant authorization-server allow-list** in Vault — only
     AS endpoints on the list will be contacted (prevents an
     attacker-controlled MCP server from redirecting AgentOS to a
     malicious AS).

  3. **RFC 8707 resource indicator** (``resource=<server URL>``) on
     every token request — the AS binds the issued token to the
     specific MCP server; tokens are never reused across servers.

  4. **Audience validation** on every received token — ``aud`` claim
     MUST match the MCP server's resource indicator. Mismatched
     audience → token rejected, server treated as 401, fresh
     discovery + token request triggered.

  5. **Insufficient-scope step-up** — per the spec, runtime
     insufficient scope is signalled by ``403 Forbidden`` (NOT 401
     — initial missing/invalid auth is 401, runtime under-scoped is
     403). Client requests a fresh token covering the wider scope
     **only if** (a) the manifest declares the wider scope AND
     (b) tenant policy permits.

  6. **Token cache + refresh** — tokens cached per
     ``(server, scopes, resource)`` tuple; refreshed before expiry;
     ``audit.mcp_token_refresh`` event per refresh.

Closed-enum error vocabulary (matches the registry-side
:class:`RefusalReason` extension landing in T6):

- ``mcp_anonymous_refused`` — server lacks PRM AND no API-key
  fallback declared.
- ``mcp_as_not_allowlisted`` — PRM advertises an AS not on the
  per-tenant allow-list.
- ``mcp_token_audience_mismatch`` — ``aud`` claim does not match the
  resource indicator.
- ``mcp_token_scope_overgrant`` — AS returned a granted scope set
  that is NOT a subset of the manifest-declared scopes (no-silent-
  privilege-widening doctrine; the AS may not promote scopes the
  manifest didn't authorise).
- ``mcp_step_up_unauthorised`` — server returns 403 insufficient_scope
  with a wider scope, but the manifest does NOT declare that scope.
- ``mcp_oauth_request_timeout`` — discovery / token / refresh
  exceeded ``settings.mcp_oauth_request_timeout_s``.
- ``mcp_oauth_transport_failure`` — non-timeout transport error
  (DNS, ConnectError, TLS handshake failure, network unreachable).
  Distinct from ``mcp_oauth_request_timeout`` so operators see the
  precise cause in audit/logs.
- ``mcp_oauth_credentials_missing`` — Vault has no OAuth client
  credentials configured for ``(tenant, AS issuer)``. Operators must
  populate the per-tenant Vault path before admission can proceed.
- ``mcp_oauth_as_discovery_invalid`` — the AS issuer's
  ``.well-known/oauth-authorization-server`` discovery document
  is malformed (non-200 status, non-JSON body, or missing
  ``token_endpoint``). Distinct from ``mcp_prm_invalid``: a bad AS
  discovery doc implicates the AS operator, not the MCP server's
  PRM. Per R11 P2 — operationally these are different debug paths.
- ``mcp_oauth_token_endpoint_error`` — the AS token endpoint
  returned a non-200 status (e.g., 401 = rejected client credentials,
  400 = ``invalid_grant`` / ``invalid_scope``, 503 = AS down).
  Distinct from ``mcp_prm_invalid``: a 401 here usually points at
  Vault-stored OAuth client credentials, not the PRM document. Per
  R11 P2.
- ``mcp_oauth_token_response_invalid`` — the AS returned 200 but
  the response shape is malformed (non-JSON body, missing
  ``access_token``, non-numeric / non-finite / non-positive / bool
  ``expires_in``, non-string ``scope``). Distinct from
  ``mcp_prm_invalid``: the failure is in the AS's *token response*,
  not the resource server's PRM. Per R11 P2.
- ``mcp_prm_invalid`` — PRM document malformed (the
  ``/.well-known/oauth-protected-resource`` document on the MCP
  server side, NOT the AS).
- ``mcp_discovery_url_refused`` — remediation §4.1 SSRF guard (widened
  by PR-2a): an MCP auth-or-discovery fetch target was refused on any of
  the five legs — server_url / prm_metadata / well_known_prm (PR-1) +
  as_metadata / token_endpoint (PR-2a OAuth legs) — for a non-http(s)
  scheme, no host, or (in stage/prod) a host resolving to a private /
  loopback / link-local / reserved address. The refusal payload carries
  ``leg`` (which fetch) + ``refused_component`` (why); it never echoes
  the raw URL.

Forward-mapping note: T6's ``plugin_registry.RefusalReason`` literal
will need entries for the six Sprint-5-T5 additions
(``mcp_token_scope_overgrant``, ``mcp_oauth_transport_failure``,
``mcp_oauth_credentials_missing``, ``mcp_oauth_as_discovery_invalid``,
``mcp_oauth_token_endpoint_error``, ``mcp_oauth_token_response_invalid``).
T6's ``_authz_reason_to_refusal()`` mapper handles them 1:1.
"""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import ipaddress
import json
import logging
import math
import time
from typing import Any, Literal, cast
from urllib.parse import quote_plus, urlparse

import httpx

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.config import _STRICT_PROFILES, Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.db.adapters.protocols import SecretAdapter

_LOG = logging.getLogger("cognic_agentos.protocol.mcp_authz")

#: Sentinel that distinguishes "field absent from JSON" from
#: "field present with malformed value". Used by token-response
#: scope parsing so a missing ``scope`` defaults to the requested
#: set (per OAuth 2.1 §3.2.3) while a present-but-non-string
#: ``scope`` fails closed with ``mcp_oauth_token_response_invalid``
#: (R11 P2 split this off the general ``mcp_prm_invalid`` bucket).
_SCOPE_ABSENT = object()


#: Closed-enum error vocabulary. Every method that fails closed maps
#: to exactly one of these values. T6's registry integration converts
#: these to the corresponding ``plugin_registry.RefusalReason``
#: literals via a 1:1 mapping helper (no fall-through).
AuthzReason = Literal[
    "mcp_anonymous_refused",
    "mcp_as_not_allowlisted",
    "mcp_token_audience_mismatch",
    "mcp_token_scope_overgrant",
    "mcp_step_up_unauthorised",
    # Runtime-only (NOT a registration-boundary value): the MCP server
    # rejected both the cached and a freshly-acquired token with 401
    # / 403 invalid_token. MCPHost emits this after one drop+retry
    # attempt fails — second-401 is the terminal state. Sprint-5 T9
    # R1 P2 #3.
    "mcp_authorisation_lost",
    "mcp_oauth_request_timeout",
    "mcp_oauth_transport_failure",
    "mcp_oauth_credentials_missing",
    "mcp_oauth_as_discovery_invalid",
    "mcp_oauth_token_endpoint_error",
    "mcp_oauth_token_response_invalid",
    "mcp_prm_invalid",
    # Remediation §4.1 (SSRF), widened by PR-2a: an MCP auth-OR-discovery URL
    # was refused by the non-public-URL guard. Covers all five legs —
    # server_url, prm_metadata, well_known_prm (PR-1) + as_metadata,
    # token_endpoint (PR-2a OAuth legs). The refusal payload carries `leg`
    # (which fetch) + `refused_component` (why). Reused, NOT a new member.
    "mcp_discovery_url_refused",
]


# PR-2a (ADR-002): the prefetch SSRF guard fires on five discovery/OAuth legs.
# `leg` is the closed-enum "which fetch" discriminator (orthogonal to
# `refused_component`, the "why" axis). It rides MCPAuthzError.payload["leg"].
DiscoveryLeg = Literal[
    "server_url",
    "prm_metadata",
    "well_known_prm",
    "as_metadata",
    "token_endpoint",
]

# The 3-value internal `discovery_path` label that `_fetch_prm` already carries
# maps onto the two PRM-family legs.
_PRM_DISCOVERY_PATH_TO_LEG: dict[str, DiscoveryLeg] = {
    "www-authenticate": "prm_metadata",
    "endpoint-well-known": "well_known_prm",
    "root-well-known": "well_known_prm",
}


class MCPAuthzError(Exception):
    """OAuth/PRM client errors carry a closed-enum reason + structured
    payload for audit-event correlation. Operators see the reason
    directly; the payload feeds the registry's audit emission.
    """

    def __init__(
        self,
        reason: AuthzReason,
        message: str = "",
        **payload: Any,
    ) -> None:
        self.reason: AuthzReason = reason
        self.payload: dict[str, Any] = payload
        super().__init__(f"{reason}: {message}" if message else reason)


@dataclasses.dataclass(frozen=True, slots=True)
class ResourceMetadata:
    """OAuth Protected Resource Metadata document.

    Per the MCP authorization spec, the PRM document advertises
    authorization servers + supported scopes for a given resource
    (the MCP server URL). AgentOS reads this to know which AS to
    request a token from.
    """

    #: The resource URL the PRM document describes (canonicalised
    #: against the MCP server's URL).
    resource: str

    #: Tuple of authorization-server issuer URLs the resource accepts
    #: tokens from. Each must be on the per-tenant AS allow-list.
    authorization_servers: tuple[str, ...]

    #: Scopes the resource server supports. Pack manifests declare a
    #: subset; the client requests only the manifest-declared scopes.
    scopes_supported: tuple[str, ...] = ()

    #: Discovery path that produced this document (one of
    #: ``"www-authenticate"`` / ``"endpoint-well-known"`` /
    #: ``"root-well-known"`` / ``"api-key-fallback"``). Used for
    #: audit/log correlation; not part of the spec.
    discovery_path: str = "unknown"


@dataclasses.dataclass(frozen=True, slots=True)
class Token:
    """An OAuth access token, RFC-8707-bound to a specific resource.

    The ``value`` field carries the raw bearer token bytes — handle
    with care: never log it, never include it in audit payloads,
    never serialize it via ``__repr__`` (frozen+slotted dataclass
    prevents accidental ``__dict__`` exposure).
    """

    #: The raw bearer token value. Operators MUST NOT log this.
    value: str

    #: Unix epoch seconds at which the token expires. Refresh
    #: triggers when ``time.time() + refresh_buffer >= expires_at``.
    expires_at: float

    #: AS issuer URL that minted the token (from the ``iss`` claim
    #: or the AS endpoint we requested it from).
    as_issuer: str

    #: Scopes the token grants. Frozen tuple for hashability +
    #: cache-key participation.
    scopes: tuple[str, ...]

    #: RFC 8707 resource indicator the token is bound to. Tokens
    #: with a mismatched ``aud`` claim are rejected at acquisition
    #: time; this field is the audience the cache + audit emit
    #: cite as the bound-to resource.
    resource_indicator: str

    #: OAuth client_id used to acquire the token. Carried in audit
    #: events for the AS-issuer correlation chain.
    client_id: str

    def __repr__(self) -> str:
        """Defensive ``__repr__`` that never leaks the token value.

        Frozen+slotted dataclass already disables ``__dict__`` access,
        but Python's default repr for slotted dataclasses still
        includes every field. Override to redact ``value``.
        """
        return (
            f"Token(value=<redacted>, expires_at={self.expires_at}, "
            f"as_issuer={self.as_issuer!r}, scopes={self.scopes}, "
            f"resource_indicator={self.resource_indicator!r}, "
            f"client_id={self.client_id!r})"
        )


#: Refresh tokens before this many seconds before their expiry. A
#: 60-second buffer means a token used right at the cusp of expiry
#: gets a fresh refresh rather than a 401 from the server.
_TOKEN_REFRESH_BUFFER_S = 60.0


def _endpoint_specific_well_known_url(server_url: str) -> str:
    """Build the endpoint-specific PRM URL for a given MCP server URL.

    Per spec: for ``https://server.example/public/mcp``, the
    endpoint-specific PRM lives at
    ``https://server.example/.well-known/oauth-protected-resource/public/mcp``.

    The path is preserved verbatim from the server URL; only the
    ``/.well-known/oauth-protected-resource`` prefix is inserted at
    the host root.
    """
    parsed = urlparse(server_url)
    # Strip trailing slash from path to avoid double-slash in the
    # well-known URL; spec uses the resource path as-is otherwise.
    path = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-protected-resource{path}"


def _root_well_known_url(server_url: str) -> str:
    """Build the host-level PRM URL: scheme://host/.well-known/oauth-protected-resource."""
    parsed = urlparse(server_url)
    return f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-protected-resource"


def _decode_jwt_payload(token: str) -> dict[str, Any]:
    """Decode the payload of a JWT-format token without verifying its
    signature.

    The signature was already verified by the AS that issued the
    token; we re-decode the payload only to read the ``aud`` claim
    for audience validation. Returns ``{}`` for non-JWT tokens (e.g.
    opaque tokens) — those skip audience validation at this layer
    (the AS is trusted to bind the audience via RFC 8707).
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        # JWT payload uses base64url; pad if needed
        payload_b64 = parts[1]
        padding = "=" * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64 + padding)
        result = json.loads(decoded)
        if not isinstance(result, dict):
            return {}
        return cast("dict[str, Any]", result)
    except (ValueError, json.JSONDecodeError):
        return {}


async def _resolve_host_addresses(host: str) -> list[str]:
    """Resolve a host to its IP-address strings for the SSRF guard. An IP
    literal resolves to itself (no DNS); a hostname is resolved via the event
    loop's ``getaddrinfo``. Module-level so the resolver is a monkeypatchable
    seam in tests. Raises ``OSError`` (e.g. ``socket.gaierror``) on resolution
    failure — the caller treats that as non-blocking (the subsequent fetch
    fails at the transport layer)."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None)
        return [str(info[4][0]) for info in infos]
    return [host]


class MCPAuthzClient:
    """OAuth + Protected Resource Metadata client per ADR-002.

    Construction is SDK-free per Sprint-5 R3 P1 doctrine — every
    method uses :mod:`httpx` for HTTP and :mod:`json` for parsing.
    The class imports + constructs without the ``mcp`` SDK installed
    (i.e., the MCP layer adds no NEW default-adapters-only requirement
    for admission). Full Sprint-4 signed-pack admission still depends
    on cosign + OPA which are default-adapters-only — that boundary is
    independent of this class.

    Audit + decision-history dependencies are constructor-required so
    refresh / acquire / step-up flows can emit chained events without
    a later breaking change to the API. Every method takes
    ``request_id`` + ``tenant_id`` keyword-only — no defaults; caller
    MUST provide.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        vault_client: SecretAdapter,
        http_client: httpx.AsyncClient,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
    ) -> None:
        # NO require_mcp() — admission-side per R3 P1 doctrine.
        # PRM discovery + token acquisition use httpx + OAuth/PRM URL
        # conventions; never the mcp SDK.
        self._settings = settings
        self._vault = vault_client
        self._http = http_client
        self._audit = audit_store
        self._dh = decision_history_store

        # Token cache keyed by (server_url, granted-scopes-frozenset,
        # resource_indicator). The asyncio.Lock guards reads + writes
        # of BOTH the cache and the in-flight map; the lock is held
        # only across the cache-lookup + in-flight-register check —
        # NEVER across the network round-trip.
        self._token_cache: dict[tuple[str, frozenset[str], str], Token] = {}
        # In-flight coalescing map (R11 P2 (a)). Keyed by the same
        # cache-key shape as the token cache (so the lookup miss key
        # is also the in-flight key). Value is an ``asyncio.Future[Token]``
        # that the in-flight owner resolves on completion or failure.
        # Concurrent cold callers for the same cache key observe the
        # Future under lock and await it, so the AS sees one network
        # round-trip per `(server, exact_scope_set, resource)` even
        # under contention.
        self._inflight_acquires: dict[tuple[str, frozenset[str], str], asyncio.Future[Token]] = {}
        self._cache_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def discover_resource_metadata(
        self,
        *,
        server_url: str,
        request_id: str,
        tenant_id: str,
    ) -> ResourceMetadata:
        """Discover the PRM document for an MCP server via the 3-path
        priority order (WWW-Authenticate → endpoint-specific well-known
        → root well-known).

        Returns the first valid PRM document. Raises
        :class:`MCPAuthzError` with reason ``mcp_prm_invalid`` if every
        path returns malformed or missing data; ``mcp_anonymous_refused``
        if every path fails entirely (no auth surface advertised);
        ``mcp_oauth_request_timeout`` on timeout.
        """
        await self._refuse_non_public_discovery_url(server_url, leg="server_url")
        timeout = self._settings.mcp_oauth_request_timeout_s

        # Path 1: probe the MCP server itself, look for
        # WWW-Authenticate: Bearer resource_metadata="..." on a 401.
        try:
            probe = await self._http.get(server_url, timeout=timeout)
        except httpx.TimeoutException as exc:
            raise MCPAuthzError(
                "mcp_oauth_request_timeout",
                f"PRM probe to {server_url} exceeded {timeout}s",
                server_url=server_url,
            ) from exc
        except httpx.RequestError as exc:
            # ConnectError, NetworkError, TLS handshake failure, DNS
            # failure, etc. Map to the closed-enum
            # mcp_oauth_transport_failure reason so registration auth
            # probes always return a closed refusal (never bubble a
            # raw httpx exception). T15 R1 P2 #3: the exception's class
            # name lands in the payload's ``transport_error_class``
            # field — but the message MUST NOT include ``str(exc)``
            # because lower-layer httpx exception text can leak
            # request URLs containing client-secret-like fragments,
            # backend debug strings, or Authorization-header bytes.
            # The ``__cause__`` chain via ``from exc`` keeps the raw
            # detail accessible in tracebacks (operator-only) without
            # including it in audit / log payloads.
            raise MCPAuthzError(
                "mcp_oauth_transport_failure",
                f"PRM probe to {server_url} failed at transport layer",
                server_url=server_url,
                transport_error_class=type(exc).__name__,
            ) from exc

        if probe.status_code == 401:
            www_auth = probe.headers.get("WWW-Authenticate", "")
            prm_url = _parse_resource_metadata_url(www_auth)
            if prm_url is not None:
                doc = await self._fetch_prm(prm_url, "www-authenticate", server_url, timeout)
                if doc is not None:
                    return doc

        # Path 2: endpoint-specific well-known fallback.
        endpoint_specific = _endpoint_specific_well_known_url(server_url)
        doc = await self._fetch_prm(endpoint_specific, "endpoint-well-known", server_url, timeout)
        if doc is not None:
            return doc

        # Path 3: root well-known fallback.
        root = _root_well_known_url(server_url)
        doc = await self._fetch_prm(root, "root-well-known", server_url, timeout)
        if doc is not None:
            return doc

        # All three paths failed. The pack manifest may still declare
        # an API-key fallback; the caller (registry / call_tool path)
        # decides whether to refuse or fall back. From this client's
        # perspective, the server is anonymous.
        raise MCPAuthzError(
            "mcp_anonymous_refused",
            f"server {server_url} advertises no PRM via any of the three discovery paths",
            server_url=server_url,
        )

    async def acquire_token(
        self,
        *,
        server_url: str,
        manifest_scopes: tuple[str, ...],
        request_id: str,
        tenant_id: str,
    ) -> Token:
        """Acquire an OAuth token for the MCP server, caching the
        result.

        Steps:
          1. Cache lookup (return only if a non-expired cached token's
             GRANTED scopes EQUAL the requested ``manifest_scopes`` —
             least-privilege match per R10 P2).
          2. PRM discovery (via :meth:`discover_resource_metadata`).
          3. Per-tenant AS allow-list lookup; refuse if AS not allowed.
          4. Token request to the allowed AS with RFC 8707 resource
             indicator.
          5. Audience validation on the returned token.
          6. Cache (under the GRANTED scope set, not the requested set
             — see :meth:`_cache_put_under_granted`) + return.

        Cache-key doctrine (R9 P2 + R10 P2): the cache key is the
        actual GRANTED scope set, and the lookup match is **exact** on
        granted == requested. Two invariants compose:

        - **R9** — granted-narrower-than-requested: AS narrowed
          ``("mcp:tools", "mcp:tools.write")`` to ``("mcp:tools",)``.
          Cached under granted = ``{"mcp:tools"}``. Next broader
          acquire's lookup key is ``{"mcp:tools", "mcp:tools.write"}``
          → MISS → fresh broad-scope token request. (Without R9, the
          narrowed token would have been silently reused for the
          broader call and silently under-scoped it.)
        - **R10** — granted-broader-than-requested: a step-up cached
          a token under granted = ``{"mcp:tools", "mcp:tools.write"}``.
          Next narrower acquire's lookup key is ``{"mcp:tools"}`` →
          MISS → fresh narrow-scope token request. (Without R10, the
          higher-privileged stepped-up token would have been reused
          for a narrower invocation, sending more privilege than the
          call needed; ADR-002 + Sprint-5 plan mandate minimum-scope
          token acquisition.)

        Cache hits only happen when granted == requested. This both
        preserves least privilege (no broader token reuse) and avoids
        silent under-scoping (no narrower token reuse).

        Closed-enum failures (every value of :data:`AuthzReason`
        EXCEPT ``mcp_step_up_unauthorised``, which is runtime-only and
        only raised by :meth:`step_up_token`): ``mcp_anonymous_refused``
        (proxied from discovery), ``mcp_as_not_allowlisted``,
        ``mcp_token_audience_mismatch``, ``mcp_token_scope_overgrant``
        (R6 — AS-granted scopes ⊋ manifest), ``mcp_oauth_request_timeout``,
        ``mcp_oauth_transport_failure`` (R6 — DNS / TLS / network),
        ``mcp_oauth_credentials_missing`` (R6 — Vault has no client
        credentials for this ``(tenant, AS-issuer)``),
        ``mcp_oauth_as_discovery_invalid`` (R11 — AS
        ``.well-known/oauth-authorization-server`` malformed),
        ``mcp_oauth_token_endpoint_error`` (R11 — token endpoint
        non-200; status_code in payload only, never the body),
        ``mcp_oauth_token_response_invalid`` (R11 — missing
        ``access_token``, malformed ``expires_in`` / ``scope``),
        ``mcp_prm_invalid`` (PRM document on the MCP server side
        malformed; narrowed by R11). Refer to the module docstring
        for the full closed-enum vocabulary + when each reason fires.
        """
        # Step 1: cache lookup + in-flight registration. Held under
        # ``_cache_lock`` so the lookup-and-register pair is atomic.
        # The lock is released BEFORE the network round-trip — the
        # in-flight map serves the same coalescing purpose without
        # holding the lock through I/O.
        inflight_key = (server_url, frozenset(manifest_scopes), server_url)
        we_own_inflight = False
        async with self._cache_lock:
            cached = self._lookup_cached_for_exact_scopes(
                server_url=server_url, requested_scopes=manifest_scopes
            )
            if cached is not None:
                return cached
            existing_inflight = self._inflight_acquires.get(inflight_key)
            if existing_inflight is not None:
                future_to_await = existing_inflight
            else:
                # We are the first concurrent caller for this key —
                # register an in-flight Future so any later concurrent
                # caller awaits us instead of issuing another AS request.
                future_to_await = asyncio.get_running_loop().create_future()
                # Discard-callback to consume any unawaited exception:
                # if no concurrent caller actually awaits this Future,
                # ``set_exception`` would otherwise emit a noisy
                # "Future exception was never retrieved" warning at
                # GC time. We retrieve the exception here so asyncio
                # considers it handled — the original exception still
                # propagates from the owner's own ``raise`` (we're
                # only handling THIS Future's reference, not muting
                # the failure path).
                future_to_await.add_done_callback(
                    lambda f: f.exception() if not f.cancelled() else None
                )
                self._inflight_acquires[inflight_key] = future_to_await
                we_own_inflight = True

        if not we_own_inflight:
            # Concurrent caller — await the in-flight owner's Future.
            # Whatever the owner resolves with (success Token or
            # MCPAuthzError) is exactly what we receive.
            #
            # ``asyncio.shield`` is load-bearing here (R12 P2): a bare
            # ``await future_to_await`` would let a waiter task's
            # cancellation propagate INTO the shared Future, marking
            # it cancelled. The owner's later ``set_result`` /
            # ``set_exception`` would then raise ``InvalidStateError``,
            # leaving the in-flight slot in an inconsistent state.
            # With shield, a waiter cancellation raises CancelledError
            # in THIS task only; the underlying Future is untouched
            # and the owner can still resolve it cleanly.
            return await asyncio.shield(future_to_await)

        # We own the in-flight Future; do the real work and resolve.
        # ``finally`` block guarantees the in-flight slot is always
        # deregistered (R12 P2 — even if ``set_exception`` itself were
        # to raise). Identity check on the dict entry prevents a
        # double-pop in pathological re-entrancy scenarios.
        try:
            # Step 2: PRM discovery
            prm = await self.discover_resource_metadata(
                server_url=server_url, request_id=request_id, tenant_id=tenant_id
            )

            # Step 3: AS allow-list
            allowed_servers = await self._load_as_allowlist(tenant_id)
            candidate_as = [s for s in prm.authorization_servers if s in allowed_servers]
            if not candidate_as:
                raise MCPAuthzError(
                    "mcp_as_not_allowlisted",
                    f"PRM advertises {list(prm.authorization_servers)} but "
                    f"per-tenant allow-list contains {sorted(allowed_servers)}",
                    server_url=server_url,
                    advertised_servers=list(prm.authorization_servers),
                )
            as_issuer = candidate_as[0]

            # Step 4: token request with RFC 8707 resource indicator
            token = await self._request_token(
                as_issuer=as_issuer,
                server_url=server_url,
                manifest_scopes=manifest_scopes,
                request_id=request_id,
                tenant_id=tenant_id,
            )

            # Step 5: audience validation
            _validate_token_audience(token, expected_audience=server_url)

            # Step 6: cache under GRANTED scopes
            async with self._cache_lock:
                self._cache_put_under_granted(token)
            # Guarded resolve: if a waiter somehow cancelled the Future
            # despite shield, ``set_result`` would raise InvalidStateError.
            # Skip the call when already done; finally still deregisters.
            if not future_to_await.done():
                future_to_await.set_result(token)
            return token
        except BaseException as exc:
            # Propagate failure to any concurrent waiters with the SAME
            # exception object. Guarded the same way as the success
            # path; if the Future is already done (cancelled), skip
            # set_exception to avoid InvalidStateError clobbering the
            # original raise.
            if not future_to_await.done():
                future_to_await.set_exception(exc)
            raise
        finally:
            # Identity-checked deregister: only pop if still ours.
            # In the unlikely case of a re-entrant retry that replaced
            # our entry, we do NOT pop someone else's Future. Always
            # runs regardless of whether the try-block raised.
            async with self._cache_lock:
                if self._inflight_acquires.get(inflight_key) is future_to_await:
                    self._inflight_acquires.pop(inflight_key, None)

    def _lookup_cached_for_exact_scopes(
        self, *, server_url: str, requested_scopes: tuple[str, ...]
    ) -> Token | None:
        """Return the cached token whose GRANTED scopes equal the
        requested set exactly, or ``None``.

        Least-privilege match (R10 P2): the lookup never returns a
        token whose granted scopes are broader OR narrower than the
        requested set. Combined with :meth:`_cache_put_under_granted`
        (which keys entries by the actual granted scope set), this
        gives:

        - **Narrower-grant** (R9 P2): cached granted ⊊ requested →
          lookup MISS → fresh request. Prevents silent under-scoping.
        - **Broader-grant** (R10 P2): cached granted ⊋ requested →
          lookup MISS → fresh request. Prevents reuse of a higher-
          privileged stepped-up token for a narrower call.
        - **Exact-grant**: the only HIT path.

        ADR-002 + Sprint-5 plan describe minimum-scope token
        acquisition with cache keys by ``(server, scope, resource)``;
        the exact-match rule is the natural reading of that contract.

        Caller MUST hold ``self._cache_lock``.
        """
        cache_key = (server_url, frozenset(requested_scopes), server_url)
        cached = self._token_cache.get(cache_key)
        if cached is None or _is_token_near_expiry(cached):
            return None
        return cached

    def _cache_put_under_granted(self, token: Token) -> None:
        """Insert a freshly-acquired token into the cache keyed by its
        GRANTED scope set (``frozenset(token.scopes)``).

        Caller MUST hold ``self._cache_lock``. The granted-keyed
        insert combined with the exact-match lookup
        (:meth:`_lookup_cached_for_exact_scopes`) implements the
        least-privilege cache contract: a cached token is reusable
        only for a request that asks for exactly the granted set.
        """
        cache_key = (
            token.resource_indicator,
            frozenset(token.scopes),
            token.resource_indicator,
        )
        self._token_cache[cache_key] = token

    async def invalidate_cached_token(self, *, server_url: str) -> None:
        """Drop every cached token entry whose resource_indicator
        matches ``server_url``.

        Sprint-5 T9 R1 P2 #3 surface: when MCPHost receives a 401
        (``mcp_authorisation_lost``) or a 403 ``error="invalid_token"``,
        the cached token is no longer accepted by the server (AS key
        rotation, revocation, expiry-not-yet-detected by our
        refresh-buffer math, etc.). The orchestrator MUST drop the
        cached entry so the retry's :meth:`acquire_token` does a
        fresh PRM discovery + token request rather than serving the
        same dead token from cache.

        Cache keys are ``(resource_indicator, frozenset(scopes),
        resource_indicator)`` per :meth:`_cache_put_under_granted`;
        invalidation matches on the resource_indicator (which the
        cache uses as a stand-in for server_url since that's the
        bound-to audience). Drops EVERY scope-tier entry for the
        server — a 401 invalidates the auth context, not just the
        specific scope tier the failing call used.

        No-op for a server with no cached entries (idempotent).
        Token-free per the same discipline as the rest of this
        module — we read keys, not values.
        """
        async with self._cache_lock:
            doomed = [
                key for key in self._token_cache if key[0] == server_url or key[2] == server_url
            ]
            for key in doomed:
                del self._token_cache[key]

    async def step_up_token(
        self,
        *,
        server_url: str,
        current_token: Token,
        requested_scope: str,
        manifest_scopes: tuple[str, ...],
        request_id: str,
        tenant_id: str,
    ) -> Token:
        """Step-up flow on 403 insufficient_scope.

        Per spec: server returns 403 with
        ``WWW-Authenticate: Bearer error="insufficient_scope",
        scope="<wider>"`` when the current token's scopes are
        insufficient. The client requests a fresh token covering the
        wider scope **only if** the manifest declares it. Manifest
        does NOT declare → fail with ``mcp_step_up_unauthorised``.

        Note: 401 ``insufficient_scope`` is treated as discovery-required
        (NOT step-up) by the caller — the 401-vs-403 distinction lives
        in :meth:`acquire_token` / the call dispatcher, not here. This
        method assumes the caller has already determined a step-up is
        warranted.
        """
        if requested_scope not in manifest_scopes:
            # Audit BEFORE raise — denied step-ups MUST land in the
            # audit chain (security-relevant; an attacker probing for
            # wider scopes leaves a trace). Token contents NEVER
            # included.
            await self._audit.append(
                AuditEvent(
                    event_type="audit.mcp_step_up",
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload={
                        "server_url": server_url,
                        "as_issuer": current_token.as_issuer,
                        "client_id": current_token.client_id,
                        "prior_scopes": list(current_token.scopes),
                        "requested_additional_scope": requested_scope,
                        "manifest_scopes": list(manifest_scopes),
                        "outcome": "mcp_step_up_unauthorised",
                    },
                )
            )
            raise MCPAuthzError(
                "mcp_step_up_unauthorised",
                f"server requested scope {requested_scope!r} but manifest "
                f"declares only {list(manifest_scopes)}",
                server_url=server_url,
                requested_scope=requested_scope,
                manifest_scopes=list(manifest_scopes),
            )

        wider_scopes = (*current_token.scopes, requested_scope)
        # Acquire a fresh token covering the wider scope set. Bypass
        # the cache lookup (we explicitly need a NEW token — the cached
        # one is the under-scoped version). Re-uses the discovery +
        # AS allow-list path of acquire_token.
        prm = await self.discover_resource_metadata(
            server_url=server_url, request_id=request_id, tenant_id=tenant_id
        )
        allowed = await self._load_as_allowlist(tenant_id)
        candidate_as = [s for s in prm.authorization_servers if s in allowed]
        if not candidate_as:
            # Audit BEFORE raise — AS-allowlist revocation during step-up
            # is a tenant-policy event and operators MUST see it.
            await self._audit.append(
                AuditEvent(
                    event_type="audit.mcp_step_up",
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload={
                        "server_url": server_url,
                        "as_issuer": current_token.as_issuer,
                        "client_id": current_token.client_id,
                        "prior_scopes": list(current_token.scopes),
                        "requested_additional_scope": requested_scope,
                        "advertised_servers": list(prm.authorization_servers),
                        "outcome": "mcp_as_not_allowlisted",
                    },
                )
            )
            raise MCPAuthzError(
                "mcp_as_not_allowlisted",
                "step-up requires a fresh token request; PRM AS no longer on per-tenant allow-list",
                server_url=server_url,
            )
        token = await self._request_token(
            as_issuer=candidate_as[0],
            server_url=server_url,
            manifest_scopes=tuple(sorted(set(wider_scopes))),
            request_id=request_id,
            tenant_id=tenant_id,
        )
        _validate_token_audience(token, expected_audience=server_url)

        # Step-up audit event (separate from refresh — the prior +
        # newly-granted scope set is the audit-relevant detail).
        await self._audit.append(
            AuditEvent(
                event_type="audit.mcp_step_up",
                request_id=request_id,
                tenant_id=tenant_id,
                payload={
                    "server_url": server_url,
                    "as_issuer": token.as_issuer,
                    "client_id": token.client_id,
                    "prior_scopes": list(current_token.scopes),
                    "requested_additional_scope": requested_scope,
                    "granted_scopes": list(token.scopes),
                    "outcome": "granted",
                },
            )
        )

        # Update cache with the wider-scoped token (keyed by granted)
        async with self._cache_lock:
            self._cache_put_under_granted(token)
        return token

    async def refresh_token(
        self,
        *,
        token: Token,
        request_id: str,
        tenant_id: str,
    ) -> Token:
        """Refresh an existing token before expiry.

        Emits ``audit.mcp_token_refresh`` on success. The audit
        payload contains ``as_issuer``, ``scopes``, ``resource_indicator``,
        ``client_id`` — **never the token value itself**.

        Writes a ``decision_history`` row for both success AND failure
        outcomes (per MCP-CONFORMANCE.md §observability + Sprint-5 T11
        doctrine — token refreshes are policy-relevant decisions
        queryable by ``request_id``; failures must be queryable too so
        operators can correlate refresh storms with AS outages).
        """
        # Token request to the same AS, same scope set, same resource.
        # Wrap the request + audience validation so any closed-enum
        # failure produces a decision_history row labelled
        # "refresh_failed" before the exception bubbles to the caller.
        try:
            new_token = await self._request_token(
                as_issuer=token.as_issuer,
                server_url=token.resource_indicator,
                manifest_scopes=token.scopes,
                request_id=request_id,
                tenant_id=tenant_id,
            )
            _validate_token_audience(new_token, expected_audience=token.resource_indicator)
        except MCPAuthzError as exc:
            await self._dh.append(
                DecisionRecord(
                    decision_type="mcp_token_refresh",
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload={
                        "as_issuer": token.as_issuer,
                        "scopes": list(token.scopes),
                        "resource_indicator": token.resource_indicator,
                        "client_id": token.client_id,
                        "decision": "refresh_failed",
                        "reason": exc.reason,
                    },
                )
            )
            raise

        # Audit event — never the token contents
        await self._audit.append(
            AuditEvent(
                event_type="audit.mcp_token_refresh",
                request_id=request_id,
                tenant_id=tenant_id,
                payload={
                    "as_issuer": new_token.as_issuer,
                    "scopes": list(new_token.scopes),
                    "resource_indicator": new_token.resource_indicator,
                    "client_id": new_token.client_id,
                    "outcome": "refreshed",
                },
            )
        )

        # Decision-history row (T11 doctrine) — success path
        await self._dh.append(
            DecisionRecord(
                decision_type="mcp_token_refresh",
                request_id=request_id,
                tenant_id=tenant_id,
                payload={
                    "as_issuer": new_token.as_issuer,
                    "scopes": list(new_token.scopes),
                    "resource_indicator": new_token.resource_indicator,
                    "client_id": new_token.client_id,
                    "decision": "refreshed",
                },
            )
        )

        # Update cache (keyed by GRANTED scopes — same as acquire/step-up)
        async with self._cache_lock:
            self._cache_put_under_granted(new_token)
        return new_token

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _refuse_non_public_discovery_url(self, url: str, *, leg: DiscoveryLeg) -> None:
        """SSRF guard (remediation §4.1) for every MCP auth/discovery fetch leg.

        Reused by all five legs (server_url, prm_metadata, well_known_prm,
        as_metadata, token_endpoint — PR-2a). Always rejects non-http(s)
        schemes and host-less URLs. In the strict (stage/prod) profile
        additionally resolves the host and rejects private / loopback /
        link-local / reserved / multicast / unspecified addresses. Rejection
        payloads identify the refused component CLASS + the `leg`, and NEVER
        echo the raw URL.

        Residual: resolve-then-fetch leaves a DNS-rebinding TOCTOU window;
        full connect-time IP-pinning is a tracked follow-up, not claimed here.
        """
        if not isinstance(url, str):
            raise MCPAuthzError(
                "mcp_discovery_url_refused",
                "discovery URL is not a string",
                refused_component="not_string",
                leg=leg,
            )
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise MCPAuthzError(
                "mcp_discovery_url_refused",
                "discovery URL scheme is not http/https",
                refused_component="scheme",
                leg=leg,
            )
        host = parsed.hostname
        if not host:
            raise MCPAuthzError(
                "mcp_discovery_url_refused",
                "discovery URL has no host",
                refused_component="host",
                leg=leg,
            )
        if self._settings.runtime_profile not in _STRICT_PROFILES:
            return
        try:
            addresses = await _resolve_host_addresses(host)
        except OSError:
            # Unresolvable host is not an SSRF vector; the subsequent fetch
            # fails at the transport layer with a closed-enum reason.
            return
        for addr in addresses:
            try:
                ip = ipaddress.ip_address(addr)
            except ValueError:
                continue
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                raise MCPAuthzError(
                    "mcp_discovery_url_refused",
                    "discovery URL host resolves to a non-public address",
                    refused_component="host_address",
                    leg=leg,
                )

    async def _fetch_prm(
        self,
        url: str,
        discovery_path: str,
        server_url: str,
        timeout: float,
    ) -> ResourceMetadata | None:
        """Fetch + parse a PRM document from a single URL.

        Returns ``None`` on 404 (allows the caller to fall through to
        the next discovery path); raises ``mcp_oauth_request_timeout``
        on timeout; raises ``mcp_prm_invalid`` on malformed JSON or
        missing required fields.
        """
        await self._refuse_non_public_discovery_url(
            url, leg=_PRM_DISCOVERY_PATH_TO_LEG[discovery_path]
        )
        try:
            resp = await self._http.get(url, timeout=timeout)
        except httpx.TimeoutException as exc:
            raise MCPAuthzError(
                "mcp_oauth_request_timeout",
                f"PRM fetch to {url} exceeded {timeout}s",
                url=url,
                server_url=server_url,
            ) from exc
        except httpx.RequestError as exc:
            # T15 R1 P2 #3: same scrubbing as discover_resource_metadata's
            # PRM-probe path — class name in payload, raw text out of message.
            raise MCPAuthzError(
                "mcp_oauth_transport_failure",
                f"PRM fetch to {url} failed at transport layer",
                url=url,
                server_url=server_url,
                transport_error_class=type(exc).__name__,
            ) from exc

        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            return None
        try:
            doc = resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise MCPAuthzError(
                "mcp_prm_invalid",
                f"PRM document at {url} is not valid JSON",
                url=url,
            ) from exc
        if not isinstance(doc, dict):
            raise MCPAuthzError(
                "mcp_prm_invalid",
                f"PRM document at {url} is not a JSON object",
                url=url,
            )
        auth_servers = doc.get("authorization_servers")
        if not isinstance(auth_servers, list) or not auth_servers:
            raise MCPAuthzError(
                "mcp_prm_invalid",
                f"PRM document at {url} has no authorization_servers",
                url=url,
            )
        for s in auth_servers:
            if not isinstance(s, str) or not s.strip():
                raise MCPAuthzError(
                    "mcp_prm_invalid",
                    f"PRM document at {url} has malformed authorization_servers entry",
                    url=url,
                )
        scopes = doc.get("scopes_supported", [])
        if not isinstance(scopes, list) or any(not isinstance(s, str) for s in scopes):
            raise MCPAuthzError(
                "mcp_prm_invalid",
                f"PRM document at {url} has malformed scopes_supported",
                url=url,
            )
        return ResourceMetadata(
            resource=doc.get("resource", server_url),
            authorization_servers=tuple(auth_servers),
            scopes_supported=tuple(scopes),
            discovery_path=discovery_path,
        )

    async def _load_as_allowlist(self, tenant_id: str) -> frozenset[str]:
        """Resolve the per-tenant AS allow-list from Vault.

        The Vault path is interpolated from
        ``settings.mcp_as_allowlist_path`` (default
        ``secret/cognic/{tenant}/mcp-as-allowlist``). The Vault secret
        stores a list under the ``servers`` key.

        Validation posture mirrors :meth:`_fetch_prm`'s
        ``authorization_servers`` check: ANY non-string or blank entry
        in the list fails closed. Silently dropping malformed entries
        would let partially-valid security config succeed — wrong
        posture for a critical authorization boundary. Operators must
        fix the misconfiguration before admission proceeds.

        T15 R1 P2 #2: Vault read failures (path-not-found, permission
        denied, backend unreachable, schema-malformed secret) all map
        to the closed-enum ``mcp_as_not_allowlisted`` reason. Without
        the wrapping, a raw adapter exception would escape the
        registration auth-probe path (which catches only
        :class:`MCPAuthzError`) and bypass the
        ``plugin.registration_refused`` evidence path; the runtime
        path could also classify it as a generic orchestrator error
        with the wrong taxonomy. ``CancelledError`` is intentionally
        NOT caught — task cancellation should propagate.
        """
        path = self._settings.mcp_as_allowlist_path.format(tenant=tenant_id)
        try:
            secret = await self._vault.read(path)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Adapter-shape failures (path missing, permission denied,
            # backend down, malformed JSON) all map to "AS not
            # allow-listed" — the operator effect is the same: this
            # tenant has no admissible AS surface for MCP packs.
            # T15 R1 P2 #3: keep ``type(exc).__name__`` in the payload
            # so operators can diagnose without raw ``str(exc)`` text
            # in the message (lower-layer Vault adapter exceptions
            # could carry secret-looking URLs or backend debug strings).
            raise MCPAuthzError(
                "mcp_as_not_allowlisted",
                f"AS allow-list read from Vault at {path} failed",
                vault_path=path,
                tenant_id=tenant_id,
                vault_error_class=type(exc).__name__,
            ) from exc

        if not isinstance(secret, dict):
            raise MCPAuthzError(
                "mcp_as_not_allowlisted",
                f"AS allow-list secret at {path} is not a mapping",
                vault_path=path,
                tenant_id=tenant_id,
            )

        servers = secret.get("servers", [])
        if not isinstance(servers, list):
            raise MCPAuthzError(
                "mcp_as_not_allowlisted",
                f"AS allow-list at {path} is not a list of strings",
                vault_path=path,
                tenant_id=tenant_id,
            )
        for entry in servers:
            if not isinstance(entry, str) or not entry.strip():
                # The entry value comes from the operator-curated Vault
                # secret (NOT pack-controlled). Including ``entry!r`` in
                # the message is operator-actionable diagnostics, not a
                # leak risk. Distinct from the P2 #3 prohibition on raw
                # ``str(exc)`` from lower-layer exceptions.
                raise MCPAuthzError(
                    "mcp_as_not_allowlisted",
                    f"AS allow-list at {path} has malformed entry {entry!r} "
                    f"(every entry must be a non-empty string)",
                    vault_path=path,
                    tenant_id=tenant_id,
                )
        return frozenset(servers)

    async def _load_oauth_credentials(self, *, tenant_id: str, as_issuer: str) -> dict[str, str]:
        """Resolve OAuth client credentials for ``(tenant, AS issuer)``
        from Vault.

        Vault path is interpolated from
        ``settings.mcp_oauth_credentials_path`` with two substitutions:
        ``{tenant}`` (tenant id) and ``{as_host}`` (the AS issuer's
        netloc, with ``:`` replaced by ``_`` so it's safe as a path
        segment).

        Vault secret shape (Sprint 5):

        - ``client_id``: registered OAuth client identifier
        - ``client_secret``: the secret itself (NEVER logged)
        - ``auth_method``: one of ``"client_secret_post"`` /
          ``"client_secret_basic"``

        Wave 2 will add ``private_key_jwt`` (with ``private_key_pem``)
        and mTLS-bound credentials.

        Raises :class:`MCPAuthzError` with reason
        ``mcp_oauth_credentials_missing`` if Vault has nothing at the
        path, the secret is missing required fields, or the
        ``auth_method`` is unsupported.
        """
        as_host = urlparse(as_issuer).netloc.replace(":", "_")
        vault_path = self._settings.mcp_oauth_credentials_path.format(
            tenant=tenant_id, as_host=as_host
        )
        try:
            secret = await self._vault.read(vault_path)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Vault read failures (path-not-found, permission denied,
            # backend unreachable) all map to credentials-missing.
            # T15 R1 P2 #3: class name in payload, raw text out of
            # message (Vault adapter exception text could carry
            # client_secret bytes or AS endpoint URLs).
            raise MCPAuthzError(
                "mcp_oauth_credentials_missing",
                f"Vault read at {vault_path} failed",
                vault_path=vault_path,
                tenant_id=tenant_id,
                as_issuer=as_issuer,
                vault_error_class=type(exc).__name__,
            ) from exc

        if not isinstance(secret, dict):
            raise MCPAuthzError(
                "mcp_oauth_credentials_missing",
                f"Vault secret at {vault_path} is not a mapping",
                vault_path=vault_path,
            )

        client_id = secret.get("client_id")
        client_secret = secret.get("client_secret")
        auth_method = secret.get("auth_method", "client_secret_post")

        # ``str`` AND non-empty AND non-whitespace. Whitespace-only is
        # malformed security configuration — fail closed the same way
        # the AS allow-list rejects blank entries (per R8 P2 doctrine).
        if not isinstance(client_id, str) or not client_id.strip():
            raise MCPAuthzError(
                "mcp_oauth_credentials_missing",
                f"Vault secret at {vault_path} has missing, empty, or whitespace-only client_id",
                vault_path=vault_path,
            )
        if not isinstance(client_secret, str) or not client_secret.strip():
            raise MCPAuthzError(
                "mcp_oauth_credentials_missing",
                f"Vault secret at {vault_path} has missing, empty, or "
                f"whitespace-only client_secret",
                vault_path=vault_path,
            )
        if auth_method not in ("client_secret_post", "client_secret_basic"):
            raise MCPAuthzError(
                "mcp_oauth_credentials_missing",
                f"Vault secret at {vault_path} has unsupported auth_method "
                f"{auth_method!r} (Sprint 5 supports client_secret_post + "
                f"client_secret_basic; private_key_jwt + mTLS are Wave 2)",
                vault_path=vault_path,
                auth_method=auth_method,
            )
        return {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_method": auth_method,
        }

    async def _request_token(
        self,
        *,
        as_issuer: str,
        server_url: str,
        manifest_scopes: tuple[str, ...],
        request_id: str,
        tenant_id: str,
    ) -> Token:
        """Request a token from an authorization server with RFC 8707
        resource indicator binding.

        Uses the OAuth-2.1 client-credentials grant with credentials
        loaded from Vault per ``(tenant, AS issuer)`` (see
        :meth:`_load_oauth_credentials`). Supports
        ``client_secret_post`` (credentials in form body) and
        ``client_secret_basic`` (credentials in HTTP Basic header).
        Wave 2 adds ``private_key_jwt`` + mTLS-bound credentials.

        After parsing the granted scope set from the AS response, this
        method asserts ``granted_scopes ⊆ manifest_scopes`` and fails
        closed with ``mcp_token_scope_overgrant`` otherwise — keeps
        the no-silent-privilege-widening doctrine intact even when the
        AS is allow-listed but misconfigured / compromised.
        """
        # Step 0: resolve OAuth client credentials from Vault. Done
        # FIRST so a missing-credentials registration never reaches the
        # AS (operator sees the closed-enum error before any network).
        creds = await self._load_oauth_credentials(tenant_id=tenant_id, as_issuer=as_issuer)
        client_id = creds["client_id"]
        client_secret = creds["client_secret"]
        auth_method = creds["auth_method"]

        # Step 1: AS-discovery via its issuer well-known.
        timeout = self._settings.mcp_oauth_request_timeout_s
        as_metadata_url = f"{as_issuer.rstrip('/')}/.well-known/oauth-authorization-server"
        # Leg 4 (PR-2a): SSRF-guard the AS-metadata discovery URL before the GET.
        await self._refuse_non_public_discovery_url(as_metadata_url, leg="as_metadata")
        try:
            discovery_resp = await self._http.get(as_metadata_url, timeout=timeout)
        except httpx.TimeoutException as exc:
            raise MCPAuthzError(
                "mcp_oauth_request_timeout",
                f"AS discovery to {as_issuer} exceeded {timeout}s",
                as_issuer=as_issuer,
            ) from exc
        except httpx.RequestError as exc:
            # T15 R1 P2 #3: class name in payload, raw text out of message.
            raise MCPAuthzError(
                "mcp_oauth_transport_failure",
                f"AS discovery to {as_issuer} failed at transport layer",
                as_issuer=as_issuer,
                transport_error_class=type(exc).__name__,
            ) from exc
        if discovery_resp.status_code != 200:
            raise MCPAuthzError(
                "mcp_oauth_as_discovery_invalid",
                f"AS {as_issuer} discovery returned {discovery_resp.status_code}",
                as_issuer=as_issuer,
                status_code=discovery_resp.status_code,
            )
        try:
            discovery_doc = discovery_resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise MCPAuthzError(
                "mcp_oauth_as_discovery_invalid",
                f"AS {as_issuer} discovery document is not valid JSON",
                as_issuer=as_issuer,
            ) from exc
        token_endpoint = discovery_doc.get("token_endpoint")
        if not isinstance(token_endpoint, str) or not token_endpoint:
            raise MCPAuthzError(
                "mcp_oauth_as_discovery_invalid",
                f"AS {as_issuer} discovery has no token_endpoint",
                as_issuer=as_issuer,
            )

        # Step 2: token request — credentials in body OR Basic header
        # depending on auth_method. RFC 8707 resource indicator on
        # every request.
        body: dict[str, str] = {
            "grant_type": "client_credentials",
            "scope": " ".join(manifest_scopes),
            "resource": server_url,
        }
        headers: dict[str, str] = {}
        if auth_method == "client_secret_post":
            body["client_id"] = client_id
            body["client_secret"] = client_secret
        else:  # client_secret_basic
            # RFC 6749 §2.3.1: "the client identifier and the client
            # password are encoded using the
            # ``application/x-www-form-urlencoded`` encoding algorithm
            # … and then encoded using base64". A raw
            # ``client_id:client_secret`` concatenation is incorrect for
            # any secret containing ':', '+', '/', '=', spaces, or other
            # reserved characters — the AS would parse the wrong
            # boundaries.
            #
            # ``quote_plus`` (NOT ``quote``) is the right primitive:
            # ``application/x-www-form-urlencoded`` encodes spaces as
            # ``+`` (per the form-encoding spec), and ``quote_plus``
            # mirrors that. ``quote(safe="")`` would encode space as
            # ``%20``, which is correct percent-encoding but the wrong
            # *form* per the cited RFC. Real Vault-issued secrets do
            # contain spaces (some operators paste passphrases), so
            # this distinction is load-bearing.
            encoded_id = quote_plus(client_id)
            encoded_secret = quote_plus(client_secret)
            basic_credentials = base64.b64encode(f"{encoded_id}:{encoded_secret}".encode()).decode()
            headers["Authorization"] = f"Basic {basic_credentials}"

        try:
            token_resp = await self._http.post(
                token_endpoint,
                data=body,
                headers=headers,
                timeout=timeout,
            )
        except httpx.TimeoutException as exc:
            raise MCPAuthzError(
                "mcp_oauth_request_timeout",
                f"token request to {token_endpoint} exceeded {timeout}s",
                token_endpoint=token_endpoint,
            ) from exc
        except httpx.RequestError as exc:
            # T15 R1 P2 #3: class name in payload, raw text out of
            # message — token-request paths carry HTTP Basic credentials
            # in the Authorization header, so any leak risk in an
            # exception message is acutely sensitive.
            raise MCPAuthzError(
                "mcp_oauth_transport_failure",
                f"token request to {token_endpoint} failed at transport layer",
                token_endpoint=token_endpoint,
                transport_error_class=type(exc).__name__,
            ) from exc

        if token_resp.status_code != 200:
            # Token endpoint non-200 — distinct from PRM-invalid: a
            # 401 here typically means rejected client credentials
            # (Vault-stored client_id/client_secret wrong / revoked /
            # expired client registration), 400 means invalid_grant /
            # invalid_scope (caller supplied unsupported scope), 503
            # means AS down. Operators debug each differently. Payload
            # carries status_code + token_endpoint + as_issuer; NEVER
            # the response body (could echo credentials or AS-side
            # debug strings).
            raise MCPAuthzError(
                "mcp_oauth_token_endpoint_error",
                f"token endpoint {token_endpoint} returned {token_resp.status_code}",
                as_issuer=as_issuer,
                token_endpoint=token_endpoint,
                status_code=token_resp.status_code,
            )

        try:
            payload = token_resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise MCPAuthzError(
                "mcp_oauth_token_response_invalid",
                f"token response from {token_endpoint} is not valid JSON",
                as_issuer=as_issuer,
                token_endpoint=token_endpoint,
            ) from exc

        access_token = payload.get("access_token")
        raw_expires_in = payload.get("expires_in", 3600)
        # Sentinel-distinguished get: absent ``scope`` field defaults
        # to the requested scopes per OAuth 2.1 §3.2.3 ("if the scope
        # is identical to the scope requested by the client, the
        # authorization server MAY omit the ``scope`` parameter"). A
        # PRESENT-but-non-string ``scope`` (null, list, object) is
        # malformed and MUST fail closed with the
        # ``mcp_oauth_token_response_invalid`` reason (R11 P2 split
        # this off from the general ``mcp_prm_invalid`` bucket — a bad
        # AS token-response is operationally distinct from a bad MCP
        # PRM document). Without the sentinel, the prior
        # ``payload.get("scope", " ".join(...))`` silently substituted
        # manifest_scopes for any non-string value, bypassing the
        # overgrant check entirely.
        raw_scope = payload.get("scope", _SCOPE_ABSENT)
        if not isinstance(access_token, str) or not access_token:
            raise MCPAuthzError(
                "mcp_oauth_token_response_invalid",
                f"token response from {token_endpoint} has no access_token",
                as_issuer=as_issuer,
                token_endpoint=token_endpoint,
            )

        # Defensive parse of expires_in. RFC 6749 says it's a positive
        # integer "number of seconds"; in the wild some AS's emit it as
        # a string ("3600"), null, or a float. Catch every shape; fail
        # closed with the closed-enum error rather than letting a raw
        # ValueError / NaN escape from ``time.time() + float(...)``.
        #
        # Three boundary cases beyond plain TypeError/ValueError:
        #   1. ``bool`` is a subclass of ``int`` so ``float(True) == 1.0``
        #      — accept that and you cache a 1-second token on every
        #      ``True`` answer; reject explicitly.
        #   2. ``float("nan")`` and ``float("Infinity")`` parse cleanly
        #      but are non-finite. ``time.time() + nan`` is ``nan``;
        #      ``_is_token_near_expiry`` then compares ``time.time() +
        #      buffer >= nan`` which is ``False`` for any time, so the
        #      token would be cached forever and never refresh. Reject
        #      with ``math.isfinite``.
        #   3. ``float("Infinity")`` would also defeat the TTL cap (the
        #      ``min(inf, ttl)`` is fine but every other arithmetic
        #      site downstream assumes finite seconds). Reject too.
        if isinstance(raw_expires_in, bool):
            raise MCPAuthzError(
                "mcp_oauth_token_response_invalid",
                f"token response from {token_endpoint} has bool expires_in "
                f"{raw_expires_in!r} (RFC 6749 requires positive integer)",
                as_issuer=as_issuer,
                token_endpoint=token_endpoint,
            )
        try:
            expires_in_s = float(raw_expires_in)
        except (TypeError, ValueError) as exc:
            raise MCPAuthzError(
                "mcp_oauth_token_response_invalid",
                f"token response from {token_endpoint} has non-numeric "
                f"expires_in {raw_expires_in!r}",
                as_issuer=as_issuer,
                token_endpoint=token_endpoint,
            ) from exc
        if not math.isfinite(expires_in_s):
            raise MCPAuthzError(
                "mcp_oauth_token_response_invalid",
                f"token response from {token_endpoint} has non-finite "
                f"expires_in {raw_expires_in!r} (NaN / Infinity rejected)",
                as_issuer=as_issuer,
                token_endpoint=token_endpoint,
            )
        if expires_in_s <= 0:
            raise MCPAuthzError(
                "mcp_oauth_token_response_invalid",
                f"token response from {token_endpoint} has non-positive expires_in {expires_in_s}",
                as_issuer=as_issuer,
                token_endpoint=token_endpoint,
            )
        # Cap effective expiry by the operator-set cache TTL. Without
        # this cap, an AS-set ``expires_in`` of e.g. 24h would override
        # tenant policy ("refresh tokens at most every hour"). The
        # cache TTL is the operator's contract, so it wins on the
        # ``min``. ``settings.mcp_oauth_token_cache_ttl_s`` is gt=0 by
        # field validator, so the min is always positive.
        ttl_cap_s = float(self._settings.mcp_oauth_token_cache_ttl_s)
        effective_expires_in_s = min(expires_in_s, ttl_cap_s)

        # Step 3: scope-overgrant check (no-silent-privilege-widening
        # doctrine). The AS may NOT promote scopes the manifest didn't
        # declare. If the granted set is wider than the requested set,
        # fail closed BEFORE caching/returning the token.
        #
        # Three-way scope handling:
        #   - absent (sentinel ``_SCOPE_ABSENT``): default to requested
        #     manifest_scopes per OAuth 2.1 §3.2.3.
        #   - string: split on whitespace (RFC 6749 form).
        #   - anything else (null, list, dict, number, bool): malformed
        #     → ``mcp_oauth_token_response_invalid``.
        if raw_scope is _SCOPE_ABSENT:
            granted_scopes: tuple[str, ...] = tuple(manifest_scopes)
        elif isinstance(raw_scope, str):
            granted_scopes = tuple(raw_scope.split())
        else:
            raise MCPAuthzError(
                "mcp_oauth_token_response_invalid",
                f"token response from {token_endpoint} has non-string "
                f"scope {raw_scope!r} (RFC 6749 requires a "
                f"space-separated string)",
                as_issuer=as_issuer,
                token_endpoint=token_endpoint,
            )
        manifest_set = frozenset(manifest_scopes)
        granted_set = frozenset(granted_scopes)
        overgrant = granted_set - manifest_set
        if overgrant:
            raise MCPAuthzError(
                "mcp_token_scope_overgrant",
                f"AS {as_issuer} granted scopes {sorted(overgrant)} that are "
                f"NOT in the manifest-declared set {sorted(manifest_set)}. "
                f"AgentOS does not permit silent privilege widening — token "
                f"discarded; registration / call refused.",
                as_issuer=as_issuer,
                manifest_scopes=sorted(manifest_set),
                granted_scopes=sorted(granted_set),
                overgrant_scopes=sorted(overgrant),
            )

        return Token(
            value=access_token,
            expires_at=time.time() + effective_expires_in_s,
            as_issuer=as_issuer,
            scopes=granted_scopes,
            resource_indicator=server_url,
            client_id=client_id,
        )


def _parse_resource_metadata_url(www_authenticate: str) -> str | None:
    """Extract the ``resource_metadata="<url>"`` parameter from a
    ``WWW-Authenticate: Bearer …`` header.

    Returns the URL if present, ``None`` if the header is missing or
    has no ``resource_metadata`` parameter. Tolerates extra whitespace
    + parameter ordering variation.
    """
    if not www_authenticate or "Bearer" not in www_authenticate:
        return None
    # Find the resource_metadata="..." substring
    needle = 'resource_metadata="'
    idx = www_authenticate.find(needle)
    if idx == -1:
        return None
    start = idx + len(needle)
    end = www_authenticate.find('"', start)
    if end == -1:
        return None
    return www_authenticate[start:end]


def _is_token_near_expiry(token: Token) -> bool:
    """True if the token expires within :data:`_TOKEN_REFRESH_BUFFER_S`
    seconds. Used by the cache-lookup path."""
    return time.time() + _TOKEN_REFRESH_BUFFER_S >= token.expires_at


def _validate_token_audience(token: Token, *, expected_audience: str) -> None:
    """Validate the token's ``aud`` claim matches the expected
    audience (the MCP server's resource indicator).

    For JWT tokens, decodes the payload (without signature
    verification — the AS already verified the signature; we re-decode
    only for the audience check). For opaque tokens, trusts the AS's
    RFC 8707 binding (non-JWT tokens are validated by the resource
    server, not here).

    Raises :class:`MCPAuthzError` with reason
    ``mcp_token_audience_mismatch`` on mismatch.
    """
    payload = _decode_jwt_payload(token.value)
    if not payload:
        # Non-JWT (opaque token) — trust the AS's RFC 8707 binding
        return
    aud = payload.get("aud")
    if aud is None:
        raise MCPAuthzError(
            "mcp_token_audience_mismatch",
            f"token from {token.as_issuer} has no aud claim",
            as_issuer=token.as_issuer,
            expected_audience=expected_audience,
        )
    # aud may be a string or a list of strings per RFC 7519
    aud_list = [aud] if isinstance(aud, str) else (aud if isinstance(aud, list) else [])
    if expected_audience not in aud_list:
        raise MCPAuthzError(
            "mcp_token_audience_mismatch",
            f"token aud claim {aud_list} does not include expected audience {expected_audience!r}",
            as_issuer=token.as_issuer,
            expected_audience=expected_audience,
            actual_audiences=aud_list,
        )
