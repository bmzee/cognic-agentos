"""MCPHost orchestrator for Sprint-5 runtime MCP traffic.

Critical-controls module per AGENTS.md. The MCPHost is the runtime
boundary that turns a registered MCP pack + a tool invocation into an
authenticated SDK-backed session round-trip plus the audit /
decision-history evidence rows that examiners replay.

Sprint-5 R3 P1 doctrine: ``MCPHost`` is one of the two classes (with
``StreamableHTTPTransport``) that genuinely consumes the ``mcp`` SDK
at runtime, so its constructor calls :func:`require_mcp` — kernel-
image-equivalent venvs MUST fail loudly with
:class:`MCPNotAvailableError` rather than silently degrading.

R1 P2 amendments (post-T9-initial):

  - **R1 P2 #1**: ``transport_kind`` accepts the spec-canonical
    ``"streamable-http"`` as well as the legacy ``"http"``. Both
    refer to the same canonical HTTP transport family per
    :data:`cognic_agentos.protocol.mcp_capabilities._HTTP_TRANSPORT_VALUES`
    — operators wire ONE physical transport under EITHER key and the
    host normalises the dispatch lookup. Without this, T6 admits
    spec-correct ``streamable-http`` packs that then fail at
    MCPHost startup unless every operator duplicates the transport
    under both keys.

  - **R1 P2 #2**: ``list_tools`` cache key includes ``tenant_id``
    plus the requested scope set, NOT just ``server_id``. Otherwise
    tenant A warming the cache lets tenant B receive the tool
    catalogue without ``authz.acquire_token`` running — bypassing
    the per-tenant AS allow-list check. Cached values are also
    returned as fresh copies so a caller can't mutate the internal
    list and silently affect every later read.

  - **R1 P2 #3**: ``call_tool`` implements the auth retry semantics
    per ADR-002 + plan §T9. 401 / 403 ``invalid_token`` triggers
    drop-cached-token + reacquire + retry-once (second 401 →
    ``mcp_authorisation_lost``). 403 ``insufficient_scope`` triggers
    ``authz.step_up_token`` with the requested wider scope; if the
    step-up succeeds the call retries with the new token, and
    ``mcp_step_up_unauthorised`` propagates from
    :meth:`MCPAuthzClient.step_up_token` unchanged (T5's existing
    audit machinery emits the row from inside the authz client).

Doctrinal scope-decisions for T9:

  1. **``servers`` parameter is a typed Mapping[str, MCPServerEntry],
     not the raw PluginRegistry.** Decoupling MCPHost from
     plugin_registry's internals avoids touching a critical-controls
     module in T9. The portal lifespan code populates the mapping
     from the registry walk + per-pack MCP manifest extraction.

  2. **Audit emission ownership is split across T9 / T10 / T11.**
     T9 wires the constructor-required deps (``audit_store``,
     ``decision_history_store``) and emits ONLY the close-failure
     tolerance audit row (``audit.mcp_session_close_failed`` with
     ``failure_class`` ∈ {``"transport"``, ``"hook"``}). T9 RAISES
     the closed-enum ``MCPAuthzError("mcp_authorisation_lost")``
     from the ``call_tool`` second-401-retry exhaustion path
     (R1 P2 #3) but does NOT emit a corresponding audit row.

     **T10 (this commit) emits ``audit.tool_invocation_refused``
     directly** for the ADR-014 transitional high-risk-tier gate
     — payload ``{server_id, tool_name, declared_risk_tier,
     refusal_reason: "tool_approval_engine_not_available",
     sprint_13_5_followup: True}`` — BEFORE raising
     :class:`MCPToolInvocationRefused`. Audit-pipeline failure
     does not mask the refusal.

     T11 expands the audit + decision-history surface with:
     ``audit.tool_invocation`` (every successful call_tool);
     ``audit.tool_invocation_error`` (call dispatched but failed —
     including ``mcp_authorisation_lost`` from the T9 second-401
     path AND the auth/transport closed-enum errors); the parallel
     ``decision_history`` rows (per MCP-CONFORMANCE.md
     §observability item 9). T11 MUST NOT duplicate the T10
     refusal row — both are ``audit.tool_invocation_refused``,
     but T10 owns the ADR-014 transitional path; T11 will own the
     other refusal classes (capability validator outcomes the
     orchestrator surfaces, future approval-engine outcomes from
     Sprint 13.5).
"""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import hashlib
import logging
import re
import time
from collections.abc import Mapping
from typing import Any, Literal

import httpx

from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore
from cognic_agentos.protocol import require_mcp
from cognic_agentos.protocol.mcp_authz import MCPAuthzClient, MCPAuthzError, Token
from cognic_agentos.protocol.mcp_transports import (
    MCPSession,
    MCPToolCallRequest,
    MCPTransport,
    MCPTransportError,
)

_LOG = logging.getLogger("cognic_agentos.protocol.mcp_host")

#: TTL multiplier applied to ``settings.mcp_call_tool_timeout_s`` to
#: derive the ``list_tools`` cache TTL. Per plan §T9 step 5.
_LIST_TOOLS_CACHE_TTL_MULTIPLIER = 5

#: Hard cap on the number of pages :meth:`MCPHost.list_tools` walks
#: before failing with ``mcp_transport_send_failed`` /
#: ``pagination_failure="cap_exceeded"``. R4 P2 #1 — defensive bound
#: against runaway / malicious server pagination. Cycle detection
#: (repeated cursor) catches the most common case; the page cap is
#: the catch-all for unbounded distinct cursors that cycle detection
#: would not flag. 100 is generous (a 100-page tool catalogue is
#: already excessive) but allows real-world packs room. Bumping
#: requires explicit Sprint-N review — pinned by a regression test.
_MAX_LIST_TOOLS_PAGES = 100

#: HTTP transport family — ``"http"`` (legacy) and ``"streamable-http"``
#: (spec-canonical name per the MCP authorization spec) refer to the
#: same physical transport. Mirrors
#: :data:`cognic_agentos.protocol.mcp_capabilities._HTTP_TRANSPORT_VALUES`.
#: R1 P2 #1: T6 admits packs declaring either name; T9's transport
#: lookup MUST treat both as the same canonical key.
_HTTP_TRANSPORT_KINDS: frozenset[str] = frozenset({"http", "streamable-http"})

#: STDIO is the other family; trivially a single value today, kept as
#: a frozenset for symmetry with the HTTP family + future extension.
_STDIO_TRANSPORT_KINDS: frozenset[str] = frozenset({"stdio"})

#: **Canonical allow-list** of every transport-kind string MCPHost will
#: accept. R2 P2 #1: pinned to the union of the two known families.
#: Pack manifests + operator wiring data are typed as plain ``str`` at
#: the boundary, so the ``TransportKind`` Literal alone does NOT
#: protect runtime data — the constructor uses this set to fail-loud
#: on unknown kinds at startup. T6's capability validator emits
#: ``mcp_transport_unsupported`` for the same allow-list at the
#: registration boundary; this set is the runtime-side fence.
#:
#: **Adding a new transport family is a Sprint-N task** that explicitly
#: extends this set + lands the corresponding transport implementation
#: + amends T6. Do not silently add values here.
_KNOWN_TRANSPORT_KINDS: frozenset[str] = _HTTP_TRANSPORT_KINDS | _STDIO_TRANSPORT_KINDS

TransportKind = Literal["http", "streamable-http", "stdio"]


#: Length of the SHA-256-prefix fingerprint emitted for repeated
#: pagination cursors. 16 hex chars = 64 bits — collision probability
#: across a single operator's debug session is effectively zero, while
#: the truncated form is short enough to read in a log line and short
#: enough to defeat trivial rainbow-table reversal of well-known
#: cursor schemes (the full sha256 of a known opaque scheme could
#: still be replayed against a precomputed table; the truncation
#: discards enough entropy that a precomputed table is unlikely to
#: contain a matching prefix for arbitrary cursors).
_CURSOR_FINGERPRINT_LEN = 16


def _fingerprint_cursor(cursor: str) -> str:
    """Return a non-reversible short fingerprint of an opaque MCP
    pagination cursor.

    Used by :meth:`MCPHost.list_tools`'s cycle-detection raise (R5
    P2) so the error payload that flows into T11 audit / operator
    logs never carries the verbatim cursor — cursors are server-
    controlled continuation tokens that may encode internal session
    state, query offsets, or signed payloads operators MUST NOT see.
    A short SHA-256 hex prefix is enough to correlate repeat
    occurrences of the SAME bug (same cursor → same fingerprint)
    without exposing what the server put in the cursor.
    """
    digest = hashlib.sha256(cursor.encode("utf-8")).hexdigest()
    return digest[:_CURSOR_FINGERPRINT_LEN]


def _canonicalize_transport_kind(kind: str) -> str:
    """Map every accepted transport-kind string to its canonical
    family key.

    HTTP family (``"http"`` legacy, ``"streamable-http"`` spec-
    canonical) → ``"http"``. STDIO → ``"stdio"``. Unknown values are
    returned unchanged so the constructor's allow-list check can flag
    them with a useful error message rather than silently masking the
    bad input — but the constructor's
    :data:`_KNOWN_TRANSPORT_KINDS` allow-list is the load-bearing
    fence; this helper does NOT decide acceptance.
    """
    if kind in _HTTP_TRANSPORT_KINDS:
        return "http"
    if kind in _STDIO_TRANSPORT_KINDS:
        return "stdio"
    return kind


@dataclasses.dataclass(frozen=True, slots=True)
class MCPServerEntry:
    """Registered MCP pack metadata MCPHost needs to dispatch a call.

    Populated by the portal lifespan code at startup from the plugin
    registry walk + per-pack ``[tool.cognic.mcp]`` block extraction.
    Frozen + slotted so the orchestrator can rely on field stability
    across the lifetime of the host (the registry is immutable post-
    startup in Sprint-4 lifecycle; Sprint-7B may extend).

    ``transport_kind`` accepts the spec-canonical
    ``"streamable-http"`` as well as the legacy ``"http"`` (R1 P2 #1):
    both dispatch through the same canonical HTTP transport family.

    Field semantics:

      - ``server_id`` — stable identifier (typically the pack
        distribution name). Examiners + audit rows correlate by this.
      - ``server_url`` — the MCP endpoint the SDK opens against.
      - ``transport_kind`` — manifest-declared transport name; the
        host normalises HTTP variants to a single canonical key.
      - ``manifest_scopes`` — least-privilege scope tuple from the
        pack manifest; passed verbatim to ``authz.acquire_token``.
      - ``risk_tier`` — read by T10's ADR-014 transitional gate.
      - ``pack_signature_digest`` — cosign signature digest, carried
        into T11's audit rows for the ``pack_id`` ↔ signature
        correlation chain.
    """

    server_id: str
    server_url: str
    transport_kind: TransportKind
    manifest_scopes: tuple[str, ...]
    risk_tier: str
    pack_signature_digest: str


@dataclasses.dataclass(frozen=True, slots=True)
class DiscoveredMCPServer:
    """Public discovery result — metadata only, no token, no session.

    Mirrors :class:`MCPServerEntry` but lives in the public discovery
    surface so the portal can return a stable shape regardless of any
    future internal field additions on ``MCPServerEntry`` (versioning
    boundary).
    """

    server_id: str
    server_url: str
    transport_kind: TransportKind
    manifest_scopes: tuple[str, ...]
    risk_tier: str


@dataclasses.dataclass(frozen=True, slots=True)
class CallResult:
    """Successful tool-invocation envelope returned by ``call_tool``.

    Carries the SDK response payload plus the correlation IDs
    examiners need to replay the invocation against the audit chain
    + decision-history rows (per MCP-CONFORMANCE.md §"Authorization"
    item 9).
    """

    payload: Any
    request_id: str
    server_id: str
    tool_name: str
    mcp_session_id: str | None
    as_issuer: str
    scopes: tuple[str, ...]
    client_id: str


@dataclasses.dataclass(slots=True)
class _CachedToolList:
    """Internal: cached ``list_tools`` result with monotonic-clock
    timestamp. Monotonic clock so TTL expiry is robust against wall-
    clock jumps (NTP / leap seconds)."""

    tools: list[Any]
    cached_at_monotonic: float


#: Sub-classification of a transport-level send error, derived by
#: walking the ``__cause__`` chain for ``httpx.HTTPStatusError``.
_AuthSignal = Literal["authz_lost", "step_up", "transport_failed"]


#: Regex for parsing the ``WWW-Authenticate: Bearer`` header to extract
#: the OAuth error + scope. Matches both ``error="..."`` and
#: ``scope="..."`` order-independently. Pinned tight enough that a
#: malformed header fails the match cleanly and falls through to the
#: generic transport-failure path.
_WWW_AUTHENTICATE_ERROR_RE = re.compile(r'error="([^"]+)"')
_WWW_AUTHENTICATE_SCOPE_RE = re.compile(r'scope="([^"]+)"')


def _classify_send_error(exc: BaseException) -> tuple[_AuthSignal, dict[str, Any]]:
    """Walk the ``__cause__`` chain looking for an
    :class:`httpx.HTTPStatusError` to classify the underlying HTTP
    response into an auth-retry signal.

    Returns ``(signal, payload)``:

      - ``("authz_lost", {})`` — 401 OR 403 with
        ``error="invalid_token"``: drop cached token, reacquire,
        retry once.
      - ``("step_up", {"requested_scope": "..."})`` — 403 with
        ``error="insufficient_scope", scope="<wider>"``: step_up via
        authz; retry with the stepped-up token if the manifest
        declares the wider scope.
      - ``("transport_failed", {})`` — anything else (no httpx
        cause, non-401/403 status, malformed WWW-Authenticate that
        we can't classify): caller propagates the original transport
        error to the caller without retry.

    The walk bounds at 16 hops so a pathologically self-referential
    exception chain can't loop forever. The bound is generous; real
    chains are typically 2-4 deep.
    """
    cur: BaseException | None = exc
    visited = 0
    while cur is not None and visited < 16:
        if isinstance(cur, httpx.HTTPStatusError):
            response = cur.response
            status_code = response.status_code
            www_auth = response.headers.get("WWW-Authenticate", "")
            if status_code == 401:
                return "authz_lost", {}
            if status_code == 403:
                error_match = _WWW_AUTHENTICATE_ERROR_RE.search(www_auth)
                error = error_match.group(1) if error_match else None
                if error == "insufficient_scope":
                    scope_match = _WWW_AUTHENTICATE_SCOPE_RE.search(www_auth)
                    if scope_match:
                        return "step_up", {"requested_scope": scope_match.group(1)}
                    # 403 insufficient_scope without a scope hint
                    # is malformed; treat as authz_lost so we at
                    # least drop the cached token + retry once.
                    return "authz_lost", {}
                if error == "invalid_token":
                    return "authz_lost", {}
                # 403 with no error= or an unknown error= falls
                # through to authz_lost — same drop+rediscover
                # remediation as the spec-named cases.
                return "authz_lost", {}
            return "transport_failed", {}
        cur = cur.__cause__
        visited += 1
    return "transport_failed", {}


#: ADR-014 §"Sprint 5 (transitional rule)" allow-list — the ONLY two
#: risk_tier values that may invoke without an approval-engine
#: sign-off. Whitelist semantics + fail-closed default: ANY other
#: declared tier (the named high-risk set OR an unknown / typo /
#: malformed value) refuses with
#: ``tool_approval_engine_not_available``. Sprint 13.5 lands the
#: approval engine and removes this gate; until then this set is
#: deliberately tight.
_ADR_014_LOW_RISK_TIERS: frozenset[str] = frozenset({"read_only", "internal_write"})

#: Maximum length of the truncated ``repr()`` emitted into the audit
#: row's ``declared_risk_tier`` field for non-string risk_tier values.
#: A pathological manifest declaring a 10-element list of 1 KB strings
#: MUST NOT produce a 10 KB audit row. Pinned by regression test.
_RISK_TIER_REPR_MAX_LEN = 200


def _sanitize_string_for_operator_surface(value: str) -> str:
    """Escape control characters + bound length for caller-supplied
    strings that flow into operator-facing surfaces (exception
    messages, warning logs).

    R4 P2 — caller-supplied strings (``tool_name``, ``request_id``,
    etc.) can carry embedded ``\\n`` / ``\\t`` / ANSI escapes / NUL
    bytes that would forge log lines, rewrite operator terminals,
    or truncate downstream viewers. Apply the same discipline as
    :func:`_normalize_risk_tier_for_gate` (``unicode_escape`` round-
    trip + ``[:_RISK_TIER_REPR_MAX_LEN]`` cap) but **without** the
    allow-list passthrough — every input is escaped + bounded. The
    raw value is preserved in the audit-row payload (T11's
    canonical-name queries depend on the unsanitised form; JSON
    canonical-form serialisation handles on-disk safety).
    """
    return value.encode("unicode_escape").decode("ascii")[:_RISK_TIER_REPR_MAX_LEN]


def _normalize_risk_tier_for_gate(value: Any) -> str:
    """Coerce a manifest-declared risk_tier into a bounded string
    suitable for the ADR-014 gate's membership check + audit row.

    R1 P2 — defense-in-depth at the orchestrator boundary.
    :class:`MCPServerEntry.risk_tier` is typed as ``str`` but the
    portal lifespan wiring populates this from manifest TOML at
    runtime; a malformed manifest declaring ``risk_tier = ["x"]``
    would, without this normalisation, raise raw ``TypeError`` from
    the membership check (``unhashable type: 'list'``) BEFORE the
    audit emit + closed-enum refusal fire. Per the T10 contract,
    malformed tiers MUST follow the same fail-closed path as unknown
    tiers — ``MCPToolInvocationRefused("tool_approval_engine_not_available")``
    + audit row carrying a sanitised representation of what was
    actually declared.

    R2 P2 — the R1 helper bounded only non-string values; long
    strings still flowed verbatim into the audit row + exception
    message + warning log. A malformed / malicious manifest
    declaring a multi-KB string risk_tier could otherwise pollute
    every operator-visible surface. Strings now also get bounded
    when they exceed :data:`_RISK_TIER_REPR_MAX_LEN`. Allow-list
    values are returned unchanged BEFORE the bounding step so the
    gate's exact-match check is preserved (and so a future
    allow-list addition with a longer name cannot be silently
    truncated below its match length).

    R3 P2 — short unknown strings used to pass through verbatim,
    enabling control-character injection: a manifest declaring
    ``"payment_action\\nINFO 2026-... auth=success"`` would forge a
    log line; ``"\\x1b[31mFAKE-ALERT\\x1b[0m"`` would rewrite
    operator terminal output via ANSI escape; ``"x\\x00y"`` would
    embed a NUL that may truncate downstream viewers. Every rejected
    string is now run through ``encode("unicode_escape")`` so
    ``\\n`` → literal ``\\\\n``, ``\\x1b`` → literal ``\\\\x1b``,
    NUL → literal ``\\\\x00``, etc. Allow-list values still pass
    through unchanged so the membership check is unaffected;
    printable-ASCII typos (``"read-only"``, ``"PAYMENT_ACTION"``)
    survive the escape transparently because they have no control
    chars to escape.

    Behaviour:

      - **Allow-list ``str``** (in :data:`_ADR_014_LOW_RISK_TIERS`)
        → returned **unchanged** (literal byte-equality preserved).
        The membership check matches.
      - **Other ``str``** → escaped via ``unicode_escape`` then
        truncated to :data:`_RISK_TIER_REPR_MAX_LEN`. Printable
        ASCII (typos) renders verbatim; control characters become
        their ``\\xNN`` / ``\\n`` / etc. escape sequences.
      - **Non-``str``** (``None``, ``list``, ``dict``, ``int``,
        ``bool``, ``float``, anything else) → ``repr(value)``
        truncated to the same cap. ``repr`` already escapes
        control chars in any embedded strings.
    """
    if isinstance(value, str):
        if value in _ADR_014_LOW_RISK_TIERS:
            return value
        # R3 P2: escape control chars BEFORE bounding so
        # log-injection / ANSI-rewrite / NUL-truncation attempts
        # are neutralised in the audit row + exception message +
        # warning log. ``encode("unicode_escape")`` round-trips
        # printable ASCII verbatim and escapes everything else.
        escaped = value.encode("unicode_escape").decode("ascii")
        return escaped[:_RISK_TIER_REPR_MAX_LEN]
    return repr(value)[:_RISK_TIER_REPR_MAX_LEN]


#: Closed-enum vocabulary for runtime tool-invocation refusals. Sprint
#: 5 ships exactly one value (the ADR-014 transitional rule); Sprint
#: 13.5 will extend with the approval-engine outcomes
#: (``tool_approval_pending``, ``tool_approval_denied``, etc.).
ToolInvocationRefusalReason = Literal["tool_approval_engine_not_available"]


class MCPToolInvocationRefused(Exception):
    """Closed-enum runtime refusal of a tool invocation by MCPHost.

    Distinct from :class:`MCPTransportError` (transport-layer
    failures) and :class:`MCPAuthzError` (auth-layer failures). This
    exception covers refusals that happen at the orchestrator layer,
    BEFORE any token / session work — currently just the ADR-014
    transitional high-risk-tier gate.

    Audit-row ownership: T10 emits ``audit.tool_invocation_refused``
    directly via :meth:`MCPHost._emit_high_risk_tier_refusal_audit`
    BEFORE raising this exception, so the refusal row is already in
    the audit chain by the time the caller sees the raise. T11 adds
    the parallel ``decision_history`` row + the OTHER invocation
    rows (``audit.tool_invocation`` for success;
    ``audit.tool_invocation_error`` for dispatch failures) but MUST
    NOT duplicate the T10 ADR-014 refusal audit row.

    Token-free + closed-enum payload, same discipline as
    ``MCPTransportError``: caller-supplied tool arguments NEVER
    appear in the payload (the refusal happens before any
    data-classification policy has run); the
    ``declared_risk_tier`` field is bounded via
    :func:`_normalize_risk_tier_for_gate` so a multi-KB malformed
    manifest can't pollute the exception message either.
    """

    def __init__(
        self,
        reason: ToolInvocationRefusalReason,
        message: str = "",
        **payload: Any,
    ) -> None:
        self.reason: ToolInvocationRefusalReason = reason
        self.payload: dict[str, Any] = payload
        super().__init__(f"{reason}: {message}" if message else reason)


class MCPHost:
    """Sprint-5 MCP orchestrator: discover servers, list tools, dispatch
    tool calls.

    Construction is fail-loud on a kernel-image-equivalent venv (per
    R3 P1 doctrine — :func:`require_mcp` raises if the ``mcp`` SDK is
    not installed). Servers + transports + audit/decision-history
    stores are constructor-required so the host's invariants are
    established at startup, not on first invocation.
    """

    def __init__(
        self,
        *,
        servers: Mapping[str, MCPServerEntry],
        transports: Mapping[str, MCPTransport],
        authz: MCPAuthzClient,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        settings: Settings,
    ) -> None:
        require_mcp()

        # R2 P2 #1: reject unknown transport-mapping keys at startup
        # — TransportKind Literal does NOT protect runtime data
        # (operator config / pack manifests are plain str at the
        # boundary). Pinning the allow-list here is the runtime-side
        # fence that mirrors T6's mcp_transport_unsupported refusal
        # at the registration boundary. Adding a new family is a
        # Sprint-N task that MUST extend _KNOWN_TRANSPORT_KINDS.
        for raw_key in transports:
            if raw_key not in _KNOWN_TRANSPORT_KINDS:
                raise ValueError(
                    f"transports mapping carries unknown key "
                    f"{raw_key!r}; allowed values: "
                    f"{sorted(_KNOWN_TRANSPORT_KINDS)!r}. AgentOS "
                    f"does not support this transport family. Adding "
                    f"a new family requires a Sprint-N task that "
                    f"explicitly extends _KNOWN_TRANSPORT_KINDS + "
                    f"lands the transport implementation + amends T6's "
                    f"capability validator. Refusing to silently "
                    f"dispatch through an unreviewed transport."
                )

        # R1 P2 #1: build a canonical-key view of the transports
        # mapping so callers can wire ONE physical HTTP transport
        # under either ``"http"`` or ``"streamable-http"`` and dispatch
        # works for both transport_kind values.
        self._transports_by_canonical: dict[str, MCPTransport] = {}
        for raw_key, transport in transports.items():
            canonical = _canonicalize_transport_kind(raw_key)
            # If the operator wired both keys for the HTTP family,
            # the second one wins — but we warn so a mismatch
            # (different physical transports under the two keys) is
            # operator-visible at startup.
            if canonical in self._transports_by_canonical:
                _LOG.warning(
                    "MCPHost transports mapping has duplicate entries "
                    "for the canonical %s family (raw key %s overrides "
                    "previously-registered entry); operators should "
                    "wire ONE physical transport per canonical family.",
                    canonical,
                    raw_key,
                )
            self._transports_by_canonical[canonical] = transport

        # R2 P2 #1: every server's transport_kind MUST be in the same
        # allow-list (the transports check above pins the wiring
        # side; this pins the manifest/server-entry side).
        # Validate every server's transport_kind has a corresponding
        # transport in the canonicalised view. Misconfiguration MUST
        # surface at startup, not on first call_tool.
        for server_id, entry in servers.items():
            if entry.transport_kind not in _KNOWN_TRANSPORT_KINDS:
                raise ValueError(
                    f"server {server_id!r} declares "
                    f"transport_kind={entry.transport_kind!r} which is "
                    f"not in the canonical allow-list "
                    f"{sorted(_KNOWN_TRANSPORT_KINDS)!r}. AgentOS does "
                    f"not support this transport family. T6's capability "
                    f"validator should have refused this pack at "
                    f"registration with mcp_transport_unsupported; "
                    f"this fence catches any path that bypassed T6 "
                    f"(e.g., a future bug or a mis-routed wiring)."
                )
            canonical = _canonicalize_transport_kind(entry.transport_kind)
            if canonical not in self._transports_by_canonical:
                raise ValueError(
                    f"server {server_id!r} declares "
                    f"transport_kind={entry.transport_kind!r} "
                    f"(canonical={canonical!r}) but no matching "
                    f"transport is configured. Available canonical "
                    f"transport families: "
                    f"{sorted(self._transports_by_canonical)!r}. Wire "
                    f"the transport at MCPHost construction or remove "
                    f"the server from the registry."
                )

        # Snapshot to plain dict so callers can't mutate after
        # construction.
        self._servers: dict[str, MCPServerEntry] = dict(servers)
        self._authz = authz
        self._audit_store = audit_store
        self._decision_history_store = decision_history_store
        self._settings = settings
        # R1 P2 #2: cache key includes tenant_id + scopes (NOT just
        # server_id). Cross-tenant cache leak would let tenant B
        # receive tenant A's already-cleared tool catalogue without
        # tenant B's per-tenant AS allow-list ever firing.
        self._list_tools_cache: dict[tuple[str, str, tuple[str, ...]], _CachedToolList] = {}
        self._list_tools_cache_lock = asyncio.Lock()

    @property
    def _list_tools_cache_ttl_s(self) -> float:
        return float(self._settings.mcp_call_tool_timeout_s) * _LIST_TOOLS_CACHE_TTL_MULTIPLIER

    def _resolve_transport(self, entry: MCPServerEntry) -> MCPTransport:
        canonical = _canonicalize_transport_kind(entry.transport_kind)
        return self._transports_by_canonical[canonical]

    # --- discovery ---------------------------------------------------------

    async def discover_servers(self) -> list[DiscoveredMCPServer]:
        """Return metadata for every registered MCP server.

        Pure read — no token acquisition, no session opened, no audit
        row. Per plan §T9: 'walks the plugin registry for packs with
        [tool.cognic.mcp] blocks; returns metadata only'.

        Order is insertion-stable (the underlying dict preserves
        construction order) so the portal can render a deterministic
        listing under repeat reads.
        """
        return [
            DiscoveredMCPServer(
                server_id=entry.server_id,
                server_url=entry.server_url,
                transport_kind=entry.transport_kind,
                manifest_scopes=entry.manifest_scopes,
                risk_tier=entry.risk_tier,
            )
            for entry in self._servers.values()
        ]

    # --- list_tools ---------------------------------------------------------

    async def list_tools(
        self,
        *,
        server_id: str,
        request_id: str,
        tenant_id: str,
    ) -> list[Any]:
        """Acquire token → open session → SDK list_tools → close →
        return cached result.

        Per plan §T9 step 5: cache TTL = ``settings.mcp_call_tool_
        timeout_s * 5`` per (tenant_id, server_id, scopes). R1 P2
        #2: tenant_id MUST be in the cache key so per-tenant AS
        allow-list checks fire on every tenant's first call. Cached
        entries skip every downstream side effect (no token, no
        session). Close failures are audit-logged but do not fail
        the result.
        """
        entry = self._lookup_server(server_id)
        cache_key = (tenant_id, server_id, entry.manifest_scopes)

        async with self._list_tools_cache_lock:
            cached = self._list_tools_cache.get(cache_key)
            if cached is not None:
                age = time.monotonic() - cached.cached_at_monotonic
                if age < self._list_tools_cache_ttl_s:
                    # R1 P2 #2 + R2 P2 #2: ``list(cached.tools)`` only
                    # protects the OUTER list; the inner descriptor
                    # objects (dict / list / nested) are still
                    # references the caller could mutate to poison
                    # every later cached read for this
                    # (tenant_id, server_id, scopes) tuple. Deep-copy
                    # on read so the cache is fully isolated from
                    # caller-side mutation. Combined with the deep-
                    # copy on write below, two consecutive callers
                    # also get independent descriptor instances.
                    return copy.deepcopy(cached.tools)

        transport = self._resolve_transport(entry)
        token = await self._authz.acquire_token(
            server_url=entry.server_url,
            manifest_scopes=entry.manifest_scopes,
            request_id=request_id,
            tenant_id=tenant_id,
        )
        session = await transport.open_session(server_url=entry.server_url, token=token)
        try:
            # R3 P1: SDK ``ClientSession.list_tools`` returns
            # :class:`mcp.types.ListToolsResult` (Pydantic), NOT a
            # bare list. ``list(result)`` on a Pydantic model yields
            # field tuples like ``[('meta', None), ('nextCursor',
            # None), ('tools', [...])]`` — completely wrong shape.
            # Normalize via ``result.tools`` and loop on
            # ``result.nextCursor`` so paginated catalogues are fully
            # walked. _normalize_list_tools_page also accepts a bare
            # list (test-mock back-compat shim).
            #
            # R4 P2 #1: pagination MUST be bounded. A buggy / malicious
            # server can return the same non-empty cursor forever or
            # an unbounded distinct-cursor sequence; the SDK per-call
            # timeout never fires if the server returns each page
            # quickly. Track ``seen_cursors`` for cycle detection +
            # cap pages at ``_MAX_LIST_TOOLS_PAGES``.
            #
            # R4 P2 #2: the SDK call itself is wrapped via
            # :meth:`_safe_sdk_list_tools`, which maps timeouts /
            # generic SDK exceptions to closed-enum
            # :class:`MCPTransportError` reasons (matching T7's
            # send-error taxonomy) so failures land in the same audit
            # shape as ``call_tool``.
            all_tools: list[Any] = []
            cursor: str | None = None
            seen_cursors: set[str] = set()
            for _page_idx in range(_MAX_LIST_TOOLS_PAGES):
                if cursor is not None:
                    if cursor in seen_cursors:
                        # R5 P2: NEVER put the verbatim cursor in
                        # the closed-enum payload — MCP pagination
                        # cursors are opaque server-controlled
                        # continuation tokens; T11 will pipe this
                        # payload into ``audit.tool_invocation_error``
                        # rows + operator logs. A non-reversible
                        # fingerprint + length is enough for operators
                        # to correlate repeat occurrences without
                        # leaking the cursor itself.
                        raise MCPTransportError(
                            "mcp_transport_send_failed",
                            "list_tools pagination cycle detected — "
                            "server returned a cursor it had already "
                            "returned",
                            server_url=entry.server_url,
                            pagination_failure="cycle_detected",
                            cursor_repeated_fingerprint=_fingerprint_cursor(cursor),
                            cursor_repeated_length=len(cursor),
                            pages_walked=len(seen_cursors),
                        )
                    seen_cursors.add(cursor)
                page = await self._safe_sdk_list_tools(session=session, cursor=cursor)
                page_tools, next_cursor = self._normalize_list_tools_page(page)
                all_tools.extend(page_tools)
                if not next_cursor:
                    break
                cursor = next_cursor
            else:
                # Loop ran the full cap without ``break`` (i.e., the
                # server kept handing us a fresh non-empty cursor on
                # every page up to and including page _MAX_LIST_TOOLS_PAGES).
                # Defensive fence — cycle detection above caught the
                # repeated-cursor case; this catches unbounded
                # distinct cursors.
                raise MCPTransportError(
                    "mcp_transport_send_failed",
                    f"list_tools pagination exceeded the "
                    f"{_MAX_LIST_TOOLS_PAGES}-page cap without the "
                    f"server signalling exhaustion",
                    server_url=entry.server_url,
                    pagination_failure="cap_exceeded",
                    pages_walked=_MAX_LIST_TOOLS_PAGES,
                )
        finally:
            await self._best_effort_close(
                transport=transport,
                session=session,
                server_id=server_id,
                request_id=request_id,
                tenant_id=tenant_id,
                operation="list_tools",
            )

        async with self._list_tools_cache_lock:
            # R2 P2 #2: deep-copy on cache WRITE so the cache is
            # isolated from any later mutation of the SDK response
            # object (the SDK or a transport-level cache could hold
            # a reference and mutate it after the orchestrator
            # received it). Combined with the deep-copy on read above,
            # this gives the cache full isolation in both directions.
            self._list_tools_cache[cache_key] = _CachedToolList(
                tools=copy.deepcopy(all_tools),
                cached_at_monotonic=time.monotonic(),
            )
        # Returned tools are also fresh — deep-copy a SECOND time so
        # the value the immediate caller mutates is not the same
        # instance the cache stored.
        return copy.deepcopy(all_tools)

    async def _safe_sdk_list_tools(
        self,
        *,
        session: MCPSession,
        cursor: str | None,
    ) -> Any:
        """Wrap ``session.sdk_session.list_tools`` with the same
        closed-enum error taxonomy T7's
        :meth:`StreamableHTTPTransport.send` uses (R4 P2 #2).

        The real MCP SDK can raise ``asyncio.TimeoutError`` (slow
        response), ``mcp.shared.exceptions.McpError`` (JSON-RPC
        server-side error), or generic transport exceptions.
        Calling the SDK directly without wrapping leaks raw SDK
        exceptions to the caller, bypassing the closed-enum taxonomy
        and (more critically) potentially leaking server-side debug
        strings or token bytes via ``str(exc)`` propagation.

        Mapping rules (mirrors T7's send pattern):
          - ``asyncio.TimeoutError`` from ``wait_for`` →
            ``mcp_call_tool_timeout`` (per-call timeout, not the
            session-open timeout).
          - already-typed ``MCPTransportError`` → re-raise unchanged
            (defensive — preserves the original closed-enum reason
            if a future SDK plugin re-throws one).
          - any other ``Exception`` → ``mcp_transport_send_failed``
            with ``error_type=type(exc).__name__`` (NEVER
            ``str(exc)`` — could carry server-side debug strings).
          - ``BaseException`` (incl. ``CancelledError``) intentionally
            NOT caught — task teardown still propagates.

        The SDK signature accepts ``cursor: str | None``; pagination
        passes ``None`` for the first page and the previous page's
        ``nextCursor`` afterwards.
        """
        try:
            return await asyncio.wait_for(
                session.sdk_session.list_tools(cursor),
                timeout=self._settings.mcp_call_tool_timeout_s,
            )
        except TimeoutError as exc:
            raise MCPTransportError(
                "mcp_call_tool_timeout",
                "list_tools timed out",
                server_url=session.server_url,
                timeout_s=self._settings.mcp_call_tool_timeout_s,
            ) from exc
        except MCPTransportError:
            raise
        except Exception as exc:
            raise MCPTransportError(
                "mcp_transport_send_failed",
                "list_tools failed",
                server_url=session.server_url,
                error_type=type(exc).__name__,
            ) from exc

    @staticmethod
    def _normalize_list_tools_page(page: Any) -> tuple[list[Any], str | None]:
        """Extract ``(tools, next_cursor)`` from one
        ``ClientSession.list_tools`` response.

        Three shapes accepted:

          1. **Production** — :class:`mcp.types.ListToolsResult`
             (Pydantic): read ``.tools`` + ``.nextCursor``.
          2. **Test-mock back-compat** — bare ``list``: treat as
             a single page with no next cursor. Tests that mock the
             SDK with ``AsyncMock(return_value=[{...}])`` keep
             working without an SDK dependency.
          3. **Defensive** — anything else raises ``TypeError`` so
             a future refactor that mis-stubs the SDK fails loud.

        Empty-string ``nextCursor`` is treated as exhausted (defensive
        — some servers signal "no more pages" with ``""`` rather than
        ``None``). Returning ``None`` for cursor stops the pagination
        loop.
        """
        if hasattr(page, "tools"):
            tools = list(page.tools)
            raw_cursor = getattr(page, "nextCursor", None)
            cursor = raw_cursor if raw_cursor else None
            return tools, cursor
        if isinstance(page, list):
            return list(page), None
        raise TypeError(
            f"Unexpected list_tools response shape: {type(page).__name__}. "
            f"Expected mcp.types.ListToolsResult or list."
        )

    # --- call_tool ----------------------------------------------------------

    async def call_tool(
        self,
        *,
        server_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        request_id: str,
        tenant_id: str,
    ) -> CallResult:
        """Dispatch a tool call with auth-retry semantics.

        Step order (per plan §T9, R1 P2 #5: token BEFORE open):

          1. Look up the server entry; resolve the transport via the
             canonical-key view.
          2. Acquire minimum-scope token via ``authz.acquire_token``.
          3. Open transport session WITH the token.
          4. Send the call_tool request.
          5. **R1 P2 #3 — retry semantics on auth-related responses**
             (one retry max). Send-failure exceptions whose
             ``__cause__`` chain contains an ``httpx.HTTPStatusError``
             are classified:
               - 401 / 403 ``invalid_token`` → drop cached token via
                 ``authz.invalidate_cached_token``, reacquire, retry
                 once. Second 401 → fail with
                 ``mcp_authorisation_lost``.
               - 403 ``insufficient_scope`` → call
                 ``authz.step_up_token`` with the requested wider
                 scope; if step-up succeeds, retry with the stepped-
                 up token. If step-up raises
                 ``mcp_step_up_unauthorised``, that propagates
                 unchanged (T5's audit machinery emits the row
                 from inside the authz client).
          6. Best-effort close (audit-logged on failure; primary
             result/error wins).
          7. Return :class:`CallResult` with correlation IDs.

        T11 amplifies this with the
        ``audit.tool_invocation`` / ``audit.tool_invocation_error``
        rows + the parallel ``decision_history`` rows. T10 prepends
        the ADR-014 transitional risk-tier gate before step 2.
        """
        entry = self._lookup_server(server_id)

        # T10 — ADR-014 §"Sprint 5 (transitional rule)": fail-closed
        # for every risk_tier above ``internal_write``. Mechanical,
        # not configurable. Sprint 13.5 lands the approval engine and
        # removes this gate. The gate fires BEFORE token-acquire and
        # BEFORE session-open — a refused call MUST NOT touch the AS
        # or the MCP server, both for security (don't burn tokens on
        # refusals) and for audit cleanliness (a refusal row is the
        # only evidence a refused call leaves; a token-refresh row
        # or a session-open row would falsely imply we tried).
        #
        # R1 P2: ``entry.risk_tier`` is typed as ``str`` but the
        # portal lifespan wiring populates this from manifest TOML —
        # malformed values (list / dict / None / etc.) MUST fail-
        # close via the same closed-enum path, NOT raw TypeError
        # from the membership check. ``_normalize_risk_tier_for_gate``
        # coerces to a bounded-length string that's never in the
        # allow-list.
        declared_risk_tier = _normalize_risk_tier_for_gate(entry.risk_tier)
        if declared_risk_tier not in _ADR_014_LOW_RISK_TIERS:
            await self._emit_high_risk_tier_refusal_audit(
                server_id=server_id,
                tool_name=tool_name,
                declared_risk_tier=declared_risk_tier,
                request_id=request_id,
                tenant_id=tenant_id,
            )
            # R4 P2: sanitize caller-supplied ``tool_name`` +
            # registry-supplied ``server_id`` for the operator-
            # facing exception message so an operator who
            # ``str(exc)``-prints or logs the message cannot have
            # control-char content rewrite their terminal / forge
            # log lines. Audit-row payload below keeps raw values
            # (T11 canonical query path).
            safe_tool_name = _sanitize_string_for_operator_surface(tool_name)
            safe_server_id = _sanitize_string_for_operator_surface(server_id)
            raise MCPToolInvocationRefused(
                "tool_approval_engine_not_available",
                f"tool {safe_tool_name!r} on server {safe_server_id!r} "
                f"declares risk_tier={declared_risk_tier!r} which is "
                f"outside the Sprint-5 transitional allow-list "
                f"({sorted(_ADR_014_LOW_RISK_TIERS)!r}). Per ADR-014, "
                f"all tiers above ``internal_write`` are refused until "
                f"Sprint 13.5 lands the approval engine.",
                server_id=server_id,
                tool_name=tool_name,
                declared_risk_tier=declared_risk_tier,
                sprint_13_5_followup=True,
            )

        transport = self._resolve_transport(entry)

        async def _attempt(token: Token) -> tuple[Any, MCPSession, Token]:
            """Open session, send, close (best-effort). Returns the
            payload + the session + the token actually used (so the
            outer caller can build CallResult correlation IDs from
            the same token instance)."""
            session = await transport.open_session(server_url=entry.server_url, token=token)
            try:
                payload = await transport.send(
                    session,
                    MCPToolCallRequest(name=tool_name, arguments=dict(arguments)),
                )
                return payload, session, token
            finally:
                # ``finally`` so we close the session even if ``send``
                # raises. Close-failure tolerance applies (the close
                # error never masks the primary fault).
                await self._best_effort_close(
                    transport=transport,
                    session=session,
                    server_id=server_id,
                    request_id=request_id,
                    tenant_id=tenant_id,
                    operation="call_tool",
                )

        token = await self._authz.acquire_token(
            server_url=entry.server_url,
            manifest_scopes=entry.manifest_scopes,
            request_id=request_id,
            tenant_id=tenant_id,
        )
        try:
            payload, session, used_token = await _attempt(token)
        except MCPTransportError as first_error:
            signal, signal_payload = _classify_send_error(first_error)
            if signal == "transport_failed":
                # Real transport error (not auth-related); propagate
                # unchanged so the caller / T11's
                # audit.tool_invocation_error path sees the original
                # closed-enum reason.
                raise
            if signal == "authz_lost":
                # 401 OR 403 invalid_token → drop cached token + retry
                # once with a freshly-acquired token. Second 401 fails
                # with the closed-enum mcp_authorisation_lost.
                await self._authz.invalidate_cached_token(server_url=entry.server_url)
                fresh_token = await self._authz.acquire_token(
                    server_url=entry.server_url,
                    manifest_scopes=entry.manifest_scopes,
                    request_id=request_id,
                    tenant_id=tenant_id,
                )
                try:
                    payload, session, used_token = await _attempt(fresh_token)
                except MCPTransportError as second_error:
                    second_signal, _ = _classify_send_error(second_error)
                    if second_signal == "authz_lost":
                        raise MCPAuthzError(
                            "mcp_authorisation_lost",
                            "MCP server rejected both the cached and "
                            "freshly-acquired tokens with 401/403; "
                            "cannot recover without operator action",
                            server_url=entry.server_url,
                            request_id=request_id,
                            tenant_id=tenant_id,
                        ) from second_error
                    # Second failure is a different class of error;
                    # propagate so the caller sees what actually
                    # broke the retry.
                    raise
            else:  # signal == "step_up"
                # 403 insufficient_scope → step_up via authz. If the
                # manifest declares the wider scope, step_up returns
                # a fresh token and we retry. If not, step_up raises
                # mcp_step_up_unauthorised which propagates unchanged
                # (T5's audit machinery emits the row from inside
                # the authz client).
                stepped_up = await self._authz.step_up_token(
                    server_url=entry.server_url,
                    current_token=token,
                    requested_scope=signal_payload["requested_scope"],
                    manifest_scopes=entry.manifest_scopes,
                    request_id=request_id,
                    tenant_id=tenant_id,
                )
                payload, session, used_token = await _attempt(stepped_up)

        return CallResult(
            payload=payload,
            request_id=request_id,
            server_id=server_id,
            tool_name=tool_name,
            mcp_session_id=session.session_id,
            as_issuer=used_token.as_issuer,
            scopes=used_token.scopes,
            client_id=used_token.client_id,
        )

    # --- helpers ------------------------------------------------------------

    def _lookup_server(self, server_id: str) -> MCPServerEntry:
        try:
            return self._servers[server_id]
        except KeyError as exc:
            raise LookupError(
                f"unknown MCP server_id {server_id!r}; registered: {sorted(self._servers)!r}"
            ) from exc

    async def _best_effort_close(
        self,
        *,
        transport: MCPTransport,
        session: MCPSession,
        server_id: str,
        request_id: str,
        tenant_id: str,
        operation: str,
    ) -> None:
        """Close the session; on failure, audit-log and swallow.

        Per plan §T9: 'close failures are audit-logged but don't fail
        the result'. The primary result (or primary error from
        ``send``) is the load-bearing contract; teardown failures are
        operator-visible via audit but don't propagate. Close failures
        masking the primary error would be a critical regression — the
        operator would lose the diagnostic of why the call actually
        failed.

        Two failure classes (R3 P2):

          - **transport** (``MCPTransportError``): the close itself
            timed out or the SDK / httpx context manager raised
            during teardown. Audit-row carries the closed-enum
            transport reason.
          - **hook** (any other ``Exception``): T7's
            :meth:`StreamableHTTPTransport.close_session` emits the
            ``session_close`` audit event AFTER the stack closes;
            that hook is NOT safe-emit-wrapped (unlike the send-error
            path's ``_emit_send_error_safe``), so a buggy audit hook
            can raise a generic exception that would otherwise mask
            the primary result/error. Catching ``Exception`` here
            preserves the same primary-outcome-wins contract.
            ``BaseException`` (incl. ``CancelledError``) is
            intentionally NOT caught — task teardown still propagates.
        """
        try:
            await transport.close_session(session)
        except MCPTransportError as exc:
            _LOG.warning(
                "MCP session close failed during %s "
                "(server_id=%s request_id=%s reason=%s); audit-logged "
                "and swallowed so the primary result/error reaches the "
                "caller unchanged.",
                operation,
                server_id,
                request_id,
                exc.reason,
            )
            await self._safe_audit_close_failure(
                server_id=server_id,
                request_id=request_id,
                tenant_id=tenant_id,
                operation=operation,
                session=session,
                failure_class="transport",
                reason=exc.reason,
            )
        except Exception as exc:
            # R3 P2: hook failure during T7's session_close event
            # emission (or any other generic exception from the
            # transport's close path). MUST NOT mask the primary
            # result/error. Log token-free + emit a hook-class
            # close-failure audit row.
            _LOG.warning(
                "MCP session close raised non-transport exception "
                "during %s (server_id=%s request_id=%s "
                "error_type=%s); audit-logged and swallowed so the "
                "primary result/error reaches the caller unchanged. "
                "Investigate the audit hook on the transport's "
                "session_close event.",
                operation,
                server_id,
                request_id,
                type(exc).__name__,
            )
            await self._safe_audit_close_failure(
                server_id=server_id,
                request_id=request_id,
                tenant_id=tenant_id,
                operation=operation,
                session=session,
                failure_class="hook",
                error_type=type(exc).__name__,
            )

    async def _safe_audit_close_failure(
        self,
        *,
        server_id: str,
        request_id: str,
        tenant_id: str,
        operation: str,
        session: MCPSession,
        failure_class: Literal["transport", "hook"],
        reason: str | None = None,
        error_type: str | None = None,
    ) -> None:
        """Emit the ``audit.mcp_session_close_failed`` row token-free.
        Audit-pipeline failure during the close-failure event MUST NOT
        mask the primary result/error either. Log but do not raise."""
        payload: dict[str, Any] = {
            "server_id": server_id,
            "operation": operation,
            "failure_class": failure_class,
            "mcp_session_id": session.session_id,
        }
        if reason is not None:
            payload["reason"] = reason
        if error_type is not None:
            # Class name only — NEVER ``str(exc)`` (could carry token
            # bytes / event payload / server-side debug strings)
            payload["error_type"] = error_type
        try:
            await self._audit_store.append(
                AuditEvent(
                    event_type="audit.mcp_session_close_failed",
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload=payload,
                )
            )
        except Exception as audit_exc:
            _LOG.warning(
                "audit append failed while logging "
                "mcp_session_close_failed (server_id=%s "
                "request_id=%s failure_class=%s "
                "audit_error_type=%s); primary result/error still "
                "reaches the caller.",
                server_id,
                request_id,
                failure_class,
                type(audit_exc).__name__,
            )

    async def _emit_high_risk_tier_refusal_audit(
        self,
        *,
        server_id: str,
        tool_name: str,
        declared_risk_tier: str,
        request_id: str,
        tenant_id: str,
    ) -> None:
        """Emit ``audit.tool_invocation_refused`` for the ADR-014
        transitional gate (T10).

        Audit-pipeline failure during this emit MUST NOT mask the
        refusal — the refusal IS the safety outcome and propagates
        to the caller regardless. Audit-emit failure is operationally
        bad but doesn't change the safety semantics; log token-free
        and let the orchestrator's ``raise`` proceed.

        Payload schema (matches plan §T10 + T11 will read this shape):

          - ``server_id`` — pack identity (registry pack_id).
          - ``tool_name`` — manifest-declared tool name. Caller-
            supplied **arguments** are NOT included (refusal happens
            before any data-classification policy has run; the
            conservative default is "no caller bytes in the refusal
            row").
          - ``declared_risk_tier`` — manifest value, **normalised +
            bounded + control-character escaped** via
            :func:`_normalize_risk_tier_for_gate` (R1+R2+R3): allow-
            list values pass through unchanged; non-string values
            (list / dict / None / etc.) become a bounded
            ``repr()``; long strings get truncated at
            :data:`_RISK_TIER_REPR_MAX_LEN`; control characters
            (``\\n``, ``\\t``, ANSI escapes, NUL) are escaped to
            their ``\\xNN`` / ``\\n`` literal forms. Operators can
            still triage typos vs intentional high-risk vs
            malformed manifests; T11 implementers MUST NOT depend
            on raw manifest bytes here. The original manifest
            bytes are recoverable only from the cosign-signed pack
            artefact.
          - ``refusal_reason`` — closed-enum
            ``"tool_approval_engine_not_available"``.
          - ``sprint_13_5_followup`` — ``True`` so a Sprint 13.5
            release-readiness query can find every refusal row that
            the approval engine will resolve.
        """
        try:
            await self._audit_store.append(
                AuditEvent(
                    event_type="audit.tool_invocation_refused",
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload={
                        "server_id": server_id,
                        "tool_name": tool_name,
                        "declared_risk_tier": declared_risk_tier,
                        "refusal_reason": "tool_approval_engine_not_available",
                        "sprint_13_5_followup": True,
                    },
                )
            )
        except Exception as audit_exc:
            # R4 P2: sanitize caller-supplied strings (``tool_name``,
            # ``request_id``) for the operator-facing log surface so
            # an embedded newline / ANSI / NUL cannot forge a log
            # line / rewrite operator terminal / truncate the line.
            # ``server_id`` comes from the registry (operator-
            # controlled) but apply the same defense for
            # consistency. ``declared_risk_tier`` is already
            # normalised + bounded + escaped via
            # :func:`_normalize_risk_tier_for_gate`.
            _LOG.warning(
                "audit append failed while logging "
                "audit.tool_invocation_refused for the ADR-014 "
                "transitional high-risk-tier gate (server_id=%s "
                "tool_name=%s declared_risk_tier=%s request_id=%s "
                "audit_error_type=%s); the refusal still propagates "
                "to the caller (safety outcome wins).",
                _sanitize_string_for_operator_surface(server_id),
                _sanitize_string_for_operator_surface(tool_name),
                declared_risk_tier,
                _sanitize_string_for_operator_surface(request_id),
                type(audit_exc).__name__,
            )
