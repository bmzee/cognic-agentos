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

  2. **Audit emission consolidated through T11's
     :meth:`_emit_call_evidence`.** Every ``call_tool`` exit path
     emits exactly one ``audit_event`` row + one
     ``decision_history`` mcp_call row, correlated by
     ``request_id`` (per MCP-CONFORMANCE.md §observability item 9).

     - **T9 — close-failure tolerance** (separate channel):
       ``audit.mcp_session_close_failed`` with ``failure_class``
       ∈ {``"transport"``, ``"hook"``} via
       :meth:`_safe_audit_close_failure`. Best-effort close
       errors don't propagate; the success/error path's
       invocation row is still emitted by ``_emit_call_evidence``.
     - **Invocation rows (T10 + T11)** all flow through
       :meth:`_emit_call_evidence`:
         * ``audit.tool_invocation`` — successful ``call_tool``
           (``decision="invoked"``, ``duration_ms``, full
           correlation context). Mirror ``mcp_call`` decision row.
         * ``audit.tool_invocation_refused`` — ADR-014
           transitional gate (T10; ``refusal_reason=
           "tool_approval_engine_not_available"`` + ``declared_
           risk_tier`` + ``sprint_13_5_followup=True``);
           pre-dispatch authz failures (T11;
           ``refusal_reason=<authz reason>``);
           ``mcp_step_up_unauthorised`` after a first send
           (T11; carries the first-send session context per
           R1 P1). Mirror ``mcp_call`` decision rows with
           ``decision="refused"``.
         * ``audit.tool_invocation_error`` — transport timeout /
           send failure (T11); ``mcp_authorisation_lost``
           second-401 retry exhaustion (T11); post-dispatch
           reacquire failures (T11 R1 P2). All carry full
           dispatch correlation context (R1 P1) so examiners
           can replay what auth context the server saw. Mirror
           ``mcp_call`` decision rows with ``decision=
           "errored"``.
     - **Token-refresh + step-up evidence** (channel separate
       from invocation rows): ``audit.mcp_token_refresh`` +
       ``audit.mcp_step_up`` + parallel ``mcp_token_refresh``
       decision rows are emitted from
       :class:`MCPAuthzClient` (T5).

     The ``pack_id`` field — a payload-row schema convention —
     resolves to ``MCPServerEntry.server_id`` (Sprint-5 wiring
     sets one pack = one MCP server). Examiners querying
     ``decision_history WHERE request_id = ?`` get the full
     MCP-call shape including ``mcp_session_id`` + auth context.
     Audit + decision pipeline failures both safe-swallow:
     log token-free + caller still sees the primary outcome.
"""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import hashlib
import logging
import re
import time
import uuid
from collections.abc import Mapping
from typing import Any, Literal

import httpx

from cognic_agentos.core.approval._types import (
    APPROVAL_REDACTED_CONTEXT_MAX_LEN,
    ApprovalEnvelope,
    ApprovalRequestNotFound,
    ApprovalTransitionRefused,
)
from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.audit import AuditEvent, AuditStore
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.config import Settings
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.mcp_config.storage import MCPServerUrlOverrideStore
from cognic_agentos.protocol import require_mcp
from cognic_agentos.protocol.discovery_status import (
    DiscoveryStatus,
    DiscoveryStatusRecorder,
    discovery_status_for_authz_reason,
)
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
      - ``data_classes`` — manifest ``[data_governance].data_classes``
        carried at registration time (Sprint 13.5b2); feeds the
        value-free ApprovalEnvelope on the wired approval path. Empty
        default keeps pre-13.5b2 constructors green.
    """

    server_id: str
    server_url: str
    transport_kind: TransportKind
    manifest_scopes: tuple[str, ...]
    risk_tier: str
    pack_signature_digest: str
    data_classes: tuple[str, ...] = ()


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


#: Closed-enum reason emitted into ``audit.tool_invocation_error.
#: payload['error_taxonomy']`` AND the parallel ``mcp_call`` decision
#: row's ``decision_reason`` field for the catch-all generic-
#: ``Exception`` path of :meth:`MCPHost.call_tool` (R4 P2).
#:
#: T11 documents ``decision_reason`` as closed-enum-or-null. The
#: typed handlers populate it with values from
#: :data:`MCPTransportReason` (e.g. ``mcp_call_tool_timeout``,
#: ``mcp_session_open_failed``) or :data:`AuthzReason` (e.g.
#: ``mcp_authorisation_lost``). The generic-``Exception`` handler
#: cannot use any of those — the exception class is unknown by
#: definition — so a separate closed value is reserved for this
#: path. The sanitised Python class name (``type(exc).__name__``)
#: is preserved in a SEPARATE ``error_type`` payload field for
#: operator debugging WITHOUT polluting the closed-enum surface.
#:
#: This value MUST NOT be reused by the typed handlers — they have
#: precise closed-enum reasons that downstream consumers depend on.
_GENERIC_INVOCATION_ERROR_TAXONOMY = "mcp_orchestrator_error"


@dataclasses.dataclass(slots=True)
class _DispatchContext:
    """Internal: dispatch-state tracker populated by
    :meth:`MCPHost._call_tool_inner` and read by the outer
    ``call_tool`` exception handlers (R1 P1, R2 P2).

    Two distinct pairs of fields, separated to avoid the R2 P2
    bug class where a candidate retry/stepped-up token (never
    sent) leaks into the audit/decision row for an earlier
    dispatched failure:

      - **Acquired** state — set after each successful
        ``acquire_token`` / ``step_up_token``. May or may not
        have been dispatched. Used by pre-dispatch refusal rows
        so they can show what token the orchestrator was about
        to send (operator-debuggable; correlates to the
        manifest's declared scopes). Updated at every acquire,
        including retry reacquires and step-up tokens — even if
        the candidate is never dispatched.

      - **Dispatched** state — set ONLY when ``transport.send``
        is actually attempted with these. The "the server saw
        this" pair. ``audit.tool_invocation_error`` rows and the
        ``mcp_step_up_unauthorised`` refusal row MUST use these
        so the row's ``mcp_session_id`` + ``as_issuer`` +
        ``scopes`` + ``resource_indicator`` + ``client_id``
        truthfully reflect what the server processed — never a
        candidate token that never left the orchestrator.

    The ``dispatched`` flag also drives R1 P2 — post-dispatch
    reacquire failures (e.g. ``mcp_oauth_request_timeout`` on
    the retry's ``acquire_token``) classify as ERRORED rather
    than REFUSED because the call already reached the server
    once with a bearer token.

    R2 P2 specifically: a retry's ``open_session`` may raise
    BEFORE its ``transport.send`` is reached. In that case the
    dispatched pair stays at the prior successful send's values
    (truthful — the candidate never reached the server) while
    ``last_acquired_token`` reflects the new candidate.
    """

    last_acquired_token: Token | None = None
    last_dispatched_session: MCPSession | None = None
    last_dispatched_token: Token | None = None
    dispatched: bool = False


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


def _canonical_tool_identity(*, server_id: str, tool_name: str) -> str:
    """Collision-proof canonical tool identity (ADR-014 / 13.5b2 spec F4).

    The replay-binding comparand persisted on approval_requests.tool_identity
    (String(256); this form is 68 chars). Derived from a canonical OBJECT so
    separator characters in either field cannot collide (raw
    f"{server_id}:{tool_name}" rejected at the 13.5b2 reconciliation). The
    human-readable pair lives in the envelope's redacted_context instead.
    SAME function serves create_request AND verify_grant_for_action — drift
    between the two would make every grant unverifiable.
    """
    digest = hashlib.sha256(
        canonical_bytes({"server_id": server_id, "tool_name": tool_name})
    ).hexdigest()
    return f"mcp:{digest}"


def _approval_redacted_context(*, server_id: str, tool_name: str) -> str:
    """Bounded, sanitized, human-readable pair for the value-free envelope
    (13.5b2 spec §3.3) — reviewers see WHICH tool in the 13.5b1 portal detail
    panel while tool_identity stays the collision-proof digest."""
    text = (
        f"mcp_tool server_id={_sanitize_string_for_operator_surface(server_id)} "
        f"tool_name={_sanitize_string_for_operator_surface(tool_name)}"
    )
    return text[:APPROVAL_REDACTED_CONTEXT_MAX_LEN]


#: Closed-enum vocabulary for runtime tool-invocation refusals.
#: Wire-protocol-public (AGENTS.md MCP-host stop rule). Sprint 5 shipped
#: exactly one value (the ADR-014 transitional rule, kept as the
#: engine-absent fallback); Sprint 13.5b2 extended it with the five
#: approval-engine outcomes per ADR-014 + the 13.5b2 spec §4. Drift-pinned
#: by ``test_mcp_approval_seam.py::
#: test_tool_invocation_refusal_reason_has_exactly_six_values``.
ToolInvocationRefusalReason = Literal[
    "tool_approval_engine_not_available",
    "tool_approval_pending",
    "tool_approval_denied",
    "tool_approval_expired",
    "tool_approval_binding_mismatch",
    "tool_approval_request_not_found",
]


class MCPToolInvocationRefused(Exception):
    """Closed-enum runtime refusal of a tool invocation by MCPHost.

    Distinct from :class:`MCPTransportError` (transport-layer
    failures) and :class:`MCPAuthzError` (auth-layer failures). This
    exception covers refusals that happen at the orchestrator layer,
    BEFORE any token / session work — currently just the ADR-014
    transitional high-risk-tier gate.

    Audit-row ownership: the ADR-014 path emits
    ``audit.tool_invocation_refused`` + the parallel ``mcp_call``
    decision row via :meth:`MCPHost._emit_call_evidence` BEFORE
    raising this exception, so both rows are already persisted
    by the time the caller sees the raise. T11 consolidated all
    invocation-row emission through ``_emit_call_evidence``;
    T10's emission flows through the same helper with
    ``decision="refused"`` + ``decision_reason=
    "tool_approval_engine_not_available"`` + extra payload
    fields ``declared_risk_tier`` + ``sprint_13_5_followup``.

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
        approval_engine: ApprovalEngine | None = None,
        discovery_status_recorder: DiscoveryStatusRecorder | None = None,
        override_store: MCPServerUrlOverrideStore | None = None,
    ) -> None:
        # ``approval_engine`` (Sprint 13.5b2, ADR-014): None (default) keeps
        # the Sprint-5 transitional gate byte-for-byte (engine-absent
        # fallback); wired, call_tool consults the engine-authoritative
        # approval path for EVERY call. The production composition root
        # threads ``runtime.approval_engine`` in a later sprint — 13.5b2 is
        # seam-cutover only (no production host construction path exists).
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
        self._approval_engine = approval_engine
        # PR-1 Slice 2 (ADR-002): OBSERVATIONAL per-(tenant, pack) discovery-status
        # recorder. None (default) keeps the invoke path byte-for-byte (no-op
        # recording); wired, list_tools / call_tool record the OAuth-probe outcome
        # WITHOUT changing the fail-closed raise behaviour. The production
        # composition root threads the same instance attached to app.state for the
        # /system/plugins read surface.
        self._discovery_status_recorder = discovery_status_recorder
        # PR-2b-1 (ADR-002, spec §6 / OD-12): resolve-per-use operator
        # ``server_url`` override. None (default) keeps the runtime path
        # byte-for-byte (manifest ``server_url`` only — no store consult);
        # wired, :meth:`_effective_server_url` resolves the per-(tenant, pack)
        # override at EACH ``server_url`` use (every list_tools / call_tool) so a
        # post-boot operator change is observed WITHOUT a host restart. A store
        # error fails SAFE to the signed manifest URL. The override is runtime
        # config ONLY — :class:`MCPServerEntry` / the manifest is NEVER mutated.
        self._override_store = override_store
        # R1 P2 #2: cache key includes tenant_id + scopes (NOT just
        # server_id). Cross-tenant cache leak would let tenant B
        # receive tenant A's already-cleared tool catalogue without
        # tenant B's per-tenant AS allow-list ever firing. PR-2b-1 adds the
        # effective ``server_url`` as the 4th key component so a changed
        # operator override is a cache MISS (re-fetch) rather than a stale
        # tool list cached against the prior URL.
        self._list_tools_cache: dict[tuple[str, str, tuple[str, ...], str], _CachedToolList] = {}
        self._list_tools_cache_lock = asyncio.Lock()

    @property
    def _list_tools_cache_ttl_s(self) -> float:
        return float(self._settings.mcp_call_tool_timeout_s) * _LIST_TOOLS_CACHE_TTL_MULTIPLIER

    def _resolve_transport(self, entry: MCPServerEntry) -> MCPTransport:
        canonical = _canonicalize_transport_kind(entry.transport_kind)
        return self._transports_by_canonical[canonical]

    def _record_discovery_status(
        self, *, tenant_id: str, server_id: str, status: DiscoveryStatus
    ) -> None:
        """Record the per-(tenant, pack) outcome of an OAuth probe (``acquire_token``)
        when a recorder is injected; no-op otherwise.

        PR-1 Slice 2 (ADR-002): OBSERVATIONAL only — the invoke path stays fail-closed
        (callers still raise on a probe failure). The store key's ``pack_id`` is the
        registry ``distribution_name`` == :attr:`MCPServerEntry.server_id`.
        """
        if self._discovery_status_recorder is not None:
            self._discovery_status_recorder.record(
                tenant_id=tenant_id, pack_id=server_id, status=status
            )

    async def _effective_server_url(
        self, *, tenant_id: str, server_id: str, manifest_url: str
    ) -> str:
        """Resolve the effective MCP ``server_url`` for THIS invocation.

        PR-2b-1 (ADR-002, spec §6 / OD-12): an operator may point a
        ``(tenant, pack)`` at a real in-cluster MCP Service via an audited
        per-``(tenant, pack)`` ``server_url`` override. Resolved per USE (each
        ``list_tools`` / ``call_tool``) — NOT cached at construction — so a
        post-boot override change is observed without a host restart.

        Fail-SAFE: if no override store is wired (default) OR the store read
        raises, fall back to the SIGNED manifest URL (``manifest_url``), never
        to a cached / arbitrary host. The override is runtime config only; the
        signed :class:`MCPServerEntry` / manifest is NEVER mutated by this read.

        ``server_id`` is the registry ``distribution_name`` ==
        :attr:`MCPServerEntry.server_id` == the override store's ``pack_id``.
        """
        if self._override_store is None:
            return manifest_url
        try:
            override = await self._override_store.get(tenant_id=tenant_id, pack_id=server_id)
        except Exception:
            # Fail-safe to the signed manifest value (spec §10 — override store
            # unreachable → manifest ``server_url``). ``asyncio.CancelledError``
            # is a ``BaseException``, so task teardown still propagates.
            return manifest_url
        return override or manifest_url

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
        # PR-2b-1: resolve the effective server_url (operator override or signed
        # manifest) BEFORE the cache lookup so (a) a changed override is observed
        # on the next call (resolve-per-use) and (b) it is part of the cache key
        # — otherwise a changed override would return the STALE tool list cached
        # against the prior URL (the P1 fix). Used at every server_url read site
        # in this method (acquire / open / pagination-error evidence).
        effective_url = await self._effective_server_url(
            tenant_id=tenant_id, server_id=server_id, manifest_url=entry.server_url
        )
        cache_key = (tenant_id, server_id, entry.manifest_scopes, effective_url)

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
        # PR-1 Slice 2 — record the OAuth-probe outcome on the per-(tenant, pack)
        # discovery-status axis. SUCCESS → auth_ready; an MCPAuthzError maps to
        # refused / unreachable and STILL re-raises (the axis is observational;
        # list_tools stays fail-closed).
        try:
            token = await self._authz.acquire_token(
                server_url=effective_url,
                manifest_scopes=entry.manifest_scopes,
                request_id=request_id,
                tenant_id=tenant_id,
            )
        except MCPAuthzError as exc:
            self._record_discovery_status(
                tenant_id=tenant_id,
                server_id=entry.server_id,
                status=discovery_status_for_authz_reason(exc.reason),
            )
            raise
        self._record_discovery_status(
            tenant_id=tenant_id, server_id=entry.server_id, status="auth_ready"
        )
        session = await transport.open_session(server_url=effective_url, token=token)
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
                            server_url=effective_url,
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
                    server_url=effective_url,
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

    async def _approval_gate(
        self,
        *,
        entry: MCPServerEntry,
        tool_name: str,
        arguments: Mapping[str, Any],
        request_id: str,
        tenant_id: str,
        originator_subject: str,
        approval_request_id: uuid.UUID | None,
        declared_risk_tier: str,
    ) -> None:
        """ADR-014 engine-authoritative approval consult (13.5b2 spec §3).

        Returns None to proceed to dispatch (auto_run classification or a
        verified grant); raises MCPToolInvocationRefused (after emitting the
        refused evidence row) otherwise. ApprovalEnvelopeInvalid deliberately
        propagates to the outer generic-Exception arm (spec §3.5 — system
        error, not a policy refusal). Runs INSIDE the evidence-emitting try
        (spec §3.6) and BEFORE token-acquire/session-open (T10 sequencing).
        """
        engine = self._approval_engine
        assert engine is not None  # call site is gated on wiredness
        args_digest = hashlib.sha256(canonical_bytes(dict(arguments))).digest()
        tool_identity = _canonical_tool_identity(server_id=entry.server_id, tool_name=tool_name)
        if approval_request_id is not None:
            try:
                res = await engine.verify_grant_for_action(
                    request_id=approval_request_id,
                    tenant_id=tenant_id,
                    expected_args_digest=args_digest,
                    expected_tool_identity=tool_identity,
                )
            except ApprovalRequestNotFound:
                # Unknown OR cross-tenant — indistinguishable by construction
                # (the engine load is tenant-scoped). No flow exists (spec §4).
                await self._emit_approval_refused(
                    reason="tool_approval_request_not_found",
                    entry=entry,
                    tool_name=tool_name,
                    request_id=request_id,
                    tenant_id=tenant_id,
                    declared_risk_tier=declared_risk_tier,
                    approval_request_id=str(approval_request_id),
                )
                raise MCPToolInvocationRefused(
                    "tool_approval_request_not_found",
                    f"approval request {approval_request_id} not found for this tenant.",
                    server_id=entry.server_id,
                    tool_name=tool_name,
                    declared_risk_tier=declared_risk_tier,
                    approval_request_id=str(approval_request_id),
                ) from None
            except ApprovalTransitionRefused as exc:
                if exc.reason != "approval_binding_mismatch":
                    raise  # defensive: unexpected verify-side refusal -> errored arm
                # flow OMITTED: verify raised without returning the result and
                # the seam does NOT issue an extra store read (spec §4).
                await self._emit_approval_refused(
                    reason="tool_approval_binding_mismatch",
                    entry=entry,
                    tool_name=tool_name,
                    request_id=request_id,
                    tenant_id=tenant_id,
                    declared_risk_tier=declared_risk_tier,
                    approval_request_id=str(approval_request_id),
                )
                raise MCPToolInvocationRefused(
                    "tool_approval_binding_mismatch",
                    f"approval request {approval_request_id} was granted for a "
                    f"DIFFERENT invocation shape (args or tool identity changed); "
                    f"a grant authorises exactly one action.",
                    server_id=entry.server_id,
                    tool_name=tool_name,
                    declared_risk_tier=declared_risk_tier,
                    approval_request_id=str(approval_request_id),
                ) from None
            if res.state == "granted":
                return  # verified grant -> dispatch
            state_to_reason: dict[str, ToolInvocationRefusalReason] = {
                "pending": "tool_approval_pending",
                "awaiting_second": "tool_approval_pending",
                "denied": "tool_approval_denied",
                "expired": "tool_approval_expired",
            }
            recall_reason = state_to_reason[res.state]
            await self._emit_approval_refused(
                reason=recall_reason,
                entry=entry,
                tool_name=tool_name,
                request_id=request_id,
                tenant_id=tenant_id,
                declared_risk_tier=declared_risk_tier,
                approval_request_id=str(approval_request_id),
                flow=res.flow,
            )
            raise MCPToolInvocationRefused(
                recall_reason,
                f"approval request {approval_request_id} is in state "
                f"{res.state!r}; not dispatchable.",
                server_id=entry.server_id,
                tool_name=tool_name,
                declared_risk_tier=declared_risk_tier,
                approval_request_id=str(approval_request_id),
                flow=res.flow,
            )
        required_refs: dict[str, str] = {}
        if declared_risk_tier == "regulator_communication":
            # Spec F3: the invocation request_id IS the audit correlator
            # every call_tool evidence row is keyed by.
            required_refs = {"audit_record_ref": request_id}
        envelope = ApprovalEnvelope(
            risk_tier=declared_risk_tier,
            tool_identity=tool_identity,
            originator_subject=originator_subject,
            tenant_id=tenant_id,
            data_classes=tuple(entry.data_classes),
            args_digest=args_digest,
            redacted_context=_approval_redacted_context(
                server_id=entry.server_id, tool_name=tool_name
            ),
            required_refs=required_refs,
        )
        try:
            request = await engine.create_request(envelope=envelope)
        except ApprovalTransitionRefused as exc:
            if exc.reason == "auto_tier_no_approval_required":
                return  # tools.rego classified auto_run -> dispatch
            raise  # defensive: unexpected create-side refusal -> errored arm
        await self._emit_approval_refused(
            reason="tool_approval_pending",
            entry=entry,
            tool_name=tool_name,
            request_id=request_id,
            tenant_id=tenant_id,
            declared_risk_tier=declared_risk_tier,
            approval_request_id=str(request.request_id),
            flow=request.flow,
        )
        safe_tool_name = _sanitize_string_for_operator_surface(tool_name)
        safe_server_id = _sanitize_string_for_operator_surface(entry.server_id)
        raise MCPToolInvocationRefused(
            "tool_approval_pending",
            f"tool {safe_tool_name!r} on server {safe_server_id!r} requires "
            f"approval (flow={request.flow}); request "
            f"{request.request_id} is pending. Grant via the portal approval "
            f"API, then re-call with approval_request_id.",
            server_id=entry.server_id,
            tool_name=tool_name,
            declared_risk_tier=declared_risk_tier,
            approval_request_id=str(request.request_id),
            flow=request.flow,
        )

    async def _emit_approval_refused(
        self,
        *,
        reason: ToolInvocationRefusalReason,
        entry: MCPServerEntry,
        tool_name: str,
        request_id: str,
        tenant_id: str,
        declared_risk_tier: str,
        approval_request_id: str,
        flow: str | None = None,
    ) -> None:
        """Refused evidence for the approval outcomes (13.5b2 spec §4/§6):
        one audit row + one decision row through the SAME _emit_call_evidence
        helper; mcp_session_id=None + token=None (truthfully pre-acquire);
        flow included only WHEN KNOWN."""
        extra: dict[str, Any] = {
            "refusal_reason": reason,
            "declared_risk_tier": declared_risk_tier,
            "approval_request_id": approval_request_id,
        }
        if flow is not None:
            extra["flow"] = flow
        await self._emit_call_evidence(
            event_type="audit.tool_invocation_refused",
            decision="refused",
            decision_reason=reason,
            entry=entry,
            tool_name=tool_name,
            request_id=request_id,
            tenant_id=tenant_id,
            declared_risk_tier=declared_risk_tier,
            mcp_session_id=None,
            token=None,
            extra_audit_payload=extra,
            extra_decision_payload=dict(extra),
        )

    async def call_tool(
        self,
        *,
        server_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        request_id: str,
        tenant_id: str,
        originator_subject: str = "",
        approval_request_id: uuid.UUID | None = None,
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
        rows + the parallel ``decision_history`` rows (emitted via
        :meth:`_emit_call_evidence` at every exit path). T10
        prepends the ADR-014 transitional risk-tier gate before
        step 2 — T10 also flows through the same evidence helper
        so the ``audit.tool_invocation_refused`` row schema is
        uniform across all refusal classes.
        """
        started_at_monotonic = time.monotonic()
        entry = self._lookup_server(server_id)

        # T10 — ADR-014 §"Sprint 5 (transitional rule)": fail-closed
        # for every risk_tier above ``internal_write``. Mechanical,
        # not configurable. Sprint 13.5b2 kept this gate as the
        # ENGINE-ABSENT fallback, byte-for-byte: when
        # ``approval_engine`` is wired, classification is
        # engine-authoritative (the _approval_gate consult inside the
        # evidence-emitting try below) and this static set is NEVER
        # consulted — a bank overlay that tightens tools.rego is
        # honoured. The gate fires BEFORE token-acquire and
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
        if self._approval_engine is None and declared_risk_tier not in _ADR_014_LOW_RISK_TIERS:
            await self._emit_call_evidence(
                event_type="audit.tool_invocation_refused",
                decision="refused",
                decision_reason="tool_approval_engine_not_available",
                entry=entry,
                tool_name=tool_name,
                request_id=request_id,
                tenant_id=tenant_id,
                declared_risk_tier=declared_risk_tier,
                extra_audit_payload={
                    "refusal_reason": "tool_approval_engine_not_available",
                    "declared_risk_tier": declared_risk_tier,
                    "sprint_13_5_followup": True,
                },
                extra_decision_payload={"sprint_13_5_followup": True},
            )
            # R4 P2: sanitize caller-supplied ``tool_name`` +
            # registry-supplied ``server_id`` for the operator-
            # facing exception message so an operator who
            # ``str(exc)``-prints or logs the message cannot have
            # control-char content rewrite their terminal / forge
            # log lines. Audit-row payload above keeps raw values
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

        # Main path — wrap the inner orchestration so every exit
        # (success / authz refusal / step_up_unauthorised /
        # transport error / second-401 mcp_authorisation_lost)
        # emits exactly one audit_event row + one decision_history
        # row. Per plan §T11: every request_id flowing through
        # call_tool produces 1 audit row (one of the 3 invocation
        # event types) + 1 mcp_call decision row.
        #
        # R1 P1 + P2: ``_DispatchContext`` is populated as the inner
        # orchestration progresses. Outer handlers read it so:
        #   - Dispatched-error rows (transport timeout / send fail /
        #     mcp_authorisation_lost / step_up_unauthorised after a
        #     first send) carry the correlation context the server
        #     actually saw (mcp_session_id, as_issuer, scopes, ...).
        #   - Post-dispatch authz failures (e.g. reacquire_token
        #     raises mcp_oauth_request_timeout AFTER a first 401)
        #     classify as ERRORED, not REFUSED — the call already
        #     reached the server once.
        ctx = _DispatchContext()
        try:
            if self._approval_engine is not None:
                # Sprint 13.5b2 (ADR-014): the engine-authoritative approval
                # consult. Runs INSIDE the evidence-emitting try (spec §3.6)
                # so ApprovalEnvelopeInvalid reaches the generic-Exception
                # arm below (ERRORED row), and BEFORE _call_tool_inner so a
                # refused call never touches the AS or the MCP server.
                await self._approval_gate(
                    entry=entry,
                    tool_name=tool_name,
                    arguments=arguments,
                    request_id=request_id,
                    tenant_id=tenant_id,
                    originator_subject=originator_subject,
                    approval_request_id=approval_request_id,
                    declared_risk_tier=declared_risk_tier,
                )
            payload, session, used_token = await self._call_tool_inner(
                entry=entry,
                tool_name=tool_name,
                arguments=arguments,
                request_id=request_id,
                tenant_id=tenant_id,
                dispatch_context=ctx,
            )
        except MCPToolInvocationRefused:
            # Spec §3.6 guard: refusal evidence was already emitted at the
            # refusal site (_approval_gate). MCPToolInvocationRefused
            # inherits RuntimeError (test-pinned), so without this bare
            # re-raise the generic-Exception arm below would DOUBLE-EMIT an
            # errored row on top of the refused row.
            raise
        except MCPAuthzError as exc:
            # Classification rules:
            #   1. ``mcp_authorisation_lost`` (post-dispatch
            #      second-401 exhaustion) → ERRORED.
            #   2. Any AuthzError raised AFTER ctx.dispatched is
            #      True (R1 P2: post-dispatch reacquire failure /
            #      step_up_unauthorised after a first send) →
            #      ERRORED; the call already reached the server.
            #   3. Pre-dispatch authz refusal (acquire_token failed
            #      before any send) → REFUSED.
            #
            # R2 P2: dispatched paths use ``last_dispatched_*``
            # (truthful — what the server actually saw); pre-
            # dispatch refusals use ``last_acquired_token`` (the
            # candidate the orchestrator was about to send). Never
            # mix candidate-token with prior-dispatch session.
            dispatched_session_id = (
                ctx.last_dispatched_session.session_id
                if ctx.last_dispatched_session is not None
                else None
            )
            if exc.reason == "mcp_authorisation_lost" or ctx.dispatched:
                # R1 P1 + P2: dispatched → errored, with full context
                event_type: Literal[
                    "audit.tool_invocation_error",
                    "audit.tool_invocation_refused",
                ] = "audit.tool_invocation_error"
                decision: Literal["refused", "errored"] = "errored"
                # Special case: step_up_unauthorised → REFUSED even
                # though dispatched (we declined to retry with the
                # wider scope). Keep the dispatch context though.
                extra_audit: dict[str, Any]
                if exc.reason == "mcp_step_up_unauthorised":
                    event_type = "audit.tool_invocation_refused"
                    decision = "refused"
                    extra_audit = {"refusal_reason": exc.reason}
                else:
                    extra_audit = {"error_taxonomy": exc.reason}
                await self._emit_call_evidence(
                    event_type=event_type,
                    decision=decision,
                    decision_reason=exc.reason,
                    entry=entry,
                    tool_name=tool_name,
                    request_id=request_id,
                    tenant_id=tenant_id,
                    declared_risk_tier=declared_risk_tier,
                    mcp_session_id=dispatched_session_id,
                    token=ctx.last_dispatched_token,
                    extra_audit_payload=extra_audit,
                )
            else:
                # Pre-dispatch authz refusal — never reached the
                # server. Token may be None (acquire_token failed
                # at the very first call) or set to the candidate
                # we were about to send.
                await self._emit_call_evidence(
                    event_type="audit.tool_invocation_refused",
                    decision="refused",
                    decision_reason=exc.reason,
                    entry=entry,
                    tool_name=tool_name,
                    request_id=request_id,
                    tenant_id=tenant_id,
                    declared_risk_tier=declared_risk_tier,
                    mcp_session_id=None,
                    token=ctx.last_acquired_token,
                    extra_audit_payload={"refusal_reason": exc.reason},
                )
            raise
        except MCPTransportError as exc:
            # R2 P2: ``last_dispatched_*`` is the truthful "the
            # server saw this" pair. Pre-dispatch open-session
            # failures (first attempt) leave the dispatched pair
            # at None+None — honest report that no dispatch
            # happened. Retry-after-401 open-session failures
            # leave the dispatched pair at the FIRST send's
            # session+token (the only one the server saw); the
            # never-sent candidate token is in
            # ``last_acquired_token`` but NOT used here.
            dispatched_session_id = (
                ctx.last_dispatched_session.session_id
                if ctx.last_dispatched_session is not None
                else None
            )
            await self._emit_call_evidence(
                event_type="audit.tool_invocation_error",
                decision="errored",
                decision_reason=exc.reason,
                entry=entry,
                tool_name=tool_name,
                request_id=request_id,
                tenant_id=tenant_id,
                declared_risk_tier=declared_risk_tier,
                mcp_session_id=dispatched_session_id,
                token=ctx.last_dispatched_token,
                extra_audit_payload={"error_taxonomy": exc.reason},
            )
            raise
        except Exception as exc:
            # R3 P2: T7's ``StreamableHTTPTransport.open_session``
            # can re-raise generic ``Exception`` (e.g., from a
            # buggy ``session_open`` audit hook — its R2 P2 #1
            # cleanup path closes the AsyncExitStack but lets the
            # original exception propagate). Without this catch,
            # such errors bypass T11 evidence emission entirely
            # — no audit row, no decision row — violating the
            # "every request_id produces 1 audit + 1 decision
            # row" invariant.
            #
            # R4 P2: closed-enum vocabulary doctrine. The audit
            # row's ``error_taxonomy`` field and the decision
            # row's ``decision_reason`` field are closed-enum
            # surfaces — operators query / map them downstream.
            # Putting Python class names like ``RuntimeError``
            # into those fields opens the vocabulary. The closed
            # reason for this path is
            # :data:`_GENERIC_INVOCATION_ERROR_TAXONOMY`
            # (``"mcp_orchestrator_error"``); the sanitised class
            # name lives in a SEPARATE ``error_type`` payload
            # field for operator debugging.
            #
            # Token-free: ``type(exc).__name__`` only — NEVER
            # ``str(exc)`` (could carry server-side debug strings
            # or token bytes).
            #
            # ``BaseException`` (incl. ``CancelledError``)
            # intentionally NOT caught — task teardown
            # propagates without evidence emission.
            dispatched_session_id = (
                ctx.last_dispatched_session.session_id
                if ctx.last_dispatched_session is not None
                else None
            )
            error_type_name = type(exc).__name__
            await self._emit_call_evidence(
                event_type="audit.tool_invocation_error",
                decision="errored",
                decision_reason=_GENERIC_INVOCATION_ERROR_TAXONOMY,
                entry=entry,
                tool_name=tool_name,
                request_id=request_id,
                tenant_id=tenant_id,
                declared_risk_tier=declared_risk_tier,
                mcp_session_id=dispatched_session_id,
                token=ctx.last_dispatched_token,
                extra_audit_payload={
                    "error_taxonomy": _GENERIC_INVOCATION_ERROR_TAXONOMY,
                    "error_type": error_type_name,
                },
                extra_decision_payload={"error_type": error_type_name},
            )
            raise

        # Success path — emit ``audit.tool_invocation`` + ``invoked``
        # decision row with full correlation context.
        duration_ms = int((time.monotonic() - started_at_monotonic) * 1000)
        await self._emit_call_evidence(
            event_type="audit.tool_invocation",
            decision="invoked",
            decision_reason=None,
            entry=entry,
            tool_name=tool_name,
            request_id=request_id,
            tenant_id=tenant_id,
            declared_risk_tier=declared_risk_tier,
            mcp_session_id=session.session_id,
            token=used_token,
            duration_ms=duration_ms,
        )

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

    async def _call_tool_inner(
        self,
        *,
        entry: MCPServerEntry,
        tool_name: str,
        arguments: Mapping[str, Any],
        request_id: str,
        tenant_id: str,
        dispatch_context: _DispatchContext,
    ) -> tuple[Any, MCPSession, Token]:
        """Inner orchestration: token acquisition + open + send +
        retry semantics + close. Returns ``(payload, session,
        used_token)``; raises :class:`MCPAuthzError` or
        :class:`MCPTransportError` on the various failure paths.

        Extracted from :meth:`call_tool` so the outer body can wrap
        the entire orchestration in a single try/except for
        evidence emission (T11). The inner method itself does not
        emit evidence — that's the caller's job.

        R1 P1 + R1 P2 + R2 P2: populates ``dispatch_context`` as
        orchestration progresses so the outer error handlers emit
        evidence with the correct dispatch correlation context. The
        R2 P2 split separates **acquired** (candidate) state from
        **dispatched** ("the server saw this") state so a never-sent
        retry/step-up token can't leak into a prior dispatch's
        evidence row. Stages:

          - After each ``acquire_token`` / ``step_up_token`` →
            :attr:`_DispatchContext.last_acquired_token` is set
            (used by pre-dispatch refusal rows).
          - After ``open_session`` succeeds (in ``_attempt``) →
            no dispatched-state mutation yet (open success ≠
            send dispatched).
          - **Just before ``transport.send``** (in ``_attempt``,
            inside the inner ``try``) →
            :attr:`_DispatchContext.last_dispatched_session` and
            :attr:`_DispatchContext.last_dispatched_token` are
            set; ``dispatched`` flips to True. From this point
            forward, any failure (including post-dispatch authz
            reacquire failures) classifies as ERRORED with the
            send-pair's session+token context. If a retry's
            ``open_session`` raises BEFORE its send is reached,
            the dispatched pair stays at the prior successful
            send's values — truthful, since the candidate
            token never reached the server.
        """
        transport = self._resolve_transport(entry)
        # PR-2b-1: resolve the effective server_url ONCE per invocation (operator
        # override or signed manifest) and use it at EVERY server_url read site
        # below — acquire, open, invalidate, reacquire, the authorisation-lost
        # evidence payload, and step-up — so a single call never splits traffic
        # between the override and the manifest URL. Resolve-per-use: a post-boot
        # override change is observed on the next call_tool. Fail-safe to the
        # signed manifest URL on a store error. The ``_attempt`` closure below
        # captures this binding.
        effective_url = await self._effective_server_url(
            tenant_id=tenant_id, server_id=entry.server_id, manifest_url=entry.server_url
        )

        async def _attempt(token: Token) -> tuple[Any, MCPSession, Token]:
            """Open session, send, close (best-effort). Returns the
            payload + the session + the token actually used.

            R2 P2: ``dispatch_context.last_dispatched_session`` and
            ``last_dispatched_token`` are updated ONLY immediately
            before ``transport.send`` — never on ``open_session``
            success alone. If a retry's ``open_session`` raises
            BEFORE this attempt's send is reached, the dispatched
            pair stays at the prior successful send's values
            (truthful: the retry candidate never reached the
            server). ``open_session`` failure first attempt leaves
            the dispatched pair at None+None (also truthful: no
            dispatch happened).
            """
            session = await transport.open_session(server_url=effective_url, token=token)
            try:
                # R2 P2 — update DISPATCHED state immediately before
                # send. Open succeeded but the bytes haven't actually
                # reached the server yet; the moment ``transport.send``
                # is awaited, ``open_session`` has been observed by
                # the server (HTTP MCP) and the candidate token is
                # in flight. From here on, any failure inside
                # ``send`` (timeout / SDK exception / 401 / 403) IS
                # a dispatched-error event correlating to (session,
                # token).
                dispatch_context.last_dispatched_session = session
                dispatch_context.last_dispatched_token = token
                dispatch_context.dispatched = True
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
                    server_id=entry.server_id,
                    request_id=request_id,
                    tenant_id=tenant_id,
                    operation="call_tool",
                )

        # PR-1 Slice 2 — record the OAuth-probe outcome on the per-(tenant, pack)
        # discovery-status axis. SUCCESS → auth_ready; an MCPAuthzError maps to
        # refused / unreachable and STILL re-raises (call_tool stays fail-closed).
        try:
            token = await self._authz.acquire_token(
                server_url=effective_url,
                manifest_scopes=entry.manifest_scopes,
                request_id=request_id,
                tenant_id=tenant_id,
            )
        except MCPAuthzError as exc:
            self._record_discovery_status(
                tenant_id=tenant_id,
                server_id=entry.server_id,
                status=discovery_status_for_authz_reason(exc.reason),
            )
            raise
        self._record_discovery_status(
            tenant_id=tenant_id, server_id=entry.server_id, status="auth_ready"
        )
        # First-acquire success — record token even before dispatch
        # so a step_up_unauthorised on the FIRST send carries the
        # correct token in the refusal row.
        dispatch_context.last_acquired_token = token
        try:
            payload, session, used_token = await _attempt(token)
        except MCPTransportError as first_error:
            signal, signal_payload = _classify_send_error(first_error)
            if signal == "transport_failed":
                # Real transport error (not auth-related); propagate
                # unchanged so the caller's audit.tool_invocation_error
                # path sees the original closed-enum reason. Dispatch
                # context already populated by _attempt.
                raise
            if signal == "authz_lost":
                # 401 OR 403 invalid_token → drop cached token + retry
                # once with a freshly-acquired token. Second 401 fails
                # with the closed-enum mcp_authorisation_lost.
                #
                # R1 P2: a reacquire failure here (e.g.
                # mcp_oauth_request_timeout) is a POST-dispatch authz
                # failure — the call already reached the server once.
                # ``dispatch_context.dispatched`` is True from the
                # first send, so the outer handler classifies the
                # reacquire failure as ERRORED (with the first
                # send's session context).
                await self._authz.invalidate_cached_token(server_url=effective_url)
                # PR-1 Slice 2 — the REACQUIRE is the third OAuth-probe site; record
                # its outcome too. SUCCESS → auth_ready; a reacquire MCPAuthzError
                # (e.g. mcp_oauth_request_timeout) maps to refused / unreachable and
                # STILL re-raises (overwriting the initial auth_ready).
                try:
                    fresh_token = await self._authz.acquire_token(
                        server_url=effective_url,
                        manifest_scopes=entry.manifest_scopes,
                        request_id=request_id,
                        tenant_id=tenant_id,
                    )
                except MCPAuthzError as exc:
                    self._record_discovery_status(
                        tenant_id=tenant_id,
                        server_id=entry.server_id,
                        status=discovery_status_for_authz_reason(exc.reason),
                    )
                    raise
                self._record_discovery_status(
                    tenant_id=tenant_id, server_id=entry.server_id, status="auth_ready"
                )
                dispatch_context.last_acquired_token = fresh_token
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
                            server_url=effective_url,
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
                try:
                    stepped_up = await self._authz.step_up_token(
                        server_url=effective_url,
                        current_token=token,
                        requested_scope=signal_payload["requested_scope"],
                        manifest_scopes=entry.manifest_scopes,
                        request_id=request_id,
                        tenant_id=tenant_id,
                    )
                except MCPAuthzError as exc:
                    # PR-2a: a step-up failure that reflects endpoint/OAuth
                    # reachability (SSRF refusal, timeout, transport, AS-discovery /
                    # token errors) surfaces on the discovery-status axis via the
                    # SHARED mapper — so step-up is not a second unobserved invoke
                    # path. mcp_step_up_unauthorised is an authorization denial (the
                    # original token is fine, only the wider scope was denied), NOT
                    # endpoint reachability, so it is the one excluded reason.
                    if exc.reason != "mcp_step_up_unauthorised":
                        self._record_discovery_status(
                            tenant_id=tenant_id,
                            server_id=entry.server_id,
                            status=discovery_status_for_authz_reason(exc.reason),
                        )
                    raise
                dispatch_context.last_acquired_token = stepped_up
                payload, session, used_token = await _attempt(stepped_up)

        return payload, session, used_token

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

    async def _emit_call_evidence(
        self,
        *,
        event_type: Literal[
            "audit.tool_invocation",
            "audit.tool_invocation_refused",
            "audit.tool_invocation_error",
        ],
        decision: Literal["invoked", "refused", "errored"],
        decision_reason: str | None,
        entry: MCPServerEntry,
        tool_name: str,
        request_id: str,
        tenant_id: str,
        declared_risk_tier: str,
        mcp_session_id: str | None = None,
        token: Token | None = None,
        duration_ms: int | None = None,
        extra_audit_payload: dict[str, Any] | None = None,
        extra_decision_payload: dict[str, Any] | None = None,
    ) -> None:
        """T11 — emit the parallel ``audit_event`` + ``decision_history``
        rows for one ``call_tool`` outcome.

        Per plan §T11 (R1 P2 #6 fix — separating the two evidence
        surfaces): every ``request_id`` flowing through ``call_tool``
        produces exactly one ``audit_event`` row (one of
        ``audit.tool_invocation`` / ``audit.tool_invocation_refused``
        / ``audit.tool_invocation_error``) AND exactly one
        ``decision_history`` mcp_call row, both correlated by
        ``request_id``. Examiners querying the audit chain by
        sequence get the tamper-evident timeline; examiners querying
        ``decision_history WHERE request_id = ?`` get the full
        MCP-call shape with ``mcp_session_id`` for replay (per
        MCP-CONFORMANCE.md §observability item 9).

        Audit + decision pipeline failures BOTH safe-swallow: log
        token-free + let the caller see the primary outcome.
        Audit-pipeline failure does NOT mask the success / refusal /
        error result — same discipline as
        :meth:`_safe_audit_close_failure`.

        Payload contract:

          - **Common fields** (audit + decision): ``pack_id`` (=
            ``entry.server_id``, the registry pack identity);
            ``tool_name`` (raw — T11 canonical query path);
            ``mcp_session_id`` (None when refused before session
            open); ``as_issuer`` / ``scopes`` (sorted for hash
            stability) / ``resource_indicator`` / ``client_id``
            (None when refused before token acquired).
          - **Audit-only**: ``pack_signature_digest``,
            ``duration_ms`` (success path only), ``outcome="ok"``
            for the success event_type. ``extra_audit_payload``
            adds ``refusal_reason`` / ``error_taxonomy`` /
            ``declared_risk_tier`` / ``sprint_13_5_followup`` per
            event class.
          - **Decision-only**: ``declared_risk_tier`` (always),
            ``decision`` ∈ {invoked, refused, errored},
            ``decision_reason`` (closed-enum or None for ok).
            ``extra_decision_payload`` adds path-specific fields.

        **Token-free**: the bearer token's ``value`` bytes NEVER
        appear in either payload. Tool ``arguments`` NEVER appear
        in the refusal/error payloads (the call may not have been
        admitted by data-classification policy; the conservative
        default is "no caller bytes").
        """
        # Build the common correlation context. ``token`` is None
        # for refusals that happened before token acquisition (e.g.
        # ADR-014 gate, mcp_anonymous_refused at acquire_token);
        # the audit row honestly records that.
        common: dict[str, Any] = {
            "pack_id": entry.server_id,
            "tool_name": tool_name,
            "mcp_session_id": mcp_session_id,
            "as_issuer": token.as_issuer if token else None,
            "scopes": sorted(token.scopes) if token else None,
            "resource_indicator": (token.resource_indicator if token else None),
            "client_id": token.client_id if token else None,
        }

        # Audit payload: common + pack_signature_digest + outcome
        # marker for success + duration_ms + per-event extras
        audit_payload: dict[str, Any] = dict(common)
        audit_payload["pack_signature_digest"] = entry.pack_signature_digest
        if event_type == "audit.tool_invocation":
            audit_payload["outcome"] = "ok"
        if duration_ms is not None:
            audit_payload["duration_ms"] = duration_ms
        if extra_audit_payload:
            audit_payload.update(extra_audit_payload)

        try:
            await self._audit_store.append(
                AuditEvent(
                    event_type=event_type,
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload=audit_payload,
                )
            )
        except Exception as audit_exc:
            _LOG.warning(
                "audit append failed while emitting %s for call_tool "
                "(pack_id=%s tool_name=%s request_id=%s "
                "audit_error_type=%s); primary outcome still "
                "propagates to the caller.",
                event_type,
                _sanitize_string_for_operator_surface(entry.server_id),
                _sanitize_string_for_operator_surface(tool_name),
                _sanitize_string_for_operator_surface(request_id),
                type(audit_exc).__name__,
            )

        # Decision payload: common + declared_risk_tier + decision
        # + decision_reason + per-path extras
        decision_payload: dict[str, Any] = dict(common)
        decision_payload["declared_risk_tier"] = declared_risk_tier
        decision_payload["decision"] = decision
        decision_payload["decision_reason"] = decision_reason
        if extra_decision_payload:
            decision_payload.update(extra_decision_payload)

        try:
            await self._decision_history_store.append(
                DecisionRecord(
                    decision_type="mcp_call",
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload=decision_payload,
                )
            )
        except Exception as decision_exc:
            _LOG.warning(
                "decision_history append failed for mcp_call "
                "(pack_id=%s tool_name=%s request_id=%s decision=%s "
                "decision_error_type=%s); primary outcome still "
                "propagates to the caller.",
                _sanitize_string_for_operator_surface(entry.server_id),
                _sanitize_string_for_operator_surface(tool_name),
                _sanitize_string_for_operator_surface(request_id),
                decision,
                type(decision_exc).__name__,
            )
