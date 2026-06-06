"""protocol/mcp_capabilities.py — MCP pack manifest capability validator.

Critical-controls module per AGENTS.md (Plugin trust + supply chain
— the validator is the only place AgentOS interprets pack-declared
MCP capability blocks at admission, and its closed-enum refusal
vocabulary is what every other Sprint-5 surface keys off).

Per Sprint-5 R3 P1 doctrine, this module is **admission-side**: it
imports + constructs cleanly without the ``mcp`` SDK installed. The
module never imports ``mcp`` (neither at module scope nor inside
function bodies) — manifest dicts are plain Python data; no SDK
needed to interpret them.

OPA dependency note: the sampling default-deny check (one of ten
capability-side reasons) subprocess-calls the OPA binary via the
Sprint-4 :class:`~cognic_agentos.core.policy.engine.OPAEngine`. OPA
ships in the default-adapters Docker image only (Sprint-4 doctrine;
same boundary as cosign). Validation paths that do NOT reach the
sampling check (manifest-shape errors, transport-unsupported
refusals, restricted-data-class refusals, STDIO-disabled refusals)
succeed without OPA — the OPA dependency is reachable only when the
manifest declares ``sampling_supported = true``.

Closed-enum reason vocabulary (10 values after T6 R1 P1 #2 added
``mcp_transport_unsupported``; 2 manifest-extraction reasons live
in :mod:`cognic_agentos.protocol.mcp_manifest` and are exception-
typed there, not in this Literal):

- ``mcp_transport_unsupported`` — ``[tool.cognic.mcp].transport``
  is missing OR not one of ``http`` / ``streamable-http`` / ``stdio``
  (gate 0 added in T6 R1 P1 #2; previously a missing or unknown
  transport silently skipped the auth probe).
- ``mcp_anonymous_refused`` — neither ``oauth-prm`` nor ``api-key``
  declared in the ``[tool.cognic.mcp]`` block.
- ``mcp_resources_declared_but_no_list`` — ``resources_supported =
  true`` but ``resources_list_supported`` / ``resources_read_supported``
  is missing or false.
- ``mcp_sampling_default_denied`` — ``sampling_supported = true``
  but the four-condition Rego gate (pack + tenant + cloud-policy +
  allow_external_llm consistency) does NOT permit it.
- ``mcp_elicitation_form_restricted_data_class`` — ``elicitation_modes``
  contains ``"form"`` AND any tool's ``data_classes`` includes a
  restricted class (``customer_pii`` / ``payment_action`` /
  ``regulator_communication``). Form-mode elicitation surfaces the
  data into a UI AgentOS can't audit; ADR-002 + ADR-017 forbid the
  combination.
- ``mcp_caching_ttl_restricted_data_class`` — a tool declares
  ``caching_strategy = "ttl"`` AND has restricted ``data_classes``.
  TTL caching of restricted data persists it past the operation it
  was authorised for.
- ``mcp_stdio_manifest_incomplete`` — STDIO transport with missing
  ``command`` / ``args`` / ``env_allowlist`` (gate 1 of ADR-002 §"MCP
  STDIO threat model").
- ``mcp_stdio_manifest_shell_metacharacter`` — STDIO ``command``
  contains shell metachars ``;`` ``|`` ``&`` `` ` `` ``$`` ``(`` ``)``
  ``<`` ``>`` (gate 2 — would otherwise be parsed by a shell).
- ``mcp_stdio_command_not_allowlisted`` — STDIO ``command`` not on
  the per-tenant Vault-stored allow-list (gate 3).
- ``mcp_stdio_disabled_in_sprint_5`` — Decision Lock umbrella
  refusal: even if every other STDIO gate passes, registration in
  Sprint 5 is refused until Sprint 8 lands the sandbox primitive
  (ADR-004). This is the umbrella that makes STDIO fail-closed
  regardless of operator config.

Order of evaluation (first failure wins; tests rely on this order):

  0. Transport closed-enum check (R1 P1 #2 — gate 0 added so a
     correctly-spec'd ``streamable-http`` pack actually invokes the
     auth probe; previously only ``"http"`` matched).
  1. Anonymous-MCP refusal (auth surface — applies to both transports).
  2. Resources gate (HTTP-relevant).
  3. Sampling 4-condition gate (HTTP-relevant; OPA call site).
  4. Elicitation + restricted-data-class gate (transport-agnostic).
  5. Caching TTL + restricted-data-class gate (transport-agnostic).
  6. STDIO gates (only fire when ``transport = "stdio"``):
     a. Manifest-incomplete (shape gate).
     b. Shell-metacharacter (shape gate).
     c. Per-tenant command allow-list (config gate).
     d. Sprint-5 umbrella refusal (Decision Lock — fires LAST so
        operators see the most actionable diagnostic first if a
        prior gate also failed).

Pack-controlled TOML safety (R2 P2): the validator's accessors
(:func:`_mcp_block`, :func:`_tools_block`) walk safely through any
intermediate that's not a dict. A pathological ``manifest = {"tool":
"bad"}`` produces ``ManifestValidation(ok=False,
reason="mcp_transport_unsupported")`` rather than raising
``AttributeError`` mid-flow.

The umbrella is intentionally last so that fixing the earlier shape /
config errors is operator-actionable; once Sprint 8 lifts the
umbrella, the same validator without the final gate becomes the
runtime check.
"""

from __future__ import annotations

import asyncio
import dataclasses
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse

if TYPE_CHECKING:
    from cognic_agentos.core.policy.engine import OPAEngine


#: Closed-enum capability-validator failure vocabulary. Pinned by a
#: drift-detector test (``test_validation_reason_literal_matches_expected_set``
#: in ``test_mcp_capabilities.py``) and by the registry-side
#: ``test_refusal_reason_completeness.py`` regression. Adding a new
#: value is a four-step change per the Sprint-4 closed-enum doctrine
#: (extend literal, extend registry RefusalReason, add registry
#: mapper branch, add test arm).
ValidationReason = Literal[
    "mcp_anonymous_refused",
    "mcp_resources_declared_but_no_list",
    "mcp_sampling_default_denied",
    "mcp_elicitation_form_restricted_data_class",
    "mcp_caching_ttl_restricted_data_class",
    "mcp_stdio_manifest_incomplete",
    "mcp_stdio_manifest_shell_metacharacter",
    "mcp_stdio_command_not_allowlisted",
    "mcp_stdio_disabled_in_sprint_5",
    "mcp_transport_unsupported",
    # T15 R1 P2 #6: HTTP-family manifest shape gate. Catches malformed
    # ``server_url`` / ``scopes`` BEFORE the registration auth probe
    # invokes ``MCPAuthzClient.acquire_token`` with the values. Without
    # this gate, ``scopes = "mcp:tools"`` (string instead of list)
    # becomes ``tuple("mcp:tools")`` — a 9-character tuple whose
    # ``" ".join(...)`` produces the wrong scope-grant string and could
    # under-/over-grant tokens; ``[42]`` crashes at the same join site;
    # blank ``server_url`` reaches httpx with an empty / malformed URL
    # rather than a closed-enum manifest refusal.
    "mcp_http_manifest_shape_invalid",
    # T15 R2 P2: tool ``data_classes`` shape gate. The R1 fail-open
    # helper coerced any non-``list[str]`` shape into an empty set,
    # silently bypassing the form / TTL restricted-data refusals.
    # Reviewer rejected: signed-static manifest contract requires
    # fail-CLOSED on shape violations. This refusal fires whenever a
    # tool block declares ``data_classes`` with a malformed shape
    # (non-list, list-with-non-string, list-with-blank).
    "mcp_tool_data_classes_shape_invalid",
]


#: Closed enum of accepted transport values per MCP-CONFORMANCE.md.
#: ``streamable-http`` is the spec-canonical HTTP transport (per the
#: MCP authorization spec April 2026 revision); ``http`` is accepted
#: as an alias for backward-compatibility with packs authored against
#: an earlier draft (the validator normalises both to the HTTP
#: code path). ``stdio`` is the four-gate-restricted local transport
#: (Decision Lock: hard-disabled in Sprint 5 via the umbrella refusal).
#: Any other transport value fails closed at this gate (R1 P1 #2 —
#: was previously silently accepted, which let a correctly-spec'd
#: ``streamable-http`` pack skip the registration auth probe).
_KNOWN_TRANSPORTS: frozenset[str] = frozenset({"http", "streamable-http", "stdio"})


#: Transport values that map to the HTTP code path (auth-probe at
#: T6.3, runtime via StreamableHTTPTransport at T7).
_HTTP_TRANSPORT_VALUES: frozenset[str] = frozenset({"http", "streamable-http"})


#: Restricted data classes per ADR-017. The form-elicitation gate
#: + the TTL-cache gate both consult this set.
_RESTRICTED_DATA_CLASSES: frozenset[str] = frozenset(
    {
        "customer_pii",
        "payment_action",
        "regulator_communication",
    }
)


#: Forbidden shell metacharacters in STDIO ``command``. If any of
#: these appear, the command was likely meant to be parsed by a
#: shell — exactly what the threat model refuses.
_SHELL_METACHARS: frozenset[str] = frozenset({";", "|", "&", "`", "$", "(", ")", "<", ">"})


#: OPA decision point for the sampling four-condition gate (matches
#: the ``package cognic.sampling`` declaration in
#: ``policies/_default/sampling.rego``).
_SAMPLING_DECISION_POINT = "data.cognic.sampling.allow"


@dataclasses.dataclass(frozen=True, slots=True)
class ValidationContext:
    """All per-tenant + per-call state the validator needs.

    Bundled into a context object (rather than threading individual
    kwargs) so the registry integration can construct one resolved
    snapshot per admission and pass it down without re-fetching from
    Vault / settings on every gate.

    Fields:
      - ``tenant_id`` — the tenant the admission is being performed
        for; used for diagnostics + for Vault-path resolution by the
        caller.
      - ``stdio_command_allowlist`` — frozenset of absolute paths
        permitted as STDIO commands for this tenant; resolved by
        the caller from ``settings.mcp_stdio_command_allowlist_path``.
        Empty set means STDIO is disallowed entirely (the per-tenant
        gate fails-closed when nothing is permitted).
      - ``tenant_sampling_permitted`` — boolean from the tenant's
        sampling policy (Sprint 13.5 will sourced from a richer
        tenant-policy bundle; Sprint 5 takes it as a plain bool the
        caller resolves).
      - ``cloud_policy_tier_consistent`` — boolean: the requested
        sampling tier is consistent with the cloud-policy mode
        (settings.policy_mode + the requested model tier).
      - ``cloud_policy_allow_external_llm_consistent`` — boolean:
        the requested sampling is consistent with
        ``settings.allow_external_llm`` (self-hosted-first
        consistency check per ADR-007).
      - ``opa_engine`` — :class:`OPAEngine` used for the four-condition
        sampling gate. ``None`` is acceptable when the manifest does
        not declare ``sampling_supported = true``; if sampling IS
        declared and ``opa_engine is None`` the validator
        fail-closes with ``mcp_sampling_default_denied`` (default-
        deny posture per Sprint-4 doctrine).
      - ``sampling_policy_bundle`` — Path to the Rego bundle the OPA
        engine was constructed against; carried for diagnostics +
        for the caller to verify bundle consistency.
    """

    tenant_id: str
    stdio_command_allowlist: frozenset[str]
    tenant_sampling_permitted: bool
    cloud_policy_tier_consistent: bool
    cloud_policy_allow_external_llm_consistent: bool
    opa_engine: OPAEngine | None
    sampling_policy_bundle: Path


@dataclasses.dataclass(frozen=True, slots=True)
class ManifestValidation:
    """Outcome of one ``validate_mcp_manifest`` call.

    Mirrors the ``RegistrationOutcome`` shape (Sprint-4 doctrine —
    closed-typed outcome with a closed-enum reason on failure). The
    registry's :meth:`PluginRegistry.register_with_full_attestation_check`
    consumes ``ManifestValidation.reason`` and maps it 1:1 to a
    ``RefusalReason`` literal at the boundary; the validator itself
    never raises a ``RefusalReason`` (different module).

    Fields:
      - ``ok`` — True iff every gate passed.
      - ``reason`` — closed-enum failure reason; ``None`` iff ``ok``.
      - ``payload`` — structured diagnostic dict for audit
        emission. Keys vary by reason; never includes pack code or
        decoded module bodies.
    """

    ok: bool
    reason: ValidationReason | None
    payload: dict[str, Any]


def _safe_get_dict(parent: Any, key: str) -> dict[str, Any]:
    """Defensive dict-only accessor. Returns ``parent[key]`` if it's
    a dict, else an empty dict. ``parent`` itself need not be a dict
    — a non-dict ``parent`` (e.g., the operator wrote ``tool = "bad"``
    in their TOML) is treated identically to an absent key.

    Crashes here would surface as raw ``AttributeError`` from the
    pack-controlled TOML — exactly the wrong shape for a critical-
    controls validator. Pack-shape errors must produce closed-enum
    refusals (or pass through as "no relevant block"), never an
    uncaught exception in the admission pipeline (R2 P2).
    """
    if not isinstance(parent, dict):
        return {}
    value = parent.get(key)
    if not isinstance(value, dict):
        return {}
    return value


def _data_classes_shape_violation(tool: dict[str, Any]) -> dict[str, Any] | None:
    """T15 R2 P2: pack-controlled-TOML SHAPE GATE for ``data_classes``.

    The previous fail-open helper (``_safe_data_classes``) treated any
    non-``list[str]`` shape as "no data classes declared" and silently
    bypassed the form/TTL restricted-data-class refusals — a fail-OPEN
    posture inconsistent with the doctrine that signed-static manifests
    must fail-CLOSED on shape violations (R2 reviewer rejection of the
    R1 fail-open helper).

    This shape-only gate returns a closed-enum refusal payload (caller
    wraps in :class:`ManifestValidation`) when ``data_classes`` is
    present but has an invalid shape. ``data_classes`` is OPTIONAL —
    a tool with no ``data_classes`` key at all (or with an empty list)
    is well-shaped; only an explicit-but-malformed value refuses.

    Returns:
      - ``None`` when the tool's ``data_classes`` is absent OR is a
        well-formed ``list[str]`` of non-empty strings.
      - A diagnostic dict (caller-formed payload) when the shape is
        invalid: non-list shape, list with non-string element,
        list with empty/whitespace-only string, etc.

    The cosign-signed manifest with a malformed ``data_classes`` field
    is a manifest defect by ADR-002 / ADR-017 contract; the validator
    MUST surface a closed-enum refusal so the downstream admission
    pipeline produces a refusal audit row rather than silently
    proceeding with the gates skipped.
    """
    if "data_classes" not in tool:
        return None
    raw = tool["data_classes"]
    if not isinstance(raw, list):
        return {
            "tool_name": tool.get("name"),
            "field": "data_classes",
            "declared_type": type(raw).__name__,
            "reason_detail": "data_classes must be a list of non-empty strings",
        }
    for entry in raw:
        if not isinstance(entry, str):
            return {
                "tool_name": tool.get("name"),
                "field": "data_classes",
                "reason_detail": ("every data_classes entry must be a non-empty string"),
                "malformed_entry_type": type(entry).__name__,
            }
        if not entry.strip():
            return {
                "tool_name": tool.get("name"),
                "field": "data_classes",
                "reason_detail": "data_classes entries must not be empty / whitespace-only",
            }
    return None


def _normalise_data_classes(tool: dict[str, Any]) -> set[str]:
    """Return the tool's ``data_classes`` as a normalised
    ``set[str]``. CALLER MUST have already validated shape via
    :func:`_data_classes_shape_violation` — passing a malformed shape
    here is undefined behaviour (the function trusts its input).

    Whitespace-only strings have already been rejected at the shape
    gate; non-list shapes have already been rejected. So this is a
    pure ``set(tool["data_classes"])`` with the absent-key fallback
    to empty set.
    """
    raw = tool.get("data_classes", [])
    return {item.strip() for item in raw if isinstance(item, str) and item.strip()}


def _mcp_block(manifest: dict[str, Any]) -> dict[str, Any]:
    """Safe accessor for ``[tool.cognic.mcp]`` — returns ``{}`` if
    any intermediate key is missing OR any intermediate (incl. the
    leaf) is not a dict. Used so a malformed-shape manifest never
    raises an uncaught ``AttributeError`` before the closed-enum
    gates fire (R2 P2)."""
    tool = _safe_get_dict(manifest, "tool")
    cognic = _safe_get_dict(tool, "cognic")
    return _safe_get_dict(cognic, "mcp")


def _tools_block(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Safe accessor for ``[[tool.cognic.tools]]`` — returns ``[]``
    if missing or malformed (the validator's restricted-data-class
    gates iterate this list; absent / malformed ⇒ no tools to check).
    Tolerates non-dict intermediates the same way :func:`_mcp_block`
    does (R2 P2)."""
    tool = _safe_get_dict(manifest, "tool")
    cognic = _safe_get_dict(tool, "cognic")
    tools = cognic.get("tools", [])
    if not isinstance(tools, list):
        return []
    return [t for t in tools if isinstance(t, dict)]


async def validate_mcp_manifest(
    manifest: dict[str, Any],
    *,
    context: ValidationContext,
) -> ManifestValidation:
    """Validate an MCP pack manifest dict against the Sprint-5 ten
    capability-side gates (see :data:`ValidationReason` for the
    closed-enum vocabulary; T6 R1 P1 #2 added ``mcp_transport_unsupported``
    to the original nine).

    Pure-functional except for the OPA evaluation in the sampling
    gate (only invoked when the manifest declares
    ``sampling_supported = true``). All other gates are local
    dict-shape checks; module imports + construction succeed without
    the ``mcp`` SDK or the OPA binary installed.

    Pack-controlled TOML safety (R2 P2): manifest accessors walk
    safely through non-dict intermediates. A pathological
    ``manifest = {"tool": "bad"}`` produces ``ManifestValidation(
    ok=False, reason="mcp_transport_unsupported")`` rather than
    raising ``AttributeError`` mid-flow. The validator MUST never
    crash on pack-controlled input — closed-enum refusals only.

    See module docstring for the full closed-enum vocabulary,
    evaluation order, and order-rationale (the Sprint-5 STDIO
    umbrella fires LAST so operators see actionable shape /
    metacharacter / allow-list diagnostics first).
    """
    mcp = _mcp_block(manifest)

    # Gate 0: transport closed-enum check (R1 P1 #2). The auth-probe
    # in T6.3 only fires for HTTP-family transports; any unsupported
    # transport value would otherwise silently fall through and skip
    # the OAuth/PRM probe entirely — exactly what the user's R1 P1
    # caught. Reject anything outside ``_KNOWN_TRANSPORTS`` here,
    # before any later gate has a chance to mis-route the pack.
    # The ``isinstance(str)`` guard avoids ``TypeError: unhashable``
    # on non-string shapes (e.g., list / dict) that can't be looked
    # up in a frozenset[str].
    transport = mcp.get("transport")
    if not isinstance(transport, str) or transport not in _KNOWN_TRANSPORTS:
        return ManifestValidation(
            ok=False,
            reason="mcp_transport_unsupported",
            payload={
                "declared_transport": transport,
                "supported_transports": sorted(_KNOWN_TRANSPORTS),
            },
        )

    # Gate 1: anonymous-MCP refusal (transport-agnostic). Every MCP
    # pack MUST declare an auth surface — either oauth-prm
    # (Sprint-5 default) or api-key (Wave 1 fallback). Missing or
    # explicit "anonymous" → refused.
    auth = mcp.get("auth")
    if auth is None or auth == "anonymous":
        return ManifestValidation(
            ok=False,
            reason="mcp_anonymous_refused",
            payload={"declared_auth": auth},
        )

    # Gate 1.5 (T15 R1 P2 #6): HTTP-family manifest shape check. Fires
    # only for HTTP transports (STDIO has its own gates 6.a-d below).
    # ``server_url`` MUST be a non-empty string; ``scopes`` MUST be
    # a list/tuple of non-empty strings. Without this gate, a string
    # ``scopes = "mcp:tools"`` becomes a 9-element tuple of characters
    # downstream (``tuple("mcp:tools")``) — silently corrupting the
    # token's scope grant. ``[42]`` crashes at ``" ".join(...)`` time
    # in ``_request_token``. Blank or non-URL ``server_url`` reaches
    # httpx as an unrouteable address rather than producing a closed-
    # enum manifest refusal. Catching all three at admission keeps the
    # auth probe + runtime invocation paths free of pack-controlled
    # type confusion.
    if transport in _HTTP_TRANSPORT_VALUES:
        server_url = mcp.get("server_url")
        if not isinstance(server_url, str) or not server_url.strip():
            return ManifestValidation(
                ok=False,
                reason="mcp_http_manifest_shape_invalid",
                payload={
                    "field": "server_url",
                    "declared_type": type(server_url).__name__,
                    "reason_detail": "server_url must be a non-empty string",
                },
            )
        # Remediation §4.1 — admission-time SSRF pre-filter: server_url MUST be
        # http/https so a non-fetchable scheme (file://, gopher://, ...) is
        # refused at the manifest boundary, not at the discovery fetch.
        if urlparse(server_url).scheme not in {"http", "https"}:
            return ManifestValidation(
                ok=False,
                reason="mcp_http_manifest_shape_invalid",
                payload={
                    "field": "server_url",
                    "declared_type": type(server_url).__name__,
                    "reason_detail": "server_url scheme must be http or https",
                },
            )
        scopes = mcp.get("scopes")
        if not isinstance(scopes, list | tuple):
            return ManifestValidation(
                ok=False,
                reason="mcp_http_manifest_shape_invalid",
                payload={
                    "field": "scopes",
                    "declared_type": type(scopes).__name__,
                    "reason_detail": "scopes must be a list of strings",
                },
            )
        for entry in scopes:
            if not isinstance(entry, str) or not entry.strip():
                return ManifestValidation(
                    ok=False,
                    reason="mcp_http_manifest_shape_invalid",
                    payload={
                        "field": "scopes",
                        "reason_detail": ("every scope must be a non-empty string"),
                        "malformed_entry_type": type(entry).__name__,
                    },
                )

    # Gate 2: resources gate. ``resources_supported = true`` requires
    # both ``resources_list_supported`` and ``resources_read_supported``;
    # MCP server can't expose resources without the read primitive.
    if mcp.get("resources_supported") is True and (
        not mcp.get("resources_list_supported") or not mcp.get("resources_read_supported")
    ):
        return ManifestValidation(
            ok=False,
            reason="mcp_resources_declared_but_no_list",
            payload={
                "resources_supported": True,
                "resources_list_supported": mcp.get("resources_list_supported"),
                "resources_read_supported": mcp.get("resources_read_supported"),
            },
        )

    # Gate 3: sampling four-condition default-deny via OPA.
    if mcp.get("sampling_supported") is True:
        if context.opa_engine is None:
            # Default-deny when OPA is unavailable (Sprint-4 doctrine
            # — any policy-engine unavailability is a deny).
            return ManifestValidation(
                ok=False,
                reason="mcp_sampling_default_denied",
                payload={
                    "reason_detail": "opa_engine_unavailable",
                    "sampling_policy_bundle": str(context.sampling_policy_bundle),
                },
            )
        # T15 R1 P2 #5: an installed OPA engine that raises during
        # ``evaluate()`` (subprocess timeout, JSON-decode failure,
        # malformed Rego output, OPA binary missing from PATH at
        # runtime) MUST default-deny rather than letting the raw
        # exception propagate. Per Sprint-4 doctrine + ADR-015
        # §"Default-deny posture": any policy-engine unavailability
        # is a deny. Without the wrap, a raw exception would bypass
        # the closed-enum ``ManifestValidation`` envelope and skip
        # the registration-refusal evidence path.
        # ``CancelledError`` is intentionally NOT caught — task
        # cancellation should propagate. ``type(exc).__name__`` is
        # carried in the payload for diagnostics; raw ``str(exc)``
        # is intentionally NOT included (could leak Rego source
        # fragments, file-system paths, or subprocess stderr text).
        try:
            decision = await context.opa_engine.evaluate(
                decision_point=_SAMPLING_DECISION_POINT,
                input={
                    "pack": {"sampling_supported": True},
                    "tenant": {"sampling_permitted": context.tenant_sampling_permitted},
                    "cloud_policy": {
                        "tier_consistent": context.cloud_policy_tier_consistent,
                        "allow_external_llm_consistent": (
                            context.cloud_policy_allow_external_llm_consistent
                        ),
                    },
                },
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            return ManifestValidation(
                ok=False,
                reason="mcp_sampling_default_denied",
                payload={
                    "reason_detail": "opa_evaluate_failed",
                    "sampling_policy_bundle": str(context.sampling_policy_bundle),
                    "error_type": type(exc).__name__,
                },
            )
        if not decision.allow:
            return ManifestValidation(
                ok=False,
                reason="mcp_sampling_default_denied",
                payload={
                    "tenant_sampling_permitted": context.tenant_sampling_permitted,
                    "cloud_policy_tier_consistent": context.cloud_policy_tier_consistent,
                    "cloud_policy_allow_external_llm_consistent": (
                        context.cloud_policy_allow_external_llm_consistent
                    ),
                    "rule_matched": decision.rule_matched,
                },
            )

    # Gate 3.5 (T15 R2 P2): tool-block ``data_classes`` shape gate.
    # Refuses fail-CLOSED on any tool whose ``data_classes`` is
    # present-but-malformed (non-list, list-with-non-string,
    # list-with-blank-string). Fires before gates 4 + 5 consume the
    # field so a malformed value can never silently bypass the
    # restricted-data refusals downstream. Tools that omit
    # ``data_classes`` entirely (or declare an empty list) are
    # well-shaped and pass; only an explicit-but-malformed value is a
    # refusal. Reviewer rejected the R1 fail-OPEN coercion-to-empty-set
    # behaviour: signed-static manifest contract requires fail-CLOSED.
    for tool in _tools_block(manifest):
        violation = _data_classes_shape_violation(tool)
        if violation is not None:
            return ManifestValidation(
                ok=False,
                reason="mcp_tool_data_classes_shape_invalid",
                payload=violation,
            )

    # Gate 4: elicitation form mode + restricted data-class.
    # Shape gate above guarantees ``data_classes`` is well-formed
    # (or absent) for every tool the gate iterates here.
    elicitation_modes = mcp.get("elicitation_modes", [])
    if isinstance(elicitation_modes, list) and "form" in elicitation_modes:
        for tool in _tools_block(manifest):
            tool_data_classes = _normalise_data_classes(tool)
            restricted_intersect = tool_data_classes & _RESTRICTED_DATA_CLASSES
            if restricted_intersect:
                return ManifestValidation(
                    ok=False,
                    reason="mcp_elicitation_form_restricted_data_class",
                    payload={
                        "tool_name": tool.get("name"),
                        "restricted_data_classes": sorted(restricted_intersect),
                    },
                )

    # Gate 5: TTL caching + restricted data-class.
    for tool in _tools_block(manifest):
        if tool.get("caching_strategy") == "ttl":
            tool_data_classes = _normalise_data_classes(tool)
            restricted_intersect = tool_data_classes & _RESTRICTED_DATA_CLASSES
            if restricted_intersect:
                return ManifestValidation(
                    ok=False,
                    reason="mcp_caching_ttl_restricted_data_class",
                    payload={
                        "tool_name": tool.get("name"),
                        "restricted_data_classes": sorted(restricted_intersect),
                    },
                )

    # Gates 6.a-d: STDIO transport (only evaluated when transport=="stdio").
    if mcp.get("transport") == "stdio":
        # 6.a: manifest-incomplete (command + args + env_allowlist all required)
        if (
            mcp.get("command") is None
            or mcp.get("args") is None
            or mcp.get("env_allowlist") is None
        ):
            return ManifestValidation(
                ok=False,
                reason="mcp_stdio_manifest_incomplete",
                payload={
                    "has_command": mcp.get("command") is not None,
                    "has_args": mcp.get("args") is not None,
                    "has_env_allowlist": mcp.get("env_allowlist") is not None,
                },
            )
        # 6.b: shell-metacharacter. A non-string command (e.g., the
        # operator typed a list — shape mistake) skips the
        # set-intersection (which would otherwise raise on a list
        # iteration of multi-character strings) and lands at the
        # per-tenant allow-list gate, which fail-closes for any
        # non-string by construction.
        command = mcp["command"]
        if isinstance(command, str):
            metacharacters_present = sorted(set(command) & _SHELL_METACHARS)
            if metacharacters_present:
                return ManifestValidation(
                    ok=False,
                    reason="mcp_stdio_manifest_shell_metacharacter",
                    payload={
                        "command": command,
                        "metacharacters": metacharacters_present,
                    },
                )
        # 6.c: per-tenant allow-list. Non-string commands fail-closed
        # at the type guard (the frozenset[str] would otherwise
        # TypeError on unhashable shapes like list / dict).
        if not isinstance(command, str) or command not in context.stdio_command_allowlist:
            return ManifestValidation(
                ok=False,
                reason="mcp_stdio_command_not_allowlisted",
                payload={
                    "command": command,
                    "tenant_id": context.tenant_id,
                    "allowlist_size": len(context.stdio_command_allowlist),
                },
            )
        # 6.d: Decision Lock umbrella refusal — Sprint 5.
        # Even if every prior STDIO gate passed, registration is
        # refused until Sprint 8 (sandbox primitive). The umbrella
        # is intentionally LAST so operators see the actionable shape
        # / metacharacter / allow-list diagnostics first; once Sprint
        # 8 lifts this gate, the validator becomes the runtime check.
        return ManifestValidation(
            ok=False,
            reason="mcp_stdio_disabled_in_sprint_5",
            payload={
                "command": command,
                "decision_lock_doctrine": (
                    "STDIO refused at admission until Sprint 8 sandbox primitive"
                ),
            },
        )

    # All gates passed.
    return ManifestValidation(ok=True, reason=None, payload={})


__all__ = (
    "ManifestValidation",
    "ValidationContext",
    "ValidationReason",
    "validate_mcp_manifest",
)
