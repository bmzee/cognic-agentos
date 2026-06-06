"""Plugin registry — entry-point discovery + registration substrate.

Critical-controls module per AGENTS.md (pack-trust attack surface).
Sprint 4 lands the API surface; T10 wires the full
discover → trust → supply-chain → policy → register pipeline.

§1 of the Sprint-4 plan-of-record locks the discovery contract:

  * ``discover()`` walks ``importlib.metadata.entry_points(group=...)``
    for the three pack-kind groups (``cognic.tools`` / ``cognic.skills``
    / ``cognic.agents``). Each ``EntryPoint.load()`` is **deferred** to
    ``PluginRegistry.load(kind, name)`` — eager loading would import
    every pack at startup, defeating the trust gate's pre-import
    verification (ADR-002 §"MCP STDIO threat model").
  * ``load(kind, name)`` is **synchronous** (R2-#2 reviewer-fix). It is
    a thin wrapper over the stdlib ``EntryPoint.load()``; no audit
    emission, no I/O beyond the import. Registration is where the
    audit / evidence trail lives.
  * ``register(...)`` emits ``audit_event(plugin.registration_succeeded)``
    or ``audit_event(plugin.registration_refused)`` chained into the
    Sprint-2 hash-chain substrate.

The ``RegistrationOutcome`` shape is the cross-sprint contract — its
field names are consumed by the T10 startup log and the T11
``/api/v1/system/plugins`` endpoint. The ``refusal_reason`` Literal is a
**closed enum**: each new refusal class requires a new branch in T10
registry assembly + a new test arm + (if operator-facing) a new
mapping in T11 (R3-#1 reviewer-fix).
"""

from __future__ import annotations

import asyncio
import importlib.metadata as _im
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from cognic_agentos.core.audit import AuditEvent, AuditStore

if TYPE_CHECKING:
    # Imported under TYPE_CHECKING to avoid an import-time cycle:
    # supply_chain.py already imports from trust_gate.py, and
    # plugin_registry needs both for the T10 integration. Keeping
    # these import-only for type-checking lets PluginRegistry stay a
    # safe import target for tests / lifespan code that don't touch
    # the T10 code path.
    from collections.abc import Callable

    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.policy.engine import OPAEngine
    from cognic_agentos.db.adapters.protocols import ObjectStoreAdapter, SecretAdapter
    from cognic_agentos.protocol.mcp_authz import MCPAuthzClient
    from cognic_agentos.protocol.supply_chain import (
        SupplyChainPipeline,
        VulnThresholds,
    )
    from cognic_agentos.protocol.trust_gate import TrustGate

_LOG = logging.getLogger("cognic_agentos.protocol.plugin_registry")

PluginKind = Literal["tools", "skills", "agents"]

#: Sprint-4 pack-kind → entry-point group mapping. The three groups are
#: the ADR-002 contract — adding a fourth pack kind is a doctrine-level
#: change (new ADR or ADR amendment), not a code-change.
_ENTRY_POINT_GROUPS: dict[PluginKind, str] = {
    "tools": "cognic.tools",
    "skills": "cognic.skills",
    "agents": "cognic.agents",
}

#: Closed enum of refusal classes. Adding a new value is a four-step
#: change: (1) extend this Literal, (2) extend the matching field on
#: ``RegistrationOutcome.refusal_reason``, (3) add a new branch in T10
#: registry assembly, (4) add a new test arm. Closed-vocabulary trade
#: makes Sprint 7B's reviewer dashboard + Sprint 13.5's OPA bundles
#: stable across sprint boundaries.
RefusalReason = Literal[
    # Sprint 4 — existing (8 values)
    "not_in_tenant_allowlist",
    "cosign_verification_failed",
    "sbom_missing",
    "sigstore_bundle_persistence_failed",
    "slsa_tampered",
    "intoto_tampered",
    "sbom_tampered",
    "policy_denied_partial_grade",
    # Sprint 5 — manifest extraction failures (T6.1; 2 values)
    "mcp_manifest_missing",  # RESERVED for a future explicit MCP-intent path (Sprint-7A
    # ``agentos validate`` or future MCP-specific entry-point group); current T6 admission
    # treats absent ``cognic-pack-manifest.toml`` as "no MCP intent" and proceeds — no
    # admission code path emits this today (R2 doctrine; see _mcp_admit + mcp_manifest
    # module docstring). Mapper kept reserved so the future caller has the literal ready.
    "mcp_manifest_malformed",  # TOML invalid OR present-but-non-dict [tool.cognic.mcp] (R2 P1)
    # Sprint 5 — capability-validator failures (T6.2; 10 values)
    "mcp_anonymous_refused",  # neither oauth-prm nor api-key declared
    "mcp_resources_declared_but_no_list",  # resources_supported=true but list/read missing
    "mcp_sampling_default_denied",  # 4-condition gate failed
    "mcp_elicitation_form_restricted_data_class",  # form mode + PII/payment/regulator
    "mcp_caching_ttl_restricted_data_class",  # ttl cache for restricted data class
    "mcp_stdio_manifest_incomplete",  # STDIO missing command/args/env_allowlist
    "mcp_stdio_manifest_shell_metacharacter",  # STDIO command contains shell metachars
    "mcp_stdio_command_not_allowlisted",  # STDIO command not on per-tenant allow-list
    "mcp_stdio_disabled_in_sprint_5",  # umbrella refusal until Sprint 8
    "mcp_transport_unsupported",  # transport != known set (R1 P1 #2 — was silent skip)
    "mcp_http_manifest_shape_invalid",  # HTTP server_url/scopes shape (T15 R1 P2 #6)
    "mcp_tool_data_classes_shape_invalid",  # tool data_classes shape (T15 R2 P2)
    # Sprint 5 — registration auth-probe failures (T6.3; 11 values)
    "mcp_as_not_allowlisted",  # PRM advertises non-allowlisted AS
    "mcp_token_audience_mismatch",  # token aud != resource indicator
    "mcp_token_scope_overgrant",  # AS granted scopes not in manifest set (R6)
    "mcp_oauth_request_timeout",  # PRM/token request exceeded timeout
    "mcp_oauth_transport_failure",  # DNS/TLS/network unreachable on PRM/AS/token (R6)
    "mcp_oauth_credentials_missing",  # Vault has no client_id/client_secret/auth_method (R6)
    "mcp_oauth_as_discovery_invalid",  # AS .well-known/oauth-authorization-server bad (R11)
    "mcp_oauth_token_endpoint_error",  # AS token endpoint non-200 (R11)
    "mcp_oauth_token_response_invalid",  # token response shape malformed (R11)
    "mcp_prm_invalid",  # PRM document malformed (MCP server side)
    "mcp_discovery_url_refused",  # SSRF guard refused a discovery/PRM fetch URL (remediation §4.1)
    "mcp_api_key_fallback_unresolved",  # api-key fallback Vault path / secret invalid
    # Sprint 5 — registry-configuration failures (T6.3; 1 value)
    "mcp_admission_deps_required",  # MCP block declared but mcp_admission=None (R1 P1 #1)
]

AttestationGrade = Literal["full", "partial"]

_VALID_REFUSAL_REASONS: frozenset[str] = frozenset(
    {
        # Sprint 4
        "not_in_tenant_allowlist",
        "cosign_verification_failed",
        "sbom_missing",
        "sigstore_bundle_persistence_failed",
        "slsa_tampered",
        "intoto_tampered",
        "sbom_tampered",
        "policy_denied_partial_grade",
        # Sprint 5 — manifest (2). Same reserved/future status as the
        # literal above: ``mcp_manifest_missing`` is in the validset
        # for type-checker + drift-detector consistency but no current
        # T6 admission code path emits it (R2 doctrine).
        "mcp_manifest_missing",
        "mcp_manifest_malformed",
        # Sprint 5 — capability (12; was 10 pre-T15-R1, 11 after T15 R1 P2 #6)
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
        "mcp_http_manifest_shape_invalid",  # T15 R1 P2 #6
        "mcp_tool_data_classes_shape_invalid",  # T15 R2 P2
        # Sprint 5 — auth-probe (11)
        "mcp_as_not_allowlisted",
        "mcp_token_audience_mismatch",
        "mcp_token_scope_overgrant",
        "mcp_oauth_request_timeout",
        "mcp_oauth_transport_failure",
        "mcp_oauth_credentials_missing",
        "mcp_oauth_as_discovery_invalid",
        "mcp_oauth_token_endpoint_error",
        "mcp_oauth_token_response_invalid",
        "mcp_prm_invalid",
        "mcp_discovery_url_refused",  # remediation §4.1
        "mcp_api_key_fallback_unresolved",
        # Sprint 5 — registry configuration (1)
        "mcp_admission_deps_required",
    }
)


#: 1:1 mapping from MCPAuthzClient's :data:`AuthzReason` vocabulary
#: to :data:`RefusalReason`. Both literals share the same underlying
#: strings for the eleven registration-boundary reasons; the mapper
#: exists as a single typed change site so a future divergence
#: between the two vocabularies (if it ever happens) lives here, not
#: scattered across the registry's exception-handling code.
#:
#: ``mcp_step_up_unauthorised`` is **runtime-only** — emitted by
#: :meth:`MCPHost.call_tool`'s step-up flow at T9, NEVER from a
#: registration-time auth probe. Passing it to this mapper is a
#: programming error and raises :class:`ValueError`.
_AUTHZ_REASON_TO_REFUSAL: dict[str, RefusalReason] = {
    "mcp_anonymous_refused": "mcp_anonymous_refused",
    "mcp_as_not_allowlisted": "mcp_as_not_allowlisted",
    "mcp_token_audience_mismatch": "mcp_token_audience_mismatch",
    "mcp_token_scope_overgrant": "mcp_token_scope_overgrant",
    "mcp_oauth_request_timeout": "mcp_oauth_request_timeout",
    "mcp_oauth_transport_failure": "mcp_oauth_transport_failure",
    "mcp_oauth_credentials_missing": "mcp_oauth_credentials_missing",
    "mcp_oauth_as_discovery_invalid": "mcp_oauth_as_discovery_invalid",
    "mcp_oauth_token_endpoint_error": "mcp_oauth_token_endpoint_error",
    "mcp_oauth_token_response_invalid": "mcp_oauth_token_response_invalid",
    "mcp_prm_invalid": "mcp_prm_invalid",
    "mcp_discovery_url_refused": "mcp_discovery_url_refused",
}


_RUNTIME_ONLY_AUTHZ_REASONS: frozenset[str] = frozenset(
    {
        # Emitted from MCPAuthzClient.step_up_token (T5) when a 403
        # insufficient_scope demands a wider scope the manifest does
        # not declare.
        "mcp_step_up_unauthorised",
        # Emitted from MCPHost.call_tool (T9 R1 P2 #3) when the
        # second-401 retry fails — both the cached and
        # freshly-acquired tokens were rejected by the MCP server.
        "mcp_authorisation_lost",
    }
)


def _authz_reason_to_refusal(authz_reason: str) -> RefusalReason:
    """Map an :class:`MCPAuthzError.reason` string to the
    corresponding :data:`RefusalReason`.

    Eleven reasons map identity-style (the two literals share strings
    for the registration-boundary set). The two runtime-only reasons
    (``mcp_step_up_unauthorised``, ``mcp_authorisation_lost``) raise
    here — they must never reach the registration-side mapper.

    :param authz_reason: A value of :data:`AuthzReason` from
        :class:`cognic_agentos.protocol.mcp_authz.MCPAuthzError`.
    :returns: The matching :data:`RefusalReason` literal.
    :raises ValueError: If ``authz_reason`` is one of
        :data:`_RUNTIME_ONLY_AUTHZ_REASONS` or any unknown value
        (defensive — would mean a closed-enum drift between the
        AuthzReason and RefusalReason vocabularies that the
        ``test_refusal_reason_completeness.py`` regression should
        have caught at type-check time).
    """
    if authz_reason in _RUNTIME_ONLY_AUTHZ_REASONS:
        raise ValueError(
            f"{authz_reason!r} is runtime-only (emitted from MCPHost "
            f"or MCPAuthzClient runtime flows, not from the registration "
            f"pipeline); it MUST NOT reach the registration-boundary "
            f"refusal mapper. Runtime-only reasons: "
            f"{sorted(_RUNTIME_ONLY_AUTHZ_REASONS)}."
        )
    try:
        return _AUTHZ_REASON_TO_REFUSAL[authz_reason]
    except KeyError as exc:
        raise ValueError(
            f"Unknown AuthzReason {authz_reason!r}; the closed-enum "
            f"drift detector (test_refusal_reason_completeness.py) "
            f"should have caught this at type-check time."
        ) from exc


@dataclass(frozen=True, slots=True)
class MCPAdmissionDeps:
    """Optional MCP admission dependencies.

    When provided to :meth:`PluginRegistry.register_with_full_attestation_check`,
    the three Sprint-5 MCP admission steps fire in order between the
    Sprint-4 cryptographic gates (cosign + SBOM + Sigstore-bundle
    persist) and the policy-engine grade evaluation:

      A. Manifest extraction (T6.1) — read
         ``cognic-pack-manifest.toml`` via
         :func:`cognic_agentos.protocol.mcp_manifest.extract_pack_manifest`.
         Outcomes per R2 doctrine: **missing manifest proceeds** (no
         MCP intent — Sprint-4-style pack); **TOML decode failure**
         refuses with ``mcp_manifest_malformed`` (always, regardless
         of pack intent — cosign-signed bytes); **present-but-non-
         dict ``[tool.cognic.mcp]`` block** refuses with
         ``mcp_manifest_malformed`` via the registry's safe walk
         (R2 P1). Note: ``mcp_manifest_missing`` is a closed-enum
         literal RESERVED for a future explicit MCP-intent path
         (Sprint-7A ``agentos validate`` or future MCP-specific
         entry-point group); current T6 admission deliberately does
         NOT emit it because the manifest's well-shaped ``[tool.cognic.mcp]``
         block is the only valid MCP-intent signal — ``mcp_admission``
         is dependency wiring, not pack intent.
      B. Capability validation (T6.2) — pure-functional check via
         :func:`cognic_agentos.protocol.mcp_capabilities.validate_mcp_manifest`.
         Closed-enum failures map 1:1 to the matching
         ``mcp_*`` :data:`RefusalReason`.
      C. Registration-time auth probe (T6.3) — for HTTP transport
         only; STDIO is umbrella-refused upstream by the validator.
         For ``auth = "oauth-prm"``: construct a fresh
         :class:`MCPAuthzClient` (via
         :attr:`make_authz_client_for_probe`), call
         :meth:`MCPAuthzClient.acquire_token`, discard the returned
         token. Failures map via :func:`_authz_reason_to_refusal`.
         For ``auth = "api-key"``: validate Vault path resolves AND
         secret is non-empty AND manifest acknowledges deprecation;
         any failure → ``mcp_api_key_fallback_unresolved``.

    When ``mcp_admission`` is ``None`` (kernel-image deployment
    without ``MCPHost`` wired), manifest extraction STILL RUNS
    (always — per R2 #1) so the MCP-intent check below can fire:

      - **Manifest absent** → no MCP intent; admission proceeds
        straight to the policy-engine evaluation (Sprint-4 path).
      - **Manifest present without ``[tool.cognic.mcp]``** → also
        no MCP intent; same proceed path.
      - **Manifest present with ``[tool.cognic.mcp]``** AND
        ``mcp_admission`` is ``None`` → registry refuses
        fail-closed with ``mcp_admission_deps_required`` (R1 P1
        #1). MCP packs cannot register on a kernel image without
        the admission infra wired.
      - **Manifest present with malformed ``[tool.cognic.mcp]``**
        (non-dict shape, e.g., ``mcp = "bad"``) → registry refuses
        fail-closed with ``mcp_manifest_malformed`` (R2 P1).

    R2 doctrine: ``mcp_admission`` is **dependency wiring**, NOT
    pack-intent. A default-adapters caller may legitimately pass
    these deps for every registration; they do NOT cause Sprint-4
    packs to be rejected. The MCP-intent signal is the manifest's
    well-shaped ``[tool.cognic.mcp]`` block — nothing else.

    Fields:
      - ``settings`` — for the STDIO command-allowlist Vault path
        template + the sampling-policy bundle path.
      - ``vault_client`` — for resolving the per-tenant STDIO
        command allow-list AND the api-key fallback secret.
      - ``opa_engine`` — for the four-condition sampling gate; pass
        ``None`` if no MCP pack will declare ``sampling_supported =
        true`` (the validator fail-closes with
        ``mcp_sampling_default_denied`` when sampling is required
        but the engine is missing — Sprint-4 default-deny doctrine).
      - ``make_authz_client_for_probe`` — factory returning a fresh
        :class:`MCPAuthzClient` per probe. The factory pattern keeps
        the probe's token cache isolated from the runtime client's
        cache, satisfying the "token-acquired-but-not-stored" probe
        contract per ADR-002 §"MCP Authorization" step 8 (R10's
        exact-match cache invariant means a leaked probe token
        would otherwise be reused by the runtime client's first
        call).
    """

    settings: Settings
    vault_client: SecretAdapter
    opa_engine: OPAEngine | None
    make_authz_client_for_probe: Callable[[], MCPAuthzClient]


@dataclass(frozen=True, slots=True)
class PluginRecord:
    """Discovered entry-point metadata BEFORE any pack code is loaded.

    Captured by ``discover()`` walking ``importlib.metadata``. The
    distribution name + version are the cosign-signature identity — the
    trust gate (T6) verifies the signature over THIS metadata, not over
    code loaded into the interpreter.
    """

    kind: PluginKind
    name: str
    distribution_name: str
    distribution_version: str
    entry_point_value: str


@dataclass(frozen=True, slots=True)
class RegistrationOutcome:
    """Outcome of one ``PluginRegistry.register`` call.

    Sprint 4 ships flat outcomes (``registered`` /
    ``refused_at_registration``). The full ADR-012 lifecycle (submitted
    / under_review / approved / allow_listed / installed / revoked /
    uninstalled) lands in Sprint 7B and extends this enum.

    Field-name contract is consumed by:
      * T10 startup-log (``logger.info`` extra={...} shape)
      * T11 ``/api/v1/system/plugins`` response — ``name`` (entry-point
        identifier) and ``pack_id`` (distribution name) are reported
        separately so a single distribution exposing several entry
        points renders correctly. R2 reviewer-P2 fix.
      * Future Sprint 7B reviewer-flow (extends, does not break)
    """

    status: Literal["registered", "refused_at_registration"]
    name: str
    pack_id: str
    version: str
    kind: PluginKind
    attestation_grade: AttestationGrade | None
    refusal_reason: RefusalReason | None
    signature_digest: str | None
    registered_at: datetime | None


@dataclass(frozen=True, slots=True)
class DiscoveredPack:
    """Output of ``PluginRegistry.discover()``.

    Pairs the ``PluginRecord`` (metadata only — what the trust gate
    needs to verify) with the captured stdlib ``EntryPoint`` (deferred
    — never ``load()``-ed at discovery time). T10's pipeline consumes
    a single ``DiscoveredPack`` per pack and forwards it to
    ``register()`` once trust + supply-chain + policy decisions are
    final. R2 reviewer-P2: previous shape returned only ``PluginRecord``
    and forced callers to manually re-supply the EntryPoint at
    register time, breaking the public discover→register→load flow.
    """

    record: PluginRecord
    entry_point: _im.EntryPoint


class PluginIdentityConflict(RuntimeError):
    """Raised by ``PluginRegistry.register`` when two PluginRecords
    sharing the same ``(kind, name)`` key carry different
    distribution metadata.

    Two installed distributions exposing the same entry-point name
    silently overwriting each other in the registry would be a
    plugin-trust attack surface — a malicious second pack could
    shadow a legitimate first. The registry rejects the conflict
    rather than picking a winner; operators must resolve by
    uninstalling one of the conflicting distributions. R2 reviewer-
    P2 fix. Re-registering the same identity (e.g. after fixing a
    refusal cause) IS allowed and replaces the previous outcome.
    """


class RegistrationRefused(RuntimeError):
    """Raised by ``PluginRegistry.load`` when the requested pack was
    refused at registration time. Encodes the refusal class so callers
    can classify the failure without re-parsing audit events."""

    def __init__(self, kind: PluginKind, name: str, refusal_reason: RefusalReason) -> None:
        super().__init__(
            f"pack {kind}/{name!r} was refused at registration "
            f"({refusal_reason}); load() is forbidden until registration "
            f"succeeds (re-register after addressing the refusal cause)"
        )
        self.kind = kind
        self.name = name
        self.refusal_reason = refusal_reason


class PluginNotRegistered(LookupError):
    """Raised by ``PluginRegistry.load`` for a (kind, name) that has
    never been ``register``-ed. Distinct from ``RegistrationRefused``
    so callers can distinguish "never asked" from "asked and refused"."""


@dataclass(frozen=True, slots=True)
class PackAttestations:
    """Paths to a pack's attestation artefacts plus the cosign-signed
    SBOM digest that pins SBOM authenticity.

    T10 takes this as a single bundle so the integration call site
    stays readable. Conventionally rooted at
    ``<attestation_root>/<pack_id>/<version>/`` but callers can
    supply arbitrary paths. The four grace-period attestations
    (SLSA / in-toto / vuln / license) are Optional — absent files
    demote the grade to ``partial`` rather than refusing.
    """

    cosign_signature_path: Path
    cosign_blob_path: Path
    cosign_trust_root: Path
    sbom_path: Path
    #: SHA-256 of the SBOM bytes as the pack's cosign signature
    #: declares it. T7 verifies SBOM file content matches this digest.
    sbom_signed_digest: str
    #: Sigstore bundle file — bytes are read by T10 and persisted to
    #: the object store via T9 with 7-year retention.
    sigstore_bundle_path: Path
    slsa_provenance_path: Path | None = None
    intoto_layout_path: Path | None = None
    vuln_scan_path: Path | None = None
    license_audit_path: Path | None = None


@dataclass(slots=True)
class _RegistryEntry:
    """Internal: the pack metadata + its registration outcome + the
    captured EntryPoint reference for sync ``load()``. The EntryPoint
    is mandatory because ``DiscoveredPack`` (the only public input to
    ``register``) always carries one. Registry state mutates only via
    ``_records[key] = entry`` swaps under the lock."""

    record: PluginRecord
    outcome: RegistrationOutcome
    entry_point: _im.EntryPoint


class PluginRegistry:
    """Sprint-4 plugin registry (entry-point discovery + register API).

    Construction takes an ``AuditStore`` for chained audit emission. The
    full T10 pipeline (discover → trust → supply-chain → policy →
    register) sits OUTSIDE this class — T5 just provides the substrate.

    Concurrency: ``register()`` serialises through ``AuditStore.append``
    (which itself FOR UPDATE-locks the chain head). The in-process
    ``_records`` dict is mutated under an asyncio.Lock so a concurrent
    register against the same key cannot race the in-memory state with
    the chain emission.
    """

    def __init__(self, *, audit_store: AuditStore) -> None:
        self._audit_store = audit_store
        self._records: dict[tuple[PluginKind, str], _RegistryEntry] = {}
        # Per-process lock; chain-head row lock provides cross-process
        # serialisation against PG / Oracle. SQLite cannot prove this
        # locally (no row-level locking).
        self._mutation_lock = asyncio.Lock()

    # --- discovery --------------------------------------------------------

    def discover(self) -> list[DiscoveredPack]:
        """Walk ``importlib.metadata.entry_points`` for the three pack
        groups; return ``DiscoveredPack`` (metadata + non-loaded
        EntryPoint) entries only.

        **Does not call ``EntryPoint.load()``.** That is the §1
        deferred-load invariant — eager loading would defeat the trust
        gate's pre-import verification. The ``test_discover_does_not_
        eager_import_pack_modules`` regression in
        ``test_plugin_registry.py`` pins this invariant.

        Re-discovery is idempotent: returning the same metadata list
        does not mutate any registry state. Registration is the only
        path that persists. Pairing the EntryPoint with the record at
        discovery time means the public ``discover → register → load``
        flow does not require callers to re-walk ``importlib.metadata``
        themselves (R2 reviewer-P2 fix).
        """
        discovered: list[DiscoveredPack] = []
        for kind, group in _ENTRY_POINT_GROUPS.items():
            for ep in _im.entry_points(group=group):
                # Resolve the owning distribution via ``ep.dist`` — populated
                # by importlib for every entry point declared via a real
                # installed distribution. None means an in-memory /
                # synthetic EntryPoint (test harness path); fall back to
                # placeholder strings so the record is still well-formed
                # but the trust gate will refuse anything without a real
                # signed distribution.
                dist = ep.dist
                record = PluginRecord(
                    kind=kind,
                    name=ep.name,
                    distribution_name=(dist.metadata["Name"] if dist is not None else "<unknown>"),
                    distribution_version=(dist.version if dist is not None else "<unknown>"),
                    entry_point_value=ep.value,
                )
                discovered.append(DiscoveredPack(record=record, entry_point=ep))
        return discovered

    # --- registration -----------------------------------------------------

    async def register(
        self,
        pack: DiscoveredPack,
        *,
        attestation_grade: AttestationGrade | None = None,
        signature_digest: str | None = None,
        refusal_reason: RefusalReason | None = None,
        tenant_id: str | None = None,
        request_id: str = "system",
    ) -> RegistrationOutcome:
        """Record the outcome of running the T10 pipeline against a
        discovered ``pack``. Emits ``audit_event(plugin.registration_
        succeeded)`` on success or ``audit_event(plugin.registration_
        refused)`` on refusal — both chained into the Sprint-2 substrate.

        Either ``attestation_grade`` (success path) or ``refusal_reason``
        (refusal path) MUST be supplied; passing both or neither raises
        ``ValueError`` at the API boundary so misuse fails fast.

        The captured ``EntryPoint`` reference travels inside ``pack``
        (R2 reviewer-P2 fix) — callers never need to forward it
        separately. The non-loaded EntryPoint is what ``load(kind, name)``
        eventually invokes after register-time decisions are persisted.

        Two PluginRecords sharing ``(kind, name)`` but with different
        distribution metadata raise ``PluginIdentityConflict`` instead
        of silently overwriting (R2 reviewer-P2 fix). Re-registering
        the SAME identity (after addressing a refusal cause, say)
        replaces the previous outcome cleanly.
        """
        record = pack.record
        self._validate_register_args(record, attestation_grade, refusal_reason, signature_digest)

        async with self._mutation_lock:
            # Identity-conflict check MUST live inside the lock (R2
            # reviewer-P2 fix): otherwise two concurrent registers for
            # the same (kind, name) but different distributions both
            # observe an empty ``_records`` map, both await
            # ``audit_store.append``, and the second silently
            # overwrites the first AFTER both audit rows have been
            # emitted — recreating the shadowing bug under
            # concurrency. The lock + the in-lock check together pin
            # the invariant that an impostor never reaches the audit
            # chain.
            self._reject_identity_conflict(record)
            now = datetime.now(UTC)
            key = (record.kind, record.name)
            if refusal_reason is not None:
                outcome = RegistrationOutcome(
                    status="refused_at_registration",
                    name=record.name,
                    pack_id=record.distribution_name,
                    version=record.distribution_version,
                    kind=record.kind,
                    attestation_grade=None,
                    refusal_reason=refusal_reason,
                    signature_digest=signature_digest,
                    registered_at=None,
                )
                event = AuditEvent(
                    event_type="plugin.registration_refused",
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload=_outcome_payload(outcome, record),
                    iso_controls=("ISO42001.A.7.4",),
                )
            else:
                # Type narrowing: ``_validate_register_args`` guarantees
                # ``attestation_grade`` is non-None on the success path.
                assert attestation_grade is not None
                outcome = RegistrationOutcome(
                    status="registered",
                    name=record.name,
                    pack_id=record.distribution_name,
                    version=record.distribution_version,
                    kind=record.kind,
                    attestation_grade=attestation_grade,
                    refusal_reason=None,
                    signature_digest=signature_digest,
                    registered_at=now,
                )
                event = AuditEvent(
                    event_type="plugin.registration_succeeded",
                    request_id=request_id,
                    tenant_id=tenant_id,
                    payload=_outcome_payload(outcome, record),
                    iso_controls=("ISO42001.A.7.4",),
                )
            # Audit FIRST so a chain-emission failure aborts the whole
            # register call — the in-memory ``_records`` dict never
            # diverges from the audit chain. The mutation_lock + chain-
            # head FOR UPDATE together serialise concurrent registrations.
            await self._audit_store.append(event)
            self._records[key] = _RegistryEntry(
                record=record, outcome=outcome, entry_point=pack.entry_point
            )
        return outcome

    def _reject_identity_conflict(self, record: PluginRecord) -> None:
        """Refuse a register call whose ``(kind, name)`` already maps
        to a DIFFERENT PluginRecord.

        Identity is the full record tuple — ``distribution_name`` +
        ``distribution_version`` + ``entry_point_value`` + ``kind`` +
        ``name``. Two installed distributions claiming the same
        ``(kind, name)`` is the plugin-trust attack surface; a
        malicious second pack could shadow a legitimate first by
        timing its registration. We refuse rather than pick a
        winner. Same identity (e.g. re-register after addressing a
        refusal cause) is allowed and replaces the previous outcome.
        """
        existing = self._records.get((record.kind, record.name))
        if existing is None:
            return
        if existing.record == record:
            return
        raise PluginIdentityConflict(
            f"plugin identity conflict at ({record.kind}, {record.name!r}): "
            f"already registered as "
            f"distribution={existing.record.distribution_name!r} "
            f"version={existing.record.distribution_version!r} "
            f"entry_point_value={existing.record.entry_point_value!r}; "
            f"refusing to overwrite with "
            f"distribution={record.distribution_name!r} "
            f"version={record.distribution_version!r} "
            f"entry_point_value={record.entry_point_value!r}. "
            f"Resolve by uninstalling one of the conflicting distributions."
        )

    @staticmethod
    def _validate_register_args(
        record: PluginRecord,
        attestation_grade: AttestationGrade | None,
        refusal_reason: RefusalReason | None,
        signature_digest: str | None,
    ) -> None:
        # Validation order: structural (record / arg-shape) checks
        # first, success-path-specific checks last. The
        # signature_digest invariant only fires once we've confirmed
        # we're on a well-formed success path.
        if attestation_grade is None and refusal_reason is None:
            raise ValueError(
                "register() requires either attestation_grade (success path) "
                "or refusal_reason (refusal path); neither was supplied"
            )
        if attestation_grade is not None and refusal_reason is not None:
            raise ValueError(
                "register() rejects both attestation_grade and refusal_reason "
                "in the same call — pick the success or refusal path"
            )
        if record.kind not in _ENTRY_POINT_GROUPS:
            raise ValueError(
                f"PluginRecord.kind {record.kind!r} is not a valid pack kind; "
                f"expected one of {sorted(_ENTRY_POINT_GROUPS)}"
            )
        if refusal_reason is not None and refusal_reason not in _VALID_REFUSAL_REASONS:
            raise ValueError(
                f"refusal_reason {refusal_reason!r} is not in the closed "
                f"enum: {sorted(_VALID_REFUSAL_REASONS)}"
            )
        if attestation_grade is not None and attestation_grade not in ("full", "partial"):
            raise ValueError(
                f"attestation_grade {attestation_grade!r} is not in {{'full', 'partial'}}"
            )
        # Trust-evidence invariant (R3 reviewer-P2 fix): a successful
        # registration MUST carry the cosign verification digest per
        # ADR-002 §"MCP plugin protocol". Without this, T10/T11 can
        # show a pack as registered/full or partial with no signature
        # evidence — defeating the audit chain's purpose. Refusal
        # paths stay flexible because verification may not have run
        # (or its absence may itself be the refusal cause).
        if attestation_grade is not None and (
            not isinstance(signature_digest, str) or not signature_digest.strip()
        ):
            raise ValueError(
                "register() with attestation_grade requires a non-empty "
                "signature_digest (cosign verification evidence per "
                f"ADR-002); got signature_digest={signature_digest!r}"
            )

    # --- read-side --------------------------------------------------------

    def known_packs(self) -> list[RegistrationOutcome]:
        """Return registered + refused outcomes in registration order.

        Order is insertion-stable because Python ``dict`` preserves
        insertion order; T11 relies on this for a deterministic
        ``/api/v1/system/plugins`` response under repeat reads.
        """
        return [entry.outcome for entry in self._records.values()]

    def load(self, kind: PluginKind, name: str) -> Any:
        """Sync wrapper over the stdlib ``EntryPoint.load()``.

        Refuses with ``RegistrationRefused`` if the pack was registered
        with a refusal status, and ``PluginNotRegistered`` if no record
        for ``(kind, name)`` exists. The actual ``EntryPoint.load()``
        runs only here — never during ``discover()``.
        """
        entry = self._records.get((kind, name))
        if entry is None:
            raise PluginNotRegistered(
                f"pack {kind}/{name!r} has not been registered with this "
                f"PluginRegistry; call discover() then register() first"
            )
        if entry.outcome.status == "refused_at_registration":
            # ``refusal_reason`` is non-None on the refused branch by
            # construction in ``register``. The ``or`` fallback satisfies
            # type-checkers without changing runtime behaviour.
            reason: RefusalReason = entry.outcome.refusal_reason or "not_in_tenant_allowlist"
            raise RegistrationRefused(kind, name, reason)
        return entry.entry_point.load()

    # --- Sprint 5 T6: MCP admission steps -------------------------------

    async def _mcp_admit(
        self,
        *,
        pack: DiscoveredPack,
        tenant_id: str,
        request_id: str,
        mcp_admission: MCPAdmissionDeps | None,
    ) -> RefusalReason | None:
        """Run the three Sprint-5 MCP admission steps; return ``None``
        on success (or on a Sprint-4-style pack with no MCP block) or
        a closed-enum :data:`RefusalReason` on failure.

        Sub-steps in order (first failure wins):

          A. **Manifest extraction (T6.1)** — read
             ``cognic-pack-manifest.toml`` via
             :func:`cognic_agentos.protocol.mcp_manifest.extract_pack_manifest`.
             Five behaviours (R2 doctrine):
               - **Manifest absent** → return ``None``; no MCP intent
                 (Sprint-4-style pack, harmless). The R1 contract
                 that refused with ``mcp_manifest_missing`` when
                 admission deps were wired was wrong (R2 #1) —
                 ``mcp_admission`` is dependency wiring, NOT pack
                 intent. ``mcp_manifest_missing`` is now reserved
                 for a future explicit MCP-intent signal (e.g.,
                 Sprint-7A's ``agentos validate`` or a future
                 MCP-specific entry-point group).
               - **Manifest present, well-shaped MCP block** → step B.
               - **Manifest present, NO ``[tool.cognic.mcp]`` block** →
                 return ``None``; no MCP intent (Sprint-4 cognic pack
                 with non-MCP config).
               - **Manifest present, MALFORMED ``[tool.cognic.mcp]``**
                 (e.g., ``mcp = "bad"``) → refuse with
                 ``mcp_manifest_malformed`` (R2 P1 — was previously
                 silent admission).
               - **Manifest itself malformed** (TOML decode failure)
                 → refuse with ``mcp_manifest_malformed`` (always —
                 cosign-signed bytes, so a malformed manifest is a
                 packaging-bug fail-closed event).
          B. **Capability validation (T6.2)** — pure-functional
             validator + OPA-backed sampling 4-condition gate.
             ``mcp_transport_unsupported`` (R1 P1 #2) fires here for
             unknown transport values.
          C. **Registration auth probe (T6.3)** — HTTP-OAuth path
             constructs a fresh :class:`MCPAuthzClient` (via the
             admission-deps factory) and calls ``acquire_token``;
             token discarded after probe (factory pattern keeps
             probe cache isolated from runtime cache —
             "token-acquired-but-not-stored" per ADR-002 §"MCP
             Authorization" step 8). API-key path validates Vault
             secret + deprecation acknowledgement.

        **R1 P1 #1 fail-closed admission rule:** if the manifest
        contains a ``[tool.cognic.mcp]`` block AND ``mcp_admission``
        was not provided, the helper returns
        ``mcp_admission_deps_required``. This prevents a caller that
        forgot to wire MCPHost from silently admitting an MCP pack
        without the manifest / capability / auth-probe gates running.
        Sprint-4 packs without an ``[tool.cognic.mcp]`` block are
        unaffected (they pass through with ``None``).
        """
        # Local imports — keep the module-import-time graph minimal
        # so kernel-image deployments without MCP wired don't pay
        # for these imports.
        from cognic_agentos.protocol.mcp_authz import MCPAuthzError
        from cognic_agentos.protocol.mcp_capabilities import (
            ValidationContext,
            validate_mcp_manifest,
        )
        from cognic_agentos.protocol.mcp_manifest import (
            PackManifestMalformedError,
            PackManifestNotFoundError,
            extract_pack_manifest,
        )

        record = pack.record
        # Derive importable package name from the entry-point value:
        # ``"cognic_test_mcp_pack:Plugin"`` → ``"cognic_test_mcp_pack"``.
        # Splits on ``:`` first (entry-point separator) then on ``.``
        # (sub-module). Most packs follow PEP 503 normalisation
        # (``-`` → ``_``) but the entry point is the authoritative
        # source.
        package_name = record.entry_point_value.split(":", 1)[0].split(".", 1)[0]

        # Step A: extract manifest. ALWAYS attempted so the
        # MCP-block detection below can fire regardless of whether
        # the caller passed admission deps. The MCP-intent signal is
        # the manifest's ``[tool.cognic.mcp]`` block, NOT the deps —
        # a default-adapters caller may legitimately wire
        # ``mcp_admission`` for every registration even though some
        # packs are pure Sprint-4 (no MCP). Per R2 #1 (corrected
        # from R1 #1), missing manifest ALWAYS proceeds.
        try:
            manifest = extract_pack_manifest(
                distribution_name=record.distribution_name,
                package_name=package_name,
            )
        except PackManifestNotFoundError:
            # No manifest = no MCP intent. Sprint-4 pack OR
            # misconfigured MCP pack (Sprint 7A's `agentos validate`
            # catches the misconfigured case at dev time; the
            # registry doesn't try to second-guess intent here).
            return None
        except PackManifestMalformedError:
            # Malformed manifest is always a fail-closed event —
            # the manifest bytes are cosign-signed, so a malformed
            # manifest implies a packaging bug or corruption that
            # MUST surface regardless of whether the pack is MCP.
            _LOG.warning(
                "T6: pack %s manifest is malformed at admission",
                record.distribution_name,
            )
            return "mcp_manifest_malformed"

        # Manifest extracted. Detect MCP intent by walking the path
        # safely (R2 P1 — non-dict intermediates would otherwise
        # raise raw AttributeError; the safe-walk treats them as
        # absent). Three outcomes:
        #
        #   1. ``[tool.cognic.mcp]`` present-and-a-dict → MCP intent
        #      (apply R1 fail-closed gate + steps B + C).
        #   2. ``[tool.cognic.mcp]`` present-but-NOT-a-dict (e.g.,
        #      ``mcp = "bad"``) → manifest shape malformed; refuse
        #      with ``mcp_manifest_malformed``. R2 P1 — previously
        #      treated as no MCP block → silent admission of
        #      structurally-broken MCP declarations.
        #   3. ``[tool.cognic.mcp]`` absent → no MCP intent; proceed
        #      (Sprint-4-style pack).
        mcp_value = _safe_walk_to_mcp(manifest)
        if mcp_value is _MCP_BLOCK_MALFORMED:
            _LOG.warning(
                "T6: pack %s manifest contains a present-but-non-dict "
                "[tool.cognic.mcp] entry; refusing as malformed",
                record.distribution_name,
            )
            return "mcp_manifest_malformed"
        if mcp_value is None:
            # No MCP block — Sprint-4-style pack with non-MCP cognic
            # config (or no cognic config at all). Proceed.
            return None

        # MCP block present-and-well-shaped. Now the R1 P1 #1
        # admission-deps fail-closed gate fires:
        if mcp_admission is None:
            _LOG.warning(
                "T6: pack %s declares [tool.cognic.mcp] but mcp_admission "
                "was not provided to register_with_full_attestation_check; "
                "refusing fail-closed (mcp_admission_deps_required)",
                record.distribution_name,
            )
            return "mcp_admission_deps_required"

        # From here onwards, mcp_admission is non-None (we just
        # checked the fail-closed condition above). The narrowing
        # is type-safe by control flow.
        assert mcp_admission is not None

        # Step B: capability validation. Build a ValidationContext
        # from the admission deps + tenant_id. STDIO command
        # allow-list resolved from Vault on a best-effort basis
        # (missing → empty set → STDIO refused at the per-tenant
        # gate, which is the correct default-deny posture).
        stdio_allowlist = await _resolve_stdio_command_allowlist(
            tenant_id=tenant_id, deps=mcp_admission
        )
        validation_context = ValidationContext(
            tenant_id=tenant_id,
            stdio_command_allowlist=stdio_allowlist,
            # Sprint-5 default-deny posture for the sampling gate.
            # Sprint 13.5 will source these from a richer
            # tenant-policy bundle; today the validator's job is to
            # surface the closed-enum refusal when sampling is
            # requested without operator approval.
            tenant_sampling_permitted=False,
            cloud_policy_tier_consistent=True,
            cloud_policy_allow_external_llm_consistent=(mcp_admission.settings.allow_external_llm),
            opa_engine=mcp_admission.opa_engine,
            sampling_policy_bundle=mcp_admission.settings.mcp_sampling_policy_bundle,
        )
        validation = await validate_mcp_manifest(manifest, context=validation_context)
        if not validation.ok:
            assert validation.reason is not None  # invariant: reason non-None when not ok
            # ValidationReason is a strict subset of RefusalReason; the
            # validator's literal IS the refusal subset for the 12
            # capability-side reasons (T6 R1 P1 #2 added
            # ``mcp_transport_unsupported`` to the original 9; T15 R1
            # P2 #6 added ``mcp_http_manifest_shape_invalid``; T15 R2
            # P2 added ``mcp_tool_data_classes_shape_invalid``; pinned
            # by the test_validation_reason_literal_matches_expected_set
            # drift test). The return is type-safe by construction.
            return validation.reason

        # Step C: auth probe. Only fires for HTTP-family transports;
        # STDIO is umbrella-refused above (the validator catches it
        # before we get here, so we never reach the probe with STDIO).
        # Both ``"http"`` (legacy) and ``"streamable-http"`` (canonical
        # per MCP-CONFORMANCE.md) map to the same OAuth/PRM probe (R1
        # P1 #2 — previously only ``"http"`` matched, which let a
        # correctly-spec'd ``streamable-http`` pack skip the probe).
        # The validator's transport closed-enum check (gate 0) means
        # any value reaching here is necessarily one of the known
        # transports.
        from cognic_agentos.protocol.mcp_capabilities import (
            _HTTP_TRANSPORT_VALUES,
        )

        mcp_block = manifest.get("tool", {}).get("cognic", {}).get("mcp", {})
        if mcp_block.get("transport") not in _HTTP_TRANSPORT_VALUES:
            return None  # STDIO already refused; safety-net for any future transports

        auth_kind = mcp_block.get("auth")
        if auth_kind == "oauth-prm":
            try:
                # Construct a FRESH client per probe (factory pattern)
                # so the probe's token cache is isolated from any
                # long-lived runtime client — "token-acquired-but-
                # not-stored" per ADR-002 step 8.
                authz_client = mcp_admission.make_authz_client_for_probe()
                server_url = mcp_block.get("server_url", "")
                manifest_scopes = tuple(mcp_block.get("scopes", []) or [])
                _ = await authz_client.acquire_token(
                    server_url=server_url,
                    manifest_scopes=manifest_scopes,
                    request_id=request_id,
                    tenant_id=tenant_id,
                )
                # Token discarded — registration only validates "could
                # acquire", not "use".
            except MCPAuthzError as exc:
                _LOG.info(
                    "T6: pack %s OAuth probe refused with reason=%s",
                    record.distribution_name,
                    exc.reason,
                )
                return _authz_reason_to_refusal(exc.reason)
        elif auth_kind == "api-key":
            api_key_refusal = await _validate_api_key_fallback(
                mcp_block=mcp_block,
                tenant_id=tenant_id,
                vault_client=mcp_admission.vault_client,
            )
            if api_key_refusal is not None:
                return api_key_refusal

        return None

    # --- T10: full pack-admission integration ----------------------------

    async def register_with_full_attestation_check(
        self,
        pack: DiscoveredPack,
        artefacts: PackAttestations,
        *,
        trust_gate: TrustGate,
        supply_chain: SupplyChainPipeline,
        object_store: ObjectStoreAdapter,
        policy_engine: OPAEngine | None = None,
        tenant_id: str = "_default",
        tenant_allowlist: frozenset[str] | None = None,
        require_full_grade: bool = False,
        license_allowlist: tuple[str, ...] = (),
        vuln_thresholds: VulnThresholds | None = None,
        request_id: str = "system",
        mcp_admission: MCPAdmissionDeps | None = None,
    ) -> RegistrationOutcome:
        """End-to-end pack registration: discover → trust gate → SBOM →
        Sigstore-bundle persistence → grace-period verifiers → policy
        engine → register.

        Per Sprint-4 plan §3 + the user's T10 scope: every failure
        becomes the matching closed ``refusal_reason`` (T5's enum).
        ``EntryPoint.load()`` is NEVER called here — that's
        ``PluginRegistry.load(kind, name)``'s job and the deferred-
        load invariant of §1. T10 only walks metadata + cryptographic
        attestations + persists evidence.

        Refusal mapping (in evaluation order — first failure wins):

          1. tenant allow-list miss → ``not_in_tenant_allowlist``
          2. ``TrustGateError`` from cosign verify (any subclass —
             CosignVerificationFailed, CosignNotInstalledError,
             PathTraversalError) → ``cosign_verification_failed``
          3. ``SBOMMissing`` → ``sbom_missing``
          4. ``SBOMTampered`` → ``sbom_tampered``
          5. ``SLSATampered`` → ``slsa_tampered``
          6. ``IntotoTampered`` → ``intoto_tampered``
          7. ``SigstoreBundlePersistenceFailed`` (incl. read failure
             on the bundle file before the persister even runs) →
             ``sigstore_bundle_persistence_failed``
          8. policy engine deny (Rego or local fallback) →
             ``policy_denied_partial_grade``

        On success, ``register()`` is called with the final
        ``attestation_grade`` (full | partial) plus
        ``signature_digest`` from the cosign verification. T5's
        register handles audit emission for both success and refusal
        paths — T10 itself never emits audit directly.
        """
        # Local imports — see TYPE_CHECKING block above for the
        # rationale (avoid import-time cycle when only the substrate
        # is needed).
        from cognic_agentos.protocol.supply_chain import (
            IntotoTampered,
            SBOMMissing,
            SBOMTampered,
            SigstoreBundlePersistenceFailed,
            SLSATampered,
            persist_sigstore_bundle,
        )
        from cognic_agentos.protocol.trust_gate import TrustGateError

        record = pack.record

        # Step 1: tenant allow-list. Sprint-4 plan §6 contract:
        # ``{tenant_id: [pack_name, ...]}`` where pack_name is the
        # signed distribution identity (the same value cosign verifies
        # in step 2 + the same value reported as ``RegistrationOutcome.
        # pack_id``). R1 reviewer-P2 fix: previously this checked
        # ``record.name`` (the entry-point alias), which let an
        # entry-point alias that didn't match the signed distribution
        # pass — and refused real allow-list entries when the
        # entry-point name differed from the distribution name.
        # ``None`` allowlist means the operator opted out of allow-
        # list enforcement; an empty frozenset means accept-no-packs.
        if tenant_allowlist is not None and record.distribution_name not in tenant_allowlist:
            return await self.register(
                pack,
                refusal_reason="not_in_tenant_allowlist",
                tenant_id=tenant_id,
                request_id=request_id,
            )

        # Step 2: cosign verification — refusal-grade gate. Any
        # TrustGateError subclass (CosignVerificationFailed,
        # CosignNotInstalledError, PathTraversalError) maps to one
        # closed reason for T5's enum.
        try:
            cosign_result = await trust_gate.verify_pack_signature(
                pack_id=record.distribution_name,
                version=record.distribution_version,
                signature_path=artefacts.cosign_signature_path,
                blob_path=artefacts.cosign_blob_path,
                trust_root=artefacts.cosign_trust_root,
                tenant_id=tenant_id,
                request_id=request_id,
            )
        except TrustGateError:
            _LOG.warning(
                "T10: cosign verification failed for pack %s/%s",
                record.distribution_name,
                record.distribution_version,
            )
            return await self.register(
                pack,
                refusal_reason="cosign_verification_failed",
                tenant_id=tenant_id,
                request_id=request_id,
            )
        signature_digest = cosign_result.signature_digest

        # Step 3 + 5 (combined): SBOM mandatory floor + grace-period
        # verifiers. T7's pipeline.verify raises the specific tampered
        # exceptions which we map to refusal reasons.
        try:
            attestation_result = supply_chain.verify(
                sbom_path=artefacts.sbom_path,
                sbom_signed_digest=artefacts.sbom_signed_digest,
                slsa_provenance_path=artefacts.slsa_provenance_path,
                intoto_layout_path=artefacts.intoto_layout_path,
                vuln_scan_path=artefacts.vuln_scan_path,
                license_audit_path=artefacts.license_audit_path,
                vuln_thresholds=vuln_thresholds,
                license_allowlist=license_allowlist,
            )
        except SBOMMissing:
            return await self.register(
                pack,
                refusal_reason="sbom_missing",
                signature_digest=signature_digest,
                tenant_id=tenant_id,
                request_id=request_id,
            )
        except SBOMTampered:
            return await self.register(
                pack,
                refusal_reason="sbom_tampered",
                signature_digest=signature_digest,
                tenant_id=tenant_id,
                request_id=request_id,
            )
        except SLSATampered:
            return await self.register(
                pack,
                refusal_reason="slsa_tampered",
                signature_digest=signature_digest,
                tenant_id=tenant_id,
                request_id=request_id,
            )
        except IntotoTampered:
            return await self.register(
                pack,
                refusal_reason="intoto_tampered",
                signature_digest=signature_digest,
                tenant_id=tenant_id,
                request_id=request_id,
            )

        # Step 4: persist Sigstore bundle. Reading the bundle file
        # itself can fail (missing / unreadable) — both surface as
        # the same closed-enum refusal so T10 has one mapping per
        # mandatory-floor failure class.
        try:
            bundle_bytes = artefacts.sigstore_bundle_path.read_bytes()
        except OSError:
            return await self.register(
                pack,
                refusal_reason="sigstore_bundle_persistence_failed",
                signature_digest=signature_digest,
                tenant_id=tenant_id,
                request_id=request_id,
            )
        try:
            # R1 reviewer-P2 fix: persist under the signed distribution
            # identity (== ``RegistrationOutcome.pack_id``), NOT the
            # entry-point alias. T9's deterministic key contract is
            # ``attestations/<pack_id>/<version>/bundle.sigstore``, so
            # the retained Sigstore bundle's path must match the pack
            # identity reported via ``/system/plugins`` — otherwise
            # examiners see the outcome's pack_id pointing at one
            # path and the bundle stored at another.
            await persist_sigstore_bundle(
                object_store=object_store,
                pack_id=record.distribution_name,
                version=record.distribution_version,
                bundle_bytes=bundle_bytes,
            )
        except SigstoreBundlePersistenceFailed:
            return await self.register(
                pack,
                refusal_reason="sigstore_bundle_persistence_failed",
                signature_digest=signature_digest,
                tenant_id=tenant_id,
                request_id=request_id,
            )

        # Step 5 (Sprint 5 — T6): MCP-specific admission steps.
        # Three sub-steps (A: extract manifest, B: validate
        # capabilities, C: probe auth at registration time) per the
        # plan-of-record §T6. Per R1 P1 #1 (fail-closed for MCP
        # packs): the helper ALWAYS attempts manifest extraction
        # regardless of whether ``mcp_admission`` was provided. If
        # the pack ships a ``[tool.cognic.mcp]`` block AND
        # ``mcp_admission`` is None, the helper returns
        # ``mcp_admission_deps_required`` — preventing a Sprint-4
        # caller that forgot to wire MCPHost from silently admitting
        # an MCP pack without the manifest / capability / auth-probe
        # gates running. Sprint-4-style packs without an
        # ``[tool.cognic.mcp]`` block remain unaffected (helper
        # returns None and the policy step proceeds).
        mcp_refusal = await self._mcp_admit(
            pack=pack,
            tenant_id=tenant_id,
            request_id=request_id,
            mcp_admission=mcp_admission,
        )
        if mcp_refusal is not None:
            return await self.register(
                pack,
                refusal_reason=mcp_refusal,
                signature_digest=signature_digest,
                tenant_id=tenant_id,
                request_id=request_id,
            )

        # Step 6: policy decision on the (grade, tenant_policy) pair.
        # The default Rego bundle (T3) implements the same logic
        # we'd apply locally if the engine isn't available: full =
        # always allow, partial = allow unless require_full. Calling
        # the engine when present gives operators a tenant-Rego seam
        # for Sprint 13.5 extensions; the local fallback keeps T10
        # working in kernel-image deployments where OPA is absent.
        grade = attestation_result.grade
        if not await _admit_grade(
            grade=grade,
            policy_engine=policy_engine,
            tenant_id=tenant_id,
            require_full=require_full_grade,
            request_id=request_id,
        ):
            return await self.register(
                pack,
                refusal_reason="policy_denied_partial_grade",
                signature_digest=signature_digest,
                tenant_id=tenant_id,
                request_id=request_id,
            )

        # Step 7: register success.
        return await self.register(
            pack,
            attestation_grade=grade,
            signature_digest=signature_digest,
            tenant_id=tenant_id,
            request_id=request_id,
        )


#: Sentinel returned by :func:`_safe_walk_to_mcp` when the manifest's
#: ``[tool.cognic.mcp]`` path leads to a present-but-non-dict value
#: (e.g., the operator wrote ``mcp = "bad"`` in their TOML). Distinct
#: from ``None`` (which means the path doesn't exist) so the caller
#: can refuse with ``mcp_manifest_malformed`` for the present-but-
#: invalid case while still proceeding for the absent case.
_MCP_BLOCK_MALFORMED = object()


def _safe_walk_to_mcp(manifest: dict[str, Any]) -> dict[str, Any] | None | object:
    """Walk ``manifest -> tool -> cognic -> mcp`` defensively.

    Returns:
      - The MCP block dict, if every intermediate is a dict AND the
        leaf ``mcp`` key is present-and-a-dict.
      - ``None`` if any intermediate is missing OR if ``mcp`` itself
        is absent (Sprint-4-style pack with no MCP intent).
      - :data:`_MCP_BLOCK_MALFORMED` (sentinel) if every intermediate
        is a dict AND ``mcp`` is present-but-NOT-a-dict (e.g.,
        ``mcp = "bad"``). Caller refuses with
        ``mcp_manifest_malformed`` (R2 P1).

    A non-dict intermediate (e.g., ``tool = "bad"``) is treated as
    "absent" rather than "malformed" because the path could not have
    reached an MCP block anyway — the structural error is in the
    parent block, which other schema checks catch (per ADR-002 §pack
    manifest structure).
    """
    tool = manifest.get("tool")
    if not isinstance(tool, dict):
        return None
    cognic = tool.get("cognic")
    if not isinstance(cognic, dict):
        return None
    if "mcp" not in cognic:
        return None
    mcp = cognic["mcp"]
    if not isinstance(mcp, dict):
        return _MCP_BLOCK_MALFORMED
    return mcp


async def _resolve_stdio_command_allowlist(
    *, tenant_id: str, deps: MCPAdmissionDeps
) -> frozenset[str]:
    """Read the per-tenant STDIO command allow-list from Vault.

    Best-effort: if the Vault path doesn't exist, the read raises, or
    the secret shape is wrong, returns an empty frozenset (which makes
    the per-tenant gate fail-closed for any STDIO command — the
    correct default-deny posture). The validator's downstream
    Sprint-5 umbrella refusal will fire regardless.
    """
    try:
        path = deps.settings.mcp_stdio_command_allowlist_path.format(tenant=tenant_id)
        secret = await deps.vault_client.read(path)
    except Exception:
        _LOG.debug(
            "T6: STDIO command allow-list Vault read failed for tenant=%s; "
            "treating as empty (default-deny)",
            tenant_id,
        )
        return frozenset()
    if not isinstance(secret, dict):
        return frozenset()
    # Vault secret shape: {commands: [...]} OR {servers: [...]} (the
    # AS-allowlist key was reused historically; tolerate both).
    commands = secret.get("commands") or secret.get("servers") or []
    if not isinstance(commands, list):
        return frozenset()
    return frozenset(c for c in commands if isinstance(c, str) and c.strip())


async def _validate_api_key_fallback(
    *,
    mcp_block: dict[str, Any],
    tenant_id: str,
    vault_client: SecretAdapter,
) -> RefusalReason | None:
    """Validate the api-key fallback's three preconditions (per
    Sprint-5 plan §T6.3 + R13 P2). All three MUST hold:

      1. Manifest's ``api_key_vault_path`` resolves AND the secret
         is non-empty.
      2. Manifest declares ``api_key_deprecation_acknowledged = true``.

    Any failure → :data:`mcp_api_key_fallback_unresolved`. Returns
    ``None`` on success.
    """
    if not mcp_block.get("api_key_deprecation_acknowledged"):
        return "mcp_api_key_fallback_unresolved"
    vault_path = mcp_block.get("api_key_vault_path")
    if not isinstance(vault_path, str) or not vault_path.strip():
        return "mcp_api_key_fallback_unresolved"
    try:
        secret = await vault_client.read(vault_path)
    except Exception:
        return "mcp_api_key_fallback_unresolved"
    if not isinstance(secret, dict) or not secret:
        return "mcp_api_key_fallback_unresolved"
    api_key = secret.get("api_key")
    if not isinstance(api_key, str) or not api_key.strip():
        return "mcp_api_key_fallback_unresolved"
    return None


async def _admit_grade(
    *,
    grade: Literal["full", "partial"],
    policy_engine: OPAEngine | None,
    tenant_id: str,
    require_full: bool,
    request_id: str,
) -> bool:
    """T10 admission gate for the (grade, tenant_policy) pair.

    Two implementations:

      * ``policy_engine`` non-None — call the OPA Rego bundle at
        decision_point ``data.cognic.supply_chain.allow``. The
        Sprint-4 default bundle (T3) encodes "full = always allow,
        partial = allow unless require_full"; tenants extend via
        Rego in Sprint 13.5.
      * ``policy_engine`` None — local fallback with the same
        decision logic. Lets T10 work in kernel-image deployments
        where OPA isn't installed.

    The local fallback's behaviour is identical to the Rego bundle's
    so flipping the engine on later doesn't change which packs admit.

    R1 reviewer-P2 fix: any exception from ``policy_engine.evaluate``
    (``OpaNotInstalledError`` / ``RegoEvaluationError`` / generic
    ``Exception``) is treated as fail-closed deny so T10's contract
    "every failure becomes a closed refusal_reason" holds. Without
    this wrap, a policy-engine error would propagate and T10 would
    never produce a ``RegistrationOutcome`` / audit row — examiners
    would see a half-finished admission with no evidence trail.
    """
    if policy_engine is None:
        if grade == "full":
            return True
        return not require_full
    try:
        decision = await policy_engine.evaluate(
            decision_point="data.cognic.supply_chain.allow",
            input={
                "attestation_grade": grade,
                "tenant_policy": {"require_full": require_full},
                "tenant_id": tenant_id,
                "request_id": request_id,
            },
        )
    except Exception:
        _LOG.warning(
            "T10: policy engine raised during evaluate(); fail-closed deny for grade=%s tenant=%s",
            grade,
            tenant_id,
        )
        return False
    return decision.allow


def _outcome_payload(outcome: RegistrationOutcome, record: PluginRecord) -> dict[str, Any]:
    """Audit payload shape for ``plugin.registration_*`` emissions.

    Surface (T10 startup log + T11 endpoint + ISO 42001 A.7.4 evidence):
    pack identity, kind, registration status, attestation grade or
    refusal reason, signature digest, entry-point value, timestamp.
    Nothing pack-controlled (no decoded module imports, no manifest
    blob) flows through here — only metadata captured from the
    distribution.
    """
    return {
        "kind": outcome.kind,
        "pack_id": outcome.pack_id,
        "name": record.name,
        "version": outcome.version,
        "entry_point_value": record.entry_point_value,
        "status": outcome.status,
        "attestation_grade": outcome.attestation_grade,
        "refusal_reason": outcome.refusal_reason,
        "signature_digest": outcome.signature_digest,
        "registered_at": (
            outcome.registered_at.isoformat() if outcome.registered_at is not None else None
        ),
    }


__all__ = (
    "AttestationGrade",
    "DiscoveredPack",
    "MCPAdmissionDeps",
    "PackAttestations",
    "PluginIdentityConflict",
    "PluginKind",
    "PluginNotRegistered",
    "PluginRecord",
    "PluginRegistry",
    "RefusalReason",
    "RegistrationOutcome",
    "RegistrationRefused",
    "_authz_reason_to_refusal",
)
