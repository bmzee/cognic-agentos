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
    from cognic_agentos.core.policy.engine import OPAEngine
    from cognic_agentos.db.adapters.protocols import ObjectStoreAdapter
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
    "not_in_tenant_allowlist",
    "cosign_verification_failed",
    "sbom_missing",
    "sigstore_bundle_persistence_failed",
    "slsa_tampered",
    "intoto_tampered",
    "sbom_tampered",
    "policy_denied_partial_grade",
]

AttestationGrade = Literal["full", "partial"]

_VALID_REFUSAL_REASONS: frozenset[str] = frozenset(
    {
        "not_in_tenant_allowlist",
        "cosign_verification_failed",
        "sbom_missing",
        "sigstore_bundle_persistence_failed",
        "slsa_tampered",
        "intoto_tampered",
        "sbom_tampered",
        "policy_denied_partial_grade",
    }
)


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
                    iso_controls=("A.7.4",),
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
                    iso_controls=("A.7.4",),
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
    "PackAttestations",
    "PluginIdentityConflict",
    "PluginKind",
    "PluginNotRegistered",
    "PluginRecord",
    "PluginRegistry",
    "RefusalReason",
    "RegistrationOutcome",
    "RegistrationRefused",
)
