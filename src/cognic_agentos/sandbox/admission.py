"""Sprint 8A T5 — Stage-2 async admission pipeline.

Critical-controls module per AGENTS.md + spec §17. Shared by all
backends (DockerSibling T10 + KubernetesPod Sprint 8B + Wave-2
backends). admit_policy is the single admission seam — backends MUST
NOT call ``validate_policy_shape`` separately; doing so creates two
independent admission seams that can drift.

Plan-vs-reality fixups vs the T2 plan-of-record (verified at session
compose time per ``feedback_verify_code_citations_at_doc_write``):

* The T2 plan declared T5 importing from
  ``sandbox/catalog`` (T6 owns) and ``sandbox/credentials`` (T8 owns)
  before either module existed. Per user direction (2026-05-17), T5
  declares the dependency Protocols + the fail-loud sentinel HERE in
  ``sandbox/admission`` so T5 remains independently runnable. T6 + T8
  ship concrete impls structurally conforming to these Protocols;
  ``KernelDefaultCredentialAdapter`` may be re-exported from
  ``sandbox/credentials`` when T8 lands.
* The T2 plan used ``rego_engine.evaluate(query, input={...})`` with
  positional + ``decision.allowed`` / ``deny_reason`` access. The
  real ``OPAEngine.evaluate`` signature at
  ``core/policy/engine.py:269`` is kw-only
  ``evaluate(*, decision_point: str, input: dict)`` returning
  ``Decision(allow, rule_matched, reasoning, decision_data)`` at
  ``core/policy/engine.py:133``. admit_policy uses the real shape.
* The T2 plan mocked unprefixed ``settings.per_tenant_max_*`` fields.
  Per the in-repo Settings sectioning convention
  (``ui_event_stream_*`` / ``adapters_*`` / etc.), the Sprint-8A
  fields land prefixed ``sandbox_per_tenant_max_*``. admit_policy
  reads the prefixed names.

The 6-value ``_HIGH_RISK_TIERS_PRE_13_5`` set is the transitional
fail-closed admission gate per ADR-014 §29 (Sprint 13.5 lifts this by
wiring the per-tenant runtime-approval engine + the 4-eyes flow).
Drift detector at ``tests/unit/sandbox/test_admission_pipeline.py``
pins lockstep with the ADR-014 canonical 8-value ``RiskTier`` Literal.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from cognic_agentos.sandbox.policy import (
    PackAdmissionContext,
    SandboxPolicy,
    validate_policy_shape,
)
from cognic_agentos.sandbox.protocol import SandboxLifecycleRefused

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.policy.engine import OPAEngine
    from cognic_agentos.core.vault import CredentialLease, VaultLeaseRequest
    from cognic_agentos.portal.rbac.actor import Actor


# ---------------------------------------------------------------------------
# Dependency Protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class CatalogProtocol(Protocol):
    """Structural contract for the canonical image catalog (T6 ships
    the concrete ``CanonicalImageCatalog`` against this shape).

    Two sync membership checks (in-process cache lookups, no I/O) +
    two async verification calls (cosign subprocess + SBOM scanner
    subprocess). The async methods fail-loud by raising
    ``SandboxLifecycleRefused`` with the matching closed-enum reason
    (NOT returning a bool) so the failure detail (signer mismatch,
    GPL-3.0 detected, etc.) reaches the audit chain.
    """

    def is_canonical(self, image_digest: str) -> bool:
        """True iff ``image_digest`` is in the 4-image canonical set."""

    def is_tenant_allow_listed(self, image_digest: str, tenant_id: str) -> bool:
        """True iff ``image_digest`` is on the per-tenant allow-list
        for the per-pack image escape hatch (spec §8.2)."""

    async def verify_cosign_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        """Run cosign verify on the full OCI ref backing
        ``image_digest``. Raises ``SandboxLifecycleRefused`` with
        reason ``sandbox_image_cosign_verification_failed`` on
        signature mismatch / unknown signer / expired bundle."""

    async def verify_sbom_policy_or_refuse(self, image_digest: str, *, tenant_id: str) -> None:
        """Run the SBOM policy check (syft + license/CVE policy) on
        the full OCI ref backing ``image_digest``. Raises
        ``SandboxLifecycleRefused`` with reason
        ``sandbox_image_sbom_check_failed`` on policy violation."""


@runtime_checkable
class CredentialAdapter(Protocol):
    """Structural contract for runtime secret retrieval + dynamic
    credential leasing. Sprint 10 T6 ships the first concrete
    ``VaultCredentialAdapter`` per ADR-009. Wave-1 ships only the
    fail-loud ``KernelDefaultCredentialAdapter`` sentinel below —
    admit_policy refuses any ``SandboxPolicy.vault_path`` non-None
    when the wired adapter is the sentinel.

    Sprint 10 T5 extension (ADR-004 §102 + spec §3.3): the Protocol
    now declares the dual lease API (``mint_lease`` / ``revoke_lease``)
    alongside ``fetch_secret``. ``fetch_secret`` is the Sprint-8A
    static-secret read path (kept for backward-compat with
    operator-supplied custom adapters); ``mint_lease`` / ``revoke_lease``
    are the Sprint-10 dynamic-secret leasing surface that the sandbox
    boundary calls when ``policy.requires_credentials`` is set.

    Operator-supplied real adapters MUST implement all 3 methods. A
    pre-T5 single-method object no longer structurally conforms —
    pinned by
    ``tests/unit/sandbox/test_credential_adapter_stub.py::TestProtocolShape::test_pre_t5_fetch_secret_only_object_no_longer_satisfies_protocol``.
    """

    async def fetch_secret(self, path: str) -> str | None:
        """Return the secret value at ``path`` or None if not found.
        Implementations MUST surface auth / network failures as
        exceptions (NOT silent None) so the caller can audit."""

    # Sprint 10 T5 — dual lease API per ADR-004 §102 Q4 LOCK + spec §3.3.
    # Implementations delegate to ``core.vault.lease_credential`` /
    # ``core.vault.revoke_credential`` (or compose with operator-policy
    # hooks). Exception taxonomy is the 4-value ``VaultUnavailable`` /
    # ``VaultPathNotFound`` / ``VaultAuthDenied`` / ``VaultProtocolError``
    # set declared in ``core/vault.py``; T6's ``VaultCredentialAdapter``
    # PRESERVES this taxonomy unchanged (user-locked T6 correction #2 +
    # patched plan §"Scope locks") — the collapse to
    # ``sandbox_credential_mint_failed_*`` closed-enum values belongs at
    # T10's backend create() / destroy() seam where ``mint_lease`` is
    # actually called, NOT at this Protocol's implementations.
    async def mint_lease(self, request: VaultLeaseRequest) -> CredentialLease:
        """Mint a dynamic credential lease for the given request.
        Returns a ``CredentialLease`` with the granted token + TTL.
        Raises one of the 4 ``core.vault`` taxonomy exceptions on
        failure."""

    async def revoke_lease(self, lease_id: str) -> None:
        """Revoke a previously-minted lease by Vault lease ID.
        Returns None on success; raises one of the 4 ``core.vault``
        taxonomy exceptions on failure."""


# ---------------------------------------------------------------------------
# Fail-loud sentinel — production-grade scaffold per CLAUDE.md
# ---------------------------------------------------------------------------


class KernelDefaultCredentialAdapter:
    """Fail-loud sentinel CredentialAdapter per the CLAUDE.md
    production-grade rule. NOT a real adapter — the ONLY safe
    consumption path is ``admit_policy``'s ``isinstance`` check, which
    refuses any policy declaring ``vault_path`` while this sentinel
    is wired.

    Sprint 10 T6 ships ``VaultCredentialAdapter`` as the first real
    concrete implementation per ADR-009. Until then, operators MUST
    EITHER wire a real adapter OR ensure no pack ever sets a
    non-None ``vault_path`` / declares ``requires_credentials``.

    The class is intentionally NOT a Protocol subclass — admit_policy
    uses an explicit ``isinstance(credential_adapter,
    KernelDefaultCredentialAdapter)`` check to distinguish the
    sentinel from any real adapter. A real adapter that structurally
    conforms to ``CredentialAdapter`` will NOT match the isinstance
    check (verified by the test
    ``test_isinstance_check_distinguishes_stub_from_real_adapter``).

    Sprint 10 T5 extension: the sentinel gains fail-loud
    ``mint_lease`` / ``revoke_lease`` methods that mirror
    ``fetch_secret``'s production-grade error-message convention
    (cite Sprint 10 + ADR-009 + ``VaultCredentialAdapter`` +
    "fail-loud sentinel" + echo input for debugging). The Sprint 10
    pre-Sprint-13.5 admission guard already refuses any policy
    requesting credentials when the sentinel is wired (sibling
    ``sandbox_credential_adapter_not_configured`` arm), so these
    fail-loud raises are defence-in-depth — they catch a future
    refactor that lets the sentinel reach the mint/revoke pathway.
    """

    async def fetch_secret(self, path: str) -> str | None:
        raise NotImplementedError(
            "KernelDefaultCredentialAdapter is a fail-loud sentinel; "
            "admit_policy should have refused before this method is "
            f"called. Got fetch_secret({path!r}). Sprint 10 ships "
            "VaultCredentialAdapter as the first real CredentialAdapter "
            "implementation per ADR-009."
        )

    # Sprint 10 T5 — fail-loud sentinel methods for the dual lease
    # API per ADR-004 §102 + spec §3.3. Mirrors ``fetch_secret``'s
    # error-message convention (Sprint 10 + ADR-009 + "fail-loud
    # sentinel" + echo input for debugging).
    async def mint_lease(self, request: VaultLeaseRequest) -> CredentialLease:
        raise NotImplementedError(
            "KernelDefaultCredentialAdapter is a fail-loud sentinel; "
            "admit_policy should have refused before this method is "
            f"called. Got mint_lease(secret_path={request.secret_path!r}). "
            "Sprint 10 ships VaultCredentialAdapter as the first real "
            "CredentialAdapter implementation per ADR-009; wire it in "
            "create_app() before any pack/sandbox declares "
            "requires_credentials."
        )

    async def revoke_lease(self, lease_id: str) -> None:
        raise NotImplementedError(
            "KernelDefaultCredentialAdapter is a fail-loud sentinel; "
            "admit_policy should have refused before this method is "
            f"called. Got revoke_lease({lease_id!r}). Sprint 10 ships "
            "VaultCredentialAdapter as the first real CredentialAdapter "
            "implementation per ADR-009; wire it in create_app() before "
            "any pack/sandbox declares requires_credentials."
        )


# ---------------------------------------------------------------------------
# Transitional high-risk-tier gate (pre-Sprint-13.5)
# ---------------------------------------------------------------------------


#: ADR-014 §29 transitional refusal — the 6 risk tiers that admit_policy
#: refuses pre-Sprint-13.5 (which will land the runtime tool-approval
#: engine + 4-eyes flow). Lockstep with the ADR-014 canonical 8-value
#: ``RiskTier`` Literal at ``cli/_governance_vocab.py`` is pinned by the
#: drift-detector test at ``tests/unit/sandbox/test_admission_pipeline.py
#: ::TestHighRiskTierDriftDetectorTestOnly`` (test-only cross-module
#: import per ``feedback_drift_detector_test_only_no_runtime_import`` —
#: this set is declared inline so production has no runtime dependency
#: on the cli package).
_HIGH_RISK_TIERS_PRE_13_5: frozenset[str] = frozenset(
    {
        "customer_data_read",
        "customer_data_write",
        "payment_action",
        "regulator_communication",
        "cross_tenant",
        "high_risk_custom",
    }
)


# ---------------------------------------------------------------------------
# Single admission seam
# ---------------------------------------------------------------------------


async def admit_policy(
    policy: SandboxPolicy,
    *,
    tenant_id: str,
    actor: Actor,
    pack_context: PackAdmissionContext,
    catalog: CatalogProtocol,
    credential_adapter: CredentialAdapter,
    rego_engine: OPAEngine,
    settings: Settings,
    requires_credentials: Sequence[VaultLeaseRequest] = (),
) -> None:
    """Admission pipeline per spec §6.1 — the single seam every
    backend MUST call.

    Internally runs Stage-1 (``validate_policy_shape``, pure
    synchronous) BEFORE Stage-2 (async I/O steps 3-9). Raises
    ``SandboxLifecycleRefused`` on the first failure in either stage.

    Stage-2 step ordering (load-bearing per spec §6.1; pinned by the
    8 adjacent-pair ordering tests at
    ``tests/unit/sandbox/test_admission_pipeline.py::
    TestAdmissionPipelineOrderingInvariants``):

      3. credential-adapter check — Sprint-8A static-secret path:
         ``policy.vault_path is not None`` AND only the sentinel
         adapter is wired → ``sandbox_credential_adapter_not_configured``.
     3a. dynamic-install refusal (production profile only)
     3b. (Sprint 10 T7) dynamic-lease admission block — runs ONLY when
         ``requires_credentials`` is non-empty. Two internal arms in
         fixed order:
           (i) Cross-tenant guard FIRST — any VaultLeaseRequest whose
               ``tenant_id`` does not match ``actor.tenant_id`` raises
               ``sandbox_credential_request_tenant_mismatch``. The
               check lives HERE (not on VaultLeaseRequest itself)
               because core/vault has NO knowledge of the requesting
               Actor — the architectural arrow runs sandbox → core.
          (ii) Sentinel-adapter guard SECOND — after every request
               passes the cross-tenant gate, if only the sentinel
               adapter is wired raise the EXISTING Sprint-8A
               ``sandbox_credential_adapter_not_configured`` reason
               (T7 scope lock — NO new closed-enum value).
         Internal ordering pinned by ``tests/unit/sandbox/
         test_admit_credentials.py::TestAdmitPolicyRefusesCrossTenantRequest::
         test_cross_tenant_check_wins_over_sentinel_adapter_check``.
      4. high-risk-tier transitional refusal (6 ADR-014 tiers)
      5. tenant-max check (cpu_cores / memory_mb / walltime_s)
      6. image-catalog membership (canonical OR per-tenant allow-list)
      7. cosign signature verification (delegates to catalog)
      8. SBOM policy check (delegates to catalog)
      9. Rego admission against ``data.cognic.sandbox.admit.allow``

    The Rego decision-point is invoked via the real
    ``OPAEngine.evaluate(*, decision_point, input)`` signature at
    ``core/policy/engine.py:269``; T9 owns the bundle at
    ``policies/_default/sandbox.rego``. **Wire-contract: the
    decision-point points at the ``allow`` boolean expression
    INSIDE the package, NOT at the package itself** — OPA's
    ``evaluate`` requires the expression result to be a single
    boolean; querying the bare package would return the package
    dict object once T11's real bundle lands, and the engine
    raises ``RegoEvaluationError`` on non-boolean expression
    values per ``core/policy/engine.py:296-298``. The
    ``Decision.reasoning`` field surfaces in the refusal detail
    when the bundle denies so examiners can trace the deny reason.

    Args:
        policy: the requested SandboxPolicy
        tenant_id: the tenant under which admission is requested
        actor: the requesting Actor (passed through for the eventual
            Rego input + the audit chain row in T4's emit pathway)
        pack_context: the immutable cosign-pinned pack identity
        catalog: the canonical image catalog (T6 concrete impl)
        credential_adapter: the runtime secret-fetch adapter (Sprint
            10 VaultCredentialAdapter; T5 ships only the fail-loud
            ``KernelDefaultCredentialAdapter`` sentinel)
        rego_engine: the OPA evaluator (Sprint 4 ``OPAEngine``)
        settings: the Settings container; admit_policy reads
            ``sandbox_per_tenant_max_*`` fields (extended in T5)
        requires_credentials: Sprint 10 T7 — sequence of
            VaultLeaseRequest the admitting pack declares it will
            need. Default ``()`` is a complete byte-shape no-op for
            Sprint-8A callers; when non-empty, admit_policy runs two
            additional checks at Step 3 (sentinel-adapter refusal
            reuses existing ``sandbox_credential_adapter_not_configured``)
            and Step 3b (cross-tenant guard raises new
            ``sandbox_credential_request_tenant_mismatch``) and threads
            the per-request shape into the Rego input dict at Step 9.

    Returns:
        None on green-path (all 9 steps passed).

    Raises:
        SandboxLifecycleRefused: on the first failure with the
            matching closed-enum ``SandboxRefusalReason`` (Stage-1
            shape-arm reason for steps 1-2; Stage-2 reason for steps
            3-9).
    """

    # Stage 1 — synchronous pure shape validation per spec §6.1 step 1+2.
    # Raises SandboxLifecycleRefused with the specific shape-arm reason
    # (sandbox_image_digest_format_invalid / sandbox_policy_egress_host_invalid
    # / etc.) BEFORE any async I/O. Single-seam contract per round-4 R4 P1 #4.
    validate_policy_shape(policy)

    # Stage 2 — async admission below (steps 3 through 9 per spec §6.1).

    # Step 3 — credential-adapter check (Sprint 8A static-secret path).
    # Unchanged from Sprint 8A: refuses when ``policy.vault_path`` is
    # non-None AND only the fail-loud sentinel adapter is wired.
    # The Sprint-10 dynamic-lease counterpart (non-empty
    # ``requires_credentials`` + sentinel) lives at Step 3b BELOW so
    # the cross-tenant check inside that block can run FIRST.
    if policy.vault_path is not None and isinstance(
        credential_adapter, KernelDefaultCredentialAdapter
    ):
        raise SandboxLifecycleRefused(
            "sandbox_credential_adapter_not_configured",
            detail=(
                f"policy.vault_path={policy.vault_path!r} requires a real "
                f"CredentialAdapter; Sprint 10 ships VaultCredentialAdapter "
                f"as the first real implementation per ADR-009"
            ),
        )

    # Step 3a — dynamic-install refusal (production profile only)
    if pack_context.declares_dynamic_install and pack_context.profile == "production":
        raise SandboxLifecycleRefused(
            "sandbox_runtime_deps_unsupported_in_production",
            detail=(
                f"pack {pack_context.pack_id} declares dynamic install + "
                f"profile=production; dev profile bypasses this gate"
            ),
        )

    # Step 3b — Sprint 10 T7 dynamic-lease admission block (per spec §6.1
    # + plan §1166-1180). Two refusal arms run in fixed order INSIDE
    # this block; ordering is load-bearing per the round-1 user-found
    # finding pinned by
    # ``test_cross_tenant_check_wins_over_sentinel_adapter_check``:
    #
    #   (i) Cross-tenant guard FIRST. Any VaultLeaseRequest whose
    #       ``tenant_id`` does not match ``actor.tenant_id`` raises the
    #       NEW closed-enum reason
    #       ``sandbox_credential_request_tenant_mismatch``. The check
    #       lives HERE (not on VaultLeaseRequest itself) because
    #       core/vault has NO knowledge of the requesting Actor — the
    #       architectural arrow runs sandbox → core, never the other
    #       direction.
    #
    #  (ii) Sentinel-adapter guard SECOND. If every request passed the
    #       cross-tenant check AND only the fail-loud sentinel adapter
    #       is wired, refuse with the EXISTING Sprint-8A
    #       ``sandbox_credential_adapter_not_configured`` reason
    #       (NOT a new closed-enum value — T7 scope lock).
    #
    # Why this order matters: a sentinel-wired + cross-tenant request
    # is BOTH problems at once, but the cross-tenant signal is the
    # more security-critical refusal — masking it behind the
    # sentinel-not-configured reason would hide a tenant-isolation
    # violation under a generic ops-config message, and a future
    # adapter rewire would silently unmask the violation rather than
    # report it at the original refusal.
    if requires_credentials:
        # (i) Cross-tenant guard — FIRST.
        for request in requires_credentials:
            if request.tenant_id != actor.tenant_id:
                raise SandboxLifecycleRefused(
                    "sandbox_credential_request_tenant_mismatch",
                    detail=(
                        f"VaultLeaseRequest.tenant_id={request.tenant_id!r} does not "
                        f"match actor.tenant_id={actor.tenant_id!r} "
                        f"(secret_path={request.secret_path!r})"
                    ),
                )
        # (ii) Sentinel-adapter guard — SECOND.
        if isinstance(credential_adapter, KernelDefaultCredentialAdapter):
            raise SandboxLifecycleRefused(
                "sandbox_credential_adapter_not_configured",
                detail=(
                    f"requires_credentials is non-empty "
                    f"({len(requires_credentials)} request(s)) but only the "
                    f"fail-loud sentinel adapter is wired; Sprint 10 ships "
                    f"VaultCredentialAdapter as the first real implementation "
                    f"per ADR-009"
                ),
            )

    # Step 4 — high-risk-tier transitional refusal (pre-Sprint-13.5)
    if pack_context.risk_tier in _HIGH_RISK_TIERS_PRE_13_5:
        raise SandboxLifecycleRefused(
            "sandbox_high_risk_tier_refused_pre_13_5",
            detail=(f"tier={pack_context.risk_tier!r} requires core/approval engine (Sprint 13.5)"),
        )

    # Step 5 — tenant-max check (cpu_cores / memory_mb / walltime_s)
    if policy.cpu_cores > settings.sandbox_per_tenant_max_cpu:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_cpu",
            detail=(
                f"cpu_cores={policy.cpu_cores} > tenant max {settings.sandbox_per_tenant_max_cpu}"
            ),
        )
    if policy.memory_mb > settings.sandbox_per_tenant_max_memory:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_memory",
            detail=(
                f"memory_mb={policy.memory_mb} > tenant max "
                f"{settings.sandbox_per_tenant_max_memory}"
            ),
        )
    if policy.walltime_s > settings.sandbox_per_tenant_max_walltime:
        raise SandboxLifecycleRefused(
            "sandbox_policy_exceeds_tenant_max_walltime",
            detail=(
                f"walltime_s={policy.walltime_s} > tenant max "
                f"{settings.sandbox_per_tenant_max_walltime}"
            ),
        )

    # Step 6 — image-catalog membership (canonical OR per-tenant allow-list)
    # Round-4 R4 P1 #3 fix: extract the digest for fast O(1) catalog
    # lookup BUT keep the full ``policy.runtime_image`` ref available
    # for cosign + syft subprocess calls inside the catalog (those
    # need the full OCI ref; ``docker.io/sha256:...`` is not a valid
    # ref). The catalog maintains a ``_digest_to_ref`` reverse-map.
    _, image_digest = policy.runtime_image.rsplit("@", 1)
    # T11 Pre-commit fix — capture both bools as locals so Step 9's
    # Rego input dict can thread the precomputed ``_runtime_image_authorised``
    # inputs the bundle's rule-4 check requires. Without this, every
    # otherwise-safe admission that already passed catalog + cosign +
    # SBOM verification would reach the Rego bundle with both fields
    # undefined and be denied with ``sandbox_policy_rego_denied`` —
    # a silent dead end. Capturing the bools here also avoids a second
    # ``catalog.is_canonical`` / ``catalog.is_tenant_allow_listed``
    # call at Step 9 (the in-memory catalog is cheap, but single-source
    # is the right shape; future remote-catalog backings would otherwise
    # double the round-trip).
    runtime_image_in_canonical_set = catalog.is_canonical(image_digest)
    runtime_image_in_tenant_allow_list = catalog.is_tenant_allow_listed(image_digest, tenant_id)
    if not (runtime_image_in_canonical_set or runtime_image_in_tenant_allow_list):
        raise SandboxLifecycleRefused(
            "sandbox_image_digest_not_in_canonical_catalog",
            detail=(
                f"digest {image_digest} not in canonical catalog and not "
                f"allow-listed for tenant {tenant_id} (full ref was "
                f"{policy.runtime_image})"
            ),
        )

    # Step 7 — cosign verification (catalog resolves digest → full ref
    # internally via its ``_digest_to_ref`` reverse-map; cosign shells
    # out against the real OCI ref, not ``docker.io/sha256:...``).
    await catalog.verify_cosign_or_refuse(image_digest, tenant_id=tenant_id)

    # Step 8 — SBOM policy check (same full-ref-resolution pattern)
    await catalog.verify_sbom_policy_or_refuse(image_digest, tenant_id=tenant_id)

    # Step 9 — Rego admission via the canonical ``OPAEngine.evaluate``
    # signature at ``core/policy/engine.py:269``: kw-only decision_point
    # + input; returns ``Decision(allow, rule_matched, reasoning,
    # decision_data)``. T9 owns the bundle at
    # ``policies/_default/sandbox.rego``.
    decision = await rego_engine.evaluate(
        # NOTE: The decision-point points at the ``.allow`` boolean
        # expression INSIDE the package — NOT at the bare
        # ``data.cognic.sandbox.admit`` package. OPA's evaluate
        # requires a boolean result; querying the package would
        # return a dict and raise RegoEvaluationError once T11's
        # real bundle lands. Spec §6.1 step 9 + §816 are the
        # wire-protocol-public source of truth.
        decision_point="data.cognic.sandbox.admit.allow",
        input={
            "policy": {
                "cpu_cores": policy.cpu_cores,
                "memory_mb": policy.memory_mb,
                "walltime_s": policy.walltime_s,
                "egress_allow_list": list(policy.egress_allow_list),
                "vault_path": policy.vault_path,
            },
            "pack_context": {
                "pack_id": pack_context.pack_id,
                "pack_version": pack_context.pack_version,
                "pack_artifact_digest": pack_context.pack_artifact_digest,
                "risk_tier": pack_context.risk_tier,
                "declares_dynamic_install": pack_context.declares_dynamic_install,
                "profile": pack_context.profile,
            },
            "tenant_max": {
                "cpu_cores": settings.sandbox_per_tenant_max_cpu,
                "memory_mb": settings.sandbox_per_tenant_max_memory,
                "walltime_s": settings.sandbox_per_tenant_max_walltime,
            },
            "credential_adapter_wired": not isinstance(
                credential_adapter, KernelDefaultCredentialAdapter
            ),
            # T11 — bundle rule 4 (defence-in-depth catalog membership
            # check; see ``policies/_default/sandbox.rego`` +
            # ``_runtime_image_authorised``). These two precomputed
            # bools were captured at Step 6 from the same catalog calls
            # that already gated the admission; threading them here is
            # what makes the rule-4 ``allow if`` branch decidable. Both
            # bools are reachable on a green path because Step 6 already
            # short-circuits the false/false case with a refusal — but
            # the Rego bundle MUST receive both fields to satisfy its
            # input contract, otherwise the precomputed-bool checks
            # become falsy-by-absence and the bundle denies fail-closed.
            "runtime_image_in_canonical_set": runtime_image_in_canonical_set,
            "runtime_image_in_tenant_allow_list": runtime_image_in_tenant_allow_list,
            "tenant_id": tenant_id,
            # Sprint 10 T7 — per-request projection threads the dynamic-
            # lease declarations into the Rego bundle. The 3-key shape
            # ({secret_path, ttl_s, scope_label}) intentionally OMITS
            # actor / tenant identity: the kernel-boundary cross-tenant
            # guard at Step 3b runs BEFORE Rego, so by the time the
            # bundle sees this list every entry's tenant has already
            # been validated against actor.tenant_id. Letting the bundle
            # re-decide tenant identity per request would be the exact
            # drift the kernel-boundary check defends against.
            # Default ``()`` callers produce an empty list (NOT a
            # missing key) so the bundle can read
            # ``count(input.requires_credentials)`` unconditionally
            # without a key-presence guard.
            "requires_credentials": [
                {
                    "secret_path": req.secret_path,
                    "ttl_s": req.ttl_s,
                    "scope_label": req.scope_label,
                }
                for req in requires_credentials
            ],
        },
    )
    if not decision.allow:
        raise SandboxLifecycleRefused(
            "sandbox_policy_rego_denied",
            detail=decision.reasoning or "rego policy denied (no reasoning)",
        )
