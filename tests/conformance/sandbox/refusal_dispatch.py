"""Sprint 8B T8B-a — cross-backend refusal-taxonomy dispatch.

Owns the ``TRIGGERS_BY_REASON`` registry — a mapping from each
wire-public ``SandboxRefusalReason`` value (at
``src/cognic_agentos/sandbox/protocol.py:34-50``) to a trigger
factory that, when entered as an async context manager, prepares
the backend / policy / context state such that a subsequent
``backend.create(...)`` raises ``SandboxLifecycleRefused`` carrying
the named refusal value.

Per the user-locked tightening edit A (Sprint 8B preflight,
2026-05-17): this module REGISTERS one trigger per refusal value.
It does NOT — and intentionally MUST NOT — claim that every backend
behaviorally raises every value via these triggers. Per-value
behavior coverage lives in the focused suites named in the
``test_refusal_taxonomy.py`` module docstring (admission pipeline /
warm-pool / per-backend tests). The membership pin at
``test_refusal_taxonomy.py`` is the load-bearing regression — it
fires when the production Literal and this registry's keyset
disagree.

Trigger bodies for the 13 admission-pipeline arms are
backend-agnostic no-ops because the admission refusal semantics
live in the policy + pack_context the caller passes to
``backend.create()``. Both ``DockerSiblingSandboxBackend`` and
``KubernetesPodSandboxBackend`` (lands Sprint 8B T8B-b) invoke
``admit_policy`` (``src/cognic_agentos/sandbox/admission.py:177``)
with the same inputs, so the same trigger envelopes operate
identically across backends.

Trigger bodies for the 2 backend-specific arms
(``sandbox_backend_unavailable`` + ``sandbox_warm_pool_drained``)
do touch backend state — but even there the behavior contract is
backend-agnostic: the warm-pool trigger drains
``backend._warm_pool`` (works for any backend that wires a
SandboxWarmPool); the backend-unavailable trigger documents the
per-backend monkey-patch the consuming test must apply (because
the "unavailable" failure mode is API-shape-specific —
``aiodocker.exceptions.DockerError(503)`` on Docker;
``kubernetes_asyncio.client.exceptions.ApiException(status=500)``
on K8s).

Design note (plan-amendment, recorded in T8B-a commit body): the
registry lives here — NOT inside ``conftest.py`` — because the
existing conformance ``conftest.py`` has
``pytest.importorskip("aiodocker")`` at module top. Importing the
registry from conftest would force aiodocker as a dep for the
backend-agnostic ``test_refusal_taxonomy.py`` membership test;
extracting to this module keeps the membership pin runnable in any
venv.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any

# Per ``feedback_consumer_owned_protocol_for_unlanded_dep`` — when
# a planned consumer has a dep on an unlanded module's API, the
# consumer declares the Protocol inline. Same shape here: the
# trigger factory contract is local to this module + the test that
# pins membership; consumers (a future cross-backend parametrize
# fixture) structurally conform.
type TriggerFactory = Callable[[Any, Any], AbstractAsyncContextManager[None]]


@asynccontextmanager
async def _trigger_sandbox_credential_adapter_not_configured(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the admission step-3 credential-adapter
    refusal at ``src/cognic_agentos/sandbox/admission.py:256-267``.

    Refusal fires when ``policy.vault_path is not None`` AND
    ``backend._credential_adapter`` is the
    ``KernelDefaultCredentialAdapter`` sentinel. Trigger is a no-op
    envelope — the caller orchestrates the policy + ctx setup that
    drives the refusal; behavior coverage lives at
    ``tests/unit/sandbox/test_admission_pipeline.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_runtime_deps_unsupported_in_production(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the admission step-3a dynamic-install
    refusal at ``src/cognic_agentos/sandbox/admission.py:269-277``.

    Refusal fires when ``pack_context.declares_dynamic_install`` AND
    ``pack_context.profile == "production"``. No-op envelope; caller
    drives the refusal via pack_context shape. Behavior coverage at
    ``tests/unit/sandbox/test_admission_pipeline.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_high_risk_tier_refused_pre_13_5(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the admission step-4 high-risk-tier
    refusal at ``src/cognic_agentos/sandbox/admission.py:279-284``.

    Refusal fires when ``pack_context.risk_tier`` is one of the 6
    high-risk tiers per ADR-014 pre-Sprint-13.5 + spec §13 rule 2.
    No-op envelope; caller drives the refusal via risk_tier value.
    Behavior coverage at
    ``tests/unit/sandbox/test_admission_pipeline.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_image_digest_not_in_canonical_catalog(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the admission step-6 catalog-membership
    refusal at ``src/cognic_agentos/sandbox/admission.py:311-339``.

    Refusal fires when the policy's runtime_image digest is NOT in
    the canonical catalog AND NOT in the tenant allow-list. No-op
    envelope; caller drives the refusal via policy.runtime_image
    pointing at a non-canonical digest. Behavior coverage at
    ``tests/unit/sandbox/test_admission_pipeline.py`` + the existing
    backend-specific test at
    ``tests/unit/sandbox/backends/test_docker_sibling_egress_classification.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_image_cosign_verification_failed(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the admission step-7 cosign refusal at
    ``src/cognic_agentos/sandbox/admission.py:341-344``.

    Refusal fires when ``catalog.verify_cosign_or_refuse`` raises.
    No-op envelope; caller drives via a catalog fixture whose
    cosign verifier is mocked to fail. Behavior coverage at
    ``tests/unit/sandbox/test_admission_pipeline.py`` +
    ``tests/unit/sandbox/test_image_catalog.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_image_sbom_check_failed(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the admission step-8 SBOM refusal at
    ``src/cognic_agentos/sandbox/admission.py:346-347``.

    Refusal fires when ``catalog.verify_sbom_policy_or_refuse``
    raises. No-op envelope; caller drives via a catalog fixture
    whose SBOM verifier is mocked to fail. Behavior coverage at
    ``tests/unit/sandbox/test_admission_pipeline.py`` +
    ``tests/unit/sandbox/test_image_catalog.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_image_digest_format_invalid(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the Stage-1 image-digest-format refusal
    at ``src/cognic_agentos/sandbox/policy.py``.

    Refusal fires when ``policy.runtime_image`` does not match the
    canonical OCI ref shape (registry/name@sha256:<64 hex>). No-op
    envelope; caller drives via a malformed runtime_image string.
    Behavior coverage at
    ``tests/unit/sandbox/test_admission_pipeline.py`` +
    ``tests/unit/sandbox/test_policy_shape.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_policy_exceeds_tenant_max_cpu(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the admission step-5 tenant-max-cpu
    refusal at ``src/cognic_agentos/sandbox/admission.py:286-293``.

    Refusal fires when ``policy.cpu_cores > settings.sandbox_per_tenant_max_cpu``.
    No-op envelope; caller drives via policy.cpu_cores. Behavior
    coverage at ``tests/unit/sandbox/test_admission_pipeline.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_policy_exceeds_tenant_max_memory(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the admission step-5 tenant-max-memory
    refusal at ``src/cognic_agentos/sandbox/admission.py:294-301``.

    No-op envelope; caller drives via policy.memory_mb. Behavior
    coverage at ``tests/unit/sandbox/test_admission_pipeline.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_policy_exceeds_tenant_max_walltime(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the admission step-5 tenant-max-walltime
    refusal at ``src/cognic_agentos/sandbox/admission.py:302-309``.

    No-op envelope; caller drives via policy.walltime_s. Behavior
    coverage at ``tests/unit/sandbox/test_admission_pipeline.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_policy_egress_host_invalid(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the Stage-1 egress-host RFC 1123 refusal
    at ``src/cognic_agentos/sandbox/policy.py:277,282``.

    Refusal fires when any ``policy.egress_allow_list`` entry fails
    the RFC 1123 hostname guard in ``_validate_egress_host``. No-op
    envelope; caller drives via a malformed host string. Behavior
    coverage at ``tests/unit/sandbox/test_admission_pipeline.py`` +
    ``tests/unit/sandbox/test_egress_proxy_config.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_policy_egress_protocol_not_http(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the Stage-1 HTTP/HTTPS-only scheme guard
    refusal at ``src/cognic_agentos/sandbox/policy.py:267``.

    Refusal fires when any ``policy.egress_allow_list`` entry carries
    a non-HTTP/HTTPS scheme (ftp:// / ssh:// / file:/// / etc). No-op
    envelope; caller drives via a non-HTTP scheme prefix. Behavior
    coverage at ``tests/unit/sandbox/test_admission_pipeline.py`` +
    ``tests/unit/sandbox/test_egress_proxy_config.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_policy_rego_denied(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the admission step-9 OPA Rego refusal at
    ``src/cognic_agentos/sandbox/admission.py:349-369``.

    Refusal fires when ``OPAEngine.evaluate`` against decision-point
    ``data.cognic.sandbox.admit.allow`` returns
    ``Decision(allow=False, ...)``. No-op envelope; caller
    drives via a mocked rego_engine fixture OR via input shaped to
    fail the live ``policies/_default/sandbox.rego`` bundle.
    Behavior coverage at
    ``tests/unit/sandbox/test_admission_pipeline.py`` +
    ``tests/unit/policies/test_sandbox_rego.py`` (now actually runs
    in CI thanks to T8B-pre OPA-on-CI commit ``4aa6c7b``).
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_backend_unavailable(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the backend-availability refusal.

    Backend-specific (NOT admission-pipeline) — fires when the
    backend's underlying API (Docker daemon socket / K8s API server)
    is unreachable. The per-backend test fixture is responsible for
    monkey-patching the API call to raise the backend-appropriate
    exception:

    * DockerSibling: monkey-patch ``backend._docker.containers.create``
      to raise ``aiodocker.exceptions.DockerError(503, "Daemon
      unreachable")``. ``sandbox_backend_unavailable`` is then
      surfaced by ``backend.create()`` translating the docker error.
    * KubernetesPod (Sprint 8B T8B-b): monkey-patch
      ``backend._kube.CoreV1Api.create_namespaced_pod`` to raise
      ``kubernetes_asyncio.client.exceptions.ApiException(status=500,
      reason="Service Unavailable")``. ``sandbox_backend_unavailable``
      is then surfaced by translating the K8s ApiException.

    NO behavior raise path exists in src today —
    ``sandbox_backend_unavailable`` was declared as a reserved
    Literal value at ``src/cognic_agentos/sandbox/protocol.py:48``
    in Sprint 8A; first behavior raise lands in Sprint 8B T8B-b
    when K8s ``health()`` surfaces the K8s-API-down case. This
    trigger envelope is the standing contract the future per-backend
    fixtures conform to.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_warm_pool_drained(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the SandboxWarmPool drained-pool refusal
    at ``src/cognic_agentos/sandbox/warm_pool.py:400``.

    Refusal fires when ``SandboxWarmPool.checkout()`` is called on a
    pool that has been ``drain()``ed. Backend-agnostic — SandboxWarmPool
    takes any SandboxBackend Protocol implementation via its
    constructor's ``backend`` arg at ``warm_pool.py:235``.

    Trigger drains the backend's wired warm pool before yielding.
    Caller subsequently calls ``backend.create(...)`` which routes
    through warm-pool checkout → raises
    ``SandboxLifecycleRefused("sandbox_warm_pool_drained")``.
    Behavior coverage at ``tests/unit/sandbox/test_warm_pool.py``.
    """
    if getattr(backend, "_warm_pool", None) is not None:
        await backend._warm_pool.drain()
    yield


# Sprint 8.5 — 6 wake-time refusal triggers per spec §3.3.
#
# No-op `yield` envelopes — IDENTICAL pattern to the 15 Sprint-8A
# admission-arm triggers above. The TRIGGERS_BY_REASON registry exists
# for the closed-enum REGISTRATION membership pin at
# test_refusal_taxonomy.py (tightening edit A); it is NOT a
# behaviour-fan-out harness. Per-value wake() behaviour coverage lives
# in the per-backend wake unit suite under `tests/unit/sandbox/`
# (single-backend scope) + the cross-backend
# `tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py`
# (tombstone-first parity; multi-backend scope).
#
# T1 seeded these as "forward declarations" anticipating that T9 would
# add substantive bodies — but T9's conformance tests use
# self-contained inline setup and never drive the registry, so wiring
# bodies here would be unreachable dead code. The triggers therefore
# stay no-op envelopes, consistent with all 15 admission triggers.


@asynccontextmanager
async def _trigger_sandbox_wake_checkpoint_not_found(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the wake-time checkpoint-not-found refusal
    at ``src/cognic_agentos/sandbox/protocol.py`` ``wake()`` step 1(b).

    No-op registration envelope (same pattern as the 15 admission-arm
    triggers above). Behaviour coverage — call wake() with a session_id
    that has NO persisted checkpoint AND no tombstone → expect
    ``sandbox_wake_checkpoint_not_found`` — lives in the per-backend
    wake unit suite under ``tests/unit/sandbox/``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_wake_checkpoint_corrupt(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the wake-time corrupt-metadata refusal at
    ``src/cognic_agentos/sandbox/protocol.py`` ``wake()`` step 1(c).

    No-op registration envelope. Behaviour coverage — pre-place
    malformed metadata.json so ``from_storage_payload()`` raises
    ``ValueError`` → expect ``sandbox_wake_checkpoint_corrupt`` — lives
    at ``tests/unit/sandbox/test_wake_checkpoint_corrupt.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_wake_checkpoint_retention_expired(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the wake-time retention-expired refusal at
    ``src/cognic_agentos/sandbox/protocol.py`` ``wake()`` step 3.

    No-op registration envelope. Behaviour coverage — pre-place
    metadata.json with ``created_at`` older than ``retention_window_s``
    → expect ``sandbox_wake_checkpoint_retention_expired`` — lives in
    the per-backend wake unit suite under ``tests/unit/sandbox/``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_wake_session_tombstoned(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the wake-time tombstoned-session refusal at
    ``src/cognic_agentos/sandbox/protocol.py`` ``wake()`` step 1(a) —
    the P1.r6 fail-closed path that also catches `TombstoneCorruptError`.

    No-op registration envelope. Behaviour coverage — single-backend
    closed-enum + detail-field invariants at
    ``tests/unit/sandbox/test_wake_session_tombstoned.py``;
    cross-backend tombstone-first parity at
    ``tests/conformance/sandbox/test_wake_session_tombstoned_conformance.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_wake_tenant_mismatch(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the wake-time tenant-mismatch refusal at
    ``src/cognic_agentos/sandbox/protocol.py`` ``wake()`` step 2.

    No-op registration envelope. Behaviour coverage — pre-place
    metadata under tenant-a; call wake with tenant_id=tenant-b for
    defence-in-depth past the prefix-keyed lookup → expect
    ``sandbox_wake_tenant_mismatch`` — lives at
    ``tests/unit/sandbox/test_wake_tenant_mismatch.py``. Pins the extra
    design lock: session_id alone is NEVER authorization.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_wake_policy_revalidation_failed(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the wake-time policy-revalidation refusal at
    ``src/cognic_agentos/sandbox/protocol.py`` ``wake()`` step 4 (per Q3
    lock — wake re-runs admit_policy against LIVE tenant policy / catalog
    / Rego / settings).

    No-op registration envelope. Behaviour coverage — pre-place
    metadata under an older-passing policy; tighten live tenant
    Settings so revalidation refuses → expect
    ``sandbox_wake_policy_revalidation_failed`` — lives at
    ``tests/unit/sandbox/test_wake_admit_policy_revalidation.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_request_tenant_mismatch(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Sprint 10 T7 — trigger envelope for the kernel-boundary
    cross-tenant guard at ``sandbox/admission.py``.

    No-op registration envelope. Behaviour coverage —
    ``admit_policy`` is called with a ``requires_credentials`` whose
    ``VaultLeaseRequest.tenant_id`` differs from
    ``actor.tenant_id`` → expect
    ``sandbox_credential_request_tenant_mismatch`` — lives at
    ``tests/unit/sandbox/test_admit_credentials.py::test_admit_policy_refuses_cross_tenant_request``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_mint_failed_vault_unavailable(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Sprint 10 T10 — trigger envelope for the Vault-unavailable
    mint failure mapped at backend ``create()`` post-admission per
    spec §7.1.

    No-op registration envelope. Behaviour coverage — Docker:
    ``tests/unit/sandbox/backends/test_docker_sibling_credentials.py::TestMintFailureClosedEnumMapping``
    parametrize row for ``VaultUnavailable`` (AND
    ``VaultProtocolError`` per the spec §7.1 collapse). K8s parallel
    lands at the T10 K8s commit's
    ``test_kubernetes_pod_credentials.py``. Closed-enum collapse
    rationale lives in ``_mint_exception_to_refusal_reason`` at
    ``sandbox/backends/docker_sibling.py``.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_mint_failed_secret_path_unknown(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Sprint 10 T10 — trigger envelope for the Vault 404
    mint failure mapped at backend ``create()`` post-admission per
    spec §7.1.

    No-op registration envelope. Behaviour coverage — Docker:
    ``tests/unit/sandbox/backends/test_docker_sibling_credentials.py::TestMintFailureClosedEnumMapping``
    parametrize row for ``VaultPathNotFound``. K8s parallel at the
    T10 K8s commit.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_mint_failed_auth_denied(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Sprint 10 T10 — trigger envelope for the Vault 403
    mint failure mapped at backend ``create()`` post-admission per
    spec §7.1.

    No-op registration envelope. Behaviour coverage — Docker:
    ``tests/unit/sandbox/backends/test_docker_sibling_credentials.py::TestMintFailureClosedEnumMapping``
    parametrize row for ``VaultAuthDenied``. K8s parallel at the
    T10 K8s commit.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_ttl_exceeds_tenant_max(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Sprint 10 T9 (Literal lift only) — trigger envelope for the
    per-tenant max-credential-TTL cap value.

    No-op registration envelope. **Special case: NO Stage-2 raise
    site at T9 or T10** per spec §7.3 amendment —
    ``OPAEngine.Decision`` exposes only ``allow`` + generic
    ``reasoning`` with no per-rule-name channel, so the
    ``sandbox.rego`` rule-6 cap-exceeded denial continues to surface
    as the generic ``sandbox_policy_rego_denied`` at
    ``admission.py:601-603``. The closed-enum value is reserved on
    the Literal for the follow-up Rego-reason-surfacing task (a
    per-rule deny-set carried via ``decision_data`` OR a
    ``rule_name`` channel on ``Decision``). This trigger envelope
    is REGISTERED so the membership pin stays green; behaviour
    coverage lands when the Rego-reason-surfacing task ships.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_lease_ttl_grant_exceeds_request(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Sprint 10.1 — trigger envelope for the post-mint
    granted-vs-requested TTL refusal raised by
    ``core/vault.lease_credential`` when
    ``ttl_s_granted > request.ttl_s`` per ADR-004 §25 amendment.

    No-op registration envelope. Behaviour coverage at the kernel
    layer lives in
    ``tests/unit/core/test_vault.py::TestLeaseCredentialTTLGrantEnforcement``;
    cross-backend mapping coverage lives at
    ``tests/unit/sandbox/backends/test_shared_credentials.py::TestMintExceptionToRefusalReasonMapping``
    (5th parametrize row) + the per-backend create() except-tuple
    regressions at
    ``tests/unit/sandbox/backends/test_docker_sibling_credentials.py::TestGrantExceedsRequestClosedEnumMapping``
    +
    ``tests/unit/sandbox/backends/test_kubernetes_pod_credentials.py::TestKubernetesGrantExceedsRequestClosedEnumMapping``.
    """
    yield


# Sprint 10.6 T16 — 9 credential-projection trigger envelopes per
# spec §5.1.
#
# **All 9 are honest no-op registration envelopes.** The conformance
# registry at ``TRIGGERS_BY_REASON`` below pins SET MEMBERSHIP between
# the wire-public ``SandboxRefusalReason`` Literal and the registry's
# keyset (see the doctrine at
# ``tests/conformance/sandbox/test_refusal_taxonomy.py:55-62``); it is
# NOT a behaviour-fan-out harness. Per-value runtime coverage lives in:
#
#   - The T18 ``sandbox/projection.py`` planner unit suite (when T18
#     lands later in Sprint 10.6) — for the 4 planner-emitted values
#     (``..._field_set_mismatch`` + ``..._field_value_non_string`` +
#     ``..._field_value_empty_string`` + ``..._field_value_size_exceeded``).
#   - The T21 lifecycle integration cross-backend conformance suite
#     (when T21 lands) — for the 5 lifecycle-emitted values
#     (``..._staging_path_not_tmpfs`` + ``..._workload_gid_unknown`` +
#     ``..._image_gid_manifest_mismatch`` +
#     ``..._image_user_directive_non_numeric`` +
#     ``..._root_workload_refused``).
#
# T16 wires Literal + registry only — no behaviour, no runtime claim.


@asynccontextmanager
async def _trigger_sandbox_credential_projection_field_set_mismatch(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the projection-time field-set-mismatch
    refusal — raised by Sprint 10.6 T18
    ``sandbox/projection.py::compute_projection_plan(...)`` when the
    Vault lease response's ``actual_fields`` tuple differs from the
    manifest's declared ``expected_fields`` (alphabetised; ``extras``
    + ``missing`` reported in the projection-failed payload per
    spec §4.4).

    No-op registration envelope (same pattern as the Sprint 8.5
    wake-time triggers + the Sprint 10 mint-failure triggers above).
    Behaviour coverage will live at the T18 planner unit suite when
    that task lands.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_staging_path_not_tmpfs(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the substrate-preflight tmpfs-check
    refusal — raised by Sprint 10.6 T21 lifecycle integration when
    the per-backend executor detects that the credential staging
    path (``/dev/shm/...`` on Docker; the projected-secret mount
    on K8s) is NOT backed by tmpfs per spec §5.8 step 2.

    No-op registration envelope. Behaviour coverage at the T21
    cross-backend conformance suite when that task lands.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_projection_workload_gid_unknown(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the workload-GID resolution refusal —
    raised by Sprint 10.6 T21 lifecycle integration when the runtime
    image's USER directive cannot be resolved to a numeric GID
    per spec §5.8 step 2 (preflight) + spec §5.1 (manifest contract).

    No-op registration envelope. Behaviour coverage at the T21
    cross-backend conformance suite when that task lands.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_projection_image_gid_manifest_mismatch(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the image-vs-manifest GID-mismatch
    refusal — raised by Sprint 10.6 T21 lifecycle integration when
    the runtime image's resolved USER GID differs from the manifest's
    declared ``[runtime].expected_workload_gid`` per spec §5.8 step 2.

    No-op registration envelope. Behaviour coverage at the T21
    cross-backend conformance suite when that task lands.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_projection_image_user_directive_non_numeric(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the image-USER-directive-non-numeric
    refusal — raised by Sprint 10.6 T21 lifecycle integration when
    the runtime image's USER directive is non-numeric (e.g.,
    ``USER root`` or ``USER appuser``) per spec §5.8 step 2 (the
    projection layer requires numeric GIDs for chgrp / fsGroup
    pinning).

    No-op registration envelope. Behaviour coverage at the T21
    cross-backend conformance suite when that task lands.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_projection_root_workload_refused(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the root-workload refusal — raised by
    Sprint 10.6 T21 lifecycle integration when the resolved workload
    GID is 0 (root) per spec §5.8 step 2 (the projection layer
    refuses root workloads because chgrp to 0 + fsGroup 0 would
    grant credential read to any process in the sandbox).

    No-op registration envelope. Behaviour coverage at the T21
    cross-backend conformance suite when that task lands.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_projection_field_value_non_string(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the field-value-non-string refusal —
    raised by Sprint 10.6 T18
    ``sandbox/projection.py::compute_projection_plan(...)`` when
    a Vault field value is not a string per spec §5.1 (credential
    values must be strings on the wire; non-string types would
    break the projection contract).

    No-op registration envelope. Behaviour coverage at the T18
    planner unit suite when that task lands.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_projection_field_value_empty_string(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the field-value-empty-string refusal —
    raised by Sprint 10.6 T18
    ``sandbox/projection.py::compute_projection_plan(...)`` when a
    Vault field value is an empty string per spec §5.1 (zero-byte
    credential values are refused; if a credential is genuinely
    empty, the pack must omit the field from ``expected_fields``).

    No-op registration envelope. Behaviour coverage at the T18
    planner unit suite when that task lands.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_credential_projection_field_value_size_exceeded(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the field-value-size-exceeded refusal —
    raised by Sprint 10.6 T18
    ``sandbox/projection.py::compute_projection_plan(...)`` when a
    Vault field value exceeds the per-value size cap per spec §5.1
    (oversized values are refused at the projection planner
    boundary; the cap protects the tmpfs staging area).

    No-op registration envelope. Behaviour coverage at the T18
    planner unit suite when that task lands.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_tenant_config_overlay_invalid(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """ADR-023 (Wave-2) — trigger envelope for the per-tenant
    config-overlay cap-resolution failure raised by ``admit_policy`` at
    Step 5 when a wired ``TenantConfigResolver`` surfaces a corrupt /
    loosening stored overlay (``TenantConfigOverlayInvalid``);
    fail-closed.

    No-op registration envelope. Unlike the Sprint-10.6 projection
    stubs, this refusal is REAL + already wired (admit_policy raises
    it) — but it is unit-proven at the admit_policy SEAM, not via a
    backend ``create()`` path, because Wave-2 is seam-only (no
    production Runtime->sandbox overlay path). Behaviour coverage lives
    at ``tests/unit/sandbox/test_admission_overlay.py``.
    """
    yield


#: Public registry — maps every wire-public ``SandboxRefusalReason``
#: value to a trigger factory. The membership pin at
#: ``test_refusal_taxonomy.py`` asserts this dict's keyset equals
#: ``frozenset(get_args(SandboxRefusalReason))``. Drift in either
#: direction fails CI with a structured diagnostic.
#:
#: When adding a new ``SandboxRefusalReason`` value at
#: ``src/cognic_agentos/sandbox/protocol.py``, add the corresponding
#: trigger factory above + register it here. The
#: ``test_refusal_reason_count_locked_at_thirty_seven`` regression
#: also needs its hard-coded count updated.
TRIGGERS_BY_REASON: dict[str, TriggerFactory] = {
    # Sprint 8A — 15 admission-arm triggers
    "sandbox_credential_adapter_not_configured": (
        _trigger_sandbox_credential_adapter_not_configured
    ),
    "sandbox_runtime_deps_unsupported_in_production": (
        _trigger_sandbox_runtime_deps_unsupported_in_production
    ),
    "sandbox_high_risk_tier_refused_pre_13_5": (_trigger_sandbox_high_risk_tier_refused_pre_13_5),
    "sandbox_image_digest_not_in_canonical_catalog": (
        _trigger_sandbox_image_digest_not_in_canonical_catalog
    ),
    "sandbox_image_cosign_verification_failed": (_trigger_sandbox_image_cosign_verification_failed),
    "sandbox_image_sbom_check_failed": _trigger_sandbox_image_sbom_check_failed,
    "sandbox_image_digest_format_invalid": _trigger_sandbox_image_digest_format_invalid,
    "sandbox_policy_exceeds_tenant_max_cpu": _trigger_sandbox_policy_exceeds_tenant_max_cpu,
    "sandbox_policy_exceeds_tenant_max_memory": (_trigger_sandbox_policy_exceeds_tenant_max_memory),
    "sandbox_policy_exceeds_tenant_max_walltime": (
        _trigger_sandbox_policy_exceeds_tenant_max_walltime
    ),
    "sandbox_policy_egress_host_invalid": _trigger_sandbox_policy_egress_host_invalid,
    "sandbox_policy_egress_protocol_not_http": (_trigger_sandbox_policy_egress_protocol_not_http),
    "sandbox_policy_rego_denied": _trigger_sandbox_policy_rego_denied,
    "sandbox_backend_unavailable": _trigger_sandbox_backend_unavailable,
    "sandbox_warm_pool_drained": _trigger_sandbox_warm_pool_drained,
    # Sprint 8.5 — 6 wake-time triggers. No-op registration envelopes
    # (same pattern as the 15 admission-arm triggers); the registry is
    # the closed-enum membership pin, not a behaviour harness — see the
    # section comment above the wake-time trigger block.
    "sandbox_wake_checkpoint_not_found": _trigger_sandbox_wake_checkpoint_not_found,
    "sandbox_wake_checkpoint_corrupt": _trigger_sandbox_wake_checkpoint_corrupt,
    "sandbox_wake_checkpoint_retention_expired": (
        _trigger_sandbox_wake_checkpoint_retention_expired
    ),
    "sandbox_wake_session_tombstoned": _trigger_sandbox_wake_session_tombstoned,
    "sandbox_wake_tenant_mismatch": _trigger_sandbox_wake_tenant_mismatch,
    "sandbox_wake_policy_revalidation_failed": _trigger_sandbox_wake_policy_revalidation_failed,
    # Sprint 10 — 5 credential-leasing values (4 lifted at T9 + 1
    # lifted at T7 cross-tenant guard). The 3 mint-failure values
    # get their Stage-2 raise sites at T10 backend create(); the
    # cross-tenant value's Stage-2 raise lives in
    # sandbox/admission.py since T7; the TTL-cap value is Literal-
    # only per spec §7.3 (Rego-reason surfacing deferred).
    "sandbox_credential_request_tenant_mismatch": (
        _trigger_sandbox_credential_request_tenant_mismatch
    ),
    "sandbox_credential_mint_failed_vault_unavailable": (
        _trigger_sandbox_credential_mint_failed_vault_unavailable
    ),
    "sandbox_credential_mint_failed_secret_path_unknown": (
        _trigger_sandbox_credential_mint_failed_secret_path_unknown
    ),
    "sandbox_credential_mint_failed_auth_denied": (
        _trigger_sandbox_credential_mint_failed_auth_denied
    ),
    "sandbox_credential_ttl_exceeds_tenant_max": (
        _trigger_sandbox_credential_ttl_exceeds_tenant_max
    ),
    # Sprint 10.1 — post-mint granted-vs-requested TTL refusal
    # (VaultLeaseGrantExceedsRequest mapped at the sandbox boundary per
    # ADR-004 §25 amendment). Wired at the backend create() Stage-2
    # except-tuple in the SAME commit as this trigger registration per
    # Finding B of the 2026-05-24 plan-review round 1.
    "sandbox_credential_lease_ttl_grant_exceeds_request": (
        _trigger_sandbox_credential_lease_ttl_grant_exceeds_request
    ),
    # Sprint 10.6 T16 — 9 credential-projection registration entries.
    # All envelopes are honest no-op `yield` stubs; the registry
    # entries here keep the membership-coverage pin green. The 4
    # planner-emitted values get their Stage-2 raise sites at T18
    # ``sandbox/projection.py``; the 5 lifecycle-emitted values get
    # theirs at T21 ``SandboxBackend.create()`` integration.
    "sandbox_credential_projection_field_set_mismatch": (
        _trigger_sandbox_credential_projection_field_set_mismatch
    ),
    "sandbox_credential_staging_path_not_tmpfs": (
        _trigger_sandbox_credential_staging_path_not_tmpfs
    ),
    "sandbox_credential_projection_workload_gid_unknown": (
        _trigger_sandbox_credential_projection_workload_gid_unknown
    ),
    "sandbox_credential_projection_image_gid_manifest_mismatch": (
        _trigger_sandbox_credential_projection_image_gid_manifest_mismatch
    ),
    "sandbox_credential_projection_image_user_directive_non_numeric": (
        _trigger_sandbox_credential_projection_image_user_directive_non_numeric
    ),
    "sandbox_credential_projection_root_workload_refused": (
        _trigger_sandbox_credential_projection_root_workload_refused
    ),
    "sandbox_credential_projection_field_value_non_string": (
        _trigger_sandbox_credential_projection_field_value_non_string
    ),
    "sandbox_credential_projection_field_value_empty_string": (
        _trigger_sandbox_credential_projection_field_value_empty_string
    ),
    "sandbox_credential_projection_field_value_size_exceeded": (
        _trigger_sandbox_credential_projection_field_value_size_exceeded
    ),
    # ADR-023 (Wave-2) — per-tenant config-overlay cap-resolution failure
    # (admit_policy Step 5; fail-closed). Real refusal, seam-unit-proven.
    "sandbox_tenant_config_overlay_invalid": (_trigger_sandbox_tenant_config_overlay_invalid),
}
