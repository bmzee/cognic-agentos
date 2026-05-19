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


# Sprint 8.5 T1 — 6 new wake-time refusal triggers per spec §3.3.
# Forward declarations only: substantive setup logic (pre-place
# tombstone sentinel, malformed metadata, etc.) lands at T9 alongside
# the CheckpointStore (T3) + the backend wake() impls (T6/T7). At T1,
# these are no-op `yield` envelopes that register the closed-enum
# membership pin (same pattern as the Sprint 8B T8B-a forward
# declarations for the 15 8A admission-arm triggers).


@asynccontextmanager
async def _trigger_sandbox_wake_checkpoint_not_found(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the wake-time checkpoint-not-found refusal
    at ``src/cognic_agentos/sandbox/protocol.py`` ``wake()`` step 1(b).

    Sprint 8.5 T1 forward declaration — substantive setup (call wake()
    with a session_id that has NO persisted checkpoint AND no tombstone)
    lands at T9 once T3's CheckpointStore + T6/T7's wake() impls land.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_wake_checkpoint_corrupt(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the wake-time corrupt-metadata refusal at
    ``src/cognic_agentos/sandbox/protocol.py`` ``wake()`` step 1(c).

    Sprint 8.5 T1 forward declaration — substantive setup (pre-place
    malformed metadata.json so from_storage_payload() raises ValueError)
    lands at T9.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_wake_checkpoint_retention_expired(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the wake-time retention-expired refusal at
    ``src/cognic_agentos/sandbox/protocol.py`` ``wake()`` step 3.

    Sprint 8.5 T1 forward declaration — substantive setup (pre-place
    metadata.json with created_at older than retention_window_s) lands
    at T9.
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

    Sprint 8.5 T1 forward declaration — substantive setup (pre-place
    `<tenant>/<session>/_tombstoned.json` sentinel via
    `CheckpointStore.tombstone_session()`) lands at T9.
    """
    yield


@asynccontextmanager
async def _trigger_sandbox_wake_tenant_mismatch(
    backend: Any,
    ctx: Any,
) -> AsyncIterator[None]:
    """Trigger envelope for the wake-time tenant-mismatch refusal at
    ``src/cognic_agentos/sandbox/protocol.py`` ``wake()`` step 2.

    Sprint 8.5 T1 forward declaration — substantive setup (pre-place
    metadata under tenant-a; call wake with tenant_id=tenant-b for
    defence-in-depth past the prefix-keyed lookup) lands at T9.
    Pins the extra design lock: session_id alone is NEVER authorization.
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

    Sprint 8.5 T1 forward declaration — substantive setup (pre-place
    metadata under an older-passing policy; tighten live tenant Settings
    so revalidation refuses) lands at T9.
    """
    yield


#: Public registry — maps every wire-public ``SandboxRefusalReason``
#: value to a trigger factory. The membership pin at
#: ``test_refusal_taxonomy.py`` asserts this dict's keyset equals
#: ``frozenset(get_args(SandboxRefusalReason))``. Drift in either
#: direction fails CI with a structured diagnostic.
#:
#: When adding a new ``SandboxRefusalReason`` value at
#: ``src/cognic_agentos/sandbox/protocol.py:34-50``, add the
#: corresponding trigger factory above + register it here. The
#: ``test_refusal_reason_count_locked_at_twenty_one`` regression
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
    # Sprint 8.5 T1 — 6 new wake-time triggers (forward declarations;
    # substantive bodies land at T9 alongside T3 CheckpointStore +
    # T6/T7 backend wake() impls).
    "sandbox_wake_checkpoint_not_found": _trigger_sandbox_wake_checkpoint_not_found,
    "sandbox_wake_checkpoint_corrupt": _trigger_sandbox_wake_checkpoint_corrupt,
    "sandbox_wake_checkpoint_retention_expired": (
        _trigger_sandbox_wake_checkpoint_retention_expired
    ),
    "sandbox_wake_session_tombstoned": _trigger_sandbox_wake_session_tombstoned,
    "sandbox_wake_tenant_mismatch": _trigger_sandbox_wake_tenant_mismatch,
    "sandbox_wake_policy_revalidation_failed": _trigger_sandbox_wake_policy_revalidation_failed,
}
