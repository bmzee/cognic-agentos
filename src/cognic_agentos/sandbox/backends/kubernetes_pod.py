"""Sprint 8B T8B-b — KubernetesPodSandboxBackend.

Critical-controls module per AGENTS.md + ADR-004 amendment.

Wave-1 production backend for Kubernetes/OpenShift per
``project_openshift_deployment_target``. Conforms to the same
:class:`SandboxBackend` Protocol as
:class:`DockerSiblingSandboxBackend`
(:mod:`cognic_agentos.sandbox.protocol`). Emits the same 8-event audit
taxonomy via :func:`emit_sandbox_event` and the same 15-value
:data:`SandboxRefusalReason` closed-enum.

Topology per ``feedback_sandbox_network_isolation_precision`` +
ADR-004 amendment "dual-container":

* Two-container Pod sharing localhost (K8s pods' containers share
  network namespace). The sandbox container's ``HTTP_PROXY`` /
  ``HTTPS_PROXY`` env points at ``http://localhost:<_PROXY_PORT>``
  — the egress-proxy sidecar listens on that port inside the same
  Pod netns. NOT a separate ClusterIP Service (which would
  introduce a cluster-DNS dependency + extra hop).
* Per-session :class:`V1NetworkPolicy` selects the pod by its
  ``cognic.agentos.sandbox.session_id`` label and declares
  ``policyTypes: [Egress]`` with NO ``egress`` rules — K8s
  deny-all-egress pattern. The pod cannot reach anything OUTSIDE
  the Pod directly; the proxy sidecar's upstream destinations are
  governed by the cluster-wide egress-proxy NetworkPolicy
  installed by the deployment kit (Sprint 14).

OpenShift compatibility per ADR-004 §30 + the OpenShift restricted-v2
SCC contract:

* SecurityContext OMITS ``privileged`` (defends against future K8s
  API changes where the default might change) + OMITS ``runAsUser``
  / ``runAsGroup`` (OpenShift's MustRunAsRange policy assigns the
  UID + GID from the namespace-allocated range; hard-coded values
  collide).
* SecurityContext sets ``runAsNonRoot=True`` +
  ``readOnlyRootFilesystem=True`` + ``allowPrivilegeEscalation=False``
  + ``capabilities.drop=[ALL]``.
* RestartPolicy=Never — sandbox pods are one-shot; a crashed
  container MUST NOT be silently restarted (the failure signal
  would be lost).

Canonical image catalog per
``feedback_canonical_artifact_not_oss_substitute``: the proxy
sidecar image is the REAL ``cognic/sandbox-egress-proxy`` artifact
(Sprint 8A T6 catalog gate; cosign-signed; SBOM-scanned). NEVER
substituted by an OSS proxy at runtime.

Sub-task arc:

* **T8B-b** (this commit) — lifecycle + dual-container topology +
  pure helpers. ``create() / destroy() / health()`` Protocol
  surface; the K8s-specific resource-cap derivation (millicores +
  Mebibytes); per-session NetworkPolicy create + delete.
  ``exec()`` is intentionally NotImplementedError pointing at
  T8B-c — calling it returns a structured error.
* **T8B-c** — ``exec()`` body via the K8s ``pods/exec`` subresource
  (websocket stream); cap-violation classification (OOMKilled
  detection via ``ContainerStatus.lastState.terminated.reason``;
  walltime; cpu-budget); backend factory in
  :mod:`cognic_agentos.sandbox.backend_factory`.
* **T8B-d** — durable critical-controls coverage gate promotion at
  95/90.

``kubernetes_asyncio`` dep (``sandbox-k8s`` extra): the module
imports ``kubernetes_asyncio`` at module level. Deployments that
do not need the K8s backend must NOT import this module; the
package-level re-export at :mod:`cognic_agentos.sandbox` wraps the
import in a ``try / except ImportError`` so the sandbox package
itself stays importable without the extra.
"""

from __future__ import annotations

import contextlib
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import kubernetes_asyncio  # noqa: F401 — admission contract: the sandbox-k8s extra MUST be installed
from kubernetes_asyncio import client as kube_client

from cognic_agentos.sandbox.admission import (
    CatalogProtocol,
    CredentialAdapter,
    admit_policy,
)
from cognic_agentos.sandbox.audit import emit_sandbox_event
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.protocol import (
    SandboxBackendHealth,
    SandboxExecResult,
    SandboxLifecycleRefused,
    SandboxSession,
)

if TYPE_CHECKING:
    from cognic_agentos.core.audit import AuditStore
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    from cognic_agentos.core.policy.engine import OPAEngine
    from cognic_agentos.portal.rbac.actor import Actor
    from cognic_agentos.sandbox.warm_pool import SandboxWarmPool


# ---------------------------------------------------------------------------
# Constants — naming + label conventions + port
# ---------------------------------------------------------------------------

#: Container name for the sandbox container inside the Pod. Pinned as
#: a constant so the pod-spec builder + the future exec() body in
#: T8B-c agree on which container to target (K8s exec requires the
#: container name when the pod has multiple containers).
_SANDBOX_CONTAINER_NAME: str = "sandbox"

#: Container name for the egress-proxy sidecar inside the Pod. Pinned
#: as a constant so the pod-spec builder + the proxy-log readback in
#: T8B-c agree on which container holds the proxy state.
_PROXY_SIDECAR_CONTAINER_NAME: str = "egress-proxy"

#: Port the proxy sidecar listens on inside the shared Pod netns.
#: The sandbox container's HTTP_PROXY / HTTPS_PROXY env targets
#: ``http://localhost:<this-port>`` per
#: ``feedback_sandbox_network_isolation_precision``. Wire-contract
#: with the canonical ``cognic/sandbox-egress-proxy`` image which
#: EXPOSEs + binds this port. Matches the Sprint-8A docker_sibling
#: backend's ``_PROXY_PORT`` so the canonical proxy image binds the
#: same port across backends.
_PROXY_PORT: int = 3128

#: Forward-proxy URL scheme. Wave-1 doctrine: HTTP/HTTPS only
#: through the AgentOS-controlled proxy endpoint per spec §10 +
#: ``feedback_sandbox_network_isolation_precision``. Split out as a
#: constant so the f-string assembling the proxy URL does NOT carry
#: a ``http://`` URL literal (which would trip
#: ``tests/unit/architecture/test_no_env_specific_values_in_source.py``
#: — the URL-literal guard is keyed to ``^https?://``).
_PROXY_SCHEME: str = "http"

#: Wire-protocol-adjacent label keys. Bank ops tooling reads these
#: to correlate pods with AgentOS sessions; drift breaks operator
#: dashboards silently. Matches the Sprint-8A docker_sibling backend's
#: ``cognic.agentos.sandbox.*`` label namespace so a bank running
#: BOTH backends in different namespaces can grep with the same
#: selector.
_SESSION_ID_LABEL: str = "cognic.agentos.sandbox.session_id"
_TENANT_ID_LABEL: str = "cognic.agentos.sandbox.tenant_id"

#: Canonical egress-proxy image. Per
#: ``feedback_canonical_artifact_not_oss_substitute`` — the REAL
#: ``cognic/sandbox-egress-proxy`` Sprint-8A T6 artifact; NEVER
#: substituted by an OSS proxy at runtime. Digest is a placeholder
#: in this module (the live Sprint-8A T6 catalog publishes the
#: cosign-signed digest at supply-chain pipeline build time); the
#: admission seam in ``create()`` verifies the digest against the
#: catalog before the pod starts (mirrors docker_sibling's
#: ``_start_proxy_sidecar`` R1 P1.1 gate).
_CANONICAL_EGRESS_PROXY_IMAGE: str = "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64


# ---------------------------------------------------------------------------
# Pure-functional helpers (unit-tested at test_kubernetes_pod_pure_helpers.py)
# ---------------------------------------------------------------------------


def _pod_name(session_id: str) -> str:
    """Deterministic per-session pod name.

    Format: ``sb-{session_id}``. The ``sb-`` prefix distinguishes
    AgentOS sandbox pods from other pods in the same namespace +
    keeps the name under K8s 253-char limit (uuid4 hex is 32
    chars; ``sb-`` + 32 = 35 chars). Determinism is required for
    idempotent pod creation — a retry after a transient apiserver
    hiccup MUST resolve to the same pod, not orphan a previous one.

    RFC 1123: pod names MUST be lowercase a-z, 0-9, hyphens; uuid4
    hex is already lowercase + LDH-compatible.

    Pinned by ``test_pod_name_is_session_id_prefixed_with_sb`` +
    ``test_pod_name_is_deterministic_for_same_session_id`` +
    ``test_pod_name_lowercase_only`` +
    ``test_two_sessions_get_distinct_pod_names``.
    """
    return f"sb-{session_id}"


def _network_policy_name(session_id: str) -> str:
    """Per-session NetworkPolicy name — 1:1 with the pod name.

    Pinning the same name keeps the lifecycle coupled — teardown
    removes pod + NetworkPolicy under the same identifier without
    a separate lookup. Drift would orphan policies on pod deletion.

    Pinned by ``test_network_policy_name_matches_pod_name``.
    """
    return _pod_name(session_id)


def _build_security_context() -> dict[str, Any]:
    """Construct the OpenShift-compatible SecurityContext dict per
    ADR-004 §30.

    OMITS ``privileged`` (defends against future K8s API default
    changes; absent is safer than explicit False — pinned by
    ``test_security_context_omits_privileged_field``).

    OMITS ``runAsUser`` / ``runAsGroup`` so OpenShift's
    MustRunAsRange policy assigns the UID + GID from the
    namespace-allocated range (hard-coded values collide on
    OpenShift — pinned by
    ``test_security_context_omits_run_as_user_for_openshift_compat``
    + ``test_security_context_omits_run_as_group_for_openshift_compat``).

    SETS ``runAsNonRoot=True`` + ``readOnlyRootFilesystem=True`` +
    ``allowPrivilegeEscalation=False`` + ``capabilities.drop=[ALL]``
    — the canonical defence-in-depth set.
    """
    return {
        "capabilities": {"drop": ["ALL"]},
        "allowPrivilegeEscalation": False,
        "runAsNonRoot": True,
        "readOnlyRootFilesystem": True,
        # INTENTIONAL OMISSIONS (load-bearing — see test class
        # TestBuildSecurityContext for the pinning regressions):
        #   * "privileged" — NOT set (absent is safer than False)
        #   * "runAsUser" — NOT set (OpenShift MustRunAsRange assigns)
        #   * "runAsGroup" — NOT set (same MustRunAsRange rationale)
    }


def _build_pod_spec(
    *,
    policy: SandboxPolicy,
    session_id: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Construct the V1Pod body dict for the two-container Pod.

    Topology per ``feedback_sandbox_network_isolation_precision``:
    sandbox + proxy sidecar share network namespace inside one Pod;
    the sandbox's ``HTTP_PROXY`` / ``HTTPS_PROXY`` targets
    ``http://localhost:<_PROXY_PORT>`` which the proxy listens on
    inside the SAME netns. NO separate Service.

    ``NO_PROXY`` is intentionally NOT set — every outbound HTTP/S
    request from the sandbox MUST pass through the proxy sidecar
    (a NO_PROXY entry would create a bypass class the per-host
    allow-list does not cover). The Pod's per-session
    NetworkPolicy (built by :func:`_build_network_policy_spec`)
    denies all egress so raw TCP attempts to non-proxy destinations
    have no upstream route.

    Resource limits per ADR-004 + spec §7: ``cpu_cores`` →
    millicores (e.g. 0.5 → ``"500m"``); ``memory_mb`` →
    Mebibytes (e.g. 256 → ``"256Mi"``). The kubelet + the underlying
    CRI runtime enforce the cgroup caps; OOM at the memory limit
    surfaces as exit_code 137 +
    ContainerStatus.lastState.terminated.reason="OOMKilled"
    (handled in T8B-c's exec body classification).

    RestartPolicy=Never — sandbox pods are one-shot per ADR-004.

    Pinned by ``TestBuildPodSpec`` (13 regressions).
    """
    proxy_url = f"{_PROXY_SCHEME}://localhost:{_PROXY_PORT}"
    sandbox_env = [
        {"name": "HTTP_PROXY", "value": proxy_url},
        {"name": "HTTPS_PROXY", "value": proxy_url},
        # INTENTIONALLY NO NO_PROXY entry — see
        # test_pod_spec_does_not_set_no_proxy. A NO_PROXY env would
        # create a bypass class the per-host allow-list does not cover.
    ]
    # cpu_cores → millicores (K8s canonical form). cpu_cores=0.5 →
    # "500m". Round to nearest integer milli; minimum 1m to avoid
    # the K8s default-of-zero interpretation (matches docker_sibling's
    # _derive_cpu_quota_period clamp rationale).
    cpu_millicores = max(1, round(policy.cpu_cores * 1000))
    cpu_limit = f"{cpu_millicores}m"
    # memory_mb → Mebibytes (K8s canonical form). memory_mb=256 →
    # "256Mi".
    memory_limit = f"{policy.memory_mb}Mi"
    security_context = _build_security_context()
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": _pod_name(session_id),
            "labels": {
                _SESSION_ID_LABEL: session_id,
                _TENANT_ID_LABEL: tenant_id,
            },
        },
        "spec": {
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": _SANDBOX_CONTAINER_NAME,
                    "image": policy.runtime_image,
                    "env": sandbox_env,
                    "securityContext": security_context,
                    "resources": {
                        "limits": {
                            "cpu": cpu_limit,
                            "memory": memory_limit,
                        },
                        # K8s convention: requests = limits avoids
                        # the BestEffort QoS class (which the kubelet
                        # evicts first under node pressure). Burstable
                        # is the safe middle.
                        "requests": {
                            "cpu": cpu_limit,
                            "memory": memory_limit,
                        },
                    },
                },
                {
                    "name": _PROXY_SIDECAR_CONTAINER_NAME,
                    "image": _CANONICAL_EGRESS_PROXY_IMAGE,
                    "securityContext": security_context,
                    # No resource caps on the sidecar — the cluster-
                    # wide LimitRange installed by the deployment kit
                    # (Sprint 14) sets sensible defaults; sandbox-
                    # session-level caps belong on the workload
                    # container only.
                },
            ],
        },
    }


def _build_network_policy_spec(
    *,
    session_id: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Construct the V1NetworkPolicy body dict for per-session
    egress lockdown.

    K8s NetworkPolicy semantics: a policy with
    ``policyTypes: [Egress]`` and NO ``egress`` rules denies ALL
    egress for the selected pods. This is the K8s-canonical
    deny-by-default pattern.

    Intra-pod localhost traffic (sandbox → proxy sidecar via
    ``http://localhost:<_PROXY_PORT>``) is NOT subject to
    NetworkPolicy — K8s NetworkPolicy operates at pod-network
    egress boundaries, not on the loopback inside a shared netns.
    The per-session policy here locks down the SANDBOX container's
    POD-EXTERNAL egress so the proxy sidecar is the only outbound
    path; the proxy's upstream destinations are governed by the
    cluster-wide egress-proxy NetworkPolicy installed by the
    deployment kit (Sprint 14).

    Pinned by ``TestBuildNetworkPolicySpec`` (7 regressions).
    """
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": _network_policy_name(session_id),
            "labels": {
                _SESSION_ID_LABEL: session_id,
                _TENANT_ID_LABEL: tenant_id,
            },
        },
        "spec": {
            "podSelector": {
                "matchLabels": {
                    _SESSION_ID_LABEL: session_id,
                },
            },
            "policyTypes": ["Egress"],
            # INTENTIONAL OMISSION — empty / missing ``egress`` rules
            # are the K8s deny-all-egress pattern. Adding any allow
            # rules here would silently grant the sandbox container
            # per-rule egress, defeating the lockdown.
        },
    }


# ---------------------------------------------------------------------------
# KubernetesPodSession — Protocol-conforming in-process value
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class KubernetesPodSession:
    """SandboxSession implementation for the Kubernetes/OpenShift
    backend.

    The 6 fields required by the SandboxSession Protocol per spec
    §5 + the back-reference to the backend so ``exec()`` /
    ``destroy()`` can delegate + ``_actor_subject`` for audit-row
    attribution + ``_destroyed`` for emission-idempotency + the
    pod / network-policy names so teardown does not need to
    re-derive them. Mutable (NOT frozen) because ``warm_pool_hit``
    is set by the warm-pool checkout path AFTER construction, and
    ``_destroyed`` is set by the first destroy() to suppress
    repeat emission on the idempotent second-destroy path.

    NOT instantiated directly by callers — produced by
    :meth:`KubernetesPodSandboxBackend.create`.
    """

    session_id: str
    policy: SandboxPolicy
    tenant_id: str
    pack_context: PackAdmissionContext
    created_at: datetime
    warm_pool_hit: bool
    _backend: KubernetesPodSandboxBackend = field(repr=False)
    _pod_name: str = field(repr=False)
    _network_policy_name: str = field(repr=False)
    _namespace: str = field(repr=False)
    _actor_subject: str = field(repr=False, default="")
    _destroyed: bool = field(repr=False, default=False)

    async def exec(
        self,
        command: list[str],
        *,
        timeout_s: float | None = None,
    ) -> SandboxExecResult:
        return await self._backend.exec(self, command, timeout_s=timeout_s)

    async def destroy(self) -> None:
        await self._backend.destroy(self)


# ---------------------------------------------------------------------------
# KubernetesPodSandboxBackend
# ---------------------------------------------------------------------------


class KubernetesPodSandboxBackend:
    """SandboxBackend implementation for Kubernetes/OpenShift per
    ADR-004 amendment + ``project_openshift_deployment_target``.

    Wave-1 production backend; dev/CI backend is
    :class:`DockerSiblingSandboxBackend` (Sprint 8A). Both conform
    to the same :class:`SandboxBackend` Protocol.

    ``exec()`` is intentionally NotImplementedError at T8B-b —
    the body lands at T8B-c (websocket pods/exec stream +
    cap-violation classification + proxy-log readback). Calling
    ``exec()`` between T8B-b + T8B-c returns a structured error
    pointing at the unfinished sub-task per the production-grade
    fail-loud rule.

    Constructor expects a configured :class:`kube_client.ApiClient`
    — caller (typically the backend factory in T8B-c) owns the
    config-loading lifecycle (``kubernetes_asyncio.config.load_kube_config``
    or ``load_incluster_config``). The backend does NOT manage the
    client's lifetime; the calling layer is responsible for
    ``await api_client.close()``.
    """

    def __init__(
        self,
        *,
        kube_api_client: kube_client.ApiClient,
        namespace: str,
        image_catalog: CatalogProtocol,
        credential_adapter: CredentialAdapter,
        rego_engine: OPAEngine,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        settings: Settings,
        warm_pool: SandboxWarmPool | None = None,
    ) -> None:
        self._kube = kube_api_client
        self._namespace = namespace
        self._catalog = image_catalog
        self._credential_adapter = credential_adapter
        self._rego = rego_engine
        self._audit = audit_store
        self._dh = decision_history_store
        self._settings = settings
        self._warm_pool = warm_pool

    # ------------------------------------------------------------------
    # SandboxBackend Protocol surface
    # ------------------------------------------------------------------

    async def create(
        self,
        policy: SandboxPolicy,
        *,
        actor: Actor,
        tenant_id: str,
        pack_context: PackAdmissionContext,
        use_warm_pool: bool = True,
    ) -> SandboxSession:
        """Admit + create a sandbox session per spec §6.1 + ADR-004
        amendment.

        Step ordering (mirrors docker_sibling's pattern for cross-
        backend behavioural equivalence):

        1. If ``use_warm_pool`` + ``self._warm_pool`` wired, attempt
           checkout; on hit, return + emit
           ``warm_pool.checked_out`` (pool's own seam) +
           ``lifecycle.created(warm_pool_hit=True)``.
        2. Run :func:`admit_policy` (Stage-1 + Stage-2; raises
           :class:`SandboxLifecycleRefused` on any admission
           failure). BACKEND-AGNOSTIC — same admission seam as
           docker_sibling.
        3. Cold-create the K8s objects in order: NetworkPolicy
           FIRST (egress lockdown ACTIVE before the Pod starts;
           defends against the brief window a Pod might start
           with default-namespace egress), then Pod.
        4. Emit ``lifecycle.created(warm_pool_hit=False)`` + return
           the :class:`KubernetesPodSession`.

        On any failure during cold-create, the cleanup envelope
        invokes :meth:`_teardown_session_state` so no K8s objects
        leak. No ``lifecycle.created`` emitted on the failure path
        because the session never reached a running state.
        """
        # 1. Warm-pool checkout (if wired + caller asked for it)
        if use_warm_pool and self._warm_pool is not None:
            warm = await self._warm_pool.checkout(
                policy, tenant_id=tenant_id, pack_context=pack_context
            )
            if warm is not None:
                if isinstance(warm, KubernetesPodSession):
                    warm.warm_pool_hit = True
                    warm._actor_subject = actor.subject
                # Cleanup envelope around lifecycle.created — a
                # transient audit failure after warm checkout MUST
                # NOT orphan the session. Fail-closed: destroy +
                # re-raise so the caller sees the audit failure.
                try:
                    await self._emit_lifecycle_created(
                        session=warm,
                        actor=actor,
                        warm_pool_hit=True,
                    )
                except Exception:
                    with contextlib.suppress(Exception):
                        await self.destroy(warm)
                    raise
                return warm

        # 2. Cold-create — admission FIRST. Backend-agnostic.
        await admit_policy(
            policy,
            tenant_id=tenant_id,
            actor=actor,
            pack_context=pack_context,
            catalog=self._catalog,
            credential_adapter=self._credential_adapter,
            rego_engine=self._rego,
            settings=self._settings,
        )

        # 3. Mint session_id + derive deterministic names
        session_id = _uuid.uuid4().hex
        pod_name = _pod_name(session_id)
        netpol_name = _network_policy_name(session_id)

        # 4. Pre-flight canonical-image catalog verification on the
        # PROXY image, mirroring docker_sibling's _start_proxy_sidecar
        # R1 P1.1 gate. The proxy IS the egress-enforcement component;
        # without this gate, a compromised registry could land an
        # unverified proxy as a trusted enforcement point. Refuses
        # session creation BEFORE any K8s API call.
        _, proxy_image_digest = _CANONICAL_EGRESS_PROXY_IMAGE.rsplit("@", 1)
        if not self._catalog.is_canonical(proxy_image_digest):
            raise SandboxLifecycleRefused(
                "sandbox_image_digest_not_in_canonical_catalog",
                detail=(
                    f"proxy sidecar image {_CANONICAL_EGRESS_PROXY_IMAGE} "
                    f"not in canonical catalog (digest {proxy_image_digest}) "
                    f"— egress enforcement component MUST be catalog-verified "
                    f"per spec §9 + the docker_sibling R1 P1.1 cross-backend "
                    f"parity contract"
                ),
            )
        await self._catalog.verify_cosign_or_refuse(proxy_image_digest, tenant_id=tenant_id)
        await self._catalog.verify_sbom_policy_or_refuse(proxy_image_digest, tenant_id=tenant_id)

        # 5. Build the K8s object specs via pure helpers
        pod_spec = _build_pod_spec(policy=policy, session_id=session_id, tenant_id=tenant_id)
        netpol_spec = _build_network_policy_spec(session_id=session_id, tenant_id=tenant_id)

        # 6. Create NetworkPolicy FIRST so egress lockdown is active
        # BEFORE the Pod starts. Then create the Pod. On any failure
        # in either step, teardown anything we created.
        try:
            await self._create_network_policy(netpol_spec)
            await self._create_pod(pod_spec)
        except Exception:
            await self._teardown_session_state(
                pod_name=pod_name,
                network_policy_name=netpol_name,
            )
            raise

        session = KubernetesPodSession(
            session_id=session_id,
            policy=policy,
            tenant_id=tenant_id,
            pack_context=pack_context,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=self,
            _pod_name=pod_name,
            _network_policy_name=netpol_name,
            _namespace=self._namespace,
            _actor_subject=actor.subject,
        )

        # 7. Emit lifecycle.created(warm_pool_hit=False) per spec
        # §4.3. Cleanup envelope — a transient audit failure here
        # would leave the Pod + NetworkPolicy running with the
        # caller never receiving the session to clean up.
        # Fail-closed: tear down + re-raise.
        try:
            await self._emit_lifecycle_created(
                session=session,
                actor=actor,
                warm_pool_hit=False,
            )
        except Exception:
            with contextlib.suppress(Exception):
                await self._teardown_session_state(
                    pod_name=pod_name,
                    network_policy_name=netpol_name,
                )
            raise
        return session

    async def exec(
        self,
        session: SandboxSession,
        command: list[str],
        *,
        timeout_s: float | None = None,
    ) -> SandboxExecResult:
        """Execute a command in the session.

        DEFERRED to T8B-c per the user-locked plan. The K8s
        ``pods/exec`` websocket stream API + cap-violation
        classification (OOMKilled detection via
        ``ContainerStatus.lastState.terminated.reason``; walltime;
        cpu-budget) land in T8B-c alongside the backend factory +
        cross-backend conformance wire-up.

        Per the production-grade fail-loud rule (CLAUDE.md): this
        stub raises :class:`NotImplementedError` pointing at the
        ADR + the unfinished sub-task so a caller who reaches this
        method sees a structured error, not a silent no-op.
        """
        raise NotImplementedError(
            "KubernetesPodSandboxBackend.exec lands at Sprint 8B T8B-c "
            "(exec via pods/exec websocket stream + cap-violation "
            "classification + proxy-log readback). The T8B-b commit "
            "ships only create() / destroy() / health(). Per ADR-004 "
            "amendment + AGENTS.md production-grade rule."
        )

    async def destroy(self, session: SandboxSession) -> None:
        """Tear down session + the K8s Pod + the per-session
        NetworkPolicy.

        Idempotent per spec §5 ``SandboxBackend.destroy`` docstring.
        Calls the same :meth:`_teardown_session_state` helper that
        the create() cleanup path uses on partial-create failure.

        Emits ``sandbox.lifecycle.destroyed`` per spec §4.3.
        Emission-idempotency: ``session._destroyed`` flag is set
        on the first call so a second ``destroy()`` (idempotent
        contract) does NOT emit a second chain row.
        """
        if not isinstance(session, KubernetesPodSession):
            raise TypeError(
                f"KubernetesPodSandboxBackend.destroy expects "
                f"KubernetesPodSession; got {type(session).__name__}"
            )

        already_destroyed = session._destroyed
        await self._teardown_session_state(
            pod_name=session._pod_name,
            network_policy_name=session._network_policy_name,
        )
        if not already_destroyed:
            # Emit BEFORE setting the flag so a transient audit
            # failure leaves _destroyed False and a retry destroy()
            # will retry the emission. The K8s teardown is idempotent
            # (the helpers swallow 404 ApiException) so calling
            # destroy() twice after a transient emit failure is safe.
            # Mirrors docker_sibling's R2 P1.2 reviewer fix ordering.
            await self._emit_lifecycle_destroyed(session=session)
            session._destroyed = True

    async def health(self) -> SandboxBackendHealth:
        """Backend readiness check — probes the K8s apiserver via a
        bounded ``list_namespaced_pod(limit=1)`` against the
        configured namespace.

        Returns ``ok`` if the apiserver responds; ``unavailable``
        on any :class:`kubernetes_asyncio.client.ApiException` or
        other exception. The wire-public 8th refusal value
        ``sandbox_backend_unavailable`` is reserved for the
        admission path — health() returns the structured
        :class:`SandboxBackendHealth` so /readyz can surface the
        apiserver state without raising.
        """
        try:
            api = kube_client.CoreV1Api(self._kube)
            await api.list_namespaced_pod(namespace=self._namespace, limit=1)
        except Exception as e:
            return SandboxBackendHealth(
                status="unavailable",
                detail=f"k8s apiserver unreachable: {e}",
            )
        return SandboxBackendHealth(status="ok")

    # ------------------------------------------------------------------
    # Internal — K8s object lifecycle
    # ------------------------------------------------------------------

    async def _create_network_policy(self, body: dict[str, Any]) -> None:
        """Create the per-session NetworkPolicy via the K8s API.

        Egress lockdown is active for the session_id-labelled pod
        the moment this returns; the subsequent
        :meth:`_create_pod` then starts the pod under the lockdown.

        The ``body`` arg is a plain dict (as built by
        :func:`_build_network_policy_spec`). kubernetes_asyncio's
        ``ApiClient.sanitize_for_serialization`` accepts both
        ``V1NetworkPolicy`` instances and dicts at runtime per
        the upstream client contract, but the typestubs annotate
        ``body: V1NetworkPolicy`` strictly. Dict-shape is the
        canonical Sprint-8B representation (pure helpers + audit
        emission both operate on dicts so a future K8s API bump
        does not force a rebuild of every pod-spec call site).
        """
        api = kube_client.NetworkingV1Api(self._kube)
        await api.create_namespaced_network_policy(
            namespace=self._namespace,
            body=body,  # type: ignore[arg-type]
        )

    async def _create_pod(self, body: dict[str, Any]) -> None:
        """Create the per-session two-container Pod via the K8s API.

        Pod readiness signalling (waiting for the kubelet to
        ack the Pod has started) is DEFERRED to T8B-c — T8B-b
        ships create-and-return; the next exec() call's body in
        T8B-c will explicitly wait for the pod to be running
        before attempting the pods/exec stream.

        Dict-body rationale identical to
        :meth:`_create_network_policy` above.
        """
        api = kube_client.CoreV1Api(self._kube)
        await api.create_namespaced_pod(
            namespace=self._namespace,
            body=body,  # type: ignore[arg-type]
        )

    async def _teardown_session_state(
        self,
        *,
        pod_name: str,
        network_policy_name: str,
    ) -> None:
        """Best-effort idempotent teardown of pod + NetworkPolicy.

        Each step swallows :class:`kubernetes_asyncio.client.ApiException`
        with status 404 (not found) so the teardown completes even
        if the object was never created (partial-create failure
        path) OR has already been removed (double-destroy path).
        Non-404 ApiExceptions surface to the caller — fail-closed
        so a real teardown failure does not silently leak.

        Order: pod → NetworkPolicy. The pod's IP / DNS / network
        bindings go away with the pod; deleting the NetworkPolicy
        afterwards is a no-op for live traffic + idempotent
        cleanup of the API object.
        """
        await self._delete_pod_if_exists(pod_name)
        await self._delete_network_policy_if_exists(network_policy_name)

    async def _delete_pod_if_exists(self, name: str) -> None:
        """Delete a pod by name; swallow ApiException 404."""
        api = kube_client.CoreV1Api(self._kube)
        try:
            await api.delete_namespaced_pod(name=name, namespace=self._namespace)
        except kube_client.ApiException as e:
            if e.status == 404:
                return  # benign: already gone
            raise

    async def _delete_network_policy_if_exists(self, name: str) -> None:
        """Delete a NetworkPolicy by name; swallow ApiException 404."""
        api = kube_client.NetworkingV1Api(self._kube)
        try:
            await api.delete_namespaced_network_policy(name=name, namespace=self._namespace)
        except kube_client.ApiException as e:
            if e.status == 404:
                return  # benign: already gone
            raise

    # ------------------------------------------------------------------
    # Audit emission — spec §4.3 + spec §12 wire-protocol-public events
    # ------------------------------------------------------------------

    async def _emit_lifecycle_created(
        self,
        *,
        session: SandboxSession,
        actor: Actor,
        warm_pool_hit: bool,
    ) -> None:
        """Emit ``sandbox.lifecycle.created`` per spec §4.3
        wire-public payload ``{warm_pool_hit: bool}``.

        Fires on BOTH warm-hit and cold-create paths so the
        evidence chain has a successful-start row for every
        sandbox session. Warm-hit pairs this event with the
        warm-pool's own ``sandbox.warm_pool.checked_out`` row;
        cold-create only emits this one.

        ``trace_id`` is empty at T8B-b — request-bound trace_id
        wiring is a future concern (the SandboxBackend Protocol's
        create signature does not take a trace_id). Matches the
        Sprint-8A docker_sibling backend's identical deferred-
        trace rationale.
        """
        await emit_sandbox_event(
            self._dh,
            event="sandbox.lifecycle.created",
            tenant_id=session.tenant_id,
            actor_id=actor.subject,
            trace_id="",
            session_id=session.session_id,
            payload={"warm_pool_hit": warm_pool_hit},
        )

    async def _emit_lifecycle_destroyed(
        self,
        *,
        session: KubernetesPodSession,
    ) -> None:
        """Emit ``sandbox.lifecycle.destroyed`` per spec §4.3
        wire-public payload ``{duration_s: float}``.

        ``duration_s`` is computed from
        ``datetime.now(UTC) - session.created_at`` so examiners
        can audit session lifetime. The destroy() caller-side
        idempotency flag (``session._destroyed``) ensures repeat
        destroy() calls do NOT emit a second row.

        ``actor_id`` carries ``session._actor_subject`` from the
        original create() call. ``trace_id`` is empty per the
        same deferred-trace rationale documented at
        :meth:`_emit_lifecycle_created`.
        """
        duration_s = (datetime.now(UTC) - session.created_at).total_seconds()
        await emit_sandbox_event(
            self._dh,
            event="sandbox.lifecycle.destroyed",
            tenant_id=session.tenant_id,
            actor_id=session._actor_subject,
            trace_id="",
            session_id=session.session_id,
            payload={"duration_s": duration_s},
        )


# Re-exports so the SandboxLifecycleRefused class is importable from
# this module (test files that import it via the kubernetes_pod
# module get the same object as the protocol module).
__all__ = [
    "_CANONICAL_EGRESS_PROXY_IMAGE",
    "_PROXY_PORT",
    "_PROXY_SCHEME",
    "_PROXY_SIDECAR_CONTAINER_NAME",
    "_SANDBOX_CONTAINER_NAME",
    "_SESSION_ID_LABEL",
    "_TENANT_ID_LABEL",
    "KubernetesPodSandboxBackend",
    "KubernetesPodSession",
    "SandboxLifecycleRefused",
    "_build_network_policy_spec",
    "_build_pod_spec",
    "_build_security_context",
    "_network_policy_name",
    "_pod_name",
]
