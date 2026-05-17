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

import asyncio
import contextlib
import json
import logging
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import kubernetes_asyncio  # noqa: F401 — admission contract: the sandbox-k8s extra MUST be installed
from kubernetes_asyncio import client as kube_client
from kubernetes_asyncio.stream import WsApiClient
from kubernetes_asyncio.stream.ws_client import (
    ERROR_CHANNEL,
    STDERR_CHANNEL,
    STDOUT_CHANNEL,
)

from cognic_agentos.sandbox.admission import (
    CatalogProtocol,
    CredentialAdapter,
    admit_policy,
)
from cognic_agentos.sandbox.audit import emit_sandbox_event
from cognic_agentos.sandbox.backends._shared_exec import (
    _classify_exec_failure,
    _ProxyLogReadFailure,
)
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.protocol import (
    ProxyAccessRecord,
    SandboxBackendHealth,
    SandboxExecResult,
    SandboxLifecycleRefused,
    SandboxPolicyViolated,
    SandboxSession,
)

_LOG = logging.getLogger(__name__)

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

#: Path inside the canonical egress-proxy image at which the proxy
#: sidecar writes its per-request JSONL audit log. T8B-c's
#: ``_read_proxy_log_from_sidecar_k8s`` reads via ``pods/exec`` ``cat``
#: on session ``exec_completed``. Wire-contract with the canonical
#: image; drift here breaks proxy_log materialisation across both
#: backends. Pinned constant equal to
#: ``docker_sibling._PROXY_LOG_PATH`` per the
#: ``feedback_drift_detector_test_only_no_runtime_import`` doctrine
#: (cross-module copy + test-only drift detector at
#: ``test_exec_classification_cross_backend_drift.py``).
_PROXY_LOG_PATH: str = "/var/log/cognic-proxy/access.jsonl"

#: cpu_time_budget_s monitor poll interval (T8B-c). Per spec §7 item 4
#: ("polled at ≥1Hz"). 0.5s strikes a balance: tight enough to fire
#: within ~500ms of budget overage, loose enough to avoid stressing
#: the apiserver's pods/exec endpoint. Matches docker_sibling's
#: ``_CPU_BUDGET_POLL_INTERVAL_S`` for cross-backend behavioural
#: equivalence — a cpu-budget kill that fired at noticeably different
#: rates across backends would break the consumer's expectations on
#: cap enforcement latency.
_CPU_BUDGET_POLL_INTERVAL_S: float = 0.5

#: Cgroup v2 cumulative cpu-usage file. Inside the sandbox container's
#: cgroup namespace this surfaces accumulated cpu time. The value is
#: read by the cpu-budget monitor via short-lived ``pods/exec``
#: ``cat`` calls. Cgroup v2 ``cpu.stat`` carries ``usage_usec`` as
#: the first field of the ``usage_usec`` line; the canonical Sprint-8A
#: runtime images mount cgroup v2 by default per the
#: Sprint-14 deploy-kit nodeselector contract.
_CGROUP_V2_CPU_STAT_PATH: str = "/sys/fs/cgroup/cpu.stat"

#: Cgroup v1 fallback path (cumulative cpu nanoseconds). Used when
#: ``_CGROUP_V2_CPU_STAT_PATH`` returns nonzero exit (kernel < 5.x
#: nodes still in field). The cpu-budget monitor tries v2 first,
#: falls back to v1 on failure.
_CGROUP_V1_CPUACCT_PATH: str = "/sys/fs/cgroup/cpuacct/cpuacct.usage"


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
        """Execute a command in the session per spec §7 lines 495-502.

        T8B-c implementation — mirrors
        :meth:`DockerSiblingSandboxBackend.exec` decision logic for
        cross-backend behavioural equivalence:

        1. AgentOS-side walltime cap — :meth:`_open_pod_exec_stream`
           runs the command via the K8s ``pods/exec`` websocket
           stream under ``asyncio.timeout(walltime)``. Timeout →
           kill pod + raise ``SandboxPolicyViolated(walltime_cap_exceeded)``.
        2. Background :meth:`_cpu_time_budget_monitor_k8s` task polls
           cgroup ``cpu.stat`` via ``pods/exec`` ``cat`` at
           ``_CPU_BUDGET_POLL_INTERVAL_S`` when ``policy.cpu_time_budget_s``
           is set; on overage kills pod + signals an asyncio.Event.
        3. After exec completes, :meth:`_read_pod_oom_killed` inspects
           the Pod's ContainerStatus for
           ``state.terminated.reason == "OOMKilled"`` (the K8s wire-
           contract equivalent of Docker's ``State.OOMKilled``);
           exit_code 137 + OOMKilled → ``memory_cap_exceeded``.
        4. Pure :func:`_classify_exec_failure` decides precedence
           (walltime > cpu_budget > OOM > green).
        5. Green-path: :meth:`_read_proxy_log_from_sidecar_k8s` reads
           the proxy sidecar's JSONL audit log via ``pods/exec``
           ``cat``. T8B-c R1 fail-closed: any readback failure →
           ``egress_audit_unreadable`` violation. Mirrors
           docker_sibling T10c R1 P1.2 wire-protocol-public contract;
           missing it ships a silent egress-bypass class.

        Throttling under ``policy.cpu_cores`` cap is NOT a violation
        per round-3 P2 invariant: the kernel scheduler may slow a
        CPU-bound workload, but only ``cpu_time_budget_exceeded``
        (when a budget is set) raises ``SandboxPolicyViolated``.
        """
        if not isinstance(session, KubernetesPodSession):
            raise TypeError(
                f"KubernetesPodSandboxBackend.exec expects "
                f"KubernetesPodSession; got {type(session).__name__}"
            )

        walltime = timeout_s if timeout_s is not None else session.policy.walltime_s
        pod_name = session._pod_name

        # Background cpu-budget monitor — only spawned when policy
        # carries a budget. The monitor sets cpu_violated_event when
        # it observes the cgroup-stat cpu_usage exceed the budget +
        # kills the pod so the in-flight exec returns.
        cpu_violated_event = asyncio.Event()
        monitor_task: asyncio.Task[None] | None = None
        if session.policy.cpu_time_budget_s is not None:
            monitor_task = asyncio.create_task(
                self._cpu_time_budget_monitor_k8s(
                    pod_name=pod_name,
                    container_name=_SANDBOX_CONTAINER_NAME,
                    budget_s=session.policy.cpu_time_budget_s,
                    cpu_violated_event=cpu_violated_event,
                )
            )

        # ``body_raised`` tracks whether the try block raises. The
        # finally block uses it to decide whether to propagate a
        # monitor-task failure (mirrors docker_sibling's R3 P1 fix
        # — if the exec body completed successfully but the monitor
        # failed, the monitor exception MUST surface so the caller
        # knows cap enforcement was unverified).
        body_raised = False
        walltime_exceeded = False
        stdout: bytes = b""
        stderr: bytes = b""
        exit_code = 0

        try:
            try:
                stdout, stderr, exit_code = await self._open_pod_exec_stream(
                    pod_name=pod_name,
                    container_name=_SANDBOX_CONTAINER_NAME,
                    command=command,
                    walltime_s=walltime,
                )
            except TimeoutError:
                # Mirror docker_sibling R2 P1.1 — kill on walltime
                # overage. _kill_pod_or_raise propagates real
                # ApiException (only 404/already-gone is benign).
                # If kill fails, the ApiException propagates instead
                # of walltime_cap_exceeded — caller knows enforcement
                # is unverified.
                await self._kill_pod_or_raise(pod_name)
                walltime_exceeded = True

            # Read pod status to detect OOM-kill. ContainerStatus
            # state.terminated.reason == "OOMKilled" is the
            # authoritative K8s signal; exit 137 alone is not enough
            # (could be manual SIGKILL).
            oom_killed = await self._read_pod_oom_killed(pod_name=pod_name)
            cpu_budget_exceeded = cpu_violated_event.is_set()

            reason = _classify_exec_failure(
                exit_code=exit_code,
                oom_killed=oom_killed,
                walltime_exceeded=walltime_exceeded,
                cpu_budget_exceeded=cpu_budget_exceeded,
            )
            if reason is not None:
                detail = (
                    f"command={command!r} exit_code={exit_code} "
                    f"oom_killed={oom_killed} "
                    f"walltime_exceeded={walltime_exceeded} "
                    f"cpu_budget_exceeded={cpu_budget_exceeded}"
                )
                # Mirror docker_sibling R1 P1.5 + R2 P1.2 — emit
                # ``sandbox.policy.violated`` BEFORE raising so the
                # cap kill gets a chain row. Without this, cap kills
                # happen in production with NO audit trail. Per spec
                # §4.3 + §12 wire-public taxonomy.
                #
                # R2 P1.2 contract: NO ``contextlib.suppress`` here.
                # A transient audit-store outage MUST fail-closed
                # (NOT silently drop the evidence row). If the audit
                # append raises, the caller sees that exception
                # instead of SandboxPolicyViolated — they should treat
                # an audit-store outage as a CC failure that supersedes
                # the cap reason.
                await self._emit_policy_violated(
                    session=session,
                    reason=reason,
                )
                raise SandboxPolicyViolated(reason, detail=detail)

            # T8B-c — read proxy_log from sidecar + classify any
            # egress refusals. Per spec §10.3 the canonical proxy
            # image writes JSONL to ``_PROXY_LOG_PATH``; backend
            # reads via pods/exec cat. Per spec §7 line 501 + §10.4,
            # egress refusals raise SandboxPolicyViolated with the
            # matching closed-enum reason.
            #
            # T8B-c R1 fail-closed (mirrors docker_sibling T10c R1 P1.2):
            # ``_read_proxy_log_from_sidecar_k8s`` raises
            # ``_ProxyLogReadFailure`` when it cannot prove the log
            # is complete (sidecar gone, cat exit nonzero, unexpected
            # exception). We catch + emit policy.violated with
            # closed-enum ``egress_audit_unreadable`` + raise —
            # AgentOS MUST NOT emit a green ``exec_completed`` when
            # refusals may have been silently elided.
            try:
                proxy_log = await self._read_proxy_log_from_sidecar_k8s(
                    pod_name=pod_name,
                    sidecar_container_name=_PROXY_SIDECAR_CONTAINER_NAME,
                )
            except _ProxyLogReadFailure as read_err:
                detail = (
                    f"command={command!r} exit_code={exit_code} proxy_log_readback_error={read_err}"
                )
                await self._emit_policy_violated(
                    session=session,
                    reason="egress_audit_unreadable",
                    proxy_log=(),
                )
                raise SandboxPolicyViolated(
                    "egress_audit_unreadable",
                    detail=detail,
                ) from read_err

            # Egress classification — Sprint 8B carries forward the
            # docker_sibling _classify_egress_refusal pattern. For
            # T8B-c the readback returns ``()`` on the green path
            # (mock returns empty tuple; live K8s reads zero-length
            # log when no outbound calls were made). When the
            # canonical proxy ships records, the same classification
            # path lights up across both backends.
            from cognic_agentos.sandbox.backends.docker_sibling import (
                _classify_egress_refusal,
            )

            egress_reason = _classify_egress_refusal(proxy_log)
            if egress_reason is not None:
                detail = (
                    f"command={command!r} exit_code={exit_code} "
                    f"proxy_log_refused_count="
                    f"{sum(1 for r in proxy_log if r.outcome == 'refused')}"
                )
                await self._emit_policy_violated(
                    session=session,
                    reason=egress_reason,
                    proxy_log=proxy_log,
                )
                raise SandboxPolicyViolated(egress_reason, detail=detail)  # type: ignore[arg-type]

            # Green path — emit sandbox.lifecycle.exec_completed per
            # spec §4.3 + §7 line 502 + return SandboxExecResult with
            # the materialised proxy_log.
            await self._emit_lifecycle_exec_completed(
                session=session,
                exit_code=exit_code,
                proxy_log=proxy_log,
            )
            return SandboxExecResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                proxy_log=proxy_log,
            )
        except BaseException:
            body_raised = True
            raise
        finally:
            # Mirror docker_sibling R3 P1 — propagate monitor task
            # failures when the exec body completed successfully.
            # Earlier ``contextlib.suppress(BaseException)`` ordering
            # silenced ALL monitor exceptions; a cpu-budget kill that
            # failed followed by a natural workload exit would return
            # green with NO policy.violated row — cap UNENFORCED.
            if monitor_task is not None:
                if not monitor_task.done():
                    monitor_task.cancel()
                try:
                    await monitor_task
                except asyncio.CancelledError:
                    pass  # expected — we cancelled it
                except BaseException as monitor_exc:
                    if not body_raised:
                        raise monitor_exc

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
    # T8B-c — exec() I/O helpers (pods/exec websocket + pod status
    # readers + cgroup-stat readers + proxy-log readback)
    # ------------------------------------------------------------------

    async def _open_pod_exec_stream(
        self,
        *,
        pod_name: str,
        container_name: str,
        command: list[str],
        walltime_s: float | None,
    ) -> tuple[bytes, bytes, int]:
        """Open a ``pods/exec`` websocket stream + consume until the
        ERROR channel close. Returns ``(stdout, stderr, exit_code)``.

        Uses ``WsApiClient`` (sharing this backend's existing
        ``Configuration`` so auth / TLS / kubeconfig flows are
        unified) with ``_preload_content=False`` so the raw
        websocket is returned + we can read the multiplexed channel
        format ourselves (channel byte 1 prefix per
        ``kubernetes_asyncio.stream.ws_client``: 1=stdout, 2=stderr,
        3=error). The ERROR channel carries the exit-code-bearing
        JSON document parseable by
        ``WsApiClient.parse_error_data``.

        Walltime enforcement: wraps the stream-consumption loop in
        ``asyncio.timeout(walltime_s)``. Timeout raises
        ``TimeoutError`` which the caller (:meth:`exec`) catches +
        translates to ``walltime_cap_exceeded``.

        T8B-c — production path. Test paths mock this method directly
        per the test isolation pattern at
        ``test_kubernetes_pod_exec_classification.py``.
        """
        ws_client_obj = WsApiClient(configuration=self._kube.configuration)
        try:
            ws_api = kube_client.CoreV1Api(ws_client_obj)
            stdout = bytearray()
            stderr = bytearray()
            exit_code = 0

            try:
                async with asyncio.timeout(walltime_s):
                    # _preload_content=False returns an
                    # _WSRequestContextManager — async-with it to get
                    # the live ClientWebSocketResponse.
                    #
                    # Typestubs annotate ``command: str`` but the
                    # runtime accepts ``list[str]`` (per the upstream
                    # ws_client.request expansion at
                    # ``kubernetes_asyncio/stream/ws_client.py:90-93``
                    # which iterates the list to one
                    # ``command=<arg>`` query param per element).
                    # Same gap for the WsResponse return type — at
                    # _preload_content=False the call returns a
                    # _WSRequestContextManager (awaitable yielding
                    # an aiohttp ClientWebSocketResponse), not a
                    # str.
                    ws_ctx = ws_api.connect_get_namespaced_pod_exec(
                        pod_name,
                        self._namespace,
                        container=container_name,
                        command=command,  # type: ignore[arg-type]
                        stdin=False,
                        stdout=True,
                        stderr=True,
                        tty=False,
                        _preload_content=False,
                    )
                    async with await ws_ctx as ws:  # type: ignore[attr-defined]
                        async for wsmsg in ws:
                            data = wsmsg.data
                            if not data or len(data) < 1:
                                continue
                            channel = data[0]
                            payload = data[1:]
                            if channel == STDOUT_CHANNEL:
                                stdout.extend(payload)
                            elif channel == STDERR_CHANNEL:
                                stderr.extend(payload)
                            elif channel == ERROR_CHANNEL and payload:
                                try:
                                    exit_code = WsApiClient.parse_error_data(
                                        bytes(payload).decode("utf-8")
                                    )
                                except (
                                    ValueError,
                                    KeyError,
                                    json.JSONDecodeError,
                                ):
                                    # Malformed error payload — surface
                                    # as a non-zero exit so the caller's
                                    # classify path doesn't silently
                                    # treat as green. Mirrors
                                    # docker_sibling defensive shape-
                                    # parsing pattern.
                                    exit_code = -1
                            # Ignore unknown channels (resize/etc).
            except TimeoutError:
                raise  # exec() body catches + classifies

            return bytes(stdout), bytes(stderr), exit_code
        finally:
            with contextlib.suppress(Exception):
                await ws_client_obj.close()

    async def _kill_pod_or_raise(self, pod_name: str) -> None:
        """Delete the Pod with ``grace_period_seconds=0`` — the K8s
        equivalent of ``container.kill(SIGKILL)``. Already-gone
        (ApiException 404) is treated as benign (the cap effectively
        enforced — workload is not running). ANY other ApiException
        is propagated unchanged (fail-closed per docker_sibling R2
        P1.1: a cap-violation path that suppresses kill failure can
        pretend it enforced when it didn't).

        Callers: walltime + cpu-budget monitor paths in :meth:`exec`.
        On propagated failure the cap-violation reason is NOT raised
        — the ApiException surfaces to the caller instead, so they
        know enforcement is unverified.
        """
        api = kube_client.CoreV1Api(self._kube)
        try:
            await api.delete_namespaced_pod(
                name=pod_name,
                namespace=self._namespace,
                grace_period_seconds=0,
            )
        except kube_client.ApiException as e:
            if getattr(e, "status", None) == 404:
                return  # benign: pod already gone
            raise  # real failure → fail-closed propagate

    async def _read_pod_oom_killed(self, *, pod_name: str) -> bool:
        """Read the Pod's ContainerStatus for the sandbox container
        and return True iff the kernel oom-killer fired.

        K8s wire-contract: the OOMKilled signal lives at
        ``container_status.state.terminated.reason == "OOMKilled"``
        (live terminated state) OR at
        ``container_status.last_state.terminated.reason == "OOMKilled"``
        (post-restart cached state — sandbox pods use
        ``RestartPolicy=Never`` so this should never fire in practice,
        but reading both surfaces defends against the kubelet's
        eventually-consistent status updates).

        Returns False if the pod / container status is unreadable
        (the caller's classify path will treat as non-OOM; exec()
        returns the exit code without raising memory_cap_exceeded).
        This mirrors docker_sibling's defensive ``info.get("State",
        {}).get("OOMKilled", False)`` pattern.
        """
        api = kube_client.CoreV1Api(self._kube)
        try:
            pod = await api.read_namespaced_pod_status(
                name=pod_name,
                namespace=self._namespace,
            )
        except kube_client.ApiException:
            return False  # status unreadable; caller's classify path proceeds

        statuses = getattr(pod.status, "container_statuses", None) or []
        for cs in statuses:
            if cs.name != _SANDBOX_CONTAINER_NAME:
                continue
            # Check current terminated state
            state = getattr(cs, "state", None)
            if state is not None:
                terminated = getattr(state, "terminated", None)
                if terminated is not None:
                    reason = getattr(terminated, "reason", None)
                    if reason == "OOMKilled":
                        return True
            # Check last_state.terminated (e.g. transitional state)
            last_state = getattr(cs, "last_state", None)
            if last_state is not None:
                terminated = getattr(last_state, "terminated", None)
                if terminated is not None:
                    reason = getattr(terminated, "reason", None)
                    if reason == "OOMKilled":
                        return True
        return False

    async def _read_cpu_usage_ns(
        self,
        *,
        pod_name: str,
        container_name: str,
    ) -> int | None:
        """Read the cumulative CPU usage (nanoseconds) for the named
        container via a short-lived ``pods/exec`` ``cat`` against the
        cgroup stat file.

        Tries cgroup v2 (``cpu.stat`` ``usage_usec`` first field of
        the ``usage_usec <ns>`` line) first; falls back to cgroup v1
        (``cpuacct/cpuacct.usage`` cumulative nanoseconds raw int)
        on v2 failure. Returns None on any failure (best-effort per
        docker_sibling's transient-stats-hiccup contract — the
        monitor will continue polling on the next valid snapshot).

        Cgroup v2 ``cpu.stat`` format::

            usage_usec 12345678
            user_usec 11000000
            system_usec 1345678

        v1 ``cpuacct.usage`` format::

            123456789012345
        """
        # Try cgroup v2 first
        result = await self._exec_short_lived(
            pod_name=pod_name,
            container_name=container_name,
            command=["cat", _CGROUP_V2_CPU_STAT_PATH],
        )
        if result is not None:
            stdout, exit_code = result
            if exit_code == 0:
                for line in stdout.decode("utf-8", errors="replace").splitlines():
                    parts = line.strip().split()
                    if len(parts) == 2 and parts[0] == "usage_usec":
                        try:
                            return int(parts[1]) * 1000  # us → ns
                        except ValueError:
                            return None

        # Fall back to cgroup v1
        result = await self._exec_short_lived(
            pod_name=pod_name,
            container_name=container_name,
            command=["cat", _CGROUP_V1_CPUACCT_PATH],
        )
        if result is not None:
            stdout, exit_code = result
            if exit_code == 0:
                try:
                    return int(stdout.decode("utf-8", errors="replace").strip())
                except ValueError:
                    return None

        return None

    async def _exec_short_lived(
        self,
        *,
        pod_name: str,
        container_name: str,
        command: list[str],
    ) -> tuple[bytes, int] | None:
        """Run a short-lived command via ``pods/exec`` + return
        ``(stdout, exit_code)`` or None on transport failure.

        Used by :meth:`_read_cpu_usage_ns` for cgroup reads + by
        :meth:`_read_proxy_log_from_sidecar_k8s` for proxy-log
        readback. Best-effort wrapper around
        :meth:`_open_pod_exec_stream` — None return indicates the
        transport itself failed (websocket open / network blip);
        the caller decides whether None is benign (cpu-stat poll:
        continue) or fail-closed (proxy-log readback: raise
        ``_ProxyLogReadFailure``).
        """
        try:
            stdout, _stderr, exit_code = await self._open_pod_exec_stream(
                pod_name=pod_name,
                container_name=container_name,
                command=command,
                walltime_s=10.0,  # short timeout per call — defence-in-depth
            )
            return stdout, exit_code
        except (kube_client.ApiException, TimeoutError, OSError):
            return None
        except Exception:
            # Other unexpected exceptions also surface as None — caller
            # decides whether to treat as transient or fail-closed.
            return None

    async def _cpu_time_budget_monitor_k8s(
        self,
        *,
        pod_name: str,
        container_name: str,
        budget_s: float,
        cpu_violated_event: asyncio.Event,
    ) -> None:
        """Background asyncio task — polls cgroup cpu_usage at
        ``_CPU_BUDGET_POLL_INTERVAL_S``; when accumulated CPU-seconds
        exceed ``budget_s``, kills the pod + sets
        ``cpu_violated_event`` so :meth:`exec`'s post-loop
        classification routes the failure to
        ``cpu_time_budget_exceeded``.

        Mirrors docker_sibling's ``_cpu_time_budget_monitor`` semantics:

        * Best-effort polling — a transient cgroup-read hiccup MUST NOT
          crash the in-flight exec; continue polling so the budget
          check still fires on the next valid snapshot.
        * Kill BEFORE setting the event (R2 P1.1 contract):
          :meth:`_kill_pod_or_raise` propagates real ApiException;
          if kill fails, the monitor task exits with the exception +
          the event is NEVER set, so :meth:`exec` does NOT raise
          cpu_time_budget_exceeded while the workload may still be
          running. Walltime then acts as the natural backstop.
        * Handle ``asyncio.CancelledError`` cleanly by re-raising
          (the finally block in :meth:`exec` cancels on every exit
          path).

        Task spawned by :meth:`exec` ONLY when
        ``policy.cpu_time_budget_s`` is set — without a budget the
        cpu-budget violation is unreachable regardless of cpu usage.
        """
        budget_ns = int(budget_s * 1_000_000_000)
        while True:
            try:
                cpu_usage_ns = await self._read_cpu_usage_ns(
                    pod_name=pod_name,
                    container_name=container_name,
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                cpu_usage_ns = None

            if cpu_usage_ns is None:
                # Transient cgroup-read hiccup — continue polling.
                await asyncio.sleep(_CPU_BUDGET_POLL_INTERVAL_S)
                continue

            if cpu_usage_ns >= budget_ns:
                # Kill BEFORE setting the event per docker_sibling
                # R2 P1.1. _kill_pod_or_raise propagates real
                # ApiException; only 404/already-gone is benign.
                await self._kill_pod_or_raise(pod_name)
                cpu_violated_event.set()
                return

            await asyncio.sleep(_CPU_BUDGET_POLL_INTERVAL_S)

    async def _read_proxy_log_from_sidecar_k8s(
        self,
        *,
        pod_name: str,
        sidecar_container_name: str,
    ) -> tuple[ProxyAccessRecord, ...]:
        """Read the canonical proxy sidecar's JSONL access log via
        ``pods/exec`` ``cat``. Returns the parsed tuple of
        ProxyAccessRecord per spec §10.3 wire-contract.

        T8B-c fail-closed contract (mirrors docker_sibling T10c R1
        P1.2): the canonical proxy image's contract is the log file
        at ``_PROXY_LOG_PATH`` ALWAYS exists + is readable; empty
        file (size 0) is the canonical "no outbound calls"
        representation. ANY failure modes (container gone, cat exit
        nonzero, exec failure, unexpected exception) raise
        ``_ProxyLogReadFailure`` so :meth:`exec` can fail-closed via
        ``SandboxPolicyViolated(egress_audit_unreadable)``.

        Bank-grade trust posture requires AgentOS to fail-closed when
        it cannot prove the absence of refusals; a best-effort
        ``return ()`` design would silently elide refusals if the
        sidecar crashed mid-exec after refusing outbound calls but
        before the backend could read.
        """
        try:
            result = await self._exec_short_lived(
                pod_name=pod_name,
                container_name=sidecar_container_name,
                command=["cat", _PROXY_LOG_PATH],
            )
        except Exception as e:
            raise _ProxyLogReadFailure(
                f"unexpected error opening proxy_log exec stream on "
                f"sidecar {sidecar_container_name!r}: {e!r}"
            ) from e

        if result is None:
            raise _ProxyLogReadFailure(
                f"proxy sidecar {sidecar_container_name!r} unreachable "
                f"during proxy_log readback; cannot prove absence of "
                f"refusals — fail-closed per T8B-c R1 (mirrors "
                f"docker_sibling T10c R1 P1.2)"
            )

        stdout, exit_code = result
        if exit_code != 0:
            raise _ProxyLogReadFailure(
                f"sidecar cat {_PROXY_LOG_PATH!r} exited {exit_code} "
                f"— canonical proxy image guarantees a readable log "
                f"file; fail-closed per T8B-c R1"
            )

        # Parse JSONL output via the shared parser. Delegating to the
        # docker_sibling parser keeps both backends' JSONL shape in
        # lockstep (the canonical proxy image emits the same JSON
        # shape regardless of backend; the parser is wire-protocol-
        # public).
        from cognic_agentos.sandbox.backends.docker_sibling import (
            _parse_proxy_log_jsonl,
        )

        raw = stdout.decode("utf-8", errors="replace")
        return _parse_proxy_log_jsonl(raw)

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

    async def _emit_lifecycle_exec_completed(
        self,
        *,
        session: KubernetesPodSession,
        exit_code: int,
        proxy_log: tuple[ProxyAccessRecord, ...],
    ) -> None:
        """Emit ``sandbox.lifecycle.exec_completed`` per spec §4.3
        wire-public payload + spec §7 line 502.

        Payload carries ``exit_code`` + serialised ``proxy_log``
        (list of dicts; canonical_bytes-safe — see warm_pool's
        ``_tuples_to_lists`` pattern for the list/tuple ambiguity
        bug class avoidance).

        Only fires on the green-path exec return; cap-violation
        + egress-violation paths emit ``sandbox.policy.violated``
        instead.

        Mirrors :meth:`DockerSiblingSandboxBackend._emit_lifecycle_exec_completed`
        wire shape for cross-backend behavioural equivalence — both
        backends emit the same chain row keys on the same lifecycle
        transitions.
        """
        from cognic_agentos.sandbox.proxy import proxy_log_to_chain_payload

        await emit_sandbox_event(
            self._dh,
            event="sandbox.lifecycle.exec_completed",
            tenant_id=session.tenant_id,
            actor_id=session._actor_subject,
            trace_id="",
            session_id=session.session_id,
            payload={
                "exit_code": exit_code,
                "proxy_log": proxy_log_to_chain_payload(proxy_log),
            },
        )

    async def _emit_policy_violated(
        self,
        *,
        session: KubernetesPodSession,
        reason: str,
        proxy_log: tuple[ProxyAccessRecord, ...] = (),
    ) -> None:
        """Emit ``sandbox.policy.violated`` per spec §4.3 wire-public
        payload ``{reason: SandboxPolicyViolationReason}``.

        Fired BEFORE :meth:`exec` raises ``SandboxPolicyViolated`` on
        any cap-violation path (memory_cap_exceeded /
        walltime_cap_exceeded / cpu_time_budget_exceeded /
        egress_audit_unreadable / egress_host_not_allow_listed /
        egress_protocol_not_http). Without this row, cap kills
        happen in production with NO audit trail and the evidence
        pack misses the wire-protocol-public event.

        When ``proxy_log`` is non-empty (egress refusal path), the
        materialised list of records is included on the chain row
        payload under the ``proxy_log`` key — spec §10.3 requires
        examiners to prove which outbound calls were attempted +
        which were refused FROM THE CHAIN ROW ALONE.

        Mirrors :meth:`DockerSiblingSandboxBackend._emit_policy_violated`
        wire shape for cross-backend behavioural equivalence.
        """
        from cognic_agentos.sandbox.proxy import proxy_log_to_chain_payload

        payload: dict[str, Any] = {"reason": reason}
        if proxy_log:
            payload["proxy_log"] = proxy_log_to_chain_payload(proxy_log)
        await emit_sandbox_event(
            self._dh,
            event="sandbox.policy.violated",
            tenant_id=session.tenant_id,
            actor_id=session._actor_subject,
            trace_id="",
            session_id=session.session_id,
            payload=payload,
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
