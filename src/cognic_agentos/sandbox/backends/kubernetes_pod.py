"""Sprint 8B T8B-b — KubernetesPodSandboxBackend.

Critical-controls module per AGENTS.md + ADR-004 amendment.

Wave-1 production backend for Kubernetes/OpenShift per
``project_openshift_deployment_target``. Conforms to the same
:class:`SandboxBackend` Protocol as
:class:`DockerSiblingSandboxBackend`
(:mod:`cognic_agentos.sandbox.protocol`). Emits the same sandbox
audit/refusal taxonomy via :func:`emit_sandbox_event` and
:data:`SandboxRefusalReason` (Sprint 8A: 8 lifecycle events + 15
refusal reasons; Sprint 8.5 T1 extended to 12 + 21 per spec §3.3 —
adds checkpointed/suspended/woken/checkpoint_purged events + 6
wake-time refusal arms; this backend stays SYMMETRIC with
DockerSibling across the extended taxonomy per spec §7.3 cross-backend
parity invariant).

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
import hashlib
import json
import logging
import uuid as _uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import kubernetes_asyncio  # noqa: F401 — admission contract: the sandbox-k8s extra MUST be installed
from kubernetes_asyncio import client as kube_client
from kubernetes_asyncio.stream import WsApiClient
from kubernetes_asyncio.stream.ws_client import (
    ERROR_CHANNEL,
    STDERR_CHANNEL,
    STDIN_CHANNEL,
    STDOUT_CHANNEL,
)

from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.vault import (
    CredentialLease,
    VaultAuthDenied,
    VaultLeaseRequest,
    VaultPathNotFound,
    VaultProtocolError,
    VaultUnavailable,
)
from cognic_agentos.sandbox.admission import (
    CatalogProtocol,
    CredentialAdapter,
    admit_policy,
)
from cognic_agentos.sandbox.audit import (
    emit_sandbox_event,
    sandbox_lifecycle_checkpointed,
    sandbox_lifecycle_lease_minted,
    sandbox_lifecycle_lease_revoke_failed,
    sandbox_lifecycle_lease_revoked,
    sandbox_lifecycle_suspended,
    sandbox_lifecycle_woken,
)
from cognic_agentos.sandbox.backends._shared_credentials import (
    # Sprint 10 T10 K8s round-2 reviewer-P1 fix: the helper lives in
    # the dependency-neutral _shared_credentials module (NOT in
    # docker_sibling) so K8s-only deployments without the sandbox-
    # docker extra do not couple to ``aiodocker`` at import time per
    # the optional-extra boundary documented at
    # ``sandbox/__init__.py``. Earlier T10 K8s round-1 imported this
    # directly from docker_sibling; reviewer caught the import-time
    # coupling regression by running a blocked-import probe. The
    # _shared_credentials module imports ONLY from core.vault +
    # sandbox.protocol — no backend-specific deps.
    _mint_exception_to_refusal_reason,
)
from cognic_agentos.sandbox.backends._shared_exec import (
    _classify_exec_failure,
    _ProxyLogReadFailure,
)
from cognic_agentos.sandbox.checkpoint_store import (
    CheckpointStore,
    TombstoneCorruptError,
)
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.protocol import (
    CheckpointId,
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

#: Parent directory of :data:`_PROXY_LOG_PATH`. Sprint 8.5 T7 P1.4
#: mounts an ``emptyDir`` volume at this path on the PROXY SIDECAR
#: ONLY so the canonical egress-proxy image can create + append to
#: ``access.jsonl`` under ``readOnlyRootFilesystem=True``. The
#: sandbox container MUST NOT mount this volume — the proxy log is
#: AgentOS-owned evidence that the workload-side sandbox must not
#: be able to tamper with. A module-load ``if not ...: raise
#: RuntimeError(...)`` guard (below) enforces that this path is the
#: parent directory of ``_PROXY_LOG_PATH`` so a future log-path
#: move cannot silently desync the mount target.
_PROXY_LOG_DIR: str = "/var/log/cognic-proxy"

#: Writable workspace path inside the sandbox container. Wire-public
#: across the workspace-tar checkpoint mechanism (spec §7.2): ``tar
#: czf - -C /workspace .`` on checkpoint + ``head -c N | tar xzf -
#: --strip-components=1 --no-overwrite-dir -C /workspace`` on restore (the P1.3-safe
#: pipeline — no temp file staged on disk; ``head -c N`` gives
#: ``tar`` clean stdin EOF under the v4 exec subprotocol, and
#: ``--strip-components=1`` skips the archive's ``./`` entry so tar
#: never rewrites the existing emptyDir mount-root metadata under
#: OpenShift arbitrary UIDs). ``readOnlyRootFilesystem=True`` (per
#: ``_build_security_context``) makes the root FS read-only; the
#: Sprint 8.5 T7 emptyDir mount makes EXACTLY this path writable.
#: The mount path + the checkpoint tar ``-C`` source + the restore
#: tar ``-C`` target MUST agree — drift here breaks the wake-restore
#: round-trip under OpenShift restricted-v2 SCC. Pinned by
#: ``test_pod_spec_writable_workspace_mount_path_matches_restore_target``
#: (regression in ``test_kubernetes_pod_pure_helpers.py``).
_SANDBOX_WORKSPACE_PATH: str = "/workspace"

# Module-load drift detector — fail-loud if the proxy log path is
# moved without updating the mount-target constant. Without this
# guard a one-line edit to ``_PROXY_LOG_PATH`` could silently
# desync the sidecar volumeMount, surfacing only on a real OpenShift
# Pod as ``egress_audit_unreadable`` after every green exec.
#
# Explicit ``if not ...: raise RuntimeError(...)`` — NOT ``assert``.
# ``assert`` statements are stripped under ``python -O`` /
# ``PYTHONOPTIMIZE=1``, which would silently let drifted constants
# import successfully on optimized runs. Critical-controls modules
# cannot accept that failure mode; the test-only drift detector at
# ``test_proxy_log_dir_is_parent_of_proxy_log_path`` is the CI guard,
# but production runs need the import-time enforcement too.
if not _PROXY_LOG_PATH.startswith(_PROXY_LOG_DIR + "/"):
    raise RuntimeError(
        f"_PROXY_LOG_DIR ({_PROXY_LOG_DIR!r}) MUST be the parent directory "
        f"of _PROXY_LOG_PATH ({_PROXY_LOG_PATH!r}). Update both constants "
        "together or the sidecar's emptyDir mount target will not cover "
        "the path the proxy writes."
    )

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

#: Sprint 8.5 T7 / #477 — interval between pod readiness/deletion
#: polls during wake(), create(), and deterministic-name teardown.
#: kubelet typically transitions a freshly-created/deleted Pod within
#: a few hundred milliseconds; 0.25s strikes a balance between
#: latency to first exec / wake recreate + apiserver load.
_POD_READY_POLL_INTERVAL_S: float = 0.25

#: Sprint 8.5 T7 / #477 — maximum seconds to wait for a
#: freshly-created Pod to become ready before create() returns or the
#: wake tar-restore exec stream opens. Bounded so a misconfigured
#: cluster cannot wedge wake()/create() indefinitely. A timeout
#: surfaces as ``RuntimeError`` which the outer try/except translates
#: to teardown + re-raise — the caller sees the failure + the partial
#: state is cleaned up.
_POD_READY_TIMEOUT_S: float = 30.0

#: #477 live CRC proof — maximum seconds to wait after deleting a Pod
#: whose name will be reused on wake. Kubernetes deletion is
#: asynchronous: immediately recreating ``sb-<session_id>`` can fail
#: with ``409 AlreadyExists: object is being deleted`` unless teardown
#: waits for the apiserver to report 404.
_POD_DELETE_TIMEOUT_S: float = 30.0


class _SuspendEventIdCorruptError(ValueError):
    """Raised when the per-session ``<tenant>/<session>/<checkpoint>.suspend_event_id``
    side-blob is missing, non-UTF-8, or does not parse as a UUID.

    Wake() catches this + surfaces ``sandbox_wake_checkpoint_corrupt``
    per spec §3.2 step 5 fail-closed contract before any fresh K8s
    resources are created.

    Mirrors ``docker_sibling._SuspendEventIdCorruptError`` consumer-
    owned per ``feedback_consumer_owned_protocol_for_unlanded_dep``;
    a test-only drift detector at
    ``tests/unit/sandbox/backends/test_exec_classification_cross_backend_drift.py``
    pins the cross-backend lockstep without a runtime cross-module import.
    """


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
    egress_proxy_image: str,
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
    # Writable workspace mount (Sprint 8.5 T7 — load-bearing).
    # ``readOnlyRootFilesystem=True`` (in ``_build_security_context``)
    # makes the container's root filesystem read-only. Without an
    # explicit writable mount, the sandbox cannot write to
    # ``/workspace`` for normal workload state OR for the T7 wake-
    # restore tar extraction (``head -c N | tar xzf -
    # --strip-components=1 --no-overwrite-dir -C /workspace`` —
    # extracts in place while skipping the archive's ``./`` entry, no
    # temp file). An ``emptyDir`` volume mounted
    # at ``/workspace`` provides per-Pod ephemeral writable storage
    # backed by the node's local disk (default) or tmpfs (when
    # ``medium: Memory`` is set; we use default disk-backed to support
    # multi-GB workspaces without consuming node memory).
    #
    # OpenShift restricted-v2 SCC compatibility: emptyDir is permitted
    # by the default restricted SCC without volume-plugin allow-list
    # changes (unlike hostPath / persistentVolumeClaim / configMap).
    # The mount inherits the container's runAsUser from the namespace
    # ``MustRunAsRange`` allocation (per ``_build_security_context``),
    # so no fsGroup is needed.
    #
    # Pinned by ``test_pod_spec_mounts_writable_workspace_emptydir`` +
    # ``test_pod_spec_writable_workspace_only_on_sandbox_not_sidecar``
    # + ``test_pod_spec_writable_workspace_mount_path_matches_restore_target``.
    _WORKSPACE_VOLUME_NAME = "workspace"
    workspace_volume = {
        "name": _WORKSPACE_VOLUME_NAME,
        "emptyDir": {},
    }
    workspace_mount = {
        "name": _WORKSPACE_VOLUME_NAME,
        "mountPath": _SANDBOX_WORKSPACE_PATH,
    }
    # Proxy-log writable volume — Sprint 8.5 T7 P1.4 (load-bearing).
    # The egress-proxy sidecar writes ``access.jsonl`` to
    # ``_PROXY_LOG_PATH`` on every outbound request; the exec() green
    # path reads that file via ``cat`` and fail-closes with
    # ``egress_audit_unreadable`` if the read fails. Under
    # ``readOnlyRootFilesystem=True`` the canonical proxy image
    # cannot create the file at all without an explicit writable
    # mount at ``_PROXY_LOG_DIR``. Without this mount EVERY normal
    # ``session.exec()`` on a real OpenShift Pod would fail-closed
    # before checkpoint/suspend/wake is reachable.
    #
    # SIDECAR ONLY — the sandbox container MUST NOT mount this
    # volume. The proxy log is AgentOS-owned evidence the workload-
    # side sandbox must not be able to read OR tamper with. Negative
    # test in ``test_kubernetes_pod_pure_helpers.py`` pins this.
    _PROXY_LOG_VOLUME_NAME = "proxy-log"
    proxy_log_volume = {
        "name": _PROXY_LOG_VOLUME_NAME,
        "emptyDir": {},
    }
    proxy_log_mount = {
        "name": _PROXY_LOG_VOLUME_NAME,
        "mountPath": _PROXY_LOG_DIR,
    }
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
            "volumes": [workspace_volume, proxy_log_volume],
            "containers": [
                {
                    "name": _SANDBOX_CONTAINER_NAME,
                    "image": policy.runtime_image,
                    "env": sandbox_env,
                    "securityContext": security_context,
                    "volumeMounts": [workspace_mount],
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
                    "image": egress_proxy_image,
                    "securityContext": security_context,
                    "volumeMounts": [proxy_log_mount],
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
    #: Sprint 10 T10 — Protocol-compat shim per spec §3.6. Tuple
    #: (NOT list) — immutable post-construction. Default empty tuple
    #: keeps Sprint-8B/8.5 construction paths backward-compat.
    #: **The K8s mint/revoke wiring + Q5 LOCK on checkpoint/suspend
    #: lands in the T10 K8s commit (next halt-before-commit cycle)** —
    #: this field declaration is the Protocol-compat shim needed to
    #: keep the branch bisection-clean (mypy SandboxSession structural
    #: conformance) when T10 Docker lands first per the user-locked
    #: 2-commit split. The K8s ``KubernetesPodSandboxBackend.create()``
    #: in this commit raises ``NotImplementedError`` on non-empty
    #: ``requires_credentials`` so no caller can accidentally trip
    #: the unwired path; the T10 K8s commit replaces the raise with
    #: the real mint loop + active_leases assignment.
    active_leases: tuple[CredentialLease, ...] = ()
    _actor_subject: str = field(repr=False, default="")
    _destroyed: bool = field(repr=False, default=False)
    #: Sprint 8.5 T7 — suspend() flips this True so subsequent exec()
    #: / checkpoint() calls raise per spec §3.1: "Subsequent ``exec()``
    #: calls on this session raise. wake() restores the session in a
    #: fresh backend resource". Defence-in-depth past Pod teardown:
    #: the underlying Pod is gone after suspend(), so the K8s API call
    #: would also fail — but this surfaces a clear RuntimeError with
    #: the wake-pointer rather than a raw ApiException. Mirrors
    #: ``DockerSiblingSession._suspended`` at docker_sibling.py:709.
    _suspended: bool = field(repr=False, default=False)

    async def exec(
        self,
        command: list[str],
        *,
        timeout_s: float | None = None,
    ) -> SandboxExecResult:
        if self._suspended:
            # Sprint 8.5 T7 — spec §3.1 + spec §8 test row
            # test_session_lifecycle_after_suspend.py. exec() on a
            # suspended session refuses fail-loud with a wake-pointer
            # so the caller knows to wake() first.
            #
            # NOT a SandboxLifecycleRefused — that closed-enum is
            # admission + wake-time only; using a wake-time value here
            # would mis-classify the failure mode in the wire-public
            # taxonomy. The session-lifetime invariant is a usage error,
            # NOT a wake refusal. RuntimeError keeps the closed-enum
            # vocabulary unpolluted while still failing loud. Mirrors
            # docker_sibling.py:717-734 verbatim, "container" → "Pod".
            raise RuntimeError(
                f"session {self.session_id} was suspend()ed; "
                f"exec() is no longer valid — call "
                f"SandboxBackend.wake(session_id) to restore the "
                f"session in a fresh Pod per spec §3.2"
            )
        return await self._backend.exec(self, command, timeout_s=timeout_s)

    async def destroy(self) -> None:
        await self._backend.destroy(self)

    # Sprint 8.5 T7 — checkpoint + suspend implementations per spec
    # §3.1 + §7.2. Delegate to backend so the kubernetes_asyncio call
    # sites stay in one module + backend can own the CheckpointStore
    # + audit-emit wiring. Symmetric with docker_sibling.py:740-758.

    async def checkpoint(self, label: str) -> CheckpointId:
        self._raise_q5_lock_if_leased("checkpoint")
        return await self._backend._do_checkpoint(self, label)

    async def suspend(self) -> None:
        self._raise_q5_lock_if_leased("suspend")
        await self._backend._do_suspend(self)

    def _raise_q5_lock_if_leased(self, op: str) -> None:
        """Sprint 10 T10 Q5 LOCK per spec §4.5 — production-grade
        fail-loud scaffolding pointing at Sprint 10.x.

        Mirrors ``DockerSiblingSession._raise_q5_lock_if_leased`` per
        the cross-backend-symmetry contract at spec §4.5 closing
        paragraph ("the fail-loud check lives in the concrete
        session classes... NOT in the base Protocol"). Cross-backend
        parity pinned by the parametrized regressions at
        ``tests/unit/sandbox/test_credential_lifecycle.py``.

        Resolution of the leased-session checkpoint/suspend/wake
        model (re-mint at wake vs revoke-at-suspend vs
        token-in-checkpoint) is the follow-up Sprint 10.x call per
        the same spec §4.5 rationale.
        """
        if not self.active_leases:
            return
        raise NotImplementedError(
            f"KubernetesPodSession.{op}() on a leased session "
            f"(active_leases count={len(self.active_leases)}) is "
            "out of scope at Sprint 10 per spec §4.5 Q5 LOCK; a "
            "follow-up Sprint 10.x sprint resolves the leased-session "
            "checkpoint / suspend / wake model (re-mint at wake vs "
            "revoke-at-suspend vs token-in-checkpoint). The Sprint-8.5 "
            "Q4 lock's vault_lease_refs=() premise breaks at Sprint 10; "
            "fail loud rather than silently drop leases."
        )


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
        checkpoint_store: CheckpointStore | None = None,
        egress_proxy_image: str | None = None,
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
        # Sprint 8.5 T7 — optional wiring for the CheckpointStore +
        # tombstone seam. checkpoint() / suspend() / wake() / destroy()'s
        # tombstone branch ALL require it. None is the Sprint-8B default
        # (callers that never use Sprint 8.5 checkpoints can leave it
        # unwired); the three Sprint-8.5 methods refuse fail-loud when
        # called against a backend without a checkpoint_store wired
        # (NotImplementedError with explicit "wire CheckpointStore"
        # pointer per CLAUDE.md production-grade rule). destroy()'s
        # tombstone path is a no-op without it — sessions that have
        # never checkpointed cannot have tombstones. Mirrors
        # docker_sibling.py:790,810 verbatim.
        self._checkpoint_store = checkpoint_store
        # #477 §5 — narrow egress-proxy image seam. Mirrors
        # docker_sibling.py exactly: explicit None-check (NOT ``or``) so
        # an empty string fails fast rather than silently falling back
        # to the placeholder canonical proxy. Production callers omit
        # the kwarg -> None -> the canonical default.
        if egress_proxy_image is not None and not egress_proxy_image.strip():
            raise ValueError(
                "egress_proxy_image, when provided, must be a non-empty "
                "OCI ref; got an empty/blank string"
            )
        self._egress_proxy_image: str = (
            _CANONICAL_EGRESS_PROXY_IMAGE if egress_proxy_image is None else egress_proxy_image
        )

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
        requires_credentials: Sequence[VaultLeaseRequest] = (),
    ) -> SandboxSession:
        """Admit + create a sandbox session per spec §6.1 + ADR-004
        amendment.

        Sprint 10 T10 Protocol-compat shim — the ``requires_credentials``
        kwarg is accepted at the Protocol surface per spec §4.2 so
        ``KubernetesPodSandboxBackend`` structurally conforms to the
        updated ``SandboxBackend`` Protocol. **The K8s mint/revoke
        wiring + Q5 LOCK lands in the T10 K8s commit (next
        halt-before-commit cycle)**; this commit fail-louds on
        non-empty input so no caller can accidentally trip the unwired
        path before the implementation lands. The Docker backend
        already ships the full T10 wiring at ``docker_sibling.py``.

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
           with default-namespace egress), then Pod, then wait for
           Pod readiness before exposing the session to callers.
        4. Emit ``lifecycle.created(warm_pool_hit=False)`` + return
           the :class:`KubernetesPodSession`.

        On any failure during cold-create, the cleanup envelope
        invokes :meth:`_teardown_session_state` so no K8s objects
        leak. No ``lifecycle.created`` emitted on the failure path
        because the session never reached a running state.
        """
        # 1. Warm-pool checkout (if wired + caller asked for it AND
        #    no credentials requested). Sprint 10 spec §4.2.1: warm
        #    members were pre-created without an actor context for
        #    leases; a warm hit on a credentialed call would silently
        #    bypass cross-tenant + Rego TTL + mint per the same
        #    reasoning that drives the Docker backend's short-circuit
        #    at docker_sibling.py:920. Force cold-create when
        #    requires_credentials is non-empty.
        if use_warm_pool and self._warm_pool is not None and not requires_credentials:
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
            requires_credentials=requires_credentials,
        )

        # 3. Mint session_id + derive deterministic names
        session_id = _uuid.uuid4().hex
        pod_name = _pod_name(session_id)
        netpol_name = _network_policy_name(session_id)

        # 4. Pre-flight canonical-image catalog verification on the
        # PROXY image. K8s-specific gate — the proxy IS the egress-
        # enforcement component; without this gate, a compromised
        # registry could land an unverified proxy as a trusted
        # enforcement point. Refuses session creation BEFORE any K8s
        # API call AND BEFORE the mint loop so a proxy-refusal never
        # leaves leases needing cleanup. Pinned by
        # ``TestKubernetesPreflightProxyRefusalDoesNotMint`` — a
        # future refactor that reorders this AFTER the mint loop
        # would silently allocate leases for sessions that
        # proxy-refusal aborts.
        _, proxy_image_digest = self._egress_proxy_image.rsplit("@", 1)
        if not self._catalog.is_canonical(proxy_image_digest):
            raise SandboxLifecycleRefused(
                "sandbox_image_digest_not_in_canonical_catalog",
                detail=(
                    f"proxy sidecar image {self._egress_proxy_image} "
                    f"not in canonical catalog (digest {proxy_image_digest}) "
                    f"— egress enforcement component MUST be catalog-verified "
                    f"per spec §9 + the docker_sibling R1 P1.1 cross-backend "
                    f"parity contract"
                ),
            )
        await self._catalog.verify_cosign_or_refuse(proxy_image_digest, tenant_id=tenant_id)
        await self._catalog.verify_sbom_policy_or_refuse(proxy_image_digest, tenant_id=tenant_id)

        # 5. Build the K8s object specs via pure helpers (no state
        # allocated — safe to do outside the cleanup envelope).
        pod_spec = _build_pod_spec(
            policy=policy,
            session_id=session_id,
            tenant_id=tenant_id,
            egress_proxy_image=self._egress_proxy_image,
        )
        netpol_spec = _build_network_policy_spec(session_id=session_id, tenant_id=tenant_id)

        # 6. Sprint 10 T10 K8s — SINGLE post-admission cleanup envelope
        # per spec §7.3 row "Any backend failure post-mint", mirroring
        # the Docker backend's round-2 + round-3 reviewer P1 shape.
        # Three except arms: asyncio.CancelledError (round-3 P1 —
        # subclasses BaseException NOT Exception per Python 3.8+ MRO,
        # so the generic-Exception arm does NOT catch it; without the
        # explicit arm a cancelled create() task would skip cleanup
        # and leak the lease), Vault taxonomy → SandboxLifecycleRefused
        # closed-enum mapping per spec §7.1, generic Exception →
        # propagate UNCHANGED per spec §7.3.
        #
        # All three arms converge on _cleanup_post_admission_failure
        # (K8s-shape helper — pod_name + network_policy_name args
        # vs Docker's 4-arg form).
        minted_leases: list[CredentialLease] = []
        try:
            # 6a. Mint leases per spec §4.2 — per request, in order.
            for request in requires_credentials:
                lease = await self._credential_adapter.mint_lease(request)
                minted_leases.append(lease)
                await sandbox_lifecycle_lease_minted(
                    self._dh,
                    lease=lease,
                    trace_id="",
                    session_id=session_id,
                )

            # 6b. Create NetworkPolicy FIRST so egress lockdown is
            # active BEFORE the Pod starts. Then create the Pod and
            # wait for the kubelet to report both containers ready
            # before exposing the session to callers.
            await self._create_network_policy(netpol_spec)
            await self._create_pod(pod_spec)
            await self._wait_for_pod_ready(pod_name=pod_name)

            # 6c. Session construct + lifecycle.created emit per spec
            # §4.3.
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
                active_leases=tuple(minted_leases),
                _actor_subject=actor.subject,
            )
            await self._emit_lifecycle_created(
                session=session,
                actor=actor,
                warm_pool_hit=False,
            )
        except asyncio.CancelledError:
            # See docker_sibling.py:create() cancellation-arm comment
            # for the full rationale. Summary: asyncio.CancelledError
            # subclasses BaseException not Exception, so the generic-
            # Exception arm doesn't catch it. Cleanup helper then
            # re-raise UNCHANGED — never swallow cancellation.
            await self._cleanup_post_admission_failure(
                minted_leases=minted_leases,
                pod_name=pod_name,
                network_policy_name=netpol_name,
            )
            raise
        except (
            VaultUnavailable,
            VaultPathNotFound,
            VaultAuthDenied,
            VaultProtocolError,
        ) as exc:
            await self._cleanup_post_admission_failure(
                minted_leases=minted_leases,
                pod_name=pod_name,
                network_policy_name=netpol_name,
            )
            raise SandboxLifecycleRefused(
                reason=_mint_exception_to_refusal_reason(exc),
                detail=str(exc),
            ) from exc
        except Exception:
            await self._cleanup_post_admission_failure(
                minted_leases=minted_leases,
                pod_name=pod_name,
                network_policy_name=netpol_name,
            )
            raise
        return session

    async def _cleanup_post_admission_failure(
        self,
        *,
        minted_leases: list[CredentialLease],
        pod_name: str,
        network_policy_name: str,
    ) -> None:
        """Sprint 10 T10 K8s — shared post-admission cleanup envelope
        per spec §7.3 row "Any backend failure post-mint".

        K8s analog of ``DockerSiblingSandboxBackend._cleanup_post_admission_failure``.
        Called from all three ``except`` arms of ``create()``'s
        post-admission cleanup envelope (``asyncio.CancelledError`` +
        Vault taxonomy + everything-else). Best-effort revoke +
        best-effort teardown — both stages wrap their await in
        ``contextlib.suppress(Exception)`` so a Vault revoke 5xx does
        not block topology teardown and a K8s ApiException does not
        block subsequent stages. **Suppresses ordinary cleanup
        exceptions; cancellation may still interrupt** —
        ``contextlib.suppress(Exception)`` deliberately does NOT catch
        ``BaseException`` subclasses (``CancelledError`` /
        ``KeyboardInterrupt`` / ``SystemExit``), so a nested re-cancel
        during cleanup propagates out of this helper. Vault
        server-side TTL is the operational safety net for that edge
        case per spec §7.2. The K8s ``_teardown_session_state`` swallows
        404s on entities that were never created so unconditional
        invocation is safe even when an early-loop exception aborted
        before any topology call.

        Differs from Docker's helper only in signature shape — K8s
        teardown takes ``pod_name + network_policy_name`` (vs Docker's
        4-arg internal/egress/sidecar form). The cross-backend
        SYMMETRY of behaviour (revoke first, teardown second, swallow
        ordinary exceptions, propagate cancellation) is pinned by the
        parametrized regressions at
        ``tests/unit/sandbox/test_credential_lifecycle.py``.

        Order: revoke leases FIRST (less time for the in-flight lease
        to be used by a still-running Pod), then teardown topology.
        Both stages independently swallow ordinary exceptions so a
        single revoke failure does not block topology teardown and
        vice-versa.
        """
        for already_minted in minted_leases:
            with contextlib.suppress(Exception):
                await self._credential_adapter.revoke_lease(already_minted.lease_id)
        with contextlib.suppress(Exception):
            await self._teardown_session_state(
                pod_name=pod_name,
                network_policy_name=network_policy_name,
            )

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

        Sprint 8.5 T7 + P1.r4 tombstone redesign: if the session has
        persisted checkpoints (any checkpoint() or suspend() call), the
        backend additionally calls
        ``CheckpointStore.tombstone_session(session_id, tenant_id,
        tombstoned_by=session._actor_subject)`` to write the
        ``<tenant>/<session>/_tombstoned.json`` sentinel. The destroyed
        chain row then carries TWO extra payload keys (``retained_until``
        + ``tombstone_object_key``) so examiners can correlate destroy →
        tombstone → eventual reaper purge. Sessions with NO persisted
        checkpoints skip the tombstone write — nothing to retain — and
        emit the destroyed event without the extension keys.

        Wake() against a tombstoned session refuses with
        ``sandbox_wake_session_tombstoned`` per spec §3.2 step 1(a) —
        destroyed sessions are NOT wakeable even though the checkpoint
        bytes might still be on disk pending reaper sweep.

        Mirrors docker_sibling.destroy at docker_sibling.py:1247-1346.
        """
        if not isinstance(session, KubernetesPodSession):
            raise TypeError(
                f"KubernetesPodSandboxBackend.destroy expects "
                f"KubernetesPodSession; got {type(session).__name__}"
            )

        already_destroyed = session._destroyed
        teardown_succeeded = False
        try:
            await self._teardown_session_state(
                pod_name=session._pod_name,
                network_policy_name=session._network_policy_name,
            )
            teardown_succeeded = True
        finally:
            # Sprint 10 T10 K8s round-2 reviewer-P2 fix + round-3
            # reviewer-P1 follow-up (2026-05-24): revoke active Vault
            # leases best-effort EVEN WHEN teardown raised AND
            # surface audit-emit failures on the normal path so banks
            # see them per spec §7.2 ("audit evidence for every
            # revoke failure"). Same conditional-suppress shape as
            # the Docker counterpart at ``docker_sibling.py``'s
            # destroy() — cross-backend invariant pinned by both
            # ``TestCrossBackendDestroyRevokesEvenWhenTeardownRaises``
            # AND ``TestCrossBackendDestroyAuditEmitConditionalSuppress``
            # in ``tests/unit/sandbox/test_credential_lifecycle.py``.
            #
            # K8s ``_teardown_session_state`` intentionally propagates
            # non-404 ApiException per its docstring ("fail-closed
            # so a real teardown failure does not silently leak").
            # Without this try/finally the original T10 K8s destroy()
            # exited on the teardown exception BEFORE the revoke
            # loop ran, leaving active leases to TTL.
            #
            # Two-axis correctness contract (per the conditional
            # suppress):
            # * teardown_succeeded=False — suppress audit-emit
            #   exceptions so the ORIGINAL teardown exception
            #   propagates per Python finally-block semantics.
            # * teardown_succeeded=True — audit-emit failures
            #   PROPAGATE per spec §7.2's bank-grade contract.
            #
            # Gated on ``not already_destroyed`` so the idempotent
            # second destroy does NOT re-emit lease events. The
            # Vault revoke itself is intentionally NOT wrapped in
            # suppress — its own try/except routes failures to
            # lease_revoke_failed audit so each lease attempt is
            # independently best-effort per §7.2.
            if not already_destroyed:
                # Capture the FIRST normal-path audit-emit exception
                # so we can raise it AFTER every lease got its
                # revoke attempt per spec §7.2's single-attempt-
                # per-lease cleanup contract. Round-3 reviewer-P1
                # propagated immediately, which aborted the loop on
                # multi-lease destroys (Gap N). Round-4 reviewer-P2
                # fix: keep attempting + emit for every lease,
                # remember first emit exception, raise after loop.
                # Same shape as the Docker counterpart at
                # ``docker_sibling.py``'s destroy() — cross-backend
                # invariant pinned by
                # ``TestCrossBackendDestroyAuditEmitConditionalSuppress``
                # at ``tests/unit/sandbox/test_credential_lifecycle.py``.
                first_normal_path_emit_exc: BaseException | None = None

                async def _emit_revoke_event(coro: Any) -> None:
                    nonlocal first_normal_path_emit_exc
                    if teardown_succeeded:
                        try:
                            await coro
                        except Exception as exc:
                            if first_normal_path_emit_exc is None:
                                first_normal_path_emit_exc = exc
                    else:
                        with contextlib.suppress(Exception):
                            await coro

                for lease in session.active_leases:
                    try:
                        await self._credential_adapter.revoke_lease(lease.lease_id)
                    except Exception as exc:
                        await _emit_revoke_event(
                            sandbox_lifecycle_lease_revoke_failed(
                                self._dh,
                                lease=lease,
                                trace_id="",
                                session_id=session.session_id,
                                vault_error=str(exc),
                            )
                        )
                        continue
                    await _emit_revoke_event(
                        sandbox_lifecycle_lease_revoked(
                            self._dh,
                            lease=lease,
                            trace_id="",
                            session_id=session.session_id,
                        )
                    )

                # Normal-path-only: raise the FIRST captured emit
                # exception AFTER every lease attempted its revoke.
                # On the teardown-failure path
                # first_normal_path_emit_exc stays None (the inner
                # suppress swallows emit failures so the original
                # teardown exception wins).
                if first_normal_path_emit_exc is not None:
                    raise first_normal_path_emit_exc
        if already_destroyed:
            return

        # Sprint 8.5 T7 — tombstone the session if it has persisted
        # checkpoints. Per spec §3.1 destroy() behavior extension +
        # P1.r4 tombstone redesign: the tombstone seam writes the
        # sentinel so wake() can fail-closed even before the reaper
        # has swept the checkpoint bytes.
        #
        # tombstoned_by comes from session._actor_subject (per spec
        # §3.1: "destroy() takes no actor parameter; the session's
        # stored _actor_subject is the authoritative source of 'who
        # owned this session' for audit-row attribution"). NOT
        # actor.subject — destroy() has no actor kwarg per the
        # Sprint-8A Protocol signature.
        retained_until_str: str | None = None
        tombstone_object_key: str | None = None
        if self._checkpoint_store is not None:
            has_checkpoints = await self._session_has_persisted_checkpoints(
                session_id=session.session_id,
                tenant_id=session.tenant_id,
            )
            if has_checkpoints:
                tombstone_object_key = await self._checkpoint_store.tombstone_session(
                    session_id=session.session_id,
                    tenant_id=session.tenant_id,
                    tombstoned_by=session._actor_subject,
                )
                retention_window_s = int(
                    self._checkpoint_store._settings.sandbox_checkpoint_retention_s
                )
                retained_until_str = (
                    datetime.now(UTC) + timedelta(seconds=retention_window_s)
                ).isoformat()

        # Emit BEFORE setting the flag so a transient audit
        # failure leaves _destroyed False and a retry destroy()
        # will retry the emission. The K8s teardown is idempotent
        # (the helpers swallow 404 ApiException) so calling
        # destroy() twice after a transient emit failure is safe.
        # Mirrors docker_sibling's R2 P1.2 reviewer fix ordering.
        # The tombstone write upstream is ALSO idempotent — a
        # retry destroy() gets back the existing sentinel key
        # (per spec §4.1).
        await self._emit_lifecycle_destroyed(
            session=session,
            retained_until=retained_until_str,
            tombstone_object_key=tombstone_object_key,
        )
        session._destroyed = True

    async def _session_has_persisted_checkpoints(
        self,
        *,
        session_id: str,
        tenant_id: str,
    ) -> bool:
        """True iff at least one ``.metadata.json`` blob exists under
        ``<tenant>/<session>/``. Used by destroy() to gate the
        tombstone branch per spec §3.1: only sessions with checkpoints
        get a tombstone (immediate-destroy sessions emit destroyed
        without the extension payload keys).

        Mirrors docker_sibling.py:1348-1367 verbatim.
        """
        assert self._checkpoint_store is not None  # narrowed by caller
        prefix = f"{tenant_id}/{session_id}/"
        async for key in self._checkpoint_store._object_store.list_prefix(
            "sandbox-checkpoints", prefix
        ):
            if key.endswith(".metadata.json"):
                return True
        return False

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

    # Sprint 8.5 T7 — wake() pipeline per spec §3.2 + §7.2.
    # LOAD-BEARING tombstone-first ordering: CheckpointStore.load_tombstone()
    # MUST be called BEFORE load_latest(). Pinned by the unit test at
    # test_wake_session_tombstoned.py + the cross-backend conformance
    # regression at T9. See the docstring below for the full step list.
    # Symmetric with DockerSibling.wake at docker_sibling.py:1390-1681
    # per spec §7.3 cross-backend wire-public parity invariant.

    async def wake(
        self,
        session_id: str,
        *,
        actor: Actor,
        tenant_id: str,
    ) -> SandboxSession:
        """Restore a suspended session per spec §3.2 + §7.2.

        Pipeline (step ordering is wire-public + tombstone-first is
        LOAD-BEARING):

        1. ``CheckpointStore.load_tombstone(session_id, tenant_id)``
           **FIRST** — three failure modes:
             (a) Non-None ``TombstoneRecord`` →
                 ``sandbox_wake_session_tombstoned`` carrying tombstone
                 metadata in ``detail``.
             (a-prime) ``TombstoneCorruptError`` raised (P1.r6
                 fail-closed) → SAME ``sandbox_wake_session_tombstoned``
                 closed-enum with the corrupt-exception message in
                 ``detail``. Operator intent ("destroyed = MUST NOT
                 wake") survives degradation.
             (b) ``None`` returned → fall through to load_latest().
                 load_latest() raises ``sandbox_wake_checkpoint_not_found``
                 on missing metadata (propagates AS-IS); raises
                 ``ValueError`` from ``from_storage_payload`` on corrupt
                 metadata — caught here + mapped to
                 ``sandbox_wake_checkpoint_corrupt``.
        2. Cross-check ``metadata.tenant_id`` against caller
           ``tenant_id`` (defence-in-depth past prefix-keyed lookup).
           Mismatch → ``sandbox_wake_tenant_mismatch``.
        3. Retention check: ``now - metadata.created_at >=
           metadata.retention_window_s`` → ``sandbox_wake_checkpoint_retention_expired``
           (defence-in-depth past reaper).
        4. Re-run ``admit_policy(...)`` against LIVE tenant policy /
           catalog / Rego / settings. Any ``SandboxLifecycleRefused``
           re-wrapped as ``sandbox_wake_policy_revalidation_failed``
           with original reason + detail in ``detail`` per spec §2.3.
        5. Read the suspend linkage side-blob written by suspend().
           Missing or malformed linkage is treated as corrupt checkpoint
           state and mapped to ``sandbox_wake_checkpoint_corrupt`` before
           any fresh K8s resources are created.
        6. Create fresh Pod + NetworkPolicy; wait for Pod readiness;
           restore workspace tar via ``tar xzf -
           --strip-components=1 --no-overwrite-dir -C /workspace``
           over the pods/exec channel.
        7. Build fresh ``KubernetesPodSession`` with ORIGINAL
           session_id + new pod (deterministic name from session_id) +
           ``warm_pool_hit=False``.
        8. Emit ``sandbox.lifecycle.woken`` with payload keys
           ``suspend_event_id`` (read from the side-blob written at
           suspend-time) + ``restored_from_checkpoint_id`` (the
           loaded metadata's ``checkpoint_id``).

        ``actor`` + ``tenant_id`` are keyword-only per Q5 identity-seam
        lock. ``session_id`` alone is NEVER authorization — the
        tenant_id cross-check at step 2 is the defence-in-depth
        identity boundary per spec §2.6.
        """
        if self._checkpoint_store is None:
            raise NotImplementedError(
                "KubernetesPodSandboxBackend.wake requires a CheckpointStore "
                "to be wired at construction time. Pass checkpoint_store=... "
                "to __init__ per spec §3.2 + §7.2."
            )

        # ------------------------------------------------------------------
        # Step 1 — tombstone-first ordering. LOAD-BEARING.
        # ------------------------------------------------------------------
        # The tombstone check MUST run BEFORE load_latest(). A
        # destroyed session may still have checkpoint bytes on disk
        # (the reaper purges asynchronously per spec §4.3); checking
        # load_latest first would surface a destroyed-but-not-yet-reaped
        # session as restorable, which is the wrong taxonomy +
        # violates operator intent.
        try:
            tombstone = await self._checkpoint_store.load_tombstone(
                session_id=session_id,
                tenant_id=tenant_id,
            )
        except TombstoneCorruptError as corrupt:
            # P1.r6 fail-closed: a corrupt tombstone surfaces as the
            # SAME closed-enum value as a well-formed tombstone — the
            # operator's destroy() intent survives tampering. The
            # corrupt message lives in ``detail`` for incident-response
            # traceability.
            raise SandboxLifecycleRefused(
                "sandbox_wake_session_tombstoned",
                detail=f"tombstone sentinel corrupt: {corrupt}",
            ) from corrupt
        if tombstone is not None:
            raise SandboxLifecycleRefused(
                "sandbox_wake_session_tombstoned",
                detail=(
                    f"session {session_id} was tombstoned at "
                    f"{tombstone.tombstoned_at.isoformat()} by "
                    f"{tombstone.tombstoned_by!r}; retained_until="
                    f"{tombstone.retained_until.isoformat()}"
                ),
            )

        # Step 1(b)/(c) — load latest checkpoint metadata + bytes.
        # load_latest() raises sandbox_wake_checkpoint_not_found on
        # missing; we propagate AS-IS. It raises ValueError from
        # from_storage_payload on corrupt metadata; we catch + map.
        try:
            metadata, snapshot_bytes = await self._checkpoint_store.load_latest(
                session_id=session_id,
                tenant_id=tenant_id,
            )
        except ValueError as corrupt_meta:
            # Step 1(c) — corrupt metadata bytes on disk. Distinguish
            # from sandbox_wake_session_tombstoned (operator destroy)
            # + sandbox_wake_checkpoint_not_found (genuinely absent).
            raise SandboxLifecycleRefused(
                "sandbox_wake_checkpoint_corrupt",
                detail=f"metadata bytes on disk are malformed: {corrupt_meta}",
            ) from corrupt_meta

        # ------------------------------------------------------------------
        # Step 2 — tenant cross-check (defence-in-depth).
        # ------------------------------------------------------------------
        # load_latest() is keyed by (tenant_id, session_id) prefix so a
        # cross-tenant query would already return not_found via the
        # prefix-keyed isolation. This second check defends against
        # an in-process refactor that bypasses prefix isolation OR a
        # storage-layer race that returned metadata from a different
        # tenant. Per spec §2.6 extra design lock: session_id alone is
        # NEVER authorization; the tenant_id cross-check IS the
        # defence-in-depth identity boundary.
        if metadata.tenant_id != tenant_id:
            raise SandboxLifecycleRefused(
                "sandbox_wake_tenant_mismatch",
                detail=(
                    f"caller tenant_id={tenant_id!r} does not match "
                    f"metadata.tenant_id={metadata.tenant_id!r} for "
                    f"session {session_id}; per-tenant prefix isolation "
                    f"should have caught this — surfacing fail-loud"
                ),
            )

        # ------------------------------------------------------------------
        # Step 3 — retention check (defence-in-depth past reaper).
        # ------------------------------------------------------------------
        # The reaper sweeps asynchronously per spec §4.3 + §6 reaper
        # interval (default 5 min). A just-expired checkpoint may
        # still be on disk between expiry + the next reaper run; wake
        # MUST refuse independently of reaper progress.
        now = datetime.now(UTC)
        age_s = (now - metadata.created_at).total_seconds()
        if age_s >= metadata.retention_window_s:
            raise SandboxLifecycleRefused(
                "sandbox_wake_checkpoint_retention_expired",
                detail=(
                    f"checkpoint {metadata.checkpoint_id} created at "
                    f"{metadata.created_at.isoformat()} is "
                    f"{age_s:.1f}s old; retention_window_s="
                    f"{metadata.retention_window_s}"
                ),
            )

        # ------------------------------------------------------------------
        # Step 4 — admit_policy revalidate against LIVE tenant state.
        # ------------------------------------------------------------------
        # Per spec §2.3 Q3 lock: wake() re-runs admit_policy against
        # the LIVE catalog / Rego / settings — a session admitted under
        # the old tenant max could no longer admit today (the operator
        # tightened limits between suspend + wake). Any Sprint-8A
        # refusal re-wraps as the wake-time
        # sandbox_wake_policy_revalidation_failed with the original
        # reason + detail in `detail` for examiner traceability.
        #
        # This is the seam that catches vault-bearing wakes per spec
        # §2.4 amended (Q4 lock): metadata.policy.vault_path set + wired
        # adapter = KernelDefaultCredentialAdapter → admit_policy step 3
        # raises sandbox_credential_adapter_not_configured → we re-wrap
        # as sandbox_wake_policy_revalidation_failed. NO CredentialAdapter
        # Protocol modification needed.
        try:
            await admit_policy(
                metadata.policy,
                tenant_id=tenant_id,
                actor=actor,
                pack_context=metadata.pack_context,
                catalog=self._catalog,
                credential_adapter=self._credential_adapter,
                rego_engine=self._rego,
                settings=self._settings,
            )
        except SandboxLifecycleRefused as original:
            raise SandboxLifecycleRefused(
                "sandbox_wake_policy_revalidation_failed",
                detail=f"original={original.reason}: {original.detail}",
            ) from original

        # ------------------------------------------------------------------
        # Step 5 — read suspend-event linkage BEFORE creating resources.
        # ------------------------------------------------------------------
        # The linkage blob is part of the suspend→wake integrity contract.
        # Missing or malformed bytes mean the checkpoint cannot be proven to
        # come from a suspend event, so wake refuses at this seam instead of
        # emitting a NIL UUID and deferring failure to the T8 verifier.
        try:
            suspend_event_id = await self._read_suspend_event_id(
                session_id=session_id,
                tenant_id=tenant_id,
                checkpoint_id=metadata.checkpoint_id,
            )
        except _SuspendEventIdCorruptError as corrupt_linkage:
            raise SandboxLifecycleRefused(
                "sandbox_wake_checkpoint_corrupt",
                detail=f"suspend_event_id linkage is malformed or missing: {corrupt_linkage}",
            ) from corrupt_linkage

        # ------------------------------------------------------------------
        # Step 6 — create fresh NetworkPolicy + Pod; wait for readiness;
        # restore workspace tar via the pods/exec channel.
        # ------------------------------------------------------------------
        # session_id is preserved from the original (continuity is the
        # whole point); pod_name + netpol_name are derived deterministically
        # from session_id by the same helpers create() uses, so a
        # wake-then-destroy works the same way as a cold-create-then-destroy.
        #
        # NetworkPolicy FIRST (egress lockdown active before Pod starts) —
        # mirrors create() Step 6 ordering at kubernetes_pod.py:670-675.
        pod_name = _pod_name(session_id)
        netpol_name = _network_policy_name(session_id)
        pod_spec = _build_pod_spec(
            policy=metadata.policy,
            session_id=session_id,
            tenant_id=tenant_id,
            egress_proxy_image=self._egress_proxy_image,
        )
        netpol_spec = _build_network_policy_spec(session_id=session_id, tenant_id=tenant_id)

        try:
            await self._create_network_policy(netpol_spec)
            await self._create_pod(pod_spec)
            # Wait for the kubelet to ack the Pod is running before
            # the tar-restore exec stream opens — without this the
            # pods/exec websocket can race the kubelet's pod-start
            # and fail with "pod not found" or "container not running".
            await self._wait_for_pod_ready(pod_name=pod_name)
            # Restore the workspace tar into /workspace via pods/exec.
            await self._restore_workspace_tar(
                session_id=session_id,
                snapshot_bytes=snapshot_bytes,
            )
        except Exception:
            # Tear down anything we managed to create + re-raise so
            # the caller sees the failure. Idempotent teardown helpers
            # make this safe even on partial-create failures.
            with contextlib.suppress(Exception):
                await self._teardown_session_state(
                    pod_name=pod_name,
                    network_policy_name=netpol_name,
                )
            raise

        # ------------------------------------------------------------------
        # Step 7 — build fresh KubernetesPodSession with ORIGINAL
        # session_id.
        # ------------------------------------------------------------------
        session = KubernetesPodSession(
            session_id=session_id,
            policy=metadata.policy,
            tenant_id=tenant_id,
            pack_context=metadata.pack_context,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=self,
            _pod_name=pod_name,
            _network_policy_name=netpol_name,
            _namespace=self._namespace,
            _actor_subject=actor.subject,
        )

        # ------------------------------------------------------------------
        # Step 8 — emit sandbox.lifecycle.woken with linkage payload.
        # ------------------------------------------------------------------
        # The suspend_event_id linkage points back at the suspended row's
        # primary-key record_id. Step 5 already validated it fail-closed so
        # the chain row never carries a NIL placeholder.
        await sandbox_lifecycle_woken(
            self._dh,
            tenant_id=tenant_id,
            actor_id=actor.subject,
            trace_id="",
            session_id=session_id,
            restored_from_checkpoint_id=metadata.checkpoint_id,
            suspend_event_id=suspend_event_id,
        )
        return session

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
        """Delete a Pod by name and wait until the apiserver reports
        it gone; swallow ApiException 404.

        The wait is load-bearing for suspend→wake: pod names are
        deterministic from session_id, so wake recreates the same
        ``sb-<session_id>`` name that suspend just deleted. K8s pod
        deletion is asynchronous; returning before the old object is
        actually gone lets wake race into ``409 AlreadyExists`` with
        "object is being deleted".
        """
        api = kube_client.CoreV1Api(self._kube)
        try:
            await api.delete_namespaced_pod(
                name=name,
                namespace=self._namespace,
                grace_period_seconds=0,
            )
        except kube_client.ApiException as e:
            if e.status == 404:
                return  # benign: already gone
            raise
        await self._wait_for_pod_deleted(pod_name=name)

    async def _delete_network_policy_if_exists(self, name: str) -> None:
        """Delete a NetworkPolicy by name; swallow ApiException 404."""
        api = kube_client.NetworkingV1Api(self._kube)
        try:
            await api.delete_namespaced_network_policy(name=name, namespace=self._namespace)
        except kube_client.ApiException as e:
            if e.status == 404:
                return  # benign: already gone
            raise

    async def _wait_for_pod_deleted(self, *, pod_name: str) -> None:
        """Poll Pod status until deletion is observed as ApiException 404."""
        deadline = asyncio.get_event_loop().time() + _POD_DELETE_TIMEOUT_S
        api = kube_client.CoreV1Api(self._kube)
        last_status_repr = "delete accepted"
        while True:
            try:
                pod = await api.read_namespaced_pod_status(
                    name=pod_name,
                    namespace=self._namespace,
                )
            except kube_client.ApiException as e:
                if getattr(e, "status", None) == 404:
                    return
                last_status_repr = f"api_exception status={getattr(e, 'status', '?')}"
            else:
                phase = getattr(getattr(pod, "status", None), "phase", "?")
                deletion_ts = getattr(getattr(pod, "metadata", None), "deletion_timestamp", None)
                last_status_repr = f"phase={phase!r} deletion_timestamp={deletion_ts!r}"

            if asyncio.get_event_loop().time() >= deadline:
                raise RuntimeError(
                    f"pod {pod_name!r} was not deleted within "
                    f"{_POD_DELETE_TIMEOUT_S}s; last observed status="
                    f"{last_status_repr}"
                )
            await asyncio.sleep(_POD_READY_POLL_INTERVAL_S)

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
        retained_until: str | None = None,
        tombstone_object_key: str | None = None,
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

        Sprint 8.5 T7 + P1.r4 tombstone redesign: when the destroying
        session has persisted checkpoints, two additional payload keys
        are conditionally included — ``retained_until`` (ISO string of
        ``now + retention_window_s``) + ``tombstone_object_key`` (the
        ``<tenant>/<session>/_tombstoned.json`` storage key returned by
        ``CheckpointStore.tombstone_session``). Sessions with NO
        checkpoints emit the Sprint-8A baseline destroyed event without
        those keys (caller passes None defaults). Mirrors
        docker_sibling._emit_lifecycle_destroyed extension contract.
        """
        duration_s = (datetime.now(UTC) - session.created_at).total_seconds()
        payload: dict[str, Any] = {"duration_s": duration_s}
        if retained_until is not None:
            payload["retained_until"] = retained_until
        if tombstone_object_key is not None:
            payload["tombstone_object_key"] = tombstone_object_key
        await emit_sandbox_event(
            self._dh,
            event="sandbox.lifecycle.destroyed",
            tenant_id=session.tenant_id,
            actor_id=session._actor_subject,
            trace_id="",
            session_id=session.session_id,
            payload=payload,
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

    # ------------------------------------------------------------------
    # Sprint 8.5 T7 — checkpoint / suspend / restore mechanics
    # ------------------------------------------------------------------

    async def _do_checkpoint(
        self,
        session: KubernetesPodSession,
        label: str,
    ) -> CheckpointId:
        """Take a workspace-tar snapshot + persist + emit audit row.

        Spec §7.2 mechanic — ``kubernetes_asyncio`` pods/exec
        ``tar czf - -C /workspace .`` into the running Pod's sandbox
        container, capture the tar bytes from the STDOUT channel, hand
        to ``CheckpointStore.persist()``. ``label="__suspend__"`` is
        reserved for the suspend-time call from ``_do_suspend``.

        Q4 lock per spec §2.4 amended: ``vault_lease_refs=()`` always
        in Sprint 8.5 — vault-bearing sessions are unreachable via the
        existing 8A ``sandbox_credential_adapter_not_configured``
        admission-time refusal. Mirrors docker_sibling._do_checkpoint
        at docker_sibling.py:2148-2214.
        """
        if self._checkpoint_store is None:
            raise NotImplementedError(
                "KubernetesPodSession.checkpoint requires a CheckpointStore "
                "to be wired at backend construction time. Pass "
                "checkpoint_store=... to KubernetesPodSandboxBackend.__init__ "
                "per spec §3.1 + §7.2."
            )
        if session._suspended:
            # Spec §3.1: suspended sessions are no longer usable. The
            # Pod is also gone (suspend tore it down), so the exec
            # would also fail — surfacing fail-loud here gives a
            # better error.
            raise RuntimeError(
                f"session {session.session_id} was suspend()ed; "
                f"checkpoint() is no longer valid — call "
                f"SandboxBackend.wake(session_id) to restore the "
                f"session in a fresh Pod per spec §3.2"
            )

        snapshot_bytes = await self._create_workspace_tar_k8s(session=session)

        checkpoint_id = await self._checkpoint_store.persist(
            session_id=session.session_id,
            tenant_id=session.tenant_id,
            label=label,
            snapshot_bytes=snapshot_bytes,
            policy=session.policy,
            pack_context=session.pack_context,
            vault_lease_refs=(),
        )

        # policy_digest = sha256(canonical_bytes(policy_as_dict)).
        # Per spec §5.1 + audit.py docstring: a caller-supplied hash
        # of the persisted policy for the chain-verifier's cross-verify
        # against the admit_policy decision. The canonical dict shape
        # mirrors CheckpointMetadata.to_storage_payload's policy sub-
        # tree so the policy_digest on the checkpointed row matches
        # what a chain-verifier could re-compute from the persisted
        # metadata.
        policy_dict = self._policy_to_canonical_dict(session.policy)
        policy_digest = hashlib.sha256(canonical_bytes(policy_dict)).hexdigest()

        await sandbox_lifecycle_checkpointed(
            self._dh,
            tenant_id=session.tenant_id,
            actor_id=session._actor_subject,
            trace_id="",
            session_id=session.session_id,
            checkpoint_id=checkpoint_id,
            label=label,
            policy_digest=policy_digest,
        )
        return checkpoint_id

    async def _do_suspend(self, session: KubernetesPodSession) -> None:
        """Take final checkpoint + tear down + emit suspended + write
        wake linkage.

        Spec §3.1 + §7.2 + the T2 ``sandbox_lifecycle_suspended``
        helper contract: the suspended chain row is emitted **after**
        the container/Pod is released, so "suspended row exists" ⇒
        "runtime resources released" for examiners. Bank-grade
        evidence semantics require that the chain claim cannot
        over-state reality: a "suspended" row that fires while the
        Pod is still running OR before the linkage is durable would
        let chain readers infer state that does not yet hold.

        Ordering (P2.r2 reorder per the reviewer round that closed
        the audit-overstatement failure window):

            Step 1 — final checkpoint with label='__suspend__'.
            Step 2 — tear down Pod + NetworkPolicy.
                     **MUST succeed before the audit row is emitted.**
            Step 3 — emit sandbox.lifecycle.suspended; capture the
                     returned record_id UUID.
            Step 4 — write the suspend_event_id side-blob so wake()
                     can read the record_id back. A failure here
                     leaves the chain row in place + the side-blob
                     absent; subsequent wake() refuses with
                     sandbox_wake_checkpoint_corrupt per the P1.r6
                     parser-fail-closed contract.
            Step 5 — flip session._suspended (cosmetic; the in-process
                     state lock after the chain + filesystem state are
                     committed).

        Failure-window semantics (regressions pin all of these):

        * Step 2 fails (teardown raises): no audit row, no side-blob,
          session is observably alive. Caller retries or destroys.
        * Step 3 fails (audit emit raises): no chain row, no side-
          blob; Pod already torn down. The session is
          'phantom-released' from the chain's perspective — examiners
          see no suspended evidence. This is conservative (no false
          claim) but means a subsequent ``destroy()`` is needed to
          reconcile state via the destroyed row.
        * Step 4 fails (side-blob write raises): chain row exists,
          Pod released, wake-linkage missing. Wake refuses with
          ``sandbox_wake_checkpoint_corrupt`` (already pinned by
          ``test_wake_checkpoint_corrupt.py``); a subsequent
          ``destroy()`` tombstones normally.

        Vault-lease revocation is OUT OF SCOPE per spec §2.4 amended:
        the existing 8A ``sandbox_credential_adapter_not_configured``
        admission-time refusal prevents any vault-bearing session from
        existing in the first place. Mirrors docker_sibling._do_suspend
        at docker_sibling.py:2216-2331.
        """
        if self._checkpoint_store is None:
            raise NotImplementedError(
                "KubernetesPodSession.suspend requires a CheckpointStore "
                "to be wired at backend construction time."
            )
        if session._suspended:
            # Idempotent guard — a double-suspend on the same session is
            # a usage bug; surface fail-loud (NOT a no-op) so the caller
            # learns.
            raise RuntimeError(
                f"session {session.session_id} is already suspended; "
                f"call SandboxBackend.wake(session_id) to restore"
            )

        # Step 1 — final checkpoint with the reserved __suspend__ label.
        final_checkpoint_id = await self._do_checkpoint(session, "__suspend__")

        # Step 2 — tear down Pod + NetworkPolicy BEFORE the audit row
        # is emitted. Spec contract: "suspended row" ⇒ "resources
        # released". The audit-helper docstring at T2 explicitly says
        # this helper is called "after ... the container/Pod is
        # released" — reordering aligns code with contract.
        await self._teardown_session_state(
            pod_name=session._pod_name,
            network_policy_name=session._network_policy_name,
        )

        # Step 3 — emit sandbox.lifecycle.suspended; capture record_id
        # for the wake-time linkage payload key per spec §5.1. Audit
        # row is only emitted if teardown above succeeded; chain claim
        # therefore cannot over-state runtime state.
        record_id, _new_hash = await sandbox_lifecycle_suspended(
            self._dh,
            tenant_id=session.tenant_id,
            actor_id=session._actor_subject,
            trace_id="",
            session_id=session.session_id,
            final_checkpoint_id=final_checkpoint_id,
        )

        # Step 4 — write the suspend_event_id side-blob so wake() can
        # read the record_id back. Failure here leaves the chain row +
        # the side-blob absent: wake refuses
        # sandbox_wake_checkpoint_corrupt per the P1.r6 parser-fail-
        # closed contract pinned by ``test_wake_checkpoint_corrupt.py
        # ::TestSuspendEventIdSideBlobSurfacesAsCorrupt``.
        await self._write_suspend_event_id(
            session_id=session.session_id,
            tenant_id=session.tenant_id,
            checkpoint_id=final_checkpoint_id,
            record_id=record_id,
        )

        # Step 5 — flip the _suspended flag. Cosmetic now: both the
        # chain row + the side-blob are committed; the in-process
        # state lock prevents exec/checkpoint on the suspended
        # session. A failure HERE is effectively impossible (simple
        # attribute set), but ordering it last makes the invariant
        # "_suspended=True ⇒ everything before is durable" hold by
        # construction.
        session._suspended = True

    async def _create_workspace_tar_k8s(self, *, session: KubernetesPodSession) -> bytes:
        """Run ``tar czf - -C /workspace .`` inside the sandbox
        container via pods/exec; return the gzipped tar bytes from
        STDOUT.

        Per spec §7.2: the workspace-tar mechanic is the cross-backend
        wire-public contract — both DockerSibling AND KubernetesPod
        use the same tar/untar shape so cross-backend checkpoints
        round-trip via the conformance suite at T9.

        Uses the existing ``_open_pod_exec_stream`` (stdin=False) so
        the multiplexed-websocket channel handling stays in one
        place. STDOUT channel carries the tar bytes; STDERR channel
        carries any tar errors; ERROR channel surfaces exit code.
        Non-zero exit code → ``RuntimeError`` with stderr in the
        message.
        """
        stdout, stderr, exit_code = await self._open_pod_exec_stream(
            pod_name=session._pod_name,
            container_name=_SANDBOX_CONTAINER_NAME,
            command=["tar", "czf", "-", "-C", "/workspace", "."],
            walltime_s=session.policy.walltime_s,
        )
        if exit_code != 0:
            stderr_text = stderr.decode("utf-8", errors="replace")
            raise RuntimeError(
                f"tar czf /workspace inside session {session.session_id} "
                f"exited {exit_code}; stderr={stderr_text!r}"
            )
        return stdout

    async def _restore_workspace_tar(
        self,
        *,
        session_id: str,
        snapshot_bytes: bytes,
    ) -> None:
        """Restore the workspace tar inside the sandbox container via
        a known-length stdin consumption pattern — counterpart to
        :meth:`_create_workspace_tar_k8s`. Cross-backend conformance
        pin per spec §7.3.

        **Protocol-version note (load-bearing).** The kubernetes_asyncio
        websocket exec client negotiates ``v4.channel.k8s.io`` (hard-
        coded at ``kubernetes_asyncio.stream.ws_client.WsApiClient.request``
        line 101 of the installed package). The v4 subprotocol has
        STDIN / STDOUT / STDERR / ERROR / RESIZE channels but **no
        per-stream CLOSE frame** — that's v5 (``v5.channel.k8s.io``,
        close frame ``[0xFF, <stream_id>]``). We CANNOT signal stdin
        EOF to ``tar xzf -`` under v4; an empty-payload frame on
        channel 0 is just an empty data frame, NOT EOF. ``tar xzf -``
        would hang on stdin read until walltime expires.

        The fix is protocol-agnostic: wrap the restore in a shell
        pipeline that uses ``head -c <N>`` to consume exactly N bytes
        from stdin then exits naturally, piped directly into ``tar
        xzf -`` for extraction. When head exits after N bytes, the
        pipe to tar closes which gives tar clean stdin EOF; tar
        extracts to ``/workspace`` and exits; the remote ``sh -c``
        exits with tar's exit code; kubelet writes the ERROR-channel
        frame + closes the websocket.

        ``--strip-components=1`` is load-bearing on OpenShift
        ``emptyDir`` mounts: the checkpoint archive contains entries
        such as ``./marker.txt`` plus the ``.`` directory entry, but
        the arbitrary namespace UID cannot chmod/utime the mount root.
        Stripping the leading ``./`` component restores the contents
        beneath ``/workspace`` while skipping the root-directory entry
        entirely. ``--no-overwrite-dir`` is retained as an extra guard
        for pre-existing directories below the mount root. No stdin
        EOF signal required at the websocket layer + no temp file
        staged on disk.

        Command shape (wire-public; pinned by regression):
        ``["sh", "-c", f"head -c {N} | tar xzf -
        --strip-components=1 --no-overwrite-dir -C {workspace}"]``
        where ``N = len(snapshot_bytes)`` and ``workspace =
        _SANDBOX_WORKSPACE_PATH`` (``/workspace``). The pipeline
        eliminates the temp-file collision risk that an in-workspace
        staging path would carry (a malicious sandbox process could
        otherwise pre-create a file matching the restore tmp name to
        trip the next wake's extraction).

        ``/workspace`` is the ONLY writable surface required —
        provided by the emptyDir volume mount declared in
        :func:`_build_pod_spec` per the Sprint 8.5 T7 P1.3 writable-
        mount contract. The rest of the container filesystem stays
        read-only per ``readOnlyRootFilesystem=True``.

        The byte-count is the only int interpolated into the shell
        string — no shell metacharacter risk.

        Requires ``sh`` + ``head`` + ``tar`` in the canonical
        ``cognic/sandbox-runtime-*`` images per ADR-004 amendment §89.
        All three are in coreutils / busybox; tar is already required
        by :meth:`_create_workspace_tar_k8s`. POSIX-mandated pipe
        semantics ensure head's stdout-close gives tar stdin EOF —
        portable across every shell implementation the canonical
        runtime images ship.

        Pinned by ``test_restore_workspace_tar_uses_head_minus_c_known_length_pattern``
        + ``test_pod_spec_writable_workspace_mount_path_matches_restore_target``.
        """
        pod_name = _pod_name(session_id)
        tar_len = len(snapshot_bytes)
        shell_cmd = (
            f"head -c {tar_len} | tar xzf - --strip-components=1 "
            f"--no-overwrite-dir -C {_SANDBOX_WORKSPACE_PATH}"
        )
        restore_cmd = [
            "sh",
            "-c",
            shell_cmd,
        ]
        _stdout, stderr, exit_code = await self._open_pod_exec_stream_with_stdin(
            pod_name=pod_name,
            container_name=_SANDBOX_CONTAINER_NAME,
            command=restore_cmd,
            stdin_bytes=snapshot_bytes,
            walltime_s=None,
        )
        if exit_code != 0:
            stderr_text = stderr.decode("utf-8", errors="replace")
            raise RuntimeError(
                f"workspace tar restore inside session {session_id} "
                f"exited {exit_code}; stderr={stderr_text!r}"
            )

    async def _open_pod_exec_stream_with_stdin(
        self,
        *,
        pod_name: str,
        container_name: str,
        command: list[str],
        stdin_bytes: bytes,
        walltime_s: float | None,
    ) -> tuple[bytes, bytes, int]:
        """Open a ``pods/exec`` websocket stream with the STDIN channel
        allocated; pipe ``stdin_bytes`` on channel 0; consume STDOUT /
        STDERR / ERROR channels. Returns ``(stdout, stderr, exit_code)``.

        Sibling helper to :meth:`_open_pod_exec_stream` (which is
        STDIN-less). Splitting the two methods keeps the no-stdin
        cpu-stat + tar-czf + proxy-log paths fast + simple, while
        the tar-xzf restore path gets a dedicated stdin-bearing seam.

        Wire-protocol details:

        * STDIN_CHANNEL = 0 (per
          ``kubernetes_asyncio.stream.ws_client``). The stdin payload
          is sent as a SINGLE websocket frame prefixed with
          ``bytes([STDIN_CHANNEL])``.
        * **NO stdin-EOF signal is sent.** kubernetes_asyncio hard-
          codes ``v4.channel.k8s.io`` (line 101 of the installed
          package's ``ws_client.py``); the v4 subprotocol has no per-
          stream CLOSE frame (that's v5, encoded as
          ``[0xFF, <stream_id>]`` per the
          ``apimachinery/pkg/util/remotecommand/constants.go`` upstream
          definition). Sending ``bytes([STDIN_CHANNEL])`` standalone is
          a no-op empty-data frame under v4, NOT EOF. Callers MUST use
          a known-length consumption pattern (e.g. ``sh -c "head -c N
          > /tmp/x && ..."``) so the remote command exits naturally
          without needing stdin close. The ``_restore_workspace_tar``
          caller above wires this pattern.
        * We MUST NOT call ``ws.close()`` ourselves before consuming
          frames — aiohttp's ``ClientWebSocketResponse`` has no half-
          close, so an explicit ``ws.close()`` tears down both
          directions + terminates the iterator before the kubelet's
          ERROR-channel frame arrives. The original bug here defaulted
          ``exit_code`` to 0 on tar failure (silent green on restore);
          pinned by ``test_kubernetes_pod_exec_with_stdin.py``. Closing
          is the responsibility of the ``async with`` ``__aexit__``
          AFTER frame iteration naturally completes.
        * Defence-in-depth: if the iterator exits without ever
          delivering an ERROR-channel frame (e.g. kubelet bug, partial
          server-side write, stream truncation), ``exit_code`` is
          forced to ``-1`` so the caller's exit-zero green path cannot
          fire silently.
        * Stdin chunking: aiohttp's send_bytes accepts large bytes
          without internal chunking; the kubelet's websocket frames
          are bounded but the aiohttp client + server-side websocket
          frame splitter handle large bodies transparently. We send
          the entire stdin payload in a single call.

        Returns the same 3-tuple shape as :meth:`_open_pod_exec_stream`
        so the restore-path caller has uniform error handling.
        """
        ws_client_obj = WsApiClient(configuration=self._kube.configuration)
        try:
            ws_api = kube_client.CoreV1Api(ws_client_obj)
            stdout = bytearray()
            stderr = bytearray()
            exit_code = 0
            error_channel_seen = False

            async with asyncio.timeout(walltime_s):
                # _preload_content=False returns an
                # _WSRequestContextManager; async-with it to get the
                # live ClientWebSocketResponse. stdin=True is the
                # critical difference from _open_pod_exec_stream —
                # it tells kubelet to allocate the STDIN_CHANNEL.
                #
                # Typestub gaps mirror those in _open_pod_exec_stream:
                # ``command: str`` annotation but runtime accepts
                # ``list[str]``; ``str`` return at _preload_content=False
                # but runtime yields an _WSRequestContextManager.
                ws_ctx = ws_api.connect_get_namespaced_pod_exec(
                    pod_name,
                    self._namespace,
                    container=container_name,
                    command=command,  # type: ignore[arg-type]
                    stdin=True,
                    stdout=True,
                    stderr=True,
                    tty=False,
                    _preload_content=False,
                )
                async with await ws_ctx as ws:  # type: ignore[attr-defined]
                    # Write the entire stdin payload as a SINGLE
                    # websocket frame prefixed with the STDIN_CHANNEL
                    # byte. NO follow-up EOF marker is sent — the v4
                    # kubernetes exec subprotocol has no per-stream
                    # close (see docstring above). Callers wire a
                    # known-length consumption pattern (e.g. head -c N)
                    # so the remote command exits naturally without
                    # needing stdin EOF; ``_restore_workspace_tar``
                    # uses exactly this shape.
                    await ws.send_bytes(bytes([STDIN_CHANNEL]) + stdin_bytes)
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
                            error_channel_seen = True
                            try:
                                exit_code = WsApiClient.parse_error_data(
                                    bytes(payload).decode("utf-8")
                                )
                            except (
                                ValueError,
                                KeyError,
                                json.JSONDecodeError,
                            ):
                                exit_code = -1
                        # Ignore unknown channels (resize/etc).
            if not error_channel_seen:
                # Defence-in-depth: the iterator exited without
                # delivering an ERROR-channel frame. We cannot trust
                # exit_code=0 — force a non-green sentinel so the
                # caller's exit-zero green path cannot fire silently
                # (e.g. on a future regression that reintroduces a
                # close-before-read pattern, or on a kubelet that
                # truncates the stream).
                exit_code = -1
            return bytes(stdout), bytes(stderr), exit_code
        finally:
            with contextlib.suppress(Exception):
                await ws_client_obj.close()

    async def _wait_for_pod_ready(self, *, pod_name: str) -> None:
        """Poll the Pod's status until the sandbox container is ready,
        bounded by ``_POD_READY_TIMEOUT_S``.

        Sprint 8.5 T7 added this for wake()'s tar-restore exec stream;
        #477 live CRC proof extended the same readiness gate to cold
        create() because callers may immediately exec into a freshly
        returned session. Without the wait, pods/exec can race kubelet
        startup and fail with an HTTP 500 websocket handshake before
        the workload ever runs.

        Readiness contract: the sandbox container's
        ``ContainerStatus.ready == True``. Per K8s wire-contract that
        means the container has started + the readiness probe (if
        any) is passing. Sandbox containers ship without readiness
        probes (RestartPolicy=Never; no probe configured in
        _build_pod_spec), so ``ready`` is True as soon as the
        kubelet's container runtime reports "Running".

        Timeout → ``RuntimeError`` — the outer try/except in create()
        / wake() translates this to teardown + re-raise.

        Status read failures (ApiException) are treated as transient:
        keep polling until the timeout fires. A real, persistent
        apiserver failure surfaces as the timeout.
        """
        deadline = asyncio.get_event_loop().time() + _POD_READY_TIMEOUT_S
        api = kube_client.CoreV1Api(self._kube)
        last_status_repr = "unknown"
        while True:
            try:
                pod = await api.read_namespaced_pod_status(
                    name=pod_name,
                    namespace=self._namespace,
                )
            except kube_client.ApiException as e:
                last_status_repr = f"api_exception status={getattr(e, 'status', '?')}"
            else:
                # Pod object exists; check the sandbox container's status.
                statuses = getattr(pod.status, "container_statuses", None) or []
                for cs in statuses:
                    if cs.name != _SANDBOX_CONTAINER_NAME:
                        continue
                    if getattr(cs, "ready", False):
                        return
                    state = getattr(cs, "state", None)
                    last_status_repr = f"container_state={state!r}"
                    break
                else:
                    # No sandbox container in status yet — still pending.
                    last_status_repr = f"phase={getattr(pod.status, 'phase', '?')!r}"

            if asyncio.get_event_loop().time() >= deadline:
                raise RuntimeError(
                    f"pod {pod_name!r} did not become ready within "
                    f"{_POD_READY_TIMEOUT_S}s; last observed status="
                    f"{last_status_repr}"
                )
            await asyncio.sleep(_POD_READY_POLL_INTERVAL_S)

    async def _write_suspend_event_id(
        self,
        *,
        session_id: str,
        tenant_id: str,
        checkpoint_id: CheckpointId,
        record_id: _uuid.UUID,
    ) -> None:
        """Persist the suspend-emitted ``record_id`` so wake() can read
        it back at restore-time per spec §5.2 + the T7 plan.

        Storage layout — sibling blob at
        ``<tenant>/<session>/<checkpoint>.suspend_event_id`` carrying
        the UUID as a UTF-8 string. Stays in the same per-tenant prefix
        as the snapshot + metadata so tenant isolation comes for free +
        the existing reaper / tombstone lifecycle covers cleanup.
        Mirrors docker_sibling._write_suspend_event_id at
        docker_sibling.py:2411-2435 verbatim.
        """
        assert self._checkpoint_store is not None  # narrowed by callers
        key = f"{tenant_id}/{session_id}/{checkpoint_id}.suspend_event_id"
        await self._checkpoint_store._object_store.put(
            "sandbox-checkpoints",
            key,
            str(record_id).encode("utf-8"),
            retention_seconds=None,
        )

    async def _read_suspend_event_id(
        self,
        *,
        session_id: str,
        tenant_id: str,
        checkpoint_id: CheckpointId,
    ) -> _uuid.UUID:
        """Read back the suspend_event_id side-blob written at suspend()
        time.

        Missing or malformed bytes are part of the corrupt-checkpoint
        taxonomy. Wake maps ``_SuspendEventIdCorruptError`` to
        ``sandbox_wake_checkpoint_corrupt`` before restoring any K8s
        resources; the T8 chain-verifier keeps the same invariant as
        defence-in-depth, not as the first fail-closed seam. Mirrors
        docker_sibling._read_suspend_event_id at
        docker_sibling.py:2437-2470 verbatim.
        """
        assert self._checkpoint_store is not None  # narrowed by callers
        key = f"{tenant_id}/{session_id}/{checkpoint_id}.suspend_event_id"
        try:
            raw = await self._checkpoint_store._object_store.get("sandbox-checkpoints", key)
        except FileNotFoundError as exc:
            raise _SuspendEventIdCorruptError(
                f"missing suspend_event_id side-blob at {key!r}"
            ) from exc
        try:
            return _uuid.UUID(raw.decode("utf-8").strip())
        except UnicodeDecodeError as exc:
            raise _SuspendEventIdCorruptError(
                f"suspend_event_id side-blob at {key!r} is not UTF-8: {exc}"
            ) from exc
        except ValueError as exc:
            raise _SuspendEventIdCorruptError(
                f"suspend_event_id side-blob at {key!r} is not a UUID: {exc}"
            ) from exc

    @staticmethod
    def _policy_to_canonical_dict(policy: SandboxPolicy) -> dict[str, Any]:
        """Convert SandboxPolicy to a canonical-bytes-safe dict for
        policy_digest computation. Mirrors
        :meth:`DockerSiblingSandboxBackend._policy_to_canonical_dict`
        + the ``CheckpointMetadata.to_storage_payload`` policy sub-tree
        shape per spec §3.4 — drift between this dict + that one would
        mean the policy_digest on the checkpointed row would not match
        the policy_digest a chain-verifier could re-compute from the
        persisted metadata.
        """
        return {
            "cpu_cores": policy.cpu_cores,
            "cpu_time_budget_s": policy.cpu_time_budget_s,
            "memory_mb": policy.memory_mb,
            "walltime_s": policy.walltime_s,
            "runtime_image": policy.runtime_image,
            "egress_allow_list": list(policy.egress_allow_list),
            "vault_path": policy.vault_path,
            "read_only_root": policy.read_only_root,
            "writable_mounts": [
                {
                    "host_path": m.host_path,
                    "container_path": m.container_path,
                    "read_only": m.read_only,
                }
                for m in policy.writable_mounts
            ],
            "warm_pool_key": policy.warm_pool_key,
        }


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
    "_SuspendEventIdCorruptError",
    "_build_network_policy_spec",
    "_build_pod_spec",
    "_build_security_context",
    "_network_policy_name",
    "_pod_name",
]
