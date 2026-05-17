"""Sprint 8A T10 — DockerSiblingSandboxBackend.

Critical-controls module per spec §17.

Wave-1 dev/CI sandbox backend; Wave-1 production target is
``KubernetesPodSandboxBackend`` (Sprint 8B). Both conform to the
``SandboxBackend`` Protocol at :mod:`cognic_agentos.sandbox.protocol`.

Topology (per spec §10.1 + ADR-004 amendment §dual-container):

* Per-session **internal Docker network** with ``Internal=true``
  (no external gateway). The sandbox container is attached to this
  network ONLY — it has no direct external route. Raw TCP attempts
  to non-proxy destinations hit ``ENETUNREACH`` from the kernel.
* **Proxy sidecar container** attached to both the internal network
  AND a per-deployment egress network with external access. The
  sidecar runs the canonical ``cognic/sandbox-egress-proxy`` image
  (cosign-signed; T6 catalog gate; per
  ``feedback_canonical_artifact_not_oss_substitute`` the sidecar
  image is a REAL Sprint-8A artifact, never an OSS substitute).
* Sandbox container env: ``HTTP_PROXY`` /  ``HTTPS_PROXY`` point at
  the sidecar's deterministic DNS name on the internal network
  (``http://egress-proxy:8080``). ``NO_PROXY`` is intentionally NOT
  set — every outbound request MUST pass through the sidecar.

Sub-task split (T10 plan-of-record):

* **T10a** — lifecycle + dual-container topology (THIS COMMIT).
  ``create() / destroy() / health()`` Protocol surface; pure
  helpers for network / container naming + env build; in-process
  ``DockerSiblingSession`` dataclass.
* **T10b** — resource caps + cgroup integration (next).
  ``--memory + --memory-swap`` for OOM; AgentOS-side
  ``asyncio.wait_for`` walltime; cgroup ``cpuacct.usage_us`` reader
  + kill for ``cpu_time_budget_s``; image-pin validation.
* **T10c** — egress integration + conformance harness. Proxy
  sidecar lifecycle (full ALLOW_LIST + proxy_log materialisation);
  shared backend conformance suite.

``exec()`` raises ``NotImplementedError`` until T10b lands the
resource-cap monitoring + T10c lands the proxy_log materialisation.
T10a's responsibility is the lifecycle envelope; the exec body is
deferred to keep this commit's scope tight.

Aiodocker dep (sandbox-docker extra): the module imports
``aiodocker`` at module level; deployments that do not need the
Docker backend must NOT import this module. The package-level
re-export at :mod:`cognic_agentos.sandbox` wraps the import in a
try/except ImportError so the sandbox package itself stays
importable without the extra.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import uuid as _uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import aiodocker

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
    SandboxPolicyViolated,
    SandboxSession,
)
from cognic_agentos.sandbox.proxy import render_proxy_config

if TYPE_CHECKING:
    from cognic_agentos.core.audit import AuditStore
    from cognic_agentos.core.config import Settings
    from cognic_agentos.core.decision_history import DecisionHistoryStore
    from cognic_agentos.core.policy.engine import OPAEngine
    from cognic_agentos.portal.rbac.actor import Actor
    from cognic_agentos.sandbox.warm_pool import SandboxWarmPool


# ---------------------------------------------------------------------------
# Constants (network + sidecar conventions)
# ---------------------------------------------------------------------------

#: DNS name of the proxy sidecar on the per-session internal network.
#: Deterministic so the sandbox HTTP_PROXY env can resolve it without
#: passing the sidecar's container_id. The sidecar's container_name
#: (``{session_id}-proxy``) is distinct from this DNS alias — Docker's
#: built-in DNS resolves the alias to the sidecar's per-network IP.
_PROXY_DNS_NAME: str = "egress-proxy"

#: Port the proxy sidecar listens on inside the internal network.
#: Wire-contract: sidecar's Dockerfile EXPOSES this port + binds the
#: HTTP proxy on it. Sandbox HTTP_PROXY / HTTPS_PROXY env include this
#: port.
_PROXY_PORT: int = 8080

#: Non-root user:group spec-locked for both sandbox + proxy sidecar
#: containers per spec §7 + ADR-004 amendment ("never run as root
#: inside the sandbox"). 65534:65534 is the conventional nobody:nogroup
#: UID/GID on Debian / Alpine / distroless base images. Without
#: ``User`` set, Docker uses the image default user — commonly root
#: on stock images — which weakens the sandbox boundary even with
#: ``CapDrop:[ALL]`` + ``ReadonlyRootfs`` + ``no-new-privileges`` set.
#: Pinned by ``test_sandbox_and_sidecar_container_configs_run_as_nobody``.
_NON_ROOT_USER: str = "65534:65534"

#: Default cpu_period for the CpuQuota/CpuPeriod cgroup-cap pair
#: (T10b). 100ms is the kernel-recommended balance between
#: scheduling overhead + throttling responsiveness. Pinned as a
#: constant so any change is intentional + reviewable.
_CPU_PERIOD_US: int = 100_000

#: cpu_time_budget_s monitor poll interval (T10b). Per spec §7 item 4
#: ("polled at ≥1Hz"). 0.5s strikes a balance: tight enough to fire
#: within ~500ms of budget overage, loose enough to avoid stressing
#: the docker daemon's stats endpoint.
_CPU_BUDGET_POLL_INTERVAL_S: float = 0.5


# ---------------------------------------------------------------------------
# Pure-functional helpers (unit-tested at test_docker_sibling_pure_helpers.py)
# ---------------------------------------------------------------------------


def _internal_network_name(session_id: str) -> str:
    """Per-session internal Docker network name.

    Format: ``cognic-sb-internal-{session_id[:8]}-{8-char-hash}``.
    The 8-char hash of the full session_id disambiguates two sessions
    whose first 8 chars collide (UUIDs collide at the prefix in
    practice less often than 1-in-4-billion, but the hash suffix
    makes the property cheap + deterministic).

    Deterministic for the same session_id — idempotent network
    creation needs this so a retry after a transient docker-daemon
    failure does not orphan the previous network.

    Pinned by ``test_internal_network_name_carries_session_prefix``
    + ``test_internal_network_name_is_deterministic_for_same_session_id``
    + ``test_two_sessions_get_distinct_network_names`` at
    ``tests/unit/sandbox/backends/test_docker_sibling_pure_helpers.py``.
    """
    prefix = session_id[:8]
    suffix = hashlib.sha256(session_id.encode()).hexdigest()[:8]
    return f"cognic-sb-internal-{prefix}-{suffix}"


def _proxy_sidecar_container_name(session_id: str) -> str:
    """Per-session proxy sidecar container name.

    Format: ``{session_id}-proxy``. Pinned by spec §10.1 ASCII
    diagram + the env-gated lifecycle test's
    ``backend._docker.containers.get(f"{session.session_id}-proxy")``
    lookup.
    """
    return f"{session_id}-proxy"


def _sandbox_container_env(
    *,
    policy: SandboxPolicy,
    session_id: str,
    proxy_dns_name: str = _PROXY_DNS_NAME,
    proxy_port: int = _PROXY_PORT,
) -> dict[str, str]:
    """Env vars set on the sandbox container.

    ``HTTP_PROXY`` / ``HTTPS_PROXY`` point at the sidecar's
    deterministic DNS name on the internal network. ``NO_PROXY`` is
    intentionally NOT set — every outbound request MUST pass through
    the proxy (a NO_PROXY entry would create a bypass class the
    egress allow-list does not cover; spec §10.1 + §10.4
    raw-TCP-blocked-at-netns).

    ``policy`` + ``session_id`` are parameters today for future
    extension (T10b may add a SANDBOX_SESSION_ID env for the
    runtime image to log; T10c may add HTTP_PROXY auth tokens for
    sidecar-side correlation). Currently neither is materialised in
    the env so the helper's output is policy-independent.
    """
    proxy_url = f"http://{proxy_dns_name}:{proxy_port}"
    return {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
    }


def _derive_cpu_quota_period(cpu_cores: float) -> tuple[int, int]:
    """Translate ``policy.cpu_cores`` into Docker's CpuQuota/CpuPeriod
    cgroup-cap pair per spec §7 line 517.

    ``--cpus=N`` is equivalent to ``CpuQuota=N * CpuPeriod`` with a
    default ``CpuPeriod=100000`` microseconds (100ms). The kernel
    scheduler enforces the quota at the container's cgroup — a
    workload bursting past the quota in any 100ms window gets
    throttled (NOT killed; throttling is not a violation per
    round-3 P2 invariant).

    Returns:
        (CpuQuota_us, CpuPeriod_us) tuple as ints for direct
        assignment to Docker HostConfig.

    T10b helper — pure-functional + non-env-gated unit-testable.
    """
    period = _CPU_PERIOD_US
    # R1 P1.3 reviewer fix — clamp to >=1us. A tiny positive
    # cpu_cores (e.g. 0.000004) rounds to 0, and Docker treats
    # CpuQuota=0 as "no limit" (the default). Stage-1 only checks
    # cpu_cores > 0, so without this clamp a malformed policy
    # could pass admission and get UNTHROTTLED CPU. The minimum
    # 1us quota is essentially "tightest possible throttle" — far
    # below any realistic workload's needs but distinct from
    # Docker's no-quota default value.
    quota = max(1, round(cpu_cores * period))
    return quota, period


def _derive_memory_caps_bytes(memory_mb: int) -> tuple[int, int]:
    """Translate ``policy.memory_mb`` into Docker's Memory +
    MemorySwap cgroup-cap pair per spec §7 line 518.

    Setting ``MemorySwap == Memory`` tells Docker to NOT allocate any
    additional swap — the workload OOM-kills at the memory cap
    instead of paging to disk. Without this, a memory-cap-exceeded
    workload would page out + the OOM-killer path that fires
    ``memory_cap_exceeded`` would silently never trigger.

    Returns:
        (Memory_bytes, MemorySwap_bytes) tuple as ints for direct
        assignment to Docker HostConfig.

    T10b helper — pure-functional + non-env-gated unit-testable.
    """
    bytes_ = memory_mb * 1024 * 1024
    return bytes_, bytes_


def _classify_exec_failure(
    *,
    exit_code: int,
    oom_killed: bool,
    walltime_exceeded: bool,
    cpu_budget_exceeded: bool,
) -> str | None:
    """Pure-functional classifier — translate exec()'s observed
    end-state into a ``SandboxPolicyViolationReason`` or None.

    Precedence (highest first):
    1. ``walltime_exceeded`` → ``"walltime_cap_exceeded"`` — AgentOS
       killed the container; exit_code + oom_killed are cascade
       effects of the kill, NOT the cause.
    2. ``cpu_budget_exceeded`` → ``"cpu_time_budget_exceeded"`` —
       same cascade rationale; the cpu-budget kill takes precedence
       over OOM signals it caused.
    3. ``exit_code == 137 AND oom_killed`` → ``"memory_cap_exceeded"``
       — the kernel's oom_killer fired, NOT AgentOS. Exit 137 alone
       without ``oom_killed`` is NOT enough (could be manual SIGKILL
       from any source); the State.OOMKilled flag is authoritative.
    4. Otherwise → None (green-path; user-code exit code returned
       to the caller).

    T10b helper — pure-functional + non-env-gated unit-testable.
    The env-gated cap tests at
    ``tests/unit/sandbox/backends/test_docker_sibling_resource_caps.py``
    exercise the actual kernel enforcement.
    """
    if walltime_exceeded:
        return "walltime_cap_exceeded"
    if cpu_budget_exceeded:
        return "cpu_time_budget_exceeded"
    if exit_code == 137 and oom_killed:
        return "memory_cap_exceeded"
    return None


async def _kill_container_or_raise(container: Any) -> None:
    """Kill the container; succeed silently. Already-gone (Docker 404)
    is treated as benign (the cap effectively enforced — workload is
    not running). ANY other DockerError is propagated unchanged
    (fail-closed per R2 P1.1 reviewer fix: a cap-violation path that
    suppresses kill failure can pretend it enforced when it didn't).

    Callers: walltime + cpu-budget monitor paths in exec(). On
    propagated failure the cap-violation reason is NOT raised — the
    DockerError surfaces to the caller instead, so they know
    enforcement is unverified.
    """
    try:
        await container.kill(signal="SIGKILL")
    except aiodocker.exceptions.DockerError as e:
        if getattr(e, "status", None) == 404:
            return  # benign: container already gone
        raise  # real failure → fail-closed propagate


async def _cpu_time_budget_monitor(
    *,
    container: Any,
    budget_s: float,
    cpu_violated_event: asyncio.Event,
) -> None:
    """Background asyncio task — polls ``container.stats`` for the
    container's accumulated CPU usage at ``_CPU_BUDGET_POLL_INTERVAL_S``
    (≥1Hz per spec §7 item 4); when accumulated CPU-seconds exceed
    ``budget_s``, kills the container + sets ``cpu_violated_event``
    so exec()'s post-loop classification routes the failure to
    ``cpu_time_budget_exceeded``.

    Polls ``container.stats(stream=False)`` which returns the
    cumulative ``cpu_stats.cpu_usage.total_usage`` in nanoseconds.
    Docker's stats endpoint abstracts cgroup v1 vs v2 — the helper
    works identically on either kernel.

    Task is created by ``exec()`` ONLY when
    ``policy.cpu_time_budget_s`` is set (round-3 P2 invariant —
    without a budget, the cpu-budget violation is unreachable
    regardless of how much CPU the workload consumes).

    The task is cancelled by exec()'s finally block — handle
    ``asyncio.CancelledError`` cleanly by re-raising so the
    coroutine state unwinds. Any ``Exception`` raised during
    stats polling is swallowed (the monitor is best-effort; a
    transient stats-endpoint hiccup MUST NOT crash the in-flight
    exec).
    """
    budget_ns = int(budget_s * 1_000_000_000)
    while True:
        # R1 P1.4 reviewer fix — wrap BOTH the stats fetch AND the
        # snapshot shape-parsing in one try. Earlier ordering only
        # caught fetch exceptions; a malformed snapshot (e.g.
        # ``{"cpu_stats": None}`` from a partial docker response
        # or a version-change) raised AFTER the try block, killed
        # the monitor task silently, and the exec()'s finally
        # suppressed the task failure — leaving the CPU budget
        # UNENFORCED until walltime fired. Best-effort: continue
        # polling on malformed shapes; container.kill still fires
        # on the next valid snapshot that exceeds the budget.
        try:
            stats = await container.stats(stream=False)
            # aiodocker.containers.stats(stream=False) may return
            # a dict (single snapshot) or a list of one dict
            # (per aiodocker version). Tolerate both shapes.
            if isinstance(stats, list):
                stats = stats[0] if stats else {}
            if not isinstance(stats, dict):
                raise TypeError(f"stats must be dict; got {type(stats).__name__}")
            cpu_stats = stats.get("cpu_stats")
            if not isinstance(cpu_stats, dict):
                raise TypeError(f"cpu_stats must be dict; got {type(cpu_stats).__name__}")
            cpu_usage = cpu_stats.get("cpu_usage")
            if not isinstance(cpu_usage, dict):
                raise TypeError(f"cpu_usage must be dict; got {type(cpu_usage).__name__}")
            total_usage = cpu_usage.get("total_usage")
            if not isinstance(total_usage, int):
                raise TypeError(f"total_usage must be int; got {type(total_usage).__name__}")
            cpu_usage_ns = total_usage
        except asyncio.CancelledError:
            raise
        except Exception:
            # Best-effort: stats-endpoint hiccup OR malformed snapshot
            # MUST NOT crash the in-flight exec. Continue polling so
            # the budget check still fires on the next valid snapshot.
            await asyncio.sleep(_CPU_BUDGET_POLL_INTERVAL_S)
            continue

        if cpu_usage_ns >= budget_ns:
            # R2 P1.1 reviewer fix — kill BEFORE setting the event.
            # _kill_container_or_raise propagates real DockerError
            # (only 404/already-gone is benign). If kill fails, the
            # monitor task exits with the exception + the event is
            # NEVER set — so exec() does NOT raise cpu_time_budget_exceeded
            # while the workload may still be running. Walltime then
            # acts as the natural backstop.
            await _kill_container_or_raise(container)
            cpu_violated_event.set()
            return
        await asyncio.sleep(_CPU_BUDGET_POLL_INTERVAL_S)


def _build_sandbox_container_config(
    *,
    policy: SandboxPolicy,
    session_id: str,
    internal_net_name: str,
) -> dict[str, Any]:
    """Pure-functional container-config builder for the sandbox container.

    Extracted so non-env-gated unit tests can pin the config shape +
    security defaults (``User`` non-root per R1 P1.3, ``CapDrop``,
    ``ReadonlyRootfs``, ``no-new-privileges``) without a real Docker
    daemon. The backend's ``_start_sandbox_container`` consumes this
    + calls ``aiodocker.containers.create_or_replace`` with it.

    T10b extends the HostConfig with cgroup-cap kwargs:

    * ``Memory`` + ``MemorySwap`` — bytes; MemorySwap=Memory disables
      swap so memory-cap-exceeded workloads OOM-kill (instead of
      paging to disk and silently exceeding the cap).
    * ``CpuQuota`` + ``CpuPeriod`` — microseconds; kernel scheduler
      throttles past the quota (NOT a violation per round-3 P2).

    T10c does NOT modify the start-time config (proxy_log
    materialisation happens at exec-time).
    """
    sandbox_env = _sandbox_container_env(policy=policy, session_id=session_id)
    env_list = [f"{k}={v}" for k, v in sandbox_env.items()]
    cpu_quota, cpu_period = _derive_cpu_quota_period(policy.cpu_cores)
    memory_bytes, memory_swap_bytes = _derive_memory_caps_bytes(policy.memory_mb)
    return {
        "Image": policy.runtime_image,
        "Env": env_list,
        # Non-root per spec §7 + R1 P1.3 reviewer fix. Without User
        # set, Docker uses the image default user (commonly root)
        # which weakens the sandbox boundary even with CapDrop:[ALL].
        "User": _NON_ROOT_USER,
        "HostConfig": {
            "NetworkMode": internal_net_name,
            "AutoRemove": False,
            "ReadonlyRootfs": policy.read_only_root,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            # T10b cgroup caps.
            "Memory": memory_bytes,
            "MemorySwap": memory_swap_bytes,
            "CpuQuota": cpu_quota,
            "CpuPeriod": cpu_period,
        },
        "Labels": {
            "cognic.agentos.sandbox": "sandbox",
            "cognic.agentos.session_id": session_id,
        },
    }


def _build_proxy_sidecar_container_config(
    *,
    policy: SandboxPolicy,
    session_id: str,
    internal_net_name: str,
    proxy_image: str,
) -> dict[str, Any]:
    """Pure-functional container-config builder for the proxy sidecar.

    Same rationale as ``_build_sandbox_container_config`` — extracted
    so unit tests can pin the security defaults (``User`` non-root +
    ``CapDrop`` + ``ReadonlyRootfs`` + ``no-new-privileges``) +
    the DNS alias wiring (sandbox HTTP_PROXY env resolves
    ``egress-proxy`` via Docker's built-in DNS to the sidecar's
    per-network IP).
    """
    sidecar_env = _proxy_sidecar_env(policy=policy, session_id=session_id)
    env_list = [f"{k}={v}" for k, v in sidecar_env.items()]
    return {
        "Image": proxy_image,
        "Env": env_list,
        # Non-root per spec §7 + R1 P1.3 reviewer fix (same rationale
        # as sandbox container).
        "User": _NON_ROOT_USER,
        "HostConfig": {
            "NetworkMode": internal_net_name,
            "AutoRemove": False,
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
        },
        "NetworkingConfig": {
            "EndpointsConfig": {
                internal_net_name: {
                    # DNS alias the sandbox HTTP_PROXY env resolves —
                    # Docker's built-in DNS maps "egress-proxy" to the
                    # sidecar's per-network IP.
                    "Aliases": [_PROXY_DNS_NAME],
                },
            },
        },
        "Labels": {
            "cognic.agentos.sandbox": "proxy-sidecar",
            "cognic.agentos.session_id": session_id,
        },
    }


def _proxy_sidecar_env(
    *,
    policy: SandboxPolicy,
    session_id: str,
) -> dict[str, str]:
    """Env vars set on the proxy sidecar container.

    Composes T7's ``render_proxy_config(...).to_env()`` which returns
    ``{"ALLOW_LIST": json.dumps(list[host]), "SESSION_ID": session_id}``.
    The sidecar reads ALLOW_LIST at boot + builds its in-memory
    allow-list set; SESSION_ID is included on every proxy_log entry
    the sidecar emits so AgentOS can correlate proxy_log records
    with the SandboxPolicy that admitted the session.

    ``render_proxy_config`` ALSO runs T7's defence-in-depth Stage-1
    re-validation of every allow-list entry, so a future code path
    that bypassed admission could not smuggle a non-HTTP host
    through this helper to the sidecar.
    """
    config = render_proxy_config(
        egress_allow_list=policy.egress_allow_list,
        session_id=session_id,
    )
    return config.to_env()


# ---------------------------------------------------------------------------
# DockerSiblingSession — Protocol-conforming in-process value
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class DockerSiblingSession:
    """SandboxSession implementation for the Docker backend.

    The 6 fields required by the SandboxSession Protocol per spec
    §5 + the back-reference to the backend so ``exec()`` /
    ``destroy()`` can delegate + ``_actor_subject`` for audit-row
    attribution + ``_destroyed`` for emission-idempotency. Mutable
    (NOT frozen) because ``warm_pool_hit`` is set by the warm-pool
    checkout path AFTER construction, and ``_destroyed`` is set by
    the first destroy() to suppress repeat emission on the
    idempotent second-destroy path.

    NOT instantiated directly by callers — produced by
    ``DockerSiblingSandboxBackend.create()``.
    """

    session_id: str
    policy: SandboxPolicy
    tenant_id: str
    pack_context: PackAdmissionContext
    created_at: datetime
    warm_pool_hit: bool
    _backend: DockerSiblingSandboxBackend = field(repr=False)
    _internal_network_name: str = field(repr=False)
    _sidecar_container_name: str = field(repr=False)
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
# DockerSiblingSandboxBackend
# ---------------------------------------------------------------------------


class DockerSiblingSandboxBackend:
    """SandboxBackend implementation for sibling-on-host-socket Docker.

    Per AGENTS.md + ADR-004 amendment, this is the Wave-1 DEV/CI
    backend; the Wave-1 PROD backend is KubernetesPodSandboxBackend
    (Sprint 8B). Both conform to the same Protocol.

    ``exec()`` is intentionally NotImplementedError at T10a — the
    body lands at T10b (resource caps) + T10c (egress proxy_log
    materialisation). Calling ``exec()`` between T10a + T10b returns
    a structured error pointing at the unfinished sub-task.
    """

    def __init__(
        self,
        *,
        docker_client: aiodocker.Docker,
        image_catalog: CatalogProtocol,
        credential_adapter: CredentialAdapter,
        rego_engine: OPAEngine,
        audit_store: AuditStore,
        decision_history_store: DecisionHistoryStore,
        settings: Settings,
        warm_pool: SandboxWarmPool | None = None,
    ) -> None:
        self._docker = docker_client
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
        """Admit + create a sandbox session per spec §6.1.

        Step ordering:
        1. If ``use_warm_pool`` + ``self._warm_pool`` wired, attempt
           checkout; on hit, return + emit ``warm_pool.checked_out``
           + ``lifecycle.created(warm_pool_hit=True)``.
        2. Run ``admit_policy`` (Stage-1 + Stage-2; raises
           ``SandboxLifecycleRefused`` on any admission failure).
        3. Cold-create the dual-container topology (internal network
           + proxy sidecar + sandbox container).
        4. Emit ``lifecycle.created(warm_pool_hit=False)`` + return
           the ``DockerSiblingSession``.

        T10a scope: lifecycle + topology only. T10b adds cgroup-cap
        derivation to the container config; T10c adds the proxy
        sidecar's ALLOW_LIST + proxy_log seam.
        """
        # 1. Warm-pool checkout (if wired + caller asked for it)
        if use_warm_pool and self._warm_pool is not None:
            warm = await self._warm_pool.checkout(
                policy, tenant_id=tenant_id, pack_context=pack_context
            )
            if warm is not None:
                # Mark + emit lifecycle.created(warm_pool_hit=True);
                # the warm-pool's own audit seam already emitted the
                # sandbox.warm_pool.checked_out event. The two events
                # together form the warm-hit evidence pair per spec
                # §4.3 + spec §11 line 270-271 + R1 P1.1 reviewer fix.
                # Re-bind _actor_subject to the consumer's actor so a
                # later destroy() audits the CONSUMER who owned the
                # session lifetime (not the AgentOS service actor that
                # warmed it).
                if isinstance(warm, DockerSiblingSession):
                    warm.warm_pool_hit = True
                    warm._actor_subject = actor.subject
                # R2 P1.1 reviewer fix — wrap created-emission in a
                # cleanup envelope. Without it, an audit-append failure
                # after a successful warm checkout leaves the warm
                # session orphaned (caller never received it; pool
                # already emitted warm_pool.checked_out so it's marked
                # as taken). Fail-closed: destroy the session via
                # backend.destroy() (which itself emits
                # lifecycle.destroyed) and re-raise so the caller sees
                # the audit failure.
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

        # 2. Cold-create — admission first
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
        internal_net_name = _internal_network_name(session_id)
        sidecar_name = _proxy_sidecar_container_name(session_id)

        # 4. Build the dual-container topology
        await self._create_internal_network(internal_net_name)
        try:
            await self._start_proxy_sidecar(
                policy=policy,
                session_id=session_id,
                container_name=sidecar_name,
                internal_net_name=internal_net_name,
            )
            await self._start_sandbox_container(
                policy=policy,
                session_id=session_id,
                internal_net_name=internal_net_name,
            )
        except Exception:
            # Tear down anything we managed to create + re-raise.
            # Idempotent destroy methods make this safe even on
            # partial-create failures. No lifecycle.created emitted
            # because the session never reached a running state.
            await self._teardown_session_state(
                session_id=session_id,
                internal_net_name=internal_net_name,
                sidecar_name=sidecar_name,
            )
            raise

        session = DockerSiblingSession(
            session_id=session_id,
            policy=policy,
            tenant_id=tenant_id,
            pack_context=pack_context,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=self,
            _internal_network_name=internal_net_name,
            _sidecar_container_name=sidecar_name,
            _actor_subject=actor.subject,
        )
        # 5. Emit lifecycle.created(warm_pool_hit=False) per spec §4.3
        # + R1 P1.1 reviewer fix — cold-create path was previously
        # absent from the evidence chain, leaving successful sandbox
        # starts unauditable.
        #
        # R2 P1.1 — wrap in cleanup envelope. Without it, an
        # audit-append failure here would leave both containers + the
        # internal network running, and the caller would never
        # receive the session to clean up. Fail-closed: tear down the
        # whole session state + re-raise so the caller sees the audit
        # failure. We use _teardown_session_state directly (NOT
        # destroy()) because the session never reached the consumer
        # — no lifecycle.destroyed row should be emitted since no
        # lifecycle.created was ever successful.
        try:
            await self._emit_lifecycle_created(
                session=session,
                actor=actor,
                warm_pool_hit=False,
            )
        except Exception:
            with contextlib.suppress(Exception):
                await self._teardown_session_state(
                    session_id=session_id,
                    internal_net_name=internal_net_name,
                    sidecar_name=sidecar_name,
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

        T10b implementation:

        1. AgentOS-side walltime cap via ``asyncio.wait_for(...,
           timeout=walltime_s)``. Timeout → kill container + raise
           ``SandboxPolicyViolated(walltime_cap_exceeded)``.
        2. Background ``_cpu_time_budget_monitor`` task polls
           ``container.stats`` cpu_usage at ≥1Hz when
           ``policy.cpu_time_budget_s`` is set; on overage kills
           container + signals an asyncio.Event. exec() checks the
           event after the command completes.
        3. After exec completes, inspect container.show() for
           ``State.OOMKilled``. exit_code 137 + OOMKilled →
           ``SandboxPolicyViolated(memory_cap_exceeded)``.
        4. Pure ``_classify_exec_failure`` decides precedence
           (walltime > cpu_budget > OOM > green).

        ``proxy_log`` is empty () at T10b — T10c materialises it
        from the proxy sidecar's per-request audit log.

        Throttling under ``policy.cpu_cores`` cap is NOT a violation
        per round-3 P2 invariant: the kernel scheduler may slow a
        CPU-bound workload, but only ``cpu_time_budget_exceeded``
        (when a budget is set) raises ``SandboxPolicyViolated``.
        """
        if not isinstance(session, DockerSiblingSession):
            raise TypeError(
                f"DockerSiblingSandboxBackend.exec expects "
                f"DockerSiblingSession; got {type(session).__name__}"
            )

        walltime = timeout_s if timeout_s is not None else session.policy.walltime_s
        container = await self._docker.containers.get(session.session_id)

        # Background cpu-budget monitor — only spawned when policy
        # carries a budget. The monitor sets cpu_violated_event when
        # it observes the cgroup-stats cpu_usage exceed the budget +
        # kills the container so the in-flight exec returns.
        cpu_violated_event = asyncio.Event()
        monitor_task: asyncio.Task[None] | None = None
        if session.policy.cpu_time_budget_s is not None:
            monitor_task = asyncio.create_task(
                _cpu_time_budget_monitor(
                    container=container,
                    budget_s=session.policy.cpu_time_budget_s,
                    cpu_violated_event=cpu_violated_event,
                )
            )

        # ``body_raised`` — track whether the try block below raises.
        # Used by the finally block to decide whether to propagate a
        # monitor-task failure (R3 P1): if exec body completed
        # successfully but the monitor failed, the monitor exception
        # MUST surface so the caller knows cap enforcement was
        # unverified. If exec body already raised, the in-flight
        # exception wins and the monitor failure is dropped (no
        # ExceptionGroup at this layer).
        body_raised = False
        walltime_exceeded = False
        stdout, stderr = b"", b""
        # R1 P1.2 reviewer fix — explicit user= on exec(). The
        # container starts non-root (User=_NON_ROOT_USER on the
        # container config per R1 P1.3 from T10a), but
        # aiodocker.DockerContainer.exec defaults user="" which
        # Docker treats as "image default" (commonly root). Without
        # this kwarg, the pack command would run as root inside an
        # otherwise non-root container.
        # R1 P1.2 reviewer fix — explicit user= on exec(). The
        # container starts non-root (User=_NON_ROOT_USER on the
        # container config per R1 P1.3 from T10a), but
        # aiodocker.DockerContainer.exec defaults user="" which
        # Docker treats as "image default" (commonly root). Without
        # this kwarg, the pack command would run as root inside an
        # otherwise non-root container.
        exec_obj = await container.exec(
            cmd=command,
            stdout=True,
            stderr=True,
            user=_NON_ROOT_USER,
        )
        try:
            try:
                async with asyncio.timeout(walltime):
                    # R1 P1.1 reviewer fix — aiodocker's Stream is NOT
                    # async-iterable; consume via ``read_out()`` which
                    # returns ``Message | None`` (None signals end of
                    # stream). Each Message carries ``.stream`` (1
                    # for stdout, 2 for stderr per the Docker exec
                    # multiplexed wire format) + ``.data`` (bytes).
                    #
                    # R2 P2 reviewer fix — wrap the Stream in
                    # ``async with`` so its underlying websocket /
                    # HTTP response is closed on EVERY exit path
                    # (clean end-of-stream, walltime timeout,
                    # read_out exception, monitor-triggered kill).
                    # Without the context manager the connection
                    # leaked on timeout/error paths.
                    async with exec_obj.start(detach=False) as stream:
                        while True:
                            message = await stream.read_out()
                            if message is None:
                                break
                            if message.stream == 1:
                                stdout += message.data
                            elif message.stream == 2:
                                stderr += message.data
            except TimeoutError:
                # R2 P1.1 reviewer fix — _kill_container_or_raise
                # propagates real DockerError (only 404/already-gone is
                # benign). If kill fails, the DockerError propagates
                # instead of walltime_cap_exceeded — caller knows
                # enforcement is unverified.
                await _kill_container_or_raise(container)
                walltime_exceeded = True

            inspect = await exec_obj.inspect()
            exit_code = int(inspect.get("ExitCode") or 0)

            # Read container attrs to detect OOM-kill. State.OOMKilled
            # is the authoritative kernel signal; exit 137 alone is
            # not enough (could be manual SIGKILL).
            info = await container.show()
            oom_killed = bool(info.get("State", {}).get("OOMKilled", False))
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
                # R1 P1.5 + R2 P1.2 reviewer fixes — emit
                # ``sandbox.policy.violated`` before raising so the
                # cap kill gets a chain row. Without this, cap kills
                # happen in production with NO audit trail. Per spec
                # §4.3 + §12 wire-public taxonomy.
                #
                # R2 P1.2 removed the ``contextlib.suppress(Exception)``
                # the earlier R1 fix had: a transient audit-store
                # outage MUST fail-closed (NOT silently drop the
                # evidence row), otherwise the whole point of the
                # P1.5 fix is defeated. If the audit append raises,
                # the caller sees that exception instead of
                # SandboxPolicyViolated — they should treat an
                # audit-store outage as a CC failure that supersedes
                # the cap reason.
                await self._emit_policy_violated(
                    session=session,
                    reason=reason,
                )
                raise SandboxPolicyViolated(reason, detail=detail)  # type: ignore[arg-type]

            return SandboxExecResult(
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                proxy_log=(),  # T10c materialises this from the sidecar
            )
        except BaseException:
            # Capture that the body raised so the finally below can
            # decide monitor-failure propagation. Re-raise so the
            # exception unwinds normally.
            body_raised = True
            raise
        finally:
            # R3 P1 reviewer fix — propagate monitor task failures
            # when the exec body completed successfully. The earlier
            # ``contextlib.suppress(BaseException)`` silenced ALL
            # monitor exceptions, which meant a CPU-budget kill that
            # failed (DockerError 500) followed by a natural workload
            # exit returned a green SandboxExecResult with NO
            # policy.violated row — cap UNENFORCED + no audit trail.
            #
            # The contract:
            # * Cancel the monitor (it's a daemon task; we always
            #   want it stopped when exec returns).
            # * Await it: ``CancelledError`` is expected (we just
            #   cancelled it on the green path); swallow.
            # * Any OTHER exception from the monitor means the kill
            #   failed → enforcement unverified. If the exec body
            #   completed successfully, propagate the monitor
            #   exception so the caller knows. If the exec body
            #   already raised (walltime / OOM / other), the in-flight
            #   exception wins (caller already has a bigger problem)
            #   and the monitor exception is dropped — there's no
            #   way to surface both without ExceptionGroup.
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
        """Tear down session + all associated docker objects.

        Idempotent per spec §5 ``SandboxBackend.destroy`` docstring.
        Calls the same _teardown_session_state helper that the
        create() cleanup path uses on partial-create failure.

        Emits ``sandbox.lifecycle.destroyed`` per spec §4.3 + R1 P1.2
        reviewer fix — without it, the start/stop evidence pair was
        asymmetric and session lifetime was unauditable.
        Emission-idempotency: ``session._destroyed`` flag is set on
        the first call so a second ``destroy()`` (idempotent contract)
        does NOT emit a second chain row.
        """
        # Pull the docker-specific fields off the session — only
        # DockerSiblingSession carries them; cross-backend session
        # objects would not have them, but cross-backend destroy is
        # an error the Protocol does not require us to handle.
        if not isinstance(session, DockerSiblingSession):
            raise TypeError(
                f"DockerSiblingSandboxBackend.destroy expects "
                f"DockerSiblingSession; got {type(session).__name__}"
            )

        already_destroyed = session._destroyed
        await self._teardown_session_state(
            session_id=session.session_id,
            internal_net_name=session._internal_network_name,
            sidecar_name=session._sidecar_container_name,
        )
        if not already_destroyed:
            # R2 P1.2 reviewer fix — emit BEFORE setting the flag, so
            # a transient audit-append failure leaves ``_destroyed``
            # False and a retry destroy() will retry the emission.
            # Earlier ordering set the flag first and lost the
            # destroyed row permanently on any audit failure.
            # The retry contract is intentional: docker teardown is
            # idempotent (the _teardown_session_state helper swallows
            # "not found" DockerError) so calling destroy() twice
            # after a transient emit failure is safe.
            await self._emit_lifecycle_destroyed(session=session)
            session._destroyed = True

    async def health(self) -> SandboxBackendHealth:
        """Backend readiness check — pings the docker daemon.

        Returns ``ok`` if ``aiodocker.Docker.system.info()`` returns
        without error; ``unavailable`` on any exception.
        """
        try:
            await self._docker.system.info()
        except Exception as e:
            return SandboxBackendHealth(
                status="unavailable",
                detail=f"docker daemon unreachable: {e}",
            )
        return SandboxBackendHealth(status="ok")

    # ------------------------------------------------------------------
    # Internal — dual-container topology builders
    # ------------------------------------------------------------------

    async def _create_internal_network(self, name: str) -> None:
        """Create the per-session internal Docker network.

        ``Internal=true`` is the load-bearing flag: it tells Docker
        the network has no external gateway. Containers on this
        network can talk to each other (sandbox ↔ proxy sidecar)
        but cannot reach the host network or external IPs directly.
        Raw TCP attempts to non-proxy destinations from the sandbox
        will hit ``ENETUNREACH`` from the kernel (spec §10.4
        raw-TCP-blocked-at-netns).
        """
        await self._docker.networks.create(
            {
                "Name": name,
                "Driver": "bridge",
                "Internal": True,
                "Labels": {
                    "cognic.agentos.sandbox": "internal",
                },
            }
        )

    async def _start_proxy_sidecar(
        self,
        *,
        policy: SandboxPolicy,
        session_id: str,
        container_name: str,
        internal_net_name: str,
    ) -> None:
        """Start the proxy sidecar container on the internal network.

        T10a wires the container start with the T7 ``EgressProxyConfig``
        env (ALLOW_LIST + SESSION_ID). T10c will extend this with the
        per-deployment egress network attachment (so the sidecar can
        reach external hosts) + the proxy_log read on session exit.

        T10a-scope simplification: sidecar runs on the internal network
        only at T10a. The egress-network attachment is T10c — at T10a
        the sidecar can't actually proxy outbound traffic, but the
        topology + env wiring + container lifecycle are all in place.
        """
        # The canonical proxy image — Sprint 8A T6 catalog gate
        # publishes the cosign-signed digest. The image name here is
        # the canonical name; the catalog verifies the digest at
        # admission time (admit_policy step 6-8). Per
        # feedback_canonical_artifact_not_oss_substitute, this is the
        # real cognic/sandbox-egress-proxy artifact — not an OSS
        # substitute.
        proxy_image = "cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64

        config = _build_proxy_sidecar_container_config(
            policy=policy,
            session_id=session_id,
            internal_net_name=internal_net_name,
            proxy_image=proxy_image,
        )
        container = await self._docker.containers.create_or_replace(
            name=container_name,
            config=config,
        )
        await container.start()

    async def _start_sandbox_container(
        self,
        *,
        policy: SandboxPolicy,
        session_id: str,
        internal_net_name: str,
    ) -> None:
        """Start the sandbox container on the internal network only.

        T10a-scope: lifecycle + topology only. T10b will extend the
        container config with cgroup caps (memory, cpu, walltime
        machinery). T10c does not modify this method — proxy_log
        materialisation happens at exec-time, not start-time.
        """
        config = _build_sandbox_container_config(
            policy=policy,
            session_id=session_id,
            internal_net_name=internal_net_name,
        )
        container = await self._docker.containers.create_or_replace(
            name=session_id,
            config=config,
        )
        await container.start()

    async def _teardown_session_state(
        self,
        *,
        session_id: str,
        internal_net_name: str,
        sidecar_name: str,
    ) -> None:
        """Best-effort idempotent teardown of all docker objects.

        Each step swallows ``aiodocker.exceptions.DockerError`` so the
        teardown completes even if some objects were never created
        (partial-create failure path) OR have already been removed
        (double-destroy path).

        Order: sandbox container → sidecar container → internal
        network. Reverses the create order so dependencies are
        removed before the things they depend on (the network cannot
        be removed while containers are still attached).
        """
        await self._destroy_container_if_exists(session_id)
        await self._destroy_container_if_exists(sidecar_name)
        await self._destroy_network_if_exists(internal_net_name)

    async def _destroy_container_if_exists(self, name: str) -> None:
        """Stop + remove a container by name; swallow DockerError
        on not-found / already-removed."""
        try:
            container = await self._docker.containers.get(name)
        except aiodocker.exceptions.DockerError:
            return
        with contextlib.suppress(aiodocker.exceptions.DockerError):
            await container.stop()
        with contextlib.suppress(aiodocker.exceptions.DockerError):
            await container.delete(force=True)

    async def _destroy_network_if_exists(self, name: str) -> None:
        """Remove a network by name; swallow DockerError on not-found."""
        try:
            network = await self._docker.networks.get(name)
        except aiodocker.exceptions.DockerError:
            return
        with contextlib.suppress(aiodocker.exceptions.DockerError):
            await network.delete()

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
        """Emit ``sandbox.lifecycle.created`` per spec §4.3 wire-public
        payload ``{warm_pool_hit: bool}`` + R1 P1.1 reviewer fix.

        Fires on BOTH warm-hit and cold-create paths so the evidence
        chain has a successful-start row for every sandbox session.
        Warm-hit pairs this event with the warm-pool's own
        ``sandbox.warm_pool.checked_out`` row (the pool emitted that
        one); cold-create only emits this one.

        ``trace_id`` is empty at T10a — request-bound trace_id wiring
        is a T10c+ concern (the Sandbox Protocol's create signature
        does not take a trace_id). Future sprints may extend
        SandboxBackend.create to thread the caller's trace_id; the
        chain row's ``trace_id`` column is then populated by this
        helper.
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

    async def _emit_policy_violated(
        self,
        *,
        session: DockerSiblingSession,
        reason: str,
    ) -> None:
        """Emit ``sandbox.policy.violated`` per spec §4.3 wire-public
        payload ``{reason: SandboxPolicyViolationReason}`` + R1 P1.5
        reviewer fix.

        Fired BEFORE ``exec()`` raises ``SandboxPolicyViolated`` on
        any cap-violation path (memory_cap_exceeded /
        walltime_cap_exceeded / cpu_time_budget_exceeded). Without
        this row, cap kills happen in production with NO audit trail
        and the evidence pack misses the wire-protocol-public event.

        ``actor_id`` carries ``session._actor_subject`` (the consumer
        who initiated the exec). ``trace_id`` is empty per the same
        deferred-trace rationale documented at
        ``_emit_lifecycle_created``.
        """
        await emit_sandbox_event(
            self._dh,
            event="sandbox.policy.violated",
            tenant_id=session.tenant_id,
            actor_id=session._actor_subject,
            trace_id="",
            session_id=session.session_id,
            payload={"reason": reason},
        )

    async def _emit_lifecycle_destroyed(
        self,
        *,
        session: DockerSiblingSession,
    ) -> None:
        """Emit ``sandbox.lifecycle.destroyed`` per spec §4.3 wire-public
        payload ``{duration_s: float}`` + R1 P1.2 reviewer fix.

        ``duration_s`` is computed from
        ``datetime.now(UTC) - session.created_at`` so examiners can
        audit session lifetime. The destroy() caller-side idempotency
        flag (``session._destroyed``) ensures repeat destroy() calls
        do NOT emit a second row.

        ``actor_id`` carries ``session._actor_subject`` from the
        original create() call (the caller who owns the session
        lifetime). ``trace_id`` is empty at T10a per the same
        T10c+ deferred rationale documented at
        ``_emit_lifecycle_created``.
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
# this module (test files that import it via the docker_sibling module
# get the same object as the protocol module).
__all__ = [
    "_CPU_BUDGET_POLL_INTERVAL_S",
    "_CPU_PERIOD_US",
    "_NON_ROOT_USER",
    "_PROXY_DNS_NAME",
    "_PROXY_PORT",
    "DockerSiblingSandboxBackend",
    "DockerSiblingSession",
    "SandboxLifecycleRefused",
    "_build_proxy_sidecar_container_config",
    "_build_sandbox_container_config",
    "_classify_exec_failure",
    "_cpu_time_budget_monitor",
    "_derive_cpu_quota_period",
    "_derive_memory_caps_bytes",
    "_internal_network_name",
    "_kill_container_or_raise",
    "_proxy_sidecar_container_name",
    "_proxy_sidecar_env",
    "_sandbox_container_env",
]
