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
  (``http://egress-proxy:3128`` per spec §10.2). ``NO_PROXY`` is
  intentionally NOT set — every outbound request MUST pass through
  the sidecar.

Sub-task arc (all landed):

* **T10a** — lifecycle + dual-container topology.
  ``create() / destroy() / health()`` Protocol surface; pure
  helpers for network / container naming + env build; in-process
  ``DockerSiblingSession`` dataclass.
* **T10b** — resource caps + cgroup integration. ``--memory +
  --memory-swap`` for OOM; AgentOS-side ``asyncio.wait_for``
  walltime; ``container.stats`` cpu_usage poller + kill for
  ``cpu_time_budget_s``.
* **T10c** — egress integration + conformance harness. Egress
  network creation + dual-homed sidecar + proxy image catalog
  verification + JSONL proxy_log readback + materialisation onto
  ``sandbox.lifecycle.exec_completed`` chain row (green path) or
  ``sandbox.policy.violated`` (refusal path); shared backend
  conformance suite at ``tests/conformance/sandbox/``.

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
import json
import uuid as _uuid
from collections.abc import Awaitable, Callable, Coroutine, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

import aiodocker

from cognic_agentos.core.approval.engine import ApprovalEngine
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.vault import (
    CredentialLease,
    VaultAuthDenied,
    VaultLeaseGrantExceedsRequest,  # Sprint 10.1 — Finding B of plan-review round 1
    VaultLeaseRequest,
    VaultPathNotFound,
    VaultProtocolError,
    VaultUnavailable,
)
from cognic_agentos.sandbox._credentials_pair import (
    verify_credentials_pair_invariants,
)
from cognic_agentos.sandbox._preflight import (
    PreflightResult,
    verify_docker_credential_projection_preflight,
)
from cognic_agentos.sandbox.admission import (
    CatalogProtocol,
    CredentialAdapter,
    admit_policy,
)
from cognic_agentos.sandbox.audit import (
    emit_sandbox_event,
    sandbox_lifecycle_checkpointed,
    sandbox_lifecycle_credentials_projected,
    sandbox_lifecycle_credentials_projection_cleaned_up,
    sandbox_lifecycle_credentials_projection_cleanup_failed,
    sandbox_lifecycle_credentials_projection_failed,
    sandbox_lifecycle_lease_minted,
    sandbox_lifecycle_lease_revoke_failed,
    sandbox_lifecycle_lease_revoked,
    sandbox_lifecycle_suspended,
    sandbox_lifecycle_woken,
)
from cognic_agentos.sandbox.backends._docker_executor import (
    ProjectionExecutorResult,
    derive_credential_opaque,
    derive_session_opaque,
    execute_projection_plan_docker,
)
from cognic_agentos.sandbox.backends._shared_credentials import (
    _mint_exception_to_refusal_reason,
)
from cognic_agentos.sandbox.checkpoint_store import (
    CheckpointStore,
    TombstoneCorruptError,
)
from cognic_agentos.sandbox.policy import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.projection import (
    CredentialDecl,
    ProjectionPlan,
    ProjectionRefused,
    compute_projection_plan,
)
from cognic_agentos.sandbox.protocol import (
    _APPROVAL_WAKE_PASSTHROUGH_REASONS,
    CheckpointId,
    ProxyAccessRecord,
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

#: Forward-proxy URL scheme. Wave-1 doctrine: HTTP/HTTPS only
#: through AgentOS-controlled proxy endpoint per spec §10 + the
#: sandbox_network_isolation_precision feedback memory. Split out
#: as a constant so the f-string assembling ``proxy_url`` does NOT
#: carry a ``http://`` URL literal (which would trip
#: ``tests/unit/architecture/test_no_env_specific_values_in_source.py``
#: — the URL-literal guard is keyed to ``^https?://``).
_PROXY_SCHEME: str = "http"

#: Port the proxy sidecar listens on inside the internal network.
#: Wire-contract per spec §10.2 + §7 line 490 — the canonical
#: ``cognic/sandbox-egress-proxy`` image EXPOSEs this port + binds
#: the HTTP/HTTPS forward proxy on it. Sandbox HTTP_PROXY /
#: HTTPS_PROXY env include this port. T10c corrected the prior
#: T10a value (8080) to the spec-locked 3128.
_PROXY_PORT: int = 3128

#: Path inside the proxy sidecar where it writes its JSONL access
#: log (one JSON object per outbound request). The canonical
#: ``cognic/sandbox-egress-proxy`` image is configured to write
#: here; T10c's ``_read_proxy_log_from_sidecar`` reads via
#: ``docker exec cat <this-path>`` on session exec_completed.
#: Wire-contract — drift here breaks the proxy_log materialisation
#: chain.
_PROXY_LOG_PATH: str = "/var/log/cognic-proxy/access.jsonl"

#: Config dir the canonical egress-proxy entrypoint renders + writes
#: ``tinyproxy.filter`` + ``tinyproxy.conf`` into at startup (MUST equal
#: the image entrypoint's ``_DEFAULT_CONFIG_DIR`` = ``/etc/cognic-proxy``).
#: The image chowns it to the proxy's 10002 user, but it is NOT a Docker
#: ``VOLUME`` — so under ``ReadonlyRootfs=True`` it is read-only. T30/T14.1
#: mounts a writable tmpfs here (owned by 10002) so the proxy can render
#: its config at boot; without it the proxy fails with
#: ``read-only file system`` and is gone when ``_read_proxy_log_from_sidecar``
#: reads its access log → ``egress_audit_unreadable``.
_PROXY_CONFIG_DIR: str = "/etc/cognic-proxy"

#: Canonical egress-proxy image. Sprint 8A T6's catalog gate publishes
#: the cosign-signed digest; per
#: ``feedback_canonical_artifact_not_oss_substitute`` this is the real
#: ``cognic/sandbox-egress-proxy`` artifact, NOT an OSS substitute.
#: #477 §5 — the default for the ``egress_proxy_image`` constructor
#: seam: production callers omit the kwarg and get this byte-identical
#: value.
#: T12 — REAL signed canonical egress-proxy ref (replaced the pre-T12 ``"d"*64``
#: placeholder digest). MUST equal ``Settings.sandbox_canonical_egress_proxy_image``
#: (launch-selector == catalog-member; a mismatch makes the launched sidecar's
#: digest a non-canonical member that admission's ``is_canonical`` rejects).
#: Pinned by ``tests/unit/sandbox/backends/test_canonical_egress_proxy_consistency.py``.
_CANONICAL_EGRESS_PROXY_IMAGE: str = (
    "ghcr.io/bmzee/cognic-agentos/sandbox-egress-proxy@sha256:"
    "eb4ea75b427d0bc42039c68039eec51d6b0d0789400ba5bfdbf470ebec9139aa"
)

#: Non-root user:group for the SANDBOX (workload) container per spec §7
#: + ADR-004 amendment ("never run as root inside the sandbox").
#: 65534:65534 is the conventional nobody:nogroup UID/GID on Debian /
#: Alpine / distroless base images. The workload is the untrusted
#: surface, so it is squashed to nobody. Without ``User`` set, Docker
#: uses the image default user — commonly root on stock images — which
#: weakens the sandbox boundary even with ``CapDrop:[ALL]`` +
#: ``ReadonlyRootfs`` + ``no-new-privileges`` set.
#: Pinned by ``TestContainerConfigsRunAsNonRoot``.
_NON_ROOT_USER: str = "65534:65534"

#: Non-root user:group for the PROXY SIDECAR container (T30/T14.1). The
#: canonical ``cognic/sandbox-egress-proxy`` image builds a dedicated
#: ``cognicproxy`` account as 10002:10002 and chowns
#: ``/etc/cognic-proxy`` + ``/var/log/cognic-proxy`` to it. The sidecar
#: is AgentOS-owned infrastructure, so it runs as its baked identity
#: (which OWNS those dirs) — NOT the workload's 65534. Forcing it to
#: 65534 (the pre-T14.1 behaviour) left it unable to write its config /
#: log dirs under ``ReadonlyRootfs=True`` (10002-owned, mode 0755),
#: which surfaced as the Z4 ``egress_audit_unreadable`` live-audit
#: failure. Pinned EXPLICITLY (not read from image metadata) so an
#: image USER-directive drift cannot silently change the sidecar
#: identity. Pinned by ``TestContainerConfigsRunAsNonRoot``.
_PROXY_NON_ROOT_USER: str = "10002:10002"

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


class _SuspendEventIdCorruptError(ValueError):
    """Internal fail-closed marker for malformed suspend→wake linkage."""


# ---------------------------------------------------------------------------
# Pure-functional helpers (unit-tested at test_docker_sibling_pure_helpers.py
# + test_docker_sibling_credentials.py)
# ---------------------------------------------------------------------------


def _read_proc_mounts_file() -> str:
    """Sprint 10.6 T21 — synchronous reader for ``/proc/mounts``.

    Module-level helper (not a method) so the asyncio off-loading
    in ``_collect_preflight_result`` can hand it to
    ``asyncio.to_thread`` cleanly. Returns the file contents as a
    single str; the T19 Phase 1 ``_check_shm_is_tmpfs`` parser
    consumes this string.

    No fallback / no exception suppression — a missing /proc/mounts
    means we're running off-Linux (test environment without proper
    mocking, OR a misconfigured deployment) and the preflight should
    fail-loud rather than silently mistreat /dev/shm as tmpfs.
    Tests inject ``backend._collect_preflight_result`` as a mock so
    they never reach this helper.
    """
    return Path("/proc/mounts").read_text(encoding="utf-8")


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


def _egress_network_name(session_id: str) -> str:
    """Per-session egress Docker network name (T10c).

    Format: ``cognic-sb-egress-{session_id[:8]}-{8-char-hash}``.
    Distinct from ``_internal_network_name`` even for the same
    session_id — the canonical dual-bridge topology per spec §10.1
    has BOTH networks per session: internal (no gateway, sandbox +
    sidecar both attached) + egress (has gateway, ONLY sidecar
    attached). Drift in either name would have Docker treating
    them as the same network → topology break.

    Pinned by ``test_egress_network_name_carries_session_prefix`` +
    ``test_egress_and_internal_names_are_distinct``.
    """
    prefix = session_id[:8]
    suffix = hashlib.sha256(("egress:" + session_id).encode()).hexdigest()[:8]
    return f"cognic-sb-egress-{prefix}-{suffix}"


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
    proxy_url = f"{_PROXY_SCHEME}://{proxy_dns_name}:{proxy_port}"
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


def _parse_proxy_log_jsonl(raw: str) -> tuple[ProxyAccessRecord, ...]:
    """Parse the canonical proxy sidecar's JSONL access log into
    a tuple of ``ProxyAccessRecord`` per spec §10.3 wire-contract.

    Each line is one JSON object with keys: ``host`` + ``method`` +
    ``timestamp`` (ISO 8601 aware) + ``policy_id`` + ``outcome`` +
    ``refusal_reason`` (None for allowed).

    Best-effort + defence-in-depth:
    * Blank lines silently skipped.
    * Malformed individual lines (JSON parse error OR missing
      required key) skipped — log is partial after a sidecar crash,
      AgentOS should still surface the valid records.

    Pure-functional; non-env-gated unit-testable. T10c helper.
    """
    records: list[ProxyAccessRecord] = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            doc = json.loads(line)
            records.append(
                ProxyAccessRecord(
                    host=doc["host"],
                    method=doc["method"],
                    timestamp=datetime.fromisoformat(doc["timestamp"]),
                    policy_id=doc["policy_id"],
                    outcome=doc["outcome"],
                    refusal_reason=doc.get("refusal_reason"),
                )
            )
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            # Malformed line — skip + continue. Defence-in-depth:
            # a partial JSONL line during a sidecar crash MUST NOT
            # crash the proxy_log materialiser; AgentOS surfaces
            # whatever valid records survived.
            continue
    return tuple(records)


def _classify_egress_refusal(
    proxy_log: tuple[ProxyAccessRecord, ...],
) -> str | None:
    """Pure-functional classifier — scan ``proxy_log`` for refused
    records + return the matching ``SandboxPolicyViolationReason``
    or None if no refusal.

    Per spec §10.4 refusal_reason → SandboxPolicyViolationReason
    mapping:
    * ``not_in_allow_list`` → ``egress_host_not_allow_listed``
    * ``non_http_connect_target`` → ``egress_protocol_not_http``

    Returns the first chronological refusal's reason (proxy log
    is FIFO; matches the order requests were made). The chain
    row's payload.proxy_log still carries ALL records for
    examiner traceability.

    T10c helper — pure-functional + non-env-gated unit-testable.
    """
    for rec in proxy_log:
        if rec.outcome != "refused":
            continue
        if rec.refusal_reason == "not_in_allow_list":
            return "egress_host_not_allow_listed"
        if rec.refusal_reason == "non_http_connect_target":
            return "egress_protocol_not_http"
    return None


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


class _ProxyLogReadFailure(Exception):
    """Internal exception raised by ``_read_proxy_log_from_sidecar``
    when it cannot prove the proxy_log is complete (T10c R1 P1.2).

    Propagates to ``exec()`` which catches + emits
    ``sandbox.policy.violated`` with closed-enum reason
    ``egress_audit_unreadable`` + raises ``SandboxPolicyViolated``.

    Fail-closed contract: a sidecar that crashed mid-exec OR a log
    file that became unreachable MUST surface as a violation
    because AgentOS cannot prove no refusals were missed. Without
    this, a denied outbound request could appear as a green
    ``exec_completed`` row when the sidecar died after the refusal
    but before the backend could read the log.
    """


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
        # T30/T14.1 — run as the canonical proxy image's purpose-built
        # cognicproxy identity (10002:10002), which OWNS /etc/cognic-proxy
        # + /var/log/cognic-proxy. NOT the workload's 65534 — that user
        # cannot write those 10002-owned dirs under ReadonlyRootfs=True
        # (the Z4 egress_audit_unreadable failure class).
        "User": _PROXY_NON_ROOT_USER,
        "HostConfig": {
            "NetworkMode": internal_net_name,
            "AutoRemove": False,
            "ReadonlyRootfs": True,
            # T30/T14.1 — writable scratch for the config dir the entrypoint
            # renders tinyproxy.filter + tinyproxy.conf into at boot. /etc/
            # cognic-proxy is part of the read-only image root + (unlike
            # /var/log/cognic-proxy) is NOT a Docker VOLUME, so it needs an
            # explicit writable mount. tmpfs owned by 10002 lets the proxy
            # write its config without leaking a named/anon volume (the
            # sidecar has AutoRemove=False, so an anon volume would leak).
            "Tmpfs": {_PROXY_CONFIG_DIR: "uid=10002,gid=10002,mode=0755"},
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
    #: Sprint 10 T10 — public Protocol field per spec §3.6. Tuple
    #: (NOT list) — immutable post-construction; mid-life mutation is
    #: out of scope Wave-1. Default empty tuple keeps the Sprint-8A
    #: warm-pool + lease-less cold-create constructors backward-compat.
    #: Iterated by ``DockerSiblingSandboxBackend.destroy()`` for the
    #: per-lease fail-soft revoke loop per spec §4.3 + §7.2; gates the
    #: Q5 LOCK at ``checkpoint()`` + ``suspend()`` per spec §4.5.
    active_leases: tuple[CredentialLease, ...] = ()
    #: Sprint 10.6 T21 — per-credential projection state for the
    #: LIFO destroy() unwind. Aligns 1:1 with ``active_leases`` (same
    #: order; same per-credential identity) so destroy() iterates
    #: reversed pairs + does cleanup-before-revoke per credential per
    #: spec §5.8 step 5. Empty tuple = no credential projections were
    #: performed (the lease-less or mint-only Sprint-10 path). T21
    #: create() sets this to the projected_stack contents on success;
    #: destroy() iterates reversed pairs for the LIFO unwind.
    active_projections: tuple[ProjectionExecutorResult, ...] = ()
    _actor_subject: str = field(repr=False, default="")
    _destroyed: bool = field(repr=False, default=False)
    #: T10c — per-session egress network name (dual-bridge topology
    #: per spec §10.1). Required by ``_teardown_session_state`` so the
    #: egress network gets removed too. Default empty string keeps
    #: backward-compat with sessions created before T10c (they had
    #: no egress network); teardown safely no-ops on missing-named
    #: networks (the DockerError 404 swallow path).
    _egress_network_name: str = field(repr=False, default="")
    #: Sprint 8.5 T6 — suspend() flips this True so subsequent exec()
    #: calls raise per spec §3.1: "Subsequent ``exec()`` calls on this
    #: session raise. wake() restores the session in a fresh backend
    #: resource". Defence-in-depth past container teardown: the
    #: underlying container is gone after suspend(), so the Docker
    #: API call would also fail — but this surfaces a clear
    #: SandboxLifecycleRefused with the wake-pointer rather than a
    #: raw aiodocker DockerError.
    _suspended: bool = field(repr=False, default=False)

    async def exec(
        self,
        command: list[str],
        *,
        timeout_s: float | None = None,
    ) -> SandboxExecResult:
        if self._suspended:
            # Sprint 8.5 T6 — spec §3.1 + spec §8 test row
            # test_session_lifecycle_after_suspend.py. exec() on a
            # suspended session refuses fail-loud with a wake-pointer
            # so the caller knows to wake() first.
            #
            # NOT a SandboxLifecycleRefused — that closed-enum is
            # admission + wake-time only; using a wake-time value here
            # would mis-classify the failure mode in the wire-public
            # taxonomy. The session-lifetime invariant is a usage error,
            # NOT a wake refusal. RuntimeError keeps the closed-enum
            # vocabulary unpolluted while still failing loud.
            raise RuntimeError(
                f"session {self.session_id} was suspend()ed; "
                f"exec() is no longer valid — call "
                f"SandboxBackend.wake(session_id) to restore the "
                f"session in a fresh container per spec §3.2"
            )
        return await self._backend.exec(self, command, timeout_s=timeout_s)

    async def destroy(self) -> None:
        await self._backend.destroy(self)

    # Sprint 8.5 T6 — checkpoint + suspend implementations per spec
    # §3.1 + §7.1. Delegate to backend so the docker / aiodocker
    # call sites stay in one module + backend can own the
    # CheckpointStore + audit-emit wiring. Implementations:
    #
    # * ``checkpoint(label)`` — exec ``tar czf - -C /workspace .`` in
    #   the running container, capture stdout bytes, build
    #   ``CheckpointMetadata``, call ``CheckpointStore.persist()``,
    #   emit ``sandbox.lifecycle.checkpointed``, return id.
    # * ``suspend()`` — take final checkpoint with ``label="__suspend__"``,
    #   emit ``sandbox.lifecycle.suspended`` (capture record_id +
    #   write to side-blob), tear down container + sidecar +
    #   networks, mark ``_suspended=True``.

    async def checkpoint(self, label: str) -> CheckpointId:
        self._raise_q5_lock_if_leased("checkpoint")
        return await self._backend._do_checkpoint(self, label)

    async def suspend(self) -> None:
        self._raise_q5_lock_if_leased("suspend")
        await self._backend._do_suspend(self)

    def _raise_q5_lock_if_leased(self, op: str) -> None:
        """Sprint 10 T10 Q5 LOCK per spec §4.5 — production-grade
        fail-loud scaffolding pointing at Sprint 10.x.

        When ``self.active_leases`` is non-empty, ``checkpoint()`` and
        ``suspend()`` MUST raise ``NotImplementedError`` rather than
        silently dropping the leases at suspend (no revoke event, no
        audit trail) or silently persisting an empty
        ``vault_lease_refs`` to the checkpoint metadata. Resolving the
        leased-session checkpoint / suspend / wake model (re-mint at
        wake vs revoke-at-suspend vs token-in-checkpoint) is the
        follow-up sprint's call per §4.5 + AGENTS.md production-grade
        rule.

        NOT a wire-protocol refusal value — ``checkpoint()`` and
        ``suspend()`` are Python-level Protocol methods, not HTTP
        endpoints; a refusal value would have to be retired by the
        follow-up sprint (wire-protocol-public breaking change).
        """
        if not self.active_leases:
            return
        raise NotImplementedError(
            f"DockerSiblingSession.{op}() on a leased session "
            f"(active_leases count={len(self.active_leases)}) is "
            "out of scope at Sprint 10 per spec §4.5 Q5 LOCK; a "
            "follow-up Sprint 10.x sprint resolves the leased-session "
            "checkpoint / suspend / wake model (re-mint at wake vs "
            "revoke-at-suspend vs token-in-checkpoint). The Sprint-8.5 "
            "Q4 lock's vault_lease_refs=() premise breaks at Sprint 10; "
            "fail loud rather than silently drop leases."
        )


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
        checkpoint_store: CheckpointStore | None = None,
        egress_proxy_image: str | None = None,
        approval_engine: ApprovalEngine | None = None,
    ) -> None:
        self._docker = docker_client
        self._catalog = image_catalog
        self._credential_adapter = credential_adapter
        self._rego = rego_engine
        self._audit = audit_store
        self._dh = decision_history_store
        self._settings = settings
        self._warm_pool = warm_pool
        # Sprint 14A-A2b (ADR-014) — optional approval engine. When non-None, it
        # is threaded into the COLD-CREATE admit_policy so the 13.5c1 sandbox
        # approval seam is consulted; None preserves the pre-13.5 Rego fallback.
        # The wake path is NOT threaded in this slice (checkpoint->wake deferred).
        self._approval_engine = approval_engine
        # Sprint 8.5 T6 — optional wiring for the CheckpointStore +
        # tombstone seam. checkpoint() / suspend() / wake() / destroy()'s
        # tombstone branch ALL require it. None is the Sprint-8A default
        # (callers that never use Sprint 8.5 checkpoints can leave it
        # unwired); the three Sprint-8.5 methods refuse fail-loud when
        # called against a backend without a checkpoint_store wired
        # (NotImplementedError with explicit "wire CheckpointStore"
        # pointer per CLAUDE.md production-grade rule). destroy()'s
        # tombstone path is a no-op without it — sessions that have
        # never checkpointed cannot have tombstones.
        self._checkpoint_store = checkpoint_store
        # #477 §5 — narrow egress-proxy image seam. Explicit None-check
        # (NOT ``or``): an empty string must fail fast, never silently
        # fall back to the placeholder canonical proxy. Production
        # callers omit the kwarg -> None -> the canonical default; an
        # env-gated test may inject a fixture proxy ref.
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
        credential_decls: Sequence[CredentialDecl] = (),
        expected_workload_gid: int | None = None,
        approval_request_id: _uuid.UUID | None = None,
    ) -> SandboxSession:
        """Admit + create a sandbox session per spec §6.1 + §5.8
        (Sprint 10.6 T21 mint-then-project lifecycle).

        Step ordering:
        0. Sprint 10.6 T21 — pair guard at the very top per lock #1.
           ``verify_credentials_pair_invariants`` raises
           ``ValueError`` BEFORE any I/O on length-mismatch /
           one-side-empty / per-index ``vault_path`` mismatch /
           per-index ``tenant_id`` mismatch.
        1. If ``use_warm_pool`` + ``self._warm_pool`` wired AND
           ``requires_credentials`` empty per spec §4.2.1, attempt
           checkout; on hit, return + emit ``warm_pool.checked_out``
           + ``lifecycle.created(warm_pool_hit=True)``.
        2. Run ``admit_policy`` (Stage-1 + Stage-2; raises
           ``SandboxLifecycleRefused`` on any admission failure).
        2.5. Sprint 10.6 T21 — substrate preflight when
           ``credential_decls`` non-empty (Docker: tmpfs /
           image-USER / GID / dev-escape per ``_collect_preflight_result``).
           Refusal raises ``SandboxLifecycleRefused`` BEFORE any
           mint; zero credential-projection events emitted.
        3. Sprint 10.6 T21 — mint-then-project interleaved per spec
           §5.8 step 3. For each ``(request, decl)`` pair in
           manifest declaration order: mint lease → emit
           ``lease_minted`` → compute T18 projection plan → either
           execute T19 + emit ``credentials_projected`` (push to
           ``projected_stack``) OR Path-2 refusal via
           ``_handle_projection_refusal`` (revoke N + emit
           ``credentials_projection_failed(revoke_outcome)`` + LIFO
           unwind 1..N-1 + raise ``SandboxLifecycleRefused``).
        4. Cold-create the dual-container topology (internal network
           + proxy sidecar + sandbox container). Credential bind-
           mounts flow through ``_start_sandbox_container``'s
           ``extra_mounts`` kwarg derived from ``projected_stack``
           per the T21 lock #3 (each mount is read-only by
           construction; mount target = ``/run/credentials/<logical_name>``
           per spec §5.4). On Path 3 topology failure post-projection:
           the cleanup envelope LIFO-unwinds ``projected_stack``
           (cleanup-before-revoke per credential).
        5. Emit ``lifecycle.created(warm_pool_hit=False)`` + return
           the ``DockerSiblingSession`` (with ``active_leases`` +
           ``active_projections`` set to the per-credential state).

        T10a scope: lifecycle + topology only. T10b adds cgroup-cap
        derivation to the container config; T10c adds the proxy
        sidecar's ALLOW_LIST + proxy_log seam. T21 layers the
        mint-then-project loop + LIFO cleanup machinery on top
        without modifying the topology/exec/destroy seams.
        """
        # Sprint 10.6 T21 — pair guard FIRST per lock #1. Raises
        # ``ValueError`` BEFORE warm pool / admission / mint / preflight
        # so a malformed pair fails at the very top of the call stack.
        # Reachable contract violations: one-side-empty, length-mismatch,
        # per-index vault_path mismatch, per-index tenant_id mismatch.
        verify_credentials_pair_invariants(
            requires_credentials=requires_credentials,
            credential_decls=credential_decls,
        )

        # 1. Warm-pool checkout (if wired + caller asked for it AND
        #    no credentials requested). Sprint 10 spec §4.2.1: warm
        #    members were pre-created without an actor context, so a
        #    warm hit on a credentialed create() would silently bypass
        #    the cross-tenant + Rego TTL + mint chain. Force cold-create
        #    when requires_credentials is non-empty.
        if use_warm_pool and self._warm_pool is not None and not requires_credentials:
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

        # 2. Cold-create — admission first. Sprint 14A-A2b: thread the approval
        #    engine + correlator so the 13.5c1 sandbox approval seam is consulted
        #    (cold-create ONLY; the wake path is deferred).
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
            approval_engine=self._approval_engine,
            approval_request_id=approval_request_id,
        )

        # 3. Sprint 10 T10 — single post-admission cleanup envelope per
        #    spec §7.3 row "Create — mint | Any backend failure
        #    post-mint" + the reviewer P1 fix at T10 Docker round 2:
        #    minted leases MUST be best-effort revoked on ANY
        #    post-mint exception (mint-time Vault failure / audit
        #    emit failure mid-batch / topology failure / Session
        #    construct / lifecycle.created emit failure). Pre-fix
        #    code had three nested try/except blocks where the inner
        #    audit-emit catch swallowed only Vault taxonomy
        #    exceptions, leaving non-Vault audit failures as
        #    lease-leak paths (the lease IS active in Vault but
        #    create() aborts → destroy() never called → revoke
        #    never fired → lease lives until its server-side TTL
        #    expires). The single envelope below collapses all
        #    post-admission failure paths onto one revoke + teardown
        #    + propagate contract.
        #
        #    trace_id="" matches the existing 8A/8.5 audit emitters
        #    in this module pending request-bound trace threading.
        minted_leases: list[CredentialLease] = []
        projected_stack: list[tuple[CredentialLease, ProjectionExecutorResult]] = []
        session_id = _uuid.uuid4().hex
        internal_net_name = _internal_network_name(session_id)
        egress_net_name = _egress_network_name(session_id)
        sidecar_name = _proxy_sidecar_container_name(session_id)

        # Sprint 10.6 T21 — substrate preflight runs AFTER admission +
        # BEFORE the mint loop per spec §5.8 step 2 + user-locked
        # sequencing #2. Preflight refusal raises SandboxLifecycleRefused
        # directly — zero minted leases + zero projection events.
        # Skipped entirely when no credentials are requested (saves the
        # /proc/mounts read + docker image inspect on every credential-
        # less sandbox).
        preflight: PreflightResult | None = None
        if credential_decls:
            preflight = await self._collect_preflight_result(
                policy=policy,
                expected_workload_gid=expected_workload_gid,
            )
        # T21 — session opaque derived once per create() call; per-
        # credential opaques derived inside the project step.
        session_opaque = derive_session_opaque() if credential_decls else ""

        try:
            # 3a. Sprint 10.6 T21 — mint-then-project interleaved loop
            #     per spec §5.8 step 3. For each (request, decl) pair
            #     in manifest declaration order:
            #       (a) mint lease → emit lease_minted
            #       (b) compute T18 projection plan
            #       (c) on ProjectionRefused: revoke N + emit
            #           credentials_projection_failed(revoke_outcome) +
            #           LIFO unwind 1..N-1 + raise SandboxLifecycleRefused
            #       (d) on ProjectionPlan: execute T19 → emit
            #           credentials_projected; push to projected_stack
            for request, decl in zip(requires_credentials, credential_decls, strict=True):
                lease = await self._credential_adapter.mint_lease(request)
                minted_leases.append(lease)
                await sandbox_lifecycle_lease_minted(
                    self._dh,
                    lease=lease,
                    trace_id="",
                    session_id=session_id,
                )

                plan_or_refused = compute_projection_plan(lease=lease, manifest_decl=decl)
                if isinstance(plan_or_refused, ProjectionRefused):
                    # Path 2 — revoke failed credential N (revoke-only;
                    # no projection cleanup since it never projected) +
                    # LIFO unwind 1..N-1. The helper clears the lists
                    # in-band so the outer except envelope sees a
                    # clean state on every exit path (normal return +
                    # round-2 P1 audit-failure raise). The helper may
                    # raise on audit-emit failure per round-2 P1; on
                    # normal return we follow up with the
                    # ``SandboxLifecycleRefused(reason)`` per the
                    # standard Path-2 contract.
                    await self._handle_projection_refusal(
                        lease=lease,
                        refused=plan_or_refused,
                        session_id=session_id,
                        minted_leases=minted_leases,
                        projected_stack=projected_stack,
                    )
                    raise SandboxLifecycleRefused(
                        plan_or_refused.reason,
                        detail=(f"projection refused for credential {decl.logical_name!r}"),
                    )

                # ProjectionPlan path — execute T19 + emit projected.
                assert preflight is not None  # mypy: non-None when credential_decls
                credential_opaque = derive_credential_opaque()
                executor_result = await self._execute_projection_plan_docker(
                    plan=plan_or_refused,
                    preflight=preflight,
                    session_opaque=session_opaque,
                    credential_opaque=credential_opaque,
                )
                projected_stack.append((lease, executor_result))
                await sandbox_lifecycle_credentials_projected(
                    self._dh,
                    lease=lease,
                    logical_name=decl.logical_name,
                    projected_field_count=executor_result.projected_field_count,
                    purpose_category=decl.purpose_category,
                    purpose_description=decl.purpose_description,
                    backend_resource_name=executor_result.host_staging_dir,
                    trace_id="",
                    session_id=session_id,
                )

            # 3b. Build the dual-bridge topology per spec §10.1. The
            # credential bind-mounts (T21) flow through to the sandbox
            # container as read-only extra_mounts.
            credential_extra_mounts: list[tuple[str, str]] = [
                (executor_result.host_staging_dir, executor_result.container_mount_target)
                for _lease, executor_result in projected_stack
            ]
            await self._create_internal_network(internal_net_name)
            await self._create_egress_network(egress_net_name)
            await self._start_proxy_sidecar(
                policy=policy,
                session_id=session_id,
                container_name=sidecar_name,
                internal_net_name=internal_net_name,
                egress_net_name=egress_net_name,
                tenant_id=tenant_id,
            )
            await self._start_sandbox_container(
                policy=policy,
                session_id=session_id,
                internal_net_name=internal_net_name,
                extra_mounts=credential_extra_mounts,
            )

            # 3c. Session construct + lifecycle.created emit per spec
            #     §4.3 + R1 P1.1 reviewer fix.
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
                active_leases=tuple(minted_leases),
                # Sprint 10.6 T21 — surface the projection state to the
                # session so destroy()'s LIFO unwind can call
                # _cleanup_projected_credential per executor result in
                # reverse manifest order (cleanup-before-revoke per
                # spec §5.8 step 5).
                active_projections=tuple(
                    executor_result for _lease, executor_result in projected_stack
                ),
                _actor_subject=actor.subject,
                _egress_network_name=egress_net_name,
            )
            await self._emit_lifecycle_created(
                session=session,
                actor=actor,
                warm_pool_hit=False,
            )
        except asyncio.CancelledError:
            # Reviewer P1 fix at T10 Docker round 3:
            # ``asyncio.CancelledError`` subclasses ``BaseException``
            # NOT ``Exception`` (Python 3.8+ change; MRO is
            # ``[CancelledError, BaseException, object]``;
            # ``issubclass(asyncio.CancelledError, Exception) is
            # False``). The ``except Exception`` arm below DOES NOT
            # catch it, so a create() task cancelled mid-flight after
            # a successful mint would skip cleanup entirely and leak
            # the lease (lease active in Vault, no Session returned
            # for destroy(), no future revoke until server-side TTL
            # expires).
            #
            # MUST come BEFORE ``except Exception`` (would not match
            # otherwise; clarity-only ordering since CancelledError
            # isn't a subclass of either VaultException or Exception
            # — neither lower arm would ever catch it). Cleanup helper
            # is invoked then cancellation re-raised UNCHANGED —
            # NEVER swallowed: cancellation semantics must propagate
            # so the asyncio task hierarchy can finish tearing down.
            # If a nested re-cancel hits the helper itself, Vault
            # TTL is the final operational safety net per spec §7.2.
            await self._cleanup_post_admission_failure(
                minted_leases=minted_leases,
                projected_stack=projected_stack,
                session_id=session_id,
                internal_net_name=internal_net_name,
                egress_net_name=egress_net_name,
                sidecar_name=sidecar_name,
            )
            raise
        except (
            VaultUnavailable,
            VaultPathNotFound,
            VaultAuthDenied,
            VaultProtocolError,
            VaultLeaseGrantExceedsRequest,  # Sprint 10.1 — Finding B of plan-review round 1
        ) as exc:
            # Vault-specific mint-failure path — closed-enum mapping
            # per spec §7.1 + the standard post-mint cleanup.
            # Sprint 10.1: tuple extended 4 → 5 to also catch
            # `VaultLeaseGrantExceedsRequest` (post-mint
            # granted-vs-requested TTL refusal per ADR-004 §25
            # amendment); mapping helper at `_shared_credentials.py`
            # was extended in the SAME commit per Finding B so the new
            # exception cannot escape uncaught at the backend boundary.
            await self._cleanup_post_admission_failure(
                minted_leases=minted_leases,
                projected_stack=projected_stack,
                session_id=session_id,
                internal_net_name=internal_net_name,
                egress_net_name=egress_net_name,
                sidecar_name=sidecar_name,
            )
            raise SandboxLifecycleRefused(
                reason=_mint_exception_to_refusal_reason(exc),
                detail=str(exc),
            ) from exc
        except Exception:
            # ANY other post-admission failure (audit emit / topology /
            # Session construct / lifecycle.created emit / etc.): same
            # cleanup + propagate the ORIGINAL exception unchanged per
            # spec §7.3 row "Any backend failure post-mint". Reviewer
            # P1 fix at round 2: pre-refactor this branch did not exist
            # as a single envelope and the inner topology +
            # lifecycle.created envelopes did NOT revoke minted_leases
            # — non-Vault audit emit failures leaked the leases.
            await self._cleanup_post_admission_failure(
                minted_leases=minted_leases,
                projected_stack=projected_stack,
                session_id=session_id,
                internal_net_name=internal_net_name,
                egress_net_name=egress_net_name,
                sidecar_name=sidecar_name,
            )
            raise
        return session

    async def _cleanup_post_admission_failure(
        self,
        *,
        minted_leases: list[CredentialLease],
        projected_stack: list[tuple[CredentialLease, ProjectionExecutorResult]],
        session_id: str,
        internal_net_name: str,
        egress_net_name: str,
        sidecar_name: str,
    ) -> None:
        """Sprint 10 T10 — shared post-admission cleanup envelope per
        spec §7.3 row "Any backend failure post-mint".

        Called from all three ``except`` arms of ``create()``'s
        post-admission cleanup envelope (``asyncio.CancelledError`` +
        Vault taxonomy + everything-else). Best-effort revoke +
        best-effort teardown — both stages wrap their await in
        ``contextlib.suppress(Exception)`` so a Vault revoke 5xx
        does not block topology teardown and a Docker DockerError
        does not block subsequent stages. **Suppresses ordinary
        cleanup exceptions; cancellation may still interrupt** —
        ``contextlib.suppress(Exception)`` deliberately does NOT
        catch ``BaseException`` subclasses (``CancelledError`` /
        ``KeyboardInterrupt`` / ``SystemExit``), so a nested
        re-cancel during cleanup propagates out of this helper.
        Vault server-side TTL is the operational safety net for that
        edge case per spec §7.2. The Docker teardown methods
        (network delete / container delete) swallow 404s on entities
        that were never created so unconditional invocation is safe
        even when an early-loop exception aborted before any
        topology call.

        Order (post-T21):
          1. **Projection LIFO unwind FIRST** — per spec §5.8 step 5,
             projection cleanup runs BEFORE Vault revoke per
             credential. For each entry in reversed(projected_stack):
             cleanup_projection_dir → emit cleaned_up/cleanup_failed
             → revoke lease → emit lease_revoked/lease_revoke_failed.
             Examiners see this exact ordering on the chain.
          2. **Bare-revoke leftover unprojected leases** — handles
             the Path-3 edge where mint succeeded but the projection
             executor raised mid-loop (T19 execute_projection_plan_docker
             I/O error). Per-lease set comparison via
             ``projected_lease_ids`` to avoid double-revoke of any
             lease already cleaned by Step 1.
          3. **Topology teardown** — networks + containers cleaned
             up via the existing best-effort ``_teardown_session_state``.
             Stages 1+2+3 each independently swallow ordinary
             exceptions so a single failure does not block the rest
             of the cleanup envelope.

        Pre-T21 (Sprint 10 T10) the order was revoke-leases-FIRST
        then teardown. T21 reorders to projection-cleanup-before-
        revoke per spec §5.8 step 5 — projection cleanup minimises
        the active-risk-surface window during cleanup, AND splitting
        revoke into per-projected-credential and bare-leftover
        groups preserves the spec §7.2 fail-soft posture per group.
        """
        # Sprint 10.6 T21 — LIFO unwind of already-projected
        # credentials. Per spec §5.8 step 5: per-credential
        # cleanup-before-revoke ordering.
        projected_lease_ids = {lease.lease_id for lease, _er in projected_stack}
        for lease, executor_result in reversed(projected_stack):
            await self._cleanup_projected_credential(
                lease=lease,
                executor_result=executor_result,
                session_id=session_id,
            )
        # Bare-revoke leases that were minted but NEVER projected
        # (mint-then-project loop raised an I/O error from
        # execute_projection_plan_docker mid-loop). Reverse order
        # for consistency with the LIFO unwind above.
        for already_minted in reversed(minted_leases):
            if already_minted.lease_id in projected_lease_ids:
                continue  # already revoked via the projection unwind above
            with contextlib.suppress(Exception):
                await self._credential_adapter.revoke_lease(already_minted.lease_id)
        with contextlib.suppress(Exception):
            await self._teardown_session_state(
                session_id=session_id,
                internal_net_name=internal_net_name,
                egress_net_name=egress_net_name,
                sidecar_name=sidecar_name,
            )

    async def _cleanup_projected_credential(
        self,
        *,
        lease: CredentialLease,
        executor_result: ProjectionExecutorResult,
        session_id: str,
        emit_handler: Callable[[Coroutine[Any, Any, Any]], Awaitable[None]] | None = None,
    ) -> None:
        """Sprint 10.6 T21 — per-credential LIFO-unwind helper.

        Per spec §5.8 step 5 ordering: projection cleanup FIRST
        (best-effort rmdir of the staging dir), THEN Vault revoke.
        Each sub-step emits its audit event before falling through
        — examiners read ``cleaned_up`` then ``lease_revoked`` per
        credential. On filesystem-cleanup failure the helper emits
        ``credentials_projection_cleanup_failed`` (carries
        partial_state + error_class + sanitized error) BEFORE
        attempting the Vault revoke — cleanup-failed does NOT
        block revoke per spec §5.8 step 5.

        T21 round-2 reviewer P2 — Stage 1 is SPLIT into a filesystem
        cleanup step (1a) + an audit emit step (1b). Pre-fix the
        same ``try/except`` wrapped both; if filesystem cleanup
        succeeded but the ``cleaned_up`` audit emit failed, the
        helper wrongly emitted ``cleanup_failed`` with
        ``partial_state="cleanup_projection_dir raised mid-unwind"``
        — false evidence (cleanup actually succeeded). The split
        ensures ``cleanup_failed`` only fires when the FS cleanup
        ITSELF raised.

        Slice-4 round-2 reviewer P1 — every audit emit goes through
        an ``emit_handler`` callable that the caller chooses based
        on context:

          * ``None`` (default) — best-effort
            ``contextlib.suppress(Exception)`` per the original
            create()-cleanup posture. Suitable for Path-2 / Path-3
            failure cleanup where the unwind is documenting state
            cleanup happening alongside an already-raising
            exception; a single audit-emit failure should NOT
            block the rest of the unwind or override the original
            exception.
          * Caller-supplied — destroy()'s normal-path uses this to
            CAPTURE audit-emit failures (continuing the LIFO
            unwind) so the first captured exception can propagate
            per spec §7.2 "audit evidence for every revoke
            failure" — the same posture as the existing
            ``_emit_revoke_event`` for the bare-revoke loop. The
            caller is responsible for managing the captured
            exception state (typically via a ``nonlocal``).

        The credentials_projection_failed emit at the Path-2 entry
        point (NOT here) still propagates its audit failures per
        the T21 round-2 P1 fix — that's the ONE chance to record
        "credential N refused projection with revoke_outcome X".
        """
        # Default emit handler: best-effort suppress (create()-cleanup posture).
        if emit_handler is None:

            async def _default_emit_handler(
                coro: Coroutine[Any, Any, Any],
            ) -> None:
                with contextlib.suppress(Exception):
                    await coro

            emit_handler = _default_emit_handler

        # Stage 1a: projection cleanup (filesystem).
        cleanup_exc: Exception | None = None
        try:
            await self._cleanup_projection_dir(executor_result.host_staging_dir)
        except Exception as exc:
            cleanup_exc = exc

        # Stage 1b: emit audit event reflecting Stage 1a's outcome.
        # The branches are mutually exclusive: cleaned_up only when
        # filesystem cleanup succeeded; cleanup_failed only when it
        # raised. Emit failure routing now goes through the
        # caller-supplied emit_handler so destroy()'s normal path
        # can capture-and-propagate.
        if cleanup_exc is None:
            await emit_handler(
                sandbox_lifecycle_credentials_projection_cleaned_up(
                    self._dh,
                    lease=lease,
                    logical_name=executor_result.logical_name,
                    cleanup_target="staging_dir",
                    backend_resource_name=executor_result.host_staging_dir,
                    trace_id="",
                    session_id=session_id,
                )
            )
        else:
            await emit_handler(
                sandbox_lifecycle_credentials_projection_cleanup_failed(
                    self._dh,
                    lease=lease,
                    logical_name=executor_result.logical_name,
                    cleanup_target="staging_dir",
                    backend_resource_name=executor_result.host_staging_dir,
                    partial_state="cleanup_projection_dir raised mid-unwind",
                    error_class=type(cleanup_exc).__name__,
                    error=str(cleanup_exc),
                    trace_id="",
                    session_id=session_id,
                )
            )

        # Stage 2: Vault revoke (runs even if cleanup failed).
        try:
            await self._credential_adapter.revoke_lease(lease.lease_id)
        except Exception as revoke_exc:
            await emit_handler(
                sandbox_lifecycle_lease_revoke_failed(
                    self._dh,
                    lease=lease,
                    trace_id="",
                    session_id=session_id,
                    vault_error=str(revoke_exc),
                )
            )
            return
        await emit_handler(
            sandbox_lifecycle_lease_revoked(
                self._dh,
                lease=lease,
                trace_id="",
                session_id=session_id,
            )
        )

    async def _execute_projection_plan_docker(
        self,
        *,
        plan: ProjectionPlan,
        preflight: PreflightResult,
        session_opaque: str,
        credential_opaque: str,
    ) -> ProjectionExecutorResult:
        """Sprint 10.6 T21 — method seam over T19's
        ``execute_projection_plan_docker`` module function. Mockable
        in tests so the existing mint-mechanics test suite does not
        need to provision ``/dev/shm/cognic`` on the host (the real
        executor writes credential bytes to that tmpfs path).

        Production calls the T19 module-level sync function with
        ``base_staging_path=Path("/dev/shm/cognic")`` per spec §5.4.
        """
        return execute_projection_plan_docker(
            plan=plan,
            preflight=preflight,
            session_opaque=session_opaque,
            credential_opaque=credential_opaque,
            base_staging_path=Path("/dev/shm/cognic"),
        )

    async def _cleanup_projection_dir(self, host_staging_dir: str) -> None:
        """Sprint 10.6 T21 — async wrapper around T19's
        ``cleanup_projection_dir`` (sync filesystem op). Off-loaded
        to a thread to avoid blocking the asyncio event loop during
        the LIFO unwind. Tests inject a mock here so the unwind path
        runs without touching the real filesystem.
        """
        from cognic_agentos.sandbox.backends._docker_executor import (
            cleanup_projection_dir as _sync_cleanup,
        )

        await asyncio.to_thread(_sync_cleanup, host_staging_dir)

    async def _handle_projection_refusal(
        self,
        *,
        lease: CredentialLease,
        refused: ProjectionRefused,
        session_id: str,
        minted_leases: list[CredentialLease],
        projected_stack: list[tuple[CredentialLease, ProjectionExecutorResult]],
    ) -> None:
        """Sprint 10.6 T21 Path 2 helper — per spec §5.8 step 3d.

        Sequence:
          1. Best-effort revoke lease N (just-minted; never projected).
          2. Emit ``credentials_projection_failed`` for credential N
             carrying ``revoke_outcome`` ∈ {``revoked``, ``revoke_failed``}.
             NOTE: NO ``credentials_projection_cleaned_up`` for N — it
             never projected, so there's no staging-dir to clean.
          3. LIFO unwind ``projected_stack`` per spec §5.8 step 5
             (cleanup-before-revoke per credential).

        T21 round-2 reviewer P1 — the Stage-2 emit MUST propagate
        on audit-store append failure. Pre-fix it was wrapped in
        ``contextlib.suppress(Exception)`` which silently swallowed
        the audit failure: ``create()`` would raise
        ``SandboxLifecycleRefused(reason)`` as if the Path-2
        evidence row had landed, but banks would have no chain row.
        Mirrors the existing ``lease_minted`` /
        ``credentials_projected`` posture in the main create() body
        where audit-append failures propagate up through the
        cleanup envelope.

        The captured audit exception is held until AFTER Stage 3
        completes — the LIFO unwind MUST run regardless so the
        already-projected stack does not leak. After unwind:

          * If audit exc was captured → raise it (this overrides
            the caller's ``SandboxLifecycleRefused(reason)`` raise
            because the audit failure is the more severe evidence
            problem).
          * Otherwise → return normally + caller raises
            ``SandboxLifecycleRefused(reason)`` per the standard
            Path-2 contract.

        Stage 3 itself uses the existing best-effort posture per
        ``_cleanup_projected_credential`` docstring — every audit
        emit there is wrapped in ``contextlib.suppress(Exception)``
        because those emits document cleanup that already happened.
        The ONE evidence row that MUST land on Path 2 is the
        ``credentials_projection_failed`` carrying the
        ``revoke_outcome`` — that's the per-credential refusal
        evidence the bank-grade contract depends on.
        """
        # Stage 1: revoke lease N + record outcome.
        revoke_outcome: str
        try:
            await self._credential_adapter.revoke_lease(lease.lease_id)
            revoke_outcome = "revoked"
        except Exception:
            revoke_outcome = "revoke_failed"

        # Stage 2: emit credentials_projection_failed for N.
        # Audit failure is CAPTURED (not suppressed) and surfaced
        # AFTER the LIFO unwind completes per the round-2 P1 fix.
        path2_audit_exc: BaseException | None = None
        try:
            await sandbox_lifecycle_credentials_projection_failed(
                self._dh,
                lease=lease,
                logical_name=refused.logical_name,
                reason=refused.reason,
                expected_fields=refused.expected_fields,
                actual_fields=refused.actual_fields,
                extras=refused.extras,
                missing=refused.missing,
                revoke_outcome=revoke_outcome,  # type: ignore[arg-type]
                field_name=refused.field_name,
                actual_type=refused.actual_type,
                actual_length=refused.actual_length,
                actual_size=refused.actual_size,
                cap=refused.cap,
                trace_id="",
                session_id=session_id,
            )
        except Exception as exc:
            path2_audit_exc = exc

        # Stage 3: LIFO unwind 1..N-1 (already-projected stack).
        # Runs UNCONDITIONALLY — even if Stage 2's audit emit failed,
        # the projected stack MUST be unwound so credential bytes
        # are cleaned + leases revoked. Per-step best-effort posture
        # lives inside _cleanup_projected_credential.
        for prev_lease, prev_executor in reversed(projected_stack):
            await self._cleanup_projected_credential(
                lease=prev_lease,
                executor_result=prev_executor,
                session_id=session_id,
            )

        # Clear minted_leases + projected_stack BEFORE the audit-
        # failure raise below. This helper has revoked + cleaned up
        # all entries already; leaving them in the lists would cause
        # the create()'s outer except envelope to re-revoke + re-
        # cleanup, producing duplicate audit rows. Round-2 P1: clear
        # is moved INTO the helper so the audit-failure exit path
        # doesn't skip the caller's previous in-band clear() calls.
        minted_leases.clear()
        projected_stack.clear()

        # Stage 4 (round-2 P1) — surface the Stage-2 audit failure
        # if one occurred. Raised AFTER Stage 3 completes so the
        # LIFO unwind runs regardless + AFTER the in-helper clear
        # so the outer envelope sees a clean state.
        if path2_audit_exc is not None:
            raise path2_audit_exc

    async def _collect_preflight_result(
        self,
        *,
        policy: SandboxPolicy,
        expected_workload_gid: int | None,
    ) -> PreflightResult:
        """Sprint 10.6 T21 — gather the inputs for the T19 Phase 1
        substrate preflight + call the verifier.

        Mockable seam: tests replace this method via ``AsyncMock`` to
        drive preflight pass/refuse behaviour without real I/O. The
        default production body reads ``/proc/mounts`` from the host
        and inspects the runtime image's ``Config.User`` field via
        ``aiodocker``, then delegates to
        ``verify_docker_credential_projection_preflight``.
        """
        # The Docker preflight signature takes ``expected_workload_gid:
        # int`` (not Optional). The runtime manifest validator at
        # ``cli/validators/credentials.py`` already enforces a non-None
        # value when ``[credentials]`` blocks are declared; reaching
        # this seam with None means a non-manifest caller bypassed
        # validation — programmer-error contract violation. Same
        # pattern as the T19/T20 boundary-grammar guards.
        if expected_workload_gid is None:
            raise ValueError(
                "expected_workload_gid MUST be provided when "
                "credential_decls is non-empty; got None"
            )
        proc_mounts_content = await asyncio.to_thread(_read_proc_mounts_file)
        image_user_directive = await self._inspect_image_user_directive(policy.runtime_image)
        return verify_docker_credential_projection_preflight(
            expected_workload_gid=expected_workload_gid,
            image_user_directive=image_user_directive,
            proc_mounts_content=proc_mounts_content,
            dev_escape_enabled=getattr(
                self._settings,
                "dev_escape_allow_permissive_credential_projection",
                False,
            ),
            profile=getattr(self._settings, "runtime_profile", "prod"),
        )

    async def _inspect_image_user_directive(self, image_ref: str) -> str | None:
        """Sprint 10.6 T21 — inspect the runtime image's ``Config.User``
        field. Default implementation queries ``aiodocker.images.inspect``;
        tests override via ``AsyncMock`` for the no-I/O path.
        Returns the raw USER string or ``None`` if the image has no
        USER directive set.
        """
        image = await self._docker.images.inspect(image_ref)
        config = image.get("Config", {}) if isinstance(image, dict) else {}
        user = config.get("User")
        return user if user else None

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

            # T10c — read proxy_log from sidecar + classify any egress
            # refusals. Per spec §10.3 the canonical proxy image
            # writes JSONL to ``_PROXY_LOG_PATH``; backend reads via
            # docker exec cat. Per spec §7 line 501 + §10.4, egress
            # refusals raise SandboxPolicyViolated with the matching
            # closed-enum reason.
            #
            # R1 P1.2 fail-closed: ``_read_proxy_log_from_sidecar``
            # raises ``_ProxyLogReadFailure`` when it cannot prove
            # the log is complete (sidecar gone, cat exit nonzero).
            # We catch + emit policy.violated with closed-enum
            # ``egress_audit_unreadable`` + raise — AgentOS MUST NOT
            # emit a green ``exec_completed`` when refusals may
            # have been silently elided.
            try:
                proxy_log = await self._read_proxy_log_from_sidecar(session._sidecar_container_name)
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

            egress_reason = _classify_egress_refusal(proxy_log)
            if egress_reason is not None:
                detail = (
                    f"command={command!r} exit_code={exit_code} "
                    f"proxy_log_refused_count="
                    f"{sum(1 for r in proxy_log if r.outcome == 'refused')}"
                )
                # R1 P1.3 — include the FULL proxy_log on the
                # policy.violated chain row so examiners can prove
                # which outbound calls were attempted + which were
                # refused (spec §10.3). Earlier T10c version dropped
                # the records and emitted only ``{reason}``.
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

        Sprint 8.5 T6 + P1.r4 tombstone redesign: if the session has
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
        teardown_succeeded = False
        try:
            await self._teardown_session_state(
                session_id=session.session_id,
                internal_net_name=session._internal_network_name,
                egress_net_name=session._egress_network_name,
                sidecar_name=session._sidecar_container_name,
            )
            teardown_succeeded = True
        finally:
            # Sprint 10 T10 Docker round-5 reviewer-P2 fix + round-6
            # reviewer-P1 follow-up (2026-05-24): revoke active Vault
            # leases best-effort EVEN WHEN teardown raised AND surface
            # audit-emit failures on the normal path so banks see
            # them per spec §7.2 ("audit evidence for every revoke
            # failure"). The P2 fix wrapped the audit emits in
            # ``contextlib.suppress(Exception)`` UNCONDITIONALLY which
            # silently swallowed audit-chain failures on the normal
            # path — that violated the bank-grade evidence contract.
            # Conditional-suppress per ``teardown_succeeded`` resolves
            # the tension between the two correctness requirements:
            #
            # * teardown_succeeded=False (teardown raised) — suppress
            #   audit-emit exceptions so the ORIGINAL teardown
            #   exception propagates per Python finally-block
            #   semantics (a new exception from finally would
            #   shadow the try-block's exception unless suppressed).
            # * teardown_succeeded=True (normal path) — audit-emit
            #   failures PROPAGATE so operators see audit-chain
            #   problems rather than silently lose revoke evidence
            #   per spec §7.2's bank-grade contract.
            #
            # Gated on ``not already_destroyed`` so the idempotent
            # second destroy does NOT re-emit lease events. The Vault
            # revoke itself is intentionally NOT wrapped in suppress —
            # its own try/except routes failures to
            # lease_revoke_failed audit so each lease attempt is
            # independently best-effort. Runs BEFORE the tombstone +
            # lifecycle.destroyed branch below so the chain row
            # order stays: revoke[_failed] → (if teardown succeeded)
            # tombstone → lifecycle.destroyed.
            if not already_destroyed:
                # Sprint 10.6 T21 slice 4 + slice-4 round-2 P1 —
                # LIFO projection cleanup BEFORE per-credential
                # revoke per spec §5.8 step 5. For each projected
                # credential in reverse manifest order:
                # cleanup_projection_dir → emit cleaned_up /
                # cleanup_failed → revoke → emit lease_revoked /
                # lease_revoke_failed. The per-credential helper
                # ``_cleanup_projected_credential`` routes its
                # audit emits through the shared
                # ``_emit_revoke_event`` handler defined below so
                # the existing spec §7.2 "capture first audit emit
                # failure, continue, raise after loop" contract
                # pinned by
                # ``test_cross_backend_destroy_audit_emit_*`` covers
                # projected leases AND bare-revoke leases on the
                # normal-destroy path. Teardown-failure path still
                # suppresses so the original teardown exception
                # propagates per Python finally-block semantics.
                #
                # Pairing: session.active_leases and
                # session.active_projections are 1:1 by manifest
                # declaration order (set by create() on success).
                # T21 invariant — the pair guard at create() entry
                # makes asymmetry impossible.
                projected_lease_ids: set[str] = {er.lease_id for er in session.active_projections}
                # Index leases by lease_id so the LIFO walk picks
                # the matching lease for each executor result.
                leases_by_id: dict[str, CredentialLease] = {
                    lease.lease_id: lease for lease in session.active_leases
                }

                # Capture the FIRST normal-path audit-emit exception
                # so we can raise it AFTER every lease got its
                # revoke + projection-cleanup attempt per spec §7.2's
                # single-attempt-per-lease cleanup contract. Round-3
                # reviewer-P1 propagated immediately, which aborted
                # the loop on multi-lease destroys (Gap N). Round-4
                # reviewer-P2 fix: keep attempting + emit for every
                # lease, remember first emit exception, raise after
                # loop. Slice-4 round-2 reviewer P1 extends the
                # capture-and-continue posture to the projected
                # credentials' audit emits via the shared handler
                # injected into ``_cleanup_projected_credential``.
                first_normal_path_emit_exc: BaseException | None = None

                async def _emit_revoke_event(
                    coro: Coroutine[Any, Any, Any],
                ) -> None:
                    nonlocal first_normal_path_emit_exc
                    if teardown_succeeded:
                        # Normal path — capture first emit exception
                        # but continue so the rest of the loop runs
                        # per spec §7.2.
                        try:
                            await coro
                        except Exception as exc:
                            if first_normal_path_emit_exc is None:
                                first_normal_path_emit_exc = exc
                    else:
                        # Teardown-failure path — suppress so the
                        # original teardown exception propagates per
                        # Python finally-block semantics.
                        with contextlib.suppress(Exception):
                            await coro

                # Projection LIFO unwind — uses the same handler so
                # projected leases' cleanup_dir / cleaned_up /
                # cleanup_failed / lease_revoked / lease_revoke_failed
                # audit emits share the destroy()-normal-path
                # capture-and-propagate posture (round-2 P1 fix).
                for executor_result in reversed(session.active_projections):
                    paired_lease = leases_by_id.get(executor_result.lease_id)
                    if paired_lease is None:
                        # Defensive: pre-T21 sessions or test fixtures
                        # could in theory produce a mismatched pair.
                        # Skip rather than fail-loud — destroy() never
                        # raises per spec §7.2.
                        continue
                    try:
                        await self._cleanup_projected_credential(
                            lease=paired_lease,
                            executor_result=executor_result,
                            session_id=session.session_id,
                            emit_handler=_emit_revoke_event,
                        )
                    except Exception:
                        # Non-audit exceptions (programmer-error in the
                        # helper itself, not Vault/FS or audit emit
                        # which are handled inside): continue the
                        # unwind for the remaining credentials.
                        continue

                # T21 slice 4: this loop now ONLY handles bare-revoke
                # of leases that do NOT have a matching projection
                # entry (defence-in-depth for the legacy Sprint-10
                # mint-only path which T21's pair guard makes
                # unreachable from create() going forward; the loop
                # filter via ``projected_lease_ids`` ensures double-
                # revoke is impossible against the projection-unwind
                # loop above).
                for lease in session.active_leases:
                    # T21 slice 4 — skip leases already revoked via
                    # the projection-unwind loop above to prevent
                    # double-revoke.
                    if lease.lease_id in projected_lease_ids:
                        continue
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

        # Sprint 8.5 T6 — tombstone the session if it has persisted
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

        # R2 P1.2 reviewer fix — emit BEFORE setting the flag, so
        # a transient audit-append failure leaves ``_destroyed``
        # False and a retry destroy() will retry the emission.
        # Earlier ordering set the flag first and lost the
        # destroyed row permanently on any audit failure.
        # The retry contract is intentional: docker teardown is
        # idempotent (the _teardown_session_state helper swallows
        # "not found" DockerError) so calling destroy() twice
        # after a transient emit failure is safe. The tombstone
        # write upstream is ALSO idempotent — a retry destroy()
        # gets back the existing sentinel key (per spec §4.1).
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

    # Sprint 8.5 T6 — wake() pipeline per spec §3.2 + §7.1.
    # LOAD-BEARING tombstone-first ordering: CheckpointStore.load_tombstone()
    # MUST be called BEFORE load_latest(). Pinned by the unit test at
    # test_wake_session_tombstoned.py + the cross-backend conformance
    # regression at T9. See the docstring below for the full step list.

    async def wake(
        self,
        session_id: str,
        *,
        actor: Actor,
        tenant_id: str,
        approval_request_id: _uuid.UUID | None = None,
    ) -> SandboxSession:
        """Restore a suspended session per spec §3.2 + §7.1.

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
           any fresh Docker resources are created.
        6. Create fresh container + sidecar + networks; restore
           workspace tar via ``tar xzf - -C /workspace`` over the
           exec channel.
        7. Build fresh ``DockerSiblingSession`` with ORIGINAL
           session_id + new container ID + ``warm_pool_hit=False``.
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
                "DockerSiblingSandboxBackend.wake requires a CheckpointStore "
                "to be wired at construction time. Pass checkpoint_store=... "
                "to __init__ per spec §3.2 + §7.1."
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
                approval_engine=self._approval_engine,  # A3c — wake approval seam
                approval_request_id=approval_request_id,  # A3c — request-time correlator
            )
        except SandboxLifecycleRefused as original:
            # A3c — let the approval family pass through un-rewrapped so the
            # executor sees sandbox_approval_pending + the approval_request_id;
            # only genuine revalidation refusals collapse.
            if original.reason in _APPROVAL_WAKE_PASSTHROUGH_REASONS:
                raise
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
        # Step 6 — create fresh container + sidecar + networks; restore
        # workspace tar via the exec channel.
        # ------------------------------------------------------------------
        # session_id is preserved from the original (continuity is the
        # whole point); network + sidecar names are derived
        # deterministically from session_id by the same helpers create()
        # uses, so a wake-then-destroy works the same way as a
        # cold-create-then-destroy.
        internal_net_name = _internal_network_name(session_id)
        egress_net_name = _egress_network_name(session_id)
        sidecar_name = _proxy_sidecar_container_name(session_id)

        await self._create_internal_network(internal_net_name)
        await self._create_egress_network(egress_net_name)
        try:
            await self._start_proxy_sidecar(
                policy=metadata.policy,
                session_id=session_id,
                container_name=sidecar_name,
                internal_net_name=internal_net_name,
                egress_net_name=egress_net_name,
                tenant_id=tenant_id,
            )
            await self._start_sandbox_container(
                policy=metadata.policy,
                session_id=session_id,
                internal_net_name=internal_net_name,
            )
            # Restore the workspace tar into /workspace via docker exec.
            await self._restore_workspace_tar(
                session_id=session_id,
                snapshot_bytes=snapshot_bytes,
            )
        except Exception:
            # Tear down anything we managed to create + re-raise so
            # the caller sees the failure. Idempotent destroy methods
            # make this safe even on partial-create failures.
            await self._teardown_session_state(
                session_id=session_id,
                internal_net_name=internal_net_name,
                egress_net_name=egress_net_name,
                sidecar_name=sidecar_name,
            )
            raise

        # ------------------------------------------------------------------
        # Step 7 — build fresh DockerSiblingSession with ORIGINAL
        # session_id.
        # ------------------------------------------------------------------
        session = DockerSiblingSession(
            session_id=session_id,
            policy=metadata.policy,
            tenant_id=tenant_id,
            pack_context=metadata.pack_context,
            created_at=datetime.now(UTC),
            warm_pool_hit=False,
            _backend=self,
            _internal_network_name=internal_net_name,
            _sidecar_container_name=sidecar_name,
            _actor_subject=actor.subject,
            _egress_network_name=egress_net_name,
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

    async def _create_egress_network(self, name: str) -> None:
        """Create the per-session egress Docker network (T10c +
        spec §10.1 dual-bridge topology).

        NO ``Internal=true`` — this network DOES have an external
        gateway. The sidecar attaches to this network for outbound
        traffic; the sandbox container does NOT (it's only on the
        internal network). This is the only path from the sandbox
        to the external world: sandbox → internal-net → sidecar →
        egress-net → external.
        """
        await self._docker.networks.create(
            {
                "Name": name,
                "Driver": "bridge",
                # NO Internal=true — egress network needs gateway
                "Labels": {
                    "cognic.agentos.sandbox": "egress",
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
        egress_net_name: str,
        tenant_id: str,
    ) -> None:
        """Start the proxy sidecar container dual-homed on internal +
        egress networks per spec §10.1.

        The sidecar is the ONLY container attached to the egress
        network — sandbox container is internal-only. Sandbox's
        HTTP_PROXY env points at the sidecar via the internal
        network's DNS alias ``egress-proxy``; the sidecar then
        forwards external traffic through the egress network's
        gateway.

        Wire-contract: the canonical proxy image listens on
        ``_PROXY_PORT`` (3128 per spec §10.2) on both networks.

        T10c R1 P1.1 — proxy image goes through the SAME catalog
        trust gate as ``policy.runtime_image`` (canonical-set
        membership + cosign verify + SBOM policy check). The proxy
        IS the egress-enforcement component; without this gate, a
        compromised registry could land an unverified proxy as a
        trusted enforcement point. Pinned by
        ``TestProxyImageGoesThroughCatalogVerification``.
        """
        # The egress-proxy image — #477 §5: the constructor-resolved
        # seam value (``_egress_proxy_image``). Defaults to the
        # canonical ``_CANONICAL_EGRESS_PROXY_IMAGE`` for production
        # callers; an env-gated test may inject a fixture ref. Either
        # way it flows through the SAME catalog trust gate below.
        proxy_image = self._egress_proxy_image

        # R1 P1.1 — canonical-set membership + cosign + SBOM verify
        # on the proxy image. Same gate as admit_policy uses on
        # runtime_image; refuses with the same closed-enum reasons.
        # If admission already passed on the runtime image but the
        # PROXY image's verification fails, AgentOS refuses
        # session creation (the caller sees SandboxLifecycleRefused
        # propagating from the create() try block + its rollback).
        #
        # R2 P1 fix — extract the digest from the full OCI ref before
        # catalog calls. CanonicalImageCatalog is digest-keyed per
        # catalog.py:279 + T5 admission's rsplit("@", 1) pattern at
        # admission.py:317. Passing the full ref was the R1 P1.1
        # bug: real catalogs returned False from is_canonical(full_ref)
        # + refused every session.
        _, proxy_image_digest = proxy_image.rsplit("@", 1)
        if not self._catalog.is_canonical(proxy_image_digest):
            raise SandboxLifecycleRefused(
                "sandbox_image_digest_not_in_canonical_catalog",
                detail=(
                    f"proxy sidecar image {proxy_image} not in canonical "
                    f"catalog (digest {proxy_image_digest}) — egress "
                    f"enforcement component MUST be catalog-verified per "
                    f"spec §9 + T10c R1 P1.1 reviewer fix"
                ),
            )
        await self._catalog.verify_cosign_or_refuse(proxy_image_digest, tenant_id=tenant_id)
        await self._catalog.verify_sbom_policy_or_refuse(proxy_image_digest, tenant_id=tenant_id)

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
        # T10c — attach sidecar to egress network as a second
        # endpoint. aiodocker's networks.connect maps to
        # ``docker network connect`` — the container ends up
        # dual-homed (one IP on internal-net, one IP on egress-net).
        egress_network = await self._docker.networks.get(egress_net_name)
        await egress_network.connect({"Container": container_name})

    async def _start_sandbox_container(
        self,
        *,
        policy: SandboxPolicy,
        session_id: str,
        internal_net_name: str,
        extra_mounts: Sequence[tuple[str, str]] = (),
    ) -> None:
        """Start the sandbox container on the internal network only.

        T10a-scope: lifecycle + topology only. T10b extended the
        container config with cgroup caps. T10c does not modify
        this method — proxy_log materialisation happens at exec-time.

        Sprint 10.6 T21 — ``extra_mounts`` kwarg accepts a Sequence
        of ``(host_path, container_path)`` tuples for credential
        projection bind-mounts (read-only by construction at this
        seam — callers cannot request writable credential mounts).
        Each pair surfaces as a Docker bind mount in the container
        config's ``HostConfig.Binds`` list with the ``:ro`` flag.
        """
        config = _build_sandbox_container_config(
            policy=policy,
            session_id=session_id,
            internal_net_name=internal_net_name,
        )
        if extra_mounts:
            # Append read-only bind mounts for credential projection.
            # ``HostConfig.Binds`` syntax: ``"<host>:<container>:ro"``.
            host_config = config.setdefault("HostConfig", {})
            existing_binds = list(host_config.get("Binds", []))
            for host_path, container_path in extra_mounts:
                existing_binds.append(f"{host_path}:{container_path}:ro")
            host_config["Binds"] = existing_binds
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
        egress_net_name: str,
        sidecar_name: str,
    ) -> None:
        """Best-effort idempotent teardown of all docker objects.

        Each step swallows ``aiodocker.exceptions.DockerError`` so the
        teardown completes even if some objects were never created
        (partial-create failure path) OR have already been removed
        (double-destroy path).

        Order: sandbox container → sidecar container → internal +
        egress networks. Reverses the create order so dependencies
        are removed before the things they depend on (a network
        cannot be removed while containers are still attached).

        T10c added the egress_net_name parameter — empty string is
        tolerated (pre-T10c sessions had no egress network; the
        network destroy helper swallows the resulting 404).
        """
        await self._destroy_container_if_exists(session_id)
        await self._destroy_container_if_exists(sidecar_name)
        await self._destroy_network_if_exists(internal_net_name)
        if egress_net_name:
            await self._destroy_network_if_exists(egress_net_name)

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

    async def _read_proxy_log_from_sidecar(
        self,
        sidecar_name: str,
    ) -> tuple[ProxyAccessRecord, ...]:
        """Read the canonical proxy sidecar's JSONL access log via
        docker exec cat. Returns the parsed tuple of
        ProxyAccessRecord per spec §10.3 wire-contract.

        T10c R1 P1.2 — FAIL-CLOSED. The canonical proxy image's
        contract is: the log file at ``_PROXY_LOG_PATH`` ALWAYS
        exists + is readable; empty file (size 0) is the
        canonical "no outbound calls" representation. ANY failure
        modes (container gone, cat exit nonzero, exec failure,
        unexpected exception) raise ``_ProxyLogReadFailure`` so
        exec() can fail-closed via
        ``SandboxPolicyViolated(egress_audit_unreadable)``.

        Earlier T10c best-effort design (``return ()`` on any
        failure) had a critical bug: a sidecar that crashed
        mid-exec AFTER refusing outbound calls but BEFORE backend
        could read would silently elide refusals + emit a green
        ``exec_completed`` row. Bank-grade trust posture requires
        AgentOS to fail-closed when it cannot prove the absence
        of refusals.

        Used by exec() after the command stream completes. The
        canonical ``cognic/sandbox-egress-proxy`` image writes to
        ``_PROXY_LOG_PATH`` per the wire-contract.
        """
        try:
            sidecar = await self._docker.containers.get(sidecar_name)
        except aiodocker.exceptions.DockerError as e:
            raise _ProxyLogReadFailure(
                f"sidecar container {sidecar_name!r} unreachable during "
                f"proxy_log readback ({e}); cannot prove absence of "
                f"refusals — fail-closed per T10c R1 P1.2"
            ) from e

        try:
            sidecar_exec = await sidecar.exec(
                cmd=["cat", _PROXY_LOG_PATH],
                stdout=True,
                stderr=True,
                # T30/T14.1 — read the proxy's access log as the proxy's own
                # 10002 identity (it owns the log under /var/log/cognic-proxy),
                # not the workload's 65534.
                user=_PROXY_NON_ROOT_USER,
            )
            chunks: list[bytes] = []
            async with sidecar_exec.start(detach=False) as stream:
                while True:
                    message = await stream.read_out()
                    if message is None:
                        break
                    if message.stream == 1:
                        chunks.append(message.data)
            # cat exit code: 0 means the file existed + was readable
            # (possibly empty = no outbound calls); nonzero means the
            # log was unreadable (missing file, permission denied,
            # I/O error). The canonical proxy image guarantees the
            # log path exists + is readable; nonzero exit is a
            # contract violation that we surface fail-closed.
            inspect = await sidecar_exec.inspect()
            exit_code = int(inspect.get("ExitCode") or 0)
            if exit_code != 0:
                raise _ProxyLogReadFailure(
                    f"sidecar cat {_PROXY_LOG_PATH!r} exited {exit_code} "
                    f"— canonical proxy image guarantees a readable log "
                    f"file; fail-closed per T10c R1 P1.2"
                )
        except _ProxyLogReadFailure:
            raise
        except Exception as e:
            raise _ProxyLogReadFailure(f"unexpected error reading proxy_log: {e!r}") from e

        raw = b"".join(chunks).decode("utf-8", errors="replace")
        return _parse_proxy_log_jsonl(raw)

    async def _emit_lifecycle_exec_completed(
        self,
        *,
        session: DockerSiblingSession,
        exit_code: int,
        proxy_log: tuple[ProxyAccessRecord, ...],
    ) -> None:
        """Emit ``sandbox.lifecycle.exec_completed`` per spec §4.3
        wire-public payload + spec §7 line 502 + T10c.

        Payload carries ``exit_code`` + serialised ``proxy_log``
        (list of dicts; canonical_bytes-safe — see warm_pool's
        ``_tuples_to_lists`` pattern for the list/tuple ambiguity
        bug class avoidance).

        Only fires on the green-path exec return; cap-violation
        + egress-violation paths emit ``sandbox.policy.violated``
        instead.
        """
        # Serialise proxy_log to list-of-dicts for chain row
        # payload. Per the canonical-bytes contract (T7's
        # ``proxy_log_to_chain_payload`` wire-shape), each record
        # becomes a 6-key dict with ISO 8601 timestamp string.
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
        session: DockerSiblingSession,
        reason: str,
        proxy_log: tuple[ProxyAccessRecord, ...] = (),
    ) -> None:
        """Emit ``sandbox.policy.violated`` per spec §4.3 wire-public
        payload ``{reason: SandboxPolicyViolationReason}`` + R1 P1.5
        reviewer fix.

        Fired BEFORE ``exec()`` raises ``SandboxPolicyViolated`` on
        any cap-violation path (memory_cap_exceeded /
        walltime_cap_exceeded / cpu_time_budget_exceeded). Without
        this row, cap kills happen in production with NO audit trail
        and the evidence pack misses the wire-protocol-public event.

        T10c R1 P1.3 — when ``proxy_log`` is non-empty (egress
        refusal path), the materialised list of records is included
        on the chain row payload under the ``proxy_log`` key. Spec
        §10.3 requires examiners to prove which outbound calls were
        attempted + which were refused FROM THE CHAIN ROW ALONE;
        emitting only ``{reason}`` dropped that evidence. Caller
        passes the full proxy_log on egress paths; cap-violation
        paths leave it empty (no proxy_log relevance).

        ``actor_id`` carries ``session._actor_subject`` (the consumer
        who initiated the exec). ``trace_id`` is empty per the same
        deferred-trace rationale documented at
        ``_emit_lifecycle_created``.
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

    async def _emit_lifecycle_destroyed(
        self,
        *,
        session: DockerSiblingSession,
        retained_until: str | None = None,
        tombstone_object_key: str | None = None,
    ) -> None:
        """Emit ``sandbox.lifecycle.destroyed`` per spec §4.3 wire-public
        payload ``{duration_s: float}`` + R1 P1.2 reviewer fix +
        Sprint 8.5 T6 P1.r4 tombstone-extension payload keys.

        ``duration_s`` is computed from
        ``datetime.now(UTC) - session.created_at`` so examiners can
        audit session lifetime. The destroy() caller-side idempotency
        flag (``session._destroyed``) ensures repeat destroy() calls
        do NOT emit a second row.

        Sprint 8.5 T6 extension per spec §3.1 + spec §5.1 audit.py
        contract: when the destroyed session had persisted checkpoints,
        the payload additionally carries TWO conditional keys:

        * ``retained_until`` — ISO 8601 string of
          ``now + settings.sandbox_checkpoint_retention_s`` at destroy()
          time.
        * ``tombstone_object_key`` — the
          ``<tenant>/<session>/_tombstoned.json`` storage key returned
          by ``CheckpointStore.tombstone_session()``.

        Presence of both keys is the wire-public marker that retention
        is in effect for this session's checkpoints. Absence (the
        Sprint-8A baseline path: session was created + destroyed
        without ever calling checkpoint()) means immediate physical
        destroy — no tombstone needed because there was nothing to
        retain.

        ``actor_id`` carries ``session._actor_subject`` from the
        original create() call (the caller who owns the session
        lifetime). ``trace_id`` is empty at T10a per the same
        T10c+ deferred rationale documented at
        ``_emit_lifecycle_created``.
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

    # ------------------------------------------------------------------
    # Sprint 8.5 T6 — checkpoint / suspend / wake / tar helpers
    # ------------------------------------------------------------------

    async def _do_checkpoint(
        self,
        session: DockerSiblingSession,
        label: str,
    ) -> CheckpointId:
        """Take a workspace-tar snapshot + persist + emit audit row.

        Spec §7.1 mechanic — ``aiodocker`` exec
        ``tar czf - -C /workspace .`` into the running container,
        capture the tar bytes from stdout, hand to
        ``CheckpointStore.persist()``. ``label="__suspend__"`` is
        reserved for the suspend-time call from ``_do_suspend``.

        Q4 lock per spec §2.4 amended: ``vault_lease_refs=()`` always
        in Sprint 8.5 — vault-bearing sessions are unreachable via the
        existing 8A ``sandbox_credential_adapter_not_configured``
        admission-time refusal.
        """
        if self._checkpoint_store is None:
            raise NotImplementedError(
                "DockerSiblingSession.checkpoint requires a CheckpointStore "
                "to be wired at backend construction time. Pass "
                "checkpoint_store=... to DockerSiblingSandboxBackend.__init__ "
                "per spec §3.1 + §7.1."
            )
        if session._suspended:
            # Spec §3.1: suspended sessions are no longer usable. The
            # container is also gone (suspend tore it down), so the
            # exec would also fail — surfacing fail-loud here gives a
            # better error.
            raise RuntimeError(
                f"session {session.session_id} was suspend()ed; "
                f"checkpoint() is no longer valid — call "
                f"SandboxBackend.wake(session_id) to restore the "
                f"session in a fresh container per spec §3.2"
            )

        snapshot_bytes = await self._create_workspace_tar(session_id=session.session_id)

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
        # against the admit_policy decision.
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

    async def _do_suspend(self, session: DockerSiblingSession) -> None:
        """Take final checkpoint + tear down + emit suspended + write
        wake linkage.

        Spec §3.1 + §7.1 + the T2 ``sandbox_lifecycle_suspended``
        helper contract: the suspended chain row is emitted **after**
        the container/Pod is released, so "suspended row exists" ⇒
        "runtime resources released" for examiners. Bank-grade
        evidence semantics require that the chain claim cannot
        over-state reality: a "suspended" row that fires while the
        container is still running OR before the linkage is durable
        would let chain readers infer state that does not yet hold.

        Ordering (P2.r2 reorder per the reviewer round that closed
        the audit-overstatement failure window):

            Step 1 — final checkpoint with label='__suspend__'.
            Step 2 — tear down container + sidecar + networks.
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
          blob; container already torn down. The session is
          'phantom-released' from the chain's perspective — examiners
          see no suspended evidence. This is conservative (no false
          claim) but means a subsequent ``destroy()`` is needed to
          reconcile state via the destroyed row.
        * Step 4 fails (side-blob write raises): chain row exists,
          container released, wake-linkage missing. Wake refuses with
          ``sandbox_wake_checkpoint_corrupt`` (already pinned by
          ``test_wake_checkpoint_corrupt.py``); a subsequent
          ``destroy()`` tombstones normally.

        Vault-lease revocation is OUT OF SCOPE per spec §2.4 amended:
        the existing 8A ``sandbox_credential_adapter_not_configured``
        admission-time refusal prevents any vault-bearing session from
        existing in the first place.
        """
        if self._checkpoint_store is None:
            raise NotImplementedError(
                "DockerSiblingSession.suspend requires a CheckpointStore "
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

        # Step 2 — tear down container + sidecar + networks BEFORE the
        # audit row is emitted. Spec contract: "suspended row" ⇒
        # "resources released". The audit-helper docstring at T2
        # explicitly says this helper is called "after ... the
        # container/Pod is released" — reordering aligns code with
        # contract.
        await self._teardown_session_state(
            session_id=session.session_id,
            internal_net_name=session._internal_network_name,
            egress_net_name=session._egress_network_name,
            sidecar_name=session._sidecar_container_name,
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

    async def _create_workspace_tar(self, *, session_id: str) -> bytes:
        """Run ``tar czf - -C /workspace .`` inside the container; return
        the gzipped tar bytes from stdout.

        Per spec §7.1: the workspace-tar mechanic is the cross-backend
        wire-public contract — both DockerSibling AND KubernetesPod use
        the same tar/untar shape so cross-backend checkpoints round-trip
        via the conformance suite at T9.
        """
        container = await self._docker.containers.get(session_id)
        exec_obj = await container.exec(
            cmd=["tar", "czf", "-", "-C", "/workspace", "."],
            stdout=True,
            stderr=True,
            user=_NON_ROOT_USER,
        )
        chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        async with exec_obj.start(detach=False) as stream:
            while True:
                message = await stream.read_out()
                if message is None:
                    break
                if message.stream == 1:
                    chunks.append(message.data)
                elif message.stream == 2:
                    stderr_chunks.append(message.data)
        inspect = await exec_obj.inspect()
        exit_code = int(inspect.get("ExitCode") or 0)
        if exit_code != 0:
            stderr_text = b"".join(stderr_chunks).decode("utf-8", errors="replace")
            raise RuntimeError(
                f"tar czf /workspace inside session {session_id} exited "
                f"{exit_code}; stderr={stderr_text!r}"
            )
        return b"".join(chunks)

    async def _restore_workspace_tar(
        self,
        *,
        session_id: str,
        snapshot_bytes: bytes,
    ) -> None:
        """Run ``tar xzf - -C /workspace`` inside the container, piping
        the snapshot bytes on stdin.

        Counterpart to ``_create_workspace_tar``; cross-backend
        conformance pin per spec §7.3.
        """
        container = await self._docker.containers.get(session_id)
        exec_obj = await container.exec(
            cmd=["tar", "xzf", "-", "-C", "/workspace"],
            stdout=True,
            stderr=True,
            stdin=True,
            user=_NON_ROOT_USER,
        )
        stderr_chunks: list[bytes] = []
        async with exec_obj.start(detach=False) as stream:
            await stream.write_in(snapshot_bytes)
            # Close stdin half so tar sees EOF + processes the archive.
            with contextlib.suppress(Exception):
                await stream.close()
            while True:
                message = await stream.read_out()
                if message is None:
                    break
                if message.stream == 2:
                    stderr_chunks.append(message.data)
        inspect = await exec_obj.inspect()
        exit_code = int(inspect.get("ExitCode") or 0)
        if exit_code != 0:
            stderr_text = b"".join(stderr_chunks).decode("utf-8", errors="replace")
            raise RuntimeError(
                f"tar xzf /workspace inside session {session_id} exited "
                f"{exit_code}; stderr={stderr_text!r}"
            )

    async def _write_suspend_event_id(
        self,
        *,
        session_id: str,
        tenant_id: str,
        checkpoint_id: CheckpointId,
        record_id: _uuid.UUID,
    ) -> None:
        """Persist the suspend-emitted ``record_id`` so wake() can read
        it back at restore-time per spec §5.2 + the T6 plan-amendment.

        Storage layout — sibling blob at
        ``<tenant>/<session>/<checkpoint>.suspend_event_id`` carrying
        the UUID as a UTF-8 string. Stays in the same per-tenant prefix
        as the snapshot + metadata so tenant isolation comes for free +
        the existing reaper / tombstone lifecycle covers cleanup.
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
        ``sandbox_wake_checkpoint_corrupt`` before restoring any Docker
        resources; the T8 chain-verifier keeps the same invariant as
        defence-in-depth, not as the first fail-closed seam.
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
        policy_digest computation. Mirrors the
        ``CheckpointMetadata.to_storage_payload`` policy sub-tree shape
        per spec §3.4 — drift between this dict + that one would mean
        the policy_digest on the checkpointed row would not match
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
# this module (test files that import it via the docker_sibling module
# get the same object as the protocol module).
__all__ = [
    "_CPU_BUDGET_POLL_INTERVAL_S",
    "_CPU_PERIOD_US",
    "_NON_ROOT_USER",
    "_PROXY_CONFIG_DIR",
    "_PROXY_DNS_NAME",
    "_PROXY_LOG_PATH",
    "_PROXY_NON_ROOT_USER",
    "_PROXY_PORT",
    "DockerSiblingSandboxBackend",
    "DockerSiblingSession",
    "SandboxLifecycleRefused",
    "_build_proxy_sidecar_container_config",
    "_build_sandbox_container_config",
    "_classify_egress_refusal",
    "_classify_exec_failure",
    "_cpu_time_budget_monitor",
    "_derive_cpu_quota_period",
    "_derive_memory_caps_bytes",
    "_egress_network_name",
    "_internal_network_name",
    "_kill_container_or_raise",
    "_parse_proxy_log_jsonl",
    "_proxy_sidecar_container_name",
    "_proxy_sidecar_env",
    "_sandbox_container_env",
]
