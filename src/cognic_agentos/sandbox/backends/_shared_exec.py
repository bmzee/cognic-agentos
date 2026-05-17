"""Sprint 8B T8B-c — shared exec-classification + proxy-log failure type.

Authoritative home for two cross-backend helpers consumed by
:mod:`cognic_agentos.sandbox.backends.kubernetes_pod`. The closed-
enum precedence in :func:`_classify_exec_failure` is wire-protocol-
public per :data:`cognic_agentos.sandbox.protocol.SandboxPolicyViolationReason`
— a backend that produced a different precedence would silently
drift the wire-protocol-public reason for the same observed end-
state.

Drift contract per ``feedback_drift_detector_test_only_no_runtime_import``:
:mod:`cognic_agentos.sandbox.backends.docker_sibling` carries its
OWN inline copies of ``_classify_exec_failure`` + ``_ProxyLogReadFailure``
(unchanged from Sprint 8A; the docker_sibling module is a stop-rule
isolation boundary per AGENTS.md and is NOT modified by 8B). A
test-only drift detector at
``tests/unit/sandbox/backends/test_exec_classification_cross_backend_drift.py``
imports the helper from BOTH modules + asserts lockstep behaviour
across the 5-arm precedence matrix. A new closed-enum reason or a
changed precedence MUST land in both modules with the same shape,
caught at test time before commit.

The :class:`_ProxyLogReadFailure` internal exception type is
similarly mirrored — both backends' exec() body catches it +
translates to the wire-public ``egress_audit_unreadable`` violation
+ raises ``SandboxPolicyViolated``. T10c R1 P1.2 (DockerSibling)
established the fail-closed contract; T8B-c carries the same
contract to KubernetesPod via this module.

No external dependencies (no aiodocker / no kubernetes_asyncio).
The sandbox-k8s extra envelope can import this module unconditionally
without forcing the sandbox-docker extra to be installed.
"""

from __future__ import annotations

from cognic_agentos.sandbox.protocol import SandboxPolicyViolationReason


def _classify_exec_failure(
    *,
    exit_code: int,
    oom_killed: bool,
    walltime_exceeded: bool,
    cpu_budget_exceeded: bool,
) -> SandboxPolicyViolationReason | None:
    """Pure-functional classifier — translate exec()'s observed
    end-state into a ``SandboxPolicyViolationReason`` or None.

    Precedence (highest first):
    1. ``walltime_exceeded`` → ``"walltime_cap_exceeded"`` — AgentOS
       killed the container/pod; exit_code + oom_killed are cascade
       effects of the kill, NOT the cause.
    2. ``cpu_budget_exceeded`` → ``"cpu_time_budget_exceeded"`` —
       same cascade rationale; the cpu-budget kill takes precedence
       over OOM signals it caused.
    3. ``exit_code == 137 AND oom_killed`` → ``"memory_cap_exceeded"``
       — the kernel's oom_killer fired, NOT AgentOS. Exit 137 alone
       without ``oom_killed`` is NOT enough (could be manual SIGKILL
       from any source); the backend-authoritative OOM flag is the
       only acceptable signal. For DockerSibling this is
       ``container.show().State.OOMKilled``; for KubernetesPod this
       is ``ContainerStatus.state.terminated.reason == "OOMKilled"``.
    4. Otherwise → None (green-path; user-code exit code returned
       to the caller).

    Pure-functional + non-env-gated unit-testable. The env-gated cap
    tests at ``tests/unit/sandbox/backends/test_<backend>_resource_caps.py``
    exercise the actual kernel enforcement on each backend.
    """
    if walltime_exceeded:
        return "walltime_cap_exceeded"
    if cpu_budget_exceeded:
        return "cpu_time_budget_exceeded"
    if exit_code == 137 and oom_killed:
        return "memory_cap_exceeded"
    return None


class _ProxyLogReadFailure(Exception):
    """Internal exception raised by either backend's
    ``_read_proxy_log_from_sidecar`` when it cannot prove the
    proxy_log is complete (T10c R1 P1.2 + T8B-c carry-forward).

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


__all__ = [
    "_ProxyLogReadFailure",
    "_classify_exec_failure",
]
