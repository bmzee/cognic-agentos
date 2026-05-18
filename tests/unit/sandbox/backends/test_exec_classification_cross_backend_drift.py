"""Sprint 8B T8B-c — cross-backend exec-classification drift detector.

Per ``feedback_drift_detector_test_only_no_runtime_import``: two
production modules each carry their own copy of
``_classify_exec_failure`` (the docker_sibling one is unchanged
from Sprint 8A; the kubernetes_pod one delegates to
``sandbox.backends._shared_exec``). A test imports BOTH and
asserts behavioural lockstep across the 5-arm precedence matrix.

This is the load-bearing pin for the wire-protocol-public
``SandboxPolicyViolationReason`` precedence: a future refactor that
changed one module without the other would silently drift the
backend's emitted closed-enum reason for the same observed end-
state. The drift would not surface in either backend's narrow
unit-test suite (each tests its own copy in isolation); only this
cross-import test catches it.

Per AGENTS.md stop rules — ``sandbox/backends/docker_sibling.py`` is
a stop-rule isolation boundary that 8B intentionally does NOT
modify; this test is the contract that pins behavioural equivalence
WITHOUT touching either production module.
"""

from __future__ import annotations

import pytest

pytest.importorskip("aiodocker")
pytest.importorskip("kubernetes_asyncio")

from cognic_agentos.sandbox.backends._shared_exec import (
    _classify_exec_failure as _shared_classify,
)
from cognic_agentos.sandbox.backends._shared_exec import (
    _ProxyLogReadFailure as _SharedProxyLogReadFailure,
)
from cognic_agentos.sandbox.backends.docker_sibling import (
    _classify_exec_failure as _docker_classify,
)
from cognic_agentos.sandbox.backends.docker_sibling import (
    _ProxyLogReadFailure as _DockerProxyLogReadFailure,
)


class TestClassifyExecFailureLockstep:
    """5-arm precedence matrix from the wire-protocol-public
    ``SandboxPolicyViolationReason`` closed-enum. Each row in the
    parametrised matrix below produces the SAME closed-enum value
    across the docker_sibling + _shared_exec implementations.
    """

    @pytest.mark.parametrize(
        "exit_code,oom_killed,walltime_exceeded,cpu_budget_exceeded,expected",
        [
            # Green path
            (0, False, False, False, None),
            # Walltime takes precedence over OOM + budget cascades
            (137, True, True, False, "walltime_cap_exceeded"),
            (137, True, True, True, "walltime_cap_exceeded"),
            # cpu-budget takes precedence over OOM (when not walltime)
            (137, True, False, True, "cpu_time_budget_exceeded"),
            # OOM alone — kernel oom_killer fired
            (137, True, False, False, "memory_cap_exceeded"),
            # exit 137 without OOM is NOT classified as OOM
            (137, False, False, False, None),
            # User-code error exit — not a violation
            (1, False, False, False, None),
            # Edge: exit 0 + cap signals (defensive — kill cascade)
            (0, False, True, False, "walltime_cap_exceeded"),
            (0, False, False, True, "cpu_time_budget_exceeded"),
        ],
    )
    def test_both_backends_classify_identically(
        self,
        exit_code: int,
        oom_killed: bool,
        walltime_exceeded: bool,
        cpu_budget_exceeded: bool,
        expected: str | None,
    ) -> None:
        docker_reason = _docker_classify(
            exit_code=exit_code,
            oom_killed=oom_killed,
            walltime_exceeded=walltime_exceeded,
            cpu_budget_exceeded=cpu_budget_exceeded,
        )
        shared_reason = _shared_classify(
            exit_code=exit_code,
            oom_killed=oom_killed,
            walltime_exceeded=walltime_exceeded,
            cpu_budget_exceeded=cpu_budget_exceeded,
        )
        # Behavioural lockstep — both must produce identical outputs
        assert docker_reason == shared_reason == expected


class TestProxyLogReadFailureLockstep:
    """Both backends define their own ``_ProxyLogReadFailure`` exception
    type. The fail-closed contract requires each backend's exec()
    body to catch its OWN local type + translate to the wire-public
    ``egress_audit_unreadable`` violation. A drift detector that
    forced them to be the SAME class would be a runtime cross-module
    import — forbidden per the doctrine. Instead, pin that both
    types share the same essential shape (Exception subclass) so a
    refactor that broke either side would surface here."""

    def test_both_proxy_log_read_failure_types_are_exception_subclasses(self) -> None:
        assert issubclass(_DockerProxyLogReadFailure, Exception)
        assert issubclass(_SharedProxyLogReadFailure, Exception)

    def test_both_types_carry_message_on_str(self) -> None:
        d = _DockerProxyLogReadFailure("docker side")
        s = _SharedProxyLogReadFailure("shared side")
        assert "docker side" in str(d)
        assert "shared side" in str(s)
