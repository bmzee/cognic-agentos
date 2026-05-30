"""T30/T14.1 — cross-backend egress-proxy sidecar-env drift detector.

The Docker (``docker_sibling``) and K8s (``kubernetes_pod``) backends MUST
derive the proxy sidecar's launch env from the SAME
``render_proxy_config(...).to_env()`` source of truth, so the canonical
``cognic/sandbox-egress-proxy`` entrypoint sees identical SESSION_ID +
ALLOW_LIST regardless of substrate.

The Z4 live audit caught exactly the drift class this detector pins: K8s
silently lacked the sidecar env Docker already had, so the canonical proxy
refused startup and the backend's proxy-log readback fail-closed with
``SandboxPolicyViolated(egress_audit_unreadable)``.

Test-only equality assertion per
``feedback_drift_detector_test_only_no_runtime_import`` — neither backend
runtime-imports the other; this test imports both helpers and asserts they
return identical dicts for the same ``(policy, session_id)``. Both modules'
``_proxy_sidecar_env`` return the raw two-key ``to_env()`` dict; the K8s
container-shape conversion (``[{"name", "value"}]``) happens later in
``_build_pod_spec`` and is pinned separately in
``test_kubernetes_pod_pure_helpers.py``.
"""

from __future__ import annotations

import pytest

# Importing BOTH backends requires BOTH optional extras. Skip cleanly on a
# kernel-only venv; runs under the dev/CI ``uv sync --all-extras`` invariant.
pytest.importorskip("aiodocker")
pytest.importorskip("kubernetes_asyncio")

from cognic_agentos.sandbox import SandboxPolicy
from cognic_agentos.sandbox.backends.docker_sibling import (
    _proxy_sidecar_env as _docker_proxy_sidecar_env,
)
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    _proxy_sidecar_env as _k8s_proxy_sidecar_env,
)

_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=("httpbin.org", "api.example.com"),
    vault_path=None,
)


def test_docker_and_k8s_proxy_sidecar_env_are_identical() -> None:
    docker_env = _docker_proxy_sidecar_env(policy=_POLICY, session_id="s-parity")
    k8s_env = _k8s_proxy_sidecar_env(policy=_POLICY, session_id="s-parity")
    assert docker_env == k8s_env
    # Both must carry exactly the two keys the canonical entrypoint reads.
    assert set(k8s_env.keys()) == {"ALLOW_LIST", "SESSION_ID"}


def test_k8s_proxy_sidecar_env_carries_session_id_and_allow_list() -> None:
    env = _k8s_proxy_sidecar_env(policy=_POLICY, session_id="s-x")
    assert env["SESSION_ID"] == "s-x"
    assert "httpbin.org" in env["ALLOW_LIST"]
    assert "api.example.com" in env["ALLOW_LIST"]
