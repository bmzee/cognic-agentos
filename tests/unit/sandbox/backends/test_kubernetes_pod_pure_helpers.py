"""Sprint 8B T8B-b — KubernetesPodSandboxBackend pure-helper unit tests.

NON-env-gated (runs in default CI under ``uv sync --all-extras``).
Mirrors the Sprint-8A pattern at
``tests/unit/sandbox/backends/test_docker_sibling_pure_helpers.py`` —
pins the pure-functional helpers that build Pod specs, NetworkPolicy
specs, and SecurityContext dictionaries for the K8s/OpenShift backend.

Per the canonical-artifact doctrine
(``feedback_canonical_artifact_not_oss_substitute``): the tests use
FAKE image digests (``sha256:`` + ``"a" * 64`` etc.) — the canonical
Sprint-8A image catalog (T6) publishes the real digests at supply-
chain pipeline build time; these tests do NOT pull real images. Per
the canonical-artifact doctrine the egress-proxy sidecar image
referenced in the pod spec IS the real ``cognic/sandbox-egress-proxy``
artifact (NEVER substituted by an OSS proxy at runtime); the unit
tests assert the canonical name prefix without contacting any
registry.

OpenShift compatibility per ADR-004 amendment §30: SecurityContext
omits ``privileged`` (defends against future K8s API default changes)
+ omits ``runAsUser`` (OpenShift restricted-v2 SCC's MustRunAsRange
assigns the UID from the namespace-allocated range; hard-coded
``runAsUser`` collides). Both omissions are PINNED explicitly so
a refactor that re-adds them fails CI rather than silently shipping
an OpenShift-incompatible spec.
"""

from __future__ import annotations

import pytest

# Per feedback_verify_dep_availability_at_implementation — gracefully
# degrade collection without the sandbox-k8s extra so kernel-only
# venvs do not fail collection on this file. With the extra installed
# (the dev/CI invariant via ``uv sync --all-extras``) the tests run.
pytest.importorskip("kubernetes_asyncio")

from cognic_agentos.sandbox import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.backends.kubernetes_pod import (
    _PROXY_PORT,
    _PROXY_SIDECAR_CONTAINER_NAME,
    _SANDBOX_CONTAINER_NAME,
    _SESSION_ID_LABEL,
    _TENANT_ID_LABEL,
    _build_network_policy_spec,
    _build_pod_spec,
    _build_security_context,
    _network_policy_name,
    _pod_name,
)

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_POLICY = SandboxPolicy(
    cpu_cores=0.5,
    cpu_time_budget_s=None,
    memory_mb=256,
    walltime_s=30.0,
    runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
    egress_allow_list=("httpbin.org", "api.example.com"),
    vault_path=None,
)

_PACK_CTX = PackAdmissionContext(
    pack_id="cognic.test_pack",
    pack_version="v1.0.0",
    pack_artifact_digest="sha256:" + "1" * 64,
    risk_tier="internal_write",
    declares_dynamic_install=False,
    profile="production",
)


# ---------------------------------------------------------------------------
# Name helpers — RFC 1123 label/name compliance + per-session uniqueness
# ---------------------------------------------------------------------------


class TestPodAndNetworkPolicyNaming:
    """Per ADR-004 amendment + K8s naming conventions: pod + network
    policy names MUST satisfy RFC 1123 (lowercase a-z, 0-9, hyphens;
    no underscores). Session_id (uuid4 hex) is already RFC 1123 safe
    once prefixed with ``sb-``."""

    def test_pod_name_is_session_id_prefixed_with_sb(self) -> None:
        """Deterministic per-session pod name. ``sb-`` prefix
        distinguishes AgentOS sandbox pods from other pods in the same
        namespace + keeps the name under K8s 253-char limit (uuid4
        hex is 32 chars; ``sb-`` + 32 = 35 chars)."""
        name = _pod_name("abcd1234efgh5678ijkl9012mnop3456")
        assert name == "sb-abcd1234efgh5678ijkl9012mnop3456"

    def test_pod_name_is_deterministic_for_same_session_id(self) -> None:
        """Idempotent pod creation needs deterministic names so a
        retry after a transient apiserver hiccup does not orphan a
        previous pod under a different name."""
        session_id = "deadbeef" * 4
        assert _pod_name(session_id) == _pod_name(session_id)

    def test_pod_name_lowercase_only(self) -> None:
        """RFC 1123 — pod names MUST be lowercase. Uuid4 hex is already
        lowercase; the helper does not transform."""
        name = _pod_name("aaaa1111bbbb2222cccc3333dddd4444")
        assert name == name.lower()

    def test_network_policy_name_is_pod_name(self) -> None:
        """1:1 mapping per-pod ↔ per-NetworkPolicy keeps the lifecycle
        coupled — teardown removes both under the same session_id
        prefix without a separate lookup."""
        session_id = "deadbeef" * 4
        assert _network_policy_name(session_id) == _pod_name(session_id)

    def test_two_sessions_get_distinct_pod_names(self) -> None:
        """Per-session isolation MUST produce distinct pod names."""
        name_a = _pod_name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        name_b = _pod_name("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        assert name_a != name_b


# ---------------------------------------------------------------------------
# Label conventions — _SESSION_ID_LABEL + _TENANT_ID_LABEL
# ---------------------------------------------------------------------------


class TestLabelConventions:
    """Label keys are wire-protocol-adjacent — bank ops tooling reads
    these to correlate pods with AgentOS sessions. Drift breaks
    operator dashboards silently. Pinned as constants."""

    def test_session_id_label_matches_namespace_convention(self) -> None:
        """Matches the Sprint-8A docker_sibling label scheme prefix
        (``cognic.agentos.sandbox.*``) so a bank running BOTH backends
        in different namespaces can grep with the same selector."""
        assert _SESSION_ID_LABEL == "cognic.agentos.sandbox.session_id"

    def test_tenant_id_label_matches_namespace_convention(self) -> None:
        assert _TENANT_ID_LABEL == "cognic.agentos.sandbox.tenant_id"


# ---------------------------------------------------------------------------
# SecurityContext — OpenShift restricted SCC compatibility (ADR-004 §30)
# ---------------------------------------------------------------------------


class TestBuildSecurityContext:
    """OpenShift-compatible SecurityContext per ADR-004 §30.

    No --privileged; matches restricted-by-default SCC. Non-root user
    via runAsNonRoot=True. capabilities.drop=[ALL].
    readOnlyRootFilesystem=True. allowPrivilegeEscalation=False.

    Two intentional OMISSIONS pinned as load-bearing:
    * ``privileged`` is NOT set (NOT False — absent). Defends against
      future K8s API changes where the default might change.
    * ``runAsUser`` is NOT set. OpenShift restricted-v2 SCC's
      MustRunAsRange policy assigns the UID from the namespace-
      allocated range; a hard-coded ``runAsUser=65534`` collides
      against the OpenShift admission webhook.
    """

    def test_security_context_drops_all_capabilities(self) -> None:
        ctx = _build_security_context()
        assert ctx["capabilities"]["drop"] == ["ALL"]

    def test_security_context_forbids_privilege_escalation(self) -> None:
        ctx = _build_security_context()
        assert ctx["allowPrivilegeEscalation"] is False

    def test_security_context_requires_non_root(self) -> None:
        ctx = _build_security_context()
        assert ctx["runAsNonRoot"] is True

    def test_security_context_uses_readonly_root_filesystem(self) -> None:
        ctx = _build_security_context()
        assert ctx["readOnlyRootFilesystem"] is True

    def test_security_context_omits_privileged_field(self) -> None:
        """OpenShift restricted SCC refuses privileged=True. The
        pod spec MUST NOT carry the field at all (omission is safer
        than explicit False — defends against future K8s API changes
        that might default differently). Pinned by absence."""
        ctx = _build_security_context()
        assert "privileged" not in ctx

    def test_security_context_omits_run_as_user_for_openshift_compat(
        self,
    ) -> None:
        """OpenShift restricted-v2 SCC assigns runAsUser from the
        namespace-allocated UID range (MustRunAsRange). Hard-coded
        runAsUser=65534 collides on OpenShift; namespace assignment
        is the canonical pattern. The pod spec MUST NOT set
        runAsUser explicitly."""
        ctx = _build_security_context()
        assert "runAsUser" not in ctx

    def test_security_context_omits_run_as_group_for_openshift_compat(
        self,
    ) -> None:
        """Same MustRunAsRange rationale as runAsUser — OpenShift
        assigns the GID from the namespace-allocated range."""
        ctx = _build_security_context()
        assert "runAsGroup" not in ctx


# ---------------------------------------------------------------------------
# Pod spec — two-container Pod (sandbox + egress proxy sidecar via
# shared Pod localhost per feedback_sandbox_network_isolation_precision)
# ---------------------------------------------------------------------------


class TestBuildPodSpec:
    """Two-container Pod sharing localhost — sandbox + egress proxy
    sidecar. Egress posture per
    ``feedback_sandbox_network_isolation_precision``: containers
    inside a single Pod share network namespace (localhost-reachable);
    the sandbox's ``HTTP_PROXY`` env points at the sidecar via
    ``http://localhost:<port>``. NO separate ClusterIP Service.
    Per-session NetworkPolicy (built separately by
    ``_build_network_policy_spec``) denies all external egress so
    the sidecar's proxy port is the ONLY outbound path."""

    def test_pod_spec_apiversion_and_kind(self) -> None:
        spec = _build_pod_spec(policy=_POLICY, session_id="s-1", tenant_id="t-1")
        assert spec["apiVersion"] == "v1"
        assert spec["kind"] == "Pod"

    def test_pod_spec_name_matches_pod_name_helper(self) -> None:
        spec = _build_pod_spec(
            policy=_POLICY,
            session_id="abcd1234efgh5678ijkl9012mnop3456",
            tenant_id="t-1",
        )
        assert spec["metadata"]["name"] == _pod_name("abcd1234efgh5678ijkl9012mnop3456")

    def test_pod_spec_carries_session_id_and_tenant_id_labels(self) -> None:
        """Labels are how the NetworkPolicy podSelector keys the
        per-session egress policy to this pod. Drift would silently
        unbind the NetworkPolicy from the pod — every session would
        get default-namespace egress (no lockdown)."""
        spec = _build_pod_spec(policy=_POLICY, session_id="s-1", tenant_id="t-1")
        labels = spec["metadata"]["labels"]
        assert labels[_SESSION_ID_LABEL] == "s-1"
        assert labels[_TENANT_ID_LABEL] == "t-1"

    def test_pod_spec_has_exactly_two_containers(self) -> None:
        spec = _build_pod_spec(policy=_POLICY, session_id="s-1", tenant_id="t-1")
        assert len(spec["spec"]["containers"]) == 2

    def test_pod_spec_container_names_are_sandbox_and_egress_proxy(self) -> None:
        spec = _build_pod_spec(policy=_POLICY, session_id="s-1", tenant_id="t-1")
        names = {c["name"] for c in spec["spec"]["containers"]}
        assert names == {_SANDBOX_CONTAINER_NAME, _PROXY_SIDECAR_CONTAINER_NAME}

    def test_pod_spec_sandbox_container_uses_policy_runtime_image(self) -> None:
        spec = _build_pod_spec(policy=_POLICY, session_id="s-1", tenant_id="t-1")
        sandbox = next(
            c for c in spec["spec"]["containers"] if c["name"] == _SANDBOX_CONTAINER_NAME
        )
        assert sandbox["image"] == _POLICY.runtime_image

    def test_pod_spec_proxy_sidecar_uses_canonical_egress_image(self) -> None:
        """Per feedback_canonical_artifact_not_oss_substitute — the
        egress proxy image MUST be the canonical
        cognic/sandbox-egress-proxy artifact (NOT a substituted OSS
        proxy). The image string carries a sha256 digest suffix so
        the kubelet pulls the exact bytes the supply-chain pipeline
        signed."""
        spec = _build_pod_spec(policy=_POLICY, session_id="s-1", tenant_id="t-1")
        proxy = next(
            c for c in spec["spec"]["containers"] if c["name"] == _PROXY_SIDECAR_CONTAINER_NAME
        )
        assert proxy["image"].startswith("cognic/sandbox-egress-proxy:")
        assert "@sha256:" in proxy["image"]

    def test_pod_spec_sandbox_container_sets_http_proxy_to_localhost(self) -> None:
        """Per feedback_sandbox_network_isolation_precision — the two
        containers share network namespace inside a single Pod; the
        sandbox's HTTP_PROXY targets the proxy sidecar via shared
        localhost. NOT a separate ClusterIP Service."""
        spec = _build_pod_spec(policy=_POLICY, session_id="s-1", tenant_id="t-1")
        sandbox = next(
            c for c in spec["spec"]["containers"] if c["name"] == _SANDBOX_CONTAINER_NAME
        )
        env_dict = {e["name"]: e["value"] for e in sandbox.get("env", [])}
        assert env_dict["HTTP_PROXY"] == f"http://localhost:{_PROXY_PORT}"
        assert env_dict["HTTPS_PROXY"] == f"http://localhost:{_PROXY_PORT}"

    def test_pod_spec_does_not_set_no_proxy(self) -> None:
        """Per Sprint 8A T10a doctrine — NO_PROXY env var would
        create an egress-bypass class the allow-list does not cover.
        Pod spec MUST NOT set NO_PROXY (or its lowercase variant)."""
        spec = _build_pod_spec(policy=_POLICY, session_id="s-1", tenant_id="t-1")
        sandbox = next(
            c for c in spec["spec"]["containers"] if c["name"] == _SANDBOX_CONTAINER_NAME
        )
        env_dict = {e["name"]: e["value"] for e in sandbox.get("env", [])}
        assert "NO_PROXY" not in env_dict
        assert "no_proxy" not in env_dict

    def test_pod_spec_sandbox_container_carries_security_context(self) -> None:
        """Per ADR-004 §30 — both containers run with the OpenShift-
        compatible SecurityContext. Drift on either container weakens
        the sandbox boundary."""
        spec = _build_pod_spec(policy=_POLICY, session_id="s-1", tenant_id="t-1")
        sandbox = next(
            c for c in spec["spec"]["containers"] if c["name"] == _SANDBOX_CONTAINER_NAME
        )
        assert sandbox["securityContext"] == _build_security_context()

    def test_pod_spec_proxy_sidecar_carries_security_context(self) -> None:
        spec = _build_pod_spec(policy=_POLICY, session_id="s-1", tenant_id="t-1")
        proxy = next(
            c for c in spec["spec"]["containers"] if c["name"] == _PROXY_SIDECAR_CONTAINER_NAME
        )
        assert proxy["securityContext"] == _build_security_context()

    def test_pod_spec_restart_policy_is_never(self) -> None:
        """Per ADR-004 — sandbox pods are one-shot; a crashed
        container MUST NOT be silently restarted (the failure
        signal would be lost). Restart policy Never matches the
        per-session lifetime contract."""
        spec = _build_pod_spec(policy=_POLICY, session_id="s-1", tenant_id="t-1")
        assert spec["spec"]["restartPolicy"] == "Never"

    def test_pod_spec_sandbox_container_carries_resource_limits(self) -> None:
        """Per ADR-004 + spec §7 — sandbox container's resources.limits
        derives from policy.cpu_cores + policy.memory_mb. The kubelet
        + the underlying CRI runtime enforce the cgroup caps; an OOM
        kill at the memory limit surfaces as exit_code 137 +
        ContainerStatus.lastState.terminated.reason=OOMKilled
        (handled at exec time in T8B-c)."""
        spec = _build_pod_spec(policy=_POLICY, session_id="s-1", tenant_id="t-1")
        sandbox = next(
            c for c in spec["spec"]["containers"] if c["name"] == _SANDBOX_CONTAINER_NAME
        )
        limits = sandbox["resources"]["limits"]
        # cpu_cores=0.5 → "500m" (millicores; K8s canonical form)
        assert limits["cpu"] == "500m"
        # memory_mb=256 → "256Mi" (Mebibytes; K8s canonical form)
        assert limits["memory"] == "256Mi"


# ---------------------------------------------------------------------------
# NetworkPolicy spec — per-session deny-all egress lockdown
# ---------------------------------------------------------------------------


class TestBuildNetworkPolicySpec:
    """Per-session NetworkPolicy per spec §10.1 + ADR-004 amendment.

    Pod-internal localhost traffic (sandbox → proxy sidecar via
    ``http://localhost:<port>``) is intra-pod and NOT subject to
    NetworkPolicy. The NetworkPolicy locks down the POD-EXTERNAL
    egress surface: the sandbox container's only legitimate
    out-of-pod traffic is via the proxy sidecar's upstream
    destinations, which the cluster-wide egress-proxy NetworkPolicy
    governs separately (Sprint 14 deployment kit). The per-session
    policy here ensures the SANDBOX container cannot reach anything
    OUTSIDE the pod directly.

    K8s NetworkPolicy semantics: a policy with ``policyTypes:
    [Egress]`` and NO ``egress`` rules denies ALL egress for the
    selected pods (deny-by-default). This is the K8s-canonical
    pattern for an egress lockdown.
    """

    def test_network_policy_apiversion_and_kind(self) -> None:
        spec = _build_network_policy_spec(session_id="s-1", tenant_id="t-1")
        assert spec["apiVersion"] == "networking.k8s.io/v1"
        assert spec["kind"] == "NetworkPolicy"

    def test_network_policy_name_matches_pod_name(self) -> None:
        """1:1 lifecycle coupling — teardown removes the policy
        under the same name the pod uses, no separate lookup."""
        spec = _build_network_policy_spec(
            session_id="abcd1234efgh5678ijkl9012mnop3456", tenant_id="t-1"
        )
        assert spec["metadata"]["name"] == _network_policy_name("abcd1234efgh5678ijkl9012mnop3456")

    def test_network_policy_targets_session_pod_via_label_selector(self) -> None:
        """podSelector matches the pod's session_id label. Drift
        between this label and the pod spec's label silently
        unbinds the policy → pod runs with default-namespace egress
        (NO lockdown)."""
        spec = _build_network_policy_spec(session_id="s-1", tenant_id="t-1")
        assert spec["spec"]["podSelector"]["matchLabels"][_SESSION_ID_LABEL] == "s-1"

    def test_network_policy_carries_tenant_id_label(self) -> None:
        """Tenant label on the NetworkPolicy itself (NOT on the
        podSelector — that keys on session_id only) so bank operator
        tooling can list per-tenant policies."""
        spec = _build_network_policy_spec(session_id="s-1", tenant_id="t-1")
        assert spec["metadata"]["labels"][_TENANT_ID_LABEL] == "t-1"

    def test_network_policy_declares_egress_type(self) -> None:
        """policyTypes MUST include Egress; K8s ignores egress rules
        on a policy that does not declare the type."""
        spec = _build_network_policy_spec(session_id="s-1", tenant_id="t-1")
        assert "Egress" in spec["spec"]["policyTypes"]

    def test_network_policy_denies_all_egress_by_default(self) -> None:
        """Empty/missing ``egress`` rules + policyTypes=[Egress] is
        the K8s deny-all-egress pattern. Pinned by ABSENCE — adding
        an ``egress: [...]`` allow rule here would silently grant
        the sandbox container per-rule egress, defeating the
        lockdown."""
        spec = _build_network_policy_spec(session_id="s-1", tenant_id="t-1")
        # Either egress key is omitted OR it's present but empty list.
        egress_rules = spec["spec"].get("egress", [])
        assert egress_rules == [], (
            "Per-session NetworkPolicy MUST have NO egress allow rules "
            "— deny-all is the lockdown contract. Per-session allow "
            "rules would let the sandbox container reach external "
            "endpoints directly, bypassing the proxy sidecar."
        )

    def test_two_sessions_get_distinct_network_policy_selectors(self) -> None:
        """Per-session isolation — policy A MUST NOT select pod B."""
        spec_a = _build_network_policy_spec(session_id="aaa", tenant_id="t-1")
        spec_b = _build_network_policy_spec(session_id="bbb", tenant_id="t-1")
        sel_a = spec_a["spec"]["podSelector"]["matchLabels"]
        sel_b = spec_b["spec"]["podSelector"]["matchLabels"]
        assert sel_a != sel_b


# ---------------------------------------------------------------------------
# Module discoverability + sandbox-k8s extra import guard
# ---------------------------------------------------------------------------


class TestSandboxK8sExtraImportGuard:
    """When ``kubernetes_asyncio`` is not installed (deployer chose
    DockerSibling-only deployment without ``-e .[sandbox-k8s]``),
    importing the backend module surfaces a structured
    NotImplementedError pointing at the extra. The kernel package
    itself stays importable — only KubernetesPodSandboxBackend
    construction fails-loud.

    With the extra INSTALLED (the dev/CI environment), the import
    succeeds + the class is constructable. This test verifies the
    happy-path import; the absent-extra path is covered by a
    separate integration test in the deployment kit at Sprint 14."""

    def test_kubernetespod_class_importable_with_sandbox_k8s_extra(self) -> None:
        from cognic_agentos.sandbox import KubernetesPodSandboxBackend

        assert KubernetesPodSandboxBackend is not None
        assert callable(KubernetesPodSandboxBackend)


class TestModuleIsCriticalControls:
    """T8B-b lands the K8s backend module; T8B-d promotes it to the
    durable critical-controls coverage gate. This test pins the
    module is discoverable + its public surface is on the package."""

    def test_backend_class_re_exported_from_sandbox_package(self) -> None:
        from cognic_agentos.sandbox import KubernetesPodSandboxBackend
        from cognic_agentos.sandbox.backends.kubernetes_pod import (
            KubernetesPodSandboxBackend as DirectImport,
        )

        # Re-export same object (catches duplicate-declaration class).
        assert KubernetesPodSandboxBackend is DirectImport


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
