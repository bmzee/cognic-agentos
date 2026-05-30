"""Sprint 8A T10a — DockerSiblingSandboxBackend pure-helper unit tests.

NON-env-gated (run in default CI). Pins the small pure-functional
helpers that build container names, network names, env dicts, and
container config dicts. The env-gated integration tests at
``test_docker_sibling_lifecycle.py`` cover the same helpers
end-to-end against a real Docker daemon; these unit tests cover the
helpers when the daemon is not available.

Per spec §10.1: per-session internal Docker network with
``Internal=true`` (no external gateway). Sandbox on internal network
only; proxy sidecar on internal + egress networks. Sandbox env
``HTTP_PROXY`` / ``HTTPS_PROXY`` point at the proxy's internal-net
DNS name (the sidecar gets a deterministic name on the internal net).

The fixtures + tests intentionally use FAKE image digests
(``sha256:`` + ``"a" * 64`` etc.) — the canonical Sprint-8A image
catalog publishes the real digests at supply-chain pipeline build
time; these tests do not pull the real images. Per
``feedback_canonical_artifact_not_oss_substitute``, NEVER substitute
an OSS image masquerading as the canonical name; fakes here are
clearly-named placeholders that never reach a Docker daemon.
"""

from __future__ import annotations

from typing import Any

import pytest

# R1 P2.2 reviewer fix — these pure-helper tests import the backend
# module which loads aiodocker at module level (the sandbox-docker
# optional extra). A base install without the extra would fail
# collection here; importorskip makes the file degrade gracefully
# in kernel-only venvs while still exercising the helpers when the
# extra is present (the dev/CI invariant via `uv sync --all-extras`).
pytest.importorskip("aiodocker")

from cognic_agentos.sandbox import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.backends.docker_sibling import (
    _NON_ROOT_USER,
    _PROXY_CONFIG_DIR,
    _PROXY_NON_ROOT_USER,
    _build_proxy_sidecar_container_config,
    _build_sandbox_container_config,
    _internal_network_name,
    _proxy_sidecar_container_name,
    _proxy_sidecar_env,
    _sandbox_container_env,
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
# Container + network naming
# ---------------------------------------------------------------------------


class TestNetworkNaming:
    def test_internal_network_name_carries_session_prefix(self) -> None:
        """Per spec §10.1 + the env-gated assertion at
        test_docker_sibling_lifecycle.py:test_create_starts_sandbox_*
        which asserts
        ``internal_net_name.startswith(f"cognic-sb-internal-{session_id[:8]}")``."""
        session_id = "abcd1234efgh5678ijkl9012mnop3456"
        name = _internal_network_name(session_id)
        assert name.startswith(f"cognic-sb-internal-{session_id[:8]}")

    def test_internal_network_name_is_deterministic_for_same_session_id(
        self,
    ) -> None:
        """Idempotent network creation needs deterministic names —
        otherwise a retry after a transient docker-daemon failure
        would orphan the previous network."""
        session_id = "deadbeef" * 4
        assert _internal_network_name(session_id) == _internal_network_name(session_id)

    def test_two_sessions_get_distinct_network_names(self) -> None:
        """Per-session isolation MUST produce distinct network names."""
        name_a = _internal_network_name("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        name_b = _internal_network_name("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        assert name_a != name_b


class TestSidecarNaming:
    def test_proxy_sidecar_container_name_carries_session_id_suffix(self) -> None:
        """Spec §10.1 + the env-gated assertion at
        test_docker_sibling_lifecycle.py asserting
        ``backend._docker.containers.get(f"{session.session_id}-proxy")``."""
        session_id = "abcd1234"
        assert _proxy_sidecar_container_name(session_id) == f"{session_id}-proxy"


# ---------------------------------------------------------------------------
# Sandbox container env (HTTP_PROXY wiring)
# ---------------------------------------------------------------------------


class TestSandboxContainerEnv:
    def test_http_proxy_points_at_egress_proxy_dns_name(self) -> None:
        """Per spec §10.1 — sandbox HTTP_PROXY env points at the proxy
        on the internal-net DNS name. The env-gated test asserts
        ``env_dict["HTTP_PROXY"].startswith("http://egress-proxy:")``."""
        env = _sandbox_container_env(
            policy=_POLICY,
            session_id="abcd" * 8,
            proxy_dns_name="egress-proxy",
            proxy_port=8080,
        )
        assert env["HTTP_PROXY"].startswith("http://egress-proxy:")
        assert env["HTTPS_PROXY"].startswith("http://egress-proxy:")
        assert env["HTTP_PROXY"] == "http://egress-proxy:8080"
        assert env["HTTPS_PROXY"] == "http://egress-proxy:8080"

    def test_no_proxy_env_unset(self) -> None:
        """``NO_PROXY`` MUST NOT be present — every outbound request
        from the sandbox MUST pass through the proxy. A NO_PROXY entry
        would create a bypass class the egress allow-list does not
        cover. Spec §10.1 + spec §10.4 (raw-TCP-blocked-at-netns).
        """
        env = _sandbox_container_env(
            policy=_POLICY,
            session_id="x" * 32,
            proxy_dns_name="egress-proxy",
            proxy_port=8080,
        )
        assert "NO_PROXY" not in env
        assert "no_proxy" not in env


# ---------------------------------------------------------------------------
# Proxy sidecar env (T7's EgressProxyConfig surface)
# ---------------------------------------------------------------------------


class TestProxySidecarEnv:
    def test_proxy_sidecar_env_carries_allow_list_and_session_id(self) -> None:
        """T10a wires T7's EgressProxyConfig.to_env() output onto the
        sidecar container's env. Verifies the integration boundary —
        the sidecar reads ALLOW_LIST (JSON) + SESSION_ID at boot per
        T7's contract."""
        session_id = "session-abc-123"
        env = _proxy_sidecar_env(policy=_POLICY, session_id=session_id)
        # T7's EgressProxyConfig.to_env() returns ALLOW_LIST + SESSION_ID
        assert "ALLOW_LIST" in env
        assert "SESSION_ID" in env
        assert env["SESSION_ID"] == session_id
        # ALLOW_LIST is JSON-encoded; sidecar parses it at boot
        import json as _json

        decoded = _json.loads(env["ALLOW_LIST"])
        assert "httpbin.org" in decoded
        assert "api.example.com" in decoded

    def test_proxy_sidecar_env_empty_allow_list_is_json_empty_array(self) -> None:
        """An empty allow-list MUST serialise as ``[]`` (NOT empty string)
        so the sidecar's JSON parser succeeds + the allow-check refuses
        every host."""
        policy = SandboxPolicy(
            cpu_cores=0.5,
            cpu_time_budget_s=None,
            memory_mb=256,
            walltime_s=30.0,
            runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
            egress_allow_list=(),  # ← KEY
            vault_path=None,
        )
        env = _proxy_sidecar_env(policy=policy, session_id="s-1")
        import json as _json

        assert _json.loads(env["ALLOW_LIST"]) == []


# ---------------------------------------------------------------------------
# DockerSibling import guard — sandbox-docker extra missing
# ---------------------------------------------------------------------------


class TestSandboxDockerExtraImportGuard:
    """When `aiodocker` is not installed (deployer chose
    KubernetesPod-only deployment without ``-e .[sandbox-docker]``),
    importing the backend module surfaces a structured
    NotImplementedError pointing at the extra. The kernel package
    itself stays importable — only DockerSiblingSandboxBackend
    construction fails-loud.

    With the extra INSTALLED (the dev/CI environment), the import
    succeeds + the class is constructable. This test verifies the
    happy-path import; the absent-extra path is covered by a separate
    integration test in the deployment kit at Sprint 14."""

    def test_dockersibling_class_importable_with_sandbox_docker_extra(self) -> None:
        from cognic_agentos.sandbox import DockerSiblingSandboxBackend

        assert DockerSiblingSandboxBackend is not None
        assert callable(DockerSiblingSandboxBackend)


# ---------------------------------------------------------------------------
# Spec §17 critical-controls classification
# ---------------------------------------------------------------------------


class TestModuleIsCriticalControls:
    """T10a + T10b + T10c all extend the same backend module; spec §17
    classifies DockerSiblingSandboxBackend as CC (security boundary
    between AgentOS and pack code). This test pins the module is
    discoverable + its public surface is on the package."""

    def test_backend_class_re_exported_from_sandbox_package(self) -> None:
        from cognic_agentos.sandbox import DockerSiblingSandboxBackend
        from cognic_agentos.sandbox.backends.docker_sibling import (
            DockerSiblingSandboxBackend as DirectImport,
        )

        # Re-export same object (caught duplicate-declaration class)
        assert DockerSiblingSandboxBackend is DirectImport

    def test_sandbox_session_helper_exposed_at_package_level(self) -> None:
        """Spec §288-334 — sandbox_session @asynccontextmanager helper
        lives at sandbox/__init__.py per the "lifecycle ergonomics"
        section. Pinned here because the env-gated lifecycle tests
        import it directly."""
        from cognic_agentos.sandbox import sandbox_session

        assert sandbox_session is not None
        assert callable(sandbox_session)


class TestContainerConfigsRunAsNonRoot:
    """Both sandbox + sidecar configs MUST run as a NON-ROOT user, but
    they use DISTINCT identities per the T30/T14.1 decision:

    * **Sandbox (workload)** — squashed to ``65534:65534``
      (nobody:nogroup). The workload is the untrusted surface; nobody
      is the safe generic identity.
    * **Proxy sidecar** — runs as ``10002:10002``, the canonical
      egress-proxy image's purpose-built ``cognicproxy`` user (it
      OWNS ``/etc/cognic-proxy`` + ``/var/log/cognic-proxy``, chowned
      at image build). The proxy is AgentOS-owned infrastructure; it
      runs as its baked identity, NOT the workload identity. Forcing
      it to 65534 (the pre-T14.1 behaviour) left it unable to write
      its config/log dirs under ``ReadonlyRootfs=True`` (those dirs
      are 10002-owned) — the Z4 live-audit failure class.

    Both are explicit, non-root, and pinned so an image-metadata drift
    cannot silently change container identity."""

    def test_sandbox_container_config_runs_as_nobody(self) -> None:
        config = _build_sandbox_container_config(
            policy=_POLICY,
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-abcd1234-abcdef01",
        )
        assert config["User"] == "65534:65534", (
            "Sandbox container config MUST set User=65534:65534 "
            "(nobody:nogroup) per spec §7 + R1 P1.3 reviewer fix. "
            "Without this, Docker uses the image default (commonly "
            "root), weakening the sandbox boundary."
        )

    def test_proxy_sidecar_container_config_runs_as_image_proxy_user(self) -> None:
        config = _build_proxy_sidecar_container_config(
            policy=_POLICY,
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-abcd1234-abcdef01",
            proxy_image="cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
        )
        assert config["User"] == "10002:10002", (
            "Proxy sidecar MUST run as the canonical image's purpose-built "
            "cognicproxy user (10002:10002) which owns /etc/cognic-proxy + "
            "/var/log/cognic-proxy — NOT the workload's 65534 (which cannot "
            "write those 10002-owned dirs under ReadonlyRootfs=True)."
        )
        # Non-root: neither uid nor gid is 0.
        uid, _, gid = config["User"].partition(":")
        assert uid != "0" and gid != "0"

    def test_non_root_user_constant_is_nobody_nogroup(self) -> None:
        """Pin the spec-locked UID/GID — 65534:65534 is the
        conventional nobody:nogroup on Debian / Alpine / distroless.
        Drift would silently change container identity. Treat the
        constant as wire-protocol-adjacent (changing it means a
        container-runtime-behaviour change at next deploy)."""
        assert _NON_ROOT_USER == "65534:65534"

    def test_proxy_non_root_user_constant_is_image_proxy_identity(self) -> None:
        """Pin the proxy sidecar's identity to the canonical egress-proxy
        image's baked ``cognicproxy`` user (10002:10002 per the image
        Dockerfile's ``groupadd -g 10002`` / ``useradd -u 10002``). The
        backend pins it EXPLICITLY rather than relying on the image's USER
        directive so image-metadata drift cannot silently change it."""
        assert _PROXY_NON_ROOT_USER == "10002:10002"

    def test_proxy_and_sandbox_use_distinct_non_root_identities(self) -> None:
        """Coherence: the trusted infra sidecar (10002) and the untrusted
        workload (65534) MUST be distinct identities — neither root."""
        assert _PROXY_NON_ROOT_USER != _NON_ROOT_USER
        for user in (_PROXY_NON_ROOT_USER, _NON_ROOT_USER):
            uid, _, gid = user.partition(":")
            assert uid not in ("", "0") and gid not in ("", "0")


class TestProxySidecarWritableConfigMount:
    """T30/T14.1 — the proxy sidecar needs a WRITABLE ``/etc/cognic-proxy``
    under ``ReadonlyRootfs=True``.

    The canonical proxy entrypoint renders + writes ``tinyproxy.filter`` +
    ``tinyproxy.conf`` into ``/etc/cognic-proxy`` at startup. That dir is
    part of the (read-only) image root, and only ``/var/log/cognic-proxy``
    is a Docker ``VOLUME`` — so without an explicit writable mount the proxy
    hits ``PermissionError: read-only file system`` at boot and is gone when
    the backend reads its access log (``egress_audit_unreadable``). A tmpfs
    mount (owned by the proxy's 10002 identity) provides the writable
    scratch surface without changing the signed image.

    Sidecar-only: the writable config tmpfs MUST NOT appear on the workload
    container's HostConfig.
    """

    def _proxy_config(self) -> dict[str, Any]:
        return _build_proxy_sidecar_container_config(
            policy=_POLICY,
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-abcd1234-abcdef01",
            proxy_image="cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
        )

    def test_proxy_config_dir_constant_is_etc_cognic_proxy(self) -> None:
        # Cross-artifact contract: MUST equal the egress-proxy entrypoint's
        # _DEFAULT_CONFIG_DIR (/etc/cognic-proxy) — the dir the proxy writes
        # its rendered tinyproxy config into.
        assert _PROXY_CONFIG_DIR == "/etc/cognic-proxy"

    def test_proxy_sidecar_has_writable_config_tmpfs(self) -> None:
        tmpfs = self._proxy_config()["HostConfig"].get("Tmpfs", {})
        assert _PROXY_CONFIG_DIR in tmpfs, (
            f"proxy sidecar HostConfig MUST declare a writable Tmpfs at "
            f"{_PROXY_CONFIG_DIR!r} so the entrypoint can render tinyproxy "
            f"config under ReadonlyRootfs=True; got Tmpfs={tmpfs!r}"
        )

    def test_proxy_config_tmpfs_owned_by_proxy_user(self) -> None:
        # The tmpfs must be writable by the proxy's 10002 identity — pin the
        # uid/gid options so a default-root-owned tmpfs (unwritable by 10002)
        # cannot regress.
        opts = self._proxy_config()["HostConfig"]["Tmpfs"][_PROXY_CONFIG_DIR]
        assert "uid=10002" in opts and "gid=10002" in opts, (
            f"config tmpfs MUST be owned by the proxy's 10002 identity; got {opts!r}"
        )

    def test_proxy_config_tmpfs_not_on_sandbox_container(self) -> None:
        sandbox_config = _build_sandbox_container_config(
            policy=_POLICY,
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-abcd1234-abcdef01",
        )
        sandbox_tmpfs = sandbox_config["HostConfig"].get("Tmpfs", {})
        assert _PROXY_CONFIG_DIR not in sandbox_tmpfs, (
            f"the proxy config tmpfs is sidecar-only; it MUST NOT appear on "
            f"the workload container HostConfig; got Tmpfs={sandbox_tmpfs!r}"
        )


class TestContainerConfigsCarrySecurityDefaults:
    """T10a security-default defence-in-depth pins. CapDrop +
    ReadonlyRootfs + no-new-privileges + non-root User combine to
    minimise the post-compromise blast radius inside the sandbox
    container.
    """

    def test_sandbox_container_drops_all_capabilities(self) -> None:
        config = _build_sandbox_container_config(
            policy=_POLICY,
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-test",
        )
        assert config["HostConfig"]["CapDrop"] == ["ALL"]

    def test_sandbox_container_has_no_new_privileges(self) -> None:
        config = _build_sandbox_container_config(
            policy=_POLICY,
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-test",
        )
        assert "no-new-privileges:true" in config["HostConfig"]["SecurityOpt"]

    def test_proxy_sidecar_drops_all_capabilities(self) -> None:
        config = _build_proxy_sidecar_container_config(
            policy=_POLICY,
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-test",
            proxy_image="cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
        )
        assert config["HostConfig"]["CapDrop"] == ["ALL"]
        assert config["HostConfig"]["ReadonlyRootfs"] is True

    def test_proxy_sidecar_carries_egress_proxy_dns_alias(self) -> None:
        """Sandbox HTTP_PROXY env resolves ``egress-proxy`` via the
        Docker DNS alias the sidecar exposes on the internal network.
        Drift breaks the proxy-mediated egress path silently."""
        config = _build_proxy_sidecar_container_config(
            policy=_POLICY,
            session_id="abcd" * 8,
            internal_net_name="cognic-sb-internal-test",
            proxy_image="cognic/sandbox-egress-proxy:v1@sha256:" + "d" * 64,
        )
        net = config["NetworkingConfig"]["EndpointsConfig"]["cognic-sb-internal-test"]
        assert "egress-proxy" in net["Aliases"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
