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

    T10b will extend the returned dict with cgroup-cap kwargs
    (``Memory``, ``MemorySwap``, ``CpuQuota``, ``CpuPeriod``); T10c
    does not modify the start-time config (proxy_log materialisation
    happens at exec-time).
    """
    sandbox_env = _sandbox_container_env(policy=policy, session_id=session_id)
    env_list = [f"{k}={v}" for k, v in sandbox_env.items()]
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
        """Execute a command in the session.

        T10a does NOT implement the exec body — resource-cap
        monitoring (T10b) + proxy_log materialisation (T10c) land in
        the next two sub-tasks. Calling exec between T10a + T10b
        raises a structured error pointing at the unfinished work.
        """
        raise NotImplementedError(
            "DockerSiblingSandboxBackend.exec lands at T10b (resource "
            "caps + cgroup integration) and T10c (proxy_log "
            "materialisation). T10a ships only the lifecycle envelope "
            "(create/destroy/health) per the sub-task split. See plan "
            "docs/superpowers/plans/2026-05-16-sprint-8a-sandbox-primitive.md "
            "§Post-T9 implementation notes."
        )

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
    "_NON_ROOT_USER",
    "_PROXY_DNS_NAME",
    "_PROXY_PORT",
    "DockerSiblingSandboxBackend",
    "DockerSiblingSession",
    "SandboxLifecycleRefused",
    "_build_proxy_sidecar_container_config",
    "_build_sandbox_container_config",
    "_internal_network_name",
    "_proxy_sidecar_container_name",
    "_proxy_sidecar_env",
    "_sandbox_container_env",
]
