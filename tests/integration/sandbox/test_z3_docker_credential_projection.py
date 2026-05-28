"""Sprint 10.6 Z3 — real-Vault + real-Docker live proof of workload credential projection.

Gates Sprint 10.6 closeout. Pinned anchors in the design doc at
``docs/superpowers/specs/2026-05-26-sprint-10.6-workload-credential-projection-design.md``:

* §5.7 — wire-protocol-public audit payload contract for the 4
  credential-projection events (``credentials_projected`` /
  ``credentials_projection_failed`` / ``credentials_projection_cleaned_up`` /
  ``credentials_projection_cleanup_failed``).
* §5.8 — lifecycle integration with ``SandboxBackend.create()``: mint-then-project
  loop in manifest declaration order; per-credential refusal triggers
  revoke-then-LIFO unwind (three-cleanup-paths table).

Earlier plan revisions cited "spec §7.2"; that anchor is legacy — the actual
wire-protocol-public contract lives at §5.7 + §5.8.

Env-gated on ``COGNIC_RUN_DOCKER_CREDENTIAL_PROJECTION_INTEGRATION=1``. Requires:

* Operator-bootstrapped real Vault server with a database/postgresql
  dynamic-secret role configured (env vars: ``COGNIC_VAULT_TEST_ADDR``,
  ``COGNIC_VAULT_TEST_TOKEN``, ``COGNIC_VAULT_TEST_SECRET_PATH``, e.g.
  ``database/creds/test-role-z3``).
* A real Docker daemon reachable from the AgentOS process UID, on a LINUX
  execution surface — the docker-sibling substrate preflight reads
  ``/proc/mounts`` + stages credentials under a shared host ``/dev/shm``, so
  a macOS host cannot run it directly; use a Linux runner, or a Linux
  container with ``--ipc=host`` + the docker socket mounted.
* A digest-pinned runtime image (``…@sha256:<64-hex>``) — set
  ``COGNIC_Z3_RUNTIME_IMAGE``. For the **canonical production proof**
  (``test_z3_happy_path_real_vault_real_docker_one_credential``) this is the
  real signed ``cognic/sandbox-runtime-python``. For the **fixture-mode
  proof** (``test_z3_fixture_mode_docker_projection_mechanics``, additionally
  opt-in via ``COGNIC_Z3_ALLOW_FIXTURE_IMAGES=1`` +
  ``COGNIC_Z3_FIXTURE_EGRESS_PROXY_IMAGE``) it is a local fixture runtime
  image. Fixture mode is dev/CI mechanics coverage and does NOT close the
  canonical Z3 gate.
* The workload GID pinned by that image's USER directive — set
  ``COGNIC_Z3_EXPECTED_WORKLOAD_GID`` to a positive integer matching the
  image's USER GID (the canonical image's USER for the production proof; the
  fixture image's USER for fixture mode). The T19 substrate preflight fails
  loud on declaration-vs-image mismatch; Z3 does NOT silently infer the GID
  from image metadata (the inference would walk back the T19 preflight
  invariant).

**Import contract per Sprint 10.1 ADR-004 §25 amendment finding #3 —
fail-loud-when-opted-in**:

* **Opt-out (env unset)**: ``pytest.skip(..., allow_module_level=True)``
  BEFORE any optional imports. No ``ImportError`` reaches the operator
  who hasn't asked for the live proof; the module is silently skipped
  at collection.
* **Opt-in (env set)**: plain ``import hvac`` / ``import aiodocker``
  AFTER the skip gate. Missing optional extras at this point surface
  as ``ImportError`` → pytest collection error. Opt-in is the
  "I have the runtime environment configured" contract (canonical for the
  production proof, fixture images for fixture mode); missing extras are a
  broken environment, NOT a non-issue.

The contract is mirrored from Sprint 10 Z2 at
``tests/integration/sandbox/test_real_vault_credential_lifecycle.py``; the
Z3/Z4-specific import-contract regression lands at T24 of the Sprint 10.6
plan (parallel to ``tests/unit/test_z2_import_fail_loud_contract.py``).

**Fail-loud configuration probes** (Z2 parity, landing at slice 2): when
opted in but env vars unset, or Vault unreachable, or Docker daemon
unreachable, or the runtime image (canonical for the production proof,
fixture for fixture mode) is unavailable, this suite raises
``AssertionError`` at fixture setup, NOT ``pytest.skip``. Opt-in
is a hard environmental claim; we don't pretend success.
"""

from __future__ import annotations

import asyncio
import os
import re
import uuid
from pathlib import Path
from typing import Any, Literal
from unittest.mock import AsyncMock, MagicMock
from urllib.request import Request, urlopen

import pytest

_OPT_IN_ENV_VAR = "COGNIC_RUN_DOCKER_CREDENTIAL_PROJECTION_INTEGRATION"
_OPTED_IN = os.environ.get(_OPT_IN_ENV_VAR) == "1"

if not _OPTED_IN:
    pytest.skip(
        f"{_OPT_IN_ENV_VAR} unset; Sprint 10.6 Z3 live proof opt-out path "
        "per Sprint 10.1 ADR-004 §25 amendment finding #3 contract. Opt "
        "in via COGNIC_RUN_DOCKER_CREDENTIAL_PROJECTION_INTEGRATION=1 "
        "with a pre-running Vault server + reachable Docker daemon (Linux "
        "execution surface) + a digest-pinned runtime image — canonical for "
        "the production proof, fixture for fixture mode (see module docstring "
        "for full env-var "
        "contract).",
        allow_module_level=True,
    )

# Opt-in path: plain imports — missing optional extras MUST fail loud as
# ImportError per Sprint 10.1 finding #3 (NOT pytest.importorskip).
# Mirrors the Z2 contract pinned by
# tests/unit/test_z2_import_fail_loud_contract.py; the Z3-specific
# regression lands at T24 of the Sprint 10.6 plan.
import aiodocker  # noqa: E402  (used by the slice-2a fixture's Docker daemon + runtime-image probes)
import hvac  # noqa: E402, F401  (kept import-only — consumed transitively via VaultCredentialAdapter; explicit module-level import pins the Sprint 10.1 finding #3 fail-loud import contract)

from cognic_agentos.core._vault_transport import VaultTransport  # noqa: E402
from cognic_agentos.core.vault import (  # noqa: E402
    VaultLeaseActorRef,
    VaultLeaseRequest,
)
from cognic_agentos.portal.rbac.actor import Actor  # noqa: E402
from cognic_agentos.sandbox.backends.docker_sibling import (  # noqa: E402
    DockerSiblingSandboxBackend,
    DockerSiblingSession,
)
from cognic_agentos.sandbox.credentials import VaultCredentialAdapter  # noqa: E402
from cognic_agentos.sandbox.policy import (  # noqa: E402
    PackAdmissionContext,
    SandboxPolicy,
)
from cognic_agentos.sandbox.projection import CredentialDecl  # noqa: E402
from cognic_agentos.sandbox.protocol import (  # noqa: E402
    SandboxLifecycleRefused,
)

_Z3_TENANT_ID = "t-z3-real"


# ──────────────────────────────────────────────────────────────────────
# Module-scoped real-Vault + real-Docker setup fixture — fail-loud on
# misconfiguration per the Sprint-10 Z2 doctrine at
# tests/integration/sandbox/test_real_vault_credential_lifecycle.py.
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def real_docker_credential_setup() -> dict[str, Any]:
    """Validate env-var contract + probe Vault + Docker + runtime-image
    reachability + return wired ``VaultTransport`` + ``VaultCredentialAdapter``.

    The 5 env vars are mandatory when the module-level env-gate is
    opted in. ``COGNIC_Z3_RUNTIME_IMAGE`` is the digest-pinned runtime
    image — the canonical signed image for the production proof, OR a
    fixture runtime image for the fixture-mode proof (the fixture-mode test
    additionally requires ``COGNIC_Z3_ALLOW_FIXTURE_IMAGES=1`` +
    ``COGNIC_Z3_FIXTURE_EGRESS_PROXY_IMAGE``, which it validates itself).
    Missing/empty values + unreachable Vault + unreachable Docker + missing
    runtime image + missing/malformed expected workload GID all raise
    ``AssertionError`` with a
    structured diagnostic naming the bootstrap-notes pointer at the
    module docstring.

    Module-scoped so the env-var validation + reachability probes amortise
    across the happy-path (slice 2b) + negative-path (slice 3) tests.

    The ``hvac.Client`` underlying ``VaultTransport`` is constructed
    lazily on first call per the Sprint-1C transport contract — fixture
    construction itself does NOT touch Vault; the reachability probe
    uses ``urllib`` so the diagnostic surfaces cleanly here rather than
    from inside the first lease attempt. The Docker probe uses a
    short-lived ``asyncio.run`` to drive ``aiodocker`` (the fixture is
    sync; one ephemeral event loop is simpler than fighting
    ``pytest-asyncio`` loop scoping for a module-scoped async fixture).
    """
    addr = os.environ.get("COGNIC_VAULT_TEST_ADDR", "").strip()
    token = os.environ.get("COGNIC_VAULT_TEST_TOKEN", "").strip()
    secret_path = os.environ.get("COGNIC_VAULT_TEST_SECRET_PATH", "").strip()
    runtime_image = os.environ.get("COGNIC_Z3_RUNTIME_IMAGE", "").strip()
    expected_workload_gid_raw = os.environ.get("COGNIC_Z3_EXPECTED_WORKLOAD_GID", "").strip()

    assert addr, (
        "COGNIC_VAULT_TEST_ADDR is unset/empty; opt-in env "
        f"{_OPT_IN_ENV_VAR}=1 implies a pre-running Vault server "
        "reachable at this address. See the module docstring."
    )
    assert token, (
        "COGNIC_VAULT_TEST_TOKEN is unset/empty; opt-in env "
        f"{_OPT_IN_ENV_VAR}=1 implies a valid Vault root or "
        "policy-scoped token. See the module docstring."
    )
    assert secret_path, (
        "COGNIC_VAULT_TEST_SECRET_PATH is unset/empty; opt-in env "
        f"{_OPT_IN_ENV_VAR}=1 implies a configured DYNAMIC secrets "
        "engine + role at the secret_path (e.g. "
        "database/creds/test-role-z3). See the module docstring — "
        "Z3 doesn't guess the path because the dynamic engine + "
        "role contract is operator-owned."
    )
    assert runtime_image, (
        "COGNIC_Z3_RUNTIME_IMAGE is unset/empty; opt-in env "
        f"{_OPT_IN_ENV_VAR}=1 implies a digest-pinned runtime image is "
        "pulled locally — the canonical signed cognic/sandbox-runtime-python "
        "for the canonical production proof, OR a fixture runtime image for "
        "the fixture-mode proof. See the module docstring — Z3 doesn't guess "
        "the image because the image contract is operator-owned."
    )
    # The operator declares the workload GID the runtime image actually pins
    # via its USER directive (the canonical image's USER for the production
    # proof; the fixture image's USER for fixture mode). T19's substrate
    # preflight will fail loud on mismatch between this declared GID and the
    # image's parsed USER GID (per the T19 preflight doctrine — silent
    # UID==GID inference from image metadata would walk back the preflight
    # invariant). The fixture validates int-parseability + positive-non-root
    # here so misconfiguration surfaces at fixture setup rather than from
    # inside the preflight subprocess.
    assert expected_workload_gid_raw, (
        "COGNIC_Z3_EXPECTED_WORKLOAD_GID is unset/empty; opt-in env "
        f"{_OPT_IN_ENV_VAR}=1 requires the operator to declare the "
        "workload GID pinned by the runtime image's USER directive "
        "(canonical image for the production proof; fixture image for "
        "fixture mode). The T19 substrate preflight fails loud on "
        "image-vs-declaration mismatch — Z3 does NOT silently infer "
        "GID from image metadata."
    )
    try:
        expected_workload_gid = int(expected_workload_gid_raw)
    except ValueError as exc:
        raise AssertionError(
            f"COGNIC_Z3_EXPECTED_WORKLOAD_GID={expected_workload_gid_raw!r} "
            f"is not an integer; opt-in env {_OPT_IN_ENV_VAR}=1 requires "
            f"a positive integer GID matching the runtime image's USER "
            f"directive (canonical or fixture image)."
        ) from exc
    assert expected_workload_gid > 0, (
        f"COGNIC_Z3_EXPECTED_WORKLOAD_GID={expected_workload_gid} must be "
        f"a positive integer (root GID 0 is refused by the T19 preflight "
        f"via sandbox_credential_projection_root_workload_refused; "
        f"negative values are nonsensical)."
    )

    # Vault reachability — urllib avoids httpx/aiohttp at fixture
    # construction. GET /v1/sys/health is unauthenticated; the
    # connection itself either succeeds or raises.
    probe_url = f"{addr.rstrip('/')}/v1/sys/health"
    try:
        with urlopen(
            Request(probe_url, method="GET"),
            timeout=5.0,
        ) as response:
            status = response.status
    except Exception as exc:
        raise AssertionError(
            f"Vault server at COGNIC_VAULT_TEST_ADDR={addr!r} is not "
            f"reachable ({type(exc).__name__}: {exc}). Opt-in env "
            f"{_OPT_IN_ENV_VAR}=1 implies a pre-running server. See "
            f"the module docstring."
        ) from exc
    # 472 = standby; 473 = performance-standby; 501 = not initialized;
    # 503 = sealed. All of these mean reachable-but-not-serving — the
    # operator needs to unseal / initialize / promote.
    assert status in (200, 429), (
        f"Vault server at {addr!r} reachable but returned HTTP {status} "
        f"on /v1/sys/health — server is not in an active state (check "
        f"unseal / standby status). See the module docstring."
    )

    # Docker daemon + runtime image reachability (the image is canonical for
    # the production proof, a fixture image for fixture mode) — async via
    # asyncio.run since the fixture is sync. One short-lived event loop
    # for the probe; the loop is closed by asyncio.run() before fixture
    # consumers' own pytest-asyncio loops take over.
    async def _probe_docker_and_runtime_image() -> None:
        client = aiodocker.Docker()
        try:
            try:
                await client.version()
            except Exception as exc:
                raise AssertionError(
                    f"Docker daemon not reachable "
                    f"({type(exc).__name__}: {exc}). Opt-in env "
                    f"{_OPT_IN_ENV_VAR}=1 implies a reachable Docker "
                    f"daemon at the AgentOS process UID."
                ) from exc
            try:
                await client.images.inspect(runtime_image)
            except aiodocker.exceptions.DockerError as exc:
                # status=404 → image absent (the common operator-config
                # failure mode). Other statuses (500 etc.) surface as
                # raw DockerError so the operator sees the daemon-side
                # diagnostic verbatim.
                if exc.status == 404:
                    raise AssertionError(
                        f"Runtime image {runtime_image!r} is not present in "
                        f"the local Docker image store (canonical image for "
                        f"the production proof; fixture image for fixture "
                        f"mode). Opt-in env {_OPT_IN_ENV_VAR}=1 implies the "
                        f"image is pulled. Run `docker pull "
                        f"{runtime_image}` before opting in."
                    ) from exc
                raise
        finally:
            await client.close()

    asyncio.run(_probe_docker_and_runtime_image())

    settings = MagicMock(
        vault_addr=addr,
        vault_token=token,
        vault_namespace=None,
        vault_http_timeout_s=10.0,
        vault_http_max_retries=3,
        sandbox_per_tenant_max_cpu=4.0,
        sandbox_per_tenant_max_memory=4096,
        sandbox_per_tenant_max_walltime=300.0,
        sandbox_kernel_default_max_credential_ttl_s=3600,
        # MUST be explicit values, NOT MagicMock auto-attrs: the Docker
        # substrate preflight reads getattr(settings,
        # "dev_escape_allow_permissive_credential_projection", False) +
        # getattr(settings, "runtime_profile", "prod"). A bare MagicMock
        # returns a TRUTHY MagicMock for both, which trips the preflight's
        # dev-escape profile guard (dev_escape_enabled truthy + profile !=
        # "dev" → ValueError) BEFORE the real checks run. Surfaced by the
        # T28 live fixture run (the preflight only executes live on Linux).
        # dev-escape OFF + a real RuntimeProfile means the fixture image
        # (valid non-root USER 65534) passes the preflight on its own
        # merits, no permissive downgrade.
        dev_escape_allow_permissive_credential_projection=False,
        runtime_profile="prod",
    )
    transport = VaultTransport(
        vault_addr=addr,
        vault_token=token,
        vault_namespace=None,
        timeout_s=10.0,
        max_retries=3,
    )
    adapter = VaultCredentialAdapter(transport=transport, settings=settings)
    return {
        "addr": addr,
        "token": token,
        "secret_path": secret_path,
        "runtime_image": runtime_image,
        "expected_workload_gid": expected_workload_gid,
        "settings": settings,
        "transport": transport,
        "adapter": adapter,
    }


def _make_z3_lease_request(
    secret_path: str,
    *,
    ttl_s: int = 900,
    tenant_id: str = _Z3_TENANT_ID,
    scope_label: str = "z3-real-docker-projection-proof",
) -> VaultLeaseRequest:
    """Build a real ``VaultLeaseRequest`` pointing at the operator-
    configured secret_path. Defaults match the Z3 happy-path scope."""
    return VaultLeaseRequest(
        secret_path=secret_path,
        ttl_s=ttl_s,
        tenant_id=tenant_id,
        actor_ref=VaultLeaseActorRef(
            actor_subject="z3-test-actor",
            actor_type="service",
        ),
        scope_label=scope_label,
    )


def _make_z3_credential_decl(
    request: VaultLeaseRequest,
    *,
    logical_name: str,
    expected_fields: tuple[str, ...] = ("password", "username"),
    purpose_category: str = "application_database_read",
    purpose_description: str = "Z3 real-Vault dynamic credential projection proof.",
) -> CredentialDecl:
    """Build a ``CredentialDecl`` paired with the given
    ``VaultLeaseRequest`` per the Sprint 10.6 T21 pair-invariant.
    Mirrors the helper at
    ``tests/unit/sandbox/backends/test_docker_sibling_credential_lifecycle.py::
    _make_credential_decl_for_request``: ``vault_path`` / ``tenant_id`` /
    ``ttl_s`` derive from the request so the 4-invariant pair guard at
    ``sandbox/_credentials_pair.py`` cannot trip on field drift.

    The default ``expected_fields = ("password", "username")`` matches a
    real Vault ``database/postgresql`` dynamic-secret role response;
    slice 3 overrides this to inject the intentional mismatch."""
    return CredentialDecl(
        logical_name=logical_name,
        vault_path=request.secret_path,
        expected_fields=list(expected_fields),
        ttl_s=request.ttl_s,
        purpose_category=purpose_category,
        purpose_description=purpose_description,
        tenant_id=request.tenant_id,
    )


# ──────────────────────────────────────────────────────────────────────
# Z3 layer-2 backend builder + per-test event recorder.
#
# The substrate preflight + topology + container exec + projection
# executor + LIFO unwind ALL run for real against the operator's Docker
# daemon. We deliberately stub the canonical-image-catalog +
# rego-engine seams because (a) the canonical cosign + SBOM
# infrastructure is operator-owned + already covered upstream at
# ``tests/unit/sandbox/test_catalog.py`` + (b) Wave-1 sandbox.rego
# admission is covered at ``tests/unit/policies/test_sandbox_rego.py``.
# Z3's envelope is the credential projection lifecycle, NOT admission
# duplication.
# ──────────────────────────────────────────────────────────────────────


def _make_event_recorder() -> tuple[AsyncMock, list[tuple[str, dict[str, Any]]]]:
    """Build a ``DecisionHistoryStore`` mock that intercepts every
    ``append_with_precondition`` call and captures
    ``(decision_type, payload)`` tuples in emission order.

    Mirrors the unit-test recorder at
    ``tests/unit/sandbox/backends/test_docker_sibling_credential_lifecycle.py``
    intentionally re-implemented here for test-suite isolation (no
    cross-import from the unit tree into the integration tree).
    """
    events: list[tuple[str, dict[str, Any]]] = []

    async def _append(
        *,
        precondition: Any,
        record_builder: Any,
        **_: Any,
    ) -> tuple[uuid.UUID, bytes]:
        captured = await precondition(AsyncMock(), 0, b"\x00" * 32)
        record = record_builder(captured)
        events.append((record.decision_type, dict(record.payload)))
        return uuid.uuid4(), b"\x00" * 32

    store = AsyncMock()
    store.append_with_precondition.side_effect = _append
    return store, events


def _emitted_event_suffixes(
    events: list[tuple[str, dict[str, Any]]],
) -> list[str]:
    """Strip the ``sandbox.lifecycle.`` prefix for compact assertions."""
    return [name.replace("sandbox.lifecycle.", "") for name, _ in events]


def _make_z3_layer2_backend(
    *,
    adapter: VaultCredentialAdapter,
    dh_store: AsyncMock,
    settings: MagicMock,
    egress_proxy_image: str | None = None,
) -> tuple[DockerSiblingSandboxBackend, aiodocker.Docker]:
    """Construct a ``DockerSiblingSandboxBackend`` with a REAL aiodocker
    client + REAL ``VaultCredentialAdapter`` + STUBBED admit_policy seam
    (catalog + rego allow-everything) + REAL substrate preflight (T19
    validates ``/dev/shm`` is tmpfs + parses image USER directive + GID
    matches operator-declared ``expected_workload_gid``).

    The stub vs real split: Z3's envelope is the credential projection
    lifecycle (mint → project → mount → workload-read → cleanup-then-
    revoke). The canonical-image-catalog cosign verification + the
    sandbox.rego admission gate are admission-time orthogonal concerns
    with their own coverage upstream. The substrate preflight is REAL
    because Z3's whole point is end-to-end validation of the image-vs-
    declaration matching contract per spec §5.8 step 2.

    Returns ``(backend, docker_client)`` — the caller MUST close the
    ``aiodocker.Docker`` client in a ``finally`` block. ``session.destroy()``
    tears down Docker resources (containers + networks + sidecar) but
    does NOT close the daemon client's aiohttp session, so an unclosed
    client leaks file descriptors across module-scoped fixtures and
    raises ``Unclosed client session`` warnings + ``RuntimeError: Event
    loop is closed`` on aiohttp's GC. The 2-tuple return shape makes
    the closure obligation explicit at every call site (slice 2b
    happy-path; slice 3 negative-path).
    """
    docker = aiodocker.Docker()
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    rego = MagicMock()
    rego.evaluate = AsyncMock(return_value=MagicMock(allow=True, reasoning=""))
    # T28 — egress_proxy_image is None by default → the backend resolves the
    # canonical ``cognic/sandbox-egress-proxy`` placeholder (the CANONICAL
    # proof's path). The fixture-mode proof injects the local fixture proxy
    # ref here so it never reaches the canonical placeholder (which has no
    # real image to start). Canonical callers pass nothing → unchanged.
    backend = DockerSiblingSandboxBackend(
        docker_client=docker,
        image_catalog=catalog,
        credential_adapter=adapter,
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=dh_store,
        settings=settings,
        warm_pool=None,
        egress_proxy_image=egress_proxy_image,
    )
    return backend, docker


def _build_z3_actor() -> Actor:
    return Actor(
        subject="z3-test-actor",
        tenant_id=_Z3_TENANT_ID,
        scopes=frozenset(),
        actor_type="service",
    )


def _build_z3_pack_context(
    *, profile: Literal["production", "development"] = "production"
) -> PackAdmissionContext:
    # T28 — canonical callers use the default profile="production"; the
    # fixture-mode proof passes profile="development" (the doctrinally-honest
    # profile for fixture images — fixtures belong in development, never
    # production). Additive: existing canonical callers are unchanged.
    return PackAdmissionContext(
        pack_id="cognic.z3_real_docker_projection",
        pack_version="v1.0.0",
        pack_artifact_digest="sha256:" + "1" * 64,
        risk_tier="internal_write",
        declares_dynamic_install=False,
        profile=profile,
    )


def _build_z3_policy(*, runtime_image: str) -> SandboxPolicy:
    return SandboxPolicy(
        cpu_cores=0.5,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image=runtime_image,
        egress_allow_list=(),
        vault_path=None,
    )


async def _run_z3_docker_projection_mechanics(
    *,
    setup: dict[str, Any],
    backend: DockerSiblingSandboxBackend,
    docker_client: aiodocker.Docker,
    events: list[tuple[str, dict[str, Any]]],
    pack_ctx: PackAdmissionContext,
    proof_label: str,
) -> None:
    """Shared Docker credential-projection MECHANICS spine for Z3 (T28).

    Exercised by BOTH the canonical proof (real signed images,
    ``profile="production"``, ``egress_proxy_image=None``) AND the fixture-mode
    proof (local fixture images, ``profile="development"``, fixture proxy
    injected). The mechanics — mint → project → mount → workload-read →
    cleanup-then-revoke — are IDENTICAL across both; only the images + profile
    differ at the call site. A single shared spine is the WHOLE POINT: a
    passing fixture run guarantees the canonical run exercises the EXACT same
    assertions, so fixture mode cannot quietly diverge from canonical mode.

    ``proof_label`` is woven into failure messages so a failure names which
    mode tripped it; the helper otherwise does NOT know or care whether it is
    canonical or fixture.

    *** Running this spine in fixture mode does NOT close the canonical Z3
    gate. *** Fixture images are dev/CI stand-ins. The canonical-artifact
    PRODUCTION proof (real signed ``cognic/sandbox-runtime-python`` + real
    signed ``cognic/sandbox-egress-proxy@sha256:…``) is a SEPARATE gate that
    stays OPEN until the operator runs this same spine against those real
    images per ``[[feedback_canonical_artifact_not_oss_substitute]]``.
    """
    secret_path = setup["secret_path"]
    runtime_image = setup["runtime_image"]
    expected_workload_gid = setup["expected_workload_gid"]

    actor = _build_z3_actor()
    policy = _build_z3_policy(runtime_image=runtime_image)
    request = _make_z3_lease_request(secret_path)
    decl = _make_z3_credential_decl(request, logical_name="db_main")

    # Outer try/finally guarantees ``docker_client.close()`` even on create()
    # failure (no session) or a post-destroy assertion failure. session.destroy()
    # cleans containers + networks but does NOT close the aiodocker client.
    try:
        session = await backend.create(
            policy,
            actor=actor,
            tenant_id=_Z3_TENANT_ID,
            pack_context=pack_ctx,
            use_warm_pool=False,
            requires_credentials=(request,),
            credential_decls=(decl,),
            expected_workload_gid=expected_workload_gid,
        )
        assert isinstance(session, DockerSiblingSession), (
            f"[{proof_label}] expected a concrete DockerSiblingSession"
        )

        try:
            # ── (1) Lease landed with a real Vault-issued lease_id + payload.
            assert len(session.active_leases) == 1, (
                f"[{proof_label}] expected exactly 1 active lease; got {len(session.active_leases)}"
            )
            lease = session.active_leases[0]
            assert lease.lease_id, f"[{proof_label}] real Vault must issue a non-empty lease_id"
            assert "username" in lease.token, (
                f"[{proof_label}] expected 'username' in lease token; "
                f"got keys {sorted(lease.token.keys())}"
            )
            assert "password" in lease.token, (
                f"[{proof_label}] expected 'password' in lease token; "
                f"got keys {sorted(lease.token.keys())}"
            )

            # ── (2) Projection landed exactly once (1:1 with active_leases).
            assert len(session.active_projections) == 1, (
                f"[{proof_label}] expected exactly 1 active projection; "
                f"got {len(session.active_projections)}"
            )
            projection = session.active_projections[0]

            # ── (3) Workload reads credential bytes byte-exactly. Compare
            #        against session.active_leases[0].token (lease-specific
            #        dynamic creds; NOT a separate Vault response).
            for field in ("password", "username"):
                cat_result = await session.exec(
                    ["cat", f"/run/credentials/db_main/{field}"],
                    timeout_s=10.0,
                )
                assert cat_result.exit_code == 0, (
                    f"[{proof_label}] cat /run/credentials/db_main/{field} failed: "
                    f"exit {cat_result.exit_code}; stderr={cat_result.stderr!r}"
                )
                assert cat_result.stdout == lease.token[field].encode("utf-8"), (
                    f"[{proof_label}] mounted /run/credentials/db_main/{field} bytes "
                    f"diverged from session.active_leases[0].token[{field!r}]"
                )

            # ── (4) Mount dir shows EXACTLY the expected_fields — no shadow
            #        files (``_*``), no extras (T19 atomic-rename per spec §5.4).
            ls_result = await session.exec(
                ["ls", "-A", "/run/credentials/db_main/"],
                timeout_s=10.0,
            )
            assert ls_result.exit_code == 0, (
                f"[{proof_label}] ls /run/credentials/db_main/ failed: "
                f"exit {ls_result.exit_code}; stderr={ls_result.stderr!r}"
            )
            listed = sorted(ls_result.stdout.decode("utf-8").split())
            assert listed == ["password", "username"], (
                f"[{proof_label}] mount dir listing diverged from declared "
                f"expected_fields; saw {listed!r}"
            )

            # ── (5) Chain audit ordering on create(): lease_minted before
            #        credentials_projected for the same logical credential.
            create_suffixes = _emitted_event_suffixes(events)
            assert "lease_minted" in create_suffixes
            assert "credentials_projected" in create_suffixes
            lease_minted_idx = create_suffixes.index("lease_minted")
            projected_idx = create_suffixes.index("credentials_projected")
            assert lease_minted_idx < projected_idx, (
                f"[{proof_label}] lease_minted ({lease_minted_idx}) must precede "
                f"credentials_projected ({projected_idx}) per spec §5.8 step 3; "
                f"event order seen: {create_suffixes}"
            )

            # ── (5b) credentials_projected payload shape per spec §5.7.
            projected_payloads = [
                payload
                for name, payload in events
                if name == "sandbox.lifecycle.credentials_projected"
            ]
            assert len(projected_payloads) == 1, (
                f"[{proof_label}] expected exactly 1 credentials_projected row; "
                f"got {len(projected_payloads)}"
            )
            projected_payload = projected_payloads[0]
            assert projected_payload["logical_name"] == "db_main"
            assert projected_payload["vault_path"] == secret_path
            assert projected_payload["tenant_id"] == _Z3_TENANT_ID
            assert projected_payload["lease_id"] == lease.lease_id, (
                f"[{proof_label}] credentials_projected lease_id diverged from the "
                f"minted lease; payload={projected_payload['lease_id']!r}, "
                f"lease={lease.lease_id!r}"
            )
            assert projected_payload["projected_field_count"] == 2, (
                f"[{proof_label}] expected projected_field_count=2 (username + "
                f"password); got: {projected_payload['projected_field_count']!r}"
            )
            assert projected_payload["purpose_category"] == "application_database_read", (
                f"[{proof_label}] expected purpose_category=application_database_read; "
                f"got: {projected_payload['purpose_category']!r}"
            )
            assert (
                projected_payload["purpose_description"]
                == "Z3 real-Vault dynamic credential projection proof."
            )
            # backend_resource_name is the Docker opaque host_staging_dir
            # (the bind-mount source) per spec §5.7; must match the session's
            # projection record exactly.
            assert projected_payload["backend_resource_name"] == projection.host_staging_dir, (
                f"[{proof_label}] credentials_projected backend_resource_name diverged "
                f"from the projection's host_staging_dir; "
                f"payload={projected_payload['backend_resource_name']!r}, "
                f"projection={projection.host_staging_dir!r}"
            )
            assert projected_payload["session_id"] == session.session_id, (
                f"[{proof_label}] credentials_projected session_id diverged from the "
                f"session; payload={projected_payload['session_id']!r}, "
                f"session={session.session_id!r}"
            )
            # Defence-in-depth: NO credential token value leaks into the chain
            # payload (the §5.7 contract carries provenance, never field values).
            rendered_payload = repr(projected_payload)
            for secret_value in lease.token.values():
                assert secret_value not in rendered_payload, (
                    f"[{proof_label}] credentials_projected payload leaked a "
                    f"credential token value — §5.7 carries provenance only, "
                    f"never field values"
                )

            # ── (5c) Host staging dir EXISTS before destroy(). The docker-
            #        sibling backend shares the host filesystem so the test
            #        process can stat the opaque staging path directly.
            assert Path(projection.host_staging_dir).exists(), (
                f"[{proof_label}] host staging dir {projection.host_staging_dir!r} "
                f"should exist after a successful projection (pre-destroy)"
            )
        finally:
            # destroy() triggers the T21 LIFO unwind: projection cleanup FIRST
            # (staging-dir delete + credentials_projection_cleaned_up) then Vault
            # revoke (lease_revoked) per spec §5.8 step 5 — even on test-body
            # failure, tear down to avoid leaking a container + a dangling lease.
            await session.destroy()

        # ── (6) Post-destroy chain ordering: credentials_projection_cleaned_up
        #        MUST precede lease_revoked for the same logical credential.
        final_suffixes = _emitted_event_suffixes(events)
        assert "credentials_projection_cleaned_up" in final_suffixes, (
            f"[{proof_label}] expected credentials_projection_cleaned_up after "
            f"destroy(); event order seen: {final_suffixes}"
        )
        assert "lease_revoked" in final_suffixes, (
            f"[{proof_label}] expected lease_revoked after destroy(); "
            f"event order seen: {final_suffixes}"
        )
        cleanup_idx = final_suffixes.index("credentials_projection_cleaned_up")
        revoke_idx = final_suffixes.index("lease_revoked")
        assert cleanup_idx < revoke_idx, (
            f"[{proof_label}] credentials_projection_cleaned_up ({cleanup_idx}) must "
            f"precede lease_revoked ({revoke_idx}) per spec §5.8 step 5 LIFO "
            f"ordering invariant; event order seen: {final_suffixes}"
        )

        # ── (7) Host staging dir GONE after destroy() — direct host filesystem
        #        proof the credential bytes were wiped (T21 LIFO cleanup §5.8 step 5).
        assert not Path(projection.host_staging_dir).exists(), (
            f"[{proof_label}] host staging dir {projection.host_staging_dir!r} "
            f"should be removed after destroy() (T21 LIFO projection cleanup)"
        )
    finally:
        # aiodocker.Docker keeps an aiohttp ClientSession; session.destroy()
        # releases container + network resources but does NOT close the client.
        await docker_client.close()


# ──────────────────────────────────────────────────────────────────────
# Slice 2b — happy-path Z3 proof (canonical + fixture-mode share the spine).
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_z3_happy_path_real_vault_real_docker_one_credential(
    real_docker_credential_setup: dict[str, Any],
) -> None:
    """Z3 happy path — full mint-then-project-then-workload-read-then-
    cleanup-then-revoke lifecycle against real Vault + real Docker.

    End-to-end proof per spec §5.7 + §5.8:

    * **Mint** runs through ``VaultCredentialAdapter.mint_lease`` →
      ``core/vault.lease_credential`` → real ``VaultTransport.lease``
      → real Vault server → real ``lease_id`` returned.
    * **Project** runs T18 planner + T19 executor: writes credential
      bytes under ``/dev/shm/cognic/<session>/<credential>/<field>``;
      backend bind-mounts read-only at ``/run/credentials/<logical_name>``.
    * **Workload read** — ``session.exec(["cat", "/run/credentials/db_main/<field>"])``
      inside the real container returns the credential bytes byte-
      exactly. Compared against ``session.active_leases[0].token[<field>]``
      (NOT a separate Vault response, because dynamic-DB creds are
      lease-specific — each lease has a unique username + password).
    * **Cleanup** during ``destroy()`` removes the staging dir
      (``credentials_projection_cleaned_up`` emitted) BEFORE the Vault
      revoke (``lease_revoked`` emitted) per spec §5.8 step 5 LIFO
      ordering invariant.

    Chain audit ordering asserted: ``lease_minted`` → ``credentials_projected``
    on create; ``credentials_projection_cleaned_up`` → ``lease_revoked``
    on destroy. ``cleanup`` precedes ``revoke`` for the same logical
    credential per the T21 LIFO invariant (cleanup minimises the
    active-risk-surface window during teardown).
    """
    # T28 — CANONICAL proof: real signed images, profile="production",
    # egress_proxy_image=None (the backend resolves the canonical
    # cognic/sandbox-egress-proxy default). The mint→project→mount→read→
    # cleanup→revoke MECHANICS + every assertion live in the shared
    # _run_z3_docker_projection_mechanics spine, which the fixture-mode test
    # below ALSO drives — so the two modes cannot diverge. This canonical gate
    # is the PRODUCTION-posture proof; it requires the operator-supplied real
    # signed cognic/sandbox-runtime-python + cognic/sandbox-egress-proxy@sha256:…
    # images.
    setup = real_docker_credential_setup
    dh_store, events = _make_event_recorder()
    backend, docker_client = _make_z3_layer2_backend(
        adapter=setup["adapter"], dh_store=dh_store, settings=setup["settings"]
    )
    await _run_z3_docker_projection_mechanics(
        setup=setup,
        backend=backend,
        docker_client=docker_client,
        events=events,
        pack_ctx=_build_z3_pack_context(),
        proof_label="canonical (real signed images, profile=production)",
    )


# ──────────────────────────────────────────────────────────────────────
# Slice 2b (fixture variant) — fixture-mode Docker projection MECHANICS proof
# (T28). Drives the SAME _run_z3_docker_projection_mechanics spine as the
# canonical proof above, against LOCAL FIXTURE images in profile="development".
# Does NOT close the canonical Z3 gate.
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.skipif(
    os.environ.get("COGNIC_Z3_ALLOW_FIXTURE_IMAGES") != "1",
    reason=(
        "COGNIC_Z3_ALLOW_FIXTURE_IMAGES != 1 — the fixture-mode Docker "
        "projection MECHANICS proof is opt-in SEPARATELY from the canonical "
        "proof so a fixture run can never be mistaken for canonical-artifact "
        "production proof. To run it: COGNIC_RUN_DOCKER_CREDENTIAL_PROJECTION_"
        "INTEGRATION=1 + COGNIC_Z3_ALLOW_FIXTURE_IMAGES=1 + "
        "COGNIC_Z3_FIXTURE_EGRESS_PROXY_IMAGE=<fixture proxy ref> + "
        "COGNIC_Z3_RUNTIME_IMAGE=<fixture runtime ref> + "
        "COGNIC_Z3_EXPECTED_WORKLOAD_GID=<fixture image USER GID>, and TARGET "
        "this test specifically (the canonical test above fails without the "
        "real signed images)."
    ),
)
async def test_z3_fixture_mode_docker_projection_mechanics(
    real_docker_credential_setup: dict[str, Any],
) -> None:
    """FIXTURE-MODE Docker projection MECHANICS proof — *** NOT a canonical
    proof; does NOT close the canonical Z3 gate. ***

    Runs the SAME mint → project → mount → workload-read → cleanup-then-revoke
    spine as the canonical happy-path test (via the shared
    ``_run_z3_docker_projection_mechanics`` helper), but against LOCAL FIXTURE
    images — ``COGNIC_Z3_RUNTIME_IMAGE`` = the fixture runtime image +
    ``COGNIC_Z3_FIXTURE_EGRESS_PROXY_IMAGE`` = the fixture egress-proxy sidecar
    — in ``profile="development"``. This proves the Docker projection MECHANICS
    work end-to-end against real Vault + real Docker (valuable dev/CI coverage)
    WITHOUT claiming the canonical-artifact production posture.

    The canonical Z3 gate (real signed ``cognic/sandbox-runtime-python`` + real
    signed ``cognic/sandbox-egress-proxy@sha256:…``) remains OPEN until the
    operator runs the canonical test above against those real images. Fixture
    images are NOT a substitute for canonical artifacts per
    ``[[feedback_canonical_artifact_not_oss_substitute]]``.

    DOUBLE-gated opt-in: the module-level
    ``COGNIC_RUN_DOCKER_CREDENTIAL_PROJECTION_INTEGRATION=1`` (shared with the
    canonical proof) AND ``COGNIC_Z3_ALLOW_FIXTURE_IMAGES=1`` (this test only),
    so a fixture run can never be silently mistaken for a production proof.
    """
    setup = real_docker_credential_setup
    # Fail-loud (NOT skip) when opted in but the fixture proxy ref is unset —
    # mirrors the module fixture's hard-environmental-claim contract. The
    # canonical egress-proxy default is a placeholder digest with NO runnable
    # image, so fixture mode MUST inject the fixture proxy explicitly.
    fixture_proxy_image = os.environ.get("COGNIC_Z3_FIXTURE_EGRESS_PROXY_IMAGE", "").strip()
    assert fixture_proxy_image, (
        "COGNIC_Z3_FIXTURE_EGRESS_PROXY_IMAGE is unset/empty; opt-in env "
        "COGNIC_Z3_ALLOW_FIXTURE_IMAGES=1 requires the local fixture egress-"
        "proxy image ref (e.g. the cognic-sandbox-egress-proxy-fixture image). "
        "The canonical egress-proxy default is a placeholder digest with no "
        "runnable image, so fixture mode cannot fall back to it."
    )
    # Must be DIGEST-PINNED (``<ref>@sha256:<64-hex>``): the backend's proxy
    # sidecar path does ``proxy_image.rsplit("@", 1)`` (docker_sibling.py) to
    # extract the catalog-keyed digest — a tag-only ref raises a raw
    # ValueError (not enough values to unpack) deep in the backend instead of
    # this friendly fail-loud. Assert the digest form here so a tag-only
    # fixture ref surfaces the env-contract diagnostic, not a backend unpack.
    assert re.fullmatch(r".+@sha256:[0-9a-f]{64}", fixture_proxy_image), (
        "COGNIC_Z3_FIXTURE_EGRESS_PROXY_IMAGE must be DIGEST-PINNED "
        f"(<ref>@sha256:<64-hex>); got {fixture_proxy_image!r}. The backend "
        "splits the proxy ref on '@' to read its catalog digest, so a "
        "tag-only ref (e.g. ':v1') — or a malformed digest like "
        "'@sha256:not-a-digest' — fails deep in the backend. Use the image's "
        "RepoDigest form (docker inspect … --format '{{.RepoDigests}}')."
    )
    dh_store, events = _make_event_recorder()
    backend, docker_client = _make_z3_layer2_backend(
        adapter=setup["adapter"],
        dh_store=dh_store,
        settings=setup["settings"],
        egress_proxy_image=fixture_proxy_image,
    )
    await _run_z3_docker_projection_mechanics(
        setup=setup,
        backend=backend,
        docker_client=docker_client,
        events=events,
        pack_ctx=_build_z3_pack_context(profile="development"),
        proof_label="FIXTURE images, profile=development — NOT canonical production proof",
    )


# ──────────────────────────────────────────────────────────────────────
# Slice 3 — negative-path Z3 proof.
#
# Mechanism: real Vault database/postgresql role returns the canonical
# ``{username, password}`` field set; manifest declares
# ``expected_fields = ("token", "username")`` (intentional mismatch).
# T18 ``compute_projection_plan`` returns ``ProjectionRefused`` with
# ``reason="sandbox_credential_projection_field_set_mismatch"``;
# T21's ``_handle_projection_refusal`` revokes the just-minted lease
# (real Vault), emits ``credentials_projection_failed`` with
# ``revoke_outcome="revoked"``, then raises ``SandboxLifecycleRefused``
# BEFORE step 4 (topology + container start) — so zero new containers
# materialise on the real Docker daemon.
#
# Mechanism rationale (Sprint 10.6 plan T22 negative-path lock):
# changing the manifest's ``expected_fields`` is operator-controlled +
# reproducible. Reconfiguring the Vault role to emit different fields
# is impractical for a database engine + leaks per-test config into
# the operator's pre-existing Vault server. Mismatch-at-manifest keeps
# the negative path local to the test module.
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_z3_negative_path_field_set_mismatch_refuses_before_container_create(
    real_docker_credential_setup: dict[str, Any],
) -> None:
    """Z3 negative path — manifest-vs-Vault field-set mismatch refuses
    at the T18 planner BEFORE the T19 executor writes any bytes AND
    BEFORE step 4 topology+container creation.

    End-to-end proof per spec §5.7 + §5.8 step 3 (Path 2):

    * **Mint** the credential's Vault lease via real
      ``VaultCredentialAdapter.mint_lease`` → real ``core/vault.lease_credential``
      → real ``VaultTransport.lease`` → real Vault server → real
      ``lease_id`` returned + ``lease_minted`` chain row.
    * **Project** invokes T18 ``compute_projection_plan`` which detects
      the field-set mismatch (manifest declares
      ``("token", "username")``; Vault response carries
      ``("username", "password")``) → returns ``ProjectionRefused``
      with ``reason="sandbox_credential_projection_field_set_mismatch"``.
    * **Revoke** the just-minted lease against real Vault (no
      projection cleanup — this credential never projected). Emits
      ``credentials_projection_failed`` carrying ``revoke_outcome="revoked"``
      + ``expected_fields`` + ``actual_fields`` + ``extras`` +
      ``missing`` (all alphabetized per §5.7).
    * **Raise** ``SandboxLifecycleRefused`` — workload container never
      starts; ``_start_sandbox_container`` is never called.

    Per-credential refusal does NOT emit a separate
    ``lease_revoked`` chain row; the revoke status is embedded in the
    ``credentials_projection_failed`` row's ``revoke_outcome`` field
    (T21 ``_handle_projection_refusal`` posture). The Z3 chain
    expectation is therefore exactly two rows for the failed
    credential: ``lease_minted`` → ``credentials_projection_failed``.
    """
    setup = real_docker_credential_setup
    settings = setup["settings"]
    adapter = setup["adapter"]
    secret_path = setup["secret_path"]
    runtime_image = setup["runtime_image"]
    expected_workload_gid = setup["expected_workload_gid"]

    dh_store, events = _make_event_recorder()
    backend, docker_client = _make_z3_layer2_backend(
        adapter=adapter, dh_store=dh_store, settings=settings
    )

    actor = _build_z3_actor()
    pack_ctx = _build_z3_pack_context()
    policy = _build_z3_policy(runtime_image=runtime_image)
    request = _make_z3_lease_request(secret_path)
    # ── Intentional mismatch: real database/postgresql role response
    #    is ``{username, password}``; this manifest declares
    #    ``{token, username}`` so the T18 planner refuses on the
    #    field_set_mismatch path. ``"token"`` is the missing field +
    #    ``"password"`` is the extras field.
    decl = _make_z3_credential_decl(
        request,
        logical_name="db_main",
        expected_fields=("token", "username"),
    )

    try:
        # ── (1) Baseline container set BEFORE create() — used to
        #        prove zero new containers materialised on the real
        #        Docker daemon. Unfiltered ``containers.list(all=True)``
        #        is the safest probe: it's label-agnostic, so the
        #        assertion does NOT depend on the backend's specific
        #        ``cognic.agentos.sandbox`` / ``cognic.agentos.session_id``
        #        label scheme staying stable. The diff against
        #        baseline naturally captures "no new container",
        #        independent of how the backend labels the ones it
        #        creates elsewhere.
        pre_containers = await docker_client.containers.list(all=True)
        pre_ids = {c.id for c in pre_containers}

        with pytest.raises(SandboxLifecycleRefused):
            await backend.create(
                policy,
                actor=actor,
                tenant_id=_Z3_TENANT_ID,
                pack_context=pack_ctx,
                use_warm_pool=False,
                requires_credentials=(request,),
                credential_decls=(decl,),
                expected_workload_gid=expected_workload_gid,
            )

        # ── (2) Zero new containers — the mint-then-project loop
        #        refused BEFORE step 4 (topology + container start),
        #        so ``_start_sandbox_container`` was never invoked.
        post_containers = await docker_client.containers.list(all=True)
        post_ids = {c.id for c in post_containers}
        new_ids = post_ids - pre_ids
        assert new_ids == set(), (
            f"Expected zero new containers after projection refusal "
            f"(spec §5.8 step 4 topology never runs on Path 2); got "
            f"new container IDs: {new_ids}"
        )

        # ── (3) Chain audit ordering: lease_minted then
        #        credentials_projection_failed for the same credential.
        suffixes = _emitted_event_suffixes(events)
        assert "lease_minted" in suffixes, (
            f"Expected lease_minted before projection refusal "
            f"(real Vault lease was successfully minted); got "
            f"event suffixes: {suffixes}"
        )
        assert "credentials_projection_failed" in suffixes, (
            f"Expected credentials_projection_failed (T21 Path 2 "
            f"refusal evidence row); got event suffixes: {suffixes}"
        )
        lease_minted_idx = suffixes.index("lease_minted")
        failed_idx = suffixes.index("credentials_projection_failed")
        assert lease_minted_idx < failed_idx, (
            f"lease_minted ({lease_minted_idx}) must precede "
            f"credentials_projection_failed ({failed_idx}) per spec "
            f"§5.8 step 3 (mint succeeded; projection then refused); "
            f"event order seen: {suffixes}"
        )

        # ── (4) NO credentials_projected event for this credential.
        #        Path 2 contract: the failed credential never reaches
        #        the executor, so no ``credentials_projected`` row
        #        is emitted for it (pinned at T21 unit-test
        #        TestPath2ProjectionRefusalForCredentialN).
        assert "credentials_projected" not in suffixes, (
            f"Failed credential MUST NOT emit credentials_projected "
            f"on Path 2 (it never projected); event suffixes: {suffixes}"
        )

        # ── (5) NO credentials_projection_cleaned_up event for this
        #        credential. Path 2 contract: the failed credential
        #        never projected, so there's nothing to clean.
        assert "credentials_projection_cleaned_up" not in suffixes, (
            f"Failed credential MUST NOT emit "
            f"credentials_projection_cleaned_up on Path 2 (no staging "
            f"dir to clean); event suffixes: {suffixes}"
        )

        # ── (6) credentials_projection_failed payload shape per spec
        #        §5.7. ``expected_fields`` / ``actual_fields`` /
        #        ``extras`` / ``missing`` are all alphabetized per
        #        the §5.7 wire-protocol contract.
        failed_payloads = [
            payload
            for name, payload in events
            if name == "sandbox.lifecycle.credentials_projection_failed"
        ]
        assert len(failed_payloads) == 1, (
            f"Expected exactly 1 credentials_projection_failed row; got {len(failed_payloads)}"
        )
        payload = failed_payloads[0]
        assert payload["reason"] == "sandbox_credential_projection_field_set_mismatch", (
            f"Expected reason=sandbox_credential_projection_field_set_mismatch; "
            f"got: {payload['reason']!r}"
        )
        assert payload["logical_name"] == "db_main"
        assert payload["expected_fields"] == ["token", "username"], (
            f"Expected alphabetized expected_fields=['token', 'username']; "
            f"got: {payload['expected_fields']!r}"
        )
        assert payload["actual_fields"] == ["password", "username"], (
            f"Expected alphabetized actual_fields=['password', 'username'] "
            f"(real database/postgresql role response); got: "
            f"{payload['actual_fields']!r}"
        )
        # extras = actual - expected = {"password"}; the field Vault
        # returned that the manifest didn't declare.
        assert payload["extras"] == ["password"], (
            f"Expected extras=['password']; got: {payload['extras']!r}"
        )
        # missing = expected - actual = {"token"}; the field the
        # manifest declared that Vault didn't return.
        assert payload["missing"] == ["token"], (
            f"Expected missing=['token']; got: {payload['missing']!r}"
        )
        # revoke_outcome="revoked" — real Vault successfully revoked
        # the just-minted lease before the chain row was emitted.
        # ``"revoke_failed"`` would indicate the lease leaked at the
        # Vault server (operator-investigatable).
        assert payload["revoke_outcome"] == "revoked", (
            f"Expected revoke_outcome='revoked' (real Vault revoke "
            f"should succeed for a valid lease_id); got: "
            f"{payload['revoke_outcome']!r}"
        )
    finally:
        # No session was created (create() raised). Only the
        # aiodocker client needs explicit closure here.
        await docker_client.close()
