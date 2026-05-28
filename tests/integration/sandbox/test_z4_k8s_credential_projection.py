"""Sprint 10.6 Z4 — real-Vault + real-Kubernetes live proof of workload credential projection.

Gates Sprint 10.6 closeout alongside the Z3 Docker proof at
``tests/integration/sandbox/test_z3_docker_credential_projection.py``. Pinned
anchors in the design doc at
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

**Z4 is the two-credential LIFO-coverage variant.** The Z3 Docker proof
covers the single-credential happy + Path-2 (refuse-before-any-projection)
paths; Z4 additionally exercises the cross-credential LIFO unwind: credential
A projects successfully (real K8s Secret created), credential B refuses at the
T18 planner, and A's already-created Secret is then DELETED during the LIFO
unwind per spec §5.8 step 5.

Env-gated on ``COGNIC_RUN_K8S_CREDENTIAL_PROJECTION_INTEGRATION=1``. Requires:

* Operator-bootstrapped real Vault server with a database/postgresql
  dynamic-secret role configured (env vars: ``COGNIC_VAULT_TEST_ADDR``,
  ``COGNIC_VAULT_TEST_TOKEN``, ``COGNIC_VAULT_TEST_SECRET_PATH``, e.g.
  ``database/creds/test-role-z4``). Shared with the Z3 proof.
* A reachable Kubernetes/OpenShift cluster. Config resolution mirrors the
  production backend's contract (``KubernetesPodSandboxBackend`` docstring) +
  the conformance suite at ``tests/conformance/sandbox/conftest.py``: prefer
  in-cluster ServiceAccount (when running inside a pod), else fall back to the
  default kubeconfig resolution (``KUBECONFIG`` env / the ``~/.kube/config``
  default). No Z4-specific kubeconfig override env var — kept identical to the
  conformance suite so operators bootstrap one cluster-config path.
* A target namespace the test ServiceAccount can create/list/delete Secrets +
  Pods + NetworkPolicies in — set ``COGNIC_K8S_SANDBOX_NAMESPACE`` (default
  ``cognic-sandbox``; the SAME env var + default the K8s conformance suite
  uses, deliberately reused so operators configure one sandbox namespace).
* The workload GID the pod runs with as ``fsGroup`` — set
  ``COGNIC_Z4_EXPECTED_WORKLOAD_GID`` to a positive integer. **Unlike Z3
  (Docker), this need NOT match any image USER directive**: the K8s substrate
  preflight is GID-axis only (no image-USER parse, no ``/proc/mounts`` tmpfs
  check — see ``verify_k8s_credential_projection_preflight``); the value
  becomes the pod-level ``fsGroup`` and the container reads the mode-0440
  projected Secret via fsGroup supplementary-group membership. Root GID 0 is
  refused (``sandbox_credential_projection_root_workload_refused``); ``None`` is
  refused (``sandbox_credential_projection_workload_gid_unknown``).
* A canonical AgentOS runtime image pullable by the cluster nodes — set
  ``COGNIC_Z4_RUNTIME_IMAGE`` to the digest-pinned ref (e.g.
  ``cognic/sandbox-runtime-python:sha256-…``). The happy path additionally
  needs the canonical egress-proxy sidecar image pullable by the cluster (the
  proxy is the egress-enforcement component the backend always co-schedules);
  Z4 uses the backend's canonical default, so the operator's cluster image
  cache must carry it. The negative path (two-credential LIFO) never reaches
  Pod creation, so it needs neither image — only Secret create/delete + the
  namespace.

**Import contract per Sprint 10.1 ADR-004 §25 amendment finding #3 —
fail-loud-when-opted-in**:

* **Opt-out (env unset)**: ``pytest.skip(..., allow_module_level=True)``
  BEFORE any optional imports. No ``ImportError`` reaches the operator
  who hasn't asked for the live proof; the module is silently skipped
  at collection.
* **Opt-in (env set)**: plain ``import kubernetes_asyncio`` / ``import hvac``
  AFTER the skip gate. Missing optional extras at this point surface as
  ``ImportError`` → pytest collection error. Opt-in is the "I have the
  canonical environment configured" contract; missing extras are a broken
  environment, NOT a non-issue.

The contract mirrors Sprint 10 Z2 at
``tests/integration/sandbox/test_real_vault_credential_lifecycle.py`` + the Z3
Docker proof; the Z3/Z4-shared import-contract regression lands at T24 of the
Sprint 10.6 plan (parallel to ``tests/unit/test_z2_import_fail_loud_contract.py``).

**Fail-loud configuration probes** (Z2/Z3 parity, landing at slice 2a): when
opted in but env vars unset, or Vault unreachable, or the cluster config fails
to load, or the namespace is not list-accessible, this suite raises
``AssertionError`` at fixture setup, NOT ``pytest.skip``. Opt-in is a hard
environmental claim; we don't pretend success.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from urllib.request import Request, urlopen

import pytest

_OPT_IN_ENV_VAR = "COGNIC_RUN_K8S_CREDENTIAL_PROJECTION_INTEGRATION"
_OPTED_IN = os.environ.get(_OPT_IN_ENV_VAR) == "1"

if not _OPTED_IN:
    pytest.skip(
        f"{_OPT_IN_ENV_VAR} unset; Sprint 10.6 Z4 live proof opt-out path "
        "per Sprint 10.1 ADR-004 §25 amendment finding #3 contract. Opt "
        "in via COGNIC_RUN_K8S_CREDENTIAL_PROJECTION_INTEGRATION=1 with a "
        "pre-running Vault server + a reachable Kubernetes cluster + a "
        "writable namespace + a canonical runtime image (see module "
        "docstring for the full env-var contract).",
        allow_module_level=True,
    )

# Opt-in path: plain imports — missing optional extras MUST fail loud as
# ImportError per Sprint 10.1 finding #3 (NOT pytest.importorskip).
# Mirrors the Z2 + Z3 contract; the Z3/Z4-shared regression lands at T24 of
# the Sprint 10.6 plan.
import hvac  # noqa: E402, F401  (kept import-only — consumed transitively via VaultCredentialAdapter; explicit module-level import pins the Sprint 10.1 finding #3 fail-loud import contract)
import kubernetes_asyncio  # noqa: E402, F401  (pins the sandbox-k8s extra fail-loud import contract; client/config accessed via the explicit re-exports below)
from kubernetes_asyncio import client as kube_client  # noqa: E402
from kubernetes_asyncio import config as kube_config  # noqa: E402

from cognic_agentos.core._vault_transport import VaultTransport  # noqa: E402
from cognic_agentos.core.vault import (  # noqa: E402
    VaultLeaseActorRef,
    VaultLeaseRequest,
)
from cognic_agentos.portal.rbac.actor import Actor  # noqa: E402
from cognic_agentos.sandbox.backends.kubernetes_pod import (  # noqa: E402
    KubernetesPodSandboxBackend,
    KubernetesPodSession,
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

_Z4_TENANT_ID = "t-z4-real"
_DEFAULT_K8S_NAMESPACE = "cognic-sandbox"


# ──────────────────────────────────────────────────────────────────────
# Cluster-config loader — shared by the module-scoped reachability probe
# (run under an ephemeral ``asyncio.run`` loop) AND the function-scoped
# ``z4_kube_client`` fixture (run under the test's pytest-asyncio loop).
#
# Resolution mirrors ``tests/conformance/sandbox/conftest.py`` + the
# ``KubernetesPodSandboxBackend`` docstring: prefer in-cluster
# ServiceAccount (sync ``load_incluster_config``); on ``ConfigException``
# fall back to the default kubeconfig resolution (async
# ``load_kube_config`` — reads ``KUBECONFIG`` / ``~/.kube/config``).
# ``load_*_config`` mutates the kubernetes_asyncio global ``Configuration``
# singleton (NOT loop-bound), so re-loading per loop is idempotent; the
# loop-bound state is the ``ApiClient``'s aiohttp session, which is why
# the client itself must be created inside the loop it is used in.
# ──────────────────────────────────────────────────────────────────────


async def _load_kube_config() -> None:
    """Load cluster config, in-cluster-first then default kubeconfig."""
    try:
        kube_config.load_incluster_config()  # type: ignore[no-untyped-call]
    except kube_config.ConfigException:
        await kube_config.load_kube_config()


# ──────────────────────────────────────────────────────────────────────
# Module-scoped real-Vault + real-Kubernetes setup fixture — fail-loud on
# misconfiguration per the Sprint-10 Z2 doctrine at
# tests/integration/sandbox/test_real_vault_credential_lifecycle.py + the
# Z3 Docker proof. Env validation + Vault probe + cluster reachability
# probe amortise across the happy-path (slice 2b) + negative-path
# (slice 3) tests.
#
# This fixture does NOT own a long-lived ``ApiClient`` — the kubernetes_asyncio
# client binds its aiohttp session to the event loop it is created in, and a
# module-scoped sync fixture cannot hand a loop-bound client to the
# per-test pytest-asyncio loops. The client lifetime lives in the
# function-scoped async ``z4_kube_client`` fixture below, which owns
# ``await client.close()`` on teardown so neither test can leak it
# (per the slice-2a reviewer lock — the backend explicitly does NOT manage
# the client's lifetime per the KubernetesPodSandboxBackend docstring).
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def real_k8s_credential_setup() -> dict[str, Any]:
    """Validate env-var contract + probe Vault + cluster reachability +
    return a wired ``VaultTransport`` + ``VaultCredentialAdapter`` + the
    resolved namespace / GID / runtime-image.

    Mandatory env vars when the module-level gate is opted in:
    ``COGNIC_VAULT_TEST_ADDR`` / ``COGNIC_VAULT_TEST_TOKEN`` /
    ``COGNIC_VAULT_TEST_SECRET_PATH`` / ``COGNIC_Z4_EXPECTED_WORKLOAD_GID``
    / ``COGNIC_Z4_RUNTIME_IMAGE``. ``COGNIC_K8S_SANDBOX_NAMESPACE`` is
    optional (defaults to ``cognic-sandbox`` — the SAME var + default the
    K8s conformance suite uses). Missing/empty mandatory values +
    unreachable Vault + cluster-config-load failure + namespace not
    list-accessible all raise ``AssertionError`` with a structured
    diagnostic pointing at the module docstring's bootstrap notes.

    The ``hvac.Client`` underlying ``VaultTransport`` is constructed
    lazily on first lease per the Sprint-1C transport contract — fixture
    construction itself does NOT touch Vault; the Vault reachability
    probe uses ``urllib`` so the diagnostic surfaces cleanly here rather
    than from inside the first lease attempt. The cluster probe uses a
    short-lived ``asyncio.run`` to drive kubernetes_asyncio (the fixture
    is sync; one ephemeral event loop is simpler than fighting
    pytest-asyncio loop scoping for a module-scoped async fixture). The
    probe's ``ApiClient`` is created AND closed inside that ephemeral
    loop, so it does not leak.
    """
    addr = os.environ.get("COGNIC_VAULT_TEST_ADDR", "").strip()
    token = os.environ.get("COGNIC_VAULT_TEST_TOKEN", "").strip()
    secret_path = os.environ.get("COGNIC_VAULT_TEST_SECRET_PATH", "").strip()
    runtime_image = os.environ.get("COGNIC_Z4_RUNTIME_IMAGE", "").strip()
    expected_workload_gid_raw = os.environ.get("COGNIC_Z4_EXPECTED_WORKLOAD_GID", "").strip()
    namespace = os.environ.get("COGNIC_K8S_SANDBOX_NAMESPACE", "").strip() or _DEFAULT_K8S_NAMESPACE

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
        "database/creds/test-role-z4). See the module docstring — "
        "Z4 doesn't guess the path because the dynamic engine + "
        "role contract is operator-owned."
    )
    assert runtime_image, (
        "COGNIC_Z4_RUNTIME_IMAGE is unset/empty; opt-in env "
        f"{_OPT_IN_ENV_VAR}=1 implies a canonical AgentOS runtime "
        "image is pullable by the cluster nodes (e.g. "
        "cognic/sandbox-runtime-python:sha256-…). The happy-path Pod "
        "create needs it; the negative-path two-credential test refuses "
        "before Pod creation so does not. See the module docstring — "
        "Z4 doesn't guess the image because the canonical-catalog "
        "contract is operator-owned."
    )
    # The operator declares the workload GID the pod runs with as its
    # pod-level ``fsGroup``. Unlike Z3 (Docker), this is NOT an image-USER
    # match — the K8s substrate preflight is GID-axis only (no image-USER
    # parse; see verify_k8s_credential_projection_preflight). The fsGroup
    # makes the projected Secret volume group-owned by this GID, and the
    # container (any non-root user) reads the mode-0440 credential files
    # via fsGroup supplementary-group membership. The fixture validates
    # int-parseability + positive-non-root here so misconfiguration
    # surfaces at fixture setup rather than from inside the preflight.
    assert expected_workload_gid_raw, (
        "COGNIC_Z4_EXPECTED_WORKLOAD_GID is unset/empty; opt-in env "
        f"{_OPT_IN_ENV_VAR}=1 requires the operator to declare the "
        "workload GID the pod runs with as its pod-level fsGroup. This "
        "is the K8s fsGroup INPUT — NOT an image-USER match (the K8s "
        "preflight does not parse the image USER directive); the "
        "container reads the mode-0440 projected Secret via fsGroup "
        "supplementary-group membership."
    )
    try:
        expected_workload_gid = int(expected_workload_gid_raw)
    except ValueError as exc:
        raise AssertionError(
            f"COGNIC_Z4_EXPECTED_WORKLOAD_GID={expected_workload_gid_raw!r} "
            f"is not an integer; opt-in env {_OPT_IN_ENV_VAR}=1 requires "
            f"a positive integer GID used as the pod-level fsGroup (NOT an "
            f"image-USER match)."
        ) from exc
    assert expected_workload_gid > 0, (
        f"COGNIC_Z4_EXPECTED_WORKLOAD_GID={expected_workload_gid} must be "
        f"a positive integer used as the pod-level fsGroup. Root GID 0 is "
        f"refused by the K8s preflight via "
        f"sandbox_credential_projection_root_workload_refused (no "
        f"dev-escape downgrade exists in K8s); negative values are "
        f"nonsensical."
    )

    # Vault reachability — urllib avoids httpx/aiohttp at fixture
    # construction. GET /v1/sys/health is unauthenticated; the
    # connection itself either succeeds or raises. Identical to Z3.
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
    # 200 = active; 429 = standby (still reachable + serving reads). Other
    # codes (472/473/501/503) mean reachable-but-not-serving — the
    # operator needs to unseal / initialize / promote.
    assert status in (200, 429), (
        f"Vault server at {addr!r} reachable but returned HTTP {status} "
        f"on /v1/sys/health — server is not in an active state (check "
        f"unseal / standby status). See the module docstring."
    )

    # Cluster reachability + namespace list-access — async via asyncio.run
    # since the fixture is sync. One short-lived event loop for the probe;
    # the probe ApiClient is created AND closed inside it so nothing
    # loop-bound leaks. ``list_namespaced_secret`` confirms BOTH cluster
    # reachability AND that the test ServiceAccount can list Secrets in
    # the target namespace (the RBAC the happy + negative paths need).
    async def _probe_cluster_and_namespace() -> None:
        try:
            await _load_kube_config()
        except (kube_config.ConfigException, FileNotFoundError) as exc:
            raise AssertionError(
                f"K8s cluster config load failed "
                f"({type(exc).__name__}: {exc}). Opt-in env "
                f"{_OPT_IN_ENV_VAR}=1 requires either an in-cluster "
                f"ServiceAccount or a readable kubeconfig "
                f"(KUBECONFIG / ~/.kube/config). See the module docstring."
            ) from exc
        api_client = kube_client.ApiClient()
        try:
            core = kube_client.CoreV1Api(api_client)
            try:
                await core.list_namespaced_secret(namespace, limit=1)
            except Exception as exc:
                raise AssertionError(
                    f"Cluster reachable-config-loaded but listing Secrets "
                    f"in namespace {namespace!r} failed "
                    f"({type(exc).__name__}: {exc}). Opt-in env "
                    f"{_OPT_IN_ENV_VAR}=1 implies the namespace exists + "
                    f"the test ServiceAccount can create/list/delete "
                    f"Secrets + Pods there. Set COGNIC_K8S_SANDBOX_NAMESPACE "
                    f"if {_DEFAULT_K8S_NAMESPACE!r} is not the right "
                    f"namespace."
                ) from exc
        finally:
            await api_client.close()

    asyncio.run(_probe_cluster_and_namespace())

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
        "namespace": namespace,
        "runtime_image": runtime_image,
        "expected_workload_gid": expected_workload_gid,
        "settings": settings,
        "transport": transport,
        "adapter": adapter,
    }


@pytest.fixture
async def z4_kube_client() -> AsyncIterator[kube_client.ApiClient]:
    """Function-scoped lifetime owner for the live ``ApiClient``.

    The ``KubernetesPodSandboxBackend`` explicitly does NOT manage the
    client's lifetime (its docstring: "the calling layer is responsible
    for ``await api_client.close()``"). This fixture IS that calling
    layer for the Z4 proofs: it creates the client inside the test's
    pytest-asyncio event loop (so the aiohttp session binds to the right
    loop), ``yield``s it, and closes it on teardown — so neither the
    happy-path nor the negative-path test can forget the close (the
    slice-2a reviewer lock). Re-loads the cluster config in the test loop
    (idempotent; ``Configuration`` is global, not loop-bound).
    """
    await _load_kube_config()
    api_client = kube_client.ApiClient()
    try:
        yield api_client
    finally:
        await api_client.close()


def _make_z4_lease_request(
    secret_path: str,
    *,
    ttl_s: int = 900,
    tenant_id: str = _Z4_TENANT_ID,
    scope_label: str = "z4-real-k8s-projection-proof",
) -> VaultLeaseRequest:
    """Build a real ``VaultLeaseRequest`` pointing at the operator-
    configured secret_path. Defaults match the Z4 scope."""
    return VaultLeaseRequest(
        secret_path=secret_path,
        ttl_s=ttl_s,
        tenant_id=tenant_id,
        actor_ref=VaultLeaseActorRef(
            actor_subject="z4-test-actor",
            actor_type="service",
        ),
        scope_label=scope_label,
    )


def _make_z4_credential_decl(
    request: VaultLeaseRequest,
    *,
    logical_name: str,
    expected_fields: tuple[str, ...] = ("password", "username"),
    purpose_category: str = "application_database_read",
    purpose_description: str = "Z4 real-Vault dynamic credential projection proof.",
) -> CredentialDecl:
    """Build a ``CredentialDecl`` paired with the given
    ``VaultLeaseRequest`` per the Sprint 10.6 T21 pair-invariant.
    ``vault_path`` / ``tenant_id`` / ``ttl_s`` derive from the request so
    the 4-invariant pair guard at ``sandbox/_credentials_pair.py`` cannot
    trip on field drift.

    The default ``expected_fields = ("password", "username")`` matches a
    real Vault ``database/postgresql`` dynamic-secret role response;
    slice 3 overrides this on credential B to inject the intentional
    mismatch that drives the LIFO unwind."""
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
# Z4 layer-2 backend builder + per-test event recorder.
#
# The substrate preflight + topology (NetworkPolicy + Pod) + Pod exec +
# K8s Secret projection executor + LIFO unwind ALL run for real against
# the operator's cluster. We deliberately stub the canonical-image-catalog
# + rego-engine seams because (a) the canonical cosign + SBOM
# infrastructure is operator-owned + already covered upstream at
# ``tests/unit/sandbox/test_catalog.py`` + (b) Wave-1 sandbox.rego
# admission is covered at ``tests/unit/policies/test_sandbox_rego.py``.
# Z4's envelope is the credential-projection lifecycle, NOT admission
# duplication.
#
# The builder does NOT create or own the ``ApiClient`` — it takes the
# loop-bound client from the ``z4_kube_client`` fixture (which owns
# ``await client.close()`` on teardown). The builder therefore returns
# just the backend; there is no per-test closure obligation (the
# slice-2a reviewer lock).
# ──────────────────────────────────────────────────────────────────────


def _make_event_recorder() -> tuple[AsyncMock, list[tuple[str, dict[str, Any]]]]:
    """Build a ``DecisionHistoryStore`` mock that intercepts every
    ``append_with_precondition`` call and captures
    ``(decision_type, payload)`` tuples in emission order.

    Mirrors the Z3 + unit-test recorder; intentionally re-implemented
    here for test-suite isolation (no cross-import from the unit tree
    into the integration tree)."""
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


def _make_z4_layer2_backend(
    *,
    kube_api_client: kube_client.ApiClient,
    namespace: str,
    adapter: VaultCredentialAdapter,
    dh_store: AsyncMock,
    settings: MagicMock,
) -> KubernetesPodSandboxBackend:
    """Construct a ``KubernetesPodSandboxBackend`` with a REAL (fixture-
    owned) ``ApiClient`` + REAL ``VaultCredentialAdapter`` + STUBBED
    admit_policy seam (catalog + rego allow-everything) + REAL substrate
    preflight (the K8s GID-axis preflight — see
    ``verify_k8s_credential_projection_preflight``).

    The stub vs real split mirrors Z3: Z4's envelope is the credential-
    projection lifecycle (mint → project → Secret-create → mount →
    workload-read → cleanup-then-revoke). The canonical-image-catalog
    cosign verification + the sandbox.rego admission gate are admission-
    time orthogonal concerns with their own coverage upstream.

    Returns just the backend. The ``ApiClient`` lifetime is owned by the
    ``z4_kube_client`` fixture (the backend explicitly does NOT manage it
    per its own docstring), so there is no per-test closure obligation."""
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    rego = MagicMock()
    rego.evaluate = AsyncMock(return_value=MagicMock(allow=True, reasoning=""))
    return KubernetesPodSandboxBackend(
        kube_api_client=kube_api_client,
        namespace=namespace,
        image_catalog=catalog,
        credential_adapter=adapter,
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=dh_store,
        settings=settings,
        warm_pool=None,
    )


def _build_z4_actor() -> Actor:
    return Actor(
        subject="z4-test-actor",
        tenant_id=_Z4_TENANT_ID,
        scopes=frozenset(),
        actor_type="service",
    )


def _build_z4_pack_context() -> PackAdmissionContext:
    return PackAdmissionContext(
        pack_id="cognic.z4_real_k8s_projection",
        pack_version="v1.0.0",
        pack_artifact_digest="sha256:" + "1" * 64,
        risk_tier="internal_write",
        declares_dynamic_install=False,
        profile="production",
    )


def _build_z4_policy(*, runtime_image: str) -> SandboxPolicy:
    return SandboxPolicy(
        cpu_cores=0.5,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=60.0,
        runtime_image=runtime_image,
        egress_allow_list=(),
        vault_path=None,
    )


# ──────────────────────────────────────────────────────────────────────
# Slice 2b — happy-path Z4 proof.
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_z4_happy_path_real_vault_real_k8s_one_credential(
    real_k8s_credential_setup: dict[str, Any],
    z4_kube_client: kube_client.ApiClient,
) -> None:
    """Z4 happy path — full mint-then-project-then-workload-read-then-
    cleanup-then-revoke lifecycle against real Vault + real Kubernetes.

    End-to-end proof per spec §5.7 + §5.8:

    * **Mint** runs through ``VaultCredentialAdapter.mint_lease`` →
      ``core/vault.lease_credential`` → real ``VaultTransport.lease``
      → real Vault server → real ``lease_id`` returned.
    * **Project** runs the T18 planner + the K8s executor: creates a
      ``type=Opaque`` Secret named ``cognic-cred-<16-hex>`` carrying the
      credential bytes base64-encoded under ``data``; the pod spec mounts
      it read-only at ``/run/credentials/db_main`` with ``defaultMode 0440``
      + a pod-level ``fsGroup`` = ``expected_workload_gid``.
    * **Workload read** — ``session.exec(["cat", "/run/credentials/db_main/<field>"])``
      inside the real Pod returns the credential bytes byte-exactly,
      readable because the container's fsGroup supplementary membership
      grants group-read on the mode-0440 file. Compared against
      ``session.active_leases[0].token[<field>]`` (NOT a separate Vault
      response — dynamic-DB creds are lease-specific).
    * **Cleanup** during ``destroy()`` deletes the K8s Secret
      (``credentials_projection_cleaned_up`` emitted) BEFORE the Vault
      revoke (``lease_revoked`` emitted) per spec §5.8 step 5 LIFO
      ordering.

    Chain audit ordering asserted: ``lease_minted`` → ``credentials_projected``
    on create; ``credentials_projection_cleaned_up`` → ``lease_revoked``
    on destroy.

    **RBAC note** — the ``real_k8s_credential_setup`` fixture probes
    Secret-LIST RBAC only. This happy path additionally exercises
    Secret-create, Pod-create/delete, and NetworkPolicy-create/delete.
    A ``kube_client.ApiException`` raised from ``create()`` is re-surfaced
    as an ``AssertionError`` naming the most-likely-missing RBAC (Pod or
    NetworkPolicy) so the operator's pre-merge audit gets an actionable
    diagnostic rather than a raw 403.
    """
    setup = real_k8s_credential_setup
    settings = setup["settings"]
    adapter = setup["adapter"]
    secret_path = setup["secret_path"]
    namespace = setup["namespace"]
    runtime_image = setup["runtime_image"]
    expected_workload_gid = setup["expected_workload_gid"]

    dh_store, events = _make_event_recorder()
    backend = _make_z4_layer2_backend(
        kube_api_client=z4_kube_client,
        namespace=namespace,
        adapter=adapter,
        dh_store=dh_store,
        settings=settings,
    )
    core = kube_client.CoreV1Api(z4_kube_client)

    actor = _build_z4_actor()
    pack_ctx = _build_z4_pack_context()
    policy = _build_z4_policy(runtime_image=runtime_image)
    request = _make_z4_lease_request(secret_path)
    decl = _make_z4_credential_decl(request, logical_name="db_main")

    # create() exercises more RBAC than the fixture's Secret-LIST probe:
    # Secret-create + Pod-create + NetworkPolicy-create. Surface a clear
    # operator diagnostic on a K8s API error (e.g. 403) so the missing
    # piece is obvious. SandboxLifecycleRefused (admission / preflight) is
    # deliberately NOT caught here — that is a real refusal the happy path
    # must not hit, and masking it would hide a genuine bug.
    try:
        session = await backend.create(
            policy,
            actor=actor,
            tenant_id=_Z4_TENANT_ID,
            pack_context=pack_ctx,
            use_warm_pool=False,
            requires_credentials=(request,),
            credential_decls=(decl,),
            expected_workload_gid=expected_workload_gid,
        )
    except kube_client.ApiException as exc:
        raise AssertionError(
            f"K8s API call during create() failed (HTTP {exc.status}: "
            f"{exc.reason}). The real_k8s_credential_setup fixture "
            f"probe verifies Secret-LIST RBAC only; the happy path "
            f"additionally needs Secret-create + Pod-create/delete + "
            f"NetworkPolicy-create/delete RBAC in namespace {namespace!r}. "
            f"A 403 here most likely means the test ServiceAccount is "
            f"missing Pod or NetworkPolicy permissions. See the module "
            f"docstring's bootstrap notes."
        ) from exc

    # Narrow the SandboxSession Protocol to the concrete K8s session so
    # the active_projections assertion is type-safe — active_projections
    # is a T21 per-backend field, not on the upstream SandboxSession
    # Protocol (active_leases is).
    assert isinstance(session, KubernetesPodSession)

    try:
        # ── (1) Lease landed with a real Vault-issued lease_id + payload.
        assert len(session.active_leases) == 1, (
            f"Expected exactly 1 active lease; got {len(session.active_leases)}"
        )
        lease = session.active_leases[0]
        assert lease.lease_id, "real Vault must issue a non-empty lease_id"
        assert "username" in lease.token, (
            f"Expected 'username' field in lease token; got keys {sorted(lease.token.keys())}"
        )
        assert "password" in lease.token, (
            f"Expected 'password' field in lease token; got keys {sorted(lease.token.keys())}"
        )

        # ── (2) Projection landed exactly once (1:1 with active_leases).
        #        Capture the EXACT opaque Secret name now (while the
        #        session is alive) for the precise post-destroy lookup.
        assert len(session.active_projections) == 1, (
            f"Expected exactly 1 active projection; got {len(session.active_projections)}"
        )
        projection = session.active_projections[0]
        secret_name = projection.secret_name

        # ── (3) Workload reads credential bytes byte-exactly via the real
        #        Pod exec. Compare against session.active_leases[0].token
        #        (lease-specific dynamic creds; NOT a separate Vault
        #        response). Group-read works via the pod fsGroup
        #        supplementary membership on the mode-0440 Secret file.
        for field in ("password", "username"):
            cat_result = await session.exec(
                ["cat", f"/run/credentials/db_main/{field}"],
                timeout_s=15.0,
            )
            assert cat_result.exit_code == 0, (
                f"cat /run/credentials/db_main/{field} failed: exit "
                f"{cat_result.exit_code}; stderr={cat_result.stderr!r}"
            )
            assert cat_result.stdout == lease.token[field].encode("utf-8"), (
                f"Mounted /run/credentials/db_main/{field} bytes "
                f"diverged from session.active_leases[0].token[{field!r}]"
            )

        # ── (4) Mount directory shows EXACTLY the declared expected_fields.
        ls_result = await session.exec(
            ["ls", "-A", "/run/credentials/db_main/"],
            timeout_s=15.0,
        )
        assert ls_result.exit_code == 0, (
            f"ls /run/credentials/db_main/ failed: exit "
            f"{ls_result.exit_code}; stderr={ls_result.stderr!r}"
        )
        listed = sorted(ls_result.stdout.decode("utf-8").split())
        assert listed == ["password", "username"], (
            f"Mount directory listing diverged from declared expected_fields; saw {listed!r}"
        )

        # ── (5) Chain audit ordering on create(): lease_minted before
        #        credentials_projected for the same logical credential.
        create_suffixes = _emitted_event_suffixes(events)
        assert "lease_minted" in create_suffixes
        assert "credentials_projected" in create_suffixes
        lease_minted_idx = create_suffixes.index("lease_minted")
        projected_idx = create_suffixes.index("credentials_projected")
        assert lease_minted_idx < projected_idx, (
            f"lease_minted ({lease_minted_idx}) must precede "
            f"credentials_projected ({projected_idx}) per spec §5.8 "
            f"step 3; event order seen: {create_suffixes}"
        )

        # ── (5b) credentials_projected payload shape per spec §5.7.
        #         backend_resource_name is the K8s opaque Secret name
        #         (NOT a host path — the K8s analog of Z3's host_staging_dir).
        projected_payloads = [
            payload for name, payload in events if name == "sandbox.lifecycle.credentials_projected"
        ]
        assert len(projected_payloads) == 1, (
            f"Expected exactly 1 credentials_projected row; got {len(projected_payloads)}"
        )
        projected_payload = projected_payloads[0]
        assert projected_payload["logical_name"] == "db_main"
        assert projected_payload["vault_path"] == secret_path
        assert projected_payload["tenant_id"] == _Z4_TENANT_ID
        assert projected_payload["lease_id"] == lease.lease_id, (
            f"credentials_projected lease_id diverged from the minted "
            f"lease; payload={projected_payload['lease_id']!r}, "
            f"lease={lease.lease_id!r}"
        )
        assert projected_payload["projected_field_count"] == 2, (
            f"Expected projected_field_count=2 (username + password); "
            f"got: {projected_payload['projected_field_count']!r}"
        )
        assert projected_payload["purpose_category"] == "application_database_read", (
            f"Expected purpose_category=application_database_read; got: "
            f"{projected_payload['purpose_category']!r}"
        )
        assert (
            projected_payload["purpose_description"]
            == "Z4 real-Vault dynamic credential projection proof."
        )
        # backend_resource_name is the K8s opaque Secret name per spec
        # §5.7; must match the session's projection record exactly.
        assert projected_payload["backend_resource_name"] == secret_name, (
            f"credentials_projected backend_resource_name diverged from "
            f"the projection's secret_name; payload="
            f"{projected_payload['backend_resource_name']!r}, "
            f"projection={secret_name!r}"
        )
        assert projected_payload["session_id"] == session.session_id, (
            f"credentials_projected session_id diverged from the session; "
            f"payload={projected_payload['session_id']!r}, "
            f"session={session.session_id!r}"
        )
        # Defence-in-depth: NO credential token value leaks into the chain
        # payload (the §5.7 contract carries provenance, never field values).
        rendered_payload = repr(projected_payload)
        for secret_value in lease.token.values():
            assert secret_value not in rendered_payload, (
                "credentials_projected payload leaked a credential token "
                "value — §5.7 carries provenance only, never field values"
            )

        # ── (5c) The EXACT opaque Secret EXISTS on the cluster before
        #         destroy(). Targets the specific secret_name (not a broad
        #         label selector) so a stale unrelated Z4 Secret cannot
        #         influence the proof.
        secret = await core.read_namespaced_secret(name=secret_name, namespace=namespace)
        assert secret is not None, (
            f"Secret {secret_name!r} should exist on the cluster after a "
            f"successful projection (pre-destroy)"
        )
    finally:
        # destroy() triggers the T21 LIFO unwind: projection cleanup FIRST
        # (Secret delete + credentials_projection_cleaned_up) then Vault
        # revoke (lease_revoked) per spec §5.8 step 5 — even on test-body
        # failure, tear down to avoid leaking a Pod + a dangling Vault
        # lease. The ApiClient itself is closed by the z4_kube_client
        # fixture teardown, not here.
        await session.destroy()

    # ── (6) Post-destroy chain ordering on the same logical credential:
    #        credentials_projection_cleaned_up MUST precede lease_revoked.
    final_suffixes = _emitted_event_suffixes(events)
    assert "credentials_projection_cleaned_up" in final_suffixes, (
        f"Expected credentials_projection_cleaned_up after destroy(); "
        f"event order seen: {final_suffixes}"
    )
    assert "lease_revoked" in final_suffixes, (
        f"Expected lease_revoked after destroy(); event order seen: {final_suffixes}"
    )
    cleanup_idx = final_suffixes.index("credentials_projection_cleaned_up")
    revoke_idx = final_suffixes.index("lease_revoked")
    assert cleanup_idx < revoke_idx, (
        f"credentials_projection_cleaned_up ({cleanup_idx}) must precede "
        f"lease_revoked ({revoke_idx}) per spec §5.8 step 5 LIFO ordering "
        f"invariant; event order seen: {final_suffixes}"
    )

    # ── (7) The EXACT opaque Secret is GONE after destroy(). read of the
    #        specific secret_name raises ApiException 404 — direct cluster
    #        proof that the T21 LIFO cleanup deleted THIS Secret (not just
    #        that the cleaned_up event was emitted, and not masked by any
    #        stale unrelated Z4 Secret).
    with pytest.raises(kube_client.ApiException) as exc_info:
        await core.read_namespaced_secret(name=secret_name, namespace=namespace)
    assert exc_info.value.status == 404, (
        f"Expected HTTP 404 reading Secret {secret_name!r} after destroy() "
        f"(T21 LIFO projection cleanup per spec §5.8 step 5); got HTTP "
        f"{exc_info.value.status}"
    )


# ──────────────────────────────────────────────────────────────────────
# Slice 3 — negative-path Z4 proof: the two-credential LIFO-coverage
# variant (the headline of T23 per the Sprint 10.6 plan).
#
# Mechanism: TWO credentials minted from the SAME operator-configured
# dynamic role (each ``transport.lease`` issues a distinct lease with its
# own ``{username, password}``):
#   * Credential A declares ``expected_fields = ("password", "username")``
#     → MATCHES the role response → projects → real K8s Secret created →
#     ``credentials_projected(A)``.
#   * Credential B declares ``expected_fields = ("token", "username")``
#     → MISMATCH → T18 ``compute_projection_plan`` returns
#     ``ProjectionRefused(reason="sandbox_credential_projection_field_set_mismatch")``
#     BEFORE the K8s executor runs → NO Secret ever created for B.
#
# T21's Path-2 + LIFO contract (spec §5.8 step 3 + step 5) then:
#   * Revoke-only B's just-minted lease (real Vault); emit
#     ``credentials_projection_failed(B, revoke_outcome="revoked")`` — NO
#     separate ``lease_revoked`` row for B (revoke status is embedded in
#     ``revoke_outcome``).
#   * LIFO-unwind A: delete Secret A (cleanup FIRST) → emit
#     ``credentials_projection_cleaned_up(A)`` → revoke A → emit
#     ``lease_revoked(A)``.
#   * Raise ``SandboxLifecycleRefused`` — workload Pod never created.
#
# Mechanism rationale (Sprint 10.6 plan T23 negative-path lock): a
# manifest field-set mismatch is operator-controlled + reproducible.
# Reconfiguring the Vault role to emit different fields is impractical for
# a database engine + leaks per-test config into the operator's
# pre-existing Vault server. Mismatch-at-manifest keeps the negative path
# local to the test module.
#
# Per-run UNIQUE logical names (``uuid4`` suffix) keep the label-selector
# proofs collision-free: a stale unrelated Z4 Secret cannot carry our
# per-run ``cognic/logical-name`` value. A's deletion proof additionally
# targets A's EXACT opaque ``secret_name`` (read → 404), not a broad label
# count (the slice-2b reviewer lock applied to the unwind path).
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_z4_negative_path_two_credential_lifo_unwind(
    real_k8s_credential_setup: dict[str, Any],
    z4_kube_client: kube_client.ApiClient,
) -> None:
    """Z4 negative path — credential A projects, credential B refuses at
    the T18 planner, A's already-created K8s Secret is DELETED during the
    LIFO unwind. Full cross-credential LIFO coverage per spec §5.8 step 5.

    End-to-end proof per spec §5.7 + §5.8:

    * **Mint A → project A**: real Vault lease + real ``create_namespaced_secret``
      → ``credentials_projected(A)`` chain row carrying A's opaque
      ``secret_name`` in ``backend_resource_name`` + A's ``session_id``.
    * **Mint B → refuse B**: real Vault lease for B, then the T18 planner
      detects the field-set mismatch (manifest declares
      ``("token", "username")``; the role response carries
      ``("username", "password")``) → ``ProjectionRefused`` BEFORE the K8s
      executor runs → NO Secret for B. Revoke-only B's lease (real Vault)
      → ``credentials_projection_failed(B, revoke_outcome="revoked")``.
    * **LIFO unwind A**: delete Secret A (cleanup FIRST) →
      ``credentials_projection_cleaned_up(A)`` → revoke A → ``lease_revoked(A)``.
    * **Raise** ``SandboxLifecycleRefused`` — the workload Pod is never
      created (the loop refuses at step 3, before step 6 topology).

    Assertions:

    * **(a)** NO K8s Secret exists for credential B — list by B's per-run
      unique ``cognic/logical-name`` label returns empty (B never reached
      the executor).
    * **(b)** A's Secret was created THEN deleted: the ``credentials_projected(A)``
      chain row proves creation (emitted only after the real Secret-create
      succeeds); a ``read_namespaced_secret`` of A's EXACT ``secret_name``
      returns HTTP 404 proving deletion; and the chain order is
      ``credentials_projected(A)`` → ``credentials_projection_failed(B)`` →
      ``credentials_projection_cleaned_up(A)`` → ``lease_revoked(A)``.
    * **(c)** Workload Pod never starts — list Pods by the session's
      ``cognic.agentos.sandbox.session_id`` label (extracted from the
      ``credentials_projected(A)`` payload) returns empty.

    **RBAC note** — this negative path exercises Secret-create + Secret-delete
    RBAC (for credential A's project-then-unwind), but NOT Pod or
    NetworkPolicy RBAC (it refuses before Pod creation). A
    ``kube_client.ApiException`` from ``create()`` is re-surfaced as an
    ``AssertionError`` naming Secret create/delete RBAC as the likely
    missing piece. The expected ``SandboxLifecycleRefused`` (B's field-set
    mismatch) is the green outcome and is NOT treated as an error.
    """
    setup = real_k8s_credential_setup
    settings = setup["settings"]
    adapter = setup["adapter"]
    secret_path = setup["secret_path"]
    namespace = setup["namespace"]
    expected_workload_gid = setup["expected_workload_gid"]

    dh_store, events = _make_event_recorder()
    backend = _make_z4_layer2_backend(
        kube_api_client=z4_kube_client,
        namespace=namespace,
        adapter=adapter,
        dh_store=dh_store,
        settings=settings,
    )
    core = kube_client.CoreV1Api(z4_kube_client)

    actor = _build_z4_actor()
    pack_ctx = _build_z4_pack_context()
    # runtime_image only matters for the (never-reached) Pod create; the
    # policy still needs a valid runtime_image to pass admission shape.
    policy = _build_z4_policy(runtime_image=setup["runtime_image"])

    # Per-run unique logical names keep the label-selector proofs
    # collision-free (grammar ^[a-z][a-z0-9_]{0,31}$; ≤32 chars).
    run_suffix = uuid.uuid4().hex[:6]
    logical_a = f"db_main_a_{run_suffix}"
    logical_b = f"db_main_b_{run_suffix}"

    # Both credentials mint from the SAME operator-configured role; each
    # lease() issues a fresh distinct lease. A matches; B mismatches.
    request_a = _make_z4_lease_request(secret_path)
    request_b = _make_z4_lease_request(secret_path)
    decl_a = _make_z4_credential_decl(request_a, logical_name=logical_a)
    decl_b = _make_z4_credential_decl(
        request_b,
        logical_name=logical_b,
        expected_fields=("token", "username"),
    )

    # create() exercises Secret-create + Secret-delete RBAC on this path
    # (project A then unwind A); it does NOT reach Pod / NetworkPolicy
    # creation (refuses at step 3). Expected outcome is
    # SandboxLifecycleRefused (B's field-set mismatch). A K8s ApiException
    # means missing Secret RBAC — surface a clear operator diagnostic.
    try:
        await backend.create(
            policy,
            actor=actor,
            tenant_id=_Z4_TENANT_ID,
            pack_context=pack_ctx,
            use_warm_pool=False,
            requires_credentials=(request_a, request_b),
            credential_decls=(decl_a, decl_b),
            expected_workload_gid=expected_workload_gid,
        )
    except SandboxLifecycleRefused:
        # Green path — B's field-set mismatch refused the create after A
        # projected + was LIFO-unwound.
        pass
    except kube_client.ApiException as exc:
        raise AssertionError(
            f"K8s API call during create() failed (HTTP {exc.status}: "
            f"{exc.reason}). This negative path exercises Secret-create + "
            f"Secret-delete RBAC in namespace {namespace!r} (for credential "
            f"A's project-then-unwind); it does NOT reach Pod/NetworkPolicy "
            f"creation. A 403 here most likely means the test ServiceAccount "
            f"is missing Secret create/delete permissions. See the module "
            f"docstring's bootstrap notes."
        ) from exc
    else:
        raise AssertionError(
            "create() should have raised SandboxLifecycleRefused on "
            "credential B's field-set mismatch, but returned a session. "
            "The two-credential LIFO negative path did not refuse."
        )

    suffixes = _emitted_event_suffixes(events)

    # ── (3) Chain audit — the cross-credential LIFO ordering. Each of
    #        these four events occurs EXACTLY ONCE (B's revoke is embedded
    #        in credentials_projection_failed.revoke_outcome — no separate
    #        lease_revoked row for B), so .index() is unambiguous.
    for required in (
        "credentials_projected",
        "credentials_projection_failed",
        "credentials_projection_cleaned_up",
        "lease_revoked",
    ):
        assert suffixes.count(required) == 1, (
            f"Expected exactly 1 {required!r} event on the two-credential "
            f"LIFO path; got {suffixes.count(required)}. event order: {suffixes}"
        )
    # Two mints (A + B both minted before B's planner refusal).
    assert suffixes.count("lease_minted") == 2, (
        f"Expected exactly 2 lease_minted events (A + B both minted before "
        f"B refused at the planner); got {suffixes.count('lease_minted')}. "
        f"event order: {suffixes}"
    )

    projected_idx = suffixes.index("credentials_projected")
    failed_idx = suffixes.index("credentials_projection_failed")
    cleaned_idx = suffixes.index("credentials_projection_cleaned_up")
    revoked_idx = suffixes.index("lease_revoked")
    assert projected_idx < failed_idx < cleaned_idx < revoked_idx, (
        f"Expected LIFO ordering credentials_projected(A) "
        f"({projected_idx}) < credentials_projection_failed(B) "
        f"({failed_idx}) < credentials_projection_cleaned_up(A) "
        f"({cleaned_idx}) < lease_revoked(A) ({revoked_idx}) per spec §5.8 "
        f"step 3 + step 5; event order seen: {suffixes}"
    )

    # ── Extract A's identifiers from the credentials_projected(A) payload.
    #    create() raised + returned no session, so the chain row is the
    #    only handle on A's opaque secret_name + session_id.
    projected_payloads = [
        payload for name, payload in events if name == "sandbox.lifecycle.credentials_projected"
    ]
    assert len(projected_payloads) == 1
    projected_a = projected_payloads[0]
    assert projected_a["logical_name"] == logical_a, (
        f"credentials_projected must be for credential A ({logical_a!r}); "
        f"got logical_name={projected_a['logical_name']!r}"
    )
    a_secret_name = projected_a["backend_resource_name"]
    a_session_id = projected_a["session_id"]

    # ── credentials_projection_failed(B) payload shape per spec §5.7.
    #    expected_fields / actual_fields / extras / missing all alphabetized.
    failed_payloads = [
        payload
        for name, payload in events
        if name == "sandbox.lifecycle.credentials_projection_failed"
    ]
    assert len(failed_payloads) == 1
    failed_b = failed_payloads[0]
    assert failed_b["reason"] == "sandbox_credential_projection_field_set_mismatch", (
        f"Expected reason=sandbox_credential_projection_field_set_mismatch; "
        f"got: {failed_b['reason']!r}"
    )
    assert failed_b["logical_name"] == logical_b, (
        f"credentials_projection_failed must be for credential B "
        f"({logical_b!r}); got logical_name={failed_b['logical_name']!r}"
    )
    assert failed_b["expected_fields"] == ["token", "username"], (
        f"Expected alphabetized expected_fields=['token', 'username']; "
        f"got: {failed_b['expected_fields']!r}"
    )
    assert failed_b["actual_fields"] == ["password", "username"], (
        f"Expected alphabetized actual_fields=['password', 'username'] "
        f"(real database/postgresql role response); got: "
        f"{failed_b['actual_fields']!r}"
    )
    assert failed_b["extras"] == ["password"], (
        f"Expected extras=['password'] (Vault returned, manifest didn't "
        f"declare); got: {failed_b['extras']!r}"
    )
    assert failed_b["missing"] == ["token"], (
        f"Expected missing=['token'] (manifest declared, Vault didn't "
        f"return); got: {failed_b['missing']!r}"
    )
    assert failed_b["revoke_outcome"] == "revoked", (
        f"Expected revoke_outcome='revoked' (real Vault revoke of B's "
        f"just-minted lease should succeed); got: {failed_b['revoke_outcome']!r}"
    )

    # ── credentials_projection_cleaned_up(A) payload — confirm the
    #    cleaned-up credential is A + the K8s cleanup target.
    cleaned_payloads = [
        payload
        for name, payload in events
        if name == "sandbox.lifecycle.credentials_projection_cleaned_up"
    ]
    assert len(cleaned_payloads) == 1
    cleaned_a = cleaned_payloads[0]
    assert cleaned_a["logical_name"] == logical_a, (
        f"credentials_projection_cleaned_up must be for credential A "
        f"({logical_a!r}); got logical_name={cleaned_a['logical_name']!r}"
    )
    assert cleaned_a["cleanup_target"] == "secret_resource", (
        f"Expected K8s cleanup_target='secret_resource'; got: {cleaned_a['cleanup_target']!r}"
    )

    # ── (a) NO K8s Secret exists for credential B. B refused at the
    #        planner BEFORE the executor, so no Secret was ever created.
    #        List by B's per-run unique logical-name label (collision-free).
    b_secrets = await core.list_namespaced_secret(
        namespace, label_selector=f"cognic/logical-name={logical_b}"
    )
    assert b_secrets.items == [], (
        f"Credential B ({logical_b!r}) must have NO K8s Secret — it refused "
        f"at the planner before the executor ran; found "
        f"{[s.metadata.name for s in b_secrets.items]}"
    )

    # ── (b) A's Secret was created (proven by credentials_projected(A))
    #        THEN deleted during the LIFO unwind — read A's EXACT opaque
    #        secret_name → HTTP 404. Targets the specific name (not a broad
    #        label count) so a stale unrelated Z4 Secret cannot mask the
    #        deletion proof.
    with pytest.raises(kube_client.ApiException) as exc_info:
        await core.read_namespaced_secret(name=a_secret_name, namespace=namespace)
    assert exc_info.value.status == 404, (
        f"Expected HTTP 404 reading A's Secret {a_secret_name!r} after the "
        f"LIFO unwind (spec §5.8 step 5 deletes A's Secret BEFORE revoking "
        f"A's lease); got HTTP {exc_info.value.status} — A's Secret leaked"
    )

    # ── (c) Workload Pod never starts. The loop refused at step 3 (before
    #        step 6 topology), so no Pod carries this session's label.
    #        session_id extracted from the credentials_projected(A) payload.
    session_pods = await core.list_namespaced_pod(
        namespace,
        label_selector=f"cognic.agentos.sandbox.session_id={a_session_id}",
    )
    assert session_pods.items == [], (
        f"Workload Pod must never start on the projection-refusal path "
        f"(create refuses at step 3, before step 6 topology); found pods "
        f"{[p.metadata.name for p in session_pods.items]} for session "
        f"{a_session_id!r}"
    )
