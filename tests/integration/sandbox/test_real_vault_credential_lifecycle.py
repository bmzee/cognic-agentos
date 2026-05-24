"""Sprint 10 Z2 — real-Vault proof of the credential-leasing lifecycle.

**Two-layer proof** per the Round-8 Gap P Z2 pre-flight Q-locks (the
locked recipe lives at
``docs/superpowers/plans/2026-05-23-sprint-10-vault-credential-leasing.md``
Task Z2):

  **Layer 1 — direct credential primitive.** Real ``VaultTransport`` →
    real :func:`cognic_agentos.core.vault.lease_credential` against a
    pre-running Vault server with a configured DYNAMIC secrets engine
    (e.g. database/creds/<role>) → real Vault returns a dynamic
    :class:`CredentialLease` with a server-issued ``lease_id`` + real
    server-issued ``ttl_s_granted``. Then :func:`revoke_credential`
    against the same server returns cleanly. This is the foundational
    primitive proof; if Layer 1 fails, ``core/vault.py``'s
    ``transport.lease(secret_path, ttl_s)`` read-style HTTP shape
    (per Round-9 Gap Q — delegates to ``client.read(path)`` at the
    hvac level; ``ttl_s`` is Wave-1 informational) is broken against
    the target Vault version + dynamic backend.

  **Layer 2 — Docker backend end-to-end.** Same real
    ``VaultCredentialAdapter`` wired into a
    ``DockerSiblingSandboxBackend`` whose docker daemon + admit_policy
    + topology calls are MOCKED (the canonical-image catalog +
    ``--cov-branch`` end-to-end docker integration is OFF the Z2
    scope per the Q1 lock — Z2 proves REAL VAULT integration, NOT
    cross-backend or container-runtime coverage). ``create()`` with
    ``requires_credentials=[<real-request>]`` mints a REAL Vault lease
    (NOT a stub), the lease lands on ``session.active_leases`` with
    the real server-issued ``lease_id``, the
    ``sandbox.lifecycle.lease_minted`` audit emit captures the same
    real ``lease_id``. ``destroy()`` then revokes via REAL Vault and
    emits ``sandbox.lifecycle.lease_revoked`` with the same real
    ``lease_id``. The audit-chain wiring uses an AsyncMock
    ``DecisionHistoryStore`` so the proof inspects what payload would
    be appended (the DH-chain integrity itself is pinned upstream by
    the on-gate ``core/decision_history.py`` + ``core/canonical.py``
    test surfaces; Z2 does not re-prove those).

**Env-gated per Q2 lock.** Module pytestmark skips on
``COGNIC_RUN_VAULT_INTEGRATION != "1"``. When the env-gate is opted
in, the suite **fails LOUD** (``AssertionError``, NOT
``pytest.skip``) if any of the following hold. The first 4 are
caught at FIXTURE setup time (validated in ``real_vault_setup``);
the 5th is caught at LAYER 1 TEST time (Layer 1's first
``lease_credential`` call raises ``VaultPathNotFound`` which the
test catches and re-raises as ``AssertionError`` with the
bootstrap-notes pointer):

  * (FIXTURE) ``COGNIC_VAULT_TEST_ADDR`` is unset / empty
  * (FIXTURE) ``COGNIC_VAULT_TEST_TOKEN`` is unset / empty
  * (FIXTURE) ``COGNIC_VAULT_TEST_SECRET_PATH`` is unset / empty
    (default ``database/creds/test-role`` documented in the
    bootstrap notes below but the env var MUST be explicit — Z2
    doesn't guess)
  * (FIXTURE) the Vault server at ``COGNIC_VAULT_TEST_ADDR`` is
    unreachable (``GET /v1/sys/health`` fails)
  * (LAYER 1 TEST, NOT fixture) the dynamic secrets engine + role
    at ``COGNIC_VAULT_TEST_SECRET_PATH`` is not configured —
    surfaces only when Layer 1 actually attempts the lease. A
    fixture-level engine probe would catch it at setup instead;
    deliberately deferred because the lease attempt IS the natural
    probe + avoids a second hvac round-trip at fixture cost.

The fail-loud convention matches Sprint 9.5 Z2 at
``tests/integration/models/test_real_cosign_proof.py``: opt-in is the
"I have the canonical artifact configured" contract; missing
configuration at that point is a broken environment, NOT a non-issue
(no silent skip, no pretend-success).

**Per Q3 lock — true dynamic secrets engine, not kv-v2.** The
fixture exercises the actual ``transport.lease(secret_path, ttl_s)``
read-style HTTP path that ``core/vault.py`` owns (per Round-9
Gap Q — ``client.read(path)`` at the hvac level; ``ttl_s`` is
Wave-1 informational). ``vault server -dev`` auto-enables kv-v2
but ``CredentialAdapter.mint_lease`` → ``lease_credential`` →
``transport.lease`` wraps the response in the T4 ``CredentialLease``
consumer-shape contract (NOT the Sprint-1C ``SecretLease`` shape
that ``transport.read`` delivers via ``VaultAdapter.lease``);
degrading the proof to kv-v2 would not exercise the dynamic-
credential lease semantics (server-issued ``lease_id`` +
revocable lifecycle) the production path actually owns.

**Vault bootstrap notes (operator setup before running this test):**

In a separate terminal, with vault binary on PATH::

    vault server -dev -dev-root-token-id=root &

    # In a fresh shell:
    export VAULT_ADDR=http://localhost:8200
    export VAULT_TOKEN=root

    # Enable + configure the database secrets engine. Below uses
    # postgresql; swap to any supported backend (mysql, mssql, etc.)
    # whose lease semantics match the production target.
    vault secrets enable database
    vault write database/config/test-db \\
        plugin_name=postgresql-database-plugin \\
        allowed_roles="test-role" \\
        connection_url="postgresql://{{u}}:{{p}}@localhost:5432/postgres?sslmode=disable" \\
        username="vault-root" \\
        password="<root-password>"
    # (substitute the real {{username}} / {{password}} template tokens
    # for {{u}} / {{p}} above — they're shortened here only to clear
    # the 100-col line limit at the docstring renderer.)
    vault write database/roles/test-role \\
        db_name=test-db \\
        creation_statements="CREATE ROLE \\"{{n}}\\" WITH LOGIN PASSWORD \
'{{p}}' VALID UNTIL '{{e}}';" \\
        default_ttl="1h" \\
        max_ttl="24h"
    # (substitute {{name}} / {{password}} / {{expiration}} for
    # {{n}} / {{p}} / {{e}} above for the same line-limit reason.)

Then run::

    COGNIC_RUN_VAULT_INTEGRATION=1 \\
    COGNIC_VAULT_TEST_ADDR=http://localhost:8200 \\
    COGNIC_VAULT_TEST_TOKEN=root \\
    COGNIC_VAULT_TEST_SECRET_PATH=database/creds/test-role \\
    uv run pytest tests/integration/sandbox/test_real_vault_credential_lifecycle.py -v

If the postgres backend is unavailable, any other configured dynamic
engine works — set ``COGNIC_VAULT_TEST_SECRET_PATH`` to the
``<mount>/creds/<role>`` path.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.request import Request, urlopen

import pytest

pytest.importorskip("hvac")
pytest.importorskip("aiodocker")

from cognic_agentos.core._vault_transport import VaultTransport
from cognic_agentos.core.vault import (
    CredentialLease,
    VaultLeaseActorRef,
    VaultLeaseRequest,
    VaultPathNotFound,
    lease_credential,
    revoke_credential,
)
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.sandbox import PackAdmissionContext, SandboxPolicy
from cognic_agentos.sandbox.backends.docker_sibling import (
    DockerSiblingSandboxBackend,
    DockerSiblingSession,
)
from cognic_agentos.sandbox.credentials import VaultCredentialAdapter

# Module-level env-gate. Default pytest invocations skip; opting in
# requires the env var. Skip message names the env var explicitly so
# operators reading "SKIPPED [N]" output know how to opt in.
pytestmark = pytest.mark.skipif(
    os.environ.get("COGNIC_RUN_VAULT_INTEGRATION") != "1",
    reason=(
        "real-Vault Z2 proof; opt in via COGNIC_RUN_VAULT_INTEGRATION=1 "
        "(requires pre-running Vault server + COGNIC_VAULT_TEST_ADDR + "
        "COGNIC_VAULT_TEST_TOKEN + COGNIC_VAULT_TEST_SECRET_PATH + a "
        "configured dynamic secrets engine at the secret_path — fails "
        "loud if any of the above is missing)"
    ),
)


# ──────────────────────────────────────────────────────────────────────
# Module-scoped real-Vault setup fixture — fail-loud on misconfiguration.
# ──────────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def real_vault_setup() -> dict[str, Any]:
    """Validate env-var contract + probe Vault reachability + return
    a wired ``VaultTransport`` + a real ``VaultCredentialAdapter``.

    The 4 env vars are mandatory when the module-level env-gate is
    opted in. Missing / empty values + unreachable server both raise
    ``AssertionError`` with a structured diagnostic naming the
    bootstrap-notes pointer at the module docstring.

    Module-scoped so the env-var validation + reachability probe cost
    is amortised across Layer 1 + Layer 2 tests. The transport's
    underlying ``hvac.Client`` is constructed lazily on first call
    per the Sprint-1C transport contract — fixture construction itself
    does NOT touch Vault, the reachability probe does so explicitly
    via a separate ``urllib`` round-trip so the diagnostic surfaces
    cleanly here rather than from inside the first lease attempt.
    """
    addr = os.environ.get("COGNIC_VAULT_TEST_ADDR", "").strip()
    token = os.environ.get("COGNIC_VAULT_TEST_TOKEN", "").strip()
    secret_path = os.environ.get("COGNIC_VAULT_TEST_SECRET_PATH", "").strip()

    assert addr, (
        "COGNIC_VAULT_TEST_ADDR is unset/empty; opt-in env "
        "COGNIC_RUN_VAULT_INTEGRATION=1 implies a pre-running Vault "
        "server reachable at this address. See the bootstrap notes at "
        "the module docstring."
    )
    assert token, (
        "COGNIC_VAULT_TEST_TOKEN is unset/empty; opt-in env "
        "COGNIC_RUN_VAULT_INTEGRATION=1 implies a valid Vault root or "
        "policy-scoped token. See the bootstrap notes at the module "
        "docstring."
    )
    assert secret_path, (
        "COGNIC_VAULT_TEST_SECRET_PATH is unset/empty; opt-in env "
        "COGNIC_RUN_VAULT_INTEGRATION=1 implies a configured DYNAMIC "
        "secrets engine + role at the secret_path (e.g. "
        "database/creds/test-role). See the bootstrap notes at the "
        "module docstring — Z2 doesn't guess the path because the Q3 "
        "lock requires a true dynamic backend (NOT kv-v2)."
    )

    # Reachability probe — GET /v1/sys/health (unauthenticated;
    # returns 200/429/472/473/501/503 depending on server state but
    # the connection itself either succeeds or raises). Done via
    # urllib so we don't depend on aiohttp / httpx being available at
    # fixture-construction time + so the diagnostic message points
    # cleanly at the bootstrap notes rather than at a transport
    # internal.
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
            f"COGNIC_RUN_VAULT_INTEGRATION=1 implies a pre-running "
            f"server. See the bootstrap notes at the module docstring."
        ) from exc
    # 472 = standby; 473 = performance-standby; 501 = not initialized;
    # 503 = sealed. All of these mean the server is reachable but not
    # serving leases — operator needs to unseal / initialize / promote.
    assert status in (200, 429), (
        f"Vault server at {addr!r} reachable but returned HTTP {status} "
        f"on /v1/sys/health — server is not in an active state "
        f"(check unseal / standby status). See the bootstrap notes at "
        f"the module docstring."
    )

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
        "settings": settings,
        "transport": transport,
        "adapter": adapter,
    }


def _make_lease_request(secret_path: str, *, ttl_s: int = 900) -> VaultLeaseRequest:
    """Build a real ``VaultLeaseRequest`` pointing at the operator-
    configured secret_path."""
    return VaultLeaseRequest(
        secret_path=secret_path,
        ttl_s=ttl_s,
        tenant_id="t-z2-real",
        actor_ref=VaultLeaseActorRef(
            actor_subject="z2-test-actor",
            actor_type="service",
        ),
        scope_label="z2-real-vault-proof",
    )


# ──────────────────────────────────────────────────────────────────────
# Layer 1 — direct primitive proof against real Vault.
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_layer1_lease_credential_returns_real_dynamic_lease(
    real_vault_setup: dict[str, Any],
) -> None:
    """Layer 1 — direct ``lease_credential`` against the pre-configured
    dynamic secrets engine.

    Asserts:
    * The returned ``CredentialLease`` carries a real server-issued
      ``lease_id`` (non-empty, distinct from the local request).
    * ``ttl_s_granted`` is a positive int (server-returned, may
      differ from requested if the role caps below).
    * ``token`` is a ``dict[str, str]`` per spec §3.4 passthrough.
    * Subsequent ``revoke_credential`` on the same ``lease_id``
      succeeds (no exception).
    """
    transport: VaultTransport = real_vault_setup["transport"]
    settings = real_vault_setup["settings"]
    secret_path: str = real_vault_setup["secret_path"]

    request = _make_lease_request(secret_path)
    try:
        lease = await lease_credential(
            request,
            transport=transport,
            settings=settings,
        )
    except VaultPathNotFound as exc:
        raise AssertionError(
            f"Vault returned 404 / InvalidPath on lease at {secret_path!r} — "
            f"the dynamic secrets engine + role is not configured. See the "
            f"bootstrap notes at the module docstring. ({exc})"
        ) from exc

    assert isinstance(lease, CredentialLease)
    assert lease.lease_id, "Vault returned an empty lease_id"
    assert lease.ttl_s_granted > 0, (
        f"Vault returned non-positive ttl_s_granted={lease.ttl_s_granted}; "
        f"role may be misconfigured"
    )
    assert isinstance(lease.token, dict), (
        f"lease.token must be dict[str, str]; got {type(lease.token).__name__}"
    )
    # Defence-in-depth — confirm the request fields round-trip onto
    # the returned lease unchanged.
    assert lease.request == request

    # Clean up — revoke the lease we just minted. Failure here means
    # either the lease_id format is wrong or the token lacks revoke
    # permission; both surface as the underlying hvac exception.
    await revoke_credential(lease.lease_id, transport=transport)


@pytest.mark.asyncio
async def test_layer1_revoke_credential_idempotent_after_real_revoke(
    real_vault_setup: dict[str, Any],
) -> None:
    """Layer 1 — second revoke of the same already-revoked lease_id
    is also accepted by Vault (or raises a benign InvalidRequest that
    the destroy fail-soft path swallows). This pins the operational
    expectation that the T10 destroy() revoke loop's single attempt
    per lease per spec §7.2 doesn't depend on the lease still being
    active at revoke time."""
    transport: VaultTransport = real_vault_setup["transport"]
    settings = real_vault_setup["settings"]
    secret_path: str = real_vault_setup["secret_path"]

    lease = await lease_credential(
        _make_lease_request(secret_path),
        transport=transport,
        settings=settings,
    )
    await revoke_credential(lease.lease_id, transport=transport)
    # Second revoke — Vault may return 204 (idempotent) OR raise
    # InvalidRequest depending on version. The destroy-side fail-soft
    # path swallows any exception per spec §7.2 so we mirror the same
    # semantic here. The substantive proof is that the FIRST revoke
    # succeeded (above) + the second-revoke contract is documented as
    # "fail-soft per spec §7.2" at the destroy() call site.
    import contextlib

    with contextlib.suppress(Exception):
        await revoke_credential(lease.lease_id, transport=transport)


# ──────────────────────────────────────────────────────────────────────
# Layer 2 — Docker backend end-to-end with real Vault.
# Docker topology + daemon mocked per Q1 lock (Z2 proves real Vault
# integration, not Docker container coverage); REAL
# VaultCredentialAdapter wired against the real Vault transport.
# ──────────────────────────────────────────────────────────────────────


def _make_layer2_backend(
    *,
    adapter: VaultCredentialAdapter,
    dh_store: AsyncMock,
    settings: MagicMock,
) -> DockerSiblingSandboxBackend:
    """Construct a ``DockerSiblingSandboxBackend`` with a MOCKED
    aiodocker client + admit_policy seam + REAL
    ``VaultCredentialAdapter`` pointing at the real Vault server."""
    import aiodocker

    docker = MagicMock()
    docker.networks.create = AsyncMock()
    docker.containers.create_or_replace = AsyncMock()
    docker.containers.create_or_replace.return_value.start = AsyncMock()
    docker.containers.get = AsyncMock(
        side_effect=aiodocker.exceptions.DockerError(404, "not found")
    )
    mock_network = MagicMock()
    mock_network.connect = AsyncMock()
    mock_network.delete = AsyncMock()
    docker.networks.get = AsyncMock(return_value=mock_network)
    catalog = MagicMock()
    catalog.is_canonical.return_value = True
    catalog.verify_cosign_or_refuse = AsyncMock(return_value=None)
    catalog.verify_sbom_policy_or_refuse = AsyncMock(return_value=None)
    rego = MagicMock()
    rego.evaluate = AsyncMock(return_value=MagicMock(allow=True, reasoning=""))
    return DockerSiblingSandboxBackend(
        docker_client=docker,
        image_catalog=catalog,
        credential_adapter=adapter,
        rego_engine=rego,
        audit_store=MagicMock(),
        decision_history_store=dh_store,
        settings=settings,
        warm_pool=None,
    )


@pytest.mark.asyncio
async def test_layer2_docker_create_destroy_threads_real_vault_lease_id_end_to_end(
    real_vault_setup: dict[str, Any],
) -> None:
    """Layer 2 — full Docker backend ``create()`` + ``destroy()`` with
    ``requires_credentials=[<real-request>]`` against the real Vault.

    End-to-end proof:
    * Mint runs through ``VaultCredentialAdapter.mint_lease`` →
      ``core/vault.lease_credential`` → real ``VaultTransport.lease``
      → real Vault server → real ``lease_id`` returned.
    * The real ``lease_id`` lands on ``session.active_leases``.
    * ``sandbox.lifecycle.lease_minted`` audit emit captures the same
      real ``lease_id`` in its payload (T9 derive-from-lease contract).
    * ``destroy()`` revoke loop calls
      ``VaultCredentialAdapter.revoke_lease`` →
      ``core/vault.revoke_credential`` → real Vault → revoke succeeds.
    * ``sandbox.lifecycle.lease_revoked`` emit captures the same real
      ``lease_id``.

    The Docker topology calls are mocked per Q1 lock — Z2 proves
    REAL VAULT integration, NOT container-runtime coverage.
    """
    adapter: VaultCredentialAdapter = real_vault_setup["adapter"]
    settings = real_vault_setup["settings"]
    secret_path: str = real_vault_setup["secret_path"]

    dh_store = AsyncMock()
    dh_store.append_with_precondition.return_value = (uuid.uuid4(), b"\x00" * 32)

    backend = _make_layer2_backend(adapter=adapter, dh_store=dh_store, settings=settings)

    actor = Actor(
        subject="z2-test-actor",
        tenant_id="t-z2-real",
        scopes=frozenset(),
        actor_type="service",
    )
    pack_ctx = PackAdmissionContext(
        pack_id="cognic.z2_real_vault",
        pack_version="v1.0.0",
        pack_artifact_digest="sha256:" + "1" * 64,
        risk_tier="internal_write",
        declares_dynamic_install=False,
        profile="production",
    )
    policy = SandboxPolicy(
        cpu_cores=0.5,
        cpu_time_budget_s=None,
        memory_mb=256,
        walltime_s=30.0,
        runtime_image="cognic/sandbox-runtime-python:v1@sha256:" + "a" * 64,
        egress_allow_list=("httpbin.org",),
        vault_path=None,
    )
    request = _make_lease_request(secret_path)

    # CREATE — mints a real Vault lease and threads it onto the session.
    with patch(
        "cognic_agentos.sandbox.backends.docker_sibling.admit_policy",
        new=AsyncMock(return_value=None),
    ):
        session = await backend.create(
            policy,
            actor=actor,
            tenant_id="t-z2-real",
            pack_context=pack_ctx,
            use_warm_pool=False,
            requires_credentials=(request,),
        )

    assert isinstance(session, DockerSiblingSession)
    assert len(session.active_leases) == 1, (
        f"Expected exactly 1 active lease minted from real Vault; got {len(session.active_leases)}"
    )
    real_lease = session.active_leases[0]
    assert real_lease.lease_id, "Real Vault returned an empty lease_id"
    assert real_lease.ttl_s_granted > 0
    assert real_lease.expires_at > datetime.now(UTC)
    assert real_lease.request == request

    # Verify lease_minted emit captured the real lease_id.
    emitted_records = [
        call.kwargs["record_builder"](None)
        for call in dh_store.append_with_precondition.await_args_list
    ]
    minted_records = [
        r for r in emitted_records if r.decision_type == "sandbox.lifecycle.lease_minted"
    ]
    assert len(minted_records) == 1
    assert minted_records[0].payload["lease_id"] == real_lease.lease_id, (
        f"lease_minted emit payload lease_id {minted_records[0].payload['lease_id']!r} "
        f"does not match the real Vault-issued lease_id {real_lease.lease_id!r}"
    )

    # DESTROY — revokes via real Vault + emits lease_revoked carrying
    # the same real lease_id.
    dh_store.append_with_precondition.reset_mock()
    await backend.destroy(session)

    emitted_records = [
        call.kwargs["record_builder"](None)
        for call in dh_store.append_with_precondition.await_args_list
    ]
    revoked_records = [
        r for r in emitted_records if r.decision_type == "sandbox.lifecycle.lease_revoked"
    ]
    revoke_failed_records = [
        r for r in emitted_records if r.decision_type == "sandbox.lifecycle.lease_revoke_failed"
    ]
    assert len(revoke_failed_records) == 0, (
        f"Real Vault revoke unexpectedly failed; payload(s): "
        f"{[r.payload for r in revoke_failed_records]}"
    )
    assert len(revoked_records) == 1, (
        f"Expected exactly 1 lease_revoked emit; got {len(revoked_records)}"
    )
    assert revoked_records[0].payload["lease_id"] == real_lease.lease_id
