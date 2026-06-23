"""Proof 1a — the real-app in-process pack-governance loop (Task 7).

Green IFF the real authoring trust pipeline produces artifacts the real runtime
trust pipeline accepts: real signed pack -> provisioned attestations -> startup
trust-registration (require_cosign=True) -> MCP host resolves it -> production
route tool call succeeds -> decision-history chain verifies.

Every helper below is a thin REAL wrapper over the composition root — no mocks /
stubs / fakes in the loop. The in-memory adapters (sqlite ``InMemoryRelational
Adapter`` + in-memory secret/vector/embedding/observability + ``local_fs`` object
store) are the approved real-but-lightweight backends per spec §6; the decision-
history hash chain still genuinely persists + verifies on sqlite. The pack signing
+ attestations are REAL (Task 6 helpers).

Env-gated COGNIC_RUN_PACK_LOOP_PROOF=1; fail-loud (not skip) when set but the
toolchain is missing (mirrors tests/integration/models/test_real_cosign_proof.py).

SEQUENTIAL PORTS: the ``pack_server`` (127.0.0.1:8765) + ``local_as``
(127.0.0.1:9000) fixtures bind FIXED ports — run this module on its own (never
``-n``/parallel).
"""

import io
import os
import shutil
import subprocess
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from cognic_agentos.compliance.iso42001.evidence_pack import export_evidence_pack
from cognic_agentos.core.chain_verifier import ChainVerifier
from cognic_agentos.core.config import Settings, build_settings_without_env_file
from cognic_agentos.core.decision_history import _decision_history
from cognic_agentos.db.adapters import AdapterRegistry
from cognic_agentos.db.adapters.factory import Adapters, build_adapters_async
from cognic_agentos.db.adapters.local_object_store_adapter import LocalObjectStoreAdapter
from cognic_agentos.harness import build_runtime
from cognic_agentos.harness.mcp_host import build_mcp_host
from cognic_agentos.harness.registry_boot import build_and_populate_registry
from cognic_agentos.harness.runtime import Runtime
from cognic_agentos.portal.api.app import create_app
from cognic_agentos.portal.rbac.actor import Actor
from cognic_agentos.protocol.mcp_authz import MCPAuthzClient
from cognic_agentos.protocol.plugin_registry import MCPAdmissionDeps, PluginRegistry
from cognic_agentos.protocol.supply_chain import SupplyChainPipeline
from tests.integration.pack_loop._authoring import (
    build_sign_verify,
    provision_attestation_tree,
    write_cosign_pub,
)
from tests.support.adapter_fixtures import (
    InMemoryEmbeddingAdapter,
    InMemoryObservabilityAdapter,
    InMemoryRelationalAdapter,
    InMemorySecretAdapter,
    InMemoryVectorAdapter,
)

_PROOF = os.environ.get("COGNIC_RUN_PACK_LOOP_PROOF") == "1"
pytestmark = pytest.mark.skipif(
    not _PROOF, reason="set COGNIC_RUN_PACK_LOOP_PROOF=1 to run the proof"
)

#: Runtime route tenant (the bound Actor). DISTINCT from the registration tenant.
_TENANT = "proof_tenant"
#: Registration runs under the boot's LOCKED ``_default`` tenant
#: (registry_boot._DEFAULT_TENANT) — so the admission OAuth probe queries secrets
#: scoped to ``_default`` while the runtime route queries ``proof_tenant``. Both
#: tenants are seeded below.
_DEFAULT_TENANT = "_default"
#: AS issuer netloc with ':' -> '_' (the mcp_oauth_credentials_path {as_host} seg).
_AS_HOST_KEY = "127.0.0.1_9000"
#: PRM advertises the issuer in pydantic-normalized form WITH a trailing slash
#: (Task 4 finding); the runtime AS allow-list check is exact-string membership.
_AS_ADVERTISED = "http://127.0.0.1:9000/"
#: The registry derives server_id == distribution_name (harness/mcp_host.py).
_SERVER_ID = "cognic-tool-search"


def _require_toolchain() -> None:
    missing = [b for b in ("cosign", "syft", "grype") if shutil.which(b) is None]
    if missing:
        raise AssertionError(
            f"COGNIC_RUN_PACK_LOOP_PROOF=1 but the signing toolchain is missing: {missing}."
        )


class _ProofActorBinder:
    """Test-fixture ActorBinder: binds every request to the fixed proof Actor.

    Structurally conforms to the ``ActorBinder`` Protocol (portal/rbac/actor.py).
    The auth backend is out of scope for the loop proof — the actor carries the
    ``mcp.tool.*`` scopes the route's ``RequireScope`` gate enforces (plus
    ``compliance.evidence_pack.read`` for the Task-8 evidence read)."""

    def bind(self, *, request: Request) -> Actor:
        return Actor(
            subject="proof",
            tenant_id=_TENANT,
            scopes=frozenset({"mcp.tool.invoke", "mcp.tool.list", "compliance.evidence_pack.read"}),
            actor_type="service",
        )


def _build_proof_settings(
    *,
    trust_root_prefix: Path,
    pack_attestation_root_path: Path,
    plugin_allowlist_path: Path,
    evidence_signing_key: Path,
) -> Settings:
    """LOCK 1: require_cosign=True. dev profile so the localhost AS/PRM URLs pass
    mcp_authz's strict-profile discovery-URL guard. ``model_copy`` does NOT re-run
    validators (mirrors tests/support/adapter_fixtures.memory_settings)."""
    return build_settings_without_env_file().model_copy(
        update={
            "runtime_profile": "dev",
            "require_cosign": True,
            "db_driver": "memory",
            "vector_driver": "memory",
            "secret_driver": "memory",
            "embed_driver": "memory",
            "obs_driver": "memory",
            "cache_driver": "none",
            "object_store_driver": "local_fs",
            # tmp_path (trust_root_prefix.parent) always exists — same posture as
            # memory_settings(local_object_store_root=tmp_path).
            "local_object_store_root": trust_root_prefix.parent,
            "trust_root_prefix": trust_root_prefix,
            "pack_attestation_root_path": str(pack_attestation_root_path),
            "plugin_allowlist_path": plugin_allowlist_path,
            "evidence_pack_signing_key_path": str(evidence_signing_key),
        }
    )


def _secret_seed() -> dict[str, dict[str, Any]]:
    """Seed the AS allow-list + OAuth client creds for BOTH the registration probe
    (``_default`` tenant) AND the runtime route (``proof_tenant``). Keys match
    settings.mcp_as_allowlist_path / mcp_oauth_credentials_path."""
    creds = {
        "client_id": "cognic-mcp-proof",
        "client_secret": "proof-secret",
        "auth_method": "client_secret_post",
    }
    seed: dict[str, dict[str, Any]] = {}
    for tenant in (_TENANT, _DEFAULT_TENANT):
        seed[f"secret/cognic/{tenant}/mcp-as-allowlist"] = {"servers": [_AS_ADVERTISED]}
        seed[f"secret/cognic/{tenant}/mcp-oauth/{_AS_HOST_KEY}"] = dict(creds)
    return seed


async def _open_minimal_adapters(
    settings: Settings, *, secret_seed: dict[str, dict[str, Any]]
) -> Adapters:
    """Build + open the curated real-but-lightweight adapter pool, then seed the
    in-memory secret adapter with the OAuth allow-list + client creds. NO cache
    (cache_driver="none") — a read_only MCP invoke touches no Redis/scheduler."""
    registry = AdapterRegistry()
    registry.register("relational", "memory", InMemoryRelationalAdapter)
    registry.register("vector", "memory", InMemoryVectorAdapter)
    registry.register("secret", "memory", InMemorySecretAdapter)
    registry.register("embedding", "memory", InMemoryEmbeddingAdapter)
    registry.register("observability", "memory", InMemoryObservabilityAdapter)
    registry.register("object_store", "local_fs", LocalObjectStoreAdapter)
    adapters = await build_adapters_async(settings, registry=registry)
    await adapters.open_all()
    for path, value in secret_seed.items():
        await adapters.secret.write(path, value)
    return adapters


async def _build_runtime(settings: Settings, adapters: Adapters) -> Runtime:
    return await build_runtime(settings, adapters)


async def _populate_registry(
    settings: Settings, runtime: Runtime, adapters: Adapters
) -> PluginRegistry:
    """Run the REAL boot-builder: discover() -> resolve_pack_attestations ->
    register_with_full_attestation_check. Mirrors the app.py lifespan exactly —
    a real SupplyChainPipeline + MCPAdmissionDeps (so the [tool.cognic.mcp] block
    clears the Sprint-5 admission gates incl. the OAuth registration probe)."""
    assert adapters.object_store is not None
    async with httpx.AsyncClient() as probe_http:
        deps = MCPAdmissionDeps(
            settings=settings,
            vault_client=adapters.secret,
            opa_engine=None,
            make_authz_client_for_probe=lambda: MCPAuthzClient(
                settings=settings,
                vault_client=adapters.secret,
                http_client=probe_http,
                audit_store=runtime.audit_store,
                decision_history_store=runtime.decision_history_store,
            ),
        )
        return await build_and_populate_registry(
            settings=settings,
            audit_store=runtime.audit_store,
            supply_chain=SupplyChainPipeline(settings=settings),
            object_store=adapters.object_store,
            mcp_admission=deps,
        )


def _build_app(
    settings: Settings,
    runtime: Runtime,
    registry: PluginRegistry,
    adapters: Adapters,
    mcp_http_client: httpx.AsyncClient,
) -> FastAPI:
    """Real composition root: build the production MCP host over the populated
    registry, then create_app with the proof actor binder. The httpx ASGITransport
    does NOT run the lifespan, so the pre-built registry + host are injected onto
    app.state directly (the lifespan's own job on the adapter path)."""
    host = build_mcp_host(
        registry=registry,
        runtime=runtime,
        settings=settings,
        http_client=mcp_http_client,
        vault_client=adapters.secret,
    )
    app = create_app(settings, actor_binder=_ProofActorBinder())
    app.state.plugin_registry = registry
    app.state.mcp_host = host
    return app


def _actor_headers() -> dict[str, str]:
    # The proof actor binder ignores request headers; the bound Actor is the auth
    # axis. An empty header set is sufficient for the in-process route drive.
    return {}


def _server_id() -> str:
    return _SERVER_ID


async def _assert_invocation_audited_and_chain_valid(
    engine: AsyncEngine, *, tenant_id: str
) -> None:
    """ASSERTION 5: a decision-history mcp_call row records the invocation AND the
    whole decision-history hash chain verifies clean (genuinely on sqlite)."""
    async with engine.connect() as conn:
        rows = (
            (
                await conn.execute(
                    select(_decision_history.c.payload)
                    .where(_decision_history.c.event_type == "mcp_call")
                    .where(_decision_history.c.tenant_id == tenant_id)
                )
            )
            .mappings()
            .all()
        )
    assert rows, "no decision-history mcp_call row was emitted for the invocation"
    invoked = [
        r["payload"]
        for r in rows
        if r["payload"].get("decision") == "invoked"
        and r["payload"].get("tool_name") == "search_policy_docs"
    ]
    assert invoked, (
        f"no invoked mcp_call row for search_policy_docs: {[r['payload'] for r in rows]}"
    )
    report = await ChainVerifier(engine, "decision_history").walk()
    assert report.is_clean, f"decision-history chain failed verification: {report}"


def _generate_evidence_signing_key(dest: Path) -> None:
    """Generate a REAL cosign keypair (empty passphrase — mirrors
    ``_authoring.build_sign_verify``) and place the PRIVATE key at ``dest`` (the
    ``settings.evidence_pack_signing_key_path`` the default ``cosign_sign_blob``
    signer consumes via ``--key``). ``cosign generate-key-pair`` writes
    ``cosign.key`` / ``cosign.pub`` into its CWD; copy the private key to the
    settings path. The caller must also expose ``COSIGN_PASSWORD=""`` in the
    process env (``cosign sign-blob`` inherits ``os.environ`` and otherwise
    prompts for the passphrase + fails)."""
    keydir = dest.parent / "evidence-keys"
    keydir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        ["cosign", "generate-key-pair"],
        cwd=keydir,
        env={**os.environ, "COSIGN_PASSWORD": ""},
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"cosign generate-key-pair (evidence-signing key) failed "
            f"({result.returncode}):\n{result.stdout}\n{result.stderr}"
        )
    shutil.copy2(keydir / "cosign.key", dest)


@pytest.mark.asyncio
async def test_proof_1a_full_loop(
    pack_server: str, local_as: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The session-scoped `pack_server` (127.0.0.1:8765) + `local_as`
    # (127.0.0.1:9000) fixtures (conftest.py) start both servers once with managed
    # teardown — no per-test thread launch (no port/lifecycle flake).
    _require_toolchain()

    pack = Path(__file__).resolve().parents[3] / "examples" / "cognic-tool-search"
    trust_root = tmp_path / "trust-roots"
    att_root = tmp_path / "attestations"

    # ---- authoring + provisioning (Task 6 helpers — REAL agentos sign/verify) ----
    artifacts = build_sign_verify(pack, key_dir=tmp_path / "keys")
    write_cosign_pub(trust_root, artifacts.cosign_pub)
    provision_attestation_tree(att_root, artifacts)

    # ---- allow-list file listing THIS pack's distribution name ----
    allowlist = tmp_path / "plugin_allowlist.json"
    allowlist.write_text('{"_default": ["cognic-tool-search"]}', encoding="utf-8")

    # ---- Settings: require_cosign=True (LOCK 1), dev profile, tmp trust/att roots ----
    settings = _build_proof_settings(
        trust_root_prefix=trust_root,
        pack_attestation_root_path=att_root,
        plugin_allowlist_path=allowlist,
        evidence_signing_key=tmp_path / "evidence-signing.pem",
    )
    assert settings.runtime_profile == "dev"
    assert settings.require_cosign is True

    # ---- minimal adapter pool + the REAL composition root ----
    adapters = await _open_minimal_adapters(settings, secret_seed=_secret_seed())
    try:
        runtime = await _build_runtime(settings, adapters)
        try:
            registry = await _populate_registry(settings, runtime, adapters)

            # ASSERTION 2 (core seam): the pack registered WITHOUT a fail-soft skip.
            registered = list(registry.iter_registered_pack_candidates())
            registered_names = [getattr(r, "distribution_name", r) for r in registered]
            outcomes = [(o.pack_id, o.status, o.refusal_reason) for o in registry.known_packs()]
            assert any(
                getattr(r, "package_name", None) == "cognic_tool_search" for r in registered
            ), (
                "cognic-tool-search not registered (a fail-soft skip/refusal = the real "
                "runtime attestation pipeline REJECTED real `agentos sign` output — the "
                f"headline seam finding). registered={registered_names} all_outcomes={outcomes}"
            )

            # ---- build the app with the MCP host + the actor binder, drive the route ----
            async with httpx.AsyncClient() as mcp_http:
                app = _build_app(settings, runtime, registry, adapters, mcp_http)
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app), base_url="http://test"
                ) as client:
                    # ASSERTION 3: list_tools shows search_policy_docs.
                    lst = await client.get(
                        f"/api/v1/mcp/servers/{_server_id()}/tools", headers=_actor_headers()
                    )
                    assert lst.status_code == 200, lst.text
                    assert any(t["name"] == "search_policy_docs" for t in lst.json()["tools"])

                    # ASSERTION 4: call_tool returns the deterministic result.
                    call = await client.post(
                        f"/api/v1/mcp/servers/{_server_id()}/tools/call",
                        headers=_actor_headers(),
                        json={
                            "tool_name": "search_policy_docs",
                            "arguments": {"query": "retention"},
                        },
                    )
                    assert call.status_code == 200, call.text
                    assert "retention" in str(call.json()).lower()

            # ASSERTION 5: a decision-history row exists + the chain verifies.
            await _assert_invocation_audited_and_chain_valid(
                adapters.relational.engine, tenant_id=_TENANT
            )

            # ASSERTION 6 (PASS criterion 6): an evidence pack exports + its signed
            # `.tar.gz` is the wire-public 5-member tamper-evident shape. The signer
            # is the DEFAULT real `cosign sign-blob` (NO `signer=` override) — a
            # genuine cosign signature over the manifest. There is no
            # `verify_evidence_pack()`; re-verification IS tarball inspection (the
            # hash-chained `decision_history.jsonl` was already verified clean at
            # assertion 5). The window (now +/- 1h, tz-aware UTC) brackets the
            # invocation just audited (`created_at == datetime.now(UTC)`).
            signing_key_path = settings.evidence_pack_signing_key_path
            assert signing_key_path is not None  # _build_proof_settings always sets it
            _generate_evidence_signing_key(Path(signing_key_path))
            # `cosign sign-blob` (signing.py) inherits `os.environ`; the empty-
            # passphrase cosign key needs `COSIGN_PASSWORD` set (else cosign prompts
            # for the passphrase + fails). monkeypatch auto-restores at teardown.
            monkeypatch.setenv("COSIGN_PASSWORD", "")
            now = datetime.now(UTC)
            tar_bytes = await export_evidence_pack(
                engine=adapters.relational.engine,
                secret_adapter=adapters.secret,
                tenant_id=_TENANT,
                period_start=now - timedelta(hours=1),
                period_end=now + timedelta(hours=1),
                signing_key_path=signing_key_path,
            )
            assert tar_bytes, "evidence pack export returned no bytes"
            with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tar:
                members = set(tar.getnames())
            assert members == {
                "manifest.json",
                "manifest.json.sig",
                "manifest.json.bundle.sigstore",
                "audit_event.jsonl",
                "decision_history.jsonl",
            }, f"unexpected evidence-pack members: {members}"
        finally:
            await runtime.aclose()
    finally:
        await adapters.close_all()
