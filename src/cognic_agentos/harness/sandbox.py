"""Sprint 14A-A (ADR-004 + ADR-022) — managed-run composition wiring.

Off-gate composition module. SDK-free at import: the concrete backend +
``aiodocker`` are imported FUNCTION-LOCALLY inside :func:`build_sandbox_backend`
(only reached on the SDK-present path), so the kernel image (no ``adapters``
extra) imports this module without ``aiodocker``. Mirrors ``harness/mcp_host.py``.

Also home to :class:`PackRecordStoreLoader` — the ``core/run.PackRecordLoader``
conformer — because ``core/run`` cannot import ``packs/storage`` (the
``core -> packs`` arrow is forbidden). The conformer does the direct UUID-keyed
``PackRecordStore.load(pack_uuid)`` and projects to the core-owned
``LoadedPackRecord``.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, cast

from cognic_agentos.core.run.executor import LoadedPackRecord
from cognic_agentos.packs.storage import PackRecordStore

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

    from cognic_agentos.core.config import Settings
    from cognic_agentos.harness.runtime import Runtime
    from cognic_agentos.sandbox.protocol import SandboxBackend
    from cognic_agentos.subagent.spawn import SubAgentSpawner


def is_sandbox_available(settings: Settings) -> bool:
    """True iff 14A-A's DockerSibling backend can be constructed: the selected
    backend is ``docker_sibling`` AND ``aiodocker`` is importable. 14A-A is
    DockerSibling-only — ``kubernetes_pod`` returns False (deferred to 14A-B+)."""
    if settings.sandbox_backend != "docker_sibling":
        return False
    try:
        import aiodocker  # noqa: F401
    except ImportError:
        return False
    return True


class PackRecordStoreLoader:
    """``core/run.PackRecordLoader`` conformer. Does the direct UUID-keyed
    ``PackRecordStore.load(pack_uuid)`` (no tenant scan) and projects
    ``PackRecord -> LoadedPackRecord`` (the core-owned projection — ``core/run``
    cannot import ``packs``)."""

    def __init__(self, *, store: PackRecordStore) -> None:
        self._store = store

    async def load_for_run(self, *, pack_uuid: uuid.UUID) -> LoadedPackRecord | None:
        """Project ``PackRecord -> LoadedPackRecord``, reading the trusted
        manifest risk tier + ``[data_governance].data_classes`` off the pack's
        LATEST submit chain row (``payload["manifest"]`` via
        ``find_latest_submit_row``) — ``core/run`` cannot import ``packs`` so the
        manifest extraction lives here (Sprint 14A-A4b T2). ``risk_tier=None``
        when no submit manifest / non-string tier; ``data_classes=()`` when
        absent/empty, ``None`` when present-but-malformed."""
        from cognic_agentos.packs._lifecycle_helpers import find_latest_submit_row

        record = await self._store.load(pack_uuid)
        if record is None:
            return None
        history = await self._store.load_lifecycle_history(pack_uuid)
        submit_row = find_latest_submit_row(history)
        raw_manifest = submit_row.payload.get("manifest") if submit_row is not None else None
        manifest = raw_manifest if isinstance(raw_manifest, dict) else {}
        rt_block = manifest.get("risk_tier")
        rt_block = rt_block if isinstance(rt_block, dict) else {}
        raw_tier = rt_block.get("tier")
        risk_tier: str | None = raw_tier if isinstance(raw_tier, str) else None
        dg_block = manifest.get("data_governance")
        dg_block = dg_block if isinstance(dg_block, dict) else {}
        raw_dc = dg_block.get("data_classes")
        data_classes: tuple[str, ...] | None
        if raw_dc is None:
            data_classes = ()
        elif isinstance(raw_dc, (list, tuple)) and all(isinstance(x, str) for x in raw_dc):
            data_classes = tuple(raw_dc)
        else:
            data_classes = None
        return LoadedPackRecord(
            tenant_id=record.tenant_id,
            pack_id=record.pack_id,
            kind=record.kind,
            signed_artefact_digest=record.signed_artefact_digest,
            state=record.state,
            risk_tier=risk_tier,
            data_classes=data_classes,
        )


async def build_sandbox_backend(
    *,
    settings: Settings,
    runtime: Runtime,
    checkpoint_store: Any | None = None,
) -> tuple[SandboxBackend, Any]:
    """Construct the DockerSibling backend + return ``(backend, docker_client)``.

    FUNCTION-LOCAL SDK + backend imports keep this module SDK-free-import. Mints a
    ``VaultTransport`` from settings + wraps it in ``VaultCredentialAdapter`` (NOT
    ``adapters.secret`` — that is a ``SecretAdapter``, lacking the
    ``lease``/``revoke`` surface). The factory ``get_backend()`` OWNS
    ``image_catalog`` + ``egress_proxy_image`` (built from the ``sandbox_canonical_*``
    settings), so the builder passes neither. ``checkpoint_store=None`` in 14A-A;
    **wired in A3b** (14A-A2 wired the route + approval, not the checkpoint store) —
    the lifespan now resolves the store + threads it here so ``suspend()``'s final
    checkpoint persists. On ANY internal failure the just-created ``docker_client``
    is closed before the re-raise (no leak); the lifespan closes it on the success
    path's shutdown.
    """
    import aiodocker

    from cognic_agentos.core._vault_transport import VaultTransport
    from cognic_agentos.core.policy.engine import OPAEngine
    from cognic_agentos.sandbox.backend_factory import get_backend
    from cognic_agentos.sandbox.credentials import VaultCredentialAdapter

    if not settings.vault_addr:
        raise RuntimeError(
            "sandbox_runtime_build_requires_vault_addr: enabling "
            "sandbox_runtime_enabled requires settings.vault_addr"
        )

    docker_client = aiodocker.Docker()
    try:
        vault_transport = VaultTransport(
            vault_addr=settings.vault_addr,
            vault_token=settings.vault_token,
            vault_namespace=settings.vault_namespace,
            timeout_s=settings.vault_http_timeout_s,
            max_retries=settings.vault_http_max_retries,
        )
        credential_adapter = VaultCredentialAdapter(transport=vault_transport, settings=settings)
        rego_engine = await OPAEngine.create(
            bundle_path=settings.sandbox_policy_bundle,
            audit_store=runtime.audit_store,
            decision_history_store=runtime.decision_history_store,
            opa_path=settings.opa_path,
            eval_timeout_s=settings.opa_eval_timeout_s,
        )
        backend = get_backend(
            settings,
            docker_client=docker_client,
            credential_adapter=credential_adapter,
            rego_engine=rego_engine,
            audit_store=runtime.audit_store,
            decision_history_store=runtime.decision_history_store,
            checkpoint_store=checkpoint_store,
            warm_pool=None,
            # Sprint 14A-A2b — thread the runtime approval engine so the
            # backend consults the 13.5c1 sandbox approval seam on cold-create.
            approval_engine=runtime.approval_engine,
        )
    except Exception:
        await docker_client.close()
        raise
    return backend, docker_client


def build_subagent_spawner(
    *,
    runtime: Runtime,
    managed_run_executor: object,  # the ManagedRunExecutor (duck-typed run())
    engine: AsyncEngine,
    settings: Settings,
) -> SubAgentSpawner:
    """Compose the live SubAgentSpawner (child-is-a-managed-run). SDK-free —
    constructs the audit emitter (from runtime.decision_history_store) and the
    pack store + escalation (from the shared AsyncEngine). Off-gate composition
    glue (the enforcement is on-gate in managed_run_runner.py + spawn.py)."""
    from cognic_agentos.core.escalation import EscalationStore
    from cognic_agentos.subagent.audit import SubAgentAuditEmitter
    from cognic_agentos.subagent.managed_run_runner import ManagedRunChildRunner
    from cognic_agentos.subagent.spawn import SubAgentSpawner

    return SubAgentSpawner(
        audit=SubAgentAuditEmitter(history=runtime.decision_history_store),
        child_runner=ManagedRunChildRunner(
            executor=cast(Any, managed_run_executor),
            pack_store=PackRecordStore(engine),
        ),
        escalation=EscalationStore(engine=engine),
        max_recursion_depth=settings.subagent_max_recursion_depth,
    )
