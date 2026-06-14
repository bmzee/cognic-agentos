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
from typing import TYPE_CHECKING, Any

from cognic_agentos.core.run.executor import LoadedPackRecord
from cognic_agentos.packs.storage import PackRecordStore

if TYPE_CHECKING:
    from cognic_agentos.core.config import Settings
    from cognic_agentos.harness.runtime import Runtime
    from cognic_agentos.sandbox.protocol import SandboxBackend


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
        record = await self._store.load(pack_uuid)
        if record is None:
            return None
        return LoadedPackRecord(
            tenant_id=record.tenant_id,
            pack_id=record.pack_id,
            kind=record.kind,
            signed_artefact_digest=record.signed_artefact_digest,
            state=record.state,
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
    settings), so the builder passes neither. ``checkpoint_store=None`` in 14A-A
    (14A-A2 wires it). On ANY internal failure the just-created ``docker_client``
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
        )
    except Exception:
        await docker_client.close()
        raise
    return backend, docker_client
