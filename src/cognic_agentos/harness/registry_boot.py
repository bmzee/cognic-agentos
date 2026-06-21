"""Sprint 3 (ADR-002 + ADR-016) — startup plugin-registry boot-builder.

Off-gate composition module, mirroring ``harness/mcp_host.py`` /
``harness/sandbox.py``. It discovers installed packs, resolves each pack's
signed attestations (the Sprint-2 locator ``resolve_pack_attestations``), and
runs the full pack-signature trust pipeline
(``PluginRegistry.register_with_full_attestation_check``) — returning ONE
populated :class:`PluginRegistry`. A LATER sprint wires this into the app
lifespan and feeds the registry to both the MCP host and the A2A endpoint.

TRUST-CRITICAL WIRING (off-gate, but get these exactly right):

  * **The trapdoor.** The boot builds its OWN ``registration_trust_gate`` and
    accepts **no** ``trust_gate`` parameter — a caller must never be able to
    hand the registry the A2A trust gate (or any other gate). The trust gate is
    constructed over a ``signature_root_path`` pinned to
    ``pack_attestation_root_path`` so ``verify_pack_signature`` canonicalises the
    resolver's signature + wheel under the SAME root the resolver located them
    under.

  * **The LOCKED cosign trust root.** The cosign trust root is resolved from the
    fixed deployment convention ``<trust_root_prefix>/_default/cosign.pub`` and
    the boot fails CLOSED (:class:`RegistryBootError`) if it is missing / not a
    regular file / empty. This is DISTINCT from the benign unset-root path
    (which returns an empty registry, never raises).

  * **Fail-closed allow-list.** The ``_default`` per-tenant plugin allow-list is
    loaded from ``plugin_allowlist_path`` fail-closed; a missing / malformed file
    raises :class:`RegistryBootError` rather than silently passing ``None`` —
    which ``register_with_full_attestation_check`` treats as allow-list opt-out.

  * **Per-pack fail-soft.** Discovery + registration is per-pack fail-soft: one
    pack that fails to resolve or register is logged + skipped; it never aborts
    boot. ``BaseException`` (``CancelledError`` / ``KeyboardInterrupt``) still
    propagates.

This module is the composition seam; the substantive trust enforcement lives in
the on-gate ``protocol/trust_gate.py`` + ``protocol/supply_chain.py`` +
``protocol/plugin_registry.py`` + ``protocol/pack_attestation_resolver.py``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from cognic_agentos.protocol.pack_attestation_resolver import (
    PackAttestationResolutionError,
    resolve_pack_attestations,
)
from cognic_agentos.protocol.plugin_registry import PluginRegistry
from cognic_agentos.protocol.trust_gate import TrustGate

if TYPE_CHECKING:
    from cognic_agentos.core.audit import AuditStore
    from cognic_agentos.core.config import Settings
    from cognic_agentos.db.adapters.protocols import ObjectStoreAdapter
    from cognic_agentos.protocol.plugin_registry import MCPAdmissionDeps
    from cognic_agentos.protocol.supply_chain import SupplyChainPipeline

logger = logging.getLogger(__name__)

#: The LOCKED deployment convention: the kernel-default tenant + the cosign
#: public-key basename. The boot resolves the trust anchor at
#: ``<trust_root_prefix>/_default/cosign.pub`` and verifies it is present +
#: non-empty before ANY pack is registered. ``_default`` is also the tenant the
#: boot registers every discovered pack under.
_DEFAULT_TENANT = "_default"
_COSIGN_PUBLIC_KEY_BASENAME = "cosign.pub"


#: Closed-enum refusal vocabulary for :class:`RegistryBootError` — mirrors the
#: ``PackAttestationResolutionError`` reason-enum style. The Sprint-4 lifespan
#: catches the error to refuse startup; the ``reason`` is the wire contract.
RegistryBootRefusalReason = Literal[
    "cosign_trust_root_missing",
    "cosign_trust_root_not_a_file",
    "cosign_trust_root_empty",
    "tenant_allowlist_unreadable",
    "tenant_allowlist_malformed",
    "tenant_allowlist_default_key_missing",
]


class RegistryBootError(Exception):
    """Fail-closed boot-builder refusal raised by
    :func:`build_and_populate_registry`.

    Carries a closed-enum :attr:`reason` (the wire contract) plus an optional
    human-readable ``detail`` for operator logs. This is DISTINCT from the
    benign unset-``pack_attestation_root_path`` path, which returns an empty
    registry and never raises — a CONFIGURED attestation root with a missing
    trust anchor or a malformed allow-list is a misconfiguration the boot must
    refuse, not silently skip.
    """

    __slots__ = ("reason",)

    def __init__(self, reason: RegistryBootRefusalReason, detail: str = "") -> None:
        self.reason: RegistryBootRefusalReason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


async def build_and_populate_registry(
    *,
    settings: Settings,
    audit_store: AuditStore,
    supply_chain: SupplyChainPipeline,
    object_store: ObjectStoreAdapter,
    mcp_admission: MCPAdmissionDeps | None = None,
) -> PluginRegistry:
    """Discover installed packs, resolve their attestations, and run the full
    trust pipeline — returning ONE populated :class:`PluginRegistry`.

    NO ``trust_gate`` parameter: the boot builds its OWN
    ``registration_trust_gate`` (the trapdoor). NO ``decision_history_store``
    parameter: none of the collaborators (``PluginRegistry`` /
    ``register_with_full_attestation_check`` / ``TrustGate`` /
    ``SupplyChainPipeline``) consume one — the pipeline's evidence is the
    ``audit_store`` hash chain.

    ``mcp_admission`` is passed-in DEPENDENCY WIRING (exactly like
    ``supply_chain`` / ``object_store``): when non-``None`` it is threaded
    into ``register_with_full_attestation_check`` so a pack declaring a
    ``[tool.cognic.mcp]`` block clears the Sprint-5 MCP admission gates
    (manifest extraction / capability validation / registration auth probe)
    instead of being refused fail-closed with ``mcp_admission_deps_required``.
    The builder NEVER constructs the deps itself — assembling
    :class:`MCPAdmissionDeps` is the lifespan's job in a later sprint. The
    default ``None`` preserves the kernel-image doctrine: an MCP pack is
    refused when the deps are absent. ``mcp_admission`` is NOT a trust gate —
    it never touches the trapdoor.

    Behaviour:

      * ``settings.pack_attestation_root_path is None`` → log
        ``pack_attestation_root_unconfigured`` (WARNING) and return a fresh
        EMPTY registry (NO discovery loop, NO trust gate built); never ``None``.
      * Otherwise build the boot-owned trust gate over the attestation root,
        resolve + fail-closed-verify the LOCKED cosign trust root, load the
        fail-closed ``_default`` allow-list, then discover + register every pack
        (per-pack fail-soft).

    :raises RegistryBootError: fail-closed on a missing / non-file / empty
        ``<trust_root_prefix>/_default/cosign.pub`` OR an unreadable / malformed
        allow-list. Distinct from the benign unset-root path.
    """
    root = settings.pack_attestation_root_path
    if root is None:
        logger.warning(
            "pack_attestation_root_unconfigured: boot registration disabled; "
            "returning an empty plugin registry (the runtime never fabricates "
            "attestations)"
        )
        return PluginRegistry(audit_store=audit_store)

    root_path = Path(root)

    # The trapdoor: the boot builds its OWN trust gate. ``signature_root_path``
    # is pinned to the attestation root so ``verify_pack_signature``
    # canonicalises the resolver's signature + wheel under the SAME root the
    # resolver located them under. ``model_copy`` produces a NEW Settings — the
    # caller's instance is never mutated.
    registration_settings = settings.model_copy(update={"signature_root_path": root_path})
    registration_trust_gate = TrustGate(settings=registration_settings, audit_store=audit_store)

    # The LOCKED deployment convention. Fail-closed BEFORE the discover loop.
    cosign_trust_root = (
        Path(settings.trust_root_prefix) / _DEFAULT_TENANT / _COSIGN_PUBLIC_KEY_BASENAME
    )
    _require_cosign_trust_root(cosign_trust_root)

    # Fail-closed: a missing / malformed allow-list raises rather than silently
    # passing ``None`` (which would DISABLE allow-list enforcement downstream).
    tenant_allowlist = _load_default_tenant_allowlist(settings.plugin_allowlist_path)

    registry = PluginRegistry(audit_store=audit_store)
    for pack in registry.discover():
        distribution_name = pack.record.distribution_name
        try:
            attestations = resolve_pack_attestations(
                pack,
                pack_attestation_root=root_path,
                cosign_trust_root=cosign_trust_root,
            )
            await registry.register_with_full_attestation_check(
                pack,
                attestations,
                trust_gate=registration_trust_gate,
                supply_chain=supply_chain,
                object_store=object_store,
                tenant_id=_DEFAULT_TENANT,
                tenant_allowlist=tenant_allowlist,
                mcp_admission=mcp_admission,
            )
        except PackAttestationResolutionError as exc:
            # Per-pack fail-soft: a malformed/missing attestation tree for ONE
            # pack never aborts boot. Log the closed-enum resolution reason.
            logger.warning(
                "registry_boot.pack_attestation_unresolved: skipping pack "
                "distribution_name=%s reason=%s",
                distribution_name,
                exc.reason,
            )
            continue
        except Exception as exc:
            # Defence-in-depth per-pack fail-soft boundary: the registration
            # pipeline maps known failures to refusal OUTCOMES (no raise), but
            # an unexpected raise (e.g. PluginIdentityConflict, an unmapped
            # collaborator error) must skip the pack, not abort boot.
            # BaseException (CancelledError / KeyboardInterrupt) still propagates.
            logger.warning(
                "registry_boot.pack_registration_failed: skipping pack "
                "distribution_name=%s error_class=%s",
                distribution_name,
                type(exc).__name__,
            )
            continue

    return registry


def _require_cosign_trust_root(cosign_trust_root: Path) -> None:
    """Fail closed unless the LOCKED ``_default`` cosign public key exists, is a
    regular file, and is non-empty.

    Three distinct closed-enum reasons so the operator log pins exactly which
    misconfiguration fired (missing anchor vs a directory-where-a-file-belongs
    vs a zero-byte key).
    """
    if not cosign_trust_root.exists():
        raise RegistryBootError("cosign_trust_root_missing", str(cosign_trust_root))
    if not cosign_trust_root.is_file():
        raise RegistryBootError("cosign_trust_root_not_a_file", str(cosign_trust_root))
    if cosign_trust_root.stat().st_size == 0:
        raise RegistryBootError("cosign_trust_root_empty", str(cosign_trust_root))


def _load_default_tenant_allowlist(path: Path) -> frozenset[str]:
    """Load the ``_default`` per-tenant plugin allow-list as a ``frozenset[str]``,
    fail-closed on every malformed path.

    A present-but-empty ``_default`` list returns ``frozenset()`` (accept-no-
    packs) — intentional, and NEVER ``None``: ``None`` would disable allow-list
    enforcement entirely in ``register_with_full_attestation_check``. Raising on
    a MISSING file / invalid JSON / non-object top level / missing ``_default``
    key / non-list-of-strings ``_default`` is the fail-closed contract.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RegistryBootError("tenant_allowlist_unreadable", str(path)) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RegistryBootError("tenant_allowlist_malformed", f"{path}: invalid JSON") from exc
    if not isinstance(data, dict):
        raise RegistryBootError(
            "tenant_allowlist_malformed", f"{path}: top-level JSON is not an object"
        )
    if _DEFAULT_TENANT not in data:
        raise RegistryBootError("tenant_allowlist_default_key_missing", str(path))
    default_entry = data[_DEFAULT_TENANT]
    if not isinstance(default_entry, list) or not all(
        isinstance(name, str) for name in default_entry
    ):
        raise RegistryBootError(
            "tenant_allowlist_malformed",
            f"{path}: '{_DEFAULT_TENANT}' must be a list of strings",
        )
    return frozenset(default_entry)


__all__ = [
    "RegistryBootError",
    "RegistryBootRefusalReason",
    "build_and_populate_registry",
]
