"""Hook-registry production construction (M5, ADR-008 + ADR-017).

Walks the ALREADY-TRUSTED registry candidates (trust is upstream — the
plugin registry's cosign gate ran before any candidate is iterable here),
admits each verified hook pack's ``[hooks]`` declarations into a
``HookRegistry`` (digest-pinned via ``register_pack``), and assembles the
``DLPGuard`` the MCP host consumes. SDK-free; the hook kernel imports
cleanly. Per-pack fail-closed: a malformed hook pack is skipped + logged
(mirrors the MCP mapper's warn-skip doctrine in ``harness/mcp_host.py``);
the guard still builds — the skipped pack's hook ids then fail CLOSED at
scan time (``dlp_hook_id_unresolved``), never silently pass.

Deferred-load invariant (ADR-002 §gate 1 discipline): the walk resolves each
declaration to an ``importlib.metadata.EntryPoint`` and threads ``ep.load``
as the ``callable_loader`` WITHOUT invoking it — pack code is imported only
when the dispatcher first runs the hook.
"""

from __future__ import annotations

import importlib.metadata as md
import logging
from typing import TYPE_CHECKING, Any, Protocol

from cognic_agentos.packs.hooks.dispatcher import HookDispatcher
from cognic_agentos.packs.hooks.dlp_integration import DLPGuard
from cognic_agentos.packs.hooks.registry import (
    HookDeclaration,
    HookRegistry,
    HookRegistryRefusal,
    VerifiedHookPack,
)
from cognic_agentos.protocol.mcp_manifest import (
    PackManifestMalformedError,
    PackManifestNotFoundError,
    extract_pack_manifest,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from cognic_agentos.core.config import Settings
    from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate

logger = logging.getLogger(__name__)

#: Payload budget fed to ``HookDispatcher.max_payload_bytes``. There is NO
#: Settings field for this today (only ``Settings.hook_max_timeout_s``
#: exists); a module constant is the YAGNI choice for M5. Promote to a
#: Setting if an operator ever needs to tune it (follow-up).
_HOOK_MAX_PAYLOAD_BYTES = 1_000_000


class _RegistryCandidates(Protocol):
    """Structural seam — anything exposing the registered-candidate iterator
    (the real ``PluginRegistry`` or a test stub)."""

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]: ...


def _hooks_block(
    manifest: dict[str, Any], *, distribution_name: str
) -> list[dict[str, Any]] | None:
    """``[hooks].declarations`` (canonical) with the legacy
    ``[tool.cognic.hooks]`` fallback (dual-path doctrine); ``None`` when
    absent (non-hook pack).

    Present-but-malformed hook blocks warn and return ``[]`` so the caller
    skips the whole pack fail-closed instead of silently admitting a subset
    of declarations.
    """
    for block_path, path in (
        ("hooks", ("hooks",)),
        ("tool.cognic.hooks", ("tool", "cognic", "hooks")),
    ):
        cur: Any = manifest
        exists = True
        for seg in path:
            if not isinstance(cur, dict):
                logger.warning(
                    "hook.block_malformed",
                    extra={
                        "distribution_name": distribution_name,
                        "block_path": block_path,
                        "reason": "non_table_path",
                    },
                )
                return []
            if seg not in cur:
                exists = False
                break
            cur = cur[seg]
        if not exists:
            continue
        if not isinstance(cur, dict):
            logger.warning(
                "hook.block_malformed",
                extra={
                    "distribution_name": distribution_name,
                    "block_path": block_path,
                    "reason": "block_not_table",
                },
            )
            return []
        raw_declarations = cur.get("declarations")
        if not isinstance(raw_declarations, list) or not raw_declarations:
            logger.warning(
                "hook.block_malformed",
                extra={
                    "distribution_name": distribution_name,
                    "block_path": block_path,
                    "reason": "declarations_not_nonempty_list",
                },
            )
            return []
        if not all(isinstance(d, dict) for d in raw_declarations):
            logger.warning(
                "hook.block_malformed",
                extra={
                    "distribution_name": distribution_name,
                    "block_path": block_path,
                    "reason": "declaration_not_table",
                },
            )
            return []
        return raw_declarations
    return None


def _entry_points_and_version(
    distribution_name: str,
) -> tuple[dict[str, md.EntryPoint], str | None]:
    """The distribution's ``cognic.hooks`` entry-points keyed by name, plus
    its version; ``({}, None)`` when the distribution is not visible."""
    try:
        dist = md.distribution(distribution_name)
    except md.PackageNotFoundError:
        return {}, None
    return (
        {ep.name: ep for ep in dist.entry_points if ep.group == "cognic.hooks"},
        dist.version,
    )


def _verified_pack(
    cand: RegisteredPackCandidate, decls_raw: list[dict[str, Any]]
) -> VerifiedHookPack | None:
    """Build the VerifiedHookPack for one candidate; ``None`` (logged) on any
    per-pack malformation — a declared hook MUST have an entry-point and a
    well-formed declaration, else the WHOLE pack is skipped (fail closed)."""
    eps, dist_version = _entry_points_and_version(cand.distribution_name)
    if dist_version is None:
        logger.warning(
            "hook.distribution_not_found",
            extra={"distribution_name": cand.distribution_name},
        )
        return None
    decls: list[HookDeclaration] = []
    for d in decls_raw:
        raw_hook_id = d.get("hook_id")
        hook_id = raw_hook_id if isinstance(raw_hook_id, str) else None
        ep = eps.get(hook_id) if hook_id is not None else None
        if hook_id is None or ep is None:
            logger.warning(
                "hook.declaration_no_entry_point",
                extra={"distribution_name": cand.distribution_name, "hook_id": raw_hook_id},
            )
            return None  # per-pack fail-closed: a declared hook must have an entry-point
        try:
            decls.append(
                HookDeclaration(
                    hook_id=hook_id,
                    phase=d["phase"],
                    ordering_class=d["ordering_class"],
                    timeout_seconds=float(d["timeout_seconds"]),
                    fail_policy=d["fail_policy"],
                    fail_open_exception=d.get("fail_open_exception"),
                    callable_loader=ep.load,  # deferred load; NOT invoked here
                )
            )
        except (KeyError, ValueError, TypeError) as exc:
            logger.warning(
                "hook.declaration_malformed",
                extra={"distribution_name": cand.distribution_name, "error": str(exc)},
            )
            return None
    try:
        return VerifiedHookPack(
            distribution_name=cand.distribution_name,
            distribution_version=dist_version,
            signature_digest=cand.signature_digest or "",
            declarations=tuple(decls),
        )
    except ValueError as exc:  # duplicate (phase, hook_id) etc.
        logger.warning(
            "hook.pack_malformed",
            extra={"distribution_name": cand.distribution_name, "error": str(exc)},
        )
        return None


def build_dlp_guard(*, registry: _RegistryCandidates, settings: Settings) -> DLPGuard:
    """Assemble the production DLPGuard over the trusted candidates.

    Raises only on hard construction failure (dispatcher/guard ctor);
    malformed hook packs are skipped per-pack (logged) so one bad pack
    cannot take the whole MCP host down — its declared hook ids then fail
    closed at scan time via ``dlp_hook_id_unresolved``.
    """
    hook_registry = HookRegistry(max_timeout_seconds=float(settings.hook_max_timeout_s))
    for cand in registry.iter_registered_pack_candidates():
        try:
            manifest = extract_pack_manifest(
                distribution_name=cand.distribution_name, package_name=cand.package_name
            )
        except PackManifestNotFoundError:
            continue  # no manifest → no hook intent → silent skip (mapper doctrine)
        except PackManifestMalformedError:
            logger.warning(
                "hook.pack_manifest_malformed",
                extra={"distribution_name": cand.distribution_name},
            )
            continue
        decls_raw = _hooks_block(manifest, distribution_name=cand.distribution_name)
        if not decls_raw:
            continue  # non-hook pack
        pack = _verified_pack(cand, decls_raw)
        if pack is None:
            continue
        try:
            hook_registry.register_pack(pack)
        except HookRegistryRefusal as exc:
            logger.warning(
                "hook.registry_refused",
                extra={"distribution_name": cand.distribution_name, "reason": exc.reason},
            )
    dispatcher = HookDispatcher(
        registry=hook_registry,
        max_payload_bytes=_HOOK_MAX_PAYLOAD_BYTES,
        max_timeout_seconds_runtime=float(settings.hook_max_timeout_s),
    )
    return DLPGuard(dispatcher=dispatcher)
