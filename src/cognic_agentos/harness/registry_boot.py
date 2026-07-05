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

  * **Per-pack HOOK + SKILL + AGENT trust roots (M5 hooks, ADR-002 hooks
    amendment; M6 skills, ADR-025; M8 A9 agents, ADR-027).** A HOOK pack may
    ship its own trust root at the LOCKED staged layout
    ``<trust_root_prefix>/hook-packs/<pack_id>/cosign.pub``, a SKILL pack at
    ``<trust_root_prefix>/skill-packs/<pack_id>/cosign.pub``, and an AGENT
    pack at ``<trust_root_prefix>/agent-packs/<pack_id>/cosign.pub``;
    absent → the ``_default`` root. PRESENT-but-invalid fails CLOSED for that
    pack (skip + warn — never a silent downgrade to the default root, never a
    boot abort). TOOLS are the ONLY kind that never consults a per-pack path,
    and no per-pack kind ever consults another kind's subdir.

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

import dataclasses
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Final, Literal

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
    from cognic_agentos.protocol.plugin_registry import MCPAdmissionDeps, PluginKind
    from cognic_agentos.protocol.supply_chain import SupplyChainPipeline

logger = logging.getLogger(__name__)

#: The LOCKED deployment convention: the kernel-default tenant + the cosign
#: public-key basename. The boot resolves the trust anchor at
#: ``<trust_root_prefix>/_default/cosign.pub`` and verifies it is present +
#: non-empty before ANY pack is registered. ``_default`` is also the tenant the
#: boot registers every discovered pack under.
_DEFAULT_TENANT = "_default"
_COSIGN_PUBLIC_KEY_BASENAME = "cosign.pub"

#: M5 (ADR-002 hooks amendment) — the LOCKED staged layout for per-pack hook
#: trust roots: ``<trust_root_prefix>/hook-packs/<pack_id>/cosign.pub`` where
#: ``pack_id`` is the signed distribution name. A HOOK pack whose per-pack key
#: is ABSENT falls back to the ``_default`` root; PRESENT-but-invalid FAILS
#: CLOSED for that pack (never a silent downgrade to the default root — a
#: corrupted per-pack key must not demote a hook pack to default-key
#: verification). Tools / skills / agents NEVER consult this path (skills +
#: agents have their OWN staged layouts below).
_HOOK_PACK_TRUST_ROOT_SUBDIR = "hook-packs"

#: M6 A8 (ADR-025) — the LOCKED staged layout for per-pack SKILL trust roots:
#: ``<trust_root_prefix>/skill-packs/<pack_id>/cosign.pub``. EXACTLY the hook
#: semantics: ABSENT → the ``_default`` root; PRESENT-but-invalid FAILS CLOSED
#: for that pack. Tools / agents / hooks NEVER consult this path.
_SKILL_PACK_TRUST_ROOT_SUBDIR = "skill-packs"

#: M8 A9 (ADR-027) — the LOCKED staged layout for per-pack AGENT trust roots:
#: ``<trust_root_prefix>/agent-packs/<pack_id>/cosign.pub``. EXACTLY the hook
#: + skill semantics: ABSENT → the ``_default`` root; PRESENT-but-invalid
#: FAILS CLOSED for that pack. Tools / hooks / skills NEVER consult this path;
#: with this entry TOOLS remain the ONLY default-root-unconditional kind.
_AGENT_PACK_TRUST_ROOT_SUBDIR = "agent-packs"


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


#: Closed-enum vocabulary for the PER-PACK hook trust-root refusal log
#: (``registry_boot.hook_pack_trust_root_invalid``). Distinct from
#: :data:`RegistryBootRefusalReason` — these are per-pack SKIPS (fail-soft for
#: the boot, fail-closed for the pack), never a whole-boot abort. The value
#: strings are OPERATOR-FACING log vocabulary locked at M5 — unchanged by the
#: M6 skills generalisation.
HookPackTrustRootRefusalReason = Literal[
    "hook_pack_trust_root_name_invalid",
    "hook_pack_trust_root_path_escape",
    "hook_pack_trust_root_not_a_file",
    "hook_pack_trust_root_empty",
]

#: M6 A8 (ADR-025) — the kind-appropriate mirror vocabulary for the per-pack
#: SKILL trust-root refusal log (``registry_boot.skill_pack_trust_root_invalid``).
#: Same four failure classes as the hook vocabulary above.
SkillPackTrustRootRefusalReason = Literal[
    "skill_pack_trust_root_name_invalid",
    "skill_pack_trust_root_path_escape",
    "skill_pack_trust_root_not_a_file",
    "skill_pack_trust_root_empty",
]

#: M8 A9 (ADR-027) — the kind-appropriate mirror vocabulary for the per-pack
#: AGENT trust-root refusal log (``registry_boot.agent_pack_trust_root_invalid``).
#: Same four failure classes as the hook + skill vocabularies above.
AgentPackTrustRootRefusalReason = Literal[
    "agent_pack_trust_root_name_invalid",
    "agent_pack_trust_root_path_escape",
    "agent_pack_trust_root_not_a_file",
    "agent_pack_trust_root_empty",
]

#: Union across the per-pack-trust-root kinds. The reason string carried by
#: :class:`_PerPackTrustRootInvalid` is always drawn from the raising kind's
#: vocabulary (hook packs raise ``hook_pack_*``; skill packs ``skill_pack_*``;
#: agent packs ``agent_pack_*``).
PerPackTrustRootRefusalReason = (
    HookPackTrustRootRefusalReason
    | SkillPackTrustRootRefusalReason
    | AgentPackTrustRootRefusalReason
)


class _PerPackTrustRootInvalid(Exception):
    """Per-pack fail-closed refusal from :func:`_resolve_pack_trust_root`.

    Module-private: caught by the boot loop (warn + skip THAT pack), never
    escapes :func:`build_and_populate_registry`. NOT :class:`RegistryBootError`
    — that class aborts the whole boot; a single hook/skill pack with a bad
    staged key must not take the deployment down (the per-pack fail-soft
    posture). M6 A8 generalised the M5 ``_HookPackTrustRootInvalid`` (no
    external consumers pinned the old name) — ``log_event`` carries the
    kind-appropriate operator log-event name so the boot loop's warn line
    stays byte-stable for hooks (``hook_pack_trust_root_invalid``) while
    skills log their own (``skill_pack_trust_root_invalid``).
    """

    __slots__ = ("log_event", "reason")

    def __init__(
        self, reason: PerPackTrustRootRefusalReason, detail: str = "", *, log_event: str
    ) -> None:
        self.reason: PerPackTrustRootRefusalReason = reason
        self.log_event = log_event
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclasses.dataclass(frozen=True, slots=True)
class _PerPackTrustRootPolicy:
    """Per-kind staged-layout policy: the subdir under the trust-root prefix,
    the operator log-event name the boot loop emits on a fail-closed skip, and
    the kind-appropriate closed-enum refusal vocabulary (one value per failure
    class). Both per-pack kinds share ONE resolve-then-validate code path in
    :func:`_resolve_pack_trust_root`; only this policy differs."""

    subdir: str
    log_event: str
    name_invalid: PerPackTrustRootRefusalReason
    path_escape: PerPackTrustRootRefusalReason
    not_a_file: PerPackTrustRootRefusalReason
    empty: PerPackTrustRootRefusalReason


#: The per-pack trust-root kinds (M5 hooks + M6 skills + M8 A9 agents). The
#: ONLY kind NOT in this map (tools) resolves the ``_default`` root
#: unconditionally — behavior unchanged since Sprint 3.
_PER_PACK_TRUST_ROOT_POLICIES: Final[dict[str, _PerPackTrustRootPolicy]] = {
    "hooks": _PerPackTrustRootPolicy(
        subdir=_HOOK_PACK_TRUST_ROOT_SUBDIR,
        log_event="hook_pack_trust_root_invalid",
        name_invalid="hook_pack_trust_root_name_invalid",
        path_escape="hook_pack_trust_root_path_escape",
        not_a_file="hook_pack_trust_root_not_a_file",
        empty="hook_pack_trust_root_empty",
    ),
    "skills": _PerPackTrustRootPolicy(
        subdir=_SKILL_PACK_TRUST_ROOT_SUBDIR,
        log_event="skill_pack_trust_root_invalid",
        name_invalid="skill_pack_trust_root_name_invalid",
        path_escape="skill_pack_trust_root_path_escape",
        not_a_file="skill_pack_trust_root_not_a_file",
        empty="skill_pack_trust_root_empty",
    ),
    "agents": _PerPackTrustRootPolicy(
        subdir=_AGENT_PACK_TRUST_ROOT_SUBDIR,
        log_event="agent_pack_trust_root_invalid",
        name_invalid="agent_pack_trust_root_name_invalid",
        path_escape="agent_pack_trust_root_path_escape",
        not_a_file="agent_pack_trust_root_not_a_file",
        empty="agent_pack_trust_root_empty",
    ),
}


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
            # M5 (ADR-002 hooks amendment) + M6 A8 (ADR-025) + M8 A9
            # (ADR-027): HOOK, SKILL, and AGENT packs may ship a per-pack
            # trust root at their LOCKED staged layouts; TOOLS (the only
            # remaining kind) keep the _default root unconditionally
            # (behavior unchanged since Sprint 3).
            pack_trust_root = _resolve_pack_trust_root(
                trust_root_prefix=Path(settings.trust_root_prefix),
                kind=pack.record.kind,
                distribution_name=distribution_name,
                default_root=cosign_trust_root,
            )
            attestations = resolve_pack_attestations(
                pack,
                pack_attestation_root=root_path,
                cosign_trust_root=pack_trust_root,
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
        except _PerPackTrustRootInvalid as exc:
            # Per-pack FAIL-CLOSED: a present-but-invalid per-pack key skips
            # THAT pack (warn) — never a silent downgrade to the _default
            # root, never a boot abort. ``exc.log_event`` is the
            # kind-appropriate operator log-event name; the rendered line
            # for hook packs is byte-identical to the M5 vintage
            # (``registry_boot.hook_pack_trust_root_invalid: ...``).
            logger.warning(
                "registry_boot.%s: skipping pack distribution_name=%s reason=%s",
                exc.log_event,
                distribution_name,
                exc.reason,
            )
            continue
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


def _resolve_pack_trust_root(
    *,
    trust_root_prefix: Path,
    kind: PluginKind,
    distribution_name: str,
    default_root: Path,
) -> Path:
    """Resolve the cosign trust root for ONE discovered pack (M5 hooks per
    the ADR-002 hooks amendment; M6 A8 skills per ADR-025; M8 A9 agents per
    ADR-027).

    Kinds without a per-pack staged layout (tools — the ONLY one) →
    ``default_root`` unconditionally (unchanged behavior). HOOK packs → the
    LOCKED staged layout
    ``<trust_root_prefix>/hook-packs/<distribution_name>/cosign.pub``; SKILL
    packs → ``<trust_root_prefix>/skill-packs/<distribution_name>/cosign.pub``;
    AGENT packs →
    ``<trust_root_prefix>/agent-packs/<distribution_name>/cosign.pub``.
    All share ONE code path parameterised by
    :data:`_PER_PACK_TRUST_ROOT_POLICIES`:

      * ABSENT → ``default_root`` (a pack signed by the deployment's
        default key is legitimate).
      * PRESENT but not a regular file / empty → raise
        :class:`_PerPackTrustRootInvalid` (fail CLOSED for the pack — a
        corrupted per-pack key must never silently demote the pack to
        default-root verification).

    Resolve-then-validate discipline (the distribution name comes from wheel
    metadata an attacker controls): (1) reject hostile name syntax BEFORE any
    path is built; (2) resolve; (3) require containment under the prefix —
    a symlink pointing outside the prefix fails closed.
    """
    policy = _PER_PACK_TRUST_ROOT_POLICIES.get(kind)
    if policy is None:
        return default_root
    if (
        not distribution_name
        or distribution_name != distribution_name.strip()
        or "/" in distribution_name
        or "\\" in distribution_name
        or distribution_name.startswith(".")
    ):
        raise _PerPackTrustRootInvalid(
            policy.name_invalid, distribution_name, log_event=policy.log_event
        )
    candidate = trust_root_prefix / policy.subdir / distribution_name / _COSIGN_PUBLIC_KEY_BASENAME
    try:
        resolved_prefix = trust_root_prefix.resolve()
        resolved = candidate.resolve()
    except (OSError, RuntimeError) as exc:
        # Path resolution failure (e.g. a planted symlink loop) — fail closed.
        raise _PerPackTrustRootInvalid(
            policy.path_escape, str(candidate), log_event=policy.log_event
        ) from exc
    try:
        resolved.relative_to(resolved_prefix)
    except ValueError:
        raise _PerPackTrustRootInvalid(
            policy.path_escape, str(candidate), log_event=policy.log_event
        ) from None
    if not resolved.exists():
        return default_root
    if not resolved.is_file():
        raise _PerPackTrustRootInvalid(
            policy.not_a_file, str(candidate), log_event=policy.log_event
        )
    if resolved.stat().st_size == 0:
        raise _PerPackTrustRootInvalid(policy.empty, str(candidate), log_event=policy.log_event)
    return resolved


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
    "AgentPackTrustRootRefusalReason",
    "HookPackTrustRootRefusalReason",
    "PerPackTrustRootRefusalReason",
    "RegistryBootError",
    "RegistryBootRefusalReason",
    "SkillPackTrustRootRefusalReason",
    "build_and_populate_registry",
]
