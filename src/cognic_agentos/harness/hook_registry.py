"""Hook-registry production construction (M5, ADR-008 + ADR-017).

Walks registry candidates admitted by the upstream plugin trust gate and
admits each installed hook pack's ``[hooks]`` declarations into a
``HookRegistry`` (digest-pinned via ``register_pack``), and assembles the
shared ``HookDispatcher`` plus the ``DLPGuard`` adapter the MCP host consumes.
The production builder wires every value-free dispatcher row into both
governed evidence stores. Per-pack fail-closed: a malformed hook pack is
skipped + logged (mirrors the MCP mapper's warn-skip doctrine in
``harness/mcp_host.py``); the runtime still builds. A DLP hook ID explicitly
referenced by a calling pack then fails closed at scan time
(``dlp_hook_id_unresolved``). The candidate's ``signature_digest`` is retained
as provenance, but this builder does not independently bind the installed
manifest/entry-point bytes re-read through ``importlib.metadata`` to the
verified wheel or its RECORD; it must not be cited as closing that parity gap.
Conversation phases are selected phase-wide:
their readiness gate refuses construction only when the admitted phase is
empty, rather than rediscovering an ID from a calling pack.

Deferred-load invariant (ADR-002 §gate 1 discipline): the walk resolves each
declaration to an ``importlib.metadata.EntryPoint`` and threads ``ep.load``
as the ``callable_loader`` WITHOUT invoking it — pack code is imported only
when the dispatcher first runs the hook.
"""

from __future__ import annotations

import importlib.metadata as md
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from cognic_agentos.core.agent._types import LoadedAgentRecord
from cognic_agentos.core.audit import AuditEvent
from cognic_agentos.core.conversation.turn import (
    ConversationHookEvidenceError,
    ConversationHookGovernance,
    ConversationHookPhase,
    ConversationHookScanResult,
    ConversationOutputOrigin,
)
from cognic_agentos.core.decision_history import DecisionRecord
from cognic_agentos.packs.hooks.dispatcher import HookDispatcher, HookDispatchEvidenceError
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
from cognic_agentos.sdk.hook import HookContext

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping

    from cognic_agentos.core.config import Settings
    from cognic_agentos.protocol.plugin_registry import RegisteredPackCandidate

logger = logging.getLogger(__name__)

#: Payload budget fed to ``HookDispatcher.max_payload_bytes``. There is NO
#: Settings field for this today (only ``Settings.hook_max_timeout_s``
#: exists); a module constant is the YAGNI choice for M5. Promote to a
#: Setting if an operator ever needs to tune it (follow-up).
_HOOK_MAX_PAYLOAD_BYTES = 1_000_000


@dataclass(frozen=True, slots=True)
class HookRuntime:
    """One shared dispatcher and its MCP DLP adapter.

    The dispatcher owns hook ordering and evidence emission independently of
    the optional MCP protocol surface. ``DLPGuard`` is only an adapter over
    that same dispatcher for MCP callers.
    """

    dispatcher: HookDispatcher
    dlp_guard: DLPGuard


class ConversationHookGuardAdapter:
    """Conversation-turn adapter over the shared phase-wide dispatcher.

    Governance is the immutable projection produced with the admitted agent
    records. No manifest is re-read at turn time. Unknown or legacy records
    without a complete declaration fail before dispatch.
    """

    def __init__(
        self,
        *,
        dispatcher: HookDispatcher,
        agent_records: Mapping[str, LoadedAgentRecord],
    ) -> None:
        conversation_phases: tuple[ConversationHookPhase, ...] = (
            "conversation_input",
            "conversation_output",
        )
        missing = [phase for phase in conversation_phases if not dispatcher.has_phase_hooks(phase)]
        if missing:
            raise ValueError(
                "conversation hook runtime requires admitted hooks for both phases; "
                f"missing {', '.join(missing)}"
            )
        if not dispatcher.evidence_emission_configured:
            raise ValueError("conversation hook runtime requires fail-loud evidence emission")
        self._dispatcher = dispatcher
        self._agent_records = agent_records

    def governance_for_agent(self, *, agent_id: str) -> ConversationHookGovernance:
        record = self._agent_records.get(agent_id)
        if record is None:
            raise LookupError("agent has no admitted governance projection")
        return ConversationHookGovernance(
            pack_id=record.pack_id,
            declared_data_classes=record.manifest_data_classes,
            manifest_purpose=record.manifest_purpose,
        )

    async def scan(
        self,
        *,
        phase: ConversationHookPhase,
        payload: bytes,
        governance: ConversationHookGovernance,
        tenant_id: str,
        request_id: str,
        conversation_id: uuid.UUID,
        turn_seq: int,
        agent_run_id: str | None,
        output_origin: ConversationOutputOrigin | None,
        approval_delivery_id: str | None,
        validate_transformed_payload: Callable[[bytes], None],
        evidence_value_projector: Callable[[bytes], bytes] | None = None,
        evidence_input_value: bytes | None = None,
    ) -> ConversationHookScanResult:
        try:
            result = await self._dispatcher.dispatch(
                phase=phase,
                payload=payload,
                context_template=HookContext(
                    hook_id="",
                    phase=phase,
                    pack_id=governance.pack_id,
                    tenant_id=tenant_id,
                    request_id=request_id,
                    trace_id=None,
                    parent_trace_id=None,
                    manifest_data_classes=governance.declared_data_classes,
                    manifest_purpose=governance.manifest_purpose,
                    conversation_id=str(conversation_id),
                    conversation_turn_seq=turn_seq,
                    agent_run_id=agent_run_id,
                    output_origin=output_origin,
                    approval_delivery_id=approval_delivery_id,
                ),
                require_nonempty=True,
                transformed_payload_validator=validate_transformed_payload,
                evidence_value_projector=evidence_value_projector,
                evidence_input_value=evidence_input_value,
            )
        except HookDispatchEvidenceError as exc:
            raise ConversationHookEvidenceError(
                final_payload=exc.final_payload,
                hook_decision_count=exc.hook_decision_count,
            ) from exc
        return ConversationHookScanResult(
            outcome=result.outcome,
            final_payload=result.final_payload,
            hook_decision_count=result.hook_decision_count,
        )

    def turn_timeout_budget_s(self) -> float:
        """Return both admitted conversation-phase invocation timeout sums."""

        return self._dispatcher.phase_timeout_budget_s(
            "conversation_input"
        ) + self._dispatcher.phase_timeout_budget_s("conversation_output")


class _RegistryCandidates(Protocol):
    """Structural seam — anything exposing the registered-candidate iterator
    (the real ``PluginRegistry`` or a test stub)."""

    def iter_registered_pack_candidates(self) -> Iterator[RegisteredPackCandidate]: ...


class _AuditAppender(Protocol):
    def append(self, event: AuditEvent) -> Awaitable[object]: ...


class _DecisionAppender(Protocol):
    def append(self, record: DecisionRecord) -> Awaitable[object]: ...


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
    """Build the runtime-admitted VerifiedHookPack; ``None`` on malformation.

    ``VerifiedHookPack`` is the runtime registry type name, not a claim that
    this builder re-verifies installed bytes against the candidate signature.
    The upstream candidate supplies trust provenance; this function validates
    installed declaration/entry-point shape and preserves that digest.

    A per-pack malformation returns ``None``: a declared hook MUST have an
    entry-point and a well-formed declaration, else the WHOLE pack is skipped
    (fail closed).
    """
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


def _dual_evidence_emitter(
    *,
    audit_store: _AuditAppender,
    decision_history_store: _DecisionAppender,
) -> Callable[[dict[str, object]], Awaitable[None]]:
    """Return the fail-loud hook evidence sink used by production.

    The dispatcher supplies a value-free row.  Both governed stores receive
    the same snapshot; either append failure propagates back through dispatch
    so a hook decision can never be used without its required evidence.
    """

    async def _emit(row: dict[str, object]) -> None:
        event_type = row.get("event_type")
        request_id = row.get("request_id")
        tenant_id = row.get("tenant_id")
        if not isinstance(event_type, str) or not event_type:
            raise ValueError("hook evidence event_type must be a non-empty string")
        if not isinstance(request_id, str) or not request_id:
            raise ValueError("hook evidence request_id must be a non-empty string")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError("hook evidence tenant_id must be a non-empty string")

        # Copy once per store so neither append implementation can mutate what
        # its sibling receives.  Store-boundary canonicalisation independently
        # snapshots each payload before hashing and persistence.
        await audit_store.append(
            AuditEvent(
                event_type=event_type,
                request_id=request_id,
                tenant_id=tenant_id,
                payload=dict(row),
            )
        )
        await decision_history_store.append(
            DecisionRecord(
                decision_type=event_type,
                request_id=request_id,
                tenant_id=tenant_id,
                payload=dict(row),
            )
        )

    return _emit


def _build_dispatcher(
    *,
    registry: _RegistryCandidates,
    settings: Settings,
    audit_emitter: Callable[[dict[str, object]], Awaitable[None]] | None,
) -> HookDispatcher:
    """Build one dispatcher over every admitted hook declaration.

    Raises only on hard construction failure (dispatcher ctor). Malformed
    hook packs are skipped per-pack (logged) so one bad pack cannot take the
    whole runtime down. Any DLP ID explicitly referenced by a calling pack
    then fails closed at scan time via ``dlp_hook_id_unresolved``;
    conversation phases have no calling-pack ID reference.
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
        audit_emitter=audit_emitter,
    )
    return dispatcher


def build_hook_runtime(
    *,
    registry: _RegistryCandidates,
    settings: Settings,
    audit_store: _AuditAppender,
    decision_history_store: _DecisionAppender,
) -> HookRuntime:
    """Build the shared production hook runtime.

    Hook evidence is mandatory on this path.  The emitter writes every
    dispatcher row to both governed stores and deliberately propagates either
    failure.
    """

    dispatcher = _build_dispatcher(
        registry=registry,
        settings=settings,
        audit_emitter=_dual_evidence_emitter(
            audit_store=audit_store,
            decision_history_store=decision_history_store,
        ),
    )
    return HookRuntime(
        dispatcher=dispatcher,
        dlp_guard=DLPGuard(dispatcher=dispatcher),
    )


def build_dlp_guard(*, registry: _RegistryCandidates, settings: Settings) -> DLPGuard:
    """Compatibility builder for callers that only need the MCP adapter.

    Production uses :func:`build_hook_runtime` so evidence is mandatory.
    This SDK-free helper retains the historical, evidence-free construction
    surface for focused tests and compatibility callers; the portal never
    uses it.
    """

    dispatcher = _build_dispatcher(
        registry=registry,
        settings=settings,
        audit_emitter=None,
    )
    return DLPGuard(dispatcher=dispatcher)
