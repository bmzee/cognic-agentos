"""M8 Task A10 (ADR-027) — the agent dispatch chokepoint (CRITICAL CONTROLS).

Critical-controls module (``core/`` stop-rule per AGENTS.md L48).
Every edit is halt-before-commit per [[feedback_strict_review_off_gate]].

Every capability call an LLM authors passes through
:meth:`AgentDispatcher.dispatch` — the SINGLE seam owning ALL dispatch
authority for the governed agent loop:

  1. **Resolve** the LLM-facing call name — built-in names (``read_skill`` /
     ``remember``) or the per-dispatch granted-tool name map (each granted ref
     is ``server_id/tool_name``; the LLM-facing name is the tool_name segment).
     A DUPLICATE tool_name across granted refs makes that name unresolvable
     (deterministic, fail-closed); an unknown name refuses
     ``agent_capability_not_assigned`` (an LLM-hallucinated tool is by
     definition unassigned).
  2. **Gate 1 — assignment**: the resolved ref must be inside the granted set
     for its kind (true by construction for tools resolved off the map —
     checked anyway, defense in depth; the skill arm is defensive/unreachable
     via the M8 resolver and direct-tested on the pure helper). The built-in
     ``read_skill`` carries THE SUB-GATE: its LLM-authored ``skill_id``
     argument is itself a capability selection and must clear
     ``run.granted.skills`` BEFORE the reader is consulted.
  3. **Gate 2 — entitlement** (stamped tools only): the LLM-authored
     ``scope_id`` argument must be a non-empty str, inside
     ``EntitlementStore.entitled_scope_ids``, and must ``resolve_scope`` to a
     real :class:`DataScope` — any miss refuses ``agent_scope_not_entitled``.
     Non-stamped calls skip gate 2 (``entitlement_verified=True`` per the
     None-scope rule).
  4. **Gate 3 — policy**: :class:`AgentDispatchPolicy` over the 11-key
     :class:`AgentPolicyInput` (the attestations are LITERALLY computed —
     gates 1-2 passed to reach here). EVERY deny — including the fail-closed
     ``opa_unavailable`` envelope — refuses ``agent_policy_denied``.
  5. **Stamp** (stamped tools only): mint the kernel-signed query-context
     token binding this dispatch to its resolved scope + the sha256 of the
     LLM-AUTHORED args (PRE-stamp — the tool-side recompute strips the token
     key), and thread it on a COPY of the arguments (the caller's dict is
     never mutated). A missing signing key is a fail-loud DEPLOYMENT error
     (RuntimeError) — never a closed-enum refusal.
  6. **Execute**: built-ins via :mod:`cognic_agentos.core.agent.builtins`;
     tools via the consumer-owned :class:`AgentToolProxy` seam (the
     ``SkillCallProxy`` precedent — the A13 harness adapter wraps
     ``MCPHost.call_tool``). ANY execution exception refuses
     ``agent_tool_dispatch_failed`` with a SAFE message (exception CLASS name
     only — never ``str(exc)`` into the LLM-visible message or the chain).
  7. **Evidence**: exactly ONE digest-only ``agent.run.dispatch``
     :class:`DecisionRecord` per ``dispatch()`` call, on EVERY arm (each
     refusal AND the ok path). ``actor_id`` is the ORIGINATOR (human
     accountability); ``agent_id`` rides the payload (the ADR-027 §f dual
     identity). NEVER raw args/results — sha256 digests + byte counts only.

Kernel-boot-clean: module-level imports are stdlib + ``core.*`` ONLY.
``llm.gateway`` is TYPE_CHECKING for annotations; the ONE runtime construction
site (:func:`build_llm_tool_specs`) uses a FUNCTION-LOCAL import (the skill
executor's sandbox-import precedent; ``llm`` is deliberately NOT on the
``core/agent`` fence). No ``portal`` / ``protocol`` / ``sdk`` / ``cli`` import
— pinned by ``tests/unit/architecture/test_agent_no_forbidden_imports.py``.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol, runtime_checkable

from cognic_agentos.core.agent import builtins as _builtins
from cognic_agentos.core.agent._types import (
    AgentDispatchRefusalReason,
    CapabilityRef,
    GrantedCapabilities,
    LoadedAgentRecord,
)
from cognic_agentos.core.agent.policy import AgentDispatchPolicy, AgentPolicyInput
from cognic_agentos.core.agent.query_context import (
    _ISSUER,
    QueryContextClaims,
    mint_query_context,
)
from cognic_agentos.core.canonical import canonical_bytes
from cognic_agentos.core.decision_history import DecisionHistoryStore, DecisionRecord
from cognic_agentos.core.entitlements import DataScope, EntitlementStore

if TYPE_CHECKING:
    from collections.abc import Mapping

    from cognic_agentos.core.memory._context import MemoryCallerContext
    from cognic_agentos.llm.gateway import GatewayToolCall, GatewayToolSpec

logger = logging.getLogger(__name__)

#: The kernel-owned built-in capability names — implicitly granted at dispatch
#: (NEVER assignment rows per ``core/agent/_types.py``); ``read_skill``'s
#: LLM-authored ``skill_id`` argument still clears the granted-skills sub-gate.
_BUILTIN_NAMES: Final[frozenset[str]] = frozenset({"read_skill", "remember"})

#: The M8 Wave-1 stamped tool set, keyed by the tool_name SEGMENT of a granted
#: ``server_id/tool_name`` ref. Dispatches to these tools run gate 2
#: (entitlement) and carry the kernel-signed query-context token; every other
#: tool skips both (``entitlement_verified=True`` per the None-scope rule).
_QUERY_CONTEXT_STAMPED_TOOLS: Final[frozenset[str]] = frozenset({"run_readonly_query"})

#: The reserved argument key the signed query-context token rides on. Kernel-
#: owned: NEVER advertised in :func:`build_llm_tool_specs` output (the
#: schema-exclusion pin) and stripped by the tool-side args-digest recompute.
_QUERY_CONTEXT_ARG: Final[str] = "_cognic_query_context"

#: ISO-control mapping for agent.* evidence is a Human-only decision — deferred
#: (mirrors ``core/skill/executor.py``'s ``_SKILL_EVIDENCE_ISO_CONTROLS`` +
#: ``core/run/executor.py``'s ``_RUN_EVIDENCE_ISO_CONTROLS``).
_AGENT_DISPATCH_ISO_CONTROLS: tuple[str, ...] = ()

#: Request-id prefixes: the downstream MCP-host call correlator (mirrors the
#: skill broker's ``skill-tool-`` minting) + the dispatch evidence row's own id.
_AGENT_TOOL_REQUEST_ID_PREFIX: Final[str] = "agent-tool-"
_AGENT_DISPATCH_REQUEST_ID_PREFIX: Final[str] = "agent-dispatch-"


# --- Dispatch contract types (they ARE the contract — the AgentPolicyInput
# --- precedent at core/agent/policy.py) ---------------------------------------


@dataclass(frozen=True, slots=True)
class AgentRunContext:
    """One governed agent run's dispatch-relevant identity + authority.

    ``granted`` is the A4 ingestion-validated grant set (gate 1 enforces it);
    ``max_steps`` is the EFFECTIVE run bound the loop resolved (the record's
    nullable ``max_steps`` already defaulted); ``record`` is the A8 loader's
    validated agent-pack projection.
    """

    run_id: str
    tenant_id: str
    originator_subject: str
    agent_id: str
    granted: GrantedCapabilities
    max_steps: int
    record: LoadedAgentRecord


@dataclass(frozen=True, slots=True)
class DispatchOutcome:
    """Outcome of one :meth:`AgentDispatcher.dispatch` call.

    ``refused=True`` carries the closed-enum ``reason`` + the closed-form
    graceful ``message`` the loop feeds back to the LLM (never raw exception
    text); ``refused=False`` carries the tool/builtin ``result`` payload.
    """

    refused: bool
    reason: AgentDispatchRefusalReason | None
    message: str | None
    result: dict[str, Any] | None


@runtime_checkable
class AgentToolProxy(Protocol):
    """Consumer-owned narrow seam over ``MCPHost.call_tool`` (the
    ``SkillCallProxy`` precedent — ``core/agent`` NEVER imports
    ``protocol.*``; the A13 harness adapter is the conformer and owns the
    ``CallResult`` → dict projection). Implementations surface failures as
    exceptions — the dispatcher maps them to ``agent_tool_dispatch_failed``.
    """

    async def call_tool(
        self,
        *,
        server_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        request_id: str,
        tenant_id: str,
        originator_subject: str,
        approval_request_id: uuid.UUID | None,
    ) -> dict[str, Any]: ...


class SkillBodyReader(Protocol):
    """Read seam for hosted INSTRUCTION skills (the M8 A7 ``read_skill``
    source): returns ``(description, body)`` or ``None`` when the id is not a
    hosted instruction skill."""

    def read(self, skill_id: str) -> tuple[str, str] | None: ...


class MemoryApiFactory(Protocol):
    """Mints a MemoryAPI-like (exposing ``async remember(key, value, *, tier,
    data_classes, purpose)``) bound to the kernel-built
    :class:`MemoryCallerContext` — the governed-memory access path for the
    ``remember`` built-in."""

    def __call__(self, context: MemoryCallerContext) -> Any: ...


# --- Pure resolution / gate-1 helpers (module-level so the defensive arms are
# --- direct-testable — the A4 ``_validate_and_partition`` precedent) -----------


def _granted_tool_name_map(tools: frozenset[str]) -> dict[str, str]:
    """LLM-facing tool name → full granted ref, built per-dispatch.

    Each granted ref is ``server_id/tool_name`` (split on the FIRST ``/``);
    the LLM-facing name is the tool_name segment. Fail-closed determinism:

    * a DUPLICATE tool_name across granted refs removes that name entirely —
      an ambiguous name must never silently pick a server;
    * a malformed ref (no separator / empty server / empty name) can never be
      addressed and is skipped.

    Consumed by both :meth:`AgentDispatcher.dispatch` (resolution) and
    :func:`build_llm_tool_specs` (advertisement) so the two surfaces can
    never diverge.
    """
    mapping: dict[str, str] = {}
    duplicates: set[str] = set()
    for ref in sorted(tools):
        server_id, sep, tool_name = ref.partition("/")
        if not sep or not server_id or not tool_name:
            continue  # malformed granted ref — unaddressable, fail-closed
        if tool_name in duplicates:
            continue
        if tool_name in mapping:
            duplicates.add(tool_name)
            del mapping[tool_name]
            continue
        mapping[tool_name] = ref
    return mapping


def _resolve_capability(name: str, granted: GrantedCapabilities) -> CapabilityRef | None:
    """Resolve the LLM-facing call name: built-ins first, then the granted-
    tool name map. ``None`` = unresolvable (hallucinated / duplicate /
    malformed) → ``agent_capability_not_assigned``."""
    if name in _BUILTIN_NAMES:
        return CapabilityRef(kind="builtin", ref=name)
    full_ref = _granted_tool_name_map(granted.tools).get(name)
    if full_ref is None:
        return None
    return CapabilityRef(kind="tool", ref=full_ref)


def _assignment_verified(resolved: CapabilityRef, granted: GrantedCapabilities) -> bool:
    """Gate 1 — the resolved ref must be inside the granted set for its kind.

    Tools resolved off the name map are granted by construction — checked
    anyway (defense in depth). The skill arm is DEFENSIVE: unreachable via the
    M8 resolver (which never mints ``kind="skill"``), direct-tested here.
    Built-ins pass the NAME gate (resolution established the name); the
    ``read_skill`` skill_id sub-gate is :func:`_validated_read_skill_id`.
    """
    if resolved.kind == "tool":
        return resolved.ref in granted.tools
    if resolved.kind == "skill":
        return resolved.ref in granted.skills
    return resolved.ref in _BUILTIN_NAMES


def _validated_read_skill_id(
    arguments: Mapping[str, Any], granted: GrantedCapabilities
) -> str | None:
    """THE read_skill SUB-GATE: the built-in is generic, so the LLM-authored
    ``skill_id`` argument is itself a capability selection and must clear the
    same granted set (without this, ``read_skill("atm-recon")`` would read an
    unassigned skill's body). ``None`` = refuse ``agent_capability_not_assigned``
    BEFORE the reader is consulted."""
    skill_id = arguments.get("skill_id")
    if isinstance(skill_id, str) and skill_id in granted.skills:
        return skill_id
    return None


def _tool_name_segment(ref: str) -> str:
    """The tool_name segment of a ``server_id/tool_name`` ref."""
    return ref.partition("/")[2]


class AgentDispatcher:
    """The single dispatch authority of the governed agent loop (ADR-027).

    Owns the assignment gate, the entitlement gate, the Rego policy gate, the
    query-context stamp, built-in routing, and the per-dispatch
    ``agent.run.dispatch`` evidence row. The loop (A11) calls
    :meth:`dispatch` once per LLM-authored tool call and feeds refusal
    messages back to the model as tool results.
    """

    def __init__(
        self,
        *,
        entitlements: EntitlementStore,
        policy: AgentDispatchPolicy,
        tool_proxy: AgentToolProxy,
        skill_reader: SkillBodyReader,
        memory_factory: MemoryApiFactory,
        decision_history: DecisionHistoryStore,
        query_context_signing_key_pem: bytes | None,
        query_context_ttl_s: float,
    ) -> None:
        self._entitlements = entitlements
        self._policy = policy
        self._tool_proxy = tool_proxy
        self._skill_reader = skill_reader
        self._memory_factory = memory_factory
        self._decision_history = decision_history
        self._signing_key_pem = query_context_signing_key_pem
        self._ttl_s = query_context_ttl_s

    async def dispatch(
        self, *, call: GatewayToolCall, step_index: int, run: AgentRunContext
    ) -> DispatchOutcome:
        """Run THE PIPELINE (order IS the contract — see the module docstring).

        Every arm — each refusal AND the ok path — ends in exactly ONE
        ``agent.run.dispatch`` evidence row. The single non-arm exit is the
        fail-loud RuntimeError on a missing signing key (a DEPLOYMENT error:
        nothing governed executed, so nothing is evidenced).
        """
        # The dispatch-evidence args digest — ALWAYS over the LLM-AUTHORED
        # args (PRE-stamp; the token key never enters any digest basis).
        args_sha256 = hashlib.sha256(canonical_bytes(dict(call.arguments))).hexdigest()

        # --- 1. Resolve the LLM-facing name.
        resolved = _resolve_capability(call.name, run.granted)
        if resolved is None:
            return await self._refuse(
                run=run,
                step_index=step_index,
                args_sha256=args_sha256,
                reason="agent_capability_not_assigned",
                message=f"capability '{call.name}' is not assigned to this agent",
                # Resolution failed: the kind is honestly unknown (None) and
                # the evidence ref falls back to the raw LLM-authored name.
                capability_kind=None,
                capability_ref=call.name,
                scope_id=None,
            )

        # --- 2. Gate 1 — assignment (defense in depth; see the pure helpers).
        if not _assignment_verified(resolved, run.granted):
            return await self._refuse(
                run=run,
                step_index=step_index,
                args_sha256=args_sha256,
                reason="agent_capability_not_assigned",
                message=f"capability '{resolved.ref}' is not assigned to this agent",
                capability_kind=resolved.kind,
                capability_ref=resolved.ref,
                scope_id=None,
            )
        read_skill_id: str | None = None
        if resolved.kind == "builtin" and resolved.ref == "read_skill":
            read_skill_id = _validated_read_skill_id(call.arguments, run.granted)
            if read_skill_id is None:
                raw_skill_id = call.arguments.get("skill_id")
                message = (
                    f"capability '{raw_skill_id}' is not assigned to this agent"
                    if isinstance(raw_skill_id, str)
                    else "builtin 'read_skill' requires a string 'skill_id' "
                    "argument naming an assigned skill"
                )
                return await self._refuse(
                    run=run,
                    step_index=step_index,
                    args_sha256=args_sha256,
                    reason="agent_capability_not_assigned",
                    message=message,
                    capability_kind=resolved.kind,
                    capability_ref=resolved.ref,
                    scope_id=None,
                )

        # --- 3. Gate 2 — entitlement (stamped tools only).
        stamped = (
            resolved.kind == "tool"
            and _tool_name_segment(resolved.ref) in _QUERY_CONTEXT_STAMPED_TOOLS
        )
        scope_id: str | None = None
        resolved_scope: DataScope | None = None
        if stamped:
            raw_scope = call.arguments.get("scope_id")
            if not isinstance(raw_scope, str) or not raw_scope:
                return await self._refuse(
                    run=run,
                    step_index=step_index,
                    args_sha256=args_sha256,
                    reason="agent_scope_not_entitled",
                    message=(
                        "a string 'scope_id' argument is required and must "
                        "name an entitled data scope"
                    ),
                    capability_kind=resolved.kind,
                    capability_ref=resolved.ref,
                    scope_id=None,
                )
            entitled = await self._entitlements.entitled_scope_ids(
                tenant_id=run.tenant_id, subject=run.originator_subject
            )
            if raw_scope not in entitled:
                return await self._refuse(
                    run=run,
                    step_index=step_index,
                    args_sha256=args_sha256,
                    reason="agent_scope_not_entitled",
                    message=f"data scope '{raw_scope}' is not entitled for this request",
                    capability_kind=resolved.kind,
                    capability_ref=resolved.ref,
                    scope_id=raw_scope,
                )
            resolved_scope = await self._entitlements.resolve_scope(
                tenant_id=run.tenant_id, scope_id=raw_scope
            )
            if resolved_scope is None:
                # Absent OR cross-tenant — the store's wire-collapse None.
                return await self._refuse(
                    run=run,
                    step_index=step_index,
                    args_sha256=args_sha256,
                    reason="agent_scope_not_entitled",
                    message=f"data scope '{raw_scope}' is not entitled for this request",
                    capability_kind=resolved.kind,
                    capability_ref=resolved.ref,
                    scope_id=raw_scope,
                )
            scope_id = raw_scope

        # --- 4. Gate 3 — policy. The attestations are LITERALLY computed:
        # gates 1-2 passed to reach this point (the bundle re-requires each
        # strictly == true — the sandbox.rego rule-4 defense-in-depth mirror).
        decision = await self._policy.evaluate(
            AgentPolicyInput(
                tenant_id=run.tenant_id,
                agent_id=run.agent_id,
                originator_subject=run.originator_subject,
                capability_kind=resolved.kind,
                capability_ref=resolved.ref,
                scope_id=scope_id,
                pack_risk_tier=run.record.risk_tier,
                step_index=step_index,
                max_steps=run.max_steps,
                assignment_verified=True,
                entitlement_verified=True,
            )
        )
        if not decision.allow:
            # EVERY deny — including the fail-closed opa_unavailable envelope
            # — maps to the wire refusal (regardless of policy_reason).
            return await self._refuse(
                run=run,
                step_index=step_index,
                args_sha256=args_sha256,
                reason="agent_policy_denied",
                message="policy refused this dispatch",
                capability_kind=resolved.kind,
                capability_ref=resolved.ref,
                scope_id=scope_id,
            )

        # --- 5. Stamp (stamped tools only). Execute-args are a COPY — the
        # caller's dict is never mutated.
        execute_arguments: dict[str, Any] = dict(call.arguments)
        if stamped:
            if self._signing_key_pem is None:
                # Fail-loud DEPLOYMENT error (NOT a closed-enum refusal): a
                # stamped tool is granted but the kernel has no signing key.
                # Nothing governed executed — nothing is evidenced.
                raise RuntimeError(
                    "query_context_signing_key_pem is not configured but the "
                    f"stamped tool {resolved.ref!r} was dispatched; the "
                    "query-context signing key is a deployment requirement "
                    "for stamped tools (ADR-027 §c)"
                )
            assert resolved_scope is not None and scope_id is not None  # gate 2 resolved
            issued_at = int(time.time())
            token = mint_query_context(
                claims=QueryContextClaims(
                    iss=_ISSUER,
                    aud=resolved.ref,  # the FULL "server_id/tool_name" ref
                    sub=run.originator_subject,
                    act=run.agent_id,
                    tenant_id=run.tenant_id,
                    scope_id=scope_id,
                    objects=resolved_scope.objects,
                    proxy_db_identity=resolved_scope.proxy_db_identity,
                    args_sha256=args_sha256,
                    jti=secrets.token_hex(16),
                    iat=issued_at,
                    exp=issued_at + int(self._ttl_s),
                ),
                signing_key_pem=self._signing_key_pem,
            )
            execute_arguments[_QUERY_CONTEXT_ARG] = token

        # --- 6. Execute (built-in or proxied tool). ANY execution exception
        # refuses with the exception CLASS name only — never str(exc).
        try:
            if resolved.kind == "builtin":
                result = await self._execute_builtin(
                    resolved.ref,
                    call=call,
                    read_skill_id=read_skill_id,
                    step_index=step_index,
                    run=run,
                )
            else:
                server_id, _, tool_name = resolved.ref.partition("/")
                result = await self._tool_proxy.call_tool(
                    server_id=server_id,
                    tool_name=tool_name,
                    arguments=execute_arguments,
                    request_id=f"{_AGENT_TOOL_REQUEST_ID_PREFIX}{uuid.uuid4().hex}",
                    tenant_id=run.tenant_id,
                    originator_subject=run.originator_subject,
                    approval_request_id=None,
                )
        except Exception as exc:
            # Operator-axis diagnostic only (exc_info) — the LLM-visible
            # message + the chain payload carry the CLASS name at most.
            logger.warning(
                "agent.dispatch_tool_failed",
                extra={
                    "capability_ref": resolved.ref,
                    "exception_class": type(exc).__name__,
                },
                exc_info=True,
            )
            return await self._refuse(
                run=run,
                step_index=step_index,
                args_sha256=args_sha256,
                reason="agent_tool_dispatch_failed",
                message=f"the tool call failed ({type(exc).__name__})",
                capability_kind=resolved.kind,
                capability_ref=resolved.ref,
                scope_id=scope_id,
            )

        # --- 7. Evidence + ok.
        await self._emit_dispatch(
            run=run,
            step_index=step_index,
            args_sha256=args_sha256,
            outcome="ok",
            refusal_reason=None,
            capability_kind=resolved.kind,
            capability_ref=resolved.ref,
            scope_id=scope_id,
            result=result,
        )
        return DispatchOutcome(refused=False, reason=None, message=None, result=result)

    async def _execute_builtin(
        self,
        ref: str,
        *,
        call: GatewayToolCall,
        read_skill_id: str | None,
        step_index: int,
        run: AgentRunContext,
    ) -> dict[str, Any]:
        """Route the two kernel-owned built-ins. ``read_skill_id`` is the
        gate-1-validated skill id (never the raw argument)."""
        if ref == "read_skill":
            assert read_skill_id is not None  # validated at gate 1
            return await _builtins.read_skill(skill_id=read_skill_id, reader=self._skill_reader)
        # remember — a missing/non-str note is a malformed LLM argument:
        # fail-closed here (→ the agent_tool_dispatch_failed arm), never
        # silently coerced. The governed MemoryAPI gate (data classes /
        # purpose / tier) governs the write downstream.
        note = call.arguments.get("note")
        if not isinstance(note, str):
            raise TypeError("builtin 'remember' requires a string 'note' argument")
        return await _builtins.remember(
            note=note,
            step_index=step_index,
            memory_factory=self._memory_factory,
            run=run,
        )

    async def _refuse(
        self,
        *,
        run: AgentRunContext,
        step_index: int,
        args_sha256: str,
        reason: AgentDispatchRefusalReason,
        message: str,
        capability_kind: str | None,
        capability_ref: str,
        scope_id: str | None,
    ) -> DispatchOutcome:
        """One refusal arm: emit the single evidence row, then return the
        closed-form graceful outcome the loop feeds back to the LLM."""
        await self._emit_dispatch(
            run=run,
            step_index=step_index,
            args_sha256=args_sha256,
            outcome="refused",
            refusal_reason=reason,
            capability_kind=capability_kind,
            capability_ref=capability_ref,
            scope_id=scope_id,
            result=None,
        )
        return DispatchOutcome(refused=True, reason=reason, message=message, result=None)

    async def _emit_dispatch(
        self,
        *,
        run: AgentRunContext,
        step_index: int,
        args_sha256: str,
        outcome: Literal["ok", "refused"],
        refusal_reason: AgentDispatchRefusalReason | None,
        capability_kind: str | None,
        capability_ref: str,
        scope_id: str | None,
        result: dict[str, Any] | None,
    ) -> None:
        """The ONE ``agent.run.dispatch`` evidence row per dispatch, on EVERY
        arm. Digest-only per ADR-027 §f: sha256 digests + canonical byte
        counts, NEVER raw args/results. ``capability_kind`` is ``None`` only
        on the resolution-failure arm (the kind is honestly unknown);
        ``capability_ref`` then falls back to the raw LLM-authored call name.
        """
        if result is not None:
            result_canonical = canonical_bytes(result)
            result_sha256: str | None = hashlib.sha256(result_canonical).hexdigest()
            result_bytes: int | None = len(result_canonical)
        else:
            result_sha256 = None
            result_bytes = None
        payload: dict[str, Any] = {
            "run_id": run.run_id,
            # The ADR-027 §f dual identity: the AGENT rides the payload; the
            # ORIGINATOR is the DecisionRecord.actor_id (human accountability).
            "agent_id": run.agent_id,
            "originator_subject": run.originator_subject,
            "capability_kind": capability_kind,
            "capability_ref": capability_ref,
            "scope_id": scope_id,
            "step_index": step_index,
            "outcome": outcome,
            "refusal_reason": refusal_reason,
            "args_sha256": args_sha256,
            "result_sha256": result_sha256,
            "result_bytes": result_bytes,
        }
        await self._decision_history.append(
            DecisionRecord(
                decision_type="agent.run.dispatch",
                request_id=f"{_AGENT_DISPATCH_REQUEST_ID_PREFIX}{uuid.uuid4().hex}",
                payload=payload,
                actor_id=run.originator_subject,
                tenant_id=run.tenant_id,
                iso_controls=_AGENT_DISPATCH_ISO_CONTROLS,
            )
        )


def build_llm_tool_specs(*, run: AgentRunContext) -> tuple[GatewayToolSpec, ...]:
    """The LLM-facing capability surface — kernel-curated for the M8 lane.

    One spec per RESOLVABLE granted tool (name = the tool_name segment, off
    the SAME name map dispatch resolves against, so the advertised surface and
    the dispatchable surface can never diverge — duplicates/malformed refs are
    advertised to the LLM as nothing at all) + the two built-ins.

    THE SCHEMA-EXCLUSION PIN: the ``run_readonly_query`` parameters are
    EXACTLY ``{scope_id (required), sql (required), max_rows (optional)}`` —
    NEVER :data:`_QUERY_CONTEXT_ARG`, NEVER identity/tenant fields. The
    query-context token is kernel-stamped at dispatch; the LLM can neither
    see nor author it.
    """
    # FUNCTION-LOCAL import (kernel-boot-clean — the skill executor's
    # sandbox-import precedent; annotations stay TYPE_CHECKING-only).
    from cognic_agentos.llm.gateway import GatewayToolSpec

    specs: list[GatewayToolSpec] = []
    name_map = _granted_tool_name_map(run.granted.tools)
    for tool_name in sorted(name_map):
        if tool_name in _QUERY_CONTEXT_STAMPED_TOOLS:
            parameters: dict[str, Any] = {
                "type": "object",
                "properties": {
                    "scope_id": {
                        "type": "string",
                        "description": "The entitled data-scope id this query runs under.",
                    },
                    "sql": {
                        "type": "string",
                        "description": "The read-only SQL statement to execute.",
                    },
                    "max_rows": {
                        "type": "integer",
                        "description": "Optional cap on the number of rows returned.",
                    },
                },
                "required": ["scope_id", "sql"],
                "additionalProperties": False,
            }
            description = "Run a governed read-only SQL query inside an entitled data scope."
        else:
            # The kernel does not curate non-stamped tool schemas in the M8
            # lane — a permissive object schema; governance is dispatch-side.
            parameters = {"type": "object", "properties": {}, "additionalProperties": True}
            description = f"Invoke the governed tool '{tool_name}'."
        specs.append(
            GatewayToolSpec(name=tool_name, description=description, parameters=parameters)
        )
    specs.append(
        GatewayToolSpec(
            name="read_skill",
            description="Read the body of an instruction skill assigned to this agent.",
            parameters={
                "type": "object",
                "properties": {
                    "skill_id": {
                        "type": "string",
                        "description": "The assigned skill id to read.",
                    }
                },
                "required": ["skill_id"],
                "additionalProperties": False,
            },
        )
    )
    specs.append(
        GatewayToolSpec(
            name="remember",
            description="Store a short task-scoped note for this run.",
            parameters={
                "type": "object",
                "properties": {
                    "note": {"type": "string", "description": "The note text to remember."}
                },
                "required": ["note"],
                "additionalProperties": False,
            },
        )
    )
    return tuple(specs)


__all__ = (
    "AgentDispatcher",
    "AgentRunContext",
    "AgentToolProxy",
    "DispatchOutcome",
    "MemoryApiFactory",
    "SkillBodyReader",
    "build_llm_tool_specs",
)
