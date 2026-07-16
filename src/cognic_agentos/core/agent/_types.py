"""M8 Task A4 (ADR-027) — agent-runtime closed enums + frozen dataclasses +
the ``AgentGrantNotRequested`` typed exception. Re-export surface for
``cognic_agentos.core.agent``.

Mirrors ``core/scheduler/_types.py`` + ``core/run/_types.py``. OFF the
critical-controls gate (pure types; the substantive enforcement lives in the
on-gate ``assignments.py`` consumer — and the A5+ dispatcher/loop). No I/O; no
DB access.

Closed-enum doctrine per ``feedback_drift_detector_test_only_no_runtime_import``
+ ``feedback_count_enum_values_via_ast_not_regex``: the ``get_args`` count pins
at ``tests/unit/core/agent/test_types.py`` are the ONLY count pins for these
enums.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# --- Closed-enum vocabularies (ADR-027 §e) ----------------------------------

#: The closed dispatch/run refusal vocabulary (8 values). Gate refusals
#: (``agent_capability_not_assigned`` / ``agent_capability_class_invalid`` /
#: ``agent_scope_not_entitled`` / ``agent_policy_denied``), the tool-side SQL-scope refusal
#: (``agent_sql_object_out_of_scope``), run-level bounds
#: (``agent_max_steps_exceeded``), backend failure
#: (``agent_tool_dispatch_failed``), and the ingestion invariant
#: (``agent_grant_not_requested``).
AgentDispatchRefusalReason = Literal[
    "agent_capability_not_assigned",
    "agent_capability_class_invalid",
    "agent_scope_not_entitled",
    "agent_sql_object_out_of_scope",
    "agent_max_steps_exceeded",
    "agent_tool_dispatch_failed",
    "agent_policy_denied",
    "agent_grant_not_requested",
]

#: Terminal states of one governed agent run (3 values). Dispatch refusals do
#: NOT terminate a run (they return to the LLM as tool messages); terminal
#: ``refused`` is reserved for run-level bounds.
AgentRunTerminalState = Literal["completed", "refused", "failed"]

# --- Frozen public dataclasses ----------------------------------------------


@dataclass(frozen=True, slots=True)
class LoadedAgentRecord:
    """Validated agent-pack projection (the A8 loader produces it; the loop +
    dispatcher + ``AssignmentStore`` consume it). ``requested_skills`` /
    ``requested_tools`` are the persona's REQUESTED capability sets — the
    ceiling the grant-not-requested ingestion invariant enforces: a grant can
    never exceed what the signed pack requested."""

    agent_id: str
    persona_body: str
    persona_sha256: str
    requested_skills: tuple[str, ...]
    requested_tools: tuple[str, ...]
    max_steps: int | None
    risk_tier: str
    pack_version: str
    signed_artefact_digest: str | None
    registered: bool


@dataclass(frozen=True, slots=True)
class CapabilityRef:
    """A resolved capability reference — what one dispatch call targets.
    ``builtin`` covers the kernel-owned built-ins (``read_skill`` /
    ``remember``): implicitly granted at dispatch, NEVER assignment rows."""

    kind: Literal["skill", "tool", "builtin"]
    ref: str


@dataclass(frozen=True, slots=True)
class PriorTurn:
    """One replayed conversation turn handed to :meth:`AgentLoop.ask` as prior
    context (ADR-028 M8.5-B).

    The loop consumes THIS shape so ``core/agent`` never imports
    ``core/conversation`` — the dependency arrow runs conversation → agent.
    """

    role: Literal["user", "assistant"]
    content: str


@dataclass(frozen=True, slots=True)
class AgentAskResult:
    """Terminal result of one governed agent run — the ONLY surface carrying
    the answer plaintext (chain rows are digest-only per ADR-027 §f).

    ``prompt_tokens`` / ``completion_tokens`` are REQUIRED, never defaulted:
    ADR-028's conversation-level cumulative budget is fed from them, and a
    bound fed by zeros reads as ENFORCED in the evidence while counting
    nothing. A caller must not be able to construct a zero-token result by
    omission.
    """

    run_id: str
    terminal_state: AgentRunTerminalState
    answer: str
    steps_used: int
    refusal_reason: AgentDispatchRefusalReason | None
    prompt_tokens: int
    completion_tokens: int


@dataclass(frozen=True, slots=True)
class GrantedCapabilities:
    """The validated granted sets dispatch enforces (gate 1). Built-ins
    (``read_skill`` / ``remember``) are kernel-owned and implicitly granted at
    dispatch — NEVER in these sets, NEVER assignment rows."""

    skills: frozenset[str]
    tools: frozenset[str]


# --- Typed exceptions ---------------------------------------------------------


class AgentGrantNotRequested(RuntimeError):
    """THE INGESTION INVARIANT refusal (ADR-027 / spec §3.1, fail-closed): an
    assignment row grants a capability the persona never REQUESTED —
    operator/config drift can never widen an agent beyond its requested set.
    Raised by ``AssignmentStore.load_for_agent`` BEFORE any grant set is
    returned (NO partial grant)."""

    def __init__(self, *, capability_ref: str, capability_kind: str) -> None:
        super().__init__(
            "agent_grant_not_requested: "
            f"{capability_kind} grant {capability_ref!r} was never requested by the persona"
        )
        self.reason: Literal["agent_grant_not_requested"] = "agent_grant_not_requested"
        self.capability_ref: str = capability_ref
        self.capability_kind: str = capability_kind
