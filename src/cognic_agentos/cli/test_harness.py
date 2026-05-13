"""Sprint-7A T13 — `agentos test-harness` hybrid runner (Doctrine Decision C).

Authoring/dev-only public CLI surface (R4 P3 #5 — public command, NOT
test-only path; sits off the critical-controls coverage floor only
because every gate it surfaces is already enforced upstream by
:func:`cognic_agentos.cli.validate.run_validators` which IS on the
floor). The harness is the pack-author iteration loop's pre-publish
green-light: scaffold → fill placeholders → ``agentos validate`` →
``agentos test-harness`` → ``agentos sign --bundle`` → ``agentos verify``.

Per Doctrine Decision C, ``agentos test-harness <pack-path>`` runs:

  1. Manifest parse via the shared loader (re-uses
     :func:`cognic_agentos.cli.validate.run_validators` so every
     refusal the validate command emits surfaces here too).
  2. The full validate pipeline (every per-concern validator runs).
  3. Per-kind dry-run dispatch for all four supported kinds (Sprint-
     7B.1 T6a widened the kind-narrowing gate from ``{"tool"}`` to
     the full ``{"tool", "skill", "agent", "hook"}`` vocabulary; T6b
     wired the dispatch impls below). Load each entry-point declared
     in the pack's ``pyproject.toml`` under the matching
     ``cognic.<kind>s`` group via filepath
     (``importlib.util.spec_from_file_location`` against
     ``pack_path/src/``), then dry-run via the kind's PUBLIC SDK
     seam — never the private ``_invoke`` paths, so the SDK's
     validation seams fire end-to-end:

       - ``tool`` — ``cls() + await tool.invoke()`` against the
         Tool template-method seam at ``sdk/tool.py:144`` (validates
         kwargs against ``input_schema`` + result against
         ``output_schema``).
       - ``skill`` — ``cls(tools=<no-op-registry>) + await
         skill.execute()`` against the Skill cross-check seam at
         ``sdk/skill.py:73`` (R5 P2 #3 — validates ``declared_tools``
         against the registry's ``list_tools()``). The no-op
         registry is built by :func:`_build_skill_tool_registry`
         from the skill class's ``declared_tools`` ClassVar so
         multi-tool skills get a registry that exactly matches
         their declaration.
       - ``agent`` — ``cls() + await agent.handle(payload, task=
         <inert TaskRecord>)`` against the Agent abstract method at
         ``sdk/agent.py:52-77``.
       - ``hook`` — ``cls() + await hook.invoke(context, payload)``
         against the PUBLIC seam at ``sdk/hook.py:347`` (NOT the
         abstract ``_invoke`` at ``sdk/hook.py:373``). Hook.invoke
         runs three SDK validation phases:
         ``_validate_hook_context`` + ``_validate_hook_payload``
         (pre-``_invoke``; sdk/hook.py:221-241) +
         ``_validate_hook_result`` (post-``_invoke``;
         sdk/hook.py:244-288). Hook results pass through
         :func:`_hook_result_to_safe_report_dict` so the
         conformance report carries only safe metadata indicators
         (``decision`` / ``policy_reason`` /
         ``redacted_payload_present`` / ``audit_metadata_keys``) —
         raw ``redacted_payload`` bytes NEVER cross the harness
         reporting boundary per ADR-017 + Doctrine Lock E (Sprint-
         7A2 T7 payload-never-logged invariant pinned by
         ``tests/architecture/test_hook_payload_never_logged.py``
         + extended to the harness in T6b's
         ``test_hook_dispatch_report_never_carries_redacted_payload_bytes``).

     Kinds outside :data:`_HARNESS_SUPPORTED_KINDS` (synthetic
     fifth-kind canary in ``test_cli_test_harness.py::Section L``
     uses ``"workflow"``) are refused at the kind-narrowing gate
     with closed-enum :data:`harness_unsupported_pack_kind` — the
     defense-in-depth layer before per-kind dispatch routing. See
     bullet 4 for the no-transport-interception narrow.
  4. **Wave-1 narrow contract — no transport interception**
     (R33 P2 #1). The harness DOES NOT install
     ``httpx.MockTransport``, inject ``agentos_sdk.testing.
     fixture_settings``, scope environment variables, or sandbox
     filesystem / network access. ``_dry_run_invoke`` simply does
     ``cls() + await instance.invoke()`` against the unmodified
     host runtime — the closed-enum :data:`HarnessReason` literal
     has no ``harness_unsupported_live_transport``-style reason,
     and pack ``_invoke()`` code runs against whatever the host
     process exposes (real httpx / hvac / sqlalchemy / Langfuse
     clients hit their live targets). Pack authors who need
     fixture-adapter isolation wire it themselves via
     ``agentos_sdk.testing.fixture_settings`` /
     ``fixture_audit_capture`` in their pack test suite — the
     ``agentos test-harness`` command is the pre-publish sanity
     gate (validate pipeline + Tool.invoke dispatch + conformance
     report), NOT a sandbox. Earlier drafts of this bullet
     promised aspirational transport sandboxing that was never
     implemented; R33 P2 #1 narrowed the docstring + the
     plan-of-record (Doctrine Decision C bullets 3-4 +
     reference-pack lifecycle prose + test inventory + closeout
     criteria) to match the actual behavior. Transport
     interception is a future expansion alongside the kind-
     dispatch-table widening (Skill ToolRegistry, Agent
     TaskRecord+payload). The Wave-1 narrow is pinned as
     documentation-as-code by
     ``test_cli_test_harness.py::test_run_harness_wave1_narrow_contract_no_transport_interception``.
  5. Emit a conformance report covering identity / A2A / MCP /
     data-governance / risk-tier / supply-chain / dispatch dry-run.

Closed-enum vocabulary:

  - :data:`HarnessReason` — closed-enum literal of every refusal-
    severity reason the harness emits. Distinct from
    :class:`ValidatorReason` (the validate orchestrator's vocab) —
    the harness's reasons cover dispatch + entry-point + pyproject
    failure modes, separate from the manifest-validation surface.
    The drift detector in
    ``test_cli_test_harness.py::test_harness_reason_literal_exposes_every_seeded_reason``
    pins the exhaustive set; growth requires updating both sites.

  - :class:`HarnessFinding` — carrier dataclass, severity + reason +
    message + payload. Mirrors :class:`ValidatorFinding`'s shape so
    CI parsers can render harness + validate findings through the
    same pipeline.

Public surface:

  - :func:`run_harness` — pure function: builds + returns the
    :class:`HarnessReport` without side effects (no stdout / stderr /
    sys.exit). The Typer command wrapper renders the report +
    computes the exit code; pack-author tests can import and call
    this directly to build their own assertions.
  - :func:`format_report` — rendering helper. Default text mode
    emits one summary line + one annotation line per finding;
    ``--json`` mode emits a single JSON object on stdout.

Authoring/dev-only (R4 P3 #5): the harness is NOT on the
critical-controls per-file coverage floor (95/90), but it IS exercised
end-to-end by ``test_cli_test_harness.py`` against the T13 task-local
fixture pack at ``tests/fixtures/cli_harness_target_pack/``.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import importlib.util
import inspect
import json
import re
import sys
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final, Literal

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli.validate import _MANIFEST_FILENAME, run_validators
from cognic_agentos.packs.conformance import (
    run_owasp_conformance,
)
from cognic_agentos.protocol.a2a_endpoint import TaskRecord, TaskState
from cognic_agentos.sdk.hook import HookContext, HookResult
from cognic_agentos.sdk.registry import ToolRegistry
from cognic_agentos.sdk.tool import Tool

# ---------------------------------------------------------------------------
# Closed-enum HarnessReason vocabulary
# ---------------------------------------------------------------------------

#: Closed-enum literal of every refusal-severity reason
#: ``run_harness`` emits. Drift detector pins the exhaustive set in
#: ``test_cli_test_harness.py::test_harness_reason_literal_exposes_every_seeded_reason``.
HarnessReason = Literal[
    "harness_validate_refusals_block_dispatch",
    "harness_pyproject_not_found",
    "harness_pyproject_unparseable",
    "harness_no_entry_points_declared",
    "harness_entry_point_unresolvable",
    "harness_dispatch_failed",
    # Defense-in-depth refusal for kinds outside :data:`PackKind`.
    # Originally seeded at Sprint-7A T13/R31 P2 #2 to narrow Wave-1
    # dispatch to ``kind="tool"`` only; Sprint-7B.1 T6a widened the
    # supported set to the full :data:`PackKind` vocabulary so this
    # gate now fires only for synthetic / typo / malicious kinds
    # outside the closed-enum entirely (e.g. ``"workflow"``).
    "harness_unsupported_pack_kind",
]


#: Pack kinds the harness's dispatch path supports. Pinned in three-
#: way lockstep with :data:`_KIND_TO_ENTRY_POINT_GROUP` keys and
#: ``typing.get_args(PackKind)`` by the drift detector in
#: ``test_harness_vocabulary.py``. Kinds outside this frozenset are
#: refused at the kind-narrowing gate with closed-enum
#: ``harness_unsupported_pack_kind`` — defending downstream dispatch
#: from a generic AttributeError on a kind the dispatch table does
#: not understand. Sprint-7B.1 T6a widened the set from
#: ``frozenset({"tool"})`` to the full four-kind vocabulary; per-kind
#: dry-run dispatch impls land in T6b.
_HARNESS_SUPPORTED_KINDS: Final[frozenset[str]] = frozenset({"tool", "skill", "agent", "hook"})


#: Regex that every dotted-module-name segment in an entry-point
#: reference MUST match before the loader resolves the file path.
#: Rejects the load-bearing escape vectors:
#:
#:   - leading ``/`` (absolute path); when paired with
#:     ``Path(*module_path.split("."))`` would discard the pack root
#:     because the right-hand operand of ``/`` is absolute. Without
#:     this guard, a malicious pack could point ``cognic.tools`` at
#:     ``/etc/passwd_module:Bad`` and the loader would probe (and
#:     potentially load) host files outside the pack tree.
#:   - ``..`` traversal segments — Path collapse / normalization
#:     might escape via the parent dir.
#:   - empty segments / non-Python-identifier characters — anything
#:     that isn't a real Python module name.
#:
#: Defense layer 1 of 2; layer 2 is the resolve-and-relative-to
#: post-check in :func:`_load_entry_point_class` (catches symlink
#: targets that the regex doesn't see).
_MODULE_SEGMENT_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


#: Closed-enum mapping ``"tool" / "skill" / "agent" / "hook"`` → the
#: matching ``[project.entry-points."<group>"]`` table the harness
#: reads. Pinned here so a future migration that renames the groups
#: updates a single source of truth. Sprint-7B.1 T6a added the
#: ``"hook"`` arm pointing at ``cognic.hooks`` (Sprint-7A2 T9 wired
#: the ``cognic.hooks`` entry-point group through the wheel-integrity
#: kind-derivation table; T6a brought the harness's vocabulary to
#: match).
_KIND_TO_ENTRY_POINT_GROUP: Final[dict[str, str]] = {
    "tool": "cognic.tools",
    "skill": "cognic.skills",
    "agent": "cognic.agents",
    "hook": "cognic.hooks",
}


# ---------------------------------------------------------------------------
# Per-kind dispatch builders + constants (Sprint-7B.1 T6b)
# ---------------------------------------------------------------------------


#: Inert :class:`HookContext` fed to every hook dispatch dry-run. The
#: ``Hook.invoke`` public seam at ``sdk/hook.py:347`` validates this
#: against ``_validate_hook_context`` BEFORE ``_invoke`` runs. Module-
#: level so the Section-B pinning regression at
#: ``tests/unit/cli/test_harness_dispatch.py`` can monkeypatch to
#: ``None`` and pin the harness's routing of the resulting
#: ``HookContextError`` into ``harness_dispatch_failed`` +
#: ``failure_message`` containing the SDK exception class name.
_DISPATCH_HOOK_CONTEXT: HookContext = HookContext(
    hook_id="harness_dispatch_dry_run",
    phase="dlp_pre",
    pack_id="harness_dispatch",
    tenant_id="harness",
    request_id="harness-dispatch-dry-run",
    trace_id=None,
    parent_trace_id=None,
    manifest_data_classes=(),
    manifest_purpose="harness_dispatch_dry_run",
)


#: Inert payload bytes fed to every hook dispatch dry-run. Empty
#: bytes mirror the ADR-017 + Doctrine Lock E payload-never-logged
#: invariant by carrying no sensitive content. Module-level for the
#: same monkeypatch-to-``None`` pinning shape as
#: :data:`_DISPATCH_HOOK_CONTEXT`.
_DISPATCH_HOOK_PAYLOAD: bytes = b""


#: Inert agent payload bytes — same empty-bytes sentinel as
#: :data:`_DISPATCH_HOOK_PAYLOAD`. The reference agent's ``handle()``
#: ignores both ``payload`` + ``task``; pack authors writing real
#: agents key their behaviour off the A2A envelope bytes + cross-
#: check ``task.payload_digest`` against ``sha256(payload).hexdigest()``
#: (the A2A endpoint's contract at ``protocol/a2a_endpoint.py:436``
#: + ``:662``). Constant declared BEFORE
#: :data:`_DISPATCH_AGENT_TASK_RECORD` so the digest derivation
#: below reads it directly.
_DISPATCH_AGENT_PAYLOAD: bytes = b""


#: Inert :class:`TaskRecord` fed to every agent dispatch dry-run.
#: All 8 required fields populated with deterministic harness
#: sentinels; ``payload_digest`` is derived from
#: :data:`_DISPATCH_AGENT_PAYLOAD` via
#: ``hashlib.sha256(payload).hexdigest()`` to match the A2A
#: source-of-truth contract at ``protocol/a2a_endpoint.py:436`` +
#: ``:662``. The reference agent's ``handle()`` ignores the task
#: entirely (Wave-1 inert path), but pack authors writing real
#: agents that cross-check the envelope against the supplied
#: payload would refuse the call if this digest drifted; the
#: regression at
#: ``test_harness_dispatch.py::test_agent_dispatch_task_record_payload_digest_matches_payload``
#: pins the lockstep.
_DISPATCH_AGENT_TASK_RECORD: TaskRecord = TaskRecord(
    task_id="harness-dispatch-dry-run-task",
    target_agent="harness-dispatch",
    parent_trace_id="harness-dispatch-parent",
    child_trace_id="harness-dispatch-child",
    state=TaskState.CREATED,
    created_at=0.0,
    updated_at=0.0,
    payload_digest=hashlib.sha256(_DISPATCH_AGENT_PAYLOAD).hexdigest(),
)


#: Permissive input schema shared by every dynamically-constructed
#: harness no-op Tool subclass. ``additionalProperties: true`` lets
#: skill code call ``await tool.invoke(arbitrary_kwarg=...)`` without
#: crashing in the SDK's input-schema validation seam.
_HARNESS_NO_OP_TOOL_INPUT_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "additionalProperties": True,
}


#: Permissive output schema — paired with the empty-dict return value
#: of :func:`_harness_dispatch_no_op_invoke` so the SDK's output-
#: schema validation seam passes for any skill that calls a no-op
#: tool.
_HARNESS_NO_OP_TOOL_OUTPUT_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "additionalProperties": True,
}


async def _harness_dispatch_no_op_invoke(self: Tool, **kwargs: Any) -> dict[str, Any]:
    """Permissive no-op ``_invoke`` body bound to every dynamically-
    constructed harness no-op Tool subclass. Ignores ``self`` + any
    kwargs + returns the empty dict so the SDK's output-schema
    validation seam clears against
    :data:`_HARNESS_NO_OP_TOOL_OUTPUT_SCHEMA`."""
    del self, kwargs
    return {}


def _make_harness_no_op_tool_class(tool_name: str) -> type[Tool]:
    """Construct a :class:`Tool` subclass whose ``name`` ClassVar
    matches ``tool_name`` EXACTLY. Used by
    :class:`_HarnessFixtureNoOpToolRegistry` so a skill that reads
    ``self._tools.get(name).name`` sees the registered key as the
    tool's identity — mirroring the contract every real
    :class:`ToolRegistry` honors (each registered tool's ``name``
    matches the key it was registered under).

    Built via ``type(...)`` so the ``name`` / ``input_schema`` /
    ``output_schema`` ClassVars resolve at class-definition time +
    :meth:`Tool.__init_subclass__` runs its template-method
    validation seam (refuses ``invoke`` overrides in any ancestor
    other than ``Tool`` / ``object``). Each declared name gets its
    own subclass; subclass-cache isn't necessary because the
    registry instance keeps each subclass alive for the duration of
    a single dispatch dry-run + the harness pops the modules
    afterwards.
    """
    return type(
        f"_HarnessNoOpTool__{tool_name}",
        (Tool,),
        {
            "name": tool_name,
            "input_schema": _HARNESS_NO_OP_TOOL_INPUT_SCHEMA,
            "output_schema": _HARNESS_NO_OP_TOOL_OUTPUT_SCHEMA,
            "_invoke": _harness_dispatch_no_op_invoke,
        },
    )


class _HarnessFixtureNoOpToolRegistry:
    """Strict-membership ``ToolRegistry`` impl. Pre-builds one
    :class:`Tool` subclass per declared name in ``__init__`` so
    ``get(name)`` returns a Tool instance whose ``.name`` matches
    the requested key EXACTLY (R1 reviewer P3 — earlier draft
    returned a singleton ``_HarnessFixtureNoOpTool`` whose ``name``
    was a constant regardless of key; a future skill calling
    ``self._tools.get(name).name`` would have seen wrong identity).

    Strict-membership semantics: ``get(name)`` for any name outside
    ``declared`` raises ``KeyError`` — prevents future multi-tool
    skill drift from masking real ``Skill.__init__`` cross-check
    failures.
    """

    def __init__(self, *, declared: tuple[str, ...]) -> None:
        self._declared: frozenset[str] = frozenset(declared)
        self._tools: dict[str, Tool] = {
            tool_name: _make_harness_no_op_tool_class(tool_name)() for tool_name in declared
        }

    def list_tools(self) -> list[str]:
        return sorted(self._declared)

    def get(self, name: str) -> Tool:
        if name not in self._declared:
            raise KeyError(
                f"tool {name!r} is not registered; the harness's no-op "
                f"registry exposes only the skill's declared_tools "
                f"tuple. Declared: {sorted(self._declared)!r}."
            )
        return self._tools[name]


def _build_skill_tool_registry(skill_cls: type) -> ToolRegistry:
    """Construct a strict-membership ``ToolRegistry`` covering the
    skill class's ``declared_tools`` ClassVar. Derives the name set
    dynamically so future multi-tool skill packs (or single-tool
    packs that rename their declared tool) get a registry that
    exactly matches their declaration without drift.
    """
    declared_tools: tuple[str, ...] = tuple(getattr(skill_cls, "declared_tools", ()))
    return _HarnessFixtureNoOpToolRegistry(declared=declared_tools)


def _hook_result_to_safe_report_dict(result: HookResult) -> dict[str, Any]:
    """Convert :class:`HookResult` to a safe report dict that omits
    raw ``redacted_payload`` bytes per ADR-017 + Doctrine Lock E +
    the Sprint-7A2 T7 payload-never-logged invariant (pinned by the
    AST-walk regression at
    ``tests/architecture/test_hook_payload_never_logged.py``).

    Only safe metadata indicators cross the harness reporting
    boundary: ``decision`` (closed-enum string), ``policy_reason``
    (string or None), ``redacted_payload_present`` (bool indicator —
    NOT the bytes themselves), ``audit_metadata_keys`` (tuple of key
    names — NOT the values). The conformance report's
    ``response_keys`` derives from ``dict.keys()`` of this dict so the
    invariant holds end-to-end through the CLI's ``--json`` payload.
    """
    return {
        "decision": result.decision,
        "policy_reason": result.policy_reason,
        "redacted_payload_present": result.redacted_payload is not None,
        "audit_metadata_keys": tuple(result.audit_metadata.keys()),
    }


#: Closed-enum tuple of validate-pipeline concerns surfaced in the
#: conformance report's ``validate_summary`` field. Ordered to match
#: the per-concern validator dispatch order in
#: :func:`cognic_agentos.cli.validate.run_validators`.
_VALIDATE_CONCERNS: Final[tuple[str, ...]] = (
    "identity",
    "a2a",
    "mcp",
    "data_governance",
    "risk_tier",
    "supply_chain",
)


#: Mapping from the per-concern validator's reason prefix → the
#: concern name in the conformance report. Mirrors the
#: ``cli/_governance_vocab`` + per-validator ownership; pinned here
#: so :class:`HarnessReport.validate_summary` builds deterministically
#: from a finding's reason without re-reading
#: ``_VALIDATOR_REASON_OWNERSHIP``.
_REASON_PREFIX_TO_CONCERN: Final[tuple[tuple[str, str], ...]] = (
    ("identity_", "identity"),
    ("a2a_", "a2a"),
    ("mcp_", "mcp"),
    ("data_governance_", "data_governance"),
    ("risk_tier_", "risk_tier"),
    ("supply_chain_", "supply_chain"),
)


# ---------------------------------------------------------------------------
# Carrier dataclasses
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class HarnessFinding:
    """Carrier dataclass for refusals emitted by the harness.

    Mirrors :class:`cognic_agentos.cli.ValidatorFinding`'s shape +
    immutability discipline (frozen + slots; payload dict is
    shallowly mutable by convention but the orchestrator + render
    paths treat findings as logically read-only).
    """

    severity: Literal["refusal", "warning"]
    reason: HarnessReason
    message: str
    payload: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True, slots=True)
class DispatchOutcome:
    """Snapshot of a successful dispatch — recorded for the
    conformance report so pack authors can diff the response shape
    against their declared ``output_schema``."""

    response_keys: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class DispatchResult:
    """Per-entry-point dispatch outcome.

    ``status`` is one of:

      - ``"pass"`` — entry-point loaded + dispatch returned a
        schema-valid response. ``outcome`` is populated;
        ``failure_reason`` / ``failure_message`` are ``None``.
      - ``"fail"`` — entry-point failed to load OR dispatch raised.
        ``outcome`` is ``None``; ``failure_reason`` carries the
        closed-enum :data:`HarnessReason`; ``failure_message`` carries
        the human-readable detail.
    """

    entry_point_name: str
    entry_point_ref: str
    status: Literal["pass", "fail"]
    outcome: DispatchOutcome | None = None
    failure_reason: HarnessReason | None = None
    failure_message: str | None = None
    payload: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True, slots=True)
class ConformanceSummary:
    """OWASP conformance summary surfaced by the test-harness tail-call
    (Sprint-7B.2 T11). **Non-gating evidence per BUILD_PLAN §627** —
    populated only when validate + dispatch are green; the harness's
    ``overall_status`` is NOT flipped by a non-green conformance
    verdict. The Sprint-7B.3 5-gate composer owns the gating decision.

    Wire-shape field order (per ADR-006 evidence-pack-export readers):
    ``green`` / ``overall_status`` / ``findings``. Drift breaks JSON
    consumers reading by position / by-key.

    ``green`` mirrors ``overall_status == "green"`` for the trivial
    yes/no answer pack authors want from CI. ``findings`` is a flat
    list of ``"<category>: <finding-text>"`` strings (per-category
    findings from the OWASP matrix, prefixed for grep-ability)."""

    green: bool
    overall_status: Literal["green", "red", "yellow"]
    findings: list[str]


@dataclasses.dataclass(frozen=True, slots=True)
class HarnessReport:
    """Conformance report — the public T13 output shape.

    ``overall_status`` is ``"pass"`` iff:

      - ``validate_findings`` carries no refusal-severity entries.
      - ``findings`` (harness-side refusals) is empty.
      - Every :class:`DispatchResult` has ``status == "pass"``.

    ``conformance`` (Sprint-7B.2 T11) carries the OWASP matrix verdict
    when validate + dispatch are green; ``None`` when conformance was
    skipped because an earlier step failed. **NON-GATING** per
    BUILD_PLAN §627 — a non-green conformance verdict does NOT flip
    ``overall_status`` to ``"fail"``; it surfaces as evidence in the
    JSON / text output + as ``::warning::`` stderr annotations.
    """

    pack_path: str
    pack_id: str
    pack_kind: str
    overall_status: Literal["pass", "fail"]
    validate_findings: list[ValidatorFinding]
    validate_summary: dict[str, Literal["pass", "fail", "skipped"]]
    findings: list[HarnessFinding]
    dispatch_results: list[DispatchResult]
    conformance: ConformanceSummary | None = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _summarise_validate(
    findings: Iterable[ValidatorFinding],
) -> dict[str, Literal["pass", "fail", "skipped"]]:
    """Project the per-concern findings into a summary dict the
    conformance report carries. A concern is ``"fail"`` iff at least
    one refusal-severity finding's reason starts with the concern's
    prefix; otherwise ``"pass"``.

    Warnings DO NOT flip a concern to ``"fail"`` — the harness
    mirrors validate's severity-aware exit-code semantics
    (warnings render but do not affect status).
    """
    summary: dict[str, Literal["pass", "fail", "skipped"]] = dict.fromkeys(
        _VALIDATE_CONCERNS, "pass"
    )
    for finding in findings:
        if not finding.affects_exit_code:
            continue
        reason = finding.reason
        for prefix, concern in _REASON_PREFIX_TO_CONCERN:
            if reason.startswith(prefix):
                summary[concern] = "fail"
                break
    return summary


def _read_pack_id_and_kind(pack_path: Path) -> tuple[str, str]:
    """Extract the pack's ``[pack].pack_id`` + ``[pack].kind`` from
    its manifest. Used after :func:`run_validators` returns no
    refusals — the manifest is well-shaped at that point."""
    manifest_path = pack_path / _MANIFEST_FILENAME
    raw_bytes = manifest_path.read_bytes()
    data = tomllib.loads(raw_bytes.decode("utf-8"))
    pack_block = data.get("pack")
    if not isinstance(pack_block, dict):
        return ("", "")
    pack_id = pack_block.get("pack_id")
    kind = pack_block.get("kind")
    pack_id_str = pack_id if isinstance(pack_id, str) else ""
    kind_str = kind if isinstance(kind, str) else ""
    return (pack_id_str, kind_str)


def _read_full_manifest_dict(pack_path: Path) -> dict[str, Any]:
    """Read + parse the full manifest dict (Sprint-7B.2 T11).

    Used by the OWASP conformance tail-call after validate +
    dispatch are green. Returns ``{}`` if the manifest cannot be
    read / parsed — the conformance runner produces a non-green
    verdict for an empty manifest dict, which is the correct
    "evidence is missing" surface for the harness output. This
    helper does NOT raise — the seam contract of :func:`run_harness`
    promises never to raise from the conformance arm.
    """
    manifest_path = pack_path / _MANIFEST_FILENAME
    try:
        raw_bytes = manifest_path.read_bytes()
        data = tomllib.loads(raw_bytes.decode("utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _build_conformance_summary(pack_path: Path) -> ConformanceSummary:
    """Run :func:`run_owasp_conformance` against ``pack_path``'s
    manifest and project the report into a :class:`ConformanceSummary`.

    Sprint-7B.2 T11 tail-call (per plan §1282). Findings are
    flattened to ``"<category>: <finding-text>"`` strings so the
    JSON shape stays trivial + grep-able. Two sources contribute to
    the flattened findings list:

      1. **Red-path failures.** Per-category results with
         ``status == "fail"`` (the OWASP probe reported a manifest-
         shape problem).
      2. **Yellow-path checker exceptions** (R45 P2 #1 fix). The
         matrix's runner-loop wrapper at
         ``packs/conformance/owasp_agentic.run_owasp_conformance``
         synthesizes a ``status="not_applicable"`` result when a
         checker body raises (incomplete suite signal) AND appends
         the category to ``report.errored_categories``. Without
         surfacing these findings, a yellow verdict produces
         ``ConformanceSummary(overall_status="yellow", findings=[])``
         + zero ``::warning`` stderr annotations — pack authors lose
         the diagnostic that the suite is incomplete. The R45 fix
         iterates ``errored_categories`` AFTER the red-path loop so
         CI parsers consuming the warning annotations see the
         category-prefixed finding for every checker exception too.

    ``not_applicable`` results that came from the applicability
    matrix (NOT from a checker exception) are deliberately omitted
    — they represent "this check does not apply to this pack kind",
    not a failure or incompleteness signal.
    """
    manifest = _read_full_manifest_dict(pack_path)
    report = run_owasp_conformance(manifest)
    findings: list[str] = []
    for category, result in report.results.items():
        if result.status != "fail":
            continue
        for finding in result.findings:
            findings.append(f"{category}: {finding}")
    # R45 P2 #1: yellow / errored-category findings ALSO flow into
    # the surfaced list so the ::warning stderr annotations cover
    # incompleteness signals too. Order: red-path findings first
    # (registry order via ``report.results.items()``), then yellow-
    # path findings (registry order via ``report.errored_categories``).
    for category in report.errored_categories:
        errored_result = report.results.get(category)
        if errored_result is None:
            continue
        for finding in errored_result.findings:
            findings.append(f"{category}: {finding}")
    return ConformanceSummary(
        green=report.overall_status == "green",
        overall_status=report.overall_status,
        findings=findings,
    )


def _load_pyproject(
    pack_path: Path,
) -> tuple[dict[str, Any] | None, HarnessFinding | None]:
    """Read + parse ``pack_path / pyproject.toml``. Returns
    ``(parsed_dict, None)`` on success or ``(None, finding)`` on
    failure (closed-enum :data:`HarnessReason` per failure mode)."""
    pyproject_path = pack_path / "pyproject.toml"
    if not pyproject_path.is_file():
        return None, HarnessFinding(
            severity="refusal",
            reason="harness_pyproject_not_found",
            message=(
                f"pyproject.toml not found at {pyproject_path}. "
                "Pack authors who scaffolded with `agentos init-*` get "
                "this file by default; if you removed it, restore it "
                "before re-running the harness."
            ),
            payload={"pyproject_path": str(pyproject_path)},
        )
    try:
        raw_bytes = pyproject_path.read_bytes()
        parsed = tomllib.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return None, HarnessFinding(
            severity="refusal",
            reason="harness_pyproject_unparseable",
            message=(
                f"pyproject.toml at {pyproject_path} could not be decoded "
                f"+ parsed as TOML: {type(exc).__name__}: {exc}. Common "
                "cause is a stray hand-edit; re-scaffold from the bundled "
                "templates if the source of truth was lost."
            ),
            payload={
                "pyproject_path": str(pyproject_path),
                "error_type": type(exc).__name__,
            },
        )
    return parsed, None


def _extract_entry_points(
    pyproject: dict[str, Any],
    *,
    kind: str,
) -> dict[str, str]:
    """Return the ``{name: 'module:class'}`` entry-point map for the
    given pack kind. Empty dict if the matching group is absent or
    the value is not a TOML inline table."""
    group = _KIND_TO_ENTRY_POINT_GROUP.get(kind)
    if group is None:
        return {}
    project = pyproject.get("project")
    if not isinstance(project, dict):
        return {}
    entry_points = project.get("entry-points")
    if not isinstance(entry_points, dict):
        return {}
    group_block = entry_points.get(group)
    if not isinstance(group_block, dict):
        return {}
    # Drop any non-string values defensively — pack-author typos
    # shouldn't crash the harness mid-iteration.
    return {
        name: ref
        for name, ref in group_block.items()
        if isinstance(name, str) and isinstance(ref, str)
    }


def _load_entry_point_class(
    pack_path: Path,
    entry_point_ref: str,
) -> type:
    """Load a ``module.path:ClassName`` reference by reading from
    ``pack_path/src/``. Raises a descriptive exception on any
    failure mode (the caller wraps + collapses into a closed-enum
    refusal).

    The harness loader is filepath-based (NOT
    :func:`importlib.metadata.entry_points`) because Wave-1 fixture
    packs + scaffolded packs are not pip-installed when the harness
    runs — pack authors run ``agentos test-harness .`` from inside
    a working tree before publishing. The runtime MCP host (Sprint 5)
    uses ``importlib.metadata`` because admission only happens after
    a pack ships as a wheel + gets installed into the host process.

    Security boundary (R31 P2 #1 — entry-point ref escape):

      - **Layer 1 (segment validation).** Each dotted-module-name
        segment MUST match :data:`_MODULE_SEGMENT_PATTERN` (a Python
        identifier). Rejects leading-``/`` absolute paths,
        ``..`` traversal, path separators, empty segments, and
        any payload that would let
        ``Path(*module_path.split('.'))`` discard the pack root.
      - **Layer 2 (resolve-and-relative-to).** After computing the
        candidate module file under ``pack_path/src``, resolve it
        and verify ``is_relative_to(src_root.resolve())``. Catches
        symlink-target escapes that the regex doesn't see.

    sys.path + sys.modules stewardship lives in the caller
    (:func:`_dispatch_one`) so the import context spans BOTH the
    class-load phase here AND the dispatch invocation that runs
    afterward (R31 P2 #3 — lazy intra-pack imports inside
    ``_invoke()`` need ``pack/src`` on sys.path during dispatch).
    """
    module_path, _, class_name = entry_point_ref.partition(":")
    if not module_path or not class_name:
        raise ValueError(
            f"entry-point reference {entry_point_ref!r} is not in 'module.path:ClassName' form"
        )

    # Layer-1 defense (R31 P2 #1): segment validation. Reject any
    # module-path segment that isn't a Python identifier — fastest
    # check, catches the load-bearing leading-``/`` absolute-path
    # attack at parse time before the filesystem is touched.
    segments = module_path.split(".")
    for seg in segments:
        if not _MODULE_SEGMENT_PATTERN.match(seg):
            raise ValueError(
                f"entry-point reference {entry_point_ref!r}: module segment "
                f"{seg!r} is not a valid Python identifier (rejected before "
                "filesystem resolution to prevent escaping the pack src tree)"
            )

    src_root = pack_path / "src"
    relative_module_file = Path(*segments).with_suffix(".py")
    module_file = src_root / relative_module_file
    if not module_file.is_file():
        # Fallback: try ``module.path/__init__.py`` for package-style
        # references whose last segment is the package itself.
        package_init = src_root / Path(*segments) / "__init__.py"
        if package_init.is_file():
            module_file = package_init
        else:
            raise FileNotFoundError(
                f"module file for {module_path!r} not found at {module_file} "
                f"(also tried {package_init})"
            )

    # Layer-2 defense (R31 P2 #1): resolve + verify the chosen
    # module file stays under the resolved src root. Catches
    # symlink-target escapes that the regex layer doesn't see —
    # a symlink under ``pack/src/<id>.py`` whose target is outside
    # the pack tree resolves OUTSIDE the src root, and we refuse.
    # ``OSError`` / ``RuntimeError`` from ``Path.resolve()`` (e.g.,
    # symlink-loop on POSIX errno 62/40) collapse into the same
    # ValueError → caller surfaces ``harness_entry_point_unresolvable``.
    try:
        src_root_resolved = src_root.resolve()
        module_file_resolved = module_file.resolve()
    except (OSError, RuntimeError) as exc:
        raise ValueError(
            f"could not resolve module file {module_file}: {type(exc).__name__}: {exc}"
        ) from exc
    if not module_file_resolved.is_relative_to(src_root_resolved):
        raise ValueError(
            f"module file {module_file} resolves to {module_file_resolved} "
            f"which is outside the pack src root {src_root_resolved} — "
            "refusing to load (would escape the pack tree via symlink "
            "or other indirection)"
        )

    # R32 P2 #2 — sys.modules collision pre-check. Refuse loading
    # any entry-point whose module name is already present in
    # ``sys.modules``. Without this guard, the loader assignment
    # at ``sys.modules[module_path] = module`` would temporarily
    # overwrite a host-loaded module (a stdlib name like ``json``,
    # an installed dependency, or another pack's module from a
    # prior harness invocation that wasn't cleaned up correctly).
    # The exec_module-failure pop below would then DELETE the host
    # entry entirely (the prior version of this module replaced
    # ``sys.modules["json"]`` with a synthetic, then on
    # ``__init_subclass__``-style failure popped it — leaving the
    # host's stdlib ``json`` gone). Pre-check + reject is the
    # load-bearing fix; the in-process harness MUST NOT mutate
    # host interpreter state under any failure mode.
    if module_path in sys.modules:
        raise ValueError(
            f"entry-point reference {entry_point_ref!r}: module name "
            f"{module_path!r} is already present in sys.modules — "
            "refusing to overwrite. Pack authors MUST use module names "
            "unique to their pack (the canonical scaffold pattern is "
            "``cognic_<kind>_<pack_name>``); colliding with a stdlib "
            "or already-installed module name would corrupt the host "
            "interpreter for the duration of the harness run."
        )

    spec = importlib.util.spec_from_file_location(module_path, module_file)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not build importlib spec for {module_path!r} at {module_file}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_path] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_path, None)
        raise
    if not hasattr(module, class_name):
        raise AttributeError(
            f"module {module_path!r} (loaded from {module_file}) does not "
            f"define class {class_name!r}"
        )
    cls = getattr(module, class_name)
    if not inspect.isclass(cls):
        raise TypeError(
            f"{module_path}:{class_name} resolved to a non-class object ({type(cls).__name__})"
        )
    return cls


async def _dry_run_invoke(cls: type, *, pack_kind: str) -> dict[str, Any]:
    """Per-kind dispatch dry-run. Routes on ``pack_kind`` to the
    public SDK seam for each kind (Sprint-7B.1 T6b widening; pre-T6b
    this function was Tool-only).

    Per-kind dispatch contracts (all public SDK seams; private
    ``_invoke`` paths are NEVER called directly so SDK validators
    fire):

      - ``"tool"`` — ``cls() + await instance.invoke()`` against
        ``Tool.invoke`` template-method seam at ``sdk/tool.py:144``
        (validates kwargs against input_schema + result against
        output_schema).
      - ``"skill"`` — ``cls(tools=<no-op-registry>) +
        await skill.execute()`` against the Skill cross-check seam
        at ``sdk/skill.py:73`` (R5 P2 #3 — validates declared_tools
        against registry list_tools()).
      - ``"agent"`` — ``cls() + await agent.handle(payload, task=
        <inert TaskRecord>)`` against the Agent abstract method at
        ``sdk/agent.py:52-77``.
      - ``"hook"`` — ``cls() + await hook.invoke(context, payload)``
        against the PUBLIC seam at ``sdk/hook.py:347`` (NOT the
        abstract ``_invoke`` at ``sdk/hook.py:373``). Hook.invoke
        runs three SDK validation phases: pre-``_invoke`` context
        + pre-``_invoke`` payload (sdk/hook.py:221-241) + post-
        ``_invoke`` result-shape (sdk/hook.py:244-288).

    Return value is the per-kind dispatch result coerced to a dict
    so ``DispatchOutcome.response_keys`` derives uniformly. For
    hook kind, :func:`_hook_result_to_safe_report_dict` strips the
    raw ``redacted_payload`` bytes per ADR-017 + Doctrine Lock E
    payload-never-logged invariant.
    """
    if pack_kind == "tool":
        tool_instance = cls()
        tool_result: dict[str, Any] = await tool_instance.invoke()
        return tool_result
    if pack_kind == "skill":
        skill_instance = cls(tools=_build_skill_tool_registry(cls))
        skill_result: dict[str, Any] = await skill_instance.execute()
        return skill_result
    if pack_kind == "agent":
        agent_instance = cls()
        agent_result: dict[str, Any] = await agent_instance.handle(
            _DISPATCH_AGENT_PAYLOAD,
            task=_DISPATCH_AGENT_TASK_RECORD,
        )
        return agent_result
    if pack_kind == "hook":
        hook_instance = cls()
        hook_result: HookResult = await hook_instance.invoke(
            _DISPATCH_HOOK_CONTEXT,
            _DISPATCH_HOOK_PAYLOAD,
        )
        return _hook_result_to_safe_report_dict(hook_result)
    # Unreachable in practice — the Step 1.5 kind-narrowing gate at
    # :func:`run_harness` refuses kinds outside :data:`PackKind`
    # BEFORE dispatch. This branch is defense-in-depth: a future
    # refactor that bypasses the Step 1.5 gate gets a deterministic
    # failure rather than silently calling an undefined SDK seam.
    raise ValueError(
        f"_dry_run_invoke received unsupported pack_kind {pack_kind!r}; "
        f"the Step 1.5 kind-narrowing gate at run_harness should have "
        f"refused this kind before dispatch."
    )


def _dispatch_one(
    pack_path: Path,
    *,
    name: str,
    entry_point_ref: str,
    pack_kind: str,
) -> DispatchResult:
    """Run the dispatch dry-run for a single entry-point declaration.
    Closed-enum refusal mapping:

      - Module file missing / class missing / segment-validation
        failure / symlink escape → ``harness_entry_point_unresolvable``.
      - Instantiation / invoke raised → ``harness_dispatch_failed`` with
        ``error_type`` recording the exception class.

    sys.path + sys.modules stewardship (R31 P2 #3):

      - ``pack/src`` is inserted into sys.path BEFORE the class
        load AND held there ACROSS the dispatch invocation. Lazy
        intra-pack imports inside ``_invoke()`` (e.g.,
        ``from <pack>.helper import VALUE``) resolve cleanly —
        without this, a pack that worked when pip-installed
        would fail under the harness.
      - A snapshot of ``sys.modules`` taken at dispatch entry is
        used to pop every newly-added key on exit (success OR
        failure). Without this discipline, repeated in-process
        harness invocations would see stale package state across
        runs (silently-cached old class objects).

    R32 P2 #1 reviewer correction: an earlier R31 wrap covered
    ``Path.resolve()`` inside :func:`_load_entry_point_class` but
    the eager resolve of ``pack_path / "src"`` here ran BEFORE
    the try/finally guard — so a pack with ``src -> src`` (or
    any filesystem condition that makes ``Path.resolve()`` raise)
    leaked ``OSError`` / ``RuntimeError`` straight out of
    :func:`run_harness` with a Python traceback. Same defensive
    doctrine T12 R29 codified for the supply_chain validator's
    path-check seam: filesystem syscalls in user-facing paths
    MUST collapse into closed-enum refusals, never tracebacks.
    """
    # R32 P2 #1: resolve the pack's src directory inside a guarded
    # try/except. A self-referential symlink (``src -> src``) or
    # any other condition that makes ``Path.resolve()`` raise
    # surfaces as a per-slot ``harness_entry_point_unresolvable``
    # refusal with ``payload.error_type`` recording the exception
    # class.
    try:
        src_dir = str((pack_path / "src").resolve())
    except (OSError, RuntimeError) as exc:
        return DispatchResult(
            entry_point_name=name,
            entry_point_ref=entry_point_ref,
            status="fail",
            failure_reason="harness_entry_point_unresolvable",
            failure_message=(
                f"entry-point {name!r} ({entry_point_ref!r}) — could not "
                f"resolve pack src directory at {pack_path / 'src'}: "
                f"{type(exc).__name__}: {exc}. Common cause is a self-"
                "referential symlink at the pack's src directory; "
                "remove the broken link and re-run "
                "`agentos test-harness <pack>`."
            ),
            payload={"error_type": type(exc).__name__},
        )
    inserted_src = False
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)
        inserted_src = True
    modules_snapshot = set(sys.modules.keys())
    try:
        # Phase 1: load the entry-point class.
        try:
            cls = _load_entry_point_class(pack_path, entry_point_ref)
        except (
            FileNotFoundError,
            ImportError,
            AttributeError,
            TypeError,
            ValueError,
        ) as exc:
            return DispatchResult(
                entry_point_name=name,
                entry_point_ref=entry_point_ref,
                status="fail",
                failure_reason="harness_entry_point_unresolvable",
                failure_message=(
                    f"entry-point {name!r} ({entry_point_ref!r}) could not be "
                    f"loaded: {type(exc).__name__}: {exc}"
                ),
                payload={"error_type": type(exc).__name__},
            )

        # Phase 2: dispatch dry-run. sys.path + module context preserved
        # so ``_invoke`` can do lazy intra-pack imports.
        # Local import — keep top-level import section clean.
        import asyncio

        try:
            result = asyncio.run(_dry_run_invoke(cls, pack_kind=pack_kind))
        except Exception as exc:
            return DispatchResult(
                entry_point_name=name,
                entry_point_ref=entry_point_ref,
                status="fail",
                failure_reason="harness_dispatch_failed",
                failure_message=(
                    f"dispatch of {name!r} ({entry_point_ref!r}) raised {type(exc).__name__}: {exc}"
                ),
                payload={"error_type": type(exc).__name__},
            )

        response_keys = tuple(result.keys()) if isinstance(result, dict) else ()
        return DispatchResult(
            entry_point_name=name,
            entry_point_ref=entry_point_ref,
            status="pass",
            outcome=DispatchOutcome(response_keys=response_keys),
        )
    finally:
        # Restore sys.modules: pop every key added during this
        # dispatch cycle (covers both the entry-point class module
        # AND any transitive imports it triggered, including lazy
        # intra-pack imports done inside ``_invoke``).
        added_modules = set(sys.modules.keys()) - modules_snapshot
        for added_key in added_modules:
            sys.modules.pop(added_key, None)
        if inserted_src:
            with contextlib.suppress(ValueError):
                sys.path.remove(src_dir)


# ---------------------------------------------------------------------------
# Public API: run_harness
# ---------------------------------------------------------------------------


def run_harness(pack_path: Path) -> HarnessReport:
    """Build + return the :class:`HarnessReport` for ``pack_path``.

    Pure function: never writes to stdout / stderr, never calls
    ``sys.exit``. The Typer wrapper renders the report + computes
    the exit code; pack-author tests can assert against the report
    object directly.

    Pipeline:

      1. Run :func:`run_validators`. If any refusals fire, emit
         ``harness_validate_refusals_block_dispatch`` + skip dispatch.
      2. Read ``pyproject.toml``; failure modes
         ``harness_pyproject_not_found`` /
         ``harness_pyproject_unparseable``.
      3. Extract the matching ``cognic.<kind>s`` entry-point group
         from ``pyproject.toml``; empty group →
         ``harness_no_entry_points_declared``.
      4. For each declared entry-point, load + dispatch via
         :func:`_dispatch_one`. Per-slot failures land in the
         dispatch results list; harness-level findings stay empty
         once dispatch starts.
    """
    findings: list[HarnessFinding] = []
    validate_findings = run_validators(pack_path)
    validate_summary = _summarise_validate(validate_findings)

    # Step 1: validate-refusal short-circuit. If validate refused,
    # dispatch cannot run — harness-side refusal carries a single
    # finding that flags the dispatch skip; the validate findings
    # list carries the underlying detail.
    has_validate_refusals = any(f.affects_exit_code for f in validate_findings)
    if has_validate_refusals:
        findings.append(
            HarnessFinding(
                severity="refusal",
                reason="harness_validate_refusals_block_dispatch",
                message=(
                    f"agentos validate emitted "
                    f"{sum(1 for f in validate_findings if f.affects_exit_code)} "
                    "refusal(s); the harness skips dispatch dry-run until the "
                    "manifest validates clean. Run `agentos validate <pack>` "
                    "for the per-concern remediation copy."
                ),
                payload={"pack_path": str(pack_path)},
            )
        )
        # Pack id / kind cannot be extracted reliably without a
        # well-shaped manifest; default to empty strings for the
        # report so the carrier shape stays stable.
        pack_id, pack_kind = "", ""
        # If the manifest was at least parseable enough to read pack
        # block, fill those in for diagnostic richness.
        manifest_path = pack_path / _MANIFEST_FILENAME
        if manifest_path.is_file():
            try:
                pack_id, pack_kind = _read_pack_id_and_kind(pack_path)
            except (UnicodeDecodeError, tomllib.TOMLDecodeError, OSError):
                pack_id, pack_kind = "", ""
        return HarnessReport(
            pack_path=str(pack_path),
            pack_id=pack_id,
            pack_kind=pack_kind,
            overall_status="fail",
            validate_findings=validate_findings,
            validate_summary=validate_summary,
            findings=findings,
            dispatch_results=[],
        )

    # Validate clean — read the pack identity for the report header.
    pack_id, pack_kind = _read_pack_id_and_kind(pack_path)

    # Step 1.5: kind-narrowing gate — defense-in-depth for kinds
    # outside :data:`_HARNESS_SUPPORTED_KINDS`. Originally seeded at
    # Sprint-7A T13/R31 P2 #2 to narrow Wave-1 dispatch to
    # ``kind="tool"`` only; Sprint-7B.1 T6a widened the supported set
    # to the full :data:`PackKind` vocabulary, so this gate now fires
    # only for kinds outside the closed-enum entirely (synthetic /
    # typo / malicious manifests with e.g. ``kind="workflow"``).
    # ``cli/sign.py:_VALID_PACK_KINDS`` refuses unknown kinds up-front
    # in the full author lifecycle, but :func:`run_harness` is also
    # called via direct integration against unsigned packs — the gate
    # is the runtime last line of defense to keep a generic dispatch-
    # table AttributeError from surfacing for a kind the table does
    # not understand.
    if pack_kind not in _HARNESS_SUPPORTED_KINDS:
        findings.append(
            HarnessFinding(
                severity="refusal",
                reason="harness_unsupported_pack_kind",
                message=(
                    f"pack kind {pack_kind!r} is not a member of the harness's "
                    f"supported-kinds closed enum "
                    f"{sorted(_HARNESS_SUPPORTED_KINDS)!r}. Common causes: a "
                    "typo in the manifest's [pack].kind field, or a manifest "
                    "from a future / experimental pack format that this "
                    "harness build does not yet support. Update [pack].kind "
                    "to one of the supported values + re-run the harness."
                ),
                payload={
                    "pack_path": str(pack_path),
                    "pack_kind": pack_kind,
                    "supported_kinds": sorted(_HARNESS_SUPPORTED_KINDS),
                },
            )
        )
        return HarnessReport(
            pack_path=str(pack_path),
            pack_id=pack_id,
            pack_kind=pack_kind,
            overall_status="fail",
            validate_findings=validate_findings,
            validate_summary=validate_summary,
            findings=findings,
            dispatch_results=[],
        )

    # Step 2: pyproject.toml.
    pyproject, pyproject_finding = _load_pyproject(pack_path)
    if pyproject_finding is not None:
        findings.append(pyproject_finding)
        return HarnessReport(
            pack_path=str(pack_path),
            pack_id=pack_id,
            pack_kind=pack_kind,
            overall_status="fail",
            validate_findings=validate_findings,
            validate_summary=validate_summary,
            findings=findings,
            dispatch_results=[],
        )
    assert pyproject is not None  # type-narrow for downstream

    # Step 3: entry-point group.
    entry_points = _extract_entry_points(pyproject, kind=pack_kind)
    if not entry_points:
        group = _KIND_TO_ENTRY_POINT_GROUP.get(pack_kind, "<unknown-kind>")
        findings.append(
            HarnessFinding(
                severity="refusal",
                reason="harness_no_entry_points_declared",
                message=(
                    f"pyproject.toml at {pack_path / 'pyproject.toml'} "
                    f"declares no entry-points under "
                    f'[project.entry-points."{group}"]. Pack authors '
                    "who scaffolded via `agentos init-*` get one entry "
                    "by default; restore it (or add yours) before "
                    "re-running the harness."
                ),
                payload={
                    "pyproject_path": str(pack_path / "pyproject.toml"),
                    "expected_group": group,
                },
            )
        )
        return HarnessReport(
            pack_path=str(pack_path),
            pack_id=pack_id,
            pack_kind=pack_kind,
            overall_status="fail",
            validate_findings=validate_findings,
            validate_summary=validate_summary,
            findings=findings,
            dispatch_results=[],
        )

    # Step 4: per-entry-point dispatch dry-run.
    dispatch_results: list[DispatchResult] = []
    for name, ref in entry_points.items():
        dispatch_results.append(
            _dispatch_one(pack_path, name=name, entry_point_ref=ref, pack_kind=pack_kind)
        )

    # Step 5: OWASP conformance tail-call (Sprint-7B.2 T11). Fires
    # only when validate + dispatch are green; skipped otherwise so
    # the conformance arm doesn't produce noise against a pack that
    # is already failing at an earlier gate. NON-GATING per
    # BUILD_PLAN §627: a non-green verdict surfaces in
    # ``HarnessReport.conformance`` + stderr ``::warning::`` lines but
    # does NOT flip ``overall_status`` to ``"fail"``. The Sprint-7B.3
    # 5-gate composer owns the gating decision; the test-harness
    # produces evidence, not a gate signal.
    conformance: ConformanceSummary | None = None
    dispatch_all_pass = all(r.status == "pass" for r in dispatch_results)
    if not findings and dispatch_all_pass:
        conformance = _build_conformance_summary(pack_path)

    overall_status: Literal["pass", "fail"] = (
        "pass" if not findings and dispatch_all_pass else "fail"
    )
    return HarnessReport(
        pack_path=str(pack_path),
        pack_id=pack_id,
        pack_kind=pack_kind,
        overall_status=overall_status,
        validate_findings=validate_findings,
        validate_summary=validate_summary,
        findings=findings,
        dispatch_results=dispatch_results,
        conformance=conformance,
    )


# ---------------------------------------------------------------------------
# Public API: format_report
# ---------------------------------------------------------------------------


def _build_report_payload(report: HarnessReport) -> dict[str, Any]:
    """Build the deterministic JSON payload for ``--json`` mode.
    Extracted so the JSON shape stays single-sourced + testable.

    The ``conformance`` key (Sprint-7B.2 T11) is ``None`` when the
    OWASP tail-call was skipped (earlier step failed), or the 3-key
    summary dict (``green`` / ``overall_status`` / ``findings``)
    when it ran. Wire-shape field order matches
    :class:`ConformanceSummary` per ADR-006."""
    conformance: dict[str, Any] | None = None
    if report.conformance is not None:
        conformance = {
            "green": report.conformance.green,
            "overall_status": report.conformance.overall_status,
            "findings": list(report.conformance.findings),
        }
    return {
        "pack_path": report.pack_path,
        "pack_id": report.pack_id,
        "pack_kind": report.pack_kind,
        "overall_status": report.overall_status,
        "validate_findings": [
            {
                "severity": f.severity,
                "reason": f.reason,
                "message": f.message,
                "payload": f.payload,
            }
            for f in report.validate_findings
        ],
        "validate_summary": report.validate_summary,
        "findings": [
            {
                "severity": f.severity,
                "reason": f.reason,
                "message": f.message,
                "payload": f.payload,
            }
            for f in report.findings
        ],
        "dispatch_results": [
            {
                "entry_point_name": r.entry_point_name,
                "entry_point_ref": r.entry_point_ref,
                "status": r.status,
                "outcome": (
                    {"response_keys": list(r.outcome.response_keys)}
                    if r.outcome is not None
                    else None
                ),
                "failure_reason": r.failure_reason,
                "failure_message": r.failure_message,
                "payload": r.payload,
            }
            for r in report.dispatch_results
        ],
        "conformance": conformance,
    }


def format_report_summary(report: HarnessReport) -> str:
    """Render the harness summary for stdout (text mode).

    Emits the overall pass/fail header + per-concern validate
    summary + per-dispatch-slot status. Error annotations go to
    :func:`format_report_finding_annotations` (stderr-bound) so
    the stdout shape stays clean for ``| grep PASS``-style
    pack-author CI checks.
    """
    lines: list[str] = []
    status_label = "PASS" if report.overall_status == "pass" else "FAIL"
    lines.append(f"test-harness: {status_label} ({report.pack_path})")
    lines.append(f"  pack_id={report.pack_id!r} kind={report.pack_kind!r}")
    for concern in _VALIDATE_CONCERNS:
        lines.append(f"  validate.{concern}: {report.validate_summary.get(concern, 'skipped')}")
    for r in report.dispatch_results:
        if r.status == "pass" and r.outcome is not None:
            keys = ",".join(r.outcome.response_keys) or "<none>"
            lines.append(f"  dispatch.{r.entry_point_name}: pass (response_keys={keys})")
        else:
            lines.append(
                f"  dispatch.{r.entry_point_name}: fail ({r.failure_reason}: {r.failure_message})"
            )
    # Conformance verdict line (Sprint-7B.2 T11). Surfaces only when
    # the OWASP tail-call ran (non-None conformance summary). The
    # "non-gating" doctrine means the verdict can be non-green while
    # the harness overall is PASS — the verdict line makes that
    # distinction visible to pack authors scanning the summary.
    if report.conformance is not None:
        finding_count = len(report.conformance.findings)
        lines.append(
            f"  conformance: {report.conformance.overall_status} "
            f"(green={report.conformance.green}, findings={finding_count})"
        )
    return "\n".join(lines)


def format_report_finding_annotations(report: HarnessReport) -> list[str]:
    """Render harness-level findings + validate refusals + failed
    dispatch results as one GH-Actions-style annotation per line.
    Caller writes these to stderr (mirrors validate's stderr-bound
    annotation pattern at T6).

    R31 P3 reviewer correction: an earlier draft skipped failed
    DispatchResults here, surfacing them ONLY in the stdout summary.
    A broken entry-point exited 1 with an empty stderr, so CI parsers
    consuming the validate-style ``::error`` stream missed the actual
    harness failure reason. The fix appends one annotation per
    failed dispatch slot — same closed-enum reason format the rest
    of the validator stack uses.
    """
    lines: list[str] = []
    for vf in report.validate_findings:
        if not vf.affects_exit_code:
            continue
        lines.append(f"::error file={report.pack_path}::{vf.reason}: {vf.message}")
    for hf in report.findings:
        lines.append(f"::error file={report.pack_path}::{hf.reason}: {hf.message}")
    for r in report.dispatch_results:
        if r.status != "pass" and r.failure_reason is not None:
            lines.append(
                f"::error file={report.pack_path}::{r.failure_reason}: "
                f"dispatch.{r.entry_point_name} ({r.entry_point_ref}) — "
                f"{r.failure_message}"
            )
    # Conformance findings emit ``::warning::`` annotations (Sprint-7B.2 T11).
    # Per the non-gating doctrine, OWASP failures are warnings (not
    # errors) — they render to stderr so CI parsers can see the
    # signal but they do NOT affect exit code. Mirrors the validate-
    # side warning-severity pattern at
    # ``cli/__init__.py:ValidatorFinding`` (e.g.,
    # ``identity_oasf_capability_set_missing``).
    if report.conformance is not None:
        for finding in report.conformance.findings:
            lines.append(f"::warning file={report.pack_path}::conformance: {finding}")
    return lines


def format_report(report: HarnessReport, *, json_output: bool) -> str:
    """JSON-mode renderer used by ``agentos test-harness --json``.

    For text mode, the Typer wrapper composes
    :func:`format_report_summary` (stdout) +
    :func:`format_report_finding_annotations` (stderr) so the
    stdout / stderr split matches validate's pattern at T6.
    """
    if json_output:
        return json.dumps(_build_report_payload(report), sort_keys=True)
    # Text mode: caller is expected to use the split helpers; this
    # unified path stitches them together for callers that want a
    # single text blob (kept narrow + thin so the stdout-only
    # contract isn't accidentally re-introduced).
    summary = format_report_summary(report)
    annotations = format_report_finding_annotations(report)
    if not annotations:
        return summary
    return "\n".join([summary, *annotations])


__all__ = [
    "ConformanceSummary",
    "DispatchOutcome",
    "DispatchResult",
    "HarnessFinding",
    "HarnessReason",
    "HarnessReport",
    "format_report",
    "format_report_finding_annotations",
    "format_report_summary",
    "run_harness",
]
