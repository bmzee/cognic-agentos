"""M8 A8 (ADR-027) — `[agent]` block + `AGENT.md` per-concern validator.

Validates the M8 governed-agent authoring surface at build time, mirroring the
runtime hosting contract at ``harness/agent_host.py`` +
``protocol/agent_manifest.py`` so a pack that validates clean here is a pack
the boot-time loader will actually host:

  - the manifest ``[agent]`` block (canonical top-level) / legacy
    ``[tool.cognic.agent]`` (R23 dual-path doctrine — a pack declaring both
    gets validated against both, refusals carrying ``payload.block_path``);
  - ``persona_path`` — the pack-relative path to the ``AGENT.md`` persona
    (absent → the conventional ``"AGENT.md"`` default). Validated per the
    identity.py resolve-then-validate path discipline (reject absolute +
    ``..`` + backslash BEFORE resolve; then resolve; then containment under
    the pack root) and the FILE is parse+shape-validated AT BUILD TIME via
    the REUSED skill_manifest frontmatter contract (``parse_skill_md`` /
    ``validate_skill_md`` — the same wire contract AGENT.md shares with
    SKILL.md; not forked);
  - ``requested_skills`` — the persona's requested skill_id ceiling (the
    grant-not-requested ingestion invariant's upper bound per ADR-027 §3.1);
    shape / id-syntax / dedupe validated per the data_governance DLP-hook-
    list pattern (skill_ids are agentskills.io labels — lowercase
    alphanumerics + internal hyphens, 1-64 chars);
  - ``requested_tools`` — ``<server_id>/<tool_name>`` two-segment identities
    (the same first-``/``-partition rule the runtime applies; a tool_name
    containing further slashes is representable and accepted);
  - ``max_steps`` — OPTIONAL int in 1..32 (``bool`` is NOT an int here).

**Kind gating.** The ``[agent]`` block is MANDATORY on ``kind = "agent"``
packs (``agent_manifest_block_missing``). A NON-agent pack declaring an
``[agent]`` block is VALIDATED, not kind-constraint-refused — mirroring
``validators/skills.py`` (block presence fires the arms for every kind).
The orchestrator-owned ``agent_pack_kind_constraint_violated`` (emitted by
``cli/validate.py``) covers a different dimension: the ``[mcp]``
block-presence check on agent packs (``[a2a]`` stays LEGAL — agent packs
are A2A-speaking by design).

Closed-enum reasons emitted by this validator (5; sub-cases ride
``payload.failure_mode``):

  - ``agent_manifest_block_missing`` — ``block_absent`` (kind="agent" with
    no block at either path) / ``block_not_table``.
  - ``agent_manifest_persona_path_invalid`` — ``value_invalid`` (non-string /
    empty / AUTHOR-FILL) / ``absolute_path_rejected`` /
    ``path_escape_rejected`` / ``file_not_found`` / ``not_valid_agent_md``
    (parse or shape failure; the protocol ``SkillMdValidationReason`` rides
    ``payload.agent_md_reason``).
  - ``agent_manifest_requested_skills_invalid`` — ``invalid_shape`` /
    ``invalid_skill_id`` / ``duplicate``.
  - ``agent_manifest_requested_tools_invalid`` — ``invalid_shape`` /
    ``invalid_tool_identity`` / ``duplicate``.
  - ``agent_manifest_max_steps_invalid`` (present-but-not-int-1..32).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Final

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.protocol.skill_manifest import (
    SkillManifestInvalid,
    parse_skill_md,
    validate_skill_md,
)

#: Closed-enum block-locations checked (R23 dual-path doctrine — mirrors
#: validators/skills.py + the runtime block reader at
#: ``harness/agent_host._agent_block``).
_AGENT_BLOCK_LOCATIONS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("agent", ("agent",)),
    ("tool.cognic.agent", ("tool", "cognic", "agent")),
)

#: The conventional persona filename; an ABSENT ``persona_path`` validates
#: this default so the scaffold's minimal block stays valid.
_DEFAULT_PERSONA_PATH: Final[str] = "AGENT.md"

#: AUTHOR-FILL placeholder prefix (the T7/T10/T11/T12 doctrine).
_AUTHOR_FILL_PREFIX: Final[str] = "AUTHOR-FILL"

#: skill_id label shape — the agentskills.io ``name`` regex (a LOCAL copy of
#: ``protocol.skill_manifest._NAME_RE`` per the drift-detector-test-only
#: doctrine; requested_skills entries reference SKILL.md ``name`` values).
_SKILL_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$")

#: ``max_steps`` closed bounds (ADR-027 — the run-level step ceiling).
_MAX_STEPS_MIN: Final[int] = 1
_MAX_STEPS_MAX: Final[int] = 32


def _resolve_path(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    """Walk ``path`` through ``data``; return the leaf if every intermediate
    step resolves to a dict, otherwise ``None``. Non-dict LEAVES are returned
    as-is so ``agent = "x"`` surfaces as ``block_not_table`` rather than
    masking as absent (mirrors validators/skills.py)."""
    cursor: Any = data
    for segment in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(segment)
    return cursor


def _pack_kind(data: dict[str, Any]) -> str | None:
    """``[pack].kind`` as a string (or ``None`` if missing / non-string)."""
    pack_block = data.get("pack")
    if not isinstance(pack_block, dict):
        return None
    kind = pack_block.get("kind")
    return kind if isinstance(kind, str) else None


def _persona_finding(
    failure_mode: str, message: str, *, block_path: str, **extra: Any
) -> ValidatorFinding:
    return ValidatorFinding(
        severity="refusal",
        reason="agent_manifest_persona_path_invalid",
        message=message,
        payload={"block_path": block_path, "failure_mode": failure_mode, **extra},
    )


def _validate_persona_path(
    block: dict[str, Any], *, block_path: str, pack_path: Path
) -> list[ValidatorFinding]:
    """Resolve-then-validate the persona path + parse/shape-validate the file
    AT BUILD TIME (per the identity.py `_check_jws_path_resolves` discipline,
    tightened by the pre-resolve ``..`` / backslash rejection): (1) reject
    hostile syntax BEFORE any resolve; (2) resolve; (3) require containment
    under the pack root; (4) require the file exists; (5) parse + validate
    the AGENT.md via the reused skill_manifest frontmatter contract."""
    raw = block.get("persona_path", _DEFAULT_PERSONA_PATH)
    if not isinstance(raw, str) or not raw.strip() or raw.strip().startswith(_AUTHOR_FILL_PREFIX):
        return [
            _persona_finding(
                "value_invalid",
                f"[{block_path}].persona_path is missing a usable value "
                f"(got {raw!r}); declare a pack-relative path to the AGENT.md "
                "persona (conventionally 'AGENT.md').",
                block_path=block_path,
                declared_value=raw if isinstance(raw, str) else str(raw),
            )
        ]
    candidate = Path(raw)
    if candidate.is_absolute():
        return [
            _persona_finding(
                "absolute_path_rejected",
                f"[{block_path}].persona_path declares {raw!r} which is an "
                "absolute path; only pack-relative paths are accepted — an "
                "absolute path could route the persona reader at files outside "
                "the published pack.",
                block_path=block_path,
                declared_path=raw,
            )
        ]
    if ".." in candidate.parts or "\\" in raw:
        # Rejected BEFORE resolve() per the resolve-then-validate discipline —
        # traversal syntax never reaches path resolution.
        return [
            _persona_finding(
                "path_escape_rejected",
                f"[{block_path}].persona_path declares {raw!r} which carries "
                "'..' traversal or a backslash; path escapes are rejected "
                "before resolution to keep the persona reader scoped to the "
                "published pack.",
                block_path=block_path,
                declared_path=raw,
            )
        ]
    pack_root_resolved = pack_path.resolve()
    persona_full_path = (pack_path / raw).resolve()
    if not persona_full_path.is_relative_to(pack_root_resolved):
        return [
            _persona_finding(
                "path_escape_rejected",
                f"[{block_path}].persona_path declares {raw!r} which resolves "
                f"to {persona_full_path} — outside the pack root at "
                f"{pack_root_resolved}. Escaping resolutions (e.g. through a "
                "symlink) fail closed.",
                block_path=block_path,
                declared_path=raw,
                resolved_path=str(persona_full_path),
            )
        ]
    if not persona_full_path.is_file():
        return [
            _persona_finding(
                "file_not_found",
                f"[{block_path}].persona_path declares {raw!r} but no file "
                f"exists at {persona_full_path}. The runtime hosting layer "
                "reads the persona at boot; it MUST ship in the pack.",
                block_path=block_path,
                declared_path=raw,
                resolved_path=str(persona_full_path),
            )
        ]
    try:
        text = persona_full_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [
            _persona_finding(
                "not_valid_agent_md",
                f"AGENT.md at {persona_full_path} could not be read as UTF-8 "
                f"text: {type(exc).__name__}.",
                block_path=block_path,
                declared_path=raw,
                error_type=type(exc).__name__,
            )
        ]
    try:
        frontmatter, body = parse_skill_md(text)
        validate_skill_md(frontmatter, body=body)
    except SkillManifestInvalid as exc:
        return [
            _persona_finding(
                "not_valid_agent_md",
                f"AGENT.md at {persona_full_path} fails the persona frontmatter "
                f"shape ({exc.reason}); the runtime hosting layer would "
                "warn-skip this pack at boot.",
                block_path=block_path,
                declared_path=raw,
                agent_md_reason=exc.reason,
            )
        ]
    return []


def _validate_requested_skills(block: dict[str, Any], *, block_path: str) -> list[ValidatorFinding]:
    """OPTIONAL ``requested_skills`` — shape / id-syntax / dedupe per the
    data_governance DLP-hook-list pattern. Absence + the empty list are
    silent (an agent may request no skills)."""
    if "requested_skills" not in block:
        return []
    raw = block["requested_skills"]

    def _finding(failure_mode: str, message: str, **extra: Any) -> ValidatorFinding:
        return ValidatorFinding(
            severity="refusal",
            reason="agent_manifest_requested_skills_invalid",
            message=message,
            payload={"block_path": block_path, "failure_mode": failure_mode, **extra},
        )

    if not isinstance(raw, list) or not all(isinstance(entry, str) for entry in raw):
        return [
            _finding(
                "invalid_shape",
                f"[{block_path}].requested_skills must be a list of skill_id "
                f"strings (got {raw!r}); each entry is a SKILL.md 'name' label "
                "the assignment store resolves at runtime.",
                invalid_value=raw,
            )
        ]
    findings: list[ValidatorFinding] = []
    for index, entry in enumerate(raw):
        if not _SKILL_ID_RE.fullmatch(entry):
            findings.append(
                _finding(
                    "invalid_skill_id",
                    f"[{block_path}].requested_skills[{index}] = {entry!r} is "
                    "not a valid skill_id label (lowercase alphanumerics + "
                    "internal hyphens, 1-64 chars — the agentskills.io name "
                    "shape SKILL.md enforces).",
                    invalid_value=entry,
                    index=index,
                )
            )
    seen: set[str] = set()
    duplicates_reported: set[str] = set()
    for entry in raw:
        if entry in seen and entry not in duplicates_reported:
            findings.append(
                _finding(
                    "duplicate",
                    f"[{block_path}].requested_skills declares {entry!r} more "
                    "than once. Each requested skill_id MUST appear at most "
                    "once; remove the duplicate(s).",
                    duplicate_value=entry,
                )
            )
            duplicates_reported.add(entry)
        seen.add(entry)
    return findings


def _validate_requested_tools(block: dict[str, Any], *, block_path: str) -> list[ValidatorFinding]:
    """OPTIONAL ``requested_tools`` — ``<server_id>/<tool_name>`` two-segment
    identities (the runtime first-``/``-partition rule) + dedupe. Absence +
    the empty list are silent."""
    if "requested_tools" not in block:
        return []
    raw = block["requested_tools"]

    def _finding(failure_mode: str, message: str, **extra: Any) -> ValidatorFinding:
        return ValidatorFinding(
            severity="refusal",
            reason="agent_manifest_requested_tools_invalid",
            message=message,
            payload={"block_path": block_path, "failure_mode": failure_mode, **extra},
        )

    if not isinstance(raw, list) or not all(isinstance(entry, str) for entry in raw):
        return [
            _finding(
                "invalid_shape",
                f"[{block_path}].requested_tools must be a list of "
                f"'<server_id>/<tool_name>' identity strings (got {raw!r}).",
                invalid_value=raw,
            )
        ]
    findings: list[ValidatorFinding] = []
    for index, entry in enumerate(raw):
        server_id, _, tool_name = entry.partition("/")
        if not server_id or not tool_name:
            findings.append(
                _finding(
                    "invalid_tool_identity",
                    f"[{block_path}].requested_tools[{index}] = {entry!r} is "
                    "not a '<server_id>/<tool_name>' identity (both halves of "
                    "the first-'/'-split must be non-empty — the same "
                    "partition rule the runtime applies).",
                    invalid_value=entry,
                    index=index,
                )
            )
    seen: set[str] = set()
    duplicates_reported: set[str] = set()
    for entry in raw:
        if entry in seen and entry not in duplicates_reported:
            findings.append(
                _finding(
                    "duplicate",
                    f"[{block_path}].requested_tools declares {entry!r} more "
                    "than once. Each requested tool identity MUST appear at "
                    "most once; remove the duplicate(s).",
                    duplicate_value=entry,
                )
            )
            duplicates_reported.add(entry)
        seen.add(entry)
    return findings


def _validate_max_steps(block: dict[str, Any], *, block_path: str) -> list[ValidatorFinding]:
    """OPTIONAL ``max_steps`` — int in 1..32 when present; ``bool`` is NOT an
    int here (True/1 aliasing would silently legalise a boolean)."""
    if "max_steps" not in block:
        return []
    raw = block["max_steps"]
    if (
        isinstance(raw, bool)
        or not isinstance(raw, int)
        or not (_MAX_STEPS_MIN <= raw <= _MAX_STEPS_MAX)
    ):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="agent_manifest_max_steps_invalid",
                message=(
                    f"[{block_path}].max_steps = {raw!r} is not an integer in "
                    f"{_MAX_STEPS_MIN}..{_MAX_STEPS_MAX} (bool is not an int "
                    "here); omit the field to inherit the kernel default."
                ),
                payload={
                    "block_path": block_path,
                    "declared_value": raw if isinstance(raw, int | float | str) else str(raw),
                },
            )
        ]
    return []


def _validate_agent_block(
    block: Any, *, block_path: str, pack_path: Path
) -> list[ValidatorFinding]:
    """Validate one ``[agent]`` block (canonical or legacy)."""
    if not isinstance(block, dict):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="agent_manifest_block_missing",
                message=(
                    f"manifest declares [{block_path}] but the value is "
                    f"{type(block).__name__}; expected a TOML table."
                ),
                payload={"block_path": block_path, "failure_mode": "block_not_table"},
            )
        ]
    findings: list[ValidatorFinding] = []
    findings.extend(_validate_persona_path(block, block_path=block_path, pack_path=pack_path))
    findings.extend(_validate_requested_skills(block, block_path=block_path))
    findings.extend(_validate_requested_tools(block, block_path=block_path))
    findings.extend(_validate_max_steps(block, block_path=block_path))
    return findings


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Validate the M8 governed-agent authoring surface (see the module
    docstring for the kind-gating contract).

    Returns the aggregated findings list (refusal-severity only — this
    validator has no warning paths).
    """
    located_blocks: list[tuple[str, Any]] = []
    for prefix, accessor in _AGENT_BLOCK_LOCATIONS:
        block = _resolve_path(data, accessor)
        if block is not None:
            located_blocks.append((prefix, block))

    if not located_blocks:
        if _pack_kind(data) == "agent":
            # The block is MANDATORY on agent packs: a persona-less agent
            # pack can never be hosted (the loader resolves the AGENT.md +
            # requested sets through it) — refuse at build time.
            return [
                ValidatorFinding(
                    severity="refusal",
                    reason="agent_manifest_block_missing",
                    message=(
                        "pack kind is 'agent' but the manifest declares no "
                        "[agent] block (canonical) or [tool.cognic.agent] "
                        "(legacy); the runtime hosting layer resolves the "
                        "persona + requested capability sets through this "
                        "block, so the pack would never be hosted."
                    ),
                    payload={"block_path": "agent", "failure_mode": "block_absent"},
                )
            ]
        return []

    findings: list[ValidatorFinding] = []
    for prefix, block in located_blocks:
        findings.extend(_validate_agent_block(block, block_path=prefix, pack_path=pack_path))
    return findings


__all__ = ["validate"]
