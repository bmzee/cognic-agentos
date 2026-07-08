"""M6 A9 (ADR-025) — `[skill]` block + `SKILL.md` per-concern validator.

Validates the M6 governed-executable-skill authoring surface at build time,
mirroring the runtime hosting contract at ``harness/skill_host.py`` +
``protocol/skill_manifest.py`` so a pack that validates clean here is a pack
the boot-time loader will actually host:

  - the manifest ``[skill]`` block (canonical top-level) / legacy
    ``[tool.cognic.skill]`` (R23 dual-path doctrine — a pack declaring both
    gets validated against both, refusals carrying ``payload.block_path``);
  - the agentskills.io ``SKILL.md`` at the PACK ROOT (the scaffold's
    force-include maps it into the wheel's package data where
    ``protocol.skill_manifest.extract_skill_md`` reads it) — parse +
    shape validation is DELEGATED to ``protocol.skill_manifest``
    (``parse_skill_md`` / ``validate_skill_md``; the ``cli → protocol``
    import arrow is established — ``cli/sign.py`` + ``cli/verify.py``
    already import ``cognic_agentos.protocol.*``), and the protocol's
    closed-enum ``SkillMdValidationReason`` rides ``payload.failure_mode``
    per the established disambiguation pattern;
  - the ``[skill].declared_tools`` list of ``<server_id>/<tool_name>`` MCP
    tool identities. The identity rule is PARTITION-aligned with the runtime
    enforcement (``core/skill/broker.py:272`` + ``harness/skill_host.py:99``
    both use ``str.partition("/")``): the FIRST ``/`` splits and both halves
    must be non-empty — a ``tool_name`` containing further slashes is
    representable at runtime and therefore accepted here (the build-time
    rule never refuses what the runtime would host);
  - the ``cognic.skills`` entry-point cross-check: the pack's pyproject MUST
    declare EXACTLY ONE ``[project.entry-points."cognic.skills"]`` entry
    (``harness/skill_host._skill_entry_point_info`` fail-closes on
    ``len(eps) != 1`` — zero AND ambiguous mappings both warn-skip at boot).

**Intent gating (Wave-1 narrow).** The runtime hosting layer treats
``[skill]``-block PRESENCE as the executable-skill intent signal — it never
consults ``[pack].kind``. This validator mirrors that exactly, widened by one
authoring-error signal: intent := a ``[skill]`` block at either path OR a
``SKILL.md`` file at the pack root.

  * intent present → the full arm set fires (block shape + declared_tools +
    SKILL.md + entry-point cross-check) for EVERY pack kind. A non-skill
    pack declaring ``[skill]`` is validated, not kind-constraint-refused —
    mirroring ``validators/hooks.py`` (non-hook packs declaring ``[hooks]``
    are validated) and the runtime loader (which would attempt to host any
    pack whose manifest carries the block). No orchestrator-owned
    forbidden-block constraint exists for ``[skill]`` today.
  * intent absent → SILENT for every kind INCLUDING ``kind = "skill"``.
    Deliberate: ``kind = "skill"`` predates M6 (the Sprint-7A SDK
    ``Skill.execute()`` composition kind — e.g. the reference pack at
    ``examples/cognic-skill-example-minimal`` ships neither a ``[skill]``
    block nor a ``SKILL.md`` and remains valid). Requiring the M6 artifacts
    on every ``kind="skill"`` pack would refuse every legacy skill pack; the
    M6 executable-skill surface is opt-in by declaring the block (or
    shipping a SKILL.md — the "wrote one half, forgot the other" author
    error is caught in BOTH directions).

**Instruction-only mode (M8 A7, ADR-027).** ``[skill].mode`` selects the
hosting shape: ABSENT → ``"executable"`` (every pre-A7 pack byte-unchanged);
``"instruction"`` hosts the SKILL.md guidance with NO executable surface —
the declared_tools requirement and the exactly-one entry-point cross-check
are SKIPPED, and the INVERSE rules fire instead (declaring truthy
``declared_tools`` / any ``cognic.skills`` entry point refuses; the runtime
loader would warn-skip such a pack at boot). The optional
``[skill].referenced_tools`` list is non-authoritative reviewer evidence:
shape-validated wherever present (either mode), and a shape-clean non-empty
list surfaces ONE warning-severity finding (build time cannot verify the
entries against a live registered-MCP set — cross-pack resolution is a
runtime concern, mirroring the data_governance DLP-hook doctrine).

Closed-enum reasons emitted by this validator (9; sub-cases ride
``payload.failure_mode``):

  - ``skill_manifest_block_shape_invalid`` —
    ``block_missing_for_skill_intent`` (SKILL.md present, no block) /
    ``block_not_table`` / ``mode_invalid`` (M8 A7 — out-of-vocabulary
    ``[skill].mode`` value).
  - ``skill_manifest_skill_md_missing`` — ``file_absent`` / ``file_blank``.
  - ``skill_manifest_skill_md_invalid`` — the protocol
    ``SkillMdValidationReason`` values (``skill_md_frontmatter_malformed`` /
    ``skill_md_name_invalid`` / ``skill_md_description_invalid`` /
    ``skill_md_description_too_long`` / ``skill_md_body_empty``) plus the
    CLI-only ``file_unreadable`` + ``description_author_fill`` (build-time
    AUTHOR-FILL hygiene per the identity/supply_chain doctrine — the
    runtime hosting validator accepts any string <= 1024 chars).
  - ``skill_manifest_declared_tools_invalid`` — ``field_absent`` /
    ``not_a_list`` / ``list_empty`` / ``entry_not_a_string`` /
    ``entry_author_fill`` / ``entry_identity_malformed`` /
    ``entry_duplicate``.
  - ``skill_manifest_entry_point_mismatch`` — ``pyproject_unparseable`` /
    ``entry_point_absent`` / ``entry_point_ambiguous``.
  - ``skill_manifest_instruction_mode_declares_tools`` (M8 A7) —
    ``declared_tools_present`` (truthy declared_tools on an
    instruction-mode block; the empty list stays legal — partition-aligned
    with the runtime loader's truthiness rule).
  - ``skill_manifest_instruction_mode_has_entry_point`` (M8 A7) —
    ``entry_point_present``.
  - ``skill_manifest_referenced_tools_invalid`` (M8 A7) — ``not_a_list`` /
    ``entry_not_a_string`` / ``entry_author_fill`` /
    ``entry_identity_malformed`` / ``entry_duplicate``.
  - ``skill_manifest_referenced_tool_unverifiable`` (M8 A7 — the
    validator's ONLY warning severity; joins ``_WARNING_REASONS``).
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Final

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.protocol.skill_manifest import (
    SkillManifestInvalid,
    parse_skill_md,
    validate_skill_md,
)

#: Closed-enum block-locations checked. Mirrors the R23 dual-path doctrine
#: (canonical top-level + legacy ``[tool.cognic.<block>]``) used by
#: validators/hooks.py AND the runtime block reader at
#: ``harness/skill_host._skill_block``.
_SKILL_BLOCK_LOCATIONS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("skill", ("skill",)),
    ("tool.cognic.skill", ("tool", "cognic", "skill")),
)

#: The agentskills.io artifact filename at the pack root.
_SKILL_MD_FILENAME: Final[str] = "SKILL.md"

#: Prefix that marks an unfilled ``AUTHOR-FILL: ...`` placeholder from the
#: T5/M6 scaffold templates; entries carrying it are refused as unfilled.
#: Mirrors the T7/T10/T11/T12 AUTHOR-FILL doctrine.
_AUTHOR_FILL_PREFIX: Final[str] = "AUTHOR-FILL"

#: M8 A7 (ADR-027) — the closed ``[skill].mode`` vocabulary. ABSENT defaults
#: to ``"executable"`` (every pre-A7 pack byte-unchanged); mirrors the runtime
#: reader at ``harness/skill_host._skill_mode``.
_SKILL_MODES: Final[frozenset[str]] = frozenset({"executable", "instruction"})


def _block_mode(block: dict[str, Any]) -> str | None:
    """``[skill].mode`` with the ABSENT → ``"executable"`` default; ``None``
    on an out-of-vocabulary / non-string value (surfaced as
    ``skill_manifest_block_shape_invalid`` + ``failure_mode="mode_invalid"``)."""
    raw = block.get("mode", "executable")
    if isinstance(raw, str) and raw in _SKILL_MODES:
        return raw
    return None


def _resolve_path(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    """Walk ``path`` through ``data``; return the leaf if every intermediate
    step resolves to a dict, otherwise ``None``. Non-dict LEAVES are
    returned as-is so ``skill = "x"`` surfaces as ``block_not_table``
    rather than masking as absent."""
    cursor: Any = data
    for segment in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(segment)
    return cursor


def _validate_declared_tools(
    block: dict[str, Any],
    *,
    block_path: str,
) -> list[ValidatorFinding]:
    """Validate ``[skill].declared_tools`` against the runtime identity rule
    (partition-aligned; see the module docstring) + build-time hygiene
    (AUTHOR-FILL / duplicates). One finding per offending entry."""

    def _finding(failure_mode: str, message: str, **extra: Any) -> ValidatorFinding:
        return ValidatorFinding(
            severity="refusal",
            reason="skill_manifest_declared_tools_invalid",
            message=message,
            payload={"block_path": block_path, "failure_mode": failure_mode, **extra},
        )

    if "declared_tools" not in block:
        return [
            _finding(
                "field_absent",
                f"[{block_path}] is missing the 'declared_tools' field; every M6 "
                "skill pack MUST declare the MCP tool identities its sandboxed "
                "action may call through the kernel-side broker.",
            )
        ]
    raw = block["declared_tools"]
    if not isinstance(raw, list):
        return [
            _finding(
                "not_a_list",
                f"[{block_path}].declared_tools is {type(raw).__name__}; expected a "
                "TOML array of '<server_id>/<tool_name>' identity strings.",
            )
        ]
    if not raw:
        return [
            _finding(
                "list_empty",
                f"[{block_path}].declared_tools is empty; a skill that calls no "
                "tools has nothing for the broker to govern — declare at least "
                "one '<server_id>/<tool_name>' identity.",
            )
        ]
    findings: list[ValidatorFinding] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw):
        if not isinstance(entry, str):
            findings.append(
                _finding(
                    "entry_not_a_string",
                    f"[{block_path}].declared_tools[{index}] is "
                    f"{type(entry).__name__}; expected a "
                    "'<server_id>/<tool_name>' identity string.",
                    entry_index=index,
                )
            )
            continue
        if entry.strip().startswith(_AUTHOR_FILL_PREFIX):
            # Checked BEFORE the identity-shape rule: the scaffold's hint
            # copy carries a slash inside the AUTHOR-FILL text, so the
            # partition rule alone would accept it silently.
            findings.append(
                _finding(
                    "entry_author_fill",
                    f"[{block_path}].declared_tools[{index}] is still an "
                    "AUTHOR-FILL placeholder; replace it with a real "
                    "'<server_id>/<tool_name>' identity.",
                    entry_index=index,
                )
            )
            continue
        server_id, _, tool_name = entry.partition("/")
        if not server_id or not tool_name:
            findings.append(
                _finding(
                    "entry_identity_malformed",
                    f"[{block_path}].declared_tools[{index}] = {entry!r} is not a "
                    "'<server_id>/<tool_name>' identity (both halves of the "
                    "first-'/'-split must be non-empty — the same partition "
                    "rule the runtime broker enforces).",
                    entry_index=index,
                    declared_value=entry,
                )
            )
            continue
        if entry in seen:
            findings.append(
                _finding(
                    "entry_duplicate",
                    f"[{block_path}].declared_tools[{index}] = {entry!r} "
                    "duplicates an earlier entry in the same block. Each "
                    "declared identity MUST be unique.",
                    entry_index=index,
                    declared_value=entry,
                )
            )
            continue
        seen.add(entry)
    return findings


def _validate_referenced_tools(
    block: dict[str, Any],
    *,
    block_path: str,
) -> list[ValidatorFinding]:
    """M8 A7 (ADR-027) — validate the optional ``[skill].referenced_tools``
    reviewer-evidence list wherever it is present (either mode). Absence and
    the empty list are silent. Shape violations refuse
    (``skill_manifest_referenced_tools_invalid``); a shape-clean non-empty
    list surfaces ONE warning-severity
    ``skill_manifest_referenced_tool_unverifiable`` finding — build time has
    no registered-MCP set to resolve the entries against (cross-pack
    resolution is a runtime concern; the boot loader warn-logs unregistered
    references, never refuses)."""
    if "referenced_tools" not in block:
        return []
    raw = block["referenced_tools"]

    def _finding(failure_mode: str, message: str, **extra: Any) -> ValidatorFinding:
        return ValidatorFinding(
            severity="refusal",
            reason="skill_manifest_referenced_tools_invalid",
            message=message,
            payload={"block_path": block_path, "failure_mode": failure_mode, **extra},
        )

    if not isinstance(raw, list):
        return [
            _finding(
                "not_a_list",
                f"[{block_path}].referenced_tools is {type(raw).__name__}; expected "
                "a TOML array of '<server_id>/<tool_name>' identity strings "
                "(non-authoritative reviewer evidence for instruction skills).",
            )
        ]
    findings: list[ValidatorFinding] = []
    seen: set[str] = set()
    for index, entry in enumerate(raw):
        if not isinstance(entry, str):
            findings.append(
                _finding(
                    "entry_not_a_string",
                    f"[{block_path}].referenced_tools[{index}] is "
                    f"{type(entry).__name__}; expected a "
                    "'<server_id>/<tool_name>' identity string.",
                    entry_index=index,
                )
            )
            continue
        if entry.strip().startswith(_AUTHOR_FILL_PREFIX):
            findings.append(
                _finding(
                    "entry_author_fill",
                    f"[{block_path}].referenced_tools[{index}] is still an "
                    "AUTHOR-FILL placeholder; replace it with a real "
                    "'<server_id>/<tool_name>' identity or remove it.",
                    entry_index=index,
                )
            )
            continue
        server_id, _, tool_name = entry.partition("/")
        if not server_id or not tool_name:
            findings.append(
                _finding(
                    "entry_identity_malformed",
                    f"[{block_path}].referenced_tools[{index}] = {entry!r} is not a "
                    "'<server_id>/<tool_name>' identity (both halves of the "
                    "first-'/'-split must be non-empty — the same partition "
                    "rule the runtime loader applies).",
                    entry_index=index,
                    declared_value=entry,
                )
            )
            continue
        if entry in seen:
            findings.append(
                _finding(
                    "entry_duplicate",
                    f"[{block_path}].referenced_tools[{index}] = {entry!r} "
                    "duplicates an earlier entry in the same block. Each "
                    "referenced identity MUST be unique.",
                    entry_index=index,
                    declared_value=entry,
                )
            )
            continue
        seen.add(entry)
    if not findings and seen:
        findings.append(
            ValidatorFinding(
                severity="warning",
                reason="skill_manifest_referenced_tool_unverifiable",
                message=(
                    f"[{block_path}].referenced_tools entries cannot be verified "
                    "against a registered-MCP-server set at build time; the "
                    "runtime hosting layer warn-logs unregistered references at "
                    "boot. Reviewers should treat the list as non-authoritative "
                    "evidence of the tools this skill's instructions mention."
                ),
                payload={
                    "block_path": block_path,
                    "referenced_tools": sorted(seen),
                },
            )
        )
    return findings


def _validate_skill_block(
    block: Any,
    *,
    block_path: str,
) -> list[ValidatorFinding]:
    """Validate one ``[skill]`` block (canonical or legacy) — mode-aware per
    M8 A7: the executable arm is byte-identical to the pre-A7 behavior; the
    instruction arm swaps the declared_tools requirement for the inverse
    no-executable-surface rule."""
    if not isinstance(block, dict):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="skill_manifest_block_shape_invalid",
                message=(
                    f"manifest declares [{block_path}] but the value is "
                    f"{type(block).__name__}; expected a TOML table."
                ),
                payload={"block_path": block_path, "failure_mode": "block_not_table"},
            )
        ]
    mode = _block_mode(block)
    if mode is None:
        return [
            ValidatorFinding(
                severity="refusal",
                reason="skill_manifest_block_shape_invalid",
                message=(
                    f"[{block_path}].mode = {block.get('mode')!r} is not in the "
                    "closed vocabulary {'executable', 'instruction'}; the "
                    "runtime hosting layer would warn-skip this pack at boot."
                ),
                payload={
                    "block_path": block_path,
                    "failure_mode": "mode_invalid",
                    "declared_value": block.get("mode"),
                },
            )
        ]
    findings: list[ValidatorFinding] = []
    if mode == "instruction":
        # Truthiness (not presence) is the executable-surface signal —
        # partition-aligned with the runtime loader (an empty list hosts).
        if block.get("declared_tools"):
            findings.append(
                ValidatorFinding(
                    severity="refusal",
                    reason="skill_manifest_instruction_mode_declares_tools",
                    message=(
                        f"[{block_path}] declares mode = 'instruction' AND a "
                        "non-empty declared_tools list; instruction skills host "
                        "SKILL.md guidance only — no broker-governed tool "
                        "authority. Use referenced_tools for non-authoritative "
                        "reviewer evidence, or switch to mode = 'executable'."
                    ),
                    payload={
                        "block_path": block_path,
                        "failure_mode": "declared_tools_present",
                    },
                )
            )
    else:
        findings.extend(_validate_declared_tools(block, block_path=block_path))
    findings.extend(_validate_referenced_tools(block, block_path=block_path))
    return findings


def _validate_skill_md(pack_path: Path) -> list[ValidatorFinding]:
    """Validate the pack-root ``SKILL.md`` — presence, then the agentskills.io
    shape via the protocol validators, then build-time AUTHOR-FILL hygiene.
    First failure per file (the protocol validators raise on the first
    violation, mirroring the runtime warn-skip granularity)."""
    skill_md_path = pack_path / _SKILL_MD_FILENAME

    def _missing(failure_mode: str, message: str) -> ValidatorFinding:
        return ValidatorFinding(
            severity="refusal",
            reason="skill_manifest_skill_md_missing",
            message=message,
            payload={"skill_md_path": str(skill_md_path), "failure_mode": failure_mode},
        )

    def _invalid(failure_mode: str, message: str, **extra: Any) -> ValidatorFinding:
        return ValidatorFinding(
            severity="refusal",
            reason="skill_manifest_skill_md_invalid",
            message=message,
            payload={
                "skill_md_path": str(skill_md_path),
                "failure_mode": failure_mode,
                **extra,
            },
        )

    if not skill_md_path.is_file():
        return [
            _missing(
                "file_absent",
                f"SKILL.md not found at {skill_md_path}; every M6 skill pack "
                "ships the agentskills.io SKILL.md at the pack root (the "
                "scaffold's force-include maps it into the wheel's package "
                "data for the runtime hosting layer).",
            )
        ]
    try:
        text = skill_md_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return [
            _invalid(
                "file_unreadable",
                f"SKILL.md at {skill_md_path} could not be read as UTF-8 text: "
                f"{type(exc).__name__}.",
                error_type=type(exc).__name__,
            )
        ]
    if not text.strip():
        return [
            _missing(
                "file_blank",
                f"SKILL.md at {skill_md_path} is blank; the agentskills.io "
                "artifact needs frontmatter (name + description) and a "
                "non-empty instructions body.",
            )
        ]
    try:
        frontmatter, body = parse_skill_md(text)
        validate_skill_md(frontmatter, body=body)
    except SkillManifestInvalid as exc:
        # Translate the protocol closed-enum reason into the CLI reason;
        # payload.failure_mode carries the protocol value (established
        # disambiguation pattern).
        return [
            _invalid(
                exc.reason,
                f"SKILL.md at {skill_md_path} fails the agentskills.io shape "
                f"({exc.reason}); the runtime hosting layer would warn-skip "
                "this pack at boot.",
            )
        ]
    description = frontmatter.get("description")
    if isinstance(description, str) and description.strip().startswith(_AUTHOR_FILL_PREFIX):
        return [
            _invalid(
                "description_author_fill",
                f"SKILL.md at {skill_md_path} still carries the AUTHOR-FILL "
                "description placeholder; replace it with a real one-sentence "
                "summary (<= 1024 chars).",
            )
        ]
    return []


def _entry_point_mismatch_finding(
    pyproject_path: Path, failure_mode: str, message: str, **extra: Any
) -> ValidatorFinding:
    return ValidatorFinding(
        severity="refusal",
        reason="skill_manifest_entry_point_mismatch",
        message=message,
        payload={
            "pyproject_path": str(pyproject_path),
            "failure_mode": failure_mode,
            **extra,
        },
    )


def _load_skill_entry_point_names(
    pack_path: Path,
) -> tuple[list[str] | None, list[ValidatorFinding]]:
    """Shared pyproject reader for BOTH entry-point rules (the executable
    exactly-one cross-check + the M8 A7 instruction-mode no-entry-point
    inverse). Returns ``(sorted names, [])`` on a parseable pyproject, or
    ``(None, [pyproject_unparseable finding])`` — an unreadable pyproject
    fails closed in either mode because neither invariant can be verified."""
    pyproject_path = pack_path / "pyproject.toml"
    if not pyproject_path.is_file():
        return None, [
            _entry_point_mismatch_finding(
                pyproject_path,
                "pyproject_unparseable",
                f"pyproject.toml not found at {pyproject_path}; the validator "
                "cannot cross-check the cognic.skills entry-point declaration.",
                error_type="FileNotFoundError",
            )
        ]
    try:
        pyproject_data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, OSError) as exc:
        return None, [
            _entry_point_mismatch_finding(
                pyproject_path,
                "pyproject_unparseable",
                f"pyproject.toml at {pyproject_path} could not be parsed: "
                f"{type(exc).__name__}: {exc}. The validator cannot cross-check "
                "the cognic.skills entry-point declaration.",
                error_type=type(exc).__name__,
            )
        ]
    project = pyproject_data.get("project", {})
    entry_points = project.get("entry-points", {}) if isinstance(project, dict) else {}
    cognic_skills = entry_points.get("cognic.skills", {}) if isinstance(entry_points, dict) else {}
    entry_names = sorted(cognic_skills.keys()) if isinstance(cognic_skills, dict) else []
    return entry_names, []


def _check_entry_point_cross_check(pack_path: Path) -> list[ValidatorFinding]:
    """Cross-check the pack's pyproject declares EXACTLY ONE
    ``[project.entry-points."cognic.skills"]`` entry — mirroring the runtime
    resolver (``harness/skill_host._skill_entry_point_info`` fail-closes on
    ``len(eps) != 1``). Hooks pair per-declaration IDs with entry-point keys
    in both directions; skills have no per-tool ID <-> entry-point pairing,
    so the bidirectional check collapses to this exactly-one rule."""
    pyproject_path = pack_path / "pyproject.toml"
    entry_names, load_findings = _load_skill_entry_point_names(pack_path)
    if entry_names is None:
        return load_findings
    if len(entry_names) == 0:
        return [
            _entry_point_mismatch_finding(
                pyproject_path,
                "entry_point_absent",
                'pyproject.toml declares no [project.entry-points."cognic.skills"] '
                "entry; the runtime resolves the sandboxed action by entry-point "
                "name, so a skill pack without one is never hosted.",
            )
        ]
    if len(entry_names) > 1:
        return [
            _entry_point_mismatch_finding(
                pyproject_path,
                "entry_point_ambiguous",
                f"pyproject.toml declares {len(entry_names)} entries under "
                f'[project.entry-points."cognic.skills"] ({entry_names!r}); the '
                "runtime resolver requires EXACTLY ONE (an ambiguous mapping is "
                "fail-closed at boot). Split multi-action packs into one pack "
                "per skill.",
                entry_point_names=entry_names,
            )
        ]
    return []


def _check_instruction_has_no_entry_point(pack_path: Path) -> list[ValidatorFinding]:
    """M8 A7 (ADR-027) — the INVERSE entry-point rule for instruction-mode
    packs: declaring ANY ``cognic.skills`` entry point on an instruction pack
    is an author error (the runtime loader warn-skips it at boot with
    ``skill.instruction_mode_declares_executable``). An unreadable pyproject
    fails closed via the shared ``pyproject_unparseable`` arm."""
    entry_names, load_findings = _load_skill_entry_point_names(pack_path)
    if entry_names is None:
        return load_findings
    if entry_names:
        return [
            ValidatorFinding(
                severity="refusal",
                reason="skill_manifest_instruction_mode_has_entry_point",
                message=(
                    f"pyproject.toml declares {len(entry_names)} "
                    '[project.entry-points."cognic.skills"] '
                    f"entr{'y' if len(entry_names) == 1 else 'ies'} "
                    f"({entry_names!r}) but the manifest's [skill].mode is "
                    "'instruction'; instruction skills host SKILL.md guidance "
                    "only — remove the entry point or switch to "
                    "mode = 'executable'."
                ),
                payload={
                    "pyproject_path": str(pack_path / "pyproject.toml"),
                    "failure_mode": "entry_point_present",
                    "entry_point_names": entry_names,
                },
            )
        ]
    return []


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Validate the M6 governed-skill authoring surface (see the module
    docstring for the intent-gating contract).

    Returns the aggregated findings list (refusal-severity only — this
    validator has no warning paths).
    """
    located_blocks: list[tuple[str, Any]] = []
    for prefix, accessor in _SKILL_BLOCK_LOCATIONS:
        block = _resolve_path(data, accessor)
        if block is not None:
            located_blocks.append((prefix, block))

    skill_md_present = (pack_path / _SKILL_MD_FILENAME).is_file()
    if not located_blocks and not skill_md_present:
        # No M6 executable-skill intent — silent for every kind INCLUDING
        # kind="skill" (the legacy Sprint-7A composition-skill carve-out;
        # see the module docstring).
        return []

    findings: list[ValidatorFinding] = []
    if not located_blocks:
        # SKILL.md shipped without the manifest block: the runtime loader
        # hosts by block presence, so this pack would silently never be
        # hosted — refuse at build time instead.
        findings.append(
            ValidatorFinding(
                severity="refusal",
                reason="skill_manifest_block_shape_invalid",
                message=(
                    f"pack ships {_SKILL_MD_FILENAME} but the manifest declares no "
                    "[skill] block (canonical) or [tool.cognic.skill] (legacy); "
                    "the runtime hosting layer resolves skills by block presence, "
                    "so this pack would never be hosted. Declare "
                    "[skill].declared_tools."
                ),
                payload={
                    "block_path": "skill",
                    "failure_mode": "block_missing_for_skill_intent",
                },
            )
        )
    for prefix, block in located_blocks:
        findings.extend(_validate_skill_block(block, block_path=prefix))

    findings.extend(_validate_skill_md(pack_path))

    # M8 A7 — the pack-level entry-point rule is mode-gated: the INVERSE
    # no-entry-point rule fires ONLY when every located block declares
    # instruction mode; otherwise (any executable / absent-mode-default /
    # invalid-mode block, or the SKILL.md-without-block case) the pre-A7
    # exactly-one cross-check runs byte-identically.
    block_modes = [_block_mode(block) for _, block in located_blocks if isinstance(block, dict)]
    all_instruction = bool(block_modes) and all(m == "instruction" for m in block_modes)
    if all_instruction:
        findings.extend(_check_instruction_has_no_entry_point(pack_path))
    else:
        findings.extend(_check_entry_point_cross_check(pack_path))
    return findings


__all__ = ["validate"]
