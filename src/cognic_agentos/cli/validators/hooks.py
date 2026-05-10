"""Sprint-7A2 T5 — `[hooks]` block validator (CRITICAL CONTROLS).

Validates the manifest's ``[hooks]`` block against the Wave-1 hook
taxonomy locked at Sprint-7A2 plan-of-record Doctrine Lock A. This
validator is on the strict 95/90 critical-controls floor (joins the
gate at Sprint-7A2 T12); halt-before-commit applies on every change.

Wave-1 scope:

  - **Block presence**: ``kind="hook"`` packs MUST declare ``[hooks]``;
    non-hook packs MUST NOT (Wave-1; non-hook packs declaring
    ``[hooks]`` is a noop today + may upgrade to a refusal in a
    follow-up sprint when hook-pack-wired non-hook packs ship).
  - **Per-declaration shape**: each entry in ``[hooks].declarations``
    MUST carry ``hook_id`` (snake_case), ``phase`` (closed-enum),
    ``ordering_class`` (closed-enum that pairs with ``phase``),
    ``timeout_seconds`` (positive float ≤ ``Settings.hook_max_timeout_s``),
    ``fail_policy`` (closed-enum; ``fail_open`` requires
    ``fail_open_exception`` declaration which is reserved for a
    follow-up sprint).
  - **Cross-reference with pyproject**: every declared ``hook_id``
    MUST have a corresponding entry in
    ``[project.entry-points."cognic.hooks"]`` (and vice versa). The
    validator reads ``pack_path/pyproject.toml`` to perform the
    bi-directional check.

R23 dual-path doctrine: both canonical top-level ``[hooks]`` AND
legacy ``[tool.cognic.hooks]`` are validated. A pack that declares
both gets validated against both (refusals carry
``payload.block_path`` distinguishing the source).

Closed-enum reasons emitted by this validator (7; the 8th hook
reason ``hook_pack_kind_constraint_violated`` is owned by
``cli/validate.py`` per Sprint-7A2 T4 ownership move; the 9th
``hook_unresolved_reference`` is reserved for a future cross-pack-
reference build-time check):

  - ``hook_block_shape_invalid`` — block-level shape failures
    (block missing for kind="hook"; ``declarations`` field absent /
    non-list / empty; per-declaration entry not a table / missing
    a required field).
    ``payload.failure_mode`` distinguishes:
      * ``block_missing_for_hook_pack``
      * ``declarations_field_absent``
      * ``declarations_field_not_list``
      * ``declarations_empty``
      * ``declaration_entry_not_table``
      * ``declaration_missing_required_field``
  - ``hook_id_invalid`` — ``hook_id`` field issues.
    ``payload.failure_mode``:
      * ``invalid_shape`` — not a snake_case identifier
      * ``duplicate_in_manifest`` — same hook_id declared twice
  - ``hook_phase_invalid`` — ``phase`` field issues.
    ``payload.failure_mode``:
      * ``not_in_closed_enum`` — value not in ``HookPhase``
      * ``not_a_string`` — non-string value
  - ``hook_ordering_class_invalid`` — ``ordering_class`` field
    issues. ``payload.failure_mode``:
      * ``not_in_closed_enum``
      * ``not_a_string``
      * ``phase_class_mismatch`` — ``input_*`` paired with
        ``dlp_post`` or ``output_*`` paired with ``dlp_pre``
  - ``hook_timeout_invalid`` — ``timeout_seconds`` issues.
    ``payload.failure_mode``:
      * ``not_a_positive_number``
      * ``above_ceiling`` — value > ``Settings.hook_max_timeout_s``
  - ``hook_fail_policy_invalid`` — ``fail_policy`` field issues.
    ``payload.failure_mode``:
      * ``not_in_closed_enum``
      * ``not_a_string``
      * ``fail_open_without_exception`` — ``fail_open`` declared
        without a matching ``fail_open_exception`` (reserved for a
        follow-up sprint; Wave-1 narrow refuses any ``fail_open``)
  - ``hook_entry_point_mismatch`` — manifest ↔ pyproject mismatch.
    ``payload.failure_mode``:
      * ``pyproject_only`` — pyproject entry-point key has no
        matching ``[hooks].declarations`` entry
      * ``value_disagreement`` — both sides reference the same key
        but with different module:class targets
      * ``pyproject_unparseable`` — pyproject.toml could not be
        parsed (non-existent / not UTF-8 / malformed TOML)
"""

from __future__ import annotations

import re as _re
import tomllib
from pathlib import Path
from typing import Any, Final, cast, get_args

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli._governance_vocab import (
    HOOK_ORDERING_CLASS_PHASE,
    HookFailPolicy,
    HookOrderingClass,
    HookPhase,
)
from cognic_agentos.core.config import build_settings_without_env_file

#: Closed-enum block-locations checked. Mirrors the R23 dual-path
#: doctrine other validators use (canonical top-level + legacy
#: ``[tool.cognic.<block>]``).
_HOOK_BLOCK_LOCATIONS: Final[tuple[tuple[str, tuple[str, ...]], ...]] = (
    ("hooks", ("hooks",)),
    ("tool.cognic.hooks", ("tool", "cognic", "hooks")),
)

#: Required fields per declaration. Each entry pairs the field name
#: with its expected type-or-types tuple for early-exit type checks
#: before semantic validation.
_REQUIRED_DECLARATION_FIELDS: Final[tuple[str, ...]] = (
    "hook_id",
    "phase",
    "ordering_class",
    "timeout_seconds",
    "fail_policy",
)

#: snake_case validator for hook_id values. Matches the same
#: pattern the init scaffolder accepts for pack_name (lowercase
#: identifier characters; cannot start with a digit). Kept narrow
#: so future cross-pack registry indexing remains predictable.
_HOOK_ID_PATTERN: Final[_re.Pattern[str]] = _re.compile(r"^[a-z][a-z0-9_]*$")


def _resolve_path(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    """Walk ``path`` through ``data``; return the leaf if every
    intermediate step resolves to a dict, otherwise ``None``."""
    cursor: Any = data
    for segment in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(segment)
    return cursor


def _shape_finding(
    *,
    failure_mode: str,
    message: str,
    block_path: str,
    **extra: Any,
) -> ValidatorFinding:
    return ValidatorFinding(
        severity="refusal",
        reason="hook_block_shape_invalid",
        message=message,
        payload={"block_path": block_path, "failure_mode": failure_mode, **extra},
    )


def _validate_declaration(
    declaration: Any,
    *,
    block_path: str,
    declaration_index: int,
    seen_hook_ids: set[str],
    settings_max_timeout: float,
) -> list[ValidatorFinding]:
    """Validate one ``[hooks].declarations[N]`` entry; emits per-field
    refusals + accumulates ``hook_id`` into ``seen_hook_ids`` so the
    duplicate-detection check fires on the second occurrence."""
    findings: list[ValidatorFinding] = []
    if not isinstance(declaration, dict):
        findings.append(
            _shape_finding(
                failure_mode="declaration_entry_not_table",
                message=(
                    f"{block_path}.declarations[{declaration_index}] is "
                    f"{type(declaration).__name__}; expected a TOML table."
                ),
                block_path=block_path,
                declaration_index=declaration_index,
            )
        )
        return findings

    # Required fields presence — one finding per missing.
    for field in _REQUIRED_DECLARATION_FIELDS:
        if field not in declaration:
            findings.append(
                _shape_finding(
                    failure_mode="declaration_missing_required_field",
                    message=(
                        f"{block_path}.declarations[{declaration_index}] is "
                        f"missing required field {field!r}."
                    ),
                    block_path=block_path,
                    declaration_index=declaration_index,
                    field=field,
                )
            )
    # Even with missing fields, run the per-field validators against
    # what IS present so authors get the full picture in one pass.

    findings.extend(
        _validate_hook_id_field(
            declaration.get("hook_id"),
            block_path=block_path,
            declaration_index=declaration_index,
            seen_hook_ids=seen_hook_ids,
        )
    )
    findings.extend(
        _validate_phase_field(
            declaration.get("phase"),
            block_path=block_path,
            declaration_index=declaration_index,
        )
    )
    findings.extend(
        _validate_ordering_class_field(
            declaration.get("ordering_class"),
            phase_value=declaration.get("phase"),
            block_path=block_path,
            declaration_index=declaration_index,
        )
    )
    findings.extend(
        _validate_timeout_field(
            declaration.get("timeout_seconds"),
            settings_max_timeout=settings_max_timeout,
            block_path=block_path,
            declaration_index=declaration_index,
        )
    )
    findings.extend(
        _validate_fail_policy_field(
            declaration.get("fail_policy"),
            block_path=block_path,
            declaration_index=declaration_index,
        )
    )
    return findings


def _validate_hook_id_field(
    value: Any,
    *,
    block_path: str,
    declaration_index: int,
    seen_hook_ids: set[str],
) -> list[ValidatorFinding]:
    if value is None:
        return []  # missing handled by required-field check
    if not isinstance(value, str) or not _HOOK_ID_PATTERN.match(value):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="hook_id_invalid",
                message=(
                    f"{block_path}.declarations[{declaration_index}].hook_id "
                    f"{value!r} is not a snake_case identifier (lowercase "
                    "letters / digits / underscores; cannot start with a digit)."
                ),
                payload={
                    "block_path": block_path,
                    "declaration_index": declaration_index,
                    "field": "hook_id",
                    "failure_mode": "invalid_shape",
                    "declared_value": value,
                },
            )
        ]
    if value in seen_hook_ids:
        return [
            ValidatorFinding(
                severity="refusal",
                reason="hook_id_invalid",
                message=(
                    f"{block_path}.declarations[{declaration_index}].hook_id "
                    f"= {value!r} duplicates an earlier declaration in the "
                    "same manifest. Each hook_id MUST be unique within a pack."
                ),
                payload={
                    "block_path": block_path,
                    "declaration_index": declaration_index,
                    "field": "hook_id",
                    "failure_mode": "duplicate_in_manifest",
                    "declared_value": value,
                },
            )
        ]
    seen_hook_ids.add(value)
    return []


def _validate_phase_field(
    value: Any,
    *,
    block_path: str,
    declaration_index: int,
) -> list[ValidatorFinding]:
    if value is None:
        return []
    if not isinstance(value, str):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="hook_phase_invalid",
                message=(
                    f"{block_path}.declarations[{declaration_index}].phase is "
                    f"{type(value).__name__}; expected one of "
                    f"{sorted(get_args(HookPhase))!r}."
                ),
                payload={
                    "block_path": block_path,
                    "declaration_index": declaration_index,
                    "field": "phase",
                    "failure_mode": "not_a_string",
                },
            )
        ]
    if value not in get_args(HookPhase):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="hook_phase_invalid",
                message=(
                    f"{block_path}.declarations[{declaration_index}].phase = "
                    f"{value!r} is not a valid Wave-1 phase. Allowed values: "
                    f"{sorted(get_args(HookPhase))!r}."
                ),
                payload={
                    "block_path": block_path,
                    "declaration_index": declaration_index,
                    "field": "phase",
                    "failure_mode": "not_in_closed_enum",
                    "declared_value": value,
                },
            )
        ]
    return []


def _validate_ordering_class_field(
    value: Any,
    *,
    phase_value: Any,
    block_path: str,
    declaration_index: int,
) -> list[ValidatorFinding]:
    if value is None:
        return []
    if not isinstance(value, str):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="hook_ordering_class_invalid",
                message=(
                    f"{block_path}.declarations[{declaration_index}]."
                    f"ordering_class is {type(value).__name__}; expected one "
                    f"of {sorted(get_args(HookOrderingClass))!r}."
                ),
                payload={
                    "block_path": block_path,
                    "declaration_index": declaration_index,
                    "field": "ordering_class",
                    "failure_mode": "not_a_string",
                },
            )
        ]
    if value not in get_args(HookOrderingClass):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="hook_ordering_class_invalid",
                message=(
                    f"{block_path}.declarations[{declaration_index}]."
                    f"ordering_class = {value!r} is not a valid Wave-1 "
                    "ordering class. Allowed values: "
                    f"{sorted(get_args(HookOrderingClass))!r}."
                ),
                payload={
                    "block_path": block_path,
                    "declaration_index": declaration_index,
                    "field": "ordering_class",
                    "failure_mode": "not_in_closed_enum",
                    "declared_value": value,
                },
            )
        ]
    # Phase-class mismatch check: input_* classes pair with dlp_pre,
    # output_* with dlp_post. Only fires when phase is itself valid
    # (otherwise hook_phase_invalid already covered it).
    if isinstance(phase_value, str) and phase_value in get_args(HookPhase):
        # ``value`` was just confirmed in the HookOrderingClass enum;
        # cast lets mypy narrow the dict-key lookup against the
        # closed-Literal-keyed map.
        expected_phase = HOOK_ORDERING_CLASS_PHASE.get(cast(HookOrderingClass, value))
        if expected_phase is not None and expected_phase != phase_value:
            return [
                ValidatorFinding(
                    severity="refusal",
                    reason="hook_ordering_class_invalid",
                    message=(
                        f"{block_path}.declarations[{declaration_index}] "
                        f"declares phase={phase_value!r} + ordering_class="
                        f"{value!r}, but ordering_class {value!r} pairs with "
                        f"phase {expected_phase!r}. ``input_*`` classes pair "
                        "with ``dlp_pre``; ``output_*`` classes pair with "
                        "``dlp_post``."
                    ),
                    payload={
                        "block_path": block_path,
                        "declaration_index": declaration_index,
                        "field": "ordering_class",
                        "failure_mode": "phase_class_mismatch",
                        "declared_phase": phase_value,
                        "declared_ordering_class": value,
                        "expected_phase_for_class": expected_phase,
                    },
                )
            ]
    return []


def _validate_timeout_field(
    value: Any,
    *,
    settings_max_timeout: float,
    block_path: str,
    declaration_index: int,
) -> list[ValidatorFinding]:
    if value is None:
        return []
    # bool is an int subclass in Python; refuse explicitly so `True`
    # / `False` doesn't slip through the int branch.
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return [
            ValidatorFinding(
                severity="refusal",
                reason="hook_timeout_invalid",
                message=(
                    f"{block_path}.declarations[{declaration_index}]."
                    f"timeout_seconds = {value!r} is not a positive number; "
                    "expected a float > 0."
                ),
                payload={
                    "block_path": block_path,
                    "declaration_index": declaration_index,
                    "field": "timeout_seconds",
                    "failure_mode": "not_a_positive_number",
                    "declared_value": value if not isinstance(value, bool) else str(value),
                },
            )
        ]
    if float(value) > settings_max_timeout:
        return [
            ValidatorFinding(
                severity="refusal",
                reason="hook_timeout_invalid",
                message=(
                    f"{block_path}.declarations[{declaration_index}]."
                    f"timeout_seconds = {value!r} exceeds the operator-"
                    f"policy ceiling of {settings_max_timeout!r}s "
                    "(Settings.hook_max_timeout_s). Lower the per-hook "
                    "timeout to fit under the ceiling, or escalate to "
                    "operators if the workload genuinely needs more."
                ),
                payload={
                    "block_path": block_path,
                    "declaration_index": declaration_index,
                    "field": "timeout_seconds",
                    "failure_mode": "above_ceiling",
                    "declared_value": float(value),
                    "ceiling_seconds": settings_max_timeout,
                },
            )
        ]
    return []


def _validate_fail_policy_field(
    value: Any,
    *,
    block_path: str,
    declaration_index: int,
) -> list[ValidatorFinding]:
    if value is None:
        return []
    if not isinstance(value, str):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="hook_fail_policy_invalid",
                message=(
                    f"{block_path}.declarations[{declaration_index}]."
                    f"fail_policy is {type(value).__name__}; expected one "
                    f"of {sorted(get_args(HookFailPolicy))!r}."
                ),
                payload={
                    "block_path": block_path,
                    "declaration_index": declaration_index,
                    "field": "fail_policy",
                    "failure_mode": "not_a_string",
                },
            )
        ]
    if value not in get_args(HookFailPolicy):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="hook_fail_policy_invalid",
                message=(
                    f"{block_path}.declarations[{declaration_index}]."
                    f"fail_policy = {value!r} is not a valid Wave-1 fail "
                    f"policy. Allowed values: "
                    f"{sorted(get_args(HookFailPolicy))!r}."
                ),
                payload={
                    "block_path": block_path,
                    "declaration_index": declaration_index,
                    "field": "fail_policy",
                    "failure_mode": "not_in_closed_enum",
                    "declared_value": value,
                },
            )
        ]
    if value == "fail_open":
        # Wave-1 narrow per Doctrine Lock A: fail_open requires the
        # calling pack's data_governance to declare a matching
        # fail_open_exception. The exception declaration shape is
        # reserved for a follow-up sprint; Wave-1 refuses any
        # fail_open until that lands.
        return [
            ValidatorFinding(
                severity="refusal",
                reason="hook_fail_policy_invalid",
                message=(
                    f"{block_path}.declarations[{declaration_index}]."
                    "fail_policy = 'fail_open' but the matching "
                    "fail_open_exception declaration is not yet supported "
                    "in Wave-1. ADR-017 mandates fail-closed by default for "
                    "all data-governance phases; use fail_policy='fail_closed' "
                    "until the fail_open_exception declaration shape lands."
                ),
                payload={
                    "block_path": block_path,
                    "declaration_index": declaration_index,
                    "field": "fail_policy",
                    "failure_mode": "fail_open_without_exception",
                    "declared_value": value,
                },
            )
        ]
    return []


def _read_pyproject_hook_entry_points(
    pack_path: Path,
) -> tuple[dict[str, str] | None, ValidatorFinding | None]:
    """Read ``pack_path/pyproject.toml`` and return its
    ``[project.entry-points."cognic.hooks"]`` mapping (or
    ``({}, None)`` if the section is absent).

    Returns ``(None, finding)`` if pyproject.toml is unreadable /
    malformed — the caller short-circuits the cross-check in that
    case (the entry-point cross-check can't fire if we can't read
    the pyproject)."""
    pyproject_path = pack_path / "pyproject.toml"
    if not pyproject_path.is_file():
        return None, ValidatorFinding(
            severity="refusal",
            reason="hook_entry_point_mismatch",
            message=(
                f"manifest declares [hooks] but pyproject.toml not found "
                f"at {pyproject_path}; the validator cannot cross-check "
                "manifest declarations against entry-point declarations."
            ),
            payload={
                "failure_mode": "pyproject_unparseable",
                "pyproject_path": str(pyproject_path),
                "error_type": "FileNotFoundError",
            },
        )
    try:
        pyproject_data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, OSError) as exc:
        return None, ValidatorFinding(
            severity="refusal",
            reason="hook_entry_point_mismatch",
            message=(
                f"pyproject.toml at {pyproject_path} could not be parsed: "
                f"{type(exc).__name__}: {exc}. The validator cannot cross-"
                "check manifest declarations against entry-point declarations."
            ),
            payload={
                "failure_mode": "pyproject_unparseable",
                "pyproject_path": str(pyproject_path),
                "error_type": type(exc).__name__,
            },
        )
    project = pyproject_data.get("project", {})
    if not isinstance(project, dict):
        return {}, None
    entry_points = project.get("entry-points", {})
    if not isinstance(entry_points, dict):
        return {}, None
    cognic_hooks = entry_points.get("cognic.hooks", {})
    if not isinstance(cognic_hooks, dict):
        return {}, None
    # Coerce string values only; non-string values surface as ``None``
    # in the cross-check so the validator emits a clear refusal.
    return {k: v for k, v in cognic_hooks.items() if isinstance(v, str)}, None


def _check_entry_point_cross_check(
    declared_hook_ids: set[str],
    pack_path: Path,
) -> list[ValidatorFinding]:
    """Cross-check ``[hooks].declarations[].hook_id`` against
    ``pyproject.toml [project.entry-points."cognic.hooks"]``.

    Three failure modes:

      - ``manifest_only`` — declared in manifest but missing from
        pyproject. Emitted via ``hook_unresolved_reference`` (the
        manifest references something pyproject doesn't define).
      - ``pyproject_only`` — pyproject entry has no matching manifest
        declaration. Emitted via ``hook_entry_point_mismatch``.
      - ``pyproject_unparseable`` — couldn't read pyproject.toml.
        Emitted via ``hook_entry_point_mismatch`` from the read
        helper.

    Note: ``manifest_only`` IS an "unresolved reference" (manifest →
    pyproject), so it routes through the ``hook_unresolved_reference``
    closed-enum reason rather than ``hook_entry_point_mismatch``;
    matches the ownership-map pairing where ``hook_unresolved_reference``
    is owned by ``validators/hooks.py`` per Sprint-7A2 T1 closed-enum
    seed.
    """
    findings: list[ValidatorFinding] = []
    pyproject_entries, pyproject_finding = _read_pyproject_hook_entry_points(pack_path)
    if pyproject_finding is not None:
        return [pyproject_finding]
    assert pyproject_entries is not None  # narrowed by guard above
    pyproject_keys = set(pyproject_entries.keys())

    manifest_only = declared_hook_ids - pyproject_keys
    pyproject_only = pyproject_keys - declared_hook_ids

    for hook_id in sorted(manifest_only):
        findings.append(
            ValidatorFinding(
                severity="refusal",
                reason="hook_unresolved_reference",
                message=(
                    f"[hooks].declarations declares hook_id={hook_id!r} but "
                    f'pyproject.toml\'s [project.entry-points."cognic.hooks"] '
                    f"has no matching key. Add an entry-point declaration "
                    f"for {hook_id!r} or remove the manifest declaration."
                ),
                payload={
                    "failure_mode": "manifest_only",
                    "hook_id": hook_id,
                },
            )
        )
    for key in sorted(pyproject_only):
        findings.append(
            ValidatorFinding(
                severity="refusal",
                reason="hook_entry_point_mismatch",
                message=(
                    f'pyproject.toml\'s [project.entry-points."cognic.hooks"] '
                    f"declares key={key!r} but [hooks].declarations has no "
                    f"matching hook_id. Add a [[hooks.declarations]] entry "
                    f"for {key!r} or remove the entry-point declaration."
                ),
                payload={
                    "failure_mode": "pyproject_only",
                    "hook_id": key,
                },
            )
        )
    return findings


def _validate_hook_block(
    block: Any,
    *,
    block_path: str,
    settings_max_timeout: float,
) -> tuple[list[ValidatorFinding], set[str]]:
    """Validate one ``[hooks]`` block (canonical or legacy). Returns
    ``(findings, declared_hook_ids)`` where ``declared_hook_ids`` is
    the set of unique IDs the block declared (used by the entry-
    point cross-check)."""
    findings: list[ValidatorFinding] = []
    declared_hook_ids: set[str] = set()
    if not isinstance(block, dict):
        # The shape gate would normally catch a non-dict block, but
        # only for the universal _REQUIRED_TOP_LEVEL_BLOCKS list.
        # [hooks] isn't in that list (hook-pack-specific), so we
        # surface the same shape failure here.
        findings.append(
            _shape_finding(
                failure_mode="block_missing_for_hook_pack",
                message=(
                    f"manifest declares [{block_path}] but the value is "
                    f"{type(block).__name__}; expected a TOML table."
                ),
                block_path=block_path,
            )
        )
        return findings, declared_hook_ids

    if "declarations" not in block:
        findings.append(
            _shape_finding(
                failure_mode="declarations_field_absent",
                message=(
                    f"[{block_path}] is missing the 'declarations' field; "
                    "every hook pack MUST declare at least one hook via a "
                    "[[hooks.declarations]] array-of-tables entry."
                ),
                block_path=block_path,
            )
        )
        return findings, declared_hook_ids

    declarations = block["declarations"]
    if not isinstance(declarations, list):
        findings.append(
            _shape_finding(
                failure_mode="declarations_field_not_list",
                message=(
                    f"[{block_path}].declarations is "
                    f"{type(declarations).__name__}; expected a TOML array "
                    "of tables (one entry per declared hook)."
                ),
                block_path=block_path,
            )
        )
        return findings, declared_hook_ids

    if not declarations:
        findings.append(
            _shape_finding(
                failure_mode="declarations_empty",
                message=(
                    f"[{block_path}].declarations is empty; every hook pack "
                    "MUST declare at least one hook via a "
                    "[[hooks.declarations]] entry."
                ),
                block_path=block_path,
            )
        )
        return findings, declared_hook_ids

    for index, declaration in enumerate(declarations):
        per_decl_findings = _validate_declaration(
            declaration,
            block_path=block_path,
            declaration_index=index,
            seen_hook_ids=declared_hook_ids,
            settings_max_timeout=settings_max_timeout,
        )
        findings.extend(per_decl_findings)
    return findings, declared_hook_ids


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Validate the manifest's ``[hooks]`` block(s) against the
    Sprint-7A2 Wave-1 hook taxonomy.

    For ``kind="hook"`` packs the block is mandatory; for non-hook
    packs the block is no-op (Wave-1; non-hook packs declaring
    [hooks] is silently allowed today). Both R23 dual-path locations
    (top-level ``[hooks]`` + legacy ``[tool.cognic.hooks]``) are
    validated; pack authors who declare both get refusals from each
    location with ``payload.block_path`` distinguishing the source.

    Returns the aggregated findings list (refusal-severity only —
    Wave-1 has no warning paths in this validator).
    """
    findings: list[ValidatorFinding] = []
    pack_block = data.get("pack")
    pack_kind = pack_block.get("kind") if isinstance(pack_block, dict) else None

    settings = build_settings_without_env_file()
    settings_max_timeout = settings.hook_max_timeout_s

    # Locate every present [hooks] block (canonical + legacy). If
    # neither path resolves AND kind="hook", that's a refusal.
    located_blocks: list[tuple[str, Any]] = []
    for prefix, accessor in _HOOK_BLOCK_LOCATIONS:
        block = _resolve_path(data, accessor)
        if block is not None:
            located_blocks.append((prefix, block))

    if not located_blocks:
        if pack_kind == "hook":
            findings.append(
                _shape_finding(
                    failure_mode="block_missing_for_hook_pack",
                    message=(
                        'kind="hook" pack manifest is missing the [hooks] '
                        "block; every hook pack MUST declare at least one "
                        "hook via a [[hooks.declarations]] array-of-tables "
                        "entry."
                    ),
                    block_path="hooks",
                )
            )
        return findings  # non-hook packs skip the validator entirely

    # Validate each located block; aggregate declared hook_ids across
    # locations so the entry-point cross-check sees the union.
    all_declared_hook_ids: set[str] = set()
    for prefix, block in located_blocks:
        block_findings, declared_ids = _validate_hook_block(
            block,
            block_path=prefix,
            settings_max_timeout=settings_max_timeout,
        )
        findings.extend(block_findings)
        all_declared_hook_ids.update(declared_ids)

    # Cross-check against pyproject.toml entry-point declarations.
    # Skip if no hook_ids were successfully extracted (every
    # declaration was malformed) — the per-declaration refusals
    # already surface the manifest issue; emitting cross-check
    # refusals on top would be noise.
    if all_declared_hook_ids:
        findings.extend(_check_entry_point_cross_check(all_declared_hook_ids, pack_path))
    elif pack_kind == "hook":
        # Hook pack with [hooks] block but ZERO valid declarations.
        # Don't emit cross-check findings (the per-declaration
        # refusals tell the author what to fix); the entry-point
        # mismatch is implied + not worth duplicate-emitting here.
        pass

    return findings


__all__ = ["validate"]
