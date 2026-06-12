"""Sprint 10.6 T14 — credentials manifest validator per ADR-004 §25 + ADR-017.

Per-concern build-time validator for ``[credentials.<logical_name>]``
pack-manifest blocks. Emits the 20 closed-enum ``ValidatorReason``
values owned by this module per ``cli/__init__.py:_VALIDATOR_REASON_OWNERSHIP``
(17 ``credentials_*`` + 3 ``runtime_expected_workload_gid_*``).

Doctrine note on ``credentials_logical_name_duplicate`` —
*UNREACHABLE from a single dict input by language invariant.* The
Wave-1 ``validate()`` entry point consumes a Python ``dict`` whose
keys are unique by construction, and TOML parsers reject duplicate
section headers at parse time. The closed-enum value is therefore
not collateral on any normal manifest. The internal helper
:func:`_detect_duplicate_names` IS the surface that will fire the
refusal when the Sprint 10.6+ T15 orchestrator overlay-merge path
produces a list-of-pairs shape from composed base + overlay manifest
sources — the helper is wired through ``validate()``'s normal flow
(called with ``list(credentials.items())``; no-op for dict input)
AND exposed for direct unit-test of the future composed-input path.
This is the "model a deliberate duplicate-preserving synthetic input
shape and document why" arm of the user-locked T14 design correction
(see ``tests/unit/cli/validators/test_validator_credentials.py``
module docstring for the full rationale).

Precedence rules (locked by user guidance):

  - ``credentials_vault_path_empty`` short-circuits further vault_path
    checks (length / chars / shape) for that block.
  - ``credentials_expected_fields_empty`` short-circuits further
    expected_fields checks (count / duplicates / per-field grammar).
  - ``credentials_expected_fields_reserved_underscore_prefix`` fires
    BEFORE the general ``credentials_expected_fields_field_name_invalid_grammar``
    refusal so authors get an actionable error pointing at the
    reserved-prefix rule rather than a generic snake_case complaint.
  - Logical-name grammar fires independently of duplicate detection
    at the :func:`validate` end-to-end level — a name failing
    grammar is dropped from per-block field checks (no collateral
    field refusals), but ``_detect_duplicate_names`` does NOT
    pre-filter by grammar at the helper level. The end-to-end
    trailing-space scenario (e.g., ``"db_main"`` vs ``"db_main "``)
    works because exact-string compare distinguishes the two keys,
    not because grammar pre-filters either of them. Callers
    consuming ``_detect_duplicate_names`` directly with a synthetic
    duplicate-preserving input (e.g., the future T15 orchestrator
    overlay-merge surface) should pre-filter for grammar themselves
    if they want grammar-clean dedup only — the helper's contract
    is exact-string compare, period.

Scope isolation (locked by user guidance):

  - This validator emits ONLY the 20 closed-enum reasons it owns
    per the ownership map. It does NOT emit orchestrator-owned
    ``manifest_*`` reasons or T11-owned
    ``risk_tier_inconsistent_with_data_classes``.

Wave-1 grammar / range constraints:

  - Logical names: ``^[a-z][a-z0-9_]*$``, max 32 chars.
  - Vault paths: max 512 chars; valid chars are ``[A-Za-z0-9/_-]``;
    must contain at least one ``/``; no leading slash; no trailing
    slash; no double-slash.
  - Expected-fields: 1-16 entries; each entry matches
    ``^[a-z][a-z0-9_]{0,31}$`` (max 32 chars per spec §5.1); no
    underscore-prefix (reserved for kernel internal field names);
    per-list uniqueness.
  - ttl_s: positive integer (> 0).
  - purpose_category: closed-enum
    :data:`cognic_agentos.cli._governance_vocab.PurposeCategory`.
  - purpose_description: non-empty string, max 256 chars.
  - Per-pack credential count: max 16.
  - expected_workload_gid: integer in [1, 4294967295] (Linux 32-bit
    kernel GID space; covers OpenShift ``MustRunAsRange``); required
    when ``[credentials.*]`` blocks exist; forbidden when none exist.
"""

from __future__ import annotations

import re as _re
import typing
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli._governance_vocab import PurposeCategory

# ---------------------------------------------------------------------------
# Grammar + range constants
# ---------------------------------------------------------------------------

_LOGICAL_NAME_PATTERN: Final[_re.Pattern[str]] = _re.compile(r"^[a-z][a-z0-9_]*$")
_LOGICAL_NAME_MAX_LEN: Final[int] = 32

_VAULT_PATH_VALID_CHARS_PATTERN: Final[_re.Pattern[str]] = _re.compile(r"^[A-Za-z0-9/_-]+$")
_VAULT_PATH_MAX_LEN: Final[int] = 512

#: Spec §5.1 grammar for ``expected_fields`` entries: leading lowercase
#: letter + up to 31 trailing snake_case chars (max 32 total). Earlier
#: T14 draft used ``^[a-z][a-z0-9_]*$`` (no length cap) which let 33+-
#: char field names pass — corrected at T14b per the reviewer-found
#: drift between the spec wording and the regex.
_FIELD_NAME_PATTERN: Final[_re.Pattern[str]] = _re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_EXPECTED_FIELDS_MAX_COUNT: Final[int] = 16

_CREDENTIALS_MAX_COUNT: Final[int] = 16
_PURPOSE_DESCRIPTION_MAX_LEN: Final[int] = 256
_GID_MIN: Final[int] = 1
# Linux kernel 32-bit GID space (2^32 - 1). Covers the OpenShift
# ``MustRunAsRange`` allocation envelope (typically 1_000_000_000-
# 1_000_999_999 per project; bank deployments routinely see GIDs
# in that range). Sprint 10.6 T20 round-4 reviewer P1 bumped from
# the previous 65535 cap which would have rejected every legitimate
# OpenShift-namespaced workload per ``[[project_openshift_deployment_target]]``.
# The K8s ``securityContext.fsGroup`` field uses int64 but the
# kernel enforces 32-bit; this cap matches the kernel limit.
_GID_MAX: Final[int] = 4_294_967_295

#: Closed-enum ``PurposeCategory`` value-set, derived at module
#: load from the build-time vocabulary literal per T12. Drift
#: detector at ``tests/unit/cli/test_purpose_category_vocab.py``
#: pins the canonical set; using ``typing.get_args`` keeps this
#: module lockstep with the Literal without a duplicate inline
#: declaration.
_VALID_PURPOSE_CATEGORIES: Final[frozenset[str]] = frozenset(typing.get_args(PurposeCategory))

#: Per-block allowed top-level field set. Any key in a
#: ``[credentials.<name>]`` block outside this set fires
#: ``credentials_unknown_field`` (with the actual offending key
#: name in ``payload.field``).
_ALLOWED_BLOCK_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "vault_path",
        "expected_fields",
        "ttl_s",
        "purpose_category",
        "purpose_description",
    }
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _detect_duplicate_names(
    name_decl_pairs: Sequence[tuple[str, Any]],
) -> list[ValidatorFinding]:
    """Defense-in-depth duplicate-logical-name detection.

    Called from :func:`validate` with ``list(credentials.items())`` —
    a no-op for normal dict input because Python dict keys are
    unique by language invariant. Reachable from the Sprint 10.6+
    T15 orchestrator overlay-merge path when multiple manifest
    sources are composed into a list-of-pairs shape that preserves
    both sources' entries.

    Exact-string comparison only — no normalization (case-fold,
    trailing-whitespace strip, etc.) per the user-locked T14 design
    guardrail AND no grammar pre-filtering. Two implications:

    1. Logical names that share a stem but differ on grammar
       (e.g., ``"db_main"`` vs ``"db_main "`` with trailing space)
       are NOT collateral duplicates here because the exact-string
       compare distinguishes them. The trailing-space variant
       independently trips ``credentials_logical_name_invalid_grammar``
       in the per-block grammar check at :func:`validate`'s loop.
    2. Logical names that ARE exact-string-equal but BOTH malformed
       (e.g., a list-of-pairs input
       ``[("DB_Main", decl), ("DB_Main", decl)]``) WILL fire both
       ``credentials_logical_name_duplicate`` (from this helper)
       AND ``credentials_logical_name_invalid_grammar`` (from the
       per-block grammar check). Callers consuming this helper
       outside :func:`validate` with a synthetic duplicate-
       preserving input shape should pre-filter for grammar
       themselves if they want grammar-clean dedup — the helper's
       contract is exact-string compare, period.

    Pinned by ``test_validator_credentials.py``'s
    ``TestLogicalNameDuplicateDetection`` class: the
    ``test_helper_fires_on_synthetic_list_of_pairs_duplicates``
    test asserts the well-formed case; the T14b
    ``test_helper_does_not_filter_grammar_on_malformed_duplicates``
    test asserts the malformed-duplicate case fires both refusals
    + documents the helper's no-grammar-filtering contract.
    """
    seen: set[str] = set()
    findings: list[ValidatorFinding] = []
    for name, _decl in name_decl_pairs:
        if name in seen:
            findings.append(
                ValidatorFinding(
                    severity="refusal",
                    reason="credentials_logical_name_duplicate",
                    message=(
                        f"Duplicate logical name {name!r} across "
                        "[credentials.*] blocks; logical names must be "
                        "unique within a manifest."
                    ),
                    payload={"logical_name": name},
                )
            )
        else:
            seen.add(name)
    return findings


def _refusal(*, reason: str, message: str, **payload: Any) -> ValidatorFinding:
    """Build a refusal-severity finding with the given closed-enum
    reason + free-form payload keys."""
    return ValidatorFinding(
        severity="refusal",
        reason=reason,  # type: ignore[arg-type]
        message=message,
        payload=dict(payload),
    )


def _validate_logical_name(name: str) -> list[ValidatorFinding]:
    """Logical-name grammar check. Fires
    ``credentials_logical_name_invalid_grammar`` on a non-matching
    name OR a name exceeding ``_LOGICAL_NAME_MAX_LEN`` chars."""
    findings: list[ValidatorFinding] = []
    if not _LOGICAL_NAME_PATTERN.fullmatch(name) or len(name) > _LOGICAL_NAME_MAX_LEN:
        findings.append(
            _refusal(
                reason="credentials_logical_name_invalid_grammar",
                message=(
                    f"Logical name {name!r} must match ^[a-z][a-z0-9_]*$ "
                    f"and be at most {_LOGICAL_NAME_MAX_LEN} chars."
                ),
                logical_name=name,
            )
        )
    return findings


def _validate_vault_path(name: str, vp: Any) -> list[ValidatorFinding]:
    """Validate the ``vault_path`` field for a single credential
    block. Precedence: empty (incl. missing field, i.e. ``vp is None``)
    → short-circuit; non-string non-None type → ``invalid_shape``
    short-circuit; otherwise length + chars + shape (each runs
    independently; multiple may fire on a single bad path that
    violates more than one constraint)."""
    findings: list[ValidatorFinding] = []
    # T14b reviewer fix: spec §5.1 marks vault_path as a required
    # field. ``vp is None`` (the missing-field case forwarded by
    # ``_validate_credential_block``'s ``decl.get(...)`` call) maps
    # to the same closed-enum refusal as an explicit empty string,
    # giving authors a single consistent error.
    if vp is None or vp == "":
        findings.append(
            _refusal(
                reason="credentials_vault_path_empty",
                message=(
                    f"vault_path for [credentials.{name}] is missing or empty; "
                    "declare the Vault secret path (e.g., 'database/creds/db-main')."
                ),
                logical_name=name,
            )
        )
        return findings
    if not isinstance(vp, str):
        # Other non-string type — emit invalid_shape so the closed-
        # enum surface stays narrow (no separate "wrong type" reason).
        findings.append(
            _refusal(
                reason="credentials_vault_path_invalid_shape",
                message=(
                    f"vault_path for [credentials.{name}] must be a string; "
                    f"got {type(vp).__name__!r}."
                ),
                logical_name=name,
                failure_mode="non_string",
            )
        )
        return findings

    if len(vp) > _VAULT_PATH_MAX_LEN:
        findings.append(
            _refusal(
                reason="credentials_vault_path_exceeds_length",
                message=(
                    f"vault_path for [credentials.{name}] is {len(vp)} chars; "
                    f"max {_VAULT_PATH_MAX_LEN}."
                ),
                logical_name=name,
                length=len(vp),
                max_length=_VAULT_PATH_MAX_LEN,
            )
        )

    if not _VAULT_PATH_VALID_CHARS_PATTERN.fullmatch(vp):
        findings.append(
            _refusal(
                reason="credentials_vault_path_invalid_chars",
                message=(
                    f"vault_path for [credentials.{name}] contains characters "
                    "outside [A-Za-z0-9/_-]."
                ),
                logical_name=name,
            )
        )

    if vp.startswith("/") or vp.endswith("/") or "//" in vp or "/" not in vp:
        findings.append(
            _refusal(
                reason="credentials_vault_path_invalid_shape",
                message=(
                    f"vault_path for [credentials.{name}] must contain at "
                    "least one '/' separator, must not start or end with "
                    "'/', and must not contain double-slash."
                ),
                logical_name=name,
            )
        )

    return findings


def _validate_expected_fields(name: str, ef: Any) -> list[ValidatorFinding]:
    """Validate the ``expected_fields`` list. Precedence: empty →
    short-circuit; otherwise count → duplicates → per-field
    (reserved-underscore-prefix BEFORE general grammar)."""
    findings: list[ValidatorFinding] = []
    if not isinstance(ef, list):
        # Shape error; emit empty as the closest semantic match
        # (caller passed something other than a list). Keeps the
        # closed-enum surface narrow.
        findings.append(
            _refusal(
                reason="credentials_expected_fields_empty",
                message=(
                    f"expected_fields for [credentials.{name}] must be a "
                    f"list of strings; got {type(ef).__name__!r}."
                ),
                logical_name=name,
                failure_mode="non_list",
            )
        )
        return findings
    if len(ef) == 0:
        findings.append(
            _refusal(
                reason="credentials_expected_fields_empty",
                message=(
                    f"expected_fields for [credentials.{name}] is an empty "
                    "list; declare at least one field name."
                ),
                logical_name=name,
            )
        )
        return findings

    if len(ef) > _EXPECTED_FIELDS_MAX_COUNT:
        findings.append(
            _refusal(
                reason="credentials_expected_fields_count_exceeds_maximum",
                message=(
                    f"expected_fields for [credentials.{name}] has {len(ef)} "
                    f"entries; max {_EXPECTED_FIELDS_MAX_COUNT}."
                ),
                logical_name=name,
                count=len(ef),
                max_count=_EXPECTED_FIELDS_MAX_COUNT,
            )
        )

    seen: set[str] = set()
    duplicates: list[str] = []
    for f in ef:
        if isinstance(f, str):
            if f in seen:
                duplicates.append(f)
            else:
                seen.add(f)
    if duplicates:
        findings.append(
            _refusal(
                reason="credentials_expected_fields_contains_duplicates",
                message=(
                    f"expected_fields for [credentials.{name}] contains "
                    f"duplicate entries: {sorted(set(duplicates))!r}."
                ),
                logical_name=name,
                duplicates=sorted(set(duplicates)),
            )
        )

    for f in ef:
        if not isinstance(f, str):
            findings.append(
                _refusal(
                    reason="credentials_expected_fields_field_name_invalid_grammar",
                    message=(
                        f"expected_fields entry in [credentials.{name}] must "
                        f"be a string; got {type(f).__name__!r}."
                    ),
                    logical_name=name,
                    failure_mode="non_string",
                )
            )
            continue
        # Reserved-underscore-prefix check BEFORE general grammar per
        # locked precedence — authors hitting `_password` get a
        # specific reserved-prefix error rather than a generic
        # snake_case complaint.
        if f.startswith("_"):
            findings.append(
                _refusal(
                    reason="credentials_expected_fields_reserved_underscore_prefix",
                    message=(
                        f"expected_fields entry {f!r} in [credentials.{name}] "
                        "begins with '_' which is reserved for kernel internal "
                        "field names; rename without the leading underscore."
                    ),
                    logical_name=name,
                    field=f,
                )
            )
            continue
        if not _FIELD_NAME_PATTERN.fullmatch(f):
            findings.append(
                _refusal(
                    reason="credentials_expected_fields_field_name_invalid_grammar",
                    message=(
                        f"expected_fields entry {f!r} in [credentials.{name}] "
                        "must match ^[a-z][a-z0-9_]*$."
                    ),
                    logical_name=name,
                    field=f,
                )
            )

    return findings


def _validate_ttl_s(name: str, ttl: Any) -> list[ValidatorFinding]:
    """Validate ttl_s. Must be a positive integer."""
    # ``bool`` is a subclass of int in Python; reject it explicitly so a
    # ``True`` value (which would otherwise pass ``int(...) > 0``) fires
    # the same invalid-ttl refusal as any other non-int shape.
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
        return [
            _refusal(
                reason="credentials_ttl_s_invalid",
                message=(
                    f"ttl_s for [credentials.{name}] must be a positive integer; got {ttl!r}."
                ),
                logical_name=name,
                value=ttl,
            )
        ]
    return []


def _validate_purpose_category(name: str, pc: Any) -> list[ValidatorFinding]:
    if not isinstance(pc, str) or pc not in _VALID_PURPOSE_CATEGORIES:
        return [
            _refusal(
                reason="credentials_purpose_category_invalid_value",
                message=(
                    f"purpose_category for [credentials.{name}] must be one "
                    f"of {sorted(_VALID_PURPOSE_CATEGORIES)!r}; got {pc!r}."
                ),
                logical_name=name,
                value=pc,
                allowed_values=sorted(_VALID_PURPOSE_CATEGORIES),
            )
        ]
    return []


def _validate_purpose_description(name: str, pd: Any) -> list[ValidatorFinding]:
    if not isinstance(pd, str) or pd == "" or len(pd) > _PURPOSE_DESCRIPTION_MAX_LEN:
        return [
            _refusal(
                reason="credentials_purpose_description_invalid_shape",
                message=(
                    f"purpose_description for [credentials.{name}] must be a "
                    f"non-empty string at most {_PURPOSE_DESCRIPTION_MAX_LEN} "
                    f"chars; got {type(pd).__name__!r} of length "
                    f"{len(pd) if isinstance(pd, str) else 'n/a'}."
                ),
                logical_name=name,
            )
        ]
    return []


def _validate_credential_block(name: str, decl: Any) -> list[ValidatorFinding]:
    """Validate a single ``[credentials.<name>]`` block. Caller has
    already grammar-checked ``name``; this validates the declaration
    body.

    Block-shape handling:

    - ``decl is None``: deep-merge sentinel for test scenarios that
      remove a baseline block; return ``[]`` silently. Real TOML
      cannot produce ``None`` here (a section header always parses
      to a dict).
    - ``decl`` is not a dict (e.g., string, int, list): emit ONE
      shape-flag refusal ``credentials_unknown_field`` with
      ``payload.failure_mode="non_table"`` to make the malformed
      block shape explicit, then continue as if the block were
      empty ``{}`` so the 5 required-field-missing refusals also
      fire — author sees both the root-cause shape error AND each
      missing-field signal. The pre-T14b-round-2 fall-through
      returned ``[]`` silently, which would have admitted
      ``{"db_main": "not-a-dict"}`` once T15 wired this validator
      into ``cli/validate.py``.
    - ``decl`` is a dict: validate unknown-field + required-field
      cascade against the real dict contents.
    """
    if decl is None:
        return []
    findings: list[ValidatorFinding] = []

    # T14b round-2 reviewer fix (P1): non-dict block → flag the shape
    # error + treat as empty for the required-field cascade so the
    # malformed-manifest-admission bug class is closed. Uses the
    # ``failure_mode="non_table"`` shape the reviewer suggested
    # (TOML terminology — a credentials block declared without a
    # section header / inline table). The closed-enum
    # ``credentials_unknown_field`` reason already carries the
    # ``payload.failure_mode`` discriminator pattern (see the per-
    # field unknown-key path below); extending it to cover block-
    # shape failures keeps the closed-enum vocabulary stable.
    if not isinstance(decl, dict):
        findings.append(
            _refusal(
                reason="credentials_unknown_field",
                message=(
                    f"[credentials.{name}] must be a TOML table (dict); got "
                    f"{type(decl).__name__!r}. Declare a section header "
                    f"``[credentials.{name}]`` and populate the required fields."
                ),
                logical_name=name,
                failure_mode="non_table",
                block_type=type(decl).__name__,
            )
        )
        effective_decl: dict[str, Any] = {}
    else:
        effective_decl = decl
        # Unknown-field detection runs only on real-dict blocks (no
        # keys to inspect when the block isn't a dict); the non-dict
        # path above already surfaced the block-shape issue.
        for key in decl:
            if key not in _ALLOWED_BLOCK_FIELDS:
                findings.append(
                    _refusal(
                        reason="credentials_unknown_field",
                        message=(
                            f"[credentials.{name}].{key} is not a recognised "
                            f"field; allowed: {sorted(_ALLOWED_BLOCK_FIELDS)!r}."
                        ),
                        logical_name=name,
                        field=key,
                    )
                )

    # T14b round-1 reviewer fix (P1): all 5 fields are required per
    # spec §5.1; call each per-field validator unconditionally (using
    # ``.get()`` so absent fields forward ``None``). Each per-field
    # validator treats ``None`` as the closest closed-enum refusal
    # for that field (empty / invalid / invalid_value / invalid_shape).
    # The pre-T14b ``in`` check let an empty-dict block + any block
    # missing any of the 5 required fields slip through silently,
    # which would have admitted malformed signed manifests once T15
    # wires this validator into ``cli/validate.py``.
    findings.extend(_validate_vault_path(name, effective_decl.get("vault_path")))
    findings.extend(_validate_expected_fields(name, effective_decl.get("expected_fields")))
    findings.extend(_validate_ttl_s(name, effective_decl.get("ttl_s")))
    findings.extend(_validate_purpose_category(name, effective_decl.get("purpose_category")))
    findings.extend(_validate_purpose_description(name, effective_decl.get("purpose_description")))

    return findings


def _detect_duplicate_vault_paths(
    name_decl_pairs: Sequence[tuple[str, Any]],
) -> list[ValidatorFinding]:
    """Detect duplicate ``vault_path`` values across credential blocks.
    Emits one refusal per offending block (the 2nd + Nth occurrences)
    so authors see which blocks collide."""
    seen: dict[str, str] = {}  # vault_path → first logical_name that declared it
    findings: list[ValidatorFinding] = []
    for name, decl in name_decl_pairs:
        if not isinstance(decl, dict):
            continue
        vp = decl.get("vault_path")
        if not isinstance(vp, str) or vp == "":
            continue
        if vp in seen:
            findings.append(
                _refusal(
                    reason="credentials_vault_path_duplicate_across_blocks",
                    message=(
                        f"vault_path {vp!r} declared in [credentials.{name}] "
                        f"is already declared in [credentials.{seen[vp]}]; "
                        "vault paths must be unique across blocks."
                    ),
                    logical_name=name,
                    vault_path=vp,
                    first_occurrence=seen[vp],
                )
            )
        else:
            seen[vp] = name
    return findings


def _cross_check_workload_gid(
    data: dict[str, Any], credentials_present: bool
) -> list[ValidatorFinding]:
    """Cross-validate ``[runtime].expected_workload_gid`` against
    credential-block presence per ADR-004 §25:

    - Credentials present + no gid → ``..._required_for_credential_pack``
    - gid present + no credentials → ``..._without_credentials``
    - gid out of [1, 4_294_967_295] → ``..._invalid_range``
    """
    findings: list[ValidatorFinding] = []
    runtime_block = data.get("runtime")
    gid: Any = None
    if isinstance(runtime_block, dict):
        gid = runtime_block.get("expected_workload_gid")

    if credentials_present and gid is None:
        findings.append(
            _refusal(
                reason="runtime_expected_workload_gid_required_for_credential_pack",
                message=(
                    "[runtime].expected_workload_gid is required when "
                    "[credentials.*] blocks are declared per ADR-004 §25; "
                    "set it to the GID owning the credential mount."
                ),
            )
        )
    elif not credentials_present and gid is not None:
        findings.append(
            _refusal(
                reason="runtime_expected_workload_gid_without_credentials",
                message=(
                    "[runtime].expected_workload_gid is set but no "
                    "[credentials.*] blocks are declared; remove the field "
                    "or add a credential block."
                ),
                value=gid,
            )
        )

    # ``bool`` is a subclass of int in Python; reject it explicitly so a
    # ``True`` GID value would fire invalid_range rather than passing.
    if gid is not None and (
        not isinstance(gid, int) or isinstance(gid, bool) or gid < _GID_MIN or gid > _GID_MAX
    ):
        findings.append(
            _refusal(
                reason="runtime_expected_workload_gid_invalid_range",
                message=(
                    f"[runtime].expected_workload_gid={gid!r} is outside the "
                    f"allowed range [{_GID_MIN}, {_GID_MAX}]."
                ),
                value=gid,
                min=_GID_MIN,
                max=_GID_MAX,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Validate the ``[credentials.*]`` + ``[runtime].expected_workload_gid``
    surface of a pack manifest. Returns a list of
    :class:`ValidatorFinding` per the orchestrator's aggregation
    contract — refusals + warnings; severity derived from
    ``severity_for(reason)``.

    Parameters
    ----------
    data:
        Parsed pack-manifest dict (typically from ``tomllib.loads``).
    pack_path:
        Unused at this validator — present to match the per-concern
        validator signature contract.
    """
    del pack_path  # signature parity with other per-concern validators
    findings: list[ValidatorFinding] = []
    credentials = data.get("credentials")
    credentials_present = isinstance(credentials, dict) and len(credentials) > 0

    if credentials_present:
        assert isinstance(credentials, dict)  # narrows for mypy

        # Pack-wide count cap
        if len(credentials) > _CREDENTIALS_MAX_COUNT:
            findings.append(
                _refusal(
                    reason="credentials_count_exceeds_maximum",
                    message=(
                        f"Pack declares {len(credentials)} credential blocks; "
                        f"max {_CREDENTIALS_MAX_COUNT}."
                    ),
                    count=len(credentials),
                    max_count=_CREDENTIALS_MAX_COUNT,
                )
            )

        # Per-block validation. Logical-name grammar fires first; if
        # it fails for a given block, per-field checks for that block
        # are skipped (the name is also dropped from the duplicate
        # detector's seen-set via the helper's exact-string compare,
        # so a near-duplicate trailing-space variant trips grammar
        # without collateral on the duplicate-detection axis).
        name_decl_pairs: list[tuple[str, Any]] = list(credentials.items())

        # Duplicate detection runs over the full pair list. No-op for
        # dict input (Python dict-key uniqueness); future-proofs
        # T15+ composed-input shapes.
        findings.extend(_detect_duplicate_names(name_decl_pairs))

        # Vault-path duplicate detection across blocks.
        findings.extend(_detect_duplicate_vault_paths(name_decl_pairs))

        # Per-block field validation.
        for name, decl in name_decl_pairs:
            if not isinstance(name, str):
                continue
            grammar_findings = _validate_logical_name(name)
            if grammar_findings:
                findings.extend(grammar_findings)
                continue
            findings.extend(_validate_credential_block(name, decl))

    # Cross-validator (gated on credentials_present)
    findings.extend(_cross_check_workload_gid(data, credentials_present))

    return findings


__all__ = ["validate"]
