"""Sprint-7A T12 — ADR-016 supply-chain attestation-path validator.

Validates the manifest's ``[supply_chain].attestation_paths`` declaration
per ADR-016 supply-chain controls. Each declared path must:

  - Be a non-empty string (not an ``AUTHOR-FILL: ...`` placeholder).
  - Be a relative path (absolute paths refused; cannot be inside the
    pack by definition).
  - Resolve to a location inside the pack root (``..``-traversal +
    symlink-traversal both refused as ``path_escapes_pack_root``).
  - Refer to an existing regular file (a directory at the declared
    path is a refusal — defends against pointing at the parent
    ``attestations/`` directory by mistake).

The path-resolution checks are critical-controls work — they feed
directly into the runtime trust gate (Sprint 4 ``protocol/trust_gate``)
which loads each declared attestation file. A manifest pointing at
``/etc/passwd`` or ``../../foo`` MUST be refused at validate time so
the unsafe path never reaches the sign / verify orchestrators.

Validator scope (Wave-1):

  - Canonical T5 shape: ``[supply_chain].attestation_paths`` (required;
    list of pack-relative path strings).
  - Legacy/docs shape: ``[tool.cognic.supply_chain].attestation_paths``
    (the pre-T6 fixture-pack layout at
    ``tests/fixtures/cognic_test_{mcp,agent}_pack/`` + the docs
    references in ``docs/MCP-CONFORMANCE.md`` /
    ``docs/A2A-CONFORMANCE.md``). Validated identically when present.

Closed-enum reasons T12 owns:

  - ``supply_chain_attestation_path_missing`` — used for "field/entry
    shape problems" (field absent, list shape wrong, AUTHOR-FILL
    placeholder, etc.). ``payload.failure_mode`` distinguishes:

      * ``field_absent`` — block declared but ``attestation_paths``
        field missing
      * ``field_not_list`` — declared but not a TOML list
      * ``list_empty`` — list is empty
      * ``path_entry_not_string`` — non-string list entry
      * ``path_entry_empty`` — empty/whitespace string entry
      * ``path_entry_author_fill`` — entry begins with ``AUTHOR-FILL``

  - ``supply_chain_attestation_path_unresolvable`` — used for "shape
    OK but path doesn't reach a real regular file inside the pack
    root". ``payload.failure_mode`` distinguishes (5 sub-cases):

      * ``path_absolute`` — path is absolute (must be pack-relative)
      * ``path_escapes_pack_root`` — resolved path escapes the pack
        root via ``..`` traversal or symlink target
      * ``path_does_not_exist`` — resolves cleanly inside the pack
        root but the file isn't present
      * ``path_not_a_file`` — exists but is a directory or other
        non-regular-file
      * ``path_resolution_error`` — ``Path.resolve()`` raised
        ``OSError`` (POSIX symlink-loop errno 62 / 40 + permission
        errors during traversal) or ``RuntimeError`` (older-Python +
        non-POSIX symlink-loop behaviour); ``payload.error_type``
        records the exception class. Critical-controls seam: a
        malformed pack must surface a deterministic refusal — never
        a traceback — at the ADR-016 path gate.

Dual-path lookup mirrors T8/T9/T10/T11 doctrine: each declared path
validates independently when both are declared, with payload's
``block_path`` distinguishing the source (``supply_chain`` /
``tool.cognic.supply_chain``) so pack authors can locate each
violation. Split-location bypass is impossible: the canonical and
legacy paths are validated as siblings, not as overrides.

Validator-promotion call (Doctrine Decision G): the path-traversal
pre-check is the validator's primary job and adds real allow/deny
logic that feeds the runtime trust gate. Plan-of-record marks T12
as a critical-controls module (95%+ line / 90%+ branch) — halt-
before-commit on every change.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Final

from cognic_agentos.cli import ValidatorFinding

#: Prefix that marks an unfilled ``AUTHOR-FILL: ...`` placeholder
#: from the T5 templates. Pack authors replace these with real
#: values; the validator treats any entry starting with this prefix
#: as missing. Mirrors T7/T10/T11 AUTHOR-FILL doctrine.
_AUTHOR_FILL_PREFIX: Final[str] = "AUTHOR-FILL"


def _resolve_path(data: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any] | None:
    """Walk ``path`` through ``data``; return the leaf dict or
    ``None`` on any non-dict intermediate."""
    cursor: Any = data
    for segment in path:
        if not isinstance(cursor, dict):
            return None
        cursor = cursor.get(segment)
    return cursor if isinstance(cursor, dict) else None


def _located_supply_chain_blocks(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return ``(block_path, block)`` pairs — one per declared/expected
    supply-chain location — in deterministic dispatch order (canonical
    T5 first, legacy second).

    Both shapes nest the same way (sub-table at the named location);
    only the dotted path differs. The orchestrator's shape gate
    short-circuits the per-concern dispatch on a missing block, so
    a return value of ``[]`` from this helper means "no shape gate
    decision was bypassed; legitimately nothing to validate at
    direct-unit-test entry"."""
    located: list[tuple[str, dict[str, Any]]] = []

    top_block = _resolve_path(data, ("supply_chain",))
    if top_block is not None:
        located.append(("supply_chain", top_block))

    legacy_block = _resolve_path(data, ("tool", "cognic", "supply_chain"))
    if legacy_block is not None:
        located.append(("tool.cognic.supply_chain", legacy_block))

    return located


def _missing(*, prefix: str, failure_mode: str, message: str, **extra: Any) -> ValidatorFinding:
    """Build a ``supply_chain_attestation_path_missing`` refusal.
    ``payload.failure_mode`` distinguishes within the closed-enum
    reason; ``payload.block_path`` carries the dotted path the
    declaration was located at."""
    return ValidatorFinding(
        severity="refusal",
        reason="supply_chain_attestation_path_missing",
        message=message,
        payload={"block_path": prefix, "failure_mode": failure_mode, **extra},
    )


def _unresolvable(
    *, prefix: str, failure_mode: str, message: str, **extra: Any
) -> ValidatorFinding:
    """Build a ``supply_chain_attestation_path_unresolvable`` refusal.
    Used for the path-traversal + existence + resolution-error checks;
    ``failure_mode`` distinguishes the five sub-cases (see module
    header for the enumerated list)."""
    return ValidatorFinding(
        severity="refusal",
        reason="supply_chain_attestation_path_unresolvable",
        message=message,
        payload={"block_path": prefix, "failure_mode": failure_mode, **extra},
    )


def _validate_path_entry(
    declared: str, *, prefix: str, index: int, pack_path: Path
) -> list[ValidatorFinding]:
    """Validate a single declared path entry against the path-traversal
    pre-check + filesystem existence checks.

    The check order matters:

      1. Absolute path → ``path_absolute`` (skips filesystem touch).
      2. Resolve relative to pack root + verify within pack root via
         ``Path.resolve().relative_to(pack_root.resolve())`` — this
         catches both ``..`` traversal AND symlinks pointing outside
         (``resolve()`` follows symlinks).
      3. Existence check — ``is_file()`` False → ``path_does_not_exist``
         OR ``path_not_a_file`` depending on whether the path exists
         at all (e.g., directory case).

    The pack-root containment check uses ``Path.resolve(strict=False)``
    so a non-existent path can still be checked for containment
    (an absent file inside the pack is ``path_does_not_exist``, not
    ``path_escapes_pack_root``).

    Resolution failures (e.g. a malformed pack with a self-referential
    symlink — ``OSError [Errno 62] Too many levels of symbolic links``
    on POSIX, or ``RuntimeError`` on older Python versions / non-POSIX
    platforms) collapse into ``path_resolution_error``. Critical-
    controls seam: ``agentos validate`` MUST surface a deterministic
    refusal rather than a traceback at the ADR-016 path gate, so a
    pack-author with a corrupted attestations directory can act on
    the message instead of debugging the validator.
    """
    findings: list[ValidatorFinding] = []
    candidate = Path(declared)

    if candidate.is_absolute():
        findings.append(
            _unresolvable(
                prefix=prefix,
                failure_mode="path_absolute",
                message=(
                    f"{prefix}.attestation_paths[{index}]={declared!r} is "
                    "an absolute path; declare paths relative to the pack "
                    "root."
                ),
                declared_path=declared,
                index=index,
            )
        )
        return findings

    try:
        pack_root_resolved = pack_path.resolve()
        candidate_resolved = (pack_path / candidate).resolve()
    except (OSError, RuntimeError) as exc:
        # ``OSError`` covers POSIX symlink-loop errors (errno 62 / 40)
        # + filesystem permission errors during traversal;
        # ``RuntimeError`` covers older-Python + non-POSIX symlink-loop
        # behaviour. Both collapse to the same closed-enum refusal so
        # CI parsers see a deterministic shape; ``error_type`` payload
        # distinguishes for remediation copy.
        findings.append(
            _unresolvable(
                prefix=prefix,
                failure_mode="path_resolution_error",
                message=(
                    f"{prefix}.attestation_paths[{index}]={declared!r} could "
                    f"not be resolved against the pack root: "
                    f"{type(exc).__name__}: {exc}. Common cause is a "
                    "self-referential or mutually-referential symlink in "
                    "the attestations/ directory; remove the broken link "
                    "and re-run `agentos sign --bundle .`."
                ),
                declared_path=declared,
                index=index,
                error_type=type(exc).__name__,
            )
        )
        return findings

    try:
        candidate_resolved.relative_to(pack_root_resolved)
    except ValueError:
        findings.append(
            _unresolvable(
                prefix=prefix,
                failure_mode="path_escapes_pack_root",
                message=(
                    f"{prefix}.attestation_paths[{index}]={declared!r} resolves "
                    f"to {candidate_resolved!s} which escapes the pack root "
                    f"({pack_root_resolved!s}); reject for path-traversal "
                    "pre-check per ADR-016."
                ),
                declared_path=declared,
                index=index,
                resolved_path=str(candidate_resolved),
            )
        )
        return findings

    if not candidate_resolved.exists():
        findings.append(
            _unresolvable(
                prefix=prefix,
                failure_mode="path_does_not_exist",
                message=(
                    f"{prefix}.attestation_paths[{index}]={declared!r} resolves "
                    f"inside the pack root but the file is not present at "
                    f"{candidate_resolved!s}; run `agentos sign --bundle .` "
                    "to populate attestations."
                ),
                declared_path=declared,
                index=index,
            )
        )
        return findings

    if not candidate_resolved.is_file():
        findings.append(
            _unresolvable(
                prefix=prefix,
                failure_mode="path_not_a_file",
                message=(
                    f"{prefix}.attestation_paths[{index}]={declared!r} resolves "
                    f"to {candidate_resolved!s} which exists but is not a "
                    "regular file (perhaps you meant a file inside that "
                    "directory)."
                ),
                declared_path=declared,
                index=index,
            )
        )

    return findings


def _validate_blob_path_field(*, block: dict[str, Any], prefix: str) -> list[ValidatorFinding]:
    """Sprint 7B.3 T2 Slice G (R6 P2 #4 + R7 P2 #4) — validate the
    optional ``[supply_chain].blob_path`` field.

    Field-absent is the GREEN path (additive contract; legacy packs
    validate cleanly + fail closed at the runtime signature gate per
    ADR-012 §110). When present, the field MUST be:

    1. A string (``failure_mode="blob_path_not_string"``)
    2. Non-empty / non-whitespace (``failure_mode="blob_path_empty"``)
    3. Relative — no leading ``/`` (``failure_mode="blob_path_absolute_forbidden"``)
    4. Path-traversal-safe — no ``..`` segments
       (``failure_mode="blob_path_traversal_rejected"``)
    5. Not AUTHOR-FILL (``failure_mode="blob_path_author_fill"``)

    All findings use the new closed-enum reason
    ``supply_chain_blob_path_unresolvable`` with ``payload.failure_mode``
    discriminator (mirrors the existing
    ``supply_chain_attestation_path_unresolvable`` multi-failure-mode
    pattern).
    """
    if "blob_path" not in block:
        # Field-absent green path; legacy packs validate cleanly.
        return []

    value = block["blob_path"]

    if not isinstance(value, str):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="supply_chain_blob_path_unresolvable",
                message=(f"{prefix}.blob_path must be a string; got {type(value).__name__}."),
                payload={
                    "block_path": prefix,
                    "failure_mode": "blob_path_not_string",
                    "declared_value": value,
                },
            )
        ]

    stripped = value.strip()
    if not stripped:
        return [
            ValidatorFinding(
                severity="refusal",
                reason="supply_chain_blob_path_unresolvable",
                message=(f"{prefix}.blob_path is empty or whitespace-only."),
                payload={
                    "block_path": prefix,
                    "failure_mode": "blob_path_empty",
                },
            )
        ]

    if stripped.startswith(_AUTHOR_FILL_PREFIX):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="supply_chain_blob_path_unresolvable",
                message=(
                    f"{prefix}.blob_path is still an AUTHOR-FILL placeholder; "
                    "run `agentos sign --bundle .` to emit the value."
                ),
                payload={
                    "block_path": prefix,
                    "failure_mode": "blob_path_author_fill",
                    "declared_value": value,
                },
            )
        ]

    # Absolute path → refused. R5 P2 #3 + R6 P2 #4 doctrine: the
    # manifest field MUST be bundle-root-relative so the runtime
    # signature path resolver can concatenate with the submit-declared
    # signed_artefact_root.
    if stripped.startswith("/"):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="supply_chain_blob_path_unresolvable",
                message=(
                    f"{prefix}.blob_path={stripped!r} is absolute; the field "
                    "MUST be bundle-root-relative per R5 P2 #3 + R6 P2 #4 "
                    "doctrine. Re-run `agentos sign --bundle --bundle-root "
                    "<bundle>` to emit a relative value."
                ),
                payload={
                    "block_path": prefix,
                    "failure_mode": "blob_path_absolute_forbidden",
                    "declared_value": value,
                },
            )
        ]

    # Path-traversal rejection — any ``..`` SEGMENT (not just substring)
    # in the relative path refuses. Splitting on "/" makes "..bar" and
    # "foo..baz" valid (legitimate filenames with leading/embedded dots).
    if ".." in stripped.split("/"):
        return [
            ValidatorFinding(
                severity="refusal",
                reason="supply_chain_blob_path_unresolvable",
                message=(
                    f"{prefix}.blob_path={stripped!r} contains a '..' "
                    "path-traversal segment; the field MUST be a clean "
                    "bundle-root-relative path."
                ),
                payload={
                    "block_path": prefix,
                    "failure_mode": "blob_path_traversal_rejected",
                    "declared_value": value,
                },
            )
        ]

    return []


def _validate_supply_chain_block(
    block: dict[str, Any], prefix: str, pack_path: Path
) -> list[ValidatorFinding]:
    """Validate one declared supply-chain block (canonical or legacy).

    Field-shape failures short-circuit before path-resolution: a
    non-list ``attestation_paths`` cannot have its entries iterated.
    Once the shape is OK, every entry is checked independently so
    pack authors get one finding per offending entry.

    Sprint 7B.3 T2 Slice G — additionally validates the optional
    ``blob_path`` field per :func:`_validate_blob_path_field`. The
    blob_path check is independent of the attestation_paths check;
    both produce their own findings independently.
    """
    raw_paths = block.get("attestation_paths")

    if "attestation_paths" not in block:
        return [
            _missing(
                prefix=prefix,
                failure_mode="field_absent",
                message=(
                    f"{prefix}.attestation_paths is required; declare a list "
                    "of pack-relative paths to ADR-016 attestation files."
                ),
            )
        ]

    if not isinstance(raw_paths, list):
        return [
            _missing(
                prefix=prefix,
                failure_mode="field_not_list",
                message=(
                    f"{prefix}.attestation_paths must be a TOML list of "
                    f"strings; got {type(raw_paths).__name__}."
                ),
                declared_value=raw_paths,
            )
        ]

    if not raw_paths:
        return [
            _missing(
                prefix=prefix,
                failure_mode="list_empty",
                message=(
                    f"{prefix}.attestation_paths is empty; declare at least "
                    "one ADR-016 attestation file (cosign signature + SBOM "
                    "minimum)."
                ),
            )
        ]

    findings: list[ValidatorFinding] = []
    for index, entry in enumerate(raw_paths):
        if not isinstance(entry, str):
            findings.append(
                _missing(
                    prefix=prefix,
                    failure_mode="path_entry_not_string",
                    message=(
                        f"{prefix}.attestation_paths[{index}] must be a string; "
                        f"got {type(entry).__name__}."
                    ),
                    index=index,
                    declared_value=entry,
                )
            )
            continue

        stripped = entry.strip()
        if not stripped:
            findings.append(
                _missing(
                    prefix=prefix,
                    failure_mode="path_entry_empty",
                    message=(f"{prefix}.attestation_paths[{index}] is empty or whitespace-only."),
                    index=index,
                )
            )
            continue

        if stripped.startswith(_AUTHOR_FILL_PREFIX):
            findings.append(
                _missing(
                    prefix=prefix,
                    failure_mode="path_entry_author_fill",
                    message=(
                        f"{prefix}.attestation_paths[{index}] is still an "
                        "AUTHOR-FILL placeholder; replace with a real path "
                        "or run `agentos sign --bundle .`."
                    ),
                    index=index,
                    declared_value=entry,
                )
            )
            continue

        findings.extend(
            _validate_path_entry(stripped, prefix=prefix, index=index, pack_path=pack_path)
        )

    # Sprint 7B.3 T2 Slice G — independent blob_path validation. Runs
    # after attestation_paths regardless of attestation_paths outcome
    # so authors see ALL shape failures in a single iteration. Field-
    # absent path is silent (additive contract).
    findings.extend(_validate_blob_path_field(block=block, prefix=prefix))

    return findings


def validate(data: dict[str, Any], pack_path: Path) -> list[ValidatorFinding]:
    """Validate the manifest's supply-chain declaration per ADR-016.

    Returns the per-block findings or an empty list. Both the
    canonical ``[supply_chain]`` and legacy
    ``[tool.cognic.supply_chain]`` paths are inspected; each declared
    location validates independently.
    """
    located = _located_supply_chain_blocks(data)
    if not located:
        return []

    findings: list[ValidatorFinding] = []
    for prefix, block in located:
        findings.extend(_validate_supply_chain_block(block, prefix, pack_path))
    return findings


__all__ = ["validate"]
