"""Sprint-7A T6 — `agentos validate` orchestrator (CRITICAL CONTROLS).

Per Doctrine Decision G, this module is on the critical-controls floor
(95% line / 90% branch). It is the single dispatch seam for every
per-concern validator (T7-T12) and the canonical exit-code calculator
the SDK's :func:`assert_manifest_validates` helper delegates into.

Public surface:

  - :func:`run_validators` — pure function: parses the manifest TOML,
    dispatches to every per-concern validator, returns the aggregated
    ``list[ValidatorFinding]`` without side-effects. SDK helpers use
    this entry point.
  - :func:`format_finding` — rendering helper. Default text mode emits
    GH-Actions-style inline annotations
    (``::error file=<pack>::<reason>: <message>``); ``--json`` mode
    emits one JSON object per line for CI parsers.

Private surface:

  - The Typer command body lives in :mod:`cognic_agentos.cli` and
    delegates here; this module never touches ``typer.Exit`` or
    ``typer.echo`` directly so the orchestrator stays unit-testable
    without a Typer runner.

Severity-aware exit code (R3 P2 #2 / R4 P2 #1 doctrine):

  - ``ValidatorFinding.affects_exit_code`` is True iff the finding's
    severity is ``"refusal"``. Warnings render but do NOT fail CI.
  - The Typer wrapper raises ``typer.Exit(1)`` iff
    ``any(f.affects_exit_code for f in findings)``.

Closed-enum drift gate:

  - The four reasons the orchestrator itself emits — ``manifest_not_found``
    (file missing), ``manifest_unparseable_toml`` (UTF-8 decode failure
    OR TOML syntax failure; R19 P2 #2), ``manifest_missing_pack_id``
    ([pack] table missing or pack_id field missing/empty; R19 P2 #1),
    and ``manifest_missing_required_block`` (a universally-required
    top-level block is absent OR present-but-not-a-TOML-table; R19
    P2 #1 + R20 P2 #1) — all appear in the closed-enum
    ``ValidatorReason`` literal + the ``_VALIDATOR_REASON_OWNERSHIP``
    mapping. A future refactor that adds a new orchestrator-emission
    site MUST update both. The drift-detector test in
    ``test_cli_validate.py`` pins the full four-reason set so a stale
    docstring or a missing ownership-map entry trips at CI time.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli.validators import (
    a2a,
    data_governance,
    identity,
    mcp,
    risk_tier,
    supply_chain,
)

#: Manifest filename the orchestrator + every per-concern validator
#: read. Pinned here so the path is single-sourced.
_MANIFEST_FILENAME: str = "cognic-pack-manifest.toml"

#: Closed-enum tuple of universally-required top-level manifest blocks.
#: Per-kind blocks (``a2a`` for agent packs, ``mcp`` for tool packs)
#: are checked by the per-concern validators that own them; the
#: orchestrator only enforces the floor every pack carries.
#:
#: R19 P2 #1 reviewer correction: the closed-enum reason
#: ``manifest_missing_required_block`` was pre-seeded against
#: ``validate.py`` in the T1 ownership map but had no fire-path
#: until T6. Adding the check here closes the gap that let
#: empty-ish manifests pass the orchestrator while every per-
#: concern validator was still a stub.
_REQUIRED_TOP_LEVEL_BLOCKS: tuple[str, ...] = (
    "identity",
    "data_governance",
    "risk_tier",
    "supply_chain",
)


def _resolves_in_legacy_path(data: dict[str, object], block_name: str) -> bool:
    """True iff ``[tool.cognic.<block_name>]`` resolves to a TOML
    sub-table. Used by the R27 P2 #1 shape-gate fallback so packs
    declaring a required block at the legacy/docs-aligned
    ``[tool.cognic.*]`` location aren't refused before the per-
    concern validators (T7-T12 dual-path-read) get a chance to see
    them. Returns False on any non-dict intermediate or if the leaf
    is missing/non-dict — the gate fires its normal block_absent
    refusal in that case."""
    cursor: object = data
    for segment in ("tool", "cognic", block_name):
        if not isinstance(cursor, dict):
            return False
        cursor = cursor.get(segment)
    return isinstance(cursor, dict)


def _check_manifest_shape(
    data: dict[str, object],
    manifest_path: Path,
) -> list[ValidatorFinding]:
    """Closed-enum manifest-shape gate. Emits one finding per missing
    required block and one for ``[pack].pack_id``. Returning a non-
    empty list short-circuits the per-concern dispatch in
    :func:`run_validators` — per-concern validators MAY panic on
    missing blocks they're scoped against, so the orchestrator
    refuses the manifest at the shape boundary.
    """
    findings: list[ValidatorFinding] = []

    # [pack].pack_id check. Two failure modes (block missing vs field
    # missing/empty) collapse into the same closed-enum reason; the
    # ``failure_mode`` field in the payload distinguishes them for
    # CI parsers that want to render different remediation copy.
    pack_block = data.get("pack")
    if not isinstance(pack_block, dict):
        findings.append(
            ValidatorFinding(
                severity="refusal",
                reason="manifest_missing_pack_id",
                message=(
                    f"manifest at {manifest_path} is missing the [pack] table "
                    "(or it is not a TOML sub-table)."
                ),
                payload={
                    "manifest_path": str(manifest_path),
                    "failure_mode": "pack_block_absent",
                },
            )
        )
    else:
        pack_id_value = pack_block.get("pack_id")
        if not isinstance(pack_id_value, str) or not pack_id_value.strip():
            findings.append(
                ValidatorFinding(
                    severity="refusal",
                    reason="manifest_missing_pack_id",
                    message=(
                        f"manifest at {manifest_path} is missing [pack].pack_id "
                        "(or the value is empty / not a string)."
                    ),
                    payload={
                        "manifest_path": str(manifest_path),
                        "failure_mode": "pack_id_field_absent_or_empty",
                    },
                )
            )

    # manifest_missing_required_block — one finding per missing OR
    # non-table block. Per-concern validators expect a TOML sub-table
    # they can index into; a scalar (e.g., ``identity = "x"``) would
    # crash the validator with a TypeError. R20 P2 #1 reviewer
    # correction: treat non-dict required blocks as failures with
    # ``failure_mode="block_not_table"``, distinct from
    # ``"block_absent"`` so CI parsers can render different
    # remediation copy.
    #
    # R27 P2 #1 reviewer correction: a required block is also
    # satisfied if declared at its legacy ``[tool.cognic.<block>]``
    # location (the per-concern validators T7-T12 dual-path-read
    # both shapes). Without this, the orchestrator's shape gate
    # short-circuited on docs-shaped manifests + the legacy/docs
    # compatibility advertised in the per-concern validators was
    # never reachable through ``agentos validate``.
    for block in _REQUIRED_TOP_LEVEL_BLOCKS:
        if block not in data:
            # Top-level absent — try the legacy fallback before
            # emitting a refusal.
            if _resolves_in_legacy_path(data, block):
                continue
            findings.append(
                ValidatorFinding(
                    severity="refusal",
                    reason="manifest_missing_required_block",
                    message=(
                        f"manifest at {manifest_path} is missing required "
                        f"top-level block [{block}] (also not present at "
                        f"legacy [tool.cognic.{block}])."
                    ),
                    payload={
                        "manifest_path": str(manifest_path),
                        "block": block,
                        "failure_mode": "block_absent",
                    },
                )
            )
        elif not isinstance(data[block], dict):
            findings.append(
                ValidatorFinding(
                    severity="refusal",
                    reason="manifest_missing_required_block",
                    message=(
                        f"manifest at {manifest_path} declares [{block}] "
                        "but the value is not a TOML table (per-concern "
                        "validators expect a sub-table they can index into)."
                    ),
                    payload={
                        "manifest_path": str(manifest_path),
                        "block": block,
                        "failure_mode": "block_not_table",
                    },
                )
            )

    return findings


def run_validators(pack_path: Path) -> list[ValidatorFinding]:
    """Parse ``pack_path/cognic-pack-manifest.toml`` + dispatch to
    every per-concern validator + return the aggregated findings.

    Side-effect-free: never raises, never writes to stdout/stderr,
    never calls ``sys.exit``. The Typer command wrapper renders the
    findings + computes the exit code; SDK helpers like
    :func:`cognic_agentos.sdk.testing.assert_manifest_validates` call
    this directly + assert against the returned list.

    Manifest-shape failures short-circuit the per-concern dispatch:

      - File not found → ``manifest_not_found`` (single finding).
      - Bytes that don't decode as UTF-8 OR don't parse as valid
        TOML → ``manifest_unparseable_toml`` (single finding;
        ``error_type`` carries the underlying ``UnicodeDecodeError``
        / ``TOMLDecodeError`` class name; R19 P2 #2).
      - ``[pack].pack_id`` missing or required top-level block
        missing → ``manifest_missing_pack_id`` /
        ``manifest_missing_required_block`` findings (one per
        missing block; R19 P2 #1).

    On any manifest-shape failure, the per-concern validators are NOT
    called — they may panic on a missing block they expected to
    validate against. Per-concern dispatch only happens on a fully-
    well-shaped manifest.
    """
    manifest_path = pack_path / _MANIFEST_FILENAME

    if not manifest_path.is_file():
        return [
            ValidatorFinding(
                severity="refusal",
                reason="manifest_not_found",
                message=f"manifest not found at {manifest_path}",
                payload={"manifest_path": str(manifest_path)},
            )
        ]

    # R19 P2 #2: read as bytes + decode UTF-8 explicitly so non-UTF-8
    # input surfaces as ``manifest_unparseable_toml`` with
    # ``error_type=UnicodeDecodeError`` rather than crashing the
    # critical-control seam. Both decode failures + TOML-syntax
    # failures share the same closed-enum reason; the payload's
    # ``error_type`` distinguishes them for CI parsers.
    try:
        raw_bytes = manifest_path.read_bytes()
        decoded = raw_bytes.decode("utf-8")
        data = tomllib.loads(decoded)
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return [
            ValidatorFinding(
                severity="refusal",
                reason="manifest_unparseable_toml",
                message=(
                    f"manifest at {manifest_path} could not be decoded + "
                    f"parsed as TOML: {type(exc).__name__}"
                ),
                payload={
                    "manifest_path": str(manifest_path),
                    "error_type": type(exc).__name__,
                },
            )
        ]

    # R19 P2 #1: manifest-shape gate (pack_id + required blocks)
    # short-circuits per-concern dispatch on any failure.
    shape_findings = _check_manifest_shape(data, manifest_path)
    if shape_findings:
        return shape_findings

    # Dispatch to every per-concern validator. Order matches the
    # closed-enum reason-ownership mapping in cognic_agentos.cli;
    # pack-author docs + CI parsers may depend on positional output.
    findings: list[ValidatorFinding] = []
    findings.extend(identity.validate(data, pack_path))
    findings.extend(a2a.validate(data, pack_path))
    findings.extend(mcp.validate(data, pack_path))
    findings.extend(data_governance.validate(data, pack_path))
    findings.extend(risk_tier.validate(data, pack_path))
    findings.extend(supply_chain.validate(data, pack_path))
    return findings


def format_finding(
    finding: ValidatorFinding,
    *,
    json_output: bool,
    pack_path: Path,
) -> str:
    """Render a finding for stderr.

    Default text mode emits a GH-Actions inline annotation
    (``::error file=<pack>::<reason>: <message>``) so CI logs surface
    refusals + warnings at the manifest path. JSON mode emits one
    JSON object per line for programmatic CI parsers.
    """
    if json_output:
        return json.dumps(
            {
                "severity": finding.severity,
                "reason": finding.reason,
                "message": finding.message,
                "payload": finding.payload,
            },
            sort_keys=True,
        )
    level = "error" if finding.severity == "refusal" else "warning"
    return f"::{level} file={pack_path}::{finding.reason}: {finding.message}"


__all__ = [
    "format_finding",
    "run_validators",
]
