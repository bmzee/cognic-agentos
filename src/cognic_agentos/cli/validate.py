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
from typing import Final

from cognic_agentos.cli import ValidatorFinding
from cognic_agentos.cli.validators import (
    a2a,
    credentials,
    data_governance,
    hooks,
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


#: Sprint-7A2 T4 — pack-kind-specific forbidden top-level blocks.
#:
#: Per the plan-of-record Doctrine Lock A: hook packs are NOT
#: A2A-speaking and NOT MCP-tool-shaped, so declaring ``[a2a]`` or
#: ``[mcp]`` on a ``kind="hook"`` manifest is a packaging error the
#: orchestrator refuses BEFORE the per-concern validators run (the
#: a2a / mcp validators would otherwise emit unrelated refusals
#: against fields hook packs aren't expected to populate). Closed
#: enum: every entry routes through ``hook_pack_kind_constraint_violated``
#: with ``payload.failure_mode`` distinguishing the offending block.
#:
#: The check covers BOTH the canonical top-level shape AND the
#: legacy ``[tool.cognic.<block>]`` shape per R23 dual-path doctrine
#: — a future maintainer cannot smuggle Wave-2 features into a hook
#: pack via either path.
_FORBIDDEN_BLOCKS_BY_KIND: Final[dict[str, frozenset[str]]] = {
    "hook": frozenset({"a2a", "mcp"}),
}


def _check_pack_kind_constraints(
    data: dict[str, object],
    manifest_path: Path,
) -> list[ValidatorFinding]:
    """Sprint-7A2 T4 — refuse pack-kind-incompatible top-level blocks.

    Wave-1 narrow: only ``kind="hook"`` packs have forbidden blocks
    (``[a2a]`` + ``[mcp]``). The check fires AFTER the shape gate
    (so a malformed [pack] block short-circuits earlier) but BEFORE
    per-concern dispatch (so unrelated validators don't emit noisy
    refusals against fields the hook pack isn't expected to populate).

    Each forbidden block emits one finding with the closed-enum
    reason ``hook_pack_kind_constraint_violated`` + a distinguishing
    ``payload.failure_mode``. The check is idempotent — declaring
    BOTH ``[a2a]`` AND ``[mcp]`` on a hook pack produces two
    findings (one per offending block).
    """
    findings: list[ValidatorFinding] = []
    pack_block = data.get("pack")
    if not isinstance(pack_block, dict):
        return findings  # shape gate already emitted; defer
    pack_kind = pack_block.get("kind")
    if not isinstance(pack_kind, str) or pack_kind not in _FORBIDDEN_BLOCKS_BY_KIND:
        return findings
    forbidden = _FORBIDDEN_BLOCKS_BY_KIND[pack_kind]
    for block in sorted(forbidden):
        # Refuse top-level shape OR legacy ``[tool.cognic.<block>]``.
        # The legacy path mirrors the per-concern validators' R23
        # dual-path-read; without checking both, an author could
        # smuggle the forbidden block via the legacy form.
        present_top = block in data
        present_legacy = _resolves_in_legacy_path(data, block)
        if not (present_top or present_legacy):
            continue
        block_path = block if present_top else f"tool.cognic.{block}"
        findings.append(
            ValidatorFinding(
                severity="refusal",
                reason="hook_pack_kind_constraint_violated",
                message=(
                    f"manifest at {manifest_path} declares "
                    f"[{block_path}] but pack kind is {pack_kind!r}; "
                    f"hook packs are not "
                    f"{'A2A-speaking' if block == 'a2a' else 'MCP-tool-shaped'} "
                    f"and MUST NOT declare this block. Remove the "
                    f"[{block_path}] declaration from the manifest."
                ),
                payload={
                    "manifest_path": str(manifest_path),
                    "pack_kind": pack_kind,
                    "block": block,
                    "block_path": block_path,
                    "failure_mode": f"{block}_block_forbidden",
                },
            )
        )
    return findings


def _resolves_in_legacy_path(data: dict[str, object], block_name: str) -> bool:
    """True iff the required block's legacy/docs-aligned location
    resolves to a meaningful declaration. Used by the R27 P2 #1
    shape-gate fallback so docs-shaped manifests aren't refused
    before the per-concern validators (T7-T12 dual-path-read) get a
    chance to see them. Returns False on any non-dict intermediate
    or if the leaf is missing/non-dict — the gate fires its normal
    block_absent refusal in that case.

    Most blocks share the same legacy nesting (a ``[tool.cognic.<block>]``
    sub-table mirroring the canonical top-level shape). The
    ``risk_tier`` block is the exception (T11 doctrine fix): per
    ``docs/BUILD_PLAN.md:528``, ``docs/HOW-TO-WRITE-A-PACK.md``, the
    Sprint-7A plan-of-record §"Task 11", and both reference fixture
    packs at ``tests/fixtures/cognic_test_{mcp,agent}_pack/``, the
    legacy/docs/runtime shape for risk-tier declaration is
    ``[tool.cognic.runtime].risk_tier`` — a flat ``risk_tier`` field
    inside the richer runtime-config sub-table, NOT a separate
    ``[tool.cognic.risk_tier]`` block. The ``runtime`` block has
    other purposes; for ``risk_tier`` to be considered satisfied via
    the legacy path the ``risk_tier`` field MUST actually be present
    inside it (any value type — the per-concern validator catches
    type-shape errors).
    """
    if block_name == "risk_tier":
        runtime_block = data.get("tool")
        if not isinstance(runtime_block, dict):
            return False
        cognic_block = runtime_block.get("cognic")
        if not isinstance(cognic_block, dict):
            return False
        runtime_sub = cognic_block.get("runtime")
        if not isinstance(runtime_sub, dict):
            return False
        return "risk_tier" in runtime_sub

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
            # ``risk_tier`` nests differently in the legacy shape
            # (``[tool.cognic.runtime].risk_tier``); other blocks
            # share the simpler ``[tool.cognic.<block>]`` form.
            legacy_hint = (
                "[tool.cognic.runtime].risk_tier"
                if block == "risk_tier"
                else f"[tool.cognic.{block}]"
            )
            findings.append(
                ValidatorFinding(
                    severity="refusal",
                    reason="manifest_missing_required_block",
                    message=(
                        f"manifest at {manifest_path} is missing required "
                        f"top-level block [{block}] (also not present at "
                        f"legacy {legacy_hint})."
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

    # Sprint-7A2 T4: pack-kind-specific forbidden-block check.
    # Refuses [a2a] / [mcp] declarations on ``kind="hook"`` packs
    # BEFORE the per-concern dispatch so the a2a / mcp validators
    # don't fire noisy refusals against blocks the hook pack
    # shouldn't populate. The check returns its findings but does
    # NOT short-circuit per-concern dispatch — pack authors get the
    # full picture in a single validate run (forbidden-block
    # refusals + any other manifest issues).
    kind_findings = _check_pack_kind_constraints(data, manifest_path)

    # Dispatch to every per-concern validator. Order matches the
    # closed-enum reason-ownership mapping in cognic_agentos.cli;
    # pack-author docs + CI parsers may depend on positional output.
    findings: list[ValidatorFinding] = []
    findings.extend(kind_findings)
    findings.extend(identity.validate(data, pack_path))
    findings.extend(a2a.validate(data, pack_path))
    findings.extend(mcp.validate(data, pack_path))
    findings.extend(data_governance.validate(data, pack_path))
    findings.extend(risk_tier.validate(data, pack_path))
    # Sprint 10.6 T15 — credentials validator (per ADR-004 §25 +
    # ADR-017). Placed AFTER risk_tier because the credentials
    # validator cross-validates on ``[risk_tier].tier`` for the
    # pre-Sprint-13.5 high-risk-tier refusal; placed BEFORE
    # supply_chain because supply_chain operates on attestation
    # paths (independent concern). The validator is silent on
    # manifests without a ``[credentials.*]`` block, so adding it
    # to the dispatch chain does NOT regress any pack without
    # credentials. Per ``[[feedback_dual_path_doctrine]]``, the
    # one-validator-owns-each-refusal invariant is preserved: the
    # 21 closed-enum reasons owned by validators/credentials.py
    # (per ``cli/__init__.py:_VALIDATOR_REASON_OWNERSHIP``) are
    # emitted only here; sibling validators do NOT collateral-emit.
    findings.extend(credentials.validate(data, pack_path))
    findings.extend(supply_chain.validate(data, pack_path))
    # Sprint-7A2 T5 — hook-block validator. Fires for every pack
    # (Wave-1 narrow: hook packs MUST declare [hooks]; non-hook
    # packs skipping a [hooks] block is silently allowed). Comes
    # last in the dispatch order so per-concern refusals from the
    # earlier validators (identity / data_governance / etc.) appear
    # first when CI parsers walk the findings list.
    findings.extend(hooks.validate(data, pack_path))
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
