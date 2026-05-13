"""Sprint-7B.2 T10 — ``agentos conformance`` thin CLI wrapper (NOT-CC).

Per the plan-of-record §1255-1273, T10 ships a thin command surface
over :func:`cognic_agentos.packs.conformance.run_owasp_conformance`.
The security-bearing logic lives in
:mod:`cognic_agentos.packs.conformance.owasp_agentic` (the OWASP check
matrix + applicability table) and :mod:`cognic_agentos.packs.conformance.checks`
(the wire-protocol-public dataclasses + closed-enum Literals) — both
on the durable critical-controls coverage gate at the 95%/90% floor.

This module owns:

- A 3-value :data:`ConformanceInvocationError` closed-enum literal for
  pre-dispatch refusals (pack-path-not-found / manifest-not-found /
  manifest-unparseable). Distinct vocabulary from
  :data:`packs.conformance.checks.ConformanceOverallStatus` — those are
  the conformance verdict, these are the wrapper's invocation outcome.
- A frozen :class:`ConformanceInvocationFailure` carrier dataclass
  surfacing the reason + a CI-parseable message + a payload dict.
- :func:`run_conformance` — pure-function seam. Side-effect-free:
  never raises, never writes to stdout/stderr, never calls
  ``sys.exit``. Returns either a
  :class:`packs.conformance.ConformanceReport` (verdict reached) or a
  :class:`ConformanceInvocationFailure` (pre-dispatch error). The
  Typer command wrapper at :func:`cognic_agentos.cli.__init__.conformance`
  renders the result + computes the exit code.
- :func:`format_report` — text / JSON renderer for the verdict path.
  JSON mode emits the runner.py 4-key wire-shape dict
  (``overall_status`` / ``results`` / ``summary`` /
  ``errored_categories``) with the load-bearing tuple → list
  conversion on ``errored_categories`` per the T9 doctrine memory
  (``dataclasses.asdict`` preserves tuples; ``core/canonical.canonical_bytes``
  rejects them in chain payloads; the CLI mirrors the same conversion so
  CI parsers consuming the CLI output get a list-typed value).

Exit-code contract (owned by the Typer command wrapper):

  - ``0`` — ``overall_status == "green"``.
  - ``1`` — ``overall_status in {"red", "yellow"}``. Yellow's
    incompleteness signal means the suite is not trustworthy and the
    CLI surfaces that with the same non-zero exit code as red; green is
    the ONLY exit-0 verdict.
  - ``2`` — invocation error (one of the
    :data:`ConformanceInvocationError` reasons).

NOT-CC per plan §1255-1273 — no decision logic of its own; pure
manifest-parse + dispatch + format. The R19 P2 #2 doctrine from
``cli/validate.py`` carries forward: invalid UTF-8 routes to the same
closed-enum reason as TOML-syntax failures, with the payload's
``error_type`` distinguishing them for CI parsers.
"""

from __future__ import annotations

import dataclasses
import json
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from cognic_agentos.cli.validate import _MANIFEST_FILENAME
from cognic_agentos.packs.conformance import (
    ConformanceReport,
    run_owasp_conformance,
)

#: Closed-enum union of every pre-dispatch refusal the conformance
#: command can emit. Growth points MUST update both this Literal AND
#: the value-count drift detector in
#: ``tests/unit/cli/test_conformance_cli.py::
#: TestSprint7B2T10ClosedEnumReasonVocabulary``.
ConformanceInvocationError = Literal[
    "conformance_pack_path_not_found",
    "conformance_manifest_not_found",
    "conformance_manifest_unparseable",
]


@dataclass(frozen=True)
class ConformanceInvocationFailure:
    """Carrier for a pre-dispatch refusal from :func:`run_conformance`.

    Distinct from :class:`packs.conformance.ConformanceReport` so call
    sites can branch via ``isinstance`` rather than sentinel values.
    Mirrors the ``ValidatorFinding`` shape from ``cli/__init__.py`` but
    narrowed to one finding (the conformance wrapper short-circuits on
    the first pre-dispatch error).
    """

    reason: ConformanceInvocationError
    message: str
    payload: dict[str, Any] = dataclasses.field(default_factory=dict)


def run_conformance(
    pack_path: Path,
) -> ConformanceReport | ConformanceInvocationFailure:
    """Resolve ``pack_path/cognic-pack-manifest.toml`` and dispatch to
    :func:`packs.conformance.run_owasp_conformance`.

    Side-effect-free: never raises, never writes to stdout/stderr,
    never calls ``sys.exit``.

      - Pack path does not exist on disk →
        ``conformance_pack_path_not_found``.
      - Pack path exists but manifest file is missing →
        ``conformance_manifest_not_found``.
      - Manifest bytes don't decode as UTF-8 OR don't parse as valid
        TOML → ``conformance_manifest_unparseable`` (``error_type`` in
        payload distinguishes ``UnicodeDecodeError`` vs
        ``TOMLDecodeError``; R19 P2 #2 doctrine carried forward from
        ``cli/validate.py``).
      - Manifest parses but is not a top-level table (e.g., raw TOML
        scalar at root) — pre-empted by ``tomllib.loads`` which always
        returns a dict for valid TOML; no explicit guard needed here.

    On the verdict path the parsed manifest is fed directly to
    :func:`packs.conformance.run_owasp_conformance`. That function
    handles its own malformed-input recovery (missing ``[pack].kind``
    routes through the applicability gate; checker exceptions route to
    ``yellow`` via the registry-loop wrapper). The CLI does NOT
    duplicate those checks — the matrix is the single source of truth
    for verdict logic.
    """
    if not pack_path.exists():
        return ConformanceInvocationFailure(
            reason="conformance_pack_path_not_found",
            message=f"pack path not found: {pack_path}",
            payload={"pack_path": str(pack_path)},
        )

    manifest_path = pack_path / _MANIFEST_FILENAME
    if not manifest_path.is_file():
        return ConformanceInvocationFailure(
            reason="conformance_manifest_not_found",
            message=f"manifest not found at {manifest_path}",
            payload={"manifest_path": str(manifest_path)},
        )

    # R19 P2 #2: read as bytes + decode UTF-8 explicitly so non-UTF-8
    # input surfaces as ``conformance_manifest_unparseable`` with
    # ``error_type=UnicodeDecodeError`` rather than crashing the CLI.
    # Decode failures + TOML-syntax failures + read-side OS errors
    # (``PermissionError``, ``IsADirectoryError``, etc — every subclass
    # of ``OSError``) share the same closed-enum reason; the payload's
    # ``error_type`` distinguishes them for CI parsers. ``OSError`` is
    # caught here so the side-effect-free contract documented in the
    # docstring holds — without it, a permission-denied manifest file
    # would propagate as a raw exception out of the seam (R44 P2 #1).
    try:
        raw_bytes = manifest_path.read_bytes()
        decoded = raw_bytes.decode("utf-8")
        data = tomllib.loads(decoded)
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        return ConformanceInvocationFailure(
            reason="conformance_manifest_unparseable",
            message=(
                f"manifest at {manifest_path} could not be read / decoded "
                f"/ parsed as TOML: {type(exc).__name__}"
            ),
            payload={
                "manifest_path": str(manifest_path),
                "error_type": type(exc).__name__,
            },
        )

    return run_owasp_conformance(data)


def format_report(report: ConformanceReport, *, json_output: bool) -> str:
    """Render a :class:`ConformanceReport` for stdout.

    JSON mode emits the runner.py 4-key wire-shape dict with
    deterministic key ordering (``sort_keys=True``) and a 2-space indent
    for human-readable CI logs. The load-bearing ``errored_categories``
    tuple → list conversion (per the T9 doctrine memory) is applied
    here too: ``dataclasses.asdict`` preserves tuples, but JSON
    consumers always coerce them to lists, so the CLI applies the same
    conversion as ``packs/conformance/runner.py`` for symmetric wire
    shape.

    Text mode emits one line per category (``  <category>: <status>``)
    followed by the indented finding strings (``    - <finding>``) and
    a trailing summary line. The verdict (``overall_status``) appears
    on the FIRST line so quick visual scans see it without scrolling.
    """
    if json_output:
        serialised = asdict(report)
        serialised["errored_categories"] = list(serialised["errored_categories"])
        return json.dumps(serialised, sort_keys=True, indent=2)

    lines: list[str] = [f"overall_status: {report.overall_status}"]
    for category, result in report.results.items():
        lines.append(f"  {category}: {result.status}")
        for finding in result.findings:
            lines.append(f"    - {finding}")
    if report.errored_categories:
        lines.append("errored_categories: " + ", ".join(report.errored_categories))
    lines.append(f"summary: {report.summary}")
    return "\n".join(lines)


__all__ = [
    "ConformanceInvocationError",
    "ConformanceInvocationFailure",
    "format_report",
    "run_conformance",
]
