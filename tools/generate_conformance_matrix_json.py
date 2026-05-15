#!/usr/bin/env python3
"""Sprint 7B.3 T6 — build-time conformance-matrix JSON generator.

Per the plan-of-record Round Flag #8 (R10 LOCKED): the T6 conformance-
matrix evidence panel compares a pack's declared MCP/A2A protocol
features against the authoritative conformance posture. The posture
source-of-truth is prose-table Markdown — ``docs/MCP-CONFORMANCE.md``
("Capability conformance" table) + ``docs/A2A-CONFORMANCE.md``
("Feature conformance matrix" table). The runtime panel MUST NOT parse
Markdown at request time; instead this build-time generator parses the
two tables once → emits a static JSON projection
(``src/cognic_agentos/packs/evidence/conformance_matrix.json``) that
the panel loads at module import.

The generator is deliberately *dumb*: it extracts the **bolded
capability/feature name** from each table row, slugifies it, and
classifies the Wave-1 cell by its leading emoji. It does NOT attempt
to parse the prose narrative of each cell — only the emoji convention
the two docs use consistently:

- ``✅`` → ``supported``  (Wave-1 production / required / optional)
- ``⚠️`` → ``restricted`` (Wave-1 gated escape-hatch / default-deny)
- ``❌`` → ``forbidden``  (Wave-1 forbidden)

``wave_2_promoted`` is ``True`` when the row's Wave-2 cell carries
substantive content (not empty, not an em-dash) — i.e. the feature is
restricted/forbidden now but the matrix already commits to promoting
it. The T6 panel uses this to flag a Wave-2 feature declared in a
Wave-1 manifest.

Output shape (sorted keys, 2-space indent, trailing newline — so a
regenerate produces a minimal reviewable diff)::

    {
      "a2a": {
        "<feature-slug>": {"wave_1": "<posture>", "wave_2_promoted": <bool>},
        ...
      },
      "mcp": {
        "<capability-slug>": {"wave_1": "<posture>", "wave_2_promoted": <bool>},
        ...
      }
    }

The committed JSON is pinned against this generator's output by the
**build-time drift detector** at
``tests/unit/tools/test_generate_conformance_matrix_json.py`` — a docs
edit that moves a Wave-1 posture without regenerating the JSON fails
that test.

Run manually after a conformance-doc edit::

    python tools/generate_conformance_matrix_json.py

This is a ``tools/`` script (no ``__init__.py`` in ``tools/``; mirrors
``tools/check_critical_coverage.py``); it is NOT importable as a
package module + is NOT on the runtime import path.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
_MCP_DOC = _REPO_ROOT / "docs" / "MCP-CONFORMANCE.md"
_A2A_DOC = _REPO_ROOT / "docs" / "A2A-CONFORMANCE.md"
_OUTPUT_PATH = (
    _REPO_ROOT / "src" / "cognic_agentos" / "packs" / "evidence" / "conformance_matrix.json"
)

#: Heading text (substring match) that immediately precedes the target
#: table in each doc. The generator scans forward from this heading for
#: the first Markdown pipe-table.
_MCP_TABLE_HEADING = "Capability conformance"
_A2A_TABLE_HEADING = "Feature conformance matrix"

#: Leading-emoji → Wave-1 posture classification. The two conformance
#: docs use this convention consistently in their Wave-1 column.
_EMOJI_TO_POSTURE: dict[str, str] = {
    "✅": "supported",  # ✅
    "⚠": "restricted",  # ⚠ (optionally followed by U+FE0F variation selector)
    "❌": "forbidden",  # ❌
}

#: Wave-2 cell values that mean "no Wave-2 commitment" (NOT promoted).
#: The conformance docs use the em-dash ``—`` as the empty-cell marker;
#: a bare hyphen is accepted defensively.
_WAVE_2_EMPTY_MARKERS: frozenset[str] = frozenset({"", "—", "-"})

_BOLD_NAME_RE = re.compile(r"\*\*(.+?)\*\*")


def _slugify(name: str) -> str:
    """Slugify a bolded capability/feature name to a stable identifier.

    Lowercases, replaces every run of non-alphanumeric characters with a
    single underscore, and strips leading/trailing underscores. E.g.
    ``"Streaming messages"`` → ``"streaming_messages"``;
    ``"Anonymous / unauthenticated A2A"`` → ``"anonymous_unauthenticated_a2a"``.
    """
    slug = re.sub(r"[^a-z0-9]+", "_", name.strip().lower())
    return slug.strip("_")


def _classify_wave_1(cell: str) -> str:
    """Classify a Wave-1 table cell into a posture by its leading emoji.

    Raises :class:`ValueError` if the cell carries none of the three
    recognised emojis — a fail-loud signal that the doc convention
    drifted (rather than silently mis-classifying a row).
    """
    stripped = cell.strip()
    for emoji, posture in _EMOJI_TO_POSTURE.items():
        if stripped.startswith(emoji):
            return posture
    raise ValueError(
        f"Wave-1 cell {cell!r} carries no recognised posture emoji "
        f"({'/'.join(_EMOJI_TO_POSTURE)}) — conformance-doc convention drifted"
    )


def _is_wave_2_promoted(cell: str) -> bool:
    """A Wave-2 cell signals "promoted" when the matrix commits to MORE
    support for the feature in Wave 2.

    True when the cell carries substantive content (not empty, not an
    em-/en-dash placeholder) AND does NOT lead with ``❌`` — a ``❌``
    Wave-2 cell means the feature stays forbidden in Wave 2 (e.g. the
    A2A "Federated" / "Anonymous" rows carry ``❌`` in BOTH the Wave-1
    and Wave-2 columns), which is the opposite of promotion.
    """
    stripped = cell.strip()
    if stripped in _WAVE_2_EMPTY_MARKERS:
        return False
    return not stripped.startswith("❌")


def _extract_table_rows(doc_text: str, heading_substring: str) -> list[list[str]]:
    """Extract the data rows of the first Markdown pipe-table that
    follows the heading containing ``heading_substring``.

    Returns a list of cell-lists (each cell stripped). The header row +
    the ``|---|`` separator row are skipped; scanning stops at the first
    non-pipe line after the table starts.
    """
    lines = doc_text.splitlines()
    heading_idx: int | None = None
    for idx, line in enumerate(lines):
        if line.lstrip().startswith("#") and heading_substring in line:
            heading_idx = idx
            break
    if heading_idx is None:
        raise ValueError(f"heading containing {heading_substring!r} not found")

    rows: list[list[str]] = []
    in_table = False
    seen_separator = False
    for line in lines[heading_idx + 1 :]:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if in_table:
                break  # table ended
            continue
        in_table = True
        # Markdown pipe-table cells: split on `|`, drop the empty
        # leading/trailing fragments produced by the bordering pipes.
        cells = [cell.strip() for cell in stripped.split("|")[1:-1]]
        if not seen_separator:
            # First pipe-line is the header row; second is the
            # `|---|---|` separator. Skip both.
            if set("".join(cells)) <= set("-: "):
                seen_separator = True
            continue
        rows.append(cells)
    if not rows:
        raise ValueError(f"no data rows found in table under {heading_substring!r}")
    return rows


def _parse_table(doc_path: Path, heading_substring: str) -> dict[str, dict[str, Any]]:
    """Parse one conformance-doc table into a ``{slug: {wave_1, wave_2_promoted}}`` dict."""
    rows = _extract_table_rows(doc_path.read_text(encoding="utf-8"), heading_substring)
    parsed: dict[str, dict[str, Any]] = {}
    for cells in rows:
        # cells[0] = name (carries the **bolded** identifier);
        # cells[1] = Wave-1 posture cell; cells[2] = Wave-2 cell.
        name_match = _BOLD_NAME_RE.search(cells[0])
        if name_match is None:
            raise ValueError(
                f"table row under {heading_substring!r} has no **bolded** name: {cells[0]!r}"
            )
        slug = _slugify(name_match.group(1))
        parsed[slug] = {
            "wave_1": _classify_wave_1(cells[1]),
            "wave_2_promoted": _is_wave_2_promoted(cells[2]) if len(cells) > 2 else False,
        }
    return parsed


def generate_conformance_matrix() -> dict[str, dict[str, dict[str, Any]]]:
    """Parse both conformance docs → the ``{mcp, a2a}`` JSON projection.

    Pure-functional over the on-disk Markdown — no global state, no
    output side effects. :func:`main` writes the result to disk; the
    drift detector calls THIS function and compares against the
    committed file.
    """
    return {
        "mcp": _parse_table(_MCP_DOC, _MCP_TABLE_HEADING),
        "a2a": _parse_table(_A2A_DOC, _A2A_TABLE_HEADING),
    }


def main() -> int:
    matrix = generate_conformance_matrix()
    serialised = json.dumps(matrix, indent=2, sort_keys=True) + "\n"
    _OUTPUT_PATH.write_text(serialised, encoding="utf-8")
    relative = _OUTPUT_PATH.relative_to(_REPO_ROOT)
    print(f"wrote {relative} ({len(matrix['mcp'])} mcp / {len(matrix['a2a'])} a2a entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
