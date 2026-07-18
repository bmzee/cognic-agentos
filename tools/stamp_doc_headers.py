#!/usr/bin/env python3
"""Apply the ruled documentation statuses and regenerate ``docs/INDEX.md``."""

from __future__ import annotations

import re
import subprocess
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import NamedTuple

_REPO_ROOT = Path(__file__).resolve().parents[1]
_INDEX_PATH = Path("docs/INDEX.md")
_VERIFIED_DATE = "2026-07-18"
_OWNER_LINE = "<!-- OWNER: cognic-agentos maintainers -->"

_OPEN_SUPERPOWER_DOCS: frozenset[Path] = frozenset(
    {
        Path("docs/superpowers/plans/2026-07-09-adr-028-conversational-vertical-slice.md"),
        Path("docs/superpowers/specs/2026-07-08-adr-028-conversational-sessions-design.md"),
        Path("docs/superpowers/specs/2026-07-14-m85d-bank-demo-design.md"),
        Path("docs/superpowers/specs/2026-07-14-skill-engineering-and-accuracy-design.md"),
    }
)

# These are conservatively CURRENT under the ruling's "when in doubt" arm.
# The report must surface them for a maintainer's later reclassification call.
FLAGGED_CURRENT_SUSPECTS: tuple[Path, ...] = (
    Path("docs/SPRINT_WORKING_SUMMARY.md"),
    Path("docs/superpowers/plans/2026-07-09-adr-028-conversational-vertical-slice.md"),
)

_SUPERSEDED_DOCS: dict[Path, str] = {
    Path("docs/ROADMAP.md"): "AS_BUILT_CAPABILITY_MAP.md",
}
_HISTORICAL_DIRECTORIES: frozenset[str] = frozenset({"closeouts", "evidence", "handoffs"})
_SUPERPOWER_HISTORY_DIRECTORIES: frozenset[str] = frozenset({"plans", "recon", "specs", "spikes"})
_LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_HTML_RE = re.compile(r"<[^>]+>")


class Classification(NamedTuple):
    status: str
    superseded_by: str | None = None


def classify_document(path: Path) -> Classification:
    """Apply the one-time R37 classification rules to one tracked document."""
    if path in _SUPERSEDED_DOCS:
        return Classification("SUPERSEDED-BY", _SUPERSEDED_DOCS[path])
    if len(path.parts) >= 2 and path.parts[0] == "docs":
        if path.parts[1] in _HISTORICAL_DIRECTORIES:
            return Classification("HISTORICAL")
        if (
            len(path.parts) >= 3
            and path.parts[1] == "superpowers"
            and path.parts[2] in _SUPERPOWER_HISTORY_DIRECTORIES
            and path not in _OPEN_SUPERPOWER_DOCS
        ):
            return Classification("HISTORICAL")
    return Classification("CURRENT")


def _tracked_markdown_docs(repo_root: Path) -> tuple[Path, ...]:
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z", "--", "docs"],
        check=True,
        capture_output=True,
        text=True,
    )
    paths = {
        Path(raw) for raw in result.stdout.split("\0") if raw and Path(raw).suffix.lower() == ".md"
    }
    paths.add(_INDEX_PATH)
    return tuple(sorted(paths, key=lambda item: item.as_posix()))


def _h1_position(lines: list[str]) -> int:
    in_fence = False
    for index, line in enumerate(lines):
        plain = line.rstrip("\r\n")
        if plain.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if not in_fence and plain.startswith("# "):
            return index + 1
    return 0


def _header_lines(classification: Classification) -> list[str]:
    if classification.status == "SUPERSEDED-BY":
        if classification.superseded_by is None:
            raise ValueError("SUPERSEDED-BY classification requires a target")
        status = f"<!-- STATUS: SUPERSEDED-BY: {classification.superseded_by} -->"
    else:
        status = f"<!-- STATUS: {classification.status} -->"
    return [
        f"{status}\n",
        f"{_OWNER_LINE}\n",
        f"<!-- LAST-VERIFIED: {_VERIFIED_DATE} -->\n",
    ]


def stamp_text(text: str, classification: Classification) -> str:
    """Insert or replace the three-line header without changing body bytes."""
    lines = text.splitlines(keepends=True)
    position = _h1_position(lines)
    status_positions = [
        index for index, line in enumerate(lines) if line.rstrip("\r\n").startswith("<!-- STATUS:")
    ]
    if status_positions:
        if len(status_positions) != 1 or status_positions[0] != position:
            raise ValueError("existing STATUS header is duplicated or misplaced")
        if position + 2 >= len(lines):
            raise ValueError("existing STATUS header is incomplete")
        owner = lines[position + 1].rstrip("\r\n")
        verified = lines[position + 2].rstrip("\r\n")
        if owner != _OWNER_LINE or not verified.startswith("<!-- LAST-VERIFIED:"):
            raise ValueError("existing STATUS header has an unexpected three-line shape")
        del lines[position : position + 3]
    lines[position:position] = _header_lines(classification)
    return "".join(lines)


def _purpose(path: Path, text: str) -> str:
    if path == _INDEX_PATH:
        return "Tracked documentation status and purpose index"
    lines = text.splitlines()
    position = _h1_position(lines)
    if position > 0:
        title = lines[position - 1][2:].strip()
    else:
        title = path.stem.replace("-", " ").replace("_", " ").strip()
    title = _LINK_RE.sub(r"\1", title)
    title = _HTML_RE.sub("", title)
    title = title.replace("|", "/")
    for marker in ("**", "__", "`"):
        title = title.replace(marker, "")
    return " ".join(title.split()) or path.stem


def render_index(documents: Mapping[Path, str]) -> str:
    """Render one deterministic, grouped line per documentation file."""
    groups: dict[str, list[Path]] = defaultdict(list)
    for path in documents:
        groups[path.parent.as_posix()].append(path)

    lines = [
        "# Documentation Index\n",
        "<!-- STATUS: CURRENT -->\n",
        f"{_OWNER_LINE}\n",
        f"<!-- LAST-VERIFIED: {_VERIFIED_DATE} -->\n",
        "\n",
        "Generated by `tools/stamp_doc_headers.py`; rerun it after adding or "
        "reclassifying documentation.\n",
        "\n",
    ]
    for directory in sorted(groups):
        lines.extend((f"## `{directory}`\n", "\n"))
        for path in sorted(groups[directory], key=lambda item: item.as_posix()):
            classification = classify_document(path)
            target = path.relative_to("docs").as_posix()
            purpose = _purpose(path, documents[path])
            lines.append(f"- [{path.as_posix()}]({target}) | {classification.status} | {purpose}\n")
        lines.append("\n")
    return "".join(lines).rstrip() + "\n"


def main() -> int:
    paths = _tracked_markdown_docs(_REPO_ROOT)
    documents: dict[Path, str] = {}
    changed = 0
    for path in paths:
        if path == _INDEX_PATH:
            documents[path] = "# Documentation Index\n"
            continue
        document = _REPO_ROOT / path
        original = document.read_text(encoding="utf-8")
        stamped = stamp_text(original, classify_document(path))
        documents[path] = stamped
        if stamped != original:
            document.write_text(stamped, encoding="utf-8")
            changed += 1

    index_text = render_index(documents)
    index_file = _REPO_ROOT / _INDEX_PATH
    previous_index = index_file.read_text(encoding="utf-8") if index_file.exists() else None
    if previous_index != index_text:
        index_file.write_text(index_text, encoding="utf-8")
        changed += 1

    counts = Counter(classify_document(path).status for path in paths)
    print(
        f"documentation stamp complete: {len(paths)} docs, {changed} files changed; "
        f"CURRENT={counts['CURRENT']} HISTORICAL={counts['HISTORICAL']} "
        f"SUPERSEDED-BY={counts['SUPERSEDED-BY']}"
    )
    for suspect in FLAGGED_CURRENT_SUSPECTS:
        print(f"flagged CURRENT suspect: {suspect.as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
