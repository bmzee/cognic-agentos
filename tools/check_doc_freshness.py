#!/usr/bin/env python3
"""Fail closed when tracked documentation freshness metadata drifts."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence
from datetime import date
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit

_REPO_ROOT = Path(__file__).resolve().parents[1]
_INDEX_PATH = Path("docs/INDEX.md")
_OWNER_LINE = "<!-- OWNER: cognic-agentos maintainers -->"
_STATUS_RE = re.compile(r"<!-- STATUS: (CURRENT|HISTORICAL) -->")
_SUPERSEDED_RE = re.compile(r"<!-- STATUS: SUPERSEDED-BY: ([^<>]+) -->")
_VERIFIED_RE = re.compile(r"<!-- LAST-VERIFIED: (\d{4}-\d{2}-\d{2}) -->")
_INDEX_ENTRY_RE = re.compile(
    r"- \[(docs/[^\]]+\.md)\]\(([^)]+)\) "
    r"\| (CURRENT|HISTORICAL|SUPERSEDED-BY) \| (.+)"
)


class DocHeader(NamedTuple):
    status: str
    superseded_by: str | None = None


def tracked_markdown_docs(repo_root: Path = _REPO_ROOT) -> tuple[Path, ...]:
    """Return only git-tracked Markdown under ``docs/`` plus the new index."""
    result = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "-z", "--", "docs"],
        check=True,
        capture_output=True,
        text=True,
    )
    paths = {
        Path(raw) for raw in result.stdout.split("\0") if raw and Path(raw).suffix.lower() == ".md"
    }
    if (repo_root / _INDEX_PATH).is_file():
        paths.add(_INDEX_PATH)
    return tuple(sorted(paths, key=lambda path: path.as_posix()))


def _header_position(lines: list[str]) -> int:
    """Find the first real H1, ignoring fenced examples; otherwise use top."""
    in_fence = False
    for index, line in enumerate(lines):
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if not in_fence and line.startswith("# "):
            return index + 1
    return 0


def _read_header(path: Path, text: str) -> tuple[DocHeader | None, list[str]]:
    lines = text.splitlines()
    errors: list[str] = []
    relative = path.as_posix()
    status_lines = [index for index, line in enumerate(lines) if line.startswith("<!-- STATUS:")]
    expected_index = _header_position(lines)
    if len(status_lines) != 1 or status_lines[0] != expected_index:
        errors.append(f"{relative}: missing well-formed status header immediately after H1")
        return None, errors

    status_index = status_lines[0]
    if status_index + 2 >= len(lines):
        errors.append(f"{relative}: incomplete three-line status header")
        return None, errors

    status_line = lines[status_index]
    status_match = _STATUS_RE.fullmatch(status_line)
    superseded_match = _SUPERSEDED_RE.fullmatch(status_line)
    if status_match is not None:
        header = DocHeader(status=status_match.group(1))
    elif superseded_match is not None:
        target = superseded_match.group(1).strip()
        if not target:
            errors.append(f"{relative}: SUPERSEDED-BY target is empty")
            return None, errors
        header = DocHeader(status="SUPERSEDED-BY", superseded_by=target)
    else:
        errors.append(f"{relative}: malformed STATUS value")
        return None, errors

    if lines[status_index + 1] != _OWNER_LINE:
        errors.append(f"{relative}: OWNER header must name cognic-agentos maintainers")
    verified_match = _VERIFIED_RE.fullmatch(lines[status_index + 2])
    if verified_match is None:
        errors.append(f"{relative}: LAST-VERIFIED must be an ISO date")
    else:
        try:
            date.fromisoformat(verified_match.group(1))
        except ValueError:
            errors.append(f"{relative}: LAST-VERIFIED is not a valid calendar date")
    return header, errors


def _resolve_relative_doc(
    *, repo_root: Path, source: Path, target: str, tracked: set[Path]
) -> Path | None:
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        return None
    target_path = Path(parsed.path)
    if target_path.is_absolute():
        return None
    resolved = (repo_root / source.parent / target_path).resolve()
    try:
        relative = resolved.relative_to(repo_root.resolve())
    except ValueError:
        return None
    return relative if relative in tracked else None


def _check_index(
    *,
    repo_root: Path,
    tracked: set[Path],
    headers: dict[Path, DocHeader],
) -> list[str]:
    errors: list[str] = []
    index_file = repo_root / _INDEX_PATH
    if not index_file.is_file():
        return ["docs/INDEX.md: documentation index is missing"]

    entries: dict[Path, tuple[str, str]] = {}
    for line_number, line in enumerate(
        index_file.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.startswith("- [docs/"):
            continue
        match = _INDEX_ENTRY_RE.fullmatch(line)
        if match is None:
            errors.append(f"docs/INDEX.md:{line_number}: malformed document entry")
            continue
        displayed = Path(match.group(1))
        link_target = match.group(2)
        status = match.group(3)
        if displayed in entries:
            errors.append(f"docs/INDEX.md:{line_number}: duplicate entry: {displayed.as_posix()}")
            continue
        resolved = _resolve_relative_doc(
            repo_root=repo_root,
            source=_INDEX_PATH,
            target=link_target,
            tracked=tracked,
        )
        if resolved != displayed:
            errors.append(
                f"docs/INDEX.md:{line_number}: link does not resolve to {displayed.as_posix()}"
            )
        entries[displayed] = (status, match.group(4))

    listed = set(entries)
    for missing in sorted(tracked - listed, key=lambda path: path.as_posix()):
        errors.append(f"index is missing tracked document: {missing.as_posix()}")
    for nonexistent in sorted(listed - tracked, key=lambda path: path.as_posix()):
        errors.append(f"index lists nonexistent document: {nonexistent.as_posix()}")
    for path in sorted(tracked & listed, key=lambda item: item.as_posix()):
        header = headers.get(path)
        if header is not None and entries[path][0] != header.status:
            errors.append(
                f"docs/INDEX.md: status for {path.as_posix()} is {entries[path][0]}, "
                f"header says {header.status}"
            )
    return errors


def check_repository(
    repo_root: Path = _REPO_ROOT,
    *,
    tracked_docs: Sequence[Path] | None = None,
) -> list[str]:
    """Return every freshness-policy violation, or an empty list on success."""
    docs = tuple(tracked_docs) if tracked_docs is not None else tracked_markdown_docs(repo_root)
    tracked = set(docs)
    errors: list[str] = []
    headers: dict[Path, DocHeader] = {}
    for path in docs:
        document = repo_root / path
        if not document.is_file():
            errors.append(f"{path.as_posix()}: tracked document is missing from disk")
            continue
        header, header_errors = _read_header(path, document.read_text(encoding="utf-8"))
        errors.extend(header_errors)
        if header is None:
            continue
        headers[path] = header
        if header.superseded_by is not None:
            target = _resolve_relative_doc(
                repo_root=repo_root,
                source=path,
                target=header.superseded_by,
                tracked=tracked,
            )
            if target is None:
                errors.append(
                    f"{path.as_posix()}: SUPERSEDED-BY target is not tracked: "
                    f"{header.superseded_by}"
                )
    errors.extend(_check_index(repo_root=repo_root, tracked=tracked, headers=headers))
    return errors


def main() -> int:
    docs = tracked_markdown_docs()
    errors = check_repository(tracked_docs=docs)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print(f"documentation freshness: PASS ({len(docs)} tracked docs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
