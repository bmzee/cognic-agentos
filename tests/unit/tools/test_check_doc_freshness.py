"""Documentation freshness policy checks."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_CHECKER_PATH = _REPO_ROOT / "tools" / "check_doc_freshness.py"


def _load_checker() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_doc_freshness", _CHECKER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def checker() -> ModuleType:
    return _load_checker()


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _current_doc(title: str = "Current document") -> str:
    return (
        f"# {title}\n"
        "<!-- STATUS: CURRENT -->\n"
        "<!-- OWNER: cognic-agentos maintainers -->\n"
        "<!-- LAST-VERIFIED: 2026-07-18 -->\n\n"
        "Current guidance.\n"
    )


def _historical_doc() -> str:
    return (
        "# Historical document\n"
        "<!-- STATUS: HISTORICAL -->\n"
        "<!-- OWNER: cognic-agentos maintainers -->\n"
        "<!-- LAST-VERIFIED: 2026-07-18 -->\n\n"
        "Retained evidence.\n"
    )


def _superseded_doc(target: str = "current.md") -> str:
    return (
        "# Superseded document\n"
        f"<!-- STATUS: SUPERSEDED-BY: {target} -->\n"
        "<!-- OWNER: cognic-agentos maintainers -->\n"
        "<!-- LAST-VERIFIED: 2026-07-18 -->\n\n"
        "Retired guidance.\n"
    )


def _index_doc(*, include_current: bool = True, include_missing: bool = False) -> str:
    entries = [
        "- [docs/INDEX.md](INDEX.md) | CURRENT | Documentation index.",
        "- [docs/historical.md](historical.md) | HISTORICAL | Historical document",
        "- [docs/old.md](old.md) | SUPERSEDED-BY | Superseded document",
    ]
    if include_current:
        entries.insert(
            1,
            "- [docs/current.md](current.md) | CURRENT | Current document",
        )
    if include_missing:
        entries.append("- [docs/missing.md](missing.md) | CURRENT | Missing document")
    return (
        "# Documentation Index\n"
        "<!-- STATUS: CURRENT -->\n"
        "<!-- OWNER: cognic-agentos maintainers -->\n"
        "<!-- LAST-VERIFIED: 2026-07-18 -->\n\n"
        "## `docs`\n\n" + "\n".join(entries) + "\n"
    )


def _green_tree(root: Path) -> tuple[Path, ...]:
    _write(root / "docs" / "current.md", _current_doc())
    _write(root / "docs" / "historical.md", _historical_doc())
    _write(root / "docs" / "old.md", _superseded_doc())
    _write(root / "docs" / "INDEX.md", _index_doc())
    return (
        Path("docs/INDEX.md"),
        Path("docs/current.md"),
        Path("docs/historical.md"),
        Path("docs/old.md"),
    )


def test_green_repository_passes(checker: ModuleType, tmp_path: Path) -> None:
    tracked = _green_tree(tmp_path)

    assert checker.check_repository(tmp_path, tracked_docs=tracked) == []


@pytest.mark.parametrize("excluded", ["docs/handoffs/note.md", "docs/reviews/audit.md"])
def test_fenced_document_needs_no_header_or_index_entry(
    checker: ModuleType, tmp_path: Path, excluded: str
) -> None:
    tracked = (*_green_tree(tmp_path), Path(excluded))
    _write(tmp_path / excluded, "# Deliberately outside freshness ownership\n")

    assert checker.check_repository(tmp_path, tracked_docs=tracked) == []
    assert excluded not in (tmp_path / "docs" / "INDEX.md").read_text(encoding="utf-8")


def test_missing_header_fails(checker: ModuleType, tmp_path: Path) -> None:
    tracked = _green_tree(tmp_path)
    _write(tmp_path / "docs" / "current.md", "# Current document\n\nNo header.\n")

    errors = checker.check_repository(tmp_path, tracked_docs=tracked)

    assert any("docs/current.md: missing well-formed status header" in error for error in errors)


def test_broken_superseded_link_fails(checker: ModuleType, tmp_path: Path) -> None:
    tracked = _green_tree(tmp_path)
    _write(tmp_path / "docs" / "old.md", _superseded_doc("missing.md"))

    errors = checker.check_repository(tmp_path, tracked_docs=tracked)

    assert any("SUPERSEDED-BY target is not tracked" in error for error in errors)


def test_index_missing_tracked_document_fails(checker: ModuleType, tmp_path: Path) -> None:
    tracked = _green_tree(tmp_path)
    _write(tmp_path / "docs" / "INDEX.md", _index_doc(include_current=False))

    errors = checker.check_repository(tmp_path, tracked_docs=tracked)

    assert any("index is missing tracked document: docs/current.md" in error for error in errors)


def test_index_listing_nonexistent_document_fails(checker: ModuleType, tmp_path: Path) -> None:
    tracked = _green_tree(tmp_path)
    _write(tmp_path / "docs" / "INDEX.md", _index_doc(include_missing=True))

    errors = checker.check_repository(tmp_path, tracked_docs=tracked)

    assert any("index lists nonexistent document: docs/missing.md" in error for error in errors)
