"""Documentation status-header and index generator tests."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]
_STAMPER_PATH = _REPO_ROOT / "tools" / "stamp_doc_headers.py"


def _load_stamper() -> ModuleType:
    spec = importlib.util.spec_from_file_location("stamp_doc_headers", _STAMPER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def stamper() -> ModuleType:
    return _load_stamper()


@pytest.mark.parametrize(
    ("path", "status", "target"),
    [
        ("docs/adrs/ADR-001.md", "CURRENT", None),
        ("docs/closeouts/done.md", "HISTORICAL", None),
        (
            "docs/superpowers/specs/2026-07-14-m85d-bank-demo-design.md",
            "CURRENT",
            None,
        ),
        ("docs/superpowers/specs/closed-design.md", "HISTORICAL", None),
        ("docs/ROADMAP.md", "SUPERSEDED-BY", "AS_BUILT_CAPABILITY_MAP.md"),
    ],
)
def test_classification_rules(
    stamper: ModuleType, path: str, status: str, target: str | None
) -> None:
    classification = stamper.classify_document(Path(path))

    assert classification.status == status
    assert classification.superseded_by == target


def test_stamp_places_header_after_h1_and_is_idempotent(stamper: ModuleType) -> None:
    original = "# Title\n\nBody stays byte-for-byte.\n"
    classification = stamper.classify_document(Path("docs/adrs/ADR-001.md"))

    first = stamper.stamp_text(original, classification)
    second = stamper.stamp_text(first, classification)

    assert first == second
    assert first == (
        "# Title\n"
        "<!-- STATUS: CURRENT -->\n"
        "<!-- OWNER: cognic-agentos maintainers -->\n"
        "<!-- LAST-VERIFIED: 2026-07-18 -->\n\n"
        "Body stays byte-for-byte.\n"
    )


def test_stamp_places_header_at_top_without_h1(stamper: ModuleType) -> None:
    classification = stamper.classify_document(Path("docs/notes.md"))

    stamped = stamper.stamp_text("Plain opening.\n", classification)

    assert stamped.startswith(
        "<!-- STATUS: CURRENT -->\n"
        "<!-- OWNER: cognic-agentos maintainers -->\n"
        "<!-- LAST-VERIFIED: 2026-07-18 -->\n"
    )
    assert stamped.endswith("\nPlain opening.\n")


def test_index_is_grouped_and_lists_every_document_once(stamper: ModuleType) -> None:
    documents = {
        Path("docs/INDEX.md"): "# Documentation Index\n",
        Path("docs/guide.md"): "# Operator **Guide**\n",
        Path("docs/adrs/ADR-001.md"): "# ADR-001 | Boundary\n",
    }

    rendered = stamper.render_index(documents)

    assert rendered.count("[docs/INDEX.md]") == 1
    assert rendered.count("[docs/guide.md]") == 1
    assert rendered.count("[docs/adrs/ADR-001.md]") == 1
    assert rendered.index("## `docs`") < rendered.index("## `docs/adrs`")
    assert "| CURRENT | Operator Guide" in rendered
    assert "| CURRENT | ADR-001 / Boundary" in rendered
    assert rendered.endswith("ADR-001 / Boundary\n")
