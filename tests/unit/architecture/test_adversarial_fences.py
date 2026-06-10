"""ADR-011 Sprint-13b — OS/pack architecture fences over ``evaluation/adversarial/``.

The adversarial red-team surface is a GENERIC, persona-agnostic OS evaluation
primitive; per-agent attack corpora ship in packs (AGENTS.md). These AST fences
pin that the subpackage imports no Layer-C agent (``cognic_agentos.agents.*``)
and no agent-SDK persona surface (``cognic_agentos.sdk.agent``). The existing
``test_eval_fences.py`` globs ``evaluation/*.py`` TOP-LEVEL only, so the
subpackage gets its OWN fence here. Path mirrors ``test_eval_fences.py``
(absolute ``parents[3]``) so the fence is CWD-independent.
"""

from __future__ import annotations

import ast
import pathlib

_ADV_DIR = (
    pathlib.Path(__file__).resolve().parents[3]
    / "src"
    / "cognic_agentos"
    / "evaluation"
    / "adversarial"
)


def _sources() -> list[pathlib.Path]:
    return sorted(_ADV_DIR.glob("*.py"))


def _imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_adversarial_dir_has_expected_sources() -> None:
    """Non-vacuous guard — pin the exact source set so a vanished glob cannot make
    the fences pass trivially."""
    expected = {"__init__.py", "mutator.py", "runner.py", "templates.py", "evidence.py"}
    assert {p.name for p in _sources()} == expected


def test_adversarial_imports_no_layer_c_or_agent_sdk() -> None:
    for path in _sources():
        for mod in _imported_modules(path):
            assert not mod.startswith("cognic_agentos.agents"), f"{path.name}: Layer-C import {mod}"
            assert mod != "cognic_agentos.sdk.agent" and not mod.startswith(
                "cognic_agentos.sdk.agent."
            ), f"{path.name}: agent-SDK import {mod}"
