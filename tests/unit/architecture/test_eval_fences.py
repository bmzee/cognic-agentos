"""ADR-010 eval slice — OS/pack architecture fences over ``evaluation/``.

The judge primitive is a GENERIC, persona-agnostic OS evaluation surface;
per-agent scorers ship in packs (AGENTS.md). These AST fences pin that
``evaluation/*.py`` imports no Layer-C agent (``cognic_agentos.agents.*``) and no
agent-SDK persona surface (``cognic_agentos.sdk.agent``). Path mirrors
``test_harness_fences.py`` (absolute ``parents[3]``) so the fence is CWD-independent.
"""

from __future__ import annotations

import ast
import pathlib

_EVAL_DIR = pathlib.Path(__file__).resolve().parents[3] / "src" / "cognic_agentos" / "evaluation"


def _eval_sources() -> list[pathlib.Path]:
    return sorted(_EVAL_DIR.glob("*.py"))


def _imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_eval_dir_has_expected_sources() -> None:
    """Non-vacuous guard — pin the exact source set so a vanished glob cannot make
    the fences pass trivially."""
    names = {p.name for p in _eval_sources()}
    # The expected set grows as Sprint-12 modules land (types/corpus/target/scorers/runner/storage)
    # and Sprint-13a adds the live-replay module (replay.py).
    assert names == {
        "__init__.py",
        "judge.py",
        "types.py",
        "corpus.py",
        "target.py",
        "scorers.py",
        "runner.py",
        "storage.py",
        "replay.py",
    }, names


def test_eval_imports_no_layer_c() -> None:
    """No ``cognic_agentos.agents.*`` import — Layer-C agents live in pack repos."""
    for path in _eval_sources():
        for mod in _imported_modules(path):
            assert not mod.startswith("cognic_agentos.agents"), f"{path.name}: Layer-C import {mod}"


def test_eval_imports_no_agent_sdk() -> None:
    """No ``cognic_agentos.sdk.agent`` persona surface — the judge is a generic OS
    primitive, not an agent."""
    for path in _eval_sources():
        for mod in _imported_modules(path):
            assert mod != "cognic_agentos.sdk.agent" and not mod.startswith(
                "cognic_agentos.sdk.agent."
            ), f"{path.name}: agent-SDK import {mod}"
