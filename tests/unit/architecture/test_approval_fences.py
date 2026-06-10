"""ADR-014/015 Sprint-13.5a — architecture fences over ``core/approval/``.

The runtime approval engine is a GENERIC, persona-agnostic OS governance
primitive (the future Sprint-14 human-checkpoint surface per the 13.5a design).
It lives under ``core/`` and MUST stay free of upward dependencies on the portal
HTTP layer (``cognic_agentos.portal.*``) and the authoring CLI
(``cognic_agentos.cli.*``): the 13.5b portal seam imports the engine, never the
reverse, and ``ApprovalActor`` is a core-owned projection (NOT
``portal.rbac.actor.Actor``). These AST fences pin both arrows. Path mirrors
``test_adversarial_fences.py`` / ``test_eval_fences.py`` (absolute ``parents[3]``)
so the fence is CWD-independent.
"""

from __future__ import annotations

import ast
import pathlib

_APPROVAL_DIR = (
    pathlib.Path(__file__).resolve().parents[3] / "src" / "cognic_agentos" / "core" / "approval"
)


def _imported_modules(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_approval_dir_has_expected_sources() -> None:
    assert {p.name for p in sorted(_APPROVAL_DIR.glob("*.py"))} == {
        "__init__.py",
        "_types.py",
        "policy.py",
        "storage.py",
        "engine.py",
    }


def test_approval_imports_no_portal_or_cli() -> None:
    for path in _APPROVAL_DIR.glob("*.py"):
        for mod in _imported_modules(path):
            assert not mod.startswith("cognic_agentos.portal"), (
                f"{path.name}: forbidden portal import {mod!r} "
                "(core/approval must not depend on the HTTP layer)"
            )
            assert not mod.startswith("cognic_agentos.cli"), (
                f"{path.name}: forbidden cli import {mod!r} "
                "(core/approval must not depend on the authoring CLI)"
            )
