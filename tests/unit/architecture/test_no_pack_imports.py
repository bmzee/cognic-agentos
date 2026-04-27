"""Architecture-discipline test — no plugin-pack imports in OS source.

Per ADR-001 and ADR-002, AgentOS is the OS-only platform. Tools, skills, and
agents ship as separately-versioned plugin packs in the ``cognic_tool_*``,
``cognic_skill_*``, and ``cognic_agent_*`` distribution namespaces and are
discovered at runtime via Python entry points (Sprint 4).

This test parses every ``.py`` file under ``src/cognic_agentos/`` and refuses
the source tree if any module top-level-imports a pack-namespace package.

Sprint 4's plugin registry will use entry-point discovery + dynamic
``importlib.import_module`` and is intentionally exempt; until that sprint
ships the rule has zero exceptions.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PACK_NAMESPACE_PREFIXES: tuple[str, ...] = (
    "cognic_tool_",
    "cognic_skill_",
    "cognic_agent_",
    # Editable test fixtures introduced in Sprint 4 use the same prefixes;
    # the registry-loader exemption flips on at that sprint.
)

SRC_ROOT = Path(__file__).resolve().parents[3] / "src" / "cognic_agentos"


def _iter_py_files() -> list[Path]:
    return sorted(p for p in SRC_ROOT.rglob("*.py") if "__pycache__" not in p.parts)


def _module_imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import
                continue
            if node.module:
                names.append(node.module)
    return names


def _is_pack_import(module: str) -> bool:
    head = module.split(".", 1)[0]
    return any(head.startswith(p) for p in PACK_NAMESPACE_PREFIXES)


@pytest.mark.parametrize("path", _iter_py_files(), ids=lambda p: str(p.relative_to(SRC_ROOT)))
def test_no_pack_namespace_imports(path: Path) -> None:
    """Every OS source file MUST avoid pack-namespace imports at module scope."""

    offenders = [m for m in _module_imports(path) if _is_pack_import(m)]
    assert not offenders, (
        f"{path.relative_to(SRC_ROOT)} imports pack-namespace modules at module scope: "
        f"{offenders!r}. Plugin packs are discovered via entry points (Sprint 4); "
        "OS source must not depend on any pack."
    )
