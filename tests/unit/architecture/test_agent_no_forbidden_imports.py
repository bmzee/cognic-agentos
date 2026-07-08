"""M8 Task A4 (ADR-027) — core/agent must stay portal-free + protocol-free +
sdk-free + cli-free.

The agent runtime is a kernel primitive: it consumes MCP tools ONLY through a
consumer-owned proxy seam (the ``SkillCallProxy`` precedent), binds actors via
projections (never ``portal.rbac``), and owns LOCAL copies of any CLI vocab it
needs (drift-pinned test-only per
``feedback_drift_detector_test_only_no_runtime_import``) — this fence keeps
those copies COPIES. The ``_all_imports`` strictness (runtime OR
TYPE_CHECKING, module-level or function-local) mirrors
``test_run_no_sdk_import.py``'s packs/cli fences.
"""

from __future__ import annotations

import ast
import pathlib

_AGENT_DIR = (
    pathlib.Path(__file__).resolve().parents[3] / "src" / "cognic_agentos" / "core" / "agent"
)

#: Forbidden import roots for every core/agent module — matched as the exact
#: module OR any submodule (``prefix.``), never as a bare-string prefix (so a
#: hypothetical ``cognic_agentos.sdk_helpers`` cannot false-positive).
_FORBIDDEN_ROOTS = (
    "cognic_agentos.portal",
    "cognic_agentos.protocol",
    "cognic_agentos.sdk",
    "cognic_agentos.cli",
)


def _agent_sources() -> list[pathlib.Path]:
    return sorted(_AGENT_DIR.glob("*.py"))


def _all_imports(path: pathlib.Path) -> set[str]:
    # Runtime AND TYPE_CHECKING, module-level AND function-local — the
    # strictest granularity (mirrors test_run_no_sdk_import._all_imports).
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_agent_dir_has_expected_sources() -> None:
    # Non-vacuous guard: a NEW core/agent module forces a deliberate fence
    # review — extend this set AND keep the forbidden-roots sweep below
    # covering it. dispatch.py + builtins.py joined at M8 A10; loop.py joined
    # at M8 A11 (the loop keeps its llm.gateway imports TYPE_CHECKING-only —
    # ``llm`` is deliberately NOT a forbidden root on this fence).
    assert {p.name for p in _agent_sources()} == {
        "__init__.py",
        "_types.py",
        "assignments.py",
        "policy.py",
        "query_context.py",
        "dispatch.py",
        "builtins.py",
        "loop.py",
    }


def test_core_agent_no_forbidden_imports_at_all() -> None:
    # NO portal / protocol / sdk / cli import in ANY core/agent module — not
    # runtime, not TYPE_CHECKING, not function-local.
    for path in _agent_sources():
        for mod in _all_imports(path):
            for root in _FORBIDDEN_ROOTS:
                assert not (mod == root or mod.startswith(root + ".")), (
                    f"{path.name}: forbidden import {mod}"
                )
