"""Sprint 14A-A — core/run must stay SDK-free + portal-runtime-free + packs-free.

The managed-run executor is the sandbox-ORCHESTRATION primitive: it depends on
the SDK-free ``sandbox.protocol``/``sandbox.policy`` interfaces, ``core.scheduler``,
and ``core.decision_history``. It MUST NOT import the docker/k8s SDK, MUST NOT
import ``cognic_agentos.portal`` at runtime (the ``Actor`` reference is
``TYPE_CHECKING``-only), and MUST NOT import ``cognic_agentos.packs`` at all.
Mirrors tests/unit/core/scheduler/test_architecture_no_sandbox_import.py.
"""

from __future__ import annotations

import ast
import pathlib

_RUN_DIR = pathlib.Path(__file__).resolve().parents[3] / "src" / "cognic_agentos" / "core" / "run"


def _run_sources() -> list[pathlib.Path]:
    return sorted(_RUN_DIR.glob("*.py"))


def _type_checking_linenos(tree: ast.AST) -> set[int]:
    lines: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test = node.test
            is_tc = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
                isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
            )
            if is_tc:
                for child in ast.walk(node):
                    lineno = getattr(child, "lineno", None)
                    if lineno is not None:
                        lines.add(lineno)
    return lines


def _runtime_imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    tc_lines = _type_checking_linenos(tree)
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and node.lineno not in tc_lines:
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.lineno not in tc_lines:
            mods.add(node.module)
    return mods


def _all_imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_run_dir_has_expected_sources() -> None:
    # Non-vacuous guard: a NEW core/run module forces a deliberate fence review.
    assert {p.name for p in _run_sources()} == {"__init__.py", "executor.py"}


def test_core_run_no_sdk_import() -> None:
    for path in _run_sources():
        for mod in _runtime_imports(path):
            assert not (mod == "aiodocker" or mod.startswith("aiodocker.")), f"{path.name}: {mod}"
            assert not (mod == "kubernetes_asyncio" or mod.startswith("kubernetes_asyncio.")), (
                f"{path.name}: {mod}"
            )


def test_core_run_no_runtime_portal_import() -> None:
    for path in _run_sources():
        for mod in _runtime_imports(path):
            assert not mod.startswith("cognic_agentos.portal"), f"{path.name}: runtime portal {mod}"


def test_core_run_no_packs_import_at_all() -> None:
    # packs access is ONLY via the PackRecordLoader seam — not even TYPE_CHECKING.
    for path in _run_sources():
        for mod in _all_imports(path):
            assert not mod.startswith("cognic_agentos.packs"), f"{path.name}: packs import {mod}"
