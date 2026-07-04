"""M6 Task A5 (ADR-025) — core/skill/executor.py must stay kernel-boot-clean +
portal-free + SDK-free + protocol-free.

The skill executor is a sandbox-ORCHESTRATION primitive: it depends on the
SDK-free ``sandbox.protocol`` / ``sandbox.policy`` interfaces, the
``core.skill`` broker + types, and ``core.decision_history`` / ``core.canonical``.
It MUST NOT import ``cognic_agentos.portal`` at runtime (the ``Actor`` reference
is ``TYPE_CHECKING``-only), MUST NOT import the sandbox at module level (that
would pull ``hvac`` via ``sandbox.policy -> sandbox.audit -> core.vault`` and
break the kernel image boot), MUST NOT import ``cognic_agentos.sdk`` at runtime
(the ``core -> sdk`` arrow — the 5-env-var contract is a LOCAL copy, drift-pinned
in test_executor.py), and MUST NOT import ``cognic_agentos.protocol`` at all (the
MCP host is reached ONLY through the injected ``SkillCallProxy`` seam).

Mirrors tests/unit/architecture/test_run_no_sdk_import.py.
"""

from __future__ import annotations

import ast
import pathlib
import subprocess
import sys

_EXECUTOR = (
    pathlib.Path(__file__).resolve().parents[3]
    / "src"
    / "cognic_agentos"
    / "core"
    / "skill"
    / "executor.py"
)


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


def _module_level_imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_module_level_import_allowlist() -> None:
    # Non-vacuous guard: the module-level cognic imports are exactly the SDK-free
    # kernel-safe set. A new module-level import forces a deliberate fence review.
    cognic_module_level = {
        m for m in _module_level_imports(_EXECUTOR) if m.startswith("cognic_agentos")
    }
    assert cognic_module_level == {
        "cognic_agentos.core.canonical",
        "cognic_agentos.core.decision_history",
        "cognic_agentos.core.skill._types",
        "cognic_agentos.core.skill.broker",
    }


def test_no_runtime_portal_import() -> None:
    for mod in _runtime_imports(_EXECUTOR):
        assert not mod.startswith("cognic_agentos.portal"), f"runtime portal import {mod}"


def test_no_sdk_import_at_all() -> None:
    # The 5-env-var contract is a LOCAL copy (drift-pinned test-only); the
    # core/skill -> sdk arrow is forbidden ENTIRELY (not even TYPE_CHECKING).
    for mod in _all_imports(_EXECUTOR):
        assert not mod.startswith("cognic_agentos.sdk"), f"sdk import {mod}"


def test_no_protocol_import_at_all() -> None:
    # The MCP host is reached ONLY through the injected SkillCallProxy seam.
    for mod in _all_imports(_EXECUTOR):
        assert not mod.startswith("cognic_agentos.protocol"), f"protocol import {mod}"


def test_no_module_level_sandbox_import() -> None:
    # sandbox.* may appear ONLY under TYPE_CHECKING (annotations) or inside
    # function bodies — never at module level (a module-level import pulls hvac
    # and breaks kernel boot).
    for mod in _module_level_imports(_EXECUTOR):
        assert not mod.startswith("cognic_agentos.sandbox"), (
            f"module-level sandbox import {mod} (must be function-local)"
        )


def test_no_packs_import_at_all() -> None:
    # skill records reach the executor ONLY via the LoadedSkillRecord projection
    # (the SkillRecordLoader seam) — core/skill cannot import packs.
    for mod in _all_imports(_EXECUTOR):
        assert not mod.startswith("cognic_agentos.packs"), f"packs import {mod}"


def test_executor_imports_without_hvac() -> None:
    """Kernel-boot regression: the kernel image (no ``adapters`` extra) lacks
    ``hvac``. A MODULE-LEVEL ``sandbox.policy`` / ``sandbox.protocol`` import
    would pull hvac (``sandbox.policy -> sandbox.audit -> core.vault -> hvac``)
    and break the kernel boot. Pin that ``core.skill.executor`` imports cleanly
    with hvac blocked — the sandbox imports must stay TYPE_CHECKING +
    function-local. Subprocess (not in-process) so a meta-path blocker can't be
    defeated by modules already imported by sibling tests."""
    code = (
        "import sys, importlib.abc\n"
        "class _B(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path, target=None):\n"
        "        if name == 'hvac' or name.startswith('hvac.'):\n"
        "            raise ModuleNotFoundError(name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, _B())\n"
        "import cognic_agentos.core.skill.executor\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, (
        f"core.skill.executor pulled hvac at import (kernel-boot regression):\n{result.stderr}"
    )
