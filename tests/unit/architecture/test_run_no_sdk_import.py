"""Sprint 14A-A — core/run must stay SDK-free + portal-runtime-free + packs-free
+ cli-free.

The managed-run executor is the sandbox-ORCHESTRATION primitive: it depends on
the SDK-free ``sandbox.protocol``/``sandbox.policy`` interfaces, ``core.scheduler``,
and ``core.decision_history``. It MUST NOT import the docker/k8s SDK, MUST NOT
import ``cognic_agentos.portal`` at runtime (the ``Actor`` reference is
``TYPE_CHECKING``-only), MUST NOT import ``cognic_agentos.packs`` at all, and
(Sprint 14A-A4b) MUST NOT import ``cognic_agentos.cli`` at all — core/run owns a
LOCAL copy of the ADR-014 RiskTier vocab (``executor.py``) precisely to avoid the
``core/run -> cli`` dependency; the value-drift test in test_executor.py keeps the
copy in lockstep, and the fence below keeps it a copy.
Mirrors tests/unit/core/scheduler/test_architecture_no_sandbox_import.py.
"""

from __future__ import annotations

import ast
import pathlib
import subprocess
import sys

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


def _module_level_imports(path: pathlib.Path) -> set[str]:
    # Top-level body statements ONLY — excludes function-body imports AND the
    # ``if TYPE_CHECKING:`` block (an ``ast.If`` in ``tree.body``, not an Import
    # node). The right granularity for "must not be a module-level import".
    tree = ast.parse(path.read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            mods.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def test_run_dir_has_expected_sources() -> None:
    # Non-vacuous guard: a NEW core/run module forces a deliberate fence review.
    assert {p.name for p in _run_sources()} == {
        "__init__.py",
        "executor.py",
        "_types.py",
        "storage.py",
    }


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


def test_core_run_no_cli_import_at_all() -> None:
    # Sprint 14A-A4b: core/run owns a LOCAL copy of the ADR-014 RiskTier vocab
    # (executor.py:RiskTier) precisely so it never depends on cli._governance_vocab.
    # The value-drift pin (test_executor.py::test_run_risk_tier_drift_pinned_to_cli_
    # canonical) keeps the copy in lockstep; THIS fence keeps it a COPY — cli access
    # is forbidden ENTIRELY (not even TYPE_CHECKING; the other half of the local-copy
    # contract). Without it, a future direct ``from cli._governance_vocab import
    # RiskTier`` would still pass the value-drift test (same values) while silently
    # re-introducing the core/run -> cli runtime dependency. Mirrors
    # test_core_run_no_packs_import_at_all (the _all_imports strictness).
    for path in _run_sources():
        for mod in _all_imports(path):
            assert not mod.startswith("cognic_agentos.cli"), f"{path.name}: cli import {mod}"


def test_core_run_no_module_level_sandbox_import() -> None:
    # Sprint 14A-A2a: the pending-approval handler catches SandboxLifecycleRefused
    # via a FUNCTION-LOCAL import (inside run()); _build_policy /
    # _build_pack_context likewise import sandbox.policy function-locally. A
    # MODULE-LEVEL sandbox import would pull hvac (sandbox.policy -> sandbox.audit
    # -> core.vault -> hvac) and break kernel boot. sandbox.* may appear ONLY
    # under TYPE_CHECKING (annotations) or inside function bodies — never at
    # module level. Complements test_core_run_imports_without_hvac (the runtime
    # proof) with a static module-level guard.
    for path in _run_sources():
        for mod in _module_level_imports(path):
            assert not mod.startswith("cognic_agentos.sandbox"), (
                f"{path.name}: module-level sandbox import {mod} (must be function-local)"
            )


def test_core_run_imports_without_hvac() -> None:
    """Kernel-boot regression: the kernel image (no ``adapters`` extra) lacks
    ``hvac``, and ``app.py`` imports ``harness.sandbox`` -> ``core.run.executor``
    at boot. A MODULE-LEVEL ``sandbox.policy`` / ``sandbox.protocol`` import would
    pull hvac (``sandbox.policy -> sandbox.audit -> core.vault -> hvac``) and
    break the kernel boot (the CI ``image size budget`` job's boot-smoke caught
    exactly this). Pin that ``core.run.executor`` + ``harness.sandbox`` import
    cleanly with hvac blocked — the sandbox imports must stay TYPE_CHECKING +
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
        "import cognic_agentos.core.run.executor\n"
        "import cognic_agentos.core.run.storage\n"
        "import cognic_agentos.harness.sandbox\n"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, (
        "core.run.executor / harness.sandbox pulled hvac at import (kernel-boot "
        f"regression):\n{result.stderr}"
    )
